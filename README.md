/**
 * context-window.ts — OpenCode plugin: Unlimited Context + Unlimited Output
 *
 * ── FEATURE 1: Input sliding window ──────────────────────────────────────────
 * When the conversation approaches the model's context window, older messages
 * are archived to `.opencode/context/chunk-NNN-*.md`. The model is notified
 * and can retrieve any archived content on demand via three built-in tools.
 * OpenCode's database is never touched — only the in-memory slice sent to the
 * model is affected.
 *
 * ── FEATURE 2: Output continuation ───────────────────────────────────────────
 * When the model is cut off mid-response (finish="length"), the partial output
 * is saved to `.opencode/context/continuation-*.md` and a follow-up prompt is
 * automatically injected into the same session. The model reads the file and
 * picks up exactly where it stopped. The user sees the response continue in the
 * next turn with no manual action required.
 *
 * ── How output continuation works ────────────────────────────────────────────
 * 1. The `event` hook listens to `message.part.delta` bus events and
 * accumulates streamed text per session in memory.
 * 2. On `session.status` (type: "idle"), the plugin fetches the session's
 * last message via GET /session/:id/message and checks info.finish.
 * 3. If finish === "length": save partial text to a .md file, then call
 * POST /session/:id/prompt_async to inject a continuation prompt into
 * the same session. OpenCode processes it as a normal new agent turn.
 * 4. The model calls read_context_archive(), continues from the last word,
 * and the response flows seamlessly in the same conversation.
 * 5. The `chat.message` hook detects real user messages (vs. our synthetic
 * continuation prompts) and resets the continuation counter so that each
 * genuine user turn gets a fresh quota of allowed continuations.
 *
 * ── Installation ─────────────────────────────────────────────────────────────
 *
 * mkdir -p .opencode/plugins
 * cp context-window.ts .opencode/plugins/context-window.ts
 *
 * opencode.json:
 * {
 * "plugin": [[
 * "file://./.opencode/plugins/context-window.ts",
 * {
 * "threshold_pct": 0.70,
 * "protected_tail_turns": 3,
 * "context_limit": 100000,
 * "max_continuation_attempts": 5
 * }
 * ]]
 * }
 *
 * ── Options ───────────────────────────────────────────────────────────────────
 * threshold_pct              Context fill fraction that triggers input archiving.
 * Default: 0.70 (fires before OpenCode's own compaction).
 *
 * protected_tail_turns       Recent user turns that are never archived.
 * Default: 3.
 *
 * context_limit              Fallback token limit when auto-detection fails.
 * Auto-detection uses model.limit.context from the
 * chat.params hook on the first API call.
 * Default: 100000.
 *
 * max_continuation_attempts  Max automatic output continuations per user turn.
 * Resets when the user sends a new real message.
 * Default: 5.
 */

import type { Plugin, Hooks } from "@opencode-ai/plugin"
import { tool } from "@opencode-ai/plugin"
import { mkdir, writeFile, readFile, readdir } from "fs/promises"
import { join } from "path"

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/** chars ÷ 4 ≈ tokens. Same heuristic as OpenCode's own Token.estimate(). */
const CHARS_PER_TOKEN = 4

const ARCHIVE_SUBDIR = ".opencode/context"

const DEFAULT_THRESHOLD_PCT = 0.70
const DEFAULT_PROTECTED_TAIL = 3
const DEFAULT_CONTEXT_LIMIT = 100_000
const DEFAULT_MAX_CONTINUATIONS = 5

/**
 * Minimum conversation length before we consider archiving.
 * Prevents archiving tiny conversations that aren't actually full.
 */
const MIN_MESSAGES_BEFORE_ARCHIVE = 6

/**
 * Maximum characters of tool output preserved per tool call in an archive.
 * 20k chars (~5k tokens) preserves grep results, file reads, and compiler
 * output reliably while keeping archive files manageable.
 */
const MAX_TOOL_OUTPUT_IN_ARCHIVE = 20_000

/**
 * Milliseconds to wait after the session.status idle event before querying
 * the database for the finish reason.
 *
 * The runner's onIdle fires synchronously after the Effect chain completes
 * (all DB writes are done before status.set is called), so this delay is not
 * strictly necessary. A small margin guards against any edge-case ordering
 * issues on slow disks.
 */
const IDLE_SETTLE_MS = 100

// ─────────────────────────────────────────────────────────────────────────────
// Token estimation
// ─────────────────────────────────────────────────────────────────────────────

function estimateTokens(text: string | undefined | null): number {
  if (!text) return 0
  return Math.ceil(text.length / CHARS_PER_TOKEN)
}

function estimateMessageCost(msg: { info: any; parts: any[] }): number {
  let tokens = 0
  for (const part of msg.parts ?? []) {
    if (part.type === "text" && part.text)      tokens += estimateTokens(part.text)
    if (part.type === "reasoning" && part.text) tokens += estimateTokens(part.text)
    if (part.type === "tool" && part.state?.status === "completed")
      tokens += estimateTokens(part.state.output)
    if (part.type === "tool" && part.state?.status === "error")
      tokens += estimateTokens(part.state.error)
  }
  return tokens
}

// ─────────────────────────────────────────────────────────────────────────────
// File name builders
// ─────────────────────────────────────────────────────────────────────────────

function chunkFilename(idx: number, sessionID: string): string {
  return `chunk-${String(idx).padStart(3, "0")}-${sessionID.slice(0, 8)}.md`
}

function continuationFilename(): string {
  // Timestamp + random suffix prevents collisions on rapid sequential truncations
  return `continuation-${Date.now()}-${Math.random().toString(36).slice(2, 6)}.md`
}

function discoveryFilename(title: string): string {
  const safe = title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 50)
  const rand = Math.random().toString(36).slice(2, 6)
  return `discovery-${safe}-${Date.now()}-${rand}.md`
}

// ─────────────────────────────────────────────────────────────────────────────
// Archive content builders
// ─────────────────────────────────────────────────────────────────────────────

function buildChunkMarkdown(
  messages: Array<{ info: any; parts: any[] }>,
  idx: number,
  sessionID: string,
  contextLimit: number,
): string {
  const lines: string[] = [
    `# Context Archive — Chunk ${idx}`,
    ``,
    `| | |`,
    `|---|---|`,
    `| **Session** | \`${sessionID.slice(0, 14)}…\` |`,
    `| **Archived at** | ${new Date().toISOString()} |`,
    `| **Messages** | ${messages.length} |`,
    `| **Model context limit** | ${contextLimit.toLocaleString()} tokens |`,
    ``,
    `> Retrieve with \`read_context_archive("${chunkFilename(idx, sessionID)}")\``,
    ``,
    `---`,
    ``,
  ]

  for (const msg of messages) {
    const label = msg.info?.role === "assistant" ? "🤖 **Assistant**" : "👤 **User**"
    const content: string[] = []

    for (const part of msg.parts ?? []) {
      // Skip plugin-injected synthetic notices — they're not real conversation content
      if (part.synthetic) continue

      if (part.type === "text" && part.text && !part.ignored)
        content.push(part.text.trim())

      if (part.type === "reasoning" && part.text) {
        const preview = part.text.length > 400
          ? part.text.slice(0, 400).trim() + "…"
          : part.text.trim()
        content.push(`*[Reasoning: ${preview}]*`)
      }

      if (part.type === "tool") {
        const name: string = part.tool ?? "unknown"
        if (part.state?.status === "completed") {
          const raw: string = part.state.output ?? ""
          const out = raw.length > MAX_TOOL_OUTPUT_IN_ARCHIVE
            ? raw.slice(0, MAX_TOOL_OUTPUT_IN_ARCHIVE) +
              `\n…[${raw.length.toLocaleString()} chars — re-run tool if full output is needed]`
            : raw
          content.push(`**Tool \`${name}\`** → ${part.state.title ?? ""}`)
          if (out.trim()) content.push("```\n" + out.trim() + "\n```")
        } else if (part.state?.status === "error") {
          content.push(`**Tool \`${name}\` ✗** ${part.state.error ?? "error"}`)
        }
      }
    }

    if (content.length === 0) continue
    lines.push(`## ${label}`, ``, content.join("\n\n"), ``, `---`, ``)
  }

  return lines.join("\n")
}

function buildContinuationMarkdown(
  partialText: string,
  sessionID: string,
  attempt: number,
): string {
  return [
    `# Partial Output — Continuation ${attempt}`,
    ``,
    `| | |`,
    `|---|---|`,
    `| **Session** | \`${sessionID.slice(0, 14)}…\` |`,
    `| **Saved at** | ${new Date().toISOString()} |`,
    `| **Continuation #** | ${attempt} |`,
    ``,
    `> The previous response was cut off by the model's per-response output token limit.`,
    `> Continue from exactly where this text ends. Do not repeat or re-introduce.`,
    ``,
    `---`,
    ``,
    `## Partial Output`,
    ``,
    partialText,
    ``,
    `---`,
    ``,
    `*Continue directly from the last word above. No preamble, no summary, no repetition.*`,
  ].join("\n")
}

// ─────────────────────────────────────────────────────────────────────────────
// Plugin
// ─────────────────────────────────────────────────────────────────────────────

export const ContextWindowPlugin: Plugin = async (input, options = {}) => {
  const thresholdPct       = (options.threshold_pct             as number) ?? DEFAULT_THRESHOLD_PCT
  const protectedTailTurns = (options.protected_tail_turns      as number) ?? DEFAULT_PROTECTED_TAIL
  const fallbackLimit      = (options.context_limit             as number) ?? DEFAULT_CONTEXT_LIMIT
  const maxContinuations   = (options.max_continuation_attempts as number) ?? DEFAULT_MAX_CONTINUATIONS

  const archiveDir = join(input.directory, ARCHIVE_SUBDIR)
  async function ensureDir() { await mkdir(archiveDir, { recursive: true }) }

  // ── Auth header for local OpenCode server calls ───────────────────────────
  //
  // OpenCode optionally runs with HTTP Basic auth (OPENCODE_SERVER_PASSWORD).
  // Compute the header once at plugin init time so all fetch calls include it.
  // If the env var is not set, the header object is empty and fetch proceeds
  // without auth (the common case).
  const serverAuthHeader: Record<string, string> = process.env.OPENCODE_SERVER_PASSWORD
    ? {
        Authorization: `Basic ${Buffer.from(
          `${process.env.OPENCODE_SERVER_USERNAME ?? "opencode"}:${process.env.OPENCODE_SERVER_PASSWORD}`,
        ).toString("base64")}`,
      }
    : {}

  // ── Per-session state ─────────────────────────────────────────────────────

  /** Model context limit in tokens, detected via chat.params on first API call. */
  const sessionLimits = new Map<string, number>()

  /** Number of chunk archives written per session. */
  const sessionChunkCounts = new Map<string, number>()

  /**
   * Number of output continuations fired for the CURRENT user turn.
   * Reset to 0 when the user sends a new real (non-synthetic) message.
   * This gives each user turn its own quota of maxContinuations attempts.
   */
  const sessionContinuationCounts = new Map<string, number>()

  /**
   * Accumulated streamed text for the current assistant turn, per session.
   * Populated by message.part.delta events (field: "text").
   * Cleared after each session.status idle event is handled.
   */
  const sessionAccumulator = new Map<string, string>()

  /**
   * Sessions where we just fired a continuation prompt.
   * Used by the chat.message hook to distinguish our synthetic prompts from
   * real user messages — so we don't reset the continuation counter on our own
   * injections.
   */
  const pendingContinuationSessions = new Set<string>()

  // ── HTTP helpers ──────────────────────────────────────────────────────────
  //
  // These call the OpenCode server's REST API directly.
  //
  // GET  /session/:sessionID/message
  //   → Array<{ info: { role, finish, summary, agent, ... }, parts: [...] }>
  //   → Returns the full message list. We reverse to find the last assistant.
  //
  // POST /session/:sessionID/prompt_async
  //   → Body: { parts: [{ type: "text", text: "...", synthetic: true }] }
  //   → Returns HTTP 204 immediately. OpenCode runs the prompt asynchronously.

  async function getLastAssistantFinish(sessionID: string): Promise<string | null> {
    try {
      const url = new URL(`/session/${sessionID}/message`, input.serverUrl)
      const res = await fetch(url.toString(), { headers: serverAuthHeader })
      if (!res.ok) {
        console.error(`[context-window] GET /session/${sessionID}/message returned ${res.status}`)
        return null
      }
      const messages = await res.json()
      
      // FIX: Guard against non-array payloads to prevent iterator crashes
      if (!Array.isArray(messages)) return null

      const lastAssistant = [...messages].reverse().find((m) => m.info?.role === "assistant")
      return lastAssistant?.info?.finish ?? null
    } catch (err) {
      console.error("[context-window] Failed to fetch session messages:", err)
      return null
    }
  }

  async function sendContinuationPrompt(
    sessionID: string,
    continuationFile: string,
  ): Promise<void> {
    const text = [
      `[System: CRITICAL INSTRUCTION — OUTPUT CONTINUATION]`,
      `Your previous response was forcefully cut off by the max output token limit.`,
      ``,
      `The partial output has been saved to:`,
      `  .opencode/context/${continuationFile}`,
      ``,
      `Instructions:`,
      `1. Call: read_context_archive("${continuationFile}") to see exactly where you were cut off.`,
      `2. Resume typing EXACTLY from the next character.`,
      `3. Do NOT output conversational filler (e.g., "Here is the rest", "Continuing...").`,
      `4. Do NOT repeat the last line.`,
      `5. MARKDOWN RULE: If you were cut off inside a code block (\`\`\`), DO NOT output a new \`\`\` language tag. OpenCode will stitch this together for the user. Just output the raw code.`,
    ].join("\n")

    const url = new URL(`/session/${sessionID}/prompt_async`, input.serverUrl)
    const res = await fetch(url.toString(), {
      method: "POST",
      headers: { "Content-Type": "application/json", ...serverAuthHeader },
      body: JSON.stringify({
        parts: [{ type: "text", text, synthetic: true }],
      }),
    })

    if (!res.ok) {
      throw new Error(`POST /session/${sessionID}/prompt_async returned ${res.status}`)
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Tools
  // ─────────────────────────────────────────────────────────────────────────

  const save_discovery = tool({
    description:
      "Save an important finding, decision, plan, or fact to persistent external memory " +
      "in .opencode/context/. These files survive context archiving and session restarts. " +
      "Use proactively for: architectural decisions, bug root causes, important file paths, " +
      "user requirements, plans, and anything you may need to recall later. " +
      "Be thorough — this is your long-term memory. Retrieve with read_context_archive.",
    args: {
      title: tool.schema
        .string()
        .describe("Short descriptive title (becomes part of the filename)"),
      content: tool.schema
        .string()
        .describe(
          "Full content to save. Include: what you found, why it matters, " +
          "relevant file paths, exact code snippets, and next steps.",
        ),
      tags: tool.schema
        .array(tool.schema.string())
        .optional()
        .describe("Optional tags e.g. ['bug', 'architecture', 'plan', 'user-requirement']"),
    },
    async execute({ title, content, tags }) {
      await ensureDir()
      const filename = discoveryFilename(title)
      const tagLine = tags?.length ? `\n**Tags:** ${tags.join(", ")}` : ""
      await writeFile(
        join(archiveDir, filename),
        [
          `# Discovery: ${title}`,
          `**Saved:** ${new Date().toISOString()}${tagLine}`,
          ``,
          content,
        ].join("\n"),
        "utf-8",
      )
      return `✓ Saved to .opencode/context/${filename}\nRetrieve with: read_context_archive("${filename}")`
    },
  })

  const read_context_archive = tool({
    description:
      "Read an archived context file: an auto-saved conversation chunk, a continuation " +
      "partial output, or a discovery you saved with save_discovery. " +
      "Use when you need information from earlier in the conversation, " +
      "when you need to continue a truncated response, " +
      "or when you need to recall something you previously saved. " +
      "Call list_context_archives first if you are unsure which file to read.",
    args: {
      filename: tool.schema
        .string()
        .describe(
          "Filename e.g. 'chunk-001-a1b2c3d4.md', 'continuation-1234-abcd.md', " +
          "'discovery-my-plan-1234-abcd.md'. Call list_context_archives() to see all files.",
        ),
    },
    async execute({ filename }) {
      try {
        return await readFile(join(archiveDir, filename), "utf-8")
      } catch {
        return (
          `File "${filename}" not found in ${ARCHIVE_SUBDIR}/.\n` +
          `Call list_context_archives() to see all available files.`
        )
      }
    },
  })

  const list_context_archives = tool({
    description:
      "List all archived context files for this project: " +
      "auto-saved conversation chunks (chunk-*.md), " +
      "output continuation files (continuation-*.md), " +
      "and discoveries you saved (discovery-*.md). " +
      "Call this whenever something seems to be missing from context, " +
      "after a context archive notice, or before starting a complex task.",
    args: {},
    async execute() {
      try {
        await ensureDir()
        const all = (await readdir(archiveDir)).filter((f) => f.endsWith(".md")).sort()
        if (all.length === 0) {
          return (
            "No archived files yet.\n" +
            "Use save_discovery(title, content) to save important findings."
          )
        }

        const chunks        = all.filter((f) => f.startsWith("chunk-"))
        const continuations = all.filter((f) => f.startsWith("continuation-"))
        const discoveries   = all.filter((f) => f.startsWith("discovery-"))
        const lines = ["## Context Archives", ""]

        if (chunks.length) {
          lines.push(`### Conversation Chunks (${chunks.length})`)
          chunks.forEach((f) => lines.push(`- \`${f}\``))
          lines.push("")
        }
        if (continuations.length) {
          lines.push(`### Output Continuations (${continuations.length})`)
          continuations.forEach((f) => lines.push(`- \`${f}\``))
          lines.push("")
        }
        if (discoveries.length) {
          lines.push(`### Saved Discoveries (${discoveries.length})`)
          discoveries.forEach((f) => lines.push(`- \`${f}\``))
          lines.push("")
        }

        lines.push("Use `read_context_archive(filename)` to read any file.")
        return lines.join("\n")
      } catch {
        return "No archived context files found."
      }
    },
  })

  // ─────────────────────────────────────────────────────────────────────────
  // Hooks
  // ─────────────────────────────────────────────────────────────────────────

  const hooks: Hooks = {
    tool: { save_discovery, read_context_archive, list_context_archives },

    // ── 1. Capture model context limit ──────────────────────────────────────
    //
    // chat.params fires on every API call with the active model.
    // model.limit.context is the full context window in tokens.
    // We capture it once on the first call per session.

    "chat.params": async ({ sessionID, model }) => {
      if (!sessionLimits.has(sessionID)) {
        const limit = model?.limit?.context ?? 0
        if (limit > 0) sessionLimits.set(sessionID, limit)
      }
    },

    // ── 2. Inject system instructions ───────────────────────────────────────

    "experimental.chat.system.transform": async (_ctx, output) => {
      output.system.push([
        "## External Memory & Context Management",
        "",
        "You have three persistent memory tools stored in .opencode/context/:",
        "`save_discovery`, `list_context_archives`, and `read_context_archive`.",
        "",
        "**CRITICAL RULE: THE ANTI-HALLUCINATION PROTOCOL**",
        "If the user asks about past decisions, code implementations, or files that you CANNOT see in your immediate message history, YOU MUST NOT GUESS.",
        "1. Stop.",
        "2. Call `list_context_archives()`.",
        "3. Read the relevant chunks or discoveries.",
        "4. Only then, answer the user.",
        "",
        "**When you receive a [System Notice: Context Sliding Window Triggered]:**",
        "The listed archive file contains the messages that were removed from context.",
        "Use read_context_archive to recover anything you need from it.",
        "",
        "**When you receive a [System: CRITICAL INSTRUCTION — OUTPUT CONTINUATION] notice:**",
        "1. Call read_context_archive with the filename given in the notice.",
        "2. Continue from EXACTLY where the partial output ends.",
        "3. No preamble, no repetition. Pick up mid-sentence if needed.",
        "",
        "**Strategy:**",
        "  · Save your plan before starting a long task.",
        "  · Save key findings after completing each sub-task.",
        "  · Check archives when you cannot find something you worked on earlier.",
      ].join("\n"))
    },

    // ── 3. Output continuation: event-driven truncation detection ───────────
    //
    // Bus events received by this hook (shape: { type: string, properties: any }):
    //
    //   "message.part.delta"
    //     properties: { sessionID, messageID, partID, field, delta }
    //     Fires for every streaming chunk. We filter field === "text" and
    //     accumulate the full output for the current turn in memory.
    //
    //   "session.status"
    //     properties: { sessionID, status: { type: "idle" | "busy" | "retry" } }
    //     Fires when the agent loop finishes a turn (type: "idle").
    //     We query the API to check if the finish reason was "length" and,
    //     if so, write the partial output to disk and inject a continuation.
    //
    // NOTE: OpenCode does not await event hooks (they are fire-and-forget).
    // All async work runs independently and does not block the session.

    event: async ({ event }: { event: any }) => {
      const ev = event as { type: string; properties: any }

      // ── Accumulate streamed text ─────────────────────────────────────────
      if (ev.type === "message.part.delta" && ev.properties?.field === "text") {
        const { sessionID, delta } = ev.properties as { sessionID: string; delta: string }
        sessionAccumulator.set(sessionID, (sessionAccumulator.get(sessionID) ?? "") + delta)
      }

      // ── Detect truncation when the turn finishes ─────────────────────────
      if (
        ev.type === "session.status" &&
        (ev.properties as { status: { type: string } }).status?.type === "idle"
      ) {
        const { sessionID } = ev.properties as { sessionID: string }
        const accumulated = sessionAccumulator.get(sessionID) ?? ""

        // Nothing was streamed this turn (tool-only turn, or compaction) — skip
        if (!accumulated) return

        // FIX: Wrap execution in try/finally to guarantee memory cleanup
        try {
          // Guard against continuation loops
          const continuationCount = sessionContinuationCounts.get(sessionID) ?? 0
          if (continuationCount >= maxContinuations) {
            console.warn(
              `[context-window] Max continuations (${maxContinuations}) reached ` +
              `for session ${sessionID.slice(0, 8)}. Stopping until next user message.`,
            )
            return
          }

          // Small settle wait (see IDLE_SETTLE_MS comment at top of file)
          if (IDLE_SETTLE_MS > 0) await new Promise((r) => setTimeout(r, IDLE_SETTLE_MS))

          const finish = await getLastAssistantFinish(sessionID)

          if (finish === "length") {
            // ── Truncated output: save + continue ──────────────────────────────
            const partialText = accumulated
            const attempt = continuationCount + 1

            let continuationFile: string
            try {
              await ensureDir()
              continuationFile = continuationFilename()
              await writeFile(
                join(archiveDir, continuationFile),
                buildContinuationMarkdown(partialText, sessionID, attempt),
                "utf-8",
              )
              sessionContinuationCounts.set(sessionID, attempt)
              console.log(
                `[context-window] Truncation detected (session ${sessionID.slice(0, 8)}). ` +
                `Saved ${continuationFile}. Sending continuation ${attempt}/${maxContinuations}.`,
              )
            } catch (err) {
              console.error("[context-window] Failed to write continuation file:", err)
              return
            }

            // Mark this session so chat.message knows not to reset the counter
            // when our synthetic prompt fires
            pendingContinuationSessions.add(sessionID)

            try {
              await sendContinuationPrompt(sessionID, continuationFile)
            } catch (err) {
              console.error("[context-window] Failed to send continuation prompt:", err)
              // Remove the pending marker since the prompt never fired
              pendingContinuationSessions.delete(sessionID)
            }
          }
        } finally {
          // Guaranteed memory clear for the current turn's text stream
          sessionAccumulator.delete(sessionID)
        }
      }
    },

    // ── 4. Reset continuation counter on real user messages ─────────────────
    //
    // chat.message fires for EVERY new user message, including our synthetic
    // continuation prompts. We distinguish them via pendingContinuationSessions:
    // if the session is in that set, it's our own injection — skip the reset
    // and remove from the set. Otherwise it's a real user message — reset the
    // continuation counter so the new turn gets a fresh quota.

    "chat.message": async ({ sessionID }, _output) => {
      if (pendingContinuationSessions.has(sessionID)) {
        // Our synthetic continuation prompt — do not reset the counter
        pendingContinuationSessions.delete(sessionID)
      } else {
        // Real user message — give this new turn a fresh continuation quota
        sessionContinuationCounts.delete(sessionID)
      }
    },

    // ── 5. Input sliding window ──────────────────────────────────────────────
    //
    // Fires before every API call. Mutates output.messages IN PLACE —
    // this is the same array reference that toModelMessages() will consume.
    // OpenCode's database is never modified.
    //
    // When context exceeds the threshold:
    //   1. Walk backwards to find the "protected tail" (last N user turns).
    //   2. Archive everything before the tail to a .md file.
    //   3. Replace the archived messages with a single synthetic notice.

    "experimental.chat.messages.transform": async (_ctx, output) => {
      const msgs = output.messages as Array<{ info: any; parts: any[] }>
      if (msgs.length < MIN_MESSAGES_BEFORE_ARCHIVE) return

      const sessionID: string =
        msgs.find((m) => m.info?.sessionID)?.info?.sessionID ?? "unknown"

      const modelContextLimit = sessionLimits.get(sessionID) ?? fallbackLimit
      const threshold = Math.floor(modelContextLimit * thresholdPct)

      // Estimate total input tokens for the current message array
      let totalTokens = 0
      for (const msg of msgs) totalTokens += estimateMessageCost(msg)

      if (totalTokens < threshold) return

      // ── Find protected tail ──────────────────────────────────────────────
      // Walk backwards, count user turns. Everything from protectedFromIndex
      // onwards is kept in context; everything before is archived.
      let userTurnsSeen = 0
      let protectedFromIndex = msgs.length

      for (let i = msgs.length - 1; i >= 0; i--) {
        if (msgs[i]?.info?.role === "user") {
          userTurnsSeen++
          if (userTurnsSeen >= protectedTailTurns) {
            protectedFromIndex = i
            break
          }
        }
      }

      if (protectedFromIndex === 0) return  // Everything is protected — nothing to archive

      const toArchive = msgs.slice(0, protectedFromIndex)
      const toKeep    = msgs.slice(protectedFromIndex)
      if (toArchive.length === 0) return

      let freedTokens = 0
      for (const m of toArchive) freedTokens += estimateMessageCost(m)

      // ── Write chunk archive ──────────────────────────────────────────────
      let archiveFile: string
      try {
        await ensureDir()
        const idx = (sessionChunkCounts.get(sessionID) ?? 0) + 1
        sessionChunkCounts.set(sessionID, idx)
        archiveFile = chunkFilename(idx, sessionID)
        await writeFile(
          join(archiveDir, archiveFile),
          buildChunkMarkdown(toArchive, idx, sessionID, modelContextLimit),
          "utf-8",
        )
      } catch (err) {
        console.error("[context-window] Failed to write chunk archive:", err)
        return  // Leave messages unchanged rather than crashing the turn
      }

      // ── Build synthetic replacement notice ───────────────────────────────
      // This single message replaces all the archived ones.
      // toModelMessages() treats it as a normal user text message.
      const noticeId = `ctx-archive-${Date.now()}`
      
      const noticeText = [
        `[System Notice: Context Sliding Window Triggered]`,
        `To maintain optimal performance, ${toArchive.length} older messages (~${freedTokens.toLocaleString()} estimated tokens)`,
        `were automatically archived to disk.`,
        ``,
        `**Archive Location:** .opencode/context/${archiveFile}`,
        ``,
        `**What is no longer in your immediate memory:**`,
        `The beginning of this conversation up until the last ${protectedTailTurns} user turns.`,
        ``,
        `If the user references something from earlier, use \`list_context_archives()\` and \`read_context_archive("${archiveFile}")\` to retrieve it. Do not ask the user to repeat themselves.`
      ].join("\n")

      // Splice in place — mutates the same reference that toModelMessages() reads
      output.messages.splice(0, output.messages.length, {
        info: {
          id: noticeId,
          role: "user",
          sessionID,
          time: { created: Date.now() },
          agent: msgs[0]?.info?.agent ?? "build",
          model: msgs[0]?.info?.model ?? {},
        },
        parts: [{
          id: `${noticeId}-p`,
          type: "text",
          text: noticeText,
          sessionID,
          messageID: noticeId,
          synthetic: true,
          time: { start: Date.now(), end: Date.now() },
        }],
      }, ...toKeep)
    },

    // ── 6. Improve compaction summary prompt ─────────────────────────────────
    //
    // When OpenCode's built-in compaction fires (context fully overflows despite
    // our sliding window), tell the compaction model about the archive directory
    // so its summary can reference those files.

    "experimental.session.compacting": async (_ctx, output) => {
      output.context.push([
        "",
        "## External Context Archives",
        "This session uses the context-window plugin. Check `.opencode/context/` for:",
        "- `chunk-NNN-*.md`      — auto-archived conversation segments",
        "- `continuation-*.md`  — partial outputs from truncated responses",
        "- `discovery-*.md`     — explicitly saved discoveries",
        "",
        "In your summary, include a section listing which archive files exist",
        "and what each one contains, so the continuation agent knows to check them.",
      ].join("\n"))
    },
  }

  return hooks
}
