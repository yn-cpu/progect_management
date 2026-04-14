
import type { Plugin, Hooks } from "@opencode-ai/plugin"
import { tool } from "@opencode-ai/plugin"
import { mkdir, writeFile, readFile, readdir, appendFile } from "fs/promises"
import { join } from "path"
import { Buffer } from "node:buffer"

// ─────────────────────────────────────────────────────────────────────────────
// Tunables (Edit these directly instead of opencode.json)
// ─────────────────────────────────────────────────────────────────────────────

const THRESHOLD_PCT = 0.75
const PROTECTED_TAIL_TURNS = 4
const CONTEXT_LIMIT = 245_000
const MAX_CONTINUATIONS = 5
const CONTINUATION_DELAY_MS = 500

const CHARS_PER_TOKEN = 4
const ARCHIVE_SUBDIR = ".opencode/context"
const INDEX_FILENAME = "index.md"
const MIN_MESSAGES_BEFORE_ARCHIVE = 6
const MAX_TOOL_OUTPUT_IN_ARCHIVE = 20_000

// ─────────────────────────────────────────────────────────────────────────────
// Token estimation & Helpers
// ─────────────────────────────────────────────────────────────────────────────

function estimateTokens(text: string | undefined | null): number {
  if (!text) return 0
  return Math.ceil(text.length / CHARS_PER_TOKEN)
}

function estimateMessageCost(msg: { info: any; parts: any[] }): number {
  let tokens = 0
  for (const part of msg.parts ?? []) {
    if (part.type === "text" && part.text) tokens += estimateTokens(part.text)
    if (part.type === "reasoning" && part.text) tokens += estimateTokens(part.text)
    if (part.type === "tool" && part.state?.status === "completed") tokens += estimateTokens(part.state.output)
    if (part.type === "tool" && part.state?.status === "error") tokens += estimateTokens(part.state.error)
  }
  return tokens
}

function chunkFilename(idx: number, sessionID: string): string {
  return `chunk-${String(idx).padStart(3, "0")}-${sessionID.slice(0, 8)}.md`
}

function continuationFilename(): string {
  return `continuation-${Date.now()}-${Math.random().toString(36).slice(2, 6)}.md`
}

function discoveryFilename(title: string): string {
  const safe = title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 50)
  return `discovery-${safe}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}.md`
}

function buildChunkMarkdown(messages: Array<{ info: any; parts: any[] }>, idx: number, sessionID: string, contextLimit: number): string {
  const lines = [
    `# Context Archive — Chunk ${idx}`, ``, `| | |`, `|---|---|`,
    `| **Session** | \`${sessionID.slice(0, 14)}…\` |`,
    `| **Archived at** | ${new Date().toISOString()} |`,
    `| **Messages** | ${messages.length} |`,
    `| **Model context limit** | ${contextLimit.toLocaleString()} tokens |`, ``,
    `> Retrieve with \`read_context_archive("${chunkFilename(idx, sessionID)}")\``, ``, `---`, ``
  ]
  for (const msg of messages) {
    const label = msg.info?.role === "assistant" ? "🤖 **Assistant**" : "👤 **User**"
    const content: string[] = []
    for (const part of msg.parts ?? []) {
      if (part.synthetic) continue
      if (part.type === "text" && part.text && !part.ignored) content.push(part.text.trim())
      if (part.type === "reasoning" && part.text) content.push(`*[Reasoning truncated for archive]*`)
      if (part.type === "tool") {
        const name = part.tool ?? "unknown"
        if (part.state?.status === "completed") {
          const raw = part.state.output ?? ""
          const out = raw.length > MAX_TOOL_OUTPUT_IN_ARCHIVE ? raw.slice(0, MAX_TOOL_OUTPUT_IN_ARCHIVE) + `\n…[${raw.length} chars truncated]` : raw
          content.push(`**Tool \`${name}\`** → ${part.state.title ?? ""}`)
          if (out.trim()) content.push("```\n" + out.trim() + "\n```")
        } else if (part.state?.status === "error") {
          content.push(`**Tool \`${name}\` ✗** ${part.state.error ?? "error"}`)
        }
      }
    }
    if (content.length > 0) lines.push(`## ${label}`, ``, content.join("\n\n"), ``, `---`, ``)
  }
  return lines.join("\n")
}

function buildContinuationMarkdown(partialText: string, sessionID: string, attempt: number): string {
  return [
    `# Partial Output — Continuation ${attempt}`, ``, `| | |`, `|---|---|`,
    `| **Session** | \`${sessionID.slice(0, 14)}…\` |`,
    `| **Saved at** | ${new Date().toISOString()} |`,
    `| **Continuation #** | ${attempt} |`, ``,
    `> The previous response was cut off by the model's output limit.`, ``, `---`, ``,
    `## Partial Output`, ``, partialText, ``, `---`, ``,
    `*Continue directly from the last word above. No preamble.*`,
  ].join("\n")
}

// ─────────────────────────────────────────────────────────────────────────────
// Plugin Execution
// ─────────────────────────────────────────────────────────────────────────────

export const ContextWindowPlugin: Plugin = async (input) => {
  const archiveDir = join(input.directory, ARCHIVE_SUBDIR)
  async function ensureDir() { await mkdir(archiveDir, { recursive: true }) }

  const serverAuthHeader: Record<string, string> = process.env.OPENCODE_SERVER_PASSWORD
    ? { Authorization: `Basic ${Buffer.from(`${process.env.OPENCODE_SERVER_USERNAME ?? "opencode"}:${process.env.OPENCODE_SERVER_PASSWORD}`).toString("base64")}` }
    : {}

  const sessionLimits = new Map<string, number>()
  const sessionChunkCounts = new Map<string, number>()
  const sessionContinuationCounts = new Map<string, number>()
  const sessionAccumulator = new Map<string, string>()
  const pendingContinuationSessions = new Set<string>()

  async function getLastAssistantFinish(sessionID: string): Promise<string | null> {
    try {
      const url = new URL(`/session/${sessionID}/message`, input.serverUrl)
      const res = await fetch(url.toString(), { headers: serverAuthHeader })
      if (!res.ok) return null
      const messages = await res.json()
      if (!Array.isArray(messages)) return null
      const lastAssistant = [...messages].reverse().find((m) => m.info?.role === "assistant")
      return lastAssistant?.info?.finish ?? null
    } catch { return null }
  }

  async function sendContinuationPrompt(sessionID: string, continuationFile: string): Promise<void> {
    const text = [
      `[System: CRITICAL INSTRUCTION — OUTPUT CONTINUATION]`,
      `Your previous response was forcefully cut off by the max output token limit.`,
      `The partial output has been saved to: .opencode/context/${continuationFile}`, ``,
      `Instructions:`,
      `1. Call: read_context_archive("${continuationFile}") to see exactly where you were cut off.`,
      `2. Resume typing EXACTLY from the next character.`,
      `3. Do NOT output conversational filler.`,
      `4. MARKDOWN RULE: If cut off inside a code block (\`\`\`), DO NOT output a new \`\`\` language tag. Just raw code.`
    ].join("\n")

    const url = new URL(`/session/${sessionID}/prompt_async`, input.serverUrl)
    await fetch(url.toString(), {
      method: "POST",
      headers: { "Content-Type": "application/json", ...serverAuthHeader },
      body: JSON.stringify({ parts: [{ type: "text", text, synthetic: true }] }),
    })
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Production Safe Index Writer Queue
  // ───────────────────────────────────────────────────────────────────────────
  let indexWriteQueue = Promise.resolve()

  function enqueueIndexWrite(filePath: string, content: string) {
    indexWriteQueue = indexWriteQueue
      .then(() => appendFile(filePath, content, "utf-8"))
      .catch((err) => console.error("[ContextPlugin] Failed to write index.md:", err))
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Background Summarizer (Fire & Forget)
  // ───────────────────────────────────────────────────────────────────────────
  async function generateAndAppendSummary(archiveFile: string, messages: Array<{ info: any; parts: any[] }>) {
    try {
      let transcript = ""
      const MAX_TRANSCRIPT_CHARS = 12000 // ~3000 tokens max for the summarizer

      for (const msg of messages) {
        if (transcript.length >= MAX_TRANSCRIPT_CHARS) break

        const role = msg.info?.role === "user" ? "User" : "Assistant"
        for (const part of msg.parts ?? []) {
          if (part.type === "text" && part.text) {
            const text = part.text.length > 1000 ? part.text.slice(0, 1000) + "\n...[truncated]" : part.text
            transcript += `${role}: ${text}\n\n`
          }
        }
      }

      transcript = transcript.slice(0, MAX_TRANSCRIPT_CHARS)

      const systemPrompt = "You are a context-indexing assistant. Summarize the following conversation log in 1 to 2 very short, highly descriptive bullet points. Focus ONLY on the main topics discussed, bugs fixed, or specific files mentioned. Be extremely concise. Do not use conversational filler."
      
      const url = new URL(`/prompt`, input.serverUrl) 
      const res = await fetch(url.toString(), {
        method: "POST",
        headers: { "Content-Type": "application/json", ...serverAuthHeader },
        body: JSON.stringify({
          system: systemPrompt,
          parts: [{ type: "text", text: transcript }]
        }),
      })

      if (!res.ok) throw new Error(`Server returned ${res.status}: ${res.statusText}`)
      
      const data = await res.json()
      const summaryText = data.text ?? data.parts?.[0]?.text ?? "- Summary unavailable."

      const indexEntry = [
        `### File: \`${archiveFile}\``,
        `- **Archived:** ${new Date().toISOString()}`,
        `- **Contains:** ${messages.length} messages`,
        `- **Contents:**\n${summaryText.trim()}`,
        `\n---\n`
      ].join('\n')
      
      enqueueIndexWrite(join(archiveDir, INDEX_FILENAME), indexEntry)

    } catch (err) {
      console.error(`[ContextPlugin] Background summarizer failed for ${archiveFile}:`, err)
      const fallbackEntry = `### File: \`${archiveFile}\`\n- **Archived:** ${new Date().toISOString()}\n- *(Summary generation failed)*\n\n---\n`
      enqueueIndexWrite(join(archiveDir, INDEX_FILENAME), fallbackEntry)
    }
  }

  const hooks: Hooks = {
    tool: {
      save_discovery: tool({
        description: "Save an important finding, architectural decision, or plan to persistent external memory. Survive session restarts.",
        args: {
          title: tool.schema.string().describe("Short descriptive title"),
          content: tool.schema.string().describe("Full content to save"),
        },
        async execute({ title, content }) {
          await ensureDir()
          const filename = discoveryFilename(title)
          await writeFile(join(archiveDir, filename), `# Discovery: ${title}\n\n${content}`, "utf-8")
          return `✓ Saved to .opencode/context/${filename}\nRetrieve with: read_context_archive("${filename}")`
        },
      }),
      read_context_archive: tool({
        description: "Read an archived context file, saved discovery, or the master index.md.",
        args: { filename: tool.schema.string() },
        async execute({ filename }) {
          try { return await readFile(join(archiveDir, filename), "utf-8") }
          catch { return `File "${filename}" not found.` }
        },
      }),
      list_context_archives: tool({
        description: "List all archived files AND output the master index summaries. Call this to figure out which chunks to load.",
        args: {},
        async execute() {
          try {
            await ensureDir()
            const all = (await readdir(archiveDir)).filter((f) => f.endsWith(".md") && f !== INDEX_FILENAME).sort()
            if (all.length === 0) return "No archived files yet."

            let indexData = "No index available."
            try {
              indexData = await readFile(join(archiveDir, INDEX_FILENAME), "utf-8")
            } catch (err) {
              // Ignore if index.md doesn't exist yet
            }

            return `## Available Files\n${all.map(f => `- \`${f}\``).join("\n")}\n\n## Master Context Index\n${indexData}`
          } catch { return "No archives found." }
        },
      })
    },

    "chat.params": async (hookInput) => {
      if (!sessionLimits.has(hookInput.sessionID)) {
        const limit = hookInput.model?.limit?.context ?? 0
        if (limit > 0) sessionLimits.set(hookInput.sessionID, limit)
      }
    },

    "experimental.chat.system.transform": async (_ctx, output) => {
      output.system.push([
        "## External Memory & Context Management",
        "**CRITICAL RULE: THE ANTI-HALLUCINATION PROTOCOL**",
        "If asked about past decisions not visible in history, DO NOT GUESS.",
        "1. Stop.",
        "2. Call `list_context_archives()` to review the Master Context Index.",
        "3. Identify exactly which chunk file contains the relevant context based on the summaries.",
        "4. Call `read_context_archive(\"chunk-XXX...\")` to read that specific chunk.",
        "5. Answer the question.",
        "When you receive an output continuation notice, call read_context_archive and continue exactly where it ends."
      ].join("\n"))
    },

    event: async ({ event }) => {
      const ev = event as { type: string; properties: any }
      if (ev.type === "message.part.delta" && ev.properties?.field === "text") {
        const { sessionID, delta } = ev.properties
        sessionAccumulator.set(sessionID, (sessionAccumulator.get(sessionID) ?? "") + delta)
      }
      
      if (ev.type === "session.status" && ev.properties?.status?.type === "idle") {
        const sessionID = ev.properties.sessionID
        const accumulated = sessionAccumulator.get(sessionID) ?? ""
        if (!accumulated) return

        try {
          const continuationCount = sessionContinuationCounts.get(sessionID) ?? 0
          if (continuationCount >= MAX_CONTINUATIONS) return

          await new Promise((r) => setTimeout(r, CONTINUATION_DELAY_MS))
          const finish = await getLastAssistantFinish(sessionID)

          if (finish === "length") {
            const attempt = continuationCount + 1
            let continuationFile = continuationFilename()
            
            try {
              await ensureDir()
              await writeFile(join(archiveDir, continuationFile), buildContinuationMarkdown(accumulated, sessionID, attempt), "utf-8")
              sessionContinuationCounts.set(sessionID, attempt)
            } catch (err) { return }

            pendingContinuationSessions.add(sessionID)
            try { await sendContinuationPrompt(sessionID, continuationFile) }
            catch (err) { pendingContinuationSessions.delete(sessionID) }
          }
        } finally {
          sessionAccumulator.delete(sessionID)
        }
      }
    },

    "chat.message": async ({ sessionID }) => {
      if (pendingContinuationSessions.has(sessionID)) {
        pendingContinuationSessions.delete(sessionID)
      } else {
        sessionContinuationCounts.delete(sessionID)
      }
    },

    "experimental.chat.messages.transform": async (_ctx, output) => {
      const msgs = output.messages as Array<{ info: any; parts: any[] }>
      if (msgs.length < MIN_MESSAGES_BEFORE_ARCHIVE) return
      
      const sessionID = msgs.find((m) => m.info?.sessionID)?.info?.sessionID ?? "unknown"
      const modelContextLimit = sessionLimits.get(sessionID) ?? CONTEXT_LIMIT
      const threshold = Math.floor(modelContextLimit * THRESHOLD_PCT)

      let totalTokens = 0
      for (const msg of msgs) totalTokens += estimateMessageCost(msg)
      if (totalTokens < threshold) return

      let userTurnsSeen = 0
      let protectedFromIndex = msgs.length
      for (let i = msgs.length - 1; i >= 0; i--) {
        if (msgs[i]?.info?.role === "user") {
          userTurnsSeen++
          if (userTurnsSeen >= PROTECTED_TAIL_TURNS) {
            protectedFromIndex = i
            break
          }
        }
      }

      if (protectedFromIndex === 0) return
      const toArchive = msgs.slice(0, protectedFromIndex)
      const toKeep = msgs.slice(protectedFromIndex)

      let freedTokens = 0
      for (const m of toArchive) freedTokens += estimateMessageCost(m)

      let archiveFile: string
      try {
        await ensureDir()
        const idx = (sessionChunkCounts.get(sessionID) ?? 0) + 1
        sessionChunkCounts.set(sessionID, idx)
        archiveFile = chunkFilename(idx, sessionID)
        
        // 1. Write the chunk file to disk synchronously
        await writeFile(join(archiveDir, archiveFile), buildChunkMarkdown(toArchive, idx, sessionID, modelContextLimit), "utf-8")
        
        // 2. Fire and forget the LLM background summarizer
        generateAndAppendSummary(archiveFile, toArchive).catch(() => {})

      } catch { return }

      const noticeId = `ctx-archive-${Date.now()}`
      output.messages.splice(0, output.messages.length, {
        info: { id: noticeId, role: "user", sessionID, time: { created: Date.now() }, agent: msgs[0]?.info?.agent ?? "build", model: msgs[0]?.info?.model ?? {} },
        parts: [{
          id: `${noticeId}-p`, type: "text", synthetic: true, time: { start: Date.now(), end: Date.now() },
          text: `[System Notice]\n${toArchive.length} older messages (~${freedTokens} tokens) automatically archived to disk to stay within context limits.\nLocation: .opencode/context/${archiveFile}\nUse list_context_archives() to read the master index if needed.`
        }],
      }, ...toKeep)
    },

    "experimental.session.compacting": async (_ctx, output) => {
      output.context.push("Check `.opencode/context/` for archived chunks, continuations, and discoveries.")
    }
  }

  return hooks
}
