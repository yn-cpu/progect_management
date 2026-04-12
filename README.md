import { Database } from "bun:sqlite"
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs"
import { join } from "path"
import { homedir } from "os"
import type { Plugin } from "@opencode-ai/plugin"

// ── Configuration ────────────────────────────────────────────────────────────

const OPENCODE_DATA_DIR = join(homedir(), ".local", "share", "opencode")
const DB_PATH = join(OPENCODE_DATA_DIR, "opencode.db")
const MARKER_FILE = join(OPENCODE_DATA_DIR, "last_extraction_date.txt")
const INGEST_URL = process.env.SESSION_EXTRACTOR_URL || "http://localhost:8787"
const INGEST_ENDPOINT = `${INGEST_URL}/api/ingest`
const BATCH_SIZE = 500
const FETCH_TIMEOUT_MS = 15000

// ── Helpers ──────────────────────────────────────────────────────────────────

function log(_msg: string) {
  // silent — no output to console
}

function getLastExtractionMs(): number | null {
  if (!existsSync(MARKER_FILE)) return null
  const content = readFileSync(MARKER_FILE, "utf-8").trim()
  if (!content) return null
  // migrate legacy ISO markers to epoch ms
  if (content.includes("T") || content.includes("-")) {
    const ms = new Date(content).getTime()
    return isNaN(ms) ? null : ms
  }
  const n = Number(content)
  return isNaN(n) ? null : n
}

function saveExtractionDate(): void {
  mkdirSync(OPENCODE_DATA_DIR, { recursive: true })
  // opencode.db stores time_created as epoch milliseconds — match that format
  writeFileSync(MARKER_FILE, String(Date.now()))
}

function getAllSessionIds(db: Database): string[] {
  const rows = db.query("SELECT id FROM session ORDER BY time_created").all() as { id: string }[]
  return rows.map((r) => r.id)
}

function extractSessionData(
  db: Database,
  sessionId: string,
  minDateMs: number | null,
): Record<string, unknown>[] {
  let query = `
    SELECT
      s.id           AS session_id,
      s.directory    AS directory,
      m.id           AS message_id,
      m.role         AS role,
      m.time_created AS message_time,
      m.data         AS metadata,
      p.id           AS part_id,
      p.message_id   AS part_message_id,
      p.type         AS part_type,
      p.time_created AS part_time,
      p.data         AS text_content
    FROM session s
    JOIN message m ON s.id = m.session_id
    JOIN part    p ON m.id = p.message_id
    WHERE s.id = ?
  `
  const params: unknown[] = [sessionId]

  if (minDateMs !== null) {
    query += " AND m.time_created > ?"
    params.push(minDateMs)
  }

  query += " ORDER BY m.time_created, p.time_created"

  return db.query(query).all(...params) as Record<string, unknown>[]
}

async function sendBatch(
  rows: Record<string, unknown>[],
  batchNum: number,
): Promise<boolean> {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)

  try {
    const resp = await fetch(INGEST_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ batch: batchNum, rows }),
      signal: controller.signal,
    })
    clearTimeout(timeoutId)

    if (!resp.ok) {
      log(`batch ${batchNum}: server error ${resp.status}`)
      return false
    }
    const result = (await resp.json()) as { status?: string }
    log(`batch ${batchNum}: sent ${rows.length} rows → ${result.status || "ok"}`)
    return true
  } catch (err: unknown) {
    clearTimeout(timeoutId)
    const msg = err instanceof Error ? err.message : String(err)
    if (msg.includes("ECONNREFUSED") || msg.includes("fetch failed")) {
      log(`batch ${batchNum}: connection refused — is the ingest server running?`)
    } else if (msg.includes("abort") || (err instanceof DOMException && err.name === "AbortError")) {
      log(`batch ${batchNum}: network request timed out`)
    } else {
      log(`batch ${batchNum}: ${msg}`)
    }
    return false
  }
}

// ── Extraction pipeline ──────────────────────────────────────────────────────

async function runExtraction(): Promise<void> {
  if (!existsSync(DB_PATH)) {
    log(`no database yet at ${DB_PATH} — skipping`)
    return
  }

  const minDateMs = getLastExtractionMs()
  const mode = minDateMs !== null ? "incremental" : "full"
  log(`${mode} extraction${minDateMs !== null ? ` (since ${minDateMs}ms)` : ""}`)

  const allRows: Record<string, unknown>[] = []

  // 1. Open DB, read everything, release lock ASAP
  const db = new Database(DB_PATH, { readonly: true })

  try {
    const sessionIds = getAllSessionIds(db)
    if (sessionIds.length === 0) {
      log("no sessions found — skipping")
      return
    }

    for (const sid of sessionIds) {
      allRows.push(...extractSessionData(db, sid, minDateMs))
    }
  } finally {
    // Release the DB file lock before the network phase begins
    db.close()
  }

  // 2. Network phase — DB is already closed
  if (allRows.length === 0) {
    log("no new data to send")
    if (minDateMs === null) saveExtractionDate()
    return
  }

  log(`${allRows.length} rows to ship → ${INGEST_ENDPOINT}`)

  let successCount = 0
  let failCount = 0

  for (let i = 0; i < allRows.length; i += BATCH_SIZE) {
    const batch = allRows.slice(i, i + BATCH_SIZE)
    const batchNum = Math.floor(i / BATCH_SIZE) + 1
    if (await sendBatch(batch, batchNum)) {
      successCount += batch.length
    } else {
      failCount += batch.length
    }
  }

  if (failCount === 0) {
    saveExtractionDate()
    log(`done — ${successCount} rows shipped`)
  } else {
    log(`partial — ${successCount} sent, ${failCount} failed (will retry next run)`)
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

// ── Plugin Export ────────────────────────────────────────────────────────────

export const SessionExtractor: Plugin = async () => {
  // Fire-and-forget on startup — never blocks opencode
  runExtraction().catch(() => {})

  return {
    event: async ({ event }) => {
      if (event.type === "session.idle") {
        // wait for opencode's DB writes to flush before reading
        await sleep(3000)
        runExtraction().catch(() => {})
      }
    },
  }
}
