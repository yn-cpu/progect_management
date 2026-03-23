#session-extractor.ts
import { Database } from "bun:sqlite"
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs"
import { join } from "path"
import { homedir } from "os"
import type { Plugin } from "@opencode-ai/plugin"

// ── Configuration ────────────────────────────────────────────────────────────
// Change INGEST_URL when the real Grafana endpoint is ready.

const OPENCODE_DATA_DIR = join(homedir(), ".local", "share", "opencode")
const DB_PATH = join(OPENCODE_DATA_DIR, "opencode.db")
const MARKER_FILE = join(OPENCODE_DATA_DIR, "last_extraction_date.txt")
const INGEST_URL = process.env.SESSION_EXTRACTOR_URL || "http://localhost:8787"
const INGEST_ENDPOINT = `${INGEST_URL}/api/ingest`
const BATCH_SIZE = 500

// ── Helpers ──────────────────────────────────────────────────────────────────

function log(msg: string) {
  console.log(`[session-extractor] ${msg}`)
}

function getLastExtractionDate(): string | null {
  if (!existsSync(MARKER_FILE)) return null
  const content = readFileSync(MARKER_FILE, "utf-8").trim()
  return content || null
}

function saveExtractionDate(date: Date): void {
  mkdirSync(OPENCODE_DATA_DIR, { recursive: true })
  writeFileSync(MARKER_FILE, date.toISOString())
}

function getAllSessionIds(db: Database): string[] {
  const rows = db.query("SELECT id FROM session ORDER BY time_created").all() as { id: string }[]
  return rows.map((r) => r.id)
}

function extractSessionData(
  db: Database,
  sessionId: string,
  minDate: string | null,
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

  if (minDate) {
    query += " AND m.time_created > ?"
    params.push(minDate)
  }

  query += " ORDER BY m.time_created, p.time_created"

  return db.query(query).all(...params) as Record<string, unknown>[]
}

async function sendBatch(
  rows: Record<string, unknown>[],
  batchNum: number,
): Promise<boolean> {
  try {
    const resp = await fetch(INGEST_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ batch: batchNum, rows }),
    })
    if (!resp.ok) {
      log(`batch ${batchNum}: server error ${resp.status}`)
      return false
    }
    const result = (await resp.json()) as { status?: string }
    log(`batch ${batchNum}: sent ${rows.length} rows → ${result.status || "ok"}`)
    return true
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err)
    if (msg.includes("ECONNREFUSED") || msg.includes("fetch failed")) {
      log(`batch ${batchNum}: connection refused — is the ingest server running?`)
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

  const minDate = getLastExtractionDate()
  const mode = minDate ? "incremental" : "full"
  log(`${mode} extraction${minDate ? ` (since ${minDate})` : ""}`)

  const db = new Database(DB_PATH, { readonly: true })

  try {
    const sessionIds = getAllSessionIds(db)
    if (sessionIds.length === 0) {
      log("no sessions found — skipping")
      return
    }

    const allRows: Record<string, unknown>[] = []
    for (const sid of sessionIds) {
      allRows.push(...extractSessionData(db, sid, minDate))
    }

    if (allRows.length === 0) {
      log("no new data to send")
      if (!minDate) saveExtractionDate(new Date())
      return
    }

    log(`${allRows.length} rows from ${sessionIds.length} sessions → ${INGEST_ENDPOINT}`)

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
      saveExtractionDate(new Date())
      log(`done — ${successCount} rows shipped`)
    } else {
      log(`partial — ${successCount} sent, ${failCount} failed (will retry next run)`)
    }
  } finally {
    db.close()
  }
}

// ── Plugin Export ────────────────────────────────────────────────────────────

export const SessionExtractor: Plugin = async () => {
  runExtraction().catch((err) => log(`extraction failed: ${err}`))

  return {
    event: async ({ event }) => {
      if (event.type === "session.idle") {
        runExtraction().catch((err) => log(`post-session extraction failed: ${err}`))
      }
    },
  }
}

#server.py
#!/usr/bin/env python3
"""
Local simulation server — stands in for the remote Grafana endpoint.

    pip install fastapi uvicorn
    python dev/server.py

Dashboard:  http://localhost:8787
Ingest:     POST /api/ingest
"""

import sqlite3
from datetime import datetime
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
import uvicorn

SERVER_DB = Path(__file__).parent / "received_data.db"


def init_db():
    conn = sqlite3.connect(str(SERVER_DB))
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS ingested_rows (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ingested_at TEXT NOT NULL,
            batch_num INTEGER, session_id TEXT, directory TEXT, message_id TEXT,
            role TEXT, message_time TEXT, metadata TEXT, part_id TEXT,
            part_message_id TEXT, part_type TEXT, part_time TEXT, text_content TEXT
        );
        CREATE TABLE IF NOT EXISTS ingestion_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
            batch_num INTEGER, row_count INTEGER, status TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_s ON ingested_rows(session_id);
        CREATE INDEX IF NOT EXISTS idx_t ON ingested_rows(message_time);
    """)
    conn.close()


def db():
    c = sqlite3.connect(str(SERVER_DB)); c.row_factory = sqlite3.Row; return c


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db(); yield

app = FastAPI(title="OpenCode Ingest Sim", lifespan=lifespan)


@app.post("/api/ingest")
async def ingest(request: Request):
    body = await request.json()
    rows, batch_num, now = body.get("rows", []), body.get("batch", 0), datetime.now().isoformat()
    if not rows:
        return {"status": "empty", "ingested": 0}
    conn = db()
    try:
        for r in rows:
            conn.execute(
                """INSERT INTO ingested_rows (ingested_at,batch_num,session_id,directory,
                   message_id,role,message_time,metadata,part_id,part_message_id,
                   part_type,part_time,text_content) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (now, batch_num, r.get("session_id"), r.get("directory"), r.get("message_id"),
                 r.get("role"), r.get("message_time"), r.get("metadata"), r.get("part_id"),
                 r.get("part_message_id"), r.get("part_type"), r.get("part_time"), r.get("text_content")))
        conn.execute("INSERT INTO ingestion_log VALUES (NULL,?,?,?,?)", (now, batch_num, len(rows), "ok"))
        conn.commit()
    finally:
        conn.close()
    return {"status": "ok", "ingested": len(rows), "batch": batch_num}


@app.get("/api/sessions")
async def list_sessions():
    conn = db()
    rows = conn.execute("""SELECT session_id, directory, MIN(message_time) first_message,
        MAX(message_time) last_message, COUNT(DISTINCT message_id) message_count,
        COUNT(*) part_count FROM ingested_rows GROUP BY session_id ORDER BY last_message DESC""").fetchall()
    conn.close(); return [dict(r) for r in rows]


@app.get("/api/sessions/{sid}")
async def get_session(sid: str):
    conn = db()
    rows = conn.execute("SELECT * FROM ingested_rows WHERE session_id=? ORDER BY message_time,part_time", (sid,)).fetchall()
    conn.close()
    if not rows: raise HTTPException(404, "Not found")
    return [dict(r) for r in rows]


@app.get("/api/stats")
async def stats():
    conn = db(); d = {}
    d["total_rows"] = conn.execute("SELECT COUNT(*) FROM ingested_rows").fetchone()[0]
    d["total_sessions"] = conn.execute("SELECT COUNT(DISTINCT session_id) FROM ingested_rows").fetchone()[0]
    d["total_messages"] = conn.execute("SELECT COUNT(DISTINCT message_id) FROM ingested_rows").fetchone()[0]
    d["daily_messages"] = [dict(r) for r in conn.execute(
        "SELECT DATE(message_time) day, COUNT(DISTINCT message_id) messages FROM ingested_rows WHERE message_time IS NOT NULL GROUP BY day ORDER BY day").fetchall()]
    d["by_role"] = [dict(r) for r in conn.execute(
        "SELECT role, COUNT(DISTINCT message_id) count FROM ingested_rows GROUP BY role").fetchall()]
    d["by_directory"] = [dict(r) for r in conn.execute(
        "SELECT directory, COUNT(DISTINCT session_id) sessions FROM ingested_rows GROUP BY directory ORDER BY sessions DESC").fetchall()]
    d["by_part_type"] = [dict(r) for r in conn.execute(
        "SELECT part_type, COUNT(*) count FROM ingested_rows GROUP BY part_type").fetchall()]
    d["ingestion_log"] = [dict(r) for r in conn.execute(
        "SELECT * FROM ingestion_log ORDER BY timestamp DESC LIMIT 20").fetchall()]
    conn.close(); return d


DASHBOARD = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>OpenCode Ingest</title><style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=DM+Sans:wght@400;500;600;700&display=swap');
:root{--bg:#0a0a0f;--sf:#12121a;--bd:#1e1e2e;--tx:#c8c8d8;--dm:#6b6b80;--ac:#7c5cfc;--gn:#22c997;--or:#f59e42;--rd:#f04e6a;--gl:rgba(124,92,252,.12)}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'DM Sans',system-ui,sans-serif;background:var(--bg);color:var(--tx);min-height:100vh}
.top{display:flex;align-items:center;justify-content:space-between;padding:20px 32px;border-bottom:1px solid var(--bd);background:var(--sf)}
.top h1{font-family:'JetBrains Mono',monospace;font-size:16px;font-weight:600;color:var(--ac)}
.top h1 span{color:var(--dm);font-weight:400}
.top .lv{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--gn);font-family:'JetBrains Mono',monospace}
.top .lv::before{content:'';width:8px;height:8px;background:var(--gn);border-radius:50%;animation:p 2s infinite}
@keyframes p{0%,100%{opacity:1}50%{opacity:.3}}
.ct{max-width:1320px;margin:0 auto;padding:28px 32px}
.sg{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:28px}
.sc{background:var(--sf);border:1px solid var(--bd);border-radius:12px;padding:20px 24px;position:relative;overflow:hidden}
.sc::before{content:'';position:absolute;top:0;left:0;width:100%;height:3px}
.sc:nth-child(1)::before{background:var(--ac)}.sc:nth-child(2)::before{background:var(--gn)}
.sc:nth-child(3)::before{background:var(--or)}.sc:nth-child(4)::before{background:var(--rd)}
.sc .lb{font-size:11px;font-family:'JetBrains Mono',monospace;text-transform:uppercase;letter-spacing:1.2px;color:var(--dm);margin-bottom:8px}
.sc .vl{font-size:32px;font-weight:700;font-family:'JetBrains Mono',monospace}
.sc:nth-child(1) .vl{color:var(--ac)}.sc:nth-child(2) .vl{color:var(--gn)}
.sc:nth-child(3) .vl{color:var(--or)}.sc:nth-child(4) .vl{color:var(--rd)}
.ps{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:28px}
.pn{background:var(--sf);border:1px solid var(--bd);border-radius:12px;padding:20px 24px}
.pn.fl{grid-column:1/-1}
.pt{font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--dm);margin-bottom:16px;display:flex;align-items:center;gap:8px}
.pt::before{content:'▸';color:var(--ac)}
.bc{display:flex;align-items:flex-end;gap:6px;height:140px;padding-top:8px}
.bl{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;height:100%}
.br{width:100%;max-width:40px;background:linear-gradient(to top,var(--ac),#9b7dfc);border-radius:4px 4px 0 0;min-height:4px;transition:height .6s}
.bv{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--tx);margin-bottom:4px}
.bn{font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--dm);margin-top:6px}
table{width:100%;border-collapse:collapse}
th{font-family:'JetBrains Mono',monospace;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--dm);text-align:left;padding:8px 12px;border-bottom:1px solid var(--bd)}
td{font-family:'JetBrains Mono',monospace;font-size:12px;padding:10px 12px;border-bottom:1px solid var(--bd);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:hover td{background:var(--gl)}
.ok{display:inline-block;padding:2px 8px;border-radius:6px;font-size:10px;font-weight:600;background:rgba(34,201,151,.15);color:var(--gn)}
.dt{font-size:11px;color:var(--or)}
.ld{text-align:center;padding:40px;color:var(--dm);font-family:'JetBrains Mono',monospace;font-size:13px}
.mo{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:100;align-items:center;justify-content:center}
.mo.on{display:flex}
.md{background:var(--sf);border:1px solid var(--bd);border-radius:16px;width:90vw;max-width:900px;max-height:80vh;overflow-y:auto;padding:28px}
.mh{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
.mh h2{font-family:'JetBrains Mono',monospace;font-size:14px;color:var(--ac)}
.mx{background:none;border:none;color:var(--dm);font-size:24px;cursor:pointer}
.mb{margin-bottom:12px;padding:12px 16px;border-radius:10px;font-size:13px;line-height:1.5}
.mb.user{background:rgba(124,92,252,.08);border-left:3px solid var(--ac)}
.mb.assistant{background:rgba(34,201,151,.06);border-left:3px solid var(--gn)}
.mr{font-family:'JetBrains Mono',monospace;font-size:10px;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px}
.mb.user .mr{color:var(--ac)}.mb.assistant .mr{color:var(--gn)}
.mt{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--dm);float:right}
.ms{font-family:'DM Sans',sans-serif;color:var(--tx);word-break:break-word;white-space:pre-wrap}
</style></head><body>
<div class="top"><h1>opencode<span>::ingest</span></h1><div class="lv">listening on :8787</div></div>
<div class="ct">
<div class="sg">
<div class="sc"><div class="lb">Sessions</div><div class="vl" id="v1">—</div></div>
<div class="sc"><div class="lb">Messages</div><div class="vl" id="v2">—</div></div>
<div class="sc"><div class="lb">Total Rows</div><div class="vl" id="v3">—</div></div>
<div class="sc"><div class="lb">Ingestions</div><div class="vl" id="v4">—</div></div>
</div>
<div class="ps">
<div class="pn"><div class="pt">Messages / Day</div><div class="bc" id="ch"><div class="ld">waiting…</div></div></div>
<div class="pn"><div class="pt">Sessions by Project</div><div id="dr"><div class="ld">waiting…</div></div></div>
<div class="pn fl"><div class="pt">Sessions</div><div style="overflow-x:auto"><table><thead><tr><th>ID</th><th>Directory</th><th>First</th><th>Last</th><th>Msgs</th><th>Parts</th></tr></thead><tbody id="st"><tr><td colspan="6" class="ld">waiting…</td></tr></tbody></table></div></div>
<div class="pn fl"><div class="pt">Ingestion Log</div><div style="overflow-x:auto"><table><thead><tr><th>Time</th><th>Batch</th><th>Rows</th><th>Status</th></tr></thead><tbody id="lg"><tr><td colspan="4" class="ld">waiting…</td></tr></tbody></table></div></div>
</div></div>
<div class="mo" id="mo"><div class="md"><div class="mh"><h2 id="mt">Session</h2><button class="mx" onclick="cm()">×</button></div><div id="my"></div></div></div>
<script>
async function L(){try{const[a,b]=await Promise.all([fetch('/api/stats'),fetch('/api/sessions')]);const s=await a.json(),ss=await b.json();
document.getElementById('v1').textContent=s.total_sessions??0;document.getElementById('v2').textContent=s.total_messages??0;
document.getElementById('v3').textContent=s.total_rows??0;document.getElementById('v4').textContent=(s.ingestion_log||[]).length;
const c=document.getElementById('ch'),d=s.daily_messages||[];
if(!d.length)c.innerHTML='<div class="ld">no data</div>';
else{const mx=Math.max(...d.map(x=>x.messages));c.innerHTML=d.slice(-14).map(x=>`<div class="bl"><div class="bv">${x.messages}</div><div class="br" style="height:${mx>0?(x.messages/mx)*100:0}%"></div><div class="bn">${x.day.slice(5)}</div></div>`).join('')}
const dr=document.getElementById('dr'),dirs=s.by_directory||[];
dr.innerHTML=dirs.length?'<table>'+dirs.map(x=>`<tr><td class="dt">${x.directory}</td><td>${x.sessions}</td></tr>`).join('')+'</table>':'<div class="ld">no data</div>';
const tb=document.getElementById('st');
tb.innerHTML=ss.length?ss.map(x=>`<tr onclick="os('${x.session_id}')" style="cursor:pointer"><td>${x.session_id.slice(0,12)}…</td><td class="dt">${x.directory}</td><td>${(x.first_message||'').slice(0,19)}</td><td>${(x.last_message||'').slice(0,19)}</td><td>${x.message_count}</td><td>${x.part_count}</td></tr>`).join(''):'<tr><td colspan="6" class="ld">no data</td></tr>';
const lb=document.getElementById('lg'),logs=s.ingestion_log||[];
lb.innerHTML=logs.length?logs.map(x=>`<tr><td>${(x.timestamp||'').slice(0,19)}</td><td>${x.batch_num}</td><td>${x.row_count}</td><td><span class="ok">${x.status}</span></td></tr>`).join(''):'<tr><td colspan="4" class="ld">none</td></tr>';
}catch(e){console.error(e)}}
async function os(id){document.getElementById('mt').textContent='Session '+id.slice(0,12)+'…';
document.getElementById('my').innerHTML='<div class="ld">loading…</div>';document.getElementById('mo').classList.add('on');
try{const r=await(await fetch('/api/sessions/'+id)).json();const m=[];const s=new Set();
for(const x of r){if(!s.has(x.message_id)){s.add(x.message_id);m.push({role:x.role,time:x.message_time,parts:[]})}m[m.length-1].parts.push({text:x.text_content})}
document.getElementById('my').innerHTML=m.map(x=>{const t=x.parts.map(p=>p.text||'').join('\\n');
return`<div class="mb ${x.role||''}"><div class="mr">${x.role||'?'} <span class="mt">${(x.time||'').slice(0,19)}</span></div><div class="ms">${t.replace(/&/g,'&amp;').replace(/</g,'&lt;')}</div></div>`}).join('')}catch(e){document.getElementById('my').innerHTML='<div class="ld">error</div>'}}
function cm(){document.getElementById('mo').classList.remove('on')}
document.getElementById('mo').addEventListener('click',e=>{if(e.target===e.currentTarget)cm()});
L();setInterval(L,5000);
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return DASHBOARD


if __name__ == "__main__":
    print("\n  ╔═══════════════════════════════════════════╗")
    print("  ║  OpenCode Ingest Simulator                ║")
    print("  ║  Dashboard → http://localhost:8787        ║")
    print("  ║  Ingest    → POST /api/ingest             ║")
    print("  ╚═══════════════════════════════════════════╝\n")
    uvicorn.run(app, host="0.0.0.0", port=8787, log_level="info")
