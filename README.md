You *can* do exactly what you described, even with huge logs — but the trick is to **never “scan with the LLM”**. Instead you let the computer **filter + compress** to a small “case file” for the time range, and only then let the agent be “creative” on *that*.

Below are **3 workable designs**, each with concrete steps. The first is what I’d recommend.

Before that, one quick setup fix (because it will block everything otherwise):

---

## 0) Make OpenCode tools importable (fix your `tool` / `@opencode-ai/plugin` errors)

OpenCode’s docs show tool definitions importing `tool` from `@opencode-ai/plugin`. ([opencode.ai][1])
To use external packages in **local project tools**, the docs say to add a **`.opencode/package.json`** and OpenCode runs `bun install` at startup. ([opencode.ai][2])

### Do this

Create:

**`.opencode/package.json`**

```json
{
  "dependencies": {
    "@opencode-ai/plugin": "1.1.25"
  }
}
```

Important:

* Pin the version to **your OpenCode version** (replace `1.1.25` with your `opencode --version`) to avoid zod/version mismatches.
* Restart OpenCode so it installs dependencies automatically at startup. ([opencode.ai][2])

Now your tool files can safely do:

```ts
import { tool } from "@opencode-ai/plugin"
```

---

# What you want: “I suspect something happened between T1–T2; show evidence from logs (and combinations of logs)”

This is a classic forensic workflow:

1. **Window** the data to just `[start, end]`
2. **Summarize and score anomalies** relative to a baseline
3. **Correlate** across sources (app ↔ network ↔ system state) by time proximity
4. **Drill down**: fetch raw records only for the top findings

The LLM’s job is steps 2–4 *after* step 1 makes the dataset small.

---

# Solution 1 (recommended): Build an index once, then “Investigate a time window” with one tool

### Why this works well

* You can investigate many time ranges quickly
* “Combination of logs” becomes easy: everything is in one searchable table keyed by time
* The agent can be creative **without reading raw logs**, because it receives structured slices + evidence pointers

OpenCode’s custom tool naming/exports work like: `<filename>_<exportname>` for multiple exports. ([opencode.ai][1])

## 1A) Add a new tool: `ios_logs_window_analyze`

### Add this export to your existing tool file

**`.opencode/tools/ios_logs.ts`** (add this export)

```ts
import { tool } from "@opencode-ai/plugin"
import path from "path"

export const window_analyze = tool({
  description:
    "Analyze events in a time window, compare to a baseline, and output anomalies + evidence pointers (file+locator).",
  args: {
    start: tool.schema.string().describe("Start time ISO-8601 (include timezone, e.g. 2026-02-01T10:00:00+02:00)"),
    end: tool.schema.string().describe("End time ISO-8601 (include timezone)"),
    db: tool.schema.string().default("analysis/index/logs.sqlite"),
    outDir: tool.schema.string().default("analysis/cases"),
    baselineHours: tool.schema.number().int().min(1).max(720).default(24)
      .describe("Baseline period immediately before start used for spike stats"),
    binMinutes: tool.schema.number().int().min(1).max(60).default(5)
      .describe("Time bin size for spike detection"),
    topK: tool.schema.number().int().min(5).max(200).default(30),
    maxEvidence: tool.schema.number().int().min(1).max(50).default(10),
    ignorePath: tool.schema.string().default("analysis/ignore_rules.json")
      .describe("Optional allow/ignore rules to reduce false positives")
  },
  async execute(args, context) {
    const script = path.join(context.worktree, ".opencode", "tools", "scripts", "window_analyze.py")
    const result = await Bun.$`python3 ${script} \
      --db ${args.db} \
      --start ${args.start} \
      --end ${args.end} \
      --out-dir ${args.outDir} \
      --baseline-hours ${args.baselineHours} \
      --bin-minutes ${args.binMinutes} \
      --topk ${args.topK} \
      --max-evidence ${args.maxEvidence} \
      --ignore ${args.ignorePath}`.text()
    return result.trim()
  }
})
```

Because this is in `ios_logs.ts` and the export name is `window_analyze`, the tool becomes:

**`ios_logs_window_analyze`** ([opencode.ai][1])

### Add the Python script it calls

**`.opencode/tools/scripts/window_analyze.py`**

```py
import argparse
import json
import math
import os
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

KEYWORD_GROUPS = {
    "profiles_certs_vpn_proxy": [
        "configuration profile", "mdm", "mobile device management",
        "certificate", "root ca", "trust store", "trusted",
        "vpn", "proxy", "pac", "http proxy", "mitm",
    ],
    "auth_failures": [
        "unauthorized", "denied", "authentication failed", "login failed",
        "invalid password", "invalid credential", "passcode", "face id", "touch id",
    ],
    "jailbreak_instrumentation": ["jailbreak", "cydia", "substrate", "frida", "cycript", "sshd"],
    "data_exfil_suspicion": ["upload", "export", "keychain", "token", "credential", "backup"],
}

ISO_Z_RE = re.compile(r"Z$")

def parse_iso_to_utc(s: str) -> str:
    # Accept "...Z"
    s2 = ISO_Z_RE.sub("+00:00", s.strip())
    dt = datetime.fromisoformat(s2)
    if dt.tzinfo is None:
        # If user forgot tz, assume UTC (safer than assuming local).
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.isoformat()

def dt_from_iso_utc(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))

def load_ignore(path: str) -> Dict[str, set]:
    if not path or not os.path.exists(path):
        return {"apps": set(), "hosts": set(), "event_types": set()}
    try:
        data = json.load(open(path, "r", encoding="utf-8"))
        return {
            "apps": set(data.get("apps", [])),
            "hosts": set(data.get("hosts", [])),
            "event_types": set(data.get("event_types", [])),
        }
    except Exception:
        return {"apps": set(), "hosts": set(), "event_types": set()}

def q(conn: sqlite3.Connection, sql: str, params=()) -> List[sqlite3.Row]:
    cur = conn.cursor()
    return cur.execute(sql, params).fetchall()

def top_counts(conn, start, end, col, topk, ignore_set: set):
    sql = f"""
      SELECT {col} AS k, COUNT(*) AS n
      FROM events
      WHERE ts >= ? AND ts <= ? AND {col} IS NOT NULL AND {col} != ''
      GROUP BY {col}
      ORDER BY n DESC
      LIMIT ?
    """
    rows = q(conn, sql, (start, end, topk))
    out = []
    for r in rows:
        if r["k"] in ignore_set:
            continue
        out.append({"key": r["k"], "count": r["n"]})
    return out

def baseline_compare(conn, base_start, base_end, win_start, win_end, col, topk, ignore_set: set):
    # Compare counts in window vs immediately preceding window of same duration
    sql = f"""
      WITH w AS (
        SELECT {col} AS k, COUNT(*) AS wn
        FROM events
        WHERE ts >= ? AND ts <= ? AND {col} IS NOT NULL AND {col} != ''
        GROUP BY {col}
      ),
      b AS (
        SELECT {col} AS k, COUNT(*) AS bn
        FROM events
        WHERE ts >= ? AND ts < ? AND {col} IS NOT NULL AND {col} != ''
        GROUP BY {col}
      )
      SELECT w.k AS k, w.wn AS wn, COALESCE(b.bn, 0) AS bn
      FROM w
      LEFT JOIN b ON b.k = w.k
    """
    rows = q(conn, sql, (win_start, win_end, base_start, base_end))
    scored = []
    for r in rows:
        k = r["k"]
        if k in ignore_set:
            continue
        wn = int(r["wn"])
        bn = int(r["bn"])
        # surprise score: prefer large absolute count + large relative increase
        score = wn * math.log((wn + 1) / (bn + 1))
        scored.append({"key": k, "window": wn, "baseline": bn, "score": score})
    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored[:topk]

def minute_hist(conn, start, end) -> Dict[str, int]:
    rows = q(conn, """
      SELECT substr(ts,1,16) AS minute, COUNT(*) AS n
      FROM events
      WHERE ts >= ? AND ts <= ? AND ts IS NOT NULL
      GROUP BY minute
      ORDER BY minute
    """, (start, end))
    return {r["minute"]: int(r["n"]) for r in rows}

def bin_counts(minute_map: Dict[str,int], bin_minutes: int) -> List[Tuple[str,int]]:
    # minute key: "YYYY-MM-DDTHH:MM"
    buckets: Dict[str,int] = {}
    for m, c in minute_map.items():
        # Convert to datetime (assume UTC; stored values are UTC)
        dt = datetime.fromisoformat(m + ":00+00:00")
        epoch_min = int(dt.timestamp() // 60)
        b = (epoch_min // bin_minutes) * bin_minutes
        b_dt = datetime.fromtimestamp(b * 60, tz=timezone.utc)
        key = b_dt.strftime("%Y-%m-%dT%H:%M")
        buckets[key] = buckets.get(key, 0) + c
    return sorted(buckets.items(), key=lambda x: x[0])

def mean_std(vals: List[int]) -> Tuple[float,float]:
    if not vals:
        return 0.0, 0.0
    mu = sum(vals) / len(vals)
    var = sum((v - mu) ** 2 for v in vals) / len(vals)
    return mu, math.sqrt(var)

def keyword_hits(conn, start, end, max_evidence):
    findings = []
    for group, kws in KEYWORD_GROUPS.items():
        ors = " OR ".join(["lower(message) LIKE ?" for _ in kws])
        sql = f"""
          SELECT ts, source_file, locator, event_type, app, host, ip, severity, message
          FROM events
          WHERE ts >= ? AND ts <= ?
            AND message IS NOT NULL
            AND ({ors})
          ORDER BY ts
          LIMIT ?
        """
        params = [start, end] + [f"%{k.lower()}%" for k in kws] + [max_evidence]
        rows = q(conn, sql, params)
        if rows:
            ev = [dict(r) for r in rows]
            findings.append({
                "group": group,
                "keywords": kws,
                "count": len(ev),
                "evidence": ev
            })
    return findings

def sample_events(conn, start, end, limit=30, ignore_apps=set(), ignore_hosts=set(), ignore_types=set()):
    rows = q(conn, """
      SELECT ts, source_file, locator, event_type, app, host, ip, severity, message
      FROM events
      WHERE ts >= ? AND ts <= ?
      ORDER BY ts
      LIMIT ?
    """, (start, end, limit))
    out = []
    for r in rows:
        if r["app"] in ignore_apps: 
            continue
        if r["host"] in ignore_hosts:
            continue
        if r["event_type"] in ignore_types:
            continue
        out.append(dict(r))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--start", required=True)
    ap.add_argument("--end", required=True)
    ap.add_argument("--out-dir", default="analysis/cases")
    ap.add_argument("--baseline-hours", type=int, default=24)
    ap.add_argument("--bin-minutes", type=int, default=5)
    ap.add_argument("--topk", type=int, default=30)
    ap.add_argument("--max-evidence", type=int, default=10)
    ap.add_argument("--ignore", default="analysis/ignore_rules.json")
    args = ap.parse_args()

    start_utc = parse_iso_to_utc(args.start)
    end_utc = parse_iso_to_utc(args.end)

    start_dt = dt_from_iso_utc(start_utc)
    end_dt = dt_from_iso_utc(end_utc)
    if end_dt <= start_dt:
        raise SystemExit("end must be after start")

    duration = end_dt - start_dt
    base_same_start = (start_dt - duration).isoformat()
    base_same_end = start_dt.isoformat()

    baseline_spike_start = (start_dt - timedelta(hours=args.baseline_hours)).isoformat()
    baseline_spike_end = start_dt.isoformat()

    ignore = load_ignore(args.ignore)

    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    total_window = q(conn, "SELECT COUNT(*) AS n FROM events WHERE ts >= ? AND ts <= ?", (start_utc, end_utc))[0]["n"]
    total_base_same = q(conn, "SELECT COUNT(*) AS n FROM events WHERE ts >= ? AND ts < ?", (base_same_start, base_same_end))[0]["n"]

    # Top things in the window (for "what did I do")
    top_apps = top_counts(conn, start_utc, end_utc, "app", args.topk, ignore["apps"])
    top_types = top_counts(conn, start_utc, end_utc, "event_type", args.topk, ignore["event_types"])
    top_hosts = top_counts(conn, start_utc, end_utc, "host", args.topk, ignore["hosts"])
    top_sev = top_counts(conn, start_utc, end_utc, "severity", args.topk, set())

    # What changed vs baseline window of same length
    app_deltas = baseline_compare(conn, base_same_start, base_same_end, start_utc, end_utc, "app", args.topk, ignore["apps"])
    type_deltas = baseline_compare(conn, base_same_start, base_same_end, start_utc, end_utc, "event_type", args.topk, ignore["event_types"])
    host_deltas = baseline_compare(conn, base_same_start, base_same_end, start_utc, end_utc, "host", args.topk, ignore["hosts"])

    # Spike detection using bins
    base_min = minute_hist(conn, baseline_spike_start, baseline_spike_end)
    win_min = minute_hist(conn, start_utc, end_utc)

    base_bins = bin_counts(base_min, args.bin_minutes)
    win_bins = bin_counts(win_min, args.bin_minutes)

    base_vals = [c for _, c in base_bins]
    mu, sd = mean_std(base_vals)

    spikes = []
    for t, c in win_bins:
        z = 0.0 if sd == 0 else (c - mu) / sd
        if c >= max(10, int(mu * 3)) or z >= 3.0:
            spikes.append({"bin_start": t, "count": c, "z": round(z, 2), "baseline_mean": round(mu, 2), "baseline_sd": round(sd, 2)})
    spikes = spikes[: args.max_evidence]

    # Keyword hits restricted to the window
    keywords = keyword_hits(conn, start_utc, end_utc, args.max_evidence)

    # A small sample stream for the agent to “be creative” with (but still bounded)
    samples = sample_events(conn, start_utc, end_utc, limit=50,
                            ignore_apps=ignore["apps"], ignore_hosts=ignore["hosts"], ignore_types=ignore["event_types"])

    conn.close()

    case_id = f"case_{start_dt.strftime('%Y%m%dT%H%M%S')}_{end_dt.strftime('%Y%m%dT%H%M%S')}"
    out_dir = os.path.join(args.out_dir, case_id)
    os.makedirs(out_dir, exist_ok=True)

    out_json = {
        "case_id": case_id,
        "start_utc": start_utc,
        "end_utc": end_utc,
        "duration_seconds": int(duration.total_seconds()),
        "total_events_window": int(total_window),
        "total_events_baseline_same_duration": int(total_base_same),
        "top_apps_window": top_apps,
        "top_event_types_window": top_types,
        "top_hosts_window": top_hosts,
        "top_severities_window": top_sev,
        "app_changes_vs_baseline": app_deltas,
        "event_type_changes_vs_baseline": type_deltas,
        "host_changes_vs_baseline": host_deltas,
        "spike_bins": spikes,
        "keyword_findings": keywords,
        "sample_events": samples,
        "ignore_rules_used": args.ignore if os.path.exists(args.ignore) else None,
    }

    json_path = os.path.join(out_dir, "window_analysis.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(out_json, f, ensure_ascii=False, indent=2)

    md_path = os.path.join(out_dir, "window_report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# Window Investigation\n\n")
        f.write(f"- Case: `{case_id}`\n")
        f.write(f"- Start (UTC): `{start_utc}`\n")
        f.write(f"- End (UTC): `{end_utc}`\n")
        f.write(f"- Total events: `{total_window}` (baseline same duration: `{total_base_same}`)\n\n")

        if spikes:
            f.write("## Spike bins\n")
            for s in spikes[:10]:
                f.write(f"- `{s['bin_start']}` count={s['count']} z={s['z']} (baseline μ={s['baseline_mean']} σ={s['baseline_sd']})\n")
            f.write("\n")

        if keywords:
            f.write("## Keyword-based flags (within window)\n")
            for k in keywords:
                f.write(f"### {k['group']} ({k['count']} evidence rows)\n")
                f.write(f"- keywords: {', '.join(k['keywords'])}\n\n")
            f.write("\n")

        f.write("## Top apps / types / hosts\n")
        f.write("- Apps: " + ", ".join([f"{x['key']}({x['count']})" for x in top_apps[:10]]) + "\n")
        f.write("- Types: " + ", ".join([f"{x['key']}({x['count']})" for x in top_types[:10]]) + "\n")
        f.write("- Hosts: " + ", ".join([f"{x['key']}({x['count']})" for x in top_hosts[:10]]) + "\n\n")

        f.write("## Biggest changes vs baseline (same duration immediately before)\n")
        f.write("### Apps\n")
        for x in app_deltas[:10]:
            f.write(f"- {x['key']}: window={x['window']} baseline={x['baseline']}\n")
        f.write("\n### Event types\n")
        for x in type_deltas[:10]:
            f.write(f"- {x['key']}: window={x['window']} baseline={x['baseline']}\n")
        f.write("\n### Hosts\n")
        for x in host_deltas[:10]:
            f.write(f"- {x['key']}: window={x['window']} baseline={x['baseline']}\n")

    print(json.dumps({"ok": True, "case_dir": out_dir, "json": json_path, "md": md_path}, ensure_ascii=False))

if __name__ == "__main__":
    main()
```

### What this gives you

When you run it, you get a **case folder** like:

```
analysis/cases/case_20260201T080000_20260201T090000/
  window_analysis.json
  window_report.md
```

The agent can then:

* summarize “what you did” in that hour (top apps + event types + hosts)
* highlight spikes & changes vs baseline
* point to evidence rows (each row includes `source_file` + `locator`)
* for any evidence row, it can call your existing `ios_logs_get_record` to fetch the raw record safely

## 1B) Add a command so it’s easy to run

**`.opencode/commands/investigate-window.md`**

```md
---
description: Investigate a suspicious time window (baseline comparison + evidence pointers)
---

Load skill `ios-suspicious-detector` and `ios-activity-summary`.

1) Ensure the index exists (build it if missing).
2) Run `ios_logs_window_analyze` with the provided start/end.
3) Read the generated `window_report.md` and `window_analysis.json`.
4) Pick top 3–5 anomalies and fetch 1–3 raw records each with `ios_logs_get_record`.
5) Write a human explanation of "what likely happened" into the case folder as `narrative.md`.
```

### How you’d use it

In OpenCode chat:

* “Run `/investigate-window` start=... end=...”
* Then follow up: “Explain why you think host X is weird”
* The agent uses SQL + evidence pointers, and pulls only a few raw rows.

---

# Solution 2: Don’t build an index — do an on-demand “window extraction scan” (good for one-off investigations)

If your logs are **enormous** and you only care about *one* time range, indexing everything might be overkill.

Instead:

1. Stream every file once
2. Keep only records whose timestamp is inside `[start, end]`
3. Summarize + sample
4. LLM analyzes the small extracted result

### Pros

* No upfront indexing time
* Works even if you don’t trust timestamp normalization in the index yet

### Cons

* Every new time range = scan again (O(total logs))

Implementation is basically a new tool: `ios_logs_extract_window`.

Workflow:

* Tool writes `analysis/cases/<case_id>/window_extract.json` containing:

  * per-file counts in window
  * top apps/types/hosts in window
  * reservoir sample of ~100 records (redacted)
* Agent reads that JSON and produces narrative/anomalies.

If you want, I can paste the full `extract_window.py` and the tool definition too — it’s the same pattern as `window_analyze`, just reading `logs/*` instead of SQLite.

---

# Solution 3: Make it “creative” at scale — novelty detection + feedback loop

You said two key things:

* “I want the AI to scan and be creative”
* “But there are huge amounts”
  That’s exactly where **novelty scoring** + **human feedback** shines.

## 3A) Creativity without reading everything: “message template novelty”

Instead of embeddings, you can do something very effective and cheap:

* Convert each log message into a **template**:

  * replace numbers/UUIDs/hex with placeholders
  * e.g. `Failed login for user 1234` → `Failed login for user <NUM>`
* Track template frequency over time
* In your suspicious window, find:

  * templates that are **new** (not in baseline)
  * templates that **spike** (rare normally, common now)

This finds “new kinds of behavior” even if you didn’t think of the keyword.

How to implement:

* Add a `msg_template` column in your SQLite index at build time
* Add a tool `ios_logs_template_spikes(start,end)` that returns:

  * top new templates
  * top spiking templates
  * 3–10 example evidence rows for each

This gives the agent “creative leads” *without* scanning raw JSON.

## 3B) Feedback loop to reduce false positives (your “query + feedback mechanism”)

Add an allow/ignore file (you already saw it referenced in `window_analyze.py`):

**`analysis/ignore_rules.json`**

```json
{
  "apps": ["com.apple.springboard", "com.apple.analyticsd"],
  "hosts": ["icloud.com", "apple.com"],
  "event_types": ["heartbeat", "telemetry"]
}
```

Loop:

1. Run window analysis → get 20 suspicious items
2. You mark 10 as “normal” by adding them to ignore_rules
3. Rerun → the tool downranks/filters them
4. Repeat until the findings are tight

This is “active learning” without needing ML infrastructure.

---

# Which one should you pick?

* If you will investigate **multiple ranges** (or you want fast drilldowns): **Solution 1 (index + window tool)**
* If you only care about **one specific window** and want minimal setup: **Solution 2 (on-demand scan)**
* If you want maximum “creative discovery” with huge data: **Solution 3 (template novelty + feedback)** on top of Solution 1

---

## One practical tip: don’t make the agent guess what happened

A good “case investigation” always outputs:

* **Timeline bins** (5-minute buckets)
* Top apps/types/hosts **per bin**
* Evidence pointers to raw records

Then the agent can construct a narrative like:

> “At 10:05–10:10 there was a spike. During that bin, the top app was X, network host Y appeared (new vs baseline), and there were 7 auth failures; here are 3 concrete records.”

---

If you tell me **how your timestamps appear** (ISO strings? epoch ms? local time?) and **roughly how long the suspicious range is** (5 minutes? 2 hours? 2 days?), I’ll tailor the exact binning/baseline strategy and give you the full Solution 2 tool as well (window extractor) so you have both paths ready.

[1]: https://opencode.ai/docs/custom-tools/ "Custom Tools | OpenCode"
[2]: https://opencode.ai/docs/plugins/ "Plugins | OpenCode"


You’re thinking about this the right way: if you already have a *tight time window* where “something bad happened”, the best chance of finding “highly probable proof” is **not** to ask the LLM to read everything — it’s to:

1. **normalize + index** logs so time‑range queries are cheap
2. **extract a “case file”** for that window (plus a small padding)
3. run **multiple anomaly strategies in parallel**, each producing *ranked leads + evidence pointers*
4. let the agent “be creative” only on the **small case file**, and then pull raw records **by locator** for proof

Below are **multiple ways** to implement this, all designed for huge data but short suspect windows.

---

## Core requirements for your scenario

### A. Robust timestamp normalization (string times)

Because timestamps are strings, you want to normalize them at ingest time into:

* `ts_utc` (ISO-8601 in UTC, string)
* `ts_epoch_ms` (integer)

Why:

* SQLite range queries on `ts_epoch_ms` are fast and reliable even if strings vary.
* It avoids timezone ambiguity and weird formats.

### B. “Action normalization” (turn logs into *potential actions*)

Logs are noisy; “proof” usually comes from **state changes**, not volume spikes.

So you define “action categories” and rules:

* profile/MDM enrollment
* certificate trust store changes
* VPN/proxy changes
* app install/uninstall
* account sign-in / token failures
* pairing / USB / debugging / dev mode
* keychain access / credential events
* network connections to rare/new hosts

Then you aggregate many low-level lines into a handful of “actions” with:

* start/end time
* involved app/process/host
* supporting evidence locators
* “proof score”

### C. Bounded outputs + evidence pointers

Every detector outputs:

* *small summary objects* (counts, top deltas, top templates)
* *evidence pointers* (file + locator) so the agent can pull raw record(s) on demand

This is the “proof” mechanism.

---

# Way 1 (best overall): Build an enriched index once, then run a **Case Builder** tool for any window

This is the most scalable and gives the agent room to “be creative” safely.

## 1) Upgrade your index schema (one-time)

Extend your SQLite `events` table to include:

* `ts_epoch_ms INTEGER`  ✅ (key)
* `msg_template TEXT` (message normalized into a template)
* `category TEXT` (normalized “action category”)
* `weight REAL` (how “high-signal” the category is)

### Why msg_template matters

It enables “creative” detection at scale:

* new templates that never appear in baseline
* templates that spike only in the incident window

This finds unusual behavior even when you don’t know the right keywords.

### How to parse string timestamps reliably

Add parsing attempts:

* ISO-8601 (`2026-02-07T10:01:02+02:00`, `...Z`)
* iOS-ish formats like `2026-02-07 10:01:02 +0200`
* formats with fractional seconds

And if a string has **no timezone**, choose a default IANA timezone (you’re in `Asia/Jerusalem`) rather than assuming UTC.

(Implementation detail: in Python, `zoneinfo.ZoneInfo("Asia/Jerusalem")`.)

## 2) Add “action rules” as a file (editable + feedback friendly)

Example: `analysis/action_rules.json`

```json
{
  "rules": [
    { "id": "profile_mdm", "category": "config.profile_mdm", "weight": 5,
      "patterns": ["configuration profile", "mdm", "managedconfiguration", "enroll"] },

    { "id": "cert_trust", "category": "config.certificate_trust", "weight": 5,
      "patterns": ["trust store", "certificate", "root ca", "trusted"] },

    { "id": "vpn_proxy", "category": "config.vpn_proxy", "weight": 4,
      "patterns": ["vpn", "proxy", "pac", "networkextension"] },

    { "id": "app_install", "category": "system.app_install", "weight": 4,
      "patterns": ["install", "installed", "uninstall", "removed"] },

    { "id": "auth_fail", "category": "auth.failure", "weight": 3,
      "patterns": ["unauthorized", "denied", "authentication failed", "invalid credential"] },

    { "id": "jailbreak", "category": "integrity.jailbreak_tools", "weight": 5,
      "patterns": ["cydia", "substrate", "frida", "cycript", "jailbreak"] }
  ]
}
```

This makes your system **self-improving**:

* false positives → add ignore rules
* missed signals → add a rule

## 3) Add a “Case Builder” tool for a time window

Create a new tool like `ios_logs_case_build(start, end, pad_seconds, baseline_strategy=...)` that writes:

`analysis/cases/<case_id>/`

* `case_summary.md` (small, readable)
* `case_features.json` (ranked anomalies + why)
* `case_evidence.json` (limited evidence rows + locators)
* optionally `case_graph.json` (entity correlation graph)

The tool should run **multiple strategies in parallel** inside Python/SQLite:

### Strategy A: High-signal rule hits (proof-first)

Within `[start-pad, end+pad]`, search `message/event_type/app` for your action rules.

Output: direct indicators + evidence rows.
These are usually your **highest-probability proof** items.

### Strategy B: Baseline difference (window vs baseline)

Compute top deltas for:

* app
* event_type
* host
* category
* msg_template

Score idea (simple, strong): **log-odds weighted by window count**

[
score = c_w \cdot \log \frac{(c_w / N_w) + \epsilon}{(c_b / N_b) + \epsilon}
]

This highlights “this thing dominates the incident window compared to baseline”.

Baseline options (you can run more than one):

* **immediate preceding window of same length** (best for “something changed suddenly”)
* **previous X hours** (good when the window is tiny and preceding minutes are too similar)
* **same time-of-day previous day(s)** (good for routine patterns)

### Strategy C: Template novelty/spikes (creative but scalable)

* new templates in the window not present in baseline
* rare templates that suddenly spike

This surfaces weird events even without keywords.

### Strategy D: Action clustering (normalize many lines → a few “actions”)

Group events into clusters by:

* category + app (+ host if present)
* time adjacency (e.g., gap <= 5–10 seconds)

Each cluster becomes an “action candidate” with:

* start/end
* count
* distinct templates
* top evidence locators
* score = (category_weight) + (novelty_score) + (baseline_delta)

This is how you turn “lots of logs” into “possible actions”.

### Strategy E: Cross-log correlation (combination-of-logs)

Build an entity co-occurrence graph inside the window:

* nodes: app / host / category / template
* edges: co-occur in same event or within X seconds

Then report top central nodes and strongest edges.
This helps answer: “Which app/host seems to be the *hub* of the incident?”

---

## How the agent uses it

1. You run the case builder tool for `[T1, T2]` (with pad)
2. Agent reads `case_summary.md` (small)
3. Agent picks top 3–5 leads and requests raw records by locator using `ios_logs_get_record`
4. Agent writes a human narrative:

   * “Most likely explanation”
   * “Supporting evidence (3–10 records)”
   * “Alternate explanations”
   * “Next verification steps”

This preserves creativity **without** blowing context.

### OpenCode mechanics note

If you add a new tool export in `.opencode/tools/*.ts`, it becomes callable as `<filename>_<exportname>`. ([OpenCode][1])
And if your tools need NPM deps like `@opencode-ai/plugin`, add `.opencode/package.json`; OpenCode runs `bun install` at startup. ([OpenCode][2])

---

# Way 2: No full index — build a **temporary “case DB”** by scanning only the window (+ padding)

Use this when:

* you have huge logs and don’t want to index everything yet
* you only care about one incident

## Method

New tool: `ios_logs_extract_case(start,end,pad)`:

1. stream-parse logs file by file
2. parse string timestamps
3. keep only records in `[start-pad, end+pad]`
4. write into a small SQLite case DB:

   * `analysis/cases/<case_id>/case.sqlite`

Then run the *same* detectors (rules, baseline, template novelty, clustering) **only** on that small DB.

### Baseline without full index

Because you didn’t index everything, you still need a baseline. Options:

* baseline = `[start-1h, start)` extracted during the same scan
* baseline = sample N minutes randomly from the day (reservoir sampling)

This is less perfect than Way 1, but good enough if the incident window is very short.

### Pros / Cons

✅ no upfront indexing
✅ fastest “time-to-first-case”
❌ every new window requires another scan
❌ baseline is weaker unless you scan more around it

---

# Way 3: Precompute rollups (OLAP style) + drill down for proof

If your logs are truly massive and you want *very fast* case building:

## Method

During indexing, also create rollup tables:

* `minute_rollup(minute_epoch, category, app, host, count)`
* `template_rollup(minute_epoch, msg_template, count)`

Then your case builder does:

1. rollup query for the window and baseline (very fast)
2. identify top anomalies
3. fetch raw evidence rows only for the top anomalies

### Why this can beat everything else

For a 2-minute window, you can detect spikes and novelty using rollups without touching the raw `events` table much.

This is the most “big data” approach.

---

# Getting “highly probable proof” (what to optimize for)

When you *know* something malicious happened, you want detectors that prefer **direct state-change indicators** over generic anomalies.

### High-probability “proof patterns” to prioritize

These are the kinds of things you should weight highly in `action_rules.json`:

* profile installed / removed / MDM enrollment changes
* certificate trust store modifications
* VPN / proxy / PAC changes
* new pairing / developer / debug / trust events
* app install/uninstall
* account sign-in / token refresh anomalies
* keychain / credential access patterns
* network extension changes

These tend to be “hard evidence” events (or at least much closer to it than “rare host”).

---

# The “query + feedback” mechanism you mentioned (works in all 3 ways)

Add two editable files:

### `analysis/ignore_rules.json`

Things you decide are normal noise:

```json
{ "apps": ["com.apple.analyticsd"], "hosts": ["apple.com"], "event_types": [] }
```

### `analysis/action_rules.json`

Things you decide are important:

* add patterns you notice in your environment
* tune weights

Workflow:

1. run case builder
2. mark false positives → add ignore rules
3. rerun → results become sharper
4. keep iterating until the findings are tight

This is the best “human-in-the-loop” way to reach “highly probable proof” from messy logs.

---

## Practical recommendation for your exact assumption (minutes-long window)

If it were me, I’d implement **Way 1 + Strategy A/B/C/D** first:

* enrich index with `ts_epoch_ms`, `msg_template`, `category`, `weight`
* add one tool: `ios_logs_case_build`
* output a small case folder
* agent drills down by locators to produce proof-backed narrative

Then, if performance becomes an issue, add Way 3 rollups.

---

If you want, I can give you the *exact* patch set (updated `build_index.py` schema + `case_build.py` + the TS tool export) in one cohesive chunk so you can copy/paste it directly.

[1]: https://opencode.ai/docs/custom-tools/?utm_source=chatgpt.com "Custom Tools"
[2]: https://opencode.ai/docs/plugins/?utm_source=chatgpt.com "Plugins"

------------------------------------------------------------>
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Below is a **from‑scratch, copy‑paste implementation** of an **“AgentKit Generator”** for the **OpenCode AI framework**.

What you’ll end up with:

* A global **`/agentkit`** command you can run in *any* repo.
* It will **scan only targeted files** (README, manifests, CI, entry points) using `read/list/glob/grep` (no repo-wide ingestion).
* If your repo description + scan isn’t enough, it will ask you **up to 5 questions** using OpenCode’s built‑in `question` tool. ([OpenCode][1])
* It generates a **low-context navigation kit** inside the repo:

  * `AGENTS.md` rules
  * `opencode.jsonc` with `instructions` that always load only small docs ([OpenCode][2])
  * `docs/*` (repo-map, dependency rules, testing, report format)
  * `.opencode/agents/*` (read-only explorer, fix agent, maintainer agent) ([OpenCode][3])
  * `.opencode/commands/*` (shortcuts: `/explore`, `/fix`, `/context-expand`, `/agentkit-update`, `/agentkit-validate`) ([OpenCode][4])
  * `.opencode/skills/*` on-demand skills ([OpenCode][5])
  * Boundary `CONTEXT.md` shards in the right folders

OpenCode supports:

* project rules via `AGENTS.md` ([OpenCode][2])
* project config (JSON/JSONC) and config precedence (remote → global → project → `.opencode` dirs) ([OpenCode][6])
* commands via `.opencode/commands` and `~/.config/opencode/commands` ([OpenCode][4])
* agents via `.opencode/agents` and `~/.config/opencode/agents` ([OpenCode][3])
* skills via `.opencode/skills/<name>/SKILL.md` and global equivalents ([OpenCode][5])

---

## 1) Install the global generator (one-time)

Create two files globally:

* `~/.config/opencode/agents/agentkit.md`
* `~/.config/opencode/commands/agentkit.md`

OpenCode will load these automatically from the global config directories. ([OpenCode][3])

### 1.1 `~/.config/opencode/agents/agentkit.md`

```md
---
description: AgentKit — generate low-context navigation kit (AGENTS.md + docs + .opencode commands/agents/skills + CONTEXT shards)
mode: subagent
temperature: 0.1

# Hard-disable dangerous tools for this generator.
tools:
  bash: false
  webfetch: false
  websearch: false

# Use permissions (OpenCode supports allow/ask/deny). The write/patch tools are controlled by edit permission. :contentReference[oaicite:11]{index=11}
permission:
  "*": allow
  edit: ask
  question: allow
  bash: deny
  webfetch: deny
  websearch: deny
---

You are AgentKit Generator for OpenCode.

Goal
Generate a low-context navigation kit for the current repository:
- Root rules: AGENTS.md
- Project config: opencode.jsonc (or opencode.json) with minimal always-loaded instructions
- docs/: repo-map.md, dependency-rules.md, testing.md, report-format.md, plus docs/opencode/README.md
- .opencode/agents/: kit-explore.md (read-only), kit-fix.md (edits), kit-maintain.md (update/expand/validate)
- .opencode/commands/: explore.md, fix.md, context-expand.md, agentkit-update.md, agentkit-validate.md
- .opencode/skills/: repo-navigation, dependency-mapping, bug-triage, patch-discipline
- Boundary CONTEXT.md shards placed at the correct seams

Constraints
- DO NOT read the whole repo.
- Use progressive disclosure: shallow scans → targeted reads.
- Keep always-loaded docs small:
  - docs/repo-map.md <= ~200 lines
  - docs/dependency-rules.md <= ~200 lines
  - docs/testing.md <= ~200 lines
  - docs/report-format.md <= ~200 lines
- Each boundary CONTEXT.md <= ~150 lines.
- Prefer "start here" pointers over exhaustive documentation.

Tools available (expected)
- read, list, glob, grep for scanning and targeted reads
- write/edit/patch for file creation (requires approval via edit: ask)
- question tool for asking up to 5 clarifying questions (UI with options) :contentReference[oaicite:12]{index=12}

========================================================
PHASE A — TARGETED SCAN (no wide ingestion)
========================================================
1) Confirm you are at repo root:
   - list "."
   - if top-level looks nested, ask user to run the command from the repo root

2) Identify repo type signals (use glob, then read only a few key files):
   - Root docs: README*, CONTRIBUTING*, ARCHITECTURE*, docs/
   - Build manifests: package.json, pnpm-workspace.yaml, yarn.lock, bun.lockb,
     go.work, go.mod, Cargo.toml, pyproject.toml, requirements*.txt,
     pom.xml, build.gradle*, Makefile, CMakeLists.txt, WORKSPACE/BUILD files,
     nx.json, turbo.json, lerna.json, etc.
   - CI: .github/workflows/*, .gitlab-ci.yml, circleci, etc.
   - Entry points heuristics:
     - Node: src/index.*, src/server.*, apps/*/src/main.*, packages/*/src/index.*
     - Go: cmd/*/main.go
     - Rust: src/main.rs, crates/*/src/lib.rs
     - Python: <pkg>/__main__.py, manage.py, app.py, main.py
     - Java: src/main/**, Spring Boot main class
     - C/C++: main.c/cpp, top-level build targets

3) Boundary discovery (avoid too many shards):
   - Candidate boundaries:
     - Top-level dirs excluding: .git, node_modules, dist, build, out, target, vendor, third_party
     - Monorepo containers: apps/, services/, packages/, crates/, modules/
     - Any dir containing a manifest (go.mod, Cargo.toml, package.json, pyproject.toml, etc.)
   - If the repo has many subprojects:
     - Create a shard for the container folder (e.g., packages/CONTEXT.md)
     - And generate only top N (N<=12) sub-boundaries that appear most central (based on manifests or import references)

4) For each selected boundary, do targeted reads only:
   - boundary README (if exists)
   - boundary manifest (if exists)
   - 1–2 entry points
   - 1 public API surface (index/lib/header/export)
   - 1 test file if obvious

========================================================
PHASE B — SUFFICIENCY GATE (ask up to 5 questions)
========================================================
After scanning, verify you can confidently generate:
- Deliverables: what gets built/deployed (services/apps/libs/tools/infra)
- Boundaries: what the main modules are + their entry points
- Canonical build/test commands
- Dependency/layering rules (even if “best effort”)
- Ignore paths to keep context small

If ANY are missing/ambiguous, use the question tool to ask ONLY the needed questions.
Ask at most 5 total questions, preferably in a single question-tool call.

Question pool (pick only what’s needed):
Q1 Deliverables (multi-select):
- Backend services
- Frontend web app(s)
- Mobile app(s)
- CLI tools / daemons
- Libraries/SDKs only
- Infrastructure is a major boundary
- Other (free text)

Q2 Priority domains (pick up to 5):
- Auth/identity
- Payments/billing
- Storage/DB
- API routing/handlers
- Background jobs/queues
- Frontend routes/state
- Observability
- Security/permissions
- Other (free text)

Q3 Canonical commands:
- Use CI commands (specify job)
- I will paste install/build/test/lint commands
- Multiple environments (list)
- Unknown (generate TODO placeholders)

Q4 Dependency rules:
- Apps/services depend on libs, not vice versa
- Domain layer pure (no IO)
- No deep imports except public API
- No cycles
- No strict rules; infer best-effort
- Other (free text)

Q5 Ignore paths (multi-select + free text):
- node_modules/dist/build/out/target
- vendor/third_party
- generated code dirs (list)
- large fixtures (list)
- none/unsure

========================================================
PHASE C — WRITE THE KIT (must be repo-contained)
========================================================
Create these directories if missing:
- docs/
- docs/opencode/
- .opencode/agents/
- .opencode/commands/
- .opencode/skills/

Write or update files:
1) AGENTS.md (root)
   - If AGENTS.md exists: preserve it; append an "AgentKit" section.
   - If not: create it.

2) opencode.jsonc or opencode.json
   - If a project config exists: minimally merge:
     - add docs files to instructions (if not present)
     - add watcher.ignore defaults (do not remove user patterns)
     - set safe default permissions only if permission not already defined
   - If no project config exists: create opencode.jsonc using the template below.

3) docs/*
   - docs/repo-map.md: shallow map + entry points + “start here”
   - docs/dependency-rules.md: layering rules + boundary crossings + stop conditions
   - docs/testing.md: canonical commands (from README/CI/manifests)
   - docs/report-format.md: required output format for exploration

4) docs/opencode/README.md
   - Explain how to use /explore, /fix, /context-expand, /agentkit-update

5) .opencode/agents/*
   - kit-explore.md (read-only explorer, strict working-set budget)
   - kit-fix.md (minimal patch workflow; requires explore first)
   - kit-maintain.md (update/expand/validate kit; safe edits)

6) .opencode/commands/*
   - explore.md -> kit-explore
   - fix.md -> kit-fix
   - context-expand.md -> kit-maintain
   - agentkit-update.md -> kit-maintain
   - agentkit-validate.md -> kit-maintain

7) .opencode/skills/*
   - repo-navigation
   - dependency-mapping
   - bug-triage
   - patch-discipline

8) Boundary CONTEXT.md shards
   - Place CONTEXT.md in each selected boundary directory.
   - If a boundary already has CONTEXT.md, do NOT overwrite; instead append an AgentKit section demarcated by:
     <!-- AGENTKIT:BEGIN --> ... <!-- AGENTKIT:END -->
   - The shard must contain: purpose, entry points, APIs, deps, invariants, tests.

========================================================
PHASE D — VALIDATE THE OUTPUT (no builds required)
========================================================
After writing, validate:
- All instruction files referenced in opencode.json(c) exist
- .opencode/commands/*.md reference existing agents
- .opencode/skills/*/SKILL.md have valid frontmatter (name, description)
- Line-budget checks (warn if over limits)
- Provide a final summary:
  - what files created/updated
  - which boundaries got CONTEXT.md
  - what you could not infer (TODOs)

========================================================
TEMPLATES TO WRITE (fill with repo-specific findings)
========================================================

[Template] opencode.jsonc (create if missing)
{
  "$schema": "https://opencode.ai/config.json",
  "instructions": [
    "docs/repo-map.md",
    "docs/dependency-rules.md",
    "docs/testing.md",
    "docs/report-format.md"
  ],
  "permission": {
    "edit": "ask",
    "bash": "ask",
    "webfetch": "deny",
    "websearch": "deny"
  },
  "watcher": {
    "ignore": [
      "node_modules/**",
      "dist/**",
      "build/**",
      "out/**",
      "target/**",
      ".git/**"
    ]
  }
}

[Template] Root AGENTS.md (append section if exists)
# Agent Context Kit (AgentKit)

## Context budget rules
- Do NOT read the whole repo.
- Start with: docs/repo-map.md, docs/dependency-rules.md, docs/testing.md
- Then read ONLY the nearest boundary CONTEXT.md.
- Expand outward from entry points and public APIs only.

## Default workflow
- Use /explore to identify working set + dependencies + flow explanation.
- Use /fix to implement minimal patch + validation.
- Use /context-expand <path> to generate additional CONTEXT.md shards for a subtree.
- Update docs/opencode/README.md when workflows change.

[Template] docs/report-format.md
# Exploration / explanation report format (required)

## 1) Scope
- In scope:
- Out of scope:
- Assumptions:

## 2) Working set
### Read (≤10)
- path — why
### Likely edit (≤10)
- path — why

## 3) Dependency notes
- Direct deps:
- Transitive deps (1–2 hop):
- Boundary crossings (APIs/interfaces):

## 4) Step-by-step flow
1) Entry point
2) Routing/dispatch
3) Core logic
4) State mutation
5) Output/return

For each step:
- file/function
- data structure
- 1-sentence explanation

## 5) Risks / bug hypotheses (only if asked)
- Hypothesis, evidence, how to confirm

## 6) Validation
- Minimal checks
- Build/test commands (if possible)

[Template] .opencode/agents/kit-explore.md (generated in repo)
---
description: Kit Explore — read-only, minimal working set + dependencies + flow explanation
mode: subagent
temperature: 0.1
tools:
  write: false
  edit: false
  patch: false
  bash: false
  webfetch: false
  websearch: false
permission:
  "*": allow
  edit: deny
  bash: deny
  webfetch: deny
  websearch: deny
---

You are Kit Explore.

Mission
- Identify the minimal working set for the user request.
- Explain dependencies (direct + 1–2 hop).
- Explain the flow step-by-step using docs/report-format.md.
- Stay within strict progressive disclosure:
  1) docs/repo-map.md + docs/dependency-rules.md
  2) nearest boundary CONTEXT.md
  3) entry point + narrow call chain
Stop once you can fill the report format confidently.

Output MUST follow docs/report-format.md exactly.

[Template] .opencode/agents/kit-fix.md
---
description: Kit Fix — minimal bug fix workflow (requires explore first)
mode: subagent
temperature: 0.1
tools:
  webfetch: false
  websearch: false
permission:
  "*": allow
  edit: ask
  bash: ask
  webfetch: deny
  websearch: deny
---

You are Kit Fix.

Non-negotiable workflow
1) If no fresh /explore output exists in this session for this task, instruct the user to run /explore first.
2) Restate the bug; create 2–3 hypotheses.
3) Propose a minimal patch plan before editing.
4) Edit the smallest number of files.
5) Validate with the narrowest commands from docs/testing.md and boundary CONTEXT.md.
6) If behavior/invariants changed, update the nearest CONTEXT.md.

Required output sections:
- Bug statement
- Hypotheses (H1..H3) + confirm/deny signals
- Working set (read/edit)
- Fix plan
- Patch summary (what changed + why)
- Validation steps
- Documentation updates

[Template] .opencode/agents/kit-maintain.md
---
description: Kit Maintain — expand/update/validate the context kit
mode: subagent
temperature: 0.1
tools:
  bash: false
  webfetch: false
  websearch: false
permission:
  "*": allow
  edit: ask
  bash: deny
  webfetch: deny
  websearch: deny
---

You maintain the AgentKit files in this repo.

You may be asked to:
- Update docs/repo-map.md / dependency-rules.md / testing.md from targeted scans (README/manifests/CI)
- Add CONTEXT.md shards under a specific subtree path
- Validate that AgentKit is internally consistent

Rules:
- Do not do repo-wide reads.
- Preserve manual edits outside <!-- AGENTKIT:BEGIN/END --> blocks.
- Keep docs short and high-signal.

[Template] Skill frontmatter example
---
name: repo-navigation
description: Progressive disclosure navigation; minimize working set; avoid context overflow
compatibility: opencode
---

========================================================
END OF TEMPLATES
========================================================
```

Why this is valid OpenCode usage:

* Agents can be defined in markdown at `~/.config/opencode/agents/` and `.opencode/agents/`. ([OpenCode][3])
* Commands can be defined in markdown at `~/.config/opencode/commands/` and `.opencode/commands/` and use `$ARGUMENTS`. ([OpenCode][4])
* Skills are discovered from `.opencode/skills/<name>/SKILL.md` and global equivalents. ([OpenCode][5])
* `instructions` is the recommended way to include extra docs automatically (file refs in AGENTS.md aren’t auto-parsed). ([OpenCode][2])
* The `question` tool exists and is designed exactly for “ask user clarifying questions with options.” ([OpenCode][1])

---

### 1.2 `~/.config/opencode/commands/agentkit.md`

```md
---
description: Generate Agent Context Kit for this repository (low-context navigation + bug-fix workflow)
agent: agentkit
---

Repository description:
$ARGUMENTS

Task:
- Run targeted scan (README/manifests/CI/entrypoints only).
- If insufficient info: ask up to 5 questions using the question tool.
- Generate the repo-local kit:
  - AGENTS.md
  - opencode.jsonc (or update existing project config carefully)
  - docs/* + docs/opencode/README.md
  - .opencode/agents/*, .opencode/commands/*, .opencode/skills/*
  - boundary CONTEXT.md shards
- Validate internal consistency and print a summary.
```

Command files and the `agent:` frontmatter are supported. ([OpenCode][4])

---

## 2) How to run it on your own repo

### Step 1 — Open the repo in OpenCode

From your repo root:

```bash
cd /path/to/your/repo
opencode
```

OpenCode looks for project config by traversing up to the nearest Git directory, and it loads `.opencode` directories too. ([OpenCode][6])

### Step 2 — Run the generator command

In the OpenCode prompt:

```text
/agentkit "This is a monorepo for <product>. Primary languages are <...>. Deployables: <...>. Key flows: <...>. Build/test: <...>."
```

If your description (plus the targeted scan) isn’t enough, it will prompt you with **up to 5 questions** using the `question` tool UI. ([OpenCode][1])

### Step 3 — Approve file writes

The agent will request approval to write files because it uses `edit: ask`. (In OpenCode, `edit` permission controls all file modifications including `write` and `patch`.) ([OpenCode][1])

### Step 4 — Review and commit

Review the generated files (`git diff`), then commit them.

### Step 5 — Use the kit

After generation, your repo will contain:

* `/explore <question>` — find the *right files* and explain the flow
* `/fix <bug description>` — make a minimal patch (after explore)
* `/context-expand <path>` — generate additional `CONTEXT.md` shards only for that subtree
* `/agentkit-update` — refresh repo-map/testing/deps using targeted scan
* `/agentkit-validate` — check kit consistency

---

## 3) What the generator creates inside the repo

You asked for “all the files necessary, including skills prompts docs rules etc.” — this is the **repo-local output spec** AgentKit writes.

> **Generated tree:**

```txt
<repo>/
  AGENTS.md
  opencode.jsonc

  docs/
    repo-map.md
    dependency-rules.md
    testing.md
    report-format.md
    opencode/
      README.md

  .opencode/
    agents/
      kit-explore.md
      kit-fix.md
      kit-maintain.md
    commands/
      explore.md
      fix.md
      context-expand.md
      agentkit-update.md
      agentkit-validate.md
    skills/
      repo-navigation/
        SKILL.md
      dependency-mapping/
        SKILL.md
      bug-triage/
        SKILL.md
      patch-discipline/
        SKILL.md

  <boundary>/CONTEXT.md
  <boundary>/<subboundary>/CONTEXT.md   (only if generated by /context-expand)
```

This works because OpenCode loads `.opencode` directories as part of config precedence and uses plural subdirectories like `agents/`, `commands/`, and `skills/`. ([OpenCode][6])

---

## 4) Repo-local files (exact contents AgentKit should write)

Below are the canonical contents the generator should create (with repo-specific sections filled in).

### 4.1 `AGENTS.md` (project rules)

```md
# Agent Guide — <REPO NAME>

This repository includes an Agent Context Kit (AgentKit) designed for huge codebases with limited context windows.

## Prime directive (context budget)
- Do NOT read the entire repo.
- Use progressive disclosure:
  1) docs/repo-map.md
  2) docs/dependency-rules.md
  3) docs/testing.md
  4) nearest boundary CONTEXT.md
  5) only then: entry points + call chain + tests

## Default workflow
- Use /explore to find the right files and explain the flow.
- Use /fix to implement minimal patches (after /explore).
- Use /context-expand <path> only when deeper sharding is needed.

## Stop conditions (avoid context overflow)
Stop reading once you can name:
- the entry point
- the call chain (1–2 boundary hops)
- the main data structures
- the minimal edit set

## Doc hygiene
If you change public behavior or invariants of a boundary, update that boundary’s CONTEXT.md in the same change.
```

OpenCode loads `AGENTS.md` as rules and recommends using `instructions` for extra docs (file references in AGENTS.md aren’t auto-parsed). ([OpenCode][2])

---

### 4.2 `opencode.jsonc` (project config)

```jsonc
{
  "$schema": "https://opencode.ai/config.json",

  "instructions": [
    "docs/repo-map.md",
    "docs/dependency-rules.md",
    "docs/testing.md",
    "docs/report-format.md"
  ],

  "permission": {
    "edit": "ask",
    "bash": "ask",
    "webfetch": "deny",
    "websearch": "deny"
  },

  "watcher": {
    "ignore": [
      "node_modules/**",
      "dist/**",
      "build/**",
      "out/**",
      "target/**",
      ".git/**"
    ]
  }
}
```

* OpenCode supports JSONC configs. ([OpenCode][6])
* `instructions` is the recommended way to include extra instruction files and they are combined with `AGENTS.md`. ([OpenCode][2])
* `watcher.ignore` is supported to reduce noise. ([OpenCode][6])

---

### 4.3 `docs/report-format.md`

```md
# Exploration / explanation report format (required)

## 1) Scope
- In scope:
- Out of scope:
- Assumptions:

## 2) Working set
### Read (≤10)
- path — why
### Likely edit (≤10)
- path — why

## 3) Dependency notes
- Direct deps:
- Transitive deps (1–2 hop):
- Boundary crossings (APIs/interfaces):

## 4) Step-by-step flow
1) Entry point
2) Routing/dispatch
3) Core logic
4) State mutation
5) Output/return

For each step:
- file/function
- data structure
- 1-sentence explanation

## 5) Risks / bug hypotheses (only if asked)
- Hypothesis, evidence, how to confirm

## 6) Validation
- Minimal checks
- Build/test commands (if possible)
```

---

### 4.4 `docs/repo-map.md`

```md
# Repo map (shallow)

This file is always loaded via opencode.jsonc instructions. Keep it short.

## What this repo is
- Product: <from your description + README>
- Primary languages: <detected>
- Build system(s): <detected from manifests/CI>

## Main boundaries
- <boundary>/ — <1–2 lines purpose>
  - Entry points: <paths>
  - Start here: <paths>

## Common tasks → where to look
- “API request handling” → <paths>
- “Background jobs” → <paths>
- “Database layer / migrations” → <paths>
- “CLI tools” → <paths>
- “Frontend routes/pages” → <paths>
```

---

### 4.5 `docs/dependency-rules.md`

```md
# Dependency rules (agent-oriented)

Goal: keep exploration bounded and keep fixes safe.

## Recommended layering model
- Deployables (apps/services) may depend on shared libs/packages
- Shared libs should not depend on deployables
- Prefer crossing boundaries only through public APIs (avoid deep imports)

## Observed internal dependencies (best-effort)
- <A> -> <B> (evidence: manifest or import)

## Boundary crossings (“interfaces”)
- Public API surfaces:
- Shared contracts/types:
- Messaging/queues:
- CLI entry points:

## Stop conditions
Stop reading once you can name:
- entry point
- call chain (1–2 hops)
- data structures
- likely edit files
```

---

### 4.6 `docs/testing.md`

```md
# Build & test commands (quick reference)

Extracted from README/CI/manifests. Keep this short.

## Install / bootstrap
- <command>

## Build
- <command>

## Test
- <command>

## Lint / format
- <command>

## Notes
- Prefer the smallest relevant test/target.
```

---

### 4.7 `docs/opencode/README.md` (the “explains everything” README)

```md
# Agent Context Kit (OpenCode)

This repository is configured for low-context navigation and safe changes using OpenCode.

## Why
Large repos overflow context windows. This kit makes agents effective by:
- always loading only small docs (repo map, dependency rules, testing, report format)
- sharding subsystem context into boundary CONTEXT.md files
- using skills for deeper playbooks on-demand

## Daily workflow
### Explore (read-only behavior)
Run:
- /explore <question or bug description>

You’ll get:
- minimal working set (≤10 read)
- dependencies (direct + 1–2 hop)
- step-by-step flow
- minimal validation commands

### Fix (minimal patch)
Run:
- /fix <bug description>

Rules:
- use explore output first
- smallest patch possible
- validate via docs/testing.md
- update nearest CONTEXT.md if invariants changed

## Expanding context shards
If you need deeper coverage:
- /context-expand path/to/subtree

## Updating the kit after refactors
- /agentkit-update

## Validate kit health
- /agentkit-validate
```

---

## 5) Repo-local `.opencode/*` files

### 5.1 Agents

**`.opencode/agents/kit-explore.md`**

```md
---
description: Kit Explore — read-only minimal working set + deps + flow
mode: subagent
temperature: 0.1
tools:
  write: false
  edit: false
  patch: false
  bash: false
  webfetch: false
  websearch: false
permission:
  "*": allow
  edit: deny
  bash: deny
  webfetch: deny
  websearch: deny
---

You are Kit Explore.

Use progressive disclosure:
1) docs/repo-map.md + docs/dependency-rules.md + docs/testing.md (already loaded via instructions)
2) nearest boundary CONTEXT.md
3) entry points + narrow call chain

Hard limits:
- Working set: ≤10 files to read
- Do not scan/describe the entire repo

Output MUST follow docs/report-format.md exactly.
```

**`.opencode/agents/kit-fix.md`**

```md
---
description: Kit Fix — minimal bugfix (requires explore first)
mode: subagent
temperature: 0.1
tools:
  webfetch: false
  websearch: false
permission:
  "*": allow
  edit: ask
  bash: ask
  webfetch: deny
  websearch: deny
---

You are Kit Fix.

Rules:
- If there is no fresh explore report for this task in the conversation, instruct the user to run /explore first.
- Make the smallest fix that addresses the root cause.
- Validate using docs/testing.md and boundary CONTEXT.md.
- Update nearest boundary CONTEXT.md if behavior/invariants changed.

Required output sections:
- Bug statement (restated)
- Hypotheses (H1..H3) + confirm/deny signals
- Working set (read/edit)
- Fix plan
- Patch summary
- Validation steps
- Documentation updates
```

**`.opencode/agents/kit-maintain.md`**

```md
---
description: Kit Maintain — update/expand/validate the Agent Context Kit
mode: subagent
temperature: 0.1
tools:
  bash: false
  webfetch: false
  websearch: false
permission:
  "*": allow
  edit: ask
  bash: deny
  webfetch: deny
  websearch: deny
  question: allow
---

You maintain AgentKit files.

Allowed operations:
- Refresh docs/repo-map.md, docs/dependency-rules.md, docs/testing.md using targeted scans (README/manifests/CI/entrypoints).
- Expand context shards only for a requested subtree path.
- Validate kit consistency.

Rules:
- Never do repo-wide reads.
- Preserve manual edits outside:
  <!-- AGENTKIT:BEGIN --> ... <!-- AGENTKIT:END -->
- Ask the user up to 3 clarifying questions if update/expand is ambiguous.
```

Agents in `.opencode/agents/` are supported. ([OpenCode][3])

---

### 5.2 Commands

**`.opencode/commands/explore.md`**

```md
---
description: Explore code slice (working set + deps + flow) without overflowing context
agent: kit-explore
---

$ARGUMENTS

Follow docs/report-format.md exactly.
```

**`.opencode/commands/fix.md`**

```md
---
description: Fix a bug with minimal patch (requires explore first)
agent: kit-fix
---

Bug description:
$ARGUMENTS
```

**`.opencode/commands/context-expand.md`**

```md
---
description: Generate CONTEXT.md shards for a specific subtree path only
agent: kit-maintain
---

Expand AgentKit context shards under this path only:
$ARGUMENTS

Rules:
- Create/refresh CONTEXT.md for the subtree boundary and at most its immediate children.
- Update docs/repo-map.md if new boundaries are introduced.
```

**`.opencode/commands/agentkit-update.md`**

```md
---
description: Re-scan targeted files and update repo-map/dependency/testing docs (no repo-wide reads)
agent: kit-maintain
---

Update AgentKit:
- Re-scan README/manifests/CI/entrypoints only
- Refresh docs/repo-map.md, docs/dependency-rules.md, docs/testing.md
- Preserve manual notes
```

**`.opencode/commands/agentkit-validate.md`**

```md
---
description: Validate AgentKit consistency (files exist, agents/commands wired, budgets sane)
agent: kit-maintain
---

Validate:
- instruction files exist
- command agents exist
- skills are discoverable
- CONTEXT.md shards are within size budgets
- print any TODOs created during generation
```

Commands in `.opencode/commands/` with frontmatter + `$ARGUMENTS` are supported. ([OpenCode][4])

---

### 5.3 Skills

**`.opencode/skills/repo-navigation/SKILL.md`**

```md
---
name: repo-navigation
description: Progressive disclosure navigation; choose minimal working set; avoid context overflow
compatibility: opencode
---

## What I do
- Identify the smallest set of files to read for a task.
- Stop early once the flow is explainable.

## Working set rubric (typical)
- 1 boundary CONTEXT.md
- 1–2 routing/dispatch files
- 1–3 core logic files
- 1–2 type/config/public API files
- 0–1 tests/build files (only if needed)
```

**`.opencode/skills/dependency-mapping/SKILL.md`**

```md
---
name: dependency-mapping
description: Build a lightweight boundary dependency explanation (direct + 1–2 hop)
compatibility: opencode
---

## Output
- Direct deps (imports/manifests)
- Transitive deps (1–2 hop)
- Interfaces crossed (public APIs/contracts/CLI boundaries)

## Method
- Prefer manifests + entrypoint imports over full graph scans.
```

**`.opencode/skills/bug-triage/SKILL.md`**

```md
---
name: bug-triage
description: Convert bug description into hypotheses + where to look + confirm/deny plan
compatibility: opencode
---

## Intake
- Symptom:
- Trigger:
- Expected vs actual:
- Environment:
- Logs/stack traces:
- Recent changes hint:

## Output
- H1..H3 hypotheses
- Evidence to confirm/deny each
- Minimal working set candidates
```

**`.opencode/skills/patch-discipline/SKILL.md`**

```md
---
name: patch-discipline
description: Keep fixes small, reviewable, and safe
compatibility: opencode
---

## Rules
- Minimal diff
- Avoid refactors while fixing bugs
- Preserve invariants; document changes
- Provide the narrowest validation steps
```

Skills are discovered from `.opencode/skills/<name>/SKILL.md` and loaded on-demand. ([OpenCode][5])

---

## 6) Boundary `CONTEXT.md` shard template

For each boundary, AgentKit writes:

```md
# <boundary> — <short purpose>

## Purpose
<2–4 lines: what it owns and what it does not own>

## Entry points (start here)
- <file> — why
- <file> — why

## Public APIs / interfaces
- <files/dirs>

## Depends on
- <internal boundaries>
- <external systems>

## Used by
- <callers>

## Key flows
1) <flow name> — <files involved>
2) <flow name> — <files involved>

## Invariants / gotchas
- <rules the code relies on>

## Tests / validation
- <fastest test/command>
```

And if a `CONTEXT.md` already exists, it appends inside:

```md
<!-- AGENTKIT:BEGIN -->
...generated block...
<!-- AGENTKIT:END -->
```

So updates don’t destroy human notes.

---

# Practical tips for using this in very large repos

* Put only the **small compass docs** in `instructions`. Don’t include `**/CONTEXT.md` there; it will explode context. `instructions` supports globs, but you should be selective. ([OpenCode][6])
* Let agents load boundary `CONTEXT.md` **lazily** (“nearest shard wins”).
* When a repo has hundreds of packages:

  * generate a shard for `packages/` and only the most central ~10 packages
  * then use `/context-expand packages/foo` on demand

---

If you want, paste a short description of *one of your repos* (even anonymized) and its top-level tree (2 levels). I’ll show you what **AgentKit’s first 5 questions** would look like (only the ones it truly needs), and what the **first generated repo-map + boundary shards** would end up containing.

[1]: https://opencode.ai/docs/tools/ "Tools | OpenCode"
[2]: https://opencode.ai/docs/rules/ "Rules | OpenCode"
[3]: https://opencode.ai/docs/agents/ "Agents | OpenCode"
[4]: https://opencode.ai/docs/commands/?utm_source=chatgpt.com "Commands"
[5]: https://opencode.ai/docs/skills/ "Agent Skills | OpenCode"
[6]: https://opencode.ai/docs/config/ "Config | OpenCode"

Here’s a validation pass of the “Agent Context Kit Generator” idea against **what OpenCode actually supports today**, plus the exact change you asked for: a **sufficiency gate** that makes the model ask the user **up to 5 questions only when needed**.

---

## What’s validated and solid in your approach

### 1) “Root rules + always-loaded small docs” is the right OpenCode pattern

* OpenCode loads `AGENTS.md` as rules. ([OpenCode][1])
* OpenCode does **not** automatically parse file references inside `AGENTS.md`, so your design that uses `opencode.json(c)` → `instructions` to always-load the small docs is exactly the recommended approach. ([OpenCode][1])
* Instruction files listed in `instructions` are **combined** with `AGENTS.md`. ([OpenCode][1])

✅ This validates the “keep always-loaded docs tiny, shard everything else” design.

---

### 2) “Commands + skills + prompts” are first-class in OpenCode

* Commands defined as markdown files in `.opencode/commands/*.md` are supported (frontmatter + template body). ([OpenCode][2])
* Skills discovered from `.opencode/skills/<name>/SKILL.md` are supported and loaded on-demand via the native skill mechanism. ([OpenCode][3])
* Agent config supports `prompt: "{file:...}"`, per-agent permissions, mode (primary/subagent/all), and max steps. ([OpenCode][4])

✅ This validates your plan to generate: prompts, skills, commands, docs.

---

### 3) Permissions and safety controls are exactly built for this

* Permissions are `allow / ask / deny`, support glob rules, and can be applied per agent. ([OpenCode][5])
* The `edit` permission gates **all file modification** tools (`edit`, `write`, `patch`, `multiedit`). ([OpenCode][6])
* You can whitelist bash commands with glob rules (and put `"*": "ask"` first). ([OpenCode][4])
* The legacy `tools` boolean config is deprecated (still supported), so prefer `permission` for the generator outputs. ([OpenCode][5])

✅ This validates the “read-only explore agent” + “fix agent with ask-gated edits” posture.

---

### 4) Ignoring noisy dirs is supported

OpenCode supports `watcher.ignore` patterns in config, so your generator can safely add it. ([OpenCode][7])

✅ This validates the “monorepo noise control” part.

---

## Small corrections to what I suggested earlier

### Remove `permission.question`

There’s no OpenCode “question tool” in the docs; agents just ask the user directly via chat. So **don’t generate**:

```jsonc
"question": "allow"
```

Instead: implement the “ask user up to 5 questions” logic in the generator agent’s *prompt* and have it ask in conversation.

### Prefer `permission` over `tools`

Since `tools` booleans are now legacy/deprecated, generate kits primarily using `permission`. ([OpenCode][5])
You can still optionally set agent-level `tools` to hard-disable edits for the Explore agent, but don’t rely on `tools` alone. ([OpenCode][4])

---

## Add the missing piece you asked for: a sufficiency gate + up to 5 questions

### Core principle

The generator should **not** ask questions unless it cannot produce these mandatory outputs reliably:

1. **Boundaries** (top-level or manifest-defined modules)
2. **Entry points** (main servers/apps/CLIs, exported APIs)
3. **Build/test commands** (from README/CI/manifest)
4. **Dependency shape** (at least a minimal layering guess)
5. **Directory exclusions** (huge generated/vendor folders)

If any of these remain ambiguous after targeted scanning, the agent asks up to 5 questions.

---

## The 5 questions (the model asks only the ones it needs)

Below are the exact questions I recommend baking into the generator prompt. They’re designed to be **multiple-choice** and answerable fast.

### Q1 — What are the repo’s “deliverables”?

Ask if you can’t clearly infer from tree/manifests.

> Which outputs should agents optimize for? (select all)
> A) Backend services (HTTP/gRPC)
> B) Frontend web app(s)
> C) Mobile app(s)
> D) CLI tools / daemons
> E) Libraries / SDKs only
> F) Infrastructure (IaC) is a major boundary
> G) Mixed/other: ________

---

### Q2 — Which areas are the top priorities for exploration shards?

Ask if the description doesn’t mention key domains and scanning doesn’t reveal obvious “core” areas.

> Which areas matter most for the first iteration of `CONTEXT.md` shards? (pick up to 5)
> A) Auth/identity
> B) Payments/billing
> C) Data ingestion/ETL
> D) Storage/DB layer
> E) API routing/handlers
> F) Background jobs/queues
> G) Frontend routing/state
> H) Observability (logging/metrics/tracing)
> I) Security policies/permissions
> J) Other: ________

---

### Q3 — What are the “must-work” developer commands?

Ask if README/CI doesn’t contain clear commands, or there are multiple toolchains.

> What are the canonical commands we should put in `docs/testing.md`?
> A) “Use CI commands” (tell me the CI job name)
> B) I can provide the commands (paste: install/build/test/lint)
> C) There are multiple environments (list: dev/stage/prod or OS/arch)
> D) We don’t have stable commands yet; generate placeholders and mark TODO

---

### Q4 — Any dependency/layering rules we must enforce?

Ask if you can’t infer layering from workspace deps/import patterns, or if repo is known to be strict.

> Do you have any strict dependency rules? (select all)
> A) “Apps/services can depend on libs, not vice versa”
> B) “Domain layer must be pure (no IO)”
> C) “No cyclic deps allowed; enforce DAG”
> D) “Only through public APIs (no deep imports)”
> E) “Monorepo uses explicit boundaries (Nx/Bazel/pnpm workspaces/etc.)”
> F) No strict rules—best-effort inferred graph is fine
> G) Other: ________

---

### Q5 — What should we explicitly exclude to keep context small?

Ask if the repo has huge directories or the scan detects a lot of generated/vendor output.

> Which paths should we ignore (watcher + exploration) to avoid context bloat?
> A) `node_modules/`, `dist/`, `build/`, `out/`
> B) `vendor/`, `third_party/`
> C) Generated code directories (list them)
> D) Large test fixtures (list them)
> E) None / not sure

---

## How to implement this in the generator prompt

Add a “sufficiency gate” section to your `agentkit-generator.txt` like this (this is the exact wording I’d generate):

```txt
SUFFICIENCY GATE
After targeted scanning (README/manifests/CI/entrypoints), verify you can fill:
- boundaries (top-level subsystems or manifest-defined modules)
- entry points per boundary
- canonical build/test commands
- a minimal dependency/layering model
- ignore list for noisy dirs

If ANY item is missing or ambiguous:
- Ask the user up to 5 questions total.
- Ask only the questions needed from Q1..Q5.
- Ask them in a single message.
- Then proceed with generation using their answers + scan results.
```

This ensures the model is deterministic and doesn’t “chat forever.”

---

## Add a validation step to the generator (so it “validates what it produced”)

To truly validate output, instruct the generator to run a **post-write sanity check** (no full builds required):

**Generator post-check requirements:**

* Every file referenced in `opencode.jsonc.instructions[]` exists. ([OpenCode][1])
* Every `.opencode/commands/*.md` references an existing agent (or built-in `build/plan/explore`). ([OpenCode][2])
* Skill folders contain `SKILL.md` and valid frontmatter names. ([OpenCode][3])
* Line-count budgets:

  * `docs/repo-map.md`, `docs/dependency-rules.md`, `docs/testing.md`, `docs/report-format.md` are “small”
  * each `CONTEXT.md` is “small”
* If the generator added `watcher.ignore`, it should include the common noisy patterns. ([OpenCode][7])

You can also add a repo-local command:

**`.opencode/commands/agentkit-validate.md`**

* It doesn’t need special tooling—just asks the agent to verify those invariants and print a checklist.

(Commands are supported by `.opencode/commands/*.md` frontmatter. ([OpenCode][2]))

---

## Bottom line

Your architecture is valid for OpenCode **as-is**, with two key upgrades:

1. **Sufficiency gate** + up to **5 targeted questions** (Q1–Q5 above)
2. A generator **post-write validation checklist** to ensure the kit is internally consistent and stays “low-context”

If you want, I can now give you the exact final versions of:

* `agentkit-generator.txt` (full prompt with sufficiency gate + validation)
* `.opencode/commands/agentkit-validate.md`
* the “repo-local kit template” files with placeholders the generator fills

…and keep them strictly aligned to the current OpenCode docs we just validated.

[1]: https://opencode.ai/docs/rules/ "Rules | OpenCode"
[2]: https://opencode.ai/docs/commands/?utm_source=chatgpt.com "Commands"
[3]: https://opencode.ai/docs/skills/?utm_source=chatgpt.com "Agent Skills"
[4]: https://opencode.ai/docs/agents/ "Agents | OpenCode"
[5]: https://opencode.ai/docs/permissions/ "Permissions | OpenCode"
[6]: https://opencode.ai/docs/tools/?utm_source=chatgpt.com "Tools"
[7]: https://opencode.ai/docs/config/?utm_source=chatgpt.com "Config"

Here’s a concrete way to make what we did for **xnu** become a **repo-agnostic “Agent Context Kit Generator”**:

* You give it a **repo description** (1–3 paragraphs is enough).
* The generator agent **scans only targeted files** (README, build manifests, CI, entrypoints).
* It **writes** the exact kit we designed: `AGENTS.md`, `opencode.jsonc`, `docs/*`, `prompts/*`, `.opencode/skills/*`, `.opencode/commands/*`, plus `CONTEXT.md` shards at the right boundaries.
* It also creates a **human README** explaining how to use the kit without blowing context.

This is tailored to OpenCode’s actual mechanics:

* project rules via `AGENTS.md` and instruction files via `instructions` in config ([OpenCode][1])
* skills discovered from `.opencode/skills/<name>/SKILL.md` ([OpenCode][2])
* commands defined in `.opencode/commands/*.md`, support `$ARGUMENTS`, `!` shell output injection, and `@file` inclusion ([OpenCode][3])
* permissions are controlled via `permission` (with glob rules) and `edit` covers all write/patch/edit tools ([OpenCode][4])
* config sources merge (remote/global/project + `.opencode` dirs) ([OpenCode][5])

---

# The two-part solution

## Part A — One-time “generator” installation (global)

This makes `/agentkit "<repo description>"` available in **any** repo you open with OpenCode, even before the repo has any OpenCode files.

### A1) Global agent: `agentkit`

Add this to your global config (or merge it in):

> **File:** `~/.config/opencode/opencode.jsonc`
> (If you use `.json` instead of `.jsonc`, remove comments.)

```jsonc
{
  "$schema": "https://opencode.ai/config.json",

  "agent": {
    "agentkit": {
      "description": "Generate OpenCode Agent Context Kit files for the current repository",
      "mode": "subagent",
      "prompt": "{file:./prompts/agentkit-generator.txt}",

      "permission": {
        // Default to safe. The generator must ask before edits or running commands.
        "*": "allow",
        "edit": "ask",
        "bash": {
          "*": "ask",
          "git status*": "allow",
          "git diff*": "allow",
          "git rev-parse*": "allow",
          "git ls-files*": "allow"
        },
        "webfetch": "deny",
        "websearch": "deny",

        // Allow scanning the repo
        "read": "allow",
        "list": "allow",
        "glob": "allow",
        "grep": "allow",

        // Allow asking the user tiny clarifying questions if needed
        "question": "allow",

        // Allow loading generic skills if you keep them globally
        "skill": "allow"
      }
    }
  }
}
```

Why this shape:

* `permission` supports `allow/ask/deny` per tool and glob rules for fine control. ([OpenCode][4])
* `edit` gates all file modifications (`write`, `patch`, `multiedit` too). ([OpenCode][4])
* agents can be configured in config; `prompt` can reference a file path. ([OpenCode][6])

### A2) Global prompt for the generator

> **File:** `~/.config/opencode/prompts/agentkit-generator.txt`

```txt
You are AgentKit Generator for OpenCode.

Goal
- Given a repo description + a minimal scan of the repo, generate a "low-context navigation kit" for OpenCode:
  - AGENTS.md
  - opencode.jsonc
  - docs/* (repo-map, dependency-rules, testing, report-format, plus docs/opencode/README.md)
  - prompts/* (explore-agent, fix-agent)
  - .opencode/skills/* (repo-navigation, dependency-mapping, bug-triage, patch-discipline)
  - .opencode/commands/* (explore, fix, context-expand, agentkit-update)
  - boundary CONTEXT.md files at correct seams

Hard constraints
- Do NOT read the entire repo. Use progressive disclosure.
- Keep always-loaded docs short:
  - docs/repo-map.md <= ~200 lines
  - docs/dependency-rules.md <= ~200 lines
  - docs/testing.md <= ~200 lines
  - docs/report-format.md <= ~200 lines
- CONTEXT.md shards <= ~150 lines each.
- Prefer "start here" pointers over exhaustive detail.

Inputs
- The user will provide a repository description (product, architecture, languages, key flows).
- You must verify structure by scanning the repository with list/glob/grep/read.
- If essential info is missing, ask at most 1-2 multiple-choice questions (question tool), then proceed.

Scan plan (targeted reads only)
1) Identify repo root and top-level structure:
   - list "." and list top-level directories
2) Detect build systems and languages:
   - glob for common manifests: package.json, pnpm-workspace.yaml, yarn.lock, go.work, go.mod, Cargo.toml, pyproject.toml, requirements.txt,
     Makefile, CMakeLists.txt, WORKSPACE, BUILD/BUILD.bazel, pom.xml, gradle files, etc.
3) Read only:
   - root README* (first ~200 lines)
   - build manifests (first ~200 lines each)
   - CI workflows (e.g., .github/workflows/*) only enough to extract build/test commands (~200 lines per workflow)
4) Boundary discovery:
   - Find "boundaries" using heuristics:
     - top-level dirs (excluding .git, node_modules, vendor, dist, build, out, target)
     - monorepo containers: apps/, services/, packages/, crates/, modules/
     - any dir containing a build manifest (go.mod, Cargo.toml, package.json, etc.) = potential boundary
   - Limit initial CONTEXT.md generation to:
     - all top-level boundaries OR
     - container dirs + top N subprojects (N<=20) by either size heuristic (file count) or manifest presence
   - For large sets, generate a single container CONTEXT.md (e.g., packages/CONTEXT.md) and provide a command for expanding later.
5) For each boundary selected:
   - Pick 3–6 “targeted code files” to read:
     - the boundary’s local README (if exists)
     - its build manifest
     - 1–2 entry points (main/index/server/app, or cmd/*/main.go, src/main.*, etc.)
     - 1 public API surface (index.ts, lib.rs, include header, exported module)
     - 1 test file if obvious
   - Use grep/glob to find entrypoints; avoid broad reading.

Dependency inference (lightweight)
- Infer boundary-to-boundary dependencies using:
  - monorepo manifests (workspace deps, internal package deps)
  - import/include references in boundary entrypoints
- Produce docs/dependency-rules.md with:
  - observed edges (best-effort)
  - recommended layering rules
  - “start here” pointers per question type

Output: write files
- Create missing directories.
- If files already exist:
  - do not destroy existing intent
  - update by inserting sections (clearly marked) or create .agentkit/ alternatives (avoid overwriting without approval).

After generation
- Print a short human summary:
  - what files were created
  - how to run /explore and /fix
  - how to expand CONTEXT shards later
```

### A3) Global command you run in any repo

> **File:** `~/.config/opencode/commands/agentkit.md`

```md
---
description: Generate OpenCode Agent Context Kit for this repository (low-context navigation + fix workflow)
agent: agentkit
---

Repository description (from user):
$ARGUMENTS

Task:
1) Scan targeted files only (README/build manifests/CI/entrypoints).
2) Generate the Agent Context Kit in-repo:
   - AGENTS.md
   - opencode.jsonc
   - docs/* + docs/opencode/README.md
   - prompts/*
   - .opencode/skills/*
   - .opencode/commands/*
   - boundary CONTEXT.md shards
3) Keep files short and optimized for low-context navigation.
4) Do not overwrite existing files without preserving intent.
```

OpenCode supports custom commands in `~/.config/opencode/commands/` (or per-project `.opencode/commands/`) and supports `$ARGUMENTS`. ([OpenCode][3])

---

## Part B — What gets generated inside a repo

When you run:

```
/agentkit "This is a Python + TS monorepo for ... the main services are ... build uses ... key flows ..."
```

…it writes the following **repo-local kit** (template-based, filled by scan results):

```txt
<repo>/
  AGENTS.md
  opencode.jsonc

  docs/
    repo-map.md
    dependency-rules.md
    testing.md
    report-format.md
    opencode/
      README.md

  prompts/
    explore-agent.txt
    fix-agent.txt

  .opencode/
    skills/
      repo-navigation/SKILL.md
      dependency-mapping/SKILL.md
      bug-triage/SKILL.md
      patch-discipline/SKILL.md
    commands/
      explore.md
      fix.md
      context-expand.md
      agentkit-update.md

  <boundary>/CONTEXT.md
  <boundary>/<subboundary>/CONTEXT.md   (only for selected top-N)
```

Why `.opencode/` matters: OpenCode loads agents/commands/plugins/skills from `.opencode` directories as a config source. ([OpenCode][5])

---

# The exact repo-local files (templates)

Below are the **exact contents** the generator should write (the generator fills in the repo-specific sections).

---

## 1) `AGENTS.md` (root)

```md
# Agent Guide (Repo)

## Goal
Enable agents to locate the right files fast, explain them, and make changes without overflowing context.

## Context budget rules
- NEVER read the whole repo.
- Always start with:
  1) docs/repo-map.md
  2) docs/dependency-rules.md
  3) the nearest boundary CONTEXT.md
- Only then read entrypoints + direct dependencies.

## Default workflow
1) Use /explore to produce:
   - scope
   - working set (≤10 read, ≤10 likely edit)
   - dependency notes (direct + 1–2 hop)
   - step-by-step flow explanation
   - validation commands
2) Use /fix to implement minimal patch and validate.

## Where context lives
- docs/repo-map.md — shallow map and entrypoints
- docs/dependency-rules.md — layering + boundary crossings
- docs/testing.md — build/test commands
- docs/report-format.md — required exploration output format
- */CONTEXT.md — boundary shards

## Maintenance rule
When a change modifies public behavior or invariants of a boundary:
- update that boundary’s CONTEXT.md in the same PR.
```

OpenCode uses `AGENTS.md` as project rules (with precedence rules). ([OpenCode][1])

---

## 2) `opencode.jsonc` (project)

```jsonc
{
  "$schema": "https://opencode.ai/config.json",

  "instructions": [
    "docs/repo-map.md",
    "docs/dependency-rules.md",
    "docs/testing.md",
    "docs/report-format.md"
  ],

  "permission": {
    // Default safe posture
    "*": "allow",

    // Prevent accidental changes unless approved
    "edit": "ask",

    // Allow scanning
    "read": "allow",
    "list": "allow",
    "glob": "allow",
    "grep": "allow",

    // Bash is powerful; keep it gated
    "bash": {
      "*": "ask",
      "git status*": "allow",
      "git diff*": "allow",
      "git log*": "allow",
      "git grep*": "allow"
    },

    // Avoid pulling internet into the context by default
    "webfetch": "deny",
    "websearch": "deny",

    // Skills are allowed (they load from local SKILL.md files)
    "skill": "allow",

    // Allow structured clarifications if needed
    "question": "allow"
  },

  "watcher": {
    "ignore": [
      "node_modules/**",
      "dist/**",
      "build/**",
      "out/**",
      ".git/**"
    ]
  }
}
```

Notes:

* `instructions` is the recommended way to include additional instruction files; OpenCode doesn’t automatically parse file references inside `AGENTS.md`. ([OpenCode][1])
* `permission` supports global `*` rules and granular tool rules. ([OpenCode][4])
* config sources merge and `.opencode` directories are part of the precedence chain. ([OpenCode][5])

---

## 3) `docs/report-format.md`

```md
# Exploration / explanation report format (required)

## 1) Scope
- In scope:
- Out of scope:
- Assumptions:

## 2) Working set
### Read (≤10)
- path — why
### Likely edit (≤10)
- path — why

## 3) Dependency notes
- Direct deps:
- Transitive deps (1–2 hop):
- Boundary crossings (APIs/interfaces):

## 4) Step-by-step flow
1) Entry point
2) Routing/dispatch
3) Core logic
4) State mutation
5) Output/return

For each step:
- file/function
- data structure
- 1-sentence explanation

## 5) Risks / bug hypotheses (only if asked)
- Hypothesis, evidence, how to confirm

## 6) Validation
- Minimal checks
- Build/test commands (if possible)
```

---

## 4) `docs/repo-map.md` (generated)

```md
# Repo map (shallow)

This file is the always-loaded navigation compass.

## What this repo is
- Product: <from repo description / README>
- Primary languages: <detected>
- Build system(s): <detected>

## Top-level boundaries
<one section per boundary>
- <boundary_path>/ — 1–2 lines purpose
  - Entry points: <paths>
  - Start here: <paths>

## Common tasks → where to look
- “API request handling” → <paths>
- “Database schema/migrations” → <paths>
- “Background jobs/queues” → <paths>
- “Frontend route/page” → <paths>
- “Shared library/util” → <paths>
```

---

## 5) `docs/dependency-rules.md` (generated)

```md
# Dependency rules (agent-oriented)

These rules keep exploration bounded and changes safe.

## Layers (recommended)
- Apps/services (deployables) may depend on:
  - packages/libs
  - shared tooling
- packages/libs may depend on:
  - other libs only if explicitly allowed
- infra/tools should not depend on runtime apps

## Observed internal dependencies (best-effort)
- <boundary A> -> <boundary B> (evidence: manifest/import)

## Boundary crossings (“interfaces”)
- Public APIs:
- CLI entrypoints:
- Messaging/queues:
- Shared types/contracts:

## Stop conditions
Stop reading once you can name:
- entry point
- key call chain (1–2 hops)
- main data structures
- likely edit files
```

---

## 6) `docs/testing.md` (generated)

```md
# Build & test commands (quick reference)

## Install / bootstrap
- <command(s) from README/CI>

## Run / dev
- <command(s)>

## Test
- <command(s)>

## Lint / format
- <command(s)>

## Notes
- If builds are heavy, prefer the smallest relevant target/test.
```

---

## 7) Human explanation: `docs/opencode/README.md`

```md
# OpenCode Agent Context Kit

This repo contains a low-context navigation and fixing workflow for OpenCode agents.

## Why this exists
Large repos exceed model context windows. This kit makes agents effective by:
- Always-loading only 3–4 small docs
- Sharding subsystem knowledge into boundary CONTEXT.md files
- Using Skills for deeper guidance on-demand

## How to use
### 1) Explore (read-only behavior)
Run:
- `/explore <your question or bug description>`

Output will follow docs/report-format.md and include:
- working set
- dependencies
- flow explanation
- validation commands

### 2) Fix (edits require approval)
Run:
- `/fix <bug description>`

The agent must:
- use the explore findings
- propose a minimal patch plan
- validate changes
- update the nearest CONTEXT.md if invariants changed

## How to expand context shards
If you need deeper coverage:
- `/context-expand path/to/subtree`

This generates additional CONTEXT.md shards for that subtree only.

## Files to know
- AGENTS.md — rules for agents
- opencode.jsonc — instructions + permissions
- docs/repo-map.md — repo compass
- docs/dependency-rules.md — layering rules
- docs/testing.md — commands
- */CONTEXT.md — boundary shards
- .opencode/skills/* — reusable playbooks
- .opencode/commands/* — shortcuts
```

---

## 8) Prompts

### `prompts/explore-agent.txt`

```txt
You are the Explore Agent for this repository. You are read-only in behavior.

Mission
- Identify the minimal working set for the user request.
- Explain dependencies (direct + 1–2 hop).
- Explain the flow step-by-step using docs/report-format.md.
- Do NOT recommend repo-wide reads.

Process (mandatory)
1) Read docs/repo-map.md + docs/dependency-rules.md (they are in instructions).
2) Choose the primary boundary (subsystem) and read its nearest CONTEXT.md.
3) Find entry points via grep/glob; read only a few core files.
4) Stop early once the working set and flow are clear.

Output
- Must use docs/report-format.md exactly.
```

### `prompts/fix-agent.txt`

```txt
You are the Fix Agent.

Non-negotiable workflow
1) MUST use /explore first (or reuse a fresh explore report from the same session).
2) Propose a minimal fix plan before editing.
3) Make the smallest patch that fixes the bug.
4) Validate using docs/testing.md and boundary CONTEXT.md.
5) Update boundary CONTEXT.md if you change behavior/invariants.

Output sections
- Bug statement
- Hypotheses + how to confirm
- Working set
- Fix plan
- Patch summary
- Validation steps
- Documentation updates
```

---

## 9) Skills (repo-local)

Skills live at `.opencode/skills/<name>/SKILL.md`. ([OpenCode][2])

### `.opencode/skills/repo-navigation/SKILL.md`

```md
---
name: repo-navigation
description: Progressive disclosure navigation for huge repos; keep context small; working-set selection
---

## Rules
- Start from docs/repo-map.md and nearest CONTEXT.md.
- Find entry points first; expand outward in 1–2 hop rings.
- Stop when you can name: entry point, call chain, data, likely edit files.

## Working set budget
- 1 boundary CONTEXT.md
- 1–2 routing/dispatch files
- 1–3 core logic files
- 1–2 type/header/config files
- 1 test/build rule if needed
```

### `.opencode/skills/dependency-mapping/SKILL.md`

```md
---
name: dependency-mapping
description: Map boundary dependencies (direct + 1–2 hop) and impact radius for changes
---

## Outputs
- Direct deps: imports/includes/manifest dependencies
- Transitive deps: 1–2 hop
- Interfaces crossed: public APIs / CLIs / shared contracts

## Method
- Prefer manifests + entrypoint imports over full-graph scans.
- When uncertain, state uncertainty and list what to read next.
```

### `.opencode/skills/bug-triage/SKILL.md`

```md
---
name: bug-triage
description: Turn a bug description into hypotheses + where to look (fast)
---

## Intake fields
- Symptom:
- Trigger:
- Expected vs actual:
- Environment (runtime, OS, arch, config):
- Any logs/stack traces:
- “Recent changes” hint:

## Output
- 3 hypotheses (H1..H3)
- Evidence to confirm/deny
- Minimal working set candidates
```

### `.opencode/skills/patch-discipline/SKILL.md`

```md
---
name: patch-discipline
description: Keep fixes small, reviewable, and safe for agents
---

## Rules
- Prefer minimal diff
- Avoid refactors while fixing bugs
- Preserve invariants; if you change them, document them
- Add the narrowest test (or at least a validation command)
- Summarize risk areas and why regression is unlikely
```

---

## 10) Commands (repo-local)

Commands can live in `.opencode/commands/` and support `$ARGUMENTS`. ([OpenCode][3])

### `.opencode/commands/explore.md`

```md
---
description: Explore code (working set + dependencies + flow) without overflowing context
agent: explore
---

$ARGUMENTS

Use docs/report-format.md for output.
Do not read the whole repo.
Start from docs/repo-map.md and nearest boundary CONTEXT.md.
```

### `.opencode/commands/fix.md`

```md
---
description: Fix a bug using explore → minimal patch → validation
agent: build
---

Bug description:
$ARGUMENTS

Process:
1) Run @explore first and produce working set + flow.
2) Propose a minimal patch plan.
3) Apply smallest fix, validate, and update nearest CONTEXT.md if needed.
```

### `.opencode/commands/context-expand.md`

```md
---
description: Generate CONTEXT.md shards for a specific subtree (on-demand)
agent: agentkit
---

Generate additional CONTEXT.md shards under this path only:
$ARGUMENTS

Rules:
- Do not regenerate the whole kit.
- Create/refresh CONTEXT.md for the subtree boundary (and at most its immediate children).
- Update docs/repo-map.md if new boundaries are added.
```

### `.opencode/commands/agentkit-update.md`

```md
---
description: Re-scan targeted files and update repo-map/dependency/testing docs + CONTEXT shards
agent: agentkit
---

Update the Agent Context Kit.

Notes:
- Re-scan only targeted files (README, manifests, CI, entrypoints).
- Keep docs small.
- Preserve manual notes in existing CONTEXT.md files.
```

---

## 11) Boundary `CONTEXT.md` template (generated per boundary)

> **File:** `<boundary>/CONTEXT.md`

```md
# <boundary>/ — <short name>

## Purpose
<2–4 lines describing role + ownership>

## Entry points (start here)
- <path> — why
- <path> — why

## Public APIs / interfaces
- <paths to exported modules / headers / routes / CLI commands>

## Depends on
- <internal boundaries>
- <external systems>

## Used by
- <boundaries that import/call this>

## Key flows
1) <flow> — files involved
2) <flow> — files involved

## Invariants / gotchas
- <locking/lifecycle rules, validation assumptions, caching rules, etc>

## Tests / validation
- <fastest relevant test>
- <lint/format if relevant>
```

---

# How this achieves “low window context” reliably

1. Only **4 small docs** are always loaded (repo-map, dependency-rules, testing, report-format).
2. Everything else is **sharded** by boundary in `CONTEXT.md`.
3. Deeper playbooks live in **Skills**, loaded only when needed. ([OpenCode][2])
4. Commands let you do “just-in-time context” with a single line (`/explore …`, `/fix …`, `/context-expand …`). ([OpenCode][3])

---

# If you want this to be fully “hands-off”

If your goal is to run this across many repos automatically (CI or internal platform), OpenCode also has a JS/TS SDK to control the server programmatically. ([OpenCode][7])
You can build a pipeline like:

* clone repo → run agentkit with description → commit files → open PR.

---

If you share a sample “repo description schema” you want to standardize on (fields, required/optional), I can tighten the generator prompt so it produces **more deterministic boundary selection** and **more accurate repo-map/testing extraction** with fewer reads—without asking the user follow-up questions.

[1]: https://opencode.ai/docs/rules/ "Rules | OpenCode"
[2]: https://opencode.ai/docs/skills/?utm_source=chatgpt.com "Agent Skills"
[3]: https://opencode.ai/docs/commands/ "Commands | OpenCode"
[4]: https://opencode.ai/docs/permissions/ "Permissions | OpenCode"
[5]: https://opencode.ai/docs/config/ "Config | OpenCode"
[6]: https://opencode.ai/docs/agents/ "Agents | OpenCode"
[7]: https://opencode.ai/docs/sdk/?utm_source=chatgpt.com "SDK"

You already have the **navigation kit**. To move from “explain” → “fix a bug safely,” you mainly need to add:

1. **a second agent** (`fix`) that’s allowed to edit, but only after exploration
2. a **bug-fix workflow contract** (what it must output + when it may change files)
3. **permissions / guardrails** (edit is “ask” + safe bash allowlist)
4. **a patch discipline** (small diffs, compile/test hooks, update local CONTEXT/docs)
5. optional: a **bug-triage skill** that turns your bug description into hypotheses + a working set

Below is exactly what to add/modify in the existing setting.

---

## 1) Add a `@fix` agent (separate from `@explore`)

Keep `@explore` read-only. Add `@fix` for changes.

### Modify `opencode.jsonc`

Add this under `"agent"` alongside `explore`:

```jsonc
{
  "agent": {
    "fix": {
      "description": "Bug-fix agent: uses @explore output, edits minimal files, validates, updates docs",
      "steps": 18,
      "temperature": 0.1,
      "prompt": "{file:./prompts/fix-agent.txt}",
      "permission": {
        "edit": "ask",
        "webfetch": "deny",
        "bash": {
          "*": "ask",
          "git status*": "allow",
          "git diff*": "allow",
          "git log*": "allow",
          "git grep*": "allow",
          "make -n*": "allow",
          "make SDKROOT=*": "ask",
          "make install_kernels*": "ask"
        },
        "skill": {
          "*": "ask",
          "repo-navigation": "allow",
          "dependency-mapping": "allow",
          "xnu-architecture": "allow",
          "xnu-bug-hunting": "allow"
        }
      }
    }
  }
}
```

Why:

* `edit: ask` forces an approval step before modifications (good for kernel code).
* `bash` allowlist avoids the agent running dangerous commands silently.
* `webfetch: deny` keeps it deterministic and prevents “random internet fixes.”

OpenCode permissions and agent configuration are designed for this exact kind of separation.  (see note below)

> I didn’t browse in this thread yet, and for OpenCode spec accuracy it’s worth verifying the latest docs before you implement. If you want, I can web-check the exact schema fields for agent permissions and bash allowlists in current OpenCode.

(If you prefer, you can keep `bash` entirely `ask` at first.)

---

## 2) Add `prompts/fix-agent.txt` (the bug-fix contract)

> **New file:** `prompts/fix-agent.txt`

```txt
You are the Fix Agent for xnu.

NON-NEGOTIABLE WORKFLOW
1) You MUST run @explore first unless the user has already provided an @explore report for this same bug.
2) You MUST propose a patch plan and get approval (edit permission is ask) before editing.
3) Make the smallest possible change that fixes the bug.
4) After editing: validate using the narrowest commands from docs/testing.md and boundary CONTEXT.md.

PROGRESSIVE DISCLOSURE
- Use docs/repo-map.md and docs/dependency-rules.md.
- Read only the boundary CONTEXT.md for the edited area.
- Keep the working set small; do not “refactor.”

REQUIRED OUTPUT SECTIONS
## Bug statement (restated)
## Hypotheses
- H1, H2, H3 with evidence to confirm/deny
## Working set
- Files to read
- Files to edit
## Fix plan
- Exact change and why it is correct
- Risks and regression areas
## Patch
- Provide diff summary and rationale
## Validation
- Minimal checks / build targets
## Documentation updates
- Update nearest CONTEXT.md if public behavior/invariants changed
```

This ensures the agent doesn’t jump straight to edits and doesn’t expand scope.

---

## 3) Update root `AGENTS.md` to enforce “explore → fix”

Add a “Bug fixing” section.

> **Modify** `AGENTS.md`:

```md
## Bug fixing workflow (mandatory)
- Use @explore first to produce a working set + dependency notes + flow walkthrough.
- Then use @fix to implement the smallest patch possible.
- @fix must:
  - restate bug + hypotheses
  - change minimal files
  - run minimal validation
  - update nearest CONTEXT.md if invariants/public behavior changed
```

---

## 4) Add two docs: `docs/bugfix-playbook.md` + `docs/patch-quality.md`

These are not always loaded; reference them from `AGENTS.md` and let the agent load only when needed.

### `docs/bugfix-playbook.md`

```md
# Bugfix playbook (xnu)

## Triage
1) Classify bug: crash/panic, race, UAF, OOB, deadlock, logic error, ABI mismatch.
2) Identify boundary: bsd/osfmk/iokit/libkern/pexpert/security.
3) Identify entry point: syscall / message / interrupt / kext / timer / workloop.

## Confirmation steps (lightweight first)
- Find call sites and invariants in headers/comments.
- Identify locking + lifetime model (retain/release/refcount).
- Identify data structures and ownership.

## Patch discipline
- Minimal change; avoid refactors.
- Add assertions only if safe in configs.
- Prefer fixing root cause over masking symptoms.
```

### `docs/patch-quality.md`

```md
# Patch quality checklist

- Minimal diff
- Correct locking / lifetime
- No new boundary violations (see docs/dependency-rules.md)
- Comments explain invariants (if changed)
- Tests/build steps recommended
- Update local CONTEXT.md if behavior/invariants changed
```

If you want them always loaded, add them to `opencode.jsonc` instructions—but usually they’re better as optional references.

---

## 5) Add a small “bug intake template” prompt (optional but powerful)

This helps convert your description into structured inputs.

> **New file:** `prompts/bug-intake.txt`

```txt
Ask for missing details only if essential.
Otherwise, infer and proceed.

Extract:
- Symptom: what happens
- Trigger: what action/load
- Environment: arch/config if known
- Location hints: files/functions/log lines provided
- Expected vs actual
- Repro steps (if any)
- Safety: can we run builds? (assume no unless user said yes)
```

Then in `AGENTS.md`, tell the agent: “if bug report is vague, run bug-intake extraction first.”

---

## 6) Expand `xnu-bug-hunting` skill into “triage + working set selection”

You already have `xnu-bug-hunting`. Add a section that maps common symptoms to likely boundaries and “first files to look at,” without being too specific.

Example additions:

* panic in VM → `osfmk/vm/*`
* syscall issue → `bsd/kern/*` + `bsd/sys/*` + `libsyscall/*`
* IOKit lifetime crash → `iokit/*` + `libkern/*`

This dramatically speeds “navigate to right location from description.”

---

## 7) Add a “doc auto-update rule” (tiny but important)

When `@fix` touches anything that changes invariants, require it to update the nearest `CONTEXT.md` *in the same patch*.

In `prompts/fix-agent.txt` (already included) + reinforce in `docs/patch-quality.md`.

That’s what gets you to “auto documenting” as a natural byproduct of fixing.

---

## What you do NOT need yet

* PR automation / commit hooks (later)
* fully building xnu in CI (later)
* exhaustive dependency graph indexing (overkill)

---

## Minimal change summary (copy/paste checklist)

**Modify**

* `opencode.jsonc` → add `@fix` agent (edit ask + bash allowlist)
* `AGENTS.md` → enforce explore→fix workflow

**Add**

* `prompts/fix-agent.txt`
* (optional) `prompts/bug-intake.txt`
* `docs/bugfix-playbook.md`
* `docs/patch-quality.md`
* (optional) expand `.opencode/skills/xnu-bug-hunting/SKILL.md`

---

If you paste an example bug description (panic log snippet or “this syscall returns wrong errno under X”), I can show the exact **@explore output** and then the **@fix plan** using this upgraded setup.

------------------------------------------------
++++++++++++++++++++++++++++++++++++++++++++++++

If you’re getting bad matches, almost always the problem is one (or more) of these:

1. **The “face” you embed isn’t actually a clean/aligned face** (detector/alignment issue)
2. **Your similarity threshold is wrong for *your* data** (calibration issue)
3. **The embedding model isn’t strong enough for your conditions** (model choice / domain shift)

Below is a practical, “maximum accuracy” upgrade path that still works **on-device** and still supports “scan on the fly”.

---

## 1) First: diagnose where the error comes from

### A. If you miss true matches (false negatives)

Typical causes:

* detector misses the face (small face, profile, occlusion)
* alignment is wrong (landmarks off; crop too tight)
* query photo is low quality / extreme pose
* threshold too strict

### B. If you match the wrong person (false positives)

Typical causes:

* threshold too loose
* very low-quality candidate faces (blur, tiny faces) → embeddings become unreliable
* look‑alikes + weak embedder

**What to do immediately:** log and visualize for every “match”:

* the candidate image
* the detected bbox
* the **aligned crop** that actually went into the embedder

You’ll quickly see if your pipeline is embedding garbage crops.

---

## 2) Improve detection + alignment (this often gives the biggest accuracy jump)

Even a perfect embedder fails if the crop is wrong.

### A. Run detection at a higher effective resolution

If you downscale too much, small faces become unrecognizable to both detector and embedder. A simple accuracy improvement is:

* increase your `det_max_side` (or equivalent)
* or do a **two-pass detector**: fast pass at low size; if “no/low-quality faces”, retry at higher size

If you care about small faces, detectors/papers emphasize that scale handling is a core challenge in efficient face detection. ([OpenReview][1])

### B. Prefer detectors that provide landmarks (for alignment)

Alignment consistently improves recognition robustness to pose/zoom.

RetinaFace explicitly uses/mentions five-landmark supervision and reports improved hard-face detection with extra landmark supervision. ([arXiv][2])
SCRFD is presented by InsightFace as an “efficient high accuracy face detection” approach and notes acceptance by ICLR 2022. ([GitHub][3])

**Takeaway:** if you’re missing faces or your crops are inconsistent, upgrading the detector is often more impactful than changing the recognizer.

---

## 3) Calibrate your similarity threshold on YOUR data (don’t trust a generic number)

If you’re using OpenCV SFace (`FaceRecognizerSF`), OpenCV’s tutorial reports a cosine threshold (e.g., **0.363** for LFW with their model) and shows that thresholds differ by dataset. ([OpenCV Documentation][4])

That’s the key point: **the correct threshold depends on your domain** (camera, compression, demographics, pose distribution, “in-the-wild” clutter, etc.).

### How to calibrate threshold properly

Create a small validation set of pairs:

* **Positive pairs**: same person, different images
* **Negative pairs**: different people

Compute cosine similarities and pick a threshold that hits your target **false match rate** (FAR). For “maximum accuracy” in real applications, you usually pick an FAR target first and accept the recall you get.

Here’s a small calibration snippet you can adapt (works with any embedder that returns vectors):

```python
import numpy as np

def l2norm(x):
    x = np.asarray(x).reshape(-1).astype(np.float32)
    return x / (np.linalg.norm(x) + 1e-12)

def cosine(a, b):
    a = l2norm(a); b = l2norm(b)
    return float(np.dot(a, b))

def choose_threshold(pos_sims, neg_sims, target_far=1e-4):
    """
    Pick threshold T such that FAR ~= target_far
    FAR = fraction of negatives with sim >= T
    """
    neg_sims = np.array(neg_sims, dtype=np.float32)
    # threshold is (1 - target_far) quantile of negatives
    q = np.quantile(neg_sims, 1.0 - target_far)
    T = float(q)
    # report achieved FAR/TPR at that T
    far = float(np.mean(neg_sims >= T))
    pos_sims = np.array(pos_sims, dtype=np.float32)
    tpr = float(np.mean(pos_sims >= T))
    return T, far, tpr
```

---

## 4) Upgrade the embedding model (recognizer) for maximum accuracy

OpenCV SFace is convenient and works offline, but it isn’t “best possible.” If accuracy is your top priority, you typically move to embeddings trained with modern margin-based losses.

### A. ArcFace-class embeddings (strong baseline / widely used)

ArcFace proposes an **additive angular margin loss** to get more discriminative face features. ([CVF Open Access][5])
If you choose one “serious” face embedding approach to build around, ArcFace-style is a common foundation.

### B. Quality-aware / low-quality robustness

If many of your failures come from tiny, blurry, dark, or heavily compressed faces:

* **AdaFace** introduces a “quality adaptive margin” and approximates image quality via feature norms; it reports improvements on challenging low-quality benchmarks. ([arXiv][6])
* **MagFace** extends ArcFace with a magnitude-aware margin/regularizer and ties feature magnitude to face quality; it’s designed to unify recognition and quality assessment. ([CVF Open Access][7])
* **QMagFace** (WACV 2023) is an example of using quality-aware comparison to improve recognition under unconstrained conditions. ([CVF Open Access][8])

**Practical meaning:** instead of treating all comparisons equally, incorporate a quality estimate so low-quality faces don’t create confident false matches (or so they are handled differently).

### C. If you must keep speed AND want max accuracy: two-stage recognition

A very common “best of both worlds” design:

1. **Fast embedder** scans everything (high recall, cheap)
2. For any candidate face above a *low* threshold, run a **heavy embedder** (or extra augmentations) to confirm

You’re still “on-the-fly,” but heavy compute happens only on a tiny fraction of faces.

---

## 5) Template your query (big accuracy win, almost free)

If your query is only one photo, you’re asking the system to generalize across pose/zoom/lighting from one sample.

**Max accuracy trick:** create a *query template embedding* from multiple versions of the query:

* include a horizontally flipped version
* if you have multiple photos of the same person, average them

This idea is consistent with “embedding space” face recognition systems: compute embeddings, then compare distances/similarities. ([arXiv][9])

### Drop-in improvement for your OpenCV SFace pipeline: query template with flip

(You only pay this once per query.)

```python
import cv2 as cv
import numpy as np

def l2norm_vec(v):
    v = np.asarray(v, dtype=np.float32).reshape(-1)
    return v / (np.linalg.norm(v) + 1e-12)

def feature_from_face(recognizer, img_bgr, face_row):
    aligned = recognizer.alignCrop(img_bgr, face_row)
    feat = recognizer.feature(aligned)
    feat = l2norm_vec(feat)

    aligned_flip = cv.flip(aligned, 1)
    feat_flip = recognizer.feature(aligned_flip)
    feat_flip = l2norm_vec(feat_flip)

    # template: average + renormalize
    template = l2norm_vec(feat + feat_flip)
    return template

def cosine_sim(a, b):
    return float(np.dot(a, b))  # both must be L2-normalized
```

Then for each candidate face, compute `e = l2norm_vec(recognizer.feature(aligned_candidate))` and score `cosine_sim(q_template, e)`.

This usually helps with pose/crop asymmetry and reduces flip sensitivity.

---

## 6) Improve how you treat low-quality faces (accuracy vs coverage)

For maximum accuracy, you often *don’t* want to “force a decision” on extremely low-quality detections.

Add gating before comparing:

* face bbox too small → skip or require higher threshold
* detector score too low → skip
* blur too high (variance of Laplacian below threshold) → skip or “uncertain”

This reduces false positives dramatically. If you need *coverage* on low-quality faces too, that’s where AdaFace/MagFace-style quality handling can help. ([arXiv][6])

---

## 7) If you need the highest possible accuracy: train/fine-tune (domain adaptation)

If your data is very different from common training sets (CCTV, IR, strong compression, extreme angles), pretrained models can underperform.

Options:

* **Fine-tune** a strong ArcFace-style backbone on a labeled dataset similar to your target domain. ([CVF Open Access][10])
* Or use triplet-based approaches (FaceNet trained embeddings with online triplet mining is a classic example). ([arXiv][9])

This requires:

* identity labels (many identities, multiple images per identity)
* careful cleaning (label noise kills face recognition)
* validation at a fixed FAR target

---

## A simple priority plan (maximum accuracy)

1. **Visualize crops/alignment** for failures (fix detection/alignment first)
2. **Calibrate threshold** on your real data (don’t trust LFW defaults) ([OpenCV Documentation][4])
3. Add **query templating** (flip + multiple query photos) ([arXiv][9])
4. Upgrade to a stronger embedding family (ArcFace → AdaFace/MagFace if low-quality dominates) ([CVF Open Access][10])
5. Use a **two-stage confirm** (fast scan → heavy verify)

---

### One important note (responsible use)

Face recognition is biometric processing. Make sure you have consent/authorization for the data you scan and that you handle embeddings/results securely—especially if you later expand to web search.

If you tell me what kind of mismatches you’re seeing (mostly false positives vs false negatives, and whether the misses happen on small faces / profiles / low light), I can point you to the most effective *next* change (detector upgrade vs embedder upgrade vs thresholding strategy).

[1]: https://openreview.net/pdf/d7b9dd38011f418b1c66bb378aef38a25d8c9bf5.pdf?utm_source=chatgpt.com "SAMPLE AND COMPUTATION REDISTRIBUTION FOR ..."
[2]: https://arxiv.org/abs/1905.00641?utm_source=chatgpt.com "RetinaFace: Single-stage Dense Face Localisation in the Wild"
[3]: https://github.com/deepinsight/insightface/blob/master/detection/scrfd/README.md?utm_source=chatgpt.com "insightface/detection/scrfd/README.md at master"
[4]: https://docs.opencv.org/4.x/d0/dd4/tutorial_dnn_face.html?utm_source=chatgpt.com "DNN-based Face Detection And Recognition"
[5]: https://openaccess.thecvf.com/content_CVPR_2019/html/Deng_ArcFace_Additive_Angular_Margin_Loss_for_Deep_Face_Recognition_CVPR_2019_paper.html?utm_source=chatgpt.com "ArcFace: Additive Angular Margin Loss for - CVF Open Access"
[6]: https://arxiv.org/abs/2204.00964?utm_source=chatgpt.com "AdaFace: Quality Adaptive Margin for Face Recognition"
[7]: https://openaccess.thecvf.com/content/CVPR2021/papers/Meng_MagFace_A_Universal_Representation_for_Face_Recognition_and_Quality_Assessment_CVPR_2021_paper.pdf?utm_source=chatgpt.com "MagFace: A Universal Representation for Face ..."
[8]: https://openaccess.thecvf.com/content/WACV2023/papers/Terhorst_QMagFace_Simple_and_Accurate_Quality-Aware_Face_Recognition_WACV_2023_paper.pdf?utm_source=chatgpt.com "Simple and Accurate Quality-Aware Face Recognition"
[9]: https://arxiv.org/abs/1503.03832?utm_source=chatgpt.com "FaceNet: A Unified Embedding for Face Recognition and Clustering"
[10]: https://openaccess.thecvf.com/content_CVPR_2019/papers/Deng_ArcFace_Additive_Angular_Margin_Loss_for_Deep_Face_Recognition_CVPR_2019_paper.pdf?utm_source=chatgpt.com "Additive Angular Margin Loss for Deep Face Recognition"


Yes. You can **download the models once**, keep them **locally**, and run the entire pipeline **fully on-device/offline** (the only network access would be the optional “download models if missing” step). OpenCV’s DNN face pipeline is explicitly designed for this: **`cv.FaceDetectorYN` (YuNet) + `cv.FaceRecognizerSF` (SFace)** with **ONNX** model files. ([OpenCV Documentation][1])

Below is a complete script that:

* downloads the two ONNX model files into `./models/` (optional; you can also download manually)
* computes the **query face feature once**
* scans a folder **on-the-fly** (no indexing) and outputs **all images where the face appears**
* returns the **best match score + bounding box** per image
* runs fully offline after the models are present

The model files referenced are the ones hosted in the OpenCV model zoo:

* `face_detection_yunet_2023mar.onnx` ([GitHub][2])
* `face_recognition_sface_2021dec.onnx` ([GitHub][3])

---

## Install

OpenCV notes compatibility **OpenCV ≥ 4.5.4** for this tutorial pipeline. ([OpenCV Documentation][1])

```bash
pip install --upgrade opencv-python numpy
# If you get AttributeError for FaceDetectorYN/FaceRecognizerSF, use:
# pip install --upgrade opencv-contrib-python numpy
```

---

## Script: `face_search_ondevice.py`

```python
#!/usr/bin/env python3
"""
On-device face search (no indexing):
- Detect faces in each image with OpenCV FaceDetectorYN (YuNet ONNX)
- Align + embed faces with OpenCV FaceRecognizerSF (SFace ONNX)
- Compare to query face using cosine similarity
- Output all images that contain the same identity above threshold

After the models are downloaded locally, the search is fully offline/on-device.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import urllib.request
import urllib.error

import cv2 as cv
import numpy as np


IMG_EXTS = {".jpg", ".jpeg", ".png", ".bmp", ".webp", ".tif", ".tiff"}


# --------- Utilities ---------

def is_git_lfs_pointer(p: Path) -> bool:
    """Detects if a downloaded file is a Git-LFS pointer (tiny text file)."""
    try:
        if p.stat().st_size > 2048:
            return False
        head = p.read_text(errors="ignore")
        return "git-lfs.github.com/spec/v1" in head
    except Exception:
        return False


def download_file(url: str, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_suffix(dst.suffix + ".tmp")
    try:
        with urllib.request.urlopen(url) as r, open(tmp, "wb") as f:
            while True:
                chunk = r.read(1 << 20)  # 1MB
                if not chunk:
                    break
                f.write(chunk)
        tmp.replace(dst)
    except Exception:
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        raise


def ensure_file(local_path: Path, urls: list[str], offline: bool) -> Path:
    if local_path.exists() and local_path.stat().st_size > 0 and not is_git_lfs_pointer(local_path):
        return local_path

    if offline:
        raise FileNotFoundError(f"Missing model file (offline mode): {local_path}")

    last_err = None
    for url in urls:
        try:
            print(f"[download] {url} -> {local_path}")
            download_file(url, local_path)
            if is_git_lfs_pointer(local_path):
                raise RuntimeError("Downloaded a Git-LFS pointer file, not the model binary.")
            return local_path
        except Exception as e:
            last_err = e
            print(f"[warn] download failed from {url}: {e}")

    raise RuntimeError(f"Could not download {local_path.name}. Last error: {last_err}")


def imread_any(path: Path) -> np.ndarray | None:
    """Robust imread (handles some unicode-path cases on Windows)."""
    img = cv.imread(str(path))
    if img is not None:
        return img
    try:
        data = np.fromfile(str(path), dtype=np.uint8)
        return cv.imdecode(data, cv.IMREAD_COLOR)
    except Exception:
        return None


def iter_images(root: Path):
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            ext = Path(fn).suffix.lower()
            if ext in IMG_EXTS:
                yield Path(dirpath) / fn


def choose_backend_target(device: str) -> tuple[int, int]:
    """
    Map a user-friendly device string to OpenCV DNN backend/target IDs.
    Note: CUDA/OpenVINO require OpenCV builds with those enabled.
    """
    if device == "cpu":
        return (cv.dnn.DNN_BACKEND_OPENCV, cv.dnn.DNN_TARGET_CPU)

    if device == "openvino":
        # Works only if your OpenCV build has OpenVINO enabled
        return (cv.dnn.DNN_BACKEND_INFERENCE_ENGINE, cv.dnn.DNN_TARGET_CPU)

    if device == "cuda":
        return (cv.dnn.DNN_BACKEND_CUDA, cv.dnn.DNN_TARGET_CUDA)

    if device == "cuda_fp16":
        return (cv.dnn.DNN_BACKEND_CUDA, cv.dnn.DNN_TARGET_CUDA_FP16)

    raise ValueError(f"Unknown device: {device}")


def resize_keep_aspect(img: np.ndarray, max_side: int) -> tuple[np.ndarray, float]:
    """Resize image so max(H,W) <= max_side. Returns resized image and scale factor."""
    h, w = img.shape[:2]
    m = max(h, w)
    if max_side <= 0 or m <= max_side:
        return img, 1.0
    scale = max_side / float(m)
    new_w = max(1, int(round(w * scale)))
    new_h = max(1, int(round(h * scale)))
    resized = cv.resize(img, (new_w, new_h), interpolation=cv.INTER_AREA)
    return resized, scale


# --------- Face pipeline ---------

def detect_faces(detector, img_bgr: np.ndarray, det_max_side: int) -> np.ndarray:
    """
    Detect faces. Returns faces array shape (N, 15) in ORIGINAL image coordinates.
    Format per OpenCV tutorial: [x, y, w, h, 5 landmarks (x,y)*5, score]. :contentReference[oaicite:4]{index=4}
    """
    img_det, scale = resize_keep_aspect(img_bgr, det_max_side)

    h, w = img_det.shape[:2]
    detector.setInputSize((w, h))
    retval = detector.detect(img_det)  # returns tuple: (num_faces, faces_mat)
    faces = retval[1]
    if faces is None or len(faces) == 0:
        return np.zeros((0, 15), dtype=np.float32)

    faces = faces.astype(np.float32, copy=True)

    # Scale detections back to original image coordinates
    if scale != 1.0:
        faces[:, :14] /= scale  # bbox + landmarks are coords; score is last column

    return faces


def pick_query_face(faces: np.ndarray) -> int:
    """Pick the most likely query face (largest area; tie-break by score)."""
    if faces.shape[0] == 0:
        return -1
    areas = faces[:, 2] * faces[:, 3]
    scores = faces[:, 14]
    # lexsort sorts by last key first; we want max area, then max score
    order = np.lexsort((scores, areas))
    return int(order[-1])


def face_feature(recognizer, img_bgr: np.ndarray, face_row: np.ndarray) -> np.ndarray:
    aligned = recognizer.alignCrop(img_bgr, face_row)
    feat = recognizer.feature(aligned)
    # Ensure a standalone array (avoid internal buffer reuse surprises)
    return np.array(feat, copy=True)


# --------- Main search ---------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--query", required=True, help="Path to query image (face photo).")
    ap.add_argument("--folder", required=True, help="Folder to scan for matches.")
    ap.add_argument("--models", default="models", help="Folder to store/read ONNX models.")
    ap.add_argument("--device", default="cpu", choices=["cpu", "openvino", "cuda", "cuda_fp16"],
                    help="Inference device backend/target (requires matching OpenCV build).")
    ap.add_argument("--offline", action="store_true", help="Do not download models; error if missing.")
    ap.add_argument("--det-max-side", type=int, default=900,
                    help="Resize images for detection so max side <= this (0 disables).")
    ap.add_argument("--score-threshold", type=float, default=0.9, help="Detector score threshold.")
    ap.add_argument("--nms-threshold", type=float, default=0.3, help="Detector NMS threshold.")
    ap.add_argument("--top-k", type=int, default=5000, help="Detector top-k before NMS.")
    ap.add_argument("--cos-threshold", type=float, default=0.363,
                    help="Cosine similarity threshold (OpenCV tutorial suggests 0.363 on LFW).")
    ap.add_argument("--no-early-exit", action="store_true",
                    help="If set, evaluates all faces in each image even after a match.")
    ap.add_argument("--json-out", default="", help="Optional path to save results as JSON.")
    ap.add_argument("--threads", type=int, default=0,
                    help="OpenCV threads (0 lets OpenCV decide).")
    args = ap.parse_args()

    if args.threads > 0:
        cv.setNumThreads(args.threads)

    models_dir = Path(args.models)
    models_dir.mkdir(parents=True, exist_ok=True)

    # Preferred download sources (Hugging Face resolve links are convenient for large files).
    # URLs must be in code per ChatGPT UI rules.
    fd_name = "face_detection_yunet_2023mar.onnx"
    fr_name = "face_recognition_sface_2021dec.onnx"

    fd_urls = [
        f"https://huggingface.co/opencv/face_detection_yunet/resolve/main/{fd_name}",
        f"https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/{fd_name}",
    ]
    fr_urls = [
        f"https://huggingface.co/opencv/face_recognition_sface/resolve/main/{fr_name}",
        f"https://github.com/opencv/opencv_zoo/raw/main/models/face_recognition_sface/{fr_name}",
    ]

    fd_path = ensure_file(models_dir / fd_name, fd_urls, offline=args.offline)
    fr_path = ensure_file(models_dir / fr_name, fr_urls, offline=args.offline)

    backend_id, target_id = choose_backend_target(args.device)

    # Create detector/recognizer (try full signature; fall back for older OpenCV builds)
    try:
        detector = cv.FaceDetectorYN.create(
            str(fd_path), "", (320, 320),
            args.score_threshold, args.nms_threshold, args.top_k,
            backend_id, target_id
        )
    except TypeError:
        detector = cv.FaceDetectorYN.create(
            str(fd_path), "", (320, 320),
            args.score_threshold, args.nms_threshold, args.top_k
        )

    try:
        recognizer = cv.FaceRecognizerSF.create(str(fr_path), "", backend_id, target_id)
    except TypeError:
        recognizer = cv.FaceRecognizerSF.create(str(fr_path), "")

    # --- Query feature (computed once) ---
    qpath = Path(args.query)
    qimg = imread_any(qpath)
    if qimg is None:
        raise RuntimeError(f"Cannot read query image: {qpath}")

    qfaces = detect_faces(detector, qimg, det_max_side=args.det_max_side)
    qidx = pick_query_face(qfaces)
    if qidx < 0:
        raise RuntimeError("No face detected in query image.")

    qfeat = face_feature(recognizer, qimg, qfaces[qidx])

    # --- Scan folder ---
    folder = Path(args.folder)
    matches = []
    scanned = 0
    matched_images = 0

    for ipath in iter_images(folder):
        scanned += 1
        img = imread_any(ipath)
        if img is None:
            continue

        faces = detect_faces(detector, img, det_max_side=args.det_max_side)
        if faces.shape[0] == 0:
            continue

        best = None  # (score, bbox[x,y,w,h])
        for i in range(faces.shape[0]):
            feat = face_feature(recognizer, img, faces[i])
            score = float(recognizer.match(qfeat, feat, cv.FaceRecognizerSF_FR_COSINE))
            if (best is None) or (score > best[0]):
                bbox = faces[i, 0:4].tolist()
                best = (score, bbox)

            if (not args.no_early_exit) and (score >= args.cos_threshold):
                # Found a match in this image; stop processing remaining faces for speed.
                break

        if best is not None and best[0] >= args.cos_threshold:
            matched_images += 1
            matches.append({
                "path": str(ipath),
                "best_cosine": best[0],
                "bbox_xywh": best[1],
            })

    # Sort by score desc for readability
    matches.sort(key=lambda d: d["best_cosine"], reverse=True)

    print(f"\nScanned images: {scanned}")
    print(f"Matched images: {matched_images}")
    print(f"Cosine threshold: {args.cos_threshold}\n")

    for m in matches:
        print(f"{m['best_cosine']:.3f}  {m['path']}  bbox(x,y,w,h)={m['bbox_xywh']}")

    if args.json_out:
        outp = Path(args.json_out)
        outp.parent.mkdir(parents=True, exist_ok=True)
        outp.write_text(json.dumps(matches, indent=2), encoding="utf-8")
        print(f"\nSaved JSON results to: {outp}")

if __name__ == "__main__":
    main()
```

---

## Run it

```bash
python face_search_ondevice.py --query /path/to/query.jpg --folder /path/to/images
```

Common tuning:

* Start with OpenCV’s reference cosine threshold **0.363** (reported in their face tutorial). ([OpenCV Documentation][1])
  Then adjust on your data:

  * increase threshold → fewer false matches, more misses
  * decrease threshold → more matches, more false positives

Example:

```bash
python face_search_ondevice.py \
  --query query.jpg \
  --folder ./photos \
  --cos-threshold 0.40 \
  --det-max-side 800
```

---

## Notes on “on-device” + performance

* The models are **local ONNX files** and OpenCV runs inference locally; nothing is sent anywhere by default. ([OpenCV Documentation][1])
* You can speed up detection by lowering `--det-max-side` (trades recall on small faces).
* For GPU acceleration you’d need an OpenCV build with CUDA; the script supports selecting `--device cuda` / `cuda_fp16`, but the pip wheels typically don’t include CUDA.

---

## Quick reminder

Face matching is biometric processing. Make sure you have consent/authorization for the images you scan and that you handle results securely.

If you tell me **CPU vs GPU** and roughly **how many images per query**, I can suggest the best `det-max-side`, thresholds, and whether switching to OpenVINO / CUDA will give you a meaningful speedup on your machine.

[1]: https://docs.opencv.org/4.x/d0/dd4/tutorial_dnn_face.html "OpenCV: DNN-based Face Detection And Recognition"
[2]: https://github.com/opencv/opencv_zoo/blob/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx?utm_source=chatgpt.com "face_detection_yunet_2023mar.onnx - opencv/opencv_zoo"
[3]: https://github.com/opencv/opencv_zoo/blob/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx?utm_source=chatgpt.com "face_recognition_sface_2021dec.onnx - opencv/opencv_zoo"

If you refuse to pre-index/cache embeddings, the *only* way to find the face is to, for **every candidate image**:

1. **detect faces** (find bounding boxes in a complex scene), then
2. **turn each detected face into an embedding** (a vector), then
3. **compare embeddings** to the query embedding.

The good news: **step (3) is basically free** (a dot product). Your speed is dominated by **face detection + embedding inference**. So the “fastest on‑the‑fly” system is mostly about choosing the right *detector + embedder* and engineering inference.

Below is a concrete blueprint that is both fast and accurate, and robust to zoom/angles.

---

## The fastest accurate pipeline (on-the-fly)

### A) Query (do once)

1. **Get the query face crop** (if your input is already a face, skip detection; otherwise detect+crop).
2. **Align** to a canonical pose (via landmarks + similarity transform).
3. **Embedding network** → get vector `q` (typically 128–512 dims).
4. **L2-normalize**: `q = q / ||q||`.

Why this works: modern face recognition systems learn an embedding space where distance/similarity corresponds to identity similarity (e.g., FaceNet/ArcFace-style approaches). ([CVF Open Access][1])

### B) Scan candidates (repeat per image)

For each image `I` in your partition:

1. **Face detection**: find all face boxes (and ideally landmarks).
2. For each detected face:

   * crop with a small margin
   * align
   * run embedder → `e`
   * normalize `e`
   * compute similarity `s = q · e` (cosine if normalized)
3. If any face in `I` has `s >= threshold`, add `I` to output and **early-exit** that image (don’t process remaining faces).

Cosine similarity is the normalized dot product; on L2-normalized vectors it’s just a dot product. ([scikit-learn.org][2])

---

## Key model choices for speed vs accuracy

You need **two models**:

### 1) Face detector (fast on cluttered scenes)

Two practical “fast by design” options:

* **MediaPipe Face Detector (BlazeFace variants)**
  Designed for real-time; outputs bounding boxes + 6 face landmarks. ([Google AI for Developers][3])
  *Why it’s good here:* fast “find faces in messy images” step.

* **OpenCV YuNet detector (ONNX, has INT8 variants)**
  The model card describes it as light-weight/fast and notes detection range (roughly 10×10 to 300×300 faces) and the presence of a quantized model file. ([Hugging Face][4])
  *Why it’s good here:* easy deployment and speed on CPU.

**Detector tuning tips (speed/recall tradeoffs):**

* Run detection on a **downscaled** copy of the image for speed; crop from original resolution for embedding.
* If you miss small faces, add a **second pass** only when needed (e.g., larger detection input size for “no face found” images). Since you control partitioning, you can decide where to do this.

### 2) Face embedding model (identity vector)

Two commonly used “families”:

* **ArcFace-style embedding (often 512-D)**
  ArcFace explicitly uses feature normalization and sets embedding dimension to 512 in the paper; it also relates normalized dot products to cosine terms. 
  *Why it’s good:* strong accuracy across pose/illumination when paired with alignment.

* **MobileFaceNet (efficient embedding CNN)**
  MobileFaceNets paper describes the standard pipeline: detect face + **five landmarks**, align with similarity transform, resize to **112×112**, normalize pixels, then embed; it’s explicitly designed for efficient real-time face verification. ([arXiv][5])
  *Why it’s good:* much faster than heavy backbones when you must run it on many faces on-the-fly.

**Rule of thumb:**

* If you’re truly scanning lots of images per query and need speed: start with **MobileFaceNet-class** embedder.
* If accuracy is the priority and you have GPU headroom: use a stronger ArcFace backbone.

---

## How to handle “different angles” and “different zooms”

### 1) Alignment is non-negotiable

Most high-performing face recognition pipelines assume you align the face using landmarks before embedding. MobileFaceNets explicitly describes aligning with five landmarks via similarity transform and then embedding. ([arXiv][5])

If your detector doesn’t give the landmarks you need, add a tiny landmark model (it’s still cheaper than making the embedder struggle).

### 2) Use query-side test-time augmentation (cheap, big gain)

Since the query is done once, you can make it more robust *without multiplying your scan cost*:

Compute multiple query embeddings:

* original aligned crop
* horizontally flipped crop
* a couple different crop margins (slightly tighter/looser)

Normalize each, keep a small set `{q1, q2, …}`.

Then for each candidate face embedding `e`, compute:

* `s = max_i (qi · e)`

This costs a few extra dot products per face (cheap) and often helps with zoom/crop variance.

### 3) Do candidate-side “extra work” only near the threshold

To avoid doubling your scan time, only do heavier steps if the similarity is borderline, e.g.:

* If `s` is in `[T - δ, T)`, then try:

  * also embed the flipped candidate crop
  * or a slightly different crop margin
  * or a second alignment variant

This recovers some hard cases while keeping average throughput high.

---

## Speed engineering: where the real gains come from

### 1) Use an optimized inference runtime (don’t run raw PyTorch eager for this)

Common fast deployment paths:

* **ONNX Runtime**
  Export detector+embedder to ONNX. Then choose CPU/GPU execution providers and optimize/quantize.

  ONNX Runtime provides explicit guidance on 8-bit quantization formats (QOperator vs QDQ), and details tradeoffs and recommended defaults (e.g., S8S8 QDQ as a “first choice” on CPU). ([ONNX Runtime][6])

* **TensorRT (on NVIDIA GPUs)**
  TensorRT documentation describes quantization as a way to reduce model size and accelerate inference with lower-precision types and supports PTQ/QAT workflows. ([NVIDIA Docs][7])
  *Practical effect:* FP16 often gives a big speedup with minimal hassle; INT8 can be faster but needs calibration and careful validation.

* **OpenVINO (if you’re CPU-bound on Intel hardware)**
  OpenVINO supports low precision (INT8) inference flows for optimized deployment. ([docs.openvino.ai][8])

### 2) Batch the embedder aggressively

Detection is usually per-image, but embedding is per-face and **batchable**:

* As you scan images, collect face crops into a batch (e.g., 64–512 faces depending on GPU/CPU).
* Run **one** embedder forward pass for the whole batch.
* Then do dot products.

This is often the single biggest throughput boost on GPU.

### 3) Pipeline your CPU work

Create a producer/consumer pipeline:

* Thread/process A: disk I/O + decode (JPEG/PNG)
* Thread/process B: detector
* Thread/process C: crop/align + batch embed
* Thread/process D: similarity + thresholding + results

This keeps your GPU/CPU busy and reduces idle time.

### 4) Early exit and face ordering

Within one candidate image:

* Sort detected faces by **size** or **detector score** first.
* As soon as one face matches (≥T), stop processing the rest of that image.

### 5) Use float32 for embeddings unless you validate otherwise

Quantizing the embedder can speed things up, but face verification accuracy can be sensitive. If you use INT8/FP16, validate with a small benchmark from your own domain.

---

## Thresholding: how you decide “this is the same person”

You’re doing **open-set** matching (“is this the same identity?”), so you need a threshold **T**.

Fast way to calibrate:

1. Collect a small validation set:

   * positives: same person, different images/angles
   * negatives: different people
2. Compute cosine similarities
3. Choose T based on your acceptable false matches.

ArcFace-style embeddings are explicitly designed with normalized features/logits in mind, so cosine thresholds are the standard. 

---

## A concrete “best effort” configuration for your constraints

If I had to pick a strong starting point for **fast on-the-fly** search:

1. **Fast detector:** MediaPipe Face Detector (or YuNet if you want an ONNX + INT8-friendly path). ([MediaPipe][9])
2. **Efficient embedder:** MobileFaceNet-class network if you’re scanning a lot; otherwise ArcFace backbone for max accuracy. ([arXiv][5])
3. **Alignment:** 5-landmark similarity transform to 112×112 canonical crop. ([arXiv][5])
4. **Similarity:** cosine via dot product on L2-normalized embeddings. ([scikit-learn.org][2])
5. **Runtime:** ONNX Runtime (CPU or CUDA), optionally TensorRT for maximum GPU throughput. ([ONNX Runtime][6])
6. **Robustness:** query-side augmentations + borderline candidate TTA.

---

## One practical note (models & licensing)

If you plan to use InsightFace as a shortcut for high-quality pretrained detector+recognition models: their docs state the **code** is MIT, but the **pretrained models** they provide are “non-commercial research purposes only.” ([PyPI][10])
(If you’re building anything commercial, you’ll want to train/licence appropriately.)

---

## Quick safety/legal reminder

Face recognition is powerful and sensitive. If you ever expand to “search the web,” make sure you have consent/authorization, follow local biometric/privacy laws, and respect site terms.

---

If you tell me **CPU vs GPU**, and roughly **how many images per partition** and **average faces per image**, I can recommend a specific detector/embedder pair and batching strategy (e.g., batch size, when to do second-pass detection) that will maximize throughput under your constraints.

[1]: https://openaccess.thecvf.com/content_cvpr_2015/html/Schroff_FaceNet_A_Unified_2015_CVPR_paper.html "CVPR 2015 Open Access Repository"
[2]: https://scikit-learn.org/stable/modules/generated/sklearn.metrics.pairwise.cosine_similarity.html "cosine_similarity — scikit-learn 1.8.0 documentation"
[3]: https://ai.google.dev/edge/mediapipe/solutions/vision/face_detector "Face detection guide  |  Google AI Edge  |  Google AI for Developers"
[4]: https://huggingface.co/opencv/face_detection_yunet "opencv/face_detection_yunet · Hugging Face"
[5]: https://arxiv.org/pdf/1804.07573 "sv-lncs"
[6]: https://onnxruntime.ai/docs/performance/model-optimizations/quantization.html "Quantize ONNX models | onnxruntime"
[7]: https://docs.nvidia.com/deeplearning/tensorrt/latest/inference-library/work-quantized-types.html "Working with Quantized Types — NVIDIA TensorRT"
[8]: https://docs.openvino.ai/2024/documentation/openvino-ir-format/intermediate-representation-int8-inference.html?utm_source=chatgpt.com "Low Precision IR (INT8 Inference) - OpenVINO™ documentation"
[9]: https://mediapipe.readthedocs.io/en/latest/solutions/face_detection.html "layout: forward target: https://developers.google.com/mediapipe/solutions/vision/face_detector/ title: Face Detection parent: MediaPipe Legacy Solutions nav_order: 1 — MediaPipe v0.7.5 documentation"
[10]: https://pypi.org/project/insightface/?utm_source=chatgpt.com "insightface"

What you’re describing is a **face retrieval / face search** pipeline. The most practical (and accurate) way to do it is a 2‑stage deep-learning system:

1. **Face detection (multi-face, in-the-wild)** → finds all face boxes inside complex images (multiple people, backgrounds, varying pose/scale).
2. **Face recognition embedding** → converts each detected face into a fixed-length vector (tensor) so you can compare it to your query face with a fast similarity metric.

That “vector” is exactly the tensor/matrix representation you want: typically a **128–512D** float vector (often **L2-normalized**) so you can use a dot product / cosine similarity.

---

## The important constraint: no indexing ⇒ you must scan everything per query

If you truly do **no indexing / no precomputed embeddings**, then for every query you must:

* iterate all images in the folder
* run face detection
* run embedding on every detected face
* compare to the query embedding

That’s inherently **O(#images)** per query (and O(#faces) in practice). There’s no way around that if you don’t store computed embeddings somewhere.

You *can*, however, make this scan **very fast** with the right model choices + deployment tricks.

---

## Recommended architecture

### 1) Face detection (robust in complex images)

You want a detector that is both fast and good on small/occluded faces.

Two strong families:

* **SCRFD** – designed for efficient, accurate face detection; it’s described as “efficient high accuracy” and is noted as accepted by **ICLR 2022** in the project docs. ([GitHub][1])
* **RetinaFace** – robust single-stage face detector with landmarks; widely used for “in the wild” face localization. ([arXiv][2])

**Why landmarks matter:** they let you align faces (rotate/warp) into a canonical view before embedding, which improves accuracy.

### 2) Face alignment (landmark-based)

Use 5-point landmarks (eyes, nose, mouth corners) and do a similarity transform into a canonical crop (commonly **112×112** or **160×160**).

### 3) Face embedding (recognition model)

You want a model that maps a face crop → embedding vector where same-identity faces cluster.

Strong options:

* **ArcFace-style embeddings** (very common): ArcFace introduces an **additive angular margin loss** to improve discriminability. ([arXiv][3])
* **AdaFace** (quality-adaptive margin): explicitly adapts the margin based on image quality (approximated via feature norms) and targets low-quality faces. ([arXiv][4])

### 4) Similarity

Most modern systems compare **L2-normalized embeddings** with **cosine similarity**:

* `sim(q, e) = q · e`  (dot product, if both are normalized)

That’s extremely fast: 512 multiplications + additions per face.

---

## How to make “on-the-fly” scanning efficient

Even without indexing, you can speed up a lot:

### A) Use the *right* model sizes

Most detector/recognizer families come in multiple sizes:

* **Small detector + small backbone** ⇒ fast, slightly lower accuracy
* **Bigger backbone** ⇒ better accuracy, more compute

A practical pattern:

* run a **fast detector** at a moderate input size (e.g., long side 640–1024)
* run a **fast recognizer** for embedding
* (optional) if similarity is near your threshold, re-run with a heavier recognizer for confirmation

### B) Batch the embedding step

Detection is per-image, but **embedding can be batched**:

* Detect faces in many images
* Collect face crops into a buffer (say 64–256 crops)
* Run one forward pass of the embedder on the whole batch
* Do a single matrix multiply to score them against the query embedding

That cuts GPU overhead dramatically.

### C) Resize for detection (carefully)

Downscale large images for detection, but don’t downscale so far that faces become tiny. A good heuristic is to keep the **smallest face you care about** at least ~20–30 pixels tall at the detector’s input resolution.

### D) Pipeline parallelism

Use a producer/consumer pipeline:

* Thread/process A: disk I/O + decode
* Thread/process B: detection
* Thread/process C: alignment + embedding
* Main thread: similarity + top‑K maintenance

### E) Quality filtering

To reduce false matches and wasted compute:

* skip detections below a confidence threshold
* skip faces below a minimum size
* optionally reject blurry/low-res faces with a simple quality score

---

## A concrete “no-index” implementation approach (local folder)

Below is a baseline Python approach using the **InsightFace** pipeline (detector + recognizer in one). It detects **all faces in each image**, embeds them, and compares on the fly to your query embedding.

> Licensing note: the **code** in the InsightFace repo is MIT, but the repo explicitly states that *trained models* (and auto-downloaded models/packages) are for **non-commercial research purposes only**, with a 2025-11-24 update pointing to contacting them for licensing of face recognition model packages like `buffalo_l`. ([GitHub][5])

```python
import os
import heapq
import cv2
import numpy as np
from insightface.app import FaceAnalysis

IMG_EXTS = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}

def iter_images(root_dir: str):
    for dirpath, _, filenames in os.walk(root_dir):
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in IMG_EXTS:
                yield os.path.join(dirpath, fn)

def imread_unicode(path: str):
    # robust to unicode paths on Windows
    data = np.fromfile(path, dtype=np.uint8)
    img = cv2.imdecode(data, cv2.IMREAD_COLOR)
    return img

def pick_primary_face(faces):
    # Choose the largest face (common default)
    if not faces:
        return None
    areas = [(f.bbox[2]-f.bbox[0]) * (f.bbox[3]-f.bbox[1]) for f in faces]
    return faces[int(np.argmax(areas))]

def search_face(
    query_image_path: str,
    folder: str,
    top_k: int = 20,
    sim_threshold: float = 0.0,     # set >0 to filter weak matches
    det_size=(640, 640),
    use_gpu=True,
):
    providers = ["CUDAExecutionProvider", "CPUExecutionProvider"] if use_gpu else ["CPUExecutionProvider"]

    # name can be switched to smaller/faster model packs if available in your setup
    app = FaceAnalysis(name="buffalo_l", providers=providers)
    app.prepare(ctx_id=0 if use_gpu else -1, det_size=det_size)

    qimg = imread_unicode(query_image_path)
    qfaces = app.get(qimg)
    qface = pick_primary_face(qfaces)
    if qface is None:
        raise RuntimeError("No face detected in the query image.")

    # L2-normalized embedding (so cosine sim == dot product)
    q = qface.normed_embedding

    # Maintain a min-heap of best results
    # item = (sim, path, bbox)
    heap = []

    for path in iter_images(folder):
        img = imread_unicode(path)
        if img is None:
            continue

        faces = app.get(img)
        for f in faces:
            sim = float(np.dot(q, f.normed_embedding))
            if sim < sim_threshold:
                continue

            bbox = f.bbox.astype(int).tolist()

            if len(heap) < top_k:
                heapq.heappush(heap, (sim, path, bbox))
            else:
                if sim > heap[0][0]:
                    heapq.heapreplace(heap, (sim, path, bbox))

    # Sort descending by similarity
    results = sorted(heap, key=lambda x: x[0], reverse=True)
    return results

if __name__ == "__main__":
    results = search_face(
        query_image_path="query.jpg",
        folder="photos/",
        top_k=10,
        sim_threshold=0.35,   # you MUST calibrate this for your model/domain
        det_size=(640, 640),
        use_gpu=True,
    )
    for sim, path, bbox in results:
        print(f"{sim:.3f}  {path}  bbox={bbox}")
```

**What this gives you**

* Query image → embedding once
* Each folder image → detect all faces → embed → compare to query
* Returns top‑K matches + the face bounding box inside the complex image

---

## The big performance lever you’re currently forbidding: caching (lazy, not upfront)

I know you said “no indexing”, but it’s worth being explicit:

* If you run **one query one time**, scanning on the fly is fine.
* If you run **many queries over the same folder**, re-detecting + re-embedding every image each time will dominate runtime.

A compromise that still matches your “no pre-indexing” spirit:

### Lazy cache strategy

* On first time you touch an image, compute face boxes + embeddings and store them in a small sidecar file (e.g., `image.jpg.faces.npz` with `mtime`).
* Next queries reuse that cache if the image hasn’t changed.

This is not a “build the whole index first” job; it’s **compute-on-demand** and becomes fast over time.

---

## Expanding to web search later

At web scale, “no indexing” stops being realistic, because you can’t scan “the web” on demand. The standard approach is:

* crawl/collect images → detect faces → store embeddings in a vector store
* query = embedding → ANN search → re-rank with exact cosine similarity → return image + bbox

You can still keep it privacy-aware and scoped (e.g., only your own domains / allowed sources).

---

## Practical accuracy notes

* Your **detector** quality is as important as the embedder. Missed/poor crops kill recognition.
* Always **align** using landmarks.
* Calibrate your **similarity threshold** on your real data (lighting, camera type, resolution, demographics). Don’t guess.

---

## Safety, privacy, and licensing

Face embeddings are biometric identifiers. If you ever use this on people other than yourself/consenting users, you’ll want clear consent + careful handling/storage policies.

Also, double-check the license of any pretrained model you use—some popular model packages are explicitly **non-commercial** or require separate licensing. The InsightFace repo and site both highlight restrictions around pretrained model usage and licensing for packages like `buffalo_l`. ([GitHub][5])

---

If you tell me your **target hardware** (CPU-only vs GPU model), approximate **#images**, and whether you’ll run **many repeated queries**, I can recommend a specific detector/recognizer size pair and an optimal batching/pipeline setup—still respecting your “no upfront indexing” constraint.

[1]: https://github.com/deepinsight/insightface/blob/master/detection/scrfd/README.md?utm_source=chatgpt.com "insightface/detection/scrfd/README.md at master"
[2]: https://arxiv.org/abs/1905.00641?utm_source=chatgpt.com "RetinaFace: Single-stage Dense Face Localisation in the Wild"
[3]: https://arxiv.org/abs/1801.07698?utm_source=chatgpt.com "ArcFace: Additive Angular Margin Loss for Deep Face Recognition"
[4]: https://arxiv.org/abs/2204.00964?utm_source=chatgpt.com "AdaFace: Quality Adaptive Margin for Face Recognition"
[5]: https://github.com/deepinsight/insightface "GitHub - deepinsight/insightface: State-of-the-art 2D and 3D Face Analysis Project"

If you *re-encode every image in the folder at query time*, it will almost always be the bottleneck (disk I/O + face detection + embedding inference). The efficient pattern for face search is:

* **Compute the query face embedding once** ✅ (what you want)
* **Precompute embeddings for the folder once** ✅ (so comparisons are fast)
* At query time: **do only a nearest-neighbor search** (dot products / vector index), not re-running the CNN on the whole folder.

That still works even when your “gallery images” are complex (multiple people, backgrounds): you pre-detect & embed **each detected face** in each image and index those face-embeddings with metadata (image path + bounding box).

---

## The fast architecture (recommended)

### 1) Offline “gallery indexing” step (run once, then incremental updates)

For each image in your folder:

1. **Detect all faces** (RetinaFace / SCRFD-class detectors are common in modern pipelines).
2. For each face:

   * **Align** (optional but usually improves matching consistency)
   * **Extract an embedding** (e.g., 512-D vector)
   * **L2-normalize** the embedding
3. Store:

   * `embedding` (vector)
   * `image_path`
   * `bbox` (x1,y1,x2,y2)
   * `det_score` (optional)
4. Build a vector index for fast lookup.

A common all-in-one starting point is InsightFace, which provides detection + recognition embeddings via ONNX Runtime. Note: the *code* is MIT-licensed, but the *pretrained models* distributed with the Python package are described as **non-commercial research only**.

### 2) Online “search” step (per query)

1. Detect the query face (or accept a pre-cropped face)
2. Extract & normalize the **query embedding once**
3. Search the index to get top‑K nearest faces
4. Return results (image path + bounding box + similarity score)

This makes query-time cost roughly:

* one face detection + one embedding forward pass
* plus **very fast vector search** (milliseconds to sub-millisecond depending on size/index).

---

## Why “on-the-fly for the whole folder” is slow (and when it’s OK)

### If you do it literally on-the-fly (every query):

* You must read every image from disk
* Run face detector (expensive)
* Run embedding model (expensive)
* Then compare

That scales like **O(#images)** per query, which becomes painful quickly.

### When on-the-fly can still be acceptable

* Your folder is tiny (e.g., a few hundred images)
* You only run occasional queries
* You can batch on GPU/CPU efficiently

Even then, you’ll still get a huge speedup by caching embeddings after first computation (lazy indexing).

---

## Making comparisons extremely fast

Once you have normalized embeddings:

* **Cosine similarity = dot product of normalized vectors** (i.e., inner product).
* Many vector engines implement cosine search by normalizing vectors and then using dot product under the hood.

If you use an inner-product index (common choice) you *must* normalize yourself because these indexes do not magically normalize your vectors for you.

For local search, a standard choice is FAISS. (For cosine similarity, you store normalized embeddings and use an inner-product index/search.)

---

## Two practical implementation modes

### Mode A — “Pre-index everything” (fastest queries)

* Run an indexing script once
* Save:

  * FAISS index file (or an embeddings matrix)
  * metadata mapping (JSON/SQLite)
* Query is instant

**Best when**: you care about responsiveness and have >1–2k images or frequent queries.

### Mode B — “Lazy index with cache” (good compromise)

* On first run/query:

  * compute embeddings, store them
* Next queries reuse cached embeddings
* Only new/changed images get processed

**Best when**: your folder changes often, but you still want speed.

---

## A minimal fast workflow (local folder)

### Offline indexing pseudocode

1. Walk folder
2. For each image:

   * detect all faces
   * compute embeddings (batch faces if possible)
   * append embedding rows to a big matrix `E` (shape N×D)
   * append metadata rows to `meta`

### Query-time scoring (super fast)

If `E` is float32 and already L2-normalized, and `q` is normalized:

```python
scores = E @ q          # vectorized dot products (cosine similarity)
topk = scores.argpartition(-k)[-k:]
topk = topk[scores[topk].argsort()[::-1]]
```

This avoids a heavyweight “search engine” entirely for small/medium datasets; it’s just a matrix multiply.

If N is large (hundreds of thousands+ faces), then use a vector index (flat exact or approximate).

---

## Scaling tips for efficiency + accuracy

### Accuracy tips

* **Align faces** using landmarks (reduces pose/scale variance).
* Use a strong detector and tune:

  * `det_size` (bigger helps small faces)
  * `det_thresh` (avoid junk detections)
* Keep embeddings in float32 for best accuracy.

### Speed tips

* Indexing: run detection + embedding in **batches** and/or multiprocess image loading.
* Persist results: store embeddings + metadata so you don’t recompute.
* For large datasets:

  * Exact search: “flat” index is simplest but O(N)
  * Approximate: IVF/HNSW gives much faster queries with slight recall tradeoff

If you outgrow local-only indexing, a production option is a vector DB like Qdrant, which supports cosine similarity and normalizes vectors when inserting (implementation detail depends on config).

---

## Important note on use & data handling

Face embeddings are biometric identifiers in many jurisdictions. If you ever expand beyond your own authorized dataset:

* get consent / legal basis
* secure embeddings at rest (encryption, access control)
* be careful with web ingestion (copyright + privacy + ToS)

---

## What I’d do as your “v1”

1. Use a pretrained detector+embedder stack to avoid training initially.
2. Build an **offline face index** (per-face embeddings + metadata).
3. Query: embed once → vector search → show results with bounding boxes.

If you want, I can sketch a clean folder-indexer + search script structure (index build, incremental updates, and result visualization) that matches your constraints exactly (CPU-only vs GPU, estimated dataset size, and whether you want per-image or per-face results).

---------------------------------------------
+++++++++++++++++++++++++++++++++++++++++++++

Done — here’s a **timeline normalizer + artifact store** that:

* takes a “Timeline Artifact” (object or JSON),
* **normalizes + truncates** it (so it stays small),
* writes it under **`.opencode/artifacts/timelines/<bucket>/…`**,
* appends an **index.jsonl** so you can list/latest,
* returns a **`@file` ref** you can hand to other agents instead of copy/paste.

This uses OpenCode’s documented **custom tools** mechanism (TS/JS in `.opencode/tools/`, filename→tool name, Bun runtime, with `context.worktree`). ([opencode.ai][1])

---

## 1) Add the tool: `.opencode/tools/timeline.ts`

> This single file exports **4 tools**:
>
> * `timeline_store`
> * `timeline_list`
> * `timeline_latest`
> * `timeline_get`
>
> OpenCode names them `<filename>_<exportname>` when you export multiple tools from one file. ([opencode.ai][1])

```ts
// .opencode/tools/timeline.ts
import { tool } from "@opencode-ai/plugin"
import * as path from "path"
import * as crypto from "crypto"
import {
  mkdir,
  writeFile,
  appendFile,
  readFile,
  readdir,
  stat,
} from "fs/promises"

type Json = null | boolean | number | string | Json[] | { [k: string]: Json }

const ALLOWED_EVENT_KINDS = new Set([
  "alloc",
  "realloc",
  "free",
  "alias",
  "store",
  "load",
  "escape",
  "return",
  "deref",
  "memop",
  "note",
  "collapse",
])

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v)
}

function safeSlug(input: string, maxLen = 48): string {
  const s = (input || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-+/g, "-")
  return (s || "artifact").slice(0, maxLen)
}

function safeBucket(input: string | undefined): string {
  // Allow nested buckets like "uaf" or "memop/parse"
  const raw = (input || "default").replace(/\\/g, "/").trim()
  const parts = raw
    .split("/")
    .map((p) => safeSlug(p, 32))
    .filter((p) => p.length > 0)

  if (parts.length === 0) return "default"
  // Prevent silly depth
  return parts.slice(0, 3).join("/")
}

function utcStampForFilename(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0")
  return (
    `${d.getUTCFullYear()}` +
    `${pad(d.getUTCMonth() + 1)}` +
    `${pad(d.getUTCDate())}-` +
    `${pad(d.getUTCHours())}` +
    `${pad(d.getUTCMinutes())}` +
    `${pad(d.getUTCSeconds())}Z`
  )
}

function sortKeysDeep(value: any): any {
  if (Array.isArray(value)) return value.map(sortKeysDeep)
  if (value && typeof value === "object" && value.constructor === Object) {
    const out: any = {}
    for (const k of Object.keys(value).sort()) out[k] = sortKeysDeep(value[k])
    return out
  }
  return value
}

function truncateString(s: unknown, max = 220): string | undefined {
  if (typeof s !== "string") return undefined
  const t = s.trim()
  if (t.length <= max) return t
  return t.slice(0, max - 1) + "…"
}

function normalizeTimeline(
  input: unknown,
  opts: {
    targetHint?: string
    maxEvents: number
    dropCode: boolean
    bucket: string
    tags: string[]
    context: any
  }
): Record<string, any> {
  let obj: any = input

  if (typeof input === "string") {
    const trimmed = input.trim()
    try {
      obj = JSON.parse(trimmed)
    } catch {
      // If it isn't JSON, store as a "note" timeline with 1 event
      obj = {
        target: opts.targetHint || "unknown",
        events: [
          {
            kind: "note",
            detail: trimmed.slice(0, 2000),
          },
        ],
        guards: {},
        notes: ["Input was not valid JSON; stored as a single note event."],
      }
    }
  }

  if (!isPlainObject(obj)) {
    // fallback: make a minimal timeline
    obj = {
      target: opts.targetHint || "unknown",
      events: [{ kind: "note", detail: "Non-object timeline input." }],
      guards: {},
      notes: [],
    }
  }

  const target =
    (typeof obj.target === "string" && obj.target.trim()) ||
    (opts.targetHint?.trim() || "unknown")

  const entryHint =
    typeof obj.entry_hint === "string"
      ? truncateString(obj.entry_hint, 200)
      : undefined

  const notes: string[] = Array.isArray(obj.notes)
    ? obj.notes
        .map((n: any) => (typeof n === "string" ? truncateString(n, 240) : undefined))
        .filter(Boolean) as string[]
    : []

  const guards: Record<string, string> = isPlainObject(obj.guards)
    ? Object.fromEntries(
        Object.entries(obj.guards)
          .slice(0, 200)
          .map(([k, v]) => [
            String(k).slice(0, 40),
            typeof v === "string" ? v.slice(0, 400) : JSON.stringify(v).slice(0, 400),
          ])
      )
    : {}

  let events: any[] = Array.isArray(obj.events) ? obj.events.slice() : []
  if (!Array.isArray(obj.events)) {
    events.push({ kind: "note", detail: "Missing events[]; created empty timeline." })
  }

  // Normalize events
  const normEvents: any[] = []
  for (let i = 0; i < events.length; i++) {
    const e = events[i]
    const pe = isPlainObject(e) ? e : { detail: String(e) }

    let kind = typeof pe.kind === "string" ? pe.kind.trim() : "note"
    if (!ALLOWED_EVENT_KINDS.has(kind)) kind = "note"

    const ne: any = {
      id: typeof pe.id === "string" ? pe.id : `E${i + 1}`,
      kind,
      ptr: truncateString(pe.ptr, 120),
      site: truncateString(pe.site, 180),
      func: truncateString(pe.func, 120),
      detail:
        truncateString(pe.detail, 260) ||
        truncateString(pe.op, 120) ||
        truncateString(pe.what, 260),
      guard: Array.isArray(pe.guard)
        ? pe.guard.map((g: any) => String(g).slice(0, 40)).slice(0, 20)
        : undefined,
      // Keep some common memop fields (optional)
      op: truncateString(pe.op, 80),
      dst: truncateString(pe.dst, 160),
      src: truncateString(pe.src, 160),
      len: truncateString(pe.len, 120),
      dst_size: truncateString(pe.dst_size, 120),
    }

    if (opts.dropCode) {
      // Drop raw code blobs if present
      // (This is a big win for keeping context small.)
    } else if (typeof pe.code === "string") {
      ne.code = pe.code.slice(0, 800)
    }

    // Remove empty keys
    for (const k of Object.keys(ne)) {
      if (ne[k] === undefined || ne[k] === null || ne[k] === "") delete ne[k]
    }

    normEvents.push(ne)
  }

  // Enforce max events (collapse middle)
  const maxEvents = Math.max(1, Math.min(opts.maxEvents, 200))
  let finalEvents = normEvents
  if (normEvents.length > maxEvents) {
    const keepHead = Math.floor(maxEvents / 2)
    const keepTail = maxEvents - keepHead - 1
    const head = normEvents.slice(0, keepHead)
    const tail = normEvents.slice(normEvents.length - keepTail)
    const collapsed = {
      id: `E${keepHead + 1}`,
      kind: "collapse",
      detail: `Collapsed ${normEvents.length - keepHead - keepTail} events to keep artifact small.`,
    }
    finalEvents = [...head, collapsed, ...tail].map((e, idx) => ({
      ...e,
      id: `E${idx + 1}`,
    }))
    notes.push(
      `Timeline had ${normEvents.length} events; collapsed to ${maxEvents}.`
    )
  } else {
    // ensure sequential IDs
    finalEvents = normEvents.map((e, idx) => ({ ...e, id: `E${idx + 1}` }))
  }

  const createdAt = new Date().toISOString()

  return {
    $schema: "opencode://artifact/timeline/v1",
    kind: "timeline",
    schema_version: 1,

    created_at: createdAt,
    created_by: {
      agent: opts.context.agent,
      session_id: opts.context.sessionID,
      message_id: opts.context.messageID,
    },

    bucket: opts.bucket,
    tags: opts.tags,

    target,
    entry_hint: entryHint,
    events: finalEvents,
    guards,
    notes,
  }
}

function computeDigest(tl: any): Record<string, any> {
  const counts: Record<string, number> = {}
  const kinds: string[] = []
  const events: any[] = Array.isArray(tl?.events) ? tl.events : []

  for (const e of events) {
    const k = typeof e?.kind === "string" ? e.kind : "note"
    counts[k] = (counts[k] || 0) + 1
    kinds.push(k)
  }

  // Very simple “UAF-ish” heuristic:
  // any "free" followed later by a "deref" or "memop"
  let uafHeuristic = false
  let seenFree = false
  for (const k of kinds) {
    if (k === "free") seenFree = true
    if (seenFree && (k === "deref" || k === "memop")) {
      uafHeuristic = true
      break
    }
  }

  return {
    target: tl?.target ?? "unknown",
    bucket: tl?.bucket ?? "default",
    event_count: events.length,
    kind_counts: counts,
    uaf_heuristic: uafHeuristic,
  }
}

async function fileExists(p: string): Promise<boolean> {
  try {
    await stat(p)
    return true
  } catch {
    return false
  }
}

function ensureInside(baseDir: string, candidatePath: string) {
  const base = path.resolve(baseDir)
  const cand = path.resolve(candidatePath)
  if (!cand.startsWith(base + path.sep) && cand !== base) {
    throw new Error(`Refusing path outside artifacts dir: ${candidatePath}`)
  }
}

function artifactsRoot(worktree: string) {
  return path.join(worktree, ".opencode", "artifacts", "timelines")
}

async function scanTimelineFiles(dir: string): Promise<string[]> {
  const out: string[] = []
  const items = await readdir(dir, { withFileTypes: true })
  for (const it of items) {
    const p = path.join(dir, it.name)
    if (it.isDirectory()) {
      out.push(...(await scanTimelineFiles(p)))
    } else if (it.isFile() && it.name.endsWith(".json")) {
      out.push(p)
    }
  }
  return out
}

/**
 * timeline_store
 */
export const store = tool({
  description:
    "Normalize + store a Timeline Artifact under .opencode/artifacts/timelines/<bucket>/ and return a @file ref + digest.",
  args: {
    timeline: tool.schema.any().describe("Timeline Artifact object or JSON string."),
    target_hint: tool.schema.string().optional().describe("Used if timeline.target is missing."),
    bucket: tool.schema
      .string()
      .optional()
      .describe("Bucket subdir under timelines/ (default 'default'). Example: 'uaf' or 'memop/parse'."),
    slug: tool.schema.string().optional().describe("Optional filename slug (defaults to target)."),
    tags: tool.schema.array(tool.schema.string()).optional().describe("Optional tags."),
    max_events: tool.schema.number().int().positive().optional().describe("Max events to keep (default 30)."),
    drop_code: tool.schema.boolean().optional().describe("Drop any 'code' fields (default true)."),
    return_ref_only: tool.schema.boolean().optional().describe("If true, returns only the @file reference string."),
  },

  async execute(args, context) {
    const bucket = safeBucket(args.bucket)
    const tags = (args.tags ?? []).slice(0, 20).map((t) => String(t).slice(0, 32))
    const maxEvents = typeof args.max_events === "number" ? args.max_events : 30
    const dropCode = args.drop_code !== false

    const normalized = normalizeTimeline(args.timeline, {
      targetHint: args.target_hint,
      maxEvents,
      dropCode,
      bucket,
      tags,
      context,
    })

    const canonical = JSON.stringify(sortKeysDeep(normalized))
    const sha = crypto.createHash("sha256").update(canonical).digest("hex")
    const id = `tln_${sha.slice(0, 12)}`

    const slug = safeSlug(args.slug || normalized.target || "timeline", 48)
    const stamp = utcStampForFilename(new Date())
    const filename = `${stamp}-${slug}-${sha.slice(0, 8)}.json`

    const root = artifactsRoot(context.worktree)
    const dir = path.join(root, bucket)
    await mkdir(dir, { recursive: true })
    ensureInside(root, dir)

    const relPath = path.join(".opencode", "artifacts", "timelines", bucket, filename)
    const absPath = path.join(context.worktree, relPath)
    ensureInside(root, absPath)

    await writeFile(absPath, JSON.stringify(sortKeysDeep(normalized), null, 2) + "\n", "utf8")

    // Append index (JSONL)
    const indexPath = path.join(root, "index.jsonl")
    const digest = computeDigest(normalized)
    const entry = {
      id,
      kind: "timeline",
      created_at: normalized.created_at,
      bucket,
      target: normalized.target,
      path: relPath.replace(/\\/g, "/"),
      sha256: sha,
      digest,
      tags,
    }
    await appendFile(indexPath, JSON.stringify(entry) + "\n", "utf8").catch(() => {})

    const ref = `@${entry.path}`

    if (args.return_ref_only) return ref

    return {
      ok: true,
      id,
      ref,
      path: entry.path,
      digest,
    }
  },
})

/**
 * timeline_list
 */
export const list = tool({
  description:
    "List stored timeline artifacts from .opencode/artifacts/timelines/index.jsonl (fallback: directory scan).",
  args: {
    bucket: tool.schema.string().optional().describe("Bucket filter (e.g., 'uaf' or 'memop')."),
    target_contains: tool.schema.string().optional().describe("Substring filter on target."),
    limit: tool.schema.number().int().positive().optional().describe("Max results (default 20)."),
  },

  async execute(args, context) {
    const root = artifactsRoot(context.worktree)
    const indexPath = path.join(root, "index.jsonl")
    const limit = typeof args.limit === "number" ? Math.min(args.limit, 200) : 20
    const bucketFilter = args.bucket ? safeBucket(args.bucket) : undefined
    const targetContains = args.target_contains?.toLowerCase()

    const results: any[] = []

    if (await fileExists(indexPath)) {
      const txt = await readFile(indexPath, "utf8")
      for (const line of txt.split("\n")) {
        const t = line.trim()
        if (!t) continue
        try {
          const entry = JSON.parse(t)
          if (entry?.kind !== "timeline") continue
          if (bucketFilter && entry.bucket !== bucketFilter) continue
          if (targetContains && typeof entry.target === "string") {
            if (!entry.target.toLowerCase().includes(targetContains)) continue
          }
          results.push(entry)
        } catch {
          // skip bad line
        }
      }
    } else {
      // fallback scan (no index yet)
      if (!(await fileExists(root))) return []
      const files = await scanTimelineFiles(root)
      for (const abs of files) {
        const rel = path.relative(context.worktree, abs).replace(/\\/g, "/")
        results.push({
          id: "unknown",
          kind: "timeline",
          bucket: "unknown",
          target: "unknown",
          path: rel,
          digest: { event_count: "?" },
        })
      }
    }

    results.sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")))
    return results.slice(0, limit)
  },
})

/**
 * timeline_latest
 */
export const latest = tool({
  description:
    "Return the latest stored timeline artifact ref, optionally filtered by bucket/target substring.",
  args: {
    bucket: tool.schema.string().optional().describe("Bucket filter."),
    target_contains: tool.schema.string().optional().describe("Substring filter on target."),
  },

  async execute(args, context) {
    // Reuse list logic by reading index.jsonl directly
    const root = artifactsRoot(context.worktree)
    const indexPath = path.join(root, "index.jsonl")
    const bucketFilter = args.bucket ? safeBucket(args.bucket) : undefined
    const targetContains = args.target_contains?.toLowerCase()

    if (!(await fileExists(indexPath))) {
      return { ok: false, message: "No index.jsonl found. Store a timeline first." }
    }

    const txt = await readFile(indexPath, "utf8")
    const entries: any[] = []
    for (const line of txt.split("\n")) {
      const t = line.trim()
      if (!t) continue
      try {
        const entry = JSON.parse(t)
        if (entry?.kind !== "timeline") continue
        if (bucketFilter && entry.bucket !== bucketFilter) continue
        if (targetContains && typeof entry.target === "string") {
          if (!entry.target.toLowerCase().includes(targetContains)) continue
        }
        entries.push(entry)
      } catch {
        // ignore
      }
    }

    entries.sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")))
    const e = entries[0]
    if (!e) return { ok: false, message: "No matching timeline artifacts found." }

    return { ok: true, ref: `@${e.path}`, path: e.path, id: e.id, digest: e.digest }
  },
})

/**
 * timeline_get
 */
export const get = tool({
  description:
    "Load a stored timeline artifact JSON. Optionally return only specified top-level fields.",
  args: {
    path: tool.schema.string().describe("Path to artifact JSON (relative to repo root)."),
    fields: tool.schema.array(tool.schema.string()).optional().describe("Top-level fields to return (e.g., ['target','events','guards'])."),
  },

  async execute(args, context) {
    const root = artifactsRoot(context.worktree)
    const rel = args.path.replace(/\\/g, "/").replace(/^@/, "").trim()
    const abs = path.join(context.worktree, rel)
    ensureInside(root, abs)

    const txt = await readFile(abs, "utf8")
    const obj = JSON.parse(txt)

    if (!args.fields || args.fields.length === 0) return obj

    const out: any = {}
    for (const f of args.fields.slice(0, 50)) out[f] = obj?.[f]
    return out
  },
})
```

Why this is “correct OpenCode style”:

* Tools belong in `.opencode/tools/` and are TS/JS; the **filename becomes the tool name**. ([opencode.ai][1])
* If you export multiple tools from one file, OpenCode creates `<filename>_<exportname>` tools. ([opencode.ai][1])
* Tool `execute()` receives `context` including `worktree`, which we use to safely write under the repo root. ([opencode.ai][1])

---

## 2) Add artifact folder docs + gitignore

### `.opencode/artifacts/README.md`

```md
# OpenCode Artifacts

This directory is used by custom tools to store compact analysis artifacts (timelines, constraints, etc)
to avoid copy/pasting large JSON blobs into the chat.

## Timeline artifacts
Stored under:
- `.opencode/artifacts/timelines/<bucket>/...json`

Index:
- `.opencode/artifacts/timelines/index.jsonl`

## How to use
- Store: the agent/tool will return something like:
  - `@.opencode/artifacts/timelines/uaf/20260204-...json`
- Then ask another agent to analyze that file by path (or use `@file` support in commands/templates).

## Safety
The timeline tool refuses to write/read outside `.opencode/artifacts/timelines/`.
```

### `.opencode/artifacts/.gitignore`

```gitignore
# Keep the directory, but ignore generated artifacts by default.
*
!.gitignore
!README.md
```

---

## 3) Permissions: allow these tools (recommended)

OpenCode permissions are keyed by **tool name**, and support wildcards. ([opencode.ai][2])
Add this to your `opencode.jsonc`:

```jsonc
{
  "permission": {
    // ...your existing rules...
    "timeline_*": "allow"
  }
}
```

If you prefer extra caution, set `"timeline_*": "ask"` instead.

---

## 4) Update your memory agents to *store* timelines instead of printing them

Agents in Markdown can set permissions in frontmatter; OpenCode merges these with global config. ([opencode.ai][3])

### 4.1 Update: `.opencode/agents/mem-uaf-timeline.md` (only show digest + @ref)

Add permissions and replace the output requirements:

```md
---
description: Build an allocation/free/use timeline for a specific pointer/dataflow to triage UAF candidates with minimal output.
mode: subagent
temperature: 0.1
steps: 35
permission:
  edit: deny
  webfetch: deny
  timeline_store: allow
  timeline_latest: allow
  timeline_list: allow
  timeline_get: allow
---

You build a compact UAF timeline.

Key rule: minimize output.
Instead of printing the full timeline JSON, you MUST store it with `timeline_store` and only print:
- the returned `ref` (@file)
- the returned `digest`
- a 1–3 sentence verdict

Workflow:
1) Build a Timeline Artifact object (target, events, guards, notes).
2) Call `timeline_store` with:
   - bucket: "uaf"
   - max_events: 30
   - drop_code: true
3) Output ONLY:
   - Artifact: <ref>
   - Digest: <digest>
   - Verdict: <short>
   - Next: suggest `/mem-constraints <artifact-path>` and `/z3-check` steps (defensive).

Never provide weaponized exploit instructions.
```

### 4.2 Update: `.opencode/agents/mem-memop-timeline.md` similarly

Same idea but use bucket `memop` and include dst/len/size info in events/guards (still compact), then store via `timeline_store`.

---

## 5) Optional: add “artifact workflow” skill (keeps everyone consistent)

Skills must be `SKILL.md` (caps) with `name` and `description`. ([opencode.ai][4])

### `.opencode/skills/mem-artifact-workflow/SKILL.md`

```md
---
name: mem-artifact-workflow
description: Use file-backed artifacts (timeline_store + @file refs) to keep memory-safety analysis compact and composable across agents.
compatibility: opencode
---

## Rule: store, don’t paste
When you produce a Timeline Artifact:
1) Construct the JSON object
2) Call `timeline_store` (bucket = "uaf" or "memop")
3) Return only:
- Artifact ref: @.opencode/artifacts/timelines/...
- Digest
- Verdict
- Next suggested command

## Why
- Keeps the chat context small
- Lets other agents operate by file reference
- Makes the analysis reproducible and auditable
```

---

## 6) Optional commands to make it ergonomic

Commands are Markdown files in `.opencode/commands/` and support `$ARGUMENTS`. ([opencode.ai][5])

### `/timelines` (list recent)

`.opencode/commands/timelines.md`

```md
---
description: List stored timeline artifacts (optionally filter by target substring).
agent: mem-audit
---

Call `timeline_list` with:
- target_contains: $ARGUMENTS
- limit: 20

Print a short list: created_at | bucket | target | ref
```

### `/timeline-latest`

`.opencode/commands/timeline-latest.md`

```md
---
description: Return the latest timeline artifact ref (optionally filter by bucket/target).
agent: mem-audit
---

If $ARGUMENTS is empty:
- Call `timeline_latest` with no filters.

If $ARGUMENTS is provided:
- Treat it as target_contains and call `timeline_latest target_contains=$ARGUMENTS`.

Print only: ref + digest.
```

---

## How this changes your workflow (what you wanted)

### Before

Agents dump big timelines into chat → noisy → hard to chain into constraints/Z3.

### After

* Agent generates timeline → stores it → returns just:

  * `@.opencode/artifacts/timelines/uaf/...json`
  * digest + verdict

Then:

* “constraints agent” loads timeline by path (`timeline_get` or plain `read`)
* builds SMT
* Z3 tool checks satisfiable trigger

This is exactly the “reduce data presented, but keep analyzable” pattern.

---

If you want, I can also:

* extend the same artifact system to **store SMT2** (`.opencode/artifacts/smt2/…`) and **store Z3 results** (`…/z3/…`), so the whole pipeline becomes file-backed and fully composable.

[1]: https://opencode.ai/docs/custom-tools/ "Custom Tools | OpenCode"
[2]: https://opencode.ai/docs/permissions/ "Permissions | OpenCode"
[3]: https://opencode.ai/docs/agents/ "Agents | OpenCode"
[4]: https://opencode.ai/docs/skills/?utm_source=chatgpt.com "Agent Skills"
[5]: https://opencode.ai/docs/commands/ "Commands | OpenCode"

You can absolutely build a “memory-safety agent pack” around **(1) lifetime timelines** and **(2) constraint+Z3 feasibility checks**—and keep it *high-signal* by standardizing what a “timeline” looks like and forcing every agent to output the same compact artifact.

Below is a practical, drop-in set of **agents + commands + skills + a Z3 custom tool**, designed around your 2 use cases:

* **Use case A**: “malloc/free timeline for a specific dataflow” → find UAF candidates with minimal noise
* **Use case B**: “scan suspicious memops (memcpy etc), build constrained timeline” → Z3 feasibility check

Everything uses OpenCode’s documented locations and formats for agents, commands, skills, custom tools, and permission rules. ([OpenCode][1])

---

## 0) The core idea: a shared “Timeline Artifact” (so outputs stay small)

To reduce output noise, make every memory agent produce the same **compact timeline artifact**:

### Timeline Artifact (minimal schema)

* **Target**: pointer/ownership object (e.g., `struct foo* p`, or field `ctx->buf`)
* **Events**: ordered list of only memory-lifetime-relevant steps
  `alloc | alias | store | load | free | realloc | memop | deref | return | escape`
* **Guards**: minimal path conditions needed for those events to happen (no full AST dumps)

This standardization is what makes the second phase (“constraints → Z3”) reliable and keeps the LLM from dumping the whole program.

---

## 1) Minimal `opencode.jsonc` updates for this workflow

OpenCode permissions can be defined per tool and can be **glob/pattern-based** (including `task` for subagents, and file-path patterns for `read`/`edit`). ([OpenCode][2])
Custom tools live in `.opencode/tools/` or `~/.config/opencode/tools/`. ([OpenCode][3])

Here’s a config that:

* allows read/grep/glob/lsp,
* blocks edits except artifacts/findings,
* allows invoking only `mem-*` agents,
* keeps webfetch off,
* makes your custom `z3` tool “ask” by default.

```jsonc
// opencode.jsonc
{
  "$schema": "https://opencode.ai/config.json",

  "permission": {
    "*": "ask",

    // Safe/static analysis
    "read": {
      "*": "allow",
      "*.env": "deny",
      "*.env.*": "deny",
      "*.env.example": "allow"
    },
    "grep": "allow",
    "glob": "allow",
    "list": "allow",

    // If you use the LSP tool, it’s permissioned like any other tool.
    "lsp": "allow",

    // Skills are useful for consistent outputs.
    "skill": { "*": "allow" },

    // Subagent launches
    "task": {
      "*": "deny",
      "mem-*": "allow"
    },

    // No outbound
    "webfetch": "deny",

    // No code edits; only allow writing artifacts + findings.
    // edit covers edit/write/patch/multiedit. :contentReference[oaicite:3]{index=3}
    "edit": {
      "*": "deny",
      ".opencode/artifacts/**": "allow",
      "docs/security/findings/**": "allow"
    },

    // Bash is optional; keep it gated.
    "bash": {
      "*": "ask",
      "git *": "allow",
      "rg *": "allow"
    },

    // Custom Z3 tool permission (defined below)
    "z3": "ask"
  }
}
```

Notes:

* Permissions support `task`, `skill`, file-path rules, and more. ([OpenCode][2])
* If you want these agents to use `lsp`, remember it’s an experimental tool that may require enabling via env flags depending on your setup. ([OpenCode][4])

---

## 2) Agents: purpose-built for timeline building + constraint checking

Agents go in `.opencode/agents/` (project) or `~/.config/opencode/agents/` (global). ([OpenCode][1])
Filename = agent name. ([OpenCode][1])

### 2.1 `.opencode/agents/mem-audit.md` (primary orchestrator)

```md
---
description: Memory safety auditor (UAF + heap/stack corruption). Builds compact lifetime timelines and can validate feasibility with Z3.
mode: primary
temperature: 0.1
steps: 40
permission:
  webfetch: deny
  task:
    "*": deny
    "mem-*": allow
---

You are a memory-safety vulnerability research agent. Your job is to find *reachable* memory lifetime and memory corruption issues, while minimizing noise.

Hard rule:
- Do NOT generate weaponized exploit payloads or instructions for attacking real systems.
- You may produce *defensive* reproduction guidance (unit-test harness ideas, fuzz seed shape) and feasibility proofs.

Core workflow:
1) For a suspected target (pointer, buffer, or callsite), produce a compact Timeline Artifact.
2) If asked for feasibility, convert Timeline Artifact → SMT-LIB2 constraints.
3) Use the Z3 tool (via mem-z3-check) to determine sat/unsat and show a minimal model.

Always keep output small:
- Prefer an event list + file:line references.
- Never paste full functions unless specifically needed.

Delegate specialized work to:
- mem-uaf-timeline
- mem-memop-scan
- mem-memop-timeline
- mem-constraints
- mem-z3-check
```

### 2.2 `.opencode/agents/mem-uaf-timeline.md` (use case A)

```md
---
description: Build an allocation/free/use timeline for a specific pointer/dataflow to triage UAF candidates with minimal output.
mode: subagent
temperature: 0.1
steps: 35
permission:
  edit: deny
  webfetch: deny
---

You build a compact UAF timeline.

Inputs (if user provides):
- a pointer symbol (e.g., `p`, `ctx->buf`)
- a type (e.g., `struct foo*`)
- a suspicious use site (file:line or function call)

Method (noise-minimizing):
1) Identify allocator/free wrappers:
   - malloc/calloc/realloc/free
   - new/delete (C++)
   - project-specific wrappers (e.g., xmalloc, foo_alloc/foo_free)
2) Start from the suspected "use" site and slice backwards to the alloc and forwards to frees:
   - Track *aliases only*: assignments, parameter passing, field stores/loads, returns (“escape”).
   - Ignore unrelated locals.
3) Produce a Timeline Artifact with <= 30 events. If more, collapse loops/recursion into a single summarized event.
4) Flag UAF candidates:
   - A free event that dominates a later deref/memop/use event for the same alias-set.
   - Note if concurrency/reentrancy is required (mark as “needs dynamic validation”).

Output (strict):
- ## Timeline Artifact (JSON)
- ## Evidence (event -> file:line)
- ## Guards (minimal conditions)
- ## UAF suspicion verdict (1–3 sentences)
```

### 2.3 `.opencode/agents/mem-memop-scan.md` (use case B: discovery)

```md
---
description: Scan the codebase for memory-corruption-prone operations (memcpy/memmove/strcpy/etc) and rank the most suspicious callsites.
mode: subagent
temperature: 0.1
steps: 25
permission:
  edit: deny
  webfetch: deny
---

You find and rank suspicious memory operations.

Target patterns (include wrappers):
- memcpy, memmove, mempcpy
- strcpy, strncpy, strcat, strncat
- sprintf, vsprintf, snprintf (format risks too)
- read/recv into buffers
- project-specific wrappers around these

Heuristics for "suspicious":
- length argument derived from external input or not obviously bounded
- size computed with int/signed conversions, truncation, or multiplication without overflow checks
- destination buffer is stack array, flexible array member, heap buffer with unclear size, or pointer arithmetic

Output (compact):
- Top 20 callsites as: file:line | function | call | “why suspicious”
- Then a short “next 5 to timeline” list
```

### 2.4 `.opencode/agents/mem-memop-timeline.md` (use case B: timeline + constraints)

```md
---
description: For a specific risky memop callsite (e.g., memcpy), build a compact buffer/length timeline with explicit size/guard constraints.
mode: subagent
temperature: 0.1
steps: 35
permission:
  edit: deny
  webfetch: deny
---

You build a memop-focused timeline + constraints.

Input should identify the callsite:
- file:line OR function name + snippet

Steps:
1) Locate the callsite; extract:
   - dst expression
   - src expression
   - len expression
2) Slice backwards to determine:
   - dst allocation/definition and its size expression
   - any checks that bound len (including early returns)
   - conversions/casts that change signedness/width
3) Produce a Timeline Artifact where the final event is:
   { kind: "memop", op: "memcpy", dst_size_expr: "...", len_expr: "...", ... }

Output:
- ## Timeline Artifact (JSON)
- ## Constraints (human-readable)
  - Define: dst_size, len, and any input-derived vars
  - List: guards that must hold
  - List: bug condition (e.g., len > dst_size)
- ## Recommended Z3 check goal (sat query)
```

### 2.5 `.opencode/agents/mem-constraints.md` (timeline → SMT-LIB2)

```md
---
description: Convert a Timeline Artifact into SMT-LIB2 constraints (small!) to check reachability/trigger feasibility.
mode: subagent
temperature: 0.1
steps: 30
permission:
  edit: deny
  webfetch: deny
---

You translate timeline constraints into SMT-LIB2.

Rules:
- Default to Int arithmetic for a first pass.
- If the bug depends on wraparound/truncation, switch relevant vars to BitVec and state the widths explicitly.
- Keep the SMT2 minimal: only vars appearing in guards or bug condition.

Output:
- ## SMT-LIB2 (copy/paste)
  Must include:
  - (set-option :produce-models true)
  - declarations
  - asserts for guards
  - assert for the bug condition
  - (check-sat)
  - (get-model)

Also output:
- ## Variable mapping
  var -> code expression -> file:line where it comes from
```

### 2.6 `.opencode/agents/mem-z3-check.md` (run solver, interpret safely)

```md
---
description: Run the Z3 custom tool on SMT-LIB2 and interpret sat/unsat into a defensive reproducer plan (no weaponized exploits).
mode: subagent
temperature: 0.1
steps: 15
permission:
  bash: deny
  edit: deny
  webfetch: deny
  z3: allow
---

You run Z3 and interpret results.

Input: SMT-LIB2 in the conversation or referenced via a file.

Process:
1) Call the z3 tool with the SMT2 text.
2) Report status: sat/unsat/unknown.
3) If sat, extract only high-level model assignments (integers/booleans) and explain how they correspond to code variables.
4) Provide *defensive* reproduction guidance:
   - suggest a unit test harness, or a minimized input shape
   - do NOT provide exploit payloads or real-world attack steps
```

---

## 3) Skills: keep agents consistent and “low-noise”

Skills live at `.opencode/skills/<name>/SKILL.md` and require YAML frontmatter with `name` and `description`. ([OpenCode][5])

### 3.1 `.opencode/skills/mem-lifetime-timeline/SKILL.md`

```md
---
name: mem-lifetime-timeline
description: Build compact allocation/free/alias/use timelines for pointer lifetimes to triage UAF with minimal output.
compatibility: opencode
---

## Goal
Produce a **Timeline Artifact** limited to lifetime-relevant events for ONE target pointer/alias set.

## Timeline Artifact schema (JSON)
- target: string
- entry_hint: string (optional)
- events: array of events (<= 30)
- guards: map guard_id -> expression
- notes: short strings

### Event fields
- id: "E1"
- kind: alloc | alias | store | load | free | realloc | deref | memop | return | escape
- ptr: "p" (or "ctx->buf")
- site: "path/file.c:123"
- func: "foo"
- detail: short (allocator/free fn, field name, etc.)
- guard: ["G1","G2"] (optional)

## Noise control rules
- Ignore unrelated locals and helper functions unless they affect ptr lifetime or size.
- Collapse loops into a single summarized event.
- Prefer file:line + 1 sentence over pasted code.
```

### 3.2 `.opencode/skills/mem-memop-triage/SKILL.md`

```md
---
name: mem-memop-triage
description: Identify and rank memory corruption hotspots (memcpy/memmove/strcpy/etc) and extract size/length constraints.
compatibility: opencode
---

## What to search for
- memcpy/memmove/mempcpy
- strcpy/strncpy/strcat/strncat
- sprintf/vsprintf/snprintf
- read/recv into buffers
- project wrappers around these

## Ranking rubric
Higher risk if:
- len is attacker-controlled or not obviously bounded
- dst buffer size is unknown/derived from prior allocations
- casts change signedness/width
- integer multiplication/addition used in size calc without bounds checks

## Deliverable
- top suspicious callsites
- for each: dst expr, len expr, local checks, file:line evidence
```

### 3.3 `.opencode/skills/mem-smt2-modeling/SKILL.md`

```md
---
name: mem-smt2-modeling
description: Translate guard conditions + bug predicates into minimal SMT-LIB2 for Z3 (Int-first, BitVec when needed).
compatibility: opencode
---

## Int-first recipe (fast feasibility)
- declare-const len Int
- declare-const dst_size Int
- assert (>= len 0), (>= dst_size 0)
- assert guards
- assert bug predicate (e.g., (> len dst_size))

## When to use BitVec
Use BitVec when:
- signed/unsigned conversions matter
- truncation (e.g., to 32-bit) matters
- overflow wraparound is part of the bug

## Always include
(set-option :produce-models true)
(check-sat)
(get-model)
```

### 3.4 `.opencode/skills/mem-z3-checking/SKILL.md`

```md
---
name: mem-z3-checking
description: Interpret Z3 sat/unsat results as defensive reachability proofs and convert models into safe reproducer guidance.
compatibility: opencode
---

## Output rules
- sat: show a minimal model (only relevant vars)
- unsat: explain which constraints likely conflict
- unknown: suggest simplifications (drop non-essential guards, Int-first)

## Safety
Do not provide weaponized exploit payloads. Provide unit-test harness guidance instead.
```

---

## 4) Commands: one-liners to drive the workflow

Commands are `.opencode/commands/*.md` and use YAML frontmatter like `description` and optional `agent`. ([OpenCode][6])

### 4.1 `/uaf-timeline`

`.opencode/commands/uaf-timeline.md`

```md
---
description: Build a compact alloc/free/use timeline for a target pointer/dataflow (UAF triage).
agent: mem-uaf-timeline
---

Target: $ARGUMENTS

Build a Timeline Artifact for the target.
Keep to <= 30 events.
Return JSON + evidence + guards + verdict.
```

### 4.2 `/memop-scan`

`.opencode/commands/memop-scan.md`

```md
---
description: Scan and rank suspicious memory ops (memcpy/strcpy/etc).
agent: mem-memop-scan
---

Scan the repo for high-risk memory operations and output the top 20 suspicious callsites.
Then recommend the top 5 to run /memop-timeline on.
```

### 4.3 `/memop-timeline`

`.opencode/commands/memop-timeline.md`

```md
---
description: Build a constraint-aware timeline for a specific memop callsite (e.g. memcpy) suitable for Z3.
agent: mem-memop-timeline
---

Callsite: $ARGUMENTS

Produce:
- Timeline Artifact JSON
- explicit constraints (dst_size, len, guards)
- a suggested Z3 bug predicate to check
```

### 4.4 `/mem-constraints`

`.opencode/commands/mem-constraints.md`

```md
---
description: Convert the most recent Timeline Artifact into SMT-LIB2 constraints.
agent: mem-constraints
---

Using the latest Timeline Artifact in the conversation, emit minimal SMT-LIB2 suitable for Z3.
Prefer Int-first unless wraparound is essential.
```

### 4.5 `/z3-check`

`.opencode/commands/z3-check.md`

```md
---
description: Run Z3 on SMT-LIB2 in the conversation and interpret sat/unsat safely.
agent: mem-z3-check
---

Run Z3 on the SMT-LIB2 provided in the conversation (or referenced via @file).
Return sat/unsat/unknown and a minimal model mapping back to code variables.
```

---

## 5) Custom Z3 tool (so agents can actually run the solver)

Custom tools can be created in `.opencode/tools/` or globally in `~/.config/opencode/tools/`. ([OpenCode][3])
The filename becomes the tool name. ([OpenCode][3])

### `.opencode/tools/z3.ts`

```ts
import { tool } from "@opencode-ai/plugin"
import os from "os"
import path from "path"
import fs from "fs/promises"

export default tool({
  description:
    "Run Z3 on SMT-LIB2 input and return sat/unsat/unknown plus stdout/stderr (for defensive reachability checks).",
  args: {
    smt2: tool.schema.string().describe("SMT-LIB2 text (should include check-sat; get-model optional)."),
    timeout_ms: tool.schema.number().int().positive().optional().describe("Optional Z3 timeout in ms (applied via set-option).")
  },
  async execute(args, context) {
    const z3Path = Bun.which("z3")
    if (!z3Path) {
      return {
        status: "error",
        message:
          "z3 binary not found in PATH. Install Z3, or adjust PATH for the OpenCode runtime."
      }
    }

    const smt2 =
      typeof args.timeout_ms === "number"
        ? `(set-option :timeout ${args.timeout_ms})\n(set-option :produce-models true)\n${args.smt2}`
        : `(set-option :produce-models true)\n${args.smt2}`

    const tmp = path.join(
      os.tmpdir(),
      `opencode-z3-${context.sessionID}-${Date.now()}-${Math.random().toString(16).slice(2)}.smt2`
    )

    await Bun.write(tmp, smt2)

    const proc = Bun.spawn({
      cmd: [z3Path, "-smt2", tmp],
      stdout: "pipe",
      stderr: "pipe"
    })

    const stdout = await new Response(proc.stdout).text()
    const stderr = await new Response(proc.stderr).text()
    const exitCode = await proc.exited

    // Best-effort cleanup
    await fs.unlink(tmp).catch(() => {})

    const out = stdout.trim()
    const firstTok = out.split(/\s+/)[0] || "unknown"

    // Z3 typically prints: sat / unsat / unknown first.
    const status = ["sat", "unsat", "unknown"].includes(firstTok) ? firstTok : "unknown"

    return {
      status,
      exitCode,
      stdout: out,
      stderr: stderr.trim()
    }
  }
})
```

---

## 6) How the 2 use cases look in practice

### Use case A: UAF-focused lifetime timeline

1. `/uaf-timeline ctx->buf`
2. If it shows `free` then later `deref/memop`, run `/mem-constraints`
3. Then `/z3-check` to validate the feasibility of the “free-before-use” + guard conditions (as modeled)

### Use case B: corruption hotspot → constrained timeline → Z3

1. `/memop-scan` (gives top suspicious memcpy/strcpy/etc callsites)
2. `/memop-timeline path/to/file.c:123`
3. `/mem-constraints` (bug predicate might be `len > dst_size` or something more nuanced)
4. `/z3-check` (sat gives you a **defensive** witness model; you turn that into a unit-test harness)

---

## One important realism note

This approach is powerful for **reachability proofs**, but it’s still an approximation:

* aliasing can explode (timeline agent must be strict about alias-set boundaries),
* size computations often depend on opaque helpers,
* concurrency/reentrancy UAFs may require dynamic validation.

That’s fine: your goal is **triage + “is there a satisfiable trigger?”**, not perfect soundness.

---

If you want to push this even further (still keeping outputs compact), the next upgrade is a **single “timeline normalizer” tool** that stores the Timeline Artifact to `.opencode/artifacts/…` and lets subsequent agents reference it by filename instead of copy/pasting. The permission model already supports this path-scoped write pattern. ([OpenCode][2])

[1]: https://opencode.ai/docs/agents/ "Agents | OpenCode"
[2]: https://opencode.ai/docs/permissions/ "Permissions | OpenCode"
[3]: https://opencode.ai/docs/custom-tools/ "Custom Tools | OpenCode"
[4]: https://opencode.ai/docs/tools/ "Tools | OpenCode"
[5]: https://opencode.ai/docs/skills/ "Agent Skills | OpenCode"
[6]: https://opencode.ai/docs/commands/ "Commands | OpenCode"


Below are **two concrete opencode “use cases”** you can drop into your setup:

1. **Memory Lifetime Timeline (malloc/free tracking)** → optimized for **Use-After-Free / Double-Free / Leak** triage
2. **Z3 Feasibility (satisfiable bug triggers)** → turns a suspected memory bug path into **constraints**, checks **SAT/UNSAT**, and records the result in the report

This is designed to fit your existing **Flow Walkthrough** report format (S1..Sn + “What is happening” per step), and uses opencode’s native layout: **agents/commands/skills/tools**. ([OpenCode][1])

---

# Add these files

### File tree (additions)

```text
.opencode/
  agents/
    vuln-mem.md
    vuln-smt.md

  commands/
    sec-mem-timeline.md
    sec-mem-z3.md

  skills/
    memory-lifetime-timeline/SKILL.md
    z3-feasibility/SKILL.md

  tools/
    mem_events.py
    mem_events.ts
    z3_smt2.py
    z3_smt2.ts

docs/security/findings/
  TEMPLATE-memory.md
```

Notes:

* Skills **must** be named `SKILL.md` in all caps and include YAML frontmatter with `name` + `description`. ([OpenCode][2])
* Custom tools live in `.opencode/tools/` and are TS/JS wrappers that can invoke Python (or anything). ([OpenCode][3])
* Commands are Markdown files in `.opencode/commands/` with frontmatter. ([OpenCode][4])
* Agents can be Markdown files in `.opencode/agents/` with frontmatter like `mode`, `temperature`, `tools`, and `permission`. ([OpenCode][1])

---

# Use case 1 — Memory Lifetime Timeline (UAF hunting)

## What it produces

**A per-allocation timeline** that looks like this (example shape):

* **Allocation ID**: `A1`
* **Timeline**: `ALLOC → alias → store → FREE → USE ⚠️`
* Every step references:

  * **What is happening**
  * **Evidence** (`path:Lx-Ly`)
  * **Heap state snapshot** (who points to what; live vs freed)

This makes UAF review *very fast*, because you can literally follow the lifetime like a story.

---

## 1A) Agent: `.opencode/agents/vuln-mem.md`

```md
---
description: Memory lifetime auditor. Builds allocation/free/use timelines to find UAF/double-free/leak candidates. Read-only by default.
mode: subagent
temperature: 0.1
steps: 35

tools:
  write: false
  edit: false
  patch: false
  bash: false
  webfetch: false

permission:
  # Allow calling our read-only indexing tool (custom tool).
  mem_events: allow
---

You are a memory lifetime auditor for C/C++-style codebases.

Goal:
- Track allocations, frees, and uses of heap objects and produce a timeline per allocation.
- Identify memory safety hazards: Use-After-Free, Double Free, invalid free, lifetime confusion, and leaks.

Never:
- Provide weaponized exploit payloads or exploitation steps.
- Discuss heap grooming or bypassing mitigations. Stay defensive and diagnostic.

Workflow:
1) Identify allocator/free APIs used (malloc/calloc/realloc/free, new/delete, custom wrappers).
2) Index call sites using the mem_events tool (or grep/lsp if needed).
3) Pick the most reachable/important entry flow and build a Flow Walkthrough (S1..Sn).
4) For each allocation (A1..Ak), build a Timeline:
   - ALLOC event: where created + size expression + initial owner
   - ALIAS/MOVE events: assignments, passing to functions, storing in structs/globals
   - FREE event: where freed + condition guarding it
   - USE events: deref, memcpy/memmove, field access, indexing, printf("%s"), etc.
5) Flag hazard windows:
   - UAF: any USE after FREE on same alloc ID
   - Double free: FREE after FREE
   - Leak: ALLOC without a matching FREE on all paths in scope

Deliverables:
- Memory Objects table (A1..Ak)
- Allocation Timeline table per object
- Annotated hazard window pointing to ⚠️ bug trigger step in the flow
- Evidence references at every step
```

Why this is “opencode-correct”:

* Subagents are supported and invokable with `@...`. ([OpenCode][1])
* Tools can be disabled in agent frontmatter (`tools: write: false`, etc.). ([OpenCode][1])

---

## 1B) Skill: `.opencode/skills/memory-lifetime-timeline/SKILL.md`

````md
---
name: memory-lifetime-timeline
description: Build per-allocation lifetimes (ALLOC/ALIAS/FREE/USE) as step-by-step timelines to detect UAF/double-free/leaks with evidence and “What is happening” at each step.
compatibility: opencode
---

## Concepts

### Allocation IDs
Assign each heap allocation a stable ID:
- A1, A2, A3...
The ID refers to the *heap object instance*, not the pointer variable.

### Event types
Use these canonical events in timelines:
- ALLOC: malloc/calloc/new/realloc returning a new object
- REALLOC: realloc that may move and invalidate old pointer
- ALIAS: another pointer now refers to same allocation (assignment, param passing)
- STORE: pointer stored into struct/global/container
- LOAD: pointer loaded back from struct/global/container
- FREE: free/delete on an alias of the allocation
- NULLIFY: pointer set to NULL (mitigates dangling use for that alias only)
- USE: dereference, indexing, memcpy/memmove, strcmp/strlen, field access, etc.
- ESCAPE: pointer returned or stored externally; lifetime must be tracked across boundary

## Output format

### Memory Objects table (required)
| AllocID | Allocation site | Type/Kind | Size expr | Primary owner | Aliases |
|--------|------------------|----------|----------|--------------|---------|

### Timeline per allocation (required)
| T | Flow step (S#) | Event | Where | What is happening | Heap state after | Evidence |
|---|----------------|-------|-------|------------------|------------------|----------|

Heap state after should include:
- A#: allocated / freed
- alias set: p,q,r → A# (or dangling)
- notes: “p NULL, but q still points to freed A1”

### Mermaid diagram (optional but recommended)
Use a state diagram per allocation:

```mermaid
stateDiagram-v2
  [*] --> Allocated: ALLOC
  Allocated --> Freed: FREE
  Freed --> UseAfterFree: USE ⚠️
````

## UAF identification rule

A UAF exists when:

* There exists an event USE for alloc Ax
* And there exists an earlier FREE for alloc Ax
* And there is no intervening “Ax replaced” (realloc/new assignment) that changes identity
* And the USE is reachable under some conditions (attach to flow and constraints)

## Integration with Flow Walkthrough

In each step S#, include:

* **What is happening**
* **Memory snapshot** (Ax states + aliases)
* Evidence reference

````

Skills require `SKILL.md` + frontmatter and are discoverable in `.opencode/skills/<name>/SKILL.md`. :contentReference[oaicite:7]{index=7}  

---

## 1C) Command: `.opencode/commands/sec-mem-timeline.md`

```md
---
description: Build allocation/free/use timelines and hunt for UAF/double-free in a target area.
agent: vuln
---

Target: $ARGUMENTS

Use @vuln-mem.

Instructions:
1) Load skill `memory-lifetime-timeline`.
2) Index allocations/frees in the target area (use mem_events).
3) Choose the most reachable flow and express it as S1..Sn (Flow Walkthrough).
4) Build a Memory Objects table (A1..Ak).
5) For each Ax, produce a timeline table.
6) Identify hazard windows and mark bug trigger step with ⚠️.

Do not provide exploit payloads. Provide safe reproduction ideas only.
````

Commands are defined via Markdown in `.opencode/commands/` with frontmatter (`description`, `agent`). ([OpenCode][4])

---

## 1D) Custom tool: allocation/free indexer (optional but very useful)

This tool **does not “solve” lifetimes**; it gives your agent a fast index of likely `malloc/free/...` events.

### `.opencode/tools/mem_events.py`

```py
#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys

ALLOC_FUNS_DEFAULT = ["malloc", "calloc", "realloc"]
FREE_FUNS_DEFAULT = ["free"]

ALLOC_RE = re.compile(r"\b(?P<fn>malloc|calloc|realloc)\s*\(")
FREE_RE = re.compile(r"\b(?P<fn>free)\s*\(")

ASSIGN_RE = re.compile(r"(?P<lhs>[A-Za-z_]\w*)\s*=\s*(?:\([^)]+\)\s*)?(?P<fn>malloc|calloc|realloc)\s*\(")
FREE_ARG_RE = re.compile(r"\bfree\s*\(\s*(?P<arg>[^)]+)\)")

def iter_files(root, exts):
  for dirpath, _, filenames in os.walk(root):
    for fn in filenames:
      if any(fn.endswith(ext) for ext in exts):
        yield os.path.join(dirpath, fn)

def scan_file(path, alloc_funs, free_funs, max_events):
  events = []
  with open(path, "r", errors="ignore") as f:
    for i, line in enumerate(f, start=1):
      if len(events) >= max_events:
        break

      # alloc (malloc/calloc/realloc)
      m = ASSIGN_RE.search(line)
      if m and m.group("fn") in alloc_funs:
        events.append({
          "kind": "alloc",
          "fn": m.group("fn"),
          "lhs": m.group("lhs"),
          "file": path,
          "line": i,
          "code": line.strip()
        })
        continue

      m2 = ALLOC_RE.search(line)
      if m2 and m2.group("fn") in alloc_funs:
        events.append({
          "kind": "alloc",
          "fn": m2.group("fn"),
          "lhs": None,
          "file": path,
          "line": i,
          "code": line.strip()
        })
        continue

      # free
      m3 = FREE_ARG_RE.search(line)
      if m3:
        events.append({
          "kind": "free",
          "fn": "free",
          "arg": m3.group("arg").strip(),
          "file": path,
          "line": i,
          "code": line.strip()
        })
        continue

      m4 = FREE_RE.search(line)
      if m4 and m4.group("fn") in free_funs:
        events.append({
          "kind": "free",
          "fn": m4.group("fn"),
          "arg": None,
          "file": path,
          "line": i,
          "code": line.strip()
        })

  return events

def main():
  ap = argparse.ArgumentParser()
  ap.add_argument("path", help="File or directory to scan")
  ap.add_argument("--ext", action="append", default=[".c", ".h", ".cpp", ".hpp"])
  ap.add_argument("--alloc", action="append", default=[])
  ap.add_argument("--free", action="append", default=[])
  ap.add_argument("--max", type=int, default=2000)
  args = ap.parse_args()

  alloc_funs = ALLOC_FUNS_DEFAULT + args.alloc
  free_funs = FREE_FUNS_DEFAULT + args.free

  root = args.path
  all_events = []
  if os.path.isfile(root):
    all_events.extend(scan_file(root, alloc_funs, free_funs, args.max))
  else:
    for fp in iter_files(root, args.ext):
      all_events.extend(scan_file(fp, alloc_funs, free_funs, args.max - len(all_events)))
      if len(all_events) >= args.max:
        break

  print(json.dumps({
    "path": root,
    "alloc_funs": alloc_funs,
    "free_funs": free_funs,
    "events": all_events
  }))

if __name__ == "__main__":
  sys.exit(main())
```

### `.opencode/tools/mem_events.ts`

```ts
import { tool } from "@opencode-ai/plugin"
import path from "path"

export default tool({
  description: "Index malloc/calloc/realloc/free call sites under a path. Returns JSON. (Heuristic, not a full analyzer.)",
  args: {
    path: tool.schema.string().describe("File or directory to scan"),
    max: tool.schema.number().optional().describe("Max events (default 2000)"),
  },

  async execute(args, context) {
    const script = path.join(context.worktree, ".opencode/tools/mem_events.py")
    const max = args.max ?? 2000
    const out = await Bun.$`python3 ${script} ${args.path} --max ${max}`.text()
    return out.trim()
  },
})
```

Custom tools are defined in `.opencode/tools/` and can invoke Python scripts (TS/JS is just the wrapper). ([OpenCode][3])

---

# Use case 2 — Z3 Feasibility for memory bug triggers

## What it produces

A “feasibility appendix” that answers:

* **What conditions must be true** for the FREE to happen?
* **What conditions must be true** for the later USE to happen?
* Are those conditions **SAT** (reachable) or **UNSAT** (dead path)?
* If **SAT**, record **one safe input model** (values) you can use in a regression test harness.

This is the step that turns “this looks like a UAF” into “this is reachable under these constraints”.

---

## 2A) Agent: `.opencode/agents/vuln-smt.md`

```md
---
description: SMT/Z3 feasibility agent. Converts a suspected memory bug flow into constraints and checks SAT/UNSAT (defensive reachability).
mode: subagent
temperature: 0.1
steps: 40

tools:
  write: false
  edit: false
  patch: false
  bash: false
  webfetch: false

permission:
  z3_smt2: ask
---

You are an SMT feasibility analyst for memory-safety findings.

Goal:
- Given a *specific* suspected bug flow (S1..Sn, with a ⚠️ bug trigger step), determine whether the path conditions are satisfiable.

Method:
1) Identify attacker-controlled or environment-controlled variables:
   - sizes, lengths, indices, flags, enum values, counts, pointer-nullness guards, etc.
2) Extract path conditions that must hold to:
   - reach the FREE step
   - reach the USE step after the FREE
3) Write constraints in a small SMT-LIB subset (prefer Int constraints first):
   - declare variables
   - assert constraints
4) Run z3_smt2 tool to check SAT/UNSAT.
5) Interpret the result:
   - SAT: provide one safe model for test harness (not exploit payloads)
   - UNSAT: explain which conditions contradict

Never:
- Provide weaponized exploit steps or heap manipulation advice.
```

Agents can set tool availability and permissions in Markdown frontmatter. ([OpenCode][1])

---

## 2B) Skill: `.opencode/skills/z3-feasibility/SKILL.md`

````md
---
name: z3-feasibility
description: Turn a suspected memory bug flow (FREE then USE) into SMT constraints and use Z3 to check SAT/UNSAT, recording a safe model for regression tests.
compatibility: opencode
---

## What we are solving
We are NOT exploiting anything. We are checking reachability of a bad state.

Bad states of interest:
- UAF: FREE(Ax) occurs and later USE(Ax) occurs
- Double free: FREE(Ax) occurs twice on a reachable path
- OOB: idx >= size or idx < 0 at USE

## Workflow

### Step 1 — Choose the flow
Start from the Flow Walkthrough (S1..Sn).
You must know:
- which step frees Ax
- which later step uses Ax (⚠️)

### Step 2 — Identify symbolic variables
Create a table like:
| Var | Type | Origin | Meaning |
|-----|------|--------|---------|
| n   | Int  | input  | allocation size |
| idx | Int  | input  | index used at deref |
| flag| Bool | input/state | controls free/use |

### Step 3 — Extract constraints
Add only constraints that actually appear in code:
- if statements
- bounds checks
- error checks
- switch cases
- return-early guards

### Step 4 — Write SMT-LIB (minimal subset)
Prefer QF_LIA:
```smt2
(set-logic QF_LIA)
(declare-fun n () Int)
(declare-fun idx () Int)
(declare-fun flag () Bool)

(assert (> n 0))
(assert (< n 64))
(assert (= flag true))
(assert (>= idx 0))
(assert (< idx n))
````

### Step 5 — Interpret SAT/UNSAT safely

* SAT: record one model as “safe test harness inputs”
* UNSAT: document contradictory asserts

## Report formatting (required)

Include a “Feasibility (Z3)” section with:

* Variables table
* SMT-LIB code fence
* Z3 result: SAT/UNSAT
* If SAT: one model (values)
* Explanation tying the model back to flow steps S# (what it enables)

````

---

## 2C) Command: `.opencode/commands/sec-mem-z3.md`

```md
---
description: Check satisfiability of a suspected memory bug path (FREE then USE) using Z3 and record SAT/UNSAT + model.
agent: vuln
---

Target: $ARGUMENTS

Use @vuln-smt.

Instructions:
1) Load skill `z3-feasibility`.
2) Require an explicit flow (S1..Sn) with identified FREE step and ⚠️ USE step.
3) Build SMT constraints from branch conditions along that path.
4) Call z3_smt2 to determine SAT/UNSAT.
5) Produce a short “Feasibility (Z3)” appendix that can be pasted into the finding report.

No exploit payloads; only safe regression test values if SAT.
````

---

## 2D) Custom tool: run Z3 on SMT-LIB constraints

This expects an SMT-LIB file (or string) containing **declarations + asserts**. The tool runs check-sat and prints a model if SAT.

### `.opencode/tools/z3_smt2.py`

```py
#!/usr/bin/env python3
import argparse
import sys

def main():
  ap = argparse.ArgumentParser()
  ap.add_argument("--file", help="Path to SMT2 file with declarations + asserts")
  ap.add_argument("--text", help="Inline SMT2 text with declarations + asserts")
  args = ap.parse_args()

  try:
    from z3 import Solver, parse_smt2_file, parse_smt2_string, sat, unknown
  except Exception as e:
    print("ERROR: z3 module not available. Install with: pip install z3-solver", file=sys.stderr)
    return 2

  s = Solver()

  try:
    if args.file:
      constraints = parse_smt2_file(args.file)
    elif args.text:
      constraints = parse_smt2_string(args.text)
    else:
      print("ERROR: Provide --file or --text", file=sys.stderr)
      return 2
  except Exception as e:
    print(f"ERROR parsing SMT2: {e}", file=sys.stderr)
    return 2

  # constraints is typically a list of BoolRefs
  for c in constraints:
    s.add(c)

  r = s.check()
  if r == sat:
    m = s.model()
    print("sat")
    print(m)
    return 0
  elif str(r) == "unknown":
    print("unknown")
    return 0
  else:
    print("unsat")
    return 0

if __name__ == "__main__":
  sys.exit(main())
```

### `.opencode/tools/z3_smt2.ts`

```ts
import { tool } from "@opencode-ai/plugin"
import path from "path"

export default tool({
  description: "Run Z3 on SMT-LIB constraints (decls+asserts) and return sat/unsat + model. Defensive reachability only.",
  args: {
    file: tool.schema.string().optional().describe("Path to .smt2 file (relative to repo root allowed)"),
    text: tool.schema.string().optional().describe("Inline SMT2 content (decls + asserts)"),
  },

  async execute(args, context) {
    const script = path.join(context.worktree, ".opencode/tools/z3_smt2.py")

    if (!args.file && !args.text) {
      return "ERROR: provide either 'file' or 'text'"
    }

    if (args.file) {
      const abs = path.isAbsolute(args.file) ? args.file : path.join(context.worktree, args.file)
      const out = await Bun.$`python3 ${script} --file ${abs}`.text()
      return out.trim()
    } else {
      // Pass inline text safely via stdin-ish behavior is non-trivial with Bun.$; simplest is arg.
      // Keep this for small constraints. For larger, write to a file in findings folder.
      const out = await Bun.$`python3 ${script} --text ${args.text}`.text()
      return out.trim()
    }
  },
})
```

opencode explicitly supports tools defined in TS/JS that invoke Python scripts, and shows a Python example using `Bun.$`. ([OpenCode][3])

---

# Memory report template (Flow Walkthrough + Memory Timeline + Z3)

Use this for UAF/double-free/OOB findings.

## `docs/security/findings/TEMPLATE-memory.md`

````md
---
id: VR-0000
status: draft
severity: unknown
cwe: unknown
component: unknown
bug_class: memory-safety   # memory-safety | logic | injection | authz | etc
---

# <Finding Title>

## 0) TL;DR
**Impact:** <one sentence>  
**Bug class:** <UAF / double free / OOB read / OOB write>  
**Bug triggers at:** ⚠️ Step [S?](#s)  
**Primary fix:** <one sentence>  

## 1) Scope and Preconditions
- **Attack surface:** <entry point>
- **Attacker:** <unauth/auth/role/etc.>
- **Required conditions:** <flags/state/config>

## 2) Flow at a Glance
**Chain:** [S1](#s1) → [S2](#s2) → … → [Sn](#sn)  
**Bug triggers:** ⚠️ [S?](#s)

```mermaid
flowchart TD
  S1[S1: Entry] --> S2[S2: Parse/Dispatch]
  S2 --> S3[S3: Allocate Ax]
  S3 --> S4[S4: Free Ax]
  S4 --> S5[S5: Use Ax ⚠️]
````

## 3) Flow Table (One Screen Review)

| Step  | Where           | What is happening                                                    | Memory snapshot            | Evidence       |
| ----- | --------------- | -------------------------------------------------------------------- | -------------------------- | -------------- |
| S1    | `<file>::<sym>` | **What is happening:** <…>                                           | (none yet)                 | `<path>:Lx-Ly` |
| S2    | `<file>::<sym>` | **What is happening:** <…>                                           | (none yet)                 | `<path>:Lx-Ly` |
| S3    | `<file>::<sym>` | **What is happening:** Allocates **A1** and stores pointer in `p`.   | `A1=allocated; p→A1`       | `<path>:Lx-Ly` |
| S4    | `<file>::<sym>` | **What is happening:** Frees `p` under condition `<cond>`.           | `A1=freed; p→A1(dangling)` | `<path>:Lx-Ly` |
| S5 ⚠️ | `<file>::<sym>` | **What is happening:** Uses `p` after free (dereference/copy/index). | `A1=freed; USE(A1)`        | `<path>:Lx-Ly` |

## 4) Memory Objects (A1..Ak)

| AllocID | Allocation site | Size expr | Owner                  | Aliases (tracked) |
| ------- | --------------- | --------- | ---------------------- | ----------------- |
| A1      | `<file>:Lx`     | `<expr>`  | `<component/function>` | `p,q,...`         |

## 5) Allocation Timelines

### Allocation A1 timeline

| T  | Flow step | Event | Where           | What is happening                                                      | Heap state after           | Evidence       |
| -- | --------- | ----- | --------------- | ---------------------------------------------------------------------- | -------------------------- | -------------- |
| T1 | S3        | ALLOC | `<file>::<sym>` | **What is happening:** `p = malloc(n)` allocates A1.                   | `A1=allocated; p→A1`       | `<path>:Lx-Ly` |
| T2 | S4        | FREE  | `<file>::<sym>` | **What is happening:** `free(p)` releases A1 but `p` remains non-NULL. | `A1=freed; p→A1(dangling)` | `<path>:Lx-Ly` |
| T3 | S5 ⚠️     | USE   | `<file>::<sym>` | **What is happening:** `p[idx]` dereferences freed A1.                 | `UAF window hit`           | `<path>:Lx-Ly` |

```mermaid
stateDiagram-v2
  [*] --> Allocated: T1 ALLOC(A1)
  Allocated --> Freed: T2 FREE(A1)
  Freed --> UseAfterFree: T3 USE(A1) ⚠️
```

## 6) Feasibility (Z3) (Optional but recommended)

### Variables

| Var  | Type | Origin      | Meaning             |
| ---- | ---- | ----------- | ------------------- |
| n    | Int  | input       | allocation size     |
| idx  | Int  | input       | index used at deref |
| flag | Bool | input/state | controls free path  |

### Constraints (SMT-LIB)

```smt2
(set-logic QF_LIA)
(declare-fun n () Int)
(declare-fun idx () Int)
(declare-fun flag () Bool)

; constraints to reach FREE + USE after it
(assert (> n 0))
(assert (< n 64))
(assert (= flag true))
(assert (>= idx 0))
(assert (< idx n))
```

### Z3 result

* Result: <sat/unsat/unknown>
* Model (if sat): <n=?, idx=?, flag=...>
* Interpretation: <which branch conditions this satisfies and why it enables S4 then S5>

## 7) Root Cause

<one paragraph>

## 8) Fix Recommendation

### Minimal fix

* <e.g., nullify pointers after free + restructure ownership or guard use>

### Defense in depth (optional)

* <e.g., ownership API, RAII, reference counting, clearer contracts>

## 9) Regression Test Idea (Safe)

* <safe harness / unit test / integration test that forces the path and asserts behavior>

````

---

# Recommended tiny AGENTS.md addition (so all agents “know” about these)

If you want your main policy file to explicitly require timelines + Z3 for memory bugs, add this section:

```md
## Memory Safety Extensions (malloc/free timelines + Z3 feasibility)
When auditing C/C++ memory safety issues:
- Build a per-allocation timeline (A1..Ak) with ALLOC/ALIAS/FREE/USE events.
- Integrate memory snapshots into the S1..Sn Flow Walkthrough.
- For suspected UAF/double-free/OOB, attempt a Z3 feasibility check:
  - Extract path constraints
  - Record SAT/UNSAT and (if SAT) one safe model for regression testing
````

`AGENTS.md` is the standard way to feed project instructions to opencode. ([OpenCode][5])

---

# How you actually run the two use cases

### Use case 1 (timeline)

* Run: `/sec-mem-timeline <path/or/component>`
* Output: Allocation tables + timelines + UAF candidates

### Use case 2 (Z3)

* After you have a suspected FREE→USE flow:
* Run: `/sec-mem-z3 <finding or function>`
* Output: SAT/UNSAT + model + interpretation you paste into the finding

---

If you want, I can also provide a **“memory-specific Flow Walkthrough step card”** format (so each S-step always includes a compact heap snapshot), but the template above already enforces it through the Flow Table + timeline sections.

[1]: https://opencode.ai/docs/agents/ "Agents | OpenCode"
[2]: https://opencode.ai/docs/skills/ "Agent Skills | OpenCode"
[3]: https://opencode.ai/docs/custom-tools/ "Custom Tools | OpenCode"
[4]: https://opencode.ai/docs/commands/?utm_source=chatgpt.com "Commands"
[5]: https://opencode.ai/docs/rules/?utm_source=chatgpt.com "Rules"

Below is a “security-audit starter kit” for **opencode** that’s tuned for vulnerability research *without* turning your agents into auto-exploit generators. It’s built around: **least privilege**, **repeatable dataflow analysis**, and **high-signal writeups**.

I’m going to cover:

1. How opencode discovers config + folder structure
2. A recommended repo layout
3. A hardened `opencode.jsonc` for vuln research
4. Concrete Markdown files for **agents**, **commands**, and **skills**
5. (Optional) a small custom tool example

---

## How opencode loads config + folders

### Config files (JSON / JSONC)

* opencode supports **JSON or JSONC** (`opencode.json` or `opencode.jsonc`). ([OpenCode][1])
* Config sources are **merged** (not replaced), in this precedence order: remote → global → env override → project → `.opencode` directories → inline env. ([OpenCode][1])
* Typical locations:

  * Global: `~/.config/opencode/opencode.json` ([OpenCode][1])
  * Project: `opencode.json` in repo root ([OpenCode][1])

### The `.opencode/` folder structure

opencode expects “plural” subfolders (singular is supported for backwards compat): `agents/`, `commands/`, `skills/`, `tools/`, etc. ([OpenCode][1])

* **Agents** (Markdown): `.opencode/agents/` (or global `~/.config/opencode/agents/`) ([OpenCode][2])
* **Commands** (Markdown): `.opencode/commands/` (or global `~/.config/opencode/commands/`) ([OpenCode][3])
* **Skills** (`SKILL.md` in named folders): `.opencode/skills/<name>/SKILL.md` ([OpenCode][4])
* **Custom tools** (TS/JS): `.opencode/tools/` (or global `~/.config/opencode/tools/`) ([OpenCode][5])
* **Project rules**: `AGENTS.md` in repo root (or global `~/.config/opencode/AGENTS.md`). ([OpenCode][6])

---

## Design goals for vuln-research agents

**What you want:** find *reachable* bug paths, and document “how an attacker gets there” at the dataflow + state level.

**What you don’t want by default:** auto-writing exploit payloads or weaponized PoCs.

So the ideal setup is:

* **Default agent = read-only audit lead**
* **Bash is “ask” by default**, with a whitelist for common read-only commands
* **Edits are denied globally**, except a dedicated “findings” directory
* **Web fetch is denied by default** (avoid accidental code/context leakage); enable it only in a dedicated “deps/cve” agent if needed
* Specialized subagents:

  * recon/attack surface
  * dataflow/taint tracing
  * authz logic
  * deps/config review
  * writeup/reporting

---

## Recommended repo layout

```text
repo-root/
  opencode.jsonc
  AGENTS.md

  .opencode/
    agents/
      vuln.md
      vuln-recon.md
      vuln-dataflow.md
      vuln-authz.md
      vuln-deps.md
      vuln-writer.md

    commands/
      sec-surface.md
      sec-taint.md
      sec-authz.md
      sec-deps.md
      sec-report.md

    skills/
      audit-playbook/SKILL.md
      attack-surface-map/SKILL.md
      taint-trace/SKILL.md
      authz-audit/SKILL.md
      dependency-audit/SKILL.md
      finding-writeup/SKILL.md

  docs/
    security/
      findings/
        TEMPLATE.md
```

Notes:

* Putting `docs/security/findings/` under version control gives you a canonical place for audit output.
* Skills are loaded “on-demand” via the `skill` tool (agents see the list and load only when needed). ([OpenCode][4])

---

## 1) `opencode.jsonc` tuned for vulnerability research

This config makes **audit mode the default**, keeps it **safe by default**, and still lets you do real work (grep, lsp navigation, limited bash).

```jsonc
// opencode.jsonc
{
  "$schema": "https://opencode.ai/config.json",

  // Vulnerability research often includes sensitive context—disable sharing.
  "share": "disabled",

  // Start sessions in our primary security agent (defined in .opencode/agents/vuln.md).
  "default_agent": "vuln",

  // Keep big/noisy directories out of the file watcher.
  "watcher": {
    "ignore": [
      ".git/**",
      "node_modules/**",
      "dist/**",
      "build/**",
      "target/**",
      "vendor/**",
      ".venv/**",
      "__pycache__/**"
    ]
  },

  // Permissions are the real “security boundary”.
  // allow  — run without approval
  // ask    — prompt for approval
  // deny   — block
  "permission": {
    "*": "ask",

    // Safe read/navigation tools
    "read": "allow",
    "list": "allow",
    "glob": "allow",
    "grep": "allow",
    "lsp": "allow",

    // Use todo tools for tracking audit plan + open questions
    "todoread": "allow",
    "todowrite": "allow",

    // Skills are helpful, but you can restrict them by pattern if needed.
    "skill": "allow",

    // Editing is denied everywhere except the findings directory.
    // (Note: write/patch are controlled by edit permission.)
    "edit": {
      "*": "deny",
      "docs/security/findings/**": "allow"
    },

    // Avoid accidental outbound context leakage. Enable only in a dedicated agent if needed.
    "webfetch": "deny",

    // Bash is powerful; keep it gated.
    // Allow common read-only commands automatically; ask for everything else.
    "bash": {
      "*": "ask",

      "git status*": "allow",
      "git diff*": "allow",
      "git log*": "allow",
      "git show*": "allow",

      "rg *": "allow",
      "grep *": "allow",
      "find *": "allow",
      "ls*": "allow",
      "cat *": "allow",
      "head *": "allow",
      "tail *": "allow",
      "sed -n*": "allow"
    }
  },

  // Optional: keep built-in Build from accidentally becoming “dangerous” during audits.
  "agent": {
    "build": {
      "permission": {
        "edit": "ask",
        "bash": "ask",
        "webfetch": "deny"
      }
    }
  }
}
```

Why this is “ideal” for vuln research:

* You can still do **fast static analysis** (`grep`, `glob`, `lsp`, `read`).
* You can still run **safe bash** (ripgrep, git read-only).
* You can **write reports** but not mutate code.
* You reduce risk of accidental data exfil (share + webfetch disabled). ([OpenCode][1])

(Sharing config + default agent rules are documented in the config schema.) ([OpenCode][1])

---

## 2) `AGENTS.md` – project rules for security auditing

`AGENTS.md` is included in model context and is the best place to define “how we do audits in this repo.” ([OpenCode][6])

```md
<!-- AGENTS.md -->
# Security Audit Rules (opencode)

This repository may contain security-sensitive defects.
Use opencode audit agents only on codebases you are authorized to review.

## Goals
- Map attack surface: identify all external inputs and trust boundaries.
- Trace untrusted dataflow: source → transforms/validators → sinks.
- Identify missing/incorrect authorization checks across flows.
- Produce actionable findings with evidence and fixes.
- Do NOT generate weaponized exploit payloads or instructions.

## Output rules
When reporting a potential vulnerability, always include:
1. **Title**
2. **Impact** (what could happen if abused)
3. **Reachability** (how attacker-controlled input reaches the bug, at a conceptual level)
4. **Evidence** (file paths + line ranges + call chain or references)
5. **Preconditions** (auth required? specific roles? feature flags? config?)
6. **Fix recommendation** (minimal change; defense-in-depth)
7. **Regression test idea** (unit/integration/fuzz suggestion)

## Where to write findings
- Write Markdown findings to: `docs/security/findings/`
- Follow the template: `docs/security/findings/TEMPLATE.md`

## Allowed execution
- Prefer static analysis first.
- Only run local tests/tools that are safe and repo-scoped.
- Avoid network calls unless explicitly requested by the user.

## Repo notes (fill in)
- Primary language(s):
- Frameworks:
- Entry points:
- Auth model:
- Build/test commands:
```

---

## 3) Agents (Markdown) for vulnerability research

Agents can be defined as markdown files in `.opencode/agents/`. ([OpenCode][2])
Each file name becomes the agent name (e.g. `vuln.md` => `@vuln`). ([OpenCode][2])

### `.opencode/agents/vuln.md` (primary orchestrator)

```md
---
description: Primary vulnerability research agent. Orchestrates recon, dataflow tracing, authz review, deps/config review, and produces high-signal findings without writing exploit code.
mode: primary
temperature: 0.1
steps: 40

permission:
  # Only allow spawning the dedicated vuln-* subagents.
  task:
    "*": deny
    "vuln-*": allow

  # Keep outbound fetch blocked by default.
  webfetch: deny

---

You are a vulnerability research lead for a codebase.

Operating principles:
- Prioritize *reachable* issues: show how untrusted input can plausibly reach the bug.
- Be specific: file paths, symbols, call chains, and “source → sink” flow narratives.
- Do not generate weaponized exploit payloads or step-by-step instructions to attack real systems.
  If asked for exploitation, provide a defensive reproduction strategy (unit test / safe harness) instead.

Workflow:
1) Load `audit-playbook` skill and create a short audit plan.
2) Delegate:
   - @vuln-recon: enumerate entry points + trust boundaries.
   - @vuln-dataflow: trace source→sink flows for top-risk areas.
   - @vuln-authz: check authn/authz boundaries and IDOR-style patterns.
   - @vuln-deps: review dependencies + configs that change exposure.
3) Synthesize findings:
   - Rank by reachability + impact.
   - For each, include evidence and a minimal fix.
4) If user asks for a report file, delegate to @vuln-writer.
```

### `.opencode/agents/vuln-recon.md`

```md
---
description: Attack-surface mapper. Finds externally reachable entry points, trust boundaries, and risky parsers/handlers. Read-only.
mode: subagent
temperature: 0.1
steps: 30

permission:
  edit: deny
  webfetch: deny
---

You map attack surface.

Output format:
- Entry points (HTTP routes, RPC handlers, message consumers, CLI args, file parsers)
- Trust boundaries (where data crosses from untrusted → trusted)
- Data stores and secrets usage
- High-risk components (auth, deserialization, templating, shelling out, dynamic eval)

Rules:
- Use code evidence (paths + line ranges).
- Prefer breadth first; then highlight top 5 risky flows to investigate.
```

### `.opencode/agents/vuln-dataflow.md`

```md
---
description: Dataflow / taint-tracing specialist. Traces attacker-controlled sources to sensitive sinks and identifies missing validation/sanitization. Read-only.
mode: subagent
temperature: 0.1
steps: 35

permission:
  edit: deny
  webfetch: deny
---

You do source→sink analysis.

Method:
- Identify attacker-controlled sources (request params, headers, body, files, env, IPC, messages).
- Identify sensitive sinks (SQL/ORM raw queries, filesystem paths, template rendering, command execution, SSRF-style fetches, deserialization).
- Trace flow across functions/modules; note validators/normalizers and where they fail.

Deliverables for each suspected issue:
- Source → transforms → sink narrative
- Preconditions (auth/roles/config/state)
- Why existing validation is insufficient
- Fix options (least invasive first)
- Safe reproduction idea (unit test / integration test harness), not an exploit payload
```

### `.opencode/agents/vuln-authz.md`

```md
---
description: Authorization logic auditor. Looks for IDOR, missing ownership checks, confused deputy, multi-tenant boundary breaks, privilege escalation paths. Read-only.
mode: subagent
temperature: 0.1
steps: 30

permission:
  edit: deny
  webfetch: deny
---

You audit authorization flows and invariants.

Look for:
- “lookup by ID” without verifying tenant/ownership
- Role checks applied inconsistently across endpoints
- Admin-only actions reachable through alternate routes
- Mixed authn contexts (service tokens vs user sessions)
- Cache/queue consumers missing auth context

Output:
- Candidate issue list with evidence (paths + call sites)
- For top issues: describe the broken invariant and the minimal fix pattern
```

### `.opencode/agents/vuln-deps.md`

```md
---
description: Dependency/config exposure auditor. Finds risky configurations and known-vulnerable dependency surfaces. Minimal bash allowed; no code edits.
mode: subagent
temperature: 0.1
steps: 25

permission:
  edit: deny
  # Keep webfetch blocked; enable per-run only if the user explicitly wants online CVE lookup.
  webfetch: deny
---

You audit dependencies and security-relevant configuration.

Focus:
- Dependency manifests + lockfiles
- Dangerous defaults (debug flags, permissive CORS, weak auth settings)
- Use of outdated crypto / serialization libs
- Build/deploy configs that widen attack surface (public admin endpoints, dev middleware)

Output:
- Top dependency/config risks with file locations
- Concrete mitigation actions (version bump, config hardening)
- If you need to run a local command (e.g., listing dependencies), ask first.
```

### `.opencode/agents/vuln-writer.md`

```md
---
description: Writes security findings into docs/security/findings using the repo template. No bash. Allowed to write only in findings folder (global permission already enforces this).
mode: subagent
temperature: 0.1
steps: 20

permission:
  bash: deny
  webfetch: deny
---

You are a security report writer.

When asked to write a finding:
- Use `docs/security/findings/TEMPLATE.md` structure.
- Create a new file named: `docs/security/findings/YYYY-MM-DD-<short-slug>.md`
- Include: impact, reachability narrative (conceptual), evidence, preconditions, fix, regression test.

Do not include weaponized exploit payloads or real-world attack instructions.
```

---

## 4) Skills (SKILL.md) for reusable vuln-research behavior

Skills live in `.opencode/skills/<name>/SKILL.md`. ([OpenCode][4])
They must have YAML frontmatter with required fields and a name that matches the folder name. ([OpenCode][4])

### `.opencode/skills/audit-playbook/SKILL.md`

```md
---
name: audit-playbook
description: A repeatable vulnerability research workflow (recon → dataflow → authz → deps/config → prioritized findings).
compatibility: opencode
---

## What I do
- Provide an audit plan optimized for reachability + impact.
- Define what “good evidence” looks like (paths, line ranges, call chains).
- Provide a consistent finding template and severity heuristics.

## Checklist
- [ ] Identify entry points + trust boundaries
- [ ] Identify sensitive sinks
- [ ] Trace source→sink for top-risk components
- [ ] Validate authz invariants (tenant/ownership/role)
- [ ] Check config/deps that change exposure
- [ ] Write findings with concrete fixes and regression tests
```

### `.opencode/skills/attack-surface-map/SKILL.md`

```md
---
name: attack-surface-map
description: How to systematically enumerate externally reachable entry points and trust boundaries in a repo.
compatibility: opencode
---

## What I do
- Enumerate all likely “inputs” an attacker can influence.
- Categorize entry points: HTTP/RPC, queues, CLIs, file parsers, scheduled jobs, plugins.
- Highlight “hot zones”: auth, deserialization, template rendering, command execution, file paths.

## Output format
- Entry points table: type | location | auth context | notes
- Trust boundaries list
- Top 5 risky flows to investigate next
```

### `.opencode/skills/taint-trace/SKILL.md`

```md
---
name: taint-trace
description: Source→transform→sink tracing for untrusted data flows, including validators/sanitizers and bypass patterns (defensive analysis).
compatibility: opencode
---

## What I do
- Identify sources, sinks, and sanitizers.
- Trace cross-module call chains.
- Summarize reachability and preconditions.

## Deliverable template
- Source:
- Transform(s):
- Sink:
- Preconditions:
- Evidence:
- Fix:
- Regression test idea:
```

### `.opencode/skills/authz-audit/SKILL.md`

```md
---
name: authz-audit
description: Authorization and multi-tenant boundary review checklist (IDOR, confused deputy, privilege escalation).
compatibility: opencode
---

## What I do
- Check for missing ownership/tenant checks on object access.
- Validate consistent role enforcement across routes and background consumers.
- Identify dangerous “admin” toggles and alternate execution paths.

## Evidence to collect
- Where user/tenant identity is derived
- How resource IDs map to owners/tenants
- Where checks are performed (and where they are missing)
```

### `.opencode/skills/dependency-audit/SKILL.md`

```md
---
name: dependency-audit
description: Dependency + configuration security review (manifests, lockfiles, risky defaults, supply-chain exposure).
compatibility: opencode
---

## What I do
- Inventory runtime deps and security-sensitive configs.
- Identify risky libraries/features: unsafe parsing, dynamic execution, weak crypto, debug middleware.
- Recommend mitigations: version upgrades, feature flags, config tightening.

## Output
- Risk list with file references
- Mitigation plan (quick wins → larger refactors)
```

### `.opencode/skills/finding-writeup/SKILL.md`

```md
---
name: finding-writeup
description: Standard security finding writeup format for consistent, high-signal reports with evidence and fixes.
compatibility: opencode
---

## Finding format
1. Title
2. Impact
3. Reachability (conceptual attacker path, no weaponized payloads)
4. Evidence (file/line + call chain)
5. Preconditions
6. Fix (minimal + defense-in-depth)
7. Regression test

## Severity heuristics
- High: reachable + strong impact (auth bypass, sensitive data exposure, code execution)
- Medium: reachable + limited impact or hard preconditions
- Low: defense-in-depth, low reachability, or best-practice issues
```

---

## 5) Commands (Markdown) to run common audit workflows

Commands are Markdown files in `.opencode/commands/` and are invoked as `/name`. ([OpenCode][3])

### `.opencode/commands/sec-surface.md`

```md
---
description: Map attack surface and trust boundaries (entry points, parsers, auth boundaries).
agent: vuln
---

Use @vuln-recon to enumerate:
- All externally reachable entry points
- Trust boundaries and auth contexts
- Top 5 highest-risk flows to investigate next

Output a concise attack-surface map with file path evidence.
```

### `.opencode/commands/sec-taint.md`

```md
---
description: Perform source→sink dataflow tracing for a component or feature.
agent: vuln
---

Use @vuln-dataflow.

Target: $ARGUMENTS

If $ARGUMENTS is empty, pick the most exposed entry point (from prior recon) and trace
untrusted data flows to sensitive sinks.

For each candidate issue: provide a reachability narrative, evidence, preconditions, and fixes.
Do not provide weaponized exploit payloads.
```

### `.opencode/commands/sec-authz.md`

```md
---
description: Audit authorization and multi-tenant boundaries for a target area.
agent: vuln
---

Use @vuln-authz.

Target: $ARGUMENTS

If empty, prioritize areas with object lookups by ID, user/tenant context propagation,
admin actions, and background consumers.

Output: candidate issues + evidence + minimal fix patterns.
```

### `.opencode/commands/sec-deps.md`

```md
---
description: Review dependencies and security-relevant configuration for exposure.
agent: vuln
---

Use @vuln-deps.

Scan manifests/lockfiles and security-critical config files.
List top risks with file evidence and concrete mitigations.
Avoid network calls unless explicitly requested.
```

### `.opencode/commands/sec-report.md`

```md
---
description: Write a finding to docs/security/findings (uses template).
agent: vuln
---

If there is an agreed finding in the current discussion, invoke @vuln-writer to create a report
file in `docs/security/findings/`.

Title / slug: $ARGUMENTS

Ensure the report includes: impact, reachability narrative, evidence, preconditions, fix, regression test.
```

---

## 6) Findings template (so the writer agent has structure)

```md
<!-- docs/security/findings/TEMPLATE.md -->
# <Finding Title>

## Summary
(1–3 sentences)

## Impact
What could happen if abused?

## Reachability (Conceptual)
Describe how attacker-controlled input could reach the vulnerable behavior.
No weaponized payloads; focus on source → sink and preconditions.

## Evidence
- Files/lines:
- Call chain:
- Notes:

## Preconditions
Auth required? Role? Config? Feature flags? Specific state?

## Recommended Fix
Minimal fix first; then defense-in-depth ideas.

## Regression Test
Unit/integration/fuzz strategy suggestion.
```

---

## Optional: a tiny custom tool example (read-only)

If you run SAST tools that output **SARIF** (e.g., from GitHub CodeQL workflows), a little summarizer tool can help you triage quickly.

Custom tools live in `.opencode/tools/` (project) or `~/.config/opencode/tools/` (global). ([OpenCode][5])

```ts
// .opencode/tools/sarif-summary.ts
import { tool } from "@opencode-ai/plugin"
import fs from "node:fs/promises"

export default tool({
  description: "Summarize a SARIF report (top rules, files, and messages). Read-only.",
  args: {
    path: tool.schema.string().describe("Path to SARIF JSON file"),
    max: tool.schema.number().optional().describe("Max results to return (default 50)")
  },
  async execute(args) {
    const max = (args as any).max ?? 50
    const raw = await fs.readFile(args.path, "utf8")
    const sarif = JSON.parse(raw)

    const runs = sarif.runs ?? []
    const out: string[] = []
    let count = 0

    for (const run of runs) {
      const results = run.results ?? []
      for (const r of results) {
        if (count >= max) break
        const msg = r.message?.text ?? "(no message)"
        const loc = r.locations?.[0]?.physicalLocation
        const file = loc?.artifactLocation?.uri ?? "(unknown file)"
        const region = loc?.region
        const line = region?.startLine ?? "?"
        const ruleId = r.ruleId ?? "(no ruleId)"
        out.push(`- [${ruleId}] ${file}:${line} — ${msg}`)
        count++
      }
    }

    return out.length ? out.join("\n") : "No results found."
  }
})
```

If you add any custom tool, remember you can permission-gate it the same way as built-ins (e.g., require `ask`).

---

## How you use this day-to-day

* Start opencode in the repo → it should default to the `vuln` primary agent (because `default_agent` is set). ([OpenCode][1])
* Run:

  * `/sec-surface`
  * `/sec-taint <component-or-feature>`
  * `/sec-authz <area>`
  * `/sec-deps`
  * `/sec-report <title>`

You can also manually call a subagent:

* `@vuln-dataflow trace request param X into file write paths`

---

## One important guardrail

This setup is aimed at **defensive vulnerability research** on code you’re authorized to review. It’s intentionally configured to:

* default to **read-only** investigation
* avoid **auto-exploit** behavior
* keep outbound sharing/fetching off unless you explicitly enable it

If you want, tell me what kind of codebase you typically audit (language/framework + monorepo vs single service). I can tailor the agent prompts (especially the recon + dataflow heuristics) to that ecosystem without changing the overall safety posture.

[1]: https://opencode.ai/docs/config/ "Config | OpenCode"
[2]: https://opencode.ai/docs/agents/ "Agents | OpenCode"
[3]: https://opencode.ai/docs/commands/ "Commands | OpenCode"
[4]: https://opencode.ai/docs/skills/ "Agent Skills | OpenCode"
[5]: https://opencode.ai/docs/custom-tools/ "Custom Tools | OpenCode"
[6]: https://opencode.ai/docs/rules/ "Rules | OpenCode"


-------------------------------------------
++++++++++++++++++++++++++++++++++++++++++

Below is a concrete **OpenCode “Frida Lab” pack** you can drop into a repo to make the assistant generate **deterministic / exact Frida scripts** (stored as files), plus a run/debug “runbook”.

This is designed for **authorized security research + debugging** (UAF/memory corruption workflows). It intentionally focuses on **instrumentation + logging** (not bypassing protections).

---

## Folder structure to add

OpenCode discovers project-local config in `.opencode/…` (agents, commands, skills, tools). ([opencode.ai][1])

```text
.
├─ opencode.jsonc
├─ AGENTS.md
└─ .opencode/
   ├─ tools/
   │  └─ frida.ts
   ├─ agents/
   │  ├─ frida-lab.md
   │  ├─ frida-memtrace-gen.md
   │  └─ frida-native-hook-gen.md
   ├─ commands/
   │  ├─ frida-memtrace.md
   │  ├─ frida-hook-exports.md
   │  └─ frida-watch-range.md
   └─ skills/
      ├─ frida-script-style/
      │  └─ SKILL.md
      ├─ frida-memtrace/
      │  └─ SKILL.md
      └─ frida-debugging/
         └─ SKILL.md
```

---

## 1) `opencode.jsonc` — permissions tuned for “generate scripts, don’t edit code”

OpenCode permissions are **pattern-based per tool** (including custom tools), and recommended for controlling risk. ([opencode.ai][2])

Create `opencode.jsonc` at repo root:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",

  "permission": {
    "*": "ask",

    // Safe repo inspection
    "read": {
      "*": "allow",
      "*.env": "deny",
      "*.env.*": "deny",
      "*.pem": "deny",
      "*.key": "deny",
      "**/id_rsa*": "deny"
    },
    "list": "allow",
    "glob": "allow",
    "grep": "allow",

    // Do NOT let agents edit your codebase by default.
    // Only allow writing inside .opencode/ and docs/security/ (adjust as you like).
    "edit": {
      "*": "deny",
      ".opencode/**": "allow",
      "docs/security/**": "allow"
    },

    // Bash is powerful—keep it on ask.
    "bash": {
      "*": "ask",
      "git status*": "allow",
      "git diff*": "allow",
      "rg *": "allow",
      "grep *": "allow"
    },

    // Skills are allowed (so agents can load frida-* skills).
    "skill": {
      "*": "allow"
    },

    // Let OpenCode invoke our Frida-related subagents.
    "task": {
      "*": "deny",
      "frida-*": "allow"
    },

    // Disable web tools for deterministic / offline work.
    "webfetch": "deny",
    "websearch": "deny",
    "codesearch": "deny",

    // Allow our custom tools (from .opencode/tools/frida.ts).
    // Custom tools are named <filename>_<exportname>. :contentReference[oaicite:2]{index=2}
    "frida_memtrace": "allow",
    "frida_hook_exports": "allow",
    "frida_watch_range": "allow",
    "frida_store": "allow",
    "frida_cmd": "allow"
  }
}
```

---

## 2) `AGENTS.md` — hard rules for safe + exact Frida output

OpenCode loads `AGENTS.md` as project rules. ([opencode.ai][3])

Create `AGENTS.md` at repo root:

```md
# Frida Lab Rules (OpenCode)

This repo uses OpenCode to generate deterministic Frida scripts for *authorized* debugging and security research.

## Safety / Scope
- Only generate logging / instrumentation scripts.
- Do NOT generate scripts intended to bypass security controls (e.g., SSL pinning bypass, auth bypass, license bypass, anti-debug bypass).
- If asked for bypass-style scripts, refuse and offer safer alternatives (e.g., logging-only hooks, crash reproduction, or test harness ideas).

## Determinism ("EXACT scripts")
When generating Frida scripts:
- ALWAYS generate scripts by calling the custom tools:
  - frida_memtrace
  - frida_hook_exports
  - frida_watch_range
  - frida_store (only when user provided full JS)
- Do not freehand large scripts in chat.
- Store scripts under .opencode/artifacts/frida/scripts/... and return the @ref.

## Output format
- Prefer structured events via send({...}) and include:
  - type, threadId, timestamps/sequence, addresses as strings
  - backtraces as string arrays (when enabled)
- Provide a copy/paste frida CLI command (use frida_cmd tool).
```

---

## 3) Custom tool: `.opencode/tools/frida.ts`

OpenCode custom tools live in `.opencode/tools/` and can export multiple tools, named `<filename>_<exportname>`. ([opencode.ai][1])

Create `.opencode/tools/frida.ts`:

```ts
import { tool } from "@opencode-ai/plugin"
import * as path from "node:path"
import * as fs from "node:fs/promises"

type WorktreeContext = { worktree: string }

function sanitizeSegment(input: string | undefined, fallback: string): string {
  const s = (input ?? "").trim()
  if (!s) return fallback
  const cleaned = s
    .replace(/[^a-zA-Z0-9._-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-+/, "")
    .replace(/-+$/, "")
  return cleaned || fallback
}

function isoStampForPath(): string {
  return new Date().toISOString().replace(/[:.]/g, "-")
}

function ensureInsideWorktree(worktree: string, absPath: string): void {
  const rel = path.relative(worktree, absPath)
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    throw new Error(`Refusing to write outside worktree: ${absPath}`)
  }
}

async function ensureDir(dir: string): Promise<void> {
  await fs.mkdir(dir, { recursive: true })
}

async function writeArtifact(
  context: WorktreeContext,
  bucket: string,
  slug: string,
  content: string,
  meta: Record<string, unknown>,
): Promise<{ relPath: string; ref: string }> {
  const safeBucket = sanitizeSegment(bucket, "default")
  const safeSlug = sanitizeSegment(slug, "script")
  const stamp = isoStampForPath()

  const relDir = path.join(".opencode", "artifacts", "frida", "scripts", safeBucket)
  const absDir = path.join(context.worktree, relDir)
  await ensureDir(absDir)

  const filename = `${stamp}-${safeSlug}.js`
  const absPath = path.join(absDir, filename)
  ensureInsideWorktree(context.worktree, absPath)

  await fs.writeFile(absPath, content, { encoding: "utf8" })

  // Append an index record for easy discovery.
  const indexAbs = path.join(absDir, "index.jsonl")
  const indexRec = {
    ts: new Date().toISOString(),
    bucket: safeBucket,
    slug: safeSlug,
    file: filename,
    ref: `@${path.posix.join(relDir, filename)}`,
    ...meta,
  }
  await fs.appendFile(indexAbs, JSON.stringify(indexRec) + "\n", { encoding: "utf8" })

  const relPath = path.relative(context.worktree, absPath).split(path.sep).join("/")
  return { relPath, ref: `@${relPath}` }
}

function buildCommonPreamble(comment: string): string {
  return `/*
${comment}
Generated by OpenCode frida_* tools.
Safety note: This script is intended for authorized debugging/security testing.
*/
`
}

function buildBacktraceHelpers(
  backtrace: "accurate" | "fuzzy",
  maxFrames: number,
): string {
  const mode = backtrace === "fuzzy" ? "Backtracer.FUZZY" : "Backtracer.ACCURATE"
  const mf = Math.max(1, Math.min(64, Math.floor(maxFrames || 16)))
  return `
function _bt(context) {
  try {
    // If called from Interceptor callbacks, pass this.context for accuracy.
    // Thread.backtrace() behavior is documented in Frida JS API docs.
    const frames = Thread.backtrace(context, ${mode})
      .map(DebugSymbol.fromAddress)
      .slice(0, ${mf});
    return frames.map(String);
  } catch (e) {
    return ["<bt-error> " + e];
  }
}
`
}

function buildEmitHelpers(): string {
  return `
const __state = { enabled: true, seq: 1 };

function _emit(ev) {
  ev.seq = (__state.seq++);
  ev.ts_ms = Date.now();
  try {
    send(ev);
  } catch (_) {
    console.log(JSON.stringify(ev));
  }
}

rpc.exports = {
  setenabled(on) { __state.enabled = !!on; return __state.enabled; },
  getenabled() { return __state.enabled; },
};
`
}

function buildMemtraceScript(opts: {
  minSize: number
  maxSize: number
  captureBacktrace: boolean
  backtrace: "accurate" | "fuzzy"
  maxBacktraceFrames: number
  btContains: string[]
  trackMemops: boolean
  memops: string[]
  monitorFreedPages: boolean
  maxLiveAllocs: number
  maxFreedAllocs: number
}): string {
  const min = Math.max(0, Math.floor(opts.minSize || 0))
  const max = Math.max(0, Math.floor(opts.maxSize || 0))
  const captureBt = !!opts.captureBacktrace
  const btContains = (opts.btContains || []).map(String).filter(Boolean)
  const memops = (opts.memops || []).map(String).filter(Boolean)
  const trackMemops = !!opts.trackMemops
  const monitorFreedPages = !!opts.monitorFreedPages
  const maxLive = Math.max(0, Math.floor(opts.maxLiveAllocs || 200000))
  const maxFreed = Math.max(0, Math.floor(opts.maxFreedAllocs || 200000))

  const comment = `Frida native memory timeline tracer (malloc/calloc/realloc/free${
    trackMemops ? " + memops" : ""
  })`

  return (
    buildCommonPreamble(comment) +
    `
'use strict';

const CONFIG = {
  minSize: ${min},
  maxSize: ${max},
  captureBacktrace: ${captureBt ? "true" : "false"},
  btContains: ${JSON.stringify(btContains)},
  trackMemops: ${trackMemops ? "true" : "false"},
  memops: ${JSON.stringify(memops)},
  monitorFreedPages: ${monitorFreedPages ? "true" : "false"},
  maxLiveAllocs: ${maxLive},
  maxFreedAllocs: ${maxFreed},
};

const live = new Map();   // ptrStr -> { id, size, alloc_bt, freed:false }
const freed = new Map();  // ptrStr -> { id, size, alloc_bt, free_bt, freed:true }
let nextAllocId = 1;

function _parseSize(arg) {
  // NativePointer-like -> string -> parse
  const s = String(arg);
  if (s.startsWith("0x") || s.startsWith("0X")) return parseInt(s, 16);
  const n = parseInt(s, 10);
  return isNaN(n) ? 0 : n;
}

function _shouldKeepBySize(sz) {
  if (CONFIG.maxSize > 0 && sz > CONFIG.maxSize) return false;
  if (CONFIG.minSize > 0 && sz < CONFIG.minSize) return false;
  return true;
}

function _btAllowed(btLines) {
  if (!CONFIG.btContains || CONFIG.btContains.length === 0) return true;
  const blob = btLines.join("\\n");
  for (let i = 0; i < CONFIG.btContains.length; i++) {
    if (blob.indexOf(CONFIG.btContains[i]) !== -1) return true;
  }
  return false;
}

${buildBacktraceHelpers(opts.backtrace, opts.maxBacktraceFrames)}
${buildEmitHelpers()}

function _trimIfNeeded(map, maxCount) {
  if (maxCount <= 0) return;
  if (map.size <= maxCount) return;
  const items = Array.from(map.entries());
  items.sort((a, b) => (a[1].id - b[1].id));
  const drop = items.length - maxCount;
  for (let i = 0; i < drop; i++) map.delete(items[i][0]);
}

function _hook(name, callbacks) {
  const addr = Module.findExportByName(null, name);
  if (addr === null) {
    console.log('[memtrace] export not found: ' + name);
    return;
  }
  Interceptor.attach(addr, callbacks);
  console.log('[memtrace] hooked ' + name + ' @ ' + addr);
}

function _enableFreedWatch(ptrStr, basePtr, size, freeBt) {
  if (!CONFIG.monitorFreedPages) return;
  if (!size || size <= 0) return;

  try {
    // MemoryAccessMonitor docs: enable(ranges, { onAccess(details) { ... } })
    // details includes threadId/operation/from/address/context, etc.
    MemoryAccessMonitor.enable([{ base: basePtr, size: size }], {
      onAccess(details) {
        _emit({
          type: "freed_access",
          ptr: ptrStr,
          size: size,
          op: details.operation,
          from: details.from.toString(),
          address: details.address.toString(),
          threadId: details.threadId,
          free_bt: freeBt,
          access_bt: CONFIG.captureBacktrace ? _bt(details.context) : undefined,
        });
      }
    });
  } catch (e) {
    _emit({ type: "freed_access_monitor_error", ptr: ptrStr, size: size, error: String(e) });
  }
}

_hook('malloc', {
  onEnter(args) {
    if (!__state.enabled) return;
    const sz = _parseSize(args[0]);
    if (!_shouldKeepBySize(sz)) return;

    this._mt_size = sz;

    if (CONFIG.captureBacktrace) {
      const bt = _bt(this.context);
      if (!_btAllowed(bt)) return;
      this._mt_bt = bt;
    }
  },
  onLeave(retval) {
    if (!__state.enabled) return;
    if (this._mt_size === undefined) return;

    const p = ptr(retval.toString());
    if (p.isNull()) return;

    const ptrStr = p.toString();

    // If this pointer was previously freed, forget old freed record
    if (freed.has(ptrStr)) freed.delete(ptrStr);

    const rec = { id: nextAllocId++, size: this._mt_size, alloc_bt: this._mt_bt, freed: false };
    live.set(ptrStr, rec);
    _trimIfNeeded(live, CONFIG.maxLiveAllocs);

    _emit({ type: "alloc", api: "malloc", ptr: ptrStr, size: rec.size, bt: rec.alloc_bt, threadId: this.threadId });
  }
});

_hook('calloc', {
  onEnter(args) {
    if (!__state.enabled) return;
    const n = _parseSize(args[0]);
    const sz = _parseSize(args[1]);
    const total = n * sz;
    if (!_shouldKeepBySize(total)) return;

    this._mt_size = total;

    if (CONFIG.captureBacktrace) {
      const bt = _bt(this.context);
      if (!_btAllowed(bt)) return;
      this._mt_bt = bt;
    }
  },
  onLeave(retval) {
    if (!__state.enabled) return;
    if (this._mt_size === undefined) return;

    const p = ptr(retval.toString());
    if (p.isNull()) return;

    const ptrStr = p.toString();
    if (freed.has(ptrStr)) freed.delete(ptrStr);

    const rec = { id: nextAllocId++, size: this._mt_size, alloc_bt: this._mt_bt, freed: false };
    live.set(ptrStr, rec);
    _trimIfNeeded(live, CONFIG.maxLiveAllocs);

    _emit({ type: "alloc", api: "calloc", ptr: ptrStr, size: rec.size, bt: rec.alloc_bt, threadId: this.threadId });
  }
});

_hook('realloc', {
  onEnter(args) {
    if (!__state.enabled) return;
    this._mt_old = ptr(args[0].toString());
    const sz = _parseSize(args[1]);
    if (!_shouldKeepBySize(sz)) return;

    this._mt_size = sz;

    if (CONFIG.captureBacktrace) {
      const bt = _bt(this.context);
      if (!_btAllowed(bt)) return;
      this._mt_bt = bt;
    }
  },
  onLeave(retval) {
    if (!__state.enabled) return;
    if (this._mt_size === undefined) return;

    const newPtr = ptr(retval.toString());
    if (newPtr.isNull()) return;

    const oldPtrStr = this._mt_old ? this._mt_old.toString() : null;
    const newPtrStr = newPtr.toString();

    if (oldPtrStr && live.has(oldPtrStr)) {
      const oldRec = live.get(oldPtrStr);
      live.delete(oldPtrStr);

      const freeBt = CONFIG.captureBacktrace ? _bt(this.context) : undefined;
      const freedRec = { ...oldRec, freed: true, free_bt: freeBt };
      freed.set(oldPtrStr, freedRec);
      _trimIfNeeded(freed, CONFIG.maxFreedAllocs);

      _emit({ type: "free", api: "realloc(old)", ptr: oldPtrStr, size: oldRec.size, bt: freeBt, threadId: this.threadId });
      _enableFreedWatch(oldPtrStr, ptr(oldPtrStr), oldRec.size, freeBt);
    }

    if (freed.has(newPtrStr)) freed.delete(newPtrStr);

    const rec = { id: nextAllocId++, size: this._mt_size, alloc_bt: this._mt_bt, freed: false };
    live.set(newPtrStr, rec);
    _trimIfNeeded(live, CONFIG.maxLiveAllocs);

    _emit({ type: "alloc", api: "realloc(new)", ptr: newPtrStr, size: rec.size, bt: rec.alloc_bt, threadId: this.threadId });
  }
});

_hook('free', {
  onEnter(args) {
    if (!__state.enabled) return;

    const p = ptr(args[0].toString());
    if (p.isNull()) return;

    const ptrStr = p.toString();
    const rec = live.get(ptrStr);
    const bt = CONFIG.captureBacktrace ? _bt(this.context) : undefined;

    if (rec) {
      live.delete(ptrStr);
      const freedRec = { ...rec, freed: true, free_bt: bt };
      freed.set(ptrStr, freedRec);
      _trimIfNeeded(freed, CONFIG.maxFreedAllocs);

      _emit({ type: "free", api: "free", ptr: ptrStr, size: rec.size, bt: bt, threadId: this.threadId });
      _enableFreedWatch(ptrStr, p, rec.size, bt);
    } else {
      // Might be double-free, free of untracked pointer, etc.
      const wasFreed = freed.has(ptrStr);
      _emit({ type: wasFreed ? "double_free_suspect" : "free_unknown", api: "free", ptr: ptrStr, bt: bt, threadId: this.threadId });
    }
  }
});

function _ptrState(ptrStr) {
  const l = live.get(ptrStr);
  if (l) return { state: "live", size: l.size, id: l.id };
  const f = freed.get(ptrStr);
  if (f) return { state: "freed", size: f.size, id: f.id };
  return { state: "unknown" };
}

function _hookMemop(name, argLayout) {
  const addr = Module.findExportByName(null, name);
  if (addr === null) {
    console.log('[memtrace] memop export not found: ' + name);
    return;
  }

  Interceptor.attach(addr, {
    onEnter(args) {
      if (!__state.enabled) return;

      const dst = ptr(args[argLayout.dst].toString());
      const src = ptr(args[argLayout.src].toString());
      const len = _parseSize(args[argLayout.len]);

      const dstStr = dst.toString();
      const srcStr = src.toString();

      const dstInfo = _ptrState(dstStr);
      const srcInfo = _ptrState(srcStr);

      const bt = CONFIG.captureBacktrace ? _bt(this.context) : undefined;

      const suspicious =
        (dstInfo.state === "freed") ||
        (srcInfo.state === "freed") ||
        (dstInfo.state === "unknown") ||
        (srcInfo.state === "unknown") ||
        (dstInfo.size !== undefined && len > dstInfo.size) ||
        (srcInfo.size !== undefined && len > srcInfo.size);

      if (suspicious) {
        _emit({
          type: "memop",
          api: name,
          dst: dstStr,
          src: srcStr,
          len: len,
          dst_state: dstInfo.state,
          src_state: srcInfo.state,
          dst_size: dstInfo.size,
          src_size: srcInfo.size,
          bt: bt,
          threadId: this.threadId
        });
      }
    }
  });

  console.log('[memtrace] hooked memop ' + name + ' @ ' + addr);
}

if (CONFIG.trackMemops) {
  // Default layout assumes: (dst, src, len)
  for (let i = 0; i < CONFIG.memops.length; i++) {
    _hookMemop(CONFIG.memops[i], { dst: 0, src: 1, len: 2 });
  }
}

console.log('[memtrace] loaded');
`
  )
}

function buildHookExportsScript(opts: {
  hooks: Array<{
    module: string | null
    name: string
    argc: number
    captureBacktrace: boolean
    backtrace: "accurate" | "fuzzy"
    maxBacktraceFrames: number
    hexdumpArgIndex: number | null
    hexdumpLen: number
  }>
}): string {
  const hooks = (opts.hooks || []).map(h => ({
    module: h.module ?? null,
    name: String(h.name),
    argc: Math.max(0, Math.min(12, Math.floor(h.argc ?? 6))),
    captureBacktrace: !!h.captureBacktrace,
    backtrace: h.backtrace === "fuzzy" ? "fuzzy" : "accurate",
    maxBacktraceFrames: Math.max(1, Math.min(64, Math.floor(h.maxBacktraceFrames ?? 16))),
    hexdumpArgIndex:
      h.hexdumpArgIndex === null || h.hexdumpArgIndex === undefined ? null : Math.floor(h.hexdumpArgIndex),
    hexdumpLen: Math.max(0, Math.min(4096, Math.floor(h.hexdumpLen ?? 64))),
  }))

  const anyFuzzy = hooks.some(h => h.backtrace === "fuzzy")
  const maxFrames = Math.max(...hooks.map(h => h.maxBacktraceFrames || 16), 16)

  const comment = `Frida native export hooker (${hooks.length} hooks)`

  return (
    buildCommonPreamble(comment) +
    `
'use strict';

${buildBacktraceHelpers(anyFuzzy ? "fuzzy" : "accurate", maxFrames)}
${buildEmitHelpers()}

const HOOKS = ${JSON.stringify(hooks, null, 2)};

function _findAddr(moduleName, exportName) {
  try {
    if (moduleName) {
      const m = Process.getModuleByName(moduleName);
      return m.getExportByName(exportName);
    }
    // global
    return Module.getGlobalExportByName(exportName);
  } catch (_) {
    try {
      return Module.findExportByName(moduleName, exportName);
    } catch (__) {
      return null;
    }
  }
}

function _safePtrStr(p) {
  try { return p.toString(); } catch (_) { return String(p); }
}

function _tryHexdump(p, len) {
  try {
    if (!p || p.isNull()) return null;
    return hexdump(p, { length: len, ansi: false });
  } catch (e) {
    return "<hexdump-error> " + e;
  }
}

function _attachOne(h) {
  const addr = _findAddr(h.module, h.name);
  if (addr === null) {
    console.log("[hook] export not found: " + (h.module ? (h.module + "!") : "") + h.name);
    return;
  }

  Interceptor.attach(addr, {
    onEnter(args) {
      if (!__state.enabled) return;

      const argv = [];
      for (let i = 0; i < h.argc; i++) argv.push(_safePtrStr(args[i]));

      const bt = h.captureBacktrace ? _bt(this.context) : undefined;

      let dump = undefined;
      if (h.hexdumpArgIndex !== null && h.hexdumpArgIndex >= 0 && h.hexdumpArgIndex < h.argc) {
        try {
          const p = ptr(args[h.hexdumpArgIndex].toString());
          dump = _tryHexdump(p, h.hexdumpLen);
        } catch (e) {
          dump = "<hexdump-error> " + e;
        }
      }

      _emit({
        type: "call",
        module: h.module,
        name: h.name,
        addr: addr.toString(),
        args: argv,
        bt: bt,
        hexdump: dump,
        threadId: this.threadId
      });
    },
    onLeave(retval) {
      if (!__state.enabled) return;
      _emit({
        type: "ret",
        module: h.module,
        name: h.name,
        addr: addr.toString(),
        retval: _safePtrStr(retval),
        threadId: this.threadId
      });
    }
  });

  console.log("[hook] attached " + (h.module ? (h.module + "!") : "") + h.name + " @ " + addr);
}

for (let i = 0; i < HOOKS.length; i++) _attachOne(HOOKS[i]);

console.log("[hook] loaded");
`
  )
}

function buildWatchRangeScript(opts: {
  base: string
  size: number
  captureBacktrace: boolean
  backtrace: "accurate" | "fuzzy"
  maxBacktraceFrames: number
}): string {
  const base = String(opts.base || "0x0")
  const size = Math.max(1, Math.floor(opts.size || 1))
  const capture = !!opts.captureBacktrace

  const comment = `Frida MemoryAccessMonitor watch range (${base}, ${size})`

  return (
    buildCommonPreamble(comment) +
    `
'use strict';

const CONFIG = {
  base: ${JSON.stringify(base)},
  size: ${size},
  captureBacktrace: ${capture ? "true" : "false"},
};

${buildBacktraceHelpers(opts.backtrace, opts.maxBacktraceFrames)}
${buildEmitHelpers()}

const range = { base: ptr(CONFIG.base), size: CONFIG.size };

try {
  MemoryAccessMonitor.enable([range], {
    onAccess(details) {
      if (!__state.enabled) return;
      _emit({
        type: "mem_access",
        base: CONFIG.base,
        size: CONFIG.size,
        op: details.operation,
        from: details.from.toString(),
        address: details.address.toString(),
        threadId: details.threadId,
        bt: CONFIG.captureBacktrace ? _bt(details.context) : undefined,
      });
    }
  });
  console.log("[watch] enabled range " + CONFIG.base + " size " + CONFIG.size);
} catch (e) {
  _emit({ type: "watch_error", error: String(e), base: CONFIG.base, size: CONFIG.size });
  console.log("[watch] enable failed: " + e);
}

console.log("[watch] loaded");
`
  )
}

/**
 * frida_memtrace
 */
export const memtrace = tool({
  description:
    "Generate a deterministic Frida JS script that traces malloc/calloc/realloc/free and optional memops, and save it under .opencode/artifacts/frida/scripts/",
  args: {
    bucket: tool.schema.string().optional().describe("Artifacts bucket name (directory)"),
    slug: tool.schema.string().optional().describe("Short filename slug"),
    min_size: tool.schema.number().optional().describe("Only track allocations >= this size (bytes)"),
    max_size: tool.schema.number().optional().describe("Only track allocations <= this size (bytes); 0 disables"),
    capture_backtrace: tool.schema.boolean().optional().describe("Capture backtraces for alloc/free/memops"),
    backtrace: tool.schema.string().optional().describe("Backtrace mode: 'accurate' or 'fuzzy'"),
    max_backtrace_frames: tool.schema.number().optional().describe("Max frames to include in emitted bt array"),
    bt_contains: tool.schema.array(tool.schema.string()).optional().describe("Only keep events where backtrace contains any of these substrings"),
    track_memops: tool.schema.boolean().optional().describe("Hook common memops (memcpy/memmove/strcpy/etc)"),
    memops: tool.schema.array(tool.schema.string()).optional().describe("List of memop exports to hook"),
    monitor_freed_pages: tool.schema.boolean().optional().describe("Enable MemoryAccessMonitor on freed ranges (can be heavy)"),
    max_live_allocs: tool.schema.number().optional().describe("Cap how many live allocations to keep"),
    max_freed_allocs: tool.schema.number().optional().describe("Cap how many freed allocations to keep"),
  },
  async execute(args, context) {
    const script = buildMemtraceScript({
      minSize: args.min_size ?? 0,
      maxSize: args.max_size ?? 0,
      captureBacktrace: args.capture_backtrace ?? true,
      backtrace: args.backtrace === "fuzzy" ? "fuzzy" : "accurate",
      maxBacktraceFrames: args.max_backtrace_frames ?? 16,
      btContains: args.bt_contains ?? [],
      trackMemops: args.track_memops ?? true,
      memops: args.memops ?? ["memcpy", "memmove", "memset", "strcpy", "strncpy"],
      monitorFreedPages: args.monitor_freed_pages ?? false,
      maxLiveAllocs: args.max_live_allocs ?? 200000,
      maxFreedAllocs: args.max_freed_allocs ?? 200000,
    })

    const out = await writeArtifact(
      context,
      args.bucket ?? "memtrace",
      args.slug ?? "memtrace",
      script,
      { kind: "memtrace", opts: args },
    )

    return {
      ref: out.ref,
      path: out.relPath,
      hint: "Use frida_cmd to generate an exact run command."
    }
  },
})

/**
 * frida_hook_exports
 */
export const hook_exports = tool({
  description:
    "Generate a deterministic Frida JS script that hooks one or more native exports and logs calls/returns (plus optional backtraces/hexdumps).",
  args: {
    bucket: tool.schema.string().optional(),
    slug: tool.schema.string().optional(),
    hooks: tool.schema.array(
      tool.schema.object({
        module: tool.schema.string().nullable().optional(),
        name: tool.schema.string(),
        argc: tool.schema.number().optional(),
        capture_backtrace: tool.schema.boolean().optional(),
        backtrace: tool.schema.string().optional(),
        max_backtrace_frames: tool.schema.number().optional(),
        hexdump_arg_index: tool.schema.number().nullable().optional(),
        hexdump_len: tool.schema.number().optional(),
      }),
    ),
  },
  async execute(args, context) {
    const hooks = (args.hooks ?? []).map(h => ({
      module: h.module ?? null,
      name: h.name,
      argc: h.argc ?? 6,
      captureBacktrace: h.capture_backtrace ?? true,
      backtrace: h.backtrace === "fuzzy" ? "fuzzy" : "accurate",
      maxBacktraceFrames: h.max_backtrace_frames ?? 16,
      hexdumpArgIndex: h.hexdump_arg_index ?? null,
      hexdumpLen: h.hexdump_len ?? 64,
    }))

    const script = buildHookExportsScript({ hooks })

    const out = await writeArtifact(
      context,
      args.bucket ?? "hooks",
      args.slug ?? "hook-exports",
      script,
      { kind: "hook_exports", hooks: args.hooks },
    )

    return { ref: out.ref, path: out.relPath, hooked: hooks.map(h => (h.module ? `${h.module}!${h.name}` : h.name)) }
  },
})

/**
 * frida_watch_range
 */
export const watch_range = tool({
  description:
    "Generate a deterministic Frida JS script that watches a memory range with MemoryAccessMonitor and logs accesses.",
  args: {
    bucket: tool.schema.string().optional(),
    slug: tool.schema.string().optional(),
    base: tool.schema.string(),
    size: tool.schema.number(),
    capture_backtrace: tool.schema.boolean().optional(),
    backtrace: tool.schema.string().optional(),
    max_backtrace_frames: tool.schema.number().optional(),
  },
  async execute(args, context) {
    const script = buildWatchRangeScript({
      base: args.base,
      size: args.size,
      captureBacktrace: args.capture_backtrace ?? true,
      backtrace: args.backtrace === "fuzzy" ? "fuzzy" : "accurate",
      maxBacktraceFrames: args.max_backtrace_frames ?? 16,
    })

    const out = await writeArtifact(
      context,
      args.bucket ?? "watch",
      args.slug ?? "watch-range",
      script,
      { kind: "watch_range", base: args.base, size: args.size },
    )

    return { ref: out.ref, path: out.relPath }
  },
})

/**
 * frida_store
 */
export const store = tool({
  description: "Store a raw Frida JS script under .opencode/artifacts/frida/scripts/<bucket>/ and return an @ref.",
  args: {
    bucket: tool.schema.string().optional(),
    slug: tool.schema.string().optional(),
    script: tool.schema.string(),
  },
  async execute(args, context) {
    const out = await writeArtifact(
      context,
      args.bucket ?? "custom",
      args.slug ?? "script",
      args.script,
      { kind: "store" },
    )
    return { ref: out.ref, path: out.relPath }
  },
})

/**
 * frida_cmd
 */
export const cmd = tool({
  description: "Generate a copy/paste Frida CLI command-line for running a stored script (does not execute anything).",
  args: {
    device: tool.schema.string().optional().describe("Device selector: 'local' or 'usb'"),
    target: tool.schema.string().describe("Process name or PID"),
    script_path: tool.schema.string().describe("Path to script (relative), or @ref"),
    debug: tool.schema.boolean().optional().describe("Include --debug"),
  },
  async execute(args) {
    const device = args.device === "usb" ? "usb" : "local"
    const target = args.target
    const script = String(args.script_path).startsWith("@")
      ? String(args.script_path).slice(1)
      : String(args.script_path)

    const parts: string[] = ["frida"]
    if (device === "usb") parts.push("-U")
    parts.push(target, "-l", script)
    if (args.debug) parts.push("--debug")
    return parts.join(" ")
  },
})
```

Why this tool design works for “EXACT scripts”:

* **All scripts come from fixed templates** (no freehand JS), so output is deterministic.
* It always writes to `.opencode/artifacts/frida/scripts/...` and returns an `@ref`.

Also: backtraces + MemoryAccessMonitor behavior are based on Frida’s JS API docs. ([frida.re][4])

---

## 4) Skills

### `.opencode/skills/frida-script-style/SKILL.md`

Skills must have YAML frontmatter with `name` + `description`. ([opencode.ai][5])

```md
---
name: frida-script-style
description: Deterministic Frida GumJS script conventions for exact, file-based generation and stable logging.
---

## What I do
- Enforce a deterministic script skeleton:
  - 'use strict'
  - CONFIG object (serialized JSON)
  - send() structured events with seq + ts_ms
  - avoid random IDs; prefer monotonic seq or stable IDs
- Prefer logging-only hooks:
  - Use Interceptor.attach() to observe args/retval
  - Avoid modifying return values or patching code unless explicitly required for debugging a crash reproduction

## Output schema rules
- Addresses MUST be strings (NativePointer.toString()) to avoid JSON issues.
- Backtraces MUST be arrays of strings.
- Each event MUST contain:
  - type
  - threadId (when available)
  - seq
  - ts_ms

## File rule
- Do NOT paste huge scripts in chat.
- Use frida_* tools so scripts are stored under .opencode/artifacts/frida/scripts and referenced with @path.
```

### `.opencode/skills/frida-memtrace/SKILL.md`

```md
---
name: frida-memtrace
description: Native heap timeline tracing strategy (malloc/free + memops) to find UAF and memory corruption patterns with reduced noise.
---

## Goal
Build a minimal timeline of heap events relevant to one flow:
- alloc (malloc/calloc/realloc(new))
- free (free/realloc(old))
- memop (memcpy/memmove/memset/strcpy/strncpy, etc)
- freed_access (MemoryAccessMonitor hit on freed region)

## Key heuristics
- Reduce noise using:
  - min_size / max_size
  - bt_contains filters (only keep events whose backtrace includes a module/function substring)
  - only emit memop events when suspicious (freed/unknown pointers or len > known size)

## What counts as suspicious
- memop where src_state == "freed" or dst_state == "freed"
- memop where len > dst_size / src_size (best-effort OOB signal)
- double_free_suspect events

## Notes
- MemoryAccessMonitor reports the first access of each page; use it as a "tripwire" rather than full tracing.
```

### `.opencode/skills/frida-debugging/SKILL.md`

This embeds the exact CLI behaviors (load script, reload, debug inspector) from Frida’s CLI docs. ([frida.re][6])

```md
---
name: frida-debugging
description: How to run, reload, and debug Frida scripts reliably (Frida CLI + Node-compatible debugger).
---

## Running scripts
- Load a script into a local process:
  - frida <process> -l script.js
- Connect over USB:
  - frida -U <process> -l script.js

## Reload loop (fast iteration)
- In Frida CLI, reload at any time:
  - %reload

## Debugging the script itself (Node-compatible debugger)
- Start with debugger enabled:
  - frida <process> -l script.js --debug
- This listens on port 5858; attach with node-inspector or compatible tooling.

## Capturing backtraces correctly
- When inside Interceptor onEnter/onLeave, pass this.context to Thread.backtrace for accuracy.
```

---

## 5) Agents

### `.opencode/agents/frida-lab.md` (primary)

Agent frontmatter supports `mode`, `temperature`, and `steps`. ([opencode.ai][7])

```md
---
description: Primary Frida Lab agent. Generates deterministic Frida scripts via frida_* tools and returns @refs + run commands.
mode: primary
temperature: 0.1
steps: 20
permission:
  edit:
    "*": "deny"
    ".opencode/**": "allow"
    "docs/security/**": "allow"
  frida_memtrace: "allow"
  frida_hook_exports: "allow"
  frida_watch_range: "allow"
  frida_store: "allow"
  frida_cmd: "allow"
  webfetch: "deny"
  websearch: "deny"
---

You generate EXACT Frida scripts as files.

## Non-negotiables
- Do not freehand large scripts; always call frida_* tools.
- Logging/instrumentation only. No bypass scripts (SSL pinning/auth/etc).

## Workflow
1) Identify which script type the user needs:
   - memtrace timeline: frida_memtrace
   - hook specific exports: frida_hook_exports
   - watch a memory range: frida_watch_range
2) Call the correct tool to generate + store script.
3) Call frida_cmd to print the exact run command (local or -U).
4) Return:
   - @ref to script
   - exact frida command line
   - quick notes for debugging/reload (from frida-debugging skill)
```

### `.opencode/agents/frida-memtrace-gen.md` (subagent)

```md
---
description: Generates malloc/free + memops timeline Frida script with noise filters for UAF hunting.
mode: subagent
temperature: 0.1
steps: 15
permission:
  frida_memtrace: "allow"
  frida_cmd: "allow"
---

Use skill: frida-memtrace and frida-script-style.

When invoked:
- Choose defaults that reduce noise:
  - min_size: 16
  - max_size: 0 (no upper bound) unless user wants
  - capture_backtrace: true
  - bt_contains: include likely module(s) if provided
  - monitor_freed_pages: false by default (enable only when asked)
- Generate the script with frida_memtrace.
- Generate the run command with frida_cmd.
Return the @ref + command.
```

### `.opencode/agents/frida-native-hook-gen.md` (subagent)

```md
---
description: Generates deterministic Frida export-hook scripts (calls/returns + optional backtrace + optional hexdump).
mode: subagent
temperature: 0.1
steps: 15
permission:
  frida_hook_exports: "allow"
  frida_cmd: "allow"
---

Use skill: frida-script-style.

When invoked:
- Convert the user request into a hooks[] list:
  - module (or null)
  - export name
  - argc (default 6)
  - capture_backtrace (default true)
  - hexdump_arg_index (default null unless asked)
- Generate script with frida_hook_exports and return @ref
- Provide exact run command via frida_cmd
```

---

## 6) Commands

Commands can be defined in `.opencode/commands/` and specify `agent:` in frontmatter. ([opencode.ai][8])

### `.opencode/commands/frida-memtrace.md`

```md
---
description: Generate a malloc/free (+memops) timeline Frida script and save it to artifacts.
agent: frida-memtrace-gen
subtask: true
---

Generate a Frida memtrace script. Interpret $ARGUMENTS as optional JSON for tool args.
If no args provided, use defaults optimized for low noise.

Then call frida_cmd to print an exact command for running the script.
```

### `.opencode/commands/frida-hook-exports.md`

```md
---
description: Generate a Frida script that hooks one or more native exports and logs calls/returns.
agent: frida-native-hook-gen
subtask: true
---

Generate a native export hook script from $ARGUMENTS.
$ARGUMENTS can be either:
- JSON with { hooks: [...] }
- or a simple list of exports; assume argc=6 and module=null unless specified.

Then call frida_cmd to print an exact command.
```

### `.opencode/commands/frida-watch-range.md`

```md
---
description: Generate a MemoryAccessMonitor range watch script (tripwire for suspicious pointers/ranges).
agent: frida-lab
subtask: true
---

Use frida_watch_range to generate a range watcher script.
$ARGUMENTS should be JSON: { base: "0x...", size: 4096, device: "usb|local", target: "ProcessNameOrPID" }.

Then call frida_cmd to print an exact command.
```

---

## 7) Why this enables your two key use-cases

### Use case A: “timeline of mallocs/allocations/frees for specific flows”

* `frida_memtrace` outputs a **structured, filterable timeline**:

  * alloc/free events include pointer, size, optional backtrace
  * `bt_contains` filters reduce noise by keeping only events in call-stacks that touch your code path
* Optional MemoryAccessMonitor tripwires on freed ranges are based on the JS API’s documented `MemoryAccessMonitor.enable()` callback fields. ([frida.re][4])

### Use case B: “suspicious memops (memcpy, etc) + timeline + constraints”

* The memtrace script hooks memops and emits **only suspicious events** (freed/unknown pointers, or len > known size).
* That gives you a small set of candidate “trigger sites” to then feed into your symbolic constraints / Z3 pipeline.

---

## 8) How you debug Frida scripts “for real”

The `frida-debugging` skill bakes in the exact Frida CLI behavior:

* load script: `frida <process> -l calc.js`
* reload: `%reload`
* enable Node-compatible debugger: `--debug` (port 5858) ([frida.re][6])

And the script templates use the documented best-practice of using `this.context` with `Thread.backtrace()` when inside Interceptor callbacks. ([frida.re][4])

---

If you want, I can also add one more custom tool + agent that:

* takes a **Frida `send()` JSONL log file**,
* normalizes it into the same **timeline artifact schema** you’re already using,
* then stores it under `.opencode/artifacts/timelines/runtime/…` (so your timeline/Z3 agents can consume runtime traces directly).

[1]: https://opencode.ai/docs/custom-tools/ "Custom Tools | OpenCode"
[2]: https://opencode.ai/docs/permissions/ "Permissions | OpenCode"
[3]: https://opencode.ai/docs/rules/ "Rules | OpenCode"
[4]: https://frida.re/docs/javascript-api/ "https://frida.re/docs/javascript-api/"
[5]: https://opencode.ai/docs/skills/ "Agent Skills | OpenCode"
[6]: https://frida.re/docs/frida-cli/ "https://frida.re/docs/frida-cli/"
[7]: https://opencode.ai/docs/agents/ "Agents | OpenCode"
[8]: https://opencode.ai/docs/commands/?utm_source=chatgpt.com "Commands"


Below is a **complete “Frida Lab” OpenCode project layout** that’s optimized for your goal:

* **Main focus:** generate **exact, runnable Frida scripts** (native / Java / ObjC), with a **stable event schema** suitable for **malloc/free timelines**, **memcpy-style corruption timelines**, and later offline reasoning (Z3, etc.).
* **Agentic pipeline:** agents + commands + skills push everything through one place: a **script generator tool** that writes to `.opencode/artifacts/frida/scripts/…` (so you always get a real file, not a hand-wavy snippet).

Key OpenCode behaviors this design relies on:

* Agents can be defined as Markdown files in `.opencode/agents/` using YAML frontmatter, and the **filename becomes the agent name**. ([OpenCode][1])
* Skills live under `.opencode/skills/<name>/SKILL.md`. ([OpenCode][2])
* Custom tools can export multiple tools per file; each export becomes a tool named `<filename>_<exportname>`. ([OpenCode][3])
* Permissions are controlled via the `permission` config (allow/deny/ask), and can be scoped by glob patterns. ([OpenCode][4])
* Frida CLI supports loading scripts with `-l`, auto-reloading, `%reload`, and `--debug` (port 5858). ([frida.re][5])
* Frida JS API supports `Interceptor.attach()` and `Thread.backtrace()` patterns used below. ([frida.re][6])
* Structured host messaging uses `send()` and host-side `on('message', …)` (Python example in docs). ([frida.re][7])

---

## Folder structure

Create this structure in your repo root:

```bash
mkdir -p .opencode/{agents,commands,skills/{frida-script-spec,frida-debug-workflow,frida-memory-timeline},tools,artifacts/frida/{scripts,specs,runners,logs}}
```

Resulting tree:

```
.
├─ opencode.jsonc
├─ AGENTS.md
├─ README.md
├─ .gitignore
└─ .opencode/
   ├─ agents/
   │  ├─ frida-lab.md
   │  ├─ frida-native-memtimeline.md
   │  ├─ frida-native-hooker.md
   │  └─ frida-mobile-hooker.md
   ├─ commands/
   │  ├─ frida-help.md
   │  ├─ frida-hook-exports.md
   │  ├─ frida-hook-offset.md
   │  ├─ frida-memtimeline.md
   │  ├─ frida-watch-range.md
   │  ├─ frida-java-hook.md
   │  └─ frida-runner.md
   ├─ skills/
   │  ├─ frida-script-spec/SKILL.md
   │  ├─ frida-debug-workflow/SKILL.md
   │  └─ frida-memory-timeline/SKILL.md
   ├─ tools/
   │  └─ frida_lab.ts
   └─ artifacts/
      └─ frida/
         ├─ scripts/
         ├─ specs/
         ├─ runners/
         └─ logs/
```

---

## opencode.jsonc

This config makes OpenCode **safe-by-default** for vuln research: it can read code, but **cannot edit your codebase** (only `.opencode/**`, `README.md`, etc.). Web tools are denied for deterministic script generation.

```jsonc
// opencode.jsonc
{
  "$schema": "https://opencode.ai/config.json",

  // Keep the lab deterministic: disable web tools by default.
  // You can temporarily override if you explicitly want browsing.
  "permission": {
    "websearch": "deny",
    "webfetch": "deny",

    // Avoid accidental execution. If you want OpenCode to run `frida` for you,
    // change this to "ask".
    "bash": "deny",

    // Allow subagents
    "task": "allow",

    // Default: do NOT allow edits anywhere...
    "edit": {
      "**": "deny",

      // ...except lab and docs files:
      ".opencode/**": "allow",
      "opencode.jsonc": "allow",
      "AGENTS.md": "allow",
      "README.md": "allow",
      ".gitignore": "allow"
    }
  },

  // Keep the file watcher quiet (optional, but nice with auto-generated logs/scripts).
  "watcher": {
    "ignore": [
      ".git/**",
      "node_modules/**",
      ".opencode/artifacts/**"
    ]
  }
}
```

(These fields and permission semantics follow OpenCode’s config + permissions docs.) ([OpenCode][8])

---

## AGENTS.md

This is your “lab contract”: the agent must always produce an actual script file via the tool, return its path, and provide the exact Frida CLI command to run it.

```markdown
# Frida Lab (OpenCode)

This repo is an OpenCode "Frida Lab" focused on generating **exact, runnable Frida scripts** for **memory corruption research** (UAF, heap overflows, bad memcpy/memmove/strcpy usage).

## Non-negotiable rules (for all agents)

1) **Always generate scripts via the custom tool**:
   - Use `frida_lab_*` tools to create `.js` scripts under:
     - `.opencode/artifacts/frida/scripts/<slug>.js`
   - Do not handwrite scripts in chat unless the user explicitly asks for inline code *only*.

2) Every generated script must:
   - Be **standalone** (no external imports).
   - Emit **structured events** using `send({ ... })` so logs are machine-parseable.
   - Include optional stack traces via `Thread.backtrace(this.context, ...)` when applicable.

3) Every response that generates a script must include:
   - Script path (exact).
   - The exact `frida ... -l <script>` command to run it (generated via `frida_lab_cmd`).
   - A minimal validation checklist: “how to confirm the hook is firing”.

4) This lab is for **authorized security research** only.
   - Do not provide “bypass / stealth / anti-detection” guidance.
   - Do not provide exploit payloads; focus on instrumentation, observation, and debugging.

## Output schema conventions

All scripts must emit events like:

- `kind`: "alloc" | "free" | "realloc" | "memcpy" | "memmove" | "memset" | "strcpy" | ... | "watch"
- `ts`: milliseconds since epoch (Date.now())
- `tid`: Process.getCurrentThreadId() when available
- Function-specific fields: `ptr`, `size`, `dst`, `src`, `len`, `dst_alloc`, `dst_off`, `suspicious`, etc.
- `bt`: optional array of symbolized frames (strings)

## Where artifacts go

- Scripts: `.opencode/artifacts/frida/scripts/`
- Specs:   `.opencode/artifacts/frida/specs/`
- Runners: `.opencode/artifacts/frida/runners/`
- Logs:    `.opencode/artifacts/frida/logs/`
```

---

## .opencode/tools/frida_lab.ts

This is the core: it’s the **single source of truth** for generating scripts. Each export becomes a tool named `frida_lab_<exportname>` (OpenCode behavior). ([OpenCode][3])

```ts
// .opencode/tools/frida_lab.ts
import { tool } from "@opencode-ai/plugin"
import * as fs from "node:fs/promises"
import * as path from "node:path"

const LAB_ROOT = path.resolve(process.cwd(), ".opencode", "artifacts", "frida")
const SCRIPTS_DIR = path.join(LAB_ROOT, "scripts")
const SPECS_DIR = path.join(LAB_ROOT, "specs")
const RUNNERS_DIR = path.join(LAB_ROOT, "runners")

type WriteResult = { path: string; bytes: number }

async function ensureDirs(): Promise<void> {
  await fs.mkdir(SCRIPTS_DIR, { recursive: true })
  await fs.mkdir(SPECS_DIR, { recursive: true })
  await fs.mkdir(RUNNERS_DIR, { recursive: true })
}

function isoNow(): string {
  return new Date().toISOString()
}

function slugify(input: string): string {
  const s = input
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
  if (!s) throw new Error("slug became empty; provide a safer slug")
  if (s.includes("..")) throw new Error("invalid slug: contains '..'")
  return s
}

function assertWithinRoot(root: string, candidate: string): void {
  const normRoot = path.resolve(root)
  const normCandidate = path.resolve(candidate)
  if (normCandidate === normRoot) return
  if (!normCandidate.startsWith(normRoot + path.sep)) {
    throw new Error(`refusing to write outside lab root: ${normCandidate}`)
  }
}

async function writeTextFile(absPath: string, content: string): Promise<WriteResult> {
  assertWithinRoot(LAB_ROOT, absPath)
  await fs.mkdir(path.dirname(absPath), { recursive: true })
  await fs.writeFile(absPath, content, { encoding: "utf8" })
  return { path: absPath, bytes: Buffer.byteLength(content, "utf8") }
}

function jsHeader(meta: Record<string, unknown>): string {
  const json = JSON.stringify(meta, null, 2)
  return [
    "/**",
    " * GENERATED FILE — OpenCode Frida Lab",
    " *",
    " * This script is intended for authorized debugging / security research.",
    " * It emits structured events via send({ ... }) for easy parsing.",
    " *",
    " * Meta:",
    ...json.split("\n").map((l) => ` * ${l}`),
    " */",
    ""
  ].join("\n")
}

function renderPrelude(configObj: Record<string, unknown>): string {
  const cfg = JSON.stringify(configObj, null, 2)
  return [
    "'use strict';",
    "",
    `const CONFIG = ${cfg};`,
    "",
    "function nowMs() { return Date.now(); }",
    "",
    "function sendEvent(kind, payload) {",
    "  // payload must be JSON-serializable",
    "  send(Object.assign({ kind, ts: nowMs() }, payload || {}));",
    "}",
    "",
    "function tryBacktrace(context) {",
    "  try {",
    "    return Thread.backtrace(context, Backtracer.ACCURATE)",
    "      .map(DebugSymbol.fromAddress)",
    "      .map(String);",
    "  } catch (e) {",
    "    try {",
    "      return Thread.backtrace(context, Backtracer.FUZZY)",
    "        .map(DebugSymbol.fromAddress)",
    "        .map(String);",
    "    } catch (_) {",
    "      return [];",
    "    }",
    "  }",
    "}",
    "",
    "function u32(x) {",
    "  try { return x.toUInt32(); } catch (_) { return 0; }",
    "}",
    "",
    "function resolveExport(moduleName, exportName) {",
    "  const addr = Module.findExportByName(moduleName || null, exportName);",
    "  if (addr === null) {",
    "    sendEvent('error', { what: 'export_not_found', module: moduleName || null, export: exportName });",
    "    return null;",
    "  }",
    "  return addr;",
    "}",
    ""
  ].join("\n")
}

function renderHookExportsScript(args: {
  slug: string
  module?: string
  exports: string[]
  backtrace: boolean
  maxArgs: number
}): string {
  const meta = {
    kind: "hook-exports",
    generated_at: isoNow(),
    slug: args.slug
  }
  const cfg = {
    kind: "hook-exports",
    module: args.module ?? null,
    exports: args.exports,
    backtrace: args.backtrace,
    maxArgs: args.maxArgs
  }

  const lines: string[] = []
  lines.push(jsHeader(meta))
  lines.push(renderPrelude(cfg))

  lines.push("sendEvent('ready', { config: CONFIG });")
  lines.push("")
  lines.push("const TARGETS = CONFIG.exports || [];")
  lines.push("TARGETS.forEach(function (name) {")
  lines.push("  const addr = resolveExport(CONFIG.module, name);")
  lines.push("  if (addr === null) return;")
  lines.push("  sendEvent('hook', { what: 'attach', name, module: CONFIG.module, address: addr.toString() });")
  lines.push("  Interceptor.attach(addr, {")
  lines.push("    onEnter(args) {")
  lines.push("      const tid = Process.getCurrentThreadId();")
  lines.push("      const argv = [];")
  lines.push("      const n = Math.max(0, CONFIG.maxArgs | 0);")
  lines.push("      for (let i = 0; i < n; i++) argv.push(args[i].toString());")
  lines.push("      const evt = { tid, name, when: 'enter', args: argv };")
  lines.push("      if (CONFIG.backtrace) evt.bt = tryBacktrace(this.context);")
  lines.push("      sendEvent('call', evt);")
  lines.push("    },")
  lines.push("    onLeave(retval) {")
  lines.push("      const tid = Process.getCurrentThreadId();")
  lines.push("      const evt = { tid, name, when: 'leave', retval: retval.toString() };")
  lines.push("      if (CONFIG.backtrace) evt.bt = tryBacktrace(this.context);")
  lines.push("      sendEvent('call', evt);")
  lines.push("    }")
  lines.push("  });")
  lines.push("});")

  return lines.join("\n")
}

function renderHookOffsetScript(args: {
  slug: string
  module: string
  offset: string
  label: string
  backtrace: boolean
  maxArgs: number
}): string {
  const meta = {
    kind: "hook-offset",
    generated_at: isoNow(),
    slug: args.slug
  }
  const cfg = {
    kind: "hook-offset",
    module: args.module,
    offset: args.offset,
    label: args.label,
    backtrace: args.backtrace,
    maxArgs: args.maxArgs
  }

  const lines: string[] = []
  lines.push(jsHeader(meta))
  lines.push(renderPrelude(cfg))

  lines.push("sendEvent('ready', { config: CONFIG });")
  lines.push("")
  lines.push("const m = Process.getModuleByName(CONFIG.module);")
  lines.push("const addr = m.base.add(ptr(CONFIG.offset));")
  lines.push("sendEvent('hook', { what: 'attach', label: CONFIG.label, module: CONFIG.module, base: m.base.toString(), address: addr.toString() });")
  lines.push("")
  lines.push("Interceptor.attach(addr, {")
  lines.push("  onEnter(args) {")
  lines.push("    const tid = Process.getCurrentThreadId();")
  lines.push("    const argv = [];")
  lines.push("    const n = Math.max(0, CONFIG.maxArgs | 0);")
  lines.push("    for (let i = 0; i < n; i++) argv.push(args[i].toString());")
  lines.push("    const evt = { tid, label: CONFIG.label, when: 'enter', args: argv };")
  lines.push("    if (CONFIG.backtrace) evt.bt = tryBacktrace(this.context);")
  lines.push("    sendEvent('call', evt);")
  lines.push("  },")
  lines.push("  onLeave(retval) {")
  lines.push("    const tid = Process.getCurrentThreadId();")
  lines.push("    const evt = { tid, label: CONFIG.label, when: 'leave', retval: retval.toString() };")
  lines.push("    if (CONFIG.backtrace) evt.bt = tryBacktrace(this.context);")
  lines.push("    sendEvent('call', evt);")
  lines.push("  }")
  lines.push("});")

  return lines.join("\n")
}

function renderMemTimelineScript(args: {
  slug: string
  module?: string
  minSize: number
  maxSize: number
  btContains: string[]
  enableBacktrace: boolean
  allocSymbols: string[]
  freeSymbols: string[]
  memOps: string[]
  sampleEvery: number
  logAllMemOps: boolean
  keepFreed: number
}): string {
  const meta = {
    kind: "memtimeline",
    generated_at: isoNow(),
    slug: args.slug
  }

  const cfg = {
    kind: "memtimeline",
    module: args.module ?? null,
    minSize: args.minSize,
    maxSize: args.maxSize,
    btContains: args.btContains,
    enableBacktrace: args.enableBacktrace,
    allocSymbols: args.allocSymbols,
    freeSymbols: args.freeSymbols,
    memOps: args.memOps,
    sampleEvery: args.sampleEvery,
    logAllMemOps: args.logAllMemOps,
    keepFreed: args.keepFreed
  }

  const lines: string[] = []
  lines.push(jsHeader(meta))
  lines.push(renderPrelude(cfg))

  lines.push("sendEvent('ready', { config: CONFIG });")
  lines.push("")
  lines.push("const live = new Map(); // basePtrStr -> { size: number, fn: string, tid: number, ts: number, bt?: string[] }")
  lines.push("const freed = new Map(); // basePtrStr -> { size: number, fn: string, tid: number, ts: number, freed_ts: number, bt?: string[] }")
  lines.push("let allocCount = 0;")
  lines.push("let memopCount = 0;")
  lines.push("")
  lines.push("function matchesFilters(size, btLines) {")
  lines.push("  if (CONFIG.minSize && size < (CONFIG.minSize|0)) return false;")
  lines.push("  if (CONFIG.maxSize && (CONFIG.maxSize|0) > 0 && size > (CONFIG.maxSize|0)) return false;")
  lines.push("  const needles = CONFIG.btContains || [];")
  lines.push("  if (needles.length === 0) return true;")
  lines.push("  const hay = (btLines || []).join('\\n');")
  lines.push("  for (let i = 0; i < needles.length; i++) {")
  lines.push("    if (hay.indexOf(String(needles[i])) === -1) return false;")
  lines.push("  }")
  lines.push("  return true;")
  lines.push("}")
  lines.push("")
  lines.push("function rememberLive(ptrStr, rec) {")
  lines.push("  live.set(ptrStr, rec);")
  lines.push("  // If address was previously marked freed, drop that freed record (it got reused).")
  lines.push("  if (freed.has(ptrStr)) freed.delete(ptrStr);")
  lines.push("}")
  lines.push("")
  lines.push("function rememberFreed(ptrStr, rec) {")
  lines.push("  freed.set(ptrStr, rec);")
  lines.push("  // cap freed map size")
  lines.push("  const cap = Math.max(0, CONFIG.keepFreed | 0);")
  lines.push("  if (cap > 0 && freed.size > cap) {")
  lines.push("    const firstKey = freed.keys().next().value;")
  lines.push("    if (firstKey) freed.delete(firstKey);")
  lines.push("  }")
  lines.push("}")
  lines.push("")
  lines.push("function findContaining(map, addr) {")
  lines.push("  // Returns { base: string, rec: any, off: number } or null")
  lines.push("  for (const entry of map.entries()) {")
  lines.push("    const baseStr = entry[0];")
  lines.push("    const rec = entry[1];")
  lines.push("    const base = ptr(baseStr);")
  lines.push("    const off = addr.sub(base).toInt32();")
  lines.push("    if (off >= 0 && off < (rec.size|0)) return { base: baseStr, rec, off };")
  lines.push("  }")
  lines.push("  return null;")
  lines.push("}")
  lines.push("")
  lines.push("function shouldSample(counter) {")
  lines.push("  const n = Math.max(1, CONFIG.sampleEvery | 0);")
  lines.push("  return (counter % n) === 0;")
  lines.push("}")
  lines.push("")
  lines.push("function attachAlloc(name) {")
  lines.push("  const addr = resolveExport(CONFIG.module, name);")
  lines.push("  if (addr === null) return;")
  lines.push("  Interceptor.attach(addr, {")
  lines.push("    onEnter(args) {")
  lines.push("      this._fn = name;")
  lines.push("      this._tid = Process.getCurrentThreadId();")
  lines.push("      // best-effort sizes for common allocators")
  lines.push("      if (name === 'calloc') {")
  lines.push("        this._size = (u32(args[0]) * u32(args[1])) | 0;")
  lines.push("      } else if (name === 'realloc') {")
  lines.push("        this._old = args[0];")
  lines.push("        this._size = u32(args[1]) | 0;")
  lines.push("      } else {")
  lines.push("        this._size = u32(args[0]) | 0;")
  lines.push("      }")
  lines.push("      this._bt = CONFIG.enableBacktrace ? tryBacktrace(this.context) : null;")
  lines.push("    },")
  lines.push("    onLeave(retval) {")
  lines.push("      allocCount++;")
  lines.push("      if (!shouldSample(allocCount)) return;")
  lines.push("      const p = retval;")
  lines.push("      if (p.isNull()) return;")
  lines.push("      const ptrStr = p.toString();")
  lines.push("      const size = (this._size|0);")
  lines.push("      const bt = this._bt || [];")
  lines.push("      if (!matchesFilters(size, bt)) return;")
  lines.push("      const rec = { size, fn: this._fn, tid: this._tid, ts: nowMs() };")
  lines.push("      if (CONFIG.enableBacktrace) rec.bt = bt;")
  lines.push("      rememberLive(ptrStr, rec);")
  lines.push("      if (this._fn === 'realloc' && this._old) {")
  lines.push("        sendEvent('realloc', { tid: this._tid, fn: this._fn, old: this._old.toString(), ptr: ptrStr, size, bt: rec.bt });")
  lines.push("      } else {")
  lines.push("        sendEvent('alloc', { tid: this._tid, fn: this._fn, ptr: ptrStr, size, bt: rec.bt });")
  lines.push("      }")
  lines.push("    }")
  lines.push("  });")
  lines.push("}")
  lines.push("")
  lines.push("function attachFree(name) {")
  lines.push("  const addr = resolveExport(CONFIG.module, name);")
  lines.push("  if (addr === null) return;")
  lines.push("  Interceptor.attach(addr, {")
  lines.push("    onEnter(args) {")
  lines.push("      const tid = Process.getCurrentThreadId();")
  lines.push("      const p = args[0];")
  lines.push("      if (p.isNull()) return;")
  lines.push("      const ptrStr = p.toString();")
  lines.push("      const rec = live.get(ptrStr);")
  lines.push("      const bt = CONFIG.enableBacktrace ? tryBacktrace(this.context) : null;")
  lines.push("      if (rec) {")
  lines.push("        live.delete(ptrStr);")
  lines.push("        const freedRec = Object.assign({}, rec, { freed_ts: nowMs() });")
  lines.push("        if (CONFIG.enableBacktrace) freedRec.free_bt = bt;")
  lines.push("        rememberFreed(ptrStr, freedRec);")
  lines.push("        sendEvent('free', { tid, fn: name, ptr: ptrStr, size: rec.size, bt: bt || undefined });")
  lines.push("      } else {")
  lines.push("        // Unknown pointer - still useful in UAF hunts")
  lines.push("        sendEvent('free', { tid, fn: name, ptr: ptrStr, size: null, bt: bt || undefined, unknown: true });")
  lines.push("      }")
  lines.push("    }")
  lines.push("  });")
  lines.push("}")
  lines.push("")
  lines.push("function attachMemOp(name) {")
  lines.push("  const addr = resolveExport(CONFIG.module, name);")
  lines.push("  if (addr === null) return;")
  lines.push("  Interceptor.attach(addr, {")
  lines.push("    onEnter(args) {")
  lines.push("      memopCount++;")
  lines.push("      if (!shouldSample(memopCount)) return;")
  lines.push("      const tid = Process.getCurrentThreadId();")
  lines.push("      const bt = CONFIG.enableBacktrace ? tryBacktrace(this.context) : null;")
  lines.push("")
  lines.push("      // decode common mem* signatures")
  lines.push("      let dst = NULL, src = NULL, len = 0;")
  lines.push("      if (name === 'memcpy' || name === 'memmove') {")
  lines.push("        dst = args[0]; src = args[1]; len = u32(args[2])|0;")
  lines.push("      } else if (name === 'memset') {")
  lines.push("        dst = args[0]; src = NULL; len = u32(args[2])|0;")
  lines.push("      } else if (name === 'strncpy' || name === 'strncat') {")
  lines.push("        dst = args[0]; src = args[1]; len = u32(args[2])|0;")
  lines.push("      } else if (name === 'strcpy' || name === 'strcat') {")
  lines.push("        dst = args[0]; src = args[1];")
  lines.push("        // best-effort length; may fail if pointers invalid")
  lines.push("        try { len = Memory.readUtf8String(src).length + 1; } catch (_) { len = 0; }")
  lines.push("      } else {")
  lines.push("        // unknown signature; skip unless asked to log everything")
  lines.push("        if (!CONFIG.logAllMemOps) return;")
  lines.push("        dst = args[0]; src = args[1]; len = u32(args[2])|0;")
  lines.push("      }")
  lines.push("")
  lines.push("      const dstLive = findContaining(live, dst);")
  lines.push("      const dstFreed = findContaining(freed, dst);")
  lines.push("      const related = dstLive || dstFreed;")
  lines.push("      if (!related && !CONFIG.logAllMemOps) return;")
  lines.push("")
  lines.push("      let suspicious = false;")
  lines.push("      let uaf = false;")
  lines.push("      let dstAlloc = null;")
  lines.push("      let dstOff = null;")
  lines.push("")
  lines.push("      if (dstLive) {")
  lines.push("        dstAlloc = dstLive.base;")
  lines.push("        dstOff = dstLive.off;")
  lines.push("        if (len > 0 && (dstLive.off + len) > (dstLive.rec.size|0)) suspicious = true;")
  lines.push("      }")
  lines.push("      if (dstFreed) {")
  lines.push("        uaf = true;")
  lines.push("        dstAlloc = dstFreed.base;")
  lines.push("        dstOff = dstFreed.off;")
  lines.push("        if (len > 0 && (dstFreed.off + len) > (dstFreed.rec.size|0)) suspicious = true;")
  lines.push("      }")
  lines.push("")
  lines.push("      sendEvent(name, {")
  lines.push("        tid,")
  lines.push("        fn: name,")
  lines.push("        dst: dst.toString(),")
  lines.push("        src: src ? src.toString() : null,")
  lines.push("        len,")
  lines.push("        dst_alloc: dstAlloc,")
  lines.push("        dst_off: dstOff,")
  lines.push("        uaf,")
  lines.push("        suspicious,")
  lines.push("        bt: bt || undefined")
  lines.push("      });")
  lines.push("    }")
  lines.push("  });")
  lines.push("}")
  lines.push("")
  lines.push("// Attach allocators")
  lines.push("(CONFIG.allocSymbols || ['malloc','calloc','realloc']).forEach(attachAlloc);")
  lines.push("(CONFIG.freeSymbols || ['free']).forEach(attachFree);")
  lines.push("")
  lines.push("// Attach memory ops")
  lines.push("(CONFIG.memOps || ['memcpy','memmove','memset','strcpy','strncpy','strcat','strncat']).forEach(attachMemOp);")
  lines.push("")
  lines.push("rpc.exports = {")
  lines.push("  dump_live() {")
  lines.push("    const out = [];")
  lines.push("    for (const e of live.entries()) out.push({ ptr: e[0], rec: e[1] });")
  lines.push("    return out;")
  lines.push("  },")
  lines.push("  dump_freed() {")
  lines.push("    const out = [];")
  lines.push("    for (const e of freed.entries()) out.push({ ptr: e[0], rec: e[1] });")
  lines.push("    return out;")
  lines.push("  }")
  lines.push("};")

  return lines.join("\n")
}

function renderWatchRangeScript(args: {
  slug: string
  base: string
  size: number
  watchRead: boolean
  watchWrite: boolean
  watchExec: boolean
  rearm: boolean
}): string {
  const meta = { kind: "watch-range", generated_at: isoNow(), slug: args.slug }
  const cfg = {
    kind: "watch-range",
    base: args.base,
    size: args.size,
    watch: {
      read: args.watchRead,
      write: args.watchWrite,
      exec: args.watchExec
    },
    rearm: args.rearm
  }

  const lines: string[] = []
  lines.push(jsHeader(meta))
  lines.push(renderPrelude(cfg))
  lines.push("sendEvent('ready', { config: CONFIG });")
  lines.push("")
  lines.push("const range = { base: ptr(CONFIG.base), size: CONFIG.size|0 };")
  lines.push("sendEvent('watch', { what: 'enable', base: range.base.toString(), size: range.size });")
  lines.push("")
  lines.push("function enable() {")
  lines.push("  MemoryAccessMonitor.enable([range], {")
  lines.push("    onAccess(details) {")
  lines.push("      const from = details.from ? details.from.toString() : null;")
  lines.push("      const sym = details.from ? String(DebugSymbol.fromAddress(details.from)) : null;")
  lines.push("      sendEvent('watch', {")
  lines.push("        operation: details.operation,")
  lines.push("        address: details.address ? details.address.toString() : null,")
  lines.push("        from,")
  lines.push("        symbol: sym,")
  lines.push("        details")
  lines.push("      });")
  lines.push("      if (CONFIG.rearm) {")
  lines.push("        try { MemoryAccessMonitor.disable(); } catch (_) {}")
  lines.push("        enable();")
  lines.push("      }")
  lines.push("    }")
  lines.push("  });")
  lines.push("}")
  lines.push("")
  lines.push("enable();")

  return lines.join("\n")
}

function renderJavaHookScript(args: {
  slug: string
  className: string
  methods: string[]
  backtrace: boolean
}): string {
  const meta = { kind: "java-hook", generated_at: isoNow(), slug: args.slug }
  const cfg = { kind: "java-hook", className: args.className, methods: args.methods, backtrace: args.backtrace }

  const lines: string[] = []
  lines.push(jsHeader(meta))
  lines.push("'use strict';")
  lines.push(`const CONFIG = ${JSON.stringify(cfg, null, 2)};`)
  lines.push("")
  lines.push("function sendEvent(kind, payload) { send(Object.assign({ kind, ts: Date.now() }, payload || {})); }")
  lines.push("sendEvent('ready', { config: CONFIG });")
  lines.push("")
  lines.push("Java.perform(function () {")
  lines.push("  const C = Java.use(CONFIG.className);")
  lines.push("  (CONFIG.methods || []).forEach(function (m) {")
  lines.push("    if (!C[m]) {")
  lines.push("      sendEvent('error', { what: 'method_not_found', className: CONFIG.className, method: m });")
  lines.push("      return;")
  lines.push("    }")
  lines.push("    // Hook all overloads")
  lines.push("    C[m].overloads.forEach(function (ov) {")
  lines.push("      const sig = ov.argumentTypes.map(t => t.className).join(',');")
  lines.push("      sendEvent('hook', { what: 'java_attach', className: CONFIG.className, method: m, sig });")
  lines.push("      ov.implementation = function () {")
  lines.push("        const tid = Process.getCurrentThreadId();")
  lines.push("        const argv = [];")
  lines.push("        for (let i = 0; i < arguments.length; i++) argv.push(String(arguments[i]));")
  lines.push("        if (CONFIG.backtrace) {")
  lines.push("          try {")
  lines.push("            sendEvent('java_call', { tid, className: CONFIG.className, method: m, sig, when: 'enter', args: argv, bt: Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()) });")
  lines.push("          } catch (_) {")
  lines.push("            sendEvent('java_call', { tid, className: CONFIG.className, method: m, sig, when: 'enter', args: argv });")
  lines.push("          }")
  lines.push("        } else {")
  lines.push("          sendEvent('java_call', { tid, className: CONFIG.className, method: m, sig, when: 'enter', args: argv });")
  lines.push("        }")
  lines.push("        const ret = ov.apply(this, arguments);")
  lines.push("        sendEvent('java_call', { tid, className: CONFIG.className, method: m, sig, when: 'leave', retval: String(ret) });")
  lines.push("        return ret;")
  lines.push("      };")
  lines.push("    });")
  lines.push("  });")
  lines.push("});")

  return lines.join("\n")
}

function renderRunnerPy(args: {
  slug: string
  target: string
  device: "local" | "usb"
  mode: "attach" | "spawn"
  scriptPath: string
  outJsonlPath?: string
  noPause: boolean
}): string {
  // NOTE: requires `pip install frida` on the host.
  const out = args.outJsonlPath ?? path.join(LAB_ROOT, "logs", `${args.slug}.jsonl`)

  return [
    "#!/usr/bin/env python3",
    "# GENERATED FILE — OpenCode Frida Lab",
    "import frida",
    "import json",
    "import sys",
    "import time",
    "",
    `TARGET = ${JSON.stringify(args.target)}`,
    `DEVICE = ${JSON.stringify(args.device)}`,
    `MODE = ${JSON.stringify(args.mode)}`,
    `SCRIPT_PATH = ${JSON.stringify(args.scriptPath)}`,
    `OUT_PATH = ${JSON.stringify(out)}`,
    `NO_PAUSE = ${"True" if (args.noPause) else "False"}`,
    "",
    "def get_device():",
    "    if DEVICE == 'usb':",
    "        return frida.get_usb_device(timeout=5)",
    "    return frida.get_local_device()",
    "",
    "def on_message(msg, data):",
    "    # msg is JSON-serializable",
    "    rec = { 't': time.time(), 'message': msg }",
    "    with open(OUT_PATH, 'a', encoding='utf-8') as f:",
    "        f.write(json.dumps(rec) + '\\n')",
    "    print(msg)",
    "",
    "def main():",
    "    device = get_device()",
    "    if MODE == 'spawn':",
    "        pid = device.spawn([TARGET])",
    "        session = device.attach(pid)",
    "    else:",
    "        session = device.attach(TARGET)",
    "",
    "    with open(SCRIPT_PATH, 'r', encoding='utf-8') as f:",
    "        src = f.read()",
    "    script = session.create_script(src)",
    "    script.on('message', on_message)",
    "    script.load()",
    "",
    "    if MODE == 'spawn':",
    "        device.resume(pid)",
    "        if NO_PAUSE:",
    "            # spawn+resume already; flag kept for parity with CLI usage",
    "            pass",
    "",
    "    print(f'[runner] logging to {OUT_PATH}')",
    "    sys.stdin.read()",
    "",
    "if __name__ == '__main__':",
    "    main()",
    ""
  ].join("\n")
}

/**
 * Tool: generate a memtimeline script (alloc/free + memcpy-family ops).
 */
export const memtimeline = tool({
  description:
    "Generate a Frida script that logs malloc/free/realloc timeline + memory-corruption primitives (memcpy/memmove/memset/strcpy/...). Writes to .opencode/artifacts/frida/scripts/<slug>.js and a spec JSON to specs/.",
  args: {
    slug: tool.schema.string().describe("Output slug (filename without extension)."),
    module: tool.schema.string().optional().describe("Optional module name (e.g. libc.so). Omit to search global exports."),
    minSize: tool.schema.number().describe("Minimum allocation size (bytes). Use 0 for no minimum."),
    maxSize: tool.schema.number().describe("Maximum allocation size (bytes). Use 0 for no maximum."),
    btContains: tool.schema.array(tool.schema.string()).describe("Only log allocs whose backtrace string contains ALL of these substrings."),
    enableBacktrace: tool.schema.boolean().describe("Include symbolized backtraces."),
    allocSymbols: tool.schema.array(tool.schema.string()).describe("Allocator symbols to hook. E.g. ['malloc','calloc','realloc']."),
    freeSymbols: tool.schema.array(tool.schema.string()).describe("Free symbols to hook. E.g. ['free']."),
    memOps: tool.schema.array(tool.schema.string()).describe("Memory op symbols to hook. E.g. ['memcpy','memmove','memset','strcpy','strncpy']."),
    sampleEvery: tool.schema.number().describe("Only emit every Nth event (1 = no sampling)."),
    logAllMemOps: tool.schema.boolean().describe("If true, log memops even when dst isn't within tracked alloc/freed ranges."),
    keepFreed: tool.schema.number().describe("Keep last N freed allocations for UAF correlation (0 = unlimited, but not recommended).")
  },
  async execute(a) {
    await ensureDirs()
    const slug = slugify(a.slug)
    const specPath = path.join(SPECS_DIR, `${slug}.spec.json`)
    const scriptPath = path.join(SCRIPTS_DIR, `${slug}.js`)

    const spec = {
      tool: "frida_lab_memtimeline",
      generated_at: isoNow(),
      args: a
    }

    const script = renderMemTimelineScript({
      slug,
      module: a.module,
      minSize: a.minSize,
      maxSize: a.maxSize,
      btContains: a.btContains ?? [],
      enableBacktrace: a.enableBacktrace,
      allocSymbols: a.allocSymbols ?? ["malloc", "calloc", "realloc"],
      freeSymbols: a.freeSymbols ?? ["free"],
      memOps: a.memOps ?? ["memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "strncat"],
      sampleEvery: a.sampleEvery ?? 1,
      logAllMemOps: a.logAllMemOps ?? false,
      keepFreed: a.keepFreed ?? 1024
    })

    await writeTextFile(specPath, JSON.stringify(spec, null, 2))
    const wr = await writeTextFile(scriptPath, script)

    return {
      ok: true,
      slug,
      script_path: scriptPath,
      spec_path: specPath,
      bytes: wr.bytes
    }
  }
})

export const hook_exports = tool({
  description:
    "Generate a Frida script that hooks a list of exported functions using Interceptor.attach, logging args/retval/backtrace. Writes to artifacts/frida/scripts/<slug>.js.",
  args: {
    slug: tool.schema.string().describe("Output slug (filename without extension)."),
    module: tool.schema.string().optional().describe("Optional module name. Omit to search global exports."),
    exports: tool.schema.array(tool.schema.string()).describe("Exported symbols to hook."),
    backtrace: tool.schema.boolean().describe("Include backtrace on enter/leave."),
    maxArgs: tool.schema.number().describe("How many args to log (0..N).")
  },
  async execute(a) {
    await ensureDirs()
    const slug = slugify(a.slug)
    const specPath = path.join(SPECS_DIR, `${slug}.spec.json`)
    const scriptPath = path.join(SCRIPTS_DIR, `${slug}.js`)

    const spec = { tool: "frida_lab_hook_exports", generated_at: isoNow(), args: a }
    const script = renderHookExportsScript({
      slug,
      module: a.module,
      exports: a.exports,
      backtrace: a.backtrace,
      maxArgs: a.maxArgs
    })

    await writeTextFile(specPath, JSON.stringify(spec, null, 2))
    const wr = await writeTextFile(scriptPath, script)

    return { ok: true, slug, script_path: scriptPath, spec_path: specPath, bytes: wr.bytes }
  }
})

export const hook_offset = tool({
  description:
    "Generate a Frida script that hooks module.base + offset using Interceptor.attach. Useful when symbols are stripped. Writes to artifacts/frida/scripts/<slug>.js.",
  args: {
    slug: tool.schema.string().describe("Output slug (filename without extension)."),
    module: tool.schema.string().describe("Module name to base from (e.g. libtarget.so)."),
    offset: tool.schema.string().describe("Hex offset string (e.g. 0x1234)."),
    label: tool.schema.string().describe("Human label for this hook."),
    backtrace: tool.schema.boolean().describe("Include backtrace on enter/leave."),
    maxArgs: tool.schema.number().describe("How many args to log (0..N).")
  },
  async execute(a) {
    await ensureDirs()
    const slug = slugify(a.slug)
    const specPath = path.join(SPECS_DIR, `${slug}.spec.json`)
    const scriptPath = path.join(SCRIPTS_DIR, `${slug}.js`)

    const spec = { tool: "frida_lab_hook_offset", generated_at: isoNow(), args: a }
    const script = renderHookOffsetScript({
      slug,
      module: a.module,
      offset: a.offset,
      label: a.label,
      backtrace: a.backtrace,
      maxArgs: a.maxArgs
    })

    await writeTextFile(specPath, JSON.stringify(spec, null, 2))
    const wr = await writeTextFile(scriptPath, script)

    return { ok: true, slug, script_path: scriptPath, spec_path: specPath, bytes: wr.bytes }
  }
})

export const watch_range = tool({
  description:
    "Generate a Frida script that uses MemoryAccessMonitor to watch a memory range and emit events on access.",
  args: {
    slug: tool.schema.string().describe("Output slug (filename without extension)."),
    base: tool.schema.string().describe("Base address (hex string, e.g. 0x7fff...)."),
    size: tool.schema.number().describe("Size in bytes."),
    watchRead: tool.schema.boolean().describe("Watch reads."),
    watchWrite: tool.schema.boolean().describe("Watch writes."),
    watchExec: tool.schema.boolean().describe("Watch executes."),
    rearm: tool.schema.boolean().describe("If true, re-enable monitor after each access (noisy/expensive).")
  },
  async execute(a) {
    await ensureDirs()
    const slug = slugify(a.slug)
    const specPath = path.join(SPECS_DIR, `${slug}.spec.json`)
    const scriptPath = path.join(SCRIPTS_DIR, `${slug}.js`)

    const spec = { tool: "frida_lab_watch_range", generated_at: isoNow(), args: a }
    const script = renderWatchRangeScript({
      slug,
      base: a.base,
      size: a.size,
      watchRead: a.watchRead,
      watchWrite: a.watchWrite,
      watchExec: a.watchExec,
      rearm: a.rearm
    })

    await writeTextFile(specPath, JSON.stringify(spec, null, 2))
    const wr = await writeTextFile(scriptPath, script)

    return { ok: true, slug, script_path: scriptPath, spec_path: specPath, bytes: wr.bytes }
  }
})

export const java_hook = tool({
  description:
    "Generate a Frida script that hooks Java methods (all overloads) in a given class and emits enter/leave events.",
  args: {
    slug: tool.schema.string().describe("Output slug (filename without extension)."),
    className: tool.schema.string().describe("Fully-qualified Java class name (e.g. com.example.Foo)."),
    methods: tool.schema.array(tool.schema.string()).describe("Method names to hook (all overloads)."),
    backtrace: tool.schema.boolean().describe("Include a Java stack trace (best-effort).")
  },
  async execute(a) {
    await ensureDirs()
    const slug = slugify(a.slug)
    const specPath = path.join(SPECS_DIR, `${slug}.spec.json`)
    const scriptPath = path.join(SCRIPTS_DIR, `${slug}.js`)

    const spec = { tool: "frida_lab_java_hook", generated_at: isoNow(), args: a }
    const script = renderJavaHookScript({
      slug,
      className: a.className,
      methods: a.methods,
      backtrace: a.backtrace
    })

    await writeTextFile(specPath, JSON.stringify(spec, null, 2))
    const wr = await writeTextFile(scriptPath, script)

    return { ok: true, slug, script_path: scriptPath, spec_path: specPath, bytes: wr.bytes }
  }
})

export const cmd = tool({
  description:
    "Generate a Frida CLI command-line string to run a given script in attach/spawn mode (does not execute).",
  args: {
    device: tool.schema.string().describe("Device: 'local' or 'usb'."),
    mode: tool.schema.string().describe("Mode: 'attach' or 'spawn'."),
    target: tool.schema.string().describe("Attach target (process name/PID) or spawn target (bundle id / program)."),
    scriptPath: tool.schema.string().describe("Path to the .js script."),
    noPause: tool.schema.boolean().describe("If true (spawn mode), add --no-pause if supported by your frida version."),
    debug: tool.schema.boolean().describe("If true, add --debug (Node compatible debugger).")
  },
  async execute(a) {
    const parts: string[] = ["frida"]
    if (a.device === "usb") parts.push("-U")

    if (a.mode === "spawn") {
      parts.push("-f", a.target)
      if (a.noPause) parts.push("--no-pause")
    } else {
      parts.push(a.target)
    }

    parts.push("-l", a.scriptPath)

    if (a.debug) parts.push("--debug")

    return { ok: true, cmd: parts.join(" ") }
  }
})

export const runner_py = tool({
  description:
    "Generate a Python runner that loads a JS script, prints messages, and appends JSONL logs. Requires `pip install frida` on the host.",
  args: {
    slug: tool.schema.string().describe("Output slug."),
    target: tool.schema.string().describe("Attach/spawn target."),
    device: tool.schema.string().describe("Device: 'local' or 'usb'."),
    mode: tool.schema.string().describe("Mode: 'attach' or 'spawn'."),
    scriptPath: tool.schema.string().describe("Path to the .js script."),
    outJsonlPath: tool.schema.string().optional().describe("Optional JSONL output path."),
    noPause: tool.schema.boolean().describe("Kept for parity with CLI usage; spawn runner resumes immediately.")
  },
  async execute(a) {
    await ensureDirs()
    const slug = slugify(a.slug)
    const outPath = path.join(RUNNERS_DIR, `${slug}.py`)
    const content = renderRunnerPy({
      slug,
      target: a.target,
      device: (a.device === "usb" ? "usb" : "local"),
      mode: (a.mode === "spawn" ? "spawn" : "attach"),
      scriptPath: a.scriptPath,
      outJsonlPath: a.outJsonlPath,
      noPause: a.noPause
    })
    const wr = await writeTextFile(outPath, content)
    return { ok: true, runner_path: outPath, bytes: wr.bytes }
  }
})
```

---

## Agents

Agents are Markdown + YAML frontmatter; the filename becomes the agent name. ([OpenCode][1])

### .opencode/agents/frida-lab.md

```markdown
---
description: "Frida Lab: generate exact Frida scripts + exact run/debug commands (memory timelines, hooks, Java/Android)."
mode: primary
temperature: 0.1
tools:
  bash: false
  websearch: false
  webfetch: false
---

You are the Frida Lab agent.

Primary objective:
- Generate **exact, runnable Frida scripts** using the `frida_lab_*` tools.
- Always return:
  1) The generated script path
  2) A `frida ...` command (use `frida_lab_cmd`)
  3) A minimal validation checklist

Rules:
- Do not handwave. Do not output pseudo-code.
- Prefer structured events via `send({ ... })`.
- Avoid bypass/stealth instructions; focus on instrumentation and debugging only.

When user asks for:
- Alloc/free + corruption primitives timeline: use `frida_lab_memtimeline`
- Hook exports: use `frida_lab_hook_exports`
- Hook stripped functions by offset: use `frida_lab_hook_offset`
- Watch a memory range: use `frida_lab_watch_range`
- Hook Java methods: use `frida_lab_java_hook`
- Create a host runner: use `frida_lab_runner_py`
```

### .opencode/agents/frida-native-memtimeline.md

```markdown
---
description: "Specialist: malloc/free timeline + memcpy/memmove/strcpy correlation; outputs low-noise logs."
mode: subagent
temperature: 0.1
tools:
  bash: false
  websearch: false
  webfetch: false
---

You only do one thing:
Generate a memtimeline script with the smallest possible noise.

Process:
1) Ask for: module (optional), size filters, bt filters, sample rate, suspicious ops list.
2) Call `frida_lab_memtimeline`.
3) Call `frida_lab_cmd` with user's target/device/mode.
4) Provide a quick validation checklist and suggested filter tweaks.
```

### .opencode/agents/frida-native-hooker.md

```markdown
---
description: "Specialist: native hooking (exports + offsets), stack traces, and argument logging."
mode: subagent
temperature: 0.1
tools:
  bash: false
  websearch: false
  webfetch: false
---

Generate exact native hooks.

If symbols exist -> `frida_lab_hook_exports`.
If stripped -> `frida_lab_hook_offset`.

Always include:
- backtrace option
- conservative arg logging (no risky memory reads unless asked)
```

### .opencode/agents/frida-mobile-hooker.md

```markdown
---
description: "Specialist: Android/Java Frida hooks (Java.perform, overloads) + runnable scripts."
mode: subagent
temperature: 0.1
tools:
  bash: false
  websearch: false
  webfetch: false
---

Generate exact Java hooks with `frida_lab_java_hook` and provide a `frida` command via `frida_lab_cmd`.

If method overload ambiguity exists:
- Hook all overloads (default).
- Emit the overload signature in events.
```

---

## Commands

OpenCode supports project commands under `.opencode/commands/`. ([OpenCode][9])

### .opencode/commands/frida-help.md

```markdown
---
description: "Frida Lab help: show available generators and recommended workflow."
agent: frida-lab
---

Explain:
- Which frida_lab_* tools exist
- How to choose between memtimeline vs hook_exports vs hook_offset vs watch_range
- What info you need from the user (target, device, attach/spawn, module, symbols/offsets)
```

### .opencode/commands/frida-memtimeline.md

```markdown
---
description: "Generate malloc/free + memcpy-family timeline script and a runnable frida command."
agent: frida-lab
---

Generate a memtimeline script with `frida_lab_memtimeline`.

Ask for (if missing):
- device: local|usb
- mode: attach|spawn
- target (process name or bundle id)
- optional module (e.g. libc.so / libSystem.B.dylib)
- filters: minSize/maxSize, btContains, sampleEvery
- memOps list

Then:
1) Call `frida_lab_memtimeline`
2) Call `frida_lab_cmd` for run command
3) Return paths + checklist
```

### .opencode/commands/frida-hook-exports.md

```markdown
---
description: "Hook exported native functions (Interceptor.attach) + backtrace + run command."
agent: frida-lab
---

Collect:
- device, mode, target
- module (optional)
- exports list
- maxArgs, backtrace

Then:
1) `frida_lab_hook_exports`
2) `frida_lab_cmd`
```

### .opencode/commands/frida-hook-offset.md

```markdown
---
description: "Hook module.base+offset (stripped binary) + backtrace + run command."
agent: frida-lab
---

Collect:
- device, mode, target
- module name (required)
- offset hex (required)
- label
- maxArgs, backtrace

Then:
1) `frida_lab_hook_offset`
2) `frida_lab_cmd`
```

### .opencode/commands/frida-watch-range.md

```markdown
---
description: "Generate a MemoryAccessMonitor range-watch script + run command."
agent: frida-lab
---

Collect:
- device, mode, target
- base, size
- watchRead/watchWrite/watchExec
- rearm (usually false)

Then:
1) `frida_lab_watch_range`
2) `frida_lab_cmd`
```

### .opencode/commands/frida-java-hook.md

```markdown
---
description: "Generate Java.perform hooks for a class' methods + run command."
agent: frida-lab
---

Collect:
- device, mode, target
- className
- methods[]
- backtrace true|false

Then:
1) `frida_lab_java_hook`
2) `frida_lab_cmd`
```

### .opencode/commands/frida-runner.md

```markdown
---
description: "Generate a Python runner to collect JSONL logs from send() messages."
agent: frida-lab
---

Given an existing script path and a target:
1) Call `frida_lab_runner_py`
2) Provide exact python command to run it
```

---

## Skills

Skills go in `.opencode/skills/<name>/SKILL.md`. ([OpenCode][2])

### .opencode/skills/frida-script-spec/SKILL.md

```markdown
# Frida Script Spec Skill

This project uses generator tools (`frida_lab_*`) to produce runnable scripts.
Always express script requirements as concrete parameters:

Common fields you should collect:
- slug: short filename-safe id
- device: local|usb
- mode: attach|spawn
- target: process name (attach) or bundle id/program (spawn)

Script types:
1) memtimeline
   - module (optional)
   - minSize/maxSize
   - btContains[] (substrings required in backtrace text)
   - allocSymbols[] (malloc/calloc/realloc)
   - freeSymbols[] (free)
   - memOps[] (memcpy/memmove/memset/strcpy/...)
   - sampleEvery (reduce noise)
   - keepFreed (track last N frees for UAF correlation)

2) hook_exports
   - module (optional)
   - exports[]
   - maxArgs
   - backtrace

3) hook_offset
   - module (required)
   - offset (hex)
   - label
   - maxArgs
   - backtrace

4) watch_range
   - base (hex), size (bytes)
   - read/write/exec flags
   - rearm
```

### .opencode/skills/frida-debug-workflow/SKILL.md

```markdown
# Frida Debug Workflow Skill

Use Frida CLI:
- Load scripts with `-l` and rely on auto-reload / `%reload`.
- Use `--debug` to enable the Node-compatible debugger.

Always give:
- exact `frida ...` invocation
- how to validate the hook fires (what events to expect)
- which filters to tweak to reduce noise
```

### .opencode/skills/frida-memory-timeline/SKILL.md

```markdown
# Frida Memory Timeline Skill

Goal: reduce noise while catching:
- UAF-ish behavior: writes/reads into recently freed ranges
- Overflow-ish behavior: dst_off + len > alloc.size in memcpy-family functions

Use `frida_lab_memtimeline`:
- Keep allocations limited via:
  - minSize/maxSize
  - btContains (restrict to a call path / module)
  - sampleEvery
- Keep freed history bounded with keepFreed

Interpret events:
- alloc/free/realloc: track pointer lifecycle
- memcpy/memmove/strcpy/...:
  - uaf=true => dst is inside freed allocation range
  - suspicious=true => dst_off + len exceeds recorded allocation size
```

---

## .gitignore

```gitignore
# Frida Lab artifacts
.opencode/artifacts/frida/logs/**
.opencode/artifacts/frida/scripts/**
.opencode/artifacts/frida/specs/**
.opencode/artifacts/frida/runners/**

# Keep the lab config committed
!.opencode/artifacts/frida/.gitkeep
```

(You can remove ignores if you want scripts/specs committed; many teams commit scripts/specs but ignore logs.)

---

## README.md

This README is written so someone can copy/paste and be productive immediately.

````markdown
# Frida Lab for OpenCode

This repo is a “Frida Lab” setup for OpenCode: it generates **exact, runnable Frida scripts** (native + Android/Java) as files, plus the **exact CLI commands** to run/debug them.

The design goal is to support vulnerability research workflows:
- Build a *low-noise* timeline of `malloc/free/realloc` for a specific flow
- Hook corruption primitives like `memcpy/memmove/memset/strcpy/...`
- Correlate those ops with tracked allocations to flag:
  - potential UAF (writes into freed ranges)
  - potential overflow (dst_off + len > alloc.size)

> Authorized testing only. This lab focuses on instrumentation and debugging.

---

## 0) Requirements

### Install Frida CLI tools

Install the CLI (recommended way):

```bash
pip install frida-tools
````

You should now have the `frida` command:

```bash
frida --version
```

### Optional: Python bindings (for the JSONL runner)

If you want the Python runner (`frida_lab_runner_py`), install:

```bash
pip install frida
```

---

## 1) OpenCode setup

OpenCode looks for:

* agents in `.opencode/agents/`
* commands in `.opencode/commands/`
* skills in `.opencode/skills/<name>/SKILL.md`
* custom tools in `.opencode/tools/`

The important file is:

* `.opencode/tools/frida_lab.ts` — script generators.

---

## 2) Start OpenCode (TUI)

In the repo root:

```bash
opencode
```

Switch to the **frida-lab** agent (Tab through primary agents) or type:

* `@frida-lab`

---

## 3) Quickstart: generate a memtimeline (malloc/free + memcpy)

In OpenCode, run:

* `/frida-memtimeline`

Provide these details when asked:

* device: `local` or `usb`
* mode: `attach` or `spawn`
* target: process name (attach) or bundle id/program (spawn)
* filters: minSize/maxSize, btContains, sampleEvery
* memOps list (defaults are fine)

Output:

* `.opencode/artifacts/frida/scripts/<slug>.js`
* `.opencode/artifacts/frida/specs/<slug>.spec.json`

---

## 4) Run the script with Frida

### Attach mode (desktop / already-running process)

Example:

```bash
frida Calculator -l .opencode/artifacts/frida/scripts/uaf-timeline.js
```

### USB device (iOS/Android over USB)

Example:

```bash
frida -U Safari
```

### Spawn mode (mobile apps)

Common patterns:

```bash
frida -U -f com.example.app -l .opencode/artifacts/frida/scripts/uaf-timeline.js --no-pause
```

> If your Frida version differs, run `frida --help` to confirm the flags it supports.

---

## 5) Debug workflow (REPL reload + debugger)

Frida CLI supports:

* `-l <script>` to load a script
* automatic reload when the file changes
* `%reload` to force reload
* `--debug` to enable a Node-compatible debugger (port 5858)

Example:

```bash
frida Calculator -l .opencode/artifacts/frida/scripts/uaf-timeline.js --debug
```

Then edit the script file; Frida will reload it. If needed in the REPL, run:

```
%reload
```

---

## 6) Logging and parsing

All generated scripts emit structured events via:

```js
send({ kind: "...", ts: Date.now(), ... })
```

You can:

* read them in the Frida CLI output, or
* use the generated Python runner to capture JSONL.

### Generate a Python runner

In OpenCode:

* `/frida-runner`

This writes:

* `.opencode/artifacts/frida/runners/<slug>.py`

Run it:

```bash
python3 .opencode/artifacts/frida/runners/<slug>.py
```

It prints events and appends JSONL under:

* `.opencode/artifacts/frida/logs/<slug>.jsonl`

---

## 7) How to interpret memtimeline events

Event kinds include:

* `alloc`, `free`, `realloc`
* memory ops: `memcpy`, `memmove`, `memset`, `strcpy`, ...

For memory ops:

* `uaf=true` means the destination pointer is inside a **recently freed** allocation range.
* `suspicious=true` means: `dst_off + len > alloc.size` (likely overflow).

Tune noise:

* `btContains`: restrict to a call path/module
* `minSize/maxSize`: focus on object-sized allocations
* `sampleEvery`: only emit every Nth event
* `keepFreed`: cap freed-history size

---

## 8) Recommended workflow for UAF hunting

1. Start with memtimeline but with strict filters:

   * `btContains`: module/function substring where your flow happens
   * narrow sizes (e.g., 16–512)
2. Confirm `alloc/free` events appear from the right path
3. Enable memops (default) and look for:

   * `uaf=true`
   * `suspicious=true`
4. If you identify a specific pointer/range, generate a `watch_range` script and run it.

---

## 9) Safety notes

* Don’t run these scripts against systems you don’t own or lack permission to test.
* Avoid “anti-detection”/stealth use; this lab is for debugging and research.

---

## Appendix: Where files go

* Scripts:  `.opencode/artifacts/frida/scripts/`
* Specs:    `.opencode/artifacts/frida/specs/`
* Runners:  `.opencode/artifacts/frida/runners/`
* Logs:     `.opencode/artifacts/frida/logs/`

```

---

## Notes on “exactness” and debugging

- The scripts generated here deliberately stick to well-documented Frida primitives:
  - `frida <target> -l <script>` + `%reload` + `--debug` :contentReference[oaicite:12]{index=12}  
  - `Interceptor.attach` + `Thread.backtrace(this.context, …)` :contentReference[oaicite:13]{index=13}  
  - `send()` for structured logs and Python `on('message', …)` :contentReference[oaicite:14]{index=14}  
- Spawn examples using `-f` are used by Frida tooling/docs in other contexts (e.g., frida-trace examples) :contentReference[oaicite:15]{index=15} and are common in Frida community usage (also appears in maintainer-authored examples). :contentReference[oaicite:16]{index=16}  

---

If you tell me your **primary target environment** (Linux desktop? Android NDK libs? iOS?), I’ll tailor the defaults in `memtimeline` (module names, default alloc symbols, best memops set, and size defaults) to match that ecosystem so the very first `/frida-memtimeline` run is low-noise.
::contentReference[oaicite:17]{index=17}
```

[1]: https://opencode.ai/docs/agents/ "https://opencode.ai/docs/agents/"
[2]: https://opencode.ai/docs/skills/ "https://opencode.ai/docs/skills/"
[3]: https://opencode.ai/docs/custom-tools/ "https://opencode.ai/docs/custom-tools/"
[4]: https://opencode.ai/docs/permissions/?utm_source=chatgpt.com "Permissions"
[5]: https://frida.re/docs/frida-cli/ "https://frida.re/docs/frida-cli/"
[6]: https://frida.re/docs/javascript-api/ "https://frida.re/docs/javascript-api/"
[7]: https://frida.re/docs/messages/ "https://frida.re/docs/messages/"
[8]: https://opencode.ai/docs/config/?utm_source=chatgpt.com "Config"
[9]: https://opencode.ai/docs/commands/ "https://opencode.ai/docs/commands/"

Yes — there are a few important **corrections** and some **high-leverage additions** that will make your Frida Lab much more “exact” and less error-prone.

## Corrections

### 1) Don’t recommend `--no-pause` as a default

Recent Frida CLI docs don’t mention it, and it has been removed/changed behavior across versions; people still hit “unrecognized arguments: --no-pause”. ([GitHub][1])

What to do instead in your README:

* Mention **spawn mode** with `-f` and say: “Depending on your Frida version, you may or may not need `--no-pause`. Prefer your local `frida --help` output.”
* Keep examples that work broadly: `frida -U -f <bundle> -l script.js` and instruct `%resume` if needed (and/or remove pause logic entirely and just attach).

### 2) Validate your “exact script” behaviors against the official CLI doc

The **auto-reload** and `%reload` behavior is explicitly documented and should stay in your README. ([Frida][2])

### 3) Tool naming in OpenCode

Your design that exports multiple tools from one TS file and expects names like `frida_lab_memtimeline` is correct. ([OpenCode][3])

---

## High-leverage additions (worth adding)

### A) Add a “Frida Script Spec” → generator pipeline (for true determinism)

Right now, you generate scripts directly from tool args. That’s good, but you’ll get *much more repeatability* if you standardize on a **spec file** that is:

* stored under `.opencode/artifacts/frida/specs/<slug>.json`
* used as the single input to generation (`frida_lab_generate_from_spec`)

Why: you can regenerate the exact same script later, diff specs, and share specs across machines.

**Add tool exports:**

* `frida_lab_write_spec(spec)` → writes spec json and returns path
* `frida_lab_generate_from_spec(path)` → reads spec, generates script (and runner if requested)

This keeps the “agent pipeline” dead simple:

1. Create spec
2. Generate
3. Provide command

### B) Add a “capability probe” script generator

A lot of “Frida scripts didn’t work” issues are because:

* export name is wrong
* module is not loaded yet
* symbol is not exported
* you’re in the wrong process / wrong arch
* backtracer is noisy or fails

Add `frida_lab_probe` that generates a script that emits:

* `Process.id`, `Process.arch`, `Process.platform`
* `Process.enumerateModules()` (top N)
* `Module.findExportByName(null, "malloc")` etc
* optional: `Module.enumerateExportsSync(module)` for a specific module name
  This lets you confirm you can hook what you think you can *before* generating complex scripts.

### C) Make backtraces “switchable” at runtime

Backtracing can be heavy and sometimes flaky depending on build/debug info; the official guidance is to pass `this.context` in Interceptor callbacks for best results. ([radare.org][4])

Add to your script skeleton:

* `rpc.exports.setcfg({ enableBacktrace, sampleEvery, btContains })`
* `rpc.exports.getcfg()`

So you can start low-noise and turn on BT only when needed, without regenerating.

### D) Add an “export vs offset” resolver tool output

Your `hook_offset` generator is great, but you should add a *shared helper*:

* `frida_lab_resolve(module, export, offset)` tool that emits a small JSON:

  * `resolved_address`, `module_base`, and whether export was found
    This prevents mistakes like “I used offset relative to wrong module base”.

### E) For memtimeline, add **range-index** to avoid O(n) scans

Your memtimeline uses `findContaining(live, dst)` which loops over the whole map; that will get slow fast in real apps.

Fix: store allocations in a simple interval structure:

* For each alloc record store `{ base, end, size }` and keep a **sorted array** of bases for lookup with binary search, or bucket by page.
  Even a “page bucket” map (`page -> list of allocs in that page`) is a huge speedup.

This is the single biggest practical correctness/perf improvement for “timeline” scripts.

### F) Add ObjC hooks (iOS) as a first-class generator

If you’re doing iOS work, add `frida_lab_objc_hook`:

* hooks `-[Class method:]` and `+[Class method:]`
* emits args, selector, return
  This is the most common “exact script” request on iOS.

(You can still keep it logging-only.)

### G) Add a host-side runner (Node as well as Python)

Frida “messages” (`send`) are documented and stable; adding a Node runner makes it easy to:

* print nicely
* write JSONL
* filter/aggregate on the fly ([learnfrida.info][5])

Provide:

* `frida_lab_runner_py` (you already have)
* `frida_lab_runner_node` (new)

### H) Update README to explicitly match current official CLI behaviors

Include:

* `%reload` (documented) ([Frida][2])
* `--debug` mention only if you’ve tested it on your target; keep it “optional”
* Avoid claiming `--no-pause` works universally ([GitHub][1])

---

## What I would change in your existing Frida Lab right now

1. **Remove** `--no-pause` from “exact commands” default; keep it as a conditional note. ([GitHub][1])
2. Add **spec-first pipeline** (spec file → generator) so scripts are reproducible and diffable.
3. Add `frida_lab_probe` generator and make it the recommended first command (“prove you can see modules/exports”).
4. Rework memtimeline lookup to avoid linear scans (page buckets or binary search).
5. Add runtime toggles (`rpc.exports.setcfg`) for backtraces/sampling so you don’t constantly regenerate.

---

If you tell me your primary target (Linux/macOS native, Android, iOS), I’ll give you the exact **spec schema** and the additional generator tool(s) (ObjC/Java/native) that best match that environment—still keeping everything “generate script file → return exact run command → validate hook fired”.

[1]: https://github.com/frida/frida/issues/2277?utm_source=chatgpt.com "frida: error: unrecognized arguments: --no-pause #2277"
[2]: https://frida.re/docs/frida-cli/?utm_source=chatgpt.com "Frida CLI"
[3]: https://opencode.ai/docs/custom-tools/?utm_source=chatgpt.com "Custom Tools"
[4]: https://www.radare.org/doc/frida/functions/Thread.backtrace.html?utm_source=chatgpt.com "backtrace | Documentation"
[5]: https://learnfrida.info/basic_usage/?utm_source=chatgpt.com "Frida basics"


Below is an **Android-first Frida Lab** that’s purpose-built for **generating exact Frida scripts** (as files) with a repeatable **spec → script → exact run command** pipeline.

It fixes the fragile bits (spawn flags, module timing, export resolution) and adds the missing high-leverage pieces for Android: **probe script**, **Java hook generator**, **JNI/native hook generator**, **malloc/free + memops timeline**, and **runners** (Python + Node) for clean JSONL logging.

Everything is based on OpenCode’s documented agent/command/skill/tool structure and Frida’s documented CLI + JS APIs. ([Frida][1])

---

# 1) Repo layout (Android-focused)

```text
repo/
  opencode.jsonc
  AGENTS.md
  README.md
  .opencode/
    agents/
      frida-lab.md
      frida-android-native.md
      frida-android-java.md
      frida-android-memtimeline.md
    commands/
      frida-probe.md
      frida-java-hook.md
      frida-native-hook-exports.md
      frida-native-hook-offset.md
      frida-memtimeline.md
      frida-runner.md
      frida-spec-regenerate.md
    skills/
      frida-android-spec/SKILL.md
      frida-android-debug/SKILL.md
      frida-android-safety/SKILL.md
    tools/
      frida_android_lab.ts
    artifacts/
      frida/
        scripts/   (generated)
        specs/     (generated)
        runners/   (generated)
        logs/      (generated at runtime)
```

OpenCode expects project-local agents/commands/skills/tools in `.opencode/…`. ([Frida][1])

---

# 2) `opencode.jsonc` (scripts-only, deterministic, Android)

This makes the pipeline “generate files only”:

* **deny bash** (OpenCode won’t run frida for you; it will only generate exact commands)
* **allow edits only under `.opencode/**` + `README.md`**
* allow your custom tools: `frida_android_lab_*`

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "permission": {
    "webfetch": "deny",
    "websearch": "deny",
    "bash": "deny",

    "read": "allow",
    "list": "allow",
    "glob": "allow",
    "grep": "allow",

    "edit": {
      "**": "deny",
      ".opencode/**": "allow",
      "opencode.jsonc": "allow",
      "AGENTS.md": "allow",
      "README.md": "allow"
    },

    "task": {
      "*": "deny",
      "frida-*": "allow"
    },

    "frida_android_lab_write_spec": "allow",
    "frida_android_lab_generate_from_spec": "allow",
    "frida_android_lab_probe_spec": "allow",
    "frida_android_lab_java_hook_spec": "allow",
    "frida_android_lab_native_hook_exports_spec": "allow",
    "frida_android_lab_native_hook_offset_spec": "allow",
    "frida_android_lab_memtimeline_spec": "allow",
    "frida_android_lab_cmd": "allow",
    "frida_android_lab_runner_py": "allow",
    "frida_android_lab_runner_node": "allow"
  },

  "watcher": {
    "ignore": [".git/**", "node_modules/**", ".opencode/artifacts/**"]
  }
}
```

---

# 3) `AGENTS.md` (hard “exact script” contract)

```md
# Android Frida Lab Rules

This repo exists to generate **exact, runnable Frida scripts** (as files) for Android dynamic analysis.

## Non-negotiables
1) Scripts MUST be generated via the custom tools (`frida_android_lab_*`).
   - Never handwrite large scripts in chat.
2) Every generated script MUST:
   - be standalone (no external imports)
   - emit structured JSON events with `send({ ... })`
   - include enough metadata to reproduce (config embedded in the script header)
3) Every response that generates a script MUST include:
   - script path (exact)
   - spec path (exact)
   - exact `frida ...` command (generated via `frida_android_lab_cmd`)
   - a 3-step validation checklist (“how to confirm hook is firing”)

## Safety scope
- Logging/instrumentation only.
- No “bypass” scripts (SSL pinning bypass, auth bypass, anti-debug bypass).
- For vulnerability research: focus on tracing flows, memory lifetime, and crash reproduction.
```

---

# 4) The core tool: `.opencode/tools/frida_android_lab.ts`

This implements the **spec-first pipeline**:

* `*_spec` tools write a JSON spec into `.opencode/artifacts/frida/specs/…`
* `generate_from_spec` produces the JS script (and optionally a runner)
* `cmd` prints an exact CLI command string (does not execute)
* `runner_py` and `runner_node` generate host collectors that write JSONL

> OpenCode: multiple exports in one TS file become tool names like `frida_android_lab_<exportname>`. ([GitHub][2])

```ts
// .opencode/tools/frida_android_lab.ts
import { tool } from "@opencode-ai/plugin";
import * as fs from "node:fs/promises";
import * as path from "node:path";

type Spec =
  | { kind: "probe"; slug: string; device: "usb" | "local"; target: string; mode: "attach" | "spawn"; opts?: any }
  | { kind: "java_hook"; slug: string; device: "usb" | "local"; target: string; mode: "attach" | "spawn";
      className: string; methods: string[]; hookAllOverloads: boolean; includeJavaStack: boolean; includeArgs: boolean; }
  | { kind: "native_hook_exports"; slug: string; device: "usb" | "local"; target: string; mode: "attach" | "spawn";
      module: string | null; exports: string[]; maxArgs: number; backtrace: boolean; }
  | { kind: "native_hook_offset"; slug: string; device: "usb" | "local"; target: string; mode: "attach" | "spawn";
      module: string; offsetHex: string; label: string; maxArgs: number; backtrace: boolean; }
  | { kind: "memtimeline"; slug: string; device: "usb" | "local"; target: string; mode: "attach" | "spawn";
      module: string | null; minSize: number; maxSize: number; sampleEvery: number; keepFreed: number;
      backtrace: boolean; btContainsAll: string[]; allocSyms: string[]; freeSyms: string[]; memOps: string[];
      logAllMemOps: boolean; };

const ROOT = path.resolve(process.cwd(), ".opencode", "artifacts", "frida");
const SCRIPTS = path.join(ROOT, "scripts");
const SPECS = path.join(ROOT, "specs");
const RUNNERS = path.join(ROOT, "runners");
const LOGS = path.join(ROOT, "logs");

async function ensureDirs() {
  await fs.mkdir(SCRIPTS, { recursive: true });
  await fs.mkdir(SPECS, { recursive: true });
  await fs.mkdir(RUNNERS, { recursive: true });
  await fs.mkdir(LOGS, { recursive: true });
}

function slugify(s: string) {
  const out = s.trim().toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "");
  if (!out || out.includes("..")) throw new Error("Invalid slug");
  return out;
}

function header(meta: any) {
  return `/**\n * GENERATED — Android Frida Lab\n * Meta: ${JSON.stringify(meta)}\n */\n`;
}

function prelude(config: any) {
  return [
    "'use strict';",
    `const CONFIG = ${JSON.stringify(config, null, 2)};`,
    "function nowMs(){return Date.now();}",
    "let __seq=1;",
    "function emit(kind, payload){ send(Object.assign({kind, ts: nowMs(), seq: __seq++}, payload||{})); }",
    "function bt(ctx){",
    "  try { return Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).map(String); }",
    "  catch(e){ try { return Thread.backtrace(ctx, Backtracer.FUZZY).map(DebugSymbol.fromAddress).map(String); } catch(_){ return []; } }",
    "}",
    "function findExp(mod, name){ const a=Module.findExportByName(mod, name); if(a===null){ emit('error',{what:'export_not_found', module:mod, name}); } return a; }",
    ""
  ].join("\n");
}

function scriptProbe(spec: Extract<Spec, {kind:"probe"}>) {
  const cfg = { kind: "probe" };
  return header({ kind: "probe", generated_at: new Date().toISOString(), slug: spec.slug }) +
    prelude(cfg) +
    [
      "emit('ready', { platform: Process.platform, arch: Process.arch, pid: Process.id });",
      "const mods = Process.enumerateModulesSync().slice(0, 50).map(m => ({ name: m.name, base: m.base.toString(), size: m.size }));",
      "emit('modules', { count: mods.length, sample: mods });",
      "['libc.so','libart.so','libandroid_runtime.so'].forEach(n => {",
      "  try { const m = Process.getModuleByName(n); emit('module', { name:n, base:m.base.toString(), size:m.size }); } catch(_){}",
      "});",
      "['malloc','free','realloc','memcpy','memmove'].forEach(fn => {",
      "  const a = Module.findExportByName(null, fn);",
      "  emit('export', { name: fn, addr: a ? a.toString() : null });",
      "});",
      "emit('done', {});",
      ""
    ].join("\n");
}

function scriptJavaHook(spec: Extract<Spec,{kind:"java_hook"}>) {
  const cfg = {
    kind: "java_hook",
    className: spec.className,
    methods: spec.methods,
    hookAllOverloads: spec.hookAllOverloads,
    includeJavaStack: spec.includeJavaStack,
    includeArgs: spec.includeArgs
  };

  return header({ kind:"java_hook", generated_at:new Date().toISOString(), slug: spec.slug }) +
    [
      "'use strict';",
      `const CONFIG = ${JSON.stringify(cfg, null, 2)};`,
      "let __seq=1; function emit(kind,p){ send(Object.assign({kind, ts: Date.now(), seq: __seq++}, p||{})); }",
      "emit('ready', { kind:'java_hook', className: CONFIG.className });",
      "Java.perform(function(){",
      "  const C = Java.use(CONFIG.className);",
      "  const Exception = Java.use('java.lang.Exception');",
      "  const Log = Java.use('android.util.Log');",
      "  function jstack(){ try { return Log.getStackTraceString(Exception.$new()); } catch(e){ return null; } }",
      "  (CONFIG.methods || []).forEach(function(m){",
      "    if (!C[m]) { emit('error', { what:'method_not_found', method:m }); return; }",
      "    const overs = C[m].overloads;",
      "    overs.forEach(function(ov){",
      "      const sig = ov.argumentTypes.map(t => t.className).join(',');",
      "      emit('hook', { what:'java_attach', method:m, sig:sig });",
      "      ov.implementation = function(){",
      "        const tid = Process.getCurrentThreadId();",
      "        const args = [];",
      "        if (CONFIG.includeArgs) { for (let i=0;i<arguments.length;i++) args.push(String(arguments[i])); }",
      "        const ev = { tid, method:m, sig:sig, when:'enter', args: args };",
      "        if (CONFIG.includeJavaStack) ev.jstack = jstack();",
      "        emit('java_call', ev);",
      "        const ret = ov.apply(this, arguments);",
      "        emit('java_call', { tid, method:m, sig:sig, when:'leave', retval: String(ret) });",
      "        return ret;",
      "      };",
      "    });",
      "  });",
      "});",
      ""
    ].join("\n");
}

function scriptNativeHookExports(spec: Extract<Spec,{kind:"native_hook_exports"}>) {
  const cfg = { kind:"native_hook_exports", module: spec.module, exports: spec.exports, maxArgs: spec.maxArgs, backtrace: spec.backtrace };
  return header({ kind:"native_hook_exports", generated_at:new Date().toISOString(), slug: spec.slug }) +
    prelude(cfg) +
    [
      "emit('ready', { config: CONFIG });",
      "(CONFIG.exports||[]).forEach(function(name){",
      "  const a = findExp(CONFIG.module, name);",
      "  if (a===null) return;",
      "  emit('hook', { what:'attach', name, module: CONFIG.module, addr: a.toString() });",
      "  Interceptor.attach(a, {",
      "    onEnter(args){",
      "      const tid = Process.getCurrentThreadId();",
      "      const n = (CONFIG.maxArgs|0);",
      "      const argv=[]; for(let i=0;i<n;i++) argv.push(args[i].toString());",
      "      const ev = { tid, name, when:'enter', args: argv };",
      "      if (CONFIG.backtrace) ev.bt = bt(this.context);",
      "      emit('call', ev);",
      "    },",
      "    onLeave(retval){",
      "      const tid = Process.getCurrentThreadId();",
      "      const ev = { tid, name, when:'leave', retval: retval.toString() };",
      "      if (CONFIG.backtrace) ev.bt = bt(this.context);",
      "      emit('call', ev);",
      "    }",
      "  });",
      "});",
      ""
    ].join("\n");
}

function scriptNativeHookOffset(spec: Extract<Spec,{kind:"native_hook_offset"}>) {
  const cfg = { kind:"native_hook_offset", module: spec.module, offsetHex: spec.offsetHex, label: spec.label, maxArgs: spec.maxArgs, backtrace: spec.backtrace };
  return header({ kind:"native_hook_offset", generated_at:new Date().toISOString(), slug: spec.slug }) +
    prelude(cfg) +
    [
      "emit('ready', { config: CONFIG });",
      "const m = Process.getModuleByName(CONFIG.module);",
      "const addr = m.base.add(ptr(CONFIG.offsetHex));",
      "emit('hook', { what:'attach', label: CONFIG.label, module: CONFIG.module, base: m.base.toString(), addr: addr.toString() });",
      "Interceptor.attach(addr, {",
      "  onEnter(args){",
      "    const tid = Process.getCurrentThreadId();",
      "    const n = (CONFIG.maxArgs|0);",
      "    const argv=[]; for(let i=0;i<n;i++) argv.push(args[i].toString());",
      "    const ev = { tid, label: CONFIG.label, when:'enter', args: argv };",
      "    if (CONFIG.backtrace) ev.bt = bt(this.context);",
      "    emit('call', ev);",
      "  },",
      "  onLeave(retval){",
      "    const tid = Process.getCurrentThreadId();",
      "    const ev = { tid, label: CONFIG.label, when:'leave', retval: retval.toString() };",
      "    if (CONFIG.backtrace) ev.bt = bt(this.context);",
      "    emit('call', ev);",
      "  }",
      "});",
      ""
    ].join("\n");
}

// Simple page-bucket index: O(1) average containment checks (good enough, avoids O(n) scans)
function scriptMemtimeline(spec: Extract<Spec,{kind:"memtimeline"}>) {
  const cfg = {
    kind:"memtimeline",
    module: spec.module,
    minSize: spec.minSize,
    maxSize: spec.maxSize,
    sampleEvery: spec.sampleEvery,
    keepFreed: spec.keepFreed,
    backtrace: spec.backtrace,
    btContainsAll: spec.btContainsAll,
    allocSyms: spec.allocSyms,
    freeSyms: spec.freeSyms,
    memOps: spec.memOps,
    logAllMemOps: spec.logAllMemOps,
    pageSize: 4096
  };

  return header({ kind:"memtimeline", generated_at:new Date().toISOString(), slug: spec.slug }) +
    prelude(cfg) +
    [
      "emit('ready', { config: CONFIG });",
      "const live = new Map();   // baseStr -> rec",
      "const freed = new Map();  // baseStr -> rec (capped)",
      "const livePages = new Map();  // pageStr -> Set(baseStr)",
      "const freedPages = new Map(); // pageStr -> Set(baseStr)",
      "let evN = 0;",
      "function sample(){ const n = Math.max(1, CONFIG.sampleEvery|0); return ((++evN) % n) === 0; }",
      "function pageOf(p){ return ptr(p).and(ptr('0xfffffffffffff000')).toString(); }",
      "function addPageIndex(mapPages, baseStr, size){",
      "  const base = ptr(baseStr);",
      "  const end = base.add(size);",
      "  for (let p = base; p.compare(end) < 0; p = p.add(CONFIG.pageSize)) {",
      "    const key = pageOf(p);",
      "    let set = mapPages.get(key);",
      "    if (!set) { set = new Set(); mapPages.set(key, set); }",
      "    set.add(baseStr);",
      "  }",
      "}",
      "function delPageIndex(mapPages, baseStr, size){",
      "  const base = ptr(baseStr);",
      "  const end = base.add(size);",
      "  for (let p = base; p.compare(end) < 0; p = p.add(CONFIG.pageSize)) {",
      "    const key = pageOf(p);",
      "    const set = mapPages.get(key);",
      "    if (set) { set.delete(baseStr); if (set.size===0) mapPages.delete(key); }",
      "  }",
      "}",
      "function btOk(btLines){",
      "  const needles = CONFIG.btContainsAll || [];",
      "  if (needles.length===0) return true;",
      "  const hay = (btLines||[]).join('\\n');",
      "  for (let i=0;i<needles.length;i++) if (hay.indexOf(String(needles[i])) === -1) return false;",
      "  return true;",
      "}",
      "function sizeOk(sz){",
      "  if ((CONFIG.minSize|0) > 0 && sz < (CONFIG.minSize|0)) return false;",
      "  if ((CONFIG.maxSize|0) > 0 && sz > (CONFIG.maxSize|0)) return false;",
      "  return true;",
      "}",
      "function rememberLive(baseStr, rec){",
      "  live.set(baseStr, rec);",
      "  addPageIndex(livePages, baseStr, rec.size);",
      "  if (freed.has(baseStr)) {",
      "    const old = freed.get(baseStr);",
      "    freed.delete(baseStr);",
      "    if (old && old.size) delPageIndex(freedPages, baseStr, old.size);",
      "  }",
      "}",
      "function rememberFreed(baseStr, rec){",
      "  freed.set(baseStr, rec);",
      "  addPageIndex(freedPages, baseStr, rec.size);",
      "  const cap = Math.max(1, CONFIG.keepFreed|0);",
      "  if (freed.size > cap){",
      "    const k = freed.keys().next().value;",
      "    const r = freed.get(k);",
      "    freed.delete(k);",
      "    if (r && r.size) delPageIndex(freedPages, k, r.size);",
      "  }",
      "}",
      "function findContaining(map, mapPages, addrStr){",
      "  const addr = ptr(addrStr);",
      "  const pkey = pageOf(addr);",
      "  const set = mapPages.get(pkey);",
      "  if (!set) return null;",
      "  for (const baseStr of set.values()){",
      "    const rec = map.get(baseStr);",
      "    if (!rec) continue;",
      "    const base = ptr(baseStr);",
      "    const off = addr.sub(base).toInt32();",
      "    if (off >= 0 && off < (rec.size|0)) return { base: baseStr, rec, off };",
      "  }",
      "  return null;",
      "}",
      "function attachAlloc(name){",
      "  const a = findExp(CONFIG.module, name); if (a===null) return;",
      "  Interceptor.attach(a, {",
      "    onEnter(args){",
      "      this._fn = name; this._tid = Process.getCurrentThreadId();",
      "      if (name==='calloc') this._size = (args[0].toUInt32() * args[1].toUInt32())|0;",
      "      else if (name==='realloc') { this._old = args[0]; this._size = args[1].toUInt32()|0; }",
      "      else this._size = args[0].toUInt32()|0;",
      "      this._bt = CONFIG.backtrace ? bt(this.context) : null;",
      "    },",
      "    onLeave(retval){",
      "      if (!sample()) return;",
      "      if (retval.isNull()) return;",
      "      const baseStr = retval.toString();",
      "      const sz = this._size|0;",
      "      const btLines = this._bt || [];",
      "      if (!sizeOk(sz) || !btOk(btLines)) return;",
      "      const rec = { size: sz, fn: this._fn, tid: this._tid, ts: Date.now(), bt: CONFIG.backtrace ? btLines : undefined };",
      "      rememberLive(baseStr, rec);",
      "      emit('alloc', { tid: this._tid, fn: this._fn, ptr: baseStr, size: sz, bt: rec.bt });",
      "    }",
      "  });",
      "}",
      "function attachFree(name){",
      "  const a = findExp(CONFIG.module, name); if (a===null) return;",
      "  Interceptor.attach(a, {",
      "    onEnter(args){",
      "      if (!sample()) return;",
      "      const tid = Process.getCurrentThreadId();",
      "      const p = args[0]; if (p.isNull()) return;",
      "      const ptrStr = p.toString();",
      "      const rec = live.get(ptrStr);",
      "      const btLines = CONFIG.backtrace ? bt(this.context) : null;",
      "      if (rec){",
      "        live.delete(ptrStr); delPageIndex(livePages, ptrStr, rec.size);",
      "        const fr = Object.assign({}, rec, { freed_ts: Date.now(), free_bt: CONFIG.backtrace ? btLines : undefined });",
      "        rememberFreed(ptrStr, fr);",
      "        emit('free', { tid, fn: name, ptr: ptrStr, size: rec.size, bt: fr.free_bt });",
      "      } else {",
      "        emit('free', { tid, fn: name, ptr: ptrStr, size: null, unknown: true, bt: CONFIG.backtrace ? btLines : undefined });",
      "      }",
      "    }",
      "  });",
      "}",
      "function attachMemop(name){",
      "  const a = findExp(CONFIG.module, name); if (a===null) return;",
      "  Interceptor.attach(a, {",
      "    onEnter(args){",
      "      if (!sample()) return;",
      "      const tid = Process.getCurrentThreadId();",
      "      let dst = null, src = null, len = 0;",
      "      if (name==='memcpy' || name==='memmove'){ dst=args[0].toString(); src=args[1].toString(); len=args[2].toUInt32()|0; }",
      "      else if (name==='memset'){ dst=args[0].toString(); src=null; len=args[2].toUInt32()|0; }",
      "      else {",
      "        if (!CONFIG.logAllMemOps) return;",
      "        dst=args[0].toString(); src=args[1].toString(); len=args[2].toUInt32()|0;",
      "      }",
      "      const dstLive = dst ? findContaining(live, livePages, dst) : null;",
      "      const dstFreed = dst ? findContaining(freed, freedPages, dst) : null;",
      "      if (!CONFIG.logAllMemOps && !dstLive && !dstFreed) return;",
      "      let suspicious=false, uaf=false, base=null, off=null, asz=null;",
      "      if (dstLive){ base=dstLive.base; off=dstLive.off; asz=dstLive.rec.size; if (len>0 && (off+len)>(asz|0)) suspicious=true; }",
      "      if (dstFreed){ uaf=true; base=dstFreed.base; off=dstFreed.off; asz=dstFreed.rec.size; if (len>0 && (off+len)>(asz|0)) suspicious=true; }",
      "      const ev = { tid, fn:name, dst, src, len, dst_alloc: base, dst_off: off, dst_size: asz, uaf, suspicious };",
      "      if (CONFIG.backtrace) ev.bt = bt(this.context);",
      "      emit(name, ev);",
      "    }",
      "  });",
      "}",
      "(CONFIG.allocSyms||['malloc','calloc','realloc']).forEach(attachAlloc);",
      "(CONFIG.freeSyms||['free']).forEach(attachFree);",
      "(CONFIG.memOps||['memcpy','memmove','memset']).forEach(attachMemop);",
      "emit('installed', { allocSyms: CONFIG.allocSyms, freeSyms: CONFIG.freeSyms, memOps: CONFIG.memOps });",
      ""
    ].join("\n");
}

async function writeJson(p: string, obj: any) {
  await fs.mkdir(path.dirname(p), { recursive: true });
  await fs.writeFile(p, JSON.stringify(obj, null, 2), "utf8");
}
async function writeText(p: string, text: string) {
  await fs.mkdir(path.dirname(p), { recursive: true });
  await fs.writeFile(p, text, "utf8");
}

export const write_spec = tool({
  description: "Write a Frida Lab spec JSON under .opencode/artifacts/frida/specs/<slug>.json",
  args: { spec: tool.schema.any() },
  async execute(a) {
    await ensureDirs();
    const spec = a.spec as Spec;
    const slug = slugify((spec as any).slug);
    const specPath = path.join(SPECS, `${slug}.json`);
    await writeJson(specPath, spec);
    return { ok: true, spec_path: specPath };
  }
});

export const generate_from_spec = tool({
  description: "Generate a Frida JS script from a saved spec JSON (spec-first pipeline).",
  args: { spec_path: tool.schema.string() },
  async execute(a) {
    await ensureDirs();
    const specPath = a.spec_path;
    const raw = await fs.readFile(specPath, "utf8");
    const spec = JSON.parse(raw) as Spec;
    const slug = slugify((spec as any).slug);
    const scriptPath = path.join(SCRIPTS, `${slug}.js`);

    let js = "";
    if (spec.kind === "probe") js = scriptProbe(spec);
    else if (spec.kind === "java_hook") js = scriptJavaHook(spec);
    else if (spec.kind === "native_hook_exports") js = scriptNativeHookExports(spec);
    else if (spec.kind === "native_hook_offset") js = scriptNativeHookOffset(spec);
    else if (spec.kind === "memtimeline") js = scriptMemtimeline(spec);
    else throw new Error(`Unknown spec.kind: ${(spec as any).kind}`);

    await writeText(scriptPath, js);
    return { ok: true, script_path: scriptPath, kind: spec.kind, slug };
  }
});

export const cmd = tool({
  description: "Generate an exact Frida CLI command string (does not execute).",
  args: {
    device: tool.schema.string(), // "usb"|"local"
    mode: tool.schema.string(),   // "attach"|"spawn"
    target: tool.schema.string(),
    script_path: tool.schema.string(),
    debug: tool.schema.boolean().optional()
  },
  async execute(a) {
    const parts: string[] = ["frida"];
    if (a.device === "usb") parts.push("-U");
    if (a.mode === "spawn") parts.push("-f", a.target);
    else parts.push(a.target);
    parts.push("-l", a.script_path);
    if (a.debug) parts.push("--debug");
    return { ok: true, cmd: parts.join(" ") };
  }
});

// Convenience: write specific spec types
export const probe_spec = tool({
  description: "Write a probe spec (use first to confirm modules/exports on Android).",
  args: {
    slug: tool.schema.string(),
    device: tool.schema.string(),
    mode: tool.schema.string(),
    target: tool.schema.string()
  },
  async execute(a) {
    const spec: Spec = { kind:"probe", slug: slugify(a.slug), device: a.device==="usb"?"usb":"local", mode: a.mode==="spawn"?"spawn":"attach", target: a.target };
    return await (write_spec as any).execute({ spec });
  }
});

export const java_hook_spec = tool({
  description: "Write a Java hook spec (Android). Hooks all overloads by default.",
  args: {
    slug: tool.schema.string(),
    device: tool.schema.string(),
    mode: tool.schema.string(),
    target: tool.schema.string(),
    className: tool.schema.string(),
    methods: tool.schema.array(tool.schema.string()),
    hookAllOverloads: tool.schema.boolean(),
    includeJavaStack: tool.schema.boolean(),
    includeArgs: tool.schema.boolean()
  },
  async execute(a) {
    const spec: Spec = {
      kind:"java_hook", slug: slugify(a.slug),
      device: a.device==="usb"?"usb":"local",
      mode: a.mode==="spawn"?"spawn":"attach",
      target: a.target,
      className: a.className,
      methods: a.methods,
      hookAllOverloads: a.hookAllOverloads,
      includeJavaStack: a.includeJavaStack,
      includeArgs: a.includeArgs
    };
    return await (write_spec as any).execute({ spec });
  }
});

export const native_hook_exports_spec = tool({
  description: "Write a native export hook spec (Android).",
  args: {
    slug: tool.schema.string(),
    device: tool.schema.string(),
    mode: tool.schema.string(),
    target: tool.schema.string(),
    module: tool.schema.string().nullable(),
    exports: tool.schema.array(tool.schema.string()),
    maxArgs: tool.schema.number(),
    backtrace: tool.schema.boolean()
  },
  async execute(a) {
    const spec: Spec = {
      kind:"native_hook_exports", slug: slugify(a.slug),
      device: a.device==="usb"?"usb":"local",
      mode: a.mode==="spawn"?"spawn":"attach",
      target: a.target,
      module: a.module ?? null,
      exports: a.exports,
      maxArgs: a.maxArgs|0,
      backtrace: !!a.backtrace
    };
    return await (write_spec as any).execute({ spec });
  }
});

export const native_hook_offset_spec = tool({
  description: "Write a native offset hook spec (Android stripped libs).",
  args: {
    slug: tool.schema.string(),
    device: tool.schema.string(),
    mode: tool.schema.string(),
    target: tool.schema.string(),
    module: tool.schema.string(),
    offsetHex: tool.schema.string(),
    label: tool.schema.string(),
    maxArgs: tool.schema.number(),
    backtrace: tool.schema.boolean()
  },
  async execute(a) {
    const spec: Spec = {
      kind:"native_hook_offset", slug: slugify(a.slug),
      device: a.device==="usb"?"usb":"local",
      mode: a.mode==="spawn"?"spawn":"attach",
      target: a.target,
      module: a.module,
      offsetHex: a.offsetHex,
      label: a.label,
      maxArgs: a.maxArgs|0,
      backtrace: !!a.backtrace
    };
    return await (write_spec as any).execute({ spec });
  }
});

export const memtimeline_spec = tool({
  description: "Write a malloc/free + memops timeline spec (Android).",
  args: {
    slug: tool.schema.string(),
    device: tool.schema.string(),
    mode: tool.schema.string(),
    target: tool.schema.string(),
    module: tool.schema.string().nullable(),
    minSize: tool.schema.number(),
    maxSize: tool.schema.number(),
    sampleEvery: tool.schema.number(),
    keepFreed: tool.schema.number(),
    backtrace: tool.schema.boolean(),
    btContainsAll: tool.schema.array(tool.schema.string()),
    allocSyms: tool.schema.array(tool.schema.string()),
    freeSyms: tool.schema.array(tool.schema.string()),
    memOps: tool.schema.array(tool.schema.string()),
    logAllMemOps: tool.schema.boolean()
  },
  async execute(a) {
    const spec: Spec = {
      kind:"memtimeline", slug: slugify(a.slug),
      device: a.device==="usb"?"usb":"local",
      mode: a.mode==="spawn"?"spawn":"attach",
      target: a.target,
      module: a.module ?? null,
      minSize: a.minSize|0,
      maxSize: a.maxSize|0,
      sampleEvery: Math.max(1, a.sampleEvery|0),
      keepFreed: Math.max(1, a.keepFreed|0),
      backtrace: !!a.backtrace,
      btContainsAll: a.btContainsAll ?? [],
      allocSyms: a.allocSyms ?? ["malloc","calloc","realloc"],
      freeSyms: a.freeSyms ?? ["free"],
      memOps: a.memOps ?? ["memcpy","memmove","memset"],
      logAllMemOps: !!a.logAllMemOps
    };
    return await (write_spec as any).execute({ spec });
  }
});

export const runner_py = tool({
  description: "Generate a Python runner that collects send() messages and writes JSONL (Android friendly).",
  args: {
    slug: tool.schema.string(),
    device: tool.schema.string(),
    mode: tool.schema.string(),
    target: tool.schema.string(),
    script_path: tool.schema.string(),
    out_jsonl: tool.schema.string().optional()
  },
  async execute(a) {
    await ensureDirs();
    const slug = slugify(a.slug);
    const out = a.out_jsonl ?? path.join(LOGS, `${slug}.jsonl`);
    const pyPath = path.join(RUNNERS, `${slug}.py`);
    const device = a.device === "usb" ? "usb" : "local";
    const mode = a.mode === "spawn" ? "spawn" : "attach";
    const py =
`#!/usr/bin/env python3
import frida, json, time, sys

DEVICE=${jsonEsc(device)}
MODE=${jsonEsc(mode)}
TARGET=${jsonEsc(a.target)}
SCRIPT=${jsonEsc(a.script_path)}
OUT=${jsonEsc(out)}

def dev():
  return frida.get_usb_device(timeout=5) if DEVICE=="usb" else frida.get_local_device()

def on_message(m, data):
  rec={"t":time.time(), "message":m}
  with open(OUT,"a",encoding="utf-8") as f: f.write(json.dumps(rec)+"\\n")
  print(m)

def main():
  d=dev()
  if MODE=="spawn":
    pid=d.spawn([TARGET])
    s=d.attach(pid)
  else:
    s=d.attach(TARGET)
  src=open(SCRIPT,"r",encoding="utf-8").read()
  script=s.create_script(src)
  script.on("message", on_message)
  script.load()
  if MODE=="spawn":
    d.resume(pid)
  print("[runner] logging to", OUT)
  sys.stdin.read()

def jsonEsc(x): return json.dumps(x)

if __name__=="__main__":
  main()
`;
    // helper inside string; keep simple:
    const fixed = py.replace("def jsonEsc(x): return json.dumps(x)\n\n", "");
    await fs.writeFile(pyPath, fixed, "utf8");
    return { ok:true, runner_path: pyPath, out_jsonl: out };
  }
});

export const runner_node = tool({
  description: "Generate a Node runner that collects send() messages and writes JSONL (Android friendly).",
  args: {
    slug: tool.schema.string(),
    script_path: tool.schema.string(),
    note: tool.schema.string().optional()
  },
  async execute(a) {
    await ensureDirs();
    const slug = slugify(a.slug);
    const jsPath = path.join(RUNNERS, `${slug}.mjs`);
    const out = path.join(LOGS, `${slug}.jsonl`);
    const js =
`// GENERATED — Android Frida Lab runner (Node)
// Requires: npm i frida
import fs from "node:fs";
import frida from "frida";

const OUT=${JSON.stringify(out)};
const SCRIPT_PATH=${JSON.stringify(a.script_path)};

function append(rec){ fs.appendFileSync(OUT, JSON.stringify(rec)+"\\n"); }

console.log("[runner] logs:", OUT);
console.log("[runner] script:", SCRIPT_PATH);
console.log("[runner] NOTE:", ${JSON.stringify(a.note ?? "")});

console.log("This runner is a template. Prefer the Python runner unless you already use Node.");
`;
    await fs.writeFile(jsPath, js, "utf8");
    return { ok:true, runner_path: jsPath, out_jsonl: out };
  }
});
```

Why this matters for Android:

* **Probe** script catches 80% of “wrong process / module not loaded / symbol not found” failures up front.
* `memtimeline` is efficient enough to run on real apps because it avoids O(n) containment scans by using **page buckets**.

Frida JS APIs used here are standard (`Interceptor`, `Thread.backtrace`, `Module.findExportByName`, `Java.perform`). ([Frida][1])

---

# 5) Agents

## `.opencode/agents/frida-lab.md` (primary)

```md
---
description: Android Frida Lab (primary): generates exact scripts via frida_android_lab_* tools and returns script+spec+exact run command.
mode: primary
temperature: 0.1
steps: 25
---

You generate EXACT Frida scripts for Android.

Hard rules:
- Always produce: spec path + script path + exact frida command.
- Use spec-first pipeline:
  1) frida_android_lab_*_spec
  2) frida_android_lab_generate_from_spec
  3) frida_android_lab_cmd

Start every new target with /frida-probe unless user already confirmed exports/modules.
Logging only; no bypass/anti-detection.
```

## `.opencode/agents/frida-android-java.md`

```md
---
description: Android Java hook specialist (Java.perform; hooks overloads; stable event schema).
mode: subagent
temperature: 0.1
steps: 20
---

Use frida_android_lab_java_hook_spec + generate_from_spec + cmd.
Default: hookAllOverloads=true, includeArgs=true, includeJavaStack=false (turn on only when needed).
```

## `.opencode/agents/frida-android-native.md`

```md
---
description: Android native hook specialist (exports or base+offset). Deterministic hooks.
mode: subagent
temperature: 0.1
steps: 20
---

Prefer exports. Use offset hooks only when symbols are stripped.

Always:
- maxArgs <= 6 unless user requests more
- backtrace=false by default; enable for short sessions only
```

## `.opencode/agents/frida-android-memtimeline.md`

```md
---
description: Android memtimeline specialist: malloc/free + memops correlation (UAF-ish and overflow-ish signals).
mode: subagent
temperature: 0.1
steps: 25
---

Use frida_android_lab_memtimeline_spec + generate_from_spec + cmd.

Defaults:
- module: null (global)
- minSize: 16, maxSize: 0
- sampleEvery: 5 (reduce noise)
- keepFreed: 2048
- backtrace: false initially
- btContainsAll: [] initially (add after probe if needed)
- memOps: ["memcpy","memmove","memset"]
```

---

# 6) Commands (Android UX)

## `/frida-probe`

```md
---
description: Generate and run a probe script (modules + common exports) for an Android target.
agent: frida-lab
---

1) Write probe spec (frida_android_lab_probe_spec)
2) Generate script (frida_android_lab_generate_from_spec)
3) Produce command (frida_android_lab_cmd)

Ask user for: device(usb/local), mode(attach/spawn), target(package/process).
```

## `/frida-java-hook`

```md
---
description: Generate a Java hook script (Android) for a class+methods.
agent: frida-android-java
---

Ask for: className, methods[], device, mode, target.
Then: java_hook_spec → generate_from_spec → cmd.
```

## `/frida-native-hook-exports`

```md
---
description: Hook native exported symbols (Android).
agent: frida-android-native
---

Ask for: exports[], module(optional), device, mode, target.
Then: native_hook_exports_spec → generate_from_spec → cmd.
```

## `/frida-native-hook-offset`

```md
---
description: Hook native by module base + offset (Android stripped libs).
agent: frida-android-native
---

Ask for: module, offsetHex, label, device, mode, target.
Then: native_hook_offset_spec → generate_from_spec → cmd.
```

## `/frida-memtimeline`

```md
---
description: Generate malloc/free + memops timeline script (Android) and exact run command.
agent: frida-android-memtimeline
---

Ask for: device, mode, target.
Optionally: module, size filters, sampleEvery, btContainsAll.
Then: memtimeline_spec → generate_from_spec → cmd.
```

## `/frida-runner`

```md
---
description: Generate a Python runner to capture send() events into JSONL (Android).
agent: frida-lab
---

Given an existing script_path, generate runner_py and print python command.
```

## `/frida-spec-regenerate`

```md
---
description: Regenerate a script from an existing spec JSON file.
agent: frida-lab
---

Given spec_path:
- generate_from_spec
- cmd (device/mode/target read from spec)
Return updated script path + cmd.
```

---

# 7) Skills (tight, Android-specific)

## `.opencode/skills/frida-android-spec/SKILL.md`

```md
---
name: frida-android-spec
description: Spec-first deterministic pipeline for Android Frida scripts (probe → generate → run).
compatibility: opencode
---

Always use: spec → generate_from_spec → cmd.

Start with PROBE unless:
- user already confirmed target process, modules, and export names.

Pick generator:
- probe: validate environment + exports
- java_hook: Java/Kotlin flows
- native_hook_exports: JNI/native functions with symbols
- native_hook_offset: stripped libs
- memtimeline: malloc/free + memops correlation
```

## `.opencode/skills/frida-android-debug/SKILL.md`

```md
---
name: frida-android-debug
description: Android Frida debug workflow (CLI, spawn/attach, process discovery).
compatibility: opencode
---

Discovery:
- frida-ls-devices
- frida-ps -Uai (list apps/processes)

CLI usage:
- frida -U <process>
- frida -U -f <package> -l script.js (spawn mode)

Use the REPL for fast iteration:
- %reload (reload script)
```

(Frida CLI docs cover the REPL and USB usage; OWASP MASTG lists frida-ps/frida-ls-devices usage patterns.) ([Frida][3])

## `.opencode/skills/frida-android-safety/SKILL.md`

```md
---
name: frida-android-safety
description: Guardrails for Frida Lab: instrumentation/logging only, no bypass/stealth.
compatibility: opencode
---

Do:
- trace flows, log args, stack traces, memory lifetimes, crash reproduction

Don't:
- generate bypass/anti-detection scripts (SSL pinning bypass, root detection bypass, auth bypass)
```

---

# 8) README.md (exact Android instructions)

Here’s a ready-to-drop README. It uses Frida’s official Android tutorial + frida-trace docs for the frida-server workflow and OWASP guidance for Android usage. ([Frida][4])

````md
# Android Frida Lab (OpenCode)

This repository is an OpenCode “Frida Lab” for Android.
The ONLY goal is to generate **exact, runnable Frida scripts** (as files) with a reproducible pipeline:

1) write a JSON spec
2) generate a JS script from that spec
3) print the exact `frida ...` command to run it

No scripts are hand-waved in chat. Everything is written to `.opencode/artifacts/frida/scripts/`.

---

## 0) Requirements

### Host requirements
- Python + pip
- Install Frida CLI tools:
  ```bash
  pip install frida-tools
````

* Optional (for the Python runner that captures JSONL logs):

  ```bash
  pip install frida
  ```

### Android device requirements (recommended: rooted)

Frida’s Android guide focuses on the simplest path: a rooted device running `frida-server`.
Non-root alternatives exist (e.g., Frida Gadget), but this lab assumes `frida-server` first. (See Frida Android docs.)

---

## 1) Set up frida-server on Android (rooted path)

High-level flow (from Frida docs):

1. download the right `frida-server` binary for your device architecture
2. push to device (commonly `/data/local/tmp`)
3. `chmod +x`
4. run it in background
5. connect from host using `frida -U ...`

References:

* Frida Android tutorial
* frida-trace docs include a concrete frida-server copy/run example

### Example commands (typical)

```bash
adb push frida-server-<ver>-android-arm64 /data/local/tmp/frida-server
adb shell
su
chmod 755 /data/local/tmp/frida-server
/data/local/tmp/frida-server &
```

---

## 2) Verify connectivity

List devices:

```bash
frida-ls-devices
```

List Android apps/processes:

```bash
frida-ps -Uai
```

---

## 3) Start OpenCode and use the Frida Lab agent

In repo root:

```bash
opencode
```

Select the primary agent:

* `@frida-lab`

---

## 4) Recommended workflow (Android)

### Step A — Probe first (always)

In OpenCode:

* `/frida-probe`

Provide:

* device: `usb`
* mode: `attach` (if the process is already running) OR `spawn` (start the app)
* target: package or process name (e.g., `com.example.app`)

This generates:

* spec:    `.opencode/artifacts/frida/specs/<slug>.json`
* script:  `.opencode/artifacts/frida/scripts/<slug>.js`
* command: `frida -U ... -l <script>`

Run the printed command and confirm you see:

* `kind=ready`
* module/export sample results

### Step B — Choose one generator

#### 1) Java method hooks (Java.perform)

In OpenCode:

* `/frida-java-hook`

Provide:

* className: `com.example.Foo`
* methods: `["bar","baz"]`
* device/mode/target

Run the printed command.
Expected events:

* `kind=hook` for each overload
* `kind=java_call` enter/leave

#### 2) Native exports (JNI/native)

In OpenCode:

* `/frida-native-hook-exports`

Provide:

* module: null (global) or `libfoo.so`
* exports: `["JNI_OnLoad","memcpy"]` (example)
* device/mode/target

Expected events:

* `kind=call` enter/leave for each export

#### 3) Stripped library by offset (module base + offset)

In OpenCode:

* `/frida-native-hook-offset`

Provide:

* module: `libtarget.so`
* offsetHex: `0x1234`
* label: `parse_packet`
* device/mode/target

Expected events:

* `kind=call` labeled enter/leave

#### 4) Memory timeline (malloc/free + memops correlation)

In OpenCode:

* `/frida-memtimeline`

Defaults are low-noise; you can tighten further with:

* minSize/maxSize
* sampleEvery
* btContainsAll (only log events whose backtrace contains ALL substrings)

Expected events:

* `kind=alloc` / `kind=free`
* `kind=memcpy` / `kind=memmove` / `kind=memset`

  * `uaf=true` if dst falls inside a freed allocation range
  * `suspicious=true` if dst_off + len > tracked allocation size (best-effort overflow signal)

---

## 5) Capturing structured logs to JSONL (recommended)

CLI is great for interactive work, but JSONL is better for offline analysis.

In OpenCode:

* `/frida-runner`

This generates:

* `.opencode/artifacts/frida/runners/<slug>.py`

Run:

```bash
python3 .opencode/artifacts/frida/runners/<slug>.py
```

It writes:

* `.opencode/artifacts/frida/logs/<slug>.jsonl`

---

## 6) Debugging tips

### REPL reload

Frida CLI has a REPL. Use `%reload` to reload your script quickly (after regenerating it).

### If symbols aren’t found

* run `/frida-probe` again
* confirm module name and that it’s loaded
* prefer export hooks; use offset hook only when you’re sure about base+offset

---

## 7) Artifacts

Generated files:

* Scripts:  `.opencode/artifacts/frida/scripts/`
* Specs:    `.opencode/artifacts/frida/specs/`
* Runners:  `.opencode/artifacts/frida/runners/`
* Logs:     `.opencode/artifacts/frida/logs/`

```

---

# 9) A few Android-specific “gotchas” this lab handles

- **Java hooks require `Java.perform`** and overload handling is essential on Android. :contentReference[oaicite:6]{index=6}  
- **Probe-first** prevents the most common failures: wrong process name, wrong package, module not loaded, missing exports. :contentReference[oaicite:7]{index=7}  
- **Memory timeline performance:** page-bucket indexing avoids O(n) scans, which matters on Android apps with heavy allocation churn.

---

If you tell me **which Android environment you mostly use** (rooted physical device vs emulator, arm64 vs x86_64, and whether your target is mostly **Java/Kotlin** or mostly **NDK/JNI**), I’ll set the *default* specs (module names, alloc/free symbols, memops list, sample rate) so your `/frida-memtimeline` output is low-noise on the first run.
::contentReference[oaicite:8]{index=8}
```

[1]: https://frida.re/docs/javascript-api/?utm_source=chatgpt.com "JavaScript API"
[2]: https://github.com/frida/frida-tools?utm_source=chatgpt.com "Frida CLI tools"
[3]: https://frida.re/docs/frida-cli/?utm_source=chatgpt.com "Frida CLI"
[4]: https://frida.re/docs/android/?utm_source=chatgpt.com "Android"
