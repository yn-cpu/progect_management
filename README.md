Below is a complete, **drop‑in OpenCode “Memory Safety Pack”** (agents + commands + skills + tools + report template) that implements:

* **Use case 1:** Allocation lifetime timelines (UAF / double‑free / leak triage)
* **Use case 2:** **Z3 feasibility** (SAT/UNSAT for trigger path conditions)
* **Accuracy upgrades** for open(-source) models:

  * **Structured Timeline Artifact JSON** (machine-usable)
  * **Schema validation tool** (`timeline_validate`) so the agent can self-correct
  * **Memop hotspot scanner** (`memops_scan`) to find/rank memcpy/strcpy/sprintf/read/recv sinks
  * **Z3 tool returns parsed model as JSON** when SAT

Everything below matches OpenCode’s documented formats for agents, commands, skills, tools, and permissions. ([OpenCode][1])

---

## Quick install notes

1. From repo root, create the folders shown in the tree.
2. Paste each file exactly as shown (paths matter).
3. Install Z3 support (recommended):

   * Python: `pip install z3-solver`
   * Or ensure `z3` binary is in `PATH` (the tool will fall back if the Python module isn’t available).

---

## File tree

```text
opencode.jsonc
AGENTS.md

.opencode/
  agents/
    vuln.md
    vuln-mem.md
    vuln-memop.md
    vuln-smt.md

  commands/
    sec-finding-new.md
    sec-mem-timeline.md
    sec-memop-scan.md
    sec-memop-timeline.md
    sec-mem-z3.md
    sec-mem-triage.md

  skills/
    memory-lifetime-timeline/SKILL.md
    z3-feasibility/SKILL.md

  tools/
    session_info.ts
    timeline_validate.ts
    mem_events.py
    mem_events.ts
    memops_scan.py
    memops_scan.ts
    z3_smt2.py
    z3_smt2.ts

docs/security/findings/
  TEMPLATE-memory.md
  README.md
```

---

# 1) `opencode.jsonc`

> Project-level config. Controls default agent + permissions + compaction. ([OpenCode][2])

```jsonc
{
  "$schema": "https://opencode.ai/config.json",

  // Use our security auditor by default.
  "default_agent": "vuln",

  // Keep long security sessions stable.
  "compaction": {
    "auto": true,
    "prune": true,
    "reserved": 12000
  },

  // Reduce noise from watcher events.
  "watcher": {
    "ignore": [
      ".git/**",
      "node_modules/**",
      "dist/**",
      "build/**",
      "out/**",
      ".opencode/artifacts/**"
    ]
  },

  "permission": {
    // Start permissive, then lock down specifics. (Defaults are permissive.) :contentReference[oaicite:2]{index=2}
    "*": "allow",

    // Keep secrets safe.
    "read": {
      "*": "allow",
      "*.env": "deny",
      "*.env.*": "deny",
      "*.env.example": "allow"
    },

    // Static analysis helpers
    "glob": "allow",
    "grep": "allow",
    "list": "allow",
    "lsp": "allow",

    // Skills are allowed (these are just reusable instructions). :contentReference[oaicite:3]{index=3}
    "skill": { "*": "allow" },

    // Allow only our subagents via the Task tool. :contentReference[oaicite:4]{index=4}
    "task": {
      "*": "deny",
      "vuln-*": "allow"
    },

    // No outbound by default (security auditing).
    "webfetch": "deny",
    "websearch": "deny",
    "codesearch": "deny",

    // Allow read-only-ish bash commands; ask for everything else.
    "bash": {
      "*": "ask",
      "rg *": "allow",
      "grep *": "allow",
      "git status*": "allow",
      "git diff*": "allow",
      "git log*": "allow"
    },

    // HARD RULE: No code edits; only allow writing artifacts + findings.
    // edit covers edit/write/patch/multiedit. :contentReference[oaicite:5]{index=5}
    "edit": {
      "*": "deny",
      ".opencode/artifacts/**": "allow",
      "docs/security/findings/**": "allow"
    },

    // Custom tools (explicitly allowed)
    "session_info": "allow",
    "timeline_validate": "allow",
    "mem_events": "allow",
    "memops_scan": "allow",
    "z3_smt2": "allow",

    // Safety rails
    "external_directory": "ask",
    "doom_loop": "ask",

    // Todo list tools (optional)
    "todoread": "allow",
    "todowrite": "allow"
  }
}
```

---

# 2) `AGENTS.md`

> Project rules loaded into context. ([OpenCode][3])

```md
# Security Rules (Memory Safety Pack)

## High-level goals
- Find and explain memory safety issues defensively.
- Produce consistent, auditable artifacts: Flow Walkthrough + timelines + (optional) Z3 feasibility.

## Hard safety rules
- Do NOT provide weaponized exploit payloads, heap grooming, mitigation bypass instructions, or real-world attack steps.
- Defensive guidance only (safe repro harness ideas, regression tests, proof of reachability).

## Required reporting artifacts for memory issues
When auditing C/C++ memory safety:

1) Flow Walkthrough (S1..Sn)
- Each step includes:
  - **What is happening**
  - **Memory snapshot** (allocation states + aliases)
  - **Evidence** (path:line-range)

2) Per-allocation lifetimes (A1..Ak)
- Each allocation gets a timeline with canonical events:
  - ALLOC, REALLOC, ALIAS, STORE, LOAD, FREE, NULLIFY, USE, ESCAPE
- Identify hazard windows:
  - UAF: USE after FREE
  - Double-free: FREE after FREE
  - Leak: ALLOC without a FREE (on reachable paths)

3) Z3 feasibility (recommended for suspected triggers)
- If there is a suspected trigger (FREE→USE, len>dst_size, double-free):
  - Extract minimal path constraints
  - Run z3_smt2
  - Record SAT/UNSAT and a **safe** witness model when SAT

## Artifact discipline (prevents losing work during compaction)
- Store machine artifacts under `.opencode/artifacts/`:
  - `<sessionID>__mem_timeline__<slug>.json`
  - `<sessionID>__mem_constraints__<slug>.smt2`
  - `<sessionID>__mem_z3__<slug>.json`
- Validate timeline JSON with `timeline_validate` before saving.
```

---

# 3) Agents

## 3.1 `.opencode/agents/vuln.md` (primary)

```md
---
description: Memory-safety security auditor. Produces Flow Walkthrough + per-allocation timelines + optional Z3 feasibility appendix. Writes only artifacts/findings.
mode: primary
temperature: 0.1
steps: 60

permission:
  task:
    "*": deny
    "vuln-*": allow
---

You are the primary memory-safety security auditor.

Primary outputs (always):
- Flow Walkthrough S1..Sn (What is happening + Memory snapshot + Evidence).
- Memory Objects table (A1..Ak).
- Allocation timelines per Ax.
Optional but recommended:
- Z3 feasibility appendix for suspected trigger paths.

Accuracy rules:
- Prefer file:line evidence over pasted code.
- Keep outputs compact and structured.
- When producing a Timeline Artifact JSON, validate it with timeline_validate.

Workflow (default):
1) Call session_info once to get sessionID/worktree.
2) Delegate timeline building to @vuln-mem.
3) Delegate memop hotspot ranking to @vuln-memop when useful.
4) Delegate feasibility to @vuln-smt when a trigger is suspected.
5) Save artifacts in `.opencode/artifacts/` with sessionID-based filenames.

Hard safety rule:
- No weaponized exploit instructions. Defensive and diagnostic only.
```

## 3.2 `.opencode/agents/vuln-mem.md` (timeline builder)

```md
---
description: Builds allocation/free/use timelines (A1..Ak) and a compact Timeline Artifact JSON to triage UAF/double-free/leaks.
mode: subagent
temperature: 0.1
steps: 45

tools:
  write: false
  edit: false
  patch: false
  bash: false
  webfetch: false
  websearch: false
  codesearch: false

permission:
  mem_events: allow
  timeline_validate: allow
  lsp: allow
---

You are a memory lifetime auditor for C/C++ codebases.

Goal:
- Track allocations, frees, and uses of heap objects and produce per-allocation timelines.
- Identify UAF, double-free, invalid free, lifetime confusion, and leaks.

Method:
1) Identify allocator/free APIs used (malloc/calloc/realloc/free, new/delete, wrappers).
2) Use mem_events to index alloc/free call sites in the target area quickly.
3) Choose the most reachable/important entry flow and build a Flow Walkthrough (S1..Sn).
4) Assign Allocation IDs (A1..Ak) to heap object identities (not pointer variables).
5) Build a timeline for each allocation:
   - ALLOC/REALLOC → ALIAS/STORE/LOAD/ESCAPE → FREE/NULLIFY → USE
6) Mark hazard windows:
   - UAF: USE after FREE for same Ax
   - Double-free: FREE after FREE
   - Leak: ALLOC without matching FREE on reachable paths

Required output:
A) Flow Walkthrough (S1..Sn) with evidence
B) Memory Objects table (A1..Ak)
C) Timeline tables per Ax
D) A single Timeline Artifact JSON (compact; ≤ ~200 lines)

Timeline Artifact JSON MUST include:
- target: string
- guards: { "G1": "...", ... }
- events: ordered list of memory-relevant events only
- allocs: A1..Ak with sites and aliases (best-effort)
- flow_steps: S1..Sn with where/evidence/what

Noise control:
- Do not paste whole files.
- Collapse loops/recursion into one summarized step if needed.
```

## 3.3 `.opencode/agents/vuln-memop.md` (memop triage + mini-timeline)

```md
---
description: Finds/ranks risky memory ops (memcpy/strcpy/sprintf/read/recv...) and can build a constraint-aware mini-timeline for a chosen callsite.
mode: subagent
temperature: 0.1
steps: 35

tools:
  write: false
  edit: false
  patch: false
  bash: false
  webfetch: false
  websearch: false
  codesearch: false

permission:
  memops_scan: allow
  lsp: allow
---

You triage memory-corruption-prone operations.

Part A — Scan & rank (default):
1) Run memops_scan on the target path.
2) Return top suspicious callsites with:
   - file:line
   - function (best-effort from context)
   - call snippet
   - why suspicious (len unbounded, dst size unclear, casts, etc.)

Part B — Mini-timeline for one callsite (if user provides a callsite):
- Extract dst/src/len expressions
- Determine dst_size_expr (from allocation/definition) and guards that constrain len/dst_size
- Propose a bug predicate:
  - e.g., len > dst_size
  - or idx >= size

Output stays compact and evidence-based.
No exploit payloads.
```

## 3.4 `.opencode/agents/vuln-smt.md` (constraints + Z3)

```md
---
description: SMT/Z3 feasibility analyst. Converts a suspected trigger path into constraints and checks SAT/UNSAT. Defensive reachability only.
mode: subagent
temperature: 0.1
steps: 45

tools:
  write: false
  edit: false
  patch: false
  bash: false
  webfetch: false
  websearch: false
  codesearch: false

permission:
  z3_smt2: allow
---

You are an SMT feasibility analyst for memory-safety findings.

Goal:
- Given a concrete suspected trigger (FREE→USE, double-free, len>dst_size, OOB predicate),
  determine whether the required path conditions are satisfiable.

Rules:
- Start Int/QF_LIA first.
- Use BitVec only when wraparound/truncation is essential.
- Keep SMT small: only variables and guards needed.
- Run z3_smt2 and interpret:
  - SAT: provide one safe witness model (values) for regression testing
  - UNSAT: explain contradiction

Hard safety rule:
- No exploitation steps or payloads. Defensive only.
```

---

# 4) Skills

## 4.1 `.opencode/skills/memory-lifetime-timeline/SKILL.md`

> Must be named `SKILL.md`, and frontmatter can only include recognized fields. ([OpenCode][4])

```md
---
name: memory-lifetime-timeline
description: Build per-allocation lifetimes (ALLOC/ALIAS/FREE/USE) as step-by-step timelines to detect UAF/double-free/leaks with evidence and “What is happening” at each step.
license: MIT
compatibility: opencode
metadata:
  domain: security
  category: memory-safety
---

## Allocation IDs
Assign each heap allocation a stable ID:
- A1, A2, A3...
The ID refers to the heap object identity, not a pointer variable.

## Canonical event types
Use these canonical events in timelines:
- ALLOC: malloc/calloc/new
- REALLOC: realloc (identity may change)
- ALIAS: another pointer refers to same allocation (assignment, param passing)
- STORE: pointer stored into struct/global/container
- LOAD: pointer loaded back from struct/global/container
- FREE: free/delete on an alias
- NULLIFY: pointer set to NULL (for that alias only)
- USE: dereference/index/memcpy/strcmp/strlen/field access/etc.
- ESCAPE: returned/stored externally; lifetime crosses boundary

## Required outputs

### 1) Flow Walkthrough (S1..Sn)
Each step includes:
- **What is happening**
- **Memory snapshot**: Ax states + alias set
- **Evidence**: path:Lx-Ly

### 2) Memory Objects table
| AllocID | Allocation site | Type/Kind | Size expr | Primary owner | Aliases |

### 3) Timeline per allocation
| T | Flow step (S#) | Event | Where | What is happening | Heap state after | Evidence |

## Timeline Artifact JSON (required)
Emit a single compact JSON object:

- target: string
- flow_steps: [{ id:"S1", where:"...", evidence:"...", what:"..." }]
- allocs: [{ id:"A1", site:"...", size_expr:"...", owner:"...", aliases:["p","q"] }]
- guards: { "G1": "cond expr", ... }
- events: [{ id:"E1", kind:"ALLOC|FREE|USE|...", alloc:"A1", step:"S3", site:"...", guard:["G1"] }]

Noise control:
- Keep events ≤ 30; collapse loops into summary events.
- Prefer file:line evidence instead of dumping code.
```

## 4.2 `.opencode/skills/z3-feasibility/SKILL.md`

```md
---
name: z3-feasibility
description: Turn a suspected memory bug trigger path into SMT constraints and use Z3 to check SAT/UNSAT, recording a safe witness model for regression tests.
license: MIT
compatibility: opencode
metadata:
  domain: security
  category: feasibility
---

## What we are solving
We are NOT exploiting anything. We are checking reachability of a bad state.

Bad states:
- UAF: FREE(Ax) then later USE(Ax)
- Double-free: FREE(Ax) twice
- OOB: idx >= size or idx < 0 at USE
- Memop overflow: len > dst_size at memcpy/memmove/strcpy-like sinks

## Workflow
1) Start from Flow Walkthrough + timeline (identify the trigger step ⚠️).
2) Identify symbolic vars (inputs/state).
3) Extract minimal guards from code (ifs/switch/bounds checks).
4) Write minimal SMT-LIB:
   - Prefer (set-logic QF_LIA) with Int/Bool first.
   - Switch to BitVec only when needed.
5) Run z3_smt2 and interpret:
   - SAT: record one safe witness model for tests
   - UNSAT: explain contradiction

## Required report section
- Variables table
- SMT-LIB (decls + asserts)
- Z3 result (sat/unsat/unknown) + model if sat
- Explanation tying the model back to S# steps
```

---

# 5) Tools

## 5.1 `.opencode/tools/session_info.ts`

> Uses documented tool context fields. ([OpenCode][5])

```ts
import { tool } from "@opencode-ai/plugin"

export default tool({
  description: "Return OpenCode session context (agent, sessionID, messageID, directory, worktree).",
  args: {},
  async execute(_args, context) {
    const { agent, sessionID, messageID, directory, worktree } = context
    return { agent, sessionID, messageID, directory, worktree }
  }
})
```

---

## 5.2 `.opencode/tools/timeline_validate.ts`

> Validates Timeline Artifact JSON so the agent can self-correct.

```ts
import { tool } from "@opencode-ai/plugin"

const EventKind = tool.schema.union([
  tool.schema.literal("ALLOC"),
  tool.schema.literal("REALLOC"),
  tool.schema.literal("ALIAS"),
  tool.schema.literal("STORE"),
  tool.schema.literal("LOAD"),
  tool.schema.literal("FREE"),
  tool.schema.literal("NULLIFY"),
  tool.schema.literal("USE"),
  tool.schema.literal("ESCAPE")
])

const EventSchema = tool.schema.object({
  id: tool.schema.string(),
  kind: EventKind,
  alloc: tool.schema.string().optional(),
  step: tool.schema.string().optional(),
  site: tool.schema.string(),
  guard: tool.schema.array(tool.schema.string()).optional(),
  detail: tool.schema.string().optional()
})

const TimelineSchema = tool.schema.object({
  target: tool.schema.string(),
  flow_steps: tool.schema
    .array(
      tool.schema.object({
        id: tool.schema.string(),
        where: tool.schema.string(),
        evidence: tool.schema.string(),
        what: tool.schema.string()
      })
    )
    .optional(),
  allocs: tool.schema
    .array(
      tool.schema.object({
        id: tool.schema.string(),
        site: tool.schema.string(),
        size_expr: tool.schema.string().optional(),
        owner: tool.schema.string().optional(),
        aliases: tool.schema.array(tool.schema.string()).optional()
      })
    )
    .optional(),
  guards: tool.schema.record(tool.schema.string(), tool.schema.string()).optional(),
  events: tool.schema.array(EventSchema),
  notes: tool.schema.array(tool.schema.string()).optional()
})

export default tool({
  description:
    "Validate Timeline Artifact JSON against the memory timeline schema. Returns ok=true or ok=false with errors.",
  args: {
    json: tool.schema.string().describe("Timeline Artifact JSON string")
  },

  async execute(args) {
    let parsed: unknown
    try {
      parsed = JSON.parse(args.json)
    } catch (e) {
      return { ok: false, errors: [{ path: "", message: "Invalid JSON", detail: String(e) }] }
    }

    const result = TimelineSchema.safeParse(parsed)
    if (result.success) return { ok: true }

    return {
      ok: false,
      errors: result.error.issues.map((i) => ({
        path: i.path.join("."),
        message: i.message
      }))
    }
  }
})
```

---

## 5.3 `.opencode/tools/mem_events.py`

```py
#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys

DEFAULT_EXTS = [".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".hh", ".hxx"]

ALLOC_DEFAULT = ["malloc", "calloc", "realloc"]
FREE_DEFAULT = ["free"]

# Very heuristic C++ signals
CPP_NEW_RE = re.compile(r"\bnew\b")
CPP_DELETE_RE = re.compile(r"\bdelete\b(\s*\[\s*\])?\s+(?P<arg>[^;]+)")

ASSIGN_RE = re.compile(
    r"(?P<lhs>[A-Za-z_]\w*)\s*=\s*(?:\([^)]+\)\s*)?(?P<fn>malloc|calloc|realloc)\s*\("
)
ALLOC_CALL_RE = re.compile(r"\b(?P<fn>malloc|calloc|realloc)\s*\(")
FREE_CALL_RE = re.compile(r"\bfree\s*\(\s*(?P<arg>[^)]+)\)")

def iter_files(root, exts):
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if any(fn.endswith(ext) for ext in exts):
                yield os.path.join(dirpath, fn)

def scan_file(path, alloc_funs, free_funs, max_events):
    events = []
    try:
        with open(path, "r", errors="ignore") as f:
            for i, line in enumerate(f, start=1):
                if len(events) >= max_events:
                    break
                s = line.strip()

                m = ASSIGN_RE.search(line)
                if m and m.group("fn") in alloc_funs:
                    events.append({
                        "kind": "alloc",
                        "fn": m.group("fn"),
                        "lhs": m.group("lhs"),
                        "file": path,
                        "line": i,
                        "code": s
                    })
                    continue

                m2 = ALLOC_CALL_RE.search(line)
                if m2 and m2.group("fn") in alloc_funs:
                    events.append({
                        "kind": "alloc",
                        "fn": m2.group("fn"),
                        "lhs": None,
                        "file": path,
                        "line": i,
                        "code": s
                    })
                    continue

                m3 = FREE_CALL_RE.search(line)
                if m3 and "free" in free_funs:
                    events.append({
                        "kind": "free",
                        "fn": "free",
                        "arg": m3.group("arg").strip(),
                        "file": path,
                        "line": i,
                        "code": s
                    })
                    continue

                # Heuristic new/delete sightings (not mapped to a lhs reliably)
                if CPP_NEW_RE.search(line):
                    events.append({
                        "kind": "alloc",
                        "fn": "new",
                        "lhs": None,
                        "file": path,
                        "line": i,
                        "code": s
                    })
                    continue

                md = CPP_DELETE_RE.search(line)
                if md:
                    events.append({
                        "kind": "free",
                        "fn": "delete",
                        "arg": md.group("arg").strip(),
                        "file": path,
                        "line": i,
                        "code": s
                    })
                    continue

    except Exception:
        return events

    return events

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help="File or directory to scan")
    ap.add_argument("--ext", action="append", default=[])
    ap.add_argument("--alloc", action="append", default=[])
    ap.add_argument("--free", action="append", default=[])
    ap.add_argument("--max", type=int, default=2000)
    args = ap.parse_args()

    exts = args.ext if args.ext else DEFAULT_EXTS
    alloc_funs = ALLOC_DEFAULT + args.alloc
    free_funs = FREE_DEFAULT + args.free

    root = args.path
    all_events = []

    if os.path.isfile(root):
        all_events.extend(scan_file(root, alloc_funs, free_funs, args.max))
    else:
        for fp in iter_files(root, exts):
            all_events.extend(scan_file(fp, alloc_funs, free_funs, args.max - len(all_events)))
            if len(all_events) >= args.max:
                break

    print(json.dumps({
        "path": root,
        "exts": exts,
        "alloc_funs": alloc_funs,
        "free_funs": free_funs,
        "events": all_events
    }))

if __name__ == "__main__":
    sys.exit(main())
```

---

## 5.4 `.opencode/tools/mem_events.ts`

```ts
import { tool } from "@opencode-ai/plugin"
import path from "path"

export default tool({
  description:
    "Index malloc/calloc/realloc/free (and heuristic new/delete sightings) under a path. Returns JSON (heuristic, not a full analyzer).",
  args: {
    path: tool.schema.string().describe("File or directory to scan (relative to repo root allowed)"),
    max: tool.schema.number().int().positive().optional().describe("Max events (default 2000)"),
    ext: tool.schema.array(tool.schema.string()).optional().describe("File extensions to include"),
    alloc: tool.schema.array(tool.schema.string()).optional().describe("Extra alloc functions (wrappers)"),
    free: tool.schema.array(tool.schema.string()).optional().describe("Extra free functions (wrappers)")
  },

  async execute(args, context) {
    const script = path.join(context.worktree, ".opencode/tools/mem_events.py")
    const scanPath = path.isAbsolute(args.path) ? args.path : path.join(context.worktree, args.path)

    const max = args.max ?? 2000
    const extArgs = (args.ext ?? []).flatMap((e) => ["--ext", e])
    const allocArgs = (args.alloc ?? []).flatMap((f) => ["--alloc", f])
    const freeArgs = (args.free ?? []).flatMap((f) => ["--free", f])

    const out = await Bun.$`python3 ${script} ${scanPath} --max ${max} ${extArgs} ${allocArgs} ${freeArgs}`.text()
    try {
      return JSON.parse(out)
    } catch {
      return out.trim()
    }
  }
})
```

---

## 5.5 `.opencode/tools/memops_scan.py`

```py
#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys

DEFAULT_EXTS = [".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".hh", ".hxx"]

SINKS = [
    "memcpy", "memmove", "memset",
    "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "vsprintf", "snprintf", "vsnprintf",
    "gets",
    "read", "recv", "recvfrom", "fread"
]

CALL_RE = re.compile(r"\b(?P<fn>" + "|".join(map(re.escape, SINKS)) + r")\s*\(")

def iter_files(root, exts):
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if any(fn.endswith(ext) for ext in exts):
                yield os.path.join(dirpath, fn)

def score(fn, line):
    base = {
        "gets": 100,
        "strcpy": 95,
        "sprintf": 95,
        "vsprintf": 95,
        "strcat": 85,
        "strncpy": 70,
        "strncat": 70,
        "snprintf": 60,
        "vsnprintf": 60,
        "memcpy": 65,
        "memmove": 60,
        "memset": 35,
        "read": 55,
        "recv": 55,
        "recvfrom": 55,
        "fread": 50
    }.get(fn, 40)

    s = line.strip()
    if "sizeof(" in s or "sizeof " in s:
        base -= 10
    if re.search(r"\b\d+\b", s):
        base -= 5
    if re.search(r"\b(len|size|count|nbytes|bytes|total|input|payload)\b", s):
        base += 8
    return max(1, min(100, base))

def scan_file(path, max_hits):
    hits = []
    try:
        with open(path, "r", errors="ignore") as f:
            for i, line in enumerate(f, start=1):
                if len(hits) >= max_hits:
                    break
                m = CALL_RE.search(line)
                if not m:
                    continue
                fn = m.group("fn")
                hits.append({
                    "kind": "memop",
                    "fn": fn,
                    "score": score(fn, line),
                    "file": path,
                    "line": i,
                    "code": line.strip()
                })
    except Exception:
        return hits
    return hits

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help="File or directory to scan")
    ap.add_argument("--ext", action="append", default=[])
    ap.add_argument("--max", type=int, default=2000)
    args = ap.parse_args()

    exts = args.ext if args.ext else DEFAULT_EXTS
    root = args.path

    all_hits = []
    if os.path.isfile(root):
        all_hits.extend(scan_file(root, args.max))
    else:
        for fp in iter_files(root, exts):
            all_hits.extend(scan_file(fp, args.max - len(all_hits)))
            if len(all_hits) >= args.max:
                break

    all_hits.sort(key=lambda h: (-h["score"], h["file"], h["line"]))

    print(json.dumps({
        "path": root,
        "exts": exts,
        "sinks": SINKS,
        "hits": all_hits
    }))
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

---

## 5.6 `.opencode/tools/memops_scan.ts`

```ts
import { tool } from "@opencode-ai/plugin"
import path from "path"

export default tool({
  description:
    "Scan and rank risky memory operations (memcpy/strcpy/sprintf/read/recv...). Returns JSON with heuristic scores.",
  args: {
    path: tool.schema.string().describe("File or directory to scan (relative to repo root allowed)"),
    max: tool.schema.number().int().positive().optional().describe("Max hits (default 2000)"),
    ext: tool.schema.array(tool.schema.string()).optional().describe("File extensions to include")
  },

  async execute(args, context) {
    const script = path.join(context.worktree, ".opencode/tools/memops_scan.py")
    const scanPath = path.isAbsolute(args.path) ? args.path : path.join(context.worktree, args.path)

    const max = args.max ?? 2000
    const extArgs = (args.ext ?? []).flatMap((e) => ["--ext", e])

    const out = await Bun.$`python3 ${script} ${scanPath} --max ${max} ${extArgs}`.text()
    try {
      return JSON.parse(out)
    } catch {
      return out.trim()
    }
  }
})
```

---

## 5.7 `.opencode/tools/z3_smt2.py`

> Runs Z3 on SMT2. Prefers `z3-solver` (structured JSON model). Falls back to `z3` binary if needed.

```py
#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

# Strip interactive commands from input; we only want decls/defs/asserts.
STRIP_CMD_RE = re.compile(r"^\s*\((check-sat|get-model|exit|push|pop)\b", re.IGNORECASE)

def sanitize_smt2(text: str) -> str:
    lines = []
    for line in text.splitlines():
        if STRIP_CMD_RE.match(line):
            continue
        lines.append(line)
    return "\n".join(lines).strip() + "\n"

def try_z3py(smt2_text: str, timeout_ms: int | None):
    try:
        from z3 import Solver, parse_smt2_string
    except Exception as e:
        return None, f"z3-solver not available: {e}"

    s = Solver()
    if timeout_ms is not None:
        try:
            s.set(timeout=timeout_ms)
        except Exception:
            pass

    core = sanitize_smt2(smt2_text)

    # parse_smt2_string returns a list of assertions (BoolRefs)
    try:
        constraints = parse_smt2_string(core)
        for c in constraints:
            s.add(c)
    except Exception as e:
        return {
            "engine": "z3py",
            "status": "error",
            "model": None,
            "stdout": "",
            "stderr": f"ERROR parsing SMT2: {e}",
            "exitCode": 2
        }, None

    r = s.check()
    status = str(r)

    if status == "sat":
        m = s.model()
        model = {}
        # Emit simple mapping for declared symbols in model
        for d in m.decls():
            try:
                model[d.name()] = str(m[d])
            except Exception:
                model[d.name()] = "<unprintable>"
        return {
            "engine": "z3py",
            "status": "sat",
            "model": model,
            "stdout": "sat",
            "stderr": "",
            "exitCode": 0
        }, None

    if status == "unsat":
        return {"engine": "z3py", "status": "unsat", "model": None, "stdout": "unsat", "stderr": "", "exitCode": 0}, None

    return {"engine": "z3py", "status": "unknown", "model": None, "stdout": "unknown", "stderr": "", "exitCode": 0}, None

def try_z3_binary(smt2_text: str, timeout_ms: int | None):
    z3 = shutil.which("z3")
    if not z3:
        return None

    prelude = "(set-option :produce-models true)\n"
    if timeout_ms is not None:
        prelude += f"(set-option :timeout {timeout_ms})\n"

    full = prelude + sanitize_smt2(smt2_text) + "\n(check-sat)\n(get-model)\n"
    with tempfile.NamedTemporaryFile("w", suffix=".smt2", delete=False) as tf:
        tf.write(full)
        tmp = tf.name

    try:
        proc = subprocess.run([z3, "-smt2", tmp], capture_output=True, text=True)
        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        status = (out.split()[:1] or ["unknown"])[0]
        if status not in ("sat", "unsat", "unknown"):
            status = "unknown"

        # Best-effort: do not parse model text (format varies). Keep raw stdout.
        return {
            "engine": "z3-binary",
            "status": status,
            "model": None,
            "stdout": out,
            "stderr": err,
            "exitCode": proc.returncode
        }
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", help="Path to SMT2 file")
    ap.add_argument("--text", help="Inline SMT2 text")
    ap.add_argument("--timeout-ms", type=int, default=0)
    args = ap.parse_args()

    if not args.file and not args.text:
        print(json.dumps({"status": "error", "stderr": "Provide --file or --text"}))
        return 2

    if args.file:
        with open(args.file, "r", errors="ignore") as f:
            smt2 = f.read()
    else:
        smt2 = args.text

    timeout = args.timeout_ms if args.timeout_ms and args.timeout_ms > 0 else None

    r, warn = try_z3py(smt2, timeout)
    if r is not None:
        print(json.dumps(r))
        return 0 if r.get("status") != "error" else 2

    # z3py not available, fall back to binary
    rb = try_z3_binary(smt2, timeout)
    if rb is None:
        print(json.dumps({
            "engine": "none",
            "status": "error",
            "model": None,
            "stdout": "",
            "stderr": (warn or "") + " | Also no z3 binary found in PATH.",
            "exitCode": 2
        }))
        return 2

    print(json.dumps(rb))
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

---

## 5.8 `.opencode/tools/z3_smt2.ts`

```ts
import { tool } from "@opencode-ai/plugin"
import path from "path"

export default tool({
  description:
    "Run Z3 on SMT-LIB2 (decls+asserts) and return JSON: sat/unsat/unknown plus model when available. Defensive feasibility only.",
  args: {
    file: tool.schema.string().optional().describe("Path to .smt2 file (relative to repo root allowed)"),
    text: tool.schema.string().optional().describe("Inline SMT2 content (decls + asserts preferred)"),
    timeout_ms: tool.schema.number().int().positive().optional().describe("Optional Z3 timeout in ms")
  },

  async execute(args, context) {
    const script = path.join(context.worktree, ".opencode/tools/z3_smt2.py")
    const timeout = args.timeout_ms ?? 0

    if (!args.file && !args.text) {
      return { status: "error", stderr: "Provide 'file' or 'text'", stdout: "" }
    }

    let out: string
    if (args.file) {
      const abs = path.isAbsolute(args.file) ? args.file : path.join(context.worktree, args.file)
      out = await Bun.$`python3 ${script} --file ${abs} --timeout-ms ${timeout}`.text()
    } else {
      out = await Bun.$`python3 ${script} --text ${args.text} --timeout-ms ${timeout}`.text()
    }

    try {
      return JSON.parse(out)
    } catch {
      return { engine: "unknown", status: "unknown", model: null, stdout: out.trim(), stderr: "" }
    }
  }
})
```

---

# 6) Commands

> Commands use YAML frontmatter + body template. Placeholders supported: `$ARGUMENTS`, `$1..$n`, `!` bash output injection, and `@file` includes file content. ([OpenCode][6])

## 6.1 `.opencode/commands/sec-finding-new.md`

```md
---
description: Create a new memory finding report from TEMPLATE-memory.md.
agent: vuln
---

Create a new finding report at: `docs/security/findings/$1.md`

- Use template: @docs/security/findings/TEMPLATE-memory.md
- Set the frontmatter `id` field to: $1
- Set the title to: $2
- Keep status: draft
- Leave severity/cwe/component unknown unless clearly evidenced.

Safety:
- No exploit payloads.
- Defensive guidance only.
```

Usage:

* `/sec-finding-new VR-0007 "UAF in foo parser"`

---

## 6.2 `.opencode/commands/sec-mem-timeline.md`

```md
---
description: Build Flow Walkthrough + per-allocation timelines and save a Timeline Artifact JSON into .opencode/artifacts/.
agent: vuln
---

Target: $ARGUMENTS

Do the following:
1) Call session_info (get sessionID/worktree).
2) Load skill `memory-lifetime-timeline`.
3) Use @vuln-mem to produce:
   - Flow Walkthrough S1..Sn (with evidence + memory snapshots)
   - Memory Objects table (A1..Ak)
   - Allocation timeline table for each Ax
   - Timeline Artifact JSON (single object)
4) Validate the JSON by calling timeline_validate.
   - If validation fails, fix JSON and re-validate until ok=true.
5) Write the validated Timeline Artifact JSON to:
   `.opencode/artifacts/<sessionID>__mem_timeline__<slug>.json`
   (Choose a safe slug derived from the target, like "parser" or "ctx_buf".)

Safety: No exploit payloads or heap grooming. Defensive/diagnostic only.
```

---

## 6.3 `.opencode/commands/sec-memop-scan.md`

```md
---
description: Scan and rank risky memops (memcpy/strcpy/sprintf/read/recv...). Save results to .opencode/artifacts/.
agent: vuln
---

Target path: $ARGUMENTS

1) Call session_info.
2) Call memops_scan on the target path.
3) Print the top 20 callsites with:
   - file:line
   - call
   - why suspicious
4) Save the raw scan JSON to:
   `.opencode/artifacts/<sessionID>__mem_memops_scan__<slug>.json`
```

---

## 6.4 `.opencode/commands/sec-memop-timeline.md`

```md
---
description: Build a constraint-aware mini-timeline for a specific memop callsite.
agent: vuln
---

Callsite: $ARGUMENTS

Use @vuln-memop.

Output:
- Callsite summary (dst/src/len expressions; evidence)
- dst_size_expr (best-effort) and guards
- Proposed bug predicate (e.g., len > dst_size)
- Minimal human-readable constraints list suitable for Z3
```

---

## 6.5 `.opencode/commands/sec-mem-z3.md`

```md
---
description: Build SMT constraints for a suspected trigger and run Z3. Save SMT2 + Z3 JSON output into .opencode/artifacts/.
agent: vuln
---

Target: $ARGUMENTS

1) Call session_info.
2) Load skill `z3-feasibility`.
3) Require a concrete trigger:
   - FREE(Ax) then USE(Ax), OR
   - double-free, OR
   - OOB predicate, OR
   - memop overflow (len > dst_size)
4) Produce minimal SMT-LIB (decls + asserts).
   - Prefer QF_LIA (Int/Bool) first.
   - Only use BitVec if wraparound/truncation is essential.
5) Call z3_smt2 with the SMT2 text.
6) Save:
   - SMT constraints: `.opencode/artifacts/<sessionID>__mem_constraints__<slug>.smt2`
   - Z3 output JSON: `.opencode/artifacts/<sessionID>__mem_z3__<slug>.json`
7) Emit a “Feasibility (Z3)” appendix:
   - variables table
   - SMT2 code fence
   - Z3 status + model (safe witness values only)
   - tie back to flow steps S#

Safety: No exploit payloads; only safe regression test values if SAT.
```

---

## 6.6 `.opencode/commands/sec-mem-triage.md` (NEW “end-to-end” command)

This is the “one command” workflow you asked for: creates finding if missing, builds timeline, runs Z3 if a trigger is suspected, and patches the report.

```md
---
description: End-to-end memory finding triage: create/update report, build timelines, and (if applicable) run Z3 feasibility. Writes only docs/security/findings and .opencode/artifacts.
agent: vuln
---

Finding ID: $1
Target: $2

End-to-end workflow:

A) Ensure report exists
1) If `docs/security/findings/$1.md` does not exist, create it using:
   /sec-finding-new $1 "Memory safety triage: $2"
   (Otherwise, keep existing content and append/update relevant sections.)

B) Timeline & flow
2) Run /sec-mem-timeline $2
3) If timelines indicate a suspected trigger (UAF/double-free/OOB/len>dst_size), run:
   /sec-mem-z3 $2
   Otherwise, skip Z3 and explicitly state why (no clear trigger / no constraints / needs dynamic validation).

C) Patch the report file
4) Update `docs/security/findings/$1.md` with:
   - TL;DR (impact, bug class, trigger step)
   - Flow table (S1..Sn)
   - Memory Objects table (A1..Ak)
   - Allocation timelines (at least the suspicious Ax)
   - Feasibility (Z3) section if run
   - Root cause + fix recommendation + safe regression test idea
   - Artifacts section with the exact artifact paths written

Rules:
- Evidence links must be file:line ranges.
- Do not paste full files or large functions.
- No exploit payloads or heap grooming.
```

Usage:

* `/sec-mem-triage VR-0007 src/parser.c`
* `/sec-mem-triage VR-0008 src/ foo_parse` (use quotes if needed)

---

# 7) Report template

## 7.1 `docs/security/findings/TEMPLATE-memory.md`

````md
---
id: VR-0000
status: draft
severity: unknown
cwe: unknown
component: unknown
bug_class: memory-safety
---

# <Finding Title>

## 0) TL;DR
**Impact:** <one sentence>  
**Bug class:** <UAF / double free / OOB read / OOB write / memop overflow>  
**Bug triggers at:** ⚠️ Step [S?](#s)  
**Primary fix:** <one sentence>  

## 1) Scope and Preconditions
- **Attack surface:** <entry point>
- **Attacker:** <unauth/auth/role/etc.>
- **Required conditions:** <flags/state/config>

## 2) Artifacts (for reproducibility)
- Timeline Artifact JSON: `.opencode/artifacts/<sessionID>__mem_timeline__<slug>.json`
- SMT constraints: `.opencode/artifacts/<sessionID>__mem_constraints__<slug>.smt2`
- Z3 output: `.opencode/artifacts/<sessionID>__mem_z3__<slug>.json`

## 3) Flow at a Glance
**Chain:** [S1](#s1) → [S2](#s2) → … → [Sn](#sn)  
**Bug triggers:** ⚠️ [S?](#s)

```mermaid
flowchart TD
  S1[S1: Entry] --> S2[S2: Parse/Dispatch]
  S2 --> S3[S3: Allocate Ax]
  S3 --> S4[S4: Free Ax]
  S4 --> S5[S5: Use Ax ⚠️]
````

## 4) Flow Table (One Screen Review)

| Step  | Where           | What is happening                                                    | Memory snapshot            | Evidence       |
| ----- | --------------- | -------------------------------------------------------------------- | -------------------------- | -------------- |
| S1    | `<file>::<sym>` | **What is happening:** <…>                                           | (none yet)                 | `<path>:Lx-Ly` |
| S2    | `<file>::<sym>` | **What is happening:** <…>                                           | (none yet)                 | `<path>:Lx-Ly` |
| S3    | `<file>::<sym>` | **What is happening:** Allocates **A1** and stores pointer in `p`.   | `A1=allocated; p→A1`       | `<path>:Lx-Ly` |
| S4    | `<file>::<sym>` | **What is happening:** Frees `p` under condition `<cond>`.           | `A1=freed; p→A1(dangling)` | `<path>:Lx-Ly` |
| S5 ⚠️ | `<file>::<sym>` | **What is happening:** Uses `p` after free (dereference/copy/index). | `A1=freed; USE(A1)`        | `<path>:Lx-Ly` |

## 5) Memory Objects (A1..Ak)

| AllocID | Allocation site | Size expr | Owner                  | Aliases (tracked) |
| ------- | --------------- | --------- | ---------------------- | ----------------- |
| A1      | `<file>:Lx`     | `<expr>`  | `<component/function>` | `p,q,...`         |

## 6) Allocation Timelines

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

## 7) Feasibility (Z3) (Optional but recommended)

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
* Interpretation: <tie back to S# steps>

## 8) Root Cause

<one paragraph>

## 9) Fix Recommendation

### Minimal fix

* <e.g., nullify pointers after free, fix ownership, guard use>

### Defense in depth (optional)

* <ownership API, RAII, refcounting, clearer contracts>

## 10) Regression Test Idea (Safe)

* <safe harness/unit test/integration test>

## Appendix A — Timeline Artifact JSON (optional)

```json
{ "...": "..." }
```

````

---

## 7.2 `docs/security/findings/README.md`

```md
# Memory Safety Pack (OpenCode)

## Commands
- `/sec-finding-new VR-0007 "Title"`: create a new report stub
- `/sec-mem-timeline <path|symbol>`: build Flow Walkthrough + allocation timelines + Timeline Artifact JSON
- `/sec-memop-scan <path>`: rank risky memops (memcpy/strcpy/sprintf/read/recv)
- `/sec-memop-timeline <file:line>`: mini-timeline for one memop sink
- `/sec-mem-z3 <target>`: build constraints + run Z3 feasibility; saves SMT2 + Z3 JSON
- `/sec-mem-triage VR-0007 <target>`: end-to-end: create/update report, timeline, Z3 if applicable

## Z3 setup
Recommended:
- `pip install z3-solver`

Fallback:
- Install the `z3` binary and ensure it is in PATH.

## Artifacts
The pack stores machine outputs in `.opencode/artifacts/` using session-scoped filenames:
- `<sessionID>__mem_timeline__<slug>.json`
- `<sessionID>__mem_constraints__<slug>.smt2`
- `<sessionID>__mem_z3__<slug>.json`
````

---

## You can now run (example)

* `/sec-mem-triage VR-0001 src/`
* or:

  * `/sec-memop-scan src/`
  * `/sec-memop-timeline src/foo.c:123`
  * `/sec-mem-z3 src/foo.c:123`

If you want one more accuracy upgrade after you try this once: I can add a **“timeline normalizer” tool** that (a) rewrites the Timeline Artifact into a canonical form (stable event ordering + normalized sites/guards) and (b) automatically generates the SMT skeleton for common predicates (FREE→USE, len>dst_size), reducing model variance even further.

[1]: https://opencode.ai/docs/agents/ "Agents | OpenCode"
[2]: https://opencode.ai/docs/config/ "Config | OpenCode"
[3]: https://opencode.ai/docs/rules/?utm_source=chatgpt.com "Rules - opencode"
[4]: https://opencode.ai/docs/skills/ "Agent Skills | OpenCode"
[5]: https://opencode.ai/docs/custom-tools/ "Custom Tools | OpenCode"
[6]: https://opencode.ai/docs/commands/ "Commands | OpenCode"


-----------+++++++++++++

Below is a **single, “best-practice” OpenCode memory-safety pack** that combines both of your drafts into one coherent workflow:

* **Use case 1:** malloc/free **lifetime timelines** (UAF / double-free / leak triage)
* **Use case 2:** **Z3 feasibility** (SAT/UNSAT for “FREE then USE” or “len > dst_size” triggers)
* Plus a couple of **small tools** to make open(-source) models much more consistent:

  * `memops_scan` (find/rank risky memcpy/strcpy/etc callsites)
  * `timeline_validate` (schema-check the Timeline Artifact JSON so it stays machine-usable)
  * `session_info` (so artifacts can be session-scoped and reproducible)

Everything is aligned with OpenCode’s current conventions for:

* **Agents** (`.opencode/agents/*.md`) ([opencode.ai][1])
* **Commands** (`.opencode/commands/*.md`) + `$ARGUMENTS` / `$1..$n` / `!` / `@file` ([opencode.ai][2])
* **Skills** (`.opencode/skills/<name>/SKILL.md` with strict naming rules) ([opencode.ai][3])
* **Custom tools** (`.opencode/tools/*.ts` invoking Python/scripts as needed; tool context includes `sessionID`, `worktree`, etc.) ([opencode.ai][4])
* **Permissions** (pattern-based, per-tool; `edit` covers write/edit/patch) ([opencode.ai][5])

---

## 1) File tree to add

```text
opencode.jsonc
AGENTS.md

.opencode/
  agents/
    vuln.md
    vuln-mem.md
    vuln-memop.md
    vuln-smt.md

  commands/
    sec-finding-new.md
    sec-mem-timeline.md
    sec-memop-scan.md
    sec-memop-timeline.md
    sec-mem-z3.md

  skills/
    memory-lifetime-timeline/SKILL.md
    z3-feasibility/SKILL.md

  tools/
    mem_events.py
    mem_events.ts
    memops_scan.py
    memops_scan.ts
    z3_smt2.py
    z3_smt2.ts
    timeline_validate.ts
    session_info.ts

docs/security/findings/
  TEMPLATE-memory.md
```

---

## 2) Project config: `opencode.jsonc`

This config is tuned for **security auditing**:

* Fast read/grep/glob/list are allowed
* **No web** (webfetch/websearch/codesearch denied)
* **No source edits** — only allow writes to:

  * `.opencode/artifacts/**` (machine outputs)
  * `docs/security/findings/**` (your reports)
* Allow spawning only your `vuln-*` subagents
* Enable LSP queries if you run with the experimental LSP tool enabled (optional) ([opencode.ai][6])

```jsonc
{
  "$schema": "https://opencode.ai/config.json",

  // Make the security auditor your default entrypoint.
  // Default agent must be a primary agent. :contentReference[oaicite:6]{index=6}
  "default_agent": "vuln",

  "permission": {
    // Safe static analysis
    "read": {
      "*": "allow",
      "*.env": "deny",
      "*.env.*": "deny",
      "*.env.example": "allow"
    },
    "grep": "allow",
    "glob": "allow",
    "list": "allow",

    // Skills are loaded on-demand via the skill tool. :contentReference[oaicite:7]{index=7}
    "skill": { "*": "allow" },

    // Optional: enable the LSP tool if you set OPENCODE_EXPERIMENTAL_LSP_TOOL=true. :contentReference[oaicite:8]{index=8}
    "lsp": "allow",

    // Keep todo tools usable in the primary agent (subagents are disabled by default). :contentReference[oaicite:9]{index=9}
    "todoread": "allow",
    "todowrite": "allow",

    // Subagent launches (only our pack)
    "task": {
      "*": "deny",
      "vuln-*": "allow"
    },

    // No outbound internet
    "webfetch": "deny",
    "websearch": "deny",
    "codesearch": "deny",

    // No repo edits. Only artifacts + findings are writable. :contentReference[oaicite:10]{index=10}
    "edit": {
      "*": "deny",
      ".opencode/artifacts/**": "allow",
      "docs/security/findings/**": "allow"
    },

    // Bash optional: allow “read-only” commands; ask otherwise. :contentReference[oaicite:11]{index=11}
    "bash": {
      "*": "ask",
      "rg *": "allow",
      "grep *": "allow",
      "git status*": "allow",
      "git diff*": "allow",
      "git log*": "allow"
    },

    // Custom tools (read-only)
    "mem_events": "allow",
    "memops_scan": "allow",
    "z3_smt2": "allow",
    "timeline_validate": "allow",
    "session_info": "allow",

    // Safety guards
    "external_directory": "ask",
    "doom_loop": "ask"
  },

  // Compaction settings (helps long audits). :contentReference[oaicite:12]{index=12}
  "compaction": {
    "auto": true,
    "prune": true,
    "reserved": 12000
  },

  // Reduce noise in watcher/diagnostics. :contentReference[oaicite:13]{index=13}
  "watcher": {
    "ignore": [
      ".git/**",
      "node_modules/**",
      "dist/**",
      "build/**",
      "out/**",
      ".opencode/artifacts/**"
    ]
  },

  // Let OpenCode auto-detect LSP servers; customize if needed. :contentReference[oaicite:14]{index=14}
  "lsp": {}
}
```

---

## 3) `AGENTS.md` (project rule snippet)

OpenCode automatically loads `AGENTS.md` rules into context. ([opencode.ai][7])
Add/append:

```md
## Memory Safety Extensions (timelines + feasibility)

When auditing C/C++ memory-safety issues:

1) Always produce a Flow Walkthrough (S1..Sn) with:
   - What is happening
   - Memory snapshot
   - Evidence (path:line-range)

2) Always build per-allocation lifetimes (A1..Ak):
   - Events: ALLOC/ALIAS/STORE/LOAD/FREE/NULLIFY/USE/ESCAPE/REALLOC

3) If there is a suspected trigger (FREE → USE, double-free, or len > dst_size):
   - Extract path constraints
   - Run Z3 feasibility via the z3_smt2 tool
   - Record SAT/UNSAT plus a safe witness model when SAT

Safety rules:
- Never provide weaponized exploit payloads or heap grooming/bypass advice.
- Provide defensive reproduction guidance only (unit test harness / regression checks).
```

---

## 4) Agents

Agents in `.opencode/agents/*.md` are supported and can set tool/permission defaults. ([opencode.ai][1])

### 4.1 `.opencode/agents/vuln.md` (primary orchestrator)

```md
---
description: Security/memory-safety auditor. Produces Flow Walkthrough + per-allocation timelines + optional Z3 feasibility appendix. Writes only to artifacts/findings by policy.
mode: primary
temperature: 0.1
steps: 60

permission:
  webfetch: deny
  websearch: deny
  codesearch: deny
  task:
    "*": deny
    "vuln-*": allow
---

You are the primary security auditor.

Core outputs (always):
- Flow Walkthrough: S1..Sn (each step has "What is happening", memory snapshot, evidence)
- Memory Objects table (A1..Ak)
- Allocation Timelines per Ax (ALLOC/ALIAS/STORE/LOAD/FREE/USE)
Optional but recommended:
- Z3 Feasibility appendix for the suspected trigger path.

Artifact discipline (to survive compaction):
1) Call session_info once at the beginning to get sessionID/worktree.
2) Save machine artifacts under .opencode/artifacts/ using sessionID in filenames:
   - <sessionID>__mem_timeline__<slug>.json
   - <sessionID>__mem_constraints__<slug>.smt2
   - <sessionID>__mem_z3__<slug>.txt
3) Validate Timeline Artifact JSON with timeline_validate before saving.

Delegation:
- Use @vuln-mem for lifetime timelines.
- Use @vuln-memop for memop hotspot triage/timelines.
- Use @vuln-smt for feasibility and Z3.

Hard safety rules:
- Do NOT provide exploitation payloads, heap grooming, mitigation bypass, or instructions to attack real systems.
- Defensive, diagnostic, and regression-test oriented guidance only.
```

### 4.2 `.opencode/agents/vuln-mem.md` (lifetime timelines)

```md
---
description: Memory lifetime auditor. Builds per-allocation allocation/free/use timelines to find UAF/double-free/leak candidates. Read-only.
mode: subagent
temperature: 0.1
steps: 45

tools:
  write: false
  edit: false
  patch: false
  bash: false
  webfetch: false

permission:
  mem_events: allow
  timeline_validate: allow
  lsp: allow
---

You are a memory lifetime auditor for C/C++-style codebases.

Goal:
- Track allocations, frees, and uses of heap objects and produce a timeline per allocation.
- Identify memory safety hazards: UAF, double-free, invalid free, lifetime confusion, leaks.

Workflow:
1) Identify allocator/free APIs used (malloc/calloc/realloc/free, new/delete, custom wrappers).
2) Use mem_events to quickly index alloc/free call sites in the target area.
3) Pick the most reachable/important entry flow and build a Flow Walkthrough (S1..Sn).
4) Assign Allocation IDs (A1..Ak) for heap object identities.
5) Produce per-allocation timeline tables:
   - ALLOC, REALLOC, ALIAS, STORE, LOAD, FREE, NULLIFY, USE, ESCAPE
6) Flag hazard windows:
   - UAF: USE after FREE for same Ax
   - Double-free: FREE after FREE
   - Leak: ALLOC without matching FREE on reachable paths

Output MUST include:
A) Flow Walkthrough (S1..Sn) with evidence
B) Memory Objects table
C) Timelines per Ax
D) A compact Timeline Artifact JSON (single object) that captures:
   - target
   - flow_steps (S1..Sn with where/evidence)
   - allocs (A1..Ak with alloc site/type/size/owners)
   - events (ordered list with event kind, alloc ID, step ID, site, and guard refs)
   - guards (map of Gi -> condition)

Keep output tight:
- Do not paste full files/functions; use file:line ranges as evidence.
- Keep Timeline Artifact to <= 200 lines.
```

### 4.3 `.opencode/agents/vuln-memop.md` (memcpy/strcpy hotspot workflow)

```md
---
description: Memory-op triage agent. Ranks dangerous memops (memcpy/strcpy/sprintf/recv/read...) and can build a constraint-aware mini-timeline for a chosen callsite. Read-only.
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
  memops_scan: allow
  lsp: allow
---

You triage memory-corruption-prone operations.

1) Use memops_scan to rank risky callsites.
2) Output top N callsites with:
   - file:line
   - function
   - call snippet
   - why suspicious (len unbounded, dst size unclear, casts, etc.)
3) If a specific callsite is requested, build a mini-timeline:
   - Where dst is allocated/defined + dst_size_expr
   - Where len is derived + len_expr
   - Guards that constrain them
   - Candidate bug predicate (e.g., len > dst_size)

No exploit payloads. Defensive reproduction ideas only.
```

### 4.4 `.opencode/agents/vuln-smt.md` (constraints + Z3)

```md
---
description: SMT/Z3 feasibility agent. Converts a suspected bug path into constraints and checks SAT/UNSAT. Defensive reachability only.
mode: subagent
temperature: 0.1
steps: 45

tools:
  write: false
  edit: false
  patch: false
  bash: false
  webfetch: false

permission:
  z3_smt2: allow
---

You are an SMT feasibility analyst for memory-safety findings.

Goal:
- Given a specific suspected bug flow (FREE then USE, double-free, or OOB predicate), determine whether the path conditions are satisfiable.

Method:
1) Identify symbolic variables (inputs/state): sizes, indices, flags, enum cases.
2) Extract path conditions required to:
   - reach FREE
   - reach later USE (or exceed bounds)
3) Write constraints in SMT-LIB (prefer Int/QF_LIA first).
4) Call z3_smt2 to check SAT/UNSAT and obtain a model if SAT.
5) Interpret safely:
   - SAT: provide ONE safe witness model (values) suitable for regression testing
   - UNSAT: explain the contradiction at a high level

Hard safety rule:
- No exploitation advice. No heap grooming. No bypassing mitigations.
```

---

## 5) Skills

Skills must be at `.opencode/skills/<name>/SKILL.md` with YAML frontmatter (`name`, `description`) and strict naming rules. ([opencode.ai][3])

### 5.1 `.opencode/skills/memory-lifetime-timeline/SKILL.md`

```md
---
name: memory-lifetime-timeline
description: Build per-allocation lifetimes (ALLOC/ALIAS/FREE/USE) as step-by-step timelines to detect UAF/double-free/leaks with evidence and “What is happening” at each step.
compatibility: opencode
---

## Allocation IDs
Assign each heap allocation a stable ID:
- A1, A2, A3...
The ID refers to the heap object instance, not a pointer variable.

## Canonical event types
- ALLOC, REALLOC
- ALIAS (new pointer refers to same Ax)
- STORE / LOAD (field/global/container)
- FREE
- NULLIFY (pointer set NULL for that alias only)
- USE (deref/index/memcpy/strcmp/strlen/field access)
- ESCAPE (returned/stored externally)

## Required outputs

### Flow Walkthrough (S1..Sn)
Each step must include:
- **What is happening**
- **Memory snapshot** (Ax state + alias set)
- Evidence: path:Lx-Ly

### Memory Objects table
| AllocID | Allocation site | Type/Kind | Size expr | Primary owner | Aliases |

### Timeline per allocation
| T | Flow step (S#) | Event | Where | What is happening | Heap state after | Evidence |

## Timeline Artifact (JSON) (required, compact)
Produce a single JSON object:

- target: string
- flow_steps: [{ id:"S1", where:"...", evidence:"...", what:"..." }]
- allocs: [{ id:"A1", site:"...", size_expr:"...", owner:"...", aliases:["p","q"] }]
- guards: { "G1": "cond expr", ... }
- events: [{ id:"E1", kind:"ALLOC|FREE|USE|...", alloc:"A1", step:"S3", site:"...", guard:["G1"] }]

Keep it short; omit unrelated locals.

## UAF rule
A UAF exists when a USE event for Ax is reachable after a FREE event for Ax on the same path, without Ax being replaced by a new identity.
```

### 5.2 `.opencode/skills/z3-feasibility/SKILL.md`

```md
---
name: z3-feasibility
description: Turn a suspected memory bug flow into SMT constraints and use Z3 to check SAT/UNSAT, recording a safe model for regression tests.
compatibility: opencode
---

## What we are solving
We are NOT exploiting anything. We are checking reachability of a bad state.

Bad states:
- UAF: FREE(Ax) then later USE(Ax)
- Double free: FREE(Ax) twice
- OOB: idx >= size or idx < 0 at USE
- Memop overflow: len > dst_size at memcpy/memmove/strcpy-like sinks

## Workflow
1) Start from Flow Walkthrough + Timeline Artifact.
2) Identify symbolic vars (inputs/state).
3) Extract only guards that appear in code (ifs/switch/bounds checks).
4) Emit minimal SMT-LIB:
   - Prefer QF_LIA (Int) first.
   - Use BitVec only when wraparound/truncation is essential.

## Report formatting (required)
- Variables table
- SMT-LIB (decls + asserts)
- Z3 result: SAT/UNSAT/UNKNOWN
- If SAT: one safe model + explanation tied to steps S#
```

---

## 6) Tools

Custom tools are defined in TS/JS under `.opencode/tools/` (project) and can invoke Python/scripts; tool context includes `sessionID`, `worktree`, etc. ([opencode.ai][4])

### 6.1 `mem_events` (alloc/free indexer)

#### `.opencode/tools/mem_events.py`

```py
#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys

# Heuristic scanner: finds alloc/free-ish callsites.
# Not a full analyzer; optimized for quickly building timelines.

DEFAULT_EXTS = [".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".hh", ".hxx"]

ALLOC_DEFAULT = ["malloc", "calloc", "realloc"]
FREE_DEFAULT  = ["free"]

# Simple C++ heuristics
CPP_ALLOC_DEFAULT = ["new"]           # matches "new Type" and "new (..)" loosely
CPP_FREE_DEFAULT  = ["delete"]        # matches "delete p" and "delete[] p"

ASSIGN_RE = re.compile(
    r"(?P<lhs>[A-Za-z_]\w*)\s*=\s*(?:\([^)]+\)\s*)?(?P<fn>malloc|calloc|realloc)\s*\("
)
ALLOC_CALL_RE = re.compile(r"\b(?P<fn>malloc|calloc|realloc)\s*\(")
FREE_CALL_RE  = re.compile(r"\bfree\s*\(\s*(?P<arg>[^)]+)\)")

CPP_NEW_RE = re.compile(r"\bnew\b")
CPP_DELETE_RE = re.compile(r"\bdelete\b(\s*\[\s*\])?\s+(?P<arg>[A-Za-z_]\w*(?:\s*->\s*[A-Za-z_]\w*|\s*\.\s*[A-Za-z_]\w*)*)")

def iter_files(root, exts):
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if any(fn.endswith(ext) for ext in exts):
                yield os.path.join(dirpath, fn)

def scan_file(path, exts, alloc_funs, free_funs, cpp_alloc, cpp_free, max_events):
    events = []
    try:
        with open(path, "r", errors="ignore") as f:
            for i, line in enumerate(f, start=1):
                if len(events) >= max_events:
                    break

                s = line.strip()

                # C alloc assignment
                m = ASSIGN_RE.search(line)
                if m and m.group("fn") in alloc_funs:
                    events.append({
                        "kind": "alloc",
                        "fn": m.group("fn"),
                        "lhs": m.group("lhs"),
                        "file": path,
                        "line": i,
                        "code": s
                    })
                    continue

                # C alloc call
                m2 = ALLOC_CALL_RE.search(line)
                if m2 and m2.group("fn") in alloc_funs:
                    events.append({
                        "kind": "alloc",
                        "fn": m2.group("fn"),
                        "lhs": None,
                        "file": path,
                        "line": i,
                        "code": s
                    })
                    continue

                # C free call
                m3 = FREE_CALL_RE.search(line)
                if m3 and "free" in free_funs:
                    events.append({
                        "kind": "free",
                        "fn": "free",
                        "arg": m3.group("arg").strip(),
                        "file": path,
                        "line": i,
                        "code": s
                    })
                    continue

                # C++ new/delete (very heuristic)
                if "new" in cpp_alloc and CPP_NEW_RE.search(line):
                    # We don't know the LHS reliably; keep it as a raw "new" sighting.
                    events.append({
                        "kind": "alloc",
                        "fn": "new",
                        "lhs": None,
                        "file": path,
                        "line": i,
                        "code": s
                    })
                    continue

                if "delete" in cpp_free:
                    md = CPP_DELETE_RE.search(line)
                    if md:
                        events.append({
                            "kind": "free",
                            "fn": "delete",
                            "arg": md.group("arg"),
                            "file": path,
                            "line": i,
                            "code": s
                        })
                        continue

    except Exception:
        return events

    return events

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help="File or directory to scan")
    ap.add_argument("--ext", action="append", default=[])
    ap.add_argument("--alloc", action="append", default=[])
    ap.add_argument("--free", action="append", default=[])
    ap.add_argument("--cpp-alloc", action="append", default=[])
    ap.add_argument("--cpp-free", action="append", default=[])
    ap.add_argument("--max", type=int, default=2000)
    args = ap.parse_args()

    exts = args.ext if args.ext else DEFAULT_EXTS
    alloc_funs = ALLOC_DEFAULT + args.alloc
    free_funs  = FREE_DEFAULT  + args.free
    cpp_alloc  = CPP_ALLOC_DEFAULT + args.cpp_alloc
    cpp_free   = CPP_FREE_DEFAULT  + args.cpp_free

    root = args.path
    all_events = []

    if os.path.isfile(root):
        all_events.extend(scan_file(root, exts, alloc_funs, free_funs, cpp_alloc, cpp_free, args.max))
    else:
        for fp in iter_files(root, exts):
            all_events.extend(scan_file(fp, exts, alloc_funs, free_funs, cpp_alloc, cpp_free, args.max - len(all_events)))
            if len(all_events) >= args.max:
                break

    print(json.dumps({
        "path": root,
        "exts": exts,
        "alloc_funs": alloc_funs,
        "free_funs": free_funs,
        "cpp_alloc": cpp_alloc,
        "cpp_free": cpp_free,
        "events": all_events
    }))

if __name__ == "__main__":
    sys.exit(main())
```

#### `.opencode/tools/mem_events.ts`

```ts
import { tool } from "@opencode-ai/plugin"
import path from "path"

export default tool({
  description:
    "Index malloc/calloc/realloc/free (and heuristic new/delete) call sites under a path. Returns JSON (heuristic, not a full analyzer).",
  args: {
    path: tool.schema.string().describe("File or directory to scan (relative to repo root allowed)"),
    max: tool.schema.number().int().positive().optional().describe("Max events (default 2000)"),
    ext: tool.schema.array(tool.schema.string()).optional().describe("File extensions to include"),
    alloc: tool.schema.array(tool.schema.string()).optional().describe("Extra alloc functions (wrappers)"),
    free: tool.schema.array(tool.schema.string()).optional().describe("Extra free functions (wrappers)")
  },

  async execute(args, context) {
    const script = path.join(context.worktree, ".opencode/tools/mem_events.py")

    const max = args.max ?? 2000
    const scanPath = path.isAbsolute(args.path) ? args.path : path.join(context.worktree, args.path)

    const extArgs = (args.ext ?? []).flatMap((e) => ["--ext", e])
    const allocArgs = (args.alloc ?? []).flatMap((f) => ["--alloc", f])
    const freeArgs = (args.free ?? []).flatMap((f) => ["--free", f])

    const out = await Bun.$`python3 ${script} ${scanPath} --max ${max} ${extArgs} ${allocArgs} ${freeArgs}`.text()

    try {
      return JSON.parse(out)
    } catch {
      return out.trim()
    }
  }
})
```

---

### 6.2 `memops_scan` (risky memop ranking)

#### `.opencode/tools/memops_scan.py`

```py
#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys

DEFAULT_EXTS = [".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".hh", ".hxx"]

# High-risk / classic footguns:
SINKS = [
    "memcpy", "memmove", "memset",
    "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "vsprintf", "snprintf", "vsnprintf",
    "gets",
    "read", "recv", "recvfrom", "fread"
]

CALL_RE = re.compile(r"\b(?P<fn>" + "|".join(map(re.escape, SINKS)) + r")\s*\(")

def iter_files(root, exts):
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if any(fn.endswith(ext) for ext in exts):
                yield os.path.join(dirpath, fn)

def score(fn, line):
    # crude scoring to rank callsites for review
    base = {
        "gets": 100,
        "strcpy": 95,
        "sprintf": 95,
        "vsprintf": 95,
        "strcat": 85,
        "strncpy": 70,
        "strncat": 70,
        "snprintf": 60,
        "vsnprintf": 60,
        "memcpy": 65,
        "memmove": 60,
        "memset": 35,
        "read": 55,
        "recv": 55,
        "recvfrom": 55,
        "fread": 50
    }.get(fn, 40)

    s = line.strip()
    # Heuristics: if size seems constant-ish, reduce score.
    if "sizeof(" in s or "sizeof " in s:
        base -= 10
    if re.search(r"\b\d+\b", s):
        base -= 5
    # If we see obvious external-ish names, increase slightly.
    if re.search(r"\b(len|size|count|nbytes|bytes|total|input|payload)\b", s):
        base += 8
    return max(1, min(100, base))

def scan_file(path, exts, max_hits):
    hits = []
    try:
        with open(path, "r", errors="ignore") as f:
            for i, line in enumerate(f, start=1):
                if len(hits) >= max_hits:
                    break
                m = CALL_RE.search(line)
                if not m:
                    continue
                fn = m.group("fn")
                hits.append({
                    "kind": "memop",
                    "fn": fn,
                    "score": score(fn, line),
                    "file": path,
                    "line": i,
                    "code": line.strip()
                })
    except Exception:
        return hits
    return hits

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help="File or directory to scan")
    ap.add_argument("--ext", action="append", default=[])
    ap.add_argument("--max", type=int, default=2000)
    args = ap.parse_args()

    exts = args.ext if args.ext else DEFAULT_EXTS
    root = args.path

    all_hits = []
    if os.path.isfile(root):
        all_hits.extend(scan_file(root, exts, args.max))
    else:
        for fp in iter_files(root, exts):
            all_hits.extend(scan_file(fp, exts, args.max - len(all_hits)))
            if len(all_hits) >= args.max:
                break

    # Sort by score desc, then file+line for stability
    all_hits.sort(key=lambda h: (-h["score"], h["file"], h["line"]))

    print(json.dumps({
        "path": root,
        "exts": exts,
        "sinks": SINKS,
        "hits": all_hits
    }))
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

#### `.opencode/tools/memops_scan.ts`

```ts
import { tool } from "@opencode-ai/plugin"
import path from "path"

export default tool({
  description:
    "Scan and rank risky memory operations (memcpy/strcpy/sprintf/read/recv...). Returns JSON with a heuristic score.",
  args: {
    path: tool.schema.string().describe("File or directory to scan (relative to repo root allowed)"),
    max: tool.schema.number().int().positive().optional().describe("Max hits (default 2000)"),
    ext: tool.schema.array(tool.schema.string()).optional().describe("File extensions to include")
  },

  async execute(args, context) {
    const script = path.join(context.worktree, ".opencode/tools/memops_scan.py")

    const max = args.max ?? 2000
    const scanPath = path.isAbsolute(args.path) ? args.path : path.join(context.worktree, args.path)
    const extArgs = (args.ext ?? []).flatMap((e) => ["--ext", e])

    const out = await Bun.$`python3 ${script} ${scanPath} --max ${max} ${extArgs}`.text()

    try {
      return JSON.parse(out)
    } catch {
      return out.trim()
    }
  }
})
```

---

### 6.3 `z3_smt2` (SAT/UNSAT + model)

This version runs Z3 via the **binary if available**, and otherwise tries **z3-solver** (Python). It also strips `(check-sat)` / `(get-model)` from input and appends its own, so your skill can output just **decls + asserts**.

#### `.opencode/tools/z3_smt2.py`

```py
#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

STRIP_CMD_RE = re.compile(r"^\s*\((check-sat|get-model|exit|push|pop)\b", re.IGNORECASE)

def sanitize_smt2(text: str) -> str:
    lines = []
    for line in text.splitlines():
        if STRIP_CMD_RE.match(line):
            continue
        lines.append(line)
    return "\n".join(lines).strip() + "\n"

def run_z3_binary(smt2_text: str, timeout_ms: int | None):
    z3 = shutil.which("z3")
    if not z3:
        return None

    prelude = "(set-option :produce-models true)\n"
    if timeout_ms is not None:
        prelude += f"(set-option :timeout {timeout_ms})\n"

    full = prelude + sanitize_smt2(smt2_text) + "\n(check-sat)\n(get-model)\n"
    with tempfile.NamedTemporaryFile("w", suffix=".smt2", delete=False) as tf:
        tf.write(full)
        tmp = tf.name

    try:
        proc = subprocess.run(
            [z3, "-smt2", tmp],
            capture_output=True,
            text=True
        )
        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        status = (out.split()[:1] or ["unknown"])[0]
        if status not in ("sat", "unsat", "unknown"):
            status = "unknown"
        return {
            "engine": "z3-binary",
            "status": status,
            "stdout": out,
            "stderr": err,
            "exitCode": proc.returncode
        }
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass

def run_z3py(smt2_text: str):
    try:
        from z3 import Solver, parse_smt2_string, sat
    except Exception as e:
        return {
            "engine": "z3py",
            "status": "error",
            "stdout": "",
            "stderr": f"z3-solver not available: {e}",
            "exitCode": 2
        }

    s = Solver()
    core = sanitize_smt2(smt2_text)

    # Try parsing; note parse_smt2_string expects decls/asserts (no commands)
    try:
        constraints = parse_smt2_string(core)
        for c in constraints:
            s.add(c)
    except Exception as e:
        return {
            "engine": "z3py",
            "status": "error",
            "stdout": "",
            "stderr": f"ERROR parsing SMT2: {e}",
            "exitCode": 2
        }

    r = s.check()
    if str(r) == "sat":
        m = s.model()
        return {
            "engine": "z3py",
            "status": "sat",
            "stdout": f"sat\n{m}",
            "stderr": "",
            "exitCode": 0
        }
    if str(r) == "unsat":
        return {"engine": "z3py", "status": "unsat", "stdout": "unsat", "stderr": "", "exitCode": 0}
    return {"engine": "z3py", "status": "unknown", "stdout": "unknown", "stderr": "", "exitCode": 0}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", help="Path to SMT2 file")
    ap.add_argument("--text", help="Inline SMT2 text")
    ap.add_argument("--timeout-ms", type=int, default=0)
    args = ap.parse_args()

    if not args.file and not args.text:
        print(json.dumps({"status": "error", "stderr": "Provide --file or --text"}))
        return 2

    if args.file:
        with open(args.file, "r", errors="ignore") as f:
            smt2 = f.read()
    else:
        smt2 = args.text

    timeout = args.timeout_ms if args.timeout_ms and args.timeout_ms > 0 else None

    r = run_z3_binary(smt2, timeout)
    if r is None:
        r = run_z3py(smt2)

    print(json.dumps(r))
    return 0 if r.get("status") != "error" else 2

if __name__ == "__main__":
    sys.exit(main())
```

#### `.opencode/tools/z3_smt2.ts`

```ts
import { tool } from "@opencode-ai/plugin"
import path from "path"

export default tool({
  description:
    "Run Z3 on SMT-LIB2 constraints and return sat/unsat/unknown + model. Defensive feasibility only.",
  args: {
    file: tool.schema.string().optional().describe("Path to .smt2 file (relative to repo root allowed)"),
    text: tool.schema.string().optional().describe("Inline SMT2 content (decls + asserts preferred)"),
    timeout_ms: tool.schema.number().int().positive().optional().describe("Optional Z3 timeout in ms")
  },

  async execute(args, context) {
    const script = path.join(context.worktree, ".opencode/tools/z3_smt2.py")
    const timeout = args.timeout_ms ?? 0

    if (!args.file && !args.text) {
      return { status: "error", stderr: "Provide 'file' or 'text'", stdout: "" }
    }

    let out: string
    if (args.file) {
      const abs = path.isAbsolute(args.file) ? args.file : path.join(context.worktree, args.file)
      out = await Bun.$`python3 ${script} --file ${abs} --timeout-ms ${timeout}`.text()
    } else {
      out = await Bun.$`python3 ${script} --text ${args.text} --timeout-ms ${timeout}`.text()
    }

    try {
      return JSON.parse(out)
    } catch {
      return { status: "unknown", stdout: out.trim(), stderr: "" }
    }
  }
})
```

---

### 6.4 `timeline_validate` (keep artifacts consistent)

#### `.opencode/tools/timeline_validate.ts`

```ts
import { tool } from "@opencode-ai/plugin"

const EventKind = tool.schema.enum([
  "ALLOC",
  "REALLOC",
  "ALIAS",
  "STORE",
  "LOAD",
  "FREE",
  "NULLIFY",
  "USE",
  "ESCAPE"
])

const EventSchema = tool.schema.object({
  id: tool.schema.string(),
  kind: EventKind,
  alloc: tool.schema.string().optional(),
  step: tool.schema.string().optional(),
  site: tool.schema.string(),
  guard: tool.schema.array(tool.schema.string()).optional(),
  detail: tool.schema.string().optional()
})

const TimelineSchema = tool.schema.object({
  target: tool.schema.string(),
  flow_steps: tool.schema
    .array(
      tool.schema.object({
        id: tool.schema.string(),
        where: tool.schema.string(),
        evidence: tool.schema.string(),
        what: tool.schema.string()
      })
    )
    .optional(),
  allocs: tool.schema
    .array(
      tool.schema.object({
        id: tool.schema.string(),
        site: tool.schema.string(),
        size_expr: tool.schema.string().optional(),
        owner: tool.schema.string().optional(),
        aliases: tool.schema.array(tool.schema.string()).optional()
      })
    )
    .optional(),
  guards: tool.schema.record(tool.schema.string(), tool.schema.string()).optional(),
  events: tool.schema.array(EventSchema),
  notes: tool.schema.array(tool.schema.string()).optional()
})

export default tool({
  description:
    "Validate Timeline Artifact JSON against the memory-timeline schema. Returns ok=true or ok=false with errors.",
  args: {
    json: tool.schema.string().describe("Timeline Artifact JSON string")
  },

  async execute(args) {
    let parsed: unknown
    try {
      parsed = JSON.parse(args.json)
    } catch (e) {
      return { ok: false, errors: [{ message: "Invalid JSON", detail: String(e) }] }
    }

    const result = TimelineSchema.safeParse(parsed)
    if (result.success) {
      return { ok: true }
    }
    return {
      ok: false,
      errors: result.error.issues.map((i) => ({
        path: i.path.join("."),
        message: i.message
      }))
    }
  }
})
```

---

### 6.5 `session_info` (so artifacts can be session-scoped)

#### `.opencode/tools/session_info.ts`

```ts
import { tool } from "@opencode-ai/plugin"

export default tool({
  description: "Return OpenCode session context info (sessionID, worktree, directory, agent).",
  args: {},
  async execute(_args, context) {
    // Context fields are documented in OpenCode custom tools docs. :contentReference[oaicite:19]{index=19}
    const { agent, sessionID, messageID, directory, worktree } = context
    return { agent, sessionID, messageID, directory, worktree }
  }
})
```

---

## 7) Commands (your “one-liners”)

Commands are Markdown files in `.opencode/commands/` with YAML frontmatter; `$ARGUMENTS`/`$1..` and `@file` are supported. ([opencode.ai][2])

### 7.1 Create a new finding file: `.opencode/commands/sec-finding-new.md`

```md
---
description: Create a new memory finding file from TEMPLATE-memory.md.
agent: vuln
---

Create a new finding report at: `docs/security/findings/$1.md`

- Use template: @docs/security/findings/TEMPLATE-memory.md
- Set:
  - id: $1
  - title: $2
  - status: draft
- Leave severity/cwe/component as unknown unless obvious from evidence.

Do not add exploit payloads. Keep it defensive.
```

Usage example:

* `/sec-finding-new VR-0007 "UAF in foo parser"`

### 7.2 Timeline workflow: `.opencode/commands/sec-mem-timeline.md`

```md
---
description: Build allocation/free/use timelines (A1..Ak) and Flow Walkthrough (S1..Sn). Stores a Timeline Artifact JSON in .opencode/artifacts/.
agent: vuln
---

Target: $ARGUMENTS

Instructions:
1) Call session_info and compute an artifact filename prefix from sessionID.
2) Load skill `memory-lifetime-timeline`.
3) Use @vuln-mem to generate:
   - Flow Walkthrough S1..Sn
   - Memory Objects A1..Ak
   - Timelines per Ax
   - Timeline Artifact JSON
4) Validate the JSON using timeline_validate.
5) Write the Timeline Artifact JSON to:
   `.opencode/artifacts/<sessionID>__mem_timeline__<safe-slug>.json`

Do not provide exploit payloads. Defensive/diagnostic only.
```

### 7.3 Memop scan: `.opencode/commands/sec-memop-scan.md`

```md
---
description: Scan and rank risky memops (memcpy/strcpy/sprintf/recv/read...). Saves JSON results to .opencode/artifacts/.
agent: vuln
---

Target path: $ARGUMENTS

Instructions:
1) Call session_info and compute an artifact filename prefix from sessionID.
2) Use memops_scan on the target path.
3) Output top 20 ranked callsites with evidence and “why suspicious”.
4) Save raw memops_scan JSON to:
   `.opencode/artifacts/<sessionID>__mem_memops_scan__<safe-slug>.json`
```

### 7.4 Memop timeline: `.opencode/commands/sec-memop-timeline.md`

```md
---
description: Build a constraint-aware mini-timeline for a specific memop callsite (memcpy/strcpy/etc).
agent: vuln
---

Callsite: $ARGUMENTS

Use @vuln-memop to:
- Extract dst/src/len expressions
- Identify dst_size_expr and guards
- Propose a bug predicate (e.g., len > dst_size)
Provide evidence as file:line ranges.
```

### 7.5 Z3 feasibility: `.opencode/commands/sec-mem-z3.md`

```md
---
description: Check satisfiability of a suspected bug trigger path using Z3 and record SAT/UNSAT + safe model.
agent: vuln
---

Target: $ARGUMENTS

Instructions:
1) Load skill `z3-feasibility`.
2) Require a concrete trigger:
   - FREE(Ax) then USE(Ax), OR
   - len > dst_size at a memop, OR
   - double-free
3) Build minimal SMT-LIB (decls + asserts). Prefer Int/QF_LIA first.
4) Call z3_smt2 with the SMT2 text.
5) Save:
   - `.opencode/artifacts/<sessionID>__mem_constraints__<safe-slug>.smt2`
   - `.opencode/artifacts/<sessionID>__mem_z3__<safe-slug>.txt`
6) Produce a “Feasibility (Z3)” appendix suitable for pasting into a finding report.

No exploit payloads; only safe regression-test values if SAT.
```

---

## 8) Report template: `docs/security/findings/TEMPLATE-memory.md`

Use your template (it’s already solid). I’d only add **two small upgrades**:

1. **Artifacts section** (so timelines/SMT/Z3 are recoverable after compaction)
2. Optional **Timeline Artifact JSON** appendix (so later sessions can reuse it)

Here’s a compatible version with those upgrades (kept minimal):

````md
---
id: VR-0000
status: draft
severity: unknown
cwe: unknown
component: unknown
bug_class: memory-safety
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

## 2) Artifacts (for reproducibility)
- Timeline Artifact JSON: `.opencode/artifacts/<sessionID>__mem_timeline__<slug>.json`
- SMT constraints: `.opencode/artifacts/<sessionID>__mem_constraints__<slug>.smt2`
- Z3 output: `.opencode/artifacts/<sessionID>__mem_z3__<slug>.txt`

## 3) Flow at a Glance
**Chain:** [S1](#s1) → [S2](#s2) → … → [Sn](#sn)  
**Bug triggers:** ⚠️ [S?](#s)

```mermaid
flowchart TD
  S1[S1: Entry] --> S2[S2: Parse/Dispatch]
  S2 --> S3[S3: Allocate Ax]
  S3 --> S4[S4: Free Ax]
  S4 --> S5[S5: Use Ax ⚠️]
````

## 4) Flow Table (One Screen Review)

| Step  | Where           | What is happening                                                    | Memory snapshot            | Evidence       |
| ----- | --------------- | -------------------------------------------------------------------- | -------------------------- | -------------- |
| S1    | `<file>::<sym>` | **What is happening:** <…>                                           | (none yet)                 | `<path>:Lx-Ly` |
| S2    | `<file>::<sym>` | **What is happening:** <…>                                           | (none yet)                 | `<path>:Lx-Ly` |
| S3    | `<file>::<sym>` | **What is happening:** Allocates **A1** and stores pointer in `p`.   | `A1=allocated; p→A1`       | `<path>:Lx-Ly` |
| S4    | `<file>::<sym>` | **What is happening:** Frees `p` under condition `<cond>`.           | `A1=freed; p→A1(dangling)` | `<path>:Lx-Ly` |
| S5 ⚠️ | `<file>::<sym>` | **What is happening:** Uses `p` after free (dereference/copy/index). | `A1=freed; USE(A1)`        | `<path>:Lx-Ly` |

## 5) Memory Objects (A1..Ak)

| AllocID | Allocation site | Size expr | Owner                  | Aliases (tracked) |
| ------- | --------------- | --------- | ---------------------- | ----------------- |
| A1      | `<file>:Lx`     | `<expr>`  | `<component/function>` | `p,q,...`         |

## 6) Allocation Timelines

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

## 7) Feasibility (Z3) (Optional but recommended)

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
* Interpretation: <tie back to S4 then S5>

## 8) Root Cause

<one paragraph>

## 9) Fix Recommendation

### Minimal fix

* <e.g., nullify pointers after free + restructure ownership or guard use>

### Defense in depth (optional)

* <ownership API, RAII, refcounting, clearer contracts>

## 10) Regression Test Idea (Safe)

* <safe harness/unit test/integration test>

## Appendix A — Timeline Artifact JSON (optional)

```json
{ "...": "..." }
```

```

---

## 9) How to run this (practical workflow)

1) **Create a finding stub**
- `/sec-finding-new VR-0007 "UAF in foo parser"`

2) **Build timeline(s)**
- `/sec-mem-timeline path/to/component/or/symbol`

3) **(Optional) Discover hotspots**
- `/sec-memop-scan .`
- `/sec-memop-timeline path/to/file.c:123`

4) **Prove feasibility**
- `/sec-mem-z3 VR-0007` (or the function name / callsite)

---

## 10) Two tiny “gotchas” that make this pack work better

- **Save artifacts**: you *will* lose tool outputs during long audits when compaction prunes old tool outputs; writing JSON/SMT/Z3 into `.opencode/artifacts/` keeps it stable across session length/compaction. :contentReference[oaicite:21]{index=21}  
- **Enable LSP only if you want it**: the `lsp` tool is experimental and requires `OPENCODE_EXPERIMENTAL_LSP_TOOL=true` (or `OPENCODE_EXPERIMENTAL=true`). :contentReference[oaicite:22]{index=22}  

---

If you want one more “best-results” upgrade (still safe + low-noise): I can add a **single “sec-mem-triage” command** that runs *mem_events → timeline → z3* in one go and writes all artifacts + appends the Z3 appendix into an existing finding file automatically (still restricted to `docs/security/findings/**`).
::contentReference[oaicite:23]{index=23}
```

[1]: https://opencode.ai/docs/agents/ "Agents | OpenCode"
[2]: https://opencode.ai/docs/commands/ "Commands | OpenCode"
[3]: https://opencode.ai/docs/skills/ "Agent Skills | OpenCode"
[4]: https://opencode.ai/docs/custom-tools/ "Custom Tools | OpenCode"
[5]: https://opencode.ai/docs/permissions/ "Permissions | OpenCode"
[6]: https://opencode.ai/docs/tools/ "Tools | OpenCode"
[7]: https://opencode.ai/docs/rules/ "Rules | OpenCode"
