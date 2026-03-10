# deeptrace-aco

Production-grade static **deep trace** tool that answers:

> Given a target `file:line` (sink) in a repo, what are the **deep dependency paths** (data-flow + call context + pointer/field/alias chains) that can lead to that line — and are they actually exploitable?

It combines:
- **Joern** (CPG + interprocedural dataflow) running via **Docker** for precise flow extraction
- **tree-sitter** (fast syntax fallback / enrichment) + optional **ctags** for cross-file resolution
- **ACO** (MAX-MIN Ant System) to explore & rank deep paths when enumerating *all* paths is infeasible
- **LLM** (Ollama / Anthropic / OpenAI-compatible) to rank paths, annotate each node, and explain vulnerabilities
- **Z3 SMT solver** to verify whether path constraints are satisfiable (path feasibility)
- **Source-sink** directed tracing to find paths connecting a specific source to the sink
- **Frontier expansion** to iteratively chase callers across file boundaries for deep multi-file traces
- **Exploit validation** — LLM generates C harnesses from traces, compiles with ASAN, runs in Docker sandbox, and produces vulnerability reports with crash evidence
- **Vulnerability scanner** — regex pattern detection (38 patterns, 19 categories) + LLM triage to auto-discover sinks and sources across a repo, outputting `lines.json` for the trace pipeline
- **Batch mode** to process multiple targets from a `lines.json` file in one run
- **Interactive session system** to save exponential branch points and let the user choose which to explore

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  deeptrace scan (entry point for unknown repos)              │
│                                                              │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────────┐  │
│  │ 38 Regex    │──▶│  Context     │──▶│  LLM Triage      │  │
│  │ Patterns    │   │  Enrichment  │   │  + Source-Sink    │  │
│  │ (19 CWEs)   │   │  ±10 lines   │   │    Pairing       │  │
│  └─────────────┘   └──────────────┘   └────────┬─────────┘  │
│                                                │             │
│                                     lines.json ▼  + report   │
└──────────────────────────────────────┬───────────────────────┘
                                       │
             ┌─────────────────────────┘
             ▼
┌──────────────┐    ┌──────────────┐
│   Joern      │    │  tree-sitter │
│  (Docker)    │    │  + ctags     │
│              │    │              │
│ CPG → flows  │    │ AST → edges  │
└──────┬───────┘    └──────┬───────┘
       │                   │
       └───────┬───────────┘
               ▼
     ┌─────────────────┐
     │ DependencyGraph  │  (unified NetworkX DiGraph)
     │ Joern-first      │  (Joern edges preferred, TS enriches)
     └────────┬────────┘
              │
     ┌────────▼────────┐
     │ Frontier Expand  │  iterative caller-chasing across files
     │ (grep/TS → param │  argument → parameter PARAM_PASS edges
     │  pass edges)     │
     └────────┬────────┘
              │
    ┌─────────┼──────────┐
    ▼         ▼          ▼
┌────────┐ ┌────────┐ ┌──────────┐
│ Source │ │  ACO   │ │  Exact   │
│ -Sink  │ │ (MMAS) │ │  Enum    │
│ BFS    │ │ 80ants │ │ (<200    │
│ ∩sect  │ │ 60iter │ │  nodes)  │
└───┬────┘ └───┬────┘ └────┬─────┘
    └──────────┼───────────┘
               ▼
     ┌─────────────────┐
     │  Z3 Constraint  │  (extract conditions → SMT → SAT/UNSAT)
     │    Solver        │
     └────────┬────────┘
              ▼
     ┌─────────────────┐
     │   LLM Ranker    │  (rank paths + annotate nodes + vuln summary)
     │ Ollama/Claude/OAI│
     └────────┬────────┘
              ▼
     ┌─────────────────┐
     │   Final Sort    │  (SAT first → LLM rank → score)
     │  + Interactive  │
     └────────┬────────┘
              ▼
     ┌─────────────────┐
     │  traces.json    │  + HTML timeline visualization
     └────────┬────────┘
              │
              ▼  (deeptrace validate)
     ┌─────────────────────────────────────────┐
     │         Exploit Validation Pipeline      │
     │                                         │
     │  ┌───────────┐   ┌──────────────────┐   │
     │  │  Harness   │──▶│  Docker Sandbox  │   │
     │  │  Generator │   │  gcc + ASAN      │   │
     │  │  (LLM)     │   │  compile + run   │   │
     │  └─────┬─────┘   └────────┬─────────┘   │
     │        │ repair loop       │ input loop  │
     │        └──────────────────┘              │
     │                   ▼                      │
     │  ┌─────────────────────────────────┐     │
     │  │  Vulnerability Reports (*.md)   │     │
     │  │  per-path + SUMMARY.md          │     │
     │  └─────────────────────────────────┘     │
     └─────────────────────────────────────────┘
```

## Supported languages

| Language | Backend | Precision |
|----------|---------|-----------|
| C/C++ | Joern (primary) + tree-sitter | High — full interprocedural dataflow |
| Java | Joern (primary) + tree-sitter | High |
| Kotlin | Joern (primary) + tree-sitter | Medium — Joern frontend is newer |
| Swift | Joern (primary) + tree-sitter | Medium |
| Rust | tree-sitter only | Lower — syntax-based, no dataflow |
| Objective-C | tree-sitter only | Lower |

## Requirements

- Python 3.10+
- Docker (for Joern backend)
- Joern Docker image: `ghcr.io/joernio/joern:nightly`
- Optional: `gcc:13` Docker image for exploit validation sandbox (auto-pulled on first use)
- Optional: local `gcc` with AddressSanitizer support (used when Docker is unavailable)
- Optional: `ctags` (universal-ctags) for better cross-file symbol resolution
- Optional: `z3-solver` (`pip install z3-solver`) for constraint satisfiability checking
- Optional: Ollama (local, default LLM) or Anthropic/OpenAI API key for LLM ranking

## Installation

```bash
git clone https://github.com/yourorg/deeptrace-aco.git
cd deeptrace-aco
python -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\activate           # Windows

# Full install (includes tree-sitter grammars + Z3)
pip install -e ".[dev]"
```

**Python 3.12+ / 3.14** — tree-sitter grammars are bundled in `[dev]`. If installing
without `[dev]`, add them manually:
```bash
pip install tree-sitter tree-sitter-c tree-sitter-cpp tree-sitter-java tree-sitter-rust
```

**Python ≤ 3.11** — you can alternatively use the `tree-sitter-languages` bundle:
```bash
pip install "tree-sitter>=0.20,<0.22" tree-sitter-languages
```

Verify:
```bash
deeptrace --version
```

## Quick start

### Basic trace

```bash
deeptrace trace --repo /path/to/repo --target src/foo.c:123 --out traces.json
```

### Source-sink directed tracing (Feature: --source)

Find paths that connect a specific source location to the sink:

```bash
deeptrace trace \
  --repo /path/to/repo \
  --target src/parser.c:456 \
  --source src/input.c:42 \
  --out traces.json
```

This performs bidirectional BFS (forward from source, backward from sink), intersects the reachable sets, and finds paths within the intersection.

### With LLM ranking + node annotations + vulnerability summaries

```bash
# Using Ollama (default, local)
deeptrace trace \
  --repo /path/to/repo \
  --target src/foo.c:123 \
  --llm --llm-provider ollama --llm-model qwen2.5-coder:14b

# Using Anthropic Claude
export ANTHROPIC_API_KEY=sk-ant-...
deeptrace trace \
  --repo /path/to/repo \
  --target src/foo.c:123 \
  --llm --llm-provider anthropic --llm-model claude-sonnet-4-20250514
```

The LLM now performs 3 passes:
1. **Rank paths** by vulnerability severity and assign tags
2. **Annotate each node** with a contextual description of what's happening in the data flow
3. **Generate vulnerability summary** — a step-by-step explanation of why each top path is a security risk

### Z3 constraint checking

Automatically enabled by default. Extracts conditions (if/while/for guards, null checks, bounds checks, type casts) from code snippets along each path and checks satisfiability:

```bash
deeptrace trace --repo . --target src/foo.c:123 --z3    # enabled (default)
deeptrace trace --repo . --target src/foo.c:123 --no-z3  # disable
```

Output shows SAT/UNSAT per path, with satisfying assignments when SAT. Paths are sorted: **SAT first**, then by LLM rank, then by score.

### Vulnerability scanning (auto-discover sinks + sources)

Don't know where the vulnerabilities are? The **scan** command searches the entire repo using 38 regex patterns across 19 vulnerability categories (buffer overflow, command injection, SQL injection, deserialization, XXE, SSRF, crypto weakness, etc.), enriches each hit with ±10 lines of code context, then sends them to the LLM for false positive elimination and source-sink pairing. The output is a `lines.json` ready to feed into `deeptrace batch`.

```bash
# Full scan with LLM triage (Ollama default)
deeptrace scan --repo ./pdfium --out lines.json

# C/C++ only, high+ severity, with Claude
deeptrace scan --repo ./pdfium --out lines.json \
  --languages c,cpp --severity high \
  --llm-provider anthropic --llm-model claude-sonnet-4-20250514

# Fast pattern-only mode (no LLM, seconds on large repos)
deeptrace scan --repo ./pdfium --out lines.json --no-llm

# Include source (input entry point) locations in output
deeptrace scan --repo ./pdfium --out lines.json --include-sources
```

The scan produces two files:

- **`lines.json`** — extended format compatible with `deeptrace batch`, each entry includes the file, line, category, severity, CWE, LLM explanation, attack scenario, and (when identified) the paired source location.
- **`lines.json.report.md`** — human-readable scan report with a findings table, severity icons, detailed explanations, and attack scenarios.

Example `lines.json` entry (extended format):

```json
{
  "file": "core/fpdfdoc/cpdf_interactiveform.cpp",
  "line": 91,
  "category": "buffer_overflow",
  "severity": "critical",
  "confidence": "high",
  "cwe": "CWE-120",
  "description": "Explicitly marked UNSAFE memory operation",
  "explanation": "UNSAFE_TODO(FXSYS_memcpy(...)) copies a LOGFONTA struct without validating that the source contains valid data.",
  "attack_scenario": "Attacker crafts a PDF with a malformed font descriptor...",
  "source_file": "fpdfsdk/pwl/cpwl_edit_impl.cpp",
  "source_line": 1875,
  "source_description": "User input character from PDF form field editing"
}
```

The three-phase pipeline:

1. **Fast regex scan** — matches 38 patterns (sinks + sources) across all source files in seconds. Covers: `memcpy`/`strcpy`/`sprintf`/`gets` (buffer overflow), `system()`/`popen()` (command injection), `pickle.load()`/`ObjectInputStream` (deserialization), `printf(var)` (format string), `reinterpret_cast` (type confusion), hardcoded secrets, weak crypto, TOCTOU races, XXE, SSRF, LDAP injection, template injection, and more.
2. **Context enrichment** — extracts surrounding code, enclosing function, nearby safety guards (bounds checks, null checks, safe wrappers). Hits inside comments or with clear guards are automatically downgraded.
3. **LLM triage** — the LLM evaluates each hit with full context and is strictly prompted to reject false positives (bounded `memcpy`, literal format strings, null-then-free). Confirmed sinks are then paired with detected sources to identify complete attack vectors.

Then feed the output directly into the trace pipeline:

```bash
# Scan → trace → validate (full pipeline)
deeptrace scan --repo ./pdfium --out lines.json
deeptrace batch --repo ./pdfium --lines lines.json --out traces/ --cpg-load repo.cpg.bin
deeptrace validate traces/batch_results.json --out reports/
```

### Batch mode (lines.json)

Process multiple targets from a JSON file:

```bash
deeptrace batch \
  --repo /path/to/repo \
  --lines lines.json \
  --out batch_results/ \
  --llm
```

Expected `lines.json` format (from `lines.py`):

```json
[
  {"file": "core/fpdftext/cpdf_linkextract.cpp", "line": 44},
  {"file": "core/fxge/dib/fx_dib.cpp", "line": 210},
  {"file": "core/fxge/dib/fx_dib.cpp", "line": 210, "source_file": "core/input.cpp", "source_line": 50}
]
```

Or the simpler string format:

```json
["core/fpdftext/cpdf_linkextract.cpp:44", "core/fxge/dib/fx_dib.cpp:210"]
```

The graph is built **once** and reused across all targets for efficiency.

### Interactive mode (branch selection)

When the dependency graph has exponential branching (e.g., a node with 30+ predecessors), deeptrace saves these **branch points** and lets you choose which path to explore:

```bash
deeptrace trace \
  --repo /path/to/repo \
  --target src/parser.c:456 \
  --interactive \
  --session-file session.json \
  --out traces.json
```

In interactive mode, you'll see:
1. A summary table of discovered paths (with Z3 SAT/UNSAT status)
2. Each branch point with its candidates (annotated by the LLM)
3. A prompt to select which candidate to explore next

### Resume a session

```bash
# Inspect
deeptrace session session.json --show-branches --show-paths

# Resolve a specific branch
deeptrace session session.json --resolve "node_id:2"
```

### Tuning ACO parameters

```bash
deeptrace trace \
  --repo . \
  --target app/Main.kt:77 \
  --max-depth 30 \
  --max-flows 400 \
  --ants 80 \
  --iterations 60 \
  --alpha 1.0 \
  --beta 2.5 \
  --rho 0.15 \
  --topk 20
```

### Export graph for visualization

```bash
# Graphviz DOT
deeptrace export-graph traces.json --format dot --out graph.dot
dot -Tsvg graph.dot -o graph.svg

# Cytoscape JSON
deeptrace export-graph traces.json --format cytoscape --out graph.cyto.json

# D3.js JSON
deeptrace export-graph traces.json --format d3 --out graph.d3.json
```

### Interactive HTML timeline

Generate a standalone HTML file with interactive trace path timelines:

```bash
deeptrace visualize traces.json --repo /path/to/repo --out timeline.html
```

The HTML file includes:
- **Path list sidebar** with SAT/UNSAT badges, LLM ranks, and vulnerability tags
- **Horizontal timeline** of nodes for each path — click any node to view its source
- **Source code panel** with the active line highlighted and ±30 lines of context
- **Info panel** showing node annotations, Z3 satisfiability, constraints, and vulnerability summaries
- **Keyboard navigation**: ← → to move between nodes, ↑ ↓ to switch paths

### CPG save / load (skip re-generation)

Joern CPG generation can take 10-15 minutes for large repos. Save it once and reuse:

```bash
# First run: generate CPG and save to disk
deeptrace trace --repo /path/to/repo --target src/foo.c:123 \
  --cpg-save repo.cpg.bin

# Subsequent runs: load the saved CPG (skips joern-parse entirely)
deeptrace trace --repo /path/to/repo --target src/bar.c:456 \
  --cpg-load repo.cpg.bin

# Works with batch mode too
deeptrace batch --repo /path/to/repo --lines lines.json --out results/ \
  --cpg-load repo.cpg.bin
```

### Cross-file frontier expansion

By default, deeptrace iteratively chases callers across file boundaries. When backward BFS hits a dead end at a function parameter (e.g., `CheckMailLink(const WideString& str, ...)`), the frontier expander searches the entire repo for call sites of that function, parses the arguments with tree-sitter, and adds `PARAM_PASS` edges connecting each argument to its corresponding parameter. This repeats up to `--max-caller-hops` levels deep, growing the trace from a single-function scope to a multi-file, multi-layer dependency chain.

```bash
# Default: 3 hops of caller expansion
deeptrace trace --repo ./pdfium --target core/fpdftext/cpdf_linkextract.cpp:44

# Deeper expansion (5 levels of callers)
deeptrace trace --repo ./pdfium --target core/fpdftext/cpdf_linkextract.cpp:44 \
  --max-caller-hops 5

# Disable expansion (single-function trace only)
deeptrace trace --repo ./pdfium --target core/fpdftext/cpdf_linkextract.cpp:44 \
  --max-caller-hops 0
```

### Exploit validation pipeline

After trace analysis produces `traces.json`, the **validate** command takes each discovered flow and attempts to **prove it's exploitable** end-to-end:

1. An LLM generates a standalone **C harness** that simulates the exact data flow described in each trace path — stubbing out the real codebase functions but preserving the same chain of conditions, function calls, and the vulnerable sink operation.
2. The harness is compiled with `gcc -fsanitize=address` inside a **Docker sandbox** (or locally with ASAN).
3. If compilation fails, the compiler errors are sent back to the LLM for **automatic repair** (up to 3 attempts).
4. The LLM generates **targeted test inputs** based on the trace's conditions and vulnerability type.
5. Each input is fed to the harness via stdin. The runner checks for two signals:
   - `SINK_REACHED` printed to stderr (the data flow reached the vulnerable operation)
   - **AddressSanitizer crash** (heap-buffer-overflow, use-after-free, stack-buffer-overflow, etc.)
6. If neither signal fires, execution results are sent back to the LLM for **adaptive input refinement** — it sees what the previous inputs produced and generates better ones (up to 3 rounds).
7. A **Markdown vulnerability report** is generated for each path, plus a **SUMMARY.md** aggregating all results.

```bash
# Basic validation (uses Ollama locally + Docker sandbox)
deeptrace validate traces.json --out reports/

# With Claude for higher-quality harness generation
deeptrace validate traces.json \
  --llm-provider anthropic \
  --llm-model claude-sonnet-4-20250514 \
  --llm-api-key $ANTHROPIC_API_KEY \
  --out reports/

# Without Docker (uses local gcc + ASAN)
deeptrace validate traces.json --no-docker --out reports/

# Control iteration depth
deeptrace validate traces.json \
  --max-compile-retries 5 \
  --max-input-rounds 5 \
  --out reports/
```

The output directory contains:

```
reports/
├── SUMMARY.md                  # Aggregated results table for all paths
├── path_0_report.md            # 🔴 CRASH CONFIRMED — asan_heap_buffer_overflow
├── path_1_report.md            # 🟡 SINK REACHED (data flow confirmed, no crash)
├── path_2_report.md            # ⚪ UNCONFIRMED (harness compiled but sink not reached)
├── path_3_report.md            # ⚫ COMPILE FAILED
└── ...
```

Each individual report includes:
- **Executive summary** with confirmation status
- **Full data flow trace** with code snippets and annotations
- **Generated C harness** source code
- **Execution results table** showing all test runs with exit codes, SINK/crash status
- **ASAN crash output** with full stack trace (when a crash was detected)
- **Triggering input** in hex and human-readable format
- **Remediation recommendations** specific to the vulnerability type

## How it works

### 1. Graph extraction

**Joern backend** (for C/C++, Java, Kotlin, Swift):
- Spins up a Docker container with the Joern image
- Generates a Code Property Graph (CPG) for the entire repo
- Runs backward dataflow reachability queries from the target `file:line`
- Extracts call-graph edges for context
- Converts Joern flows into typed graph edges (data_flow, param_pass, return, field_access, pointer_deref, alias, etc.)

**tree-sitter backend** (fallback + enrichment):
- Parses source files into ASTs
- Extracts identifier references, function calls, and field accesses
- **Scope-aware def-use chains**: links identifiers to their nearest predecessor in the same scope (not all-to-all, which caused edge explosion)
- **Noise filtering**: skips single-character variables, keywords, and common noise names (reduces node count by ~60%)
- **Built-in cross-file resolution**: two-pass scan — first pass builds a definition index from all function definitions found, second pass links unresolved call sites to definitions in other files
- Uses ctags for cross-file resolution when available; falls back to the built-in index on Windows or when ctags is not installed
- Parses `#include` directives to build an include graph
- Produces lower-confidence edges that fill gaps in the Joern graph

The two backends merge into a single `DependencyGraph` (NetworkX DiGraph). When both backends produce an edge for the same node pair, the Joern edge takes precedence.

### 2. Path exploration (ACO)

For real-world repos, the dependency graph can have thousands of nodes and exponential paths. We use **MAX-MIN Ant System (MMAS)** to efficiently explore:

- **Backward exploration**: ants start at the target and walk backward through predecessors
- **Transition rule**: ACS-style with exploitation threshold `q0` — balances greedy vs probabilistic selection
- **Pheromone bounds**: prevents stagnation (min/max clamping)
- **Elite ants**: only the top-K ants deposit pheromone each iteration
- **Local search**: extends best paths by one hop if it improves the score
- **Stagnation detection**: resets pheromones if no improvement for N iterations

If the reachable subgraph is small (< 200 nodes by default), deeptrace falls back to **exact enumeration** of all simple paths via NetworkX.

### 3. Branch-point detection

During ACO exploration, when a node has more predecessors than `--max-fan-out` (default: 15), it's recorded as a **branch point**. Each candidate predecessor is saved with:
- Edge type and code preview
- Estimated backward depth (BFS)
- LLM-generated one-line summary and vulnerability hint

Branch points are persisted to the session file so you can come back and explore different branches without re-running the full analysis.

### 4. Z3 constraint solving

After path discovery, deeptrace extracts constraints from code snippets along each path:
- **If/while/for conditions** (e.g., `if (len > MAX_BUF)`)
- **Null checks** (e.g., `ptr != NULL`)
- **Bounds checks** (e.g., `idx < arr.size()`)
- **Type casts** (implied range constraints from narrowing casts)
- **Assertions** (e.g., `DCHECK(x > 0)`)

These constraints are encoded as Z3 integer arithmetic and checked for joint satisfiability:
- **SAT**: the path is feasible — all conditions can be simultaneously satisfied. Z3 provides a concrete satisfying assignment (e.g., `len = 256; idx = 0`).
- **UNSAT**: the path is infeasible — constraints contradict each other. This specific execution path cannot be triggered.
- **UNKNOWN**: solver timed out or couldn't determine.

### 5. LLM ranking + annotation + vulnerability summary

With `--llm` enabled, deeptrace performs three LLM passes:

**Pass 1: Rank paths** — Send top-K paths to the LLM for ranking by:
- Security relevance (vulnerability tags from 12 categories)
- Severity assessment and rationale

**Pass 2: Node annotation** — For each top path, the LLM describes each node's role in context: what data enters, how it's transformed/checked, and why it matters for security. Stored in each step's `annotation` field.

**Pass 3: Vulnerability summary** — For top paths (SAT-first), generate a step-by-step explanation of:
- What the vulnerability is
- How data flows to trigger it
- What conditions must hold (incorporating Z3 results)
- Potential impact and exploitation scenario

The LLM also pre-ranks branch candidates in interactive mode.

### 6. Final ranking

Paths are sorted with a composite key:
1. **SAT first** (satisfiable paths are more interesting than UNSAT)
2. **LLM rank** (lower rank = more critical)
3. **ACO score** (deeper, more diverse paths rank higher)

### 7. Static pattern detection

In addition to LLM ranking, deeptrace runs fast regex-based pattern matching against known vulnerability shapes:
- Buffer overflow (memcpy/strcpy with unvalidated input)
- Use-after-free (pointer deref after free)
- Null dereference
- Command/SQL injection
- Integer overflow
- Format string vulnerabilities
- Resource leaks
- Race conditions

These patterns provide immediate tags even without an API key.

### 8. Exploit validation (deeptrace validate)

The validation pipeline bridges the gap between static trace analysis and dynamic proof of exploitability. It operates on the output of the trace phase (`traces.json`) and works as follows:

**Harness generation** — For each trace path, the full step-by-step data flow (file locations, code snippets, annotations, edge types, vulnerability tags, Z3 constraints) is formatted into a structured prompt. The LLM generates a standalone C program that simulates the exact data flow: reading input from stdin, passing it through the same chain of conditions and function calls, and performing the vulnerable operation at the sink. The harness includes a `SINK_REACHED` marker that fires only when all path conditions are satisfied.

**Sandbox execution** — The harness is compiled with `gcc -fsanitize=address -g` inside a Docker container (`gcc:13`) or locally. AddressSanitizer detects memory corruption at runtime: heap-buffer-overflow, stack-buffer-overflow, use-after-free, global-buffer-overflow, double-free, etc. Each test run is isolated with a 10-second timeout and 512MB memory cap.

**Iterative refinement** — The pipeline runs up to 3 compile-repair cycles (sending gcc errors to the LLM for fixes) and up to 3 input-generation rounds (sending execution results to the LLM for adaptive input crafting). The LLM sees what previous inputs produced — exit codes, whether the sink was reached, ASAN output — and generates more targeted inputs to satisfy the remaining unsatisfied conditions.

**Crash classification** — Run results are classified by crash type: ASAN detections are parsed from stderr (`heap-buffer-overflow`, `use-after-free`, etc.); signal-based crashes are identified from exit codes (SIGSEGV → segfault, SIGABRT → abort); and the `SINK_REACHED` marker confirms data flow completeness even without a crash.

**Report generation** — Each path gets a detailed Markdown report with: executive summary, full trace with code, the generated harness, a results table for all test runs, ASAN stack traces, the triggering input (hex + description), and vulnerability-specific remediation recommendations. A `SUMMARY.md` provides an overview table across all paths.

### 9. Vulnerability scanning (deeptrace scan)

The scanner is the recommended entry point when you don't already know which lines to trace. It processes the entire repository to produce a prioritized list of attack targets.

**Phase 1 — Regex pattern scan** — 38 compiled regex patterns are applied to every source file. Patterns are organized by vulnerability category (19 total) and tagged with CWE identifiers, severity levels, and whether they represent a **sink** (dangerous operation) or **source** (attacker input entry point). The scanner covers 7 language families (C, C++, Java, Kotlin, Python, Swift, Rust) and skips test/vendor/build directories. A single pass over pdfium's ~500K lines completes in seconds.

**Phase 2 — Context enrichment** — For each regex hit, the scanner reads ±10 lines of surrounding code, identifies the enclosing function name and signature, detects nearby safety guards (bounds checks, null checks, safe wrapper calls like `snprintf`/`strlcpy`), and extracts the call arguments. Hits inside comments are discarded. Hits with nearby guards have their confidence downgraded. Duplicate hits (same file:line from different patterns) are deduplicated, keeping the highest-severity match.

**Phase 3 — LLM triage** — When an LLM is configured, enriched hits are sent in batches of 10 with a strict evaluation prompt. The LLM sees the full code context and is specifically instructed that:
- `memcpy` with `sizeof(dest)` as the length is **not** a vulnerability.
- `printf("literal string")` is **not** a format string bug.
- `free(ptr)` followed by `ptr = NULL` is **not** use-after-free.

For each hit, the LLM returns: whether it's a real vulnerability or false positive, a confidence level, a concrete explanation of the attack vector, and a severity assessment. A second LLM pass then identifies **source-sink pairs** — matching attacker input entry points (HTTP params, socket reads, file reads, environment variables) to the confirmed dangerous operations, explaining the likely data flow connection between them.

**Supported categories** — buffer overflow, format string, command injection, SQL injection, path traversal, use-after-free, integer overflow, type confusion, deserialization, XXE, SSRF, crypto weakness, auth bypass, race condition, template injection, LDAP injection, information leak, resource leak, stack overflow.

## Output format

```json
{
  "version": "1.0.0",
  "target": "src/foo.c:123",
  "source": "src/input.c:42",
  "repo": "/path/to/repo",
  "language": "c",
  "node_count": 847,
  "edge_count": 1523,
  "nodes": [ ... ],
  "edges": [ ... ],
  "paths": [
    {
      "id": "a1b2c3d4e5f6g7h8",
      "depth": 12,
      "score": 45.5,
      "llm_rank": 1,
      "llm_rationale": "Unvalidated network input flows through 3 functions to a memcpy with attacker-controlled length",
      "vulnerability_tags": ["buffer_overflow", "unvalidated_input"],
      "vulnerability_summary": "Step-by-step: (1) Network data is received at socket.c:42... (2) Length is passed unchecked to copy_data()... (3) memcpy at foo.c:123 copies attacker-controlled length bytes, causing heap overflow.",
      "is_satisfiable": true,
      "z3_model": "buf_len = 4096; max_size = 256",
      "constraints": [
        "[step 3, condition] buf_len > max_size",
        "[step 5, bounds] idx < arr_size"
      ],
      "steps": [
        {
          "node_id": "j:net/socket.c:42:recv_data",
          "location": {"file": "net/socket.c", "line": 42},
          "edge_kind": "data_flow",
          "code_snippet": "int n = recv(fd, buf, sizeof(buf), 0);",
          "annotation": "Network data source — attacker-controlled bytes received into buf, n holds byte count"
        },
        ...
      ]
    }
  ],
  "session": {
    "session_id": "abc123",
    "pending_branches": [ ... ],
    "resolved_branches": [ ... ]
  },
  "metadata": {
    "elapsed_seconds": 34.2,
    "branch_points_detected": 3,
    "source_sink_mode": true,
    "z3_enabled": true,
    "aco_config": { ... }
  }
}
```

## Configuration

All settings can be set via CLI flags, environment variables (`DEEPTRACE_` prefix), or a config file.

### Environment variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | API key for Claude LLM ranking |
| `OPENAI_API_KEY` | API key for OpenAI-compatible LLM |
| `OLLAMA_HOST` | Ollama server URL (default: http://localhost:11434) |
| `DEEPTRACE_MAX_DEPTH` | Max trace depth |
| `DEEPTRACE_MAX_CALLER_HOPS` | Max frontier expansion depth (default: 3, 0=disabled) |
| `DEEPTRACE_ACO__ANTS` | Number of ACO ants |
| `DEEPTRACE_ACO__ITERATIONS` | ACO iterations |
| `DEEPTRACE_JOERN__DOCKER_IMAGE` | Joern Docker image |
| `DEEPTRACE_JOERN__MEMORY_LIMIT` | Docker memory limit |

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest -v

# Type checking
mypy src/deeptrace

# Lint
ruff check src/ tests/
```

## Limitations

- Joern precision varies by language frontend; Kotlin/Swift are newer and may miss some flows
- Pointer aliasing in C/C++ is under-approximated in some cases
- tree-sitter fallback is syntax-based and cannot track actual dataflow
- ACO is stochastic — different runs may produce different path sets (use `--ants` and `--iterations` to improve coverage)
- LLM ranking requires API access and has per-call costs
- Exploit validation harnesses are simplified stubs, not compilable against the real codebase — a confirmed crash proves the *pattern* is exploitable, not that the exact real-world path is reachable at runtime
- Frontier expansion uses text search (grep or Python fallback) which may produce false matches in comments or string literals; tree-sitter confirmation filters most of these but edge cases exist
- Windows users without Docker will use local gcc, which may not have AddressSanitizer support depending on the MinGW/MSVC installation
- Scanner regex patterns are intentionally broad for recall — without LLM triage (`--no-llm`), expect a higher false positive rate; enable LLM for production-quality results
