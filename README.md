
"""Staged exploit agent with state-object architecture.

Stages:
  0. UNDERSTAND  — system reads sink, entry, header, fuzzers (no LLM)
  1. EXPLORE     — LLM fills gaps from UNDERSTAND (only if needed)
  2. WRITE       — LLM writes harness (sees state object + last 2 exchanges)
  3. COMPILE     — LLM fixes errors (system validates .o on disk)
  4. LINK        — system resolves dependencies (no LLM unless it fails)
  5. RUN         — system runs binary with test input
  6. SWEEP       — system tries all test files
  7. CRAFT       — isolated LLM call to generate malformed input
  8. RUN_CRAFTED — system runs binary with crafted input
  9. VERIFY      — GDB + ASAN confirms crash at sink

Every stage has a concrete gate. The LLM never sees more than 2 prior
exchanges. The state object IS the memory.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable

from deeptrace.exploit.docker_env import DockerEnv, ExecResult
from deeptrace.exploit.repo_analyzer import RepoProfile
from deeptrace.exploit.verification import verify_harness, VerificationResult
from deeptrace.models.graph import TracePath

logger = logging.getLogger(__name__)


# =====================================================================
# State
# =====================================================================

class Stage(Enum):
    UNDERSTAND = auto()
    EXPLORE = auto()
    WRITE = auto()
    COMPILE = auto()
    LINK = auto()
    RUN = auto()
    SWEEP = auto()
    CRAFT = auto()
    RUN_CRAFTED = auto()
    VERIFY = auto()
    SUCCESS = auto()
    HALTED = auto()


@dataclass
class StateObject:
    """Structured facts accumulated across stages. This IS the agent's memory."""
    # Target
    sink_function: str = ""
    sink_file: str = ""
    entry_function: str = ""
    entry_file: str = ""
    vuln_tags: list[str] = field(default_factory=list)
    vuln_summary: str = ""
    trace_text: str = ""

    # Gathered by UNDERSTAND / EXPLORE
    sink_source: str = ""           # actual code around the sink
    entry_source: str = ""          # actual code at entry point
    header_file: str = ""           # path to header declaring sink
    header_declarations: str = ""   # function signatures from header
    include_flags: str = ""         # -I flags derived from header path
    reference_harness: str = ""     # content of existing fuzzer/test
    test_files: list[str] = field(default_factory=list)
    input_format: str = "binary"    # PDF, CGATS/ICC, XML, PNG, etc.
    input_ext: str = ".bin"
    repo_layout: str = ""

    # Filled by stages
    compile_errors: list[str] = field(default_factory=list)
    link_errors: str = ""
    run_output: str = ""
    crash_type: str = ""            # target_sink, same_file, wrong_location, harness_bug, clean, timeout
    crash_file: str = ""            # input file that caused crash
    pipeline_attempts: int = 0
    backward_reasons: list[str] = field(default_factory=list)

    def summary(self) -> str:
        """Compact text representation for LLM context."""
        lines = [
            f"SINK: {self.sink_function} @ {self.sink_file}",
            f"ENTRY: {self.entry_function} @ {self.entry_file}",
            f"VULN: {', '.join(self.vuln_tags) or 'unknown'} — {self.vuln_summary or 'N/A'}",
        ]
        if self.header_file:
            lines.append(f"HEADER: {self.header_file}")
        if self.include_flags:
            lines.append(f"COMPILE FLAGS: {self.include_flags}")
        if self.input_format != "binary":
            lines.append(f"INPUT FORMAT: {self.input_format} ({self.input_ext})")
        if self.test_files:
            lines.append(f"TEST FILES: {', '.join(self.test_files[:5])}")
        if self.backward_reasons:
            lines.append(f"PREVIOUS ATTEMPTS FAILED:")
            for r in self.backward_reasons[-3:]:
                lines.append(f"  - {r}")
        return "\n".join(lines)


# =====================================================================
# Prompts
# =====================================================================

_TOOLS_BLOCK = """
=== TOOLS ===

<shell>ls /src/ | head -20</shell>
  Run any shell command. Put your ACTUAL command inside the tags.

<write_file path="/work/harness.cpp">
#include <stdio.h>
int main() { return 0; }
</write_file>
  Create or overwrite a file.

<read_file path="/src/some/file.c" />
  Read a file.

=== RULES ===
- Every response MUST contain at least one tool tag
- Put your ACTUAL command inside <shell>...</shell>
- Fix the SPECIFIC error — do not rewrite from scratch
"""


# =====================================================================
# Action parsing
# =====================================================================

@dataclass
class AgentAction:
    kind: str
    content: str = ""
    path: str = ""

_PLACEHOLDERS = frozenset({
    "command", "your command here", "your command", "command here",
    "content", "your reasoning", "your reasoning here", "summary",
})

def parse_actions(response: str) -> list[AgentAction]:
    actions: list[AgentAction] = []

    for m in re.finditer(r"<shell>(.*?)</shell>", response, re.DOTALL):
        cmd = m.group(1).strip()
        if not cmd:
            continue
        if cmd.lower() in _PLACEHOLDERS:
            # Try to recover real command from the line after </shell>
            after = response[m.end():m.end()+300].strip().split("\n")[0].strip()
            if after and re.match(r'^[a-z/]', after) and len(after) > 3:
                actions.append(AgentAction(kind="shell", content=after))
                logger.warning("Recovered command after placeholder: %s", after[:80])
            continue
        actions.append(AgentAction(kind="shell", content=cmd))

    for m in re.finditer(r'<write_file\s+path="([^"]+)">(.*?)</write_file>', response, re.DOTALL):
        actions.append(AgentAction(kind="write_file", path=m.group(1), content=m.group(2)))

    for m in re.finditer(r'<read_file\s+path="([^"]+)"\s*/>', response):
        actions.append(AgentAction(kind="read_file", path=m.group(1)))

    if actions:
        return actions

    # Markdown fallback
    for m in re.finditer(r"```(?:bash|sh|shell)\s*\n([\s\S]*?)\n\s*```", response):
        for line in m.group(1).strip().split("\n"):
            s = line.strip()
            if s and not s.startswith("#"):
                actions.append(AgentAction(kind="shell", content=s))

    for m in re.finditer(r"```(?:cpp|c\+\+|c)\s*\n([\s\S]*?)\n\s*```", response):
        code = m.group(1).strip()
        if "#include" in code and ("int main" in code or "LLVMFuzzerTestOneInput" in code):
            actions.append(AgentAction(kind="write_file", path="/work/harness.cpp", content=code))

    return actions


def extract_thought(response: str) -> str:
    m = re.search(r"<think>(.*?)</think>", response, re.DOTALL)
    return m.group(1).strip() if m else ""


# =====================================================================
# Config & Result
# =====================================================================

@dataclass
class AgentConfig:
    max_turns: int = 80
    max_actions_per_turn: int = 10
    exec_timeout: int = 60
    verify_timeout: int = 30
    max_write_attempts: int = 3
    max_compile_attempts: int = 5
    max_pipeline_attempts: int = 3


@dataclass
class AgentResult:
    success: bool = False
    verification: VerificationResult | None = None
    turns_used: int = 0
    total_actions: int = 0
    elapsed_seconds: float = 0.0
    harness_path: str = ""
    input_path: str = ""
    final_reason: str = ""
    postmortem: dict[str, Any] = field(default_factory=dict)
    log: list[dict[str, Any]] = field(default_factory=list)


# =====================================================================
# Agent
# =====================================================================

class ExploitAgent:

    def __init__(self, llm_caller, env, profile, trace_path, sink_function, sink_file,
                 config=None, progress_callback=None, llm_coder=None):
        self.llm_a = llm_caller                                    # explorer / reviewer
        self.llm_b = llm_coder if llm_coder else llm_caller        # coder / crafter
        self.dual = llm_coder is not None
        self.env = env
        self.profile = profile
        self.trace = trace_path
        self.sink_function = sink_function
        self.sink_file = sink_file
        self.config = config or AgentConfig()
        self._progress = progress_callback

        # State
        self.stage = Stage.UNDERSTAND
        self.so = StateObject()             # the state object — agent's only memory
        self._exchanges: list[tuple[str, str]] = []  # last 2 kept per stage
        self._turn = 0

        # For CLI compatibility
        self.llm_call = llm_caller
        self.llm_code = self.llm_b

    # =================================================================
    # Main loop
    # =================================================================

    def run(self) -> AgentResult:
        t0 = time.time()
        result = AgentResult()
        result.log.append({"event": "agent_start", "stage": self.stage.name,
                           "sink": self.sink_function, "repo": self.profile.repo_name})

        # --- STAGE 0: UNDERSTAND (no LLM) ---
        self._run_understand()
        result.log.append({"event": "understand_done", "has_sink_source": bool(self.so.sink_source),
                           "has_header": bool(self.so.header_file), "has_reference": bool(self.so.reference_harness),
                           "test_files": len(self.so.test_files)})

        # Gate 0: decide whether to EXPLORE or skip to WRITE
        if self.so.sink_source and self.so.header_declarations:
            self.stage = Stage.WRITE
            logger.info("UNDERSTAND found sink + header → skipping EXPLORE")
        elif self.so.sink_source:
            self.stage = Stage.EXPLORE
            logger.info("UNDERSTAND found sink but no header → EXPLORE for header")
        else:
            self.stage = Stage.EXPLORE
            logger.info("UNDERSTAND found nothing → full EXPLORE")

        # --- Main stage loop ---
        for self._turn in range(self.config.max_turns):
            if self.stage in (Stage.SUCCESS, Stage.HALTED):
                break

            if self._progress:
                self._progress(f"Turn {self._turn+1} [{self.stage.name}]", self._turn)

            turn_log = {"event": "turn", "turn": self._turn+1, "stage": self.stage.name,
                        "timestamp": time.time()}

            if self.stage == Stage.EXPLORE:
                self._run_explore_turn(result, turn_log)
            elif self.stage == Stage.WRITE:
                self._run_write_turn(result, turn_log)
            elif self.stage == Stage.COMPILE:
                self._run_compile_turn(result, turn_log)
            elif self.stage in (Stage.LINK, Stage.RUN, Stage.SWEEP, Stage.CRAFT,
                                Stage.RUN_CRAFTED, Stage.VERIFY):
                # Deterministic pipeline — runs without LLM turns
                self._run_pipeline(result, turn_log)
            else:
                break

            result.turns_used = self._turn + 1
            result.log.append(turn_log)

        result.elapsed_seconds = round(time.time() - t0, 2)
        if not result.success:
            result.postmortem = {"turns": result.turns_used, "stage": self.stage.name,
                                 "backward_reasons": self.so.backward_reasons}
        result.log.append({"event": "agent_end", "success": result.success,
                           "turns": result.turns_used, "elapsed": result.elapsed_seconds})
        return result

    # =================================================================
    # STAGE 0: UNDERSTAND (system only, no LLM)
    # =================================================================

    def _run_understand(self):
        """Fill the state object with everything we can find without an LLM."""
        so = self.so
        so.sink_function = self.sink_function
        so.sink_file = self.sink_file
        so.vuln_tags = self.trace.vulnerability_tags or []
        so.vuln_summary = self.trace.vulnerability_summary or ""

        # Trace text
        lines = []
        for i, s in enumerate(self.trace.steps[:20]):
            loc = f"{s.location.file}:{s.location.line}" if s.location else "?"
            tag = " [ENTRY]" if i == 0 else (" [SINK]" if i == len(self.trace.steps)-1 else "")
            edge = f" [{s.edge_kind.value}]" if s.edge_kind else ""
            lines.append(f"  {i}{tag}: {loc}{edge} — {(s.code_snippet or '?')[:100]}")
        so.trace_text = "\n".join(lines)

        # Entry point info
        if self.trace.steps:
            entry = self.trace.steps[0].location
            if entry and entry.file:
                so.entry_file = entry.file
                so.entry_function = self.trace.steps[0].node_name or ""

        if not self.env.is_running:
            return

        # (1) Read sink source
        sink_loc = self.trace.steps[-1].location if self.trace.steps else None
        if sink_loc and sink_loc.file:
            r = self.env.exec(f"sed -n '{max(1,sink_loc.line-15)},{sink_loc.line+15}p' /src/{sink_loc.file} 2>/dev/null", timeout=5)
            so.sink_source = r.stdout.strip()[:2000] if r.stdout.strip() else ""

        # (2) Read entry source
        entry_loc = self.trace.steps[0].location if self.trace.steps else None
        if entry_loc and entry_loc.file:
            r = self.env.exec(f"sed -n '{max(1,entry_loc.line-10)},{entry_loc.line+10}p' /src/{entry_loc.file} 2>/dev/null", timeout=5)
            so.entry_source = r.stdout.strip()[:1500] if r.stdout.strip() else ""

        # (3) Find header declaring sink
        hdr_r = self.env.exec(f"grep -rn '{self.sink_function}' /src/ --include='*.h' -l 2>/dev/null | head -3", timeout=10)
        if hdr_r.stdout.strip():
            so.header_file = hdr_r.stdout.strip().split("\n")[0].strip()
            # Derive include flags
            hdr_dir = so.header_file.rsplit("/", 1)[0] if "/" in so.header_file else ""
            if hdr_dir:
                so.include_flags = f"-I{hdr_dir}"
                # Also try parent (e.g., -I/src/third_party/lcms/include from .../include/lcms2.h)
                parent = hdr_dir.rsplit("/", 1)[0] if "/" in hdr_dir else ""
                if parent and parent != "/src":
                    so.include_flags = f"-I{hdr_dir} -I{parent}"
            # Read declaration
            decl = self.env.exec(f"grep -n '{self.sink_function}' {so.header_file} 2>/dev/null | head -3", timeout=5)
            if decl.stdout.strip():
                try:
                    ln = int(decl.stdout.strip().split(":")[0])
                    hdr_src = self.env.exec(f"sed -n '{max(1,ln-5)},{ln+10}p' {so.header_file} 2>/dev/null", timeout=5)
                    so.header_declarations = hdr_src.stdout.strip()[:1000] if hdr_src.stdout.strip() else ""
                except ValueError:
                    pass

        # (4) Find existing fuzzer/test
        fuzz = self.env.exec("find /src -name '*fuzz*' \\( -name '*.c' -o -name '*.cc' -o -name '*.cpp' \\) 2>/dev/null | head -5", timeout=10)
        if fuzz.stdout.strip():
            best = fuzz.stdout.strip().split("\n")[0].strip()
            # Prefer one in same directory as sink
            sink_dir = self.sink_file.rsplit("/", 1)[0] if "/" in self.sink_file else ""
            for ff in fuzz.stdout.strip().split("\n"):
                if sink_dir and sink_dir in ff.strip():
                    best = ff.strip()
                    break
            src = self.env.exec(f"head -80 {best} 2>/dev/null", timeout=5)
            so.reference_harness = src.stdout.strip()[:2000] if src.stdout.strip() else ""

        # (5) Find test data + detect format
        for kws, fmt, ext in [
            (("cms", "lcms", "icc", "cgats", "it8"), "CGATS/ICC", ".it8"),
            (("pdf", "fpdf"), "PDF", ".pdf"),
            (("xml", "expat"), "XML", ".xml"),
            (("png",), "PNG", ".png"),
        ]:
            if any(k in (so.sink_file + so.entry_file + so.sink_source).lower() for k in kws):
                so.input_format, so.input_ext = fmt, ext
                break

        test_r = self.env.exec(
            f"find /src -type f \\( -name '*{so.input_ext}' -o -name '*.pdf' -o -name '*.it8' "
            f"-o -name '*.icc' -o -name '*.xml' -o -name '*.png' \\) 2>/dev/null | head -20", timeout=10)
        if test_r.stdout.strip():
            so.test_files = [f.strip() for f in test_r.stdout.strip().split("\n") if f.strip()]

        # (6) Repo layout
        ls = self.env.exec("ls /src/ | head -30", timeout=5)
        so.repo_layout = ls.stdout.strip()[:500] if ls.stdout.strip() else ""

        # Public headers for include reference
        pub = self.env.exec("find /src -path '*/include/*.h' -o -path '*/public/*.h' | head -10", timeout=5)
        if pub.stdout.strip() and not so.include_flags:
            first_hdr = pub.stdout.strip().split("\n")[0].strip()
            hdr_dir = first_hdr.rsplit("/", 1)[0]
            so.include_flags = f"-I{hdr_dir}"

    # =================================================================
    # STAGE 1: EXPLORE (LLM, only to fill gaps)
    # =================================================================

    _explore_turns = 0

    def _run_explore_turn(self, result: AgentResult, turn_log: dict):
        self._explore_turns += 1
        so = self.so

        # Build task based on what's missing
        missing = []
        if not so.header_file:
            missing.append(f"Find the header file that declares {so.sink_function}. Use: grep -rn '{so.sink_function}' /src/ --include='*.h' -l")
        if not so.reference_harness:
            missing.append("Find any test/fuzzer that calls functions from this library. Use: find /src -name '*fuzz*' -o -name '*test*'")
        if not so.test_files:
            missing.append(f"Find sample input files ({so.input_ext}). Use: find /src -type f -name '*{so.input_ext}'")

        if not missing:
            # Nothing to explore — gate passes
            self.stage = Stage.WRITE
            self._exchanges.clear()
            turn_log["gate"] = "EXPLORE complete — all fields filled"
            return

        prompt = f"""STATE:\n{so.summary()}\n\nMISSING INFORMATION:\n""" + "\n".join(f"  {i+1}. {m}" for i, m in enumerate(missing))
        prompt += "\n\nFind these items. Use <shell> to search."

        response = self._call_llm(self.llm_a, "You are exploring a C/C++ repo. Source at /src/.\n" + _TOOLS_BLOCK, prompt)
        turn_log["llm_response"] = response[:4000]

        actions = parse_actions(response)
        if not actions:
            turn_log["no_actions"] = True
            return

        results = self._exec_actions(actions[:self.config.max_actions_per_turn], result)
        self._exchanges.append((response[:1500], results[:1500]))
        self._exchanges = self._exchanges[-2:]
        turn_log["actions_count"] = len(actions)

        # Update state from results
        self._update_state_from_results(results)

        # Gate: check if we now have enough
        if so.header_file or self._explore_turns >= 6:
            self.stage = Stage.WRITE
            self._exchanges.clear()
            turn_log["gate"] = "EXPLORE → WRITE"

    def _update_state_from_results(self, results: str):
        """Parse action results to fill state object fields."""
        so = self.so
        # Look for header files in output
        for line in results.split("\n"):
            line = line.strip()
            if line.endswith(".h") and "/src/" in line and not so.header_file:
                so.header_file = line
                hdr_dir = line.rsplit("/", 1)[0]
                so.include_flags = f"-I{hdr_dir}"
                logger.info("Found header: %s → flags: %s", so.header_file, so.include_flags)

    # =================================================================
    # STAGE 2: WRITE (LLM writes harness)
    # =================================================================

    _write_attempts = 0

    def _run_write_turn(self, result: AgentResult, turn_log: dict):
        so = self.so
        self._write_attempts += 1

        # Build focused prompt from state object
        sections = [f"TASK: Write /work/harness.cpp\n\n{so.summary()}"]

        if so.sink_source:
            sections.append(f"\n=== SINK SOURCE ({so.sink_file}) ===\n{so.sink_source}")
        if so.entry_source:
            sections.append(f"\n=== ENTRY POINT ({so.entry_file}) ===\n{so.entry_source}")
        if so.header_declarations:
            sections.append(f"\n=== API HEADER ({so.header_file}) ===\n{so.header_declarations}")
        if so.reference_harness:
            sections.append(f"\n=== REFERENCE FUZZER ===\n{so.reference_harness}")
        sections.append(f"\nTRACE:\n{so.trace_text}")

        # Add feedback from previous failures
        if so.backward_reasons:
            sections.append(f"\n=== PREVIOUS FAILURES ===")
            for r in so.backward_reasons[-3:]:
                sections.append(f"  - {r}")

        # Add last 2 exchanges
        for _, res in self._exchanges[-2:]:
            sections.append(f"\n--- Previous result ---\n{res[:1000]}")

        sections.append(f"""
REQUIREMENTS:
1. #include the correct header (use {so.include_flags or '-I/src'})
2. Read input from argv[1] as a file
3. Call {so.entry_function or so.sink_function} to process the input
4. The execution path must reach {so.sink_function}

Use <write_file path="/work/harness.cpp"> to create the file.""")

        prompt = "\n".join(sections)
        response = self._call_llm(self.llm_b, "You write C/C++ exploit harnesses.\n" + _TOOLS_BLOCK, prompt)
        turn_log["llm_response"] = response[:4000]

        actions = parse_actions(response)
        results = self._exec_actions(actions[:self.config.max_actions_per_turn], result) if actions else ""
        self._exchanges.append((response[:1500], results[:1500]))
        self._exchanges = self._exchanges[-2:]

        # Gate 2: harness.cpp exists + valid
        check = self._validate_harness()
        turn_log["gate"] = check

        if check == "PASS":
            self.stage = Stage.COMPILE
            self._exchanges.clear()
            so.compile_errors.clear()
        elif self._write_attempts >= self.config.max_write_attempts:
            logger.warning("WRITE failed %dx → force-writing template", self._write_attempts)
            self._force_write_harness()
            self.stage = Stage.COMPILE
            self._exchanges.clear()
            turn_log["forced_harness"] = True
        else:
            # Tell LLM what's wrong
            self._exchanges.append(("(system)", f"⚠️ Harness invalid: {check}\nFix it with <write_file>."))

    def _validate_harness(self) -> str:
        """Check if harness.cpp exists and looks correct."""
        exists = self.env.exec("test -f /work/harness.cpp && echo y", timeout=5).stdout.strip() == "y"
        if not exists:
            return "FAIL: /work/harness.cpp does not exist"
        content = self.env.exec("cat /work/harness.cpp 2>/dev/null", timeout=5).stdout or ""
        if "#include" not in content:
            return "FAIL: missing #include"
        if "main" not in content and "LLVMFuzzerTestOneInput" not in content:
            return "FAIL: missing main() or LLVMFuzzerTestOneInput"
        # Check if it references any function from the trace
        trace_funcs = [s.node_name.split("|")[0].strip() for s in self.trace.steps
                       if s.node_name and len(s.node_name) > 3]
        has_trace_func = any(f in content for f in trace_funcs if f)
        if not has_trace_func and self.so.sink_function not in content and self.so.entry_function not in content:
            return f"FAIL: harness doesn't call any function from the trace ({self.so.sink_function}, {self.so.entry_function})"
        return "PASS"

    # =================================================================
    # STAGE 3: COMPILE (LLM fixes errors, system validates .o)
    # =================================================================

    _compile_attempts = 0

    def _run_compile_turn(self, result: AgentResult, turn_log: dict):
        so = self.so
        self._compile_attempts += 1

        # First attempt: system tries to compile directly
        flags = so.include_flags or "-I/src"
        cmd = f"g++ -fsanitize=address -g -std=c++17 {flags} /work/harness.cpp -c -o /work/harness.o 2>&1"
        r = self.env.exec(cmd, timeout=60)
        output = self._smart_truncate(cmd, r.exit_code, r.output or "")

        # Gate 3: does .o exist?
        obj_exists = self.env.exec("test -f /work/harness.o && echo y", timeout=5).stdout.strip() == "y"

        if obj_exists:
            turn_log["gate"] = "COMPILE PASS"
            self.stage = Stage.LINK
            self._exchanges.clear()
            return

        # Failed — analyze the error
        turn_log["compile_output"] = output[:2000]
        so.compile_errors.append(output[:500])

        # Decision: missing header → try to auto-fix include path
        if "No such file or directory" in output and ".h" in output:
            missing = re.search(r"['\"]([^'\"]+\.h)['\"]", output)
            if missing:
                hdr_name = missing.group(1).split("/")[-1]
                find_r = self.env.exec(f"find /src -name '{hdr_name}' 2>/dev/null | head -3", timeout=10)
                if find_r.stdout.strip():
                    found_path = find_r.stdout.strip().split("\n")[0].strip()
                    new_dir = found_path.rsplit("/", 1)[0]
                    so.include_flags = f"{so.include_flags} -I{new_dir}".strip()
                    turn_log["auto_fix"] = f"Added -I{new_dir}"
                    return  # retry compile next turn with new flags

        # Decision: too many failures with same error → ask reviewer
        if self._compile_attempts >= self.config.max_compile_attempts:
            # Ask reviewer for help
            review = self._ask_reviewer(f"Compilation failed {self._compile_attempts}x.\nLast error:\n{output[:500]}")
            turn_log["review"] = review
            if "rewrite" in review.get("message", "").lower():
                so.backward_reasons.append(f"compile failed {self._compile_attempts}x: {output[:100]}")
                self.stage = Stage.WRITE
                self._write_attempts = 0
                self._compile_attempts = 0
                self._exchanges.clear()
                return
            # reviewer gave redirect — inject it
            self._exchanges = [(("(system)", f"Compile error:\n{output[:800]}\n\nReviewer says: {review.get('message', '')}"))]
            return

        # Normal case: LLM fixes the error
        prompt = f"STATE:\n{so.summary()}\n\nCOMPILE ERROR:\n{output[:1500]}\n\nFix ONLY this error in /work/harness.cpp. Use <write_file>."
        response = self._call_llm(self.llm_b, "Fix compile errors.\n" + _TOOLS_BLOCK, prompt)
        turn_log["llm_response"] = response[:4000]

        actions = parse_actions(response)
        if actions:
            self._exec_actions(actions[:self.config.max_actions_per_turn], result)

    # =================================================================
    # STAGES 4-9: PIPELINE (deterministic, no LLM except CRAFT)
    # =================================================================

    def _run_pipeline(self, result: AgentResult, turn_log: dict):
        """Run all deterministic stages in sequence."""

        # --- STAGE 4: LINK ---
        if self.stage == Stage.LINK:
            turn_log["pipeline_stage"] = "LINK"
            ok = self.env.exec("test -x /work/harness && echo y", timeout=5).stdout.strip() == "y"

            if not ok:
                objs = self.env.exec("ls /work/*.o 2>/dev/null", timeout=5).stdout.replace("\n", " ").strip()
                if objs:
                    self.env.exec(f"g++ -fsanitize=address -g {objs} -o /work/harness -lpthread -ldl 2>&1", timeout=60)
                    ok = self.env.exec("test -x /work/harness && echo y", timeout=5).stdout.strip() == "y"

                if not ok:
                    resolve_out = self._resolve_linking()
                    turn_log["link_resolve"] = resolve_out[:1000]
                    ok = self.env.exec("test -x /work/harness && echo y", timeout=5).stdout.strip() == "y"

            if ok:
                self.stage = Stage.RUN
            else:
                self.so.backward_reasons.append(f"link failed: {turn_log.get('link_resolve', 'unknown')[:100]}")
                self.so.link_errors = turn_log.get("link_resolve", "")
                self._exchanges = [("(system)", f"⚠️ LINK FAILED.\n{self.so.link_errors[:500]}\nRewrite harness to avoid these deps.")]
                self.stage = Stage.WRITE
                self._write_attempts = 0
            return

        # --- STAGE 5: RUN ---
        if self.stage == Stage.RUN:
            turn_log["pipeline_stage"] = "RUN"
            inp = self._find_input_file()
            run_out = self._run_harness(inp)
            self.so.run_output = run_out
            turn_log["run_output"] = run_out[:1000]

            crash = self._classify_crash(run_out)
            self.so.crash_type = crash
            turn_log["crash_type"] = crash

            if crash in ("target_sink", "same_file"):
                self.so.crash_file = inp
                self.stage = Stage.VERIFY
            elif crash == "harness_bug":
                self.so.backward_reasons.append(f"harness bug: {run_out[:100]}")
                self._exchanges = [("(system)", f"⚠️ Crash in YOUR harness, not library:\n{run_out[:500]}\nFix the bug.")]
                self.stage = Stage.WRITE
                self._write_attempts = 0
            else:
                self.stage = Stage.SWEEP
            return

        # --- STAGE 6: SWEEP ---
        if self.stage == Stage.SWEEP:
            turn_log["pipeline_stage"] = "SWEEP"
            crash_file = self._sweep_inputs()
            if crash_file:
                self.so.crash_file = crash_file
                self.stage = Stage.VERIFY
            else:
                self.stage = Stage.CRAFT
            return

        # --- STAGE 7: CRAFT (isolated LLM) ---
        if self.stage == Stage.CRAFT:
            turn_log["pipeline_stage"] = "CRAFT"
            crafted = self._craft_input()
            if crafted:
                self.so.crash_file = crafted
                self.stage = Stage.RUN_CRAFTED
            else:
                self.so.pipeline_attempts += 1
                if self.so.pipeline_attempts >= self.config.max_pipeline_attempts:
                    self.stage = Stage.HALTED
                    self.so.backward_reasons.append("pipeline exhausted: no crash after max attempts")
                else:
                    self.so.backward_reasons.append(f"attempt {self.so.pipeline_attempts}: no crash with any input")
                    self._exchanges = [("(system)", f"⚠️ Pipeline attempt {self.so.pipeline_attempts} failed.\n"
                                        f"Harness runs clean. Rewrite to exercise more of the trace.\n"
                                        f"Trace: {self.so.sink_function} needs to be reached via {self.so.entry_function}")]
                    self.stage = Stage.WRITE
                    self._write_attempts = 0
                    self._compile_attempts = 0
            return

        # --- STAGE 8: RUN_CRAFTED ---
        if self.stage == Stage.RUN_CRAFTED:
            turn_log["pipeline_stage"] = "RUN_CRAFTED"
            run_out = self._run_harness(self.so.crash_file)
            crash = self._classify_crash(run_out)
            turn_log["crash_type"] = crash

            if crash in ("target_sink", "same_file"):
                self.stage = Stage.VERIFY
            elif crash == "wrong_location":
                self.so.pipeline_attempts += 1
                self.so.backward_reasons.append(f"crash at wrong location, not {self.so.sink_function}")
                if self.so.pipeline_attempts >= self.config.max_pipeline_attempts:
                    self.stage = Stage.HALTED
                else:
                    self._exchanges = [("(system)", f"⚠️ Crash at wrong function.\nTarget: {self.so.sink_function}\nRewrite harness to reach the correct code path.")]
                    self.stage = Stage.WRITE
                    self._write_attempts = 0
            else:
                # Clean exit from crafted input — try craft again or go back
                self.so.pipeline_attempts += 1
                if self.so.pipeline_attempts >= self.config.max_pipeline_attempts:
                    self.stage = Stage.HALTED
                else:
                    self.stage = Stage.CRAFT  # retry with different craft
            return

        # --- STAGE 9: VERIFY ---
        if self.stage == Stage.VERIFY:
            turn_log["pipeline_stage"] = "VERIFY"
            vr = self._run_verification("/work/harness", self.so.crash_file)
            result.verification = vr
            turn_log["verified"] = vr.confirmed

            if vr.confirmed:
                result.success = True
                result.harness_path = "/work/harness"
                result.input_path = self.so.crash_file
                self.stage = Stage.SUCCESS
            else:
                # Verification failed — crash wasn't at the right place
                self.so.backward_reasons.append(f"verification failed: {vr.summary[:100]}")
                self.so.pipeline_attempts += 1
                if self.so.pipeline_attempts >= self.config.max_pipeline_attempts:
                    self.stage = Stage.HALTED
                else:
                    self.stage = Stage.WRITE
                    self._write_attempts = 0
            return

    # =================================================================
    # Helpers
    # =================================================================

    def _call_llm(self, llm_fn, system: str, prompt: str) -> str:
        try:
            return llm_fn(system, prompt)
        except Exception as exc:
            logger.error("LLM call failed: %s", exc)
            return ""

    def _exec_actions(self, actions: list[AgentAction], result: AgentResult) -> str:
        parts = []
        for a in actions:
            result.total_actions += 1
            if a.kind == "shell":
                r = self.env.exec(a.content, timeout=self.config.exec_timeout)
                out = self._smart_truncate(a.content, r.exit_code, r.output or "")
                parts.append(f"[shell] $ {a.content}\nexit_code={r.exit_code}\n{out}")
            elif a.kind == "write_file":
                wr = self.env.write_file(a.path, a.content)
                parts.append(f"[write_file] {'OK' if wr.success else 'FAIL'}: {a.path}")
            elif a.kind == "read_file":
                content = self.env.read_file(a.path)
                parts.append(f"[read_file] {a.path}:\n{content[:3000]}")
        return "\n\n".join(parts)

    def _classify_crash(self, output: str) -> str:
        if "AddressSanitizer" not in output:
            if "Segmentation fault" in output:
                return "segfault_no_asan"
            return "clean" if "exit_code=0" in output or not output.strip() else "timeout"

        if self.sink_function in output:
            return "target_sink"
        sink_base = self.sink_file.rsplit("/", 1)[-1] if self.sink_file else ""
        if sink_base and sink_base in output:
            return "same_file"
        if "/work/" in output and "/src/" not in output:
            return "harness_bug"
        if "/src/" in output:
            return "wrong_location"
        return "unknown_crash"

    def _run_harness(self, inp: str) -> str:
        r = self.env.exec(f"timeout 20 /work/harness {inp} 2>&1", timeout=30)
        return self._smart_truncate(f"/work/harness {inp}", r.exit_code, r.output or "")

    def _find_input_file(self) -> str:
        r = self.env.exec("ls /work/input.* /work/crash_input 2>/dev/null | head -1", timeout=5)
        if r.stdout.strip():
            return r.stdout.strip().split("\n")[0]
        # Copy first test file
        if self.so.test_files:
            self.env.exec(f"cp {self.so.test_files[0]} /work/input.dat 2>/dev/null", timeout=5)
        else:
            self.env.exec(
                f"cp $(find /src -type f -name '*{self.so.input_ext}' 2>/dev/null | head -1) /work/input.dat 2>/dev/null",
                timeout=10)
        return "/work/input.dat"

    def _sweep_inputs(self) -> str:
        files = self.so.test_files or []
        if not files:
            find = self.env.exec(
                f"find /src -type f \\( -name '*{self.so.input_ext}' -o -name '*.bin' \\) 2>/dev/null | head -50",
                timeout=15)
            files = [f.strip() for f in find.stdout.strip().split("\n") if f.strip()] if find.stdout.strip() else []
        for tf in files:
            r = self.env.exec(f"timeout 10 /work/harness {tf} 2>&1", timeout=15)
            crash = self._classify_crash(r.output or "")
            if crash in ("target_sink", "same_file"):
                self.env.exec(f"cp {tf} /work/crash_input", timeout=5)
                return "/work/crash_input"
        return ""

    # --- Linking ---
    def _resolve_linking(self) -> str:
        nm = self.env.exec(
            "nm /work/harness.o 2>/dev/null | grep ' U ' | "
            "grep -v '__asan\\|__cxa\\|__stack\\|_Unwind\\|__gxx\\|_GLOBAL\\|_Z.*std' | "
            "awk '{print $2}' | head -20", timeout=10)
        if not nm.stdout.strip():
            return "No undefined symbols."
        undefined = [s.strip() for s in nm.stdout.strip().split("\n") if s.strip()]
        parts = [f"Undefined: {', '.join(undefined[:8])}"]
        src_map: dict[str, list[str]] = {}
        for sym in undefined[:5]:
            dem = self.env.exec(f"echo '{sym}' | c++filt 2>/dev/null", timeout=5)
            func = (dem.stdout.strip() if dem.success else sym).split("(")[0].split("::")[-1].split("<")[0].strip()
            if len(func) < 3:
                continue
            grep = self.env.exec(
                f"grep -rn '{func}' /src/ --include='*.c' --include='*.cc' --include='*.cpp' -l 2>/dev/null | "
                f"grep -v '_test\\|_fuzzer' | head -5", timeout=15)
            if grep.stdout.strip():
                for f in grep.stdout.strip().split("\n"):
                    if f.strip():
                        src_map.setdefault(f.strip(), []).append(func)
        if not src_map:
            return "\n".join(parts + ["Could not find source files."])
        compiled = []
        flags = self.so.include_flags or "-I/src"
        for src, _ in sorted(src_map.items(), key=lambda x: -len(x[1]))[:5]:
            obj = f"/work/{src.replace('/', '_').replace('.c', '.o').replace('.cc', '.o').replace('.cpp', '.o')}"
            self.env.exec(f"g++ -fsanitize=address -g -std=c++20 {flags} -c {src} -o {obj} 2>&1", timeout=60)
            if self.env.exec(f"test -f {obj} && echo y", timeout=5).stdout.strip() == "y":
                compiled.append(obj)
                parts.append(f"  ✅ {src}")
            else:
                parts.append(f"  ❌ {src}")
        if compiled:
            all_o = " ".join(["/work/harness.o"] + compiled)
            self.env.exec(f"g++ -fsanitize=address -g {all_o} -o /work/harness -lpthread -ldl 2>&1", timeout=60)
            if self.env.exec("test -x /work/harness && echo y", timeout=5).stdout.strip() == "y":
                parts.append("✅ LINKED!")
        return "\n".join(parts)

    # --- Crafting (isolated LLM) ---
    def _craft_input(self) -> str:
        so = self.so
        vc = so.vuln_tags[0] if so.vuln_tags else "unknown"
        guide = {"buffer_overflow": "Set a length/size field very large, provide less data.",
                 "use_after_free": "Create circular refs or duplicate entries.",
                 "null_deref": "Remove required fields or set references to null.",
                 "integer_overflow": "Set numeric fields to 0xFFFFFFFF.",
                 "type_confusion": "Change type tags."}.get(vc, "Corrupt input to exercise the trace.")

        src_ctx = ""
        if so.sink_source:
            src_ctx = f"\nSINK CODE:\n{so.sink_source[:1000]}"

        sample = ""
        if so.test_files:
            sample = f"\nSample file: {so.test_files[0]} — read and mutate it."

        prompt = f"""Craft malformed {so.input_format} for {vc} at {so.sink_function}.
{so.vuln_summary}
TRACE:
{so.trace_text}{src_ctx}
STRATEGY: {guide}{sample}

Write /work/craft.py that creates /work/crafted_input{so.input_ext}.
<write_file path="/work/craft.py">
import struct
# Create /work/crafted_input{so.input_ext}
</write_file>
<shell>python3 /work/craft.py</shell>"""

        response = self._call_llm(
            self.llm_b,
            "Write a Python script to create a malformed input file. Output ONLY <write_file> and <shell>.",
            prompt)
        for a in parse_actions(response):
            if a.kind == "write_file":
                self.env.write_file(a.path, a.content)
            elif a.kind == "shell":
                self.env.exec(a.content, timeout=30)
        check = self.env.exec("ls /work/crafted_input* 2>/dev/null | head -1", timeout=5)
        return check.stdout.strip().split("\n")[0] if check.stdout.strip() else ""

    # --- Force-write harness ---
    def _force_write_harness(self):
        so = self.so
        includes = ['#include <stdio.h>', '#include <stdlib.h>', '#include <string.h>']
        if so.header_file:
            hdr_rel = so.header_file.replace("/src/", "")
            includes.append(f'#include "{hdr_rel}"')
        else:
            pub = self.env.exec("find /src -path '*/include/*.h' | head -3", timeout=5)
            for h in (pub.stdout.strip().split("\n") if pub.stdout.strip() else [])[:2]:
                includes.append(f'#include "{h.strip().replace("/src/", "")}"')

        entry = so.entry_function.split("|")[0].strip() if so.entry_function else so.sink_function
        code = "\n".join(includes) + f"""

int main(int argc, char* argv[]) {{
    if (argc < 2) {{ fprintf(stderr, "Usage: %s <file>\\n", argv[0]); return 1; }}
    FILE* f = fopen(argv[1], "rb");
    if (!f) {{ perror("fopen"); return 1; }}
    fseek(f, 0, SEEK_END); long len = ftell(f); fseek(f, 0, SEEK_SET);
    char* buf = (char*)malloc(len);
    fread(buf, 1, len, f);
    fclose(f);
    // Call entry function — this should reach {so.sink_function}
    // {entry}(buf, len) or {entry}(argv[1]) — adjust based on API
    free(buf);
    return 0;
}}
"""
        self.env.write_file("/work/harness.cpp", code)

    # --- Reviewer ---
    def _ask_reviewer(self, context: str) -> dict[str, str]:
        prompt = f"GOAL: Trigger {self.so.sink_function} at {self.so.sink_file}\n\n{context}\n\nVerdict: REDIRECT with specific fix, or say 'rewrite harness'."
        try:
            resp = self.llm_a(
                "You review exploit development progress. Give specific actionable advice.",
                prompt)
            return {"verdict": "REDIRECT", "message": resp[:500]}
        except Exception as e:
            return {"verdict": "CONTINUE", "message": str(e)}

    # --- Verification ---
    def _run_verification(self, binary: str, input_file: str) -> VerificationResult:
        return verify_harness(env=self.env, harness_binary=binary, input_file=input_file,
                              sink_function=self.sink_function, sink_file=self.sink_file,
                              library_name=self.profile.library_name, timeout=self.config.verify_timeout)

    # --- Output truncation ---
    @staticmethod
    def _smart_truncate(cmd: str, exit_code: int, raw: str, max_len: int = 4000) -> str:
        if not raw:
            return "(no output)"
        if len(raw) <= max_len:
            return raw
        if "AddressSanitizer" in raw:
            keep = []
            cap = False
            for line in raw.split("\n"):
                if "ERROR:" in line and "AddressSanitizer" in line:
                    cap = True
                if cap:
                    keep.append(line)
                    if line.strip() == "" and len(keep) > 5:
                        break
                if "SUMMARY:" in line:
                    keep.append(line)
            if keep:
                return "\n".join(keep)[:max_len]
            return raw[-max_len:]
        is_cc = any(k in cmd for k in ("g++", "gcc", "clang", "make"))
        if is_cc and exit_code != 0:
            blocks = []
            lines = raw.split("\n")
            for i, line in enumerate(lines):
                if "error:" in line.lower() or "undefined reference" in line.lower():
                    blocks.append("\n".join(lines[max(0, i-1):min(len(lines), i+4)]))
            if blocks:
                return "\n...\n".join(blocks)[:max_len]
            return raw[-max_len:]
        h = max_len // 2 - 30
        return raw[:h] + "\n... [TRUNCATED] ...\n" + raw[-h:]
