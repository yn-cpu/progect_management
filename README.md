
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
    BUILD = auto()  # NEW: LLM fixes library build (failed files, stubs, etc.)
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
    sink_source: str = ""  # actual code around the sink
    entry_source: str = ""  # actual code at entry point
    header_file: str = ""  # path to header declaring sink
    header_declarations: str = ""  # function signatures from header
    include_flags: str = ""  # -I flags derived from header path
    reference_harness: str = ""  # content of existing fuzzer/test
    test_files: list[str] = field(default_factory=list)
    input_format: str = "binary"  # PDF, CGATS/ICC, XML, PNG, etc.
    input_ext: str = ".bin"
    repo_layout: str = ""

    # Filled by stages
    compile_errors: list[str] = field(default_factory=list)
    link_errors: str = ""
    run_output: str = ""
    crash_type: str = ""  # target_sink, same_file, wrong_location, harness_bug, clean, timeout
    crash_file: str = ""  # input file that caused crash
    pipeline_attempts: int = 0
    backward_reasons: list[str] = field(default_factory=list)
    harness_locked: bool = False  # True after force-write — LLM must NOT overwrite harness

    # Pre-built library info (populated from /work/build_info.json)
    prebuild_success: bool = False
    prebuild_archive: str = ""  # Path to .a archive (pre-built)
    prebuild_objects: list[str] = field(default_factory=list)  # Pre-built .o files
    prebuild_compile_flags: str = ""  # Exact -I/-D flags from pre-build
    prebuild_sink_obj: str = ""  # .o file containing the sink
    library_root: str = ""

    # BUILD stage info
    prebuild_failed_detail: list[dict] = field(default_factory=list)  # [{source, error}]
    prebuild_undefined_symbols: list[str] = field(default_factory=list)
    prebuild_internal_headers: list[str] = field(default_factory=list)
    prebuild_verify_ok: bool = False  # True if entry_fn(NULL) works

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
        if self.library_root:
            status = "pre-built ✅" if self.prebuild_success else "not built"
            lines.append(f"LIBRARY: {self.library_root} ({status})")
            if self.prebuild_archive:
                lines.append(f"ARCHIVE: {self.prebuild_archive}")
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

    # Strip <think>...</think> blocks BEFORE parsing actions.
    # Models with reasoning traces (qwen3, deepseek, etc.) wrap their
    # chain-of-thought in <think> tags. These often contain example
    # tool calls like <shell>grep foo</shell> that should NOT be executed.
    cleaned = re.sub(r"<think>.*?</think>", "", response, flags=re.DOTALL)

    for m in re.finditer(r"<shell>(.*?)</shell>", cleaned, re.DOTALL):
        cmd = m.group(1).strip()
        if not cmd:
            continue
        if cmd.lower() in _PLACEHOLDERS:
            # Try to recover real command from the line after </shell>
            after = cleaned[m.end():m.end() + 300].strip().split("\n")[0].strip()
            if after and re.match(r'^[a-z/]', after) and len(after) > 3:
                actions.append(AgentAction(kind="shell", content=after))
                logger.warning("Recovered command after placeholder: %s", after[:80])
            continue
        actions.append(AgentAction(kind="shell", content=cmd))

    for m in re.finditer(r'<write_file\s+path="([^"]+)">(.*?)</write_file>', cleaned, re.DOTALL):
        actions.append(AgentAction(kind="write_file", path=m.group(1), content=m.group(2)))

    for m in re.finditer(r'<read_file\s+path="([^"]+)"\s*/?>', cleaned):
        actions.append(AgentAction(kind="read_file", path=m.group(1)))

    if actions:
        return actions

    # Bracket syntax fallback: [shell]...[/shell], [write_file path="..."]...[/write_file]
    # Some LLMs (qwen3, etc.) sometimes use bracket syntax instead of XML
    for m in re.finditer(r'\[shell\]\s*(.*?)\s*\[/shell\]', cleaned, re.DOTALL):
        cmd = m.group(1).strip()
        if cmd and cmd.lower() not in _PLACEHOLDERS:
            actions.append(AgentAction(kind="shell", content=cmd))
    for m in re.finditer(r'\[write_file\s+path="([^"]+)"\]?\s*(.*?)\s*\[/write_file\]', cleaned, re.DOTALL):
        actions.append(AgentAction(kind="write_file", path=m.group(1), content=m.group(2)))
    for m in re.finditer(r'\[read_file\s+path="([^"]+)"\s*/?]', cleaned):
        actions.append(AgentAction(kind="read_file", path=m.group(1)))

    # Also try: [shell] $ command\nexit_code=... format (LLM echoing previous output)
    for m in re.finditer(r'\[shell\]\s*\$?\s*(.+?)(?:\n|$)', cleaned):
        cmd = m.group(1).strip()
        if cmd and not cmd.startswith("exit_code") and cmd.lower() not in _PLACEHOLDERS:
            if not any(a.content == cmd for a in actions):
                actions.append(AgentAction(kind="shell", content=cmd))

    if actions:
        return actions

    # Markdown fallback (also on cleaned text)
    for m in re.finditer(r"```(?:bash|sh|shell)\s*\n([\s\S]*?)\n\s*```", cleaned):
        for line in m.group(1).strip().split("\n"):
            s = line.strip()
            if s and not s.startswith("#"):
                actions.append(AgentAction(kind="shell", content=s))

    for m in re.finditer(r"```(?:cpp|c\+\+|c)\s*\n([\s\S]*?)\n\s*```", cleaned):
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
    max_pipeline_attempts: int = 5


@dataclass
class AgentResult:
    success: bool = False
    verification: VerificationResult | None = None
    turns_used: int = 0
    total_actions: int = 0
    elapsed_seconds: float = 0.0
    harness_path: str = ""  # path to compiled binary in container
    harness_source_path: str = ""  # path to .cpp source in container
    input_path: str = ""  # path to crash input in container
    input_files: list[str] = field(default_factory=list)  # all relevant input files
    final_reason: str = ""
    vulnerability_report: str = ""  # markdown report
    run_poc_script: str = ""  # shell script to reproduce
    postmortem: dict[str, Any] = field(default_factory=dict)
    log: list[dict[str, Any]] = field(default_factory=list)


# =====================================================================
# Agent
# =====================================================================

class ExploitAgent:

    def __init__(self, llm_caller, env, profile, trace_path, sink_function, sink_file,
                 config=None, progress_callback=None, llm_coder=None):
        self.llm_a = llm_caller  # explorer / reviewer
        self.llm_b = llm_coder if llm_coder else llm_caller  # coder / crafter
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
        self.so = StateObject()  # the state object — agent's only memory
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
            # If prebuild had failures and verify didn't pass, route to BUILD first
            if self.so.prebuild_failed_detail and not self.so.prebuild_verify_ok:
                self.stage = Stage.BUILD
                logger.info("UNDERSTAND found sink + header, but library has %d failed files → BUILD",
                            len(self.so.prebuild_failed_detail))
            else:
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
                self._progress(f"Turn {self._turn + 1} [{self.stage.name}]", self._turn)

            turn_log = {"event": "turn", "turn": self._turn + 1, "stage": self.stage.name,
                        "timestamp": time.time()}

            if self.stage == Stage.EXPLORE:
                self._run_explore_turn(result, turn_log)
            elif self.stage == Stage.BUILD:
                self._run_build_turn(result, turn_log)
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
            tag = " [ENTRY]" if i == 0 else (" [SINK]" if i == len(self.trace.steps) - 1 else "")
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
            r = self.env.exec(
                f"sed -n '{max(1, sink_loc.line - 15)},{sink_loc.line + 15}p' /src/{sink_loc.file} 2>/dev/null",
                timeout=5)
            so.sink_source = r.stdout.strip()[:2000] if r.stdout.strip() else ""

        # (2) Read entry source
        entry_loc = self.trace.steps[0].location if self.trace.steps else None
        if entry_loc and entry_loc.file:
            r = self.env.exec(
                f"sed -n '{max(1, entry_loc.line - 10)},{entry_loc.line + 10}p' /src/{entry_loc.file} 2>/dev/null",
                timeout=5)
            so.entry_source = r.stdout.strip()[:1500] if r.stdout.strip() else ""

        # (3) Find header declaring sink function
        # Problem: sink_function might be a variable name like "Buffer" which matches
        # everywhere. We need to search smartly.
        GENERIC_NAMES = {"buffer", "buf", "data", "ptr", "len", "size", "result", "ret",
                         "val", "value", "str", "msg", "err", "tmp", "ctx", "handle",
                         "status", "count", "index", "offset", "flag", "type", "name",
                         # Calling convention macros — not function names
                         "cmsexport", "cmsapi", "winapi", "stdcall", "cdecl",
                         "dllexport", "dllimport", "export", "import",
                         "extern", "static", "inline", "void", "const",
                         # Common type names
                         "bool", "int", "char", "float", "double", "long",
                         "uint32", "int32", "uint64", "int64"}

        # Build a list of search terms, from most specific to least
        search_terms = []
        # 1. Try actual function names from trace steps (most specific)
        #    node_name can be pipe-delimited: "CMSEXPORT | Val | cProp | cmsIT8SetPropertyDbl | hIT8"
        for step in self.trace.steps:
            if not step.node_name or len(step.node_name) < 4:
                continue
            # Split on | and check ALL parts
            for part in step.node_name.split("|"):
                fname = part.strip()
                if (fname and len(fname) > 3
                        and fname.lower() not in GENERIC_NAMES
                        and not fname.startswith("<")
                        and not fname.isupper()  # skip ALL_CAPS macros like CMSEXPORT
                        and ("_" in fname or len(fname) > 8)):  # prefer cmsIT8SetPropertyDbl over Val
                    search_terms.append(fname)
        # 2. Try sink_function if it's not generic
        if self.sink_function.lower() not in GENERIC_NAMES and len(self.sink_function) > 3:
            search_terms.insert(0, self.sink_function)
        # 3. Deduplicate
        search_terms = list(dict.fromkeys(search_terms))[:5]

        # Search for each term, prefer headers near the sink file
        sink_dir = self.sink_file.rsplit("/", 1)[0] if "/" in self.sink_file else ""
        for term in search_terms:
            hdr_r = self.env.exec(
                f"grep -rn '{term}' /src/ --include='*.h' -l 2>/dev/null | head -10",
                timeout=10,
            )
            if not hdr_r.stdout.strip():
                continue
            candidates = [h.strip() for h in hdr_r.stdout.strip().split("\n") if h.strip()]
            # Prefer header in same directory tree as sink
            best = candidates[0]
            for c in candidates:
                if sink_dir and sink_dir.split("/")[0] in c:
                    best = c
                    break
                # Also prefer headers in include/ directories
                if "/include/" in c:
                    best = c
                    break

            so.header_file = best
            logger.info("Found header via '%s': %s", term, best)
            break

        # If no header found via function names, try finding headers near the sink file
        if not so.header_file and sink_dir:
            # Look for headers in the same directory tree
            near_r = self.env.exec(
                f"find /src/{sink_dir}/.. -name '*.h' -path '*/include/*' 2>/dev/null | head -5",
                timeout=10,
            )
            if near_r.stdout.strip():
                so.header_file = near_r.stdout.strip().split("\n")[0].strip()
                logger.info("Found header near sink: %s", so.header_file)

        # Derive include flags from header
        if so.header_file:
            hdr_dir = so.header_file.rsplit("/", 1)[0] if "/" in so.header_file else ""
            if hdr_dir:
                so.include_flags = f"-I{hdr_dir}"
                parent = hdr_dir.rsplit("/", 1)[0] if "/" in hdr_dir else ""
                if parent and parent != "/src":
                    so.include_flags = f"-I{hdr_dir} -I{parent}"
            # Read declaration — use the BEST search term, not sink_function
            search_for = search_terms[0] if search_terms else self.sink_function
            decl = self.env.exec(f"grep -n '{search_for}' {so.header_file} 2>/dev/null | head -3", timeout=5)
            if decl.stdout.strip():
                try:
                    ln = int(decl.stdout.strip().split(":")[0])
                    hdr_src = self.env.exec(f"sed -n '{max(1, ln - 5)},{ln + 10}p' {so.header_file} 2>/dev/null",
                                            timeout=5)
                    so.header_declarations = hdr_src.stdout.strip()[:1000] if hdr_src.stdout.strip() else ""
                except ValueError:
                    pass

        # (4) Find existing fuzzer/test
        fuzz = self.env.exec(
            "find /src -name '*fuzz*' \\( -name '*.c' -o -name '*.cc' -o -name '*.cpp' \\) 2>/dev/null | head -5",
            timeout=10)
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

        # Always ensure -I/src is present — many repos use source-root-relative includes
        if "-I/src" not in so.include_flags:
            so.include_flags = f"-I/src {so.include_flags}".strip()

        # (7) Read pre-build results from /work/build_info.json
        build_info_r = self.env.exec("cat /work/build_info.json 2>/dev/null", timeout=5)
        if build_info_r.success and build_info_r.stdout.strip():
            import json
            try:
                info = json.loads(build_info_r.stdout.strip())
                so.prebuild_success = info.get("success", False)
                so.prebuild_archive = info.get("archive", "")
                so.prebuild_objects = info.get("objects", [])
                so.prebuild_compile_flags = info.get("compile_flags", "")
                so.prebuild_sink_obj = info.get("sink_obj", "")
                so.library_root = info.get("library_root", "")
                so.prebuild_failed_detail = info.get("failed_detail", [])
                so.prebuild_undefined_symbols = info.get("undefined_symbols", [])
                so.prebuild_internal_headers = info.get("internal_headers", [])
                so.prebuild_verify_ok = info.get("verify_ok", False)

                # Use pre-build compile flags (they're more accurate than discovered ones)
                if so.prebuild_compile_flags:
                    so.include_flags = so.prebuild_compile_flags
                    # Ensure -I/src is still present
                    if "-I/src" not in so.include_flags:
                        so.include_flags = f"-I/src {so.include_flags}"

                if so.prebuild_success:
                    logger.info("UNDERSTAND: pre-built library OK (%d objects, archive=%s)",
                                len(so.prebuild_objects), so.prebuild_archive)
                else:
                    logger.warning("UNDERSTAND: pre-build failed, agent must compile interactively")
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning("UNDERSTAND: failed to parse build_info.json: %s", e)
        else:
            logger.info("UNDERSTAND: no build_info.json — library not pre-built")

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
            missing.append(
                f"Find the header file that declares {so.sink_function}. Use: grep -rn '{so.sink_function}' /src/ --include='*.h' -l")
        if not so.reference_harness:
            missing.append(
                "Find any test/fuzzer that calls functions from this library. Use: find /src -name '*fuzz*' -o -name '*test*'")
        if not so.test_files:
            missing.append(f"Find sample input files ({so.input_ext}). Use: find /src -type f -name '*{so.input_ext}'")

        if not missing:
            # Nothing to explore — gate passes
            self.stage = Stage.WRITE
            self._exchanges.clear()
            turn_log["gate"] = "EXPLORE complete — all fields filled"
            return

        prompt = f"""STATE:\n{so.summary()}\n\nMISSING INFORMATION:\n""" + "\n".join(
            f"  {i + 1}. {m}" for i, m in enumerate(missing))
        prompt += "\n\nFind these items. Use <shell> to search."

        response = self._call_llm(self.llm_a, "You are exploring a C/C++ repo. Source at /src/.\n" + _TOOLS_BLOCK,
                                  prompt)
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
    # STAGE 1.5: BUILD (LLM fixes library build — failed files, stubs)
    # =================================================================

    _build_turns = 0
    _MAX_BUILD_TURNS = 5

    def _run_build_turn(self, result: AgentResult, turn_log: dict):
        """LLM-driven library build fix.

        The prebuild compiled N-1 files but some failed (e.g., cmserr.c needs
        external headers). The LLM reads the errors, internal headers, and
        undefined symbols, then writes replacement stubs or patches.

        Gate: /work/build/verify binary exits 0, or max turns reached.
        """
        self._build_turns += 1
        so = self.so

        # Quick check: did a previous turn already fix it?
        verify_r = self.env.exec(
            "test -x /work/build/verify && ASAN_OPTIONS=detect_leaks=0 /work/build/verify 2>&1", timeout=10)
        if verify_r.exit_code == 0 and "OK:" in (verify_r.output or ""):
            logger.info("BUILD: verify passes — library is working")
            so.prebuild_verify_ok = True
            self._exchanges.clear()
            if self.env.exec("test -f /work/harness.o && echo y", timeout=3).stdout.strip() == "y":
                logger.info("BUILD: harness.o exists — resuming at LINK")
                self.env.exec("rm -f /work/harness", timeout=3)
                self.stage = Stage.LINK
            else:
                self.stage = Stage.WRITE
            turn_log["gate"] = f"BUILD PASS — {self.stage.name}"
            return

        # Max turns → proceed to WRITE anyway (force_write may still work)
        if self._build_turns > self._MAX_BUILD_TURNS:
            logger.warning("BUILD: %d turns exhausted — proceeding to WRITE", self._build_turns - 1)
            self.stage = Stage.WRITE
            self._exchanges.clear()
            turn_log["gate"] = "BUILD timeout — proceeding"
            return

        # Ensure verify test exists (prebuild may not have created it)
        archive = so.prebuild_archive or "/work/build/libtarget.a"
        flags = so.prebuild_compile_flags or so.include_flags or "-I/src"
        if self.env.exec("test -f /work/build/verify.o && echo y", timeout=3).stdout.strip() != "y":
            # NOTE: verify.c is no longer hardcoded — the LLM will write it below
            # as part of the task_desc prompt. Skip pre-creating it here.
            pass

        # Try linking and running verify to get crash trace for the LLM
        verify_crash_trace = ""
        link_r = self.env.exec(
            f"gcc -fsanitize=address -g /work/build/verify.o {archive} "
            f"-o /work/build/verify -Wl,--unresolved-symbols=ignore-in-object-files "
            f"-lm -lpthread 2>&1", timeout=30)
        if self.env.exec("test -x /work/build/verify && echo y", timeout=3).stdout.strip() == "y":
            vrun = self.env.exec("ASAN_OPTIONS=detect_leaks=0 /work/build/verify 2>&1", timeout=10)
            if vrun.exit_code != 0:
                verify_crash_trace = (vrun.output or "")[:1500]

        # Pre-read key files so the LLM doesn't waste turns on read_file
        # This is the #1 reason BUILD was failing: LLM spent 5+ turns just reading
        internal_hdr_content = ""
        crashing_src_content = ""
        crashing_file = ""

        if so.prebuild_internal_headers:
            hdr_path = so.prebuild_internal_headers[0]
            # TRUTH: C syntax spans multiple lines. Grep breaks it.
            # Grab the first 400 lines to give the LLM intact struct definitions and typedefs.
            r = self.env.exec(f"head -n 400 {hdr_path} 2>/dev/null", timeout=5)
            if r.stdout.strip():
                # Strip out long comment blocks to save context window, keep the code
                cleaned_hdr = re.sub(r'/\*.*?\*/', '', r.stdout.strip(), flags=re.DOTALL)
                internal_hdr_content = cleaned_hdr[:3000]

        # Identify the crashing file from trace
        crash_trace = verify_crash_trace or so.run_output or ""
        crash_file_match = re.search(r'in \w+ (/src/[^:]+):(\d+)', crash_trace)
        if crash_file_match:
            crashing_file = crash_file_match.group(1)
            crash_line = int(crash_file_match.group(2))
            r = self.env.exec(
                f"sed -n '{max(1, crash_line - 10)},{crash_line + 10}p' {crashing_file} 2>/dev/null",
                timeout=5)
            if r.stdout.strip():
                crashing_src_content = r.stdout.strip()[:1500]

        # List what's in the archive (so LLM knows which .o to replace)
        ar_contents = ""
        ar_r = self.env.exec(f"ar t {archive} 2>/dev/null | head -30", timeout=5)
        if ar_r.stdout.strip():
            ar_contents = ar_r.stdout.strip()

        # Build the prompt with all diagnostics
        sections = [f"TASK: Fix the library build so the entry function works.\n\n{so.summary()}"]

        # Failed files and their errors (compile-time failures)
        if so.prebuild_failed_detail:
            sections.append("\n=== FAILED SOURCE FILES (compile errors) ===")
            for fd in so.prebuild_failed_detail[:5]:
                sections.append(f"  {fd.get('source', '?')}: {fd.get('error', 'unknown')[:200]}")
        elif not so.prebuild_verify_ok:
            # All files compiled but library crashes at runtime — explain clearly
            sections.append("\n=== PROBLEM: RUNTIME CRASH (not compile error) ===")
            sections.append("All source files compiled successfully, but the library crashes at runtime.")
            sections.append("This usually means one of the compiled files has functions that go through")
            sections.append("NULL pointers at runtime (e.g., memory allocator functions that dereference")
            sections.append("a NULL context parameter).")
            sections.append("You need to REPLACE the crashing object file in the archive with stubs")
            sections.append("that use direct stdlib calls (malloc/calloc/free) instead.")

        # Undefined symbols
        if so.prebuild_undefined_symbols:
            syms = ", ".join(so.prebuild_undefined_symbols[:20])
            sections.append(f"\n=== UNDEFINED SYMBOLS IN ARCHIVE ===\n{syms}")

        # Internal headers (useful for writing type-correct stubs)
        if so.prebuild_internal_headers:
            sections.append(f"\n=== INTERNAL HEADERS (for correct types) ===")
            for h in so.prebuild_internal_headers[:3]:
                sections.append(f"  {h}")

        # Current crash trace — from verify OR from the harness run that triggered BUILD
        if verify_crash_trace:
            sections.append(f"\n=== CRASH TRACE ===\n{verify_crash_trace}")
        elif so.run_output and "AddressSanitizer" in so.run_output:
            # Use the crash trace from the harness run that sent us here
            asan_lines = []
            for line in so.run_output.split("\n"):
                if line.strip().startswith("#") or "ERROR:" in line or "SUMMARY:" in line:
                    asan_lines.append(line.strip())
            if asan_lines:
                sections.append(f"\n=== CRASH TRACE (from harness run) ===\n" + "\n".join(asan_lines[:20]))

        # PRE-READ content — saves the LLM from wasting turns on read_file
        if internal_hdr_content:
            sections.append(
                f"\n=== KEY TYPES FROM INTERNAL HEADER ({so.prebuild_internal_headers[0]}) ===\n{internal_hdr_content}")
        if crashing_src_content and crashing_file:
            sections.append(f"\n=== CRASHING SOURCE ({crashing_file}) ===\n{crashing_src_content}")
        if ar_contents:
            sections.append(f"\n=== ARCHIVE CONTENTS ({archive}) ===\n{ar_contents}")

        # Build environment info
        sections.append(f"\n=== BUILD ENVIRONMENT ===")
        sections.append(f"Archive: {archive}")
        sections.append(f"CFLAGS: {flags}")
        sections.append(f"Compiled: {len(so.prebuild_objects)} objects OK")

        # Show last exchange results
        for _, res in self._exchanges[-2:]:
            sections.append(f"\n--- Previous result ---\n{res[:1500]}")

        # Determine the entry function name for dynamic verify.c generation
        entry_fn = so.entry_function or "the main initialization function"
        # Clean up pipe-delimited entry names: take the longest meaningful part
        if "|" in entry_fn:
            parts = [p.strip() for p in entry_fn.split("|") if len(p.strip()) > 3]
            parts.sort(key=len, reverse=True)
            entry_fn = parts[0] if parts else entry_fn

        if so.prebuild_failed_detail:
            task_desc = f"""
=== YOUR TASK ===
The library has {len(so.prebuild_failed_detail)} file(s) that failed to compile.
The key types and archive contents are shown above — DO NOT waste a turn reading them again.

Write TWO files NOW:
1. <write_file path="/work/build/stubs.c">
   #include "{so.prebuild_internal_headers[0] if so.prebuild_internal_headers else '/src/path/to/internal.h'}"
   // Implement missing memory/allocator functions using direct stdlib (malloc/free/calloc).
   </write_file>

2. <write_file path="/work/build/verify.c">
   // Write a minimal C program to test if the library links and initializes without crashing.
   // You MUST call: {entry_fn}
   // Pass NULL, 0, or dummy pointers to satisfy the arguments.
   // Print "OK:" to stderr on success.
   int main() {{
       // Call {entry_fn} here
       return 0;
   }}
   </write_file>

3. <shell>gcc -fsanitize=address -g {flags} -c /work/build/stubs.c -o /work/build/stubs.o 2>&1</shell>
4. <shell>ar rcs {archive} /work/build/stubs.o</shell>
5. <shell>gcc -fsanitize=address -g /work/build/verify.c {archive} -o /work/build/verify -lm -lpthread 2>&1</shell>
6. <shell>ASAN_OPTIONS=detect_leaks=0 /work/build/verify 2>&1</shell>
"""
        else:
            # Runtime crash — all files compiled but library crashes
            # Identify the crashing .o name for the LLM
            crash_obj = ""
            if crashing_file:
                obj_base = crashing_file.split("/")[-1].replace(".c", "")
                if ar_contents:
                    for line in ar_contents.split("\n"):
                        if obj_base in line:
                            crash_obj = line.strip()
                            break

            task_desc = f"""
=== YOUR TASK ===
All files compiled but the library CRASHES AT RUNTIME. The crash trace, internal header
types, crashing source code, and archive contents are ALL shown above.
DO NOT use <read_file> to re-read them — that wastes turns.

{"The crashing .o file is: " + crash_obj if crash_obj else "Find the crashing .o in ARCHIVE CONTENTS above."}

Write TWO files — stubs AND a verification test — then replace the crashing .o NOW:
1. <write_file path="/work/build/stubs.c">
   #include "{so.prebuild_internal_headers[0] if so.prebuild_internal_headers else '/src/path/to/internal.h'}"
   #include <stdarg.h>
   // Replace ALL memory/allocator functions with direct stdlib calls.
   // Check the KEY TYPES section for correct signatures.
   </write_file>

2. <write_file path="/work/build/verify.c">
   // Write a minimal C program to test if the library links and initializes without crashing.
   // You MUST call: {entry_fn}
   // Pass NULL, 0, or dummy pointers to satisfy the arguments.
   // Print "OK:" to stderr on success.
   int main() {{
       // Call {entry_fn} here
       return 0;
   }}
   </write_file>

3. <shell>gcc -fsanitize=address -g {flags} -c /work/build/stubs.c -o /work/build/stubs.o 2>&1</shell>
4. <shell>ar d {archive} {crash_obj or 'THE_CRASHING.o'}</shell>
5. <shell>ar rcs {archive} /work/build/stubs.o</shell>
6. <shell>gcc -fsanitize=address -g -c /work/build/verify.c -o /work/build/verify.o 2>&1</shell>
7. <shell>gcc -fsanitize=address -g /work/build/verify.o {archive} -o /work/build/verify -lm -lpthread 2>&1</shell>
8. <shell>ASAN_OPTIONS=detect_leaks=0 /work/build/verify 2>&1</shell>

RULES:
- Do NOT use <read_file> — all info is above
- Write the COMPLETE stubs.c file in ONE <write_file> block
- Include the internal header for correct types
- Use stdlib (malloc/calloc/free) for memory functions
"""

        sections.append(task_desc)

        prompt = "\n".join(sections)
        response = self._call_llm(self.llm_b,
                                  "You are fixing a C library that crashes at runtime. All context is in the prompt.\n"
                                  "DO NOT read files — the key types, crash trace, and archive contents are already shown.\n"
                                  "Write stubs.c AND verify.c immediately, compile, replace the crashing .o, and test.\n" + _TOOLS_BLOCK,
                                  prompt)
        turn_log["llm_response"] = response[:4000]

        actions = parse_actions(response)
        if not actions:
            turn_log["no_actions"] = True
            return

        results = self._exec_actions(actions[:self.config.max_actions_per_turn], result)
        self._exchanges.append((response[:1500], results[:1500]))
        self._exchanges = self._exchanges[-2:]
        turn_log["actions_count"] = len(actions)

        # Auto-compile any stubs.c the LLM wrote and update the archive.
        # The LLM often writes stubs.c but forgets to run gcc/ar commands.
        stubs_src = self.env.exec("ls /work/build/stubs.c 2>/dev/null", timeout=3).stdout.strip()
        if stubs_src:
            logger.info("BUILD: auto-compiling stubs.c")
            comp = self.env.exec(
                f"gcc -fsanitize=address -g {flags} -c /work/build/stubs.c "
                f"-o /work/build/stubs.o 2>&1", timeout=30)
            if self.env.exec("test -f /work/build/stubs.o && echo y", timeout=3).stdout.strip() == "y":
                # Find and remove the crashing .o (if we know it from the trace)
                if crashing_file:
                    obj_base = crashing_file.split("/")[-1].replace(".c", "")
                    ar_list = self.env.exec(f"ar t {archive} 2>/dev/null", timeout=5)
                    for obj_name in (ar_list.stdout or "").strip().split("\n"):
                        if obj_base in obj_name:
                            self.env.exec(f"ar d {archive} {obj_name} 2>/dev/null", timeout=5)
                            logger.info("BUILD: removed %s from archive", obj_name)
                            break
                # Also remove any previous stubs.o
                self.env.exec(f"ar d {archive} stubs.o 2>/dev/null", timeout=5)
                self.env.exec(f"ar rcs {archive} /work/build/stubs.o 2>&1", timeout=10)
                logger.info("BUILD: added stubs.o to archive")
            else:
                err_msg = (comp.output or "")[:2000]
                logger.warning("BUILD: stubs.c compile failed: %s", err_msg[:200])

                # Feed error back to LLM instead of brittle auto-fix
                self._exchanges.append(("(system)",
                                        f"⚠️ YOUR stubs.c FAILED TO COMPILE:\n{err_msg[:400]}\n\n"
                                        f"Fix the errors. Use the EXACT types from the internal header."))

        # Auto-compile verify.c if the LLM wrote one
        verify_src = self.env.exec("test -f /work/build/verify.c && echo y", timeout=3).stdout.strip()
        if verify_src == "y":
            self.env.exec(
                f"gcc -fsanitize=address -g {flags} -c /work/build/verify.c "
                f"-o /work/build/verify.o 2>/dev/null", timeout=15)

        # Try to rebuild verify binary and test
        if self.env.exec("test -f /work/build/verify.o && echo y", timeout=3).stdout.strip() == "y":
            relink = self.env.exec(
                f"gcc -fsanitize=address -g /work/build/verify.o {archive} "
                f"-o /work/build/verify -lm -lpthread 2>&1",
                timeout=30)
            if self.env.exec("test -x /work/build/verify && echo y", timeout=3).stdout.strip() != "y":
                # Retry with unresolved symbols allowed
                relink = self.env.exec(
                    f"gcc -fsanitize=address -g /work/build/verify.o {archive} "
                    f"-o /work/build/verify -Wl,--unresolved-symbols=ignore-in-object-files "
                    f"-lm -lpthread 2>&1",
                    timeout=30)
            if self.env.exec("test -x /work/build/verify && echo y", timeout=3).stdout.strip() == "y":
                vr = self.env.exec("ASAN_OPTIONS=detect_leaks=0 /work/build/verify 2>&1", timeout=10)
                if vr.exit_code == 0 and "OK:" in (vr.output or ""):
                    logger.info("BUILD: verify passes after LLM fix!")
                    so.prebuild_verify_ok = True
                    self._exchanges.clear()
                    # If harness.o already exists (force-written), go straight to LINK
                    if self.env.exec("test -f /work/harness.o && echo y", timeout=3).stdout.strip() == "y":
                        logger.info("BUILD: harness.o exists — resuming at LINK")
                        self.env.exec("rm -f /work/harness", timeout=3)  # force re-link
                        self.stage = Stage.LINK
                    else:
                        self.stage = Stage.WRITE
                    turn_log["gate"] = f"BUILD PASS → {self.stage.name}"
                    return

        turn_log["gate"] = f"BUILD: verify still failing (turn {self._build_turns})"

    # =================================================================
    # STAGE 2: WRITE (LLM writes harness)
    # =================================================================

    _write_attempts = 0

    def _run_write_turn(self, result: AgentResult, turn_log: dict):
        so = self.so
        self._write_attempts += 1
        so.harness_locked = False  # LLM is writing a new harness — unlock

        # Compute the exact #include line for the LLM
        include_line = ""
        if so.header_file:
            hdr_basename = so.header_file.split("/")[-1]
            # Sort -I flags by path length (longest/most-specific first)
            # e.g., -I/src/third_party/lcms/include before -I/src
            # so we get #include "lcms2.h" not #include "third_party/lcms/include/lcms2.h"
            flags = [f for f in so.include_flags.split() if f.startswith("-I")]
            flags.sort(key=lambda f: -len(f))
            for flag in flags:
                idir = flag[2:]
                if so.header_file.startswith(idir + "/"):
                    rel = so.header_file[len(idir) + 1:]
                    include_line = f'#include "{rel}"'
                    break
            if not include_line:
                include_line = f'#include "{hdr_basename}"'

        sections = [f"TASK: Write /work/harness.cpp\n\n{so.summary()}"]

        if include_line:
            sections.append(f"\n⚠️ CRITICAL: Use EXACTLY this include line: {include_line}")
            sections.append(
                f"Compile with: g++ -fsanitize=address -g -std=c++17 {so.include_flags} /work/harness.cpp -c -o /work/harness.o")

        if so.sink_source:
            sections.append(f"\n=== SINK SOURCE ({so.sink_file}) ===\n{so.sink_source}")
        if so.entry_source:
            sections.append(f"\n=== ENTRY POINT ({so.entry_file}) ===\n{so.entry_source}")
        if so.header_declarations:
            sections.append(f"\n=== API HEADER ({so.header_file}) ===\n{so.header_declarations}")

        # If we're coming back from compile failures, show broader API signatures
        if so.backward_reasons and any("compile" in r.lower() or "api" in r.lower() for r in so.backward_reasons[-3:]):
            if so.header_file:
                # Show functions from the header related to the entry/sink
                broad_api = self.env.exec(
                    f"grep -n 'EXPORT\\|extern.*(' {so.header_file} 2>/dev/null | head -20", timeout=5)
                if broad_api.stdout.strip():
                    sections.append(
                        f"\n=== FULL API (from {so.header_file}) ===\n{broad_api.stdout.strip()[:1500]}")
                    sections.append(
                        "⚠️ NOTE: Check the function signatures carefully — parameter types may differ from what you expect.")

        if so.reference_harness:
            sections.append(f"\n=== REFERENCE FUZZER ===\n{so.reference_harness}")
        sections.append(f"\nTRACE:\n{so.trace_text}")

        if so.backward_reasons:
            sections.append(f"\n=== PREVIOUS FAILURES ===")
            for r in so.backward_reasons[-3:]:
                sections.append(f"  - {r}")

        for _, res in self._exchanges[-2:]:
            sections.append(f"\n--- Previous result ---\n{res[:1000]}")

        sections.append(f"""
REQUIREMENTS:
1. Use EXACTLY: {include_line or '#include the header from the API HEADER section above'}
2. Do NOT include internal source files — use the PUBLIC header
3. CRITICAL: Do NOT define fake structs or mock handles. You MUST use the library's actual initialization API to create valid objects. Look at the REFERENCE FUZZER for how to properly initialize handles.
4. Read input from argv[1] as a file
5. Call {so.entry_function or so.sink_function} to process the input
6. The execution path must reach {so.sink_function}

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

        # Reject mock/stub implementations
        content_lower = content.lower()
        mock_indicators = ["mock", "stub", "fake", "// mock implementation",
                           "// stub", "// fake implementation"]
        if any(m in content_lower for m in mock_indicators):
            return "FAIL: contains mock/stub implementations — use REAL library functions"

        # Reject if harness re-declares library functions (common LLM cheat)
        sink = self.so.sink_function
        if sink and content.count(sink) >= 2:
            # Check if it's declaring the function, not just calling it
            for line in content.split("\n"):
                stripped = line.strip()
                if sink in stripped and (stripped.startswith("static") or
                                         (stripped.endswith("{") and "=" not in stripped)):
                    return f"FAIL: harness re-implements {sink} — call the REAL library function"

        # Check if it references any function from the trace
        # node_name can be pipe-delimited: "CMSEXPORT | Val | cProp | cmsIT8SetPropertyDbl"
        trace_funcs = []
        for s in self.trace.steps:
            if s.node_name:
                for part in s.node_name.split("|"):
                    p = part.strip()
                    if p and len(p) > 3:
                        trace_funcs.append(p)
        has_trace_func = any(f in content for f in trace_funcs if f)
        # Also extract all parts from entry_function
        entry_parts = [p.strip() for p in self.so.entry_function.split("|") if
                       len(p.strip()) > 3] if self.so.entry_function else []
        entry = entry_parts[0] if entry_parts else ""
        if not has_trace_func and sink not in content and not any(e in content for e in entry_parts):
            return f"FAIL: harness doesn't call {sink} or {entry}"

        return "PASS"

    # =================================================================
    # STAGE 3: COMPILE (LLM fixes errors, system validates .o)
    # =================================================================

    _compile_attempts = 0

    def _run_compile_turn(self, result: AgentResult, turn_log: dict):
        so = self.so
        self._compile_attempts += 1

        # Try compiling up to 3 times in this single turn (auto-fix loop for missing headers)
        for retry in range(3):
            flags = so.include_flags or "-I/src"
            cmd = f"g++ -fsanitize=address -g -std=c++17 {flags} /work/harness.cpp -c -o /work/harness.o 2>&1"
            r = self.env.exec(cmd, timeout=120)
            output = self._smart_truncate(cmd, r.exit_code, r.output or "")

            # Gate: does .o exist?
            if self.env.exec("test -f /work/harness.o && echo y", timeout=5).stdout.strip() == "y":
                turn_log["gate"] = f"COMPILE PASS (retry {retry})"
                # Remove old binary so LINK doesn't skip re-linking
                self.env.exec("rm -f /work/harness", timeout=3)
                self.stage = Stage.LINK
                self._exchanges.clear()
                return

            turn_log[f"compile_output_{retry}"] = output[:1000]
            so.compile_errors.append(output[:500])

            # Auto-fix: missing header → find and add -I flag (no LLM needed)
            fixed = False
            if "No such file or directory" in output and ".h" in output:
                same_count = sum(1 for e in so.compile_errors[-3:] if e == so.compile_errors[-1])
                if same_count <= 1:
                    fixed = self._auto_fix_include(output, turn_log)

            if not fixed:
                break  # can't auto-fix include → fall through to LLM

        # If we get here, the harness failed to compile and requires LLM intervention

        # Too many total attempts → ask reviewer
        if self._compile_attempts >= self.config.max_compile_attempts:
            review = self._ask_reviewer(
                f"Compilation failed {self._compile_attempts}x.\nLast error:\n{output[:500]}")
            turn_log["review"] = review
            if "rewrite" in review.get("message", "").lower():
                so.backward_reasons.append(f"compile failed {self._compile_attempts}x: {output[:100]}")
                self.stage = Stage.WRITE
                self._write_attempts = 0
                self._compile_attempts = 0
                self._exchanges.clear()
                return
            self._exchanges = [
                ("(system)", f"Compile error:\n{output[:800]}\n\nReviewer says: {review.get('message', '')}")]
            return

        # ==========================================
        # THE HARD RESET PROTOCOL
        # ==========================================
        # Detect repeated identical LLM output (LLM stuck in a hallucination loop)
        if len(so.compile_errors) >= 3:
            last_3 = so.compile_errors[-3:]
            if last_3[0] == last_3[1] == last_3[2]:
                repeat_count = sum(1 for r in so.backward_reasons if "compile stuck" in r)
                logger.warning("Same compile error 3x in a row (cycle %d) — Forcing Hard Reset", repeat_count + 1)
                so.backward_reasons.append(f"compile stuck: same error 3x: {last_3[0][:100]}")

                # Clean up pipe-delimited entry names for the prompt
                entry_fn = so.entry_function or so.sink_function
                if "|" in entry_fn:
                    parts = [p.strip() for p in entry_fn.split("|") if len(p.strip()) > 3]
                    parts.sort(key=len, reverse=True)
                    entry_fn = parts[0] if parts else entry_fn

                # Wipe the context and force a new approach
                self._exchanges = [("(system)",
                                    f"⚠️ You are stuck in a compilation loop hallucinating functions or types that do not exist.\n"
                                    f"The target entry point from the trace you MUST use is: {entry_fn}\n"
                                    f"Stop guessing initialization functions. Use <shell>grep</shell> to find the correct setup and free functions in the header.\n"
                                    f"Write a completely NEW harness from scratch. Do not repeat your previous code.")]

                self.stage = Stage.WRITE
                self._write_attempts = 0
                self._compile_attempts = 0
                so.compile_errors.clear()
                turn_log["reason"] = f"LLM stuck {repeat_count + 1} cycles - Hard Reset Triggered"
                return

        # ==========================================
        # DYNAMIC API HINTING
        # ==========================================
        header_hint = ""
        if "No such file or directory" in output and ".h" in output and so.header_file:
            hdr_basename = so.header_file.split("/")[-1]
            header_hint = f"\n\nHINT: The correct header is {hdr_basename}. Try #include \"{hdr_basename}\" instead of relative paths."

        api_hint = ""
        if ("not declared" in output or "was not declared" in output or "too few arguments" in output
                or "invalid conversion" in output or "no matching function" in output):

            # 1. Extract GCC's extremely helpful compiler notes
            for line in output.split("\n"):
                if "note:" in line and ("declared here" in line or "candidate:" in line or "EXPORT" in line):
                    api_hint += f"\n  {line.strip()}"

            # 2. Clean up pipe-delimited entry names
            entry_fn = so.entry_function or so.sink_function
            if "|" in entry_fn:
                parts = [p.strip() for p in entry_fn.split("|") if len(p.strip()) > 3]
                parts.sort(key=len, reverse=True)
                entry_fn = parts[0] if parts else entry_fn

            # 3. Formulate the dynamic reality check
            api_hint = f"\n\n⚠️ API MISMATCH DETECTED:" + api_hint
            api_hint += f"\n\nThe target entry point from the trace is: {entry_fn}"
            if so.header_file and "not declared" in output:
                api_hint += f"\nStop guessing function names! If you need an allocator or setup function, output a <shell> action to search for it: <shell>grep -iE 'alloc|create|new|init|load' {so.header_file}</shell>"

        # Read current harness so the LLM doesn't truncate the file
        current_harness = self.env.read_file("/work/harness.cpp")

        prompt = (f"COMPILE ERROR:\n{output[:1500]}{header_hint}{api_hint}\n\n"
                  f"CURRENT HARNESS:\n```cpp\n{current_harness}\n```\n\n"
                  f"Fix ONLY this error. You MUST output the COMPLETE corrected file inside a "
                  f"<write_file path=\"/work/harness.cpp\"> block. "
                  f"Do NOT strip out the library functions or main(). Do NOT write stub implementations.")

        response = self._call_llm(self.llm_b,
                                  "Fix the compile error. Output the FULL corrected file in <write_file>.",
                                  prompt)
        turn_log["llm_response"] = response[:4000]

        actions = parse_actions(response)
        if actions:
            self._exec_actions(actions[:self.config.max_actions_per_turn], result)

        # Re-validate: did the LLM strip all library calls to "fix" the error?
        recheck = self._validate_harness()
        if recheck != "PASS":
            logger.warning("LLM broke harness during compile fix: %s", recheck)
            turn_log["revalidation_failed"] = recheck
            so.backward_reasons.append(f"LLM stripped library calls to fix compile: {recheck}")
            self.stage = Stage.WRITE
            self._write_attempts = 0
            self._compile_attempts = 0
            self._exchanges = [("(system)",
                                f"⚠️ You removed all library calls to fix the compile error. That's not acceptable.\n"
                                f"The harness MUST call {so.entry_function or so.sink_function}.\n"
                                f"Error was: {output[:300]}\n"
                                f"Fix the include path or function signatures, not the overall logic.")]

    # =================================================================
    # STAGES 4-9: PIPELINE (deterministic, no LLM except CRAFT)
    # =================================================================
    _init_crash_retries = 0
    _MAX_INIT_CRASH_RETRIES = 3

    def _run_pipeline(self, result: AgentResult, turn_log: dict):
        """Run all deterministic stages in sequence."""

        # --- STAGE 4: LINK ---
        if self.stage == Stage.LINK:
            turn_log["pipeline_stage"] = "LINK"
            ok = self.env.exec("test -x /work/harness && echo y", timeout=5).stdout.strip() == "y"

            if not ok:
                so = self.so
                # Strategy 1: Link against pre-built archive (best)
                if so.prebuild_archive:
                    link_cmd = (f"g++ -fsanitize=address -g /work/harness.o {so.prebuild_archive} "
                                f"-o /work/harness -lpthread -ldl -lm 2>&1")
                    link_r = self.env.exec(link_cmd, timeout=120)
                    ok = self.env.exec("test -x /work/harness && echo y", timeout=5).stdout.strip() == "y"
                    if not ok:
                        # Try with force-link for any remaining external symbols
                        link_cmd = (f"g++ -fsanitize=address -g /work/harness.o {so.prebuild_archive} "
                                    f"-o /work/harness -Wl,--unresolved-symbols=ignore-in-object-files "
                                    f"-lpthread -ldl -lm 2>&1")
                        link_r = self.env.exec(link_cmd, timeout=120)
                        ok = self.env.exec("test -x /work/harness && echo y", timeout=5).stdout.strip() == "y"
                    if ok:
                        turn_log["link_method"] = "prebuild_archive"

                # Strategy 2: Link against pre-built .o files
                if not ok and so.prebuild_objects:
                    objs = " ".join(so.prebuild_objects)
                    link_cmd = (f"g++ -fsanitize=address -g /work/harness.o {objs} "
                                f"-o /work/harness -Wl,--unresolved-symbols=ignore-in-object-files "
                                f"-lpthread -ldl -lm 2>&1")
                    link_r = self.env.exec(link_cmd, timeout=120)
                    ok = self.env.exec("test -x /work/harness && echo y", timeout=5).stdout.strip() == "y"
                    if ok:
                        turn_log["link_method"] = "prebuild_objects"

                # Strategy 3: Link harness.o + any /work/*.o (legacy fallback)
                if not ok:
                    objs = self.env.exec("ls /work/build/*.o /work/*.o 2>/dev/null", timeout=5).stdout.replace("\n",
                                                                                                               " ").strip()
                    if objs:
                        link_cmd = (f"g++ -fsanitize=address -g /work/harness.o {objs} "
                                    f"-o /work/harness -Wl,--unresolved-symbols=ignore-in-object-files "
                                    f"-lpthread -ldl -lm 2>&1")
                        link_r = self.env.exec(link_cmd, timeout=120)
                        ok = self.env.exec("test -x /work/harness && echo y", timeout=5).stdout.strip() == "y"
                        if ok:
                            turn_log["link_method"] = "glob_objects"

                if not ok:
                    turn_log["link_error"] = (link_r.output if 'link_r' in dir() else "no objects")[:500]

            if ok:
                self.stage = Stage.RUN
            else:
                link_fail_count = sum(1 for r in self.so.backward_reasons if "link failed" in r)
                self.so.backward_reasons.append(f"link failed: {turn_log.get('link_error', 'unknown')[:100]}")
                self.so.link_errors = turn_log.get("link_error", "")

                if link_fail_count >= 3:
                    logger.warning("Link failed %d times — halting", link_fail_count + 1)
                    self.stage = Stage.HALTED
                    self.so.backward_reasons.append("link failed repeatedly — cannot produce executable")
                else:
                    self._exchanges = [("(system)",
                                        f"⚠️ LINK FAILED.\n{self.so.link_errors[:500]}\n"
                                        f"The library is pre-built at {self.so.prebuild_archive or '/work/build/'}.\n"
                                        f"Ensure your harness only uses functions declared in the public header.")]
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
            elif crash == "init_crash":
                # Library crashes during initialization — route to BUILD to fix stubs
                if self._build_turns < self._MAX_BUILD_TURNS:
                    logger.info("Init crash detected — routing to BUILD stage")
                    self.so.backward_reasons.append(f"init_crash: library crashes during init")
                    # Store the crash trace so BUILD can show it to the LLM
                    self.so.run_output = run_out
                    self.env.exec("rm -f /work/harness", timeout=3)
                    self.stage = Stage.BUILD
                else:
                    self._route_init_crash_to_write("RUN")
            elif crash == "harness_bug":
                self.so.backward_reasons.append(f"harness bug: {run_out[:100]}")
                self._exchanges = [
                    ("(system)", f"⚠️ Crash in YOUR harness, not library:\n{run_out[:500]}\nFix the bug.")]
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
                # Re-classify to check if it's an init crash
                recheck = self.env.exec(f"timeout 10 /work/harness {crash_file} 2>&1", timeout=15)
                recheck_crash = self._classify_crash(recheck.output or "")
                if recheck_crash == "init_crash" and self._build_turns < self._MAX_BUILD_TURNS:
                    logger.info("SWEEP found init_crash — routing to BUILD")
                    self.so.backward_reasons.append("init_crash in SWEEP")
                    self.env.exec("rm -f /work/harness", timeout=3)
                    self.stage = Stage.BUILD
                    return
                elif recheck_crash == "init_crash":
                    # BUILD exhausted — let LLM try different approach
                    self._route_init_crash_to_write("SWEEP")
                    return
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
                    self._try_fallback_or_halt()
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
            elif crash == "init_crash":
                if self._build_turns < self._MAX_BUILD_TURNS:
                    logger.info("Init crash in RUN_CRAFTED — routing to BUILD")
                    self.so.backward_reasons.append("init_crash in RUN_CRAFTED")
                    self.so.run_output = run_out
                    self.env.exec("rm -f /work/harness", timeout=3)
                    self.stage = Stage.BUILD
                else:
                    self._route_init_crash_to_write("RUN_CRAFTED")
            elif crash == "wrong_location":
                self.so.pipeline_attempts += 1
                self.so.backward_reasons.append(f"crash at wrong location, not {self.so.sink_function}")
                if self.so.pipeline_attempts >= self.config.max_pipeline_attempts:
                    self._try_fallback_or_halt()
                else:
                    self._exchanges = [("(system)",
                                        f"⚠️ Crash at wrong function.\nTarget: {self.so.sink_function}\nRewrite harness to reach the correct code path.")]
                    self.stage = Stage.WRITE
                    self._write_attempts = 0
            else:
                # Clean exit from crafted input — try craft again or go back
                self.so.pipeline_attempts += 1
                if self.so.pipeline_attempts >= self.config.max_pipeline_attempts:
                    self._try_fallback_or_halt()
                else:
                    self.stage = Stage.CRAFT  # retry with different craft
            return

        # --- STAGE 9: VERIFY ---
        if self.stage == Stage.VERIFY:
            turn_log["pipeline_stage"] = "VERIFY"

            vr = self._run_verification("/work/harness", self.so.crash_file)
            result.verification = vr
            turn_log["verified"] = vr.confirmed
            turn_log["sink_reached"] = getattr(vr, "sink_reached", False)

            if vr.confirmed and getattr(vr, "sink_reached", False):
                # REAL exploit — crash is at the actual sink
                self._finalize_success(result, self.so.crash_file,
                                       reason=f"verified: {vr.summary[:100]}")
                self.stage = Stage.SUCCESS
            elif vr.confirmed and not getattr(vr, "sink_reached", False):
                # Crash in library but NOT at the sink.
                # This is usually an init crash (stubs wrong) or wrong code path.
                asan_loc = getattr(vr, "asan_location", "") or ""
                is_init = any(kw in asan_loc for kw in ("Alloc", "Init", "Create", "Malloc"))

                if is_init and self._build_turns < self._MAX_BUILD_TURNS:
                    # Init crash → route to BUILD to fix stubs
                    logger.warning("VERIFY: crash at %s (init, not sink) — routing to BUILD", asan_loc)
                    self.so.backward_reasons.append(f"verify: crash at {asan_loc} not sink — init crash")
                    self.env.exec("rm -f /work/harness", timeout=3)
                    self.stage = Stage.BUILD
                elif is_init:
                    # Init crash but BUILD exhausted — let LLM try different approach
                    self._route_init_crash_to_write("VERIFY")
                else:
                    # Wrong code path or BUILD exhausted
                    logger.warning("VERIFY: crash at %s, not at sink %s — retrying",
                                   asan_loc, self.sink_function)
                    self.so.backward_reasons.append(f"verify: crash at {asan_loc} not sink")
                    self.so.pipeline_attempts += 1
                    if self.so.pipeline_attempts >= self.config.max_pipeline_attempts:
                        self._try_fallback_or_halt()
                    else:
                        self.stage = Stage.WRITE
                        self._write_attempts = 0
            else:
                self.so.backward_reasons.append(f"verification failed: {vr.summary[:100]}")
                self.so.pipeline_attempts += 1
                if self.so.pipeline_attempts >= self.config.max_pipeline_attempts:
                    self._try_fallback_or_halt()
                else:
                    self.stage = Stage.WRITE
                    self._write_attempts = 0
            return

    # =================================================================
    # Success finalization — generates all output artifacts
    # =================================================================

    def _finalize_success(self, result: AgentResult, crash_file: str, reason: str = ""):
        """Populate all result fields when exploitation succeeds."""
        result.success = True
        result.harness_path = "/work/harness"
        result.harness_source_path = "/work/harness.cpp"
        result.input_path = crash_file
        result.final_reason = reason

        # Collect all input files
        ls_r = self.env.exec("ls /work/input.* /work/crafted_input* /work/crash_input 2>/dev/null", timeout=5)
        if ls_r.stdout.strip():
            result.input_files = [f.strip() for f in ls_r.stdout.strip().split("\n") if f.strip()]

        # Get the crash output for the report
        crash_output = self.so.run_output or ""

        # Generate RunPoc.sh
        result.run_poc_script = self._generate_run_poc()

        # Generate vulnerability report
        result.vulnerability_report = self._generate_vuln_report(crash_output, crash_file)

        logger.info("Success finalized: harness=%s input=%s", result.harness_source_path, crash_file)

    def _generate_run_poc(self) -> str:
        """Generate a shell script to reproduce the vulnerability."""
        so = self.so
        flags = so.include_flags or "-I/src"
        archive = so.prebuild_archive or "/work/build/libtarget.a"

        return f"""#!/bin/bash
# PoC for vulnerability in {so.sink_file} → {so.sink_function}
# Generated by DeepTrace agent
# NOTE: Must be run inside the Docker container with source at /src/
set -e

echo "=== Building PoC harness ==="
g++ -fsanitize=address -g -std=c++17 {flags} /work/harness.cpp -c -o /work/harness.o

echo "=== Linking against pre-built library ==="
g++ -fsanitize=address -g /work/harness.o {archive} \\
  -Wl,--unresolved-symbols=ignore-in-object-files \\
  -o /work/harness -lpthread -ldl -lm

echo ""
echo "=== Running PoC ==="
ASAN_OPTIONS=detect_leaks=0 /work/harness {self.so.crash_file or '/work/input.dat'} 2>&1 || true

echo ""
echo "=== Done ==="
echo "If you see 'AddressSanitizer' output, the vulnerability is confirmed."
"""

    def _generate_vuln_report(self, crash_output: str, crash_file: str) -> str:
        """Generate a markdown vulnerability report."""
        so = self.so

        # Extract ASAN summary from crash output
        asan_summary = ""
        asan_trace = ""
        if "AddressSanitizer" in crash_output:
            for line in crash_output.split("\n"):
                if "ERROR:" in line and "AddressSanitizer" in line:
                    asan_summary = line.strip()
                if "SUMMARY:" in line:
                    asan_summary = line.strip()
                if line.strip().startswith("#"):
                    asan_trace += f"    {line.strip()}\n"

        # Determine vulnerability type details
        vuln_tags = ", ".join(so.vuln_tags) if so.vuln_tags else "unknown"

        report = f"""# Vulnerability Report

## Overview

| Field | Value |
|-------|-------|
| **Sink Function** | `{so.sink_function}` |
| **Sink File** | `{so.sink_file}` |
| **Entry Point** | `{so.entry_function}` @ `{so.entry_file}` |
| **Vulnerability Type** | {vuln_tags} |
| **Repository** | {self.profile.repo_name} |
| **Turns Used** | {self._turn + 1} |

## Vulnerability Description

{so.vuln_summary or 'See trace and crash details below.'}

## Crash Details

"""
        if asan_summary:
            report += f"""### AddressSanitizer Output

```
{asan_summary}
```

### Stack Trace

```
{asan_trace.strip() or '(see agent_log.json for full trace)'}
```
"""

        report += f"""
## Reproduction

### Files

| File | Description |
|------|-------------|
| `harness.cpp` | PoC harness source code |
| `harness` | Compiled binary (ASAN-enabled) |
| `RunPoc.sh` | Script to build and run the PoC |
| `agent_log.json` | Full agent execution log |

### Quick Reproduction

```bash
chmod +x RunPoc.sh
./RunPoc.sh
```

## Trace Path

```
{so.trace_text}
```

## Sink Source Code

```c
{so.sink_source[:2000] if so.sink_source else '(see source file)'}
```
"""
        return report

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

    def _route_init_crash_to_write(self, from_stage: str):
        """Route init_crash to WRITE with guidance, or HALT after too many retries."""
        self._init_crash_retries += 1
        if self._init_crash_retries > self._MAX_INIT_CRASH_RETRIES:
            logger.warning("%s: init crash, %d WRITE retries exhausted — HALTING", from_stage, self._init_crash_retries)
            self.so.backward_reasons.append(
                f"HALTED: init crash persists after {self._init_crash_retries} WRITE retries")
            self.stage = Stage.HALTED
            return

        logger.warning("%s: init crash, BUILD exhausted — routing to WRITE (retry %d/%d)",
                       from_stage, self._init_crash_retries, self._MAX_INIT_CRASH_RETRIES)
        self.so.backward_reasons.append(
            f"init_crash: BUILD exhausted, trying different approach (retry {self._init_crash_retries})")
        self.so.harness_locked = False  # unlock so LLM can write new harness

        # Dynamically determine what the entry function is
        entry_fn = self.so.entry_function or self.so.sink_function
        if "|" in entry_fn:
            parts = [p.strip() for p in entry_fn.split("|") if len(p.strip()) > 3]
            parts.sort(key=len, reverse=True)
            entry_fn = parts[0] if parts else entry_fn

        self._exchanges = [("(system)",
                            f"⚠️ The library crashes during initialization.\n"
                            f"The memory allocator stubs could not be fixed after {self._MAX_BUILD_TURNS} BUILD attempts.\n\n"
                            f"You MUST try a COMPLETELY DIFFERENT APPROACH:\n"
                            f"- Instead of allocating a handle manually, try loading from a file (look for LoadFromFile or similar functions in the API)\n"
                            f"- This may initialize the handle differently and avoid the crashing allocator path\n"
                            f"- Create a crafted input file that triggers the vulnerability\n"
                            f"- Or try any other approach to reach {self.so.sink_file}\n\n"
                            f"Write a NEW /work/harness.cpp that avoids the crashing initialization path.")]
        self.stage = Stage.WRITE
        self._write_attempts = 0
        self._compile_attempts = 0

    def _classify_crash(self, output: str) -> str:
        """Classify a crash based on ASAN output.

        Returns one of: target_sink, same_file, init_crash, harness_bug,
                        wrong_location, segfault_no_asan, timeout, clean, unknown_crash
        """
        if not output or output == "(no output)" or output.strip() == "":
            return "clean"
        if "AddressSanitizer" not in output:
            if "Segmentation fault" in output:
                return "segfault_no_asan"
            m = re.search(r"exit_code=(\d+)", output)
            if m:
                code = int(m.group(1))
                if code == 0:
                    return "clean"
                if code in (124, 127):
                    return "timeout"
                return "clean"
            return "clean"

        # ASAN crash — classify by location
        init_keywords = ("Alloc", "Create", "Init", "Setup", "New", "Open", "Malloc")

        if self.sink_function in output:
            return "target_sink"

        sink_base = self.sink_file.rsplit("/", 1)[-1] if self.sink_file else ""
        if sink_base and sink_base in output:
            # Crash in the sink file — but is it at the sink or during init?
            for line in output.split("\n"):
                if sink_base in line and any(kw in line for kw in init_keywords):
                    return "init_crash"
            return "same_file"

        # Check ALL trace frames for init crashes (any library file)
        for line in output.split("\n"):
            if ("/src/" in line or "/work/build/" in line) and any(kw in line for kw in init_keywords):
                return "init_crash"

        # Crash only in /work/ (no /src/) = harness code
        if "/work/" in output and "/src/" not in output:
            return "harness_bug"

        if "/src/" in output:
            return "wrong_location"

        return "unknown_crash"

    def _run_harness(self, inp: str) -> str:
        # Check binary exists before trying to run
        if self.env.exec("test -x /work/harness && echo y", timeout=3).stdout.strip() != "y":
            return "exit_code=127\nERROR: /work/harness does not exist or is not executable"
        r = self.env.exec(f"ASAN_OPTIONS=detect_leaks=0 timeout 20 /work/harness {inp} 2>&1", timeout=30)
        smart = self._smart_truncate(f"/work/harness {inp}", r.exit_code, r.output or "")
        return f"exit_code={r.exit_code}\n{smart}"

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
            r = self.env.exec(f"ASAN_OPTIONS=detect_leaks=0 timeout 10 /work/harness {tf} 2>&1", timeout=15)
            crash = self._classify_crash(r.output or "")
            if crash in ("target_sink", "same_file", "init_crash"):
                self.env.exec(f"cp {tf} /work/crash_input", timeout=5)
                return "/work/crash_input"
        return ""

    def _craft_input(self) -> str:
        """Ask the LLM to craft a malicious input file."""
        so = self.so
        vc = (so.vuln_tags[0] if so.vuln_tags else "unknown")
        guide = {"format_string": "Use %s, %n, %x format specifiers as data.",
                 "buffer_overflow": "Exceed expected field lengths.",
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

    def _try_fallback_or_halt(self):
        """When pipeline is exhausted, try force-write harness then halt.
        Crash must be in real (pre-built) library code."""
        reasons = self.so.backward_reasons

        # Try force-write harness as last resort
        if not any("force_write_fallback" in r for r in reasons):
            logger.info("Pipeline exhausted — force-writing generic harness")
            self._force_write_harness()
            reasons.append("force_write_fallback: last resort before halt")
            self.stage = Stage.COMPILE
            self._compile_attempts = 0
            self.so.compile_errors.clear()
            self.so.pipeline_attempts = 0
            return

        logger.info("All strategies exhausted — halting")
        self.stage = Stage.HALTED
        reasons.append("pipeline exhausted: no crash after max attempts")

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
                    blocks.append("\n".join(lines[max(0, i - 1):min(len(lines), i + 4)]))
            if blocks:
                return "\n...\n".join(blocks)[:max_len]
            return raw[-max_len:]
        h = max_len // 2 - 30
        return raw[:h] + "\n... [TRUNCATED] ...\n" + raw[-h:]

        +++++++++++++++++++++++++++++++++++++++++++++++++

        """Docker environment for the exploit agent.

Builds a Docker image with the target repo compiled with ASAN + gdb + tools,
then keeps a container running for the agent to exec commands in interactively.
"""

from __future__ import annotations

import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from deeptrace.exploit.repo_analyzer import RepoProfile

logger = logging.getLogger(__name__)

_AGENT_IMAGE_PREFIX = "deeptrace-agent"
_CONTAINER_PREFIX = "deeptrace-agent"
_EXEC_TIMEOUT = 120  # seconds per command
_BUILD_TIMEOUT = 1800  # 30 min for building the repo


@dataclass
class ExecResult:
    """Result of executing a command in the container."""
    command: str
    stdout: str
    stderr: str
    exit_code: int
    elapsed: float = 0.0
    timed_out: bool = False

    @property
    def output(self) -> str:
        """Combined stdout+stderr for display."""
        parts = []
        if self.stdout.strip():
            parts.append(self.stdout.strip())
        if self.stderr.strip():
            parts.append(self.stderr.strip())
        return "\n".join(parts) or "(no output)"

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


class DockerEnv:
    """Manages a persistent Docker container for the exploit agent.

    Lifecycle:
      1. build_image() — builds repo with ASAN + installs tools
      2. start_container() — runs the image as a persistent container
      3. exec(cmd) — runs shell commands inside the container
      4. write_file(path, content) — writes a file into the container
      5. read_file(path) — reads a file from the container
      6. cleanup() — stops and removes the container
    """

    def __init__(self, profile: RepoProfile, work_dir: str = "/work") -> None:
        self.profile = profile
        self.work_dir = work_dir
        self._image_name = f"{_AGENT_IMAGE_PREFIX}-{profile.repo_name.lower()}"
        self._container_id: str | None = None
        self._image_built = False

    def use_prebuilt_image(self, image_name: str) -> None:
        """Use an existing Docker image instead of building one.

        The image must have:
          - The repo source at /src/
          - Basic tools (gcc/g++, gdb, grep)
          - A writable /work/ directory

        This is useful for complex repos (pdfium, chromium) where the user
        has already set up a Docker image with the correct toolchain.
        """
        # Verify the image exists
        proc = subprocess.run(
            ["docker", "image", "inspect", image_name],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"Docker image '{image_name}' not found. Pull or build it first.")

        self._image_name = image_name
        self._image_built = True
        logger.info("Using pre-built Docker image: %s", image_name)

    # ------------------------------------------------------------------
    # Image building
    # ------------------------------------------------------------------

    def build_image(self, progress_callback=None) -> None:
        """Build a Docker image with the repo compiled with ASAN + tools."""
        dockerfile = self._generate_dockerfile()

        # Write Dockerfile to a temp location
        build_ctx = os.path.join(self.profile.repo_path, ".deeptrace-agent-build")
        os.makedirs(build_ctx, exist_ok=True)
        df_path = os.path.join(build_ctx, "Dockerfile")
        Path(df_path).write_text(dockerfile, encoding="utf-8")

        logger.info("Building Docker image %s (this may take several minutes)...", self._image_name)

        try:
            proc = subprocess.run(
                ["docker", "build",
                 "-f", df_path,
                 "-t", self._image_name,
                 self.profile.repo_path],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=_BUILD_TIMEOUT,
            )
            if proc.returncode != 0:
                logger.error("Docker build failed:\n%s", (proc.stderr or "")[-3000:])
                raise RuntimeError(f"Docker build failed (rc={proc.returncode})")

            self._image_built = True
            logger.info("Docker image built successfully: %s", self._image_name)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Docker build timed out after {_BUILD_TIMEOUT}s")

    def _generate_dockerfile(self) -> str:
        """Generate a Dockerfile that sets up tools + copies source.

        IMPORTANT: The Dockerfile does NOT build the repo. Building is the
        agent's first task — it reads README/BUILD files interactively and
        figures out the correct commands. This avoids failures from complex
        build systems (gn, depot_tools, bazel, etc.) that can't be
        automated with a single RUN command.
        """
        p = self.profile
        deps = " ".join(p.system_deps + [
            "gdb", "cscope", "strace", "ltrace", "binutils",
            "file", "less", "vim-tiny",
        ])

        include_dirs = " ".join(f"/src/{d}" for d in p.public_header_dirs) or "/src"

        # Build hints for the agent (as comments in env vars)
        build_hint_lines = []
        if p.build_system:
            build_hint_lines.append(f"BUILD_SYSTEM={p.build_system}")
        if p.build_commands:
            # Store as hints, NOT as RUN commands
            for i, cmd in enumerate(p.build_commands):
                escaped = cmd.replace("\\", "\\\\").replace('"', '\\"')
                build_hint_lines.append(f'BUILD_HINT_{i}="{escaped}"')

        env_lines = "\n".join(f"ENV {line}" for line in build_hint_lines)

        return f"""FROM {p.base_docker_image}

# System deps + agent tools
RUN apt-get update && apt-get install -y \\
    {deps} \\
    && rm -rf /var/lib/apt/lists/*

# Copy repository source
COPY . /src/

# Create agent workspace
RUN mkdir -p {self.work_dir}
WORKDIR {self.work_dir}

# Environment: ASAN defaults + repo metadata
ENV ASAN_OPTIONS=detect_leaks=0:print_stacktrace=1:halt_on_error=0
ENV SRC_DIR=/src
ENV INCLUDE_DIRS="{include_dirs}"
ENV LIBRARY_NAME="{p.library_name}"
{env_lines}

# NOTE: The repo is NOT pre-built. The agent's first task is to
# explore /src/ (read README, BUILD.gn, CMakeLists.txt, Makefile, etc.)
# and figure out how to build the library with ASAN.

CMD ["sleep", "infinity"]
"""

    # ------------------------------------------------------------------
    # Container lifecycle
    # ------------------------------------------------------------------

    def start_container(self) -> str:
        """Start a persistent container from the built image."""
        if not self._image_built:
            raise RuntimeError("Image not built. Call build_image() first.")

        name = f"{_CONTAINER_PREFIX}-{self.profile.repo_name.lower()}-{os.getpid()}"

        proc = subprocess.run(
            ["docker", "run", "-d", "--rm",
             "--name", name,
             "--memory=2g", "--cpus=4",
             "--security-opt", "seccomp=unconfined",  # needed for gdb
             "--cap-add=SYS_PTRACE",  # needed for gdb
             self._image_name],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"Failed to start container: {proc.stderr or 'unknown error'}")

        self._container_id = (proc.stdout or "").strip()[:12]
        logger.info("Container started: %s", self._container_id)
        return self._container_id

    def exec(self, command: str, timeout: int = _EXEC_TIMEOUT) -> ExecResult:
        """Execute a shell command inside the running container."""
        if not self._container_id:
            raise RuntimeError("No running container. Call start_container() first.")

        t0 = time.time()

        try:
            proc = subprocess.run(
                ["docker", "exec", self._container_id,
                 "bash", "-c", command],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
            )
            # Guard against None stdout/stderr — can happen on Windows when
            # the subprocess reader thread crashes on binary output
            stdout = (proc.stdout or "")[-8000:]
            stderr = (proc.stderr or "")[-4000:]
            return ExecResult(
                command=command,
                stdout=stdout,
                stderr=stderr,
                exit_code=proc.returncode if proc.returncode is not None else -1,
                elapsed=round(time.time() - t0, 2),
            )
        except subprocess.TimeoutExpired:
            return ExecResult(
                command=command,
                stdout="",
                stderr=f"Command timed out after {timeout}s",
                exit_code=-1,
                elapsed=timeout,
                timed_out=True,
            )
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            # Handle encoding crashes on Windows or other I/O failures
            return ExecResult(
                command=command,
                stdout="",
                stderr=f"exec failed: {exc}",
                exit_code=-1,
                elapsed=round(time.time() - t0, 2),
            )

    def write_file(self, container_path: str, content: str) -> ExecResult:
        """Write a file into the container.

        For large files, uses chunked base64 to avoid Windows command-line limits
        (CreateProcess has a ~32KB limit).
        """
        import base64
        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")

        # If the command would be too long (>30000 chars), chunk it
        if len(encoded) > 25000:
            # Write in chunks using append mode
            self.exec(f"rm -f {container_path}", timeout=5)
            chunk_size = 20000  # safe margin under 32KB limit
            for i in range(0, len(encoded), chunk_size):
                chunk = encoded[i:i + chunk_size]
                if i == 0:
                    self.exec(f"echo -n '{chunk}' > /tmp/_dt_b64", timeout=30)
                else:
                    self.exec(f"echo -n '{chunk}' >> /tmp/_dt_b64", timeout=30)
            result = self.exec(f"base64 -d /tmp/_dt_b64 > {container_path} && rm -f /tmp/_dt_b64",
                               timeout=30)
            return result
        else:
            return self.exec(f"echo '{encoded}' | base64 -d > {container_path}")

    def read_file(self, container_path: str, max_lines: int = 200) -> str:
        """Read a file from the container."""
        result = self.exec(f"head -n {max_lines} {container_path}")
        return result.stdout if result.success else f"(read failed: {result.stderr})"

    def cleanup(self) -> None:
        """Stop and remove the container."""
        if self._container_id:
            try:
                subprocess.run(
                    ["docker", "stop", self._container_id],
                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15,
                )
                logger.info("Container stopped: %s", self._container_id)
            except Exception:
                pass
            self._container_id = None

    @property
    def is_running(self) -> bool:
        return self._container_id is not None

    @property
    def container_id(self) -> str:
        return self._container_id or ""

    # ------------------------------------------------------------------
    # Pre-build: compile the target library with ASAN before agent starts
    # ------------------------------------------------------------------

    def prebuild_library(self, sink_file: str) -> dict:
        """Compile the library containing the sink file with ASAN.

        This runs INSIDE the container after start_container().
        The agent doesn't need to compile anything — it just links.

        Returns a dict with:
          - compile_flags: str — exact -I/-D flags for the library
          - objects: list[str] — paths to .o files
          - archive: str — path to .a if created
          - sink_obj: str — path to the .o containing the sink
          - success: bool
          - error: str
        """
        if not self._container_id:
            raise RuntimeError("Container not running")

        logger.info("Pre-building library for sink: %s", sink_file)

        # Write the build script into the container
        main_script = self._generate_prebuild_script(sink_file)

        # Create build dir and write script
        self.exec("mkdir -p /work/build", timeout=5)
        self.write_file("/work/prebuild.sh", main_script)
        self.exec("chmod +x /work/prebuild.sh", timeout=5)

        # Verify the script was written
        check = self.exec("test -f /work/prebuild.sh && wc -c /work/prebuild.sh", timeout=5)
        if "prebuild.sh" not in (check.stdout or ""):
            logger.error("Failed to write prebuild script to container!")
            return {"success": False, "error": "write_file failed (script too large for command line?)",
                    "objects": [], "archive": "", "compile_flags": "", "sink_obj": ""}

        # Run the build (up to 5 minutes)
        result = self.exec("bash /work/prebuild.sh 2>&1", timeout=300)
        logger.info("Pre-build output (last 500 chars): %s", (result.output or "")[-500:])

        # Read the build info
        info_r = self.exec("cat /work/build_info.json 2>/dev/null", timeout=5)
        if info_r.success and info_r.stdout.strip():
            import json
            try:
                info = json.loads(info_r.stdout.strip())
                logger.info("Pre-build: %d objects, archive=%s, flags=%s",
                            len(info.get("objects", [])),
                            info.get("archive", ""),
                            info.get("compile_flags", "")[:100])
                return info
            except json.JSONDecodeError:
                logger.warning("Pre-build: invalid JSON in build_info.json")

        return {"success": False, "error": result.output[-500:] if result.output else "no output",
                "objects": [], "archive": "", "compile_flags": "", "sink_obj": ""}

    def _generate_prebuild_script(self, sink_file: str) -> str:
        """Generate a shell script that compiles the library with ASAN.

        Strategy (kept simple — the agent BUILD stage handles failures):
          1. Find library root and all source files
          2. Create shims for external headers (BUILDFLAG, fx_memory.h, etc.)
          3. Compile everything that compiles
          4. Archive into libtarget.a
          5. Collect diagnostics: failed files, errors, undefined symbols
          6. Write build_info.json so the agent's BUILD stage can fix what's broken

        NOTE: verify.c is NOT generated here. The agent's BUILD stage
        prompts the LLM to write a verify.c dynamically based on the
        actual entry function from the trace — no library-specific hardcoding.
        """
        main_script = r'''#!/bin/bash
# DeepTrace pre-build: compile what we can, report what fails.
# The agent's BUILD stage will fix failed files interactively.
SINK_FILE="__SINK_FILE__"
BUILD_DIR="/work/build"
SHIM_DIR="/work/inc_shim"
mkdir -p "$BUILD_DIR" "$SHIM_DIR"

echo "========================================="
echo "Phase 0: Check for compile_commands.json"
echo "========================================="

# If the repo already has a compilation database, extract exact flags
# This handles repos built with CMake (-DCMAKE_EXPORT_COMPILE_COMMANDS=ON)
# or GN (gn gen --export-compile-commands)
CC_JSON=""
CCDB_FLAGS=""
for candidate in \
    /src/compile_commands.json \
    /src/out/Default/compile_commands.json \
    /src/out/Release/compile_commands.json \
    /src/build/compile_commands.json \
    /src/cmake-build-*/compile_commands.json; do
    if [ -f "$candidate" ]; then
        CC_JSON="$candidate"
        echo "Found compilation database: $CC_JSON"
        break
    fi
done

if [ -n "$CC_JSON" ]; then
    # Extract flags for the sink file
    SINK_BASENAME=$(basename "$SINK_FILE" .c)
    CCDB_FLAGS=$(python3 -c "
import json, sys
try:
    db = json.load(open('$CC_JSON'))
    for entry in db:
        if '$SINK_BASENAME' in entry.get('file', ''):
            cmd = entry.get('command', '') or ' '.join(entry.get('arguments', []))
            # Extract -I and -D flags
            flags = []
            for part in cmd.split():
                if part.startswith('-I') or part.startswith('-D'):
                    flags.append(part)
            print(' '.join(flags))
            sys.exit(0)
    print('')
except: print('')
" 2>/dev/null)
    if [ -n "$CCDB_FLAGS" ]; then
        echo "Extracted flags from compile_commands.json: ${CCDB_FLAGS:0:200}..."
    fi
fi

echo "========================================="
echo "Phase 1: Find library and source files"
echo "========================================="

SINK_PATH=$(find /src -path "*/$SINK_FILE" -type f 2>/dev/null | head -1)
if [ -z "$SINK_PATH" ]; then
    echo '{"success":false,"error":"sink not found","objects":[],"archive":"","compile_flags":"","sink_obj":""}' > /work/build_info.json
    exit 0
fi
echo "Sink: $SINK_PATH"
SINK_DIR=$(dirname "$SINK_PATH")

# Walk up to find library root
LIB_ROOT="$SINK_DIR"
for i in 1 2 3 4 5; do
    PARENT=$(dirname "$LIB_ROOT")
    [ "$PARENT" = "/src" ] || [ "$PARENT" = "/" ] && break
    [ -d "$LIB_ROOT/include" ] || [ -f "$LIB_ROOT/CMakeLists.txt" ] || [ -f "$LIB_ROOT/BUILD.gn" ] && break
    LIB_ROOT="$PARENT"
done
echo "Library root: $LIB_ROOT"

# Collect include paths
HDIRS=$(find "$LIB_ROOT" -name '*.h' -exec dirname {} \; 2>/dev/null | sort -u | head -30)
INC_FLAGS="-I/src"
for d in $HDIRS; do INC_FLAGS="$INC_FLAGS -I$d"; done
INC_FLAGS="$INC_FLAGS -I$LIB_ROOT"

# Merge compile_commands.json flags if available
if [ -n "$CCDB_FLAGS" ]; then
    for flag in $CCDB_FLAGS; do
        if ! echo "$INC_FLAGS" | grep -qF "$flag"; then
            INC_FLAGS="$INC_FLAGS $flag"
        fi
    done
    echo "Merged compile_commands.json flags into INC_FLAGS"
fi

# All source files
SOURCES=$(find "$LIB_ROOT" -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' \) 2>/dev/null | grep -v '_test\|_fuzzer\|_bench\|/test/\|/tests/' | sort)
TOTAL=$(echo "$SOURCES" | wc -l)
echo "Source files: $TOTAL"

echo "========================================="
echo "Phase 2: Create shims for external deps"
echo "========================================="

cat > "$SHIM_DIR/deeptrace_compat.h" << 'COMPAT'
#ifndef DEEPTRACE_COMPAT_H_
#define DEEPTRACE_COMPAT_H_
#ifndef BUILDFLAG
#define BUILDFLAG(x) (0)
#endif
#endif
COMPAT

# Create shims for external headers needed by source files
for src in $SOURCES; do
    for attempt in 1 2 3 4 5 6 7 8; do
        ERR=$(gcc -fsanitize=address -g -include "$SHIM_DIR/deeptrace_compat.h" -I"$SHIM_DIR" $INC_FLAGS -c "$src" -o /dev/null 2>&1)
        MISSING=$(echo "$ERR" | grep -oP 'fatal error:\s*\K[^\s:]+' | head -1)
        [ -z "$MISSING" ] && break
        echo "$MISSING" | grep -q "$(basename "$LIB_ROOT")" && break
        SHIM_PATH="$SHIM_DIR/$MISSING"
        [ -f "$SHIM_PATH" ] && break
        mkdir -p "$(dirname "$SHIM_PATH")"
        REAL=$(find /src -path "*/$MISSING" -type f 2>/dev/null | head -1)
        if [ -n "$REAL" ]; then
            printf '#ifndef BUILDFLAG\n#define BUILDFLAG(x) (0)\n#endif\n' > "$SHIM_PATH"
            cat "$REAL" >> "$SHIM_PATH"
        else
            printf '/* empty shim for %s */\n#include <stdlib.h>\n#include <string.h>\n' "$MISSING" > "$SHIM_PATH"
        fi
    done
done

CFLAGS="-include $SHIM_DIR/deeptrace_compat.h -I$SHIM_DIR $INC_FLAGS"
echo "CFLAGS: $CFLAGS"

echo "========================================="
echo "Phase 3: Compile all source files"
echo "========================================="

COMPILED=0
FAILED=0
OBJECTS=""
SINK_OBJ=""
ASAN="-fsanitize=address -g"

# Write failed file info to a JSON file incrementally (avoids quote-escaping issues)
echo "[]" > "$BUILD_DIR/failed_detail.json"

for src in $SOURCES; do
    fname=$(echo "$src" | tr '/' '_' | sed 's/\.[^.]*$//')
    obj="$BUILD_DIR/$fname.o"
    compiler=gcc
    echo "$src" | grep -qE '\.(cc|cpp)$' && compiler=g++

    CERR=$($compiler $ASAN $CFLAGS -c "$src" -o "$obj" 2>&1)
    if [ -f "$obj" ]; then
        COMPILED=$((COMPILED + 1))
        OBJECTS="$OBJECTS $obj"
        echo "$src" | grep -q "$(basename "$SINK_FILE" .c)" && SINK_OBJ="$obj"
    else
        FAILED=$((FAILED + 1))
        # Append to failed_detail.json using Python (handles quotes safely)
        python3 -c "
import json, sys
d = json.load(open('$BUILD_DIR/failed_detail.json'))
d.append({'source': '$src', 'error': sys.stdin.read().strip()[:300]})
json.dump(d, open('$BUILD_DIR/failed_detail.json', 'w'))
" <<< "$CERR" 2>/dev/null || true
        echo "FAIL: $src"
        echo "$CERR" | head -5
    fi
done

echo "Compiled: $COMPILED/$TOTAL (failed: $FAILED)"

echo "========================================="
echo "Phase 4: Create archive"
echo "========================================="

ARCHIVE=""
if [ -n "$OBJECTS" ]; then
    ARCHIVE="$BUILD_DIR/libtarget.a"
    ar rcs "$ARCHIVE" $OBJECTS && echo "Archive: $ARCHIVE ($(echo $OBJECTS | wc -w) objects)"
fi

echo "========================================="
echo "Phase 5: Collect diagnostics for BUILD stage"
echo "========================================="

# Undefined symbols in the archive (what the failed files would have provided)
UNDEF_SYMS=""
if [ -n "$ARCHIVE" ]; then
    UNDEF_SYMS=$(nm -u $OBJECTS 2>/dev/null | grep ' U ' | awk '{print $2}' | sort -u | head -40 | tr '\n' ' ')
    echo "Undefined symbols: $UNDEF_SYMS"
fi

# Find internal headers that might help write correct stubs
INTERNAL_HDRS=$(find "$LIB_ROOT" -name '*internal*' -name '*.h' -o -name '*_priv*' -name '*.h' 2>/dev/null | head -5 | tr '\n' ' ')
echo "Internal headers: $INTERNAL_HDRS"

# NOTE: verify.c is NOT created here. The agent's BUILD stage will prompt
# the LLM to write a verify.c dynamically using the actual entry function
# from the trace. This keeps the prebuild script repository-agnostic.
VERIFY_OK="false"

echo "========================================="
echo "Phase 6: Write build info"
echo "========================================="

python3 << PYEOF
import json, glob

objs = glob.glob('$BUILD_DIR/*.o')
objs = [o for o in objs if not o.endswith('verify.o')]

# Read failed detail from file (written during compilation, avoids quoting issues)
try:
    failed_detail = json.load(open('$BUILD_DIR/failed_detail.json'))
except:
    failed_detail = []

info = {
    'success': $COMPILED > 0,
    'compile_flags': '$CFLAGS',
    'objects': objs,
    'archive': '$ARCHIVE',
    'sink_obj': '$SINK_OBJ',
    'compiled': $COMPILED,
    'total': $TOTAL,
    'failed': $FAILED,
    'failed_detail': failed_detail,
    'undefined_symbols': '$UNDEF_SYMS'.split(),
    'internal_headers': '$INTERNAL_HDRS'.split(),
    'library_root': '$LIB_ROOT',
    'verify_ok': '$VERIFY_OK' == 'true',
    'compile_commands_json': '$CC_JSON',
}
with open('/work/build_info.json', 'w') as f:
    json.dump(info, f, indent=2)
print(json.dumps(info, indent=2))
PYEOF

echo "=== Pre-build complete ==="
'''
        return main_script.replace('__SINK_FILE__', sink_file)

        
