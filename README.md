agents
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
  8. CRAFT       — isolated LLM call to generate malformed input
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
    RUN = auto(); SWEEP = auto(); CRAFT = auto()
    RUN_CRAFTED = auto(); VERIFY = auto()
    SUCCESS = auto(); HALTED = auto()

@dataclass
class StateObject:
    """Structured facts accumulated across stages."""
    sink_function: str = ""; sink_file: str = ""
    entry_function: str = ""; entry_file: str = ""
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
                 f"ENTRY: {self.entry_function} @ {self.entry_file}",
                 f"VULN: {', '.join(self.vuln_tags) or 'unknown'} — {self.vuln_summary or 'N/A'}"]
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
  Run any shell command.
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
    kind: str; content: str = ""; path: str = ""

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
                 config=None, progress_callback=None, llm_coder=None):
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
            if n <= 1:
                return (f"Rewrite to exercise more of the trace: "
                        f"{so.sink_function} via {entry_fn}")
            elif n <= 3:
                return (f"Attempt {n} failed. Try a DIFFERENT initialization path.\n"
                        f"Use <shell>grep -iE 'alloc|create|load|open|parse' "
                        f"{hdr}</shell> to discover alternative API functions.\n"
                        f"Target: {so.sink_function}")
            else:
                return (f"Attempt {n} failed. DRASTICALLY change your approach:\n"
                        f"- Read the REFERENCE FUZZER again if available\n"
                        f"- Try calling {so.sink_function} directly with crafted args\n"
                        f"- Try a different entry point from the trace\n"
                        f"- Use <shell>grep -rn '{so.sink_function}' /src/ --include='*.c' | head -5</shell> "
                        f"to see how the sink is called in the actual codebase")

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
                            f"- Search the codebase for how {so.sink_function} is actually called:\n"
                            f"  <shell>grep -rn '{so.sink_function}' /src/ --include='*.c' | head -10</shell>\n"
                            f"- Try calling {so.sink_function} directly with minimal setup\n"
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
                    self.stage = Stage.CRAFT
                    return
                else:
                    # Even crafting can't trigger it after 3 rounds — try new harness
                    so.sink_confirmed_reachable = False
                    logger.info("DECISION: sink reachable but %d pipeline attempts → WRITE",
                                so.pipeline_attempts)

            # Differentiate: sink never reached vs. reached but input doesn't trigger
            if "never reached" in context.lower():
                self._exchanges = [("(system)",
                    f"⚠️ Your harness compiled and ran but NEVER CALLED {so.sink_function}().\n"
                    f"GDB confirmed {so.sink_function} was never hit.\n"
                    f"Your harness must contain an actual call: {so.sink_function}(args...);\n"
                    f"Look at the REFERENCE FUZZER and TRACE to see how to reach it.\n"
                    f"{_escalation_hint()}")]
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
            elif self.stage in (Stage.LINK, Stage.RUN, Stage.SWEEP, Stage.CRAFT,
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
        lines = []
        for i, s in enumerate(self.trace.steps[:20]):
            loc = f"{s.location.file}:{s.location.line}" if s.location else "?"
            tag = " [ENTRY]" if i == 0 else (" [SINK]" if i == len(self.trace.steps)-1 else "")
            edge = f" [{s.edge_kind.value}]" if s.edge_kind else ""
            lines.append(f"  {i}{tag}: {loc}{edge} — {(s.code_snippet or '?')[:100]}")
        so.trace_text = "\n".join(lines)
        if self.trace.steps:
            entry = self.trace.steps[0].location
            if entry and entry.file:
                so.entry_file = entry.file
                so.entry_function = self.trace.steps[0].node_name or ""
        if not self.env.is_running: return

        sink_loc = self.trace.steps[-1].location if self.trace.steps else None
        if sink_loc and sink_loc.file:
            r = self.env.exec(f"sed -n '{max(1,sink_loc.line-15)},{sink_loc.line+15}p' /src/{sink_loc.file} 2>/dev/null", timeout=5)
            so.sink_source = r.stdout.strip()[:2000] if r.stdout.strip() else ""
        entry_loc = self.trace.steps[0].location if self.trace.steps else None
        if entry_loc and entry_loc.file:
            r = self.env.exec(f"sed -n '{max(1,entry_loc.line-10)},{entry_loc.line+10}p' /src/{entry_loc.file} 2>/dev/null", timeout=5)
            so.entry_source = r.stdout.strip()[:1500] if r.stdout.strip() else ""

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
"""
        sections.append(td)
        resp = self._call_llm(self.llm_b, "Fix the C library. Write stubs.c AND verify.c. All context above.\n"+_TOOLS_BLOCK, "\n".join(sections))
        turn_log["llm_response"] = resp[:4000]
        actions = parse_actions(resp)
        if not actions: return
        results = self._exec_actions(actions[:self.config.max_actions_per_turn], result)
        self._exchanges.append((resp[:1500], results[:1500])); self._exchanges = self._exchanges[-2:]

        if self.env.exec("test -f /work/build/stubs.c && echo y", timeout=3).stdout.strip() == "y":
            comp = self.env.exec(f"gcc -fsanitize=address -g {flags} -c /work/build/stubs.c -o /work/build/stubs.o 2>&1", timeout=30)
            if self.env.exec("test -f /work/build/stubs.o && echo y", timeout=3).stdout.strip() == "y":
                if crashing_file:
                    ob = crashing_file.split("/")[-1].replace(".c","")
                    for obj_name in (self.env.exec(f"ar t {archive} 2>/dev/null", timeout=5).stdout or "").strip().split("\n"):
                        if ob in obj_name: self.env.exec(f"ar d {archive} {obj_name} 2>/dev/null", timeout=5); break
                self.env.exec(f"ar d {archive} stubs.o 2>/dev/null", timeout=5)
                self.env.exec(f"ar rcs {archive} /work/build/stubs.o", timeout=10)
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

        for _, res in self._exchanges[-2:]: sections.append(f"\n--- Previous ---\n{res[:1000]}")
        sections.append(f"""
REQUIREMENTS:
1. Use EXACTLY: {include_line or 'the header from API HEADER above'}
2. Do NOT include internal source files — use the PUBLIC header
3. Do NOT write stubs, mocks, or fake implementations — call REAL library functions
4. Read input from argv[1]
5. {'Call the PUBLIC API function from the CALL CHAIN above' if so.call_chain else f'Call {so.entry_function or so.sink_function} to process input'}
6. The execution path must reach {so.sink_function}
7. If unsure about a function, use <shell>grep</shell> to find it in the codebase

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
        # This prevents "// targets GetBPP" or "printf("GetBPP")" from passing.
        stripped = re.sub(r'//.*$', '', content, flags=re.MULTILINE)  # line comments
        stripped = re.sub(r'/\*.*?\*/', '', stripped, flags=re.DOTALL)  # block comments
        stripped = re.sub(r'"[^"]*"', '""', stripped)  # string literals

        sink = self.so.sink_function

        # Check for re-implementation (in unstripped content — declarations don't have quotes)
        if sink and content.count(sink) >= 2:
            for line in content.split("\n"):
                s = line.strip()
                if sink in s and (s.startswith("static") or (s.endswith("{") and "=" not in s)):
                    return f"FAIL: re-implements {sink}"

        # Check that a trace function is actually CALLED (appears as "func(" in code,
        # not just mentioned in a comment or string).
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
            ([sink] if sink else []) + entry_parts + trace_funcs))
        has_call = False
        for func in all_funcs:
            if func and re.search(rf'\b{re.escape(func)}\s*\(', stripped):
                has_call = True
                break

        if not has_call:
            return (f"FAIL: harness does not CALL any target function. "
                    f"You must call {sink or entry_parts[0] if entry_parts else '?'}(). "
                    f"Having the name in a comment or string is not enough.")

        # Skeleton detection: a harness that just opens a file and prints
        # without doing any library work is useless
        code_lines = [l.strip() for l in stripped.split("\n")
                      if l.strip() and not l.strip().startswith("//") and not l.strip().startswith("#")]
        # Count lines inside main() that aren't just boilerplate
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
                # Clean run — save output as feedback for next WRITE cycle
                self.so.last_run_feedback = f"CLEAN EXIT (no crash). Output:\n{run_out[:800]}"
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
                    # Harness reaches the sink — problem is the INPUT, not the harness
                    self.so.sink_confirmed_reachable = True
                    self.so.last_run_feedback = (
                        (self.so.last_run_feedback or "") +
                        f"\n\n✅ GDB confirmed: sink function {self.so.sink_function} IS reachable. "
                        f"The harness is CORRECT. Only the input needs to trigger the vulnerability.")
                    self.stage = Stage.CRAFT
                else:
                    # Harness never reaches the sink — rewrite it
                    self.so.sink_confirmed_reachable = False
                    self.so.last_run_feedback = (
                        (self.so.last_run_feedback or "") +
                        f"\n\n❌ GDB confirmed: sink function {self.so.sink_function} is NEVER CALLED. "
                        f"The harness does NOT exercise the vulnerable code path. Rewrite it.")
                    self._decide_recovery("no_crash",
                        f"sink {self.so.sink_function} never reached (GDB confirmed)", "SWEEP")
            return

        if self.stage == Stage.CRAFT:
            turn_log["pipeline_stage"] = "CRAFT"
            # Clean old crafted files to prevent testing stale payloads
            self.env.exec("rm -f /work/crafted_input* 2>/dev/null", timeout=3)
            crafted = self._craft_input()
            if crafted: self.so.crash_file = crafted; self.stage = Stage.RUN_CRAFTED
            else: self._decide_recovery("no_crash", "craft failed", "CRAFT")
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
                    self.stage = Stage.CRAFT
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

    def _discover_call_chain(self) -> str:
        """Walk the codebase to find the call chain from public API to sink.

        When the sink is an internal function (not in any public header),
        the LLM can't write a valid harness without knowing which public
        API function eventually calls the sink.

        Strategy:
          1. Find all callers of sink_function in the codebase
          2. For each caller, check if IT is in the public header
          3. If not, find callers of the caller (up to 4 levels deep)
          4. Return the discovered chain + source snippets

        This runs automatically after 2+ failed WRITE attempts where
        the LLM keeps writing stubs/mocks.
        """
        so = self.so
        sink = so.sink_function
        if not sink or len(sink) < 3:
            return ""

        logger.info("Discovering call chain for sink: %s", sink)
        chain_parts = []
        visited = set()
        current_func = sink
        current_file = so.sink_file

        for depth in range(5):  # walk up to 5 levels
            if current_func in visited:
                break
            visited.add(current_func)

            # Find callers of current_func in the codebase
            grep_r = self.env.exec(
                f"grep -rn '{current_func}' /src/ --include='*.cpp' --include='*.c' --include='*.cc' "
                f"2>/dev/null | grep -v '^\\.\\|define\\|typedef\\|/test/\\|_test\\.' | head -15",
                timeout=10)
            if not grep_r.stdout.strip():
                break

            callers = []
            for line in grep_r.stdout.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                # Skip the function's own definition
                parts = line.split(":", 2)
                if len(parts) < 3:
                    continue
                file_path, line_num, code = parts[0], parts[1], parts[2]
                # Skip if this is the definition itself (same file, or contains the function signature)
                if current_file and current_file in file_path and depth == 0:
                    # Could be the definition — check if it's a call or definition
                    if f"{current_func}(" not in code and f"{current_func} (" not in code:
                        continue
                callers.append((file_path, line_num, code.strip()))

            if not callers:
                break

            # Read context around the first few callers
            for file_path, line_num, code_snippet in callers[:3]:
                try:
                    ln = int(line_num)
                except ValueError:
                    continue

                # Read surrounding code to understand the calling context
                ctx_r = self.env.exec(
                    f"sed -n '{max(1, ln - 5)},{ln + 10}p' {file_path} 2>/dev/null",
                    timeout=5)
                ctx = ctx_r.stdout.strip() if ctx_r.stdout.strip() else code_snippet

                # Try to extract the enclosing function DEFINITION (not call).
                # Use ctags if available, fall back to regex for C/C++ definitions:
                # "type funcname(" at the start of a line, before the call line.
                func_r = self.env.exec(
                    f"sed -n '1,{ln}p' {file_path} 2>/dev/null | "
                    f"grep -nE '^[A-Za-z_].*\\b(\\w+)\\s*\\(' | "
                    f"grep -vE '^[0-9]+:\\s*(if|for|while|switch|return|else|sizeof|typeof|decltype|static_assert)\\b' | "
                    f"tail -3",
                    timeout=5)

                caller_name = "?"
                if func_r.stdout.strip():
                    # Last function definition before the call line
                    for fline in reversed(func_r.stdout.strip().split("\n")):
                        # Extract the function name (last word before "(")
                        m = re.search(r'(\w+)\s*\(', fline.split(":", 1)[-1] if ":" in fline else fline)
                        if m and m.group(1) not in ("if","for","while","switch","return",
                                                     "sizeof","typeof","decltype","defined"):
                            caller_name = m.group(1)
                            break

                chain_parts.append(
                    f"\n--- Level {depth}: {current_func} is called by {caller_name} "
                    f"in {file_path}:{line_num} ---\n{ctx[:500]}")

                # Check if this caller is in the public header
                if so.header_file and caller_name != "?":
                    hdr_check = self.env.exec(
                        f"grep '{caller_name}' {so.header_file} 2>/dev/null | head -2",
                        timeout=5)
                    if hdr_check.stdout.strip():
                        chain_parts.append(
                            f"\n✅ PUBLIC API FOUND: {caller_name} is declared in {so.header_file}:\n"
                            f"  {hdr_check.stdout.strip()[:300]}\n"
                            f"  → Call {caller_name}() in your harness to reach {sink}!")
                        # Found the public entry — stop walking
                        result = "\n".join(chain_parts)
                        logger.info("Call chain discovered: %s → ... → %s",
                                    caller_name, sink)
                        return result

                # Continue walking up from this caller
                current_func = caller_name if caller_name != "?" else current_func
                current_file = file_path
                break  # take the first caller at each level

        if chain_parts:
            result = "\n".join(chain_parts)
            logger.info("Partial call chain discovered (no public API found)")
            return result

        return ""

    # =================================================================
    # Helpers
    # =================================================================

    def _call_llm(self, fn, system, prompt):
        try: return fn(system, prompt)
        except Exception as e: logger.error("LLM failed: %s", e); return ""

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

        if self.sink_function in stack_text: return "target_sink"
        sb = self.sink_file.rsplit("/",1)[-1] if self.sink_file else ""
        if sb and sb in stack_text:
            for l in stack_lines:
                if sb in l and any(k in l for k in init_kw): return "init_crash"
            return "same_file"
        for l in stack_lines:
            if ("/src/" in l or "/work/build/" in l) and any(k in l for k in init_kw): return "init_crash"
        if any("/work/" in l and "/src/" not in l for l in stack_lines) and not any("/src/" in l for l in stack_lines):
            return "harness_bug"
        if any("/src/" in l for l in stack_lines): return "wrong_location"
        return "unknown_crash"

    def _check_sink_reachable(self) -> bool:
        """Use GDB to check if the sink function is reachable from the harness.

        Sets a breakpoint on the sink function, runs with test input.
        Returns True if the breakpoint is hit (sink IS reachable).
        This prevents the agent from rewriting correct harnesses when
        only the input needs to change.
        """
        inp = self._find_input_file()
        sink = self.so.sink_function
        if not sink or len(sink) < 3:
            return False  # can't check meaningfully

        # GDB batch: set breakpoint, run, check if it was hit
        gdb_cmd = (
            f"echo 'set confirm off\n"
            f"set pagination off\n"
            f"break {sink}\n"
            f"run {inp}\n"
            f"quit' | "
            f"ASAN_OPTIONS=detect_leaks=0:halt_on_error=0 "
            f"gdb -batch -q /work/harness 2>&1 | head -30"
        )
        r = self.env.exec(gdb_cmd, timeout=20)
        gdb_out = r.stdout or ""

        # GDB prints "Breakpoint 1, <function> ..." when hit
        hit = ("Breakpoint" in gdb_out and sink in gdb_out) or f"in {sink}" in gdb_out
        logger.info("Sink reachability check: %s → %s",
                     sink, "REACHABLE" if hit else "NOT REACHED")
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
        files = self.so.test_files or []
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

    def _craft_input(self):
        so = self.so; vc = so.vuln_tags[0] if so.vuln_tags else "unknown"
        guide = {
            "format_string": "Use %s, %n, %x format specifiers. The harness passes this data as a format string argument.",
            "buffer_overflow": "Exceed expected field lengths with long strings or huge counts.",
            "integer_overflow": "Set numeric fields to 0xFFFFFFFF or -1.",
            "type_confusion": "Change type tags or mix incompatible types.",
        }.get(vc, "Corrupt the input to exercise edge cases in the vulnerable path.")

        # Build rich context for the LLM
        sections = [f"Craft malformed {so.input_format} input to trigger {vc} at {so.sink_function}."]
        sections.append(f"\n{so.vuln_summary}")
        sections.append(f"\nTRACE:\n{so.trace_text}")
        if so.sink_source:
            sections.append(f"\nSINK CODE:\n{so.sink_source[:800]}")
        sections.append(f"\nSTRATEGY: {guide}")

        # Show how the harness uses the input — critical for crafting the right payload
        if so.last_harness_source:
            sections.append(f"\nHARNESS (how your input is consumed):\n```cpp\n{so.last_harness_source[:1500]}\n```")

        # Show what happened last time — the LLM can see error messages, "property not found", etc.
        if so.last_run_feedback:
            sections.append(f"\nLAST RUN OUTPUT (use this to fix your payload):\n{so.last_run_feedback[:500]}")

        # If there's a sample file, read a snippet so the LLM knows the format
        if so.test_files:
            sample_r = self.env.exec(f"head -c 200 {so.test_files[0]} 2>/dev/null | xxd | head -10", timeout=5)
            if sample_r.stdout.strip():
                sections.append(f"\nSAMPLE FILE ({so.test_files[0]}) hex dump:\n{sample_r.stdout.strip()[:500]}")
            sections.append(f"\nYou can also read/mutate the sample: {so.test_files[0]}")

        sections.append(f"\nWrite /work/craft.py that creates /work/crafted_input{so.input_ext}.")
        sections.append(f'<write_file path="/work/craft.py">\nimport struct\n# Create /work/crafted_input{so.input_ext}\n</write_file>')
        sections.append(f"<shell>python3 /work/craft.py</shell>")

        prompt = "\n".join(sections)
        resp = self._call_llm(self.llm_b,
            "Write a Python script to create a malformed input file. Output ONLY <write_file> and <shell>.",
            prompt)
        for a in parse_actions(resp):
            if a.kind == "write_file": self.env.write_file(a.path, a.content)
            elif a.kind == "shell": self.env.exec(a.content, timeout=30)
        c = self.env.exec("ls /work/crafted_input* 2>/dev/null | head -1", timeout=5)
        return c.stdout.strip().split("\n")[0] if c.stdout.strip() else ""

    def _ask_reviewer(self, context):
        try:
            r = self.llm_a("You review exploit development. Give specific advice.", f"GOAL: Trigger {self.so.sink_function} at {self.so.sink_file}\n\n{context}\n\nVerdict: REDIRECT or 'rewrite harness'.")
            return {"verdict": "REDIRECT", "message": r[:500]}
        except Exception as e: return {"verdict": "CONTINUE", "message": str(e)}

    def _run_verification(self, binary, input_file):
        return verify_harness(env=self.env, harness_binary=binary, input_file=input_file, sink_function=self.sink_function, sink_file=self.sink_file, library_name=self.profile.library_name, timeout=self.config.verify_timeout)

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


verification
"""GDB-based exploit verification.

Verifies that a harness actually reaches the vulnerable sink function
inside the REAL library code — not in the harness itself.

Verification methods:
  1. GDB breakpoint on sink function → confirms code path is exercised
  2. ASAN crash location check → confirms crash is in library, not harness
  3. Stack frame analysis → confirms sink function is on the call stack
  4. File-based matching → handles path abbreviations and mangled names
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from deeptrace.exploit.docker_env import DockerEnv, ExecResult

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Result of verifying a harness against the real target."""
    # Did the sink breakpoint get hit?
    sink_reached: bool = False
    sink_hit_count: int = 0
    sink_backtrace: str = ""

    # Did ASAN detect a crash?
    asan_crash: bool = False
    asan_crash_type: str = ""
    asan_location: str = ""       # file:line of the crash
    asan_in_library: bool = False  # crash inside the target lib (not harness)
    asan_trace: str = ""

    # Is the sink function present in the crash stack trace?
    sink_in_crash_stack: bool = False

    # Overall
    confirmed: bool = False       # crash in library with sink on the stack
    harness_compiled: bool = False
    harness_crashed_itself: bool = False  # crash in harness code (false positive)

    error: str = ""
    raw_output: str = ""

    @property
    def status_icon(self) -> str:
        if self.confirmed:
            return "🔴 CONFIRMED"
        if self.sink_reached and self.asan_crash:
            return "🟠 CRASH (check location)"
        if self.sink_reached:
            return "🟡 SINK REACHED"
        if self.harness_compiled:
            return "⚪ NO TRIGGER"
        return "⚫ COMPILE FAILED"

    @property
    def summary(self) -> str:
        if self.confirmed:
            return f"CONFIRMED: {self.asan_crash_type} at {self.asan_location}"
        if self.harness_crashed_itself:
            return f"FALSE POSITIVE: crash in harness code at {self.asan_location}"
        if self.sink_reached and self.asan_crash:
            return f"Crash at {self.asan_location} — sink reached but crash may be elsewhere"
        if self.sink_reached:
            return "Sink reached but no crash — try different inputs"
        if self.asan_crash and self.asan_in_library:
            return f"Library crash at {self.asan_location} — but sink not confirmed on stack"
        if self.harness_compiled:
            return "Harness compiled but sink not reached — adjust harness or input"
        return f"Compilation failed: {self.error[:200]}"


def verify_harness(
    env: DockerEnv,
    harness_binary: str,
    input_file: str,
    sink_function: str,
    sink_file: str = "",
    library_name: str = "",
    timeout: int = 30,
) -> VerificationResult:
    """Run a harness under GDB with a breakpoint on the sink function.

    Strategy:
      1. Run under GDB to check if sink is reached (breakpoint)
      2. Run directly to get clean ASAN output
      3. Cross-reference: is the sink function on the crash stack?

    Args:
        env: Running Docker environment.
        harness_binary: Path to compiled harness binary inside container.
        input_file: Path to input file inside container.
        sink_function: Function name to set breakpoint on.
        sink_file: Source file containing the sink (for location check).
        library_name: Library name to check crash location against.
        timeout: Execution timeout in seconds.

    Returns:
        VerificationResult with detailed information about what happened.
    """
    result = VerificationResult()

    # Verify binary exists
    check = env.exec(f"test -x {harness_binary} && echo y", timeout=5)
    if check.stdout.strip() != "y":
        result.error = f"{harness_binary} not found or not executable"
        return result
    result.harness_compiled = True

    # ── Step 1: GDB breakpoint verification ──────────────────────────
    gdb_script = _generate_gdb_script(harness_binary, input_file, sink_function)
    env.write_file("/work/verify.gdb", gdb_script)

    logger.info("Verification step 1: GDB breakpoint on %s", sink_function)
    gdb_result = env.exec(
        "ASAN_OPTIONS=detect_leaks=0:halt_on_error=0 "
        "gdb -batch -x /work/verify.gdb 2>&1",
        timeout=timeout,
    )
    result.raw_output = gdb_result.output or ""

    _parse_gdb_output(result, gdb_result.output or "", sink_function, sink_file)

    # ── Step 2: Direct run for clean ASAN output ─────────────────────
    logger.info("Verification step 2: direct ASAN run")
    direct_result = env.exec(
        f"ASAN_OPTIONS=detect_leaks=0:print_stacktrace=1:halt_on_error=1 "
        f"timeout {timeout} {harness_binary} {input_file} 2>&1",
        timeout=timeout + 5,
    )
    result.raw_output += "\n\n--- Direct run ---\n" + (direct_result.output or "")

    _parse_asan_output(result, direct_result.output or "",
                       sink_function, sink_file, library_name)

    # ── Step 3: Determine confirmation status ────────────────────────
    # CONFIRMED requires:
    #   - A crash happened (ASAN or signal)
    #   - The crash is in library code (not harness)
    #   - The sink function is on the stack (either via GDB breakpoint
    #     or by finding it in the ASAN stack trace)
    if result.asan_crash and result.asan_in_library:
        if result.sink_reached or result.sink_in_crash_stack:
            result.confirmed = True
        else:
            # Crash in library but sink not on stack — could be init crash
            # or wrong code path.  Don't confirm, but don't call it a
            # harness crash either.
            logger.warning("Verification: crash in library at %s but sink %s not on stack",
                           result.asan_location, sink_function)
    elif result.asan_crash and not result.asan_in_library:
        result.harness_crashed_itself = True
    elif not result.asan_crash and result.sink_reached:
        # Sink reached but no crash — harness works but input isn't triggering
        pass
    elif not result.asan_crash:
        # Check for non-ASAN crash (segfault caught by GDB)
        if "Program received signal" in result.raw_output:
            result.asan_crash = True
            sig = re.search(r"Program received signal (\w+)", result.raw_output)
            result.asan_crash_type = sig.group(1) if sig else "SIGNAL"
            # Use GDB backtrace to determine if it's in library
            if result.sink_reached or result.sink_in_crash_stack:
                result.asan_in_library = True
                result.confirmed = True

    logger.info("Verification result: %s (sink_reached=%s, sink_in_stack=%s, "
                "asan_crash=%s, in_library=%s)",
                result.status_icon, result.sink_reached, result.sink_in_crash_stack,
                result.asan_crash, result.asan_in_library)
    return result


def _generate_gdb_script(binary: str, input_file: str, sink_function: str) -> str:
    """Generate a GDB batch script that sets a breakpoint on the sink.

    CRITICAL: The `commands` block MUST be defined BEFORE `run`.
    GDB processes commands sequentially — if `commands` comes after `run`,
    the breakpoint fires before the commands are registered, and the
    SINK_BREAKPOINT_HIT marker is never printed.
    """
    return f"""# Auto-generated GDB verification script
set pagination off
set confirm off
set print thread-events off

# Suppress ASAN signal handling so GDB sees breakpoints, not ASAN signals
handle SIGSEGV nostop noprint pass
handle SIGBUS nostop noprint pass
handle SIGABRT stop print nopass

# Load the binary
file {binary}

# Set breakpoint on the sink function
break {sink_function}

# Define what happens when breakpoint is hit — MUST be before run
commands
  silent
  echo \\n=== SINK_BREAKPOINT_HIT ===\\n
  backtrace 20
  echo \\n=== END_BACKTRACE ===\\n
  continue
end

# Run with the input
run {input_file}

# If we get here, program exited or crashed after the breakpoint
# Print final backtrace in case of crash
echo \\n=== FINAL_STATE ===\\n
backtrace 20
echo \\n=== END_FINAL ===\\n
quit
"""


def _parse_gdb_output(
    result: VerificationResult,
    output: str,
    sink_function: str,
    sink_file: str,
) -> None:
    """Parse GDB output for breakpoint hits and backtraces."""

    # Check for breakpoint hits
    if "SINK_BREAKPOINT_HIT" in output:
        result.sink_reached = True
        result.sink_hit_count = output.count("SINK_BREAKPOINT_HIT")

        # Extract backtrace from the breakpoint hit
        bt_match = re.search(
            r"=== SINK_BREAKPOINT_HIT ===\s*(.*?)=== END_BACKTRACE ===",
            output, re.DOTALL,
        )
        if bt_match:
            result.sink_backtrace = bt_match.group(1).strip()
    else:
        # Breakpoint might not have fired if GDB can't resolve the symbol.
        # Check if GDB said "Make breakpoint pending" or "not defined"
        if "Make breakpoint pending" in output or "not defined" in output:
            logger.warning("GDB could not resolve breakpoint for %s — "
                           "symbol may be mangled or inlined", sink_function)

            # Try to find sink in the crash backtrace instead
            final_bt = re.search(
                r"=== FINAL_STATE ===\s*(.*?)=== END_FINAL ===",
                output, re.DOTALL,
            )
            if final_bt:
                bt_text = final_bt.group(1)
                if _function_in_backtrace(sink_function, bt_text, sink_file):
                    result.sink_reached = True
                    result.sink_in_crash_stack = True
                    result.sink_backtrace = bt_text.strip()
                    logger.info("Found sink %s in crash backtrace (GDB breakpoint failed)",
                                sink_function)

    # Check for signal delivery (crash under GDB)
    if "Program received signal" in output:
        sig_match = re.search(r"Program received signal (\w+)", output)
        if sig_match:
            result.asan_crash = True
            result.asan_crash_type = sig_match.group(1)

        # Check final backtrace for sink presence (crash might be AT the sink)
        final_bt = re.search(
            r"=== FINAL_STATE ===\s*(.*?)=== END_FINAL ===",
            output, re.DOTALL,
        )
        if final_bt:
            bt_text = final_bt.group(1)
            if _function_in_backtrace(sink_function, bt_text, sink_file):
                result.sink_in_crash_stack = True


def _parse_asan_output(
    result: VerificationResult,
    output: str,
    sink_function: str,
    sink_file: str,
    library_name: str,
) -> None:
    """Parse ASAN output to determine crash type, location, and whether
    the sink function is on the crash stack."""

    # Check for ASAN errors
    asan_match = re.search(r"ERROR: AddressSanitizer: ([^\s:]+)", output)
    if asan_match:
        result.asan_crash = True
        result.asan_crash_type = asan_match.group(1)

    # Also check SUMMARY line (sometimes ERROR line is missing)
    if not result.asan_crash_type:
        summary_match = re.search(r"SUMMARY: AddressSanitizer: (\S+)", output)
        if summary_match:
            result.asan_crash = True
            result.asan_crash_type = summary_match.group(1)

    if not result.asan_crash:
        return

    # Extract the full crash stack trace
    trace_match = re.search(r"(#0.*?)(?:\n\n|\nSUMMARY:)", output, re.DOTALL)
    if trace_match:
        result.asan_trace = trace_match.group(1).strip()

    # Parse ALL frames from the ASAN trace
    # Format: #N 0xaddr in function_name file.cpp:line[:col]
    # Also:   #N 0xaddr in function_name (module+0xoffset)
    # Also:   #N 0xaddr  (/path/to/binary+0xoffset)
    frames = _parse_asan_frames(output)

    if not frames:
        return

    # ── Determine crash location and library membership ──────────────
    # Walk ALL frames to find the first one in real code (skip libc/asan)
    sink_file_base = sink_file.rsplit("/", 1)[-1] if sink_file else ""

    for func_name, file_loc in frames:
        file_part = file_loc.split(":")[0] if file_loc else ""

        # Skip ASAN/libc internals
        if any(skip in func_name for skip in
               ("__asan", "__interceptor", "__sanitizer", "__libc")):
            continue
        if any(skip in file_part for skip in
               ("/asan/", "/sanitizer/", "/libc/")):
            continue

        # This is the first meaningful frame — set as crash location
        if not result.asan_location:
            result.asan_location = file_loc or func_name

        # Check if this frame is in the library (not in harness or system)
        in_library = _frame_in_library(func_name, file_part,
                                        sink_file, sink_file_base,
                                        library_name)
        if in_library and not result.asan_in_library:
            result.asan_in_library = True
            result.asan_location = file_loc or func_name

        # Check if this frame IS the sink function
        if _function_matches_sink(func_name, sink_function):
            result.sink_in_crash_stack = True
            result.asan_in_library = True
            if file_loc:
                result.asan_location = file_loc
            break  # found the sink, no need to keep looking

    # If no frames had source info, check by function names alone
    if not result.asan_in_library:
        for func_name, _ in frames:
            if _function_matches_sink(func_name, sink_function):
                result.sink_in_crash_stack = True
                result.asan_in_library = True
                break

    # Check if harness crashed (first non-ASAN frame is in /work/)
    if not result.asan_in_library:
        for func_name, file_loc in frames:
            file_part = file_loc.split(":")[0] if file_loc else ""
            if any(skip in func_name for skip in
                   ("__asan", "__interceptor", "__sanitizer")):
                continue
            if "/work/harness" in file_part or "/work/fuzz" in file_part:
                result.harness_crashed_itself = True
            break  # only check first meaningful frame


def _parse_asan_frames(output: str) -> list[tuple[str, str]]:
    """Parse ASAN stack frames into (function_name, file_location) tuples.

    Handles multiple ASAN output formats:
      #0 0xaddr in func_name file.c:line
      #0 0xaddr in func_name file.c:line:col
      #0 0xaddr in func_name (/path/module+0xoffset)
      #0 0xaddr  (/path/module+0xoffset)
    """
    frames: list[tuple[str, str]] = []

    for line in output.split("\n"):
        line = line.strip()
        if not re.match(r"#\d+", line):
            continue

        # Format: #N 0xaddr in function_name file:line
        m = re.match(
            r"#\d+\s+0x[\da-f]+\s+in\s+(\S+)\s+(\S+:\d+(?::\d+)?)",
            line,
        )
        if m:
            frames.append((m.group(1), m.group(2)))
            continue

        # Format: #N 0xaddr in function_name (module+0xoffset)
        m = re.match(
            r"#\d+\s+0x[\da-f]+\s+in\s+(\S+)\s+\(([^)]+)\)",
            line,
        )
        if m:
            frames.append((m.group(1), m.group(2)))
            continue

        # Format: #N 0xaddr  (module+0xoffset)  — no function name
        m = re.match(
            r"#\d+\s+0x[\da-f]+\s+\(([^)]+)\)",
            line,
        )
        if m:
            frames.append(("??", m.group(1)))
            continue

        # Format: #N 0xaddr in function_name  — no file/module
        m = re.match(
            r"#\d+\s+0x[\da-f]+\s+in\s+(\S+)",
            line,
        )
        if m:
            frames.append((m.group(1), ""))
            continue

    return frames


def _function_matches_sink(func_name: str, sink_function: str) -> bool:
    """Check if a function name from ASAN/GDB matches the target sink.

    Handles:
      - Exact match: "snprintf" == "snprintf"
      - C++ mangling: "_Z7snprintfPcmPKcz" contains "snprintf"
      - Namespace prefix: "std::snprintf" ends with "::snprintf"
      - Partial match: "cmsIT8SetPropertyDbl" in "CMSEXPORT_cmsIT8SetPropertyDbl"
    """
    if not func_name or not sink_function or func_name == "??":
        return False

    # Exact match
    if func_name == sink_function:
        return True

    # Sink function appears as a substring (handles mangled names)
    if sink_function in func_name:
        return True

    # Check if the func ends with ::sink_function (namespace qualified)
    if func_name.endswith("::" + sink_function):
        return True

    # For very short sink names (e.g., "free"), require exact match only
    # to avoid false positives
    if len(sink_function) <= 4:
        return func_name == sink_function

    return False


def _function_in_backtrace(
    sink_function: str,
    backtrace: str,
    sink_file: str,
) -> bool:
    """Check if the sink function appears anywhere in a GDB backtrace.

    More lenient than _function_matches_sink — checks the raw text
    of the backtrace for the sink function name or file.
    """
    if not backtrace:
        return False

    # Direct function name match in any frame
    if sink_function in backtrace:
        return True

    # Check by file basename
    if sink_file:
        base = sink_file.rsplit("/", 1)[-1]
        if base and base in backtrace:
            return True

    return False


def _frame_in_library(
    func_name: str,
    file_part: str,
    sink_file: str,
    sink_file_base: str,
    library_name: str,
) -> bool:
    """Determine if a stack frame is in the target library.

    Uses multiple heuristics to handle different path formats.
    """
    # In harness code — definitely NOT in library
    if "/work/harness" in file_part or "/work/fuzz" in file_part:
        return False

    # In /src/ — the library source mount point
    if file_part.startswith("/src/"):
        return True

    # File basename matches sink file basename
    if sink_file_base:
        frame_base = file_part.rsplit("/", 1)[-1] if "/" in file_part else file_part
        if frame_base == sink_file_base:
            return True

    # Sink file path appears in the frame's file path (or vice versa)
    if sink_file and file_part:
        if sink_file in file_part or file_part in sink_file:
            return True
        # Compare basenames (handles /src/lib/foo.c vs foo.c)
        sink_base = sink_file.rsplit("/", 1)[-1]
        frame_base = file_part.rsplit("/", 1)[-1]
        if sink_base and sink_base == frame_base:
            return True

    # Library name appears in the file path
    if library_name and library_name.lower() in file_part.lower():
        return True

    # Library name appears in the function name (e.g., "cms" in "cmsIT8Alloc")
    if library_name and len(library_name) > 2:
        if library_name.lower() in func_name.lower():
            return True

    return False


docker_env
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
