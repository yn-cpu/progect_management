"""Interactive exploit agent: worker/reviewer dual-LLM architecture.

Two models in separate sessions:
  WORKER  — does the task (explore, write code, compile)
  REVIEWER — evaluates progress in a fresh session every N turns,
             decides: CONTINUE / REDIRECT / TRANSITION

The system handles mechanical work (linking, running, sweeping, verifying).
No hard turn limits per phase — the reviewer decides when to move on.
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


class AgentState(Enum):
    EXPLORE = auto()
    CODE = auto()
    PIPELINE = auto()
    SUCCESS = auto()
    HALTED = auto()


_ACTION_FORMAT_BLOCK = """
=== TOOLS ===

<think>your reasoning</think>
  Optional. Plan before acting.

<shell>command</shell>
  Run a shell command. You see stdout+stderr.

<write_file path="/work/file.cpp">
content
</write_file>
  Write a file.

<read_file path="/src/file.c" />
  Read a file.

<submit path="/work/harness" input="/work/input.dat">
  Explanation of what triggers the vulnerability.
</submit>
  Submit for verification.

<done reason="summary" />
  Signal phase completion.

=== RULES ===
- Every response MUST have at least one tool tag
- If compilation fails, read the SPECIFIC error and fix THAT issue
- Use gdb when crashes happen — do NOT guess
"""

_EXPLORER_PROMPT = f"""You are a security researcher exploring a C/C++ repository.
Source at /src/. Workspace at /work/.
{_ACTION_FORMAT_BLOCK}
Find: build system, public headers, existing fuzzers/tests, test data files."""

_CODER_PROMPT = f"""You are an exploit developer with shell access.
Source at /src/. Workspace at /work/.
{_ACTION_FORMAT_BLOCK}
Write /work/harness.cpp calling REAL library functions (NO stubs).
Compile: g++ -fsanitize=address -g -I/src harness.cpp -c -o harness.o
After .o compiles, the system auto-handles linking and testing."""

_SYSTEM_PROMPT = f"""You are an exploit developer with shell access.
Source at /src/. Workspace at /work/.
{_ACTION_FORMAT_BLOCK}
1. Explore /src/ — find headers, tests, build system
2. Write /work/harness.cpp calling REAL library functions
3. Compile: g++ -fsanitize=address -g -I/src harness.cpp -c -o harness.o"""

_REVIEWER_PROMPT = """You are a senior security researcher reviewing an agent's progress.

You see: the GOAL, current STATE, recent ACTIONS and results, workspace ARTIFACTS.

Respond with EXACTLY ONE verdict:

CONTINUE — agent is making progress, let it work.
REDIRECT: <specific instruction> — agent is stuck. Tell it EXACTLY what to do.
TRANSITION: <summary> — current phase is done. Summarize findings for the next phase.

Be concrete: "add -I/src/third_party/lcms/include" not "fix the include path"."""


@dataclass
class AgentAction:
    kind: str
    content: str = ""
    path: str = ""


def parse_actions(response: str) -> list[AgentAction]:
    actions: list[AgentAction] = []
    for m in re.finditer(r"<shell>(.*?)</shell>", response, re.DOTALL):
        if cmd := m.group(1).strip():
            actions.append(AgentAction(kind="shell", content=cmd))
    for m in re.finditer(r'<write_file\s+path="([^"]+)">(.*?)</write_file>', response, re.DOTALL):
        actions.append(AgentAction(kind="write_file", path=m.group(1), content=m.group(2)))
    for m in re.finditer(r'<read_file\s+path="([^"]+)"\s*/>', response):
        actions.append(AgentAction(kind="read_file", path=m.group(1)))
    for m in re.finditer(r'<done\s+reason="([^"]*)"', response):
        actions.append(AgentAction(kind="done", content=m.group(1)))
    for m in re.finditer(r"<done>(.*?)</done>", response, re.DOTALL):
        if not any(a.kind == "done" for a in actions):
            actions.append(AgentAction(kind="done", content=m.group(1).strip()))
    for m in re.finditer(r'<submit\s+path="([^"]+)"(?:\s+input="([^"]*)")?\s*>(.*?)</submit>', response, re.DOTALL):
        actions.append(AgentAction(kind="submit", path=m.group(1),
            content=f"input={m.group(2) or '/work/input.dat'}|{m.group(3).strip()}"))
    if actions:
        return actions
    for m in re.finditer(r"```(?:bash|sh|shell)\s*\n([\s\S]*?)\n\s*```", response):
        for line in m.group(1).strip().split("\n"):
            s = line.strip()
            if s and not s.startswith("#"):
                actions.append(AgentAction(kind="shell", content=s))
    for m in re.finditer(r"```(?:cpp|c\+\+|c)\s*\n([\s\S]*?)\n\s*```", response):
        code = m.group(1).strip()
        if "#include" in code and ("int main" in code or "LLVMFuzzerTestOneInput" in code):
            actions.append(AgentAction(kind="write_file", path="/work/harness.cpp", content=code))
    if not actions:
        for line in response.split("\n"):
            s = line.strip()
            if s.startswith("$ ") and (cmd := s[2:].strip()):
                actions.append(AgentAction(kind="shell", content=cmd))
            elif re.match(r'^(ls |cat |grep |find |head |g\+\+|gcc |make )', s):
                actions.append(AgentAction(kind="shell", content=s))
    return actions


def extract_thought(response: str) -> str:
    m = re.search(r"<think>(.*?)</think>", response, re.DOTALL)
    return m.group(1).strip() if m else ""


@dataclass
class AgentConfig:
    max_turns: int = 80
    review_interval: int = 3
    max_actions_per_turn: int = 10
    exec_timeout: int = 60
    verify_timeout: int = 30
    context_window: int = 12


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


class ExploitAgent:

    def __init__(self, llm_caller, env, profile, trace_path, sink_function, sink_file,
                 config=None, progress_callback=None, llm_coder=None):
        self.llm_model_a = llm_caller
        self.llm_model_b = llm_coder if llm_coder else llm_caller
        self.dual_model = llm_coder is not None
        self.env = env
        self.profile = profile
        self.trace = trace_path
        self.sink_function = sink_function
        self.sink_file = sink_file
        self.config = config or AgentConfig()
        self._progress = progress_callback
        self._exchanges: list[tuple[str, str]] = []
        self.state = AgentState.EXPLORE if self.dual_model else AgentState.CODE
        self._exploration_summary = ""
        self._pipeline_ran = False
        self.llm_call = llm_caller
        self.llm_code = self.llm_model_b

    def _get_reviewer(self):
        return self.llm_model_b if self.state == AgentState.EXPLORE else self.llm_model_a

    def run(self) -> AgentResult:
        t0 = time.time()
        result = AgentResult()
        initial_context = self._build_initial_context()
        result.log.append({"event": "agent_start", "state": self.state.name,
                           "dual_model": self.dual_model, "sink": self.sink_function,
                           "repo": self.profile.repo_name, "max_turns": self.config.max_turns})
        turns_in_phase = 0

        for turn in range(self.config.max_turns):
            turn_log = {"event": "turn", "turn": turn+1, "state": self.state.name, "timestamp": time.time()}
            if self.state in (AgentState.SUCCESS, AgentState.HALTED):
                break
            if self._progress:
                self._progress(f"Turn {turn+1}/{self.config.max_turns} [{self.state.name}]", turn)

            turns_in_phase += 1

            # --- REVIEWER ---
            if turns_in_phase > 1 and turns_in_phase % self.config.review_interval == 0:
                review = self._run_review()
                turn_log["review"] = review
                if review["verdict"] == "TRANSITION":
                    logger.info("Reviewer: TRANSITION")
                    if self.state == AgentState.EXPLORE:
                        self._exploration_summary = review["message"]
                        self._transition_to_code(result)
                        self.state = AgentState.CODE
                        turns_in_phase = 0
                        turn_log["transition"] = "EXPLORE->CODE"
                        result.log.append(turn_log)
                        continue
                elif review["verdict"] == "REDIRECT":
                    logger.info("Reviewer: REDIRECT")
                    self._exchanges.append(("(reviewer)", f"📋 REVIEWER:\n{review['message']}"))
                    turn_log["redirect"] = review["message"][:500]

            # --- SELECT WORKER ---
            if self.state == AgentState.EXPLORE:
                llm_fn, sys_prompt = self.llm_model_a, _EXPLORER_PROMPT
                prompt = self._build_prompt(initial_context)
            elif self.state == AgentState.CODE:
                llm_fn = self.llm_model_b
                sys_prompt = _CODER_PROMPT if self.dual_model else _SYSTEM_PROMPT
                prompt = self._build_coder_prompt(initial_context)
            else:
                break

            logger.info("Turn %d/%d [%s]", turn+1, self.config.max_turns, self.state.name)
            try:
                response = llm_fn(sys_prompt, prompt)
            except Exception as exc:
                logger.error("Worker failed: %s", exc)
                turn_log["error"] = str(exc)
                result.log.append(turn_log)
                continue

            turn_log["llm_response"] = response[:8000]
            if thought := extract_thought(response):
                turn_log["thought"] = thought[:2000]

            actions = parse_actions(response)
            if not actions:
                self._exchanges.append((response[:500], "(NO ACTIONS) Use <shell> or <write_file>."))
                result.log.append(turn_log)
                continue

            action_results, action_logs, done = self._execute_actions(actions[:self.config.max_actions_per_turn], result)
            results_str = "\n\n".join(action_results)
            self._exchanges.append((response[:3000], results_str[:3000]))
            turn_log["actions"] = action_logs
            result.turns_used = turn + 1

            if done:
                turn_log["success"] = result.success
                result.log.append(turn_log)
                break

            # --- PIPELINE TRIGGER ---
            if self.state == AgentState.CODE and not self._pipeline_ran:
                obj = self._detect_successful_compile(action_logs)
                if obj and self.env.exec(f"test -s {obj} && echo y", timeout=5).stdout.strip() == "y":
                    logger.info(".o verified -> PIPELINE")
                    self._pipeline_ran = True
                    self.state = AgentState.PIPELINE
                    pipe_out, pipe_ok = self._run_pipeline(result)
                    if pipe_out:
                        self._exchanges[-1] = (self._exchanges[-1][0], self._exchanges[-1][1] + f"\n\n{pipe_out}")
                        turn_log["pipeline"] = pipe_out[:3000]
                    if pipe_ok:
                        self.state = AgentState.SUCCESS
                        result.log.append(turn_log)
                        break
                    self.state = AgentState.CODE

            for a in actions:
                if a.kind == "write_file" and a.path.endswith((".cpp", ".cc", ".c")):
                    self._pipeline_ran = False

            # Deterministic stall checks (cheap, always run)
            stall = self._detect_stall(turn, results_str)
            if stall:
                self._exchanges[-1] = (
                    self._exchanges[-1][0],
                    self._exchanges[-1][1] + f"\n\n{stall}",
                )
                turn_log["stall_hint"] = stall[:500]

            result.log.append(turn_log)

        result.elapsed_seconds = round(time.time() - t0, 2)
        if not result.success:
            result.postmortem = self._generate_postmortem(result)
        result.log.append({"event": "agent_end", "success": result.success,
                           "turns": result.turns_used, "elapsed": result.elapsed_seconds})
        return result

    # === REVIEWER ===
    def _run_review(self) -> dict[str, str]:
        try:
            response = self._get_reviewer()(_REVIEWER_PROMPT, self._build_review_snapshot())
        except Exception as exc:
            return {"verdict": "CONTINUE", "message": f"Review failed: {exc}"}
        return self._parse_review(response)

    def _build_review_snapshot(self) -> str:
        parts = [f"GOAL: Trigger {self.sink_function} at {self.sink_file}",
                 f"Vuln: {', '.join(self.trace.vulnerability_tags or ['unknown'])}",
                 f"State: {self.state.name}, Turns: {len(self._exchanges)}"]
        arts = self.env.exec("ls -la /work/harness* /work/*.o /work/*.cpp /work/input* 2>/dev/null", timeout=5)
        parts.append(f"\nARTIFACTS:\n{arts.stdout.strip() or '(empty)'}")
        compiled = self.env.exec("test -f /work/harness.o && echo Y", timeout=5).stdout.strip() == "Y"
        linked = self.env.exec("test -x /work/harness && echo Y", timeout=5).stdout.strip() == "Y"
        parts.append(f"Compiled: {compiled}  Linked: {linked}")
        parts.append("\nRECENT:")
        for i, (resp, res) in enumerate(self._exchanges[-3:]):
            cmds = re.findall(r"<shell>(.*?)</shell>", resp, re.DOTALL)
            writes = re.findall(r'<write_file\s+path="([^"]+)"', resp)
            summary = []
            if cmds: summary.append(f"ran: {', '.join(c[:50] for c in cmds[:3])}")
            if writes: summary.append(f"wrote: {', '.join(writes)}")
            has_err = "error:" in res.lower()
            icon = "❌" if has_err else "✅"
            parts.append(f"  {icon} {'; '.join(summary) or '(no actions)'}")
            if has_err:
                for line in res.split("\n"):
                    if "error:" in line.lower():
                        parts.append(f"    -> {line.strip()[:120]}")
                        break
        if self.state == AgentState.EXPLORE:
            parts.append("\nHas the agent found enough to write a harness? (headers, API, test data)")
        else:
            parts.append("\nIs the agent making progress on compilation, or going in circles?")
        return "\n".join(parts)

    @staticmethod
    def _parse_review(response: str) -> dict[str, str]:
        t = response.strip()
        if t.upper().startswith("TRANSITION"):
            return {"verdict": "TRANSITION", "message": t.split(":", 1)[1].strip() if ":" in t else t}
        if t.upper().startswith("REDIRECT"):
            return {"verdict": "REDIRECT", "message": t.split(":", 1)[1].strip() if ":" in t else t}
        lower = t.lower()
        if "transition" in lower and ("complete" in lower or "move on" in lower):
            return {"verdict": "TRANSITION", "message": t}
        if "redirect" in lower or "stuck" in lower or "circles" in lower:
            return {"verdict": "REDIRECT", "message": t}
        return {"verdict": "CONTINUE", "message": t[:200]}

    # === ACTIONS ===
    def _execute_actions(self, actions, result):
        action_results, action_logs, done = [], [], False
        for action in actions:
            result.total_actions += 1
            alog = {"kind": action.kind}
            if action.kind == "shell":
                r = self.env.exec(action.content, timeout=self.config.exec_timeout)
                s = self._smart_truncate_output(action.content, r.exit_code, r.output)
                action_results.append(f"[shell] $ {action.content}\nexit_code={r.exit_code}\n{s}")
                alog.update(command=action.content, exit_code=r.exit_code, output=s[:2000])
            elif action.kind == "write_file":
                wr = self.env.write_file(action.path, action.content)
                action_results.append(f"[write_file] {'OK' if wr.success else 'FAIL'}: {action.path}")
                alog.update(path=action.path, success=wr.success)
            elif action.kind == "read_file":
                action_results.append(f"[read_file] {action.path}:\n{self.env.read_file(action.path)[:3000]}")
            elif action.kind == "submit":
                parts = action.content.split("|", 1)
                inp = parts[0].replace("input=", "").strip()
                vr = self._run_verification(action.path, inp)
                result.verification = vr
                action_results.append(f"=== VERIFY: {vr.status_icon} {vr.summary} ===")
                if vr.confirmed:
                    result.success, result.harness_path, result.input_path = True, action.path, inp
                    done = True
                else:
                    action_results.append(f"❌ {vr.summary}")
                break
            elif action.kind == "done":
                if self.state == AgentState.EXPLORE:
                    self._exploration_summary = action.content
                    self._transition_to_code(None)
                    self.state = AgentState.CODE
                else:
                    result.final_reason = action.content
                    done = True
                break
            action_logs.append(alog)
        return action_results, action_logs, done

    # === PIPELINE ===
    def _run_pipeline(self, result):
        parts = ["", "=" * 60, "AUTO-PIPELINE: link -> run -> sweep -> craft", "=" * 60]
        # LINK
        parts.append("\n📦 LINK...")
        ok = self.env.exec("test -x /work/harness && echo y", timeout=5).stdout.strip() == "y"
        if not ok:
            objs = self.env.exec("ls /work/*.o 2>/dev/null", timeout=5).stdout.replace("\n", " ").strip()
            if objs:
                self.env.exec(f"g++ -fsanitize=address -g {objs} -o /work/harness -lpthread -ldl 2>&1", timeout=60)
                ok = self.env.exec("test -x /work/harness && echo y", timeout=5).stdout.strip() == "y"
            if not ok:
                parts.append("  Direct link failed -> resolving...")
                parts.append(self._resolve_linking()[:2000])
                ok = self.env.exec("test -x /work/harness && echo y", timeout=5).stdout.strip() == "y"
        if not ok:
            parts.append("\n❌ Link failed.")
            self._scrub_context_for_linker()
            return "\n".join(parts), False
        parts.append("  ✅ Binary ready.")
        # RUN
        parts.append("\n▶️  RUN...")
        inp = self._find_input_file()
        run_out = self._run_harness(inp)
        parts.append(run_out[:1500])
        if self._is_library_crash(run_out):
            return self._finalize(result, inp, parts)
        # SWEEP
        parts.append("\n🔍 SWEEP...")
        crash = self._sweep_inputs()
        if crash:
            return self._finalize(result, crash, parts)
        parts.append("  No crashes.")
        # CRAFT
        parts.append("\n🧠 CRAFT...")
        crafted = self._craft_input()
        if crafted:
            cr = self._run_harness(crafted)
            parts.append(cr[:1000])
            if self._is_library_crash(cr):
                return self._finalize(result, crafted, parts)
        parts.append("\n⚠️ No crash. Modify harness to exercise more of the trace.")
        return "\n".join(parts), False

    def _finalize(self, result, inp, parts):
        parts.append("\n🔴 CRASH -> verifying...")
        vr = self._run_verification("/work/harness", inp)
        result.verification = vr
        if vr.confirmed:
            result.success, result.harness_path, result.input_path = True, "/work/harness", inp
            self.state = AgentState.SUCCESS
            parts.append(f"  ✅ CONFIRMED: {vr.summary}")
            return "\n".join(parts), True
        parts.append(f"  ❌ {vr.summary}")
        return "\n".join(parts), False

    def _run_harness(self, inp):
        r = self.env.exec(f"timeout 20 /work/harness {inp} 2>&1", timeout=30)
        return self._smart_truncate_output(f"/work/harness {inp}", r.exit_code, r.output or "")

    def _is_library_crash(self, output: str) -> bool:
        """Check if ASAN output shows a crash in the library near the target sink.

        Not just any ASAN crash — we verify the crash stack trace mentions
        the sink function or at least the sink file. This prevents false
        positives from unrelated crashes.
        """
        if "AddressSanitizer" not in output or "/src/" not in output:
            return False

        # Best case: sink function name appears in the stack trace
        if self.sink_function in output:
            return True

        # Good case: sink file appears in the stack trace
        sink_basename = self.sink_file.rsplit("/", 1)[-1] if self.sink_file else ""
        if sink_basename and sink_basename in output:
            return True

        # Fallback: any crash in /src/ still counts — the trace might not
        # include the exact sink if it crashed in a callee. But log it.
        logger.warning("ASAN crash in /src/ but sink '%s' not in trace — accepting as potential hit",
                       self.sink_function)
        return True

    def _find_input_file(self):
        r = self.env.exec("ls /work/input.* /work/crash_input 2>/dev/null | head -1", timeout=5)
        if r.stdout.strip(): return r.stdout.strip().split("\n")[0]
        self.env.exec("cp $(find /src -type f \\( -name '*.pdf' -o -name '*.it8' -o -name '*.icc' -o -name '*.xml' \\) 2>/dev/null | head -1) /work/input.dat 2>/dev/null", timeout=10)
        return "/work/input.dat"

    def _sweep_inputs(self):
        harness = self.env.exec("cat /work/harness.cpp 2>/dev/null", timeout=5).stdout or ""
        exts = "*.pdf -o -name *.xml -o -name *.png -o -name *.bin"
        for kw, ext in [("cms", "*.it8 -o -name *.icc"), ("pdf", "*.pdf"), ("xml", "*.xml"), ("png", "*.png")]:
            if kw in harness.lower():
                exts = ext
                break
        find = self.env.exec(f"find /src -type f \\( -name {exts} \\) 2>/dev/null | head -50", timeout=15)
        if not find.stdout.strip(): return ""
        for tf in find.stdout.strip().split("\n"):
            tf = tf.strip()
            if not tf: continue
            r = self.env.exec(f"timeout 10 /work/harness {tf} 2>&1", timeout=15)
            if self._is_library_crash(r.output or ""):
                self.env.exec(f"cp {tf} /work/crash_input", timeout=5)
                return "/work/crash_input"
        return ""

    # === LINKING ===
    def _resolve_linking(self):
        nm = self.env.exec("nm /work/harness.o 2>/dev/null | grep ' U ' | grep -v '__asan\\|__cxa\\|__stack\\|_Unwind\\|__gxx\\|_GLOBAL\\|_Z.*std' | awk '{print $2}' | head -20", timeout=10)
        if not nm.stdout.strip(): return "No undefined symbols."
        undefined = [s.strip() for s in nm.stdout.strip().split("\n") if s.strip()]
        parts = [f"Undefined: {', '.join(undefined[:8])}"]
        src_map = {}
        for sym in undefined[:5]:
            dem = self.env.exec(f"echo '{sym}' | c++filt 2>/dev/null", timeout=5)
            func = (dem.stdout.strip() if dem.success else sym).split("(")[0].split("::")[-1].split("<")[0].strip()
            if len(func) < 3: continue
            grep = self.env.exec(f"grep -rn '{func}' /src/ --include='*.c' --include='*.cc' --include='*.cpp' -l 2>/dev/null | grep -v '_test\\|_fuzzer' | head -5", timeout=15)
            if grep.stdout.strip():
                for f in grep.stdout.strip().split("\n"):
                    if f.strip(): src_map.setdefault(f.strip(), []).append(func)
        if not src_map: return "\n".join(parts + ["Could not find sources."])
        compiled = []
        for src, _ in sorted(src_map.items(), key=lambda x: -len(x[1]))[:5]:
            obj = f"/work/{src.replace('/', '_').replace('.c', '.o').replace('.cc', '.o').replace('.cpp', '.o')}"
            self.env.exec(f"g++ -fsanitize=address -g -std=c++20 -I/src -I/src/public -c {src} -o {obj} 2>&1", timeout=60)
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

    def _scrub_context_for_linker(self):
        nm = self.env.exec("nm /work/harness.o 2>/dev/null | grep ' U ' | head -15", timeout=5)
        self._exchanges = self._exchanges[-2:]
        self._exchanges.append(("(system)", f"⚠️ LINK FAILED. Undefined:\n{nm.stdout[:1000]}\nFind sources, compile, link."))

    # === INPUT CRAFTING (isolated) ===
    def _craft_input(self):
        ctx = self._build_vuln_craft_context()
        fmt = self._analyze_input_format()
        prompt = self._build_craft_prompt(ctx, fmt)
        try:
            resp = self.llm_code("Write a Python script to create a malformed input. Output ONLY <write_file> and <shell>.", prompt)
        except Exception as e:
            logger.error("Craft failed: %s", e)
            return ""
        for a in parse_actions(resp):
            if a.kind == "write_file": self.env.write_file(a.path, a.content)
            elif a.kind == "shell": self.env.exec(a.content, timeout=30)
        check = self.env.exec("ls /work/crafted_input* 2>/dev/null | head -1", timeout=5)
        return check.stdout.strip().split("\n")[0] if check.stdout.strip() else ""

    def _build_vuln_craft_context(self):
        tags = self.trace.vulnerability_tags or []
        ctx = {"vuln_class": tags[0] if tags else "unknown", "sink_function": self.sink_function,
               "sink_file": self.sink_file, "vuln_summary": self.trace.vulnerability_summary or "",
               "constraints": self.trace.constraints[:10] if self.trace.constraints else [],
               "z3_model": self.trace.z3_model or "", "key_functions": [], "source_contexts": []}
        for i, step in enumerate(self.trace.steps[:15]):
            loc = step.location
            if not loc or not loc.file: continue
            is_key = (i == 0 or i == len(self.trace.steps)-1 or (step.edge_kind and step.edge_kind.value in ("call", "pointer_deref", "type_cast")))
            if is_key:
                src = self.env.exec(f"sed -n '{max(1, loc.line-6)},{loc.line+6}p' /src/{loc.file} 2>/dev/null", timeout=5)
                if src.stdout.strip():
                    label = "ENTRY" if i == 0 else ("SINK" if i == len(self.trace.steps)-1 else f"Step {i}")
                    ctx["source_contexts"].append(f"--- {label}: {loc.file}:{loc.line} ---\n{src.stdout.strip()}")
            if step.node_name and len(step.node_name) > 2:
                ctx["key_functions"].append(step.node_name.split("|")[0].strip())
        lines = []
        for i, s in enumerate(self.trace.steps[:15]):
            loc = f"{s.location.file}:{s.location.line}" if s.location else "?"
            edge = f" [{s.edge_kind.value}]" if s.edge_kind else ""
            lines.append(f"  {i}: {loc}{edge} | {(s.code_snippet or '?')[:80]}")
        ctx["trace_text"] = "\n".join(lines)
        return ctx

    def _analyze_input_format(self):
        info = {"format": "binary", "ext": ".bin", "sample_path": ""}
        harness = self.env.read_file("/work/harness.cpp", max_lines=80).lower()
        for kws, fmt, ext in [
            (("fpdf", "pdf", "loadmemdocument"), "PDF", ".pdf"),
            (("cms", "lcms", "cmsit8", "cgats", "icc"), "CGATS/ICC", ".it8"),
            (("xml", "parsexml"), "XML", ".xml"), (("png", "read_png"), "PNG", ".png"),
        ]:
            if any(k in harness for k in kws):
                info["format"], info["ext"] = fmt, ext
                break
        find = self.env.exec(f"find /src -type f -name '*{info['ext']}' 2>/dev/null | head -1", timeout=10)
        if find.stdout.strip(): info["sample_path"] = find.stdout.strip().split("\n")[0]
        return info

    def _build_craft_prompt(self, ctx, fmt):
        vc, ext = ctx["vuln_class"], fmt.get("ext", ".bin")
        guide = {"buffer_overflow": "Set a length field very large, provide less data.",
                 "use_after_free": "Create circular refs or duplicate entries.",
                 "null_deref": "Remove required fields or set refs to null.",
                 "integer_overflow": "Set numeric fields to 0xFFFFFFFF.",
                 "type_confusion": "Change type tags."}.get(vc, "Corrupt input to exercise the trace.")
        src = "\nSOURCE:\n" + "\n\n".join(ctx.get("source_contexts", [])[:3]) if ctx.get("source_contexts") else ""
        sample = f"\nSample: {fmt['sample_path']}" if fmt.get("sample_path") else ""
        return f"""Craft malformed {fmt['format']} for {vc} at {ctx['sink_function']}.
{ctx.get('vuln_summary', '')}
TRACE:
{ctx['trace_text']}{src}
STRATEGY: {guide}{sample}

<write_file path="/work/craft.py">
import struct
# Create /work/crafted_input{ext}
</write_file>
<shell>python3 /work/craft.py</shell>"""

    # === UTILS ===
    @staticmethod
    def _smart_truncate_output(cmd, exit_code, raw, max_len=4000):
        if not raw: return "(no output)"
        if len(raw) <= max_len: return raw
        if "AddressSanitizer" in raw:
            keep = []
            cap = False
            for line in raw.split("\n"):
                if "ERROR:" in line and "AddressSanitizer" in line: cap = True
                if cap:
                    keep.append(line)
                    if line.strip() == "" and len(keep) > 5: break
                if "SUMMARY:" in line: keep.append(line)
            if keep: return "\n".join(keep)[:max_len]
            return raw[-max_len:]
        is_cc = any(k in cmd for k in ("g++", "gcc", "clang", "make"))
        if is_cc and exit_code != 0:
            blocks = []
            lines = raw.split("\n")
            for i, l in enumerate(lines):
                if "error:" in l.lower() or "undefined reference" in l.lower():
                    blocks.append("\n".join(lines[max(0,i-1):min(len(lines),i+4)]))
            if blocks: return "\n...\n".join(blocks)[:max_len]
            return raw[-max_len:]
        h = max_len // 2 - 30
        return raw[:h] + "\n... [TRUNCATED] ...\n" + raw[-h:]

    @staticmethod
    def _detect_successful_compile(action_logs):
        for al in action_logs:
            if al.get("kind") != "shell": continue
            cmd = al.get("command", "")
            output = al.get("output", "") or ""
            # Skip if output contains compilation errors
            if "error:" in output or "fatal error" in output:
                continue
            if "-c" in cmd and "-o" in cmd and any(cmd.strip().startswith(cc) for cc in ("g++", "gcc", "clang")):
                parts = cmd.split()
                for i, p in enumerate(parts):
                    if p == "-o" and i+1 < len(parts) and parts[i+1].endswith(".o"):
                        return parts[i+1]
        return ""

    def _detect_stall(self, turn: int, results_str: str) -> str | None:
        """Cheap deterministic stall checks. Reviewer handles complex judgment."""
        if turn < 3:
            return None
        recent = self._exchanges[-6:]
        all_res = "\n".join(r for _, r in recent)

        # Pattern 1: Build tool not found repeatedly
        for tool in ("gn", "cmake", "meson", "bazel", "cargo"):
            if all_res.lower().count(f"{tool}: command not found") >= 2:
                return f"⚠️ {tool} is not installed. Compile source files directly with g++."

        # Pattern 2: Same compile error 3+ times
        errors = []
        for _, r in recent:
            if "error:" in r and any(k in r for k in ("g++", "gcc", "clang")):
                for line in r.split("\n"):
                    if "error:" in line:
                        errors.append(line.strip()[:100])
                        break
        if len(errors) >= 3 and len(set(errors)) == 1:
            return f"⚠️ Same error 3x: {errors[0][:80]}. Try a DIFFERENT approach."

        # Pattern 3: Repeated identical commands
        cmds = []
        for a, _ in recent:
            for m in re.finditer(r"\[shell\] \$ (.+)", a):
                cmds.append(m.group(1).strip()[:80])
            for m in re.finditer(r"<shell>(.*?)</shell>", a, re.DOTALL):
                cmds.append(m.group(1).strip()[:80])
        if len(cmds) >= 6:
            from collections import Counter
            counts = Counter(cmds)
            repeated = [c for c, n in counts.items() if n >= 3]
            if repeated:
                return f"⚠️ '{repeated[0][:50]}' repeated {counts[repeated[0]]}x. Do something different."

        # Pattern 4: No write_file or compile in 4+ turns (exploration-only in CODE state)
        if self.state == AgentState.CODE and len(recent) >= 4:
            has_code_action = False
            for _, r in recent[-4:]:
                if "[write_file]" in r or any(k in r for k in ("g++", "gcc", "clang")):
                    has_code_action = True
                    break
            if not has_code_action:
                return "⚠️ You've been exploring for 4 turns in CODE phase. Write /work/harness.cpp NOW."

        return None

    def _force_write_harness(self):
        includes = ['#include <stdio.h>', '#include <stdlib.h>', '#include <string.h>']
        hdr = self.env.exec("find /src -path '*/include/*.h' -o -path '*/public/*.h' | head -5", timeout=5)
        for h in (hdr.stdout.strip().split("\n") if hdr.stdout.strip() else [])[:3]:
            includes.append(f'#include "{h.strip().replace("/src/", "")}"')
        code = "\n".join(includes) + f"""
int main(int argc, char* argv[]) {{
    if (argc < 2) return 1;
    FILE* f = fopen(argv[1], "rb"); if (!f) return 1;
    fseek(f, 0, SEEK_END); long len = ftell(f); fseek(f, 0, SEEK_SET);
    char* buf = (char*)malloc(len); fread(buf, 1, len, f); fclose(f);
    // TODO: Call {self.sink_function}
    free(buf); return 0;
}}
"""
        self.env.write_file("/work/harness.cpp", code)
        r = self.env.exec("g++ -fsanitize=address -g -std=c++17 -I/src -I/src/public /work/harness.cpp -c -o /work/harness.o 2>&1", timeout=60)
        ok = self.env.exec("test -f /work/harness.o && echo y", timeout=5).stdout.strip() == "y"
        return f"{'✅' if ok else '❌'} harness.o\n{r.output[:1000]}"

    def _transition_to_code(self, result):
        if result:
            result.log.append({"event": "transition", "to": "CODE", "summary": self._exploration_summary[:500]})
        self._exchanges = self._exchanges[-2:]

    def _run_verification(self, binary, input_file):
        return verify_harness(env=self.env, harness_binary=binary, input_file=input_file,
                              sink_function=self.sink_function, sink_file=self.sink_file,
                              library_name=self.profile.library_name, timeout=self.config.verify_timeout)

    # === CONTEXT ===
    def _build_initial_context(self):
        """Build context the way a human researcher would prepare.

        A human reads: (1) the sink function code, (2) the entry point code,
        (3) an existing fuzzer/test for reference, (4) the relevant header,
        (5) checks what test data exists. All BEFORE writing any code.
        """
        p = self.profile
        ctx = [f"=== REPO: {p.repo_name} | {p.language} | {p.build_system or '?'} ==="]
        if p.build_commands:
            ctx.append("Build: " + "; ".join(p.build_commands[:3]))

        # --- VULNERABILITY TARGET ---
        ctx += [
            f"\n=== TARGET: {self.sink_function} @ {self.sink_file} ===",
            f"Tags: {', '.join(self.trace.vulnerability_tags or [])}",
            f"Summary: {self.trace.vulnerability_summary or 'N/A'}",
        ]

        # --- TRACE with enriched context ---
        ctx.append("\n=== DATA FLOW TRACE ===")
        for i, s in enumerate(self.trace.steps[:20]):
            loc = f"{s.location.file}:{s.location.line}" if s.location else "?"
            sink = " [SINK]" if i == len(self.trace.steps) - 1 else ""
            entry = " [ENTRY]" if i == 0 else ""
            ctx.append(f"  {i}{entry}{sink}: {loc} — {(s.code_snippet or '?')[:100]}")

        if not self.env.is_running:
            return "\n".join(ctx)

        # --- (1) READ SINK FUNCTION (what a human does first) ---
        sink_loc = self.trace.steps[-1].location if self.trace.steps else None
        if sink_loc and sink_loc.file:
            src = self.env.exec(
                f"sed -n '{max(1, sink_loc.line-15)},{sink_loc.line+15}p' /src/{sink_loc.file} 2>/dev/null",
                timeout=5,
            )
            if src.stdout.strip():
                ctx.append(f"\n=== SINK FUNCTION SOURCE: {sink_loc.file}:{sink_loc.line} ===")
                ctx.append(src.stdout.strip()[:2000])

        # --- (2) READ ENTRY POINT (how user input reaches the sink) ---
        entry_loc = self.trace.steps[0].location if self.trace.steps else None
        if entry_loc and entry_loc.file and entry_loc.file != (sink_loc.file if sink_loc else ""):
            src = self.env.exec(
                f"sed -n '{max(1, entry_loc.line-10)},{entry_loc.line+10}p' /src/{entry_loc.file} 2>/dev/null",
                timeout=5,
            )
            if src.stdout.strip():
                ctx.append(f"\n=== ENTRY POINT SOURCE: {entry_loc.file}:{entry_loc.line} ===")
                ctx.append(src.stdout.strip()[:1500])

        # --- (3) FIND AND READ AN EXISTING FUZZER/TEST ---
        fuzz_r = self.env.exec(
            "find /src -name '*fuzz*' \\( -name '*.c' -o -name '*.cc' -o -name '*.cpp' \\) 2>/dev/null | head -5",
            timeout=10,
        )
        fuzz_content = ""
        if fuzz_r.stdout.strip():
            fuzz_files = fuzz_r.stdout.strip().split("\n")
            ctx.append(f"\n=== EXISTING FUZZERS: {', '.join(f.strip() for f in fuzz_files[:3])} ===")
            # Read the most relevant one (prefer one that mentions the sink or is in the same dir)
            best = fuzz_files[0].strip()
            for ff in fuzz_files:
                ff = ff.strip()
                sink_dir = sink_loc.file.rsplit("/", 1)[0] if sink_loc and sink_loc.file and "/" in sink_loc.file else ""
                if sink_dir and sink_dir in ff:
                    best = ff
                    break
            src = self.env.exec(f"head -80 {best} 2>/dev/null", timeout=5)
            if src.stdout.strip():
                fuzz_content = src.stdout.strip()[:2000]
                ctx.append(f"--- {best} ---")
                ctx.append(fuzz_content)

        # --- (4) READ THE RELEVANT HEADER ---
        # Find the header that declares the sink function
        hdr_r = self.env.exec(
            f"grep -rn '{self.sink_function}' /src/ --include='*.h' -l 2>/dev/null | head -3",
            timeout=10,
        )
        if hdr_r.stdout.strip():
            hdr_file = hdr_r.stdout.strip().split("\n")[0].strip()
            # Read lines around the declaration
            decl_r = self.env.exec(
                f"grep -n '{self.sink_function}' {hdr_file} 2>/dev/null | head -3",
                timeout=5,
            )
            if decl_r.stdout.strip():
                line_num = decl_r.stdout.strip().split(":")[0]
                try:
                    ln = int(line_num)
                    hdr_src = self.env.exec(
                        f"sed -n '{max(1, ln-5)},{ln+10}p' {hdr_file} 2>/dev/null",
                        timeout=5,
                    )
                    if hdr_src.stdout.strip():
                        ctx.append(f"\n=== API HEADER: {hdr_file}:{ln} ===")
                        ctx.append(hdr_src.stdout.strip()[:1000])
                except ValueError:
                    pass

        # Also list all public headers for include path reference
        pub_hdrs = self.env.exec(
            "find /src -path '*/include/*.h' -o -path '*/public/*.h' | head -10",
            timeout=5,
        )
        if pub_hdrs.stdout.strip():
            ctx.append(f"\n=== PUBLIC HEADERS ===")
            ctx.append(pub_hdrs.stdout.strip()[:500])

        # --- (5) CHECK TEST DATA ---
        test_data = self.env.exec(
            "find /src -type f \\( -name '*.pdf' -o -name '*.it8' -o -name '*.icc' "
            "-o -name '*.xml' -o -name '*.png' \\) 2>/dev/null | head -10",
            timeout=10,
        )
        if test_data.stdout.strip():
            ctx.append(f"\n=== TEST DATA FILES ===")
            ctx.append(test_data.stdout.strip()[:500])

        # --- (6) BASIC REPO LAYOUT ---
        ls_r = self.env.exec("ls /src/ | head -30", timeout=5)
        if ls_r.stdout.strip():
            ctx.append(f"\n=== REPO LAYOUT ===")
            ctx.append(ls_r.stdout.strip()[:500])

        return "\n".join(ctx)

    def _build_prompt(self, ic):
        parts = [ic]
        for i, (r, o) in enumerate(self._exchanges[-self.config.context_window:]):
            parts.append(f"--- Turn {i} ---\nYou: {r[:1500]}\nResult: {o[:1500]}")
        return "\n\n".join(parts)

    def _build_coder_prompt(self, ic):
        parts = [ic]
        if self._exploration_summary:
            parts.append(f"\n=== EXPLORATION SUMMARY ===\n{self._exploration_summary[:2000]}")
        for i, (r, o) in enumerate(self._exchanges[-self.config.context_window:]):
            parts.append(f"--- Turn {i} ---\nYou: {r[:1500]}\nResult: {o[:1500]}")
        return "\n\n".join(parts)

    def _generate_postmortem(self, result):
        pm = {"turns": result.turns_used}
        if self.env.is_running:
            pm["compiled"] = "COMPILED" in self.env.exec("test -x /work/harness && echo COMPILED || echo NO", timeout=5).stdout
        return pm
