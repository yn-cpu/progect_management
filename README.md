#src\deeptrace\analysis\constraint_solver.py
"""Z3-based constraint solver for verifying path feasibility.

Extracts mathematical constraints strictly from graph AST properties.
Refuses to use brittle string-matching (regex) on raw code snippets.

Uses z3-solver (pip install z3-solver).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from deeptrace.models.config import Z3Config
from deeptrace.models.graph import TracePath, NodeKind
from deeptrace.core.graph_builder import DependencyGraph

logger = logging.getLogger(__name__)

@dataclass
class ExtractedConstraint:
    """A constraint cleanly extracted from an AST representation."""
    expression_repr: str
    source_step: int
    z3_expr: Any  # The actual z3 ArithRef/BoolRef object

    def __str__(self) -> str:
        return f"[step {self.source_step}] {self.expression_repr}"


class ASTtoZ3Translator:
    """Translates semantic AST structures into Z3 constraints."""

    def __init__(self):
        try:
            import z3
            self.z3 = z3
            self.variables: dict[str, z3.ArithRef] = {}
        except ImportError:
            self.z3 = None

    def get_var(self, name: str) -> Any:
        """Get or create an integer variable in the Z3 context."""
        if name not in self.variables:
            self.variables[name] = self.z3.Int(name)
        return self.variables[name]

    def translate_ast(self, ast_node: dict[str, Any]) -> Any | None:
        """
        Recursively translates an AST dictionary into a Z3 expression.
        EXPECTS: {"operator": "==", "lhs": {"type": "identifier", "name": "x"}, "rhs": {"type": "literal", "value": 0}}
        """
        if not ast_node:
            return None

        node_type = ast_node.get("type")

        if node_type == "literal":
            try:
                # Handle hex and dec literals
                val = ast_node.get("value", "0")
                if isinstance(val, str) and val.startswith("0x"):
                    return int(val, 16)
                return int(val)
            except (ValueError, TypeError):
                return None

        if node_type == "identifier":
            return self.get_var(ast_node.get("name", "unknown"))

        if node_type == "binary_expression":
            lhs = self.translate_ast(ast_node.get("lhs", {}))
            rhs = self.translate_ast(ast_node.get("rhs", {}))
            op = ast_node.get("operator")

            if lhs is None or rhs is None:
                return None

            # Cast literal integers to z3 values if necessary
            if isinstance(lhs, int):
                lhs = self.z3.IntVal(lhs)
            if isinstance(rhs, int):
                rhs = self.z3.IntVal(rhs)

            if op == "==": return lhs == rhs
            if op == "!=": return lhs != rhs
            if op == "<": return lhs < rhs
            if op == "<=": return lhs <= rhs
            if op == ">": return lhs > rhs
            if op == ">=": return lhs >= rhs
            if op == "&&": return self.z3.And(lhs, rhs)
            if op == "||": return self.z3.Or(lhs, rhs)

        return None


@dataclass
class Z3Result:
    """Result of Z3 satisfiability check."""
    satisfiable: bool | None = None
    model_str: str = ""
    encoded_constraints: int = 0
    total_constraints: int = 0
    error: str = ""
    constraint_reprs: list[str] = field(default_factory=list)  # string representations for reuse


def extract_constraints_from_path(
    path: TracePath,
    graph: DependencyGraph,
    translator: ASTtoZ3Translator
) -> list[ExtractedConstraint]:
    """Extract constraints strictly from semantic AST properties, not strings."""
    constraints: list[ExtractedConstraint] = []

    for step_idx, step in enumerate(path.steps):
        node = graph.get_node(step.node_id)
        if not node:
            continue

        # Look for the deterministic AST representation you MUST inject from Joern/Treesitter
        ast_data = node.properties.get("ast_condition")

        if ast_data:
            z3_expr = translator.translate_ast(ast_data)
            if z3_expr is not None:
                constraints.append(ExtractedConstraint(
                    expression_repr=str(ast_data),
                    source_step=step_idx,
                    z3_expr=z3_expr
                ))

    return constraints


def check_path_satisfiability(
    path: TracePath,
    graph: DependencyGraph,
    config: Z3Config,
) -> Z3Result:
    """Check if the path is satisfiable using rigorous AST-to-Z3 translation."""
    translator = ASTtoZ3Translator()
    if not translator.z3:
        return Z3Result(error="z3-solver not installed")

    extracted = extract_constraints_from_path(path, graph, translator)
    result = Z3Result(total_constraints=len(extracted))
    result.constraint_reprs = [str(c.expression_repr) for c in extracted]

    if not extracted:
        # If we have no math to prove, we cannot declare it unreachable.
        result.satisfiable = True
        return result

    solver = translator.z3.Solver()
    solver.set("timeout", config.timeout_ms)

    for constraint in extracted:
        solver.add(constraint.z3_expr)
        result.encoded_constraints += 1

    try:
        check = solver.check()
        if check == translator.z3.sat:
            result.satisfiable = True
            model = solver.model()
            assignments = []
            for v_name, v_ref in sorted(translator.variables.items()):
                val = model.evaluate(v_ref, model_completion=True)
                assignments.append(f"{v_name} = {val}")
            result.model_str = "; ".join(assignments)
        elif check == translator.z3.unsat:
            result.satisfiable = False
        else:
            result.satisfiable = None
    except Exception as exc:
        logger.error("Z3 solver error: %s", exc)
        result.error = str(exc)

    return result


def check_paths_satisfiability(
    paths: list[TracePath],
    graph: DependencyGraph,
    config: Z3Config,
) -> list[TracePath]:
    """Check satisfiability for all paths in-place. Returns paths."""
    if not config.enabled:
        return paths

    try:
        import z3  # noqa: F401
    except ImportError:
        logger.warning("z3-solver not installed — skipping constraint checking")
        return paths

    sat_count = 0
    unsat_count = 0
    unknown_count = 0

    for path in paths:
        result = check_path_satisfiability(path, graph, config)

        path.is_satisfiable = result.satisfiable
        path.z3_model = result.model_str

        # Reuse the constraint representations already extracted
        path.constraints = result.constraint_reprs

        if result.satisfiable is True:
            sat_count += 1
        elif result.satisfiable is False:
            unsat_count += 1
        else:
            unknown_count += 1

    logger.info(
        "Z3 results: %d SAT, %d UNSAT, %d UNKNOWN (out of %d paths)",
        sat_count, unsat_count, unknown_count, len(paths),
    )
    return paths


class IncrementalZ3Checker:
    """Lightweight on-the-fly solver for ACO ants."""

    def __init__(self):
        self.translator = ASTtoZ3Translator()
        self.solver = self.translator.z3.Solver() if self.translator.z3 else None
        self.is_active = self.solver is not None

    def add_and_check(self, ast_condition: dict[str, Any]) -> bool:
        """Adds a constraint and returns True if SAT/UNKNOWN, False if UNSAT."""
        if not self.is_active:
            return True

        z3_expr = self.translator.translate_ast(ast_condition)
        if z3_expr is not None:
            self.solver.add(z3_expr)
            # Use a tiny timeout for on-the-fly checks so ants don't get bogged down
            self.solver.set("timeout", 50)

            try:
                check = self.solver.check()
                # Only kill the ant if we are mathematically certain it's impossible
                if check == self.translator.z3.unsat:
                    return False
            except Exception:
                pass  # If Z3 throws an error or times out, let the ant live
        return True
#src\deeptrace\analysis\flow_analyzer.py
"""Static analysis helpers: detect vulnerability patterns in trace paths using semantic graph properties."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from deeptrace.models.graph import EdgeKind, NodeKind, TracePath


@dataclass
class VulnPattern:
    """A vulnerability pattern to match against trace paths using semantic node properties."""
    name: str
    description: str
    edge_sequence: list[EdgeKind] | None = None
    target_calls: set[str] = field(default_factory=set)
    target_node_kinds: set[NodeKind] = field(default_factory=set)
    target_names: set[str] = field(default_factory=set)  # For specific variables, identifiers, or literals
    min_depth: int = 2
    severity: str = "medium"  # low, medium, high, critical


# Pre-defined vulnerability patterns mapped to exact AST/CPG semantic properties
VULN_PATTERNS: list[VulnPattern] = [
    VulnPattern(
        name="buffer_overflow",
        description="Potential buffer overflow: data flows to unsafe memory/string operations",
        target_calls={"memcpy", "strcpy", "strcat", "sprintf", "gets", "scanf"},
        severity="critical",
    ),
    VulnPattern(
        name="use_after_free",
        description="Potential use-after-free: data flows from a deallocation call to a pointer dereference",
        target_calls={"free", "delete"},
        edge_sequence=[EdgeKind.POINTER_DEREF, EdgeKind.DATA_FLOW],
        severity="critical",
    ),
    VulnPattern(
        name="null_deref",
        description="Potential null pointer dereference: null literal flows to a dereference",
        # In a CPG, nulls are usually literals or specific identifiers
        target_names={"null", "NULL", "nullptr", "nil", "0"},
        target_node_kinds={NodeKind.LITERAL, NodeKind.IDENTIFIER},
        edge_sequence=[EdgeKind.POINTER_DEREF],
        severity="high",
    ),
    VulnPattern(
        name="injection",
        description="Potential injection: data flows to execution or query sinks",
        target_calls={"exec", "system", "popen", "eval", "query", "execute", "getenv"},
        severity="critical",
    ),
    VulnPattern(
        name="integer_overflow",
        description="Potential integer overflow: data flows to arithmetic operations",
        # NOTE: In a true CPG, arithmetic operations are CALL_SITEs to operators like "<operator>.addition"
        target_calls={"<operator>.addition", "<operator>.subtraction", "<operator>.multiplication", "<operator>.shiftLeft"},
        severity="high",
    ),
    VulnPattern(
        name="format_string",
        description="Potential format string vulnerability: data flows to formatting sinks",
        target_calls={"printf", "fprintf", "sprintf", "snprintf", "syslog"},
        severity="critical",
    ),
    VulnPattern(
        name="resource_leak",
        description="Potential resource leak: opened handle not properly tracked to closure",
        target_calls={"fopen", "open", "socket", "connect", "malloc", "new"},
        severity="medium",
    ),
    VulnPattern(
        name="race_condition",
        description="Potential race condition: synchronization primitives identified",
        target_calls={"pthread_mutex_lock", "pthread_mutex_unlock", "lock", "unlock", "acquire", "release"},
        severity="high",
    ),
    VulnPattern(
        name="unvalidated_input",
        description="Unvalidated external input flows to sensitive operation",
        target_calls={"read", "recv", "fgets", "getline", "scanf"},
        severity="high",
    ),
]


def detect_patterns(path: TracePath) -> list[str]:
    """Detect vulnerability patterns in a trace path using semantic node properties."""
    matches: list[str] = []

    for pattern in VULN_PATTERNS:
        if path.depth < pattern.min_depth:
            continue

        semantic_match_count = 0
        for step in path.steps:
            # Check 1: Is this a call site targeting a known vulnerable/sink function?
            if step.node_kind == NodeKind.CALL_SITE and step.node_name in pattern.target_calls:
                semantic_match_count += 1

            # Check 2: Are we looking for specific node types (e.g., Array Access operations)?
            elif step.node_kind in pattern.target_node_kinds:
                # If target_names is specified, it must match the name too (e.g., checking for 'NULL' literals)
                if pattern.target_names:
                    if step.node_name in pattern.target_names:
                        semantic_match_count += 1
                else:
                    semantic_match_count += 1

        # If we didn't find any semantic anchors, this pattern doesn't apply
        if semantic_match_count == 0:
            continue

        # If the pattern requires a specific sequence of edges (e.g., Deref followed by DataFlow)
        if pattern.edge_sequence:
            path_edges = [s.edge_kind for s in path.steps if s.edge_kind]
            if _contains_subsequence(path_edges, pattern.edge_sequence):
                matches.append(pattern.name)
        else:
            matches.append(pattern.name)

    return matches


def _contains_subsequence(haystack: list[Any], needle: list[Any]) -> bool:
    """Check if needle appears as a (non-contiguous) subsequence of haystack."""
    it = iter(haystack)
    return all(item in it for item in needle)


def enrich_paths_with_patterns(paths: list[TracePath]) -> list[TracePath]:
    """Add static pattern-based vulnerability tags to paths."""
    for path in paths:
        detected = detect_patterns(path)
        existing = set(path.vulnerability_tags)
        for tag in detected:
            if tag not in existing:
                path.vulnerability_tags.append(tag)
    return paths


def compute_path_risk_score(path: TracePath) -> float:
    """Compute a numeric risk score based on vulnerability patterns and depth."""
    severity_weights = {
        "critical": 10.0,
        "high": 7.0,
        "medium": 4.0,
        "low": 1.0,
    }

    score = 0.0
    matched_patterns = set()

    for pattern in VULN_PATTERNS:
        if pattern.name in path.vulnerability_tags:
            score += severity_weights.get(pattern.severity, 1.0)
            matched_patterns.add(pattern.name)

    # Depth multiplier (deeper paths that still match are more concerning)
    depth_factor = min(path.depth / 10.0, 3.0)
    score *= (1.0 + depth_factor * 0.2)

    # Cross-file bonus (vulnerabilities crossing file boundaries are harder to spot)
    files = {s.location.file for s in path.steps if s.location and s.location.file}
    if len(files) > 1:
        score *= 1.3

    return round(score, 2)

#src\deeptrace\analysis\llm_ranker.py
"""LLM-based ranking and annotation of trace paths.

Supports multiple providers:
  - Ollama (local, default) — via OpenAI-compatible /v1/chat/completions
  - Anthropic (Claude)      — via anthropic SDK
  - OpenAI-compatible       — any API that speaks the OpenAI chat format
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from deeptrace.models.config import LLMConfig, LLMProvider
from deeptrace.models.graph import BranchCandidate, BranchPoint, TracePath, TraceStep, EdgeKind

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT_RANK = """You are a senior security researcher and static analysis expert.
You are analyzing dependency trace paths through source code. Each path represents a
chain of data flow, calls, and dependencies leading to a specific target line of code.

Your task is to rank these paths by security relevance and potential vulnerability,
and annotate each with insights.

CRITICAL INSTRUCTION: Your ENTIRE response must be a single JSON object. Do NOT include
any explanatory text, markdown formatting, or commentary before or after the JSON.
Do NOT use ```json fences. Output ONLY raw JSON.

The JSON schema:
{
  "ranked_paths": [
    {
      "path_id": "<id>",
      "rank": <1-based rank, 1 = most critical>,
      "vulnerability_tags": ["<tag1>", ...],
      "rationale": "<1-2 sentence explanation>",
      "step_annotations": [
        {"step_index": <0-based>, "note": "<brief annotation>"}
      ]
    }
  ]
}

Vulnerability tag categories: buffer_overflow, use_after_free, null_deref, injection,
integer_overflow, race_condition, unvalidated_input, information_leak,
privilege_escalation, resource_leak, type_confusion, format_string.
Only tag what's actually evidenced by the code in the trace.

REMEMBER: Output ONLY the JSON object. No other text."""

_SYSTEM_PROMPT_BRANCH = """You are a senior security researcher analyzing branch points
in a code dependency graph. At each branch point, multiple backward dependency paths diverge.
Your job is to provide a brief summary and vulnerability hint for each candidate path.

Respond ONLY with a JSON object (no markdown fences, no preamble). The schema:
{
  "candidates": [
    {
      "index": <candidate index>,
      "summary": "<one-line description of what this path represents>",
      "vulnerability_hint": "<potential security concern or 'none'>",
      "priority": <1-5, where 1 = most interesting to explore>
    }
  ]
}"""


_SYSTEM_PROMPT_ANNOTATE = """You are a senior security researcher annotating code trace paths.
For each step in a trace path, you must provide a brief contextual description of what is
happening at that node and why it matters in the context of the overall data flow path.

Respond ONLY with a JSON object (no markdown fences, no preamble). The schema:
{
  "step_annotations": [
    {
      "step_index": <0-based index>,
      "description": "<1-2 sentence description of what happens at this step in context>"
    }
  ]
}

Cover EVERY step in the path. Be specific about data flow: what data enters, how it is
transformed/checked/passed, and what leaves. Mention relevant security implications."""


_SYSTEM_PROMPT_VULN_SUMMARY = """You are a senior security researcher writing a detailed
vulnerability analysis of a code trace path. You must explain step-by-step how data flows
through the code and why this path represents a potential vulnerability.

CRITICAL RULES FOR FALSE POSITIVES:
1. If a memory copy operation (e.g., memcpy, strncpy) is strictly bounded by the static size of the destination buffer (e.g., sizeof(DestinationStruct)), you MUST NOT flag it as a buffer overflow unless the attacker can explicitly control the size parameter.
2. Do not assume a macro named "UNSAFE" automatically implies an exploitable state. You must prove the math allows an overflow.

Respond ONLY with a JSON object (no markdown fences, no preamble). The schema:
{
  "summary": "<2-4 paragraph step-by-step explanation of the vulnerability. If this is a false positive based on static bounds, explicitly explain why it is NOT exploitable.>",
  "step_explanations": [
    {
      "step_index": <0-based index>,
      "explanation": "<1 sentence explaining this step's role in the vulnerability or data flow>"
    }
  ]
}

If the path has Z3 satisfiability information, incorporate it: explain whether the
constraints make exploitation feasible or infeasible."""


def _format_path_for_llm(path: TracePath, index: int) -> str:
    """Format a trace path for LLM consumption.

    After statement-level collapse, paths are already compact.
    Show ALL steps so the LLM has full context for ranking and annotation.
    """
    lines = [f"--- Path {index + 1} (id={path.id}, score={path.score:.1f}, depth={path.depth}) ---"]

    # Deduplicate repeated lines (e.g., multiple AST nodes on the same line)
    seen_lines = set()
    for i, step in enumerate(path.steps):
        loc = step.location.short if step.location else "?"
        if loc in seen_lines:
            continue
        seen_lines.add(loc)

        edge = f" [{step.edge_kind.value}]" if step.edge_kind else ""
        code = step.code_snippet[:150] if step.code_snippet else ""
        lines.append(f"  [{i}] {loc}{edge}: {code}")
    return "\n".join(lines)

def _format_branch_for_llm(bp: BranchPoint) -> str:
    """Format a branch point for LLM consumption."""
    loc = bp.location.short if bp.location else "?"
    lines = [f"Branch at {loc} ({bp.node_id}):"]
    for cand in bp.candidates:
        lines.append(
            f"  [{cand.index}] -> {cand.next_node_id} "
            f"({cand.edge_kind.value}, est_depth={cand.estimated_depth}): "
            f"{cand.code_preview[:120]}"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Provider-specific API callers
# ---------------------------------------------------------------------------

def _call_ollama(config: LLMConfig, system: str, user_message: str) -> str:
    """Call Ollama via its OpenAI-compatible /v1/chat/completions endpoint."""
    import urllib.request
    import urllib.error

    base_url = config.get_base_url().rstrip("/")
    url = f"{base_url}/v1/chat/completions"

    payload_dict: dict[str, Any] = {
        "model": config.model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_message},
        ],
        "temperature": config.temperature,
        "max_tokens": config.max_tokens,
        "stream": False,
    }

    # Ollama supports response_format to force JSON output.
    # If the system prompt asks for JSON, enable it.
    if "json" in system.lower():
        payload_dict["response_format"] = {"type": "json_object"}

    payload = json.dumps(payload_dict).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
    }

    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=config.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Ollama request failed ({url}): {exc}. "
            f"Is Ollama running? Start it with: ollama serve"
        ) from exc
    except (KeyError, IndexError) as exc:
        raise RuntimeError(f"Unexpected Ollama response format: {exc}") from exc


def _call_openai_compat(config: LLMConfig, system: str, user_message: str) -> str:
    """Call any OpenAI-compatible API (including LM Studio, vLLM, etc.)."""
    import urllib.request
    import urllib.error

    base_url = config.get_base_url().rstrip("/")
    url = f"{base_url}/v1/chat/completions"

    payload = json.dumps({
        "model": config.model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_message},
        ],
        "temperature": config.temperature,
        "max_tokens": config.max_tokens,
    }).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {config.get_api_key()}",
    }

    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=config.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]
    except urllib.error.URLError as exc:
        raise RuntimeError(f"OpenAI-compatible API request failed ({url}): {exc}") from exc
    except (KeyError, IndexError) as exc:
        raise RuntimeError(f"Unexpected API response format: {exc}") from exc


def _call_anthropic(config: LLMConfig, system: str, user_message: str) -> str:
    """Call Anthropic's Claude API via the anthropic SDK."""
    try:
        import anthropic
    except ImportError:
        raise RuntimeError(
            "anthropic package not installed. "
            "pip install anthropic  -- or switch to --llm-provider ollama"
        )

    api_key = config.get_api_key()
    if not api_key:
        raise ValueError(
            "No Anthropic API key found. Set ANTHROPIC_API_KEY env var "
            "or pass --llm-api-key."
        )

    client = anthropic.Anthropic(api_key=api_key)
    response = client.messages.create(
        model=config.model,
        max_tokens=config.max_tokens,
        temperature=config.temperature,
        system=system,
        messages=[{"role": "user", "content": user_message}],
    )
    return response.content[0].text


# ---------------------------------------------------------------------------
# Unified caller with retry
# ---------------------------------------------------------------------------

def _call_llm(config: LLMConfig, system: str, user_message: str) -> str:
    """Route to the correct provider and retry on transient failures."""
    from tenacity import retry, stop_after_attempt, wait_exponential

    dispatch = {
        LLMProvider.OLLAMA: _call_ollama,
        LLMProvider.OPENAI: _call_openai_compat,
        LLMProvider.ANTHROPIC: _call_anthropic,
    }

    caller = dispatch.get(config.provider)
    if caller is None:
        raise ValueError(f"Unknown LLM provider: {config.provider}")

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=30))
    def _do_call() -> str:
        return caller(config, system, user_message)

    return _do_call()


# ---------------------------------------------------------------------------
# LLM Ranker
# ---------------------------------------------------------------------------

class LLMRanker:
    """Ranks and annotates trace paths using a configurable LLM backend."""

    def __init__(self, config: LLMConfig) -> None:
        self.config = config

    def _call_api(self, system: str, user_message: str) -> str:
        return _call_llm(self.config, system, user_message)

    def _parse_json_response(self, text: str) -> dict[str, Any]:
        """Robustly extract and parse JSON from an LLM response."""
        text = text.strip()

        # 1. Strip markdown fences if the model ignored instructions
        if "```" in text:
            import re
            match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', text, re.IGNORECASE)
            if match:
                text = match.group(1).strip()
            else:
                text = text.strip("` \n")

        # 2. Strip conversational prefixes (e.g., "Here is the JSON you requested:")
        start_idx = text.find("{")
        if start_idx >= 0:
            text = text[start_idx:]

        # 3. Strip trailing conversational suffixes
        end_idx = text.rfind("}")
        if end_idx >= 0:
            text = text[:end_idx + 1]

        if not text:
            return {}

        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            logger.error("LLM JSON parsing failed: %s", exc)
            logger.debug("Raw LLM output causing failure:\n%s", text[:500])
            return {}

    # -----------------------------------------------------------------------
    # Path ranking
    # -----------------------------------------------------------------------

    def rank_paths(self, paths: list[TracePath]) -> list[TracePath]:
        """Rank paths by vulnerability / value using the LLM.

        Mutates the paths in-place (sets llm_rank, llm_rationale,
        vulnerability_tags, and step annotations) and returns them
        sorted by LLM rank.
        """
        if not self.config.enabled or not paths:
            return paths

        # For Anthropic, require API key
        if self.config.provider == LLMProvider.ANTHROPIC:
            api_key = self.config.get_api_key()
            if not api_key:
                logger.warning("LLM ranking disabled: no Anthropic API key")
                return paths

        # Process in batches
        batch_size = self.config.max_paths_per_batch
        all_ranked: list[TracePath] = []

        for batch_start in range(0, len(paths), batch_size):
            batch = paths[batch_start:batch_start + batch_size]
            try:
                ranked_batch = self._rank_batch(batch)
                all_ranked.extend(ranked_batch)
            except Exception as exc:
                logger.error("LLM ranking failed for batch %d: %s", batch_start, exc)
                all_ranked.extend(batch)

        all_ranked.sort(key=lambda p: (p.llm_rank or 9999, -p.score))
        return all_ranked

    def _rank_batch(self, paths: list[TracePath]) -> list[TracePath]:
        """Rank a single batch of paths."""
        path_texts = [_format_path_for_llm(p, i) for i, p in enumerate(paths)]
        user_msg = (
            f"Analyze and rank these {len(paths)} dependency trace paths by security "
            f"relevance and potential vulnerability:\n\n"
            + "\n\n".join(path_texts)
            + "\n\nIMPORTANT: Respond with ONLY a JSON object, nothing else."
        )

        logger.info(
            "Calling LLM (%s/%s) to rank %d paths...",
            self.config.provider.value, self.config.model, len(paths),
        )

        # Try up to 2 times — first normal, then with stricter prompt
        result: dict[str, Any] = {}
        for attempt in range(2):
            prompt = _SYSTEM_PROMPT_RANK if attempt == 0 else (
                "You MUST respond with ONLY a JSON object. No explanations. "
                "Schema: {\"ranked_paths\": [{\"path_id\": \"<id>\", \"rank\": <int>, "
                "\"vulnerability_tags\": [\"<tag>\"], \"rationale\": \"<text>\", "
                "\"step_annotations\": [{\"step_index\": <int>, \"note\": \"<text>\"}]}]}"
            )
            try:
                response_text = self._call_api(prompt, user_msg)
                result = self._parse_json_response(response_text)
                if result.get("ranked_paths"):
                    break
                if attempt == 0:
                    logger.warning("LLM returned empty JSON, retrying with stricter prompt...")
            except Exception as exc:
                if attempt == 0:
                    logger.warning("LLM attempt %d failed: %s, retrying...", attempt + 1, exc)
                else:
                    raise

        # Apply rankings
        id_to_path = {p.id: p for p in paths}
        ranked_count = 0
        for rp in result.get("ranked_paths", []):
            pid = rp.get("path_id", "")
            if pid in id_to_path:
                path = id_to_path[pid]
                path.llm_rank = rp.get("rank", 999)
                path.llm_rationale = rp.get("rationale", "")
                path.vulnerability_tags = rp.get("vulnerability_tags", [])
                ranked_count += 1

                for ann in rp.get("step_annotations", []):
                    idx = ann.get("step_index", -1)
                    if 0 <= idx < len(path.steps):
                        path.steps[idx].annotation = ann.get("note", "")

        # Fallback: if LLM returned no/partial rankings, assign heuristic ranks
        if ranked_count < len(paths):
            logger.warning(
                "LLM ranked only %d/%d paths — applying heuristic fallback",
                ranked_count, len(paths),
            )
            unranked = [p for p in paths if p.llm_rank is None]
            # Sort by depth (deeper = more interesting) then score
            unranked.sort(key=lambda p: (-p.depth, -p.score))
            base_rank = ranked_count + 1
            for i, p in enumerate(unranked):
                p.llm_rank = base_rank + i
                if not p.llm_rationale:
                    p.llm_rationale = f"Heuristic rank (LLM parsing failed): depth={p.depth}, score={p.score:.1f}"

        return paths

    # -----------------------------------------------------------------------
    # Branch candidate ranking
    # -----------------------------------------------------------------------

    def rank_branch_candidates(self, branch_point: BranchPoint) -> BranchPoint:
        """Use LLM to summarize and prioritize branch candidates."""
        if not self.config.enabled or not branch_point.candidates:
            return branch_point

        if self.config.provider == LLMProvider.ANTHROPIC:
            api_key = self.config.get_api_key()
            if not api_key:
                return branch_point

        try:
            user_msg = (
                "Analyze these branch candidates and provide summaries and "
                "vulnerability hints:\n\n"
                + _format_branch_for_llm(branch_point)
            )

            response_text = self._call_api(_SYSTEM_PROMPT_BRANCH, user_msg)
            result = self._parse_json_response(response_text)

            idx_to_cand = {c.index: c for c in branch_point.candidates}
            for rc in result.get("candidates", []):
                idx = rc.get("index", -1)
                if idx in idx_to_cand:
                    cand = idx_to_cand[idx]
                    cand.llm_summary = rc.get("summary", "")
                    cand.vulnerability_hint = rc.get("vulnerability_hint", "")

            priorities = {
                rc.get("index", -1): rc.get("priority", 5)
                for rc in result.get("candidates", [])
            }
            branch_point.candidates.sort(
                key=lambda c: priorities.get(c.index, 5)
            )

        except Exception as exc:
            logger.error("LLM branch ranking failed: %s", exc)

        return branch_point

    # -----------------------------------------------------------------------
    # Node-level annotation (Feature #2)
    # -----------------------------------------------------------------------

    def annotate_path_nodes(self, paths: list[TracePath]) -> list[TracePath]:
        """For each path, have the LLM describe each node's role in context.

        Adds a brief description to each TraceStep.annotation field
        explaining what is happening at this node in the context of the
        overall data/control flow path.
        """
        if not self.config.enabled or not paths:
            return paths

        # Only annotate top paths to save API calls
        top_paths = [p for p in paths if (p.llm_rank or 9999) <= 10]
        if not top_paths:
            top_paths = paths[:5]

        for path in top_paths:
            try:
                self._annotate_single_path(path)
            except Exception as exc:
                logger.error("Node annotation failed for path %s: %s", path.id, exc)

        return paths

    def _annotate_single_path(self, path: TracePath) -> None:
        """Annotate each node in a single path with contextual descriptions."""
        path_text = _format_path_for_llm(path, 0)

        user_msg = (
            "For each step in this trace path, provide a brief description (1-2 sentences) "
            "of what is happening at that node in the context of the overall data flow. "
            "Explain the role of the code at each step: what data is being passed, "
            "transformed, or checked, and why it matters for security.\n\n"
            + path_text
        )

        response_text = self._call_api(_SYSTEM_PROMPT_ANNOTATE, user_msg)
        result = self._parse_json_response(response_text)

        for ann in result.get("step_annotations", []):
            idx = ann.get("step_index", -1)
            desc = ann.get("description", "")
            if 0 <= idx < len(path.steps) and desc:
                path.steps[idx].annotation = desc

    # -----------------------------------------------------------------------
    # Vulnerability summary (Feature #5)
    # -----------------------------------------------------------------------

    def generate_vulnerability_summaries(
        self,
        paths: list[TracePath],
        z3_available: bool = False,
    ) -> list[TracePath]:
        """Generate step-by-step vulnerability summaries for top paths.

        Summarizes WHY the path is a vulnerability, walking through each step.
        Satisfiable paths (Z3 SAT) are given priority in explanation.
        """
        if not self.config.enabled or not paths:
            return paths

        # Prioritize: SAT paths first, then top-ranked
        candidates = sorted(paths, key=lambda p: (
            0 if p.is_satisfiable is True else (2 if p.is_satisfiable is False else 1),
            p.llm_rank or 9999,
        ))

        # Summarize top N paths
        max_summaries = min(10, len(candidates))
        for path in candidates[:max_summaries]:
            try:
                self._generate_single_summary(path, z3_available)
            except Exception as exc:
                logger.error("Vulnerability summary failed for path %s: %s", path.id, exc)

        return paths

    def _generate_single_summary(self, path: TracePath, z3_available: bool) -> None:
        """Generate a vulnerability summary for one path."""
        path_text = _format_path_for_llm(path, 0)

        # Build context about satisfiability
        z3_context = ""
        if z3_available and path.is_satisfiable is not None:
            if path.is_satisfiable:
                z3_context = (
                    f"\n\nZ3 SATISFIABILITY: This path is SATISFIABLE. "
                    f"The constraints along this path have a valid solution: {path.z3_model}\n"
                    f"This means the path is feasible and the vulnerability can potentially be triggered."
                )
            else:
                z3_context = (
                    "\n\nZ3 SATISFIABILITY: This path is UNSATISFIABLE. "
                    "The constraints along this path are contradictory, meaning this "
                    "specific path cannot be triggered in practice. However, related "
                    "paths with slightly different conditions may still be exploitable."
                )

        constraint_context = ""
        if path.constraints:
            constraint_context = (
                "\n\nExtracted constraints along the path:\n"
                + "\n".join(f"  - {c}" for c in path.constraints[:20])
            )

        vuln_context = ""
        if path.vulnerability_tags:
            vuln_context = f"\n\nDetected vulnerability patterns: {', '.join(path.vulnerability_tags)}"

        user_msg = (
            "Provide a step-by-step vulnerability analysis of this trace path. "
            "For each step, explain what is happening and how data flows toward "
            "the vulnerability. Conclude with a summary of why this path represents "
            "a security risk and how it could be exploited.\n\n"
            + path_text
            + z3_context
            + constraint_context
            + vuln_context
        )

        response_text = self._call_api(_SYSTEM_PROMPT_VULN_SUMMARY, user_msg)
        result = self._parse_json_response(response_text)

        path.vulnerability_summary = result.get("summary", "")

        # Also update step annotations from the summary if we got them
        for ann in result.get("step_explanations", []):
            idx = ann.get("step_index", -1)
            explanation = ann.get("explanation", "")
            if 0 <= idx < len(path.steps) and explanation:
                # Append to existing annotation if present
                existing = path.steps[idx].annotation
                if existing and explanation not in existing:
                    path.steps[idx].annotation = f"{existing} | {explanation}"
                elif not existing:
                    path.steps[idx].annotation = explanation

#src\deeptrace\analysis\vulnerability_reasoner.py
"""Vulnerability Reasoner: Deep LLM analysis of trace paths.

Takes a trace path and the actual source code, then has the LLM reason
through the data flow step-by-step like a security researcher would:

  1. Read each step and the surrounding source code
  2. Understand what data flows where and how
  3. Identify what conditions would make this exploitable
  4. Check for guards, sanitization, and mitigations
  5. Assess confidence with concrete reasoning

The module uses few-shot examples from real vulnerability classes to teach
the model HOW to reason about code security.

Usage::

    reasoner = VulnerabilityReasoner(llm_caller, repo_path)
    assessment = reasoner.analyze_path(trace_path)
    print(assessment.verdict)       # "VULNERABLE" / "LIKELY" / "UNLIKELY" / "FALSE_POSITIVE"
    print(assessment.reasoning)     # Step-by-step reasoning
    print(assessment.root_cause)    # What the bug actually is
    print(assessment.trigger)       # What input would trigger it
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from deeptrace.models.graph import TracePath, TraceStep

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Output models
# ---------------------------------------------------------------------------

@dataclass
class VulnAssessment:
    """Result of reasoning about a single trace path."""
    path_id: str = ""
    verdict: str = ""           # EXPLOITABLE / NOT_EXPLOITABLE / NEEDS_REVIEW
    confidence: float = 0.0     # 0.0–1.0
    vulnerability_class: str = ""  # e.g., "use-after-free", "buffer-overflow"
    root_cause: str = ""        # What the actual bug is (1-3 sentences)
    trigger: str = ""           # What input/conditions trigger it
    impact: str = ""            # What an attacker can achieve
    guards: str = ""            # What mitigations exist (if any)
    reasoning: str = ""         # Full step-by-step reasoning
    exploit_sketch: str = ""    # High-level exploit approach
    cwe: str = ""               # CWE identifier if applicable
    why_not: str = ""           # If NOT_EXPLOITABLE: why exactly it's safe
    steps_analysis: list[StepAnalysis] = field(default_factory=list)
    raw_llm_output: str = ""    # Full LLM response for debugging


@dataclass
class StepAnalysis:
    """Analysis of a single step in the trace."""
    step_index: int
    location: str               # file:line
    code_context: str           # surrounding source code
    role_in_flow: str           # what this step does in the data flow
    security_note: str          # security-relevant observation


# ---------------------------------------------------------------------------
# Real-world vulnerability reasoning examples (few-shot)
# ---------------------------------------------------------------------------

_EXAMPLES = """
=== EXAMPLE 1: Use-After-Free → EXPLOITABLE ===

TRACE:
  Step 0: dom/element.cpp:142 — Element* elem = GetChild(id);
  Step 1: dom/element.cpp:155 — RemoveChild(elem);
  Step 2: dom/tree.cpp:89     — free(node);   [inside RemoveChild]
  Step 3: dom/element.cpp:160 — elem->Render();  [POINTER_DEREF after free]

ANALYSIS:
Pointer `elem` obtained at step 0. RemoveChild() at step 1 frees the memory (step 2). Then elem->Render() at step 3 dereferences the freed pointer. No null check, no reassignment between free and use. If heap is reallocated between steps 2–3, attacker controls vtable → code execution.

VERDICT: EXPLOITABLE
CONFIDENCE: 0.92
CLASS: use-after-free
ROOT_CAUSE: elem is dereferenced after being freed in RemoveChild()
TRIGGER: DOM operation that removes then renders the same element
IMPACT: Arbitrary code execution via vtable corruption
GUARDS: None
CWE: CWE-416
EXPLOIT_SKETCH: Force RemoveChild, spray heap with controlled data in freed slot, Render() follows corrupted vtable.

=== EXAMPLE 2: Buffer Overflow → EXPLOITABLE ===

TRACE:
  Step 0: net/packet.cpp:49 — size_t len = packet->GetLength();  [attacker-controlled]
  Step 1: net/packet.cpp:52 — char buf[256];
  Step 2: net/packet.cpp:53 — memcpy(buf, packet->Data(), len);  [overflow if len > 256]

ANALYSIS:
`len` comes from network input (attacker-controlled). memcpy copies `len` bytes into a 256-byte stack buffer. No bounds check anywhere. Trivially exploitable: send len > 256 → stack overflow → overwrite return address.

VERDICT: EXPLOITABLE
CONFIDENCE: 0.95
CLASS: stack-buffer-overflow
ROOT_CAUSE: Attacker-controlled length used in memcpy without bounds check
TRIGGER: Network packet with length > 256
IMPACT: Stack overflow → RCE via return address overwrite
GUARDS: None
CWE: CWE-120
EXPLOIT_SKETCH: Send packet with length=512, payload overwrites return address on stack.

=== EXAMPLE 3: Guarded null check → NOT EXPLOITABLE ===

TRACE:
  Step 0: db/query.cpp:78 — Record* rec = table->Lookup(key);
  Step 1: db/query.cpp:85 — rec->GetField("name");  [POINTER_DEREF]

SOURCE at step 1:
  78 |   Record* rec = table->Lookup(key);
  79 |   if (!rec) {
  80 |       LogError("not found");
  81 |       return nullptr;
  82 |   }
  85 |   rec->GetField("name");  // safe: rec guaranteed non-null here

ANALYSIS:
Lookup() may return null, but lines 79-82 check for null and return early. The dereference at line 85 only runs when rec is non-null. This is a false positive from the trace tool missing the guard.

VERDICT: NOT_EXPLOITABLE
CONFIDENCE: 0.90
CLASS: null-dereference
WHY_NOT: Null check at line 79 with early return guards the dereference at line 85.
GUARDS: if (!rec) return at line 79

=== EXAMPLE 4: Integer Overflow → EXPLOITABLE ===

TRACE:
  Step 0: image/png.cpp:200 — uint32_t width = ReadU32(stream);  [attacker-controlled]
  Step 1: image/png.cpp:201 — uint32_t height = ReadU32(stream);  [attacker-controlled]
  Step 2: image/png.cpp:205 — size_t size = width * height * 4;  [overflow wraps to 0]
  Step 3: image/png.cpp:206 — uint8_t* pixels = malloc(size);  [tiny allocation]
  Step 4: image/png.cpp:210 — DecodePixels(stream, pixels, width, height);  [huge write]

ANALYSIS:
width and height from file input. width*height*4 overflows uint32_t when dimensions are large (e.g. 65536×65536). malloc gets tiny size, DecodePixels writes the real (huge) amount → heap overflow. malloc(0) returns non-null on most systems so the null check doesn't help.

VERDICT: EXPLOITABLE
CONFIDENCE: 0.90
CLASS: integer-overflow → heap-overflow
ROOT_CAUSE: Integer overflow in size = width*height*4 causes undersized allocation
TRIGGER: PNG with dimensions causing uint32_t overflow (e.g. 65536×65536)
IMPACT: Heap overflow → arbitrary code execution
GUARDS: None effective — null check on malloc doesn't prevent the overflow
CWE: CWE-190
EXPLOIT_SKETCH: Craft PNG with overflow dimensions, malloc allocates small buffer, decode writes past it corrupting heap metadata.

=== EXAMPLE 5: Test-only code → NOT EXPLOITABLE ===

TRACE:
  Step 0: testing/test_helper.cpp:20 — auto* doc = reinterpret_cast<Doc*>(handle);
  Step 1: testing/test_helper.cpp:25 — doc->Process();

ANALYSIS:
This is test infrastructure code. The reinterpret_cast is intentionally unsafe for testing purposes. This code only runs in unit tests, never in production. Not a real attack surface.

VERDICT: NOT_EXPLOITABLE
CONFIDENCE: 0.95
CLASS: type-confusion
WHY_NOT: Test-only helper function. Not reachable from production code. Intentionally unsafe for testing.
GUARDS: Not applicable — test code only.
"""

# ---------------------------------------------------------------------------
# Source code reader
# ---------------------------------------------------------------------------

def _read_source_context(
    repo_path: str,
    file_path: str,
    line: int,
    radius: int = 12,
) -> str:
    """Read source code around a specific line with line numbers."""
    full_path = os.path.join(repo_path, file_path)
    try:
        all_lines = Path(full_path).read_text(encoding="utf-8", errors="replace").split("\n")
    except OSError:
        return f"(could not read {file_path})"

    start = max(0, line - 1 - radius)
    end = min(len(all_lines), line + radius)

    numbered = []
    for i in range(start, end):
        marker = " →" if i == line - 1 else "  "
        numbered.append(f"{marker} {i + 1:4d} | {all_lines[i]}")

    return "\n".join(numbered)


def _build_trace_context(
    trace: TracePath,
    repo_path: str,
    max_steps: int = 30,
    code_radius: int = 10,
) -> str:
    """Build a rich context string with trace steps + source code."""
    parts = []

    steps = trace.steps[:max_steps]
    for i, step in enumerate(steps):
        loc = step.location
        loc_str = f"{loc.file}:{loc.line}" if loc else "?"
        edge = f"  [{step.edge_kind.value}]" if step.edge_kind else ""
        kind = f"  ({step.node_kind.value})" if step.node_kind else ""
        name = f"  {step.node_name}" if step.node_name else ""
        is_sink = " ← SINK" if i == len(steps) - 1 else ""
        is_source = " ← SOURCE" if i == 0 else ""

        parts.append(f"Step {i}{is_source}{is_sink}: {loc_str}{edge}{kind}{name}")
        parts.append(f"  Snippet: {step.code_snippet or '?'}")

        # Read actual source code
        if loc and loc.file:
            ctx = _read_source_context(repo_path, loc.file, loc.line, code_radius)
            if ctx and "(could not read" not in ctx:
                parts.append(f"  Source context ({loc.file}:{loc.line}):")
                parts.append(ctx)

        parts.append("")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = f"""You analyze data-flow traces through C/C++ code to determine if they represent exploitable vulnerabilities.

For each trace, you see the steps (source → sink) with actual source code. Your job:
1. Follow the data flow step by step
2. Check for guards (null checks, bounds checks, validation) between source and sink
3. Determine: can an attacker actually exploit this? Yes or no.

{_EXAMPLES}

YOUR RESPONSE FORMAT — you MUST end with this exact block:

VERDICT: <EXPLOITABLE or NOT_EXPLOITABLE>
CONFIDENCE: <0.0 to 1.0>
CLASS: <vulnerability class like use-after-free, buffer-overflow, null-dereference, type-confusion, integer-overflow, or none>
ROOT_CAUSE: <1-2 sentences: what the bug is. Be specific — name the variable, the line, the operation.>
TRIGGER: <what input triggers it — be concrete>
IMPACT: <what happens — e.g. "heap corruption → code execution", "crash", "info leak">
GUARDS: <what prevents exploitation, or "None">
CWE: <CWE-XXX or N/A>
WHY_NOT: <if NOT_EXPLOITABLE: explain exactly why it's safe — name the guard, the check, the reason>
EXPLOIT_SKETCH: <if EXPLOITABLE: 1-2 sentences on how to exploit it>

RULES:
- EXPLOITABLE means: an attacker can trigger this with crafted input and cause harm (crash, code execution, info leak).
- NOT_EXPLOITABLE means: there is a guard, the code is safe, it's test-only, or it's unreachable from attacker input.
- Do NOT hedge. Pick one. If you're unsure, lean toward NOT_EXPLOITABLE and explain why in WHY_NOT.
- ROOT_CAUSE must be concrete: "memcpy at line 53 copies attacker-controlled length into 256-byte stack buffer" — not "potential buffer overflow".

Write your step-by-step analysis FIRST, then the VERDICT block at the END."""


# ---------------------------------------------------------------------------
# Response parser
# ---------------------------------------------------------------------------

def _parse_assessment(raw: str, path_id: str) -> VulnAssessment:
    """Parse the LLM's response into a VulnAssessment.

    Handles structured ("VERDICT: EXPLOITABLE"), markdown, and free-form text.
    """
    assessment = VulnAssessment(path_id=path_id, raw_llm_output=raw)

    # Known field names — used to prevent cross-contamination
    _ALL_FIELDS = (
        "VERDICT", "CONFIDENCE", "CLASS", "ROOT_CAUSE", "ROOT CAUSE",
        "TRIGGER", "IMPACT", "GUARDS", "CWE", "WHY_NOT", "WHY NOT",
        "EXPLOIT_SKETCH", "EXPLOIT SKETCH", "MITIGATIONS",
    )

    def _extract_field(key: str) -> str:
        """Extract a field value, stopping at the next field label."""
        # Build a stop pattern from all OTHER field names
        stop_fields = "|".join(re.escape(f) for f in _ALL_FIELDS if f != key)
        stop_pattern = rf'\n\s*\**(?:{stop_fields})\**\s*:'

        # Pattern A: "KEY: value" (possibly with ** or other markup)
        pattern = rf'(?:^|\n)\s*\**{key}\**\s*:\s*(.+?)(?={stop_pattern}|\Z)'
        m = re.search(pattern, raw, re.DOTALL | re.IGNORECASE)
        if m:
            val = m.group(1).strip()
            # Take only first line for single-value fields
            if key in ("VERDICT", "CONFIDENCE", "CLASS", "CWE"):
                val = val.split("\n")[0].strip()
            # Clean markup
            return re.sub(r'^[\s*`"#→]+|[\s*`"]+$', '', val)

        return ""

    # Extract all fields
    assessment.verdict = _extract_field("VERDICT").upper().replace(" ", "_")
    assessment.vulnerability_class = _extract_field("CLASS")
    assessment.root_cause = _extract_field("ROOT_CAUSE") or _extract_field("ROOT CAUSE")
    assessment.trigger = _extract_field("TRIGGER")
    assessment.impact = _extract_field("IMPACT")
    assessment.guards = _extract_field("GUARDS") or _extract_field("MITIGATIONS")
    assessment.cwe = _extract_field("CWE")
    assessment.exploit_sketch = _extract_field("EXPLOIT_SKETCH") or _extract_field("EXPLOIT SKETCH")
    assessment.why_not = _extract_field("WHY_NOT") or _extract_field("WHY NOT")

    # Extract confidence
    conf_raw = _extract_field("CONFIDENCE").replace("%", "").strip()
    try:
        val = float(conf_raw)
        assessment.confidence = val if val <= 1.0 else val / 100.0
        assessment.confidence = max(0.0, min(1.0, assessment.confidence))
    except (ValueError, TypeError):
        assessment.confidence = -1  # mark as unparsed

    # Extract reasoning: everything before the VERDICT block
    verdict_pos = -1
    for marker in ("VERDICT:", "CONFIDENCE:", "CLASS:", "ROOT_CAUSE:", "ROOT CAUSE:"):
        pos = raw.upper().find(marker)
        if pos > 0 and (verdict_pos < 0 or pos < verdict_pos):
            verdict_pos = pos
    if verdict_pos > 0:
        assessment.reasoning = raw[:verdict_pos].strip()
    else:
        assessment.reasoning = raw.strip()

    # Normalize verdict to binary
    assessment.verdict = _normalize_verdict(assessment.verdict, raw)

    # Infer confidence if not parsed
    if assessment.confidence < 0:
        assessment.confidence = {
            "EXPLOITABLE": 0.80,
            "NOT_EXPLOITABLE": 0.75,
            "NEEDS_REVIEW": 0.40,
        }.get(assessment.verdict, 0.30)

    # Sanity check: root_cause should not contain verdict/field labels
    if assessment.root_cause:
        for field_name in _ALL_FIELDS:
            if field_name in assessment.root_cause.upper() and len(assessment.root_cause) < 50:
                assessment.root_cause = ""  # corrupted — clear it
                break

    # Extract root cause from reasoning if field was empty or corrupted
    if not assessment.root_cause and assessment.reasoning:
        sentences = [s.strip() for s in assessment.reasoning.replace("\n", " ").split(".")
                     if len(s.strip()) > 20]
        if sentences:
            assessment.root_cause = sentences[-1].strip() + "."

    return assessment


def _normalize_verdict(parsed: str, full_text: str) -> str:
    """Normalize to EXPLOITABLE / NOT_EXPLOITABLE / NEEDS_REVIEW."""
    # Direct matches
    if "EXPLOITABLE" in parsed and "NOT" not in parsed:
        return "EXPLOITABLE"
    if "NOT_EXPLOITABLE" in parsed or "NOT EXPLOITABLE" in parsed:
        return "NOT_EXPLOITABLE"

    # Map old-style verdicts
    if parsed in ("VULNERABLE",):
        return "EXPLOITABLE"
    if parsed in ("FALSE_POSITIVE", "SAFE", "NOT_VULNERABLE"):
        return "NOT_EXPLOITABLE"
    if parsed in ("LIKELY",):
        return "EXPLOITABLE"
    if parsed in ("UNLIKELY",):
        return "NOT_EXPLOITABLE"
    if parsed in ("NEEDS_REVIEW",):
        return "NEEDS_REVIEW"

    # Infer from full text
    return _infer_verdict_from_text(full_text)


def _infer_verdict_from_text(text: str) -> str:
    """Infer verdict from free-form prose."""
    lower = text.lower()

    # Exploitable indicators
    exploit_phrases = [
        "this is exploitable",
        "is exploitable",
        "can be exploited",
        "leads to arbitrary code execution",
        "allows remote code execution",
        "heap overflow", "stack overflow",
        "use-after-free", "use after free",
        "buffer overflow", "out-of-bounds write",
        "dangling pointer", "vtable corruption",
        "verdict: exploitable",
        "this is a real vulnerability",
        "this is a real bug",
    ]

    # Not exploitable indicators
    safe_phrases = [
        "not exploitable", "not_exploitable",
        "false positive", "not a vulnerability",
        "not a real vulnerability", "no vulnerability",
        "is safe", "safely guarded", "correctly checks",
        "properly validated", "this is a false positive",
        "no security issue", "no real-world risk",
        "not a bug", "test code", "test helper", "unit test",
        "test-only", "test only", "unreachable",
        "verdict: not_exploitable", "verdict: false_positive",
    ]

    exploit_score = sum(1 for p in exploit_phrases if p in lower)
    safe_score = sum(1 for p in safe_phrases if p in lower)

    if safe_score > exploit_score and safe_score > 0:
        return "NOT_EXPLOITABLE"
    if exploit_score >= 2:
        return "EXPLOITABLE"
    if exploit_score == 1 and safe_score == 0:
        return "EXPLOITABLE"
    if safe_score > 0:
        return "NOT_EXPLOITABLE"

    return "NEEDS_REVIEW"


# ---------------------------------------------------------------------------
# Main Reasoner
# ---------------------------------------------------------------------------

class VulnerabilityReasoner:
    """Reasons about vulnerability traces using LLM analysis.

    Usage::

        from deeptrace.analysis.vulnerability_reasoner import VulnerabilityReasoner
        from deeptrace.analysis.llm_ranker import _call_llm

        llm = lambda sys, msg: _call_llm(config, sys, msg)
        reasoner = VulnerabilityReasoner(llm, repo_path="/path/to/repo")

        # Analyze a single path
        assessment = reasoner.analyze_path(trace_path)

        # Analyze all paths
        results = reasoner.analyze_all(trace_output.paths, top_n=10)
    """

    def __init__(
        self,
        llm_caller: Callable[[str, str], str],
        repo_path: str,
        code_radius: int = 10,
    ) -> None:
        self.llm_call = llm_caller
        self.repo_path = os.path.abspath(repo_path)
        self.code_radius = code_radius

    def analyze_path(self, trace: TracePath) -> VulnAssessment:
        """Analyze a single trace path for real vulnerability potential."""
        # Build the rich context
        trace_context = _build_trace_context(
            trace, self.repo_path, code_radius=self.code_radius,
        )

        # Build the user message — end with a strong format reminder
        user_msg_parts = [
            "Analyze this trace for vulnerabilities.",
            "",
            f"Path ID: {trace.id}",
            f"Depth: {trace.depth} steps",
            f"Tags: {', '.join(trace.vulnerability_tags) or 'none'}",
            f"Z3 Satisfiable: {trace.is_satisfiable}",
        ]

        if trace.constraints:
            user_msg_parts.append(f"Path constraints: {'; '.join(trace.constraints[:5])}")

        if trace.vulnerability_summary:
            user_msg_parts.append(f"Automated summary: {trace.vulnerability_summary}")

        user_msg_parts += [
            "",
            "=== TRACE STEPS WITH SOURCE CODE ===",
            trace_context,
            "",
            "Now analyze this trace. Write your reasoning, then end with the structured VERDICT block.",
            "Remember: VERDICT must be one of VULNERABLE / LIKELY / UNLIKELY / FALSE_POSITIVE",
        ]

        user_msg = "\n".join(user_msg_parts)

        logger.info(
            "Analyzing path %s (%d steps, tags: %s)",
            trace.id, len(trace.steps), trace.vulnerability_tags,
        )

        try:
            raw_response = self.llm_call(_SYSTEM_PROMPT, user_msg)
        except Exception as exc:
            logger.error("LLM call failed for path %s: %s", trace.id, exc)
            return VulnAssessment(
                path_id=trace.id,
                verdict="ERROR",
                reasoning=f"LLM call failed: {exc}",
            )

        assessment = _parse_assessment(raw_response, trace.id)

        # Rescue call: if parsing couldn't determine verdict, ask a focused question
        if assessment.verdict == "NEEDS_REVIEW":
            logger.info("Path %s: verdict unclear — attempting rescue call", trace.id)
            assessment = self._rescue_parse(raw_response, assessment, trace.id)

        logger.info(
            "Path %s: %s (%.0f%% confidence) — %s",
            trace.id, assessment.verdict, assessment.confidence * 100,
            assessment.vulnerability_class,
        )

        return assessment

    def _rescue_parse(
        self,
        original_response: str,
        partial: VulnAssessment,
        path_id: str,
    ) -> VulnAssessment:
        """Short focused LLM call to extract structured fields from a free-form response."""
        rescue_prompt = (
            "You wrote the following vulnerability analysis:\n\n"
            f"{original_response[:3000]}\n\n"
            "Now fill in EXACTLY these fields based on your analysis above. "
            "Write ONLY the fields, nothing else:\n\n"
            "VERDICT: <EXPLOITABLE or NOT_EXPLOITABLE>\n"
            "CONFIDENCE: <0.0 to 1.0>\n"
            "CLASS: <vulnerability class or none>\n"
            "ROOT_CAUSE: <1-2 sentences — name the variable, line, and operation>\n"
            "TRIGGER: <what triggers it, or N/A>\n"
            "IMPACT: <what attacker achieves, or N/A>\n"
            "GUARDS: <existing mitigations, or None>\n"
            "CWE: <CWE-XXX or N/A>\n"
            "WHY_NOT: <if NOT_EXPLOITABLE: why exactly it's safe>\n"
        )

        try:
            rescue_response = self.llm_call(
                "Extract structured fields from the analysis. Output ONLY the fields.",
                rescue_prompt,
            )
            rescued = _parse_assessment(rescue_response, path_id)
            # Keep the original reasoning
            rescued.reasoning = partial.reasoning or original_response[:2000]
            rescued.raw_llm_output = original_response
            if rescued.verdict in ("EXPLOITABLE", "NOT_EXPLOITABLE"):
                logger.info("Rescue succeeded: %s", rescued.verdict)
                return rescued
        except Exception as exc:
            logger.debug("Rescue call failed: %s", exc)

        # Rescue failed too — return partial with inferred verdict
        return partial

    def analyze_all(
        self,
        paths: list[TracePath],
        top_n: int = 10,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> list[VulnAssessment]:
        """Analyze multiple trace paths, sorted by ACO score.

        Args:
            paths: List of trace paths to analyze.
            top_n: Only analyze the top N paths (by score).
            progress_callback: Optional (current, total) callback.

        Returns:
            List of VulnAssessment objects, ordered by confidence.
        """
        # Sort by score (highest first) and take top N
        sorted_paths = sorted(paths, key=lambda p: p.score, reverse=True)[:top_n]

        results: list[VulnAssessment] = []
        for i, path in enumerate(sorted_paths):
            if progress_callback:
                progress_callback(i + 1, len(sorted_paths))

            assessment = self.analyze_path(path)
            results.append(assessment)

        # Sort results: VULNERABLE first, then by confidence
        verdict_order = {"EXPLOITABLE": 0, "NEEDS_REVIEW": 1, "NOT_EXPLOITABLE": 2}
        results.sort(key=lambda a: (
            verdict_order.get(a.verdict, 9),
            -a.confidence,
        ))

        return results


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def format_assessment_report(
    assessments: list[VulnAssessment],
    target: str = "",
    repo: str = "",
) -> str:
    """Format assessments into a readable Markdown report."""
    parts = [
        "# Vulnerability Reasoning Report",
        "",
        f"**Target:** `{target}`" if target else "",
        f"**Repository:** `{repo}`" if repo else "",
        f"**Paths analyzed:** {len(assessments)}",
        "",
    ]

    # Summary table
    exploit_count = sum(1 for a in assessments if a.verdict == "EXPLOITABLE")
    safe_count = sum(1 for a in assessments if a.verdict == "NOT_EXPLOITABLE")
    review_count = sum(1 for a in assessments if a.verdict == "NEEDS_REVIEW")

    parts += [
        "## Summary",
        "",
        f"| Verdict | Count |",
        f"|---------|-------|",
        f"| 🔴 EXPLOITABLE | {exploit_count} |",
        f"| ✅ NOT EXPLOITABLE | {safe_count} |",
        f"| ❓ NEEDS REVIEW | {review_count} |",
        f"| Total | {len(assessments)} |",
        "",
    ]

    # Detailed assessments
    for i, a in enumerate(assessments):
        icon = {
            "EXPLOITABLE": "🔴",
            "NOT_EXPLOITABLE": "✅",
            "NEEDS_REVIEW": "❓",
        }.get(a.verdict, "❓")

        parts += [
            f"---",
            f"## Path {i+1}: {icon} {a.verdict} ({a.confidence:.0%} confidence)",
            "",
            f"**Class:** {a.vulnerability_class}" if a.vulnerability_class else "",
            f"**CWE:** {a.cwe}" if a.cwe else "",
            f"**Path ID:** `{a.path_id}`",
            "",
        ]

        if a.root_cause:
            parts += [f"### Root Cause", "", a.root_cause, ""]

        if a.why_not:
            parts += [f"### Why Not Exploitable", "", a.why_not, ""]

        if a.reasoning:
            parts += [f"### Reasoning", "", a.reasoning, ""]

        if a.trigger:
            parts += [f"### Trigger", "", a.trigger, ""]

        if a.impact:
            parts += [f"### Impact", "", a.impact, ""]

        if a.guards:
            parts += [f"### Guards / Mitigations", "", a.guards, ""]

        if a.exploit_sketch:
            parts += [f"### Exploit Sketch", "", a.exploit_sketch, ""]

        parts.append("")

    return "\n".join(parts)


def assessments_to_json(assessments: list[VulnAssessment]) -> list[dict]:
    """Convert assessments to JSON-serializable dicts."""
    return [
        {
            "path_id": a.path_id,
            "verdict": a.verdict,
            "confidence": a.confidence,
            "vulnerability_class": a.vulnerability_class,
            "root_cause": a.root_cause,
            "trigger": a.trigger,
            "impact": a.impact,
            "guards": a.guards,
            "cwe": a.cwe,
            "why_not": a.why_not,
            "exploit_sketch": a.exploit_sketch,
            "reasoning": a.reasoning,
        }
        for a in assessments
    ]
#src\deeptrace\backends\dynamic_resolver.py
"""Dynamic resolution backend: ripgrep + LLM tie-breaker for broken graph edges."""

from __future__ import annotations

import io
import json
import logging
import os
import platform
import shutil
import stat
import subprocess
import sys
import urllib.request
import zipfile
import tarfile
from dataclasses import dataclass

from deeptrace.models.config import LLMConfig
from deeptrace.analysis.llm_ranker import _call_llm

logger = logging.getLogger(__name__)

_DISAMBIGUATION_PROMPT = """You are a senior security researcher analyzing a multi-language codebase (C, C++, Rust, Java, Kotlin, Swift, ObjC, Python).
An automated static analysis tool hit a dead end at a function call. It might be a standard call, or it might be a cross-language FFI (Foreign Function Interface) call.

Caller Context:
File: {caller_file}
Code: {caller_code}
Calling Function / Missing Symbol: {callee_name}

Candidate Definitions Found Across the Repository:
{candidates}

Your job is to identify the correct definition of the function being called.
CRITICAL FFI RULES:
- If this is Java/Kotlin calling C/C++, look for JNI naming conventions (e.g., `Java_com_package_class_method`).
- If this is Python calling C/C++, look for PyBind11, ctypes, or CPython extension macros (`PyMethodDef`).
- If this is Swift/ObjC calling C/C++, look for `extern "C"` or Bridging Headers.
- If this is Rust, look for `#[no_mangle] extern "C"`.

Analyze the caller context and determine which candidate is the exact execution target.
Respond ONLY with a JSON object. No explanations.
Schema:
{{
  "selected_index": <int>
}}
"""

@dataclass
class ResolutionResult:
    resolved: bool
    file_path: str = ""
    line_number: int = 0
    code_snippet: str = ""


class DynamicResolver:
    def __init__(self, repo_path: str, llm_config: LLMConfig):
        self.repo_path = repo_path
        self.llm_config = llm_config
        # Cache mapping: (caller_file, callee_name) -> ResolutionResult
        self._cache: dict[tuple[str, str], ResolutionResult] = {}
        # Get or download ripgrep binary
        self._rg_cmd = self._get_rg_exe()

    def _get_rg_exe(self) -> str:
        """Find ripgrep in PATH, or auto-install a portable version locally."""
        if shutil.which("rg"):
            return "rg"

        bin_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".bin")
        exe_name = "rg.exe" if sys.platform == "win32" else "rg"
        rg_path = os.path.join(bin_dir, exe_name)

        if os.path.exists(rg_path):
            return rg_path

        logger.info("ripgrep not found in PATH. Auto-downloading portable binary...")
        os.makedirs(bin_dir, exist_ok=True)

        if sys.platform == "win32":
            url = "https://github.com/BurntSushi/ripgrep/releases/download/14.1.0/ripgrep-14.1.0-x86_64-pc-windows-msvc.zip"
        elif sys.platform == "darwin":
            if platform.machine() == "arm64":
                url = "https://github.com/BurntSushi/ripgrep/releases/download/14.1.0/ripgrep-14.1.0-aarch64-apple-darwin.tar.gz"
            else:
                url = "https://github.com/BurntSushi/ripgrep/releases/download/14.1.0/ripgrep-14.1.0-x86_64-apple-darwin.tar.gz"
        else:
            return "rg"

        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as response:
                if url.endswith(".zip"):
                    with zipfile.ZipFile(io.BytesIO(response.read())) as z:
                        for name in z.namelist():
                            if name.endswith("rg.exe"):
                                with z.open(name) as source, open(rg_path, "wb") as target:
                                    shutil.copyfileobj(source, target)
                                break
                elif url.endswith(".tar.gz"):
                    with tarfile.open(fileobj=io.BytesIO(response.read()), mode="r:gz") as t:
                        for member in t.getmembers():
                            if member.name.endswith("rg") and member.isfile():
                                with t.extractfile(member) as source, open(rg_path, "wb") as target:
                                    shutil.copyfileobj(source, target)
                                break

            if sys.platform != "win32":
                st = os.stat(rg_path)
                os.chmod(rg_path, st.st_mode | stat.S_IEXEC)

            logger.info("Successfully installed portable ripgrep to %s", rg_path)
            return rg_path
        except Exception as exc:
            logger.error("Failed to auto-install portable ripgrep: %s", exc)
            return "rg"

    def resolve_call(self, caller_file: str, caller_code: str, callee_name: str) -> ResolutionResult:
        """Finds the definition of a missing function using rg, with LLM tie-breaking and caching."""

        cache_key = (caller_file, callee_name)
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Simpler, faster regex to avoid catastrophic backtracking timeouts
        rg_regex = f"\\b.*{callee_name}.*\\b"

        try:
            result = subprocess.run(
                [self._rg_cmd, "-n", rg_regex, self.repo_path],
                capture_output=True, text=True, timeout=5
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.error("ripgrep search failed: %s", exc)
            failed_result = ResolutionResult(resolved=False)
            self._cache[cache_key] = failed_result
            return failed_result

        if not result.stdout:
            failed_result = ResolutionResult(resolved=False)
            self._cache[cache_key] = failed_result
            return failed_result

        candidates = []
        # Hard limit to 15 candidates to protect the LLM context window
        for line in result.stdout.strip().split("\n")[:15]:
            parts = line.split(":", 2)
            if len(parts) >= 3:
                candidates.append({
                    "file": parts[0].replace(self.repo_path, "").lstrip("/\\"),
                    "line": int(parts[1]),
                    "code": parts[2].strip()
                })

        if not candidates:
            failed_result = ResolutionResult(resolved=False)
            self._cache[cache_key] = failed_result
            return failed_result

        if len(candidates) == 1:
            logger.debug("Auto-resolved %s to %s", callee_name, candidates[0]["file"])
            success_result = ResolutionResult(
                resolved=True,
                file_path=candidates[0]["file"],
                line_number=candidates[0]["line"],
                code_snippet=candidates[0]["code"]
            )
            self._cache[cache_key] = success_result
            return success_result

        if not self.llm_config.enabled:
            logger.warning("Multiple targets for %s, but LLM disabled. Failing.", callee_name)
            failed_result = ResolutionResult(resolved=False)
            self._cache[cache_key] = failed_result
            return failed_result

        final_result = self._ask_llm_to_disambiguate(caller_file, caller_code, callee_name, candidates)
        self._cache[cache_key] = final_result
        return final_result

    def _ask_llm_to_disambiguate(self, caller_file: str, caller_code: str, callee_name: str, candidates: list[dict]) -> ResolutionResult:
        candidates_text = "\n".join(
            f"[{i}] File: {c['file']} Line: {c['line']} Code: {c['code']}"
            for i, c in enumerate(candidates)
        )

        user_msg = _DISAMBIGUATION_PROMPT.format(
            caller_file=caller_file,
            caller_code=caller_code,
            callee_name=callee_name,
            candidates=candidates_text
        )

        try:
            logger.info("Invoking LLM tie-breaker for ambiguous call: %s in %s", callee_name, caller_file)
            response_text = _call_llm(self.llm_config, "You are a precise JSON-only output agent.", user_msg)

            start_idx = response_text.find("{")
            end_idx = response_text.rfind("}")
            if start_idx >= 0 and end_idx >= 0:
                data = json.loads(response_text[start_idx:end_idx+1])
                selected = data.get("selected_index", -1)

                if 0 <= selected < len(candidates):
                    chosen = candidates[selected]
                    logger.info("LLM successfully disambiguated %s -> %s", callee_name, chosen['file'])
                    return ResolutionResult(
                        resolved=True,
                        file_path=chosen["file"],
                        line_number=chosen["line"],
                        code_snippet=chosen["code"]
                    )
        except Exception as exc:
            logger.error("LLM disambiguation failed: %s", exc)

        return ResolutionResult(resolved=False)
#src\deeptrace\backends\joern.py
"""Joern backend: runs Joern inside Docker to extract CPG and dataflow."""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from deeptrace.models.config import JoernConfig
from deeptrace.models.graph import (
    BackendKind,
    EdgeKind,
    GraphEdge,
    GraphNode,
    Language,
    NodeKind,
    SourceLocation,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

_EXT_MAP: dict[str, Language] = {
    ".c": Language.C, ".h": Language.C,
    ".cc": Language.CPP, ".cpp": Language.CPP, ".cxx": Language.CPP,
    ".hh": Language.CPP, ".hpp": Language.CPP, ".hxx": Language.CPP,
    ".java": Language.JAVA,
    ".kt": Language.KOTLIN, ".kts": Language.KOTLIN,
    ".py": Language.PYTHON,
    ".swift": Language.SWIFT,
    ".rs": Language.RUST,
    ".m": Language.OBJC, ".mm": Language.OBJC,
}

_JOERN_LANG: dict[Language, str] = {
    Language.C: "NEWC",
    Language.CPP: "NEWC",
    Language.JAVA: "JAVASRC",
    Language.KOTLIN: "KOTLIN",
    Language.SWIFT: "SWIFTSRC",
}

JOERN_PRIMARY: set[Language] = {Language.C, Language.CPP, Language.JAVA, Language.KOTLIN, Language.SWIFT}


def detect_language(target_file: str) -> Language | None:
    ext = Path(target_file).suffix.lower()
    return _EXT_MAP.get(ext)


def is_joern_primary(lang: Language | None) -> bool:
    return lang is not None and lang in JOERN_PRIMARY


# ---------------------------------------------------------------------------
# Joern script templates
# ---------------------------------------------------------------------------

_SCRIPT_IMPORT = r'''import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import scala.util.Try

implicit val engineContext: EngineContext = EngineContext()

val cpg = importCpg("__CPG_PATH__").get
println("CPG_LOADED")
'''

_SCRIPT_FLOWS = r'''val targetFile = "__TARGET_FILE__"
val targetLine = __TARGET_LINE__
val maxFlows = __MAX_FLOWS__

// Store IDs to iterate, preventing the loss of the Traversal context later
val sinkIds = (cpg.call.lineNumber(targetLine).where(_.file.name(".*" + targetFile + "$")).id.l ++
  cpg.identifier.lineNumber(targetLine).where(_.file.name(".*" + targetFile + "$")).id.l).distinct

println("SINKS=" + sinkIds.size.toString)

var flowCount = 0
println("FLOWS_TSV_START")

sinkIds.foreach { sId =>
  if (flowCount < maxFlows) {
    scala.util.Try {
      val sinkT = cpg.call.id(sId) ++ cpg.identifier.id(sId)
      // THE FIX: Broad enough to cross files, safe enough to prevent timeouts
      val sources = cpg.methodParameterIn ++ cpg.call.nameNot("<operator>.*") ++ cpg.identifier
      sinkT.reachableByFlows(sources)
    }.toOption.foreach { paths =>
      paths.foreach { flow =>
        if (flowCount < maxFlows) {
          println("FLOW_START")
          flow.elements.foreach { elem =>
            val nid = elem.id.toString
            val lbl = elem.label
            val f = scala.util.Try(elem.file.name.head).getOrElse("?")
            val ln = elem.lineNumber.getOrElse(0).toString
            val cl = elem.columnNumber.getOrElse(0).toString
            val cd = elem.code.take(500).replace("\n", " ").replace("\r", " ").replace("\t", " ")
            val nm = elem.code.take(60).replace("\n", " ").replace("\t", " ")
            println("STEP\t" + nid + "\t" + lbl + "\t" + nm + "\t" + f + "\t" + ln + "\t" + cl + "\t" + cd)
          }
          println("FLOW_END")
          flowCount = flowCount + 1
        }
      }
    }
  }
}

println("FLOWS_TSV_END")
println("FLOWS=" + flowCount.toString)
'''

_SCRIPT_CALLGRAPH = r'''println("CALLGRAPH_TSV_START")
cpg.call.take(__MAX_EDGES__).foreach { c =>
  val callerId = c.id.toString  // USE THE EXACT CALL SITE ID, NOT THE METHOD NAME
  val callee = c.methodFullName
  val file = c.file.name.headOption.getOrElse("?")
  val line = c.lineNumber.getOrElse(0).toString
  val code = c.code.take(200).replace("\n", " ").replace("\r", " ").replace("\t", " ")
  println("CALL\t" + callerId + "\t" + callee + "\t" + file + "\t" + line + "\t" + code)
}
println("CALLGRAPH_TSV_END")
'''

def _render_import(cpg_path: str) -> str:
    return _SCRIPT_IMPORT.replace("__CPG_PATH__", cpg_path)


def _render_flows(target_file: str, target_line: int, max_flows: int) -> str:
    return (
        _SCRIPT_FLOWS
        .replace("__TARGET_FILE__", target_file)
        .replace("__TARGET_LINE__", str(target_line))
        .replace("__MAX_FLOWS__", str(max_flows))
    )


def _render_callgraph(max_edges: int) -> str:
    return _SCRIPT_CALLGRAPH.replace("__MAX_EDGES__", str(max_edges))


# ---------------------------------------------------------------------------
# Docker execution
# ---------------------------------------------------------------------------

class JoernBackend:
    """Manages Joern via Docker for CPG generation and querying."""

    def __init__(self, config: JoernConfig, repo_path: str) -> None:
        self.config = config
        self.repo_path = os.path.abspath(repo_path)
        self._container_id: str | None = None
        self._cpg_path: str = "/workspace/cpg.bin"
        self._work_dir = tempfile.mkdtemp(prefix="deeptrace_joern_")

    def _run_docker(self, cmd: list[str], timeout: int | None = None) -> str:
        timeout = timeout or self.config.container_timeout
        full_cmd = ["docker"] + cmd
        logger.debug("Running: %s", " ".join(full_cmd))
        result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            logger.debug("Docker stderr: %s", result.stderr[:2000])
            logger.debug("Docker stdout (tail): %s", result.stdout[-2000:] if result.stdout else "<empty>")
            raise RuntimeError(f"Docker command failed (rc={result.returncode}): {result.stderr[:500]}")
        return result.stdout

    def _ensure_container(self) -> str:
        if self._container_id:
            return self._container_id
        mount_flag = "ro" if self.config.mount_readonly else "rw"
        cmd = [
            "run", "-d", "--rm",
            "--name", f"deeptrace-joern-{os.getpid()}",
            "-v", f"{self.repo_path}:/repo:{mount_flag}",
            "-v", f"{self._work_dir}:/workspace",
            f"--memory={self.config.memory_limit}",
            f"--cpus={self.config.cpus}",
            self.config.docker_image,
            "tail", "-f", "/dev/null",
        ]
        self._container_id = self._run_docker(cmd).strip()[:12]
        logger.info("Started Joern container: %s", self._container_id)
        return self._container_id

    def _exec_in_container(self, cmd: str, timeout: int | None = None) -> str:
        cid = self._ensure_container()
        timeout = timeout or self.config.query_timeout
        return self._run_docker(["exec", cid, "bash", "-c", cmd], timeout=timeout)

    def _exec_joern_script(self, script: str, timeout: int | None = None) -> str:
        script_path = "/workspace/query.sc"
        local_script_path = os.path.join(self._work_dir, "query.sc")
        with open(local_script_path, "w", encoding="utf-8") as f:
            f.write(script)
        logger.debug("Joern script written to %s (%d bytes)", local_script_path, len(script))
        timeout = timeout or self.config.query_timeout
        return self._exec_in_container(
            f"cd /workspace && joern --script {script_path} 2>&1",
            timeout=timeout,
        )

    def cleanup(self) -> None:
        if self._container_id:
            try:
                subprocess.run(["docker", "stop", self._container_id], capture_output=True, timeout=30)
            except Exception:
                pass
            self._container_id = None

    # -----------------------------------------------------------------------
    # CPG generation / save / load
    # -----------------------------------------------------------------------

    def generate_cpg(self, language: Language | None = None) -> None:
        cid = self._ensure_container()
        if self.config.cpg_load_path:
            self.load_cpg(self.config.cpg_load_path)
            return
        lang_flag = ""
        if language and language in _JOERN_LANG:
            lang_flag = f"--language {_JOERN_LANG[language]}"
        extra = " ".join(self.config.extra_joern_opts)
        logger.info("Generating CPG for %s (lang=%s)...", self.repo_path, language)
        t0 = time.time()
        self._exec_in_container(f"joern-parse /repo -o {self._cpg_path} {lang_flag} {extra}", timeout=self.config.cpg_timeout)
        logger.info("CPG generated in %.1fs", time.time() - t0)
        if self.config.cpg_save_path:
            self.save_cpg(self.config.cpg_save_path)

    def save_cpg(self, host_path: str) -> None:
        if not self._container_id:
            raise RuntimeError("No active Joern container")
        host_path = os.path.abspath(host_path)
        os.makedirs(os.path.dirname(host_path) or ".", exist_ok=True)
        logger.info("Saving CPG to %s ...", host_path)
        t0 = time.time()
        subprocess.run(["docker", "cp", f"{self._container_id}:{self._cpg_path}", host_path], check=True, capture_output=True, timeout=120)
        size_mb = os.path.getsize(host_path) / (1024 * 1024)
        logger.info("CPG saved: %s (%.1f MB) in %.1fs", host_path, size_mb, time.time() - t0)

    def load_cpg(self, host_path: str) -> None:
        if not self._container_id:
            raise RuntimeError("No active Joern container")
        host_path = os.path.abspath(host_path)
        if not os.path.exists(host_path):
            raise FileNotFoundError(f"CPG file not found: {host_path}")
        size_mb = os.path.getsize(host_path) / (1024 * 1024)
        logger.info("Loading pre-built CPG from %s (%.1f MB)...", host_path, size_mb)
        t0 = time.time()
        subprocess.run(["docker", "cp", host_path, f"{self._container_id}:{self._cpg_path}"], check=True, capture_output=True, timeout=120)
        logger.info("CPG loaded in %.1fs (skipped joern-parse)", time.time() - t0)

    # -----------------------------------------------------------------------
    # Flow extraction
    # -----------------------------------------------------------------------

    def extract_backward_flows(self, target_file: str, target_line: int, max_flows: int = 400) -> list[list[dict[str, Any]]]:
        logger.info("Extracting backward flows to %s:%d (max=%d)", target_file, target_line, max_flows)
        script = _render_import(self._cpg_path)
        script += _render_flows(target_file, target_line, max_flows)
        output = self._exec_joern_script(script, timeout=self.config.query_timeout)
        return self._parse_tsv_flows(output)

    def extract_call_graph(self, max_edges: int = 2000) -> list[dict[str, Any]]:
        script = _render_import(self._cpg_path)
        script += _render_callgraph(max_edges)
        output = self._exec_joern_script(script, timeout=self.config.query_timeout)
        return self._parse_tsv_calls(output)

    def extract_pdg_edges(self, target_file: str, max_edges: int = 2000) -> list[dict[str, Any]]:
        return []  # PDG extraction disabled

    # -----------------------------------------------------------------------
    # TSV parsing
    # -----------------------------------------------------------------------

    @staticmethod
    def _parse_tsv_flows(output: str) -> list[list[dict[str, Any]]]:
        flows: list[list[dict[str, Any]]] = []
        current: list[dict[str, Any]] = []
        active = False
        for line in output.split("\n"):
            s = line.strip()
            if s == "FLOWS_TSV_START":
                active = True
            elif s == "FLOWS_TSV_END":
                break
            elif not active:
                continue
            elif s == "FLOW_START":
                current = []
            elif s == "FLOW_END":
                if current:
                    flows.append(current)
            elif s.startswith("STEP\t"):
                parts = s.split("\t", 7)
                if len(parts) >= 7:
                    current.append({
                        "id": parts[1], "label": parts[2], "name": parts[3],
                        "file": parts[4],
                        "line": int(parts[5]) if parts[5].lstrip("-").isdigit() else 0,
                        "col": int(parts[6]) if parts[6].lstrip("-").isdigit() else 0,
                        "code": parts[7] if len(parts) > 7 else "",
                    })
        logger.info("Parsed %d flows from Joern TSV", len(flows))
        return flows

    @staticmethod
    def _parse_tsv_calls(output: str) -> list[dict[str, Any]]:
        edges: list[dict[str, Any]] = []
        active = False
        for line in output.split("\n"):
            s = line.strip()
            if s == "CALLGRAPH_TSV_START":
                active = True
            elif s == "CALLGRAPH_TSV_END":
                break
            elif not active:
                continue
            elif s.startswith("CALL\t"):
                parts = s.split("\t", 5)
                if len(parts) >= 5:
                    edges.append({
                        "caller": parts[1], "callee": parts[2], "file": parts[3],
                        "line": int(parts[4]) if parts[4].lstrip("-").isdigit() else 0,
                        "code": parts[5] if len(parts) > 5 else "",
                    })
        logger.info("Parsed %d call edges from Joern TSV", len(edges))
        return edges


# ---------------------------------------------------------------------------
# Flow → Graph conversion
# ---------------------------------------------------------------------------

def flows_to_graph(
    flows: list[list[dict[str, Any]]],
    call_edges: list[dict[str, Any]] | None = None,
) -> tuple[list[GraphNode], list[GraphEdge]]:
    nodes_map: dict[str, GraphNode] = {}
    edges_set: set[str] = set()
    edges: list[GraphEdge] = []

    def _node_id(item: dict[str, Any]) -> str:
        return f"j:{item.get('file', '?')}:{item.get('line', 0)}:{item.get('name', item.get('id', '?'))}"

    def _classify_node(label: str) -> NodeKind:
        ll = label.lower()
        if "call" in ll: return NodeKind.CALL_SITE
        if "identifier" in ll: return NodeKind.IDENTIFIER
        if "param" in ll: return NodeKind.PARAM
        if "return" in ll: return NodeKind.RETURN_VAL
        if "literal" in ll: return NodeKind.LITERAL
        if "field" in ll: return NodeKind.FIELD
        return NodeKind.UNKNOWN

    def _classify_edge(src_label: str, dst_label: str) -> EdgeKind:
        if "param" in dst_label.lower(): return EdgeKind.PARAM_PASS
        if "return" in src_label.lower(): return EdgeKind.RETURN
        if "call" in src_label.lower() or "call" in dst_label.lower(): return EdgeKind.CALL
        if "field" in src_label.lower() or "field" in dst_label.lower(): return EdgeKind.FIELD_ACCESS
        return EdgeKind.DATA_FLOW

    for flow in flows:
        prev_id: str | None = None
        current_method: str = ""
        for step in flow:
            nid = _node_id(step)
            # Track enclosing method scope from Joern labels.
            # IMPORTANT: Only METHOD / METHOD_RETURN labels carry the real
            # function name.  METHOD_PARAMETER_IN nodes carry the *parameter
            # declaration* (e.g. "const WideString& str") which must NOT be
            # used as the scope — that would make the frontier expander search
            # for call sites of "const WideString& str" instead of "CheckMailLink".
            label = step.get("label", "").upper()
            step_name = step.get("name", "")
            if step_name and ("METHOD" in label and "PARAM" not in label):
                current_method = step_name

            if nid not in nodes_map:
                nodes_map[nid] = GraphNode(
                    id=nid, kind=_classify_node(step.get("label", "")),
                    name=step_name,
                    location=SourceLocation(
                        file=step.get("file", ""), line=step.get("line", 0),
                        column=step.get("col", 0), code_snippet=step.get("code", ""),
                    ),
                    backend=BackendKind.JOERN,
                    properties={"scope": current_method},
                )
            if prev_id and prev_id != nid:
                eid = f"{prev_id}->{nid}"
                if eid not in edges_set:
                    edges_set.add(eid)
                    prev_label = nodes_map[prev_id].kind.value if prev_id in nodes_map else ""
                    edges.append(GraphEdge(src=prev_id, dst=nid, kind=_classify_edge(prev_label, step.get("label", "")), backend=BackendKind.JOERN))
            prev_id = nid

    if call_edges:
        for ce in call_edges:
            # Build caller ID consistently with flow nodes (file:line:code-based)
            caller_file = ce.get("file", "?")
            caller_line = ce.get("line", 0)
            caller_code = ce.get("code", "")[:60].replace("\t", " ").replace("\n", " ")
            caller_id = f"j:{caller_file}:{caller_line}:call:{caller_code}"

            # Extract short function name from fully-qualified callee name
            callee_full = ce.get("callee", "")
            callee_short = callee_full.rsplit(".", 1)[-1] if callee_full else ""
            callee_id = f"j:method:{callee_full}"

            if caller_id not in nodes_map:
                nodes_map[caller_id] = GraphNode(id=caller_id, kind=NodeKind.CALL_SITE, name=callee_short,
                    location=SourceLocation(file=caller_file, line=caller_line, code_snippet=ce.get("code", "")),
                    backend=BackendKind.JOERN,
                    properties={"scope": ""})

            # Callee stubs represent the function definition target, not a call site
            if callee_id not in nodes_map:
                nodes_map[callee_id] = GraphNode(id=callee_id, kind=NodeKind.IDENTIFIER, name=callee_short,
                    backend=BackendKind.JOERN,
                    properties={"scope": callee_short})

            eid = f"{caller_id}->{callee_id}"
            if eid not in edges_set:
                edges_set.add(eid)
                edges.append(GraphEdge(src=caller_id, dst=callee_id, kind=EdgeKind.CALL, backend=BackendKind.JOERN))

    return list(nodes_map.values()), edges
#src\deeptrace\backends\treesitter.py
"""Tree-sitter backend: fast syntax-based fallback and enrichment."""

from __future__ import annotations

import logging
import os
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any

from deeptrace.models.config import TreeSitterConfig
from deeptrace.models.graph import (
    BackendKind,
    EdgeKind,
    GraphEdge,
    GraphNode,
    Language,
    NodeKind,
    SourceLocation,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Language → tree-sitter grammar mapping
# ---------------------------------------------------------------------------

_TS_LANG_MAP: dict[Language, str] = {
    Language.C: "c",
    Language.CPP: "cpp",
    Language.JAVA: "java",
    Language.KOTLIN: "kotlin",
    Language.SWIFT: "swift",
    Language.RUST: "rust",
    Language.OBJC: "objc",
    Language.PYTHON: "python",
}

_EXT_TO_LANG: dict[str, Language] = {
    ".c": Language.C, ".h": Language.C,
    ".cc": Language.CPP, ".cpp": Language.CPP, ".cxx": Language.CPP,
    ".hpp": Language.CPP, ".hxx": Language.CPP, ".hh": Language.CPP,
    ".java": Language.JAVA,
    ".kt": Language.KOTLIN, ".kts": Language.KOTLIN,
    ".swift": Language.SWIFT,
    ".rs": Language.RUST,
    ".m": Language.OBJC, ".mm": Language.OBJC,
    ".py": Language.PYTHON,
}


def _read_file_safe(path: str, max_kb: int = 2048) -> str | None:
    """Read a file, returning None if too large or unreadable."""
    try:
        size = os.path.getsize(path)
        if size > max_kb * 1024:
            return None
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# tree-sitter parsing
# ---------------------------------------------------------------------------

_COMMON_NOISE_NAMES: set[str] = {
    "i", "j", "k", "n", "m", "x", "y", "p", "c", "s", "t", "a", "b",
    "e", "f", "r", "v", "w", "d", "l", "h", "g", "u", "o", "q", "z",
    "int", "void", "bool", "char", "auto", "true", "false", "NULL",
    "nullptr", "size_t", "std", "this", "self", "super",
    "return", "break", "continue", "const", "static", "inline",
    "public", "private", "protected", "virtual", "override",
    "include", "define", "ifdef", "ifndef", "endif", "pragma",
    "unsigned", "signed", "long", "short", "float", "double",
    "class", "struct", "enum", "union", "typedef", "namespace",
    "new", "delete", "sizeof", "typeof", "decltype",
    "if", "else", "for", "while", "do", "switch", "case", "default",
    "try", "catch", "throw", "noexcept", "explicit", "constexpr",
    "vector", "map", "set", "pair", "list", "array", "span", "string",
    "unique_ptr", "shared_ptr", "optional", "variant",
    "assert", "ASSERT", "DCHECK", "CHECK",
    "NOTREACHED", "DCHECK_EQ", "DCHECK_NE", "DCHECK_LT", "DCHECK_GT",
    # Macros and memory functions that poison traces
    "UNSAFE_TODO", "FXSYS_memcpy", "strlen", "memset",
}


class TreeSitterBackend:
    """Extracts dependency edges using tree-sitter AST parsing."""

    def __init__(self, config: TreeSitterConfig, repo_path: str) -> None:
        self.config = config
        self.repo_path = os.path.abspath(repo_path)
        self._parsers: dict[str, Any] = {}
        self._failed_languages: set[str] = set()
        self._ctags_symbols: dict[str, list[dict[str, str]]] | None = None
        self._scope_last_use: dict[str, str] = {}
        self._builtin_defs: dict[str, list[tuple[str, int]]] = defaultdict(list)
        self._include_graph: dict[str, set[str]] = defaultdict(set)

    def _get_parser(self, language: Language) -> Any:
        ts_name = _TS_LANG_MAP.get(language)
        if not ts_name:
            raise ValueError(f"No tree-sitter grammar for {language}")

        if ts_name in self._parsers:
            return self._parsers[ts_name]

        try:
            from tree_sitter_languages import get_parser
            parser = get_parser(ts_name)
            self._parsers[ts_name] = parser
            return parser
        except Exception as exc:
            raise RuntimeError(
                f"Failed to load tree-sitter parser for {ts_name}. "
                "Ensure you have run: pip install tree-sitter-languages"
            ) from exc

    def _get_ctags_exe(self) -> str:
        """Find ctags in PATH, or auto-install a portable version locally."""
        import shutil
        import urllib.request
        import zipfile
        import io
        import sys

        # 1. Check if it already exists in the system PATH
        if shutil.which("ctags"):
            return "ctags"

        # 2. If not Windows, we cannot safely auto-install a generic binary
        if sys.platform != "win32":
            return "ctags"

        # 3. Setup local portable binary path
        bin_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".bin")
        ctags_exe = os.path.join(bin_dir, "ctags.exe")

        if os.path.exists(ctags_exe):
            return ctags_exe

        # 4. Auto-download and extract
        logger.info("Universal Ctags not found in PATH. Auto-downloading portable binary...")
        os.makedirs(bin_dir, exist_ok=True)

        # Hardcoding a stable release URL to ensure it doesn't break on API changes
        url = "https://github.com/universal-ctags/ctags-win32/releases/download/p6.1.20240317.0/ctags-p6.1.20240317.0-x64.zip"

        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as response:
                with zipfile.ZipFile(io.BytesIO(response.read())) as z:
                    z.extract("ctags.exe", bin_dir)
            logger.info("Successfully installed portable ctags to %s", ctags_exe)
            return ctags_exe
        except Exception as exc:
            logger.error("Failed to auto-install portable ctags: %s", exc)
            return "ctags"  # Fallback to failing naturally

    def _load_ctags(self) -> dict[str, list[dict[str, str]]]:
        if self._ctags_symbols is not None:
            return self._ctags_symbols

        self._ctags_symbols = {}
        if not self.config.use_ctags:
            return self._ctags_symbols

        try:
            ctags_cmd = self._get_ctags_exe()
            result = subprocess.run(
                [
                    ctags_cmd, "--output-format=json", "--fields=+ne",
                    "-R", "--languages=C,C++,Java,Kotlin,Rust,ObjectiveC",
                    self.repo_path,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",  # FORCE UTF-8
                errors="replace",  # IGNORE GARBAGE BYTES
                timeout=60,
            )

            if not result.stdout:
                return self._ctags_symbols

            import json
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    tag = json.loads(line)
                    name = tag.get("name", "")
                    if name:
                        self._ctags_symbols.setdefault(name, []).append(tag)
                except Exception:
                    continue
            logger.info("ctags indexed %d unique symbols", len(self._ctags_symbols))
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.warning("ctags not available: %s", exc)

        return self._ctags_symbols

    def resolve_symbol(self, name: str) -> list[dict[str, str]]:
        syms = self._load_ctags()
        return syms.get(name, [])

    def extract_edges_for_file(
        self,
        file_path: str,
        language: Language,
        target_line: int | None = None,
    ) -> tuple[list[GraphNode], list[GraphEdge]]:
        file_path = file_path.replace("\\", "/")
        abs_path = os.path.join(self.repo_path, file_path)
        source = _read_file_safe(abs_path, self.config.max_file_size_kb)
        if source is None:
            return [], []

        parser = self._get_parser(language)
        tree = parser.parse(source.encode("utf-8"))

        nodes_map: dict[str, GraphNode] = {}
        edges: list[GraphEdge] = []
        edges_set: set[str] = set()

        self._scope_last_use.clear()

        self._walk_tree(
            tree.root_node, file_path, source, language,
            nodes_map, edges, edges_set, target_line,
        )

        return list(nodes_map.values()), edges

    def _walk_tree(
        self,
        node: Any,
        file_path: str,
        source: str,
        language: Language,
        nodes_map: dict[str, GraphNode],
        edges: list[GraphEdge],
        edges_set: set[str],
        target_line: int | None,
        parent_scope: str | None = None,
        current_condition: dict[str, Any] | None = None,
    ) -> None:
        node_type = node.type
        start_line = node.start_point[0] + 1

        current_scope = parent_scope

        if node_type in (
            "function_definition", "function_declarator",
            "method_declaration", "function_declaration",
            "fun_declaration",
        ):
            def _extract_node_name(n: Any) -> str | None:
                if n.type in ("identifier", "field_identifier", "scoped_identifier", "name"):
                    return n.text.decode("utf-8", errors="replace").split("::")[-1]
                for child in n.children:
                    found = _extract_node_name(child)
                    if found:
                        return found
                return None

            decl = self._find_child_by_type(node, "function_declarator") or node
            extracted_scope = _extract_node_name(decl)
            if extracted_scope:
                current_scope = extracted_scope
                if current_scope and len(current_scope) > 2:
                    self._builtin_defs[current_scope].append((file_path, start_line))

        # Parse control structure conditions for Z3 math extraction (Properly isolated)
        if node_type in ("if_statement", "while_statement", "for_statement", "do_statement"):
            cond_node = node.child_by_field_name("condition")
            if cond_node:
                parsed_cond = self._parse_ast_condition(cond_node)
                if parsed_cond:
                    current_condition = parsed_cond

        if node_type == "preproc_include":
            path_node = self._find_child_by_type(node, "string_literal") or \
                        self._find_child_by_type(node, "system_lib_string")
            if path_node:
                inc_path = path_node.text.decode("utf-8", errors="replace").strip('"<> ')
                self._include_graph[file_path].add(inc_path)

        if node_type in ("identifier", "simple_identifier", "field_identifier"):
            name = node.text.decode("utf-8", errors="replace")

            if len(name) <= 1 or name in _COMMON_NOISE_NAMES:
                return

            nid = f"ts:{file_path}:{start_line}:{name}"
            code_line = self._get_line(source, start_line)

            if nid not in nodes_map:
                props: dict[str, Any] = {"scope": current_scope or ""}
                if current_condition:
                    props["ast_condition"] = current_condition

                nodes_map[nid] = GraphNode(
                    id=nid,
                    kind=NodeKind.IDENTIFIER,
                    name=name,
                    location=SourceLocation(
                        file=file_path,
                        line=start_line,
                        column=node.start_point[1],
                        code_snippet=code_line,
                    ),
                    language=language,
                    backend=BackendKind.TREESITTER,
                    properties=props,
                )

            scope_key = f"{file_path}:{current_scope or '?'}:{name}"
            prev_nid = self._scope_last_use.get(scope_key)
            if prev_nid and prev_nid != nid and prev_nid in nodes_map:
                eid = f"{prev_nid}->{nid}"
                if eid not in edges_set:
                    edges_set.add(eid)
                    edges.append(GraphEdge(
                        src=prev_nid,
                        dst=nid,
                        kind=EdgeKind.DATA_FLOW,
                        weight=2.0,
                        backend=BackendKind.TREESITTER,
                    ))
            self._scope_last_use[scope_key] = nid

        if node_type in ("call_expression", "method_invocation", "call_suffix"):
            func_node = self._find_child_by_type(node, "identifier") or \
                        self._find_child_by_type(node, "simple_identifier") or \
                        self._find_child_by_type(node, "field_expression")
            if func_node:
                callee_name = func_node.text.decode("utf-8", errors="replace")
                caller_id = f"ts:{file_path}:{start_line}:call:{callee_name}"
                code_line = self._get_line(source, start_line)

                if caller_id not in nodes_map:
                    props = {"scope": current_scope or ""}
                    if current_condition:
                        props["ast_condition"] = current_condition

                    nodes_map[caller_id] = GraphNode(
                        id=caller_id,
                        kind=NodeKind.CALL_SITE,
                        name=callee_name,
                        location=SourceLocation(
                            file=file_path,
                            line=start_line,
                            code_snippet=code_line,
                        ),
                        language=language,
                        backend=BackendKind.TREESITTER,
                        properties=props,
                    )

                defs = self.resolve_symbol(callee_name)
                if not defs and callee_name in self._builtin_defs:
                    defs = [
                        {"path": df, "line": str(dl)}
                        for df, dl in self._builtin_defs[callee_name]
                        if df != file_path
                    ]
                for d in defs:
                    def_file = d.get("path", "")
                    def_line = int(d.get("line", 0))
                    if def_file and def_line:
                        rel_def_file = os.path.relpath(def_file, self.repo_path) if os.path.isabs(def_file) else def_file
                        rel_def_file = rel_def_file.replace("\\", "/")
                        def_id = f"ts:{rel_def_file}:{def_line}:{callee_name}"
                        if def_id not in nodes_map:
                            nodes_map[def_id] = GraphNode(
                                id=def_id,
                                kind=NodeKind.IDENTIFIER,
                                name=callee_name,
                                location=SourceLocation(file=rel_def_file, line=def_line),
                                language=language,
                                backend=BackendKind.TREESITTER,
                            )
                        eid = f"{caller_id}->{def_id}"
                        if eid not in edges_set:
                            edges_set.add(eid)
                            edges.append(GraphEdge(
                                src=caller_id,
                                dst=def_id,
                                kind=EdgeKind.CALL,
                                weight=1.5,
                                backend=BackendKind.TREESITTER,
                            ))

        if node_type in ("field_expression", "member_expression", "navigation_expression"):
            field_node = self._find_child_by_type(node, "field_identifier") or \
                         self._find_child_by_type(node, "property_identifier") or \
                         self._find_child_by_type(node, "simple_identifier")
            if field_node:
                fname = field_node.text.decode("utf-8", errors="replace")
                fid = f"ts:{file_path}:{start_line}:field:{fname}"
                code_line = self._get_line(source, start_line)

                if fid not in nodes_map:
                    props = {"scope": current_scope or ""}
                    if current_condition:
                        props["ast_condition"] = current_condition

                    nodes_map[fid] = GraphNode(
                        id=fid,
                        kind=NodeKind.FIELD,
                        name=fname,
                        location=SourceLocation(
                            file=file_path, line=start_line,
                            code_snippet=code_line,
                        ),
                        language=language,
                        backend=BackendKind.TREESITTER,
                        properties=props,
                    )

        for child in node.children:
            self._walk_tree(
                child, file_path, source, language,
                nodes_map, edges, edges_set, target_line,
                current_scope,
                current_condition,
            )

    def _parse_ast_condition(self, node: Any) -> dict[str, Any] | None:
        if not node:
            return None

        while node.type == "parenthesized_expression" and len(node.children) >= 3:
            node = node.children[1]

        ntype = node.type
        text = node.text.decode("utf-8", errors="replace").strip()

        if ntype in ("binary_expression", "logical_expression", "comparison_expression"):
            if len(node.children) >= 3:
                lhs = self._parse_ast_condition(node.children[0])
                op = node.children[1].text.decode("utf-8").strip()
                rhs = self._parse_ast_condition(node.children[2])
                if lhs and rhs:
                    return {"type": "binary_expression", "operator": op, "lhs": lhs, "rhs": rhs}

        elif ntype in ("identifier", "simple_identifier", "field_identifier"):
            return {"type": "identifier", "name": text}

        elif "literal" in ntype or ntype in ("number", "null", "true", "false", "integer"):
            return {"type": "literal", "value": text}

        return None

    @staticmethod
    def _find_child_by_type(node: Any, type_name: str) -> Any | None:
        for child in node.children:
            if child.type == type_name:
                return child
        return None

    @staticmethod
    def _get_line(source: str, line_no: int) -> str:
        lines = source.split("\n")
        if 0 < line_no <= len(lines):
            return lines[line_no - 1].strip()[:200]
        return ""

    def extract_edges_for_repo(
        self,
        language: Language,
        target_file: str | None = None,
        max_files: int | None = None,
    ) -> tuple[list[GraphNode], list[GraphEdge]]:
        try:
            self._get_parser(language)
            logger.info("tree-sitter parser for %s loaded successfully", language.value)
        except Exception as exc:
            ts_name = _TS_LANG_MAP.get(language, language.value)
            logger.error(
                "tree-sitter parser for '%s' unavailable: %s. ",
                ts_name, exc,
            )
            raise RuntimeError(
                f"tree-sitter parser for {ts_name} is not available."
            ) from exc

        if max_files is None:
            max_files = self.config.max_files

        if not os.path.isdir(self.repo_path):
            raise RuntimeError(
                f"Repository path does not exist: {self.repo_path}\n"
            )

        exts = {ext for ext, lang in _EXT_TO_LANG.items() if lang == language}
        if language == Language.CPP:
            exts.add(".h")

        skip_dirs = {
            ".git", "node_modules", "build", "target", ".gradle",
            "__pycache__", ".venv", "venv", "vendor",
            "out", "dist", ".cache", ".ccache",
            "test", "tests", "testing", "testdata", "test_data",
            "examples", "samples", "benchmarks", "docs", "doc",
            "fuzz", "fuzzer", "fuzzers", "skia",
        }

        candidates: list[str] = []
        for root, dirs, files in os.walk(self.repo_path):
            rel_root = os.path.relpath(root, self.repo_path)
            dirs[:] = [d for d in dirs if d not in skip_dirs]

            for fname in files:
                if Path(fname).suffix.lower() not in exts:
                    continue
                rel_path = os.path.relpath(os.path.join(root, fname), self.repo_path)
                rel_path = rel_path.replace("\\", "/")
                candidates.append(rel_path)

        target_dir = ""
        if target_file:
            target_dir = "/".join(target_file.replace("\\", "/").split("/")[:-1])

        def _sort_key(path: str) -> tuple[int, str]:
            if target_file and path == target_file.replace("\\", "/"):
                return (0, path)
            path_dir = "/".join(path.split("/")[:-1])
            if target_dir and path_dir == target_dir:
                return (1, path)
            if target_dir and path_dir.startswith(target_dir.rsplit("/", 1)[0]):
                return (2, path)
            if target_dir:
                target_parts = target_dir.split("/")
                path_parts = path_dir.split("/")
                shared = 0
                for a, b in zip(target_parts, path_parts):
                    if a == b:
                        shared += 1
                    else:
                        break
                return (10 - min(shared, 9), path)
            return (5, path)

        candidates.sort(key=_sort_key)

        if not candidates:
            logger.error(
                "No source files found! Check path and extensions."
            )

        if max_files > 0:
            candidates = candidates[:max_files]

        files_scanned = 0
        files_failed = 0
        nodes_map_global: dict[str, GraphNode] = {}
        edges_set_global: set[str] = set()
        all_edges: list[GraphEdge] = []

        MAX_EDGES = 500_000

        for rel_path in candidates:
            if len(all_edges) >= MAX_EDGES:
                break
            try:
                nodes, edges = self.extract_edges_for_file(rel_path, language)
                for n in nodes:
                    if n.id not in nodes_map_global:
                        nodes_map_global[n.id] = n
                for e in edges:
                    eid = f"{e.src}->{e.dst}"
                    if eid not in edges_set_global:
                        edges_set_global.add(eid)
                        all_edges.append(e)
                files_scanned += 1
            except Exception as exc:
                logger.error("Failed parsing %s: %s", rel_path, exc)
                import traceback
                traceback.print_exc()
                files_failed += 1

        all_nodes = list(nodes_map_global.values())

        calls_with_xfile: set[str] = set()
        for e in all_edges:
            if e.kind == EdgeKind.CALL:
                src_node = nodes_map_global.get(e.src)
                dst_node = nodes_map_global.get(e.dst)
                if src_node and dst_node and src_node.location and dst_node.location:
                    if src_node.location.file != dst_node.location.file:
                        calls_with_xfile.add(e.src)

        cross_file_edges = 0
        for nid, node in nodes_map_global.items():
            if node.kind != NodeKind.CALL_SITE:
                continue
            if nid in calls_with_xfile:
                continue
            callee_name = node.name
            if not callee_name or callee_name in _COMMON_NOISE_NAMES or len(callee_name) <= 2:
                continue
            defs = self._builtin_defs.get(callee_name, [])
            src_file = node.location.file if node.location else ""
            for def_file, def_line in defs:
                if def_file == src_file:
                    continue
                def_id = f"ts:{def_file}:{def_line}:{callee_name}"
                eid = f"{nid}->{def_id}"
                if eid in edges_set_global:
                    continue
                if def_id not in nodes_map_global:
                    new_node = GraphNode(
                        id=def_id,
                        kind=NodeKind.IDENTIFIER,
                        name=callee_name,
                        location=SourceLocation(file=def_file, line=def_line),
                        language=language,
                        backend=BackendKind.TREESITTER,
                    )
                    nodes_map_global[def_id] = new_node
                    all_nodes.append(new_node)
                edges_set_global.add(eid)
                new_edge = GraphEdge(
                    src=nid, dst=def_id,
                    kind=EdgeKind.CALL,
                    weight=1.8,
                    backend=BackendKind.TREESITTER,
                )
                all_edges.append(new_edge)
                cross_file_edges += 1
                break

        return all_nodes, all_edges

    def get_enclosing_function_name(self, file_path: str, language: Language, target_line: int) -> str | None:
        """Find the name of the function enclosing the target line."""
        abs_path = os.path.join(self.repo_path, file_path)
        source = _read_file_safe(abs_path, self.config.max_file_size_kb)
        if not source:
            return None

        try:
            parser = self._get_parser(language)
            tree = parser.parse(source.encode("utf-8"))
        except Exception as exc:
            logger.error("Tree-sitter parse failed for scope detection: %s", exc)
            return None

        target_ts_line = target_line - 1

        def _extract_name(n: Any) -> str | None:
            """Recursively extract the identifier text from a declarator node."""
            if n.type in ("identifier", "field_identifier", "scoped_identifier", "name"):
                return n.text.decode("utf-8", errors="replace").split("::")[-1]
            for child in n.children:
                found = _extract_name(child)
                if found:
                    return found
            return None

        def _walk(node: Any) -> str | None:
            best_scope = None
            if node.start_point[0] <= target_ts_line <= node.end_point[0]:
                if "function" in node.type or "method" in node.type:
                    # Find the declarator and extract the actual name
                    decl = self._find_child_by_type(node, "function_declarator") or node
                    name = _extract_name(decl)
                    if name:
                        best_scope = name

                for child in node.children:
                    child_scope = _walk(child)
                    if child_scope:
                        best_scope = child_scope

            return best_scope

        return _walk(tree.root_node)
#src\deeptrace\cli\interactive.py
"""Interactive terminal UI for branch-point selection."""

from __future__ import annotations

import logging
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from deeptrace.models.graph import BranchPoint, TracePath

logger = logging.getLogger(__name__)
console = Console()


def display_path(path: TracePath, index: int) -> None:
    """Display a single trace path with rich formatting."""
    title = f"Path #{index + 1}"
    if path.llm_rank:
        title += f" (LLM rank: {path.llm_rank})"
    title += f" | score: {path.score:.1f} | depth: {path.depth}"

    if path.vulnerability_tags:
        title += f" | vulns: {', '.join(path.vulnerability_tags)}"

    # Z3 satisfiability status
    if path.is_satisfiable is True:
        title += " | [bold green]SAT[/bold green]"
    elif path.is_satisfiable is False:
        title += " | [bold red]UNSAT[/bold red]"

    tree = Tree(f"[bold cyan]{title}[/bold cyan]")

    for i, step in enumerate(path.steps):
        loc = step.location.short if step.location else "?"
        edge = f" [dim]({step.edge_kind.value})[/dim]" if step.edge_kind else ""
        code = step.code_snippet[:100] if step.code_snippet else ""

        label = f"[yellow]{loc}[/yellow]{edge}"
        if code:
            label += f"  [white]{code}[/white]"
        if step.annotation:
            label += f"\n    [italic green]> {step.annotation}[/italic green]"

        tree.add(label)

    if path.llm_rationale:
        tree.add(f"[bold magenta]Rationale:[/bold magenta] {path.llm_rationale}")

    # Z3 model
    if path.is_satisfiable is True and path.z3_model:
        tree.add(f"[bold green]Z3 Model:[/bold green] {path.z3_model}")

    # Constraints
    if path.constraints:
        constraints_str = "; ".join(path.constraints[:5])
        if len(path.constraints) > 5:
            constraints_str += f" ... (+{len(path.constraints) - 5} more)"
        tree.add(f"[dim]Constraints: {constraints_str}[/dim]")

    # Vulnerability summary
    if path.vulnerability_summary:
        console.print(tree)
        console.print(Panel(
            path.vulnerability_summary,
            title="[bold red]Vulnerability Analysis[/bold red]",
            border_style="red",
            padding=(1, 2),
        ))
    else:
        console.print(tree)

    console.print()


def display_paths_summary(paths: list[TracePath]) -> None:
    """Display a summary table of all paths."""
    table = Table(title="Trace Paths Summary", show_lines=True)
    table.add_column("#", style="bold", width=4)
    table.add_column("Depth", width=6)
    table.add_column("Score", width=8)
    table.add_column("LLM Rank", width=9)
    table.add_column("Z3", width=6)
    table.add_column("Vulnerabilities", style="red")
    table.add_column("Start -> End", style="cyan")
    table.add_column("Files", style="dim")

    for i, path in enumerate(paths):
        files = set()
        for step in path.steps:
            if step.location:
                files.add(step.location.file.split("/")[-1])

        start_loc = path.steps[0].location.short if path.steps and path.steps[0].location else "?"
        end_loc = path.steps[-1].location.short if path.steps and path.steps[-1].location else "?"

        # Z3 status
        if path.is_satisfiable is True:
            z3_str = "[green]SAT[/green]"
        elif path.is_satisfiable is False:
            z3_str = "[red]UNSAT[/red]"
        else:
            z3_str = "[dim]-[/dim]"

        table.add_row(
            str(i + 1),
            str(path.depth),
            f"{path.score:.1f}",
            str(path.llm_rank) if path.llm_rank else "-",
            z3_str,
            ", ".join(path.vulnerability_tags) or "-",
            f"{start_loc} -> {end_loc}",
            ", ".join(sorted(files)[:3]),
        )

    console.print(table)


def display_branch_point(bp: BranchPoint, index: int) -> None:
    """Display a branch point with its candidates."""
    loc = bp.location.short if bp.location else "?"
    console.print(Panel(
        f"[bold]Branch #{index + 1}[/bold] at [cyan]{loc}[/cyan] "
        f"({bp.node_id})\n"
        f"[dim]{len(bp.candidates)} candidate paths diverge here[/dim]",
        title="Branch Point",
        border_style="yellow",
    ))

    table = Table(show_lines=True)
    table.add_column("#", width=4)
    table.add_column("Edge", width=14)
    table.add_column("Est. Depth", width=10)
    table.add_column("Code Preview", style="white")
    table.add_column("LLM Summary", style="green")
    table.add_column("Vuln Hint", style="red")

    for cand in bp.candidates:
        table.add_row(
            str(cand.index),
            cand.edge_kind.value,
            str(cand.estimated_depth),
            cand.code_preview[:80] or "-",
            cand.llm_summary[:80] or "-",
            cand.vulnerability_hint[:40] or "-",
        )

    console.print(table)


def prompt_branch_selection(bp: BranchPoint) -> int | None:
    """Prompt user to select a branch candidate. Returns chosen index or None to skip."""
    valid_indices = {c.index for c in bp.candidates}

    while True:
        console.print(
            "\n[bold]Select a candidate to explore[/bold] "
            f"(enter number, 'a' for all, 's' to skip): ",
            end="",
        )
        try:
            from prompt_toolkit import prompt as pt_prompt
            choice = pt_prompt("").strip().lower()
        except (ImportError, EOFError, KeyboardInterrupt):
            choice = input().strip().lower()

        if choice == "s":
            return None
        if choice == "a":
            return -1  # signal to explore all
        try:
            idx = int(choice)
            if idx in valid_indices:
                return idx
            console.print(f"[red]Invalid index. Choose from: {sorted(valid_indices)}[/red]")
        except ValueError:
            console.print("[red]Enter a number, 'a', or 's'[/red]")


def interactive_session(
    paths: list[TracePath],
    branch_points: list[BranchPoint],
) -> list[int]:
    """Run interactive session. Returns list of chosen branch indices."""
    console.print("\n[bold green]===  Interactive Trace Explorer  ===[/bold green]\n")

    # Show paths summary
    if paths:
        display_paths_summary(paths)
        console.print()

        # Let user expand individual paths
        while True:
            console.print(
                "[bold]View path details?[/bold] (enter path # or 'c' to continue): ",
                end="",
            )
            try:
                choice = input().strip().lower()
            except (EOFError, KeyboardInterrupt):
                break
            if choice == "c":
                break
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(paths):
                    display_path(paths[idx], idx)
                else:
                    console.print("[red]Invalid path number[/red]")
            except ValueError:
                break

    # Handle branch points
    chosen: list[int] = []
    if branch_points:
        console.print(f"\n[bold yellow]{len(branch_points)} branch point(s) detected:[/bold yellow]\n")

        for i, bp in enumerate(branch_points):
            display_branch_point(bp, i)
            selection = prompt_branch_selection(bp)
            if selection is not None:
                chosen.append(selection)
                bp.chosen_index = selection
                console.print(f"[green]Selected candidate #{selection}[/green]\n")
            else:
                console.print("[dim]Skipped[/dim]\n")
    else:
        console.print("\n[dim]No branch points to resolve (graph was fully explored).[/dim]")

    return chosen

#src\deeptrace\cli\main.py
"""CLI entry point for deeptrace."""

from __future__ import annotations

import logging
import os
import sys

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from deeptrace.models.config import DeeptraceConfig

console = Console()


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_path=False, show_time=False)],
    )
    # Quiet noisy libraries
    for name in ("docker", "urllib3", "httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(package_name="deeptrace-aco")
def cli() -> None:
    """deeptrace — Deep dependency trace analysis using Joern + ACO."""
    pass


# ---------------------------------------------------------------------------
# trace command
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--repo", required=True, help="Path to the source repository.")
@click.option("--target", required=True, help="Sink file:line (e.g. src/foo.c:123).")
@click.option("--source", default="", help="Source file:line to trace FROM (e.g. src/input.c:42). Finds paths source->sink.")
@click.option("--out", default="traces.json", help="Output JSON file.")
@click.option("--language", default=None, help="Override language detection (c/cpp/java/kotlin/swift/rust/objc).")
@click.option("--max-depth", default=30, type=int, help="Max backward trace depth.")
@click.option("--max-flows", default=400, type=int, help="Max Joern flows to extract.")
@click.option("--topk", default=50, type=int, help="Number of top paths in output.")
@click.option("--ants", default=80, type=int, help="ACO: number of ants.")
@click.option("--iterations", default=60, type=int, help="ACO: number of iterations.")
@click.option("--alpha", default=1.0, type=float, help="ACO: pheromone importance.")
@click.option("--beta", default=2.5, type=float, help="ACO: heuristic importance.")
@click.option("--rho", default=0.15, type=float, help="ACO: evaporation rate.")
@click.option("--interactive/--no-interactive", default=False, help="Enter interactive branch-selection mode.")
@click.option("--session-file", default="", help="Path to save/resume session state.")
@click.option("--llm/--no-llm", "llm_enabled", default=True, help="Enable LLM-based ranking.")
@click.option("--llm-provider", type=click.Choice(["ollama", "anthropic", "openai"]), default="ollama", help="LLM provider.")
@click.option("--llm-model", default="qwen3-coder:30b", help="LLM model name (e.g. qwen3-coder:30b, llama3.1:8b, claude-sonnet-4-20250514).")
@click.option("--llm-base-url", default="", help="LLM API base URL (default: http://localhost:11434 for Ollama).")
@click.option("--llm-api-key", default="", help="API key (not needed for Ollama).")
@click.option("--z3/--no-z3", "z3_enabled", default=True, help="Enable Z3 constraint satisfiability checking.")
@click.option("--enumerate-small-graphs/--no-enumerate-small-graphs", default=True, help="Exact enumeration for small graphs.")
@click.option("--docker-image", default="ghcr.io/joernio/joern:nightly", help="Joern Docker image.")
@click.option("--cpg-timeout", default=7200, type=int, help="Joern CPG generation timeout in seconds.")
@click.option("--cpg-save", default="", help="Save Joern CPG to this path for reuse (e.g. repo.cpg.bin).")
@click.option("--cpg-load", default="", help="Load a pre-built CPG instead of generating (skips joern-parse).")
@click.option("--max-files", default=5000, type=int, help="Max source files for tree-sitter to scan (0=unlimited).")
@click.option("--max-caller-hops", default=3, type=int, help="Cross-file caller expansion depth (0=disabled).")
@click.option("--no-treesitter", is_flag=True, default=False, help="Disable tree-sitter fallback.")
@click.option("-v", "--verbose", is_flag=True, default=False, help="Enable debug logging.")
def trace(
    repo: str,
    target: str,
    source: str,
    out: str,
    language: str | None,
    max_depth: int,
    max_flows: int,
    topk: int,
    ants: int,
    iterations: int,
    alpha: float,
    beta: float,
    rho: float,
    interactive: bool,
    session_file: str,
    llm_enabled: bool,
    llm_provider: str,
    llm_model: str,
    llm_base_url: str,
    llm_api_key: str,
    z3_enabled: bool,
    enumerate_small_graphs: bool,
    docker_image: str,
    cpg_timeout: int,
    cpg_save: str,
    cpg_load: str,
    max_files: int,
    max_caller_hops: int,
    no_treesitter: bool,
    verbose: bool,
) -> None:
    """Trace deep dependencies backward from a target (sink) file:line."""
    _setup_logging(verbose)

    # Build config
    config = DeeptraceConfig(
        repo=repo,
        target=target,
        source=source,
        out=out,
        language=language,
        max_depth=max_depth,
        max_flows=max_flows,
        topk=topk,
        interactive=interactive,
        session_file=session_file,
        enumerate_small_graphs=enumerate_small_graphs,
    )
    config.aco.ants = ants
    config.aco.iterations = iterations
    config.aco.alpha = alpha
    config.aco.beta = beta
    config.aco.rho = rho
    config.joern.docker_image = docker_image
    config.joern.cpg_timeout = cpg_timeout
    if cpg_save:
        config.joern.cpg_save_path = cpg_save
    if cpg_load:
        config.joern.cpg_load_path = cpg_load
    config.treesitter.enabled = not no_treesitter
    config.treesitter.max_files = max_files
    config.max_caller_hops = max_caller_hops
    config.llm.enabled = llm_enabled
    if llm_provider:
        from deeptrace.models.config import LLMProvider
        config.llm.provider = LLMProvider(llm_provider)
    config.llm.model = llm_model
    if llm_base_url:
        config.llm.base_url = llm_base_url
    if llm_api_key:
        config.llm.api_key = llm_api_key
    config.z3.enabled = z3_enabled

    # Run
    from deeptrace.core.orchestrator import TraceOrchestrator

    console.print(f"\n[bold]deeptrace[/bold] v1.0.0 — tracing [cyan]{target}[/cyan] in [cyan]{repo}[/cyan]")
    if source:
        console.print(f"  Source (from): [green]{source}[/green]")
    console.print()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Initializing...", total=100)

        def on_progress(stage: str, pct: float) -> None:
            labels = {
                "detecting_language": "Detecting language...",
                "extracting_graph": "Extracting dependency graph (Joern + tree-sitter)...",
                "expanding_frontiers": "Expanding cross-file caller frontiers...",
                "finding_target": "Locating target nodes...",
                "exploring_paths": "Running ACO path exploration...",
                "z3_checking": "Checking path satisfiability (Z3)...",
                "collapsing_statements": "Collapsing to statement-level flows...",
                "llm_ranking": "Ranking paths with LLM...",
                "building_output": "Building output...",
                "done": "Complete!",
            }
            progress.update(task, description=labels.get(stage, stage), completed=pct * 100)

        try:
            orchestrator = TraceOrchestrator(config)
            output = orchestrator.run(progress_callback=on_progress)
        except Exception as exc:
            progress.stop()
            console.print(f"\n[bold red]Error:[/bold red] {exc}")
            if verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)

    # Display results
    console.print(f"\n[bold green]Trace complete![/bold green]")
    console.print(f"  Nodes: {output.node_count}")
    console.print(f"  Edges: {output.edge_count}")
    console.print(f"  Paths found: {len(output.paths)}")
    if source:
        console.print(f"  Mode: [cyan]source-sink[/cyan] ({source} -> {target})")

    # Z3 summary
    if z3_enabled and output.paths:
        sat = sum(1 for p in output.paths if p.is_satisfiable is True)
        unsat = sum(1 for p in output.paths if p.is_satisfiable is False)
        unknown = sum(1 for p in output.paths if p.is_satisfiable is None)
        console.print(f"  Z3: [green]{sat} SAT[/green], [red]{unsat} UNSAT[/red], [yellow]{unknown} unknown[/yellow]")

    console.print(f"  Output: {out}")

    if output.metadata.get("branch_points_detected", 0) > 0:
        bp_count = output.metadata["branch_points_detected"]
        console.print(f"  Branch points: [yellow]{bp_count}[/yellow]")

    # Interactive mode
    if interactive and output.paths:
        from deeptrace.cli.interactive import interactive_session

        branch_points = []
        if hasattr(orchestrator, '_aco_explorer') and orchestrator._aco_explorer:
            branch_points = orchestrator._aco_explorer.branch_points
        interactive_session(output.paths, branch_points)

    # Show top paths
    if output.paths and not interactive:
        from deeptrace.cli.interactive import display_paths_summary
        console.print()
        display_paths_summary(output.paths[:10])

    console.print()


# ---------------------------------------------------------------------------
# session command
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("session_file")
@click.option("--show-branches", is_flag=True, help="Show pending branch points.")
@click.option("--show-paths", is_flag=True, help="Show completed paths.")
@click.option("--resolve", type=str, default=None, help="Resolve a branch: node_id:candidate_index")
def session(
    session_file: str,
    show_branches: bool,
    show_paths: bool,
    resolve: str | None,
) -> None:
    """Inspect or resume a trace session."""
    _setup_logging(False)

    from deeptrace.core.session import SessionManager

    mgr = SessionManager(session_file)
    sess = mgr.load()
    if not sess:
        console.print(f"[red]Could not load session from {session_file}[/red]")
        sys.exit(1)

    console.print(f"[bold]Session:[/bold] {sess.session_id}")
    console.print(f"  Target: {sess.target}")
    console.print(f"  Repo: {sess.repo_path}")
    stats = mgr.summary()
    for k, v in stats.items():
        console.print(f"  {k}: {v}")

    if show_branches:
        from deeptrace.cli.interactive import display_branch_point
        console.print(f"\n[bold yellow]Pending branches ({len(sess.pending_branches)}):[/bold yellow]")
        for i, bp in enumerate(sess.pending_branches):
            display_branch_point(bp, i)

    if show_paths:
        from deeptrace.cli.interactive import display_paths_summary
        console.print(f"\n[bold]Completed paths ({len(sess.completed_paths)}):[/bold]")
        display_paths_summary(sess.completed_paths[:20])

    if resolve:
        parts = resolve.rsplit(":", 1)
        if len(parts) != 2:
            console.print("[red]Format: node_id:candidate_index[/red]")
            sys.exit(1)
        node_id, idx_str = parts
        bp = mgr.resolve_branch(node_id, int(idx_str))
        if bp:
            console.print(f"[green]Resolved branch at {node_id} → candidate #{idx_str}[/green]")
        else:
            console.print(f"[red]Branch not found: {node_id}[/red]")


# ---------------------------------------------------------------------------
# graph command (export for visualization)
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("traces_json")
@click.option("--format", "fmt", type=click.Choice(["dot", "cytoscape", "d3"]), default="dot", help="Export format.")
@click.option("--out", default=None, help="Output file (default: stdout).")
def export_graph(traces_json: str, fmt: str, out: str | None) -> None:
    """Export the dependency graph for visualization."""
    _setup_logging(False)

    import json
    from pathlib import Path

    data = json.loads(Path(traces_json).read_text())
    nodes = data.get("nodes", [])
    edges = data.get("edges", [])

    if fmt == "dot":
        lines = ["digraph deeptrace {", '  rankdir=BT;', '  node [shape=box, fontsize=10];']
        for n in nodes:
            label = n.get("name", n["id"])[:40]
            loc = ""
            if n.get("location"):
                loc = f"\\n{n['location'].get('file', '')}:{n['location'].get('line', '')}"
            lines.append(f'  "{n["id"]}" [label="{label}{loc}"];')
        for e in edges:
            label = e.get("kind", "")
            lines.append(f'  "{e["src"]}" -> "{e["dst"]}" [label="{label}"];')
        lines.append("}")
        result = "\n".join(lines)

    elif fmt == "cytoscape":
        elements = []
        for n in nodes:
            elements.append({"data": {"id": n["id"], "label": n.get("name", "")}})
        for e in edges:
            elements.append({"data": {"source": e["src"], "target": e["dst"], "kind": e.get("kind", "")}})
        result = json.dumps(elements, indent=2)

    elif fmt == "d3":
        d3_nodes = [{"id": n["id"], "name": n.get("name", "")} for n in nodes]
        d3_links = [{"source": e["src"], "target": e["dst"], "kind": e.get("kind", "")} for e in edges]
        result = json.dumps({"nodes": d3_nodes, "links": d3_links}, indent=2)
    else:
        result = ""

    if out:
        Path(out).write_text(result)
        console.print(f"[green]Exported to {out}[/green]")
    else:
        print(result)


# ---------------------------------------------------------------------------
# visualize command (HTML timeline)
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("traces_json")
@click.option("--repo", default=".", help="Path to source repo (for reading source files).")
@click.option("--out", default=None, help="Output HTML file (default: traces_timeline.html).")
@click.option("--max-paths", default=50, type=int, help="Max paths to include.")
def visualize(traces_json: str, repo: str, out: str | None, max_paths: int) -> None:
    """Generate an interactive HTML timeline visualization of trace paths."""
    _setup_logging(False)

    import json
    from pathlib import Path

    from deeptrace.models.graph import TraceOutput
    from deeptrace.cli.visualize import generate_html

    console.print(f"[bold]Loading traces from {traces_json}...[/bold]")

    data = json.loads(Path(traces_json).read_text())
    output = TraceOutput.model_validate(data)

    if not output.paths:
        console.print("[yellow]No paths found in the trace output.[/yellow]")
        sys.exit(0)

    if not out:
        out = str(Path(traces_json).with_suffix('.html'))

    html_path = generate_html(output, repo_path=repo, out_path=out, max_paths=max_paths)

    console.print(f"\n[bold green]HTML visualization generated![/bold green]")
    console.print(f"  Paths: {min(len(output.paths), max_paths)}")
    console.print(f"  Output: [cyan]{html_path}[/cyan]")
    console.print(f"\n  Open in browser: [bold]file://{os.path.abspath(html_path)}[/bold]\n")


# ---------------------------------------------------------------------------
# batch command
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--repo", required=True, help="Path to the source repository.")
@click.option("--lines", "lines_file", required=True, help="Path to lines.json with targets.")
@click.option("--out", default="batch_results", help="Output directory for results.")
@click.option("--language", default=None, help="Override language detection.")
@click.option("--max-depth", default=60, type=int, help="Max backward trace depth.")
@click.option("--topk", default=40, type=int, help="Number of top paths per target.")
@click.option("--llm/--no-llm", "llm_enabled", default=True, help="Enable LLM-based ranking.")
@click.option("--llm-provider", type=click.Choice(["ollama", "anthropic", "openai"]), default="ollama", help="LLM provider.")
@click.option("--llm-model", default="qwen3-coder:30b", help="LLM model name.")
@click.option("--llm-base-url", default="", help="LLM API base URL.")
@click.option("--llm-api-key", default="", help="API key (not needed for Ollama).")
@click.option("--z3/--no-z3", "z3_enabled", default=True, help="Enable Z3 constraint checking.")
@click.option("--cpg-save", default="", help="Save Joern CPG to this path for reuse.")
@click.option("--cpg-load", default="", help="Load a pre-built CPG instead of generating.")
@click.option("--max-files", default=5000, type=int, help="Max source files for tree-sitter.")
@click.option("--max-caller-hops", default=3, type=int, help="Cross-file caller expansion depth (0=disabled).")
@click.option("--no-treesitter", is_flag=True, default=False, help="Disable tree-sitter fallback.")
@click.option("-v", "--verbose", is_flag=True, default=False, help="Enable debug logging.")
def batch(
    repo: str,
    lines_file: str,
    out: str,
    language: str | None,
    max_depth: int,
    topk: int,
    llm_enabled: bool,
    llm_provider: str,
    llm_model: str,
    llm_base_url: str,
    llm_api_key: str,
    z3_enabled: bool,
    cpg_save: str,
    cpg_load: str,
    max_files: int,
    max_caller_hops: int,
    no_treesitter: bool,
    verbose: bool,
) -> None:
    """Batch trace: process multiple targets from a lines.json file."""
    _setup_logging(verbose)

    from deeptrace.core.batch import BatchRunner, load_targets

    # Load targets
    try:
        targets = load_targets(lines_file)
    except Exception as exc:
        console.print(f"[bold red]Error loading {lines_file}:[/bold red] {exc}")
        sys.exit(1)

    if not targets:
        console.print("[yellow]No valid targets found in lines.json[/yellow]")
        sys.exit(0)

    console.print(f"\n[bold]deeptrace batch[/bold] — {len(targets)} targets from [cyan]{lines_file}[/cyan]\n")

    # Build base config
    config = DeeptraceConfig(
        repo=repo,
        target=f"{targets[0].file}:{targets[0].line}",  # initial target for language detection
        out=out,
        language=language,
        max_depth=max_depth,
        topk=topk,
    )
    config.treesitter.enabled = not no_treesitter
    config.treesitter.max_files = max_files
    config.max_caller_hops = max_caller_hops
    config.llm.enabled = llm_enabled
    if llm_provider:
        from deeptrace.models.config import LLMProvider
        config.llm.provider = LLMProvider(llm_provider)
    config.llm.model = llm_model
    if llm_base_url:
        config.llm.base_url = llm_base_url
    if llm_api_key:
        config.llm.api_key = llm_api_key
    config.z3.enabled = z3_enabled
    if cpg_save:
        config.joern.cpg_save_path = cpg_save
    if cpg_load:
        config.joern.cpg_load_path = cpg_load

    # Run batch
    runner = BatchRunner(config)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Processing targets...", total=len(targets))

        def on_batch_progress(idx: int, total: int, target_str: str) -> None:
            progress.update(
                task,
                description=f"[{idx+1}/{total}] {target_str}",
                completed=idx,
            )

        try:
            batch_output = runner.run(targets, progress_callback=on_batch_progress)
            progress.update(task, completed=len(targets))
        except Exception as exc:
            progress.stop()
            console.print(f"\n[bold red]Error:[/bold red] {exc}")
            if verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)

    # Write aggregated output
    import os
    os.makedirs(out, exist_ok=True)
    agg_path = os.path.join(out, "batch_results.json")
    runner.write_batch_output(batch_output, agg_path)

    # Summary
    console.print(f"\n[bold green]Batch complete![/bold green]")
    console.print(f"  Targets: {batch_output.total_targets}")
    console.print(f"  Successful: [green]{batch_output.successful}[/green]")
    if batch_output.failed:
        console.print(f"  Failed: [red]{batch_output.failed}[/red]")
    console.print(f"  Output: {out}/")

    # Show per-target summaries
    total_paths = 0
    total_sat = 0
    for result in batch_output.results:
        n_paths = len(result.paths)
        n_sat = sum(1 for p in result.paths if p.is_satisfiable is True)
        total_paths += n_paths
        total_sat += n_sat
        sat_str = f" [green]({n_sat} SAT)[/green]" if z3_enabled and n_sat else ""
        console.print(f"    {result.target}: {n_paths} paths{sat_str}")

    console.print(f"\n  Total paths: {total_paths}")
    if z3_enabled:
        console.print(f"  Total satisfiable: [green]{total_sat}[/green]")

    for err in batch_output.errors:
        console.print(f"    [red]FAILED[/red] {err['target']}: {err['error']}")

    console.print()


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--repo", required=True, help="Path to the source repository.")
@click.option("--out", default="lines.json", help="Output lines.json file.")
@click.option("--languages", default=None, help="Comma-separated language filter (c,cpp,java,python,etc). Default: all.")
@click.option("--severity", type=click.Choice(["critical", "high", "medium", "low", "info"]), default="low", help="Minimum severity threshold.")
@click.option("--context-lines", default=10, type=int, help="Lines of code context around each hit.")
@click.option("--max-hits", default=500, type=int, help="Maximum total pattern hits to process.")
@click.option("--max-source-hops", default=3, type=int, help="Caller chain depth for source discovery (0=skip source discovery).")
@click.option("--include-sources", is_flag=True, default=False, help="Include source (input) locations in output.")
@click.option("--llm/--no-llm", "llm_enabled", default=True, help="Enable LLM triage of pattern hits.")
@click.option("--llm-provider", type=click.Choice(["ollama", "anthropic", "openai"]), default="ollama", help="LLM provider.")
@click.option("--llm-model", default="qwen3-coder:30b", help="LLM model name.")
@click.option("--llm-base-url", default="", help="LLM API base URL.")
@click.option("--llm-api-key", default="", help="API key (not needed for Ollama).")
@click.option("-v", "--verbose", is_flag=True, default=False, help="Enable debug logging.")
def scan(
    repo: str,
    out: str,
    languages: str | None,
    severity: str,
    context_lines: int,
    max_hits: int,
    max_source_hops: int,
    include_sources: bool,
    llm_enabled: bool,
    llm_provider: str,
    llm_model: str,
    llm_base_url: str,
    llm_api_key: str,
    verbose: bool,
) -> None:
    """Scan a repository for potential vulnerability sinks and sources."""
    _setup_logging(verbose)

    from deeptrace.scanner.scanner import VulnScanner

    # Parse language filter
    lang_list = None
    if languages:
        lang_list = [l.strip() for l in languages.split(",")]

    # Set up LLM caller
    llm_caller = None
    if llm_enabled:
        from deeptrace.models.config import LLMConfig, LLMProvider
        from deeptrace.analysis.llm_ranker import _call_llm

        llm_config = LLMConfig(
            enabled=True,
            provider=LLMProvider(llm_provider),
            model=llm_model,
            max_tokens=4096,
            temperature=0.2,
        )
        if llm_base_url:
            llm_config.base_url = llm_base_url
        if llm_api_key:
            llm_config.api_key = llm_api_key

        llm_caller = lambda system, user_msg: _call_llm(llm_config, system, user_msg)

    console.print(f"\n[bold]deeptrace scan[/bold] — scanning [cyan]{repo}[/cyan]")
    console.print(f"  Languages: {languages or 'all'}")
    console.print(f"  Severity threshold: {severity}")
    console.print(f"  Source discovery: {f'{max_source_hops} hops' if max_source_hops > 0 else 'disabled'}")
    console.print(f"  LLM triage: {'enabled' if llm_enabled else 'disabled'}")
    if llm_enabled:
        console.print(f"  LLM: {llm_provider}/{llm_model}")
    console.print()

    scanner = VulnScanner(
        repo_path=repo,
        llm_caller=llm_caller,
        languages=lang_list,
        severity_threshold=severity,
        context_lines=context_lines,
        max_total_hits=max_hits,
        max_source_hops=max_source_hops,
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=100)

        def on_progress(stage: str, pct: float) -> None:
            labels = {
                "scanning": "Phase A1: Scanning for vulnerability patterns...",
                "context": "Phase A2: Extracting code context...",
                "llm_triage": "Phase A3: LLM triaging candidates...",
                "source_discovery": "Phase B1: Discovering sources from repo...",
                "attack_vectors": "Phase B3: LLM analyzing attack vectors...",
                "pairing": "Phase C: Connecting sinks with sources...",
                "results": "Building results...",
                "done": "Complete!",
            }
            progress.update(task, description=labels.get(stage, stage), completed=pct * 100)

        try:
            summary = scanner.scan(progress_callback=on_progress)
        except Exception as exc:
            progress.stop()
            console.print(f"\n[bold red]Error:[/bold red] {exc}")
            if verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)

    # Write output
    scanner.write_output(summary, out, include_sources=include_sources)

    # Display results
    console.print(f"\n[bold green]Scan complete![/bold green]")
    console.print(f"  Files scanned: {summary.files_scanned}")
    console.print(f"  Pattern hits: {summary.pattern_hits}")
    if summary.llm_evaluated:
        console.print(f"  LLM evaluated: {summary.llm_evaluated}")
        console.print(f"  False positives removed: [green]{summary.false_positives_removed}[/green]")
    console.print(f"  [bold]Confirmed vulnerabilities: {summary.confirmed_vulns}[/bold]")
    if summary.attack_vectors_analyzed:
        console.print(f"  Attack vectors analyzed: {summary.attack_vectors_analyzed}")
    console.print(f"  Sources identified: {summary.sources_found}")
    if summary.pairs_identified:
        console.print(f"  Source-sink pairs: {summary.pairs_identified}")
    console.print(f"  Output: [cyan]{out}[/cyan]")
    console.print(f"  Report: [cyan]{out}.report.md[/cyan]")

    # Show top findings
    sinks = [r for r in summary.results if r.hit_type != "source"]
    if sinks:
        console.print(f"\n  [bold]Top findings:[/bold]")
        sev_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}
        for r in sinks[:10]:
            icon = sev_icons.get(r.severity, "⚪")
            console.print(
                f"    {icon} [{r.severity}] {r.category}: "
                f"[cyan]{r.file}:{r.line}[/cyan] — {r.description}"
            )

    console.print()


# ---------------------------------------------------------------------------
# agent command (interactive exploit agent)
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("traces_json")
@click.option("--repo", required=True, help="Path to the source repository.")
@click.option("--out", default="agent_results", help="Output directory for results and logs.")
@click.option("--path-index", default=0, type=int, help="Which trace path to exploit (default: 0 = top ranked).")
@click.option("--max-turns", default=40, type=int, help="Maximum LLM turns before stopping.")
@click.option("--docker-image", default="", help="Pre-built Docker image (skips image build). Must have /src/ with the repo and tools installed.")
@click.option("--llm-provider", type=click.Choice(["ollama", "anthropic", "openai"]), default="ollama", help="LLM provider (used for exploration, or both if no coder specified).")
@click.option("--llm-model", default="qwen3.5:35b", help="LLM model name.")
@click.option("--llm-base-url", default="", help="LLM API base URL.")
@click.option("--llm-api-key", default="", help="API key (not needed for Ollama).")
@click.option("--coder-provider", type=click.Choice(["ollama", "anthropic", "openai"]), default="ollama", help="Coder LLM provider (optional — defaults to same as --llm-provider).")
@click.option("--coder-model", default="gpt-oss:20b", help="Coder LLM model (optional — defaults to same as --llm-model).")
@click.option("--coder-base-url", default="", help="Coder LLM API base URL (optional).")
@click.option("--coder-api-key", default="", help="Coder API key (optional).")
@click.option("-v", "--verbose", is_flag=True, default=False, help="Enable debug logging.")
def agent(
    traces_json: str,
    repo: str,
    out: str,
    path_index: int,
    max_turns: int,
    docker_image: str,
    llm_provider: str,
    llm_model: str,
    llm_base_url: str,
    llm_api_key: str,
    coder_provider: str,
    coder_model: str,
    coder_base_url: str,
    coder_api_key: str,
    verbose: bool,
) -> None:
    """Interactive exploit agent — LLM in a loop with shell + gdb inside Docker.

    Supports two modes:

    \b
    SINGLE MODEL (default):
      deeptrace agent traces.json --repo ./pdfium --llm-model qwen3-coder:30b

    \b
    DUAL MODEL (explorer + coder):
      deeptrace agent traces.json --repo ./pdfium \\
        --llm-provider ollama --llm-model qwen3-coder:30b \\
        --coder-provider anthropic --coder-model claude-sonnet-4-20250514

    In dual mode, the cheaper explorer model gathers repo information, then
    the stronger coder model writes and iterates on the exploit harness.
    If --coder-model is the same as --llm-model, single-model mode is used.

    Requires Docker to be running.
    """
    _setup_logging(verbose)

    import json as json_mod
    from pathlib import Path

    from deeptrace.models.graph import TraceOutput
    from deeptrace.models.config import LLMConfig, LLMProvider
    from deeptrace.analysis.llm_ranker import _call_llm
    from deeptrace.exploit.repo_analyzer import analyze_repo
    from deeptrace.exploit.docker_env import DockerEnv
    from deeptrace.exploit.agent import ExploitAgent, AgentConfig

    # Load traces
    data = json_mod.loads(Path(traces_json).read_text(encoding="utf-8"))
    trace_output = TraceOutput.model_validate(data)

    if not trace_output.paths:
        console.print("[yellow]No paths found in traces.json[/yellow]")
        sys.exit(0)

    if path_index >= len(trace_output.paths):
        console.print(f"[red]Path index {path_index} out of range (0-{len(trace_output.paths)-1})[/red]")
        sys.exit(1)

    trace_path = trace_output.paths[path_index]

    # Extract sink info from the trace
    last_step = trace_path.steps[-1] if trace_path.steps else None
    if not last_step:
        console.print("[red]Trace path has no steps[/red]")
        sys.exit(1)

    sink_function = (last_step.node_name or "").split("|")[0].strip()
    sink_file = last_step.location.file if last_step.location else ""

    # Analyze repo
    console.print(f"\n[bold]deeptrace agent[/bold] — interactive exploit agent")
    console.print(f"  Repo: [cyan]{repo}[/cyan]")

    profile = analyze_repo(repo)

    console.print(f"  Detected: {profile.language} / {profile.build_system} / lib={profile.library_name}")
    console.print(f"  Headers: {len(profile.key_headers)} | Fuzz harnesses: {len(profile.existing_fuzz_harnesses)}")
    console.print(f"  Trace path: {path_index} (rank {trace_path.llm_rank})")
    console.print(f"  Sink: [cyan]{sink_file}[/cyan] → {sink_function}")
    console.print(f"  Tags: {', '.join(trace_path.vulnerability_tags or [])}")
    console.print(f"  LLM: {llm_provider}/{llm_model}")

    # Determine if dual-model mode
    use_dual = bool(coder_model and (coder_model != llm_model or coder_provider != llm_provider))

    if use_dual:
        console.print(f"  Coder: {coder_provider or llm_provider}/{coder_model}")
    console.print(f"  Max turns: {max_turns}")
    console.print()

    # Set up explorer LLM
    llm_config = LLMConfig(
        enabled=True,
        provider=LLMProvider(llm_provider),
        model=llm_model,
        max_tokens=16384,
        temperature=0.3,
    )
    if llm_base_url:
        llm_config.base_url = llm_base_url
    if llm_api_key:
        llm_config.api_key = llm_api_key

    llm_caller = lambda system, user_msg: _call_llm(llm_config, system, user_msg)

    # Set up coder LLM (if different)
    coder_caller = None
    if use_dual:
        coder_config = LLMConfig(
            enabled=True,
            provider=LLMProvider(coder_provider or llm_provider),
            model=coder_model,
            max_tokens=16384,
            temperature=0.2,  # slightly lower temp for code
        )
        if coder_base_url:
            coder_config.base_url = coder_base_url
        elif llm_base_url:
            coder_config.base_url = llm_base_url
        if coder_api_key:
            coder_config.api_key = coder_api_key
        elif llm_api_key:
            coder_config.api_key = llm_api_key

        coder_caller = lambda system, user_msg: _call_llm(coder_config, system, user_msg)

    # Build Docker environment
    env = DockerEnv(profile)

    try:
        if docker_image:
            console.print(f"[bold]Phase 1:[/bold] Using pre-built Docker image: {docker_image}")
            env.use_prebuilt_image(docker_image)
        else:
            console.print("[bold]Phase 1:[/bold] Building Docker image (tools + source, no build)...")
            console.print("  [dim]The agent will figure out how to build the library interactively.[/dim]")
            env.build_image()

        console.print("[bold]Phase 2:[/bold] Starting container...")
        env.start_container()

        console.print(f"[bold]Phase 3:[/bold] Running exploit agent (max {max_turns} turns)...")
        console.print()

        agent_config = AgentConfig(max_turns=max_turns)

        exploit_agent = ExploitAgent(
            llm_caller=llm_caller,
            env=env,
            profile=profile,
            trace_path=trace_path,
            sink_function=sink_function,
            sink_file=sink_file,
            config=agent_config,
            progress_callback=lambda msg, turn: console.print(f"  [{turn+1}/{max_turns}] {msg}"),
            llm_coder=coder_caller,
        )

        result = exploit_agent.run()

        # Save results
        os.makedirs(out, exist_ok=True)

        # Save conversation log
        log_path = os.path.join(out, "agent_log.json")
        Path(log_path).write_text(
            json_mod.dumps(result.log, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        # Save verification result
        if result.verification:
            vr_path = os.path.join(out, "verification.json")
            Path(vr_path).write_text(json_mod.dumps({
                "confirmed": result.verification.confirmed,
                "sink_reached": result.verification.sink_reached,
                "asan_crash": result.verification.asan_crash,
                "asan_crash_type": result.verification.asan_crash_type,
                "asan_location": result.verification.asan_location,
                "asan_in_library": result.verification.asan_in_library,
                "summary": result.verification.summary,
            }, indent=2), encoding="utf-8")

        # Copy harness out of container if successful
        if result.harness_path:
            try:
                harness_content = env.read_file(result.harness_path, max_lines=5000)
                Path(os.path.join(out, "harness.cpp")).write_text(
                    harness_content, encoding="utf-8",
                )
            except Exception:
                pass

        # Display results
        console.print()
        console.print("=" * 60)
        if result.success and result.verification:
            console.print(f"[bold red]{result.verification.status_icon}[/bold red]")
            console.print(f"[bold]{result.verification.summary}[/bold]")
            console.print(f"  Turns used: {result.turns_used}")
            console.print(f"  Time: {result.elapsed_seconds:.0f}s")
            if result.verification.asan_trace:
                console.print(f"\n  ASAN stack trace:")
                for line in result.verification.asan_trace.split("\n")[:10]:
                    console.print(f"    {line}")
        elif result.verification and result.verification.sink_reached:
            console.print(f"[yellow]{result.verification.status_icon}[/yellow]")
            console.print("Sink reached but no crash — try with different LLM or more turns")
        else:
            console.print("[dim]⚪ Agent finished without triggering the vulnerability[/dim]")
            console.print(f"  Turns used: {result.turns_used}/{max_turns}")
            console.print(f"  Reason: {result.final_reason or 'budget exhausted'}")

        console.print(f"\n  Log: [cyan]{log_path}[/cyan]")
        if result.success:
            console.print(f"  Harness: [cyan]{os.path.join(out, 'harness.cpp')}[/cyan]")
        console.print()

    except Exception as exc:
        console.print(f"\n[bold red]Error:[/bold red] {exc}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    finally:
        console.print("Cleaning up Docker container...")
        env.cleanup()


# ---------------------------------------------------------------------------
# validate command
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("traces_json")
@click.option("--out", default="validation_reports", help="Output directory for reports.")
@click.option("--llm-provider", type=click.Choice(["ollama", "anthropic", "openai"]), default="ollama", help="LLM provider.")
@click.option("--llm-model", default="qwen3-coder:30b", help="LLM model name.")
@click.option("--llm-base-url", default="", help="LLM API base URL.")
@click.option("--llm-api-key", default="", help="API key (not needed for Ollama).")
@click.option("--max-compile-retries", default=3, type=int, help="Max LLM repair attempts per harness.")
@click.option("--max-input-rounds", default=3, type=int, help="Max rounds of input generation.")
@click.option("--docker-image", default="gcc:13", help="Docker image for sandbox.")
@click.option("--no-docker", is_flag=True, default=False, help="Use local gcc instead of Docker.")
@click.option("-v", "--verbose", is_flag=True, default=False, help="Enable debug logging.")
def validate(
    traces_json: str,
    out: str,
    llm_provider: str,
    llm_model: str,
    llm_base_url: str,
    llm_api_key: str,
    max_compile_retries: int,
    max_input_rounds: int,
    docker_image: str,
    no_docker: bool,
    verbose: bool,
) -> None:
    """Validate trace paths: generate C harnesses, compile, run, and report."""
    _setup_logging(verbose)

    from deeptrace.exploit.validator import run_validation_pipeline
    from deeptrace.models.config import LLMConfig, LLMProvider
    from deeptrace.analysis.llm_ranker import _call_llm

    # Build LLM config
    llm_config = LLMConfig(
        enabled=True,
        provider=LLMProvider(llm_provider),
        model=llm_model,
        max_tokens=8192,   # harness code can be long
        temperature=0.3,
    )
    if llm_base_url:
        llm_config.base_url = llm_base_url
    if llm_api_key:
        llm_config.api_key = llm_api_key

    # Create LLM caller
    def llm_caller(system: str, user_msg: str) -> str:
        return _call_llm(llm_config, system, user_msg)

    console.print(f"\n[bold]deeptrace validate[/bold] — validating traces from [cyan]{traces_json}[/cyan]")
    console.print(f"  LLM: {llm_provider}/{llm_model}")
    console.print(f"  Sandbox: {'Docker (' + docker_image + ')' if not no_docker else 'local gcc'}")
    console.print(f"  Output: {out}/\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating...", total=100)

        def on_progress(current: int, total: int, msg: str) -> None:
            pct = (current / max(total, 1)) * 100
            progress.update(task, description=msg, completed=pct)

        try:
            report_files = run_validation_pipeline(
                traces_json_path=traces_json,
                output_dir=out,
                llm_caller=llm_caller,
                max_compile_retries=max_compile_retries,
                max_input_rounds=max_input_rounds,
                use_docker=not no_docker,
                docker_image=docker_image,
                progress_callback=on_progress,
            )
            progress.update(task, description="Complete!", completed=100)
        except Exception as exc:
            progress.stop()
            console.print(f"\n[bold red]Error:[/bold red] {exc}")
            if verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)

    # Summary
    console.print(f"\n[bold green]Validation complete![/bold green]")
    console.print(f"  Reports: {len(report_files)} files in [cyan]{out}/[/cyan]")
    for rf in report_files:
        name = os.path.basename(rf)
        console.print(f"    {name}")
    console.print()

# ======================================================================
# REASON command — deep vulnerability analysis of traces
# ======================================================================

@cli.command()
@click.argument("traces_json")
@click.option("--repo", required=True, help="Path to the source repository (needed to read source code).")
@click.option("--out", default="", help="Output file for the report (default: <traces>_reasoning.md).")
@click.option("--top-n", default=10, type=int, help="Analyze the top N paths by score (default: 10).")
@click.option("--llm-provider", type=click.Choice(["ollama", "anthropic", "openai"]), default="ollama", help="LLM provider.")
@click.option("--llm-model", default="qwen3-coder:30b", help="LLM model name.")
@click.option("--llm-base-url", default="", help="LLM API base URL (for LiteLLM proxy, vLLM, etc.).")
@click.option("--llm-api-key", default="", help="API key.")
@click.option("--json-out", default="", help="Also write structured JSON output to this file.")
@click.option("-v", "--verbose", is_flag=True, default=False, help="Enable debug logging.")
def reason(
    traces_json: str,
    repo: str,
    out: str,
    top_n: int,
    llm_provider: str,
    llm_model: str,
    llm_base_url: str,
    llm_api_key: str,
    json_out: str,
    verbose: bool,
) -> None:
    """Deep vulnerability reasoning — analyze traces like a security researcher.

    \b
    Takes the trace output (traces.json) and has the LLM reason step-by-step
    through each path, reading actual source code, checking for guards and
    mitigations, and determining if the vulnerability is real.

    \b
    Each path gets a verdict:
      🔴 VULNERABLE    — real bug with clear root cause
      🟡 LIKELY        — probably a bug, needs confirmation
      ⚪ UNLIKELY      — probably safe, but edge cases possible
      ⚫ FALSE_POSITIVE — not a real bug (guard exists, safe pattern, etc.)

    \b
    Output: Markdown report with reasoning + optional JSON.

    \b
    Examples:
      deeptrace reason traces.json --repo ./pdfium
      deeptrace reason traces.json --repo ./pdfium --top-n 5 --llm-provider anthropic --llm-model claude-sonnet-4-20250514
      deeptrace reason traces.json --repo ./libxml2 --llm-base-url http://my-proxy:4000 --json-out results.json
    """
    _setup_logging(verbose)

    import json as json_mod
    from pathlib import Path

    from deeptrace.models.graph import TraceOutput
    from deeptrace.models.config import LLMConfig, LLMProvider
    from deeptrace.analysis.llm_ranker import _call_llm
    from deeptrace.analysis.vulnerability_reasoner import (
        VulnerabilityReasoner,
        format_assessment_report,
        assessments_to_json,
    )

    # Load traces
    data = json_mod.loads(Path(traces_json).read_text(encoding="utf-8"))
    trace_output = TraceOutput.model_validate(data)

    if not trace_output.paths:
        console.print("[yellow]No paths found in traces.json[/yellow]")
        sys.exit(0)

    console.print(f"\n[bold]deeptrace reason[/bold] — vulnerability reasoning")
    console.print(f"  Repo: [cyan]{repo}[/cyan]")
    console.print(f"  Target: [cyan]{trace_output.target}[/cyan]")
    console.print(f"  Paths: {len(trace_output.paths)} total, analyzing top {min(top_n, len(trace_output.paths))}")
    console.print(f"  LLM: {llm_provider}/{llm_model}")
    console.print()

    # Set up LLM
    llm_config = LLMConfig(
        enabled=True,
        provider=LLMProvider(llm_provider),
        model=llm_model,
        max_tokens=4096,
        temperature=0.2,
    )
    if llm_base_url:
        llm_config.base_url = llm_base_url
    if llm_api_key:
        llm_config.api_key = llm_api_key

    llm_caller = lambda system, user_msg: _call_llm(llm_config, system, user_msg)

    # Create reasoner
    reasoner = VulnerabilityReasoner(
        llm_caller=llm_caller,
        repo_path=repo,
    )

    # Analyze paths
    console.print("[bold]Analyzing traces...[/bold]")
    assessments = reasoner.analyze_all(
        trace_output.paths,
        top_n=top_n,
        progress_callback=lambda cur, total: console.print(
            f"  [{cur}/{total}] Analyzing path...", end="\r"
        ),
    )
    console.print()

    # Print summary to console
    for i, a in enumerate(assessments):
        icon = {
            "EXPLOITABLE": "[bold red]🔴 EXPLOITABLE[/bold red]",
            "NOT_EXPLOITABLE": "[dim green]✅ NOT EXPLOITABLE[/dim green]",
            "NEEDS_REVIEW": "[yellow]❓ NEEDS REVIEW[/yellow]",
        }.get(a.verdict, f"❓ {a.verdict}")

        console.print(f"  Path {i + 1} ({a.path_id}): {icon}  ({a.confidence:.0%})")
        if a.vulnerability_class:
            console.print(f"    Class: {a.vulnerability_class}")
        if a.root_cause:
            console.print(f"    Root cause: {a.root_cause[:150]}")
        if a.why_not:
            console.print(f"    Why safe: {a.why_not[:150]}")
        if a.cwe:
            console.print(f"    {a.cwe}")
        console.print()

    # Write Markdown report
    if not out:
        base = Path(traces_json).stem
        out = f"{base}_reasoning.md"

    report = format_assessment_report(
        assessments,
        target=trace_output.target,
        repo=repo,
    )
    Path(out).write_text(report, encoding="utf-8")
    console.print(f"[bold green]Report written to:[/bold green] [cyan]{out}[/cyan]")

    # Write JSON if requested
    if json_out:
        json_data = assessments_to_json(assessments)
        Path(json_out).write_text(
            json_mod.dumps(json_data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        console.print(f"[bold green]JSON written to:[/bold green] [cyan]{json_out}[/cyan]")

    # Final summary
    exploit_count = sum(1 for a in assessments if a.verdict == "EXPLOITABLE")
    safe_count = sum(1 for a in assessments if a.verdict == "NOT_EXPLOITABLE")
    if exploit_count:
        console.print(f"\n[bold red]🔴 {exploit_count} exploitable vulnerabilities found.[/bold red]")
    elif safe_count == len(assessments):
        console.print(f"\n[bold green]✅ All {safe_count} paths are not exploitable.[/bold green]")
    else:
        console.print(f"\n[yellow]❓ {len(assessments) - safe_count} paths need manual review.[/yellow]")
    console.print()


if __name__ == "__main__":
    cli()
#src\deeptrace\cli\visualize.py
"""Generate an interactive HTML visualization of trace paths.

Produces a standalone HTML file with:
  - Horizontal timelines for each trace path
  - Click-to-select nodes to view file + line + code
  - Navigation (prev/next) through timeline nodes
  - Color coding for SAT/UNSAT, vulnerability tags
  - Edge-type indicators between nodes
  - Sortable path list with Z3/LLM info
  - Source code panel with line highlighting
"""

from __future__ import annotations

import html
import json
import logging
import os
from pathlib import Path
from typing import Any

from deeptrace.models.graph import TraceOutput

logger = logging.getLogger(__name__)


def _read_source_file(repo_path: str, file_path: str) -> list[str] | None:
    """Try to read a source file from the repo."""
    candidates = [
        os.path.join(repo_path, file_path),
        os.path.join(repo_path, file_path.lstrip("./")),
        file_path,
    ]
    for p in candidates:
        try:
            return Path(p).read_text(encoding="utf-8", errors="replace").splitlines()
        except (FileNotFoundError, PermissionError, OSError):
            continue
    return None


def _collect_source_files(output: TraceOutput, repo_path: str) -> dict[str, list[str]]:
    """Pre-read all source files referenced by paths."""
    files_needed: set[str] = set()
    for path in output.paths:
        for step in path.steps:
            if step.location and step.location.file:
                files_needed.add(step.location.file)

    source_cache: dict[str, list[str]] = {}
    for fpath in files_needed:
        lines = _read_source_file(repo_path, fpath)
        if lines is not None:
            source_cache[fpath] = lines
    return source_cache


def generate_html(
    output: TraceOutput,
    repo_path: str = ".",
    out_path: str = "traces_timeline.html",
    max_paths: int = 50,
) -> str:
    """Generate a standalone HTML file with interactive trace timelines.

    Args:
        output: TraceOutput from a deeptrace run.
        repo_path: Path to the source repo (for reading source files).
        out_path: Where to write the HTML file.
        max_paths: Max paths to include in the visualization.

    Returns:
        Path to the generated HTML file.
    """
    source_cache = _collect_source_files(output, repo_path)
    paths_data = _serialize_paths(output, max_paths)
    source_data = {k: v for k, v in source_cache.items()}

    html_content = _TEMPLATE.replace(
        "/*__PATHS_DATA__*/",
        json.dumps(paths_data, ensure_ascii=False),
    ).replace(
        "/*__SOURCE_DATA__*/",
        json.dumps(source_data, ensure_ascii=False),
    ).replace(
        "/*__META__*/",
        json.dumps({
            "target": output.target,
            "source": output.source,
            "repo": output.repo,
            "node_count": output.node_count,
            "edge_count": output.edge_count,
            "total_paths": len(output.paths),
        }, ensure_ascii=False),
    )

    Path(out_path).write_text(html_content, encoding="utf-8")
    logger.info("HTML visualization written to %s", out_path)
    return out_path


def _serialize_paths(output: TraceOutput, max_paths: int) -> list[dict]:
    """Serialize paths for the JS frontend."""
    result = []
    for i, path in enumerate(output.paths[:max_paths]):
        steps = []
        for j, step in enumerate(path.steps):
            steps.append({
                "idx": j,
                "node_id": step.node_id,
                "file": step.location.file if step.location else "",
                "line": step.location.line if step.location else 0,
                "col": step.location.column if step.location else 0,
                "code": step.code_snippet,
                "edge_kind": step.edge_kind.value if step.edge_kind else "",
                "annotation": step.annotation,
            })
        result.append({
            "index": i,
            "id": path.id,
            "depth": path.depth,
            "score": round(path.score, 1),
            "llm_rank": path.llm_rank,
            "is_sat": path.is_satisfiable,
            "z3_model": path.z3_model,
            "vuln_tags": path.vulnerability_tags,
            "vuln_summary": path.vulnerability_summary,
            "rationale": path.llm_rationale,
            "constraints": path.constraints[:15],
            "steps": steps,
        })
    return result


# ---------------------------------------------------------------------------
# HTML template — standalone, no external dependencies
# ---------------------------------------------------------------------------

_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>deeptrace — Trace Timeline</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=DM+Sans:wght@400;500;600;700&display=swap" rel="stylesheet"/>
<style>
:root {
  --bg: #0c0e14;
  --bg-surface: #141721;
  --bg-elevated: #1a1e2e;
  --bg-code: #0d1017;
  --border: #2a2f42;
  --border-accent: #3d4463;
  --text: #c8cdd8;
  --text-dim: #6b7394;
  --text-bright: #e8ecf4;
  --accent: #6c9eff;
  --accent-glow: rgba(108,158,255,0.15);
  --green: #4ade80;
  --green-dim: rgba(74,222,128,0.12);
  --red: #f87171;
  --red-dim: rgba(248,113,113,0.12);
  --yellow: #fbbf24;
  --yellow-dim: rgba(251,191,36,0.12);
  --orange: #fb923c;
  --purple: #a78bfa;
  --teal: #2dd4bf;
  --line-highlight: rgba(108,158,255,0.08);
  --line-active: rgba(108,158,255,0.18);
  --font-sans: 'DM Sans', system-ui, sans-serif;
  --font-mono: 'JetBrains Mono', 'Fira Code', monospace;
  --radius: 8px;
  --radius-sm: 4px;
}

* { margin:0; padding:0; box-sizing:border-box; }
body {
  font-family: var(--font-sans);
  background: var(--bg);
  color: var(--text);
  overflow: hidden;
  height: 100vh;
}

/* ---- Layout ---- */
.app {
  display: grid;
  grid-template-columns: 340px 1fr;
  grid-template-rows: 56px 1fr;
  height: 100vh;
  gap: 0;
}
.header {
  grid-column: 1 / -1;
  display: flex;
  align-items: center;
  padding: 0 24px;
  background: var(--bg-surface);
  border-bottom: 1px solid var(--border);
  gap: 16px;
  z-index: 10;
}
.header h1 {
  font-size: 15px;
  font-weight: 700;
  color: var(--text-bright);
  letter-spacing: -0.02em;
}
.header h1 span { color: var(--accent); }
.header .meta {
  font-size: 12px;
  color: var(--text-dim);
  font-family: var(--font-mono);
}
.header .badge {
  font-size: 11px;
  padding: 2px 8px;
  border-radius: 99px;
  font-weight: 600;
  letter-spacing: 0.02em;
}
.badge-sat { background: var(--green-dim); color: var(--green); }
.badge-unsat { background: var(--red-dim); color: var(--red); }
.badge-vuln { background: var(--yellow-dim); color: var(--yellow); }

/* ---- Sidebar: path list ---- */
.sidebar {
  background: var(--bg-surface);
  border-right: 1px solid var(--border);
  overflow-y: auto;
  scrollbar-width: thin;
  scrollbar-color: var(--border) transparent;
}
.path-card {
  padding: 14px 18px;
  border-bottom: 1px solid var(--border);
  cursor: pointer;
  transition: background 0.15s;
}
.path-card:hover { background: var(--bg-elevated); }
.path-card.active {
  background: var(--accent-glow);
  border-left: 3px solid var(--accent);
  padding-left: 15px;
}
.path-card .top {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 6px;
}
.path-card .title {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-bright);
}
.path-card .rank {
  font-size: 11px;
  font-family: var(--font-mono);
  color: var(--accent);
}
.path-card .tags {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
  margin-top: 4px;
}
.path-card .tag {
  font-size: 10px;
  padding: 1px 6px;
  border-radius: 3px;
  font-weight: 500;
  background: var(--bg);
  color: var(--text-dim);
  border: 1px solid var(--border);
}
.path-card .tag.sat { background: var(--green-dim); color: var(--green); border-color: transparent; }
.path-card .tag.unsat { background: var(--red-dim); color: var(--red); border-color: transparent; }
.path-card .info {
  font-size: 11px;
  color: var(--text-dim);
  margin-top: 4px;
}

/* ---- Main content ---- */
.main {
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

/* ---- Timeline ---- */
.timeline-panel {
  padding: 20px 24px;
  border-bottom: 1px solid var(--border);
  overflow-x: auto;
  flex-shrink: 0;
  min-height: 190px;
  scrollbar-width: thin;
  scrollbar-color: var(--border) transparent;
}
.timeline-title {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 14px;
}
.timeline {
  display: flex;
  align-items: center;
  gap: 0;
  padding: 8px 0;
  width: max-content;
  min-width: 100%;
}
.tl-node {
  display: flex;
  flex-direction: column;
  align-items: center;
  cursor: pointer;
  transition: transform 0.15s;
  flex-shrink: 0;
}
.tl-node:hover { transform: translateY(-2px); }
.tl-dot {
  width: 38px;
  height: 38px;
  border-radius: 50%;
  background: var(--bg-elevated);
  border: 2px solid var(--border-accent);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 11px;
  font-family: var(--font-mono);
  font-weight: 700;
  color: var(--text-dim);
  transition: all 0.2s;
}
.tl-node.active .tl-dot {
  border-color: var(--accent);
  background: var(--accent-glow);
  color: var(--accent);
  box-shadow: 0 0 16px rgba(108,158,255,0.25);
}
.tl-node.first .tl-dot { border-color: var(--teal); color: var(--teal); }
.tl-node.last .tl-dot  { border-color: var(--orange); color: var(--orange); }
.tl-file {
  font-size: 10px;
  color: var(--text-dim);
  margin-top: 6px;
  max-width: 90px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  text-align: center;
  font-family: var(--font-mono);
}
.tl-node.active .tl-file { color: var(--accent); }
.tl-edge {
  display: flex;
  flex-direction: column;
  align-items: center;
  min-width: 56px;
  flex-shrink: 0;
}
.tl-edge-line {
  height: 2px;
  width: 100%;
  background: var(--border-accent);
  position: relative;
}
.tl-edge-line::after {
  content: '';
  position: absolute;
  right: -5px;
  top: -4px;
  border: 5px solid transparent;
  border-left-color: var(--border-accent);
}
.tl-edge-label {
  font-size: 9px;
  color: var(--text-dim);
  font-family: var(--font-mono);
  margin-top: 3px;
  white-space: nowrap;
}

/* ---- Node detail panel ---- */
.detail-panel {
  display: flex;
  flex: 1;
  overflow: hidden;
}
.code-panel {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.code-header {
  padding: 12px 24px;
  background: var(--bg-surface);
  border-bottom: 1px solid var(--border);
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.code-header .filepath {
  font-family: var(--font-mono);
  font-size: 13px;
  color: var(--accent);
  font-weight: 500;
}
.code-header .nav-btns {
  display: flex;
  gap: 6px;
}
.nav-btn {
  padding: 4px 14px;
  font-size: 12px;
  font-family: var(--font-mono);
  background: var(--bg-elevated);
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all 0.15s;
}
.nav-btn:hover { background: var(--accent-glow); border-color: var(--accent); color: var(--accent); }
.nav-btn:disabled { opacity: 0.3; cursor: default; }
.code-body {
  flex: 1;
  overflow: auto;
  scrollbar-width: thin;
  scrollbar-color: var(--border) transparent;
}
.code-body pre {
  margin: 0;
  padding: 12px 0;
  font-family: var(--font-mono);
  font-size: 12.5px;
  line-height: 1.65;
  color: var(--text);
}
.code-line {
  display: flex;
  padding: 0 24px;
  min-height: 21px;
}
.code-line.highlight { background: var(--line-highlight); }
.code-line.active-line {
  background: var(--line-active);
  border-left: 3px solid var(--accent);
  padding-left: 21px;
}
.line-no {
  width: 52px;
  text-align: right;
  padding-right: 16px;
  color: var(--text-dim);
  user-select: none;
  flex-shrink: 0;
  font-size: 11px;
}
.line-code { white-space: pre; flex: 1; }

/* ---- Info sidebar (right) ---- */
.info-panel {
  width: 320px;
  background: var(--bg-surface);
  border-left: 1px solid var(--border);
  overflow-y: auto;
  padding: 18px;
  scrollbar-width: thin;
  scrollbar-color: var(--border) transparent;
}
.info-section {
  margin-bottom: 20px;
}
.info-section .label {
  font-size: 11px;
  font-weight: 600;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  margin-bottom: 8px;
}
.info-section .value {
  font-size: 13px;
  color: var(--text-bright);
  line-height: 1.5;
}
.info-section .value.mono { font-family: var(--font-mono); font-size: 12px; }
.info-section .value.annotation {
  font-style: italic;
  color: var(--green);
  background: var(--green-dim);
  padding: 8px 12px;
  border-radius: var(--radius-sm);
  font-size: 12px;
}
.info-section .value.vuln-summary {
  background: var(--bg);
  padding: 12px;
  border-radius: var(--radius);
  border: 1px solid var(--border);
  font-size: 12px;
  line-height: 1.6;
  white-space: pre-wrap;
}
.constraint-item {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-dim);
  padding: 3px 0;
  border-bottom: 1px solid var(--border);
}
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: var(--text-dim);
  font-size: 14px;
  gap: 8px;
}
.empty-state .icon { font-size: 36px; opacity: 0.3; }
.kbd {
  display: inline-block;
  padding: 1px 6px;
  font-family: var(--font-mono);
  font-size: 11px;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: 3px;
  color: var(--text-dim);
}
</style>
</head>
<body>
<div class="app" id="app">
  <div class="header">
    <h1><span>deeptrace</span> timeline</h1>
    <div class="meta" id="meta-target"></div>
    <div class="meta" id="meta-stats"></div>
    <div style="flex:1"></div>
    <div class="meta">
      <span class="kbd">&larr;</span> <span class="kbd">&rarr;</span> navigate &nbsp;
      <span class="kbd">&uarr;</span> <span class="kbd">&darr;</span> switch path
    </div>
  </div>
  <div class="sidebar" id="sidebar"></div>
  <div class="main">
    <div class="timeline-panel" id="timeline-panel">
      <div class="timeline-title">PATH TIMELINE</div>
      <div class="timeline" id="timeline">
        <div class="empty-state">
          <div class="icon">&#x2190;</div>
          <div>Select a path from the list</div>
        </div>
      </div>
    </div>
    <div class="detail-panel">
      <div class="code-panel">
        <div class="code-header">
          <div class="filepath" id="filepath">No file selected</div>
          <div class="nav-btns">
            <button class="nav-btn" id="btn-prev" disabled onclick="navStep(-1)">&larr; Prev</button>
            <span id="step-counter" style="font-size:12px;color:var(--text-dim);font-family:var(--font-mono);padding:4px 8px">—</span>
            <button class="nav-btn" id="btn-next" disabled onclick="navStep(1)">Next &rarr;</button>
          </div>
        </div>
        <div class="code-body" id="code-body">
          <div class="empty-state">
            <div class="icon">&#x1F4C4;</div>
            <div>Click a node to view source code</div>
          </div>
        </div>
      </div>
      <div class="info-panel" id="info-panel">
        <div class="empty-state">
          <div class="icon">&#x1F50D;</div>
          <div>Node details appear here</div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
// ---- Data injected at build time ----
const PATHS = /*__PATHS_DATA__*/[];
const SOURCES = /*__SOURCE_DATA__*/{};
const META = /*__META__*/{};

// ---- State ----
let currentPathIdx = -1;
let currentStepIdx = -1;

// ---- Init ----
document.addEventListener('DOMContentLoaded', () => {
  renderMeta();
  renderSidebar();
  if (PATHS.length > 0) selectPath(0);
  document.addEventListener('keydown', onKey);
});

function renderMeta() {
  const t = META.source
    ? `${META.source} → ${META.target}`
    : META.target;
  document.getElementById('meta-target').textContent = t;
  document.getElementById('meta-stats').textContent =
    `${META.node_count} nodes · ${META.edge_count} edges · ${META.total_paths} paths`;
}

function renderSidebar() {
  const sb = document.getElementById('sidebar');
  sb.innerHTML = '';
  PATHS.forEach((p, i) => {
    const card = document.createElement('div');
    card.className = 'path-card';
    card.dataset.idx = i;
    card.onclick = () => selectPath(i);

    const satBadge = p.is_sat === true ? '<span class="tag sat">SAT</span>'
                   : p.is_sat === false ? '<span class="tag unsat">UNSAT</span>' : '';
    const vulnTags = p.vuln_tags.map(t => `<span class="tag">${esc(t)}</span>`).join('');
    const rank = p.llm_rank ? `LLM #${p.llm_rank}` : `score ${p.score}`;
    const startF = p.steps.length ? shortFile(p.steps[0].file) : '?';
    const endF = p.steps.length ? shortFile(p.steps[p.steps.length-1].file) : '?';

    card.innerHTML = `
      <div class="top">
        <span class="title">Path #${i+1}</span>
        <span class="rank">${rank}</span>
      </div>
      <div class="info">${p.depth} steps · ${startF} → ${endF}</div>
      <div class="tags">${satBadge}${vulnTags}</div>
    `;
    sb.appendChild(card);
  });
}

function selectPath(idx) {
  if (idx < 0 || idx >= PATHS.length) return;
  currentPathIdx = idx;
  currentStepIdx = -1;

  // Update sidebar active state
  document.querySelectorAll('.path-card').forEach((c, i) => {
    c.classList.toggle('active', i === idx);
  });
  // Scroll active card into view
  const active = document.querySelector('.path-card.active');
  if (active) active.scrollIntoView({ block: 'nearest' });

  renderTimeline(PATHS[idx]);
  clearDetail();
  if (PATHS[idx].steps.length > 0) selectStep(0);
}

function renderTimeline(path) {
  const tl = document.getElementById('timeline');
  tl.innerHTML = '';

  path.steps.forEach((step, i) => {
    // Edge connector (before node, except first)
    if (i > 0) {
      const edge = document.createElement('div');
      edge.className = 'tl-edge';
      edge.innerHTML = `
        <div class="tl-edge-line"></div>
        <div class="tl-edge-label">${esc(step.edge_kind || '?')}</div>
      `;
      tl.appendChild(edge);
    }

    // Node
    const node = document.createElement('div');
    node.className = 'tl-node';
    if (i === 0) node.classList.add('first');
    if (i === path.steps.length - 1) node.classList.add('last');
    node.dataset.step = i;
    node.onclick = () => selectStep(i);

    const fname = step.file ? step.file.split('/').pop().split('\\').pop() : '?';
    node.innerHTML = `
      <div class="tl-dot">${i+1}</div>
      <div class="tl-file">${esc(fname)}:${step.line}</div>
    `;
    tl.appendChild(node);
  });
}

function selectStep(idx) {
  const path = PATHS[currentPathIdx];
  if (!path || idx < 0 || idx >= path.steps.length) return;
  currentStepIdx = idx;
  const step = path.steps[idx];

  // Update timeline active
  document.querySelectorAll('.tl-node').forEach((n, i) => {
    n.classList.toggle('active', i === idx);
  });
  // Scroll active node into view in timeline
  const activeNode = document.querySelector('.tl-node.active');
  if (activeNode) activeNode.scrollIntoView({ block: 'nearest', inline: 'center', behavior: 'smooth' });

  // Update nav
  document.getElementById('btn-prev').disabled = idx <= 0;
  document.getElementById('btn-next').disabled = idx >= path.steps.length - 1;
  document.getElementById('step-counter').textContent = `${idx+1} / ${path.steps.length}`;

  // Render code
  renderCode(step);
  renderInfo(step, path, idx);
}

function renderCode(step) {
  const fp = document.getElementById('filepath');
  const body = document.getElementById('code-body');

  if (!step.file) {
    fp.textContent = 'No file';
    body.innerHTML = '<div class="empty-state"><div>No source file for this node</div></div>';
    return;
  }

  fp.textContent = `${step.file}:${step.line}`;

  const lines = SOURCES[step.file];
  if (!lines) {
    body.innerHTML = `<div class="empty-state">
      <div>Source not available</div>
      <div style="font-size:12px;color:var(--text-dim)">${esc(step.file)}</div>
      ${step.code ? '<pre style="padding:16px 24px;color:var(--text)">' + esc(step.code) + '</pre>' : ''}
    </div>`;
    return;
  }

  const targetLine = step.line;
  const contextRadius = 30;
  const startLine = Math.max(1, targetLine - contextRadius);
  const endLine = Math.min(lines.length, targetLine + contextRadius);

  let html = '<pre>';
  for (let i = startLine; i <= endLine; i++) {
    const lineText = lines[i-1] || '';
    const isActive = i === targetLine;
    const isNear = Math.abs(i - targetLine) <= 3;
    const cls = isActive ? 'code-line active-line' : isNear ? 'code-line highlight' : 'code-line';
    html += `<div class="${cls}" id="line-${i}"><span class="line-no">${i}</span><span class="line-code">${esc(lineText)}</span></div>`;
  }
  html += '</pre>';
  body.innerHTML = html;

  // Scroll to active line
  requestAnimationFrame(() => {
    const el = document.getElementById(`line-${targetLine}`);
    if (el) el.scrollIntoView({ block: 'center' });
  });
}

function renderInfo(step, path, idx) {
  const panel = document.getElementById('info-panel');
  let h = '';

  // Node ID
  h += `<div class="info-section">
    <div class="label">Node</div>
    <div class="value mono">${esc(step.node_id.substring(0, 60))}</div>
  </div>`;

  // Edge
  if (step.edge_kind) {
    h += `<div class="info-section">
      <div class="label">Edge Type</div>
      <div class="value">${esc(step.edge_kind)}</div>
    </div>`;
  }

  // Code snippet
  if (step.code) {
    h += `<div class="info-section">
      <div class="label">Code</div>
      <div class="value mono" style="white-space:pre-wrap;background:var(--bg-code);padding:10px;border-radius:var(--radius-sm)">${esc(step.code)}</div>
    </div>`;
  }

  // Annotation
  if (step.annotation) {
    h += `<div class="info-section">
      <div class="label">AI Annotation</div>
      <div class="value annotation">${esc(step.annotation)}</div>
    </div>`;
  }

  // Path-level info (only show on first viewing or when asking)
  if (path.vuln_tags.length) {
    h += `<div class="info-section">
      <div class="label">Vulnerability Tags</div>
      <div class="value">${path.vuln_tags.map(t => `<span class="badge badge-vuln" style="margin-right:4px">${esc(t)}</span>`).join('')}</div>
    </div>`;
  }

  // Z3
  if (path.is_sat !== null && path.is_sat !== undefined) {
    const satLabel = path.is_sat ? '<span class="badge badge-sat">SATISFIABLE</span>' : '<span class="badge badge-unsat">UNSATISFIABLE</span>';
    h += `<div class="info-section">
      <div class="label">Z3 Satisfiability</div>
      <div class="value">${satLabel}</div>
    </div>`;
    if (path.z3_model) {
      h += `<div class="info-section">
        <div class="label">Satisfying Assignment</div>
        <div class="value mono">${esc(path.z3_model)}</div>
      </div>`;
    }
  }

  // Constraints (for this step)
  const stepConstraints = path.constraints.filter(c => c.includes(`step ${idx}`));
  if (stepConstraints.length) {
    h += `<div class="info-section">
      <div class="label">Constraints at this step</div>
      ${stepConstraints.map(c => `<div class="constraint-item">${esc(c)}</div>`).join('')}
    </div>`;
  }

  // Rationale
  if (path.rationale) {
    h += `<div class="info-section">
      <div class="label">LLM Rationale</div>
      <div class="value">${esc(path.rationale)}</div>
    </div>`;
  }

  // Vulnerability summary
  if (path.vuln_summary) {
    h += `<div class="info-section">
      <div class="label">Vulnerability Analysis</div>
      <div class="value vuln-summary">${esc(path.vuln_summary)}</div>
    </div>`;
  }

  panel.innerHTML = h;
}

function clearDetail() {
  document.getElementById('filepath').textContent = 'No file selected';
  document.getElementById('code-body').innerHTML = '<div class="empty-state"><div class="icon">&#x1F4C4;</div><div>Click a node to view source code</div></div>';
  document.getElementById('info-panel').innerHTML = '<div class="empty-state"><div class="icon">&#x1F50D;</div><div>Node details appear here</div></div>';
  document.getElementById('step-counter').textContent = '—';
  document.getElementById('btn-prev').disabled = true;
  document.getElementById('btn-next').disabled = true;
}

function navStep(delta) {
  if (currentPathIdx < 0) return;
  const newIdx = currentStepIdx + delta;
  if (newIdx >= 0 && newIdx < PATHS[currentPathIdx].steps.length) {
    selectStep(newIdx);
  }
}

function onKey(e) {
  if (e.key === 'ArrowRight') { e.preventDefault(); navStep(1); }
  else if (e.key === 'ArrowLeft') { e.preventDefault(); navStep(-1); }
  else if (e.key === 'ArrowDown') { e.preventDefault(); selectPath(currentPathIdx + 1); }
  else if (e.key === 'ArrowUp') { e.preventDefault(); selectPath(currentPathIdx - 1); }
}

function shortFile(f) {
  if (!f) return '?';
  const parts = f.replace(/\\/g, '/').split('/');
  return parts.length > 1 ? parts.slice(-2).join('/') : parts[0];
}

function esc(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
</script>
</body>
</html>"""

#src\deeptrace\core\aco.py
"""Ant Colony Optimization explorer for deep dependency paths.

Implements MAX-MIN Ant System (MMAS) with:
- Backward exploration from target
- Pheromone bounds to prevent stagnation
- Elite ant reinforcement
- Local search refinement
- Branch-point detection for interactive mode
"""

from __future__ import annotations

import logging
import random
from collections import defaultdict
from typing import Any, Callable

import numpy as np

from deeptrace.analysis.constraint_solver import IncrementalZ3Checker
from deeptrace.core.graph_builder import DependencyGraph
from deeptrace.models.config import ACOConfig, BranchingConfig
from deeptrace.models.graph import (
    BranchCandidate,
    BranchPoint,
    EdgeKind,
    NodeKind,
    BackendKind,
    SourceLocation,
    GraphNode,
    GraphEdge,
    TracePath,
    TraceStep,
)

logger = logging.getLogger(__name__)


class ACOExplorer:
    """MAX-MIN Ant System for exploring deep dependency paths."""

    def __init__(
        self,
        graph: DependencyGraph,
        config: ACOConfig,
        branching_config: BranchingConfig | None = None,
        dynamic_resolver: Any | None = None,
        z3_enabled: bool = False,
    ) -> None:
        self.graph = graph
        self.config = config
        self.branching = branching_config or BranchingConfig()
        self.dynamic_resolver = dynamic_resolver
        self.z3_enabled = z3_enabled

        # Pheromone table: (src, dst) → pheromone value
        self._pheromone: dict[tuple[str, str], float] = defaultdict(
            lambda: (config.max_pheromone + config.min_pheromone) / 2
        )

        # Results
        self.best_paths: list[TracePath] = []
        self.branch_points: list[BranchPoint] = []

        # Tracking
        self._iteration_best: list[float] = []
        self._stagnation_counter = 0
        self._global_best_score = 0.0
        self._path_hashes: set[str] = set()   # deduplicate paths

    # -----------------------------------------------------------------------
    # Main exploration loop
    # -----------------------------------------------------------------------

    def explore(
        self,
        targets: list[str],
        max_depth: int = 30,
        topk: int = 20,
        progress_callback: Callable[[int, int, int], None] | None = None,
        reachable_override: set[str] | None = None,
    ) -> list[TracePath]:
        """Run ACO exploration backward from target nodes.

        Args:
            targets: Target node IDs to trace backward from.
            max_depth: Maximum trace depth.
            topk: Number of top paths to return.
            progress_callback: Called with (iteration, total, paths_found).
            reachable_override: If provided, restrict exploration to these nodes
                                (used for source-sink constrained tracing).

        Returns:
            Top-K trace paths sorted by score.
        """
        if not targets:
            logger.warning("No target nodes provided")
            return []

        # Compute heuristic weights
        self.graph.compute_heuristic_weights()

        # Restrict to reachable subgraph
        if reachable_override is not None:
            reachable = reachable_override
            logger.info(
                "Using provided reachable set: %d nodes (source-sink mode)",
                len(reachable),
            )
        else:
            reachable = self.graph.subgraph_around(targets, max_depth)
            logger.info(
                "Reachable subgraph: %d nodes (from %d total)",
                len(reachable), self.graph.node_count,
            )

        total_iterations = self.config.iterations
        for iteration in range(total_iterations):
            iteration_paths: list[TracePath] = []

            for ant_idx in range(self.config.ants):
                target = random.choice(targets)
                path = self._construct_path(target, reachable, max_depth)
                if path and len(path.steps) >= 2:
                    # Deduplicate
                    if path.id not in self._path_hashes:
                        self._path_hashes.add(path.id)
                        iteration_paths.append(path)

            # Apply local search to top paths
            if self.config.local_search and iteration_paths:
                iteration_paths = self._local_search(iteration_paths, reachable, max_depth)

            # Update pheromones
            self._evaporate()
            self._deposit(iteration_paths)

            # Track best
            if iteration_paths:
                iter_best = max(p.score for p in iteration_paths)
                self._iteration_best.append(iter_best)

                if iter_best > self._global_best_score:
                    self._global_best_score = iter_best
                    self._stagnation_counter = 0
                else:
                    self._stagnation_counter += 1

                self.best_paths.extend(iteration_paths)

            # Stagnation reset
            if self._stagnation_counter >= self.config.stagnation_limit:
                logger.debug("Stagnation reset at iteration %d", iteration)
                self._reset_pheromones()
                self._stagnation_counter = 0

            if progress_callback:
                progress_callback(iteration + 1, total_iterations, len(self.best_paths))

        # Sort and return top-K
        self.best_paths.sort(key=lambda p: p.score, reverse=True)
        pool_size = topk * 5
        result = self.best_paths[:pool_size]

        logger.info(
            "ACO complete: %d total paths, returning top %d to orchestrator for filtering",
            len(self.best_paths), len(result),
        )
        return result

    # -----------------------------------------------------------------------
    # Path construction (single ant)
    # -----------------------------------------------------------------------

    def _construct_path(
        self,
        start: str,
        reachable: set[str],
        max_depth: int,
    ) -> TracePath | None:
        """One ant constructs a backward path from the target."""
        visited: set[str] = set()
        steps: list[TraceStep] = []
        current = start

        # Give the ant an organic constraint pruner
        z3_checker = IncrementalZ3Checker() if self.z3_enabled else None  # <--- FIX THIS LINE

        for depth in range(max_depth):
            if current in visited:
                break
            visited.add(current)

            node = self.graph.get_node(current)

            if node and z3_checker and "ast_condition" in node.properties:
                is_feasible = z3_checker.add_and_check(node.properties["ast_condition"])
                if not is_feasible:
                    logger.debug("Ant died at %s: Path became mathematically UNSAT.", current)
                    break  # Kill the ant. The path is impossible.


            steps.append(TraceStep(
                node_id=current,
                location=node.location if node else None,
                code_snippet=node.location.code_snippet if node and node.location else "",
                node_kind=node.kind if node else None,
                node_name=node.name if node else "",
            ))

            # Get predecessors within reachable set (including interprocedural jumps)
            direct_preds = self.graph.predecessors(current)
            interproc_preds = self.graph._interprocedural_predecessors(current)
            all_preds = set(direct_preds) | set(interproc_preds)
            preds = [p for p in all_preds if p in reachable and p not in visited]

            if not preds:
                # 1. Check if we died on a CALL_SITE
                if node and node.kind == NodeKind.CALL_SITE and node.name and self.dynamic_resolver:
                    logger.debug("Ant hit dead end at call to %s. Attempting dynamic resolution.", node.name)

                    caller_file = node.location.file if node.location else "unknown"
                    caller_code = node.location.code_snippet if node.location else ""

                    result = self.dynamic_resolver.resolve_call(caller_file, caller_code, node.name)

                    if result.resolved:
                        # 2. Generate a new Node ID
                        new_node_id = f"dyn:{result.file_path}:{result.line_number}:{node.name}"

                        # 3. Patch the Graph dynamically
                        if not self.graph.get_node(new_node_id):
                            new_node = GraphNode(
                                id=new_node_id,
                                kind=NodeKind.IDENTIFIER,
                                name=node.name,
                                location=SourceLocation(
                                    file=result.file_path,
                                    line=result.line_number,
                                    code_snippet=result.code_snippet
                                ),
                                backend=BackendKind.TREESITTER
                            )
                            self.graph.add_nodes([new_node])

                        # 4. Link the dead-end node to the newly discovered definition
                        if not self.graph.get_edge_data(current, new_node_id):
                            new_edge = GraphEdge(
                                src=current,
                                dst=new_node_id,
                                kind=EdgeKind.CALL,
                                weight=1.0,
                                backend=BackendKind.TREESITTER
                            )
                            self.graph.add_edges([new_edge])

                        # 5. Inject the new node into the ant's reachable pool
                        reachable.add(new_node_id)
                        preds = [new_node_id]
                    else:
                        break # Resolution failed, ant dies here.
                else:
                    break # Not a call site, ant dies here.

            # Detect branch points (high fan-out)
            if len(preds) > self.branching.max_fan_out:
                self._record_branch_point(current, preds, node)

            # Select next node via ACO probability
            next_node = self._select_next(current, preds)
            if next_node is None:
                break

            # ---> LOCAL PHEROMONE EVAPORATION (ACS) <---
            # Instantly degrade the pheromone on this edge so the next ant explores elsewhere.
            # Formula: tau = (1 - rho) * tau + rho * tau_0
            edge_key = (next_node, current)
            tau_0 = self.config.min_pheromone
            self._pheromone[edge_key] = (
                    (1.0 - self.config.rho) * self._pheromone[edge_key] +
                    (self.config.rho * tau_0)
            )

            # Record the edge kind
            edge_data = self.graph.get_edge_data(next_node, current)
            if edge_data:
                steps[-1].edge_kind = EdgeKind(edge_data.get("kind", "unknown"))

            current = next_node

        if len(steps) < 2:
            return None

        # Steps are from target backward; reverse for source→target order
        steps.reverse()

        # Score the path
        score = self._score_path(steps)

        return TracePath(steps=steps, score=score)

    def _select_next(self, current: str, candidates: list[str]) -> str | None:
        """Select next node using ACO transition rule."""
        if not candidates:
            return None

        if len(candidates) == 1:
            return candidates[0]

        # Compute transition probabilities
        probs = np.zeros(len(candidates), dtype=np.float64)

        for i, cand in enumerate(candidates):
            tau = self._pheromone[(cand, current)]  # pheromone on edge cand→current
            edge_data = self.graph.get_edge_data(cand, current)

            # Weight convention: lower = more important.  ACO picks higher eta,
            # so invert:  eta = 1/weight  → important edges get high eta.
            raw_w = float(edge_data.get("weight", 1.0)) if edge_data else 2.0
            eta = 1.0 / max(raw_w, 0.01)

            probs[i] = (tau ** self.config.alpha) * (eta ** self.config.beta)

        # Exploitation vs exploration (ACS-style)
        if random.random() < self.config.q0:
            # Greedy: pick best
            return candidates[int(np.argmax(probs))]
        else:
            # Probabilistic: roulette wheel
            total = probs.sum()
            if total <= 0:
                return random.choice(candidates)
            probs /= total
            idx = np.random.choice(len(candidates), p=probs)
            return candidates[idx]

    # -----------------------------------------------------------------------
    # Path scoring
    # -----------------------------------------------------------------------

    def _score_path(self, steps: list[TraceStep]) -> float:
        """Score a path based on depth, diversity, and edge types."""
        if not steps:
            return 0.0

        score = 0.0

        # Depth bonus (deeper = more interesting)
        score += len(steps) * 2.0

        # Edge type diversity bonus
        edge_kinds: set[str] = set()
        for step in steps:
            if step.edge_kind:
                edge_kinds.add(step.edge_kind.value)
        score += len(edge_kinds) * 3.0

        # File diversity bonus (cross-file traces are more interesting)
        files: set[str] = set()
        for step in steps:
            if step.location and step.location.file:
                files.add(step.location.file)
        score += len(files) * 5.0

        # Bonus for interesting edge types
        interesting_edges = {EdgeKind.POINTER_DEREF, EdgeKind.ALIAS, EdgeKind.FIELD_ACCESS}
        for step in steps:
            if step.edge_kind in interesting_edges:
                score += 2.0

        # Code snippet coverage bonus
        has_code = sum(1 for s in steps if s.code_snippet)
        score += has_code * 0.5

        return score

    # -----------------------------------------------------------------------
    # Pheromone management
    # -----------------------------------------------------------------------

    def _evaporate(self) -> None:
        """Evaporate pheromones."""
        for key in self._pheromone:
            self._pheromone[key] = max(
                self._pheromone[key] * (1 - self.config.rho),
                self.config.min_pheromone,
            )

    def _deposit(self, paths: list[TracePath]) -> None:
        """Deposit pheromones on edges of good paths."""
        if not paths:
            return

        # Sort by score
        sorted_paths = sorted(paths, key=lambda p: p.score, reverse=True)

        # Only elite ants deposit
        elite = sorted_paths[:self.config.elite_ants]
        for rank, path in enumerate(elite):
            deposit = path.score / (rank + 1)
            for i in range(len(path.steps) - 1):
                src = path.steps[i].node_id
                dst = path.steps[i + 1].node_id
                self._pheromone[(src, dst)] = min(
                    self._pheromone[(src, dst)] + deposit,
                    self.config.max_pheromone,
                )

    def _reset_pheromones(self) -> None:
        """Reset pheromones to midpoint (stagnation escape)."""
        mid = (self.config.max_pheromone + self.config.min_pheromone) / 2
        for key in self._pheromone:
            self._pheromone[key] = mid

    # -----------------------------------------------------------------------
    # Local search
    # -----------------------------------------------------------------------

    def _local_search(
        self,
        paths: list[TracePath],
        reachable: set[str],
        max_depth: int,
    ) -> list[TracePath]:
        """Try extending or improving top paths via 2-opt-like moves."""
        improved: list[TracePath] = list(paths)

        for path in sorted(paths, key=lambda p: p.score, reverse=True)[:5]:
            # Try extending: continue backward from the earliest step
            if path.steps:
                first = path.steps[0]
                direct = self.graph.predecessors(first.node_id)
                interproc = self.graph._interprocedural_predecessors(first.node_id)
                preds = [
                    p for p in set(direct) | set(interproc)
                    if p in reachable and not any(s.node_id == p for s in path.steps)
                ]
                for pred_id in preds[:3]:
                    node = self.graph.get_node(pred_id)
                    # Pass the semantic attributes required by the vulnerability analyzer
                    new_step = TraceStep(
                        node_id=pred_id,
                        location=node.location if node else None,
                        code_snippet=node.location.code_snippet if node and node.location else "",
                        node_kind=node.kind if node else None,
                        node_name=node.name if node else "",
                    )
                    new_steps = [new_step] + list(path.steps)
                    new_score = self._score_path(new_steps)
                    if new_score > path.score:
                        new_path = TracePath(steps=new_steps, score=new_score)
                        if new_path.id not in self._path_hashes:
                            self._path_hashes.add(new_path.id)
                            improved.append(new_path)

        return improved

    # -----------------------------------------------------------------------
    # Branch point detection
    # -----------------------------------------------------------------------

    def _record_branch_point(
        self,
        node_id: str,
        candidates: list[str],
        node: GraphNode | None,
    ) -> None:
        """Record a branching point where exploration diverges."""
        # Don't duplicate
        if any(bp.node_id == node_id for bp in self.branch_points):
            return

        branch_candidates: list[BranchCandidate] = []
        for idx, cand_id in enumerate(candidates[:self.branching.auto_prune_threshold]):
            cand_node = self.graph.get_node(cand_id)
            edge_data = self.graph.get_edge_data(cand_id, node_id)

            # Estimate sub-path depth via BFS
            est_depth = self._estimate_depth(cand_id, max_depth=10)

            branch_candidates.append(BranchCandidate(
                index=idx,
                next_node_id=cand_id,
                edge_kind=EdgeKind(edge_data.get("kind", "unknown")) if edge_data else EdgeKind.UNKNOWN,
                code_preview=(
                    cand_node.location.code_snippet if cand_node and cand_node.location else ""
                ),
                estimated_depth=est_depth,
            ))

        bp = BranchPoint(
            node_id=node_id,
            location=node.location if node else None,
            candidates=branch_candidates,
        )
        self.branch_points.append(bp)
        logger.info(
            "Branch point at %s: %d candidates (total in graph: %d)",
            node_id, len(branch_candidates), len(candidates),
        )

    def _estimate_depth(self, node_id: str, max_depth: int = 10) -> int:
        """Estimate how deep the backward trace goes from a node (via BFS)."""
        visited: set[str] = set()
        frontier = [node_id]
        depth = 0
        while frontier and depth < max_depth:
            next_f: list[str] = []
            for nid in frontier:
                if nid in visited:
                    continue
                visited.add(nid)
                next_f.extend(self.graph.predecessors(nid))
                next_f.extend(self.graph._interprocedural_predecessors(nid))
            frontier = next_f
            depth += 1
        return depth
#src\deeptrace\core\batch.py
"""Batch runner: loop through multiple file:line targets from lines.json.

Reads a JSON file produced by lines.py containing an array of targets,
runs the full trace pipeline for each, and aggregates results.

Expected lines.json format (from lines.py):
[
  {"file": "core/fpdftext/cpdf_linkextract.cpp", "line": 44},
  {"file": "core/fxge/dib/fx_dib.cpp", "line": 210, "source_file": "...", "source_line": 50},
  ...
]

Or the simpler string format:
[
  "core/fpdftext/cpdf_linkextract.cpp:44",
  "core/fxge/dib/fx_dib.cpp:210",
  ...
]
"""

from __future__ import annotations

import json
import logging
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable

import orjson

from deeptrace.models.config import DeeptraceConfig
from deeptrace.models.graph import BatchOutput, BatchTarget, TraceOutput

logger = logging.getLogger(__name__)


def load_targets(lines_file: str) -> list[BatchTarget]:
    """Load targets from a lines.json file.

    Supports two formats:
    1. Array of objects: [{"file": "...", "line": N}, ...]
    2. Array of strings: ["path/to/file.c:42", ...]
    """
    raw = Path(lines_file).read_text(encoding="utf-8")
    data = json.loads(raw)

    if not isinstance(data, list):
        raise ValueError(f"lines.json must be a JSON array, got {type(data).__name__}")

    targets: list[BatchTarget] = []
    for i, item in enumerate(data):
        if isinstance(item, str):
            # String format: "file:line"
            parts = item.rsplit(":", 1)
            if len(parts) != 2:
                logger.warning("Skipping invalid target at index %d: %r", i, item)
                continue
            targets.append(BatchTarget(file=parts[0], line=int(parts[1])))

        elif isinstance(item, dict):
            # Object format
            file_path = item.get("file", "")
            line = item.get("line", 0)
            if not file_path or not line:
                logger.warning("Skipping invalid target at index %d: %r", i, item)
                continue
            targets.append(BatchTarget(
                file=file_path,
                line=int(line),
                source_file=item.get("source_file", ""),
                source_line=int(item.get("source_line", 0)),
            ))
        else:
            logger.warning("Skipping unrecognized item at index %d: %r", i, item)

    logger.info("Loaded %d targets from %s", len(targets), lines_file)
    return targets


class BatchRunner:
    """Runs the trace pipeline for each target in a lines.json file."""

    def __init__(self, base_config: DeeptraceConfig) -> None:
        self.base_config = base_config

    def run(
        self,
        targets: list[BatchTarget],
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> BatchOutput:
        """Execute trace pipeline for each target.

        Args:
            targets: List of targets to trace.
            progress_callback: Called with (current_idx, total, target_str).

        Returns:
            Aggregated BatchOutput.
        """
        from deeptrace.core.orchestrator import TraceOrchestrator

        t0 = time.time()
        batch_output = BatchOutput(
            repo=self.base_config.repo,
            total_targets=len(targets),
        )

        # We build the graph ONCE for the whole repo, then reuse it
        # This is a major optimization: extract graph once, query many times
        shared_graph = None
        shared_language = None

        for idx, target in enumerate(targets):
            target_str = f"{target.file}:{target.line}"

            if progress_callback:
                progress_callback(idx, len(targets), target_str)

            logger.info(
                "--- Batch target %d/%d: %s ---",
                idx + 1, len(targets), target_str,
            )

            # Build per-target config
            config = deepcopy(self.base_config)
            config.target = target_str
            if target.source_file and target.source_line:
                config.source = f"{target.source_file}:{target.source_line}"

            # Per-target output file
            safe_name = target.file.replace("/", "_").replace("\\", "_")
            config.out = str(
                Path(self.base_config.out) / f"trace_{safe_name}_{target.line}.json"
            )

            try:
                orchestrator = TraceOrchestrator(config)

                # Reuse shared graph if we already built it
                if shared_graph is not None:
                    orchestrator.graph = shared_graph
                    orchestrator.language = shared_language
                    # Run pipeline skipping graph extraction
                    output = orchestrator.run_with_existing_graph()
                else:
                    output = orchestrator.run()
                    # Cache the graph for subsequent targets
                    shared_graph = orchestrator.graph
                    shared_language = orchestrator.language

                batch_output.results.append(output)
                batch_output.successful += 1

                logger.info(
                    "  Found %d paths for %s",
                    len(output.paths), target_str,
                )

            except Exception as exc:
                logger.error("  Failed to trace %s: %s", target_str, exc)
                batch_output.failed += 1
                batch_output.errors.append({
                    "target": target_str,
                    "error": str(exc),
                })

        elapsed = time.time() - t0
        batch_output.metadata = {
            "elapsed_seconds": round(elapsed, 2),
            "avg_seconds_per_target": round(elapsed / max(len(targets), 1), 2),
        }

        logger.info(
            "Batch complete: %d/%d succeeded in %.1fs",
            batch_output.successful, batch_output.total_targets, elapsed,
        )

        return batch_output

    def write_batch_output(self, output: BatchOutput, out_path: str) -> None:
        """Write aggregated batch output to JSON."""
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        raw = orjson.dumps(
            output.model_dump(),
            option=orjson.OPT_INDENT_2 | orjson.OPT_SERIALIZE_NUMPY,
        )
        Path(out_path).write_bytes(raw)
        logger.info("Batch output written to %s (%d bytes)", out_path, len(raw))

#src\deeptrace\core\graph_builder.py
"""Graph builder: merges backends into a unified dependency graph."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

import networkx as nx

from deeptrace.models.config import DeeptraceConfig
from deeptrace.models.graph import (
    BackendKind,
    EdgeKind,
    GraphEdge,
    GraphNode,
    NodeKind,
    SourceLocation,
)

logger = logging.getLogger(__name__)


class DependencyGraph:
    """Unified dependency graph backed by NetworkX DiGraph."""

    def __init__(self) -> None:
        self.g: nx.DiGraph = nx.DiGraph()
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []
        self._location_index: dict[str, list[str]] = defaultdict(list)  # "file:line" -> [node_ids]
        # Interprocedural indices (built lazily)
        self._scope_index: dict[str, set[str]] | None = None   # "file:func" → {node_ids inside func}
        self._callers_of: dict[str, set[str]] | None = None    # func_name → {call_site_node_ids}

    @property
    def node_count(self) -> int:
        return self.g.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self.g.number_of_edges()

    # -----------------------------------------------------------------------
    # Building
    # -----------------------------------------------------------------------

    def add_nodes(self, nodes: list[GraphNode]) -> None:
        for node in nodes:
            if node.id in self._nodes:
                existing = self._nodes[node.id]
                merged_props = {**existing.properties, **node.properties}

                if node.backend == BackendKind.JOERN and existing.backend == BackendKind.TREESITTER:
                    node.properties = merged_props
                    self._nodes[node.id] = node
                    self.g.nodes[node.id].update(self._node_attrs(node))
                else:
                    existing.properties = merged_props
                continue

            self._nodes[node.id] = node
            self.g.add_node(node.id, **self._node_attrs(node))

            if node.location:
                norm_file = node.location.file.replace("\\", "/")
                key = f"{norm_file}:{node.location.line}"
                self._location_index[key].append(node.id)

    def add_edges(self, edges: list[GraphEdge]) -> None:
        for edge in edges:
            # Ensure endpoints exist
            if edge.src not in self._nodes:
                self._nodes[edge.src] = GraphNode(id=edge.src)
                self.g.add_node(edge.src)
            if edge.dst not in self._nodes:
                self._nodes[edge.dst] = GraphNode(id=edge.dst)
                self.g.add_node(edge.dst)

            # Prefer Joern edges over tree-sitter
            if self.g.has_edge(edge.src, edge.dst):
                existing_backend = self.g.edges[edge.src, edge.dst].get("backend", "")
                if existing_backend == BackendKind.JOERN.value and edge.backend == BackendKind.TREESITTER:
                    continue

            self.g.add_edge(edge.src, edge.dst, **self._edge_attrs(edge))
            self._edges.append(edge)

    def build_interprocedural_edges(self) -> int:
        """Add synthetic edges for interprocedural tracing and intra-function flow.

        Creates two types of edges:
        1. CALLER → first body node: enables backward BFS to jump to callers
        2. Sequential backbone within each function: links adjacent nodes by
           line number so BFS can traverse across different variable names.

        Returns the number of synthetic edges added.
        """
        self._build_interprocedural_index()
        if not self._scope_index or not self._callers_of:
            return 0

        added = 0

        for scope_key, body_node_ids in self._scope_index.items():
            if len(body_node_ids) < 2:
                continue

            file_path, func_name = scope_key.rsplit(":", 1)

            # Sort body nodes by line number
            body_sorted = sorted(
                body_node_ids,
                key=lambda nid: (self._nodes[nid].location.line if self._nodes[nid].location else 9999),
            )

            # --- Sequential backbone ---
            # Link adjacent nodes (sorted by line) within the function.
            # Direction: earlier → later (so BFS backward from later reaches earlier).
            prev_nid = body_sorted[0]
            backbone_count = 0
            MAX_BACKBONE_PER_FUNC = 300  # cap to avoid explosion in huge functions

            for nid in body_sorted[1:]:
                if backbone_count >= MAX_BACKBONE_PER_FUNC:
                    break
                if prev_nid == nid:
                    continue
                if not self.g.has_edge(prev_nid, nid):
                    self.g.add_edge(prev_nid, nid,
                                    kind=EdgeKind.DATA_FLOW.value,
                                    weight=0.5,
                                    backend=BackendKind.TREESITTER.value)
                    self._edges.append(GraphEdge(
                        src=prev_nid, dst=nid,
                        kind=EdgeKind.DATA_FLOW, weight=0.5,
                        backend=BackendKind.TREESITTER,
                    ))
                    added += 1
                    backbone_count += 1
                prev_nid = nid

            # --- Interprocedural: callers → first body node ---
            callers = self._callers_of.get(func_name, set())
            if not callers:
                continue
            def_node_id = body_sorted[0]
            for caller_id in callers:
                if not self.g.has_edge(caller_id, def_node_id):
                    self.g.add_edge(caller_id, def_node_id,
                                    kind=EdgeKind.CALL.value,
                                    weight=1.5,
                                    backend=BackendKind.TREESITTER.value)
                    self._edges.append(GraphEdge(
                        src=caller_id, dst=def_node_id,
                        kind=EdgeKind.CALL, weight=1.5,
                        backend=BackendKind.TREESITTER,
                    ))
                    added += 1

        if added:
            logger.info("Added %d interprocedural synthetic edges", added)
        return added

    @staticmethod
    def _node_attrs(node: GraphNode) -> dict[str, Any]:
        return {
            "kind": node.kind.value,
            "name": node.name,
            "file": node.location.file if node.location else "",
            "line": node.location.line if node.location else 0,
            "code": node.location.code_snippet if node.location else "",
            "backend": node.backend.value,
        }

    @staticmethod
    def _edge_attrs(edge: GraphEdge) -> dict[str, Any]:
        return {
            "kind": edge.kind.value,
            "weight": edge.weight,
            "backend": edge.backend.value,
        }

    # -----------------------------------------------------------------------
    # Queries
    # -----------------------------------------------------------------------

    def find_target_nodes(self, file_path: str, line: int) -> list[str]:
        """Find graph node IDs that correspond to the given file:line."""
        # Normalize to forward slashes for cross-platform consistency
        norm_path = file_path.replace("\\", "/").lstrip("./")
        key = f"{norm_path}:{line}"
        direct = self._location_index.get(key, [])
        if direct:
            return direct

        # Try with ./ prefix stripped from index keys too
        for loc_key, nids in self._location_index.items():
            loc_norm = loc_key.replace("\\", "/").lstrip("./")
            if loc_norm == key:
                return nids

        # Fuzzy: match any index key whose file path ends with the target path
        results: list[str] = []
        for loc_key, nids in self._location_index.items():
            loc_norm = loc_key.replace("\\", "/")
            if loc_norm.endswith(f"{norm_path}:{line}"):
                results.extend(nids)
        if results:
            return results

        # Last resort: match just the filename
        tail = norm_path.split("/")[-1]
        for loc_key, nids in self._location_index.items():
            if loc_key.endswith(f"{tail}:{line}"):
                results.extend(nids)
        return results

    def find_nodes_in_file(self, file_path: str, max_nodes: int = 200) -> list[str]:
        """Find ALL graph node IDs in a given file (any line).

        Used as a fallback when --source file:line doesn't match a specific
        line (e.g., line 1 is a comment, or line 0 means "anywhere in file").

        Returns node IDs sorted by line number (earliest first).
        """
        norm_path = file_path.replace("\\", "/").lstrip("./")
        tail = norm_path.split("/")[-1]

        results: list[tuple[int, str]] = []  # (line, node_id)

        for loc_key, nids in self._location_index.items():
            loc_norm = loc_key.replace("\\", "/").lstrip("./")
            # Match full path or suffix
            # loc_key is "file:line", extract file part
            parts = loc_norm.rsplit(":", 1)
            if len(parts) != 2:
                continue
            loc_file = parts[0]
            try:
                loc_line = int(parts[1])
            except ValueError:
                continue

            if loc_file == norm_path or loc_file.endswith(f"/{norm_path}") or loc_file.endswith(f"/{tail}"):
                for nid in nids:
                    results.append((loc_line, nid))

        # Sort by line number and cap
        results.sort(key=lambda x: x[0])
        return [nid for _, nid in results[:max_nodes]]

    def predecessors(self, node_id: str) -> list[str]:
        """Get predecessor node IDs (backward direction)."""
        if node_id not in self.g:
            return []
        return list(self.g.predecessors(node_id))

    def successors(self, node_id: str) -> list[str]:
        """Get successor node IDs (forward direction)."""
        if node_id not in self.g:
            return []
        return list(self.g.successors(node_id))

    def get_node(self, node_id: str) -> GraphNode | None:
        return self._nodes.get(node_id)

    def get_edge_data(self, src: str, dst: str) -> dict[str, Any] | None:
        if self.g.has_edge(src, dst):
            return dict(self.g.edges[src, dst])
        return None

    def all_nodes(self) -> list[GraphNode]:
        return list(self._nodes.values())

    def all_edges(self) -> list[GraphEdge]:
        return list(self._edges)

    def subgraph_around(self, targets: list[str], max_depth: int = 30) -> set[str]:
        """BFS backward from targets up to max_depth. Returns reachable node IDs.

        Includes interprocedural jumps: when visiting a node inside function F,
        also adds callers of F to the frontier (enabling cross-function tracing).
        """
        self._build_interprocedural_index()

        visited: set[str] = set()
        frontier: list[str] = list(targets)
        depth = 0

        while frontier and depth < max_depth:
            next_frontier: list[str] = []
            for nid in frontier:
                if nid in visited:
                    continue
                visited.add(nid)
                # Standard backward traversal
                next_frontier.extend(self.predecessors(nid))
                # Interprocedural jump: if this node is inside a function,
                # also reach the callers of that function
                next_frontier.extend(self._interprocedural_predecessors(nid))
            frontier = next_frontier
            depth += 1

        return visited

    def _build_interprocedural_index(self) -> None:
        """Build indices for interprocedural backward tracing.

        Creates:
          _scope_index: "file:func_name" → {node_ids inside that function}
          _callers_of: "func_name" → {call_site node_ids that call it}
        """
        if self._scope_index is not None:
            return  # already built

        self._scope_index = defaultdict(set)
        self._callers_of = defaultdict(set)

        for nid, node in self._nodes.items():
            scope = node.properties.get("scope", "")
            if scope and node.location:
                scope_key = f"{node.location.file}:{scope}"
                self._scope_index[scope_key].add(nid)

            # Build callers index from CALL edges
            if node.kind == NodeKind.CALL_SITE and node.name:
                # This node calls `node.name` — record it as a caller
                self._callers_of[node.name].add(nid)

        logger.debug(
            "Interprocedural index: %d scoped functions, %d callable names",
            len(self._scope_index), len(self._callers_of),
        )

    def _interprocedural_predecessors(self, node_id: str) -> list[str]:
        """Get call sites that call the function containing this node.

        This enables backward tracing to "jump up" from a node inside function F
        to the call sites that invoke F, achieving interprocedural analysis.
        """
        if not self._scope_index or not self._callers_of:
            return []

        node = self._nodes.get(node_id)
        if not node or not node.location:
            return []

        scope = node.properties.get("scope", "")
        if not scope:
            return []

        # Find all call sites that call this function
        callers = self._callers_of.get(scope, set())
        if not callers:
            return []

        return list(callers)

    def fan_out(self, node_id: str) -> int:
        """Number of predecessors (backward fan-out for trace exploration).
        Includes interprocedural predecessors."""
        direct = len(self.predecessors(node_id))
        interproc = len(self._interprocedural_predecessors(node_id))
        return direct + interproc

    # -----------------------------------------------------------------------
    # Enumeration for small graphs
    # -----------------------------------------------------------------------

    def enumerate_all_simple_paths(
        self,
        targets: list[str],
        sources: list[str] | None = None,
        max_depth: int = 50,
    ) -> list[list[str]]:
        """Enumerate all simple paths if graph is small enough."""
        if sources is None:
            # Sources are nodes with no predecessors in the subgraph
            reachable = self.subgraph_around(targets, max_depth)
            sources = [
                nid for nid in reachable
                if not any(p in reachable for p in self.predecessors(nid))
            ]

        all_paths: list[list[str]] = []
        reversed_g = self.g.reverse()
        for target in targets:
            for source in sources:
                if source == target:
                    continue
                try:
                    for path in nx.all_simple_paths(reversed_g, target, source, cutoff=max_depth):
                        all_paths.append(list(reversed(path)))  # reverse to get source→target
                except nx.NetworkXError:
                    continue

        return all_paths

    # -----------------------------------------------------------------------
    # Edge weight computation for ACO heuristic
    # -----------------------------------------------------------------------

    def compute_heuristic_weights(self) -> None:
        """Compute edge weights based on edge type and structural properties."""
        for u, v, data in self.g.edges(data=True):
            kind = data.get("kind", "unknown")
            backend = data.get("backend", "")

            # Base weight by edge type (lower = more valuable for tracing)
            kind_weights = {
                EdgeKind.DATA_FLOW.value: 1.0,
                EdgeKind.PARAM_PASS.value: 1.0,
                EdgeKind.RETURN.value: 1.2,
                EdgeKind.CALL.value: 1.5,
                EdgeKind.FIELD_ACCESS.value: 1.3,
                EdgeKind.POINTER_DEREF.value: 0.8,  # pointer flows are interesting
                EdgeKind.ALIAS.value: 0.9,
                EdgeKind.TYPE_CAST.value: 1.8,
                EdgeKind.CONTROL_DEP.value: 2.0,
                EdgeKind.TREESITTER.value: 2.5,      # lower confidence
            }

            w = kind_weights.get(kind, 2.0)

            # Penalize tree-sitter-only edges slightly
            if backend == BackendKind.TREESITTER.value:
                w *= 1.3

            # Prefer edges going to nodes with more context / code
            dst_node = self._nodes.get(v)
            if dst_node and dst_node.location and dst_node.location.code_snippet:
                w *= 0.9  # slight bonus for having code

            self.g.edges[u, v]["weight"] = w

    # -----------------------------------------------------------------------
    # Serialization
    # -----------------------------------------------------------------------

    def to_serializable(self) -> dict[str, Any]:
        return {
            "nodes": [n.model_dump() for n in self._nodes.values()],
            "edges": [e.model_dump() for e in self._edges],
            "node_count": self.node_count,
            "edge_count": self.edge_count,
        }
#src\deeptrace\core\orchestrator.py
"""Orchestrator: ties together backends, graph building, ACO, and LLM ranking."""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any, Callable

import orjson

from deeptrace.backends.dynamic_resolver import DynamicResolver
from deeptrace.analysis.llm_ranker import LLMRanker
from deeptrace.backends.joern import (
    JoernBackend,
    detect_language,
    flows_to_graph,
    is_joern_primary,
)
from deeptrace.backends.treesitter import TreeSitterBackend
from deeptrace.core.aco import ACOExplorer
from deeptrace.core.graph_builder import DependencyGraph
from deeptrace.core.session import SessionManager
from deeptrace.models.config import DeeptraceConfig
from deeptrace.models.graph import (
    Language,
    TraceOutput,
    TracePath,
    TraceStep,
    BranchPoint,
    BackendKind,
    NodeKind,
    SourceLocation,
)

logger = logging.getLogger(__name__)


class TraceOrchestrator:
    """Main orchestrator for the deeptrace pipeline."""

    def __init__(self, config: DeeptraceConfig) -> None:
        self.config = config
        self.graph = DependencyGraph()
        self.language: Language | None = None
        self.joern: JoernBackend | None = None
        self.treesitter: TreeSitterBackend | None = None
        self.llm_ranker: LLMRanker | None = None
        self.session_mgr: SessionManager | None = None
        self._aco_explorer: ACOExplorer | None = None
        self.dynamic_resolver = DynamicResolver(self.config.repo, self.config.llm)

        # Parse sink (target)
        normalized_target = config.target.replace("\\", "/")
        parts = normalized_target.rsplit(":", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid target format '{config.target}'. Expected file:line")
        self.target_file = parts[0]
        self.target_line = int(parts[1])

        # Parse source (optional)
        self.source_file: str | None = None
        self.source_line: int | None = None
        if config.source:
            normalized_source = config.source.replace("\\", "/")
            src_parts = normalized_source.rsplit(":", 1)
            if len(src_parts) == 2:
                self.source_file = src_parts[0]
                self.source_line = int(src_parts[1])
                logger.info("Source-sink mode: %s -> %s", config.source, config.target)

    # -----------------------------------------------------------------------
    # Pipeline stages
    # -----------------------------------------------------------------------

    def run(
        self,
        progress_callback: Callable[[str, float], None] | None = None,
    ) -> TraceOutput:
        """Execute the full trace pipeline."""
        t0 = time.time()

        def _progress(stage: str, pct: float) -> None:
            if progress_callback:
                progress_callback(stage, pct)

        # 1. Detect language
        _progress("detecting_language", 0.0)
        self.language = self._detect_language()
        logger.info("Detected language: %s", self.language)

        # 2. Initialize session
        self._init_session()

        # 3. Extract graph from backends
        _progress("extracting_graph", 0.1)
        self._extract_graph()

        # 4-11: Run analysis on the built graph
        return self._run_analysis(t0, _progress)

    def run_with_existing_graph(
        self,
        progress_callback: Callable[[str, float], None] | None = None,
    ) -> TraceOutput:
        """Run pipeline reusing an already-built graph (for batch mode)."""
        t0 = time.time()

        def _progress(stage: str, pct: float) -> None:
            if progress_callback:
                progress_callback(stage, pct)

        if not self.language:
            self.language = self._detect_language()

        self._init_session()
        return self._run_analysis(t0, _progress)

    def _run_analysis(
        self,
        t0: float,
        _progress: Callable[[str, float], None],
    ) -> TraceOutput:
        """Core analysis: target finding, path exploration, Z3, LLM."""

        # 4. Find sink (target) nodes
        _progress("finding_target", 0.4)
        targets = self.graph.find_target_nodes(self.target_file, self.target_line)
        if not targets:
            logger.error("No nodes found for target %s:%d", self.target_file, self.target_line)
            sample_keys = list(self.graph._location_index.keys())[:10]
            if sample_keys:
                logger.error("Sample indexed paths: %s", sample_keys)
            raise ValueError(
                f"Target {self.target_file}:{self.target_line} not found in the graph. "
                "Check the file path is relative to the repo root."
            )
        logger.info("Found %d sink node(s)", len(targets))

        for tid in targets[:5]:
            tnode = self.graph.get_node(tid)
            if tnode:
                scope = tnode.properties.get("scope", "?")
                preds = self.graph.predecessors(tid)
                interproc = self.graph._interprocedural_predecessors(tid)
                logger.info("  Sink %s (scope=%s) → %d preds, %d interproc preds",
                           tid[:80], scope, len(preds), len(interproc))

        # 4b. Find source nodes (if source-sink mode)
        source_nodes: list[str] | None = None
        if self.source_file and self.source_line:
            source_nodes = self.graph.find_target_nodes(self.source_file, self.source_line)
            if source_nodes:
                logger.info("Found %d source node(s)", len(source_nodes))
            else:
                logger.warning(
                    "Source %s:%d not found in graph -- falling back to unrestricted backward trace",
                    self.source_file, self.source_line,
                )

        # 5. Explore paths (Raw AST paths)
        _progress("exploring_paths", 0.5)
        paths = self._explore_paths(targets, source_nodes=source_nodes)
        logger.info("Found %d raw paths", len(paths))

        # 6. Z3 constraint checking (Operates on RAW paths to preserve math semantics)
        _progress("z3_checking", 0.65)
        paths = self._z3_check(paths)

        paths = self._enforce_diversity(paths)

        # 6.5 Collapse to Statement-Level Flows
        _progress("collapsing_statements", 0.70)
        paths = self._collapse_to_statements(paths)

        # 7. LLM ranking + node annotation + vulnerability summary (Operates on CLEAN paths)
        _progress("llm_ranking", 0.75)
        paths = self._llm_rank(paths)

        # 8. Final sort: SAT first, then by LLM rank, then by score
        paths = self._final_sort(paths)

        # 9. Handle branch points
        branch_points: list[BranchPoint] = []
        if self._aco_explorer:
            branch_points = self._aco_explorer.branch_points
            if self.session_mgr:
                self.session_mgr.add_branch_points(branch_points)
                self.session_mgr.add_completed_paths(paths)

        # 10. Build output — only include REACHABLE nodes/edges
        _progress("building_output", 0.95)
        elapsed = time.time() - t0

        path_node_ids: set[str] = set()
        for p in paths:
            for step in p.steps:
                path_node_ids.add(step.node_id)

        reachable_ids = self.graph.subgraph_around(targets, self.config.max_depth)
        relevant_ids = path_node_ids | reachable_ids

        relevant_nodes = [n for n in self.graph.all_nodes() if n.id in relevant_ids]
        relevant_edges = [e for e in self.graph.all_edges()
                          if e.src in relevant_ids and e.dst in relevant_ids]

        logger.info("Output: %d/%d relevant nodes, %d/%d relevant edges",
                     len(relevant_nodes), self.graph.node_count,
                     len(relevant_edges), self.graph.edge_count)

        output = TraceOutput(
            target=self.config.target,
            source=self.config.source,
            repo=self.config.repo,
            language=self.language,
            node_count=self.graph.node_count,
            edge_count=self.graph.edge_count,
            nodes=relevant_nodes,
            edges=relevant_edges,
            paths=paths,
            session=(self.session_mgr.session if self.session_mgr else None),
            metadata={
                "elapsed_seconds": round(elapsed, 2),
                "branch_points_detected": len(branch_points),
                "source_sink_mode": bool(source_nodes),
                "z3_enabled": self.config.z3.enabled,
                "aco_config": self.config.aco.model_dump(),
                "reachable_nodes": len(relevant_ids),
                "total_graph_nodes": self.graph.node_count,
                "total_graph_edges": self.graph.edge_count,
            },
        )

        # 11. Write output
        self._write_output(output)

        _progress("done", 1.0)
        logger.info("Trace complete in %.1fs", elapsed)

        return output

    # -----------------------------------------------------------------------
    # Internal stages
    # -----------------------------------------------------------------------

    def _detect_language(self) -> Language | None:
        if self.config.language:
            try:
                return Language(self.config.language)
            except ValueError:
                logger.warning("Unknown language '%s', auto-detecting", self.config.language)
        return detect_language(self.target_file)

    def _init_session(self) -> None:
        if self.config.session_file or self.config.interactive:
            sf = self.config.session_file or f"deeptrace_session_{os.getpid()}.json"
            self.session_mgr = SessionManager(sf)
            existing = self.session_mgr.load()
            if not existing:
                self.session_mgr.create(self.config.repo, self.config.target)

    def _extract_graph(self) -> None:
        """Extract dependency graph across all supported languages."""
        joern_nodes = []
        joern_edges = []
        target_scope = ""

        # Supported languages to scan for multi-language FFI bridging
        target_languages = [
            Language.C, Language.CPP, Language.RUST,
            Language.JAVA, Language.KOTLIN, Language.PYTHON,
            Language.SWIFT, Language.OBJC
        ]

        # 1. Tree-sitter Universal Pass (Ingest ALL languages into one graph)
        if self.config.treesitter.enabled:
            self.treesitter = TreeSitterBackend(self.config.treesitter, self.config.repo)

            # Scout the target method using the primary language
            if self.language:
                target_scope = self.treesitter.get_enclosing_function_name(
                    self.target_file, self.language, self.target_line
                ) or ""
                if target_scope:
                    logger.info("Tree-sitter identified target scope in %s: %s", self.language.value, target_scope)
                else:
                    logger.warning("Tree-sitter could not identify enclosing scope for %s:%d", self.target_file,
                                   self.target_line)

            # Extract graphs for ALL languages
            for lang in target_languages:
                try:
                    ts_nodes, ts_edges = self.treesitter.extract_edges_for_repo(
                        lang,
                        target_file=self.target_file if lang == self.language else None,
                        max_files=1000  # Throttle to prevent massive multi-language repos from OOMing
                    )
                    if ts_nodes:
                        self.graph.add_nodes(ts_nodes)
                        self.graph.add_edges(ts_edges)
                        logger.info("tree-sitter merged %d nodes, %d edges from %s", len(ts_nodes), len(ts_edges),
                                    lang.value)
                except Exception as exc:
                    logger.debug("Skipped or failed parsing language %s: %s", lang.value, exc)

        # 2. Joern Extraction (Target language only to save time)
        if self.language and is_joern_primary(self.language):
            try:
                self.joern = JoernBackend(self.config.joern, self.config.repo)
                self.joern.generate_cpg(self.language)

                flows = self.joern.extract_backward_flows(
                    self.target_file,
                    self.target_line,
                    self.config.max_flows,
                    target_method=target_scope  # PASS THE SCOUTED SCOPE
                )
                call_edges = self.joern.extract_call_graph(max_edges=2000)
                joern_nodes, joern_edges = flows_to_graph(flows, call_edges)

                self.graph.add_nodes(joern_nodes)
                self.graph.add_edges(joern_edges)
                logger.info("Joern merged %d nodes, %d edges into unified graph", len(joern_nodes), len(joern_edges))

            except Exception as exc:
                logger.warning("Joern extraction failed, falling back to tree-sitter: %s", exc)
            finally:
                if self.joern:
                    self.joern.cleanup()

        # 3. Build synthetic bridges (This will trigger DynamicResolver for FFI)
        interproc_count = self.graph.build_interprocedural_edges()

        logger.info("Universal Graph: %d nodes, %d edges (incl. %d interprocedural)",
                    self.graph.node_count, self.graph.edge_count, interproc_count)

        self._verify_completeness()

        if self.graph.node_count == 0:
            raise RuntimeError("No dependency graph could be extracted across any language.")


    def _explore_paths(
        self,
        targets: list[str],
        source_nodes: list[str] | None = None,
    ) -> list[TracePath]:
        """Run ACO explorer to find paths."""

        # Source-sink mode
        if source_nodes:
            return self._explore_source_sink(targets, source_nodes)

        reachable = self.graph.subgraph_around(targets, self.config.max_depth)
        logger.info("Backward BFS from %d sinks: %d reachable nodes (depth=%d)",
                     len(targets), len(reachable), self.config.max_depth)

        # HARD FIX: Exact enumeration disabled to force ACO scaling across files
        if False:
            logger.info("Small graph, attempting exact enumeration")
            all_paths_raw = self.graph.enumerate_all_simple_paths(
                targets, max_depth=self.config.max_depth,
            )
            if all_paths_raw:
                paths = self._raw_paths_to_trace(all_paths_raw)
                paths.sort(key=lambda p: p.score, reverse=True)
                return paths[:self.config.topk]

        # ACO exploration
        self._aco_explorer = ACOExplorer(
            self.graph,
            self.config.aco,
            self.config.branching,
            dynamic_resolver=self.dynamic_resolver,
            z3_enabled=self.config.z3.enabled
        )
        return self._aco_explorer.explore(
            targets=targets,
            max_depth=self.config.max_depth,
            topk=self.config.topk,
        )

    def _explore_source_sink(
            self,
            sink_nodes: list[str],
            source_nodes: list[str],
        ) -> list[TracePath]:
        """Find paths that connect source -> sink, or fallback to proximity near-misses."""
        backward = self.graph.subgraph_around(sink_nodes, self.config.max_depth)
        forward = self._forward_reachable(source_nodes, self.config.max_depth)

        intersection = backward & forward

        # 1. STRICT INTERSECTION (The graph is unbroken)
        if intersection:
            logger.info("Source-sink intersection: %d nodes", len(intersection))

            reachable_sources = [s for s in source_nodes if s in intersection]
            if not reachable_sources:
                reachable_sources = [
                    nid for nid in intersection
                    if not any(p in intersection for p in self.graph.predecessors(nid))
                ]

            self._aco_explorer = ACOExplorer(
                self.graph, self.config.aco, self.config.branching,
                dynamic_resolver=self.dynamic_resolver, z3_enabled=self.config.z3.enabled
            )
            paths = self._aco_explorer.explore(
                targets=sink_nodes,
                max_depth=self.config.max_depth,
                topk=self.config.topk,
                reachable_override=intersection,
            )

            if reachable_sources:
                source_set = set(reachable_sources)
                source_paths = [
                    p for p in paths
                    if any(step.node_id in source_set for step in p.steps)
                ]
                if source_paths:
                    return source_paths
            return paths

        # 2. GAP ANALYSIS (The graph is broken, find the closest near-miss)
        logger.warning("No unbroken graph path connects source to sink. Initiating Proximity Gap Analysis.")

        # Run an unconstrained backward trace from the sink
        paths = self._explore_paths(sink_nodes, source_nodes=None)

        # Extract valid source locations for distance math
        source_locs = []
        for nid in source_nodes:
            node = self.graph.get_node(nid)
            if node and node.location:
                source_locs.append(node.location)

        if not source_locs or not paths:
            return paths

        # Calculate physical distance from the trace's endpoint to the requested source
        def calculate_distance(path: TracePath) -> tuple[int, int]:
            if not path.steps:
                return (9999, 9999)

            endpoint = path.steps[-1]
            if not endpoint.location:
                return (9999, 9999)

            best_file_match = 1  # 0 = exact file match, 1 = different file
            best_line_dist = 99999

            for sloc in source_locs:
                if sloc.file == endpoint.location.file:
                    dist = abs(sloc.line - endpoint.location.line)
                    if best_file_match == 1 or dist < best_line_dist:
                        best_file_match = 0
                        best_line_dist = dist
                else:
                    # Penalize cross-file misses, but keep a baseline to differentiate them
                    if best_file_match == 1:
                        best_line_dist = min(best_line_dist, 50000)

            return (best_file_match, best_line_dist)

        # Sort paths: 1) Same File First -> 2) Closest Line Number -> 3) Highest ACO Score
        paths.sort(key=lambda p: (*calculate_distance(p), -p.score))

        # Tag the paths so the LLM and the UI know this is a broken chain
        for p in paths:
            p.vulnerability_tags.append("near_miss_gap")

        logger.info("Proximity Analysis: Reranked fallback paths based on physical distance to source.")

        # We return a slightly larger pool so the diversity filter doesn't starve the output
        return paths[:self.config.topk * 2]

    def _forward_reachable(self, sources: list[str], max_depth: int) -> set[str]:
        """BFS forward from source nodes up to max_depth."""
        visited: set[str] = set()
        frontier: list[str] = list(sources)
        depth = 0
        while frontier and depth < max_depth:
            next_frontier: list[str] = []
            for nid in frontier:
                if nid in visited:
                    continue
                visited.add(nid)
                next_frontier.extend(self.graph.successors(nid))
            frontier = next_frontier
            depth += 1
        return visited

    def _raw_paths_to_trace(self, raw_paths: list[list[str]]) -> list[TracePath]:
        """Convert raw node-ID paths into TracePath objects."""
        temp_aco = ACOExplorer(self.graph, self.config.aco)

        results: list[TracePath] = []
        for node_ids in raw_paths:
            steps = []
            for i, nid in enumerate(node_ids):
                node = self.graph.get_node(nid)
                edge_kind = None
                if i > 0:
                    edge_data = self.graph.get_edge_data(node_ids[i - 1], nid)
                    if edge_data:
                        from deeptrace.models.graph import EdgeKind
                        edge_kind = EdgeKind(edge_data.get("kind", "unknown"))

                steps.append(TraceStep(
                    node_id=nid,
                    location=node.location if node else None,
                    edge_kind=edge_kind,
                    code_snippet=node.location.code_snippet if node and node.location else "",
                    node_kind=node.kind if node else None,
                    node_name=node.name if node else "",
                ))

            score = temp_aco._score_path(steps)
            results.append(TracePath(steps=steps, score=score))

        return results

    def _collapse_to_statements(self, paths: list[TracePath]) -> list[TracePath]:
        """Squashes granular AST/CPG nodes into single statement-level flows per line."""
        for path in paths:
            if not path.steps:
                continue

            collapsed_steps = []
            current_line = None
            current_file = None
            snippet = ""
            accumulated_names = set()
            last_step = None
            first_edge_kind = None

            for step in path.steps:
                loc = step.location
                if not loc:
                    collapsed_steps.append(step)
                    continue

                if loc.line != current_line or loc.file != current_file:
                    if current_line is not None and last_step is not None:
                        collapsed_steps.append(TraceStep(
                            node_id=last_step.node_id,
                            location=SourceLocation(file=current_file, line=current_line, code_snippet=snippet),
                            edge_kind=first_edge_kind,
                            code_snippet=snippet,
                            node_kind=last_step.node_kind,
                            node_name=" | ".join(sorted(accumulated_names)) if accumulated_names else last_step.node_name,
                            annotation=""
                        ))

                    current_line = loc.line
                    current_file = loc.file
                    snippet = loc.code_snippet
                    accumulated_names = {step.node_name} if step.node_name and len(step.node_name) > 2 else set()
                    first_edge_kind = step.edge_kind
                    last_step = step
                else:
                    if step.node_name and len(step.node_name) > 2:
                        accumulated_names.add(step.node_name)
                    last_step = step

            # Append the final line
            if current_line is not None and last_step is not None:
                collapsed_steps.append(TraceStep(
                    node_id=last_step.node_id,
                    location=SourceLocation(file=current_file, line=current_line, code_snippet=snippet),
                    edge_kind=first_edge_kind,
                    code_snippet=snippet,
                    node_kind=last_step.node_kind,
                    node_name=" | ".join(sorted(accumulated_names)) if accumulated_names else last_step.node_name,
                    annotation=""
                ))

            path.steps = collapsed_steps

        return paths

    def _z3_check(self, paths: list[TracePath]) -> list[TracePath]:
        """Check path satisfiability with Z3 if enabled."""
        if not self.config.z3.enabled:
            return paths
        try:
            from deeptrace.analysis.constraint_solver import check_paths_satisfiability
            return check_paths_satisfiability(paths, self.graph, self.config.z3)
        except Exception as exc:
            logger.warning("Z3 checking failed: %s", exc)
            return paths

    def _llm_rank(self, paths: list[TracePath]) -> list[TracePath]:
        """Apply LLM ranking, node annotation, and vulnerability summary."""
        if not self.config.llm.enabled:
            return paths

        try:
            self.llm_ranker = LLMRanker(self.config.llm)

            paths = self.llm_ranker.rank_paths(paths)
            paths = self.llm_ranker.annotate_path_nodes(paths)
            paths = self.llm_ranker.generate_vulnerability_summaries(
                paths, z3_available=self.config.z3.enabled,
            )

            if self.config.interactive and self.session_mgr:
                for bp in self.session_mgr.get_pending_branches():
                    self.llm_ranker.rank_branch_candidates(bp)

        except Exception as exc:
            logger.warning("LLM ranking failed (paths returned unranked): %s", exc)

        return paths

    def _final_sort(self, paths: list[TracePath]) -> list[TracePath]:
        """Final sort: SAT paths first, then by LLM rank, then by score."""
        def sort_key(p: TracePath) -> tuple:
            sat_order = 0 if p.is_satisfiable is True else (2 if p.is_satisfiable is False else 1)
            llm = p.llm_rank or 9999
            return (sat_order, llm, -p.score)

        if paths is not None:
            paths.sort(key=sort_key)
        return paths

    # -----------------------------------------------------------------------
    # Output
    # -----------------------------------------------------------------------

    def _write_output(self, output: TraceOutput) -> None:
        """Write trace output to file."""
        out_path = self.config.out
        try:
            Path(out_path).parent.mkdir(parents=True, exist_ok=True)
            raw = orjson.dumps(
                output.model_dump(),
                option=orjson.OPT_INDENT_2 | orjson.OPT_SERIALIZE_NUMPY,
            )
            Path(out_path).write_bytes(raw)
            logger.info("Output written to %s (%d bytes)", out_path, len(raw))
        except Exception as exc:
            logger.error("Failed to write output: %s", exc)
            raise

    def _verify_completeness(self) -> None:
        """Deterministically find parsing failures by diffing backends."""
        logger.info("Verifying backend completeness...")

        ts_functions = {
            node.name for node in self.graph._nodes.values()
            if node.backend == BackendKind.TREESITTER
               and node.kind == NodeKind.IDENTIFIER
               and node.properties.get("scope") == node.name
        }

        # Compare against ALL Joern-known symbol names (not just call-graph stubs)
        joern_known = {
            node.name for node in self.graph._nodes.values()
            if node.backend == BackendKind.JOERN and node.name
        }

        missing_in_joern = ts_functions - joern_known

        if missing_in_joern:
            logger.warning(
                "COMPLETENESS FAILURE: Joern dropped %d symbols defined in Tree-sitter.",
                len(missing_in_joern)
            )
            for missing in list(missing_in_joern)[:10]:
                logger.warning("  - Missing in Joern CPG: %s", missing)
            logger.warning("Downstream paths relying on these symbols will be broken.")
        else:
            logger.info("Completeness check passed. Joern CPG aligns with Tree-sitter AST.")

    def _enforce_diversity(self, paths: list[TracePath]) -> list[TracePath]:
        """Filters out path clones, strictly prioritizing SAT paths over UNSAT paths."""
        if not paths:
            return paths

        # Sort: SAT first, then UNKNOWN, then UNSAT. Break ties by ACO score.
        def sort_key(p: TracePath) -> tuple:
            sat_order = 0 if p.is_satisfiable is True else (2 if p.is_satisfiable is False else 1)
            return (sat_order, -p.score)

        paths.sort(key=sort_key)

        diverse_results: list[TracePath] = []
        accepted_endpoints: set[str] = set()
        JACCARD_THRESHOLD = 0.75  # Paths sharing > 75% of nodes are clones

        for path in paths:
            if len(diverse_results) >= self.config.topk:
                break

            if not path.steps:
                continue

            endpoint_id = path.steps[-1].node_id
            path_node_ids = {s.node_id for s in path.steps}

            is_new_endpoint = endpoint_id not in accepted_endpoints
            is_clone = False

            for accepted in diverse_results:
                accepted_ids = {s.node_id for s in accepted.steps}
                intersection = len(path_node_ids & accepted_ids)
                union = len(path_node_ids | accepted_ids)
                similarity = intersection / union if union > 0 else 0

                if similarity > JACCARD_THRESHOLD:
                    is_clone = True
                    break

            if is_new_endpoint or not is_clone:
                diverse_results.append(path)
                accepted_endpoints.add(endpoint_id)

        logger.info(
            "Diversity filter: Reduced %d raw paths to %d unique, SAT-prioritized paths",
            len(paths), len(diverse_results)
        )
        return diverse_results
#src\deeptrace\core\session.py
"""Session manager for interactive tracing with branch selection."""

from __future__ import annotations

import logging
import os
import time
import uuid
from pathlib import Path

import orjson

from deeptrace.models.graph import BranchPoint, TraceSession, TracePath

logger = logging.getLogger(__name__)


class SessionManager:
    """Manages persistent trace sessions with branch-point bookmarks."""

    def __init__(self, session_file: str = "") -> None:
        self.session_file = session_file
        self.session: TraceSession | None = None

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    def create(self, repo_path: str, target: str) -> TraceSession:
        """Create a new session."""
        self.session = TraceSession(
            session_id=uuid.uuid4().hex[:12],
            repo_path=repo_path,
            target=target,
        )
        if self.session_file:
            self._save()
        logger.info("Created session %s", self.session.session_id)
        return self.session

    def load(self) -> TraceSession | None:
        """Load an existing session from disk."""
        if not self.session_file or not os.path.exists(self.session_file):
            return None

        try:
            raw = Path(self.session_file).read_bytes()
            data = orjson.loads(raw)
            self.session = TraceSession.model_validate(data)
            logger.info(
                "Loaded session %s (%d completed paths, %d pending branches)",
                self.session.session_id,
                len(self.session.completed_paths),
                len(self.session.pending_branches),
            )
            return self.session
        except Exception as exc:
            logger.error("Failed to load session from %s: %s", self.session_file, exc)
            return None

    def _save(self) -> None:
        """Persist session to disk."""
        if not self.session or not self.session_file:
            return
        try:
            raw = orjson.dumps(
                self.session.model_dump(),
                option=orjson.OPT_INDENT_2,
            )
            Path(self.session_file).write_bytes(raw)
        except Exception as exc:
            logger.error("Failed to save session: %s", exc)

    # -----------------------------------------------------------------------
    # Branch management
    # -----------------------------------------------------------------------

    def add_branch_points(self, branch_points: list[BranchPoint]) -> None:
        """Register discovered branch points."""
        if not self.session:
            return
        for bp in branch_points:
            # Avoid duplicates
            if not any(existing.node_id == bp.node_id for existing in self.session.pending_branches):
                self.session.pending_branches.append(bp)
        self._save()

    def get_pending_branches(self) -> list[BranchPoint]:
        """Get all unresolved branch points."""
        if not self.session:
            return []
        return self.session.pending_branches

    def resolve_branch(self, node_id: str, chosen_index: int) -> BranchPoint | None:
        """Mark a branch point as resolved with the user's choice."""
        if not self.session:
            return None

        for i, bp in enumerate(self.session.pending_branches):
            if bp.node_id == node_id:
                bp.chosen_index = chosen_index
                bp.timestamp = time.time()
                self.session.resolved_branches.append(bp)
                self.session.pending_branches.pop(i)
                self._save()
                return bp
        return None

    def add_completed_paths(self, paths: list[TracePath]) -> None:
        """Add paths discovered in this run."""
        if not self.session:
            return
        self.session.completed_paths.extend(paths)
        self._save()

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------

    def summary(self) -> dict[str, int]:
        """Get session summary stats."""
        if not self.session:
            return {}
        return {
            "completed_paths": len(self.session.completed_paths),
            "pending_branches": len(self.session.pending_branches),
            "resolved_branches": len(self.session.resolved_branches),
        }

#src\deeptrace\exploit\agent.py
"""Interactive exploit agent: LLM in a loop with shell access.

The agent operates inside a Docker container with the target compiled with
ASAN.  It has access to gdb, cscope, grep, and can compile and run code.
It iterates — writing code, compiling, observing failures, adjusting —
until the exploit is verified or the budget is exhausted.

Architecture:
  1. System prompt sets the role and rules.
  2. Initial context provides: repo profile, vulnerability trace, source code
     near the sink, existing test/fuzz harnesses.
  3. Each turn: LLM emits actions in XML tags, we execute them in Docker,
     feed the results back.
  4. Verification: GDB breakpoint on the real sink function — the LLM
     can't fake this.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from deeptrace.exploit.docker_env import DockerEnv, ExecResult
from deeptrace.exploit.repo_analyzer import RepoProfile
from deeptrace.exploit.verification import verify_harness, VerificationResult
from deeptrace.models.graph import TracePath

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_ACTION_FORMAT_BLOCK = """
IMPORTANT: You communicate by emitting commands in <shell> tags. I execute them and show you the output. You MUST use these tags — I cannot read prose or markdown code blocks.

EXAMPLE TURN:

<shell>ls /src/ | head -20</shell>
<shell>find /src -name "README*" -o -name "BUILD*" -o -name "Makefile" | head -10</shell>

EXAMPLE: Writing a file:

<write_file path="/work/harness.cpp">
#include "public/fpdfview.h"
int main(int argc, char* argv[]) {
    FILE* f = fopen(argv[1], "rb");
    // ... real code here ...
}
</write_file>

EXAMPLE: Compiling:

<shell>g++ -fsanitize=address -g -I/src -I/src/public /work/harness.cpp -L/src/out/asan -lpdfium -o /work/harness 2>&1</shell>

RULES:
- Every response MUST contain at least one <shell> or <write_file> tag
- Do NOT write prose explanations — just emit commands
- To signal completion: <done reason="explanation here" />
"""

_EXPLORER_PROMPT = f"""You are a security researcher exploring a C/C++ repository inside a Docker container.
The target library source is at /src/. Your workspace is /work/.
{_ACTION_FORMAT_BLOCK}

YOUR TASK: Explore the repository and gather ALL information needed to write an exploit harness.

You need to find:
1. BUILD SYSTEM: How does this project compile? (CMake, Make, gn, Cargo, etc.)
   - Can you build it with the tools available? (g++, cmake, make are installed)
   - If not, which source files would need to be compiled directly?

2. PUBLIC API: Where are the public headers?
   - What functions are exposed? What are their signatures?
   - How do you initialize/cleanup the library?

3. EXISTING TESTS: Are there fuzz harnesses or test programs?
   - How do they call the library? What input format do they use?
   - What #includes and link flags do they use?

4. VULNERABILITY CONTEXT: The trace shows a path to the sink.
   - What functions are in the trace? How are they connected?
   - What input triggers this code path?

5. TEST DATA: Are there sample input files (PDFs, images, etc.)?

Be EFFICIENT. Don't repeat commands. Don't read entire files — use head/grep/sed.
After 3-5 turns of exploration, summarize what you've found with:
<done reason="EXPLORATION COMPLETE: [summary of findings]" />"""

_CODER_PROMPT = f"""You are an exploit developer with shell access to a Docker container.
The target library source is at /src/. Your workspace is /work/.
{_ACTION_FORMAT_BLOCK}

YOUR OBJECTIVE: Write a C/C++ harness that triggers a crash INSIDE the real library code.

You will receive an exploration summary from a prior analysis phase. Use it.

APPROACH:
1. Write /work/harness.cpp that calls REAL library functions via REAL headers
   - NO stubs, NO mocks, NO fake implementations
   - Read input from argv[1] (file on disk)
   - Use the existing fuzz harnesses/tests as reference

2. Compile it:
   - Try: g++ -fsanitize=address -g -std=c++17 -I/src -I/src/public harness.cpp ...
   - If linking fails, compile individual source files and link them
   - Check compilation errors and fix them — don't repeat the same broken command

3. Run it with a test input:
   - Find seed files in /src/testing/resources/ or create minimal ones
   - Check ASAN output: crash must be in LIBRARY code, not your harness

4. Iterate:
   - Compilation error → fix include paths or missing files
   - Crash in harness → fix your code
   - Crash in library → SUCCESS

Start your FIRST response by writing the harness based on the exploration summary."""

# Combined prompt for single-model mode (backward compatible)
_SYSTEM_PROMPT = f"""You are an exploit developer with shell access to a Docker container.
The target library source is at /src/. Your workspace is /work/.
{_ACTION_FORMAT_BLOCK}

YOUR OBJECTIVE: Trigger a crash INSIDE the real library code (not in your harness).

PHASE 1 — EXPLORE AND BUILD:
  - Start by exploring /src/ (ls, find, cat README, etc.)
  - Find how the project builds (CMake? Make? gn? Cargo?)
  - Build with ASAN flags or find pre-built ASAN binaries
  - If full build is too complex, compile just the trace-relevant source files

PHASE 2 — WRITE HARNESS:
  - Find public headers and existing test/fuzz harnesses in the repo
  - Write /work/harness.cpp that calls REAL library functions
  - NO stubs, NO mocks, NO fake implementations
  - Read input from argv[1] (file on disk)

PHASE 3 — TEST AND ITERATE:
  - Compile harness against the ASAN library
  - Find seed input files in /src/testing/ or /src/test/
  - Run and check ASAN output
  - If crash is in YOUR code → fix your harness
  - If crash is in LIBRARY code → SUCCESS

- Do NOT create stub/mock functions
- Start your FIRST response with: <shell>ls /src/ | head -30</shell>"""

# ---------------------------------------------------------------------------
# Action parsing
# ---------------------------------------------------------------------------

@dataclass
class AgentAction:
    """One parsed action from the LLM's response."""
    kind: str          # "shell", "write_file", "read_file", "done"
    content: str = ""  # command text, file content, or reason
    path: str = ""     # file path (for write_file/read_file)


def parse_actions(response: str) -> list[AgentAction]:
    """Parse actions from the LLM's response.

    Supports both XML tags (preferred) and markdown code blocks (fallback).
    Many LLMs default to markdown even when asked for XML, so we handle both.
    """
    actions: list[AgentAction] = []

    # === Priority 1: XML tags (the format we asked for) ===

    # <shell>command</shell>
    for m in re.finditer(r"<shell>(.*?)</shell>", response, re.DOTALL):
        cmd = m.group(1).strip()
        if cmd:
            actions.append(AgentAction(kind="shell", content=cmd))

    # <write_file path="...">content</write_file>
    for m in re.finditer(
        r'<write_file\s+path="([^"]+)">(.*?)</write_file>', response, re.DOTALL
    ):
        actions.append(AgentAction(kind="write_file", path=m.group(1), content=m.group(2)))

    # <read_file path="..." />
    for m in re.finditer(r'<read_file\s+path="([^"]+)"\s*/>', response):
        actions.append(AgentAction(kind="read_file", path=m.group(1)))

    # <done reason="..." /> or <done>reason</done>
    for m in re.finditer(r'<done\s+reason="([^"]*)"', response):
        actions.append(AgentAction(kind="done", content=m.group(1)))
    for m in re.finditer(r"<done>(.*?)</done>", response, re.DOTALL):
        if not any(a.kind == "done" for a in actions):
            actions.append(AgentAction(kind="done", content=m.group(1).strip()))

    # If XML parsing found actions, return them
    if actions:
        return actions

    # === Priority 2: Markdown code blocks (common LLM fallback) ===

    # ```bash ... ``` → shell action
    for m in re.finditer(r"```(?:bash|sh|shell)\s*\n([\s\S]*?)\n\s*```", response):
        block = m.group(1).strip()
        if not block:
            continue
        # Split multi-line shell blocks into individual commands
        # but keep multi-line commands (ending with \) together
        lines = block.split("\n")
        cmd_buffer = ""
        for line in lines:
            stripped = line.strip()
            # Skip comments and empty lines
            if not stripped or stripped.startswith("#"):
                continue
            cmd_buffer += (" " if cmd_buffer else "") + stripped
            if not stripped.endswith("\\"):
                actions.append(AgentAction(kind="shell", content=cmd_buffer))
                cmd_buffer = ""
        if cmd_buffer:
            actions.append(AgentAction(kind="shell", content=cmd_buffer))

    # ```cpp ... ``` or ```c ... ``` → write_file if it looks like a complete file
    for m in re.finditer(r"```(?:cpp|c\+\+|c)\s*\n([\s\S]*?)\n\s*```", response):
        code = m.group(1).strip()
        if "#include" in code and ("int main" in code or "LLVMFuzzerTestOneInput" in code):
            # Looks like a complete harness file
            # Try to find a filename hint nearby
            before = response[max(0, m.start() - 200):m.start()]
            fname_match = re.search(r'(/work/\S+\.(?:cpp|c|cc))', before)
            path = fname_match.group(1) if fname_match else "/work/harness.cpp"
            actions.append(AgentAction(kind="write_file", path=path, content=code))

    # === Priority 3: Bare shell commands (lines starting with $ or common commands) ===
    if not actions:
        for line in response.split("\n"):
            stripped = line.strip()
            # Lines starting with $ (shell prompt)
            if stripped.startswith("$ "):
                cmd = stripped[2:].strip()
                if cmd:
                    actions.append(AgentAction(kind="shell", content=cmd))
            # Common exploration commands without $ prefix
            elif re.match(r'^(ls |cat |grep |find |head |tail |cd |pwd|echo |mkdir |cp |make |g\+\+|gcc |clang|ninja |cmake )', stripped):
                actions.append(AgentAction(kind="shell", content=stripped))

    return actions


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

@dataclass
class AgentConfig:
    """Configuration for the exploit agent."""
    max_turns: int = 40             # maximum LLM turns
    max_actions_per_turn: int = 10  # cap actions parsed per turn
    exec_timeout: int = 60          # per-command timeout
    verify_timeout: int = 30        # verification run timeout
    context_window: int = 12        # keep last N exchanges in context


@dataclass
class AgentResult:
    """Final result of the agent run."""
    success: bool = False
    verification: VerificationResult | None = None
    turns_used: int = 0
    total_actions: int = 0
    elapsed_seconds: float = 0.0
    harness_path: str = ""
    input_path: str = ""
    final_reason: str = ""
    log: list[dict[str, str]] = field(default_factory=list)  # conversation log


class ExploitAgent:
    """Interactive exploit agent that drives an LLM in a tool-use loop.

    Supports two operating modes:

    **Single-model** (default): One LLM handles both exploration and coding.
    Uses ``_SYSTEM_PROMPT`` for all turns.

    **Dual-model**: A cheaper/faster explorer model gathers information,
    then a stronger coder model writes and iterates on the harness.
    Pass ``llm_coder`` to enable this mode.

    Usage::

        # Single model
        agent = ExploitAgent(llm_caller, env, profile, trace_path)

        # Dual model (e.g., qwen for exploration, claude for coding)
        agent = ExploitAgent(llm_caller, env, profile, trace_path,
                             llm_coder=coder_caller)
    """

    def __init__(
        self,
        llm_caller: Callable[[str, str], str],
        env: DockerEnv,
        profile: RepoProfile,
        trace_path: TracePath,
        sink_function: str,
        sink_file: str,
        config: AgentConfig | None = None,
        progress_callback: Callable[[str, int], None] | None = None,
        llm_coder: Callable[[str, str], str] | None = None,
    ) -> None:
        self.llm_explore = llm_caller
        self.llm_code = llm_coder if llm_coder else llm_caller
        self.dual_model = llm_coder is not None
        self.env = env
        self.profile = profile
        self.trace = trace_path
        self.sink_function = sink_function
        self.sink_file = sink_file
        self.config = config or AgentConfig()
        self._progress = progress_callback
        self._exchanges: list[tuple[str, str]] = []  # (assistant, result)
        self._phase: str = "explore" if self.dual_model else "single"
        self._exploration_summary: str = ""  # filled when explorer finishes
        self._last_force_resolve_turn: int = -99  # cooldown tracking
        self._force_resolve_count: int = 0

        # backward compat: single-caller property
        self.llm_call = llm_caller

    def run(self) -> AgentResult:
        """Run the agent loop until success or budget exhaustion."""
        t0 = time.time()
        result = AgentResult()

        # Build initial context
        initial_context = self._build_initial_context()

        for turn in range(self.config.max_turns):
            phase_label = f"[{self._phase}]" if self.dual_model else ""
            if self._progress:
                self._progress(f"Turn {turn + 1}/{self.config.max_turns} {phase_label}", turn)

            # Select LLM caller and system prompt based on current phase
            if self._phase == "explore":
                llm_fn = self.llm_explore
                system_prompt = _EXPLORER_PROMPT
                prompt_context = self._build_prompt(initial_context)
            elif self._phase == "code":
                llm_fn = self.llm_code
                system_prompt = _CODER_PROMPT
                prompt_context = self._build_coder_prompt(initial_context)
            else:
                # single-model mode
                llm_fn = self.llm_explore
                system_prompt = _SYSTEM_PROMPT
                prompt_context = self._build_prompt(initial_context)

            # Call LLM
            logger.info("Agent turn %d/%d [%s]", turn + 1, self.config.max_turns, self._phase)
            try:
                response = llm_fn(system_prompt, prompt_context)
            except Exception as exc:
                logger.error("LLM call failed at turn %d: %s", turn + 1, exc)
                result.log.append({"role": "error", "content": str(exc)})
                continue

            # Parse actions
            actions = parse_actions(response)
            if not actions:
                # LLM didn't emit any executable actions — redirect it
                no_action_count = sum(1 for _, r in self._exchanges if "(NO ACTIONS)" in r)
                redirect_msg = (
                    "⚠️ NO ACTIONS DETECTED in your response. I need you to use "
                    "the action format so I can execute commands in the Docker container.\n\n"
                    "Use <shell>command</shell> tags or ```bash code blocks.\n\n"
                    "Example — do this RIGHT NOW as your next response:\n"
                    "<shell>ls /src/ | head -20</shell>\n"
                    "<shell>find /src -name 'README*' -o -name 'BUILD*' -o -name 'Makefile' | head -10</shell>\n\n"
                    "Do NOT explain what you plan to do. Just emit the commands."
                )
                self._exchanges.append((response[:1000], f"(NO ACTIONS) {redirect_msg}"))
                result.log.append({"role": "assistant", "content": response[:2000]})
                result.log.append({"role": "system", "content": redirect_msg})

                # If stuck for too many turns, force an exploration command
                if no_action_count >= 3:
                    logger.warning("Agent stuck (no actions for %d turns) — forcing exploration", no_action_count)
                    forced_cmds = [
                        "ls -la /src/",
                        "find /src -maxdepth 2 -name '*.h' -path '*/public/*' -o -name '*.h' -path '*/include/*' | head -20",
                        "find /src -name 'fuzz*' -o -name '*_fuzzer*' | head -10",
                        "cat /src/BUILD.gn 2>/dev/null || cat /src/CMakeLists.txt 2>/dev/null || cat /src/Makefile 2>/dev/null | head -50",
                    ]
                    forced_results = []
                    for cmd in forced_cmds:
                        exec_r = self.env.exec(cmd, timeout=30)
                        forced_results.append(f"$ {cmd}\n{exec_r.output[:1500]}")
                    forced_output = "\n\n".join(forced_results)
                    self._exchanges.append((
                        "(forced exploration)",
                        f"I ran some exploration commands for you:\n\n{forced_output}\n\n"
                        "Now based on this output, write a <shell> command or <write_file> to proceed."
                    ))
                    result.log.append({"role": "system", "content": f"Forced exploration:\n{forced_output[:3000]}"})

                continue

            actions = actions[:self.config.max_actions_per_turn]

            # Execute actions
            action_results: list[str] = []
            done = False

            for action in actions:
                result.total_actions += 1

                if action.kind == "shell":
                    exec_r = self.env.exec(action.content, timeout=self.config.exec_timeout)
                    output = f"[shell] $ {action.content}\n"
                    output += f"exit_code={exec_r.exit_code}\n"
                    output += exec_r.output[:4000]
                    action_results.append(output)

                elif action.kind == "write_file":
                    exec_r = self.env.write_file(action.path, action.content)
                    if exec_r.success:
                        action_results.append(f"[write_file] Wrote {len(action.content)} bytes to {action.path}")
                    else:
                        action_results.append(f"[write_file] FAILED: {exec_r.stderr}")

                elif action.kind == "read_file":
                    content = self.env.read_file(action.path)
                    action_results.append(f"[read_file] {action.path}:\n{content[:3000]}")

                elif action.kind == "done":
                    if self._phase == "explore":
                        # Explorer is done — transition to coder phase
                        self._exploration_summary = action.content
                        self._transition_to_code(result)
                        done = False  # don't exit the loop
                    else:
                        result.final_reason = action.content
                        done = True
                    break

            # Build result string
            results_str = "\n\n".join(action_results)

            # Log
            result.log.append({"role": "assistant", "content": response[:5000]})
            result.log.append({"role": "results", "content": results_str[:5000]})

            # Store exchange for context
            self._exchanges.append((
                response[:3000],
                results_str[:3000],
            ))

            result.turns_used = turn + 1

            if done:
                break

            # ----------------------------------------------------------
            # Stall detection: is the agent spinning without progress?
            # ----------------------------------------------------------
            stall_hint = self._detect_stall(turn, results_str)
            if stall_hint:
                logger.warning("Stall detected at turn %d — injecting hint", turn + 1)

                # In dual-model mode, exploration stall → force transition to coder
                if self._phase == "explore" and "EXPLORATION PHASE IS OVER" in stall_hint:
                    logger.info("Exploration stall → auto-transitioning to coder model")
                    self._exploration_summary = (
                        "Exploration was auto-terminated due to stall. "
                        "The explorer spent too many turns without producing actionable results. "
                        "Review the exchange history for what was found."
                    )
                    self._transition_to_code(result)
                    continue

                # If the hint contains a harness template, actually write it
                if "<write_file" in stall_hint and turn >= 6:
                    forced_output = self._force_write_harness()
                    if forced_output:
                        stall_hint += f"\n\n=== I wrote and compiled the harness for you ===\n{forced_output}"

                # Linker resolution: auto-run the binary if linking succeeded
                if "LINKING SUCCEEDED" in stall_hint:
                    logger.info("Force-resolve produced a working binary!")
                    auto_run_output = self._auto_run_harness()
                    if auto_run_output:
                        stall_hint += f"\n\n{auto_run_output}"

                self._exchanges[-1] = (
                    self._exchanges[-1][0],
                    self._exchanges[-1][1] + f"\n\n{stall_hint}",
                )
                result.log.append({"role": "system", "content": stall_hint[:3000]})

            # In dual-model explore phase, auto-transition if agent writes code
            if self._phase == "explore":
                wrote_code = any(
                    a.kind == "write_file" and a.path.endswith((".cpp", ".cc", ".c", ".h"))
                    for a in actions
                )
                if wrote_code:
                    logger.info("Explorer wrote code — auto-transitioning to coder model")
                    self._exploration_summary = (
                        "The explorer started writing code. Transition to coder phase. "
                        "Continue from where the explorer left off."
                    )
                    self._transition_to_code(result)

            # Auto-verify: check if the agent compiled and ran something
            # Look for harness binary and input file
            check = self.env.exec("ls /work/harness* /work/*.bin 2>/dev/null")
            if check.success and check.stdout.strip():
                # Check if there's an input file
                input_check = self.env.exec("ls /work/input* /work/seed* /work/*.pdf /work/*.xml 2>/dev/null")
                input_file = ""
                if input_check.success and input_check.stdout.strip():
                    input_file = input_check.stdout.strip().split("\n")[0]

                binary = check.stdout.strip().split("\n")[0]

                if input_file and binary:
                    # Run verification
                    vr = self._run_verification(binary, input_file)
                    result.verification = vr

                    if vr.confirmed:
                        logger.info("🔴 VERIFIED: vulnerability confirmed!")
                        result.success = True
                        result.harness_path = binary
                        result.input_path = input_file

                        # Tell the agent about the verification
                        verify_msg = (
                            f"\n\n=== AUTOMATIC VERIFICATION ===\n"
                            f"Status: {vr.status_icon}\n"
                            f"Result: {vr.summary}\n"
                            f"Sink breakpoint hit: {vr.sink_reached} ({vr.sink_hit_count} times)\n"
                            f"ASAN crash: {vr.asan_crash} ({vr.asan_crash_type})\n"
                            f"Crash location: {vr.asan_location}\n"
                            f"Crash in library: {vr.asan_in_library}\n"
                        )
                        results_str += verify_msg
                        self._exchanges[-1] = (
                            self._exchanges[-1][0],
                            self._exchanges[-1][1] + verify_msg,
                        )
                        break

                    elif vr.harness_crashed_itself:
                        # Tell the agent its harness has a bug
                        warn_msg = (
                            f"\n\n=== AUTOMATIC VERIFICATION WARNING ===\n"
                            f"The crash occurred in YOUR HARNESS CODE at {vr.asan_location}, "
                            f"not inside the library. This is a FALSE POSITIVE.\n"
                            f"Fix your harness — the crash must be inside the target library.\n"
                            f"ASAN trace:\n{vr.asan_trace[:1500]}\n"
                        )
                        self._exchanges[-1] = (
                            self._exchanges[-1][0],
                            self._exchanges[-1][1] + warn_msg,
                        )

                    elif vr.sink_reached:
                        info_msg = (
                            f"\n\n=== VERIFICATION UPDATE ===\n"
                            f"Sink function {self.sink_function} was REACHED but no crash.\n"
                            f"Try crafting inputs that violate the conditions along the trace path.\n"
                        )
                        self._exchanges[-1] = (
                            self._exchanges[-1][0],
                            self._exchanges[-1][1] + info_msg,
                        )

        result.elapsed_seconds = round(time.time() - t0, 2)
        return result

    # ------------------------------------------------------------------
    # Stall detection
    # ------------------------------------------------------------------

    def _detect_stall(self, turn: int, latest_results: str) -> str | None:
        """Detect if the agent is stuck and inject progressively stronger hints.

        Tracks three phases:
          1. EXPLORE (find/ls/cat/grep only)
          2. BUILD (g++/gcc/make/cmake compile commands)
          3. TEST (running a binary with input)

        If the agent stays in EXPLORE too long, it gets pushed to BUILD.
        If BUILD keeps failing the same way, it gets a different approach.
        """
        if turn < 3:
            return None

        recent = self._exchanges[-6:]  # last 6 turns

        # Classify each turn by what actions were actually executed
        explore_turns = 0
        build_turns = 0
        write_turns = 0
        test_turns = 0
        for resp, res in recent:
            has_write = "[write_file]" in res
            has_compile = any(k in res for k in (
                "g++ ", "gcc ", "clang ", "make ", "cmake ", "ninja ",
                "g++:", "gcc:", "clang:", "error:", "undefined reference",
            ))
            has_run = any(k in res for k in (
                "./harness", "/work/harness", "ASAN", "AddressSanitizer",
                "Segmentation fault", "SUMMARY:",
            ))
            has_explore = any(k in res for k in ("exit_code=0\n/", "[shell] $ cat ", "[shell] $ find ", "[shell] $ grep ", "[shell] $ ls ", "[shell] $ sed "))

            if has_run:
                test_turns += 1
            elif has_compile:
                build_turns += 1
            elif has_write:
                write_turns += 1
            else:
                explore_turns += 1

        # --- Pattern 1: Build tool not found ---
        all_results = "\n".join(r for _, r in recent)
        not_found_tools = set()
        for tool in ("gn", "cmake", "meson", "bazel", "cargo", "scons", "waf"):
            count = all_results.lower().count(f"{tool}: command not found") + \
                    all_results.lower().count(f"{tool}: not found")
            if count >= 2:
                not_found_tools.add(tool)

        if not_found_tools:
            tools_str = ", ".join(sorted(not_found_tools))
            # Find existing fuzz harnesses to use as reference
            fuzz_check = self.env.exec(
                "find /src -name '*fuzz*' -name '*.cc' | head -5", timeout=10,
            )
            fuzz_files = fuzz_check.stdout.strip() if fuzz_check.success else ""
            ref_hint = ""
            if fuzz_files:
                first_fuzz = fuzz_files.split("\n")[0]
                ref_hint = f"\nThere are existing fuzz harnesses you can reference:\n{fuzz_files}\nRead one with: cat {first_fuzz} | head -80\n"

            return (
                f"⚠️ STOP: {tools_str} is not installed. The full build system is NOT available.\n\n"
                f"You have two options:\n"
                f"A) Write a harness using the PUBLIC API (fpdfview.h) — this doesn't need {tools_str}.\n"
                f"   Just link against the .o files you compile from source.\n"
                f"B) Find an EXISTING fuzz harness and adapt it.\n"
                f"{ref_hint}\n"
                f"DO NOT search for {tools_str} again. Write code NOW with <write_file>."
            )

        # --- Pattern 2: Stuck in exploration phase ---
        if explore_turns >= 4 and write_turns == 0 and build_turns == 0 and turn >= 5:
            # Agent has been exploring for too long — inject a concrete harness
            return self._generate_harness_hint()

        # --- Pattern 3: Wrote harness but never tried to compile ---
        if write_turns >= 2 and build_turns == 0 and turn >= 8:
            return (
                "⚠️ You've written files but never tried to compile them.\n\n"
                "Try compiling NOW:\n"
                "<shell>g++ -fsanitize=address -g -std=c++17 -I/src -I/src/public "
                "/work/harness.cpp -c -o /work/harness.o 2>&1 | head -30</shell>\n\n"
                "Even if it fails, the error will tell you what's missing."
            )

        # --- Pattern 4: Linker "cannot find -l" / searching for .a/.so loop ---
        # .o compiles but linking fails because no pre-built library exists
        linker_failures = 0
        has_successful_compile = False
        searching_for_lib = 0
        for resp, res in recent:
            if "cannot find -l" in res:
                linker_failures += 1
            if ("No such file or directory" in res and
                    (".a" in res or ".so" in res or "-l" in res)):
                linker_failures += 1
            if "undefined reference to" in res and "ld:" in res:
                linker_failures += 1
            if "exit_code=0" in res and ("-c -o" in res or "-c -o" in resp):
                has_successful_compile = True
            combined = resp + " " + res
            if (("find" in combined or "ls" in combined) and
                    (".so" in combined or ".a" in combined or
                     "lib" in combined) and
                    "(no output)" in res):
                searching_for_lib += 1

        if (linker_failures >= 2 or searching_for_lib >= 3) and has_successful_compile:
            # Cooldown: if binary already exists and was recently built, just tell
            # the agent to RUN it instead of rebuilding from scratch
            binary_exists = self.env.exec(
                "test -x /work/harness && echo yes", timeout=5,
            ).stdout.strip() == "yes"
            turns_since_last = turn - self._last_force_resolve_turn

            if binary_exists and turns_since_last < 8:
                # Find an input file
                input_r = self.env.exec(
                    "ls /work/input.pdf /work/input.* /src/testing/resources/hello_world.pdf "
                    "2>/dev/null | head -1", timeout=5,
                )
                input_file = input_r.stdout.strip().split("\n")[0] if input_r.stdout.strip() else "/work/input.pdf"

                return (
                    "⚠️ /work/harness already exists and is executable.\n"
                    "STOP searching for libraries. STOP recompiling. The binary is READY.\n\n"
                    "RUN IT NOW with:\n"
                    f"<shell>/work/harness {input_file} 2>&1 | head -80</shell>\n\n"
                    "If it runs without crashing, try:\n"
                    "- Different PDF files: ls /src/testing/resources/*.pdf | head -20\n"
                    "- Malformed input: create a corrupted PDF with truncated/modified bytes\n"
                    "- More API calls: add more functions from the vulnerability trace to the harness\n\n"
                    "Do NOT search for .a/.so files. Do NOT try -lpdfium. Just RUN the binary."
                )

            # First time or cooldown expired — do the full resolution
            self._last_force_resolve_turn = turn
            self._force_resolve_count += 1
            return self._generate_linking_hint()

        # --- Pattern 5: Same compilation error repeated ---
        compile_errors = []
        for _, r in recent:
            if "error:" in r and any(k in r for k in ("g++", "gcc", "clang")):
                for line in r.split("\n"):
                    if "error:" in line:
                        compile_errors.append(line.strip()[:100])
                        break
        if len(compile_errors) >= 3 and len(set(compile_errors)) == 1:
            return (
                f"⚠️ Same error 3 times: {compile_errors[0][:80]}\n\n"
                "Try a DIFFERENT approach:\n"
                "- Missing header → find /src -name 'header.h' and add -I flag\n"
                "- Missing symbol → compile more source files or use a different function\n"
                "- Template/C++ issue → try -std=c++20\n"
                "Do NOT repeat the same command."
            )

        # --- Pattern 6: Repeated identical commands ---
        recent_cmds = []
        for a, _ in recent:
            for m in re.finditer(r"\[shell\] \$ (.+)", a):
                recent_cmds.append(m.group(1).strip()[:80])
        if len(recent_cmds) >= 6:
            from collections import Counter
            counts = Counter(recent_cmds)
            repeated = [cmd for cmd, n in counts.items() if n >= 3]
            if repeated:
                return (
                    f"⚠️ You've run '{repeated[0][:60]}' {counts[repeated[0]]} times.\n"
                    "This is not productive. Do something DIFFERENT."
                )

        return None

    def _generate_linking_hint(self) -> str:
        """Generate a concrete hint for resolving linker failures.

        Called when the harness .o compiles fine but linking fails because
        there's no pre-built library. Runs nm, finds source files, and
        tries to compile them.
        """
        # Step 1: Find what symbols the harness needs
        nm_r = self.env.exec(
            "nm /work/harness.o 2>/dev/null | grep ' U ' | "
            "grep -v '__asan\\|__cxa\\|__stack\\|_Unwind\\|__gxx\\|_GLOBAL\\|_Z.*std' | "
            "awk '{print $2}' | head -20",
            timeout=10,
        )
        if not nm_r.success or not nm_r.stdout.strip():
            return (
                "⚠️ LINKER STALL: No pre-built library exists in this repo.\n"
                "The project needs its build system (gn/cmake/etc.) to create the library.\n\n"
                "ALTERNATIVE: Compile source files directly.\n"
                "1. Find which .cc/.cpp files implement the functions your harness calls\n"
                "2. Compile them individually: g++ -c -I/src file.cc -o file.o\n"
                "3. Link all .o files together with your harness\n"
            )

        undefined_symbols = [s.strip() for s in nm_r.stdout.strip().split("\n") if s.strip()]

        parts = [
            "⚠️ LINKER STALL DETECTED: There is NO pre-built library (.a or .so) in this repo.",
            "STOP searching for libpdfium or any .a/.so files — they do not exist.",
            "The library was never compiled. You must compile source files directly.",
            "",
            f"Your harness.o needs these {len(undefined_symbols)} symbols:",
        ]
        for s in undefined_symbols[:15]:
            parts.append(f"  {s}")

        # Step 2: Find source files that define these symbols
        # Use the first few symbols to search
        search_symbols = undefined_symbols[:5]
        source_files_found: dict[str, list[str]] = {}  # file → symbols it defines

        for sym in search_symbols:
            # Demangle C++ symbol to get function name
            demangle_r = self.env.exec(f"echo '{sym}' | c++filt 2>/dev/null", timeout=5)
            demangled = demangle_r.stdout.strip() if demangle_r.success else sym

            # Extract just the function name (last component before '(')
            func_name = demangled.split("(")[0].split("::")[-1].split("<")[0].strip()
            if len(func_name) < 3:
                continue

            # Search for definition in source files
            grep_r = self.env.exec(
                f"grep -rn '{func_name}' /src/ "
                f"--include='*.cc' --include='*.cpp' --include='*.c' -l 2>/dev/null | "
                f"grep -v '_test\\|_unittest\\|_fuzzer\\|_embeddertest' | head -5",
                timeout=15,
            )
            if grep_r.success and grep_r.stdout.strip():
                for f in grep_r.stdout.strip().split("\n"):
                    f = f.strip()
                    if f:
                        source_files_found.setdefault(f, []).append(func_name)

        if source_files_found:
            parts.append("")
            parts.append("I found these source files that likely define the needed symbols:")
            # Sort by number of symbols matched (most relevant first)
            ranked = sorted(source_files_found.items(), key=lambda x: -len(x[1]))
            for f, syms in ranked[:10]:
                parts.append(f"  {f} (defines: {', '.join(syms[:3])})")

            # Step 3: Try compiling the top source files
            parts.append("")
            parts.append("=== Attempting to compile source files ===")

            compiled_objects: list[str] = []
            top_files = [f for f, _ in ranked[:5]]

            for src_file in top_files:
                obj_name = src_file.replace("/", "_").replace(".cc", ".o").replace(".cpp", ".o")
                obj_path = f"/work/{obj_name}"
                compile_r = self.env.exec(
                    f"g++ -fsanitize=address -g -std=c++20 -I/src -I/src/public "
                    f"-c {src_file} -o {obj_path} 2>&1 | tail -3",
                    timeout=60,
                )
                if compile_r.exit_code == 0:
                    compiled_objects.append(obj_path)
                    parts.append(f"  ✅ {src_file} → {obj_path}")
                else:
                    first_err = compile_r.output.strip().split("\n")[0][:120] if compile_r.output.strip() else "unknown error"
                    parts.append(f"  ❌ {src_file}: {first_err}")

            if compiled_objects:
                # Step 4: Try linking with compiled objects
                objs_str = " ".join(compiled_objects)
                link_r = self.env.exec(
                    f"g++ -fsanitize=address -g -std=c++20 -I/src -I/src/public "
                    f"/work/harness.o {objs_str} -o /work/harness -lpthread -ldl 2>&1 | head -20",
                    timeout=60,
                )
                parts.append("")
                if link_r.exit_code == 0:
                    parts.append("✅ LINKING SUCCEEDED! Try running: /work/harness /work/input.pdf")
                else:
                    # Extract remaining undefined symbols
                    remaining = []
                    for line in link_r.output.split("\n"):
                        if "undefined reference to" in line:
                            m = re.search(r"undefined reference to `([^']+)'", line)
                            if m:
                                remaining.append(m.group(1)[:60])
                    remaining = list(dict.fromkeys(remaining))[:10]  # dedupe

                    parts.append(f"❌ Linking still has {len(remaining)} undefined symbols:")
                    for r in remaining[:8]:
                        parts.append(f"    {r}")
                    parts.append("")
                    parts.append(
                        "You need to compile more source files to resolve these.\n"
                        "Search for them: grep -rn 'FUNCTION_NAME' /src --include='*.cc' -l\n"
                        "Then compile each: g++ -c -std=c++20 -I/src FILE.cc -o FILE.o\n"
                        "Then link all .o files together."
                    )
            else:
                parts.append("")
                parts.append(
                    "❌ None of the source files compiled individually.\n"
                    "This repo has complex build dependencies that require the full\n"
                    "build system. Consider a DIFFERENT approach:\n\n"
                    "OPTION A: Use the internal C++ API directly (skip the public C API).\n"
                    "  Look at the existing tests/fuzzers — they #include internal headers\n"
                    "  and call C++ classes directly.\n\n"
                    "OPTION B: Compile a minimal subset of the trace files.\n"
                    "  Look at which .cc/.cpp files are in the trace, compile only those,\n"
                    "  and stub out any missing dependencies with empty functions.\n\n"
                    "OPTION C: Use the repo's own test infrastructure.\n"
                    "  Find existing test programs that already link against the library.\n"
                    "  Look for: find /src -name '*test*.cc' -o -name '*_test.cpp' | head -10\n"
                    "  Copy one and modify it to exercise the vulnerability trace."
                )
        else:
            # Build generic search commands from the actual undefined symbols
            search_cmds = []
            for sym in undefined_symbols[:3]:
                demangle_r = self.env.exec(f"echo '{sym}' | c++filt 2>/dev/null", timeout=5)
                func = demangle_r.stdout.strip().split("(")[0].split("::")[-1] if demangle_r.success else sym
                if len(func) >= 3:
                    search_cmds.append(
                        f"<shell>grep -rn '{func}' /src --include='*.cc' --include='*.cpp' -l | "
                        f"grep -v test | head -5</shell>"
                    )
            parts.append("")
            parts.append(
                "Could not find source files for the needed symbols.\n"
                "Try searching manually:\n" + "\n".join(search_cmds)
            )

        return "\n".join(parts)

    def _generate_harness_hint(self) -> str:
        """Generate a concrete harness template based on the trace and repo."""
        # Check what public API is available
        api_check = self.env.exec(
            "grep -h 'FPDF_EXPORT\\|DLLEXPORT' /src/public/fpdfview.h 2>/dev/null | head -15",
            timeout=10,
        )
        api_funcs = api_check.stdout.strip() if api_check.success else ""

        # Check for existing fuzz harnesses
        fuzz_check = self.env.exec(
            "cat $(find /src -name '*fuzz*' -name '*.cc' | head -1) 2>/dev/null | head -40",
            timeout=10,
        )
        fuzz_ref = fuzz_check.stdout.strip() if fuzz_check.success else ""

        # Check for test PDFs
        pdf_check = self.env.exec(
            "ls /src/testing/resources/*.pdf 2>/dev/null | head -5",
            timeout=10,
        )
        pdf_files = pdf_check.stdout.strip() if pdf_check.success else ""

        hint_parts = [
            "⚠️ EXPLORATION PHASE IS OVER. Time to write code.\n",
            "You've gathered enough information. Write a harness NOW.\n\n",
        ]

        if fuzz_ref:
            hint_parts.append(
                f"Here's an existing fuzzer from the repo for reference:\n"
                f"```\n{fuzz_ref[:1500]}\n```\n\n"
            )

        hint_parts.append(
            "Write your harness with <write_file>. Here's a template:\n\n"
            '<write_file path="/work/harness.cpp">\n'
            '#include <stdio.h>\n'
            '#include <stdlib.h>\n'
            '#include <string.h>\n'
            '#include "public/fpdfview.h"\n\n'
            'int main(int argc, char* argv[]) {\n'
            '    if (argc < 2) { fprintf(stderr, "Usage: %s <pdf>\\n", argv[0]); return 1; }\n'
            '    FILE* f = fopen(argv[1], "rb");\n'
            '    if (!f) { perror("fopen"); return 1; }\n'
            '    fseek(f, 0, SEEK_END);\n'
            '    long len = ftell(f);\n'
            '    fseek(f, 0, SEEK_SET);\n'
            '    char* buf = (char*)malloc(len);\n'
            '    fread(buf, 1, len, f);\n'
            '    fclose(f);\n\n'
            '    FPDF_LIBRARY_CONFIG config = {2, NULL, NULL, 0};\n'
            '    FPDF_InitLibraryWithConfig(&config);\n'
            '    FPDF_DOCUMENT doc = FPDF_LoadMemDocument(buf, len, NULL);\n'
            '    if (doc) {\n'
            '        int pages = FPDF_GetPageCount(doc);\n'
            '        for (int i = 0; i < pages && i < 10; i++) {\n'
            '            FPDF_PAGE page = FPDF_LoadPage(doc, i);\n'
            '            if (page) FPDF_ClosePage(page);\n'
            '        }\n'
            '        FPDF_CloseDocument(doc);\n'
            '    }\n'
            '    FPDF_DestroyLibrary();\n'
            '    free(buf);\n'
            '    return 0;\n'
            '}\n'
            '</write_file>\n\n'
        )

        if pdf_files:
            first_pdf = pdf_files.split("\n")[0]
            hint_parts.append(
                f"Then compile and test:\n"
                f"<shell>g++ -fsanitize=address -g -std=c++17 -I/src -I/src/public "
                f"/work/harness.cpp -c -o /work/harness.o 2>&1 | head -30</shell>\n\n"
                f"Seed PDF: {first_pdf}\n"
            )

        return "".join(hint_parts)

    def _force_write_harness(self) -> str:
        """Actually write a starter harness and attempt compilation.

        Called when the agent has been exploring for too long. We write
        a minimal harness, try to compile it, and return the results so
        the LLM can iterate from a concrete starting point instead of
        continuing to explore.
        """
        harness_code = (
            '#include <stdio.h>\n'
            '#include <stdlib.h>\n'
            '#include <string.h>\n'
            '#include "public/fpdfview.h"\n\n'
            'int main(int argc, char* argv[]) {\n'
            '    if (argc < 2) { fprintf(stderr, "Usage: %s <pdf>\\n", argv[0]); return 1; }\n'
            '    FILE* f = fopen(argv[1], "rb");\n'
            '    if (!f) { perror("fopen"); return 1; }\n'
            '    fseek(f, 0, SEEK_END);\n'
            '    long len = ftell(f);\n'
            '    fseek(f, 0, SEEK_SET);\n'
            '    char* buf = (char*)malloc(len);\n'
            '    fread(buf, 1, len, f);\n'
            '    fclose(f);\n\n'
            '    FPDF_LIBRARY_CONFIG config = {2, NULL, NULL, 0};\n'
            '    FPDF_InitLibraryWithConfig(&config);\n'
            '    FPDF_DOCUMENT doc = FPDF_LoadMemDocument(buf, len, NULL);\n'
            '    if (doc) {\n'
            '        int pages = FPDF_GetPageCount(doc);\n'
            '        for (int i = 0; i < pages && i < 10; i++) {\n'
            '            FPDF_PAGE page = FPDF_LoadPage(doc, i);\n'
            '            if (page) FPDF_ClosePage(page);\n'
            '        }\n'
            '        FPDF_CloseDocument(doc);\n'
            '    }\n'
            '    FPDF_DestroyLibrary();\n'
            '    free(buf);\n'
            '    return 0;\n'
            '}\n'
        )

        parts = []

        # Write the harness
        wr = self.env.write_file("/work/harness.cpp", harness_code)
        if wr.success:
            parts.append("✅ Wrote /work/harness.cpp (starter harness)")
        else:
            parts.append(f"❌ Failed to write harness: {wr.stderr}")
            return "\n".join(parts)

        # Try to compile (just -c to see what headers are missing)
        compile_r = self.env.exec(
            "g++ -fsanitize=address -g -std=c++17 -I/src -I/src/public "
            "/work/harness.cpp -c -o /work/harness.o 2>&1 | head -40",
            timeout=60,
        )
        parts.append(f"$ g++ -c /work/harness.cpp\nexit_code={compile_r.exit_code}")
        parts.append(compile_r.output[:2000])

        if compile_r.exit_code == 0:
            parts.append("\n✅ Compilation to .o succeeded!")
            parts.append(
                "Now you need to find what other .o files or libraries to link against.\n"
                "Try: nm /work/harness.o | grep ' U ' to see undefined symbols.\n"
                "Then find which source files define them."
            )
        else:
            parts.append(
                "\n❌ Compilation failed. Read the errors above and fix the harness.\n"
                "Common fixes: add missing -I paths, or find the right header names."
            )

        # Copy a test PDF
        pdf_r = self.env.exec(
            "cp $(ls /src/testing/resources/hello_world.pdf 2>/dev/null || "
            "ls /src/testing/resources/*.pdf 2>/dev/null | head -1) "
            "/work/input.pdf 2>/dev/null && echo 'Copied test PDF' || echo 'No test PDF found'",
            timeout=10,
        )
        parts.append(pdf_r.output.strip())

        return "\n".join(parts)

    def _auto_run_harness(self) -> str:
        """Auto-run the harness binary with a test input and return the output.

        Called when force-resolve produces a working binary. Instead of
        waiting for the LLM to run it (which weak models often don't),
        we run it ourselves and feed the ASAN output back.
        """
        parts = ["=== AUTO-RUN: Executing /work/harness with test input ==="]

        # Make sure input exists
        input_check = self.env.exec(
            "ls /work/input.pdf /work/input.* 2>/dev/null | head -1",
            timeout=5,
        )
        input_file = input_check.stdout.strip().split("\n")[0] if input_check.success and input_check.stdout.strip() else ""

        if not input_file:
            # Try to copy one
            self.env.exec(
                "cp $(ls /src/testing/resources/hello_world.pdf 2>/dev/null || "
                "ls /src/testing/resources/*.pdf 2>/dev/null | head -1) "
                "/work/input.pdf 2>/dev/null",
                timeout=10,
            )
            input_file = "/work/input.pdf"

        # Run the harness
        run_r = self.env.exec(
            f"/work/harness {input_file} 2>&1 | head -80",
            timeout=30,
        )
        parts.append(f"$ /work/harness {input_file}")
        parts.append(f"exit_code={run_r.exit_code}")
        parts.append(run_r.output[:3000] if run_r.output else "(no output)")

        # Interpret the result
        output = run_r.output or ""
        if run_r.exit_code == 0 and "ERROR" not in output.upper() and "ASAN" not in output.upper():
            parts.append(
                "\n✅ Harness ran without crashing. This means:\n"
                "- The binary works and can load the PDF\n"
                "- No ASAN error with this particular input\n\n"
                "NEXT STEPS for the coder:\n"
                "1. Try other PDF files: ls /src/testing/resources/*.pdf | head -20\n"
                "2. Try MALFORMED inputs: create a corrupted PDF to trigger the bug\n"
                "3. Try accessing more API functions along the vulnerability trace\n"
                "4. Try exercising the specific code path from the trace"
            )
        elif "AddressSanitizer" in output or "ASAN" in output:
            # Check if crash is in library or harness
            if "/work/harness" in output and "/src/" not in output:
                parts.append(
                    "\n⚠️ ASAN error detected but it's in the HARNESS code, not the library.\n"
                    "Fix the harness code — the crash must be inside /src/ library code."
                )
            elif "/src/" in output:
                parts.append(
                    "\n🔴 ASAN ERROR DETECTED INSIDE THE LIBRARY!\n"
                    "This may be the vulnerability. Check the stack trace above.\n"
                    "The coder should analyze the output and confirm it matches the trace."
                )
            else:
                parts.append(
                    "\n⚠️ ASAN error detected. Check the stack trace to see if it's\n"
                    "in the library (/src/) or in the harness (/work/)."
                )
        elif run_r.exit_code != 0:
            parts.append(
                f"\n❌ Harness exited with code {run_r.exit_code}.\n"
                "This could be a crash. Check the output above.\n"
                "If it's a segfault, try running with: "
                f"gdb -batch -ex run -ex bt /work/harness --args /work/harness {input_file}"
            )
        else:
            parts.append(
                "\nHarness produced output but no clear crash.\n"
                "Try different input files or modify the harness to exercise\n"
                "more of the vulnerability trace."
            )

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Context building
    # ------------------------------------------------------------------

    def _build_initial_context(self) -> str:
        """Build the initial context with repo profile + trace + pre-seeded exploration."""
        p = self.profile

        # Pre-seed: run initial exploration commands so the LLM already has info
        exploration = ""
        if self.env.is_running:
            cmds = [
                "ls /src/ | head -30",
                "find /src -maxdepth 1 -name 'README*' -o -name 'BUILD*' -o -name 'Makefile' -o -name 'CMakeLists.txt' -o -name 'Cargo.toml' -o -name 'meson.build' | head -10",
                "find /src -path '*/public/*.h' -o -path '*/include/*.h' | head -15",
                "find /src -name '*fuzz*' -o -name '*fuzzer*' | head -10",
                "find /src/testing -name '*.pdf' -o -name '*.xml' -o -name '*.json' 2>/dev/null | head -10",
            ]
            parts = []
            for cmd in cmds:
                r = self.env.exec(cmd, timeout=15)
                if r.stdout.strip():
                    parts.append(f"$ {cmd}\n{r.stdout.strip()[:1000]}")
            exploration = "\n\n".join(parts)

        ctx_parts = [
            "=== REPOSITORY INFO ===",
            f"Name: {p.repo_name}",
            f"Language: {p.language}",
            f"Build system: {p.build_system or 'unknown'}",
        ]
        if p.build_commands:
            ctx_parts.append("Build hints (may need adaptation):")
            for cmd in p.build_commands:
                ctx_parts.append(f"  $ {cmd}")

        ctx_parts += [
            "",
            "=== VULNERABILITY TRACE ===",
            f"Sink function: {self.sink_function}",
            f"Sink file: {self.sink_file}",
            f"Tags: {', '.join(self.trace.vulnerability_tags or [])}",
            "",
            "Steps:",
        ]
        for i, step in enumerate(self.trace.steps[:20]):  # cap at 20 steps
            loc = step.location
            loc_str = f"{loc.file}:{loc.line}" if loc else "?"
            sink = " [SINK]" if i == len(self.trace.steps) - 1 else ""
            ctx_parts.append(f"  {i}{sink}: {loc_str} — {(step.code_snippet or '?')[:100]}")

        if exploration:
            ctx_parts += [
                "",
                "=== INITIAL EXPLORATION (already executed for you) ===",
                exploration,
            ]

        ctx_parts += [
            "",
            "=== START ===",
            "Based on the exploration above, emit your first <shell> commands.",
            "Good first steps: read the build config, check existing fuzz harnesses,",
            "or look at the public API headers.",
            "",
            "Remember: use <shell>command</shell> tags. I execute them and show you output.",
        ]

        return "\n".join(ctx_parts)

    def _build_prompt(self, initial_context: str) -> str:
        """Build the full user prompt with conversation history."""
        parts = [initial_context]

        # Add recent exchanges (sliding window)
        window = self._exchanges[-self.config.context_window:]
        for i, (assistant, results) in enumerate(window):
            turn_num = len(self._exchanges) - len(window) + i + 1
            parts.append(f"\n--- Turn {turn_num} ---")
            # Truncate assistant response to save context
            parts.append(f"[You said]:\n{assistant[:1500]}")
            parts.append(f"[Output]:\n{results[:2000]}")

        if self._exchanges:
            parts.append(
                "\n--- Your next turn ---\n"
                "Emit <shell> or <write_file> commands based on the output above.\n"
                "Do NOT repeat previous commands that already succeeded."
            )

        return "\n\n".join(parts)

    def _transition_to_code(self, result: AgentResult) -> None:
        """Transition from exploration phase to coding phase.

        Builds a summary of what was discovered and resets the exchange
        history so the coder model starts with a clean context.
        """
        logger.info("=== Phase transition: EXPLORE → CODE ===")
        result.log.append({
            "role": "system",
            "content": f"Phase transition: explore → code. Summary: {self._exploration_summary[:500]}",
        })

        # Save exploration exchanges for the summary, then reset
        explore_exchanges = self._exchanges[:]
        self._exchanges.clear()

        self._phase = "code"

    def _build_coder_prompt(self, initial_context: str) -> str:
        """Build prompt for the coder model with exploration summary."""
        parts = []

        # Compact version of initial context (repo info + trace)
        parts.append(initial_context)

        # Exploration summary
        parts.append("\n=== EXPLORATION SUMMARY ===")
        parts.append(self._exploration_summary or "(no summary provided)")

        # Key findings from exploration exchanges we saved
        # Include the last few exploration results as concrete data
        if not self._exchanges:
            # First coder turn — give it the raw exploration data
            parts.append("\n=== KEY FINDINGS FROM EXPLORATION ===")
            parts.append(
                "The explorer phase gathered the information above. "
                "Now write a harness, compile it, and iterate.\n"
                "Start by writing /work/harness.cpp with <write_file>."
            )
        else:
            # Subsequent coder turns — show recent exchanges
            window = self._exchanges[-self.config.context_window:]
            for i, (assistant, results) in enumerate(window):
                turn_num = len(self._exchanges) - len(window) + i + 1
                parts.append(f"\n--- Turn {turn_num} ---")
                parts.append(f"[You said]:\n{assistant[:1500]}")
                parts.append(f"[Output]:\n{results[:2000]}")

            parts.append(
                "\n--- Your next turn ---\n"
                "Continue from where you left off. Emit <shell> or <write_file> commands.\n"
                "Do NOT repeat commands that already succeeded."
            )

        return "\n\n".join(parts)

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def _run_verification(self, binary: str, input_file: str) -> VerificationResult:
        """Run GDB-based verification on the harness."""
        return verify_harness(
            env=self.env,
            harness_binary=binary,
            input_file=input_file,
            sink_function=self.sink_function,
            sink_file=self.sink_file,
            library_name=self.profile.library_name,
            timeout=self.config.verify_timeout,
        )
#src\deeptrace\exploit\CLIUsage.md
# Basic — uses Ollama locally
deeptrace validate traces.json --out reports/

# With Claude
deeptrace validate traces.json \
  --llm-provider anthropic \
  --llm-model claude-sonnet-4-20250514 \
  --llm-api-key $ANTHROPIC_API_KEY \
  --out reports/

# Without Docker (uses local gcc)
deeptrace validate traces.json --no-docker --out reports/

# Control iteration depth
deeptrace validate traces.json \
  --max-compile-retries 5 \
  --max-input-rounds 5 \
  --out reports/
```

### What the reports look like
```
reports/
├── SUMMARY.md                  # Table of all paths with status
├── path_0_report.md            # 🔴 CRASH CONFIRMED — asan_heap_buffer_overflow
├── path_1_report.md            # 🟡 SINK REACHED
├── path_2_report.md            # ⚪ UNCONFIRMED
├── path_3_report.md            # ...
└── ...
```

Each report includes the triggering input (hex + description), the ASAN stack trace, and the exact C harness that triggered it — so you can reproduce the crash independently.

### How the LLM prompt works for your traces.json

For path 0, the LLM receives:
```
=== Trace Path 0 ===
Vulnerability: buffer_overflow
Satisfiable: True
Summary: The trace path represents a potential buffer overflow...

Step 0:
  Location: fpdfsdk/pwl/cpwl_edit_impl.cpp:1875
  Code: if (word == pdfium::ascii::kBackspace) {
  Variables: word
  Context: Checks if the input word is a backspace character...

Step 3:
  Location: fpdfsdk/pwl/cpwl_edit_impl.cpp:1896
  Code: InsertWord(word, charset);
  ...

Step 17 [SINK]:
  Location: core/fpdfdoc/cpdf_interactiveform.cpp:91
  Code: UNSAFE_TODO(FXSYS_memcpy(&lf, &fd.lf, sizeof(LOGFONTA)));
  Context: Copies the log font information... unsafe memory copy...

traces.json
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│  deeptrace validate traces.json --out reports/              │
│                                                             │
│  For each path in traces.json:                              │
│                                                             │
│   ┌──────────────────┐                                      │
│   │ harness_generator │─── LLM prompt with full trace ───▶  │
│   │                  │◀── C source code ──────────────────  │
│   └────────┬─────────┘                                      │
│            ▼                                                │
│   ┌──────────────────┐    ┌─────────┐                       │
│   │  sandbox_runner   │───▶│ Docker  │  gcc -fsanitize=addr  │
│   │                  │    │ or local│  compile + run         │
│   └────────┬─────────┘    └─────────┘                       │
│            │                                                │
│            │ compile failed?                                │
│            ├──── yes ──▶ LLM repair_harness ──▶ recompile   │
│            │            (up to 3×)                           │
│            │                                                │
│            │ compiled ✓ → run with inputs                   │
│            │                                                │
│            │ sink not reached?                              │
│            ├──── yes ──▶ LLM generate_inputs (adaptive) ──▶ │
│            │            rerun with new inputs (up to 3×)    │
│            │                                                │
│            ▼                                                │
│   ┌──────────────────┐                                      │
│   │ report_generator  │──▶ path_0_report.md                 │
│   │                  │──▶ path_1_report.md                  │
│   │                  │──▶ ...                               │
│   │                  │──▶ SUMMARY.md                        │
│   └──────────────────┘                                      │
└─────────────────────────────────────────────────────────────┘
#src\deeptrace\exploit\docker_env.py
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
                build_hint_lines.append(f"BUILD_HINT_{i}=\"{cmd}\"")

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
        """Write a file into the container."""
        # Use base64 encoding to safely transfer any content
        import base64
        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
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
#src\deeptrace\exploit\harness_generator.py
"""LLM-based C harness generator for exploit validation.

Takes a TracePath from traces.json, formats it into a structured prompt,
and asks the LLM to generate a standalone C program that:
  1. Simulates the exact data flow described in the path.
  2. Accepts input (from stdin or argv) that drives data through each step.
  3. Includes a SINK_REACHED marker at the final step so we can detect success.
  4. Compiles with gcc + AddressSanitizer.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from deeptrace.models.graph import TracePath

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are an expert C/C++ security researcher writing proof-of-concept harnesses.

You will receive a data-flow trace through a real codebase. Each step shows:
- The file and line in the original codebase
- The code at that location
- An annotation explaining what happens
- The edge type (data_flow, call, param_pass, etc.)

Your job: Write a SINGLE standalone C file that:

1. SIMULATES the exact data flow described — you don't have access to the real
   codebase, so recreate the logic using simplified stub functions.
2. Reads input from stdin (use fread/fgets into a buffer).
3. Passes that input through the same chain of function calls and conditions
   shown in the trace. Each condition from the trace must appear as an if/check.
4. At the SINK (last step), include this exact marker:
      fprintf(stderr, "SINK_REACHED\\n");
   This marker fires only if the input satisfies ALL conditions in the flow.
5. For buffer overflow sinks, also do the actual unsafe operation (memcpy with
   controlled size, etc.) so AddressSanitizer can detect it.
6. Compile cleanly with: gcc -fsanitize=address -g -o harness harness.c

CRITICAL RULES:
- Output ONLY the C code. No markdown fences, no explanations.
- The program must compile with gcc (C17). Use <stdio.h>, <stdlib.h>, <string.h>.
- Read input from stdin at the start of main().
- Every condition from the trace must be a real if-statement in the code.
- The SINK_REACHED marker must only print when ALL conditions are satisfied.
- Include a comment "// Step N: <description>" for each trace step.
- If the trace shows a memcpy/strcpy at the sink, replicate it with a small
  fixed-size destination buffer so ASAN catches the overflow.
"""

_REPAIR_SYSTEM = """You are an expert C programmer. The previous harness code had an error.
Fix the code so it compiles and runs correctly. Output ONLY the complete fixed C file.
No markdown fences, no explanations. Just the C code."""


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def format_path_for_harness(path: TracePath, path_index: int) -> str:
    """Format a TracePath into a structured description for the LLM."""
    lines = [
        f"=== Trace Path {path_index} ===",
        f"Vulnerability: {', '.join(path.vulnerability_tags) or 'unknown'}",
        f"Satisfiable: {path.is_satisfiable}",
        f"Depth: {path.depth} steps across multiple files",
        "",
    ]

    if path.vulnerability_summary:
        lines.append(f"Summary: {path.vulnerability_summary[:500]}")
        lines.append("")

    if path.constraints:
        lines.append("Path constraints (must hold for exploit):")
        for c in path.constraints[:10]:
            lines.append(f"  - {c}")
        lines.append("")

    lines.append("Data flow steps (source → sink):")
    lines.append("")

    for i, step in enumerate(path.steps):
        loc = step.location
        file_str = f"{loc.file}:{loc.line}" if loc else "?"
        edge = f" [{step.edge_kind}]" if step.edge_kind else ""
        is_sink = (i == len(path.steps) - 1)

        lines.append(f"Step {i}{' [SINK]' if is_sink else ''}:{edge}")
        lines.append(f"  Location: {file_str}")
        lines.append(f"  Code: {step.code_snippet}")
        if step.node_name:
            lines.append(f"  Variables: {step.node_name}")
        if step.annotation:
            lines.append(f"  Context: {step.annotation[:200]}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Input generation prompt
# ---------------------------------------------------------------------------

_INPUT_GEN_SYSTEM = """You are a security researcher generating test inputs for a vulnerability harness.

The harness reads from stdin. Based on the trace conditions and previous execution
results, generate inputs that will satisfy ALL conditions and reach the SINK.

Respond with ONLY a JSON object:
{
  "inputs": [
    {"description": "what this input tests", "data": "the raw bytes as a string", "hex": false},
    {"description": "...", "data": "414243", "hex": true}
  ]
}

Generate 5-10 diverse inputs. Include edge cases: empty, very long, special chars,
values that match specific conditions from the trace."""


# ---------------------------------------------------------------------------
# Generator class
# ---------------------------------------------------------------------------

class HarnessGenerator:
    """Generates C harness code from trace paths using an LLM."""

    def __init__(self, llm_caller: Any) -> None:
        """
        Args:
            llm_caller: A callable(system_prompt, user_message) -> str
                        that calls the configured LLM provider.
        """
        self.llm_call = llm_caller

    def generate_harness(self, path: TracePath, path_index: int) -> str:
        """Generate initial C harness code for a trace path.

        Returns:
            C source code as a string.
        """
        path_desc = format_path_for_harness(path, path_index)

        user_msg = (
            "Generate a standalone C harness that exercises this trace path. "
            "The harness must read input from stdin and pass it through the "
            "same chain of conditions and function calls shown below. "
            "Print SINK_REACHED to stderr when the sink is triggered.\n\n"
            + path_desc
        )

        raw = self.llm_call(_SYSTEM_PROMPT, user_msg)
        return _extract_c_code(raw)

    def repair_harness(
        self,
        code: str,
        error_output: str,
        attempt: int,
    ) -> str:
        """Ask the LLM to fix compilation or runtime errors.

        Args:
            code: The current C source code.
            error_output: Compiler or runtime error messages.
            attempt: Which repair attempt this is (for context).

        Returns:
            Fixed C source code.
        """
        user_msg = (
            f"Repair attempt {attempt}. The following C code has errors:\n\n"
            f"```c\n{code}\n```\n\n"
            f"Error output:\n```\n{error_output[:2000]}\n```\n\n"
            "Fix ALL errors. Output ONLY the complete corrected C file."
        )

        raw = self.llm_call(_REPAIR_SYSTEM, user_msg)
        return _extract_c_code(raw)

    def generate_inputs(
        self,
        path: TracePath,
        path_index: int,
        previous_results: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Generate test inputs for the harness.

        Args:
            path: The trace path (for condition context).
            path_index: Index of this path.
            previous_results: Results from prior runs (for adaptive generation).

        Returns:
            List of {"description": str, "data": str|bytes, "hex": bool}
        """
        path_desc = format_path_for_harness(path, path_index)

        context = ""
        if previous_results:
            context = "\n\nPrevious execution results:\n"
            for r in previous_results[-5:]:  # last 5 results
                context += (
                    f"  Input: {r.get('input_desc', '?')}\n"
                    f"  Exit code: {r.get('exit_code', '?')}\n"
                    f"  Sink reached: {r.get('sink_reached', False)}\n"
                    f"  Stderr: {r.get('stderr', '')[:200]}\n\n"
                )

        user_msg = (
            "Generate test inputs for this vulnerability harness. "
            "The program reads from stdin. The inputs must satisfy the "
            "conditions in the trace to reach the SINK.\n\n"
            + path_desc
            + context
        )

        try:
            raw = self.llm_call(_INPUT_GEN_SYSTEM, user_msg)
            return _parse_inputs_response(raw)
        except Exception as exc:
            logger.warning("Input generation failed: %s — using defaults", exc)
            return _default_inputs()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_c_code(raw: str) -> str:
    """Extract C source code from LLM response, stripping markdown fences."""
    raw = raw.strip()

    # Strip ```c ... ``` fences
    match = re.search(r'```(?:c|cpp)?\s*\n([\s\S]*?)\n\s*```', raw)
    if match:
        return match.group(1).strip()

    # If it starts with #include, it's already raw C
    if raw.startswith("#include") or raw.startswith("//"):
        return raw

    # Try finding the first #include
    idx = raw.find("#include")
    if idx >= 0:
        return raw[idx:].strip()

    # Last resort: return as-is
    return raw


def _parse_inputs_response(raw: str) -> list[dict[str, Any]]:
    """Parse the LLM's JSON response for test inputs."""
    raw = raw.strip()

    # Strip markdown fences
    match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', raw)
    if match:
        raw = match.group(1)

    # Find JSON object
    start = raw.find("{")
    end = raw.rfind("}")
    if start >= 0 and end > start:
        raw = raw[start:end + 1]

    try:
        data = json.loads(raw)
        inputs = data.get("inputs", [])
        if isinstance(inputs, list) and inputs:
            return inputs
    except json.JSONDecodeError:
        pass

    return _default_inputs()


def _default_inputs() -> list[dict[str, Any]]:
    """Fallback inputs when LLM generation fails."""
    return [
        {"description": "empty input", "data": "", "hex": False},
        {"description": "single char A", "data": "A", "hex": False},
        {"description": "backspace char", "data": "08", "hex": True},
        {"description": "return char (0x0D)", "data": "0D", "hex": True},
        {"description": "long string 256 bytes", "data": "A" * 256, "hex": False},
        {"description": "long string 1024 bytes", "data": "A" * 1024, "hex": False},
        {"description": "long string 4096 bytes", "data": "A" * 4096, "hex": False},
        {"description": "null bytes", "data": "00" * 64, "hex": True},
        {"description": "format string", "data": "%s%s%s%s%s%s%s%s%s%s", "hex": False},
        {"description": "ANSI charset marker + long payload",
         "data": "01" + "41" * 512, "hex": True},
    ]

#src\deeptrace\exploit\real_harness_generator.py
"""Generic real harness generator for ANY repository.

Uses RepoProfile to understand the target repo's build system, headers,
and API surface. Produces: harness C++, libFuzzer harness, Dockerfile,
run.sh, seed_info.json, README.md.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Callable

from deeptrace.exploit.repo_analyzer import RepoProfile, analyze_repo
from deeptrace.models.graph import TracePath

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are an expert security researcher writing REAL exploit harnesses
that link against actual compiled libraries — NOT stub/mock code.

You will receive:
1. Repository profile: build system, public headers, API samples, existing fuzz harnesses.
2. A vulnerability trace showing the call chain from a public API to a dangerous sink.

Write a SINGLE C or C++ file that:
1. #includes ONLY real headers from the target library (shown in the profile).
2. Reads an input FILE from argv[1] via fopen/fread into a malloc'd buffer.
3. Calls REAL public API functions to initialize the library and process the input,
   driving execution toward the sink shown in the trace.
4. Contains ZERO stub/mock/fake function implementations.
5. Does NOT use memcpy/strcpy/sprintf in the harness — crashes must happen inside
   the library code, not in the harness.
6. Cleans up resources so ASAN leak detection works.
7. If the profile includes an existing fuzz harness, use it as structural reference.

Output ONLY the code. No markdown fences. No explanations."""

_LIBFUZZER_SYSTEM = """You are writing a libFuzzer harness for a C/C++ library.
Write: int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
Initialize the library lazily. Feed raw data to the parsing API.
Drive toward the vulnerable sink. Return 0. No stubs.
Output ONLY code. No markdown."""

_SEED_SYSTEM = """Describe what a seed input file must contain to exercise a vulnerability path.
Respond ONLY with JSON:
{"file_type":"<ext>","description":"<what it needs>","structure":["<req1>","<req2>"],
"known_test_files":["<repo paths>"],"generation_script":"<optional python>"}"""


def analyze_trace(path: TracePath) -> dict[str, Any]:
    steps = path.steps
    if not steps:
        return {}

    files, call_chain, conditions, api_hints = set(), [], [], []

    for step in steps:
        if step.location and step.location.file:
            files.add(step.location.file)
        name = (step.node_name or "").split("|")[0].strip()
        if name and name not in call_chain and len(name) > 2:
            call_chain.append(name)
        code = step.code_snippet or ""
        if any(kw in code for kw in ("if (", "if(", "ASSERT", "EXPECT", "while (", "for (")):
            conditions.append(code.strip())
        f = step.location.file if step.location else ""
        if any(d in f for d in ("public/", "include/", "api/")):
            api_hints.append(name)

    first, last = steps[0], steps[-1]
    all_text = " ".join((s.code_snippet or "") + " " + (s.location.file if s.location else "") for s in steps).lower()
    file_type = "binary"
    for kw, ft in [("pdf","pdf"),("xml","xml"),("xfa","xml"),("png","png"),("jpeg","jpg"),
                    ("image","png"),("font","ttf"),("html","html"),("json","json"),("svg","svg")]:
        if kw in all_text:
            file_type = ft
            break

    return {
        "entry_file": first.location.file if first.location else "",
        "sink_file": last.location.file if last.location else "",
        "sink_line": last.location.line if last.location else 0,
        "sink_code": last.code_snippet or "",
        "call_chain": call_chain, "conditions": conditions,
        "files": sorted(files), "file_type": file_type,
        "api_hints": api_hints, "vuln_tags": path.vulnerability_tags or [],
    }


class RealHarnessGenerator:
    def __init__(self, llm_caller: Callable[[str, str], str], repo_path: str,
                 profile: RepoProfile | None = None) -> None:
        self.llm_call = llm_caller
        self.repo_path = os.path.abspath(repo_path)
        if profile is None:
            logger.info("Analyzing repository structure...")
            self.profile = analyze_repo(repo_path)
        else:
            self.profile = profile

    def generate(self, path: TracePath, path_index: int, output_dir: str,
                 include_libfuzzer: bool = True) -> dict[str, str]:
        os.makedirs(output_dir, exist_ok=True)
        analysis = analyze_trace(path)
        if not analysis:
            return {}

        p = self.profile
        lang_ext = "cpp" if p.language in ("cpp", "c") else "cpp"
        files: dict[str, str] = {}

        # 1. Main harness
        h = self._gen_harness(path, analysis)
        hf = f"harness_{path_index}.{lang_ext}"
        files[hf] = h
        _w(output_dir, hf, h)

        # 2. libFuzzer
        if include_libfuzzer:
            fz = self._gen_libfuzzer(path, analysis)
            ff = f"fuzz_{path_index}.cpp"
            files[ff] = fz
            _w(output_dir, ff, fz)

        # 3. Dockerfile
        df = self._gen_dockerfile(path_index, hf, analysis)
        files["Dockerfile"] = df
        _w(output_dir, "Dockerfile", df)

        # 4. run.sh
        rs = self._gen_run_script(path_index, hf, analysis)
        files["run.sh"] = rs
        _w(output_dir, "run.sh", rs)
        os.chmod(os.path.join(output_dir, "run.sh"), 0o755)

        # 5. seed_info.json
        si = self._gen_seed_info(path, analysis)
        files["seed_info.json"] = json.dumps(si, indent=2)
        _w(output_dir, "seed_info.json", json.dumps(si, indent=2))

        # 6. README
        rm = self._gen_readme(path_index, hf, analysis)
        files["README.md"] = rm
        _w(output_dir, "README.md", rm)

        logger.info("Path %d: wrote %d files to %s", path_index, len(files), output_dir)
        return files

    # ------ LLM calls ------

    def _gen_harness(self, path: TracePath, analysis: dict) -> str:
        ctx = self.profile.format_for_llm() + "\n\n" + _fmt_trace(path, analysis)
        try:
            raw = self.llm_call(_SYSTEM_PROMPT,
                f"Generate a C/C++ harness for {self.profile.repo_name}.\n\n{ctx}")
            return _code(raw)
        except Exception as e:
            logger.error("Harness gen failed: %s", e)
            return _fallback(self.profile, analysis)

    def _gen_libfuzzer(self, path: TracePath, analysis: dict) -> str:
        ctx = self.profile.format_for_llm() + "\n\n" + _fmt_trace(path, analysis)
        try:
            raw = self.llm_call(_LIBFUZZER_SYSTEM,
                f"Generate libFuzzer harness for {self.profile.repo_name}.\n\n{ctx}")
            return _code(raw)
        except Exception:
            return "// libFuzzer generation failed\n"

    def _gen_seed_info(self, path: TracePath, analysis: dict) -> dict:
        try:
            raw = self.llm_call(_SEED_SYSTEM,
                f"Trace in {self.profile.repo_name}:\n{_fmt_trace(path, analysis)}\n"
                f"Test files in repo: {self.profile.existing_test_files[:10]}")
            return _json(raw) or {"file_type": analysis["file_type"]}
        except Exception:
            return {"file_type": analysis["file_type"],
                    "known_test_files": self.profile.existing_test_files[:5]}

    # ------ Docker / scripts ------

    def _gen_dockerfile(self, idx: int, hf: str, analysis: dict) -> str:
        p = self.profile
        deps = " \\\n    ".join(p.system_deps) if p.system_deps else "build-essential"
        build = "\n".join(f"RUN cd /src/repo && {c}" for c in p.build_commands) or "# TODO: build commands"
        inc = " ".join(f"-I/src/repo/{d}" for d in p.public_header_dirs) or "-I/src/repo"

        if p.build_system == "cmake":
            lpath, lflags = "/src/repo/build", f"-l{p.library_name or 'target'}"
        elif p.build_system == "gn":
            lpath, lflags = "/src/repo/out/asan", f"-l{p.library_name or 'target'}"
        else:
            lpath, lflags = "/src/repo", f"-l{p.library_name or 'target'}"

        return f"""FROM {p.base_docker_image}
RUN apt-get update && apt-get install -y \\
    {deps} \\
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src/repo
COPY repo/ /src/repo/

{build}

WORKDIR /src
COPY {hf} /src/{hf}
RUN g++ -std=c++17 -fsanitize=address -g \\
    {inc} -I/src/repo \\
    /src/{hf} \\
    -L{lpath} {lflags} \\
    -lpthread -ldl -lm \\
    -o /src/harness 2>&1 || echo "COMPILE_FAILED"

ENV ASAN_OPTIONS=detect_leaks=0:print_stacktrace=1:halt_on_error=0
ENTRYPOINT ["/src/harness"]
"""

    def _gen_run_script(self, idx: int, hf: str, analysis: dict) -> str:
        p = self.profile
        ft = analysis["file_type"]
        return f"""#!/bin/bash
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="${{REPO_PATH:-{p.repo_path}}}"
SEED="${{1:-seed.{ft}}}"
IMG="deeptrace-harness-{idx}"

echo "=== DeepTrace Real Harness Runner ==="
echo "Repo: {p.repo_name} | Build: {p.build_system} | Input: {ft}"
echo ""

# Build everything in Docker
echo "[1/2] Building Docker image (repo with ASAN + harness)..."
docker build -f "$DIR/Dockerfile" --build-context repo="$REPO" -t "$IMG" "$DIR"

# Run
echo "[2/2] Running harness..."
docker run --rm \\
    -v "$(realpath "$SEED")":/input/seed.{ft}:ro \\
    --memory=1g --cpus=2 \\
    "$IMG" /input/seed.{ft} 2>&1 | tee "$DIR/output.txt"

echo ""
if grep -q "AddressSanitizer" "$DIR/output.txt"; then
    echo "🔴 CRASH — ASAN detected a bug!"
    grep -A 15 "ERROR: AddressSanitizer" "$DIR/output.txt"
elif grep -q "SINK_REACHED" "$DIR/output.txt"; then
    echo "🟡 SINK REACHED — path exercised, no crash"
else
    echo "⚪ No trigger — try different seed input (see seed_info.json)"
fi
"""

    def _gen_readme(self, idx: int, hf: str, analysis: dict) -> str:
        p = self.profile
        chain = " → ".join(analysis["call_chain"][:8])
        ft = analysis["file_type"]
        return f"""# Harness {idx} — {p.repo_name}

**Vuln:** {', '.join(analysis['vuln_tags']) or '?'} |
**Sink:** `{analysis['sink_file']}:{analysis['sink_line']}` |
**Chain:** {chain} |
**Input:** {ft} file

## Run (Docker — one command)
```bash
chmod +x run.sh
./run.sh path/to/seed.{ft}
```

## Run (manual)
```bash
# 1. Build {p.repo_name} with ASAN
cd {p.repo_path}
{chr(10).join(p.build_commands) or '# see Dockerfile'}

# 2. Compile harness
g++ -fsanitize=address -g {' '.join(f'-I{d}' for d in p.public_header_dirs)} \\
    {hf} -l{p.library_name or 'target'} -o harness_{idx}

# 3. Run
ASAN_OPTIONS=detect_leaks=0 ./harness_{idx} seed.{ft}
```

## Validate
| Crash in... | Means |
|---|---|
| {p.repo_name} code | ✅ Real vulnerability |
| harness code | ❌ Harness bug |
| No crash | Try other seeds |
"""


# ---- Helpers ----

def _fmt_trace(path: TracePath, analysis: dict) -> str:
    lines = [f"Vuln: {', '.join(analysis['vuln_tags'])}",
             f"Input: {analysis['file_type']}",
             f"Chain: {' → '.join(analysis['call_chain'])}",
             f"Sink: {analysis['sink_file']}:{analysis['sink_line']} — {analysis['sink_code'][:100]}",
             "", "Steps:"]
    for i, s in enumerate(path.steps):
        loc = f"{s.location.file}:{s.location.line}" if s.location else "?"
        edge = f" [{s.edge_kind}]" if s.edge_kind else ""
        sink = " [SINK]" if i == len(path.steps) - 1 else ""
        lines.append(f"  {i}{sink}{edge}: {loc} — {s.code_snippet or '?'}")
    return "\n".join(lines)

def _fallback(profile: RepoProfile, analysis: dict) -> str:
    hdrs = "\n".join(f'#include "{h}"' for h in profile.key_headers[:5]) or "// TODO: headers"
    return f"""// TEMPLATE — LLM failed. Fill in API calls manually.
// Chain: {' → '.join(analysis.get('call_chain',[])[:8])}
// Sink: {analysis.get('sink_file','?')}:{analysis.get('sink_line','?')}
{hdrs}
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char* argv[]) {{
    if (argc < 2) {{ fprintf(stderr, "Usage: %s <input>\\n", argv[0]); return 1; }}
    FILE* f = fopen(argv[1], "rb");
    if (!f) {{ perror("fopen"); return 1; }}
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char* buf = (unsigned char*)malloc(sz);
    fread(buf, 1, sz, f); fclose(f);
    // TODO: init library, feed buf/sz, drive to sink
    free(buf); return 0;
}}
"""

def _code(raw: str) -> str:
    raw = raw.strip()
    m = re.search(r'```(?:c|cpp|c\+\+)?\s*\n([\s\S]*?)\n\s*```', raw)
    if m: return m.group(1).strip()
    if raw.startswith("#include") or raw.startswith("//"): return raw
    idx = raw.find("#include")
    return raw[idx:].strip() if idx >= 0 else raw

def _json(raw: str) -> dict | None:
    raw = raw.strip()
    m = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', raw)
    if m: raw = m.group(1)
    s, e = raw.find("{"), raw.rfind("}")
    if s >= 0 and e > s:
        try: return json.loads(raw[s:e+1])
        except json.JSONDecodeError: pass
    return None

def _w(d: str, f: str, c: str) -> None:
    Path(os.path.join(d, f)).write_text(c, encoding="utf-8")

#src\deeptrace\exploit\report_generator.py
"""Vulnerability report generator.

Produces a Markdown report for each validated trace path, containing:
  - Flow summary and vulnerability description
  - Generated C harness code
  - Execution results (which inputs triggered the sink/crash)
  - Exploitability assessment
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from deeptrace.exploit.sandbox_runner import ValidationResult, RunResult
from deeptrace.models.graph import TracePath

logger = logging.getLogger(__name__)


def generate_report(
    path: TracePath,
    result: ValidationResult,
    repo_name: str = "",
) -> str:
    """Generate a Markdown vulnerability report for one trace path.

    Args:
        path: The original TracePath from traces.json.
        result: The ValidationResult from the exploit validator.
        repo_name: Name of the repository being analyzed.

    Returns:
        Complete Markdown document as a string.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    vuln_tags = ", ".join(path.vulnerability_tags) if path.vulnerability_tags else "unknown"
    status = _status_badge(result)

    # --- Header ---
    lines = [
        f"# Vulnerability Report — Path {result.path_index}",
        "",
        f"**Generated:** {now}  ",
        f"**Repository:** {repo_name or 'unknown'}  ",
        f"**Status:** {status}  ",
        f"**Path ID:** `{result.path_id}`  ",
        f"**Vulnerability Type:** {vuln_tags}  ",
        f"**LLM Rank:** {path.llm_rank or 'N/A'}  ",
        f"**Z3 Satisfiable:** {path.is_satisfiable}  ",
        "",
        "---",
        "",
    ]

    # --- Executive Summary ---
    lines += [
        "## Executive Summary",
        "",
    ]
    if result.sink_triggered or result.crash_triggered:
        lines.append(
            f"**CONFIRMED**: The vulnerability was successfully triggered. "
            f"{'A ' + result.crash_type + ' crash was detected.' if result.crash_triggered else 'The sink was reached.'}"
        )
    else:
        lines.append(
            "**UNCONFIRMED**: The generated harness did not trigger the sink "
            "with the tested inputs. This does not mean the vulnerability is "
            "unexploitable — it may require more sophisticated input crafting."
        )
    lines += ["", ""]

    # --- Vulnerability Description ---
    lines += [
        "## Vulnerability Description",
        "",
    ]
    if path.vulnerability_summary:
        lines.append(path.vulnerability_summary)
    elif path.llm_rationale:
        lines.append(path.llm_rationale)
    else:
        lines.append(f"A potential {vuln_tags} vulnerability was identified through "
                     "automated dependency tracing.")
    lines += ["", ""]

    # --- Data Flow Trace ---
    lines += [
        "## Data Flow Trace",
        "",
        f"The trace spans **{path.depth}** steps across "
        f"**{len(_unique_files(path))}** files:",
        "",
    ]
    for i, step in enumerate(path.steps):
        loc = step.location
        loc_str = f"`{loc.file}:{loc.line}`" if loc else "unknown"
        edge = f" ← *{step.edge_kind}*" if step.edge_kind else ""
        is_sink = (i == len(path.steps) - 1)
        marker = " **[SINK]**" if is_sink else ""

        lines.append(f"**Step {i}**{marker}{edge}  ")
        lines.append(f"Location: {loc_str}  ")
        if step.code_snippet:
            lines.append(f"```cpp")
            lines.append(step.code_snippet)
            lines.append(f"```")
        if step.annotation:
            lines.append(f"> {step.annotation[:300]}")
        lines.append("")

    lines.append("")

    # --- Generated Harness ---
    lines += [
        "## Generated C Harness",
        "",
        f"Repair attempts: {result.repair_attempts} | "
        f"LLM iterations: {result.llm_iterations} | "
        f"Compiled: {'Yes' if result.compile_success else 'No'}",
        "",
    ]
    if result.harness_code:
        lines += [
            "```c",
            result.harness_code,
            "```",
            "",
        ]
    else:
        lines.append("*No harness code was generated.*")
        lines.append("")

    # --- Execution Results ---
    lines += [
        "## Execution Results",
        "",
        f"Total runs: **{result.total_runs}**  ",
        f"Sink triggered: **{'Yes' if result.sink_triggered else 'No'}**  ",
        f"Crash detected: **{'Yes — ' + result.crash_type if result.crash_triggered else 'No'}**  ",
        "",
    ]

    if result.sink_triggered or result.crash_triggered:
        lines += [
            "### Triggering Input",
            "",
            f"**Description:** {result.triggering_input_desc}  ",
            f"**Size:** {len(result.triggering_input)} bytes  ",
            f"**Data (hex):** `{result.triggering_input[:64].hex()}`"
            + ("..." if len(result.triggering_input) > 64 else ""),
            "",
        ]

    # Run results table
    if result.all_run_results:
        lines += [
            "### All Test Runs",
            "",
            "| # | Input | Exit | Sink | Crash | Time |",
            "|---|-------|------|------|-------|------|",
        ]
        for i, rr in enumerate(result.all_run_results):
            sink_mark = "**YES**" if rr.sink_reached else "no"
            crash_mark = f"**{rr.crash_type}**" if rr.crash_detected else "no"
            lines.append(
                f"| {i} | {rr.input_desc[:30]} | {rr.exit_code} | "
                f"{sink_mark} | {crash_mark} | {rr.elapsed:.2f}s |"
            )
        lines += ["", ""]

    # --- ASAN Output (if crash) ---
    crash_runs = [r for r in result.all_run_results if r.crash_detected]
    if crash_runs:
        lines += [
            "### Crash Details",
            "",
        ]
        for cr in crash_runs[:3]:  # show at most 3 crash outputs
            lines += [
                f"**Input:** {cr.input_desc}  ",
                f"**Crash type:** {cr.crash_type}  ",
                "```",
                cr.stderr[:2000],
                "```",
                "",
            ]

    # --- Error Log ---
    if result.error_log:
        lines += [
            "## Error Log",
            "",
            "```",
            result.error_log[:3000],
            "```",
            "",
        ]

    # --- Recommendations ---
    lines += [
        "## Recommendations",
        "",
    ]
    if "buffer_overflow" in (path.vulnerability_tags or []):
        lines += [
            "1. Add bounds checking before the `memcpy`/`strcpy` at the sink.",
            "2. Use safe alternatives: `memcpy_s`, `strncpy`, or `std::copy` with size limits.",
            "3. Validate the size of source data before copying into fixed-size buffers.",
            "",
        ]
    elif "use_after_free" in (path.vulnerability_tags or []):
        lines += [
            "1. Set pointers to NULL after `free()`.",
            "2. Use smart pointers (`std::unique_ptr`, `std::shared_ptr`) to manage lifetime.",
            "3. Audit all code paths between allocation and use for early deallocation.",
            "",
        ]
    else:
        lines += [
            "1. Review the data flow from source to sink for missing validation.",
            "2. Add input sanitization at the boundary where external data enters.",
            "3. Consider fuzzing the affected function with the generated harness.",
            "",
        ]

    lines += [
        "---",
        f"*Report generated by DeepTrace v1.0.0*",
    ]

    return "\n".join(lines)


def generate_summary_report(
    all_results: list[tuple[TracePath, ValidationResult]],
    repo_name: str = "",
    output_dir: str = "",
) -> str:
    """Generate a summary report covering all validated paths.

    Args:
        all_results: List of (TracePath, ValidationResult) pairs.
        repo_name: Repository name.
        output_dir: Directory where individual reports were saved.

    Returns:
        Summary Markdown as a string.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(all_results)
    confirmed = sum(1 for _, r in all_results if r.sink_triggered or r.crash_triggered)
    compiled = sum(1 for _, r in all_results if r.compile_success)
    crashes = sum(1 for _, r in all_results if r.crash_triggered)

    lines = [
        "# DeepTrace Validation Summary",
        "",
        f"**Generated:** {now}  ",
        f"**Repository:** {repo_name or 'unknown'}  ",
        f"**Total paths analyzed:** {total}  ",
        f"**Harnesses compiled:** {compiled}/{total}  ",
        f"**Vulnerabilities confirmed:** {confirmed}/{total}  ",
        f"**Crashes detected:** {crashes}/{total}  ",
        "",
        "---",
        "",
        "## Results by Path",
        "",
        "| Path | Rank | Type | Compiled | Sink | Crash | Report |",
        "|------|------|------|----------|------|-------|--------|",
    ]

    for path, result in all_results:
        vuln = ", ".join(path.vulnerability_tags)[:20] if path.vulnerability_tags else "?"
        compiled_str = "Yes" if result.compile_success else "No"
        sink_str = "**YES**" if result.sink_triggered else "no"
        crash_str = f"**{result.crash_type}**" if result.crash_triggered else "no"
        report_file = f"path_{result.path_index}_report.md"

        lines.append(
            f"| {result.path_index} | {path.llm_rank or '?'} | {vuln} | "
            f"{compiled_str} | {sink_str} | {crash_str} | [{report_file}]({report_file}) |"
        )

    lines += [
        "",
        "---",
        "",
    ]

    # Highlight confirmed vulnerabilities
    confirmed_results = [(p, r) for p, r in all_results if r.sink_triggered or r.crash_triggered]
    if confirmed_results:
        lines += [
            "## Confirmed Vulnerabilities",
            "",
        ]
        for path, result in confirmed_results:
            lines += [
                f"### Path {result.path_index} — {', '.join(path.vulnerability_tags) or '?'}",
                "",
                f"**Crash type:** {result.crash_type or 'sink reached (no crash)'}  ",
                f"**Triggering input:** {result.triggering_input_desc}  ",
                f"**Input size:** {len(result.triggering_input)} bytes  ",
                "",
            ]
            if path.vulnerability_summary:
                lines += [path.vulnerability_summary[:300], ""]
            lines.append("")

    lines += [
        "---",
        "*Generated by DeepTrace v1.0.0*",
    ]

    return "\n".join(lines)


def write_reports(
    all_results: list[tuple[TracePath, ValidationResult]],
    output_dir: str,
    repo_name: str = "",
) -> list[str]:
    """Write individual reports + summary to the output directory.

    Returns:
        List of file paths written.
    """
    os.makedirs(output_dir, exist_ok=True)
    written: list[str] = []

    # Individual reports
    for path, result in all_results:
        report = generate_report(path, result, repo_name)
        filename = f"path_{result.path_index}_report.md"
        filepath = os.path.join(output_dir, filename)
        Path(filepath).write_text(report, encoding="utf-8")
        written.append(filepath)
        logger.info("Wrote report: %s", filepath)

    # Summary report
    summary = generate_summary_report(all_results, repo_name, output_dir)
    summary_path = os.path.join(output_dir, "SUMMARY.md")
    Path(summary_path).write_text(summary, encoding="utf-8")
    written.append(summary_path)
    logger.info("Wrote summary: %s", summary_path)

    return written


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _status_badge(result: ValidationResult) -> str:
    if result.crash_triggered:
        return "🔴 CRASH CONFIRMED"
    if result.sink_triggered:
        return "🟡 SINK REACHED"
    if result.compile_success:
        return "⚪ UNCONFIRMED"
    return "⚫ COMPILE FAILED"


def _unique_files(path: TracePath) -> set[str]:
    files = set()
    for step in path.steps:
        if step.location and step.location.file:
            files.add(step.location.file)
    return files

#src\deeptrace\exploit\repo_analyzer.py
"""Repo analyzer: auto-detects build system, headers, and public API.

Scans a repository to discover:
  - Build system (CMake, Meson, Makefile, gn, Cargo, Maven, Gradle, setup.py)
  - Public header directories and key header files
  - Library name / target name
  - Language (C, C++, Rust, Java, etc.)
  - Existing test/fuzz harnesses for reference
  - Compile flags needed
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class RepoProfile:
    """Everything we know about a repository's build and API surface."""
    repo_path: str = ""
    repo_name: str = ""
    language: str = "cpp"                 # primary language

    # Build system
    build_system: str = ""                # cmake, meson, make, gn, cargo, maven, gradle, bazel
    build_files: list[str] = field(default_factory=list)  # paths to build config files

    # Headers / API
    public_header_dirs: list[str] = field(default_factory=list)  # e.g., ["include/", "public/"]
    key_headers: list[str] = field(default_factory=list)          # e.g., ["public/fpdfview.h"]
    header_snippets: dict[str, str] = field(default_factory=dict) # header_path → first 50 lines

    # Library
    library_name: str = ""                # e.g., "pdfium", "libxml2"
    library_targets: list[str] = field(default_factory=list)  # build targets

    # Existing harnesses/tests
    existing_fuzz_harnesses: list[str] = field(default_factory=list)
    existing_test_files: list[str] = field(default_factory=list)
    example_harness_snippet: str = ""     # content of best existing harness

    # Docker
    base_docker_image: str = "ubuntu:22.04"
    system_deps: list[str] = field(default_factory=list)  # apt packages needed
    build_commands: list[str] = field(default_factory=list)  # how to build with ASAN

    def format_for_llm(self) -> str:
        """Format the profile as context for the LLM harness generator."""
        lines = [
            f"Repository: {self.repo_name}",
            f"Language: {self.language}",
            f"Build system: {self.build_system}",
            f"Library: {self.library_name or '(unknown)'}",
            "",
        ]
        if self.public_header_dirs:
            lines.append(f"Public header directories: {', '.join(self.public_header_dirs)}")
        if self.key_headers:
            lines.append(f"Key headers to #include:")
            for h in self.key_headers[:10]:
                lines.append(f"  #include \"{h}\"")
        lines.append("")

        if self.header_snippets:
            lines.append("=== Public API samples (from headers) ===")
            for hdr, snippet in list(self.header_snippets.items())[:3]:
                lines.append(f"--- {hdr} ---")
                lines.append(snippet)
                lines.append("")

        if self.example_harness_snippet:
            lines.append("=== Existing harness/fuzz target in the repo (use as reference) ===")
            lines.append(self.example_harness_snippet)
            lines.append("")

        if self.existing_fuzz_harnesses:
            lines.append(f"Existing fuzz harnesses found: {', '.join(self.existing_fuzz_harnesses[:5])}")

        return "\n".join(lines)


def analyze_repo(repo_path: str) -> RepoProfile:
    """Analyze a repository and return a RepoProfile.

    This is a fast, non-compiling scan — it just reads files and directories.
    """
    repo_path = os.path.abspath(repo_path)
    profile = RepoProfile(
        repo_path=repo_path,
        repo_name=os.path.basename(repo_path),
    )

    # Detect build system
    _detect_build_system(profile)

    # Detect language
    _detect_language(profile)

    # Find public headers
    _find_public_headers(profile)

    # Find existing harnesses/tests
    _find_existing_harnesses(profile)

    # Infer library name
    _infer_library_name(profile)

    # Determine Docker base image and deps
    _determine_docker_config(profile)

    # Generate build commands
    _generate_build_commands(profile)

    logger.info(
        "Repo profile: %s (%s, %s, headers=%d, fuzz=%d)",
        profile.repo_name, profile.language, profile.build_system,
        len(profile.key_headers), len(profile.existing_fuzz_harnesses),
    )

    return profile


# ---------------------------------------------------------------------------
# Detection functions
# ---------------------------------------------------------------------------

def _detect_build_system(profile: RepoProfile) -> None:
    """Detect which build system the repo uses."""
    repo = profile.repo_path
    checks = [
        ("CMakeLists.txt", "cmake"),
        ("meson.build", "meson"),
        ("BUILD.gn", "gn"),
        ("Cargo.toml", "cargo"),
        ("pom.xml", "maven"),
        ("build.gradle", "gradle"),
        ("build.gradle.kts", "gradle"),
        ("BUILD", "bazel"),
        ("WORKSPACE", "bazel"),
        ("setup.py", "setuptools"),
        ("pyproject.toml", "pyproject"),
        ("Makefile", "make"),
        ("GNUmakefile", "make"),
    ]

    for filename, system in checks:
        path = os.path.join(repo, filename)
        if os.path.exists(path):
            profile.build_system = system
            profile.build_files.append(filename)

    # Check for autotools
    if os.path.exists(os.path.join(repo, "configure.ac")) or os.path.exists(os.path.join(repo, "configure")):
        if not profile.build_system:
            profile.build_system = "autotools"
            profile.build_files.append("configure.ac")


def _detect_language(profile: RepoProfile) -> None:
    """Detect the primary language from file extensions."""
    ext_counts: dict[str, int] = {}
    for root, dirs, files in os.walk(profile.repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in _LANG_MAP:
                ext_counts[ext] = ext_counts.get(ext, 0) + 1
        if sum(ext_counts.values()) > 5000:
            break  # enough samples

    if not ext_counts:
        return

    # Most common extension → language
    best_ext = max(ext_counts, key=lambda e: ext_counts[e])
    profile.language = _LANG_MAP.get(best_ext, "cpp")


def _find_public_headers(profile: RepoProfile) -> None:
    """Find public/API header directories and key header files."""
    repo = profile.repo_path

    # Check common header directory names
    header_dirs = ["include", "public", "api", "src/include",
                   "inc", "include/public", "lib/include"]

    for d in header_dirs:
        full = os.path.join(repo, d)
        if os.path.isdir(full):
            profile.public_header_dirs.append(d)
            # Collect header files
            for root, _, files in os.walk(full):
                for f in files:
                    if f.endswith((".h", ".hpp", ".hxx")):
                        rel = os.path.relpath(os.path.join(root, f), repo).replace("\\", "/")
                        profile.key_headers.append(rel)

    # Cap headers and read snippets from the most important ones
    profile.key_headers = profile.key_headers[:30]

    for hdr in profile.key_headers[:5]:
        abs_path = os.path.join(repo, hdr)
        try:
            text = Path(abs_path).read_text(encoding="utf-8", errors="replace")
            # Extract first 80 lines (function declarations, typedefs)
            first_lines = "\n".join(text.split("\n")[:80])
            profile.header_snippets[hdr] = first_lines
        except OSError:
            pass


def _find_existing_harnesses(profile: RepoProfile) -> None:
    """Find existing fuzz harnesses and test files for reference."""
    repo = profile.repo_path

    fuzz_patterns = ["fuzz", "fuzzer", "harness", "afl", "libfuzzer"]
    test_patterns = ["test", "Test", "_test", "_unittest"]

    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        rel_root = os.path.relpath(root, repo).replace("\\", "/")

        for f in files:
            if not f.endswith((".c", ".cc", ".cpp", ".cxx", ".h")):
                continue

            rel_path = os.path.join(rel_root, f).replace("\\", "/")

            # Fuzz harnesses
            if any(p in f.lower() or p in rel_root.lower() for p in fuzz_patterns):
                profile.existing_fuzz_harnesses.append(rel_path)

            # Test files
            if any(p in f for p in test_patterns):
                profile.existing_test_files.append(rel_path)

    # Read the best existing fuzz harness as a reference
    profile.existing_fuzz_harnesses = profile.existing_fuzz_harnesses[:20]
    profile.existing_test_files = profile.existing_test_files[:20]

    if profile.existing_fuzz_harnesses:
        best = profile.existing_fuzz_harnesses[0]
        abs_path = os.path.join(repo, best)
        try:
            text = Path(abs_path).read_text(encoding="utf-8", errors="replace")
            profile.example_harness_snippet = f"// From: {best}\n" + text[:3000]
        except OSError:
            pass


def _infer_library_name(profile: RepoProfile) -> None:
    """Infer the library name from build files or directory name."""
    repo = profile.repo_path

    # Try CMakeLists.txt
    cmake_path = os.path.join(repo, "CMakeLists.txt")
    if os.path.exists(cmake_path):
        try:
            text = Path(cmake_path).read_text(encoding="utf-8", errors="replace")
            m = re.search(r'project\s*\(\s*(\w+)', text, re.IGNORECASE)
            if m:
                profile.library_name = m.group(1).lower()
                return
            m = re.search(r'add_library\s*\(\s*(\w+)', text)
            if m:
                profile.library_name = m.group(1).lower()
                return
        except OSError:
            pass

    # Try Cargo.toml
    cargo_path = os.path.join(repo, "Cargo.toml")
    if os.path.exists(cargo_path):
        try:
            text = Path(cargo_path).read_text(encoding="utf-8", errors="replace")
            m = re.search(r'name\s*=\s*"(\w+)"', text)
            if m:
                profile.library_name = m.group(1)
                return
        except OSError:
            pass

    # Fallback: directory name
    profile.library_name = profile.repo_name.lower().replace("-", "").replace("_", "")


def _determine_docker_config(profile: RepoProfile) -> None:
    """Determine the Docker base image and system dependencies."""
    lang = profile.language
    build = profile.build_system

    # Base image
    if lang in ("c", "cpp"):
        profile.base_docker_image = "ubuntu:22.04"
        profile.system_deps = [
            "build-essential", "cmake", "ninja-build", "git", "pkg-config",
            "python3", "wget", "curl",
        ]
    elif lang == "rust":
        profile.base_docker_image = "rust:latest"
        profile.system_deps = ["build-essential", "cmake", "pkg-config"]
    elif lang in ("java", "kotlin"):
        profile.base_docker_image = "eclipse-temurin:17"
        profile.system_deps = ["build-essential"]
    else:
        profile.base_docker_image = "ubuntu:22.04"
        profile.system_deps = ["build-essential", "cmake"]

    # Build-system-specific deps
    if build == "meson":
        profile.system_deps.append("meson")
    if build == "gn":
        profile.system_deps.append("python3")  # gn needs python
    if build == "bazel":
        profile.system_deps.append("bazel")

    # Common library deps for C/C++ projects
    if lang in ("c", "cpp"):
        profile.system_deps += ["libfreetype-dev", "libpng-dev", "zlib1g-dev"]


def _generate_build_commands(profile: RepoProfile) -> None:
    """Generate shell commands to build the repo with ASAN."""
    lang = profile.language
    build = profile.build_system
    name = profile.library_name

    if build == "cmake":
        profile.build_commands = [
            f'cmake -B build -DCMAKE_C_FLAGS="-fsanitize=address -g" '
            f'-DCMAKE_CXX_FLAGS="-fsanitize=address -g" '
            f'-DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" .',
            "cmake --build build -j$(nproc)",
        ]
    elif build == "meson":
        profile.build_commands = [
            'meson setup build -Db_sanitize=address -Dbuildtype=debug',
            'ninja -C build',
        ]
    elif build == "make":
        profile.build_commands = [
            'make CFLAGS="-fsanitize=address -g" CXXFLAGS="-fsanitize=address -g" '
            'LDFLAGS="-fsanitize=address" -j$(nproc)',
        ]
    elif build == "gn":
        profile.build_commands = [
            f'gn gen out/asan --args=\'is_asan=true is_debug=true\'',
            f'ninja -C out/asan {name}',
        ]
    elif build == "cargo":
        profile.build_commands = [
            'RUSTFLAGS="-Z sanitizer=address" cargo build --target x86_64-unknown-linux-gnu',
        ]
    elif build == "autotools":
        profile.build_commands = [
            './configure CFLAGS="-fsanitize=address -g" CXXFLAGS="-fsanitize=address -g" '
            'LDFLAGS="-fsanitize=address"',
            'make -j$(nproc)',
        ]
    else:
        profile.build_commands = [
            "# Unknown build system — customize these commands:",
            'make CFLAGS="-fsanitize=address -g" CXXFLAGS="-fsanitize=address -g" -j$(nproc)',
        ]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SKIP_DIRS = {
    ".git", "node_modules", "build", "out", "target", "dist",
    ".cache", "__pycache__", ".venv", "venv", "vendor",
    "third_party", "3rdparty", "external", "deps",
}

_LANG_MAP = {
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hh": "cpp", ".hpp": "cpp", ".hxx": "cpp",
    ".java": "java",
    ".kt": "kotlin",
    ".rs": "rust",
    ".py": "python",
    ".swift": "swift",
    ".m": "objc", ".mm": "objc",
}

#src\deeptrace\exploit\sandbox_runner.py
"""Docker sandbox for compiling and running C harness programs.

Provides a safe execution environment using Docker containers.
Supports both Docker-based and local (fallback) execution for
platforms where Docker is not available.
"""

from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Docker image with gcc + ASAN support
_DEFAULT_IMAGE = "gcc:13"
_COMPILE_TIMEOUT = 30   # seconds
_RUN_TIMEOUT = 10       # seconds per input


@dataclass
class CompileResult:
    """Result of compiling a C harness."""
    success: bool = False
    stdout: str = ""
    stderr: str = ""
    binary_path: str = ""    # path to compiled binary (inside container or local)
    elapsed: float = 0.0


@dataclass
class RunResult:
    """Result of running a compiled harness with one input."""
    input_desc: str = ""
    input_data: bytes = b""
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    sink_reached: bool = False
    crash_detected: bool = False
    crash_type: str = ""          # "asan", "segfault", "abort", etc.
    elapsed: float = 0.0


@dataclass
class ValidationResult:
    """Full result of validating one trace path."""
    path_index: int = 0
    path_id: str = ""
    harness_code: str = ""        # final C source
    compile_success: bool = False
    total_runs: int = 0
    sink_triggered: bool = False
    crash_triggered: bool = False
    triggering_input: bytes = b""
    triggering_input_desc: str = ""
    crash_type: str = ""
    all_run_results: list[RunResult] = field(default_factory=list)
    repair_attempts: int = 0
    llm_iterations: int = 0
    error_log: str = ""


class SandboxRunner:
    """Compiles and runs C harnesses in a Docker container or locally."""

    def __init__(
        self,
        docker_image: str = _DEFAULT_IMAGE,
        use_docker: bool = True,
        compile_timeout: int = _COMPILE_TIMEOUT,
        run_timeout: int = _RUN_TIMEOUT,
    ) -> None:
        self.docker_image = docker_image
        self.compile_timeout = compile_timeout
        self.run_timeout = run_timeout

        # Auto-detect Docker availability
        if use_docker:
            self.use_docker = self._docker_available()
            if not self.use_docker:
                logger.info(
                    "Docker not available — using local gcc "
                    "(install Docker for sandboxed execution)"
                )
        else:
            self.use_docker = False

        self._work_dir = tempfile.mkdtemp(prefix="deeptrace_exploit_")
        self._container_id: str | None = None

    def cleanup(self) -> None:
        """Stop container and clean up temp files."""
        if self._container_id:
            try:
                subprocess.run(
                    ["docker", "stop", self._container_id],
                    capture_output=True, timeout=15,
                )
            except Exception:
                pass
            self._container_id = None
        try:
            shutil.rmtree(self._work_dir, ignore_errors=True)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Compile
    # ------------------------------------------------------------------

    def compile_harness(self, c_source: str, harness_id: str = "harness") -> CompileResult:
        """Compile a C harness with gcc + AddressSanitizer.

        Args:
            c_source: The C source code to compile.
            harness_id: Base name for the source/binary files.

        Returns:
            CompileResult with success/failure and error messages.
        """
        # Write source to work dir
        src_path = os.path.join(self._work_dir, f"{harness_id}.c")
        bin_name = f"{harness_id}.bin"
        bin_path = os.path.join(self._work_dir, bin_name)

        Path(src_path).write_text(c_source, encoding="utf-8")

        t0 = time.time()

        if self.use_docker:
            result = self._compile_docker(src_path, bin_name)
        else:
            result = self._compile_local(src_path, bin_path)

        result.elapsed = time.time() - t0

        if result.success:
            logger.debug("Compiled %s in %.1fs", harness_id, result.elapsed)
        else:
            logger.debug(
                "Compilation failed for %s: %s",
                harness_id, result.stderr[:300],
            )

        return result

    def _compile_docker(self, src_path: str, bin_name: str) -> CompileResult:
        """Compile inside Docker container."""
        cid = self._ensure_container()
        src_filename = os.path.basename(src_path)

        # Copy source into container
        try:
            subprocess.run(
                ["docker", "cp", src_path, f"{cid}:/work/{src_filename}"],
                capture_output=True, timeout=10, check=True,
            )
        except Exception as exc:
            return CompileResult(success=False, stderr=f"Failed to copy source: {exc}")

        # Compile with ASAN
        cmd = (
            f"gcc -fsanitize=address -g -std=c17 -Wall "
            f"-o /work/{bin_name} /work/{src_filename} -lm 2>&1"
        )
        try:
            proc = subprocess.run(
                ["docker", "exec", cid, "bash", "-c", cmd],
                capture_output=True, text=True, timeout=self.compile_timeout,
            )
            if proc.returncode == 0:
                return CompileResult(
                    success=True, stdout=proc.stdout, stderr=proc.stderr,
                    binary_path=f"/work/{bin_name}",
                )
            return CompileResult(
                success=False, stdout=proc.stdout,
                stderr=proc.stdout + proc.stderr,
            )
        except subprocess.TimeoutExpired:
            return CompileResult(success=False, stderr="Compilation timed out")

    def _compile_local(self, src_path: str, bin_path: str) -> CompileResult:
        """Compile locally with gcc."""
        gcc = self._find_gcc()
        if not gcc:
            return CompileResult(success=False, stderr="gcc not found on this system")

        cmd = [gcc, "-fsanitize=address", "-g", "-std=c17", "-Wall",
               "-o", bin_path, src_path, "-lm"]

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.compile_timeout,
            )
            if proc.returncode == 0:
                return CompileResult(
                    success=True, stdout=proc.stdout, stderr=proc.stderr,
                    binary_path=bin_path,
                )
            return CompileResult(
                success=False, stdout=proc.stdout,
                stderr=proc.stdout + proc.stderr,
            )
        except subprocess.TimeoutExpired:
            return CompileResult(success=False, stderr="Compilation timed out")
        except FileNotFoundError:
            return CompileResult(success=False, stderr=f"gcc not found at {gcc}")

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run_harness(
        self,
        compile_result: CompileResult,
        input_data: bytes,
        input_desc: str = "",
    ) -> RunResult:
        """Run a compiled harness with the given input.

        Args:
            compile_result: Result from compile_harness (contains binary path).
            input_data: Raw bytes to feed to stdin.
            input_desc: Human-readable description of the input.

        Returns:
            RunResult with exit code, output, crash detection, etc.
        """
        if not compile_result.success:
            return RunResult(
                input_desc=input_desc, input_data=input_data,
                exit_code=-1, stderr="Binary not compiled",
            )

        t0 = time.time()

        if self.use_docker:
            result = self._run_docker(compile_result.binary_path, input_data, input_desc)
        else:
            result = self._run_local(compile_result.binary_path, input_data, input_desc)

        result.elapsed = time.time() - t0

        # Detect sink/crash from output
        result.sink_reached = "SINK_REACHED" in result.stderr
        result.crash_detected, result.crash_type = _detect_crash(
            result.exit_code, result.stderr,
        )

        return result

    def _run_docker(
        self, binary_path: str, input_data: bytes, input_desc: str,
    ) -> RunResult:
        """Run inside Docker container."""
        cid = self._ensure_container()

        try:
            proc = subprocess.run(
                ["docker", "exec", "-i", cid, binary_path],
                input=input_data,
                capture_output=True,
                timeout=self.run_timeout,
            )
            return RunResult(
                input_desc=input_desc, input_data=input_data,
                exit_code=proc.returncode,
                stdout=proc.stdout.decode("utf-8", errors="replace")[:5000],
                stderr=proc.stderr.decode("utf-8", errors="replace")[:5000],
            )
        except subprocess.TimeoutExpired:
            return RunResult(
                input_desc=input_desc, input_data=input_data,
                exit_code=-1, stderr="Execution timed out",
            )

    def _run_local(
        self, binary_path: str, input_data: bytes, input_desc: str,
    ) -> RunResult:
        """Run locally."""
        env = os.environ.copy()
        env["ASAN_OPTIONS"] = "detect_leaks=0:print_stacktrace=1"

        try:
            proc = subprocess.run(
                [binary_path],
                input=input_data,
                capture_output=True,
                timeout=self.run_timeout,
                env=env,
            )
            return RunResult(
                input_desc=input_desc, input_data=input_data,
                exit_code=proc.returncode,
                stdout=proc.stdout.decode("utf-8", errors="replace")[:5000],
                stderr=proc.stderr.decode("utf-8", errors="replace")[:5000],
            )
        except subprocess.TimeoutExpired:
            return RunResult(
                input_desc=input_desc, input_data=input_data,
                exit_code=-1, stderr="Execution timed out",
            )
        except OSError as exc:
            return RunResult(
                input_desc=input_desc, input_data=input_data,
                exit_code=-1, stderr=f"Execution failed: {exc}",
            )

    # ------------------------------------------------------------------
    # Docker management
    # ------------------------------------------------------------------

    def _ensure_container(self) -> str:
        """Start or reuse a Docker container."""
        if self._container_id:
            return self._container_id

        try:
            proc = subprocess.run(
                [
                    "docker", "run", "-d", "--rm",
                    "--name", f"deeptrace-exploit-{os.getpid()}",
                    "-v", f"{self._work_dir}:/work",
                    "--memory=512m", "--cpus=2",
                    "--security-opt", "no-new-privileges",
                    self.docker_image,
                    "tail", "-f", "/dev/null",
                ],
                capture_output=True, text=True, timeout=60,
            )
            self._container_id = proc.stdout.strip()[:12]
            logger.info("Started exploit sandbox container: %s", self._container_id)
            return self._container_id
        except Exception as exc:
            raise RuntimeError(f"Failed to start Docker container: {exc}") from exc

    @staticmethod
    def _docker_available() -> bool:
        try:
            proc = subprocess.run(
                ["docker", "info"], capture_output=True, timeout=5,
            )
            return proc.returncode == 0
        except Exception:
            return False

    @staticmethod
    def _find_gcc() -> str | None:
        """Find gcc on the system."""
        for candidate in ["gcc", "gcc-13", "gcc-12", "gcc-11", "cc"]:
            path = shutil.which(candidate)
            if path:
                return path
        return None


# ---------------------------------------------------------------------------
# Crash detection
# ---------------------------------------------------------------------------

def _detect_crash(exit_code: int, stderr: str) -> tuple[bool, str]:
    """Detect if the program crashed and classify the crash type."""
    stderr_lower = stderr.lower()

    # AddressSanitizer
    if "addresssanitizer" in stderr_lower or "asan" in stderr_lower:
        if "heap-buffer-overflow" in stderr_lower:
            return True, "asan_heap_buffer_overflow"
        if "stack-buffer-overflow" in stderr_lower:
            return True, "asan_stack_buffer_overflow"
        if "heap-use-after-free" in stderr_lower:
            return True, "asan_use_after_free"
        if "global-buffer-overflow" in stderr_lower:
            return True, "asan_global_buffer_overflow"
        if "stack-overflow" in stderr_lower:
            return True, "asan_stack_overflow"
        return True, "asan_other"

    # Signal-based crashes
    if exit_code == -11 or exit_code == 139:  # SIGSEGV
        return True, "segfault"
    if exit_code == -6 or exit_code == 134:   # SIGABRT
        return True, "abort"
    if exit_code == -8 or exit_code == 136:   # SIGFPE
        return True, "fpe"

    # Windows-style crash codes
    if exit_code < 0 and exit_code not in (-1,):
        return True, f"signal_{abs(exit_code)}"

    return False, ""


def prepare_input(input_spec: dict[str, Any]) -> bytes:
    """Convert an input specification to raw bytes.

    Args:
        input_spec: {"data": "...", "hex": bool, "description": "..."}

    Returns:
        Raw bytes to feed to stdin.
    """
    data = input_spec.get("data", "")
    is_hex = input_spec.get("hex", False)

    if is_hex:
        try:
            # Remove spaces and decode hex
            clean = data.replace(" ", "").replace("\n", "")
            return bytes.fromhex(clean)
        except ValueError:
            return data.encode("utf-8", errors="replace")
    else:
        if isinstance(data, bytes):
            return data
        return data.encode("utf-8", errors="replace")

#src\deeptrace\exploit\validator.py
"""Exploit validator: orchestrates the generate → compile → run → refine loop.

For each trace path:
  1. LLM generates a C harness from the trace.
  2. Compile the harness (Docker or local gcc + ASAN).
  3. If compile fails → send errors to LLM for repair, retry.
  4. Run with LLM-generated + default inputs.
  5. If sink not reached → send results to LLM for input refinement, retry.
  6. Collect results, generate vulnerability report.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Callable

from deeptrace.exploit.harness_generator import HarnessGenerator
from deeptrace.exploit.report_generator import write_reports
from deeptrace.exploit.sandbox_runner import (
    CompileResult,
    SandboxRunner,
    ValidationResult,
    prepare_input,
)
from deeptrace.models.graph import TracePath, TraceOutput

logger = logging.getLogger(__name__)


class ExploitValidator:
    """Orchestrates the exploit validation pipeline for all trace paths.

    The loop for each path:

        ┌─ generate_harness (LLM)
        │     ↓
        ├─ compile → fails? → repair_harness (LLM) → compile again (max 3×)
        │     ↓
        ├─ generate_inputs (LLM)
        │     ↓
        ├─ run with each input → check for SINK_REACHED or ASAN crash
        │     ↓
        ├─ if no trigger → generate_inputs again with results context (max 3×)
        │     ↓
        └─ collect ValidationResult → generate report
    """

    def __init__(
        self,
        llm_caller: Callable[[str, str], str],
        sandbox: SandboxRunner | None = None,
        max_compile_retries: int = 3,
        max_input_rounds: int = 3,
        max_inputs_per_round: int = 10,
    ) -> None:
        """
        Args:
            llm_caller: A callable(system_prompt, user_message) -> str
            sandbox: SandboxRunner instance (created if None).
            max_compile_retries: Max LLM repair attempts for compile errors.
            max_input_rounds: Max rounds of input generation/execution.
            max_inputs_per_round: Max inputs to test per round.
        """
        self.harness_gen = HarnessGenerator(llm_caller)
        self.sandbox = sandbox or SandboxRunner()
        self.max_compile_retries = max_compile_retries
        self.max_input_rounds = max_input_rounds
        self.max_inputs_per_round = max_inputs_per_round

    def validate_all(
        self,
        trace_output: TraceOutput,
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> list[tuple[TracePath, ValidationResult]]:
        """Validate all paths in a TraceOutput.

        Args:
            trace_output: Parsed traces.json content.
            progress_callback: Called with (current_idx, total, status_msg).

        Returns:
            List of (TracePath, ValidationResult) pairs.
        """
        paths = trace_output.paths
        results: list[tuple[TracePath, ValidationResult]] = []

        for i, path in enumerate(paths):
            if progress_callback:
                progress_callback(i, len(paths), f"Validating path {i}...")

            logger.info(
                "=== Validating path %d/%d (id=%s, rank=%s, tags=%s) ===",
                i, len(paths), path.id[:8], path.llm_rank,
                path.vulnerability_tags,
            )

            try:
                result = self.validate_one(path, i)
            except Exception as exc:
                logger.error("Path %d validation failed: %s", i, exc)
                result = ValidationResult(
                    path_index=i, path_id=path.id,
                    error_log=str(exc),
                )

            results.append((path, result))

            # Log result
            status = "CRASH" if result.crash_triggered else (
                "SINK" if result.sink_triggered else "UNCONFIRMED"
            )
            logger.info(
                "  Path %d result: %s (compiled=%s, runs=%d, crash=%s)",
                i, status, result.compile_success,
                result.total_runs, result.crash_type or "none",
            )

        # Cleanup sandbox
        try:
            self.sandbox.cleanup()
        except Exception:
            pass

        return results

    def validate_one(
        self,
        path: TracePath,
        path_index: int,
    ) -> ValidationResult:
        """Validate a single trace path through the full pipeline.

        Returns:
            ValidationResult with all execution data.
        """
        result = ValidationResult(path_index=path_index, path_id=path.id)
        error_parts: list[str] = []

        # ---------------------------------------------------------------
        # Phase 1: Generate C harness
        # ---------------------------------------------------------------
        logger.info("  [1/3] Generating C harness...")
        try:
            code = self.harness_gen.generate_harness(path, path_index)
        except Exception as exc:
            error_parts.append(f"Harness generation failed: {exc}")
            result.error_log = "\n".join(error_parts)
            return result

        result.harness_code = code
        result.llm_iterations += 1

        # ---------------------------------------------------------------
        # Phase 2: Compile (with repair loop)
        # ---------------------------------------------------------------
        logger.info("  [2/3] Compiling harness...")
        compile_result = self._compile_with_retries(
            code, path_index, result, error_parts,
        )

        if not compile_result.success:
            error_parts.append("All compile attempts failed")
            result.error_log = "\n".join(error_parts)
            return result

        result.compile_success = True

        # ---------------------------------------------------------------
        # Phase 3: Run with inputs (iterative refinement)
        # ---------------------------------------------------------------
        logger.info("  [3/3] Running with inputs...")
        self._run_with_inputs(
            path, path_index, compile_result, result, error_parts,
        )

        result.error_log = "\n".join(error_parts)
        return result

    # ------------------------------------------------------------------
    # Phase 2: Compile with repair
    # ------------------------------------------------------------------

    def _compile_with_retries(
        self,
        code: str,
        path_index: int,
        result: ValidationResult,
        error_parts: list[str],
    ) -> CompileResult:
        """Try to compile; if it fails, ask LLM to repair and retry."""
        harness_id = f"harness_{path_index}"

        for attempt in range(1 + self.max_compile_retries):
            compile_result = self.sandbox.compile_harness(code, harness_id)

            if compile_result.success:
                if attempt > 0:
                    logger.info("    Compilation succeeded on repair attempt %d", attempt)
                return compile_result

            # Compilation failed
            if attempt < self.max_compile_retries:
                logger.info(
                    "    Compile failed (attempt %d/%d), asking LLM to repair...",
                    attempt + 1, self.max_compile_retries + 1,
                )
                error_parts.append(
                    f"Compile attempt {attempt + 1}: {compile_result.stderr[:500]}"
                )
                try:
                    code = self.harness_gen.repair_harness(
                        code, compile_result.stderr, attempt + 1,
                    )
                    result.harness_code = code
                    result.repair_attempts += 1
                    result.llm_iterations += 1
                except Exception as exc:
                    error_parts.append(f"LLM repair failed: {exc}")
                    break
            else:
                error_parts.append(
                    f"Final compile attempt failed: {compile_result.stderr[:500]}"
                )

        return CompileResult(success=False, stderr="All compile attempts failed")

    # ------------------------------------------------------------------
    # Phase 3: Run with inputs
    # ------------------------------------------------------------------

    def _run_with_inputs(
        self,
        path: TracePath,
        path_index: int,
        compile_result: CompileResult,
        result: ValidationResult,
        error_parts: list[str],
    ) -> None:
        """Generate inputs, run the harness, iterate if sink not reached."""
        previous_results: list[dict[str, Any]] = []

        for round_num in range(self.max_input_rounds):
            # Generate inputs (first round: fresh; later: adaptive)
            try:
                if round_num == 0:
                    input_specs = self.harness_gen.generate_inputs(path, path_index)
                else:
                    input_specs = self.harness_gen.generate_inputs(
                        path, path_index, previous_results,
                    )
                    result.llm_iterations += 1
            except Exception as exc:
                error_parts.append(f"Input generation round {round_num} failed: {exc}")
                from deeptrace.exploit.harness_generator import _default_inputs
                input_specs = _default_inputs()

            # Cap inputs per round
            input_specs = input_specs[:self.max_inputs_per_round]

            logger.info(
                "    Round %d: testing %d inputs...",
                round_num, len(input_specs),
            )

            # Run each input
            for input_spec in input_specs:
                input_data = prepare_input(input_spec)
                input_desc = input_spec.get("description", "?")

                run_result = self.sandbox.run_harness(
                    compile_result, input_data, input_desc,
                )
                result.all_run_results.append(run_result)
                result.total_runs += 1

                # Track for adaptive input generation
                previous_results.append({
                    "input_desc": input_desc,
                    "exit_code": run_result.exit_code,
                    "sink_reached": run_result.sink_reached,
                    "crash_detected": run_result.crash_detected,
                    "stderr": run_result.stderr[:200],
                })

                # Check success
                if run_result.sink_reached or run_result.crash_detected:
                    result.sink_triggered = result.sink_triggered or run_result.sink_reached
                    if run_result.crash_detected:
                        result.crash_triggered = True
                        result.crash_type = run_result.crash_type
                    result.triggering_input = input_data
                    result.triggering_input_desc = input_desc
                    logger.info(
                        "    SUCCESS: %s (input: %s)",
                        "crash" if run_result.crash_detected else "sink reached",
                        input_desc,
                    )

            # If we already have a trigger, stop
            if result.sink_triggered or result.crash_triggered:
                break

            if round_num < self.max_input_rounds - 1:
                logger.info(
                    "    No trigger in round %d — generating new inputs...",
                    round_num,
                )


# ---------------------------------------------------------------------------
# High-level entry point
# ---------------------------------------------------------------------------

def run_validation_pipeline(
    traces_json_path: str,
    output_dir: str,
    llm_caller: Callable[[str, str], str],
    max_compile_retries: int = 3,
    max_input_rounds: int = 3,
    use_docker: bool = True,
    docker_image: str = "gcc:13",
    progress_callback: Callable[[int, int, str], None] | None = None,
) -> list[str]:
    """Run the full validation pipeline from a traces.json file.

    Args:
        traces_json_path: Path to traces.json.
        output_dir: Directory to write reports into.
        llm_caller: LLM API caller function.
        max_compile_retries: Max repair attempts per harness.
        max_input_rounds: Max input generation rounds.
        use_docker: Whether to use Docker for sandboxing.
        docker_image: Docker image with gcc.
        progress_callback: Optional progress reporting.

    Returns:
        List of report file paths written.
    """
    # Load traces
    data = json.loads(Path(traces_json_path).read_text(encoding="utf-8"))
    trace_output = TraceOutput.model_validate(data)

    if not trace_output.paths:
        logger.warning("No paths found in %s", traces_json_path)
        return []

    logger.info(
        "Loaded %d paths from %s (target: %s)",
        len(trace_output.paths), traces_json_path, trace_output.target,
    )

    # Set up sandbox
    sandbox = SandboxRunner(
        docker_image=docker_image,
        use_docker=use_docker,
    )

    # Set up validator
    validator = ExploitValidator(
        llm_caller=llm_caller,
        sandbox=sandbox,
        max_compile_retries=max_compile_retries,
        max_input_rounds=max_input_rounds,
    )

    # Run validation
    all_results = validator.validate_all(trace_output, progress_callback)

    # Generate reports
    report_files = write_reports(
        all_results,
        output_dir=output_dir,
        repo_name=trace_output.repo,
    )

    # Summary
    confirmed = sum(1 for _, r in all_results if r.sink_triggered or r.crash_triggered)
    logger.info(
        "Validation complete: %d/%d confirmed, %d reports written to %s",
        confirmed, len(all_results), len(report_files), output_dir,
    )

    return report_files

#src\deeptrace\exploit\verification.py
"""GDB-based exploit verification.

Verifies that a harness actually reaches the vulnerable sink function
inside the REAL library code — not in the harness itself.

Verification methods:
  1. GDB breakpoint on the sink function → confirms the code path is exercised
  2. ASAN crash location check → confirms crash is in library, not harness
  3. Argument inspection at the sink → confirms attacker-controlled data
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
    asan_location: str = ""      # file:line of the crash
    asan_in_library: bool = False  # crash inside the target lib (not harness)
    asan_trace: str = ""

    # Overall
    confirmed: bool = False      # sink reached AND crash in library code
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
        if self.sink_reached:
            return "Sink reached but no crash — try different inputs"
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

    Args:
        env: Running Docker environment.
        harness_binary: Path to compiled harness binary inside container.
        input_file: Path to input file inside container.
        sink_function: Function name to set breakpoint on (e.g., "GetNativeFontName").
        sink_file: Source file containing the sink (for ASAN location check).
        library_name: Library name to check ASAN crash location against.
        timeout: Execution timeout in seconds.

    Returns:
        VerificationResult with detailed information about what happened.
    """
    result = VerificationResult()

    # Generate GDB script
    gdb_script = _generate_gdb_script(harness_binary, input_file, sink_function)
    env.write_file("/work/verify.gdb", gdb_script)

    # Run under GDB
    gdb_cmd = (
        f"gdb -batch -x /work/verify.gdb 2>&1; echo EXIT_CODE=$?"
    )

    logger.info("Running verification: breakpoint on %s", sink_function)
    exec_result = env.exec(gdb_cmd, timeout=timeout)

    result.raw_output = exec_result.output

    # Parse GDB output
    _parse_gdb_output(result, exec_result.output, sink_function)

    # Also run directly (without GDB) to get clean ASAN output
    direct_result = env.exec(
        f"{harness_binary} {input_file} 2>&1",
        timeout=timeout,
    )
    result.raw_output += "\n\n--- Direct run ---\n" + direct_result.output

    # Parse ASAN output
    _parse_asan_output(result, direct_result.output, sink_file, library_name)

    # Determine confirmation status
    if result.asan_crash and result.asan_in_library:
        result.confirmed = True
    elif result.asan_crash and not result.asan_in_library:
        result.harness_crashed_itself = True

    logger.info("Verification: %s", result.summary)
    return result


def _generate_gdb_script(binary: str, input_file: str, sink_function: str) -> str:
    """Generate a GDB batch script that sets a breakpoint on the sink."""
    return f"""# Auto-generated GDB verification script
set pagination off
set confirm off
set print thread-events off

# Load the binary
file {binary}

# Set breakpoint on the real sink function
break {sink_function}

# Run with the input
run {input_file}

# If we hit the breakpoint, print backtrace and continue
commands
  echo \\n=== SINK_BREAKPOINT_HIT ===\\n
  backtrace 20
  echo \\n=== END_BACKTRACE ===\\n
  continue
end

# Let it finish
continue
quit
"""


def _parse_gdb_output(result: VerificationResult, output: str, sink_function: str) -> None:
    """Parse GDB output for breakpoint hits and backtraces."""
    if "SINK_BREAKPOINT_HIT" in output:
        result.sink_reached = True
        result.sink_hit_count = output.count("SINK_BREAKPOINT_HIT")
        
        # Extract backtrace
        bt_match = re.search(
            r"=== SINK_BREAKPOINT_HIT ===\s*(.*?)=== END_BACKTRACE ===",
            output, re.DOTALL,
        )
        if bt_match:
            result.sink_backtrace = bt_match.group(1).strip()

    # Also check for signal delivery (crash)
    if "Program received signal" in output:
        sig_match = re.search(r"Program received signal (\w+)", output)
        if sig_match:
            result.asan_crash = True
            result.asan_crash_type = sig_match.group(1)


def _parse_asan_output(
    result: VerificationResult,
    output: str,
    sink_file: str,
    library_name: str,
) -> None:
    """Parse ASAN output to determine crash type and location."""
    # Check for ASAN errors
    asan_match = re.search(r"ERROR: AddressSanitizer: ([^\s:]+)", output)
    if asan_match:
        result.asan_crash = True
        result.asan_crash_type = asan_match.group(1)

    # Extract the crash stack trace
    trace_match = re.search(r"(#0.*?)(?:\n\n|\nSUMMARY:)", output, re.DOTALL)
    if trace_match:
        result.asan_trace = trace_match.group(1).strip()

    # Find the crash location (first frame with source info)
    # ASAN format: #N 0xaddr in function_name file.cpp:line
    frames = re.findall(r"#\d+\s+0x[\da-f]+\s+in\s+(\S+)\s+(\S+:\d+)", output)

    if frames:
        # First frame with a source file
        for func_name, file_loc in frames:
            result.asan_location = file_loc

            # Check if crash is in the library (not in harness or libc)
            file_part = file_loc.split(":")[0]

            # It's in the library if:
            # 1. The file matches the sink file
            # 2. The file is in the repo source (not /work/harness*)
            # 3. The file contains the library name
            if sink_file and sink_file in file_part:
                result.asan_in_library = True
                break
            if "/work/harness" in file_part or "/work/fuzz" in file_part:
                result.asan_in_library = False
                result.harness_crashed_itself = True
                break
            if library_name and library_name.lower() in file_part.lower():
                result.asan_in_library = True
                break
            if file_part.startswith("/src/"):
                # Source is mounted at /src/ in the container
                result.asan_in_library = True
                break

    # Also check ASAN summary
    summary_match = re.search(r"SUMMARY: AddressSanitizer: (\S+)", output)
    if summary_match and not result.asan_crash_type:
        result.asan_crash_type = summary_match.group(1)

#src\deeptrace\models\config.py
"""Configuration and settings for deeptrace."""

from __future__ import annotations

import os
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class JoernConfig(BaseModel):
    """Joern / Docker settings."""
    docker_image: str = "ghcr.io/joernio/joern:nightly"
    container_timeout: int = 600        # seconds
    cpg_timeout: int = 7200              # CPG generation timeout (large repos need more)
    query_timeout: int = 5000            # per-query timeout
    memory_limit: str = "24g"
    cpus: float = 4.0
    mount_readonly: bool = True
    keep_container: bool = False        # keep container after run for debugging
    extra_joern_opts: list[str] = Field(default_factory=list)
    cpg_save_path: str = ""             # path to save CPG for reuse (e.g. repo.cpg.bin)
    cpg_load_path: str = ""             # path to a pre-built CPG to load instead of re-generating


class TreeSitterConfig(BaseModel):
    """Tree-sitter fallback settings."""
    enabled: bool = True
    use_ctags: bool = True              # use ctags for cross-file resolution
    max_file_size_kb: int = 2048        # skip files larger than this
    max_files: int = 5000               # max files to scan (0 = unlimited)
    parse_timeout: float = 10.0         # per-file parse timeout


class ACOConfig(BaseModel):
    """Ant Colony Optimization parameters."""
    ants: int = 80
    iterations: int = 60
    alpha: float = 1.0                  # pheromone importance
    beta: float = 2.5                   # heuristic importance
    rho: float = 0.15                   # evaporation rate
    q0: float = 0.9                     # exploitation vs exploration threshold
    min_pheromone: float = 0.01
    max_pheromone: float = 10.0
    elite_ants: int = 5                 # number of elite ants for pheromone update
    stagnation_limit: int = 15          # reset if no improvement for N iterations
    local_search: bool = True           # apply local search to best paths


class BranchingConfig(BaseModel):
    """Settings for interactive branching / explosion handling."""
    max_fan_out: int = 15               # if a node has more successors, trigger branch save
    auto_prune_threshold: int = 50      # auto-prune candidates beyond this
    save_all_candidates: bool = True    # persist all candidates even if pruned
    llm_pre_rank_candidates: bool = True  # use LLM to rank candidates before presenting


class LLMProvider(str, Enum):
    """Supported LLM providers."""
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    OPENAI = "openai"     # any OpenAI-compatible API


class LLMConfig(BaseModel):
    """LLM ranking settings — supports Anthropic, Ollama, and OpenAI-compatible APIs."""
    enabled: bool = True
    provider: LLMProvider = LLMProvider.OLLAMA
    model: str = "qwen2.5-coder:14b"   # default Ollama model (good at code + JSON)
    api_key: str = Field(default="", description="API key (not needed for Ollama)")
    base_url: str = ""                  # e.g. http://localhost:11434 for Ollama
    max_tokens: int = 4096
    temperature: float = 0.2
    max_paths_per_batch: int = 5       # how many paths to rank in one call
    timeout: int = 120                  # request timeout in seconds
    vulnerability_categories: list[str] = Field(default_factory=lambda: [
        "buffer_overflow",
        "use_after_free",
        "null_deref",
        "injection",
        "integer_overflow",
        "race_condition",
        "unvalidated_input",
        "information_leak",
        "privilege_escalation",
        "resource_leak",
        "type_confusion",
        "format_string",
    ])

    def get_api_key(self) -> str:
        if self.provider == LLMProvider.OLLAMA:
            return self.api_key or "ollama"  # Ollama doesn't need a real key
        if self.provider == LLMProvider.ANTHROPIC:
            return self.api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        # OpenAI-compatible
        return self.api_key or os.environ.get("OPENAI_API_KEY", "")

    def get_base_url(self) -> str:
        if self.base_url:
            return self.base_url
        if self.provider == LLMProvider.OLLAMA:
            return os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        if self.provider == LLMProvider.OPENAI:
            return "https://api.openai.com"
        # Anthropic — not used (SDK handles it)
        return ""


class Z3Config(BaseModel):
    """Z3 constraint solver settings."""
    enabled: bool = True
    timeout_ms: int = 5000              # Z3 solver timeout per path
    extract_from_code: bool = True      # extract constraints from code snippets
    extract_from_conditions: bool = True  # extract from if/while/for guards


class DeeptraceConfig(BaseSettings):
    """Top-level configuration."""
    # Target
    repo: str = "."
    target: str = ""                    # sink file:line
    source: str = ""                    # optional source file:line
    language: str | None = None         # auto-detect if None

    # Batch mode
    lines_file: str = ""               # path to lines.json for batch mode

    # Graph extraction
    max_depth: int = 30                 # max backward trace depth
    max_flows: int = 400                # max Joern flows to extract
    max_nodes: int = 5000               # graph size limit
    context_lines: int = 3              # lines of code context per node
    max_caller_hops: int = 3            # iterative frontier expansion: chase callers N levels deep (0=disabled)

    # Output
    out: str = "traces.json"
    topk: int = 20                      # top-K paths in output
    session_file: str = ""              # path to save/resume session
    enumerate_small_graphs: bool = True # exact enumeration if graph is small
    small_graph_threshold: int = 15    # "small" = fewer than N nodes

    # Interactive
    interactive: bool = False           # enter interactive branch-selection mode

    # Sub-configs
    joern: JoernConfig = Field(default_factory=JoernConfig)
    treesitter: TreeSitterConfig = Field(default_factory=TreeSitterConfig)
    aco: ACOConfig = Field(default_factory=ACOConfig)
    branching: BranchingConfig = Field(default_factory=BranchingConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    z3: Z3Config = Field(default_factory=Z3Config)

    class Config:
        env_prefix = "DEEPTRACE_"
        env_nested_delimiter = "__"

#src\deeptrace\models\graph.py
"""Core data models for the dependency graph, trace paths, and sessions."""

from __future__ import annotations

import hashlib
import time
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field, computed_field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class EdgeKind(str, Enum):
    """Classification of dependency edges."""
    DATA_FLOW = "data_flow"           # Joern reaching-def / data-dep
    CALL = "call"                      # function call edge
    RETURN = "return"                  # return value propagation
    FIELD_ACCESS = "field_access"      # struct/class field access
    POINTER_DEREF = "pointer_deref"    # pointer / reference dereference
    ALIAS = "alias"                    # pointer alias
    PARAM_PASS = "param_pass"          # argument → parameter binding
    TYPE_CAST = "type_cast"            # cast / coercion
    CONTROL_DEP = "control_dep"        # control dependency (branch guards)
    INCLUDE = "include"                # file-level include / import
    TREESITTER = "treesitter"          # tree-sitter-only fallback edge
    UNKNOWN = "unknown"


class NodeKind(str, Enum):
    IDENTIFIER = "identifier"
    CALL_SITE = "call_site"
    PARAM = "parameter"
    RETURN_VAL = "return_value"
    LITERAL = "literal"
    FIELD = "field"
    TYPE_REF = "type_ref"
    CONTROL = "control"               # if / switch / loop guard
    UNKNOWN = "unknown"


class Language(str, Enum):
    C = "c"
    CPP = "cpp"
    JAVA = "java"
    KOTLIN = "kotlin"
    SWIFT = "swift"
    RUST = "rust"
    OBJC = "objc"
    PYTHON = "python"


class BackendKind(str, Enum):
    JOERN = "joern"
    TREESITTER = "treesitter"


# ---------------------------------------------------------------------------
# Graph primitives
# ---------------------------------------------------------------------------

class SourceLocation(BaseModel):
    """A precise location in source code."""
    file: str
    line: int
    column: int = 0
    end_line: int | None = None
    end_column: int | None = None
    code_snippet: str = ""

    @computed_field  # type: ignore[misc]
    @property
    def short(self) -> str:
        return f"{self.file}:{self.line}"

    def __hash__(self) -> int:
        return hash((self.file, self.line, self.column))


class GraphNode(BaseModel):
    """A node in the dependency graph."""
    id: str
    kind: NodeKind = NodeKind.UNKNOWN
    name: str = ""
    location: SourceLocation | None = None
    language: Language | None = None
    backend: BackendKind = BackendKind.JOERN
    properties: dict[str, Any] = Field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, GraphNode):
            return self.id == other.id
        return NotImplemented


class GraphEdge(BaseModel):
    """A directed edge in the dependency graph."""
    src: str              # source node id
    dst: str              # destination node id
    kind: EdgeKind = EdgeKind.UNKNOWN
    weight: float = 1.0   # base weight (lower = more important)
    backend: BackendKind = BackendKind.JOERN
    properties: dict[str, Any] = Field(default_factory=dict)

    @computed_field  # type: ignore[misc]
    @property
    def edge_id(self) -> str:
        return f"{self.src}->{self.dst}:{self.kind.value}"


# ---------------------------------------------------------------------------
# Trace path
# ---------------------------------------------------------------------------

class TraceStep(BaseModel):
    """One step in a traced dependency path."""
    node_id: str
    location: SourceLocation | None = None
    edge_kind: EdgeKind | None = None   # edge used to reach this step
    code_snippet: str = ""
    node_kind: NodeKind | None = None
    node_name: str = ""
    annotation: str = ""

    @computed_field  # type: ignore[misc]
    @property
    def display(self) -> str:
        loc = self.location.short if self.location else "?"
        return f"[{loc}] {self.code_snippet[:120]}"


class TracePath(BaseModel):
    """A complete dependency path from some origin to the target."""
    id: str = ""
    steps: list[TraceStep] = Field(default_factory=list)
    score: float = 0.0                  # ACO pheromone / heuristic score
    depth: int = 0
    llm_rank: int | None = None         # rank assigned by LLM (1 = most critical)
    llm_rationale: str = ""             # LLM explanation
    vulnerability_tags: list[str] = Field(default_factory=list)
    vulnerability_summary: str = ""     # step-by-step vulnerability explanation
    is_satisfiable: bool | None = None  # Z3 constraint satisfiability
    constraints: list[str] = Field(default_factory=list)  # extracted path constraints
    z3_model: str = ""                  # Z3 satisfying assignment (if SAT)

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            h = hashlib.sha256()
            for s in self.steps:
                h.update(s.node_id.encode())
            self.id = h.hexdigest()[:16]
        if not self.depth:
            self.depth = len(self.steps)


# ---------------------------------------------------------------------------
# Branching / interactive session
# ---------------------------------------------------------------------------

class BranchPoint(BaseModel):
    """A point in exploration where multiple next-step paths diverge."""
    node_id: str
    location: SourceLocation | None = None
    candidates: list[BranchCandidate] = Field(default_factory=list)
    chosen_index: int | None = None     # which candidate was selected
    timestamp: float = Field(default_factory=time.time)


class BranchCandidate(BaseModel):
    """One possible continuation at a branch point."""
    index: int
    next_node_id: str
    edge_kind: EdgeKind
    code_preview: str = ""
    llm_summary: str = ""               # one-line LLM description
    estimated_depth: int = 0            # how deep this sub-path goes
    vulnerability_hint: str = ""        # LLM quick hint


class TraceSession(BaseModel):
    """Persistent session state for interactive tracing."""
    session_id: str = ""
    repo_path: str = ""
    target: str = ""                     # file:line
    created_at: float = Field(default_factory=time.time)
    completed_paths: list[TracePath] = Field(default_factory=list)
    pending_branches: list[BranchPoint] = Field(default_factory=list)
    resolved_branches: list[BranchPoint] = Field(default_factory=list)
    graph_snapshot_file: str = ""        # path to serialized graph

    @computed_field  # type: ignore[misc]
    @property
    def has_pending(self) -> bool:
        return len(self.pending_branches) > 0


# ---------------------------------------------------------------------------
# Full output
# ---------------------------------------------------------------------------

class TraceOutput(BaseModel):
    """Complete output of a trace run."""
    version: str = "1.0.0"
    target: str = ""
    source: str = ""                    # optional source file:line
    repo: str = ""
    language: Language | None = None
    node_count: int = 0
    edge_count: int = 0
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    paths: list[TracePath] = Field(default_factory=list)
    session: TraceSession | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class BatchTarget(BaseModel):
    """A single target from lines.json."""
    file: str
    line: int
    source_file: str = ""               # optional source endpoint
    source_line: int = 0


class BatchOutput(BaseModel):
    """Aggregated output of a batch trace run."""
    version: str = "1.0.0"
    repo: str = ""
    total_targets: int = 0
    successful: int = 0
    failed: int = 0
    results: list[TraceOutput] = Field(default_factory=list)
    errors: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

#src\deeptrace\scanner\context_analyzer.py
"""Context analyzer: extracts surrounding code and structural information
for each pattern hit so the LLM can make an informed assessment.

For each hit, extracts:
  - N lines of surrounding code (configurable, default ±10).
  - The enclosing function name and signature.
  - Nearby guards/checks that might make the hit a false positive
    (e.g., bounds check before memcpy, null check before deref).
  - Arguments to the dangerous call (when parseable).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from deeptrace.scanner.patterns import VulnPattern, HitType

logger = logging.getLogger(__name__)


@dataclass
class ScanHit:
    """A single pattern match with full context."""
    pattern: VulnPattern
    file: str                         # relative path
    line: int
    matched_text: str                 # the line that matched
    context_before: list[str] = field(default_factory=list)  # lines above
    context_after: list[str] = field(default_factory=list)   # lines below
    enclosing_function: str = ""
    function_signature: str = ""
    nearby_guards: list[str] = field(default_factory=list)  # bounds checks / null checks
    call_arguments: str = ""          # raw text of arguments to the dangerous call
    confidence: str = "medium"        # low/medium/high (adjusted by context)

    @property
    def full_context(self) -> str:
        """Return the surrounding code block as a single string."""
        lines = list(self.context_before)
        lines.append(f">>> {self.matched_text}  // <-- LINE {self.line} (PATTERN HIT)")
        lines.extend(self.context_after)
        return "\n".join(lines)

    @property
    def context_line_range(self) -> tuple[int, int]:
        before_start = max(1, self.line - len(self.context_before))
        after_end = self.line + len(self.context_after)
        return (before_start, after_end)


# Guard patterns that reduce confidence (potential false positives)
_GUARD_PATTERNS = [
    # Bounds checks
    "sizeof", "strlen", "size()", "length()", "count()",
    "< sizeof", "<= sizeof", "< len", "<= len",
    "min(", "std::min(", "MIN(",
    # Null checks
    "!= NULL", "!= nullptr", "!= nil", "!= 0",
    "== NULL", "== nullptr",
    "if (!", "if (!",
    # Safe wrappers
    "snprintf", "strlcpy", "strlcat", "strncpy_s", "memcpy_s",
    "safe_", "checked_", "bounded_",
    # ASAN / sanitizer annotations
    "__asan", "ASAN_", "sanitize",
]


def extract_context(
    file_path: str,
    repo_path: str,
    line_no: int,
    pattern: VulnPattern,
    context_lines: int = 10,
) -> ScanHit | None:
    """Read the file and extract rich context around the pattern match.

    Args:
        file_path: Relative path within the repo.
        repo_path: Absolute path to the repo root.
        line_no: 1-based line number of the match.
        pattern: The VulnPattern that matched.
        context_lines: Number of context lines above and below.

    Returns:
        A ScanHit with full context, or None if the file is unreadable.
    """
    abs_path = os.path.join(repo_path, file_path)
    try:
        source = Path(abs_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    all_lines = source.split("\n")
    if line_no < 1 or line_no > len(all_lines):
        return None

    matched_text = all_lines[line_no - 1].rstrip()

    # Context window
    start = max(0, line_no - 1 - context_lines)
    end = min(len(all_lines), line_no + context_lines)

    context_before = [all_lines[i].rstrip() for i in range(start, line_no - 1)]
    context_after = [all_lines[i].rstrip() for i in range(line_no, end)]

    # Find enclosing function
    enclosing_func, func_sig = _find_enclosing_function(all_lines, line_no)

    # Find nearby guards
    guard_window = all_lines[max(0, line_no - 6):line_no + 2]
    guards = _find_guards(guard_window)

    # Extract call arguments (rough heuristic)
    call_args = _extract_call_args(matched_text)

    # Confidence adjustment
    confidence = _assess_confidence(pattern, matched_text, guards, context_before)

    return ScanHit(
        pattern=pattern,
        file=file_path,
        line=line_no,
        matched_text=matched_text,
        context_before=context_before,
        context_after=context_after,
        enclosing_function=enclosing_func,
        function_signature=func_sig,
        nearby_guards=guards,
        call_arguments=call_args,
        confidence=confidence,
    )


def _find_enclosing_function(lines: list[str], target_line: int) -> tuple[str, str]:
    """Walk backward from target_line to find the enclosing function definition.

    Returns (function_name, full_signature_line).
    """
    import re

    # Patterns for function definitions across languages
    func_patterns = [
        # C/C++: return_type func_name(params) {
        re.compile(r'^\s*(?:[\w:*&<>\s]+?)\s+(\w[\w:]*)\s*\(([^)]*)\)\s*(?:const\s*)?(?:override\s*)?(?:noexcept\s*)?{?\s*$'),
        # Java/Kotlin: access? return? funcName(params) {
        re.compile(r'^\s*(?:public|private|protected|static|final|override|fun|void|int|boolean|String)[\s\w]*\s+(\w+)\s*\(([^)]*)\)\s*(?:\{|:|\s*$)'),
        # Python: def funcName(params):
        re.compile(r'^\s*def\s+(\w+)\s*\(([^)]*)\)\s*(?:->.*)?:\s*$'),
        # Rust: fn funcName(params) {
        re.compile(r'^\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)'),
        # Swift: func funcName(params) {
        re.compile(r'^\s*(?:public\s+|private\s+|internal\s+)?func\s+(\w+)\s*\(([^)]*)\)'),
    ]

    # Walk backward from the target line
    for i in range(target_line - 1, max(target_line - 80, -1), -1):
        if i < 0 or i >= len(lines):
            continue
        line = lines[i]
        for pat in func_patterns:
            m = pat.match(line)
            if m:
                return m.group(1), line.strip()

    return "", ""


def _find_guards(window: list[str]) -> list[str]:
    """Find safety guards (bounds checks, null checks) in a code window."""
    guards: list[str] = []
    for line in window:
        line_stripped = line.strip()
        for guard in _GUARD_PATTERNS:
            if guard in line_stripped:
                guards.append(line_stripped[:120])
                break
    return guards


def _extract_call_args(line: str) -> str:
    """Extract the argument list from a function call on this line."""
    # Find first ( and matching )
    start = line.find("(")
    if start < 0:
        return ""

    depth = 0
    for i in range(start, len(line)):
        if line[i] == "(":
            depth += 1
        elif line[i] == ")":
            depth -= 1
            if depth == 0:
                return line[start + 1:i].strip()
    # No matching ) found — return until end of line
    return line[start + 1:].strip().rstrip(")")


def _assess_confidence(
    pattern: VulnPattern,
    matched_text: str,
    guards: list[str],
    context_before: list[str],
) -> str:
    """Heuristically adjust confidence based on context.

    Returns "low", "medium", or "high".
    """
    # Start at pattern's default severity level
    base = {"critical": "high", "high": "high", "medium": "medium", "low": "low", "info": "low"}
    confidence = base.get(pattern.severity.value, "medium")

    # Boost: pattern has very few false positive hints and is critical
    if pattern.severity.value == "critical" and not guards:
        return "high"

    # Reduce: nearby guards suggest bounds checking
    if guards:
        guard_text = " ".join(guards).lower()
        for fp_hint in pattern.false_positive_hints:
            if fp_hint.lower() in guard_text:
                return "low"
        # Generic reduction for any guard
        if confidence == "high":
            confidence = "medium"

    # Reduce: the match is inside a comment
    stripped = matched_text.strip()
    if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
        return "low"

    # Reduce: the match is inside a string literal
    if stripped.count('"') >= 2 and pattern.hit_type == HitType.SINK:
        # Might be in a string constant
        pass  # leave as-is, LLM will evaluate

    return confidence
#src\deeptrace\scanner\llm_analyzer.py
"""LLM-based analyzer for vulnerability scan hits.

Takes pattern hits enriched with code context and asks the LLM to:
  1. Evaluate whether each hit is a real vulnerability or a false positive.
  2. Explain the attack vector in concrete terms.
  3. Identify likely source locations (where attacker input enters).
  4. Rank hits by exploitability.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable

from deeptrace.scanner.context_analyzer import ScanHit

logger = logging.getLogger(__name__)


_SYSTEM_PROMPT = """You are a senior vulnerability researcher performing triage on static analysis hits.

For each candidate, you will receive:
- The vulnerability pattern that matched (category, CWE, description)
- The exact code line that matched
- 10 lines of surrounding context (before and after)
- The enclosing function name and signature
- Any nearby safety guards (bounds checks, null checks, etc.)

Your job: For each hit, evaluate whether this is a REAL vulnerability or a false positive,
and if real, explain the attack vector concretely.

CRITICAL: Respond with ONLY a JSON object. No markdown fences. No commentary.

Schema:
{
  "evaluations": [
    {
      "hit_index": <0-based index>,
      "is_real": <true/false>,
      "confidence": <"high"/"medium"/"low">,
      "explanation": "<2-3 sentences: WHY this is/isn't a real vulnerability. Be specific about what data flows where.>",
      "attack_scenario": "<If is_real: describe a concrete attack. What input does the attacker provide? What happens step by step? Otherwise empty string.>",
      "source_hint": "<If is_real: where does attacker-controlled data likely enter? Name the function/parameter/file if visible in context. Otherwise empty string.>",
      "severity": <"critical"/"high"/"medium"/"low">,
      "false_positive_reason": "<If NOT real: why is this a false positive? E.g., 'size is bounded by sizeof(dest)', 'input is validated 3 lines above'. Otherwise empty string.>"
    }
  ]
}

Rules:
- A memcpy/strcpy is NOT a vulnerability if the size is statically bounded (sizeof, constant).
- A printf is NOT a format string bug if the format is a string literal.
- A free() is NOT use-after-free if the pointer is set to NULL or not used after.
- Consider the FULL context: if there's a bounds check above, the hit may be safe.
- Be ruthless about false positives — only flag things that are genuinely dangerous.
- For "source_hint": look at function parameters, global reads, or IO calls in the context."""


_PAIR_SYSTEM_PROMPT = """You are a senior vulnerability researcher identifying source-sink pairs.

Given a list of confirmed vulnerabilities (sinks) and potential source locations,
identify the most likely source → sink pairings. A "source" is where attacker-controlled
data enters the system. A "sink" is where that data triggers a vulnerability.

Respond with ONLY a JSON object:
{
  "pairs": [
    {
      "sink_index": <index in the sinks list>,
      "source_file": "<file path of the likely source, or empty string>",
      "source_line": <line number, or 0>,
      "source_description": "<what the source is: e.g., 'HTTP request parameter', 'socket recv()', 'file read'>",
      "connection_explanation": "<how data flows from source to sink — be specific about the call chain if visible>"
    }
  ]
}

If you cannot identify a source for a sink, still include it with empty source fields."""


_ATTACK_VECTOR_SYSTEM_PROMPT = """You are a senior vulnerability researcher analyzing dangerous code sinks to determine
how an attacker could reach them with controlled data.

For each sink you receive:
- The exact dangerous code line and its surrounding context (±10 lines)
- The enclosing function name and full signature (including parameter types)
- The file path within the project
- The vulnerability category (buffer_overflow, type_confusion, command_injection, etc.)

Your job: For EACH sink, reason BACKWARD from the dangerous operation through the
function parameters and call context to determine:
1. Which function parameters carry data that reaches the sink?
2. What TYPE of external input could provide that data? (file format, network protocol,
   user interaction, environment variable, config file, etc.)
3. What is the concrete attack scenario? (What does the attacker craft/send?)
4. Where in the codebase does attacker data likely ENTER? (Be specific about the module,
   subsystem, or API layer — even if you can't name the exact file:line.)

IMPORTANT: Don't just say "attacker-controlled input reaches the sink." Be domain-specific:
- For a PDF library: "A malformed PDF font table with an oversized glyph descriptor..."
- For a web server: "An HTTP POST request with a Content-Length exceeding the buffer..."
- For a parser: "A crafted XFA form node with a type attribute that forces the wrong cast..."

Respond with ONLY a JSON object:
{
  "analyses": [
    {
      "sink_index": <0-based index>,
      "tainted_parameters": ["<param1>", "<param2>"],
      "input_type": "<file format / protocol / user action that provides the data>",
      "entry_point_description": "<where in the codebase external data enters (module/subsystem/API)>",
      "entry_point_file_hint": "<best guess at file path or directory, or empty string>",
      "attack_scenario": "<3-5 sentences: What does the attacker craft? What path does the data take? What happens at the sink? What is the impact?>",
      "exploitability": "<high/medium/low — based on how reachable the sink is from external input>",
      "prerequisites": "<what conditions must hold for the attack to work, e.g., 'XFA forms must be enabled', 'user must open the crafted PDF'>"
    }
  ]
}"""


def format_hits_for_llm(hits: list[ScanHit], batch_start: int = 0) -> str:
    """Format a batch of scan hits into a prompt for the LLM."""
    sections: list[str] = []

    for i, hit in enumerate(hits):
        idx = batch_start + i
        lines = [
            f"=== Hit {idx} ===",
            f"Pattern: {hit.pattern.id} ({hit.pattern.category.value})",
            f"CWE: {hit.pattern.cwe}",
            f"Description: {hit.pattern.description}",
            f"File: {hit.file}:{hit.line}",
            f"Function: {hit.enclosing_function or '(unknown)'}",
        ]
        if hit.function_signature:
            lines.append(f"Signature: {hit.function_signature}")
        if hit.call_arguments:
            lines.append(f"Arguments: {hit.call_arguments}")
        if hit.nearby_guards:
            lines.append(f"Nearby guards: {'; '.join(hit.nearby_guards[:3])}")

        lines.append("")
        lines.append("Code context:")
        lines.append(hit.full_context)
        lines.append("")

        sections.append("\n".join(lines))

    return "\n\n".join(sections)


class LLMAnalyzer:
    """Sends scan hits to the LLM for evaluation and ranking."""

    def __init__(self, llm_caller: Callable[[str, str], str]) -> None:
        self.llm_call = llm_caller

    def evaluate_hits(
        self,
        hits: list[ScanHit],
        batch_size: int = 10,
    ) -> list[dict[str, Any]]:
        """Evaluate all hits in batches, returning LLM assessments.

        Returns a list (same length as hits) of evaluation dicts.
        """
        all_evals: list[dict[str, Any]] = [{}] * len(hits)

        for batch_start in range(0, len(hits), batch_size):
            batch = hits[batch_start:batch_start + batch_size]
            batch_end = min(batch_start + batch_size, len(hits))

            logger.info(
                "  LLM evaluating hits %d–%d of %d...",
                batch_start, batch_end - 1, len(hits),
            )

            try:
                evals = self._evaluate_batch(batch, batch_start)
                for ev in evals:
                    idx = ev.get("hit_index", -1)
                    if 0 <= idx < len(hits):
                        all_evals[idx] = ev
            except Exception as exc:
                logger.warning("  LLM evaluation failed for batch %d: %s", batch_start, exc)
                # Fill with defaults
                for i in range(batch_start, batch_end):
                    if not all_evals[i]:
                        all_evals[i] = {
                            "hit_index": i, "is_real": True, "confidence": "medium",
                            "explanation": "LLM evaluation failed — retaining as potential hit.",
                            "attack_scenario": "", "source_hint": "",
                            "severity": hits[i].pattern.severity.value,
                            "false_positive_reason": "",
                        }

        return all_evals

    def _evaluate_batch(
        self, hits: list[ScanHit], batch_start: int,
    ) -> list[dict[str, Any]]:
        """Send one batch to the LLM and parse the response."""
        prompt = format_hits_for_llm(hits, batch_start)

        user_msg = (
            f"Evaluate these {len(hits)} vulnerability candidates. "
            "For each one, determine if it's a real vulnerability or false positive. "
            "Be strict — only flag genuinely dangerous code.\n\n"
            + prompt
        )

        raw = self.llm_call(_SYSTEM_PROMPT, user_msg)
        result = _parse_json_response(raw)
        return result.get("evaluations", [])

    def identify_source_sink_pairs(
        self,
        sinks: list[ScanHit],
        sources: list[ScanHit],
    ) -> list[dict[str, Any]]:
        """Ask the LLM to pair sinks with likely sources.

        Args:
            sinks: Confirmed vulnerability sinks.
            sources: Detected source (input) locations.

        Returns:
            List of pairing dicts with source file/line info.
        """
        if not sinks:
            return []

        sink_descs = []
        for i, s in enumerate(sinks):
            sink_descs.append(
                f"Sink {i}: {s.file}:{s.line} — {s.pattern.category.value} — "
                f"{s.matched_text.strip()[:100]} — function: {s.enclosing_function}"
            )

        source_descs = []
        for i, s in enumerate(sources):
            source_descs.append(
                f"Source {i}: {s.file}:{s.line} — {s.pattern.description} — "
                f"{s.matched_text.strip()[:100]} — function: {s.enclosing_function}"
            )

        user_msg = (
            f"Given {len(sinks)} vulnerability sinks and {len(sources)} potential sources, "
            "identify the most likely source→sink pairings.\n\n"
            "SINKS:\n" + "\n".join(sink_descs) + "\n\n"
            "SOURCES:\n" + ("\n".join(source_descs) if source_descs else "(none detected)") + "\n\n"
            "For each sink, identify where attacker-controlled data likely enters."
        )

        try:
            raw = self.llm_call(_PAIR_SYSTEM_PROMPT, user_msg)
            result = _parse_json_response(raw)
            return result.get("pairs", [])
        except Exception as exc:
            logger.warning("Source-sink pairing failed: %s", exc)
            return []

    def analyze_attack_vectors(
        self,
        sinks: list[ScanHit],
        call_chains: list[Any] | None = None,
        batch_size: int = 5,
    ) -> list[dict[str, Any]]:
        """Analyze each confirmed sink to determine how attacker data reaches it.

        When ``call_chains`` is provided (from SourceDiscoverer), the LLM sees
        the REAL upstream code from the repo — actual callers, their function
        signatures, parameter names, and surrounding code.  This produces
        dramatically better results than reasoning from the sink's ±10 lines alone.

        Args:
            sinks: Confirmed vulnerability sinks with full code context.
            call_chains: Real call chains from SourceDiscoverer (same length as sinks).
                         If None, falls back to sink-context-only analysis.
            batch_size: Sinks per LLM call (smaller = better context per sink).

        Returns:
            List of analysis dicts (same length as sinks), each containing:
              tainted_parameters, input_type, entry_point_description,
              entry_point_file_hint, attack_scenario, exploitability, prerequisites.
        """
        if not sinks:
            return []

        all_analyses: list[dict[str, Any]] = [{}] * len(sinks)

        for batch_start in range(0, len(sinks), batch_size):
            batch_sinks = sinks[batch_start:batch_start + batch_size]
            batch_chains = None
            if call_chains:
                batch_chains = call_chains[batch_start:batch_start + batch_size]
            batch_end = min(batch_start + batch_size, len(sinks))

            logger.info(
                "  LLM analyzing attack vectors for sinks %d–%d of %d...",
                batch_start, batch_end - 1, len(sinks),
            )

            try:
                analyses = self._analyze_vector_batch(batch_sinks, batch_chains, batch_start)
                for av in analyses:
                    idx = av.get("sink_index", -1)
                    if 0 <= idx < len(sinks):
                        all_analyses[idx] = av
            except Exception as exc:
                logger.warning(
                    "  Attack vector analysis failed for batch %d: %s",
                    batch_start, exc,
                )

        return all_analyses

    def _analyze_vector_batch(
        self,
        sinks: list[ScanHit],
        call_chains: list[Any] | None,
        batch_start: int,
    ) -> list[dict[str, Any]]:
        """Send one batch of sinks (with real call chains) for attack vector analysis."""
        sections: list[str] = []

        for i, hit in enumerate(sinks):
            idx = batch_start + i
            lines = [
                f"=== Sink {idx} ===",
                f"Category: {hit.pattern.category.value} ({hit.pattern.cwe})",
                f"File: {hit.file}:{hit.line}",
                f"Function: {hit.enclosing_function or '(unknown)'}",
            ]
            if hit.function_signature:
                lines.append(f"Full signature: {hit.function_signature}")
            if hit.call_arguments:
                lines.append(f"Dangerous call arguments: {hit.call_arguments}")

            lines.append("")
            lines.append("Sink code context (±10 lines):")
            lines.append(hit.full_context)

            # Include REAL call chain from the repo if available
            chain = call_chains[i] if call_chains and i < len(call_chains) else None
            if chain and chain.depth > 0:
                lines.append("")
                lines.append("=" * 60)
                lines.append("REAL CALLER CHAIN FROM THE REPOSITORY (not hypothetical):")
                lines.append("=" * 60)
                lines.append(chain.format_for_llm())
            else:
                lines.append("")
                lines.append("(No callers found in the repository for this function)")

            # Add the project path structure hint
            path_parts = hit.file.replace("\\", "/").split("/")
            if len(path_parts) >= 2:
                lines.append(f"\nProject module: {'/'.join(path_parts[:2])}")

            lines.append("")
            sections.append("\n".join(lines))

        prompt_body = "\n\n".join(sections)

        # Adapt the user message based on whether we have real call chains
        has_chains = call_chains and any(c.depth > 0 for c in call_chains)

        if has_chains:
            user_msg = (
                f"Analyze {len(sinks)} vulnerability sinks. For each one you have:\n"
                "1. The dangerous code at the sink with surrounding context\n"
                "2. The REAL call chain from the repository — actual callers with their "
                "code, function signatures, and parameter names.\n\n"
                "Use the REAL caller chain to trace backward and determine:\n"
                "- Which parameters carry tainted data (follow them through the chain)\n"
                "- What external input type reaches the top of the chain\n"
                "- The concrete file:line where attacker data enters\n"
                "- A precise attack scenario based on the actual code\n\n"
                "IMPORTANT: Use the real function signatures and parameter names from "
                "the chain — don't guess. The entry_point_file_hint should be the file "
                "at the TOP of the call chain (the outermost caller).\n\n"
                + prompt_body
            )
        else:
            user_msg = (
                f"Analyze {len(sinks)} vulnerability sinks. For each one, reason BACKWARD "
                "from the dangerous operation through the function parameters and call context "
                "to determine: (1) which parameters carry tainted data, (2) what type of external "
                "input could provide it, (3) the concrete attack scenario, and (4) where in the "
                "codebase the attacker's data enters.\n\n"
                "Be DOMAIN-SPECIFIC — look at the file paths, function names, and data types "
                "to infer what kind of project this is.\n\n"
                + prompt_body
            )

        raw = self.llm_call(_ATTACK_VECTOR_SYSTEM_PROMPT, user_msg)
        result = _parse_json_response(raw)
        return result.get("analyses", [])


def _parse_json_response(text: str) -> dict[str, Any]:
    """Robustly extract JSON from LLM response."""
    text = text.strip()

    # Strip markdown fences
    match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', text, re.IGNORECASE)
    if match:
        text = match.group(1).strip()

    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        text = text[start:end + 1]

    if not text:
        return {}

    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        logger.debug("LLM JSON parse failed: %s", exc)
        return {}
#src\deeptrace\scanner\patterns.py
"""Vulnerability pattern definitions for the scanner.

Each pattern defines:
  - A regex to find candidate lines (fast first pass).
  - The vulnerability category and severity.
  - Whether this is a SINK (dangerous operation) or SOURCE (attacker input).
  - Context hints for the LLM to evaluate the real risk.

Patterns are organized by language family and vulnerability class.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class VulnCategory(str, Enum):
    """Vulnerability categories — covers OWASP Top 10, CWE Top 25, and beyond."""
    BUFFER_OVERFLOW = "buffer_overflow"
    FORMAT_STRING = "format_string"
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"
    PATH_TRAVERSAL = "path_traversal"
    USE_AFTER_FREE = "use_after_free"
    INTEGER_OVERFLOW = "integer_overflow"
    TYPE_CONFUSION = "type_confusion"
    NULL_DEREFERENCE = "null_dereference"
    RACE_CONDITION = "race_condition"
    DESERIALIZATION = "deserialization"
    XXE = "xxe"
    SSRF = "ssrf"
    CRYPTO_WEAKNESS = "crypto_weakness"
    AUTH_BYPASS = "auth_bypass"
    INFORMATION_LEAK = "information_leak"
    RESOURCE_LEAK = "resource_leak"
    UNVALIDATED_REDIRECT = "unvalidated_redirect"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    DOUBLE_FREE = "double_free"
    HEAP_OVERFLOW = "heap_overflow"
    STACK_OVERFLOW = "stack_overflow"
    UNSAFE_REFLECTION = "unsafe_reflection"
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"
    TEMPLATE_INJECTION = "template_injection"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class HitType(str, Enum):
    SINK = "sink"        # dangerous operation that can be exploited
    SOURCE = "source"    # attacker-controlled input entry point
    BOTH = "both"        # can be either depending on context


@dataclass
class VulnPattern:
    """A single vulnerability detection pattern."""
    id: str                           # unique identifier e.g. "c_memcpy_overflow"
    category: VulnCategory
    severity: Severity
    hit_type: HitType
    regex: str                        # raw regex string (compiled lazily)
    languages: list[str]              # which languages this applies to
    description: str                  # what the pattern detects
    attack_vector: str                # WHY this is dangerous (for the LLM and report)
    cwe: str = ""                     # CWE identifier
    false_positive_hints: list[str] = field(default_factory=list)  # things that make this a FP
    _compiled: Any = field(default=None, repr=False)

    @property
    def compiled_regex(self) -> re.Pattern:
        if self._compiled is None:
            self._compiled = re.compile(self.regex, re.IGNORECASE)
        return self._compiled


# ===========================================================================
# Pattern definitions — organized by category
# ===========================================================================

PATTERNS: list[VulnPattern] = []

def _p(pattern: VulnPattern) -> VulnPattern:
    """Register a pattern."""
    PATTERNS.append(pattern)
    return pattern


# ---------------------------------------------------------------------------
# BUFFER OVERFLOW / HEAP OVERFLOW (CWE-120, CWE-122, CWE-787)
# ---------------------------------------------------------------------------

_p(VulnPattern(
    id="c_memcpy_unbounded",
    category=VulnCategory.BUFFER_OVERFLOW,
    severity=Severity.CRITICAL,
    hit_type=HitType.SINK,
    regex=r'\b(?:memcpy|memmove|bcopy)\s*\(',
    languages=["c", "cpp"],
    description="Unbounded memory copy",
    attack_vector="memcpy/memmove with attacker-controlled size can overflow the destination "
                  "buffer, enabling arbitrary code execution via heap or stack corruption.",
    cwe="CWE-120",
    false_positive_hints=["sizeof(dest) as length", "static buffer with compile-time size"],
))

_p(VulnPattern(
    id="c_strcpy_no_bounds",
    category=VulnCategory.BUFFER_OVERFLOW,
    severity=Severity.CRITICAL,
    hit_type=HitType.SINK,
    regex=r'\b(?:strcpy|strcat|wcscpy|wcscat)\s*\(',
    languages=["c", "cpp"],
    description="Unbounded string copy/concat",
    attack_vector="strcpy/strcat copies until null terminator with no length limit. "
                  "A source string longer than the destination buffer causes overflow.",
    cwe="CWE-120",
    false_positive_hints=["preceded by strlen check", "destination is dynamically allocated to fit"],
))

_p(VulnPattern(
    id="c_sprintf_overflow",
    category=VulnCategory.BUFFER_OVERFLOW,
    severity=Severity.HIGH,
    hit_type=HitType.SINK,
    regex=r'\b(?:sprintf|vsprintf)\s*\(',
    languages=["c", "cpp"],
    description="Unbounded sprintf into fixed buffer",
    attack_vector="sprintf writes formatted output without length bounds. If format args are "
                  "attacker-controlled, the output can exceed the destination buffer size.",
    cwe="CWE-120",
    false_positive_hints=["all format args are compile-time constants"],
))

_p(VulnPattern(
    id="c_gets",
    category=VulnCategory.BUFFER_OVERFLOW,
    severity=Severity.CRITICAL,
    hit_type=HitType.SINK,
    regex=r'\bgets\s*\(',
    languages=["c", "cpp"],
    description="Use of gets() — universally unsafe",
    attack_vector="gets() reads from stdin with absolutely no bounds checking. Always exploitable. "
                  "Removed from C11 standard for this reason.",
    cwe="CWE-242",
))

_p(VulnPattern(
    id="c_scanf_no_width",
    category=VulnCategory.BUFFER_OVERFLOW,
    severity=Severity.HIGH,
    hit_type=HitType.SINK,
    regex=r'\b(?:scanf|sscanf|fscanf)\s*\([^)]*%[^0-9*]*s',
    languages=["c", "cpp"],
    description="scanf %s without field width",
    attack_vector="scanf with %s reads unbounded input into a fixed buffer. "
                  "Without a width specifier (e.g., %63s), arbitrarily long input overflows.",
    cwe="CWE-120",
))

_p(VulnPattern(
    id="c_alloca",
    category=VulnCategory.STACK_OVERFLOW,
    severity=Severity.HIGH,
    hit_type=HitType.SINK,
    regex=r'\balloca\s*\(',
    languages=["c", "cpp"],
    description="Stack allocation with potentially unbounded size",
    attack_vector="alloca() allocates on the stack. With attacker-controlled size, causes "
                  "immediate stack overflow — no heap metadata needed for exploitation.",
    cwe="CWE-770",
))

_p(VulnPattern(
    id="c_strncpy_no_null",
    category=VulnCategory.BUFFER_OVERFLOW,
    severity=Severity.MEDIUM,
    hit_type=HitType.SINK,
    regex=r'\bstrncpy\s*\(',
    languages=["c", "cpp"],
    description="strncpy may not null-terminate",
    attack_vector="strncpy does not guarantee null termination when src >= n. Subsequent "
                  "string operations on the destination may read out of bounds.",
    cwe="CWE-170",
    false_positive_hints=["followed by explicit dest[n-1] = '\\0'"],
))

# ---------------------------------------------------------------------------
# FORMAT STRING (CWE-134)
# ---------------------------------------------------------------------------

_p(VulnPattern(
    id="c_printf_variable_format",
    category=VulnCategory.FORMAT_STRING,
    severity=Severity.CRITICAL,
    hit_type=HitType.SINK,
    regex=r'\b(?:printf|fprintf|sprintf|snprintf|syslog|err|warn)\s*\(\s*[^")\s]',
    languages=["c", "cpp"],
    description="printf-family with non-literal format string",
    attack_vector="If the format string is attacker-controlled, %n writes to arbitrary memory, "
                  "%x leaks stack data, and %s reads from arbitrary pointers. Full code execution.",
    cwe="CWE-134",
    false_positive_hints=["format is a compile-time constant variable"],
))

# ---------------------------------------------------------------------------
# COMMAND INJECTION (CWE-78)
# ---------------------------------------------------------------------------

_p(VulnPattern(
    id="c_system",
    category=VulnCategory.COMMAND_INJECTION,
    severity=Severity.CRITICAL,
    hit_type=HitType.SINK,
    regex=r'\b(?:system|popen|exec[lv]?p?e?|ShellExecute[A-Za-z]*|WinExec|CreateProcess[A-Za-z]*)\s*\(',
    languages=["c", "cpp"],
    description="OS command execution",
    attack_vector="system()/popen()/exec() pass strings to the OS shell. Any attacker-controlled "
                  "component enables arbitrary command execution via shell metacharacters (;|`$).",
    cwe="CWE-78",
    false_positive_hints=["argument is a compile-time literal with no interpolation"],
))

_p(VulnPattern(
    id="py_os_system",
    category=VulnCategory.COMMAND_INJECTION,
    severity=Severity.CRITICAL,
    hit_type=HitType.SINK,
    regex=r'\b(?:os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\(',
    languages=["python"],
    description="Python OS command execution",
    attack_vector="os.system() and subprocess with shell=True pass strings to /bin/sh. "
                  "f-strings or .format() with user input enable full shell injection.",
    cwe="CWE-78",
))

_p(VulnPattern(
    id="java_runtime_exec",
    category=VulnCategory.COMMAND_INJECTION,
    severity=Severity.CRITICAL,
    hit_type=HitType.SINK,
    regex=r'\b(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(',
    languages=["java", "kotlin"],
    description="Java/Kotlin command execution",
    attack_vector="Runtime.exec() and ProcessBuilder can execute arbitrary commands. "
                  "String concatenation with user input enables injection.",
    cwe="CWE-78",
))

# ---------------------------------------------------------------------------
# SQL INJECTION (CWE-89)
# ---------------------------------------------------------------------------

_p(VulnPattern(
    id="sql_string_concat",
    category=VulnCategory.SQL_INJECTION,
    severity=Severity.CRITICAL,
    hit_type=HitType.SINK,
    regex=r'(?:execute|query|prepare|rawQuery|cursor\.execute)\s*\([^)]*[\+%f]',
    languages=["c", "cpp", "java", "kotlin", "python", "swift"],
    description="SQL query with string concatenation/formatting",
    attack_vector="Building SQL queries via string concatenation or formatting allows "
                  "attacker input to escape the string context and inject SQL clauses "
                  "(UNION SELECT, OR 1=1, DROP TABLE).",
    cwe="CWE-89",
    false_positive_hints=["uses parameterized queries", "input is an integer cast"],
))

# ---------------------------------------------------------------------------
# PATH TRAVERSAL (CWE-22)
# ---------------------------------------------------------------------------

_p(VulnPattern(
    id="c_fopen_variable",
    category=VulnCategory.PATH_TRAVERSAL,
    severity=Severity.HIGH,
    hit_type=HitType.SINK,
    regex=r'\b(?:fopen|open|_wfopen|CreateFile[A-Za-z]*)\s*\(\s*[^")\s]',
    languages=["c", "cpp"],
    description="File open with non-literal path",
    attack_vector="Opening files with attacker-controlled paths enables reading/writing "
                  "arbitrary files via ../ traversal sequences (/etc/passwd, /proc/self/mem).",
    cwe="CWE-22",
    false_positive_hints=["path is validated/sanitized", "chroot/sandbox is active"],
))

_p(VulnPattern(
    id="py_open_variable",
    category=VulnCategory.PATH_TRAVERSAL,
    severity=Severity.HIGH,
    hit_type=HitType.SINK,
    regex=r'\b(?:open|io\.open|pathlib\.Path)\s*\(\s*[^")\s]',
    languages=["python"],
    description="Python file open with variable path",
    attack_vector="open() with user-controlled path argument allows reading/writing arbitrary "
                  "files. os.path.join doesn't prevent absolute path injection.",
    cwe="CWE-22",
))

# ---------------------------------------------------------------------------
# USE AFTER FREE (CWE-416)
# ---------------------------------------------------------------------------

_p(VulnPattern(
    id="c_free_use",
    category=VulnCategory.USE_AFTER_FREE,
    severity=Severity.CRITICAL,
    hit_type=HitType.SINK,
    regex=r'\bfree\s*\(\s*(\w+)',
    languages=["c", "cpp"],
    description="free() call — check for subsequent use of freed pointer",
    attack_vector="If the freed pointer is used after free() (read, write, or passed to "
                  "another function), the attacker can control the contents via heap feng shui "
                  "to achieve arbitrary read/write.",
    cwe="CWE-416",
    false_positive_hints=["pointer set to NULL immediately after free"],
))

_p(VulnPattern(
    id="cpp_delete_use",
    category=VulnCategory.USE_AFTER_FREE,
    severity=Severity.CRITICAL,
    hit_type=HitType.SINK,
    regex=r'\bdelete\b\s+(\w+)',
    languages=["cpp"],
    description="C++ delete — check for subsequent use of deleted object",
    attack_vector="Using an object after delete enables use-after-free. The vtable pointer "
                  "can be overwritten via heap spray to hijack virtual method calls.",
    cwe="CWE-416",
))

# ---------------------------------------------------------------------------
# INTEGER OVERFLOW (CWE-190)
# ---------------------------------------------------------------------------

_p(VulnPattern(
    id="c_malloc_arithmetic",
    category=VulnCategory.INTEGER_OVERFLOW,
    severity=Severity.HIGH,
    hit_type=HitType.SINK,
    regex=r'\b(?:malloc|calloc|realloc|new\s*\[)\s*\([^)]*[\*\+]',
    languages=["c", "cpp"],
    description="Heap allocation with arithmetic size",
    attack_vector="malloc(n * sizeof(T)) without overflow check: if n is attacker-controlled "
                  "and large enough, n*sizeof(T) wraps around to a small value, allocating a "
                  "tiny buffer that is then overflowed by the subsequent write.",
    cwe="CWE-190",
))

# ---------------------------------------------------------------------------
# TYPE CONFUSION (CWE-843)
# ---------------------------------------------------------------------------

_p(VulnPattern(
    id="cpp_reinterpret_cast",
    category=VulnCategory.TYPE_CONFUSION,
    severity=Severity.HIGH,
    hit_type=HitType.SINK,
    regex=r'\breinterpret_cast\s*<',
    languages=["cpp"],
    description="reinterpret_cast — unchecked type conversion",
    attack_vector="reinterpret_cast bypasses type safety. If the source object is attacker-"
                  "controlled, the cast can create a type-confused pointer that accesses "
                  "wrong offsets, leading to info leak or code execution.",
    cwe="CWE-843",
))

_p(VulnPattern(
    id="c_void_ptr_cast",
    category=VulnCategory.TYPE_CONFUSION,
    severity=Severity.MEDIUM,
    hit_type=HitType.SINK,
    regex=r'\(\s*(?:struct\s+)?\w+\s*\*\s*\)\s*(?:\w+|malloc|calloc)',
    languages=["c"],
    description="C-style cast from void* or between pointer types",
    attack_vector="Casting void* to a struct pointer without validation. If the underlying "
                  "data is attacker-controlled, field accesses read wrong offsets.",
    cwe="CWE-843",
))

# ---------------------------------------------------------------------------
# DESERIALIZATION (CWE-502)
# ---------------------------------------------------------------------------

_p(VulnPattern(
    id="py_pickle_load",
    category=VulnCategory.DESERIALIZATION,
    severity=Severity.CRITICAL,
    hit_type=HitType.SINK,
    regex=r'\b(?:pickle\.loads?|cPickle\.loads?|shelve\.open|yaml\.load\b(?!.*Loader\s*=\s*SafeLoader)|yaml\.unsafe_load)',
    languages=["python"],
    description="Unsafe Python deserialization",
    attack_vector="pickle.load() executes arbitrary Python code embedded in the serialized data. "
                  "An attacker providing the pickled input gets full RCE.",
    cwe="CWE-502",
))

_p(VulnPattern(
    id="java_deserialize",
    category=VulnCategory.DESERIALIZATION,
    severity=Severity.CRITICAL,
    hit_type=HitType.SINK,
    regex=r'\b(?:ObjectInputStream|readObject|readUnshared|XMLDecoder)\s*[.(]',
    languages=["java", "kotlin"],
    description="Java/Kotlin deserialization",
    attack_vector="Java ObjectInputStream.readObject() triggers gadget chains from libraries "
                  "on the classpath (Commons Collections, Spring, etc.) for RCE.",
    cwe="CWE-502",
))

# ---------------------------------------------------------------------------
# CRYPTO WEAKNESS (CWE-327, CWE-321)
# ---------------------------------------------------------------------------

_p(VulnPattern(
    id="crypto_weak_hash",
    category=VulnCategory.CRYPTO_WEAKNESS,
    severity=Severity.MEDIUM,
    hit_type=HitType.SINK,
    regex=r'\b(?:MD5|SHA1|SHA-1|md5|sha1)\s*[.(]',
    languages=["c", "cpp", "java", "kotlin", "python", "swift", "rust"],
    description="Weak hash algorithm (MD5/SHA1)",
    attack_vector="MD5 and SHA-1 are broken for collision resistance. If used for integrity "
                  "verification, signatures, or password hashing, an attacker can forge collisions.",
    cwe="CWE-327",
))

_p(VulnPattern(
    id="crypto_hardcoded_key",
    category=VulnCategory.CRYPTO_WEAKNESS,
    severity=Severity.HIGH,
    hit_type=HitType.SINK,
    regex=r'(?:password|secret|api_?key|token|private_?key)\s*=\s*["\'][^"\']{8,}["\']',
    languages=["c", "cpp", "java", "kotlin", "python", "swift", "rust"],
    description="Hardcoded secret/key/password",
    attack_vector="Hardcoded credentials in source code are extractable by anyone with repo access. "
                  "They cannot be rotated without a code change and deployment.",
    cwe="CWE-321",
))

_p(VulnPattern(
    id="crypto_ecb_mode",
    category=VulnCategory.CRYPTO_WEAKNESS,
    severity=Severity.MEDIUM,
    hit_type=HitType.SINK,
    regex=r'\b(?:ECB|DES|RC4|Blowfish)\b',
    languages=["c", "cpp", "java", "kotlin", "python", "swift", "rust"],
    description="Weak cipher or mode (ECB/DES/RC4)",
    attack_vector="ECB mode preserves patterns in plaintext. DES/RC4 have known cryptanalytic "
                  "attacks. Data encrypted with these can be partially or fully recovered.",
    cwe="CWE-327",
))

# ---------------------------------------------------------------------------
# RACE CONDITION (CWE-362)
# ---------------------------------------------------------------------------

_p(VulnPattern(
    id="c_toctou",
    category=VulnCategory.RACE_CONDITION,
    severity=Severity.MEDIUM,
    hit_type=HitType.SINK,
    regex=r'\b(?:access|stat|lstat)\s*\([^)]+\).*\n.*\b(?:open|fopen|unlink|rename)\s*\(',
    languages=["c", "cpp"],
    description="TOCTOU race — check then act on file",
    attack_vector="Time-of-check to time-of-use: if access()/stat() checks a file and then "
                  "open()/unlink() operates on it, an attacker can swap the file between the two calls.",
    cwe="CWE-367",
))

# ---------------------------------------------------------------------------
# XXE (CWE-611)
# ---------------------------------------------------------------------------

_p(VulnPattern(
    id="xml_parse_unsafe",
    category=VulnCategory.XXE,
    severity=Severity.HIGH,
    hit_type=HitType.SINK,
    regex=r'\b(?:XMLParser|SAXParser|DocumentBuilder|etree\.parse|etree\.fromstring|parseString|xml\.sax\.make_parser)\s*\(',
    languages=["c", "cpp", "java", "kotlin", "python"],
    description="XML parsing without disabling external entities",
    attack_vector="Default XML parser configurations allow external entity expansion. "
                  "Attacker-supplied XML with <!ENTITY> declarations can read local files "
                  "(file:///etc/passwd) or make SSRF requests.",
    cwe="CWE-611",
))

# ---------------------------------------------------------------------------
# SSRF (CWE-918)
# ---------------------------------------------------------------------------

_p(VulnPattern(
    id="ssrf_url_fetch",
    category=VulnCategory.SSRF,
    severity=Severity.HIGH,
    hit_type=HitType.SINK,
    regex=r'\b(?:requests\.get|requests\.post|urllib\.request\.urlopen|HttpURLConnection|fetch|curl_exec|URLSession)\s*\(\s*[^")\s]',
    languages=["python", "java", "kotlin", "swift", "c", "cpp"],
    description="HTTP request with variable URL",
    attack_vector="Server-side request forgery: if the URL is attacker-controlled, internal "
                  "services (cloud metadata at 169.254.169.254, admin panels, databases) become accessible.",
    cwe="CWE-918",
))

# ---------------------------------------------------------------------------
# TEMPLATE INJECTION (CWE-1336)
# ---------------------------------------------------------------------------

_p(VulnPattern(
    id="py_template_injection",
    category=VulnCategory.TEMPLATE_INJECTION,
    severity=Severity.CRITICAL,
    hit_type=HitType.SINK,
    regex=r'\b(?:Template|render_template_string|Jinja2|Environment)\s*\([^)]*\+',
    languages=["python"],
    description="Server-side template injection",
    attack_vector="Template engines (Jinja2, Mako) evaluate expressions. If user input is "
                  "concatenated into the template string, {{config}} or {{''.__class__}} "
                  "gives RCE.",
    cwe="CWE-1336",
))

# ---------------------------------------------------------------------------
# LDAP INJECTION (CWE-90)
# ---------------------------------------------------------------------------

_p(VulnPattern(
    id="ldap_injection",
    category=VulnCategory.LDAP_INJECTION,
    severity=Severity.HIGH,
    hit_type=HitType.SINK,
    regex=r'\b(?:ldap_search|ldap\.search|search_s|search_ext_s)\s*\([^)]*[\+%f]',
    languages=["c", "cpp", "python", "java"],
    description="LDAP query with string concatenation",
    attack_vector="LDAP filter injection: user input like *)(&(password=*) can bypass "
                  "authentication or extract directory data.",
    cwe="CWE-90",
))

# ---------------------------------------------------------------------------
# INFORMATION LEAK (CWE-209)
# ---------------------------------------------------------------------------

_p(VulnPattern(
    id="error_stack_leak",
    category=VulnCategory.INFORMATION_LEAK,
    severity=Severity.LOW,
    hit_type=HitType.SINK,
    regex=r'\b(?:printStackTrace|traceback\.print_exc|traceback\.format_exc|e\.getMessage)\s*\(',
    languages=["java", "kotlin", "python"],
    description="Error/stack trace exposed to user",
    attack_vector="Stack traces reveal internal paths, library versions, database schemas, "
                  "and configuration details that help an attacker map the attack surface.",
    cwe="CWE-209",
))

_p(VulnPattern(
    id="c_unsafe_memcpy_macro",
    category=VulnCategory.BUFFER_OVERFLOW,
    severity=Severity.HIGH,
    hit_type=HitType.SINK,
    regex=r'\bUNSAFE_TODO\s*\(\s*(?:FXSYS_)?(?:memcpy|memmove|memset)',
    languages=["c", "cpp"],
    description="Explicitly marked UNSAFE memory operation",
    attack_vector="The codebase itself marks this operation as unsafe (UNSAFE_TODO). "
                  "This is a strong signal that the developers know bounds checking is missing.",
    cwe="CWE-120",
))

# ---------------------------------------------------------------------------
# SOURCES (attacker-controlled input entry points)
# ---------------------------------------------------------------------------

_p(VulnPattern(
    id="c_recv_source",
    category=VulnCategory.BUFFER_OVERFLOW,  # category of the associated sink
    severity=Severity.INFO,
    hit_type=HitType.SOURCE,
    regex=r'\b(?:recv|recvfrom|recvmsg|read)\s*\(\s*(?:sock|fd|client)',
    languages=["c", "cpp"],
    description="Network socket read — attacker-controlled input entry",
    attack_vector="Data received from a network socket is fully attacker-controlled. "
                  "Any path from here to a dangerous sink is a potential vulnerability.",
    cwe="CWE-20",
))

_p(VulnPattern(
    id="c_getenv_source",
    category=VulnCategory.COMMAND_INJECTION,
    severity=Severity.INFO,
    hit_type=HitType.SOURCE,
    regex=r'\bgetenv\s*\(',
    languages=["c", "cpp"],
    description="Environment variable read — semi-trusted input",
    attack_vector="Environment variables can be set by the attacker in some contexts "
                  "(CGI, containerized apps, child processes). Data flows to sinks without "
                  "sanitization are exploitable.",
    cwe="CWE-20",
))

_p(VulnPattern(
    id="c_fread_source",
    category=VulnCategory.BUFFER_OVERFLOW,
    severity=Severity.INFO,
    hit_type=HitType.SOURCE,
    regex=r'\b(?:fread|fgets|getline)\s*\(',
    languages=["c", "cpp"],
    description="File/stdin read — potentially attacker-controlled",
    attack_vector="If the file being read is attacker-provided (uploaded document, config file, "
                  "media file), the data is fully controlled. Flows to parsing sinks are critical.",
    cwe="CWE-20",
))

_p(VulnPattern(
    id="py_request_source",
    category=VulnCategory.SQL_INJECTION,
    severity=Severity.INFO,
    hit_type=HitType.SOURCE,
    regex=r'\b(?:request\.(?:GET|POST|args|form|json|data|params|body)|request\.getParameter|getQueryString)\b',
    languages=["python", "java", "kotlin"],
    description="HTTP request parameter — direct attacker input",
    attack_vector="HTTP request parameters are the primary attack surface for web applications. "
                  "Every flow from request params to a sink (SQL, command, file) is an attack vector.",
    cwe="CWE-20",
))

_p(VulnPattern(
    id="java_inputstream_source",
    category=VulnCategory.BUFFER_OVERFLOW,
    severity=Severity.INFO,
    hit_type=HitType.SOURCE,
    regex=r'\b(?:InputStream|BufferedReader|DataInputStream|Scanner)\s*[.(]',
    languages=["java", "kotlin"],
    description="Java input stream — external data source",
    attack_vector="Input streams from files, network, or user input carry attacker-controlled data.",
    cwe="CWE-20",
))


# ---------------------------------------------------------------------------
# AUTH BYPASS (CWE-287)
# ---------------------------------------------------------------------------

_p(VulnPattern(
    id="auth_strcmp_password",
    category=VulnCategory.AUTH_BYPASS,
    severity=Severity.HIGH,
    hit_type=HitType.SINK,
    regex=r'\b(?:strcmp|strncmp|memcmp)\s*\([^)]*(?:password|passwd|secret|token)',
    languages=["c", "cpp"],
    description="String comparison for authentication",
    attack_vector="Non-constant-time string comparison for passwords/tokens leaks information "
                  "via timing side channels. An attacker can brute-force one byte at a time.",
    cwe="CWE-208",
))

# ---------------------------------------------------------------------------
# RESOURCE LEAK (CWE-772)
# ---------------------------------------------------------------------------

_p(VulnPattern(
    id="c_resource_no_close",
    category=VulnCategory.RESOURCE_LEAK,
    severity=Severity.LOW,
    hit_type=HitType.SINK,
    regex=r'\b(?:fopen|socket|open|CreateFile[A-Za-z]*|malloc)\s*\(',
    languages=["c", "cpp"],
    description="Resource allocation — check for matching deallocation",
    attack_vector="Repeated resource allocation without deallocation leads to denial of service "
                  "via file descriptor / memory exhaustion. Exploitable in long-running services.",
    cwe="CWE-772",
    false_positive_hints=["fclose/close in the same function", "RAII/smart pointer wrapper"],
))


# ===========================================================================
# Language mapping for file extension → language name
# ===========================================================================

EXT_TO_LANGUAGE: dict[str, str] = {
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hh": "cpp", ".hpp": "cpp", ".hxx": "cpp",
    ".java": "java",
    ".kt": "kotlin", ".kts": "kotlin",
    ".py": "python",
    ".swift": "swift",
    ".rs": "rust",
    ".m": "objc", ".mm": "objc",
}

# Directories to skip during scanning
SKIP_DIRS: set[str] = {
    ".git", "node_modules", "build", "target", ".gradle",
    "__pycache__", ".venv", "venv", "vendor", "third_party",
    "out", "dist", ".cache", ".ccache",
    "test", "tests", "testing", "testdata", "test_data",
    "examples", "samples", "benchmarks", "docs", "doc",
    "fuzz", "fuzzer", "fuzzers",
}
#src\deeptrace\scanner\scanner.py
"""Vulnerability scanner: scans a repo for potential attack vectors.

Orchestrates three phases:
  1. FAST PASS — Regex pattern matching across all source files.
  2. CONTEXT ENRICHMENT — Extracts surrounding code, enclosing function,
     nearby safety guards for each hit.
  3. LLM TRIAGE — Sends enriched hits to the LLM to eliminate false positives,
     explain attack vectors, and pair sources with sinks.

Output: Extended lines.json compatible with `deeptrace batch`.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from deeptrace.scanner.context_analyzer import ScanHit, extract_context
from deeptrace.scanner.llm_analyzer import LLMAnalyzer
from deeptrace.scanner.patterns import (
    EXT_TO_LANGUAGE,
    PATTERNS,
    SKIP_DIRS,
    HitType,
    Severity,
    VulnPattern,
)

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Final result for one confirmed vulnerability."""
    file: str
    line: int
    category: str
    severity: str
    confidence: str
    pattern_id: str
    cwe: str
    description: str
    explanation: str                  # LLM explanation of WHY this is vulnerable
    attack_scenario: str              # concrete attack description
    source_file: str = ""             # paired source location (for deeptrace batch)
    source_line: int = 0
    source_description: str = ""
    enclosing_function: str = ""
    code_snippet: str = ""
    hit_type: str = "sink"            # sink / source / both
    # Attack vector analysis fields (from LLM backward reasoning)
    tainted_parameters: list[str] = field(default_factory=list)
    input_type: str = ""              # e.g. "malformed PDF font table", "HTTP POST body"
    entry_point_description: str = "" # where attacker data enters the codebase
    entry_point_file_hint: str = ""   # best guess at file/directory
    exploitability: str = ""          # high/medium/low
    prerequisites: str = ""           # conditions for the attack to work

    def to_lines_json_entry(self) -> dict[str, Any]:
        """Convert to lines.json format for `deeptrace batch`."""
        entry: dict[str, Any] = {
            "file": self.file,
            "line": self.line,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "cwe": self.cwe,
            "description": self.description,
            "explanation": self.explanation,
            "attack_scenario": self.attack_scenario,
            "enclosing_function": self.enclosing_function,
        }
        if self.source_file:
            entry["source_file"] = self.source_file
            entry["source_line"] = self.source_line
            entry["source_description"] = self.source_description
        # Attack vector analysis
        if self.input_type:
            entry["input_type"] = self.input_type
        if self.entry_point_description:
            entry["entry_point"] = self.entry_point_description
        if self.entry_point_file_hint:
            entry["entry_point_file_hint"] = self.entry_point_file_hint
        if self.tainted_parameters:
            entry["tainted_parameters"] = self.tainted_parameters
        if self.exploitability:
            entry["exploitability"] = self.exploitability
        if self.prerequisites:
            entry["prerequisites"] = self.prerequisites
        return entry


@dataclass
class ScanSummary:
    """Summary of a full scan."""
    repo: str
    files_scanned: int = 0
    pattern_hits: int = 0
    after_dedup: int = 0
    llm_evaluated: int = 0
    confirmed_vulns: int = 0
    false_positives_removed: int = 0
    sources_found: int = 0
    pairs_identified: int = 0
    attack_vectors_analyzed: int = 0
    elapsed_seconds: float = 0.0
    results: list[ScanResult] = field(default_factory=list)


class VulnScanner:
    """Scans a repository for potential attack vectors.

    Usage::

        scanner = VulnScanner(repo_path="/path/to/repo")
        summary = scanner.scan()
        scanner.write_output(summary, "lines.json")
    """

    def __init__(
        self,
        repo_path: str,
        llm_caller: Callable[[str, str], str] | None = None,
        languages: list[str] | None = None,
        severity_threshold: str = "low",
        context_lines: int = 10,
        max_hits_per_file: int = 50,
        max_total_hits: int = 500,
        max_source_hops: int = 3,
    ) -> None:
        self.repo_path = os.path.abspath(repo_path)
        self.llm_caller = llm_caller
        self.languages = set(languages) if languages else None  # None = all
        self.severity_threshold = Severity(severity_threshold)
        self.context_lines = context_lines
        self.max_hits_per_file = max_hits_per_file
        self.max_total_hits = max_total_hits
        self.max_source_hops = max_source_hops

        self._severity_order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1,
            Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4,
        }

    def scan(
        self,
        progress_callback: Callable[[str, float], None] | None = None,
    ) -> ScanSummary:
        """Run the full scan pipeline.

        The pipeline is structured as three independent phases:

        **Phase A — Sink detection** (independent):
          A1. Regex pattern scan across all source files.
          A2. Context enrichment + dedup.
          A3. LLM triage (real vs false positive).

        **Phase B — Source discovery** (independent, uses real repo code):
          B1. For each confirmed sink, search the repo for callers of the
              enclosing function (grep/Python + file parsing).
          B2. Walk UP 2-3 hops collecting real code, signatures, parameters.
          B3. LLM analyzes the real call chains to identify entry points
              and concrete attack scenarios.

        **Phase C — Connect**:
          C1. Merge sink triage results with source discovery results.
          C2. Also run legacy regex source-sink pairing as a supplement.
          C3. Build final results and output lines.json.

        Args:
            progress_callback: Called with (stage_name, percent).

        Returns:
            ScanSummary with all results.
        """
        t0 = time.time()
        summary = ScanSummary(repo=self.repo_path)

        def _prog(stage: str, pct: float) -> None:
            if progress_callback:
                progress_callback(stage, pct)

        # ==================================================================
        # PHASE A: Sink detection (independent)
        # ==================================================================

        # A1. Fast pattern scan
        _prog("scanning", 0.0)
        logger.info("Phase A1: Scanning repo for pattern matches...")
        raw_hits = self._scan_repo()
        summary.files_scanned = self._last_files_count
        summary.pattern_hits = len(raw_hits)
        logger.info("  Found %d raw pattern hits across %d files",
                     len(raw_hits), summary.files_scanned)

        # A2. Context enrichment + deduplication
        _prog("context", 0.15)
        logger.info("Phase A2: Extracting context for %d hits...", len(raw_hits))
        enriched = self._enrich_hits(raw_hits)
        enriched = self._deduplicate(enriched)
        summary.after_dedup = len(enriched)
        logger.info("  After enrichment + dedup: %d hits", len(enriched))

        # Separate sinks from regex-detected sources
        sinks = [h for h in enriched if h.pattern.hit_type in (HitType.SINK, HitType.BOTH)]
        regex_sources = [h for h in enriched if h.pattern.hit_type == HitType.SOURCE]
        summary.sources_found = len(regex_sources)

        # A3. LLM triage
        evaluations: list[dict[str, Any]] = []
        confirmed_sinks: list[ScanHit] = list(sinks)  # default: keep all if no LLM

        if self.llm_caller and sinks:
            _prog("llm_triage", 0.25)
            logger.info("Phase A3: LLM evaluating %d sink candidates...", len(sinks))
            analyzer = LLMAnalyzer(self.llm_caller)

            evaluations = analyzer.evaluate_hits(sinks)
            summary.llm_evaluated = len(evaluations)

            confirmed_sinks = []
            for i, (hit, ev) in enumerate(zip(sinks, evaluations)):
                if ev.get("is_real", True):
                    confirmed_sinks.append(hit)
                else:
                    summary.false_positives_removed += 1

            logger.info(
                "  LLM confirmed %d / %d sinks (removed %d false positives)",
                len(confirmed_sinks), len(sinks), summary.false_positives_removed,
            )
        elif not self.llm_caller:
            logger.info("Phase A3: Skipped (no LLM). All %d pattern sinks retained.", len(sinks))

        logger.info("--- Phase A complete: %d confirmed sinks ---", len(confirmed_sinks))

        # ==================================================================
        # PHASE B: Source discovery (independent, from real repo code)
        # ==================================================================

        call_chains: list[Any] = []
        attack_vectors: list[dict[str, Any]] = []

        if confirmed_sinks and self.max_source_hops > 0:
            # B1 + B2. Walk the repo to find real caller chains
            _prog("source_discovery", 0.45)
            logger.info("Phase B1: Discovering sources from repo for %d sinks (max %d hops)...",
                        len(confirmed_sinks), self.max_source_hops)

            from deeptrace.scanner.source_discoverer import SourceDiscoverer

            discoverer = SourceDiscoverer(
                repo_path=self.repo_path,
                max_hops=self.max_source_hops,
                context_lines=8,
            )

            # Build the sink descriptors for the discoverer
            sink_descriptors = [
                {
                    "file": h.file,
                    "line": h.line,
                    "enclosing_function": h.enclosing_function,
                    "code_snippet": h.matched_text.strip(),
                }
                for h in confirmed_sinks
            ]

            call_chains = discoverer.discover_sources(sink_descriptors)

            chains_found = sum(1 for c in call_chains if c.depth > 0)
            logger.info(
                "  Found caller chains for %d / %d sinks (total hops: %d)",
                chains_found, len(confirmed_sinks),
                sum(c.depth for c in call_chains),
            )

            # B3. LLM analyzes the real call chains
            if self.llm_caller:
                _prog("attack_vectors", 0.60)
                logger.info("Phase B3: LLM analyzing attack vectors with real call chains...")
                analyzer = LLMAnalyzer(self.llm_caller)
                attack_vectors = analyzer.analyze_attack_vectors(
                    confirmed_sinks, call_chains,
                )
                summary.attack_vectors_analyzed = sum(1 for av in attack_vectors if av)
                logger.info(
                    "  Attack vectors analyzed: %d / %d",
                    summary.attack_vectors_analyzed, len(confirmed_sinks),
                )

        elif self.max_source_hops == 0:
            logger.info("Phase B: Skipped (--max-source-hops 0)")
        else:
            logger.info("Phase B: Skipped (no confirmed sinks)")

        logger.info("--- Phase B complete: %d attack vectors ---", len(attack_vectors))

        # ==================================================================
        # PHASE C: Connect sinks with sources → output
        # ==================================================================
        _prog("pairing", 0.80)
        logger.info("Phase C: Connecting sinks with discovered sources...")

        # C1. Legacy regex source-sink pairing (supplement)
        pairs: list[dict[str, Any]] = []
        if self.llm_caller and confirmed_sinks and regex_sources:
            logger.info("  C1: Regex source-sink pairing (%d sources)...", len(regex_sources))
            analyzer = LLMAnalyzer(self.llm_caller)
            pairs = analyzer.identify_source_sink_pairs(confirmed_sinks, regex_sources)
            summary.pairs_identified = len([p for p in pairs if p.get("source_file")])

        # C2. Build final results (merges everything)
        _prog("results", 0.90)
        results = self._build_results(
            confirmed_sinks, regex_sources,
            evaluations, pairs, attack_vectors, call_chains,
        )
        summary.confirmed_vulns = len([r for r in results if r.hit_type == "sink"])
        summary.results = results
        summary.elapsed_seconds = round(time.time() - t0, 2)

        _prog("done", 1.0)
        logger.info(
            "Scan complete: %d confirmed sinks, %d regex sources, "
            "%d attack vectors, %d pairs in %.1fs",
            summary.confirmed_vulns, summary.sources_found,
            summary.attack_vectors_analyzed, summary.pairs_identified,
            summary.elapsed_seconds,
        )

        return summary
        summary.confirmed_vulns = len([r for r in results if r.hit_type == "sink"])
        summary.results = results
        summary.elapsed_seconds = round(time.time() - t0, 2)

        _prog("done", 1.0)
        logger.info(
            "Scan complete: %d confirmed sinks, %d sources, %d pairs in %.1fs",
            summary.confirmed_vulns, summary.sources_found,
            summary.pairs_identified, summary.elapsed_seconds,
        )

        return summary

    # ------------------------------------------------------------------
    # Phase 1: Regex scan
    # ------------------------------------------------------------------

    _last_files_count: int = 0

    def _scan_repo(self) -> list[tuple[str, int, VulnPattern]]:
        """Walk the repo and apply all patterns to every source file.

        Returns list of (relative_file_path, line_number, pattern).
        """
        hits: list[tuple[str, int, VulnPattern]] = []
        files_scanned = 0

        # Filter patterns by severity threshold
        threshold_val = self._severity_order.get(self.severity_threshold, 3)
        active_patterns = [
            p for p in PATTERNS
            if self._severity_order.get(p.severity, 4) <= threshold_val
        ]

        for root, dirs, files in os.walk(self.repo_path):
            # Skip uninteresting directories
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for fname in files:
                ext = Path(fname).suffix.lower()
                lang = EXT_TO_LANGUAGE.get(ext)
                if not lang:
                    continue
                if self.languages and lang not in self.languages:
                    continue

                abs_path = os.path.join(root, fname)
                rel_path = os.path.relpath(abs_path, self.repo_path).replace("\\", "/")

                try:
                    source = Path(abs_path).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                files_scanned += 1
                file_hits = 0

                for pattern in active_patterns:
                    if lang not in pattern.languages:
                        continue

                    for m in pattern.compiled_regex.finditer(source):
                        if file_hits >= self.max_hits_per_file:
                            break
                        if len(hits) >= self.max_total_hits:
                            break

                        # Convert byte offset to line number
                        line_no = source[:m.start()].count("\n") + 1
                        hits.append((rel_path, line_no, pattern))
                        file_hits += 1

                    if len(hits) >= self.max_total_hits:
                        break

                if len(hits) >= self.max_total_hits:
                    logger.warning("Hit limit (%d) reached — stopping scan", self.max_total_hits)
                    break

            if len(hits) >= self.max_total_hits:
                break

        self._last_files_count = files_scanned
        return hits

    # ------------------------------------------------------------------
    # Phase 2: Context enrichment
    # ------------------------------------------------------------------

    def _enrich_hits(
        self, raw_hits: list[tuple[str, int, VulnPattern]],
    ) -> list[ScanHit]:
        """Extract context for each raw hit."""
        enriched: list[ScanHit] = []
        for file_path, line_no, pattern in raw_hits:
            hit = extract_context(
                file_path, self.repo_path, line_no, pattern,
                context_lines=self.context_lines,
            )
            if hit and hit.confidence != "low":
                enriched.append(hit)
        return enriched

    def _deduplicate(self, hits: list[ScanHit]) -> list[ScanHit]:
        """Remove duplicate hits on the same line (different patterns may match)."""
        seen: set[tuple[str, int]] = set()
        deduped: list[ScanHit] = []

        # Sort by severity (critical first) so we keep the most severe pattern
        hits.sort(key=lambda h: self._severity_order.get(h.pattern.severity, 4))

        for hit in hits:
            key = (hit.file, hit.line)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(hit)

        return deduped

    # ------------------------------------------------------------------
    # Phase 4: Build results
    # ------------------------------------------------------------------

    def _build_results(
        self,
        sinks: list[ScanHit],
        sources: list[ScanHit],
        evaluations: list[dict[str, Any]],
        pairs: list[dict[str, Any]],
        attack_vectors: list[dict[str, Any]],
        call_chains: list[Any] | None = None,
    ) -> list[ScanResult]:
        """Combine hits, LLM evaluations, pairings, call chains, and attack vectors.

        Source resolution priority (highest → lowest):
          1. Call chain top — the outermost real caller file:line from the repo
          2. Regex pair — source matched by pattern + LLM pairing
          3. LLM attack vector hint — inferred entry_point_file_hint
          4. LLM triage source_hint — from the evaluation pass
        """
        results: list[ScanResult] = []

        # Build evaluation lookup
        eval_map: dict[int, dict[str, Any]] = {}
        for ev in evaluations:
            idx = ev.get("hit_index", -1)
            if idx >= 0:
                eval_map[idx] = ev

        # Build pair lookup
        pair_map: dict[int, dict[str, Any]] = {}
        for p in pairs:
            idx = p.get("sink_index", -1)
            if idx >= 0:
                pair_map[idx] = p

        # Build attack vector lookup
        av_map: dict[int, dict[str, Any]] = {}
        for i, av in enumerate(attack_vectors):
            if av:
                idx = av.get("sink_index", i)
                av_map[idx] = av

        # Sink results
        for i, hit in enumerate(sinks):
            ev = eval_map.get(i, {})
            pair = pair_map.get(i, {})
            av = av_map.get(i, {})
            chain = call_chains[i] if call_chains and i < len(call_chains) else None

            # --- Attack scenario: prefer call-chain-aware analysis ---
            attack_scenario = (
                av.get("attack_scenario")
                or ev.get("attack_scenario")
                or ""
            )

            # --- Source resolution (priority order) ---
            source_file = ""
            source_line = 0
            source_desc = ""

            # Priority 1: Top of the REAL call chain from the repo
            if chain and chain.depth > 0:
                top_hop = chain.hops[-1]  # outermost caller
                source_file = top_hop.file
                source_line = top_hop.line
                source_desc = (
                    f"Caller chain top: {top_hop.enclosing_function}() "
                    f"— {top_hop.call_expression[:80]}"
                )

            # Priority 2: Regex-detected source matched by LLM pairing
            if not source_file and pair.get("source_file"):
                source_file = pair.get("source_file", "")
                source_line = int(pair.get("source_line", 0))
                source_desc = pair.get("source_description", "")

            # Priority 3: LLM attack vector file hint
            if not source_file and av.get("entry_point_file_hint"):
                source_file = av.get("entry_point_file_hint", "")
                source_desc = av.get("entry_point_description", "")

            # Priority 4: LLM triage source hint (just a description, no file)
            if not source_desc and ev.get("source_hint"):
                source_desc = ev.get("source_hint", "")

            results.append(ScanResult(
                file=hit.file,
                line=hit.line,
                category=hit.pattern.category.value,
                severity=ev.get("severity", hit.pattern.severity.value),
                confidence=ev.get("confidence", hit.confidence),
                pattern_id=hit.pattern.id,
                cwe=hit.pattern.cwe,
                description=hit.pattern.description,
                explanation=ev.get("explanation", hit.pattern.attack_vector),
                attack_scenario=attack_scenario,
                source_file=source_file,
                source_line=source_line,
                source_description=source_desc,
                enclosing_function=hit.enclosing_function,
                code_snippet=hit.matched_text.strip(),
                hit_type="sink",
                # Attack vector analysis fields
                tainted_parameters=av.get("tainted_parameters", []),
                input_type=av.get("input_type", ""),
                entry_point_description=av.get("entry_point_description", ""),
                entry_point_file_hint=av.get("entry_point_file_hint", ""),
                exploitability=av.get("exploitability", ""),
                prerequisites=av.get("prerequisites", ""),
            ))

        # Source results (included for reference, not as primary targets)
        for hit in sources:
            results.append(ScanResult(
                file=hit.file,
                line=hit.line,
                category=hit.pattern.category.value,
                severity=hit.pattern.severity.value,
                confidence=hit.confidence,
                pattern_id=hit.pattern.id,
                cwe=hit.pattern.cwe,
                description=hit.pattern.description,
                explanation=hit.pattern.attack_vector,
                attack_scenario="",
                enclosing_function=hit.enclosing_function,
                code_snippet=hit.matched_text.strip(),
                hit_type="source",
            ))

        # Sort: sinks first (by severity), then sources
        type_order = {"sink": 0, "both": 0, "source": 1}
        results.sort(key=lambda r: (
            type_order.get(r.hit_type, 1),
            self._severity_order.get(Severity(r.severity), 4),
        ))

        return results

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    def write_output(
        self,
        summary: ScanSummary,
        output_path: str,
        include_sources: bool = False,
    ) -> None:
        """Write results to a lines.json file + a human-readable report.

        Creates two files:
          - {output_path}:        lines.json (for `deeptrace batch`)
          - {output_path}.report: human-readable scan report
        """
        # lines.json — only sinks (suitable for deeptrace batch)
        entries = []
        for r in summary.results:
            if r.hit_type == "source" and not include_sources:
                continue
            entries.append(r.to_lines_json_entry())

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(
            json.dumps(entries, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info("Wrote %d entries to %s", len(entries), output_path)

        # Human-readable report
        report_path = output_path + ".report.md"
        report = self._generate_report(summary)
        Path(report_path).write_text(report, encoding="utf-8")
        logger.info("Wrote scan report to %s", report_path)

    def _generate_report(self, summary: ScanSummary) -> str:
        """Generate a human-readable Markdown scan report."""
        lines = [
            "# DeepTrace Vulnerability Scan Report",
            "",
            f"**Repository:** {summary.repo}",
            f"**Files scanned:** {summary.files_scanned}",
            f"**Pattern hits:** {summary.pattern_hits}",
            f"**After dedup:** {summary.after_dedup}",
            f"**LLM evaluated:** {summary.llm_evaluated}",
            f"**False positives removed:** {summary.false_positives_removed}",
            f"**Confirmed vulnerabilities:** {summary.confirmed_vulns}",
            f"**Attack vectors analyzed:** {summary.attack_vectors_analyzed}",
            f"**Sources identified:** {summary.sources_found}",
            f"**Source-sink pairs:** {summary.pairs_identified}",
            f"**Time:** {summary.elapsed_seconds:.1f}s",
            "",
            "---",
            "",
        ]

        # Results table
        sinks = [r for r in summary.results if r.hit_type != "source"]
        if sinks:
            lines += [
                "## Vulnerability Targets",
                "",
                "| # | Severity | Category | File:Line | Function | CWE | Confidence |",
                "|---|----------|----------|-----------|----------|-----|------------|",
            ]
            for i, r in enumerate(sinks):
                sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}.get(r.severity, "⚪")
                lines.append(
                    f"| {i} | {sev_icon} {r.severity} | {r.category} | "
                    f"`{r.file}:{r.line}` | {r.enclosing_function or '?'} | "
                    f"{r.cwe} | {r.confidence} |"
                )
            lines += ["", ""]

        # Detailed findings
        if sinks:
            lines.append("## Detailed Findings")
            lines.append("")

            for i, r in enumerate(sinks):
                lines += [
                    f"### {i}. {r.category} — `{r.file}:{r.line}`",
                    "",
                    f"**Severity:** {r.severity} | **CWE:** {r.cwe} | **Confidence:** {r.confidence}",
                ]
                if r.exploitability:
                    lines.append(f" | **Exploitability:** {r.exploitability}")
                lines += [
                    "",
                    f"**Code:**",
                    f"```",
                    f"{r.code_snippet}",
                    f"```",
                    "",
                    f"**Why this is dangerous:**",
                    f"{r.explanation}",
                    "",
                ]
                if r.attack_scenario:
                    lines += [
                        f"**Attack scenario:**",
                        f"{r.attack_scenario}",
                        "",
                    ]
                if r.input_type:
                    lines += [
                        f"**Attack input type:** {r.input_type}",
                        "",
                    ]
                if r.tainted_parameters:
                    lines += [
                        f"**Tainted parameters:** `{'`, `'.join(r.tainted_parameters)}`",
                        "",
                    ]
                if r.entry_point_description:
                    lines += [
                        f"**Entry point:** {r.entry_point_description}",
                    ]
                    if r.entry_point_file_hint:
                        lines.append(f"  Likely location: `{r.entry_point_file_hint}`")
                    lines.append("")
                if r.prerequisites:
                    lines += [
                        f"**Prerequisites:** {r.prerequisites}",
                        "",
                    ]
                if r.source_file:
                    lines += [
                        f"**Paired source:** `{r.source_file}:{r.source_line}` — {r.source_description}",
                        "",
                    ]
                elif r.source_description:
                    lines += [
                        f"**Likely source:** {r.source_description}",
                        "",
                    ]
                lines += ["---", ""]

        lines += ["*Generated by DeepTrace Scanner v1.0.0*"]
        return "\n".join(lines)
#src\deeptrace\scanner\source_discoverer.py
"""Source discoverer: walks the real repo to find how data reaches each sink.

For each confirmed sink, this module:
  1. Finds callers of the sink's enclosing function (grep + tree-sitter).
  2. Walks UP 2-3 hops, collecting real code context at each level.
  3. Packages the result into a CallChain that carries actual code from the repo.

This runs as an INDEPENDENT phase from sink scanning — it only needs the
confirmed sink locations and function names, not the pattern/triage data.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Directories to skip
_SKIP_DIRS = {
    ".git", "node_modules", "build", "target", ".gradle",
    "__pycache__", ".venv", "venv", "vendor", "third_party",
    "out", "dist", ".cache", ".ccache",
    "test", "tests", "testing", "testdata",
}

# File extensions to search
_SEARCH_EXTENSIONS = {
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx", ".hh",
    ".java", ".kt", ".kts", ".py", ".swift", ".rs", ".m", ".mm",
}


@dataclass
class CallerInfo:
    """One caller in the chain — real code from the repo."""
    file: str                         # relative path
    line: int                         # line of the call expression
    enclosing_function: str           # function that contains the call
    function_signature: str           # full signature of the enclosing function
    call_expression: str              # the actual call line (e.g., "GetNativeFontName(charset, &lf)")
    context: list[str] = field(default_factory=list)  # ±N lines around the call
    parameters: list[str] = field(default_factory=list)  # parameter names of enclosing function

    @property
    def context_str(self) -> str:
        return "\n".join(self.context)


@dataclass
class CallChain:
    """A chain of callers leading to a sink — all from real repo code."""
    sink_file: str
    sink_line: int
    sink_function: str
    sink_code: str
    hops: list[CallerInfo] = field(default_factory=list)  # [0]=direct caller, [1]=caller's caller, etc.

    @property
    def depth(self) -> int:
        return len(self.hops)

    @property
    def files_involved(self) -> list[str]:
        files = [self.sink_file]
        for hop in self.hops:
            if hop.file not in files:
                files.append(hop.file)
        return files

    def format_for_llm(self) -> str:
        """Format the entire call chain as readable text for LLM analysis."""
        lines = [
            f"=== Call Chain to Sink ===",
            f"Sink: {self.sink_file}:{self.sink_line} — function {self.sink_function}",
            f"Sink code: {self.sink_code}",
            f"Chain depth: {self.depth} hops across {len(self.files_involved)} files",
            "",
        ]

        for i, hop in enumerate(self.hops):
            lines.append(f"--- Hop {i} (caller of {'sink' if i == 0 else f'hop {i-1}'}) ---")
            lines.append(f"File: {hop.file}:{hop.line}")
            lines.append(f"Enclosing function: {hop.enclosing_function}")
            if hop.function_signature:
                lines.append(f"Signature: {hop.function_signature}")
            if hop.parameters:
                lines.append(f"Parameters: {', '.join(hop.parameters)}")
            lines.append(f"Call: {hop.call_expression}")
            lines.append("")
            lines.append("Context:")
            lines.append(hop.context_str)
            lines.append("")

        return "\n".join(lines)


class SourceDiscoverer:
    """Walks the real repo to discover how data reaches each sink.

    This is the Phase B of the scanning pipeline — completely independent
    from Phase A (sink pattern detection + triage).  It takes a list of
    confirmed sink locations and, for each one, searches the codebase for
    the chain of callers that could carry attacker-controlled data to the
    sink.
    """

    def __init__(
        self,
        repo_path: str,
        max_hops: int = 3,
        context_lines: int = 8,
        max_callers_per_function: int = 10,
    ) -> None:
        self.repo_path = os.path.abspath(repo_path)
        self.max_hops = max_hops
        self.context_lines = context_lines
        self.max_callers = max_callers_per_function
        self._grep_available: bool | None = None

    def discover_sources(
        self,
        sinks: list[dict[str, Any]],
    ) -> list[CallChain]:
        """Build call chains for a list of confirmed sinks.

        Args:
            sinks: List of dicts with keys: file, line, enclosing_function, code_snippet

        Returns:
            List of CallChain objects (same length as sinks; empty chains when
            no callers are found).
        """
        chains: list[CallChain] = []

        for i, sink in enumerate(sinks):
            func_name = sink.get("enclosing_function", "")
            sink_file = sink.get("file", "")
            sink_line = sink.get("line", 0)
            sink_code = sink.get("code_snippet", "")

            chain = CallChain(
                sink_file=sink_file,
                sink_line=sink_line,
                sink_function=func_name,
                sink_code=sink_code,
            )

            if not func_name or len(func_name) <= 2:
                chains.append(chain)
                continue

            logger.debug("  Sink %d: tracing callers of %s from %s:%d",
                        i, func_name, sink_file, sink_line)

            # Walk up the call chain
            current_func = func_name
            current_file = sink_file
            visited_funcs: set[str] = {func_name}

            for hop_num in range(self.max_hops):
                callers = self._find_callers(current_func, exclude_file=current_file)

                if not callers:
                    break

                # Take the best caller (first one found; they're already deduped)
                best = callers[0]
                chain.hops.append(best)

                # Prepare for next hop
                next_func = best.enclosing_function
                if not next_func or next_func in visited_funcs or len(next_func) <= 2:
                    break
                visited_funcs.add(next_func)
                current_func = next_func
                current_file = best.file

            if chain.depth > 0:
                logger.info(
                    "  Sink %d (%s): found %d-hop chain across %s",
                    i, func_name, chain.depth, chain.files_involved,
                )

            chains.append(chain)

        return chains

    # ------------------------------------------------------------------
    # Find callers of a function
    # ------------------------------------------------------------------

    def _find_callers(
        self,
        func_name: str,
        exclude_file: str = "",
    ) -> list[CallerInfo]:
        """Search the repo for call sites of func_name.

        Returns CallerInfo objects with real code context from the repo.
        """
        # Validate function name
        if not func_name or " " in func_name or "&" in func_name or "*" in func_name:
            return []

        # Text search for "func_name("
        candidate_lines = self._search_repo(func_name)

        results: list[CallerInfo] = []
        exclude_norm = exclude_file.replace("\\", "/")
        seen_locations: set[tuple[str, int]] = set()

        for file_path, line_no in candidate_lines:
            if len(results) >= self.max_callers:
                break
            if file_path == exclude_norm:
                continue

            key = (file_path, line_no)
            if key in seen_locations:
                continue
            seen_locations.add(key)

            # Read the file and extract context
            caller = self._extract_caller_context(file_path, line_no, func_name)
            if caller is not None:
                results.append(caller)

        return results

    def _extract_caller_context(
        self,
        file_path: str,
        line_no: int,
        called_func: str,
    ) -> CallerInfo | None:
        """Read real code from the file and extract caller context."""
        abs_path = os.path.join(self.repo_path, file_path)
        try:
            source = Path(abs_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

        all_lines = source.split("\n")
        if line_no < 1 or line_no > len(all_lines):
            return None

        call_line = all_lines[line_no - 1].strip()

        # Verify this is actually a call (not a definition, comment, or string)
        if self._is_definition(call_line, called_func):
            return None
        if call_line.lstrip().startswith("//") or call_line.lstrip().startswith("*"):
            return None

        # Extract context window
        start = max(0, line_no - 1 - self.context_lines)
        end = min(len(all_lines), line_no + self.context_lines)
        context = []
        for i in range(start, end):
            marker = ">>>" if i == line_no - 1 else "   "
            context.append(f"{marker} {i+1:4d} | {all_lines[i].rstrip()}")

        # Find enclosing function
        enc_func, func_sig, params = self._find_enclosing_function(all_lines, line_no)

        return CallerInfo(
            file=file_path,
            line=line_no,
            enclosing_function=enc_func,
            function_signature=func_sig,
            call_expression=call_line,
            context=context,
            parameters=params,
        )

    @staticmethod
    def _is_definition(line: str, func_name: str) -> bool:
        """Check if this line is the function DEFINITION, not a call."""
        stripped = line.strip()
        # Definition patterns: "ReturnType FuncName(" at the start, or with class prefix
        # Key signal: the function name is followed by ( and preceded by a type/qualifier
        # but NOT preceded by another call or assignment context

        # If it contains "= func(" or ".func(" or "->func(", it's a call
        if f".{func_name}(" in stripped or f"->{func_name}(" in stripped:
            return False
        if f"= {func_name}(" in stripped or f"({func_name}(" in stripped:
            return False
        if f"return {func_name}(" in stripped.lower():
            return False

        # If it looks like "Type Class::FuncName(params) {" → definition
        if re.search(rf'\b{re.escape(func_name)}\s*\([^)]*\)\s*(?:const\s*)?(?:override\s*)?{{?\s*$', stripped):
            # Could be definition — check if there's a return type before it
            before_func = stripped[:stripped.index(func_name)].strip()
            if before_func and not before_func.endswith((".", "->", "(", ",")):
                # Likely a definition
                if any(before_func.endswith(kw) for kw in ("void", "int", "bool", "auto", "char",
                         "size_t", "string", "String", "ByteString", "WideString", "float", "double")):
                    return True
                if "::" in before_func:  # Class::FuncName
                    return True

        return False

    @staticmethod
    def _find_enclosing_function(
        lines: list[str],
        target_line: int,
    ) -> tuple[str, str, list[str]]:
        """Walk backward to find the enclosing function definition.

        Returns (function_name, full_signature, [parameter_names]).
        """
        func_patterns = [
            # C/C++
            re.compile(r'^\s*(?:[\w:*&<>\s]+?)\s+(\w[\w:]*)\s*\(([^)]*)\)\s*(?:const\s*)?(?:override\s*)?(?:noexcept\s*)?{?\s*$'),
            # Java/Kotlin
            re.compile(r'^\s*(?:public|private|protected|static|final|override|fun|void|int|boolean|String)[\s\w]*\s+(\w+)\s*\(([^)]*)\)\s*(?:\{|:|\s*$)'),
            # Python
            re.compile(r'^\s*def\s+(\w+)\s*\(([^)]*)\)\s*(?:->.*)?:\s*$'),
            # Rust
            re.compile(r'^\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)'),
            # Swift
            re.compile(r'^\s*(?:public\s+|private\s+|internal\s+)?func\s+(\w+)\s*\(([^)]*)\)'),
        ]

        for i in range(target_line - 1, max(target_line - 80, -1), -1):
            if i < 0 or i >= len(lines):
                continue
            line = lines[i]
            for pat in func_patterns:
                m = pat.match(line)
                if m:
                    func_name = m.group(1)
                    params_str = m.group(2)
                    # Extract parameter names
                    params = _extract_param_names(params_str)
                    return func_name, line.strip(), params

        return "", "", []

    # ------------------------------------------------------------------
    # Text search
    # ------------------------------------------------------------------

    def _search_repo(self, func_name: str) -> list[tuple[str, int]]:
        """Find lines containing 'func_name(' in the repo."""
        # Try grep first
        if self._grep_available is None:
            self._grep_available = _check_grep()

        if self._grep_available:
            return self._grep_search(func_name)
        return self._python_search(func_name)

    def _grep_search(self, func_name: str) -> list[tuple[str, int]]:
        """Use grep for fast text search."""
        include_flags: list[str] = []
        for ext in _SEARCH_EXTENSIONS:
            include_flags += ["--include", f"*{ext}"]

        hits: list[tuple[str, int]] = []
        try:
            proc = subprocess.run(
                ["grep", "-rn", f"{func_name}("] + include_flags + [self.repo_path],
                capture_output=True, text=True, timeout=60,
            )
            for line in proc.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                parts = line.split(":", 2)
                if len(parts) < 2:
                    continue
                try:
                    abs_file = parts[0]
                    line_no = int(parts[1])
                    rel_file = os.path.relpath(abs_file, self.repo_path).replace("\\", "/")
                    # Skip test/build dirs
                    if any(f"/{d}/" in f"/{rel_file}" or rel_file.startswith(f"{d}/") for d in _SKIP_DIRS):
                        continue
                    hits.append((rel_file, line_no))
                except (ValueError, IndexError):
                    continue
        except Exception:
            pass
        return hits

    def _python_search(self, func_name: str) -> list[tuple[str, int]]:
        """Pure-Python fallback for Windows."""
        pattern = f"{func_name}("
        hits: list[tuple[str, int]] = []

        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in _SEARCH_EXTENSIONS:
                    continue
                abs_path = os.path.join(root, fname)
                rel_path = os.path.relpath(abs_path, self.repo_path).replace("\\", "/")
                try:
                    with open(abs_path, encoding="utf-8", errors="replace") as f:
                        for i, line in enumerate(f, 1):
                            if pattern in line:
                                hits.append((rel_path, i))
                except OSError:
                    continue
        return hits


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_param_names(params_str: str) -> list[str]:
    """Extract parameter names from a function signature parameter list.

    E.g., "FX_Charset charset, void* log_font" → ["charset", "log_font"]
    """
    if not params_str.strip():
        return []

    names: list[str] = []
    for part in params_str.split(","):
        part = part.strip()
        if not part:
            continue
        # Remove default values
        if "=" in part:
            part = part[:part.index("=")].strip()
        # The last word is the parameter name
        tokens = part.replace("*", " ").replace("&", " ").replace("<", " ").replace(">", " ").split()
        if tokens:
            name = tokens[-1].strip("()[]")
            if name and name not in ("void", "const", "..."):
                names.append(name)
    return names


def _check_grep() -> bool:
    """Check if grep is available."""
    try:
        proc = subprocess.run(["grep", "--version"], capture_output=True, timeout=5)
        return proc.returncode == 0
    except Exception:
        return False
#src\deeptrace_aco.egg-info\dependency_links.txt


#src\deeptrace_aco.egg-info\entry_points.txt
[console_scripts]
deeptrace = deeptrace.cli.main:cli

#src\deeptrace_aco.egg-info\PKG-INFO
Metadata-Version: 2.4
Name: deeptrace-aco
Version: 1.0.0
Summary: Production-grade deep dependency trace tool using Joern + tree-sitter + ACO
Author: deeptrace contributors
Requires-Python: >=3.10
Description-Content-Type: text/markdown
Requires-Dist: click>=8.1
Requires-Dist: rich>=13.0
Requires-Dist: pydantic>=2.0
Requires-Dist: pydantic-settings>=2.0
Requires-Dist: networkx>=3.1
Requires-Dist: numpy>=1.24
Requires-Dist: docker>=7.0
Requires-Dist: anthropic>=0.40
Requires-Dist: orjson>=3.9
Requires-Dist: tenacity>=8.2
Requires-Dist: xxhash>=3.4
Requires-Dist: tqdm>=4.66
Requires-Dist: prompt_toolkit>=3.0
Provides-Extra: treesitter-compat
Requires-Dist: tree-sitter<0.22,>=0.20; extra == "treesitter-compat"
Requires-Dist: tree-sitter-languages>=1.10; extra == "treesitter-compat"
Provides-Extra: treesitter
Requires-Dist: tree-sitter<0.24,>=0.23; extra == "treesitter"
Requires-Dist: tree-sitter-c<0.24,>=0.23; extra == "treesitter"
Requires-Dist: tree-sitter-cpp<0.24,>=0.23; extra == "treesitter"
Requires-Dist: tree-sitter-java<0.24,>=0.23; extra == "treesitter"
Requires-Dist: tree-sitter-rust<0.24,>=0.23; extra == "treesitter"
Requires-Dist: tree-sitter-swift>=0.0.1; extra == "treesitter"
Provides-Extra: z3
Requires-Dist: z3-solver>=4.12; extra == "z3"
Provides-Extra: dev
Requires-Dist: pytest>=7.4; extra == "dev"
Requires-Dist: pytest-cov>=4.1; extra == "dev"
Requires-Dist: pytest-asyncio>=0.21; extra == "dev"
Requires-Dist: ruff>=0.4; extra == "dev"
Requires-Dist: mypy>=1.8; extra == "dev"
Requires-Dist: z3-solver>=4.12; extra == "dev"
Requires-Dist: tree-sitter<0.24,>=0.23; extra == "dev"
Requires-Dist: tree-sitter-c<0.24,>=0.23; extra == "dev"
Requires-Dist: tree-sitter-cpp<0.24,>=0.23; extra == "dev"
Requires-Dist: tree-sitter-java<0.24,>=0.23; extra == "dev"
Requires-Dist: tree-sitter-rust<0.24,>=0.23; extra == "dev"
Requires-Dist: tree-sitter-swift>=0.0.1; extra == "dev"

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

#src\deeptrace_aco.egg-info\requires.txt
click>=8.1
rich>=13.0
pydantic>=2.0
pydantic-settings>=2.0
networkx>=3.1
numpy>=1.24
docker>=7.0
anthropic>=0.40
orjson>=3.9
tenacity>=8.2
xxhash>=3.4
tqdm>=4.66
prompt_toolkit>=3.0

[dev]
pytest>=7.4
pytest-cov>=4.1
pytest-asyncio>=0.21
ruff>=0.4
mypy>=1.8
z3-solver>=4.12
tree-sitter<0.24,>=0.23
tree-sitter-c<0.24,>=0.23
tree-sitter-cpp<0.24,>=0.23
tree-sitter-java<0.24,>=0.23
tree-sitter-rust<0.24,>=0.23
tree-sitter-swift>=0.0.1

[treesitter]
tree-sitter<0.24,>=0.23
tree-sitter-c<0.24,>=0.23
tree-sitter-cpp<0.24,>=0.23
tree-sitter-java<0.24,>=0.23
tree-sitter-rust<0.24,>=0.23
tree-sitter-swift>=0.0.1

[treesitter-compat]
tree-sitter<0.22,>=0.20
tree-sitter-languages>=1.10

[z3]
z3-solver>=4.12

#src\deeptrace_aco.egg-info\SOURCES.txt
README.md
pyproject.toml
src/deeptrace/__init__.py
src/deeptrace/analysis/__init__.py
src/deeptrace/analysis/constraint_solver.py
src/deeptrace/analysis/flow_analyzer.py
src/deeptrace/analysis/llm_ranker.py
src/deeptrace/backends/__init__.py
src/deeptrace/backends/dynamic_resolver.py
src/deeptrace/backends/joern.py
src/deeptrace/backends/treesitter.py
src/deeptrace/cli/__init__.py
src/deeptrace/cli/interactive.py
src/deeptrace/cli/main.py
src/deeptrace/cli/visualize.py
src/deeptrace/core/__init__.py
src/deeptrace/core/aco.py
src/deeptrace/core/batch.py
src/deeptrace/core/graph_builder.py
src/deeptrace/core/orchestrator.py
src/deeptrace/core/session.py
src/deeptrace/exploit/__init__.py
src/deeptrace/exploit/agent.py
src/deeptrace/exploit/docker_env.py
src/deeptrace/exploit/harness_generator.py
src/deeptrace/exploit/real_harness_generator.py
src/deeptrace/exploit/repo_analyzer.py
src/deeptrace/exploit/report_generator.py
src/deeptrace/exploit/sandbox_runner.py
src/deeptrace/exploit/validator.py
src/deeptrace/exploit/verification.py
src/deeptrace/models/__init__.py
src/deeptrace/models/config.py
src/deeptrace/models/graph.py
src/deeptrace/scanner/__init__.py
src/deeptrace/scanner/context_analyzer.py
src/deeptrace/scanner/llm_analyzer.py
src/deeptrace/scanner/patterns.py
src/deeptrace/scanner/scanner.py
src/deeptrace/scanner/source_discoverer.py
src/deeptrace_aco.egg-info/PKG-INFO
src/deeptrace_aco.egg-info/SOURCES.txt
src/deeptrace_aco.egg-info/dependency_links.txt
src/deeptrace_aco.egg-info/entry_points.txt
src/deeptrace_aco.egg-info/requires.txt
src/deeptrace_aco.egg-info/top_level.txt
tests/test_deeptrace.py
#src\deeptrace_aco.egg-info\top_level.txt
deeptrace

#tests\test_deeptrace.py
"""Tests for deeptrace-aco core functionality."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from deeptrace.models.graph import (
    BackendKind,
    BranchCandidate,
    BranchPoint,
    EdgeKind,
    GraphEdge,
    GraphNode,
    Language,
    NodeKind,
    SourceLocation,
    TracePath,
    TraceStep,
)
from deeptrace.models.config import DeeptraceConfig, ACOConfig, BranchingConfig
from deeptrace.core.graph_builder import DependencyGraph
from deeptrace.core.aco import ACOExplorer
from deeptrace.core.session import SessionManager
from deeptrace.analysis.flow_analyzer import (
    detect_patterns,
    enrich_paths_with_patterns,
    compute_path_risk_score,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_graph() -> DependencyGraph:
    """Build a small sample dependency graph for testing."""
    g = DependencyGraph()

    nodes = [
        GraphNode(
            id="n1", kind=NodeKind.IDENTIFIER, name="input_buf",
            location=SourceLocation(file="main.c", line=10, code_snippet='char *input_buf = read_input();'),
        ),
        GraphNode(
            id="n2", kind=NodeKind.CALL_SITE, name="read_input",
            location=SourceLocation(file="main.c", line=10, code_snippet='char *input_buf = read_input();'),
        ),
        GraphNode(
            id="n3", kind=NodeKind.IDENTIFIER, name="len",
            location=SourceLocation(file="main.c", line=11, code_snippet='int len = strlen(input_buf);'),
        ),
        GraphNode(
            id="n4", kind=NodeKind.CALL_SITE, name="memcpy",
            location=SourceLocation(file="main.c", line=15, code_snippet='memcpy(dest, input_buf, len);'),
        ),
        GraphNode(
            id="n5", kind=NodeKind.IDENTIFIER, name="dest",
            location=SourceLocation(file="main.c", line=14, code_snippet='char dest[64];'),
        ),
        GraphNode(
            id="n6", kind=NodeKind.IDENTIFIER, name="result",
            location=SourceLocation(file="main.c", line=20, code_snippet='return result;'),
        ),
        GraphNode(
            id="n7", kind=NodeKind.IDENTIFIER, name="config",
            location=SourceLocation(file="config.c", line=5, code_snippet='struct Config *config = load_config();'),
        ),
        GraphNode(
            id="n8", kind=NodeKind.FIELD, name="max_size",
            location=SourceLocation(file="config.c", line=6, code_snippet='config->max_size'),
        ),
    ]

    edges = [
        GraphEdge(src="n1", dst="n3", kind=EdgeKind.DATA_FLOW),
        GraphEdge(src="n2", dst="n1", kind=EdgeKind.RETURN),
        GraphEdge(src="n1", dst="n4", kind=EdgeKind.PARAM_PASS),
        GraphEdge(src="n3", dst="n4", kind=EdgeKind.PARAM_PASS),
        GraphEdge(src="n5", dst="n4", kind=EdgeKind.PARAM_PASS),
        GraphEdge(src="n4", dst="n6", kind=EdgeKind.DATA_FLOW),
        GraphEdge(src="n7", dst="n8", kind=EdgeKind.FIELD_ACCESS),
        GraphEdge(src="n8", dst="n3", kind=EdgeKind.DATA_FLOW),
    ]

    g.add_nodes(nodes)
    g.add_edges(edges)
    return g


@pytest.fixture
def aco_config() -> ACOConfig:
    return ACOConfig(ants=10, iterations=5, stagnation_limit=3)


@pytest.fixture
def branching_config() -> BranchingConfig:
    return BranchingConfig(max_fan_out=3)


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

class TestModels:
    def test_source_location_short(self):
        loc = SourceLocation(file="src/main.c", line=42)
        assert loc.short == "src/main.c:42"

    def test_graph_node_hash(self):
        n1 = GraphNode(id="a")
        n2 = GraphNode(id="a")
        assert hash(n1) == hash(n2)
        assert n1 == n2

    def test_trace_path_auto_id(self):
        steps = [
            TraceStep(node_id="n1"),
            TraceStep(node_id="n2"),
        ]
        path = TracePath(steps=steps)
        assert path.id  # auto-generated
        assert path.depth == 2

    def test_trace_path_dedup(self):
        s1 = [TraceStep(node_id="a"), TraceStep(node_id="b")]
        s2 = [TraceStep(node_id="a"), TraceStep(node_id="b")]
        p1 = TracePath(steps=s1)
        p2 = TracePath(steps=s2)
        assert p1.id == p2.id

    def test_edge_id(self):
        e = GraphEdge(src="a", dst="b", kind=EdgeKind.CALL)
        assert e.edge_id == "a->b:call"

    def test_branch_point_model(self):
        bp = BranchPoint(
            node_id="n1",
            candidates=[
                BranchCandidate(index=0, next_node_id="n2", edge_kind=EdgeKind.DATA_FLOW),
                BranchCandidate(index=1, next_node_id="n3", edge_kind=EdgeKind.CALL),
            ],
        )
        assert len(bp.candidates) == 2
        assert bp.chosen_index is None


# ---------------------------------------------------------------------------
# Graph builder tests
# ---------------------------------------------------------------------------

class TestDependencyGraph:
    def test_add_nodes_and_edges(self, sample_graph: DependencyGraph):
        assert sample_graph.node_count == 8
        assert sample_graph.edge_count == 8

    def test_find_target_nodes(self, sample_graph: DependencyGraph):
        targets = sample_graph.find_target_nodes("main.c", 15)
        assert len(targets) >= 1

    def test_predecessors(self, sample_graph: DependencyGraph):
        preds = sample_graph.predecessors("n4")
        assert "n1" in preds
        assert "n3" in preds
        assert "n5" in preds

    def test_successors(self, sample_graph: DependencyGraph):
        succs = sample_graph.successors("n4")
        assert "n6" in succs

    def test_subgraph_around(self, sample_graph: DependencyGraph):
        reachable = sample_graph.subgraph_around(["n6"], max_depth=10)
        assert "n6" in reachable
        assert "n4" in reachable
        assert "n1" in reachable

    def test_fan_out(self, sample_graph: DependencyGraph):
        assert sample_graph.fan_out("n4") == 3  # n1, n3, n5

    def test_enumerate_small_graph(self, sample_graph: DependencyGraph):
        paths = sample_graph.enumerate_all_simple_paths(["n6"])
        assert len(paths) > 0
        # All paths should end at n6
        for p in paths:
            assert p[-1] == "n6"

    def test_merge_prefers_joern(self):
        g = DependencyGraph()
        ts_node = GraphNode(id="x", name="ts_version", backend=BackendKind.TREESITTER)
        j_node = GraphNode(id="x", name="joern_version", backend=BackendKind.JOERN)

        g.add_nodes([ts_node])
        g.add_nodes([j_node])  # should overwrite

        node = g.get_node("x")
        assert node is not None
        assert node.name == "joern_version"

    def test_heuristic_weights(self, sample_graph: DependencyGraph):
        sample_graph.compute_heuristic_weights()
        # Verify weights were set
        edge_data = sample_graph.get_edge_data("n1", "n4")
        assert edge_data is not None
        assert "weight" in edge_data


# ---------------------------------------------------------------------------
# ACO tests
# ---------------------------------------------------------------------------

class TestACO:
    def test_explore_finds_paths(self, sample_graph: DependencyGraph, aco_config: ACOConfig):
        explorer = ACOExplorer(sample_graph, aco_config)
        paths = explorer.explore(targets=["n6"], max_depth=10, topk=5)
        assert len(paths) > 0

    def test_paths_end_at_target(self, sample_graph: DependencyGraph, aco_config: ACOConfig):
        explorer = ACOExplorer(sample_graph, aco_config)
        paths = explorer.explore(targets=["n6"], max_depth=10, topk=5)
        for path in paths:
            # Last step should be the target (since we reversed)
            assert path.steps[-1].node_id == "n6"

    def test_paths_have_scores(self, sample_graph: DependencyGraph, aco_config: ACOConfig):
        explorer = ACOExplorer(sample_graph, aco_config)
        paths = explorer.explore(targets=["n6"], max_depth=10, topk=5)
        for path in paths:
            assert path.score > 0

    def test_paths_sorted_by_score(self, sample_graph: DependencyGraph, aco_config: ACOConfig):
        explorer = ACOExplorer(sample_graph, aco_config)
        paths = explorer.explore(targets=["n6"], max_depth=10, topk=10)
        scores = [p.score for p in paths]
        assert scores == sorted(scores, reverse=True)

    def test_branch_detection(self, sample_graph: DependencyGraph, aco_config: ACOConfig):
        branching = BranchingConfig(max_fan_out=2)  # trigger on n4 (3 preds)
        explorer = ACOExplorer(sample_graph, aco_config, branching)
        explorer.explore(targets=["n6"], max_depth=10, topk=5)
        # n4 has 3 predecessors, threshold is 2, so should detect a branch
        assert len(explorer.branch_points) >= 1

    def test_empty_targets(self, sample_graph: DependencyGraph, aco_config: ACOConfig):
        explorer = ACOExplorer(sample_graph, aco_config)
        paths = explorer.explore(targets=[], max_depth=10, topk=5)
        assert len(paths) == 0


# ---------------------------------------------------------------------------
# Session tests
# ---------------------------------------------------------------------------

class TestSession:
    def test_create_and_save(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        mgr = SessionManager(path)
        sess = mgr.create("/tmp/repo", "main.c:10")
        assert sess.session_id
        assert sess.target == "main.c:10"

        # Reload
        mgr2 = SessionManager(path)
        loaded = mgr2.load()
        assert loaded is not None
        assert loaded.session_id == sess.session_id

        Path(path).unlink()

    def test_add_and_resolve_branch(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        mgr = SessionManager(path)
        mgr.create("/tmp/repo", "main.c:10")

        bp = BranchPoint(
            node_id="n4",
            candidates=[
                BranchCandidate(index=0, next_node_id="n1", edge_kind=EdgeKind.DATA_FLOW),
                BranchCandidate(index=1, next_node_id="n3", edge_kind=EdgeKind.CALL),
            ],
        )
        mgr.add_branch_points([bp])
        assert len(mgr.get_pending_branches()) == 1

        resolved = mgr.resolve_branch("n4", 0)
        assert resolved is not None
        assert resolved.chosen_index == 0
        assert len(mgr.get_pending_branches()) == 0

        Path(path).unlink()


# ---------------------------------------------------------------------------
# Flow analyzer tests
# ---------------------------------------------------------------------------

class TestFlowAnalyzer:
    def test_detect_buffer_overflow(self):
        path = TracePath(
            steps=[
                TraceStep(node_id="n1", code_snippet="char *buf = read_input();",
                          node_kind=NodeKind.CALL_SITE, node_name="read_input"),
                TraceStep(node_id="n2", code_snippet="int len = strlen(buf);",
                          node_kind=NodeKind.CALL_SITE, node_name="strlen"),
                TraceStep(node_id="n3", code_snippet="memcpy(dest, buf, len);",
                          node_kind=NodeKind.CALL_SITE, node_name="memcpy"),
            ],
        )
        tags = detect_patterns(path)
        assert "buffer_overflow" in tags

    def test_detect_injection(self):
        path = TracePath(
            steps=[
                TraceStep(node_id="n1", code_snippet="char *cmd = getenv('CMD');",
                          node_kind=NodeKind.CALL_SITE, node_name="getenv"),
                TraceStep(node_id="n2", code_snippet="system(cmd);",
                          node_kind=NodeKind.CALL_SITE, node_name="system"),
            ],
        )
        tags = detect_patterns(path)
        assert "injection" in tags

    def test_no_false_positive(self):
        path = TracePath(
            steps=[
                TraceStep(node_id="n1", code_snippet="int x = 5;",
                          node_kind=NodeKind.IDENTIFIER, node_name="x"),
                TraceStep(node_id="n2", code_snippet="int y = x + 1;",
                          node_kind=NodeKind.IDENTIFIER, node_name="y"),
            ],
        )
        tags = detect_patterns(path)
        # Should not match critical patterns on trivial code
        assert "buffer_overflow" not in tags
        assert "injection" not in tags

    def test_risk_score(self):
        path = TracePath(
            steps=[
                TraceStep(node_id="n1", code_snippet="read(fd, buf, size);",
                          node_kind=NodeKind.CALL_SITE, node_name="read",
                          location=SourceLocation(file="a.c", line=1)),
                TraceStep(node_id="n2", code_snippet="memcpy(out, buf, size);",
                          node_kind=NodeKind.CALL_SITE, node_name="memcpy",
                          location=SourceLocation(file="b.c", line=5)),
            ],
            vulnerability_tags=["buffer_overflow", "unvalidated_input"],
        )
        score = compute_path_risk_score(path)
        assert score > 0

    def test_enrich_paths(self):
        paths = [
            TracePath(
                steps=[
                    TraceStep(node_id="n1", code_snippet="gets(buf);",
                              node_kind=NodeKind.CALL_SITE, node_name="gets"),
                    TraceStep(node_id="n2", code_snippet="strcpy(out, buf);",
                              node_kind=NodeKind.CALL_SITE, node_name="strcpy"),
                ],
            )
        ]
        enriched = enrich_paths_with_patterns(paths)
        assert len(enriched[0].vulnerability_tags) > 0


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------

class TestConfig:
    def test_default_config(self):
        cfg = DeeptraceConfig()
        assert cfg.max_depth == 30
        assert cfg.aco.ants == 80
        assert cfg.llm.model == "qwen2.5-coder:14b"

    def test_config_override(self):
        cfg = DeeptraceConfig(
            repo="/tmp/test",
            target="foo.c:42",
            max_depth=50,
        )
        assert cfg.max_depth == 50
        assert cfg.target == "foo.c:42"

#.gitignore
__pycache__/
*.py[cod]
*.egg-info/
dist/
build/
.eggs/
*.egg
.venv/
venv/
.mypy_cache/
.ruff_cache/
.pytest_cache/
*.json
!pyproject.toml
session_*.json
traces.json
cpg.bin
*.dot
*.svg

#pyproject.toml
[build-system]
requires = ["setuptools>=68.0", "setuptools-scm>=8.0"]
build-backend = "setuptools.build_meta"

[project]
name = "deeptrace-aco"
version = "1.0.0"
description = "Production-grade deep dependency trace tool using Joern + tree-sitter + ACO"
readme = "README.md"
license = { text = "" }
requires-python = ">=3.10"
authors = [{ name = "deeptrace contributors" }]

dependencies = [
    "click>=8.1",
    "rich>=13.0",
    "pydantic>=2.0",
    "pydantic-settings>=2.0",
    "networkx>=3.1",
    "numpy>=1.24",
    "docker>=7.0",
    "anthropic>=0.40",
    "orjson>=3.9",
    "tenacity>=8.2",
    "xxhash>=3.4",
    "tqdm>=4.66",
    "prompt_toolkit>=3.0",
]

[project.optional-dependencies]
# Option A: use tree-sitter-languages (Python <= 3.11 only)
treesitter-compat = [
    "tree-sitter>=0.20,<0.22",
    "tree-sitter-languages>=1.10",
]
# Option B: use per-language packages (Python >= 3.12, recommended)
treesitter = [
    "tree-sitter>=0.23,<0.24",
    "tree-sitter-c>=0.23,<0.24",
    "tree-sitter-cpp>=0.23,<0.24",
    "tree-sitter-java>=0.23,<0.24",
    "tree-sitter-rust>=0.23,<0.24",
    "tree-sitter-swift>=0.0.1",
]
z3 = [
    "z3-solver>=4.12",
]
dev = [
    "pytest>=7.4",
    "pytest-cov>=4.1",
    "pytest-asyncio>=0.21",
    "ruff>=0.4",
    "mypy>=1.8",
    "z3-solver>=4.12",
    "tree-sitter>=0.23,<0.24",
    "tree-sitter-c>=0.23,<0.24",
    "tree-sitter-cpp>=0.23,<0.24",
    "tree-sitter-java>=0.23,<0.24",
    "tree-sitter-rust>=0.23,<0.24",
    "tree-sitter-swift>=0.0.1",
]

[project.scripts]
deeptrace = "deeptrace.cli.main:cli"

[tool.setuptools.packages.find]
where = ["src"]

[tool.ruff]
line-length = 100
target-version = "py310"

[tool.ruff.lint]
select = ["E", "F", "W", "I", "N", "UP", "B", "SIM", "TCH"]

[tool.mypy]
python_version = "3.10"
strict = true
warn_return_any = true

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"

#README.md
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

