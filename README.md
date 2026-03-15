
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
        result = subprocess.run(full_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        if result.returncode != 0:
            logger.debug("Docker stderr: %s", result.stderr[:2000])
            logger.debug("Docker stdout (tail): %s", result.stdout[-2000:] if result.stdout else "<empty>")
            raise RuntimeError(f"Docker command failed (rc={result.returncode}): {result.stderr[:500]}")
        return result.stdout

    def _ensure_container(self) -> str:
        if self._container_id:
            return self._container_id
        mount_flag = "ro" if self.config.mount_readonly else "rw"
        jvm_heap = self.config.jvm_heap
        cmd = [
            "run", "-d", "--rm",
            "--name", f"deeptrace-joern-{os.getpid()}",
            "-v", f"{self.repo_path}:/repo:{mount_flag}",
            "-v", f"{self._work_dir}:/workspace",
            "-e", f"JAVA_OPTS=-Xmx{jvm_heap}",
            "-e", f"_JAVA_OPTIONS=-Xmx{jvm_heap}",
            f"--memory={self.config.memory_limit}",
            f"--cpus={self.config.cpus}",
            self.config.docker_image,
            "tail", "-f", "/dev/null",
        ]
        self._container_id = self._run_docker(cmd).strip()[:12]
        logger.info("Started Joern container: %s (JVM heap: %s, container: %s)",
                     self._container_id, jvm_heap, self.config.memory_limit)
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
        jvm_flag = f"-J-Xmx{self.config.jvm_heap}"
        return self._exec_in_container(
            f"cd /workspace && joern {jvm_flag} --script {script_path} 2>&1",
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
        jvm_flag = f"-J-Xmx{self.config.jvm_heap}"
        logger.info("Generating CPG for %s (lang=%s, heap=%s)...",
                     self.repo_path, language, self.config.jvm_heap)
        t0 = time.time()
        self._exec_in_container(
            f"joern-parse {jvm_flag} /repo -o {self._cpg_path} {lang_flag} {extra}",
            timeout=self.config.cpg_timeout,
        )
        # Log CPG size to help diagnose truncation
        size_output = self._exec_in_container(f"ls -lh {self._cpg_path} | awk '{{print $5}}'", timeout=10)
        logger.info("CPG generated in %.1fs (size: %s)", time.time() - t0, size_output.strip())
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
