"""
VulnHunter-Hybrid v2: The "Greedy but Safe" Pipeline.
Strategy:
  1. Ask Joern for precise callers.
  2. If Joern misses (returns empty), fallback to Regex/Tree-Sitter.
  3. Apply strict 'Syntax Filters' to prevent infinite loops (no 'if', 'toString').
"""

import json
import sqlite3
import subprocess
import os
import re
import logging
import html
from typing import List, Dict
from dataclasses import dataclass, field, asdict
from enum import Enum

# --- CONFIGURATION ---
LLM_BASE_URL = "http://localhost:11434/v1"
LLM_MODEL_NAME = "qwen2.5-coder:14b"
LLM_API_KEY = "ollama"
LLM_TEMPERATURE = 0.0
MAX_DEPTH = 10  # Stop after 10 hops to prevent infinite recursion

# --- FILTERS (The Safety Net) ---
# We use Regex fallback, so we MUST filter these out.
SYNTAX_NOISE = {
    "if", "else", "for", "while", "switch", "try", "catch", "synchronized", "return",
    "new", "this", "super", "get", "set", "run"
}
SYSTEM_NOISE = {
    "toString", "hashCode", "equals", "clone", "onDraw", "onMeasure",
    "onLayout", "writeToParcel", "describeContents"
}

logging.basicConfig(level=logging.INFO, format='%(asctime)s | [HUNTER] %(levelname)s | %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("VulnHunter")

# --- I. JOERN CLIENT (DOCKER/LOCAL) ---
class JoernClient:
    def __init__(self, target_path):
        # Translate Windows path to Docker path if needed
        self.local_root = r"C:\Users\omern\Desktop\projects\BeeColony"
        self.container_root = "/data"

        if self.local_root in target_path:
            rel_path = os.path.relpath(target_path, self.local_root).replace("\\", "/")
            self.container_target_path = f"{self.container_root}/{rel_path}"
        else:
            self.container_target_path = target_path # Assume Linux/WSL

        self.cpg_path_container = "/tmp/cpg.bin"
        self.is_ready = self._check_docker()
        if self.is_ready:
            self._import_code()

    def _check_docker(self):
        try:
            res = subprocess.run(["docker", "ps", "--filter", "name=joern-box", "--format", "{{.Names}}"], capture_output=True, text=True)
            return "joern-box" in res.stdout
        except: return False

    def _import_code(self):
        logger.info(f"🧪 Joern: Analyzing {self.container_target_path}...")
        script = f"""
        importCode.c(inputPath="{self.container_target_path}", projectName="vh_project")
        saveCpg("{self.cpg_path_container}")
        """
        self._run_in_docker(script)

    def get_callers(self, func_name):
        # Loose matching (contains) instead of exact matching to catch partials
        script = f"""
        loadCpg("{self.cpg_path_container}")
        cpg.call.name(".*{func_name}.*").method.name.l
        """
        output = self._run_in_docker(script)
        return self._parse_scala_list(output)

    def _run_in_docker(self, scala_script):
        with open("temp_joern_script.sc", "w") as f: f.write(scala_script)
        cmd = ["docker", "exec", "joern-box", "joern", "--script", "/data/temp_joern_script.sc"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout
        except: return ""
        finally:
            if os.path.exists("temp_joern_script.sc"): os.remove("temp_joern_script.sc")

    def _parse_scala_list(self, output):
        clean_lines = [line for line in output.splitlines() if "List(" in line]
        if not clean_lines: return []
        raw_list = clean_lines[-1]
        return list(set(re.findall(r'"([^"]*)"', raw_list)))

# --- II. CORE STRUCTURES ---
class Platform(Enum):
    ANDROID = "android"; IOS = "ios"; LINUX = "linux"; UNKNOWN = "unknown"

@dataclass
class PathTrace:
    steps: List[Dict] = field(default_factory=list)
    constraints: List[str] = field(default_factory=list)
    injection_param: str = "payload"
    def to_dict(self): return asdict(self)

# --- III. HYBRID INDEXER ---
class CodebaseIndexer:
    def __init__(self, root_dir: str):
        self.root = root_dir
        self.func_map = {}
        self.call_graph_regex = {} # Specific fallback graph
        self.profile = SystemProfile()
        self.joern = JoernClient(root_dir)

        self._profile_system()
        self._index_hybrid()

    def _profile_system(self):
        # (Manifest parsing logic same as before)
        pass

    def _index_hybrid(self):
        """
        Builds the Regex Graph AND prepares Joern.
        """
        logger.info("📂 Building Hybrid Index (Regex + Joern)...")
        for root, _, files in os.walk(self.root):
            for f in files:
                path = os.path.join(root, f)
                ext = f.split('.')[-1]
                if ext in ['c', 'cpp', 'java', 'kt', 'm', 'mm', 'swift']:
                    self._scan_smart_regex(path)

    def _scan_smart_regex(self, path):
        with open(path, "r", errors="ignore") as f: content = f.read()

        # 1. Definitions
        def_pattern = r"(?:void|int|char|struct|static|fun|def|class|public|private)\s+(\w+)\s*\("
        for m in re.finditer(def_pattern, content):
            name = m.group(1)
            if name not in SYNTAX_NOISE:
                self.func_map[name] = {"code": content, "file": path}

        # 2. Calls (Regex Fallback)
        # We build this map REGARDLESS of Joern, so we have a backup.
        # Negative lookahead to skip keywords
        call_pattern = r"(?!(if|for|while|switch|catch)\b)\b(\w+)\s*\("

        # We need to approximate the 'caller'.
        # In regex scanning, we assume the last seen definition is the caller.
        current_caller = "unknown_context"

        for m in re.finditer(r"(?:(public|private|fun|def)\s+(\w+)\s*\(|(\w+)\s*\()", content):
            # If it looks like a definition
            if m.group(1):
                current_caller = m.group(2)
            # If it looks like a call
            elif m.group(3):
                callee = m.group(3)
                if callee in SYNTAX_NOISE: continue

                if callee not in self.call_graph_regex:
                    self.call_graph_regex[callee] = []
                self.call_graph_regex[callee].append(current_caller)

    def get_callers(self, func_name):
        # 1. Try Joern
        joern_callers = []
        if self.joern.is_ready:
            joern_callers = self.joern.get_callers(func_name)

        # 2. Try Regex
        regex_callers = self.call_graph_regex.get(func_name, [])

        # 3. Merge & Deduplicate
        # Priority: Joern results are cleaner, but Regex results are more abundant.
        # If Joern returned NOTHING, we rely entirely on Regex.
        combined = list(set(joern_callers + regex_callers))

        # 4. Filter Noise
        final_callers = [c for c in combined if c not in SYNTAX_NOISE and c not in SYSTEM_NOISE]

        return final_callers

    def find_class_definition(self, class_name):
        """
        Fuzzy search for the file defining a class (e.g., 'InfoCard' -> 'InfoCard.java')
        """
        for root, _, files in os.walk(self.root):
            for f in files:
                if f == f"{class_name}.java" or f == f"{class_name}.kt":
                    return os.path.join(root, f)
        return None

    def get_class_structure(self, class_name):
        path = self.find_class_definition(class_name)
        if not path: return ""
        with open(path, 'r', errors='ignore') as f:
            return f.read()

    def get_source(self, func): return self.func_map.get(func, {}).get("code", "")

# --- IV. AGENT BRAIN (Unchanged) ---
try:
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import HumanMessage, SystemMessage
    HAS_LC = True
except: HAS_LC = False

class AgentBrain:
    def __init__(self):
        self.llm = ChatOpenAI(model=LLM_MODEL_NAME, temperature=0.0, base_url=LLM_BASE_URL, api_key=LLM_API_KEY) if HAS_LC else None

    def _extract_json(self, text):
        try:
            match = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
            if match: return json.loads(match.group(1))
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match: return json.loads(match.group(0))
            return None
        except: return None

    def analyze_hop(self, caller_name, code_snippet, callee, param, platform):
        # 1. Platform Context (Primes the LLM for specific syntax)
        ctx_prompt = ""
        if platform == Platform.ANDROID:
            ctx_prompt = "Context: Android App. Look for Intents, Bundles, getExtra, and IPC mechanisms."
        elif platform == Platform.IOS:
            ctx_prompt = "Context: iOS App. Look for XPC, URL Schemes, and Delegate methods."
        elif platform == Platform.LINUX:
            ctx_prompt = "Context: Linux Kernel/C. Look for pointer assignments, struct initialization, and macros."

        # 2. Taint Tracking Instruction
        # We tell the LLM: "We are tracking 'param'. Find what variable feeds into it."
        var_prompt = f"Trace the data flow feeding into `{param}` (or the argument position it occupies)."

        system = f"""
        You are a Vulnerability Researcher. {ctx_prompt}

        GOAL: {var_prompt}.
        
        TASKS:
        1. Does `{caller_name}` call `{callee}`?
        2. DATA FLOW: Identify the exact variable in `{caller_name}` that is passed to `{callee}`.
           - Example: If code is `funcB(myVar)`, and we are tracing `funcB`, the upstream variable is `myVar`.
        3. LOGIC: What conditions guard this call?

        OUTPUT JSON ONLY:
        {{ 
            "is_connected": bool, 
            "upstream_variable": "The exact variable name passed to callee (e.g., 'intent', 'args', 'model')", 
            "taint_source": "Where does this variable come from? (e.g., 'Function Argument', 'Class Field', 'New Instance')",
            "reasoning": "Explain the data flow.", 
            "constraints": ["if (x != null)"] 
        }}"""

        human = f"""
        CODE SNIPPET:
        Snippet from `{caller_name}`:
        {code_snippet}

        TARGET: I need to verify if data flows into `{callee}`.
        CURRENT FOCUS: `{caller_name}`
        TRACED PARAMETER: `{param}`        
        """

        try:
            res = self.llm.invoke([SystemMessage(content=system), HumanMessage(content=human)])
            data = self._extract_json(res.content)
            if not data: return {"is_connected": "assign" in res.content.lower(), "reasoning": "Fallback",
                                 "upstream_variable": "unknown", "constraints": []}
            return data
        except: return {"is_connected": False, "constraints": []}

    def summarize_strategy(self, trace: PathTrace):
        chain_desc = []
        for step in reversed(trace.steps):
            chain_desc.append(f"{step['caller']} -> {step['callee']}")
        all_constraints = trace.constraints

        gates_json = json.dumps(all_constraints)
        system = """
                You are an Exploit Developer. Write a 'Strategy Report'.
                INPUT:
                - Execution Chain: The function calls.
                - Constraints: The 'if' conditions gathered along the path.
                OUTPUT JSON:
                {
                    "attack_vector": "Vector (e.g. Deep Link, Intent)",
                    "prerequisites": "What state is required?",
                    "trigger_logic": "Step-by-step guide to bypass the constraints and trigger the sink.",
                    "confidence": "High/Med/Low"
                }
                """

        human = f"CHAIN:\n{json.dumps(chain_desc)}\n\nACCUMULATED LOGIC GATES:\n{gates_json}"
        try:
            res = self.llm.invoke([SystemMessage(content=system), HumanMessage(content=human)])
            return self._extract_json(res.content) or {"attack_vector": "Unknown"}
        except: return {"attack_vector": "Unknown"}

    def speculate_triggers(self, code, func, platform):
        system = "Speculate entry vectors. OUTPUT JSON: { \"triggers\": [ { \"type\": \"str\", \"likelihood\": \"High\", \"reasoning\": \"str\" } ] }"
        try:
            res = self.llm.invoke([SystemMessage(content=system), HumanMessage(content=code[:2000])])
            return self._extract_json(res.content) or {"triggers": []}
        except: return {"triggers": []}

    def inspect_sink_usage(self, sink_caller_code, sink_name, variable_name):
        """
        Analyzes the lines IMMEDIATELY AFTER the sink call to see if the return value is used dangerously.
        """
        system = f"""
        You are an Exploit Validator.

        The function `{sink_name}` (called on variable `{variable_name}`) returns a value.
        Analyze the code to see how that return value is used.

        Is it used in a DANGEROUS Sink?
        - Reflection (Class.forName)
        - File I/O (File(), open())
        - Database (execSQL, rawQuery)
        - Webview (loadUrl)
        - Serialization

        OUTPUT JSON:
        {{
            "is_dangerous": bool,
            "danger_type": "Reflection / SQLi / Path Traversal / None",
            "evidence": "Code line showing usage"
        }}
        """

        try:
            res = self.llm.invoke([SystemMessage(content=system), HumanMessage(content=sink_caller_code)])
            return self._extract_json(res.content)
        except:
            return {"is_dangerous": False, "danger_type": "Unknown"}

# --- V. VISUALIZATION ---
class GraphGenerator:
    def __init__(self, filename="vulnhunter_graph.html"):
        self.filename = filename
        self.nodes = {}; self.edges = []
    def add_trace(self, trace):
        for step in trace.steps:
            src, dst = step['caller'], step['callee']
            if src in SYNTAX_NOISE: continue
            self._add_node(src, "source" if "VIRTUAL" in src else "intermediate")
            self._add_node(dst, "sink" if step == trace.steps[0] else "intermediate")
            self.edges.append({"from": src, "to": dst, "title": html.escape(step.get('reasoning','')), "arrows": "to"})
    def _add_node(self, label, node_type):
        if label in self.nodes: return
        color = "#C2FABC" if node_type == "source" else "#FFB3BA" if node_type == "sink" else "#97C2FC"
        self.nodes[label] = {"id": label, "label": label, "color": color, "shape": "box"}
    def save(self):
        nodes_json = json.dumps(list(self.nodes.values()))
        edges_json = json.dumps(self.edges)
        with open(self.filename, "w", encoding="utf-8") as f:
            f.write(f"""<!DOCTYPE html><html><head><script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script><style>#mynetwork {{ width: 100%; height: 800px; border: 1px solid lightgray; }}</style></head><body><div id="mynetwork"></div><script>var nodes = new vis.DataSet({nodes_json}); var edges = new vis.DataSet({edges_json}); var network = new vis.Network(document.getElementById('mynetwork'), {{ nodes: nodes, edges: edges }}, {{ layout: {{ hierarchical: {{ direction: "UD", sortMethod: "directed" }} }} }});</script></body></html>""")
        logger.info(f"📊 Graph saved: {os.path.abspath(self.filename)}")

# --- VI. STATE & ORCHESTRATOR ---
@dataclass
class SystemProfile: platform: Platform = Platform.UNKNOWN; schemes: List[str] = field(default_factory=list)

class StateManager:
    def __init__(self, db_path="vulnhunter.db"):
        self.db_path = db_path
        self._init_db()
    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, sink_func TEXT, strategy TEXT)''')
        conn.commit()
    def save_full_report(self, exploits, json_path):
        with open(json_path, "w") as f: json.dump(exploits, f, indent=4)
        logger.info(f"📄 Report saved: {json_path}")

class UniversalPipeline:
    def __init__(self, repo_path):
        self.indexer = CodebaseIndexer(repo_path)
        self.brain = AgentBrain()
        self.visualizer = GraphGenerator()
        self.state_manager = StateManager()
        self.proven_exploits = []

    def run(self, sink_func, sink_param):
        logger.info(f"🎯 Target: {sink_func}")
        queue = [(sink_func, sink_param, PathTrace(injection_param=sink_param), 0)]
        visited_global = set()

        while queue:
            func, param, path, depth = queue.pop(0)

            # --- GUARDRAILS ---
            if depth >= MAX_DEPTH: continue
            if func in visited_global: continue
            visited_global.add(func)
            if func in SYNTAX_NOISE or func in SYSTEM_NOISE: continue

            # 1. GET CALLERS (HYBRID: JOERN + REGEX)
            callers = self.indexer.get_callers(func)

            # 2. SPECULATION (Only if NO callers found anywhere)
            if not callers:
                code = self.indexer.get_source(func)
                if code:
                    spec = self.brain.speculate_triggers(code, func, Platform.ANDROID)
                    for trig in spec.get("triggers", []):
                        step = {"caller": f"VIRTUAL: {trig['type']}", "callee": func, "reasoning": trig['reasoning']}
                        self.proven_exploits.append(PathTrace(steps=path.steps + [step], constraints=path.constraints))
                continue

            for caller in callers:
                if any(step['caller'] == caller for step in path.steps): continue
                self._process_hop(caller, func, param, path, queue, depth + 1, sink_func)

    def _process_hop(self, caller, callee, param, path, queue, depth, original_sink):
        if caller in SYNTAX_NOISE: return
        full_code = self.indexer.get_source(caller)
        if not full_code: return

        # Context Slicing
        lines = full_code.split('\n')
        snippets = []
        for i, line in enumerate(lines):
            if callee in line:
                snippets.append(f"Line {i}: " + "\n".join(lines[max(0, i-10):min(len(lines), i+11)]))
        focused_code = "\n...\n".join(snippets[:5])

        res = self.brain.analyze_hop(caller, focused_code, callee, param, self.indexer.profile.platform)
        if res.get("is_connected"):
            logger.info(f"   🔗 [{depth}/{MAX_DEPTH}] {caller} -> {callee}")
            if callee == original_sink:  # The sink_func passed to run()
                sink_report = self.brain.inspect_sink_usage(focused_code, callee, res.get("upstream_variable"))
                if sink_report.get("is_dangerous"):
                    logger.warning(f"   🚨 DANGEROUS USAGE DETECTED: {sink_report.get('danger_type')}")
                    # Add this danger info to the reasoning so it appears in the report
                    res["reasoning"] += f" [DANGER: {sink_report.get('danger_type')}]"

            step = {"caller": caller, "callee": callee, "reasoning": res.get("reasoning")}
            queue.append((caller, res.get("upstream_variable"), PathTrace(steps=path.steps + [step], constraints=path.constraints + res.get("constraints", [])), depth))

    def report(self, json_path="final_report.json"):
        if not self.proven_exploits: print("\n[Secure] No paths.")
        full_report_data = []
        for path in self.proven_exploits:
            self.visualizer.add_trace(path)
            strategy = self.brain.summarize_strategy(path)
            full_report_data.append({
                "sink": path.steps[0].get('callee'),
                "entry_point": path.steps[-1]['caller'],
                "strategy": strategy,
                "trace": path.steps
            })
        self.state_manager.save_full_report(full_report_data, json_path)
        self.visualizer.save()

if __name__ == "__main__":
    hunter = UniversalPipeline("Signal-Android/app/src")
    hunter.run("getType", "parsers")
    hunter.report("signal_hybrid_report.json")


----------->

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>iOS Security Workbench: Research Edition</title>
<style>
  :root {
    --bg-color: #050505;
    --panel-bg: #0f0f0f;
    --card-bg: #141414;
    --text-primary: #e0e0e0;
    --text-secondary: #888;
    --border: #222;
    
    /* Teams */
    --blue-team: #0A84FF;
    --red-team: #FF453A; /* Now includes RE */
    
    --code-font: 'Menlo', 'Monaco', 'Courier New', monospace;
    --radius: 10px;
  }

  body {
    background-color: var(--bg-color);
    color: var(--text-primary);
    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "Segoe UI", Roboto, sans-serif;
    margin: 0;
    height: 100vh;
    display: flex;
    overflow: hidden;
  }

  /* --- LEFT PANEL: NAVIGATION --- */
  .nav-panel {
    width: 320px;
    height: 100%;
    background: var(--panel-bg);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
  }

  .nav-header {
    padding: 15px;
    border-bottom: 1px solid var(--border);
    background: #000;
  }
  .nav-title { font-size: 13px; font-weight: 900; letter-spacing: 0.5px; color: #fff; text-transform: uppercase; }
  .nav-subtitle { font-size: 10px; color: var(--text-secondary); margin-top: 4px; }

  .nav-content {
    flex: 1;
    overflow-y: auto;
    padding: 10px;
  }
  .nav-content::-webkit-scrollbar { width: 4px; }
  .nav-content::-webkit-scrollbar-thumb { background: #333; border-radius: 2px; }

  .section-label {
    font-size: 9px;
    font-weight: 800;
    color: #555;
    text-transform: uppercase;
    margin: 20px 10px 8px 10px;
    letter-spacing: 1px;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .section-label::after { content: ''; flex: 1; height: 1px; background: #222; }

  .nav-item {
    padding: 8px 10px;
    margin-bottom: 2px;
    border-radius: 6px;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 10px;
    transition: all 0.15s;
    border-left: 2px solid transparent;
  }
  .nav-item:hover { background: #1a1a1a; }
  .nav-item.active { background: #1f1f1f; }
  
  /* Context Colors */
  body.mode-blue .nav-item.active { border-left-color: var(--blue-team); }
  body.mode-red .nav-item.active { border-left-color: var(--red-team); }

  .item-icon { font-size: 14px; width: 20px; text-align: center; }
  .item-name { font-size: 12px; font-weight: 500; color: #ccc; }

  /* Mode Switcher */
  .mode-bar {
    padding: 15px;
    border-top: 1px solid var(--border);
    display: flex;
    gap: 10px;
    background: #080808;
  }
  .mode-btn {
    flex: 1;
    background: #1a1a1a;
    border: 1px solid #2a2a2a;
    color: #666;
    padding: 10px 0;
    border-radius: 6px;
    font-size: 10px;
    font-weight: 700;
    cursor: pointer;
    text-transform: uppercase;
    transition: all 0.2s;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
  }
  .mode-btn:hover { background: #222; color: #eee; }
  .mode-btn.blue.active { background: rgba(10, 132, 255, 0.15); border-color: var(--blue-team); color: var(--blue-team); }
  .mode-btn.red.active { background: rgba(255, 69, 58, 0.15); border-color: var(--red-team); color: var(--red-team); }

  /* --- RIGHT PANEL: LAB --- */
  .lab-panel {
    flex: 1;
    background: #050505;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  /* Lab Header */
  .lab-header {
    padding: 20px 30px;
    border-bottom: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    background: rgba(15,15,15,0.95);
  }
  .lab-title { font-size: 24px; font-weight: 800; margin: 0; letter-spacing: -0.5px; color:#fff; }
  .lab-path { 
    font-family: var(--code-font); font-size: 11px; color: var(--text-secondary); 
    background: #1a1a1a; padding: 4px 8px; border-radius: 4px; margin-top: 6px; display: inline-block; 
  }

  .context-badge {
    font-size: 9px; font-weight: 800; text-transform: uppercase; padding: 5px 10px; border-radius: 4px;
    background: #222; color: #aaa; letter-spacing: 1px; border: 1px solid #333;
  }

  /* Lab Content Grid */
  .lab-content {
    flex: 1;
    padding: 20px;
    overflow-y: auto;
    display: grid;
    grid-template-columns: 1.1fr 0.9fr;
    grid-template-rows: auto 1fr;
    gap: 15px;
  }

  /* Cards */
  .card {
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px;
    display: flex;
    flex-direction: column;
  }
  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 15px;
    padding-bottom: 8px;
    border-bottom: 1px solid #222;
  }
  .card-title { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: #666; }

  /* Concept Chips */
  .concepts-grid { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 15px; }
  .concept-chip {
    font-size: 10px;
    background: #1f1f1f;
    color: #ccc;
    padding: 5px 10px;
    border-radius: 4px;
    cursor: pointer;
    border: 1px solid #2a2a2a;
    transition: all 0.2s;
  }
  .concept-chip:hover { border-color: #666; color: #fff; background:#2a2a2a; }
  
  /* Description Area */
  .desc-area { font-size: 13px; line-height: 1.6; color: #ccc; margin-bottom: 15px; }
  .desc-area strong { color: #fff; font-weight: 600; }
  .desc-area code { background: rgba(255,255,255,0.08); padding: 2px 4px; border-radius: 3px; font-size: 11px; font-family: var(--code-font); color: #a9b7c6; }

  /* Structure/Format View */
  .struct-view {
      font-family: var(--code-font);
      font-size: 10px;
      background: #000;
      padding: 12px;
      border-radius: 6px;
      border: 1px solid #222;
      color: #aaa;
      white-space: pre;
      overflow-x: auto;
      margin-bottom: 15px;
  }
  body.mode-red .struct-view { border-color: #511; }
  .struct-key { color: #d19a66; }
  .struct-val { color: #98c379; }
  
  /* Relationships */
  .relation-list { display: flex; flex-direction: column; gap: 6px; margin-top: auto; }
  .relation-item {
      display: flex; align-items: center; gap: 8px; 
      font-size: 11px; background: #0f0f0f; padding: 8px; border-radius: 6px; border: 1px solid #222;
      transition: all 0.2s; cursor: pointer;
  }
  .relation-item:hover { border-color: #444; background:#1a1a1a; }
  .arrow { color: #444; font-size: 10px; }
  .target-node { font-weight: 700; color: #fff; }

  /* Code Editor Area */
  .code-toolbar { display: flex; gap: 8px; margin-bottom: 8px; }
  .template-select {
      background: #1a1a1a; color: #ccc; border: 1px solid #333; padding: 8px; border-radius: 6px;
      font-size: 11px; outline: none; flex: 1; cursor: pointer;
  }
  .template-select:hover { border-color: #555; }

  .editor-container {
      flex: 1;
      position: relative;
      border: 1px solid #222;
      border-radius: 6px;
      background: #0a0a0a;
      overflow: hidden;
      display: flex;
      flex-direction: column;
  }
  
  textarea.code-editor {
      flex: 1;
      width: 100%;
      background: transparent;
      border: none;
      color: #72f1b8; /* Matrix green */
      font-family: var(--code-font);
      font-size: 11px;
      padding: 12px;
      resize: none;
      outline: none;
      line-height: 1.5;
  }

  /* AI Output Console */
  .ai-console {
      background: #000;
      border-top: 1px solid #222;
      height: 160px;
      padding: 12px;
      font-family: var(--code-font);
      font-size: 10px;
      color: #ccc;
      overflow-y: auto;
      white-space: pre-wrap;
      display: none;
  }
  .ai-console.open { display: block; }
  .console-prompt { color: var(--blue-team); margin-right: 6px; }

  /* Action Bar */
  .action-bar { margin-top: 12px; display: flex; justify-content: flex-end; }
  .run-btn {
      background: #1a1a1a;
      border: 1px solid #333;
      color: #fff;
      padding: 10px 20px;
      border-radius: 6px;
      font-weight: 600;
      font-size: 11px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 8px;
      transition: all 0.2s;
  }
  .run-btn:hover { background: #222; border-color: #555; }
  
  /* Context Colors for Button */
  body.mode-blue .run-btn span { color: var(--blue-team); }
  body.mode-red .run-btn span { color: var(--red-team); }

  /* Empty State */
  .empty-state {
      position: absolute; top: 0; left: 0; width: 100%; height: 100%;
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      color: #333;
  }
  .empty-icon { font-size: 48px; margin-bottom: 15px; opacity: 0.2; }

</style>
</head>
<body class="mode-blue">

<!-- LEFT NAV -->
<div class="nav-panel">
  <div class="nav-header">
    <div class="nav-title">iOS Security Workbench</div>
    <div class="nav-subtitle">
        <span>Research Edition v6.0</span>
    </div>
  </div>
  
  <div class="nav-content" id="nav-list">
    <!-- JS Injected -->
  </div>

  <div class="mode-bar">
    <button class="mode-btn blue active" onclick="setMode('blue')">
        <span>🛡️</span> Architect
    </button>
    <button class="mode-btn red" onclick="setMode('red')">
        <span>⚔️</span> Red Team / RE
    </button>
  </div>
</div>

<!-- MAIN LAB -->
<div class="lab-panel">

  <div id="empty-state" class="empty-state">
    <div class="empty-icon">🗺️</div>
    <h3>System Map Ready</h3>
    <p>Select a component to trace its connections.</p>
  </div>

  <div id="lab-interface" style="display:none; flex-direction:column; height:100%;">
    
    <!-- HEADER -->
    <div class="lab-header">
        <div>
            <h1 class="lab-title" id="lab-title">SpringBoard</h1>
            <div class="lab-path" id="lab-path">/System/Library/CoreServices/SpringBoard.app</div>
        </div>
        <div class="context-badge" id="lab-badge">USER LAND</div>
    </div>

    <!-- CONTENT -->
    <div class="lab-content">
        
        <!-- LEFT: KNOWLEDGE -->
        <div class="card" style="grid-row: span 2;">
            <div class="card-header">
                <span class="card-title">Deep Dive Analysis</span>
                <span style="font-size:9px; color:#555;">KNOWLEDGE GRAPH</span>
            </div>
            
            <div class="concepts-grid" id="lab-concepts"></div>
            
            <div class="desc-area" id="lab-desc"></div>
            
            <!-- Structure View (Formats) -->
            <div id="lab-struct" class="struct-view" style="display:none;"></div>
            
            <div style="margin-top:auto;">
                <div class="card-header" style="margin-bottom:8px; border:none; padding:0;">
                    <span class="card-title">System Connections</span>
                </div>
                <div class="relation-list" id="lab-relations"></div>
            </div>
        </div>

        <!-- RIGHT: CODE LAB -->
        <div class="card" style="grid-row: span 2;">
            <div class="card-header">
                <span class="card-title">Code Laboratory</span>
                <span id="lab-mode-label" style="font-size:9px; font-weight:bold; color:var(--blue-team);">ARCHITECT MODE</span>
            </div>

            <div class="code-toolbar">
                <select class="template-select" id="code-template" onchange="insertTemplate()">
                    <option value="">-- Load Research Scenario --</option>
                    <!-- Injected via JS based on context -->
                </select>
            </div>

            <div class="editor-container">
                <textarea class="code-editor" id="code-input" placeholder="// Select a scenario to generate a research query..."></textarea>
                <div class="ai-console" id="ai-console"></div>
            </div>

            <div class="action-bar">
                <button class="run-btn" onclick="runNeuralAnalysis()">
                    <span style="font-size:14px;">⚡</span> Run Neural Analysis
                </button>
            </div>
        </div>

    </div>
  </div>
</div>

<script>
  // SYSTEM STATE
  const apiKey = "";
  let currentMode = 'blue';
  let activeId = null;

  // --- MASTER KNOWLEDGE BASE ---
  const sysData = {
    // --- 1. USER LAND ---
    "webkit": {
        name: "WebKit (JSC)",
        path: "/System/Library/Frameworks/WebKit.framework",
        cat: "User Land",
        tags: ["JIT", "RWX", "Sandboxed"],
        concepts: ["JIT Spraying", "RWX Memory", "StructureID", "Addrof/Fakeobj"],
        desc: {
            blue: "Renders web content. Uses JIT (Just-In-Time) compilation for performance, which requires writable and executable memory.",
            red: "The primary entry point for remote exploitation. JIT memory bypasses W^X protection. Attackers use JavaScript to corrupt memory layout (Addrof/Fakeobj primitives). Researchers use debug builds to trace JIT optimizations.",
        },
        links: [
            { to: "sandbox", type: "restricted_by", desc: "Tight WebContent Profile" },
            { to: "kernel", type: "attacks", desc: "Uses Kernel exploits to escape" }
        ]
    },
    "springboard": {
        name: "SpringBoard",
        path: "/System/Library/CoreServices/SpringBoard.app",
        cat: "User Land",
        tags: ["UI", "WindowServer", "BackBoard"],
        concepts: ["AlertView Hooking", "Icon Layout", "Control Center", "Lock Screen"],
        desc: {
            blue: "The window manager and app launcher. Handles touch input routing and UI coordination.",
            red: "If SpringBoard crashes, the device 'Resprings'. Bypassing the Lock Screen logic allows physical access attacks. It is the #1 target for UI Tweaks (hooking `applicationDidFinishLaunching`).",
        },
        links: [
            { to: "private_frameworks", type: "uses", desc: "BackBoardServices" },
            { to: "tweak_inject", type: "modified_by", desc: "Heavy Tweak Usage" }
        ]
    },

    // --- 2. RUNTIME & BINARY ---
    "objc_runtime": {
        name: "Obj-C Runtime",
        path: "libobjc.A.dylib",
        cat: "Runtime",
        tags: ["Messaging", "Swizzling", "Introspection"],
        concepts: ["objc_msgSend", "Method Swizzling", "ISA Swizzling", "Selector", "IMP"],
        desc: {
            blue: "Handles dynamic method dispatch. Allows objects to send messages to each other. Central to the flexibility of iOS development.",
            red: "Malware uses the runtime to inspect the app structure and hook sensitive methods (e.g., `isJailbroken`) to hide itself. Researchers use **Cycript** to talk to the runtime live and **class-dump** to generate headers.",
        },
        links: [
            { to: "tweak_inject", type: "manipulated_by", desc: "Target of Swizzling" },
            { to: "libsystem", type: "lives_on", desc: "Uses Heap Memory" }
        ]
    },
    "tweak_inject": {
        name: "Tweak Injection",
        path: "Cydia Substrate / Substitute",
        cat: "Runtime",
        tags: ["Hooking", "Trampoline", "DYLD_INSERT"],
        concepts: ["MSHookMessageEx", "Trampolines", "DYLD_INSERT_LIBRARIES", "Logos Syntax"],
        desc: {
            blue: "Not present in stock iOS. Used by MDM solutions or debugging tools to monitor app behavior.",
            red: "The mechanism used by attackers (and jailbreaks) to inject code into legitimate processes. It forces `dyld` to load a dylib which then patches memory using Trampolines to redirect execution.",
        },
        links: [
            { to: "springboard", type: "injects_into", desc: "Modifies System UI" },
            { to: "dyld", type: "relies_on", desc: "Env Vars" }
        ]
    },
    "dyld": {
        name: "dyld (Linker)",
        path: "/usr/lib/dyld",
        cat: "Runtime",
        tags: ["Loader", "Linking", "Bootstrap"],
        concepts: ["Rebasing", "Binding", "Main Executable", "Constructor"],
        desc: {
            blue: "The Dynamic Linker. It runs before `main()`. It maps the binary and dependent dylibs into memory, applying the ASLR slide.",
            red: "Historical vector for privilege escalation via environment variables. Modern attacks attack the CS_VALID validation logic. Researchers reverse `dyld_sim` to understand loading logic.",
        },
        links: [
            { to: "mach_o", type: "parses", desc: "Reads Load Commands" },
            { to: "dyld_shared_cache", type: "maps", desc: "Loads Cache" }
        ]
    },

    // --- 3. FILE FORMATS ---
    "mach_o": {
        name: "Mach-O Binary",
        path: "Binary Format",
        cat: "Formats",
        tags: ["Load Commands", "Header", "Fat Binary"],
        concepts: ["LC_LOAD_DYLIB", "__TEXT", "__DATA", "MH_MAGIC_64", "ASLR Slide"],
        struct: `struct mach_header_64 {
    uint32_t magic;      // MH_MAGIC_64
    int32_t cputype;     // CPU_TYPE_ARM64
    uint32_t filetype;   // MH_EXECUTE
    uint32_t ncmds;      // Number of Load Commands
    uint32_t sizeofcmds; 
    uint32_t flags;      // PIE, TWOLEVEL
};`,
        desc: {
            blue: "The native executable format for iOS. Contains a header, a series of Load Commands (telling dyld what to do), and data segments.",
            red: "Injecting malicious `LC_LOAD_DYLIB` commands forces the app to load a rogue library on startup. Attackers look for unencrypted segments (Cryptid=0) to patch.",
        },
        links: [
            { to: "dyld", type: "loaded_by", desc: "Parsed at launch" },
            { to: "code_signature_blob", type: "contains", desc: "LC_CODE_SIGNATURE" }
        ]
    },
    "dyld_shared_cache": {
        name: "dyld Shared Cache",
        path: "/System/Library/Caches/com.apple.dyld/",
        cat: "Formats",
        tags: ["Optimization", "Pre-linking", "Massive"],
        concepts: ["Slide Info", "Local Symbols", "Mapping Info", "dsc_extractor"],
        struct: `struct dyld_cache_header {
    char     magic[16];  // "dyld_v1    "
    uint32_t mappingOffset; 
    uint32_t mappingCount; 
    uint32_t imagesOffset; 
    uint32_t imagesCount; 
    uint64_t dyldBaseAddress; 
};`,
        desc: {
            blue: "A single massive file containing all system libraries (UIKit, Foundation, etc.) pre-linked together to speed up launch time.",
            red: "Attackers scour the cache for 'ROP Gadgets'—snippets of code ending in `ret`—to bypass Code Signing. Researchers must use `dsc_extractor` to analyze individual libraries.",
        },
        links: [
            { to: "dyld", type: "mapped_by", desc: "Mapped at boot" },
            { to: "libsystem", type: "contains", desc: "Includes libSystem" }
        ]
    },
    "ipa_bundle": {
        name: "IPA Bundle",
        path: "Application.ipa",
        cat: "Formats",
        tags: ["Container", "Zip", "Payload"],
        concepts: ["Info.plist", "PkgInfo", "embedded.mobileprovision", "_CodeSignature"],
        desc: {
            blue: "The standard packaging format. It's a ZIP archive containing the `Payload` directory, the executable, and resources.",
            red: "Modification involves unzipping, replacing the executable or resources, re-signing with a dev certificate, and re-zipping. `Info.plist` reveals URL Schemes (attack surface).",
        },
        links: [
            { to: "mach_o", type: "contains", desc: "Executable inside" },
            { to: "property_list", type: "configures", desc: "Info.plist" }
        ]
    },
    "property_list": {
        name: "Property List (plist)",
        path: "*.plist",
        cat: "Formats",
        tags: ["XML", "Binary", "Config"],
        concepts: ["bplist00", "Info.plist", "Entitlements", "NSUserDefaults"],
        desc: {
            blue: "Hierarchical data storage. Used for configuration (`Info.plist`), serialization, and user preferences.",
            red: "Sensitive data is often mistakenly stored in plain text plists in the app container. Checking `Info.plist` reveals App Transport Security (ATS) exceptions.",
        },
        links: [
            { to: "ipa_bundle", type: "defines", desc: "App Metadata" },
            { to: "sandbox", type: "rules", desc: "Entitlements are plists" }
        ]
    },
    "code_signature_blob": {
        name: "Code Signature Blob",
        path: "LC_CODE_SIGNATURE",
        cat: "Formats",
        tags: ["CMS", "Hashes", "Integrity"],
        concepts: ["Code Directory", "CDHash", "Entitlements", "Blob Wrapper"],
        struct: `struct CS_SuperBlob {
    uint32_t magic;    // CSMAGIC_EMBEDDED_SIGNATURE
    uint32_t length;
    uint32_t count;
    CS_BlobIndex index[]; 
};`,
        desc: {
            blue: "Embedded in the Mach-O. Contains cryptographic hashes of every memory page (Code Directory) and the CMS signature.",
            red: "If the hash of a page doesn't match the signature, the kernel kills the process. Exploits target the parsing logic of this blob. Researchers use `jtool --sig` to dump entitlements.",
        },
        links: [
            { to: "kernel", type: "enforced_by", desc: "Page Fault check" }
        ]
    },

    // --- 4. CORE LIBRARIES ---
    "libsystem": {
        name: "libSystem.B.dylib",
        path: "/usr/lib/libSystem.B.dylib",
        cat: "Libraries",
        tags: ["Syscalls", "BSD", "libc"],
        concepts: ["dlsym", "dlopen", "syscall", "malloc", "pthread"],
        desc: {
            blue: "The fundamental library that every executable links against. It acts as the umbrella framework for standard C libraries, threading, and the kernel interface (`syscall`).",
            red: "Attackers often hook `dlsym` and `dlopen` here to intercept library loading or hide malicious dylibs. ROP chains usually look for gadgets here first.",
        },
        links: [
            { to: "kernel", type: "invokes", desc: "Makes Syscalls" },
            { to: "dyld", type: "loaded_by", desc: "First loaded lib" }
        ]
    },
    "private_frameworks": {
        name: "PrivateFrameworks",
        path: "/System/Library/PrivateFrameworks",
        cat: "Libraries",
        tags: ["Undocumented", "Apple-Only", "SPI"],
        concepts: ["BackBoardServices", "SpringBoardServices", "MobileInstaller", "FrontBoard"],
        desc: {
            blue: "Internal libraries used by Apple's apps. Not available to App Store developers. Containing powerful, unstable APIs.",
            red: "A goldmine for exploits. Since they are undocumented, they receive less scrutiny. Vulnerabilities here often lead to sandbox escapes or privilege escalation. Researchers use `class-dump` to discover headers.",
        },
        links: [
            { to: "springboard", type: "used_by", desc: "System Apps" },
            { to: "tweak_inject", type: "hooked_by", desc: "Targeted by Tweaks" }
        ]
    },
    "core_foundation": {
        name: "CoreFoundation",
        path: "/System/Library/Frameworks/CoreFoundation.framework",
        cat: "Libraries",
        tags: ["CFType", "Bridging", "Toll-Free"],
        concepts: ["CFString", "CFDictionary", "RunLoop", "Toll-Free Bridging"],
        desc: {
            blue: "C-based framework providing basic data management and service features. 'Toll-Free Bridging' allows interchangeable use with Foundation (ObjC) objects.",
            red: "Type confusion bugs between CF types and ObjC objects can lead to memory corruption. Analyze `CFRunLoop` to understand event handling mechanics.",
        },
        links: [
            { to: "libsystem", type: "depends_on", desc: "Uses libc/malloc" },
            { to: "objc_runtime", type: "bridges_to", desc: "Foundation Bridging" }
        ]
    },

    // --- 5. KERNEL SPACE ---
    "kernel": {
        name: "XNU Kernel",
        path: "/System/Library/Kernels/kernel",
        cat: "Kernel Space",
        tags: ["Mach", "BSD", "PAC"],
        concepts: ["Mach Ports", "Zone Allocator", "Task Struct", "Syscalls", "PAC Bypass"],
        desc: {
            blue: "The hybrid kernel. Enforces security boundaries, manages hardware, and isolates processes.",
            red: "The ultimate target. Kernel R/W allows disabling the sandbox, root, and codesigning. Modern exploits must bypass PAC (Pointer Authentication). Researchers use **kprintf** logs and analyze **panic logs**.",
        },
        links: [
            { to: "libsystem", type: "called_by", desc: "Syscall Interface" },
            { to: "iokit", type: "extends", desc: "Loads Drivers" }
        ]
    },
    "iokit": {
        name: "IOKit Drivers",
        path: "Kernel Extensions",
        cat: "Kernel Space",
        tags: ["Drivers", "C++", "Attack Surface"],
        concepts: ["IOUserClient", "ExternalMethod", "Memory Mapping", "Race Condition"],
        desc: {
            blue: "Object-oriented driver framework. Allows user space to talk to hardware via `IOConnectCallMethod`.",
            red: "Huge attack surface. Drivers often contain bugs in structure parsing or race conditions in memory mapping. Researchers reverse `externalMethod` tables to find input handlers.",
        },
        links: [
            { to: "kernel", type: "runs_in", desc: "Ring 0 Execution" }
        ]
    }
  };

  // --- SCENARIO TEMPLATES ---
  const templates = {
      // General Runtime
      "theos_hook": `// Scenario: Hooking a Method with Logos (Theos)
// Used to analyze arguments or modify return values.
%hook ClassName

- (void)methodName:(id)arg1 {
    %log; // Log arguments to console
    
    // Call original implementation
    %orig; 
    
    NSLog(@"[Researcher] Method hooked. Arg: %@", arg1);
}
%end`,

      "frida_trace": `// Scenario: Tracing Function Calls with Frida
// Used to dynamically inspect API usage.
Interceptor.attach(ObjC.classes.ClassName['- methodName:'].implementation, {
  onEnter: function(args) {
    console.log("[*] Method called");
    console.log("Arg1: " + new ObjC.Object(args[2]).toString());
  },
  onLeave: function(retval) {
    console.log("Return: " + retval);
  }
});`,

      "cycript_ui": `// Scenario: UI Inspection with Cycript
// Used to find View Controllers and memory addresses.
UIApp.keyWindow.recursiveDescription().toString()
// [UIApp.keyWindow _autolayoutTrace]`,

      // C / Low Level
      "dlsym_interpose": `// Scenario: Interposing dlsym
// Used to intercept library loading calls.
#include <dlfcn.h>

void* dlsym(void* handle, const char* symbol) {
    printf("[Audit] dlsym called for: %s\\n", symbol);
    // Call original dlsym...
}`,

      // Formats
      "otool_header": `// Scenario: Inspecting Mach-O Load Commands
// Look for LC_LOAD_DYLIB or LC_RPATH
otool -l Application.app/Application | grep -A 5 LC_LOAD_DYLIB`,

      "jtool_sig": `// Scenario: Dumping Entitlements (Code Signing)
// Verifies if the app has specific capabilities (e.g. get-task-allow)
jtool --sig --ent Application.app/Application`,

      "lldb_attach": `// Scenario: Kernel Debugging / Process Attach
// Attaching to a running process to inspect memory.
process attach --name SpringBoard
continue
// (Trigger bug)
bt  // Backtrace`
  };

  // --- UI LOGIC ---

  function init() {
    renderNav();
    setMode('blue');
    loadComponent('springboard'); // Default load
  }

  function setMode(mode) {
    currentMode = mode;
    document.body.className = `mode-${mode}`;
    
    document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
    document.querySelector(`.mode-btn.${mode}`).classList.add('active');
    
    const label = document.getElementById('lab-mode-label');
    if(mode === 'blue') { label.innerText = "ARCHITECT MODE"; label.style.color = "var(--blue-team)"; }
    if(mode === 'red') { label.innerText = "RED TEAM MODE"; label.style.color = "var(--red-team)"; }

    if(activeId) loadComponent(activeId);
  }

  function renderNav() {
    const list = document.getElementById('nav-list');
    list.innerHTML = '';

    const categories = {
        "User Land": ["webkit", "springboard"],
        "Runtime & Binary": ["mach_o", "objc_runtime", "tweak_inject", "dyld"],
        "File Formats": ["dyld_shared_cache", "ipa_bundle", "property_list", "code_signature_blob"],
        "Core Libraries": ["libsystem", "private_frameworks", "core_foundation"],
        "Kernel Space": ["kernel", "iokit"]
    };

    for(const [cat, ids] of Object.entries(categories)) {
        const label = document.createElement('div');
        label.className = 'section-label';
        label.innerText = cat;
        list.appendChild(label);

        ids.forEach(id => {
            if(!sysData[id]) return; // Guard
            const item = sysData[id];
            const div = document.createElement('div');
            div.className = 'nav-item';
            div.id = `nav-${id}`;
            div.onclick = () => loadComponent(id);
            
            let icon = "📦";
            if(cat === "File Formats") icon = "📄";
            if(cat === "Core Libraries") icon = "📚";
            if(cat === "Kernel Space") icon = "🛡️";
            if(cat === "Runtime & Binary") icon = "⚙️";

            div.innerHTML = `
                <div class="item-icon">${icon}</div>
                <div class="item-name">${item.name}</div>
            `;
            list.appendChild(div);
        });
    }
  }

  function loadComponent(id) {
    activeId = id;
    const data = sysData[id];
    
    // UI Updates
    document.getElementById('empty-state').style.display = 'none';
    document.getElementById('lab-interface').style.display = 'flex';
    
    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    document.getElementById(`nav-${id}`).classList.add('active');

    // Header
    document.getElementById('lab-title').innerText = data.name;
    document.getElementById('lab-path').innerText = data.path;
    document.getElementById('lab-badge').innerText = data.cat;

    // Sub Concepts
    const conceptsDiv = document.getElementById('lab-concepts');
    conceptsDiv.innerHTML = '';
    data.concepts.forEach(c => {
        const chip = document.createElement('div');
        chip.className = 'concept-chip';
        chip.innerText = c;
        chip.onclick = () => {
            document.getElementById('code-input').value += `// Analyzing concept: ${c}\n`;
        };
        conceptsDiv.appendChild(chip);
    });

    // Description (Mode Aware)
    const descDiv = document.getElementById('lab-desc');
    descDiv.innerHTML = data.desc[currentMode];

    // Struct View (Formats only)
    const structDiv = document.getElementById('lab-struct');
    if(data.struct) {
        structDiv.style.display = 'block';
        structDiv.innerHTML = highlightStruct(data.struct);
    } else {
        structDiv.style.display = 'none';
    }

    // Relations
    const relDiv = document.getElementById('lab-relations');
    relDiv.innerHTML = '';
    data.links.forEach(l => {
        if(!sysData[l.to]) return;
        const item = document.createElement('div');
        item.className = 'relation-item';
        item.onclick = () => loadComponent(l.to);
        item.innerHTML = `
            <span style="color:#666;">${l.type}</span>
            <span class="arrow">➜</span>
            <span class="target-node">${sysData[l.to].name}</span>
            <span style="margin-left:auto; color:#444;">${l.desc}</span>
        `;
        relDiv.appendChild(item);
    });

    // Populate Templates Contextually
    const select = document.getElementById('code-template');
    select.innerHTML = '<option value="">-- Load Research Scenario --</option>';
    
    // Add templates based on category or specific logic
    if (data.cat === "Runtime" || data.cat === "User Land" || data.cat === "Libraries") {
        select.innerHTML += `
            <optgroup label="Runtime Inspection">
                <option value="frida_trace">Frida: Trace API Call</option>
                <option value="theos_hook">Theos: Hook Method</option>
                <option value="cycript_ui">Cycript: Inspect UI</option>
                <option value="dlsym_interpose">C: Interpose Symbol</option>
            </optgroup>`;
    }
    if (data.cat === "Formats" || data.cat === "Binary") {
        select.innerHTML += `
            <optgroup label="Static Analysis">
                <option value="otool_header">Otool: Headers</option>
                <option value="jtool_sig">Jtool: Entitlements</option>
            </optgroup>`;
    }
    if (data.cat === "Kernel Space") {
        select.innerHTML += `
            <optgroup label="Kernel Debugging">
                <option value="lldb_attach">LLDB: Attach & Backtrace</option>
            </optgroup>`;
    }

    // Reset Console
    document.getElementById('ai-console').classList.remove('open');
    document.getElementById('ai-console').innerText = '';
  }

  function highlightStruct(text) {
      return text.replace(/(uint32_t|int32_t|uint64_t|char|struct)/g, '<span class="struct-key">$1</span>')
                 .replace(/(\/\/.*)/g, '<span style="color:#555;">$1</span>');
  }

  function insertTemplate() {
      const val = document.getElementById('code-template').value;
      if(templates[val]) {
          document.getElementById('code-input').value = templates[val];
      }
  }

  // --- NEURAL ANALYSIS ---
  async function runNeuralAnalysis() {
      if(!activeId) return;
      
      const code = document.getElementById('code-input').value;
      const data = sysData[activeId];
      const consoleDiv = document.getElementById('ai-console');
      
      consoleDiv.classList.add('open');
      consoleDiv.innerText = `> Connecting to Neural Engine...\n> Context: ${data.name} (${currentMode.toUpperCase()})\n> Analyzing Scenario...`;

      const prompt = `
      You are an expert iOS Security Researcher and Exploit Developer.
      
      CURRENT MODE: ${currentMode.toUpperCase()} (Red Team = Offense/Reversing, Blue Team = Defense/Arch)
      
      CONTEXT:
      Component: ${data.name}
      Type: ${data.cat}
      Tags: ${data.tags.join(', ')}
      Concepts: ${data.concepts.join(', ')}
      
      USER SCENARIO / CODE:
      """
      ${code}
      """
      
      TASK:
      1. Explain this specific scenario in the context of ${data.name}.
      2. If Red Team: Explain how this technique is used for exploitation, bypassing protections, or reverse engineering. Mention specific risks.
      3. If Blue Team: Explain the architectural flow and what security mechanisms are at play (e.g., CodeSign, Sandbox).
      4. If the input is code, explain line-by-line what it achieves.
      `;

      try {
          const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key=${apiKey}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] })
        });

        const result = await response.json();
        const text = result.candidates[0].content.parts[0].text;
        
        consoleDiv.innerText += `\n\n[NEURAL ANALYSIS RESULT]\n------------------------\n${text}`;
      } catch (e) {
          consoleDiv.innerText += `\n\n[ERROR] Connection Failed.`;
      }
  }

  init();

</script>
</body>
</html>


    
