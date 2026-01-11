"""
VulnHunter-Production: The Unified Agentic Zero-Day Discovery Pipeline.
Target Models: Qwen 2.5 32B-Coder-Instruct (Local via Ollama/vLLM).

[Capabilities]
  - Multi-Platform: Android (Deep Links), iOS (Schemes/XPC), Linux (Kernel/C)
  - Polyglot AST: Java, Kotlin, Swift, ObjC, Rust, C/C++, Python
  - Logic Accumulation: Extracts Constraints (If/Else) along the path
  - Strategic Reasoning: Generates human-readable exploit strategies
  - Pointer Chasing: Follows C function pointers and struct assignments
"""

import json
import sqlite3
import subprocess
import os
import re
import logging
import html
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field, asdict
from enum import Enum

# --- CONFIGURATION ---
LLM_BASE_URL = "http://localhost:11434/v1"
LLM_MODEL_NAME = "qwen2.5-coder:14b"
LLM_API_KEY = "ollama"
LLM_TEMPERATURE = 0.0  # Deterministic

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | [HUNTER] %(levelname)s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("VulnHunter")


# --- I. CORE DATA STRUCTURES ---

class Platform(Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    ANDROID = "android"
    IOS = "ios"
    UNKNOWN = "unknown"


@dataclass
class SystemProfile:
    platform: Platform = Platform.UNKNOWN
    frameworks: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    schemes: List[str] = field(default_factory=list)


@dataclass
class PathTrace:
    steps: List[Dict] = field(default_factory=list)
    constraints: List[str] = field(default_factory=list)  # Logic Accumulation
    injection_param: str = "payload"

    def to_dict(self):
        return asdict(self)


# --- II. VISUALIZATION ---

class GraphGenerator:
    def __init__(self, filename="vulnhunter_graph.html"):
        self.filename = filename
        self.nodes = {}
        self.edges = []

    def add_trace(self, trace: PathTrace):
        for step in trace.steps:
            src, dst = step['caller'], step['callee']
            # Noise Filter
            if "license" in src.lower() or "copyright" in src.lower(): continue

            self._add_node(src, "source" if "VIRTUAL" in src else "intermediate")
            self._add_node(dst, "sink" if step == trace.steps[0] else "intermediate")
            self.edges.append({"from": src, "to": dst, "title": html.escape(step.get('reasoning', '')), "arrows": "to"})

    def _add_node(self, label, node_type):
        if label in self.nodes: return
        color = "#97C2FC"
        if node_type == "source":
            color = "#C2FABC"
        elif node_type == "sink":
            color = "#FFB3BA"

        self.nodes[label] = {
            "id": label, "label": label, "color": color,
            "shape": "box", "font": {"face": "monospace", "align": "left"}
        }

    def save(self):
        nodes_json = json.dumps(list(self.nodes.values()))
        edges_json = json.dumps(self.edges)
        html_content = f"""<!DOCTYPE html><html><head><script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script><style>#mynetwork {{ width: 100%; height: 800px; border: 1px solid lightgray; background: #f8f9fa; }}</style></head><body><div id="mynetwork"></div><script>var nodes = new vis.DataSet({nodes_json}); var edges = new vis.DataSet({edges_json}); var network = new vis.Network(document.getElementById('mynetwork'), {{ nodes: nodes, edges: edges }}, {{ layout: {{ hierarchical: {{ direction: "UD", sortMethod: "directed" }} }} }});</script></body></html>"""
        with open(self.filename, "w", encoding="utf-8") as f: f.write(html_content)
        logger.info(f"📊 Graph saved: {os.path.abspath(self.filename)}")


# --- III. STATE MANAGEMENT ---

class StateManager:
    def __init__(self, db_path="vulnhunter.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            '''CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, sink_func TEXT, platform TEXT, strategy TEXT)''')
        conn.commit()
        conn.close()

    def save_full_report(self, exploits: List[Dict], json_path):
        with open(json_path, "w") as f:
            json.dump(exploits, f, indent=4)
        logger.info(f"📄 Full Strategy Report saved to {json_path}")


# --- IV. ROBUST INDEXER (TREE-SITTER + REGEX) ---

class CodebaseIndexer:
    def __init__(self, root_dir: str):
        self.root = root_dir
        self.func_map = {}
        self.call_graph = {}
        self.profile = SystemProfile()
        self.parsers = {}
        self.use_tree_sitter = False
        self._setup_parsers()
        self._profile_system()
        self._index_repo()

    def _setup_parsers(self):
        try:
            import tree_sitter_languages
            # Support C, C++, Java, Kotlin, Python, Rust, Swift
            for lang in ['python', 'java', 'c', 'cpp', 'kotlin', 'rust', 'swift']:
                try:
                    self.parsers[lang] = tree_sitter_languages.get_parser(lang)
                except:
                    pass
            self.use_tree_sitter = True
            logger.info("✅ Tree-Sitter Polyglot Engine initialized.")
        except:
            logger.warning("⚠️ Tree-Sitter failed. Defaulting to Regex.")
            self.use_tree_sitter = False

    def _profile_system(self):
        for root, _, files in os.walk(self.root):
            if "AndroidManifest.xml" in files:
                self.profile.platform = Platform.ANDROID
                self._parse_android_manifest(os.path.join(root, "AndroidManifest.xml"))
            elif "Info.plist" in files:
                self.profile.platform = Platform.IOS
                self._parse_ios_plist(os.path.join(root, "Info.plist"))
            elif "Cargo.toml" in files and self.profile.platform == Platform.UNKNOWN:
                self.profile.platform = Platform.LINUX  # Rust Backend assumption

    def _parse_android_manifest(self, path):
        with open(path, "r", errors="ignore") as f: content = f.read()
        schemes = re.findall(r'android:scheme="([^"]+)"', content)
        self.profile.schemes.extend(schemes)
        if schemes: logger.info(f"📱 Android Schemes: {schemes}")

    def _parse_ios_plist(self, path):
        with open(path, "r", errors="ignore") as f: content = f.read()
        # Extract CFBundleURLSchemes
        schemes = re.findall(r"<string>([a-zA-Z0-9\.\-]+)</string>", content)
        valid_schemes = [s for s in schemes if "UI" not in s and "Story" not in s and len(s) < 20]
        if valid_schemes:
            self.profile.schemes.extend(valid_schemes)
            logger.info(f"🍎 iOS Schemes: {valid_schemes}")

    def _index_repo(self):
        logger.info(f"📂 Indexing {self.root}...")
        for root, _, files in os.walk(self.root):
            for f in files:
                path = os.path.join(root, f)
                ext = f.split('.')[-1]

                # Header Protection (Don't let .h overwrite .c)
                is_header = ext in ['h', 'hpp', 'hh']

                # 1. Tree-Sitter Parsing
                if self.use_tree_sitter:
                    if ext == 'java':
                        self._parse_ast(path, 'java')
                    elif ext in ['c', 'h']:
                        self._parse_ast(path, 'c', is_header)
                    elif ext in ['cpp', 'cc', 'hpp']:
                        self._parse_ast(path, 'cpp', is_header)
                    elif ext == 'kt':
                        self._parse_ast(path, 'kotlin')
                    elif ext == 'rs':
                        self._parse_ast(path, 'rust')
                    elif ext == 'swift':
                        self._parse_ast(path, 'swift')

                # 2. Regex Fallback (Objective-C & others)
                if ext in ['m', 'mm', 'java', 'kt', 'c', 'cpp', 'swift']:
                    self._scan_permissive_regex(path, ext)

        self._link_fuzzy_calls()

    def _scan_permissive_regex(self, path, ext):
        with open(path, "r", errors="ignore") as f:
            content = f.read()

        # ObjC vs C-Style regex
        if ext in ['m', 'mm']:
            def_pattern = r"[-+]\s*\(\w+\)\s*(\w+)[:\s]"
        elif ext == 'swift':
            def_pattern = r"func\s+(\w+)\s*\("
        else:
            def_pattern = r"(?:void|int|char|struct|static|fun|def|class)\s+(\w+)\s*\("

        defs = []
        for m in re.finditer(def_pattern, content):
            defs.append((m.start(), m.group(1)))
            if m.group(1) not in self.func_map: self.func_map[m.group(1)] = {"code": content, "file": path}

        # Greedy Linker (Calls + Pointers)
        for m in re.finditer(r"(?:\.|::|\s|\[|=)\s*(\w+)(?:\(|\]|\s|;)", content):
            self._link(defs, m.start(), m.group(1))

    def _link(self, defs, pos, name):
        parent = None
        for d_start, d_name in defs:
            if d_start < pos:
                parent = d_name
            else:
                break
        if parent and parent != name:
            if name not in self.call_graph: self.call_graph[name] = []
            if parent not in self.call_graph[name]: self.call_graph[name].append(parent)

    def _parse_ast(self, path, lang, is_header=False):
        try:
            with open(path, "r", errors="ignore") as f:
                code = f.read().encode()
            tree = self.parsers[lang].parse(code)
            import tree_sitter_languages

            queries = {
                'java': {'def': "(method_declaration name: (identifier) @n)",
                         'call': "(method_invocation name: (identifier) @n)"},
                'c': {'def': "(function_definition declarator: (function_declarator declarator: (identifier) @n))",
                      'call': "(call_expression function: (identifier) @n)"},
                'cpp': {'def': "(function_definition declarator: (function_declarator declarator: (identifier) @n))",
                        'call': "(call_expression function: (identifier) @n)"},
                'kotlin': {'def': "(function_declaration name: (simple_identifier) @n)",
                           'call': "(call_expression callee: (simple_identifier) @n)"},
                'swift': {'def': "(function_declaration name: (simple_identifier) @n)",
                          'call': "(call_expression function: (simple_identifier) @n)"},
                'rust': {'def': "(function_item name: (identifier) @n)",
                         'call': "(call_expression function: (identifier) @n)"}
            }

            if lang in queries:
                # Definitions
                try:
                    q_def = tree_sitter_languages.get_language(lang).query(queries[lang]['def'])
                    for node, _ in q_def.captures(tree.root_node):
                        name = code[node.start_byte:node.end_byte].decode()
                        if not is_header or name not in self.func_map:
                            self.func_map[name] = {"code": code.decode(), "file": path}
                except:
                    pass

                # Calls
                try:
                    q_call = tree_sitter_languages.get_language(lang).query(queries[lang]['call'])
                    for node, _ in q_call.captures(tree.root_node):
                        called = code[node.start_byte:node.end_byte].decode()
                        self._link_ast(node, called, code)
                except:
                    pass

            # --- POINTER/REFERENCE TRACKING (C/C++ Fix) ---
            if lang in ['c', 'cpp']:
                try:
                    ref_query_scm = """
                    (assignment_expression right: (identifier) @n)
                    (initializer_pair value: (identifier) @n)
                    (call_expression arguments: (argument_list (identifier) @n))
                    """
                    q_ref = tree_sitter_languages.get_language(lang).query(ref_query_scm)
                    for node, _ in q_ref.captures(tree.root_node):
                        ref_name = code[node.start_byte:node.end_byte].decode()
                        self._link_ast(node, ref_name, code, is_pointer=True)
                except:
                    pass

        except:
            pass

    def _link_ast(self, node, called_name, code, is_pointer=False):
        caller = self._find_parent(node, code)
        if caller:
            if called_name not in self.call_graph: self.call_graph[called_name] = []
            relationship = f"{caller} (Ptr)" if is_pointer else caller
            if relationship not in self.call_graph[called_name]:
                self.call_graph[called_name].append(relationship)

    def _find_parent(self, node, code):
        curr = node
        while curr:
            if "declaration" in curr.type or "definition" in curr.type or "function_item" in curr.type:
                child = curr.child_by_field_name("name") or curr.child_by_field_name("declarator")
                if child:
                    while child.child_count > 0: child = child.children[0]
                    return code[child.start_byte:child.end_byte].decode()
            curr = curr.parent
        return None

    def _link_fuzzy_calls(self):
        for func in list(self.func_map.keys()):
            if "Java_" in func:
                short = func.split("_")[-1]
                self.func_map[short] = self.func_map[func]
                if short in self.call_graph and func not in self.call_graph:
                    self.call_graph[func] = self.call_graph[short]

    def get_source(self, func):
        return self.func_map.get(func, {}).get("code", "")

    def get_file_path(self, func):
        return self.func_map.get(func, {}).get("file", "")


# --- V. AGENT BRAIN (LOGIC & STRATEGY) ---

try:
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import HumanMessage, SystemMessage

    HAS_LC = True
except:
    HAS_LC = False


class AgentBrain:
    def __init__(self):
        self.llm = ChatOpenAI(model=LLM_MODEL_NAME, temperature=0.0, base_url=LLM_BASE_URL,
                              api_key=LLM_API_KEY) if HAS_LC else None

    def _extract_json(self, text):
        try:
            match = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
            if match: return json.loads(match.group(1))
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match: return json.loads(match.group(0))
            return None
        except:
            return None

    def analyze_hop(self, caller_name, code_snippet, callee, param, platform):
        # PROMPT: Logic Accumulation + Pointer Awareness
        c_instr = "POINTER RULES: If `target` is assigned to a struct field (x.cb = target), RETURN TRUE." if platform == Platform.LINUX else ""
        system = f"""
        Analyze code connectivity AND constraints. {c_instr}
        OUTPUT JSON ONLY:
        {{ 
            "is_connected": bool, 
            "upstream_variable": "str", 
            "reasoning": "How is it used?",
            "constraints": ["List IF conditions guarding this call. E.g. 'if (admin)'"] 
        }}
        """
        human = f"Do these code lines use `{callee}`? What logic guards it?\nSNIPPET FROM {caller_name}:\n{code_snippet}"
        try:
            res = self.llm.invoke([SystemMessage(content=system), HumanMessage(content=human)])
            data = self._extract_json(res.content)
            if not data:
                return {"is_connected": "assign" in res.content.lower(), "reasoning": "Fallback",
                        "upstream_variable": "unknown", "constraints": []}
            return data
        except:
            return {"is_connected": False, "constraints": []}

    def summarize_strategy(self, trace: PathTrace):
        """
        Takes a full chain and writes a Hacker's Strategy.
        """
        chain_desc = []
        for step in reversed(trace.steps):
            chain_desc.append(f"Function: {step['caller']} -> {step['callee']}")
            chain_desc.append(f"   Logic: {step['reasoning']}")

        gates = json.dumps(trace.constraints)

        system = """
        You are an Exploit Developer. 
        Review the execution chain and write a 'Strategy Report'.
        OUTPUT JSON:
        {
            "attack_vector": "How to trigger (e.g. Deep Link, IOCTL, Broadcast)",
            "prerequisites": "What state is needed (e.g. Auth Token, Network Up)",
            "trigger_logic": "Step-by-step logic flow explanation",
            "confidence": "High/Med/Low"
        }
        """
        human = f"CHAIN:\n{json.dumps(chain_desc, indent=2)}\nCONSTRAINTS:\n{gates}"
        try:
            res = self.llm.invoke([SystemMessage(content=system), HumanMessage(content=human)])
            return self._extract_json(res.content) or {"attack_vector": "Unknown"}
        except:
            return {"attack_vector": "Unknown"}

    def speculate_triggers(self, code, func, platform):
        ctx = "Focus: Deep Links, Intents." if platform == Platform.ANDROID else "Focus: URL Schemes, NSUserActivity." if platform == Platform.IOS else "Focus: Syscalls, IOCTLs."
        system = f"Speculate entry vectors. {ctx} OUTPUT JSON: {{ \"triggers\": [ {{ \"type\": \"str\", \"likelihood\": \"High\", \"reasoning\": \"str\" }} ] }}"
        try:
            res = self.llm.invoke([SystemMessage(content=system), HumanMessage(content=code[:2000])])
            return self._extract_json(res.content) or {"triggers": []}
        except:
            return {"triggers": []}


# --- VI. COMPILER (ANDROID/IOS/LINUX) ---

class ExploitCompiler:
    def __init__(self, brain):
        self.brain = brain

    def generate_command(self, path: PathTrace, profile: SystemProfile) -> str:
        if not path.steps: return "echo 'Empty Path'"
        root_step = path.steps[-1]
        caller_name = root_step.get("caller", "")

        # Virtual Entry Logic
        if "Background Job" in caller_name:
            return f"echo '⚠️  Trigger Job: {root_step['callee']}'"
        elif "Broadcast" in caller_name:
            return f"adb shell am broadcast -a {path.injection_param}"

        # Solving Parameters
        data = self._solve_to_json(path.constraints, profile, path.injection_param)

        if profile.platform == Platform.ANDROID:
            return self._build_android_cmd(data, path.injection_param)
        elif profile.platform == Platform.IOS:
            scheme = data.get("scheme", "myapp")
            if "extracted" in scheme: scheme = "myapp"
            return f'xcrun simctl openurl booted "{scheme}://{data.get("host", "")}"'
        elif profile.platform == Platform.LINUX:
            return f"curl http://localhost{data.get('path', '')}"

        return "echo 'Exploit Generated'"

    def _solve_to_json(self, constraints, profile, param) -> Dict:
        from langchain_core.messages import HumanMessage, SystemMessage
        system_prompt = f"""
        Exploit Configurator for {profile.platform.value}.
        Constraints: {json.dumps(constraints)}
        Target: {param}
        Deep Links: {profile.schemes}
        OUTPUT JSON: {{ "scheme": "scheme", "host": "host", "path": "/path", "params": {{ "{param}": "INJECTED" }} }}
        """
        try:
            res = self.brain.llm.invoke([SystemMessage(content=system_prompt), HumanMessage(content="Extract.")])
            return self.brain._extract_json(res.content) or {}
        except:
            return {"scheme": "http", "host": "localhost"}

    def _build_android_cmd(self, data, injection_param) -> str:
        scheme = data.get("scheme", "https")
        if "extracted" in scheme: scheme = "https"
        host = data.get("host", "example.com")
        path = data.get("path", "")
        params = data.get("params", {})
        if injection_param not in params: params[injection_param] = "INJECTED"
        query_str = "&".join([f"{k}={v}" for k, v in params.items()])
        uri = f"{scheme}://{host}{path}?{query_str}"
        return f'adb shell am start -W -a android.intent.action.VIEW -d "{uri}"'


class ExploitLauncher:
    @staticmethod
    def prompt_and_execute(command: str):
        print(f"\n⚡ CMD: {command}")


# --- VII. ORCHESTRATOR ---

class UniversalPipeline:
    def __init__(self, repo_path):
        self.indexer = CodebaseIndexer(repo_path)
        self.brain = AgentBrain()
        self.compiler = ExploitCompiler(self.brain)
        self.visualizer = GraphGenerator()
        self.state_manager = StateManager()
        self.proven_exploits = []

    def run(self, sink_func, sink_param):
        logger.info(f"🎯 Target: {sink_func}")
        # Greedy search for target
        callers = self.indexer.call_graph.get(sink_func, [])
        if not callers:
            for k in self.indexer.call_graph.keys():
                if sink_func in k: callers.extend(self.indexer.call_graph[k])

        queue = [(sink_func, sink_param, PathTrace(injection_param=sink_param))]
        visited = set()

        while queue:
            func, param, path = queue.pop(0)
            if func in visited: continue
            visited.add(func)

            callers = self.indexer.call_graph.get(func, [])

            # --- SPECULATION ENGINE ---
            if not callers:
                code = self.indexer.get_source(func)
                spec = self.brain.speculate_triggers(code, func, self.indexer.profile.platform)
                for trig in spec.get("triggers", []):
                    step = {"caller": f"VIRTUAL: {trig['type']}", "callee": func, "reasoning": trig['reasoning']}
                    self.proven_exploits.append(PathTrace(steps=path.steps + [step], constraints=path.constraints))
                continue

            # Standard Trace
            for caller in callers:
                self._process_hop(caller, func, param, path, queue)

    def _process_hop(self, caller, callee, param, path, queue):
        clean_caller = caller.replace(" (Ptr)", "")
        full_code = self.indexer.get_source(clean_caller)
        if not full_code or callee not in full_code: return

        # --- CONTEXT SLICING ---
        lines = full_code.split('\n')
        snippets = []
        for i, line in enumerate(lines):
            if callee in line:
                snippets.append(f"Line {i}: " + "\n".join(lines[max(0, i - 5):min(len(lines), i + 6)]))
        focused_code = "\n...\n".join(snippets[:5])

        res = self.brain.analyze_hop(clean_caller, focused_code, callee, param, self.indexer.profile.platform)
        if res.get("is_connected"):
            logger.info(f"   🔗 {clean_caller} -> {callee}")
            step = {"caller": clean_caller, "callee": callee, "reasoning": res.get("reasoning")}

            # Accumulate Constraints
            new_constraints = path.constraints + res.get("constraints", [])

            queue.append((clean_caller, res.get("upstream_variable"),
                          PathTrace(steps=path.steps + [step], constraints=new_constraints)))

    def report(self, json_path="final_report.json"):
        if not self.proven_exploits: print("\n[Secure] No paths.")

        full_report_data = []
        for path in self.proven_exploits:
            if "license" in path.steps[-1]['caller'].lower(): continue

            self.visualizer.add_trace(path)

            # 1. Generate Strategy
            print(f"📝 Generating Strategy for chain starting at {path.steps[-1]['caller']}...")
            strategy = self.brain.summarize_strategy(path)

            # 2. Compile Command
            cmd = self.compiler.generate_command(path, self.indexer.profile)

            full_report_data.append({
                "sink": path.steps[0].get('callee'),
                "entry_point": path.steps[-1]['caller'],
                "exploit_command": cmd,
                "strategy": strategy,
                "constraints": path.constraints,
                "trace": path.steps
            })
            ExploitLauncher.prompt_and_execute(cmd)

        self.state_manager.save_full_report(full_report_data, json_path)
        self.visualizer.save()


if __name__ == "__main__":
    # EXAMPLE 1: iOS (Wikipedia)
    # hunter = UniversalPipeline("wikipedia-ios")
    # hunter.run("openURL", "url")
    # hunter.report("ios_report.json")

    # EXAMPLE 2: Kernel (XNU) - Enable for C Pointer Chasing
    # hunter = UniversalPipeline("darwin-xnu/bsd/netinet6")
    # hunter.indexer.profile.platform = Platform.LINUX  # Force Kernel Mode
    # hunter.run("nd6_llinfo_purge", "rt")
    # hunter.report("xnu_final.json")

    # Example 3
    hunter = UniversalPipeline("Signal-Android/app/src")
    hunter.indexer.profile.platform = Platform.ANDROID
    hunter.run("getType", "parsers")
    hunter.report("signal_final.json") # ImageHeaderParserUtils
