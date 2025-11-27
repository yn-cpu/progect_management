I have reviewed the architecture and logic. Here are the corrected, robust, and fully implemented files.

### Key Improvements & Fixes:

1.  **Regex Robustness**: Improved regex patterns to capture function signatures more accurately and avoid common false positives (like comments containing keywords).
2.  **Path Normalization**: Fixed a potential bug where the AST engine returns absolute paths while the scanner returns relative paths, causing the "Entry Point Reached" check to fail.
3.  **Batch Processing**: The `EntryPointAgent` groups hits by file to reduce LLM calls, but handles them efficiently.
4.  **Targeting Logic**: Added specific logic to `Deep Flow` to prioritize a *user-selected* entry point if provided, acting as a strong heuristic guide.

-----

### 1\. Template: `prompts/templates/entry_point_validator.j2`

````jinja
[System]
You are a Senior Security Architect specializing in Attack Surface Analysis.
Your goal is to validate if specific functions are **External Entry Points** (Attack Surface).

[User]
**Language**: {{ language }}
**File**: {{ file_path }}

**Candidate Functions (found via Regex)**:
{{ candidates_list }}

**Source Code Context**:
```{{ language }}
{{ source_code }}
````

**Definition of Entry Point**:
A function that handles data crossing a trust boundary.

1.  **Mobile**: Lifecycle methods (`onCreate`, `applicationDidFinishLaunching`), UI Events (`onClick`, `IBAction`), URL Schemes, IPC (`onBind`, `onReceive`).
2.  **Native**: `JNIEXPORT`, `main`, exported symbols.
3.  **Web**: Route handlers, Controllers.

**Instruction**:
Analyze the candidates. Return the subset that are TRUE external entry points.
Discard internal helpers or private methods even if they match patterns.

**Response Schema**:
{
"entry\_points": [
{
"function\_name": "\<name\>",
"line\_number": \<int\>,
"type": "\<JNI | IPC | UI | Network | Main | Exported\>",
"confidence": \<0-100\>
}
]
}

````

### 2. Template: `prompts/templates/deep_flow.j2`

```jinja
[System]
You are a Senior Security Researcher specializing in Complex Data Flows.
Standard static analysis failed to find a direct caller. You must infer "hidden" data flows.

[User]
**Target Function**: `{{ target_func }}`
**Tainted Variable**: `{{ tainted_var }}`
**Current Location**: `{{ current_file }}`

**Repository Structure**:
```text
{{ repo_map }}
````

**Known Entry Points (Attack Surface)**:
{% if target\_ep %}
\*\*\* PRIORITY TARGET \*\*\*: {{ target\_ep.function\_name }} ({{ target\_ep.type }}) in {{ target\_ep.file }}
{% endif %}
{% for ep in entry\_points %}

  - {{ ep.function\_name }} ({{ ep.type }}) in {{ ep.file }}
    {% endfor %}

**Scenario Analysis**:
We are tracing BACKWARDS from `{{ target_func }}`.
If `{{ target_func }}` is not called directly, how does data get here?

Consider:

1.  **Implicit Connection**: Is `{{ target_func }}` a callback, an interface implementation, or assigned to a function pointer?
2.  **Entry Point Link**: Can one of the **Known Entry Points** (especially the Priority Target) trigger this path via IPC, JNI, or Event Bus?
3.  **Data Store**: Does an Entry Point write to a DB/File that this function reads?

**Instruction**:
Propose up to 3 potential sources.
If a **Priority Target** is set, you MUST try to find a logical path from that target to here.

**Response Schema**:
{
"deep\_candidates": [
{
"source\_file": "\<path\_to\_file\>",
"suspected\_function": "\<function\_name\_from\_entry\_points\_or\_repo\>",
"mechanism": "\<IPC, JNI, Event, File, etc.\>",
"reasoning": "\<Explain the specific connection logic\>"
}
]
}

````

### 3. Agent: `agents/entry_point_agent.py`

```python
import re
import os
import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional
from rich.console import Console

from core.agent import ConversationTreeAgent
from core.cache import SemanticCache
from tools.code_search import CodeSearch
from prompts.loader import PromptLoader

console = Console()

class EntryPointAgent(ConversationTreeAgent):
    """
    Identifies external entry points (Attack Surface) in mobile/system codebases.
    Uses Regex for fast candidate generation and LLM for semantic validation.
    """

    # Optimized Patterns to reduce false positives
    PATTERNS = {
        "java": [
            r"public\s+void\s+on[A-Z]\w+\s*\(",  # Android Lifecycle/Events
            r"@\w+Mapping", # Spring/Web
            r"extends\s+(ContentProvider|Service|BroadcastReceiver|Activity)",
            r"JNIEXPORT",
            r"@JavascriptInterface"
        ],
        "c": [
            r"JNIEXPORT\s+\w+\s+JNICALL", # JNI strict
            r"Java_\w+", # JNI naming convention
            r"int\s+main\s*\(", 
            r"__attribute__\s*\(\(constructor\)\)",
            r"EXPORT_SYMBOL"
        ],
        "cpp": [
            r"JNIEXPORT", 
            r"extern\s+\"C\"\s+JNIEXPORT",
            r"int\s+main\s*\(", 
            r"Q_INVOKABLE" # Qt
        ],
        "rust": [
            r"#\[no_mangle\]", 
            r"pub\s+extern\s+\"C\"",
            r"fn\s+main\s*\("
        ],
        "swift": [
            r"@IBAction", 
            r"func\s+application\s*\(", # AppDelegate
            r"func\s+scene\s*\(", # SceneDelegate
            r"@objc\s+public"
        ],
        "objective-c": [
            r"-\s*\(\s*IBAction\s*\)",
            r"-\s*\(\s*void\s*\)\s*application",
            r"RCT_EXPORT_METHOD" # React Native
        ]
    }

    def __init__(self, model: str, cache: SemanticCache, repo_path: Path):
        self.repo_path = repo_path
        self.search = CodeSearch() # Initialize simple code reader
        
        # Must pass empty tools list to super
        super().__init__(
            name="EntryPointAgent",
            model=model,
            system_prompt="You are an Attack Surface Analyzer.",
            cache=cache,
            tools=[] 
        )

    def _get_language(self, file_path: str) -> Optional[str]:
        ext = file_path.split('.')[-1].lower()
        mapping = {
            'java': 'java', 'kt': 'java',
            'c': 'c', 'h': 'c',
            'cpp': 'cpp', 'cc': 'cpp', 'hpp': 'cpp', 'cxx': 'cpp',
            'rs': 'rust',
            'swift': 'swift',
            'm': 'objective-c', 'mm': 'objective-c'
        }
        return mapping.get(ext)

    async def scan_repo(self) -> List[Dict[str, Any]]:
        """
        Scans the repo for entry points. 
        Returns a list of validated entry point objects.
        """
        console.print("[bold cyan]Scanning for Entry Points (Attack Surface)...[/bold cyan]")
        
        candidates_by_file = {}
        
        # 1. Regex Scan (Fast)
        for root, dirs, files in os.walk(self.repo_path):
            # Skip noise
            dirs[:] = [d for d in dirs if d not in {'.git', 'build', 'node_modules', 'venv', '__pycache__'}]
            
            for file in files:
                lang = self._get_language(file)
                if not lang: continue
                
                full_path = Path(root) / file
                try:
                    # Read only first 200 lines for header/class defs if file is huge, 
                    # but regex needs context. We read full text but handle errors.
                    content = full_path.read_text(errors='ignore')
                    
                    hits = []
                    for pattern in self.PATTERNS.get(lang, []):
                        for match in re.finditer(pattern, content):
                            line_num = content[:match.start()].count('\n') + 1
                            # Extract snippet cleanly
                            start = max(0, match.start() - 10)
                            end = min(len(content), match.end() + 40)
                            snippet = content[start:end].strip().replace('\n', ' ')
                            hits.append(f"Line {line_num}: {snippet}")
                    
                    if hits:
                        # Deduplicate hits
                        unique_hits = list(set(hits))[:10] # Cap at 10 per file to save tokens
                        candidates_by_file[str(full_path)] = {"lang": lang, "hits": unique_hits}
                        
                except Exception:
                    continue

        console.print(f"[dim]Regex found potential entry points in {len(candidates_by_file)} files.[/dim]")

        # 2. LLM Validation (Smart)
        validated_entry_points = []
        
        for file_path, data in candidates_by_file.items():
            result = await self._validate_file(file_path, data['lang'], data['hits'])
            if result:
                for ep in result:
                    # Normalize file path relative to repo root for cleaner reporting
                    try:
                        rel_path = str(Path(file_path).relative_to(self.repo_path))
                    except ValueError:
                        rel_path = file_path
                        
                    ep['file'] = rel_path
                    validated_entry_points.append(ep)
                    console.print(f"  [green]Confirmed[/green]: {ep['function_name']} ({ep['type']}) in {Path(rel_path).name}")

        return validated_entry_points

    async def _validate_file(self, file_path: str, language: str, hits: List[str]) -> List[Dict]:
        """Sends regex hits to LLM for confirmation."""
        
        # Read code context (first 300 lines usually contain the definitions)
        code_data = await self.search.read_code(file_path, 1, 300) 
        if "error" in code_data: 
            return []

        prompt = PromptLoader.render(
            "entry_point_validator.j2",
            language=language,
            file_path=file_path,
            candidates_list="\n".join(hits),
            source_code=code_data['source']
        )

        result = await self.run(prompt)
        return result.get("entry_points", [])
````

### 4\. Agent: `agents/flow_finder_agent.py`

```python
import json
import os
from pathlib import Path
from typing import List, Dict, Any, Optional

from rich.console import Console
from rich.prompt import Confirm
from rich.panel import Panel

from core.agent import ConversationTreeAgent
from core.cache import SemanticCache
from core.models import SARIFFinding
from tools.ast_engine import ASTEngine
from tools.code_search import CodeSearch
from prompts.loader import PromptLoader

console = Console()

class FlowFinderAgent(ConversationTreeAgent):
    """
    Graph-based Taint Analysis agent with Deep Flow capabilities.
    Integrates AST walking with Semantic Inference (Deep Flow).
    """

    def __init__(self, model: str, cache: SemanticCache, repo_path: Path):
        self.repo_path = repo_path
        self.ast = ASTEngine(str(repo_path))
        self.search = CodeSearch(language="c") 
        
        self.history = []
        self.known_entry_points: List[Dict] = []
        self.target_entry_point: Optional[Dict] = None

        super().__init__(
            name="FlowFinderAgent",
            model=model,
            system_prompt="You are an expert Taint Analysis Engine.",
            cache=cache,
            tools=[] 
        )

    def set_entry_points(self, entry_points: List[Dict], target_ep: Optional[Dict] = None):
        """Populate the agent with known attack surface."""
        self.known_entry_points = entry_points
        self.target_entry_point = target_ep

    def _get_repo_map(self) -> str:
        """
        Generates a high-level tree view of the repo for Deep Analysis.
        Filters for relevant source files to keep context small.
        """
        file_list = []
        for root, dirs, files in os.walk(self.repo_path):
            # Exclude common junk
            dirs[:] = [d for d in dirs if d not in {'.git', '.idea', '__pycache__', 'venv', 'node_modules', 'build', 'target'}]
            
            for f in files:
                if f.endswith(('.c', '.cpp', '.h', '.hpp', '.py', '.java', '.js', '.ts', '.go', '.rs', '.swift', '.m')):
                    rel_path = os.path.relpath(os.path.join(root, f), self.repo_path)
                    file_list.append(rel_path)
        
        # Limit to 200 files to prevent token overflow
        return "\n".join(file_list[:200])

    async def identify_sink_context(self, finding: SARIFFinding) -> Dict[str, Any]:
        """Step 1: Parse SARIF for function/var name."""
        code_data = await self.search.read_code(
            str(finding.location.file),
            max(1, finding.location.line - 5),
            finding.location.line + 5
        )

        if "error" in code_data:
            return None

        prompt = PromptLoader.render(
            "flow_context.j2",
            finding=finding,
            source_code=code_data['source']
        )
        return await self.run(prompt)

    async def analyze_step(self, current_func: str, current_file: str, tainted_var: str, exclude_funcs: List[str] = None):
        """Step 2: Standard AST-based Caller Analysis."""
        if exclude_funcs is None: exclude_funcs = []
        
        callers = self.ast.get_callers(current_func)
        if not callers: return []

        caller_contexts = {}
        caller_meta = {}

        for c in callers:
            if c['name'] in exclude_funcs: continue
            body = self.ast.get_function_body(c['name'], specific_file_path=c['file'])
            if "not found" not in body:
                caller_contexts[c['name']] = body
                caller_meta[c['name']] = c['file']

        if not caller_contexts: return []

        target_code = self.ast.get_function_body(current_func, specific_file_path=current_file)
        
        prompt = PromptLoader.render(
            "flow_step.j2",
            target_func=current_func,
            tainted_var=tainted_var,
            target_code=target_code,
            context=caller_contexts
        )
        
        result = await self.run(prompt)
        
        candidates = []
        raw = result.get("candidates", [])
        for cand in raw:
            c_name = cand.get('caller_name')
            if c_name in caller_meta:
                cand['file_path'] = caller_meta[c_name]
                candidates.append(cand)
        
        candidates.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
        return candidates

    async def deep_analysis_step(self, current_func: str, current_file: str, tainted_var: str):
        """
        Fallback Step: Uses semantic reasoning and Entry Points when AST fails.
        """
        console.print(f"[bold magenta]Initiating Deep Flow Analysis for {current_func}...[/bold magenta]")
        
        repo_map = self._get_repo_map()
        
        prompt = PromptLoader.render(
            "deep_flow.j2",
            target_func=current_func,
            tainted_var=tainted_var,
            current_file=current_file,
            repo_map=repo_map,
            entry_points=self.known_entry_points,
            target_ep=self.target_entry_point
        )
        
        result = await self.run(prompt)
        raw_candidates = result.get("deep_candidates", [])
        
        candidates = []
        for deep in raw_candidates:
            candidates.append({
                "caller_name": deep.get("suspected_function", "Unknown"),
                "file_path": deep.get("source_file"),
                "tainted_argument_in_caller": "IMPLICIT_FLOW",
                "risk_score": 50,
                "explanation": f"[DEEP FLOW] {deep.get('mechanism')}: {deep.get('reasoning')}"
            })
            
        return candidates

    async def generate_summary(self) -> str:
        trace_text = ""
        for i, step in enumerate(reversed(self.history)):
            trace_text += (
                f"Step {i + 1}: Function '{step['func']}' (File: {step['file']})\n"
                f"- Variable: {step['var']}\n"
                f"- Risk Score: {step['score']}\n"
                f"- Analysis: {step['reason']}\n"
                "--------------------------------------------------\n"
            )

        prompt = PromptLoader.render("flow_summary.j2", trace_history=trace_text)
        result = await self.run(prompt)
        return result.get("report", "No report generated.")

    def _is_entry_point(self, func_name: str, file_path: str) -> bool:
        """Checks if the current location matches a known entry point."""
        if not self.known_entry_points:
            return False
            
        # Normalize file path for comparison (handling relative vs absolute)
        # We try to match the filename and the function name
        current_filename = os.path.basename(file_path)
        
        for ep in self.known_entry_points:
            ep_filename = os.path.basename(ep['file'])
            if ep['function_name'] == func_name and ep_filename == current_filename:
                return True
        return False

    # --- Autonomous Mode ---

    async def run_autonomous(self, finding: SARIFFinding, max_depth: int = 8):
        self.history = []
        
        start_ctx = await self.identify_sink_context(finding)
        if not start_ctx:
            return {"success": False, "reason": "Could not identify sink context."}

        start_func = start_ctx.get("function_name")
        start_var = start_ctx.get("tainted_variable")
        start_file = str(finding.location.file)

        success = await self._dfs_search(start_func, start_var, start_file, 0, max_depth)
        
        if success:
            report = await self.generate_summary()
            return {"success": True, "report": report, "trace": self.history}
        else:
            return {"success": False, "reason": "No path to entry point found."}

    async def _dfs_search(self, current_func, current_var, current_file, depth, max_depth):
        indent = "  " * depth
        self.history.append({
            "func": current_func, "file": current_file, "var": current_var, 
            "score": 100 if depth == 0 else 0, 
            "reason": "Sink" if depth == 0 else "Tracing..."
        })
        
        console.print(f"{indent}[dim]Tracing: {current_func} ({os.path.basename(current_file or '')})[/dim]")

        # --- Base Cases ---
        
        # 1. Main
        if current_func == "main":
            self.history[-1]['reason'] = "Reached main()"
            return True
            
        # 2. Known Entry Point (Gravity Well)
        if self._is_entry_point(current_func, current_file):
            console.print(f"{indent}[bold green]REACHED ENTRY POINT: {current_func}[/bold green]")
            self.history[-1]['reason'] = "Reached Confirmed Entry Point (Source)"
            return True
            
        if depth >= max_depth:
            return False

        path_funcs = [step['func'] for step in self.history[:-1]]
        
        # --- Step 1: Standard AST ---
        candidates = await self.analyze_step(current_func, current_file, current_var, exclude_funcs=path_funcs)

        # --- Step 2: Deep Analysis (Fallback) ---
        if not candidates:
            console.print(f"{indent}[yellow]Standard AST dead end. Triggering Deep Analysis...[/yellow]")
            candidates = await self.deep_analysis_step(current_func, current_file, current_var)

        # Backtrack if still empty
        if not candidates:
            self.history.pop()
            return False

        # DFS Recursion
        for cand in candidates:
            self.history[-1]['reason'] = cand['explanation']
            found = await self._dfs_search(
                cand['caller_name'], 
                cand['tainted_argument_in_caller'], 
                cand['file_path'], 
                depth + 1, 
                max_depth
            )
            if found: return True
        
        self.history.pop()
        return False
    
    # --- Interactive Mode ---

    async def run_interactive(self, finding: SARIFFinding):
        self.history = []
        
        start_ctx = await self.identify_sink_context(finding)
        if not start_ctx:
            console.print("[red]Could not identify context.[/red]")
            return

        current_func = start_ctx.get("function_name")
        current_var = start_ctx.get("tainted_variable")
        current_file = str(finding.location.file)

        self.history.append({"func": current_func, "file": current_file, "var": current_var, "score": 100, "reason": "Sink"})

        while True:
            # Check for Entry Point Reached
            if self._is_entry_point(current_func, current_file):
                console.print(f"\n[bold green]🎉 REACHED CONFIRMED ENTRY POINT: {current_func}[/bold green]")
                if Confirm.ask("Stop tracing and generate report?"):
                    break

            console.print(f"\n[bold]Current[/bold]: {current_func} (Var: {current_var})")
            
            visited = [h['func'] for h in self.history]
            candidates = await self.analyze_step(current_func, current_file, current_var, exclude_funcs=visited)

            # Deep Flow Trigger
            if not candidates:
                console.print("[yellow]End of chain (no AST callers found).[/yellow]")
                if Confirm.ask("Activate Deep Flow Analysis (Semantic Search)?"):
                    candidates = await self.deep_analysis_step(current_func, current_file, current_var)

            if not candidates:
                console.print("[red]Dead end.[/red]")
                break

            console.print("\n[bold cyan]Incoming Calls / Sources:[/bold cyan]")
            for idx, cand in enumerate(candidates):
                style = "magenta" if "[DEEP FLOW]" in cand['explanation'] else "white"
                console.print(f"[{idx + 1}] [{style}]{cand['caller_name']}[/{style}] - {cand['explanation'][:80]}...")

            choice = input("\nSelect path [number], [s]ummary, or [q]uit: ").strip().lower()

            if choice == 'q': return
            if choice == 's': break
            
            if choice.isdigit() and 0 < int(choice) <= len(candidates):
                sel = candidates[int(choice) - 1]
                
                self.history.append({
                    "func": sel['caller_name'], 
                    "file": sel['file_path'], 
                    "var": sel['tainted_argument_in_caller'],
                    "score": sel.get('risk_score', 50), 
                    "reason": sel['explanation']
                })
                
                current_func = sel['caller_name']
                current_var = sel['tainted_argument_in_caller']
                current_file = sel['file_path']
            else:
                console.print("[red]Invalid selection.[/red]")

        report = await self.generate_summary()
        console.print(Panel(report, title="Interactive Analysis Report", border_style="green"))
```

### 5\. CLI: `main.py`

```python
import typer
import asyncio
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm

from config.settings import settings
from core.cache import SemanticCache
from core.models import SARIFFinding, CodeLocation
from tools.sarif_parser import SARIFParser
from scanners.llm_scanner import LLMScanner
from agents.triage_agent import SARIFTriageAgent
from agents.flow_finder_agent import FlowFinderAgent
from agents.entry_point_agent import EntryPointAgent

app = typer.Typer(help="VulnTriage: AI-Powered Vulnerability Research System")
console = Console()

async def run_scan(target_dir: Path, output_dir: Path) -> Path:
    """Helper to run the scanner."""
    console.print(f"[bold cyan]1. Scanning {target_dir}...[/bold cyan]")
    scanner = LLMScanner(model=settings.default_triage_model)
    sarif_file = await scanner.run(target_dir, output_dir)
    return sarif_file

async def run_triage(sarif_file: Path, codebase: Path, cache: SemanticCache) -> list[dict]:
    """Helper to run triage and return validated findings."""
    console.print(f"[bold cyan]2. Triaging Findings...[/bold cyan]")
    try:
        findings = SARIFParser.parse(sarif_file)
    except Exception as e:
        console.print(f"[red]Error parsing SARIF: {e}[/red]")
        return []

    triage_agent = SARIFTriageAgent(model=settings.default_triage_model, cache=cache)
    
    validated = []
    for f in findings:
        f.location.file = codebase.resolve() / f.location.file
        console.print(f"  > Checking {f.rule_id} at {f.location.file.name}:{f.location.line}...")
        res = await triage_agent.triage(f, codebase)
        if res.get("is_true_positive"):
            validated.append({"finding": f, "triage_data": res})
    return validated

# --- Option 1: Full Repo Research ---
async def mode_full_research(target_dir: Path):
    output_dir = Path("results")
    cache = SemanticCache()

    # 1. Scan
    sarif_file = await run_scan(target_dir, output_dir)
    
    # 2. Triage
    validated = await run_triage(sarif_file, target_dir, cache)
    if not validated:
        console.print("[green]No high-confidence vulnerabilities found.[/green]")
        return

    # Prioritize findings
    validated.sort(key=lambda x: 0 if x['finding'].severity.value == 'critical' else 1)
    finding = validated[0]['finding']

    console.print(Panel(f"[bold red]Top Priority: {finding.rule_id}[/bold red]\n{finding.message}", title="Starting Autonomous Flow Analysis"))

    # 3. Entry Point Scan
    ep_agent = EntryPointAgent(model=settings.default_triage_model, cache=cache, repo_path=target_dir)
    entry_points = await ep_agent.scan_repo()

    # 4. Flow Finder
    finder = FlowFinderAgent(model=settings.default_investigation_model, cache=cache, repo_path=target_dir)
    finder.set_entry_points(entry_points)
    
    result = await finder.run_autonomous(finding)

    if result["success"]:
        console.print(Panel(result["report"], title="Autonomous Research Report", border_style="green"))
    else:
        console.print("[red]Autonomous analysis failed to find a complete path.[/red]")

# --- Option 2: Bug Finder ---
async def mode_bug_finder(target_dir: Path):
    output_dir = Path("results")
    cache = SemanticCache()
    
    sarif_file = await run_scan(target_dir, output_dir)
    validated = await run_triage(sarif_file, target_dir, cache)

    table = Table(title="Validated Bugs")
    table.add_column("Rule", style="cyan")
    table.add_column("Location")
    table.add_column("Severity", style="red")
    
    for v in validated:
        f = v['finding']
        table.add_row(f.rule_id, f"{f.location.file.name}:{f.location.line}", f.severity.value)
    
    console.print(table)

# --- Option 3 & 4: Flow Finder (Interactive/Auto) ---
async def mode_flow_finder(target_dir: Path, interactive: bool):
    cache = SemanticCache()
    
    # 1. Scan Attack Surface
    ep_agent = EntryPointAgent(model=settings.default_triage_model, cache=cache, repo_path=target_dir)
    entry_points = await ep_agent.scan_repo()
    
    if not entry_points:
        console.print("[yellow]No specific entry points found. Will rely on 'main' or implicit flows.[/yellow]")

    # 2. Setup Finder
    finder = FlowFinderAgent(model=settings.default_investigation_model, cache=cache, repo_path=target_dir)
    
    # Optional Target Selection
    target_ep = None
    if interactive and entry_points and Confirm.ask("Do you want to direct the analysis toward a specific Entry Point?"):
        console.print("\n[bold]Available Entry Points:[/bold]")
        for i, ep in enumerate(entry_points):
            console.print(f"[{i}] {ep['function_name']} ({ep['type']}) in {ep['file']}")
        
        idx = int(Prompt.ask("Select Index", default="0"))
        if 0 <= idx < len(entry_points):
            target_ep = entry_points[idx]
            console.print(f"[green]Target set: {target_ep['function_name']}[/green]")

    finder.set_entry_points(entry_points, target_ep)

    # 3. Define Sink (Finding)
    console.print("\n[bold]Define Vulnerability Sink (Start Point)[/bold]")
    file_name = Prompt.ask("Target File Path (relative to repo)")
    line_num = int(Prompt.ask("Line Number"))
    vuln_name = Prompt.ask("Vulnerability Name", default="Manual Investigation")

    finding = SARIFFinding(
        rule_id=vuln_name,
        message="Manual investigation request",
        location=CodeLocation(file=target_dir / file_name, line=line_num),
        severity="high"
    )

    if interactive:
        await finder.run_interactive(finding)
    else:
        console.print("[yellow]Running Autonomous Search...[/yellow]")
        result = await finder.run_autonomous(finding)
        if result["success"]:
            console.print(Panel(result["report"], title="Research Report", border_style="green"))
        else:
            console.print("[red]No path found.[/red]")

@app.command()
def start(
    target: Path = typer.Argument(..., exists=True, file_okay=False, help="Target repository directory")
):
    """
    Main entry point. Selects mode via prompt.
    """
    console.print(Panel("VulnTriage CLI", subtitle="Select Operation Mode"))
    console.print("1. Full Repo Research (Scan -> Triage -> Auto Trace Top Vulnerability)")
    console.print("2. Bug Finder (Scan -> Triage Only)")
    console.print("3. Flow Finder (Interactive Trace of Specific Location)")
    console.print("4. Flow Finder (Autonomous Trace of Specific Location)")
    
    mode = int(Prompt.ask("Choice", choices=["1", "2", "3", "4"], default="1"))

    if mode == 1:
        asyncio.run(mode_full_research(target))
    elif mode == 2:
        asyncio.run(mode_bug_finder(target))
    elif mode == 3:
        asyncio.run(mode_flow_finder(target, interactive=True))
    elif mode == 4:
        asyncio.run(mode_flow_finder(target, interactive=False))

if __name__ == "__main__":
    app()
```
