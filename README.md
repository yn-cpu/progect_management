#prompts/templates/deep_flow.j2
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

**Scenario Analysis**:
If `{{ target_func }}` is not called directly, how does data get here?
Consider:

1.  **IPC / RPC**: Handlers, intent receivers, or message queues.
2.  **File I/O**: Does another part of the app write to a file that this function reads?
3.  **Database**: Is this data pulled from a shared DB table?
4.  **Framework Events**: Is this an event listener (e.g., `onClick`, `onReceive`)?
5.  **Memory**: Shared memory regions or global state.

**Instruction**:
Propose up to 3 *potential* sources from the repository structure that could logically trigger this function or provide this data.
Be creative but grounded in the context of the file names and structure.

**Response Schema**:
{"deep\_candidates": [{"source\_file": "\<path\_to\_file\>",
"suspected\_function": "\<function\_name\_exact\_match\_if\_possible\>",
"mechanism": "\<IPC, File, DB, Event, etc.\>",
"reasoning": "\<Why you think this connects\>"}]}


#agents/flow_finder_agent.py
import json
import os
from pathlib import Path
from typing import List, Dict, Any

from rich.console import Console
from rich.prompt import Confirm  # <--- NEW IMPORT
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
    """

    def __init__(self, model: str, cache: SemanticCache, repo_path: Path):
        self.repo_path = repo_path
        self.ast = ASTEngine(str(repo_path))
        self.search = CodeSearch(language="c") 
        tools = [] 
        
        system_prompt = "You are an expert Taint Analysis Engine."
        
        super().__init__(
            name="FlowFinderAgent",
            model=model,
            system_prompt=system_prompt,
            cache=cache,
            tools=tools
        )
        self.history = []

    def _get_repo_map(self) -> str:
        """
        Generates a high-level tree view of the repo for Deep Analysis.
        Filters for relevant source files to keep context small.
        """
        file_list = []
        # Walk the directory
        for root, dirs, files in os.walk(self.repo_path):
            # Exclude common junk dirs to speed up and clean output
            dirs[:] = [d for d in dirs if d not in {'.git', '.idea', '__pycache__', 'venv', 'node_modules', 'build'}]
            
            for f in files:
                if f.endswith(('.c', '.cpp', '.h', '.hpp', '.py', '.java', '.js', '.go', '.rs')):
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
        Fallback Step: Uses semantic reasoning when AST fails.
        """
        console.print(f"[bold magenta]Initiating Deep Flow Analysis for {current_func}...[/bold magenta]")
        
        repo_map = self._get_repo_map()
        
        prompt = PromptLoader.render(
            "deep_flow.j2",
            target_func=current_func,
            tainted_var=tainted_var,
            current_file=current_file,
            repo_map=repo_map
        )
        
        result = await self.run(prompt)
        raw_candidates = result.get("deep_candidates", [])
        
        # Convert "deep" format to standard "candidate" format
        candidates = []
        for deep in raw_candidates:
            candidates.append({
                "caller_name": deep.get("suspected_function", "Unknown"),
                "file_path": deep.get("source_file"),
                "tainted_argument_in_caller": "IMPLICIT_FLOW",
                "risk_score": 50, # Lower confidence for semantic inference
                "explanation": f"[DEEP FLOW] Mechanism: {deep.get('mechanism')}. {deep.get('reasoning')}"
            })
            
        return candidates

    async def generate_summary(self) -> str:
        trace_text = ""
        for i, step in enumerate(reversed(self.history)):
            trace_text += (
                f"Step {i + 1}: Function '{step['func']}' (File: {step['file']})\n"
                f"- Variable: {step['var']}\n"
                f"- Analysis: {step['reason']}\n"
                "--------------------------------------------------\n"
            )

        prompt = PromptLoader.render("flow_summary.j2", trace_history=trace_text)
        result = await self.run(prompt)
        return result.get("report", "No report generated.")

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
            return {"success": False, "reason": "No path to main/entry point found"}

    async def _dfs_search(self, current_func, current_var, current_file, depth, max_depth):
        indent = "  " * depth
        
        self.history.append({
            "func": current_func, 
            "file": current_file, 
            "var": current_var, 
            "score": 100 if depth == 0 else 0, 
            "reason": "Sink" if depth == 0 else "Tracing..."
        })
        
        console.print(f"{indent}[dim]Tracing: {current_func} (var: {current_var})[/dim]")

        # Base Cases
        if current_func == "main":
            return True
        if depth >= max_depth:
            return False

        path_funcs = [step['func'] for step in self.history[:-1]]
        
        # 1. Try Standard AST First
        candidates = await self.analyze_step(current_func, current_file, current_var, exclude_funcs=path_funcs)

        # 2. If AST fails, trigger Deep Analysis
        if not candidates:
            console.print(f"{indent}[yellow]Standard AST dead end. Triggering Deep Analysis...[/yellow]")
            candidates = await self.deep_analysis_step(current_func, current_file, current_var)

        # If both fail, backtrack
        if not candidates:
            self.history.pop()
            return False

        # DFS Recursion
        for cand in candidates:
            # Update history with reasoning *before* diving deeper
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
                # Highlight Deep Flow candidates
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
