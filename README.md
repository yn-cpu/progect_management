#folow_finder_agent.py
import json
from pathlib import Path
from typing import List, Dict, Any

from rich.console import Console
from core.agent import ConversationTreeAgent
from core.cache import SemanticCache
from core.models import SARIFFinding
from tools.ast_engine import ASTEngine
from tools.code_search import CodeSearch
from prompts.loader import PromptLoader

console = Console()


class FlowFinderAgent(ConversationTreeAgent):
    """
    Graph-based Taint Analysis agent.
    Performs Reverse Taint Analysis (Sink -> Source) using DFS.
    """

    def __init__(self, model: str, cache: SemanticCache, repo_path: Path):
        # Tools used internally by the Python logic, not directly by the LLM
        self.repo_path = repo_path
        self.ast = ASTEngine(str(repo_path))
        self.search = CodeSearch(language="c")

        # We pass empty tools list because this agent is 'driven' by the Python DFS loop,
        # but uses the Agent base class for standard LLM interaction.
        tools = []

        system_prompt = "You are an expert Taint Analysis Engine."

        super().__init__(
            name="FlowFinderAgent",
            model=model,
            system_prompt=system_prompt,
            cache=cache,
            tools=tools
        )

        # Internal state for the DFS trace
        self.history = []

    async def identify_sink_context(self, finding: SARIFFinding) -> Dict[str, Any]:
        """
        Step 1: Parse the SARIF location to find the function/var name.
        """
        # Get code context surrounding the finding
        code_data = await self.search.read_code(
            str(finding.location.file),
            max(1, finding.location.line - 5),
            finding.location.line + 5
        )

        if "error" in code_data:
            return None

        # Render Prompt
        prompt = PromptLoader.render(
            "flow_context.j2",
            finding=finding,
            source_code=code_data['source']
        )

        # Run Agent
        return await self.run(prompt)

    async def analyze_step(self, current_func: str, current_file: str, tainted_var: str,
                           exclude_funcs: List[str] = None):
        """
        Step 2: Analyze callers to find the next step up the chain.
        """
        if exclude_funcs is None: exclude_funcs = []

        # --- AST Logic (Python Side) ---
        callers = self.ast.get_callers(current_func)
        if not callers: return []

        caller_contexts = {}
        caller_meta = {}

        # Prepare context for LLM by fetching code for all callers
        for c in callers:
            if c['name'] in exclude_funcs: continue
            body = self.ast.get_function_body(c['name'], specific_file_path=c['file'])
            if "not found" not in body:
                caller_contexts[c['name']] = body
                caller_meta[c['name']] = c['file']

        if not caller_contexts: return []

        target_code = self.ast.get_function_body(current_func, specific_file_path=current_file)

        # --- Render Prompt ---
        prompt = PromptLoader.render(
            "flow_step.j2",
            target_func=current_func,
            tainted_var=tainted_var,
            target_code=target_code,
            context=caller_contexts
        )

        # --- Run Agent ---
        result = await self.run(prompt)

        # Parse result and re-attach file paths from our metadata
        candidates = []
        raw_candidates = result.get("candidates", [])

        for cand in raw_candidates:
            c_name = cand.get('caller_name')
            if c_name in caller_meta:
                cand['file_path'] = caller_meta[c_name]
                candidates.append(cand)

        # Sort by risk (Highest risk first)
        candidates.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
        return candidates

    async def generate_summary(self) -> str:
        """
        Step 3: Generate final report from trace history.
        """
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

    # --- Orchestration Logic ---

    async def run_autonomous(self, finding: SARIFFinding, max_depth: int = 8):
        """
        Main entry point for Autonomous Mode.
        """
        self.history = []

        # 1. Initialization
        start_ctx = await self.identify_sink_context(finding)
        if not start_ctx:
            return {"success": False,
                    "reason": "Could not identify sink context (function/variable) from SARIF finding."}

        start_func = start_ctx.get("function_name")
        start_var = start_ctx.get("tainted_variable")
        start_file = str(finding.location.file)

        # 2. Start DFS
        success = await self._dfs_search(start_func, start_var, start_file, 0, max_depth)

        if success:
            report = await self.generate_summary()
            return {"success": True, "report": report, "trace": self.history}
        else:
            return {"success": False, "reason": "No path to main/entry point found"}

    async def _dfs_search(self, current_func, current_var, current_file, depth, max_depth):
        indent = "  " * depth

        # Record history
        self.history.append({
            "func": current_func,
            "file": current_file,
            "var": current_var,
            "score": 100 if depth == 0 else 0,
            "reason": "Vulnerable Sink" if depth == 0 else "Tracing..."
        })

        console.print(f"{indent}[dim]Tracing: {current_func} (var: {current_var})[/dim]")

        # Base Cases
        if current_func == "main":
            return True
        if depth >= max_depth:
            return False

        # Get Candidates via LLM
        # Exclude functions currently in the stack to prevent recursion loops
        path_funcs = [step['func'] for step in self.history[:-1]]
        candidates = await self.analyze_step(current_func, current_file, current_var, exclude_funcs=path_funcs)

        if not candidates:
            self.history.pop()  # Backtrack
            return False

        # Iterate Candidates
        for cand in candidates:
            # Prune low probability paths (heuristics)
            if cand['risk_score'] < 40:
                continue

                # Update the *current* step reasoning with why we chose this next step
            self.history[-1]['score'] = cand['risk_score']
            self.history[-1]['reason'] = cand['explanation']

            # Recurse
            found = await self._dfs_search(
                cand['caller_name'],
                cand['tainted_argument_in_caller'],
                cand['file_path'],
                depth + 1,
                max_depth
            )
            if found: return True

        # Backtrack if no candidates yield a result
        self.history.pop()
        return False

    async def run_interactive(self, finding: SARIFFinding):
        """
        Interactive Mode: Prompts user at each step.
        """
        self.history = []

        # 1. Identify Start
        start_ctx = await self.identify_sink_context(finding)
        if not start_ctx:
            console.print("[red]Could not identify context.[/red]")
            return

        current_func = start_ctx.get("function_name")
        current_var = start_ctx.get("tainted_variable")
        current_file = str(finding.location.file)

        self.history.append(
            {"func": current_func, "file": current_file, "var": current_var, "score": 100, "reason": "Sink"})

        while True:
            console.print(f"\n[bold]Current[/bold]: {current_func} (Var: {current_var})")

            visited = [h['func'] for h in self.history]
            candidates = await self.analyze_step(current_func, current_file, current_var, exclude_funcs=visited)

            if not candidates:
                console.print("[yellow]End of chain (no callers found).[/yellow]")
                break

            console.print("\n[bold cyan]Incoming Calls:[/bold cyan]")
            for idx, cand in enumerate(candidates):
                console.print(
                    f"[{idx + 1}] {cand['caller_name']} (Risk: {cand['risk_score']}) - Var: {cand['tainted_argument_in_caller']}")

            choice = input("\nSelect path [number], [s]ummary, or [q]uit: ").strip().lower()

            if choice == 'q': return
            if choice == 's': break

            if choice.isdigit() and 0 < int(choice) <= len(candidates):
                sel = candidates[int(choice) - 1]

                # Add to history
                self.history.append({
                    "func": sel['caller_name'],
                    "file": sel['file_path'],
                    "var": sel['tainted_argument_in_caller'],
                    "score": sel['risk_score'],
                    "reason": sel['explanation']
                })

                # Advance pointers
                current_func = sel['caller_name']
                current_var = sel['tainted_argument_in_caller']
                current_file = sel['file_path']
            else:
                console.print("[red]Invalid selection.[/red]")

        report = await self.generate_summary()
        console.print(Panel(report, title="Interactive Analysis Report", border_style="green"))

#vuln_agent.py
import asyncio
import os
import json
import sys
from litellm import completion
from tools.ast_engine import ASTEngine


class VulnAnalysisAgent:
    def __init__(self, repo_path, model="ollama/qwen2.5-coder:14b"):
        self.ast = ASTEngine(repo_path)
        self.model = model
        self.history = []

    async def _analyze_step_shared(self, current_func, current_file, tainted_var, exclude_funcs=None):
        if exclude_funcs is None: exclude_funcs = []

        # 1. Get Callers
        callers = self.ast.get_callers(current_func)
        if not callers: return []

        # 2. Get Contexts
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

        # 3. LLM Request
        system_prompt = """You are a Taint Analysis Expert.
        Identify which callers pass data into the target variable.
        Return JSON."""

        user_prompt = f"""
        TARGET: `{current_func}` | TAINTED VAR: `{tainted_var}`
        TARGET CODE:
        {target_code}

        CALLERS:
        {"".join([f"--- {name} ---\n{code}\n" for name, code in caller_contexts.items()])}

        OUTPUT JSON:
        {{ "candidates": [ {{ "caller_name": "name", "tainted_argument_in_caller": "var", "risk_score": 0-100, "explanation": "..." }} ] }}
        """

        try:
            response = completion(
                model=self.model,
                messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
                format="json"
            )

            content = response.choices[0].message.content
            if "```" in content:
                content = content.split("```json")[1].split("```")[0] if "json" in content else content.split("```")[1]

            data = json.loads(content.strip())
            raw_candidates = data.get("candidates", [])

            candidates = []
            for cand in raw_candidates:
                c_name = cand['caller_name']

                if c_name in caller_meta:
                    c_file = caller_meta[c_name]
                    cand['file_path'] = c_file
                    candidates.append(cand)
            candidates.sort(key=lambda x: x['risk_score'], reverse=True)
            return candidates

        except Exception as e:
            print(f"LLM Error: {e}")
            return []

    async def generate_summary(self):
        print("=" * 40)
        print("📝 Generating Comprehensive Summary...")
        print("=" * 40)
        for i, step in enumerate(reversed(self.history)):
            print(f"Step {i + 1}: {step['func']} (Var: {step['var']})")
            print(f"  -> File: {os.path.basename(step['file'])}")
            print(f"  -> Note: {step['reason']}")
            print("-" * 40)

        trace_text = ""
        for i, step in enumerate(reversed(self.history)):
            trace_text += f"""
            Step {i + 1}: Function '{step['func']}' (File: {step['file']})
            - Variable Tainted: {step['var']}
            - Risk Score: {step['score']}
            - Analysis: {step['reason']}
            --------------------------------------------------
            """

        prompt = f"""
        You are a Senior Security Researcher writing a vulnerability report.
        Below is a confirmed execution trace found in the codebase, leading from a Source to a Sink.

        TRACE HISTORY (Source to Sink):
        {trace_text}

        TASK:
        1. Summarize the vulnerability class (e.g., Buffer Overflow, SQLi, Command Injection).
        2. Explain the flow logic: How the data travels from the entry point to the dangerous sink.
        3. Suggest a proof of vulnerability in python, craft an input that will trigger the vulnerability.
        """

        response = completion(
            model=self.model,
            messages=[{"role": "user", "content": prompt}]
        )
        print("\n" + "=" * 60)
        print("DETAILED VULNERABILITY SUMMARY REPORT")
        print("=" * 60)
        print(response.choices[0].message.content)
        print("=" * 60)

    async def run_interactive(self, start_func, start_var, start_file):
        current_func, current_var, current_file = start_func, start_var, start_file
        self.history.append({"func": current_func, "file": current_file or "Unknown", "var": current_var, "score": 100,
                             "reason": "Sink"})

        while True:
            print(f"\n📍 CURRENT: {current_func} (Tainted: {current_var})")
            visited = [h['func'] for h in self.history]
            candidates = await self._analyze_step_shared(current_func, current_file, current_var, exclude_funcs=visited)

            if not candidates:
                print("🛑 No verified flows found.")
                await self.generate_summary();
                break

            print("\n👇 VERIFIED FLOWS:")
            for idx, cand in enumerate(candidates[:5]):
                print(
                    f"[{idx + 1}] {cand['caller_name']} (Risk: {cand['risk_score']}) - Var: {cand['tainted_argument_in_caller']}")

            print("\n[#] Select | [s] Summary | [q] Quit")
            choice = input("> ").strip().lower()

            if choice == 's': await self.generate_summary(); break
            if choice == 'q': break

            if choice.isdigit() and 0 < int(choice) <= len(candidates):
                sel = candidates[int(choice) - 1]
                self.history.append({
                    "func": sel['caller_name'], "file": sel['file_path'], "var": sel['tainted_argument_in_caller'],
                    "score": sel['risk_score'], "reason": sel['explanation']
                })
                current_func = sel['caller_name']
                current_var = sel['tainted_argument_in_caller']
                current_file = sel['file_path']

    # --- MODE 2: AUTONOMOUS (DFS + Backtracking) ---
    async def run_autonomous(self, current_func, current_var, current_file, depth=0, max_depth=8):
        indent = "  " * depth
        if depth == 0:
            print(f"🤖 AUTO-AGENT STARTED: Tracing '{current_var}' in '{current_func}'")
            self.history.append(
                {"func": current_func, "file": current_file or "Unknown", "var": current_var, "score": 100,
                 "reason": "Sink"})

        if current_func == "main":
            print(f"{indent}🔥 ROOT CAUSE FOUND: main()")
            return True

        if depth >= max_depth:
            print(f"{indent}⚠️ Max depth reached.")
            return False

        print(f"{indent}🔍 Analyzing: {current_func}...")
        current_path_funcs = [step['func'] for step in self.history]
        candidates = await self._analyze_step_shared(current_func, current_file, current_var,
                                                     exclude_funcs=current_path_funcs)

        if not candidates:
            print(f"{indent}🛑 Dead end.")
            return False

        for cand in candidates:
            if cand['risk_score'] < 40: continue

            print(f"{indent}➡️ Trying path: {cand['caller_name']} (Risk: {cand['risk_score']})")
            self.history.append({
                "func": cand['caller_name'], "file": cand['file_path'], "var": cand['tainted_argument_in_caller'],
                "score": cand['risk_score'], "reason": cand['explanation']
            })

            found_root = await self.run_autonomous(cand['caller_name'], cand['tainted_argument_in_caller'],
                                                   cand['file_path'], depth + 1)

            if found_root: return True

            print(f"{indent}↩️ Backtracking from {cand['caller_name']}...")
            self.history.pop()

        return False


async def main():
    print("=" * 40);
    print("      VULNERABILITY RESEARCH CLI");
    print("=" * 40)
    repo_path = input("Repo Path (default: ./complex_repo): ").strip() or "./complex_repo"
    if not os.path.exists(repo_path): print("Invalid path."); sys.exit(1)

    print("\nSelect Mode: [1] Interactive [2] Autonomous")
    mode = input("> ").strip()

    target_func = input("Target Function: ").strip() or "unsafe_copy"
    target_var = input("Tainted Variable: ").strip() or "src"
    target_file = input("Target File (Optional): ").strip() or None

    agent = VulnAnalysisAgent(repo_path)
    if mode == "1":
        await agent.run_interactive(target_func, target_var, target_file)
    elif mode == "2":
        success = await agent.run_autonomous(target_func, target_var, target_file)
        if success:
            await agent.generate_summary()
        else:
            print("\n❌ No path to main found."); await agent.generate_summary()


if __name__ == "__main__":
    asyncio.run(main())

#ast_engine.py
import os
import glob
from typing import List, Dict
from tree_sitter import Language, Parser, Node


class LanguageStrategy:
    def __init__(self, name: str, package, file_ext: list):
        self.name = name
        self.language = Language(package.language())
        self.file_ext = file_ext

    def get_func_def_query(self, name: str) -> str:
        raise NotImplementedError

    def get_call_query(self, name: str) -> str:
        raise NotImplementedError

    def get_arg_validation_query(self, callee_name: str) -> str:
        raise NotImplementedError


class CLang(LanguageStrategy):
    def __init__(self, name, package, file_ext):
        super().__init__(name, package, file_ext)

    def get_func_def_query(self, name: str) -> str:
        return f"""(function_definition declarator: (_ declarator: (identifier) @id) (#eq? @id "{name}")) @func"""

    def get_call_query(self, name: str) -> str:
        return f"""(call_expression function: (identifier) @callee (#eq? @callee "{name}")) @call"""

    def get_arg_validation_query(self, callee_name: str) -> str:
        return f"""(call_expression function: (identifier) @id arguments: (argument_list) @args (#eq? @id "{callee_name}"))"""


class CppLang(LanguageStrategy):
    """
    Handles C++ complexity: Namespaces, Classes, Methods (obj.method, ptr->method)
    """

    def __init__(self, name, package, file_ext):
        super().__init__(name, package, file_ext)

    def get_func_def_query(self, name: str) -> str:
        # Matches: void func() OR void Class::func()
        return f"""
        (function_definition
            declarator: (function_declarator
                declarator: [
                    (identifier) @id
                    (qualified_identifier name: (identifier) @id)
                ]
            )
            (#eq? @id "{name}")
        ) @func
        """

    def get_call_query(self, name: str) -> str:
        # Matches: func(), obj.func(), ptr->func(), Class::func()
        return f"""
        (call_expression
            function: [
                (identifier) @simple
                (field_expression field: (field_identifier) @method)
                (qualified_identifier name: (identifier) @scoped)
            ] @callee
            (#match? @callee "{name}")
        ) @call
        """

    def get_arg_validation_query(self, callee_name: str) -> str:
        # Capture arguments for all the variations above
        return f"""
        (call_expression
            function: [
                (identifier) @simple
                (field_expression field: (field_identifier) @method)
                (qualified_identifier name: (identifier) @scoped)
            ] @id
            arguments: (argument_list) @args
            (#match? @id "{callee_name}")
        )
        """


class JavaLang(LanguageStrategy):
    def __init__(self, name, package, file_ext):
        super().__init__(name, package, file_ext)

    def get_func_def_query(self, name: str) -> str:
        return f"""(method_declaration name: (identifier) @id (#eq? @id "{name}")) @func"""

    def get_call_query(self, name: str) -> str:
        return f"""(method_invocation name: (identifier) @callee (#eq? @callee "{name}")) @call"""

    def get_arg_validation_query(self, callee_name: str) -> str:
        return f"""(method_invocation name: (identifier) @id arguments: (argument_list) @args (#eq? @id "{callee_name}"))"""


class RustLang(LanguageStrategy):
    def __init__(self, name, package, file_ext):
        super().__init__(name, package, file_ext)

    def get_func_def_query(self, name: str) -> str:
        return f"""(function_item name: (identifier) @id (#eq? @id "{name}")) @func"""

    def get_call_query(self, name: str) -> str:
        return f"""(call_expression function: [ (identifier) @simple (field_expression field: (identifier) @method) ] @callee (#match? @callee "{name}")) @call"""

    def get_arg_validation_query(self, callee_name: str) -> str:
        return f"""(call_expression function: [ (identifier) @simple (field_expression field: (identifier) @method) ] @id arguments: (argument_list) @args (#match? @id "{callee_name}"))"""


def get_strategies():
    strategies = []
    # C
    try:
        import tree_sitter_c
        strategies.append(CLang("C", tree_sitter_c, [".c", ".h"]))
    except ImportError:
        pass

    # C++
    try:
        import tree_sitter_cpp
        strategies.append(CppLang("C++", tree_sitter_cpp, [".cpp", ".cc", ".cxx", ".hpp", ".hxx"]))
    except ImportError:
        print("Note: 'tree-sitter-cpp' not found. C++ support disabled.")

    # Java
    try:
        import tree_sitter_java
        strategies.append(JavaLang("Java", tree_sitter_java, [".java"]))
    except ImportError:
        pass

    # Rust
    try:
        import tree_sitter_rust
        strategies.append(RustLang("Rust", tree_sitter_rust, [".rs"]))
    except ImportError:
        pass

    return strategies


class ASTEngine:
    def __init__(self, repo_path):
        self.repo_path = repo_path
        self.strategies = get_strategies()
        if not self.strategies:
            print("WARNING: No tree-sitter languages found.")

    def _get_strategy_for_file(self, file_path):
        for s in self.strategies:
            if any(file_path.endswith(ext) for ext in s.file_ext):
                return s
        return None

    def get_function_body(self, func_name: str, specific_file_path: str = None) -> str:
        if specific_file_path and os.path.exists(specific_file_path):
            strategy = self._get_strategy_for_file(specific_file_path)
            if strategy:
                return self._parse_file_for_func(specific_file_path, strategy, func_name)

        for strategy in self.strategies:
            files = []
            for ext in strategy.file_ext:
                files.extend(glob.glob(os.path.join(self.repo_path, "**", f"*{ext}"), recursive=True))

            for file_path in files:
                result = self._parse_file_for_func(file_path, strategy, func_name)
                if "not found" not in result:
                    return result
        return f"Function '{func_name}' not found."

    def _parse_file_for_func(self, file_path, strategy, func_name):
        try:
            with open(file_path, 'rb') as f:
                src = f.read()
            parser = Parser(strategy.language)
            tree = parser.parse(src)
            query = strategy.language.query(strategy.get_func_def_query(func_name))
            matches = query.matches(tree.root_node)
            if matches:
                for _, captures in matches:
                    node = list(captures.values())[0] if isinstance(captures, dict) else captures[0][0]
                    if isinstance(node, list): node = node[0]
                    return f"// File: {file_path}\n{src[node.start_byte:node.end_byte].decode('utf-8', errors='replace')}"
        except Exception:
            pass
        return f"Function '{func_name}' not found in {file_path}"

    def get_callers(self, func_name: str) -> List[Dict[str, str]]:
        callers = []
        for strategy in self.strategies:
            parser = Parser(strategy.language)
            files = []
            for ext in strategy.file_ext:
                files.extend(glob.glob(os.path.join(self.repo_path, "**", f"*{ext}"), recursive=True))

            for file_path in files:
                try:
                    with open(file_path, 'rb') as f:
                        src = f.read()
                    tree = parser.parse(src)
                    query = strategy.language.query(strategy.get_call_query(func_name))
                    matches = query.matches(tree.root_node)

                    if matches:
                        for _, captures in matches:
                            call_node = list(captures.values())[0] if isinstance(captures, dict) else captures[0][0]
                            if isinstance(call_node, list): call_node = call_node[0]

                            curr = call_node
                            while curr:
                                if curr.type in ['function_definition', 'method_declaration', 'function_item',
                                                 'method_definition']:
                                    name_node = curr.child_by_field_name('declarator') or curr.child_by_field_name(
                                        'name')

                                    if name_node and name_node.type == 'function_declarator':
                                        name_node = name_node.child_by_field_name('declarator')

                                    if name_node:
                                        func_text = src[name_node.start_byte:name_node.end_byte].decode('utf-8')
                                        if "::" in func_text:
                                            func_text = func_text.split("::")[-1]

                                        func_text = func_text.split('(')[0].strip()
                                        callers.append({"name": func_text, "file": file_path})
                                    break
                                curr = curr.parent
                except Exception:
                    pass

        unique_callers = []
        seen = set()
        for c in callers:
            key = f"{c['name']}|{c['file']}"
            if key not in seen:
                seen.add(key)
                unique_callers.append(c)
        return unique_callers

 #main3.py
 import typer
import asyncio
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

from config.settings import settings
from core.cache import SemanticCache
from core.models import SARIFFinding, CodeLocation
from tools.sarif_parser import SARIFParser
from scanners.llm_scanner import LLMScanner
from agents.triage_agent import SARIFTriageAgent
from agents.flow_finder_agent import FlowFinderAgent

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
        # Resolve absolute path
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

    # Sort: Prioritize Critical/High
    def severity_rank(item):
        sev = item['finding'].severity.value.lower()
        if sev == 'critical': return 0
        if sev == 'high': return 1
        return 2

    validated.sort(key=severity_rank)
    top_hit = validated[0]
    finding = top_hit['finding']

    console.print(Panel(
        f"[bold red]Top Priority: {finding.rule_id}[/bold red]\n{finding.message}\nFile: {finding.location.file}:{finding.location.line}",
        title="Starting Autonomous Flow Analysis"
    ))

    # 3. Autonomous Flow Finder
    finder = FlowFinderAgent(model=settings.default_investigation_model, cache=cache, repo_path=target_dir)
    result = await finder.run_autonomous(finding)

    if result["success"]:
        console.print(Panel(result["report"], title="Autonomous Research Report", border_style="green"))
    else:
        console.print("[red]Autonomous analysis failed to find a complete path to main.[/red]")


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
    finder = FlowFinderAgent(model=settings.default_investigation_model, cache=cache, repo_path=target_dir)

    console.print("[bold]Manual Flow Finder Mode[/bold]")
    file_name = Prompt.ask("Target File Path (relative to repo)")
    line_num = int(Prompt.ask("Line Number"))
    vuln_name = Prompt.ask("Vulnerability Name (e.g. CWE-120)", default="Generic Vulnerability")

    # Construct a synthetic finding
    finding = SARIFFinding(
        rule_id=vuln_name,
        message="Manual investigation request",
        location=CodeLocation(
            file=target_dir / file_name,
            line=line_num
        ),
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

# prompts/templates/flow_context.j2
[System]
You are a Vulnerability Researcher.
Your task is to identify the specific function name and the "tainted" variable (the dangerous input) in a code snippet.

[User]
**Vulnerability**: {{ finding.rule_id }}
**Message**: {{ finding.message }}
**Location**: {{ finding.location.file }}:{{ finding.location.line }}
**Code Snippet**:
```c
{{ source_code }}
```
**Instruction**: Identify the function name containing this code, and the variable that acts as the dangerous input (the 'sink'). Respond with a single JSON object.
**Response Schema**: { "function_name": "<string>", "tainted_variable": "<string>" }
# prompts/templates/flow_step.j2
[System]
You are a Taint Analysis Expert.
Your goal is to determine which function callers are passing data into a specific variable.

[User]
**Target Function**: `{{ target_func }}`
**Tainted Variable**: `{{ tainted_var }}`

**Target Code**:
```c
{{ target_code }}
```
**Candidate Callers**: {% for name, code in context.items() %} --- Function: {{ name }} ---{{ code }}{% endfor %}
**Instruction**: Analyze the "Candidate Callers". Determine which of them pass data into the {{ tainted_var }} of the {{ target_func }}. Assign a risk score (0-100). High score (80+) means the data comes from an external/user-controlled source or parameter.
**Response Schema**: { "candidates": [ { "caller_name": "<string>", "tainted_argument_in_caller": "<string, the var name in the caller's scope>", "risk_score": <int>, "explanation": "<string>" } ] }
# prompts/templates/flow_summary.j2
[System]
You are a Senior Security Researcher writing a vulnerability report.

[User]
**Task**: Write a detailed report based on the execution trace below.

**Trace History (Source to Sink)**:
{{ trace_history }}

**Requirements**:
1. Summarize the vulnerability class.
2. Explain the flow logic: How the data travels from the entry point to the dangerous sink.
3. Suggest a proof of vulnerability strategy (e.g. what input to provide to `main`).

Respond with a JSON object containing a "report" field (markdown string).
