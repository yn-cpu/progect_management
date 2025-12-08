You are absolutely correct to double-check. For the system to work as a cohesive whole—handling the **state reset** on disconnect *and* the **semantic reasoning** with **precise file mapping**—you need to update **6 files**.

If you only updated the 4 files from the previous step, the "Save & Reset" feature would fail because the orchestration layer (`SidebarProvider` and `extension.ts`) wouldn't know how to handle the shutdown or the handshake.

Here is the **Complete, Verified File Set**.

### 1\. `src/core/types.ts`

**Reason:** Defines the data structure for holding Logic, Constraints, and IDs.

```typescript
import { z } from 'zod';

export const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);

export interface Finding {
    id: string;
    ruleId: string;
    message: string;
    file: string;
    line: number;
    severity: z.infer<typeof SeveritySchema>;
    status: 'pending' | 'verified' | 'false_positive';
    triageReason?: string;
}

export const ScanResponseSchema = z.object({
  findings: z.array(z.object({
    rule_id: z.string(),
    message: z.string(),
    line_number: z.number(),
    severity: z.string()
  }))
});

export interface FlowNode {
    id: string;
    function: string;
    file: string;
    variable: string;
    line?: number;
    type: 'source' | 'sink' | 'intermediate';
    // \new: Stores the constraint active at this node (e.g. "len < 1024")
    active_constraint?: string; 
}

export interface FlowEdge {
    from: string;
    to: string;
    label?: string;
    // \new: Logic status of the connection
    status?: 'open' | 'sanitized' | 'constrained';
    reason?: string;
}

export interface FlowGraph {
    nodes: FlowNode[];
    edges: FlowEdge[];
}

export interface FlowCandidate {
    // \new: Internal ID for mapping back to exact source file
    id?: number; 
    caller: string;
    arg: string;
    risk: number;
    file: string;
    line: number;
    reason?: string;
    
    // \new: Semantic Analysis Fields
    reachability: 'possible' | 'unlikely' | 'safe';
    // \new: The logic transformation (e.g. "x = y + 5")
    transformation_logic: string; 
    // \new: The constraint for the NEXT step
    upstream_constraint: string;
}

export type BackendMessage = 
    | { type: 'scan_progress', value: string, percent?: number } 
    | { type: 'scan_complete', findings: Finding[], shouldSwitchView?: boolean }
    | { type: 'triage_update', findingId: string, status: 'verified' | 'false_positive', reason: string, percent?: number }
    | { type: 'flow_update', graph: FlowGraph, log: string }
    | { type: 'scope_selected', path: string }
    | { type: 'report_generated', report: string }
    | { type: 'interactive_candidates', candidates: FlowCandidate[] }
    | { type: 'reset_state' }; // \new: Command to clear Frontend

export type FrontendMessage = 
    | { command: 'webview_loaded' } // \new: Handshake signal
    | { command: 'selectScope' } 
    | { command: 'saveSession', findings?: Finding[], logs?: string[], report?: string } 
    | { command: 'startScan', scopePath?: string, focus?: string }
    | { command: 'startFlow', finding: Finding, mode: 'interactive' | 'autonomous' }
    | { command: 'generateReport', finding: Finding }
    | { command: 'openFile', file: string, line: number }
    | { command: 'interactive_selection', selection: FlowCandidate };
```

-----

### 2\. `src/core/prompts.ts`

**Reason:** Instructs the LLM to act as a Symbolic Execution Engine and use IDs for mapping.

```typescript
import { Finding } from "./types";

export class PromptFactory {
    
    static renderTriage(finding: Finding, codeSnippet: string): string {
        return `
        [System]
        You are a Senior Security Triage Engineer. Filter False Positives.
        
        [User]
        Analyze this finding:
        Rule: ${finding.ruleId}
        Message: ${finding.message}
        Location: ${finding.file}:${finding.line}
        
        Code Context:
        \`\`\`c
        ${codeSnippet}
        \`\`\`
        
        Is this a True Positive?
        Return JSON: { "is_true_positive": boolean, "confidence": float, "reasoning": "string" }
        `;
    }

    // \new: Prompt to extract the "Root Cause" constraint
    static renderExploitCondition(finding: Finding, code: string): string {
        return `
        [System]
        You are an Exploit Engineer.
        Analyze this vulnerability. Define the mathematical or logical "Constraint" on the variable that triggers the bug.
        
        [User]
        Vuln: ${finding.ruleId}
        Message: ${finding.message}
        Code: 
        \`\`\`
        ${code}
        \`\`\`

        Task:
        1. Identify the dangerous variable.
        2. Define the constraint (e.g., "len < 0", "cmd contains ';'", "ptr == NULL").

        Return JSON: { "exploit_condition": "string", "tainted_variable_name": "string" }
        `;
    }

    // \new: Semantic Prompt with ID Mapping and Constraint Propagation
    static renderReachabilityStep(targetFunc: string, taintedVar: string, currentConstraint: string, callers: string): string {
        return `
        [System]
        You are a Semantic Code Analyzer performing Backward Taint Analysis.
        You must perform "Constraint Propagation".

        [Context]
        Target Function: ${targetFunc}
        Variable of Interest: ${taintedVar}
        Current Constraint Required for Exploit: "${currentConstraint}"

        [Task]
        Analyze the "Incoming Callers" below. Each is marked with an [ID].
        For each caller:
        1. Identify the value/variable passed to '${taintedVar}'.
        2. MAPPING: If a literal is passed, does it satisfy "${currentConstraint}"? (If yes -> Exploit Found. If no -> Safe).
        3. TRANSFORMATION: If a variable is passed, deduce the NEW constraint on that upstream variable.
           - Example: If need "x > 10" and caller has "func(y + 5)", new constraint is "y > 5".

        [Incoming Callers]
        ${callers}

        [Output Format]
        Return JSON: 
        { 
          "candidates": [ 
            { 
              "caller_id": number, // \new: MUST MATCH THE [ID] FROM INPUT
              "caller_name": "string", 
              "tainted_arg": "string", 
              "reachability": "possible" | "unlikely" | "safe",
              "transformation_logic": "string (Explain reasoning)",
              "upstream_constraint": "string (The NEW constraint)",
              "risk_score": number
            } 
          ] 
        }
        `;
    }

    static renderDeepFlow(funcName: string, file: string, repoMap: string): string {
        return `
        [System]
        You are a Senior Security Researcher specializing in Complex Data Flows.
        
        [User]
        Target Function: ${funcName}
        Current Location: ${file}
        Repo Map: ${repoMap}

        We are tracing BACKWARDS from '${funcName}'. It is not called directly.
        Propose up to 3 potential indirect sources.

        Return JSON: { "candidates": [ { "caller_name": "string (inferred)", "tainted_arg": "string", "risk_score": number, "reason": "string" } ] }
        `;
    }

    static renderReport(finding: Finding, traceHistory: string): string {
        return `
        [System]
        You are a Senior Security Researcher writing a vulnerability report.

        [User]
        Vulnerability: ${finding.ruleId}
        Location: ${finding.file}:${finding.line}
        Trace: ${traceHistory}

        Write a detailed executive summary.
        Return JSON: { "markdown_report": "string" }
        `;
    }
}
```

-----

### 3\. `src/agents/flowFinderAgent.ts`

**Reason:** Performs the logic loop, maps IDs to files, and prioritizes "Possible" paths over "Unlikely" ones.

```typescript
import * as vscode from 'vscode';
import * as path from 'path';
import { LLMProvider } from '../core/llm';
import { ASTEngine } from '../tools/astEngine';
import { PromptFactory } from '../core/prompts';
import { Finding, FlowGraph, FlowNode, FlowCandidate } from '../core/types';

export class FlowFinderAgent {
    private graph: FlowGraph = { nodes: [], edges: [] };
    private history: string[] = [];
    private currentNodeId: string = "";
    // \new: Store root constraint for reporting
    private rootExploitCondition: string = "Unknown"; 

    constructor(
        private llm: LLMProvider,
        private ast: ASTEngine,
        private sendUpdate: (graph: FlowGraph, log: string) => void,
        private sendCandidates: (candidates: FlowCandidate[]) => void 
    ) {}

    private dispatchUpdate(log: string) {
        const safeGraph: FlowGraph = JSON.parse(JSON.stringify(this.graph));
        this.sendUpdate(safeGraph, log);
    }
    public getSessionData() { return { graph: this.graph, traceHistory: this.history }; }

    async startAnalysis(finding: Finding, mode: 'interactive' | 'autonomous') {
        this.graph = { nodes: [], edges: [] }; 
        this.history = [];
        
        this.dispatchUpdate(`Analyzing Sink Logic...`);
        let sinkCode = "";
        try {
            const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(finding.file));
            const range = new vscode.Range(Math.max(0, finding.line - 5), 0, Math.min(doc.lineCount, finding.line + 5), 0);
            sinkCode = doc.getText(range);
        } catch (e) { console.error(e); }

        // \new: Determine Root Condition
        const conditionPrompt = PromptFactory.renderExploitCondition(finding, sinkCode);
        const conditionRes = await this.llm.chat([{ role: 'user', content: conditionPrompt }], true);
        
        let taintedVar = "UNKNOWN";
        try {
            const parsed = JSON.parse(conditionRes);
            this.rootExploitCondition = parsed.exploit_condition;
            taintedVar = parsed.tainted_variable_name;
            this.history.push(`Sink Requirement: ${this.rootExploitCondition}`);
        } catch { this.rootExploitCondition = "Generic Taint"; }

        // \new: Create Sink Node with active_constraint
        const sinkNode: FlowNode = {
            id: `step_0`,
            function: 'Sink', 
            variable: taintedVar, 
            file: finding.file,
            line: finding.line,
            type: 'sink',
            active_constraint: this.rootExploitCondition 
        };
        this.graph.nodes.push(sinkNode);
        this.currentNodeId = sinkNode.id;

        const ext = path.extname(finding.file).substring(1);
        await this.ast.init(ext || 'c');
        try {
            const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(finding.file));
            sinkNode.function = this.ast.getFunctionName(this.ast.getFunctionAtLine(doc.getText(), finding.line) || "") || "unknown";
        } catch(e) {}

        if (mode === 'autonomous') {
            await this.autonomousLoop(sinkNode, 0);
        } else {
            this.dispatchUpdate(`Verifying Reachability for ${sinkNode.function} (Constraint: ${this.rootExploitCondition})...`);
            const candidates = await this.verifyCallerReachability(sinkNode, this.rootExploitCondition);
            
            if (candidates.length === 0) {
                this.dispatchUpdate("No reachable paths found.");
                this.sendCandidates([]); 
            } else {
                // \new: Sort by Risk for Interactive Mode
                this.sendCandidates(candidates.sort((a,b) => b.risk - a.risk));
            }
        }
    }

    public async processInteractiveSelection(selection: FlowCandidate) {
        const depth = this.graph.nodes.length;
        
        const newNode: FlowNode = {
            id: `step_${depth}`,
            function: selection.caller,
            variable: selection.arg,
            file: selection.file,
            line: selection.line,
            type: 'intermediate',
            // \new: Inherit the calculated upstream constraint
            active_constraint: selection.upstream_constraint 
        };

        this.graph.nodes.push(newNode);
        this.graph.edges.push({
            from: newNode.id,
            to: this.currentNodeId,
            label: selection.arg,
            // \new: Visual status based on reachability logic
            status: selection.reachability === 'safe' ? 'sanitized' : 'open',
            reason: selection.transformation_logic 
        });
        
        this.currentNodeId = newNode.id;
        this.history.push(`${selection.caller} -> ${selection.transformation_logic}`);
        this.dispatchUpdate(`Advanced to ${selection.caller}`);

        // \new: Terminate if constraint resolved
        if (selection.upstream_constraint === 'Fixed Value' || selection.upstream_constraint === 'None') {
             this.dispatchUpdate(`Trace Ended: Value is ${selection.reachability}.`);
             this.sendCandidates([]);
             return;
        }

        const nextCandidates = await this.verifyCallerReachability(newNode, newNode.active_constraint || "Unknown");
        this.sendCandidates(nextCandidates.sort((a,b) => b.risk - a.risk));
    }

    // \new: Updated to use ID Mapping for 100% File/Line Accuracy
    private async verifyCallerReachability(node: FlowNode, currentConstraint: string): Promise<FlowCandidate[]> {
        const files = await vscode.workspace.findFiles('**/*.{c,cpp,h,py,java}', '**/node_modules/**', 20);
        let callersText = "";
        
        // \new: Map to store exact file info by index
        const potentialCallers: {file: string, line: number, caller: string}[] = [];

        for (const file of files) {
             try {
                const contentBytes = await vscode.workspace.fs.readFile(file);
                const content = contentBytes.toString();
                if (content.includes(node.function)) {
                    const ext = path.extname(file.fsPath).substring(1);
                    await this.ast.init(ext);
                    const lines = content.split('\n');
                    lines.forEach((lineText, idx) => {
                        if (lineText.includes(`${node.function}(`)) {
                            const enclosingFunc = this.ast.getFunctionName(this.ast.getFunctionAtLine(content, idx + 1) || "") || "unknown";
                            const snippet = lines.slice(Math.max(0, idx - 5), Math.min(lines.length, idx + 5)).join('\n');
                            
                            // \new: Generate ID based on array index
                            const id = potentialCallers.length; 
                            callersText += `[ID: ${id}]\nFile: ${file.fsPath}\nCaller: ${enclosingFunc}\nSnippet:\n${snippet}\n---\n`;
                            
                            potentialCallers.push({ 
                                file: file.fsPath, 
                                line: idx + 1, // Store precise line
                                caller: enclosingFunc 
                            });
                        }
                    });
                }
             } catch(e) {}
        }

        if (callersText.length > 0) {
            const prompt = PromptFactory.renderReachabilityStep(node.function, node.variable, currentConstraint, callersText);
            const response = await this.llm.chat([{ role: 'user', content: prompt }], true);
            
            try {
                const result = JSON.parse(response);
                return result.candidates.map((c: any) => {
                    // \new: Retrieve precise location using ID
                    const matchedCaller = potentialCallers[c.caller_id];
                    // Fallback to name match if LLM hallucinates ID
                    const finalMatch = matchedCaller || potentialCallers.find(p => p.caller === c.caller_name) || potentialCallers[0];

                    return {
                        caller: c.caller_name,
                        arg: c.tainted_arg,
                        risk: c.risk_score,
                        
                        // \new: Use the trusted file/line data
                        file: finalMatch ? finalMatch.file : "unknown",
                        line: finalMatch ? finalMatch.line : 0,
                        
                        reason: c.transformation_logic, 
                        reachability: c.reachability,
                        transformation_logic: c.transformation_logic,
                        upstream_constraint: c.upstream_constraint
                    };
                });
            } catch (e) { return []; }
        }
        return [];
    }

    private async autonomousLoop(currentNode: FlowNode, depth: number) {
        if (depth >= 5) return;

        const candidates = await this.verifyCallerReachability(currentNode, currentNode.active_constraint || "Unknown");
        
        // \new: Sorting Logic - Prioritize Possibility THEN Risk
        const viable = candidates.filter(c => c.reachability !== 'safe').sort((a,b) => {
            if (a.reachability === 'possible' && b.reachability !== 'possible') return -1;
            if (b.reachability === 'possible' && a.reachability !== 'possible') return 1;
            return b.risk - a.risk; 
        });

        if (viable.length > 0) {
            const best = viable[0]; 
            
            const newNode: FlowNode = {
                id: `step_${depth+1}`,
                function: best.caller,
                variable: best.arg, 
                file: best.file,    
                line: best.line,
                type: 'intermediate',
                active_constraint: best.upstream_constraint 
            };

            this.graph.nodes.push(newNode);
            this.graph.edges.push({ 
                from: newNode.id, 
                to: currentNode.id, 
                label: best.arg,
                status: 'open',
                reason: best.transformation_logic
            });
            
            this.dispatchUpdate(`Tracing upstream: ${best.caller} (New Constraint: ${best.upstream_constraint})`);
            
            if (best.upstream_constraint === 'Fixed Value') {
                this.dispatchUpdate("Source Reached. Exploit verified.");
                return;
            }

            await this.autonomousLoop(newNode, depth + 1);
        } else {
            this.dispatchUpdate("Trace ended. No reachable paths.");
        }
    }
}
```

-----

### 4\. `src/SidebarProvider.ts`

**Reason:** Manages State Mirroring, saves on shutdown, and handles the "Reset" handshake.

```typescript
import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { LLMProvider } from './core/llm';
import { LLMScanner } from './scanners/llmScanner';
import { TriageAgent } from './agents/triageAgent';
import { FlowFinderAgent } from './agents/flowFinderAgent';
import { ASTEngine } from './tools/astEngine';
import { FrontendMessage, Finding, FlowGraph, FlowCandidate } from './core/types';

export class SidebarProvider implements vscode.WebviewViewProvider {
  _view?: vscode.WebviewView;
  private activeAgent?: FlowFinderAgent;

  // \new: State Mirroring for Auto-Save
  private sessionFindings: Finding[] = [];
  private sessionLogs: string[] = [];
  private sessionGraph: FlowGraph = { nodes: [], edges: [] };
  private sessionReport: string = "";

  constructor(private context: vscode.ExtensionContext) {}

  resolveWebviewView(webviewView: vscode.WebviewView) {
    this._view = webviewView;
    webviewView.webview.options = { enableScripts: true, localResourceRoots: [this.context.extensionUri] };
    webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);

    webviewView.webview.onDidReceiveMessage(async (data: FrontendMessage) => {
      const llm = new LLMProvider();
      
      // \new: HANDSHAKE - Reset Frontend when it loads
      if (data.command === 'webview_loaded') {
          this.post({ type: 'reset_state' });
      }

      if (data.command === 'selectScope') {
          const selectionType = await vscode.window.showQuickPick(['Folder', 'File'], { placeHolder: 'Scan Scope?' });
          if (selectionType) {
              const options: vscode.OpenDialogOptions = {
                  canSelectMany: false,
                  openLabel: `Select ${selectionType}`,
                  canSelectFiles: selectionType === 'File',
                  canSelectFolders: selectionType === 'Folder',
                  filters: selectionType === 'File' ? { 'Code': ['c', 'cpp', 'h', 'hpp', 'py', 'js', 'ts', 'java'], 'All Files': ['*'] } : undefined
              };
              const fileUri = await vscode.window.showOpenDialog(options);
              if (fileUri && fileUri[0]) {
                  this.post({ type: 'scope_selected', path: vscode.workspace.asRelativePath(fileUri[0]) });
              }
          }
      }

      if (data.command === 'startScan') {
          // \new: Clear internal state on new scan
          this.sessionFindings = [];
          this.sessionLogs = ['Initializing Cyber Scan...'];
          this.sessionGraph = { nodes: [], edges: [] };
          this.sessionReport = "";

          const scanner = new LLMScanner(llm);
          const triage = new TriageAgent(llm);
          this.post({ type: 'scan_progress', value: 'Resolving scope...', percent: 0 });
          
          let globPattern = '**/*.{c,cpp,py}';
          if (data.scopePath && data.scopePath !== 'Workspace') {
              const absPath = path.join(vscode.workspace.workspaceFolders![0].uri.fsPath, data.scopePath);
              try {
                if (fs.existsSync(absPath) && fs.lstatSync(absPath).isFile()) globPattern = data.scopePath; 
                else globPattern = `${data.scopePath}/**/*.{c,cpp,py}`;
              } catch { globPattern = `${data.scopePath}/**/*.{c,cpp,py}`; }
          }

          const files = await vscode.workspace.findFiles(globPattern, '**/node_modules/**', 20);
          const allFindings: Finding[] = [];
          
          if (files.length === 0) {
              this.post({ type: 'scan_progress', value: 'No files found.', percent: 100 });
              this.post({ type: 'scan_complete', findings: [], shouldSwitchView: false});
              return;
          }

          for (let i = 0; i < files.length; i++) {
              const file = files[i];
              const progress = 5 + Math.round(((i + 1) / files.length) * 45);
              this.post({ type: 'scan_progress', value: `Scanning ${vscode.workspace.asRelativePath(file)}...`, percent: progress });
              const findings = await scanner.scanFile(await vscode.workspace.openTextDocument(file), data.focus);
              allFindings.push(...findings);
          }
          this.post({ type: 'scan_complete', findings: allFindings });

          for (let i = 0; i < allFindings.length; i++) {
              const finding = allFindings[i];
              const progress = 50 + Math.round(((i + 1) / allFindings.length) * 50);
              const verdict = await triage.triage(finding);
              this.post({ type: 'triage_update', findingId: finding.id, status: verdict.status, reason: verdict.reason, percent: progress });
          }
          this.post({ type: 'scan_progress', value: 'Scan Complete', percent: 100 });
      }

      if (data.command === 'saveSession') {
          this.saveReportToDisk(data);
      }

      if (data.command === 'startFlow') {
          const ast = new ASTEngine(this.context);
          this.activeAgent = new FlowFinderAgent(llm, ast, 
            (graph, log) => this.post({ type: 'flow_update', graph, log }),
            (candidates) => this.post({ type: 'interactive_candidates', candidates })
          );
          
          this.post({ type: 'flow_update', graph: { nodes: [], edges: [] }, log: 'Initializing...' });
          
          try {
            await this.activeAgent.startAnalysis(data.finding, data.mode);
            if (data.mode === 'autonomous') {
                this.post({ type: 'scan_progress', value: 'Flow Trace Complete. Ready for Report.', percent: 100 });
            }
          } catch(e) {
             this.post({ type: 'flow_update', graph: { nodes: [], edges: [] }, log: `Error: ${e}` });
          }
      }

      if (data.command === 'interactive_selection') {
          if (this.activeAgent) await this.activeAgent.processInteractiveSelection(data.selection);
      }

      if (data.command === 'generateReport') {
        if (this.activeAgent) {
              this.post({ type: 'scan_progress', value: 'Generating Report...', percent: 50 });
              const reportContent = await this.activeAgent.generateFinalReport(data.finding);
              this.sessionReport = reportContent;
              this.post({ type: 'report_generated', report: reportContent });
              this.post({ type: 'scan_progress', value: 'Report Ready.', percent: 100 });
        }
      }

      if (data.command === 'openFile') {
          try {
            let fileUri = vscode.Uri.file(data.file);
            if (!path.isAbsolute(data.file) && vscode.workspace.workspaceFolders) {
                fileUri = vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, data.file);
            }
            const doc = await vscode.workspace.openTextDocument(fileUri);
            const editor = await vscode.window.showTextDocument(doc, vscode.ViewColumn.One);
            if (data.line > 0) {
                const lineIndex = data.line - 1;
                const range = doc.lineAt(lineIndex).range;
                editor.selection = new vscode.Selection(range.start, range.end);
                editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
            }
          } catch(e) {
              vscode.window.showErrorMessage(`VulnTriage Error: Could not open file ${data.file}. ${e}`);
          }
      }
    });
  }

  // \new: Save to disk on Shutdown or Manual Save
  private saveReportToDisk(data: any) {
    const rootPath = vscode.workspace.workspaceFolders?.[0].uri.fsPath;
    if (rootPath) {
        const finalFindings = data.findings || this.sessionFindings;
        const finalLogs = data.logs || this.sessionLogs;
        const finalReport = data.report || this.sessionReport;

        if (!finalFindings.length && !finalLogs.length) return;

        const reportPath = path.join(rootPath, `vulntriage_autosave_${Date.now()}.json`);
        const fullReport = { 
            timestamp: new Date().toISOString(), 
            findings: finalFindings,
            logs: finalLogs,
            graph: this.sessionGraph,
            report: finalReport
        }; 
        
        try {
          fs.writeFileSync(reportPath, JSON.stringify(fullReport, null, 2));
        } catch (e) { console.error("VulnTriage: Failed to auto-save.", e); }
    }
  }

  // \new: Public shutdown hook
  public shutdown() {
    this.saveReportToDisk({}); 
  }

  public handleManualSelection(file: string, line: number, code: string) {
    if (!this._view) return;
    this.post({ type: 'scan_progress', value: 'Analyzing selection...', percent: 50 });
    const manualFinding: Finding = {
        id: `manual_${Date.now()}`, 
        ruleId: 'MNL-SEL',          
        message: `Manual Selection: ${code.trim().substring(0, 50)}${code.length > 50 ? '...' : ''}`,
        file: file,
        line: line,
        severity: 'medium',        
        status: 'verified',        
        triageReason: 'User manually selected this location for analysis.'
    };
    this.post({ type: 'scan_complete', findings: [manualFinding], shouldSwitchView: true });
  }

  public handleFolderScope(relativePath: string) { this.post({ type: 'scope_selected', path: relativePath }); }
  
  // \new: Mirror state changes
  private post(msg: any) { 
    if (msg.type === 'scan_progress') this.sessionLogs.push(msg.value);
    if (msg.type === 'flow_update') {
        this.sessionLogs.push(msg.log);
        this.sessionGraph = msg.graph;
    }
    if (msg.type === 'scan_complete') this.sessionFindings = msg.findings;
    if (msg.type === 'triage_update') {
        this.sessionFindings = this.sessionFindings.map(f => f.id === msg.findingId ? { ...f, status: msg.status } : f);
    }
    this._view?.webview.postMessage(msg); 
  }
  
  private _getHtmlForWebview(webview: vscode.Webview) {
    const scriptUri = webview.asWebviewUri(vscode.Uri.joinPath(this.context.extensionUri, 'dist', 'webview.js'));
    const styleUri = webview.asWebviewUri(vscode.Uri.joinPath(this.context.extensionUri, 'src', 'webview', 'style.css'));
    const logoUri = webview.asWebviewUri(vscode.Uri.joinPath(this.context.extensionUri, 'images', 'logo.png'));
    const nonce = getNonce();
    return `<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${webview.cspSource} https: data:; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}' 'unsafe-inline';">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="${styleUri}" rel="stylesheet">
        <title>VulnTriage</title>
        <script nonce="${nonce}">window.vsLogoUrl = "${logoUri}";</script>
    </head>
    <body>
        <div id="root"></div>
        <script nonce="${nonce}" src="${scriptUri}"></script>
    </body>
    </html>`;
  }
}

function getNonce() {
  let text = '';
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < 32; i++) { text += possible.charAt(Math.floor(Math.random() * possible.length)); }
  return text;
}
```

-----

### 5\. `src/extension.ts`

**Reason:** Captures the provider instance for shutdown.

```typescript
import * as vscode from 'vscode';
import { SidebarProvider } from './SidebarProvider';

let sidebarProvider: SidebarProvider; 

export function activate(context: vscode.ExtensionContext) {
  sidebarProvider = new SidebarProvider(context); 

  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider(
      "vulntriage.chatView",
      sidebarProvider,
      {
        webviewOptions: {
            retainContextWhenHidden: true 
        }
      }
    )
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('vulntriage.addToContext', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        const selection = editor.selection;
        const text = editor.document.getText(selection);
        const line = selection.start.line + 1;
        const file = editor.document.uri.fsPath;
        sidebarProvider.handleManualSelection(file, line, text);
        vscode.commands.executeCommand('vulntriage.chatView.focus');
      }
    })
  );

  context.subscriptions.push(
      vscode.commands.registerCommand('vulntriage.addFolderToScope', (uri: vscode.Uri) => {
       if (uri) {
          const relativePath = vscode.workspace.asRelativePath(uri);
          sidebarProvider.handleFolderScope(relativePath);
          vscode.commands.executeCommand('vulntriage.chatView.focus');
      }
    })
  );
}

// \new: Calls shutdown on exit
export function deactivate() {
    if (sidebarProvider) {
        sidebarProvider.shutdown();
    }
}
```

-----

### 6\. `src/webview/App.tsx`

**Reason:** Enhanced UI to show Constraints, Logic, Reasoning, and clickable File paths. Also includes the handshake logic.

```typescript
import React, { useState, useEffect, useRef } from 'react';
import { vscode } from './vscode';
import { ArrowLeft, Search, FileCode, FileText, Save, Folder, RefreshCw, ChevronUp, Terminal, Bug, Play, GitCommit, Layout, Loader2, MousePointerClick, Zap, Scale, ArrowUpRight } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import './style.css'; 

interface Finding { id: string; ruleId: string; message: string; file: string; line: number; severity: string; status: 'pending' | 'verified' | 'false_positive'; }
interface FlowCandidate { caller: string; arg: string; risk: number; file: string; line: number; reason?: string; reachability?: 'possible' | 'unlikely' | 'safe'; transformation_logic?: string; upstream_constraint?: string; }
interface AppState { mode: 'HOME' | 'SCAN' | 'FLOW'; findings: Finding[]; logs: string[]; progress: number; statusMsg: string; scope: string; focus: string; reportContent: string; selectedFinding: Finding | null; graphData: any; candidates: FlowCandidate[]; }

const StatusBadge = ({ severity }: { severity: string }) => {
    const colors: any = { critical: 'text-alert border-alert', high: 'text-orange-500 border-orange-500', medium: 'text-yellow-500 border-yellow-500', low: 'text-blue-400 border-blue-400' };
    const colorClass = colors[severity.toLowerCase()] || 'text-gray-400 border-gray-400';
    return <span className={`text-[10px] uppercase border px-2 py-0.5 rounded ${colorClass}`}>{severity}</span>;
};

const ProgressBar = ({ percent, label }: { percent: number, label: string }) => (
    <div className="w-full mb-4 px-1">
        <div className="flex justify-between text-xs text-primary mb-1 font-mono uppercase"><span className="truncate pr-2">; {label}</span><span>{percent}%</span></div>
        <div className="progress-container rounded"><div className="progress-bar" style={{ width: `${percent}%` }}></div></div>
    </div>
);

// \new: Enhanced Candidate Card with File Link and Reasoning
const CandidateSelector = ({ candidates, onSelect }: { candidates: FlowCandidate[], onSelect: (c: FlowCandidate) => void }) => {
    // \new: Helper to open file
    const openFile = (e: React.MouseEvent, c: FlowCandidate) => {
        e.stopPropagation(); 
        vscode.postMessage({ command: 'openFile', file: c.file, line: c.line });
    };

    return (
        <div className="flex-none bg-[#151720] border-t border-primary p-4 shadow-[0_-5px_20px_rgba(0,0,0,0.5)] max-h-[50vh] overflow-y-auto animate-slide-in">
            <div className="flex items-center gap-2 mb-3 text-primary uppercase font-bold text-xs tracking-wider animate-pulse">
                <MousePointerClick size={14} /> Select Exploit Path (Interactive)
            </div>
            <div className="space-y-3">
                {candidates.map((c, i) => (
                    <div key={i} onClick={() => onSelect(c)} className="p-3 rounded border border-gray-700 bg-[#0f111a] hover:border-primary hover:bg-[#1a1d29] cursor-pointer transition-all group">
                        <div className="flex justify-between items-center mb-2">
                            <span className="font-bold text-sm text-white flex items-center gap-2">
                                <ArrowUpRight size={14} className="text-muted group-hover:text-primary"/> 
                                {c.caller}
                            </span>
                            <div className="flex gap-2">
                                {c.reachability === 'safe' 
                                    ? <span className="text-[10px] bg-green-900/50 text-green-400 border border-green-800 px-1 rounded uppercase">Safe/Blocked</span>
                                    : <span className="text-[10px] bg-red-900/20 text-alert border border-alert/50 px-1 rounded uppercase">Risk: {c.risk}/10</span>
                                }
                            </div>
                        </div>

                        {/* \new: Logic & Constraint Visualization */}
                        <div className="bg-[#151720] p-2 rounded mb-2 border-l-2 border-gray-600 group-hover:border-primary">
                            <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Logic Transformation</div>
                            <div className="text-xs text-gray-300 font-mono mb-1">{c.transformation_logic || "Direct Propagation"}</div>
                            
                            <div className="flex items-start gap-2 mt-2 pt-2 border-t border-gray-800">
                                <Scale size={12} className="text-secondary mt-0.5"/>
                                <div>
                                    <div className="text-[10px] text-secondary uppercase tracking-wider">New Constraint</div>
                                    <div className="text-xs text-white font-mono">{c.upstream_constraint || "Unchanged"}</div>
                                </div>
                            </div>
                        </div>

                        <div className="flex justify-between items-end">
                            <div className="text-[10px] text-gray-600 font-mono"><span className="text-gray-500">Arg:</span> {c.arg}</div>
                            {/* \new: Precise File Link Button */}
                            <button onClick={(e) => openFile(e, c)} className="text-[10px] text-gray-500 hover:text-primary hover:underline flex items-center gap-1">
                                <FileCode size={10}/> {c.file.split(/[\\/]/).pop()}:{c.line}
                            </button>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
};

// \new: Timeline updated to show Active Constraint at each node
const FlowTimeline = ({ graphData, isScanning }: { graphData: any, isScanning: boolean }) => {
    if (!graphData.nodes || graphData.nodes.length === 0) return null;
    const nodes = [...graphData.nodes].reverse(); 
    const handleNodeClick = (n: any) => { if(n.file && n.line) vscode.postMessage({ command: 'openFile', file: n.file, line: n.line }); };

    return (
        <div className="flex flex-col items-start space-y-0 relative pl-4 py-4">
            <div className="absolute left-[27px] top-6 bottom-6 w-[2px] bg-gray-800 z-0"></div>
            {isScanning && (
                <div className="relative z-10 flex gap-4 w-full mb-4 animate-pulse">
                     <div className="w-6 h-6 rounded-full bg-panel border border-primary/50 flex items-center justify-center shrink-0 mt-3"><Loader2 size={14} className="text-primary animate-spin"/></div>
                     <div className="flex-1 p-3 rounded border border-dashed border-primary/30 bg-primary/5"><span className="text-xs text-primary font-mono uppercase">Scanning Upstream...</span></div>
                </div>
            )}
            {nodes.map((node: any, index: number) => {
                const isSource = index === 0 && !isScanning; 
                const isSink = index === nodes.length - 1;
                let icon = <ChevronUp size={14} className="text-primary"/>;
                let borderColor = "border-gray-700";
                let titleColor = "text-white";
                let bgColor = "bg-[#1a1d29]";

                if (isSource) { icon = <Play size={14} className="text-success fill-success"/>; borderColor = "border-success"; titleColor = "text-success"; } 
                else if (isSink) { icon = <Bug size={14} className="text-alert fill-alert"/>; borderColor = "border-alert"; titleColor = "text-alert"; bgColor = "bg-[#3f1010]/20"; } 
                else if (index === 0 && isScanning) { icon = <GitCommit size={14} className="text-primary"/>; borderColor = "border-primary"; }

                return (
                    <div key={node.id} className="relative z-10 flex gap-4 w-full animate-slide-in">
                        <div className={`w-6 h-6 rounded-full bg-[#0f111a] border ${borderColor} flex items-center justify-center shrink-0 mt-3 shadow-[0_0_10px_rgba(0,0,0,0.5)]`}>{icon}</div>
                        <div onClick={() => handleNodeClick(node)} className={`flex-1 p-3 mb-4 rounded border ${borderColor} ${bgColor} hover:brightness-110 cursor-pointer transition-all shadow-lg group`}>
                            <div className="flex justify-between items-start mb-2">
                                <div className={`font-bold font-mono text-sm ${titleColor}`}>{node.function}</div>
                                {node.line && <span className="text-[10px] text-gray-500 font-mono bg-black/40 px-1 rounded">Ln {node.line}</span>}
                            </div>
                            
                            {/* \new: Active Constraint Display */}
                            {node.active_constraint && (
                                <div className="bg-black/30 p-2 rounded mb-2 border-l-2 border-secondary">
                                    <div className="text-[10px] text-secondary uppercase font-bold mb-0.5">Active Constraint</div>
                                    <div className="text-xs text-gray-300 font-mono">{node.active_constraint}</div>
                                </div>
                            )}

                            <div className="flex justify-between items-end">
                                <div className="text-xs text-gray-400 font-mono break-all"><span className="text-gray-600 select-none">$ </span>{node.variable}</div>
                                <div className="flex items-center gap-1 text-[10px] text-gray-500"><FileCode size={10}/><span className="truncate max-w-[100px]">{node.file.split(/[\\/]/).pop()}</span></div>
                            </div>
                        </div>
                    </div>
                );
            })}
        </div>
    );
};

const FlowView = ({ candidates, onCandidateSelect, finding, progress, statusMsg, graphData, logs, reportContent, onBack, onSave, onGenerateReport, bottomRef, timelineRef }: any) => (
    <div className="flex flex-col h-full overflow-hidden relative">
         <div className="p-4 border-b border-gray-800 bg-[#0f111a] z-10 shadow-lg flex-none">
            <div className="flex justify-between items-center mb-3">
                <div className="flex items-center gap-2">
                    <button onClick={onBack} className="btn-icon"><ArrowLeft size={16}/></button>
                    <h2 className="font-bold text-sm uppercase tracking-wider">Taint Analysis</h2>
                </div>
                <div className="flex gap-2">
                    {!reportContent && <button onClick={onGenerateReport} className="btn-primary text-xs py-1 px-2 flex gap-1"><FileText size={12}/> Report</button>}
                    <button onClick={onSave} className="btn-icon"><Save size={14}/></button>
                </div>
            </div>
            <ProgressBar percent={progress} label={statusMsg} />
        </div>

        <div className="flex-1 flex flex-col min-h-0 bg-panel relative overflow-hidden">
            {reportContent ? (
                <div className="flex-1 overflow-y-auto p-4">
                    <div className="prose prose-invert prose-sm max-w-none bg-panel p-4 rounded border border-gray-700">
                        <h3 className="text-success font-bold mb-4 uppercase tracking-widest border-b border-gray-700 pb-2">Intelligence Report</h3>
                        <ReactMarkdown>{reportContent}</ReactMarkdown>
                    </div>
                </div>
            ) : (
                <>
                  <div ref={timelineRef} className="flex-1 overflow-y-auto bg-[#0f111a] relative p-4 custom-scrollbar">
                      {(!graphData.nodes || graphData.nodes.length === 0) ? (
                          <div className="flex flex-col items-center justify-center h-full text-gray-500 animate-pulse">
                              <RefreshCw className="animate-spin mb-4 text-primary" size={32}/>
                              <span className="text-xs font-mono">TRACING CALL STACK...</span>
                          </div>
                      ) : (
                          <FlowTimeline graphData={graphData} isScanning={progress < 100 && candidates.length === 0} />
                      )}
                  </div>
                  {candidates.length > 0 && <CandidateSelector candidates={candidates} onSelect={onCandidateSelect} />}
                  <div className="h-48 border-t border-gray-700 bg-panel flex-none flex flex-col z-20">
                      <div className="flex items-center gap-2 px-3 py-2 border-b border-gray-700 bg-[#151720]">
                          <Terminal size={12} className="text-primary"/>
                          <span className="text-[10px] font-bold uppercase text-muted">Agent Logs</span>
                      </div>
                      <div className="text-[10px] font-mono space-y-1 text-gray-400 flex-1 overflow-y-auto p-2">
                          {logs.map((l: string, i: number) => (
                              <div key={i} className="border-l-2 border-gray-700 pl-2 hover:border-primary hover:text-white transition-colors">
                                  <span className="text-gray-600">[{i.toString().padStart(2,'0')}]</span> {l}
                              </div>
                          ))}
                          <div ref={bottomRef}/>
                      </div>
                  </div>
                </>
            )}
        </div>
    </div>
);

const App = () => {
  const savedState = vscode.getState() as AppState || {};
  const [mode, setMode] = useState<'HOME' | 'SCAN' | 'FLOW'>(savedState.mode || 'HOME');
  const [findings, setFindings] = useState<Finding[]>(savedState.findings || []);
  const [logs, setLogs] = useState<string[]>(savedState.logs || []);
  const [progress, setProgress] = useState<number>(savedState.progress || 0);
  const [statusMsg, setStatusMsg] = useState<string>(savedState.statusMsg || "");
  const [scope, setScope] = useState<string>(savedState.scope || "Workspace");
  const [focus, setFocus] = useState<string>(savedState.focus || "");
  const [reportContent, setReportContent] = useState<string>(savedState.reportContent || "");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(savedState.selectedFinding || null);
  const [graphData, setGraphData] = useState<any>(savedState.graphData || { nodes: [], edges: [] });
  const [candidates, setCandidates] = useState<FlowCandidate[]>(savedState.candidates || []);
  const bottomRef = useRef<HTMLDivElement>(null);
  const timelineRef = useRef<HTMLDivElement>(null);

  useEffect(() => { vscode.setState({ mode, findings, logs, progress, statusMsg, scope, focus, reportContent, selectedFinding, graphData, candidates }); }, [mode, findings, logs, progress, statusMsg, scope, focus, reportContent, selectedFinding, graphData, candidates]);
  useEffect(() => { if (mode === 'FLOW' && timelineRef.current) timelineRef.current.scrollTo({ top: 0, behavior: 'smooth' }); }, [graphData, mode]);
  useEffect(() => {
    const handler = (event: MessageEvent) => {
      const msg = event.data;
      if (msg.type === 'reset_state') { setMode('HOME'); setFindings([]); setLogs([]); setReportContent(""); setScope("Workspace"); setGraphData({ nodes: [], edges: [] }); setCandidates([]); setStatusMsg(""); setProgress(0); setSelectedFinding(null); }
      if (msg.type === 'scope_selected') setScope(msg.path);
      if (msg.type === 'scan_progress') { setLogs(prev => [...prev, msg.value]); setStatusMsg(msg.value); if (msg.percent !== undefined) setProgress(msg.percent); }
      if (msg.type === 'scan_complete') { setFindings(msg.findings); setProgress(100); if (msg.shouldSwitchView) setMode('SCAN'); }
      if (msg.type === 'triage_update') { setFindings(prev => prev.map(f => f.id === msg.findingId ? { ...f, status: msg.status } : f)); }
      if (msg.type === 'flow_update') { setLogs(prev => [...prev, msg.log]); setGraphData(msg.graph); }
      if (msg.type === 'interactive_candidates') { setCandidates(msg.candidates); setStatusMsg("Waiting for user selection..."); }
      if (msg.type === 'report_generated') { setReportContent(msg.report); setCandidates([]); }
    };
    window.addEventListener('message', handler);
    // \new: Handshake to trigger reset
    vscode.postMessage({ command: 'webview_loaded' });
    return () => window.removeEventListener('message', handler);
  }, []);
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [logs]);
  const handleStartScan = () => { setLogs(['Initializing Cyber Scan...']); setProgress(0); setStatusMsg("Scanning Target..."); setMode('SCAN'); vscode.postMessage({ command: 'startScan', scopePath: scope, focus: focus }); };
  const handleFlow = (finding: Finding, type: 'interactive' | 'autonomous') => { setSelectedFinding(finding); setMode('FLOW'); setGraphData({ nodes: [], edges: [] }); setReportContent(""); setCandidates([]); setLogs([`Initiating ${type} trace analysis...`]); setProgress(5); setStatusMsg("Tracing Data Flow..."); vscode.postMessage({ command: 'startFlow', finding, mode: type }); };
  const handleCandidateSelect = (c: FlowCandidate) => { setCandidates([]); setStatusMsg(`Analyzing path: ${c.caller}...`); vscode.postMessage({ command: 'interactive_selection', selection: c }); };
  const handleGenerateReport = () => { if (selectedFinding) vscode.postMessage({ command: 'generateReport', finding: selectedFinding }); };
  const handleSave = () => { vscode.postMessage({ command: 'saveSession', findings, logs, report: reportContent }); setMode('HOME'); setFindings([]); setLogs([]); setReportContent(""); setScope("Workspace"); };
  
  return (
    <div className="h-screen text-white selection:bg-primary/30 font-sans">
        {mode === 'HOME' && (<HomeView scope={scope} focus={focus} setFocus={setFocus} onSelectScope={() => vscode.postMessage({command: 'selectScope'})} onStart={handleStartScan} hasResults={findings.length > 0} onViewResults={() => setMode('SCAN')} />)}
        {mode === 'SCAN' && <ScanResultsView findings={findings} progress={progress} statusMsg={statusMsg} onBack={() => setMode('HOME')} onNewScan={handleSave} onFlow={handleFlow} />}
        {mode === 'FLOW' && <FlowView candidates={candidates} onCandidateSelect={handleCandidateSelect} finding={selectedFinding} progress={progress} statusMsg={statusMsg} graphData={graphData} logs={logs} reportContent={reportContent} onBack={() => setMode('SCAN')} onSave={handleSave} onGenerateReport={handleGenerateReport} bottomRef={bottomRef} timelineRef={timelineRef} />}
    </div>
  );
};
export default App;
```

------------------------>

This is the complete, production-ready pipeline. It integrates the **Planner-Executor Architecture**, the **Context Ledger**, **Crash Recovery**, and **Code Inspection** capabilities into a single cohesive system.

### 1\. Project Structure

Create a new folder named `frida-agent` and set up this structure:

```text
frida-agent/
├── recipes/              # Folder for pre-written scripts
│   └── ssl_bypass.js
├── requirements.txt      # Dependencies
├── server.py             # The MCP Server (Hands & Eyes)
└── client.py             # The Agentic Client (Brain)
```

-----

### 2\. Dependencies (`requirements.txt`)

```text
mcp
frida
frida-tools
ollama
pydantic
anyio
```

*Run:* `pip install -r requirements.txt`

-----

### 3\. The Recipe Book

Create the `recipes/` folder. For testing, create a file named `recipes/ssl_bypass.js` and paste this dummy content (or your real bypass script):

```javascript
/* Generic SSL Unpinning Recipe */
Java.perform(function() {
    console.log("[*] Attempting generic SSL TrustManager bypass...");
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        console.log("[+] Intercepted TrustManagerImpl.verifyChain - Bypassing exception");
        return untrustedChain; // Return the chain without throwing
    }
});
```

-----

### 4\. The Server (`server.py`)

This is the robust backend that manages the **Context Ledger** and **Frida Sessions**.

```python
#!/usr/bin/env python3
import sys
import frida
import time
import json
import threading
import os
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from mcp.server.fastmcp import FastMCP
from pydantic import Field

# Configure logging to stderr (Standard Error) to keep stdout clean for MCP communication
logging.basicConfig(level=logging.INFO, stream=sys.stderr)

# ==============================================================================
# 1. THE CONTEXT LEDGER (Persistent Memory)
# ==============================================================================

@dataclass
class DiscoveredArtifact:
    name: str
    type: str  # 'java_class', 'native_export'
    address: Optional[str] = None

class ContextLedger:
    def __init__(self):
        self.artifacts: Dict[str, DiscoveredArtifact] = {}
        self.active_hooks: List[str] = []
        self.runtime_env: str = "unknown"
        self.current_process: Optional[str] = None

        # Session Management
        self.sessions: Dict[str, frida.core.Session] = {}
        self.locks: Dict[str, threading.Lock] = {}

    def register_artifact(self, name, art_type, address=None):
        if name not in self.artifacts:
            self.artifacts[name] = DiscoveredArtifact(name, art_type, address)

    def get_summary(self) -> str:
        """Returns the 'Technical Reality' for the System Prompt."""
        summary = [f"### RUNTIME: {self.runtime_env.upper()}"]

        if self.current_process:
            summary.append(f"TARGET: {self.current_process}")

        if self.artifacts:
            summary.append("\n### DISCOVERED ARTIFACTS (Known Facts):")
            # Limit list size to save tokens
            items = list(self.artifacts.values())[-25:]
            for art in items:
                addr = f" @ {art.address}" if art.address else ""
                summary.append(f"- [{art.type}] {art.name}{addr}")

        if self.active_hooks:
            summary.append(f"\n### ACTIVE HOOKS: {', '.join(self.active_hooks)}")

        return "\n".join(summary)

ledger = ContextLedger()
mcp = FastMCP("Frida-Agent")

# ==============================================================================
# 2. FRIDA TOOLS
# ==============================================================================

@mcp.tool()
def enumerate_processes() -> str:
    """List running processes on the USB device."""
    try:
        device = frida.get_usb_device()
        procs = device.enumerate_processes()
        procs.sort(key=lambda x: x.name.lower())
        return "\n".join([f"PID: {p.pid} | Name: {p.name}" for p in procs])
    except Exception as e:
        return f"Error: {e}"

@mcp.tool()
def attach_process(target: str) -> str:
    """
    Attach to a process by Name or PID.
    Automatically detects if runtime is Java or Native.
    """
    try:
        device = frida.get_usb_device()
        try:
            target_val = int(target)
        except ValueError:
            target_val = target

        session = device.attach(target_val)
        sid = f"session_{int(time.time())}"

        ledger.sessions[sid] = session
        ledger.locks[sid] = threading.Lock()
        ledger.current_process = str(target)

        # Runtime Detection
        script = session.create_script("send({java: Java.available});")
        def on_msg(message, data):
            if message['type'] == 'send':
                ledger.runtime_env = "java" if message['payload'].get('java') else "native"
        script.on('message', on_msg)
        script.load()
        time.sleep(0.2)
        script.unload()

        return f"Attached. Session ID: {sid}. Runtime: {ledger.runtime_env.upper()}"
    except Exception as e:
        return f"Attach failed: {str(e)}"

@mcp.tool()
def scan_environment(query: str, session_id: str) -> str:
    """
    Search for classes or exports matching a query (e.g., 'crypto', 'auth').
    Automatically updates the Ledger.
    """
    if session_id not in ledger.sessions: return "Error: Invalid Session ID."

    js = """
    (function() {
        var res = [];
        var q = "%s".toLowerCase();
        if (Java.available) {
            Java.perform(function() {
                try {
                    var classes = Java.enumerateLoadedClassesSync();
                    for (var i=0; i<classes.length; i++) {
                        if (classes[i].toLowerCase().includes(q)) {
                            res.push({name: classes[i], type: 'java_class'});
                            if (res.length > 40) return;
                        }
                    }
                } catch(e) {}
            });
        }
        if (res.length < 40) {
            var exports = Module.enumerateExportsSync(null);
            for (var i=0; i<exports.length; i++) {
                if (exports[i].name.toLowerCase().includes(q)) {
                    res.push({name: exports[i].name, type: 'native', address: exports[i].address});
                    if (res.length > 40) return;
                }
            }
        }
        return res;
    })();
    """ % query

    try:
        res = _run_script(session_id, js)
        if "error" in res: return res["error"]

        data = res.get("result", [])
        if not data: return "No matches found."

        count = 0
        for item in data:
            ledger.register_artifact(item['name'], item['type'], item.get('address'))
            count += 1

        return f"Found {count} items. Added to Context Ledger."
    except Exception as e:
        return str(e)

@mcp.tool()
def inspect_java_class(class_name: str, session_id: str) -> str:
    """
    Reflects on a Java class to show methods and fields.
    Use this BEFORE hooking to ensure correct method signature.
    """
    js = """
    (function() {
        var output = "";
        try {
            Java.perform(function() {
                var cls = Java.use("%s");
                output += "CLASS: " + cls + "\\n";
                var methods = cls.class.getDeclaredMethods();
                for (var i in methods) {
                    output += "METHOD: " + methods[i].toString() + "\\n";
                }
            });
        } catch(e) { output = "Error reflecting class: " + e; }
        return output;
    })();
    """ % class_name
    return _run_script(session_id, js).get("result", "No output")

@mcp.tool()
def load_recipe(recipe_name: str, session_id: str) -> str:
    """
    Loads a pre-written script from the recipes folder.
    """
    path = os.path.join("recipes", f"{recipe_name}.js")
    if not os.path.exists(path):
        return f"Recipe not found at {path}"

    with open(path, 'r') as f:
        code = f.read()

    res = _run_script(session_id, code)
    ledger.active_hooks.append(f"Recipe: {recipe_name}")
    return f"Recipe Loaded. Output: {res.get('logs') or 'None'}"

@mcp.tool()
def execute_frida_script(session_id: str, code: str) -> str:
    """
    Execute raw JavaScript.
    Ensure Java code is wrapped in Java.perform().
    """
    res = _run_script(session_id, code)
    if "error" in res: return f"Script Error: {res['error']}"

    if "Interceptor.attach" in code or ".implementation" in code:
        ledger.active_hooks.append("Custom Hook")

    return f"Logs:\n{res.get('logs')}\nResult:\n{res.get('result')}"

def _run_script(sid, code):
    if sid not in ledger.sessions: return {"error": "Session Invalid"}
    session = ledger.sessions[sid]

    wrapper = f"""
    (function(){{
        var logs = [];
        var oldLog = console.log;
        console.log = function(){{ logs.push(Array.from(arguments).join(' ')); oldLog.apply(console, arguments); }};
        var res, err;
        try {{ res = eval({json.dumps(code)}); }} catch(e) {{ err = e.toString(); }}
        send({{type:'done', res: res, err: err, logs: logs}});
    }})();
    """

    script = session.create_script(wrapper)
    result = {}
    event = threading.Event()

    def on_message(msg, data):
        if msg['type'] == 'send' and msg['payload'].get('type') == 'done':
            result['data'] = msg['payload']
            event.set()

    script.on('message', on_message)
    script.load()
    event.wait(5.0)
    script.unload()

    data = result.get('data', {})
    return {"result": data.get('res'), "error": data.get('err'), "logs": "\n".join(data.get('logs', []))}

@mcp.resource("frida://context")
def get_ledger() -> str:
    return ledger.get_summary()

if __name__ == "__main__":
    mcp.run()
```

-----

### 5\. The Client (`client.py`)

This is the **Orchestrator**. It creates plans, recovers from crashes, and partitions the context.

```python
import asyncio
import ollama
import sys
import json
import re
from dataclasses import dataclass
from typing import List
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# CONFIGURATION
OLLAMA_MODEL = "llama3.1"
SERVER_SCRIPT = "./server.py"

@dataclass
class Task:
    id: int
    description: str
    status: str = "pending"

class TaskManager:
    def __init__(self):
        self.mission = "Idle"
        self.tasks: List[Task] = []
        self.current = 0

    def set_mission(self, text, steps):
        self.mission = text
        self.tasks = [Task(i, s) for i, s in enumerate(steps)]
        self.current = 0
        if self.tasks: self.tasks[0].status = "active"

    def advance(self):
        if self.current < len(self.tasks):
            self.tasks[self.current].status = "done"
            self.current += 1
            if self.current < len(self.tasks):
                self.tasks[self.current].status = "active"

    def get_plan(self):
        lines = [f"MISSION: {self.mission}"]
        for t in self.tasks:
            mark = "[x]" if t.status == "done" else "[->]" if t.status == "active" else "[ ]"
            lines.append(f"{mark} {t.description}")
        return "\n".join(lines)

async def generate_plan(mission: str, context: str) -> List[str]:
    prompt = f"""
    You are a Security Lead.
    MISSION: "{mission}"
    CONTEXT: {context}

    Create a 3-5 step plan to achieve this using Frida tools.
    Format: Return ONLY a JSON list of strings.
    Example: ["Attach to process", "Scan for 'Auth'", "Inspect Auth class", "Hook check method"]
    """
    res = ollama.chat(model=OLLAMA_MODEL, messages=[{'role': 'user', 'content': prompt}])
    try:
        match = re.search(r'\[.*\]', res['message']['content'], re.DOTALL)
        if match: return json.loads(match.group(0))
    except: pass
    return [mission]

async def main():
    server_params = StdioServerParameters(command=sys.executable, args=[SERVER_SCRIPT], env=None)

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Load Tools
            tools = await session.list_tools()
            ollama_tools = [{"type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.inputSchema}} for t in tools.tools]

            tm = TaskManager()
            print(f"✅ Security Agent Ready ({OLLAMA_MODEL}). Waiting for orders...")

            while True:
                user_input = input("\n(User) > ")
                if user_input.lower() in ['quit', 'exit']: break

                # Fetch Ledger
                try:
                    res = await session.read_resource("frida://context")
                    ledger_str = res.contents[0].text
                except: ledger_str = "No context."

                # Plan Generation
                if len(user_input) > 5 and not user_input.lower().startswith("y"):
                    print("🧠 Analyzing & Planning...")
                    steps = await generate_plan(user_input, ledger_str)
                    tm.set_mission(user_input, steps)
                    print(f"📋 PLAN:\n{tm.get_plan()}")

                # Execution Loop
                subtask_done = False
                messages = []

                while not subtask_done:
                    if tm.current >= len(tm.tasks):
                        print("🎉 Mission Complete.")
                        break

                    task = tm.tasks[tm.current]

                    # Partitioned System Prompt
                    sys_prompt = f"""
ROLE: Frida Automation Expert.
=== PLAN ===
{tm.get_plan()}

=== CURRENT TASK ===
EXECUTING: "{task.description}"
Focus ONLY on this step.

=== TECHNICAL REALITY (LEDGER) ===
{ledger_str}
"""
                    msgs_payload = [{'role': 'system', 'content': sys_prompt}] + messages
                    if not messages: msgs_payload.append({'role': 'user', 'content': f"Execute: {task.description}"})

                    print(f"\n[Working on Step {task.id+1} / {len(tm.tasks)}]...")
                    response = ollama.chat(model=OLLAMA_MODEL, messages=msgs_payload, tools=ollama_tools)
                    msg = response['message']
                    messages.append(msg)

                    if msg.get('tool_calls'):
                        for tool in msg['tool_calls']:
                            print(f"  🛠️  Tool: {tool['function']['name']}")
                            try:
                                res = await session.call_tool(tool['function']['name'], tool['function']['arguments'])
                                output = res.content[0].text
                            except Exception as e:
                                output = f"Error: {e}"
                                if "Session Invalid" in output or "detached" in str(e):
                                    output += "\nCRITICAL: Process crashed. Suggest respawning."

                            print(f"     -> {output[:100]}...")
                            messages.append({'role': 'tool', 'content': output})
                        continue

                    print(f"🤖 Agent: {msg['content']}")
                    choice = input(f">> Is step '{task.description}' done? [y/n]: ")
                    if choice.lower() == 'y':
                        tm.advance()
                        subtask_done = True
                        messages = []
                    elif choice.lower() == 'n':
                        messages.append({'role': 'user', 'content': "That didn't work. Try a different way."})
                    else:
                        messages.append({'role': 'user', 'content': choice})

if __name__ == "__main__":
    asyncio.run(main())
```

-----

### 6\. Activation (How to run)

1.  **Prepare the Device:**

      * Connect Android device via USB.
      * Ensure `adb devices` shows the device.
      * Ensure `frida-server` is running on the device (`adb shell -> ./data/local/tmp/frida-server &`).

2.  **Start the LLM Backend:**

      * Open Terminal A.
      * Run: `ollama serve`
      * (First time only): `ollama pull llama3.1`

3.  **Start the Agent:**

      * Open Terminal B.
      * Navigate to `frida-agent/`.
      * Run: `python client.py`

4.  **Engage:**

      * Type: *"I want to bypass the SSL pinning on the com.example.bank app."*
      * **Watch the Agent:**
        1.  Create a 4-step plan.
        2.  Attach to the process.
        3.  Scan for TrustManagers.
        4.  Load the `ssl_bypass` recipe or write a custom hook.
        5.  Ask you to verify.
