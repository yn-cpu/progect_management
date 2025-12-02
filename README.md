#.vscode\launch.json
{
	"version": "0.2.0",
	"configurations": [
		{
			"name": "Run Extension",
			"type": "extensionHost",
			"request": "launch",
			"runtimeExecutable": "${execPath}",
			"args": [
				"--extensionDevelopmentPath=${workspaceFolder}"
			],
			"outFiles": [
				"${workspaceFolder}/dist/**/*.js"
			],
			"preLaunchTask": "npm: compile"
		}
	]
}
#.vscode\tasks.json
{
	"version": "2.0.0",
	"tasks": [
		{
			"type": "npm",
			"script": "compile",
			"group": {
				"kind": "build",
				"isDefault": true
			},
			"problemMatcher": [
				"$ts-loader",
				"$eslint-compact"
			],
			"label": "npm: compile",
			"detail": "compile extension"
		},
		{
			"type": "npm",
			"script": "watch",
			"group": "build",
			"problemMatcher": "$ts-loader",
			"label": "npm: watch",
			"isBackground": true,
			"presentation": {
				"reveal": "never"
			}
		}
	]
}
#src\extension.ts
import * as vscode from 'vscode';
import { SidebarProvider } from './SidebarProvider';

export function activate(context: vscode.ExtensionContext) {
  const sidebarProvider = new SidebarProvider(context);

  // Register Webview with "retainContextWhenHidden"
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

  // Command: Select Text in Editor
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

  // Command: Select Folder in Explorer
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

export function deactivate() {}
#src\SidebarProvider.ts
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

  constructor(private context: vscode.ExtensionContext) {}

  resolveWebviewView(webviewView: vscode.WebviewView) {
    this._view = webviewView;
    webviewView.webview.options = { enableScripts: true, localResourceRoots: [this.context.extensionUri] };
    webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);

    webviewView.webview.onDidReceiveMessage(async (data: FrontendMessage) => {
      
      // --- ROBUST SCOPE SELECTION ---
      if (data.command === 'selectScope') {
          const selectionType = await vscode.window.showQuickPick(['Folder', 'File'], {
              placeHolder: 'Do you want to scan a specific File or a whole Folder?'
          });

          if (selectionType) {
              const options: vscode.OpenDialogOptions = {
                  canSelectMany: false,
                  openLabel: `Select ${selectionType}`,
                  canSelectFiles: selectionType === 'File',
                  canSelectFolders: selectionType === 'Folder',
                  filters: selectionType === 'File' ? { 
                      'Code': ['c', 'cpp', 'h', 'hpp', 'py', 'js', 'ts', 'java'],
                      'All Files': ['*'] 
                  } : undefined
              };

              const fileUri = await vscode.window.showOpenDialog(options);
              if (fileUri && fileUri[0]) {
                  this.post({ type: 'scope_selected', path: vscode.workspace.asRelativePath(fileUri[0]) });
              }
          }
      }

      if (data.command === 'startScan') {
          const llm = new LLMProvider(data.llmConfig);
          const scanner = new LLMScanner(llm);
          const triage = new TriageAgent(llm);
          this.post({ type: 'scan_progress', value: 'Resolving scope...', percent: 0 });
          
          let globPattern = '**/*.{c,cpp,py}';
          if (data.scopePath && data.scopePath !== 'Workspace') {
              const absPath = path.join(vscode.workspace.workspaceFolders![0].uri.fsPath, data.scopePath);
              if (fs.existsSync(absPath) && fs.lstatSync(absPath).isFile()) {
                  globPattern = data.scopePath; 
              } else {
                  globPattern = `${data.scopePath}/**/*.{c,cpp,py}`; 
              }
          }

          const files = await vscode.workspace.findFiles(globPattern, '**/node_modules/**', 20);
          const allFindings: Finding[] = [];
          
          if (files.length === 0) {
              this.post({ type: 'scan_progress', value: 'No files found.', percent: 100 });
              this.post({ type: 'scan_complete', findings: allFindings, shouldSwitchView: false});
              return;
          }

          for (let i = 0; i < files.length; i++) {
              const file = files[i];
              const progress = 5 + Math.round(((i + 1) / files.length) * 45);
              this.post({ type: 'scan_progress', value: `Scanning ${vscode.workspace.asRelativePath(file)}...`, percent: progress });
              const findings = await scanner.scanFile(await vscode.workspace.openTextDocument(file), data.focus);
              
              // UPDATE: Check for critical configuration errors immediately
              if (findings.some(f => f.ruleId === 'CONFIG-ERR')) {
                  allFindings.push(...findings);
                  this.post({ type: 'scan_complete', findings: allFindings, shouldSwitchView: true });
                  this.post({ type: 'scan_progress', value: 'Scan Failed (Auth/Net Error)', percent: 100 });
                  return; // Stop scanning
              }

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
          const rootPath = vscode.workspace.workspaceFolders?.[0].uri.fsPath;
          if (rootPath) {
              const reportPath = path.join(rootPath, `vulntriage_report_${Date.now()}.json`);
              const fullReport = { timestamp: new Date().toISOString(), ...data }; 
              fs.writeFile(reportPath, JSON.stringify(fullReport, null, 2), (err) => {
                  if (!err) vscode.window.showInformationMessage(`Report saved: ${path.basename(reportPath)}`);
              });
          }
      }

      if (data.command === 'startFlow') {
          const llm = new LLMProvider(data.llmConfig);
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
          if (this.activeAgent) {
              await this.activeAgent.processInteractiveSelection(data.selection);
          }
      }

      if (data.command === 'generateReport') {
        if (this.activeAgent) {
              this.post({ type: 'scan_progress', value: 'Generating Report...', percent: 50 });
              const reportContent = await this.activeAgent.generateFinalReport(data.finding);
              this.post({ type: 'report_generated', report: reportContent });
              this.post({ type: 'scan_progress', value: 'Report Ready.', percent: 100 });

              const rootPath = vscode.workspace.workspaceFolders?.[0].uri.fsPath;
              if (rootPath) {
                  const agentData = this.activeAgent.getSessionData();
                  const savePayload = {
                      timestamp: new Date().toISOString(),
                      security_issue: { ruleId: data.finding.ruleId, severity: data.finding.severity, file: data.finding.file, line: data.finding.line, message: data.finding.message },
                      starting_point: { file: data.finding.file, line: data.finding.line, function: agentData.graph.nodes[0]?.function || "Unknown" },
                      agent_summary: reportContent,
                      flow_trace_log: agentData.traceHistory,
                      full_graph_data: agentData.graph
                  };
                  const filename = `vulntriage_report_${data.finding.ruleId}_${Date.now()}.json`;
                  const reportPath = path.join(rootPath, filename);
                  fs.writeFile(reportPath, JSON.stringify(savePayload, null, 2), (err) => {
                      if (!err) vscode.window.showInformationMessage(`Full Report saved to: ${filename}`);
                  });
              }
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

 public handleManualSelection(file: string, line: number, code: string) {
    if (!this._view) return;
    this.post({ type: 'scan_progress', value: 'Analyzing selection...', percent: 50 });
    const manualFinding: Finding = {
        id: `manual_${Date.now()}`, ruleId: 'MNL-SEL', message: `Manual Selection: ${code.trim().substring(0, 50)}${code.length > 50 ? '...' : ''}`,
        file: file, line: line, severity: 'medium', status: 'verified', triageReason: 'User manually selected this location for analysis.'
    };
    this.post({ type: 'scan_complete', findings: [manualFinding], shouldSwitchView: true });
  }

  public handleFolderScope(relativePath: string) { this.post({ type: 'scope_selected', path: relativePath }); }
  private post(msg: any) { this._view?.webview.postMessage(msg); }
  
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
#src\agents\flowFinderAgent.ts
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

    public getSessionData() {
        return { graph: this.graph, traceHistory: this.history };
    }

    // PHASE 1: BUILD THE GRAPH
    async startAnalysis(finding: Finding, mode: 'interactive' | 'autonomous') {
        this.graph = { nodes: [], edges: [] }; 
        this.history = [];
        
        // 1. Setup Sink Node
        const sinkNode: FlowNode = {
            id: `step_0`,
            function: 'Sink',
            variable: 'UNKNOWN', 
            file: finding.file,
            line: finding.line,
            type: 'sink'
        };
        this.graph.nodes.push(sinkNode);
        this.currentNodeId = sinkNode.id;
        
        // Initialize AST
        const ext = path.extname(finding.file).substring(1);
        await this.ast.init(ext || 'c');

        try {
            const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(finding.file));
            const funcName = this.ast.getFunctionName(this.ast.getFunctionAtLine(doc.getText(), finding.line) || "") || "unknown";
            
            sinkNode.function = funcName;
            this.history.push(`Sink: ${funcName} in ${finding.file} at line ${finding.line}`);
            this.dispatchUpdate(`Identified Sink Function: ${funcName}`);
        } catch (e) {
            this.dispatchUpdate(`Error reading sink file: ${e}`);
        }

        if (mode === 'autonomous') {
            await this.autonomousLoop(sinkNode, 0);
        } else {
            // Interactive: Just find candidates for the Sink and stop
            this.dispatchUpdate(`Interactive Mode: Analyzing callers for ${sinkNode.function}...`);
            const candidates = await this.calculateCandidates(sinkNode);
            if (candidates.length === 0) {
                this.dispatchUpdate("No callers found. Trace ends here.");
                this.sendCandidates([]); // Empty list signals end
            } else {
                this.dispatchUpdate(`Found ${candidates.length} potential paths. Waiting for user selection...`);
                // Sort by risk so they look nice in UI
                this.sendCandidates(candidates.sort((a,b) => b.risk - a.risk));
            }
        }
    }

    // Called by SidebarProvider when Frontend sends 'interactive_selection'
    public async processInteractiveSelection(selection: FlowCandidate) {
        // 1. Convert Candidate to Node
        const depth = this.graph.nodes.length;
        const newNode: FlowNode = {
            id: `step_${depth}`,
            function: selection.caller,
            variable: selection.arg,
            file: selection.file,
            line: selection.line,
            type: 'intermediate'
        };

        // 2. Add to Graph
        this.graph.nodes.push(newNode);
        this.graph.edges.push({
            from: newNode.id,
            to: this.currentNodeId,
            label: selection.arg
        });
        
        this.currentNodeId = newNode.id; // Advance tip
        this.history.push(`User Selected: ${selection.caller} passes '${selection.arg}'`);
        this.dispatchUpdate(`Advanced to ${selection.caller}`);

        // 3. Find Next Candidates
        this.dispatchUpdate(`Analyzing callers for ${newNode.function}...`);
        const nextCandidates = await this.calculateCandidates(newNode);
        
        if (nextCandidates.length === 0) {
             // Mark tip as source if no callers
             newNode.type = 'source';
             this.dispatchUpdate("No further callers found. Reached potential source.");
             this.sendCandidates([]);
        } else {
             this.sendCandidates(nextCandidates.sort((a,b) => b.risk - a.risk));
        }
    }

    async generateFinalReport(finding: Finding): Promise<string> {
        this.sendUpdate(this.graph, "Generating Final Intelligence Report...");
        const trace = this.history.join("\n ↓ \n");
        const prompt = PromptFactory.renderReport(finding, trace);
        const response = await this.llm.chat([{ role: 'user', content: prompt }], true);
        try {
            return JSON.parse(response).markdown_report;
        } catch {
            return "Failed to generate report format.";
        }
    }

    private async autonomousLoop(currentNode: FlowNode, depth: number) {
        if (depth >= 3) {
            this.history.push("Trace limit reached.");
            this.dispatchUpdate("Trace limit reached.");
            return;
        }

        if (['main', 'wmain', '_start'].includes(currentNode.function)) {
            const lastNode = this.graph.nodes[this.graph.nodes.length - 1];
            if (lastNode) lastNode.type = 'source';
            this.history.push("Reached Entry Point (main). Trace Complete.");
            this.dispatchUpdate("Reached Entry Point (main).");
            return;
        }

        this.dispatchUpdate(`Analyzing callers for ${currentNode.function}...`);
        const candidates = await this.calculateCandidates(currentNode);
        
        if (candidates.length > 0) {
            const best = candidates.sort((a, b) => b.risk - a.risk)[0];
            
            const newNode: FlowNode = {
                id: `step_${depth+1}`,
                function: best.caller,
                variable: best.arg, 
                file: best.file,    
                line: best.line,
                type: 'intermediate'
            };

            this.graph.nodes.push(newNode);
            this.graph.edges.push({ from: newNode.id, to: currentNode.id, label: best.arg });
            
            this.history.push(`Step ${depth+1}: ${best.caller} passes '${best.arg}' to ${currentNode.function}`);
            this.dispatchUpdate(`Found Caller: ${best.caller}`);
            
            await this.autonomousLoop(newNode, depth + 1);
        } else {
            const lastNode = this.graph.nodes[this.graph.nodes.length - 1];
            if (lastNode && lastNode.type === 'intermediate') lastNode.type = 'source';
            this.history.push("Trace ended (No callers found).");
            this.dispatchUpdate("Trace Complete.");
        }
    }

    // Shared logic for both modes
    private async calculateCandidates(node: FlowNode): Promise<FlowCandidate[]> {
        const files = await vscode.workspace.findFiles('**/*.{c,cpp,h}', '**/node_modules/**', 20);
        let callersText = "";
        const potentialCallers: any[] = [];

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
                            const enclosingFunc = this.ast.getFunctionName(
                                this.ast.getFunctionAtLine(content, idx + 1) || ""
                            ) || "unknown";

                            const snippet = lines.slice(Math.max(0, idx - 2), Math.min(lines.length, idx + 3)).join('\n');
                            
                            callersText += `File: ${file.fsPath}\nLine: ${idx + 1}\nEnclosing Function: ${enclosingFunc}\nSnippet:\n${snippet}\n---\n`;
                            potentialCallers.push({ file: file.fsPath, line: idx + 1, caller: enclosingFunc });
                        }
                    });
                }
            } catch (e) { }
        }

        if (callersText.length > 0) {
            const prompt = PromptFactory.renderFlowStep(node.function, node.variable, callersText);
            const response = await this.llm.chat([{ role: 'user', content: prompt }], true);
            try {
                const result = JSON.parse(response);
                return result.candidates.map((c: any) => {
                    // FIX: Robust Matching Logic
                    // 1. Try exact match
                    let matchedCaller = potentialCallers.find(p => p.caller === c.caller_name);
                    
                    // 2. Try fuzzy match (e.g., if LLM returns "DoStuff" but code is "Class::DoStuff")
                    if (!matchedCaller) {
                        matchedCaller = potentialCallers.find(p => p.caller.includes(c.caller_name) || c.caller_name.includes(p.caller));
                    }

                    // 3. Last Resort: If we only found ONE caller via grep, assume that's the one
                    if (!matchedCaller && potentialCallers.length === 1) {
                        matchedCaller = potentialCallers[0];
                    }

                    // 4. Return
                    return {
                        caller: c.caller_name,
                        arg: c.tainted_arg,
                        risk: c.risk_score,
                        // Ensure we don't send a file link if we couldn't match the LLM's hallucination to real code
                        file: matchedCaller ? matchedCaller.file : "",
                        line: matchedCaller ? matchedCaller.line : 0,
                        reason: c.reason
                    };
                });
            } catch (e) { return []; }
        } else {
            // Deep inference fallback
            const allFiles = await vscode.workspace.findFiles('**/*.{c,cpp,py,java}', '**/node_modules/**', 50);
            const repoMap = allFiles.map(f => vscode.workspace.asRelativePath(f)).join('\n');
            const prompt = PromptFactory.renderDeepFlow(node.function, node.file, repoMap);
            const response = await this.llm.chat([{ role: 'user', content: prompt }], true);
            try {
                const result = JSON.parse(response);
                return result.candidates.map((c: any) => ({
                    caller: c.caller_name + " (Inferred)",
                    arg: c.tainted_arg,
                    risk: c.risk_score,
                    // FIX: Do NOT assign the current node's file/line to an inferred caller. 
                    // This prevents the UI from creating circular links to the sink.
                    file: "", 
                    line: 0,
                    reason: c.reason || "Inferred via Deep Analysis"
                }));
            } catch (e) { return []; }
        }
    }
}
#src\agents\triageAgent.ts
import * as vscode from 'vscode';
import { LLMProvider } from '../core/llm';
import { PromptFactory } from '../core/prompts';
import { Finding } from '../core/types';

export class TriageAgent {
    constructor(private llm: LLMProvider) {}

    async triage(finding: Finding): Promise<{ status: 'verified' | 'false_positive', reason: string }> {
        // 1. Read File Context
        try {
            const uri = vscode.Uri.file(finding.file); // Assuming absolute path or workspace relative
            const doc = await vscode.workspace.openTextDocument(uri);
            const range = new vscode.Range(
                Math.max(0, finding.line - 5), 0,
                Math.min(doc.lineCount, finding.line + 5), 0
            );
            const snippet = doc.getText(range);

            // 2. Ask LLM
            const prompt = PromptFactory.renderTriage(finding, snippet);
            const response = await this.llm.chat([{ role: 'user', content: prompt }], true);
            const result = JSON.parse(response);

            return {
                status: result.is_true_positive ? 'verified' : 'false_positive',
                reason: result.reasoning
            };

        } catch (e) {
            return { status: 'verified', reason: "Could not read file for triage." };
        }
    }
}
#src\core\llm.ts
import * as vscode from 'vscode';
import OpenAI from 'openai';
import * as fs from 'fs';
import * as path from 'path';

export interface LLMConfig {
    apiKey?: string;
    baseUrl?: string;
    model?: string;
}

export class LLMProvider {
  private client: OpenAI;
  private model: string;

  constructor(configOverride?: LLMConfig) {
    // 1. Define Defaults
    let baseUrl = "http://localhost:11434/v1";
    let apiKey = "ollama";
    let model = "llama3:8b";

    // 2. Check VS Code Global Settings (Fallback)
    const config = vscode.workspace.getConfiguration('vulntriage');
    if (config.get<string>('llm.baseUrl')) baseUrl = config.get<string>('llm.baseUrl')!;
    if (config.get<string>('llm.apiKey')) apiKey = config.get<string>('llm.apiKey')!;
    if (config.get<string>('llm.model')) model = config.get<string>('llm.model')!;

    // 3. Check Local Workspace Config File (Priority)
    const workspaceConfig = this.loadWorkspaceConfig();
    if (workspaceConfig) {
        if (workspaceConfig.baseUrl) baseUrl = workspaceConfig.baseUrl;
        if (workspaceConfig.apiKey) apiKey = workspaceConfig.apiKey;
        if (workspaceConfig.model) model = workspaceConfig.model;
        console.log(`VulnTriage: Loaded configuration from vulntriage.config.json`);
    }

    // 4. Check UI Overrides (Highest Priority)
    if (configOverride) {
        if (configOverride.baseUrl && configOverride.baseUrl.trim() !== "") baseUrl = configOverride.baseUrl;
        if (configOverride.apiKey && configOverride.apiKey.trim() !== "") apiKey = configOverride.apiKey;
        if (configOverride.model && configOverride.model.trim() !== "") model = configOverride.model;
        console.log(`VulnTriage: Using UI Configuration Overrides`);
    }

    this.model = model;
    this.client = new OpenAI({
      baseURL: baseUrl,
      apiKey: apiKey,
      dangerouslyAllowBrowser: true
    });
    
    console.log(`VulnTriage: Active Model: ${this.model} | Base: ${baseUrl}`);
  }

  /**
   * Looks for 'vulntriage.config.json' in the root of the active workspace.
   */
  private loadWorkspaceConfig(): any {
      if (!vscode.workspace.workspaceFolders || vscode.workspace.workspaceFolders.length === 0) {
          return null;
      }
      
      // Look in the root of the first open folder
      const rootPath = vscode.workspace.workspaceFolders[0].uri.fsPath;
      const configPath = path.join(rootPath, 'vulntriage.config.json');

      if (fs.existsSync(configPath)) {
          try {
              const content = fs.readFileSync(configPath, 'utf-8');
              return JSON.parse(content);
          } catch (e) {
              console.error("Failed to parse vulntriage.config.json", e);
              vscode.window.showErrorMessage("VulnTriage: Failed to parse your config file.");
              return null;
          }
      }
      return null;
  }

  async chat(messages: any[], jsonMode: boolean = false): Promise<string> {
    try {
      const response = await this.client.chat.completions.create({
        model: this.model,
        messages: messages,
        temperature: 0.2, // Low temp for technical analysis
        response_format: jsonMode ? { type: "json_object" } : { type: "text" }
      });
      return response.choices[0].message.content || "No response generated.";
    } catch (e: any) {
      console.error("LLM Error:", e);
      return `LLM Error: ${e.message}. (Attempted Model: ${this.model})`;
    }
  }
}
#src\core\prompts.ts
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

    static renderFlowStep(funcName: string, taintedVar: string, callers: string): string {
        return `
        [System]
        You are a Taint Analysis Expert. Determine which function callers pass data into the tainted variable.

        [User]
        Target Function: ${funcName}
        Tainted Var: ${taintedVar}
        
        Incoming Callers Found via Grep:
        ${callers}
        
        Analyze which callers pass data to '${taintedVar}'.
        Return JSON: { "candidates": [ { "caller_name": "string", "tainted_arg": "string", "risk_score": number, "reason": "string" } ] }
        `;
    }

    static renderDeepFlow(funcName: string, file: string, repoMap: string): string {
        return `
        [System]
        You are a Senior Security Researcher specializing in Complex Data Flows.
        Standard static analysis failed to find a direct caller. You must infer "hidden" data flows.

        [User]
        Target Function: ${funcName}
        Current Location: ${file}

        Repository Structure (Top Level Files):
        ${repoMap}

        Scenario Analysis:
        We are tracing BACKWARDS from '${funcName}'.
        If it is not called directly, how does data get here?
        Consider:
        1. Implicit Connection: Is it a callback, interface impl, or function pointer?
        2. Entry Point Link: Can a main/server entry point trigger this path via IPC, JNI, or Event Bus?
        3. Data Store: Does an Entry Point write to a DB/File that this function reads?

        Instruction:
        Propose up to 3 potential sources.
        Return JSON: { "candidates": [ { "caller_name": "string (inferred)", "tainted_arg": "string", "risk_score": number, "reason": "string (mechanism explanation)" } ] }
        `;
    }

    static renderReport(finding: Finding, traceHistory: string): string {
        return `
        [System]
        You are a Senior Security Researcher writing a vulnerability report.

        [User]
        Task: Write a detailed executive summary based on the analysis below.

        Vulnerability: ${finding.ruleId}
        Location: ${finding.file}:${finding.line}

        Trace History (Sink -> Source):
        ${traceHistory}

        Requirements:
        1. Summarize the vulnerability class.
        2. Explain the flow logic: How the data travels from the entry point to the dangerous sink.
        3. Suggest a remediation strategy.

        Return JSON: { "markdown_report": "string" }
        `;
    }
}
#src\core\types.ts
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
}

export interface FlowEdge {
    from: string;
    to: string;
    label?: string;
}

export interface FlowGraph {
    nodes: FlowNode[];
    edges: FlowEdge[];
}

export interface FlowCandidate {
    caller: string;
    arg: string;
    risk: number;
    file: string;
    line: number;
    reason?: string;
}

export type BackendMessage = 
    | { type: 'scan_progress', value: string, percent?: number } 
    | { type: 'scan_complete', findings: Finding[], shouldSwitchView?: boolean }
    | { type: 'triage_update', findingId: string, status: 'verified' | 'false_positive', reason: string, percent?: number }
    | { type: 'flow_update', graph: FlowGraph, log: string }
    | { type: 'scope_selected', path: string }
    | { type: 'report_generated', report: string }
    | { type: 'interactive_candidates', candidates: FlowCandidate[] };

// UPDATE: Added llmConfig to startScan and startFlow
export type FrontendMessage = 
    | { command: 'selectScope' } 
    | { command: 'saveSession', findings: Finding[], graph: FlowGraph, logs: string[], report: string } 
    | { 
        command: 'startScan', 
        scopePath?: string, 
        focus?: string,
        llmConfig?: { apiKey: string, baseUrl: string, model: string }
      }
    | { 
        command: 'startFlow', 
        finding: Finding, 
        mode: 'interactive' | 'autonomous',
        llmConfig?: { apiKey: string, baseUrl: string, model: string } 
      }
    | { command: 'generateReport', finding: Finding }
    | { command: 'openFile', file: string, line: number }
    | { command: 'interactive_selection', selection: FlowCandidate };
#src\scanners\llmScanner.ts
import * as vscode from 'vscode';
import { LLMProvider } from '../core/llm';
import { ScanResponseSchema, Finding } from '../core/types';

export class LLMScanner {
  constructor(private llm: LLMProvider) {}

  async scanFile(document: vscode.TextDocument, focus?: string): Promise<Finding[]> {
    const code = document.getText();
    if (code.length > 50000) return [];

    let focusInstruction = "";
    if (focus && focus.trim().length > 0) {
        focusInstruction = `\nATTENTION: The user is specifically looking for "${focus}". Prioritize findings related to this.`;
    }

    const prompt = `
      You are a SAST Tool. Analyze this code.${focusInstruction}
      Return ONLY valid JSON matching: { "findings": [{ "rule_id": "...", "message": "...", "line_number": 1, "severity": "high" }] }
      
      Code:
      ${code}
    `;

    const result = await this.llm.chat([{ role: "user", content: prompt }], true);
    
    // UPDATE: Check for LLM Error messages (returned by LLMProvider on catch)
    if (result.startsWith("LLM Error")) {
        return [{
            id: `err_${Date.now()}`,
            ruleId: 'CONFIG-ERR',
            message: `Scanner Failed: ${result}`,
            line: 1,
            severity: 'critical',
            file: document.uri.fsPath,
            status: 'verified',
            triageReason: 'Configuration or Network Error'
        }];
    }

    try {
      let cleanJson = result.trim();
      if (cleanJson.startsWith('```')) {
          cleanJson = cleanJson.replace(/^```json/, '').replace(/^```/, '').replace(/```$/, '');
      }
      
      const parsed = ScanResponseSchema.parse(JSON.parse(cleanJson));
      
      return parsed.findings.map((f: any) => ({
        id: `f_${Math.random().toString(36).substr(2, 9)}`,
        ruleId: f.rule_id,
        message: f.message,
        line: f.line_number,
        severity: f.severity as any,
        file: document.uri.fsPath,
        status: 'pending'
      }));
    } catch (e) {
      console.error("Parse error", e);
      return [];
    }
  }
}
#src\tools\astEngine.ts
import * as vscode from 'vscode';
import * as path from 'path';
const Parser = require('web-tree-sitter');

/**
 * Configuration map for supported languages.
 * Defines the WASM file to load and the Tree-sitter queries to extract data.
 */
const LANG_CONFIG: { [key: string]: { wasm: string; queryFunc: string; queryName: string; queryLocation: string } } = {
    c: {
        wasm: 'tree-sitter-c.wasm',
        queryFunc: '(function_definition) @func',
        queryName: '(function_declarator declarator: (identifier) @name)',
        // Captures both the full definition (@def) and the name (@name) to link them
        queryLocation: '(function_definition declarator: (function_declarator declarator: (identifier) @name)) @def'
    },
    cpp: {
        wasm: 'tree-sitter-cpp.wasm',
        queryFunc: '(function_definition) @func',
        queryName: `(function_declarator 
            declarator: [
                (identifier) @name
                (qualified_identifier) @name
                (field_identifier) @name
            ]
        )`,
        queryLocation: `(function_definition 
            declarator: (function_declarator 
                declarator: [
                    (identifier) @name
                    (qualified_identifier) @name
                    (field_identifier) @name
                ]
            )
        ) @def`
    },
    java: {
        wasm: 'tree-sitter-java.wasm',
        queryFunc: '(method_declaration) @func',
        queryName: '(method_declaration name: (identifier) @name)',
        queryLocation: '(method_declaration name: (identifier) @name) @def'
    },
    rust: {
        wasm: 'tree-sitter-rust.wasm',
        queryFunc: '(function_item) @func',
        queryName: '(function_item name: (identifier) @name)',
        queryLocation: '(function_item name: (identifier) @name) @def'
    },
    kotlin: {
        wasm: 'tree-sitter-kotlin.wasm',
        queryFunc: '(function_declaration) @func',
        queryName: '(function_declaration name: (simple_identifier) @name)',
        queryLocation: '(function_declaration name: (simple_identifier) @name) @def'
    },
    swift: {
        wasm: 'tree-sitter-swift.wasm',
        queryFunc: '(function_declaration) @func',
        queryName: '(function_declaration name: (simple_identifier) @name)',
        queryLocation: '(function_declaration name: (simple_identifier) @name) @def'
    },
    'objective-c': {
        wasm: 'tree-sitter-objc.wasm', 
        queryFunc: '(method_definition) @func',
        queryName: '(method_definition selector: (selector) @name)',
        queryLocation: '(method_definition selector: (selector) @name) @def'
    },
    python: {
        wasm: 'tree-sitter-python.wasm',
        queryFunc: '(function_definition) @func',
        queryName: '(function_definition name: (identifier) @name)',
        queryLocation: '(function_definition name: (identifier) @name) @def'
    }
};

export class ASTEngine {
    private parser: any = null;
    private lang: any = null;
    private currentLangId: string = '';
    private isInit = false;

    constructor(private context: vscode.ExtensionContext) {}

    /**
     * Initializes the parser for the specific language.
     */
    async init(languageId: string) {
        // Normalize language ID (handle 'cpp' vs 'c' vs 'objective-c')
        const configKey = languageId === 'c' || languageId === 'cpp' ? languageId : languageId.toLowerCase();

        if (this.isInit && this.currentLangId === configKey) return;

        const config = LANG_CONFIG[configKey];
        if (!config) {
            console.warn(`[ASTEngine] Language '${languageId}' is not supported.`);
            return;
        }

        try {
            if (!this.parser) {
                await Parser.init({
                    locateFile: (scriptName: string) => {
                        return path.join(this.context.extensionPath, 'resources', scriptName);
                    }
                });
                this.parser = new Parser();
            }

            const langPath = path.join(this.context.extensionPath, 'resources', config.wasm);
            this.lang = await Parser.Language.load(langPath);
            this.parser.setLanguage(this.lang);

            this.currentLangId = configKey;
            this.isInit = true;
            console.log(`[ASTEngine] Initialized for ${configKey}`);
        } catch (e) {
            console.error(`[ASTEngine] Failed to init tree-sitter for ${configKey}`, e);
            vscode.window.showErrorMessage(`Failed to load parser for ${configKey}. Is ${config.wasm} in resources?`);
            // Reset init state on failure to allow retries
            this.isInit = false;
            this.currentLangId = '';
        }
    }

    /**
     * Gets the full text of the function definition surrounding a specific line.
     */
    getFunctionAtLine(code: string, line: number): string | null {
        if (!this.parser || !this.lang || !this.isInit) return null;

        try {
            const config = LANG_CONFIG[this.currentLangId];
            const tree = this.parser.parse(code);
            const row = line - 1; 

            const query = this.lang.query(config.queryFunc);
            const captures = query.captures(tree.rootNode);

            let bestNode: any = null;

            for (const cap of captures) {
                const node = cap.node;
                if (node.startPosition.row <= row && node.endPosition.row >= row) {
                    if (!bestNode || (node.endIndex - node.startIndex) < (bestNode.endIndex - bestNode.startIndex)) {
                        bestNode = node;
                    }
                }
            }
            return bestNode ? bestNode.text : null;
        } catch (e) {
            console.error("[ASTEngine] Error parsing function at line", e);
            return null;
        }
    }

    /**
     * Extracts the function name from a block of code.
     */
    getFunctionName(code: string): string | null {
        if (!this.parser || !this.lang || !this.isInit) return null;

        try {
            const config = LANG_CONFIG[this.currentLangId];
            const tree = this.parser.parse(code);

            const query = this.lang.query(config.queryName);
            const captures = query.captures(tree.rootNode);

            if (captures.length > 0) {
                return captures[0].node.text;
            }
            return null;
        } catch (e) {
            console.error("[ASTEngine] Error extracting function name", e);
            return null;
        }
    }

    /**
     * Finds the start line number (1-based) of a specific function name in the file.
     */
    getFunctionLocation(code: string, funcName: string): number | null {
        if (!this.parser || !this.lang || !this.isInit) return null;

        try {
            const config = LANG_CONFIG[this.currentLangId];
            const tree = this.parser.parse(code);
            
            // We use 'matches' here instead of 'captures' to keep the @name and @def paired together
            const query = this.lang.query(config.queryLocation);
            const matches = query.matches(tree.rootNode);

            for (const match of matches) {
                let foundName = false;
                let defNode: any = null;

                // A match contains multiple captures (e.g., one for @name, one for @def)
                for (const cap of match.captures) {
                    if (cap.name === 'name' && cap.node.text === funcName) {
                        foundName = true;
                    }
                    if (cap.name === 'def') {
                        defNode = cap.node;
                    }
                }

                if (foundName && defNode) {
                    return defNode.startPosition.row + 1; // Return 1-based line number
                }
            }
            
            return null;
        } catch (e) {
            console.error("[ASTEngine] Error finding function location", e);
            return null;
        }
    }
}
#src\webview\App.tsx
import React, { useState, useEffect, useRef } from 'react';
import { vscode } from './vscode';
import { ArrowLeft, Search, FileCode, FileText, Save, Folder, RefreshCw, ChevronUp, Terminal, Bug, Play, GitCommit, Layout, Loader2, MousePointerClick, Zap, Key, AlertTriangle } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import './style.css'; 

// --- TYPES ---
interface Finding {
    id: string; ruleId: string; message: string; file: string; line: number; severity: string;
    status: 'pending' | 'verified' | 'false_positive';
}

interface FlowCandidate {
    caller: string; arg: string; risk: number; file: string; line: number; reason?: string;
}

interface AppState {
    mode: 'HOME' | 'SCAN' | 'FLOW';
    findings: Finding[];
    logs: string[];
    progress: number;
    statusMsg: string;
    scope: string;
    focus: string;
    reportContent: string;
    selectedFinding: Finding | null;
    graphData: any;
    candidates: FlowCandidate[];
    apiKey: string;
    baseUrl: string;
    modelName: string;
}

// --- COMPONENTS ---

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

// --- CANDIDATE SELECTION PANEL ---
const CandidateSelector = ({ candidates, onSelect }: { candidates: FlowCandidate[], onSelect: (c: FlowCandidate) => void }) => (
    <div className="flex-none bg-[#151720] border-t border-primary p-4 shadow-[0_-5px_20px_rgba(0,0,0,0.5)] max-h-[40vh] overflow-y-auto animate-slide-in">
        <div className="flex items-center gap-2 mb-3 text-primary uppercase font-bold text-xs tracking-wider animate-pulse">
            <MousePointerClick size={14} /> Select Next Step (Interactive Mode)
        </div>
        <div className="space-y-2">
            {candidates.map((c, i) => (
                <div key={i} onClick={() => onSelect(c)} className="p-3 rounded border border-gray-700 bg-[#0f111a] hover:border-primary hover:bg-[#1a1d29] cursor-pointer transition-all">
                    <div className="flex justify-between mb-1">
                        <span className="font-bold text-sm text-white">{c.caller}</span>
                        <span className="text-xs text-orange-400 border border-orange-400/30 px-1 rounded">Risk: {c.risk}/10</span>
                    </div>
                    <div className="text-xs text-gray-400 mb-1 font-mono">Arg: <span className="text-white">{c.arg}</span></div>
                    <div className="text-[10px] text-gray-500 truncate">{c.reason}</div>
                    {/* UPDATE: Only show file path if we actually have one */}
                    {c.file && (
                        <div className="mt-1 flex items-center gap-1 text-[9px] text-gray-600 font-mono">
                            <FileCode size={8}/> {c.file.split(/[\\/]/).pop()}:{c.line}
                        </div>
                    )}
                </div>
            ))}
        </div>
    </div>
);

// --- HOME VIEW ---
const HomeView = ({ 
    scope, focus, setFocus, 
    apiKey, setApiKey, baseUrl, setBaseUrl, modelName, setModelName,
    onSelectScope, onStart, hasResults, onViewResults, validationError 
}: any) => (
    <div className="flex flex-col h-full p-6 overflow-y-auto">
        <div className="text-center mb-6 mt-4 animate-pulse">
            <img src={(window as any).vsLogoUrl} alt="VulnTriage Logo" className="mx-auto mb-4 h-16 w-16 object-contain" />
            <h1 className="text-2xl font-bold tracking-widest uppercase">Vuln<span className="text-primary">Triage</span></h1>
            <p className="text-xs text-muted mt-2">Autonomous Vulnerability Research Agent</p>
        </div>
        <div className="space-y-6 flex-1">
            
            {/* LLM Config Section */}
            <div className={`bg-panel p-4 rounded border ${validationError ? 'border-alert' : 'border-gray-800'} relative group transition-colors`}>
                <div className="space-y-3 pt-2">
                    <div>
                        <label className="block text-[10px] text-muted mb-1 uppercase font-mono">API Base URL</label>
                        <input type="text" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="http://localhost:11434/v1" className="cyber-input text-xs" />
                    </div>
                    <div className="flex gap-2">
                        <div className="flex-1">
                            <label className="block text-[10px] text-muted mb-1 uppercase font-mono">API Key</label>
                            <div className="relative">
                                <input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder="Default/Env" className="cyber-input text-xs pr-6" />
                                <Key size={10} className="absolute right-2 top-2 text-gray-600"/>
                            </div>
                        </div>
                        <div className="flex-1">
                            <label className="block text-[10px] text-muted mb-1 uppercase font-mono">Model Name</label>
                            <input type="text" value={modelName} onChange={(e) => setModelName(e.target.value)} placeholder="llama3:8b" className="cyber-input text-xs" />
                        </div>
                    </div>
                    {validationError && <div className="text-[10px] text-alert flex items-center gap-1"><AlertTriangle size={10}/> {validationError}</div>}
                </div>
            </div>

            {/* Scan Config Section */}
            <div className="bg-panel p-4 rounded border border-gray-800">
                <label className="block text-xs font-bold uppercase text-muted mb-2">Target Scope</label>
                <button onClick={onSelectScope} className="w-full flex items-center justify-between cyber-input hover:border-primary text-sm text-left">
                    <span className="truncate">{scope}</span><Folder size={14}/>
                </button>
            </div>
            <div className="bg-panel p-4 rounded border border-gray-800">
                <label className="block text-xs font-bold uppercase text-muted mb-2">Vulnerability Focus</label>
                <input type="text" value={focus} onChange={(e) => setFocus(e.target.value)} placeholder="e.g. Memory Corruption" className="cyber-input text-sm" />
            </div>

            <div className="flex flex-col gap-3 mt-4">
                <button onClick={onStart} className="btn-primary w-full flex justify-center gap-2 py-3"><Search size={18}/> Initialize Scan</button>
                {hasResults && <button onClick={onViewResults} className="btn-primary w-full flex justify-center gap-2 py-3 border-dashed opacity-80 hover:opacity-100"><Layout size={18}/> View Active Results</button>}
            </div>
        </div>
        <div className="text-center text-[10px] text-gray-600 font-mono mt-4">v0.4.4 // FLOW FIXES</div>
    </div>
);

// --- SCAN RESULTS VIEW ---
const ScanResultsView = ({ findings, progress, statusMsg, onBack, onNewScan, onFlow }: any) => (
    <div className="flex flex-col h-full">
        <div className="p-4 border-b border-gray-800 sticky top-0 bg-[#0f111a] z-10 shadow-lg">
            <div className="flex justify-between items-center mb-4">
                <div className="flex items-center gap-2">
                    <button onClick={onBack} className="btn-icon"><ArrowLeft size={16}/></button>
                    <h2 className="font-bold uppercase tracking-wider text-sm">Detections <span className="text-primary">[{findings.length}]</span></h2>
                </div>
                <button onClick={onNewScan} className="text-xs text-muted hover:text-white flex gap-1 items-center"><Save size={12}/> New</button>
            </div>
            <ProgressBar percent={progress} label={statusMsg} />
        </div>
        <div className="flex-1 overflow-y-auto p-2 space-y-2 scroll-smooth">
            {findings.length === 0 && progress === 100 && <div className="text-center text-muted mt-10">No vulnerabilities detected. System Secure.</div>}
            {findings.map((f: Finding) => (
                <div key={f.id} className={`p-4 rounded finding-card ${f.status}`}>
                    <div className="flex justify-between mb-2 items-start">
                        <span className="font-bold text-sm text-white truncate pr-2">{f.ruleId}</span>
                        <StatusBadge severity={f.severity} />
                    </div>
                    <p className="text-xs text-gray-400 mb-3 line-clamp-2">{f.message}</p>
                    <div className="flex justify-between items-end gap-2">
                        <div className="text-[10px] text-gray-500 font-mono flex gap-1 items-center flex-1">
                            <FileCode size={10}/> {f.file.split(/[\\/]/).pop()}:{f.line}
                        </div>
                        {f.status === 'verified' && f.ruleId !== 'CONFIG-ERR' && (
                            <div className="flex gap-2">
                                <button onClick={() => onFlow(f, 'interactive')} className="btn-primary text-[10px] py-1 px-2 flex gap-1 items-center border-dashed hover:border-solid">
                                    <MousePointerClick size={12}/> Interactive
                                </button>
                                <button onClick={() => onFlow(f, 'autonomous')} className="btn-primary text-[10px] py-1 px-2 flex gap-1 items-center">
                                    Autonomous <Zap size={12} className="fill-current"/>
                                </button>
                            </div>
                        )}
                    </div>
                </div>
            ))}
        </div>
    </div>
);

// --- FLOW VIEW COMPONENTS (Timeline & Wrapper) ---
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
                            <div className="flex justify-between items-start mb-1">
                                <div className={`font-bold font-mono text-sm ${titleColor}`}>{node.function}</div>
                                {node.line && <span className="text-[10px] text-gray-500 font-mono bg-black/40 px-1 rounded">Ln {node.line}</span>}
                            </div>
                            <div className="text-xs text-gray-400 font-mono break-all"><span className="text-gray-600 select-none">$ </span>{node.variable}</div>
                            {/* UPDATE: Check for empty file path to avoid rendering empty bar */}
                            {node.file && (
                                <div className="mt-2 flex items-center gap-1 text-[10px] text-gray-500"><FileCode size={10}/><span className="truncate">{node.file}</span></div>
                            )}
                        </div>
                    </div>
                );
            })}
        </div>
    );
};

const FlowView = ({ candidates, onCandidateSelect, finding, progress, statusMsg, graphData, logs, reportContent, onBack, onSave, onGenerateReport, bottomRef }: any) => (
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
                  <div className="flex-1 overflow-y-auto bg-[#0f111a] relative p-4 custom-scrollbar">
                      {(!graphData.nodes || graphData.nodes.length === 0) ? (
                          <div className="flex flex-col items-center justify-center h-full text-gray-500 animate-pulse">
                              <RefreshCw className="animate-spin mb-4 text-primary" size={32}/>
                              <span className="text-xs font-mono">TRACING CALL STACK...</span>
                          </div>
                      ) : <FlowTimeline graphData={graphData} isScanning={progress < 100 && candidates.length === 0} />}
                  </div>
                  {candidates.length > 0 && <CandidateSelector candidates={candidates} onSelect={onCandidateSelect} />}
                  <div className="h-48 border-t border-gray-700 bg-panel flex-none flex flex-col z-20">
                      <div className="flex items-center gap-2 px-3 py-2 border-b border-gray-700 bg-[#151720]">
                          <Terminal size={12} className="text-primary"/>
                          <span className="text-[10px] font-bold uppercase text-muted">Agent Logs</span>
                      </div>
                      <div className="text-[10px] font-mono space-y-1 text-gray-400 flex-1 overflow-y-auto p-2">
                          {logs.map((l: string, i: number) => <div key={i} className="border-l-2 border-gray-700 pl-2 hover:border-primary hover:text-white transition-colors"><span className="text-gray-600">[{i.toString().padStart(2,'0')}]</span> {l}</div>)}
                          <div ref={bottomRef}/>
                      </div>
                  </div>
                </>
            )}
        </div>
    </div>
);

// --- APP CONTROLLER ---

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
  
  const [apiKey, setApiKey] = useState<string>(savedState.apiKey || "");
  const [baseUrl, setBaseUrl] = useState<string>(savedState.baseUrl || "http://localhost:11434/v1");
  const [modelName, setModelName] = useState<string>(savedState.modelName || "llama3:8b");
  const [validationError, setValidationError] = useState<string>(""); 

  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
      vscode.setState({ 
          mode, findings, logs, progress, statusMsg, scope, focus, 
          reportContent, selectedFinding, graphData, candidates,
          apiKey, baseUrl, modelName 
      });
  }, [mode, findings, logs, progress, statusMsg, scope, focus, reportContent, selectedFinding, graphData, candidates, apiKey, baseUrl, modelName]);

  useEffect(() => {
    const handler = (event: MessageEvent) => {
      const msg = event.data;
      if (msg.type === 'scope_selected') setScope(msg.path);
      if (msg.type === 'scan_progress') { 
          setLogs(prev => [...prev, msg.value]); 
          setStatusMsg(msg.value); 
          if (msg.percent !== undefined) setProgress(msg.percent); 
      }
      if (msg.type === 'scan_complete') { 
          setFindings(msg.findings); 
          setProgress(100); 
          if (msg.shouldSwitchView) setMode('SCAN');
      }
      if (msg.type === 'triage_update') { 
          setFindings(prev => prev.map(f => f.id === msg.findingId ? { ...f, status: msg.status } : f)); 
      }
      if (msg.type === 'flow_update') { 
          setLogs(prev => [...prev, msg.log]); 
          setGraphData(msg.graph); 
      }
      if (msg.type === 'interactive_candidates') {
          setCandidates(msg.candidates);
          setStatusMsg("Waiting for user selection...");
      }
      if (msg.type === 'report_generated') { setReportContent(msg.report); setCandidates([]); }
    };
    window.addEventListener('message', handler);
    return () => window.removeEventListener('message', handler);
  }, []);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [logs]);

  const validateConfig = () => {
      setValidationError("");
      if (!baseUrl.trim()) { setValidationError("Base URL is required"); return false; }
      if (!modelName.trim()) { setValidationError("Model Name is required"); return false; }
      if (!baseUrl.includes("localhost") && !baseUrl.includes("127.0.0.1") && !apiKey.trim()) {
          setValidationError("API Key is required for remote providers");
          return false;
      }
      return true;
  };

  const handleStartScan = () => { 
      if (!validateConfig()) return;
      setLogs(['Initializing Cyber Scan...']); setProgress(0); setStatusMsg("Scanning Target..."); 
      setMode('SCAN'); 
      vscode.postMessage({ 
          command: 'startScan', 
          scopePath: scope, 
          focus: focus,
          llmConfig: { apiKey, baseUrl, model: modelName }
      }); 
  };
  
  const handleFlow = (finding: Finding, type: 'interactive' | 'autonomous') => { 
      if (!validateConfig()) return;
      setSelectedFinding(finding); 
      setMode('FLOW'); 
      setGraphData({ nodes: [], edges: [] }); setReportContent(""); setCandidates([]);
      setLogs([`Initiating ${type} trace analysis...`]); 
      setProgress(5); setStatusMsg("Tracing Data Flow..."); 
      vscode.postMessage({ 
          command: 'startFlow', 
          finding, 
          mode: type,
          llmConfig: { apiKey, baseUrl, model: modelName }
      }); 
  };

  const handleCandidateSelect = (c: FlowCandidate) => {
      setCandidates([]); 
      setStatusMsg(`Analyzing path: ${c.caller}...`);
      vscode.postMessage({ command: 'interactive_selection', selection: c });
  };

  const handleGenerateReport = () => { if (selectedFinding) vscode.postMessage({ command: 'generateReport', finding: selectedFinding }); };
  const handleSave = () => { 
      vscode.postMessage({ command: 'saveSession', findings, logs, report: reportContent }); 
      setMode('HOME'); setFindings([]); setLogs([]); setReportContent(""); setScope("Workspace"); 
  };

  return (
    <div className="h-screen text-white selection:bg-primary/30 font-sans">
        {mode === 'HOME' && (
            <HomeView 
                scope={scope} focus={focus} setFocus={setFocus} 
                apiKey={apiKey} setApiKey={setApiKey}
                baseUrl={baseUrl} setBaseUrl={setBaseUrl}
                modelName={modelName} setModelName={setModelName}
                validationError={validationError}
                onSelectScope={() => vscode.postMessage({command: 'selectScope'})} 
                onStart={handleStartScan} hasResults={findings.length > 0} onViewResults={() => setMode('SCAN')}
            />
        )}
        {mode === 'SCAN' && <ScanResultsView findings={findings} progress={progress} statusMsg={statusMsg} onBack={() => setMode('HOME')} onNewScan={handleSave} onFlow={handleFlow} />}
        {mode === 'FLOW' && <FlowView candidates={candidates} onCandidateSelect={handleCandidateSelect} finding={selectedFinding} progress={progress} statusMsg={statusMsg} graphData={graphData} logs={logs} reportContent={reportContent} onBack={() => setMode('SCAN')} onSave={handleSave} onGenerateReport={handleGenerateReport} bottomRef={bottomRef} />}
    </div>
  );
};

export default App;
#src\webview\index.tsx
import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';

const container = document.getElementById('root');
const root = createRoot(container!);
root.render(<App />);
#src\webview\style.css
/* Reset & Base */
:root {
    --bg-dark: #0f111a;
    --bg-panel: #1a1d29;
    --primary: #00f0ff; /* Cyber Cyan */
    --secondary: #7000ff; /* Neon Purple */
    --alert: #ff003c; /* Cyber Red */
    --success: #00ff9f; /* Matrix Green */
    --text-main: #e0e6ed;
    --text-muted: #94a3b8;
    --border: #2d3748;
}

body {
    background-color: var(--bg-dark);
    color: var(--text-main);
    font-family: 'JetBrains Mono', 'Fira Code', Consolas, monospace;
    margin: 0;
    padding: 0;
    height: 100vh;
    overflow: hidden;
}

/* Utilities */
.h-screen { height: 100vh; }
.flex { display: flex; }
.flex-col { flex-direction: column; }
.flex-none { flex: none; }
.flex-1 { flex: 1 1 0%; }
.min-h-0 { min-height: 0; }
.gap-1 { gap: 0.25rem; }
.gap-2 { gap: 0.5rem; }
.gap-4 { gap: 1rem; }
.p-2 { padding: 0.5rem; }
.p-3 { padding: 0.75rem; }
.p-4 { padding: 1rem; }
.p-6 { padding: 1.5rem; }
.px-1 { padding-left: 0.25rem; padding-right: 0.25rem; }
.px-2 { padding-left: 0.5rem; padding-right: 0.5rem; }
.px-3 { padding-left: 0.75rem; padding-right: 0.75rem; }
.py-1 { padding-top: 0.25rem; padding-bottom: 0.25rem; }
.py-2 { padding-top: 0.5rem; padding-bottom: 0.5rem; }
.py-3 { padding-top: 0.75rem; padding-bottom: 0.75rem; }
.py-4 { padding-top: 1rem; padding-bottom: 1rem; }
.pl-2 { padding-left: 0.5rem; }
.pl-4 { padding-left: 1rem; }
.mb-1 { margin-bottom: 0.25rem; }
.mb-2 { margin-bottom: 0.5rem; }
.mb-3 { margin-bottom: 0.75rem; }
.mb-4 { margin-bottom: 1rem; }
.mt-2 { margin-top: 0.5rem; }
.mt-3 { margin-top: 0.75rem; }
.mt-4 { margin-top: 1rem; }
.border-b { border-bottom: 1px solid var(--border); }
.border-t { border-top: 1px solid var(--border); }
.border { border: 1px solid var(--border); }
.rounded { border-radius: 4px; }
.rounded-full { border-radius: 9999px; }
.items-center { align-items: center; }
.items-start { align-items: flex-start; }
.justify-between { justify-content: space-between; }
.justify-center { justify-content: center; }
.text-center { text-align: center; }
.w-full { width: 100%; }
.w-6 { width: 1.5rem; }
.h-6 { height: 1.5rem; }
.h-48 { height: 12rem; }
.truncate { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.shrink-0 { flex-shrink: 0; }
.relative { position: relative; }
.absolute { position: absolute; }
.left-\[27px\] { left: 27px; }
.top-6 { top: 1.5rem; }
.bottom-6 { bottom: 1.5rem; }
.z-0 { z-index: 0; }
.z-10 { z-index: 10; }
.cursor-pointer { cursor: pointer; }
.bg-black\/40 { background-color: rgba(0, 0, 0, 0.4); }

/* Colors */
.bg-panel { background-color: var(--bg-panel); }
.text-primary { color: var(--primary); text-shadow: 0 0 10px rgba(0, 240, 255, 0.3); }
.text-alert { color: var(--alert); text-shadow: 0 0 10px rgba(255, 0, 60, 0.3); }
.text-success { color: var(--success); }
.text-muted { color: var(--text-muted); }
.fill-success { fill: var(--success); }
.fill-alert { fill: var(--alert); }

.border-gray-700 { border-color: #374151; }
.border-gray-800 { border-color: #1f2937; }
.text-gray-400 { color: #9ca3af; }
.text-gray-500 { color: #6b7280; }
.text-gray-600 { color: #4b5563; }

/* Buttons */
.btn-primary {
    background: rgba(0, 240, 255, 0.1);
    color: var(--primary);
    border: 1px solid var(--primary);
    border-radius: 4px;
    font-family: inherit;
    font-weight: bold;
    cursor: pointer;
    transition: all 0.2s;
    text-transform: uppercase;
    letter-spacing: 1px;
}
.btn-primary:hover {
    background: var(--primary);
    color: #000;
    box-shadow: 0 0 15px var(--primary);
}

.btn-icon {
    background: transparent;
    color: var(--text-muted);
    border: 1px solid transparent;
    padding: 4px;
    cursor: pointer;
    transition: color 0.2s;
}
.btn-icon:hover { color: var(--text-main); border-color: var(--border); }

/* Scrollbars */
.overflow-y-auto { overflow-y: auto; }
::-webkit-scrollbar { width: 8px; }
::-webkit-scrollbar-track { background: #0f111a; }
::-webkit-scrollbar-thumb { background: #374151; border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: var(--primary); }

/* Inputs & Cards */
.cyber-input {
    background: #000;
    border: 1px solid var(--border);
    color: var(--primary);
    padding: 0.5rem;
    width: 100%;
    font-family: inherit;
}
.cyber-input:focus { outline: none; border-color: var(--primary); }

.finding-card {
    background: linear-gradient(135deg, var(--bg-panel) 0%, rgba(26, 29, 41, 0.5) 100%);
    border-left: 3px solid var(--border);
    transition: transform 0.1s, border-color 0.2s;
}
.finding-card:hover { transform: translateX(2px); }
.finding-card.verified { border-left-color: var(--alert); background: linear-gradient(90deg, rgba(255,0,60,0.05), transparent); }
.finding-card.false_positive { border-left-color: var(--text-muted); opacity: 0.6; }

.progress-container { background: #000; height: 4px; width: 100%; position: relative; overflow: hidden; }
.progress-bar { height: 100%; background: var(--primary); box-shadow: 0 0 10px var(--primary); transition: width 0.3s ease; }

@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
.animate-spin { animation: spin 2s linear infinite; }
.animate-pulse { animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .5; } }

/* Slide In Animation for Timeline Items */
@keyframes slideIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}
.animate-slide-in {
    animation: slideIn 0.3s ease-out forwards;
}
#src\webview\vscode.ts
// Define the interface manually to avoid dependency hell
interface VSCodeApi {
  postMessage(message: unknown): void;
  getState(): any;
  setState(state: any): void;
}

// Global declaration
declare function acquireVsCodeApi(): VSCodeApi;

class VSCodeAPIWrapper {
  private readonly vsCodeApi: VSCodeApi | undefined;

  constructor() {
    if (typeof acquireVsCodeApi === "function") {
      this.vsCodeApi = acquireVsCodeApi();
    }
  }

  public postMessage(message: unknown) {
    if (this.vsCodeApi) {
      this.vsCodeApi.postMessage(message);
    } else {
      console.log("VS Code API unavailable (mock mode):", message);
    }
  }

  public getState(): any {
    if (this.vsCodeApi) {
      return this.vsCodeApi.getState();
    }
    return undefined;
  }

  public setState(state: any): void {
    if (this.vsCodeApi) {
      this.vsCodeApi.setState(state);
    }
  }
}

export const vscode = new VSCodeAPIWrapper();
#package.json
{
  "name": "vulntriage-vscode",
  "displayName": "VulnTriage Agent",
  "description": "Context-aware vulnerability research agent",
  "version": "0.2.0",
  "engines": {
    "vscode": "^1.85.0"
  },
  "main": "./dist/extension.js",
  "activationEvents": [
    "onView:vulntriage.chatView",
    "onCommand:vulntriage.addToContext",
    "onCommand:vulntriage.addFolderToScope"
  ],
  "contributes": {
    "viewsContainers": {
      "activitybar": [
        {
          "id": "vulntriage-sidebar",
          "title": "VulnTriage",
          "icon": "$(shield)"
        }
      ]
    },
    "views": {
      "vulntriage-sidebar": [
        {
          "type": "webview",
          "id": "vulntriage.chatView",
          "name": "Research Agent",
          "visibility": "visible"
        }
      ]
    },
    "commands": [
      {
        "command": "vulntriage.addToContext",
        "title": "VulnTriage: Analyze Flow From Selection"
      },
      {
        "command": "vulntriage.addFolderToScope",
        "title": "VulnTriage: Add Folder to Scope"
      }
    ],
    "menus": {
      "editor/context": [
        {
          "command": "vulntriage.addToContext",
          "group": "vulntriage",
          "when": "editorHasSelection"
        }
      ],
      "explorer/context": [
        {
          "command": "vulntriage.addFolderToScope",
          "group": "vulntriage",
          "when": "explorerResourceIsFolder"
        }
      ]
    },
    "configuration": {
      "title": "VulnTriage",
      "properties": {
        "vulntriage.llm.baseUrl": {
          "type": "string",
          "default": "http://localhost:11434/v1",
          "description": "Base URL for LLM (Ollama, LM Studio, or OpenAI)"
        },
        "vulntriage.llm.apiKey": {
          "type": "string",
          "default": "ollama",
          "description": "API Key"
        },
        "vulntriage.llm.model": {
          "type": "string",
          "default": "llama3:8b",
          "description": "Model ID to use"
        }
      }
    }
  },
  "scripts": {
    "vscode:prepublish": "npm run package",
    "compile": "webpack",
    "watch": "webpack --watch",
    "package": "webpack --mode production --devtool hidden-source-map",
    "test": "vscode-test"
  },
  "devDependencies": {
    "@types/node": "^18.x",
    "@types/react": "^18.x",
    "@types/react-dom": "^18.x",
    "@types/vscode": "^1.85.0",
    "copy-webpack-plugin": "^11.0.0",
    "css-loader": "^6.8.1",
    "path-browserify": "^1.0.1",
    "process": "^0.11.10",
    "style-loader": "^3.3.3",
    "ts-loader": "^9.5.1",
    "typescript": "^5.3.3",
    "webpack": "^5.89.0",
    "webpack-cli": "^5.1.4"
  },
  "dependencies": {
    "clsx": "^2.1.1",
    "lucide-react": "^0.555.0",
    "mermaid": "^11.12.1",
    "openai": "^4.28.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-markdown": "^10.1.0",
    "tailwind-merge": "^3.4.0",
    "tree-sitter-wasms": "^0.1.13",
    "vscode-languageclient": "^9.0.1",
    "web-tree-sitter": "^0.20.8",
    "zod": "^3.22.4"
  }
}

#package-lock.json
{
  "name": "vulntriage-vscode",
  "version": "0.2.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "vulntriage-vscode",
      "version": "0.2.0",
      "dependencies": {
        "clsx": "^2.1.1",
        "lucide-react": "^0.555.0",
        "mermaid": "^11.12.1",
        "openai": "^4.28.0",
        "react": "^18.2.0",
        "react-dom": "^18.2.0",
        "react-markdown": "^10.1.0",
        "tailwind-merge": "^3.4.0",
        "tree-sitter-wasms": "^0.1.13",
        "vscode-languageclient": "^9.0.1",
        "web-tree-sitter": "^0.20.8",
        "zod": "^3.22.4"
      },
      "devDependencies": {
        "@types/node": "^18.x",
        "@types/react": "^18.x",
        "@types/react-dom": "^18.x",
        "@types/vscode": "^1.85.0",
        "copy-webpack-plugin": "^11.0.0",
        "css-loader": "^6.8.1",
        "path-browserify": "^1.0.1",
        "process": "^0.11.10",
        "style-loader": "^3.3.3",
        "ts-loader": "^9.5.1",
        "typescript": "^5.3.3",
        "webpack": "^5.89.0",
        "webpack-cli": "^5.1.4"
      },
      "engines": {
        "vscode": "^1.85.0"
      }
    },
    "node_modules/@antfu/install-pkg": {
      "version": "1.1.0",
      "resolved": "https://registry.npmjs.org/@antfu/install-pkg/-/install-pkg-1.1.0.tgz",
      "integrity": "sha512-MGQsmw10ZyI+EJo45CdSER4zEb+p31LpDAFp2Z3gkSd1yqVZGi0Ebx++YTEMonJy4oChEMLsxZ64j8FH6sSqtQ==",
      "license": "MIT",
      "dependencies": {
        "package-manager-detector": "^1.3.0",
        "tinyexec": "^1.0.1"
      },
      "funding": {
        "url": "https://github.com/sponsors/antfu"
      }
    },
    "node_modules/@braintree/sanitize-url": {
      "version": "7.1.1",
      "resolved": "https://registry.npmjs.org/@braintree/sanitize-url/-/sanitize-url-7.1.1.tgz",
      "integrity": "sha512-i1L7noDNxtFyL5DmZafWy1wRVhGehQmzZaz1HiN5e7iylJMSZR7ekOV7NsIqa5qBldlLrsKv4HbgFUVlQrz8Mw==",
      "license": "MIT"
    },
    "node_modules/@chevrotain/cst-dts-gen": {
      "version": "11.0.3",
      "resolved": "https://registry.npmjs.org/@chevrotain/cst-dts-gen/-/cst-dts-gen-11.0.3.tgz",
      "integrity": "sha512-BvIKpRLeS/8UbfxXxgC33xOumsacaeCKAjAeLyOn7Pcp95HiRbrpl14S+9vaZLolnbssPIUuiUd8IvgkRyt6NQ==",
      "license": "Apache-2.0",
      "dependencies": {
        "@chevrotain/gast": "11.0.3",
        "@chevrotain/types": "11.0.3",
        "lodash-es": "4.17.21"
      }
    },
    "node_modules/@chevrotain/gast": {
      "version": "11.0.3",
      "resolved": "https://registry.npmjs.org/@chevrotain/gast/-/gast-11.0.3.tgz",
      "integrity": "sha512-+qNfcoNk70PyS/uxmj3li5NiECO+2YKZZQMbmjTqRI3Qchu8Hig/Q9vgkHpI3alNjr7M+a2St5pw5w5F6NL5/Q==",
      "license": "Apache-2.0",
      "dependencies": {
        "@chevrotain/types": "11.0.3",
        "lodash-es": "4.17.21"
      }
    },
    "node_modules/@chevrotain/regexp-to-ast": {
      "version": "11.0.3",
      "resolved": "https://registry.npmjs.org/@chevrotain/regexp-to-ast/-/regexp-to-ast-11.0.3.tgz",
      "integrity": "sha512-1fMHaBZxLFvWI067AVbGJav1eRY7N8DDvYCTwGBiE/ytKBgP8azTdgyrKyWZ9Mfh09eHWb5PgTSO8wi7U824RA==",
      "license": "Apache-2.0"
    },
    "node_modules/@chevrotain/types": {
      "version": "11.0.3",
      "resolved": "https://registry.npmjs.org/@chevrotain/types/-/types-11.0.3.tgz",
      "integrity": "sha512-gsiM3G8b58kZC2HaWR50gu6Y1440cHiJ+i3JUvcp/35JchYejb2+5MVeJK0iKThYpAa/P2PYFV4hoi44HD+aHQ==",
      "license": "Apache-2.0"
    },
    "node_modules/@chevrotain/utils": {
      "version": "11.0.3",
      "resolved": "https://registry.npmjs.org/@chevrotain/utils/-/utils-11.0.3.tgz",
      "integrity": "sha512-YslZMgtJUyuMbZ+aKvfF3x1f5liK4mWNxghFRv7jqRR9C3R3fAOGTTKvxXDa2Y1s9zSbcpuO0cAxDYsc9SrXoQ==",
      "license": "Apache-2.0"
    },
    "node_modules/@discoveryjs/json-ext": {
      "version": "0.5.7",
      "resolved": "https://registry.npmjs.org/@discoveryjs/json-ext/-/json-ext-0.5.7.tgz",
      "integrity": "sha512-dBVuXR082gk3jsFp7Rd/JI4kytwGHecnCoTtXFb7DB6CNHp4rg5k1bhg0nWdLGLnOV71lmDzGQaLMy8iPLY0pw==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=10.0.0"
      }
    },
    "node_modules/@iconify/types": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/@iconify/types/-/types-2.0.0.tgz",
      "integrity": "sha512-+wluvCrRhXrhyOmRDJ3q8mux9JkKy5SJ/v8ol2tu4FVjyYvtEzkc/3pK15ET6RKg4b4w4BmTk1+gsCUhf21Ykg==",
      "license": "MIT"
    },
    "node_modules/@iconify/utils": {
      "version": "3.1.0",
      "resolved": "https://registry.npmjs.org/@iconify/utils/-/utils-3.1.0.tgz",
      "integrity": "sha512-Zlzem1ZXhI1iHeeERabLNzBHdOa4VhQbqAcOQaMKuTuyZCpwKbC2R4Dd0Zo3g9EAc+Y4fiarO8HIHRAth7+skw==",
      "license": "MIT",
      "dependencies": {
        "@antfu/install-pkg": "^1.1.0",
        "@iconify/types": "^2.0.0",
        "mlly": "^1.8.0"
      }
    },
    "node_modules/@jridgewell/gen-mapping": {
      "version": "0.3.13",
      "resolved": "https://registry.npmjs.org/@jridgewell/gen-mapping/-/gen-mapping-0.3.13.tgz",
      "integrity": "sha512-2kkt/7niJ6MgEPxF0bYdQ6etZaA+fQvDcLKckhy1yIQOzaoKjBBjSj63/aLVjYE3qhRt5dvM+uUyfCg6UKCBbA==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@jridgewell/sourcemap-codec": "^1.5.0",
        "@jridgewell/trace-mapping": "^0.3.24"
      }
    },
    "node_modules/@jridgewell/resolve-uri": {
      "version": "3.1.2",
      "resolved": "https://registry.npmjs.org/@jridgewell/resolve-uri/-/resolve-uri-3.1.2.tgz",
      "integrity": "sha512-bRISgCIjP20/tbWSPWMEi54QVPRZExkuD9lJL+UIxUKtwVJA8wW1Trb1jMs1RFXo1CBTNZ/5hpC9QvmKWdopKw==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=6.0.0"
      }
    },
    "node_modules/@jridgewell/source-map": {
      "version": "0.3.11",
      "resolved": "https://registry.npmjs.org/@jridgewell/source-map/-/source-map-0.3.11.tgz",
      "integrity": "sha512-ZMp1V8ZFcPG5dIWnQLr3NSI1MiCU7UETdS/A0G8V/XWHvJv3ZsFqutJn1Y5RPmAPX6F3BiE397OqveU/9NCuIA==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@jridgewell/gen-mapping": "^0.3.5",
        "@jridgewell/trace-mapping": "^0.3.25"
      }
    },
    "node_modules/@jridgewell/sourcemap-codec": {
      "version": "1.5.5",
      "resolved": "https://registry.npmjs.org/@jridgewell/sourcemap-codec/-/sourcemap-codec-1.5.5.tgz",
      "integrity": "sha512-cYQ9310grqxueWbl+WuIUIaiUaDcj7WOq5fVhEljNVgRfOUhY9fy2zTvfoqWsnebh8Sl70VScFbICvJnLKB0Og==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/@jridgewell/trace-mapping": {
      "version": "0.3.31",
      "resolved": "https://registry.npmjs.org/@jridgewell/trace-mapping/-/trace-mapping-0.3.31.tgz",
      "integrity": "sha512-zzNR+SdQSDJzc8joaeP8QQoCQr8NuYx2dIIytl1QeBEZHJ9uW6hebsrYgbz8hJwUQao3TWCMtmfV8Nu1twOLAw==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@jridgewell/resolve-uri": "^3.1.0",
        "@jridgewell/sourcemap-codec": "^1.4.14"
      }
    },
    "node_modules/@mermaid-js/parser": {
      "version": "0.6.3",
      "resolved": "https://registry.npmjs.org/@mermaid-js/parser/-/parser-0.6.3.tgz",
      "integrity": "sha512-lnjOhe7zyHjc+If7yT4zoedx2vo4sHaTmtkl1+or8BRTnCtDmcTpAjpzDSfCZrshM5bCoz0GyidzadJAH1xobA==",
      "license": "MIT",
      "dependencies": {
        "langium": "3.3.1"
      }
    },
    "node_modules/@nodelib/fs.scandir": {
      "version": "2.1.5",
      "resolved": "https://registry.npmjs.org/@nodelib/fs.scandir/-/fs.scandir-2.1.5.tgz",
      "integrity": "sha512-vq24Bq3ym5HEQm2NKCr3yXDwjc7vTsEThRDnkp2DK9p1uqLR+DHurm/NOTo0KG7HYHU7eppKZj3MyqYuMBf62g==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@nodelib/fs.stat": "2.0.5",
        "run-parallel": "^1.1.9"
      },
      "engines": {
        "node": ">= 8"
      }
    },
    "node_modules/@nodelib/fs.stat": {
      "version": "2.0.5",
      "resolved": "https://registry.npmjs.org/@nodelib/fs.stat/-/fs.stat-2.0.5.tgz",
      "integrity": "sha512-RkhPPp2zrqDAQA/2jNhnztcPAlv64XdhIp7a7454A5ovI7Bukxgt7MX7udwAu3zg1DcpPU0rz3VV1SeaqvY4+A==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">= 8"
      }
    },
    "node_modules/@nodelib/fs.walk": {
      "version": "1.2.8",
      "resolved": "https://registry.npmjs.org/@nodelib/fs.walk/-/fs.walk-1.2.8.tgz",
      "integrity": "sha512-oGB+UxlgWcgQkgwo8GcEGwemoTFt3FIO9ababBmaGwXIoBKZ+GTy0pP185beGg7Llih/NSHSV2XAs1lnznocSg==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@nodelib/fs.scandir": "2.1.5",
        "fastq": "^1.6.0"
      },
      "engines": {
        "node": ">= 8"
      }
    },
    "node_modules/@types/d3": {
      "version": "7.4.3",
      "resolved": "https://registry.npmjs.org/@types/d3/-/d3-7.4.3.tgz",
      "integrity": "sha512-lZXZ9ckh5R8uiFVt8ogUNf+pIrK4EsWrx2Np75WvF/eTpJ0FMHNhjXk8CKEx/+gpHbNQyJWehbFaTvqmHWB3ww==",
      "license": "MIT",
      "dependencies": {
        "@types/d3-array": "*",
        "@types/d3-axis": "*",
        "@types/d3-brush": "*",
        "@types/d3-chord": "*",
        "@types/d3-color": "*",
        "@types/d3-contour": "*",
        "@types/d3-delaunay": "*",
        "@types/d3-dispatch": "*",
        "@types/d3-drag": "*",
        "@types/d3-dsv": "*",
        "@types/d3-ease": "*",
        "@types/d3-fetch": "*",
        "@types/d3-force": "*",
        "@types/d3-format": "*",
        "@types/d3-geo": "*",
        "@types/d3-hierarchy": "*",
        "@types/d3-interpolate": "*",
        "@types/d3-path": "*",
        "@types/d3-polygon": "*",
        "@types/d3-quadtree": "*",
        "@types/d3-random": "*",
        "@types/d3-scale": "*",
        "@types/d3-scale-chromatic": "*",
        "@types/d3-selection": "*",
        "@types/d3-shape": "*",
        "@types/d3-time": "*",
        "@types/d3-time-format": "*",
        "@types/d3-timer": "*",
        "@types/d3-transition": "*",
        "@types/d3-zoom": "*"
      }
    },
    "node_modules/@types/d3-array": {
      "version": "3.2.2",
      "resolved": "https://registry.npmjs.org/@types/d3-array/-/d3-array-3.2.2.tgz",
      "integrity": "sha512-hOLWVbm7uRza0BYXpIIW5pxfrKe0W+D5lrFiAEYR+pb6w3N2SwSMaJbXdUfSEv+dT4MfHBLtn5js0LAWaO6otw==",
      "license": "MIT"
    },
    "node_modules/@types/d3-axis": {
      "version": "3.0.6",
      "resolved": "https://registry.npmjs.org/@types/d3-axis/-/d3-axis-3.0.6.tgz",
      "integrity": "sha512-pYeijfZuBd87T0hGn0FO1vQ/cgLk6E1ALJjfkC0oJ8cbwkZl3TpgS8bVBLZN+2jjGgg38epgxb2zmoGtSfvgMw==",
      "license": "MIT",
      "dependencies": {
        "@types/d3-selection": "*"
      }
    },
    "node_modules/@types/d3-brush": {
      "version": "3.0.6",
      "resolved": "https://registry.npmjs.org/@types/d3-brush/-/d3-brush-3.0.6.tgz",
      "integrity": "sha512-nH60IZNNxEcrh6L1ZSMNA28rj27ut/2ZmI3r96Zd+1jrZD++zD3LsMIjWlvg4AYrHn/Pqz4CF3veCxGjtbqt7A==",
      "license": "MIT",
      "dependencies": {
        "@types/d3-selection": "*"
      }
    },
    "node_modules/@types/d3-chord": {
      "version": "3.0.6",
      "resolved": "https://registry.npmjs.org/@types/d3-chord/-/d3-chord-3.0.6.tgz",
      "integrity": "sha512-LFYWWd8nwfwEmTZG9PfQxd17HbNPksHBiJHaKuY1XeqscXacsS2tyoo6OdRsjf+NQYeB6XrNL3a25E3gH69lcg==",
      "license": "MIT"
    },
    "node_modules/@types/d3-color": {
      "version": "3.1.3",
      "resolved": "https://registry.npmjs.org/@types/d3-color/-/d3-color-3.1.3.tgz",
      "integrity": "sha512-iO90scth9WAbmgv7ogoq57O9YpKmFBbmoEoCHDB2xMBY0+/KVrqAaCDyCE16dUspeOvIxFFRI+0sEtqDqy2b4A==",
      "license": "MIT"
    },
    "node_modules/@types/d3-contour": {
      "version": "3.0.6",
      "resolved": "https://registry.npmjs.org/@types/d3-contour/-/d3-contour-3.0.6.tgz",
      "integrity": "sha512-BjzLgXGnCWjUSYGfH1cpdo41/hgdWETu4YxpezoztawmqsvCeep+8QGfiY6YbDvfgHz/DkjeIkkZVJavB4a3rg==",
      "license": "MIT",
      "dependencies": {
        "@types/d3-array": "*",
        "@types/geojson": "*"
      }
    },
    "node_modules/@types/d3-delaunay": {
      "version": "6.0.4",
      "resolved": "https://registry.npmjs.org/@types/d3-delaunay/-/d3-delaunay-6.0.4.tgz",
      "integrity": "sha512-ZMaSKu4THYCU6sV64Lhg6qjf1orxBthaC161plr5KuPHo3CNm8DTHiLw/5Eq2b6TsNP0W0iJrUOFscY6Q450Hw==",
      "license": "MIT"
    },
    "node_modules/@types/d3-dispatch": {
      "version": "3.0.7",
      "resolved": "https://registry.npmjs.org/@types/d3-dispatch/-/d3-dispatch-3.0.7.tgz",
      "integrity": "sha512-5o9OIAdKkhN1QItV2oqaE5KMIiXAvDWBDPrD85e58Qlz1c1kI/J0NcqbEG88CoTwJrYe7ntUCVfeUl2UJKbWgA==",
      "license": "MIT"
    },
    "node_modules/@types/d3-drag": {
      "version": "3.0.7",
      "resolved": "https://registry.npmjs.org/@types/d3-drag/-/d3-drag-3.0.7.tgz",
      "integrity": "sha512-HE3jVKlzU9AaMazNufooRJ5ZpWmLIoc90A37WU2JMmeq28w1FQqCZswHZ3xR+SuxYftzHq6WU6KJHvqxKzTxxQ==",
      "license": "MIT",
      "dependencies": {
        "@types/d3-selection": "*"
      }
    },
    "node_modules/@types/d3-dsv": {
      "version": "3.0.7",
      "resolved": "https://registry.npmjs.org/@types/d3-dsv/-/d3-dsv-3.0.7.tgz",
      "integrity": "sha512-n6QBF9/+XASqcKK6waudgL0pf/S5XHPPI8APyMLLUHd8NqouBGLsU8MgtO7NINGtPBtk9Kko/W4ea0oAspwh9g==",
      "license": "MIT"
    },
    "node_modules/@types/d3-ease": {
      "version": "3.0.2",
      "resolved": "https://registry.npmjs.org/@types/d3-ease/-/d3-ease-3.0.2.tgz",
      "integrity": "sha512-NcV1JjO5oDzoK26oMzbILE6HW7uVXOHLQvHshBUW4UMdZGfiY6v5BeQwh9a9tCzv+CeefZQHJt5SRgK154RtiA==",
      "license": "MIT"
    },
    "node_modules/@types/d3-fetch": {
      "version": "3.0.7",
      "resolved": "https://registry.npmjs.org/@types/d3-fetch/-/d3-fetch-3.0.7.tgz",
      "integrity": "sha512-fTAfNmxSb9SOWNB9IoG5c8Hg6R+AzUHDRlsXsDZsNp6sxAEOP0tkP3gKkNSO/qmHPoBFTxNrjDprVHDQDvo5aA==",
      "license": "MIT",
      "dependencies": {
        "@types/d3-dsv": "*"
      }
    },
    "node_modules/@types/d3-force": {
      "version": "3.0.10",
      "resolved": "https://registry.npmjs.org/@types/d3-force/-/d3-force-3.0.10.tgz",
      "integrity": "sha512-ZYeSaCF3p73RdOKcjj+swRlZfnYpK1EbaDiYICEEp5Q6sUiqFaFQ9qgoshp5CzIyyb/yD09kD9o2zEltCexlgw==",
      "license": "MIT"
    },
    "node_modules/@types/d3-format": {
      "version": "3.0.4",
      "resolved": "https://registry.npmjs.org/@types/d3-format/-/d3-format-3.0.4.tgz",
      "integrity": "sha512-fALi2aI6shfg7vM5KiR1wNJnZ7r6UuggVqtDA+xiEdPZQwy/trcQaHnwShLuLdta2rTymCNpxYTiMZX/e09F4g==",
      "license": "MIT"
    },
    "node_modules/@types/d3-geo": {
      "version": "3.1.0",
      "resolved": "https://registry.npmjs.org/@types/d3-geo/-/d3-geo-3.1.0.tgz",
      "integrity": "sha512-856sckF0oP/diXtS4jNsiQw/UuK5fQG8l/a9VVLeSouf1/PPbBE1i1W852zVwKwYCBkFJJB7nCFTbk6UMEXBOQ==",
      "license": "MIT",
      "dependencies": {
        "@types/geojson": "*"
      }
    },
    "node_modules/@types/d3-hierarchy": {
      "version": "3.1.7",
      "resolved": "https://registry.npmjs.org/@types/d3-hierarchy/-/d3-hierarchy-3.1.7.tgz",
      "integrity": "sha512-tJFtNoYBtRtkNysX1Xq4sxtjK8YgoWUNpIiUee0/jHGRwqvzYxkq0hGVbbOGSz+JgFxxRu4K8nb3YpG3CMARtg==",
      "license": "MIT"
    },
    "node_modules/@types/d3-interpolate": {
      "version": "3.0.4",
      "resolved": "https://registry.npmjs.org/@types/d3-interpolate/-/d3-interpolate-3.0.4.tgz",
      "integrity": "sha512-mgLPETlrpVV1YRJIglr4Ez47g7Yxjl1lj7YKsiMCb27VJH9W8NVM6Bb9d8kkpG/uAQS5AmbA48q2IAolKKo1MA==",
      "license": "MIT",
      "dependencies": {
        "@types/d3-color": "*"
      }
    },
    "node_modules/@types/d3-path": {
      "version": "3.1.1",
      "resolved": "https://registry.npmjs.org/@types/d3-path/-/d3-path-3.1.1.tgz",
      "integrity": "sha512-VMZBYyQvbGmWyWVea0EHs/BwLgxc+MKi1zLDCONksozI4YJMcTt8ZEuIR4Sb1MMTE8MMW49v0IwI5+b7RmfWlg==",
      "license": "MIT"
    },
    "node_modules/@types/d3-polygon": {
      "version": "3.0.2",
      "resolved": "https://registry.npmjs.org/@types/d3-polygon/-/d3-polygon-3.0.2.tgz",
      "integrity": "sha512-ZuWOtMaHCkN9xoeEMr1ubW2nGWsp4nIql+OPQRstu4ypeZ+zk3YKqQT0CXVe/PYqrKpZAi+J9mTs05TKwjXSRA==",
      "license": "MIT"
    },
    "node_modules/@types/d3-quadtree": {
      "version": "3.0.6",
      "resolved": "https://registry.npmjs.org/@types/d3-quadtree/-/d3-quadtree-3.0.6.tgz",
      "integrity": "sha512-oUzyO1/Zm6rsxKRHA1vH0NEDG58HrT5icx/azi9MF1TWdtttWl0UIUsjEQBBh+SIkrpd21ZjEv7ptxWys1ncsg==",
      "license": "MIT"
    },
    "node_modules/@types/d3-random": {
      "version": "3.0.3",
      "resolved": "https://registry.npmjs.org/@types/d3-random/-/d3-random-3.0.3.tgz",
      "integrity": "sha512-Imagg1vJ3y76Y2ea0871wpabqp613+8/r0mCLEBfdtqC7xMSfj9idOnmBYyMoULfHePJyxMAw3nWhJxzc+LFwQ==",
      "license": "MIT"
    },
    "node_modules/@types/d3-scale": {
      "version": "4.0.9",
      "resolved": "https://registry.npmjs.org/@types/d3-scale/-/d3-scale-4.0.9.tgz",
      "integrity": "sha512-dLmtwB8zkAeO/juAMfnV+sItKjlsw2lKdZVVy6LRr0cBmegxSABiLEpGVmSJJ8O08i4+sGR6qQtb6WtuwJdvVw==",
      "license": "MIT",
      "dependencies": {
        "@types/d3-time": "*"
      }
    },
    "node_modules/@types/d3-scale-chromatic": {
      "version": "3.1.0",
      "resolved": "https://registry.npmjs.org/@types/d3-scale-chromatic/-/d3-scale-chromatic-3.1.0.tgz",
      "integrity": "sha512-iWMJgwkK7yTRmWqRB5plb1kadXyQ5Sj8V/zYlFGMUBbIPKQScw+Dku9cAAMgJG+z5GYDoMjWGLVOvjghDEFnKQ==",
      "license": "MIT"
    },
    "node_modules/@types/d3-selection": {
      "version": "3.0.11",
      "resolved": "https://registry.npmjs.org/@types/d3-selection/-/d3-selection-3.0.11.tgz",
      "integrity": "sha512-bhAXu23DJWsrI45xafYpkQ4NtcKMwWnAC/vKrd2l+nxMFuvOT3XMYTIj2opv8vq8AO5Yh7Qac/nSeP/3zjTK0w==",
      "license": "MIT"
    },
    "node_modules/@types/d3-shape": {
      "version": "3.1.7",
      "resolved": "https://registry.npmjs.org/@types/d3-shape/-/d3-shape-3.1.7.tgz",
      "integrity": "sha512-VLvUQ33C+3J+8p+Daf+nYSOsjB4GXp19/S/aGo60m9h1v6XaxjiT82lKVWJCfzhtuZ3yD7i/TPeC/fuKLLOSmg==",
      "license": "MIT",
      "dependencies": {
        "@types/d3-path": "*"
      }
    },
    "node_modules/@types/d3-time": {
      "version": "3.0.4",
      "resolved": "https://registry.npmjs.org/@types/d3-time/-/d3-time-3.0.4.tgz",
      "integrity": "sha512-yuzZug1nkAAaBlBBikKZTgzCeA+k1uy4ZFwWANOfKw5z5LRhV0gNA7gNkKm7HoK+HRN0wX3EkxGk0fpbWhmB7g==",
      "license": "MIT"
    },
    "node_modules/@types/d3-time-format": {
      "version": "4.0.3",
      "resolved": "https://registry.npmjs.org/@types/d3-time-format/-/d3-time-format-4.0.3.tgz",
      "integrity": "sha512-5xg9rC+wWL8kdDj153qZcsJ0FWiFt0J5RB6LYUNZjwSnesfblqrI/bJ1wBdJ8OQfncgbJG5+2F+qfqnqyzYxyg==",
      "license": "MIT"
    },
    "node_modules/@types/d3-timer": {
      "version": "3.0.2",
      "resolved": "https://registry.npmjs.org/@types/d3-timer/-/d3-timer-3.0.2.tgz",
      "integrity": "sha512-Ps3T8E8dZDam6fUyNiMkekK3XUsaUEik+idO9/YjPtfj2qruF8tFBXS7XhtE4iIXBLxhmLjP3SXpLhVf21I9Lw==",
      "license": "MIT"
    },
    "node_modules/@types/d3-transition": {
      "version": "3.0.9",
      "resolved": "https://registry.npmjs.org/@types/d3-transition/-/d3-transition-3.0.9.tgz",
      "integrity": "sha512-uZS5shfxzO3rGlu0cC3bjmMFKsXv+SmZZcgp0KD22ts4uGXp5EVYGzu/0YdwZeKmddhcAccYtREJKkPfXkZuCg==",
      "license": "MIT",
      "dependencies": {
        "@types/d3-selection": "*"
      }
    },
    "node_modules/@types/d3-zoom": {
      "version": "3.0.8",
      "resolved": "https://registry.npmjs.org/@types/d3-zoom/-/d3-zoom-3.0.8.tgz",
      "integrity": "sha512-iqMC4/YlFCSlO8+2Ii1GGGliCAY4XdeG748w5vQUbevlbDu0zSjH/+jojorQVBK/se0j6DUFNPBGSqD3YWYnDw==",
      "license": "MIT",
      "dependencies": {
        "@types/d3-interpolate": "*",
        "@types/d3-selection": "*"
      }
    },
    "node_modules/@types/debug": {
      "version": "4.1.12",
      "resolved": "https://registry.npmjs.org/@types/debug/-/debug-4.1.12.tgz",
      "integrity": "sha512-vIChWdVG3LG1SMxEvI/AK+FWJthlrqlTu7fbrlywTkkaONwk/UAGaULXRlf8vkzFBLVm0zkMdCquhL5aOjhXPQ==",
      "license": "MIT",
      "dependencies": {
        "@types/ms": "*"
      }
    },
    "node_modules/@types/eslint": {
      "version": "9.6.1",
      "resolved": "https://registry.npmjs.org/@types/eslint/-/eslint-9.6.1.tgz",
      "integrity": "sha512-FXx2pKgId/WyYo2jXw63kk7/+TY7u7AziEJxJAnSFzHlqTAS3Ync6SvgYAN/k4/PQpnnVuzoMuVnByKK2qp0ag==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@types/estree": "*",
        "@types/json-schema": "*"
      }
    },
    "node_modules/@types/eslint-scope": {
      "version": "3.7.7",
      "resolved": "https://registry.npmjs.org/@types/eslint-scope/-/eslint-scope-3.7.7.tgz",
      "integrity": "sha512-MzMFlSLBqNF2gcHWO0G1vP/YQyfvrxZ0bF+u7mzUdZ1/xK4A4sru+nraZz5i3iEIk1l1uyicaDVTB4QbbEkAYg==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@types/eslint": "*",
        "@types/estree": "*"
      }
    },
    "node_modules/@types/estree": {
      "version": "1.0.8",
      "resolved": "https://registry.npmjs.org/@types/estree/-/estree-1.0.8.tgz",
      "integrity": "sha512-dWHzHa2WqEXI/O1E9OjrocMTKJl2mSrEolh1Iomrv6U+JuNwaHXsXx9bLu5gG7BUWFIN0skIQJQ/L1rIex4X6w==",
      "license": "MIT"
    },
    "node_modules/@types/estree-jsx": {
      "version": "1.0.5",
      "resolved": "https://registry.npmjs.org/@types/estree-jsx/-/estree-jsx-1.0.5.tgz",
      "integrity": "sha512-52CcUVNFyfb1A2ALocQw/Dd1BQFNmSdkuC3BkZ6iqhdMfQz7JWOFRuJFloOzjk+6WijU56m9oKXFAXc7o3Towg==",
      "license": "MIT",
      "dependencies": {
        "@types/estree": "*"
      }
    },
    "node_modules/@types/geojson": {
      "version": "7946.0.16",
      "resolved": "https://registry.npmjs.org/@types/geojson/-/geojson-7946.0.16.tgz",
      "integrity": "sha512-6C8nqWur3j98U6+lXDfTUWIfgvZU+EumvpHKcYjujKH7woYyLj2sUmff0tRhrqM7BohUw7Pz3ZB1jj2gW9Fvmg==",
      "license": "MIT"
    },
    "node_modules/@types/hast": {
      "version": "3.0.4",
      "resolved": "https://registry.npmjs.org/@types/hast/-/hast-3.0.4.tgz",
      "integrity": "sha512-WPs+bbQw5aCj+x6laNGWLH3wviHtoCv/P3+otBhbOhJgG8qtpdAMlTCxLtsTWA7LH1Oh/bFCHsBn0TPS5m30EQ==",
      "license": "MIT",
      "dependencies": {
        "@types/unist": "*"
      }
    },
    "node_modules/@types/json-schema": {
      "version": "7.0.15",
      "resolved": "https://registry.npmjs.org/@types/json-schema/-/json-schema-7.0.15.tgz",
      "integrity": "sha512-5+fP8P8MFNC+AyZCDxrB2pkZFPGzqQWUzpSeuuVLvm8VMcorNYavBqoFcxK8bQz4Qsbn4oUEEem4wDLfcysGHA==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/@types/mdast": {
      "version": "4.0.4",
      "resolved": "https://registry.npmjs.org/@types/mdast/-/mdast-4.0.4.tgz",
      "integrity": "sha512-kGaNbPh1k7AFzgpud/gMdvIm5xuECykRR+JnWKQno9TAXVa6WIVCGTPvYGekIDL4uwCZQSYbUxNBSb1aUo79oA==",
      "license": "MIT",
      "dependencies": {
        "@types/unist": "*"
      }
    },
    "node_modules/@types/ms": {
      "version": "2.1.0",
      "resolved": "https://registry.npmjs.org/@types/ms/-/ms-2.1.0.tgz",
      "integrity": "sha512-GsCCIZDE/p3i96vtEqx+7dBUGXrc7zeSK3wwPHIaRThS+9OhWIXRqzs4d6k1SVU8g91DrNRWxWUGhp5KXQb2VA==",
      "license": "MIT"
    },
    "node_modules/@types/node": {
      "version": "18.19.130",
      "resolved": "https://registry.npmjs.org/@types/node/-/node-18.19.130.tgz",
      "integrity": "sha512-GRaXQx6jGfL8sKfaIDD6OupbIHBr9jv7Jnaml9tB7l4v068PAOXqfcujMMo5PhbIs6ggR1XODELqahT2R8v0fg==",
      "license": "MIT",
      "dependencies": {
        "undici-types": "~5.26.4"
      }
    },
    "node_modules/@types/node-fetch": {
      "version": "2.6.13",
      "resolved": "https://registry.npmjs.org/@types/node-fetch/-/node-fetch-2.6.13.tgz",
      "integrity": "sha512-QGpRVpzSaUs30JBSGPjOg4Uveu384erbHBoT1zeONvyCfwQxIkUshLAOqN/k9EjGviPRmWTTe6aH2qySWKTVSw==",
      "license": "MIT",
      "dependencies": {
        "@types/node": "*",
        "form-data": "^4.0.4"
      }
    },
    "node_modules/@types/prop-types": {
      "version": "15.7.15",
      "resolved": "https://registry.npmjs.org/@types/prop-types/-/prop-types-15.7.15.tgz",
      "integrity": "sha512-F6bEyamV9jKGAFBEmlQnesRPGOQqS2+Uwi0Em15xenOxHaf2hv6L8YCVn3rPdPJOiJfPiCnLIRyvwVaqMY3MIw==",
      "license": "MIT"
    },
    "node_modules/@types/react": {
      "version": "18.3.27",
      "resolved": "https://registry.npmjs.org/@types/react/-/react-18.3.27.tgz",
      "integrity": "sha512-cisd7gxkzjBKU2GgdYrTdtQx1SORymWyaAFhaxQPK9bYO9ot3Y5OikQRvY0VYQtvwjeQnizCINJAenh/V7MK2w==",
      "license": "MIT",
      "peer": true,
      "dependencies": {
        "@types/prop-types": "*",
        "csstype": "^3.2.2"
      }
    },
    "node_modules/@types/react-dom": {
      "version": "18.3.7",
      "resolved": "https://registry.npmjs.org/@types/react-dom/-/react-dom-18.3.7.tgz",
      "integrity": "sha512-MEe3UeoENYVFXzoXEWsvcpg6ZvlrFNlOQ7EOsvhI3CfAXwzPfO8Qwuxd40nepsYKqyyVQnTdEfv68q91yLcKrQ==",
      "dev": true,
      "license": "MIT",
      "peerDependencies": {
        "@types/react": "^18.0.0"
      }
    },
    "node_modules/@types/trusted-types": {
      "version": "2.0.7",
      "resolved": "https://registry.npmjs.org/@types/trusted-types/-/trusted-types-2.0.7.tgz",
      "integrity": "sha512-ScaPdn1dQczgbl0QFTeTOmVHFULt394XJgOQNoyVhZ6r2vLnMLJfBPd53SB52T/3G36VI1/g2MZaX0cwDuXsfw==",
      "license": "MIT",
      "optional": true
    },
    "node_modules/@types/unist": {
      "version": "3.0.3",
      "resolved": "https://registry.npmjs.org/@types/unist/-/unist-3.0.3.tgz",
      "integrity": "sha512-ko/gIFJRv177XgZsZcBwnqJN5x/Gien8qNOn0D5bQU/zAzVf9Zt3BlcUiLqhV9y4ARk0GbT3tnUiPNgnTXzc/Q==",
      "license": "MIT"
    },
    "node_modules/@types/vscode": {
      "version": "1.106.1",
      "resolved": "https://registry.npmjs.org/@types/vscode/-/vscode-1.106.1.tgz",
      "integrity": "sha512-R/HV8u2h8CAddSbX8cjpdd7B8/GnE4UjgjpuGuHcbp1xV6yh4OeqU4L1pKjlwujCrSFS0MOpwJAIs/NexMB1fQ==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/@ungap/structured-clone": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/@ungap/structured-clone/-/structured-clone-1.3.0.tgz",
      "integrity": "sha512-WmoN8qaIAo7WTYWbAZuG8PYEhn5fkz7dZrqTBZ7dtt//lL2Gwms1IcnQ5yHqjDfX8Ft5j4YzDM23f87zBfDe9g==",
      "license": "ISC"
    },
    "node_modules/@webassemblyjs/ast": {
      "version": "1.14.1",
      "resolved": "https://registry.npmjs.org/@webassemblyjs/ast/-/ast-1.14.1.tgz",
      "integrity": "sha512-nuBEDgQfm1ccRp/8bCQrx1frohyufl4JlbMMZ4P1wpeOfDhF6FQkxZJ1b/e+PLwr6X1Nhw6OLme5usuBWYBvuQ==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@webassemblyjs/helper-numbers": "1.13.2",
        "@webassemblyjs/helper-wasm-bytecode": "1.13.2"
      }
    },
    "node_modules/@webassemblyjs/floating-point-hex-parser": {
      "version": "1.13.2",
      "resolved": "https://registry.npmjs.org/@webassemblyjs/floating-point-hex-parser/-/floating-point-hex-parser-1.13.2.tgz",
      "integrity": "sha512-6oXyTOzbKxGH4steLbLNOu71Oj+C8Lg34n6CqRvqfS2O71BxY6ByfMDRhBytzknj9yGUPVJ1qIKhRlAwO1AovA==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/@webassemblyjs/helper-api-error": {
      "version": "1.13.2",
      "resolved": "https://registry.npmjs.org/@webassemblyjs/helper-api-error/-/helper-api-error-1.13.2.tgz",
      "integrity": "sha512-U56GMYxy4ZQCbDZd6JuvvNV/WFildOjsaWD3Tzzvmw/mas3cXzRJPMjP83JqEsgSbyrmaGjBfDtV7KDXV9UzFQ==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/@webassemblyjs/helper-buffer": {
      "version": "1.14.1",
      "resolved": "https://registry.npmjs.org/@webassemblyjs/helper-buffer/-/helper-buffer-1.14.1.tgz",
      "integrity": "sha512-jyH7wtcHiKssDtFPRB+iQdxlDf96m0E39yb0k5uJVhFGleZFoNw1c4aeIcVUPPbXUVJ94wwnMOAqUHyzoEPVMA==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/@webassemblyjs/helper-numbers": {
      "version": "1.13.2",
      "resolved": "https://registry.npmjs.org/@webassemblyjs/helper-numbers/-/helper-numbers-1.13.2.tgz",
      "integrity": "sha512-FE8aCmS5Q6eQYcV3gI35O4J789wlQA+7JrqTTpJqn5emA4U2hvwJmvFRC0HODS+3Ye6WioDklgd6scJ3+PLnEA==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@webassemblyjs/floating-point-hex-parser": "1.13.2",
        "@webassemblyjs/helper-api-error": "1.13.2",
        "@xtuc/long": "4.2.2"
      }
    },
    "node_modules/@webassemblyjs/helper-wasm-bytecode": {
      "version": "1.13.2",
      "resolved": "https://registry.npmjs.org/@webassemblyjs/helper-wasm-bytecode/-/helper-wasm-bytecode-1.13.2.tgz",
      "integrity": "sha512-3QbLKy93F0EAIXLh0ogEVR6rOubA9AoZ+WRYhNbFyuB70j3dRdwH9g+qXhLAO0kiYGlg3TxDV+I4rQTr/YNXkA==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/@webassemblyjs/helper-wasm-section": {
      "version": "1.14.1",
      "resolved": "https://registry.npmjs.org/@webassemblyjs/helper-wasm-section/-/helper-wasm-section-1.14.1.tgz",
      "integrity": "sha512-ds5mXEqTJ6oxRoqjhWDU83OgzAYjwsCV8Lo/N+oRsNDmx/ZDpqalmrtgOMkHwxsG0iI//3BwWAErYRHtgn0dZw==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@webassemblyjs/ast": "1.14.1",
        "@webassemblyjs/helper-buffer": "1.14.1",
        "@webassemblyjs/helper-wasm-bytecode": "1.13.2",
        "@webassemblyjs/wasm-gen": "1.14.1"
      }
    },
    "node_modules/@webassemblyjs/ieee754": {
      "version": "1.13.2",
      "resolved": "https://registry.npmjs.org/@webassemblyjs/ieee754/-/ieee754-1.13.2.tgz",
      "integrity": "sha512-4LtOzh58S/5lX4ITKxnAK2USuNEvpdVV9AlgGQb8rJDHaLeHciwG4zlGr0j/SNWlr7x3vO1lDEsuePvtcDNCkw==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@xtuc/ieee754": "^1.2.0"
      }
    },
    "node_modules/@webassemblyjs/leb128": {
      "version": "1.13.2",
      "resolved": "https://registry.npmjs.org/@webassemblyjs/leb128/-/leb128-1.13.2.tgz",
      "integrity": "sha512-Lde1oNoIdzVzdkNEAWZ1dZ5orIbff80YPdHx20mrHwHrVNNTjNr8E3xz9BdpcGqRQbAEa+fkrCb+fRFTl/6sQw==",
      "dev": true,
      "license": "Apache-2.0",
      "dependencies": {
        "@xtuc/long": "4.2.2"
      }
    },
    "node_modules/@webassemblyjs/utf8": {
      "version": "1.13.2",
      "resolved": "https://registry.npmjs.org/@webassemblyjs/utf8/-/utf8-1.13.2.tgz",
      "integrity": "sha512-3NQWGjKTASY1xV5m7Hr0iPeXD9+RDobLll3T9d2AO+g3my8xy5peVyjSag4I50mR1bBSN/Ct12lo+R9tJk0NZQ==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/@webassemblyjs/wasm-edit": {
      "version": "1.14.1",
      "resolved": "https://registry.npmjs.org/@webassemblyjs/wasm-edit/-/wasm-edit-1.14.1.tgz",
      "integrity": "sha512-RNJUIQH/J8iA/1NzlE4N7KtyZNHi3w7at7hDjvRNm5rcUXa00z1vRz3glZoULfJ5mpvYhLybmVcwcjGrC1pRrQ==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@webassemblyjs/ast": "1.14.1",
        "@webassemblyjs/helper-buffer": "1.14.1",
        "@webassemblyjs/helper-wasm-bytecode": "1.13.2",
        "@webassemblyjs/helper-wasm-section": "1.14.1",
        "@webassemblyjs/wasm-gen": "1.14.1",
        "@webassemblyjs/wasm-opt": "1.14.1",
        "@webassemblyjs/wasm-parser": "1.14.1",
        "@webassemblyjs/wast-printer": "1.14.1"
      }
    },
    "node_modules/@webassemblyjs/wasm-gen": {
      "version": "1.14.1",
      "resolved": "https://registry.npmjs.org/@webassemblyjs/wasm-gen/-/wasm-gen-1.14.1.tgz",
      "integrity": "sha512-AmomSIjP8ZbfGQhumkNvgC33AY7qtMCXnN6bL2u2Js4gVCg8fp735aEiMSBbDR7UQIj90n4wKAFUSEd0QN2Ukg==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@webassemblyjs/ast": "1.14.1",
        "@webassemblyjs/helper-wasm-bytecode": "1.13.2",
        "@webassemblyjs/ieee754": "1.13.2",
        "@webassemblyjs/leb128": "1.13.2",
        "@webassemblyjs/utf8": "1.13.2"
      }
    },
    "node_modules/@webassemblyjs/wasm-opt": {
      "version": "1.14.1",
      "resolved": "https://registry.npmjs.org/@webassemblyjs/wasm-opt/-/wasm-opt-1.14.1.tgz",
      "integrity": "sha512-PTcKLUNvBqnY2U6E5bdOQcSM+oVP/PmrDY9NzowJjislEjwP/C4an2303MCVS2Mg9d3AJpIGdUFIQQWbPds0Sw==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@webassemblyjs/ast": "1.14.1",
        "@webassemblyjs/helper-buffer": "1.14.1",
        "@webassemblyjs/wasm-gen": "1.14.1",
        "@webassemblyjs/wasm-parser": "1.14.1"
      }
    },
    "node_modules/@webassemblyjs/wasm-parser": {
      "version": "1.14.1",
      "resolved": "https://registry.npmjs.org/@webassemblyjs/wasm-parser/-/wasm-parser-1.14.1.tgz",
      "integrity": "sha512-JLBl+KZ0R5qB7mCnud/yyX08jWFw5MsoalJ1pQ4EdFlgj9VdXKGuENGsiCIjegI1W7p91rUlcB/LB5yRJKNTcQ==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@webassemblyjs/ast": "1.14.1",
        "@webassemblyjs/helper-api-error": "1.13.2",
        "@webassemblyjs/helper-wasm-bytecode": "1.13.2",
        "@webassemblyjs/ieee754": "1.13.2",
        "@webassemblyjs/leb128": "1.13.2",
        "@webassemblyjs/utf8": "1.13.2"
      }
    },
    "node_modules/@webassemblyjs/wast-printer": {
      "version": "1.14.1",
      "resolved": "https://registry.npmjs.org/@webassemblyjs/wast-printer/-/wast-printer-1.14.1.tgz",
      "integrity": "sha512-kPSSXE6De1XOR820C90RIo2ogvZG+c3KiHzqUoO/F34Y2shGzesfqv7o57xrxovZJH/MetF5UjroJ/R/3isoiw==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@webassemblyjs/ast": "1.14.1",
        "@xtuc/long": "4.2.2"
      }
    },
    "node_modules/@webpack-cli/configtest": {
      "version": "2.1.1",
      "resolved": "https://registry.npmjs.org/@webpack-cli/configtest/-/configtest-2.1.1.tgz",
      "integrity": "sha512-wy0mglZpDSiSS0XHrVR+BAdId2+yxPSoJW8fsna3ZpYSlufjvxnP4YbKTCBZnNIcGN4r6ZPXV55X4mYExOfLmw==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=14.15.0"
      },
      "peerDependencies": {
        "webpack": "5.x.x",
        "webpack-cli": "5.x.x"
      }
    },
    "node_modules/@webpack-cli/info": {
      "version": "2.0.2",
      "resolved": "https://registry.npmjs.org/@webpack-cli/info/-/info-2.0.2.tgz",
      "integrity": "sha512-zLHQdI/Qs1UyT5UBdWNqsARasIA+AaF8t+4u2aS2nEpBQh2mWIVb8qAklq0eUENnC5mOItrIB4LiS9xMtph18A==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=14.15.0"
      },
      "peerDependencies": {
        "webpack": "5.x.x",
        "webpack-cli": "5.x.x"
      }
    },
    "node_modules/@webpack-cli/serve": {
      "version": "2.0.5",
      "resolved": "https://registry.npmjs.org/@webpack-cli/serve/-/serve-2.0.5.tgz",
      "integrity": "sha512-lqaoKnRYBdo1UgDX8uF24AfGMifWK19TxPmM5FHc2vAGxrJ/qtyUyFBWoY1tISZdelsQ5fBcOusifo5o5wSJxQ==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=14.15.0"
      },
      "peerDependencies": {
        "webpack": "5.x.x",
        "webpack-cli": "5.x.x"
      },
      "peerDependenciesMeta": {
        "webpack-dev-server": {
          "optional": true
        }
      }
    },
    "node_modules/@xtuc/ieee754": {
      "version": "1.2.0",
      "resolved": "https://registry.npmjs.org/@xtuc/ieee754/-/ieee754-1.2.0.tgz",
      "integrity": "sha512-DX8nKgqcGwsc0eJSqYt5lwP4DH5FlHnmuWWBRy7X0NcaGR0ZtuyeESgMwTYVEtxmsNGY+qit4QYT/MIYTOTPeA==",
      "dev": true,
      "license": "BSD-3-Clause"
    },
    "node_modules/@xtuc/long": {
      "version": "4.2.2",
      "resolved": "https://registry.npmjs.org/@xtuc/long/-/long-4.2.2.tgz",
      "integrity": "sha512-NuHqBY1PB/D8xU6s/thBgOAiAP7HOYDQ32+BFZILJ8ivkUkAHQnWfn6WhL79Owj1qmUnoN/YPhktdIoucipkAQ==",
      "dev": true,
      "license": "Apache-2.0"
    },
    "node_modules/abort-controller": {
      "version": "3.0.0",
      "resolved": "https://registry.npmjs.org/abort-controller/-/abort-controller-3.0.0.tgz",
      "integrity": "sha512-h8lQ8tacZYnR3vNQTgibj+tODHI5/+l06Au2Pcriv/Gmet0eaj4TwWH41sO9wnHDiQsEj19q0drzdWdeAHtweg==",
      "license": "MIT",
      "dependencies": {
        "event-target-shim": "^5.0.0"
      },
      "engines": {
        "node": ">=6.5"
      }
    },
    "node_modules/acorn": {
      "version": "8.15.0",
      "resolved": "https://registry.npmjs.org/acorn/-/acorn-8.15.0.tgz",
      "integrity": "sha512-NZyJarBfL7nWwIq+FDL6Zp/yHEhePMNnnJ0y3qfieCrmNvYct8uvtiV41UvlSe6apAfk0fY1FbWx+NwfmpvtTg==",
      "license": "MIT",
      "peer": true,
      "bin": {
        "acorn": "bin/acorn"
      },
      "engines": {
        "node": ">=0.4.0"
      }
    },
    "node_modules/acorn-import-phases": {
      "version": "1.0.4",
      "resolved": "https://registry.npmjs.org/acorn-import-phases/-/acorn-import-phases-1.0.4.tgz",
      "integrity": "sha512-wKmbr/DDiIXzEOiWrTTUcDm24kQ2vGfZQvM2fwg2vXqR5uW6aapr7ObPtj1th32b9u90/Pf4AItvdTh42fBmVQ==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=10.13.0"
      },
      "peerDependencies": {
        "acorn": "^8.14.0"
      }
    },
    "node_modules/agentkeepalive": {
      "version": "4.6.0",
      "resolved": "https://registry.npmjs.org/agentkeepalive/-/agentkeepalive-4.6.0.tgz",
      "integrity": "sha512-kja8j7PjmncONqaTsB8fQ+wE2mSU2DJ9D4XKoJ5PFWIdRMa6SLSN1ff4mOr4jCbfRSsxR4keIiySJU0N9T5hIQ==",
      "license": "MIT",
      "dependencies": {
        "humanize-ms": "^1.2.1"
      },
      "engines": {
        "node": ">= 8.0.0"
      }
    },
    "node_modules/ajv": {
      "version": "8.17.1",
      "resolved": "https://registry.npmjs.org/ajv/-/ajv-8.17.1.tgz",
      "integrity": "sha512-B/gBuNg5SiMTrPkC+A2+cW0RszwxYmn6VYxB/inlBStS5nx6xHIt/ehKRhIMhqusl7a8LjQoZnjCs5vhwxOQ1g==",
      "dev": true,
      "license": "MIT",
      "peer": true,
      "dependencies": {
        "fast-deep-equal": "^3.1.3",
        "fast-uri": "^3.0.1",
        "json-schema-traverse": "^1.0.0",
        "require-from-string": "^2.0.2"
      },
      "funding": {
        "type": "github",
        "url": "https://github.com/sponsors/epoberezkin"
      }
    },
    "node_modules/ajv-formats": {
      "version": "2.1.1",
      "resolved": "https://registry.npmjs.org/ajv-formats/-/ajv-formats-2.1.1.tgz",
      "integrity": "sha512-Wx0Kx52hxE7C18hkMEggYlEifqWZtYaRgouJor+WMdPnQyEK13vgEWyVNup7SoeeoLMsr4kf5h6dOW11I15MUA==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "ajv": "^8.0.0"
      },
      "peerDependencies": {
        "ajv": "^8.0.0"
      },
      "peerDependenciesMeta": {
        "ajv": {
          "optional": true
        }
      }
    },
    "node_modules/ajv-keywords": {
      "version": "5.1.0",
      "resolved": "https://registry.npmjs.org/ajv-keywords/-/ajv-keywords-5.1.0.tgz",
      "integrity": "sha512-YCS/JNFAUyr5vAuhk1DWm1CBxRHW9LbJ2ozWeemrIqpbsqKjHVxYPyi5GC0rjZIT5JxJ3virVTS8wk4i/Z+krw==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "fast-deep-equal": "^3.1.3"
      },
      "peerDependencies": {
        "ajv": "^8.8.2"
      }
    },
    "node_modules/ansi-styles": {
      "version": "4.3.0",
      "resolved": "https://registry.npmjs.org/ansi-styles/-/ansi-styles-4.3.0.tgz",
      "integrity": "sha512-zbB9rCJAT1rbjiVDb2hqKFHNYLxgtk8NURxZ3IZwD3F6NtxbXZQCnnSi1Lkx+IDohdPlFp222wVALIheZJQSEg==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "color-convert": "^2.0.1"
      },
      "engines": {
        "node": ">=8"
      },
      "funding": {
        "url": "https://github.com/chalk/ansi-styles?sponsor=1"
      }
    },
    "node_modules/asynckit": {
      "version": "0.4.0",
      "resolved": "https://registry.npmjs.org/asynckit/-/asynckit-0.4.0.tgz",
      "integrity": "sha512-Oei9OH4tRh0YqU3GxhX79dM/mwVgvbZJaSNaRk+bshkj0S5cfHcgYakreBjrHwatXKbz+IoIdYLxrKim2MjW0Q==",
      "license": "MIT"
    },
    "node_modules/bail": {
      "version": "2.0.2",
      "resolved": "https://registry.npmjs.org/bail/-/bail-2.0.2.tgz",
      "integrity": "sha512-0xO6mYd7JB2YesxDKplafRpsiOzPt9V02ddPCLbY1xYGPOX24NTyN50qnUxgCPcSoYMhKpAuBTjQoRZCAkUDRw==",
      "license": "MIT",
      "funding": {
        "type": "github",
        "url": "https://github.com/sponsors/wooorm"
      }
    },
    "node_modules/balanced-match": {
      "version": "1.0.2",
      "resolved": "https://registry.npmjs.org/balanced-match/-/balanced-match-1.0.2.tgz",
      "integrity": "sha512-3oSeUO0TMV67hN1AmbXsK4yaqU7tjiHlbxRDZOpH0KW9+CeX4bRAaX0Anxt0tx2MrpRpWwQaPwIlISEJhYU5Pw==",
      "license": "MIT"
    },
    "node_modules/baseline-browser-mapping": {
      "version": "2.8.32",
      "resolved": "https://registry.npmjs.org/baseline-browser-mapping/-/baseline-browser-mapping-2.8.32.tgz",
      "integrity": "sha512-OPz5aBThlyLFgxyhdwf/s2+8ab3OvT7AdTNvKHBwpXomIYeXqpUUuT8LrdtxZSsWJ4R4CU1un4XGh5Ez3nlTpw==",
      "dev": true,
      "license": "Apache-2.0",
      "bin": {
        "baseline-browser-mapping": "dist/cli.js"
      }
    },
    "node_modules/brace-expansion": {
      "version": "2.0.2",
      "resolved": "https://registry.npmjs.org/brace-expansion/-/brace-expansion-2.0.2.tgz",
      "integrity": "sha512-Jt0vHyM+jmUBqojB7E1NIYadt0vI0Qxjxd2TErW94wDz+E2LAm5vKMXXwg6ZZBTHPuUlDgQHKXvjGBdfcF1ZDQ==",
      "license": "MIT",
      "dependencies": {
        "balanced-match": "^1.0.0"
      }
    },
    "node_modules/braces": {
      "version": "3.0.3",
      "resolved": "https://registry.npmjs.org/braces/-/braces-3.0.3.tgz",
      "integrity": "sha512-yQbXgO/OSZVD2IsiLlro+7Hf6Q18EJrKSEsdoMzKePKXct3gvD8oLcOQdIzGupr5Fj+EDe8gO/lxc1BzfMpxvA==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "fill-range": "^7.1.1"
      },
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/browserslist": {
      "version": "4.28.0",
      "resolved": "https://registry.npmjs.org/browserslist/-/browserslist-4.28.0.tgz",
      "integrity": "sha512-tbydkR/CxfMwelN0vwdP/pLkDwyAASZ+VfWm4EOwlB6SWhx1sYnWLqo8N5j0rAzPfzfRaxt0mM/4wPU/Su84RQ==",
      "dev": true,
      "funding": [
        {
          "type": "opencollective",
          "url": "https://opencollective.com/browserslist"
        },
        {
          "type": "tidelift",
          "url": "https://tidelift.com/funding/github/npm/browserslist"
        },
        {
          "type": "github",
          "url": "https://github.com/sponsors/ai"
        }
      ],
      "license": "MIT",
      "peer": true,
      "dependencies": {
        "baseline-browser-mapping": "^2.8.25",
        "caniuse-lite": "^1.0.30001754",
        "electron-to-chromium": "^1.5.249",
        "node-releases": "^2.0.27",
        "update-browserslist-db": "^1.1.4"
      },
      "bin": {
        "browserslist": "cli.js"
      },
      "engines": {
        "node": "^6 || ^7 || ^8 || ^9 || ^10 || ^11 || ^12 || >=13.7"
      }
    },
    "node_modules/buffer-from": {
      "version": "1.1.2",
      "resolved": "https://registry.npmjs.org/buffer-from/-/buffer-from-1.1.2.tgz",
      "integrity": "sha512-E+XQCRwSbaaiChtv6k6Dwgc+bx+Bs6vuKJHHl5kox/BaKbhiXzqQOwK4cO22yElGp2OCmjwVhT3HmxgyPGnJfQ==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/call-bind-apply-helpers": {
      "version": "1.0.2",
      "resolved": "https://registry.npmjs.org/call-bind-apply-helpers/-/call-bind-apply-helpers-1.0.2.tgz",
      "integrity": "sha512-Sp1ablJ0ivDkSzjcaJdxEunN5/XvksFJ2sMBFfq6x0ryhQV/2b/KwFe21cMpmHtPOSij8K99/wSfoEuTObmuMQ==",
      "license": "MIT",
      "dependencies": {
        "es-errors": "^1.3.0",
        "function-bind": "^1.1.2"
      },
      "engines": {
        "node": ">= 0.4"
      }
    },
    "node_modules/caniuse-lite": {
      "version": "1.0.30001757",
      "resolved": "https://registry.npmjs.org/caniuse-lite/-/caniuse-lite-1.0.30001757.tgz",
      "integrity": "sha512-r0nnL/I28Zi/yjk1el6ilj27tKcdjLsNqAOZr0yVjWPrSQyHgKI2INaEWw21bAQSv2LXRt1XuCS/GomNpWOxsQ==",
      "dev": true,
      "funding": [
        {
          "type": "opencollective",
          "url": "https://opencollective.com/browserslist"
        },
        {
          "type": "tidelift",
          "url": "https://tidelift.com/funding/github/npm/caniuse-lite"
        },
        {
          "type": "github",
          "url": "https://github.com/sponsors/ai"
        }
      ],
      "license": "CC-BY-4.0"
    },
    "node_modules/ccount": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/ccount/-/ccount-2.0.1.tgz",
      "integrity": "sha512-eyrF0jiFpY+3drT6383f1qhkbGsLSifNAjA61IUjZjmLCWjItY6LB9ft9YhoDgwfmclB2zhu51Lc7+95b8NRAg==",
      "license": "MIT",
      "funding": {
        "type": "github",
        "url": "https://github.com/sponsors/wooorm"
      }
    },
    "node_modules/chalk": {
      "version": "4.1.2",
      "resolved": "https://registry.npmjs.org/chalk/-/chalk-4.1.2.tgz",
      "integrity": "sha512-oKnbhFyRIXpUuez8iBMmyEa4nbj4IOQyuhc/wy9kY7/WVPcwIO9VA668Pu8RkO7+0G76SLROeyw9CpQ061i4mA==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "ansi-styles": "^4.1.0",
        "supports-color": "^7.1.0"
      },
      "engines": {
        "node": ">=10"
      },
      "funding": {
        "url": "https://github.com/chalk/chalk?sponsor=1"
      }
    },
    "node_modules/character-entities": {
      "version": "2.0.2",
      "resolved": "https://registry.npmjs.org/character-entities/-/character-entities-2.0.2.tgz",
      "integrity": "sha512-shx7oQ0Awen/BRIdkjkvz54PnEEI/EjwXDSIZp86/KKdbafHh1Df/RYGBhn4hbe2+uKC9FnT5UCEdyPz3ai9hQ==",
      "license": "MIT",
      "funding": {
        "type": "github",
        "url": "https://github.com/sponsors/wooorm"
      }
    },
    "node_modules/character-entities-html4": {
      "version": "2.1.0",
      "resolved": "https://registry.npmjs.org/character-entities-html4/-/character-entities-html4-2.1.0.tgz",
      "integrity": "sha512-1v7fgQRj6hnSwFpq1Eu0ynr/CDEw0rXo2B61qXrLNdHZmPKgb7fqS1a2JwF0rISo9q77jDI8VMEHoApn8qDoZA==",
      "license": "MIT",
      "funding": {
        "type": "github",
        "url": "https://github.com/sponsors/wooorm"
      }
    },
    "node_modules/character-entities-legacy": {
      "version": "3.0.0",
      "resolved": "https://registry.npmjs.org/character-entities-legacy/-/character-entities-legacy-3.0.0.tgz",
      "integrity": "sha512-RpPp0asT/6ufRm//AJVwpViZbGM/MkjQFxJccQRHmISF/22NBtsHqAWmL+/pmkPWoIUJdWyeVleTl1wydHATVQ==",
      "license": "MIT",
      "funding": {
        "type": "github",
        "url": "https://github.com/sponsors/wooorm"
      }
    },
    "node_modules/character-reference-invalid": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/character-reference-invalid/-/character-reference-invalid-2.0.1.tgz",
      "integrity": "sha512-iBZ4F4wRbyORVsu0jPV7gXkOsGYjGHPmAyv+HiHG8gi5PtC9KI2j1+v8/tlibRvjoWX027ypmG/n0HtO5t7unw==",
      "license": "MIT",
      "funding": {
        "type": "github",
        "url": "https://github.com/sponsors/wooorm"
      }
    },
    "node_modules/chevrotain": {
      "version": "11.0.3",
      "resolved": "https://registry.npmjs.org/chevrotain/-/chevrotain-11.0.3.tgz",
      "integrity": "sha512-ci2iJH6LeIkvP9eJW6gpueU8cnZhv85ELY8w8WiFtNjMHA5ad6pQLaJo9mEly/9qUyCpvqX8/POVUTf18/HFdw==",
      "license": "Apache-2.0",
      "peer": true,
      "dependencies": {
        "@chevrotain/cst-dts-gen": "11.0.3",
        "@chevrotain/gast": "11.0.3",
        "@chevrotain/regexp-to-ast": "11.0.3",
        "@chevrotain/types": "11.0.3",
        "@chevrotain/utils": "11.0.3",
        "lodash-es": "4.17.21"
      }
    },
    "node_modules/chevrotain-allstar": {
      "version": "0.3.1",
      "resolved": "https://registry.npmjs.org/chevrotain-allstar/-/chevrotain-allstar-0.3.1.tgz",
      "integrity": "sha512-b7g+y9A0v4mxCW1qUhf3BSVPg+/NvGErk/dOkrDaHA0nQIQGAtrOjlX//9OQtRlSCy+x9rfB5N8yC71lH1nvMw==",
      "license": "MIT",
      "dependencies": {
        "lodash-es": "^4.17.21"
      },
      "peerDependencies": {
        "chevrotain": "^11.0.0"
      }
    },
    "node_modules/chrome-trace-event": {
      "version": "1.0.4",
      "resolved": "https://registry.npmjs.org/chrome-trace-event/-/chrome-trace-event-1.0.4.tgz",
      "integrity": "sha512-rNjApaLzuwaOTjCiT8lSDdGN1APCiqkChLMJxJPWLunPAt5fy8xgU9/jNOchV84wfIxrA0lRQB7oCT8jrn/wrQ==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=6.0"
      }
    },
    "node_modules/clone-deep": {
      "version": "4.0.1",
      "resolved": "https://registry.npmjs.org/clone-deep/-/clone-deep-4.0.1.tgz",
      "integrity": "sha512-neHB9xuzh/wk0dIHweyAXv2aPGZIVk3pLMe+/RNzINf17fe0OG96QroktYAUm7SM1PBnzTabaLboqqxDyMU+SQ==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "is-plain-object": "^2.0.4",
        "kind-of": "^6.0.2",
        "shallow-clone": "^3.0.0"
      },
      "engines": {
        "node": ">=6"
      }
    },
    "node_modules/clsx": {
      "version": "2.1.1",
      "resolved": "https://registry.npmjs.org/clsx/-/clsx-2.1.1.tgz",
      "integrity": "sha512-eYm0QWBtUrBWZWG0d386OGAw16Z995PiOVo2B7bjWSbHedGl5e0ZWaq65kOGgUSNesEIDkB9ISbTg/JK9dhCZA==",
      "license": "MIT",
      "engines": {
        "node": ">=6"
      }
    },
    "node_modules/color-convert": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/color-convert/-/color-convert-2.0.1.tgz",
      "integrity": "sha512-RRECPsj7iu/xb5oKYcsFHSppFNnsj/52OVTRKb4zP5onXwVF3zVmmToNcOfGC+CRDpfK/U584fMg38ZHCaElKQ==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "color-name": "~1.1.4"
      },
      "engines": {
        "node": ">=7.0.0"
      }
    },
    "node_modules/color-name": {
      "version": "1.1.4",
      "resolved": "https://registry.npmjs.org/color-name/-/color-name-1.1.4.tgz",
      "integrity": "sha512-dOy+3AuW3a2wNbZHIuMZpTcgjGuLU/uBL/ubcZF9OXbDo8ff4O8yVp5Bf0efS8uEoYo5q4Fx7dY9OgQGXgAsQA==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/colorette": {
      "version": "2.0.20",
      "resolved": "https://registry.npmjs.org/colorette/-/colorette-2.0.20.tgz",
      "integrity": "sha512-IfEDxwoWIjkeXL1eXcDiow4UbKjhLdq6/EuSVR9GMN7KVH3r9gQ83e73hsz1Nd1T3ijd5xv1wcWRYO+D6kCI2w==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/combined-stream": {
      "version": "1.0.8",
      "resolved": "https://registry.npmjs.org/combined-stream/-/combined-stream-1.0.8.tgz",
      "integrity": "sha512-FQN4MRfuJeHf7cBbBMJFXhKSDq+2kAArBlmRBvcvFE5BB1HZKXtSFASDhdlz9zOYwxh8lDdnvmMOe/+5cdoEdg==",
      "license": "MIT",
      "dependencies": {
        "delayed-stream": "~1.0.0"
      },
      "engines": {
        "node": ">= 0.8"
      }
    },
    "node_modules/comma-separated-tokens": {
      "version": "2.0.3",
      "resolved": "https://registry.npmjs.org/comma-separated-tokens/-/comma-separated-tokens-2.0.3.tgz",
      "integrity": "sha512-Fu4hJdvzeylCfQPp9SGWidpzrMs7tTrlu6Vb8XGaRGck8QSNZJJp538Wrb60Lax4fPwR64ViY468OIUTbRlGZg==",
      "license": "MIT",
      "funding": {
        "type": "github",
        "url": "https://github.com/sponsors/wooorm"
      }
    },
    "node_modules/commander": {
      "version": "2.20.3",
      "resolved": "https://registry.npmjs.org/commander/-/commander-2.20.3.tgz",
      "integrity": "sha512-GpVkmM8vF2vQUkj2LvZmD35JxeJOLCwJ9cUkugyk2nuhbv3+mJvpLYYt+0+USMxE+oj+ey/lJEnhZw75x/OMcQ==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/confbox": {
      "version": "0.1.8",
      "resolved": "https://registry.npmjs.org/confbox/-/confbox-0.1.8.tgz",
      "integrity": "sha512-RMtmw0iFkeR4YV+fUOSucriAQNb9g8zFR52MWCtl+cCZOFRNL6zeB395vPzFhEjjn4fMxXudmELnl/KF/WrK6w==",
      "license": "MIT"
    },
    "node_modules/copy-webpack-plugin": {
      "version": "11.0.0",
      "resolved": "https://registry.npmjs.org/copy-webpack-plugin/-/copy-webpack-plugin-11.0.0.tgz",
      "integrity": "sha512-fX2MWpamkW0hZxMEg0+mYnA40LTosOSa5TqZ9GYIBzyJa9C3QUaMPSE2xAi/buNr8u89SfD9wHSQVBzrRa/SOQ==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "fast-glob": "^3.2.11",
        "glob-parent": "^6.0.1",
        "globby": "^13.1.1",
        "normalize-path": "^3.0.0",
        "schema-utils": "^4.0.0",
        "serialize-javascript": "^6.0.0"
      },
      "engines": {
        "node": ">= 14.15.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/webpack"
      },
      "peerDependencies": {
        "webpack": "^5.1.0"
      }
    },
    "node_modules/cose-base": {
      "version": "1.0.3",
      "resolved": "https://registry.npmjs.org/cose-base/-/cose-base-1.0.3.tgz",
      "integrity": "sha512-s9whTXInMSgAp/NVXVNuVxVKzGH2qck3aQlVHxDCdAEPgtMKwc4Wq6/QKhgdEdgbLSi9rBTAcPoRa6JpiG4ksg==",
      "license": "MIT",
      "dependencies": {
        "layout-base": "^1.0.0"
      }
    },
    "node_modules/cross-spawn": {
      "version": "7.0.6",
      "resolved": "https://registry.npmjs.org/cross-spawn/-/cross-spawn-7.0.6.tgz",
      "integrity": "sha512-uV2QOWP2nWzsy2aMp8aRibhi9dlzF5Hgh5SHaB9OiTGEyDTiJJyx0uy51QXdyWbtAHNua4XJzUKca3OzKUd3vA==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "path-key": "^3.1.0",
        "shebang-command": "^2.0.0",
        "which": "^2.0.1"
      },
      "engines": {
        "node": ">= 8"
      }
    },
    "node_modules/css-loader": {
      "version": "6.11.0",
      "resolved": "https://registry.npmjs.org/css-loader/-/css-loader-6.11.0.tgz",
      "integrity": "sha512-CTJ+AEQJjq5NzLga5pE39qdiSV56F8ywCIsqNIRF0r7BDgWsN25aazToqAFg7ZrtA/U016xudB3ffgweORxX7g==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "icss-utils": "^5.1.0",
        "postcss": "^8.4.33",
        "postcss-modules-extract-imports": "^3.1.0",
        "postcss-modules-local-by-default": "^4.0.5",
        "postcss-modules-scope": "^3.2.0",
        "postcss-modules-values": "^4.0.0",
        "postcss-value-parser": "^4.2.0",
        "semver": "^7.5.4"
      },
      "engines": {
        "node": ">= 12.13.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/webpack"
      },
      "peerDependencies": {
        "@rspack/core": "0.x || 1.x",
        "webpack": "^5.0.0"
      },
      "peerDependenciesMeta": {
        "@rspack/core": {
          "optional": true
        },
        "webpack": {
          "optional": true
        }
      }
    },
    "node_modules/cssesc": {
      "version": "3.0.0",
      "resolved": "https://registry.npmjs.org/cssesc/-/cssesc-3.0.0.tgz",
      "integrity": "sha512-/Tb/JcjK111nNScGob5MNtsntNM1aCNUDipB/TkwZFhyDrrE47SOx/18wF2bbjgc3ZzCSKW1T5nt5EbFoAz/Vg==",
      "dev": true,
      "license": "MIT",
      "bin": {
        "cssesc": "bin/cssesc"
      },
      "engines": {
        "node": ">=4"
      }
    },
    "node_modules/csstype": {
      "version": "3.2.3",
      "resolved": "https://registry.npmjs.org/csstype/-/csstype-3.2.3.tgz",
      "integrity": "sha512-z1HGKcYy2xA8AGQfwrn0PAy+PB7X/GSj3UVJW9qKyn43xWa+gl5nXmU4qqLMRzWVLFC8KusUX8T/0kCiOYpAIQ==",
      "license": "MIT"
    },
    "node_modules/cytoscape": {
      "version": "3.33.1",
      "resolved": "https://registry.npmjs.org/cytoscape/-/cytoscape-3.33.1.tgz",
      "integrity": "sha512-iJc4TwyANnOGR1OmWhsS9ayRS3s+XQ185FmuHObThD+5AeJCakAAbWv8KimMTt08xCCLNgneQwFp+JRJOr9qGQ==",
      "license": "MIT",
      "peer": true,
      "engines": {
        "node": ">=0.10"
      }
    },
    "node_modules/cytoscape-cose-bilkent": {
      "version": "4.1.0",
      "resolved": "https://registry.npmjs.org/cytoscape-cose-bilkent/-/cytoscape-cose-bilkent-4.1.0.tgz",
      "integrity": "sha512-wgQlVIUJF13Quxiv5e1gstZ08rnZj2XaLHGoFMYXz7SkNfCDOOteKBE6SYRfA9WxxI/iBc3ajfDoc6hb/MRAHQ==",
      "license": "MIT",
      "dependencies": {
        "cose-base": "^1.0.0"
      },
      "peerDependencies": {
        "cytoscape": "^3.2.0"
      }
    },
    "node_modules/cytoscape-fcose": {
      "version": "2.2.0",
      "resolved": "https://registry.npmjs.org/cytoscape-fcose/-/cytoscape-fcose-2.2.0.tgz",
      "integrity": "sha512-ki1/VuRIHFCzxWNrsshHYPs6L7TvLu3DL+TyIGEsRcvVERmxokbf5Gdk7mFxZnTdiGtnA4cfSmjZJMviqSuZrQ==",
      "license": "MIT",
      "dependencies": {
        "cose-base": "^2.2.0"
      },
      "peerDependencies": {
        "cytoscape": "^3.2.0"
      }
    },
    "node_modules/cytoscape-fcose/node_modules/cose-base": {
      "version": "2.2.0",
      "resolved": "https://registry.npmjs.org/cose-base/-/cose-base-2.2.0.tgz",
      "integrity": "sha512-AzlgcsCbUMymkADOJtQm3wO9S3ltPfYOFD5033keQn9NJzIbtnZj+UdBJe7DYml/8TdbtHJW3j58SOnKhWY/5g==",
      "license": "MIT",
      "dependencies": {
        "layout-base": "^2.0.0"
      }
    },
    "node_modules/cytoscape-fcose/node_modules/layout-base": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/layout-base/-/layout-base-2.0.1.tgz",
      "integrity": "sha512-dp3s92+uNI1hWIpPGH3jK2kxE2lMjdXdr+DH8ynZHpd6PUlH6x6cbuXnoMmiNumznqaNO31xu9e79F0uuZ0JFg==",
      "license": "MIT"
    },
    "node_modules/d3": {
      "version": "7.9.0",
      "resolved": "https://registry.npmjs.org/d3/-/d3-7.9.0.tgz",
      "integrity": "sha512-e1U46jVP+w7Iut8Jt8ri1YsPOvFpg46k+K8TpCb0P+zjCkjkPnV7WzfDJzMHy1LnA+wj5pLT1wjO901gLXeEhA==",
      "license": "ISC",
      "dependencies": {
        "d3-array": "3",
        "d3-axis": "3",
        "d3-brush": "3",
        "d3-chord": "3",
        "d3-color": "3",
        "d3-contour": "4",
        "d3-delaunay": "6",
        "d3-dispatch": "3",
        "d3-drag": "3",
        "d3-dsv": "3",
        "d3-ease": "3",
        "d3-fetch": "3",
        "d3-force": "3",
        "d3-format": "3",
        "d3-geo": "3",
        "d3-hierarchy": "3",
        "d3-interpolate": "3",
        "d3-path": "3",
        "d3-polygon": "3",
        "d3-quadtree": "3",
        "d3-random": "3",
        "d3-scale": "4",
        "d3-scale-chromatic": "3",
        "d3-selection": "3",
        "d3-shape": "3",
        "d3-time": "3",
        "d3-time-format": "4",
        "d3-timer": "3",
        "d3-transition": "3",
        "d3-zoom": "3"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-array": {
      "version": "3.2.4",
      "resolved": "https://registry.npmjs.org/d3-array/-/d3-array-3.2.4.tgz",
      "integrity": "sha512-tdQAmyA18i4J7wprpYq8ClcxZy3SC31QMeByyCFyRt7BVHdREQZ5lpzoe5mFEYZUWe+oq8HBvk9JjpibyEV4Jg==",
      "license": "ISC",
      "dependencies": {
        "internmap": "1 - 2"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-axis": {
      "version": "3.0.0",
      "resolved": "https://registry.npmjs.org/d3-axis/-/d3-axis-3.0.0.tgz",
      "integrity": "sha512-IH5tgjV4jE/GhHkRV0HiVYPDtvfjHQlQfJHs0usq7M30XcSBvOotpmH1IgkcXsO/5gEQZD43B//fc7SRT5S+xw==",
      "license": "ISC",
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-brush": {
      "version": "3.0.0",
      "resolved": "https://registry.npmjs.org/d3-brush/-/d3-brush-3.0.0.tgz",
      "integrity": "sha512-ALnjWlVYkXsVIGlOsuWH1+3udkYFI48Ljihfnh8FZPF2QS9o+PzGLBslO0PjzVoHLZ2KCVgAM8NVkXPJB2aNnQ==",
      "license": "ISC",
      "dependencies": {
        "d3-dispatch": "1 - 3",
        "d3-drag": "2 - 3",
        "d3-interpolate": "1 - 3",
        "d3-selection": "3",
        "d3-transition": "3"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-chord": {
      "version": "3.0.1",
      "resolved": "https://registry.npmjs.org/d3-chord/-/d3-chord-3.0.1.tgz",
      "integrity": "sha512-VE5S6TNa+j8msksl7HwjxMHDM2yNK3XCkusIlpX5kwauBfXuyLAtNg9jCp/iHH61tgI4sb6R/EIMWCqEIdjT/g==",
      "license": "ISC",
      "dependencies": {
        "d3-path": "1 - 3"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-color": {
      "version": "3.1.0",
      "resolved": "https://registry.npmjs.org/d3-color/-/d3-color-3.1.0.tgz",
      "integrity": "sha512-zg/chbXyeBtMQ1LbD/WSoW2DpC3I0mpmPdW+ynRTj/x2DAWYrIY7qeZIHidozwV24m4iavr15lNwIwLxRmOxhA==",
      "license": "ISC",
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-contour": {
      "version": "4.0.2",
      "resolved": "https://registry.npmjs.org/d3-contour/-/d3-contour-4.0.2.tgz",
      "integrity": "sha512-4EzFTRIikzs47RGmdxbeUvLWtGedDUNkTcmzoeyg4sP/dvCexO47AaQL7VKy/gul85TOxw+IBgA8US2xwbToNA==",
      "license": "ISC",
      "dependencies": {
        "d3-array": "^3.2.0"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-delaunay": {
      "version": "6.0.4",
      "resolved": "https://registry.npmjs.org/d3-delaunay/-/d3-delaunay-6.0.4.tgz",
      "integrity": "sha512-mdjtIZ1XLAM8bm/hx3WwjfHt6Sggek7qH043O8KEjDXN40xi3vx/6pYSVTwLjEgiXQTbvaouWKynLBiUZ6SK6A==",
      "license": "ISC",
      "dependencies": {
        "delaunator": "5"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-dispatch": {
      "version": "3.0.1",
      "resolved": "https://registry.npmjs.org/d3-dispatch/-/d3-dispatch-3.0.1.tgz",
      "integrity": "sha512-rzUyPU/S7rwUflMyLc1ETDeBj0NRuHKKAcvukozwhshr6g6c5d8zh4c2gQjY2bZ0dXeGLWc1PF174P2tVvKhfg==",
      "license": "ISC",
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-drag": {
      "version": "3.0.0",
      "resolved": "https://registry.npmjs.org/d3-drag/-/d3-drag-3.0.0.tgz",
      "integrity": "sha512-pWbUJLdETVA8lQNJecMxoXfH6x+mO2UQo8rSmZ+QqxcbyA3hfeprFgIT//HW2nlHChWeIIMwS2Fq+gEARkhTkg==",
      "license": "ISC",
      "dependencies": {
        "d3-dispatch": "1 - 3",
        "d3-selection": "3"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-dsv": {
      "version": "3.0.1",
      "resolved": "https://registry.npmjs.org/d3-dsv/-/d3-dsv-3.0.1.tgz",
      "integrity": "sha512-UG6OvdI5afDIFP9w4G0mNq50dSOsXHJaRE8arAS5o9ApWnIElp8GZw1Dun8vP8OyHOZ/QJUKUJwxiiCCnUwm+Q==",
      "license": "ISC",
      "dependencies": {
        "commander": "7",
        "iconv-lite": "0.6",
        "rw": "1"
      },
      "bin": {
        "csv2json": "bin/dsv2json.js",
        "csv2tsv": "bin/dsv2dsv.js",
        "dsv2dsv": "bin/dsv2dsv.js",
        "dsv2json": "bin/dsv2json.js",
        "json2csv": "bin/json2dsv.js",
        "json2dsv": "bin/json2dsv.js",
        "json2tsv": "bin/json2dsv.js",
        "tsv2csv": "bin/dsv2dsv.js",
        "tsv2json": "bin/dsv2json.js"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-dsv/node_modules/commander": {
      "version": "7.2.0",
      "resolved": "https://registry.npmjs.org/commander/-/commander-7.2.0.tgz",
      "integrity": "sha512-QrWXB+ZQSVPmIWIhtEO9H+gwHaMGYiF5ChvoJ+K9ZGHG/sVsa6yiesAD1GC/x46sET00Xlwo1u49RVVVzvcSkw==",
      "license": "MIT",
      "engines": {
        "node": ">= 10"
      }
    },
    "node_modules/d3-ease": {
      "version": "3.0.1",
      "resolved": "https://registry.npmjs.org/d3-ease/-/d3-ease-3.0.1.tgz",
      "integrity": "sha512-wR/XK3D3XcLIZwpbvQwQ5fK+8Ykds1ip7A2Txe0yxncXSdq1L9skcG7blcedkOX+ZcgxGAmLX1FrRGbADwzi0w==",
      "license": "BSD-3-Clause",
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-fetch": {
      "version": "3.0.1",
      "resolved": "https://registry.npmjs.org/d3-fetch/-/d3-fetch-3.0.1.tgz",
      "integrity": "sha512-kpkQIM20n3oLVBKGg6oHrUchHM3xODkTzjMoj7aWQFq5QEM+R6E4WkzT5+tojDY7yjez8KgCBRoj4aEr99Fdqw==",
      "license": "ISC",
      "dependencies": {
        "d3-dsv": "1 - 3"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-force": {
      "version": "3.0.0",
      "resolved": "https://registry.npmjs.org/d3-force/-/d3-force-3.0.0.tgz",
      "integrity": "sha512-zxV/SsA+U4yte8051P4ECydjD/S+qeYtnaIyAs9tgHCqfguma/aAQDjo85A9Z6EKhBirHRJHXIgJUlffT4wdLg==",
      "license": "ISC",
      "dependencies": {
        "d3-dispatch": "1 - 3",
        "d3-quadtree": "1 - 3",
        "d3-timer": "1 - 3"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-format": {
      "version": "3.1.0",
      "resolved": "https://registry.npmjs.org/d3-format/-/d3-format-3.1.0.tgz",
      "integrity": "sha512-YyUI6AEuY/Wpt8KWLgZHsIU86atmikuoOmCfommt0LYHiQSPjvX2AcFc38PX0CBpr2RCyZhjex+NS/LPOv6YqA==",
      "license": "ISC",
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-geo": {
      "version": "3.1.1",
      "resolved": "https://registry.npmjs.org/d3-geo/-/d3-geo-3.1.1.tgz",
      "integrity": "sha512-637ln3gXKXOwhalDzinUgY83KzNWZRKbYubaG+fGVuc/dxO64RRljtCTnf5ecMyE1RIdtqpkVcq0IbtU2S8j2Q==",
      "license": "ISC",
      "dependencies": {
        "d3-array": "2.5.0 - 3"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-hierarchy": {
      "version": "3.1.2",
      "resolved": "https://registry.npmjs.org/d3-hierarchy/-/d3-hierarchy-3.1.2.tgz",
      "integrity": "sha512-FX/9frcub54beBdugHjDCdikxThEqjnR93Qt7PvQTOHxyiNCAlvMrHhclk3cD5VeAaq9fxmfRp+CnWw9rEMBuA==",
      "license": "ISC",
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-interpolate": {
      "version": "3.0.1",
      "resolved": "https://registry.npmjs.org/d3-interpolate/-/d3-interpolate-3.0.1.tgz",
      "integrity": "sha512-3bYs1rOD33uo8aqJfKP3JWPAibgw8Zm2+L9vBKEHJ2Rg+viTR7o5Mmv5mZcieN+FRYaAOWX5SJATX6k1PWz72g==",
      "license": "ISC",
      "dependencies": {
        "d3-color": "1 - 3"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-path": {
      "version": "3.1.0",
      "resolved": "https://registry.npmjs.org/d3-path/-/d3-path-3.1.0.tgz",
      "integrity": "sha512-p3KP5HCf/bvjBSSKuXid6Zqijx7wIfNW+J/maPs+iwR35at5JCbLUT0LzF1cnjbCHWhqzQTIN2Jpe8pRebIEFQ==",
      "license": "ISC",
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-polygon": {
      "version": "3.0.1",
      "resolved": "https://registry.npmjs.org/d3-polygon/-/d3-polygon-3.0.1.tgz",
      "integrity": "sha512-3vbA7vXYwfe1SYhED++fPUQlWSYTTGmFmQiany/gdbiWgU/iEyQzyymwL9SkJjFFuCS4902BSzewVGsHHmHtXg==",
      "license": "ISC",
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-quadtree": {
      "version": "3.0.1",
      "resolved": "https://registry.npmjs.org/d3-quadtree/-/d3-quadtree-3.0.1.tgz",
      "integrity": "sha512-04xDrxQTDTCFwP5H6hRhsRcb9xxv2RzkcsygFzmkSIOJy3PeRJP7sNk3VRIbKXcog561P9oU0/rVH6vDROAgUw==",
      "license": "ISC",
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-random": {
      "version": "3.0.1",
      "resolved": "https://registry.npmjs.org/d3-random/-/d3-random-3.0.1.tgz",
      "integrity": "sha512-FXMe9GfxTxqd5D6jFsQ+DJ8BJS4E/fT5mqqdjovykEB2oFbTMDVdg1MGFxfQW+FBOGoB++k8swBrgwSHT1cUXQ==",
      "license": "ISC",
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-sankey": {
      "version": "0.12.3",
      "resolved": "https://registry.npmjs.org/d3-sankey/-/d3-sankey-0.12.3.tgz",
      "integrity": "sha512-nQhsBRmM19Ax5xEIPLMY9ZmJ/cDvd1BG3UVvt5h3WRxKg5zGRbvnteTyWAbzeSvlh3tW7ZEmq4VwR5mB3tutmQ==",
      "license": "BSD-3-Clause",
      "dependencies": {
        "d3-array": "1 - 2",
        "d3-shape": "^1.2.0"
      }
    },
    "node_modules/d3-sankey/node_modules/d3-array": {
      "version": "2.12.1",
      "resolved": "https://registry.npmjs.org/d3-array/-/d3-array-2.12.1.tgz",
      "integrity": "sha512-B0ErZK/66mHtEsR1TkPEEkwdy+WDesimkM5gpZr5Dsg54BiTA5RXtYW5qTLIAcekaS9xfZrzBLF/OAkB3Qn1YQ==",
      "license": "BSD-3-Clause",
      "dependencies": {
        "internmap": "^1.0.0"
      }
    },
    "node_modules/d3-sankey/node_modules/d3-path": {
      "version": "1.0.9",
      "resolved": "https://registry.npmjs.org/d3-path/-/d3-path-1.0.9.tgz",
      "integrity": "sha512-VLaYcn81dtHVTjEHd8B+pbe9yHWpXKZUC87PzoFmsFrJqgFwDe/qxfp5MlfsfM1V5E/iVt0MmEbWQ7FVIXh/bg==",
      "license": "BSD-3-Clause"
    },
    "node_modules/d3-sankey/node_modules/d3-shape": {
      "version": "1.3.7",
      "resolved": "https://registry.npmjs.org/d3-shape/-/d3-shape-1.3.7.tgz",
      "integrity": "sha512-EUkvKjqPFUAZyOlhY5gzCxCeI0Aep04LwIRpsZ/mLFelJiUfnK56jo5JMDSE7yyP2kLSb6LtF+S5chMk7uqPqw==",
      "license": "BSD-3-Clause",
      "dependencies": {
        "d3-path": "1"
      }
    },
    "node_modules/d3-sankey/node_modules/internmap": {
      "version": "1.0.1",
      "resolved": "https://registry.npmjs.org/internmap/-/internmap-1.0.1.tgz",
      "integrity": "sha512-lDB5YccMydFBtasVtxnZ3MRBHuaoE8GKsppq+EchKL2U4nK/DmEpPHNH8MZe5HkMtpSiTSOZwfN0tzYjO/lJEw==",
      "license": "ISC"
    },
    "node_modules/d3-scale": {
      "version": "4.0.2",
      "resolved": "https://registry.npmjs.org/d3-scale/-/d3-scale-4.0.2.tgz",
      "integrity": "sha512-GZW464g1SH7ag3Y7hXjf8RoUuAFIqklOAq3MRl4OaWabTFJY9PN/E1YklhXLh+OQ3fM9yS2nOkCoS+WLZ6kvxQ==",
      "license": "ISC",
      "dependencies": {
        "d3-array": "2.10.0 - 3",
        "d3-format": "1 - 3",
        "d3-interpolate": "1.2.0 - 3",
        "d3-time": "2.1.1 - 3",
        "d3-time-format": "2 - 4"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-scale-chromatic": {
      "version": "3.1.0",
      "resolved": "https://registry.npmjs.org/d3-scale-chromatic/-/d3-scale-chromatic-3.1.0.tgz",
      "integrity": "sha512-A3s5PWiZ9YCXFye1o246KoscMWqf8BsD9eRiJ3He7C9OBaxKhAd5TFCdEx/7VbKtxxTsu//1mMJFrEt572cEyQ==",
      "license": "ISC",
      "dependencies": {
        "d3-color": "1 - 3",
        "d3-interpolate": "1 - 3"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-selection": {
      "version": "3.0.0",
      "resolved": "https://registry.npmjs.org/d3-selection/-/d3-selection-3.0.0.tgz",
      "integrity": "sha512-fmTRWbNMmsmWq6xJV8D19U/gw/bwrHfNXxrIN+HfZgnzqTHp9jOmKMhsTUjXOJnZOdZY9Q28y4yebKzqDKlxlQ==",
      "license": "ISC",
      "peer": true,
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-shape": {
      "version": "3.2.0",
      "resolved": "https://registry.npmjs.org/d3-shape/-/d3-shape-3.2.0.tgz",
      "integrity": "sha512-SaLBuwGm3MOViRq2ABk3eLoxwZELpH6zhl3FbAoJ7Vm1gofKx6El1Ib5z23NUEhF9AsGl7y+dzLe5Cw2AArGTA==",
      "license": "ISC",
      "dependencies": {
        "d3-path": "^3.1.0"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-time": {
      "version": "3.1.0",
      "resolved": "https://registry.npmjs.org/d3-time/-/d3-time-3.1.0.tgz",
      "integrity": "sha512-VqKjzBLejbSMT4IgbmVgDjpkYrNWUYJnbCGo874u7MMKIWsILRX+OpX/gTk8MqjpT1A/c6HY2dCA77ZN0lkQ2Q==",
      "license": "ISC",
      "dependencies": {
        "d3-array": "2 - 3"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-time-format": {
      "version": "4.1.0",
      "resolved": "https://registry.npmjs.org/d3-time-format/-/d3-time-format-4.1.0.tgz",
      "integrity": "sha512-dJxPBlzC7NugB2PDLwo9Q8JiTR3M3e4/XANkreKSUxF8vvXKqm1Yfq4Q5dl8budlunRVlUUaDUgFt7eA8D6NLg==",
      "license": "ISC",
      "dependencies": {
        "d3-time": "1 - 3"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-timer": {
      "version": "3.0.1",
      "resolved": "https://registry.npmjs.org/d3-timer/-/d3-timer-3.0.1.tgz",
      "integrity": "sha512-ndfJ/JxxMd3nw31uyKoY2naivF+r29V+Lc0svZxe1JvvIRmi8hUsrMvdOwgS1o6uBHmiz91geQ0ylPP0aj1VUA==",
      "license": "ISC",
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/d3-transition": {
      "version": "3.0.1",
      "resolved": "https://registry.npmjs.org/d3-transition/-/d3-transition-3.0.1.tgz",
      "integrity": "sha512-ApKvfjsSR6tg06xrL434C0WydLr7JewBB3V+/39RMHsaXTOG0zmt/OAXeng5M5LBm0ojmxJrpomQVZ1aPvBL4w==",
      "license": "ISC",
      "dependencies": {
        "d3-color": "1 - 3",
        "d3-dispatch": "1 - 3",
        "d3-ease": "1 - 3",
        "d3-interpolate": "1 - 3",
        "d3-timer": "1 - 3"
      },
      "engines": {
        "node": ">=12"
      },
      "peerDependencies": {
        "d3-selection": "2 - 3"
      }
    },
    "node_modules/d3-zoom": {
      "version": "3.0.0",
      "resolved": "https://registry.npmjs.org/d3-zoom/-/d3-zoom-3.0.0.tgz",
      "integrity": "sha512-b8AmV3kfQaqWAuacbPuNbL6vahnOJflOhexLzMMNLga62+/nh0JzvJ0aO/5a5MVgUFGS7Hu1P9P03o3fJkDCyw==",
      "license": "ISC",
      "dependencies": {
        "d3-dispatch": "1 - 3",
        "d3-drag": "2 - 3",
        "d3-interpolate": "1 - 3",
        "d3-selection": "2 - 3",
        "d3-transition": "2 - 3"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/dagre-d3-es": {
      "version": "7.0.13",
      "resolved": "https://registry.npmjs.org/dagre-d3-es/-/dagre-d3-es-7.0.13.tgz",
      "integrity": "sha512-efEhnxpSuwpYOKRm/L5KbqoZmNNukHa/Flty4Wp62JRvgH2ojwVgPgdYyr4twpieZnyRDdIH7PY2mopX26+j2Q==",
      "license": "MIT",
      "dependencies": {
        "d3": "^7.9.0",
        "lodash-es": "^4.17.21"
      }
    },
    "node_modules/dayjs": {
      "version": "1.11.19",
      "resolved": "https://registry.npmjs.org/dayjs/-/dayjs-1.11.19.tgz",
      "integrity": "sha512-t5EcLVS6QPBNqM2z8fakk/NKel+Xzshgt8FFKAn+qwlD1pzZWxh0nVCrvFK7ZDb6XucZeF9z8C7CBWTRIVApAw==",
      "license": "MIT"
    },
    "node_modules/debug": {
      "version": "4.4.3",
      "resolved": "https://registry.npmjs.org/debug/-/debug-4.4.3.tgz",
      "integrity": "sha512-RGwwWnwQvkVfavKVt22FGLw+xYSdzARwm0ru6DhTVA3umU5hZc28V3kO4stgYryrTlLpuvgI9GiijltAjNbcqA==",
      "license": "MIT",
      "dependencies": {
        "ms": "^2.1.3"
      },
      "engines": {
        "node": ">=6.0"
      },
      "peerDependenciesMeta": {
        "supports-color": {
          "optional": true
        }
      }
    },
    "node_modules/decode-named-character-reference": {
      "version": "1.2.0",
      "resolved": "https://registry.npmjs.org/decode-named-character-reference/-/decode-named-character-reference-1.2.0.tgz",
      "integrity": "sha512-c6fcElNV6ShtZXmsgNgFFV5tVX2PaV4g+MOAkb8eXHvn6sryJBrZa9r0zV6+dtTyoCKxtDy5tyQ5ZwQuidtd+Q==",
      "license": "MIT",
      "dependencies": {
        "character-entities": "^2.0.0"
      },
      "funding": {
        "type": "github",
        "url": "https://github.com/sponsors/wooorm"
      }
    },
    "node_modules/delaunator": {
      "version": "5.0.1",
      "resolved": "https://registry.npmjs.org/delaunator/-/delaunator-5.0.1.tgz",
      "integrity": "sha512-8nvh+XBe96aCESrGOqMp/84b13H9cdKbG5P2ejQCh4d4sK9RL4371qou9drQjMhvnPmhWl5hnmqbEE0fXr9Xnw==",
      "license": "ISC",
      "dependencies": {
        "robust-predicates": "^3.0.2"
      }
    },
    "node_modules/delayed-stream": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/delayed-stream/-/delayed-stream-1.0.0.tgz",
      "integrity": "sha512-ZySD7Nf91aLB0RxL4KGrKHBXl7Eds1DAmEdcoVawXnLD7SDhpNgtuII2aAkg7a7QS41jxPSZ17p4VdGnMHk3MQ==",
      "license": "MIT",
      "engines": {
        "node": ">=0.4.0"
      }
    },
    "node_modules/dequal": {
      "version": "2.0.3",
      "resolved": "https://registry.npmjs.org/dequal/-/dequal-2.0.3.tgz",
      "integrity": "sha512-0je+qPKHEMohvfRTCEo3CrPG6cAzAYgmzKyxRiYSSDkS6eGJdyVJm7WaYA5ECaAD9wLB2T4EEeymA5aFVcYXCA==",
      "license": "MIT",
      "engines": {
        "node": ">=6"
      }
    },
    "node_modules/devlop": {
      "version": "1.1.0",
      "resolved": "https://registry.npmjs.org/devlop/-/devlop-1.1.0.tgz",
      "integrity": "sha512-RWmIqhcFf1lRYBvNmr7qTNuyCt/7/ns2jbpp1+PalgE/rDQcBT0fioSMUpJ93irlUhC5hrg4cYqe6U+0ImW0rA==",
      "license": "MIT",
      "dependencies": {
        "dequal": "^2.0.0"
      },
      "funding": {
        "type": "github",
        "url": "https://github.com/sponsors/wooorm"
      }
    },
    "node_modules/dir-glob": {
      "version": "3.0.1",
      "resolved": "https://registry.npmjs.org/dir-glob/-/dir-glob-3.0.1.tgz",
      "integrity": "sha512-WkrWp9GR4KXfKGYzOLmTuGVi1UWFfws377n9cc55/tb6DuqyF6pcQ5AbiHEshaDpY9v6oaSr2XCDidGmMwdzIA==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "path-type": "^4.0.0"
      },
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/dompurify": {
      "version": "3.3.0",
      "resolved": "https://registry.npmjs.org/dompurify/-/dompurify-3.3.0.tgz",
      "integrity": "sha512-r+f6MYR1gGN1eJv0TVQbhA7if/U7P87cdPl3HN5rikqaBSBxLiCb/b9O+2eG0cxz0ghyU+mU1QkbsOwERMYlWQ==",
      "license": "(MPL-2.0 OR Apache-2.0)",
      "optionalDependencies": {
        "@types/trusted-types": "^2.0.7"
      }
    },
    "node_modules/dunder-proto": {
      "version": "1.0.1",
      "resolved": "https://registry.npmjs.org/dunder-proto/-/dunder-proto-1.0.1.tgz",
      "integrity": "sha512-KIN/nDJBQRcXw0MLVhZE9iQHmG68qAVIBg9CqmUYjmQIhgij9U5MFvrqkUL5FbtyyzZuOeOt0zdeRe4UY7ct+A==",
      "license": "MIT",
      "dependencies": {
        "call-bind-apply-helpers": "^1.0.1",
        "es-errors": "^1.3.0",
        "gopd": "^1.2.0"
      },
      "engines": {
        "node": ">= 0.4"
      }
    },
    "node_modules/electron-to-chromium": {
      "version": "1.5.262",
      "resolved": "https://registry.npmjs.org/electron-to-chromium/-/electron-to-chromium-1.5.262.tgz",
      "integrity": "sha512-NlAsMteRHek05jRUxUR0a5jpjYq9ykk6+kO0yRaMi5moe7u0fVIOeQ3Y30A8dIiWFBNUoQGi1ljb1i5VtS9WQQ==",
      "dev": true,
      "license": "ISC"
    },
    "node_modules/enhanced-resolve": {
      "version": "5.18.3",
      "resolved": "https://registry.npmjs.org/enhanced-resolve/-/enhanced-resolve-5.18.3.tgz",
      "integrity": "sha512-d4lC8xfavMeBjzGr2vECC3fsGXziXZQyJxD868h2M/mBI3PwAuODxAkLkq5HYuvrPYcUtiLzsTo8U3PgX3Ocww==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "graceful-fs": "^4.2.4",
        "tapable": "^2.2.0"
      },
      "engines": {
        "node": ">=10.13.0"
      }
    },
    "node_modules/envinfo": {
      "version": "7.21.0",
      "resolved": "https://registry.npmjs.org/envinfo/-/envinfo-7.21.0.tgz",
      "integrity": "sha512-Lw7I8Zp5YKHFCXL7+Dz95g4CcbMEpgvqZNNq3AmlT5XAV6CgAAk6gyAMqn2zjw08K9BHfcNuKrMiCPLByGafow==",
      "dev": true,
      "license": "MIT",
      "bin": {
        "envinfo": "dist/cli.js"
      },
      "engines": {
        "node": ">=4"
      }
    },
    "node_modules/es-define-property": {
      "version": "1.0.1",
      "resolved": "https://registry.npmjs.org/es-define-property/-/es-define-property-1.0.1.tgz",
      "integrity": "sha512-e3nRfgfUZ4rNGL232gUgX06QNyyez04KdjFrF+LTRoOXmrOgFKDg4BCdsjW8EnT69eqdYGmRpJwiPVYNrCaW3g==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.4"
      }
    },
    "node_modules/es-errors": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/es-errors/-/es-errors-1.3.0.tgz",
      "integrity": "sha512-Zf5H2Kxt2xjTvbJvP2ZWLEICxA6j+hAmMzIlypy4xcBg1vKVnx89Wy0GbS+kf5cwCVFFzdCFh2XSCFNULS6csw==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.4"
      }
    },
    "node_modules/es-module-lexer": {
      "version": "1.7.0",
      "resolved": "https://registry.npmjs.org/es-module-lexer/-/es-module-lexer-1.7.0.tgz",
      "integrity": "sha512-jEQoCwk8hyb2AZziIOLhDqpm5+2ww5uIE6lkO/6jcOCusfk6LhMHpXXfBLXTZ7Ydyt0j4VoUQv6uGNYbdW+kBA==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/es-object-atoms": {
      "version": "1.1.1",
      "resolved": "https://registry.npmjs.org/es-object-atoms/-/es-object-atoms-1.1.1.tgz",
      "integrity": "sha512-FGgH2h8zKNim9ljj7dankFPcICIK9Cp5bm+c2gQSYePhpaG5+esrLODihIorn+Pe6FGJzWhXQotPv73jTaldXA==",
      "license": "MIT",
      "dependencies": {
        "es-errors": "^1.3.0"
      },
      "engines": {
        "node": ">= 0.4"
      }
    },
    "node_modules/es-set-tostringtag": {
      "version": "2.1.0",
      "resolved": "https://registry.npmjs.org/es-set-tostringtag/-/es-set-tostringtag-2.1.0.tgz",
      "integrity": "sha512-j6vWzfrGVfyXxge+O0x5sh6cvxAog0a/4Rdd2K36zCMV5eJ+/+tOAngRO8cODMNWbVRdVlmGZQL2YS3yR8bIUA==",
      "license": "MIT",
      "dependencies": {
        "es-errors": "^1.3.0",
        "get-intrinsic": "^1.2.6",
        "has-tostringtag": "^1.0.2",
        "hasown": "^2.0.2"
      },
      "engines": {
        "node": ">= 0.4"
      }
    },
    "node_modules/escalade": {
      "version": "3.2.0",
      "resolved": "https://registry.npmjs.org/escalade/-/escalade-3.2.0.tgz",
      "integrity": "sha512-WUj2qlxaQtO4g6Pq5c29GTcWGDyd8itL8zTlipgECz3JesAiiOKotd8JU6otB3PACgG6xkJUyVhboMS+bje/jA==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=6"
      }
    },
    "node_modules/eslint-scope": {
      "version": "5.1.1",
      "resolved": "https://registry.npmjs.org/eslint-scope/-/eslint-scope-5.1.1.tgz",
      "integrity": "sha512-2NxwbF/hZ0KpepYN0cNbo+FN6XoK7GaHlQhgx/hIZl6Va0bF45RQOOwhLIy8lQDbuCiadSLCBnH2CFYquit5bw==",
      "dev": true,
      "license": "BSD-2-Clause",
      "dependencies": {
        "esrecurse": "^4.3.0",
        "estraverse": "^4.1.1"
      },
      "engines": {
        "node": ">=8.0.0"
      }
    },
    "node_modules/esrecurse": {
      "version": "4.3.0",
      "resolved": "https://registry.npmjs.org/esrecurse/-/esrecurse-4.3.0.tgz",
      "integrity": "sha512-KmfKL3b6G+RXvP8N1vr3Tq1kL/oCFgn2NYXEtqP8/L3pKapUA4G8cFVaoF3SU323CD4XypR/ffioHmkti6/Tag==",
      "dev": true,
      "license": "BSD-2-Clause",
      "dependencies": {
        "estraverse": "^5.2.0"
      },
      "engines": {
        "node": ">=4.0"
      }
    },
    "node_modules/esrecurse/node_modules/estraverse": {
      "version": "5.3.0",
      "resolved": "https://registry.npmjs.org/estraverse/-/estraverse-5.3.0.tgz",
      "integrity": "sha512-MMdARuVEQziNTeJD8DgMqmhwR11BRQ/cBP+pLtYdSTnf3MIO8fFeiINEbX36ZdNlfU/7A9f3gUw49B3oQsvwBA==",
      "dev": true,
      "license": "BSD-2-Clause",
      "engines": {
        "node": ">=4.0"
      }
    },
    "node_modules/estraverse": {
      "version": "4.3.0",
      "resolved": "https://registry.npmjs.org/estraverse/-/estraverse-4.3.0.tgz",
      "integrity": "sha512-39nnKffWz8xN1BU/2c79n9nB9HDzo0niYUqx6xyqUnyoAnQyyWpOTdZEeiCch8BBu515t4wp9ZmgVfVhn9EBpw==",
      "dev": true,
      "license": "BSD-2-Clause",
      "engines": {
        "node": ">=4.0"
      }
    },
    "node_modules/estree-util-is-identifier-name": {
      "version": "3.0.0",
      "resolved": "https://registry.npmjs.org/estree-util-is-identifier-name/-/estree-util-is-identifier-name-3.0.0.tgz",
      "integrity": "sha512-hFtqIDZTIUZ9BXLb8y4pYGyk6+wekIivNVTcmvk8NoOh+VeRn5y6cEHzbURrWbfp1fIqdVipilzj+lfaadNZmg==",
      "license": "MIT",
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/unified"
      }
    },
    "node_modules/event-target-shim": {
      "version": "5.0.1",
      "resolved": "https://registry.npmjs.org/event-target-shim/-/event-target-shim-5.0.1.tgz",
      "integrity": "sha512-i/2XbnSz/uxRCU6+NdVJgKWDTM427+MqYbkQzD321DuCQJUqOuJKIA0IM2+W2xtYHdKOmZ4dR6fExsd4SXL+WQ==",
      "license": "MIT",
      "engines": {
        "node": ">=6"
      }
    },
    "node_modules/events": {
      "version": "3.3.0",
      "resolved": "https://registry.npmjs.org/events/-/events-3.3.0.tgz",
      "integrity": "sha512-mQw+2fkQbALzQ7V0MY0IqdnXNOeTtP4r0lN9z7AAawCXgqea7bDii20AYrIBrFd/Hx0M2Ocz6S111CaFkUcb0Q==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=0.8.x"
      }
    },
    "node_modules/extend": {
      "version": "3.0.2",
      "resolved": "https://registry.npmjs.org/extend/-/extend-3.0.2.tgz",
      "integrity": "sha512-fjquC59cD7CyW6urNXK0FBufkZcoiGG80wTuPujX590cB5Ttln20E2UB4S/WARVqhXffZl2LNgS+gQdPIIim/g==",
      "license": "MIT"
    },
    "node_modules/fast-deep-equal": {
      "version": "3.1.3",
      "resolved": "https://registry.npmjs.org/fast-deep-equal/-/fast-deep-equal-3.1.3.tgz",
      "integrity": "sha512-f3qQ9oQy9j2AhBe/H9VC91wLmKBCCU/gDOnKNAYG5hswO7BLKj09Hc5HYNz9cGI++xlpDCIgDaitVs03ATR84Q==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/fast-glob": {
      "version": "3.3.3",
      "resolved": "https://registry.npmjs.org/fast-glob/-/fast-glob-3.3.3.tgz",
      "integrity": "sha512-7MptL8U0cqcFdzIzwOTHoilX9x5BrNqye7Z/LuC7kCMRio1EMSyqRK3BEAUD7sXRq4iT4AzTVuZdhgQ2TCvYLg==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@nodelib/fs.stat": "^2.0.2",
        "@nodelib/fs.walk": "^1.2.3",
        "glob-parent": "^5.1.2",
        "merge2": "^1.3.0",
        "micromatch": "^4.0.8"
      },
      "engines": {
        "node": ">=8.6.0"
      }
    },
    "node_modules/fast-glob/node_modules/glob-parent": {
      "version": "5.1.2",
      "resolved": "https://registry.npmjs.org/glob-parent/-/glob-parent-5.1.2.tgz",
      "integrity": "sha512-AOIgSQCepiJYwP3ARnGx+5VnTu2HBYdzbGP45eLw1vr3zB3vZLeyed1sC9hnbcOc9/SrMyM5RPQrkGz4aS9Zow==",
      "dev": true,
      "license": "ISC",
      "dependencies": {
        "is-glob": "^4.0.1"
      },
      "engines": {
        "node": ">= 6"
      }
    },
    "node_modules/fast-uri": {
      "version": "3.1.0",
      "resolved": "https://registry.npmjs.org/fast-uri/-/fast-uri-3.1.0.tgz",
      "integrity": "sha512-iPeeDKJSWf4IEOasVVrknXpaBV0IApz/gp7S2bb7Z4Lljbl2MGJRqInZiUrQwV16cpzw/D3S5j5Julj/gT52AA==",
      "dev": true,
      "funding": [
        {
          "type": "github",
          "url": "https://github.com/sponsors/fastify"
        },
        {
          "type": "opencollective",
          "url": "https://opencollective.com/fastify"
        }
      ],
      "license": "BSD-3-Clause"
    },
    "node_modules/fastest-levenshtein": {
      "version": "1.0.16",
      "resolved": "https://registry.npmjs.org/fastest-levenshtein/-/fastest-levenshtein-1.0.16.tgz",
      "integrity": "sha512-eRnCtTTtGZFpQCwhJiUOuxPQWRXVKYDn0b2PeHfXL6/Zi53SLAzAHfVhVWK2AryC/WH05kGfxhFIPvTF0SXQzg==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">= 4.9.1"
      }
    },
    "node_modules/fastq": {
      "version": "1.19.1",
      "resolved": "https://registry.npmjs.org/fastq/-/fastq-1.19.1.tgz",
      "integrity": "sha512-GwLTyxkCXjXbxqIhTsMI2Nui8huMPtnxg7krajPJAjnEG/iiOS7i+zCtWGZR9G0NBKbXKh6X9m9UIsYX/N6vvQ==",
      "dev": true,
      "license": "ISC",
      "dependencies": {
        "reusify": "^1.0.4"
      }
    },
    "node_modules/fill-range": {
      "version": "7.1.1",
      "resolved": "https://registry.npmjs.org/fill-range/-/fill-range-7.1.1.tgz",
      "integrity": "sha512-YsGpe3WHLK8ZYi4tWDg2Jy3ebRz2rXowDxnld4bkQB00cc/1Zw9AWnC0i9ztDJitivtQvaI9KaLyKrc+hBW0yg==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "to-regex-range": "^5.0.1"
      },
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/find-up": {
      "version": "4.1.0",
      "resolved": "https://registry.npmjs.org/find-up/-/find-up-4.1.0.tgz",
      "integrity": "sha512-PpOwAdQ/YlXQ2vj8a3h8IipDuYRi3wceVQQGYWxNINccq40Anw7BlsEXCMbt1Zt+OLA6Fq9suIpIWD0OsnISlw==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "locate-path": "^5.0.0",
        "path-exists": "^4.0.0"
      },
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/flat": {
      "version": "5.0.2",
      "resolved": "https://registry.npmjs.org/flat/-/flat-5.0.2.tgz",
      "integrity": "sha512-b6suED+5/3rTpUBdG1gupIl8MPFCAMA0QXwmljLhvCUKcUvdE4gWky9zpuGCcXHOsz4J9wPGNWq6OKpmIzz3hQ==",
      "dev": true,
      "license": "BSD-3-Clause",
      "bin": {
        "flat": "cli.js"
      }
    },
    "node_modules/form-data": {
      "version": "4.0.5",
      "resolved": "https://registry.npmjs.org/form-data/-/form-data-4.0.5.tgz",
      "integrity": "sha512-8RipRLol37bNs2bhoV67fiTEvdTrbMUYcFTiy3+wuuOnUog2QBHCZWXDRijWQfAkhBj2Uf5UnVaiWwA5vdd82w==",
      "license": "MIT",
      "dependencies": {
        "asynckit": "^0.4.0",
        "combined-stream": "^1.0.8",
        "es-set-tostringtag": "^2.1.0",
        "hasown": "^2.0.2",
        "mime-types": "^2.1.12"
      },
      "engines": {
        "node": ">= 6"
      }
    },
    "node_modules/form-data-encoder": {
      "version": "1.7.2",
      "resolved": "https://registry.npmjs.org/form-data-encoder/-/form-data-encoder-1.7.2.tgz",
      "integrity": "sha512-qfqtYan3rxrnCk1VYaA4H+Ms9xdpPqvLZa6xmMgFvhO32x7/3J/ExcTd6qpxM0vH2GdMI+poehyBZvqfMTto8A==",
      "license": "MIT"
    },
    "node_modules/formdata-node": {
      "version": "4.4.1",
      "resolved": "https://registry.npmjs.org/formdata-node/-/formdata-node-4.4.1.tgz",
      "integrity": "sha512-0iirZp3uVDjVGt9p49aTaqjk84TrglENEDuqfdlZQ1roC9CWlPk6Avf8EEnZNcAqPonwkG35x4n3ww/1THYAeQ==",
      "license": "MIT",
      "dependencies": {
        "node-domexception": "1.0.0",
        "web-streams-polyfill": "4.0.0-beta.3"
      },
      "engines": {
        "node": ">= 12.20"
      }
    },
    "node_modules/function-bind": {
      "version": "1.1.2",
      "resolved": "https://registry.npmjs.org/function-bind/-/function-bind-1.1.2.tgz",
      "integrity": "sha512-7XHNxH7qX9xG5mIwxkhumTox/MIRNcOgDrxWsMt2pAr23WHp6MrRlN7FBSFpCpr+oVO0F744iUgR82nJMfG2SA==",
      "license": "MIT",
      "funding": {
        "url": "https://github.com/sponsors/ljharb"
      }
    },
    "node_modules/get-intrinsic": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/get-intrinsic/-/get-intrinsic-1.3.0.tgz",
      "integrity": "sha512-9fSjSaos/fRIVIp+xSJlE6lfwhES7LNtKaCBIamHsjr2na1BiABJPo0mOjjz8GJDURarmCPGqaiVg5mfjb98CQ==",
      "license": "MIT",
      "dependencies": {
        "call-bind-apply-helpers": "^1.0.2",
        "es-define-property": "^1.0.1",
        "es-errors": "^1.3.0",
        "es-object-atoms": "^1.1.1",
        "function-bind": "^1.1.2",
        "get-proto": "^1.0.1",
        "gopd": "^1.2.0",
        "has-symbols": "^1.1.0",
        "hasown": "^2.0.2",
        "math-intrinsics": "^1.1.0"
      },
      "engines": {
        "node": ">= 0.4"
      },
      "funding": {
        "url": "https://github.com/sponsors/ljharb"
      }
    },
    "node_modules/get-proto": {
      "version": "1.0.1",
      "resolved": "https://registry.npmjs.org/get-proto/-/get-proto-1.0.1.tgz",
      "integrity": "sha512-sTSfBjoXBp89JvIKIefqw7U2CCebsc74kiY6awiGogKtoSGbgjYE/G/+l9sF3MWFPNc9IcoOC4ODfKHfxFmp0g==",
      "license": "MIT",
      "dependencies": {
        "dunder-proto": "^1.0.1",
        "es-object-atoms": "^1.0.0"
      },
      "engines": {
        "node": ">= 0.4"
      }
    },
    "node_modules/glob-parent": {
      "version": "6.0.2",
      "resolved": "https://registry.npmjs.org/glob-parent/-/glob-parent-6.0.2.tgz",
      "integrity": "sha512-XxwI8EOhVQgWp6iDL+3b0r86f4d6AX6zSU55HfB4ydCEuXLXc5FcYeOu+nnGftS4TEju/11rt4KJPTMgbfmv4A==",
      "dev": true,
      "license": "ISC",
      "dependencies": {
        "is-glob": "^4.0.3"
      },
      "engines": {
        "node": ">=10.13.0"
      }
    },
    "node_modules/glob-to-regexp": {
      "version": "0.4.1",
      "resolved": "https://registry.npmjs.org/glob-to-regexp/-/glob-to-regexp-0.4.1.tgz",
      "integrity": "sha512-lkX1HJXwyMcprw/5YUZc2s7DrpAiHB21/V+E1rHUrVNokkvB6bqMzT0VfV6/86ZNabt1k14YOIaT7nDvOX3Iiw==",
      "dev": true,
      "license": "BSD-2-Clause"
    },
    "node_modules/globby": {
      "version": "13.2.2",
      "resolved": "https://registry.npmjs.org/globby/-/globby-13.2.2.tgz",
      "integrity": "sha512-Y1zNGV+pzQdh7H39l9zgB4PJqjRNqydvdYCDG4HFXM4XuvSaQQlEc91IU1yALL8gUTDomgBAfz3XJdmUS+oo0w==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "dir-glob": "^3.0.1",
        "fast-glob": "^3.3.0",
        "ignore": "^5.2.4",
        "merge2": "^1.4.1",
        "slash": "^4.0.0"
      },
      "engines": {
        "node": "^12.20.0 || ^14.13.1 || >=16.0.0"
      },
      "funding": {
        "url": "https://github.com/sponsors/sindresorhus"
      }
    },
    "node_modules/gopd": {
      "version": "1.2.0",
      "resolved": "https://registry.npmjs.org/gopd/-/gopd-1.2.0.tgz",
      "integrity": "sha512-ZUKRh6/kUFoAiTAtTYPZJ3hw9wNxx+BIBOijnlG9PnrJsCcSjs1wyyD6vJpaYtgnzDrKYRSqf3OO6Rfa93xsRg==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.4"
      },
      "funding": {
        "url": "https://github.com/sponsors/ljharb"
      }
    },
    "node_modules/graceful-fs": {
      "version": "4.2.11",
      "resolved": "https://registry.npmjs.org/graceful-fs/-/graceful-fs-4.2.11.tgz",
      "integrity": "sha512-RbJ5/jmFcNNCcDV5o9eTnBLJ/HszWV0P73bc+Ff4nS/rJj+YaS6IGyiOL0VoBYX+l1Wrl3k63h/KrH+nhJ0XvQ==",
      "dev": true,
      "license": "ISC"
    },
    "node_modules/hachure-fill": {
      "version": "0.5.2",
      "resolved": "https://registry.npmjs.org/hachure-fill/-/hachure-fill-0.5.2.tgz",
      "integrity": "sha512-3GKBOn+m2LX9iq+JC1064cSFprJY4jL1jCXTcpnfER5HYE2l/4EfWSGzkPa/ZDBmYI0ZOEj5VHV/eKnPGkHuOg==",
      "license": "MIT"
    },
    "node_modules/has-flag": {
      "version": "4.0.0",
      "resolved": "https://registry.npmjs.org/has-flag/-/has-flag-4.0.0.tgz",
      "integrity": "sha512-EykJT/Q1KjTWctppgIAgfSO0tKVuZUjhgMr17kqTumMl6Afv3EISleU7qZUzoXDFTAHTDC4NOoG/ZxU3EvlMPQ==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/has-symbols": {
      "version": "1.1.0",
      "resolved": "https://registry.npmjs.org/has-symbols/-/has-symbols-1.1.0.tgz",
      "integrity": "sha512-1cDNdwJ2Jaohmb3sg4OmKaMBwuC48sYni5HUw2DvsC8LjGTLK9h+eb1X6RyuOHe4hT0ULCW68iomhjUoKUqlPQ==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.4"
      },
      "funding": {
        "url": "https://github.com/sponsors/ljharb"
      }
    },
    "node_modules/has-tostringtag": {
      "version": "1.0.2",
      "resolved": "https://registry.npmjs.org/has-tostringtag/-/has-tostringtag-1.0.2.tgz",
      "integrity": "sha512-NqADB8VjPFLM2V0VvHUewwwsw0ZWBaIdgo+ieHtK3hasLz4qeCRjYcqfB6AQrBggRKppKF8L52/VqdVsO47Dlw==",
      "license": "MIT",
      "dependencies": {
        "has-symbols": "^1.0.3"
      },
      "engines": {
        "node": ">= 0.4"
      },
      "funding": {
        "url": "https://github.com/sponsors/ljharb"
      }
    },
    "node_modules/hasown": {
      "version": "2.0.2",
      "resolved": "https://registry.npmjs.org/hasown/-/hasown-2.0.2.tgz",
      "integrity": "sha512-0hJU9SCPvmMzIBdZFqNPXWa6dqh7WdH0cII9y+CyS8rG3nL48Bclra9HmKhVVUHyPWNH5Y7xDwAB7bfgSjkUMQ==",
      "license": "MIT",
      "dependencies": {
        "function-bind": "^1.1.2"
      },
      "engines": {
        "node": ">= 0.4"
      }
    },
    "node_modules/hast-util-to-jsx-runtime": {
      "version": "2.3.6",
      "resolved": "https://registry.npmjs.org/hast-util-to-jsx-runtime/-/hast-util-to-jsx-runtime-2.3.6.tgz",
      "integrity": "sha512-zl6s8LwNyo1P9uw+XJGvZtdFF1GdAkOg8ujOw+4Pyb76874fLps4ueHXDhXWdk6YHQ6OgUtinliG7RsYvCbbBg==",
      "license": "MIT",
      "dependencies": {
        "@types/estree": "^1.0.0",
        "@types/hast": "^3.0.0",
        "@types/unist": "^3.0.0",
        "comma-separated-tokens": "^2.0.0",
        "devlop": "^1.0.0",
        "estree-util-is-identifier-name": "^3.0.0",
        "hast-util-whitespace": "^3.0.0",
        "mdast-util-mdx-expression": "^2.0.0",
        "mdast-util-mdx-jsx": "^3.0.0",
        "mdast-util-mdxjs-esm": "^2.0.0",
        "property-information": "^7.0.0",
        "space-separated-tokens": "^2.0.0",
        "style-to-js": "^1.0.0",
        "unist-util-position": "^5.0.0",
        "vfile-message": "^4.0.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/unified"
      }
    },
    "node_modules/hast-util-whitespace": {
      "version": "3.0.0",
      "resolved": "https://registry.npmjs.org/hast-util-whitespace/-/hast-util-whitespace-3.0.0.tgz",
      "integrity": "sha512-88JUN06ipLwsnv+dVn+OIYOvAuvBMy/Qoi6O7mQHxdPXpjy+Cd6xRkWwux7DKO+4sYILtLBRIKgsdpS2gQc7qw==",
      "license": "MIT",
      "dependencies": {
        "@types/hast": "^3.0.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/unified"
      }
    },
    "node_modules/html-url-attributes": {
      "version": "3.0.1",
      "resolved": "https://registry.npmjs.org/html-url-attributes/-/html-url-attributes-3.0.1.tgz",
      "integrity": "sha512-ol6UPyBWqsrO6EJySPz2O7ZSr856WDrEzM5zMqp+FJJLGMW35cLYmmZnl0vztAZxRUoNZJFTCohfjuIJ8I4QBQ==",
      "license": "MIT",
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/unified"
      }
    },
    "node_modules/humanize-ms": {
      "version": "1.2.1",
      "resolved": "https://registry.npmjs.org/humanize-ms/-/humanize-ms-1.2.1.tgz",
      "integrity": "sha512-Fl70vYtsAFb/C06PTS9dZBo7ihau+Tu/DNCk/OyHhea07S+aeMWpFFkUaXRa8fI+ScZbEI8dfSxwY7gxZ9SAVQ==",
      "license": "MIT",
      "dependencies": {
        "ms": "^2.0.0"
      }
    },
    "node_modules/iconv-lite": {
      "version": "0.6.3",
      "resolved": "https://registry.npmjs.org/iconv-lite/-/iconv-lite-0.6.3.tgz",
      "integrity": "sha512-4fCk79wshMdzMp2rH06qWrJE4iolqLhCUH+OiuIgU++RB0+94NlDL81atO7GX55uUKueo0txHNtvEyI6D7WdMw==",
      "license": "MIT",
      "dependencies": {
        "safer-buffer": ">= 2.1.2 < 3.0.0"
      },
      "engines": {
        "node": ">=0.10.0"
      }
    },
    "node_modules/icss-utils": {
      "version": "5.1.0",
      "resolved": "https://registry.npmjs.org/icss-utils/-/icss-utils-5.1.0.tgz",
      "integrity": "sha512-soFhflCVWLfRNOPU3iv5Z9VUdT44xFRbzjLsEzSr5AQmgqPMTHdU3PMT1Cf1ssx8fLNJDA1juftYl+PUcv3MqA==",
      "dev": true,
      "license": "ISC",
      "engines": {
        "node": "^10 || ^12 || >= 14"
      },
      "peerDependencies": {
        "postcss": "^8.1.0"
      }
    },
    "node_modules/ignore": {
      "version": "5.3.2",
      "resolved": "https://registry.npmjs.org/ignore/-/ignore-5.3.2.tgz",
      "integrity": "sha512-hsBTNUqQTDwkWtcdYI2i06Y/nUBEsNEDJKjWdigLvegy8kDuJAS8uRlpkkcQpyEXL0Z/pjDy5HBmMjRCJ2gq+g==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">= 4"
      }
    },
    "node_modules/import-local": {
      "version": "3.2.0",
      "resolved": "https://registry.npmjs.org/import-local/-/import-local-3.2.0.tgz",
      "integrity": "sha512-2SPlun1JUPWoM6t3F0dw0FkCF/jWY8kttcY4f599GLTSjh2OCuuhdTkJQsEcZzBqbXZGKMK2OqW1oZsjtf/gQA==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "pkg-dir": "^4.2.0",
        "resolve-cwd": "^3.0.0"
      },
      "bin": {
        "import-local-fixture": "fixtures/cli.js"
      },
      "engines": {
        "node": ">=8"
      },
      "funding": {
        "url": "https://github.com/sponsors/sindresorhus"
      }
    },
    "node_modules/inline-style-parser": {
      "version": "0.2.7",
      "resolved": "https://registry.npmjs.org/inline-style-parser/-/inline-style-parser-0.2.7.tgz",
      "integrity": "sha512-Nb2ctOyNR8DqQoR0OwRG95uNWIC0C1lCgf5Naz5H6Ji72KZ8OcFZLz2P5sNgwlyoJ8Yif11oMuYs5pBQa86csA==",
      "license": "MIT"
    },
    "node_modules/internmap": {
      "version": "2.0.3",
      "resolved": "https://registry.npmjs.org/internmap/-/internmap-2.0.3.tgz",
      "integrity": "sha512-5Hh7Y1wQbvY5ooGgPbDaL5iYLAPzMTUrjMulskHLH6wnv/A+1q5rgEaiuqEjB+oxGXIVZs1FF+R/KPN3ZSQYYg==",
      "license": "ISC",
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/interpret": {
      "version": "3.1.1",
      "resolved": "https://registry.npmjs.org/interpret/-/interpret-3.1.1.tgz",
      "integrity": "sha512-6xwYfHbajpoF0xLW+iwLkhwgvLoZDfjYfoFNu8ftMoXINzwuymNLd9u/KmwtdT2GbR+/Cz66otEGEVVUHX9QLQ==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=10.13.0"
      }
    },
    "node_modules/is-alphabetical": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/is-alphabetical/-/is-alphabetical-2.0.1.tgz",
      "integrity": "sha512-FWyyY60MeTNyeSRpkM2Iry0G9hpr7/9kD40mD/cGQEuilcZYS4okz8SN2Q6rLCJ8gbCt6fN+rC+6tMGS99LaxQ==",
      "license": "MIT",
      "funding": {
        "type": "github",
        "url": "https://github.com/sponsors/wooorm"
      }
    },
    "node_modules/is-alphanumerical": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/is-alphanumerical/-/is-alphanumerical-2.0.1.tgz",
      "integrity": "sha512-hmbYhX/9MUMF5uh7tOXyK/n0ZvWpad5caBA17GsC6vyuCqaWliRG5K1qS9inmUhEMaOBIW7/whAnSwveW/LtZw==",
      "license": "MIT",
      "dependencies": {
        "is-alphabetical": "^2.0.0",
        "is-decimal": "^2.0.0"
      },
      "funding": {
        "type": "github",
        "url": "https://github.com/sponsors/wooorm"
      }
    },
    "node_modules/is-core-module": {
      "version": "2.16.1",
      "resolved": "https://registry.npmjs.org/is-core-module/-/is-core-module-2.16.1.tgz",
      "integrity": "sha512-UfoeMA6fIJ8wTYFEUjelnaGI67v6+N7qXJEvQuIGa99l4xsCruSYOVSQ0uPANn4dAzm8lkYPaKLrrijLq7x23w==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "hasown": "^2.0.2"
      },
      "engines": {
        "node": ">= 0.4"
      },
      "funding": {
        "url": "https://github.com/sponsors/ljharb"
      }
    },
    "node_modules/is-decimal": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/is-decimal/-/is-decimal-2.0.1.tgz",
      "integrity": "sha512-AAB9hiomQs5DXWcRB1rqsxGUstbRroFOPPVAomNk/3XHR5JyEZChOyTWe2oayKnsSsr/kcGqF+z6yuH6HHpN0A==",
      "license": "MIT",
      "funding": {
        "type": "github",
        "url": "https://github.com/sponsors/wooorm"
      }
    },
    "node_modules/is-extglob": {
      "version": "2.1.1",
      "resolved": "https://registry.npmjs.org/is-extglob/-/is-extglob-2.1.1.tgz",
      "integrity": "sha512-SbKbANkN603Vi4jEZv49LeVJMn4yGwsbzZworEoyEiutsN3nJYdbO36zfhGJ6QEDpOZIFkDtnq5JRxmvl3jsoQ==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=0.10.0"
      }
    },
    "node_modules/is-glob": {
      "version": "4.0.3",
      "resolved": "https://registry.npmjs.org/is-glob/-/is-glob-4.0.3.tgz",
      "integrity": "sha512-xelSayHH36ZgE7ZWhli7pW34hNbNl8Ojv5KVmkJD4hBdD3th8Tfk9vYasLM+mXWOZhFkgZfxhLSnrwRr4elSSg==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "is-extglob": "^2.1.1"
      },
      "engines": {
        "node": ">=0.10.0"
      }
    },
    "node_modules/is-hexadecimal": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/is-hexadecimal/-/is-hexadecimal-2.0.1.tgz",
      "integrity": "sha512-DgZQp241c8oO6cA1SbTEWiXeoxV42vlcJxgH+B3hi1AiqqKruZR3ZGF8In3fj4+/y/7rHvlOZLZtgJ/4ttYGZg==",
      "license": "MIT",
      "funding": {
        "type": "github",
        "url": "https://github.com/sponsors/wooorm"
      }
    },
    "node_modules/is-number": {
      "version": "7.0.0",
      "resolved": "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz",
      "integrity": "sha512-41Cifkg6e8TylSpdtTpeLVMqvSBEVzTttHvERD741+pnZ8ANv0004MRL43QKPDlK9cGvNp6NZWZUBlbGXYxxng==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=0.12.0"
      }
    },
    "node_modules/is-plain-obj": {
      "version": "4.1.0",
      "resolved": "https://registry.npmjs.org/is-plain-obj/-/is-plain-obj-4.1.0.tgz",
      "integrity": "sha512-+Pgi+vMuUNkJyExiMBt5IlFoMyKnr5zhJ4Uspz58WOhBF5QoIZkFyNHIbBAtHwzVAgk5RtndVNsDRN61/mmDqg==",
      "license": "MIT",
      "engines": {
        "node": ">=12"
      },
      "funding": {
        "url": "https://github.com/sponsors/sindresorhus"
      }
    },
    "node_modules/is-plain-object": {
      "version": "2.0.4",
      "resolved": "https://registry.npmjs.org/is-plain-object/-/is-plain-object-2.0.4.tgz",
      "integrity": "sha512-h5PpgXkWitc38BBMYawTYMWJHFZJVnBquFE57xFpjB8pJFiF6gZ+bU+WyI/yqXiFR5mdLsgYNaPe8uao6Uv9Og==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "isobject": "^3.0.1"
      },
      "engines": {
        "node": ">=0.10.0"
      }
    },
    "node_modules/isexe": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/isexe/-/isexe-2.0.0.tgz",
      "integrity": "sha512-RHxMLp9lnKHGHRng9QFhRCMbYAcVpn69smSGcq3f36xjgVVWThj4qqLbTLlq7Ssj8B+fIQ1EuCEGI2lKsyQeIw==",
      "dev": true,
      "license": "ISC"
    },
    "node_modules/isobject": {
      "version": "3.0.1",
      "resolved": "https://registry.npmjs.org/isobject/-/isobject-3.0.1.tgz",
      "integrity": "sha512-WhB9zCku7EGTj/HQQRz5aUQEUeoQZH2bWcltRErOpymJ4boYE6wL9Tbr23krRPSZ+C5zqNSrSw+Cc7sZZ4b7vg==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=0.10.0"
      }
    },
    "node_modules/jest-worker": {
      "version": "27.5.1",
      "resolved": "https://registry.npmjs.org/jest-worker/-/jest-worker-27.5.1.tgz",
      "integrity": "sha512-7vuh85V5cdDofPyxn58nrPjBktZo0u9x1g8WtjQol+jZDaE+fhN+cIvTj11GndBnMnyfrUOG1sZQxCdjKh+DKg==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@types/node": "*",
        "merge-stream": "^2.0.0",
        "supports-color": "^8.0.0"
      },
      "engines": {
        "node": ">= 10.13.0"
      }
    },
    "node_modules/jest-worker/node_modules/supports-color": {
      "version": "8.1.1",
      "resolved": "https://registry.npmjs.org/supports-color/-/supports-color-8.1.1.tgz",
      "integrity": "sha512-MpUEN2OodtUzxvKQl72cUF7RQ5EiHsGvSsVG0ia9c5RbWGL2CI4C7EpPS8UTBIplnlzZiNuV56w+FuNxy3ty2Q==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "has-flag": "^4.0.0"
      },
      "engines": {
        "node": ">=10"
      },
      "funding": {
        "url": "https://github.com/chalk/supports-color?sponsor=1"
      }
    },
    "node_modules/js-tokens": {
      "version": "4.0.0",
      "resolved": "https://registry.npmjs.org/js-tokens/-/js-tokens-4.0.0.tgz",
      "integrity": "sha512-RdJUflcE3cUzKiMqQgsCu06FPu9UdIJO0beYbPhHN4k6apgJtifcoCtT9bcxOpYBtpD2kCM6Sbzg4CausW/PKQ==",
      "license": "MIT"
    },
    "node_modules/json-parse-even-better-errors": {
      "version": "2.3.1",
      "resolved": "https://registry.npmjs.org/json-parse-even-better-errors/-/json-parse-even-better-errors-2.3.1.tgz",
      "integrity": "sha512-xyFwyhro/JEof6Ghe2iz2NcXoj2sloNsWr/XsERDK/oiPCfaNhl5ONfp+jQdAZRQQ0IJWNzH9zIZF7li91kh2w==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/json-schema-traverse": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/json-schema-traverse/-/json-schema-traverse-1.0.0.tgz",
      "integrity": "sha512-NM8/P9n3XjXhIZn1lLhkFaACTOURQXjWhV4BA/RnOv8xvgqtqpAX9IO4mRQxSx1Rlo4tqzeqb0sOlruaOy3dug==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/katex": {
      "version": "0.16.25",
      "resolved": "https://registry.npmjs.org/katex/-/katex-0.16.25.tgz",
      "integrity": "sha512-woHRUZ/iF23GBP1dkDQMh1QBad9dmr8/PAwNA54VrSOVYgI12MAcE14TqnDdQOdzyEonGzMepYnqBMYdsoAr8Q==",
      "funding": [
        "https://opencollective.com/katex",
        "https://github.com/sponsors/katex"
      ],
      "license": "MIT",
      "dependencies": {
        "commander": "^8.3.0"
      },
      "bin": {
        "katex": "cli.js"
      }
    },
    "node_modules/katex/node_modules/commander": {
      "version": "8.3.0",
      "resolved": "https://registry.npmjs.org/commander/-/commander-8.3.0.tgz",
      "integrity": "sha512-OkTL9umf+He2DZkUq8f8J9of7yL6RJKI24dVITBmNfZBmri9zYZQrKkuXiKhyfPSu8tUhnVBB1iKXevvnlR4Ww==",
      "license": "MIT",
      "engines": {
        "node": ">= 12"
      }
    },
    "node_modules/khroma": {
      "version": "2.1.0",
      "resolved": "https://registry.npmjs.org/khroma/-/khroma-2.1.0.tgz",
      "integrity": "sha512-Ls993zuzfayK269Svk9hzpeGUKob/sIgZzyHYdjQoAdQetRKpOLj+k/QQQ/6Qi0Yz65mlROrfd+Ev+1+7dz9Kw=="
    },
    "node_modules/kind-of": {
      "version": "6.0.3",
      "resolved": "https://registry.npmjs.org/kind-of/-/kind-of-6.0.3.tgz",
      "integrity": "sha512-dcS1ul+9tmeD95T+x28/ehLgd9mENa3LsvDTtzm3vyBEO7RPptvAD+t44WVXaUjTBRcrpFeFlC8WCruUR456hw==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=0.10.0"
      }
    },
    "node_modules/langium": {
      "version": "3.3.1",
      "resolved": "https://registry.npmjs.org/langium/-/langium-3.3.1.tgz",
      "integrity": "sha512-QJv/h939gDpvT+9SiLVlY7tZC3xB2qK57v0J04Sh9wpMb6MP1q8gB21L3WIo8T5P1MSMg3Ep14L7KkDCFG3y4w==",
      "license": "MIT",
      "dependencies": {
        "chevrotain": "~11.0.3",
        "chevrotain-allstar": "~0.3.0",
        "vscode-languageserver": "~9.0.1",
        "vscode-languageserver-textdocument": "~1.0.11",
        "vscode-uri": "~3.0.8"
      },
      "engines": {
        "node": ">=16.0.0"
      }
    },
    "node_modules/layout-base": {
      "version": "1.0.2",
      "resolved": "https://registry.npmjs.org/layout-base/-/layout-base-1.0.2.tgz",
      "integrity": "sha512-8h2oVEZNktL4BH2JCOI90iD1yXwL6iNW7KcCKT2QZgQJR2vbqDsldCTPRU9NifTCqHZci57XvQQ15YTu+sTYPg==",
      "license": "MIT"
    },
    "node_modules/loader-runner": {
      "version": "4.3.1",
      "resolved": "https://registry.npmjs.org/loader-runner/-/loader-runner-4.3.1.tgz",
      "integrity": "sha512-IWqP2SCPhyVFTBtRcgMHdzlf9ul25NwaFx4wCEH/KjAXuuHY4yNjvPXsBokp8jCB936PyWRaPKUNh8NvylLp2Q==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=6.11.5"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/webpack"
      }
    },
    "node_modules/locate-path": {
      "version": "5.0.0",
      "resolved": "https://registry.npmjs.org/locate-path/-/locate-path-5.0.0.tgz",
      "integrity": "sha512-t7hw9pI+WvuwNJXwk5zVHpyhIqzg2qTlklJOf0mVxGSbe3Fp2VieZcduNYjaLDoy6p9uGpQEGWG87WpMKlNq8g==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "p-locate": "^4.1.0"
      },
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/lodash-es": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash-es/-/lodash-es-4.17.21.tgz",
      "integrity": "sha512-mKnC+QJ9pWVzv+C4/U3rRsHapFfHvQFoFB92e52xeyGMcX6/OlIl78je1u8vePzYZSkkogMPJ2yjxxsb89cxyw==",
      "license": "MIT"
    },
    "node_modules/longest-streak": {
      "version": "3.1.0",
      "resolved": "https://registry.npmjs.org/longest-streak/-/longest-streak-3.1.0.tgz",
      "integrity": "sha512-9Ri+o0JYgehTaVBBDoMqIl8GXtbWg711O3srftcHhZ0dqnETqLaoIK0x17fUw9rFSlK/0NlsKe0Ahhyl5pXE2g==",
      "license": "MIT",
      "funding": {
        "type": "github",
        "url": "https://github.com/sponsors/wooorm"
      }
    },
    "node_modules/loose-envify": {
      "version": "1.4.0",
      "resolved": "https://registry.npmjs.org/loose-envify/-/loose-envify-1.4.0.tgz",
      "integrity": "sha512-lyuxPGr/Wfhrlem2CL/UcnUc1zcqKAImBDzukY7Y5F/yQiNdko6+fRLevlw1HgMySw7f611UIY408EtxRSoK3Q==",
      "license": "MIT",
      "dependencies": {
        "js-tokens": "^3.0.0 || ^4.0.0"
      },
      "bin": {
        "loose-envify": "cli.js"
      }
    },
    "node_modules/lucide-react": {
      "version": "0.555.0",
      "resolved": "https://registry.npmjs.org/lucide-react/-/lucide-react-0.555.0.tgz",
      "integrity": "sha512-D8FvHUGbxWBRQM90NZeIyhAvkFfsh3u9ekrMvJ30Z6gnpBHS6HC6ldLg7tL45hwiIz/u66eKDtdA23gwwGsAHA==",
      "license": "ISC",
      "peerDependencies": {
        "react": "^16.5.1 || ^17.0.0 || ^18.0.0 || ^19.0.0"
      }
    },
    "node_modules/marked": {
      "version": "16.4.2",
      "resolved": "https://registry.npmjs.org/marked/-/marked-16.4.2.tgz",
      "integrity": "sha512-TI3V8YYWvkVf3KJe1dRkpnjs68JUPyEa5vjKrp1XEEJUAOaQc+Qj+L1qWbPd0SJuAdQkFU0h73sXXqwDYxsiDA==",
      "license": "MIT",
      "bin": {
        "marked": "bin/marked.js"
      },
      "engines": {
        "node": ">= 20"
      }
    },
    "node_modules/math-intrinsics": {
      "version": "1.1.0",
      "resolved": "https://registry.npmjs.org/math-intrinsics/-/math-intrinsics-1.1.0.tgz",
      "integrity": "sha512-/IXtbwEk5HTPyEwyKX6hGkYXxM9nbj64B+ilVJnC/R6B0pH5G4V3b0pVbL7DBj4tkhBAppbQUlf6F6Xl9LHu1g==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.4"
      }
    },
    "node_modules/mdast-util-from-markdown": {
      "version": "2.0.2",
      "resolved": "https://registry.npmjs.org/mdast-util-from-markdown/-/mdast-util-from-markdown-2.0.2.tgz",
      "integrity": "sha512-uZhTV/8NBuw0WHkPTrCqDOl0zVe1BIng5ZtHoDk49ME1qqcjYmmLmOf0gELgcRMxN4w2iuIeVso5/6QymSrgmA==",
      "license": "MIT",
      "dependencies": {
        "@types/mdast": "^4.0.0",
        "@types/unist": "^3.0.0",
        "decode-named-character-reference": "^1.0.0",
        "devlop": "^1.0.0",
        "mdast-util-to-string": "^4.0.0",
        "micromark": "^4.0.0",
        "micromark-util-decode-numeric-character-reference": "^2.0.0",
        "micromark-util-decode-string": "^2.0.0",
        "micromark-util-normalize-identifier": "^2.0.0",
        "micromark-util-symbol": "^2.0.0",
        "micromark-util-types": "^2.0.0",
        "unist-util-stringify-position": "^4.0.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/unified"
      }
    },
    "node_modules/mdast-util-mdx-expression": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/mdast-util-mdx-expression/-/mdast-util-mdx-expression-2.0.1.tgz",
      "integrity": "sha512-J6f+9hUp+ldTZqKRSg7Vw5V6MqjATc+3E4gf3CFNcuZNWD8XdyI6zQ8GqH7f8169MM6P7hMBRDVGnn7oHB9kXQ==",
      "license": "MIT",
      "dependencies": {
        "@types/estree-jsx": "^1.0.0",
        "@types/hast": "^3.0.0",
        "@types/mdast": "^4.0.0",
        "devlop": "^1.0.0",
        "mdast-util-from-markdown": "^2.0.0",
        "mdast-util-to-markdown": "^2.0.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/unified"
      }
    },
    "node_modules/mdast-util-mdx-jsx": {
      "version": "3.2.0",
      "resolved": "https://registry.npmjs.org/mdast-util-mdx-jsx/-/mdast-util-mdx-jsx-3.2.0.tgz",
      "integrity": "sha512-lj/z8v0r6ZtsN/cGNNtemmmfoLAFZnjMbNyLzBafjzikOM+glrjNHPlf6lQDOTccj9n5b0PPihEBbhneMyGs1Q==",
      "license": "MIT",
      "dependencies": {
        "@types/estree-jsx": "^1.0.0",
        "@types/hast": "^3.0.0",
        "@types/mdast": "^4.0.0",
        "@types/unist": "^3.0.0",
        "ccount": "^2.0.0",
        "devlop": "^1.1.0",
        "mdast-util-from-markdown": "^2.0.0",
        "mdast-util-to-markdown": "^2.0.0",
        "parse-entities": "^4.0.0",
        "stringify-entities": "^4.0.0",
        "unist-util-stringify-position": "^4.0.0",
        "vfile-message": "^4.0.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/unified"
      }
    },
    "node_modules/mdast-util-mdxjs-esm": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/mdast-util-mdxjs-esm/-/mdast-util-mdxjs-esm-2.0.1.tgz",
      "integrity": "sha512-EcmOpxsZ96CvlP03NghtH1EsLtr0n9Tm4lPUJUBccV9RwUOneqSycg19n5HGzCf+10LozMRSObtVr3ee1WoHtg==",
      "license": "MIT",
      "dependencies": {
        "@types/estree-jsx": "^1.0.0",
        "@types/hast": "^3.0.0",
        "@types/mdast": "^4.0.0",
        "devlop": "^1.0.0",
        "mdast-util-from-markdown": "^2.0.0",
        "mdast-util-to-markdown": "^2.0.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/unified"
      }
    },
    "node_modules/mdast-util-phrasing": {
      "version": "4.1.0",
      "resolved": "https://registry.npmjs.org/mdast-util-phrasing/-/mdast-util-phrasing-4.1.0.tgz",
      "integrity": "sha512-TqICwyvJJpBwvGAMZjj4J2n0X8QWp21b9l0o7eXyVJ25YNWYbJDVIyD1bZXE6WtV6RmKJVYmQAKWa0zWOABz2w==",
      "license": "MIT",
      "dependencies": {
        "@types/mdast": "^4.0.0",
        "unist-util-is": "^6.0.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/unified"
      }
    },
    "node_modules/mdast-util-to-hast": {
      "version": "13.2.1",
      "resolved": "https://registry.npmjs.org/mdast-util-to-hast/-/mdast-util-to-hast-13.2.1.tgz",
      "integrity": "sha512-cctsq2wp5vTsLIcaymblUriiTcZd0CwWtCbLvrOzYCDZoWyMNV8sZ7krj09FSnsiJi3WVsHLM4k6Dq/yaPyCXA==",
      "license": "MIT",
      "dependencies": {
        "@types/hast": "^3.0.0",
        "@types/mdast": "^4.0.0",
        "@ungap/structured-clone": "^1.0.0",
        "devlop": "^1.0.0",
        "micromark-util-sanitize-uri": "^2.0.0",
        "trim-lines": "^3.0.0",
        "unist-util-position": "^5.0.0",
        "unist-util-visit": "^5.0.0",
        "vfile": "^6.0.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/unified"
      }
    },
    "node_modules/mdast-util-to-markdown": {
      "version": "2.1.2",
      "resolved": "https://registry.npmjs.org/mdast-util-to-markdown/-/mdast-util-to-markdown-2.1.2.tgz",
      "integrity": "sha512-xj68wMTvGXVOKonmog6LwyJKrYXZPvlwabaryTjLh9LuvovB/KAH+kvi8Gjj+7rJjsFi23nkUxRQv1KqSroMqA==",
      "license": "MIT",
      "dependencies": {
        "@types/mdast": "^4.0.0",
        "@types/unist": "^3.0.0",
        "longest-streak": "^3.0.0",
        "mdast-util-phrasing": "^4.0.0",
        "mdast-util-to-string": "^4.0.0",
        "micromark-util-classify-character": "^2.0.0",
        "micromark-util-decode-string": "^2.0.0",
        "unist-util-visit": "^5.0.0",
        "zwitch": "^2.0.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/unified"
      }
    },
    "node_modules/mdast-util-to-string": {
      "version": "4.0.0",
      "resolved": "https://registry.npmjs.org/mdast-util-to-string/-/mdast-util-to-string-4.0.0.tgz",
      "integrity": "sha512-0H44vDimn51F0YwvxSJSm0eCDOJTRlmN0R1yBh4HLj9wiV1Dn0QoXGbvFAWj2hSItVTlCmBF1hqKlIyUBVFLPg==",
      "license": "MIT",
      "dependencies": {
        "@types/mdast": "^4.0.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/unified"
      }
    },
    "node_modules/merge-stream": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/merge-stream/-/merge-stream-2.0.0.tgz",
      "integrity": "sha512-abv/qOcuPfk3URPfDzmZU1LKmuw8kT+0nIHvKrKgFrwifol/doWcdA4ZqsWQ8ENrFKkd67Mfpo/LovbIUsbt3w==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/merge2": {
      "version": "1.4.1",
      "resolved": "https://registry.npmjs.org/merge2/-/merge2-1.4.1.tgz",
      "integrity": "sha512-8q7VEgMJW4J8tcfVPy8g09NcQwZdbwFEqhe/WZkoIzjn/3TGDwtOCYtXGxA3O8tPzpczCCDgv+P2P5y00ZJOOg==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">= 8"
      }
    },
    "node_modules/mermaid": {
      "version": "11.12.1",
      "resolved": "https://registry.npmjs.org/mermaid/-/mermaid-11.12.1.tgz",
      "integrity": "sha512-UlIZrRariB11TY1RtTgUWp65tphtBv4CSq7vyS2ZZ2TgoMjs2nloq+wFqxiwcxlhHUvs7DPGgMjs2aeQxz5h9g==",
      "license": "MIT",
      "dependencies": {
        "@braintree/sanitize-url": "^7.1.1",
        "@iconify/utils": "^3.0.1",
        "@mermaid-js/parser": "^0.6.3",
        "@types/d3": "^7.4.3",
        "cytoscape": "^3.29.3",
        "cytoscape-cose-bilkent": "^4.1.0",
        "cytoscape-fcose": "^2.2.0",
        "d3": "^7.9.0",
        "d3-sankey": "^0.12.3",
        "dagre-d3-es": "7.0.13",
        "dayjs": "^1.11.18",
        "dompurify": "^3.2.5",
        "katex": "^0.16.22",
        "khroma": "^2.1.0",
        "lodash-es": "^4.17.21",
        "marked": "^16.2.1",
        "roughjs": "^4.6.6",
        "stylis": "^4.3.6",
        "ts-dedent": "^2.2.0",
        "uuid": "^11.1.0"
      }
    },
    "node_modules/micromark": {
      "version": "4.0.2",
      "resolved": "https://registry.npmjs.org/micromark/-/micromark-4.0.2.tgz",
      "integrity": "sha512-zpe98Q6kvavpCr1NPVSCMebCKfD7CA2NqZ+rykeNhONIJBpc1tFKt9hucLGwha3jNTNI8lHpctWJWoimVF4PfA==",
      "funding": [
        {
          "type": "GitHub Sponsors",
          "url": "https://github.com/sponsors/unifiedjs"
        },
        {
          "type": "OpenCollective",
          "url": "https://opencollective.com/unified"
        }
      ],
      "license": "MIT",
      "dependencies": {
        "@types/debug": "^4.0.0",
        "debug": "^4.0.0",
        "decode-named-character-reference": "^1.0.0",
        "devlop": "^1.0.0",
        "micromark-core-commonmark": "^2.0.0",
        "micromark-factory-space": "^2.0.0",
        "micromark-util-character": "^2.0.0",
        "micromark-util-chunked": "^2.0.0",
        "micromark-util-combine-extensions": "^2.0.0",
        "micromark-util-decode-numeric-character-reference": "^2.0.0",
        "micromark-util-encode": "^2.0.0",
        "micromark-util-normalize-identifier": "^2.0.0",
        "micromark-util-resolve-all": "^2.0.0",
        "micromark-util-sanitize-uri": "^2.0.0",
        "micromark-util-subtokenize": "^2.0.0",
        "micromark-util-symbol": "^2.0.0",
        "micromark-util-types": "^2.0.0"
      }
    },
    "node_modules/micromark-core-commonmark": {
      "version": "2.0.3",
      "resolved": "https://registry.npmjs.org/micromark-core-commonmark/-/micromark-core-commonmark-2.0.3.tgz",
      "integrity": "sha512-RDBrHEMSxVFLg6xvnXmb1Ayr2WzLAWjeSATAoxwKYJV94TeNavgoIdA0a9ytzDSVzBy2YKFK+emCPOEibLeCrg==",
      "funding": [
        {
          "type": "GitHub Sponsors",
          "url": "https://github.com/sponsors/unifiedjs"
        },
        {
          "type": "OpenCollective",
          "url": "https://opencollective.com/unified"
        }
      ],
      "license": "MIT",
      "dependencies": {
        "decode-named-character-reference": "^1.0.0",
        "devlop": "^1.0.0",
        "micromark-factory-destination": "^2.0.0",
        "micromark-factory-label": "^2.0.0",
        "micromark-factory-space": "^2.0.0",
        "micromark-factory-title": "^2.0.0",
        "micromark-factory-whitespace": "^2.0.0",
        "micromark-util-character": "^2.0.0",
        "micromark-util-chunked": "^2.0.0",
        "micromark-util-classify-character": "^2.0.0",
        "micromark-util-html-tag-name": "^2.0.0",
        "micromark-util-normalize-identifier": "^2.0.0",
        "micromark-util-resolve-all": "^2.0.0",
        "micromark-util-subtokenize": "^2.0.0",
        "micromark-util-symbol": "^2.0.0",
        "micromark-util-types": "^2.0.0"
      }
    },
    "node_modules/micromark-factory-destination": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/micromark-factory-destination/-/micromark-factory-destination-2.0.1.tgz",
      "integrity": "sha512-Xe6rDdJlkmbFRExpTOmRj9N3MaWmbAgdpSrBQvCFqhezUn4AHqJHbaEnfbVYYiexVSs//tqOdY/DxhjdCiJnIA==",
      "funding": [
        {
          "type": "GitHub Sponsors",
          "url": "https://github.com/sponsors/unifiedjs"
        },
        {
          "type": "OpenCollective",
          "url": "https://opencollective.com/unified"
        }
      ],
      "license": "MIT",
      "dependencies": {
        "micromark-util-character": "^2.0.0",
        "micromark-util-symbol": "^2.0.0",
        "micromark-util-types": "^2.0.0"
      }
    },
    "node_modules/micromark-factory-label": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/micromark-factory-label/-/micromark-factory-label-2.0.1.tgz",
      "integrity": "sha512-VFMekyQExqIW7xIChcXn4ok29YE3rnuyveW3wZQWWqF4Nv9Wk5rgJ99KzPvHjkmPXF93FXIbBp6YdW3t71/7Vg==",
      "funding": [
        {
          "type": "GitHub Sponsors",
          "url": "https://github.com/sponsors/unifiedjs"
        },
        {
          "type": "OpenCollective",
          "url": "https://opencollective.com/unified"
        }
      ],
      "license": "MIT",
      "dependencies": {
        "devlop": "^1.0.0",
        "micromark-util-character": "^2.0.0",
        "micromark-util-symbol": "^2.0.0",
        "micromark-util-types": "^2.0.0"
      }
    },
    "node_modules/micromark-factory-space": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/micromark-factory-space/-/micromark-factory-space-2.0.1.tgz",
      "integrity": "sha512-zRkxjtBxxLd2Sc0d+fbnEunsTj46SWXgXciZmHq0kDYGnck/ZSGj9/wULTV95uoeYiK5hRXP2mJ98Uo4cq/LQg==",
      "funding": [
        {
          "type": "GitHub Sponsors",
          "url": "https://github.com/sponsors/unifiedjs"
        },
        {
          "type": "OpenCollective",
          "url": "https://opencollective.com/unified"
        }
      ],
      "license": "MIT",
      "dependencies": {
        "micromark-util-character": "^2.0.0",
        "micromark-util-types": "^2.0.0"
      }
    },
    "node_modules/micromark-factory-title": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/micromark-factory-title/-/micromark-factory-title-2.0.1.tgz",
      "integrity": "sha512-5bZ+3CjhAd9eChYTHsjy6TGxpOFSKgKKJPJxr293jTbfry2KDoWkhBb6TcPVB4NmzaPhMs1Frm9AZH7OD4Cjzw==",
      "funding": [
        {
          "type": "GitHub Sponsors",
          "url": "https://github.com/sponsors/unifiedjs"
        },
        {
          "type": "OpenCollective",
          "url": "https://opencollective.com/unified"
        }
      ],
      "license": "MIT",
      "dependencies": {
        "micromark-factory-space": "^2.0.0",
        "micromark-util-character": "^2.0.0",
        "micromark-util-symbol": "^2.0.0",
        "micromark-util-types": "^2.0.0"
      }
    },
    "node_modules/micromark-factory-whitespace": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/micromark-factory-whitespace/-/micromark-factory-whitespace-2.0.1.tgz",
      "integrity": "sha512-Ob0nuZ3PKt/n0hORHyvoD9uZhr+Za8sFoP+OnMcnWK5lngSzALgQYKMr9RJVOWLqQYuyn6ulqGWSXdwf6F80lQ==",
      "funding": [
        {
          "type": "GitHub Sponsors",
          "url": "https://github.com/sponsors/unifiedjs"
        },
        {
          "type": "OpenCollective",
          "url": "https://opencollective.com/unified"
        }
      ],
      "license": "MIT",
      "dependencies": {
        "micromark-factory-space": "^2.0.0",
        "micromark-util-character": "^2.0.0",
        "micromark-util-symbol": "^2.0.0",
        "micromark-util-types": "^2.0.0"
      }
    },
    "node_modules/micromark-util-character": {
      "version": "2.1.1",
      "resolved": "https://registry.npmjs.org/micromark-util-character/-/micromark-util-character-2.1.1.tgz",
      "integrity": "sha512-wv8tdUTJ3thSFFFJKtpYKOYiGP2+v96Hvk4Tu8KpCAsTMs6yi+nVmGh1syvSCsaxz45J6Jbw+9DD6g97+NV67Q==",
      "funding": [
        {
          "type": "GitHub Sponsors",
          "url": "https://github.com/sponsors/unifiedjs"
        },
        {
          "type": "OpenCollective",
          "url": "https://opencollective.com/unified"
        }
      ],
      "license": "MIT",
      "dependencies": {
        "micromark-util-symbol": "^2.0.0",
        "micromark-util-types": "^2.0.0"
      }
    },
    "node_modules/micromark-util-chunked": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/micromark-util-chunked/-/micromark-util-chunked-2.0.1.tgz",
      "integrity": "sha512-QUNFEOPELfmvv+4xiNg2sRYeS/P84pTW0TCgP5zc9FpXetHY0ab7SxKyAQCNCc1eK0459uoLI1y5oO5Vc1dbhA==",
      "funding": [
        {
          "type": "GitHub Sponsors",
          "url": "https://github.com/sponsors/unifiedjs"
        },
        {
          "type": "OpenCollective",
          "url": "https://opencollective.com/unified"
        }
      ],
      "license": "MIT",
      "dependencies": {
        "micromark-util-symbol": "^2.0.0"
      }
    },
    "node_modules/micromark-util-classify-character": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/micromark-util-classify-character/-/micromark-util-classify-character-2.0.1.tgz",
      "integrity": "sha512-K0kHzM6afW/MbeWYWLjoHQv1sgg2Q9EccHEDzSkxiP/EaagNzCm7T/WMKZ3rjMbvIpvBiZgwR3dKMygtA4mG1Q==",
      "funding": [
        {
          "type": "GitHub Sponsors",
          "url": "https://github.com/sponsors/unifiedjs"
        },
        {
          "type": "OpenCollective",
          "url": "https://opencollective.com/unified"
        }
      ],
      "license": "MIT",
      "dependencies": {
        "micromark-util-character": "^2.0.0",
        "micromark-util-symbol": "^2.0.0",
        "micromark-util-types": "^2.0.0"
      }
    },
    "node_modules/micromark-util-combine-extensions": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/micromark-util-combine-extensions/-/micromark-util-combine-extensions-2.0.1.tgz",
      "integrity": "sha512-OnAnH8Ujmy59JcyZw8JSbK9cGpdVY44NKgSM7E9Eh7DiLS2E9RNQf0dONaGDzEG9yjEl5hcqeIsj4hfRkLH/Bg==",
      "funding": [
        {
          "type": "GitHub Sponsors",
          "url": "https://github.com/sponsors/unifiedjs"
        },
        {
          "type": "OpenCollective",
          "url": "https://opencollective.com/unified"
        }
      ],
      "license": "MIT",
      "dependencies": {
        "micromark-util-chunked": "^2.0.0",
        "micromark-util-types": "^2.0.0"
      }
    },
    "node_modules/micromark-util-decode-numeric-character-reference": {
      "version": "2.0.2",
      "resolved": "https://registry.npmjs.org/micromark-util-decode-numeric-character-reference/-/micromark-util-decode-numeric-character-reference-2.0.2.tgz",
      "integrity": "sha512-ccUbYk6CwVdkmCQMyr64dXz42EfHGkPQlBj5p7YVGzq8I7CtjXZJrubAYezf7Rp+bjPseiROqe7G6foFd+lEuw==",
      "funding": [
        {
          "type": "GitHub Sponsors",
          "url": "https://github.com/sponsors/unifiedjs"
        },
        {
          "type": "OpenCollective",
          "url": "https://opencollective.com/unified"
        }
      ],
      "license": "MIT",
      "dependencies": {
        "micromark-util-symbol": "^2.0.0"
      }
    },
    "node_modules/micromark-util-decode-string": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/micromark-util-decode-string/-/micromark-util-decode-string-2.0.1.tgz",
      "integrity": "sha512-nDV/77Fj6eH1ynwscYTOsbK7rR//Uj0bZXBwJZRfaLEJ1iGBR6kIfNmlNqaqJf649EP0F3NWNdeJi03elllNUQ==",
      "funding": [
        {
          "type": "GitHub Sponsors",
          "url": "https://github.com/sponsors/unifiedjs"
        },
        {
          "type": "OpenCollective",
          "url": "https://opencollective.com/unified"
        }
      ],
      "license": "MIT",
      "dependencies": {
        "decode-named-character-reference": "^1.0.0",
        "micromark-util-character": "^2.0.0",
        "micromark-util-decode-numeric-character-reference": "^2.0.0",
        "micromark-util-symbol": "^2.0.0"
      }
    },
    "node_modules/micromark-util-encode": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/micromark-util-encode/-/micromark-util-encode-2.0.1.tgz",
      "integrity": "sha512-c3cVx2y4KqUnwopcO9b/SCdo2O67LwJJ/UyqGfbigahfegL9myoEFoDYZgkT7f36T0bLrM9hZTAaAyH+PCAXjw==",
      "funding": [
        {
          "type": "GitHub Sponsors",
          "url": "https://github.com/sponsors/unifiedjs"
        },
        {
          "type": "OpenCollective",
          "url": "https://opencollective.com/unified"
        }
      ],
      "license": "MIT"
    },
    "node_modules/micromark-util-html-tag-name": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/micromark-util-html-tag-name/-/micromark-util-html-tag-name-2.0.1.tgz",
      "integrity": "sha512-2cNEiYDhCWKI+Gs9T0Tiysk136SnR13hhO8yW6BGNyhOC4qYFnwF1nKfD3HFAIXA5c45RrIG1ub11GiXeYd1xA==",
      "funding": [
        {
          "type": "GitHub Sponsors",
          "url": "https://github.com/sponsors/unifiedjs"
        },
        {
          "type": "OpenCollective",
          "url": "https://opencollective.com/unified"
        }
      ],
      "license": "MIT"
    },
    "node_modules/micromark-util-normalize-identifier": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/micromark-util-normalize-identifier/-/micromark-util-normalize-identifier-2.0.1.tgz",
      "integrity": "sha512-sxPqmo70LyARJs0w2UclACPUUEqltCkJ6PhKdMIDuJ3gSf/Q+/GIe3WKl0Ijb/GyH9lOpUkRAO2wp0GVkLvS9Q==",
      "funding": [
        {
          "type": "GitHub Sponsors",
          "url": "https://github.com/sponsors/unifiedjs"
        },
        {
          "type": "OpenCollective",
          "url": "https://opencollective.com/unified"
        }
      ],
      "license": "MIT",
      "dependencies": {
        "micromark-util-symbol": "^2.0.0"
      }
    },
    "node_modules/micromark-util-resolve-all": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/micromark-util-resolve-all/-/micromark-util-resolve-all-2.0.1.tgz",
      "integrity": "sha512-VdQyxFWFT2/FGJgwQnJYbe1jjQoNTS4RjglmSjTUlpUMa95Htx9NHeYW4rGDJzbjvCsl9eLjMQwGeElsqmzcHg==",
      "funding": [
        {
          "type": "GitHub Sponsors",
          "url": "https://github.com/sponsors/unifiedjs"
        },
        {
          "type": "OpenCollective",
          "url": "https://opencollective.com/unified"
        }
      ],
      "license": "MIT",
      "dependencies": {
        "micromark-util-types": "^2.0.0"
      }
    },
    "node_modules/micromark-util-sanitize-uri": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/micromark-util-sanitize-uri/-/micromark-util-sanitize-uri-2.0.1.tgz",
      "integrity": "sha512-9N9IomZ/YuGGZZmQec1MbgxtlgougxTodVwDzzEouPKo3qFWvymFHWcnDi2vzV1ff6kas9ucW+o3yzJK9YB1AQ==",
      "funding": [
        {
          "type": "GitHub Sponsors",
          "url": "https://github.com/sponsors/unifiedjs"
        },
        {
          "type": "OpenCollective",
          "url": "https://opencollective.com/unified"
        }
      ],
      "license": "MIT",
      "dependencies": {
        "micromark-util-character": "^2.0.0",
        "micromark-util-encode": "^2.0.0",
        "micromark-util-symbol": "^2.0.0"
      }
    },
    "node_modules/micromark-util-subtokenize": {
      "version": "2.1.0",
      "resolved": "https://registry.npmjs.org/micromark-util-subtokenize/-/micromark-util-subtokenize-2.1.0.tgz",
      "integrity": "sha512-XQLu552iSctvnEcgXw6+Sx75GflAPNED1qx7eBJ+wydBb2KCbRZe+NwvIEEMM83uml1+2WSXpBAcp9IUCgCYWA==",
      "funding": [
        {
          "type": "GitHub Sponsors",
          "url": "https://github.com/sponsors/unifiedjs"
        },
        {
          "type": "OpenCollective",
          "url": "https://opencollective.com/unified"
        }
      ],
      "license": "MIT",
      "dependencies": {
        "devlop": "^1.0.0",
        "micromark-util-chunked": "^2.0.0",
        "micromark-util-symbol": "^2.0.0",
        "micromark-util-types": "^2.0.0"
      }
    },
    "node_modules/micromark-util-symbol": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/micromark-util-symbol/-/micromark-util-symbol-2.0.1.tgz",
      "integrity": "sha512-vs5t8Apaud9N28kgCrRUdEed4UJ+wWNvicHLPxCa9ENlYuAY31M0ETy5y1vA33YoNPDFTghEbnh6efaE8h4x0Q==",
      "funding": [
        {
          "type": "GitHub Sponsors",
          "url": "https://github.com/sponsors/unifiedjs"
        },
        {
          "type": "OpenCollective",
          "url": "https://opencollective.com/unified"
        }
      ],
      "license": "MIT"
    },
    "node_modules/micromark-util-types": {
      "version": "2.0.2",
      "resolved": "https://registry.npmjs.org/micromark-util-types/-/micromark-util-types-2.0.2.tgz",
      "integrity": "sha512-Yw0ECSpJoViF1qTU4DC6NwtC4aWGt1EkzaQB8KPPyCRR8z9TWeV0HbEFGTO+ZY1wB22zmxnJqhPyTpOVCpeHTA==",
      "funding": [
        {
          "type": "GitHub Sponsors",
          "url": "https://github.com/sponsors/unifiedjs"
        },
        {
          "type": "OpenCollective",
          "url": "https://opencollective.com/unified"
        }
      ],
      "license": "MIT"
    },
    "node_modules/micromatch": {
      "version": "4.0.8",
      "resolved": "https://registry.npmjs.org/micromatch/-/micromatch-4.0.8.tgz",
      "integrity": "sha512-PXwfBhYu0hBCPw8Dn0E+WDYb7af3dSLVWKi3HGv84IdF4TyFoC0ysxFd0Goxw7nSv4T/PzEJQxsYsEiFCKo2BA==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "braces": "^3.0.3",
        "picomatch": "^2.3.1"
      },
      "engines": {
        "node": ">=8.6"
      }
    },
    "node_modules/micromatch/node_modules/picomatch": {
      "version": "2.3.1",
      "resolved": "https://registry.npmjs.org/picomatch/-/picomatch-2.3.1.tgz",
      "integrity": "sha512-JU3teHTNjmE2VCGFzuY8EXzCDVwEqB2a8fsIvwaStHhAWJEeVd1o1QD80CU6+ZdEXXSLbSsuLwJjkCBWqRQUVA==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=8.6"
      },
      "funding": {
        "url": "https://github.com/sponsors/jonschlinkert"
      }
    },
    "node_modules/mime-db": {
      "version": "1.52.0",
      "resolved": "https://registry.npmjs.org/mime-db/-/mime-db-1.52.0.tgz",
      "integrity": "sha512-sPU4uV7dYlvtWJxwwxHD0PuihVNiE7TyAbQ5SWxDCB9mUYvOgroQOwYQQOKPJ8CIbE+1ETVlOoK1UC2nU3gYvg==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.6"
      }
    },
    "node_modules/mime-types": {
      "version": "2.1.35",
      "resolved": "https://registry.npmjs.org/mime-types/-/mime-types-2.1.35.tgz",
      "integrity": "sha512-ZDY+bPm5zTTF+YpCrAU9nK0UgICYPT0QtT1NZWFv4s++TNkcgVaT0g6+4R2uI4MjQjzysHB1zxuWL50hzaeXiw==",
      "license": "MIT",
      "dependencies": {
        "mime-db": "1.52.0"
      },
      "engines": {
        "node": ">= 0.6"
      }
    },
    "node_modules/minimatch": {
      "version": "5.1.6",
      "resolved": "https://registry.npmjs.org/minimatch/-/minimatch-5.1.6.tgz",
      "integrity": "sha512-lKwV/1brpG6mBUFHtb7NUmtABCb2WZZmm2wNiOA5hAb8VdCS4B3dtMWyvcoViccwAW/COERjXLt0zP1zXUN26g==",
      "license": "ISC",
      "dependencies": {
        "brace-expansion": "^2.0.1"
      },
      "engines": {
        "node": ">=10"
      }
    },
    "node_modules/mlly": {
      "version": "1.8.0",
      "resolved": "https://registry.npmjs.org/mlly/-/mlly-1.8.0.tgz",
      "integrity": "sha512-l8D9ODSRWLe2KHJSifWGwBqpTZXIXTeo8mlKjY+E2HAakaTeNpqAyBZ8GSqLzHgw4XmHmC8whvpjJNMbFZN7/g==",
      "license": "MIT",
      "dependencies": {
        "acorn": "^8.15.0",
        "pathe": "^2.0.3",
        "pkg-types": "^1.3.1",
        "ufo": "^1.6.1"
      }
    },
    "node_modules/ms": {
      "version": "2.1.3",
      "resolved": "https://registry.npmjs.org/ms/-/ms-2.1.3.tgz",
      "integrity": "sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA==",
      "license": "MIT"
    },
    "node_modules/nanoid": {
      "version": "3.3.11",
      "resolved": "https://registry.npmjs.org/nanoid/-/nanoid-3.3.11.tgz",
      "integrity": "sha512-N8SpfPUnUp1bK+PMYW8qSWdl9U+wwNWI4QKxOYDy9JAro3WMX7p2OeVRF9v+347pnakNevPmiHhNmZ2HbFA76w==",
      "dev": true,
      "funding": [
        {
          "type": "github",
          "url": "https://github.com/sponsors/ai"
        }
      ],
      "license": "MIT",
      "bin": {
        "nanoid": "bin/nanoid.cjs"
      },
      "engines": {
        "node": "^10 || ^12 || ^13.7 || ^14 || >=15.0.1"
      }
    },
    "node_modules/neo-async": {
      "version": "2.6.2",
      "resolved": "https://registry.npmjs.org/neo-async/-/neo-async-2.6.2.tgz",
      "integrity": "sha512-Yd3UES5mWCSqR+qNT93S3UoYUkqAZ9lLg8a7g9rimsWmYGK8cVToA4/sF3RrshdyV3sAGMXVUmpMYOw+dLpOuw==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/node-domexception": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/node-domexception/-/node-domexception-1.0.0.tgz",
      "integrity": "sha512-/jKZoMpw0F8GRwl4/eLROPA3cfcXtLApP0QzLmUT/HuPCZWyB7IY9ZrMeKw2O/nFIqPQB3PVM9aYm0F312AXDQ==",
      "deprecated": "Use your platform's native DOMException instead",
      "funding": [
        {
          "type": "github",
          "url": "https://github.com/sponsors/jimmywarting"
        },
        {
          "type": "github",
          "url": "https://paypal.me/jimmywarting"
        }
      ],
      "license": "MIT",
      "engines": {
        "node": ">=10.5.0"
      }
    },
    "node_modules/node-fetch": {
      "version": "2.7.0",
      "resolved": "https://registry.npmjs.org/node-fetch/-/node-fetch-2.7.0.tgz",
      "integrity": "sha512-c4FRfUm/dbcWZ7U+1Wq0AwCyFL+3nt2bEw05wfxSz+DWpWsitgmSgYmy2dQdWyKC1694ELPqMs/YzUSNozLt8A==",
      "license": "MIT",
      "dependencies": {
        "whatwg-url": "^5.0.0"
      },
      "engines": {
        "node": "4.x || >=6.0.0"
      },
      "peerDependencies": {
        "encoding": "^0.1.0"
      },
      "peerDependenciesMeta": {
        "encoding": {
          "optional": true
        }
      }
    },
    "node_modules/node-releases": {
      "version": "2.0.27",
      "resolved": "https://registry.npmjs.org/node-releases/-/node-releases-2.0.27.tgz",
      "integrity": "sha512-nmh3lCkYZ3grZvqcCH+fjmQ7X+H0OeZgP40OierEaAptX4XofMh5kwNbWh7lBduUzCcV/8kZ+NDLCwm2iorIlA==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/normalize-path": {
      "version": "3.0.0",
      "resolved": "https://registry.npmjs.org/normalize-path/-/normalize-path-3.0.0.tgz",
      "integrity": "sha512-6eZs5Ls3WtCisHWp9S2GUy8dqkpGi4BVSz3GaqiE6ezub0512ESztXUwUB6C6IKbQkY2Pnb/mD4WYojCRwcwLA==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=0.10.0"
      }
    },
    "node_modules/openai": {
      "version": "4.104.0",
      "resolved": "https://registry.npmjs.org/openai/-/openai-4.104.0.tgz",
      "integrity": "sha512-p99EFNsA/yX6UhVO93f5kJsDRLAg+CTA2RBqdHK4RtK8u5IJw32Hyb2dTGKbnnFmnuoBv5r7Z2CURI9sGZpSuA==",
      "license": "Apache-2.0",
      "dependencies": {
        "@types/node": "^18.11.18",
        "@types/node-fetch": "^2.6.4",
        "abort-controller": "^3.0.0",
        "agentkeepalive": "^4.2.1",
        "form-data-encoder": "1.7.2",
        "formdata-node": "^4.3.2",
        "node-fetch": "^2.6.7"
      },
      "bin": {
        "openai": "bin/cli"
      },
      "peerDependencies": {
        "ws": "^8.18.0",
        "zod": "^3.23.8"
      },
      "peerDependenciesMeta": {
        "ws": {
          "optional": true
        },
        "zod": {
          "optional": true
        }
      }
    },
    "node_modules/p-limit": {
      "version": "2.3.0",
      "resolved": "https://registry.npmjs.org/p-limit/-/p-limit-2.3.0.tgz",
      "integrity": "sha512-//88mFWSJx8lxCzwdAABTJL2MyWB12+eIY7MDL2SqLmAkeKU9qxRvWuSyTjm3FUmpBEMuFfckAIqEaVGUDxb6w==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "p-try": "^2.0.0"
      },
      "engines": {
        "node": ">=6"
      },
      "funding": {
        "url": "https://github.com/sponsors/sindresorhus"
      }
    },
    "node_modules/p-locate": {
      "version": "4.1.0",
      "resolved": "https://registry.npmjs.org/p-locate/-/p-locate-4.1.0.tgz",
      "integrity": "sha512-R79ZZ/0wAxKGu3oYMlz8jy/kbhsNrS7SKZ7PxEHBgJ5+F2mtFW2fK2cOtBh1cHYkQsbzFV7I+EoRKe6Yt0oK7A==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "p-limit": "^2.2.0"
      },
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/p-try": {
      "version": "2.2.0",
      "resolved": "https://registry.npmjs.org/p-try/-/p-try-2.2.0.tgz",
      "integrity": "sha512-R4nPAVTAU0B9D35/Gk3uJf/7XYbQcyohSKdvAxIRSNghFl4e71hVoGnBNQz9cWaXxO2I10KTC+3jMdvvoKw6dQ==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=6"
      }
    },
    "node_modules/package-manager-detector": {
      "version": "1.6.0",
      "resolved": "https://registry.npmjs.org/package-manager-detector/-/package-manager-detector-1.6.0.tgz",
      "integrity": "sha512-61A5ThoTiDG/C8s8UMZwSorAGwMJ0ERVGj2OjoW5pAalsNOg15+iQiPzrLJ4jhZ1HJzmC2PIHT2oEiH3R5fzNA==",
      "license": "MIT"
    },
    "node_modules/parse-entities": {
      "version": "4.0.2",
      "resolved": "https://registry.npmjs.org/parse-entities/-/parse-entities-4.0.2.tgz",
      "integrity": "sha512-GG2AQYWoLgL877gQIKeRPGO1xF9+eG1ujIb5soS5gPvLQ1y2o8FL90w2QWNdf9I361Mpp7726c+lj3U0qK1uGw==",
      "license": "MIT",
      "dependencies": {
        "@types/unist": "^2.0.0",
        "character-entities-legacy": "^3.0.0",
        "character-reference-invalid": "^2.0.0",
        "decode-named-character-reference": "^1.0.0",
        "is-alphanumerical": "^2.0.0",
        "is-decimal": "^2.0.0",
        "is-hexadecimal": "^2.0.0"
      },
      "funding": {
        "type": "github",
        "url": "https://github.com/sponsors/wooorm"
      }
    },
    "node_modules/parse-entities/node_modules/@types/unist": {
      "version": "2.0.11",
      "resolved": "https://registry.npmjs.org/@types/unist/-/unist-2.0.11.tgz",
      "integrity": "sha512-CmBKiL6NNo/OqgmMn95Fk9Whlp2mtvIv+KNpQKN2F4SjvrEesubTRWGYSg+BnWZOnlCaSTU1sMpsBOzgbYhnsA==",
      "license": "MIT"
    },
    "node_modules/path-browserify": {
      "version": "1.0.1",
      "resolved": "https://registry.npmjs.org/path-browserify/-/path-browserify-1.0.1.tgz",
      "integrity": "sha512-b7uo2UCUOYZcnF/3ID0lulOJi/bafxa1xPe7ZPsammBSpjSWQkjNxlt635YGS2MiR9GjvuXCtz2emr3jbsz98g==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/path-data-parser": {
      "version": "0.1.0",
      "resolved": "https://registry.npmjs.org/path-data-parser/-/path-data-parser-0.1.0.tgz",
      "integrity": "sha512-NOnmBpt5Y2RWbuv0LMzsayp3lVylAHLPUTut412ZA3l+C4uw4ZVkQbjShYCQ8TCpUMdPapr4YjUqLYD6v68j+w==",
      "license": "MIT"
    },
    "node_modules/path-exists": {
      "version": "4.0.0",
      "resolved": "https://registry.npmjs.org/path-exists/-/path-exists-4.0.0.tgz",
      "integrity": "sha512-ak9Qy5Q7jYb2Wwcey5Fpvg2KoAc/ZIhLSLOSBmRmygPsGwkVVt0fZa0qrtMz+m6tJTAHfZQ8FnmB4MG4LWy7/w==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/path-key": {
      "version": "3.1.1",
      "resolved": "https://registry.npmjs.org/path-key/-/path-key-3.1.1.tgz",
      "integrity": "sha512-ojmeN0qd+y0jszEtoY48r0Peq5dwMEkIlCOu6Q5f41lfkswXuKtYrhgoTpLnyIcHm24Uhqx+5Tqm2InSwLhE6Q==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/path-parse": {
      "version": "1.0.7",
      "resolved": "https://registry.npmjs.org/path-parse/-/path-parse-1.0.7.tgz",
      "integrity": "sha512-LDJzPVEEEPR+y48z93A0Ed0yXb8pAByGWo/k5YYdYgpY2/2EsOsksJrq7lOHxryrVOn1ejG6oAp8ahvOIQD8sw==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/path-type": {
      "version": "4.0.0",
      "resolved": "https://registry.npmjs.org/path-type/-/path-type-4.0.0.tgz",
      "integrity": "sha512-gDKb8aZMDeD/tZWs9P6+q0J9Mwkdl6xMV8TjnGP3qJVJ06bdMgkbBlLU8IdfOsIsFz2BW1rNVT3XuNEl8zPAvw==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/pathe": {
      "version": "2.0.3",
      "resolved": "https://registry.npmjs.org/pathe/-/pathe-2.0.3.tgz",
      "integrity": "sha512-WUjGcAqP1gQacoQe+OBJsFA7Ld4DyXuUIjZ5cc75cLHvJ7dtNsTugphxIADwspS+AraAUePCKrSVtPLFj/F88w==",
      "license": "MIT"
    },
    "node_modules/picocolors": {
      "version": "1.1.1",
      "resolved": "https://registry.npmjs.org/picocolors/-/picocolors-1.1.1.tgz",
      "integrity": "sha512-xceH2snhtb5M9liqDsmEw56le376mTZkEX/jEb/RxNFyegNul7eNslCXP9FDj/Lcu0X8KEyMceP2ntpaHrDEVA==",
      "dev": true,
      "license": "ISC"
    },
    "node_modules/pkg-dir": {
      "version": "4.2.0",
      "resolved": "https://registry.npmjs.org/pkg-dir/-/pkg-dir-4.2.0.tgz",
      "integrity": "sha512-HRDzbaKjC+AOWVXxAU/x54COGeIv9eb+6CkDSQoNTt4XyWoIJvuPsXizxu/Fr23EiekbtZwmh1IcIG/l/a10GQ==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "find-up": "^4.0.0"
      },
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/pkg-types": {
      "version": "1.3.1",
      "resolved": "https://registry.npmjs.org/pkg-types/-/pkg-types-1.3.1.tgz",
      "integrity": "sha512-/Jm5M4RvtBFVkKWRu2BLUTNP8/M2a+UwuAX+ae4770q1qVGtfjG+WTCupoZixokjmHiry8uI+dlY8KXYV5HVVQ==",
      "license": "MIT",
      "dependencies": {
        "confbox": "^0.1.8",
        "mlly": "^1.7.4",
        "pathe": "^2.0.1"
      }
    },
    "node_modules/points-on-curve": {
      "version": "0.2.0",
      "resolved": "https://registry.npmjs.org/points-on-curve/-/points-on-curve-0.2.0.tgz",
      "integrity": "sha512-0mYKnYYe9ZcqMCWhUjItv/oHjvgEsfKvnUTg8sAtnHr3GVy7rGkXCb6d5cSyqrWqL4k81b9CPg3urd+T7aop3A==",
      "license": "MIT"
    },
    "node_modules/points-on-path": {
      "version": "0.2.1",
      "resolved": "https://registry.npmjs.org/points-on-path/-/points-on-path-0.2.1.tgz",
      "integrity": "sha512-25ClnWWuw7JbWZcgqY/gJ4FQWadKxGWk+3kR/7kD0tCaDtPPMj7oHu2ToLaVhfpnHrZzYby2w6tUA0eOIuUg8g==",
      "license": "MIT",
      "dependencies": {
        "path-data-parser": "0.1.0",
        "points-on-curve": "0.2.0"
      }
    },
    "node_modules/postcss": {
      "version": "8.5.6",
      "resolved": "https://registry.npmjs.org/postcss/-/postcss-8.5.6.tgz",
      "integrity": "sha512-3Ybi1tAuwAP9s0r1UQ2J4n5Y0G05bJkpUIO0/bI9MhwmD70S5aTWbXGBwxHrelT+XM1k6dM0pk+SwNkpTRN7Pg==",
      "dev": true,
      "funding": [
        {
          "type": "opencollective",
          "url": "https://opencollective.com/postcss/"
        },
        {
          "type": "tidelift",
          "url": "https://tidelift.com/funding/github/npm/postcss"
        },
        {
          "type": "github",
          "url": "https://github.com/sponsors/ai"
        }
      ],
      "license": "MIT",
      "peer": true,
      "dependencies": {
        "nanoid": "^3.3.11",
        "picocolors": "^1.1.1",
        "source-map-js": "^1.2.1"
      },
      "engines": {
        "node": "^10 || ^12 || >=14"
      }
    },
    "node_modules/postcss-modules-extract-imports": {
      "version": "3.1.0",
      "resolved": "https://registry.npmjs.org/postcss-modules-extract-imports/-/postcss-modules-extract-imports-3.1.0.tgz",
      "integrity": "sha512-k3kNe0aNFQDAZGbin48pL2VNidTF0w4/eASDsxlyspobzU3wZQLOGj7L9gfRe0Jo9/4uud09DsjFNH7winGv8Q==",
      "dev": true,
      "license": "ISC",
      "engines": {
        "node": "^10 || ^12 || >= 14"
      },
      "peerDependencies": {
        "postcss": "^8.1.0"
      }
    },
    "node_modules/postcss-modules-local-by-default": {
      "version": "4.2.0",
      "resolved": "https://registry.npmjs.org/postcss-modules-local-by-default/-/postcss-modules-local-by-default-4.2.0.tgz",
      "integrity": "sha512-5kcJm/zk+GJDSfw+V/42fJ5fhjL5YbFDl8nVdXkJPLLW+Vf9mTD5Xe0wqIaDnLuL2U6cDNpTr+UQ+v2HWIBhzw==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "icss-utils": "^5.0.0",
        "postcss-selector-parser": "^7.0.0",
        "postcss-value-parser": "^4.1.0"
      },
      "engines": {
        "node": "^10 || ^12 || >= 14"
      },
      "peerDependencies": {
        "postcss": "^8.1.0"
      }
    },
    "node_modules/postcss-modules-scope": {
      "version": "3.2.1",
      "resolved": "https://registry.npmjs.org/postcss-modules-scope/-/postcss-modules-scope-3.2.1.tgz",
      "integrity": "sha512-m9jZstCVaqGjTAuny8MdgE88scJnCiQSlSrOWcTQgM2t32UBe+MUmFSO5t7VMSfAf/FJKImAxBav8ooCHJXCJA==",
      "dev": true,
      "license": "ISC",
      "dependencies": {
        "postcss-selector-parser": "^7.0.0"
      },
      "engines": {
        "node": "^10 || ^12 || >= 14"
      },
      "peerDependencies": {
        "postcss": "^8.1.0"
      }
    },
    "node_modules/postcss-modules-values": {
      "version": "4.0.0",
      "resolved": "https://registry.npmjs.org/postcss-modules-values/-/postcss-modules-values-4.0.0.tgz",
      "integrity": "sha512-RDxHkAiEGI78gS2ofyvCsu7iycRv7oqw5xMWn9iMoR0N/7mf9D50ecQqUo5BZ9Zh2vH4bCUR/ktCqbB9m8vJjQ==",
      "dev": true,
      "license": "ISC",
      "dependencies": {
        "icss-utils": "^5.0.0"
      },
      "engines": {
        "node": "^10 || ^12 || >= 14"
      },
      "peerDependencies": {
        "postcss": "^8.1.0"
      }
    },
    "node_modules/postcss-selector-parser": {
      "version": "7.1.1",
      "resolved": "https://registry.npmjs.org/postcss-selector-parser/-/postcss-selector-parser-7.1.1.tgz",
      "integrity": "sha512-orRsuYpJVw8LdAwqqLykBj9ecS5/cRHlI5+nvTo8LcCKmzDmqVORXtOIYEEQuL9D4BxtA1lm5isAqzQZCoQ6Eg==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "cssesc": "^3.0.0",
        "util-deprecate": "^1.0.2"
      },
      "engines": {
        "node": ">=4"
      }
    },
    "node_modules/postcss-value-parser": {
      "version": "4.2.0",
      "resolved": "https://registry.npmjs.org/postcss-value-parser/-/postcss-value-parser-4.2.0.tgz",
      "integrity": "sha512-1NNCs6uurfkVbeXG4S8JFT9t19m45ICnif8zWLd5oPSZ50QnwMfK+H3jv408d4jw/7Bttv5axS5IiHoLaVNHeQ==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/process": {
      "version": "0.11.10",
      "resolved": "https://registry.npmjs.org/process/-/process-0.11.10.tgz",
      "integrity": "sha512-cdGef/drWFoydD1JsMzuFf8100nZl+GT+yacc2bEced5f9Rjk4z+WtFUTBu9PhOi9j/jfmBPu0mMEY4wIdAF8A==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">= 0.6.0"
      }
    },
    "node_modules/property-information": {
      "version": "7.1.0",
      "resolved": "https://registry.npmjs.org/property-information/-/property-information-7.1.0.tgz",
      "integrity": "sha512-TwEZ+X+yCJmYfL7TPUOcvBZ4QfoT5YenQiJuX//0th53DE6w0xxLEtfK3iyryQFddXuvkIk51EEgrJQ0WJkOmQ==",
      "license": "MIT",
      "funding": {
        "type": "github",
        "url": "https://github.com/sponsors/wooorm"
      }
    },
    "node_modules/queue-microtask": {
      "version": "1.2.3",
      "resolved": "https://registry.npmjs.org/queue-microtask/-/queue-microtask-1.2.3.tgz",
      "integrity": "sha512-NuaNSa6flKT5JaSYQzJok04JzTL1CA6aGhv5rfLW3PgqA+M2ChpZQnAC8h8i4ZFkBS8X5RqkDBHA7r4hej3K9A==",
      "dev": true,
      "funding": [
        {
          "type": "github",
          "url": "https://github.com/sponsors/feross"
        },
        {
          "type": "patreon",
          "url": "https://www.patreon.com/feross"
        },
        {
          "type": "consulting",
          "url": "https://feross.org/support"
        }
      ],
      "license": "MIT"
    },
    "node_modules/randombytes": {
      "version": "2.1.0",
      "resolved": "https://registry.npmjs.org/randombytes/-/randombytes-2.1.0.tgz",
      "integrity": "sha512-vYl3iOX+4CKUWuxGi9Ukhie6fsqXqS9FE2Zaic4tNFD2N2QQaXOMFbuKK4QmDHC0JO6B1Zp41J0LpT0oR68amQ==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "safe-buffer": "^5.1.0"
      }
    },
    "node_modules/react": {
      "version": "18.3.1",
      "resolved": "https://registry.npmjs.org/react/-/react-18.3.1.tgz",
      "integrity": "sha512-wS+hAgJShR0KhEvPJArfuPVN1+Hz1t0Y6n5jLrGQbkb4urgPE/0Rve+1kMB1v/oWgHgm4WIcV+i7F2pTVj+2iQ==",
      "license": "MIT",
      "peer": true,
      "dependencies": {
        "loose-envify": "^1.1.0"
      },
      "engines": {
        "node": ">=0.10.0"
      }
    },
    "node_modules/react-dom": {
      "version": "18.3.1",
      "resolved": "https://registry.npmjs.org/react-dom/-/react-dom-18.3.1.tgz",
      "integrity": "sha512-5m4nQKp+rZRb09LNH59GM4BxTh9251/ylbKIbpe7TpGxfJ+9kv6BLkLBXIjjspbgbnIBNqlI23tRnTWT0snUIw==",
      "license": "MIT",
      "dependencies": {
        "loose-envify": "^1.1.0",
        "scheduler": "^0.23.2"
      },
      "peerDependencies": {
        "react": "^18.3.1"
      }
    },
    "node_modules/react-markdown": {
      "version": "10.1.0",
      "resolved": "https://registry.npmjs.org/react-markdown/-/react-markdown-10.1.0.tgz",
      "integrity": "sha512-qKxVopLT/TyA6BX3Ue5NwabOsAzm0Q7kAPwq6L+wWDwisYs7R8vZ0nRXqq6rkueboxpkjvLGU9fWifiX/ZZFxQ==",
      "license": "MIT",
      "dependencies": {
        "@types/hast": "^3.0.0",
        "@types/mdast": "^4.0.0",
        "devlop": "^1.0.0",
        "hast-util-to-jsx-runtime": "^2.0.0",
        "html-url-attributes": "^3.0.0",
        "mdast-util-to-hast": "^13.0.0",
        "remark-parse": "^11.0.0",
        "remark-rehype": "^11.0.0",
        "unified": "^11.0.0",
        "unist-util-visit": "^5.0.0",
        "vfile": "^6.0.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/unified"
      },
      "peerDependencies": {
        "@types/react": ">=18",
        "react": ">=18"
      }
    },
    "node_modules/rechoir": {
      "version": "0.8.0",
      "resolved": "https://registry.npmjs.org/rechoir/-/rechoir-0.8.0.tgz",
      "integrity": "sha512-/vxpCXddiX8NGfGO/mTafwjq4aFa/71pvamip0++IQk3zG8cbCj0fifNPrjjF1XMXUne91jL9OoxmdykoEtifQ==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "resolve": "^1.20.0"
      },
      "engines": {
        "node": ">= 10.13.0"
      }
    },
    "node_modules/remark-parse": {
      "version": "11.0.0",
      "resolved": "https://registry.npmjs.org/remark-parse/-/remark-parse-11.0.0.tgz",
      "integrity": "sha512-FCxlKLNGknS5ba/1lmpYijMUzX2esxW5xQqjWxw2eHFfS2MSdaHVINFmhjo+qN1WhZhNimq0dZATN9pH0IDrpA==",
      "license": "MIT",
      "dependencies": {
        "@types/mdast": "^4.0.0",
        "mdast-util-from-markdown": "^2.0.0",
        "micromark-util-types": "^2.0.0",
        "unified": "^11.0.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/unified"
      }
    },
    "node_modules/remark-rehype": {
      "version": "11.1.2",
      "resolved": "https://registry.npmjs.org/remark-rehype/-/remark-rehype-11.1.2.tgz",
      "integrity": "sha512-Dh7l57ianaEoIpzbp0PC9UKAdCSVklD8E5Rpw7ETfbTl3FqcOOgq5q2LVDhgGCkaBv7p24JXikPdvhhmHvKMsw==",
      "license": "MIT",
      "dependencies": {
        "@types/hast": "^3.0.0",
        "@types/mdast": "^4.0.0",
        "mdast-util-to-hast": "^13.0.0",
        "unified": "^11.0.0",
        "vfile": "^6.0.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/unified"
      }
    },
    "node_modules/require-from-string": {
      "version": "2.0.2",
      "resolved": "https://registry.npmjs.org/require-from-string/-/require-from-string-2.0.2.tgz",
      "integrity": "sha512-Xf0nWe6RseziFMu+Ap9biiUbmplq6S9/p+7w7YXP/JBHhrUDDUhwa+vANyubuqfZWTveU//DYVGsDG7RKL/vEw==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=0.10.0"
      }
    },
    "node_modules/resolve": {
      "version": "1.22.11",
      "resolved": "https://registry.npmjs.org/resolve/-/resolve-1.22.11.tgz",
      "integrity": "sha512-RfqAvLnMl313r7c9oclB1HhUEAezcpLjz95wFH4LVuhk9JF/r22qmVP9AMmOU4vMX7Q8pN8jwNg/CSpdFnMjTQ==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "is-core-module": "^2.16.1",
        "path-parse": "^1.0.7",
        "supports-preserve-symlinks-flag": "^1.0.0"
      },
      "bin": {
        "resolve": "bin/resolve"
      },
      "engines": {
        "node": ">= 0.4"
      },
      "funding": {
        "url": "https://github.com/sponsors/ljharb"
      }
    },
    "node_modules/resolve-cwd": {
      "version": "3.0.0",
      "resolved": "https://registry.npmjs.org/resolve-cwd/-/resolve-cwd-3.0.0.tgz",
      "integrity": "sha512-OrZaX2Mb+rJCpH/6CpSqt9xFVpN++x01XnN2ie9g6P5/3xelLAkXWVADpdz1IHD/KFfEXyE6V0U01OQ3UO2rEg==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "resolve-from": "^5.0.0"
      },
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/resolve-from": {
      "version": "5.0.0",
      "resolved": "https://registry.npmjs.org/resolve-from/-/resolve-from-5.0.0.tgz",
      "integrity": "sha512-qYg9KP24dD5qka9J47d0aVky0N+b4fTU89LN9iDnjB5waksiC49rvMB0PrUJQGoTmH50XPiqOvAjDfaijGxYZw==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/reusify": {
      "version": "1.1.0",
      "resolved": "https://registry.npmjs.org/reusify/-/reusify-1.1.0.tgz",
      "integrity": "sha512-g6QUff04oZpHs0eG5p83rFLhHeV00ug/Yf9nZM6fLeUrPguBTkTQOdpAWWspMh55TZfVQDPaN3NQJfbVRAxdIw==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "iojs": ">=1.0.0",
        "node": ">=0.10.0"
      }
    },
    "node_modules/robust-predicates": {
      "version": "3.0.2",
      "resolved": "https://registry.npmjs.org/robust-predicates/-/robust-predicates-3.0.2.tgz",
      "integrity": "sha512-IXgzBWvWQwE6PrDI05OvmXUIruQTcoMDzRsOd5CDvHCVLcLHMTSYvOK5Cm46kWqlV3yAbuSpBZdJ5oP5OUoStg==",
      "license": "Unlicense"
    },
    "node_modules/roughjs": {
      "version": "4.6.6",
      "resolved": "https://registry.npmjs.org/roughjs/-/roughjs-4.6.6.tgz",
      "integrity": "sha512-ZUz/69+SYpFN/g/lUlo2FXcIjRkSu3nDarreVdGGndHEBJ6cXPdKguS8JGxwj5HA5xIbVKSmLgr5b3AWxtRfvQ==",
      "license": "MIT",
      "dependencies": {
        "hachure-fill": "^0.5.2",
        "path-data-parser": "^0.1.0",
        "points-on-curve": "^0.2.0",
        "points-on-path": "^0.2.1"
      }
    },
    "node_modules/run-parallel": {
      "version": "1.2.0",
      "resolved": "https://registry.npmjs.org/run-parallel/-/run-parallel-1.2.0.tgz",
      "integrity": "sha512-5l4VyZR86LZ/lDxZTR6jqL8AFE2S0IFLMP26AbjsLVADxHdhB/c0GUsH+y39UfCi3dzz8OlQuPmnaJOMoDHQBA==",
      "dev": true,
      "funding": [
        {
          "type": "github",
          "url": "https://github.com/sponsors/feross"
        },
        {
          "type": "patreon",
          "url": "https://www.patreon.com/feross"
        },
        {
          "type": "consulting",
          "url": "https://feross.org/support"
        }
      ],
      "license": "MIT",
      "dependencies": {
        "queue-microtask": "^1.2.2"
      }
    },
    "node_modules/rw": {
      "version": "1.3.3",
      "resolved": "https://registry.npmjs.org/rw/-/rw-1.3.3.tgz",
      "integrity": "sha512-PdhdWy89SiZogBLaw42zdeqtRJ//zFd2PgQavcICDUgJT5oW10QCRKbJ6bg4r0/UY2M6BWd5tkxuGFRvCkgfHQ==",
      "license": "BSD-3-Clause"
    },
    "node_modules/safe-buffer": {
      "version": "5.2.1",
      "resolved": "https://registry.npmjs.org/safe-buffer/-/safe-buffer-5.2.1.tgz",
      "integrity": "sha512-rp3So07KcdmmKbGvgaNxQSJr7bGVSVk5S9Eq1F+ppbRo70+YeaDxkw5Dd8NPN+GD6bjnYm2VuPuCXmpuYvmCXQ==",
      "dev": true,
      "funding": [
        {
          "type": "github",
          "url": "https://github.com/sponsors/feross"
        },
        {
          "type": "patreon",
          "url": "https://www.patreon.com/feross"
        },
        {
          "type": "consulting",
          "url": "https://feross.org/support"
        }
      ],
      "license": "MIT"
    },
    "node_modules/safer-buffer": {
      "version": "2.1.2",
      "resolved": "https://registry.npmjs.org/safer-buffer/-/safer-buffer-2.1.2.tgz",
      "integrity": "sha512-YZo3K82SD7Riyi0E1EQPojLz7kpepnSQI9IyPbHHg1XXXevb5dJI7tpyN2ADxGcQbHG7vcyRHk0cbwqcQriUtg==",
      "license": "MIT"
    },
    "node_modules/scheduler": {
      "version": "0.23.2",
      "resolved": "https://registry.npmjs.org/scheduler/-/scheduler-0.23.2.tgz",
      "integrity": "sha512-UOShsPwz7NrMUqhR6t0hWjFduvOzbtv7toDH1/hIrfRNIDBnnBWd0CwJTGvTpngVlmwGCdP9/Zl/tVrDqcuYzQ==",
      "license": "MIT",
      "dependencies": {
        "loose-envify": "^1.1.0"
      }
    },
    "node_modules/schema-utils": {
      "version": "4.3.3",
      "resolved": "https://registry.npmjs.org/schema-utils/-/schema-utils-4.3.3.tgz",
      "integrity": "sha512-eflK8wEtyOE6+hsaRVPxvUKYCpRgzLqDTb8krvAsRIwOGlHoSgYLgBXoubGgLd2fT41/OUYdb48v4k4WWHQurA==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@types/json-schema": "^7.0.9",
        "ajv": "^8.9.0",
        "ajv-formats": "^2.1.1",
        "ajv-keywords": "^5.1.0"
      },
      "engines": {
        "node": ">= 10.13.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/webpack"
      }
    },
    "node_modules/semver": {
      "version": "7.7.3",
      "resolved": "https://registry.npmjs.org/semver/-/semver-7.7.3.tgz",
      "integrity": "sha512-SdsKMrI9TdgjdweUSR9MweHA4EJ8YxHn8DFaDisvhVlUOe4BF1tLD7GAj0lIqWVl+dPb/rExr0Btby5loQm20Q==",
      "license": "ISC",
      "bin": {
        "semver": "bin/semver.js"
      },
      "engines": {
        "node": ">=10"
      }
    },
    "node_modules/serialize-javascript": {
      "version": "6.0.2",
      "resolved": "https://registry.npmjs.org/serialize-javascript/-/serialize-javascript-6.0.2.tgz",
      "integrity": "sha512-Saa1xPByTTq2gdeFZYLLo+RFE35NHZkAbqZeWNd3BpzppeVisAqpDjcp8dyf6uIvEqJRd46jemmyA4iFIeVk8g==",
      "dev": true,
      "license": "BSD-3-Clause",
      "dependencies": {
        "randombytes": "^2.1.0"
      }
    },
    "node_modules/shallow-clone": {
      "version": "3.0.1",
      "resolved": "https://registry.npmjs.org/shallow-clone/-/shallow-clone-3.0.1.tgz",
      "integrity": "sha512-/6KqX+GVUdqPuPPd2LxDDxzX6CAbjJehAAOKlNpqqUpAqPM6HeL8f+o3a+JsyGjn2lv0WY8UsTgUJjU9Ok55NA==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "kind-of": "^6.0.2"
      },
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/shebang-command": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/shebang-command/-/shebang-command-2.0.0.tgz",
      "integrity": "sha512-kHxr2zZpYtdmrN1qDjrrX/Z1rR1kG8Dx+gkpK1G4eXmvXswmcE1hTWBWYUzlraYw1/yZp6YuDY77YtvbN0dmDA==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "shebang-regex": "^3.0.0"
      },
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/shebang-regex": {
      "version": "3.0.0",
      "resolved": "https://registry.npmjs.org/shebang-regex/-/shebang-regex-3.0.0.tgz",
      "integrity": "sha512-7++dFhtcx3353uBaq8DDR4NuxBetBzC7ZQOhmTQInHEd6bSrXdiEyzCvG07Z44UYdLShWUyXt5M/yhz8ekcb1A==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/slash": {
      "version": "4.0.0",
      "resolved": "https://registry.npmjs.org/slash/-/slash-4.0.0.tgz",
      "integrity": "sha512-3dOsAHXXUkQTpOYcoAxLIorMTp4gIQr5IW3iVb7A7lFIp0VHhnynm9izx6TssdrIcVIESAlVjtnO2K8bg+Coew==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=12"
      },
      "funding": {
        "url": "https://github.com/sponsors/sindresorhus"
      }
    },
    "node_modules/source-map": {
      "version": "0.7.6",
      "resolved": "https://registry.npmjs.org/source-map/-/source-map-0.7.6.tgz",
      "integrity": "sha512-i5uvt8C3ikiWeNZSVZNWcfZPItFQOsYTUAOkcUPGd8DqDy1uOUikjt5dG+uRlwyvR108Fb9DOd4GvXfT0N2/uQ==",
      "dev": true,
      "license": "BSD-3-Clause",
      "engines": {
        "node": ">= 12"
      }
    },
    "node_modules/source-map-js": {
      "version": "1.2.1",
      "resolved": "https://registry.npmjs.org/source-map-js/-/source-map-js-1.2.1.tgz",
      "integrity": "sha512-UXWMKhLOwVKb728IUtQPXxfYU+usdybtUrK/8uGE8CQMvrhOpwvzDBwj0QhSL7MQc7vIsISBG8VQ8+IDQxpfQA==",
      "dev": true,
      "license": "BSD-3-Clause",
      "engines": {
        "node": ">=0.10.0"
      }
    },
    "node_modules/source-map-support": {
      "version": "0.5.21",
      "resolved": "https://registry.npmjs.org/source-map-support/-/source-map-support-0.5.21.tgz",
      "integrity": "sha512-uBHU3L3czsIyYXKX88fdrGovxdSCoTGDRZ6SYXtSRxLZUzHg5P/66Ht6uoUlHu9EZod+inXhKo3qQgwXUT/y1w==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "buffer-from": "^1.0.0",
        "source-map": "^0.6.0"
      }
    },
    "node_modules/source-map-support/node_modules/source-map": {
      "version": "0.6.1",
      "resolved": "https://registry.npmjs.org/source-map/-/source-map-0.6.1.tgz",
      "integrity": "sha512-UjgapumWlbMhkBgzT7Ykc5YXUT46F0iKu8SGXq0bcwP5dz/h0Plj6enJqjz1Zbq2l5WaqYnrVbwWOWMyF3F47g==",
      "dev": true,
      "license": "BSD-3-Clause",
      "engines": {
        "node": ">=0.10.0"
      }
    },
    "node_modules/space-separated-tokens": {
      "version": "2.0.2",
      "resolved": "https://registry.npmjs.org/space-separated-tokens/-/space-separated-tokens-2.0.2.tgz",
      "integrity": "sha512-PEGlAwrG8yXGXRjW32fGbg66JAlOAwbObuqVoJpv/mRgoWDQfgH1wDPvtzWyUSNAXBGSk8h755YDbbcEy3SH2Q==",
      "license": "MIT",
      "funding": {
        "type": "github",
        "url": "https://github.com/sponsors/wooorm"
      }
    },
    "node_modules/stringify-entities": {
      "version": "4.0.4",
      "resolved": "https://registry.npmjs.org/stringify-entities/-/stringify-entities-4.0.4.tgz",
      "integrity": "sha512-IwfBptatlO+QCJUo19AqvrPNqlVMpW9YEL2LIVY+Rpv2qsjCGxaDLNRgeGsQWJhfItebuJhsGSLjaBbNSQ+ieg==",
      "license": "MIT",
      "dependencies": {
        "character-entities-html4": "^2.0.0",
        "character-entities-legacy": "^3.0.0"
      },
      "funding": {
        "type": "github",
        "url": "https://github.com/sponsors/wooorm"
      }
    },
    "node_modules/style-loader": {
      "version": "3.3.4",
      "resolved": "https://registry.npmjs.org/style-loader/-/style-loader-3.3.4.tgz",
      "integrity": "sha512-0WqXzrsMTyb8yjZJHDqwmnwRJvhALK9LfRtRc6B4UTWe8AijYLZYZ9thuJTZc2VfQWINADW/j+LiJnfy2RoC1w==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">= 12.13.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/webpack"
      },
      "peerDependencies": {
        "webpack": "^5.0.0"
      }
    },
    "node_modules/style-to-js": {
      "version": "1.1.21",
      "resolved": "https://registry.npmjs.org/style-to-js/-/style-to-js-1.1.21.tgz",
      "integrity": "sha512-RjQetxJrrUJLQPHbLku6U/ocGtzyjbJMP9lCNK7Ag0CNh690nSH8woqWH9u16nMjYBAok+i7JO1NP2pOy8IsPQ==",
      "license": "MIT",
      "dependencies": {
        "style-to-object": "1.0.14"
      }
    },
    "node_modules/style-to-object": {
      "version": "1.0.14",
      "resolved": "https://registry.npmjs.org/style-to-object/-/style-to-object-1.0.14.tgz",
      "integrity": "sha512-LIN7rULI0jBscWQYaSswptyderlarFkjQ+t79nzty8tcIAceVomEVlLzH5VP4Cmsv6MtKhs7qaAiwlcp+Mgaxw==",
      "license": "MIT",
      "dependencies": {
        "inline-style-parser": "0.2.7"
      }
    },
    "node_modules/stylis": {
      "version": "4.3.6",
      "resolved": "https://registry.npmjs.org/stylis/-/stylis-4.3.6.tgz",
      "integrity": "sha512-yQ3rwFWRfwNUY7H5vpU0wfdkNSnvnJinhF9830Swlaxl03zsOjCfmX0ugac+3LtK0lYSgwL/KXc8oYL3mG4YFQ==",
      "license": "MIT"
    },
    "node_modules/supports-color": {
      "version": "7.2.0",
      "resolved": "https://registry.npmjs.org/supports-color/-/supports-color-7.2.0.tgz",
      "integrity": "sha512-qpCAvRl9stuOHveKsn7HncJRvv501qIacKzQlO/+Lwxc9+0q2wLyv4Dfvt80/DPn2pqOBsJdDiogXGR9+OvwRw==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "has-flag": "^4.0.0"
      },
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/supports-preserve-symlinks-flag": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/supports-preserve-symlinks-flag/-/supports-preserve-symlinks-flag-1.0.0.tgz",
      "integrity": "sha512-ot0WnXS9fgdkgIcePe6RHNk1WA8+muPa6cSjeR3V8K27q9BB1rTE3R1p7Hv0z1ZyAc8s6Vvv8DIyWf681MAt0w==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">= 0.4"
      },
      "funding": {
        "url": "https://github.com/sponsors/ljharb"
      }
    },
    "node_modules/tailwind-merge": {
      "version": "3.4.0",
      "resolved": "https://registry.npmjs.org/tailwind-merge/-/tailwind-merge-3.4.0.tgz",
      "integrity": "sha512-uSaO4gnW+b3Y2aWoWfFpX62vn2sR3skfhbjsEnaBI81WD1wBLlHZe5sWf0AqjksNdYTbGBEd0UasQMT3SNV15g==",
      "license": "MIT",
      "funding": {
        "type": "github",
        "url": "https://github.com/sponsors/dcastil"
      }
    },
    "node_modules/tapable": {
      "version": "2.3.0",
      "resolved": "https://registry.npmjs.org/tapable/-/tapable-2.3.0.tgz",
      "integrity": "sha512-g9ljZiwki/LfxmQADO3dEY1CbpmXT5Hm2fJ+QaGKwSXUylMybePR7/67YW7jOrrvjEgL1Fmz5kzyAjWVWLlucg==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=6"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/webpack"
      }
    },
    "node_modules/terser": {
      "version": "5.44.1",
      "resolved": "https://registry.npmjs.org/terser/-/terser-5.44.1.tgz",
      "integrity": "sha512-t/R3R/n0MSwnnazuPpPNVO60LX0SKL45pyl9YlvxIdkH0Of7D5qM2EVe+yASRIlY5pZ73nclYJfNANGWPwFDZw==",
      "dev": true,
      "license": "BSD-2-Clause",
      "dependencies": {
        "@jridgewell/source-map": "^0.3.3",
        "acorn": "^8.15.0",
        "commander": "^2.20.0",
        "source-map-support": "~0.5.20"
      },
      "bin": {
        "terser": "bin/terser"
      },
      "engines": {
        "node": ">=10"
      }
    },
    "node_modules/terser-webpack-plugin": {
      "version": "5.3.14",
      "resolved": "https://registry.npmjs.org/terser-webpack-plugin/-/terser-webpack-plugin-5.3.14.tgz",
      "integrity": "sha512-vkZjpUjb6OMS7dhV+tILUW6BhpDR7P2L/aQSAv+Uwk+m8KATX9EccViHTJR2qDtACKPIYndLGCyl3FMo+r2LMw==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@jridgewell/trace-mapping": "^0.3.25",
        "jest-worker": "^27.4.5",
        "schema-utils": "^4.3.0",
        "serialize-javascript": "^6.0.2",
        "terser": "^5.31.1"
      },
      "engines": {
        "node": ">= 10.13.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/webpack"
      },
      "peerDependencies": {
        "webpack": "^5.1.0"
      },
      "peerDependenciesMeta": {
        "@swc/core": {
          "optional": true
        },
        "esbuild": {
          "optional": true
        },
        "uglify-js": {
          "optional": true
        }
      }
    },
    "node_modules/tinyexec": {
      "version": "1.0.2",
      "resolved": "https://registry.npmjs.org/tinyexec/-/tinyexec-1.0.2.tgz",
      "integrity": "sha512-W/KYk+NFhkmsYpuHq5JykngiOCnxeVL8v8dFnqxSD8qEEdRfXk1SDM6JzNqcERbcGYj9tMrDQBYV9cjgnunFIg==",
      "license": "MIT",
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/to-regex-range": {
      "version": "5.0.1",
      "resolved": "https://registry.npmjs.org/to-regex-range/-/to-regex-range-5.0.1.tgz",
      "integrity": "sha512-65P7iz6X5yEr1cwcgvQxbbIw7Uk3gOy5dIdtZ4rDveLqhrdJP+Li/Hx6tyK0NEb+2GCyneCMJiGqrADCSNk8sQ==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "is-number": "^7.0.0"
      },
      "engines": {
        "node": ">=8.0"
      }
    },
    "node_modules/tr46": {
      "version": "0.0.3",
      "resolved": "https://registry.npmjs.org/tr46/-/tr46-0.0.3.tgz",
      "integrity": "sha512-N3WMsuqV66lT30CrXNbEjx4GEwlow3v6rr4mCcv6prnfwhS01rkgyFdjPNBYd9br7LpXV1+Emh01fHnq2Gdgrw==",
      "license": "MIT"
    },
    "node_modules/tree-sitter-wasms": {
      "version": "0.1.13",
      "resolved": "https://registry.npmjs.org/tree-sitter-wasms/-/tree-sitter-wasms-0.1.13.tgz",
      "integrity": "sha512-wT+cR6DwaIz80/vho3AvSF0N4txuNx/5bcRKoXouOfClpxh/qqrF4URNLQXbbt8MaAxeksZcZd1j8gcGjc+QxQ==",
      "license": "Unlicense",
      "dependencies": {
        "tree-sitter-wasms": "^0.1.11"
      }
    },
    "node_modules/trim-lines": {
      "version": "3.0.1",
      "resolved": "https://registry.npmjs.org/trim-lines/-/trim-lines-3.0.1.tgz",
      "integrity": "sha512-kRj8B+YHZCc9kQYdWfJB2/oUl9rA99qbowYYBtr4ui4mZyAQ2JpvVBd/6U2YloATfqBhBTSMhTpgBHtU0Mf3Rg==",
      "license": "MIT",
      "funding": {
        "type": "github",
        "url": "https://github.com/sponsors/wooorm"
      }
    },
    "node_modules/trough": {
      "version": "2.2.0",
      "resolved": "https://registry.npmjs.org/trough/-/trough-2.2.0.tgz",
      "integrity": "sha512-tmMpK00BjZiUyVyvrBK7knerNgmgvcV/KLVyuma/SC+TQN167GrMRciANTz09+k3zW8L8t60jWO1GpfkZdjTaw==",
      "license": "MIT",
      "funding": {
        "type": "github",
        "url": "https://github.com/sponsors/wooorm"
      }
    },
    "node_modules/ts-dedent": {
      "version": "2.2.0",
      "resolved": "https://registry.npmjs.org/ts-dedent/-/ts-dedent-2.2.0.tgz",
      "integrity": "sha512-q5W7tVM71e2xjHZTlgfTDoPF/SmqKG5hddq9SzR49CH2hayqRKJtQ4mtRlSxKaJlR/+9rEM+mnBHf7I2/BQcpQ==",
      "license": "MIT",
      "engines": {
        "node": ">=6.10"
      }
    },
    "node_modules/ts-loader": {
      "version": "9.5.4",
      "resolved": "https://registry.npmjs.org/ts-loader/-/ts-loader-9.5.4.tgz",
      "integrity": "sha512-nCz0rEwunlTZiy6rXFByQU1kVVpCIgUpc/psFiKVrUwrizdnIbRFu8w7bxhUF0X613DYwT4XzrZHpVyMe758hQ==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "chalk": "^4.1.0",
        "enhanced-resolve": "^5.0.0",
        "micromatch": "^4.0.0",
        "semver": "^7.3.4",
        "source-map": "^0.7.4"
      },
      "engines": {
        "node": ">=12.0.0"
      },
      "peerDependencies": {
        "typescript": "*",
        "webpack": "^5.0.0"
      }
    },
    "node_modules/typescript": {
      "version": "5.9.3",
      "resolved": "https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz",
      "integrity": "sha512-jl1vZzPDinLr9eUt3J/t7V6FgNEw9QjvBPdysz9KfQDD41fQrC2Y4vKQdiaUpFT4bXlb1RHhLpp8wtm6M5TgSw==",
      "dev": true,
      "license": "Apache-2.0",
      "peer": true,
      "bin": {
        "tsc": "bin/tsc",
        "tsserver": "bin/tsserver"
      },
      "engines": {
        "node": ">=14.17"
      }
    },
    "node_modules/ufo": {
      "version": "1.6.1",
      "resolved": "https://registry.npmjs.org/ufo/-/ufo-1.6.1.tgz",
      "integrity": "sha512-9a4/uxlTWJ4+a5i0ooc1rU7C7YOw3wT+UGqdeNNHWnOF9qcMBgLRS+4IYUqbczewFx4mLEig6gawh7X6mFlEkA==",
      "license": "MIT"
    },
    "node_modules/undici-types": {
      "version": "5.26.5",
      "resolved": "https://registry.npmjs.org/undici-types/-/undici-types-5.26.5.tgz",
      "integrity": "sha512-JlCMO+ehdEIKqlFxk6IfVoAUVmgz7cU7zD/h9XZ0qzeosSHmUJVOzSQvvYSYWXkFXC+IfLKSIffhv0sVZup6pA==",
      "license": "MIT"
    },
    "node_modules/unified": {
      "version": "11.0.5",
      "resolved": "https://registry.npmjs.org/unified/-/unified-11.0.5.tgz",
      "integrity": "sha512-xKvGhPWw3k84Qjh8bI3ZeJjqnyadK+GEFtazSfZv/rKeTkTjOJho6mFqh2SM96iIcZokxiOpg78GazTSg8+KHA==",
      "license": "MIT",
      "dependencies": {
        "@types/unist": "^3.0.0",
        "bail": "^2.0.0",
        "devlop": "^1.0.0",
        "extend": "^3.0.0",
        "is-plain-obj": "^4.0.0",
        "trough": "^2.0.0",
        "vfile": "^6.0.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/unified"
      }
    },
    "node_modules/unist-util-is": {
      "version": "6.0.1",
      "resolved": "https://registry.npmjs.org/unist-util-is/-/unist-util-is-6.0.1.tgz",
      "integrity": "sha512-LsiILbtBETkDz8I9p1dQ0uyRUWuaQzd/cuEeS1hoRSyW5E5XGmTzlwY1OrNzzakGowI9Dr/I8HVaw4hTtnxy8g==",
      "license": "MIT",
      "dependencies": {
        "@types/unist": "^3.0.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/unified"
      }
    },
    "node_modules/unist-util-position": {
      "version": "5.0.0",
      "resolved": "https://registry.npmjs.org/unist-util-position/-/unist-util-position-5.0.0.tgz",
      "integrity": "sha512-fucsC7HjXvkB5R3kTCO7kUjRdrS0BJt3M/FPxmHMBOm8JQi2BsHAHFsy27E0EolP8rp0NzXsJ+jNPyDWvOJZPA==",
      "license": "MIT",
      "dependencies": {
        "@types/unist": "^3.0.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/unified"
      }
    },
    "node_modules/unist-util-stringify-position": {
      "version": "4.0.0",
      "resolved": "https://registry.npmjs.org/unist-util-stringify-position/-/unist-util-stringify-position-4.0.0.tgz",
      "integrity": "sha512-0ASV06AAoKCDkS2+xw5RXJywruurpbC4JZSm7nr7MOt1ojAzvyyaO+UxZf18j8FCF6kmzCZKcAgN/yu2gm2XgQ==",
      "license": "MIT",
      "dependencies": {
        "@types/unist": "^3.0.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/unified"
      }
    },
    "node_modules/unist-util-visit": {
      "version": "5.0.0",
      "resolved": "https://registry.npmjs.org/unist-util-visit/-/unist-util-visit-5.0.0.tgz",
      "integrity": "sha512-MR04uvD+07cwl/yhVuVWAtw+3GOR/knlL55Nd/wAdblk27GCVt3lqpTivy/tkJcZoNPzTwS1Y+KMojlLDhoTzg==",
      "license": "MIT",
      "dependencies": {
        "@types/unist": "^3.0.0",
        "unist-util-is": "^6.0.0",
        "unist-util-visit-parents": "^6.0.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/unified"
      }
    },
    "node_modules/unist-util-visit-parents": {
      "version": "6.0.2",
      "resolved": "https://registry.npmjs.org/unist-util-visit-parents/-/unist-util-visit-parents-6.0.2.tgz",
      "integrity": "sha512-goh1s1TBrqSqukSc8wrjwWhL0hiJxgA8m4kFxGlQ+8FYQ3C/m11FcTs4YYem7V664AhHVvgoQLk890Ssdsr2IQ==",
      "license": "MIT",
      "dependencies": {
        "@types/unist": "^3.0.0",
        "unist-util-is": "^6.0.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/unified"
      }
    },
    "node_modules/update-browserslist-db": {
      "version": "1.1.4",
      "resolved": "https://registry.npmjs.org/update-browserslist-db/-/update-browserslist-db-1.1.4.tgz",
      "integrity": "sha512-q0SPT4xyU84saUX+tomz1WLkxUbuaJnR1xWt17M7fJtEJigJeWUNGUqrauFXsHnqev9y9JTRGwk13tFBuKby4A==",
      "dev": true,
      "funding": [
        {
          "type": "opencollective",
          "url": "https://opencollective.com/browserslist"
        },
        {
          "type": "tidelift",
          "url": "https://tidelift.com/funding/github/npm/browserslist"
        },
        {
          "type": "github",
          "url": "https://github.com/sponsors/ai"
        }
      ],
      "license": "MIT",
      "dependencies": {
        "escalade": "^3.2.0",
        "picocolors": "^1.1.1"
      },
      "bin": {
        "update-browserslist-db": "cli.js"
      },
      "peerDependencies": {
        "browserslist": ">= 4.21.0"
      }
    },
    "node_modules/util-deprecate": {
      "version": "1.0.2",
      "resolved": "https://registry.npmjs.org/util-deprecate/-/util-deprecate-1.0.2.tgz",
      "integrity": "sha512-EPD5q1uXyFxJpCrLnCc1nHnq3gOa6DZBocAIiI2TaSCA7VCJ1UJDMagCzIkXNsUYfD1daK//LTEQ8xiIbrHtcw==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/uuid": {
      "version": "11.1.0",
      "resolved": "https://registry.npmjs.org/uuid/-/uuid-11.1.0.tgz",
      "integrity": "sha512-0/A9rDy9P7cJ+8w1c9WD9V//9Wj15Ce2MPz8Ri6032usz+NfePxx5AcN3bN+r6ZL6jEo066/yNYB3tn4pQEx+A==",
      "funding": [
        "https://github.com/sponsors/broofa",
        "https://github.com/sponsors/ctavan"
      ],
      "license": "MIT",
      "bin": {
        "uuid": "dist/esm/bin/uuid"
      }
    },
    "node_modules/vfile": {
      "version": "6.0.3",
      "resolved": "https://registry.npmjs.org/vfile/-/vfile-6.0.3.tgz",
      "integrity": "sha512-KzIbH/9tXat2u30jf+smMwFCsno4wHVdNmzFyL+T/L3UGqqk6JKfVqOFOZEpZSHADH1k40ab6NUIXZq422ov3Q==",
      "license": "MIT",
      "dependencies": {
        "@types/unist": "^3.0.0",
        "vfile-message": "^4.0.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/unified"
      }
    },
    "node_modules/vfile-message": {
      "version": "4.0.3",
      "resolved": "https://registry.npmjs.org/vfile-message/-/vfile-message-4.0.3.tgz",
      "integrity": "sha512-QTHzsGd1EhbZs4AsQ20JX1rC3cOlt/IWJruk893DfLRr57lcnOeMaWG4K0JrRta4mIJZKth2Au3mM3u03/JWKw==",
      "license": "MIT",
      "dependencies": {
        "@types/unist": "^3.0.0",
        "unist-util-stringify-position": "^4.0.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/unified"
      }
    },
    "node_modules/vscode-jsonrpc": {
      "version": "8.2.0",
      "resolved": "https://registry.npmjs.org/vscode-jsonrpc/-/vscode-jsonrpc-8.2.0.tgz",
      "integrity": "sha512-C+r0eKJUIfiDIfwJhria30+TYWPtuHJXHtI7J0YlOmKAo7ogxP20T0zxB7HZQIFhIyvoBPwWskjxrvAtfjyZfA==",
      "license": "MIT",
      "engines": {
        "node": ">=14.0.0"
      }
    },
    "node_modules/vscode-languageclient": {
      "version": "9.0.1",
      "resolved": "https://registry.npmjs.org/vscode-languageclient/-/vscode-languageclient-9.0.1.tgz",
      "integrity": "sha512-JZiimVdvimEuHh5olxhxkht09m3JzUGwggb5eRUkzzJhZ2KjCN0nh55VfiED9oez9DyF8/fz1g1iBV3h+0Z2EA==",
      "license": "MIT",
      "dependencies": {
        "minimatch": "^5.1.0",
        "semver": "^7.3.7",
        "vscode-languageserver-protocol": "3.17.5"
      },
      "engines": {
        "vscode": "^1.82.0"
      }
    },
    "node_modules/vscode-languageserver": {
      "version": "9.0.1",
      "resolved": "https://registry.npmjs.org/vscode-languageserver/-/vscode-languageserver-9.0.1.tgz",
      "integrity": "sha512-woByF3PDpkHFUreUa7Hos7+pUWdeWMXRd26+ZX2A8cFx6v/JPTtd4/uN0/jB6XQHYaOlHbio03NTHCqrgG5n7g==",
      "license": "MIT",
      "dependencies": {
        "vscode-languageserver-protocol": "3.17.5"
      },
      "bin": {
        "installServerIntoExtension": "bin/installServerIntoExtension"
      }
    },
    "node_modules/vscode-languageserver-protocol": {
      "version": "3.17.5",
      "resolved": "https://registry.npmjs.org/vscode-languageserver-protocol/-/vscode-languageserver-protocol-3.17.5.tgz",
      "integrity": "sha512-mb1bvRJN8SVznADSGWM9u/b07H7Ecg0I3OgXDuLdn307rl/J3A9YD6/eYOssqhecL27hK1IPZAsaqh00i/Jljg==",
      "license": "MIT",
      "dependencies": {
        "vscode-jsonrpc": "8.2.0",
        "vscode-languageserver-types": "3.17.5"
      }
    },
    "node_modules/vscode-languageserver-textdocument": {
      "version": "1.0.12",
      "resolved": "https://registry.npmjs.org/vscode-languageserver-textdocument/-/vscode-languageserver-textdocument-1.0.12.tgz",
      "integrity": "sha512-cxWNPesCnQCcMPeenjKKsOCKQZ/L6Tv19DTRIGuLWe32lyzWhihGVJ/rcckZXJxfdKCFvRLS3fpBIsV/ZGX4zA==",
      "license": "MIT"
    },
    "node_modules/vscode-languageserver-types": {
      "version": "3.17.5",
      "resolved": "https://registry.npmjs.org/vscode-languageserver-types/-/vscode-languageserver-types-3.17.5.tgz",
      "integrity": "sha512-Ld1VelNuX9pdF39h2Hgaeb5hEZM2Z3jUrrMgWQAu82jMtZp7p3vJT3BzToKtZI7NgQssZje5o0zryOrhQvzQAg==",
      "license": "MIT"
    },
    "node_modules/vscode-uri": {
      "version": "3.0.8",
      "resolved": "https://registry.npmjs.org/vscode-uri/-/vscode-uri-3.0.8.tgz",
      "integrity": "sha512-AyFQ0EVmsOZOlAnxoFOGOq1SQDWAB7C6aqMGS23svWAllfOaxbuFvcT8D1i8z3Gyn8fraVeZNNmN6e9bxxXkKw==",
      "license": "MIT"
    },
    "node_modules/watchpack": {
      "version": "2.4.4",
      "resolved": "https://registry.npmjs.org/watchpack/-/watchpack-2.4.4.tgz",
      "integrity": "sha512-c5EGNOiyxxV5qmTtAB7rbiXxi1ooX1pQKMLX/MIabJjRA0SJBQOjKF+KSVfHkr9U1cADPon0mRiVe/riyaiDUA==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "glob-to-regexp": "^0.4.1",
        "graceful-fs": "^4.1.2"
      },
      "engines": {
        "node": ">=10.13.0"
      }
    },
    "node_modules/web-streams-polyfill": {
      "version": "4.0.0-beta.3",
      "resolved": "https://registry.npmjs.org/web-streams-polyfill/-/web-streams-polyfill-4.0.0-beta.3.tgz",
      "integrity": "sha512-QW95TCTaHmsYfHDybGMwO5IJIM93I/6vTRk+daHTWFPhwh+C8Cg7j7XyKrwrj8Ib6vYXe0ocYNrmzY4xAAN6ug==",
      "license": "MIT",
      "engines": {
        "node": ">= 14"
      }
    },
    "node_modules/web-tree-sitter": {
      "version": "0.20.8",
      "resolved": "https://registry.npmjs.org/web-tree-sitter/-/web-tree-sitter-0.20.8.tgz",
      "integrity": "sha512-weOVgZ3aAARgdnb220GqYuh7+rZU0Ka9k9yfKtGAzEYMa6GgiCzW9JjQRJyCJakvibQW+dfjJdihjInKuuCAUQ==",
      "license": "MIT"
    },
    "node_modules/webidl-conversions": {
      "version": "3.0.1",
      "resolved": "https://registry.npmjs.org/webidl-conversions/-/webidl-conversions-3.0.1.tgz",
      "integrity": "sha512-2JAn3z8AR6rjK8Sm8orRC0h/bcl/DqL7tRPdGZ4I1CjdF+EaMLmYxBHyXuKL849eucPFhvBoxMsflfOb8kxaeQ==",
      "license": "BSD-2-Clause"
    },
    "node_modules/webpack": {
      "version": "5.103.0",
      "resolved": "https://registry.npmjs.org/webpack/-/webpack-5.103.0.tgz",
      "integrity": "sha512-HU1JOuV1OavsZ+mfigY0j8d1TgQgbZ6M+J75zDkpEAwYeXjWSqrGJtgnPblJjd/mAyTNQ7ygw0MiKOn6etz8yw==",
      "dev": true,
      "license": "MIT",
      "peer": true,
      "dependencies": {
        "@types/eslint-scope": "^3.7.7",
        "@types/estree": "^1.0.8",
        "@types/json-schema": "^7.0.15",
        "@webassemblyjs/ast": "^1.14.1",
        "@webassemblyjs/wasm-edit": "^1.14.1",
        "@webassemblyjs/wasm-parser": "^1.14.1",
        "acorn": "^8.15.0",
        "acorn-import-phases": "^1.0.3",
        "browserslist": "^4.26.3",
        "chrome-trace-event": "^1.0.2",
        "enhanced-resolve": "^5.17.3",
        "es-module-lexer": "^1.2.1",
        "eslint-scope": "5.1.1",
        "events": "^3.2.0",
        "glob-to-regexp": "^0.4.1",
        "graceful-fs": "^4.2.11",
        "json-parse-even-better-errors": "^2.3.1",
        "loader-runner": "^4.3.1",
        "mime-types": "^2.1.27",
        "neo-async": "^2.6.2",
        "schema-utils": "^4.3.3",
        "tapable": "^2.3.0",
        "terser-webpack-plugin": "^5.3.11",
        "watchpack": "^2.4.4",
        "webpack-sources": "^3.3.3"
      },
      "bin": {
        "webpack": "bin/webpack.js"
      },
      "engines": {
        "node": ">=10.13.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/webpack"
      },
      "peerDependenciesMeta": {
        "webpack-cli": {
          "optional": true
        }
      }
    },
    "node_modules/webpack-cli": {
      "version": "5.1.4",
      "resolved": "https://registry.npmjs.org/webpack-cli/-/webpack-cli-5.1.4.tgz",
      "integrity": "sha512-pIDJHIEI9LR0yxHXQ+Qh95k2EvXpWzZ5l+d+jIo+RdSm9MiHfzazIxwwni/p7+x4eJZuvG1AJwgC4TNQ7NRgsg==",
      "dev": true,
      "license": "MIT",
      "peer": true,
      "dependencies": {
        "@discoveryjs/json-ext": "^0.5.0",
        "@webpack-cli/configtest": "^2.1.1",
        "@webpack-cli/info": "^2.0.2",
        "@webpack-cli/serve": "^2.0.5",
        "colorette": "^2.0.14",
        "commander": "^10.0.1",
        "cross-spawn": "^7.0.3",
        "envinfo": "^7.7.3",
        "fastest-levenshtein": "^1.0.12",
        "import-local": "^3.0.2",
        "interpret": "^3.1.1",
        "rechoir": "^0.8.0",
        "webpack-merge": "^5.7.3"
      },
      "bin": {
        "webpack-cli": "bin/cli.js"
      },
      "engines": {
        "node": ">=14.15.0"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/webpack"
      },
      "peerDependencies": {
        "webpack": "5.x.x"
      },
      "peerDependenciesMeta": {
        "@webpack-cli/generators": {
          "optional": true
        },
        "webpack-bundle-analyzer": {
          "optional": true
        },
        "webpack-dev-server": {
          "optional": true
        }
      }
    },
    "node_modules/webpack-cli/node_modules/commander": {
      "version": "10.0.1",
      "resolved": "https://registry.npmjs.org/commander/-/commander-10.0.1.tgz",
      "integrity": "sha512-y4Mg2tXshplEbSGzx7amzPwKKOCGuoSRP/CjEdwwk0FOGlUbq6lKuoyDZTNZkmxHdJtp54hdfY/JUrdL7Xfdug==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=14"
      }
    },
    "node_modules/webpack-merge": {
      "version": "5.10.0",
      "resolved": "https://registry.npmjs.org/webpack-merge/-/webpack-merge-5.10.0.tgz",
      "integrity": "sha512-+4zXKdx7UnO+1jaN4l2lHVD+mFvnlZQP/6ljaJVb4SZiwIKeUnrT5l0gkT8z+n4hKpC+jpOv6O9R+gLtag7pSA==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "clone-deep": "^4.0.1",
        "flat": "^5.0.2",
        "wildcard": "^2.0.0"
      },
      "engines": {
        "node": ">=10.0.0"
      }
    },
    "node_modules/webpack-sources": {
      "version": "3.3.3",
      "resolved": "https://registry.npmjs.org/webpack-sources/-/webpack-sources-3.3.3.tgz",
      "integrity": "sha512-yd1RBzSGanHkitROoPFd6qsrxt+oFhg/129YzheDGqeustzX0vTZJZsSsQjVQC4yzBQ56K55XU8gaNCtIzOnTg==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=10.13.0"
      }
    },
    "node_modules/whatwg-url": {
      "version": "5.0.0",
      "resolved": "https://registry.npmjs.org/whatwg-url/-/whatwg-url-5.0.0.tgz",
      "integrity": "sha512-saE57nupxk6v3HY35+jzBwYa0rKSy0XR8JSxZPwgLr7ys0IBzhGviA1/TUGJLmSVqs8pb9AnvICXEuOHLprYTw==",
      "license": "MIT",
      "dependencies": {
        "tr46": "~0.0.3",
        "webidl-conversions": "^3.0.0"
      }
    },
    "node_modules/which": {
      "version": "2.0.2",
      "resolved": "https://registry.npmjs.org/which/-/which-2.0.2.tgz",
      "integrity": "sha512-BLI3Tl1TW3Pvl70l3yq3Y64i+awpwXqsGBYWkkqMtnbXgrMD+yj7rhW0kuEDxzJaYXGjEW5ogapKNMEKNMjibA==",
      "dev": true,
      "license": "ISC",
      "dependencies": {
        "isexe": "^2.0.0"
      },
      "bin": {
        "node-which": "bin/node-which"
      },
      "engines": {
        "node": ">= 8"
      }
    },
    "node_modules/wildcard": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/wildcard/-/wildcard-2.0.1.tgz",
      "integrity": "sha512-CC1bOL87PIWSBhDcTrdeLo6eGT7mCFtrg0uIJtqJUFyK+eJnzl8A1niH56uu7KMa5XFrtiV+AQuHO3n7DsHnLQ==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/zod": {
      "version": "3.25.76",
      "resolved": "https://registry.npmjs.org/zod/-/zod-3.25.76.tgz",
      "integrity": "sha512-gzUt/qt81nXsFGKIFcC3YnfEAx5NkunCfnDlvuBSSFS02bcXu4Lmea0AFIUwbLWxWPx3d9p8S5QoaujKcNQxcQ==",
      "license": "MIT",
      "peer": true,
      "funding": {
        "url": "https://github.com/sponsors/colinhacks"
      }
    },
    "node_modules/zwitch": {
      "version": "2.0.4",
      "resolved": "https://registry.npmjs.org/zwitch/-/zwitch-2.0.4.tgz",
      "integrity": "sha512-bXE4cR/kVZhKZX/RjPEflHaKVhUVl85noU3v6b8apfQEc1x4A+zBxjZ4lN8LqGd6WZ3dl98pY4o717VFmoPp+A==",
      "license": "MIT",
      "funding": {
        "type": "github",
        "url": "https://github.com/sponsors/wooorm"
      }
    }
  }
}

#tsconfig.json
{
  "compilerOptions": {
    "module": "commonjs",
    "target": "ES2020",
    "outDir": "dist",
    "lib": ["ES2020", "DOM"],
    "sourceMap": true,
    "rootDir": "src",
    "strict": true,
    "jsx": "react",
    "esModuleInterop": true
  },
  "exclude": ["node_modules"]
}
#webpack.config.js
const path = require('path');
const webpack = require('webpack');

const extensionConfig = {
  target: 'node',
  mode: 'none',
  entry: './src/extension.ts',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'extension.js',
    libraryTarget: 'commonjs',
  },
  externals: {
    'vscode': 'commonjs vscode',
  },
  resolve: { extensions: ['.ts', '.js'] },
  module: {
    rules: [{ test: /\.ts$/, exclude: /node_modules/, use: 'ts-loader' }]
  },
  node: { __dirname: false }
};

const webviewConfig = {
  target: 'web',
  mode: 'none', // Set to 'production' if you want minification
  entry: './src/webview/index.tsx',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'webview.js',
  },
  resolve: { 
    extensions: ['.ts', '.tsx', '.js', '.jsx'],
    fallback: {
        "process": require.resolve("process/browser"),
        "path": require.resolve("path-browserify")
    },
    alias: {
        'process/browser': require.resolve('process/browser')
    }
  },
  module: {
    rules: [
      { test: /\.tsx?$/, exclude: /node_modules/, use: 'ts-loader' },
      { test: /\.css$/, use: ['style-loader', 'css-loader'] }
    ]
  },
  plugins: [
    new webpack.ProvidePlugin({
      process: 'process/browser',
    }),
    // CRITICAL FIX: Forces everything into ONE file (webview.js).
    // Eliminates "Loading chunk failed" errors in VS Code.
    new webpack.optimize.LimitChunkCountPlugin({
      maxChunks: 1,
    }),
  ]
};

module.exports = [extensionConfig, webviewConfig];
