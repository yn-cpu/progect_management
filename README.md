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

export interface LLMConfig {
    baseUrl: string;
    apiKey: string;
    model: string;
}

export type BackendMessage = 
    | { type: 'scan_progress', value: string, percent?: number } 
    | { type: 'scan_complete', findings: Finding[], shouldSwitchView?: boolean }
    | { type: 'triage_update', findingId: string, status: 'verified' | 'false_positive', reason: string, percent?: number }
    | { type: 'flow_update', graph: FlowGraph, log: string }
    | { type: 'scope_selected', path: string }
    | { type: 'report_generated', report: string }
    | { type: 'interactive_candidates', candidates: FlowCandidate[] }
    | { type: 'config_load', config: LLMConfig }; // NEW: Send config to UI

export type FrontendMessage = 
    | { command: 'selectScope' } 
    | { command: 'saveSession', findings: Finding[], graph: FlowGraph, logs: string[], report: string } 
    | { command: 'startScan', scopePath?: string, focus?: string }
    | { command: 'startFlow', finding: Finding, mode: 'interactive' | 'autonomous' }
    | { command: 'generateReport', finding: Finding }
    | { command: 'openFile', file: string, line: number }
    | { command: 'interactive_selection', selection: FlowCandidate }
    | { command: 'saveLLMConfig', baseUrl: string, apiKey: string, model: string };


£££££££££££££££££££££££££££


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

    // --- NEW: Load Config on Startup ---
    // Wait slightly for UI to be ready
    setTimeout(() => {
        const currentConfig = this.readConfig();
        this.post({ type: 'config_load', config: currentConfig });
    }, 500);

    webviewView.webview.onDidReceiveMessage(async (data: FrontendMessage) => {
      const llm = new LLMProvider();
      
      // --- SAVE CONFIG HANDLER ---
      if (data.command === 'saveLLMConfig') {
          const workspaceFolders = vscode.workspace.workspaceFolders;
          if (!workspaceFolders || workspaceFolders.length === 0) {
              vscode.window.showErrorMessage("VulnTriage: Open a workspace folder to save configuration.");
              return;
          }
          
          const rootPath = workspaceFolders[0].uri.fsPath;
          const configPath = path.join(rootPath, 'vulntriage.config.json');
          
          const configData = {
              baseUrl: data.baseUrl,
              apiKey: data.apiKey,
              model: data.model
          };

          try {
              fs.writeFileSync(configPath, JSON.stringify(configData, null, 2));
              vscode.window.showInformationMessage(`AI Config updated! (Model: ${data.model})`);
              // Send it back to UI to confirm persistence
              this.post({ type: 'config_load', config: configData });
          } catch (e: any) {
              vscode.window.showErrorMessage(`Failed to save config: ${e.message}`);
          }
      }

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
          const scanner = new LLMScanner(llm);
          const triage = new TriageAgent(llm);
          this.post({ type: 'scan_progress', value: 'Resolving scope...', percent: 0 });
          
          let globPattern = '**/*.{c,cpp,py,java}';
          if (data.scopePath && data.scopePath !== 'Workspace') {
              const absPath = path.join(vscode.workspace.workspaceFolders![0].uri.fsPath, data.scopePath);
              if (fs.existsSync(absPath) && fs.lstatSync(absPath).isFile()) {
                  globPattern = data.scopePath; 
              } else {
                  globPattern = `${data.scopePath}/**/*.{c,cpp,py,java}`; 
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
                      security_issue: {
                          ruleId: data.finding.ruleId,
                          severity: data.finding.severity,
                          file: data.finding.file,
                          line: data.finding.line,
                          message: data.finding.message
                      },
                      starting_point: {
                          file: data.finding.file,
                          line: data.finding.line,
                          function: agentData.graph.nodes[0]?.function || "Unknown"
                      },
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

  // Helper to read the config file
  private readConfig() {
      if (!vscode.workspace.workspaceFolders || vscode.workspace.workspaceFolders.length === 0) {
          return { baseUrl: "http://localhost:11434/v1", apiKey: "ollama", model: "llama3:8b" };
      }
      const rootPath = vscode.workspace.workspaceFolders[0].uri.fsPath;
      const configPath = path.join(rootPath, 'vulntriage.config.json');
      if (fs.existsSync(configPath)) {
          try {
              const content = fs.readFileSync(configPath, 'utf-8');
              return JSON.parse(content);
          } catch (e) { return { baseUrl: "http://localhost:11434/v1", apiKey: "ollama", model: "llama3:8b" }; }
      }
      return { baseUrl: "http://localhost:11434/v1", apiKey: "ollama", model: "llama3:8b" };
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

££££££££££££££££££££££££££

import React, { useState, useEffect, useRef } from 'react';
import { vscode } from './vscode';
import { ArrowLeft, Search, FileCode, FileText, Save, Folder, RefreshCw, ChevronUp, ChevronDown, Terminal, Bug, Play, GitCommit, Layout, Loader2, MousePointerClick, Zap, Settings, X } from 'lucide-react';
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

interface LLMConfig {
    baseUrl: string;
    apiKey: string;
    model: string;
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
    llmConfig: LLMConfig; // NEW: Persist config in state
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

// --- AI CONFIGURATION SECTION (IN-LINE) ---
// Now accepts 'currentConfig' prop so it displays the loaded values
const AIConfigSection = ({ currentConfig }: { currentConfig: LLMConfig }) => {
    const [isExpanded, setIsExpanded] = useState(false);
    const [baseUrl, setBaseUrl] = useState(currentConfig.baseUrl);
    const [apiKey, setApiKey] = useState(currentConfig.apiKey);
    const [model, setModel] = useState(currentConfig.model);
    const [saved, setSaved] = useState(false);

    // Sync local state when parent config loads (e.g. from disk)
    useEffect(() => {
        setBaseUrl(currentConfig.baseUrl);
        setApiKey(currentConfig.apiKey);
        setModel(currentConfig.model);
    }, [currentConfig]);

    const handleSave = () => {
        vscode.postMessage({ command: 'saveLLMConfig', baseUrl, apiKey, model });
        setSaved(true);
        setTimeout(() => setSaved(false), 2000);
        setIsExpanded(false); 
    };

    return (
        <div className="bg-panel rounded border border-gray-800 overflow-hidden transition-all duration-300">
            {/* Header / Toggle */}
            <div 
                className="p-4 flex justify-between items-center cursor-pointer hover:bg-[#1f2330]" 
                onClick={() => setIsExpanded(!isExpanded)}
            >
                <div className="flex items-center gap-2">
                    <Settings size={14} className="text-primary"/>
                    <label className="block text-xs font-bold uppercase text-muted cursor-pointer select-none">AI Configuration</label>
                </div>
                {isExpanded ? <ChevronUp size={14} className="text-gray-500"/> : <ChevronDown size={14} className="text-gray-500"/>}
            </div>

            {/* Expandable Form */}
            {isExpanded && (
                <div className="px-4 pb-4 space-y-3 border-t border-gray-800 animate-slide-in">
                    <div>
                        <span className="text-[10px] text-gray-500 mb-1 block">Base URL (must end in /v1)</span>
                        <input className="cyber-input text-xs" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} />
                    </div>
                    <div>
                        <span className="text-[10px] text-gray-500 mb-1 block">API Key</span>
                        <input className="cyber-input text-xs" type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} />
                    </div>
                    <div>
                        <span className="text-[10px] text-gray-500 mb-1 block">Model Name</span>
                        <input className="cyber-input text-xs" value={model} onChange={(e) => setModel(e.target.value)} />
                    </div>
                    <button onClick={handleSave} className="btn-primary w-full py-2 flex justify-center gap-2 text-xs">
                        {saved ? <span className="text-green-400">Saved!</span> : <><Save size={12} /> Update Config</>}
                    </button>
                </div>
            )}
        </div>
    );
};

// --- CANDIDATE SELECTION PANEL ---
const CandidateSelector = ({ candidates, onSelect }: { candidates: FlowCandidate[], onSelect: (c: FlowCandidate) => void }) => (
    <div className="flex-none bg-[#151720] border-t border-primary p-4 shadow-[0_-5px_20px_rgba(0,0,0,0.5)] max-h-[40vh] overflow-y-auto custom-scrollbar animate-slide-in">
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
                </div>
            ))}
        </div>
    </div>
);

// --- HOME VIEW ---
const HomeView = ({ scope, focus, setFocus, onSelectScope, onStart, hasResults, onViewResults, llmConfig }: any) => (
    <div className="flex flex-col h-full p-6 overflow-y-auto custom-scrollbar relative">
        <div className="text-center mb-8 mt-4 animate-pulse">
            <img 
                src={(window as any).vsLogoUrl} 
                alt="VulnTriage Logo" 
                className="app-logo" 
            />
            <h1 className="text-2xl font-bold tracking-widest uppercase">Vuln<span className="text-primary">Triage</span></h1>
            <p className="text-xs text-muted mt-2">Autonomous Vulnerability Research Agent</p>
        </div>
        
        <div className="space-y-4 flex-1">
            {/* 1. AI Config (Passed Config from State) */}
            <AIConfigSection currentConfig={llmConfig} />

            {/* 2. Target Scope */}
            <div className="bg-panel p-4 rounded border border-gray-800">
                <label className="block text-xs font-bold uppercase text-muted mb-2">Target Scope</label>
                <button onClick={onSelectScope} className="w-full flex items-center justify-between cyber-input hover:border-primary text-sm text-left">
                    <span className="truncate">{scope}</span><Folder size={14}/>
                </button>
            </div>

            {/* 3. Vulnerability Focus */}
            <div className="bg-panel p-4 rounded border border-gray-800">
                <label className="block text-xs font-bold uppercase text-muted mb-2">Vulnerability Focus</label>
                <input type="text" value={focus} onChange={(e) => setFocus(e.target.value)} placeholder="e.g. Memory Corruption" className="cyber-input text-sm" />
            </div>

            {/* 4. Actions */}
            <div className="flex flex-col gap-3 mt-4">
                <button onClick={onStart} className="btn-primary w-full flex justify-center gap-2 py-3"><Search size={18}/> Initialize Scan</button>
                {hasResults && <button onClick={onViewResults} className="btn-primary w-full flex justify-center gap-2 py-3 border-dashed opacity-80 hover:opacity-100"><Layout size={18}/> View Active Results</button>}
            </div>
        </div>
        <div className="text-center text-[10px] text-gray-600 font-mono mt-8">v0.4.4 // CONFIG SYNC</div>
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
        <div className="flex-1 overflow-y-auto custom-scrollbar p-2 space-y-2 scroll-smooth">
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
                        {f.status === 'verified' && (
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

// --- FLOW TIMELINE & VIEW ---
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
                            <div className="mt-2 flex items-center gap-1 text-[10px] text-gray-500"><FileCode size={10}/><span className="truncate">{node.file}</span></div>
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
                <div className="flex-1 overflow-y-auto custom-scrollbar p-4">
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
                      <div className="text-[10px] font-mono space-y-1 text-gray-400 flex-1 overflow-y-auto custom-scrollbar p-2">
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
  // Init config state
  const [llmConfig, setLLMConfig] = useState<LLMConfig>(savedState.llmConfig || { baseUrl: "http://localhost:11434/v1", apiKey: "ollama", model: "llama3:8b" });
  
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
      vscode.setState({ mode, findings, logs, progress, statusMsg, scope, focus, reportContent, selectedFinding, graphData, candidates, llmConfig });
  }, [mode, findings, logs, progress, statusMsg, scope, focus, reportContent, selectedFinding, graphData, candidates, llmConfig]);

  useEffect(() => {
    const handler = (event: MessageEvent) => {
      const msg = event.data;
      if (msg.type === 'config_load') {
          // UPDATE CONFIG STATE when message received
          setLLMConfig(msg.config);
      }
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

  const handleStartScan = () => { 
      setLogs(['Initializing Cyber Scan...']); setProgress(0); setStatusMsg("Scanning Target..."); 
      setMode('SCAN'); 
      vscode.postMessage({ command: 'startScan', scopePath: scope, focus: focus }); 
  };
  
  const handleFlow = (finding: Finding, type: 'interactive' | 'autonomous') => { 
      setSelectedFinding(finding); 
      setMode('FLOW'); 
      setGraphData({ nodes: [], edges: [] }); setReportContent(""); setCandidates([]);
      setLogs([`Initiating ${type} trace analysis...`]); 
      setProgress(5); setStatusMsg("Tracing Data Flow..."); 
      vscode.postMessage({ command: 'startFlow', finding, mode: type }); 
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
    <div className="h-screen text-white selection:bg-primary/30 font-sans relative">
        {mode === 'HOME' && (
            <HomeView 
                scope={scope} focus={focus} setFocus={setFocus} onSelectScope={() => vscode.postMessage({command: 'selectScope'})} 
                onStart={handleStartScan} hasResults={findings.length > 0} onViewResults={() => setMode('SCAN')}
                llmConfig={llmConfig} // PASS CONFIG TO CHILD
                onOpenSettings={() => {}} 
            />
        )}
        {mode === 'SCAN' && <ScanResultsView findings={findings} progress={progress} statusMsg={statusMsg} onBack={() => setMode('HOME')} onNewScan={handleSave} onFlow={handleFlow} />}
        {mode === 'FLOW' && <FlowView candidates={candidates} onCandidateSelect={handleCandidateSelect} finding={selectedFinding} progress={progress} statusMsg={statusMsg} graphData={graphData} logs={logs} reportContent={reportContent} onBack={() => setMode('SCAN')} onSave={handleSave} onGenerateReport={handleGenerateReport} bottomRef={bottomRef} />}
    </div>
  );
};

export default App;
