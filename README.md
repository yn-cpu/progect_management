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
        <div className="flex justify-between text-xs text-primary mb-1 font-mono uppercase"><span className="truncate pr-2">> {label}</span><span>{percent}%</span></div>
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
        <div className="text-center text-[10px] text-gray-600 font-mono mt-4">v0.4.3 // ERROR UX</div>
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
                        {/* UPDATE: Hide buttons if ruleId is CONFIG-ERR */}
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
