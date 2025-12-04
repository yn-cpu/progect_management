import React, { useState, useEffect, useRef } from 'react';
import { vscode } from './vscode';
// UPDATE: Added ChevronLeft, ChevronRight to imports
import { ArrowLeft, Search, FileCode, FileText, Save, Folder, RefreshCw, ChevronUp, ChevronDown, ChevronLeft, ChevronRight, Terminal, Bug, Play, GitCommit, Layout, Loader2, MousePointerClick, Zap, Settings, X } from 'lucide-react';
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
    llmConfig: LLMConfig; 
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
const AIConfigSection = ({ currentConfig }: { currentConfig: LLMConfig }) => {
    const [isExpanded, setIsExpanded] = useState(false);
    const [baseUrl, setBaseUrl] = useState(currentConfig.baseUrl);
    const [apiKey, setApiKey] = useState(currentConfig.apiKey);
    const [model, setModel] = useState(currentConfig.model);
    const [saved, setSaved] = useState(false);

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
            <AIConfigSection currentConfig={llmConfig} />

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
        <div className="text-center text-[10px] text-gray-600 font-mono mt-8">v0.4.7 // PAGINATION ADDED</div>
    </div>
);

// --- SCAN RESULTS VIEW (UPDATED WITH PAGINATION) ---
const ScanResultsView = ({ findings, progress, statusMsg, onBack, onNewScan, onFlow }: any) => {
    // 1. Pagination State
    const [page, setPage] = useState(1);
    const ITEMS_PER_PAGE = 5;

    // 2. Reset page logic
    useEffect(() => {
        if (findings.length === 0) setPage(1);
    }, [findings.length]);

    // 3. Slicing Logic
    const totalPages = Math.ceil(findings.length / ITEMS_PER_PAGE);
    // Safety check to ensure page is valid if findings array shrinks
    const safePage = Math.min(Math.max(1, page), Math.max(1, totalPages));
    const displayedFindings = findings.slice((safePage - 1) * ITEMS_PER_PAGE, safePage * ITEMS_PER_PAGE);

    return (
        <div className="flex flex-col h-full">
            {/* Fixed Header */}
            <div className="p-4 border-b border-gray-800 sticky top-0 bg-[#0f111a] z-10 shadow-lg flex-none">
                <div className="flex justify-between items-center mb-4">
                    <div className="flex items-center gap-2">
                        <button onClick={onBack} className="btn-icon"><ArrowLeft size={16}/></button>
                        <h2 className="font-bold uppercase tracking-wider text-sm">Detections <span className="text-primary">[{findings.length}]</span></h2>
                    </div>
                    <button onClick={onNewScan} className="text-xs text-muted hover:text-white flex gap-1 items-center"><Save size={12}/> New</button>
                </div>
                <ProgressBar percent={progress} label={statusMsg} />
            </div>

            {/* Scrollable List Area - flex-1 takes all available space between header and footer */}
            <div className="flex-1 overflow-y-auto custom-scrollbar p-2 space-y-2 scroll-smooth">
                {findings.length === 0 && progress === 100 && <div className="text-center text-muted mt-10">No vulnerabilities detected. System Secure.</div>}
                
                {displayedFindings.map((f: Finding) => (
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
                            {/* CONFIG-ERR Check Included here */}
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

            {/* Pagination Footer - Fixed Height */}
            {totalPages > 1 && (
                <div className="p-3 border-t border-gray-800 bg-[#0f111a] flex justify-between items-center z-10 flex-none">
                    <button 
                        onClick={() => setPage(p => Math.max(1, p - 1))} 
                        disabled={safePage === 1}
                        className="btn-icon disabled:opacity-30 disabled:cursor-not-allowed hover:text-primary hover:border-primary flex items-center gap-1 text-[10px]"
                    >
                        <ChevronLeft size={14} /> Prev
                    </button>
                    <span className="text-[10px] font-mono text-muted">Page <span className="text-white">{safePage}</span> of {totalPages}</span>
                    <button 
                        onClick={() => setPage(p => Math.min(totalPages, p + 1))} 
                        disabled={safePage === totalPages}
                        className="btn-icon disabled:opacity-30 disabled:cursor-not-allowed hover:text-primary hover:border-primary flex items-center gap-1 text-[10px]"
                    >
                        Next <ChevronRight size={14} />
                    </button>
                </div>
            )}
        </div>
    );
};

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
