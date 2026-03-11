<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>DeepTrace — Path Visualizer</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,300;0,400;0,500;0,700;1,400&family=Syne:wght@400;700;800&display=swap');
:root {
  --bg:#07080c; --panel:#0d0f18; --card:#111420; --border:#1c1f2e; --border2:#262a3e;
  --c0:#e8ecf4; --c1:#8b93b0; --c2:#3f4560;
  --accent:#38bdf8; --gold:#f59e0b; --orange:#f97316; --green:#34d399; --purple:#a78bfa; --red:#f87171;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--c0);font-family:'JetBrains Mono',monospace;font-size:12px;height:100vh;overflow:hidden;display:flex;flex-direction:column;}

/* UPLOAD */
#upload-screen{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;position:relative;overflow:hidden;}
#upload-screen::before{content:'';position:absolute;inset:0;background:radial-gradient(ellipse 60% 40% at 50% 50%,rgba(56,189,248,.06) 0%,transparent 70%);pointer-events:none;}
.upload-grid{position:absolute;inset:0;background-image:linear-gradient(rgba(56,189,248,.04) 1px,transparent 1px),linear-gradient(90deg,rgba(56,189,248,.04) 1px,transparent 1px);background-size:40px 40px;mask-image:radial-gradient(ellipse 80% 80% at 50% 50%,black 30%,transparent 100%);}
.upload-logo{font-family:'Syne',sans-serif;font-size:36px;font-weight:800;letter-spacing:.06em;color:var(--accent);text-transform:uppercase;margin-bottom:4px;}
.upload-logo span{color:var(--c2);}
.upload-tagline{font-size:11px;color:var(--c2);letter-spacing:.12em;text-transform:uppercase;margin-bottom:48px;}
.drop-zone{position:relative;width:420px;border:1.5px dashed var(--border2);border-radius:12px;padding:44px 32px;text-align:center;cursor:pointer;transition:all .2s;background:var(--panel);}
.drop-zone:hover,.drop-zone.dragging{border-color:var(--accent);background:rgba(56,189,248,.05);}
.drop-icon{font-size:36px;margin-bottom:16px;display:block;opacity:.4;}
.drop-title{font-family:'Syne',sans-serif;font-size:16px;font-weight:700;color:var(--c0);margin-bottom:6px;}
.drop-sub{font-size:10px;color:var(--c2);line-height:1.6;}
.drop-sub b{color:var(--c1);}
#file-input{display:none;}
.upload-hint{margin-top:24px;font-size:9px;color:var(--c2);letter-spacing:.08em;}

/* MAIN */
#main-screen{display:none;flex:1;flex-direction:column;min-height:0;}
header{display:flex;align-items:center;gap:10px;padding:8px 14px;border-bottom:1px solid var(--border);background:var(--panel);flex-shrink:0;z-index:20;}
header h1{font-family:'Syne',sans-serif;font-size:15px;font-weight:800;letter-spacing:.05em;color:var(--accent);text-transform:uppercase;white-space:nowrap;}
header h1 span{color:var(--c2);}
.target-pill{display:flex;align-items:center;gap:6px;background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.3);border-radius:4px;padding:3px 8px;font-size:10px;}
.target-pill .tl{color:var(--gold);font-weight:700;text-transform:uppercase;letter-spacing:.08em;font-size:8px;}
.target-pill .tv{color:var(--c1);}
.hbar{width:1px;height:20px;background:var(--border);flex-shrink:0;}
.stat-pill{display:flex;gap:5px;align-items:center;font-size:10px;color:var(--c1);white-space:nowrap;}
.stat-pill b{color:var(--c0);}
.hctrls{margin-left:auto;display:flex;gap:5px;align-items:center;}
input[type=text]{background:var(--bg);border:1px solid var(--border);color:var(--c0);font-family:'JetBrains Mono',monospace;font-size:11px;padding:4px 9px;border-radius:4px;width:150px;outline:none;transition:border-color .2s;}
input[type=text]:focus{border-color:var(--accent);}
input[type=text]::placeholder{color:var(--c2);}
.btn{background:var(--bg);border:1px solid var(--border);color:var(--c1);font-family:'JetBrains Mono',monospace;font-size:9px;padding:4px 9px;border-radius:4px;cursor:pointer;transition:all .15s;letter-spacing:.05em;white-space:nowrap;}
.btn:hover{border-color:var(--accent);color:var(--accent);}
.btn.active{background:var(--accent);color:var(--bg);border-color:var(--accent);font-weight:700;}
.btn.danger:hover{border-color:var(--red);color:var(--red);}
.btn.ok{border-color:var(--green);color:var(--green);}
.btn.ok:hover{background:rgba(52,211,153,.08);}

/* WORKSPACE */
.workspace{display:flex;flex:1;min-height:0;}

/* SIDEBAR */
.sidebar{width:235px;flex-shrink:0;border-right:1px solid var(--border);background:var(--panel);display:flex;flex-direction:column;overflow:hidden;}
.ss{padding:10px 12px;border-bottom:1px solid var(--border);flex-shrink:0;}
.ss h3{font-size:8px;text-transform:uppercase;letter-spacing:.14em;color:var(--c2);margin-bottom:8px;}
.file-legend{display:flex;flex-direction:column;gap:5px;}
.file-item{display:flex;align-items:center;gap:7px;padding:3px 5px;border-radius:3px;cursor:pointer;transition:background .1s;}
.file-item:hover{background:rgba(255,255,255,.04);}
.file-item.hf{opacity:.3;}
.fdot{width:7px;height:7px;border-radius:2px;flex-shrink:0;}
.fname{font-size:9px;color:var(--c1);flex:1;}
.fcount{font-size:9px;color:var(--c2);font-weight:700;}
.paths-list{flex:1;overflow-y:auto;}
.path-item{padding:8px 12px;border-bottom:1px solid var(--border);cursor:pointer;transition:background .12s;position:relative;}
.path-item:hover{background:rgba(255,255,255,.025);}
.path-item.active{background:rgba(56,189,248,.07);}
.path-item.active::before{content:'';position:absolute;left:0;top:0;bottom:0;width:2px;background:var(--accent);}
.ph{display:flex;align-items:center;gap:6px;margin-bottom:4px;}
.prank{font-size:9px;font-weight:700;color:var(--gold);width:14px;flex-shrink:0;}
.pscore{font-size:8px;color:var(--c2);margin-left:auto;}
.pscore b{color:var(--c1);}
.ptags{display:flex;flex-wrap:wrap;gap:3px;margin-bottom:4px;}
.vtag{font-size:7px;padding:1px 5px;border-radius:2px;background:rgba(248,113,113,.15);color:var(--red);border:1px solid rgba(248,113,113,.3);letter-spacing:.06em;text-transform:uppercase;}
.vtag.sat{background:rgba(52,211,153,.12);color:var(--green);border-color:rgba(52,211,153,.3);}
.prat{font-size:8.5px;color:var(--c2);line-height:1.5;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;}
.pmeta{display:flex;gap:10px;margin-top:4px;}
.pmi{font-size:8px;color:var(--c2);}
.pmi b{color:var(--c1);}
.niw{flex-shrink:0;max-height:195px;overflow-y:auto;border-top:1px solid var(--border);padding:10px 12px;}
.niw h3{font-size:8px;text-transform:uppercase;letter-spacing:.14em;color:var(--c2);margin-bottom:8px;}
.ie{color:var(--c2);font-size:10px;}
.iname{font-size:11px;font-weight:700;color:var(--c0);word-break:break-all;line-height:1.4;}
.ifile{font-size:9px;color:var(--c1);margin-top:3px;}
.isnip{margin-top:8px;background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:6px 8px;font-size:9px;color:var(--c1);line-height:1.6;word-break:break-all;white-space:pre-wrap;}
.ianno{margin-top:6px;font-size:9px;color:var(--c2);line-height:1.5;display:-webkit-box;-webkit-line-clamp:4;-webkit-box-orient:vertical;overflow:hidden;}

/* CENTER */
.center-area{display:flex;flex:1;min-width:0;min-height:0;overflow:hidden;}

/* CANVAS */
#canvas-wrap{flex:1;position:relative;overflow:hidden;background:var(--bg);min-width:200px;}
#graph-svg{width:100%;height:100%;cursor:grab;}
#graph-svg:active{cursor:grabbing;}
.link{fill:none;stroke-opacity:.45;pointer-events:none;}
.link.call{stroke:var(--orange);stroke-width:1.5;stroke-dasharray:5,3;}
.link.data_flow{stroke:var(--c2);stroke-width:1.2;}
.link.faded{stroke-opacity:.05!important;}
.link.phi{stroke-opacity:.9!important;stroke-width:2.5!important;}
.link.shi{stroke-opacity:1!important;stroke-width:3!important;}
.node circle{stroke-width:1.5;cursor:pointer;}
.node text{font-family:'JetBrains Mono',monospace;font-size:8px;fill:var(--c1);pointer-events:none;text-anchor:middle;}
.node.tgt circle{stroke:var(--gold)!important;fill:rgba(245,158,11,.18)!important;stroke-width:2.5;filter:drop-shadow(0 0 8px rgba(245,158,11,.5));}
.node.tgt text{fill:var(--gold);font-weight:700;}
.node.sel circle{stroke-width:3;filter:drop-shadow(0 0 8px currentColor);}
.node.faded{opacity:.07;}
.node.phi{opacity:1;}
.node.scur circle{stroke-width:3.5!important;filter:drop-shadow(0 0 14px currentColor)!important;}
.node.scur text{font-weight:700;fill:var(--c0);}
#tooltip{position:absolute;background:var(--card);border:1px solid var(--border2);border-radius:6px;padding:8px 11px;font-size:10px;pointer-events:none;z-index:100;opacity:0;transition:opacity .1s;max-width:340px;line-height:1.6;box-shadow:0 12px 40px rgba(0,0,0,.6);}
#tooltip.vis{opacity:1;}
.ttn{font-weight:700;color:var(--c0);font-size:11px;word-break:break-all;}
.ttf{color:var(--c1);font-size:9px;margin-top:2px;}
.tts{color:var(--c2);font-size:9px;margin-top:5px;font-style:italic;border-top:1px solid var(--border);padding-top:5px;}
.zoom-controls{position:absolute;bottom:14px;right:14px;display:flex;flex-direction:column;gap:3px;z-index:10;}
.zoom-btn{width:26px;height:26px;background:var(--panel);border:1px solid var(--border);color:var(--c1);border-radius:4px;display:flex;align-items:center;justify-content:center;cursor:pointer;font-size:14px;transition:all .15s;font-family:monospace;}
.zoom-btn:hover{border-color:var(--accent);color:var(--accent);}
.mini-badge{position:absolute;bottom:14px;left:14px;font-size:9px;color:var(--c2);letter-spacing:.06em;}
.arrowhead-df{fill:var(--c2);}
.arrowhead-call{fill:var(--orange);}
.layer-sep{stroke:var(--border);stroke-dasharray:2,4;}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}

/* RESIZE */
#rh{width:5px;flex-shrink:0;cursor:col-resize;background:var(--border);transition:background .15s;position:relative;z-index:5;}
#rh:hover,#rh.dragging{background:var(--accent);}

/* CODE PANEL */
#cp{display:flex;flex-direction:column;width:0;overflow:hidden;transition:width .3s cubic-bezier(.4,0,.2,1);background:var(--bg);flex-shrink:0;}
#cp.open{width:520px;}
#cph{display:flex;flex-direction:column;flex-shrink:0;border-bottom:1px solid var(--border);background:var(--panel);}
#ctabs{display:flex;align-items:stretch;overflow-x:auto;min-height:32px;border-bottom:1px solid var(--border);}
#ctabs::-webkit-scrollbar{height:2px;}
.ctab{display:flex;align-items:center;gap:6px;padding:0 12px;font-size:9px;color:var(--c2);cursor:pointer;white-space:nowrap;border-right:1px solid var(--border);flex-shrink:0;transition:all .12s;position:relative;}
.ctab:hover{background:rgba(255,255,255,.03);color:var(--c1);}
.ctab.active{color:var(--c0);background:var(--bg);}
.ctab.active::after{content:'';position:absolute;bottom:0;left:0;right:0;height:2px;background:var(--accent);}
.ctab-dot{width:6px;height:6px;border-radius:1px;flex-shrink:0;}
.ctab-x{opacity:0;font-size:11px;color:var(--c2);line-height:1;margin-left:2px;}
.ctab:hover .ctab-x{opacity:1;}
.ctab-x:hover{color:var(--red);}
#stepbar{display:none;align-items:center;gap:7px;padding:5px 10px;font-size:9px;color:var(--c1);background:rgba(56,189,248,.05);border-bottom:1px solid rgba(56,189,248,.15);}
#stepbar.vis{display:flex;}
#sinfo{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--c0);}
#sinfo span{color:var(--c2);}
.sbtn{background:var(--bg);border:1px solid var(--border);color:var(--c1);font-family:'JetBrains Mono',monospace;font-size:13px;padding:2px 11px;border-radius:3px;cursor:pointer;transition:all .1s;flex-shrink:0;line-height:1.5;}
.sbtn:hover:not(:disabled){border-color:var(--accent);color:var(--accent);}
.sbtn:disabled{opacity:.25;cursor:default;pointer-events:none;}
#sctr{font-size:9px;color:var(--accent);white-space:nowrap;font-weight:700;padding:0 2px;}

/* CODE CONTENT */
#cc{flex:1;overflow:auto;font-family:'JetBrains Mono',monospace;font-size:11.5px;line-height:1.65;position:relative;}
#cc::-webkit-scrollbar{width:4px;height:4px;}
.cl{display:flex;align-items:stretch;min-height:20px;transition:background .1s;}
.cl:hover{background:rgba(255,255,255,.02);}
.cl.ln{background:rgba(56,189,248,.04);}
.cl.la{background:rgba(245,158,11,.12)!important;border-left:2px solid var(--gold);}
.cl.lps{background:rgba(56,189,248,.07)!important;border-left:2px solid rgba(56,189,248,.5);}
.cl.lcs{background:rgba(56,189,248,.18)!important;border-left:2px solid var(--accent);box-shadow:inset 0 0 0 1px rgba(56,189,248,.15);}
.lg{width:20px;flex-shrink:0;display:flex;align-items:center;justify-content:flex-end;padding-right:3px;gap:2px;overflow:hidden;}
.gd{width:5px;height:5px;border-radius:1px;flex-shrink:0;cursor:pointer;transition:transform .1s,opacity .1s;opacity:.65;}
.gd:hover{transform:scale(1.6);opacity:1;}
.lnum{width:42px;flex-shrink:0;text-align:right;padding-right:12px;font-size:10px;color:var(--c2);user-select:none;padding-top:2px;}
.cl.la .lnum{color:var(--gold);}
.cl.lcs .lnum,.cl.lps .lnum{color:var(--accent);}
.lcode{flex:1;padding-right:20px;white-space:pre;padding-top:2px;}

/* Syntax */
.kw{color:#7dd3fc;}.ty{color:#86efac;}.cls{color:#c4b5fd;}.str{color:#fde68a;}.cmt{color:#4a5568;font-style:italic;}.num{color:#fca5a5;}.pp{color:#fb923c;}.fn{color:#a5f3fc;}

/* Empty state */
#cempty{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;gap:10px;color:var(--c2);}
.ce-icon{font-size:28px;opacity:.3;}
.ce-title{font-size:11px;color:var(--c1);}
.ce-sub{font-size:9px;line-height:1.6;text-align:center;max-width:220px;}

/* Scrollbar */
::-webkit-scrollbar{width:3px;}
::-webkit-scrollbar-track{background:transparent;}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px;}
</style>
</head>
<body>

<!-- UPLOAD SCREEN -->
<div id="upload-screen">
  <div class="upload-grid"></div>
  <div class="upload-logo">DeepTrace <span>/</span> Paths</div>
  <div class="upload-tagline">Backwards call-path visualizer</div>
  <div class="drop-zone" id="drop-zone">
    <span class="drop-icon">⬡</span>
    <div class="drop-title">Drop your trace.json</div>
    <div class="drop-sub">Drag &amp; drop a <b>traces.json</b> file here,<br/>or click to browse</div>
    <input type="file" id="file-input" accept=".json"/>
  </div>
  <div class="upload-hint">Generated by DeepTrace · supports v1.0.0+</div>
</div>

<!-- MAIN SCREEN -->
<div id="main-screen">
  <header>
    <h1>DeepTrace <span>/ Paths</span></h1>
    <div class="hbar"></div>
    <div class="target-pill">
      <span class="tl">target</span>
      <span class="tv" id="htarget">—</span>
    </div>
    <div class="hbar"></div>
    <div class="stat-pill">Nodes <b id="sn">—</b></div>
    <div class="stat-pill">Edges <b id="se">—</b></div>
    <div class="stat-pill">Paths <b id="sp">—</b></div>
    <div class="hctrls">
      <input type="text" id="search-box" placeholder="Search node…"/>
      <button class="btn" id="btn-repo">📁 Open Repo</button>
      <input type="file" id="repo-dir-input" webkitdirectory multiple style="display:none"/>
      <button class="btn" id="btn-fit">⊡ Fit</button>
      <button class="btn" id="btn-labels">Labels ON</button>
      <button class="btn danger" id="btn-reload">↩ New</button>
    </div>
  </header>

  <div class="workspace">
    <aside class="sidebar">
      <div class="ss"><h3>Source Files</h3><div class="file-legend" id="flegend"></div></div>
      <div class="ss" style="flex-shrink:0;"><h3>Paths to Target — ranked by score</h3></div>
      <div class="paths-list" id="plist"></div>
      <div class="niw" id="ninfo"><h3>Node Detail</h3><div class="ie">Click a node to inspect</div></div>
    </aside>

    <div class="center-area">
      <div id="canvas-wrap">
        <svg id="graph-svg">
          <defs>
            <marker id="arrow-df" viewBox="0 -4 8 8" refX="14" refY="0" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,-4L8,0L0,4" class="arrowhead-df"/></marker>
            <marker id="arrow-call" viewBox="0 -4 8 8" refX="14" refY="0" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,-4L8,0L0,4" class="arrowhead-call"/></marker>
          </defs>
        </svg>
        <div id="tooltip"></div>
        <div class="zoom-controls">
          <div class="zoom-btn" id="zi">+</div>
          <div class="zoom-btn" id="zo">−</div>
          <div class="zoom-btn" id="zf">⊡</div>
        </div>
        <div class="mini-badge" id="mbadge"></div>
      </div>

      <div id="rh"></div>

      <div id="cp">
        <div id="cph">
          <div id="ctabs"></div>
          <div id="stepbar">
            <button class="sbtn" id="sprev">←</button>
            <div id="sinfo"><span>Select a path to step through code</span></div>
            <span id="sctr"></span>
            <button class="sbtn" id="snext">→</button>
          </div>
        </div>
        <div id="cc">
          <div id="cempty">
            <div class="ce-icon">{ }</div>
            <div class="ce-title">No file open</div>
            <div class="ce-sub">Open repo then click any graph node to view source</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
'use strict';

// ─── Upload ───────────────────────────────────────────────────────────────────
const dz = document.getElementById('drop-zone');
const fi = document.getElementById('file-input');
dz.addEventListener('click', () => fi.click());
fi.addEventListener('change', e => loadJSON(e.target.files[0]));
dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('dragging'); });
dz.addEventListener('dragleave', () => dz.classList.remove('dragging'));
dz.addEventListener('drop', e => { e.preventDefault(); dz.classList.remove('dragging'); if (e.dataTransfer.files[0]) loadJSON(e.dataTransfer.files[0]); });

document.getElementById('btn-reload').addEventListener('click', () => {
  document.getElementById('main-screen').style.display = 'none';
  document.getElementById('upload-screen').style.display = 'flex';
  fi.value = ''; resetRepo();
});

function loadJSON(file) {
  const r = new FileReader();
  r.onload = e => { try { initGraph(JSON.parse(e.target.result)); } catch(err) { alert('JSON parse error: ' + err.message); } };
  r.readAsText(file);
}

// ─── Repo ─────────────────────────────────────────────────────────────────────
let repoHandle = null, repoFiles = new Map(), fileCache = new Map(), repoReady = false;
let lineNodeMap = new Map();

function resetRepo() {
  repoHandle = null; repoFiles.clear(); fileCache.clear(); repoReady = false;
  lineNodeMap.clear(); openTabs = []; activeTab = null;
}

const repoBtn = document.getElementById('btn-repo');
const repoDirInput = document.getElementById('repo-dir-input');

repoBtn.addEventListener('click', async () => {
  if (window.showDirectoryPicker) {
    try {
      repoHandle = await window.showDirectoryPicker({ mode: 'read' });
      repoReady = true;
      repoBtn.textContent = '✓ Repo Open';
      repoBtn.classList.add('ok');
      revealCodePanel();
      return;
    } catch(e) { if (e.name === 'AbortError') return; }
  }
  repoDirInput.click();
});

repoDirInput.addEventListener('change', async function() {
  const files = Array.from(this.files).filter(f => /\.(cpp|h|c|cc|hpp|cxx|mm)$/i.test(f.name));
  if (!files.length) return;
  const prefix = files[0].webkitRelativePath.split('/')[0] + '/';
  await Promise.all(files.map(async f => {
    try { repoFiles.set(f.webkitRelativePath.replace(prefix,''), await f.text()); } catch(_) {}
  }));
  repoReady = true;
  repoBtn.textContent = `✓ Repo (${repoFiles.size})`;
  repoBtn.classList.add('ok');
  revealCodePanel();
});

async function getLines(filePath) {
  if (fileCache.has(filePath)) return fileCache.get(filePath);
  let text = repoFiles.get(filePath) || null;
  if (!text && repoHandle) {
    try {
      const parts = filePath.split('/');
      let cur = repoHandle;
      for (let i = 0; i < parts.length - 1; i++) cur = await cur.getDirectoryHandle(parts[i]);
      text = await (await (await cur.getFileHandle(parts[parts.length-1])).getFile()).text();
    } catch(_) {}
  }
  if (!text) return null;
  const lines = hl_file(text);
  fileCache.set(filePath, lines);
  return lines;
}

// ─── C++ highlighter ──────────────────────────────────────────────────────────
const KW = new Set('if else for while do return void int bool float double char long short unsigned signed const static auto struct class enum namespace using template typename public private protected virtual override new delete true false nullptr this sizeof typedef inline explicit operator friend extern volatile mutable constexpr noexcept throw try catch switch case break continue default goto union final decltype auto nullptr_t size_t int32_t int64_t uint32_t uint64_t uint16_t uint8_t wchar_t'.split(' '));

function eh(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function hl_line(line) {
  const tr = line.trimStart();
  if (tr.startsWith('#')) return `<span class="pp">${eh(line)}</span>`;
  let o = '', i = 0;
  while (i < line.length) {
    if (line[i]==='/' && line[i+1]==='/') { o+=`<span class="cmt">${eh(line.slice(i))}</span>`; break; }
    if (line[i]==='/' && line[i+1]==='*') {
      const e2 = line.indexOf('*/',i+2);
      if (e2!==-1) { o+=`<span class="cmt">${eh(line.slice(i,e2+2))}</span>`; i=e2+2; continue; }
      else { o+=`<span class="cmt">${eh(line.slice(i))}</span>`; break; }
    }
    if (line[i]==='"') {
      let j=i+1; while(j<line.length&&!(line[j]==='"'&&line[j-1]!=='\\'))j++;
      o+=`<span class="str">${eh(line.slice(i,j+1))}</span>`; i=j+1; continue;
    }
    if (line[i]==="'") {
      let j=i+1; while(j<line.length&&!(line[j]==="'"&&line[j-1]!=='\\'))j++;
      o+=`<span class="str">${eh(line.slice(i,j+1))}</span>`; i=j+1; continue;
    }
    if (/[a-zA-Z_]/.test(line[i])) {
      let j=i; while(j<line.length&&/[a-zA-Z0-9_]/.test(line[j]))j++;
      const w=line.slice(i,j);
      const after=line.slice(j).trimStart();
      if (KW.has(w)) o+=`<span class="kw">${eh(w)}</span>`;
      else if (/^[A-Z]/.test(w)&&w.length>1) o+=`<span class="cls">${eh(w)}</span>`;
      else if (after.startsWith('(')) o+=`<span class="fn">${eh(w)}</span>`;
      else o+=eh(w);
      i=j; continue;
    }
    if (/[0-9]/.test(line[i])) {
      let j=i; while(j<line.length&&/[0-9a-fA-FxX._uUlL]/.test(line[j]))j++;
      o+=`<span class="num">${eh(line.slice(i,j))}</span>`; i=j; continue;
    }
    o+=eh(line[i]); i++;
  }
  return o||' ';
}

function hl_file(text) { return text.split('\n').map(hl_line); }

// ─── Color ────────────────────────────────────────────────────────────────────
const PAL=['#38bdf8','#f472b6','#4ade80','#fb923c','#a78bfa','#fbbf24','#34d399','#e879f9','#60a5fa','#f87171'];
const fcache={};let ci=0;
function fc(f){ if(!fcache[f])fcache[f]=PAL[ci++%PAL.length]; return fcache[f]; }

// ─── Parse ────────────────────────────────────────────────────────────────────
function parseTraces(data) {
  const paths = data.paths||[];
  const nm = new Map(), em = new Map();
  paths.forEach((path,pi) => {
    (path.steps||[]).forEach((step,si) => {
      const id=step.node_id; if(!id) return;
      const dep=path.steps.length-1-si;
      if(!nm.has(id)){nm.set(id,{id,name:step.node_name||id.split(':').pop(),file:step.location?.file||'unknown',line:step.location?.line||0,snippet:step.code_snippet||'',kind:step.node_kind||'identifier',annotation:step.annotation||'',depthFromEnd:dep,pathIndices:new Set([pi])});}
      else{const n=nm.get(id);n.depthFromEnd=Math.min(n.depthFromEnd,dep);n.pathIndices.add(pi);}
    });
    for(let i=0;i<path.steps.length-1;i++){
      const s=path.steps[i].node_id,t=path.steps[i+1].node_id; if(!s||!t)continue;
      const k=`${s}||${t}`;
      const rawAnn=(path.steps[i+1].annotation||'').split('|')[0].trim();
      if(!em.has(k))em.set(k,{src:s,dst:t,kind:path.steps[i+1].edge_kind||'data_flow',annotation:rawAnn,pathIndices:new Set([pi])});
      else{const e2=em.get(k);e2.pathIndices.add(pi);if(!e2.annotation&&rawAnn)e2.annotation=rawAnn;}
    }
  });
  return {target:data.target||'',paths,nodes:[...nm.values()].map(n=>({...n,pathIndices:[...n.pathIndices]})),edges:[...em.values()].map(e=>({...e,pathIndices:[...e.pathIndices]}))};
}

// ─── Layout ───────────────────────────────────────────────────────────────────
function layout(nodes,W,H) {
  const maxD=Math.max(...nodes.map(n=>n.depthFromEnd),0);
  const lm=new Map();
  nodes.forEach(n=>{const li=maxD-n.depthFromEnd;n._layer=li;if(!lm.has(li))lm.set(li,[]);lm.get(li).push(n);});
  const nL=maxD+1,PX=80,PY=50;
  lm.forEach((ln,li)=>{
    const x=PX+(nL===1?(W-2*PX)/2:(li/(nL-1))*(W-2*PX));
    ln.forEach((nd,i)=>{nd.x=x;nd.y=ln.length===1?PY+(H-2*PY)/2:PY+(i/(ln.length-1))*(H-2*PY);});
  });
  return maxD+1;
}

// ─── State ────────────────────────────────────────────────────────────────────
let G=null,activePathIdx=null,stepIdx=-1,labelsVis=true,fileVis={};
let svg,zg,lsel,nsel,lblsel,zb;
let openTabs=[],activeTab=null;

function buildLineNodeMap() {
  lineNodeMap.clear();
  G.nodes.forEach(nd=>{
    if(!lineNodeMap.has(nd.file))lineNodeMap.set(nd.file,new Map());
    const fm=lineNodeMap.get(nd.file);
    if(!fm.has(nd.line))fm.set(nd.line,[]);
    fm.get(nd.line).push(nd.id);
  });
}

// ─── Init ─────────────────────────────────────────────────────────────────────
function initGraph(data) {
  Object.keys(fcache).forEach(k=>delete fcache[k]); ci=0;
  G=parseTraces(data); activePathIdx=null; stepIdx=-1;
  document.getElementById('main-screen').style.display='flex';
  document.getElementById('upload-screen').style.display='none';
  document.getElementById('htarget').textContent=G.target;
  document.getElementById('sn').textContent=G.nodes.length;
  document.getElementById('se').textContent=G.edges.length;
  document.getElementById('sp').textContent=G.paths.length;

  // File legend
  const fcounts={};
  G.nodes.forEach(n=>{fcounts[n.file]=(fcounts[n.file]||0)+1;});
  fileVis={};
  const fleg=document.getElementById('flegend');
  fleg.innerHTML='';
  Object.entries(fcounts).sort((a,b)=>b[1]-a[1]).forEach(([file,cnt])=>{
    fileVis[file]=true;
    const color=fc(file),sn=file.split('/').pop();
    const el=document.createElement('div');
    el.className='file-item';
    el.innerHTML=`<div class="fdot" style="background:${color}"></div><div class="fname" title="${file}">${sn}</div><div class="fcount">${cnt}</div>`;
    el.addEventListener('click',()=>{fileVis[file]=!fileVis[file];el.classList.toggle('hf',!fileVis[file]);applyVis();});
    fleg.appendChild(el);
  });

  // Paths list
  const pl=document.getElementById('plist');
  pl.innerHTML='';
  G.paths.forEach((path,idx)=>{
    const el=document.createElement('div');
    el.className='path-item';
    const tags=(path.vulnerability_tags||[]).map(t=>`<span class="vtag">${t}</span>`).join('');
    const sat=path.is_satisfiable?`<span class="vtag sat">SAT ✓</span>`:'';
    const rat=path.llm_rationale||path.vulnerability_summary||'';
    el.innerHTML=`<div class="ph"><span class="prank">#${idx+1}</span><div class="ptags">${tags}${sat}</div><span class="pscore">score <b>${(path.score||0).toFixed(1)}</b></span></div><div class="prat">${rat.length>110?rat.slice(0,108)+'…':rat}</div><div class="pmeta"><span class="pmi">depth <b>${path.depth||path.steps?.length||'?'}</b></span><span class="pmi">steps <b>${path.steps?.length||'?'}</b></span></div>`;
    el.addEventListener('click',()=>selectPath(idx,el));
    pl.appendChild(el);
  });

  buildLineNodeMap();
  buildD3();
}

// ─── D3 ───────────────────────────────────────────────────────────────────────
function buildD3() {
  d3.select('#graph-svg').selectAll('*:not(defs)').remove();
  svg=d3.select('#graph-svg');
  const wrap=document.getElementById('canvas-wrap');
  layout(G.nodes,wrap.clientWidth,wrap.clientHeight);
  G._nb=new Map(G.nodes.map(n=>[n.id,n]));

  zg=svg.append('g');
  const maxD=Math.max(...G.nodes.map(n=>n.depthFromEnd),0);
  const nL=maxD+1,PX=80;
  const lg=zg.append('g');
  for(let li=0;li<nL;li++){
    const x=PX+(nL===1?(wrap.clientWidth-2*PX)/2:(li/(nL-1))*(wrap.clientWidth-2*PX));
    lg.append('line').attr('class','layer-sep').attr('x1',x).attr('y1',0).attr('x2',x).attr('y2',wrap.clientHeight);
  }

  // Visible edge paths
  const linkG = zg.append('g');
  lsel=linkG.selectAll('path.link').data(G.edges).join('path')
    .attr('class',d=>`link ${d.kind||'data_flow'}`)
    .attr('marker-end',d=>d.kind==='call'?'url(#arrow-call)':'url(#arrow-df)')
    .attr('d',ep);

  // Wide invisible hit-area paths for edge hover
  const tt=document.getElementById('tooltip');
  linkG.selectAll('path.edge-hit').data(G.edges).join('path')
    .attr('class','edge-hit')
    .style('fill','none').style('stroke','transparent').style('stroke-width','12px').style('cursor','default')
    .attr('d',ep)
    .on('mouseover',(ev,d)=>{
      const src=G._nb.get(d.src),dst=G._nb.get(d.dst);
      const srcName=src?src.name.split('|')[0].trim():'?';
      const dstName=dst?dst.name.split('|')[0].trim():'?';
      const kindColor=d.kind==='call'?'var(--orange)':'var(--c2)';
      const kindLabel=d.kind==='call'?'call':'data_flow';
      tt.innerHTML=`<div class="ttn" style="font-size:10px">${eh(srcName)} <span style="color:${kindColor};font-size:9px">─${kindLabel}→</span> ${eh(dstName)}</div>${d.annotation?`<div class="tts" style="margin-top:5px;font-style:normal;color:var(--c1)">${eh(d.annotation.length>200?d.annotation.slice(0,198)+'…':d.annotation)}</div>`:''}`;
      tt.classList.add('vis');
    })
    .on('mousemove',ev=>{
      const r=wrap.getBoundingClientRect();
      let x=ev.clientX-r.left+14,y=ev.clientY-r.top-30;
      if(x+320>wrap.clientWidth)x-=340;
      tt.style.left=x+'px';tt.style.top=y+'px';
    })
    .on('mouseleave',()=>tt.classList.remove('vis'));

  nsel=zg.append('g').selectAll('g').data(G.nodes).join('g')
    .attr('class',d=>`node${d.depthFromEnd===0?' tgt':''}`)
    .attr('transform',d=>`translate(${d.x},${d.y})`);

  nsel.append('circle')
    .attr('r',d=>d.depthFromEnd===0?10:d.pathIndices.length>=5?8:d.pathIndices.length>=3?6.5:5)
    .attr('fill',d=>fc(d.file)+'22')
    .attr('stroke',d=>d.depthFromEnd===0?'var(--gold)':fc(d.file));

  lblsel=nsel.append('text').attr('dy',-10)
    .text(d=>{const nm=d.name.split('|')[0].trim();return nm.length>20?nm.slice(0,18)+'…':nm;});

  nsel
    .on('mouseover',(ev,d)=>{
      const nm=d.name.split('|')[0].trim();
      tt.innerHTML=`<div class="ttn">${nm}</div><div class="ttf">${d.file.split('/').pop()} : line ${d.line}</div>${d.snippet?`<div class="tts">${eh(d.snippet.slice(0,90).trim())}</div>`:''}`;
      tt.classList.add('vis');
    })
    .on('mousemove',ev=>{
      const r=wrap.getBoundingClientRect();
      let x=ev.clientX-r.left+14,y=ev.clientY-r.top-30;
      if(x+300>wrap.clientWidth)x-=320;
      tt.style.left=x+'px';tt.style.top=y+'px';
    })
    .on('mouseleave',()=>tt.classList.remove('vis'))
    .on('click',(ev,d)=>{
      ev.stopPropagation();
      showNI(d);
      // If a path is active, sync stepIdx to this node's position in the path
      if(activePathIdx!==null){
        const steps=G.paths[activePathIdx].steps;
        const si=steps.findIndex(s=>s.node_id===d.id);
        if(si!==-1){
          stepIdx=si;
          document.getElementById('sprev').disabled=si===0;
          document.getElementById('snext').disabled=si===steps.length-1;
          document.getElementById('sctr').textContent=`${si+1} / ${steps.length}`;
          const step=steps[si];
          const nm2=step.node_name?.split('|')[0].trim()||d.name.split('|')[0].trim();
          document.getElementById('sinfo').innerHTML=`<span>Step ${si+1}/${steps.length}</span> · ${eh(nm2)} <span>@ ${step.location?.short||''}</span>`;
          nsel.classed('scur',n=>n.id===d.id);
        }
      }
      if(repoReady)openNodeCode(d);
    });

  svg.on('click',()=>{showNI(null);clearPH();});

  zb=d3.zoom().scaleExtent([.04,5]).on('zoom',e=>zg.attr('transform',e.transform));
  svg.call(zb);
  document.getElementById('mbadge').textContent=`${G.nodes.length} nodes · ${G.edges.length} edges · ${G.paths.length} paths`;
  setTimeout(fitView,80);
}

function ep(d){
  const s=G._nb.get(d.src),t=G._nb.get(d.dst);
  if(!s||!t)return'';
  const dx=t.x-s.x,cp=Math.abs(dx)*.4+20;
  return `M${s.x},${s.y} C${s.x+cp},${s.y} ${t.x-cp},${t.y} ${t.x},${t.y}`;
}

// ─── Code panel ───────────────────────────────────────────────────────────────
function revealCodePanel() {
  document.getElementById('cp').classList.add('open');
  setTimeout(()=>{
    if(!G)return;
    const w=document.getElementById('canvas-wrap');
    layout(G.nodes,w.clientWidth,w.clientHeight);
    nsel.attr('transform',d=>`translate(${d.x},${d.y})`);
    lsel.attr('d',ep);
    fitView();
  },330);
}

async function openNodeCode(node) {
  revealCodePanel();
  await showFileTab(node.file, node.line, node.id);
}

async function showFileTab(filePath, scrollLine, hlNodeId) {
  if(!openTabs.find(t=>t.filePath===filePath)){
    openTabs.push({filePath,shortName:filePath.split('/').pop(),color:fc(filePath)});
  }
  activeTab=filePath;
  renderTabs();

  const lines=await getLines(filePath);
  const cc=document.getElementById('cc');
  if(!lines){
    cc.innerHTML=`<div id="cempty"><div class="ce-icon">⚠</div><div class="ce-title">File not found</div><div class="ce-sub">${eh(filePath)}</div></div>`;
    return;
  }

  const fileNodes=lineNodeMap.get(filePath)||new Map();

  // Collect path step lines for this file
  const pathLines=new Set();
  if(activePathIdx!==null){
    G.paths[activePathIdx].steps.forEach(s=>{if(s.location?.file===filePath)pathLines.add(s.location.line);});
  }

  // Current step line
  const curStepLine = (activePathIdx!==null&&stepIdx>=0) ?
    (G.paths[activePathIdx].steps[stepIdx]?.location?.file===filePath ?
      G.paths[activePathIdx].steps[stepIdx]?.location?.line : -1) : -1;

  let html='';
  lines.forEach((lineHtml,idx)=>{
    const ln=idx+1;
    const nids=fileNodes.get(ln)||[];
    const isActive=hlNodeId&&nids.includes(hlNodeId);
    const isCur=ln===curStepLine;
    const isStep=!isCur&&pathLines.has(ln);

    let cls='cl';
    if(isCur)cls+=' lcs';
    else if(isActive)cls+=' la';
    else if(isStep)cls+=' lps';
    else if(nids.length)cls+=' ln';

    const dots=nids.slice(0,3).map(id=>{
      const nd=G._nb.get(id);
      return `<span class="gd" style="background:${fc(nd?.file||'')}" data-nid="${id}" title="${nd?nd.name.split('|')[0].trim():id}"></span>`;
    }).join('');

    html+=`<div class="${cls}" data-line="${ln}"><div class="lg">${dots}</div><div class="lnum">${ln}</div><div class="lcode">${lineHtml}</div></div>`;
  });
  cc.innerHTML=html;

  // Gutter dot → pan to node in graph
  cc.querySelectorAll('.gd').forEach(dot=>{
    dot.addEventListener('click',ev=>{
      ev.stopPropagation();
      const nd=G._nb.get(dot.dataset.nid);
      if(nd){showNI(nd);panTo(nd);}
    });
  });

  // Line click → select first node on that line
  cc.querySelectorAll('.cl').forEach(row=>{
    row.addEventListener('click',()=>{
      const ln=parseInt(row.dataset.line);
      const nids=fileNodes.get(ln)||[];
      if(nids.length){const nd=G._nb.get(nids[0]);if(nd){showNI(nd);panTo(nd);}}
    });
  });

  if(scrollLine)scrollTo(scrollLine);
}

function scrollTo(ln) {
  const cc=document.getElementById('cc');
  const row=cc.querySelector(`[data-line="${ln}"]`);
  if(row)cc.scrollTo({top:Math.max(0,row.offsetTop-cc.clientHeight/3),behavior:'smooth'});
}

function renderTabs() {
  const tabsEl=document.getElementById('ctabs');
  tabsEl.innerHTML='';
  openTabs.forEach(tab=>{
    const el=document.createElement('div');
    el.className=`ctab${tab.filePath===activeTab?' active':''}`;
    el.innerHTML=`<span class="ctab-dot" style="background:${tab.color}"></span><span>${eh(tab.shortName)}</span><span class="ctab-x">×</span>`;
    el.addEventListener('click',async ev=>{
      if(ev.target.classList.contains('ctab-x')){
        openTabs=openTabs.filter(t=>t.filePath!==tab.filePath);
        if(activeTab===tab.filePath){
          activeTab=openTabs[openTabs.length-1]?.filePath||null;
          if(activeTab)await showFileTab(activeTab,null,null);
          else document.getElementById('cc').innerHTML='<div id="cempty"><div class="ce-icon">{ }</div><div class="ce-title">No file open</div></div>';
        }
        renderTabs();
      } else {
        await showFileTab(tab.filePath,null,null);
      }
    });
    tabsEl.appendChild(el);
  });
}

// ─── Path selection ───────────────────────────────────────────────────────────
async function selectPath(pathIdx,el) {
  if(activePathIdx===pathIdx){activePathIdx=null;stepIdx=-1;clearPH();document.querySelectorAll('.path-item.active').forEach(e=>e.classList.remove('active'));hideStep();return;}
  activePathIdx=pathIdx; stepIdx=0;
  document.querySelectorAll('.path-item.active').forEach(e=>e.classList.remove('active'));
  el.classList.add('active');
  const pnids=new Set(G.paths[pathIdx].steps.map(s=>s.node_id));
  nsel.classed('faded',d=>!pnids.has(d.id)).classed('phi',d=>pnids.has(d.id));
  lsel.classed('faded',d=>!d.pathIndices.includes(pathIdx)).classed('phi',d=>d.pathIndices.includes(pathIdx));
  showStep();
  await jumpStep(0);
}

async function jumpStep(idx) {
  if(activePathIdx===null)return;
  const path=G.paths[activePathIdx];
  if(idx<0||idx>=path.steps.length)return;
  stepIdx=idx;
  const step=path.steps[idx];
  const nd=G._nb.get(step.node_id);
  const nm=step.node_name?.split('|')[0].trim()||step.node_id;

  document.getElementById('sinfo').innerHTML=`<span>Step ${idx+1}/${path.steps.length}</span> · ${eh(nm)} <span>@ ${step.location?.short||''}</span>`;
  document.getElementById('sctr').textContent=`${idx+1} / ${path.steps.length}`;
  document.getElementById('sprev').disabled=idx===0;
  document.getElementById('snext').disabled=idx===path.steps.length-1;

  nsel.classed('scur',d=>d.id===step.node_id);
  if(nd){ showNI(nd); panTo(nd); }

  if(repoReady&&step.location?.file){
    revealCodePanel();
    await showFileTab(step.location.file,step.location.line,step.node_id);
  }
}

function showStep(){document.getElementById('stepbar').classList.add('vis');}
function hideStep(){document.getElementById('stepbar').classList.remove('vis');nsel?.classed('scur',false);}

document.getElementById('sprev').addEventListener('click',()=>jumpStep(stepIdx-1));
document.getElementById('snext').addEventListener('click',()=>jumpStep(stepIdx+1));

document.addEventListener('keydown',e=>{
  if(activePathIdx===null||e.target.tagName==='INPUT')return;
  if(e.key==='ArrowRight'||e.key==='ArrowDown'){e.preventDefault();jumpStep(stepIdx+1);}
  if(e.key==='ArrowLeft'||e.key==='ArrowUp'){e.preventDefault();jumpStep(stepIdx-1);}
});

function clearPH(){
  activePathIdx=null;stepIdx=-1;
  nsel?.classed('faded',false).classed('phi',false).classed('scur',false);
  lsel?.classed('faded',false).classed('phi',false);
  hideStep();
  applyVis();
}

// ─── Node info ────────────────────────────────────────────────────────────────
function showNI(d) {
  const el=document.getElementById('ninfo');
  if(!d){el.innerHTML='<h3>Node Detail</h3><div class="ie">Click a node to inspect</div>';return;}
  const color=fc(d.file);
  el.innerHTML=`<h3>Node Detail</h3><div class="iname" style="color:${color}">${d.name.replace(/\|/g,' · ')}</div><div class="ifile">${d.file.split('/').pop()} : line ${d.line}</div>${d.snippet?`<div class="isnip">${eh(d.snippet.trim())}</div>`:''}${d.annotation?`<div class="ianno">${eh(d.annotation.split('|')[0].trim())}</div>`:''}`;
}

function panTo(d){
  if(!svg||!d)return;
  const t=d3.zoomTransform(svg.node()),w=document.getElementById('canvas-wrap');
  svg.transition().duration(350).call(zb.transform,d3.zoomIdentity.translate(w.clientWidth/2-t.k*d.x,w.clientHeight/2-t.k*d.y).scale(t.k));
}

function applyVis(){
  if(!nsel)return;
  nsel.style('display',d=>fileVis[d.file]!==false?null:'none');
  const edgeVisible=d=>{const sf=G._nb.get(d.src)?.file,tf=G._nb.get(d.dst)?.file;return(fileVis[sf]!==false&&fileVis[tf]!==false)?null:'none';};
  lsel.style('display',edgeVisible);
  d3.selectAll('.edge-hit').style('display',edgeVisible);
}

// ─── Zoom ─────────────────────────────────────────────────────────────────────
function fitView(){
  if(!zg)return;
  const b=zg.node().getBBox(); if(!b.width)return;
  const w=document.getElementById('canvas-wrap'),W=w.clientWidth,H=w.clientHeight;
  const scale=Math.min(.88,Math.min(W/b.width,H/b.height));
  svg.transition().duration(500).call(zb.transform,d3.zoomIdentity.translate(W/2-scale*(b.x+b.width/2),H/2-scale*(b.y+b.height/2)).scale(scale));
}

document.getElementById('zi').addEventListener('click',()=>svg?.transition().duration(200).call(zb.scaleBy,1.4));
document.getElementById('zo').addEventListener('click',()=>svg?.transition().duration(200).call(zb.scaleBy,.7));
document.getElementById('zf').addEventListener('click',fitView);
document.getElementById('btn-fit').addEventListener('click',fitView);
document.getElementById('btn-labels').addEventListener('click',function(){
  labelsVis=!labelsVis;this.textContent=labelsVis?'Labels ON':'Labels OFF';
  this.classList.toggle('active',labelsVis);lblsel?.style('display',labelsVis?null:'none');
});

// ─── Resize handle ────────────────────────────────────────────────────────────
let isRes=false,resX=0,resW=0;
const rhEl=document.getElementById('rh'),cpEl=document.getElementById('cp');
rhEl.addEventListener('mousedown',e=>{isRes=true;resX=e.clientX;resW=cpEl.offsetWidth;rhEl.classList.add('dragging');document.body.style.cssText='cursor:col-resize;user-select:none;';});
document.addEventListener('mousemove',e=>{if(!isRes)return;const nw=Math.max(280,Math.min(window.innerWidth-500,resW+(resX-e.clientX)));cpEl.style.width=nw+'px';cpEl.style.transition='none';});
document.addEventListener('mouseup',()=>{if(!isRes)return;isRes=false;rhEl.classList.remove('dragging');document.body.style.cssText='';cpEl.style.transition='';});

// ─── Search ───────────────────────────────────────────────────────────────────
let st;
document.getElementById('search-box').addEventListener('input',function(){
  clearTimeout(st);
  st=setTimeout(async()=>{
    if(!G)return;
    const q=this.value.trim().toLowerCase();if(!q)return;
    const m=G.nodes.find(n=>n.name.toLowerCase().includes(q)||n.id.toLowerCase().includes(q));
    if(m){showNI(m);panTo(m);if(repoReady)await openNodeCode(m);}
  },300);
});

function eh(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
</script>
</body>
</html>

===============

[
  {
    "file": "core/fxcrt/fx_memcpy_wrappers.h",
    "line": 39,
    "category": "buffer_overflow",
    "severity": "critical",
    "confidence": "high",
    "cwe": "CWE-120",
    "description": "Unbounded memory copy",
    "explanation": "memcpy/memmove with attacker-controlled size can overflow the destination buffer, enabling arbitrary code execution via heap or stack corruption.",
    "attack_scenario": "This sink is a wrapper around memcpy and does not appear to be directly called from external input. The vulnerability would only manifest if an attacker could somehow control the parameters passed to FXSYS_memcpy, which are not externally sourced in the provided call chain.",
    "enclosing_function": "",
    "input_type": "unspecified",
    "entry_point": "No direct callers found in repository; this is a wrapper function that directly calls memcpy without any external input handling",
    "exploitability": "low",
    "prerequisites": "The function must be called with attacker-controlled parameters, but no such calls are found in the repository"
  },
  {
    "file": "core/fxcrt/fx_memcpy_wrappers.h",
    "line": 53,
    "category": "buffer_overflow",
    "severity": "critical",
    "confidence": "high",
    "cwe": "CWE-120",
    "description": "Unbounded memory copy",
    "explanation": "memcpy/memmove with attacker-controlled size can overflow the destination buffer, enabling arbitrary code execution via heap or stack corruption.",
    "attack_scenario": "This sink is a wrapper around memmove and does not appear to be directly called from external input. The vulnerability would only manifest if an attacker could somehow control the parameters passed to FXSYS_memmove, which are not externally sourced in the provided call chain.",
    "enclosing_function": "",
    "input_type": "unspecified",
    "entry_point": "No direct callers found in repository; this is a wrapper function that directly calls memmove without any external input handling",
    "exploitability": "low",
    "prerequisites": "The function must be called with attacker-controlled parameters, but no such calls are found in the repository"
  },
  {
    "file": "core/fxcrt/fx_memory.h",
    "line": 88,
    "category": "use_after_free",
    "severity": "critical",
    "confidence": "high",
    "cwe": "CWE-416",
    "description": "free() call — check for subsequent use of freed pointer",
    "explanation": "If the freed pointer is used after free() (read, write, or passed to another function), the attacker can control the contents via heap feng shui to achieve arbitrary read/write.",
    "attack_scenario": "This sink is a wrapper around free and does not appear to be directly called from external input. The vulnerability would only manifest if an attacker could somehow control the parameters passed to FX_AlignedFree, which are not externally sourced in the provided call chain.",
    "enclosing_function": "FX_AlignedFree",
    "input_type": "unspecified",
    "entry_point": "No direct callers found in repository; this is a wrapper function that directly calls free without any external input handling",
    "exploitability": "low",
    "prerequisites": "The function must be called with attacker-controlled parameters, but no such calls are found in the repository"
  },
  {
    "file": "core/fxge/win32/cgdi_plus_ext.cpp",
    "line": 397,
    "category": "use_after_free",
    "severity": "critical",
    "confidence": "high",
    "cwe": "CWE-416",
    "description": "C++ delete — check for subsequent use of deleted object",
    "explanation": "Using an object after delete enables use-after-free. The vtable pointer can be overwritten via heap spray to hijack virtual method calls.",
    "attack_scenario": "This sink is a direct call to delete within a COM object's Release method. The vulnerability would only manifest if the object was already freed or double-freed, which could occur due to improper reference counting in COM interfaces. This is a use-after-free scenario where an object is deleted when its reference count reaches zero.",
    "enclosing_function": "if",
    "input_type": "unspecified",
    "entry_point": "No direct callers found in repository; this is a direct call to delete within a Release method of an COM object",
    "exploitability": "low",
    "prerequisites": "Improper reference counting leading to double-free or use-after-free conditions in COM interface management"
  },
  {
    "file": "fpdfsdk/fpdf_annot.cpp",
    "line": 494,
    "category": "use_after_free",
    "severity": "critical",
    "confidence": "medium",
    "cwe": "CWE-416",
    "description": "C++ delete — check for subsequent use of deleted object",
    "explanation": "Using an object after delete enables use-after-free. The vtable pointer can be overwritten via heap spray to hijack virtual method calls.",
    "attack_scenario": "An attacker crafts a malicious PDF document containing an annotation object with invalid or corrupted metadata. When the application calls FPDFPage_CloseAnnot on this annotation, it triggers deletion of a CPDFAnnotContextFromFPDFAnnotation object that may have been previously freed or is otherwise in an inconsistent state. This leads to a use-after-free condition where the deleted memory is accessed and potentially overwritten.",
    "enclosing_function": "FPDFPage_CloseAnnot",
    "source_file": "fpdfsdk/fpdf_annot_embeddertest.cpp",
    "source_line": 846,
    "source_description": "Caller chain top: () — FPDFPage_CloseAnnot(annot);",
    "input_type": "PDF annotation handle from PDF document",
    "entry_point": "External input enters through FPDFPage_CloseAnnot API call, which is part of the PDF SDK's public interface for managing annotations",
    "entry_point_file_hint": "fpdfsdk/fpdf_annot.cpp",
    "tainted_parameters": [
      "annot"
    ],
    "exploitability": "high",
    "prerequisites": "The PDF document must contain a malformed annotation, and the application must call FPDFPage_CloseAnnot on that annotation object"
  },
  {
    "file": "fxjs/cjs_util.cpp",
    "line": 104,
    "category": "format_string",
    "severity": "critical",
    "confidence": "medium",
    "cwe": "CWE-134",
    "description": "printf-family with non-literal format string",
    "explanation": "If the format string is attacker-controlled, %n writes to arbitrary memory, %x leaks stack data, and %s reads from arbitrary pointers. Full code execution.",
    "attack_scenario": "An attacker crafts malicious JavaScript code that is executed within a PDF document's context. When the JS engine processes this code, it eventually calls CJS_Util::printf with attacker-controlled format string arguments. The printf function concatenates these arguments into an unsafe format string and passes it to v8::String::Utf8Value, which can lead to format string vulnerabilities if the input is not properly sanitized.",
    "enclosing_function": "CJS_Util::DefineJSObjects",
    "source_file": "fxjs/cjs_runtime.cpp",
    "source_line": 119,
    "source_description": "Caller chain top: CJS_Runtime::DefineJSObjects() — CJS_Util::DefineJSObjects(this);",
    "input_type": "JavaScript code executed within PDF context",
    "entry_point": "PDF JavaScript execution via PDF viewer or SDK",
    "entry_point_file_hint": "fxjs/cjs_runtime.cpp",
    "exploitability": "high",
    "prerequisites": "PDF document must be opened and JavaScript execution enabled"
  },
  {
    "file": "fxjs/xfa/cfxjse_context.cpp",
    "line": 275,
    "category": "format_string",
    "severity": "critical",
    "confidence": "high",
    "cwe": "CWE-134",
    "description": "printf-family with non-literal format string",
    "explanation": "If the format string is attacker-controlled, %n writes to arbitrary memory, %x leaks stack data, and %s reads from arbitrary pointers. Full code execution.",
    "attack_scenario": "An attacker injects JavaScript code that causes a V8 exception to be thrown during execution. When the CFXJSE_Context::EnableCompatibleMode function is called in debug mode, it prints the exception message to stderr using fprintf with an attacker-controlled format string from v8::String::Utf8Value. This can lead to information disclosure or potentially arbitrary code execution if the format string contains format specifiers.",
    "enclosing_function": "CFXJSE_Context::EnableCompatibleMode",
    "source_file": "fxjs/cjs_runtime.cpp",
    "source_line": 0,
    "source_description": "PDF JavaScript execution via PDF viewer or SDK",
    "input_type": "JavaScript code executed within PDF context",
    "entry_point": "PDF JavaScript execution via PDF viewer or SDK",
    "entry_point_file_hint": "fxjs/cjs_runtime.cpp",
    "exploitability": "medium",
    "prerequisites": "PDF document must be opened and JavaScript execution enabled; debug build required"
  },
  {
    "file": "fxjs/xfa/cfxjse_context.cpp",
    "line": 283,
    "category": "format_string",
    "severity": "critical",
    "confidence": "medium",
    "cwe": "CWE-134",
    "description": "printf-family with non-literal format string",
    "explanation": "If the format string is attacker-controlled, %n writes to arbitrary memory, %x leaks stack data, and %s reads from arbitrary pointers. Full code execution.",
    "attack_scenario": "An attacker injects JavaScript code that causes a V8 exception to be thrown during execution. When the CFXJSE_Context::EnableCompatibleMode function is called in debug mode, it prints the source line of the error to stderr using fprintf with an attacker-controlled format string from v8::String::Utf8Value. This can lead to information disclosure or potentially arbitrary code execution if the format string contains format specifiers.",
    "enclosing_function": "CFXJSE_Context::EnableCompatibleMode",
    "source_file": "fxjs/cjs_runtime.cpp",
    "source_line": 0,
    "source_description": "PDF JavaScript execution via PDF viewer or SDK",
    "input_type": "JavaScript code executed within PDF context",
    "entry_point": "PDF JavaScript execution via PDF viewer or SDK",
    "entry_point_file_hint": "fxjs/cjs_runtime.cpp",
    "exploitability": "medium",
    "prerequisites": "PDF document must be opened and JavaScript execution enabled; debug build required"
  },
  {
    "file": "core/fxcrt/fx_codepage.cpp",
    "line": 329,
    "category": "type_confusion",
    "severity": "critical",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "This is a classic use-after-free in a COM-style Release() method. The 'this' object is deleted when ref_count_ reaches zero, but there's no guarantee that the caller won't access the object after calling Release(). This is a genuine vulnerability.",
    "attack_scenario": "An attacker crafts a malformed UTF-8 byte sequence in a PDF string object. When this string is processed by the code path, it's passed to fx_codepage.cpp where each character is cast to uint8_t without proper bounds checking. This can lead to incorrect memory access patterns and potentially allow an attacker to manipulate memory layout or cause a crash.",
    "enclosing_function": "if",
    "source_file": "core/fpdfdoc",
    "source_line": 0,
    "source_description": "A function that processes UTF-8 encoded strings from PDF content or user input",
    "input_type": "UTF-8 encoded byte string from external input (e.g., PDF content)",
    "entry_point": "A function that processes UTF-8 encoded strings from PDF content or user input",
    "entry_point_file_hint": "core/fpdfdoc",
    "tainted_parameters": [
      "bstr"
    ],
    "exploitability": "medium",
    "prerequisites": "PDF parsing must be enabled and user input must be processed through this code path"
  },
  {
    "file": "core/fpdfdoc/cpdf_interactiveform.cpp",
    "line": 81,
    "category": "buffer_overflow",
    "severity": "high",
    "confidence": "high",
    "cwe": "CWE-120",
    "description": "Unbounded string copy/concat",
    "explanation": "The reinterpret_cast converts a void* to std::deque<FX_FONTDESCRIPTOR>* without any validation. If lParam does not point to a deque, this leads to type confusion and potential memory corruption.",
    "attack_scenario": "An attacker manipulates the function pointer table used in the CALLFUNC macro to redirect calls to malicious code. This can happen if the GDI+ extension module loads functions from an untrusted source or DLL, leading to type confusion when function pointers are cast and invoked.",
    "enclosing_function": "if",
    "source_file": "core/fxge/win32/",
    "source_line": 0,
    "source_description": "Dynamic loading of GDI+ DLLs or external graphics libraries that provide function pointers for rendering operations",
    "input_type": "untrusted GDI+ function pointers or DLL exports",
    "entry_point": "Dynamic loading of GDI+ DLLs or external graphics libraries that provide function pointers for rendering operations",
    "entry_point_file_hint": "core/fxge/win32/",
    "exploitability": "high",
    "prerequisites": "The application must dynamically load GDI+ functions from external sources or allow modification of function pointer tables."
  },
  {
    "file": "core/fpdfdoc/cpdf_nametree.cpp",
    "line": 616,
    "category": "use_after_free",
    "severity": "high",
    "confidence": "high",
    "cwe": "CWE-416",
    "description": "C++ delete — check for subsequent use of deleted object",
    "explanation": "This reinterpret_cast converts a void* to int32_t without validation. If the value is not actually an integer, this leads to type confusion and undefined behavior.",
    "attack_scenario": "An attacker crafts a malicious IStream implementation or provides untrusted data to the Write method of a stream object. When the data is cast to const char* and written to an internal buffer, it can cause type confusion due to incorrect assumptions about memory layout or size, potentially leading to memory corruption.",
    "enclosing_function": "if",
    "source_file": "core/fxge/win32/",
    "source_line": 0,
    "source_description": "External input that flows into an IStream Write method, such as network streams or file parsing",
    "input_type": "malformed stream data or IStream implementation",
    "entry_point": "External input that flows into an IStream Write method, such as network streams or file parsing",
    "entry_point_file_hint": "core/fxge/win32/",
    "exploitability": "medium",
    "prerequisites": "The application must be using IStream interfaces with untrusted input streams or allow custom stream implementations."
  },
  {
    "file": "core/fpdfdoc/cpdf_nametree_unittest.cpp",
    "line": 322,
    "category": "use_after_free",
    "severity": "high",
    "confidence": "high",
    "cwe": "CWE-416",
    "description": "C++ delete — check for subsequent use of deleted object",
    "explanation": "This reinterpret_cast converts a void* to XFA_AttributeValue without validation. If the value is not actually an enum, this leads to type confusion and undefined behavior.",
    "attack_scenario": "An attacker could craft a unit test that manipulates the internal state of a CPDF_NameTree object to trigger use-after-free behavior by deleting nodes and then accessing freed memory. The attack would involve creating a malformed name tree structure with specific Kids arrays, calling DeleteValueAndName with crafted indices, and then accessing previously deleted nodes through subsequent lookups.",
    "enclosing_function": "",
    "source_file": "core/fpdfdoc/cpdf_nametree_unittest.cpp",
    "source_line": 0,
    "source_description": "Unit test framework calling into PDF name tree deletion logic",
    "input_type": "unit test data",
    "entry_point": "Unit test framework calling into PDF name tree deletion logic",
    "entry_point_file_hint": "core/fpdfdoc/cpdf_nametree_unittest.cpp",
    "exploitability": "low",
    "prerequisites": "The attacker must be able to write unit tests that directly manipulate internal PDF name tree structures and execute them in a test environment"
  },
  {
    "file": "core/fpdfapi/parser/object_tree_traversal_util_embeddertest.cpp",
    "line": 25,
    "category": "type_confusion",
    "severity": "high",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "reinterpret_cast bypasses type safety. If the source object is attacker-controlled, the cast can create a type-confused pointer that accesses wrong offsets, leading to info leak or code execution.",
    "attack_scenario": "An attacker provides a malicious FPDF_DOCUMENT handle that is cast directly to CPDF_Document*. This bypasses type checking and allows the attacker to pass an invalid pointer to functions expecting a valid CPDF_Document object. If the application dereferences this pointer, it can lead to memory corruption or arbitrary code execution.",
    "enclosing_function": "GetCPDFDocument",
    "source_file": "core/fpdfapi/parser/cpdf_parser.cpp",
    "source_line": 0,
    "source_description": "External PDF SDK API call to open or process a document",
    "input_type": "FPDF_DOCUMENT handle passed from external API",
    "entry_point": "External PDF SDK API call to open or process a document",
    "entry_point_file_hint": "core/fpdfapi/parser/cpdf_parser.cpp",
    "tainted_parameters": [
      "document"
    ],
    "exploitability": "high",
    "prerequisites": "Application must accept external FPDF_DOCUMENT handles and pass them to GetCPDFDocument function"
  },
  {
    "file": "core/fpdfapi/render/cpdf_renderstatus.cpp",
    "line": 1309,
    "category": "type_confusion",
    "severity": "high",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "reinterpret_cast bypasses type safety. If the source object is attacker-controlled, the cast can create a type-confused pointer that accesses wrong offsets, leading to info leak or code execution.",
    "attack_scenario": "An attacker crafts a PDF document with specific transparency settings that cause the alpha parameter to be set to a value other than 1.0f. When the rendering code path executes, it passes this alpha value to the conditional block where reinterpret_cast is used on fill_argb. If the alpha value is manipulated in an unexpected way, it can lead to type confusion or memory corruption due to incorrect casting of the ARGB structure.",
    "enclosing_function": "if",
    "source_file": "core/fpdfapi/render/cpdf_renderstatus.cpp",
    "source_line": 0,
    "source_description": "PDF rendering pipeline with transparency effects",
    "input_type": "Floating-point alpha value passed from rendering pipeline",
    "entry_point": "PDF rendering pipeline with transparency effects",
    "entry_point_file_hint": "core/fpdfapi/render/cpdf_renderstatus.cpp",
    "exploitability": "low",
    "prerequisites": "PDF document must contain transparency effects and rendering pipeline must be invoked with specific alpha values"
  },
  {
    "file": "core/fxcrt/fx_memory.cpp",
    "line": 41,
    "category": "type_confusion",
    "severity": "high",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The code deletes a CPDFAnnotContext object that was created from an FPDF_ANNOTATION parameter. If the annotation is still referenced elsewhere, this deletion could lead to use-after-free when those references are later accessed.",
    "attack_scenario": "An attacker manipulates a pointer value to be misaligned, or crafts an alignment parameter that causes incorrect behavior in IsAligned. If this function is used for memory safety checks, it could allow bypassing alignment requirements and potentially lead to memory corruption or crashes when the alignment check fails.",
    "enclosing_function": "IsAligned",
    "source_file": "core/fxcrt",
    "source_line": 0,
    "source_description": "A function that checks memory alignment of pointers passed from various parts of the PDF engine",
    "input_type": "memory address and alignment value from external or internal memory management",
    "entry_point": "A function that checks memory alignment of pointers passed from various parts of the PDF engine",
    "entry_point_file_hint": "core/fxcrt",
    "tainted_parameters": [
      "val",
      "alignment"
    ],
    "exploitability": "low",
    "prerequisites": "The function must be called with attacker-controlled pointer values or alignment parameters"
  },
  {
    "file": "fpdfsdk/fpdf_annot_embeddertest.cpp",
    "line": 1542,
    "category": "buffer_overflow",
    "severity": "high",
    "confidence": "high",
    "cwe": "CWE-120",
    "description": "Explicitly marked UNSAFE memory operation",
    "explanation": "This printf uses a format string constructed from user input (params[0]) without sanitization. The unsafe_fmt_string is built by prepending 'S' to the user-provided format string, but this doesn't prevent format string vulnerabilities if the user provides malicious format specifiers.",
    "attack_scenario": "An attacker provides a crafted annotation in a PDF file that causes FPDFAnnot_GetAP to return an unexpectedly large buffer size. The code then writes 8 bytes of 'abcdefgh' into this oversized buffer, potentially overwriting adjacent memory or corrupting heap metadata. This is a buffer overflow because the memcpy operation does not validate that buf.data() has sufficient space for the 8-byte string.",
    "enclosing_function": "for",
    "source_file": "fpdfsdk/fpdf_annot_embeddertest.cpp",
    "source_line": 0,
    "source_description": "FPDF annotation API layer where external PDF annotations are processed",
    "input_type": "buffer size returned by FPDFAnnot_GetAP API",
    "entry_point": "FPDF annotation API layer where external PDF annotations are processed",
    "entry_point_file_hint": "fpdfsdk/fpdf_annot_embeddertest.cpp",
    "tainted_parameters": [
      "buf.data()"
    ],
    "exploitability": "medium",
    "prerequisites": "PDF annotation must be processed by FPDF library and API must be called with crafted input"
  },
  {
    "file": "fpdfsdk/fpdf_edittext.cpp",
    "line": 340,
    "category": "type_confusion",
    "severity": "high",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "This fprintf uses v8::String::Utf8Value which can contain arbitrary data from JavaScript exceptions. The error string is directly passed to fprintf without sanitization, creating a format string vulnerability.",
    "attack_scenario": "An attacker crafts a malformed PDF file with a specially constructed glyph path object that contains a crafted FPDF_GLYPHPATH pointer. When the PDF is processed by the FPDF library, this pointer gets passed to CFXPathFromFPDFGlyphPath which performs an unsafe reinterpret_cast, potentially causing type confusion and arbitrary code execution.",
    "enclosing_function": "CFXPathFromFPDFGlyphPath",
    "source_file": "fpdfsdk/fpdf_parser.cpp",
    "source_line": 0,
    "source_description": "PDF parser reading glyph path data from a malicious PDF file",
    "input_type": "malformed PDF data containing crafted FPDF_GLYPHPATH structures",
    "entry_point": "PDF parser reading glyph path data from a malicious PDF file",
    "entry_point_file_hint": "fpdfsdk/fpdf_parser.cpp",
    "exploitability": "high",
    "prerequisites": "User must open the crafted PDF file with a PDF viewer using the FPDF library"
  },
  {
    "file": "fpdfsdk/fpdf_sysfontinfo.cpp",
    "line": 194,
    "category": "type_confusion",
    "severity": "high",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "This fprintf uses v8::String::Utf8Value which can contain arbitrary data from JavaScript source lines. The sourceline string is directly passed to fprintf without sanitization, creating a format string vulnerability.",
    "attack_scenario": "An attacker modifies the embedded default TTF map data to contain invalid or malicious entries. When FPDF_GetDefaultTTFMapEntry is called with an index pointing to this crafted data, it returns a pointer to a malformed FPDF_CharsetFontMap structure via reinterpret_cast, leading to type confusion and potential code execution when the returned structure is accessed.",
    "enclosing_function": "FPDF_GetDefaultTTFMapCount",
    "source_file": "fpdfsdk/fpdf_sysfontinfo_embeddertest.cpp",
    "source_line": 372,
    "source_description": "Caller chain top: while() — const size_t count = FPDF_GetDefaultTTFMapCount();",
    "input_type": "malformed font mapping data in default TTF map entries",
    "entry_point": "Font mapping table loaded from embedded resources during font initialization",
    "entry_point_file_hint": "fpdfsdk/fpdf_sysfontinfo.cpp",
    "exploitability": "medium",
    "prerequisites": "The application must load and process default font mapping tables"
  },
  {
    "file": "core/fpdfapi/page/cpdf_psengine.cpp",
    "line": 151,
    "category": "sql_injection",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-89",
    "description": "SQL query with string concatenation/formatting",
    "explanation": "The memcpy operation is bounded by the size calculation (gap_position_ - idx) * char_size, and there are no obvious overflows in the bounds. The gap_position_ and idx are controlled by internal state management.",
    "attack_scenario": "An attacker crafts a malformed bitmap or DIB (Device Independent Bitmap) structure with a specially crafted BITMAPINFOHEADER that, when passed to StretchDIBits via the GDI device driver, causes a type confusion due to incorrect casting. The attacker's data enters through image file parsing or graphics rendering APIs that construct device contexts and bitmaps.",
    "enclosing_function": "CPDF_PSProc::Execute",
    "source_file": "core/fxge/win32/",
    "source_line": 0,
    "source_description": "External input that manipulates or constructs GDI device contexts, potentially through untrusted image files or graphics operations",
    "input_type": "malformed bitmap data or GDI device context manipulation",
    "entry_point": "External input that manipulates or constructs GDI device contexts, potentially through untrusted image files or graphics operations",
    "entry_point_file_hint": "core/fxge/win32/",
    "exploitability": "medium",
    "prerequisites": "The application must be processing untrusted bitmap images or using GDI functions with user-controlled device contexts."
  },
  {
    "file": "core/fpdfapi/page/cpdf_psengine.h",
    "line": 78,
    "category": "sql_injection",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-89",
    "description": "SQL query with string concatenation/formatting",
    "explanation": "Similar to previous case, this memcpy is also bounded by (idx - gap_position_) * char_size. The bounds are controlled by the function's logic and internal state.",
    "attack_scenario": "An attacker manipulates a graphics context or clipping region through an untrusted input source (e.g., a PDF page with malformed clip data) that leads to incorrect casting in GetClipBox. This causes a type confusion when the RECT structure is interpreted incorrectly, potentially leading to memory corruption.",
    "enclosing_function": "",
    "source_file": "core/fxge/win32/",
    "source_line": 0,
    "source_description": "Graphics rendering subsystem or external APIs that interact with GDI device contexts and clipping regions, such as drawing operations or window management",
    "input_type": "untrusted graphics context or clipping region manipulation",
    "entry_point": "Graphics rendering subsystem or external APIs that interact with GDI device contexts and clipping regions, such as drawing operations or window management",
    "entry_point_file_hint": "core/fxge/win32/",
    "exploitability": "medium",
    "prerequisites": "The application must be using GDI device contexts and performing clipping operations on untrusted graphics input."
  },
  {
    "file": "core/fpdfapi/page/cpdf_psengine.h",
    "line": 94,
    "category": "sql_injection",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-89",
    "description": "SQL query with string concatenation/formatting",
    "explanation": "This memcpy is also bounded by (text_length_ - gap_position_) * char_size. The size calculation is based on internal state and text length, which are controlled.",
    "attack_scenario": "An attacker provides a malformed FX_RECT structure through a graphics operation (e.g., a PDF path fill command) that gets incorrectly cast to a RECT pointer. This leads to type confusion when FillRect is called, potentially causing memory corruption or arbitrary code execution.",
    "enclosing_function": "",
    "source_file": "core/fxge/win32/",
    "source_line": 0,
    "source_description": "Graphics rendering APIs or PDF drawing operations that accept user-defined rectangles for clipping or filling",
    "input_type": "malformed rectangle data or graphics rendering parameters",
    "entry_point": "Graphics rendering APIs or PDF drawing operations that accept user-defined rectangles for clipping or filling",
    "entry_point_file_hint": "core/fxge/win32/",
    "exploitability": "medium",
    "prerequisites": "The application must be processing user-defined drawing commands or clipping regions with untrusted input."
  },
  {
    "file": "core/fxcodec/jpx/cjpx_decoder.cpp",
    "line": 547,
    "category": "use_after_free",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-416",
    "description": "free() call — check for subsequent use of freed pointer",
    "explanation": "While strncpy is used, it's bounded by PNG_ERROR_SIZE - 1 which ensures null termination. The function is not vulnerable to buffer overflow.",
    "attack_scenario": "An attacker could craft a malicious JPEG2000 image file containing a crafted ICC profile buffer that, when processed by the JPX decoder, leads to freeing memory that is subsequently accessed. The attack would involve creating an image with malformed ICC data that causes the decoder to free the buffer and then access it again during cleanup.",
    "enclosing_function": "if",
    "source_file": "core/fxcodec/jpx/cjpx_decoder.cpp",
    "source_line": 0,
    "source_description": "JPEG2000 decoder reading and processing ICC profile data from image files",
    "input_type": "JPEG2000 image data processed by OpenJPEG library",
    "entry_point": "JPEG2000 decoder reading and processing ICC profile data from image files",
    "entry_point_file_hint": "core/fxcodec/jpx/cjpx_decoder.cpp",
    "exploitability": "medium",
    "prerequisites": "The application must process JPEG2000 images with embedded ICC profiles, and the OpenJPEG library must be used for decoding"
  },
  {
    "file": "core/fxcrt/bytestring_unittest.cpp",
    "line": 1029,
    "category": "buffer_overflow",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-120",
    "description": "Unbounded string copy/concat",
    "explanation": "This is a simple memcpy wrapper that does not introduce any vulnerability. The size parameter is validated and controlled.",
    "attack_scenario": "An attacker could craft a unit test that manipulates the internal buffer of a ByteString object to cause a buffer overflow by writing beyond the allocated bounds. The attack would involve calling GetBuffer with insufficient space and then using strcpy to write data past the end of the buffer, potentially overwriting adjacent memory.",
    "enclosing_function": "",
    "source_file": "core/fxcrt/bytestring_unittest.cpp",
    "source_line": 0,
    "source_description": "Unit test framework calling into ByteString buffer manipulation logic",
    "input_type": "unit test data",
    "entry_point": "Unit test framework calling into ByteString buffer manipulation logic",
    "entry_point_file_hint": "core/fxcrt/bytestring_unittest.cpp",
    "exploitability": "low",
    "prerequisites": "The attacker must be able to write unit tests that directly manipulate ByteString internal buffers and execute them in a test environment"
  },
  {
    "file": "core/fxcrt/bytestring_unittest.cpp",
    "line": 1039,
    "category": "buffer_overflow",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-120",
    "description": "Unbounded string copy/concat",
    "explanation": "While strncpy is used, it's bounded by copy_length * sizeof(ByteString::CharType) which ensures null termination. The buffer size is validated.",
    "attack_scenario": "An attacker could craft a unit test that manipulates the internal buffer of a ByteString object to cause a buffer overflow by writing beyond the allocated bounds. The attack would involve calling GetBuffer with insufficient space and then using strcpy to write data past the end of the buffer, potentially overwriting adjacent memory.",
    "enclosing_function": "",
    "source_file": "core/fxcrt/bytestring_unittest.cpp",
    "source_line": 0,
    "source_description": "Unit test framework calling into ByteString buffer manipulation logic",
    "input_type": "unit test data",
    "entry_point": "Unit test framework calling into ByteString buffer manipulation logic",
    "entry_point_file_hint": "core/fxcrt/bytestring_unittest.cpp",
    "exploitability": "low",
    "prerequisites": "The attacker must be able to write unit tests that directly manipulate ByteString internal buffers and execute them in a test environment"
  },
  {
    "file": "core/fxcrt/cfx_timer.cpp",
    "line": 28,
    "category": "use_after_free",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-416",
    "description": "C++ delete — check for subsequent use of deleted object",
    "explanation": "This is a test code that uses reinterpret_cast to check if malloc'd objects are managed by PartitionAlloc. This is legitimate testing code for verification purposes, not actual vulnerable runtime behavior.",
    "attack_scenario": "An attacker could craft a unit test that manipulates the global timer map state to trigger use-after-free behavior. The attack would involve creating a scenario where CFX_Timer::DestroyGlobals is called multiple times or with a corrupted timer map, leading to double-free or access of freed memory during cleanup.",
    "enclosing_function": "CFX_Timer::DestroyGlobals",
    "source_file": "core/fxcrt/cfx_timer_unittest.cpp",
    "source_line": 34,
    "source_description": "Caller chain top: () — void TearDown() override { CFX_Timer::DestroyGlobals(); }",
    "input_type": "unit test data",
    "entry_point": "Unit test framework calling into timer global cleanup logic",
    "entry_point_file_hint": "core/fxcrt/cfx_timer_unittest.cpp",
    "exploitability": "low",
    "prerequisites": "The attacker must be able to write unit tests that directly manipulate global timer state and execute them in a test environment"
  },
  {
    "file": "core/fpdfdoc/cpdf_interactiveform.cpp",
    "line": 91,
    "category": "buffer_overflow",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-120",
    "description": "Explicitly marked UNSAFE memory operation",
    "explanation": "This is a simple wrapper function that calls free() on a pointer passed in as an argument. There's no subsequent use of the pointer after freeing, and the function signature shows it takes a void* parameter without any complex state management.",
    "attack_scenario": "An attacker crafts a malicious PDF file containing a malformed font resource that triggers the EnumFontFamiliesExA function to populate a crafted LOGFONTA structure. When this structure is copied into the caller's buffer via FXSYS_memcpy, it overflows the destination buffer because the size check is bypassed. The attacker can control the contents of the LOGFONTA structure through malicious font data in the PDF.",
    "enclosing_function": "if",
    "source_file": "core/fpdfdoc/cpdf_interactiveform.cpp",
    "source_line": 0,
    "source_description": "PDF parser processing font-related dictionaries and font resources",
    "input_type": "font data from PDF files or embedded resources",
    "entry_point": "PDF parser processing font-related dictionaries and font resources",
    "entry_point_file_hint": "core/fpdfdoc/cpdf_interactiveform.cpp",
    "tainted_parameters": [
      "log_font"
    ],
    "exploitability": "high",
    "prerequisites": "PDF file must be opened and parsed by the interactive form handler"
  },
  {
    "file": "core/fpdfdoc/cpdf_interactiveform.cpp",
    "line": 130,
    "category": "buffer_overflow",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-120",
    "description": "Explicitly marked UNSAFE memory operation",
    "explanation": "Similar to hit 20, this is a simple wrapper that calls free() on the input pointer. No subsequent use of the freed pointer occurs in the function scope.",
    "attack_scenario": "An attacker crafts a malicious PDF with specially crafted font data that causes the RetrieveSpecificFont function to populate a LOGFONTA structure. When this structure is copied into the caller's buffer via FXSYS_memcpy, it overflows the destination buffer because the size check is bypassed. The attacker can control the contents of the LOGFONTA structure through malicious font data in the PDF.",
    "enclosing_function": "if",
    "source_file": "core/fpdfdoc/cpdf_interactiveform.cpp",
    "source_line": 0,
    "source_description": "PDF parser processing font-related dictionaries and font resources",
    "input_type": "font data from PDF files or embedded resources",
    "entry_point": "PDF parser processing font-related dictionaries and font resources",
    "entry_point_file_hint": "core/fpdfdoc/cpdf_interactiveform.cpp",
    "tainted_parameters": [
      "log_font"
    ],
    "exploitability": "high",
    "prerequisites": "PDF file must be opened and parsed by the interactive form handler"
  },
  {
    "file": "core/fxcodec/png/libpng_png_decoder.cpp",
    "line": 63,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The Free() call here is within an if (ptr) check, and there's no subsequent use of the freed pointer. The function is a simple wrapper that delegates to PartitionAlloc's Free method.",
    "attack_scenario": "An attacker crafts a malformed PNG file that triggers the _png_get_header_func callback. The png_get_progressive_ptr function returns an invalid or maliciously crafted pointer, which is then cast to CPngContext* without proper validation. This leads to a type confusion vulnerability where the attacker-controlled data is interpreted as a different type, potentially allowing for arbitrary code execution.",
    "enclosing_function": "_png_get_header_func",
    "source_file": "core/fxcodec/png/libpng_png_decoder.cpp",
    "source_line": 0,
    "source_description": "PNG decoder processing progressive PNG images",
    "input_type": "malformed PNG image data",
    "entry_point": "PNG decoder processing progressive PNG images",
    "entry_point_file_hint": "core/fxcodec/png/libpng_png_decoder.cpp",
    "tainted_parameters": [
      "png_ptr"
    ],
    "exploitability": "high",
    "prerequisites": "PNG image must be processed by the progressive PNG decoder"
  },
  {
    "file": "core/fxcodec/png/libpng_png_decoder.cpp",
    "line": 120,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "This is another simple wrapper function that calls Free() on a pointer. The code shows proper null checking before calling Free(), and there's no subsequent use of the freed pointer.",
    "attack_scenario": "An attacker crafts a malformed PNG file that triggers the _png_get_row_func callback. The png_get_progressive_ptr function returns an invalid or maliciously crafted pointer, which is then cast to CPngContext* without proper validation. This leads to a type confusion vulnerability where the attacker-controlled data is interpreted as a different type, potentially allowing for arbitrary code execution.",
    "enclosing_function": "_png_get_end_func",
    "source_file": "core/fxcodec/png/libpng_png_decoder.cpp",
    "source_line": 0,
    "source_description": "PNG decoder processing progressive PNG images",
    "input_type": "malformed PNG image data",
    "entry_point": "PNG decoder processing progressive PNG images",
    "entry_point_file_hint": "core/fxcodec/png/libpng_png_decoder.cpp",
    "tainted_parameters": [
      "png_ptr"
    ],
    "exploitability": "high",
    "prerequisites": "PNG image must be processed by the progressive PNG decoder"
  },
  {
    "file": "core/fxcodec/tiff/tiff_decoder.cpp",
    "line": 111,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "This is a destructor that deletes a global allocator object. The code sets g_allocators to nullptr immediately after deletion, which prevents any subsequent use of the freed memory.",
    "attack_scenario": "An attacker crafts a malformed TIFF file that causes the tiff_read function to be called with a malicious context pointer. The reinterpret_cast operation directly casts this pointer to CTiffContext* without validation, leading to type confusion. This allows the attacker to control memory access patterns and potentially execute arbitrary code by manipulating the decoded image data.",
    "enclosing_function": "tiff_read",
    "source_file": "core/fxcodec/tiff/tiff_decoder.cpp",
    "source_line": 0,
    "source_description": "TIFF decoder processing image data streams",
    "input_type": "malformed TIFF image data",
    "entry_point": "TIFF decoder processing image data streams",
    "entry_point_file_hint": "core/fxcodec/tiff/tiff_decoder.cpp",
    "tainted_parameters": [
      "context"
    ],
    "exploitability": "high",
    "prerequisites": "TIFF image must be processed by the TIFF decoder"
  },
  {
    "file": "core/fxcodec/tiff/tiff_decoder.cpp",
    "line": 139,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "This is a test case where free() is called on memory allocated with malloc. The test is clearly for verification purposes and doesn't represent real code execution flow.",
    "attack_scenario": "An attacker crafts a malformed TIFF file containing a specially crafted context pointer in the TIFF structure. When the TIFF decoder calls tiff_seek with this malicious context, the reinterpret_cast converts the attacker-controlled pointer into a CTiffContext* which is then dereferenced, leading to type confusion and potential arbitrary code execution.",
    "enclosing_function": "tiff_seek",
    "source_file": "core/fxcodec/tiff/",
    "source_line": 0,
    "source_description": "TIFF file parsing module that processes external TIFF image data",
    "input_type": "malformed TIFF file with crafted context pointer",
    "entry_point": "TIFF file parsing module that processes external TIFF image data",
    "entry_point_file_hint": "core/fxcodec/tiff/",
    "tainted_parameters": [
      "context"
    ],
    "exploitability": "high",
    "prerequisites": "TIFF file parsing must be enabled and a user must open the crafted TIFF file"
  },
  {
    "file": "core/fxcodec/tiff/tiff_decoder.cpp",
    "line": 181,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "This is a template declaration, not an actual function call. The Free() parameter is a function pointer type, not a call to free().",
    "attack_scenario": "An attacker crafts a malformed TIFF file containing a specially crafted context pointer. When the TIFF decoder calls tiff_get_size with this malicious context, the reinterpret_cast converts the attacker-controlled pointer into a CTiffContext* which is then dereferenced to access file size information, causing type confusion and potential memory corruption.",
    "enclosing_function": "tiff_get_size",
    "source_file": "core/fxcodec/tiff/",
    "source_line": 0,
    "source_description": "TIFF file parsing module that processes external TIFF image data",
    "input_type": "malformed TIFF file with crafted context pointer",
    "entry_point": "TIFF file parsing module that processes external TIFF image data",
    "entry_point_file_hint": "core/fxcodec/tiff/",
    "tainted_parameters": [
      "context"
    ],
    "exploitability": "high",
    "prerequisites": "TIFF file parsing must be enabled and a user must open the crafted TIFF file"
  },
  {
    "file": "core/fxcodec/tiff/tiff_decoder.cpp",
    "line": 97,
    "category": "buffer_overflow",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-120",
    "description": "Explicitly marked UNSAFE memory operation",
    "explanation": "This is a member function of a template class that calls Free() on the passed pointer. However, this is part of a standard allocator pattern and the function itself doesn't show any subsequent use of the freed pointer.",
    "attack_scenario": "An attacker crafts a malformed TIFF file containing oversized buffer size values in the TIFF structure. When _TIFFmemset is called with these malicious size parameters, the static_cast<size_t>(size) can overflow or become extremely large, leading to a buffer overflow when FXSYS_memset attempts to write beyond allocated memory boundaries.",
    "enclosing_function": "_TIFFmemset",
    "source_file": "core/fxcodec/tiff/",
    "source_line": 0,
    "source_description": "TIFF file parsing module that processes external TIFF image data",
    "input_type": "malformed TIFF file with oversized buffer size",
    "entry_point": "TIFF file parsing module that processes external TIFF image data",
    "entry_point_file_hint": "core/fxcodec/tiff/",
    "tainted_parameters": [
      "ptr",
      "size"
    ],
    "exploitability": "high",
    "prerequisites": "TIFF file parsing must be enabled and a user must open the crafted TIFF file"
  },
  {
    "file": "core/fxcrt/cfx_fileaccess_posix.cpp",
    "line": 37,
    "category": "path_traversal",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-22",
    "description": "File open with non-literal path",
    "explanation": "This is a test case using UNSAFE_BUFFERS macro. The wcscpy call is within a test context where buffer bounds are explicitly managed by the test framework.",
    "attack_scenario": "An attacker provides a crafted file path containing directory traversal sequences like '../' or '..\\'. When CFX_FileAccess_Posix::Open is called with this malicious fileName, the open() system call will attempt to access files outside the intended directory, potentially allowing unauthorized file access or path traversal attacks.",
    "enclosing_function": "CFX_FileAccess_Posix::Open",
    "source_file": "core/fxcrt/",
    "source_line": 0,
    "source_description": "File access subsystem that handles external file operations",
    "input_type": "malformed file path string with directory traversal sequences",
    "entry_point": "File access subsystem that handles external file operations",
    "entry_point_file_hint": "core/fxcrt/",
    "tainted_parameters": [
      "fileName"
    ],
    "exploitability": "medium",
    "prerequisites": "File access operations must be enabled and user must attempt to open a crafted file path"
  },
  {
    "file": "core/fxcrt/cfx_fileaccess_posix.cpp",
    "line": 43,
    "category": "path_traversal",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-22",
    "description": "File open with non-literal path",
    "explanation": "Similar to hit 28, this is a test case using UNSAFE_TODO macro. The wcscpy call is within a controlled test environment where buffer bounds are managed by the test framework.",
    "attack_scenario": "An attacker provides a crafted file path containing directory traversal sequences like '../' or '..\\'. When CFX_FileAccess_Posix::Open is called with this malicious fileName, the open() system call will attempt to access files outside the intended directory. The unterminated_c_str() method may not properly sanitize the input, leading to path traversal vulnerabilities that could allow unauthorized file access.",
    "enclosing_function": "if",
    "source_file": "core/fxcrt/",
    "source_line": 0,
    "source_description": "File access subsystem that handles external file operations",
    "input_type": "malformed file path string with directory traversal sequences",
    "entry_point": "File access subsystem that handles external file operations",
    "entry_point_file_hint": "core/fxcrt/",
    "tainted_parameters": [
      "fileName"
    ],
    "exploitability": "medium",
    "prerequisites": "File access operations must be enabled and user must attempt to open a crafted file path"
  },
  {
    "file": "core/fxcrt/cfx_fileaccess_stream.cpp",
    "line": 15,
    "category": "path_traversal",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-22",
    "description": "File open with non-literal path",
    "explanation": "The code deletes g_GEModule and immediately sets it to nullptr. There are no subsequent uses of g_GEModule after the delete operation, and the Get() function has a DCHECK that would catch any misuse.",
    "attack_scenario": "An attacker crafts a malicious file path containing directory traversal sequences like '../' or '..\\' and passes it as the filename parameter. This path is then passed through CFX_FileAccessStream::CreateFromFilename to CFX_FileAccess_Windows::Open, which uses it directly in CreateFileW without sanitization. The result is that an attacker can access arbitrary files on the system.",
    "enclosing_function": "",
    "source_file": "core/fpdfdoc",
    "source_line": 0,
    "source_description": "A function that accepts a filename from an untrusted source and passes it to CFX_FileAccessStream::CreateFromFilename",
    "input_type": "file path provided by user or external configuration",
    "entry_point": "A function that accepts a filename from an untrusted source and passes it to CFX_FileAccessStream::CreateFromFilename",
    "entry_point_file_hint": "core/fpdfdoc",
    "tainted_parameters": [
      "filename"
    ],
    "exploitability": "high",
    "prerequisites": "The calling code must accept user-provided filenames and pass them to this function"
  },
  {
    "file": "core/fxcrt/cfx_fileaccess_windows.cpp",
    "line": 25,
    "category": "path_traversal",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-22",
    "description": "File open with non-literal path",
    "explanation": "Similar to the previous case, g_fontmgr is deleted and immediately set to nullptr. No subsequent access occurs in the provided context.",
    "attack_scenario": "An attacker provides a crafted filename containing path traversal sequences such as '../' or '..\\'. This filename is passed through the call chain to CFX_FileAccess_Windows::Open, where it's converted from UTF8 to wide string and then directly used in CreateFileW. The vulnerability allows an attacker to open arbitrary files on the filesystem.",
    "enclosing_function": "CFX_FileAccess_Windows::Open",
    "source_file": "core/fpdfdoc",
    "source_line": 0,
    "source_description": "A function that accepts a filename from an untrusted source and passes it to CFX_FileAccess_Windows::Open",
    "input_type": "file path provided by user or external configuration",
    "entry_point": "A function that accepts a filename from an untrusted source and passes it to CFX_FileAccess_Windows::Open",
    "entry_point_file_hint": "core/fpdfdoc",
    "tainted_parameters": [
      "fileName"
    ],
    "exploitability": "high",
    "prerequisites": "The calling code must accept user-provided filenames and pass them to this function"
  },
  {
    "file": "core/fxcrt/cfx_fileaccess_windows.cpp",
    "line": 31,
    "category": "path_traversal",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-22",
    "description": "File open with non-literal path",
    "explanation": "gs_pPFModule is deleted and immediately set to nullptr. The context shows no further access to this pointer after deletion.",
    "attack_scenario": "An attacker supplies a malicious filename with path traversal sequences like '../' or '..\\'. This filename is passed through the call chain to CFX_FileAccess_Windows::Open, where it's converted from UTF8 to wide string and then used directly in CreateFileW. The vulnerability allows an attacker to access arbitrary files on the system by bypassing intended file access restrictions.",
    "enclosing_function": "if",
    "source_file": "core/fpdfdoc",
    "source_line": 0,
    "source_description": "A function that accepts a filename from an untrusted source and passes it to CFX_FileAccess_Windows::Open",
    "input_type": "file path provided by user or external configuration",
    "entry_point": "A function that accepts a filename from an untrusted source and passes it to CFX_FileAccess_Windows::Open",
    "entry_point_file_hint": "core/fpdfdoc",
    "tainted_parameters": [
      "fileName"
    ],
    "exploitability": "high",
    "prerequisites": "The calling code must accept user-provided filenames and pass them to this function"
  },
  {
    "file": "core/fxcrt/fx_memory.cpp",
    "line": 44,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "This is a test case that deletes an annotation object. The context shows this is part of a unit test, not actual runtime code execution.",
    "attack_scenario": "This sink is not directly reachable from external input. It's an internal alignment check used in memory management code and does not represent a real attack vector since it's not called with attacker-controlled data.",
    "enclosing_function": "IsAligned",
    "input_type": "N/A",
    "entry_point": "No external input reaches this sink directly; it's a utility function used internally.",
    "exploitability": "low",
    "prerequisites": "None - this function is not exposed to external input."
  },
  {
    "file": "core/fxcrt/fx_memory.h",
    "line": 101,
    "category": "integer_overflow",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-190",
    "description": "Heap allocation with arithmetic size",
    "explanation": "This is also a test case that deletes an attachment. The context shows this is part of a unit test, not actual runtime code execution.",
    "attack_scenario": "This is just a function declaration for FX_AlignedFree, not an actual implementation. It does not represent a real vulnerability since no code path leads to an integer overflow here.",
    "enclosing_function": "FX_AlignedFree",
    "input_type": "N/A",
    "entry_point": "No external input reaches this sink directly; it's a declaration only.",
    "exploitability": "low",
    "prerequisites": "None - this is a header-only declaration."
  },
  {
    "file": "core/fxcrt/fx_memory_malloc.cpp",
    "line": 44,
    "category": "integer_overflow",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-190",
    "description": "Heap allocation with arithmetic size",
    "explanation": "This is a test case that deletes pages from a document. The context shows this is part of a unit test, not actual runtime code execution.",
    "attack_scenario": "An attacker crafts a malformed media file with a specially crafted buffer size that, when passed to FX_TryRealloc through CFX_CodecMemory::TryResize, causes integer overflow during multiplication of num_members and member_size. This leads to an underflowed allocation size that can result in heap corruption or arbitrary code execution.",
    "enclosing_function": "Realloc",
    "source_file": "core/fxcodec/cfx_codec_memory.cpp",
    "source_line": 39,
    "source_description": "Caller chain top: CFX_CodecMemory::TryResize() — uint8_t* pNewBuf = FX_TryRealloc(uint8_t, pOldBuf, new_buffer_size);",
    "input_type": "User-controlled buffer resize request in media processing",
    "entry_point": "HTTP or file-based media data stream being processed by the codec memory manager",
    "entry_point_file_hint": "core/fxcodec/cfx_codec_memory.cpp",
    "tainted_parameters": [
      "new_buffer_size"
    ],
    "exploitability": "high",
    "prerequisites": "Media processing must be enabled and a user must open the crafted media file."
  },
  {
    "file": "core/fxcrt/fx_memory_pa.cpp",
    "line": 68,
    "category": "integer_overflow",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-190",
    "description": "Heap allocation with arithmetic size",
    "explanation": "This is a test case that deletes pages from a document. The context shows this is part of a unit test, not actual runtime code execution.",
    "attack_scenario": "An attacker crafts a malformed media file with a specially crafted buffer size that, when passed to FX_TryRealloc through CFX_CodecMemory::TryResize, causes integer overflow during multiplication of num_members and member_size. This leads to an underflowed allocation size that can result in heap corruption or arbitrary code execution.",
    "enclosing_function": "Realloc",
    "source_file": "core/fxcodec/cfx_codec_memory.cpp",
    "source_line": 39,
    "source_description": "Caller chain top: CFX_CodecMemory::TryResize() — uint8_t* pNewBuf = FX_TryRealloc(uint8_t, pOldBuf, new_buffer_size);",
    "input_type": "User-controlled buffer resize request in media processing",
    "entry_point": "HTTP or file-based media data stream being processed by the codec memory manager",
    "entry_point_file_hint": "core/fxcodec/cfx_codec_memory.cpp",
    "tainted_parameters": [
      "new_buffer_size"
    ],
    "exploitability": "high",
    "prerequisites": "Media processing must be enabled and a user must open the crafted media file."
  },
  {
    "file": "core/fxcrt/fx_memory_unittest.cpp",
    "line": 160,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "This is a test case that deletes pages from a document. The context shows this is part of a unit test, not actual runtime code execution.",
    "attack_scenario": "This is a unit test assertion that checks memory allocation behavior. It does not represent an actual vulnerability since it's only executed during testing and doesn't involve attacker-controlled data in production code paths.",
    "enclosing_function": "PA_BUILDFLAG",
    "source_file": "core/fxcrt/unowned_ptr.h",
    "source_line": 48,
    "source_description": "Caller chain top: () — #if !PA_BUILDFLAG(USE_PARTITION_ALLOC)",
    "input_type": "N/A",
    "entry_point": "No external input reaches this sink directly; it's part of a unit test.",
    "exploitability": "low",
    "prerequisites": "None - this is a test-only code path."
  },
  {
    "file": "core/fxcrt/fx_memory_unittest.cpp",
    "line": 163,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The delete occurs in FPDFPageObj_Destroy which is called explicitly by the user of the API. There's no subsequent use of the deleted object in the same function or nearby code paths. The pattern match is a false positive due to the explicit nature of the deletion and lack of reuse.",
    "attack_scenario": "An attacker who can control build configuration flags could manipulate the PA_BUILDFLAG(HAS_64_BIT_POINTERS) condition to bypass runtime checks. This would allow an attacker to force code paths that assume a certain pointer size, leading to incorrect memory layout assumptions and potential type confusion vulnerabilities when the actual pointer size differs from what's assumed at compile time.",
    "enclosing_function": "PA_BUILDFLAG",
    "source_file": "core/fxcrt/unowned_ptr.h",
    "source_line": 48,
    "source_description": "Caller chain top: () — #if !PA_BUILDFLAG(USE_PARTITION_ALLOC)",
    "input_type": "build configuration flags set at compile time",
    "entry_point": "Build configuration system that determines compile-time flags",
    "entry_point_file_hint": "core/fxcrt/unowned_ptr.h",
    "exploitability": "low",
    "prerequisites": "Ability to control build configuration flags during compilation of the PDF library"
  },
  {
    "file": "core/fxcrt/fx_memory_unittest.cpp",
    "line": 170,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The format string is a literal string with no user-controlled data. The printf call uses fixed format specifiers and only static values from function parameters, making it immune to format string vulnerabilities.",
    "attack_scenario": "An attacker who can control build configuration flags could manipulate the PA_BUILDFLAG(USE_PARTITION_ALLOC_AS_MALLOC) condition to bypass runtime checks. This would allow an attacker to force code paths that assume a certain memory allocation strategy, leading to incorrect memory layout assumptions and potential type confusion vulnerabilities when the actual allocation method differs from what's assumed at compile time.",
    "enclosing_function": "PA_BUILDFLAG",
    "source_file": "core/fxcrt/unowned_ptr.h",
    "source_line": 48,
    "source_description": "Caller chain top: () — #if !PA_BUILDFLAG(USE_PARTITION_ALLOC)",
    "input_type": "build configuration flags set at compile time",
    "entry_point": "Build configuration system that determines compile-time flags",
    "entry_point_file_hint": "core/fxcrt/unowned_ptr.h",
    "exploitability": "low",
    "prerequisites": "Ability to control build configuration flags during compilation of the PDF library"
  },
  {
    "file": "core/fxcrt/fx_memory_unittest.cpp",
    "line": 173,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The format string is a literal string with no user-controlled data. The printf call uses fixed format specifiers and only static values from function parameters, making it immune to format string vulnerabilities.",
    "attack_scenario": "An attacker who can control build configuration flags could manipulate the PA_BUILDFLAG(ENABLE_BACKUP_REF_PTR_SUPPORT) condition to bypass runtime checks. This would allow an attacker to force code paths that assume backup reference pointer support, leading to incorrect memory layout assumptions and potential type confusion vulnerabilities when the actual support status differs from what's assumed at compile time.",
    "enclosing_function": "PA_BUILDFLAG",
    "source_file": "core/fxcrt/unowned_ptr.h",
    "source_line": 48,
    "source_description": "Caller chain top: () — #if !PA_BUILDFLAG(USE_PARTITION_ALLOC)",
    "input_type": "build configuration flags set at compile time",
    "entry_point": "Build configuration system that determines compile-time flags",
    "entry_point_file_hint": "core/fxcrt/unowned_ptr.h",
    "exploitability": "low",
    "prerequisites": "Ability to control build configuration flags during compilation of the PDF library"
  },
  {
    "file": "core/fxcrt/fx_memory_unittest.cpp",
    "line": 181,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The format string is a literal string with no user-controlled data. The printf call uses fixed format specifiers and only static values from function parameters, making it immune to format string vulnerabilities.",
    "attack_scenario": "An attacker who can control build configuration flags could manipulate the PA_BUILDFLAG(USE_PARTITION_ALLOC_AS_MALLOC) and PA_BUILDFLAG(HAS_64_BIT_POINTERS) conditions to bypass runtime checks. This would allow an attacker to force code paths that assume specific memory allocation strategies and pointer sizes, leading to incorrect memory layout assumptions and potential type confusion vulnerabilities when the actual conditions differ from what's assumed at compile time.",
    "enclosing_function": "PA_BUILDFLAG",
    "source_file": "core/fxcrt/unowned_ptr.h",
    "source_line": 48,
    "source_description": "Caller chain top: () — #if !PA_BUILDFLAG(USE_PARTITION_ALLOC)",
    "input_type": "build configuration flags set at compile time",
    "entry_point": "Build configuration system that determines compile-time flags",
    "entry_point_file_hint": "core/fxcrt/unowned_ptr.h",
    "exploitability": "low",
    "prerequisites": "Ability to control build configuration flags during compilation of the PDF library"
  },
  {
    "file": "core/fxcrt/fx_memory_unittest.cpp",
    "line": 184,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The format string is a literal string with no user-controlled data. The printf call uses fixed format specifiers and only static values from function parameters, making it immune to format string vulnerabilities.",
    "attack_scenario": "An attacker who can control build configuration flags could manipulate the PA_BUILDFLAG(ENABLE_BACKUP_REF_PTR_SUPPORT) and PA_BUILDFLAG(HAS_64_BIT_POINTERS) conditions to bypass runtime checks. This would allow an attacker to force code paths that assume specific backup reference pointer support and pointer sizes, leading to incorrect memory layout assumptions and potential type confusion vulnerabilities when the actual conditions differ from what's assumed at compile time.",
    "enclosing_function": "PA_BUILDFLAG",
    "source_file": "core/fxcrt/unowned_ptr.h",
    "source_line": 48,
    "source_description": "Caller chain top: () — #if !PA_BUILDFLAG(USE_PARTITION_ALLOC)",
    "input_type": "build configuration flags set at compile time",
    "entry_point": "Build configuration system that determines compile-time flags",
    "entry_point_file_hint": "core/fxcrt/unowned_ptr.h",
    "exploitability": "low",
    "prerequisites": "Ability to control build configuration flags during compilation of the PDF library"
  },
  {
    "file": "core/fxcrt/fx_random.cpp",
    "line": 37,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The format string is a literal string with no user-controlled data. The printf call uses fixed format specifiers and only static values from function parameters, making it immune to format string vulnerabilities.",
    "attack_scenario": "An attacker could potentially manipulate the Windows CryptoAPI context or influence the environment in which CryptAcquireContext is called, possibly leading to a type confusion if the seed value is misinterpreted as another data type during subsequent operations. However, this sink itself does not directly accept external input.",
    "enclosing_function": "GenerateSeedFromCryptoRandom",
    "input_type": "cryptographic randomness source or system entropy",
    "entry_point": "System-level cryptographic API calls that are not directly user-controlled but may be influenced by environment state",
    "exploitability": "low",
    "prerequisites": "The system must be running on Windows with proper cryptographic provider installed and accessible."
  },
  {
    "file": "core/fxcrt/fx_random.cpp",
    "line": 45,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The delete occurs in RemovePageView which is called explicitly and the object is no longer used after that point. There's no subsequent use of the deleted object in the same function or nearby code paths.",
    "attack_scenario": "An attacker might attempt to control stack layout through memory manipulation techniques to influence the generated seed. This is a type confusion issue where the stack address interpretation could be misused in downstream code expecting a different data type.",
    "enclosing_function": "GenerateSeedFromEnvironment",
    "input_type": "stack memory address or environment entropy",
    "entry_point": "Stack-based entropy generation that relies on memory layout, not direct user input",
    "exploitability": "low",
    "prerequisites": "Requires ability to manipulate memory layout or environment state that affects stack addresses."
  },
  {
    "file": "core/fxcrt/mapped_data_bytes.cpp",
    "line": 28,
    "category": "path_traversal",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-22",
    "description": "File open with non-literal path",
    "explanation": "This is a unit test code snippet with no actual runtime execution path. The FORM_ReplaceSelection call is part of a test case and not part of the main application logic, so it's not a real use-after-free scenario.",
    "attack_scenario": "An attacker crafts a malicious file path string that includes directory traversal sequences like '../' to bypass intended file access restrictions. When the path is passed to open(), it could allow reading arbitrary files on the system, leading to path traversal vulnerability.",
    "enclosing_function": "",
    "source_file": "core/fxcrt/",
    "source_line": 0,
    "source_description": "File system access point where file paths are read from external sources such as config files, command-line arguments, or network requests",
    "input_type": "file path string from external configuration or user input",
    "entry_point": "File system access point where file paths are read from external sources such as config files, command-line arguments, or network requests",
    "entry_point_file_hint": "core/fxcrt/",
    "tainted_parameters": [
      "file_name"
    ],
    "exploitability": "high",
    "prerequisites": "The application must be processing user-provided file paths without proper sanitization or validation."
  },
  {
    "file": "core/fxcrt/css/cfx_cssdeclaration.cpp",
    "line": 191,
    "category": "xxe",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-611",
    "description": "XML parsing without disabling external entities",
    "explanation": "This is a unit test code snippet with no actual runtime execution path. The FORM_ReplaceSelection call is part of a test case and not part of the main application logic, so it's not a real use-after-free scenario.",
    "attack_scenario": "An attacker injects a malicious CSS string into a stylesheet that gets parsed by CFX_CSSDeclaration::ParseString. If the parsing logic doesn't properly validate or sanitize the input, it could lead to XXE (XML External Entity) processing where external resources are fetched or executed.",
    "enclosing_function": "switch",
    "source_file": "core/fxcrt/css/",
    "source_line": 0,
    "source_description": "CSS parser that processes external CSS input, typically from web pages or embedded stylesheets",
    "input_type": "CSS property value string from external stylesheet or web content",
    "entry_point": "CSS parser that processes external CSS input, typically from web pages or embedded stylesheets",
    "entry_point_file_hint": "core/fxcrt/css/",
    "tainted_parameters": [
      "value"
    ],
    "exploitability": "medium",
    "prerequisites": "CSS parsing must be enabled and external CSS content must be processed without strict validation."
  },
  {
    "file": "core/fxcrt/css/cfx_cssdeclaration.cpp",
    "line": 285,
    "category": "xxe",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-611",
    "description": "XML parsing without disabling external entities",
    "explanation": "This is a unit test code snippet with no actual runtime execution path. The FORM_ReplaceSelection call is part of a test case and not part of the main application logic, so it's not a real use-after-free scenario.",
    "attack_scenario": "An attacker provides a crafted CSS string value that triggers unsafe parsing behavior in ParseCSSString. If the parser fails to properly validate or escape the input, it could lead to XXE vulnerabilities where external entities are resolved or executed during CSS processing.",
    "enclosing_function": "CFX_CSSDeclaration::ParseString",
    "source_file": "core/fxcrt/css/",
    "source_line": 0,
    "source_description": "CSS string parsing module that processes CSS values from external sources like web pages or embedded stylesheets",
    "input_type": "WideStringView containing CSS string value from external stylesheet or web content",
    "entry_point": "CSS string parsing module that processes CSS values from external sources like web pages or embedded stylesheets",
    "entry_point_file_hint": "core/fxcrt/css/",
    "tainted_parameters": [
      "value"
    ],
    "exploitability": "medium",
    "prerequisites": "The application must be parsing external CSS content and not properly validating string inputs for malicious patterns."
  },
  {
    "file": "core/fxcrt/css/cfx_cssdeclaration.h",
    "line": 71,
    "category": "xxe",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-611",
    "description": "XML parsing without disabling external entities",
    "explanation": "This is a test case using Google Test framework. The delete operation happens in a test function that's not part of the actual code path, and there are no subsequent uses of the deleted object.",
    "attack_scenario": "An attacker crafts a malicious PDF file containing an inline CSS style that includes a crafted 'string' property value. When the PDF is parsed and processed by CFX_CSSStyleSelector, the ParseString function is invoked with this attacker-controlled data. The vulnerability lies in how the string is handled during CSS parsing, potentially leading to XXE (XML External Entity) processing if the parser does not properly sanitize external entity references.",
    "enclosing_function": "custom_begin",
    "source_file": "core/fxcrt/css/cfx_cssstyleselector.cpp",
    "source_line": 145,
    "source_description": "Caller chain top: if() — for (auto it = decl->custom_begin(); it != decl->custom_end(); it++) {",
    "input_type": "CSS style string parsed by PDF parser",
    "entry_point": "A CSS style string provided in a PDF document's inline styles or external stylesheet",
    "entry_point_file_hint": "core/fpdfdoc/cpdf_interactiveform.cpp",
    "exploitability": "medium",
    "prerequisites": "PDF document must be opened and parsed by a PDF viewer using this codebase"
  },
  {
    "file": "core/fxcrt/win/win_util.cc",
    "line": 20,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The function deletes the object and immediately returns, so there's no subsequent use of the deleted pointer. The delete is at the end of a function that returns void.",
    "attack_scenario": "An attacker crafts a PDF file with a font descriptor that specifies an ANSI charset. When the code path in CFX_Font::GetNativeFontName is executed, it calls IsUser32AndGdi32Available() which uses GetProcAddress to retrieve function pointers from kernel32.dll. If the system has certain mitigation policies enabled or if the attacker can manipulate the process environment, this could lead to type confusion by forcing incorrect reinterpretation of memory addresses.",
    "enclosing_function": "IsUser32AndGdi32Available",
    "source_file": "core/fpdfdoc/cpdf_interactiveform.cpp",
    "source_line": 105,
    "source_description": "Caller chain top: if() — if (!pdfium::IsUser32AndGdi32Available()) {",
    "input_type": "Font charset parameter passed from PDF document parsing",
    "entry_point": "A font charset value extracted from a PDF document's font descriptor or embedded font data",
    "entry_point_file_hint": "core/fpdfdoc/cpdf_interactiveform.cpp",
    "tainted_parameters": [
      "charset"
    ],
    "exploitability": "low",
    "prerequisites": "PDF document must contain a font with ANSI charset and system must be in a vulnerable state where GetProcAddress behavior can be manipulated"
  },
  {
    "file": "core/fxge/cfx_folderfontinfo.cpp",
    "line": 189,
    "category": "path_traversal",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-22",
    "description": "File open with non-literal path",
    "explanation": "The object is deleted in a function that returns void and there are no subsequent uses. The deletion happens before the function ends.",
    "attack_scenario": "An attacker crafts a PDF with a malformed font path that includes directory traversal sequences (e.g., '../') in the font file name. When the CFX_FolderFontInfo::ScanFile function is called to process this font, it directly passes the attacker-controlled path to fopen(), enabling path traversal and potentially allowing access to arbitrary files on the system.",
    "enclosing_function": "CFX_FolderFontInfo::ScanFile",
    "source_file": "core/fxge/cfx_folderfontinfo.cpp",
    "source_line": 0,
    "source_description": "A font file path extracted from the PDF's font catalog or embedded font resources",
    "input_type": "Font file path from PDF font catalog or embedded font data",
    "entry_point": "A font file path extracted from the PDF's font catalog or embedded font resources",
    "entry_point_file_hint": "core/fxge/cfx_folderfontinfo.cpp",
    "tainted_parameters": [
      "path"
    ],
    "exploitability": "high",
    "prerequisites": "PDF document must be opened and parsed by a PDF viewer using this codebase"
  },
  {
    "file": "core/fxge/cfx_folderfontinfo.cpp",
    "line": 440,
    "category": "path_traversal",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-22",
    "description": "File open with non-literal path",
    "explanation": "This is a deliberately leaked static object that's meant to persist for the lifetime of the program. No deletion occurs in this function.",
    "attack_scenario": "An attacker crafts a malformed PDF with corrupted font table metadata that specifies an invalid file path in font->file_path_.c_str(). When the code attempts to open this file using fopen(), it will use the attacker-controlled path, potentially enabling path traversal or access to arbitrary files on the system. The vulnerability is in the lack of validation of the font file path before being passed to fopen.",
    "enclosing_function": "for",
    "source_file": "core/fxge/cfx_folderfontinfo.cpp",
    "source_line": 0,
    "source_description": "Font table data extracted from embedded or external font files referenced in PDF document",
    "input_type": "Font table offset and size from PDF font data structures",
    "entry_point": "Font table data extracted from embedded or external font files referenced in PDF document",
    "entry_point_file_hint": "core/fxge/cfx_folderfontinfo.cpp",
    "exploitability": "high",
    "prerequisites": "PDF document must be opened and parsed by a PDF viewer using this codebase"
  },
  {
    "file": "core/fxge/cfx_fontmapper_unittest.cpp",
    "line": 131,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "This is a test case using UNSAFE_TODO macro. The strcpy is used for testing purposes and the buffer size is checked by the API call that follows.",
    "attack_scenario": "This is a unit test sink and not reachable from external input. The reinterpret_cast<void*>(12345) is used to simulate a font handle in a mock system for testing purposes. This is not exploitable in production code as it's only used in unit tests.",
    "enclosing_function": "SetUp",
    "source_file": "core/fpdfapi/page/test_with_page_module.h",
    "source_line": 12,
    "source_description": "Caller chain top: () — void SetUp() override;",
    "input_type": "Test fixture setup data for unit testing",
    "entry_point": "Unit test setup code that initializes mock font handles for testing purposes",
    "entry_point_file_hint": "core/fxge/cfx_fontmapper_unittest.cpp",
    "exploitability": "low",
    "prerequisites": "Only relevant during unit test execution"
  },
  {
    "file": "core/fxge/cfx_fontmapper_unittest.cpp",
    "line": 159,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The SaveData function call is followed by a check for pObserved being null. If it's deleted during SaveData, the subsequent checks will prevent use-after-free.",
    "attack_scenario": "",
    "enclosing_function": ""
  },
  {
    "file": "core/fxge/cfx_fontmapper_unittest.cpp",
    "line": 174,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The DeletePage function deletes an object and returns immediately. There's no subsequent use of the deleted object in this function.",
    "attack_scenario": "",
    "enclosing_function": ""
  },
  {
    "file": "core/fxge/cfx_fontmapper_unittest.cpp",
    "line": 192,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "This is a switch statement in an event handler. The delete key case returns false but doesn't actually delete anything.",
    "attack_scenario": "",
    "enclosing_function": ""
  },
  {
    "file": "core/fxge/cfx_fontmapper_unittest.cpp",
    "line": 214,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "This is a test case for delete key handling. The OnChar call is expected to return false and not cause any deletion.",
    "attack_scenario": "",
    "enclosing_function": ""
  },
  {
    "file": "core/fxge/cfx_fontmapper_unittest.cpp",
    "line": 234,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "This is a test case for delete key handling. The OnChar call is expected to return false and not cause any deletion.",
    "attack_scenario": "",
    "enclosing_function": ""
  },
  {
    "file": "core/fxge/apple/fx_quartz_device.cpp",
    "line": 74,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The pointer pSharedCaptureFocusState is deleted and not used afterwards. The code properly sets the pointer to nullptr after deletion, and there are no subsequent uses of the deleted object in the function scope.",
    "attack_scenario": "",
    "enclosing_function": "if"
  },
  {
    "file": "core/fxge/apple/fx_quartz_device.cpp",
    "line": 112,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The g_symbols array elements are deleted in a loop and then set to nullptr. There is no subsequent use of these pointers after deletion, and the function is a static Finalize function that's meant to clean up global state.",
    "attack_scenario": "",
    "enclosing_function": "if"
  },
  {
    "file": "core/fxge/dib/cfx_dibbase.cpp",
    "line": 933,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The global pointer g_QRCodeField is deleted and then set to nullptr. The code is a static Finalize function meant for cleanup, and there are no subsequent uses of the deleted object.",
    "attack_scenario": "",
    "enclosing_function": "if"
  },
  {
    "file": "core/fxge/win32/cgdi_device_driver.cpp",
    "line": 105,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The static pointers L, M, Q, H are deleted and set to nullptr. This is part of a Finalize function for cleanup, and there are no subsequent uses of these objects in the scope.",
    "attack_scenario": "",
    "enclosing_function": "if"
  },
  {
    "file": "core/fxge/win32/cgdi_device_driver.cpp",
    "line": 170,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The static pointer M is deleted and set to nullptr. This is part of a Finalize function for cleanup, and there are no subsequent uses of this object in the scope.",
    "attack_scenario": "",
    "enclosing_function": "if"
  },
  {
    "file": "core/fxge/win32/cgdi_device_driver.cpp",
    "line": 430,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The static pointer Q is deleted and set to nullptr. This is part of a Finalize function for cleanup, and there are no subsequent uses of this object in the scope.",
    "attack_scenario": "",
    "enclosing_function": "if"
  },
  {
    "file": "core/fxge/win32/cgdi_device_driver.cpp",
    "line": 439,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The static pointer H is deleted and set to nullptr. This is part of a Finalize function for cleanup, and there are no subsequent uses of this object in the scope.",
    "attack_scenario": "",
    "enclosing_function": "if"
  },
  {
    "file": "core/fxge/win32/cgdi_device_driver.cpp",
    "line": 449,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The static pointers sBYTE, sALPHANUMERIC, sNUMERIC are deleted and set to nullptr. This is part of a Finalize function for cleanup, and there are no subsequent uses of these objects in the scope.",
    "attack_scenario": "",
    "enclosing_function": "if"
  },
  {
    "file": "core/fxge/win32/cgdi_device_driver.cpp",
    "line": 454,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The static pointer sALPHANUMERIC is deleted and set to nullptr. This is part of a Finalize function for cleanup, and there are no subsequent uses of this object in the scope.",
    "attack_scenario": "",
    "enclosing_function": "if"
  },
  {
    "file": "core/fxge/win32/cgdi_device_driver.cpp",
    "line": 491,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The static pointer sNUMERIC is deleted and set to nullptr. This is part of a Finalize function for cleanup, and there are no subsequent uses of this object in the scope.",
    "attack_scenario": "",
    "enclosing_function": "if"
  },
  {
    "file": "core/fxge/win32/cgdi_device_driver.cpp",
    "line": 495,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The code deletes g_VERSION and immediately sets it to nullptr. There are no subsequent uses of g_VERSION after this deletion in the provided context.",
    "attack_scenario": "",
    "enclosing_function": "if"
  },
  {
    "file": "core/fxge/win32/cgdi_device_driver.cpp",
    "line": 566,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The code deletes g_DefaultGlobalObjectTemplate and immediately sets it to nullptr. There are no subsequent uses of this pointer after the deletion in the provided context.",
    "attack_scenario": "",
    "enclosing_function": "CGdiDeviceDriver::GetClipBox"
  },
  {
    "file": "core/fxge/win32/cgdi_device_driver.cpp",
    "line": 730,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The code deletes g_arrayBufferAllocator and immediately sets it to nullptr. There are no subsequent uses of this pointer after the deletion in the provided context.",
    "attack_scenario": "",
    "enclosing_function": "if"
  },
  {
    "file": "core/fxge/win32/cgdi_plus_ext.cpp",
    "line": 184,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The code deletes pData which is retrieved from a local variable. There are no subsequent uses of the deleted pointer in the provided context.",
    "attack_scenario": "",
    "enclosing_function": ""
  },
  {
    "file": "core/fxge/win32/cgdi_plus_ext.cpp",
    "line": 435,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The code deletes pIsolateData which is a local variable. There are no subsequent uses of the deleted pointer in the provided context.",
    "attack_scenario": "",
    "enclosing_function": "if"
  },
  {
    "file": "core/fxge/win32/cps_printer_driver.cpp",
    "line": 76,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "This is a test case that executes JavaScript code. It's not actual SQL injection - it's just testing error handling for invalid JS syntax.",
    "attack_scenario": "An attacker crafts a PDF file that, when rendered, causes the PDF renderer to call Windows GDI functions like ::GetClipRgn and ::GetRegionData with maliciously constructed region data. The buffer allocated by the renderer is then interpreted as RGNDATA structure via reinterpret_cast, leading to type confusion. This allows an attacker to control memory layout and potentially execute arbitrary code through crafted region data.",
    "enclosing_function": "if",
    "source_file": "core/fxge/win32/cps_printer_driver.cpp",
    "source_line": 0,
    "source_description": "Windows GDI API calls from PDF rendering context that manipulate device context clip regions",
    "input_type": "Windows GDI API calls with malformed region data",
    "entry_point": "Windows GDI API calls from PDF rendering context that manipulate device context clip regions",
    "entry_point_file_hint": "core/fxge/win32/cps_printer_driver.cpp",
    "exploitability": "high",
    "prerequisites": "PDF rendering must be enabled and a PDF with maliciously crafted clip regions must be processed"
  },
  {
    "file": "fpdfsdk/cpdfsdk_helpers.cpp",
    "line": 206,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "This is a test case that executes JavaScript code. It's not actual SQL injection - it's just testing error handling for invalid JS syntax.",
    "attack_scenario": "An attacker crafts a PDF file with maliciously constructed page objects. When the PDF is parsed and an FPDF_PAGE handle is returned to the SDK, it gets passed through IPDFPageFromFPDFPage which performs a dangerous reinterpret_cast on the handle. This allows an attacker to manipulate the type of the page object, potentially leading to memory corruption or code execution when the SDK later uses this handle.",
    "enclosing_function": "IPDFPageFromFPDFPage",
    "source_file": "fpdfsdk/cpdfsdk_baannot_embeddertest.cpp",
    "source_line": 37,
    "source_description": "Caller chain top: if() — form_fill_env_->GetOrCreatePageView(IPDFPageFromFPDFPage(page.get()));",
    "input_type": "FPDF_PAGE handle from PDF document parsing",
    "entry_point": "PDF document parsing APIs that return FPDF_PAGE handles to SDK clients",
    "entry_point_file_hint": "fpdfsdk/cpdfsdk_baannot_embeddertest.cpp",
    "tainted_parameters": [
      "page"
    ],
    "exploitability": "medium",
    "prerequisites": "PDF parsing must be enabled and SDK must process FPDF_PAGE handles from untrusted PDFs"
  },
  {
    "file": "fpdfsdk/cpdfsdk_helpers.cpp",
    "line": 210,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The code deletes g_pInstance and immediately sets it to nullptr. There are no subsequent uses of g_pInstance after this deletion in the provided context.",
    "attack_scenario": "An attacker crafts a PDF with maliciously constructed form fields. When the SDK processes these fields and calls GetPage() on a widget, it returns an FPDF_PAGE handle that gets passed to FPDFPageFromIPDFPage. The dangerous reinterpret_cast allows an attacker to manipulate the type of the page object, potentially leading to memory corruption or code execution when the SDK later uses this handle.",
    "enclosing_function": "FPDFPageFromIPDFPage",
    "source_file": "fpdfsdk/cpdfsdk_formfillenvironment.cpp",
    "source_line": 118,
    "source_description": "Caller chain top: if() — auto* pPage = FPDFPageFromIPDFPage(pFormField->GetSDKWidget()->GetPage());",
    "input_type": "FPDF_PAGE handle from form field processing",
    "entry_point": "Form field processing APIs that return FPDF_PAGE handles to SDK clients",
    "entry_point_file_hint": "fpdfsdk/cpdfsdk_formfillenvironment.cpp",
    "tainted_parameters": [
      "page"
    ],
    "exploitability": "medium",
    "prerequisites": "Form field processing must be enabled and SDK must process FPDF_PAGE handles from untrusted PDFs"
  },
  {
    "file": "fpdfsdk/cpdfsdk_helpers.cpp",
    "line": 214,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "This is a wrapper function that delegates the Free operation to another allocator. The actual deletion happens in wrapped_->Free(data, length), not directly in this function.",
    "attack_scenario": "An attacker crafts a PDF file with maliciously constructed document objects. When the PDF is parsed and an FPDF_DOCUMENT handle is returned to the SDK, it gets passed through CPDFDocumentFromFPDFDocument which performs a dangerous reinterpret_cast on the handle. This allows an attacker to manipulate the type of the document object, potentially leading to memory corruption or code execution when the SDK later uses this handle.",
    "enclosing_function": "CPDFDocumentFromFPDFDocument",
    "source_file": "core/fpdfapi/edit/cpdf_fontsubsetter_embeddertest.cpp",
    "source_line": 51,
    "source_description": "Caller chain top: CPDFDocumentFromFPDFDocument() — CPDF_Document* CPDFDocumentFromFPDFDocument(FPDF_DOCUMENT document) {",
    "input_type": "FPDF_DOCUMENT handle from PDF document parsing",
    "entry_point": "PDF document parsing APIs that return FPDF_DOCUMENT handles to SDK clients",
    "entry_point_file_hint": "core/fpdfapi/edit/cpdf_fontsubsetter_embeddertest.cpp",
    "tainted_parameters": [
      "document"
    ],
    "exploitability": "medium",
    "prerequisites": "PDF parsing must be enabled and SDK must process FPDF_DOCUMENT handles from untrusted PDFs"
  },
  {
    "file": "fpdfsdk/cpdfsdk_helpers.cpp",
    "line": 218,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "This is a wrapper function that delegates the Free operation to another allocator. The actual deletion happens in wrapped_->Free(data, length), not directly in this function.",
    "attack_scenario": "An attacker crafts a PDF file with maliciously constructed document objects. When the SDK processes form fields and calls GetCurrentPage(), it returns an IPDF_Page* that gets passed through FPDFDocumentFromCPDFDocument which performs a dangerous reinterpret_cast on the CPDF_Document pointer. This allows an attacker to manipulate the type of the document object, potentially leading to memory corruption or code execution when the SDK later uses this handle.",
    "enclosing_function": "FPDFDocumentFromCPDFDocument",
    "source_file": "fpdfsdk/cpdfsdk_formfillenvironment.cpp",
    "source_line": 140,
    "source_description": "Caller chain top: if() — info_, FPDFDocumentFromCPDFDocument(cpdfdoc_)));",
    "input_type": "CPDF_Document* pointer from SDK internal state",
    "entry_point": "SDK internal APIs that return CPDF_Document pointers to form fill environment",
    "entry_point_file_hint": "fpdfsdk/cpdfsdk_formfillenvironment.cpp",
    "tainted_parameters": [
      "doc"
    ],
    "exploitability": "medium",
    "prerequisites": "Form field processing must be enabled and SDK must process document objects from untrusted PDFs"
  },
  {
    "file": "fpdfsdk/cpdfsdk_helpers.cpp",
    "line": 273,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "This is a V8 ArrayBuffer allocator's Free method. The pattern match is a false positive because the code doesn't actually use the freed memory, and there are no subsequent accesses of the 'data' pointer after freeing.",
    "attack_scenario": "An attacker crafts a malformed PDF file containing an XObject with a specially crafted wide string that bypasses the NUL-termination precondition. When FPDF_CloseXObject is called on this object, it eventually leads to WideStringFromFPDFWideString which interprets the invalid wide string as a byte span, causing type confusion between FPDF_WIDESTRING and uint8_t*. This can lead to memory corruption or arbitrary code execution if the attacker controls the data layout.",
    "enclosing_function": "WideStringFromFPDFWideString",
    "source_file": "fpdfsdk/fpdf_ppo_embeddertest.cpp",
    "source_line": 203,
    "source_description": "Caller chain top: for() — FPDF_CloseXObject(xobject);",
    "input_type": "malformed PDF XObject with invalid wide string data",
    "entry_point": "PDF parsing layer where external PDF data is processed into FPDF_XOBJECT structures",
    "entry_point_file_hint": "fpdfsdk/fpdf_ppo_embeddertest.cpp",
    "tainted_parameters": [
      "wide_string"
    ],
    "exploitability": "high",
    "prerequisites": "PDF file must be opened with a PDF parser that allows malformed XObjects to be created"
  },
  {
    "file": "fpdfsdk/fpdf_dataavail.cpp",
    "line": 142,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "This is just a function declaration in the header file. It's not actual code execution, and no printf call occurs here.",
    "attack_scenario": "An attacker creates a malicious FPDF_AVAIL object that points to an invalid memory location. When passed to FPDFAvailContextFromFPDFAvail, the reinterpret_cast treats this invalid handle as a pointer to FPDF_AvailContext, leading to type confusion. If the attacker controls the memory layout, they can cause arbitrary reads/writes by dereferencing the misinterpreted pointer.",
    "enclosing_function": "FPDFAvailContextFromFPDFAvail",
    "source_file": "fpdfsdk/fpdf_dataavail.cpp",
    "source_line": 0,
    "source_description": "PDF data availability API layer where external PDF data is checked for completeness",
    "input_type": "FPDF_AVAIL handle from PDF availability checking APIs",
    "entry_point": "PDF data availability API layer where external PDF data is checked for completeness",
    "entry_point_file_hint": "fpdfsdk/fpdf_dataavail.cpp",
    "tainted_parameters": [
      "avail"
    ],
    "exploitability": "high",
    "prerequisites": "API must be called with an invalid or crafted FPDF_AVAIL handle"
  },
  {
    "file": "fpdfsdk/fpdf_dataavail.cpp",
    "line": 146,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "The delete occurs at the end of DestroyGlobals() and is immediately followed by setting g_global_timer_map to nullptr. There are no subsequent uses of the deleted pointer.",
    "attack_scenario": "An attacker creates a malicious FPDF_AvailContext object and passes it to FPDFAvailFromFPDFAvailContext. The reinterpret_cast treats this context as an FPDF_AVAIL handle, causing type confusion when the handle is later used in other APIs. This can lead to memory corruption or information disclosure if the attacker controls the memory layout.",
    "enclosing_function": "FPDFAvailFromFPDFAvailContext",
    "source_file": "fpdfsdk/fpdf_dataavail.cpp",
    "source_line": 0,
    "source_description": "PDF data availability API layer where external PDF data is checked for completeness",
    "input_type": "FPDF_AvailContext pointer from PDF availability checking APIs",
    "entry_point": "PDF data availability API layer where external PDF data is checked for completeness",
    "entry_point_file_hint": "fpdfsdk/fpdf_dataavail.cpp",
    "tainted_parameters": [
      "pAvailContext"
    ],
    "exploitability": "high",
    "prerequisites": "API must be called with a crafted FPDF_AvailContext pointer"
  },
  {
    "file": "fpdfsdk/fpdf_edittext.cpp",
    "line": 337,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "This delete occurs in a deleter function for a cppgc::Heap object. The heap is being destroyed and deleted as part of normal cleanup, with no subsequent access to the deleted pointer.",
    "attack_scenario": "An attacker supplies a malicious CFX_Path object to FPDFGlyphPathFromCFXPath. The reinterpret_cast treats this path as an FPDF_GLYPHPATH handle, causing type confusion. If the attacker can control the memory layout of the CFX_Path object, they may be able to perform arbitrary reads/writes by dereferencing the misinterpreted pointer in subsequent API calls.",
    "enclosing_function": "FPDFGlyphPathFromCFXPath",
    "source_file": "fpdfsdk/fpdf_edittext.cpp",
    "source_line": 0,
    "source_description": "PDF text editing API layer where glyph paths are manipulated",
    "input_type": "CFX_Path object from PDF text rendering APIs",
    "entry_point": "PDF text editing API layer where glyph paths are manipulated",
    "entry_point_file_hint": "fpdfsdk/fpdf_edittext.cpp",
    "tainted_parameters": [
      "path"
    ],
    "exploitability": "high",
    "prerequisites": "API must be called with a crafted CFX_Path object"
  },
  {
    "file": "xfa/fde/cfde_texteditengine.cpp",
    "line": 165,
    "category": "buffer_overflow",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-120",
    "description": "Explicitly marked UNSAFE memory operation",
    "explanation": "This is a test case using Execute() with a string literal. It's not executing SQL, but rather testing JavaScript form calculation functionality.",
    "attack_scenario": "An attacker provides malicious text input that causes the AdjustGap function to be called with invalid indices. The FXSYS_memmove call at line 165 can then overwrite memory beyond intended bounds due to improper bounds checking, leading to a buffer overflow and potential code execution.",
    "enclosing_function": "if",
    "source_file": "xfa/fde/cfde_texteditengine.cpp",
    "source_line": 0,
    "source_description": "XFA text edit engine handling user input or document content",
    "input_type": "malformed text input or editing operations in XFA forms",
    "entry_point": "XFA text edit engine handling user input or document content",
    "entry_point_file_hint": "xfa/fde/cfde_texteditengine.cpp",
    "exploitability": "high",
    "prerequisites": "XFA form processing must be enabled and user input must be processed through the text edit engine"
  },
  {
    "file": "xfa/fde/cfde_texteditengine.cpp",
    "line": 170,
    "category": "buffer_overflow",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-120",
    "description": "Explicitly marked UNSAFE memory operation",
    "explanation": "This is a test case using Execute() with a string literal. It's not executing SQL, but rather testing JavaScript form calculation functionality.",
    "attack_scenario": "An attacker provides malicious text input that causes the AdjustGap function to be called with invalid indices. The FXSYS_memmove call at line 170 can then overwrite memory beyond intended bounds due to improper bounds checking, leading to a buffer overflow and potential code execution.",
    "enclosing_function": "if",
    "source_file": "xfa/fde/cfde_texteditengine.cpp",
    "source_line": 0,
    "source_description": "XFA text edit engine handling user input or document content",
    "input_type": "malformed text input or editing operations in XFA forms",
    "entry_point": "XFA text edit engine handling user input or document content",
    "entry_point_file_hint": "xfa/fde/cfde_texteditengine.cpp",
    "exploitability": "high",
    "prerequisites": "XFA form processing must be enabled and user input must be processed through the text edit engine"
  },
  {
    "file": "xfa/fde/cfde_texteditengine.cpp",
    "line": 181,
    "category": "buffer_overflow",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-120",
    "description": "Explicitly marked UNSAFE memory operation",
    "explanation": "This is a test case using Execute() with a string literal. It's not executing SQL, but rather testing JavaScript form calculation functionality.",
    "attack_scenario": "An attacker provides malicious text input that causes the AdjustGap function to be called with invalid indices and large length parameters. The FXSYS_memmove call at line 181 can then overwrite memory beyond intended bounds due to improper bounds checking, leading to a buffer overflow and potential code execution.",
    "enclosing_function": "if",
    "source_file": "xfa/fde/cfde_texteditengine.cpp",
    "source_line": 0,
    "source_description": "XFA text edit engine handling user input or document content",
    "input_type": "malformed text input or editing operations in XFA forms",
    "entry_point": "XFA text edit engine handling user input or document content",
    "entry_point_file_hint": "xfa/fde/cfde_texteditengine.cpp",
    "exploitability": "high",
    "prerequisites": "XFA form processing must be enabled and user input must be processed through the text edit engine"
  },
  {
    "file": "xfa/fgas/font/cfgas_fontmgr.cpp",
    "line": 194,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "This is a test case using EXPECT_TRUE(Execute(...)) with hardcoded string literals. No dynamic data is involved in SQL query construction.",
    "attack_scenario": "An attacker crafts a malformed hex string in the test case that gets passed to HexToBytes, which then feeds it into CRYPT_MD5Generate. The MD5 function uses pdfium::byte_span_from_ref on this data, and if the data is not properly validated, it could lead to type confusion when the byte span is interpreted as a different type elsewhere in the codebase.",
    "enclosing_function": "pdfium::byte_span_from_ref",
    "source_file": "core/fdrm/fx_crypt_unittest.cpp",
    "source_line": 73,
    "source_description": "Caller chain top: HexToBytes() — CRYPT_MD5Generate(pdfium::byte_span_from_ref(c), digest);",
    "input_type": "string literal or byte sequence",
    "entry_point": "Test harness input via HexToBytes function",
    "entry_point_file_hint": "core/fdrm/fx_crypt_unittest.cpp",
    "exploitability": "low",
    "prerequisites": "Test environment must be running with unit tests enabled"
  },
  {
    "file": "xfa/fxfa/parser/cxfa_node.cpp",
    "line": 2190,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "This is a test case using EXPECT_TRUE(Execute(...)) with hardcoded string literals. No dynamic data is involved in SQL query construction.",
    "attack_scenario": "An attacker crafts an XFA form with a malformed attribute that gets parsed by GetDefaultValue. The returned void* value is then cast to uintptr_t and interpreted as an integer, leading to type confusion if the original data was not of the expected type (e.g., a pointer instead of an integer).",
    "enclosing_function": "CXFA_Node::GetDefaultInteger",
    "source_file": "xfa/fxfa/parser/cxfa_node.cpp",
    "source_line": 0,
    "source_description": "XML parser in XFA subsystem processing node attributes",
    "input_type": "XFA attribute value from XML parsing",
    "entry_point": "XML parser in XFA subsystem processing node attributes",
    "entry_point_file_hint": "xfa/fxfa/parser/cxfa_node.cpp",
    "exploitability": "medium",
    "prerequisites": "XFA form processing must be enabled and attacker must control XML input"
  },
  {
    "file": "xfa/fxfa/parser/cxfa_node.cpp",
    "line": 2221,
    "category": "type_confusion",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-843",
    "description": "reinterpret_cast — unchecked type conversion",
    "explanation": "This is a test case using EXPECT_TRUE(Execute(...)) with hardcoded string literals. No dynamic data is involved in SQL query construction.",
    "attack_scenario": "An attacker crafts an XFA form with a malformed enum attribute that gets parsed by GetDefaultValue. The returned void* value is then cast to uintptr_t and interpreted as an enum value, leading to type confusion if the original data was not of the expected type (e.g., a pointer instead of an enum).",
    "enclosing_function": "CXFA_Node::GetDefaultCData",
    "source_file": "xfa/fxfa/parser/cxfa_node.cpp",
    "source_line": 0,
    "source_description": "XML parser in XFA subsystem processing node attributes",
    "input_type": "XFA attribute value from XML parsing",
    "entry_point": "XML parser in XFA subsystem processing node attributes",
    "entry_point_file_hint": "xfa/fxfa/parser/cxfa_node.cpp",
    "exploitability": "medium",
    "prerequisites": "XFA form processing must be enabled and attacker must control XML input"
  },
  {
    "file": "core/fxcodec/png/libpng_png_decoder.cpp",
    "line": 52,
    "category": "buffer_overflow",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-170",
    "description": "strncpy may not null-terminate",
    "explanation": "This is a test case using EXPECT_TRUE(Execute(...)) with hardcoded string literals. No dynamic data is involved in SQL query construction.",
    "attack_scenario": "An attacker provides a malformed PNG file that triggers an error condition in the PNG decoder. The _png_error_data function is called with attacker-controlled error_msg, which gets copied into a fixed-size buffer using strncpy without proper bounds checking, potentially causing a buffer overflow if the error message exceeds PNG_ERROR_SIZE - 1 bytes.",
    "enclosing_function": "_png_error_data",
    "source_file": "core/fxcodec/png/libpng_png_decoder.cpp",
    "source_line": 0,
    "source_description": "PNG decoder in fxcodec module handling corrupted or invalid PNG files",
    "input_type": "PNG error message string from PNG decoder",
    "entry_point": "PNG decoder in fxcodec module handling corrupted or invalid PNG files",
    "entry_point_file_hint": "core/fxcodec/png/libpng_png_decoder.cpp",
    "tainted_parameters": [
      "error_msg"
    ],
    "exploitability": "high",
    "prerequisites": "PNG decoder must be processing a malformed file and error handling path must be triggered"
  },
  {
    "file": "core/fxcodec/tiff/tiff_decoder.cpp",
    "line": 100,
    "category": "crypto_weakness",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-327",
    "description": "Weak cipher or mode (ECB/DES/RC4)",
    "explanation": "This is a test case using EXPECT_TRUE(Execute(...)) with hardcoded string literals. No dynamic data is involved in SQL query construction.",
    "attack_scenario": "An attacker provides a malformed TIFF file where the size parameter in _TIFFmemcpy is manipulated to exceed the bounds of the destination buffer. The UNSAFE_TODO macro allows direct memory copy without validation, leading to potential memory corruption or information disclosure when data is copied from source to destination with incorrect size parameters.",
    "enclosing_function": "_TIFFmemcpy",
    "source_file": "core/fxcodec/tiff/tiff_decoder.cpp",
    "source_line": 0,
    "source_description": "TIFF decoder in fxcodec module reading and copying image data",
    "input_type": "TIFF image data from TIFF file parsing",
    "entry_point": "TIFF decoder in fxcodec module reading and copying image data",
    "entry_point_file_hint": "core/fxcodec/tiff/tiff_decoder.cpp",
    "tainted_parameters": [
      "des",
      "src",
      "size"
    ],
    "exploitability": "high",
    "prerequisites": "TIFF decoder must be processing a malformed file and _TIFFmemcpy must be called with attacker-controlled parameters"
  },
  {
    "file": "fpdfsdk/fpdf_sysfontinfo.cpp",
    "line": 256,
    "category": "buffer_overflow",
    "severity": "low",
    "confidence": "high",
    "cwe": "CWE-170",
    "description": "strncpy may not null-terminate",
    "explanation": "This is a test case using EXPECT_TRUE(Execute(...)) with hardcoded string literals. No dynamic data is involved in SQL query construction.",
    "attack_scenario": "An attacker crafts a malicious PDF file containing a malformed font table with an oversized face name field. When the PDF is opened and the system attempts to retrieve font information through the FPDF_SYSFONTINFO interface, the GetFaceName method populates the name ByteString with data exceeding the buffer size. The unsafe strncpy operation then copies this oversized string into the attacker-controlled buffer, causing a buffer overflow. This could allow an attacker to execute arbitrary code when the PDF is rendered or processed.",
    "enclosing_function": "if",
    "source_file": "fpdf_parser.cpp or similar PDF parsing module",
    "source_line": 0,
    "source_description": "PDF parser subsystem that processes embedded font resources in PDF documents",
    "input_type": "font data from PDF files (specifically font table data)",
    "entry_point": "PDF parser subsystem that processes embedded font resources in PDF documents",
    "entry_point_file_hint": "fpdf_parser.cpp or similar PDF parsing module",
    "tainted_parameters": [
      "buffer",
      "name"
    ],
    "exploitability": "medium",
    "prerequisites": "PDF rendering must be enabled and the system must attempt to access font information from embedded fonts in the malicious PDF"
  }
]

======================


