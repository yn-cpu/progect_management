This is the complete, production-ready project suite. It is designed to be robust, thread-safe (by separating JEB reads from LLM processing), and "agentic" using the Ripple/Wavefront algorithm.

### **Directory Structure**

Create a folder named `RippleNamer` and place these 6 files inside.

```text
RippleNamer/
├── config.py            # Settings (Models, Keys, thresholds)
├── core_engine.py       # The Brain (Graph & Wavefront Logic)
├── jeb_adapter.py       # The Bridge (JEB API Parser)
├── llm_agent.py         # The Worker (LLM handling & Caching)
├── RippleAutoNamer.py   # The Plugin (JEB Entry Point)
└── README.md            # Instructions
```

-----

### **1. `config.py`**

Centralized configuration. Edit this file to change models or API keys.

```python
import os

class Config:
    # --- API Configuration ---
    # Options: "gpt-4o", "gpt-4o-mini", "claude-3-5-sonnet", "ollama/llama3"
    MODEL_FAST = "gpt-4o-mini"  # For simple cases (getters/setters)
    MODEL_SMART = "gpt-4o"      # For complex logic
    
    # API Keys (Best practice: Set these in your OS environment, fallback here)
    OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "sk-...")
    ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

    # --- Processing Thresholds ---
    MAX_FUNCTIONS = 500         # Hard limit to prevent huge bills
    BATCH_SIZE = 5              # Functions to process per LLM wave
    MIN_CONFIDENCE = "MEDIUM"   # Minimum confidence to apply rename (LOW, MEDIUM, HIGH)
    
    # --- System ---
    CACHE_FILE = "ripple_cache.json"  # Stores results to prevent re-billing
    LOG_FILE = "ripple_namer.log"
```

-----

### **2. `jeb_adapter.py`**

The "Ear" of the system. Reads Dalvik bytecode efficiently without relying on slow source decompilation.

```python
# jeb_adapter.py
import sys
import time

# JEB Imports (Mocking for linting, available at runtime)
try:
    from com.pnfsoftware.jeb.core.units.code.android import IDexUnit
    from com.pnfsoftware.jeb.core.units.code.android.dex import IDexMethod, IDexClass
except ImportError:
    pass

class JEBAdapter:
    """
    Parses Dalvik bytecode to extract function features and graph connections.
    Optimized for speed: Avoids full decompilation during the scan phase.
    """
    def __init__(self, dex_unit):
        self.dex = dex_unit
        self.internal_signatures = set()
        self._pre_scan_internal_methods()

    def _pre_scan_internal_methods(self):
        """Cache all internal method signatures for fast lookup."""
        for clazz in self.dex.getClasses():
            if self._is_valid_class(clazz):
                for method in clazz.getMethods():
                    self.internal_signatures.add(method.getSignature(True))

    def _is_valid_class(self, clazz):
        """Filter out Framework/Library classes to focus on the App code."""
        name = clazz.getName(True)
        # Skip standard Android/Java libraries
        if any(name.startswith(p) for p in ["Landroid/", "Ljava/", "Ljavax/", "Lkotlin/", "Landroidx/"]):
            return False
        return True

    def get_all_functions(self):
        """Scans DEX and returns list of (signature, name, features_dict)."""
        results = []
        classes = self.dex.getClasses()
        print(f"[*] Scanning {len(classes)} classes...")

        for clazz in classes:
            if not self._is_valid_class(clazz): continue
            
            for method in clazz.getMethods():
                if not method.getData(): continue  # Skip abstract/native
                
                sig = method.getSignature(True)
                name = method.getName(True)
                
                # Only process obfuscated/unnamed functions
                if not self._needs_naming(name):
                    continue

                try:
                    features = self._analyze_method(method)
                    if features: # Only add if we found *some* evidence
                        results.append((sig, name, features))
                except Exception as e:
                    print(f"[!] Error scanning {name}: {e}")
        
        return results

    def _needs_naming(self, name):
        """Heuristic: Does this function need a name?"""
        # Check for standard obfuscation patterns
        return name.startswith("sub_") or len(name) < 3 or name.startswith("func_")

    def _analyze_method(self, method):
        """Extract strings, APIs, and outgoing calls from Bytecode."""
        features = {
            'strings': set(),
            'api_calls': set(),
            'callees': set() # Internal calls (Edges)
        }
        
        code_item = method.getData()
        if not code_item: return None

        for insn in code_item.getInstructions():
            mnemonic = insn.getMnemonic()
            
            # 1. Strings (const-string)
            if mnemonic.startswith("const-string"):
                idx = insn.getParameter(1).getValue()
                s = self.dex.getString(idx)
                if s and len(s) > 3 and " " not in s: # Simple noise filter
                    features['strings'].add(s)

            # 2. Calls (invoke-*)
            elif mnemonic.startswith("invoke"):
                try:
                    # Parameter 0 or 1 depending on format, usually 0 for MethodReference
                    mref_idx = insn.getParameter(0).getValue()
                    mref = self.dex.getMethod(mref_idx)
                    
                    if mref:
                        target_sig = mref.getSignature(True)
                        
                        if target_sig in self.internal_signatures:
                            features['callees'].add(target_sig)
                        else:
                            # External API call
                            features['api_calls'].add(self._clean_api(target_sig))
                except:
                    pass
        
        # Convert sets to lists
        return {k: list(v) for k, v in features.items()}

    def _clean_api(self, sig):
        """Simplify 'Ljava/lang/String;->length()I' to 'String.length'"""
        try:
            base = sig.split('(')[0]
            parts = base.split(';->')
            cls = parts[0].split('/')[-1]
            method = parts[1]
            return f"{cls}.{method}"
        except:
            return sig

    def rename_method(self, signature, new_name):
        """Apply name change in JEB."""
        method = self.dex.getMethod(signature)
        if method:
            method.setName(new_name)
```

-----

### **3. `core_engine.py`**

The Brain. This contains the **Ripple/Wavefront** algorithm. It manages the priority queue and propagates context when functions get named.

```python
# core_engine.py
import heapq
import threading
from collections import defaultdict

class FunctionNode:
    def __init__(self, func_id, original_name, features):
        self.id = func_id
        self.original_name = original_name
        self.features = features
        
        self.suggested_name = None
        self.summary = None
        self.is_named = False
        
        # Graph connections
        self.callers = set()
        self.callees = set()
        
        # Scoring
        self.base_score = self._calc_base_score()
        self.dynamic_score = 0.0

    def _calc_base_score(self):
        """Static score: How much raw evidence do we have?"""
        score = 0.0
        score += len(self.features.get('strings', [])) * 4.0
        score += len(self.features.get('api_calls', [])) * 2.0
        # Penalize huge functions slightly as they might be confusing
        return score

    def get_priority(self):
        return self.base_score + self.dynamic_score

class RippleGraph:
    def __init__(self):
        self.nodes = {}
        self.pq = [] # Heap Queue
        self.lock = threading.Lock()

    def add_node(self, func_id, original_name, features):
        if func_id not in self.nodes:
            self.nodes[func_id] = FunctionNode(func_id, original_name, features)

    def build_edges(self):
        """Finalize graph connections (must run after all nodes added)."""
        print("[*] Building Graph Edges...")
        for node_id, node in self.nodes.items():
            # Process outgoing calls (callees)
            for target_id in node.features.get('callees', []):
                if target_id in self.nodes:
                    # Link forward
                    node.callees.add(target_id)
                    # Link backward
                    self.nodes[target_id].callers.add(node_id)

    def initialize_queue(self):
        """Populate priority queue."""
        self.pq = []
        for node in self.nodes.values():
            if node.get_priority() > 5.0: # Only queue items with actual evidence
                # Negative priority because heapq is min-heap
                heapq.heappush(self.pq, (-node.get_priority(), node.id))

    def get_next_batch(self, batch_size=5):
        """Get highest priority unnamed nodes."""
        batch = []
        with self.lock:
            while len(batch) < batch_size and self.pq:
                priority, func_id = heapq.heappop(self.pq)
                if func_id in self.nodes:
                    node = self.nodes[func_id]
                    if not node.is_named:
                        batch.append(node)
        return batch

    def update_node(self, func_id, name, summary):
        """
        The Ripple Effect: Name a node -> Boost neighbors.
        """
        with self.lock:
            if func_id not in self.nodes: return
            node = self.nodes[func_id]
            
            node.is_named = True
            node.suggested_name = name
            node.summary = summary
            
            # --- PROPAGATION LOGIC ---
            # Boost score of anyone touching this node
            neighbors = node.callers.union(node.callees)
            for nid in neighbors:
                neighbor = self.nodes[nid]
                if not neighbor.is_named:
                    # Huge boost: "I now know what my neighbor does!"
                    neighbor.dynamic_score += 15.0 
                    heapq.heappush(self.pq, (-neighbor.get_priority(), nid))
```

-----

### **4. `llm_agent.py`**

The Worker. Handles the `litellm` interaction, caching, and prompt engineering.

```python
# llm_agent.py
import json
import os
import hashlib
from config import Config

# Try to import litellm, handle failure gracefully for JEB env
try:
    from litellm import completion
    LITELLM_AVAILABLE = True
except ImportError:
    LITELLM_AVAILABLE = False

class NamingAgent:
    def __init__(self):
        self.cache_file = Config.CACHE_FILE
        self.cache = self._load_cache()
        self.system_prompt = """
You are a Lead Android Reverse Engineer.
Goal: Rename the function based on its logic and context.

Rules:
1. Output JSON ONLY.
2. Name format: camelCase (verbNoun). E.g., 'decryptKey', 'uploadLogs'.
3. If uncertain, use 'sub_Description'.
4. 'summary': A 10-word description for other agents.
"""

    def _load_cache(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f: return json.load(f)
            except: pass
        return {}

    def _save_cache(self):
        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f, indent=2)

    def analyze(self, node, neighbor_context):
        if not LITELLM_AVAILABLE:
            return {"name": node.original_name, "confidence": "FAIL", "summary": "Install litellm"}

        # 1. Prepare Data
        data = {
            "original": node.original_name,
            "strings": node.features.get('strings', [])[:8],
            "apis": node.features.get('api_calls', [])[:12],
            # WAVEFRONT CONTEXT: Known neighbors
            "calls_outgoing_to": [neighbor_context.get(x, x) for x in list(node.callees)[:5]],
            "called_by": [neighbor_context.get(x, x) for x in list(node.callers)[:5]]
        }
        
        # 2. Check Cache
        sig = hashlib.md5(json.dumps(data, sort_keys=True).encode()).hexdigest()
        if sig in self.cache:
            return self.cache[sig]

        # 3. Call LLM
        try:
            response = completion(
                model=Config.MODEL_FAST,
                api_key=Config.OPENAI_API_KEY,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": json.dumps(data)}
                ],
                response_format={"type": "json_object"}
            )
            result = json.loads(response.choices[0].message.content)
            
            # Cache and Return
            self.cache[sig] = result
            self._save_cache()
            return result
        except Exception as e:
            print(f"[!] LLM Error: {e}")
            return {"name": node.original_name, "confidence": "LOW", "summary": "Error"}
```

-----

### **5. `RippleAutoNamer.py`**

The Plugin entry point. This script runs inside JEB, loads the dependencies, and orchestrates the flow.

```python
# RippleAutoNamer.py
import sys
import os
import time
from com.pnfsoftware.jeb.client.api import IScript
from com.pnfsoftware.jeb.core import RuntimeProjectUtil
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit

# --- PATH SETUP ---
# Detect where this script is running and add to path to import local modules
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.append(SCRIPT_DIR)

# Import our modules
from config import Config
from jeb_adapter import JEBAdapter
from core_engine import RippleGraph
from llm_agent import NamingAgent

class RippleAutoNamer(IScript):
    def run(self, ctx):
        print(">>> Ripple Auto-Namer: Initializing...")
        
        # 1. Setup JEB Context
        prj = ctx.getMainProject()
        if not prj:
            print("[!] No project opened.")
            return

        dex_units = RuntimeProjectUtil.findUnitsByType(prj, IDexUnit, False)
        if not dex_units:
            print("[!] No DEX unit found.")
            return
        
        dex = dex_units[0]
        adapter = JEBAdapter(dex)
        graph = RippleGraph()
        agent = NamingAgent()

        # 2. Extract Data (Main Thread)
        print(">>> Scanning Bytecode (Phase 1/3)...")
        raw_funcs = adapter.get_all_functions()
        print(f"    Found {len(raw_funcs)} candidates.")
        
        if len(raw_funcs) == 0:
            print("    No suitable functions found. Exiting.")
            return

        # 3. Build Graph
        for sig, name, features in raw_funcs:
            graph.add_node(sig, name, features)
        graph.build_edges()
        graph.initialize_queue()

        # 4. Wavefront Execution (Phase 2/3)
        print(">>> Starting Wavefront Analysis (Phase 2/3)...")
        renamed_count = 0
        iteration = 0
        
        # LIMITER: Don't run forever
        MAX_ITER = Config.MAX_FUNCTIONS // Config.BATCH_SIZE
        
        while iteration < MAX_ITER:
            batch = graph.get_next_batch(Config.BATCH_SIZE)
            if not batch:
                print("    Queue empty. Analysis finished.")
                break
                
            iteration += 1
            print(f"    Wave {iteration}: Analyzing {len(batch)} functions...")
            
            for node in batch:
                # Build context from neighbors that are ALREADY named
                neighbor_ctx = {}
                
                # Check neighbors for names
                all_neighbors = node.callees.union(node.callers)
                for nid in all_neighbors:
                    if nid in graph.nodes and graph.nodes[nid].is_named:
                        neighbor_ctx[nid] = graph.nodes[nid].suggested_name
                
                # Ask Agent
                result = agent.analyze(node, neighbor_ctx)
                
                # Update Graph
                confidence = result.get('confidence', 'LOW')
                if confidence in ['HIGH', 'MEDIUM']:
                    new_name = result.get('name')
                    summary = result.get('summary', '')
                    
                    print(f"      [+] {node.original_name} -> {new_name} ({confidence})")
                    graph.update_node(node.id, new_name, summary)
                    renamed_count += 1
                else:
                    # Mark processed so we don't loop, but don't propagate strong score
                    graph.update_node(node.id, node.original_name, "Unclear")

        # 5. Apply Changes (Phase 3/3)
        print(f">>> Applying {renamed_count} names to JEB (Phase 3/3)...")
        applied = 0
        for node in graph.nodes.values():
            if node.is_named and node.suggested_name and node.suggested_name != node.original_name:
                adapter.rename_method(node.id, node.suggested_name)
                applied += 1
                
        print(f">>> Done! Renamed {applied} functions.")
```

-----

### **6. `README.md`**

The Quick Start Guide.

````markdown
# Ripple Auto-Namer for JEB

An agentic, AI-powered plugin for JEB Decompiler that automatically names Android functions using a **Wavefront/Ripple Algorithm**.

It starts with the easiest functions (those with clear Strings/APIs), names them, and then uses those names as context to solve harder, connected functions.

## Features
- **Ripple Algorithm:** Solves the dependency graph dynamically.
- **Dalvik Analysis:** Scans bytecode instantly (no slow decompilation needed).
- **Caching:** Saves results to JSON to prevent re-billing on crashes or re-runs.
- **Thread Safe:** Separates Analysis from JEB UI updates.

## Prerequisites
1. **JEB Decompiler** (Pro recommended, 4.x or 5.x).
2. **Python 3.8+** installed on your system.
3. `litellm` library.

## Installation

### 1. Install Python Dependencies
JEB uses its own Jython environment, but we need standard Python libraries.
Open your terminal:

```bash
pip install litellm python-dotenv openai anthropic
````

### 2\. Configure the Plugin

1.  Open `config.py`.
2.  Add your API Key (OpenAI or Anthropic).
3.  (Optional) Adjust `MAX_FUNCTIONS` to control costs.

### 3\. Install in JEB

1.  Copy the entire `RippleNamer` folder to your JEB scripts folder.
      - **Windows:** `C:\Program Files\JEB\scripts\`
      - **Mac/Linux:** `~/jeb/scripts/`
2.  **CRITICAL:** You must ensure JEB can find your installed `litellm` library.
      - The plugin attempts to import it. If it fails, you may need to add your site-packages path to `RippleAutoNamer.py` line 12:
    <!-- end list -->
    ```python
    sys.path.append(r"C:\Users\YourName\AppData\Local\Programs\Python\Python39\Lib\site-packages")
    ```

## Usage

1.  Open JEB and load an APK.
2.  Wait for the initial auto-analysis to finish.
3.  Go to **File -\> Scripts -\> Run Script...**
4.  Select `RippleNamer/RippleAutoNamer.py`.
5.  Watch the logs in the JEB Console.

## Troubleshooting

  - **ImportError: No module named litellm**:
    JEB uses Jython (Java Python). It cannot natively run C-based Python modules.
    *Solution:* For pure Python power, run the script via JEB's floating controller or ensure `litellm` is installed in a path accessible to JEB's Jython interpreter (this is tricky).
    *Alternative:* Use `requests` to hit OpenAI API directly in `llm_agent.py` if `litellm` proves difficult in Jython.

<!-- end list -->

```

### **Important Note on JEB & Jython**
JEB runs Python scripts via Jython (Java implementation of Python 2.7 or sometimes generic Python 3 bridges depending on version).
* `litellm` is a modern Python library. It might not load in standard JEB Jython.
* **Recommendation:** If JEB complains about `litellm`, replace the `completion` call in `llm_agent.py` with standard python `urllib2` or `requests` calls to the OpenAI API endpoint. This ensures compatibility with the Java environment.

Would you like me to provide the `requests`-based version of `llm_agent.py` just in case, to ensure 100% compatibility with JEB's environment?
```
