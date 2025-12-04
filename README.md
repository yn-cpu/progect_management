import * as http from 'http';
import * as https from 'https';
// ... other imports

// ... inside your class
    async chat(messages: any[], jsonMode: boolean = false): Promise<string> {
        try {
            // FORCE 127.0.0.1 if user provided localhost (Fixes Proxy DNS issues)
            let safeBaseUrl = this.baseUrl.replace('localhost', '127.0.0.1');
            const url = `${safeBaseUrl}/chat/completions`;

            // --- THE NUCLEAR BYPASS ---
            // We create a custom agent that strictly connects DIRECTLY.
            // This bypasses VS Code's global agent injection.
            const httpAgent = new http.Agent({ keepAlive: true });
            const httpsAgent = new https.Agent({ keepAlive: true });

            const axiosConfig: any = {
                // FORCE the Node.js adapter. 
                // Without this, Axios might try to use the Browser XHR (which VS Code intercepts).
                adapter: 'http', 
                
                // Explicitly disable proxy logic in Axios
                proxy: false, 

                // Attach our direct-connection agents
                httpAgent: httpAgent,
                httpsAgent: httpsAgent,

                headers: {
                    'Content-Type': 'application/json',
                    // Use a dummy key if none provided (some servers 403 on missing Auth header)
                    'Authorization': (this.apiKey && this.apiKey.trim() !== "") 
                        ? `Bearer ${this.apiKey}` 
                        : 'Bearer vulntriage-local'
                }
            };
            // ---------------------------

            const body = {
                model: this.model,
                messages: messages,
                temperature: 0.2,
                response_format: jsonMode ? { type: "json_object" } : { type: "text" }
            };

            console.log(`[LLM] Requesting: ${url}`);
            
            const response = await axios.post(url, body, axiosConfig);
            const data = response.data;
            
            if (!data.choices || data.choices.length === 0) return "No response generated.";
            return data.choices[0].message.content || "No content.";

        } catch (e: any) {
            if (axios.isAxiosError(e)) {
                const status = e.response?.status || 'Unknown';
                // LOG THE HEADERS: This tells us WHO denied us.
                // If you see "Via: corporate-proxy", the proxy is still active.
                // If you see "Server: uvicorn/ollama", the target blocked us.
                console.error("Failure Headers:", e.response?.headers);
                
                const errorData = JSON.stringify(e.response?.data || e.message);
                return `LLM Error (HTTP ${status}): ${errorData}. Check Debug Console for headers.`;
            }
            console.error("LLM Error:", e);
            return `LLM Error: ${e.message}`;
        }
    }
