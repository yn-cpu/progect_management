async chat(messages: any[], jsonMode: boolean = false): Promise<string> {
        try {
            const url = `${this.baseUrl}/chat/completions`;
            
            // --- NEW PROXY BYPASS LOGIC ---
            // 1. Get the destination hostname
            const targetUrl = new URL(url);
            const hostname = targetUrl.hostname;

            // 2. Get the NO_PROXY list (from env or VS Code settings)
            // Note: VS Code extensions sometimes don't inherit shell env vars if launched from the OS UI.
            const noProxy = process.env.NO_PROXY || process.env.no_proxy || "";
            
            // 3. Check if we should bypass
            let useProxy = true;
            
            // Always bypass for localhost/127.0.0.1 if not explicitly handled
            if (hostname === 'localhost' || hostname === '127.0.0.1') {
                useProxy = false;
            } else if (noProxy) {
                // Split by comma and check if our hostname is in the list
                const noProxyList = noProxy.split(',').map(s => s.trim().toLowerCase());
                // Simple check: strict match or endsWith (for wildcards like .internal.com)
                const match = noProxyList.some(domain => 
                    hostname === domain || hostname.endsWith(domain.replace(/^\*/, ''))
                );
                if (match) useProxy = false;
            }

            // 4. Construct Axios Config
            const axiosConfig: any = {
                headers: {
                    'Content-Type': 'application/json',
                    // Authorization logic...
                    'Authorization': (this.apiKey && this.apiKey.trim() !== "") 
                        ? `Bearer ${this.apiKey}` 
                        : 'Bearer vulntriage-local'
                }
            };

            // THE KEY FIX: Explicitly set proxy to false if we detected a match
            if (!useProxy) {
                console.log(`[VulnTriage] Bypassing Proxy for ${hostname}`);
                axiosConfig.proxy = false; // <--- This forces direct connection
            } else {
                console.log(`[VulnTriage] Using Default Proxy Settings for ${hostname}`);
            }
            // -----------------------------

            const body = {
                model: this.model,
                messages: messages,
                temperature: 0.2,
                response_format: jsonMode ? { type: "json_object" } : { type: "text" }
            };

            console.log(`[LLM] Requesting: ${url}`);

            const response = await axios.post(url, body, axiosConfig);

            const data = response.data;
            
            if (!data.choices || data.choices.length === 0) {
                return "No response generated (empty choices).";
            }

            return data.choices[0].message.content || "No content in response.";

        } catch (e: any) {
            if (axios.isAxiosError(e)) {
                const status = e.response?.status || 'Unknown Status';
                // Log the full error to debug console to see if it's still the proxy
                console.error(`LLM Axios Error full:`, e);
                const errorData = JSON.stringify(e.response?.data || e.message);
                return `LLM Error (HTTP ${status}): ${errorData}. (Target: ${this.baseUrl})`;
            }
            console.error("LLM Error:", e);
            return `LLM Error: ${e.message}. (Target: ${this.baseUrl})`;
        }
    }
