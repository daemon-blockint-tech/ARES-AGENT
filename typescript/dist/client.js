export class AresClient {
    baseUrl;
    apiKey;
    timeoutMs;
    constructor(config) {
        this.baseUrl = config.baseUrl.replace(/\/$/, "");
        this.apiKey = config.apiKey;
        this.timeoutMs = config.timeoutMs ?? 30_000;
    }
    async request(method, path, body) {
        const headers = {
            "Content-Type": "application/json",
        };
        if (this.apiKey) {
            headers["X-API-Key"] = this.apiKey;
        }
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);
        try {
            const response = await fetch(`${this.baseUrl}${path}`, {
                method,
                headers,
                body: body ? JSON.stringify(body) : undefined,
                signal: controller.signal,
            });
            if (!response.ok) {
                const text = await response.text().catch(() => "unknown error");
                throw new Error(`ARES API error ${response.status}: ${text}`);
            }
            return (await response.json());
        }
        finally {
            clearTimeout(timer);
        }
    }
    async health() {
        return this.request("GET", "/health");
    }
    async listPrograms() {
        return this.request("GET", "/programs");
    }
    async ingestProgram(path, name) {
        return this.request("POST", "/programs", {
            path,
            name: name ?? path,
        });
    }
    async scanProgram(programId) {
        return this.request("POST", "/programs/scan", {
            program_id: programId,
        });
    }
    async listFindings(query) {
        const params = new URLSearchParams();
        if (query) {
            for (const [key, value] of Object.entries(query)) {
                if (value !== undefined && value !== null) {
                    params.append(key, String(value));
                }
            }
        }
        const queryString = params.toString() ? `?${params.toString()}` : "";
        return this.request("GET", `/findings${queryString}`);
    }
    async getFinding(id) {
        return this.request("GET", `/findings/${id}`);
    }
    async getRisk(programId) {
        return this.request("GET", `/programs/${programId}/risk`);
    }
    async bundleEvidence(programId) {
        return this.request("POST", `/programs/${programId}/bundle`);
    }
    async anchorEvidence(programId) {
        return this.request("POST", "/anchor", { program_id: programId });
    }
    async searchCVEs(keyword) {
        return this.request("GET", `/cve/search?q=${encodeURIComponent(keyword)}`);
    }
    async cveForFinding(findingId) {
        const response = await this.request("GET", `/cve/finding/${findingId}`);
        return response.cves;
    }
    async registerWebhook(req) {
        return this.request("POST", "/webhooks/register", req);
    }
    async getMetrics() {
        return this.request("GET", "/eval/metrics");
    }
}
//# sourceMappingURL=client.js.map