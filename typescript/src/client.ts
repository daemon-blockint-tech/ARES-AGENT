import { getCurrentRunTree } from "langsmith/traceable";
import type {
  CVEEntry,
  CVESearchResponse,
  EvidenceBundle,
  Finding,
  FindingsQuery,
  FindingsResponse,
  HealthResponse,
  MetricsResponse,
  ProgramInfo,
  RegisterWebhookRequest,
  RiskResponse,
  WebhookRegistration,
} from "./types.js";

export interface AresClientConfig {
  baseUrl: string;
  apiKey?: string;
  timeoutMs?: number;
}

export class AresClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly timeoutMs: number;

  constructor(config: AresClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.apiKey = config.apiKey;
    this.timeoutMs = config.timeoutMs ?? 30_000;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.apiKey) {
      headers["X-API-Key"] = this.apiKey;
    }

    // Propagate LangSmith distributed tracing context if we're inside a traceable run.
    // This links the server-side spans to the client-side parent run.
    // permitAbsentRunTree=true returns undefined instead of throwing when no run is active.
    const runTree = getCurrentRunTree(true);
    if (runTree) {
      const traceHeaders = runTree.toHeaders();
      headers["langsmith-trace"] = traceHeaders["langsmith-trace"];
      headers["baggage"] = traceHeaders.baggage;
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

      return (await response.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  }

  async health(): Promise<HealthResponse> {
    return this.request<HealthResponse>("GET", "/health");
  }

  async listPrograms(): Promise<ProgramInfo[]> {
    return this.request<ProgramInfo[]>("GET", "/programs");
  }

  async ingestProgram(path: string, name?: string): Promise<ProgramInfo> {
    return this.request<ProgramInfo>("POST", "/programs", {
      path,
      name: name ?? path,
    });
  }

  async scanProgram(programId: string): Promise<FindingsResponse> {
    return this.request<FindingsResponse>("POST", "/programs/scan", {
      program_id: programId,
    });
  }

  async listFindings(query?: FindingsQuery): Promise<FindingsResponse> {
    const params = new URLSearchParams();
    if (query) {
      for (const [key, value] of Object.entries(query)) {
        if (value !== undefined && value !== null) {
          params.append(key, String(value));
        }
      }
    }
    const queryString = params.toString() ? `?${params.toString()}` : "";
    return this.request<FindingsResponse>("GET", `/findings${queryString}`);
  }

  async getFinding(id: string): Promise<Finding> {
    return this.request<Finding>("GET", `/findings/${id}`);
  }

  async getRisk(programId: string): Promise<RiskResponse> {
    return this.request<RiskResponse>("GET", `/programs/${programId}/risk`);
  }

  async bundleEvidence(programId: string): Promise<EvidenceBundle> {
    return this.request<EvidenceBundle>("POST", `/programs/${programId}/bundle`);
  }

  async anchorEvidence(programId: string): Promise<{ tx: string }> {
    return this.request<{ tx: string }>("POST", "/anchor", { program_id: programId });
  }

  async searchCVEs(keyword: string): Promise<CVESearchResponse> {
    return this.request<CVESearchResponse>("GET", `/cve/search?q=${encodeURIComponent(keyword)}`);
  }

  async cveForFinding(findingId: string): Promise<CVEEntry[]> {
    const response = await this.request<CVESearchResponse>(
      "GET",
      `/cve/finding/${findingId}`,
    );
    return response.cves;
  }

  async registerWebhook(req: RegisterWebhookRequest): Promise<WebhookRegistration> {
    return this.request<WebhookRegistration>("POST", "/webhooks/register", req);
  }

  async getMetrics(): Promise<MetricsResponse> {
    return this.request<MetricsResponse>("GET", "/eval/metrics");
  }
}
