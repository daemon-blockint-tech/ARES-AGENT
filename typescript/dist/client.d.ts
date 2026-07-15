import type { CVEEntry, CVESearchResponse, EvidenceBundle, Finding, FindingsQuery, FindingsResponse, HealthResponse, MetricsResponse, ProgramInfo, RegisterWebhookRequest, RiskResponse, WebhookRegistration } from "./types.js";
export interface AresClientConfig {
    baseUrl: string;
    apiKey?: string;
    timeoutMs?: number;
}
export declare class AresClient {
    private readonly baseUrl;
    private readonly apiKey?;
    private readonly timeoutMs;
    constructor(config: AresClientConfig);
    private request;
    health(): Promise<HealthResponse>;
    listPrograms(): Promise<ProgramInfo[]>;
    ingestProgram(path: string, name?: string): Promise<ProgramInfo>;
    scanProgram(programId: string): Promise<FindingsResponse>;
    listFindings(query?: FindingsQuery): Promise<FindingsResponse>;
    getFinding(id: string): Promise<Finding>;
    getRisk(programId: string): Promise<RiskResponse>;
    bundleEvidence(programId: string): Promise<EvidenceBundle>;
    anchorEvidence(programId: string): Promise<{
        tx: string;
    }>;
    searchCVEs(keyword: string): Promise<CVESearchResponse>;
    cveForFinding(findingId: string): Promise<CVEEntry[]>;
    registerWebhook(req: RegisterWebhookRequest): Promise<WebhookRegistration>;
    getMetrics(): Promise<MetricsResponse>;
}
//# sourceMappingURL=client.d.ts.map