export declare enum Severity {
    Info = "Info",
    Low = "Low",
    Medium = "Medium",
    High = "High",
    Critical = "Critical"
}
export declare enum VulnerabilityClass {
    C1 = "C1",
    C2 = "C2",
    C3 = "C3"
}
export interface Finding {
    id: string;
    program_id: string;
    vulnerability_class: VulnerabilityClass;
    severity: Severity;
    title: string;
    description: string;
    evidence_refs: string[];
    detector: string;
    line?: number;
    file?: string;
}
export interface Evidence {
    id: string;
    finding_id: string;
    kind: string;
    data: string;
    hash: string;
}
export interface EvidenceBundle {
    id: string;
    program_id: string;
    findings: string[];
    evidence: Evidence[];
    merkle_root?: string;
}
export interface RiskScore {
    program_id: string;
    score: number;
    severity: Severity;
    findings_count: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    info_count: number;
}
export interface ProgramInfo {
    id: string;
    name: string;
    path: string;
    language: string;
    size_bytes: number;
}
export interface CVEEntry {
    cve_id: string;
    description: string;
    severity?: Severity;
    references: string[];
}
export interface HealthResponse {
    status: string;
    version: string;
}
export interface FindingsResponse {
    findings: Finding[];
    total: number;
}
export interface FindingsQuery {
    program_id?: string;
    severity?: Severity;
    vulnerability_class?: VulnerabilityClass;
    limit?: number;
    offset?: number;
}
export interface RiskResponse {
    program_id: string;
    risk: RiskScore;
}
export interface RegisterWebhookRequest {
    url: string;
    events: string[];
    secret?: string;
}
export interface WebhookRegistration {
    id: string;
    url: string;
    events: string[];
}
export interface CVESearchResponse {
    cves: CVEEntry[];
}
export interface MetricsResponse {
    total_findings: number;
    total_programs: number;
    average_risk_score: number;
}
export interface AgentReport {
    program_id: string;
    program_name?: string;
    risk?: RiskScore;
    findings: Finding[];
    bundle?: EvidenceBundle;
    cves: CVEEntry[];
    summary: string;
}
export type Program = ProgramInfo;
export type CveEntry = CVEEntry;
export interface ProgramFamily {
    id: string;
    program_id: string;
    family_name: string;
    members: string[];
}
export interface WebhookConfig {
    id: string;
    url: string;
    events: string[];
    secret?: string;
}
export interface AresConfig {
    baseUrl: string;
    apiKey: string | null;
    timeoutMs: number;
}
export interface DetectorResult {
    detector: string;
    findings: Finding[];
    duration_ms: number;
    error?: string;
}
export interface FindingWithRisk extends Finding {
    risk_score: number;
}
//# sourceMappingURL=types.d.ts.map