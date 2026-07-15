import type { Program, EvidenceBundle, RiskScore, CveEntry, ProgramFamily, WebhookConfig, AresConfig, DetectorResult, FindingWithRisk } from "./types.js";
export type Status = "idle" | "running" | "error" | "done";
export type Artifact<T = unknown> = {
    ok: boolean;
    value?: T;
    error?: string;
};
export interface AresAgentState {
    config: AresConfig;
    status: Status;
    program: Program | null;
    bundle: EvidenceBundle | null;
    findings: FindingWithRisk[];
    detectorResults: DetectorResult[];
    cveEntries: CveEntry[];
    families: ProgramFamily[];
    risk: RiskScore | null;
    errors: string[];
    webhook: WebhookConfig | null;
    output: string | null;
}
export declare const StateAnnotations: import("@langchain/langgraph").AnnotationRoot<AresAgentState>;
//# sourceMappingURL=state.d.ts.map