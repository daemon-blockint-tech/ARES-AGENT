import { Annotation } from "@langchain/langgraph";
import type {
  Program,
  Finding,
  EvidenceBundle,
  RiskScore,
  CveEntry,
  ProgramFamily,
  WebhookConfig,
  AresConfig,
  DetectorResult,
  FindingWithRisk,
} from "./types.js";

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

export const StateAnnotations = Annotation.Root<AresAgentState>({
  config: Annotation<AresConfig>({
    reducer: (left, right) => ({ ...left, ...right }),
    default: () => ({
      baseUrl: "http://localhost:3000",
      apiKey: null,
      timeoutMs: 30_000,
    }),
  }),

  status: Annotation<Status>({
    reducer: (_left, right) => right,
    default: () => "idle",
  }),

  program: Annotation<Program | null>({
    reducer: (_left, right) => right,
    default: () => null,
  }),

  bundle: Annotation<EvidenceBundle | null>({
    reducer: (_left, right) => right,
    default: () => null,
  }),

  findings: Annotation<FindingWithRisk[]>({
    reducer: (left, right) => [...left, ...right],
    default: () => [],
  }),

  detectorResults: Annotation<DetectorResult[]>({
    reducer: (left, right) => [...left, ...right],
    default: () => [],
  }),

  cveEntries: Annotation<CveEntry[]>({
    reducer: (left, right) => [...left, ...right],
    default: () => [],
  }),

  families: Annotation<ProgramFamily[]>({
    reducer: (left, right) => [...left, ...right],
    default: () => [],
  }),

  risk: Annotation<RiskScore | null>({
    reducer: (_left, right) => right,
    default: () => null,
  }),

  errors: Annotation<string[]>({
    reducer: (left, right) => [...left, ...right],
    default: () => [],
  }),

  webhook: Annotation<WebhookConfig | null>({
    reducer: (_left, right) => right,
    default: () => null,
  }),

  output: Annotation<string | null>({
    reducer: (_left, right) => right,
    default: () => null,
  }),
});
