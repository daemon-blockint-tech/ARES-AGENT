import { Annotation } from "@langchain/langgraph";
export const StateAnnotations = Annotation.Root({
    config: Annotation({
        reducer: (left, right) => ({ ...left, ...right }),
        default: () => ({
            baseUrl: "http://localhost:3000",
            apiKey: null,
            timeoutMs: 30_000,
        }),
    }),
    status: Annotation({
        reducer: (_left, right) => right,
        default: () => "idle",
    }),
    program: Annotation({
        reducer: (_left, right) => right,
        default: () => null,
    }),
    bundle: Annotation({
        reducer: (_left, right) => right,
        default: () => null,
    }),
    findings: Annotation({
        reducer: (left, right) => [...left, ...right],
        default: () => [],
    }),
    detectorResults: Annotation({
        reducer: (left, right) => [...left, ...right],
        default: () => [],
    }),
    cveEntries: Annotation({
        reducer: (left, right) => [...left, ...right],
        default: () => [],
    }),
    families: Annotation({
        reducer: (left, right) => [...left, ...right],
        default: () => [],
    }),
    risk: Annotation({
        reducer: (_left, right) => right,
        default: () => null,
    }),
    errors: Annotation({
        reducer: (left, right) => [...left, ...right],
        default: () => [],
    }),
    webhook: Annotation({
        reducer: (_left, right) => right,
        default: () => null,
    }),
    output: Annotation({
        reducer: (_left, right) => right,
        default: () => null,
    }),
});
//# sourceMappingURL=state.js.map