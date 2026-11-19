import type { CaseStore, Finding, Verdict } from "./core/store.js";

export const VERDICT_TEXT: Record<Verdict, string> = {
  clear: "No signs of compromise in what was checked",
  review: "Suspicious items need a closer look",
  alert: "Strong signs of compromise",
};

const COVERAGE_MARK = { checked: "checked", partial: "partly checked", skipped: "NOT checked" } as const;

function findingBlock(store: CaseStore, f: Finding): string {
  const cited = f.evidenceIds
    .map((id) => store.get(id))
    .filter((e) => e !== undefined)
    .map((e) => `  - \`${e.id}\` ${e.time ? `${e.time} ` : ""}${e.summary} (sha256 ${e.sha256.slice(0, 12)})`);
  return [
    `### ${f.id} · ${f.severity.toUpperCase()} · ${f.title}`,
    "",
    `- **Why it matters:** ${f.why}`,
    f.benign ? `- **Innocent explanation:** ${f.benign}` : "",
    `- **Confidence:** ${f.confidence}${f.technique ? ` · **ATT&CK:** ${f.technique}` : ""} · **Source:** ${f.origin === "agent" ? "agent conclusion" : `rule \`${f.ruleId}\``}`,
    "- **Evidence:**",
    ...cited,
  ].filter(Boolean).join("\n");
}

/** The whole case as Markdown: verdict, findings with their evidence, and what was not checked. */
export function renderReport(store: CaseStore): string {
  const findings = store.findings();
  const counts = store.counts();
  const lines = [
    "# amihacked report",
    "",
    `**Verdict: ${VERDICT_TEXT[store.verdict()]}**`,
    "",
    `Generated ${new Date().toISOString()} · ${findings.length} finding(s) · ${Object.values(counts).reduce((a, b) => a + b, 0)} evidence record(s)`,
    "",
    "A clear verdict means nothing was found in the areas listed under Coverage. It is not proof the system is clean.",
    "",
    "## Findings",
    "",
    findings.length === 0 ? "None." : findings.map((f) => findingBlock(store, f)).join("\n\n"),
    "",
    "## Coverage",
    "",
    ...store.coverage().map((c) => `- **${c.area}** (${COVERAGE_MARK[c.status]}): ${c.note}`),
    "",
    "## Evidence collected",
    "",
    ...Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([kind, count]) => `- ${kind}: ${count}`),
    "",
  ];
  return lines.join("\n");
}

/** Compact summary for an agent: what was found and what to look at next. */
export function summarise(store: CaseStore): Record<string, unknown> {
  return {
    verdict: store.verdict(),
    verdictMeaning: VERDICT_TEXT[store.verdict()],
    findings: store.findings().map((f) => ({
      id: f.id, severity: f.severity, confidence: f.confidence, title: f.title, why: f.why,
      innocentExplanation: f.benign, technique: f.technique, evidenceIds: f.evidenceIds, origin: f.origin,
    })),
    coverage: store.coverage(),
    evidenceCounts: store.counts(),
  };
}
