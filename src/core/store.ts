import { createHash } from "node:crypto";

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type Verdict = "clear" | "review" | "alert";

export const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];
export const CONFIDENCES: Confidence[] = ["low", "medium", "high"];

export interface Evidence {
  id: string;
  kind: string;
  source: string;
  collectedAt: string;
  /** When the recorded thing happened, ISO 8601 UTC, if it has a time. */
  time?: string;
  summary: string;
  data: Record<string, unknown>;
  sha256: string;
}

export interface EvidenceInput {
  kind: string;
  source: string;
  summary: string;
  data: Record<string, unknown>;
  time?: string | undefined;
}

export interface FindingInput {
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  /** MITRE ATT&CK technique ID, e.g. T1547.001 */
  technique?: string | undefined;
  evidenceIds: string[];
  why: string;
  /** The most likely innocent explanation. */
  benign?: string | undefined;
}

export interface Finding extends FindingInput {
  id: string;
  origin: "rule" | "agent";
}

export interface CoverageNote {
  area: string;
  status: "checked" | "partial" | "skipped";
  note: string;
}

export class EvidenceError extends Error {}

/** JSON with sorted keys, so the same record always hashes the same. */
export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",")}}`;
}

/** Any date-like value to ISO 8601 UTC, or undefined when it is not a real date. */
export function toIso(value: unknown): string | undefined {
  if (value === null || value === undefined || value === "") return undefined;
  const d = value instanceof Date ? value : new Date(value as string | number);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

export class CaseStore {
  readonly startedAt = new Date().toISOString();
  private readonly evidence = new Map<string, Evidence>();
  private readonly findingList: Finding[] = [];
  private readonly coverageList: CoverageNote[] = [];
  private seq = 0;
  private findingSeq = 0;

  add(input: EvidenceInput): Evidence {
    const time = toIso(input.time);
    const body = { kind: input.kind, source: input.source, time, summary: input.summary, data: input.data };
    const record: Evidence = {
      id: `E${String(++this.seq).padStart(5, "0")}`,
      kind: input.kind,
      source: input.source,
      collectedAt: new Date().toISOString(),
      summary: input.summary,
      data: input.data,
      sha256: createHash("sha256").update(stableStringify(body)).digest("hex"),
    };
    if (time) record.time = time;
    this.evidence.set(record.id, record);
    return record;
  }

  get(id: string): Evidence | undefined {
    return this.evidence.get(id);
  }

  all(kind?: string): Evidence[] {
    const list = [...this.evidence.values()];
    return kind ? list.filter((e) => e.kind === kind) : list;
  }

  counts(): Record<string, number> {
    const out: Record<string, number> = {};
    for (const e of this.evidence.values()) out[e.kind] = (out[e.kind] ?? 0) + 1;
    return out;
  }

  search(query: string, kind?: string): Evidence[] {
    const needle = query.toLowerCase();
    return this.all(kind).filter(
      (e) => e.summary.toLowerCase().includes(needle) || JSON.stringify(e.data).toLowerCase().includes(needle),
    );
  }

  /**
   * Record a finding. Throws EvidenceError unless it cites at least one evidence
   * record that exists in this case: a claim with no evidence is not a finding.
   * Returns the existing finding when the same rule already cited the same evidence.
   */
  addFinding(input: FindingInput, origin: "rule" | "agent"): Finding {
    const ids = [...new Set(input.evidenceIds)].sort();
    if (ids.length === 0) {
      throw new EvidenceError("A finding must cite at least one evidence ID.");
    }
    const missing = ids.filter((id) => !this.evidence.has(id));
    if (missing.length > 0) {
      throw new EvidenceError(`Unknown evidence ID(s): ${missing.join(", ")}. Cite records that exist in this case.`);
    }
    if (!SEVERITIES.includes(input.severity)) throw new EvidenceError(`Invalid severity: ${input.severity}`);
    if (!CONFIDENCES.includes(input.confidence)) throw new EvidenceError(`Invalid confidence: ${input.confidence}`);
    if (!input.title.trim() || !input.why.trim()) throw new EvidenceError("A finding needs a title and a reason.");

    const key = `${input.ruleId}|${ids.join(",")}`;
    const existing = this.findingList.find((f) => `${f.ruleId}|${f.evidenceIds.join(",")}` === key);
    if (existing) return existing;

    const finding: Finding = { ...input, evidenceIds: ids, id: `F${String(++this.findingSeq).padStart(3, "0")}`, origin };
    this.findingList.push(finding);
    return finding;
  }

  findings(): Finding[] {
    const rank = (f: Finding) => SEVERITIES.indexOf(f.severity) * 10 + CONFIDENCES.indexOf(f.confidence);
    return [...this.findingList].sort((a, b) => rank(b) - rank(a));
  }

  noteCoverage(note: CoverageNote): void {
    const i = this.coverageList.findIndex((c) => c.area === note.area);
    if (i >= 0) this.coverageList[i] = note;
    else this.coverageList.push(note);
  }

  coverage(): CoverageNote[] {
    return [...this.coverageList];
  }

  /** Evidence that has a time, oldest first. */
  timeline(opts: { from?: string | undefined; to?: string | undefined } = {}): Evidence[] {
    const from = toIso(opts.from);
    const to = toIso(opts.to);
    return this.all()
      .filter((e): e is Evidence & { time: string } => Boolean(e.time))
      .filter((e) => (!from || e.time >= from) && (!to || e.time <= to))
      .sort((a, b) => a.time.localeCompare(b.time));
  }

  /**
   * `alert` needs strong evidence: a critical finding, a high finding held with
   * high confidence, or two high findings held with at least medium confidence.
   */
  verdict(): Verdict {
    const solid = this.findingList.filter((f) => f.confidence !== "low");
    const high = solid.filter((f) => f.severity === "high");
    if (solid.some((f) => f.severity === "critical")) return "alert";
    if (high.some((f) => f.confidence === "high") || high.length >= 2) return "alert";
    if (this.findingList.some((f) => SEVERITIES.indexOf(f.severity) >= SEVERITIES.indexOf("medium"))) return "review";
    return "clear";
  }

  toJSON(): unknown {
    return {
      startedAt: this.startedAt,
      verdict: this.verdict(),
      coverage: this.coverage(),
      findings: this.findings(),
      evidence: this.all(),
    };
  }
}
