import { webAttackReason, type AuthAttempt } from "../core/analysis.js";

/** Parsers for the two text logs people most often have: SSH auth logs and web access logs. */

export interface SshEvent extends AuthAttempt {
  line: number;
  method: string;
}

export interface WebHit {
  line: number;
  time?: string | undefined;
  ip: string;
  method: string;
  path: string;
  status: number;
  userAgent: string;
  attack: string;
}

export interface WebClient {
  ip: string;
  requests: number;
  errors: number;
  first?: string | undefined;
  last?: string | undefined;
}

const MONTHS: Record<string, number> = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };

const SYSLOG = /^(?:(\d{4}-\d\d-\d\dT[\d:.]+(?:Z|[+-]\d\d:?\d\d)?)|([A-Z][a-z]{2})\s+(\d{1,2})\s(\d\d):(\d\d):(\d\d))\s+\S+\s+sshd(?:\[\d+\])?:\s+(.*)$/;
const SSH_FAILED = /^Failed (password|publickey|keyboard-interactive\/pam|none) for (?:invalid user )?(\S+) from (\S+)/;
const SSH_INVALID = /^(?:Invalid user|Connection closed by invalid user|Disconnected from invalid user) (\S+)(?: from)? (\S+)/;
const SSH_ACCEPTED = /^Accepted (\S+) for (\S+) from (\S+)/;

/** Classic syslog lines carry no year, so the caller supplies one (usually the file's). */
function syslogTime(m: RegExpExecArray, year: number): string | undefined {
  if (m[1]) {
    const d = new Date(m[1]);
    return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
  }
  const month = MONTHS[(m[2] ?? "").toLowerCase()];
  if (month === undefined) return undefined;
  return new Date(Date.UTC(year, month, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]))).toISOString();
}

/** One SSH login attempt from an auth.log / secure line, or null for any other line. */
export function parseSshLine(text: string, line: number, year: number): SshEvent | null {
  const m = SYSLOG.exec(text);
  if (!m) return null;
  const message = m[7] ?? "";
  const time = syslogTime(m, year);
  let hit = SSH_FAILED.exec(message);
  if (hit) return { line, time, ok: false, method: hit[1] ?? "", user: hit[2] ?? "", ip: hit[3] ?? "" };
  hit = SSH_ACCEPTED.exec(message);
  if (hit) return { line, time, ok: true, method: hit[1] ?? "", user: hit[2] ?? "", ip: hit[3] ?? "" };
  hit = SSH_INVALID.exec(message);
  if (hit) return { line, time, ok: false, method: "invalid user", user: hit[1] ?? "", ip: hit[2] ?? "" };
  return null;
}

const ACCESS = /^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]{3,10}) (\S*)[^"]*" (\d{3}) \S+(?: "[^"]*" "([^"]*)")?/;
const ACCESS_TIME = /^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d\d):(\d\d):(\d\d) ([+-])(\d\d)(\d\d)$/;

function accessTime(raw: string): string | undefined {
  const m = ACCESS_TIME.exec(raw);
  const month = m ? MONTHS[(m[2] ?? "").toLowerCase()] : undefined;
  if (!m || month === undefined) return undefined;
  const utc = Date.UTC(Number(m[3]), month, Number(m[1]), Number(m[4]), Number(m[5]), Number(m[6]));
  const offset = (Number(m[8]) * 60 + Number(m[9])) * 60_000 * (m[7] === "-" ? -1 : 1);
  return new Date(utc - offset).toISOString();
}

export interface WebLine {
  time?: string | undefined;
  ip: string;
  method: string;
  path: string;
  status: number;
  userAgent: string;
}

/** One request from a common/combined format access log line, or null. */
export function parseAccessLine(text: string): WebLine | null {
  const m = ACCESS.exec(text);
  if (!m) return null;
  return { ip: m[1] ?? "", time: accessTime(m[2] ?? ""), method: m[3] ?? "", path: m[4] ?? "", status: Number(m[5]), userAgent: m[6] ?? "" };
}

export type TextLogKind = "ssh" | "web" | "unknown";

/** Decide what a text log is from its first lines. */
export function sniffTextLog(lines: string[]): TextLogKind {
  let ssh = 0;
  let web = 0;
  for (const line of lines.slice(0, 200)) {
    if (SYSLOG.test(line)) ssh++;
    else if (ACCESS.test(line)) web++;
  }
  if (ssh === 0 && web === 0) return "unknown";
  return ssh >= web ? "ssh" : "web";
}

export interface WebSummary {
  requests: number;
  hits: WebHit[];
  clients: WebClient[];
}

/** Attack-looking requests, plus the busiest clients, from access log lines. */
export function summariseWeb(lines: Iterable<string>, maxHits = 3000): WebSummary {
  const hits: WebHit[] = [];
  const clients = new Map<string, WebClient>();
  let requests = 0;
  let lineNo = 0;
  for (const text of lines) {
    lineNo++;
    const r = parseAccessLine(text);
    if (!r) continue;
    requests++;
    const c = clients.get(r.ip) ?? { ip: r.ip, requests: 0, errors: 0, first: r.time, last: r.time };
    c.requests++;
    if (r.status >= 400) c.errors++;
    if (r.time) c.last = r.time;
    clients.set(r.ip, c);
    const attack = webAttackReason(r.path, r.userAgent);
    if (attack && hits.length < maxHits) hits.push({ ...r, line: lineNo, attack });
  }
  return { requests, hits, clients: [...clients.values()].sort((a, b) => b.requests - a.requests).slice(0, 50) };
}
