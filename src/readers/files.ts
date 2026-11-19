import { closeSync, openSync, readFileSync, readSync, statSync } from "node:fs";
import { basename, resolve } from "node:path";
import { asArray, runPowerShell } from "../collectors/powershell.js";
import { PS_EVENTS } from "../collectors/scripts.js";
import { ingestWindowsEvents, type RawEvent } from "../collectors/windows.js";
import { aggregateAuth, findBeacons, findDnsTunnels } from "../core/analysis.js";
import type { CaseStore } from "../core/store.js";
import { clean } from "../core/untrusted.js";
import { readPcap } from "./pcap.js";
import { parseSshLine, sniffTextLog, summariseWeb } from "./textlog.js";

export type FileKind = "evtx" | "pcap" | "ssh-log" | "web-log";

// Text logs are read whole, so the cap keeps memory use modest.
const MAX_TEXT_LOG_BYTES = 100 * 1024 * 1024;
const iso = (ms: number): string | undefined => (Number.isFinite(ms) && ms > 0 ? new Date(ms).toISOString() : undefined);

function magic(path: string): Buffer {
  const fd = openSync(path, "r");
  try {
    const buf = Buffer.alloc(8);
    readSync(fd, buf, 0, 8, 0);
    return buf;
  } finally {
    closeSync(fd);
  }
}

function ingestPcap(store: CaseStore, path: string, source: string): string {
  const r = readPcap(path);
  const topFlows = [...r.flows].sort((a, b) => b.bytes - a.bytes).slice(0, 1500);
  for (const f of topFlows) {
    store.add({
      kind: "flow",
      source,
      time: iso(f.first),
      summary: clean(`${f.proto} ${f.src}:${f.sport} -> ${f.sni ?? f.httpHost ?? f.dst}:${f.dport} (${f.packets} packets, ${f.bytes} bytes)`, 300),
      data: { ...f, first: iso(f.first), last: iso(f.last), sni: clean(f.sni ?? "", 255), httpHost: clean(f.httpHost ?? "", 255) },
    });
  }
  const lookups = new Map<string, { count: number; first: number; src: string }>();
  for (const q of r.dns) {
    const seen = lookups.get(q.name);
    if (seen) seen.count++;
    else lookups.set(q.name, { count: 1, first: q.time, src: q.src });
  }
  for (const [name, q] of [...lookups].slice(0, 3000)) {
    store.add({ kind: "dns", source, time: iso(q.first), summary: clean(`DNS lookup ${name} (${q.count}x) by ${q.src}`, 300), data: { name: clean(name, 255), count: q.count, src: q.src } });
  }
  for (const h of r.http.slice(0, 2000)) {
    store.add({
      kind: "http",
      source,
      time: iso(h.time),
      summary: clean(`${h.method} http://${h.host}${h.uri} from ${h.src}`, 300),
      data: { ...h, time: iso(h.time), host: clean(h.host, 255), uri: clean(h.uri, 1000), userAgent: clean(h.userAgent, 300) },
    });
  }
  for (const c of r.credentials.slice(0, 200)) {
    store.add({
      kind: "credential",
      source,
      time: iso(c.time),
      summary: clean(`${c.protocol} login "${c.user}" sent unencrypted ${c.src} -> ${c.dst}`, 300),
      data: { ...c, time: iso(c.time), user: clean(c.user, 100), password: "[redacted]" },
    });
  }
  const tcp = r.flows.filter((f) => f.proto === "tcp");
  for (const b of findBeacons(tcp.map((f) => ({ src: f.src, dst: f.dst, dport: f.dport, first: f.first, label: f.sni ?? f.httpHost }))).slice(0, 50)) {
    store.add({ kind: "beacon", source, summary: clean(`${b.src} -> ${b.label ?? b.dst}:${b.dport} every ${b.meanIntervalSec}s (${b.count} times)`, 300), data: { ...b, label: clean(b.label ?? "", 255) } });
  }
  for (const t of findDnsTunnels(r.dns.map((q) => q.name)).slice(0, 20)) {
    store.add({ kind: "dns_tunnel", source, summary: clean(`${t.uniqueLongNames} long unique names under ${t.domain}`, 300), data: { ...t, domain: clean(t.domain, 255), sample: clean(t.sample, 255) } });
  }
  return `${r.packets} packets, ${r.flows.length} flows (top ${topFlows.length} kept), ${lookups.size} DNS names, ${r.http.length} HTTP requests${r.truncated ? ". Capture exceeded a size cap, so some detail was dropped" : ""}`;
}

function ingestSshLog(store: CaseStore, lines: string[], source: string, year: number): string {
  const attempts = lines.flatMap((text, i) => {
    const e = parseSshLine(text, i + 1, year);
    return e ? [e] : [];
  });
  // Keep every success, and the first failures, as citable records; totals come from the aggregate.
  let kept = 0;
  for (const a of attempts) {
    if (!a.ok && kept >= 4000) continue;
    kept++;
    const record = store.add({
      kind: "auth",
      source,
      time: a.time,
      summary: clean(`line ${a.line}: SSH ${a.ok ? "login accepted" : "login failed"} user=${a.user} from=${a.ip}`, 300),
      data: { line: a.line, ok: a.ok, user: clean(a.user, 100), ip: clean(a.ip, 60), method: clean(a.method, 60) },
    });
    a.evidenceId = record.id;
  }
  const sources = aggregateAuth(attempts);
  for (const src of sources.slice(0, 500)) {
    store.add({ kind: "auth_source", source, time: src.first, summary: `${src.ip}: ${src.failures} failed and ${src.successes} successful SSH logins`, data: { ...src, ip: clean(src.ip, 60), users: src.users.map((u) => clean(u, 100)) } });
  }
  return `${attempts.length} SSH login attempts from ${sources.length} addresses`;
}

function ingestWebLog(store: CaseStore, lines: string[], source: string): string {
  const r = summariseWeb(lines);
  for (const h of r.hits) {
    store.add({
      kind: "web_request",
      source,
      time: h.time,
      summary: clean(`line ${h.line}: ${h.attack} from ${h.ip}: ${h.method} ${h.path} -> ${h.status}`, 300),
      data: { ...h, ip: clean(h.ip, 60), path: clean(h.path, 1000), userAgent: clean(h.userAgent, 300) },
    });
  }
  for (const c of r.clients) {
    store.add({ kind: "web_client", source, time: c.first, summary: `${c.ip}: ${c.requests} requests, ${c.errors} errors`, data: { ...c, ip: clean(c.ip, 60) } });
  }
  return `${r.requests} requests, ${r.hits.length} carrying attack payloads`;
}

/**
 * Read one evidence file into the case. The type is detected from the file's contents,
 * never from its name. Returns what kind of file it was.
 */
export async function readEvidenceFile(store: CaseStore, inputPath: string): Promise<FileKind> {
  const path = resolve(inputPath);
  const stat = statSync(path);
  if (!stat.isFile()) throw new Error(`Not a file: ${path}`);
  const source = `file:${basename(path)}`;
  const head = magic(path);
  const le = head.readUInt32LE(0);

  if (head.toString("latin1", 0, 7) === "ElfFile") {
    if (process.platform !== "win32") {
      store.noteCoverage({ area: source, status: "skipped", note: "EVTX files need Windows in this version. A cross-platform parser is on the roadmap." });
      return "evtx";
    }
    const r = await runPowerShell<{ events: RawEvent[] | null; gaps: string[] | null }>(PS_EVENTS, { path }, 300_000);
    const added = ingestWindowsEvents(store, asArray(r.events), source);
    const gaps = asArray(r.gaps);
    store.noteCoverage({ area: source, status: gaps.length ? "partial" : "checked", note: `${added} relevant events${gaps.length ? `. Problems: ${clean(gaps.join("; "), 300)}` : ""}. Only security-relevant event IDs are read.` });
    return "evtx";
  }

  if (le === 0x0a0d0d0a || [0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1].includes(le)) {
    store.noteCoverage({ area: source, status: "checked", note: `${ingestPcap(store, path, source)}. Encrypted traffic is seen only as destinations and timing.` });
    return "pcap";
  }

  if (stat.size > MAX_TEXT_LOG_BYTES) throw new Error(`Text log is larger than ${MAX_TEXT_LOG_BYTES / 1024 / 1024} MB. Split it first.`);
  const lines = readFileSync(path, "utf8").split(/\r?\n/);
  const kind = sniffTextLog(lines);
  if (kind === "ssh") {
    store.noteCoverage({ area: source, status: "checked", note: `${ingestSshLog(store, lines, source, stat.mtime.getUTCFullYear())}. Only sshd lines are read.` });
    return "ssh-log";
  }
  if (kind === "web") {
    store.noteCoverage({ area: source, status: "checked", note: `${ingestWebLog(store, lines, source)}. Request bodies are not in access logs, so POST payloads are invisible.` });
    return "web-log";
  }
  throw new Error("Unrecognised file. Supported: .evtx, pcap/pcapng, SSH auth logs, and web access logs in common/combined format.");
}
