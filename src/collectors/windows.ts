import { readFileSync } from "node:fs";
import { join, win32 } from "node:path";
import { aggregateAuth, exePathFromCommand, type AuthAttempt } from "../core/analysis.js";
import type { CaseStore } from "../core/store.js";
import { clean } from "../core/untrusted.js";
import { asArray, BOOTSTRAP, PREAMBLE, runPowerShell } from "./powershell.js";
import * as ps from "./scripts.js";

export const LIVE_AREAS = ["autoruns", "tasks", "services", "processes", "network", "defender", "accounts", "hosts", "events"] as const;
export type LiveArea = (typeof LIVE_AREAS)[number];

export interface LiveOptions {
  areas?: LiveArea[] | undefined;
  /** How many days of event logs to read. */
  days?: number | undefined;
}

interface Signature {
  path: string;
  status: string;
  signer: string;
}

const SIGNABLE = /\.(exe|dll|sys|scr|com|cpl)$/i;
const MAX_SIGNATURE_PATHS = 400;

const windir = (): string => (process.env.SystemRoot ?? "C:\\Windows").toLowerCase();
const underWindows = (path: string): boolean => path.toLowerCase().startsWith(`${windir()}\\`);
/** Store apps are signed as a package, so a per-file check wrongly reports them unsigned. */
const storeApp = (path: string): boolean => /\\program files\\windowsapps\\/i.test(path);
const normal = (path: string): string => (path ? win32.normalize(path) : path);

const squash = (text: string): string => text.replace(/\s+/g, " ").trim();
const OWN_SCRIPTS = [BOOTSTRAP, ...Object.values(ps).map((script) => `${PREAMBLE}\n${script}`)].map(squash);

/**
 * True when a logged script block is one of this tool's own collector scripts.
 * It must match our script text exactly, so nothing else can hide behind this.
 */
export function isOwnScript(text: string): boolean {
  const block = squash(text);
  return block.length >= 40 && OWN_SCRIPTS.some((own) => own.includes(block));
}

/** Publisher signatures for files outside the Windows folder, in batches that fit an environment variable. */
async function signatures(paths: string[]): Promise<Map<string, Signature>> {
  const wanted = [...new Set(paths.map(normal).filter((p) => p && SIGNABLE.test(p) && !underWindows(p) && !storeApp(p)))].slice(0, MAX_SIGNATURE_PATHS);
  const out = new Map<string, Signature>();
  let batch: string[] = [];
  let size = 0;
  const flush = async (): Promise<void> => {
    if (batch.length === 0) return;
    for (const sig of asArray(await runPowerShell<Signature | Signature[]>(ps.PS_SIGNATURES, batch, 180_000))) {
      out.set(sig.path.toLowerCase(), sig);
    }
    batch = [];
    size = 0;
  };
  for (const p of wanted) {
    if (size + p.length > 20_000) await flush();
    batch.push(p);
    size += p.length + 4;
  }
  await flush();
  return out;
}

const signatureOf = (map: Map<string, Signature>, path: string): { signature: string; signer: string } => {
  const sig = map.get(normal(path).toLowerCase());
  return { signature: sig?.status ?? "", signer: clean(sig?.signer ?? "", 200) };
};

interface Launchable {
  name: string;
  command: string;
  [key: string]: unknown;
}

/** Autoruns, scheduled tasks and services share a shape: a named thing that launches a command. */
async function collectLaunchables(store: CaseStore, kind: string, source: string, script: string, describe: (x: Launchable) => string): Promise<number> {
  const items = asArray(await runPowerShell<Launchable | Launchable[]>(script)).filter((x) => x.command || kind === "autorun");
  const withPath = items.map((x) => ({ ...x, path: exePathFromCommand(String(x.command ?? "")) }));
  const sigs = await signatures(withPath.map((x) => x.path));
  for (const x of withPath) {
    const data: Record<string, unknown> = { ...x, ...signatureOf(sigs, x.path) };
    for (const key of Object.keys(data)) if (typeof data[key] === "string") data[key] = clean(data[key], 1000);
    store.add({ kind, source, summary: clean(describe(x), 300), data });
  }
  return withPath.length;
}

interface RawProcess {
  pid: number;
  ppid: number;
  name: string;
  path: string;
  commandLine: string;
  started: string | null;
}

interface RawConnection {
  state: string;
  localAddress: string;
  localPort: number;
  remoteAddress: string;
  remotePort: number;
  pid: number;
}

async function collectProcesses(store: CaseStore, withNetwork: boolean): Promise<{ processes: number; connections: number }> {
  const all = asArray(await runPowerShell<RawProcess | RawProcess[]>(ps.PS_PROCESSES));
  // Leave out this tool and the PowerShell collectors it started.
  const own = new Set<number>([process.pid]);
  for (const p of all) if (own.has(p.ppid)) own.add(p.pid);
  for (const p of all) if (own.has(p.ppid)) own.add(p.pid);
  const procs = all.filter((p) => !own.has(p.pid));
  const byPid = new Map(all.map((p) => [p.pid, p]));
  const sigs = await signatures(procs.map((p) => p.path));

  for (const p of procs) {
    store.add({
      kind: "process",
      source: "live:processes",
      time: p.started ?? undefined,
      summary: clean(`${p.name} (pid ${p.pid}) ${p.path || "path not readable"}`, 300),
      data: {
        pid: p.pid, ppid: p.ppid, name: clean(p.name, 200), path: clean(p.path, 500),
        commandLine: clean(p.commandLine, 1500), parentName: clean(byPid.get(p.ppid)?.name ?? "", 200),
        ...signatureOf(sigs, p.path ?? ""),
      },
    });
  }
  if (!withNetwork) return { processes: procs.length, connections: 0 };

  const loopback = (a: string): boolean => a.startsWith("127.") || a === "::1";
  const seen = new Set<string>();
  let connections = 0;
  for (const c of asArray(await runPowerShell<RawConnection | RawConnection[]>(ps.PS_NETWORK))) {
    if (c.state === "Established" && (loopback(c.remoteAddress) || loopback(c.localAddress))) continue;
    const key = c.state === "Listen" ? `L|${c.localAddress}|${c.localPort}|${c.pid}` : `E|${c.remoteAddress}|${c.remotePort}|${c.pid}`;
    if (seen.has(key) || connections >= 600) continue;
    seen.add(key);
    const owner = byPid.get(c.pid);
    store.add({
      kind: "connection",
      source: "live:network",
      summary: c.state === "Listen"
        ? `${owner?.name ?? `pid ${c.pid}`} listening on ${c.localAddress}:${c.localPort}`
        : `${owner?.name ?? `pid ${c.pid}`} connected to ${c.remoteAddress}:${c.remotePort}`,
      data: { ...c, processName: clean(owner?.name ?? "", 200), processPath: clean(owner?.path ?? "", 500), ...signatureOf(sigs, owner?.path ?? "") },
    });
    connections++;
  }
  return { processes: procs.length, connections };
}

interface DefenderResult {
  status: Record<string, unknown> | null;
  detections: Array<Record<string, unknown>> | null;
  products: string[] | null;
}

async function collectDefender(store: CaseStore): Promise<string> {
  const r = await runPowerShell<DefenderResult>(ps.PS_DEFENDER);
  const others = asArray(r.products).filter((p) => p && !/windows defender|microsoft defender/i.test(p));
  if (r.status) {
    store.add({
      kind: "defender",
      source: "live:defender",
      summary: `Defender real-time protection ${r.status.realTimeProtectionEnabled ? "on" : "off"}; signatures ${String(r.status.signatureAgeDays)} day(s) old`,
      // With another antivirus installed, Defender steps aside by design.
      data: { ...r.status, otherAntivirus: others, runningMode: others.length > 0 ? `Passive (${others.join(", ")})` : r.status.runningMode },
    });
  }
  for (const d of asArray(r.detections)) {
    store.add({
      kind: "detection",
      source: "live:defender",
      time: typeof d.time === "string" ? d.time : undefined,
      summary: clean(`Defender detected ${String(d.threat || "a threat")} in ${String(d.path)}`, 300),
      data: { ...d, threat: clean(d.threat, 200), path: clean(d.path, 800), process: clean(d.process, 300) },
    });
  }
  return r.status ? `status read, ${asArray(r.detections).length} recorded detection(s)` : "Defender status not available";
}

export interface RawEvent {
  log: string;
  eventId: number;
  provider: string;
  time: string;
  fields: Record<string, string> | null;
}

const EVENT_LABELS: Record<number, string> = {
  4624: "successful network logon", 4625: "failed logon", 4720: "user account created", 4732: "member added to a local group",
  1102: "Security log cleared", 104: "event log cleared", 7045: "service installed", 4104: "PowerShell script block",
  1116: "Defender detected malware", 1117: "Defender acted on malware",
};

/** Turn raw Windows events into evidence, plus one auth_source record per remote address. */
export function ingestWindowsEvents(store: CaseStore, events: RawEvent[], source: string): number {
  const attempts: AuthAttempt[] = [];
  let added = 0;
  for (const e of events) {
    const fields: Record<string, string> = {};
    for (const [k, v] of Object.entries(e.fields ?? {})) fields[k] = clean(v, 2000);
    const networkLogon = e.eventId === 4624 && ["3", "10"].includes(fields.LogonType ?? "");
    if (e.eventId === 4624 && !networkLogon) continue;
    if (e.eventId === 4104 && isOwnScript(e.fields?.ScriptBlockText ?? "")) continue;
    const who = fields.TargetUserName ? ` user=${fields.TargetUserName}` : "";
    const from = fields.IpAddress && fields.IpAddress !== "-" ? ` from=${fields.IpAddress}` : "";
    const record = store.add({
      kind: "event",
      source,
      time: e.time,
      summary: clean(`${e.log} ${e.eventId} ${EVENT_LABELS[e.eventId] ?? ""}${who}${from}`, 300),
      data: { log: clean(e.log, 200), eventId: e.eventId, provider: clean(e.provider, 200), fields },
    });
    added++;
    if (e.eventId === 4625 || networkLogon) {
      attempts.push({ evidenceId: record.id, ip: fields.IpAddress ?? "", user: fields.TargetUserName ?? "", ok: e.eventId === 4624, time: e.time });
    }
  }
  for (const src of aggregateAuth(attempts)) {
    if (src.failures === 0) continue;
    store.add({
      kind: "auth_source",
      source,
      time: src.first,
      summary: `${src.ip}: ${src.failures} failed and ${src.successes} successful logons`,
      data: { ...src },
    });
  }
  return added;
}

interface EventsResult {
  events: RawEvent[] | null;
  gaps: string[] | null;
  admin: boolean;
}

function collectHosts(store: CaseStore): number {
  const text = readFileSync(join(process.env.SystemRoot ?? "C:\\Windows", "System32", "drivers", "etc", "hosts"), "utf8");
  let count = 0;
  for (const line of text.split(/\r?\n/)) {
    const [ip, ...hosts] = line.replace(/#.*$/, "").trim().split(/\s+/);
    if (!ip || hosts.length === 0) continue;
    for (const host of hosts) {
      store.add({ kind: "hosts", source: "live:hosts", summary: clean(`hosts file: ${host} -> ${ip}`, 200), data: { ip: clean(ip, 60), host: clean(host, 255) } });
      count++;
    }
  }
  return count;
}

/** Inspect the machine this process runs on. Read-only. Records what it could not check. */
export async function scanLive(store: CaseStore, opts: LiveOptions = {}): Promise<void> {
  const areas = opts.areas?.length ? opts.areas : [...LIVE_AREAS];
  const days = Math.min(Math.max(Math.trunc(opts.days ?? 7), 1), 90);

  if (process.platform !== "win32") {
    store.noteCoverage({ area: "live", status: "skipped", note: `Live scan supports Windows only in this version (this is ${process.platform}). Evidence files still work.` });
    return;
  }

  const run = async (area: LiveArea, work: () => Promise<string>): Promise<void> => {
    if (!areas.includes(area)) return;
    try {
      store.noteCoverage({ area, status: "checked", note: await work() });
    } catch (err) {
      store.noteCoverage({ area, status: "skipped", note: `Could not read: ${clean((err as Error).message, 200)}` });
    }
  };

  await run("autoruns", async () => {
    const count = await collectLaunchables(store, "autorun", "live:autoruns", ps.PS_AUTORUNS, (x) => `${String(x.location)}: ${x.name} -> ${x.command}`);
    return `${count} startup entries (Run keys, Winlogon, Startup folders). WMI and browser-extension persistence are not checked yet.`;
  });
  await run("tasks", async () => {
    const count = await collectLaunchables(store, "task", "live:tasks", ps.PS_TASKS, (x) => `Task ${x.name} -> ${x.command}`);
    return `${count} scheduled tasks outside \\Microsoft\\. Tasks under \\Microsoft\\ are not checked.`;
  });
  await run("services", async () => {
    const count = await collectLaunchables(store, "service", "live:services", ps.PS_SERVICES, (x) => `Service ${x.name} -> ${x.command}`);
    return `${count} services`;
  });

  const wantNetwork = areas.includes("network");
  if (areas.includes("processes") || wantNetwork) {
    try {
      const r = await collectProcesses(store, wantNetwork);
      if (areas.includes("processes")) store.noteCoverage({ area: "processes", status: "checked", note: `${r.processes} running processes. Paths of protected system processes are hidden without administrator rights.` });
      if (wantNetwork) store.noteCoverage({ area: "network", status: "checked", note: `${r.connections} TCP listeners and connections right now. Past connections and UDP are not visible.` });
    } catch (err) {
      store.noteCoverage({ area: "processes", status: "skipped", note: `Could not read: ${clean((err as Error).message, 200)}` });
    }
  }

  await run("defender", () => collectDefender(store));
  await run("accounts", async () => {
    const users = asArray(await runPowerShell<Record<string, unknown> | Array<Record<string, unknown>>>(ps.PS_ACCOUNTS));
    for (const u of users) {
      store.add({
        kind: "account",
        source: "live:accounts",
        time: typeof u.lastLogon === "string" ? u.lastLogon : undefined,
        summary: clean(`Local account ${String(u.name)}${u.isAdmin ? " (administrator)" : ""}${u.enabled ? "" : " (disabled)"}`, 200),
        data: { ...u, name: clean(u.name, 100) },
      });
    }
    return `${users.length} local accounts`;
  });
  await run("hosts", async () => `${collectHosts(store)} hosts file entries`);

  if (areas.includes("events")) {
    try {
      const r = await runPowerShell<EventsResult>(ps.PS_EVENTS, { days }, 180_000);
      const added = ingestWindowsEvents(store, asArray(r.events), "live:events");
      const gaps = asArray(r.gaps);
      store.noteCoverage({
        area: "events",
        status: gaps.length > 0 || !r.admin ? "partial" : "checked",
        note: `${added} relevant events from the last ${days} day(s).${r.admin ? "" : " Not running as administrator, so the Security log (logons, account changes, log clearing) could not be read."}${gaps.length > 0 && r.admin ? ` Unreadable: ${clean(gaps.join("; "), 300)}` : ""}`,
      });
    } catch (err) {
      store.noteCoverage({ area: "events", status: "skipped", note: `Could not read: ${clean((err as Error).message, 200)}` });
    }
  }
}
