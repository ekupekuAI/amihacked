/** Pure analysis helpers shared by collectors, readers and rules. No I/O. */

const EXECUTABLE_EXT = /\.(exe|dll|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|scr|com|msi|lnk|pif|cpl)\b/i;

/** Expand %VAR% using the given environment (case-insensitive names). */
export function expandEnv(text: string, env: Record<string, string | undefined> = process.env): string {
  const lower = new Map(Object.entries(env).map(([k, v]) => [k.toLowerCase(), v]));
  return text.replace(/%([^%]+)%/g, (whole, name: string) => lower.get(name.toLowerCase()) ?? whole);
}

/**
 * The executable or script a Windows command line launches.
 * Handles quoted paths, unquoted paths with spaces, and %VAR% references.
 */
export function exePathFromCommand(command: string, env?: Record<string, string | undefined>): string {
  const text = expandEnv(command.trim(), env);
  if (!text) return "";
  if (text.startsWith('"')) {
    const end = text.indexOf('"', 1);
    return end > 1 ? text.slice(1, end) : text.slice(1);
  }
  const match = EXECUTABLE_EXT.exec(text);
  if (match) return text.slice(0, match.index + match[0].length);
  return text.split(/\s+/)[0] ?? "";
}

const USER_WRITABLE = [
  /\\appdata\\local\\temp\\/i,
  /\\windows\\temp\\/i,
  /\\users\\public\\/i,
  /\\\$recycle\.bin\\/i,
  /\\users\\[^\\]+\\downloads\\/i,
  /^[a-z]:\\temp\\/i,
  /^[a-z]:\\tmp\\/i,
  /\\perflogs\\/i,
];

/** True for folders any user can write to, where installed software rarely lives. */
export function isUserWritablePath(path: string): boolean {
  return USER_WRITABLE.some((p) => p.test(path));
}

const LOLBIN_PATTERNS: Array<[RegExp, string]> = [
  [/powershell(\.exe)?["']?\s.*\s-(e|ec|enc|encodedcommand)\s+[a-z0-9+/=]{20,}/i, "PowerShell running an encoded command"],
  [/\b(downloadstring|downloadfile|downloaddata)\b|\bfrombase64string\b/i, "downloads or decodes code at run time"],
  [/\b(iex|invoke-expression)\b.*\b(new-object|iwr|irm|invoke-webrequest|invoke-restmethod|net\.webclient)\b/i, "runs code fetched from the network"],
  [/\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b.*\|\s*(iex|invoke-expression)\b/i, "runs code fetched from the network"],
  [/mshta(\.exe)?["']?\s+["']?(https?:|javascript:|vbscript:)/i, "mshta running remote or inline script"],
  [/regsvr32(\.exe)?["']?\s.*\/i:\s*["']?https?:/i, "regsvr32 loading a remote scriptlet"],
  [/rundll32(\.exe)?["']?\s.*(javascript:|vbscript:)/i, "rundll32 running inline script"],
  [/certutil(\.exe)?["']?\s.*-(urlcache|decode)\b/i, "certutil used to download or decode a file"],
  [/bitsadmin(\.exe)?["']?\s.*\/transfer\b/i, "bitsadmin file transfer"],
  [/(wscript|cscript)(\.exe)?["']?\s.*\\(temp|appdata|public)\\/i, "script host running a script from a user-writable folder"],
];

/** Why a command line looks like living-off-the-land abuse, or null. */
export function lolbinReason(command: string): string | null {
  for (const [pattern, reason] of LOLBIN_PATTERNS) if (pattern.test(command)) return reason;
  return null;
}

const SCRIPT_BLOCK_PATTERNS: Array<[RegExp, string]> = [
  [/\b(iex|invoke-expression)\b[\s\S]{0,200}\b(downloadstring|downloaddata|net\.webclient|invoke-webrequest|invoke-restmethod|iwr|irm)\b/i, "runs code fetched from the network"],
  [/\b(downloadstring|invoke-webrequest|invoke-restmethod|iwr|irm)\b[\s\S]{0,200}\|\s*(iex|invoke-expression)\b/i, "runs code fetched from the network"],
  [/amsiutils|amsiinitfailed|amsiscanbuffer/i, "tampers with the antimalware scan interface"],
  [/virtualalloc[\s\S]{0,600}(createthread|rtlmovememory)/i, "loads raw code into memory"],
  [/\bfrombase64string\b[\s\S]{0,300}\b(iex|invoke-expression|reflection\.assembly\]::load)\b/i, "decodes and runs hidden code"],
];

/** Why a logged PowerShell script block looks hostile, or null. Stricter than lolbinReason: script text is noisy. */
export function scriptBlockReason(text: string): string | null {
  for (const [pattern, reason] of SCRIPT_BLOCK_PATTERNS) if (pattern.test(text)) return reason;
  return null;
}

/** Windows binaries malware commonly impersonates, and where the real ones live. */
const SYSTEM_BINARIES = new Set([
  "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "wininit.exe",
  "explorer.exe", "spoolsv.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe", "rundll32.exe", "lsm.exe",
]);

/** True when a process uses a core Windows binary name but runs from outside Windows' folder. */
export function isMasquerade(name: string, path: string, windir = process.env.SystemRoot ?? "C:\\Windows"): boolean {
  if (!path || !SYSTEM_BINARIES.has(name.toLowerCase())) return false;
  return !path.toLowerCase().startsWith(`${windir.toLowerCase()}\\`);
}

export interface AuthAttempt {
  evidenceId?: string | undefined;
  ip: string;
  user: string;
  ok: boolean;
  time?: string | undefined;
}

export interface AuthSource {
  ip: string;
  failures: number;
  successes: number;
  users: string[];
  first?: string | undefined;
  last?: string | undefined;
  /** A success that came after at least `minFailures` failures from the same address. */
  successAfterFailures: boolean;
  evidenceIds: string[];
}

/** Group login attempts by source address and spot password guessing. */
export function aggregateAuth(attempts: AuthAttempt[], minFailures = 5): AuthSource[] {
  const groups = new Map<string, AuthAttempt[]>();
  for (const a of attempts) {
    if (!a.ip || a.ip === "-" || a.ip === "::1" || a.ip === "127.0.0.1") continue;
    const list = groups.get(a.ip) ?? [];
    list.push(a);
    groups.set(a.ip, list);
  }
  const out: AuthSource[] = [];
  for (const [ip, list] of groups) {
    list.sort((a, b) => (a.time ?? "").localeCompare(b.time ?? ""));
    let failuresSoFar = 0;
    let successAfterFailures = false;
    for (const a of list) {
      if (a.ok) {
        if (failuresSoFar >= minFailures) successAfterFailures = true;
      } else failuresSoFar++;
    }
    out.push({
      ip,
      failures: failuresSoFar,
      successes: list.length - failuresSoFar,
      users: [...new Set(list.map((a) => a.user).filter(Boolean))].slice(0, 20),
      first: list[0]?.time,
      last: list[list.length - 1]?.time,
      successAfterFailures,
      evidenceIds: list.map((a) => a.evidenceId).filter((x): x is string => Boolean(x)).slice(0, 25),
    });
  }
  return out.sort((a, b) => b.failures - a.failures);
}

export interface ConnectionStart {
  src: string;
  dst: string;
  dport: number;
  /** Milliseconds since epoch. */
  first: number;
  label?: string | undefined;
}

export interface Beacon {
  src: string;
  dst: string;
  dport: number;
  count: number;
  meanIntervalSec: number;
  /** Standard deviation of the interval divided by its mean. 0 is perfectly regular. */
  jitter: number;
  label?: string | undefined;
}

/**
 * Connections repeating at a steady interval: the shape of malware checking in.
 * Software updaters and telemetry look the same, so this is a lead, not proof.
 */
export function findBeacons(starts: ConnectionStart[], minCount = 8, maxJitter = 0.15, minIntervalSec = 5): Beacon[] {
  const groups = new Map<string, ConnectionStart[]>();
  for (const s of starts) {
    const key = `${s.src}|${s.dst}|${s.dport}`;
    const list = groups.get(key) ?? [];
    list.push(s);
    groups.set(key, list);
  }
  const out: Beacon[] = [];
  for (const list of groups.values()) {
    if (list.length < minCount) continue;
    const times = list.map((s) => s.first).sort((a, b) => a - b);
    const gaps: number[] = [];
    for (let i = 1; i < times.length; i++) gaps.push(((times[i] ?? 0) - (times[i - 1] ?? 0)) / 1000);
    const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
    if (mean < minIntervalSec) continue;
    const variance = gaps.reduce((a, b) => a + (b - mean) ** 2, 0) / gaps.length;
    const jitter = Math.sqrt(variance) / mean;
    if (jitter > maxJitter) continue;
    const head = list[0];
    if (!head) continue;
    out.push({
      src: head.src,
      dst: head.dst,
      dport: head.dport,
      count: list.length,
      meanIntervalSec: Math.round(mean * 10) / 10,
      jitter: Math.round(jitter * 1000) / 1000,
      label: list.find((s) => s.label)?.label,
    });
  }
  return out.sort((a, b) => b.count - a.count);
}

export interface DnsTunnelSuspect {
  domain: string;
  uniqueLongNames: number;
  longestLabel: number;
  sample: string;
}

/** Many long, unique subdomains under one domain: the shape of data smuggled over DNS. */
export function findDnsTunnels(names: string[], minUnique = 15, minLabel = 24): DnsTunnelSuspect[] {
  const groups = new Map<string, Set<string>>();
  for (const raw of names) {
    const name = raw.toLowerCase().replace(/\.$/, "");
    const labels = name.split(".");
    if (labels.length < 3) continue;
    const longest = Math.max(...labels.slice(0, -2).map((l) => l.length));
    if (longest < minLabel) continue;
    const parent = labels.slice(-2).join(".");
    const set = groups.get(parent) ?? new Set<string>();
    set.add(name);
    groups.set(parent, set);
  }
  const out: DnsTunnelSuspect[] = [];
  for (const [domain, set] of groups) {
    if (set.size < minUnique) continue;
    const all = [...set];
    out.push({
      domain,
      uniqueLongNames: set.size,
      longestLabel: Math.max(...all.flatMap((n) => n.split(".").map((l) => l.length))),
      sample: all[0] ?? "",
    });
  }
  return out.sort((a, b) => b.uniqueLongNames - a.uniqueLongNames);
}

const WEB_ATTACKS: Array<[RegExp, string]> = [
  [/(\bunion\b.{0,20}\bselect\b|'\s*or\s*'?1'?\s*=\s*'?1|\bsleep\s*\(\s*\d+\s*\)|information_schema)/i, "SQL injection"],
  [/(\.\.[\\/]){2,}|\/etc\/passwd|\/proc\/self\/environ|boot\.ini|win\.ini/i, "path traversal"],
  [/<script\b|onerror\s*=|javascript:/i, "cross-site scripting"],
  [/(\bcmd|\bexec|\bcommand|\bshell)=|;\s*(cat|wget|curl|bash|sh|nc)\s|\$\(|`.+`|\|\s*(id|whoami|uname)\b/i, "command injection"],
  [/\$\{jndi:/i, "Log4Shell (JNDI lookup)"],
  [/\/(wp-login\.php|xmlrpc\.php|\.env|\.git\/config|phpmyadmin|actuator\/env)\b/i, "probing for exposed files or logins"],
];

const SCANNER_AGENTS = /sqlmap|nikto|nmap|masscan|wpscan|dirbuster|gobuster|nuclei|acunetix|zgrab|hydra|feroxbuster/i;

/** Attack technique visible in one web request, or null. */
export function webAttackReason(path: string, userAgent = ""): string | null {
  // Bound the work: a log line can carry a megabyte-long path.
  const head = path.slice(0, 4000);
  let decoded = head;
  try {
    decoded = decodeURIComponent(head.replace(/\+/g, " "));
  } catch {
    // keep the raw path when it is not valid percent-encoding
  }
  for (const [pattern, reason] of WEB_ATTACKS) if (pattern.test(decoded)) return reason;
  if (SCANNER_AGENTS.test(userAgent)) return "automated scanner";
  return null;
}
