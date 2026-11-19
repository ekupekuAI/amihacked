import { isMasquerade, isUserWritablePath, lolbinReason, scriptBlockReason } from "../core/analysis.js";
import type { CaseStore, Evidence, Finding, FindingInput } from "../core/store.js";
import { looksLikeInjection } from "../core/untrusted.js";

export interface Rule {
  id: string;
  describe: string;
  run(store: CaseStore): FindingInput[];
}

const s = (e: Evidence, key: string): string => {
  const v = e.data[key];
  return v === null || v === undefined ? "" : String(v);
};
const n = (e: Evidence, key: string): number => Number(e.data[key] ?? 0);
const b = (e: Evidence, key: string): boolean => e.data[key] === true;

const PERSISTENCE: Record<string, { label: string; technique: string }> = {
  autorun: { label: "Startup entry", technique: "T1547.001" },
  task: { label: "Scheduled task", technique: "T1053.005" },
  service: { label: "Service", technique: "T1543.003" },
};

const OFFICE_APPS = new Set(["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "onenote.exe"]);
const SHELLS = new Set(["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"]);
const REMOTE_TOOLS =
  /^(anydesk|teamviewer|teamviewer_service|rustdesk|screenconnect\.clientservice|ngrok|tailscaled?|logmein|lmiguardiansvc|vncserver|winvnc|tvnserver|splashtopstreamer|ammyy|supremo|atera_agent|remoteutilities|rutserv|meshagent|cloudflared|frpc|chisel)(\.exe)?$/i;
const SENSITIVE_HOSTS =
  /(microsoft|windowsupdate|google|gmail|apple|icloud|paypal|amazon|facebook|github|bank|kaspersky|avast|avg|bitdefender|malwarebytes|eset|norton|mcafee|sophos|virustotal|defender)/i;

export const rules: Rule[] = [
  {
    id: "persist-lolbin",
    describe: "Something that starts automatically runs a script interpreter in a way malware favours.",
    run: (store) =>
      Object.keys(PERSISTENCE).flatMap((kind) =>
        store.all(kind).flatMap((e): FindingInput[] => {
          const reason = lolbinReason(s(e, "command"));
          const meta = PERSISTENCE[kind];
          if (!reason || !meta) return [];
          return [{
            ruleId: "persist-lolbin",
            title: `${meta.label} "${s(e, "name")}" ${reason}`,
            severity: "high",
            confidence: "medium",
            technique: meta.technique,
            evidenceIds: [e.id],
            why: `It runs at startup or on a schedule, and its command ${reason}. Legitimate software rarely needs this.`,
            benign: "Some admin scripts and a few installers do this. Check who created it and when.",
          }];
        }),
      ),
  },
  {
    id: "persist-writable-path",
    describe: "Something that starts automatically lives in a folder any user can write to.",
    run: (store) =>
      Object.keys(PERSISTENCE).flatMap((kind) =>
        store.all(kind).flatMap((e): FindingInput[] => {
          const meta = PERSISTENCE[kind];
          if (!meta || !isUserWritablePath(s(e, "path"))) return [];
          const signed = s(e, "signature") === "Valid";
          return [{
            ruleId: "persist-writable-path",
            title: `${meta.label} "${s(e, "name")}" runs from a temporary or public folder`,
            severity: "medium",
            confidence: signed ? "low" : "high",
            technique: meta.technique,
            evidenceIds: [e.id],
            why: `It launches ${s(e, "path")} automatically. Installed software lives in Program Files; malware drops itself into folders like this because no admin rights are needed.`,
            benign: signed ? "The file has a valid publisher signature, so this is likely an updater." : "A half-finished installer can leave an entry like this.",
          }];
        }),
      ),
  },
  {
    id: "persist-tampered",
    describe: "An auto-starting file's signature no longer matches its contents.",
    run: (store) =>
      Object.keys(PERSISTENCE).flatMap((kind) =>
        store.all(kind).flatMap((e): FindingInput[] => {
          const meta = PERSISTENCE[kind];
          if (!meta || s(e, "signature") !== "HashMismatch") return [];
          return [{
            ruleId: "persist-tampered",
            title: `${meta.label} "${s(e, "name")}" was modified after it was signed`,
            severity: "high",
            confidence: "high",
            technique: "T1554",
            evidenceIds: [e.id],
            why: `${s(e, "path")} carries a publisher signature that does not match the file. The file changed after the publisher signed it.`,
            benign: "Disk corruption or a broken update can cause this, but it is rare.",
          }];
        }),
      ),
  },
  {
    id: "winlogon-hijack",
    describe: "The program Windows starts at logon was replaced.",
    run: (store) =>
      store.all("autorun").flatMap((e): FindingInput[] => {
        if (s(e, "location") !== "Winlogon") return [];
        const value = s(e, "command").toLowerCase().replace(/,+\s*$/, "").trim();
        const name = s(e, "name");
        const ok =
          name === "Shell" ? value === "explorer.exe" : /^([a-z]:\\windows\\system32\\)?userinit\.exe$/.test(value);
        if (ok || !value) return [];
        return [{
          ruleId: "winlogon-hijack",
          title: `Windows logon ${name} value was changed`,
          severity: "high",
          confidence: "high",
          technique: "T1547.004",
          evidenceIds: [e.id],
          why: `Winlogon ${name} is "${s(e, "command")}" instead of the Windows default. Whatever is listed there runs at every logon.`,
          benign: "A few kiosk and shell-replacement tools change this on purpose.",
        }];
      }),
  },
  {
    id: "process-masquerade",
    describe: "A running program uses a core Windows name from the wrong folder.",
    run: (store) =>
      store.all("process").flatMap((e): FindingInput[] => {
        if (!isMasquerade(s(e, "name"), s(e, "path"))) return [];
        return [{
          ruleId: "process-masquerade",
          title: `"${s(e, "name")}" is running from outside the Windows folder`,
          severity: "high",
          confidence: "high",
          technique: "T1036.005",
          evidenceIds: [e.id],
          why: `The real ${s(e, "name")} lives under the Windows folder. This one runs from ${s(e, "path")}, which is how malware hides in the process list.`,
          benign: "Almost none. Check the file before trusting it.",
        }];
      }),
  },
  {
    id: "process-office-child",
    describe: "An Office program started a command interpreter.",
    run: (store) =>
      store.all("process").flatMap((e): FindingInput[] => {
        if (!OFFICE_APPS.has(s(e, "parentName").toLowerCase()) || !SHELLS.has(s(e, "name").toLowerCase())) return [];
        return [{
          ruleId: "process-office-child",
          title: `${s(e, "parentName")} started ${s(e, "name")}`,
          severity: "high",
          confidence: "high",
          technique: "T1204.002",
          evidenceIds: [e.id],
          why: "Documents do not normally launch command interpreters. This is the classic sign of a malicious macro or attachment.",
          benign: "Some corporate add-ins do this.",
        }];
      }),
  },
  {
    id: "process-lolbin",
    describe: "A running command line uses a technique malware favours.",
    run: (store) =>
      store.all("process").flatMap((e): FindingInput[] => {
        const reason = lolbinReason(s(e, "commandLine"));
        if (!reason) return [];
        return [{
          ruleId: "process-lolbin",
          title: `Running process "${s(e, "name")}" ${reason}`,
          severity: "high",
          confidence: "medium",
          technique: "T1059.001",
          evidenceIds: [e.id],
          why: `Its command line ${reason}.`,
          benign: "Developer tools and management agents sometimes launch PowerShell this way.",
        }];
      }),
  },
  {
    id: "process-writable-unsigned",
    describe: "An unsigned program is running from a temporary or public folder.",
    run: (store) =>
      store.all("process").flatMap((e): FindingInput[] => {
        const sig = s(e, "signature");
        if (!isUserWritablePath(s(e, "path")) || sig === "Valid" || sig === "") return [];
        return [{
          ruleId: "process-writable-unsigned",
          title: `Unsigned program "${s(e, "name")}" is running from a temporary or public folder`,
          severity: "medium",
          confidence: "medium",
          technique: "T1204",
          evidenceIds: [e.id],
          why: `${s(e, "path")} has no valid publisher signature (${sig}) and runs from a folder used for downloads and temporary files.`,
          benign: "Small open-source tools and installers in progress look like this.",
        }];
      }),
  },
  {
    id: "remote-access-tool",
    describe: "A remote-control tool is running.",
    run: (store) =>
      [...groupBy(store.all("process").filter((e) => REMOTE_TOOLS.test(s(e, "name"))), (e) => s(e, "name").toLowerCase())].map(
        ([, list]): FindingInput => ({
          ruleId: "remote-access-tool",
          title: `Remote access tool "${list[0] ? s(list[0], "name") : ""}" is running`,
          severity: "low",
          confidence: "high",
          technique: "T1219",
          evidenceIds: list.map((e) => e.id).slice(0, 12),
          why: "This software lets someone control or reach this computer from elsewhere. Scammers and intruders install the same legitimate tools.",
          benign: "Expected if you installed it yourself.",
        }),
      ),
  },
  {
    id: "listener-unsigned",
    describe: "An unsigned program accepts connections from the network.",
    run: (store) =>
      store.all("connection").flatMap((e): FindingInput[] => {
        const sig = s(e, "signature");
        const open = ["0.0.0.0", "::"].includes(s(e, "localAddress"));
        if (s(e, "state") !== "Listen" || !open || sig === "Valid" || sig === "") return [];
        return [{
          ruleId: "listener-unsigned",
          title: `Unsigned program "${s(e, "processName")}" is listening on port ${n(e, "localPort")}`,
          severity: "low",
          confidence: "medium",
          technique: "T1571",
          evidenceIds: [e.id],
          why: `${s(e, "processPath")} accepts connections from any network address and has no valid publisher signature (${sig}).`,
          benign: "Development servers and open-source tools commonly do this.",
        }];
      }),
  },
  {
    id: "defender-off",
    describe: "Built-in antivirus protection is switched off.",
    run: (store) =>
      store.all("defender").flatMap((e): FindingInput[] => {
        if (b(e, "realTimeProtectionEnabled") || /passive|edr block/i.test(s(e, "runningMode"))) return [];
        return [{
          ruleId: "defender-off",
          title: "Microsoft Defender real-time protection is off",
          severity: "medium",
          confidence: "high",
          technique: "T1562.001",
          evidenceIds: [e.id],
          why: "Real-time protection is disabled and no other antivirus has taken over. Malware often turns it off first.",
          benign: "You or a tool may have disabled it deliberately.",
        }];
      }),
  },
  {
    id: "defender-detection",
    describe: "Antivirus recorded a threat on this machine.",
    run: (store) =>
      store.all("detection").map((e): FindingInput => ({
        ruleId: "defender-detection",
        title: `Defender detected "${s(e, "threat") || "a threat"}"`,
        severity: b(e, "actionSuccess") ? "medium" : "high",
        confidence: "high",
        technique: "T1204",
        evidenceIds: [e.id],
        why: `Defender flagged ${s(e, "path").slice(0, 200) || "a file"}${b(e, "actionSuccess") ? " and reports it handled it" : " and does not report a successful clean-up"}. Something malicious reached this machine.`,
        benign: "Hacking tools kept for study and some cracks are flagged without an actual intrusion.",
      })),
  },
  {
    id: "hosts-redirect",
    describe: "The hosts file overrides the address of a well-known site.",
    run: (store) =>
      store.all("hosts").flatMap((e): FindingInput[] => {
        const host = s(e, "host");
        if (!SENSITIVE_HOSTS.test(host) || /^(localhost|.*\.local)$/i.test(host)) return [];
        const blocked = /^(127\.|0\.0\.0\.0|::1?$)/.test(s(e, "ip"));
        return [{
          ruleId: "hosts-redirect",
          title: `Hosts file ${blocked ? "blocks" : "redirects"} ${host}`,
          severity: "medium",
          confidence: blocked ? "low" : "medium",
          technique: "T1565.001",
          evidenceIds: [e.id],
          why: blocked
            ? `${host} is pointed at nowhere. Malware does this to stop security updates.`
            : `${host} is forced to ${s(e, "ip")} instead of its real address, which can send you to a fake site.`,
          benign: "Ad blockers and licence-check blockers add entries like this.",
        }];
      }),
  },
  {
    id: "log-cleared",
    describe: "An event log was wiped.",
    run: (store) =>
      store.all("event").flatMap((e): FindingInput[] => {
        if (![1102, 104].includes(n(e, "eventId"))) return [];
        const fields = (e.data.fields ?? {}) as Record<string, unknown>;
        const channel = n(e, "eventId") === 1102 ? "Security" : String(fields.Channel ?? "");
        // Only the core logs record intrusions. Tools clear their own application logs routinely.
        const core = /^(security|system|microsoft-windows-powershell\/operational|windows powershell)$/i.test(channel);
        return [{
          ruleId: "log-cleared",
          title: `${channel || "An"} event log was cleared`,
          severity: core ? "high" : "low",
          confidence: core ? "medium" : "low",
          technique: "T1070.001",
          evidenceIds: [e.id],
          why: "Clearing logs removes the record of what happened. Intruders do it to cover their tracks.",
          benign: "An administrator or a clean-up utility may have done it.",
        }];
      }),
  },
  {
    id: "account-created",
    describe: "A local account was created or given administrator rights.",
    run: (store) =>
      store.all("event").flatMap((e): FindingInput[] => {
        const id = n(e, "eventId");
        const fields = (e.data.fields ?? {}) as Record<string, unknown>;
        const toAdmins = id === 4732 && String(fields.TargetSid ?? "").endsWith("S-1-5-32-544");
        if (id !== 4720 && !toAdmins) return [];
        return [{
          ruleId: "account-created",
          title: toAdmins ? "An account was added to the Administrators group" : `Local account "${String(fields.TargetUserName ?? "?")}" was created`,
          severity: toAdmins ? "medium" : "low",
          confidence: "medium",
          technique: toAdmins ? "T1098" : "T1136.001",
          evidenceIds: [e.id],
          why: "New or newly privileged accounts are a common way to keep access to a machine.",
          benign: "Expected if you set up the account yourself.",
        }];
      }),
  },
  {
    id: "service-installed",
    describe: "A newly installed service looks malicious.",
    run: (store) =>
      store.all("event").flatMap((e): FindingInput[] => {
        if (n(e, "eventId") !== 7045) return [];
        const fields = (e.data.fields ?? {}) as Record<string, unknown>;
        const image = String(fields.ImagePath ?? "");
        const abuse = lolbinReason(image);
        const reason = abuse ?? (isUserWritablePath(image) ? "runs from a temporary or public folder" : null);
        if (!reason) return [];
        return [{
          ruleId: "service-installed",
          title: `Service "${String(fields.ServiceName ?? "?")}" was installed and ${reason}`,
          // Installers routinely run a short-lived service from Temp, so that alone is a weak signal.
          severity: abuse ? "high" : "medium",
          confidence: abuse ? "medium" : "low",
          technique: "T1543.003",
          evidenceIds: [e.id],
          why: `A service was installed with the command "${image.slice(0, 200)}". Services run with high privileges and survive reboots.`,
          benign: "Some drivers and updaters install short-lived services from temporary folders.",
        }];
      }),
  },
  {
    id: "powershell-script",
    describe: "PowerShell logged a script using download-and-run or decode techniques.",
    run: (store) => {
      const hits = store.all("event").flatMap((e) => {
        if (n(e, "eventId") !== 4104) return [];
        const fields = (e.data.fields ?? {}) as Record<string, unknown>;
        const reason = scriptBlockReason(String(fields.ScriptBlockText ?? ""));
        return reason ? [{ e, reason, script: String(fields.Path ?? "") || "a script typed or piped in (no file)" }] : [];
      });
      // One finding per script and reason, however many times it ran.
      return [...groupBy(hits, (h) => `${h.script}|${h.reason}`)].map(([, list]): FindingInput => {
        const first = list[0];
        return {
          ruleId: "powershell-script",
          title: `PowerShell ${first?.reason ?? ""}: ${first?.script ?? ""}`,
          severity: "medium",
          confidence: "low",
          technique: "T1059.001",
          evidenceIds: list.map((h) => h.e.id).slice(0, 12),
          why: `Windows recorded ${list.length} script block${list.length === 1 ? "" : "s"} from ${first?.script ?? "a script"} where the code ${first?.reason ?? ""}.`,
          benign: "Package managers, installers, developer tools and security tools that carry detection patterns all trip this. Read the script before worrying.",
        };
      });
    },
  },
  {
    id: "password-guessing",
    describe: "One address tried many passwords.",
    run: (store) =>
      store.all("auth_source").flatMap((e): FindingInput[] => {
        const failures = n(e, "failures");
        const broke = b(e, "successAfterFailures");
        if (failures < 10 && !broke) return [];
        const cited = [e.id, ...((e.data.evidenceIds as string[] | undefined) ?? []).filter((id) => store.get(id))];
        return [{
          ruleId: "password-guessing",
          title: broke
            ? `${s(e, "ip")} logged in after ${failures} failed attempts`
            : `${s(e, "ip")} made ${failures} failed login attempts`,
          severity: broke ? "high" : "medium",
          confidence: "high",
          technique: "T1110",
          evidenceIds: cited.slice(0, 12),
          why: broke
            ? "Many failures followed by a success from the same address is what a guessed password looks like."
            : "Repeated failures from one address is password guessing. No success from that address was seen.",
          benign: broke ? "A user who forgot the password, then remembered it." : "Internet-facing logins get this constantly.",
        }];
      }),
  },
  {
    id: "beacon",
    describe: "Connections repeat at a machine-regular interval.",
    run: (store) =>
      store.all("beacon").map((e): FindingInput => ({
        ruleId: "beacon",
        title: `${s(e, "src")} contacts ${s(e, "label") || s(e, "dst")}:${n(e, "dport")} every ${n(e, "meanIntervalSec")}s`,
        severity: "medium",
        confidence: "low",
        technique: "T1071",
        evidenceIds: [e.id],
        why: `${n(e, "count")} connections at a steady ${n(e, "meanIntervalSec")}-second interval. Malware checking in with its controller looks like this.`,
        benign: "Update checks, telemetry, chat clients and monitoring agents also poll on a timer. Identify the destination.",
      })),
  },
  {
    id: "dns-tunnel",
    describe: "DNS lookups carry long, unique names under one domain.",
    run: (store) =>
      store.all("dns_tunnel").map((e): FindingInput => ({
        ruleId: "dns-tunnel",
        title: `Possible data tunnelling over DNS through ${s(e, "domain")}`,
        severity: "medium",
        confidence: "low",
        technique: "T1071.004",
        evidenceIds: [e.id],
        why: `${n(e, "uniqueLongNames")} different long names were looked up under ${s(e, "domain")}. Encoding data into lookups is a way to smuggle it past firewalls.`,
        benign: "Some CDNs, antivirus reputation lookups and tracking services use long generated names.",
      })),
  },
  {
    id: "cleartext-credentials",
    describe: "A username and password crossed the network unencrypted.",
    run: (store) =>
      store.all("credential").map((e): FindingInput => ({
        ruleId: "cleartext-credentials",
        title: `Login for "${s(e, "user")}" sent unencrypted over ${s(e, "protocol")}`,
        severity: "low",
        confidence: "high",
        technique: "T1040",
        evidenceIds: [e.id],
        why: `Anyone on the path between ${s(e, "src")} and ${s(e, "dst")} could read this login. Treat the password as exposed.`,
        benign: "Old devices and internal tools still use unencrypted logins.",
      })),
  },
  {
    id: "web-attack",
    describe: "A client sent web requests carrying attack payloads.",
    run: (store) => {
      const byClient = new Map<string, Evidence[]>();
      for (const e of store.all("web_request")) {
        const list = byClient.get(s(e, "ip")) ?? [];
        list.push(e);
        byClient.set(s(e, "ip"), list);
      }
      return [...byClient.entries()].map(([ip, list]): FindingInput => {
        const kinds = [...new Set(list.map((e) => s(e, "attack")))];
        const landed = list.filter((e) => n(e, "status") >= 200 && n(e, "status") < 300 && /injection|traversal|Log4Shell/.test(s(e, "attack")));
        return {
          ruleId: "web-attack",
          title: `${ip} sent ${list.length} attack request${list.length === 1 ? "" : "s"} (${kinds.join(", ")})`,
          severity: landed.length > 0 ? "high" : "medium",
          confidence: landed.length > 0 ? "low" : "high",
          technique: "T1190",
          evidenceIds: [...landed, ...list].map((e) => e.id).slice(0, 12),
          why: landed.length > 0
            ? `${landed.length} of these requests got a success response. A success code alone does not prove the attack worked; check what the server returned.`
            : "The requests carry known attack payloads. None of the injected ones returned a success response.",
          benign: "Every public web server receives automated probes like these.",
        };
      });
    },
  },
  {
    id: "ai-injection",
    describe: "Evidence contains text written to steer an AI assistant.",
    run: (store) =>
      store.all().flatMap((e): FindingInput[] => {
        if (!hasInjection(e.data)) return [];
        return [{
          ruleId: "ai-injection",
          title: `Evidence ${e.id} contains text addressed to an AI assistant`,
          severity: "medium",
          confidence: "medium",
          technique: "T1027",
          evidenceIds: [e.id],
          why: "This record contains instructions aimed at an AI reading it. Someone may be trying to make an automated investigation overlook them. Do not follow that text.",
          benign: "Documentation or chat logs about AI can contain similar phrases.",
        }];
      }),
  },
];

function groupBy<T>(items: T[], key: (item: T) => string): Map<string, T[]> {
  const out = new Map<string, T[]>();
  for (const item of items) {
    const k = key(item);
    const list = out.get(k) ?? [];
    list.push(item);
    out.set(k, list);
  }
  return out;
}

function hasInjection(value: unknown, depth = 0): boolean {
  if (typeof value === "string") return looksLikeInjection(value);
  if (depth > 3 || value === null || typeof value !== "object") return false;
  return Object.values(value as Record<string, unknown>).some((v) => hasInjection(v, depth + 1));
}

/** Run every rule and record what it finds. Safe to call again after adding evidence. */
export function runRules(store: CaseStore): Finding[] {
  for (const rule of rules) {
    for (const input of rule.run(store)) store.addFinding(input, "rule");
  }
  return store.findings();
}
