# amihacked: design

## Why

AI agents can reason about an intrusion, but they cannot see one. Existing forensic
MCP servers assume a professional with a Linux forensics lab and evidence images.
amihacked gives any agent the ability to investigate **the machine it is running on**
or **loose evidence files**, with one install and no lab.

## Goals

- One tool, two inputs: a live machine, or evidence files (EVTX, pcap/pcapng, text logs).
- Every finding cites evidence records by ID. A finding without evidence is rejected.
- Read-only and local. No network calls, no uploads, no changes to the machine.
- Works without administrator rights, and says plainly what it could not check.
- Low false-alarm rate: each finding carries a confidence and a benign explanation.

## Non-goals (v0.1)

- Not an antivirus and not real-time protection.
- No disk images or memory dumps.
- No remediation. It reports; a person decides.

## Anti-goals

- A verdict the evidence does not support.
- Running anything the agent supplies as a command.
- Treating text found in evidence as instructions.

## Approaches considered

1. **Wrap heavy forensic suites (Plaso, Volatility).** Deep, but needs a lab install.
   Rejected: this is what the existing tools already do.
2. **Agent runs shell commands itself, guided by a skill.** Zero code, but results are
   unrepeatable, unbounded, and nothing stops invented findings. Rejected.
3. **Typed collectors + evidence store + rules (chosen).** Fixed read-only collectors
   produce structured evidence; rules and the agent both write findings that must cite it.

## Shape

```
collectors (live Windows)  ─┐
readers (evtx, pcap, logs) ─┼─> CaseStore (evidence, hashed, IDs) ─> rules ─> findings
agent (submit_finding)     ─┘                                     └─> timeline, report
```

- `src/core/store.ts`: evidence, findings, coverage notes. Rejects uncited findings.
- `src/core/untrusted.ts`: cleans evidence text and flags text aimed at AI assistants.
- `src/collectors/`: fixed PowerShell scripts. Arguments travel in an environment
  variable as JSON, never spliced into script text.
- `src/readers/`: pure TypeScript pcap/pcapng and text-log parsers; EVTX through
  Windows' own reader.
- `src/rules/`: detections mapped to MITRE ATT&CK technique IDs.
- `src/server.ts`: MCP tools. `src/cli.ts`: the same engine from a terminal.

## Decisions

- TypeScript on Node 20+, distributed through npm (`npx amihacked`).
- Windows first for the live scan: it is where most people asking the question are.
- Passwords seen in captures are redacted before they become evidence.
- Verdict has three levels: `clear`, `review`, `alert`. `alert` needs strong evidence.

## Roadmap

- Live collectors for macOS and Linux.
- Pure TypeScript EVTX and registry-hive parsers, so evidence files work on any OS.
- Browser extension and WMI persistence collectors.
- Known-answer test cases that grade the agent's conclusions.
