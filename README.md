# amihacked

**Ask your AI agent: "Am I hacked?"**

amihacked gives an AI agent (Claude Code, Codex, Cursor, Gemini CLI, or anything that
speaks MCP) the ability to investigate a computer for signs of compromise. It inspects
the live machine or evidence files, and every conclusion has to cite the evidence it
rests on.

It is read-only, runs entirely on your machine, and needs no forensics lab.

> Status: early (v0.1). The live scan supports Windows. It is not an antivirus.

## Why

An agent can reason about an intrusion, but it cannot see one. Left to run shell
commands on its own, it produces a different investigation every time and nothing
stops it from stating things it never checked.

amihacked fixes both. Fixed collectors turn the system into structured evidence
records, each with an ID and a hash. Findings, whether from the built-in rules or from
the agent, are rejected unless they cite records that exist.

## Quick start

Needs Node.js 20 or newer. amihacked is not on npm yet, so build it from source:

```bash
git clone https://github.com/ekupekuAI/amihacked.git
```

```bash
cd amihacked && npm install && npm run build
```

Try it on the bundled examples, no agent needed:

```bash
node dist/cli.js file examples/auth.log examples/access.log
```

Inspect this computer (Windows):

```bash
node dist/cli.js scan --report case.md
```

Add it to Claude Code, using the full path to your clone:

```bash
claude mcp add amihacked -- node /path/to/amihacked/dist/cli.js mcp
```

Then ask:

```text
Am I hacked? Check this computer and show me the evidence.
```

For other agents, register the same command as a stdio MCP server.

## What it looks at

**The live machine (Windows)**

| Area | What is collected |
| --- | --- |
| Startup | Run keys, Winlogon values, Startup folders |
| Scheduled tasks | Tasks outside `\Microsoft\` |
| Services | Every service and the file it launches |
| Processes | Path, command line, parent, publisher signature |
| Network | Listening ports and open connections, with the owning program |
| Antivirus | Defender state and recorded detections |
| Accounts | Local users and administrators |
| Hosts file | Address overrides |
| Event logs | Failed and remote logons, new accounts, cleared logs, installed services, flagged PowerShell |

**Evidence files (any OS unless noted)**

| File | What is extracted |
| --- | --- |
| pcap / pcapng | Flows, DNS lookups, TLS server names, HTTP requests, unencrypted logins, regular "check-in" traffic, DNS tunnelling |
| SSH auth log | Login attempts per address, password guessing, a success after many failures |
| Web access log | Requests carrying SQL injection, path traversal, command injection, Log4Shell and scanner signatures |
| Windows `.evtx` | The same security events as the live scan (needs Windows in this version) |

The file type is detected from the content, not the name.

## What you get

Output of the examples command above, shortened:

```text
Verdict: Strong signs of compromise

HIGH     203.0.113.9 logged in after 30 failed attempts
         Many failures followed by a success from the same address is what a guessed password looks like.
         Innocent explanation: A user who forgot the password, then remembered it.
         confidence high · T1110 · evidence E00001, E00002, E00003, ... E00033
           E00001 line 1: SSH login failed user=root from=203.0.113.9

MEDIUM   203.0.113.9 sent 3 attack requests (SQL injection, path traversal, probing for exposed files or logins)
         The requests carry known attack payloads. None of the injected ones returned a success response.
         Innocent explanation: Every public web server receives automated probes like these.
         confidence high · T1190 · evidence E00035, E00036, E00037

Coverage
  checked  file:auth.log: 32 SSH login attempts from 2 addresses. Only sshd lines are read.
  checked  file:access.log: 5 requests, 3 carrying attack payloads. Request bodies are not in access logs, so POST payloads are invisible.
```

- **Verdict** is one of three: no signs of compromise in what was checked, suspicious
  items need a closer look, or strong signs of compromise. The strongest verdict needs
  strong evidence, not a pile of weak signals.
- **Findings** carry a severity, a confidence, a MITRE ATT&CK technique, the most
  likely innocent explanation, and the evidence IDs behind them.
- **Coverage** lists what was checked and, just as plainly, what could not be.

## MCP tools

| Tool | Purpose |
| --- | --- |
| `scan_live` | Inspect the machine the server runs on |
| `read_evidence_file` | Read an evidence file into the case |
| `list_evidence`, `get_evidence`, `search_evidence` | Examine the collected records |
| `timeline` | Records in time order, optionally around a moment |
| `submit_finding` | Record the agent's own conclusion; refused without real evidence IDs |
| `report` | Markdown report with verdict, findings, evidence and coverage |
| `new_case` | Start over |

## Safety

- **Read-only.** It never changes, deletes or quarantines anything.
- **Local.** It makes no network connections and uploads nothing.
- **No agent-supplied commands.** Collectors are fixed scripts. Values from the agent
  travel as data and are never spliced into a script.
- **Evidence is treated as hostile.** Text from logs and captures is cleaned and capped,
  and a rule flags content written to steer an AI ("ignore previous instructions...").
- **Passwords are redacted.** A login seen in a capture is recorded by username only.

## Limits

- A clear verdict means nothing was found in the areas listed under Coverage. It does
  not prove a system is clean. Kernel rootkits, firmware implants and malware that
  hides from the operating system are out of reach.
- Without administrator rights the Windows Security log cannot be read, so logon and
  account events are missing. The report says so when that happens.
- Rules are heuristics. Each finding states its confidence and an innocent
  explanation; read both before acting.
- Live scanning of macOS and Linux, cross-platform `.evtx`, disk images and memory
  dumps are not supported yet.

## Development

```bash
npm install
```

```bash
npm test
```

See [docs/DESIGN.md](docs/DESIGN.md) for the design and roadmap.

## License

MIT
