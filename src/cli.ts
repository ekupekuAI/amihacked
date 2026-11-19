#!/usr/bin/env node
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { scanLive } from "./collectors/windows.js";
import { CaseStore, type Finding, type Verdict } from "./core/store.js";
import { readEvidenceFile } from "./readers/files.js";
import { renderReport, VERDICT_TEXT } from "./report.js";
import { runRules } from "./rules/index.js";
import { serveStdio, VERSION } from "./server.js";

const HELP = `amihacked ${VERSION}: ask your AI agent "Am I hacked?"

Usage
  amihacked scan [--days N]        Inspect this computer (Windows). Read-only.
  amihacked file <path> [...]      Investigate evidence files: .evtx, pcap/pcapng,
                                   SSH auth logs, web access logs.
  amihacked mcp                    Run as an MCP server for an AI agent (stdio).

Options
  --json             Print the full case as JSON.
  --report <file>    Also write a Markdown report to <file>.
  --days <N>         Days of event logs to read for scan (default 7, max 90).

Use with an AI agent
  Register "amihacked mcp" as a stdio MCP server. See the README.
`;

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: number, text: string): string => (useColor ? `\u001b[${code}m${text}\u001b[0m` : text);
const VERDICT_COLOR: Record<Verdict, number> = { clear: 32, review: 33, alert: 31 };
const SEVERITY_COLOR: Record<Finding["severity"], number> = { info: 90, low: 36, medium: 33, high: 31, critical: 35 };

function printCase(store: CaseStore): void {
  const verdict = store.verdict();
  console.log(`\n${paint(1, "Verdict:")} ${paint(VERDICT_COLOR[verdict], VERDICT_TEXT[verdict])}\n`);
  const findings = store.findings();
  if (findings.length === 0) console.log("No findings.\n");
  for (const f of findings) {
    console.log(`${paint(SEVERITY_COLOR[f.severity], f.severity.toUpperCase().padEnd(8))} ${f.title}`);
    console.log(`         ${f.why}`);
    if (f.benign) console.log(paint(90, `         Innocent explanation: ${f.benign}`));
    console.log(paint(90, `         confidence ${f.confidence}${f.technique ? ` · ${f.technique}` : ""} · evidence ${f.evidenceIds.join(", ")}`));
    for (const id of f.evidenceIds.slice(0, 3)) console.log(paint(90, `           ${id} ${store.get(id)?.summary ?? ""}`));
    console.log("");
  }
  console.log(paint(1, "Coverage"));
  for (const c of store.coverage()) {
    const mark = c.status === "checked" ? paint(32, "checked ") : c.status === "partial" ? paint(33, "partial ") : paint(31, "skipped ");
    console.log(`  ${mark} ${c.area}: ${c.note}`);
  }
  console.log(paint(90, "\nA clear verdict covers only what is listed above. This is not an antivirus."));
}

function takeOption(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  if (i < 0) return undefined;
  const value = args[i + 1];
  if (value === undefined || value.startsWith("--")) throw new Error(`${name} needs a value`);
  args.splice(i, 2);
  return value;
}

function takeFlag(args: string[], name: string): boolean {
  const i = args.indexOf(name);
  if (i < 0) return false;
  args.splice(i, 1);
  return true;
}

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  const command = args.shift();
  if (!command || command === "help" || command === "--help" || command === "-h") {
    console.log(HELP);
    return 0;
  }
  if (command === "--version" || command === "-v") {
    console.log(VERSION);
    return 0;
  }
  if (command === "mcp") {
    await serveStdio();
    return new Promise<number>(() => undefined);
  }

  const json = takeFlag(args, "--json");
  const reportPath = takeOption(args, "--report");
  const daysText = takeOption(args, "--days");
  const store = new CaseStore();

  if (command === "scan") {
    const days = daysText === undefined ? undefined : Number(daysText);
    if (days !== undefined && (!Number.isInteger(days) || days < 1 || days > 90)) throw new Error("--days must be a whole number from 1 to 90");
    if (!json) console.error("Inspecting this computer. Read-only; usually under a minute...");
    await scanLive(store, { days });
  } else if (command === "file") {
    if (args.length === 0) throw new Error("file needs at least one path");
    for (const path of args) {
      if (!json) console.error(`Reading ${path}...`);
      await readEvidenceFile(store, path);
    }
  } else {
    throw new Error(`Unknown command "${command}". Run amihacked --help.`);
  }

  runRules(store);
  if (json) console.log(JSON.stringify(store.toJSON(), null, 1));
  else printCase(store);
  if (reportPath) {
    writeFileSync(resolve(reportPath), renderReport(store), "utf8");
    console.error(`\nReport written to ${resolve(reportPath)}`);
  }
  // Exit code lets scripts react: 0 clear, 1 review, 2 alert.
  return { clear: 0, review: 1, alert: 2 }[store.verdict()];
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    console.error(`amihacked: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 64;
  },
);
