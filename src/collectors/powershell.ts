import { spawn } from "node:child_process";

export const PREAMBLE = `
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
`;

/** The bootstrap reads the real script from stdin, so no script text is ever on a command line. */
export const BOOTSTRAP ="& ([scriptblock]::Create([Console]::In.ReadToEnd()))";

const MAX_OUTPUT_BYTES = 64 * 1024 * 1024;

/**
 * Run one of this package's fixed, read-only PowerShell scripts and parse its JSON output.
 *
 * `script` must be a constant from this codebase. Caller-supplied values go in `arg`,
 * which reaches the script as JSON in the AMIHACKED_ARG environment variable and is
 * never spliced into script text.
 */
export function runPowerShell<T = unknown>(script: string, arg: unknown = null, timeoutMs = 90_000): Promise<T> {
  return new Promise((resolve, reject) => {
    const child = spawn("powershell.exe", ["-NoProfile", "-NonInteractive", "-NoLogo", "-Command", BOOTSTRAP], {
      env: { ...process.env, AMIHACKED_ARG: JSON.stringify(arg) },
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const chunks: Buffer[] = [];
    let size = 0;
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`PowerShell collector timed out after ${timeoutMs / 1000}s`));
    }, timeoutMs);
    child.stdout.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_OUTPUT_BYTES) {
        child.kill();
        return;
      }
      chunks.push(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      if (stderr.length < 4000) stderr += chunk.toString("utf8");
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on("close", () => {
      clearTimeout(timer);
      const text = Buffer.concat(chunks).toString("utf8").replace(/^﻿/, "").trim();
      if (!text) {
        reject(new Error(`PowerShell collector returned nothing${stderr ? `: ${stderr.trim().slice(0, 300)}` : ""}`));
        return;
      }
      try {
        resolve(JSON.parse(text) as T);
      } catch {
        reject(new Error(`PowerShell collector returned invalid JSON: ${text.slice(0, 200)}`));
      }
    });
    child.stdin.on("error", () => undefined);
    child.stdin.end(`${PREAMBLE}\n${script}\n`);
  });
}

/** PowerShell hands back a bare object for one item and an array for several. */
export function asArray<T>(value: T | T[] | null | undefined): T[] {
  if (value === null || value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}
