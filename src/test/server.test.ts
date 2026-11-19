import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "../server.js";

const dir = mkdtempSync(join(tmpdir(), "amihacked-mcp-"));
after(() => rmSync(dir, { recursive: true, force: true }));

async function connect(): Promise<Client> {
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await createServer().connect(serverSide);
  const client = new Client({ name: "test", version: "0" });
  await client.connect(clientSide);
  return client;
}

async function call(client: Client, name: string, args: Record<string, unknown> = {}): Promise<{ text: string; isError: boolean }> {
  const result = await client.callTool({ name, arguments: args });
  const content = result.content as Array<{ type: string; text: string }>;
  return { text: content.map((c) => c.text).join("\n"), isError: result.isError === true };
}

test("an agent can investigate a file end to end over MCP", async () => {
  const client = await connect();
  const tools = (await client.listTools()).tools.map((t) => t.name).sort();
  assert.deepEqual(tools, ["get_evidence", "list_evidence", "new_case", "read_evidence_file", "report", "scan_live", "search_evidence", "submit_finding", "timeline"]);

  const log = join(dir, "auth.log");
  writeFileSync(log, [
    ...Array.from({ length: 15 }, (_, i) => `Mar  3 04:05:${String(i).padStart(2, "0")} web1 sshd[9]: Failed password for root from 203.0.113.9 port 4242 ssh2`),
    "Mar  3 04:06:10 web1 sshd[9]: Accepted password for root from 203.0.113.9 port 4242 ssh2",
  ].join("\n"));

  const read = await call(client, "read_evidence_file", { path: log });
  assert.equal(read.isError, false);
  assert.match(read.text, /untrusted data/);
  assert.match(read.text, /"verdict": "alert"/);
  assert.match(read.text, /logged in after 15 failed attempts/);

  const search = await call(client, "search_evidence", { query: "203.0.113.9", kind: "auth_source" });
  const id = /"id": "(E\d+)"/.exec(search.text)?.[1];
  assert.ok(id, "search should return an evidence ID");

  const invented = await call(client, "submit_finding", {
    title: "Attacker installed a rootkit", severity: "critical", confidence: "high", evidenceIds: ["E99999"], why: "I am sure this happened.",
  });
  assert.equal(invented.isError, true);
  assert.match(invented.text, /Finding rejected.*Unknown evidence ID/);

  const backed = await call(client, "submit_finding", {
    title: "Root password was guessed over SSH", severity: "high", confidence: "high", evidenceIds: [id], technique: "T1110.001",
    why: "The same address failed 15 times and then logged in as root.",
  });
  assert.equal(backed.isError, false);

  const saved = join(dir, "report.md");
  const report = await call(client, "report", { savePath: saved });
  assert.match(report.text, /Verdict: Strong signs of compromise/);
  assert.match(report.text, /agent conclusion/);
  assert.match(readFileSync(saved, "utf8"), /Root password was guessed over SSH/);
  assert.equal((await call(client, "report", { savePath: saved })).isError, true, "must not overwrite an existing file");
  assert.equal((await call(client, "report", { savePath: join(dir, "x.exe") })).isError, true);

  await call(client, "new_case");
  assert.match((await call(client, "list_evidence")).text, /"total": 0/);
  await client.close();
});

test("bad tool input is refused", async () => {
  const client = await connect();
  assert.equal((await call(client, "read_evidence_file", { path: join(dir, "missing.log") })).isError, true);
  const bad = await client.callTool({ name: "get_evidence", arguments: { ids: ["../../etc/passwd"] } }).catch((e: unknown) => ({ isError: true, e }));
  assert.equal(bad.isError, true);
  await client.close();
});
