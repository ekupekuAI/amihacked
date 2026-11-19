import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { isOwnScript } from "../collectors/windows.js";
import { PREAMBLE } from "../collectors/powershell.js";
import { PS_TASKS } from "../collectors/scripts.js";
import { CaseStore } from "../core/store.js";
import { readEvidenceFile } from "../readers/files.js";
import { dnsQueryName, readPcap, tlsServerName } from "../readers/pcap.js";
import { parseAccessLine, parseSshLine, sniffTextLog } from "../readers/textlog.js";
import { runRules } from "../rules/index.js";

const dir = mkdtempSync(join(tmpdir(), "amihacked-test-"));
after(() => rmSync(dir, { recursive: true, force: true }));

const u16 = (n: number): Buffer => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const u32le = (n: number): Buffer => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
const ip = (text: string): Buffer => Buffer.from(text.split(".").map(Number));

function ethIp(proto: number, src: string, dst: string, transport: Buffer): Buffer {
  const ipHeader = Buffer.concat([
    Buffer.from([0x45, 0]), u16(20 + transport.length), u16(1), u16(0), Buffer.from([64, proto]), u16(0), ip(src), ip(dst),
  ]);
  return Buffer.concat([Buffer.alloc(12), u16(0x0800), ipHeader, transport]);
}
const udp = (sport: number, dport: number, payload: Buffer): Buffer =>
  Buffer.concat([u16(sport), u16(dport), u16(8 + payload.length), u16(0), payload]);
const tcp = (sport: number, dport: number, payload: Buffer, flags = 0x18): Buffer =>
  Buffer.concat([u16(sport), u16(dport), Buffer.alloc(8), Buffer.from([0x50, flags]), u16(1024), u16(0), u16(0), payload]);

function dnsQuery(name: string): Buffer {
  const labels = name.split(".").map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l, "latin1")]));
  return Buffer.concat([u16(0x1234), u16(0x0100), u16(1), u16(0), u16(0), u16(0), ...labels, Buffer.from([0]), u16(1), u16(1)]);
}

function clientHello(serverName: string): Buffer {
  const name = Buffer.from(serverName, "latin1");
  const sni = Buffer.concat([u16(0), u16(name.length + 5), u16(name.length + 3), Buffer.from([0]), u16(name.length), name]);
  const body = Buffer.concat([
    Buffer.from([3, 3]), Buffer.alloc(32, 7), Buffer.from([0]), u16(2), Buffer.from([0x13, 0x01]), Buffer.from([1, 0]), u16(sni.length), sni,
  ]);
  const handshake = Buffer.concat([Buffer.from([1, 0]), u16(body.length), body]);
  return Buffer.concat([Buffer.from([0x16, 3, 1]), u16(handshake.length), handshake]);
}

function classicPcap(packets: Array<{ sec: number; data: Buffer }>): Buffer {
  const header = Buffer.concat([u32le(0xa1b2c3d4), Buffer.from([2, 0, 4, 0]), Buffer.alloc(8), u32le(65535), u32le(1)]);
  return Buffer.concat([header, ...packets.flatMap((p) => [u32le(p.sec), u32le(0), u32le(p.data.length), u32le(p.data.length), p.data])]);
}

function pcapng(packets: Array<{ sec: number; data: Buffer }>): Buffer {
  const shb = Buffer.concat([u32le(0x0a0d0d0a), u32le(28), u32le(0x1a2b3c4d), Buffer.from([1, 0, 0, 0]), Buffer.alloc(8, 0xff), u32le(28)]);
  const idb = Buffer.concat([u32le(1), u32le(20), Buffer.from([1, 0, 0, 0]), u32le(65535), u32le(20)]);
  const blocks = packets.map((p) => {
    const padded = Buffer.concat([p.data, Buffer.alloc((4 - (p.data.length % 4)) % 4)]);
    const micros = BigInt(p.sec) * 1_000_000n;
    const total = 32 + padded.length;
    return Buffer.concat([
      u32le(6), u32le(total), u32le(0), u32le(Number(micros >> 32n)), u32le(Number(micros & 0xffffffffn)),
      u32le(p.data.length), u32le(p.data.length), padded, u32le(total),
    ]);
  });
  return Buffer.concat([shb, idb, ...blocks]);
}

const T0 = 1_760_000_000;
const sample = [
  { sec: T0, data: ethIp(17, "10.0.0.5", "8.8.8.8", udp(40000, 53, dnsQuery("update.example.com"))) },
  { sec: T0 + 1, data: ethIp(6, "10.0.0.5", "203.0.113.7", tcp(50000, 443, clientHello("c2.evil.example"))) },
  {
    sec: T0 + 2,
    data: ethIp(6, "10.0.0.5", "198.51.100.9", tcp(50001, 80, Buffer.from(
      `GET /admin HTTP/1.1\r\nHost: router.local\r\nUser-Agent: curl/8\r\nAuthorization: Basic ${Buffer.from("admin:hunter2").toString("base64")}\r\n\r\n`, "latin1",
    ))),
  },
];

test("protocol parsers", () => {
  assert.equal(dnsQueryName(dnsQuery("a.b.example")), "a.b.example");
  assert.equal(dnsQueryName(Buffer.alloc(5)), null);
  assert.equal(tlsServerName(clientHello("host.example")), "host.example");
  assert.equal(tlsServerName(Buffer.from("GET / HTTP/1.1\r\n")), null);
  assert.equal(tlsServerName(clientHello("host.example").subarray(0, 50)), null);
});

for (const [label, build] of [["classic pcap", classicPcap], ["pcapng", pcapng]] as const) {
  test(`${label}: flows, DNS, SNI, HTTP and credentials`, () => {
    const path = join(dir, `${label.replace(" ", "-")}.cap`);
    writeFileSync(path, build(sample));
    const r = readPcap(path);
    assert.equal(r.packets, 3);
    assert.equal(r.flows.length, 3);
    assert.deepEqual(r.dns.map((q) => q.name), ["update.example.com"]);
    assert.equal(r.flows.find((f) => f.dport === 443)?.sni, "c2.evil.example");
    assert.equal(r.flows.find((f) => f.dport === 443)?.first, (T0 + 1) * 1000);
    assert.equal(r.http[0]?.host, "router.local");
    assert.deepEqual(r.credentials.map((c) => [c.protocol, c.user]), [["HTTP Basic", "admin"]]);
    assert.ok(!JSON.stringify(r).includes("hunter2"), "password must not be kept");
  });
}

test("a truncated or foreign file does not crash the pcap reader", () => {
  const cut = join(dir, "cut.cap");
  writeFileSync(cut, classicPcap(sample).subarray(0, 70));
  assert.equal(readPcap(cut).packets, 0);
  const other = join(dir, "other.bin");
  writeFileSync(other, Buffer.from("this is not a capture"));
  assert.throws(() => readPcap(other), /Not a pcap/);
});

test("a beaconing capture produces a beacon finding with redacted evidence", async () => {
  const packets = Array.from({ length: 12 }, (_, i) => ({
    sec: T0 + i * 30,
    data: ethIp(6, "10.0.0.5", "203.0.113.7", tcp(51000 + i, 443, clientHello("c2.evil.example"), 0x02)),
  }));
  const path = join(dir, "beacon.pcap");
  writeFileSync(path, classicPcap([...packets, sample[2]!]));
  const store = new CaseStore();
  assert.equal(await readEvidenceFile(store, path), "pcap");
  const ids = runRules(store).map((f) => f.ruleId);
  assert.ok(ids.includes("beacon"));
  assert.ok(ids.includes("cleartext-credentials"));
  assert.ok(!JSON.stringify(store.toJSON()).includes("hunter2"));
});

test("SSH log lines", () => {
  const failed = parseSshLine("Mar  3 04:05:06 web1 sshd[911]: Failed password for invalid user admin from 203.0.113.9 port 4242 ssh2", 1, 2026);
  assert.deepEqual([failed?.ok, failed?.user, failed?.ip, failed?.time], [false, "admin", "203.0.113.9", "2026-03-03T04:05:06.000Z"]);
  const accepted = parseSshLine("2026-03-03T04:06:00.123456+00:00 web1 sshd[912]: Accepted publickey for deploy from 198.51.100.2 port 22 ssh2", 2, 2026);
  assert.deepEqual([accepted?.ok, accepted?.user, accepted?.method], [true, "deploy", "publickey"]);
  assert.equal(parseSshLine("Mar  3 04:05:06 web1 cron[1]: job ran", 3, 2026), null);
});

test("web access log lines", () => {
  const r = parseAccessLine('203.0.113.9 - - [10/Oct/2026:13:55:36 +0200] "GET /a.php?id=1 HTTP/1.1" 200 512 "-" "sqlmap/1.7"');
  assert.deepEqual([r?.ip, r?.method, r?.path, r?.status, r?.userAgent, r?.time], ["203.0.113.9", "GET", "/a.php?id=1", 200, "sqlmap/1.7", "2026-10-10T11:55:36.000Z"]);
  assert.equal(parseAccessLine("not a log line"), null);
  assert.equal(sniffTextLog(["random text", "more text"]), "unknown");
});

test("an SSH log with a guessed password ends in an alert", async () => {
  const lines = [
    ...Array.from({ length: 30 }, (_, i) => `Mar  3 04:05:${String(i).padStart(2, "0")} web1 sshd[9]: Failed password for root from 203.0.113.9 port 4242 ssh2`),
    "Mar  3 04:06:10 web1 sshd[9]: Accepted password for root from 203.0.113.9 port 4242 ssh2",
    "Mar  3 09:00:00 web1 sshd[9]: Accepted publickey for deploy from 198.51.100.2 port 22 ssh2",
  ];
  const path = join(dir, "auth.log");
  writeFileSync(path, lines.join("\n"));
  const store = new CaseStore();
  assert.equal(await readEvidenceFile(store, path), "ssh-log");
  const findings = runRules(store);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.ruleId, "password-guessing");
  assert.equal(findings[0]?.severity, "high");
  assert.ok(findings[0]?.evidenceIds.every((id) => store.get(id)));
  assert.equal(store.verdict(), "alert");
});

test("a web log separates attacks from normal traffic", async () => {
  const lines = [
    '198.51.100.2 - - [10/Oct/2026:13:55:36 +0000] "GET /products/42 HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
    '203.0.113.9 - - [10/Oct/2026:13:56:00 +0000] "GET /item?id=1%20UNION%20SELECT%20pw%20FROM%20users HTTP/1.1" 500 0 "-" "Mozilla/5.0"',
    '203.0.113.9 - - [10/Oct/2026:13:56:05 +0000] "GET /dl?f=../../../../etc/passwd HTTP/1.1" 404 0 "-" "Mozilla/5.0"',
  ];
  const path = join(dir, "access.log");
  writeFileSync(path, lines.join("\n"));
  const store = new CaseStore();
  assert.equal(await readEvidenceFile(store, path), "web-log");
  const findings = runRules(store);
  assert.equal(findings.length, 1);
  assert.match(findings[0]?.title ?? "", /203\.0\.113\.9 sent 2 attack requests/);
  assert.equal(store.verdict(), "review");
});

test("unknown files are refused, not guessed at", async () => {
  const path = join(dir, "notes.txt");
  writeFileSync(path, "hello\nworld\n");
  await assert.rejects(readEvidenceFile(new CaseStore(), path), /Unrecognised file/);
});

test("only this tool's exact collector scripts count as its own", () => {
  assert.ok(isOwnScript(`${PREAMBLE}\n${PS_TASKS}`));
  assert.ok(isOwnScript(PS_TASKS.slice(0, 200)));
  assert.ok(!isOwnScript(`${PREAMBLE}\nInvoke-Something -Evil`));
  assert.ok(!isOwnScript("Get-Process"));
});
