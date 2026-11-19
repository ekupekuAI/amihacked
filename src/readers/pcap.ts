import { closeSync, openSync, readSync } from "node:fs";

/** Pure TypeScript reader for pcap and pcapng captures. No native code, no tshark. */

export interface Flow {
  proto: "tcp" | "udp";
  src: string;
  sport: number;
  dst: string;
  dport: number;
  packets: number;
  bytes: number;
  /** Milliseconds since epoch. */
  first: number;
  last: number;
  sni?: string;
  httpHost?: string;
}

export interface DnsQuery {
  time: number;
  src: string;
  name: string;
}

export interface HttpRequest {
  time: number;
  src: string;
  dst: string;
  method: string;
  host: string;
  uri: string;
  userAgent: string;
}

export interface Credential {
  time: number;
  src: string;
  dst: string;
  protocol: string;
  user: string;
}

export interface PcapResult {
  packets: number;
  flows: Flow[];
  dns: DnsQuery[];
  http: HttpRequest[];
  credentials: Credential[];
  /** True when a cap was reached and some detail was dropped. */
  truncated: boolean;
}

export interface PcapLimits {
  maxPackets: number;
  maxFlows: number;
  maxDns: number;
  maxHttp: number;
}

const DEFAULT_LIMITS: PcapLimits = { maxPackets: 5_000_000, maxFlows: 50_000, maxDns: 20_000, maxHttp: 5_000 };
const MAX_PACKET_BYTES = 262_144;

class Cursor {
  private pos = 0;
  constructor(private readonly fd: number) {}
  read(length: number): Buffer | null {
    if (length < 0) return null;
    const buf = Buffer.allocUnsafe(length);
    const got = length === 0 ? 0 : readSync(this.fd, buf, 0, length, this.pos);
    if (got < length) return null;
    this.pos += length;
    return buf;
  }
  skip(length: number): void {
    this.pos += Math.max(0, length);
  }
}

type PacketHandler = (linkType: number, data: Buffer, timeMs: number) => boolean;

function readClassic(cur: Cursor, header: Buffer, onPacket: PacketHandler): void {
  const magic = header.readUInt32LE(0);
  const little = magic === 0xa1b2c3d4 || magic === 0xa1b23c4d;
  const nano = magic === 0xa1b23c4d || magic === 0x4d3cb2a1;
  const u32 = (b: Buffer, o: number): number => (little ? b.readUInt32LE(o) : b.readUInt32BE(o));
  const rest = cur.read(20);
  if (!rest) return;
  const linkType = u32(rest, 16) & 0xffff;
  for (;;) {
    const ph = cur.read(16);
    if (!ph) return;
    const caplen = u32(ph, 8);
    if (caplen > MAX_PACKET_BYTES) return;
    const data = cur.read(caplen);
    if (!data) return;
    const timeMs = u32(ph, 0) * 1000 + u32(ph, 4) / (nano ? 1e6 : 1e3);
    if (!onPacket(linkType, data, timeMs)) return;
  }
}

function readNg(cur: Cursor, firstFour: Buffer, onPacket: PacketHandler): void {
  let little = true;
  // Per interface: link type and how many timestamp units make one millisecond.
  const interfaces: Array<{ linkType: number; unitsPerMs: number }> = [];
  let head: Buffer | null = Buffer.concat([firstFour, cur.read(4) ?? Buffer.alloc(4)]);
  while (head && head.length === 8) {
    const typeLE = head.readUInt32LE(0);
    if (typeLE === 0x0a0d0d0a) {
      const bom = cur.read(4);
      if (!bom) return;
      little = bom.readUInt32LE(0) === 0x1a2b3c4d;
      const total = little ? head.readUInt32LE(4) : head.readUInt32BE(4);
      if (total < 16) return;
      cur.skip(total - 12);
      interfaces.length = 0;
    } else {
      const type = little ? typeLE : head.readUInt32BE(0);
      const total = little ? head.readUInt32LE(4) : head.readUInt32BE(4);
      if (total < 12 || total > MAX_PACKET_BYTES + 4096) return;
      const body = cur.read(total - 8);
      if (!body) return;
      const u16 = (o: number): number => (little ? body.readUInt16LE(o) : body.readUInt16BE(o));
      const u32 = (o: number): number => (little ? body.readUInt32LE(o) : body.readUInt32BE(o));
      if (type === 1 && body.length >= 12) {
        let unitsPerMs = 1000;
        for (let o = 8; o + 4 <= body.length - 4; ) {
          const code = u16(o);
          const len = u16(o + 2);
          if (code === 0) break;
          if (code === 9 && len >= 1) {
            const v = body[o + 4] ?? 6;
            const perSecond = v & 0x80 ? 2 ** (v & 0x7f) : 10 ** v;
            unitsPerMs = perSecond / 1000;
          }
          o += 4 + Math.ceil(len / 4) * 4;
        }
        interfaces.push({ linkType: u16(0), unitsPerMs });
      } else if (type === 6 && body.length >= 24) {
        const iface = interfaces[u32(0)];
        const caplen = u32(12);
        if (iface && caplen <= body.length - 24) {
          const ticks = u32(4) * 2 ** 32 + u32(8);
          if (!onPacket(iface.linkType, body.subarray(20, 20 + caplen), ticks / iface.unitsPerMs)) return;
        }
      }
    }
    head = cur.read(8);
  }
}

const ipv4 = (b: Buffer, o: number): string => `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;

function ipv6(b: Buffer, o: number): string {
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(b.readUInt16BE(o + i).toString(16));
  return groups.join(":").replace(/(^|:)0(:0)+(:|$)/, "::");
}

interface Segment {
  proto: "tcp" | "udp";
  src: string;
  dst: string;
  sport: number;
  dport: number;
  payload: Buffer;
  syn: boolean;
}

/** Strip link, IP and transport headers. Returns null for anything that is not TCP or UDP over IP. */
export function decodePacket(linkType: number, data: Buffer): Segment | null {
  let o: number;
  if (linkType === 1) {
    if (data.length < 14) return null;
    let type = data.readUInt16BE(12);
    o = 14;
    while ((type === 0x8100 || type === 0x88a8) && data.length >= o + 4) {
      type = data.readUInt16BE(o + 2);
      o += 4;
    }
    if (type !== 0x0800 && type !== 0x86dd) return null;
  } else if (linkType === 113) o = 16;
  else if (linkType === 276) o = 20;
  else if (linkType === 0 || linkType === 108) o = 4;
  else if (linkType === 101 || linkType === 228 || linkType === 229 || linkType === 12) o = 0;
  else return null;
  if (data.length < o + 20) return null;

  const version = (data[o] ?? 0) >> 4;
  let proto: number;
  let src: string;
  let dst: string;
  let t: number;
  if (version === 4) {
    const ihl = ((data[o] ?? 0) & 0x0f) * 4;
    if (ihl < 20 || (data.readUInt16BE(o + 6) & 0x1fff) !== 0) return null;
    proto = data[o + 9] ?? 0;
    src = ipv4(data, o + 12);
    dst = ipv4(data, o + 16);
    t = o + ihl;
  } else if (version === 6) {
    if (data.length < o + 40) return null;
    proto = data[o + 6] ?? 0;
    src = ipv6(data, o + 8);
    dst = ipv6(data, o + 24);
    t = o + 40;
  } else return null;

  if (proto === 6) {
    if (data.length < t + 20) return null;
    const headerLen = ((data[t + 12] ?? 0) >> 4) * 4;
    if (headerLen < 20 || data.length < t + headerLen) return null;
    const flags = data[t + 13] ?? 0;
    return {
      proto: "tcp", src, dst, sport: data.readUInt16BE(t), dport: data.readUInt16BE(t + 2),
      payload: data.subarray(t + headerLen), syn: (flags & 0x12) === 0x02,
    };
  }
  if (proto === 17) {
    if (data.length < t + 8) return null;
    return { proto: "udp", src, dst, sport: data.readUInt16BE(t), dport: data.readUInt16BE(t + 2), payload: data.subarray(t + 8), syn: false };
  }
  return null;
}

/** The name asked for in a DNS query, or null for responses and malformed packets. */
export function dnsQueryName(p: Buffer): string | null {
  if (p.length < 17 || ((p[2] ?? 0) & 0x80) !== 0 || p.readUInt16BE(4) < 1) return null;
  const labels: string[] = [];
  let o = 12;
  for (;;) {
    const len = p[o];
    if (len === undefined || len > 63) return null;
    if (len === 0) break;
    if (o + 1 + len > p.length) return null;
    labels.push(p.toString("latin1", o + 1, o + 1 + len));
    o += 1 + len;
    if (labels.length > 40) return null;
  }
  const name = labels.join(".");
  return /^[\x21-\x7e]{1,253}$/.test(name) ? name : null;
}

/** The server name a TLS client asks for (SNI), or null. */
export function tlsServerName(p: Buffer): string | null {
  if (p.length < 44 || p[0] !== 0x16 || p[1] !== 0x03 || p[5] !== 0x01) return null;
  let o = 43;
  const skip = (lengthBytes: 1 | 2): boolean => {
    if (o + lengthBytes > p.length) return false;
    o += lengthBytes + (lengthBytes === 1 ? (p[o] ?? 0) : p.readUInt16BE(o));
    return o <= p.length;
  };
  if (!skip(1) || !skip(2) || !skip(1) || o + 2 > p.length) return null;
  const end = Math.min(p.length, o + 2 + p.readUInt16BE(o));
  o += 2;
  while (o + 4 <= end) {
    const type = p.readUInt16BE(o);
    const len = p.readUInt16BE(o + 2);
    if (type === 0 && o + 9 <= end) {
      const nameLen = p.readUInt16BE(o + 7);
      if (o + 9 + nameLen > p.length) return null;
      const name = p.toString("latin1", o + 9, o + 9 + nameLen);
      return /^[a-zA-Z0-9.-]{1,253}$/.test(name) ? name : null;
    }
    o += 4 + len;
  }
  return null;
}

const HTTP_START = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (\S{1,2000}) HTTP\/1\.[01]\r\n/;

function header(text: string, name: string): string {
  const m = new RegExp(`\\r\\n${name}:[ \\t]*([^\\r\\n]{0,500})`, "i").exec(text);
  return m?.[1] ?? "";
}

/** Read a capture and reduce it to flows, DNS lookups, HTTP requests and exposed logins. */
export function readPcap(path: string, limits: Partial<PcapLimits> = {}): PcapResult {
  const cap = { ...DEFAULT_LIMITS, ...limits };
  const flows = new Map<string, Flow>();
  const result: PcapResult = { packets: 0, flows: [], dns: [], http: [], credentials: [], truncated: false };

  const onPacket: PacketHandler = (linkType, data, timeMs) => {
    if (++result.packets > cap.maxPackets) {
      result.truncated = true;
      return false;
    }
    const seg = decodePacket(linkType, data);
    if (!seg) return true;

    const forward = `${seg.proto}|${seg.src}|${seg.sport}|${seg.dst}|${seg.dport}`;
    let flow = flows.get(forward) ?? flows.get(`${seg.proto}|${seg.dst}|${seg.dport}|${seg.src}|${seg.sport}`);
    if (!flow) {
      if (flows.size >= cap.maxFlows) {
        result.truncated = true;
      } else {
        // Whoever speaks first is the client, unless the ports say otherwise mid-capture.
        const clientFirst = seg.syn || seg.sport >= seg.dport;
        flow = clientFirst
          ? { proto: seg.proto, src: seg.src, sport: seg.sport, dst: seg.dst, dport: seg.dport, packets: 0, bytes: 0, first: timeMs, last: timeMs }
          : { proto: seg.proto, src: seg.dst, sport: seg.dport, dst: seg.src, dport: seg.sport, packets: 0, bytes: 0, first: timeMs, last: timeMs };
        flows.set(`${flow.proto}|${flow.src}|${flow.sport}|${flow.dst}|${flow.dport}`, flow);
      }
    }
    if (flow) {
      flow.packets++;
      flow.bytes += data.length;
      flow.last = timeMs;
    }

    const p = seg.payload;
    if (p.length === 0) return true;
    if (seg.proto === "udp" && seg.dport === 53) {
      const name = dnsQueryName(p);
      if (name) {
        if (result.dns.length < cap.maxDns) result.dns.push({ time: timeMs, src: seg.src, name });
        else result.truncated = true;
      }
      return true;
    }
    if (seg.proto !== "tcp") return true;
    if (p[0] === 0x16) {
      const sni = tlsServerName(p);
      if (sni && flow) flow.sni = sni;
      return true;
    }
    const text = p.toString("latin1", 0, Math.min(p.length, 4096));
    const http = HTTP_START.exec(text);
    if (http) {
      const host = header(text, "Host");
      if (flow && host) flow.httpHost = host;
      if (result.http.length < cap.maxHttp) {
        result.http.push({ time: timeMs, src: seg.src, dst: seg.dst, method: http[1] ?? "", host, uri: http[2] ?? "", userAgent: header(text, "User-Agent") });
      } else result.truncated = true;
      const basic = /^Basic\s+([A-Za-z0-9+/=]{4,400})/.exec(header(text, "Authorization"));
      if (basic?.[1]) {
        // Keep the username, never the password.
        const user = Buffer.from(basic[1], "base64").toString("latin1").split(":")[0] ?? "";
        result.credentials.push({ time: timeMs, src: seg.src, dst: seg.dst, protocol: "HTTP Basic", user });
      }
      return true;
    }
    if (seg.dport === 21 || seg.dport === 110 || seg.dport === 143) {
      const user = /^USER\s+(\S{1,100})\r?\n/i.exec(text);
      if (user?.[1]) {
        result.credentials.push({ time: timeMs, src: seg.src, dst: seg.dst, protocol: seg.dport === 21 ? "FTP" : seg.dport === 110 ? "POP3" : "IMAP", user: user[1] });
      }
    }
    return true;
  };

  const fd = openSync(path, "r");
  try {
    const cur = new Cursor(fd);
    const magic = cur.read(4);
    if (!magic) throw new Error("File is too short to be a capture.");
    const le = magic.readUInt32LE(0);
    if (le === 0x0a0d0d0a) readNg(cur, magic, onPacket);
    else if ([0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1].includes(le)) readClassic(cur, magic, onPacket);
    else throw new Error("Not a pcap or pcapng file.");
  } finally {
    closeSync(fd);
  }
  result.flows = [...flows.values()];
  return result;
}
