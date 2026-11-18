/**
 * 通用工具（不依赖 DOM，可在 Node 测试中使用）
 */

export function normalizePassword(password) {
  return String(password ?? "").normalize("NFC");
}

export function bytesToBase64(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (typeof Buffer !== "undefined") {
    return Buffer.from(arr).toString("base64");
  }
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < arr.length; i += chunk) {
    bin += String.fromCharCode(...arr.subarray(i, i + chunk));
  }
  return btoa(bin);
}

export function base64ToBytes(b64) {
  if (typeof Buffer !== "undefined") {
    const buf = Buffer.from(String(b64), "base64");
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  const bin = atob(String(b64));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function concatBytes(parts) {
  const list = parts.map((p) => (p instanceof Uint8Array ? p : new Uint8Array(p)));
  let total = 0;
  for (const p of list) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of list) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function writeAscii(target, offset, text) {
  for (let i = 0; i < text.length; i++) target[offset + i] = text.charCodeAt(i) & 0xff;
}

export function readAscii(bytes, offset, length) {
  return String.fromCharCode(...bytes.subarray(offset, offset + length));
}

export function u32(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
}

export function u16(n) {
  const b = new Uint8Array(2);
  new DataView(b.buffer).setUint16(0, n & 0xffff, true);
  return b;
}

export function u64(n) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
}

export function readU16(bytes, offset) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(offset, true);
}

export function readU32(bytes, offset) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, true);
}

export function readU64(bytes, offset) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return Number(view.getBigUint64(offset, true));
}

export function randomId() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  const b = new Uint8Array(16);
  globalThis.crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const hex = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function formatBytes(n) {
  const num = Number(n) || 0;
  if (num < 1024) return `${num} B`;
  if (num < 1024 * 1024) return `${(num / 1024).toFixed(1)} KB`;
  if (num < 1024 * 1024 * 1024) return `${(num / (1024 * 1024)).toFixed(1)} MB`;
  return `${(num / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function formatDuration(seconds) {
  if (seconds == null || !Number.isFinite(seconds) || seconds < 0) return "--:--";
  const s = Math.floor(seconds % 60);
  const m = Math.floor(seconds / 60) % 60;
  const h = Math.floor(seconds / 3600);
  const pad = (v) => String(v).padStart(2, "0");
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`;
}

export function formatDateTime(date = new Date()) {
  const d = date instanceof Date ? date : new Date(date);
  const pad = (v) => String(v).padStart(2, "0");
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}

export function safeFileBaseName(name, fallback = "video") {
  const raw = String(name ?? "").trim() || fallback;
  return raw.replace(/[\\/:*?"<>|]/g, "_").slice(0, 80) || fallback;
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
