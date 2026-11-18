/**
 * 本地加密核心。
 * - 应用密码不明文存盘
 * - 随机 DEK，用密码派生的 KEK（PBKDF2-SHA-256）包装
 * - 改密码只重新包装 DEK
 * - 视频与元数据使用 AES-256-GCM（分块）加密
 *
 * 仅使用 Web Crypto，可在浏览器与 Node 中运行。
 */

import {
  normalizePassword,
  bytesToBase64,
  base64ToBytes,
  concatBytes,
  writeAscii,
  readAscii,
  readU16,
  readU32,
  readU64,
  u16,
  u32,
  u64,
} from "./util.js";

export const PBKDF2_ITERATIONS = 600_000;
export const CHUNK_SIZE = 1024 * 1024;
export const SALT_BYTES = 16;
export const IV_BYTES = 12;
export const DEK_BYTES = 32;
export const GCM_TAG_BYTES = 16;
export const PVID_MAGIC = "PVID";
export const PVID_VERSION = 1;
export const PVID_HEADER_SIZE = 18;
export const MIN_PASSWORD_LENGTH = 8;

export class CryptoError extends Error {
  constructor(message, code = "CRYPTO") {
    super(message);
    this.name = "CryptoError";
    this.code = code;
  }
}

function subtle() {
  const c = globalThis.crypto;
  if (!c?.subtle) {
    throw new CryptoError(
      "当前不是安全上下文（需要 HTTPS 或 localhost），无法使用加密接口。",
      "NO_SUBTLE"
    );
  }
  return c.subtle;
}

function randomBytes(length) {
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}

export function assertPassword(password) {
  const p = normalizePassword(password);
  if (!p) throw new CryptoError("请输入密码。", "EMPTY_PASSWORD");
  if (p.length < MIN_PASSWORD_LENGTH) {
    throw new CryptoError(`密码至少需要 ${MIN_PASSWORD_LENGTH} 个字符。`, "WEAK_PASSWORD");
  }
  return p;
}

export async function deriveKEK(password, salt, iterations) {
  const pwd = normalizePassword(password);
  if (!pwd) throw new CryptoError("请输入密码。", "EMPTY_PASSWORD");
  if (!salt?.length) throw new CryptoError("缺少盐值。", "BAD_SALT");
  const iter = Number(iterations);
  if (!Number.isFinite(iter) || iter < 1) {
    throw new CryptoError("KDF 迭代次数无效。", "BAD_ITER");
  }
  const keyMaterial = await subtle().importKey(
    "raw",
    new TextEncoder().encode(pwd),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return subtle().deriveKey(
    { name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function generateDEKBytes() {
  return randomBytes(DEK_BYTES);
}

export async function importDEK(dekBytes) {
  if (!(dekBytes instanceof Uint8Array) || dekBytes.length !== DEK_BYTES) {
    throw new CryptoError("DEK 长度无效。", "BAD_DEK");
  }
  return subtle().importKey("raw", dekBytes, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

export async function wrapDEK(dekBytes, kek) {
  const iv = randomBytes(IV_BYTES);
  const wrapped = new Uint8Array(
    await subtle().encrypt({ name: "AES-GCM", iv }, kek, dekBytes)
  );
  return { iv, wrapped };
}

export async function unwrapDEK(wrapped, iv, kek) {
  try {
    return new Uint8Array(
      await subtle().decrypt({ name: "AES-GCM", iv }, kek, wrapped)
    );
  } catch {
    throw new CryptoError("密码不正确，或密钥数据已损坏。", "BAD_PASSWORD");
  }
}

export function serializeVaultRecord(record) {
  return {
    version: 1,
    kdf: "PBKDF2-SHA-256",
    iterations: record.iterations,
    salt: typeof record.salt === "string" ? record.salt : bytesToBase64(record.salt),
    wrapIV: typeof record.wrapIV === "string" ? record.wrapIV : bytesToBase64(record.wrapIV),
    wrappedDEK:
      typeof record.wrappedDEK === "string"
        ? record.wrappedDEK
        : bytesToBase64(record.wrappedDEK),
  };
}

export async function createVaultRecord(password, options = {}) {
  const pwd = assertPassword(password);
  const iterations = options.iterations ?? PBKDF2_ITERATIONS;
  const salt = options.salt ?? randomBytes(SALT_BYTES);
  const dekBytes = options.dekBytes ?? (await generateDEKBytes());
  const kek = await deriveKEK(pwd, salt, iterations);
  const { iv, wrapped } = await wrapDEK(dekBytes, kek);
  const record = serializeVaultRecord({
    iterations,
    salt,
    wrapIV: iv,
    wrappedDEK: wrapped,
  });
  return { record, dekBytes };
}

export async function unlockVault(record, password) {
  if (!record || record.kdf !== "PBKDF2-SHA-256") {
    throw new CryptoError("不支持的密钥库格式。", "BAD_VAULT");
  }
  const pwd = normalizePassword(password);
  if (!pwd) throw new CryptoError("请输入密码。", "EMPTY_PASSWORD");
  const salt = base64ToBytes(record.salt);
  const kek = await deriveKEK(pwd, salt, record.iterations);
  const dekBytes = await unwrapDEK(
    base64ToBytes(record.wrappedDEK),
    base64ToBytes(record.wrapIV),
    kek
  );
  if (dekBytes.length !== DEK_BYTES) {
    throw new CryptoError("密钥数据已损坏。", "BAD_VAULT");
  }
  return dekBytes;
}

/**
 * 只重新包装 DEK，不重新加密任何视频。
 */
export async function rewrapVault(dekBytes, newPassword, options = {}) {
  const pwd = assertPassword(newPassword);
  const iterations = options.iterations ?? PBKDF2_ITERATIONS;
  const salt = randomBytes(SALT_BYTES);
  const kek = await deriveKEK(pwd, salt, iterations);
  const { iv, wrapped } = await wrapDEK(dekBytes, kek);
  return serializeVaultRecord({
    iterations,
    salt,
    wrapIV: iv,
    wrappedDEK: wrapped,
  });
}

export async function encryptBytes(dekKey, plaintext) {
  const iv = randomBytes(IV_BYTES);
  const data = plaintext instanceof Uint8Array ? plaintext : new Uint8Array(plaintext);
  const ct = new Uint8Array(
    await subtle().encrypt({ name: "AES-GCM", iv }, dekKey, data)
  );
  return concatBytes([iv, ct]);
}

export async function decryptBytes(dekKey, packed) {
  const data = packed instanceof Uint8Array ? packed : new Uint8Array(packed);
  if (data.length < IV_BYTES + GCM_TAG_BYTES) {
    throw new CryptoError("密文太短，无法解密。", "BAD_CIPHERTEXT");
  }
  const iv = data.subarray(0, IV_BYTES);
  const ct = data.subarray(IV_BYTES);
  try {
    return new Uint8Array(
      await subtle().decrypt({ name: "AES-GCM", iv }, dekKey, ct)
    );
  } catch {
    throw new CryptoError("数据解密失败，文件可能已损坏或密钥不匹配。", "DECRYPT_FAIL");
  }
}

export function encodePvidHeader(originalSize, chunkSize = CHUNK_SIZE) {
  const header = new Uint8Array(PVID_HEADER_SIZE);
  writeAscii(header, 0, PVID_MAGIC);
  header.set(u16(PVID_VERSION), 4);
  header.set(u32(chunkSize), 6);
  header.set(u64(originalSize), 10);
  return header;
}

export function parsePvidHeader(bytes) {
  const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (data.length < PVID_HEADER_SIZE) {
    throw new CryptoError("加密视频文件头不完整。", "BAD_PVID");
  }
  const magic = readAscii(data, 0, 4);
  if (magic !== PVID_MAGIC) {
    throw new CryptoError("不是有效的加密视频文件。", "BAD_PVID");
  }
  const version = readU16(data, 4);
  if (version !== PVID_VERSION) {
    throw new CryptoError(`不支持的加密视频版本：${version}。`, "BAD_PVID");
  }
  const chunkSize = readU32(data, 6);
  const originalSize = readU64(data, 10);
  if (!chunkSize || chunkSize > 32 * 1024 * 1024) {
    throw new CryptoError("分块大小无效。", "BAD_PVID");
  }
  if (!Number.isFinite(originalSize) || originalSize < 0) {
    throw new CryptoError("原始大小无效。", "BAD_PVID");
  }
  return { version, chunkSize, originalSize };
}

export async function encryptChunk(dekKey, plainChunk) {
  return encryptBytes(dekKey, plainChunk);
}

export async function decryptChunk(dekKey, encChunk) {
  return decryptBytes(dekKey, encChunk);
}

/**
 * 把整段明文加密为 PVID 容器（适合测试与较小数据）。
 */
export async function encryptChunked(dekKey, plaintext, chunkSize = CHUNK_SIZE) {
  const data = plaintext instanceof Uint8Array ? plaintext : new Uint8Array(plaintext);
  const header = encodePvidHeader(data.length, chunkSize);
  const parts = [header];
  for (let offset = 0; offset < data.length; offset += chunkSize) {
    const slice = data.subarray(offset, Math.min(offset + chunkSize, data.length));
    parts.push(await encryptChunk(dekKey, slice));
  }
  return concatBytes(parts);
}

/**
 * 解密完整 PVID 容器，返回明文。
 */
export async function decryptChunked(dekKey, pvidBytes) {
  const data = pvidBytes instanceof Uint8Array ? pvidBytes : new Uint8Array(pvidBytes);
  const { chunkSize, originalSize } = parsePvidHeader(data);
  const parts = [];
  let offset = PVID_HEADER_SIZE;
  let remaining = originalSize;
  while (remaining > 0) {
    const plainLen = Math.min(chunkSize, remaining);
    const encLen = IV_BYTES + plainLen + GCM_TAG_BYTES;
    if (offset + encLen > data.length) {
      throw new CryptoError("加密视频数据不完整。", "BAD_PVID");
    }
    const enc = data.subarray(offset, offset + encLen);
    const plain = await decryptChunk(dekKey, enc);
    if (plain.length !== plainLen) {
      throw new CryptoError("分块长度与文件头不一致。", "BAD_PVID");
    }
    parts.push(plain);
    offset += encLen;
    remaining -= plainLen;
  }
  if (offset !== data.length) {
    throw new CryptoError("加密视频文件有多余数据。", "BAD_PVID");
  }
  return concatBytes(parts);
}

/**
 * 按块加密 Blob / File，通过 onChunk 写出，避免把全部明文或密文一次放进内存。
 * onChunk(uint8) 可返回 Promise。
 */
export async function encryptBlobChunked(dekKey, blob, onChunk, options = {}) {
  const chunkSize = options.chunkSize ?? CHUNK_SIZE;
  const size = Number(blob.size);
  await onChunk(encodePvidHeader(size, chunkSize));
  let offset = 0;
  let processed = 0;
  while (offset < size) {
    const end = Math.min(offset + chunkSize, size);
    const slice = blob.slice(offset, end);
    const buf = new Uint8Array(await slice.arrayBuffer());
    const enc = await encryptChunk(dekKey, buf);
    buf.fill(0);
    await onChunk(enc);
    processed += end - offset;
    offset = end;
    options.onProgress?.(processed, size);
  }
}

/**
 * 从 PVID Blob 分块解密。onPlainChunk(uint8) 用于组装播放用 Blob。
 * 解密后不会把整个密文留在函数作用域。
 */
export async function decryptPvidBlob(dekKey, pvidBlob, options = {}) {
  if (pvidBlob.size < PVID_HEADER_SIZE) {
    throw new CryptoError("加密视频文件头不完整。", "BAD_PVID");
  }
  const headerBuf = new Uint8Array(
    await pvidBlob.slice(0, PVID_HEADER_SIZE).arrayBuffer()
  );
  const { chunkSize, originalSize } = parsePvidHeader(headerBuf);
  const parts = [];
  let offset = PVID_HEADER_SIZE;
  let remaining = originalSize;
  const totalEnc = pvidBlob.size;
  while (remaining > 0) {
    const plainLen = Math.min(chunkSize, remaining);
    const encLen = IV_BYTES + plainLen + GCM_TAG_BYTES;
    if (offset + encLen > totalEnc) {
      throw new CryptoError("加密视频数据不完整。", "BAD_PVID");
    }
    const enc = new Uint8Array(
      await pvidBlob.slice(offset, offset + encLen).arrayBuffer()
    );
    const plain = await decryptChunk(dekKey, enc);
    enc.fill(0);
    if (plain.length !== plainLen) {
      throw new CryptoError("分块长度与文件头不一致。", "BAD_PVID");
    }
    parts.push(plain);
    offset += encLen;
    remaining -= plainLen;
    options.onProgress?.(originalSize - remaining, originalSize);
  }
  if (offset !== totalEnc) {
    throw new CryptoError("加密视频文件有多余数据。", "BAD_PVID");
  }
  const mime = options.mime || "application/octet-stream";
  const blob = new Blob(parts, { type: mime });
  for (const p of parts) p.fill?.(0);
  parts.length = 0;
  return blob;
}

export async function encryptJson(dekKey, value) {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  const packed = await encryptBytes(dekKey, bytes);
  bytes.fill(0);
  return packed;
}

export async function decryptJson(dekKey, packed) {
  const plain = await decryptBytes(dekKey, packed);
  const text = new TextDecoder().decode(plain);
  plain.fill(0);
  return JSON.parse(text);
}
