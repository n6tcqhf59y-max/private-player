/**
 * 加密备份容器（.ppb）。
 * 仍需应用密码才能恢复。不包含任何自动上传逻辑。
 *
 * 格式（小端）：
 *   magic "PPB1" (4)
 *   version uint16 (2)
 *   flags uint16 (2)  保留为 0
 *   headerLen uint32 (4)
 *   header JSON utf-8
 *   catalogLen uint32 (4)
 *   catalog  (AES-GCM 包装：iv + ct，内容为目录 JSON)
 *   随后按 header.items 顺序拼接每条视频的密文（已是 PVID，不再二次加密）
 */

import {
  bytesToBase64,
  base64ToBytes,
  concatBytes,
  writeAscii,
  readAscii,
  readU16,
  readU32,
  u16,
  u32,
} from "./util.js";
import { decryptJson, encryptJson, unlockVault } from "./crypto.js";

export const BACKUP_MAGIC = "PPB1";
export const BACKUP_VERSION = 1;
export const BACKUP_PREFIX = 12;

export class BackupError extends Error {
  constructor(message, code = "BACKUP") {
    super(message);
    this.name = "BackupError";
    this.code = code;
  }
}

function headerToVaultRecord(header) {
  const v = header?.vault;
  if (!v) throw new BackupError("备份中缺少密钥信息。", "BAD_BACKUP");
  return {
    version: 1,
    kdf: v.kdf,
    iterations: v.iterations,
    salt: v.salt,
    wrapIV: v.wrapIV,
    wrappedDEK: v.wrappedDEK,
  };
}

export function buildBackupHeader({ vaultRecord, items, createdAt, catalog }) {
  return {
    app: "iphone-private-player",
    createdAt: createdAt || new Date().toISOString(),
    vault: {
      kdf: vaultRecord.kdf,
      iterations: vaultRecord.iterations,
      salt: vaultRecord.salt,
      wrapIV: vaultRecord.wrapIV,
      wrappedDEK: vaultRecord.wrappedDEK,
    },
    catalog: catalog ? { encoding: "aes-256-gcm" } : undefined,
    items: items.map((it) => ({
      id: it.id,
      encSize: Number(it.encSize),
      hasThumb: Boolean(it.hasThumb),
      thumbSize: it.hasThumb ? Number(it.thumbSize || 0) : 0,
    })),
  };
}

export async function buildBackupBlob({ vaultRecord, dekKey, catalog, items }) {
  if (!vaultRecord || !dekKey) {
    throw new BackupError("无法在未解锁时导出备份。", "LOCKED");
  }
  const catalogPacked = await encryptJson(dekKey, catalog);
  const normalized = [];
  for (const item of items) {
    const encBytes = item.encBytes ?? new Uint8Array(await item.encBlob.arrayBuffer());
    const thumbBytes = item.hasThumb
      ? item.thumbBytes ?? (item.thumbBlob ? new Uint8Array(await item.thumbBlob.arrayBuffer()) : null)
      : null;
    normalized.push({
      id: item.id,
      encBytes,
      encSize: encBytes.length,
      hasThumb: Boolean(thumbBytes && thumbBytes.length),
      thumbBytes: thumbBytes || null,
      thumbSize: thumbBytes ? thumbBytes.length : 0,
    });
  }
  const header = buildBackupHeader({
    vaultRecord,
    items: normalized,
    catalog: true,
  });
  const headerBytes = new TextEncoder().encode(JSON.stringify(header));
  const parts = [
    (() => {
      const prefix = new Uint8Array(BACKUP_PREFIX);
      writeAscii(prefix, 0, BACKUP_MAGIC);
      prefix.set(u16(BACKUP_VERSION), 4);
      prefix.set(u16(0), 6);
      prefix.set(u32(headerBytes.length), 8);
      return prefix;
    })(),
    headerBytes,
    u32(catalogPacked.length),
    catalogPacked,
  ];
  for (const item of normalized) {
    parts.push(item.encBytes);
    if (item.hasThumb) parts.push(item.thumbBytes);
  }
  return new Blob(parts, { type: "application/octet-stream" });
}

export function parseBackupPrefixAndHeader(bytes) {
  const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (data.length < BACKUP_PREFIX) {
    throw new BackupError("备份文件太短或不完整。", "BAD_BACKUP");
  }
  const magic = readAscii(data, 0, 4);
  if (magic !== BACKUP_MAGIC) {
    throw new BackupError("不是有效的私密播放器备份文件。", "BAD_BACKUP");
  }
  const version = readU16(data, 4);
  if (version !== BACKUP_VERSION) {
    throw new BackupError(`不支持的备份版本：${version}。`, "BAD_BACKUP");
  }
  const headerLen = readU32(data, 8);
  const headerStart = BACKUP_PREFIX;
  const headerEnd = headerStart + headerLen;
  if (headerEnd > data.length) {
    throw new BackupError("备份文件头不完整。", "BAD_BACKUP");
  }
  let header;
  try {
    header = JSON.parse(new TextDecoder().decode(data.subarray(headerStart, headerEnd)));
  } catch {
    throw new BackupError("备份文件头已损坏。", "BAD_BACKUP");
  }
  if (!header || header.app !== "iphone-private-player" || !Array.isArray(header.items)) {
    throw new BackupError("备份内容无法识别。", "BAD_BACKUP");
  }
  return { header, headerEnd, version };
}

/**
 * 解析完整备份（适合测试与中等大小文件）。大文件在浏览器中请用 parseBackupBlob。
 */
export function parseBackupBytes(bytes) {
  const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const { header, headerEnd } = parseBackupPrefixAndHeader(data);
  if (headerEnd + 4 > data.length) {
    throw new BackupError("备份目录不完整。", "BAD_BACKUP");
  }
  const catalogLen = readU32(data, headerEnd);
  const catalogStart = headerEnd + 4;
  const catalogEnd = catalogStart + catalogLen;
  if (catalogEnd > data.length) {
    throw new BackupError("备份目录不完整。", "BAD_BACKUP");
  }
  const encCatalog = data.subarray(catalogStart, catalogEnd);
  let offset = catalogEnd;
  const items = [];
  for (const meta of header.items) {
    const encSize = Number(meta.encSize);
    if (!Number.isFinite(encSize) || encSize < 0 || offset + encSize > data.length) {
      throw new BackupError("备份中的视频数据不完整。", "BAD_BACKUP");
    }
    const encBytes = data.subarray(offset, offset + encSize);
    offset += encSize;
    let thumbBytes = null;
    const thumbSize = meta.hasThumb ? Number(meta.thumbSize || 0) : 0;
    if (meta.hasThumb) {
      if (!Number.isFinite(thumbSize) || thumbSize < 0 || offset + thumbSize > data.length) {
        throw new BackupError("备份中的缩略图不完整。", "BAD_BACKUP");
      }
      thumbBytes = data.subarray(offset, offset + thumbSize);
      offset += thumbSize;
    }
    items.push({
      id: meta.id,
      encBytes,
      encSize,
      hasThumb: Boolean(meta.hasThumb),
      thumbBytes,
      thumbSize,
    });
  }
  if (offset !== data.length) {
    throw new BackupError("备份文件有多余或缺失的数据。", "BAD_BACKUP");
  }
  return {
    header,
    vaultRecord: headerToVaultRecord(header),
    encCatalog,
    items,
  };
}

export async function parseBackupBlob(blob) {
  if (blob.size < BACKUP_PREFIX + 4) {
    throw new BackupError("备份文件太短或不完整。", "BAD_BACKUP");
  }
  const headGuess = Math.min(blob.size, 2 * 1024 * 1024);
  const prefixBytes = new Uint8Array(await blob.slice(0, headGuess).arrayBuffer());
  const { header, headerEnd } = parseBackupPrefixAndHeader(prefixBytes);
  if (headerEnd + 4 > blob.size) {
    throw new BackupError("备份目录不完整。", "BAD_BACKUP");
  }
  let catalogLen;
  if (headerEnd + 4 <= prefixBytes.length) {
    catalogLen = readU32(prefixBytes, headerEnd);
  } else {
    const n = new Uint8Array(await blob.slice(headerEnd, headerEnd + 4).arrayBuffer());
    catalogLen = readU32(n, 0);
  }
  const catalogStart = headerEnd + 4;
  const catalogEnd = catalogStart + catalogLen;
  if (catalogEnd > blob.size) {
    throw new BackupError("备份目录不完整。", "BAD_BACKUP");
  }
  const encCatalog = new Uint8Array(await blob.slice(catalogStart, catalogEnd).arrayBuffer());
  let offset = catalogEnd;
  const items = [];
  for (const meta of header.items) {
    const encSize = Number(meta.encSize);
    if (!Number.isFinite(encSize) || encSize < 0 || offset + encSize > blob.size) {
      throw new BackupError("备份中的视频数据不完整。", "BAD_BACKUP");
    }
    const encBlob = blob.slice(offset, offset + encSize);
    offset += encSize;
    let thumbBlob = null;
    const thumbSize = meta.hasThumb ? Number(meta.thumbSize || 0) : 0;
    if (meta.hasThumb) {
      if (!Number.isFinite(thumbSize) || thumbSize < 0 || offset + thumbSize > blob.size) {
        throw new BackupError("备份中的缩略图不完整。", "BAD_BACKUP");
      }
      thumbBlob = blob.slice(offset, offset + thumbSize);
      offset += thumbSize;
    }
    items.push({
      id: meta.id,
      encBlob,
      encSize,
      hasThumb: Boolean(meta.hasThumb),
      thumbBlob,
      thumbSize,
    });
  }
  if (offset !== blob.size) {
    throw new BackupError("备份文件有多余或缺失的数据。", "BAD_BACKUP");
  }
  return {
    header,
    vaultRecord: headerToVaultRecord(header),
    encCatalog,
    items,
  };
}

/**
 * 用密码打开备份：解开 DEK 并解密目录。视频密文保持加密，不必解密内容。
 */
export async function openBackupWithPassword(parsed, password) {
  const dekBytes = await unlockVault(parsed.vaultRecord, password);
  const { importDEK } = await import("./crypto.js");
  const dekKey = await importDEK(dekBytes);
  const catalog = await decryptJson(dekKey, parsed.encCatalog);
  return { dekBytes, dekKey, catalog, vaultRecord: parsed.vaultRecord };
}

export function vaultRecordFromBackup(parsed) {
  return parsed.vaultRecord;
}

export { bytesToBase64, base64ToBytes };
