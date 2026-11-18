/**
 * 本地存储：优先 OPFS 存放加密视频，IndexedDB 存密钥库记录与加密目录。
 * 不向网络发送任何数据。
 */

const DB_NAME = "private-player";
const DB_VERSION = 1;
const KV_STORE = "kv";
const BLOB_STORE = "blobs";

export const KEY_VAULT = "vault";
export const KEY_CATALOG = "catalog";
export const KEY_SETTINGS = "settings";
export const KEY_WEBAUTHN = "webauthn";

let dbPromise = null;

function openDb() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(KV_STORE)) db.createObjectStore(KV_STORE);
      if (!db.objectStoreNames.contains(BLOB_STORE)) db.createObjectStore(BLOB_STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error("无法打开本地数据库"));
  });
  return dbPromise;
}

function idbReq(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function kvGet(key) {
  const db = await openDb();
  return idbReq(db.transaction(KV_STORE, "readonly").objectStore(KV_STORE).get(key));
}

export async function kvSet(key, value) {
  const db = await openDb();
  const tx = db.transaction(KV_STORE, "readwrite");
  tx.objectStore(KV_STORE).put(value, key);
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function kvDelete(key) {
  const db = await openDb();
  const tx = db.transaction(KV_STORE, "readwrite");
  tx.objectStore(KV_STORE).delete(key);
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function idbPutBlob(key, blob) {
  const db = await openDb();
  const tx = db.transaction(BLOB_STORE, "readwrite");
  tx.objectStore(BLOB_STORE).put(blob, key);
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function idbGetBlob(key) {
  const db = await openDb();
  return idbReq(db.transaction(BLOB_STORE, "readonly").objectStore(BLOB_STORE).get(key));
}

async function idbDeleteBlob(key) {
  const db = await openDb();
  const tx = db.transaction(BLOB_STORE, "readwrite");
  tx.objectStore(BLOB_STORE).delete(key);
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

let opfsSupported = null;

export async function hasOPFS() {
  if (opfsSupported != null) return opfsSupported;
  try {
    opfsSupported = Boolean(navigator.storage?.getDirectory);
    if (opfsSupported) await navigator.storage.getDirectory();
  } catch {
    opfsSupported = false;
  }
  return opfsSupported;
}

async function getDir(name, create = true) {
  const root = await navigator.storage.getDirectory();
  return root.getDirectoryHandle(name, { create });
}

async function opfsWrite(dirName, fileName, source) {
  const dir = await getDir(dirName, true);
  const fh = await dir.getFileHandle(fileName, { create: true });
  const writable = await fh.createWritable();
  try {
    if (typeof source === "function") {
      await source(writable);
    } else {
      await writable.write(source);
    }
  } finally {
    await writable.close();
  }
}

async function opfsRead(dirName, fileName) {
  try {
    const dir = await getDir(dirName, false);
    const fh = await dir.getFileHandle(fileName, { create: false });
    return fh.getFile();
  } catch (err) {
    if (err && (err.name === "NotFoundError" || err.name === "TypeError")) return null;
    throw err;
  }
}

async function opfsRemove(dirName, fileName) {
  try {
    const dir = await getDir(dirName, false);
    await dir.removeEntry(fileName);
  } catch (err) {
    if (err && (err.name === "NotFoundError" || err.name === "TypeError")) return;
    throw err;
  }
}

function videoKey(id) {
  return `video:${id}`;
}
function thumbKey(id) {
  return `thumb:${id}`;
}

async function writeToIdb(id, source) {
  if (typeof source === "function") {
    const parts = [];
    const collector = {
      write: async (chunk) => {
        parts.push(chunk);
      },
      close: async () => {},
    };
    await source(collector);
    await idbPutBlob(videoKey(id), new Blob(parts, { type: "application/octet-stream" }));
    return "idb";
  }
  await idbPutBlob(videoKey(id), source);
  return "idb";
}

export async function writeEncryptedVideo(id, source) {
  if (await hasOPFS()) {
    try {
      await opfsWrite("videos", `${id}.pvid`, source);
      return "opfs";
    } catch {
      try {
        await opfsRemove("videos", `${id}.pvid`);
      } catch {
        /* 忽略不完整文件 */
      }
    }
  }
  return writeToIdb(id, source);
}

export async function readEncryptedVideo(id) {
  if (await hasOPFS()) {
    const file = await opfsRead("videos", `${id}.pvid`);
    if (file) return file;
  }
  const blob = await idbGetBlob(videoKey(id));
  return blob || null;
}

export async function deleteEncryptedVideo(id) {
  if (await hasOPFS()) await opfsRemove("videos", `${id}.pvid`);
  await idbDeleteBlob(videoKey(id));
}

export async function writeEncryptedThumb(id, blob) {
  if (await hasOPFS()) {
    await opfsWrite("thumbs", `${id}.pth`, blob);
    return;
  }
  await idbPutBlob(thumbKey(id), blob);
}

export async function readEncryptedThumb(id) {
  if (await hasOPFS()) {
    const file = await opfsRead("thumbs", `${id}.pth`);
    if (file) return file;
  }
  return (await idbGetBlob(thumbKey(id))) || null;
}

export async function deleteEncryptedThumb(id) {
  if (await hasOPFS()) await opfsRemove("thumbs", `${id}.pth`);
  await idbDeleteBlob(thumbKey(id));
}

export async function requestPersist() {
  if (!navigator.storage?.persist) {
    return { supported: false, persisted: false };
  }
  try {
    const already = await navigator.storage.persisted?.();
    if (already) return { supported: true, persisted: true, already: true };
    const persisted = await navigator.storage.persist();
    return { supported: true, persisted };
  } catch (err) {
    return { supported: true, persisted: false, error: String(err?.message || err) };
  }
}

export async function storageEstimate() {
  try {
    const est = await navigator.storage?.estimate?.();
    if (!est) return null;
    return { usage: est.usage || 0, quota: est.quota || 0 };
  } catch {
    return null;
  }
}

export function defaultSettings() {
  return {
    autoLockMs: 2 * 60 * 1000,
    lockOnBackground: true,
  };
}

export async function loadSettings() {
  const saved = await kvGet(KEY_SETTINGS);
  return { ...defaultSettings(), ...(saved || {}) };
}

export async function saveSettings(settings) {
  await kvSet(KEY_SETTINGS, { ...defaultSettings(), ...settings });
}
