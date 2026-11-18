import {
  assertPassword,
  createVaultRecord,
  unlockVault,
  rewrapVault,
  importDEK,
  encryptJson,
  decryptJson,
  encryptBytes,
  decryptBytes,
  encryptBlobChunked,
  decryptPvidBlob,
  CryptoError,
} from "./crypto.js";
import {
  kvGet,
  kvSet,
  kvDelete,
  KEY_VAULT,
  KEY_CATALOG,
  KEY_WEBAUTHN,
  writeEncryptedVideo,
  readEncryptedVideo,
  deleteEncryptedVideo,
  writeEncryptedThumb,
  readEncryptedThumb,
  deleteEncryptedThumb,
  requestPersist,
  storageEstimate,
  loadSettings,
  saveSettings,
} from "./storage.js";
import { buildBackupBlob, parseBackupBlob, openBackupWithPassword } from "./backup.js";
import { createPlayQueue } from "./queue.js";
import {
  detectWebAuthnPrf,
  enrollWebAuthnPrf,
  unlockWithWebAuthnPrf,
  describePrfSupport,
  isSecureAppContext,
} from "./webauthn.js";
import {
  formatBytes,
  formatDuration,
  formatDateTime,
  randomId,
} from "./util.js";

const LARGE_FILE_BYTES = 400 * 1024 * 1024;
const HIDE_CONTROLS_MS = 3500;

const $ = (id) => document.getElementById(id);

const state = {
  vaultRecord: null,
  dekBytes: null,
  dekKey: null,
  catalog: emptyCatalog(),
  settings: { autoLockMs: 120000, lockOnBackground: true },
  webauthn: null,
  prfSupport: "no",
  unlocked: false,
  thumbUrls: new Map(),
  playQueue: null,
  shuffleMode: false,
  videoObjectUrl: null,
  wakeLock: null,
  idleTimer: null,
  hideControlsTimer: null,
  seeking: false,
  currentView: null,
  busy: 0,
};

function beginBusy() {
  state.busy += 1;
  clearIdleTimer();
}

function endBusy() {
  state.busy = Math.max(0, state.busy - 1);
  if (state.unlocked) bumpActivity();
}

function canAutoLock() {
  return state.unlocked && state.busy === 0;
}

function emptyCatalog() {
  return { version: 1, videos: [] };
}

function asBytes(value) {
  if (!value) return null;
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  return new Uint8Array(value);
}

function showView(id) {
  for (const el of document.querySelectorAll(".view")) el.hidden = true;
  const view = $(id);
  if (view) view.hidden = false;
  state.currentView = id;
}

function toast(message) {
  const el = $("toast");
  el.textContent = message;
  el.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => {
    el.hidden = true;
  }, 2600);
}

function closeOverlay() {
  $("overlay").hidden = true;
  $("sheet").replaceChildren();
}

function openSheet({ title, body, actions, center = true }) {
  const overlay = $("overlay");
  const sheet = $("sheet");
  sheet.replaceChildren();
  const h = document.createElement("h3");
  h.textContent = title;
  sheet.append(h);
  if (typeof body === "string") {
    const p = document.createElement("p");
    p.textContent = body;
    sheet.append(p);
  } else if (body) {
    sheet.append(body);
  }
  const stack = document.createElement("div");
  stack.className = "stack";
  for (const action of actions || []) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = `btn ${action.className || "btn-ghost"}`;
    btn.textContent = action.label;
    btn.addEventListener("click", async () => {
      if (action.keepOpen) {
        await action.onClick?.();
        return;
      }
      closeOverlay();
      await action.onClick?.();
    });
    stack.append(btn);
  }
  sheet.append(stack);
  overlay.classList.toggle("center", center);
  overlay.hidden = false;
}

function confirmDialog(title, body, { confirmLabel = "确定", danger = false } = {}) {
  return new Promise((resolve) => {
    openSheet({
      title,
      body,
      actions: [
        {
          label: confirmLabel,
          className: danger ? "btn-danger" : "btn-primary",
          onClick: () => resolve(true),
        },
        { label: "取消", className: "btn-ghost", onClick: () => resolve(false) },
      ],
    });
  });
}

function showProgress(title, text, ratio = 0) {
  $("progressTitle").textContent = title;
  $("progressText").textContent = text || "";
  $("progressBar").style.width = `${Math.max(0, Math.min(1, ratio)) * 100}%`;
  $("progressPane").hidden = false;
}

function hideProgress() {
  $("progressPane").hidden = true;
}

function dropKeys() {
  if (state.dekBytes) state.dekBytes.fill(0);
  state.dekBytes = null;
  state.dekKey = null;
  state.unlocked = false;
  state.catalog = emptyCatalog();
}

function revokeThumbs() {
  for (const url of state.thumbUrls.values()) URL.revokeObjectURL(url);
  state.thumbUrls.clear();
}

function stopPlayback() {
  const video = $("playerVideo");
  video.pause();
  video.removeAttribute("src");
  video.load();
  if (state.videoObjectUrl) {
    URL.revokeObjectURL(state.videoObjectUrl);
    state.videoObjectUrl = null;
  }
  releaseWakeLock();
  state.playQueue = null;
}

function releaseWakeLock() {
  try {
    state.wakeLock?.release?.();
  } catch {
    /* 忽略 */
  }
  state.wakeLock = null;
}

async function tryWakeLock() {
  if (!navigator.wakeLock?.request) return;
  try {
    state.wakeLock = await navigator.wakeLock.request("screen");
    state.wakeLock.addEventListener("release", () => {
      state.wakeLock = null;
    });
  } catch {
    /* iOS 或策略不允许时忽略 */
  }
}

function clearIdleTimer() {
  if (state.idleTimer) {
    clearTimeout(state.idleTimer);
    state.idleTimer = null;
  }
}

function bumpActivity() {
  if (!state.unlocked) return;
  clearIdleTimer();
  const ms = Number(state.settings.autoLockMs) || 0;
  if (ms <= 0) return;
  const playing = state.currentView === "view-player" && !$("playerVideo").paused;
  if (playing) return;
  state.idleTimer = setTimeout(() => {
    if (canAutoLock()) lock("闲置超时");
  }, ms);
}

async function lock(_reason) {
  if (!state.unlocked && state.currentView !== "view-player") {
    stopPlayback();
    return;
  }
  stopPlayback();
  revokeThumbs();
  dropKeys();
  clearIdleTimer();
  closeOverlay();
  hideProgress();
  $("unlock-pass").value = "";
  showView("view-lock");
  updateFaceUnlockButton();
}

async function persistCatalog() {
  const packed = await encryptJson(state.dekKey, state.catalog);
  await kvSet(KEY_CATALOG, packed);
}

async function loadCatalog() {
  const packed = asBytes(await kvGet(KEY_CATALOG));
  if (!packed) {
    state.catalog = emptyCatalog();
    return;
  }
  state.catalog = await decryptJson(state.dekKey, packed);
  if (!state.catalog || !Array.isArray(state.catalog.videos)) {
    state.catalog = emptyCatalog();
  }
}

async function afterUnlock() {
  state.unlocked = true;
  await loadCatalog();
  await loadThumbnails();
  try {
    const result = await requestPersist();
    state.persist = result;
  } catch {
    /* 忽略 */
  }
  renderLibrary();
  refreshSettingsPane();
  showView("view-library");
  bumpActivity();
}

async function unlockWithPassword(password) {
  const dekBytes = await unlockVault(state.vaultRecord, password);
  state.dekBytes = dekBytes;
  state.dekKey = await importDEK(dekBytes);
  await afterUnlock();
}

async function setupPassword(password, confirm) {
  if (password !== confirm) throw new CryptoError("两次输入的密码不一致。", "MISMATCH");
  const { record, dekBytes } = await createVaultRecord(password);
  await kvSet(KEY_VAULT, record);
  state.vaultRecord = record;
  state.dekBytes = dekBytes;
  state.dekKey = await importDEK(dekBytes);
  state.catalog = emptyCatalog();
  await persistCatalog();
  await afterUnlock();
}

function guessMime(name) {
  const lower = String(name || "").toLowerCase();
  if (lower.endsWith(".mov")) return "video/quicktime";
  if (lower.endsWith(".m4v") || lower.endsWith(".mp4")) return "video/mp4";
  if (lower.endsWith(".webm")) return "video/webm";
  if (lower.endsWith(".mkv")) return "video/x-matroska";
  return "video/mp4";
}

function isVideoFile(file) {
  if (file.type && file.type.startsWith("video/")) return true;
  return /\.(mp4|mov|m4v|mkv|webm|hevc|avi)$/i.test(file.name || "");
}

function captureThumb(file, timeoutMs = 8000) {
  return new Promise((resolve) => {
    const url = URL.createObjectURL(file);
    const video = document.createElement("video");
    video.muted = true;
    video.playsInline = true;
    video.setAttribute("playsinline", "");
    video.setAttribute("webkit-playsinline", "");
    video.preload = "auto";
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      URL.revokeObjectURL(url);
      video.removeAttribute("src");
      video.load();
      resolve(result);
    };
    const timer = setTimeout(() => {
      finish({
        blob: null,
        duration: Number.isFinite(video.duration) ? video.duration : null,
      });
    }, timeoutMs);
    const snap = () => {
      const duration = Number.isFinite(video.duration) ? video.duration : null;
      try {
        if (!video.videoWidth) {
          finish({ blob: null, duration });
          return;
        }
        const w = 480;
        const h = 270;
        const canvas = document.createElement("canvas");
        canvas.width = w;
        canvas.height = h;
        const ctx = canvas.getContext("2d");
        const vw = video.videoWidth;
        const vh = video.videoHeight;
        const scale = Math.max(w / vw, h / vh);
        const dw = vw * scale;
        const dh = vh * scale;
        ctx.drawImage(video, (w - dw) / 2, (h - dh) / 2, dw, dh);
        canvas.toBlob((blob) => finish({ blob, duration }), "image/jpeg", 0.8);
      } catch {
        finish({
          blob: null,
          duration: Number.isFinite(video.duration) ? video.duration : null,
        });
      }
    };
    video.addEventListener("loadeddata", () => {
      const duration = Number.isFinite(video.duration) ? video.duration : null;
      const target = duration && duration > 1 ? Math.min(1, duration * 0.08) : 0;
      if (target > 0) {
        video.addEventListener("seeked", snap, { once: true });
        try {
          video.currentTime = target;
        } catch {
          snap();
        }
      } else {
        snap();
      }
    });
    video.addEventListener("error", () => finish({ blob: null, duration: null }));
    video.src = url;
  });
}

async function loadThumbnails() {
  revokeThumbs();
  for (const item of state.catalog.videos) {
    if (!item.hasThumb) continue;
    try {
      const enc = await readEncryptedThumb(item.id);
      if (!enc) continue;
      const packed = new Uint8Array(await enc.arrayBuffer());
      const plain = await decryptBytes(state.dekKey, packed);
      packed.fill(0);
      const blob = new Blob([plain], { type: "image/jpeg" });
      plain.fill(0);
      state.thumbUrls.set(item.id, URL.createObjectURL(blob));
    } catch {
      /* 缩略图失败不影响播放 */
    }
  }
}

function renderLibrary() {
  const empty = $("library-empty");
  const grid = $("library-grid");
  grid.replaceChildren();
  const videos = state.catalog.videos;
  empty.hidden = videos.length > 0;
  for (const item of videos) {
    const card = document.createElement("button");
    card.type = "button";
    card.className = "card";
    const thumb = document.createElement("div");
    thumb.className = "card-thumb";
    const url = state.thumbUrls.get(item.id);
    if (url) {
      const img = document.createElement("img");
      img.alt = "";
      img.src = url;
      thumb.append(img);
    } else {
      const ph = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      ph.setAttribute("viewBox", "0 0 24 24");
      ph.classList.add("ph-icon");
      const p = document.createElementNS("http://www.w3.org/2000/svg", "path");
      p.setAttribute("d", "M8 5v14l11-7z");
      p.setAttribute("fill", "currentColor");
      ph.append(p);
      thumb.append(ph);
    }
    if (item.duration) {
      const dur = document.createElement("span");
      dur.className = "duration";
      dur.textContent = formatDuration(item.duration);
      thumb.append(dur);
    }
    const del = document.createElement("button");
    del.type = "button";
    del.className = "card-delete";
    del.setAttribute("aria-label", "删除");
    del.innerHTML =
      '<svg viewBox="0 0 24 24"><path d="M6 7h12M10 7V5h4v2M9 7l1 12h4l1-12"/></svg>';
    del.addEventListener("click", (ev) => {
      ev.stopPropagation();
      confirmDelete(item);
    });
    thumb.append(del);
    const meta = document.createElement("div");
    meta.className = "card-meta";
    const title = document.createElement("div");
    title.className = "card-title";
    title.textContent = item.name || "未命名视频";
    const sub = document.createElement("div");
    sub.className = "card-sub";
    sub.textContent = formatBytes(item.size);
    meta.append(title, sub);
    card.append(thumb, meta);
    card.addEventListener("click", () => playFromLibrary(item.id, false));
    grid.append(card);
  }
}

async function confirmDelete(item) {
  const ok = await confirmDialog(
    "删除这部视频？",
    `将从本机删除「${item.name || "未命名视频"}」。删除后无法恢复，除非你有备份。`,
    { confirmLabel: "删除", danger: true }
  );
  if (!ok) return;
  await deleteEncryptedVideo(item.id);
  await deleteEncryptedThumb(item.id);
  const thumbUrl = state.thumbUrls.get(item.id);
  if (thumbUrl) {
    URL.revokeObjectURL(thumbUrl);
    state.thumbUrls.delete(item.id);
  }
  state.catalog.videos = state.catalog.videos.filter((v) => v.id !== item.id);
  await persistCatalog();
  renderLibrary();
  toast("已删除");
}

async function importFiles(fileList) {
  const files = [...fileList].filter(isVideoFile);
  if (!files.length) {
    toast("没有选到可识别的视频文件");
    return;
  }
  const large = files.filter((f) => f.size > LARGE_FILE_BYTES);
  if (large.length) {
    const names = large.map((f) => `${f.name}（${formatBytes(f.size)}）`).join("、");
    const ok = await confirmDialog(
      "文件较大",
      `${names} 体积较大。播放时需要在内存中解密，iPhone 可能内存不足。仍要导入吗？`,
      { confirmLabel: "继续导入" }
    );
    if (!ok) return;
  }
  beginBusy();
  try {
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      showProgress(
        `正在导入 ${i + 1} / ${files.length}`,
        file.name,
        i / files.length
      );
      const id = randomId();
      let duration = null;
      let thumbBlob = null;
      try {
        const meta = await captureThumb(file);
        duration = meta.duration;
        thumbBlob = meta.blob;
      } catch {
        /* 缩略图可选 */
      }
      try {
        await writeEncryptedVideo(id, async (writable) => {
          await encryptBlobChunked(state.dekKey, file, (chunk) => writable.write(chunk), {
            onProgress: (done, total) => {
              const base = i / files.length;
              const part = total ? done / total : 1;
              showProgress(
                `正在导入 ${i + 1} / ${files.length}`,
                `${file.name}（${formatBytes(done)} / ${formatBytes(total)}）`,
                base + part / files.length
              );
            },
          });
        });
      } catch (err) {
        await deleteEncryptedVideo(id);
        throw err;
      }
      const encFile = await readEncryptedVideo(id);
      if (thumbBlob) {
        const raw = new Uint8Array(await thumbBlob.arrayBuffer());
        const encThumb = await encryptBytes(state.dekKey, raw);
        raw.fill(0);
        await writeEncryptedThumb(id, new Blob([encThumb], { type: "application/octet-stream" }));
        const url = URL.createObjectURL(new Blob([thumbBlob], { type: "image/jpeg" }));
        state.thumbUrls.set(id, url);
      }
      state.catalog.videos.unshift({
        id,
        name: file.name || "未命名视频",
        size: file.size,
        encSize: encFile ? encFile.size : 0,
        mime: file.type || guessMime(file.name),
        createdAt: file.lastModified
          ? new Date(file.lastModified).toISOString()
          : new Date().toISOString(),
        importedAt: new Date().toISOString(),
        duration,
        hasThumb: Boolean(thumbBlob),
      });
      await persistCatalog();
    }
    renderLibrary();
    toast(files.length === 1 ? "已导入 1 个视频" : `已导入 ${files.length} 个视频`);
  } catch (err) {
    console.error(err);
    toast(err.message || "导入失败，可能是存储空间不足");
  } finally {
    hideProgress();
    $("file-import").value = "";
    endBusy();
  }
}

async function playFromLibrary(startId, shuffle) {
  const ids = state.catalog.videos.map((v) => v.id);
  if (!ids.length) {
    toast("资料库是空的");
    return;
  }
  state.shuffleMode = Boolean(shuffle);
  let startIndex = 0;
  if (shuffle) {
    state.playQueue = createPlayQueue(ids, { shuffle: true });
  } else {
    startIndex = Math.max(0, ids.indexOf(startId));
    state.playQueue = createPlayQueue(ids, { shuffle: false, startIndex });
  }
  $("shuffleBadge").hidden = !state.shuffleMode;
  showView("view-player");
  await loadCurrentVideo(true);
}

async function loadCurrentVideo(autoplay) {
  const id = state.playQueue?.current;
  const item = state.catalog.videos.find((v) => v.id === id);
  if (!item) {
    toast("找不到这部视频");
    return;
  }
  if (item.size > LARGE_FILE_BYTES) {
    toast("这部视频较大，解密时可能占用较多内存");
  }
  const video = $("playerVideo");
  stopSrcOnly();
  $("playerTitle").textContent = item.name || "未命名视频";
  showProgress("正在解密", item.name, 0);
  try {
    const enc = await readEncryptedVideo(item.id);
    if (!enc) throw new Error("加密文件丢失，可能已被系统清理。请从备份恢复。");
    const plainBlob = await decryptPvidBlob(state.dekKey, enc, {
      mime: item.mime || guessMime(item.name),
      onProgress: (done, total) => {
        showProgress("正在解密", `${item.name}（${formatBytes(done)} / ${formatBytes(total)}）`, total ? done / total : 0);
      },
    });
    state.videoObjectUrl = URL.createObjectURL(plainBlob);
    video.setAttribute("playsinline", "");
    video.setAttribute("webkit-playsinline", "");
    video.playsInline = true;
    video.src = state.videoObjectUrl;
    $("btn-prev").disabled = !state.playQueue.hasPrev();
    $("btn-next").disabled = !state.playQueue.hasNext();
    hideProgress();
    if (autoplay) {
      try {
        await video.play();
      } catch {
        /* 需要用户再次点击播放 */
      }
    }
    await tryWakeLock();
    showPlayerControls(true);
  } catch (err) {
    hideProgress();
    toast(err.message || "无法播放");
  }
}

function stopSrcOnly() {
  const video = $("playerVideo");
  video.pause();
  video.removeAttribute("src");
  video.load();
  if (state.videoObjectUrl) {
    URL.revokeObjectURL(state.videoObjectUrl);
    state.videoObjectUrl = null;
  }
}

function setPlayingUi(playing) {
  $("iconPlay").hidden = playing;
  $("iconPause").hidden = !playing;
  $("btn-play").setAttribute("aria-label", playing ? "暂停" : "播放");
}

function showPlayerControls(visible) {
  $("playerOverlay").classList.toggle("hidden-ui", !visible);
  clearTimeout(state.hideControlsTimer);
  if (visible && !$("playerVideo").paused) {
    state.hideControlsTimer = setTimeout(() => {
      $("playerOverlay").classList.add("hidden-ui");
    }, HIDE_CONTROLS_MS);
  }
}

function updateTimeUi() {
  const video = $("playerVideo");
  $("timeCurrent").textContent = formatDuration(video.currentTime || 0);
  $("timeTotal").textContent = formatDuration(
    Number.isFinite(video.duration) ? video.duration : null
  );
  if (!state.seeking && Number.isFinite(video.duration) && video.duration > 0) {
    $("seekBar").value = String(Math.round((video.currentTime / video.duration) * 1000));
  }
}

async function goRelative(dir) {
  if (!state.playQueue) return;
  const id = dir > 0 ? state.playQueue.next() : state.playQueue.prev();
  if (!id) {
    if (dir > 0) toast("已经是最后一条");
    return;
  }
  await loadCurrentVideo(true);
}

function closePlayer() {
  stopPlayback();
  showView("view-library");
  bumpActivity();
}

async function exportBackup() {
  if (!state.catalog.videos.length) {
    const ok = await confirmDialog("资料库是空的", "仍要导出一份只有密钥和空目录的备份吗？", {
      confirmLabel: "导出",
    });
    if (!ok) return;
  }
  beginBusy();
  try {
    showProgress("正在打包加密备份", "不会上传，只在本机生成文件", 0);
    const items = [];
    const total = state.catalog.videos.length || 1;
    let i = 0;
    for (const v of state.catalog.videos) {
      const encBlob = await readEncryptedVideo(v.id);
      if (!encBlob) throw new Error(`找不到「${v.name}」的加密文件`);
      const item = {
        id: v.id,
        encBlob,
        encSize: encBlob.size,
        hasThumb: false,
      };
      if (v.hasThumb) {
        const thumbBlob = await readEncryptedThumb(v.id);
        if (thumbBlob) {
          item.hasThumb = true;
          item.thumbBlob = thumbBlob;
          item.thumbSize = thumbBlob.size;
        }
      }
      items.push(item);
      i += 1;
      showProgress("正在打包加密备份", v.name, i / total);
    }
    const blob = await buildBackupBlob({
      vaultRecord: state.vaultRecord,
      dekKey: state.dekKey,
      catalog: state.catalog,
      items,
    });
    const name = `私密播放器备份-${formatDateTime()}.ppb`;
    const file = new File([blob], name, { type: "application/octet-stream" });
    hideProgress();
    if (navigator.canShare && navigator.canShare({ files: [file] })) {
      try {
        await navigator.share({ files: [file], title: name });
        toast("请把备份存到你自己的「文件」或网盘");
        return;
      } catch (err) {
        if (err?.name === "AbortError") return;
      }
    }
    const url = URL.createObjectURL(file);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.rel = "noopener";
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
    toast("已开始保存备份文件");
  } catch (err) {
    hideProgress();
    toast(err.message || "导出失败");
  } finally {
    endBusy();
  }
}

function passwordFields(ids, labels) {
  const wrap = document.createElement("div");
  wrap.className = "stack";
  const inputs = [];
  ids.forEach((id, i) => {
    const field = document.createElement("div");
    field.className = "field";
    const label = document.createElement("label");
    label.setAttribute("for", id);
    label.textContent = labels[i];
    const input = document.createElement("input");
    input.id = id;
    input.type = "password";
    input.maxLength = 256;
    input.autocomplete = "off";
    field.append(label, input);
    wrap.append(field);
    inputs.push(input);
  });
  return { wrap, inputs };
}

function askBackupAndRestore(mode) {
  const { wrap, inputs } = passwordFields(["restore-pass"], ["备份文件的应用密码"]);
  const hint = document.createElement("p");
  hint.className = "hint";
  hint.textContent =
    mode === "fresh"
      ? "将用备份在本机重建资料库。请只选择你自己导出的 .ppb 文件。"
      : "备份中的视频会解密后再用当前密钥重新加密，然后合并进现有资料库。过程只在本机进行。";
  wrap.append(hint);
  openSheet({
    title: "从加密备份恢复",
    body: wrap,
    actions: [
      {
        label: "选择备份文件",
        className: "btn-primary",
        keepOpen: true,
        onClick: () => {
          const password = inputs[0].value;
          if (!password) {
            toast("请输入备份密码");
            return;
          }
          state.pendingRestore = { mode, password };
          closeOverlay();
          $("file-backup").value = "";
          openLocalFilePicker($("file-backup"));
        },
      },
      { label: "取消", className: "btn-ghost" },
    ],
  });
}

async function handleBackupFile(file) {
  const pending = state.pendingRestore;
  state.pendingRestore = null;
  if (!pending) return;
  beginBusy();
  try {
    showProgress("正在读取备份", file.name, 0);
    const parsed = await parseBackupBlob(file);
    const opened = await openBackupWithPassword(parsed, pending.password);
    if (pending.mode === "fresh" && !state.unlocked) {
      await kvSet(KEY_VAULT, opened.vaultRecord);
      state.vaultRecord = opened.vaultRecord;
      let i = 0;
      const total = parsed.items.length || 1;
      for (const item of parsed.items) {
        await writeEncryptedVideo(item.id, item.encBlob);
        if (item.hasThumb && item.thumbBlob) {
          await writeEncryptedThumb(item.id, item.thumbBlob);
        }
        i += 1;
        showProgress("正在写入本机", `${i} / ${parsed.items.length}`, i / total);
      }
      await kvSet(KEY_CATALOG, parsed.encCatalog);
      state.dekBytes = opened.dekBytes;
      state.dekKey = opened.dekKey;
      hideProgress();
      await afterUnlock();
      toast(`已恢复 ${state.catalog.videos.length} 个视频`);
      return;
    }
    if (!state.unlocked) {
      hideProgress();
      toast("请先解锁，再合并备份");
      return;
    }
    const existingNames = new Set(state.catalog.videos.map((v) => `${v.name}:${v.size}`));
    let added = 0;
    let i = 0;
    const total = parsed.items.length || 1;
    const sourceVideos = Array.isArray(opened.catalog?.videos) ? opened.catalog.videos : [];
    const metaById = new Map(sourceVideos.map((v) => [v.id, v]));
    for (const item of parsed.items) {
      i += 1;
      const meta = metaById.get(item.id) || { name: "恢复的视频", size: 0, mime: "video/mp4" };
      showProgress("正在合并备份", meta.name || item.id, i / total);
      const newId = randomId();
      const plain = await decryptPvidBlob(opened.dekKey, item.encBlob, {
        mime: meta.mime || "application/octet-stream",
      });
      await writeEncryptedVideo(newId, async (writable) => {
        await encryptBlobChunked(state.dekKey, plain, (chunk) => writable.write(chunk));
      });
      const encFile = await readEncryptedVideo(newId);
      let hasThumb = false;
      if (item.hasThumb && item.thumbBlob) {
        try {
          const packed = new Uint8Array(await item.thumbBlob.arrayBuffer());
          const thumbPlain = await decryptBytes(opened.dekKey, packed);
          const reenc = await encryptBytes(state.dekKey, thumbPlain);
          await writeEncryptedThumb(newId, new Blob([reenc]));
          const url = URL.createObjectURL(new Blob([thumbPlain], { type: "image/jpeg" }));
          state.thumbUrls.set(newId, url);
          thumbPlain.fill(0);
          hasThumb = true;
        } catch {
          hasThumb = false;
        }
      }
      state.catalog.videos.unshift({
        id: newId,
        name: meta.name || "恢复的视频",
        size: meta.size || 0,
        encSize: encFile ? encFile.size : item.encSize,
        mime: meta.mime || guessMime(meta.name),
        createdAt: meta.createdAt || new Date().toISOString(),
        importedAt: new Date().toISOString(),
        duration: meta.duration ?? null,
        hasThumb,
      });
      added += 1;
      void existingNames;
    }
    await persistCatalog();
    renderLibrary();
    hideProgress();
    toast(`已合并 ${added} 个视频`);
  } catch (err) {
    hideProgress();
    toast(err.message || "恢复失败，请检查密码与文件");
  } finally {
    $("file-backup").value = "";
    endBusy();
  }
}

function openChangePassword() {
  const { wrap, inputs } = passwordFields(
    ["old-pass", "new-pass", "new-pass2"],
    ["当前密码", "新密码（至少 8 个字符）", "再输入一次新密码"]
  );
  openSheet({
    title: "更改应用密码",
    body: wrap,
    actions: [
      {
        label: "保存",
        className: "btn-primary",
        keepOpen: true,
        onClick: async () => {
          try {
            await unlockVault(state.vaultRecord, inputs[0].value);
            if (inputs[1].value !== inputs[2].value) {
              toast("两次新密码不一致");
              return;
            }
            assertPassword(inputs[1].value);
            const record = await rewrapVault(state.dekBytes, inputs[1].value);
            await kvSet(KEY_VAULT, record);
            state.vaultRecord = record;
            closeOverlay();
            toast("密码已更改，视频不必重新加密");
          } catch (err) {
            toast(err.message || "更改失败");
          }
        },
      },
      { label: "取消", className: "btn-ghost" },
    ],
  });
}

function updateFaceUnlockButton() {
  const btn = $("btn-face");
  btn.hidden = !(state.webauthn && state.webauthn.wrappedDEK);
}

async function refreshSettingsPane() {
  $("setting-autolock").value = String(state.settings.autoLockMs ?? 120000);
  const est = await storageEstimate();
  $("storage-usage").textContent = est
    ? `${formatBytes(est.usage)} / ${formatBytes(est.quota)}`
    : "当前浏览器未提供用量";
  try {
    const persisted = await navigator.storage?.persisted?.();
    $("storage-persist").textContent = persisted ? "已请求持久化" : "尚未获得持久化";
  } catch {
    $("storage-persist").textContent = "无法检测";
  }
  const enrolled = Boolean(state.webauthn && state.webauthn.wrappedDEK);
  $("btn-enroll-face").hidden = enrolled || state.prfSupport === "no";
  $("btn-remove-face").hidden = !enrolled;
  $("face-note").textContent = enrolled
    ? "已启用基于 WebAuthn PRF 的面容解锁。加密根仍是应用密码；面容只用于安全派生解包密钥，不会把密钥明文存放在磁盘上。"
    : describePrfSupport(state.prfSupport);
}

async function enrollFace() {
  beginBusy();
  try {
    const rec = await enrollWebAuthnPrf(state.dekBytes);
    await kvSet(KEY_WEBAUTHN, rec);
    state.webauthn = rec;
    await refreshSettingsPane();
    toast("已启用面容 ID 解锁");
  } catch (err) {
    if (err?.name === "NotAllowedError") {
      toast("已取消或系统不允许");
      return;
    }
    toast(err.message || "无法启用人脸解锁");
  } finally {
    endBusy();
  }
}

async function removeFace() {
  const ok = await confirmDialog("关闭面容 ID 解锁？", "之后只能使用应用密码解锁。", {
    confirmLabel: "关闭",
    danger: true,
  });
  if (!ok) return;
  await kvDelete(KEY_WEBAUTHN);
  state.webauthn = null;
  await refreshSettingsPane();
  updateFaceUnlockButton();
  toast("已关闭");
}

async function toggleFullscreen() {
  const root = $("view-player");
  try {
    if (!document.fullscreenElement && !document.webkitFullscreenElement) {
      if (root.requestFullscreen) await root.requestFullscreen();
      else if (root.webkitRequestFullscreen) root.webkitRequestFullscreen();
    } else if (document.exitFullscreen) {
      await document.exitFullscreen();
    } else {
      document.webkitExitFullscreen?.();
    }
  } catch {
    toast("当前环境无法进入页面全屏；视频已保持行内播放，以免系统控件接管");
  }
}


function openLocalFilePicker(input) {
  beginBusy();
  let released = false;
  const resume = () => {
    if (released) return;
    released = true;
    setTimeout(endBusy, 1500);
  };
  input.addEventListener("change", resume, { once: true });
  input.addEventListener("cancel", resume, { once: true });
  const onVisible = () => {
    if (!document.hidden) resume();
  };
  document.addEventListener("visibilitychange", onVisible, { once: true });
  window.addEventListener("focus", resume, { once: true });
  setTimeout(resume, 5 * 60 * 1000);
  input.click();
}

function bindEvents() {
  $("form-setup").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    beginBusy();
    try {
      showProgress("正在创建密钥", "只需这一次", 0.4);
      await setupPassword($("setup-pass").value, $("setup-pass2").value);
      $("setup-pass").value = "";
      $("setup-pass2").value = "";
    } catch (err) {
      toast(err.message || "设置失败");
    } finally {
      hideProgress();
      endBusy();
    }
  });

  $("form-unlock").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    beginBusy();
    try {
      showProgress("正在解锁", "派生密钥不会离开本机", 0.5);
      await unlockWithPassword($("unlock-pass").value);
      $("unlock-pass").value = "";
    } catch (err) {
      toast(err.message || "解锁失败");
    } finally {
      hideProgress();
      endBusy();
    }
  });

  $("btn-face").addEventListener("click", async () => {
    beginBusy();
    try {
      showProgress("等待面容验证", "只会使用安全密钥派生", 0.4);
      const dekBytes = await unlockWithWebAuthnPrf(state.webauthn);
      state.dekBytes = dekBytes;
      state.dekKey = await importDEK(dekBytes);
      await afterUnlock();
    } catch (err) {
      if (err?.name === "NotAllowedError") toast("已取消");
      else toast(err.message || "面容解锁失败，请使用应用密码");
    } finally {
      hideProgress();
      endBusy();
    }
  });

  $("btn-setup-restore").addEventListener("click", () => askBackupAndRestore("fresh"));
  $("btn-lock-restore").addEventListener("click", () =>
    askBackupAndRestore(state.unlocked ? "merge" : "fresh")
  );
  $("btn-import").addEventListener("click", () => openLocalFilePicker($("file-import")));
  $("btn-import-empty").addEventListener("click", () => openLocalFilePicker($("file-import")));
  $("file-import").addEventListener("change", (ev) => {
    const files = ev.target.files;
    if (files && files.length) importFiles(files);
  });
  $("file-backup").addEventListener("change", (ev) => {
    const file = ev.target.files && ev.target.files[0];
    if (file) handleBackupFile(file);
  });
  $("btn-shuffle").addEventListener("click", () => playFromLibrary(null, true));
  $("btn-settings").addEventListener("click", async () => {
    await refreshSettingsPane();
    showView("view-settings");
  });
  $("btn-settings-back").addEventListener("click", () => {
    showView("view-library");
  });
  $("setting-autolock").addEventListener("change", async (ev) => {
    state.settings.autoLockMs = Number(ev.target.value);
    await saveSettings(state.settings);
    bumpActivity();
  });
  $("btn-change-pass").addEventListener("click", openChangePassword);
  $("btn-enroll-face").addEventListener("click", enrollFace);
  $("btn-remove-face").addEventListener("click", removeFace);
  $("btn-export").addEventListener("click", exportBackup);
  $("btn-restore").addEventListener("click", () => askBackupAndRestore("merge"));
  $("btn-persist").addEventListener("click", async () => {
    const result = await requestPersist();
    state.persist = result;
    await refreshSettingsPane();
    toast(result.persisted ? "已请求持久化存储" : "系统未授予持久化，请更勤快地导出备份");
  });
  $("btn-lock-now").addEventListener("click", () => lock("手动锁定"));

  $("btn-player-close").addEventListener("click", closePlayer);
  $("btn-play").addEventListener("click", async () => {
    const video = $("playerVideo");
    if (video.paused) {
      try {
        await video.play();
      } catch {
        toast("无法开始播放");
      }
    } else {
      video.pause();
    }
  });
  $("btn-prev").addEventListener("click", () => goRelative(-1));
  $("btn-next").addEventListener("click", () => goRelative(1));
  $("btn-fullscreen").addEventListener("click", toggleFullscreen);
  $("seekBar").addEventListener("input", () => {
    state.seeking = true;
  });
  $("seekBar").addEventListener("change", () => {
    const video = $("playerVideo");
    if (Number.isFinite(video.duration) && video.duration > 0) {
      video.currentTime = (Number($("seekBar").value) / 1000) * video.duration;
    }
    state.seeking = false;
  });

  const video = $("playerVideo");
  video.addEventListener("play", () => {
    setPlayingUi(true);
    tryWakeLock();
    showPlayerControls(true);
    clearIdleTimer();
  });
  video.addEventListener("pause", () => {
    setPlayingUi(false);
    showPlayerControls(true);
    bumpActivity();
  });
  video.addEventListener("timeupdate", updateTimeUi);
  video.addEventListener("loadedmetadata", updateTimeUi);
  video.addEventListener("ended", async () => {
    if (state.playQueue?.hasNext()) await goRelative(1);
    else {
      setPlayingUi(false);
      showPlayerControls(true);
      toast("已播完当前队列");
    }
  });
  $("playerStage").addEventListener("click", (ev) => {
    if (ev.target.closest(".player-top, .player-bottom, .btn, input")) return;
    const hidden = $("playerOverlay").classList.contains("hidden-ui");
    showPlayerControls(hidden);
  });

  document.addEventListener("pointerdown", bumpActivity, { passive: true });
  document.addEventListener("keydown", bumpActivity);
  document.addEventListener("visibilitychange", () => {
    if (document.hidden && state.settings.lockOnBackground !== false) {
      if (canAutoLock()) lock("进入后台");
    } else if (!document.hidden && state.currentView === "view-player" && !$("playerVideo").paused) {
      tryWakeLock();
    }
  });
  window.addEventListener("pagehide", () => {
    if (canAutoLock()) lock("页面隐藏");
  });
  $("overlay").addEventListener("click", (ev) => {
    if (ev.target === $("overlay")) closeOverlay();
  });
}

async function registerSw() {
  if (!("serviceWorker" in navigator)) return;
  try {
    await navigator.serviceWorker.register("./sw.js", { scope: "./" });
  } catch {
    /* HTTP 局域网等环境下会失败，预览仍可使用界面 */
  }
}

async function boot() {
  bindEvents();
  if (!(await isSecureAppContext())) {
    showView("view-insecure");
    return;
  }
  registerSw();
  state.settings = await loadSettings();
  state.vaultRecord = (await kvGet(KEY_VAULT)) || null;
  state.webauthn = (await kvGet(KEY_WEBAUTHN)) || null;
  try {
    state.prfSupport = await detectWebAuthnPrf();
  } catch {
    state.prfSupport = "no";
  }
  if (!state.vaultRecord) {
    showView("view-setup");
  } else {
    showView("view-lock");
    updateFaceUnlockButton();
  }
}

boot();
