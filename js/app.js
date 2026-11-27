import {
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
  KEY_RECOVERY,
  KEY_PIN_FAILS,
  KEY_RECOVERY_GUARD,
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
import { createPlayQueue, nextShuffleQueue } from "./queue.js";
import {
  PIN_DIGITS,
  PIN_FAILS_BEFORE_RECOVERY,
  advanceGate,
  retreatGate,
  countsAsPinAttempt,
  notePinFailure,
  notePinSuccess,
} from "./pinflow.js";
import {
  normalizeAnswer,
  assertAnswer,
  assertQuestion,
  createRecoveryRecord,
  unlockRecovery,
  assessRecoveryGuard,
  registerRecoveryFailure,
  clearRecoveryGuard,
} from "./recovery.js";
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
import {
  EXPORT_HELP_PARAGRAPHS,
  PLAIN_EXPORT_WARNING,
  applyExportAction,
  createExportSession,
  deletionAllowed,
  exportContentType,
  exportFileName,
  plainUrlRevokeDelayMs,
  shouldSuppressAutoLock,
} from "./export.js";

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
  plainExport: null,
  exportShareActive: false,
  exportGen: 0,
  sheetDismiss: null,
  recoveryRecord: null,
  pinFails: 0,
  recoveryGuard: clearRecoveryGuard(),
  pendingPin: null,
  secretMode: null,
  gate: { mode: "unlock", digits: "", first: "", notice: null },
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
  if (shouldSuppressAutoLock({ exportShareActive: state.exportShareActive, busy: state.busy })) {
    return false;
  }
  return state.unlocked;
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
  clearToast();
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

function clearToast() {
  clearTimeout(toast._t);
  const el = $("toast");
  if (el) el.hidden = true;
}

function closeOverlay() {
  state.sheetDismiss = null;
  $("overlay").hidden = true;
  $("sheet").replaceChildren();
}

function openSheet({ title, body, actions, center = true, onDismiss = null }) {
  clearToast();
  state.sheetDismiss = onDismiss;
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
      const run = action.onClick;
      closeOverlay();
      await run?.();
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
  const bar = $("progressBar");
  const step = Math.round(Math.max(0, Math.min(1, ratio)) * 20) * 5;
  for (const name of [...bar.classList]) {
    if (name.startsWith("w")) bar.classList.remove(name);
  }
  bar.classList.add(`w${step}`);
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
  if (state.plainExport) abortPlainExport("lock");
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
  state.pendingPin = null;
  state.gate = { mode: "unlock", digits: "", first: "", notice: null };
  if ((state.pinFails || 0) >= PIN_FAILS_BEFORE_RECOVERY && state.recoveryRecord?.question) {
    showSecret("recover");
  } else {
    showGate("unlock");
  }
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
  const cleared = notePinSuccess();
  state.pinFails = cleared.fails;
  state.recoveryGuard = clearRecoveryGuard();
  await kvSet(KEY_PIN_FAILS, 0);
  await kvSet(KEY_RECOVERY_GUARD, state.recoveryGuard);
  await afterUnlock();
}

function showGate(mode) {
  state.gate = { mode, digits: "", first: "", notice: null };
  showView("view-gate");
  renderGate();
}

function gateNoticeText() {
  if (state.gate.notice === "mismatch") return "两次路径不一样，请重新选择。";
  if (state.gate.notice === "denied") return "打不开这个文件夹。";
  if (state.gate.digits) return "";
  switch (state.gate.mode) {
    case "setup-choose":
      return "走进六层文件夹。这条路径以后用来打开 gitbb。";
    case "setup-confirm":
      return "再走一遍刚才的路径。";
    case "reset-choose":
    case "change-choose":
      return "选一条新的六层路径。";
    case "reset-confirm":
    case "change-confirm":
      return "再走一遍新路径。";
    default:
      return "";
  }
}

function renderGate() {
  const digits = state.gate.digits;
  const title = $("gate-title");
  const back = $("btn-gate-back");
  const path = $("gate-path");
  const hint = $("gate-hint");
  if (!title || !path) return;
  title.textContent = digits ? digits[digits.length - 1] : "gitbb";
  const atConfirmStart =
    !digits &&
    (state.gate.mode === "setup-confirm" ||
      state.gate.mode === "reset-confirm" ||
      state.gate.mode === "change-confirm");
  back.hidden = !digits && !atConfirmStart && state.gate.mode !== "change-choose" && state.gate.mode !== "reset-choose";
  const parts = ["gitbb"];
  for (const digit of digits) parts.push(digit);
  path.textContent = parts.join("  /  ");
  hint.textContent = gateNoticeText();
  const browsingLocked = state.gate.mode === "unlock" || state.gate.mode === "setup-choose";
  $("btn-gate-restore").hidden = !browsingLocked;
  const legacy = $("btn-legacy-pass");
  if (legacy) {
    legacy.hidden = !(state.gate.mode === "unlock" && state.vaultRecord && !state.recoveryRecord);
  }
  updateFaceUnlockButton();
}

function ensureFolderGrid() {
  const grid = $("gate-grid");
  if (!grid || grid.childElementCount) return;
  for (const digit of PIN_DIGITS) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "folder-item";
    btn.setAttribute("aria-label", `文件夹 ${digit}`);
    const glyph = document.createElement("span");
    glyph.className = `folder-glyph tone-${digit}`;
    glyph.setAttribute("aria-hidden", "true");
    const name = document.createElement("span");
    name.className = "folder-name";
    name.textContent = digit;
    btn.append(glyph, name);
    btn.addEventListener("click", () => onFolderDigit(digit));
    grid.append(btn);
  }
}

async function onFolderDigit(digit) {
  if (state.busy || state.gate.hold) return;
  const next = advanceGate(state.gate, digit);
  state.gate = {
    mode: next.mode,
    digits: next.digits,
    first: next.first,
    notice: next.notice,
    hold: false,
  };
  renderGate();
  if (next.kind === "browsing" || next.kind === "need-confirm" || next.kind === "mismatch") return;
  state.gate.hold = true;
  try {
    if (countsAsPinAttempt(next.kind)) {
      await attemptUnlock(next.pin);
      return;
    }
    if (next.kind === "submit-new-pin") {
      await acceptNewPin(next.pin);
    }
  } finally {
    if (state.gate) state.gate.hold = false;
  }
}

async function attemptUnlock(pin) {
  beginBusy();
  try {
    showProgress("正在打开", "", 0.45);
    await unlockWithPassword(pin);
    state.gate = { mode: "unlock", digits: "", first: "", notice: null };
  } catch (err) {
    hideProgress();
    state.gate.digits = "";
    state.gate.first = "";
    if (err?.code === "BAD_PASSWORD" || err?.code === "BAD_VAULT") {
      const result = notePinFailure(state.pinFails);
      state.pinFails = result.fails;
      await kvSet(KEY_PIN_FAILS, state.pinFails);
      if (result.showRecovery && state.recoveryRecord?.question) {
        showSecret("recover");
        return;
      }
      state.gate.notice = "denied";
      renderGate();
    } else {
      state.gate.notice = null;
      renderGate();
      toast(err.message || "打不开");
    }
  } finally {
    hideProgress();
    endBusy();
  }
}

async function acceptNewPin(pin) {
  const mode = state.gate.mode;
  if (mode === "setup-confirm") {
    state.pendingPin = pin;
    showSecret("setup");
    return;
  }
  if (mode === "reset-confirm") {
    await finishPinReset(pin);
    return;
  }
  if (mode === "change-confirm") {
    if (!state.recoveryRecord) {
      state.pendingPin = pin;
      showSecret("migrate");
      return;
    }
    await finishPinChange(pin);
  }
}

function gateBack() {
  if (state.busy) return;
  const next = retreatGate(state.gate);
  if (next.atRoot && state.gate.mode === "change-choose") {
    showView("view-settings");
    return;
  }
  if (next.atRoot && state.gate.mode === "reset-choose") {
    dropKeys();
    state.pendingPin = null;
    showSecret("recover");
    return;
  }
  state.gate = {
    mode: next.mode,
    digits: next.digits,
    first: next.first,
    notice: next.restarted ? null : state.gate.notice,
  };
  if (next.digits) state.gate.notice = null;
  renderGate();
}

function showSecret(mode) {
  state.secretMode = mode;
  const question = $("secret-question");
  const answer = $("secret-answer");
  const answer2 = $("secret-answer2");
  question.value = "";
  answer.value = "";
  answer2.value = "";
  const defining = mode === "setup" || mode === "edit" || mode === "migrate";
  $("field-secret-question").hidden = !defining;
  $("field-secret-answer2").hidden = !defining;
  $("secret-lockout").hidden = true;
  $("btn-secret-submit").disabled = false;
  answer.disabled = false;
  if (mode === "setup" || mode === "migrate") {
    $("secret-title").textContent = "留一个问题";
    $("secret-lead").textContent = "忘记六层路径时，会用这个问题改一条新路径。答案不会明文保存。";
    $("secret-hint").textContent =
      "答案请只有你自己知道，不要太短，也不要写别人能猜到的词。保存时会去掉首尾空格。";
    $("btn-secret-submit").textContent = "完成";
  } else if (mode === "edit") {
    $("secret-title").textContent = "更改问题";
    question.value = state.recoveryRecord?.question || "";
    $("secret-lead").textContent = "换一道只有你能回答的问题。答对才能在忘记路径后重设路径。";
    $("secret-hint").textContent =
      "答案请只有你自己知道，不要太短。保存时会去掉首尾空格。旧答案在保存后失效。";
    $("btn-secret-submit").textContent = "保存";
  } else {
    $("secret-title").textContent = "gitbb";
    $("secret-lead").textContent = state.recoveryRecord?.question || "";
    $("secret-hint").textContent = "回答正确后可以重设六层路径。回答错误会限制尝试次数。";
    $("btn-secret-submit").textContent = "继续";
    refreshRecoveryLockout();
  }
  showView("view-secret");
}

function refreshRecoveryLockout() {
  if (state.secretMode !== "recover") return;
  const decision = assessRecoveryGuard(state.recoveryGuard, Date.now());
  const note = $("secret-lockout");
  const submit = $("btn-secret-submit");
  const answer = $("secret-answer");
  if (!decision.allowed) {
    const mins = Math.max(1, Math.ceil((decision.retryAt - Date.now()) / 60000));
    note.hidden = false;
    note.textContent = `尝试次数过多，请约 ${mins} 分钟后再试。`;
    submit.disabled = true;
    answer.disabled = true;
  } else {
    note.hidden = true;
    submit.disabled = false;
    answer.disabled = false;
  }
}

async function finishSetup(question, answer) {
  const pin = state.pendingPin;
  if (!pin) throw new CryptoError("请先走完六层路径。", "BAD_PIN");
  showProgress("正在整理", "请稍等片刻", 0.35);
  const { record, dekBytes } = await createVaultRecord(pin, { pin: true });
  const recovery = await createRecoveryRecord(question, answer, dekBytes);
  await kvSet(KEY_VAULT, record);
  try {
    await kvSet(KEY_RECOVERY, recovery);
  } catch (err) {
    await kvDelete(KEY_VAULT);
    throw err;
  }
  await kvSet(KEY_PIN_FAILS, 0);
  await kvSet(KEY_RECOVERY_GUARD, clearRecoveryGuard());
  state.vaultRecord = record;
  state.recoveryRecord = recovery;
  state.pinFails = 0;
  state.recoveryGuard = clearRecoveryGuard();
  state.pendingPin = null;
  state.dekBytes = dekBytes;
  state.dekKey = await importDEK(dekBytes);
  state.catalog = emptyCatalog();
  await persistCatalog();
  await afterUnlock();
}

async function finishPinReset(pin) {
  if (!state.dekBytes) {
    showSecret("recover");
    return;
  }
  beginBusy();
  try {
    showProgress("正在整理", "请稍等片刻", 0.5);
    const record = await rewrapVault(state.dekBytes, pin, { pin: true });
    await kvSet(KEY_VAULT, record);
    await kvSet(KEY_PIN_FAILS, 0);
    await kvSet(KEY_RECOVERY_GUARD, clearRecoveryGuard());
    state.vaultRecord = record;
    state.pinFails = 0;
    state.recoveryGuard = clearRecoveryGuard();
    state.pendingPin = null;
    hideProgress();
    await afterUnlock();
    toast("已改用新的路径");
  } catch (err) {
    hideProgress();
    toast(err.message || "没能改路径");
  } finally {
    endBusy();
  }
}

async function finishPinChange(pin) {
  beginBusy();
  try {
    showProgress("正在整理", "文件不会重新加密", 0.5);
    const record = await rewrapVault(state.dekBytes, pin, { pin: true });
    await kvSet(KEY_VAULT, record);
    state.vaultRecord = record;
    state.pendingPin = null;
    hideProgress();
    showView("view-settings");
    toast("路径已更改，文件不必重新加密");
  } catch (err) {
    hideProgress();
    toast(err.message || "没能改路径");
  } finally {
    endBusy();
  }
}

async function finishQuestionChange(question, answer) {
  beginBusy();
  try {
    showProgress("正在整理", "请稍等片刻", 0.5);
    const recovery = await createRecoveryRecord(question, answer, state.dekBytes);
    await kvSet(KEY_RECOVERY, recovery);
    state.recoveryRecord = recovery;
    state.recoveryGuard = clearRecoveryGuard();
    await kvSet(KEY_RECOVERY_GUARD, state.recoveryGuard);
    hideProgress();
    showView("view-settings");
    await refreshSettingsPane();
    toast("问题已更新");
  } catch (err) {
    hideProgress();
    toast(err.message || "没能保存问题");
  } finally {
    endBusy();
  }
}

async function finishMigrate(question, answer) {
  const pin = state.pendingPin;
  if (!pin || !state.dekBytes) {
    toast("请先走完六层路径");
    return;
  }
  beginBusy();
  try {
    showProgress("正在整理", "请稍等片刻", 0.4);
    const record = await rewrapVault(state.dekBytes, pin, { pin: true });
    const recovery = await createRecoveryRecord(question, answer, state.dekBytes);
    await kvSet(KEY_VAULT, record);
    await kvSet(KEY_RECOVERY, recovery);
    await kvSet(KEY_PIN_FAILS, 0);
    await kvSet(KEY_RECOVERY_GUARD, clearRecoveryGuard());
    state.vaultRecord = record;
    state.recoveryRecord = recovery;
    state.pinFails = 0;
    state.recoveryGuard = clearRecoveryGuard();
    state.pendingPin = null;
    hideProgress();
    showView("view-settings");
    await refreshSettingsPane();
    toast("以后用六层路径打开");
  } catch (err) {
    hideProgress();
    toast(err.message || "没能保存");
  } finally {
    endBusy();
  }
}

async function submitSecretForm(event) {
  event.preventDefault();
  if (state.busy) return;
  const mode = state.secretMode;
  if (mode === "recover") {
    await submitRecoveryAnswer($("secret-answer").value);
    return;
  }
  let question;
  let answer;
  try {
    question = assertQuestion($("secret-question").value);
    answer = assertAnswer($("secret-answer").value);
  } catch (err) {
    toast(err.message || "请检查问题和答案");
    return;
  }
  if (answer !== normalizeAnswer($("secret-answer2").value)) {
    toast("两次答案不一致");
    return;
  }
  if (mode === "setup") {
    beginBusy();
    try {
      await finishSetup(question, answer);
    } catch (err) {
      toast(err.message || "没能完成");
    } finally {
      hideProgress();
      endBusy();
    }
    return;
  }
  if (mode === "edit") {
    await finishQuestionChange(question, answer);
    return;
  }
  if (mode === "migrate") {
    await finishMigrate(question, answer);
  }
}

async function submitRecoveryAnswer(raw) {
  const decision = assessRecoveryGuard(state.recoveryGuard, Date.now());
  if (!decision.allowed) {
    refreshRecoveryLockout();
    return;
  }
  if (!normalizeAnswer(raw)) {
    toast("请填写答案");
    return;
  }
  beginBusy();
  try {
    showProgress("正在打开", "", 0.5);
    const dekBytes = await unlockRecovery(state.recoveryRecord, raw);
    state.dekBytes = dekBytes;
    state.dekKey = await importDEK(dekBytes);
    state.recoveryGuard = clearRecoveryGuard();
    await kvSet(KEY_RECOVERY_GUARD, state.recoveryGuard);
    hideProgress();
    $("secret-answer").value = "";
    showGate("reset-choose");
    toast("回答正确，请设定新的六层路径");
  } catch (err) {
    hideProgress();
    $("secret-answer").value = "";
    if (err?.code === "EMPTY_ANSWER") {
      toast("请填写答案");
      return;
    }
    state.recoveryGuard = registerRecoveryFailure(state.recoveryGuard, Date.now());
    await kvSet(KEY_RECOVERY_GUARD, state.recoveryGuard);
    refreshRecoveryLockout();
    const stillOpen = assessRecoveryGuard(state.recoveryGuard, Date.now());
    toast(stillOpen.allowed ? "回答不正确" : "尝试次数过多，请稍后再试");
  } finally {
    endBusy();
  }
}

function secretBack() {
  if (state.busy) return;
  if (state.secretMode === "setup") {
    state.pendingPin = null;
    showGate("setup-choose");
    return;
  }
  if (state.secretMode === "edit" || state.secretMode === "migrate") {
    state.pendingPin = null;
    showView("view-settings");
    return;
  }
  state.gate = { mode: "unlock", digits: "", first: "", notice: null };
  showView("view-gate");
  renderGate();
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

function fileGlyph() {
  const ph = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  ph.setAttribute("viewBox", "0 0 24 24");
  ph.classList.add("ph-icon");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", "M4 7.5A2.5 2.5 0 0 1 6.5 5H10l2 2h5.5A2.5 2.5 0 0 1 20 9.5v7A2.5 2.5 0 0 1 17.5 19h-11A2.5 2.5 0 0 1 4 16.5v-9z");
  path.setAttribute("fill", "currentColor");
  ph.append(path);
  return ph;
}

function renderLibrary() {
  const empty = $("library-empty");
  const grid = $("library-grid");
  grid.replaceChildren();
  const videos = state.catalog.videos;
  empty.hidden = videos.length > 0;
  if (videos.length) {
    const shuffle = document.createElement("button");
    shuffle.type = "button";
    shuffle.className = "card shuffle-card";
    const thumb = document.createElement("div");
    thumb.className = "card-thumb";
    thumb.append(fileGlyph());
    const meta = document.createElement("div");
    meta.className = "card-meta";
    const title = document.createElement("div");
    title.className = "card-title";
    title.textContent = "随机";
    const sub = document.createElement("div");
    sub.className = "card-sub";
    sub.textContent = `全部 ${videos.length} 个文件`;
    meta.append(title, sub);
    shuffle.append(thumb, meta);
    shuffle.addEventListener("click", () => playFromLibrary(null, true));
    grid.append(shuffle);
  }
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
      thumb.append(fileGlyph());
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
    del.setAttribute("aria-label", "删除或导出");
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

const EXPORT_ABORT_TOAST = {
  lock: "应用已锁定，未删除加密副本",
  cancel: "已取消，未删除加密副本",
  "wrong-key": "密钥不正确，未删除加密副本",
  "decrypt-fail": "解密失败，未删除加密副本",
  "share-aborted": "已取消分享，未删除加密副本",
  "share-failed": "导出失败，未删除加密副本",
  "deny-saved": "尚未确认保存成功，未删除加密副本",
};

function exportStillCurrent(gen) {
  return Boolean(state.unlocked && state.dekKey && state.plainExport && state.plainExport.gen === gen);
}

function releasePlainFile(exp, { immediate }) {
  if (!exp) return;
  const url = exp.url;
  const delay = plainUrlRevokeDelayMs({
    shareActive: state.exportShareActive,
    downloadTriggered: Boolean(exp.downloadTriggered),
    immediate,
  });
  exp.file = null;
  exp.url = null;
  if (!url || delay == null) return;
  if (delay === 0) URL.revokeObjectURL(url);
  else setTimeout(() => URL.revokeObjectURL(url), delay);
}

function abortPlainExport(reason, { silent = false } = {}) {
  const exp = state.plainExport;
  state.exportGen += 1;
  state.plainExport = null;
  state.exportShareActive = false;
  if (exp) {
    const result = applyExportAction(exp.session, { type: reason });
    if (result.deleteEncryptedCopy) {
      state.plainExport = exp;
      toast("未删除加密副本");
      return;
    }
    releasePlainFile(exp, { immediate: true });
  }
  closeOverlay();
  hideProgress();
  if (!silent && exp) toast(EXPORT_ABORT_TOAST[reason] || "未删除加密副本");
}

function waitUntilVisible(timeoutMs) {
  if (!document.hidden) return Promise.resolve(true);
  return new Promise((resolve) => {
    const done = (value) => {
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisible);
      resolve(value);
    };
    const onVisible = () => {
      if (!document.hidden) done(true);
    };
    const timer = setTimeout(() => done(!document.hidden), timeoutMs);
    document.addEventListener("visibilitychange", onVisible);
  });
}

function plainExportWarningBody(item) {
  const name = item.name || "未命名视频";
  const wrap = document.createElement("div");
  const lead = document.createElement("p");
  lead.textContent = `将只在这台设备上把「${name}」解密成原视频，再交给系统分享，由你保存到「文件」、相册或你自己的网盘。不会上传到开发者的服务器。`;
  const warn = document.createElement("p");
  warn.className = "alert alert-danger";
  warn.textContent = PLAIN_EXPORT_WARNING;
  wrap.append(lead, warn);
  if (item.size > LARGE_FILE_BYTES) {
    const big = document.createElement("p");
    big.textContent = `这个文件约 ${formatBytes(item.size)}，解密时会占用较多内存，iPhone 可能内存不足。`;
    wrap.append(big);
  }
  return wrap;
}

function confirmDelete(item) {
  const name = item.name || "未命名视频";
  const wrap = document.createElement("div");
  const lead = document.createElement("p");
  lead.textContent = `将从本机删除「${name}」。删除后无法恢复，除非你有备份。`;
  const warn = document.createElement("p");
  warn.className = "alert alert-danger";
  warn.textContent = `${PLAIN_EXPORT_WARNING}也可以先解密导出，再决定是否删除。`;
  wrap.append(lead, warn);
  openSheet({
    title: "删除这部视频？",
    body: wrap,
    actions: [
      {
        label: "解密导出",
        className: "btn-primary",
        onClick: () => startPlainExport(item),
      },
      {
        label: "删除",
        className: "btn-danger",
        onClick: () => performDelete(item, "library"),
      },
      { label: "取消", className: "btn-ghost" },
    ],
  });
}

async function performDelete(item, cause) {
  if (!item?.id) return false;
  if (cause === "export") {
    const exp = state.plainExport;
    if (!exp || exp.item.id !== item.id || !deletionAllowed(exp.session)) return false;
  } else if (cause !== "library") {
    return false;
  }
  if (!state.unlocked || !state.dekKey) {
    toast("应用已锁定，未删除");
    return false;
  }
  if (!state.catalog.videos.some((video) => video.id === item.id)) return false;
  beginBusy();
  try {
    await deleteEncryptedVideo(item.id);
    await deleteEncryptedThumb(item.id);
    const thumbUrl = state.thumbUrls.get(item.id);
    if (thumbUrl) {
      URL.revokeObjectURL(thumbUrl);
      state.thumbUrls.delete(item.id);
    }
    state.catalog.videos = state.catalog.videos.filter((video) => video.id !== item.id);
    await persistCatalog();
    renderLibrary();
    toast("已删除");
    return true;
  } catch (err) {
    toast(err?.message || "删除失败，加密副本仍保留");
    return false;
  } finally {
    endBusy();
  }
}

function startPlainExport(item) {
  if (!state.unlocked || !state.dekKey) {
    toast("应用已锁定，未删除加密副本");
    return;
  }
  if (state.plainExport) abortPlainExport("cancel", { silent: true });
  state.exportGen += 1;
  const gen = state.exportGen;
  state.plainExport = {
    gen,
    item,
    session: createExportSession(item.id),
    file: null,
    url: null,
    sharing: false,
    downloadTriggered: false,
  };
  openSheet({
    title: "导出未加密原视频？",
    body: plainExportWarningBody(item),
    onDismiss: () => {
      if (state.plainExport?.gen === gen) abortPlainExport("cancel");
    },
    actions: [
      {
        label: "开始解密",
        className: "btn-primary",
        onClick: () => decryptForExport(item, gen),
      },
      {
        label: "取消",
        className: "btn-ghost",
        onClick: () => abortPlainExport("cancel"),
      },
    ],
  });
}

async function decryptForExport(item, gen) {
  const exp = state.plainExport;
  if (!exp || exp.gen !== gen || exp.item.id !== item.id) return;
  if (!state.unlocked || !state.dekKey) {
    abortPlainExport("lock");
    return;
  }
  const accepted = applyExportAction(exp.session, { type: "accept-warning" });
  if (accepted.rejected || accepted.deleteEncryptedCopy) {
    abortPlainExport("cancel");
    return;
  }
  exp.session = accepted.session;
  beginBusy();
  try {
    showProgress("正在本机解密", item.name || "未命名视频", 0);
    const enc = await readEncryptedVideo(item.id);
    if (!exportStillCurrent(gen)) return;
    if (!enc) throw new Error("加密文件丢失，可能已被系统清理。");
    const mime = exportContentType(item.name, item.mime);
    const plainBlob = await decryptPvidBlob(state.dekKey, enc, {
      mime,
      onProgress: (done, total) => {
        if (!exportStillCurrent(gen)) return;
        showProgress(
          "正在本机解密",
          `${item.name || "未命名视频"}（${formatBytes(done)} / ${formatBytes(total)}）`,
          total ? done / total : 0
        );
      },
    });
    if (!exportStillCurrent(gen)) return;
    const name = exportFileName(item.name, mime);
    const parsedTime = Date.parse(item.createdAt || "");
    const file = new File([plainBlob], name, {
      type: mime,
      lastModified: Number.isFinite(parsedTime) ? parsedTime : Date.now(),
    });
    const ready = applyExportAction(exp.session, { type: "decrypt-ok" });
    if (ready.rejected || ready.deleteEncryptedCopy || !exportStillCurrent(gen)) {
      abortPlainExport("decrypt-fail");
      return;
    }
    exp.session = ready.session;
    exp.file = file;
    hideProgress();
    showReadyToSaveSheet(item, gen);
  } catch (err) {
    if (!exportStillCurrent(gen)) return;
    hideProgress();
    const wrong = err?.code === "DECRYPT_FAIL" || err?.code === "BAD_PASSWORD";
    abortPlainExport(wrong ? "wrong-key" : "decrypt-fail");
  } finally {
    endBusy();
  }
}

function showReadyToSaveSheet(item, gen) {
  const exp = state.plainExport;
  if (!exp || exp.gen !== gen || !exp.file) return;
  const wrap = document.createElement("div");
  const lead = document.createElement("p");
  lead.textContent = `「${exp.file.name}」已在本机解密，尚未离开这台设备。请点「保存到系统…」，用系统分享保存到「文件」、相册或你的网盘。`;
  const warn = document.createElement("p");
  warn.className = "alert alert-danger";
  warn.textContent = PLAIN_EXPORT_WARNING;
  const note = document.createElement("p");
  note.textContent =
    "点保存前如果切到别的应用，gitbb 会锁定并取消这次导出，不会删除加密副本。系统分享结束或开始下载，都不代表文件已经保存成功。";
  wrap.append(lead, warn, note);
  openSheet({
    title: "请点保存",
    body: wrap,
    onDismiss: () => {
      if (state.plainExport?.gen === gen && !state.exportShareActive) abortPlainExport("cancel");
    },
    actions: [
      {
        label: "保存到系统…",
        className: "btn-primary",
        keepOpen: true,
        onClick: () => handoffPlainExport(item, gen),
      },
      {
        label: "取消",
        className: "btn-ghost",
        onClick: () => abortPlainExport("cancel"),
      },
    ],
  });
}

function triggerPlainDownload(exp, file) {
  const url = URL.createObjectURL(file);
  exp.url = url;
  exp.downloadTriggered = true;
  const link = document.createElement("a");
  link.href = url;
  link.download = file.name;
  link.rel = "noopener";
  link.className = "export-download-link";
  document.body.append(link);
  link.click();
  link.remove();
}

async function handoffPlainExport(item, gen) {
  const exp = state.plainExport;
  if (!exp || exp.gen !== gen || exp.sharing || !exp.file) return;
  if (!state.unlocked || !state.dekKey) {
    abortPlainExport("lock");
    return;
  }
  if (exp.session.phase !== "ready") return;
  const file = exp.file;
  exp.sharing = true;
  state.exportShareActive = true;
  beginBusy();
  let outcome = null;
  let failed = null;
  try {
    let canFileShare = false;
    try {
      canFileShare =
        typeof navigator.share === "function" &&
        typeof navigator.canShare === "function" &&
        navigator.canShare({ files: [file] });
    } catch {
      canFileShare = false;
    }
    if (canFileShare) {
      await navigator.share({ files: [file], title: file.name });
      outcome = "share-resolved";
    } else {
      triggerPlainDownload(exp, file);
      outcome = "download-triggered";
    }
  } catch (err) {
    failed = err;
  }
  const visible = failed ? true : await waitUntilVisible(4000);
  exp.sharing = false;
  state.exportShareActive = false;
  endBusy();
  if (!exportStillCurrent(gen)) return;
  if (failed) {
    if (failed.name === "AbortError") {
      abortPlainExport("share-aborted");
      return;
    }
    toast("系统分享没有完成，请再点一次保存。未删除加密副本");
    return;
  }
  if (!visible) {
    await lock("分享后仍在后台");
    return;
  }
  const stepped = applyExportAction(exp.session, { type: outcome });
  if (stepped.rejected || stepped.deleteEncryptedCopy || deletionAllowed(stepped.session)) {
    abortPlainExport("cancel");
    toast("导出状态异常，未删除加密副本");
    return;
  }
  exp.session = stepped.session;
  askWhetherSaved(item, gen);
}

function askWhetherSaved(item, gen) {
  const exp = state.plainExport;
  if (!exp || exp.gen !== gen) return;
  const wrap = document.createElement("div");
  const lead = document.createElement("p");
  lead.textContent =
    "系统分享或下载已经交给系统，但这不等于文件已经存进「文件」、相册或网盘。请先到保存位置打开检查，确认未加密原视频完整可用。";
  const warn = document.createElement("p");
  warn.className = "alert alert-danger";
  warn.textContent = PLAIN_EXPORT_WARNING;
  wrap.append(lead, warn);
  openSheet({
    title: "请确认已经保存成功",
    body: wrap,
    onDismiss: () => {
      if (state.plainExport?.gen === gen) abortPlainExport("deny-saved");
    },
    actions: [
      {
        label: "已经保存成功",
        className: "btn-primary",
        onClick: () => confirmSavedForExport(item, gen),
      },
      {
        label: "还没有，先保留",
        className: "btn-ghost",
        onClick: () => abortPlainExport("deny-saved"),
      },
    ],
  });
}

function confirmSavedForExport(item, gen) {
  const exp = state.plainExport;
  if (!exp || exp.gen !== gen || !state.unlocked || !state.dekKey) {
    abortPlainExport("lock");
    return;
  }
  const stepped = applyExportAction(exp.session, { type: "confirm-saved" });
  if (stepped.rejected || stepped.deleteEncryptedCopy || !deletionAllowed(stepped.session)) {
    abortPlainExport("cancel");
    return;
  }
  exp.session = stepped.session;
  askDeleteEncryptedCopy(item, gen);
}

function askDeleteEncryptedCopy(item, gen) {
  const name = item.name || "未命名视频";
  const wrap = document.createElement("div");
  const lead = document.createElement("p");
  lead.textContent = `你已确认「${name}」的未加密原视频保存成功。是否从 gitbb 中删除加密副本？可以只导出、不删除。`;
  wrap.append(lead);
  openSheet({
    title: "删除 gitbb 里的加密副本？",
    body: wrap,
    onDismiss: () => keepExportedCopy(gen),
    actions: [
      {
        label: "删除加密副本",
        className: "btn-danger",
        onClick: () => finalizeExportDelete(item, gen),
      },
      {
        label: "只导出，不删除",
        className: "btn-ghost",
        onClick: () => keepExportedCopy(gen),
      },
    ],
  });
}

function keepExportedCopy(gen) {
  const exp = state.plainExport;
  if (!exp || exp.gen !== gen) return;
  const stepped = applyExportAction(exp.session, { type: "keep-copy" });
  if (stepped.deleteEncryptedCopy) {
    abortPlainExport("cancel");
    return;
  }
  releasePlainFile(exp, { immediate: !exp.downloadTriggered });
  state.plainExport = null;
  state.exportGen += 1;
  toast("已保留 gitbb 中的加密副本");
}

async function finalizeExportDelete(item, gen) {
  const exp = state.plainExport;
  if (!exp || exp.gen !== gen || exp.item.id !== item.id || !state.unlocked || !state.dekKey) {
    abortPlainExport("lock");
    return;
  }
  if (!deletionAllowed(exp.session)) {
    abortPlainExport("cancel");
    return;
  }
  const removed = await performDelete(item, "export");
  if (!exportStillCurrent(gen)) return;
  if (!removed) return;
  applyExportAction(state.plainExport.session, { type: "confirm-delete" });
  releasePlainFile(exp, { immediate: !exp.downloadTriggered });
  state.plainExport = null;
  state.exportGen += 1;
}

function openExportHelp() {
  const wrap = document.createElement("div");
  for (const text of EXPORT_HELP_PARAGRAPHS) {
    const paragraph = document.createElement("p");
    paragraph.textContent = text;
    wrap.append(paragraph);
  }
  openSheet({
    title: "解密导出说明",
    body: wrap,
    actions: [{ label: "知道了", className: "btn-primary" }],
  });
}

async function importFiles(fileList) {
  const files = [...fileList].filter(isVideoFile);
  if (!files.length) {
    toast("没有选到可识别的文件");
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
    toast(files.length === 1 ? "已放入 1 个文件" : `已放入 ${files.length} 个文件`);
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
    toast("这个文件夹是空的");
    return;
  }
  state.shuffleMode = Boolean(shuffle);
  let startIndex = 0;
  if (shuffle) {
    state.playQueue = nextShuffleQueue(ids, null);
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
  showProgress("正在打开", item.name, 0);
  try {
    const enc = await readEncryptedVideo(item.id);
    if (!enc) throw new Error("加密文件丢失，可能已被系统清理。请从备份恢复。");
    const plainBlob = await decryptPvidBlob(state.dekKey, enc, {
      mime: item.mime || guessMime(item.name),
      onProgress: (done, total) => {
        showProgress("正在打开", `${item.name}（${formatBytes(done)} / ${formatBytes(total)}）`, total ? done / total : 0);
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
    const ok = await confirmDialog("文件夹是空的", "仍要导出一份只有密钥和空目录的备份吗？", {
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
      recovery: state.recoveryRecord,
    });
    const name = `gitbb-${formatDateTime()}.ppb`;
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
  const { wrap, inputs } = passwordFields(["restore-pass"], ["备份口令（六位路径或原来的口令）"]);
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
            toast("请输入备份口令");
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
      const restoredRecovery = parsed.header?.recovery;
      if (restoredRecovery?.wrappedDEK && restoredRecovery?.question) {
        const recovery = { version: 1, ...restoredRecovery };
        await kvSet(KEY_RECOVERY, recovery);
        state.recoveryRecord = recovery;
      } else {
        await kvDelete(KEY_RECOVERY);
        state.recoveryRecord = null;
      }
      state.pinFails = 0;
      state.recoveryGuard = clearRecoveryGuard();
      await kvSet(KEY_PIN_FAILS, 0);
      await kvSet(KEY_RECOVERY_GUARD, state.recoveryGuard);
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
      toast(`已恢复 ${state.catalog.videos.length} 个文件`);
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
    toast(`已合并 ${added} 个文件`);
  } catch (err) {
    hideProgress();
    toast(err.message || "恢复失败，请检查口令与文件");
  } finally {
    $("file-backup").value = "";
    endBusy();
  }
}

function openChangePassword() {
  if (!state.unlocked || !state.dekBytes) {
    toast("请先打开文件夹");
    return;
  }
  showGate("change-choose");
}

function openLegacyPass() {
  const { wrap, inputs } = passwordFields(["legacy-pass"], ["原来的口令"]);
  const hint = document.createElement("p");
  hint.className = "hint";
  hint.textContent = "这是改版前留下的口令。打开后可以在设置里改成六层路径，并留下找回问题。";
  wrap.append(hint);
  openSheet({
    title: "用原来的口令打开",
    body: wrap,
    actions: [
      {
        label: "打开",
        className: "btn-primary",
        keepOpen: true,
        onClick: async () => {
          const value = inputs[0].value;
          if (!value) {
            toast("请填写口令");
            return;
          }
          beginBusy();
          try {
            showProgress("正在打开", "", 0.5);
            await unlockWithPassword(value);
            closeOverlay();
          } catch (err) {
            toast(err?.code === "BAD_PASSWORD" ? "打不开" : err.message || "打不开");
          } finally {
            hideProgress();
            endBusy();
          }
        },
      },
      { label: "取消", className: "btn-ghost" },
    ],
  });
}

function updateFaceUnlockButton() {
  const btn = $("btn-face");
  if (!btn) return;
  const onLock = state.gate?.mode === "unlock" && state.currentView === "view-gate";
  btn.hidden = !(onLock && state.webauthn && state.webauthn.wrappedDEK);
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
  const changeLabel = $("btn-change-pass")?.querySelector(".label");
  if (changeLabel) changeLabel.textContent = state.recoveryRecord ? "更改六层路径" : "改成六层路径";
  const secretBtn = $("btn-change-secret");
  if (secretBtn) secretBtn.hidden = !state.recoveryRecord;
  $("face-note").textContent = enrolled
    ? "已启用基于 WebAuthn PRF 的面容打开。加密根仍是六层路径；面容只用于安全派生解包密钥，不会把密钥明文存放在磁盘上。"
    : describePrfSupport(state.prfSupport);
}

async function enrollFace() {
  beginBusy();
  try {
    const rec = await enrollWebAuthnPrf(state.dekBytes);
    await kvSet(KEY_WEBAUTHN, rec);
    state.webauthn = rec;
    await refreshSettingsPane();
    toast("已启用面容 ID");
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
  const ok = await confirmDialog("关闭面容 ID？", "之后用六层路径打开。", {
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
  ensureFolderGrid();
  $("btn-gate-back").addEventListener("click", gateBack);
  $("btn-gate-restore").addEventListener("click", () =>
    askBackupAndRestore(state.unlocked ? "merge" : "fresh")
  );
  $("btn-legacy-pass").addEventListener("click", openLegacyPass);
  $("form-secret").addEventListener("submit", submitSecretForm);
  $("btn-secret-back").addEventListener("click", secretBack);

  $("btn-face").addEventListener("click", async () => {
    beginBusy();
    try {
      showProgress("等待面容验证", "只会使用安全密钥派生", 0.4);
      const dekBytes = await unlockWithWebAuthnPrf(state.webauthn);
      state.dekBytes = dekBytes;
      state.dekKey = await importDEK(dekBytes);
      state.pinFails = 0;
      state.recoveryGuard = clearRecoveryGuard();
      await kvSet(KEY_PIN_FAILS, 0);
      await kvSet(KEY_RECOVERY_GUARD, state.recoveryGuard);
      await afterUnlock();
    } catch (err) {
      if (err?.name === "NotAllowedError") toast("已取消");
      else toast(err.message || "面容打开失败，请使用六层路径");
    } finally {
      hideProgress();
      endBusy();
    }
  });

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
  $("btn-change-secret").addEventListener("click", () => {
    if (!state.unlocked || !state.dekBytes) return;
    showSecret("edit");
  });
  $("btn-enroll-face").addEventListener("click", enrollFace);
  $("btn-remove-face").addEventListener("click", removeFace);
  $("btn-export").addEventListener("click", exportBackup);
  $("btn-export-help").addEventListener("click", openExportHelp);
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
    if (state.playQueue?.hasNext()) {
      await goRelative(1);
      return;
    }
    const ids = state.catalog.videos.map((item) => item.id);
    if (state.shuffleMode && ids.length > 1) {
      const last = state.playQueue?.current;
      state.playQueue = nextShuffleQueue(ids, last);
      toast("换了一个顺序，继续");
      await loadCurrentVideo(true);
      return;
    }
    setPlayingUi(false);
    showPlayerControls(true);
    toast("已经看完");
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
      else if (!state.unlocked && (state.dekBytes || state.pendingPin)) {
        dropKeys();
        state.pendingPin = null;
        if (state.vaultRecord && (state.pinFails || 0) >= PIN_FAILS_BEFORE_RECOVERY && state.recoveryRecord?.question) {
          showSecret("recover");
        } else if (!state.vaultRecord) {
          showGate("setup-choose");
        } else {
          showGate("unlock");
        }
      }
    } else if (!document.hidden && state.currentView === "view-player" && !$("playerVideo").paused) {
      tryWakeLock();
    }
  });
  window.addEventListener("pagehide", () => {
    if (canAutoLock()) lock("页面隐藏");
  });
  $("overlay").addEventListener("click", (ev) => {
    if (ev.target !== $("overlay")) return;
    const dismiss = state.sheetDismiss;
    closeOverlay();
    dismiss?.();
  });
}

async function registerSw() {
  if (!("serviceWorker" in navigator)) return;
  try {
    const hadController = Boolean(navigator.serviceWorker.controller);
    navigator.serviceWorker.addEventListener("controllerchange", () => {
      if (!hadController) return;
      if (state.unlocked || state.plainExport || state.exportShareActive || state.busy > 0) return;
      try {
        if (sessionStorage.getItem("pp-sw-reload") === "1") return;
        sessionStorage.setItem("pp-sw-reload", "1");
      } catch {
        return;
      }
      location.reload();
    });
    await navigator.serviceWorker.register("./sw.js", { scope: "./" });
    setTimeout(() => {
      try {
        sessionStorage.removeItem("pp-sw-reload");
      } catch {
        /* 忽略无法使用的会话存储 */
      }
    }, 10000);
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
  state.recoveryRecord = (await kvGet(KEY_RECOVERY)) || null;
  state.webauthn = (await kvGet(KEY_WEBAUTHN)) || null;
  const storedFails = await kvGet(KEY_PIN_FAILS);
  state.pinFails = Number(storedFails) || 0;
  state.recoveryGuard = (await kvGet(KEY_RECOVERY_GUARD)) || clearRecoveryGuard();
  try {
    state.prfSupport = await detectWebAuthnPrf();
  } catch {
    state.prfSupport = "no";
  }
  if (!state.vaultRecord) {
    showGate("setup-choose");
  } else if (state.pinFails >= PIN_FAILS_BEFORE_RECOVERY && state.recoveryRecord?.question) {
    showSecret("recover");
  } else {
    showGate("unlock");
  }
}

boot();
