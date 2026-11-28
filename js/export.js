/**
 * 解密导出的纯决策与文件名。
 *
 * 不变量：
 * - 导出前必须先看到未加密警告，用户确认后才解密。
 * - 系统分享面板打开，或下载被触发，才表示导出流程已经摆出来。
 * - 流程摆出来之后立刻移除资料库里的加密副本，不再询问是否保存成功。
 * - 在分享面板打开之前取消、解密失败、分享面板没能打开、或锁定，都不移除。
 * 多个文件逐个分享。iOS 一次分享多个文件不可靠。
 * 本模块不访问网络，也不读取任何真实视频。
 */

export const PLAIN_EXPORT_WARNING =
  "导出的是未加密原视频，不再受播放器密码或面容保护。";

export const EXPORT_REMOVE_NOTE =
  "系统分享面板一旦打开，这个文件会立刻从 gitbb 里移除，即使你在面板里取消也一样。";

export const EXPORT_HELP_PARAGRAPHS = [
  "点右上角「选择」，勾选一个或多个文件，再点「解密导出」。也可以在单个文件的删除框里点「解密导出」。",
  "确认导出之前会先说明这是未加密原视频，并且分享面板打开后会从 gitbb 里移除。",
  "点「解密导出」后，会先在这台设备上解密，再请你点「保存到系统…」。iPhone 的 Safari 和主屏幕应用要求这一步由你的点击直接唤起系统分享。多个文件会一个接一个打开。",
  "请在系统分享里把视频存到「文件」、相册，或你自己的网盘。gitbb 不会把视频上传到开发者的服务器。网页应用不能直接写回原来的相册或文件夹。",
  `${PLAIN_EXPORT_WARNING}拿到该文件的人无需路径或面容即可播放。`,
  EXPORT_REMOVE_NOTE,
  "点「保存到系统…」之前如果取消，加密副本不会移除。解密失败、密钥不对，或分享面板没能打开，也不会移除。",
];

const MIME_EXT = {
  "video/mp4": ".mp4",
  "video/quicktime": ".mov",
  "video/webm": ".webm",
  "video/x-matroska": ".mkv",
  "video/avi": ".avi",
  "video/x-msvideo": ".avi",
  "video/hevc": ".hevc",
};

const TERMINAL = new Set(["aborted", "presented"]);
const PRESENTED = new Set(["share-resolved", "share-aborted", "download-triggered"]);

export function uniqueExportIds(ids) {
  const out = [];
  const seen = new Set();
  for (const id of Array.isArray(ids) ? ids : []) {
    if (typeof id !== "string" || !id || seen.has(id)) continue;
    seen.add(id);
    out.push(id);
  }
  return out;
}

export function createExportSession(videoId) {
  if (typeof videoId !== "string" || !videoId) {
    throw new TypeError("需要视频 id");
  }
  return {
    videoId,
    phase: "idle",
    deleteArmed: false,
    deleted: false,
    handoff: null,
    cancelReason: null,
    rejected: false,
  };
}

function abort(session, reason) {
  return {
    ...session,
    phase: "aborted",
    cancelReason: reason,
    deleteArmed: false,
    deleted: false,
    rejected: false,
  };
}

function reduceExport(session, type) {
  switch (type) {
    case "accept-warning":
      if (session.phase !== "idle") return null;
      return { ...session, phase: "decrypting", rejected: false };
    case "decrypt-ok":
      if (session.phase !== "decrypting") return null;
      return { ...session, phase: "ready", rejected: false };
    case "decrypt-fail":
      if (session.phase !== "decrypting") return null;
      return abort(session, "decrypt-fail");
    case "wrong-key":
      if (session.phase !== "decrypting") return null;
      return abort(session, "wrong-key");
    case "share-resolved":
    case "share-aborted":
    case "download-triggered":
      if (session.phase !== "ready") return null;
      return {
        ...session,
        phase: "presented",
        handoff: type,
        deleteArmed: true,
        deleted: true,
        rejected: false,
      };
    case "share-failed":
      if (session.phase !== "ready") return null;
      return abort(session, "share-failed");
    case "cancel":
      return abort(session, "cancel");
    case "lock":
      return abort(session, "lock");
    default:
      return null;
  }
}

/**
 * 推进一次导出。分享面板已经打开，或下载已经触发时，deleteEncryptedCopy 为 true。
 */
export function applyExportAction(session, action) {
  if (!session || typeof session.videoId !== "string" || !session.videoId) {
    return { session, deleteEncryptedCopy: false, rejected: true };
  }
  if (TERMINAL.has(session.phase)) {
    return {
      session: { ...session, rejected: true },
      deleteEncryptedCopy: false,
      rejected: true,
    };
  }
  const type = action?.type;
  const next = reduceExport(session, type);
  if (!next || (next.deleted && !PRESENTED.has(type))) {
    return {
      session: { ...session, rejected: true },
      deleteEncryptedCopy: false,
      rejected: true,
    };
  }
  return {
    session: next,
    deleteEncryptedCopy: next.phase === "presented" && next.deleted === true,
    rejected: false,
  };
}

export function deletionAllowed(session) {
  return Boolean(session && session.phase === "presented" && session.deleted === true);
}

export function replayExport(videoId, steps) {
  let session = createExportSession(videoId);
  let deleteCalls = 0;
  const trace = [];
  for (const type of steps) {
    const result = applyExportAction(session, { type });
    session = result.session;
    if (result.deleteEncryptedCopy) deleteCalls += 1;
    trace.push({
      type,
      phase: session.phase,
      deleted: session.deleted,
      deleteArmed: Boolean(session.deleteArmed),
      rejected: result.rejected,
      deleteEncryptedCopy: result.deleteEncryptedCopy,
    });
  }
  return { session, deleteCalls, trace };
}

/** 分享面板打开期间不能自动锁定，否则可能打断系统分享。锁定本身也不删除。 */
export function shouldSuppressAutoLock(flags) {
  if (!flags) return false;
  if (flags.exportShareActive) return true;
  return Number(flags.busy) > 0;
}

/**
 * 分享进行中不要撤销 Blob URL。
 * 下载刚触发时给浏览器一点时间读取；锁定、取消、失败应立即撤销。
 * 返回 null 表示先不要撤销。
 */
export function plainUrlRevokeDelayMs({ shareActive = false, downloadTriggered = false, immediate = false } = {}) {
  if (shareActive) return null;
  if (immediate) return 0;
  if (downloadTriggered) return 15000;
  return 0;
}

export function exportContentType(name, mime) {
  const raw = String(mime || "")
    .split(";")[0]
    .trim()
    .toLowerCase();
  if (raw && raw !== "application/octet-stream") return raw;
  const lower = String(name || "").toLowerCase();
  if (lower.endsWith(".mov")) return "video/quicktime";
  if (lower.endsWith(".m4v") || lower.endsWith(".mp4")) return "video/mp4";
  if (lower.endsWith(".webm")) return "video/webm";
  if (lower.endsWith(".mkv")) return "video/x-matroska";
  if (lower.endsWith(".avi")) return "video/x-msvideo";
  return "video/mp4";
}

function extensionForMime(mime) {
  return MIME_EXT[mime] || "";
}

function splitExtension(filename) {
  const i = filename.lastIndexOf(".");
  if (i <= 0 || i === filename.length - 1 || filename.length - i > 8) {
    return { stem: filename, ext: "" };
  }
  return { stem: filename.slice(0, i), ext: filename.slice(i) };
}

export function exportFileName(name, mime) {
  const type = exportContentType(name, mime);
  let cleaned = String(name ?? "")
    .replace(/[\u0000-\u001f]/g, "")
    .replace(/[\\/:*?"<>|]/g, "_")
    .trim();
  cleaned = cleaned.replace(/^\.+$/, "");
  const fallbackExt = extensionForMime(type) || ".mp4";
  if (!cleaned) return `视频${fallbackExt}`;
  let { stem, ext } = splitExtension(cleaned);
  if (!ext) ext = fallbackExt;
  if (!stem) stem = "视频";
  const max = 180;
  if (stem.length + ext.length > max) {
    stem = stem.slice(0, Math.max(1, max - ext.length));
  }
  return stem + ext;
}

export function bytesEqual(a, b) {
  const x = a instanceof Uint8Array ? a : new Uint8Array(a);
  const y = b instanceof Uint8Array ? b : new Uint8Array(b);
  if (x.length !== y.length) return false;
  for (let i = 0; i < x.length; i += 1) {
    if (x[i] !== y[i]) return false;
  }
  return true;
}
