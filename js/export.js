/**
 * 解密导出的纯决策与文件名。
 *
 * 不变量：
 * - 系统分享 Promise 完成、或下载被触发，都只是「交给系统」，不是保存成功。
 * - 只有用户明确确认「已经保存成功」之后，才允许询问删除。
 * - 只有用户再明确点删除，才标记为可删除。
 * - 取消、失败、错误密钥、锁定都不会删除。
 * 本模块不访问网络，也不读取任何真实视频。
 */

export const PLAIN_EXPORT_WARNING =
  "导出的是未加密原视频，不再受播放器密码或面容保护。";

export const EXPORT_HELP_PARAGRAPHS = [
  "在资料库里点视频卡片右上角，打开「删除这部视频？」。可以解密导出，也可以删除或取消。",
  "点「解密导出」后，会先在这台设备上解密出原视频，再请你点「保存到系统…」。iPhone 的 Safari 和主屏幕应用要求这一步由你的点击直接唤起系统分享。",
  "请在系统分享里把视频存到「文件」、相册，或你自己的网盘。播放器不会把视频上传到开发者的服务器，也不会发给任何第三方服务。",
  `${PLAIN_EXPORT_WARNING}拿到该文件的人无需应用密码或面容即可播放。`,
  "点保存之前如果离开本页，播放器会锁定并取消这次导出，加密副本不会被删除。系统分享面板打开之后，请在面板里完成保存。",
  "系统分享窗口关闭，或者浏览器开始下载，都只说明系统接手了文件，不等于已经落盘。请亲自打开保存位置检查。",
  "只有你明确点「已经保存成功」之后，才会另外询问是否删除播放器里的加密副本。你可以只导出、不删除。",
  "取消、分享失败、解密失败、密钥不对，或应用锁定时，都不会删除加密副本。",
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

const TERMINAL = new Set(["aborted", "deleted", "kept"]);

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
    case "download-triggered":
      if (session.phase !== "ready") return null;
      return {
        ...session,
        phase: "handoff",
        handoff: type,
        deleteArmed: false,
        deleted: false,
        rejected: false,
      };
    case "share-aborted":
      if (session.phase !== "ready" && session.phase !== "handoff") return null;
      return abort(session, "share-aborted");
    case "share-failed":
      if (session.phase !== "ready" && session.phase !== "handoff") return null;
      return abort(session, "share-failed");
    case "confirm-saved":
      if (session.phase !== "handoff") return null;
      return {
        ...session,
        phase: "saved-confirmed",
        deleteArmed: true,
        deleted: false,
        rejected: false,
      };
    case "deny-saved":
      if (session.phase !== "handoff") return null;
      return abort(session, "not-saved");
    case "confirm-delete":
      if (session.phase !== "saved-confirmed" || session.deleteArmed !== true) return null;
      return {
        ...session,
        phase: "deleted",
        deleteArmed: true,
        deleted: true,
        rejected: false,
      };
    case "keep-copy":
      if (session.phase !== "saved-confirmed") return null;
      return {
        ...session,
        phase: "kept",
        deleteArmed: false,
        deleted: false,
        rejected: false,
      };
    case "cancel":
      return abort(session, "cancel");
    case "lock":
      return abort(session, "lock");
    default:
      return null;
  }
}

/**
 * 推进一次导出。deleteEncryptedCopy 仅在「确认已保存」之后又明确确认删除时为 true。
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
  if (!next || (next.deleted && type !== "confirm-delete")) {
    return {
      session: { ...session, rejected: true },
      deleteEncryptedCopy: false,
      rejected: true,
    };
  }
  return {
    session: next,
    deleteEncryptedCopy: next.phase === "deleted" && next.deleted === true,
    rejected: false,
  };
}

export function deletionAllowed(session) {
  return Boolean(
    session &&
      session.phase === "saved-confirmed" &&
      session.deleteArmed === true &&
      session.deleted === false
  );
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
