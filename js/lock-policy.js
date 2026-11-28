/**
 * 解锁后的自动锁定。
 * 正在播放算作操作，不在播放中途锁定。
 * 暂停或停止后，连续 10 分钟没有操作才锁定。
 * 系统分享打开或正在忙时不锁定。
 */

export const IDLE_LOCK_MS = 10 * 60 * 1000;

export function normalizeIdleLockMs(savedMs) {
  void savedMs;
  return IDLE_LOCK_MS;
}

export function playbackInProgress(flags) {
  return Boolean(flags && flags.view === "player" && flags.paused === false);
}

export function shouldArmIdleLock(flags) {
  if (!flags?.unlocked) return false;
  if (flags.shareActive) return false;
  if (Number(flags.busy) > 0) return false;
  if (playbackInProgress(flags)) return false;
  return true;
}

export function shouldLockOnBackground(flags) {
  if (!shouldArmIdleLock(flags)) return false;
  if (flags.lockOnBackground === false) return false;
  return true;
}
