/**
 * 播放控制：快进快退、倍速范围、画面适应和全屏策略。
 * 不读取真实视频。全屏优先用页面元素，以便倍速和快退按钮还在。
 * iOS 的 webkitEnterFullscreen 会换成系统播放器，自定义按钮会消失，因此不用它。
 */

export const MIN_RATE = 0.1;
export const MAX_RATE = 4;
export const SKIP_SECONDS = 10;
export const RATE_PRESETS = [0.1, 0.25, 0.5, 0.75, 1, 1.25, 1.5, 2, 3, 4];

export function clampRate(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 1;
  const clamped = Math.min(MAX_RATE, Math.max(MIN_RATE, n));
  return Math.round(clamped * 100) / 100;
}

export function formatRate(value) {
  const n = clampRate(value);
  const text = n.toFixed(2).replace(/0+$/, "").replace(/\.$/, "");
  return `${text}×`;
}

export function skipTime(current, delta, duration) {
  const cur = Number(current);
  const start = Number.isFinite(cur) && cur > 0 ? cur : 0;
  let next = start + Number(delta || 0);
  if (next < 0) next = 0;
  const total = Number(duration);
  if (Number.isFinite(total) && total > 0 && next > total) next = total;
  return next;
}

/**
 * 宽视频上下留边，高视频左右留边。始终完整显示，不裁切。
 */
export function frameFit(videoWidth, videoHeight, viewWidth, viewHeight) {
  const vw = Number(videoWidth);
  const vh = Number(videoHeight);
  const sw = Number(viewWidth);
  const sh = Number(viewHeight);
  if (!(vw > 0) || !(vh > 0) || !(sw > 0) || !(sh > 0)) {
    return { fit: "contain", bars: "unknown" };
  }
  const videoRatio = vw / vh;
  const viewRatio = sw / sh;
  if (Math.abs(videoRatio - viewRatio) < 0.02) {
    return { fit: "contain", bars: "none" };
  }
  return { fit: "contain", bars: videoRatio > viewRatio ? "letterbox" : "pillarbox" };
}

/**
 * standard / webkit：把播放器元素本身全屏，自定义控件还在里面。
 * css：接口不可用时铺满可视区域，仍然用 contain。
 */
export function fullscreenStrategy(capabilities) {
  if (capabilities?.active) return "exit";
  if (capabilities?.standard) return "element";
  if (capabilities?.webkit) return "element-webkit";
  return "css";
}
