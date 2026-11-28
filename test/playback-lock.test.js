import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import { PBKDF2_ITERATIONS, PVID_MAGIC } from "../js/crypto.js";
import {
  IDLE_LOCK_MS,
  normalizeIdleLockMs,
  playbackInProgress,
  shouldArmIdleLock,
  shouldLockOnBackground,
} from "../js/lock-policy.js";
import {
  MAX_RATE,
  MIN_RATE,
  RATE_PRESETS,
  SKIP_SECONDS,
  clampRate,
  frameFit,
  fullscreenStrategy,
  skipTime,
} from "../js/playback.js";
import { KEY_CATALOG, KEY_RECOVERY, KEY_VAULT, defaultSettings } from "../js/storage.js";

const root = new URL("..", import.meta.url);

describe("10 分钟锁定", () => {
  it("旧的短超时都会变成 10 分钟，播放中不启动闲置计时", () => {
    assert.equal(IDLE_LOCK_MS, 10 * 60 * 1000);
    assert.equal(normalizeIdleLockMs(60_000), IDLE_LOCK_MS);
    assert.equal(normalizeIdleLockMs(120_000), IDLE_LOCK_MS);
    assert.equal(normalizeIdleLockMs(0), IDLE_LOCK_MS);
    assert.equal(defaultSettings().autoLockMs, IDLE_LOCK_MS);
    const playing = {
      unlocked: true,
      shareActive: false,
      busy: 0,
      lockOnBackground: true,
      view: "player",
      paused: false,
    };
    assert.equal(playbackInProgress(playing), true);
    assert.equal(shouldArmIdleLock(playing), false);
    assert.equal(shouldLockOnBackground(playing), false);
    const paused = { ...playing, paused: true };
    assert.equal(shouldArmIdleLock(paused), true);
    assert.equal(shouldLockOnBackground(paused), true);
    assert.equal(shouldArmIdleLock({ ...paused, shareActive: true }), false);
    assert.equal(shouldLockOnBackground({ ...paused, shareActive: true }), false);
    assert.equal(shouldArmIdleLock({ ...paused, busy: 1 }), false);
  });
});

describe("播放控制", () => {
  it("快进快退不超过片头片尾", () => {
    assert.equal(SKIP_SECONDS, 10);
    assert.equal(skipTime(20, 10, 100), 30);
    assert.equal(skipTime(5, -10, 100), 0);
    assert.equal(skipTime(95, 10, 100), 100);
    assert.equal(skipTime(Number.NaN, -10, 40), 0);
  });

  it("倍速限制在 0.1 到 4，预设都在范围内", () => {
    assert.equal(MIN_RATE, 0.1);
    assert.equal(MAX_RATE, 4);
    assert.equal(clampRate(0.04), 0.1);
    assert.equal(clampRate(9), 4);
    assert.equal(clampRate(1.25), 1.25);
    assert.equal(clampRate("2.04"), 2.04);
    assert.equal(clampRate("nope"), 1);
    for (const rate of RATE_PRESETS) {
      assert.equal(clampRate(rate), rate);
    }
  });

  it("横竖视频都完整显示，横的上下留边，竖的左右留边", () => {
    assert.deepEqual(frameFit(1920, 1080, 390, 844), { fit: "contain", bars: "letterbox" });
    assert.deepEqual(frameFit(1080, 1920, 844, 390), { fit: "contain", bars: "pillarbox" });
    assert.deepEqual(frameFit(1080, 1920, 390, 844), { fit: "contain", bars: "letterbox" });
    assert.equal(frameFit(0, 0, 100, 100).bars, "unknown");
  });

  it("全屏优先用播放器元素，没有接口时用样式铺满，不用系统视频全屏", () => {
    assert.equal(fullscreenStrategy({ active: true, standard: true }), "exit");
    assert.equal(fullscreenStrategy({ standard: true, webkit: true }), "element");
    assert.equal(fullscreenStrategy({ webkit: true }), "element-webkit");
    assert.equal(fullscreenStrategy({}), "css");
    const app = readFileSync(new URL("js/app.js", root), "utf8");
    assert.equal(app.includes("webkitEnterFullscreen"), false);
    assert.match(app, /player-fill/);
    assert.match(app, /btn-back-10|skipPlayback/);
  });
});

describe("已有资料不受影响", () => {
  it("密钥库、目录和找回记录的存储键以及加密参数都没有换", () => {
    assert.equal(KEY_VAULT, "vault");
    assert.equal(KEY_CATALOG, "catalog");
    assert.equal(KEY_RECOVERY, "recovery");
    assert.equal(PBKDF2_ITERATIONS, 600_000);
    assert.equal(PVID_MAGIC, "PVID");
    const storage = readFileSync(new URL("js/storage.js", root), "utf8");
    assert.match(storage, /const DB_NAME = "private-player"/);
    assert.match(storage, /const DB_VERSION = 1/);
    assert.match(storage, /KEY_PIN_FAILS = "pinFails"/);
    assert.match(storage, /KEY_RECOVERY_GUARD = "recoveryGuard"/);
  });
});
