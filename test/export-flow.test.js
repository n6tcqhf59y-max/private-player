import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { describe, it } from "node:test";

import { buildBackupBlob, openBackupWithPassword, parseBackupBytes } from "../js/backup.js";
import {
  createVaultRecord,
  decryptChunked,
  decryptPvidBlob,
  encryptBlobChunked,
  encryptChunked,
  importDEK,
  parsePvidHeader,
  PVID_VERSION,
  unlockVault,
} from "../js/crypto.js";
import {
  EXPORT_HELP_PARAGRAPHS,
  EXPORT_REMOVE_NOTE,
  PLAIN_EXPORT_WARNING,
  applyExportAction,
  bytesEqual,
  createExportSession,
  deletionAllowed,
  exportContentType,
  exportFileName,
  plainUrlRevokeDelayMs,
  replayExport,
  shouldSuppressAutoLock,
  uniqueExportIds,
} from "../js/export.js";

const root = new URL("..", import.meta.url);

function readRoot(path) {
  return readFileSync(new URL(path, root), "utf8");
}

function randomBytes(size) {
  const out = new Uint8Array(size);
  crypto.getRandomValues(out);
  return out;
}

async function encryptSynthetic(plain, chunkSize) {
  const password = `synthetic-${crypto.randomUUID()}-password`;
  const { record, dekBytes } = await createVaultRecord(password, { iterations: 1_000 });
  const dek = await importDEK(dekBytes);
  const parts = [];
  await encryptBlobChunked(dek, new Blob([plain], { type: "video/mp4" }), (chunk) => {
    parts.push(chunk);
  }, { chunkSize });
  const pvidBlob = new Blob(parts, { type: "application/octet-stream" });
  return { password, record, dekBytes, dek, pvidBlob, plain };
}

describe("解密导出字节", () => {
  it("分块加密后的导出字节与原明文、decryptChunked 一致", async () => {
    const size = 8192 * 3 + 700 + Math.floor(Math.random() * 400);
    const plain = randomBytes(size);
    const { dek, pvidBlob } = await encryptSynthetic(plain, 8192);
    const packed = new Uint8Array(await pvidBlob.arrayBuffer());
    const header = parsePvidHeader(packed);
    assert.equal(header.version, PVID_VERSION);
    assert.equal(header.originalSize, plain.length);

    const viaBytes = await decryptChunked(dek, packed);
    const viaBlob = await decryptPvidBlob(dek, pvidBlob, { mime: "video/quicktime" });
    const exported = new Uint8Array(await viaBlob.arrayBuffer());
    const file = new File([viaBlob], "假期.mov", { type: viaBlob.type });
    const fileBytes = new Uint8Array(await file.arrayBuffer());

    assert.equal(bytesEqual(viaBytes, plain), true);
    assert.equal(bytesEqual(exported, plain), true);
    assert.equal(bytesEqual(fileBytes, plain), true);
    assert.equal(bytesEqual(exported, packed), false);
    assert.equal(file.type, "video/quicktime");
    assert.equal(file.name, "假期.mov");
  });

  it("空内容和单字节也能原样导出", async () => {
    for (const size of [0, 1]) {
      const plain = randomBytes(size);
      const { dek, pvidBlob } = await encryptSynthetic(plain, 64);
      const exported = new Uint8Array(
        await (await decryptPvidBlob(dek, pvidBlob, { mime: "video/mp4" })).arrayBuffer()
      );
      assert.equal(bytesEqual(exported, plain), true);
    }
  });

  it("错误密钥解密失败，且不会进入可删除状态", async () => {
    const plain = randomBytes(3000);
    const { pvidBlob } = await encryptSynthetic(plain, 1024);
    const other = await createVaultRecord("wrong-password-value", { iterations: 1_000 });
    const badKey = await importDEK(other.dekBytes);
    await assert.rejects(() => decryptPvidBlob(badKey, pvidBlob, { mime: "video/mp4" }), /解密失败|密钥/);

    const replay = replayExport("synthetic-id", ["accept-warning", "wrong-key", "confirm-delete"]);
    assert.equal(replay.deleteCalls, 0);
    assert.equal(replay.session.deleted, false);
    assert.equal(replay.session.phase, "aborted");
    assert.equal(replay.session.cancelReason, "wrong-key");
  });

  it("篡改密文视为失败，不删除", async () => {
    const plain = randomBytes(1200);
    const { dek, pvidBlob } = await encryptSynthetic(plain, 512);
    const packed = new Uint8Array(await pvidBlob.arrayBuffer());
    packed[packed.length - 1] ^= 0xff;
    await assert.rejects(() => decryptChunked(dek, packed));
    const replay = replayExport("synthetic-id", ["accept-warning", "decrypt-fail"]);
    assert.equal(replay.deleteCalls, 0);
    assert.equal(replay.session.deleted, false);
  });
});

describe("导出流程", () => {
  it("分享面板打开或下载触发后立刻移除一次，不再询问是否保存成功", () => {
    for (const handoff of ["share-resolved", "share-aborted", "download-triggered"]) {
      const replay = replayExport("vid-1", ["accept-warning", "decrypt-ok", handoff]);
      assert.equal(replay.deleteCalls, 1, handoff);
      assert.equal(replay.session.phase, "presented", handoff);
      assert.equal(replay.session.deleted, true, handoff);
      assert.equal(deletionAllowed(replay.session), true, handoff);
      const again = replayExport("vid-1", ["accept-warning", "decrypt-ok", handoff, "confirm-delete"]);
      assert.equal(again.deleteCalls, 1, handoff);
    }
  });

  it("多个 id 会去重并保持顺序", () => {
    assert.deepEqual(uniqueExportIds(["b", "a", "b", "", null, "a", "c"]), ["b", "a", "c"]);
  });

  it("分享面板打开之前取消、失败或锁定都不会移除", () => {
    const prefixes = [[], ["accept-warning"], ["accept-warning", "decrypt-ok"]];
    const stops = ["cancel", "lock", "share-failed", "decrypt-fail", "wrong-key"];
    for (const prefix of prefixes) {
      for (const stop of stops) {
        if (prefix.length < 2 && (stop === "share-failed")) continue;
        if (prefix.length < 1 && (stop === "decrypt-fail" || stop === "wrong-key")) continue;
        const label = `${prefix.join(",") || "idle"} + ${stop}`;
        const replay = replayExport("vid-4", [...prefix, stop]);
        assert.equal(replay.deleteCalls, 0, label);
        assert.equal(replay.session.deleted, false, label);
        assert.notEqual(replay.session.phase, "presented", label);
      }
    }
  });

  it("还没解密就说分享已打开，不会移除", () => {
    const replay = replayExport("vid-5", ["share-resolved", "download-triggered", "share-aborted"]);
    assert.equal(replay.deleteCalls, 0);
    assert.equal(replay.session.phase, "idle");
    assert.equal(replay.trace.every((step) => step.rejected), true);
  });
});

describe("分享期间的锁定与 Blob URL", () => {
  it("分享进行中抑制自动锁定；面板打开后才移除，之后再锁定不会再移除一次", () => {
    assert.equal(shouldSuppressAutoLock({ exportShareActive: true, busy: 0 }), true);
    assert.equal(shouldSuppressAutoLock({ exportShareActive: false, busy: 2 }), true);
    assert.equal(shouldSuppressAutoLock({ exportShareActive: false, busy: 0 }), false);
    const before = replayExport("vid-7", ["accept-warning", "decrypt-ok", "lock"]);
    assert.equal(before.deleteCalls, 0);
    assert.equal(before.session.cancelReason, "lock");
    const after = replayExport("vid-7", ["accept-warning", "decrypt-ok", "share-resolved", "lock"]);
    assert.equal(after.deleteCalls, 1);
    assert.equal(after.session.phase, "presented");
  });

  it("分享进行中不撤销 URL；下载后延迟撤销；锁定时立即撤销", () => {
    assert.equal(plainUrlRevokeDelayMs({ shareActive: true, downloadTriggered: true }), null);
    assert.equal(plainUrlRevokeDelayMs({ shareActive: false, downloadTriggered: true }), 15000);
    assert.equal(plainUrlRevokeDelayMs({ shareActive: false, downloadTriggered: true, immediate: true }), 0);
    assert.equal(plainUrlRevokeDelayMs({ immediate: true }), 0);
  });
});

describe("文件名与说明", () => {
  it("保留原文件名和 MIME，并补上缺失的扩展名", () => {
    assert.equal(exportFileName("假期.MOV", "video/quicktime"), "假期.MOV");
    assert.equal(exportContentType("假期.MOV", "video/quicktime"), "video/quicktime");
    assert.equal(exportFileName("a/b:c.mp4", "video/mp4"), "a_b_c.mp4");
    assert.equal(exportFileName("clip", "video/webm"), "clip.webm");
    assert.equal(exportFileName("", "video/quicktime"), "视频.mov");
    assert.equal(exportContentType("clip.mp4", "video/mp4; codecs=avc1"), "video/mp4");
    const long = `${"甲".repeat(200)}.mp4`;
    const named = exportFileName(long, "video/mp4");
    assert.ok(named.endsWith(".mp4"));
    assert.ok(named.length <= 180);
  });

  it("界面在导出前写明未加密，分享面板打开后移除，不再询问是否保存成功", () => {
    assert.equal(PLAIN_EXPORT_WARNING, "导出的是未加密原视频，不再受播放器密码或面容保护。");
    assert.ok(EXPORT_HELP_PARAGRAPHS.some((line) => line.includes(PLAIN_EXPORT_WARNING)));
    assert.ok(EXPORT_HELP_PARAGRAPHS.some((line) => line.includes(EXPORT_REMOVE_NOTE)));
    assert.ok(EXPORT_HELP_PARAGRAPHS.every((line) => !line.includes("已经保存成功")));
    const app = readRoot("js/app.js");
    const html = readRoot("index.html");
    const readme = readRoot("README.md");
    assert.ok(app.includes("PLAIN_EXPORT_WARNING"));
    assert.ok(app.includes("EXPORT_REMOVE_NOTE"));
    assert.ok(app.includes("解密导出"));
    assert.ok(!app.includes("已经保存成功"));
    assert.ok(html.includes(PLAIN_EXPORT_WARNING));
    assert.ok(html.includes("系统分享面板一旦打开"));
    assert.ok(!html.includes("已经保存成功"));
    assert.ok(readme.includes(PLAIN_EXPORT_WARNING));
    assert.ok(readme.includes("系统分享面板一旦打开"));
    assert.ok(!readme.includes("已经保存成功"));
    assert.ok(app.includes('performDelete(item, "library")'));
    assert.ok(app.includes('performDelete(item, "export")'));
    assert.deepEqual(
      [...app.matchAll(/deleteEncryptedVideo\(([^)]*)\)/g)].map((match) => match[1]),
      ["item.id", "id"]
    );
  });
});

describe("现有加密格式仍兼容", () => {
  it("备份可往返，错误密码不能打开，且不改变 PVID 版本", async () => {
    const plain = randomBytes(4096 + 50);
    const password = "backup-password-ok";
    const { record, dekBytes } = await createVaultRecord(password, { iterations: 1_000 });
    const dek = await importDEK(dekBytes);
    const pvid = await encryptChunked(dek, plain, 1000);
    assert.equal(parsePvidHeader(pvid).version, 1);
    const catalog = {
      version: 1,
      videos: [
        {
          id: "synthetic-1",
          name: "随机.mp4",
          size: plain.length,
          mime: "video/mp4",
          hasThumb: false,
        },
      ],
    };
    const backup = await buildBackupBlob({
      vaultRecord: record,
      dekKey: dek,
      catalog,
      items: [{ id: "synthetic-1", encBlob: new Blob([pvid]), hasThumb: false }],
    });
    const parsed = parseBackupBytes(new Uint8Array(await backup.arrayBuffer()));
    assert.equal(parsed.vaultRecord.kdf, "PBKDF2-SHA-256");
    const opened = await openBackupWithPassword(parsed, password);
    assert.equal(opened.catalog.videos[0].name, "随机.mp4");
    const round = await decryptChunked(opened.dekKey, parsed.items[0].encBytes);
    assert.equal(bytesEqual(round, plain), true);
    await assert.rejects(() => openBackupWithPassword(parsed, "not-the-password"));
    await assert.rejects(() => unlockVault(record, "not-the-password"));
  });
});

describe("service worker", () => {
  it("缓存版本已更新，并包含新的导出模块", () => {
    const sw = readRoot("sw.js");
    assert.match(sw, /gitbb-v6/);
    assert.doesNotMatch(sw, /gitbb-v5/);
    assert.doesNotMatch(sw, /private-player-v2/);
    assert.doesNotMatch(sw, /private-player-v1/);
    assert.match(sw, /networkFirst/);
    for (const file of readdirSync(new URL("js/", root))) {
      if (file.endsWith(".js")) assert.ok(sw.includes(`./js/${file}`), file);
    }
  });

  it("导出模块不包含上传接口", () => {
    const src = readRoot("js/export.js");
    assert.doesNotMatch(src, /fetch\s*\(|XMLHttpRequest|sendBeacon|WebSocket/);
  });
});
