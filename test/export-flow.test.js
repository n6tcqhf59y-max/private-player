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

describe("确认流程", () => {
  const savedThenDelete = [
    "accept-warning",
    "decrypt-ok",
    "share-resolved",
    "confirm-saved",
    "confirm-delete",
  ];

  it("只有明确确认已经保存成功后，再确认删除，才会删除一次", () => {
    const replay = replayExport("vid-1", savedThenDelete);
    assert.equal(replay.deleteCalls, 1);
    assert.equal(replay.session.phase, "deleted");
    assert.equal(replay.trace.filter((step) => step.deleteEncryptedCopy).length, 1);
    assert.equal(replay.trace[2].phase, "handoff");
    assert.equal(replay.trace[2].deleteArmed, false);
    assert.equal(replay.trace[2].deleteEncryptedCopy, false);
    assert.equal(deletionAllowed(replay.trace[2] && { ...replay.session, phase: "handoff", deleteArmed: false, deleted: false }), false);
  });

  it("分享完成或下载触发都不等于保存成功，也不能删除", () => {
    for (const handoff of ["share-resolved", "download-triggered"]) {
      const replay = replayExport("vid-2", ["accept-warning", "decrypt-ok", handoff, "confirm-delete"]);
      assert.equal(replay.deleteCalls, 0);
      assert.equal(replay.session.phase, "handoff");
      assert.equal(replay.session.deleteArmed, false);
      assert.equal(deletionAllowed(replay.session), false);
      assert.equal(replay.trace.at(-1).rejected, true);
    }
  });

  it("确认已保存后仍可只导出不删除", () => {
    const replay = replayExport("vid-3", [
      "accept-warning",
      "decrypt-ok",
      "download-triggered",
      "confirm-saved",
      "keep-copy",
      "confirm-delete",
    ]);
    assert.equal(replay.deleteCalls, 0);
    assert.equal(replay.session.phase, "kept");
    assert.equal(replay.session.deleted, false);
    const afterSaved = createExportSession("vid-3");
    let session = afterSaved;
    for (const type of ["accept-warning", "decrypt-ok", "share-resolved", "confirm-saved"]) {
      session = applyExportAction(session, { type }).session;
    }
    assert.equal(deletionAllowed(session), true);
    const kept = applyExportAction(session, { type: "keep-copy" });
    assert.equal(kept.deleteEncryptedCopy, false);
    assert.equal(deletionAllowed(kept.session), false);
  });

  it("取消、失败、未保存和锁定本身都不会删除", () => {
    const prefixes = [
      [],
      ["accept-warning"],
      ["accept-warning", "decrypt-ok"],
      ["accept-warning", "decrypt-ok", "share-resolved"],
      ["accept-warning", "decrypt-ok", "download-triggered"],
      ["accept-warning", "decrypt-ok", "share-resolved", "confirm-saved"],
    ];
    const stops = ["cancel", "lock", "share-aborted", "share-failed", "deny-saved", "decrypt-fail", "wrong-key"];
    for (const prefix of prefixes) {
      for (const stop of stops) {
        const label = `${prefix.join(",") || "idle"} + ${stop}`;
        const replay = replayExport("vid-4", [...prefix, stop]);
        assert.equal(replay.deleteCalls, 0, label);
        assert.equal(replay.session.deleted, false, label);
        if (replay.session.phase === "saved-confirmed") continue;
        const followed = replayExport("vid-4", [...prefix, stop, "confirm-delete"]);
        assert.equal(followed.deleteCalls, 0, `${label} 之后不能删除`);
        assert.notEqual(followed.session.phase, "deleted", label);
      }
    }
  });

  it("未走完确认流程时直接删除会被拒绝", () => {
    const replay = replayExport("vid-5", ["confirm-delete", "confirm-saved", "decrypt-ok"]);
    assert.equal(replay.deleteCalls, 0);
    assert.equal(replay.session.phase, "idle");
    assert.equal(replay.trace.every((step) => step.rejected), true);
  });

  it("用户否认已经保存成功后不能删除", () => {
    const replay = replayExport("vid-6", [
      "accept-warning",
      "decrypt-ok",
      "share-resolved",
      "deny-saved",
      "confirm-saved",
      "confirm-delete",
    ]);
    assert.equal(replay.deleteCalls, 0);
    assert.equal(replay.session.cancelReason, "not-saved");
    assert.equal(deletionAllowed(replay.session), false);
  });
});

describe("分享期间的锁定与 Blob URL", () => {
  it("分享进行中抑制自动锁定；锁定动作本身仍然不删除", () => {
    assert.equal(shouldSuppressAutoLock({ exportShareActive: true, busy: 0 }), true);
    assert.equal(shouldSuppressAutoLock({ exportShareActive: false, busy: 2 }), true);
    assert.equal(shouldSuppressAutoLock({ exportShareActive: false, busy: 0 }), false);
    const replay = replayExport("vid-7", [
      "accept-warning",
      "decrypt-ok",
      "share-resolved",
      "lock",
    ]);
    assert.equal(replay.deleteCalls, 0);
    assert.equal(replay.session.cancelReason, "lock");
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

  it("界面文案写明未加密，且帮助说明要求单独确认保存成功", () => {
    assert.equal(PLAIN_EXPORT_WARNING, "导出的是未加密原视频，不再受播放器密码或面容保护。");
    assert.ok(EXPORT_HELP_PARAGRAPHS.some((line) => line.includes(PLAIN_EXPORT_WARNING)));
    assert.ok(EXPORT_HELP_PARAGRAPHS.some((line) => line.includes("已经保存成功")));
    assert.ok(EXPORT_HELP_PARAGRAPHS.some((line) => line.includes("只导出、不删除")));
    const app = readRoot("js/app.js");
    const html = readRoot("index.html");
    const readme = readRoot("README.md");
    assert.ok(app.includes("PLAIN_EXPORT_WARNING"));
    assert.ok(app.includes("已经保存成功"));
    assert.ok(app.includes("解密导出"));
    assert.ok(html.includes(PLAIN_EXPORT_WARNING));
    assert.ok(html.includes("已经保存成功"));
    assert.ok(readme.includes(PLAIN_EXPORT_WARNING));
    assert.ok(readme.includes("已经保存成功"));
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
    assert.match(sw, /gitbb-v3/);
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
