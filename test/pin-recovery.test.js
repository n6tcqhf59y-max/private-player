import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import { buildBackupBlob, openBackupWithPassword, parseBackupBytes } from "../js/backup.js";
import {
  PBKDF2_ITERATIONS,
  createVaultRecord,
  decryptChunked,
  encryptChunked,
  importDEK,
  rewrapVault,
  unlockVault,
} from "../js/crypto.js";
import { bytesEqual } from "../js/export.js";
import {
  PIN_DIGITS,
  PIN_FAILS_BEFORE_RECOVERY,
  advanceGate,
  countsAsPinAttempt,
  notePinFailure,
  notePinSuccess,
  retreatGate,
} from "../js/pinflow.js";
import { nextShuffleQueue } from "../js/queue.js";
import {
  assessRecoveryGuard,
  clearRecoveryGuard,
  createRecoveryRecord,
  normalizeAnswer,
  registerRecoveryFailure,
  unlockRecovery,
} from "../js/recovery.js";

const root = new URL("..", import.meta.url);
const readRoot = (path) => readFileSync(new URL(path, root), "utf8");
const FAST = { iterations: 1_000 };

function randomBytes(size) {
  const out = new Uint8Array(size);
  crypto.getRandomValues(out);
  return out;
}

function walk(mode, pin, first = "") {
  let state = { mode, digits: "", first };
  let last = state;
  for (const digit of pin) {
    last = advanceGate(state, digit);
    state = last;
  }
  return last;
}

describe("六层路径的设定和确认", () => {
  it("每一层都是 0 到 9，没走完六层不算一次尝试", () => {
    assert.deepEqual(PIN_DIGITS, ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]);
    const mid = walk("unlock", "13579");
    assert.equal(mid.kind, "browsing");
    assert.equal(mid.pin, null);
    assert.equal(countsAsPinAttempt(mid.kind), false);
    assert.equal(mid.digits, "13579");
    const back = retreatGate(mid);
    assert.equal(back.digits, "1357");
    assert.equal(back.restarted, false);
  });

  it("两次路径一致才算定好，不一致就整条重来", () => {
    const chosen = walk("setup-choose", "135790");
    assert.equal(chosen.kind, "need-confirm");
    assert.equal(chosen.mode, "setup-confirm");
    assert.equal(chosen.digits, "");
    assert.equal(chosen.pin, null);

    const wrong = walk("setup-confirm", "135791", chosen.first);
    assert.equal(wrong.kind, "mismatch");
    assert.equal(wrong.mode, "setup-choose");
    assert.equal(wrong.first, "");
    assert.equal(wrong.digits, "");
    assert.equal(wrong.notice, "mismatch");
    assert.equal(countsAsPinAttempt(wrong.kind), false);

    const again = walk("setup-choose", "135790");
    const confirmed = walk(again.mode, "135790", again.first);
    assert.equal(confirmed.kind, "submit-new-pin");
    assert.equal(confirmed.pin, "135790");
  });

  it("确认走到一半返回，会丢掉第一次的路径", () => {
    const chosen = walk("change-choose", "246801");
    const back = retreatGate({ mode: chosen.mode, digits: "", first: chosen.first });
    assert.equal(back.restarted, true);
    assert.equal(back.mode, "change-choose");
    assert.equal(back.first, "");
  });

  it("六位数字才能包装密钥，迭代次数保持 60 万", async () => {
    await assert.rejects(() => createVaultRecord("13579", { pin: true, ...FAST }), /六位/);
    await assert.rejects(() => createVaultRecord("1357901", { pin: true, ...FAST }), /六位/);
    await assert.rejects(() => createVaultRecord("13579a", { pin: true, ...FAST }), /六位/);
    const { record, dekBytes } = await createVaultRecord("135790", { pin: true, ...FAST });
    assert.equal(record.kdf, "PBKDF2-SHA-256");
    assert.equal(record.iterations, 1_000);
    const opened = await unlockVault(record, "135790");
    assert.equal(bytesEqual(opened, dekBytes), true);
    await assert.rejects(() => unlockVault(record, "135791"));
    assert.equal(PBKDF2_ITERATIONS, 600_000);
  });
});

describe("连续走错五次才出现找回问题", () => {
  it("前四次完整失败不出现问题，第五次才出现，走对一次就清零", () => {
    let fails = 0;
    for (let i = 0; i < 4; i += 1) {
      const entered = walk("unlock", `11111${i}`);
      assert.equal(entered.kind, "submit-unlock");
      assert.equal(countsAsPinAttempt(entered.kind), true);
      const next = notePinFailure(fails);
      fails = next.fails;
      assert.equal(next.showRecovery, false);
    }
    const fifth = notePinFailure(fails);
    assert.equal(fifth.fails, PIN_FAILS_BEFORE_RECOVERY);
    assert.equal(fifth.showRecovery, true);
    assert.equal(notePinSuccess().fails, 0);
    assert.equal(notePinSuccess().showRecovery, false);
  });
});

describe("找回问题", () => {
  it("去掉首尾空格和零宽字符后，正确答案能解开，错误答案不能", async () => {
    const plain = randomBytes(900);
    const pin = "102938";
    const answer = "  蓝色的海岸  ";
    const { record, dekBytes } = await createVaultRecord(pin, { pin: true, ...FAST });
    const dek = await importDEK(dekBytes);
    const hidden = await encryptChunked(dek, plain, 256);
    const recovery = await createRecoveryRecord("只有我知道的岸", answer, dekBytes, FAST);
    assert.equal(recovery.kdf, "PBKDF2-SHA-256");
    assert.equal(recovery.iterations, 1_000);
    assert.equal(recovery.question, "只有我知道的岸");
    assert.equal(JSON.stringify(recovery).includes("蓝色的海岸"), false);

    const fromTrimmed = await unlockRecovery(recovery, "蓝色的海岸");
    const fromSpaces = await unlockRecovery(recovery, "\u200b  蓝色的海岸  ");
    assert.equal(bytesEqual(fromTrimmed, dekBytes), true);
    assert.equal(bytesEqual(fromSpaces, dekBytes), true);
    assert.equal(bytesEqual(await decryptChunked(await importDEK(fromTrimmed), hidden), plain), true);

    await assert.rejects(() => unlockRecovery(recovery, "蓝色海岸"));
    await assert.rejects(() => unlockRecovery(recovery, "   "));
    await assert.rejects(() => createRecoveryRecord("问题", "   \u200b", dekBytes, FAST), /请填写答案/);
    assert.equal(normalizeAnswer("  a\u200b  "), "a");

    const short = await createRecoveryRecord("问题", "短", dekBytes, FAST);
    assert.equal(bytesEqual(await unlockRecovery(short, "短"), dekBytes), true);
    const one = await createRecoveryRecord("问题", " a ", dekBytes, FAST);
    assert.equal(bytesEqual(await unlockRecovery(one, "a"), dekBytes), true);
    const longAnswer = "甲".repeat(300);
    const longRecord = await createRecoveryRecord("问题", longAnswer, dekBytes, FAST);
    assert.equal(bytesEqual(await unlockRecovery(longRecord, longAnswer), dekBytes), true);
    assert.equal(JSON.stringify(short).includes("短"), false);
  });

  it("答对后重设路径，新旧路径都能按预期解密或拒绝", async () => {
    const plain = randomBytes(1400);
    const { record, dekBytes } = await createVaultRecord("135790", { pin: true, ...FAST });
    const recovery = await createRecoveryRecord("我的问题是什么", "海岸的蓝颜色", dekBytes, FAST);
    const hidden = await encryptChunked(await importDEK(dekBytes), plain, 300);

    await assert.rejects(() => unlockRecovery(recovery, "猜一个错误答案"));
    const restored = await unlockRecovery(recovery, "  海岸的蓝颜色 ");
    const next = await rewrapVault(restored, "246801", { pin: true, ...FAST });
    const viaNew = await unlockVault(next, "246801");
    assert.equal(bytesEqual(viaNew, dekBytes), true);
    assert.equal(bytesEqual(await decryptChunked(await importDEK(viaNew), hidden), plain), true);
    await assert.rejects(() => unlockVault(next, "135790"));
    await assert.rejects(() => unlockVault(record, "246801"));
    assert.equal(bytesEqual(await unlockVault(record, "135790"), dekBytes), true);
  });

  it("答错会锁住，锁住期间不允许继续猜", () => {
    const start = 1_700_000_000_000;
    let guard = clearRecoveryGuard();
    for (let i = 0; i < 4; i += 1) {
      guard = registerRecoveryFailure(guard, start);
      assert.equal(assessRecoveryGuard(guard, start).allowed, true);
    }
    guard = registerRecoveryFailure(guard, start);
    const locked = assessRecoveryGuard(guard, start + 1000);
    assert.equal(locked.allowed, false);
    assert.equal(locked.fails, 5);
    assert.ok(locked.retryAt - start >= 60 * 1000);
    const later = assessRecoveryGuard(guard, locked.retryAt + 1);
    assert.equal(later.allowed, true);
    assert.equal(later.fails, 5);
    assert.deepEqual(clearRecoveryGuard(), { fails: 0, lockedUntil: 0 });
  });

  it("默认迭代次数不降低，备份仍能用路径打开并带上问题", async () => {
    const { record, dekBytes } = await createVaultRecord("135790", { pin: true });
    const recovery = await createRecoveryRecord("默认强度", "足够长的答案", dekBytes);
    assert.equal(record.iterations, PBKDF2_ITERATIONS);
    assert.equal(recovery.iterations, PBKDF2_ITERATIONS);
    const plain = randomBytes(80);
    const dek = await importDEK(dekBytes);
    const backup = await buildBackupBlob({
      vaultRecord: record,
      dekKey: dek,
      catalog: { version: 1, videos: [{ id: "s", name: "合成.bin", size: plain.length }] },
      items: [{ id: "s", encBlob: new Blob([await encryptChunked(dek, plain, 40)]), hasThumb: false }],
      recovery,
    });
    const parsed = parseBackupBytes(new Uint8Array(await backup.arrayBuffer()));
    assert.equal(parsed.header.app, "iphone-private-player");
    assert.equal(parsed.header.recovery.question, "默认强度");
    assert.equal(parsed.header.recovery.iterations, PBKDF2_ITERATIONS);
    const opened = await openBackupWithPassword(parsed, "135790");
    assert.equal(bytesEqual(await decryptChunked(opened.dekKey, parsed.items[0].encBytes), plain), true);
    await assert.rejects(() => openBackupWithPassword(parsed, "000000"));
    const fromAnswer = await unlockRecovery(parsed.header.recovery, "足够长的答案");
    assert.equal(bytesEqual(fromAnswer, dekBytes), true);
  });
});

describe("随机打开与界面伪装", () => {
  it("随机队列包含资料库里的全部文件且不重复", () => {
    const ids = ["a", "b", "c", "d"];
    const queue = nextShuffleQueue(ids, "a", () => 0);
    const list = queue.list;
    assert.equal(list.length, ids.length);
    assert.deepEqual([...list].sort(), [...ids].sort());
    assert.equal(new Set(list).size, ids.length);
  });

  it("名称是 gitbb，锁屏文案不再叫私密播放器", () => {
    const html = readRoot("index.html");
    const manifest = readRoot("manifest.webmanifest");
    const app = readRoot("js/app.js");
    const readme = readRoot("README.md");
    const sw = readRoot("sw.js");
    assert.match(html, /<title>gitbb<\/title>/);
    assert.match(manifest, /"name": "gitbb"/);
    assert.match(manifest, /"short_name": "gitbb"/);
    for (const file of [html, manifest, app, readme]) {
      assert.equal(file.includes("私密播放器"), false);
    }
    assert.match(sw, /gitbb-v5/);
    assert.doesNotMatch(readRoot("js/recovery.js"), /MIN_ANSWER_LENGTH|MAX_ANSWER_LENGTH|答案太短|答案太长/);
    assert.doesNotMatch(html, /id="secret-answer"[\s\S]*?maxlength/);
    assert.doesNotMatch(html, /id="secret-answer2"[\s\S]*?maxlength/);
    assert.doesNotMatch(html, /rel="icon"|apple-touch-icon|icons\//);
    assert.doesNotMatch(manifest, /"icons"/);
    assert.doesNotMatch(sw, /icons\//);
    assert.match(html, /id="gate-grid"/);
    assert.match(sw, /\/js\/pinflow\.js/);
    assert.match(sw, /\/js\/recovery\.js/);
    assert.match(app, /advanceGate/);
    assert.match(app, /countsAsPinAttempt/);
    assert.match(app, /notePinFailure/);
    assert.match(app, /unlockRecovery/);
    assert.match(app, /createRecoveryRecord/);
    assert.match(app, /PIN_FAILS_BEFORE_RECOVERY/);
    assert.match(readme, /60 万/);
    assert.match(readme, /已经保存成功/);
    assert.match(html, /已经保存成功/);
    assert.match(html, /解密导出/);
  });
});
