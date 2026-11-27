/**
 * 用用户自己写的问题答案再包一层 DEK。
 * KDF 与路径相同：PBKDF2-SHA-256，默认迭代次数不降低。
 * 答案不明文保存。问题需要在忘记路径后显示，因此只保存问题原文。
 */

import { bytesToBase64, base64ToBytes } from "./util.js";
import {
  CryptoError,
  DEK_BYTES,
  PBKDF2_ITERATIONS,
  SALT_BYTES,
  deriveKEK,
  unwrapDEK,
  wrapDEK,
} from "./crypto.js";

export const MIN_ANSWER_LENGTH = 4;
export const MAX_ANSWER_LENGTH = 200;
export const MIN_QUESTION_LENGTH = 2;
export const MAX_QUESTION_LENGTH = 80;
export const RECOVERY_FAILS_PER_LOCK = 5;
export const RECOVERY_LOCK_STEPS_MS = [
  60 * 1000,
  5 * 60 * 1000,
  15 * 60 * 1000,
  60 * 60 * 1000,
  6 * 60 * 60 * 1000,
  24 * 60 * 60 * 1000,
];

function randomBytes(length) {
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}

function charLength(value) {
  return [...value].length;
}

/**
 * 比对前的归一化：NFC、去掉首尾空格、去掉零宽字符。
 * 不改动中间的空格，避免把用户故意留下的间隔弄丢。
 */
export function normalizeAnswer(value) {
  return String(value ?? "")
    .normalize("NFC")
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .trim();
}

export function normalizeQuestion(value) {
  return String(value ?? "")
    .normalize("NFC")
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .trim();
}

export function assertAnswer(value) {
  const answer = normalizeAnswer(value);
  if (!answer) throw new CryptoError("请填写答案。", "EMPTY_ANSWER");
  const length = charLength(answer);
  if (length < MIN_ANSWER_LENGTH) {
    throw new CryptoError("答案太短。请换一个只有你知道、更长一些的答案。", "SHORT_ANSWER");
  }
  if (length > MAX_ANSWER_LENGTH) {
    throw new CryptoError("答案太长。", "LONG_ANSWER");
  }
  return answer;
}

export function assertQuestion(value) {
  const question = normalizeQuestion(value);
  const length = charLength(question);
  if (length < MIN_QUESTION_LENGTH) {
    throw new CryptoError("请写下只有你能回答的问题。", "EMPTY_QUESTION");
  }
  if (length > MAX_QUESTION_LENGTH) {
    throw new CryptoError("问题太长。", "LONG_QUESTION");
  }
  return question;
}

export async function createRecoveryRecord(question, answer, dekBytes, options = {}) {
  if (!(dekBytes instanceof Uint8Array) || dekBytes.length !== DEK_BYTES) {
    throw new CryptoError("DEK 长度无效。", "BAD_DEK");
  }
  const q = assertQuestion(question);
  const ans = assertAnswer(answer);
  const iterations = options.iterations ?? PBKDF2_ITERATIONS;
  const salt = options.salt ?? randomBytes(SALT_BYTES);
  const kek = await deriveKEK(ans, salt, iterations);
  const { iv, wrapped } = await wrapDEK(dekBytes, kek);
  return {
    version: 1,
    kdf: "PBKDF2-SHA-256",
    iterations,
    salt: bytesToBase64(salt),
    wrapIV: bytesToBase64(iv),
    wrappedDEK: bytesToBase64(wrapped),
    question: q,
  };
}

/**
 * 答案正确则返回 DEK。错误答案不会返回任何密钥。
 * 这里不做最短长度检查，避免用不同的报错暴露答案规则。
 */
export async function unlockRecovery(record, answer) {
  if (!record || record.kdf !== "PBKDF2-SHA-256" || !record.question) {
    throw new CryptoError("还没有设置找回问题。", "BAD_RECOVERY");
  }
  const ans = normalizeAnswer(answer);
  if (!ans) throw new CryptoError("请填写答案。", "EMPTY_ANSWER");
  const salt = base64ToBytes(record.salt);
  const kek = await deriveKEK(ans, salt, record.iterations);
  const dekBytes = await unwrapDEK(
    base64ToBytes(record.wrappedDEK),
    base64ToBytes(record.wrapIV),
    kek
  );
  if (dekBytes.length !== DEK_BYTES) {
    throw new CryptoError("密钥数据已损坏。", "BAD_RECOVERY");
  }
  return dekBytes;
}

export function assessRecoveryGuard(guard, now) {
  const fails = Number(guard?.fails) || 0;
  const lockedUntil = Number(guard?.lockedUntil) || 0;
  if (lockedUntil > now) {
    return { allowed: false, fails, retryAt: lockedUntil };
  }
  return { allowed: true, fails, retryAt: 0 };
}

export function registerRecoveryFailure(guard, now) {
  const fails = (Number(guard?.fails) || 0) + 1;
  let lockedUntil = 0;
  if (fails % RECOVERY_FAILS_PER_LOCK === 0) {
    const step = Math.floor(fails / RECOVERY_FAILS_PER_LOCK) - 1;
    const wait = RECOVERY_LOCK_STEPS_MS[Math.min(step, RECOVERY_LOCK_STEPS_MS.length - 1)];
    lockedUntil = now + wait;
  }
  return { fails, lockedUntil };
}

export function clearRecoveryGuard() {
  return { fails: 0, lockedUntil: 0 };
}
