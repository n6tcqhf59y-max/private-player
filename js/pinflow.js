/**
 * 六层文件夹路径的纯状态。
 * 每一层都是 0–9，走满六层才结算。中途不判断某一层对不对。
 */

export const PIN_LENGTH = 6;
export const PIN_FAILS_BEFORE_RECOVERY = 5;
export const PIN_DIGITS = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];

export function appendDigit(digits, digit) {
  const current = String(digits || "");
  const key = String(digit ?? "");
  if (!PIN_DIGITS.includes(key)) {
    throw new TypeError("只能进入 0 到 9 号文件夹");
  }
  if (current.length >= PIN_LENGTH) {
    return { digits: current, complete: true };
  }
  const next = current + key;
  return { digits: next, complete: next.length === PIN_LENGTH };
}

export function popDigit(digits) {
  return String(digits || "").slice(0, -1);
}

/**
 * 推进一层。
 * kind:
 * - browsing：还没走完六层
 * - submit-unlock：六层走完，可以拿整条路径去试着打开
 * - need-confirm：第一次走完，请再走一遍
 * - submit-new-pin：两次路径一致
 * - mismatch：两次不一致，整条作废，不指出哪一层不同
 */
export function advanceGate(state, digit) {
  const mode = state?.mode || "unlock";
  const first = state?.first || "";
  const step = appendDigit(state?.digits || "", digit);
  if (!step.complete) {
    return {
      mode,
      digits: step.digits,
      first,
      pin: null,
      notice: null,
      kind: "browsing",
    };
  }
  const pin = step.digits;
  if (mode === "unlock") {
    return {
      mode: "unlock",
      digits: pin,
      first: "",
      pin,
      notice: null,
      kind: "submit-unlock",
    };
  }
  if (mode.endsWith("-choose")) {
    return {
      mode: mode.replace("-choose", "-confirm"),
      digits: "",
      first: pin,
      pin: null,
      notice: null,
      kind: "need-confirm",
    };
  }
  if (mode.endsWith("-confirm")) {
    if (pin !== first) {
      return {
        mode: mode.replace("-confirm", "-choose"),
        digits: "",
        first: "",
        pin: null,
        notice: "mismatch",
        kind: "mismatch",
      };
    }
    return {
      mode,
      digits: pin,
      first,
      pin,
      notice: null,
      kind: "submit-new-pin",
    };
  }
  throw new TypeError("未知的文件夹状态");
}

export function retreatGate(state) {
  const mode = state?.mode || "unlock";
  const digits = String(state?.digits || "");
  const first = state?.first || "";
  if (digits) {
    return { mode, digits: popDigit(digits), first, atRoot: false, restarted: false };
  }
  if (mode.endsWith("-confirm")) {
    return {
      mode: mode.replace("-confirm", "-choose"),
      digits: "",
      first: "",
      atRoot: false,
      restarted: true,
    };
  }
  return { mode, digits: "", first, atRoot: true, restarted: false };
}

/** 只有完整走完六层并打开失败才计数。走到一半返回不计数。 */
export function countsAsPinAttempt(kind) {
  return kind === "submit-unlock";
}

export function notePinFailure(fails) {
  const next = (Number(fails) || 0) + 1;
  return {
    fails: next,
    showRecovery: next >= PIN_FAILS_BEFORE_RECOVERY,
  };
}

export function notePinSuccess() {
  return { fails: 0, showRecovery: false };
}
