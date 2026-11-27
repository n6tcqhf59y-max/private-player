/**
 * 可选的 WebAuthn PRF 解锁。
 * 只有在平台验证者真正能通过 PRF 派生密钥来包装 DEK 时才启用。
 * 绝不在“仅仅认证成功”后从磁盘读取明文密钥。
 */

import { bytesToBase64, base64ToBytes } from "./util.js";
import { wrapDEK, unwrapDEK, CryptoError } from "./crypto.js";

const RP_NAME = "gitbb";
const PRF_SALT_INFO = new TextEncoder().encode("private-player-prf-v1");

function subtle() {
  if (!globalThis.crypto?.subtle) {
    throw new CryptoError("当前不是安全上下文，无法使用加密接口。", "NO_SUBTLE");
  }
  return globalThis.crypto.subtle;
}

export async function isSecureAppContext() {
  return Boolean(window.isSecureContext && globalThis.crypto?.subtle);
}

/**
 * 返回 'yes' | 'no' | 'unknown'
 * yes：客户端明确声明支持 PRF
 * no：明确不支持或非安全上下文 / 无平台验证者
 * unknown：无法探测，只有在登记时拿到 PRF 输出才算成功
 */
export async function detectWebAuthnPrf() {
  if (!(await isSecureAppContext())) return "no";
  if (typeof PublicKeyCredential === "undefined") return "no";
  try {
    if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function") {
      const uvpa = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      if (!uvpa) return "no";
    }
    if (typeof PublicKeyCredential.getClientCapabilities === "function") {
      const caps = await PublicKeyCredential.getClientCapabilities();
      if (caps && typeof caps === "object") {
        if ("extension:prf" in caps) return caps["extension:prf"] ? "yes" : "no";
        if ("prf" in caps) return caps.prf ? "yes" : "no";
      }
    }
    return "unknown";
  } catch {
    return "no";
  }
}

async function prfOutputToKek(prfBytes) {
  const keyMaterial = await subtle().importKey("raw", prfBytes, "HKDF", false, ["deriveKey"]);
  return subtle().deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info: PRF_SALT_INFO,
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function getPrfResult(credential) {
  const ext = credential.getClientExtensionResults?.() || {};
  const results = ext.prf?.results;
  const first = results?.first;
  if (!first) return null;
  return first instanceof Uint8Array ? first : new Uint8Array(first);
}

export async function enrollWebAuthnPrf(dekBytes) {
  const support = await detectWebAuthnPrf();
  if (support === "no") {
    throw new CryptoError(
      "当前 Safari / 系统无法用面容 ID 通过安全方式打开，请继续使用六层路径。",
      "NO_PRF"
    );
  }
  const userId = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const prfSalt = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const challenge = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const credential = await navigator.credentials.create({
    publicKey: {
      rp: { name: RP_NAME, id: location.hostname },
      user: {
        id: userId,
        name: "local-owner",
        displayName: "本机用户",
      },
      challenge,
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      timeout: 120000,
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        userVerification: "required",
        residentKey: "required",
        requireResidentKey: true,
      },
      attestation: "none",
      extensions: {
        prf: { eval: { first: prfSalt } },
      },
    },
  });
  if (!credential) {
    throw new CryptoError("未能完成面容或系统验证。", "NO_CREDENTIAL");
  }
  let prf = getPrfResult(credential);
  if (!prf) {
    // 部分实现只在 get() 时返回 PRF，再立即做一次 get 验证
    prf = await evaluatePrf(credential.rawId, prfSalt);
  }
  if (!prf) {
    throw new CryptoError(
      "本次验证成功，但浏览器没有提供 PRF 密钥派生。为避免把密钥明文存放，已取消面容打开。请继续使用六层路径。",
      "NO_PRF"
    );
  }
  const kek = await prfOutputToKek(prf);
  prf.fill(0);
  const { iv, wrapped } = await wrapDEK(dekBytes, kek);
  return {
    version: 1,
    credentialId: bytesToBase64(new Uint8Array(credential.rawId)),
    userId: bytesToBase64(userId),
    prfSalt: bytesToBase64(prfSalt),
    wrapIV: bytesToBase64(iv),
    wrappedDEK: bytesToBase64(wrapped),
    createdAt: new Date().toISOString(),
  };
}

async function evaluatePrf(credentialId, prfSalt) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: globalThis.crypto.getRandomValues(new Uint8Array(32)),
      rpId: location.hostname,
      timeout: 120000,
      userVerification: "required",
      allowCredentials: [
        {
          type: "public-key",
          id: credentialId instanceof Uint8Array ? credentialId : new Uint8Array(credentialId),
          transports: ["internal"],
        },
      ],
      extensions: {
        prf: { eval: { first: prfSalt } },
      },
    },
  });
  if (!assertion) return null;
  return getPrfResult(assertion);
}

export async function unlockWithWebAuthnPrf(record) {
  if (!record?.credentialId || !record?.prfSalt || !record?.wrappedDEK || !record?.wrapIV) {
    throw new CryptoError("尚未登记可用的面容安全解锁。", "NO_PRF");
  }
  const credentialId = base64ToBytes(record.credentialId);
  const prfSalt = base64ToBytes(record.prfSalt);
  const prf = await evaluatePrf(credentialId, prfSalt);
  if (!prf) {
    throw new CryptoError(
      "面容或系统验证已完成，但没有得到可用的 PRF 密钥，无法安全打开。请使用六层路径。",
      "NO_PRF"
    );
  }
  try {
    const kek = await prfOutputToKek(prf);
    prf.fill(0);
    return await unwrapDEK(base64ToBytes(record.wrappedDEK), base64ToBytes(record.wrapIV), kek);
  } catch (err) {
    if (err instanceof CryptoError) throw err;
    throw new CryptoError("面容打开失败，请使用六层路径。", "PRF_UNLOCK_FAIL");
  }
}

export function describePrfSupport(flag) {
  if (flag === "yes") {
    return "当前浏览器可能支持用面容 ID 通过安全密钥派生解锁。登记成功后才会显示该入口。";
  }
  if (flag === "unknown") {
    return "无法事先确认面容 ID 是否能安全派生密钥。只有登记时真正拿到 PRF 才会启用。";
  }
  return "当前环境不能安全地用面容 ID 打开（加密根仍是六层路径或原来的口令）。";
}
