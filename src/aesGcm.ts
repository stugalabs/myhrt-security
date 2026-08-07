// Native (Android / iOS) — AES-256-GCM via react-native-quick-crypto (C++/JSI,
// hardware-accelerated through OpenSSL). Replaces the previous pure-JS @noble
// implementation for dose logs and local backups: @noble is correct but runs
// interpreted under Hermes, and at multi-decade history scale (tens of thousands
// of per-row operations) that measured 20-40+ seconds of frozen UI on a low-end
// device (Samsung A41) for a cold-start full-table decrypt, ~30 s for a backfill
// write, and a saturated JS thread — tester-reported 2026-07-06/07.
//
// WIRE-COMPATIBLE with the @noble format — this is a hard requirement, existing
// installs must keep decrypting their data:
//   stored string = base64(nonce[12]) + "." + base64(ciphertext || authTag[16])
// @noble's gcm(key, nonce).encrypt() returns ciphertext||tag in one buffer;
// Node-style GCM keeps them separate (getAuthTag/setAuthTag), so we concatenate
// on encrypt and split the last 16 bytes on decrypt. Covered by a cross-
// implementation round-trip test in __tests__/aesGcm.test.ts.
//
// Nonces still come from expo-crypto's getRandomValues — NOT globalThis.crypto
// (crashes on some MediaTek devices, e.g. Samsung A41) and not quick-crypto's
// RNG, purely to keep the proven RNG path unchanged.
//
// Metro resolves aesGcm.web.ts (@noble, unchanged behaviour) on web, where
// quick-crypto's native module does not exist.
import * as Crypto from "expo-crypto";
import { Buffer as CryptoBuffer, createCipheriv, createDecipheriv } from "react-native-quick-crypto";

const NONCE_LEN = 12;
const TAG_LEN = 16;

function _u8ToB64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
function _b64ToU8(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function _concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

export function encryptGcm(key: Uint8Array, plaintext: string): string {
  const nonce = new Uint8Array(NONCE_LEN);
  Crypto.getRandomValues(nonce);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const body = _concat(
    new Uint8Array(cipher.update(new TextEncoder().encode(plaintext))),
    new Uint8Array(cipher.final())
  );
  const tag = new Uint8Array(cipher.getAuthTag());
  return `${_u8ToB64(nonce)}.${_u8ToB64(_concat(body, tag))}`;
}

export function decryptGcm(key: Uint8Array, stored: string): string {
  const dot = stored.indexOf(".");
  const nonce = _b64ToU8(stored.slice(0, dot));
  const combined = _b64ToU8(stored.slice(dot + 1));
  const body = combined.subarray(0, combined.length - TAG_LEN);
  const tag = combined.subarray(combined.length - TAG_LEN);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(CryptoBuffer.from(tag));
  const plaintext = _concat(
    new Uint8Array(decipher.update(body)),
    new Uint8Array(decipher.final())
  );
  return new TextDecoder().decode(plaintext);
}
