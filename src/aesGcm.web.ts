// SCOPE: Web is a DEVELOPMENT-ONLY target, not a supported security surface. No
// web build is published, and the security guarantees documented in ARCHITECTURE.md
// (Platform scope) apply to the NATIVE Android build only, browser storage is not
// hardware-backed and has a different threat model. Do not treat this file as
// inheriting the Android at-rest guarantees.
//
// Web: AES-256-GCM via @noble/ciphers (pure JS). This is the original
// implementation that native used too until 2026-07-07; on web there is no
// react-native-quick-crypto native module, browser JS engines JIT the pure-JS
// path acceptably, and web datasets go through the single-blob storage layer
// rather than per-row operations. Format is identical to utils/aesGcm.ts:
//   stored string = base64(nonce[12]) + "." + base64(ciphertext || authTag[16])
import * as Crypto from "expo-crypto";
import { gcm } from "@noble/ciphers/aes.js";

const NONCE_LEN = 12;

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

export function encryptGcm(key: Uint8Array, plaintext: string): string {
  const nonce = new Uint8Array(NONCE_LEN);
  Crypto.getRandomValues(nonce);
  const ciphertext = gcm(key, nonce).encrypt(new TextEncoder().encode(plaintext));
  return `${_u8ToB64(nonce)}.${_u8ToB64(ciphertext)}`;
}

export function decryptGcm(key: Uint8Array, stored: string): string {
  const dot = stored.indexOf(".");
  const nonce = _b64ToU8(stored.slice(0, dot));
  const ciphertext = _b64ToU8(stored.slice(dot + 1));
  const plaintext = gcm(key, nonce).decrypt(ciphertext);
  return new TextDecoder().decode(plaintext);
}
