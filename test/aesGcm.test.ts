// Wire-format and correctness tests for the AES-256-GCM engine.
//
// The stored format is: base64(nonce[12]) + "." + base64(ct||tag[16]).
// The native implementation (react-native-quick-crypto) and the web
// implementation (@noble/ciphers) must produce and consume identical bytes, so
// data written by one always decrypts with the other. In this test suite
// react-native-quick-crypto is mocked with node:crypto (same API), so these
// tests exercise the REAL src/aesGcm.ts concat/split logic and wire format.
import { gcm } from "@noble/ciphers/aes.js";
import { encryptGcm, decryptGcm } from "../src/aesGcm";

const KEY = new Uint8Array(32).map((_, i) => (i * 7 + 3) % 256);

function nobleEncrypt(key: Uint8Array, plaintext: string): string {
  const nonce = new Uint8Array(12).map((_, i) => (i * 13 + 1) % 256);
  const ciphertext = gcm(key, nonce).encrypt(new TextEncoder().encode(plaintext));
  const b64 = (u: Uint8Array) => Buffer.from(u).toString("base64");
  return `${b64(nonce)}.${b64(ciphertext)}`;
}

function nobleDecrypt(key: Uint8Array, stored: string): string {
  const dot = stored.indexOf(".");
  const b64 = (s: string) => new Uint8Array(Buffer.from(s, "base64"));
  const nonce = b64(stored.slice(0, dot));
  const ciphertext = b64(stored.slice(dot + 1));
  return new TextDecoder().decode(gcm(key, nonce).decrypt(ciphertext));
}

describe("aesGcm wire-format compatibility", () => {
  const SAMPLES = [
    "hello",
    JSON.stringify({ id: "abc123", medicationId: "m1", date: "2026-07-07T08:00:00.000", status: "taken", dose: "2", doseUnit: "mg" }),
    "unicode: åäö 中文 emoji-free ✓".replace("✓", "check"),
    "",
  ];

  it("round-trips through the native implementation", () => {
    for (const s of SAMPLES) {
      expect(decryptGcm(KEY, encryptGcm(KEY, s))).toBe(s);
    }
  });

  it("decrypts data written by the @noble implementation (cross-implementation parity)", () => {
    for (const s of SAMPLES) {
      expect(decryptGcm(KEY, nobleEncrypt(KEY, s))).toBe(s);
    }
  });

  it("produces output the @noble implementation can decrypt (web parity)", () => {
    for (const s of SAMPLES) {
      expect(nobleDecrypt(KEY, encryptGcm(KEY, s))).toBe(s);
    }
  });

  it("rejects tampered ciphertext (auth tag verification)", () => {
    const stored = encryptGcm(KEY, "sensitive");
    const dot = stored.indexOf(".");
    const body = Buffer.from(stored.slice(dot + 1), "base64");
    body[0] ^= 0xff;
    const tampered = stored.slice(0, dot + 1) + body.toString("base64");
    expect(() => decryptGcm(KEY, tampered)).toThrow();
  });

  it("rejects decryption with the wrong key", () => {
    const otherKey = new Uint8Array(32).map((_, i) => (i * 11 + 5) % 256);
    const stored = encryptGcm(KEY, "sensitive");
    expect(() => decryptGcm(otherKey, stored)).toThrow();
  });
});
