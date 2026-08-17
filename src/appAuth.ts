import AsyncStorage from '@react-native-async-storage/async-storage';
import * as Crypto from 'expo-crypto';
import * as LocalAuthentication from 'expo-local-authentication';
import { pbkdf2Async } from '@noble/hashes/pbkdf2.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { storageGet, storageSet } from '../../utils/storage';

// ── Lock config keys, now routed to EncryptedStorage (registered in
// SECURE_KEYS) so they cannot be tampered with by editing a plain AsyncStorage
// file on a rooted device (e.g. flipping app_lock_enabled to "false" to skip
// the lock without knowing the PIN). readLockConfig() self-heals values left
// in legacy plain AsyncStorage by pre-2026-07 builds. ──────────────────────
export const LOCK_ENABLED_KEY = 'app_lock_enabled';
export const LOCK_TIMEOUT_KEY = 'app_lock_timeout_secs';
export const LOCK_METHOD_KEY = 'app_lock_method'; // "device" | "app_pin"

// Reads a lock-config value from EncryptedStorage, transparently migrating any
// value still sitting in legacy plain AsyncStorage. Done at read time (not via a
// startup migration) so there is no window where AppLockGate could read a
// not-yet-migrated key as null and treat the lock as disabled.
async function readLockConfig(key: string): Promise<string | null> {
  const secure = await storageGet(key);
  if (secure != null) return secure;
  const legacy = await AsyncStorage.getItem(key);
  if (legacy != null) {
    try { await storageSet(key, legacy); await AsyncStorage.removeItem(key); } catch { /* self-heal best-effort */ }
    return legacy;
  }
  return null;
}

// ── EncryptedStorage keys (routed via storageGet/storageSet) ───────────────
const PIN_KEY = 'app_pin';
const RECOVERY_KEY = 'app_recovery_code';

// ── Lock suppression for trusted system UI (SAF picker, share sheet) ──────
// Set to true before launching any system Activity that temporarily moves the
// app to background (file picker, share sheet). AppLockGate reads this and
// skips the re-lock check on the next foreground event. Always auto-clears.
export const lockSuppressedRef = { current: false };

// ── Timeout options ────────────────────────────────────────────────────────
export type TimeoutOption = {
  label: string;
  secs: number;
};

export const TIMEOUT_OPTIONS: TimeoutOption[] = [
  { label: 'Immediately', secs: 0 },
  { label: 'After 30 seconds', secs: 30 },
  { label: 'After 1 minute', secs: 60 },
  { label: 'After 5 minutes', secs: 300 },
  { label: 'After 15 minutes', secs: 900 },
];

// ── Preferences ────────────────────────────────────────────────────────────
export async function getLockEnabled(): Promise<boolean> {
  return (await readLockConfig(LOCK_ENABLED_KEY)) === 'true';
}

export async function setLockEnabled(enabled: boolean): Promise<void> {
  await storageSet(LOCK_ENABLED_KEY, enabled ? 'true' : 'false');
}

export async function getLockTimeoutSecs(): Promise<number> {
  const raw = await readLockConfig(LOCK_TIMEOUT_KEY);
  return raw != null ? parseInt(raw, 10) : 0;
}

export async function setLockTimeoutSecs(secs: number): Promise<void> {
  await storageSet(LOCK_TIMEOUT_KEY, String(secs));
}

export async function getLockMethod(): Promise<'device' | 'app_pin'> {
  const raw = await readLockConfig(LOCK_METHOD_KEY);
  return raw === 'app_pin' ? 'app_pin' : 'device';
}

export async function setLockMethod(method: 'device' | 'app_pin'): Promise<void> {
  await storageSet(LOCK_METHOD_KEY, method);
}

// ── PIN lockout state (persisted) ──────────────────────────────────────────
// failCount + lockoutUntil live in EncryptedStorage, NOT just React state, so
// force-killing and relaunching the app cannot reset the brute-force counter
// (the classic "try 4, kill, repeat" bypass). Encrypted so it also can't be
// edited away on a rooted device.
export const LOCKOUT_STATE_KEY = 'app_lock_lockout';

export async function getLockoutState(): Promise<{ failCount: number; lockoutUntil: number | null }> {
  const raw = await storageGet(LOCKOUT_STATE_KEY);
  if (!raw) return { failCount: 0, lockoutUntil: null };
  try {
    const p = JSON.parse(raw);
    return {
      failCount: typeof p.failCount === 'number' ? p.failCount : 0,
      lockoutUntil: typeof p.lockoutUntil === 'number' ? p.lockoutUntil : null,
    };
  } catch { return { failCount: 0, lockoutUntil: null }; }
}

export async function saveLockoutState(failCount: number, lockoutUntil: number | null): Promise<void> {
  try { await storageSet(LOCKOUT_STATE_KEY, JSON.stringify({ failCount, lockoutUntil })); } catch { /* best-effort */ }
}

// ── PIN hashing (PBKDF2-SHA256) ──────────────────────────────────────────────
// Stored format v2: JSON { v: 2, c: <iterations>, salt: "<base64>", hash: "<base64>" }
// c is stored alongside the hash so changing PIN_ITERATIONS never breaks existing hashes.
// Legacy format (no c field): treated as 100_000 iterations (original value).
// Legacy format: raw digit string (migrated transparently on first successful login)

// 10k iterations, defense-in-depth on top of hardware-backed EncryptedStorage.
// Full 100k is not justified when Android Keystore / iOS Keychain is the primary boundary.
const PIN_ITERATIONS = 10_000;
// Recovery code is a 20-char string from a 32-char alphabet (~10^30 possible values),
// orders of magnitude more entropy than a 6-digit PIN (~10^6). At that keyspace, heavy
// KDF stretching adds negligible real brute-force resistance, but costs the same JS-thread
// CPU time as the PIN hash. Lower iterations here cuts perceived setup delay roughly in
// half without weakening the PIN's own protection (verifyPin/verifyRecoveryCode read the
// iteration count from the stored record, so this is safe to tune independently).
const RECOVERY_ITERATIONS = 1_000;
const PIN_HASH_LEN = 32;

function _u8ToB64(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
function _b64ToU8(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

async function _hashPin(pin: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const enc = new TextEncoder();
  return pbkdf2Async(sha256, enc.encode(pin), salt, {
    c: iterations,
    dkLen: PIN_HASH_LEN,
  });
}

// ── PIN (stored in EncryptedStorage via storageGet/storageSet) ─────────────
export async function savePin(pin: string): Promise<void> {
  const salt = new Uint8Array(16);
  Crypto.getRandomValues(salt);
  const hash = await _hashPin(pin, salt, PIN_ITERATIONS);
  await storageSet(PIN_KEY, JSON.stringify({ v: 2, c: PIN_ITERATIONS, salt: _u8ToB64(salt), hash: _u8ToB64(hash) }));
}

export async function clearPin(): Promise<void> {
  await storageSet(PIN_KEY, '');
}

export async function verifyPin(input: string): Promise<boolean> {
  const stored = await storageGet(PIN_KEY);
  if (!stored || stored.length === 0) return false;

  try {
    const parsed = JSON.parse(stored);
    if (parsed?.v === 2) {
      const salt = _b64ToU8(parsed.salt);
      const expected = _b64ToU8(parsed.hash);
      // Use stored iteration count so old hashes remain verifiable after PIN_ITERATIONS changes.
      const iterations = typeof parsed.c === 'number' ? parsed.c : 100_000;
      const actual = await _hashPin(input, salt, iterations);
      if (actual.length !== expected.length) return false;
      let diff = 0;
      for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
      return diff === 0;
    }
  } catch { /* fall through to legacy check */ }

  // Legacy: plaintext PIN, verify, then transparently migrate to hashed format
  if (stored === input) {
    await savePin(input).catch(() => {});
    return true;
  }
  return false;
}

// ── Recovery code ──────────────────────────────────────────────────────────
// Format: XXXXX-XXXXX-XXXXX-XXXXX (20 alphanum chars in 4 groups of 5)
// Stored as PBKDF2-SHA256 hash (same scheme as PIN), plaintext never at rest.
const CHARSET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no I/O/1/0 to avoid confusion

function _normaliseCode(code: string): string {
  return code.trim().toUpperCase().replace(/-/g, '');
}

export async function generateAndSaveRecoveryCode(): Promise<string> {
  const bytes = new Uint8Array(20);
  Crypto.getRandomValues(bytes);
  const raw = Array.from(bytes)
    .map(b => CHARSET[b % CHARSET.length])
    .join('');
  const code = `${raw.slice(0, 5)}-${raw.slice(5, 10)}-${raw.slice(10, 15)}-${raw.slice(15, 20)}`;
  const salt = new Uint8Array(16);
  Crypto.getRandomValues(salt);
  const hash = await _hashPin(_normaliseCode(code), salt, RECOVERY_ITERATIONS);
  await storageSet(RECOVERY_KEY, JSON.stringify({ v: 2, c: RECOVERY_ITERATIONS, salt: _u8ToB64(salt), hash: _u8ToB64(hash) }));
  return code;
}

export async function verifyRecoveryCode(input: string): Promise<boolean> {
  const stored = await storageGet(RECOVERY_KEY);
  if (!stored) return false;
  try {
    const parsed = JSON.parse(stored);
    if (parsed?.v === 2) {
      const salt = _b64ToU8(parsed.salt);
      const expected = _b64ToU8(parsed.hash);
      const iterations = typeof parsed.c === 'number' ? parsed.c : 100_000;
      const actual = await _hashPin(_normaliseCode(input), salt, iterations);
      if (actual.length !== expected.length) return false;
      let diff = 0;
      for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
      return diff === 0;
    }
  } catch { /* fall through to legacy */ }
  // Legacy: plaintext code, verify then transparently migrate to hashed format
  if (_normaliseCode(stored) === _normaliseCode(input)) {
    const salt = new Uint8Array(16);
    Crypto.getRandomValues(salt);
    const hash = await _hashPin(_normaliseCode(stored), salt, RECOVERY_ITERATIONS);
    await storageSet(RECOVERY_KEY, JSON.stringify({ v: 2, c: RECOVERY_ITERATIONS, salt: _u8ToB64(salt), hash: _u8ToB64(hash) })).catch(() => {});
    return true;
  }
  return false;
}

export async function clearRecoveryCode(): Promise<void> {
  await storageSet(RECOVERY_KEY, '');
}

// ── Device auth capability ─────────────────────────────────────────────────
export type DeviceAuthLevel = 'none' | 'pin_only' | 'biometric';

export async function getDeviceAuthLevel(): Promise<DeviceAuthLevel> {
  try {
    // isEnrolledAsync is the most reliable biometric check across Android versions
    const isEnrolled = await LocalAuthentication.isEnrolledAsync();
    if (isEnrolled) return 'biometric';

    // Numeric comparison avoids enum value mismatches on some Samsung/Android builds
    const level = await LocalAuthentication.getEnrolledLevelAsync();
    if ((level as number) >= 1) return 'pin_only';

    return 'none';
  } catch {
    // If detection itself throws, assume device has security rather than
    // incorrectly prompting the user to set up an app PIN.
    return 'pin_only';
  }
}

// ── Authenticate via device (biometrics + PIN fallback) ───────────────────
export async function authenticateWithDevice(reason: string): Promise<boolean> {
  try {
    const result = await LocalAuthentication.authenticateAsync({
      promptMessage: reason,
      disableDeviceFallback: false,
      cancelLabel: 'Cancel',
      requireConfirmation: false,
    });
    return result.success;
  } catch {
    return false;
  }
}

// ── Full disable (clear all auth data) ────────────────────────────────────
export async function disableAppLock(): Promise<void> {
  await Promise.all([
    setLockEnabled(false),
    clearPin(),
    clearRecoveryCode(),
    setLockTimeoutSecs(0),
    setLockMethod('device'),
    // Remove any legacy plain copies too (pre-migration installs).
    AsyncStorage.removeItem(LOCK_TIMEOUT_KEY),
    AsyncStorage.removeItem(LOCK_METHOD_KEY),
    AsyncStorage.removeItem(LOCK_ENABLED_KEY),
  ]);
}
