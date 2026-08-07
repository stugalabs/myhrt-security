// Native (Android / iOS) — dose_logs storage backed by expo-sqlite instead of
// expo-secure-store's SharedPreferences-on-Android backend.
//
// Why: SharedPreferences (what expo-secure-store uses on Android) loads its entire
// backing file into memory on every access and rewrites it whole on every commit.
// Android's own guidance is to never use it for data that grows large. Splitting
// dose_logs into year-partitions (the previous approach) only split the *logical
// keys* — on Android those keys can still live inside the same physical preferences
// file, so a multi-year retroactive backfill kept getting slower as that file grew,
// freezing the UI thread and occasionally crashing on lower-end devices.
//
// SQLite is built for exactly this: datasets that grow over years, with proper
// per-row transactional writes instead of whole-file rewrites. Each row's full
// content is still encrypted (AES-256-GCM) before it touches disk — the only
// plaintext column is `id`, a random opaque token carrying no health information,
// kept in the clear purely so it can be a primary key for point lookups/updates.
// The encryption key itself is generated once and stored in expo-secure-store
// (Android Keystore / iOS Keychain) — a single small fixed-size value, exactly
// what SecureStore is good at. This keeps the privacy policy's encryption claim
// accurate: the key lives in the device's secure key store (hardware-backed
// where the device supports it), and only ciphertext ever lands in SQLite.
import * as SQLite from "expo-sqlite";
import * as Crypto from "expo-crypto";
// Metro resolves aesGcm.ts (react-native-quick-crypto, hardware AES) on native
// and aesGcm.web.ts (@noble pure-JS) on web — same wire format either way.
import { encryptGcm, decryptGcm } from "./aesGcm";
import SecureStorage from "./secureStorage";
import type { DoseLog } from "./doseLogTypes";

const DB_NAME = "myhrt_dose_logs.db";
const DB_KEY_STORAGE_KEY = "dose_logs_db_key";

// ==================== KEY MANAGEMENT ====================

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

let _keyPromise: Promise<Uint8Array> | null = null;

async function _getOrCreateKey(): Promise<Uint8Array> {
  const existing = await SecureStorage.getItem(DB_KEY_STORAGE_KEY);
  if (existing) return _b64ToU8(existing);
  const key = new Uint8Array(32); // AES-256
  Crypto.getRandomValues(key);
  await SecureStorage.setItem(DB_KEY_STORAGE_KEY, _u8ToB64(key));
  return key;
}

function _getKey(): Promise<Uint8Array> {
  if (!_keyPromise) _keyPromise = _getOrCreateKey();
  return _keyPromise;
}

/**
 * Exposes the same device-bound AES-256 key used for dose_logs encryption, for
 * reuse by utils/localBackup.ts. Deliberately the same key rather than a second
 * one — both protect equivalent-sensitivity data on the same device, and one
 * fewer secret in Keystore/Keychain is one fewer thing that can go missing.
 */
export function getDoseLogsEncryptionKey(): Promise<Uint8Array> {
  return _getKey();
}

// ==================== ENCRYPTION ====================
// Delegated to utils/aesGcm (native: react-native-quick-crypto, hardware AES;
// web: @noble pure-JS). Same wire format as the original inline implementation:
// base64(nonce).base64(ciphertext||tag). Local aliases keep the rest of this
// file reading unchanged.

const _encrypt = encryptGcm;
const _decrypt = decryptGcm;

// ==================== DATABASE ====================

let _dbPromise: Promise<SQLite.SQLiteDatabase> | null = null;

function _getDb(): Promise<SQLite.SQLiteDatabase> {
  if (!_dbPromise) {
    _dbPromise = (async () => {
      const db = await SQLite.openDatabaseAsync(DB_NAME);
      // secure_delete=FAST zeros freed pages when SQLite is already rewriting them,
      // so deleted ciphertext and opaque ids aren't left carveable in the db file or
      // its WAL. Measured negligible on a Samsung A41 (a 9.8k-row delete ran in ~0.5s
      // with it on, once the delete was batched — see dbDeleteDoseLogsForMedication),
      // so it's kept as free defense-in-depth.
      await db.execAsync("PRAGMA secure_delete = FAST;");
      await db.execAsync(
        "CREATE TABLE IF NOT EXISTS dose_logs (id TEXT PRIMARY KEY NOT NULL, payload TEXT NOT NULL)"
      );
      return db;
    })();
  }
  return _dbPromise;
}

function _rowToLog(key: Uint8Array, payload: string): DoseLog | null {
  try {
    return JSON.parse(_decrypt(key, payload)) as DoseLog;
  } catch {
    return null; // skip a corrupted row rather than failing the whole read
  }
}

// ==================== SERIALIZATION ====================
//
// expo-sqlite's single connection does not support overlapping transactions —
// calling withTransactionAsync while another is still in flight on the same
// connection throws "cannot start a transaction within a transaction". Multiple
// independent call sites write dose logs (medication-setup's retroactive backfill,
// Home's auto-miss backfill, log-dose, edit modal, ...) and nothing guarantees
// they run sequentially relative to each other. Every exported function in this
// module is routed through this single in-process queue so calls always run one
// at a time regardless of caller discipline — mirrors utils/storage.ts's
// withLogLock, but scoped here so it's impossible to forget at a call site.
let _dbQueue: Promise<unknown> = Promise.resolve();
function _withDbLock<T>(fn: () => Promise<T>): Promise<T> {
  const next = _dbQueue.then(fn, fn);
  _dbQueue = next.catch(() => undefined);
  return next;
}

// Yields control back to the JS event loop between insert chunks during a large
// bulk insert/replace, so a multi-decade backfill doesn't run as one unbroken
// synchronous-feeling stretch.
function _yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

// ==================== IN-MEMORY CACHE ====================
//
// Every field except `id` is encrypted, so there's no plaintext column to filter
// or window a query by — any read of "the logs" must decrypt every row. Without
// caching, Home re-pays that full-table decrypt cost on every focus/foreground,
// which gets slower the longer someone uses the app (or after a large retroactive
// backfill). This cache decrypts the whole table once per app session and keeps
// itself in sync on every write below — never written to disk, so it doesn't
// change what's encrypted at rest, only how often the same ciphertext gets
// decrypted in memory during one running session. Cleared on cold start.
let _cache: Map<string, DoseLog> | null = null;

/**
 * Clears the module-level encryption key cache so the next call to _getKey()
 * fetches (or generates) a fresh key from SecureStore. Must be called from
 * clearAllData() after the old key is deleted — without this, a user who
 * re-onboards in the same session would encrypt new dose rows with the deleted
 * key, causing silent decryption failures on the next cold start.
 */
export function resetDoseLogsKeyCache(): void {
  _keyPromise = null;
}

/** Test-only: this module is loaded once per test file, so the cache otherwise
 * leaks state between test cases. Call from beforeEach alongside resetting the
 * mock SQLite store. No-op effect in production — nothing calls this there. */
export function __resetDoseLogsCacheForTests(): void {
  _cache = null;
}

function _cacheGetAll(): DoseLog[] {
  return Array.from((_cache as Map<string, DoseLog>).values());
}

// ==================== PUBLIC API ====================

// Rows decrypted per tick before yielding to the event loop. The first
// dbGetAllDoseLogs() call each app session decrypts the entire table — for a
// multi-year history that's thousands of pure-JS AES-GCM operations. This call
// happens at cold start (refreshWidgets in _layout.tsx's startup sequence), the
// exact moment the app-lock screen is shown — an unyielded loop here blocks the
// JS thread long enough to delay PIN verification or the device-auth trigger.
const DECRYPT_YIELD_EVERY_N_ROWS = 200;

export async function dbGetAllDoseLogs(): Promise<DoseLog[]> {
  return _withDbLock(async () => {
    if (_cache) return _cacheGetAll();
    const db = await _getDb();
    const key = await _getKey();
    const rows = await db.getAllAsync<{ payload: string }>("SELECT payload FROM dose_logs");
    const map = new Map<string, DoseLog>();
    for (let i = 0; i < rows.length; i++) {
      const log = _rowToLog(key, rows[i].payload);
      if (log) map.set(log.id, log);
      if (i > 0 && i % DECRYPT_YIELD_EVERY_N_ROWS === 0) await _yieldToEventLoop();
    }
    _cache = map;
    return _cacheGetAll();
  });
}

// Rows packed into one multi-row INSERT per native call. A prepared statement
// reused per-row still costs one JS<->native bridge round-trip per row — at tens
// of thousands of rows (a multi-decade backfill) that overhead alone is minutes,
// regardless of how the SQL itself is compiled. Packing many rows into a single
// "INSERT ... VALUES (?,?),(?,?),..." statement cuts the round-trip count by this
// factor. 100 rows (200 bound params) matches published SQLite bulk-insert
// benchmarks showing diminishing/negative returns past ~100 rows per statement —
// comfortably under SQLite's bound-parameter limit either way (999 on older
// builds, 32766 on current ones).
const ROWS_PER_INSERT_STATEMENT = 100;
const IDS_PER_DELETE_STATEMENT = 500; // batch id-list deletes so a large per-med delete isn't thousands of single-row round-trips

/**
 * Inserts rows in chunks of ROWS_PER_INSERT_STATEMENT, each as one multi-row
 * INSERT statement, yielding to the event loop between chunks so a large batch
 * doesn't run as one unbroken stretch.
 */
async function _insertRows(db: SQLite.SQLiteDatabase, key: Uint8Array, logs: DoseLog[]): Promise<void> {
  for (let i = 0; i < logs.length; i += ROWS_PER_INSERT_STATEMENT) {
    const chunk = logs.slice(i, i + ROWS_PER_INSERT_STATEMENT);
    const placeholders = chunk.map(() => "(?, ?)").join(", ");
    const params: string[] = [];
    for (const log of chunk) {
      params.push(log.id, _encrypt(key, JSON.stringify(log)));
    }
    await db.runAsync(`INSERT INTO dose_logs (id, payload) VALUES ${placeholders}`, ...params);
    await _yieldToEventLoop();
  }
}

/** Insert new rows. Caller guarantees these ids don't already exist. */
export async function dbInsertDoseLogs(logs: DoseLog[]): Promise<void> {
  if (logs.length === 0) return;
  await _withDbLock(async () => {
    const db = await _getDb();
    const key = await _getKey();
    await db.withTransactionAsync(async () => {
      await _insertRows(db, key, logs);
    });
    if (_cache) for (const log of logs) _cache.set(log.id, log);
  });
}

function _logsEqual(a: DoseLog, b: DoseLog): boolean {
  return (
    a.medicationId === b.medicationId &&
    a.date === b.date &&
    a.time === b.time &&
    a.status === b.status &&
    a.dose === b.dose &&
    a.doseUnit === b.doseUnit &&
    a.notes === b.notes &&
    a.site === b.site &&
    a.siteLabel === b.siteLabel &&
    a.source === b.source
  );
}

/**
 * Semantically replaces the full dataset, but diffs against the current state
 * and only touches rows that actually changed. hooks/useDoseLogger.ts calls this
 * with "the full allLogs array, mutated by one entry" for every single toggle/
 * edit/delete action on Home — without diffing, every tap would unconditionally
 * delete and re-insert the entire multi-year table.
 */
export async function dbReplaceAllDoseLogs(logs: DoseLog[]): Promise<void> {
  await _withDbLock(async () => {
    const db = await _getDb();
    const key = await _getKey();

    let previous: Map<string, DoseLog>;
    if (_cache) {
      previous = _cache;
    } else {
      const rows = await db.getAllAsync<{ payload: string }>("SELECT payload FROM dose_logs");
      previous = new Map();
      for (const row of rows) {
        const log = _rowToLog(key, row.payload);
        if (log) previous.set(log.id, log);
      }
    }

    const nextIds = new Set(logs.map((l) => l.id));
    const toInsert: DoseLog[] = [];
    const toUpdate: DoseLog[] = [];
    for (const log of logs) {
      const prev = previous.get(log.id);
      if (!prev) toInsert.push(log);
      else if (!_logsEqual(prev, log)) toUpdate.push(log);
    }
    const toDeleteIds: string[] = [];
    for (const id of previous.keys()) {
      if (!nextIds.has(id)) toDeleteIds.push(id);
    }

    // Circuit breaker: dbReplaceAllDoseLogs is meant for small, targeted edits
    // (moving/editing a handful of logs) or one-time schema migrations that
    // preserve every existing id. It should never legitimately delete a majority
    // of existing rows — a caller passing a stale or incomplete array (e.g. a
    // read that raced with a huge concurrent backfill) would otherwise silently
    // wipe real history. Genuine full wipes must go through dbDeleteAllDoseLogs()
    // instead, which is explicit and only reachable from "Clear all data".
    //
    // The absolute floor is on toDeleteIds.length, not previous.size — every
    // legitimate call site here only ever touches a handful of logs for one
    // medication on one day (at most a few multi-dose slots), never double
    // digits in one call. A previous version gated this on previous.size > 50,
    // which meant any account with 50 or fewer total dose logs — exactly a
    // freshly-tested account — had zero protection from this breaker at all,
    // regardless of what percentage a stale-array call would wipe.
    if (toDeleteIds.length >= 10 && toDeleteIds.length / previous.size > 0.5) {
      throw new Error(
        `dbReplaceAllDoseLogs refused: would delete ${toDeleteIds.length} of ${previous.size} existing dose logs in one call. ` +
        `This looks like a stale/incomplete array was passed in, not an intentional edit.`
      );
    }

    if (toInsert.length > 0 || toUpdate.length > 0 || toDeleteIds.length > 0) {
      await db.withTransactionAsync(async () => {
        if (toInsert.length > 0) await _insertRows(db, key, toInsert);
        for (const log of toUpdate) {
          await db.runAsync("UPDATE dose_logs SET payload = ? WHERE id = ?", _encrypt(key, JSON.stringify(log)), log.id);
        }
        for (const id of toDeleteIds) {
          await db.runAsync("DELETE FROM dose_logs WHERE id = ?", id);
        }
      });
    }

    _cache = new Map(logs.map((l) => [l.id, l]));
  });
}

/** Returns true if a row with this id existed and was updated. */
export async function dbUpdateDoseLog(id: string, updates: Partial<DoseLog>): Promise<boolean> {
  return _withDbLock(async () => {
    const db = await _getDb();
    const key = await _getKey();
    let existing = _cache?.get(id);
    if (!existing) {
      const row = await db.getFirstAsync<{ payload: string }>("SELECT payload FROM dose_logs WHERE id = ?", id);
      if (!row) return false;
      const decoded = _rowToLog(key, row.payload);
      if (!decoded) return false;
      existing = decoded;
    }
    const updated = { ...existing, ...updates };
    await db.runAsync("UPDATE dose_logs SET payload = ? WHERE id = ?", _encrypt(key, JSON.stringify(updated)), id);
    if (_cache) _cache.set(id, updated);
    return true;
  });
}

export async function dbDeleteDoseLog(id: string): Promise<void> {
  await _withDbLock(async () => {
    const db = await _getDb();
    await db.runAsync("DELETE FROM dose_logs WHERE id = ?", id);
    _cache?.delete(id);
  });
}

/**
 * medicationId isn't a plaintext column (every field except id is encrypted),
 * so this decrypts every row to find matches (unless already cached). Deleting a
 * medication's history is rare and user-initiated, not part of any hot path, so a
 * full scan is acceptable.
 */
export async function dbDeleteDoseLogsForMedication(medId: string): Promise<void> {
  await _withDbLock(async () => {
    const db = await _getDb();
    const idsToDelete: string[] = [];
    if (_cache) {
      for (const log of _cache.values()) {
        if (log.medicationId === medId) idsToDelete.push(log.id);
      }
    } else {
      const key = await _getKey();
      const rows = await db.getAllAsync<{ id: string; payload: string }>("SELECT id, payload FROM dose_logs");
      for (const row of rows) {
        const log = _rowToLog(key, row.payload);
        if (log && log.medicationId === medId) idsToDelete.push(row.id);
      }
    }
    if (idsToDelete.length === 0) return;
    await db.withTransactionAsync(async () => {
      for (let i = 0; i < idsToDelete.length; i += IDS_PER_DELETE_STATEMENT) {
        const chunk = idsToDelete.slice(i, i + IDS_PER_DELETE_STATEMENT);
        const placeholders = chunk.map(() => "?").join(",");
        await db.runAsync(`DELETE FROM dose_logs WHERE id IN (${placeholders})`, ...chunk);
      }
    });
    if (_cache) for (const id of idsToDelete) _cache.delete(id);
  });
}

export async function dbDeleteAllDoseLogs(): Promise<void> {
  await _withDbLock(async () => {
    const db = await _getDb();
    await db.execAsync("DELETE FROM dose_logs");
    _cache = new Map();
  });
}
