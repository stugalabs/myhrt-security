// Automatic local backup of all health data — a last-resort safety net in case
// a future bug (anywhere in the app) causes data loss, independent of any
// specific storage layer. Runs at most once per calendar day, fire-and-forget,
// and must never throw or block app startup. Restore is a separate, explicit,
// user-confirmed action — never triggered automatically.
//
// Snapshot reuses loadAllUserData() (also used by the manual JSON export) so
// it stays in sync with whatever data domains the app tracks, rather than
// duplicating a second "everything" list that could drift out of date.
//
// Encrypted with the same device-bound AES-256-GCM key already used for
// dose_logs (utils/doseLogsDb.ts) — no user password, since this backup is
// automatic and silent. The key never leaves SecureStore (Android Keystore /
// iOS Keychain); only ciphertext touches disk, in the app's private document
// directory. android:allowBackup="false" already excludes the whole app from
// Android's OS-level cloud backup, so this file never leaves the device.
import * as FileSystem from "expo-file-system/legacy";
import AsyncStorage from "@react-native-async-storage/async-storage";
// Metro resolves aesGcm.ts (react-native-quick-crypto, hardware AES) on native
// and aesGcm.web.ts (@noble pure-JS) on web — same wire format either way, and
// the same format previously produced inline here, so old backups stay readable.
import { encryptGcm, decryptGcm } from "./aesGcm";
import { getDoseLogsEncryptionKey, dbDeleteAllDoseLogs } from "./doseLogsDb";
import { loadAllUserData } from "../services/export/exportJson";
import type { DomainData } from "../services/export/exportTypes";
import {
  appendDoseLogs,
  saveMedications,
  saveSymptomLogs,
  saveBloodTestLogs,
  saveReminderSettings,
  saveUnitPreferences,
  saveCustomTrackingItems,
  saveCustomBloodMarkers,
  saveInjectionSitePreferences,
  saveUserProfile,
  setHRTType,
  storageSet,
} from "./storage";

const LAST_BACKUP_DATE_KEY = "last_local_backup_date";
const BACKUP_ENABLED_KEY = "local_backup_enabled";
const BACKUP_DIR = (FileSystem.documentDirectory ?? "") + "local_backups/";
const MAX_BACKUPS = 3;
const BACKUP_FORMAT_VERSION = 1;

// ==================== ENABLE/DISABLE PREFERENCE ====================
// Opt-in: disabled by default. The user turns this on explicitly in Settings,
// which keeps it coherent with the manual cloud backup (also an explicit
// choice) and avoids putting extra copies of health data on disk without the
// user asking for them. Plain AsyncStorage — this is a UI preference, not
// sensitive health data itself.

/** Defaults to false (disabled): local backups are opt-in, turned on explicitly in Settings. */
export async function isLocalBackupEnabled(): Promise<boolean> {
  try {
    const raw = await AsyncStorage.getItem(BACKUP_ENABLED_KEY);
    return raw === "true";
  } catch {
    return false;
  }
}

export async function setLocalBackupEnabled(enabled: boolean): Promise<void> {
  await AsyncStorage.setItem(BACKUP_ENABLED_KEY, enabled ? "true" : "false");
}

// One-time offer to turn backups on, surfaced on Home once the user has data
// worth protecting (see app/(tabs)/home.tsx). "Seen" is stored whether they
// accept or decline, so the offer never shows twice. On read error, treat as
// seen — better to skip the offer than to nag on every launch.
const BACKUP_OFFER_SEEN_KEY = "local_backup_offer_seen";

export async function hasSeenBackupOffer(): Promise<boolean> {
  try {
    return (await AsyncStorage.getItem(BACKUP_OFFER_SEEN_KEY)) === "true";
  } catch {
    return true;
  }
}

export async function markBackupOfferSeen(): Promise<void> {
  try { await AsyncStorage.setItem(BACKUP_OFFER_SEEN_KEY, "true"); } catch {}
}

// ==================== ENCRYPTION (shared with doseLogsDb.ts) ====================
// Delegated to utils/aesGcm — same key, same wire format as before.

const _encrypt = encryptGcm;
const _decrypt = decryptGcm;

// ==================== BACKUP ====================

export type LocalBackupInfo = {
  filename: string;
  createdAt: string; // ISO timestamp, parsed from the filename
};

async function _ensureBackupDir(): Promise<void> {
  const info = await FileSystem.getInfoAsync(BACKUP_DIR);
  if (!info.exists) {
    await FileSystem.makeDirectoryAsync(BACKUP_DIR, { intermediates: true });
  }
}

/**
 * Lists existing local backups, newest first. Safe to call any time (e.g. to
 * show "Last backup: ..." in Settings).
 */
export async function listLocalBackups(): Promise<LocalBackupInfo[]> {
  try {
    const info = await FileSystem.getInfoAsync(BACKUP_DIR);
    if (!info.exists) return [];
    const files = await FileSystem.readDirectoryAsync(BACKUP_DIR);
    return files
      .filter((f) => f.startsWith("backup_") && f.endsWith(".enc"))
      .map((f) => ({ filename: f, createdAt: f.slice("backup_".length, -".enc".length) }))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  } catch {
    return [];
  }
}

/**
 * Deletes every local backup file. Must be called alongside "Clear all data"
 * (utils/storage.ts's clearAllData(), which this file deliberately does not
 * import — it already imports several save* functions FROM storage.ts, so the
 * reverse import would be a require cycle, same reasoning as the reminder-
 * cancellation comment in settings.tsx's doClearData). clearAllData() deletes
 * dose_logs_db_key, the same key backups are encrypted with — any backup made
 * before that point becomes permanently undecryptable garbage the moment the
 * key is gone, so leaving the files behind serves no purpose and just shows
 * the user backups that will always fail to restore. Safe to call even if no
 * backups exist yet.
 */
export async function deleteAllLocalBackups(): Promise<void> {
  try {
    await FileSystem.deleteAsync(BACKUP_DIR, { idempotent: true });
  } catch (e) {
    if (__DEV__) console.warn("Failed to delete local backups (non-fatal):", e);
  }
}

/**
 * Runs the daily backup if one hasn't already run today. Fire-and-forget from
 * _layout.tsx — must never throw and must never block startup.
 */
export async function runDailyLocalBackupIfNeeded(): Promise<void> {
  try {
    if (!(await isLocalBackupEnabled())) return;
    const todayStr = new Date().toISOString().substring(0, 10);
    const lastRun = await AsyncStorage.getItem(LAST_BACKUP_DATE_KEY);
    if (lastRun === todayStr) return;

    const data = await loadAllUserData();

    // Skip if there's nothing worth backing up yet (fresh install, no medications added).
    if (!data.medications || data.medications.length === 0) return;

    const snapshot = JSON.stringify({ formatVersion: BACKUP_FORMAT_VERSION, createdAt: new Date().toISOString(), data });

    await _ensureBackupDir();
    const key = await getDoseLogsEncryptionKey();
    const encrypted = _encrypt(key, snapshot);
    const filename = `backup_${new Date().toISOString().replace(/[:.]/g, "-")}.enc`;
    await FileSystem.writeAsStringAsync(BACKUP_DIR + filename, encrypted, { encoding: FileSystem.EncodingType.UTF8 });

    // Rotate: keep only the MAX_BACKUPS most recent files.
    const existing = await listLocalBackups();
    const toDelete = existing.slice(MAX_BACKUPS);
    await Promise.all(toDelete.map((b) => FileSystem.deleteAsync(BACKUP_DIR + b.filename, { idempotent: true })));

    await AsyncStorage.setItem(LAST_BACKUP_DATE_KEY, todayStr);
  } catch (e) {
    if (__DEV__) console.warn("Local backup failed (non-fatal):", e);
  }
}

// ==================== RESTORE ====================

async function _loadBackupFile(filename: string): Promise<{ formatVersion: number; createdAt: string; data: DomainData }> {
  const key = await getDoseLogsEncryptionKey();
  const raw = await FileSystem.readAsStringAsync(BACKUP_DIR + filename, { encoding: FileSystem.EncodingType.UTF8 });
  const decrypted = _decrypt(key, raw);
  return JSON.parse(decrypted) as { formatVersion: number; createdAt: string; data: DomainData };
}

// Same five categories/labels as EXPORT_CATEGORIES in components/ExportOptionsModal.tsx —
// keep both in sync if a new data domain is ever added to either.
export type BackupCategoryCounts = {
  medications: number;
  doseHistory: number;
  diary: number;
  bloodTests: number;
  bodyMetrics: number;
};

/**
 * Decrypts a backup just far enough to report what's in it, without restoring
 * anything — used to show category counts in the restore confirmation dialog
 * before the user commits to an irreversible overwrite.
 */
export async function peekLocalBackup(filename: string): Promise<{ createdAt: string; counts: BackupCategoryCounts }> {
  const parsed = await _loadBackupFile(filename);
  const data = parsed.data;
  return {
    createdAt: parsed.createdAt,
    counts: {
      medications: data.medications.length,
      doseHistory: data.doseLogs.length,
      diary: data.diaryLogs.length,
      bloodTests: data.bloodTests.length,
      bodyMetrics: data.weightLogs.length + data.measurements.length,
    },
  };
}

/**
 * Restores all health data from a local backup file, overwriting whatever is
 * currently stored. This is destructive and must only be called after explicit
 * user confirmation (e.g. a Settings button with a confirmation dialog).
 *
 * Dose logs go through dbDeleteAllDoseLogs() + appendDoseLogs() — an explicit
 * clear-then-insert — rather than the SQLite "replace all" path, since that
 * path's circuit breaker (see doseLogsDb.ts) is designed to refuse exactly
 * this kind of full-history overwrite when it isn't clearly intentional.
 */
export async function restoreFromLocalBackup(filename: string): Promise<{ doseLogCount: number }> {
  const parsed = await _loadBackupFile(filename);
  const data = parsed.data;

  await dbDeleteAllDoseLogs();
  await appendDoseLogs(data.doseLogs);

  await Promise.all([
    saveMedications(data.medications),
    saveSymptomLogs(data.diaryLogs),
    saveBloodTestLogs(data.bloodTests),
    data.reminderSettings ? saveReminderSettings(data.reminderSettings) : Promise.resolve(),
    data.unitPreferences ? saveUnitPreferences(data.unitPreferences) : Promise.resolve(),
    saveCustomTrackingItems(data.customTrackingItems),
    saveCustomBloodMarkers(data.customBloodMarkers),
    data.injectionSitePreferences ? saveInjectionSitePreferences(data.injectionSitePreferences) : Promise.resolve(),
    data.profile ? saveUserProfile(data.profile) : Promise.resolve(),
    data.hrtType ? setHRTType(data.hrtType) : Promise.resolve(),
    storageSet("medication_change_log", JSON.stringify(data.medicationChanges)),
    storageSet("weight_logs", JSON.stringify(data.weightLogs)),
    storageSet("measurement_logs", JSON.stringify(data.measurements)),
    storageSet("added_blood_markers", JSON.stringify(data.addedBloodMarkers)),
    storageSet("measurement_custom_fields", JSON.stringify(data.measurementCustomFields)),
    storageSet("blood_test_reference_ranges", JSON.stringify(data.bloodTestReferenceRanges)),
  ]);

  return { doseLogCount: data.doseLogs.length };
}
