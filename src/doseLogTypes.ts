// Standalone type-only module so utils/doseLogsDb.ts can reference DoseLog without
// importing utils/storage.ts — that direction would create a require cycle
// (storage.ts imports the live doseLogsDb functions; doseLogsDb.ts would import a
// type back from storage.ts). storage.ts re-exports DoseLog from here so every
// existing `import { DoseLog } from "../utils/storage"` elsewhere keeps working.
export type DoseLog = {
  id: string;
  medicationId: string;
  date: string;      // ISO string — the date the log was created / the scheduled dose date
  time: string;      // ISO string
  status: "taken" | "missed" | "skipped";
  dose?: string;
  doseUnit?: string;
  notes?: string;
  site?: string;       // injection zone ID, e.g. "leftDelt"
  siteLabel?: string;  // human-readable, e.g. "Left delt"
  source?: "auto-missed" | "user_deleted"; // "auto-missed" = backfill; "user_deleted" = tombstone, prevents auto-missed recreation
};
