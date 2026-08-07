// Native (Android / iOS) — uses Android Keystore / iOS Keychain via expo-secure-store.
//
// expo-secure-store itself enforces a 2048-byte (UTF-8) limit per value on BOTH
// platforms — see byteCountOverLimit() in its source. Above that it logs a
// warning today and is documented to throw in a future SDK version. This is a
// constraint of the JS wrapper, not of the native storage backend, so it applies
// uniformly on Android and iOS regardless of either platform's real capacity.
// Large values are split into chunks stored as `key__0`, `key__1`, … with a
// `key__n` count key, sized in actual UTF-8 bytes (not JS string length) so
// multi-byte content (non-ASCII diary notes, emoji) can't silently produce an
// oversized chunk.
//
// Reads transparently reassemble chunks. Backward-compatible: unchunked values still read normally.
import * as SecureStore from "expo-secure-store";

// Safety margin under expo-secure-store's 2048-byte limit.
const MAX_CHUNK_BYTES = 1900;
const CHUNK_META = "__n";

function utf8ByteLength(str: string): number {
  return new TextEncoder().encode(str).length;
}

/** Splits `val` into chunks each <= maxBytes when UTF-8 encoded, without splitting surrogate pairs. */
function chunkByUtf8Bytes(val: string, maxBytes: number): string[] {
  const chunks: string[] = [];
  let i = 0;
  while (i < val.length) {
    let end = Math.min(i + maxBytes, val.length);
    while (end > i && utf8ByteLength(val.slice(i, end)) > maxBytes) end--;
    if (end < val.length && end > i) {
      const code = val.charCodeAt(end - 1);
      if (code >= 0xd800 && code <= 0xdbff) end--; // keep surrogate pairs intact
    }
    if (end <= i) end = i + 1; // always advance at least one char
    chunks.push(val.slice(i, end));
    i = end;
  }
  return chunks;
}

// Caps how many native SecureStore calls are ever in flight at once for a single
// chunked read/write/delete. Firing hundreds of simultaneous native bridge calls
// (e.g. for a very large chunked value) can overwhelm the bridge/native module
// and present as the app freezing, even though each individual call is fast.
const MAX_CONCURRENT_CHUNK_OPS = 8;

async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let cursor = 0;
  async function worker() {
    while (cursor < items.length) {
      const i = cursor++;
      results[i] = await fn(items[i], i);
    }
  }
  const workerCount = Math.min(limit, items.length);
  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  return results;
}

async function getItem(key: string): Promise<string | null> {
  const meta = await SecureStore.getItemAsync(key + CHUNK_META);
  if (meta) {
    const n = parseInt(meta, 10);
    const parts = await mapWithConcurrency(
      Array.from({ length: n }, (_, i) => i),
      MAX_CONCURRENT_CHUNK_OPS,
      (i) => SecureStore.getItemAsync(`${key}__${i}`)
    );
    return parts.map((p) => p ?? "").join("");
  }
  return SecureStore.getItemAsync(key);
}

async function setItem(key: string, val: string): Promise<void> {
  // Clean up previous chunks if any — bounded concurrency, same reasoning as below.
  const prevMeta = await SecureStore.getItemAsync(key + CHUNK_META);
  if (prevMeta) {
    const prevN = parseInt(prevMeta, 10);
    await mapWithConcurrency(
      Array.from({ length: prevN }, (_, i) => i),
      MAX_CONCURRENT_CHUNK_OPS,
      (i) => SecureStore.deleteItemAsync(`${key}__${i}`)
    );
    await SecureStore.deleteItemAsync(key + CHUNK_META);
  }

  if (utf8ByteLength(val) <= MAX_CHUNK_BYTES) {
    await SecureStore.setItemAsync(key, val);
    return;
  }

  // Remove the plain key so reads don't return stale data
  await SecureStore.deleteItemAsync(key);

  // Chunks are independent writes — bounded concurrency avoids flooding the native
  // bridge with potentially hundreds of simultaneous calls for a very large value.
  // The count key is written last, after every chunk has actually landed, so a
  // reader never sees a meta count pointing at chunks that don't exist yet.
  const chunks = chunkByUtf8Bytes(val, MAX_CHUNK_BYTES);
  await mapWithConcurrency(
    chunks,
    MAX_CONCURRENT_CHUNK_OPS,
    (chunk, i) => SecureStore.setItemAsync(`${key}__${i}`, chunk)
  );
  await SecureStore.setItemAsync(key + CHUNK_META, String(chunks.length));
}

async function removeItem(key: string): Promise<void> {
  const meta = await SecureStore.getItemAsync(key + CHUNK_META);
  if (meta) {
    const n = parseInt(meta, 10);
    await mapWithConcurrency(
      Array.from({ length: n }, (_, i) => i),
      MAX_CONCURRENT_CHUNK_OPS,
      (i) => SecureStore.deleteItemAsync(`${key}__${i}`)
    );
    await SecureStore.deleteItemAsync(key + CHUNK_META);
  }
  await SecureStore.deleteItemAsync(key);
}

// ==================== GLOBAL SERIALIZATION ====================
// All SecureStore operations run strictly one-at-a-time through this queue.
// Rationale: on a Samsung A41 (Android 11), concurrent SecureStore reads —
// e.g. Home's first load racing the startup backup snapshot's ~17 reads after
// the splash screen stopped serializing them — intermittently NEVER RESOLVED
// (Keystore-level hang; JS thread confirmed idle via a heartbeat probe while
// loadData sat awaiting a read forever, 2026-07-07). Samsung keymaster HALs
// are known to misbehave under concurrent operations. Individual ops are
// single-digit milliseconds, so serializing costs nothing measurable, and the
// per-op chunk fan-out (mapWithConcurrency above) still parallelises WITHIN
// one logical operation — the queue wraps whole getItem/setItem/removeItem
// calls, not individual chunk reads.
//
// A failed op must not wedge the queue: the chain continues via .then(fn, fn).
let _queue: Promise<unknown> = Promise.resolve();
function _serialize<T>(fn: () => Promise<T>): Promise<T> {
  const next = _queue.then(fn, fn);
  _queue = next.catch(() => undefined);
  return next;
}

export default {
  getItem: (key: string) => _serialize(() => getItem(key)),
  setItem: (key: string, val: string) => _serialize(() => setItem(key, val)),
  removeItem: (key: string) => _serialize(() => removeItem(key)),
  clear: async () => {},
};
