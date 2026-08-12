# Architecture and security:

This document exists so you don't have to take our word for anything. MyHRT makes
privacy claims, and the point of publishing this code is that each claim can be
checked. This guide points at where each guarantee lives, how to verify it, and
where the limits are, including a few controls that are weaker than a
marketing line would suggest.

It is written to be defensible rather than reassuring. If a claim here is stronger
than the code supports, that is a bug in the claim, and we want to hear about it:
**privacy@myhrt.health**.

## Read this first: what platform this covers

- **MyHRT v1 is an Android app.** Every security property described here is about
  the **Android release build** unless it says otherwise.
- **iOS is planned and is not covered here.** The shared code compiles for iOS,
  but the parts that actually matter for security are platform-specific: the
  Keychain accessibility class, what happens to data on uninstall, the Data
  Protection class, whether a key can be gated behind biometrics, app-switcher
  snapshots, and so on. None of that has been implemented or verified yet, so this
  document makes no iOS claims. When there is an iOS release, it will get its own
  documented and verified analysis first. Do not read the Android guarantees below
  as iOS guarantees.
- **Web is not a security target.** The project builds for web only as a
  development convenience. No web build is published. Browser storage is not
  hardware-backed and has a completely different threat model, so nothing here
  applies to a browser.

There has been **no independent third-party security audit yet.** This document
and the published code are the interim. The roadmap at the end tracks the path to
a real audit.

## 1. Threat model: what this defends against, and what it doesn't

| Scenario | Defended? | How |
|---|---|---|
| The app sends your data to us or a third party | Yes | There is no server and no networking code, and the release build has no INTERNET permission (see §3). |
| Lost or stolen phone, locked | Yes | The device lock plus encryption at rest (§4); the key sits in the OS secure key store. |
| Someone pulls the app's files off the device at rest | Yes | The database holds only ciphertext (§4). |
| Casual snooping on an unlocked phone | Partly | The optional app lock (§6) is a barrier, not a cryptographic wall. |
| Someone who knows your device passcode | Partly | The app lock adds friction, but a short PIN is not brute-force proof (§6). |
| Malware or a rooted device, phone unlocked | **No** | An attacker running with your privileges can read keys in memory and data in the clear. Encryption at rest protects data on disk, not against code running as you. |
| Live instrumentation (e.g. Frida) or forensic extraction (e.g. Cellebrite) on an unlocked, rooted device | **No, out of scope** | Same reason as the row above: code running as you sees the key in memory and the plaintext while the app is open, and can dump the app's heap. This is not something a React Native app can defend against. If your threat model includes a determined actor with a rooted device in hand, this is not the right tool. |
| Data you exported or shared, after it leaves the app | **No, out of scope** | Exports are yours to place wherever you choose (§7). |

## 2. What we claim, and what we don't

**We claim, for the Android release build:**
- The app starts no network communication of its own, and the release build cannot
  open a network connection because the OS is not granted the permission.
- Health records are encrypted at rest with AES-256-GCM before they are written to
  disk, using a key kept in the OS secure key store that is never transmitted.
- Clearing the app's data removes the records and keys MyHRT manages on the device.

**We do not claim:**
- Anything about iOS or web security (see the platform note above).
- Protection against an attacker running code on an unlocked device.
- That the app lock is a strong cryptographic boundary. It is a privacy barrier.
- That data you have already exported or shared is still under our control.
- That an independent audit has happened. It has not.

## 3. No data leaves the device

There is no server, and no analytics, crash-reporting, or advertising SDK.

**A quick sniff test, not a full proof.** The code published here contains no
networking primitives. This search comes back empty:

```
grep -rnE "\bfetch\(|XMLHttpRequest|WebSocket|axios|sendBeacon" src/
```

Treat that as a starting signal, nothing more. It only covers the files in this
repository, not the whole app, and it can't see third-party dependencies or native
code. The real assurance is the permission below, which the OS enforces on the
shipped binary regardless of what any code, ours or a dependency's, tries to do.

**The release build has no INTERNET permission.** Without it, the Android kernel
will not let the app's process open a socket at all. This holds even if a bundled
dependency tried to reach the network, because the whole process has no network
access. The permission is removed by [`src/config/app.config.js`](src/config/app.config.js),
which adds INTERNET to `blockedPermissions` when `MYHRT_BLOCK_INTERNET=1` (set for
the `preview` and `production` profiles in [`src/config/eas.json`](src/config/eas.json)).
[`docs/VERIFY.md`](docs/VERIFY.md) walks through confirming this on the app you
actually installed, using the Play permission list, `adb`, `aapt`, or an Exodus
Privacy scan.

**The bundled Firebase code.** `expo-notifications`, the library MyHRT uses for
reminders, bundles Firebase Cloud Messaging on Android whether or not an app uses
push. Its Kotlin names the `FirebaseMessaging` class at build time, so that class
and nearly forty others around it stay in the package unless the library is forked.
MyHRT only uses local, on-device scheduling: there is no `google-services.json` in
the project and no push-token registration anywhere in the code, so nothing ever
connects. The bundled FCM code would otherwise add `INTERNET`,
`com.google.android.c2dm.permission.RECEIVE`, and an install-referrer permission to
the manifest; the release build blocks all of these in
[`src/config/app.config.js`](src/config/app.config.js) and `app.json`. On top of
that, the release build strips Firebase's manifest components, the messaging
service, the init provider, and the `c2dm` receiver, so nothing can start the code
either. What remains is inert: with no INTERNET permission it cannot open a
connection, and with no entry point nothing invokes it. Replacing the notification
layer to drop it entirely is on the roadmap; the permission-level guarantee above
does not depend on that.

React Native's own networking and image stack bundles OkHttp, an HTTP client, for
the same structural reason. The app makes no network calls, so R8 strips its networking classes out and
leaves only OkHttp's `PublicSuffixDatabase` helper, and with no INTERNET
permission it too has nothing to open.

**The strongest single check** is to run a release build behind a deny-all
firewall or packet capture (PCAPdroid, NetGuard, mitmproxy) and confirm nothing
goes out during normal use. External links, like the privacy policy or a `mailto:`,
open through another app in its own process. MyHRT opens no socket, and there is no
WebView anywhere.

**One caveat, stated plainly:** a debug build carries INTERNET, because the
development server delivers the app's code over the local network. Check a release
build, which is what you install.

**The two exported providers.** Decompiling the manifest shows two exported
content providers, and each has a specific reason.

`expo.modules.clipboard.ClipboardFileProvider` ships with `expo-clipboard`, the
module MyHRT uses to copy your recovery code, and the library requires it to be
exported (the app fails to launch otherwise). MyHRT only ever puts text on the
clipboard, never a file or image, so nothing is written to the paths this
provider would serve, and it is never exercised.

`com.reactnativeandroidwidget.RNWidgetImageProvider` serves the home-screen
widget's rendered image. An Android widget is drawn by the launcher, a separate
app, which must be able to read that image, so this provider is exported by
design. That is inherent to how every Android home-screen widget works, not
specific to MyHRT. The image can show medication names, so the app's "Hide names
on widget" setting replaces them with a neutral label for anyone who wants the
widget kept legible only to themselves on a shared or observed home screen. (An
earlier build tried to lock this provider down; that silently broke widget
rendering on some launchers, so exported is the working, standard configuration.)

The app's own file-sharing providers, `FileSystemFileProvider` and
`SharingFileProvider`, are not exported. These are named here so that finding an
exported flag comes with its reason attached.

## 4. Encryption at rest

MyHRT does its own encryption in the app before anything reaches storage, rather
than trusting a storage layer to do it. All of it goes through one wire-format
module, [`src/aesGcm.ts`](src/aesGcm.ts), which on Android uses
`react-native-quick-crypto` (hardware-accelerated OpenSSL). The web build uses a
matching pure-JS version, [`src/aesGcm.web.ts`](src/aesGcm.web.ts), but per the
platform scope only the Android path is a supported security target.

The format is `base64(nonce) + "." + base64(ciphertext + auth tag)`, with a 12-byte
nonce from a cryptographically secure RNG (`expo-crypto`) and a 16-byte GCM tag
that is checked on decrypt, so tampering is rejected. The round-trip, tamper, and
wrong-key tests are in [`test/aesGcm.test.ts`](test/aesGcm.test.ts) and you can run
them yourself.

**Where the key lives.** The dose-log database key is 32 random bytes (256-bit)
from `expo-crypto`, generated once and stored in the OS secure key store (Android
Keystore, iOS Keychain) through `expo-secure-store`, under `dose_logs_db_key`. See
[`src/secureStorage.ts`](src/secureStorage.ts) and
[`src/doseLogsDb.ts`](src/doseLogsDb.ts). The key is loaded into memory only to
encrypt or decrypt, and it is never transmitted. The same key is reused by the
local-backup feature, so there is exactly one stored key, not copies.

**On "hardware-backed."** The key store is hardware-backed on devices that support
it, and software-backed on devices that don't. Availability varies by device,
Android version, and StrongBox support, so we say "hardware-backed where
supported" rather than claiming it everywhere. And because the app has to actually
decrypt your data to show it to you, the key necessarily enters memory while the
app runs. So the at-rest guarantee does not extend to a rooted or instrumented
device that is unlocked and running code.

**Why the database holds only ciphertext.** The `dose_logs` table has two columns:
an opaque random `id` with no health content, and a `payload` column holding the
whole record, encrypted in the app before any SQL runs. So SQLite, and everything
it touches (its write-ahead log, journals, temp tables, indexes) only ever sees
ciphertext. There is no readable health column to query or leak. To be precise
about the division of labour: `expo-secure-store` guards the key; it does not
encrypt the database. The app's own AES-256-GCM layer does that.

**What still leaks.** Row count, rough insertion order, database file
size, and filesystem timestamps are all visible to anyone with file access, even
though the contents are not. That is inherent to an on-device encrypted store and
we don't hide it.

## 5. What is stored where, and the deletion boundary

Storage routing lives in the app's central `storage.ts` (part of the closed
application, not reproduced here, but its behaviour is described below):

- **Encrypted:** all health data (medications, diary and symptom logs, blood
  tests, metrics, the change log, profile, HRT type, reminder settings) and the
  preferences that reveal what a user tracks. Most of this goes through
  `expo-secure-store`, which on Android encrypts values with AES-GCM under a
  Keystore key; the high-volume dose logs use the app's own AES-256-GCM layer over
  SQLite described in §4.
- **Unencrypted:** UI state only (collapse state, theme, unit display, migration
  flags). Nothing here reveals anything about a user's health.

**Deletion is scoped, not magic.** "Clear all data" removes every registered
encrypted key, drops the dose-log table, and deletes the database key. Once that
key is gone, the remaining ciphertext is computationally infeasible to recover.
Two limits: exported or shared files are outside the app and survive this
(see §7), and the sweep only covers keys the app knows about, which is enforced by
a review rule and a test in the closed app rather than by the OS. Uninstalling the
app removes its sandbox, including the database file, under normal Android
behaviour. `allowBackup` is set to `false`, so the app's data is excluded from
Android's cloud and device-transfer backups.

## 6. App lock, PIN, and recovery: a barrier, not a boundary

The optional app lock ([`src/appAuth.ts`](src/appAuth.ts)) exists to stop casual
access to a phone that is already unlocked. It is not represented as a strong
defence against someone who can extract stored data.

- **PIN and recovery-code storage.** Both are hashed with PBKDF2-SHA256 (10,000
  iterations for the PIN, 1,000 for the recovery code, each with a random salt) and
  compared in constant time. The plaintext is never stored. The limit: a
  6-digit PIN has only about a million possible values, so PBKDF2 at 10,000
  iterations does not make an offline guess of an extracted hash hard on modern
  hardware. The real protection for that hash is that it lives in secure storage on
  a locked device. The PIN is a second layer, not the main confidentiality control.
  A memory-hard KDF is on the roadmap.
- **Rate limiting** (lockout after 5 tries, forced recovery after 10) is UX
  friction held in app storage. It is persisted so that force-quitting and
  relaunching cannot reset the counter, but a rooted device could roll it back. It
  is not claimed as a durable brute-force defence.
- **Biometric or device unlock** gates the UI. It does not currently bind release
  of the database key to a biometric result.
- **Screenshot blocking** is a deterrent, not prevention. It can be defeated by OS
  behaviour, accessibility services, screen mirroring, or another camera.

## 7. Export and local backups

- **Export** produces a JSON or CSV file, generated entirely on the device, with an
  optional AES-256 password-protected ZIP. You choose where it goes through the OS
  share sheet. Once it leaves the app it is yours to look after, and it is outside
  MyHRT's control and not covered by "Clear all data." That is by design, since it
  is your data to take, but we state it plainly rather than imply otherwise.
- **Local backups** ([`src/localBackup.ts`](src/localBackup.ts)) are optional,
  on-device, encrypted with the same device-bound key, written to an app-private
  directory, removed on uninstall, and destroyed by "Clear all data."

## 8. The planned sync feature (not in this version)

This is described so its arrival is a documented promise rather than a surprise,
and so the design can be criticised before it is built. **None of it exists in the
current version.**

The intended design stores a single encrypted blob in a cloud account you choose
(your own Google Drive or iCloud, not a server we run), encrypted on the device
with a key derived from your passphrase using a memory-hard KDF (Argon2id), in a
versioned envelope. Neither we nor the provider could decrypt it. The trade-offs
are real and will be stated up front: lose the passphrase and the backup is
unrecoverable, and because Android's INTERNET permission is all-or-nothing,
shipping sync in the same package would weaken the v1 guarantee, so the intended
approach is a separate build or companion app for people who want to stay
local-only. It will be public in this repository, with time to be reviewed, before
it ships.

## 9. Known limitations and roadmap

Published on purpose, so the gaps are visible rather than discovered:

- No independent third-party audit yet. Planned as a scoped engagement as the
  project can support it.
- No iOS security analysis yet. iOS will get its own before any iOS release.
- No reproducible build yet, so an auditor cannot yet confirm that the store binary
  matches a given commit. Planned: a pinned toolchain, a published commit tag and
  signed release hash, and a documented build path.
- No SBOM or dependency-vulnerability policy yet. `react-native-quick-crypto`, the
  Expo modules, and their native dependencies are part of the trusted base.
- The INTERNET-absence check is not yet a CI release gate. It is currently a manual
  check on the signed artifact before release; automating it is on the roadmap.
- The dormant Firebase Cloud Messaging components bundled by `expo-notifications`
  are blocked at the permission level but not yet stripped from the manifest
  entirely (see §3).
- AES-GCM does not use AAD, so ciphertext is not cryptographically bound to its row
  id. Low practical impact under the local-only threat model, and a candidate for a
  versioned format change.
- The app lock is a casual-access barrier, not brute-force-hardened (§6).

## Reporting

Security or privacy issues: **privacy@myhrt.health**. Please don't open a public
issue for an undisclosed vulnerability. A formal disclosure policy is on the
roadmap above.