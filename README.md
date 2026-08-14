# MyHRT Security Layer

The at-rest encryption and secure-storage code from the [MyHRT](https://myhrt.health)
app, published so anyone can read how MyHRT protects health data on your device,
and verify on the installed app that it cannot send that data anywhere.

MyHRT is a private hormone-replacement-therapy tracker. All data stays on your
device: no accounts, no servers, no tracking. This repository contains the
**exact code** MyHRT uses to encrypt that data at rest, keep its encryption key
in your device's secure key store, lock the app, and make automatic encrypted
local backups, plus the build config that removes the app's internet
permission entirely.

The source files are copied **verbatim** from the app; nothing has been
rewritten or simplified for show. The one exception is the test file, whose
`import` paths are adjusted so the suite runs standalone in this repository. Its
logic and assertions are unchanged. These are the real files, so you can read them
and compare the logic against a decompiled build, keeping in mind that compiled
bytecode never diffs cleanly against source (see the note on that gap below).

For the full, caveated walkthrough of every security property, including
where the limits are: see **[ARCHITECTURE.md](ARCHITECTURE.md)**. This README is
the short version.

## What's in here

| File | What it does |
|------|--------------|
| `src/aesGcm.ts` | AES-256-GCM encryption on device (native), via hardware-accelerated OpenSSL |
| `src/aesGcm.web.ts` | The same encryption for the web build, via the audited `@noble/ciphers` library; identical wire format |
| `src/secureStorage.ts` | Reads/writes the encryption key in Android Keystore / iOS Keychain (via `expo-secure-store`); serialises Keystore ops and chunks large values |
| `src/doseLogsDb.ts` | Stores dose history in SQLite with every row encrypted before it touches disk |
| `src/doseLogTypes.ts` | The shape of a dose-log record |
| `src/appAuth.ts` | Optional app lock: PIN and recovery-code hashing (PBKDF2-SHA256, constant-time compare), persisted lockout, device biometrics |
| `src/localBackup.ts` | Automatic on-device encrypted backups (same device-bound key), and the explicit user-confirmed restore |
| `src/config/app.config.js` | The build hook that strips `android.permission.INTERNET` from release builds |
| `src/config/eas.json` | Build profiles showing `MYHRT_BLOCK_INTERNET=1` set for `preview` and `production` |
| `src/config/withManifestHardening.js` | The build plugin that, on release builds, adds `tools:node="remove"` markers for the Firebase and transitive datatransport manifest entry points (messaging and component-discovery services, init provider, instance-id/`c2dm` receiver, transport schedulers), plus defensive markers for ML Kit / code-scanner left over from a since-removed dev dependency. It removes manifest entry points, not the compiled DEX classes. |
| `src/config/withBackupRules.js` | The build plugin that excludes every data domain from Android cloud backup and device-to-device transfer (the Android 12+ "Copy my data" flow), overwriting expo-secure-store's permissive defaults, so no app data leaves the device by either backup path |
| `src/config/withWidgetProviderSecurity.js` | The build plugin that makes the home-screen widget's image provider non-exported (readable only by the launcher, through a temporary per-image grant), so other apps cannot read rendered widget images, which can contain medication names |
| `test/aesGcm.test.ts` | Proves the encryption round-trips, cross-checks native vs web, and rejects tampering and wrong keys |

> **A note on `appAuth.ts` and `localBackup.ts`:** these two reference the app's
> central storage layer (`utils/storage.ts`), which is part of the closed
> application and not reproduced here, so they will not resolve or run standalone.
> They are included so their security-relevant logic (how PINs are hashed, how
> backups are encrypted) can be read and diffed against the shipped app. The
> encryption core (`aesGcm`, `secureStorage`, `doseLogsDb`) is self-contained and
> the test suite runs against it directly.

## How MyHRT protects your data

- **Your data is encrypted by the app before it is stored, using AES-256-GCM.** MyHRT
  does *application-level* encryption: each dose-log record is encrypted with
  AES-256-GCM (`src/aesGcm.ts`) **before** it is written to the database
  (`src/doseLogsDb.ts`). The SQLite file therefore holds only ciphertext, an
  opaque random `id` that carries no health information, and an encrypted
  `payload`, with no readable health column to read, index, or leak. GCM is
  *authenticated* encryption, so tampering with the stored bytes is detected, not
  just concealed.
- **The encryption key is kept in your phone's secure key store, not in the
  database.** The secure key store is a small vault built into the operating
  system, made specifically for holding secrets like encryption keys and kept
  separate from where apps save ordinary data. On Android it's called the
  Keystore, and on iPhone it's the Keychain. Think of your encrypted data as a
  locked diary, and think of this as where the key is kept, deliberately not next
  to the diary. That way, if someone copies the database file off a lost phone, all
  they get is scrambled text that is useless without the key. MyHRT generates one
  256-bit key using a cryptographically secure random generator, then hands it to
  the key store through `expo-secure-store` (`src/secureStorage.ts`). On phones
  with dedicated security hardware, the key is protected by that hardware. On
  phones without it, the operating system protects the key in software instead.
  That is why we say "hardware-backed where supported" rather than everywhere.
  One point worth being precise about: `expo-secure-store` guards the key, but it
  does not encrypt the database itself. The app's own AES-256-GCM layer does that.
  The key is only pulled into memory for the moment data is being encrypted or
  decrypted.
  - *The limit.* Because the app has to decrypt your data to show it to you,
    the key and the cleartext necessarily exist in the app's memory while it is
    running. This protects data **at rest**: a lost or stolen phone, or a copied
    database file, yields only ciphertext, but not against malware or an attacker
    running code inside the app's process on an unlocked, rooted device.
    [ARCHITECTURE.md](ARCHITECTURE.md) is explicit about this boundary.
- **Same format on every platform.** The native and web implementations use the
  identical wire format, `base64(nonce) + "." + base64(ciphertext‖authTag)`, so
  the two are interchangeable and independently testable.

## What this proves, and what it doesn't

**What it proves:** that the encryption is real and competently built: genuine
AES-256-GCM applied by the app before storage, the key kept in the device's
secure key store (hardware-backed where supported), authenticated so
tampering is caught, no plaintext health data at rest, and no backdoor hiding in
these files. You can read every line and run the tests yourself.

**What it does *not* prove:** that this exact source is what got compiled into
the app on your phone. Publishing source can never prove that by itself; that's
the inherent "source ≠ binary" gap.

**The stronger, binary-level proof**: the one that doesn't require trusting that
the source matches the build, is a property of the shipped app itself:

- **MyHRT requests no internet permission.** Android therefore blocks the app
  from opening a network connection of its own, enforced by the operating
  system (the app's process is not granted network access), not merely asserted
  by a source file. You can confirm it on the Google Play listing's permission
  list, or by scanning the published app with
  [εxodus Privacy](https://reports.exodus-privacy.eu.org/), **before** you
  install anything. So the app cannot silently phone home or stream your data to
  a server in the background. Two caveats: (1) it can still hand a file or a link to another app *you*
  explicitly choose: your browser opening the privacy policy, the export share
  sheet you tap, which is a visible action routed through Android, not the app
  reaching the network itself; and (2) lacking the permission does not by itself
  stop an app from smuggling data *inside* such a handoff, so the real assurance
  there is the code: the only links MyHRT opens are its own privacy policy and a
  `mailto:` address, they carry no health data, and you can read every one of
  them.
- **No analytics, ad, or crash-reporting SDK.** Two bundled leftovers a decompiler
  will still surface. `expo-notifications`, the library behind reminders, brings
  Firebase Cloud Messaging with it; its Kotlin names the `FirebaseMessaging` class
  outright, so that class and the nearly forty other Firebase classes around it can't leave the build
  unless the library is forked. The app never uses push: nothing is configured for
  it, there's no Firebase project, and no code asks for a token. Firebase's entry
  points are cut from the release manifest, the messaging service, the init
  provider, the `c2dm` receiver, so nothing can start it. The second is OkHttp, an
  HTTP client React Native pulls in for its own networking and image loading; the
  app makes no network calls, so R8 strips its networking classes out and leaves
  only OkHttp's `PublicSuffixDatabase` helper (one class plus a synthetic inner
  class). Neither
  can act, for the reason in the bullet above: with no internet permission the
  process has no network socket to open. A later release removes Firebase with the
  notification rewrite. An εxodus scan currently reports zero trackers on the
  release build, since it looks for analytics and ad SDKs and finds none, which is a
  useful check but not evidence that no Google code is bundled.

So: **read this repository to judge the design; check the shipped app's
permissions or its εxodus report to verify the running app can't exfiltrate your
data.** Together they cover both "is the crypto real" and "does the real app
behave." (App package: `health.myhrt`.)

## Verify it yourself

Run the crypto tests:

```
npm install
npm test
```

The tests confirm the encryption round-trips, that native and web produce
byte-compatible output, and that tampered ciphertext or a wrong key is rejected.

The code is small and heavily commented, and reading it end to end takes only a
few minutes.

**To verify the "no internet" guarantee on the app you installed** (rather than on
this source), see [docs/VERIFY.md](docs/VERIFY.md). It walks through checking the
shipped build's permissions with the Play listing, `adb`, `aapt`, or an Exodus
Privacy scan, and is the check that doesn't require trusting that this source
matches the binary.

## Scope

This is the **security-critical layer** of MyHRT, not the whole application. The
app's user interface and feature logic are not published here. This repository
exists so the one thing that matters most for a health app (how your data is
protected) can be inspected by anyone.

## License

Source-available under the [MyHRT Source Verification License](LICENSE). You may
read this code, run its tests, fork it to inspect, and diff it against the shipped
app, so you can verify MyHRT's security claims for yourself. It is not open-source
software: it is not licensed for reuse in other apps, and rights beyond that
verification are reserved. The MyHRT and Stuga Labs names and the MyHRT logo are not licensed for use in
other apps.

## Security

Found an issue? See [SECURITY.md](SECURITY.md); report privately to
privacy@myhrt.health.
