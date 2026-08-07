# Verifying that MyHRT can't reach the network

The strongest privacy claim MyHRT makes is also the easiest one to check for
yourself, and you can check it on the exact app you installed rather than trusting
any source code.

The release build ships with **no `INTERNET` permission**. On Android, network
access is granted by the kernel: a process is only allowed to open a network
socket if the app holds that permission. Without it, the app simply cannot open a
connection, no matter what its own code, or any library bundled inside it, tries
to do.

Here is how to confirm it, from quickest to most thorough.

## 1. The permission list (no tools needed)

On the app's Google Play page, open **About this app → App permissions**, or on
the phone go to **Settings → Apps → MyHRT → Permissions**. There is no "full
network access" or internet permission listed. This list is read from the app's
manifest, so it reflects what the app can actually do, not a self-declaration.

## 2. With adb, against the installed app

Connect the phone to a computer with USB debugging enabled, then run:

```
adb shell dumpsys package health.myhrt | grep -i internet
```

It prints nothing. The permission is not requested, held, or granted.

## 3. Inspect the installed APK directly

Pull the APK off the device and read its declared permissions:

```
adb shell pm path health.myhrt
adb pull <the path printed above> base.apk
aapt dump permissions base.apk | grep -i internet
```

`aapt` comes with the Android SDK build-tools, and `apkanalyzer manifest
permissions base.apk` does the same job. No `INTERNET` line appears.

## 4. Exodus Privacy

Look up `health.myhrt` at reports.exodus-privacy.eu.org, or submit the APK to
Exodus yourself. Exodus is a static scanner: it reads the compiled bytecode and
lists known SDK signatures it finds, whether or not the app uses them. The report
shows the app's permissions (no internet permission) and its tracker count. That
count is currently zero, because Exodus matches analytics and advertising SDK
signatures and none are present. Zero there is not proof the app carries no Google
code: the notification library bundles Firebase Cloud Messaging, which a decompiler
will find (see the Firebase note in ARCHITECTURE.md). Exodus measures what its
signatures match, not everything bundled and not what runs. The traffic capture in
the next section is the behavioural check.

## 5. The strongest check: watch the traffic

Install a release build and route it through an on-device deny-all firewall or a
packet capture such as PCAPdroid or NetGuard. Use the app normally. Nothing goes
out, because the operating system will not allow the app to open a connection in
the first place.

## What this proves, and what it doesn't

It proves the app **cannot open a network connection of its own**. That is
enforced by the operating system, and it holds even if one of the app's
dependencies were compromised, because the whole process has no network access to
abuse.

It does not, on its own, prove the app can never move data off the device by any
route at all. The app can still hand a file or a link to another app that *you*
explicitly choose, such as your browser opening the privacy policy, or the share
sheet when you export your data. Those are visible actions that you start. The
reason those handoffs carry no health data is the app's own code, which only ever
opens its privacy-policy URL and a `mailto:` address, and you can read every one
of those in this repository. So the permission covers silent, background network
access, and the code covers the visible handoffs. Together they close both.

One caveat worth stating plainly: a **debug** build does carry `INTERNET`, because
the development server delivers the app's code over the local network during
development. Always check a **release** build, which is what you install from the
store.

## How this is checked before every release

Config is not proof on its own. When Android builds the app it merges the
permission lists from every dependency's manifest, so in principle a library could
reintroduce `INTERNET` even though the app's own config removes it. For that
reason the check has to be run against the final, signed artifact, not the config.

- The permission is removed by [`src/config/app.config.js`](../src/config/app.config.js),
  which adds `INTERNET` to `blockedPermissions` whenever the environment variable
  `MYHRT_BLOCK_INTERNET` is set to `1`. That flag is set for the `preview` and
  `production` build profiles in [`src/config/eas.json`](../src/config/eas.json).
- Before a production release, the signed app bundle is built and its merged
  manifest is checked for `INTERNET`, using the same `aapt dump permissions` or
  on-device `dumpsys` checks shown above, run against the actual production build.
- A production build that still shows `INTERNET` is not released.

Right now this is a manual step run before each release. Turning it into an
automated build gate, one that fails the release if `INTERNET` ever reappears in
the merged manifest, is on the roadmap and not yet in place.
