// Dynamic Expo config. Layers one build-time-conditional tweak on top of the
// static app.json and otherwise returns it unchanged: when the environment
// variable MYHRT_BLOCK_INTERNET is "1", android.permission.INTERNET is added
// to android.blockedPermissions. Expo prebuild turns a blockedPermissions
// entry into a `tools:node="remove"` marker in the generated manifest, and
// that marker survives Gradle's library-manifest merge (the same mechanism
// app.json already relies on to strip READ_EXTERNAL_STORAGE, SYSTEM_ALERT_WINDOW,
// etc.). The result: the shipped APK declares NO internet permission at all,
// so the operating system itself forbids the app from opening any network
// connection. This is a hardening/trust signal for a local-only health app —
// its absence is visible on the Play Store listing and in an exodus-privacy
// scan without anyone installing the app.
//
// Why conditional instead of adding it straight to app.json's blockedPermissions:
// a debug/dev build loads its JS bundle from the Metro dev server over the LAN
// and genuinely needs INTERNET. So the block is opt-in via this env flag, set
// only for the release build profiles that bundle JS into the APK (see the
// "preview" / "production" profiles in eas.json). It defaults OFF, so a plain
// `expo start` or `expo run:android` (debug) dev build is unaffected.
//
// To verify locally on a real RELEASE build (Windows PowerShell):
//   $env:MYHRT_BLOCK_INTERNET="1"; npx expo run:android --variant release
//
// External links (privacy policy, mailto:) keep working without INTERNET:
// Linking.openURL fires an OS intent that the browser/email app handles in its
// own process, so this app never opens a socket. There is no WebView anywhere,
// and the Terms/FAQ legal text is rendered natively from bundled content, so it
// is fully readable offline regardless.
//
// iOS has no INTERNET-permission concept (apps may always use the network, with
// privacy governed by App Store nutrition labels), so this is a no-op on iOS.
module.exports = ({ config }) => {
  if (process.env.MYHRT_BLOCK_INTERNET === '1') {
    config.android = config.android || {};
    const blocked = config.android.blockedPermissions || [];
    if (!blocked.includes('android.permission.INTERNET')) {
      config.android.blockedPermissions = [...blocked, 'android.permission.INTERNET'];
    }
  }
  return config;
};
