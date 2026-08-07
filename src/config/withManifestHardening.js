// Expo config plugin: removes entries that expo prebuild regenerates but
// must not appear in production builds.
//
// exp+myhrt intent-filter scheme, Expo's dev-client deep-link scheme. It has no
// function in a production build and exposes an unnecessary deep-link entry point.
//
// NOTE on USE_FINGERPRINT: an earlier version of this plugin also stripped the
// USE_FINGERPRINT <uses-permission> entry from the main manifest. That was a
// no-op in the final APK: expo-local-authentication's own library manifest
// declares USE_FINGERPRINT, and Gradle manifest merging unions library
// permissions back in regardless of the main manifest. Worse, once
// USE_FINGERPRINT was added to android.blockedPermissions in app.json (the
// correct mechanism, which generates a tools:node="remove" marker that survives
// the merge), a name-based strip here would have deleted that remove-marker
// and defeated it. Permission removal belongs in blockedPermissions only.
// Do not re-add permission filtering to this plugin.
//
// Firebase / ML Kit manifest-surface removal (release builds only):
// expo-notifications bundles Firebase Cloud Messaging unavoidably. Its own Kotlin
// subclasses FirebaseMessagingService (PushTokenModule, the messaging delegates),
// so the FCM classes cannot be dropped from the DEX without forking the library.
// datatransport rides in transitively under firebase-messaging. ML Kit and Google
// code-scanner previously arrived via the expo-dev-client dev tool, now removed;
// their remove-markers below are kept as a defensive backstop should a future
// dependency reintroduce them. MyHRT uses only LOCAL notifications:
// there is no getDevicePushTokenAsync / MESSAGING_EVENT usage anywhere in the app,
// so none of these components is ever exercised at runtime. Firebase is only
// touched lazily inside PushTokenModule (FirebaseMessaging.getInstance(), wrapped
// in a try/catch that fails safe when Firebase is uninitialised), which the app
// never calls, so removing FirebaseInitProvider does not affect local-notification
// delivery. That path is AlarmManager -> NotificationsService, which we keep.
//
// These libraries declare their components in their OWN library manifests, which
// Gradle merges into the app manifest. Deleting them from the main manifest does
// nothing (they are not there at prebuild time); the merge would add them back.
// The only mechanism that survives the merge is a tools:node="remove" marker in
// the higher-priority main manifest, the same mechanism blockedPermissions uses
// for permissions. So we add remove-markers, not deletions.
//
// What this does and does NOT do: it removes the RUNTIME SURFACE (no push service,
// no c2dm receiver, no Firebase auto-init provider), so the shipped, merged
// manifest declares no Firebase or ML Kit entry point at all. It does NOT remove
// the compiled FCM classes from the DEX; those remain (dead, unreachable as entry
// points, and OS-blocked from any network by the absent INTERNET permission). A
// decompiler will still find them; that is disclosed in the security repo rather
// than hidden. Gated on the same MYHRT_BLOCK_INTERNET flag as the INTERNET strip
// (set only for release profiles in eas.json), so dev/debug builds are untouched.
const { withAndroidManifest } = require('@expo/config-plugins');

// Firebase Cloud Messaging (bundled by expo-notifications; the app is local-only
// and never uses push) and its transitive datatransport scheduler. The ML Kit and
// code-scanner entries below previously came from the expo-dev-client dev tool,
// now removed; they are kept as a defensive backstop and are no-ops unless a
// future dependency pulls those libraries back in. Enumerated from the merged
// manifest (aapt2 dump xmltree): every Google service/receiver/provider/activity/
// meta-data entry that keeps one of these class trees alive.
const REMOVE_SERVICES = [
  'expo.modules.notifications.service.ExpoFirebaseMessagingService',
  'com.google.firebase.messaging.FirebaseMessagingService',
  'com.google.firebase.components.ComponentDiscoveryService',
  'com.google.mlkit.common.internal.MlKitComponentDiscoveryService',
  'com.google.android.datatransport.runtime.backends.TransportBackendDiscovery',
  'com.google.android.datatransport.runtime.scheduling.jobscheduling.JobInfoSchedulerService',
];
const REMOVE_RECEIVERS = [
  'com.google.firebase.iid.FirebaseInstanceIdReceiver',
  'com.google.android.datatransport.runtime.scheduling.jobscheduling.AlarmManagerSchedulerBroadcastReceiver',
];
const REMOVE_PROVIDERS = [
  'com.google.firebase.provider.FirebaseInitProvider',
  'com.google.mlkit.common.internal.MlKitInitProvider',
];
const REMOVE_ACTIVITIES = [
  'com.google.mlkit.vision.codescanner.internal.GmsBarcodeScanningDelegateActivity',
];
const REMOVE_META_DATA = [
  'com.google.mlkit.vision.DEPENDENCIES',
];

module.exports = (config) => {
  return withAndroidManifest(config, (cfg) => {
    const manifest = cfg.modResults.manifest;

    // Strip exp+myhrt scheme from every intent-filter in every activity.
    const activities = manifest.application?.[0]?.activity ?? [];
    for (const activity of activities) {
      for (const filter of activity['intent-filter'] ?? []) {
        if (Array.isArray(filter.data)) {
          filter.data = filter.data.filter(
            (d) => d.$?.['android:scheme'] !== 'exp+myhrt'
          );
        }
      }
    }

    // Firebase / ML Kit manifest-surface removal, release builds only.
    if (process.env.MYHRT_BLOCK_INTERNET === '1') {
      // tools:node="remove" markers need the tools namespace on <manifest>.
      manifest.$ = manifest.$ || {};
      if (!manifest.$['xmlns:tools']) {
        manifest.$['xmlns:tools'] = 'http://schemas.android.com/tools';
      }

      const app = manifest.application?.[0];
      if (app) {
        const addRemoveMarkers = (key, names) => {
          const list = app[key] || (app[key] = []);
          for (const name of names) {
            const already = list.some(
              (el) =>
                el.$?.['android:name'] === name &&
                el.$?.['tools:node'] === 'remove'
            );
            if (!already) {
              list.push({ $: { 'android:name': name, 'tools:node': 'remove' } });
            }
          }
        };
        addRemoveMarkers('service', REMOVE_SERVICES);
        addRemoveMarkers('receiver', REMOVE_RECEIVERS);
        addRemoveMarkers('provider', REMOVE_PROVIDERS);
        addRemoveMarkers('activity', REMOVE_ACTIVITIES);
        addRemoveMarkers('meta-data', REMOVE_META_DATA);
      }
    }

    return cfg;
  });
};
