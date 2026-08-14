// Expo config plugin — forces react-native-android-widget's RNWidgetImageProvider
// to be NON-exported and permission-gated (SEC-002).
//
// This provider serves rendered widget images, which contain medication names,
// so it must not be readable by other apps on the device. react-native-android-
// widget declares it in its OWN library AndroidManifest, which Gradle merges into
// the app manifest LATE — after all config plugins have run. At prebuild time the
// provider is therefore NOT yet present in the manifest object, so an in-place
// `findIndex(...).exported = 'false'` silently does nothing. Verified on a real
// build: the provider shipped android:exported="true" with no permission,
// regardless of where this plugin sat in the plugin list.
//
// The working fix is the same mechanism withManifestHardening uses to strip
// Firebase's (also library-merged) entry points: declare a matching <provider>
// stub in the higher-priority MAIN manifest with tools:replace, which the Gradle
// manifest merger honors over the library value. The element is matched by
// android:name; the authorities and the meta-data child come from the library,
// so only android:exported and android:permission are overridden.
const { withAndroidManifest } = require('@expo/config-plugins');

const PROVIDER_NAME = 'com.reactnativeandroidwidget.RNWidgetImageProvider';

module.exports = (config) => {
  return withAndroidManifest(config, (cfg) => {
    const manifest = cfg.modResults.manifest;

    // tools:replace requires the tools namespace declared on <manifest>.
    manifest.$ = manifest.$ || {};
    if (!manifest.$['xmlns:tools']) {
      manifest.$['xmlns:tools'] = 'http://schemas.android.com/tools';
    }

    const app = manifest.application && manifest.application[0];
    if (!app) return cfg;

    const providers = app.provider || (app.provider = []);
    const secured = {
      'android:name': PROVIDER_NAME,
      'android:exported': 'false',
      // grantUriPermissions lets the LAUNCHER read each rendered widget image via
      // the temporary per-URI grant the library issues (RemoteViews.setImageViewUri
      // sets FLAG_GRANT_READ_URI_PERMISSION). Without it, exported="false" leaves
      // the launcher with no way in, and the widget shows "can't load widget"
      // (Permission Denial opening RNWidgetImageProvider from com.miui.home /
      // com.sec... observed on-device, 2026-08-12). Do NOT add
      // android:permission="BIND_APPWIDGET" here — that is for the widget RECEIVER,
      // not this image provider, and it blocks the launcher's read. Net effect:
      // other apps still cannot read the images (not exported, no blanket grant),
      // but the launcher can, so widgets render AND stay private.
      'android:grantUriPermissions': 'true',
      // Only android:exported conflicts with the library value (true); the merger
      // takes grantUriPermissions in without a tools:replace since the library does
      // not declare it.
      'tools:replace': 'android:exported',
    };

    const existing = providers.find(
      (p) => p.$ && p.$['android:name'] === PROVIDER_NAME
    );
    if (existing) {
      Object.assign(existing.$, secured);
    } else {
      providers.push({ $: secured });
    }
    app.provider = providers;
    return cfg;
  });
};
