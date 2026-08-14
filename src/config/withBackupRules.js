// Expo config plugin — overwrites expo-secure-store's default backup rule XMLs
// with versions that exclude all domains from both cloud-backup and device-transfer.
//
// Why this exists: expo-secure-store's bundled defaults include all SharedPreferences
// (except its own) in cloud-backup and device-transfer. allowBackup:false in app.json
// blocks cloud backup at the app level, but device-transfer (Android 12+ "Copy my data"
// flow) is a separate mechanism not covered by allowBackup. AsyncStorage (non-sensitive
// UI state) would otherwise transfer. This plugin runs after expo-secure-store's plugin
// and overwrites both XML files so no domain transfers by any path.
const { withDangerousMod } = require('@expo/config-plugins');
const path = require('path');
const fs = require('fs');

const BACKUP_RULES_XML = `<?xml version="1.0" encoding="utf-8"?>
<!-- Auto Backup rules for Android 11 and lower — exclude everything -->
<full-backup-content>
  <exclude domain="root" path="."/>
  <exclude domain="file" path="."/>
  <exclude domain="database" path="."/>
  <exclude domain="sharedpref" path="."/>
  <exclude domain="external" path="."/>
</full-backup-content>
`;

const DATA_EXTRACTION_RULES_XML = `<?xml version="1.0" encoding="utf-8"?>
<!-- Auto Backup rules for Android 12+ — exclude everything from cloud and device-transfer -->
<data-extraction-rules>
  <cloud-backup>
    <exclude domain="root" path="."/>
    <exclude domain="file" path="."/>
    <exclude domain="database" path="."/>
    <exclude domain="sharedpref" path="."/>
    <exclude domain="external" path="."/>
  </cloud-backup>
  <device-transfer>
    <exclude domain="root" path="."/>
    <exclude domain="file" path="."/>
    <exclude domain="database" path="."/>
    <exclude domain="sharedpref" path="."/>
    <exclude domain="external" path="."/>
  </device-transfer>
</data-extraction-rules>
`;

module.exports = (config) => {
  return withDangerousMod(config, [
    'android',
    (cfg) => {
      const xmlDir = path.join(cfg.modRequest.platformProjectRoot, 'app', 'src', 'main', 'res', 'xml');
      fs.mkdirSync(xmlDir, { recursive: true });
      fs.writeFileSync(path.join(xmlDir, 'secure_store_backup_rules.xml'), BACKUP_RULES_XML, 'utf8');
      fs.writeFileSync(path.join(xmlDir, 'secure_store_data_extraction_rules.xml'), DATA_EXTRACTION_RULES_XML, 'utf8');
      return cfg;
    },
  ]);
};
