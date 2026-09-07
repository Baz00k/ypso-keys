import Java from 'frida-java-bridge';

// Install before resuming a Frida-spawned process. Park its main thread BEFORE
// Application.attach executes; application initialization, activities and services
// cannot run. The host kills this process after reading; the latch is never released.
let donorContext = null;
Java.performNow(() => {
  Java.use('android.app.ContextImpl').getApplicationContext.implementation = function () {
    return this;
  };
  Java.use('android.app.Application').attach.overload('android.content.Context')
    .implementation = function (context) {
      donorContext = Java.retain(context);
      Java.classFactory.loader = context.getClassLoader();
      Java.use('java.util.concurrent.CountDownLatch').$new(1).await();
    };
});

// The host imposes a deadline and always force-stops the app after this RPC.
rpc.exports.read = (config) => new Promise((resolve, reject) => {
  Java.performNow(() => {
    let stage = 'context';
    try {
      const context = donorContext;
      if (context === null) { reject(new Error('CONTEXT_NOT_READY')); return; }
      stage = 'bluetooth';
      const adapter = Java.use('android.bluetooth.BluetoothAdapter').getDefaultAdapter();
      if (adapter !== null && adapter.getState() !== 10) {
        reject(new Error('BLUETOOTH_NOT_OFF')); return;
      }
      stage = 'file';
      const file = Java.use('java.io.File').$new(
        context.getApplicationInfo().dataDir.value + '/shared_prefs/' + config.preferences + '.xml');
      if (!file.isFile()) { reject(new Error('PREFERENCES_MISSING')); return; }
      const plain = context.getSharedPreferences(config.preferences, 0);
      for (const name of ['__androidx_security_crypto_encrypted_prefs_key_keyset__',
                          '__androidx_security_crypto_encrypted_prefs_value_keyset__']) {
        if (!plain.contains(name)) { reject(new Error('KEYSET_MISSING')); return; }
      }
      stage = 'keystore';
      const store = Java.use('java.security.KeyStore').getInstance('AndroidKeyStore');
      store.load(null);
      if (!store.containsAlias(config.alias)) { reject(new Error('MASTER_KEY_MISSING')); return; }
      stage = 'classes';
      const Prefs = Java.use('androidx.security.crypto.EncryptedSharedPreferences');
      const keys = Java.use('androidx.security.crypto.EncryptedSharedPreferences$PrefKeyEncryptionScheme');
      const values = Java.use('androidx.security.crypto.EncryptedSharedPreferences$PrefValueEncryptionScheme');
      stage = 'create';
      const prefs = Prefs.create.overload('java.lang.String', 'java.lang.String',
        'android.content.Context',
        'androidx.security.crypto.EncryptedSharedPreferences$PrefKeyEncryptionScheme',
        'androidx.security.crypto.EncryptedSharedPreferences$PrefValueEncryptionScheme')
        .call(Prefs, config.preferences, config.alias, context, keys.valueOf('AES256_SIV'),
          values.valueOf('AES256_GCM'));
      stage = 'read';
      // Decrypt preference NAMES only. Never enumerate credential/private-key values.
      const encryptedNames = plain.getAll().keySet().iterator();
      const prefixes = [];
      while (encryptedNames.hasNext()) {
        const encrypted = String(encryptedNames.next());
        if (encrypted.startsWith('__androidx_security_crypto_')) continue;
        const name = String(Java.cast(prefs, Prefs).decryptKey(encrypted));
        if (name.endsWith(config.fields.shared_key)) {
          prefixes.push(name.slice(0, -config.fields.shared_key.length));
        }
      }
      if (prefixes.length !== 1) { reject(new Error('AMBIGUOUS_KEY_RECORD')); return; }
      const result = {};
      for (const [field, name] of Object.entries(config.fields)) {
        const value = prefs.getString(prefixes[0] + name, null);
        result[field] = value === null ? null : String(value);
      }
      const info = context.getPackageManager().getPackageInfo(config.package, 0);
      result.app_version = String(info.versionName.value);
      if (config.identity === 'mylife-db-v1') {
        stage = 'identity';
        const db = Java.use('android.database.sqlite.SQLiteDatabase').openDatabase(
          context.getApplicationInfo().dataDir.value + '/files/mylifeHealthData.db', null, 1);
        try {
          const cursor = db.rawQuery('SELECT d.SerialNumber, m.UUID FROM "PATIENT.DEVICE" d ' +
            'JOIN DEVICE_NAME_MAPPING m ON m.DeviceId=d.DeviceId ' +
            'WHERE d.Active=1 AND m.Name LIKE \'YpsoPump_%\'', null);
          try {
            if (cursor.getCount() !== 1) { reject(new Error('AMBIGUOUS_PUMP_RECORD')); return; }
            cursor.moveToFirst();
            result.pump_serial = String(cursor.getString(0));
            result.pump_uuid = String(cursor.getString(1));
          } finally { cursor.close(); }
        } finally { db.close(); }
      }
      resolve(result);
    } catch (_) {
      reject(new Error('PREFERENCE_READ_FAILED_' + stage));
    }
  });
});
