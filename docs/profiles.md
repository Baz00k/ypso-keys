# Source profile v1

A profile tells the tool where an app keeps its encrypted preferences and how to read them. It is a JSON file with exactly these fields:

```json
{
  "id": "example-encrypted-prefs-v1",
  "package": "org.example.app",
  "preferences": "encrypted_preferences",
  "preferences_path": "shared_prefs/encrypted_preferences.xml",
  "alias": "_androidx_security_master_key_",
  "identity": "explicit",
  "identity_config": null,
  "encoding": "base64",
  "fields": {
    "shared_key": "sharedKey",
    "created_at": "sharedKeyDate",
    "reboot_counter": "rebootCounter"
  }
}
```

This example shows the format only. It is not a working CamAPS configuration; you must fill in values verified for the app and version. Pass the file with `--profile` to `doctor` or `extract`.

- `identity`: how the tool learns which pump the key belongs to. `mylife-db-v1` reads the mylife database and converts the stored UUID to the pump's Bluetooth address. `explicit` requires both `--expect-pump` and `--pump-serial` on the command line and records that.
- `preferences_path`: path to the encrypted file inside the app's data folder. It is only used to confirm the file did not change. It must be relative and cannot contain `..`.
- `identity_config`: `null` for explicit identity. The built-in mylife adapter keeps its database path and fixed read-only query here. A custom profile that uses `mylife-db-v1` must repeat the built-in query exactly. Any other SQL is rejected, and a different database schema needs a new, reviewed identity strategy in the code.
- `encoding`: `hex` or `base64`, nothing else. The tool does not guess the encoding or scan memory.
- `fields`: must contain exactly `shared_key`, `created_at`, and `reboot_counter`. Their values are the preference name endings to look for, and each must be different. The tool finds the one stored entry whose name ends with the `shared_key` name, then reads the other two fields with the same prefix. No match, or more than one, is an error.
- Key date: a 13-digit Unix timestamp in milliseconds. Other formats need a separately tested converter. The tool never guesses dates.
- Reboot counter: a decimal string, or `null` if absent. AAPS accepts 0 to 2147483647.
- The preferences file, both Tink keysets (the encryption keys AndroidX uses), and the master key alias must already exist. The tool never creates a master key or app key storage.

Profiles hold only paths inside the app. They contain no executable paths and no absolute paths specific to one phone, because the tool finds the app's data folder from the installed package.

## Adding a new source

Write a separate, bounded worker behind `capture()` that returns the raw fields `normalize()` expects. Keep Android-specific code out of `model.py`, secret storage in `storage.py`, and AAPS preferences in `aaps.py`.

Add tests that inject failures, and test on real hardware, before calling an adapter supported. When you upgrade the host, server, or bridge versions, pin them and rerun the unchanged-storage check.
