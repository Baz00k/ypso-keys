# Architecture

```text
CLI
 ├─ profile validation
 ├─ Android lifecycle capture ─ bounded Frida worker ─ source adapter
 ├─ canonical Session validation
 ├─ private session storage
 └─ destination adapter (AndroidAPS)
```

The current worker supports AndroidX EncryptedSharedPreferences. It spawns the
source app suspended, installs hooks before resume, parks the main thread before
`Application.attach`, and reads only configured values. A read-only identity query
is source-specific.

ADB owns outer lifecycle and cleanup. Frida runs in a separate host process so RPC
calls have a hard deadline. A private journal makes cleanup recoverable after host
interruption. Android app data directories are resolved dynamically from package
metadata; app-relative files are declared by the versioned source profile. Source
Frida path and host application state directory are explicit configuration.

The canonical session contains pump identity, 32-byte shared key, source key date,
capture date, optional reboot counter, and non-device-specific adapter provenance.
It intentionally excludes source-device identifiers, credentials, private keys,
read counters, and write counters.

Python is used because Frida's maintained bindings are Python-native. A Rust front
end would still require a Frida runtime boundary while adding another binding and
packaging layer.
