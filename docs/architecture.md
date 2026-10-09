# Architecture

```text
CLI
 ├─ profile validation
 ├─ Android lifecycle capture ─ bounded Frida worker ─ source adapter
 ├─ canonical Session validation
 ├─ private session storage
 └─ destination adapter (AndroidAPS)
```

The only worker so far reads AndroidX EncryptedSharedPreferences. It starts the source app paused and installs its hooks (small pieces of code that watch the app) before the app resumes. It holds the app's main thread before `Application.attach`, so the app never starts normally, and it reads only the values the profile names. The query that finds which pump the key belongs to depends on the source app.

ADB handles starting and stopping the app and cleanup. Frida runs in a separate process on the computer, so every call to it has a hard time limit. A private journal lets cleanup finish even if the computer was interrupted.

The tool finds the app's data folders at runtime from the installed package. The source profile lists which files inside the app to use. You supply the `frida-server` location and the folder where sessions are saved.

A session holds the pump's Bluetooth address, the 32-byte shared key, the key date from the source app, the capture date, an optional reboot counter, and adapter details that do not identify a device. It never holds source-device identifiers, credentials, private keys, or read and write counters.

The tool is written in Python because Frida's maintained bindings are Python. A Rust version would still need Frida, plus an extra binding and packaging layer.
