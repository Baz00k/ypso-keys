# ypso-keys

A command-line tool that copies the session key of a YpsoPump from the mylife App on a rooted Android phone and prepares it for AndroidAPS (AAPS). The session key is the secret the app and the pump share to talk to each other over Bluetooth.

> Research software, not a medical device. Reading a key does not prove the pump still accepts it, and this tool cannot renew it. Before relying on a key, confirm it works with a read-only status request to the pump.

Only the mylife App is supported (version 2.6.1.001 on Android 15 is the one verified). CamAPS is not supported.

## What you need

- A computer running Linux (or similar) with `adb` (Android Debug Bridge, which lets the computer control a phone over USB) and Python 3.11 or newer
- A rooted Android phone, called the source, with the mylife App installed and its data intact
- Frida, the tool this program uses to read the app's stored settings. The `frida-server` program must already be on the source phone, and its version must match the Frida version on the computer
- For direct import only: a second phone, called the target, running a debuggable AAPS build

## Install

```sh
uv tool install .
ypso-keys devices
```

Tell the tool where `frida-server` is on the source phone, either with `--frida-server` or once in your shell:

```sh
export YPSO_KEYS_FRIDA_SERVER=/absolute/path/on/android/frida-server
```

## Usage

`ypso-keys devices` lists connected phones with their ADB serial numbers. Every command that touches a phone needs the exact serial, so the tool never picks a device for you.

1. Check the setup, then extract the key. `--expect-pump` is the pump's Bluetooth address. Extraction fails if the app has a different pump stored.

   ```sh
   ypso-keys devices
   ypso-keys doctor --source SOURCE_SERIAL --target TARGET_SERIAL
   ypso-keys extract --source SOURCE_SERIAL --expect-pump AA:BB:CC:DD:EE:FF --json
   ```

   Extraction saves a new session file that only you can read (permissions `0600`). By default it goes in `~/.local/state/ypso-keys`; set `YPSO_KEYS_STATE_DIR` to use another folder. The tool never overwrites an existing file. Screen and JSON output show only metadata and a key fingerprint. The session file holds the key in plain text, so keep it private.

2. Check the session file, then send it to AAPS. `export-aaps` writes a preferences file you can place into AAPS yourself. `import-aaps` writes it directly into AAPS on the target phone.

   ```sh
   ypso-keys inspect PATH.session.json
   ypso-keys export-aaps PATH.session.json \
     --status-only --output aaps.prefs.xml

   ypso-keys import-aaps PATH.session.json \
     --target TARGET_SERIAL --status-only --backup aaps-before.xml
   ```

   `--status-only` is required. It leaves out the read and write counters, but it does not switch off therapy features in the AAPS driver.

   Direct import needs a debuggable AAPS build, because it uses Android's `run-as` feature to reach the app's private files. The package name defaults to `info.nightscout.androidaps` and the preferences file to `ypso_ble_state`. Override them if your build differs:

   ```sh
   ypso-keys import-aaps PATH.session.json --target TARGET_SERIAL --status-only \
     --aaps-package your.aaps.package --aaps-preferences ypso_ble_state \
     --backup aaps-before.xml
   ```

   Import checks access first, then stops AAPS, keeps your other settings, removes old read and write counters, writes the new file in one step, and verifies the result. It saves your original settings to the `--backup` file and leaves AAPS stopped.

3. If extraction is interrupted (for example, the cable is unplugged), clean up with:

   ```sh
   ypso-keys recover --source SOURCE_SERIAL
   ```

   The tool keeps a small private log of what it changed: the processes it started and the phone's original Bluetooth setting. `recover` uses that log and confirms a process is still the one it started before stopping it.

## Safety

- Extraction uses no internet, no mylife backend, no Bluetooth connection to the pump, and sends no pump commands.
- Bluetooth on the source phone is confirmed off before the app resumes.
- The app is held paused while its stored settings are read, so it never starts normally.
- The app's storage is hashed before and after extraction. Any change makes the run fail.
- Exactly one key and one pump must be found, or the run fails.
- Login credentials, the app's private keys, and read and write counters are never exported.
- Secret files are private, never overwrite existing files, never follow symlinks, and have a size limit.
- Timeouts, clear error messages, cleanup logs, and locks that stop two runs on the same phone.
- The key's age is saved as `created_at`. A key lasts at most 28 days from that date. See [Session key lifetime](docs/compatibility.md#session-key-lifetime).

## Other apps

`--profile FILE` accepts a JSON description of another app that stores keys in AndroidX EncryptedSharedPreferences. See [`docs/profiles.md`](docs/profiles.md). The built-in profile is `mylife-maui-v1`. Tested versions are listed in [`docs/compatibility.md`](docs/compatibility.md).

Developers adding a new source should return the raw fields that `model.normalize()` expects. Keep app-specific Android code in the source worker, session rules in `model.py`, private file handling in `storage.py`, and AAPS formatting in `aaps.py`.

## Development

```sh
uv sync --locked
npm ci
npm run build:agent
uv run pytest -q
uv run mypy src
uv run ruff check src tests
uv run ruff format --check src tests
uv build
```

Node is only needed to rebuild the bundled Frida script. CI rebuilds it and fails if the result differs from the committed copy. Tests use fake keys and simulated devices; CI never touches real hardware.

More detail: [architecture](docs/architecture.md), [compatibility](docs/compatibility.md), [security](docs/security.md), [sources](docs/sources.md).

## License

Apache License 2.0. See [`LICENSE`](LICENSE). Third-party notices are in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
