# ypso-keys

A local CLI for recovering an existing YpsoPump session from an Android app that
owns it and preparing that session for AndroidAPS. It replaces manual or
LLM-assisted extraction with a repeatable, tested workflow.

The built-in source adapter supports the mylife App's AndroidX encrypted storage.
The source-adapter seam is intentionally separate from session validation and
AndroidAPS export, so other app versions or sources can be added without changing
the canonical format.

> Research software, not a medical device. Extraction does not prove that a key is
> current on the pump and does not renew a session. Verify it with authenticated,
> read-only status before relying on it.

## Requirements

- Linux or another host with `adb`
- Python 3.11+
- Rooted Android source device with the associated app and intact app data
- Matching Frida client/server versions
- A `frida-server` binary already present on the source device

## Install

```sh
uv tool install .
ypso-keys devices
```

The tool does not assume where `frida-server` was installed. Pass its absolute
path or configure it once in your shell:

```sh
export YPSO_KEYS_FRIDA_SERVER=/absolute/path/on/android/frida-server
```

## Usage

Always select devices by their exact ADB serial:

```sh
ypso-keys devices
ypso-keys doctor --source SOURCE_SERIAL --target TARGET_SERIAL
ypso-keys extract --source SOURCE_SERIAL --expect-pump AA:BB:CC:DD:EE:FF --json
```

Extraction writes a new `0600` session file to the application state directory.
Set `YPSO_KEYS_STATE_DIR` for an explicit location; otherwise the standard XDG
state location is used. Existing
outputs are never overwritten. Terminal and JSON output contain only metadata and
a key fingerprint. The session file contains the plaintext key and must remain
private.

```sh
ypso-keys inspect PATH.session.json
ypso-keys export-aaps PATH.session.json \
  --status-only --output aaps.prefs.xml

ypso-keys import-aaps PATH.session.json \
  --target TARGET_SERIAL --status-only --backup aaps-before.xml
```

Direct import needs an installed debuggable AAPS build because it uses Android's
`run-as` boundary. Package and preference names default to the common AndroidAPS
fork values and can be overridden:

```sh
ypso-keys import-aaps PATH.session.json --target TARGET_SERIAL --status-only \
  --aaps-package your.aaps.package --aaps-preferences ypso_ble_state \
  --backup aaps-before.xml
```

Import checks access before mutation, force-stops AAPS, preserves unrelated
preferences, removes stale read/write counters, writes through stdin and an atomic
rename, verifies the result, and leaves AAPS stopped. `--status-only` describes the
imported state; it does not disable therapy features in the driver.

If extraction is interrupted:

```sh
ypso-keys recover --source SOURCE_SERIAL
```

The recovery journal records only lifecycle resources and original Bluetooth
state. Cleanup checks process identity before terminating anything it owns.

## Safety properties

- No internet, backend call, BLE pump connection, or pump command during extraction
- Source Bluetooth is confirmed off before the app process is resumed
- The app main thread is parked before `Application.attach`; normal app startup is
  prevented while its Android Keystore-backed preferences are read
- Source app storage is hashed before and after extraction; changes fail closed
- Exactly one key namespace and one pump identity must be resolved
- No login credentials, application private keys, or write/read counters are exported
- Secret input/output uses restrictive files, no-clobber creation, no symlink
  following, and bounded size
- Worker timeouts, structured errors, cleanup journals, and device locks
- Stored key age is preserved; `review_after` is only an operational reminder and
  `pump_validity` remains `unverified`

## Source adapters

`--profile FILE` accepts a strict, data-only AndroidX EncryptedSharedPreferences
profile. See [`docs/profiles.md`](docs/profiles.md). The built-in adapter is
`mylife-maui-v1`; compatibility is verified for the app version listed in
[`docs/compatibility.md`](docs/compatibility.md). CamAPS is not yet supported.

New source strategies should return the canonical raw fields consumed by
`model.normalize()`. Keep app-specific Android APIs in the source worker, session
semantics in `model.py`, private persistence in `storage.py`, and destination
formatting in `aaps.py`.

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

Node is required only to rebuild the committed Frida agent bundle. CI reproduces
the bundle and checks for drift. Tests use synthetic keys and fake device/process
boundaries; no hardware operation runs in CI.

See [`docs/architecture.md`](docs/architecture.md),
[`docs/compatibility.md`](docs/compatibility.md),
[`docs/security.md`](docs/security.md), and [`docs/sources.md`](docs/sources.md).

## License

Apache License 2.0. See [`LICENSE`](LICENSE). Third-party notices are in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
