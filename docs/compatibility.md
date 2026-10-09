# Compatibility

## Verified source

| Adapter | Application | App version | Android | Frida | Status |
|---|---|---:|---:|---:|---|
| `mylife-maui-v1` | mylife App | 2.6.1.001 | 15 | 17.17.0 | Repeated captures worked; encrypted preferences unchanged |

Phone make and model do not matter. What matters is the app's storage layout and the Android and Frida versions.

The tool checks its prerequisites but cannot confirm that other app, Android, or Frida versions work. Treat any other version as untested.

## Destination

The AAPS export writes the preference keys the experimental YpsoPump driver reads: `ypso_shared_key`, `ypso_pump_mac`, and optionally `ypso_reboot_counter`. You can change the package and preference file names at import time. Direct import needs `run-as` access to the installed AAPS build.

## Session key lifetime

A session key lasts at most 28 days.

- `created_at` is the app's `sharedKeyDate`, the closest value available to when the key was generated.
- `captured_at` is when you extracted the key. Extracting or re-exporting does not renew the key.

The key expires at `created_at` plus 28 days. The pump does not report an expiry time, so the tool exports none.

## Not verified

- CamAPS extraction
- Other mylife versions or Android releases
- A fresh key exchange between the backend and the pump
- Direct import on every AAPS flavor and signing setup

A successful extraction only shows that the app's stored data was read and passed validation. Whether the pump accepts the key must be checked separately.
