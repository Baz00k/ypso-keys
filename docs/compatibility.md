# Compatibility

## Verified source adapter

| Adapter | Application | App version | Android | Frida | Status |
|---|---|---:|---:|---:|---|
| `mylife-maui-v1` | mylife App | 2.6.1.001 | 15 | 17.17.0 | Repeatable live captures; encrypted preferences unchanged |

Device make/model and ADB identifiers are intentionally irrelevant. Compatibility
is based on storage layout and runtime versions, not a particular phone.

The extractor checks runtime prerequisites but cannot prove compatibility with
untested application/Android versions. Treat upgrades as a new validation target.

## Destination

AAPS export targets the preference keys used by the experimental YpsoPump driver:
`ypso_shared_key`, `ypso_pump_mac`, and optional `ypso_reboot_counter`.
Package and preference-file names are configurable at import time. Direct import
requires `run-as` access to the installed build.

## Not verified

- CamAPS extraction
- Other mylife versions or Android releases
- Fresh backend/pump key exchange
- Pump-side expiry semantics
- Direct import across all AAPS product flavors/signing configurations

A successful extraction establishes only that local app storage was read and
validated. Authenticated pump communication remains a separate verification step.
