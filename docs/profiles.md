# Source profile v1

An alternate encrypted-preferences profile has exactly these fields:

```json
{
  "id": "example-encrypted-prefs-v1",
  "package": "org.example.app",
  "preferences": "encrypted_preferences",
  "alias": "_androidx_security_master_key_",
  "identity": "explicit",
  "encoding": "base64",
  "fields": {
    "shared_key": "sharedKey",
    "created_at": "sharedKeyDate",
    "reboot_counter": "rebootCounter"
  }
}
```

This is a schema example, **not a working CamAPS configuration**. Supply actual
values verified for that app/version. `--profile` is accepted by doctor and extract.

- `identity`: `mylife-db-v1` uses the observed mylife tables and UUID-to-MAC mapping;
  `explicit` requires both `--expect-pump` and `--pump-serial` and records that provenance.
- `encoding`: exactly `hex` or `base64`. No heuristic decoding or memory scanning.
- `fields`: exactly the three unique preference suffixes shown. The worker finds
  one prefix ending in the session key suffix and reads the same prefix for the
  other fields. Zero/multiple matches fail.
- Key date: 13-digit Unix epoch milliseconds. Another representation needs a
  separately tested normalizer, not guessing dates.
- Reboot counter: decimal string or absent (`null`); range 0..2147483647 for AAPS.
- Existing preference file, both Tink keysets and master alias must already exist.
  The tool never provisions a master key or intentionally creates app key storage.

Profiles contain storage metadata, not external executable paths or device-specific
filesystem locations. Android app data directories are resolved from package metadata.

To add a new extraction strategy, implement a separate bounded worker behind
`capture()` and return the normalized raw fields consumed by `normalize()`. Keep
Android-specific APIs out of `model.py`, secret persistence in `storage.py`, and
AAPS preferences in `aaps.py`. Add failure-injection tests and actual hardware
evidence before describing an adapter as supported. Pin host/server/bridge versions
and rerun unchanged-storage validation when upgrading any of them.
