# Security model

The tool assumes the operator owns and trusts the host and rooted source device.
Root and dynamic instrumentation can read all source-app data; the tool narrows its
own behavior but cannot make a compromised device trustworthy.

## Protected

- Secrets are not printed, placed in argv, copied to shared Android storage, or
  committed by default patterns.
- Session and backup files require owner-only permissions and regular-file semantics.
- App Bluetooth is off and normal initialization is parked during extraction.
- Encrypted source preferences must remain unchanged.
- Ambiguous or malformed state fails closed.
- AAPS import leaves the app stopped and excludes protocol write/read counters.

## Residual risks

- A source app/runtime upgrade can invalidate hooks or storage assumptions.
- SIGKILL, host crash, or USB removal can defer cleanup until the source reconnects.
- The stored app key may not be the current pump key.
- Root malware, host malware, shell history, backups, or filesystem compromise are
  outside the tool's protection boundary.
- The source app's pump-identity association is inferred from its local database,
  not cryptographically bound by this tool. `--expect-pump` checks that stored identity.

Run `recover` after an interruption and independently authenticate the resulting
session with a read-only pump operation.
