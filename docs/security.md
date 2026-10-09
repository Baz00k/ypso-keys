# Security model

The tool assumes you own and trust both the computer and the rooted phone. Root access and instrumentation can read everything in the source app. The tool limits what it does itself but cannot make a compromised device safe.

## What the tool protects

- Keys are never printed, passed on the command line, or copied to shared Android storage. The default `.gitignore` patterns keep session files out of Git.
- Session and backup files must be regular files readable only by you.
- During extraction, Bluetooth on the source phone is off and the app is held paused.
- The app's encrypted preferences must stay unchanged.
- Unclear or malformed state stops the run.
- AAPS import leaves the app stopped and excludes read and write counters.

## Remaining risks

- An update to the source app or to Android can break the tool's assumptions.
- If the tool is killed, the computer crashes, or the USB cable is pulled, cleanup waits until the phone reconnects.
- The key stored in the app may not be the one the pump currently uses.
- Malware on the phone or computer, shell history, backups, and filesystem compromise are outside what the tool can protect.
- The link between the key and a pump is inferred from the app's local database. The tool does not verify it cryptographically. `--expect-pump` only compares against the stored identity.

After an interruption, run `recover`. Then confirm the session works with a read-only request to the pump.
