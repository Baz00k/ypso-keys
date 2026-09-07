# Product contract

## Requirements

- Recover an existing YpsoPump session from a user-owned rooted Android source.
- Require explicit ADB device selection; never choose the first connected device.
- Avoid machine-, phone-, account-, repository-owner-, and installation-specific assumptions.
- Do not hardcode external executable paths or Android private data directories.
- Provide one documented CLI with structured, redacted output and stable error codes.
- Separate source adapters, canonical session validation, secure persistence, and destinations.
- Test malformed state, partial failures, cleanup, concurrency, and secret handling.
- Never print or commit keys; use restrictive local files.
- Preserve key age and never imply extraction renews or authenticates a session.
- Send no pump commands; preserve source storage and restore lifecycle state.
- Support status-only AAPS export and explicit import into builds granting `run-as` access.
- Keep unsupported sources, including CamAPS, clearly labeled rather than guessed.

## Coding and security standards

- Static non-secret errors; never forward external command output or tracebacks.
- No secret in argv, console, tests, fixtures, docs, Git, or CI artifacts.
- Validate identifiers before shell interpolation and quote all external values.
- Fail closed on ambiguous/malformed state. Never replace corrupt preferences with an empty map.
- Attempt independent cleanup actions even when another cleanup action fails.
- Hardware behavior must be opt-in and absent from CI.
