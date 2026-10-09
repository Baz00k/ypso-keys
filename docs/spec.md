# Product contract

## Requirements

- Recover an existing YpsoPump session from a rooted Android phone the user owns.
- Require the user to pick the ADB device explicitly. Never choose the first one connected.
- Make no assumptions tied to a specific machine, phone, account, repository owner, or installation.
- Do not hardcode paths to external programs or to Android private data folders.
- Offer one documented CLI with redacted, structured output and stable error codes.
- Keep source adapters, session validation, secure storage, and destinations separate.
- Test malformed state, partial failures, cleanup, concurrent runs, and secret handling.
- Never print or commit keys. Store them in restrictive local files.
- Keep the key's age. Never suggest that extraction renews or authenticates a session.
- Send no pump commands. Leave the source app's storage unchanged and restore the phone's original state.
- Support status-only AAPS export, and import into builds that allow `run-as`.
- Label unsupported sources, including CamAPS, as unsupported instead of guessing.

## Rules for contributors

- Use fixed error messages with no secrets. Never pass on output from external commands or tracebacks.
- Keep secrets out of command-line arguments, console output, tests, fixtures, docs, Git, and CI artifacts.
- Validate identifiers before putting them in a shell command, and quote every external value.
- Stop on unclear or malformed state. Never replace corrupt preferences with an empty set.
- Run every independent cleanup step even if another one fails.
- Hardware tests must be opt-in and never run in CI.
