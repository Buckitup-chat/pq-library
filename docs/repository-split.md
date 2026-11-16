# Repository split

This repository owns the SDK sources, protocol tests, backend schema generator,
consumer checks and npm release workflow. `chat-frontend` consumes the built
package through its exports; it has no workspace or source alias to this repo.

The repository split preserves runtime source bytes. `extraction-manifest.json` records
the extracted source hashes over frontend baseline 507d0ff plus its working tree.
Frontend integration fixtures stay in frontend tests and use the public SDK.

`CHAT_REPO=/path/to/chat npm run schema:check` checks backend schema drift.
No backend checkout is needed to build or consume this package; the optional
schema-generator test is skipped without one.

The SDK retains GPL-3.0-only from chat-frontend, as required by the original
partner specification. `LICENSE` and the package declaration agree.
