# SDK development

This repository owns @buckitup/pq-client. Consumers import built module entry points. Keep production code
independent of application source trees and UI frameworks.

The versioned documentation, exported types, schemas and conformance vectors
in this repository define the released contract. Changes to cryptographic
payloads or derivations require an explicit protocol version decision and
compatible vectors. Service implementations are integration targets; their
source does not silently change the SDK's released contract.

Run npm run typecheck, npm run lint, npm test and npm run build. Verify packed
exports with npm run check:consumer -- /absolute/path/to/package.tgz. Optional
CHAT_REPO tooling checks compatibility with an Ecto service schema; it is not
required to build, test the protocol, or consume the package.

Integration-dependent acceptance and known storage concurrency limits must
not be presented as verified by the fake server.

Keep code and shared documentation in English. Do not log secret keys.
The license is GPL-3.0-only. Use the Node version in .nvmrc.
