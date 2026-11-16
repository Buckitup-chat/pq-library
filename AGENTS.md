# SDK development

This repository owns @buckitup/pq-client. Consumers import built module entry
points; do not introduce imports from chat-frontend, Vue, Pinia or TanStack.
Preserve cryptographic payloads and derivations during structural changes.
Golden vectors in tests pin the protocol. The backend source is the wire
contract; set CHAT_REPO to check schemas with npm run schema:check.

Run npm run typecheck, npm run lint, npm test and npm run build. Verify packed
exports with npm run check:consumer -- /absolute/path/to/package.tgz.
Backend-dependent acceptance and known storage concurrency limits must not
be presented as verified by the fake server.

Keep code and shared documentation in English. Do not log secret keys.
The license is GPL-3.0-only, as required by the original partner specification.
Use the Node version in .nvmrc for development and CI.
