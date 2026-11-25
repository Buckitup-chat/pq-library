# Protocol and integration contract

@buckitup/pq-client implements identity keys, canonical signed rows, encrypted
dialogs, storage slots and authenticated service requests. Exported types,
schemas and conformance vectors describe the supported wire format.

## Local operations

Identity generation, row signing and verification, encryption, key wrapping,
message construction and envelope operations run locally. Browser vault
operations additionally require IndexedDB and WebAuthn PRF support. See the
[README](../README.md) for environment requirements.

## Service operations

`createTransport` accepts a base URL and an optional fetch implementation.
Its HTTP adapter implements challenge/proof requests, signed mutations through
`ingest` and `ingest_each`, shape reads, live updates and read sessions. A service
must implement the expected endpoints, row schemas, encodings and responses.

The SDK's Transport interface can also be implemented by an adapter for another
service, provided that adapter preserves the outcomes and guarantees expected
by the higher-level APIs. An arbitrary HTTP API is not automatically compatible.

## Canonical rows

The signed fields are selected by the SDK relation schema. Fields are ordered
lexicographically, encoded canonically and framed with a big-endian 32-bit byte
length. ML-DSA-87 signs that payload. Binary normalization, signature hashes
and row verification must match the versioned conformance vectors. See
[row encoding](row-encoding.md) and `src/schema.generated.ts`.

## Consumer responsibilities

Consumers choose server endpoints, identity lifecycle, UI, domain policy,
durable pending-write storage, notifications and offline behavior. A successful
write response is distinct from visibility in a subscription. Unknown write
outcomes must be reconciled before constructing replacement writes.

For device-storage access following contact confirmation, the SDK provides the
reusable [`contactAccess`](contact-access.md) policy: initial-grant decisions,
explicit grant/revoke, device-scoped request reconciliation and view state.
Applications choose to invoke it, persist contacts, provide its infrastructure
adapters, schedule retries and render the UI. The service does not move camera
handling, durable storage or an offline delivery engine into the SDK. Other
admission flows, such as partner one-time codes, remain consumer policies.
The backend still determines effective permission through its gates and trust
chain. This additive API uses the existing signed `vouch_tokens` wire format.

## Compatibility and releases

Protocol or derivation changes require a major version. Compatibility must be
verified for each claimed service integration. Known limitations of the
currently audited implementation are recorded in
[service compatibility](backend-dependencies.md). They are constraints of that
integration.

## Initial requirements and acceptance

The [partner venue messaging requirement](https://github.com/Buckitup-chat/chat/blob/docs/partner-venue-messaging/docs/pq/reqs/pq_partner_venue_messaging.proposed.md)
defines the eight partner-facing modules and the venue messaging flows. The
SDK is maintained in this standalone repository following the team's repository
split decision. Its protocol tests, golden vectors, build and release tooling
belong here. Applications retain their integration and UI tests; the
requirement's Phase 1 explicitly requires frontend tests to pass on the SDK.

Known differences from the initial document must remain explicit:

- Multi-identity sessions are managed by `identity.createIdentitySession`.
  The vault helpers store one identity's key set per vault, while venue keys
  are stored in the owner's User Storage. The initial module table assigns
  multi-identity sessions to `vault`.
- Venue creation stores V's keys before publishing V's card and origin, so an
  interrupted publication can resume the same identity. The initial flow
  places key storage last. See the README's origins lifecycle.
- Guaranteed simultaneous multi-device storage merge and universal
  `missing_parent` errors are not provided by the audited service contract;
  see [service compatibility](backend-dependencies.md).
- Local tests and a published npm package do not establish the partner-server
  Phase 2 acceptance: second-device replies, content-free notifications and
  effective write refusal after vouch retraction require that deployment.

These differences are not resolved by relocating tests or documentation.
