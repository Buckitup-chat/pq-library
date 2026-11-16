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

## Compatibility and releases

Protocol or derivation changes require a major version. Compatibility must be
verified for each claimed service integration. Known limitations of the
currently audited implementation are recorded in
[service compatibility](backend-dependencies.md). They are constraints of that
integration.
