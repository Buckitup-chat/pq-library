# @buckitup/pq-client completion plan

Historical document retained from chat-frontend during the repository split.
Paths, commands, test counts and completion marks describe their recorded
baseline; use the [current documentation index](../README.md) for the supported
SDK and [frontend integration](https://github.com/Buckitup-chat/chat-frontend/blob/main/docs/pq-client-integration.md) for the app.

Status: in progress. Stages 0–6 are done (§ 16). Stage 7 is prepared and
checked locally; the package is not published (§ 16.19). Stage 8 waits for
the partner's test server.

## 1. Task and scope

Finish the framework-independent TypeScript SDK `@buckitup/pq-client` in
`chat-frontend/packages/pq-client`, move the protocol logic the frontend shares
with other clients onto it, and prepare it for the public npm registry.

The package exists and the app already uses part of it; this is a continuation,
not a new library. It stays in the frontend repository, next to the app, as the
specification places it.

The plan covers technical work only: modules, dependencies, protocol, frontend
migration, verification and delivery. The roles VO (venue owner) and V (venue)
appear only to define keys and authorization.

The plan distinguishes:

- **Requirement** — set by the specification or the protocol.
- **Code fact** — confirmed in the files named.
- **Recommendation** — a way to implement; not an additional product
  requirement.
- **Delivery question** — needs outside data or coordination.

## 2. Sources

### 2.1. Scope

[Partner Venue Messaging — proposed](https://github.com/Buckitup-chat/chat/blob/docs/partner-venue-messaging/docs/pq/reqs/pq_partner_venue_messaging.proposed.md),
branch `docs/partner-venue-messaging`, blob
`937706d36f52a0c89ff2b9a1192adc378826296d` (a file SHA, not a commit SHA).
Status proposed. Its sections: Decisions, Server operation, Flows, Venue keys,
Dialog key derivation, Client library, Out of scope, Phases, Open questions.

Wire contract from the same branch:
[external_client.md](https://github.com/Buckitup-chat/chat/blob/docs/partner-venue-messaging/docs/pq/external_client.md),
blob `98870bccf90534cd3cf47cc8fe7d54d540341f78`.

Where this plan and the specification differ, the specification wins.

### 2.2. Checkouts

| Repository | Revision | Note |
|---|---|---|
| chat-frontend | branch `feat/pq-client-rows` from `origin/main` `507d0ff` | All code facts refer to it |
| chat (backend) | local `a1f3a742`; the specification's baseline is `40d8c8e4` | 8 commits apart; `lib/chat/data/schemas` and `integrity.ex` are identical between them |

The backend is read as the contract and is not changed by this work.

### 2.3. Files checked

Paths are relative to the frontend repository unless marked as backend.

| Area | Files |
|---|---|
| Packaging | `packages/pq-client/package.json`, `tsconfig.build.json`, `scripts/smoke.mjs`, `README.md` |
| App wiring | `package.json`, `vite.config.js`, `tsconfig.json`, `.github/workflows/checks.yml` |
| Rows | `packages/pq-client/src/rows.ts`, `signature.ts`, `schema.ts`, `schema.generated.ts`, `verifyCard.ts`, `verifyDialogRow.ts` |
| Identity / vault | `packages/pq-client/src/identity.ts`, `vault.ts`, `vaultLock.ts`, `derivedIdentity.ts`, `vaultEnvelope.ts`; `src/libs/EncryptionManagerPQ.js`, `src/libs/accountVault.js`, `src/lib/data/keyCustody.ts` |
| Dialogs | `packages/pq-client/src/dialogs.ts`, `src/libs/DialogCrypto.js`, `src/store/dialogs.store.js`, `src/lib/data/messageIntent.ts` |
| Transport / reads | `packages/pq-client/src/transport.ts`, `src/lib/data/transport.ts`, `readSession.ts`, `collections.ts` |
| Storage | `packages/pq-client/src/slotId.ts`, `src/lib/data/slots.ts`, `userStorage.ts`, `storageIntent.ts` |
| Identity routing / vouch | `src/lib/data/sessionIdentities.ts`, `contactVouches.ts`, `writeContracts.ts`, `rowVerification.ts` |
| Schema generation / vectors | `scripts/gen-pq-schema.mjs`, `packages/pq-client/tests/conformance.test.ts`, `packages/pq-client/tests/vectors/pq-conformance.json` |
| Backend | `lib/chat/data/schemas/*.ex`, `lib/chat/data/integrity.ex`, `lib/chat/data/origin/validation.ex`, `lib/chat/data/origin_setting/validation.ex`, `lib/chat/data/types/consts.ex`, `test/fixtures/pq_conformance_vectors.json` |

## 3. State

| Module | Done | Remaining |
|---|---|---|
| Workspace package | `@buckitup/pq-client` 0.1.0, npm workspaces, ESM build with declarations, `./*` exports, Node smoke import | ✅ tarball consumer check (§ 16.16) |
| `rows` | ✅ Entry point: canonical payload, `signRow` / `verifyRow`, `sign_hash`, schemas of 12 relations generated from the backend, enum values, base64 rules | — |
| `identity` | ✅ Key generation, restore from secret keys with keypair checks, `user_cards` row and certificates, handles, multi-identity session, card publication | — |
| `vault` | ✅ PRF vault create/open/lock/drop, identity keys in the vault, typed errors; the app's PRF vault runs on it | — |
| `transport` | ✅ `baseUrl`, custom fetch, timeout, abort; key proof; `/ingest` and `/ingest_each` with typed rejections; complete snapshots; live shape subscriptions; read-session lifecycle; typed transport errors | Electric `columns`/`replica` options beyond `columns`; SSE live mode |
| `dialogs` | ✅ Spec derivation everywhere, wrap/unwrap, encryption, hashes, row builders, refs, opening a message with verification | Reactions and receipts builders stay in the app |
| `origins` | ✅ Creation (keys first, card, row), resume, update (VO or V signs, VO proves), settings, `owner_cert`, verification | — |
| `vouch` | ✅ Issue and retract, scopes; the app's contact vouches build rows on it | — |
| `storage` | ✅ Encryption, addressing, slot resolver, generic merge, signed writes reconciled on the current base, read outcomes, the `origins` slot | The app's outbox-driven storage path stays app-side (stage 6) |
| Conformance | Frontend vectors equal the backend file | Origin vectors (external, § 11.2) |
| npm | README, build, prepack | Release workflow, consumer validation, publication |

## 4. Target architecture

### 4.1. Dependencies

Direction: UI / app adapters → SDK → crypto, transport and storage primitives.

Requirements:

- The SDK imports neither Vue, Pinia, TanStack nor the app's `src/`.
- No `@/` alias, no frontend build constants, no `EncryptionManagerPQ`
  singleton.
- The server is a parameter: the transport takes an API base such as
  `https://host/electric/v1`.
- Each of the eight modules is an entry point `@buckitup/pq-client/<module>`.
- Existing entry points (`signature`, `verifyCard`, `vaultLock`, …) stay.

Importing a module performs no network request, no WebAuthn ceremony and no
storage access. Browser-only packages (`@lo-fi/*`, which needs libsodium as a
global) are loaded on the first call that needs them.

### 4.2. What stays in the frontend

Vue components, Pinia stores, TanStack collections, UI projections, routing,
the service worker, the Storage screen and the outbox orchestration. The SDK
does not take over the local database, the scheduler, the media cache or the
offline engine; it carries enough storage and transport logic that a partner
need not copy the protocol out of the app.

### 4.3. API contract

- An identity is a handle: `user_hash`, public keys, signing and decapsulation
  without exposing secret keys, `close()`.
- A row signature and a request's key proof are separate: `signRow` signs the
  row, the `sign` passed to the transport proves the request. Origin updates
  need them from different identities.
- Builders return rows or mutations; only functions that take a transport send.
- Server acceptance (`ingest` result) and shape visibility are different
  events.
- Verifiers take the author's verified public key from the caller.

## 5. Work by module

### 5.1. identity ✅

1. ✅ ML-DSA-87, ML-KEM-1024 and secp256k1 key generation
   (`generateIdentityKeys`).
2. ✅ `user_hash` from the signing public key (`userHashOf`, reused).
3. ✅ Certificates and the signed card (`cardKeyFields`, `unsignedUserCard`,
   `signedUserCard`); `derivedIdentity.signedUserCard` delegates to it.
4. ✅ `user_cards` rows signed through `rows.signRow`, with `owner_timestamp`
   and `deleted_flag`.
5. ✅ Restore from secret keys (`identityKeysFromSecrets`): public keys are
   recomputed and checked against an expected `user_hash` or public keys, with
   the mismatching key named (`IdentityKeysError.reason`). Each keypair must
   also work: ML-DSA `tr` equals SHAKE256(pk, 64) and a probe signature
   verifies; the ML-KEM secret key embeds the public key and its SHA3-256, and
   an encapsulation decapsulates to the same secret; the contact public key is
   derived from its secret key. A failing pair is `sign_keypair`,
   `crypt_keypair` or `contact_keypair`; temporary secret copies are wiped
   before the error is thrown. `openIdentity` runs the same checks, so no
   handle is made from a broken pair.
6. ✅ Generation, persistence (`vault.writeIdentityKeys`) and publication
   (`publishUserCard`) are separate functions.
7. ✅ Card verification is the existing `verifyUserCard`.
8. ✅ The card carries wire fields only.

A new identity's card is written in its own request, proved by that identity:
`publishUserCard` refuses a card of another identity.

Known limit of the keypair check: a corrupted ML-DSA `t0` keeps the public key
and makes only some signatures invalid (one probe caught 1 of 13 sampled
corruptions). An exact check recomputes `t0` = Power2Round(A·s1 + s2), which
`@noble/post-quantum` 0.5.4 does not expose. Corrupted ML-DSA `K` or ML-KEM
`z` leave every honest operation correct and are not detected.

### 5.2. vault ✅

Requirement: secret keys at rest under a passkey's WebAuthn PRF output; several
identities per session.

1. ✅ `vault` is built on `vaultLock` and the PRF part of `accountVault.js`,
   moved into the SDK; `accountVault.js` keeps its exports and delegates.
2. ✅ Browser dependencies are explicit: `credentials` and `rpId` are
   parameters; persistence is IndexedDB through `@lo-fi/local-vault`.
3. ✅ `createPrfVault`, `openPrfVault`, `lock()`, `dropPrfVault`;
   `writeIdentityKeys`, `readIdentityKeys`, `openVaultIdentity`. The stored
   format is the app's: ML-DSA and ML-KEM secret keys as bytes, the contact key
   as hex.
4. ✅ VO and V handles at once (`createIdentitySession`), no global current
   user.
5. ✅ A closed handle refuses signing, decapsulation and export
   (`IdentityClosedError`).
6. ✅ `lock()` wipes the vault's lock key; `close()` wipes a handle's key
   copies. JavaScript gives no guarantee that every copy of a secret is erased.
7. ✅ Typed errors: `PrfUnsupportedError`, `PrfMissingError`,
   `PasskeyMismatchError` (also when a passkey's PRF output does not decrypt
   the vault), `VaultLockedError`, `VaultMissingError`. The app's
   `VaultLockedError` is the SDK class.
8. ✅ `@lo-fi/local-vault` and `@lo-fi/local-data-lock` are dependencies of
   the package.

Without PRF the SDK throws; no fallback protocol is designed. The legacy vault,
recovery (`vaultEnvelope.ts`, passkey recovery) and the login path of
`EncryptionManagerPQ` stay in the app unchanged.

V's keys live in VO's User Storage (§ 5.8), not in a vault; once loaded they
become a handle through `identityKeysFromSecrets` and `openIdentity`.

Locking a vault does not close the handles opened from it; closing them is the
session's job.

### 5.3. rows ✅

1. ✅ One canonical serialization (`signature.ts`), exposed through `rows`.
2. ✅ `rows` re-exports it and adds `rowSignableFields`, `signRow`,
   `verifyRow`, `RowVerdict`, row types.
3. ✅ Wire row types are separate from app metadata.
4. ✅ `origins` and `origin_settings` are in schema generation.
5. ✅ The generator maps `Ecto.Enum` to text, emits its values
   (`ENUM_VALUES`), and resolves `sign_hash` prefixes from the backend types
   (`SIGN_HASH_PREFIX`: `uss_`, `dms_`, `ors_`).
6. ✅ `schema.generated.ts` is reproduced by the generator
   (`--check`, `tests/pqSchemaGen.test.ts`).
7. ✅ Padded base64 in the payload; unpadded shape values are normalized.
8. ✅ ML-DSA-87, pure, empty context.
9. ✅ `sign_hash` = prefix + hex(SHA3-512(signature bytes)). For a relation
   with a `sign_hash` column, `verifyRow` requires it: absent or empty is
   `missing_sign_hash`, different is `sign_hash_mismatch`.
10. ✅ `verifyRow` checks a row against the key it is given. Which key —
    V or VO for an origin — is decided in `origins` (§ 5.6).

`signRow` returns `SignedRow<T>`: the input's `sign_b64` / `sign_hash` types
are replaced, so a row built with `sign_b64: null` is typed `string` after
signing; a relation without `sign_hash` loses the field.

### 5.4. transport ✅

1. ✅ Parametric `baseUrl`, custom fetch, timeout and `AbortSignal`. A caller's
   signal is used as given (the caller owns its deadline); without one the
   transport's timeout applies.
2. ✅ `ingest`: `POST /ingest`, one transaction, `{ kind: 'written', txid }` or
   `{ kind: 'rejected', rejection }`; not a loop over `ingest_each`.
3. ✅ Every write takes a fresh challenge signed by the `sign` it is given:
   the proving identity is the caller's choice per request.
4. ✅ `ingest_each` keeps the cardinality, index and status checks and adds
   `rows`, one typed outcome per mutation. `ingestEachResponse` (raw) stays for
   the app's outbox.
5. ✅ `subscribeShape`: snapshot across pages, live long-poll with
   `handle` / `offset` / `cursor`, merge of partial updates, deletes, reset on
   409 or `must-refetch`, retries with backoff on network and 5xx failures,
   stop on other refusals, `dispose()` and the caller's signal abort the request
   in flight. `ready` resolves when the snapshot is up to date; `done` tells
   disposal from failure.
6. ✅ Implemented on the Electric HTTP API directly (`readShapeChunk`); no
   `@electric-sql/client` and no TanStack bridge in the SDK.
7. ✅ `createReadSessions` holds the lifecycle that was in `readSession.ts`;
   the app keeps card recovery and the access-gate marks as callbacks.
8. ✅ A session opens on `read_session_required`, renews 60 s before expiry,
   reopens after a 401 (once in a row in a subscription), and forgets every
   token on `dispose()`.
9. ✅ State is per instance: one instance per server and identity, tokens
   keyed by shape, tables mapped to the shape the server names.
10. ✅ `unknown_user` goes to the caller's `onUnknownUser` (publish the card,
    then one retry); the SDK never publishes by itself.
11. ✅ Rejections (`WriteRejection.kind`): `gate`, `stale_timestamp`,
    `missing_parent`, `exists` (`conflicted`), `unique_conflict`,
    `pub_key_taken`, `validation`, `proof_rejected`, `bad_request`,
    `rejected`. Transport failures (`TransportError.kind`): `network`,
    `timeout`, `aborted`, `http` (5xx, with `retryAfter`), `malformed`.
12. ✅ The raw status, body and details stay on the outcome or error.

Mapping, as `lib/chat_web/controllers/electric_controller.ex` answers:

| Answer | Outcome |
|---|---|
| `200 {txid}` | `written` |
| `401 {error}` (`IngestPop`: missing or invalid challenge) | `proof_rejected` |
| `403 {error: "not_in_trust_chain", max_depth}` (`WriteGate.denied_body`) | `gate` |
| `409 {status: "exists", conflicted}` | `exists` |
| `409 {error: "pub_key_taken"}` | `pub_key_taken` |
| `422 validation_failed`, `owner_timestamp: ["timestamp not newer"]` | `stale_timestamp` |
| `422 validation_failed`, a field with `"does not exist"` (Ecto `foreign_key_constraint`) | `missing_parent` |
| `422 validation_failed`, `"has already been taken"` | `unique_conflict` |
| other `422 validation_failed` | `validation` |
| `400 {error}` (malformed request) | `bad_request` |
| `400` plain text (a row check failed) | `rejected` |
| `503 {error: "database_timeout"}`, `retry-after` | `TransportError` `http` |

`ingest_each` rows carry the same bodies per row.

`missing_parent` exists only where the backend refuses a missing parent: the
`parent_sign_hash` foreign key of `user_storage` and `user_storage_versions`.
`dialog_messages` checks only the format of `parent_sign_hash`, so a message
with an unknown parent is accepted, not refused.

Wire requirements from `external_client.md` hold: the UTF-8 bytes of the
challenge are signed; the proof is unpadded base64; the challenge comes from
`GET /challenge`; shape binaries are unpadded; read sessions last 300 s and
renew at 60 s.

`not_in_trust_chain` is a `gate` rejection, not a verdict on the row; nothing
retries it. Acceptance (`written`) is not visibility: a write whose successor
reads the shape waits for the row there (the app's
`sendMutationsAndAwaitShape`).

`readShapeOnce` follows `handle` / `offset` until up-to-date (at most 10 000
pages, at most 3 restarts on 409) and returns the merged rows. Success
requires the server's up-to-date mark; a response that is not up to date and
names no handle or offset to continue from is a `malformed` `TransportError`.

`subscribeShape` retries `network`, `timeout` and `http` (5xx) failures; a
`malformed` answer ends the subscription with a `protocol` error, anything
else with `internal`. A timeout is told from a cancellation by the signal's
reason, also when the signal combines a timeout with a caller's abort (as the
read sessions' does).

### 5.5. dialogs ✅

1. ✅ One derivation, `sign_skey || crypt_skey || UTF8(peer_user_hash)`,
   HKDF-SHA3-256, salt `buckitup/dialog-mk/v1`, info `dialog-mk`, 32 bytes:
   `dialogs.deriveSenderMsgKey`, `IdentityHandle.senderMsgKey(peerHash)`, and
   the app's `DialogCrypto.deriveSenderMsgKey(signSkey, cryptSkey, peerHash)`,
   which delegates to it. `evm_skey` is no longer an input; it stays in the
   vault for recovery signing.
2. ✅ The app's two call sites use it: `dialogs.store.js` (the own key for
   reading) and `messageIntent.ts::ownSenderMsgKey` (writing).
3. ✅ Wrap/unwrap, AES-GCM and hash helpers are unchanged;
   `IdentityHandle.unwrapPeerKey(row)` unwraps without exposing `crypt_skey`.
4. ✅ Builders: `buildDialogKeyRow`, `buildMessageRow`, `buildRevisionRow`
   (edit or tombstone), `newMessageId` (`dmsg_` + UUIDv7); `rows.rowMutation`
   turns a signed row into the insert or update the server takes.
5. ✅ A new message has no parent; a revision's `parent_sign_hash` is the
   tip's `sign_hash` and its `owner_timestamp` must be strictly newer (the
   builder refuses otherwise); `refs_map_b64` is the encrypted
   `{message_id: sign_hash}` map, checked to name message revisions only;
   `sign_b64` and `sign_hash` come from `signRow`.
6. ✅ `content.withEditedText(parts, text)` replaces the single text part and
   keeps quotes, files, images and videos in place; `canEditText` refuses a
   message an edit would not keep whole. The app's `editMessage` builds the
   edit from the decrypted current parts with it.
7. ✅ `openMessageRow` verifies the signature (and `sign_hash`) before it
   decrypts, and tells `invalid` from `undecryptable`; `deleted_flag` is read
   with `wireBool` in every wire form.
8. ✅ Content encoding unchanged.
9. ✅ A fresh random 12-byte nonce per encryption (`sealAesGcm`).
10. ✅ `openPeerDialogKey(reader, row, { peerHash, peerCard })` uses a key row
    only when the peer's card verifies and is `peerHash`'s, the row's
    `sender_hash` is the peer, `peer_hash` the reader, `dialog_hash` the pair's,
    the signature the peer's, and the row is not a tombstone.
    `openDialogMessage(row, { me, peerHash, senderCard, senderMsgKey })` opens
    a message only in the pair's dialog, from one of the two, under the
    author's verified card. The caller names the participants; nothing is
    taken from the row. The backend checks none of it, so these are the read
    path for a client that receives rows from any vouched identity.
11. ✅ `ensureDialogKey` reads the identity's own `dialog_keys` row and writes
    one only when there is none: a verified own row serves every device of
    the identity (one derivation, so one key). A concurrent insert from
    another device answers `exists` and is settled by a read; a write without
    an answer is `unknown`, and the next call reads before writing. An own
    tombstone is reported as `deleted` and not rewritten.

The builders take optional `encrypt` / `wrap` functions. The app passes its
`DialogCrypto` wrappers, so its tests keep the seam they already mock; a
partner's client leaves them out.

The app signs every ready row of a dialog relation through `signRow` +
`rowMutation` (`src/api/client.js::createGenericMutation`): only the
relation's schema fields are signed and sent.

**Derivation switch and existing `dialog_keys` rows.** No migration and no
key versioning (`docs/invariants.md` § 1a). What changes:

- `dialog_keys` has one row per direction, and the author cannot read its own
  row back (the key is wrapped to the peer). A row published before the switch
  wraps the old key, and the peer would unwrap it and fail on every new
  message.
- A device therefore republishes its own `dialog_keys` row once, as an update
  with a newer `owner_timestamp`, unless it has itself published that row
  since the switch. It remembers that per account and dialog in the local
  store (`dialog-key-published-here:<user>|<dialog>`), set only after the
  server accepted the write. The protocol allows republishing from any device
  (pq_dialogs § `dialog_keys`). A mark that cannot be read is not taken as
  published: a locked account raises `VaultLockedError` and the intent waits
  for the unlock (`AWAITING_UNLOCK`); any other read failure leaves the intent
  for the next recovery pass. Nothing is sent under an unconfirmed key, and
  once the mark reads again the key row is republished before the message.
- A peer's key is cached per dialog and author together with the `sign_b64`
  of the row it came from; a republished row replaces the cached key.

Consequences for dialogs of test accounts written before the switch: nothing
is deleted. Each side's messages written before the switch become unreadable
— for the author at once (it re-derives the new key), for the peer once the
author republishes its row. New messages work in both directions after both
sides run the new client. A client still on the old version keeps writing
under the old key; the two versions do not interoperate.

### 5.6. origins ✅

1. ✅ Types and canonical schemas of `origins` and `origin_settings`.
2. ✅ V's keys come from `identity.generateIdentityKeys`.
3. ✅ V's card is published in its own request, proved by V.
4. ✅ Origin row (`originRow`): `origin_hash` = V's `user_hash`, `owner_hash`
   = VO's.
5. ✅ `owner_cert` = ML-DSA-87 by VO over the raw bytes of V's `sign_pkey`
   (`ownerCert`, `verifyOwnerCert`).
6. ✅ Insert: row signed by V with its `ors_` `sign_hash`, proved by V.
7. ✅ `updateOrigin`: the row is signed by VO (default) or V, the request is
   always proved by VO (`origin/validation.ex`: `validate_origin_update_signature`
   accepts either signer, `owner_auth` checks the proof against the owner).
8. ✅ `setOriginSetting`: insert signed and proved by V; update signed and
   proved by V or VO (`origin_setting/validation.ex`); `removeOriginSetting`
   writes a tombstone. Timestamps are strictly newer.
9. ✅ Validation mirrored before sending: `moderation_mode` ∈ none/post/pre,
   `review_access` ∈ open/invite_only, `review_token_ttl_days` an integer in
   1..365 (`OriginSettingError`). An update refused while reviews await
   moderation is `{ kind: 'pending_moderation' }`.
10. ✅ Creation order: V's keys go into VO's `origins` slot **before** anything
    is published, then V's card, then the origin row. After the keys write the
    SDK reloads V from the slot and publishes as the reloaded V, so nothing is
    published for keys that are not stored. Outcomes of the keys step: stored;
    refused or never sent (`incomplete`, `originHash: null`, V discarded); sent
    without an answer (`incomplete`, reason `unknown`, V's `originHash`).
    `resumeOrigin` always reloads V from the slot and checks the keys against
    `originHash`; it finishes the missing steps, which are idempotent (an
    existing verified card or row is not written again), or answers
    `keys` / `absent` when V was never stored. It never makes another V. A
    caller that lost the hash finds an unpublished V as a slot entry whose
    origin row is absent. V handles are closed on every path that does not
    hand them to the caller.
11. ✅ Access mode `trust`: `OriginContext.sessions` carries the owner's read
    sessions; reads of `origins` and `origin_settings` send its bearer and
    reopen on `read_session_required`. The context's storage and sessions must
    belong to the owner (`TypeError` otherwise).

`readOrigin` verifies the row against V's card and VO's key (owner cert,
signature by V or VO, `sign_hash`). `openOrigin` gives another device of VO a
handle for V. Creation spans several requests and identities and is not
atomic. The partner's venue mapping and moderation UI are not in the SDK.

### 5.7. vouch ✅

1. ✅ `issueVouch` / `retractVouch` build the row (`vouchRow`), sign it as the
   issuer, write it with the issuer's proof, and read the current row first.
2. ✅ Explicit issuer (the handle), subject, scope (`storageScope`,
   `adminScope`) and timestamp (`now`, strictly above the stored one).
3. ✅ Retraction is `deleted_flag = true` with a newer timestamp from the same
   issuer; retracting a scope never granted inserts a tombstone row of its own
   (as a wider-scope tombstone needs).
4. ✅ Proof by the issuer only; a proof by another identity is refused.
5. ✅ `contactVouches.ts` keeps its policy and outbox; it signs rows through
   `rows.signRow` and names scopes with `storageScope`.
6. ✅ Tests: issue, repeat (no request), retract, re-issue, two devices at
   once, a write overtaken by a newer one, an unverified stored row, a foreign
   proof. The gate's refusal of the subject's next write is the server's
   evaluation and is not reproduced by the fake server (§ 11.2).

Scopes use the server's `device_id` from `device_identity`. A scope suffix does
not narrow a grant; the trust chain is the server's.

### 5.8. storage ✅

1. ✅ `createUserStorage({ transport, owner })`: slot addressing, encryption,
   JSON merge and signed `user_storage` writes.
2. ✅ Root uuid derived from `crypt_skey`; other slots random, found through
   the encrypted root map.
3. ✅ `createSlotResolver` moved into the SDK (`slots`); the app's
   `src/lib/data/slots.ts` re-exports it. Row first, then its reference in the
   root map. A name missing from the cached map re-reads the root, so a slot
   another client created is found without a reset; an address already known
   never changes.
4. ✅ Encryption as the app's: AES-256-GCM, PBKDF2-SHA-256 from `crypt_skey`,
   salt `avatar-encryption`, 100 000 iterations (`deriveStorageKey`,
   `sealJson`, `openJson`); the app's `EncryptionManagerPQ` now uses them.
5. ✅ First row insert; later revisions update with the tip as
   `parent_sign_hash` and `owner_timestamp` = the tip's + 1.
6. ✅ Read outcomes: `found`, `absent`, `unavailable`, `unverified`,
   `undecryptable`; a write is never built on the last three. A slot read or
   write behind a root that does not verify or decrypt reports that kind, not
   `unavailable` (`readSlot`, `patchSlot`, `loadOriginKeys`, `putOriginKeys`).
7. ✅ `updateJson` / `patchJson` re-read the current base and write again on
   `stale_timestamp`, `exists` or `missing_parent`, at most four attempts. The
   server refuses no stale parent: it checks the signature, then replaces
   `parent_sign_hash` with its tip's `sign_hash` whenever the timestamp is
   newer (`chat/lib/chat/data/versioning.ex` `compare_timestamps`). The
   parent + 1 timestamp is what turns a write on a replaced base into a
   `stale_timestamp` refusal. It does not cover a writer that uses another
   timestamp rule, nor two writes the server checks at the same moment (the
   check and the update are separate statements); such a write is stored with
   a parent it did not sign, the overtaken change is gone from the current
   row, and the row stops verifying (§ 11.2 item 6). A write sent without an
   answer is `unknown`.
8. ✅ `mergeJson` is generic: top-level keys, `null` deletes, named maps merged
   per entry; the root's `slots` map keeps an existing address. The app's
   recovery `$sticky`, vault lists and contact edits stay in
   `storageIntent.ts`.
9. ✅ Named slot `origins` (`ORIGINS_SLOT`): one record per `origin_hash` with
   `name`, `sign_skey`, `crypt_skey` (base64), `contact_skey` (hex),
   `sign_pkey`, `crypt_pkey` (base64).
10. ✅ `putOriginKeys` patches one entry; others are kept.
11. ✅ `removeOriginKeys` removes the entry from the JSON; no marker reaches
    the stored value.
12. ✅ Tests: two clients creating the slot at once (one address, both
    entries), two clients editing different entries at once (both kept, the
    later one through a re-read), a write on a base replaced seconds earlier
    (refused and re-applied), the backend limitation (a stale-base row with a
    newer timestamp is stored unverifiable and reported `unverified`, nothing
    written over it), a second client reading the slot. The fake server
    checks the signature of the row as sent and then rewrites the parent, as
    the backend does.
13. ✅ `loadOriginKeys` / `openOriginKeys` rebuild V only when the stored keys
    match its `user_hash` and public keys (`identityKeysFromSecrets`).

The root record keeps its other fields. Removing V from the slot is not
erasure from server history: User Storage keeps versions.

## 6. Frontend migration

| App surface | Target | State |
|---|---|---|
| `EncryptionManagerPQ.js` | Orchestration stays; primitives from the SDK | ✅ New account keys and card fields from `identity`, vault writes through `writeIdentityKeys` |
| `accountVault.js` | Adapter over the SDK vault | ✅ PRF functions delegate; legacy vault and `navigator.credentials` patch stay |
| `keyCustody.ts` | One error class | ✅ `VaultLockedError` is the SDK's |
| `rowVerification.ts` | One verification | ✅ Signed-field rows and `SIGN_HASH_PREFIX` from `rows` |
| `DialogCrypto.js` | Wrapper over the SDK | ✅ Every method delegates; `deriveSenderMsgKey` takes the spec's three inputs |
| `messageIntent.ts` | Row building in the SDK | ✅ Key, message and revision rows from the SDK builders; outbox, intents, causal capture and acceptance rules unchanged |
| `api/client.js` | Schema-based signing | ✅ `createGenericMutation`, `createUserCard` and `createStorageMutation` build rows through `signRow` + `rowMutation`; their signatures for callers are unchanged |
| `dialogs.store.js` | Own key, peer key cache, edit | ✅ Spec derivation; peer key cache follows the key row; edits keep quotes and attachments |
| `data/transport.ts` | Config adapter over the SDK transport | ✅ Unchanged: it was one already |
| `readSession.ts` | Auth adapter over the SDK lifecycle | ✅ Public API kept; tokens, dedup, renewal and cleanup in `createReadSessions`; card recovery and access-gate marks stay app-side |
| `shapeRead.ts` | One-shot reads | ✅ Complete snapshots through the SDK's paginated `readShapeOnce` |
| `ingest.ts` | Outbox, retries, IngestError | ✅ Row outcomes classified by `classifyRowResult` and `validationReasons`; the outbox, retries and `IngestError` stay; requests stay on `ingestEachResponse` |
| `fileTransfer.ts` | Schema-based signing | ✅ Chunk and manifest signatures through `signRow`; the manifest mutation through `rowMutation` |
| `intentRecovery.ts`, `dialogs.store.js` dispatch | One order per entity | ✅ `withIntentEntityLock` + `handOverEarlierOfEntity` (§ 16.11) |
| `collections.ts` | TanStack stays; transport primitives reused | Stays on `@electric-sql/client` through TanStack; not moved |
| `contactVouches.ts` | Contact policy stays; rows from the SDK | ✅ Rows signed by `rows.signRow`, scopes by `vouch.storageScope` |
| `slots.ts` | Resolver in the SDK | ✅ Re-exports `@buckitup/pq-client/slots` |
| `EncryptionManagerPQ.js` slot encryption | SDK encryption | ✅ `deriveStorageKey`, `sealJson`, `openJson` |
| `userStorage.ts`, `storageIntent.ts` | Durable orchestration in the app, protocol in the SDK | ✅ Encryption (`sealJson` / `openJson`), addressing (`slotId`), the slot resolver (`slots`) and row signing (`createStorageMutation` on `signRow`) are the SDK's. Intents, the outbox, accepted snapshots, base decisions and the app's merge rules (`$keyed`, `$sticky`, vault lists) stay: `createUserStorage` writes directly over HTTP and has none of those guarantees, so it is not used here |
| `sessionIdentities.ts` | Aligned with SDK identity handles | ✅ No protocol in it: derivation is `notes` / `derivedIdentity`; it only records which derived identity signs an outbox write |

Order for each move: extract a pure function or service → SDK tests → app
adapter → app regressions → remove the duplicate.

Vite and TypeScript resolve `@buckitup/pq-client` to its sources through
aliases, which does not test exports, `dist` or dependencies: a tarball
consumer test is required before delivery.

## 7. Errors and lifecycle

Requirement: a refused gate, a stale `owner_timestamp`, a missing parent and a
transport failure are distinct.

| Category | Information for the caller |
|---|---|
| Access denied | ✅ `gate` with `maxDepth`; read sessions: `not_in_trust_chain` |
| Stale timestamp | ✅ `stale_timestamp` with details |
| Missing parent | ✅ `missing_parent` with the fields (User Storage only, § 5.4) |
| Conflict / exists | ✅ `exists` with `conflicted`; `unique_conflict`; `pub_key_taken`. An exact repeat of a committed `dialog_messages` or `user_storage` insert is `stale_timestamp`, not `exists` |
| Unknown outcome | ✅ `unknown` from `storage`, `origins` and `ensureDialogKey` writes sent without an answer |
| Transport / server | ✅ `TransportError` `network`, `timeout`, `aborted`, `http` with `retryAfter` |
| Protocol response | ✅ `TransportError` `malformed` with status and body |
| Vault / PRF | ✅ Locked, unsupported, missing output, wrong passkey, missing vault |
| Identity keys | ✅ Malformed keys, the key that does not match, a keypair that does not work, closed handle |
| Verification | ✅ Missing signature, missing or wrong `sign_hash`, missing fields, bad signature; cards add hash and cert reasons |

Reasons are read from server details, not from HTTP 422 alone.

Lifecycle: create the transport → open a vault, open identity handles →
operations and subscriptions → dispose subscriptions → close handles, lock
vaults.

## 8. Verification

### 8.1. Protocol conformance

- `packages/pq-client/tests/vectors/pq-conformance.json` equals the backend's
  `test/fixtures/pq_conformance_vectors.json` up to key order and the `source`
  field. It covers `user_cards`, `user_storage`, `dialog_messages`,
  `dialog_keys`, reactions, receipts, `files`, and hash/HKDF derivations.
- Expected values are never edited to match the SDK.
- The backend file has no `origins` or `origin_settings` cases. The SDK tests
  pin their payload with frontend fixtures (`packages/pq-client/tests/rows.test.ts`);
  those are not backend conformance vectors (§ 11.2).
- Protocol fixtures and app integration tests stay apart, so the package can be
  checked on its own.

### 8.2. Matrix

| Area | Checks | State |
|---|---|---|
| Identity | Key sizes, card verification, tampered hash/cert/name, restore from stored encodings, mismatching key named, broken keypairs on restore and in `openIdentity`, temporary copies wiped, closed handle | ✅ `packages/pq-client/tests/identity.test.ts` |
| Vault | PRF create/open/lock, ciphertext at rest, app storage format, VO and V at once, wrong passkey, missing PRF, missing vault | ✅ `packages/pq-client/tests/vault.test.ts`; app: `accountVaultPrf.test.js`, `vaultModesManager.test.js` |
| Rows | Golden origin payload, unicode, enum, padded/unpadded, `sign_hash` required, tampering, types | ✅ `packages/pq-client/tests/rows.test.ts`, `schema.test.ts` |
| Ingest | Atomic batch vs per-row, every controller answer, 503 not retried, malformed answers, network/timeout/abort | ✅ `packages/pq-client/tests/ingest.test.ts` |
| Auth | UTF-8 challenge, unpadded proof, single-use challenge, another identity's proof refused | ✅ `packages/pq-client/tests/transport.test.ts`, `ingest.test.ts` |
| Reads | 2 500-row snapshot over 3 pages, restart mid-snapshot, live insert/update/delete, reset, retries, permanent refusal, dispose and signal | ✅ `packages/pq-client/tests/shapes.test.ts` |
| Read sessions | Dedup, isolation by server/identity/shape, renewal and its cancellation, expiry, 401 reopen, `unknown_user`, `not_in_trust_chain`, logout during an open, timeout | ✅ `packages/pq-client/tests/readSessions.test.ts`; app: `readSessionAudit` (46) and the other read-session suites |
| Dialogs | Derivation equal to the protocol in SDK, app and handle; two independent clients both ways; the identity reopened on another client; new message, edit and tombstone with parents, refs, timestamps and signatures; refs validation; invalid vs undecryptable; quotes and attachments kept across an edit; a pre-switch key row and its republication | ✅ `packages/pq-client/tests/dialogBuilders.test.ts`, `dialogs.test.ts`; app: `dialogKeysReloadSafety` (republication), `getSenderMsgKeyReadCacheFallback` (stale peer key), the dialog, outbox and notes suites |
| Origins | VO creates V, stores its keys; another client with VO's keys loads V and writes as V; separate card and origin requests; owner certificate; VO or V signs an update, VO proves it; settings rules; pending moderation; a failed card write resumed into the same V; nothing published when keys cannot be stored; keys sent and not committed, committed with the answer lost, resumed after a reload with and without the kept hash, a refused keys write; access mode trust with the owner's sessions, without them, and with another identity's | ✅ `packages/pq-client/tests/origins.test.ts` |
| Dialog reads and own key | A third, correctly signed identity claiming another pair's dialog; another peer, another dialog, forged and foreign cards, bad signature, tombstones in every wire form; `ensureDialogKey` on a second device, two devices at once, an answer lost after the commit, an unverified peer card, an own tombstone | ✅ `packages/pq-client/tests/dialogSafety.test.ts` |
| Vouch | Issue, repeat, retract, re-issue, tombstone without a grant, foreign proof, two devices at once, overtaken write, unverified row | ✅ `packages/pq-client/tests/vouch.test.ts`; app: `contactVouchTokens` |
| Storage | Encryption compatible with the app's format, merge, insert/update chain, read outcomes, slot on a second client, concurrent slot creation, concurrent entry edits, a base replaced seconds earlier, the backend's parent rewrite, the `origins` slot, key checks on restore | ✅ `packages/pq-client/tests/storage.test.ts`; app: the slot and storage suites |
| App | Auth, messaging, notes identities, User Storage, outbox | Full suite on every stage |
| Package | Tarball install, ESM imports, declarations, eight entry points without aliases; Node without the DOM lib; PRF vault in Chromium | ✅ `npm run check:consumer -w @buckitup/pq-client -- <tgz> --browser` |

### 8.3. Independent consumer

A minimal consumer outside the app's aliases installs the built tarball and
checks public imports from `dist`, TypeScript resolution, runtime dependencies
without hoisting from the frontend, the browser setup for vault (libsodium for
`@lo-fi`), and that Node-compatible modules import without touching
`navigator` or `window`. Full WebAuthn in Node is not a goal.

### 8.4. End-to-end acceptance (partner's test server)

1. VO and V created through the SDK; cards and origin published; V's keys
   stored.
2. Vouches set up by the server's admin.
3. G admitted by the partner backend.
4. G writes a dialog key and a message.
5. Another device with VO's keys loads V from storage, reads and replies as V.
6. The partner's subscription sees metadata without plaintext.
7. Retracting B → G blocks G's next write; old rows stay.

Admission, notifications and admin setup are partner or operator work.

## 9. Build, npm and documentation

### 9.1. In place

- Workspace dependency `@buckitup/pq-client: *` in the app.
- ESM, ES2022, `.d.ts`; exports `./*` (types, import) and `./package.json`;
  `files`: `dist`, `LICENSE`, `README.md`, `CHANGELOG.md`.
- `engines.node` `>=20.3`; `publishConfig.access` `public`; runtime
  dependencies are the package's own (`@noble/*`, `@lo-fi/*`,
  `libsodium-wrappers`), nothing is resolved from the app.
- Prepack copies `LICENSE` and builds; the tarball holds 76 files, only
  `dist`, the licence, README, changelog and `package.json`.
- `npm run check:consumer -w @buckitup/pq-client -- <tgz> [--browser]`
  installs a tarball into a temporary project outside the workspace,
  typechecks it under `Bundler`, `NodeNext` and `NodeNext` without the DOM
  lib, imports all eight modules in Node, and with `--browser` bundles a
  browser scenario (dialogs, storage, PRF vault) and runs it in Chromium with
  a virtual WebAuthn authenticator that supports PRF.
- README: requirements (Node ≥ 20.3, TypeScript ≥ 5.7, the DOM lib for
  `vault`), install including `@next`, the module table, concepts, examples
  of identity and card, vault, a dialog, User Storage, vouches, the VO/V
  flow and reads without a UI framework, the error table, lifecycle and
  disposal, the vault's browser setup (libsodium as the global `sodium`, the
  bundler note), versioning, development.
- `CHANGELOG.md` (Keep a Changelog; `0.2.0` planned as the first published
  version) and `docs/pq-client-release.md` (semver, prerequisites,
  procedure, local check).
- `.github/workflows/release-pq-client.yml`: manual only, publishes nothing
  by default (§ 16.16).
- GPL-3.0-only.

### 9.2. To do

1. The `@buckitup` scope on npm, its owners, and publishing credentials:
   trusted publishing for the workflow or an `NPM_TOKEN` in the
   `npm-release` environment (§ 11.3).
2. The `npm-release` GitHub environment with required reviewers, limited to
   `main`.
3. A version PR for `0.2.0-rc.0`, a dry run of the workflow, then the
   approved publication under `next`.
4. A real passkey, Safari and Firefox for the vault; only Chromium with a
   virtual authenticator is checked.

Recommendation: prereleases through public npm under the `next` dist-tag.

## 10. Stages

| Stage | Work | Done when | State |
|---|---|---|---|
| 0. Baseline | Pinned sources, export inventory, derivation switch analysis | Sources recorded | ✅ |
| 1. Rows | `rows`, origin schemas, generator | Conformance passes; generator reproduces the schemas | ✅ |
| 2. Identity / vault | Identity API, PRF vault, multi-identity handles | VO and V used at once without a global current user | ✅ |
| 3. Transport | `ingest`, live shapes, read sessions, typed errors | A consumer reads and writes without app modules | ✅ |
| 4. Dialogs / Phase 0 | Builders, app on the spec derivation | New flows interoperate between SDK and app | ✅ (frontend part of Phase 0) |
| 5. Storage / vouch / origins | Slots, merge, issue/retract, origin lifecycle | SDK-only VO/V flow; concurrent storage tests | ✅ |
| 6. App migration | Adapters, duplicates removed | App regressions and checks pass | ✅ |
| 7. Distribution | Tarball consumer, docs, release workflow, prerelease | The partner installs from the registry and runs an example | Prepared; not published (§ 16.16) |
| 8. Partner acceptance | End-to-end on the partner's server | Second device replies as V; retract blocks G | |

Intermediate versions can be published once base APIs are stable.

## 11. Dependencies

### 11.1. Frontend work (this repository)

Stages 3–7 above. No product question blocks them: internal API, adapters,
retries and file layout are the implementers' choice.

### 11.2. External: backend

The backend is read, not changed, in this work. These need backend changes or
backend-owned data:

1. **Origin conformance vectors.** `test/fixtures/pq_conformance_vectors.json`
   has no `origins` / `origin_settings` cases. Adding them means changing
   `regen_vectors.exs` and the backend test; until then origin payloads are
   pinned only by frontend fixtures.
2. **Phase 0 backend items** from the specification: peer vouch freshness,
   sandboxes not exposed on production servers, the `router.ex` CORS comment.
3. **A test server** with its endpoint, owner, device identity and grants for
   integration acceptance. The transport is tested against fakes that keep
   the controller's answers; it has not run against a live server in this
   work.
4. **Gate effects.** That a retracted vouch stops the subject's next write,
   and that a guest admitted for one venue can write elsewhere, are the
   server's trust-chain evaluation; the fake server does not implement the
   gate. They need the live test server of item 3.
5. **A refused missing parent for dialog messages**, if one is wanted:
   `dialog_messages.parent_sign_hash` has no foreign key, so the server accepts
   an unknown parent and the client has nothing to type (§ 5.4).
6. **The stored row must be the signed row.** For `user_storage` and
   `dialog_messages` the server checks the signature, then replaces
   `parent_sign_hash` with its tip's `sign_hash` when the timestamp is newer,
   and compares the timestamp with a row it read before the update statement.
   A write on a stale base is then stored with a parent it did not sign: the
   change it overtook leaves the current row and the row stops verifying.
   The SDK's parent + 1 timestamp covers its own writers except for writes
   the server checks at the same moment. A guaranteed multi-device merge
   needs one of: refuse an update whose `parent_sign_hash` is not the stored
   `sign_hash`, in the statement that updates it (compare-and-swap); or store
   the parent as signed and make the timestamp check atomic with the update,
   so an overtaken change stays detectable as a fork. Either way the server
   must not change a signed field.

### 11.3. External: delivery

1. npm: the `@buckitup` scope, who may publish, and the credentials —
   trusted publishing for `release-pq-client.yml` or an `NPM_TOKEN` in the
   `npm-release` environment. None exists yet; until then the release
   workflow can only run dry.
2. When the partner gets a prerelease (the specification's open question 1).
3. The split of frontend, backend and partner work between people.

Not open: a separate public npm package, its place in the frontend repository,
a parametric server URL, a same-domain vault, no sync with BuckitUp's servers.

## 12. Out of scope

- The partner's frontend, guest and owner screens, QR codes and their
  protocol.
- The partner's admission bot and notification service.
- Deployment and administration of the partner's server and proxy.
- Backend Phase 0 fixes (§ 11.2).
- Peer-scoped grants restricting a guest to one venue.
- Staff delegation and the full subaccount model.
- Cross-domain sign-in with keys of BuckitUp's app (PoP v1).
- Sync between the partner's and BuckitUp's servers.
- New offline scheduling, file upload, backup, recovery or device-link
  protocols.
- The reviews and moderation system beyond origins and settings.
- Physical database erasure and cascade audits.

Existing offline, files, recovery and device-link features of the app keep
working; that is a regression constraint, not a requirement to move them into
the SDK.

## 13. Readiness criteria

- [x] All eight entry points exist: `identity`, `vault`, `rows`, `transport`,
  `dialogs`, `origins`, `vouch`, `storage`.
- [ ] No dependency on Vue, Pinia, TanStack, `@/` or app singletons. (Holds
  for every current module.)
- [x] Crypto primitives reused; protocol not implemented twice. (What the app
  keeps is listed in § 16.12.)
- [x] Identities, cards and certificates compatible with the server.
- [x] PRF vault and several identities work independently of the app.
- [x] Row signatures and request proofs use the right identities, origin
  updates included.
- [x] Transport covers `ingest`, `ingest_each`, snapshot and live shapes, and
  read sessions.
- [x] Gate, stale timestamp, missing parent and transport errors are typed
  apart.
- [x] The frontend uses the spec `sender_msg_key`.
- [x] Origin create/update/settings and the `origins` slot work through the
  SDK (against the fake server), in access modes open, guarded and trust.
- [ ] Concurrent storage merge loses no entries. (Holds between writers of
  this library when the server sees their writes one after the other; not
  for other writers or simultaneous writes, § 11.2 item 6.)
- [x] A client reads a dialog only for the participants it names, and
  publishes its own dialog key once across devices.
- [ ] Vouch issue/retract compatible with backend gating. (Rows and proofs
  follow the backend contract; the gate's effect needs a live server.)
- [x] Conformance, app tests and package checks pass.
- [x] The tarball installs in an independent browser/TypeScript consumer.
  (Chromium with a virtual authenticator; no real passkey, Safari or
  Firefox.)
- [x] Public API, errors, lifecycle and examples documented.
- [ ] Published on public npm under an agreed semver and release process.
- [ ] End-to-end second-device and retract scenario confirmed with the
  partner.

## 14. Common misreadings

1. "The vault is missing" — the PRF vault is in the SDK; the legacy vault and
   recovery stay in the app.
2. "Identity has to be written from scratch" — it reuses `userHashOf`,
   `verifyUserCard` and the card builder shared with derived identities.
3. "The frontend does not use the SDK" — it imports it through workspace
   aliases throughout.
4. "Changing the derivation helper is enough" — the call sites and the
   `dialog_keys` republication rule change with it (§ 5.5).
5. "A row signature and a request proof are always one identity" — origin
   updates separate them.
6. "Adding origins to the generated file is enough" — the generator itself
   produces them, enum values included.
7. "Offline, recovery and files are new modules of this release" — the
   specification does not ask for them.
8. "The whole partner document is frontend work" — backend, deployment and
   partner work are separate (§ 11).
9. "The build passed, so the package is ready" — aliases and hoisting can hide
   package errors; the tarball consumer decides.
10. "Removing V from the slot erases its keys" — User Storage keeps versions.
11. "Old test dialogs must keep working after the derivation switch" — no
    compatibility is owed (`docs/invariants.md` § 1a).
12. "A stale parent shows as an invalid signature, so storage retries" — the
    server accepts it and rewrites the parent; only the timestamp refuses a
    stale base (§ 5.8).

## 15. Out of this plan's authority

The specification is proposed; this plan neither approves it nor proves any
test result beyond § 16.

## 16. Implementation status

### 16.1. Stage 1 — rows

- `scripts/gen-pq-schema.mjs` reads `origin.ex` and `origin_setting.ex`, maps
  `Ecto.Enum`, emits `ENUM_VALUES` and `SIGN_HASH_PREFIX`.
- `packages/pq-client/src/rows.ts`: `rowSignableFields`, `signRow` (typed
  `SignedRow<T>`; refuses unknown relations, missing columns, enum values the
  server cannot cast), `verifyRow` (requires `sign_hash` where the relation
  has one).
- `verifyDialogRow.ts` delegates to `verifyRow`; `RowVerdict` gains
  `missing_sign_hash`, a reason the app's `RowInvalidReason` already had.
- `src/lib/data/rowVerification.ts` takes `verifyRow` and `SIGN_HASH_PREFIX`
  from the SDK instead of its own copy.

### 16.2. Stage 2 — identity and vault

- `packages/pq-client/src/identity.ts`: `generateIdentityKeys`,
  `identityKeysFromSecrets`, `cardKeyFields`, `unsignedUserCard`,
  `signedUserCard`, `userCardInsert`, `openIdentity`, `publishUserCard`,
  `createIdentitySession`, `IdentityKeysError`, `IdentityClosedError`.
- `packages/pq-client/src/vault.ts`: the PRF vault from `accountVault.js`,
  identity keys in it, `VaultLockedError`, `VaultMissingError`; a passkey whose
  PRF output does not decrypt the vault is `PasskeyMismatchError`.
- App adapters: `accountVault.js` (PRF part delegates), `keyCustody.ts`
  (re-exports `VaultLockedError`), `EncryptionManagerPQ.#writeNewAccount`
  (SDK keys and card fields; `evm_skey` and `meta_seed` stay app-side).
- `derivedIdentity.signedUserCard` delegates to `identity.signedUserCard`.
- Package dependencies: `@lo-fi/local-vault`, `@lo-fi/local-data-lock`;
  `package-lock.json` updated for them.

### 16.3. Review fix — keypair checks

`identityKeysFromSecrets` accepted an ML-KEM secret key with byte 0 flipped
(same public key, wrong shared secret) and an ML-DSA secret key with byte 64
flipped (same public key, signatures that do not verify), even with every
expected public key given; `openIdentity` accepted any `IdentityKeys`. Both
were reproduced, then fixed as § 5.1 describes. Four new tests fail without
the fix.

### 16.4. Stage 3 — transport

- `packages/pq-client/src/transport.ts`: `TransportError.kind` /
  `retryAfter` / `body`; `ingest`; typed `ingestEach`; `readShapeChunk`;
  paginated `readShapeOnce`; re-exports the modules below.
- `writeOutcome.ts`: `WriteRejection`, `RowOutcome`, `classifyRowResult`,
  `classifyErrorBody`, `classifyValidation`.
- `readSessions.ts`: `createReadSessions`.
- `shapeStream.ts`: `subscribeShape`.
- `shapeLog.ts`: applying shape messages (insert, partial update, delete).
- `abortSignals.ts`: a signal with a timeout, an abortable delay.
- App: `src/lib/data/readSession.ts` is an adapter over `createReadSessions`
  with the same exports; its `EncryptionManagerPQ` import is shared between
  concurrent opens.
- `IngestEachOutcome` is now a union (`kind: 'results' | 'rejected'`) with
  `rows`; the app does not call `ingestEach`, only `ingestEachResponse`.

The new snapshot test fails on the previous `readShapeOnce`, which read only
the first response of a multi-page snapshot.

### 16.5. Review fixes — transport

Each was reproduced first, then fixed; the new tests fail without the fix.

- `readShapeOnce` returned rows from a response that was not up to date and
  carried no handle or offset. It now requires the up-to-date mark and throws
  `malformed` otherwise. The app's fake `/shapes` servers answered bare row
  arrays, which no Electric server sends; they now end a snapshot with the
  `up-to-date` control message (`tests/helpers/fileServer.ts` and six suites).
- `subscribeShape` retried every exception, a `malformed` answer included (30
  requests in 50 ms). It now ends with a `protocol` error, `ready` resolves
  `false`, `done` resolves once, and nothing more is sent.
- A read session's timeout was reported as `aborted`, because the transport
  read only `signal.aborted` of the combined signal. It now reads the
  signal's reason.

### 16.6. Stage 4 — dialogs

- SDK: `dialogs.ts` builders (`buildDialogKeyRow`, `buildMessageRow`,
  `buildRevisionRow`, `newMessageId`), refs (`checkRefs`, `encryptRefs`,
  `decryptRefs`), `openMessageRow`; `content.ts` `canEditText` /
  `withEditedText`; `rows.ts` `rowMutation`; `IdentityHandle.senderMsgKey` and
  `unwrapPeerKey`.
- App: `DialogCrypto.deriveSenderMsgKey(signSkey, cryptSkey, peerHash)` on the
  SDK; `ownSenderMsgKey` and the store without `evm_skey`;
  `messageIntent.ts` on the builders; `createGenericMutation` on
  `signRow` + `rowMutation`; `ensureOwnDialogKeyPublished` with the
  republication rule of § 5.5; the peer key cache follows its row;
  `editMessage` keeps quotes and attachments.
- The edit change is the same as the unmerged branch
  `fix/preserve-parts-on-edit` (`f7aed78`), with the helpers in the SDK
  instead of `src/lib/editableParts.ts`; that branch's UI guard (hiding Edit
  in `ChatWindow.vue`) is not taken. Merging both will conflict in
  `dialogs.store.js` and `tests/dialogsStore.test.js`.
- Test fixtures that the stricter builders refuse were corrected: message ids
  that are not `dmsg_` + UUIDv7, refs that are not message revisions, a mocked
  signer whose `sign_hash` was not a `dms_` hash, an edit base without a
  `sign_hash`. Suites whose own key row stands for a device that already
  published it set the local mark (`tests/helpers/dialogKeyPublished.ts`).

Found while doing it: two dialog intents of one entity could be built
concurrently by the store's dispatch and `recoverIntents` on the same base;
fixed in stage 6 (§ 16.11).

### 16.7. Review fix — an unreadable publish mark

`keyPublishedHere` read a failure of the local store as "published", so with a
dialog key row from before the switch the republication was skipped and the
message went out under a key the peer could not unwrap. It now tells a missing
mark (`false`: republish) from a failed read: a locked account raises
`VaultLockedError` (the intent waits in `AWAITING_UNLOCK`), any other failure
an error the intent recovery retries. The regression test
(`tests/messageIntentRecovery.test.ts`, "an old own dialog_keys row whose
publish mark cannot be read") covers both failures: nothing is sent while the
mark is unreadable; once it reads, the key row is republished as an update
with a newer timestamp and then the message is delivered, and the mark is
set. It fails on the previous code. Eleven app suites that never configured a
local store now use an in-memory one (`useMemoryLocalStore`); the six whose
fixtures hold an own key row also set the mark.

### 16.8. Stage 5 — storage, vouch, origins

- `packages/pq-client/src/storage.ts`, `slots.ts` (moved from the app),
  `vouch.ts`, `origins.ts`; § 5.6–5.8.
- App: `src/lib/data/slots.ts` re-exports the SDK resolver;
  `EncryptionManagerPQ` encrypts slots with `deriveStorageKey` / `sealJson` /
  `openJson`; `contactVouches.ts` signs rows through `rows.signRow` and names
  scopes with `storageScope`. The app has no venue feature, so `origins` has
  no app adapter.
- Tests run against `packages/pq-client/tests/helpers/fakePqServer.ts`, an in-process server that
  keeps the backend's contract for `user_cards`, `user_storage`,
  `vouch_tokens`, `origins` and `origin_settings`: real key proofs with the
  prover each relation requires, signature checks (V or VO for origin and
  setting updates, `owner_cert` on insert), strictly newer timestamps, the tip
  as `parent_sign_hash`, `exists` with `conflicted`, the settings rules, the
  pending-moderation refusal, shape answers ending in up-to-date, and requests
  that can be held to stage a race. Its fixtures are frontend fixtures, not
  backend conformance vectors.

### 16.9. Review fixes — storage

- The slot resolver cached absence: a client that read a slot as absent did
  not see it after another client created it. A miss now re-reads the root
  map and merges it under the addresses already known.
- `readSlot` turned a root that does not verify or decrypt into
  `unavailable`. It now returns the root's own outcome, and so do
  `loadOriginKeys`, `patchSlot` and `putOriginKeys`; nothing is written.
- Tests (`packages/pq-client/tests/storage.test.ts`, "root map freshness and root
  failures"): a second client's slot found without a reset, a known address
  kept, a root with a broken signature and one that does not decrypt. Each
  failed before the fix.

### 16.10. Stage 6 — app migration

Remaining duplication found and removed:

| File | Before | Now |
|---|---|---|
| `src/api/client.js` | `createUserCard` and `createStorageMutation` listed the signed fields, signed them and derived `uss_` by hand | `signRow` + `rowMutation` |
| `src/lib/data/ingest.ts` | Own regexes for the gate, unique and stale-timestamp refusals and the `exists` verdict | `classifyRowResult` and `validationReasons` (each reason tested apart, as before) |
| `src/lib/data/fileTransfer.ts` | `signFields` over hand-built `file_chunks` and `files` fields; a hand-built manifest mutation | `signRow`; `rowMutation` |
| `packages/pq-client/src/writeOutcome.ts` | — | `validationReasons` exported; `classifyValidation` built on it |

Already on the SDK before this stage and not redone: slot encryption and
addressing, the resolver, one-shot reads and read sessions, dialog rows,
contact vouch rows, account keys, the PRF vault.

### 16.11. The intent race

Reproduced deterministically (`tests/messageIntentRecovery.test.ts`, "two
dispatch paths and one entity"): recovery stops intent A of a reaction after
it read its base; the store's path builds and hands over intent B of the same
reaction; A then goes on. Both were built as inserts on the same empty base,
B before A.

Fix, shared by both paths:

- `withIntentEntityLock(payload, fn)`: one entity (a message's
  `message_id`; a reaction's author, message and emoji, the inputs of its
  `reaction_hash`; a receipt's `receipt_hash`) is built and handed over by
  one path at a time, until its write is durable in the outbox. Web Locks
  where available, an in-process queue otherwise, as the per-intent lock.
- `handOverEarlierOfEntity`: under that lock, unsigned intents of the same
  entity captured earlier are built and handed over first, oldest first.
- `recoverIntents` re-reads an intent under the lock and skips it once the
  other path resolved it.

Tests: the reproduction (insert on the tip, then update on it, newer
timestamp); another entity proceeds while one is held; a later intent sent
first hands over the earlier one and recovery sends neither again. Without
the lock the first fails; without the earlier handover the third fails. With
a sequential `await` and a delay put back into `ensureOwnDialogKeyPublished`
(the perturbation that reordered the store test before), the suites still
pass.

The store's `dispatchDialogIntent` now takes the signing key before it builds
the row (a locked vault gives the same `VaultLockedError`, earlier).

### 16.12. Kept in the app on purpose

- `userStorage.ts` / `storageIntent.ts` orchestration (intents before signing,
  outbox, accepted snapshots, base decisions) and their merge rules.
- `collections.ts` / `shapeLink.ts`: live reads stay on `@electric-sql/client`
  through TanStack for the reactive collections; `subscribeShape` is the
  SDK's equivalent for clients without TanStack.
- `src/libs/enigma.js` helpers (`decodeHexOrBase64` returns null where
  `toBytes` throws; different contract).
- `fileIntegrity.ts` compares raw SHA3-512 bytes of a chunk signature with the
  manifest's list, which is not a prefixed `sign_hash`.

### 16.13. Tests added

| File | Covers |
|---|---|
| `packages/pq-client/tests/rows.test.ts` (15) | Rows, `sign_hash`, enum, `SignedRow` types |
| `packages/pq-client/tests/identity.test.ts` (18) | Identity, cards, restore, keypair checks, handles, sessions |
| `packages/pq-client/tests/vault.test.ts` (5) | PRF vault on real `@lo-fi` |
| `packages/pq-client/tests/ingest.test.ts` (19) | `/ingest` vs `/ingest_each`, rejection mapping, transport errors |
| `packages/pq-client/tests/readSessions.test.ts` (10) | Read-session lifecycle; timeout vs cancellation |
| `packages/pq-client/tests/shapes.test.ts` (16) | Complete snapshots, up-to-date required, live subscriptions, protocol errors, trust mode |
| `packages/pq-client/tests/dialogBuilders.test.ts` (12) | Derivation, two clients, reopened identity, revisions, refs, edits keeping parts, a pre-switch key row |
| `packages/pq-client/tests/storage.test.ts` (13) | Encryption format, merge, insert/update chain, read outcomes, slots on two clients, concurrent creation and edits, root map freshness, root failures, the `origins` slot |
| `packages/pq-client/tests/vouch.test.ts` (6) | Scopes, issue/retract, tombstone, foreign proof, concurrency, overtaken write, unverified row |
| `packages/pq-client/tests/origins.test.ts` (7) | VO → V → keys → second client acts as V; partial creation and resume; updates; settings; verification |
| `tests/messageIntentRecovery.test.ts` (+7) | An unreadable publish mark; the intent race, parallel entities, earlier-first handover; a signed intent that never reached the outbox, store-first and concurrent |
| `tests/intentOrder.test.ts` (2) | Capture order with a variable-length counter; the id comparator |
| `tests/dialogKeysReloadSafety.test.ts` (+2), `getSenderMsgKeyReadCacheFallback.test.ts` (+1), `dialogsStore.test.js` (+4) | Republication, stale peer key, edits through the store |

All tests run against fakes in the test process; none ran against a live
server.

### 16.14. Review fix — a signed intent outside the outbox

Reproduced: an intent for a ready row was signed, the tab stopped before the
outbox took it, and after reload the store built a later intent for the same
message while recovery handled the first. The ready-row intent had no entity
key, so the two did not share the per-entity lock and the later revision
could be sent first.

Fix: a ready-row intent records its entity key when it is materialized
(`dialog_messages:<message_id>` or `dialog_message_receipts:<receipt_hash>`
when the key is absent). Recovery handles it under the entity lock, re-reads
it there, hands earlier intents of the same entity to the outbox first, and
sends its stored signed mutation unchanged. Two tests (the store first, and
both at once) check the order insert → update, the same `sign_hash` as
stored (no re-signing), one dispatch each and both intents resolved with an
outbox reference; they fail without the fix. Different entities still run
in parallel.

`toggleReactionCoalescedAcceptance.test.js` had an intents fixture that never
recorded a resolution, which the real store does; it now honours that, and
nothing else in the test changed.

### 16.15. Review fix — intent order

`intentsOf` sorted ids as strings. Ids are
`intent-<time base36>-<counter base36>-<tab>`, and the counter has variable
length, so `…-z-` sorted after `…-10-`. `compareIntentIds` orders by time,
then by tab as a deterministic tie-break (capture order across tabs within
one millisecond is not known), then by the counter as a number.
`tests/intentOrder.test.ts` captures 40 intents within one millisecond and
checks the comparator; it fails with the string sort.

### 16.16. Stage 7 — distribution

Found while checking the tarball:

- Tools that read `@buckitup/pq-client/package.json` failed with
  `ERR_PACKAGE_PATH_NOT_EXPORTED`; the export is added.
- The declarations use the generic `Uint8Array` and need TypeScript ≥ 5.7;
  5.6 fails, 5.7.3 and 7.0.2 pass. Documented.
- `vault` declares DOM types; every other module typechecks without the DOM
  lib. Node ≥ 20.3 for `crypto.subtle` and `AbortSignal.any`.
- `libsodium-wrappers` imports `./libsodium.mjs`, which lives in the sibling
  `libsodium` package; Vite resolves it, esbuild does not. The README shows
  the resolver, and the consumer check uses it.

Prepack ran in a temporary copy of the working tree (tracked and untracked
files, no ignored ones) so the working tree gained no `LICENSE` or build
output. The tarball has 76 files; none is a test, fixture, vector, key or
environment file.

The release workflow runs only from *Run workflow*. Inputs: version, dist-tag
(`next` by default) and `publish` (off by default). `verify` checks the
version against `package.json`, the dist-tag against prerelease or release,
and the changelog section; runs typecheck, lint, tests and build; packs;
checks the tarball's file list; runs the consumer check with the browser;
runs `npm publish --dry-run`; keeps the tarball. `publish` runs only with
`publish` on and from `main`, waits for the `npm-release` environment, and
publishes the tarball from `verify` with provenance. The workflow has not
been run.

Files: `packages/pq-client/package.json`, `README.md`, `CHANGELOG.md`,
`consumer/` (not packed), `scripts/consumer-check.ts`,
`docs/pq-client-release.md`, `.github/workflows/release-pq-client.yml`.

### 16.17. Verification results (2026-11-11)

| Check | Result |
|---|---|
| `node scripts/gen-pq-schema.mjs --check` | Matches the backend schemas |
| `npm run typecheck` | 0 errors |
| `npm run lint` | 0 errors, 82 warnings, all present on `main` |
| `npm test` | 302 files, 3543 passed, 3 skipped. Two earlier full runs failed only `keptFilesStorage`, which passes alone (3 of 3) and failed the same way on the base in stage 1; the last full run was green |
| `npm run build` | App and SDK built; 36 dist modules |
| Consumer check with `--browser` | The tarball from the clean copy: three `tsc` configurations, Node import of all eight modules, Chromium 151 with a virtual PRF authenticator — dialogs, storage and vault pass |
| Framework imports in `packages/pq-client/src` | None |

Not verified: a real passkey, Safari, Firefox, a live server, the release
workflow on GitHub, and publication.

### 16.18. Separate SDK test suite (2026-11-12)

The SDK's tests live in `packages/pq-client/tests` and run without the app:
their own `vitest.config.ts` (node environment, one alias from
`@buckitup/pq-client/*` to `src`, no Vue plugin, no `@/` alias, no app build
constants) and `tsconfig.test.json` for type-checking sources and tests,
including `expectTypeOf` assertions. Test dependencies are declared in the
package's `devDependencies`. `tsconfig.build.json` and the `files` list are
unchanged, so neither the build nor the tarball carries tests, fixtures,
vectors or test configuration.

Moved: identity, vault, rows, transport, ingest, read sessions, shapes,
dialogs, dialog builders, dialog hashes, storage, vouch, origins, notes,
signature, schema, slot ids, slots, gallery keys, conformance, checkpoint,
content, fileCrypto, deviceLink, vaultEnvelope, vaultLock, videoRange,
presented-row fingerprint, avatar gallery access and card vouches for a
contact key (30 files), with `helpers/fakePqServer.ts`,
`helpers/prfAuthenticator.ts`, `helpers/signedFixtures.ts` and
`vectors/pq-conformance.json` (unchanged). The app's tests reach the two
shared helpers through one-line re-exports in `tests/helpers/`.

Split: the passkey-recovery golden vectors use the app's
`src/lib/recovery/passkeyRecovery.ts` and stay in the app as
`tests/passkeyRecoveryGolden.test.ts`; the rest of the checkpoint test moved.
The relation checks of `pqSchemaGen` moved to `schema.test.ts`; the comparison
with the backend generator stays in the app's `tests/pqSchemaGen.test.ts` as a
tooling check, skipped without a backend checkout. The SDK still pins the
schema through the conformance vectors.

Stayed in the app: tests that import app modules, stores, intents, outbox,
auth or components, and those that check the app against the SDK (for example
`apiClientTimeout`, `handshake`, `passkeyLocalIdentity`, which exercises
`@lo-fi/local-data-lock` from the root `node_modules`).

| Command | Result |
|---|---|
| `npm test -w @buckitup/pq-client` (from the package directory: `npx vitest run`) | 30 files, 401 passed |
| `npm run test:app` | 274 files (273 passed, 1 skipped), 3144 passed, 3 skipped |
| `npm test` (runs both) | Both suites green; 3548 tests, the same titles and count as the single suite before the split, none in both suites |
| `npm run typecheck` (`vue-tsc`, then `tsc -p packages/pq-client/tsconfig.test.json`) | No errors; a deliberately wrong `expectTypeOf` is reported |
| `npm run lint` | 0 errors, 81 warnings |
| `npm run build` | App and SDK built; 36 dist modules load in Node |
| `npm pack -w @buckitup/pq-client` | 76 files: `dist`, `README.md`, `CHANGELOG.md`, `LICENSE`, `package.json` |
| `npm run check:consumer -w @buckitup/pq-client -- <tarball>` | Passed (three `tsc` configurations, Node smoke); `--browser` not run |

The CI workflows call `npm run typecheck` and `npm test`, so they run both
suites without change.

Follow-ups (2026-11-12):

- `tests/pqSchemaGen.test.ts` carried an `eslint-disable` for
  `import/no-relative-packages`, a rule of a plugin the ESLint config does not
  load, so linting the file reported an error. The directive is removed;
  `npx eslint tests/pqSchemaGen.test.ts` is clean.
- The `source` field of `pq-conformance.json` named the old test path. It now
  names `packages/pq-client/tests/conformance.test.ts`, the value
  `buildVectors()` writes; regenerating with `WRITE_VECTORS=1` yields the
  committed file byte for byte. A structural comparison shows `source` is the
  only changed key; the cases and expected values are untouched, and `source`
  is excluded from the vector comparison.
- `tests/keptFilesStorage.test.ts` failed once in a full run (first test,
  "lists each with its name, chat, sender, date, size and type", through
  `await world()` at line 141); the error message was not kept. It is
  **open**. Not reproduced in: the file alone, 16 runs of 8 concurrent
  instances (first test about 5 s, the rest about 1.7 s, against a 20 s
  limit), and three later full runs. Checked and excluded: a test timeout
  (Vitest reports it at the `it(` line, not at the `await`); a race between
  `keepFile` and the stray-pin sweep (both hold `underFileLock` for the file,
  and the sweep re-reads the index under it); cross-file shared state (files
  run in separate workers; each test installs a new `IDBFactory` and fake
  server). Not excluded: components are never unmounted between tests, and
  `settle()` waits a fixed number of ticks rather than for a condition. No
  change was made without a reproduced cause; the next failure must be
  captured with its full output.

### 16.19. Audit fixes (2026-11-13)

Checked against backend `origin/main` 26104e4 before each change.

| Finding | Change | Regression test |
|---|---|---|
| A stale-base `user_storage` write with a newer timestamp is accepted with its parent rewritten; the slot stops verifying | Storage writes take the parent's timestamp + 1, so the server refuses a write on a replaced base and the SDK re-applies it; the rest is a backend dependency (§ 11.2 item 6). The fake server checked the signature after rewriting the parent, so it refused what the backend accepts; it now checks the row as sent, then rewrites | `storage.test.ts`: a base replaced seconds earlier (red with the old timestamp rule); the backend limitation, stated as such |
| A keys write without an answer lost V's hash | `incomplete` keeps `originHash` with reason `unknown`; resume reloads and checks V's keys; definite failures return `null` | `origins.test.ts`: before commit, after commit, after a reload with and without the hash, a refused write |
| Origins unreadable in access mode trust | `OriginContext.sessions` for the owner, bearer and reopen on reads; identity of storage and sessions checked | `origins.test.ts` § access mode trust |
| A correctly signed third identity can claim another pair's dialog | `openPeerDialogKey`, `openDialogMessage` | `dialogSafety.test.ts`; every check removed in turn turns a test red |
| A second device's insert of its own `dialog_keys` is `exists` / `conflicted: true` | `ensureDialogKey` | `dialogSafety.test.ts` |
| A tombstone served as `"true"` opened as a live message | `wireBool` in `openMessageRow` | `dialogSafety.test.ts` (red with the old check) |
| A clean install of the package outside the workspace failed `vault.test.ts` (`libsodium-wrappers` 0.7.16's ESM entry) | devDependency pinned to `0.7.15` | Clean copy of the package: `npm install`, `vault.test.ts` 5 passed |

| Command | Result |
|---|---|
| `npm run test:sdk` | 31 files, 419 passed |
| `npm run typecheck` | No errors |
| `npm run lint` | 0 errors, 81 warnings |
| `npm run build` | App and SDK built; 36 dist modules load in Node |
| `npm test` (`test:app`, then `test:sdk`) | `test:app` 1 failed of 3147: `keptFilesStorage.test.ts`, first test, `expect(k.errors.value).toEqual({})` at line 108 received `{ "<user>/f_…01": "Unlock the account to keep files on this device." }`, reached through `world()` (line 141). It is the open failure of § 16.18, now with its output; the file touches no changed SDK path. `test:sdk` did not run after it in that command and was run alone |
| Tarball installed in a clean TypeScript consumer (no workspace, no aliases) | `tsc` strict without `skipLibCheck`; 45 Node scenarios pass against an independent fake that rewrites parents as the backend does |

Not verified: a live server, a real passkey, Safari, Firefox.

### 16.20. Next

Before publication, outside this repository: the npm scope and credentials,
the `npm-release` environment (§ 11.3, § 9.2). Then a version PR for
`0.2.0-rc.0`, a dry run, and the approved publication under `next`. Stage 8
and the live checks of § 11.2 need the partner's test server.
