# Changelog

Semver. A change of the wire protocol or of a derivation is a major version
and is announced to partners. Prereleases carry `-rc.N` and the `next`
dist-tag.

## [Unreleased]

### Added

- `personas`: identities an account derives from its own keys and an index
  (HKDF-SHA3-256, salt `buckitup/persona/v1`, info I2OSP(index, 4) || label,
  labels `sign`, `crypt`, `contact`, `evm`, `meta`). `derivePersona`,
  `accountPersonas` (several indexes from one extract, `userHash` alone),
  `personaPrefix`, `isPersonaIndex`, `wipePersona`; indexes 0 to 2³² − 1.
- `derivedIdentity`: `DerivedAccount`, `IdentityFamily.account`,
  `deriveAccount` and `wipeAccount` give every key an account holds, the EVM
  key and meta seed included. Existing derivations and the notes identities
  are unchanged.
- `deviceLink`: an invite may name its server, `<room>.<fingerprint>@<origin>`
  (`LinkInvite.origin`, `isInviteOrigin`). The origin must be a serialized
  HTTPS origin, or HTTP for `localhost`. Codes without an origin encode and
  parse as in 1.1.0; the session derivation does not change.

### Tests

- Persona golden vectors for a fixed account at indexes 0, 258 and 2³² − 1,
  checked against a reference HKDF; index bounds; parent keys left unchanged.
- Invite codes with and without an origin, refused schemes, hosts and URL
  forms, damaged rooms and fingerprints.

## [1.1.0] - 2026-11-19

### Added

- `contactAccess`: a contact's device-storage access as a service over
  application adapters. `initialAccessDecision` grants after a verified QR
  confirmation only over a contacts list known to hold no confirmation of the
  key; `classifySlotPrior` and `contactsPriorOf` tell a readable list, a new
  slot and an unknown one apart; a list, record or entry of any other
  shape is unknown and grants nothing. `createContactAccess` stores explicit grants
  and revokes as durable requests queued per issuer, device and contact,
  binds a request without a device before signing, sends through the
  application's outbox, and resolves a request only when both verified rows
  show it. `contactAccessView` derives the confirmed state, the request in
  flight and whether the switch may be used.

### Tests

- Behavior of contact access against the fake server: initial and repeated
  confirmation, revoke and regrant, prior list states including malformed
  ones, partial outcomes,
  retries across a reload, confirmation through rows, device isolation.

## [1.0.1] - 2026-11-18

### Changed

- Clarify SDK ownership, handshake implementation status and service
  compatibility limits; update standalone-package paths and commands.

### Tests

- Complete migrated handshake, PRF vault lifecycle, identity, row mutation
  and vouch payload coverage.

## [1.0.0] - 2026-11-16

First public release.

### Added

- `identity`: key generation, restoring keys from secret keys with keypair
  checks, `user_cards` rows, identity handles (sign, decapsulate, dialog keys)
  and a multi-identity session; `publishUserCard`.
- `vault`: secret keys at rest under a passkey's WebAuthn PRF output
  (`createPrfVault`, `openPrfVault`, `writeIdentityKeys`, `openVaultIdentity`)
  with typed errors.
- `rows`: `signRow`, `verifyRow`, `rowMutation`, schemas of every relation
  including `origins` and `origin_settings`.
- `transport`: `ingest`, typed write rejections, `TransportError.kind`,
  `readShapeChunk`, complete snapshots, `subscribeShape`, `createReadSessions`.
- `dialogs`: row builders for `dialog_keys`, messages and revisions, refs,
  `openMessageRow` (a tombstone's `deleted_flag` in every wire form);
  `ensureDialogKey` writes an identity's own `dialog_keys` row only when none
  is stored; `openPeerDialogKey` and `openDialogMessage` open a peer's key and
  a message only for the dialog, peer and author the caller names, with the
  author's card verified.
- `storage`: User Storage slots, merge, the `origins` slot. A write takes its
  parent's `owner_timestamp` + 1, so a write on a replaced base is refused and
  made again on the newer one; a write sent without an answer is `unknown`.
- `vouch`: issue and retract, scopes.
- `origins`: venue creation, resume, update and settings. A keys write sent
  without an answer returns `incomplete` with V's `originHash` and reason
  `unknown`; `resumeOrigin` reloads V from the `origins` slot and checks its
  keys; reads use the owner's read sessions (`OriginContext.sessions`) in
  access mode `trust`.
- `./package.json` is exported.

### Changed

- `transport.ingestEach` returns `{ kind: 'results', status, results, rows }`
  or `{ kind: 'rejected', status, rejection }` instead of `{ status, results }`.
- `readShapeOnce` follows the shape until it is up to date and fails with a
  `malformed` `TransportError` when the server does not say so.
- `verifyDialogRow` requires `sign_hash` on message rows
  (`missing_sign_hash`).
- `derivedIdentity.signedUserCard` signs through `rows`; same rows as before.

### Requirements

- Node 22.14 or newer; TypeScript 5.7 or newer for the declarations.
- ES2022 output for code that imports `vault` (top-level await in its
  `@lo-fi/*` dependencies).

## [0.1.0]

Workspace-only; never published. Canonical payloads and signatures, card and
dialog row verification, content encoding, key derivations, the vault
envelope, device link, the optical handshake, derived identities, and the
HTTP transport (`ingest_each`, read-session requests, one-shot reads).
