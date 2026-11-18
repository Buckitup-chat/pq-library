# Changelog

Semver. A change of the wire protocol or of a derivation is a major version
and is announced to partners. Prereleases carry `-rc.N` and the `next`
dist-tag.

## [Unreleased]

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
