# Frontend / pq-client extraction audit

Historical document retained from chat-frontend during the repository split.
Paths, commands, test counts and completion marks describe their recorded
baseline; use the [current documentation index](../README.md) for the supported
SDK and [frontend integration](https://github.com/Buckitup-chat/chat-frontend/blob/main/docs/pq-client-integration.md) for the app.

Date: 2026-11-12. Scope: the working tree over frontend HEAD `507d0ff6108fe967982f78740aa8159cc3449bec`, including untracked SDK files.

The audit first listed deletion candidates without changing code. The cleanup it recommended (sections 2–3.4) was then carried out in the same working tree, with callers re-checked before each deletion; section 3 records what was done and what was kept. Nothing was committed, pushed or published.

## 1. Size of the application

Against the local HEAD, `git diff --numstat -- src` reported **428 added / 746 removed / net -318 lines** before the cleanup and **454 added / 972 removed / net -518 lines** after it. The cleanup alone accounts for **61 added / 261 removed / net -200 lines** in `src` (current tree compared with a snapshot taken immediately before it). These counts include comments and formatting.

The repository-wide diff is larger because it includes SDK source, new functionality, tests, consumer checks, documentation and release tooling.

## 2. Unused code — removed

| App location | Result |
| --- | --- |
| `src/api/client.js`: `FETCH_TIMEOUT_MS`, `timedFetch` and their comment | Removed. App requests go through the SDK transport, which carries its own deadline (`tests/apiClientTimeout.test.js` still checks it). The unrelated timeout constants in recovery, readSession and turnCredentials are untouched |
| `src/libs/DialogCrypto.js`: `strToBytes` | Removed together with the whole file (3.1); it had no caller |

## 3. Wrappers whose implementation is in the SDK

### 3.1. `src/libs/DialogCrypto.js` — removed

Runtime callers import `@buckitup/pq-client/dialogs` directly:

| Former class method | Direct SDK function | Callers |
| --- | --- | --- |
| `computeDialogHash` | `dialogHash` (imported as `computeDialogHash` where a local `dialogHash` exists) | `dialogs.store.js` |
| `deriveSenderMsgKey` | `deriveSenderMsgKey` | `dialogs.store.js`, `messageIntent.ts` |
| `wrapSenderMsgKey` | `wrapSenderMsgKey`, returning snake_case `peer_kem_wrap_key_b64` / `peer_wrapped_msg_key_b64` | `messageIntent.ts` (through the builders) |
| `unwrapSenderMsgKey` | `unwrapSenderMsgKey` | `dialogs.store.js` |
| `encryptContent` / `decryptContent` | same names | `messageIntent.ts` / `dialogs.store.js` |
| `computeReactionHash` | `reactionHash` (imported as `computeReactionHash`) | `messageIntent.ts` |
| `computeReceiptHash` | `receiptHash` (imported as `computeReceiptHash`) | `dialogs.store.js` |

The camelCase→snake_case round trip of `appCrypto.wrap` is gone. What remains in `messageIntent.ts` is one line, `const dialogRowCrypto = { encrypt: encryptContent, wrap: wrapSenderMsgKey }`, passed to `buildDialogKeyRow` / `buildMessageRow` / `buildRevisionRow`.

**Why it is kept.** A builder calls its own module's bindings, which a module mock cannot replace. Behavioural tests replace `encryptContent` and `wrapSenderMsgKey` to hold encryption at a gate (session-switch and race tests in `messageIntentRecovery`), to count wraps (`dialogKeysReloadSafety`, `messageIntentSessionBoundaries`) and to make content readable without keys. With the builders left to their defaults, 15 of those tests fail. In production the object passes exactly the functions the builders would use by default.

Tests: thirteen `vi.mock('@/libs/DialogCrypto')` mocks became partial mocks of `@buckitup/pq-client/dialogs` with the SDK names and snake_case wrap results; direct users import the SDK functions. Conformance (`conformance`), derivation (`dialogs`, `dialogBuilders`), receipts, wrapping and messaging tests are kept. The two tests that compared `DialogCrypto.deriveSenderMsgKey` with the SDK now check the SDK function alone, since the app no longer has a second entry point. A stale comment in `packages/pq-client/src/hkdf.ts` that named the removed class was dropped (comment only).

### 3.2. `src/lib/data/slots.ts` — removed

`EncryptionManagerPQ.js`, `packages/pq-client/tests/slots.test.ts`, `tests/slotRootDeliveryOutcome.test.ts` and the module mock in `tests/slotCreationRace.test.js` use `@buckitup/pq-client/slots`.

### 3.3. `src/lib/data/types.ts` — removed

All production imports (13 relative `./types` and 6 `@/lib/data/types`), test imports and `scripts/handshake-check/harness.ts` use `@buckitup/pq-client/types`. Type-only; no runtime effect.

### 3.4. Mutation construction — one path, adapters removed

`intentRecovery.ts::buildSignedMutation` is now:

```ts
rowMutation(intent.relation, signRow(intent.relation, intent.row, signSkey), intent.mutationType ?? 'insert')
```

`createUserCard`, `createStorageMutation` and `createGenericMutation` are removed from `src/api/client.js`, which now holds only `ingestWithAuthEach`, `getDeviceIdentity` and `getChallenge`. `ReadyRowIntent.mutationType` is narrowed to `'insert' | 'update'`, the only values any producer writes; `?? 'insert'` keeps the old default.

Contract check of the removed branches:

| Old behaviour | Where it is now |
| --- | --- |
| Storage: captured `owner_timestamp`, falling back to now | `materializeStorageIntent` always sets `nextOwnerTimestamp(base)`; the fallback was unreachable for ready rows |
| Storage: `deleted_flag` coerced with `!!`, `parent_sign_hash ?? null` | The materializer writes a boolean `deletedFlag` (typed, defaulted to `false` by every caller) and `base?.sign_hash ?? null` |
| Storage: accepts a ready signature / positional arguments | No production caller used them. The ready-signature case is the recovery replay below |
| Card: `deleted_flag` forced to `false` | `storeCardIntentUnderLock` writes `deleted_flag: false` into the ready row |
| Card: keys decoded (`\x` hex or base64) and re-encoded as padded base64 | `storeCardIntentUnderLock` writes `toBase64(toBytes(field))` for the five binary columns, so wire values and the signed payload stay canonical whatever encoding the local card holds |
| Card: return value wrapped with `sign_skey` | Only `.mutation` was used |
| Local metadata stripped | `rowMutation` copies only schema fields, as before |
| Insert vs update, `original` keys | Same `rowMutation` as before |

**Recovery replay.** A stored `signedMutation` is still sent as it was signed: the `claimed` path in `signAndDispatchIntentUnguarded` does not call `buildSignedMutation`. A new test in `tests/intentRecovery.test.ts` stores a really signed `user_storage` snapshot, replays it with a different key, and checks that `signRow` is never called and the sent mutation is byte-identical (JSON) and still verifies; it fails if the claimed snapshot is re-signed.

**Card equivalence.** A new test in `tests/userCardConstructionDecision.test.ts` gives `storeCardIntentUnderLock` a card with an unpadded `sign_pkey` and a `\x` hex `crypt_cert`, and checks that the stored row is the complete wire row (padded base64, `deleted_flag: false`) and that its signed mutation verifies. It fails both without `deleted_flag` and without the re-encoding.

Tests: the fake builders that about thirty tests injected through `vi.mock('@/api/client')` now sit in partial mocks of `@buckitup/pq-client/rows` (`signRow` returns the row, `rowMutation` carries the old fake body; positional storage arguments became fields of the row, e.g. `call[9]` → `call[1].parent_sign_hash`). Where a test also uploads files (`liveSendThroughSender`, `approvalCallerStatus`), `files` and `file_chunks` pass through to the real functions. `userCardBootstrap` wraps the real `signRow` for `user_cards` to count signatures and simulate a signing failure. The adapter tests in `dataLayer.test.ts` (update shape, server signing payload for `user_storage`) now exercise `signRow` + `rowMutation`.

### 3.5. Small duplicate primitives in `secureStore.ts` — not done (out of scope)

The private Base64 encoder duplicates SDK `signature.toBase64` for Uint8Array inputs. Its decoder uses `atob` directly, while SDK `fromBase64` normalizes padding; malformed-input and error behaviour must be validated before replacing it. Keep `DecryptFailedError` and the app's storage error mapping. This does not justify removing secureStore or changing its encryption key.

## 4. Similar code that is not safe to replace blindly

| App area | Why the SDK is not a drop-in replacement | Decision |
| --- | --- | --- |
| `userStorage.ts`, `storageIntent.ts`, `userStorageBase.ts` | Durable intents, outbox linkage, accepted/pending bases, cross-tab locks, recovery and delivery statuses. SDK storage performs direct HTTP writes | Keep orchestration. Do not replace these modules with SDK `createUserStorage` |
| `storageIntent.ts::mergeJsonPatch`, keyed/sticky/contact/vault-list helpers | App merges preserve null deletion directives across coalescing, contact confirmation state and recovery-vault retirement. SDK `mergeJson` removes null entries immediately and has a different root-slot merge policy | No direct deletion. Extract only a proven equivalent generic subroutine, preserving policy tests |
| `readSession.ts`, `shapeRead.ts` | SDK read-session lifecycle/snapshot logic is already used, while card recovery, auth state, blocked-shape UI and anonymous-read policy stay in app | Keep adapters |
| `rowVerification.ts` | Resolves verified author cards, maps missing/locked states and selects supported relations. Generic SDK signature verification does not replace that policy | Keep dispatcher/resolver. Optionally simplify redundant dialog-specific forwarding branches using generic SDK verifyRow, preserving outcomes |
| `accountVault.js` | Legacy vault support, credential defaults, navigator patch and SDK forwarding | Keep app-specific behaviour. Direct re-exports can replace assignment boilerplate, but deleting the file breaks legacy/current callers |
| `keyCustody.ts` | VaultLockedError is re-exported; SigningKeySource and AccountMismatchError are app contracts | Keep the file |
| `EncryptionManagerPQ.js` | Auth/session lifecycle, bootstrap, recovery, account registry, outbox and gallery behaviour. Storage encryption is delegated to SDK | Do not replace the manager with IdentityHandle |
| `contactVouches.ts` | SDK signs rows, while contact-specific grant policy, queued supersession, intents and session fences remain in app | Keep app policy; SDK issueVouch would bypass that durable lifecycle |
| `ingest.ts`, `intentRecovery.ts`, outbox/coordinator/barrier | SDK classifies transport outcomes; app owns durable replay, acceptance/visibility, dependencies and UI statuses | Keep. These are not duplicate HTTP transport |
| `collections.ts`, `shapeLink.ts` | Electric/TanStack reactivity, caching and persistence integration | Keep. SDK live subscription is a separate frontend-independent service |
| `fileTransfer.ts`, file caches and kept-file modules | SDK file encryption/signing reused; chunk IO, resume, progress, quota and offline copies remain app features | Keep orchestration |
| `secureStore.ts::deriveLocalStorageKey` | Salt `buckitup-local-storage-v1`, extractable key required for HMAC key mapping; SDK storage uses `avatar-encryption` and a non-extractable key | Not equivalent; never substitute one derivation for the other |
| `backupCrypto.ts` | Password-derived file backup, 600000 PBKDF2 rounds, separate envelope and error contract | Not SDK User Storage encryption |
| `avatars/sharedGallery.ts` | Versioned envelope and address-bound AES-GCM AAD; SDK plain AES-GCM has no equivalent contract | Keep gallery-specific encryption/validation |
| `enigma.js`, `EncryptionManager.js`, Yjs/WebRTC legacy modules | Active global/legacy consumers; not all contracts exist in pq-client | Outside safe extraction deletion. Separate legacy usage audit required |

`enigma.arrayToBase64` normalizes non-Uint8Array inputs, `base64ToArray` uses permissive Buffer decoding, and `decodeHexOrBase64` returns null on empty input. SDK functions have different accepted-input/error contracts, so direct alias replacement is not automatically safe. `intentRecovery.ts` no longer imports `decodeHexOrBase64`; other callers still do.

The manager's challenge/handshake signing methods are guarded access to the authenticated account. Removing them requires integrating an IdentityHandle through login/lock/logout/recovery, not replacing a line with an import.

## 5. What is delegated to the SDK

- Slot resolution, dialog cryptography, row types and mutation construction: imported from the SDK with no app wrapper.
- PRF vault implementation: SDK; accountVault keeps the legacy/browser adapter.
- Canonical row schemas, signatures and hash prefixes: SDK rows.
- Ordinary identity key generation and card key fields: SDK identity.
- User Storage encryption and key derivation in the manager: SDK storage; small private wrappers still add an app-specific hash/return shape.
- Read-session timers and snapshot pagination: SDK transport services.
- File chunk encryption: SDK fileCrypto.
- Server-result classification: SDK helpers.

## 6. Validation of the cleanup

Run on the working tree after the cleanup:

- `npm run typecheck` (vue-tsc): no errors. `scripts/handshake-check/harness.ts`, outside the tsconfig include, was type-checked separately with a temporary config: no errors.
- `npm run lint`: 0 errors, 81 warnings; the changed files add no warnings.
- `npm test`: 302 files passed, 1 skipped; 3545 tests passed, 3 skipped. One earlier full run had a single failure in `tests/keptFilesStorage.test.ts` (a component test that touches none of the changed modules); it passed in isolation and on the next full run.
- `npm run build`: app, service worker and pq-client build and the SDK Node smoke check pass.
- Replay and isolation: `intentRecovery`, `intentRecoveryDurableResolve`, `messageIntentRecovery`, `signedSnapshotUnlock`, `crossTabSigningRace`, `awaitingUnlock`, `dialogIntentsAwaitingUnlock`, `heldWriteCallers`, `messageIntentSessionBoundaries`, `userStorageSessionFencing`, `userStorageLocalStoreOwnerPinning`, `chainedConstructionAndIsolation`, `userCardBootstrap`, `userCardConstructionDecision`, `conformance`, `checkpoint`, `dialogCrypto`, `dialogs`, `dialogBuilders`, `receiptSingleIdentity`: 20 files, 298 tests passed.
- No import or mock of `@/libs/DialogCrypto`, `@/lib/data/slots`, `@/lib/data/types` or the removed `api.create*` methods remains in `src`, `tests`, `e2e`, `scripts` or `packages/pq-client/src`.
- The E2E suite against staging was not run.

## 7. Remaining candidates

1. `secureStore.ts` Base64 helpers (3.5), after malformed-input behaviour is pinned.
2. Redundant dialog-specific forwarding in `rowVerification.ts`, preserving outcomes.
3. Assignment boilerplate in `accountVault.js` that can become direct re-exports.
4. A legacy usage audit for `enigma.js`, `EncryptionManager.js` and the Yjs/WebRTC modules before any of them is treated as removable.

Everything in section 4 stays: those modules hold lifecycle, persistence and policy that the SDK does not provide.
