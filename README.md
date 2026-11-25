# @buckitup/pq-client

The BuckitUp post-quantum protocol as a library, without a UI framework:
identities and their `user_cards`, secret keys at rest under a passkey,
canonical signed rows, the HTTP transport (key proofs, writes, snapshot and
live reads, read sessions), two-person dialogs, User Storage slots, vouches
and venues (origins).

Use the SDK from browser or Node applications with any UI framework. Local
cryptographic operations work independently of a server. Network operations
use the documented [service protocol](https://github.com/Buckitup-chat/pq-library/blob/main/docs/protocol.md); consumers can supply
a server URL and a fetch implementation, or implement the Transport interface
for a compatible service.

## Requirements

| Where | Needs |
|---|---|
| Node | 22.14 or newer, ESM |
| Browser | WebCrypto, IndexedDB and, for the vault, WebAuthn with the PRF extension |
| TypeScript | 5.7 or newer (the declarations use `Uint8Array<ArrayBuffer>`). DOM types are also required by declarations using WebCrypto types, including `vault`, `storage` and `origins` |
| Vault | libsodium available as the global `sodium` before the first vault call (§ Vault in the browser) |
| Bundler | ES2022 output for code that imports `vault`: its `@lo-fi/*` dependencies use top-level await. In Vite set both `build.target` and `optimizeDeps.esbuildOptions.target` to `'es2022'`; with Vite's defaults the dev server fails to pre-bundle them |

## Install

The public package is available on npm. Development and CI use Node 22.23.1
(`.nvmrc`). Pin the release used by your application and run its integration
checks when upgrading.

```sh
npm install --save-exact @buckitup/pq-client@1.0.0  # the first public release
npm install --save-exact @buckitup/pq-client@next   # when a prerelease is published
```

Each module is its own entry point, `@buckitup/pq-client/<module>`, an ES2022
module. Importing a module makes no network request, opens no passkey prompt
and touches no browser storage.

| Module | Contents |
|---|---|
| `identity` | key generation, restoring keys from secret keys (checked), `user_cards` row and certificates, `user_hash`, identity handles, a multi-identity session |
| `vault` | secret keys at rest under a passkey's WebAuthn PRF output |
| `rows` | canonical payload, `signRow` / `verifyRow`, `sign_hash`, the signable schema of every relation, base64 padding rules, mutations |
| `transport` | challenge and key proof, `ingest` / `ingest_each` with typed rejections, device identity, read sessions, complete snapshots, live subscriptions |
| `dialogs` | `dialog_hash`, `sender_msg_key`, key wrap and unwrap, content encryption, row builders, publishing one's own `dialog_keys` row once, opening a peer's key and messages against the expected dialog and authors |
| `storage` | User Storage slots: addressing, encryption, JSON merge, signed writes that a newer base refuses and that are then re-applied on it, the `origins` slot of venue keys |
| `vouch` | `vouch_tokens` issue and retract, scopes |
| `contactAccess` | a contact's device-storage access: initial grant after a verified QR confirmation, explicit grant and revoke as durable requests, confirmation through verified rows, the state a client shows |
| `origins` | venue creation, resume and update, `origin_settings` |

Lower-level modules the eight build on (`signature`, `schema`, `verifyCard`,
`vaultLock`, `content`, `hkdf`, …) are entry points too.

## Concepts

- **Row signature and request proof are separate.** `identity.signRow` signs a
  row as one identity; the `sign` passed to the transport proves the request
  as an identity. Usually both are the author of the rows; an origin update is
  signed by the owner or the venue and always proved by the owner.
- **One request, one prover.** A new identity's card goes in a request of its
  own, proved by that identity, before anything else of it.
- **Accepted is not visible.** `ingest` answers when the server committed a
  row; the row reaches a live subscription later. `readShapeOnce` reads a
  fresh snapshot (it asks for a shape nobody else uses); server read-model
  propagation can still lag behind a commit; a subscription's first up-to-date answer is not a freshness
  guarantee (§ Reads).
- **Timestamps grow.** An update must carry an `owner_timestamp` strictly
  above the stored one; the builders take a timestamp and refuse one that is
  not newer than the base.
- **Binary columns arrive unpadded.** `/shapes` serves `bytea` columns
  (`sign_b64`, `*_pkey`, `*_cert`, `*_b64`) as base64 without `=` padding;
  rows built and signed locally carry padding. Every verify and decode
  function takes either form. Compare two binary values by their bytes
  (`toBytes`) or after `padBase64`, never as raw strings; `sign_hash`,
  `user_hash` and `dialog_hash` are hex text and compare as strings.
- **Keys stay inside handles.** An `IdentityHandle` signs, decapsulates and
  derives dialog keys without exposing secret keys; `exportKeys()` returns a
  copy when keys must be stored, and `close()` wipes the handle's copy.

## Examples

### Identity and card

```ts
import { generateIdentityKeys, openIdentity, publishUserCard } from '@buckitup/pq-client/identity';
import { createTransport } from '@buckitup/pq-client/transport';

const server = createTransport({ baseUrl: 'https://chat.example/electric/v1' });

const alice = openIdentity(generateIdentityKeys());
const card = alice.userCard({ name: 'Alice', ownerTimestamp: Math.floor(Date.now() / 1000) });
const outcome = await publishUserCard(server, alice, card);
// outcome.kind === 'results' → outcome.rows[0].kind is 'written' or 'rejected'
```

`identityKeysFromSecrets({ signSkey, cryptSkey, contactSkey }, { userHash })`
rebuilds the keys of a known identity, checks the expected public identity and
runs keypair consistency checks, and throws `IdentityKeysError` on failure.
The ML-DSA signing probe does not detect every possible corruption of a secret
key; it is not a complete structural validation of all ML-DSA components.

### Vault (browser)

```ts
import { generateIdentityKeys } from '@buckitup/pq-client/identity';
import { createPrfVault, openPrfVault, prfLockOf, writeIdentityKeys, openVaultIdentity } from '@buckitup/pq-client/vault';

const keys = generateIdentityKeys();
const { vault } = await createPrfVault({ name: 'Alice', credentials: navigator.credentials, rpId: location.hostname });
await writeIdentityKeys(vault, keys);
vault.lock();

// later, or on another visit
const lock = await prfLockOf(vault.id);
const reopened = await openPrfVault(vault.id, lock!, { credentials: navigator.credentials });
const alice = await openVaultIdentity(reopened);
```

Keep `vault.id` (and the user's `user_hash`) somewhere your app can find it;
the vault itself is an encrypted IndexedDB record.

### A dialog

```ts
import { buildMessageRow, dialogHash, ensureDialogKey, openDialogMessage, openPeerDialogKey } from '@buckitup/pq-client/dialogs';
import { rowMutation } from '@buckitup/pq-client/rows';

const now = () => Math.floor(Date.now() / 1000);

// Alice writes to Bob. bobCard: Bob's user_cards row as read from the server.
const key = await ensureDialogKey({ transport: server, identity: alice, peerHash: bob.userHash, peerCard: bobCard });
if (key.kind !== 'written' && key.kind !== 'present') {
	// For 'unknown', read/retry the same operation before sending.
	throw new Error(`Dialog key is not ready: ${key.kind}`);
}
const message = alice.signRow('dialog_messages', await buildMessageRow(alice.senderMsgKey(bob.userHash), {
	senderHash: alice.userHash, dialogHash: dialogHash(alice.userHash, bob.userHash),
	parts: [{ kind: 'text', text: 'Hello' }], refs: {}, ownerTimestamp: now(),
}));
await server.ingest([rowMutation('dialog_messages', message)], alice.sign);

// Bob reads the dialog with Alice. Bob says whom he expects; nothing is taken from the rows.
const peerKey = await openPeerDialogKey(bob, keyRowFromShape, { peerHash: alice.userHash, peerCard: aliceCard });
if (peerKey.status === 'ok') {
	const opened = await openDialogMessage(messageFromShape, {
		me: bob.userHash, peerHash: alice.userHash, senderCard: aliceCard, senderMsgKey: peerKey.senderMsgKey,
	});
	// opened.status: 'ok' (parts, refs, deleted) | 'invalid' (reason) | 'undecryptable'
}
```

`ensureDialogKey` reads the identity's own `dialog_keys` row first and writes
only when there is none. Any device of the identity derives the same
`sender_msg_key`, so a verified own row written elsewhere serves every device;
a second insert would be refused as `exists` with `conflicted: true`, because
each wrapping is randomised. An own row that is a tombstone is reported as
`deleted` and left as it is. In access mode `trust` pass the identity's read
sessions as `sessions`.

`openPeerDialogKey` uses a key row only when the peer's card verifies and
belongs to `peerHash`, the row is that peer's (`sender_hash`), addressed to the
reader (`peer_hash`), in their dialog (`dialog_hash`), signed by the peer, and
not a tombstone. `openDialogMessage` opens a message only when it is in the
dialog of `me` and `peerHash`, its author is one of the two, and the card given
for the author verifies and is the author's. The backend verifies row signatures and request proofs, but does not enforce
the caller's expected participant-to-dialog binding: a vouched identity can
write a correctly signed row naming another dialog. The lower-level `IdentityHandle.unwrapPeerKey` and `openMessageRow`
check only what their names say — a decapsulation, and a signature against the
key passed in.

`refs` are the caller's: the tails of what the author has seen in the dialog,
as `pq_dialogs` § References defines them. `{}` is accepted by every reader.

An edit or a deletion is `buildRevisionRow(key, tip, { parts | deleted, refs,
ownerTimestamp })`, written as an update: its parent is the tip's `sign_hash`.
`withEditedText(parts, text)` (from `content`) replaces the text and keeps
quotes and attachments. Build a revision on the freshest tip: the server
accepts a revision whose timestamp is newer than the stored one even when its
parent is an older revision, and then stores its own tip as the parent, so the
row no longer matches its signature (§ Concurrent writers).

### User Storage

```ts
import { createUserStorage } from '@buckitup/pq-client/storage';

const storage = createUserStorage({ transport: server, owner: alice });
await storage.patchSlot('settings', { theme: 'dark' });
const read = await storage.readSlot<{ theme: string }>('settings');
// read.kind: 'found' | 'absent' | 'unavailable' | 'unverified' | 'undecryptable'
```

A write reads the current row first and signs the new one with that row as
its parent and `owner_timestamp` = the parent's + 1. A write built on a base
another device has already replaced therefore carries a timestamp that is not
newer than the stored one; the server refuses it as `stale_timestamp`, and the
write is made again on the newer base (at most four attempts). Nothing is
written over a base that is unavailable, does not verify or does not decrypt.
A write sent without an answer is `unknown`: it may have been committed, and
the next read tells.

Removing an entry (`patchSlot(name, { key: null })`, `removeOriginKeys`)
writes a new revision without it. The server keeps every earlier revision in
`user_storage_versions`, encrypted as before, so a removed value stays
readable to whoever holds the owner's keys; erasing it is an operator's step
on the server.

#### Concurrent writers

The server does not compare a write's parent with the stored row: it refuses
only a timestamp that is not newer, and after checking the signature it
replaces `parent_sign_hash` with the stored row's `sign_hash`
(`chat/lib/chat/data/versioning.ex`, `compare_timestamps`). Parent + 1 rejects
a stale SDK write once a newer base is visible to validation. It does not
protect against:

- a writer that does not derive the timestamp from the parent (another
  client) writes on a stale base; or
- two writes from the same base reach the server at the same moment: it reads
  the stored row and updates it in separate statements.

Depending on the interleaving, a write can overwrite a concurrent change or
be stored with a parent it did not sign. An altered parent makes the row fail
verification: reads report `unverified`, and the SDK refuses to write over it
until it is repaired. A guaranteed merge needs an atomic stale-base rejection
that preserves signed fields and lets the client re-read and re-apply its
change. Preserving the signed parent alone does not prevent lost updates.
The same backend limitation affects revisions of `dialog_messages`.

### Vouches

```ts
import { issueVouch, retractVouch, storageScope } from '@buckitup/pq-client/vouch';

const { device_id } = await server.deviceIdentity();
const scope = storageScope(device_id, 'write', 'dialog_messages', codeId);
await issueVouch({ transport: server, issuer: bot }, scope, guestHash);
await retractVouch({ transport: server, issuer: bot }, scope, guestHash);
```

A vouch for `device.<id>.storage.write.<shape>.<suffix>` grants the whole
shape: the suffix only makes the row distinct. Whether a write is admitted is
decided by the server's trust chain.

### Contact access

```ts
import { contactAccessView, createContactAccess, initialAccessDecision, verifyContactConfirmation } from '@buckitup/pq-client/contactAccess';

const access = createContactAccess(adapters);
const decision = initialAccessDecision({ confirmation: verifyContactConfirmation(card, peerHash, shownKey), prior, subjectHash: peerHash, contactPkey: shownKey });
if (decision.grant) await access.request(session, peerHash, true);
await access.request(session, peerHash, false, deviceId);
const view = contactAccessView(await access.snapshot(me.userHash, peerHash));
```

The service owns the rules; the application supplies durable intents, its
outbox, row verification, shape reads and the device identity as adapters.
Withdrawing an issuer's grant does not remove access another issuer gave. See
[contact access](docs/contact-access.md).

### Venues

```ts
import { createOrigin, resumeOrigin, openOrigin, readOrigin, updateOrigin, setOriginSetting } from '@buckitup/pq-client/origins';
import { createUserStorage, ORIGINS_SLOT } from '@buckitup/pq-client/storage';

const ctx = { transport: server, owner, storage: createUserStorage({ transport: server, owner }) };
const created = await createOrigin(ctx, { name: 'Cafe', moderationMode: 'post' });
if (created.kind === 'incomplete' && created.originHash) {
	// keep created.originHash; later, or after a reload:
	await resumeOrigin(ctx, created.originHash, { name: 'Cafe' });
}

// another device of the same owner
const venue = await openOrigin(ctxOnThatDevice, originHash); // venue.kind === 'found' → venue.identity acts as V
await updateOrigin(ctx, originHash, { name: 'Cafe & Bar' });
await setOriginSetting(ctx, originHash, 'review_access', 'invite_only');
venue.kind === 'found' && venue.identity.close();
```

`createOrigin` generates V and stores V's keys in the owner's `origins` slot
before anything is published. It then reads them back from the slot and, as
V, publishes V's card and the `origins` row, each in a request of its own
proved by V. The requests are not one transaction. An `incomplete` result
names the step that failed and why:

| `failed` | `originHash` | What it means | What to do |
|---|---|---|---|
| `keys`, reason `unknown` | V's hash | The keys were sent and no answer came: they may be stored | `resumeOrigin`: it continues V if the keys are in the slot, and returns `keys` / `absent` if they are not |
| `keys`, any other reason | `null` | Nothing was stored, nothing published; V is discarded | Call `createOrigin` again |
| `keys`, reason `absent` (from `resumeOrigin`) | V's hash | V's keys are not currently in the slot; this does not prove V was never published | Check the server and local operation state before creating another V |
| `card` or `origin` | V's hash | Keys stored; the step's write was refused, unanswered (`unknown`) or its read failed | `resumeOrigin` |

`resumeOrigin` always reloads V from the slot and checks that the keys belong
to V; it never makes another V, and it skips a step whose verified row is
already on the server. A caller that lost `originHash` (a crash before the
result) finds an unpublished V as an entry of the `origins` slot for which
`readOrigin` is `absent`. A V whose answer was lost before the write reached
the server is not in the slot; if that write was still committed later, the
slot keeps an entry for a V that was never published.

The handle in a `created` result and in `openOrigin` belongs to the caller,
who closes it. `updateOrigin` signs as the owner by default; with
`signer: 'venue'` it loads V and closes that handle when finished.
`setOriginSetting` loads V and closes that handle when finished.
The context's `storage` and `sessions` must belong to `owner`; anything else
throws `TypeError`. In access mode `trust` pass the owner's read sessions as
`sessions` (for `origins` and `origin_settings`) and to `createUserStorage`
(for `user_storage`); `user_cards` and `vouch_tokens` are not gated.

### Reads

```ts
import { subscribeShape } from '@buckitup/pq-client/transport';

const snapshot = await server.readShapeOnce('dialog_messages', `dialog_hash = '${hash}'`);
const sub = subscribeShape(server, { table: 'dialog_messages', where: `dialog_hash = '${hash}'`, onChange: (u) => render(u.rows) });
await sub.ready;
sub.dispose();
```

`readShapeOnce` is the read to take a decision on: it salts the where clause,
so the server builds a new snapshot and no HTTP cache holds an answer for it.
`subscribeShape` follows a shape live; its first request is the plain
`offset=-1` snapshot, which a browser may answer from its HTTP cache when the
server sends cacheable headers. Its first up-to-date update can
therefore be old; the live requests after it bring the changes since. Do not
use a subscription's first up-to-date as a fresh one-shot read.

In access mode `trust`, `createReadSessions({ transport: server, identity: {
userHash, sign } })` keeps one identity's read sessions on one server; pass it
to `subscribeShape` as `sessions`, and for `readShapeOnce` pass
`sessions.bearer(table)` as `authorization` and reopen on
`read_session_required`.

## Errors

| Situation | What you get |
|---|---|
| Write refused | `{ kind: 'rejected', rejection }`; `rejection.kind`: `gate` (`not_in_trust_chain`: keep the write until the identity is vouched for), `stale_timestamp`, `missing_parent` (only `user_storage`'s parent foreign key), `exists` (with `conflicted`), `unique_conflict`, `pub_key_taken`, `validation`, `proof_rejected` (the challenge), `bad_request`, `rejected` (the server's text: `Invalid operation` for a proof by another identity than the row needs or an identity without a card, `dialog_key required before posting to dialog`, a self-reaction, pending moderation) |
| No answer, timeout, abort, 5xx, not the API's answer | `TransportError` with `kind` `network`, `timeout`, `aborted`, `http` (with `retryAfter`; a cross-origin page cannot read the header, so it is `null` there), `malformed` |
| A write of `storage`, `origins`, `dialogs.ensureDialogKey` sent without an answer | `{ kind: 'unknown' }`: the write may have been committed; read before writing again |
| Row read | `verifyRow` → `ok` or `invalid` with `missing_signature`, `missing_sign_hash`, `sign_hash_mismatch`, `missing_fields`, `bad_signature` |
| Keys | `IdentityKeysError` (`reason` names the key), `IdentityClosedError` |
| Vault | `PrfUnsupportedError`, `PrfMissingError`, `PasskeyMismatchError`, `VaultLockedError`, `VaultMissingError` |

Nothing is retried behind the caller except the storage, vouch and origin
reconciliation on a stale base, which is bounded.

### Retries and unknown outcomes

- **HTTP 200 is a commit**, not visibility in a live subscription.
- **`/ingest` is one transaction.** A refusal does not say which mutation it
  was, and nothing of the batch was written — including when the answer is
  `exists`. `/ingest_each` answers per row; the rows before a refused one stay
  written.
- **No answer** (timeout, network failure, 5xx, a malformed answer) leaves the
  outcome unknown. Resend the same signed row, not a re-signed one:
  - on `user_cards`, `dialog_keys`, `vouch_tokens`, `origins`,
    `origin_settings`, reactions and receipts an exact repeat of an insert
    already committed is `exists` with `conflicted: false` — done;
    `conflicted: true` means another row with that key is stored: read it;
  - on `dialog_messages` and `user_storage` an exact repeat is
    `stale_timestamp` (the stored row's timestamp is not older than the
    repeat's): read the row and compare its `sign_hash` with yours before
    building anything new;
  - an update repeated after it was committed is `stale_timestamp` too.
- The library keeps nothing across a reload. A client that must not lose a
  write keeps the signed row (or, for a venue, `originHash`) in its own
  storage until the server's answer or a read settles it.

## Lifecycle

Create a transport → open identities (vault or keys) → work, subscribe →
`sub.dispose()`, `sessions.dispose()` → `identity.close()` /
`createIdentitySession().closeAll()`, `vault.lock()`. Locking a vault does not
close identities opened from it.

## Vault in the browser

- A passkey with the WebAuthn PRF extension is required; without it
  `createPrfVault` throws `PrfUnsupportedError`. There is no fallback.
- `credentials` and `rpId` are parameters of the vault; it reads neither
  `navigator` nor `location`. Two functions do read `location` when it
  exists: `forgetUnusablePasskey` (`vaultLock`) uses `location.hostname` as
  the default `rpId`, and a transport created with a relative `baseUrl`
  resolves `url()` on `location.origin`. The page must be a secure context.
- Entries are stored in IndexedDB through `@lo-fi/local-vault`, which expects
  libsodium as the global `sodium`:

  ```ts
  import sodium from 'libsodium-wrappers';
  await sodium.ready;
  globalThis.sodium = sodium;
  ```

  A Vite app can instead use the plugin of
  `@lo-fi/webauthn-local-client/bundlers/vite`, as `@lo-fi/local-vault`
  describes in its `BUNDLERS.md`.
- `libsodium-wrappers` 0.7.16's ESM file imports `./libsodium.mjs`, which
  lives in the sibling package `libsodium`; some bundlers (esbuild) need that
  import resolved to `libsodium/dist/modules-esm/libsodium.mjs`.
- `@lo-fi/*` are loaded on the first vault call, not on import, so the other
  modules work in Node without libsodium.

## Versioning

Semver. A change of the wire protocol or of a derivation is a major version
and is announced to partners. Prereleases are published under the `next`
dist-tag; see `CHANGELOG.md`.

## Documentation

Protocol design, API usage and release instructions are indexed in the [SDK documentation](https://github.com/Buckitup-chat/pq-library/blob/main/docs/README.md).

## Develop

The package has its own test suite in `tests`: protocol,
identity, vault, rows, transport, dialogs, storage, vouches, origins and the
versioned conformance vectors (`tests/vectors/pq-conformance.json`). It imports only the package sources (through a local
alias to `src`), its own helpers and its declared dependencies — no app code,
Vue or application configuration. Applications maintain their own integration
tests against the installed package.

```sh
npm test                            # the SDK suite (vitest, from this directory)
npm run typecheck                   # sources and tests, including type assertions
WRITE_VECTORS=1 npm test -- tests/conformance.test.ts   # regenerate vectors after a deliberate protocol change
npm run build                       # dist, then every module loads in Node
npm pack --pack-destination /tmp     # the tarball
npm run check:consumer -- /tmp/buckitup-pq-client-<version>.tgz [--browser]
```

`check:consumer` installs the tarball in a temporary project outside this
repository, type-checks it (NodeNext, Bundler, and a Node project without the
DOM lib), runs a functional smoke in Node and, with `--browser`, runs the
dialogs, storage and PRF vault in headless Chromium with a virtual WebAuthn
authenticator. Releasing: `docs/releasing.md` in this repository.

## Licence

GPL-3.0-only. See [LICENSE](LICENSE).
