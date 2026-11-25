# Contact access

`@buckitup/pq-client/contactAccess` manages the device-storage access an
issuer gives a contact: the two `vouch_tokens` rows
`device.<deviceId>.storage.read` and `device.<deviceId>.storage.write`,
issuer → contact. The module is part of the `1.1.0` API. It owns the initial
grant decision, explicit grant/revoke planning, request reconciliation and
the access state a client shows. The application supplies storage, delivery,
reads and scheduling through adapters; it renders the controls and obtains
the user's confirmation. The server remains responsible for enforcing access.

## Contact membership and permissions

The contact-page switch changes the signed permissions, not the contact
record. Revoking or restoring access does not delete or hide the contact,
change its name or notes, or clear its QR confirmation. Deleting a contact
also requests revocation; hiding or editing it does not.

The application calls `verifyContactConfirmation` for the peer's certified
identity, saves the contact, and passes the reliable prior state to
`initialAccessDecision`. It requests a grant only when that SDK decision
allows it. Alternatively, a consumer can use `afterConfirmation` to combine
the decision and request. Completing the optical handshake by itself does
not issue permissions. Partner code-based admission is a separate policy
and can use the lower-level `vouch` API.

## Rules

| Situation | Behavior |
| --- | --- |
| QR confirmation whose card does not certify the key shown | No grant (`not-verified`). |
| Confirmation over a contacts slot this write created | Initial grant of both scopes. |
| Confirmation over a readable list without a confirmation of this key | Initial grant. |
| Confirmation over a list that already confirmed this key | No grant (`already-confirmed`): a repeated confirmation never restores access the issuer revoked. |
| Confirmation over a list that cannot be read | No grant (`unknown-prior`). An existing slot with no readable row is not an empty list. |
| Malformed slot, contacts map or target confirmation data | No grant (`unknown-prior`); invalid data is not an empty prior list. |
| Contact added without a confirmation | The service is not called; nothing is granted. |
| Explicit grant by an issuer that neither owns the device nor holds a verified device vouch | Resolved as `skipped:not-vouched`; nothing is signed. |
| Device without an owner | Resolved as `skipped:no-owner`. |

`classifySlotPrior` distinguishes `readable`, `new` and `unknown`.
`contactsPriorOf` accepts a readable plain record with a plain contacts map;
an omitted `contacts` field is a known empty map. Arrays, a non-record slot,
an invalid contacts field or a non-record entry are unknown.
`initialAccessDecision` also validates direct prior-state inputs and the
target entry's `confirmed` and `contact_pkey` fields. A confirmed entry
without a key is unknown. Only a genuinely new slot or a valid readable prior
can authorize an initial grant; a queued write with such a prior can still
do so. Repeating QR confirmation with the same confirmed key does not restore
revoked access. The user restores it through an explicit request.

## Requests

`request(session, subjectHash, granted, deviceId?)` stores a durable intent
and tries it once. Later attempts come from the application calling
`apply(entry, session)` for each stored intent, for example after a reload,
on reconnect and on a backoff.

- Requests are queued per issuer, device and contact. Only the newest
  request of that queue is carried out; older ones resolve as `superseded`.
  A request bound to another device never supersedes one for this device.
- A request stored without a device (an initial grant, or one stored before
  devices were recorded) is bound to the device that answers before anything
  is signed. A request bound to another device than the one answering
  resolves as `skipped:device-changed` and signs nothing.
- Each scope is planned from the issuer's verified rows: a row already in the
  wanted state is not rewritten, a stored row is updated above its
  `owner_timestamp` and above any of the issuer's queued writes of that scope,
  and a scope whose stored row does not verify is left open. A revoke of a
  scope never granted writes nothing.
- Rows go out through the application's outbox. A write the outbox keeps
  after a transient failure is retried by the outbox; the request stays
  pending. An insert that meets a row it did not see is followed by an update
  from that row.
- A request resolves as `applied` only when the shape serves verified rows in
  the wanted state for both scopes, each at or above the `owner_timestamp`
  this request sent. Server acceptance alone leaves it pending. A newer row of
  the issuer in the other state resolves it as `overridden`.
- The session's `stillCurrent()` is checked before signing and before
  sending; a request whose account changed signs nothing and stays for that
  account.

## State

`snapshot(issuerHash, subjectHash)` reads the device identity, the issuer's
rows, the pending and last request, and whether the issuer may grant.
`contactAccessView(snapshot, { submitting })` turns it into what a client
shows:

- `confirmed`: `granted`, `revoked` (both rows are tombstones),
  `not-granted` (no live row), `partial` (one scope, named by
  `partialScope`), `unknown` (a row does not verify), `unavailable` (the
  device or the rows could not be read). Missing or unverified rows are never
  shown as `revoked`.
- `pending`: the request in flight, separate from the confirmed state.
- `switchOn`, `canChange` and `notice`: the switch position, whether it may
  be used now, and the reason it may not or the last request's outcome.

`issuerMayGrant`, and therefore the view's `inEffect` value, are client-side
preflight results from device identity and verified vouch rows. They do not
perform the server's full trust-chain, scope and depth evaluation. A
verified vouch row alone is not proof of effective access on the server.

## Server effect of a revoke

`revoked` describes this issuer's two verified tombstones. It does not mean
that existing data was erased, encryption keys were rotated, or every
possible server access path has immediately stopped.

- A non-owner issuer retracts its own edge. Another valid chain may still
  admit the subject. A direct tombstone from the device owner blocks that
  subject at the same or narrower scope even through alternative chains.
- In `open`, the gate does not restrict reads or writes. In `guarded`, it
  restricts writes but leaves reads open. In `trust`, it restricts both.
- For a gated write, the server evaluates the resulting chain on the next
  request. In `trust`, an already issued read session remains valid until
  its fixed five-minute expiry; revocation does not invalidate it early.
- Confirming the tombstones through a shape establishes the request's
  replicated state. It does not establish when another client loses access.

These are service rules, defined by the backend's access-gating and
vouch-token requirements. SDK and frontend tests using a fake backend do not
prove those deployment effects. Acceptance on a permitted live service must
check gate modes, alternative chains and existing read sessions; see
[service compatibility](backend-dependencies.md).

## Adapters

| Adapter | Supplies |
| --- | --- |
| `readDeviceIdentity` | The answering device and its owner, or null when unknown. |
| `readVouchRows` | Current rows for a subject (and issuer); `forbidden` when the account may not read them; throws when unavailable. |
| `verifyVouchRow` | Whether a replicated row verifies against its issuer's card. `verifyVouchRowWith(signPkeyOf)` builds one from a card lookup. |
| `intents` | Durable intent storage. `resolve` replaces an intent with `{ resolved: true, outcome, purpose }`, keeping its `purpose`. |
| `outbox` | Durable delivery of a `ContactAccessWrite`, the writes still queued, those it gave up on, and discarding one. |
| `lock` | Serializes work per key across the application's tabs. |
| `now` | Wall clock in seconds; defaults to `Date.now()`. |

The adapters carry infrastructure only; every decision above is made by the
service.
