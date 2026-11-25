# Service compatibility and integration limits

The SDK has its own [versioned protocol contract](protocol.md). These notes
record limitations observed in the audited BuckitUp-compatible service
implementation. Other services or adapters must be checked independently.

## Concurrent versioned writes

The audited backend verifies the incoming signature and can then replace
`parent_sign_hash` with its current tip. Timestamp validation and update do not
provide the atomic stale-base rejection needed by concurrent writers. A row
accepted with altered signed fields can fail subsequent verification.

The SDK uses parent timestamp + 1 for storage writes and bounded reconciliation.
This protects sequential SDK writers from some stale-base races, but does not
guarantee multi-device merge or protect against other writers. An unverified
row is reported and must not be overwritten as though it were absent.

A backend solution must preserve signed fields and define an atomic version
conflict contract. The backend owner determines the implementation. The fake
server and its limitation test do not constitute live backend acceptance.

## Conformance and deployment

- Backend vectors for origins/settings and vouches were missing from the
  audited fixture. SDK-specific fixtures do not replace independent vectors.
- Verify peer-vouch freshness and production endpoint exposure for the chosen
  service deployment. These properties cannot be established by SDK unit tests.
- Gate effects, retraction and second-device identity scenarios require a
  permitted test service with known mode, device identity and grants.
- Unknown message parents are not guaranteed to produce `missing_parent`;
  error expectations must follow the actual relation's backend validation.

Consumers own their UI, selection of admission policy, scheduling and
notification delivery. SDK `contactAccess` supplies the reusable policy for
QR-confirmed contact access and explicit grant/revoke; consumers connect it
through infrastructure adapters. Its verified-row state and client-side grant
preflight do not replace the service's full trust-chain evaluation. See
[contact access](contact-access.md#server-effect-of-a-revoke) for gate modes,
owner tombstones and the lifetime of existing read sessions.
