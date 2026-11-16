# Backend dependencies and acceptance limits

These are external dependencies of SDK guarantees, not frontend implementation
tasks. The SDK does not change the server contract. See the
[partner messaging specification](https://github.com/Buckitup-chat/chat/blob/docs/partner-venue-messaging/docs/pq/reqs/pq_partner_venue_messaging.proposed.md).

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
- The specification's Phase 0 peer-vouch freshness and production exposure
  requirements belong to the backend/deployment owners. Verify them there.
- Gate effects, retraction and the full second-device VO/V scenario require a
  permitted test server with known mode, device identity and grants.
- Unknown message parents are not guaranteed to produce `missing_parent`;
  error expectations must follow the actual relation's backend validation.

Consumer UI, guest codes, partner bot and notification operations belong to the
partner integration. Their absence is not a missing SDK module.
