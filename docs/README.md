# SDK documentation

The SDK is maintained in [Buckitup-chat/pq-library](https://github.com/Buckitup-chat/pq-library).

| Document | Responsibility |
| --- | --- |
| [Package README](../README.md) | Public API, modules, examples, errors and lifecycle |
| [Row encoding](row-encoding.md) | Binary normalization and schema ownership |
| [Storage slots](storage-slots.md) | Slot addressing, encryption and write limits |
| [Device link](device-link.md) | Transfer protocol and threat model |
| [Optical handshake](handshake.md) | PQ2 wire format, transcript and identity binding |
| [Sealed recovery envelope](vault-envelope.md) | Locator and envelope primitives |
| [Backend dependencies](backend-dependencies.md) | External contract and acceptance limits |
| [Releasing](releasing.md) | npm package validation and publication |
| [Repository split](repository-split.md) | Source ownership and extraction provenance |

## Requirements source

The [original Partner Venue Messaging specification](https://github.com/Buckitup-chat/chat/blob/docs/partner-venue-messaging/docs/pq/reqs/pq_partner_venue_messaging.proposed.md) defines the eight modules, GPL-3.0-only license, public npm distribution, conformance and partner acceptance.
The team subsequently approved a separate SDK repository. Implementation histories
below are evidence, not additional requirements or acceptance substitutes.

## Historical records

These retain implementation decisions and validation evidence, not current API
promises. Source paths and commands describe the recorded frontend baseline.

- [Implementation plan and status](history/pq-client-implementation-plan.md)
- [Extraction audit](history/pq-client-extraction-audit.md)
- [Slot identifier implementation task](history/task-user-storage-slot-ids.md)
- [Original PQ2 implementation task](history/task-handshake-pq2.md)
- [Original combined device-link document](history/device-link.md)

Frontend UI, stores, durable outbox, recovery coordination and app acceptance
are documented in [chat-frontend integration](https://github.com/Buckitup-chat/chat-frontend/blob/main/docs/pq-client-integration.md).
