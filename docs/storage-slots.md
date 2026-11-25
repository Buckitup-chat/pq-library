# User Storage slots

Implementation: [`slotId`](../src/slotId.ts), [`slots`](../src/slots.ts),
[`storage`](../src/storage.ts). API examples and concurrency limitations are
in the [SDK README](../README.md#user-storage).

## Addressing

The root UUID is deterministic for an identity: take 16 bytes from
HKDF-SHA3-256 of `crypt_skey`, salt `buckitup/user-storage-root/v1`, info `slot`,
then set UUID version 8 and the RFC 4122 variant. Other named slots use random
UUIDs recorded in the root JSON `slots` map. Reads resolve existing addresses
and do not create records. The root may also hold caller-specific profile data.

## Encryption and verification

JSON slot values use AES-256-GCM. The storage key is derived from `crypt_skey`
with PBKDF2-SHA-256, salt `avatar-encryption`, 100,000 iterations. Rows are
verified before decryption or selection as a write base. Absent, unavailable,
unverified and undecryptable reads are distinct outcomes. The last three must
not be treated as an empty slot.

## Writes and concurrency

SDK direct writes re-read and reconcile supported conflicts with bounded
attempts. The current backend can rewrite a signed parent and lacks the atomic
contract needed for guaranteed concurrent multi-device merge. Parent + 1
timestamps reduce stale-base writes between sequential SDK writers; they do not
remove the backend limitation. See [backend dependencies](backend-dependencies.md).

The `origins` slot has one entry per venue identity. Removing an entry does
not erase its keys from historical User Storage versions or other devices.

Durable intents, accepted snapshots, domain-specific merge policies and outbox
delivery belong to consumers. The SDK does not provide an offline delivery engine.

For contacts, `contactAccess.classifySlotPrior` and `contactsPriorOf` interpret
the prior supplied by the storage integration. The application reports the
read value and whether this write generated the slot UUID; the SDK classifies
that evidence as readable, genuinely new or unknown before deciding on an
initial grant. A write awaiting recovery does not establish an empty prior.
