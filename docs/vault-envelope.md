# Sealed recovery envelope

Implementation: [`src/vaultEnvelope.ts`](../src/vaultEnvelope.ts). The SDK
provides the envelope and key primitives; guardian selection, blockchain
coordination, recovery screens and durable delivery remain consumer concerns.

`newWrapKey` creates a 32-byte secret S. `splitIntoHalves` produces a random node
half and a friends half whose XOR is S; `joinHalves` reconstructs it. Neither
half alone is the encryption key. Splitting guardian shares and managing their
policy are separate from this primitive.

The User Storage locator is a UUIDv8 from HKDF-SHA3-256(S,
`buckitup/vault-locator/v1`, `locator`, 16). The sealing key is derived separately
with salt `buckitup/vault-seal/v1`, info `seal`, length 32. Reconstructing S lets
a caller locate and open the envelope without first restoring the account.

The encoded envelope is base64 of `version(1) || nonce(12) || AES-256-GCM(text)`.
Structural failures are distinguished from failure to open a valid envelope.
Device linking reuses the same sealed representation with its negotiated key.

Tests: [`tests/vaultEnvelope.test.ts`](../tests/vaultEnvelope.test.ts).
