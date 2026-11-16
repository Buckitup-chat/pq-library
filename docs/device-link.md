# Device-link protocol

The implementation is [`src/deviceLink.ts`](../src/deviceLink.ts), with sealed
payload primitives in [`src/vaultEnvelope.ts`](../src/vaultEnvelope.ts). The
SDK negotiates and authenticates a transfer; the caller owns the relay, UI,
consent prompts and importing the account. The frontend integration is
[documented separately](https://github.com/Buckitup-chat/chat-frontend/blob/main/docs/device-link.md).

## Why not a password, and why not WebRTC

What crosses is the account's long-term ML-DSA and ML-KEM secrets plus the
secp256k1 contact and EVM keys — the whole identity. A transfer keyed by
anything a person can type is brute-forced offline the moment it is recorded,
and a transfer wrapped in ECDH is handed to whoever records it now and breaks
the curve later, which is the one threat the identity was built to resist. So
the session key comes from ML-KEM-1024, and the transport is the backend's
existing Phoenix signaling channel, spoken directly: two devices exchanging a
few kilobytes need a relay, not a peer-to-peer media stack with TURN servers.

## Protocol

1. **New device** — makes an *offer*: a fresh ML-KEM-1024 key pair and a
   128-bit random room id. It shows a QR code carrying the code
   `<room>.<base64url(sha256(kem_pk))>`, joins `room:<id>` on
   `/webrtc-socket`, and announces its public key there (again whenever someone
   joins).
2. **Existing device** — the person opens *Account → Add a device* themselves,
   scans the QR code (or pastes the code), joins the room, receives the public
   key through the relay and **refuses it unless its hash is the one the screen
   showed**. That check is the whole defence against a relay
   substituting a key: the fingerprint travelled screen-to-camera, which the
   relay cannot touch. It encapsulates and sends the ciphertext.
3. Both derive `key = HKDF(ss, "buckitup/device-link/v1", "seal|<room>")` and a
   six-digit `sas = HKDF(ss, …, "sas|<room>")`. The room in the info binds the
   session to the room it was negotiated in.
4. Both screens show the SAS, and the two confirmations do different jobs.
   The fingerprint already keeps the backup confidential: a relay cannot make
   the existing device encapsulate to any key but the one the screen showed.
   What a relay *can* do is replace the ciphertext with its own encapsulation
   to that key — then the new device derives the relay's session, not the
   owner's, and the relay can plant an account of its choosing. The two codes
   differ in that case, so **the new device's confirmation is the check that
   matters**: it imports nothing until the person has compared the codes on it.
   The existing device's tap is consent to send the account, taken before
   anything is sealed. Two taps is the minimum — consent on one device,
   verification on the other — and neither may be automated away.
5. The existing device sends the caller-provided backup payload (`exportBackup()` in the frontend) — the same object a local backup
   file holds, contact key included — sealed as `version || nonce || AES-256-GCM`.
   The new device unseals it and, **from a tap**, passes it to its import callback (`importBackup` in the frontend) (creating the vault asks for a passkey, which WebKit refuses
   outside a user gesture) and answers `done`.

Everything after the encapsulation — `backup`, `done`, `abort` — carries an
HMAC under a key derived from the session. The relay's sender ids are
client-supplied and prove nothing, so a screen acts only on commands that
verify: a stranger holding the code can join the room and claim any id, and
still cannot sign a command.

The relay sees a public key, a ciphertext and an AES-GCM blob. The room id is
unguessable, but nothing depends on that: a stranger in the room can neither pass
the fingerprint check nor open the payload. The sealed form is the vault row's
(`vaultEnvelope.sealWithKey`), so a truncated frame is reported as a broken
payload and not as a wrong key.

**The invite is a code, not a link.** A link that opened the app would have to
do something, and the only useful thing it could do — start the approve screen
on the device that has the account — is exactly what a crafted invite sent to a
victim must never do: the fingerprint authenticates *whoever made the QR code*,
not "your own new device", and the codes would match on the attacker's screen.
The one check that a stranger's invite cannot pass is a person starting the
flow from their own account page with a code they are looking at on their own
new device. So the screen is opened only by that person, and the copy on it says
which codes to trust.

Commands carry no free text: an abort is rendered as a fixed sentence, never as
whatever the other side wrote.


## Lifecycle

Offers and sessions live in memory. The caller must discard them after a
closed tab, failed channel or cancelled exchange. Do not silently resume a
one-shot session. The SDK does not register devices or revoke copies of an
identity: the receiving device holds the same identity keys.
