# Optical handshake v2 (PQ2)

The pure protocol implementation is [`src/handshake.ts`](../src/handshake.ts).
The sections below define wire messages, identity binding and session proofs.
The caller owns camera rendering, transport orchestration, contact persistence
and acceptance on actual devices. Device-storage contact-access rules are
provided separately by [`contactAccess`](contact-access.md); the optical
protocol does not itself grant access. Section numbers remain stable for references.

## Implementation task status

**SDK protocol implementation: completed for `@buckitup/pq-client@1.0.0`.**
Protocol code and cryptographic unit coverage are present in this repository.
This status does not declare consumer camera, WebRTC, TURN or phone/deployment
acceptance complete.

### Agreement and ownership

The original task placed the protocol in frontend
`packages/pq-client/src/handshake.ts`, with protocol tests in frontend
`tests/handshake.test.ts`, starting from the two-phone sandbox. The team chose
a standalone `Buckitup-chat/pq-library` project published to npm so other
clients can use the same protocol and the SDK can have its own release cycle.

The task and its security requirements remain here with the implementation.
The repository split changes ownership and installation, not PQ2 wire
messages, identity binding or acceptance requirements. The sandbox remains a
consumer experiment; animated QR is not part of the released PQ2 module.

| SDK work | Status | Implementation and coverage |
| --- | --- | --- |
| A–D encoding/parsing, lengths and base64url; reject PQ1 | Done | `src/handshake.ts`, `tests/handshake.test.ts` |
| Transcript ordering, PQ message, session tag and six-digit SAS | Done | `src/handshake.ts`, fixed vectors in `tests/handshake.test.ts` |
| Optical signature bound to key, nonce and counterpart | Done | `src/handshake.ts`, negative cases in `tests/handshake.test.ts` |
| Confirmation bound to a verified, non-deleted identity card and certified optical key | Done | `src/handshake.ts`, `src/verifyCard.ts`, `tests/handshake.test.ts`, `tests/cardVouchesForContactKey.test.ts` |
| Challenge proof over the challenge's UTF-8 bytes | Done | `src/challengeProof.ts`, `tests/handshake.test.ts` |

The SDK protocol checks are run with:

```sh
npm test -- tests/handshake.test.ts tests/cardVouchesForContactKey.test.ts
```

### Consumer work and remaining acceptance

Camera rendering, session/channel orchestration, candidate selection, relay
credential lifecycle and saving the contact remain consumer responsibilities.
The BuckitUp frontend's `confirmContact` passes verified identity evidence and
the stored prior contact state to SDK `contactAccess` for the initial-grant
decision. The same service handles explicit grant/revoke and derives the
switch state. The frontend provides durable intent/outbox adapters and keeps
the switch, confirmation dialog and context guard. Other consumers choose
whether to use this contact-access policy; protocol confirmation supplies
identity evidence and does not itself grant server access.

The [frontend integration task](https://github.com/Buckitup-chat/chat-frontend/blob/main/docs/task-handshake-pq2.md)
owns UI behavior and the retained device acceptance criteria. Its
[validation checklist](https://github.com/Buckitup-chat/chat-frontend/blob/main/docs/task-handshake-pq2-rollout.md)
owns browser/WebRTC and deployment checks. These links navigate consumer
tasks; they do not redefine this SDK's versioned protocol. Those acceptance
checks require the intended deployment and are not established by local SDK
tests.

## 2. Keys

An identity exposes the following certified keys (see [`src/identity.ts`](../src/identity.ts)):

| Key | Algorithm | On the card | Role here |
|---|---|---|---|
| `sign_skey` / `sign_pkey` | ML-DSA-87 (pk 2,592 B, sig 4,627 B) | `sign_pkey`, `sign_b64` (self-signature) | The identity; `user_hash = 'u_' + hex(SHA3-512(sign_pkey))` |
| `contact_skey` / `contact_pkey` | secp256k1, compressed (33 B) | `contact_pkey`, `contact_cert = ML-DSA-87.sign(contact_pkey, sign_skey)` | What the QR carries and what signs the optical transcript |
| `crypt_skey` / `crypt_pkey` | ML-KEM-1024 | `crypt_pkey`, `crypt_cert` | Not used by the handshake |

The QR carries `contact_pkey` because neither the ML-DSA key nor its
signature fits one code (2,953 bytes at most; sizes above). The certificate is what ties the small key to the identity:
**a contact is confirmed only when the key proved optically is the one the
identity's verified card certifies** (`cardVouchesForContactKey`,
`@buckitup/pq-client/verifyCard`) — without that, anyone can show a friend's
`user_hash` with their own key.

## 3. Messages

Text in QR byte mode. Fields are separated by `:`; binary fields are
base64url without padding (`toBase64Url`, `@buckitup/pq-client/signature`), which
contains no `:`. `user_hash` travels as is (`u_` + 128 hex). A reader ignores
any code that does not start with `PQ2:`, and any message whose fixed-length
fields do not decode to their length.

```
A  PQ2:A:<user_hash>:<contact_pkey>:<nonce>
B  PQ2:B:<user_hash>:<contact_pkey>:<nonce>:<sig>
C  PQ2:C:<sig>:<qwbp>
D  PQ2:D:<tag>:<qwbp>
```

| Field | Bytes | Meaning |
|---|---|---|
| `user_hash` | 130 chars | The sender's identity |
| `contact_pkey` | 33 | The sender's handshake key, compressed secp256k1 |
| `nonce` | 16 | Fresh random per session (`randomBytes(16)`) |
| `sig` | 64 | ECDSA over the transcript, §4, compact `r‖s` |
| `tag` | 6 | The first 6 bytes of `SHA-256(T)`. D carries no signature, so the tag is what names its session: a D whose tag is not the reader's is ignored, or a neighbouring pair's D would be fed to the connection |
| `qwbp` | 55–135 chars | The sender's QWBP bootstrap payload (`QWBPConnection.getQRPayload()`), which carries its DTLS certificate fingerprint and up to six addresses, at most two of them IPv6 (§5a): 34 bytes plus 7 per IPv4 and 19 per IPv6 address |

Sizes: A ≈ 205 bytes, B ≈ 292, C up to ≈ 230, D up to ≈ 150 — QR versions 7–11 at
error-correction level L, as today.

## 4. Transcript and signatures

Both sides compute the same transcript. The two parties are ordered by their
`user_hash` strings (byte-wise, they are hex): `lo` and `hi`. The two are
never equal: a code carrying the reader's own `user_hash` (its own screen in
a reflection, or a second device of the same account) is ignored at every
step.

```
T = "buckitup/handshake/v2\n"
    || hash_lo (130 B, UTF-8) || pk_lo (33 B) || nonce_lo (16 B)
    || hash_hi (130 B, UTF-8) || pk_hi (33 B) || nonce_hi (16 B)
```

Every field is fixed-length, so the encoding is unambiguous; a parser still
checks each length before hashing (a field that is short lets bytes move
between fields).

- **Optical signature** (in B and C): `sig = ECDSA_secp256k1(SHA-256(T))` under
  `contact_skey` — the caller supplies the contact-key signing operation.
  Verified under the counterpart's `contact_pkey` from its A or B.
- **Post-quantum signature** (over the channel, §5):
  `sigPQ = ML-DSA-87.sign(M, sign_skey)`, with
  `M = "buckitup/handshake/v2/pq\n" || T || fp_lo (32 B) || fp_hi (32 B)`,
  where `fp` is each side's DTLS certificate fingerprint — the 32-byte
  fingerprint in its QWBP payload (`decode(payload).fingerprint`). Verified under `sign_pkey` of
  the counterpart's verified card.
- **Short authentication string**:
  `sas = u32be(hkdfDerive(T || fp_lo || fp_hi, "buckitup/handshake/v2", "sas", 4)) mod 10^6`,
  six digits, zero-padded, with `hkdfDerive` from `@buckitup/pq-client/hkdf` (the
  derivation device-link uses). It covers the fingerprints on purpose: `T`
  holds only values shown in plain codes, and the `qwbp` fields are not under
  the optical signatures, so a relay that swaps the bootstrap payloads would
  leave a `T`-only code equal on both screens. With the fingerprints in it,
  the two screens differ whenever the channel does not join the two phones.

## 5. Sequence

Each device runs the same state machine. "Show" means render as the QR under
the camera; "read" means the camera decoded a code. A device's own data is
`(hash_me, pk_me, nonce_me)`; the counterpart's, once seen, is bound for the
rest of the session: a later code naming a different `user_hash` or
`contact_pkey` is ignored.

1. **Start.** Once the camera runs — a permission prompt takes nothing out
   of the session — generate `nonce_me`; create the session's QWBP connection
   (§5a); show **A**; start the 90 s session timer. If this side cannot sign
   its code (three reads in a row), the session ends with that cause and no
   result.
2. **Read A** (state 1 only): bind the counterpart; compute `T`, sign it; show
   **B**.
3. **Read B** (states 1–2): bind the counterpart if not bound (both scanned
   each other's A at once, and both are showing B — the symmetric race);
   compute `T`; verify `sig` under the counterpart's `contact_pkey`. If it
   fails, log and stay — a code that does not verify binds nothing. Otherwise
   sign `T`, take the payload of the session's QWBP connection (§5a), show
   **C**; mark *optically verified*.
4. **Read C** in state 2 (this device showed B): verify `sig` as in 3;
   mark *optically verified*; feed the counterpart's payload to the session's
   QWBP connection, take own payload, show **D**.
   **Read C** in state 3 (this device showed C too — both read B at once, the
   symmetric race): verify `sig` as in 3 and feed the counterpart's payload to
   the connection this device already has. Both hold both payloads; QWBP picks
   offerer and answerer by comparing fingerprints, so neither needs a D.
5. **Read D** (state 3 only — this device showed C): if its `tag` is not this
   session's, ignore it; otherwise feed the payload to the connection.
6. **Channel.** QWBP derives the ICE credentials from the scanned
   fingerprint, and WebRTC's DTLS handshake accepts only a peer whose
   certificate has that fingerprint — that is what makes the channel the one
   negotiated on screen. When the data channel opens, each side sends **one**
   message and expects one. A message that arrives before this side listens
   — the peer may send the moment the channel opens — is kept for it, not
   dropped:

   ```json
   { "type": "PQ2_CONFIRM", "card": <own signed user card row>, "sig": "<base64 sigPQ>" }
   ```

   The card is the freshest self-signed card row (with `sign_b64`), not the
   unsigned local registry entry. The caller supplies a verified, current
   signed card for the identity used to sign the session. A side with
   no card (never published, offline) or whose signature over `M` fails sends
   a refusal in its place, so that the other phone names the real cause:

   ```json
   { "type": "PQ2_REFUSE", "cause": "no-card" | "no-signature" }
   ```

   It still checks what the peer sends. With no channel at all, it names its
   own cause rather than the missing channel.

   On receipt: the card vouches for the bound counterpart and key —
   `contactKeyVouch`: the card is that `user_hash`'s, verifies, is not a
   deleted account's, and certifies the key — and
   `ML-DSA-87.verify(sig, M, card.sign_pkey)` holds. Both, and the
   counterpart is **confirmed**. Any failure is logged, the
   handshake ends *optically verified* only with its cause (a refused card, a
   deleted account, the peer's refusal), and the card is dropped.
   The camera stops decoding once both payloads are known; nothing is left to
   read while the channel opens and the ML-DSA work runs.
7. **Done.** Stop the camera; keep the last code on screen (the counterpart
   may still be reading it — `docs/handshake_fix_report.md`); show the SAS;
   emit `completed`:

   ```ts
   {
     user_hash: string;
     contact_pkey: string;     // padded base64, as cards carry it
     confirmed: boolean;       // step 6 passed
     card: UserCardRow | null; // the verified card, when confirmed
     sas: string;              // six digits
     name: string;             // card.name, else a known card's, else 'Unknown user'
   }
   ```

**Channel failure.** If the channel has not opened 15 s after both payloads
are known, the handshake ends *optically verified*. There is no retry (§5a).
The UI says so: "Key verified in person; not yet confirmed — check that both
phones are online, or scan again on a shared Wi-Fi."

**Session end.** After 90 s without completion, or when the person stops the
scanner, the session is discarded; a new start mints a new nonce. Codes from
an ended session verify against nothing.

## 5a. Addresses and the relay

**Credentials.** The client asks its backend for relay credentials when the
add-contact view opens, one screen before the scanner (`pq_turn_relay`
§ Endpoint):
- `GET /electric/v1/challenge` (`api.getChallenge()`);
- then `POST /electric/v1/turn_credentials {user_hash, challenge_id,
  signature}`.

The signature is ML-DSA-87 over the challenge string's UTF-8 bytes, unpadded
base64 — the proof ingest and read sessions already send. One helper signs it
for all of them; a test pins the bytes, since a proof over anything else is
refused and the handshake then runs without a relay, silently.

The client keeps the credentials in memory and renews them in the background
once less than 150 s remain (half the lifetime, for a credential that lives
less than 300 s): a session (90 s, then 15 s for the channel and 10 s for the
confirmation) must not outlive its credential, or the relay refuses it
mid-session. At session start it takes what it holds when that lasts the
session, else waits at most 1 s for the renewal, then takes the freshest
credential still valid. A failure, an offline phone, `503 turn_unavailable`
or a timeout all mean no relay, remembered for a minute or a 429's
`retry_after`: the handshake goes on with the phone's own addresses, which is
all a shared network needs.

**One connection per session, created at start.** A relay allocation takes up
to a second or two, so the session creates its QWBP connection in step 1, with
the relay as its only ICE server, or with none — passed as `iceServers: []`,
explicitly: QWBP falls back to Google's STUN servers when the option is
missing. Its `timeout` is at least 3 minutes, longer than any session; QWBP's
default of 30 s closes a connection while the codes are still being read. Its
payload is shown first in
C or D, never before the optical check. There is no retry with other servers:
they would mean new codes, so a new session.

**What goes into the code.** UDP addresses only, no mDNS names (`….local`:
19 bytes each, and resolvable only on the same link), at most six:
- the relay's first, at most two;
- then one STUN-found address — the relay answers STUN too;
- then the phone's own (host) addresses;
- at most two IPv6 addresses in all, so C and D stay below B's density.

A TCP candidate only repeats an address the channel reaches over UDP anyway.
Relay addresses go in typed as srflx: QWBP's format has no relay type, and the
other phone only needs where to send.

**What QWBP needs.** QWBP 0.1.0 picks the addresses itself — host ones, then
the first srflx — and drops relay candidates while parsing. Teaching it to
parse relay as srflx is not enough: it would still keep one of the STUN
address and the relays, and the STUN answer arrives first. So the patch adds
one public hook and nothing else:
- `selectCandidates(all)` receives every gathered candidate, relay included,
  with its real type, and returns the list to encode;
- QWBP's own `maxCandidates` carries the limit, set explicitly to 6: its
  default is 4;
- the payload is yielded once the hook's list is complete, or after 2 s,
  instead of at gathering-complete: one slow or blocked transport must not
  hold up the code.

Candidate selection belongs to the transport integration and must be tested
by its consumer. Use the transport adapter's public API rather than depending
on private connection internals.

**What the relay changes.** Nothing in §4. The relay carries DTLS between the
phones; the fingerprints in `M` and in the SAS make sure the channel ends at
the phone whose code was scanned. A relay can only drop the channel, which ends
the handshake *optically verified*.


## Verification

The SDK's `tests/handshake.test.ts` checks fixed transcript/PQ-message/SAS
vectors, parsing, optical signatures, confirmation binding and challenge proofs.
`tests/cardVouchesForContactKey.test.ts` checks card/contact binding.
Consumers must also exercise the installed handshake module with their own
engine, transport and UI, including transcript and confirmation checks.
