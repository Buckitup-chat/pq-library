// PQ2 protocol vectors and cryptographic primitives; no frontend engine.
import { describe, it, expect } from 'vitest';
import { sha256 } from '@noble/hashes/sha256';
import { sha3_256 } from '@noble/hashes/sha3';
import { hkdf } from '@noble/hashes/hkdf';
import { bytesToHex, concatBytes } from '@noble/hashes/utils';
import * as secp from '@noble/secp256k1';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import {
	checkConfirm, confirmMessage, encode, parse, pqMessage, refusalMessage, sasOf, sessionTag, signOptical, transcript, verifyOptical, type Message,
	type Party,
} from '@buckitup/pq-client/handshake';
import { fromBase64 } from '@buckitup/pq-client/signature';
import { proveChallenge } from '@buckitup/pq-client/challengeProof';
import { makeTestIdentity, resignedCard, type TestIdentity } from './helpers/signedFixtures';
import type { UserCardRow } from '@buckitup/pq-client/types';

const utf8 = (s: string) => new TextEncoder().encode(s);
const fill = (n: number, v: number) => new Uint8Array(n).fill(v);
const partyOf = (id: TestIdentity, nonce: Uint8Array): Party => ({
	userHash: id.userHash,
	contactPkey: fromBase64(id.card.contact_pkey as string),
	nonce,
});

// Two fixed identities (ML-DSA-87 and secp256k1 keys from fixed seeds) and fixed nonces.
const alice = makeTestIdentity(7, 'Alice');
const bob = makeTestIdentity(8, 'Bob');
const mallory = makeTestIdentity(9, 'Mallory');
const A = partyOf(alice, fill(16, 0x17));
const B = partyOf(bob, fill(16, 0x18));
const FP_A = fill(32, 0xa1);
const FP_B = fill(32, 0xb2);
const fps = { [alice.userHash]: FP_A, [bob.userHash]: FP_B };

describe('the golden vectors (§8)', () => {
	it('the identities are the pinned ones', () => {
		expect(alice.userHash).toBe('u_b20139a2ee3cdfcb609388774e69b925d59831fb77cd9404714d986745b57075e6c5d3ef7a67cd2f3b4c231b940b5c83da78a497f605d988551d3dd548bb9449');
		expect(bob.userHash).toBe('u_6fe9dbbfb0f1992d4683fab33af9d5d9f3bb4c9e3052f98a664c5d943adca56b7650c958c88cae35b304adc7615d98b9e91ce4ad701f3c2b75791587c9c9c4cb');
		expect(bytesToHex(A.contactPkey)).toBe('02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f');
		expect(bytesToHex(B.contactPkey)).toBe('03f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661b');
	});

	it('T, byte for byte (Bob is lo: his user_hash sorts first)', () => {
		expect(bytesToHex(transcript(A, B))).toBe(PINNED_T);
	});

	it('M, the session tag and the six digits', () => {
		const T = transcript(A, B);
		const M = pqMessage(T, fps);
		expect(M.length).toBe(469);
		expect(bytesToHex(sha256(M))).toBe('e5bf5a8e2e92e076099c404b954a28a1f610564b5db8406adbd80208441921b9');
		expect(bytesToHex(sessionTag(T))).toBe('ca576a2ec251');
		expect(sasOf(T, fps)).toBe('139529');
	});
});

describe('the transcript', () => {
	it('is the definition, whichever side computes it', () => {
		const [lo, hi] = [B, A];
		const expected = concatBytes(
			utf8('buckitup/handshake/v2\n'),
			utf8(lo.userHash), lo.contactPkey, lo.nonce,
			utf8(hi.userHash), hi.contactPkey, hi.nonce,
		);
		expect(transcript(A, B)).toEqual(expected);
		expect(transcript(B, A)).toEqual(expected);
	});

	it('refuses a party handshaking with itself, and a field of the wrong length', () => {
		expect(() => transcript(A, { ...A, nonce: fill(16, 9) })).toThrow(/itself/);
		expect(() => transcript(A, { ...B, nonce: fill(15, 9) })).toThrow(/nonce/);
		expect(() => transcript(A, { ...B, contactPkey: fill(32, 2) })).toThrow(/contact key/);
		expect(() => transcript(A, { ...B, userHash: 'u_abc' })).toThrow(/user_hash/);
	});
});

describe('M and the six digits', () => {
	const T = transcript(A, B);

	it('M is the tag, T and both fingerprints in transcript order', () => {
		expect(pqMessage(T, fps)).toEqual(concatBytes(utf8('buckitup/handshake/v2/pq\n'), T, FP_B, FP_A));
	});

	it('the six digits are HKDF-SHA3-256 over T and both fingerprints in transcript order, mod 10^6', () => {
		const out = hkdf(sha3_256, concatBytes(T, FP_B, FP_A), utf8('buckitup/handshake/v2'), utf8('sas'), 4);
		const n = new DataView(out.buffer, out.byteOffset, 4).getUint32(0);
		expect(sasOf(T, fps)).toBe(String(n % 1_000_000).padStart(6, '0'));
	});

	it('change when a channel fingerprint changes: a swapped channel shows different digits', () => {
		expect(sasOf(T, { ...fps, [bob.userHash]: fill(32, 0xb3) })).not.toBe(sasOf(T, fps));
	});

	it('need both fingerprints, of the two parties of T', () => {
		expect(() => sasOf(T, { [alice.userHash]: FP_A })).toThrow(/fingerprints/);
		expect(() => pqMessage(T, { [alice.userHash]: FP_A, [mallory.userHash]: FP_B })).toThrow(/fingerprints/);
		expect(() => pqMessage(T, { [alice.userHash]: FP_A, [bob.userHash]: fill(31, 1) })).toThrow(/fingerprints/);
	});
});

describe('messages (§3)', () => {
	const sig = fill(64, 7);
	const qwbp = fill(70, 9);
	const all: Message[] = [
		{ kind: 'A', ...A },
		{ kind: 'B', ...A, sig },
		{ kind: 'C', sig, qwbp },
		{ kind: 'D', tag: fill(6, 3), qwbp },
	];

	it('round-trip, every kind', () => {
		for (const m of all) expect(parse(encode(m))).toEqual(m);
	});

	it('refuse a PQ1 code, a missing or extra field, a field of the wrong length, and a malformed user_hash', () => {
		const a = encode({ kind: 'A', ...A });
		expect(parse(a.replace('PQ2', 'PQ1'))).toBeNull();
		expect(parse(`PQ1:A:${A.userHash}:${bytesToHex(A.contactPkey)}:${bytesToHex(A.nonce)}`)).toBeNull();
		expect(parse(a.split(':').slice(0, -1).join(':'))).toBeNull();
		expect(parse(`${a}:x`)).toBeNull();
		expect(parse(encode({ kind: 'A', ...A, nonce: fill(15, 1) }))).toBeNull();
		expect(parse(encode({ kind: 'A', ...A, contactPkey: fill(32, 2) }))).toBeNull();
		expect(parse(encode({ kind: 'A', ...A, userHash: 'u_' + 'g'.repeat(128) }))).toBeNull();
		expect(parse(encode({ kind: 'B', ...A, sig: fill(65, 1) }))).toBeNull();
		expect(parse(encode({ kind: 'C', sig: fill(63, 1), qwbp }))).toBeNull();
		expect(parse(encode({ kind: 'C', sig, qwbp: fill(600, 1) }))).toBeNull();
		expect(parse(encode({ kind: 'D', tag: fill(7, 1), qwbp }))).toBeNull();
		expect(parse('PQ2:E:x')).toBeNull();
		expect(parse('https://example.com')).toBeNull();
	});

	it('refuse a field in anything but unpadded base64url', () => {
		const a = encode({ kind: 'A', ...A, nonce: fill(16, 0xfb) });
		const cut = a.lastIndexOf(':') + 1;
		const [head, nonce] = [a.slice(0, cut), a.slice(cut)];
		expect(nonce).toMatch(/-/);
		for (const variant of [nonce.replaceAll('-', '+'), `${nonce}==`, ` ${nonce}`, `${nonce.slice(0, -1)}!`]) {
			expect(parse(head + variant), variant).toBeNull();
		}
	});

	it('stay within the sizes the spec gives: A ≈ 205 bytes, B ≈ 292', () => {
		expect(encode(all[0]).length).toBeLessThanOrEqual(210);
		expect(encode(all[1]).length).toBeLessThanOrEqual(295);
	});
});

describe('the optical signature', () => {
	const T = transcript(A, B);

	it('verifies under the key that signed T', async () => {
		const sig = await signOptical(T, alice.contactSk);
		expect(sig).toHaveLength(64);
		expect(secp.verify(sig, sha256(T), A.contactPkey)).toBe(true); // ECDSA over SHA-256(T), by noble directly
		expect(verifyOptical(sig, T, A.contactPkey)).toBe(true);
	});

	it('does not verify under another key, another nonce, another counterpart, or as a PQ1 signature of the bare nonce', async () => {
		const sig = await signOptical(T, alice.contactSk);
		expect(verifyOptical(sig, T, B.contactPkey)).toBe(false);
		expect(verifyOptical(sig, transcript({ ...A, nonce: fill(16, 0x99) }, B), A.contactPkey)).toBe(false);
		expect(verifyOptical(sig, transcript(A, partyOf(mallory, B.nonce)), A.contactPkey)).toBe(false);
		const bare = await signOptical(B.nonce, alice.contactSk);
		expect(verifyOptical(bare, T, A.contactPkey)).toBe(false);
		expect(verifyOptical(fill(64, 1), T, A.contactPkey)).toBe(false);
	});
});

describe('the confirmation over the channel', () => {
	const T = transcript(A, B);
	const M = pqMessage(T, fps);
	const bound = { userHash: alice.userHash, contactPkey: A.contactPkey };
	const card = alice.card as UserCardRow;
	const signed = (signer: TestIdentity, over = M) => ml_dsa87.sign(over, signer.signSkey);

	it('confirms the identity the codes showed, with its card and its signature over M', () => {
		expect(checkConfirm(confirmMessage(card, signed(alice)), bound, T, fps)).toEqual({ ok: true, card });
	});

	it('refuses a valid card shown under someone else\'s key (Mallory showing Alice\'s user_hash)', () => {
		const impostor = { userHash: alice.userHash, contactPkey: fromBase64(mallory.card.contact_pkey as string) };
		expect(checkConfirm(confirmMessage(card, signed(mallory)), impostor, T, fps))
			.toEqual({ ok: false, reason: 'the card does not certify the contact key the codes showed', refusal: 'refused' });
	});

	it('refuses a deleted account\'s card, though it verifies and certifies the key: a deleted account is never confirmed', () => {
		const deleted = resignedCard(alice, { deleted_flag: true }) as UserCardRow;
		expect(checkConfirm(confirmMessage(deleted, signed(alice)), bound, T, fps))
			.toEqual({ ok: false, reason: 'the card is a deleted account\'s', refusal: 'deleted' });
	});

	it('reads the peer\'s refusal — no card, or no signature — as the peer\'s, not as a bad card', () => {
		expect(checkConfirm(refusalMessage('no-card'), bound, T, fps)).toMatchObject({ ok: false, refusal: 'peer-unable', reason: expect.stringMatching(/no card/) });
		expect(checkConfirm(refusalMessage('no-signature'), bound, T, fps)).toMatchObject({ ok: false, refusal: 'peer-unable', reason: expect.stringMatching(/no signature/) });
	});

	it('refuses a card of another identity, a card that does not verify, a signature by another key, and one over another channel', () => {
		expect(checkConfirm(confirmMessage(bob.card as UserCardRow, signed(bob)), bound, T, fps))
			.toMatchObject({ ok: false, reason: expect.stringMatching(/another identity/) });
		expect(checkConfirm(confirmMessage({ ...card, name: 'Eve' }, signed(alice)), bound, T, fps))
			.toMatchObject({ ok: false, reason: expect.stringMatching(/does not verify \(bad_signature\)/) });
		expect(checkConfirm(confirmMessage(card, signed(bob)), bound, T, fps))
			.toMatchObject({ ok: false, reason: expect.stringMatching(/post-quantum/) });
		const otherChannel = pqMessage(T, { ...fps, [bob.userHash]: fill(32, 0xee) });
		expect(checkConfirm(confirmMessage(card, signed(alice, otherChannel)), bound, T, fps))
			.toMatchObject({ ok: false, reason: expect.stringMatching(/post-quantum/) });
		expect(checkConfirm(confirmMessage(card, signed(alice)), bound, T, { ...fps, [alice.userHash]: fill(32, 0xee) }))
			.toMatchObject({ ok: false, reason: expect.stringMatching(/post-quantum/) });
	});

	it('refuses a card whose contact key is swapped for the shown one, though its other fields are re-signed', () => {
		const swapped = resignedCard(alice, { contact_pkey: mallory.card.contact_pkey }) as UserCardRow;
		const impostor = { userHash: alice.userHash, contactPkey: fromBase64(mallory.card.contact_pkey as string) };
		expect(checkConfirm(confirmMessage(swapped, signed(alice)), impostor, T, fps))
			.toMatchObject({ ok: false, reason: expect.stringMatching(/does not verify \(bad_cert\)/) });
	});

	it('refuses what is not a confirmation message', () => {
		expect(checkConfirm('not json', bound, T, fps)).toMatchObject({ ok: false });
		expect(checkConfirm(JSON.stringify({ type: 'USER_CARD', card }), bound, T, fps)).toMatchObject({ ok: false });
		expect(checkConfirm(JSON.stringify({ type: 'PQ2_CONFIRM', card, sig: '!!' }), bound, T, fps)).toMatchObject({ ok: false });
		expect(checkConfirm('null', bound, T, fps)).toMatchObject({ ok: false });
	});
});

const PINNED_T = '6275636b697475702f68616e647368616b652f76320a755f366665396462626662306631393932643436383366616233336166396435643966336262346339653330353266393861363634633564393433616463613536623736353063393538633838636165333562333034616463373631356439386239653931636534616437303166336332623735373931353837633963396334636203f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661b18181818181818181818181818181818755f623230313339613265653363646663623630393338383737346536396239323564353938333166623737636439343034373134643938363734356235373037356536633564336566376136376364326633623463323331623934306235633833646137386134393766363035643938383535316433646435343862623934343902989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f17171717171717171717171717171717';

describe('the challenge proof', () => {
	it('is ML-DSA-87 over the challenge string\'s UTF-8 bytes, unpadded base64 — as the server checks it', async () => {
		// Not base64: a client that base64-decodes the challenge first would sign other bytes, or throw.
		const challenge = 'Zm9v: a challenge, ✓ not base64';
		const signature = await proveChallenge(challenge, (m) => ml_dsa87.sign(m, alice.signSkey));
		expect(signature).not.toMatch(/=$/);
		expect(signature).toMatch(/^[A-Za-z0-9+/]+$/);
		const sig = fromBase64(signature);
		const pkey = fromBase64(alice.card.sign_pkey as string);
		expect(ml_dsa87.verify(sig, new TextEncoder().encode(challenge), pkey)).toBe(true);
		expect(ml_dsa87.verify(sig, fromBase64('Zm9v'), pkey)).toBe(false);
	});

});
