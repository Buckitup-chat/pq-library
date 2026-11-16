import { describe, it, expect, vi } from 'vitest';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { bytesToHex } from '@noble/hashes/utils';
import {
	generateIdentityKeys,
	identityKeysFromSecrets,
	openIdentity,
	signedUserCard,
	unsignedUserCard,
	cardKeyFields,
	userCardInsert,
	publishUserCard,
	createIdentitySession,
	userHashOf,
	verifyUserCard,
	IdentityClosedError,
	IdentityKeysError,
	type IdentityKeys,
} from '@buckitup/pq-client/identity';
import { verifyRow, toBase64 } from '@buckitup/pq-client/rows';
import { deriveIdentity, signedUserCard as derivedCard } from '@buckitup/pq-client/derivedIdentity';
import type { IngestEachOutcome, Mutation, Signer } from '@buckitup/pq-client/transport';

const vo = generateIdentityKeys();
const venue = generateIdentityKeys();

const secretsOf = (keys: IdentityKeys) => ({
	signSkey: toBase64(keys.signSkey),
	cryptSkey: toBase64(keys.cryptSkey),
	contactSkey: bytesToHex(keys.contactSkey),
});

describe('generateIdentityKeys', () => {
	it('makes ML-DSA-87, ML-KEM-1024 and compressed secp256k1 keys of fresh randomness', () => {
		expect(vo.signPkey).toHaveLength(2592);
		expect(vo.cryptPkey).toHaveLength(1568);
		expect(vo.contactSkey).toHaveLength(32);
		expect(vo.contactPkey).toHaveLength(33);
		expect(userHashOf(vo.signPkey)).not.toBe(userHashOf(venue.signPkey));
	});
});

describe('user_cards row', () => {
	it('verifies as the server checks it: hash from sign_pkey, self-signature, both certs', () => {
		const card = signedUserCard(vo, { name: 'Venue owner', ownerTimestamp: 1_700_000_000 });
		expect(card.user_hash).toBe(userHashOf(vo.signPkey));
		expect(card).not.toHaveProperty('sign_hash');
		expect(verifyUserCard(card)).toMatchObject({ status: 'verified', card: { userHash: card.user_hash, name: 'Venue owner' } });
		expect(verifyRow('user_cards', card, vo.signPkey)).toEqual({ status: 'ok' });
	});

	it('is refused when its hash, certificate or fields are tampered', () => {
		const card = signedUserCard(vo, { name: 'Venue owner', ownerTimestamp: 1_700_000_000 });
		expect(verifyUserCard({ ...card, user_hash: userHashOf(venue.signPkey) })).toMatchObject({ reason: 'hash_mismatch' });
		expect(verifyUserCard({ ...card, name: 'Mallory' })).toMatchObject({ reason: 'bad_signature' });
		const foreignCert = cardKeyFields(venue).crypt_cert;
		expect(verifyUserCard({ ...card, crypt_cert: foreignCert })).toMatchObject({ status: 'invalid' });
	});

	it('refuses an empty name or a non-positive timestamp before signing', () => {
		expect(() => unsignedUserCard(vo, { name: '', ownerTimestamp: 1 })).toThrow(/name must not be empty/);
		expect(() => unsignedUserCard(vo, { name: 'x', ownerTimestamp: 0 })).toThrow(/positive integer/);
	});

	it('is the same row derived identities sign', () => {
		const derived = deriveIdentity({ signSkey: vo.signSkey, cryptSkey: vo.cryptSkey }, 'buckitup/test-family/v1');
		const card = derivedCard(derived, 5);
		expect(card.name).toBe(derived.cardName);
		expect(verifyUserCard(card).status).toBe('verified');
	});

	it('travels as an insert mutation of user_cards', () => {
		const card = signedUserCard(vo, { name: 'n', ownerTimestamp: 1 });
		expect(userCardInsert(card)).toEqual({ type: 'insert', syncMetadata: { relation: 'user_cards' }, modified: card });
	});
});

describe('identityKeysFromSecrets', () => {
	it('restores every public key from the secret keys alone, in any stored encoding', () => {
		for (const secrets of [secretsOf(vo), { signSkey: vo.signSkey, cryptSkey: vo.cryptSkey, contactSkey: vo.contactSkey }]) {
			const keys = identityKeysFromSecrets(secrets, { userHash: userHashOf(vo.signPkey) });
			expect(keys.signPkey).toEqual(vo.signPkey);
			expect(keys.cryptPkey).toEqual(vo.cryptPkey);
			expect(keys.contactPkey).toEqual(vo.contactPkey);
		}
	});

	it('names which key does not belong to the expected identity', () => {
		const mixed = { ...secretsOf(vo), cryptSkey: toBase64(venue.cryptSkey) };
		const reasonOf = (fn: () => unknown) => {
			try {
				fn();
			} catch (e) {
				expect(e).toBeInstanceOf(IdentityKeysError);
				return (e as IdentityKeysError).reason;
			}
			return null;
		};
		expect(reasonOf(() => identityKeysFromSecrets(secretsOf(vo), { userHash: userHashOf(venue.signPkey) }))).toBe('user_hash');
		expect(reasonOf(() => identityKeysFromSecrets(mixed, { cryptPkey: vo.cryptPkey }))).toBe('crypt_pkey');
		expect(reasonOf(() => identityKeysFromSecrets(secretsOf(vo), { contactPkey: venue.contactPkey }))).toBe('contact_pkey');
		expect(reasonOf(() => identityKeysFromSecrets(secretsOf(vo), { signPkey: toBase64(venue.signPkey) }))).toBe('sign_pkey');
		expect(reasonOf(() => identityKeysFromSecrets({ ...secretsOf(vo), signSkey: 'AAAA' }))).toBe('malformed');
	});
});

describe('keypair checks on restore', () => {
	const expectedOf = (keys: IdentityKeys) => ({
		userHash: userHashOf(keys.signPkey),
		signPkey: keys.signPkey,
		cryptPkey: keys.cryptPkey,
		contactPkey: keys.contactPkey,
	});
	const flipped = (bytes: Uint8Array, index: number) => {
		const copy = new Uint8Array(bytes);
		copy[index] ^= 1;
		return copy;
	};
	const reasonOf = (fn: () => unknown): string | null => {
		try {
			fn();
		} catch (e) {
			expect(e).toBeInstanceOf(IdentityKeysError);
			return (e as IdentityKeysError).reason;
		}
		return null;
	};

	it('refuses an ML-KEM secret key whose public key still matches but which decapsulates wrongly', () => {
		const cryptSkey = flipped(vo.cryptSkey, 0);
		expect(ml_kem1024.getPublicKey(cryptSkey)).toEqual(vo.cryptPkey);
		expect(reasonOf(() => identityKeysFromSecrets({ ...secretsOf(vo), cryptSkey }, expectedOf(vo)))).toBe('crypt_keypair');
		expect(reasonOf(() => identityKeysFromSecrets({ ...secretsOf(vo), cryptSkey: flipped(vo.cryptSkey, 3110) }))).toBe('crypt_keypair');
	});

	it('refuses an ML-DSA secret key whose public key still matches but whose signatures do not verify', () => {
		const signSkey = flipped(vo.signSkey, 64);
		expect(ml_dsa87.getPublicKey(signSkey)).toEqual(vo.signPkey);
		expect(reasonOf(() => identityKeysFromSecrets({ ...secretsOf(vo), signSkey }, expectedOf(vo)))).toBe('sign_keypair');
	});

	it('wipes its temporary secret copies when it refuses, and leaves the caller\'s keys alone', () => {
		const signSkey = flipped(vo.signSkey, 64);
		const cryptSkey = new Uint8Array(vo.cryptSkey);
		const fill = vi.spyOn(Uint8Array.prototype, 'fill');
		try {
			expect(() => identityKeysFromSecrets({ signSkey, cryptSkey, contactSkey: vo.contactSkey })).toThrow(IdentityKeysError);
			const wiped = fill.mock.contexts.filter((buffer, i) => fill.mock.calls[i][0] === 0) as Uint8Array[];
			expect(wiped.map((b) => b.length)).toEqual(expect.arrayContaining([4896, 3168, 32]));
			expect(wiped.every((b) => b !== signSkey && b !== cryptSkey && b !== vo.contactSkey)).toBe(true);
		} finally {
			fill.mockRestore();
		}
		expect(cryptSkey).toEqual(vo.cryptSkey);
		expect(signSkey.some((b) => b !== 0)).toBe(true);
	});

	it('is not bypassed by openIdentity: a broken pair never becomes a handle', () => {
		expect(reasonOf(() => openIdentity({ ...vo, signSkey: flipped(vo.signSkey, 64) }))).toBe('sign_keypair');
		expect(reasonOf(() => openIdentity({ ...vo, cryptSkey: flipped(vo.cryptSkey, 0) }))).toBe('crypt_keypair');
		expect(reasonOf(() => openIdentity({ ...vo, contactPkey: venue.contactPkey }))).toBe('contact_keypair');
		expect(reasonOf(() => openIdentity({ ...vo, cryptPkey: venue.cryptPkey }))).toBe('crypt_keypair');
		expect(reasonOf(() => openIdentity({ ...vo, signPkey: venue.signPkey }))).toBe('sign_keypair');
		expect(createIdentitySession().list()).toEqual([]);
		expect(() => createIdentitySession().open({ ...vo, signSkey: flipped(vo.signSkey, 64) })).toThrow(IdentityKeysError);
	});
});

describe('IdentityHandle', () => {
	it('signs, signs rows and decapsulates under its own keys without exposing them', () => {
		const handle = openIdentity(vo);
		const message = new TextEncoder().encode('challenge');
		expect(ml_dsa87.verify(handle.sign(message), message, vo.signPkey)).toBe(true);
		const card = handle.userCard({ name: 'VO', ownerTimestamp: 2 });
		expect(verifyUserCard(card).status).toBe('verified');
		const { cipherText, sharedSecret } = ml_kem1024.encapsulate(vo.cryptPkey);
		expect(handle.decapsulate(cipherText)).toEqual(sharedSecret);
		expect(Object.keys(handle)).not.toContain('signSkey');
	});

	it('refuses every secret-key operation once closed, and wipes only its own copy', () => {
		const handle = openIdentity(vo);
		const exported = handle.exportKeys();
		handle.close();
		expect(handle.closed).toBe(true);
		expect(() => handle.sign(new Uint8Array([1]))).toThrow(IdentityClosedError);
		expect(() => handle.signRow('user_cards', {})).toThrow(IdentityClosedError);
		expect(() => handle.decapsulate(new Uint8Array(1568))).toThrow(IdentityClosedError);
		expect(() => handle.exportKeys()).toThrow(IdentityClosedError);
		expect(vo.signSkey.some((b) => b !== 0)).toBe(true);
		expect(exported.signSkey).toEqual(vo.signSkey);
		expect(handle.userHash).toBe(userHashOf(vo.signPkey));
	});
});

describe('publishUserCard', () => {
	const recordingTransport = () => {
		const calls: Array<{ mutations: Mutation[]; sign: Signer }> = [];
		return {
			calls,
			ingestEach: async (mutations: Mutation[], sign: Signer): Promise<IngestEachOutcome> => {
				calls.push({ mutations, sign });
				return { kind: 'results', status: 200, results: [{ index: 0, status: 'ok', txid: 1 }], rows: [{ index: 0, kind: 'written', txid: 1 }] };
			},
		};
	};

	it('writes the card in a request of its own, proved by the identity it introduces', async () => {
		const transport = recordingTransport();
		const handle = openIdentity(venue);
		const card = handle.userCard({ name: 'Venue', ownerTimestamp: 3 });
		await expect(publishUserCard(transport, handle, card)).resolves.toMatchObject({ status: 200 });
		expect(transport.calls).toHaveLength(1);
		expect(transport.calls[0].mutations).toEqual([userCardInsert(card)]);
		const challenge = new TextEncoder().encode('one-time challenge');
		expect(ml_dsa87.verify(await transport.calls[0].sign(challenge), challenge, venue.signPkey)).toBe(true);
	});

	it('refuses to prove one identity\'s card with another', async () => {
		const transport = recordingTransport();
		const card = signedUserCard(venue, { name: 'Venue', ownerTimestamp: 3 });
		await expect(publishUserCard(transport, openIdentity(vo), card)).rejects.toThrow(/another identity/);
		expect(transport.calls).toHaveLength(0);
	});
});

describe('createIdentitySession', () => {
	it('holds VO and V at once, each signing for itself, and closes them independently', () => {
		const session = createIdentitySession();
		const owner = session.open(vo);
		const v = session.open(venue);
		const message = new TextEncoder().encode('row');
		expect(ml_dsa87.verify(session.get(owner.userHash)!.sign(message), message, vo.signPkey)).toBe(true);
		expect(ml_dsa87.verify(session.get(v.userHash)!.sign(message), message, venue.signPkey)).toBe(true);
		session.close(v.userHash);
		expect(v.closed).toBe(true);
		expect(session.get(v.userHash)).toBeNull();
		expect(session.list()).toEqual([owner]);
		expect(() => owner.sign(message)).not.toThrow();
		session.closeAll();
		expect(owner.closed).toBe(true);
		expect(session.list()).toEqual([]);
	});

	it('closes the handle it replaces for the same identity, and refuses a closed one', () => {
		const session = createIdentitySession();
		const first = session.open(vo);
		const second = session.open(vo);
		expect(first.closed).toBe(true);
		expect(session.get(second.userHash)).toBe(second);
		const closed = openIdentity(venue);
		closed.close();
		expect(() => session.add(closed)).toThrow(IdentityClosedError);
	});
});
