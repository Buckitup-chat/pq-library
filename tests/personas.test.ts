import { describe, it, expect } from 'vitest';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { hmac } from '@noble/hashes/hmac';
import { sha3_256 } from '@noble/hashes/sha3';
import { bytesToHex, concatBytes } from '@noble/hashes/utils';
import * as secp from '@noble/secp256k1';
import { MAX_PERSONA_INDEX, PERSONA_SALT, accountPersonas, derivePersona, personaPrefix, wipePersona } from '@buckitup/pq-client/personas';
import { accountNotes } from '@buckitup/pq-client/notes';
import { signedUserCard } from '@buckitup/pq-client/identity';
import { userHashOf, verifyUserCard } from '@buckitup/pq-client/verifyCard';
import { makeTestIdentity } from './helpers/signedFixtures';

const utf8 = (s: string) => new TextEncoder().encode(s);

const fixed = makeTestIdentity(1);
const account = { signSkey: fixed.signSkey, cryptSkey: fixed.kemSkey };

const reference = (index: number) => {
	const prk = hmac(sha3_256, utf8(PERSONA_SALT), concatBytes(account.signSkey, account.cryptSkey));
	const expand = (label: string, length: number) => {
		const info = concatBytes(Uint8Array.of(index >>> 24, (index >>> 16) & 0xff, (index >>> 8) & 0xff, index & 0xff), utf8(label));
		let t = new Uint8Array(0);
		const out: Uint8Array[] = [];
		for (let i = 1; out.length * 32 < length; i++) {
			t = hmac(sha3_256, prk, concatBytes(t, info, Uint8Array.of(i)));
			out.push(t);
		}
		return concatBytes(...out).slice(0, length);
	};
	const sign = ml_dsa87.keygen(expand('sign', 32));
	const crypt = ml_kem1024.keygen(expand('crypt', 64));
	const contactSkey = secp.etc.hashToPrivateKey(expand('contact', 48));
	return {
		userHash: userHashOf(sign.publicKey),
		signSkey: sign.secretKey,
		signPkey: sign.publicKey,
		cryptSkey: crypt.secretKey,
		cryptPkey: crypt.publicKey,
		contactSkey,
		contactPkey: secp.getPublicKey(contactSkey, true),
		evmSkey: secp.etc.hashToPrivateKey(expand('evm', 48)),
		metaSeed: expand('meta', 32),
	};
};

const hex = (o: object) =>
	Object.fromEntries(Object.entries(o).map(([k, v]) => [k, v instanceof Uint8Array ? bytesToHex(v) : v]));

describe('personas', () => {
	it('derive every key of an account by HKDF with the persona salt and I2OSP(index, 4) before each label', () => {
		for (const index of [0, 258, MAX_PERSONA_INDEX]) {
			expect(hex(derivePersona(account, index))).toEqual(hex({ ...reference(index), index }));
		}
	});

	it('pin the personas of a fixed account', () => {
		const first = derivePersona(account, 0);
		expect(first.userHash).toBe('u_eff872caec26fa85f7f892585d382b4cdd3921f10bf62e49568c199a94257bf8c5ffeec328bb7ca7980348fe0b927eb3c98c14edf1d4558b705b3f8bc37a4e7d');
		expect(bytesToHex(sha3_256(first.cryptPkey))).toBe('53c96af175737f4e7538028df7467d72735d49bc23d4a55c8c51f488557c0874');
		expect(bytesToHex(first.contactPkey)).toBe('02a72be3377a39c5193ae89264451d996a2752f87634b1b39f4348b33a7c8f54d5');
		expect(bytesToHex(first.evmSkey)).toBe('ed2c8e64d5f364fd52c4cb5d2cedbb3105f3a4026ca62f40f6c3dd72d0ee32fe');
		expect(bytesToHex(first.metaSeed)).toBe('d58d196c377d1e8e3b7d119e488edd0079cd34a92bd74cfd7bc64faa939a4094');

		const other = derivePersona(account, 258);
		expect(other.userHash).toBe('u_52e33e8e6b99176ff8e9cdc1c4e709d6f5be643e2acaf62eca1c28f21318be6f3cec1230526c28814d308ac2e804edeb93c112d5f2b7ed4fe5fce3ec97d01130');
		expect(bytesToHex(other.contactPkey)).toBe('0205c23b84f2b5b382a819b7c139d7c7cd1b1cd8b7680d6f2b87021ce4f399cb49');
		expect(bytesToHex(other.evmSkey)).toBe('00e2eb69f6af67ea1c07f570f74415eaa134771a92e291863d71c882bdc8d769');
		expect(bytesToHex(other.metaSeed)).toBe('20828c2e22f377f6fdbd4355bb126f655b3f5038127e34a4b660f1fbaaa4b79c');

		expect(derivePersona(account, MAX_PERSONA_INDEX).userHash).toBe('u_3192136e0bd985708008a7c983e301c955252fe0da115416ba4d733b2192821f6d488c141299c5dd61409d0db4a45bdc9b9b282971fc8d0556a943bdb3b20a10');
	});

	it('are the same on every device, and distinct from the account, its notes and each other', () => {
		const personas = accountPersonas(account);
		expect(personas.userHash(0)).toBe(derivePersona(account, 0).userHash);
		expect(personas.persona(1).userHash).toBe(personas.userHash(1));
		const hashes = new Set([fixed.userHash, accountNotes(account).identity.userHash, personas.userHash(0), personas.userHash(1)]);
		expect(hashes.size).toBe(4);
	});

	it('publish a card under the name the person chooses, verified like any account\'s', () => {
		const card = signedUserCard(derivePersona(account, 0), { name: 'Work', ownerTimestamp: 1_700_000_000 });
		expect(card.name).toBe('Work');
		expect(verifyUserCard(card).status).toBe('verified');
	});

	it('take only an index that fits in four bytes, and derive nothing for another', () => {
		expect(bytesToHex(personaPrefix(0))).toBe('00000000');
		expect(bytesToHex(personaPrefix(MAX_PERSONA_INDEX))).toBe('ffffffff');
		const personas = accountPersonas(account);
		for (const index of [-1, MAX_PERSONA_INDEX + 1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '1' as unknown as number, 1n as unknown as number]) {
			expect(() => derivePersona(account, index)).toThrow(RangeError);
			expect(() => personas.persona(index)).toThrow(RangeError);
			expect(() => personas.userHash(index)).toThrow(RangeError);
		}
	});

	it('leave the account\'s keys as they were, and wipe their own', () => {
		const signSkey = account.signSkey.slice();
		const cryptSkey = account.cryptSkey.slice();
		const personas = accountPersonas(account);
		const persona = personas.persona(0);
		personas.wipe();
		expect(account.signSkey).toEqual(signSkey);
		expect(account.cryptSkey).toEqual(cryptSkey);
		expect(() => personas.userHash(0)).toThrow(/wiped/);

		wipePersona(persona);
		for (const key of [persona.signSkey, persona.cryptSkey, persona.contactSkey, persona.evmSkey, persona.metaSeed]) {
			expect(key.every((b) => b === 0)).toBe(true);
		}
		expect(derivePersona(account, 0).userHash).toBe(persona.userHash);
	});
});
