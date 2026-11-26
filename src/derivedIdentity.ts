// Identities derived from secret keys instead of drawn at random
// (chat/docs/pq/reqs/pq_subaccounts.proposed.md, U4).
//
// Every device that holds the parent's secret keys arrives at the same
// identity, so it needs no storage and no syncing: notes to self are the first
// use (pq_notes_to_self.proposed.md § Identities). The derivation of each key
// is HKDF-SHA3-256 over the parent's keys with a family salt; `info` is a
// per-identity prefix (empty, or a note id) followed by the key's label.
import { concatBytes } from '@noble/hashes/utils';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import * as secp from '@noble/secp256k1';
import { hkdfExpand, hkdfExtract } from './hkdf.js';
import { signedUserCard as signedIdentityCard } from './identity.js';
import type { UserCardRow } from './types.js';
import { userHashOf } from './verifyCard.js';

export interface DerivedIdentity {
	userHash: string;
	signSkey: Uint8Array;
	signPkey: Uint8Array;
	cryptSkey: Uint8Array;
	cryptPkey: Uint8Array;
	contactSkey: Uint8Array;
	/** compressed secp256k1, 33 bytes */
	contactPkey: Uint8Array;
	/** The public name its card carries; see cardName below. */
	cardName: string;
}

export interface DerivedAccount extends Omit<DerivedIdentity, 'cardName'> {
	evmSkey: Uint8Array;
	metaSeed: Uint8Array;
}

/** The parent's keys a derivation starts from. */
export interface ParentKeys {
	signSkey: Uint8Array;
	cryptSkey: Uint8Array;
}

/** The identities of one family under one parent, sharing the HKDF extract. */
export interface IdentityFamily {
	/** Every key of the identity with this prefix. */
	identity(prefix?: Uint8Array): DerivedIdentity;
	account(prefix?: Uint8Array): DerivedAccount;
	/** Only its user_hash: the signing key alone, without the KEM and contact keys. */
	userHash(prefix?: Uint8Array): string;
	/** Only its signing secret key, a fresh copy the caller wipes after use. */
	signSkey(prefix?: Uint8Array): Uint8Array;
	/** Wipes the family's extract: nothing more can be derived from it. */
	wipe(): void;
}

const utf8 = (s: string) => new TextEncoder().encode(s);
const NO_PREFIX = new Uint8Array(0);

// Card names must be non-empty and are public. A derived identity takes a
// common given name, picked by a byte derived from the parent's secret keys:
// one picked by anything public (the user_hash) would let anyone recompute it
// and spot derived cards. One list for every family, so names do not tell
// families apart either.
export const DERIVED_CARD_NAMES: readonly string[] = [
	'Alex', 'Anna', 'Ari', 'Ben', 'Cami', 'Chris', 'Dana', 'Dani',
	'Eli', 'Ella', 'Emil', 'Eva', 'Felix', 'Finn', 'Gabi', 'Hana',
	'Ian', 'Ida', 'Ilya', 'Ivan', 'Jade', 'Jan', 'Jona', 'Kai',
	'Kim', 'Lara', 'Lea', 'Leo', 'Lina', 'Luca', 'Maja', 'Max',
	'Maya', 'Mia', 'Mila', 'Nadia', 'Nico', 'Nina', 'Noa', 'Ola',
	'Oleg', 'Omar', 'Pau', 'Petra', 'Rafa', 'Remi', 'Rita', 'Robin',
	'Rosa', 'Sam', 'Sara', 'Sasha', 'Simon', 'Sofia', 'Tara', 'Teo',
	'Tom', 'Uma', 'Vera', 'Viktor', 'Yara', 'Yuri', 'Zoe', 'Zora',
];

/**
 * The identities of family `salt` under `parent`. For each prefix, from
 * HKDF-Expand with info prefix || label:
 * - ML-DSA-87 from a 32-byte seed ("sign"),
 * - ML-KEM-1024 from a 64-byte seed ("crypt"),
 * - secp256k1 from 48 bytes reduced to a scalar in [1, n − 1] ("contact"),
 * - the card name from one byte ("name"), an index into a 64-name list;
 * and for an account, in place of the card name:
 * - secp256k1 from 48 bytes, as the contact key ("evm"),
 * - the meta seed, 32 bytes ("meta").
 */
export const identityFamily = (parent: ParentKeys, salt: string): IdentityFamily => {
	const ikm = concatBytes(parent.signSkey, parent.cryptSkey);
	const prk = hkdfExtract(ikm, salt);
	ikm.fill(0);
	let wiped = false;
	// Seeds are secret: each is wiped once its key is made.
	const withSeed = <T>(prefix: Uint8Array, label: string, length: number, use: (seed: Uint8Array) => T): T => {
		if (wiped) throw new Error('derived identities: the family has been wiped');
		const seed = hkdfExpand(prk, concatBytes(prefix, utf8(label)), length);
		try {
			return use(seed);
		} finally {
			seed.fill(0);
		}
	};
	const signKeys = (prefix: Uint8Array) => withSeed(prefix, 'sign', 32, (seed) => ml_dsa87.keygen(seed));
	const secpKey = (prefix: Uint8Array, label: string) => withSeed(prefix, label, 48, (seed) => secp.etc.hashToPrivateKey(seed));
	const keys = (prefix: Uint8Array): Omit<DerivedIdentity, 'cardName'> => {
		const sign = signKeys(prefix);
		const crypt = withSeed(prefix, 'crypt', 64, (seed) => ml_kem1024.keygen(seed));
		const contactSkey = secpKey(prefix, 'contact');
		return {
			userHash: userHashOf(sign.publicKey),
			signSkey: sign.secretKey,
			signPkey: sign.publicKey,
			cryptSkey: crypt.secretKey,
			cryptPkey: crypt.publicKey,
			contactSkey,
			contactPkey: secp.getPublicKey(contactSkey, true),
		};
	};
	return {
		identity: (prefix = NO_PREFIX) => ({
			...keys(prefix),
			cardName: withSeed(prefix, 'name', 1, (seed) => DERIVED_CARD_NAMES[seed[0] % DERIVED_CARD_NAMES.length]),
		}),
		account: (prefix = NO_PREFIX) => ({
			...keys(prefix),
			evmSkey: secpKey(prefix, 'evm'),
			metaSeed: withSeed(prefix, 'meta', 32, (seed) => seed.slice()),
		}),
		userHash: (prefix = NO_PREFIX) => userHashOf(signKeys(prefix).publicKey),
		signSkey: (prefix = NO_PREFIX) => signKeys(prefix).secretKey,
		wipe() {
			wiped = true;
			prk.fill(0);
		},
	};
};

export const deriveIdentity = (parent: ParentKeys, salt: string, prefix: Uint8Array = NO_PREFIX): DerivedIdentity => {
	const family = identityFamily(parent, salt);
	try {
		return family.identity(prefix);
	} finally {
		family.wipe();
	}
};

export const deriveAccount = (parent: ParentKeys, salt: string, prefix: Uint8Array = NO_PREFIX): DerivedAccount => {
	const family = identityFamily(parent, salt);
	try {
		return family.account(prefix);
	} finally {
		family.wipe();
	}
};

/** Zeroes an identity's secret keys. */
export const wipeIdentity = (id: Pick<DerivedIdentity, 'signSkey' | 'cryptSkey' | 'contactSkey'>): void => {
	for (const key of [id.signSkey, id.cryptSkey, id.contactSkey]) key.fill(0);
};

export const wipeAccount = (account: DerivedAccount): void => {
	wipeIdentity(account);
	account.evmSkey.fill(0);
	account.metaSeed.fill(0);
};

/**
 * The identity's `user_cards` row, certified and signed by its own key, as an
 * account's card is made at registration. Padded base64 binary columns.
 *
 * Every device derives the same keys and name, but not the same row: the
 * signatures are randomized and the timestamp is the caller's. A device that
 * finds a valid card for the identity does not publish another.
 */
export const signedUserCard = (id: DerivedIdentity, ownerTimestamp: number, name = id.cardName): UserCardRow =>
	signedIdentityCard(id, { name, ownerTimestamp });
