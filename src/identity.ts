import { sha3_256, shake256 } from '@noble/hashes/sha3';
import { hexToBytes, randomBytes } from '@noble/hashes/utils';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import * as secp from '@noble/secp256k1';
import { deriveSenderMsgKey, unwrapSenderMsgKey } from './dialogs.js';
import { signRow, type SignedRow } from './rows.js';
import { toBase64, toBytes } from './signature.js';
import type { IngestEachOutcome, Mutation, RequestOptions, Transport } from './transport.js';
import type { UserCardRow } from './types.js';
import { userHashOf, verifyUserCard, type CardVerdict } from './verifyCard.js';

export { userHashOf, verifyUserCard, type CardVerdict };

export interface IdentityKeys {
	signSkey: Uint8Array;
	signPkey: Uint8Array;
	cryptSkey: Uint8Array;
	cryptPkey: Uint8Array;
	contactSkey: Uint8Array;
	contactPkey: Uint8Array;
}

export interface SecretKeys {
	signSkey: Uint8Array | string;
	cryptSkey: Uint8Array | string;
	contactSkey: Uint8Array | string;
}

export interface ExpectedPublicKeys {
	userHash?: string;
	signPkey?: Uint8Array | string;
	cryptPkey?: Uint8Array | string;
	contactPkey?: Uint8Array | string;
}

export type IdentityKeysMismatch =
	| 'malformed'
	| 'user_hash'
	| 'sign_pkey'
	| 'crypt_pkey'
	| 'contact_pkey'
	| 'sign_keypair'
	| 'crypt_keypair'
	| 'contact_keypair';

export class IdentityKeysError extends Error {
	constructor(readonly reason: IdentityKeysMismatch, message = `identity keys: ${reason} does not match`) {
		super(message);
		this.name = 'IdentityKeysError';
	}
}

export class IdentityClosedError extends Error {
	constructor(readonly userHash: string) {
		super(`identity ${userHash.slice(0, 12)}… is closed`);
		this.name = 'IdentityClosedError';
	}
}

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]);

const contactBytes = (value: Uint8Array | string): Uint8Array =>
	typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value) ? hexToBytes(value) : toBytes(value);

export const generateIdentityKeys = (): IdentityKeys => {
	const seed = randomBytes(32);
	const sign = ml_dsa87.keygen(seed);
	seed.fill(0);
	const crypt = ml_kem1024.keygen();
	const contactSkey = secp.utils.randomPrivateKey();
	return {
		signSkey: sign.secretKey,
		signPkey: sign.publicKey,
		cryptSkey: crypt.secretKey,
		cryptPkey: crypt.publicKey,
		contactSkey,
		contactPkey: secp.getPublicKey(contactSkey, true),
	};
};

const KEYPAIR_PROBE = new TextEncoder().encode('buckitup/identity-keypair-check/v1');
const ML_DSA_TR = { from: 64, to: 128 };
const ML_KEM_EK = { from: 1536, to: 3104 };
const ML_KEM_EK_HASH = { from: 3104, to: 3136 };

const signKeypairWorks = (signSkey: Uint8Array, signPkey: Uint8Array): boolean => {
	try {
		if (!sameBytes(signSkey.subarray(ML_DSA_TR.from, ML_DSA_TR.to), shake256(signPkey, { dkLen: 64 }))) return false;
		return ml_dsa87.verify(ml_dsa87.sign(KEYPAIR_PROBE, signSkey), KEYPAIR_PROBE, signPkey);
	} catch {
		return false;
	}
};

const cryptKeypairWorks = (cryptSkey: Uint8Array, cryptPkey: Uint8Array): boolean => {
	let shared: Uint8Array | null = null;
	let opened: Uint8Array | null = null;
	try {
		if (!sameBytes(cryptSkey.subarray(ML_KEM_EK.from, ML_KEM_EK.to), cryptPkey)) return false;
		if (!sameBytes(cryptSkey.subarray(ML_KEM_EK_HASH.from, ML_KEM_EK_HASH.to), sha3_256(cryptPkey))) return false;
		const { cipherText, sharedSecret } = ml_kem1024.encapsulate(cryptPkey);
		shared = sharedSecret;
		opened = ml_kem1024.decapsulate(cipherText, cryptSkey);
		return sameBytes(opened, shared);
	} catch {
		return false;
	} finally {
		shared?.fill(0);
		opened?.fill(0);
	}
};

const contactKeypairWorks = (contactSkey: Uint8Array, contactPkey: Uint8Array): boolean => {
	try {
		return sameBytes(secp.getPublicKey(contactSkey, true), contactPkey);
	} catch {
		return false;
	}
};

export const identityKeypairFault = (keys: IdentityKeys): IdentityKeysMismatch | null => {
	if (!signKeypairWorks(keys.signSkey, keys.signPkey)) return 'sign_keypair';
	if (!cryptKeypairWorks(keys.cryptSkey, keys.cryptPkey)) return 'crypt_keypair';
	if (!contactKeypairWorks(keys.contactSkey, keys.contactPkey)) return 'contact_keypair';
	return null;
};

export const identityKeysFromSecrets = (secrets: SecretKeys, expected: ExpectedPublicKeys = {}): IdentityKeys => {
	const buffers: Uint8Array[] = [];
	const fail = (reason: IdentityKeysMismatch, message?: string) => {
		for (const buffer of buffers) buffer.fill(0);
		return new IdentityKeysError(reason, message);
	};
	let keys: IdentityKeys;
	try {
		const own = (bytes: Uint8Array) => {
			const copy = new Uint8Array(bytes);
			buffers.push(copy);
			return copy;
		};
		const signSkey = own(toBytes(secrets.signSkey));
		const cryptSkey = own(toBytes(secrets.cryptSkey));
		const contactSkey = own(contactBytes(secrets.contactSkey));
		keys = {
			signSkey,
			signPkey: ml_dsa87.getPublicKey(signSkey),
			cryptSkey,
			cryptPkey: ml_kem1024.getPublicKey(cryptSkey),
			contactSkey,
			contactPkey: secp.getPublicKey(contactSkey, true),
		};
	} catch (e) {
		throw fail('malformed', `identity keys: ${(e as Error)?.message ?? e}`);
	}
	if (expected.userHash !== undefined && expected.userHash !== userHashOf(keys.signPkey)) throw fail('user_hash');
	for (const [field, reason] of [
		['signPkey', 'sign_pkey'],
		['cryptPkey', 'crypt_pkey'],
		['contactPkey', 'contact_pkey'],
	] as const) {
		const value = expected[field];
		if (value !== undefined && !sameBytes(toBytes(value), keys[field])) throw fail(reason);
	}
	const fault = identityKeypairFault(keys);
	if (fault) throw fail(fault);
	return keys;
};

export const wipeIdentityKeys = (keys: IdentityKeys): void => {
	for (const key of [keys.signSkey, keys.cryptSkey, keys.contactSkey]) key.fill(0);
};

export interface UserCardInput {
	name: string;
	ownerTimestamp: number;
	deleted?: boolean;
}

export interface CardKeyFields {
	user_hash: string;
	sign_pkey: string;
	crypt_pkey: string;
	crypt_cert: string;
	contact_pkey: string;
	contact_cert: string;
}

export const cardKeyFields = (
	keys: Pick<IdentityKeys, 'signSkey' | 'signPkey' | 'cryptPkey' | 'contactPkey'>,
): CardKeyFields => ({
	user_hash: userHashOf(keys.signPkey),
	sign_pkey: toBase64(keys.signPkey),
	crypt_pkey: toBase64(keys.cryptPkey),
	crypt_cert: toBase64(ml_dsa87.sign(keys.cryptPkey, keys.signSkey)),
	contact_pkey: toBase64(keys.contactPkey),
	contact_cert: toBase64(ml_dsa87.sign(keys.contactPkey, keys.signSkey)),
});

export const unsignedUserCard = (
	keys: Pick<IdentityKeys, 'signSkey' | 'signPkey' | 'cryptPkey' | 'contactPkey'>,
	{ name, ownerTimestamp, deleted = false }: UserCardInput,
): UserCardRow => {
	if (!Number.isSafeInteger(ownerTimestamp) || ownerTimestamp <= 0) throw new Error('user card: owner_timestamp must be a positive integer');
	if (!name) throw new Error('user card: the name must not be empty');
	return {
		...cardKeyFields(keys),
		name,
		deleted_flag: deleted,
		owner_timestamp: ownerTimestamp,
		sign_b64: null,
	};
};

export const signedUserCard = (
	keys: Pick<IdentityKeys, 'signSkey' | 'signPkey' | 'cryptPkey' | 'contactPkey'>,
	input: UserCardInput,
): UserCardRow & { sign_b64: string } => {
	const row = signRow('user_cards', unsignedUserCard(keys, input), keys.signSkey);
	return row as SignedRow<UserCardRow> as UserCardRow & { sign_b64: string };
};

export const userCardInsert = (row: UserCardRow): Mutation => ({
	type: 'insert',
	syncMetadata: { relation: 'user_cards' },
	modified: row,
});

export interface IdentityHandle {
	readonly userHash: string;
	readonly signPkey: Uint8Array;
	readonly cryptPkey: Uint8Array;
	readonly contactPkey: Uint8Array;
	readonly closed: boolean;
	sign(message: Uint8Array): Uint8Array;
	signRow<T extends Record<string, unknown>>(relation: string, row: T): SignedRow<T>;
	userCard(input: UserCardInput): UserCardRow & { sign_b64: string };
	decapsulate(cipherText: Uint8Array): Uint8Array;
	senderMsgKey(peerHash: string): Uint8Array;
	unwrapPeerKey(row: { peer_kem_wrap_key_b64: string | null; peer_wrapped_msg_key_b64: string | null }): Promise<Uint8Array>;
	exportKeys(): IdentityKeys;
	close(): void;
}

export const openIdentity = (source: IdentityKeys): IdentityHandle => {
	const fault = identityKeypairFault(source);
	if (fault) throw new IdentityKeysError(fault);
	const keys: IdentityKeys = {
		signSkey: new Uint8Array(source.signSkey),
		signPkey: new Uint8Array(source.signPkey),
		cryptSkey: new Uint8Array(source.cryptSkey),
		cryptPkey: new Uint8Array(source.cryptPkey),
		contactSkey: new Uint8Array(source.contactSkey),
		contactPkey: new Uint8Array(source.contactPkey),
	};
	const userHash = userHashOf(keys.signPkey);
	let closed = false;
	const open = (): IdentityKeys => {
		if (closed) throw new IdentityClosedError(userHash);
		return keys;
	};
	return Object.freeze({
		userHash,
		get signPkey() { return new Uint8Array(keys.signPkey); },
		get cryptPkey() { return new Uint8Array(keys.cryptPkey); },
		get contactPkey() { return new Uint8Array(keys.contactPkey); },
		get closed() { return closed; },
		sign: (message: Uint8Array) => ml_dsa87.sign(message, open().signSkey),
		signRow: <T extends Record<string, unknown>>(relation: string, row: T) => signRow(relation, row, open().signSkey),
		userCard: (input: UserCardInput) => signedUserCard(open(), input),
		decapsulate: (cipherText: Uint8Array) => ml_kem1024.decapsulate(cipherText, open().cryptSkey),
		senderMsgKey: (peerHash: string) => {
			const k = open();
			return deriveSenderMsgKey(k.signSkey, k.cryptSkey, peerHash);
		},
		unwrapPeerKey: async (row: { peer_kem_wrap_key_b64: string | null; peer_wrapped_msg_key_b64: string | null }) => {
			if (!row.peer_kem_wrap_key_b64 || !row.peer_wrapped_msg_key_b64) throw new Error('dialog_keys row carries no wrapped key');
			return unwrapSenderMsgKey(open().cryptSkey, row.peer_kem_wrap_key_b64, row.peer_wrapped_msg_key_b64);
		},
		exportKeys: (): IdentityKeys => {
			const k = open();
			return {
				signSkey: new Uint8Array(k.signSkey),
				signPkey: new Uint8Array(k.signPkey),
				cryptSkey: new Uint8Array(k.cryptSkey),
				cryptPkey: new Uint8Array(k.cryptPkey),
				contactSkey: new Uint8Array(k.contactSkey),
				contactPkey: new Uint8Array(k.contactPkey),
			};
		},
		close: () => {
			if (closed) return;
			closed = true;
			wipeIdentityKeys(keys);
		},
	});
};

export const publishUserCard = (
	transport: Pick<Transport, 'ingestEach'>,
	identity: IdentityHandle,
	row: UserCardRow,
	opts?: RequestOptions,
): Promise<IngestEachOutcome> => {
	if (row.user_hash !== identity.userHash) {
		return Promise.reject(new Error('publishUserCard: the card belongs to another identity than the one proving it'));
	}
	return transport.ingestEach([userCardInsert(row)], identity.sign, opts);
};

export interface IdentitySession {
	add(identity: IdentityHandle): IdentityHandle;
	open(keys: IdentityKeys): IdentityHandle;
	get(userHash: string): IdentityHandle | null;
	list(): IdentityHandle[];
	close(userHash: string): void;
	closeAll(): void;
}

export const createIdentitySession = (): IdentitySession => {
	const handles = new Map<string, IdentityHandle>();
	const session: IdentitySession = {
		add(identity) {
			if (identity.closed) throw new IdentityClosedError(identity.userHash);
			const existing = handles.get(identity.userHash);
			if (existing && existing !== identity) existing.close();
			handles.set(identity.userHash, identity);
			return identity;
		},
		open: (keys) => session.add(openIdentity(keys)),
		get: (userHash) => {
			const handle = handles.get(userHash);
			return handle && !handle.closed ? handle : null;
		},
		list: () => [...handles.values()].filter((h) => !h.closed),
		close(userHash) {
			handles.get(userHash)?.close();
			handles.delete(userHash);
		},
		closeAll() {
			for (const handle of handles.values()) handle.close();
			handles.clear();
		},
	};
	return session;
};
