import { bytesToHex } from '@noble/hashes/utils';
import { identityKeysFromSecrets, openIdentity, wipeIdentityKeys, type IdentityHandle, type IdentityKeys } from './identity.js';
import type { ReadSessions } from './readSessions.js';
import { rowMutation, verifyRow, type RowVerdict } from './rows.js';
import { toBase64, toBytes } from './signature.js';
import { createSlotResolver, type RootRecord } from './slots.js';
import { deriveRootSlotUuid, randomSlotUuid } from './slotId.js';
import type { IngestOutcome, Transport, WriteRejection } from './transport.js';
import { wireBool } from './schema.js';
import type { UserStorageRow } from './types.js';

export { createSlotResolver, SlotMapError, type RootAccess, type RootRecord } from './slots.js';
export { deriveRootSlotUuid, randomSlotUuid } from './slotId.js';

export const STORAGE_KEY_SALT = 'avatar-encryption';
export const STORAGE_KEY_ITERATIONS = 100_000;

const bufferOf = (bytes: Uint8Array): Uint8Array<ArrayBuffer> => new Uint8Array(bytes);

export const deriveStorageKey = async (cryptSkey: Uint8Array): Promise<CryptoKey> => {
	const material = await crypto.subtle.importKey('raw', bufferOf(cryptSkey), 'PBKDF2', false, ['deriveKey']);
	return crypto.subtle.deriveKey(
		{ name: 'PBKDF2', salt: new TextEncoder().encode(STORAGE_KEY_SALT), iterations: STORAGE_KEY_ITERATIONS, hash: 'SHA-256' },
		material,
		{ name: 'AES-GCM', length: 256 },
		false,
		['encrypt', 'decrypt'],
	);
};

export const sealJson = async (key: CryptoKey, value: unknown): Promise<string> => {
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(value))));
	const out = new Uint8Array(iv.length + sealed.length);
	out.set(iv);
	out.set(sealed, iv.length);
	return toBase64(out);
};

export const openJson = async <T = any>(key: CryptoKey, valueB64: string): Promise<T> => {
	const combined = toBytes(valueB64);
	const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: combined.slice(0, 12) }, key, combined.slice(12));
	return JSON.parse(new TextDecoder().decode(plain)) as T;
};

export type JsonRecord = Record<string, unknown>;

const isRecord = (v: unknown): v is JsonRecord => !!v && typeof v === 'object' && !Array.isArray(v);

export interface MergeOptions {
	maps?: Record<string, 'patch' | 'keep-existing'>;
}

export const mergeJson = (base: JsonRecord | null | undefined, patch: JsonRecord, options: MergeOptions = {}): JsonRecord => {
	const merged: JsonRecord = { ...(base ?? {}) };
	for (const [key, value] of Object.entries(patch)) {
		const mode = options.maps?.[key];
		if (mode && isRecord(value)) {
			const current = isRecord(merged[key]) ? (merged[key] as JsonRecord) : {};
			const next: JsonRecord = { ...current };
			for (const [entry, entryValue] of Object.entries(value)) {
				if (entryValue === null) delete next[entry];
				else if (mode === 'keep-existing' && entry in current) continue;
				else next[entry] = entryValue;
			}
			merged[key] = next;
		} else if (value === null) {
			delete merged[key];
		} else {
			merged[key] = value;
		}
	}
	return merged;
};

export const ROOT_MERGE: MergeOptions = { maps: { slots: 'keep-existing' } };

export type StorageRead<T> =
	| { kind: 'found'; value: T; row: UserStorageRow }
	| { kind: 'absent'; row: UserStorageRow | null }
	| { kind: 'unavailable'; error: unknown }
	| { kind: 'unverified'; verdict: Exclude<RowVerdict, { status: 'ok' }>; row: UserStorageRow }
	| { kind: 'undecryptable'; error: unknown; row: UserStorageRow };

export type StorageWrite<T> =
	| { kind: 'written'; value: T; row: UserStorageRow; txid: number }
	| { kind: 'rejected'; rejection: WriteRejection; attempts: number }
	| { kind: 'unknown'; error: unknown }
	| Exclude<StorageRead<T>, { kind: 'found' } | { kind: 'absent' }>;

export interface UserStorageOptions {
	transport: Pick<Transport, 'readShapeOnce' | 'ingest'>;
	owner: IdentityHandle;
	sessions?: ReadSessions | null;
	maxAttempts?: number;
	now?: () => number;
}

const RECONCILABLE = (rejection: WriteRejection): boolean =>
	rejection.kind === 'stale_timestamp'
	|| rejection.kind === 'exists'
	|| rejection.kind === 'missing_parent';

export function createUserStorage(options: UserStorageOptions) {
	const { transport, owner, sessions = null } = options;
	const maxAttempts = options.maxAttempts ?? 4;
	const now = options.now ?? (() => Math.floor(Date.now() / 1000));
	const keys = owner.exportKeys();
	const rootUuid = deriveRootSlotUuid(keys.cryptSkey);
	const keyPromise = deriveStorageKey(keys.cryptSkey).finally(() => wipeIdentityKeys(keys));

	const readRow = async (uuid: string): Promise<
		{ kind: 'row'; row: UserStorageRow | null } | { kind: 'unavailable'; error: unknown } | { kind: 'unverified'; verdict: Exclude<RowVerdict, { status: 'ok' }>; row: UserStorageRow }
	> => {
		const where = `user_hash = '${owner.userHash}' AND uuid = '${uuid}'`;
		try {
			const read = () => transport.readShapeOnce<UserStorageRow>('user_storage', where, { authorization: sessions?.bearer('user_storage') ?? undefined });
			let res = await read();
			if (res.kind === 'read_session_required' && sessions && (await sessions.reopen(res.shape, 'user_storage')).kind === 'opened') res = await read();
			if (res.kind !== 'rows') return { kind: 'unavailable', error: res };
			const row = res.rows.find((r) => r.user_hash === owner.userHash && r.uuid === uuid) ?? null;
			if (!row) return { kind: 'row', row: null };
			const verdict = verifyRow('user_storage', row, owner.signPkey);
			if (verdict.status !== 'ok') return { kind: 'unverified', verdict, row };
			return { kind: 'row', row };
		} catch (error) {
			return { kind: 'unavailable', error };
		}
	};

	const readJson = async <T = JsonRecord>(uuid: string): Promise<StorageRead<T>> => {
		const read = await readRow(uuid);
		if (read.kind !== 'row') return read;
		const { row } = read;
		if (!row || wireBool(row.deleted_flag) || !row.value_b64) return { kind: 'absent', row };
		try {
			return { kind: 'found', value: await openJson<T>(await keyPromise, row.value_b64), row };
		} catch (error) {
			return { kind: 'undecryptable', error, row };
		}
	};

	const writeJson = async <T>(uuid: string, value: T | null, base: UserStorageRow | null): Promise<
		{ kind: 'written'; row: UserStorageRow; txid: number } | { kind: 'rejected'; rejection: WriteRejection } | { kind: 'unknown'; error: unknown }
	> => {
		const unsigned = {
			user_hash: owner.userHash,
			uuid,
			value_b64: value === null ? null : await sealJson(await keyPromise, value),
			deleted_flag: value === null,
			parent_sign_hash: base?.sign_hash ?? null,
			owner_timestamp: base ? Number(base.owner_timestamp) + 1 : now(),
		};
		const signed = owner.signRow('user_storage', unsigned);
		let outcome: IngestOutcome;
		try {
			outcome = await transport.ingest([rowMutation('user_storage', signed, base ? 'update' : 'insert')], owner.sign);
		} catch (error) {
			return { kind: 'unknown', error };
		}
		if (outcome.kind === 'rejected') return outcome;
		return { kind: 'written', row: { ...signed, sign_hash: signed.sign_hash ?? null } as UserStorageRow, txid: outcome.txid };
	};

	const updateJson = async <T extends JsonRecord>(
		uuid: string,
		change: (current: T | null) => T | null,
	): Promise<StorageWrite<T>> => {
		for (let attempt = 1; ; attempt++) {
			const read = await readJson<T>(uuid);
			if (read.kind !== 'found' && read.kind !== 'absent') return read;
			const base = read.row ?? null;
			const next = change(read.kind === 'found' ? read.value : null);
			const written = await writeJson(uuid, next, base);
			if (written.kind === 'written') return { kind: 'written', value: next as T, row: written.row, txid: written.txid };
			if (written.kind === 'unknown') return written;
			if (!RECONCILABLE(written.rejection) || attempt >= maxAttempts) {
				return { kind: 'rejected', rejection: written.rejection, attempts: attempt };
			}
		}
	};

	const patchJson = <T extends JsonRecord>(uuid: string, patch: JsonRecord, merge: MergeOptions = {}) =>
		updateJson<T>(uuid, (current) => mergeJson(current, patch, merge) as T);

	const resolver = createSlotResolver({
		read: async () => {
			const root = await readJson<RootRecord>(rootUuid);
			if (root.kind === 'found') return root.value;
			if (root.kind === 'absent') return null;
			throw new StorageReadError(rootUuid, root);
		},
		write: async (patch) => {
			const result = await patchJson(rootUuid, patch, ROOT_MERGE);
			if (result.kind !== 'written') throw new StorageWriteError(rootUuid, result);
		},
	});

	const slotUuid = (name: string) => resolver.getSlotUuid(name);

	const readSlot = async <T = JsonRecord>(name: string): Promise<StorageRead<T>> => {
		let uuid: string | null;
		try {
			uuid = await resolver.getSlotUuid(name);
		} catch (error) {
			if (error instanceof StorageReadError) return error.outcome as StorageRead<T>;
			return { kind: 'unavailable', error };
		}
		return uuid ? readJson<T>(uuid) : { kind: 'absent', row: null };
	};

	const updateSlot = async <T extends JsonRecord>(name: string, change: (current: T | null) => T | null): Promise<StorageWrite<T>> => {
		let result: StorageWrite<T> | null = null;
		try {
			await resolver.ensureSlotUuid(name, {
				mint: randomSlotUuid,
				writeRow: async (uuid) => {
					result = await updateJson<T>(uuid, change);
					if (result.kind !== 'written') throw new StorageWriteError(uuid, result);
				},
			});
		} catch (error) {
			if (error instanceof StorageReadError) return error.outcome as StorageWrite<T>;
			if (error instanceof StorageWriteError) return error.outcome as StorageWrite<T>;
			return { kind: 'unavailable', error };
		}
		return result as unknown as StorageWrite<T>;
	};

	const patchSlot = <T extends JsonRecord>(name: string, patch: JsonRecord, merge: MergeOptions = {}) =>
		updateSlot<T>(name, (current) => mergeJson(current, patch, merge) as T);

	return {
		ownerHash: owner.userHash,
		rootUuid,
		readRow,
		readJson,
		writeJson,
		updateJson,
		patchJson,
		slotUuid,
		readSlot,
		updateSlot,
		patchSlot,
		reset: resolver.reset,
	};
}

export type UserStorage = ReturnType<typeof createUserStorage>;

export class StorageReadError extends Error {
	constructor(readonly uuid: string, readonly outcome: Exclude<StorageRead<unknown>, { kind: 'found' } | { kind: 'absent' }>) {
		super(`user_storage ${uuid}: ${outcome.kind}`);
		this.name = 'StorageReadError';
	}
}

export class StorageWriteError extends Error {
	constructor(readonly uuid: string, readonly outcome: Exclude<StorageWrite<unknown>, { kind: 'written' }>) {
		super(`user_storage ${uuid}: ${outcome.kind === 'rejected' ? outcome.rejection.kind : outcome.kind}`);
		this.name = 'StorageWriteError';
	}
}

export const ORIGINS_SLOT = 'origins';

export interface OriginKeysRecord {
	name: string;
	sign_skey: string;
	crypt_skey: string;
	contact_skey: string;
	sign_pkey: string;
	crypt_pkey: string;
}

export const originKeysRecord = (name: string, keys: IdentityKeys): OriginKeysRecord => ({
	name,
	sign_skey: toBase64(keys.signSkey),
	crypt_skey: toBase64(keys.cryptSkey),
	contact_skey: bytesToHex(keys.contactSkey),
	sign_pkey: toBase64(keys.signPkey),
	crypt_pkey: toBase64(keys.cryptPkey),
});

export const openOriginKeys = (originHash: string, record: OriginKeysRecord): IdentityHandle => {
	const keys = identityKeysFromSecrets(
		{ signSkey: record.sign_skey, cryptSkey: record.crypt_skey, contactSkey: record.contact_skey },
		{ userHash: originHash, signPkey: record.sign_pkey, cryptPkey: record.crypt_pkey },
	);
	try {
		return openIdentity(keys);
	} finally {
		wipeIdentityKeys(keys);
	}
};

export type OriginsSlot = Record<string, OriginKeysRecord>;

export const putOriginKeys = (storage: UserStorage, originHash: string, record: OriginKeysRecord) =>
	storage.patchSlot<OriginsSlot>(ORIGINS_SLOT, { [originHash]: record as unknown as JsonRecord });

export const removeOriginKeys = (storage: UserStorage, originHash: string) =>
	storage.patchSlot<OriginsSlot>(ORIGINS_SLOT, { [originHash]: null });

export type OriginKeysRead =
	| { kind: 'found'; record: OriginKeysRecord; identity: IdentityHandle }
	| { kind: 'absent' }
	| { kind: 'unavailable' | 'unverified' | 'undecryptable'; outcome: StorageRead<OriginsSlot> }
	| { kind: 'mismatch'; error: unknown };

export const loadOriginKeys = async (storage: UserStorage, originHash: string): Promise<OriginKeysRead> => {
	const slot = await storage.readSlot<OriginsSlot>(ORIGINS_SLOT);
	if (slot.kind === 'absent') return { kind: 'absent' };
	if (slot.kind !== 'found') return { kind: slot.kind, outcome: slot };
	const record = slot.value[originHash];
	if (!record) return { kind: 'absent' };
	try {
		return { kind: 'found', record, identity: openOriginKeys(originHash, record) };
	} catch (error) {
		return { kind: 'mismatch', error };
	}
};
