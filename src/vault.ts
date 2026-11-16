import { bytesToHex } from '@noble/hashes/utils';
import {
	assertPrf,
	createPrfPasskey,
	lockSaltOf,
	lockSeedFromPrf,
	readLockSeed,
	PasskeyMismatchError,
	PrfMissingError,
	PrfUnsupportedError,
	type Credentials,
	type PrfLockRecord,
} from './vaultLock.js';
import {
	IdentityKeysError,
	identityKeysFromSecrets,
	openIdentity,
	wipeIdentityKeys,
	type ExpectedPublicKeys,
	type IdentityHandle,
	type IdentityKeys,
} from './identity.js';

export { PasskeyMismatchError, PrfMissingError, PrfUnsupportedError, type Credentials, type PrfLockRecord };

export class VaultLockedError extends Error {
	constructor(message: string, options?: { cause?: unknown }) {
		super(message, options);
		this.name = 'VaultLockedError';
	}
}

export class VaultMissingError extends Error {
	constructor(readonly vaultId: string) {
		super(`No vault ${vaultId} on this device`);
		this.name = 'VaultMissingError';
	}
}

interface LockKey {
	iv: Uint8Array;
	privateKey: Uint8Array;
	encSK: Uint8Array;
	localIdentity?: string;
	[key: string]: unknown;
}

interface LofiVault {
	id: string;
	get(name: string, options: { useLockKey: LockKey }): Promise<unknown>;
	set(name: string, value: unknown, options: { useLockKey: LockKey }): Promise<unknown>;
	entries(options: { useLockKey: LockKey }): Promise<Array<[string, unknown]>>;
	clear(options: { useLockKey: LockKey }): Promise<unknown>;
	lock(): unknown;
}

interface RawStorage {
	get(key: string): Promise<unknown>;
	set(key: string, value: unknown): Promise<unknown>;
	remove(key: string): Promise<unknown>;
	keys(): Promise<string[]>;
}

interface LocalVaultModule {
	connect(options: Record<string, unknown>): Promise<LofiVault>;
	rawStorage(type: 'idb'): RawStorage;
}

interface LocalDataLockModule {
	deriveLockKey(seed: Uint8Array): LockKey;
}

let localVault: Promise<LocalVaultModule> | null = null;
let localDataLock: Promise<LocalDataLockModule> | null = null;

const loadLocalVault = (): Promise<LocalVaultModule> =>
	(localVault ??= (async () => {
		// @ts-ignore
		const mod = (await import('@lo-fi/local-vault')) as LocalVaultModule;
		// @ts-ignore
		await import('@lo-fi/local-vault/adapter/idb');
		return mod;
	})());

const loadLocalDataLock = (): Promise<LocalDataLockModule> =>
	// @ts-ignore
	(localDataLock ??= import('@lo-fi/local-data-lock') as Promise<LocalDataLockModule>);

export const vaultStorage = async (): Promise<RawStorage> => (await loadLocalVault()).rawStorage('idb');

const lockKeyOf = (vaultId: string) => `pq-vault-lock-${vaultId}`;
const vaultKeyOf = (vaultId: string) => `local-vault-${vaultId}`;

export const prfLockOf = async (vaultId: string | null | undefined): Promise<PrfLockRecord | null> =>
	vaultId ? (((await (await vaultStorage()).get(lockKeyOf(vaultId))) as PrfLockRecord | undefined) ?? null) : null;

export const newPrfVaultId = (): string => {
	const bytes = crypto.getRandomValues(new Uint8Array(12));
	return btoa(String.fromCharCode(...bytes)).replace(/[^a-zA-Z0-9]+/g, '');
};

export interface PrfVault {
	readonly id: string;
	readonly lockMode: 'prf';
	readonly locked: boolean;
	get(name: string): Promise<unknown>;
	set(name: string, value: unknown): Promise<unknown>;
	entries(): Promise<Array<[string, unknown]>>;
	clear(): Promise<unknown>;
	lock(): true;
}

const wipeLockKey = (key: LockKey) => {
	key.iv.fill(0);
	key.privateKey.fill(0);
	key.encSK.fill(0);
};

const prfHandle = (vault: LofiVault, lockKey: LockKey): PrfVault => {
	let key: LockKey | null = lockKey;
	const withKey = () => {
		if (!key) throw new VaultLockedError('the vault is locked; its passkey has to open it again');
		return { useLockKey: key };
	};
	return Object.freeze({
		id: vault.id,
		lockMode: 'prf' as const,
		get locked() { return key === null; },
		get: async (name: string) => vault.get(name, withKey()),
		entries: async () => vault.entries(withKey()),
		set: async (name: string, value: unknown) => vault.set(name, value, withKey()),
		clear: async () => vault.clear(withKey()),
		lock: () => {
			if (key) {
				wipeLockKey(key);
				key = null;
			}
			try { vault.lock(); } catch { return true as const; }
			return true as const;
		},
	});
};

export const isPrfVault = (vault: unknown): vault is PrfVault => (vault as PrfVault | null)?.lockMode === 'prf';

const openWithSeed = async (vaultId: string, lock: PrfLockRecord, seed: Uint8Array): Promise<PrfVault> => {
	const [{ connect }, { deriveLockKey }] = await Promise.all([loadLocalVault(), loadLocalDataLock()]);
	const lockKey: LockKey = { ...deriveLockKey(seed), localIdentity: vaultId };
	try {
		const vault = await connect({
			storageType: 'idb',
			vaultID: vaultId,
			keyOptions: { useLockKey: lockKey, cacheManualLockKey: false, relyingPartyID: lock.rpId },
		});
		return prfHandle(vault, lockKey);
	} catch (e) {
		wipeLockKey(lockKey);
		if (/decryption failed/i.test((e as Error)?.message ?? '')) throw new PasskeyMismatchError();
		throw e;
	}
};

const createWithSeed = async (vaultId: string, lock: PrfLockRecord, seed: Uint8Array) => {
	const vault = await openWithSeed(vaultId, lock, seed);
	try {
		await (await vaultStorage()).set(lockKeyOf(vaultId), lock);
	} catch (e) {
		vault.lock();
		throw e;
	}
	return { vault, lock };
};

export interface CreatePrfVaultOptions {
	name: string;
	credentials: Credentials;
	rpId: string;
	vaultId?: string;
}

export const createPrfVault = async ({
	name,
	credentials,
	rpId,
	vaultId = newPrfVaultId(),
}: CreatePrfVaultOptions): Promise<{ vault: PrfVault; lock: PrfLockRecord }> => {
	const { record, seed } = await createPrfPasskey(credentials, { rpId, vaultId, name });
	return createWithSeed(vaultId, record, seed);
};

export const createPrfVaultWithSeed = ({ lock, seed, vaultId = newPrfVaultId() }: {
	lock: PrfLockRecord;
	seed: Uint8Array;
	vaultId?: string;
}): Promise<{ vault: PrfVault; lock: PrfLockRecord }> => createWithSeed(vaultId, lock, seed);

export interface RecoverySaltRequest {
	salt: Uint8Array<ArrayBuffer>;
	prf?: Uint8Array | null;
	flags?: { backupEligible: boolean; backupState: boolean } | null;
}

const TWO_SALT_REFUSALS = ['NotSupportedError', 'TypeError'];

const assertWithRecoverySalt = async (credentials: Credentials, lock: PrfLockRecord, recoverySalt: Uint8Array<ArrayBuffer>) => {
	try {
		return await assertPrf(credentials, {
			rpId: lock.rpId,
			credentialId: lock.credentialId,
			transports: lock.transports,
			first: lockSaltOf(lock),
			second: recoverySalt,
		});
	} catch (e) {
		if (TWO_SALT_REFUSALS.includes((e as Error)?.name)) return null;
		throw e;
	}
};

export const openPrfVault = async (
	vaultId: string,
	lock: PrfLockRecord,
	{ credentials, recovery = null }: { credentials: Credentials; recovery?: RecoverySaltRequest | null },
): Promise<PrfVault> => {
	const stored = (await (await vaultStorage()).get(vaultKeyOf(vaultId))) as { data?: unknown } | undefined;
	if (!stored?.data) throw new VaultMissingError(vaultId);
	if (!recovery) return openWithSeed(vaultId, lock, await readLockSeed(credentials, lock));
	let answer = await assertWithRecoverySalt(credentials, lock, recovery.salt);
	const twoSaltRefused = !answer;
	if (!answer) {
		recovery.prf = null;
		recovery.flags = null;
		answer = await assertPrf(credentials, {
			rpId: lock.rpId,
			credentialId: lock.credentialId,
			transports: lock.transports,
			first: lockSaltOf(lock),
		});
	}
	const assertion = answer;
	try {
		let seed: Uint8Array;
		try {
			seed = lockSeedFromPrf(assertion.first);
		} finally {
			assertion.first.fill(0);
		}
		const vault = await openWithSeed(vaultId, lock, seed);
		recovery.prf = twoSaltRefused ? null : assertion.second;
		recovery.flags = assertion.flags;
		if (twoSaltRefused) assertion.second?.fill(0);
		return vault;
	} catch (e) {
		assertion.second?.fill(0);
		throw e;
	}
};

export const dropPrfVault = async (vaultId: string, handle: PrfVault | null = null): Promise<void> => {
	if (handle) {
		await handle.clear().catch(() => {});
		handle.lock();
	}
	const storage = await vaultStorage();
	await storage.remove(vaultKeyOf(vaultId));
	await storage.remove(lockKeyOf(vaultId));
};

export interface VaultEntries {
	get(name: string): Promise<unknown>;
	set(name: string, value: unknown): Promise<unknown>;
}

export const writeIdentityKeys = async (vault: VaultEntries, keys: IdentityKeys): Promise<void> => {
	await vault.set('sign_skey', new Uint8Array(keys.signSkey));
	await vault.set('crypt_skey', new Uint8Array(keys.cryptSkey));
	await vault.set('contact_skey', bytesToHex(keys.contactSkey));
};

export const storedKeyBytes = (value: unknown): Uint8Array | string | null => {
	if (value instanceof Uint8Array) return new Uint8Array(value);
	if (typeof value === 'string' && value) return value;
	if (value && typeof value === 'object' && !ArrayBuffer.isView(value)) {
		return new Uint8Array(Object.values(value as Record<string, unknown>).map((v) => Number(v)));
	}
	return null;
};

export const readIdentityKeys = async (vault: VaultEntries, expected: ExpectedPublicKeys = {}): Promise<IdentityKeys> => {
	const [signSkey, cryptSkey, contactSkey] = await Promise.all(
		['sign_skey', 'crypt_skey', 'contact_skey'].map(async (name) => storedKeyBytes(await vault.get(name))),
	);
	if (!signSkey || !cryptSkey || !contactSkey) throw new IdentityKeysError('malformed', 'the vault holds no identity keys');
	try {
		return identityKeysFromSecrets({ signSkey, cryptSkey, contactSkey }, expected);
	} finally {
		for (const key of [signSkey, cryptSkey, contactSkey]) if (key instanceof Uint8Array) key.fill(0);
	}
};

export const openVaultIdentity = async (vault: VaultEntries, expected: ExpectedPublicKeys = {}): Promise<IdentityHandle> => {
	const keys = await readIdentityKeys(vault, expected);
	try {
		return openIdentity(keys);
	} finally {
		wipeIdentityKeys(keys);
	}
};
