import 'fake-indexeddb/auto';
import { describe, it, expect, beforeAll } from 'vitest';
// @ts-expect-error
import sodium from 'libsodium-wrappers';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import {
	createPrfVault,
	openPrfVault,
	dropPrfVault,
	prfLockOf,
	vaultStorage,
	writeIdentityKeys,
	readIdentityKeys,
	openVaultIdentity,
	PrfUnsupportedError,
	PasskeyMismatchError,
	VaultLockedError,
	VaultMissingError,
} from '@buckitup/pq-client/vault';
import {
	generateIdentityKeys,
	createIdentitySession,
	userHashOf,
	IdentityKeysError,
} from '@buckitup/pq-client/identity';
import { prfAuthenticator } from './helpers/prfAuthenticator';

const RP_ID = 'partner.example';

beforeAll(async () => {
	await sodium.ready;
	(globalThis as unknown as { sodium: unknown }).sodium = sodium;
});

const message = new TextEncoder().encode('proof');

const newIdentityVault = async (name: string) => {
	const auth = prfAuthenticator('at-create');
	const keys = generateIdentityKeys();
	const { vault, lock } = await createPrfVault({ name, credentials: auth.credentials, rpId: RP_ID });
	await writeIdentityKeys(vault, keys);
	return { auth, keys, vault, lock, userHash: userHashOf(keys.signPkey) };
};

describe('PRF vault', () => {
	it('keeps an identity at rest as ciphertext and opens it again with its passkey only', async () => {
		const { auth, keys, vault, lock, userHash } = await newIdentityVault('Owner');
		expect(lock).toMatchObject({ v: 1, rpId: RP_ID });
		expect(await prfLockOf(vault.id)).toEqual(lock);
		const stored = await (await vaultStorage()).get(`local-vault-${vault.id}`);
		expect(JSON.stringify(stored)).not.toContain(Buffer.from(keys.signSkey.slice(0, 24)).toString('base64'));

		vault.lock();
		expect(vault.locked).toBe(true);
		await expect(vault.get('sign_skey')).rejects.toBeInstanceOf(VaultLockedError);

		const reopened = await openPrfVault(vault.id, lock, { credentials: auth.credentials });
		const identity = await openVaultIdentity(reopened, { userHash });
		expect(identity.userHash).toBe(userHash);
		expect(identity.cryptPkey).toEqual(keys.cryptPkey);
		expect(ml_dsa87.verify(identity.sign(message), message, keys.signPkey)).toBe(true);
		expect(auth.calls).toEqual(['create', 'get']);
	});

	it('stores keys in the format the app vault reads: bytes for ML-DSA/ML-KEM, hex for the contact key', async () => {
		const { keys, vault } = await newIdentityVault('Owner');
		expect(await vault.get('contact_skey')).toBe(Buffer.from(keys.contactSkey).toString('hex'));
		expect(new Uint8Array(Object.values((await vault.get('sign_skey')) as Record<string, number>))).toEqual(keys.signSkey);
		const restored = await readIdentityKeys(vault);
		expect(restored.signPkey).toEqual(keys.signPkey);
		keys.signSkey.fill(0);
		expect((await readIdentityKeys(vault)).signPkey).toEqual(restored.signPkey);
	});

	it('holds VO and V open at once, and locking one leaves the other usable', async () => {
		const owner = await newIdentityVault('Owner');
		const venue = await newIdentityVault('Venue');
		const session = createIdentitySession();
		const vo = session.add(await openVaultIdentity(owner.vault, { userHash: owner.userHash }));
		const v = session.add(await openVaultIdentity(venue.vault, { userHash: venue.userHash }));

		const [voSig, vSig] = await Promise.all([vo.sign(message), v.sign(message)]);
		expect(ml_dsa87.verify(voSig, message, owner.keys.signPkey)).toBe(true);
		expect(ml_dsa87.verify(vSig, message, venue.keys.signPkey)).toBe(true);

		owner.vault.lock();
		await expect(owner.vault.get('sign_skey')).rejects.toBeInstanceOf(VaultLockedError);
		expect(await venue.vault.get('contact_skey')).toBe(Buffer.from(venue.keys.contactSkey).toString('hex'));

		session.closeAll();
		expect(() => vo.sign(message)).toThrow(/closed/);
		expect(() => v.sign(message)).toThrow(/closed/);
	});

	it('refuses an identity whose keys do not belong to the expected user', async () => {
		const owner = await newIdentityVault('Owner');
		const other = userHashOf(generateIdentityKeys().signPkey);
		await expect(openVaultIdentity(owner.vault, { userHash: other })).rejects.toMatchObject({ name: 'IdentityKeysError', reason: 'user_hash' });
		await owner.vault.clear();
		await expect(readIdentityKeys(owner.vault)).rejects.toBeInstanceOf(IdentityKeysError);
	});

	it('reports a missing PRF, a passkey that does not open the vault and a missing vault as distinct errors', async () => {
		await expect(createPrfVault({ name: 'x', credentials: prfAuthenticator('none').credentials, rpId: RP_ID }))
			.rejects.toBeInstanceOf(PrfUnsupportedError);
		await expect(createPrfVault({ name: 'x', credentials: prfAuthenticator('browser-none').credentials, rpId: RP_ID }))
			.rejects.toMatchObject({ name: 'PrfUnsupportedError', reason: 'browser' });

		const owner = await newIdentityVault('Owner');
		const venue = await newIdentityVault('Venue');
		owner.vault.lock();
		await expect(openPrfVault(owner.vault.id, owner.lock, { credentials: venue.auth.credentials }))
			.rejects.toMatchObject({ name: 'NotAllowedError' });
		const answeredByAnother = { ...owner.lock, credentialId: venue.lock.credentialId };
		await expect(openPrfVault(owner.vault.id, answeredByAnother, { credentials: venue.auth.credentials }))
			.rejects.toBeInstanceOf(PasskeyMismatchError);
		const reopened = await openPrfVault(owner.vault.id, owner.lock, { credentials: owner.auth.credentials });
		expect((await openVaultIdentity(reopened)).userHash).toBe(owner.userHash);

		await dropPrfVault(owner.vault.id);
		await expect(openPrfVault(owner.vault.id, owner.lock, { credentials: owner.auth.credentials }))
			.rejects.toBeInstanceOf(VaultMissingError);
		expect(await prfLockOf(owner.vault.id)).toBeNull();
	});
});
