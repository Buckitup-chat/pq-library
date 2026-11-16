import { describe, it, expect, vi } from 'vitest';
import { generateIdentityKeys, openIdentity, type IdentityKeys } from '@buckitup/pq-client/identity';
import {
	createUserStorage,
	deriveRootSlotUuid,
	loadOriginKeys,
	mergeJson,
	openJson,
	originKeysRecord,
	putOriginKeys,
	removeOriginKeys,
	sealJson,
	deriveStorageKey,
	ORIGINS_SLOT,
	type OriginsSlot,
} from '@buckitup/pq-client/storage';
import { rowMutation, fromBase64, toBase64 } from '@buckitup/pq-client/rows';
import { createFakePqServer, type FakePqServer } from './helpers/fakePqServer';

const publishCard = async (server: FakePqServer, keys: IdentityKeys, name = 'Owner') => {
	const me = openIdentity(keys);
	const card = me.userCard({ name, ownerTimestamp: 1 });
	const outcome = await server.transport.ingest([rowMutation('user_cards', card)], me.sign);
	expect(outcome.kind).toBe('written');
	return me;
};

const client = (server: FakePqServer, keys: IdentityKeys) =>
	createUserStorage({ transport: server.transport, owner: openIdentity(keys) });

describe('slot encryption and addressing', () => {
	it('opens a value the app sealed: AES-256-GCM, PBKDF2-SHA-256 of crypt_skey, salt "avatar-encryption", 100 000 rounds', async () => {
		const keys = generateIdentityKeys();
		const material = await crypto.subtle.importKey('raw', new Uint8Array(keys.cryptSkey), 'PBKDF2', false, ['deriveKey']);
		const appKey = await crypto.subtle.deriveKey(
			{ name: 'PBKDF2', salt: new TextEncoder().encode('avatar-encryption'), iterations: 100000, hash: 'SHA-256' },
			material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
		);
		const iv = crypto.getRandomValues(new Uint8Array(12));
		const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, appKey, new TextEncoder().encode('{"name":"Ann"}')));
		const valueB64 = toBase64(new Uint8Array([...iv, ...sealed]));
		const sdkKey = await deriveStorageKey(keys.cryptSkey);
		expect(await openJson(sdkKey, valueB64)).toEqual({ name: 'Ann' });
		const back = fromBase64(await sealJson(sdkKey, { a: 1 }));
		expect(JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: back.slice(0, 12) }, appKey, back.slice(12))))).toEqual({ a: 1 });
		expect(client(createFakePqServer(), keys).rootUuid).toBe(deriveRootSlotUuid(keys.cryptSkey));
	});

	it('merges top-level keys, deletes an entry with null, and keeps an existing slot address', () => {
		expect(mergeJson({ a: 1, b: { x: 1 } }, { b: { y: 2 }, c: null, a: null })).toEqual({ b: { y: 2 } });
		expect(mergeJson({ slots: { contacts: 'u1' } }, { slots: { contacts: 'u2', origins: 'u3' } }, { maps: { slots: 'keep-existing' } }))
			.toEqual({ slots: { contacts: 'u1', origins: 'u3' } });
		expect(mergeJson({ m: { a: 1, b: 2 } }, { m: { a: null } }, { maps: { m: 'patch' } })).toEqual({ m: { b: 2 } });
	});
});

describe('user_storage rows', () => {
	it('inserts, then updates from the current tip with a strictly newer timestamp', async () => {
		const server = createFakePqServer();
		const keys = generateIdentityKeys();
		await publishCard(server, keys);
		const storage = client(server, keys);
		const uuid = crypto.randomUUID();
		const first = await storage.patchJson(uuid, { a: 1 });
		const second = await storage.patchJson(uuid, { b: 2 });
		if (first.kind !== 'written' || second.kind !== 'written') throw new Error('expected both writes');
		expect(first.row.parent_sign_hash).toBeNull();
		expect(second.row.parent_sign_hash).toBe(first.row.sign_hash);
		expect(Number(second.row.owner_timestamp)).toBeGreaterThan(Number(first.row.owner_timestamp));
		expect(await storage.readJson(uuid)).toMatchObject({ kind: 'found', value: { a: 1, b: 2 } });
	});

	it('tells absent, unavailable, unverified and undecryptable apart, and writes over none of the last three', async () => {
		const server = createFakePqServer();
		const keys = generateIdentityKeys();
		const owner = await publishCard(server, keys);
		const storage = client(server, keys);
		const uuid = crypto.randomUUID();
		expect(await storage.readJson(uuid)).toEqual({ kind: 'absent', row: null });

		const offline = createUserStorage({
			transport: { ...server.transport, readShapeOnce: async () => { throw new TypeError('Failed to fetch'); } },
			owner,
		});
		expect((await offline.readJson(uuid)).kind).toBe('unavailable');
		expect((await offline.patchJson(uuid, { a: 1 })).kind).toBe('unavailable');

		const wrongKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt']);
		const foreign = owner.signRow('user_storage', {
			user_hash: owner.userHash, uuid, value_b64: await sealJson(wrongKey, { a: 1 }), deleted_flag: false, parent_sign_hash: null, owner_timestamp: 5,
		});
		await server.transport.ingest([rowMutation('user_storage', foreign)], owner.sign);
		expect((await storage.readJson(uuid)).kind).toBe('undecryptable');
		expect((await storage.patchJson(uuid, { b: 2 })).kind).toBe('undecryptable');

		const stored = server.tables.get('user_storage')!.get(`${owner.userHash}|${uuid}`)!;
		stored.owner_timestamp = 6;
		expect(await storage.readJson(uuid)).toMatchObject({ kind: 'unverified', verdict: { reason: 'bad_signature' } });
		expect((await storage.patchJson(uuid, { b: 2 })).kind).toBe('unverified');
		expect(stored.owner_timestamp).toBe(6);
	});
});

describe('named slots', () => {
	it('creates a slot behind the root map, keeps the root\'s other fields, and a second client finds it', async () => {
		const server = createFakePqServer();
		const keys = generateIdentityKeys();
		await publishCard(server, keys);
		const a = client(server, keys);
		await a.patchJson(a.rootUuid, { name: 'Owner', avatar: 'a1' });
		expect(await a.patchSlot('notes', { first: 'x' })).toMatchObject({ kind: 'written' });

		const b = client(server, keys);
		expect(await b.readSlot('notes')).toMatchObject({ kind: 'found', value: { first: 'x' } });
		expect(await b.readJson(b.rootUuid)).toMatchObject({ kind: 'found', value: { name: 'Owner', avatar: 'a1', slots: { notes: expect.any(String) } } });
		expect(await b.readSlot('never')).toEqual({ kind: 'absent', row: null });
	});

	it('two clients creating the same slot at once end on one address with both entries', async () => {
		const server = createFakePqServer();
		const keys = generateIdentityKeys();
		await publishCard(server, keys);
		const a = client(server, keys);
		const b = client(server, keys);
		let armed = true;
		const release = server.hold((path, body) => {
			if (!armed || path !== '/ingest' || !JSON.stringify(body).includes(a.rootUuid)) return false;
			armed = false;
			return true;
		});
		const first = a.patchSlot('origins', { va: { n: 1 } });
		await vi.waitFor(() => expect(armed).toBe(false), { timeout: 5000 });
		const second = await b.patchSlot('origins', { vb: { n: 2 } });
		release();
		const firstDone = await first;
		expect(second.kind).toBe('written');
		expect(firstDone.kind).toBe('written');
		const fresh = client(server, keys);
		expect(await fresh.readSlot('origins')).toMatchObject({ kind: 'found', value: { va: { n: 1 }, vb: { n: 2 } } });
		expect(await a.slotUuid('origins')).toBe(await fresh.slotUuid('origins'));
		expect(server.tables.get('user_storage')!.size).toBe(3);
	});

	it('two clients changing different entries at once keep both, through a re-read of the newer base', async () => {
		const server = createFakePqServer();
		const keys = generateIdentityKeys();
		await publishCard(server, keys);
		const a = client(server, keys);
		await a.patchSlot('origins', { v0: { n: 0 } });
		const b = client(server, keys);
		await b.readSlot('origins');
		const slotUuid = (await a.slotUuid('origins'))!;
		const slotWrites = () => server.requests.filter((r) => r.path === '/ingest' && JSON.stringify(r.body).includes(slotUuid)).length;
		const before = slotWrites();
		let armed = true;
		const release = server.hold((path, body) => {
			if (!armed || path !== '/ingest' || !JSON.stringify(body).includes(slotUuid)) return false;
			armed = false;
			return true;
		});
		const first = a.patchSlot('origins', { v1: { n: 1 } });
		await vi.waitFor(() => expect(armed).toBe(false), { timeout: 5000 });
		expect(await b.patchSlot('origins', { v2: { n: 2 } })).toMatchObject({ kind: 'written' });
		release();
		expect(await first).toMatchObject({ kind: 'written' });
		expect(await client(server, keys).readSlot('origins')).toMatchObject({ kind: 'found', value: { v0: { n: 0 }, v1: { n: 1 }, v2: { n: 2 } } });
		expect(slotWrites() - before).toBe(3);
	});

	it('a write built on a base another device has replaced is refused and re-applied on the newer base, even seconds later', async () => {
		const server = createFakePqServer();
		const keys = generateIdentityKeys();
		await publishCard(server, keys);
		let clock = 1_800_000_000;
		const now = () => clock;
		const a = createUserStorage({ transport: server.transport, owner: openIdentity(keys), now });
		await a.patchSlot('origins', { v0: { n: 0 } });
		const slotUuid = (await a.slotUuid('origins'))!;
		let replaced = false;
		const transport = {
			...server.transport,
			readShapeOnce: (async (...args: Parameters<typeof server.transport.readShapeOnce>) => {
				const read = await server.transport.readShapeOnce(...args);
				if (!replaced && String(args[1]).includes(slotUuid)) {
					replaced = true;
					clock += 5;
					expect(await a.patchSlot('origins', { vA: { n: 1 } })).toMatchObject({ kind: 'written' });
					clock += 5;
				}
				return read;
			}) as typeof server.transport.readShapeOnce,
		};
		const b = createUserStorage({ transport, owner: openIdentity(keys), now });
		expect(await b.patchSlot('origins', { vB: { n: 2 } })).toMatchObject({ kind: 'written' });
		expect(replaced).toBe(true);
		expect(await client(server, keys).readSlot('origins')).toMatchObject({ kind: 'found', value: { v0: { n: 0 }, vA: { n: 1 }, vB: { n: 2 } } });
	});

	it('backend limitation: a row on a stale base with a newer timestamp from a writer outside this rule is accepted with its parent rewritten, and the slot is reported unverified, not merged', async () => {
		const server = createFakePqServer();
		const keys = generateIdentityKeys();
		const owner = await publishCard(server, keys);
		const a = client(server, keys);
		await a.patchSlot('origins', { v0: { n: 0 } });
		const slotUuid = (await a.slotUuid('origins'))!;
		const base = await a.readRow(slotUuid);
		if (base.kind !== 'row' || !base.row) throw new Error('no base');
		expect(await a.patchSlot('origins', { vA: { n: 1 } })).toMatchObject({ kind: 'written' });

		const stale = owner.signRow('user_storage', {
			user_hash: owner.userHash,
			uuid: slotUuid,
			value_b64: await sealJson(await deriveStorageKey(keys.cryptSkey), { v0: { n: 0 }, vB: { n: 2 } }),
			deleted_flag: false,
			parent_sign_hash: base.row.sign_hash,
			owner_timestamp: Number(base.row.owner_timestamp) + 100,
		});
		expect(await server.transport.ingest([rowMutation('user_storage', stale, 'update')], owner.sign)).toMatchObject({ kind: 'written' });
		const stored = server.tables.get('user_storage')!.get(`${owner.userHash}|${slotUuid}`)!;
		expect(stored.parent_sign_hash).not.toBe(stale.parent_sign_hash);

		const reader = client(server, keys);
		expect(await reader.readSlot('origins')).toMatchObject({ kind: 'unverified', verdict: { reason: 'bad_signature' } });
		const writesBefore = server.requests.filter((r) => r.path === '/ingest').length;
		expect(await reader.patchSlot('origins', { vC: { n: 3 } })).toMatchObject({ kind: 'unverified' });
		expect(server.requests.filter((r) => r.path === '/ingest').length).toBe(writesBefore);
	});
});

describe('root map freshness and root failures', () => {
	it('a client that saw no slot sees it once another client creates it, without a reset', async () => {
		const server = createFakePqServer();
		const keys = generateIdentityKeys();
		await publishCard(server, keys);
		const a = client(server, keys);
		await a.patchJson(a.rootUuid, { name: 'Owner' });
		expect(await a.readSlot(ORIGINS_SLOT)).toEqual({ kind: 'absent', row: null });
		const b = client(server, keys);
		await b.patchSlot(ORIGINS_SLOT, { v1: { n: 1 } });
		expect(await a.readSlot(ORIGINS_SLOT)).toMatchObject({ kind: 'found', value: { v1: { n: 1 } } });
		expect(await a.slotUuid(ORIGINS_SLOT)).toBe(await b.slotUuid(ORIGINS_SLOT));
		expect(await a.patchSlot(ORIGINS_SLOT, { v2: { n: 2 } })).toMatchObject({ kind: 'written' });
		expect(server.tables.get('user_storage')!.size).toBe(2);
		expect(await client(server, keys).readSlot(ORIGINS_SLOT)).toMatchObject({ kind: 'found', value: { v1: { n: 1 }, v2: { n: 2 } } });
	});

	it('keeps an address it already knows even if the root map later names another', async () => {
		const server = createFakePqServer();
		const keys = generateIdentityKeys();
		await publishCard(server, keys);
		const a = client(server, keys);
		await a.patchSlot('notes', { x: 1 });
		const known = await a.slotUuid('notes');
		const other = client(server, keys);
		await other.patchJson(other.rootUuid, { slots: { notes: crypto.randomUUID() } }, { maps: { slots: 'patch' } });
		expect(await a.slotUuid('notes')).toBe(known);
	});

	const brokenRoot = async (damage: 'signature' | 'encryption') => {
		const server = createFakePqServer();
		const keys = generateIdentityKeys();
		const owner = await publishCard(server, keys);
		const a = client(server, keys);
		await a.patchSlot(ORIGINS_SLOT, { v1: { n: 1 } });
		const root = server.tables.get('user_storage')!.get(`${owner.userHash}|${a.rootUuid}`)!;
		if (damage === 'signature') root.owner_timestamp = Number(root.owner_timestamp) + 1;
		else {
			const wrongKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt']);
			const resealed = owner.signRow('user_storage', {
				user_hash: owner.userHash, uuid: a.rootUuid, value_b64: await sealJson(wrongKey, { slots: {} }),
				deleted_flag: false, parent_sign_hash: root.sign_hash as string, owner_timestamp: Number(root.owner_timestamp) + 1,
			});
			server.tables.get('user_storage')!.set(`${owner.userHash}|${a.rootUuid}`, resealed);
		}
		return { server, keys, before: JSON.stringify([...server.tables.get('user_storage')!.values()]) };
	};

	it.each([['signature', 'unverified'], ['encryption', 'undecryptable']] as const)(
		'a root with a broken %s is reported as %s by every slot read and write, and nothing is written over it',
		async (damage, kind) => {
			const { server, keys, before } = await brokenRoot(damage);
			const fresh = client(server, keys);
			expect((await fresh.readSlot(ORIGINS_SLOT)).kind).toBe(kind);
			expect((await fresh.patchSlot(ORIGINS_SLOT, { v2: { n: 2 } })).kind).toBe(kind);
			expect((await loadOriginKeys(fresh, 'u_' + 'a'.repeat(128))).kind).toBe(kind);
			expect((await putOriginKeys(fresh, 'u_' + 'a'.repeat(128), originKeysRecord('x', generateIdentityKeys()))).kind).toBe(kind);
			expect(JSON.stringify([...server.tables.get('user_storage')!.values()])).toBe(before);
		},
	);
});

describe('the origins slot', () => {
	it('keeps one record per origin_hash; adds, replaces and removes one without touching the others', async () => {
		const server = createFakePqServer();
		const ownerKeys = generateIdentityKeys();
		await publishCard(server, ownerKeys);
		const storage = client(server, ownerKeys);
		const [v1, v2] = [generateIdentityKeys(), generateIdentityKeys()];
		const h1 = openIdentity(v1).userHash;
		const h2 = openIdentity(v2).userHash;
		await putOriginKeys(storage, h1, originKeysRecord('Cafe', v1));
		await putOriginKeys(storage, h2, originKeysRecord('Bar', v2));
		await putOriginKeys(storage, h1, originKeysRecord('Cafe renamed', v1));
		await removeOriginKeys(storage, h2);

		const slot = await client(server, ownerKeys).readSlot<OriginsSlot>(ORIGINS_SLOT);
		if (slot.kind !== 'found') throw new Error('expected the slot');
		expect(Object.keys(slot.value)).toEqual([h1]);
		expect(slot.value[h1]).toMatchObject({ name: 'Cafe renamed', contact_skey: expect.stringMatching(/^[0-9a-f]{64}$/) });
		expect(JSON.stringify(slot.value)).not.toContain('null');
		expect(Object.keys(slot.value[h1]).sort()).toEqual(['contact_skey', 'crypt_pkey', 'crypt_skey', 'name', 'sign_pkey', 'sign_skey']);
	});

	it('restores a working handle only when the stored keys belong to that origin', async () => {
		const server = createFakePqServer();
		const ownerKeys = generateIdentityKeys();
		await publishCard(server, ownerKeys);
		const storage = client(server, ownerKeys);
		const venue = generateIdentityKeys();
		const venueHash = openIdentity(venue).userHash;
		await putOriginKeys(storage, venueHash, originKeysRecord('Cafe', venue));
		const loaded = await loadOriginKeys(client(server, ownerKeys), venueHash);
		expect(loaded.kind === 'found' && loaded.identity.userHash).toBe(venueHash);

		const other = generateIdentityKeys();
		await putOriginKeys(storage, venueHash, { ...originKeysRecord('Cafe', venue), sign_skey: toBase64(other.signSkey) });
		expect((await loadOriginKeys(client(server, ownerKeys), venueHash)).kind).toBe('mismatch');
		expect((await loadOriginKeys(client(server, ownerKeys), 'u_' + 'f'.repeat(128))).kind).toBe('absent');
	});
});
