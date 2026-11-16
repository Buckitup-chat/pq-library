import { describe, it, expect } from 'vitest';
import { generateIdentityKeys, openIdentity, type IdentityKeys } from '@buckitup/pq-client/identity';
import { createUserStorage, ORIGINS_SLOT, type OriginsSlot } from '@buckitup/pq-client/storage';
import {
	createOrigin,
	openOrigin,
	originRow,
	resumeOrigin,
	setOriginSetting,
	removeOriginSetting,
	updateOrigin,
	verifyOriginRow,
	OriginSettingError,
	readOrigin,
	type OriginContext,
} from '@buckitup/pq-client/origins';
import { rowMutation, verifyRow, toBase64 } from '@buckitup/pq-client/rows';
import { createReadSessions, createTransport, type Transport } from '@buckitup/pq-client/transport';
import { createFakePqServer, type FakePqServer } from './helpers/fakePqServer';

const ownerOn = async (server: FakePqServer, keys: IdentityKeys = generateIdentityKeys()) => {
	const owner = openIdentity(keys);
	expect((await server.transport.ingest([rowMutation('user_cards', owner.userCard({ name: 'Owner', ownerTimestamp: 1 }))], owner.sign)).kind).toBe('written');
	return { keys, owner };
};

const contextOn = (server: FakePqServer, keys: IdentityKeys, transport: Pick<Transport, 'readShapeOnce' | 'ingest'> = server.transport): OriginContext => {
	const owner = openIdentity(keys);
	return { transport, owner, storage: createUserStorage({ transport, owner }) };
};

const ingestsOf = (server: FakePqServer, relation: string) =>
	server.requests.filter((r) => r.path === '/ingest' && JSON.stringify(r.body).includes(`"relation":"${relation}"`));

describe('venue creation', () => {
	it('VO creates V, keeps its keys; another client with VO\'s keys loads V and acts as V', async () => {
		const server = createFakePqServer();
		const { keys } = await ownerOn(server);
		const vo = contextOn(server, keys);
		const created = await createOrigin(vo, { name: 'Cafe', moderationMode: 'post' });
		if (created.kind !== 'created') throw new Error(`expected created, got ${JSON.stringify(created)}`);
		const originHash = created.originHash;
		expect(originHash).not.toBe(vo.owner.userHash);

		const origin = server.tables.get('origins')!.get(originHash)!;
		const venueCard = server.tables.get('user_cards')!.get(originHash)!;
		expect(origin).toMatchObject({ origin_hash: originHash, owner_hash: vo.owner.userHash, name: 'Cafe', moderation_mode: 'post' });
		expect(String(origin.sign_hash)).toMatch(/^ors_[0-9a-f]{128}$/);
		expect(verifyOriginRow(origin, { venueSignPkey: String(venueCard.sign_pkey), ownerSignPkey: vo.owner.signPkey })).toEqual({ status: 'ok', signer: 'venue' });
		const cardWrite = ingestsOf(server, 'user_cards').at(-1)!;
		expect((cardWrite.body!.mutations as unknown[])).toHaveLength(1);
		expect((ingestsOf(server, 'origins')[0].body!.mutations as unknown[])).toHaveLength(1);

		const elsewhere = contextOn(server, keys, createTransport({ baseUrl: 'https://fake.example/electric/v1', fetch: server.fetch }));
		const loaded = await openOrigin(elsewhere, originHash);
		if (loaded.kind !== 'found') throw new Error('expected V on the second client');
		expect(loaded.identity.userHash).toBe(originHash);
		const setting = await setOriginSetting(elsewhere, originHash, 'review_access', 'invite_only');
		expect(setting).toMatchObject({ kind: 'written', row: { origin_hash: originHash, key: 'review_access', value: 'invite_only' } });
		const storedSetting = server.tables.get('origin_settings')!.get(`${originHash}|review_access`)!;
		expect(verifyRow('origin_settings', storedSetting, String(venueCard.sign_pkey)).status).toBe('ok');
	});

	it('stores V\'s keys before anything is published: a failed card write leaves the keys, and the retry finishes the same V', async () => {
		const server = createFakePqServer();
		const { keys } = await ownerOn(server);
		let failCard = true;
		const flaky: Pick<Transport, 'readShapeOnce' | 'ingest'> = {
			readShapeOnce: server.transport.readShapeOnce,
			ingest: async (mutations, sign, opts) => {
				if (failCard && JSON.stringify(mutations).includes('"relation":"user_cards"')) {
					failCard = false;
					throw new TypeError('Failed to fetch');
				}
				return server.transport.ingest(mutations, sign, opts);
			},
		};
		const vo = contextOn(server, keys, flaky);
		const first = await createOrigin(vo, { name: 'Cafe' });
		expect(first).toMatchObject({ kind: 'incomplete', completed: ['keys'], failed: 'card', reason: { kind: 'unknown' } });
		const originHash = (first as { originHash: string }).originHash;
		expect(server.tables.get('user_cards')!.has(originHash)).toBe(false);

		const again = contextOn(server, keys);
		const finished = await resumeOrigin(again, originHash, { name: 'Cafe' });
		expect(finished).toMatchObject({ kind: 'created', originHash });
		const slot = await again.storage.readSlot<OriginsSlot>(ORIGINS_SLOT);
		expect(slot.kind === 'found' && Object.keys(slot.value)).toEqual([originHash]);
		expect(await resumeOrigin(again, originHash, { name: 'Cafe' })).toMatchObject({ kind: 'created', originHash });
		expect(ingestsOf(server, 'origins')).toHaveLength(1);
	});

	it('publishes nothing when the keys cannot be stored', async () => {
		const server = createFakePqServer();
		const { keys } = await ownerOn(server);
		const offline: Pick<Transport, 'readShapeOnce' | 'ingest'> = {
			readShapeOnce: async () => { throw new TypeError('Failed to fetch'); },
			ingest: server.transport.ingest,
		};
		const result = await createOrigin(contextOn(server, keys, offline), { name: 'Cafe' });
		expect(result).toMatchObject({ kind: 'incomplete', originHash: null, completed: [], failed: 'keys' });
		expect(server.tables.get('origins')!.size).toBe(0);
		expect(server.tables.get('user_cards')!.size).toBe(1);
	});

	const storageIngest = (path: string, body: Record<string, unknown> | null) => path === '/ingest' && JSON.stringify(body).includes('"relation":"user_storage"');

	it('keys sent but not answered, never committed: the result names V as unknown, nothing is published, and resume says V was never stored', async () => {
		const server = createFakePqServer();
		const { keys } = await ownerOn(server);
		const vo = contextOn(server, keys);
		await vo.storage.patchSlot(ORIGINS_SLOT, {});
		server.fault(storageIngest, 'before-commit');
		const first = await createOrigin(vo, { name: 'Cafe' });
		expect(first).toMatchObject({ kind: 'incomplete', completed: [], failed: 'keys', reason: { kind: 'unknown' } });
		const originHash = (first as { originHash: string | null }).originHash;
		expect(originHash).toMatch(/^u_[0-9a-f]{128}$/);
		expect(server.tables.get('user_cards')!.has(originHash!)).toBe(false);
		expect(server.tables.get('origins')!.size).toBe(0);

		const resumed = await resumeOrigin(contextOn(server, keys), originHash!, { name: 'Cafe' });
		expect(resumed).toMatchObject({ kind: 'incomplete', originHash, completed: [], failed: 'keys', reason: { kind: 'absent' } });
		expect(server.tables.get('user_cards')!.has(originHash!)).toBe(false);
		expect(ingestsOf(server, 'user_cards')).toHaveLength(1);
	});

	it('keys committed but the answer lost: the same V is resumed after a reload, from the hash the caller kept', async () => {
		const server = createFakePqServer();
		const { keys } = await ownerOn(server);
		const vo = contextOn(server, keys);
		await vo.storage.patchSlot(ORIGINS_SLOT, {});
		server.fault(storageIngest, 'after-commit');
		const first = await createOrigin(vo, { name: 'Cafe' });
		expect(first).toMatchObject({ kind: 'incomplete', completed: [], failed: 'keys', reason: { kind: 'unknown' } });
		const originHash = (first as { originHash: string | null }).originHash!;
		expect(originHash).toMatch(/^u_[0-9a-f]{128}$/);
		expect(server.tables.get('origins')!.size).toBe(0);
		expect(server.tables.get('user_cards')!.has(originHash)).toBe(false);

		const afterReload = contextOn(server, keys, createTransport({ baseUrl: 'https://fake.example/electric/v1', fetch: server.fetch }));
		const finished = await resumeOrigin(afterReload, originHash, { name: 'Cafe' });
		expect(finished).toMatchObject({ kind: 'created', originHash });
		expect(ingestsOf(server, 'origins')).toHaveLength(1);
		const slot = await afterReload.storage.readSlot<OriginsSlot>(ORIGINS_SLOT);
		expect(slot.kind === 'found' && Object.keys(slot.value)).toEqual([originHash]);
	});

	it('keys committed but the answer and the hash lost: the unpublished V is found in the origins slot and resumed, not replaced', async () => {
		const server = createFakePqServer();
		const { keys } = await ownerOn(server);
		const vo = contextOn(server, keys);
		await vo.storage.patchSlot(ORIGINS_SLOT, {});
		server.fault(storageIngest, 'after-commit');
		await createOrigin(vo, { name: 'Cafe' });

		const afterReload = contextOn(server, keys);
		const slot = await afterReload.storage.readSlot<OriginsSlot>(ORIGINS_SLOT);
		if (slot.kind !== 'found') throw new Error('expected the origins slot');
		const unpublished: string[] = [];
		for (const hash of Object.keys(slot.value)) if ((await readOrigin(afterReload, hash)).kind === 'absent') unpublished.push(hash);
		expect(unpublished).toHaveLength(1);
		expect(await resumeOrigin(afterReload, unpublished[0], { name: slot.value[unpublished[0]].name })).toMatchObject({ kind: 'created', originHash: unpublished[0] });
		expect(server.tables.get('origins')!.size).toBe(1);
	});

	it('a refused keys write is a definite failure: no origin hash to resume', async () => {
		const server = createFakePqServer();
		const { keys } = await ownerOn(server);
		const refusing: Pick<Transport, 'readShapeOnce' | 'ingest'> = {
			readShapeOnce: server.transport.readShapeOnce,
			ingest: async (mutations, sign, opts) => JSON.stringify(mutations).includes('"relation":"user_storage"')
				? { kind: 'rejected', status: 403, rejection: { kind: 'gate', error: 'not_in_trust_chain', maxDepth: 7 } }
				: server.transport.ingest(mutations, sign, opts),
		};
		const result = await createOrigin(contextOn(server, keys, refusing), { name: 'Cafe' });
		expect(result).toMatchObject({ kind: 'incomplete', originHash: null, failed: 'keys', reason: { kind: 'rejected', rejection: { kind: 'gate' } } });
		expect(server.tables.get('user_cards')!.size).toBe(1);
	});
});

describe('access mode trust', () => {
	const trustedContext = (server: FakePqServer, keys: IdentityKeys) => {
		const owner = openIdentity(keys);
		const sessions = createReadSessions({ transport: server.transport, identity: { userHash: owner.userHash, sign: owner.sign } });
		const ctx: OriginContext = { transport: server.transport, owner, sessions, storage: createUserStorage({ transport: server.transport, owner, sessions }) };
		return { ctx, sessions };
	};

	it('creates, reads, updates and configures a venue with the owner\'s read sessions', async () => {
		const readers = new Set<string>();
		const server = createFakePqServer({ trust: { readers } });
		const { keys, owner } = await ownerOn(server);
		readers.add(owner.userHash);
		const { ctx, sessions } = trustedContext(server, keys);
		const created = await createOrigin(ctx, { name: 'Cafe' });
		if (created.kind !== 'created') throw new Error(`expected created, got ${JSON.stringify(created)}`);
		expect(await readOrigin(ctx, created.originHash)).toMatchObject({ kind: 'found' });
		expect(await updateOrigin(ctx, created.originHash, { name: 'Cafe & Bar' })).toMatchObject({ kind: 'written' });
		expect(await setOriginSetting(ctx, created.originHash, 'review_access', 'invite_only')).toMatchObject({ kind: 'written' });
		const originReads = server.requests.filter((r) => r.path === '/shapes' && r.authorization);
		expect(originReads.length).toBeGreaterThan(0);
		sessions.dispose();
		expect(await readOrigin(ctx, created.originHash)).toMatchObject({ kind: 'unavailable' });
	});

	it('without read sessions a trust-mode server refuses the reads, and nothing past the keys is published', async () => {
		const readers = new Set<string>();
		const server = createFakePqServer({ trust: { readers } });
		const { keys, owner } = await ownerOn(server);
		readers.add(owner.userHash);
		const sessions = createReadSessions({ transport: server.transport, identity: { userHash: owner.userHash, sign: owner.sign } });
		const ctx: OriginContext = { transport: server.transport, owner, storage: createUserStorage({ transport: server.transport, owner, sessions }) };
		const result = await createOrigin(ctx, { name: 'Cafe' });
		expect(result).toMatchObject({ kind: 'incomplete', failed: 'origin', reason: { kind: 'unavailable' } });
		expect(server.tables.get('origins')!.size).toBe(0);
		sessions.dispose();
	});

	it('refuses read sessions or storage of another identity than the owner', async () => {
		const server = createFakePqServer();
		const { keys } = await ownerOn(server);
		const other = openIdentity(generateIdentityKeys());
		const ctx = contextOn(server, keys);
		const foreign = createReadSessions({ transport: server.transport, identity: { userHash: other.userHash, sign: other.sign } });
		await expect(createOrigin({ ...ctx, sessions: foreign }, { name: 'Cafe' })).rejects.toThrow(TypeError);
		await expect(createOrigin({ ...ctx, storage: createUserStorage({ transport: server.transport, owner: other }) }, { name: 'Cafe' })).rejects.toThrow(TypeError);
		foreign.dispose();
	});
});

describe('venue updates and settings', () => {
	const setup = async () => {
		const server = createFakePqServer();
		const { keys } = await ownerOn(server);
		const vo = contextOn(server, keys);
		const created = await createOrigin(vo, { name: 'Cafe' });
		if (created.kind !== 'created') throw new Error('setup');
		return { server, vo, originHash: created.originHash, venue: created.venue };
	};

	it('an update is signed by VO or V and always proved by VO', async () => {
		const { server, vo, originHash, venue } = await setup();
		expect(await updateOrigin(vo, originHash, { name: 'Cafe 2' })).toMatchObject({ kind: 'written', row: { name: 'Cafe 2' } });
		expect(await updateOrigin(vo, originHash, { moderationMode: 'pre' }, { signer: 'venue' })).toMatchObject({ kind: 'written', row: { moderation_mode: 'pre', name: 'Cafe 2' } });
		expect(server.tables.get('origins')!.get(originHash)).toMatchObject({ name: 'Cafe 2', moderation_mode: 'pre' });

		const current = server.tables.get('origins')!.get(originHash)!;
		const byVenueProof = venue.signRow('origins', { ...current, name: 'Proved by V', owner_timestamp: Number(current.owner_timestamp) + 10 });
		const refused = await server.transport.ingest([rowMutation('origins', byVenueProof, 'update')], venue.sign);
		expect(refused).toMatchObject({ kind: 'rejected', rejection: { kind: 'rejected', error: 'Invalid operation' } });
	});

	it('reports a refusal while reviews await moderation, and rejects a moderation mode the server does not know', async () => {
		const { server, vo, originHash } = await setup();
		server.pendingReviews.add(originHash);
		expect(await updateOrigin(vo, originHash, { name: 'x' })).toEqual({ kind: 'pending_moderation' });
		await expect(updateOrigin(vo, originHash, { moderationMode: 'strict' as never })).rejects.toThrow(/moderation_mode/);
		const venue = openIdentity(generateIdentityKeys());
		expect(() => originRow(venue, vo.owner, { name: 'x', moderationMode: 'strict' as never, ownerTimestamp: 1 })).toThrow(/moderation_mode/);
	});

	it('settings: created by V, changed by VO or V, checked as the server checks them, removed as a tombstone', async () => {
		const { server, vo, originHash } = await setup();
		await expect(setOriginSetting(vo, originHash, 'review_access', 'everyone')).rejects.toBeInstanceOf(OriginSettingError);
		await expect(setOriginSetting(vo, originHash, 'review_token_ttl_days', '400')).rejects.toBeInstanceOf(OriginSettingError);
		await expect(setOriginSetting(vo, originHash, 'review_token_ttl_days', '7', { signer: 'owner', prover: 'owner' })).rejects.toThrow(/signed by the origin/);

		expect(await setOriginSetting(vo, originHash, 'review_token_ttl_days', '7')).toMatchObject({ kind: 'written' });
		expect(await setOriginSetting(vo, originHash, 'review_token_ttl_days', '30', { signer: 'owner', prover: 'owner' })).toMatchObject({ kind: 'written', row: { value: '30' } });
		expect(await removeOriginSetting(vo, originHash, 'review_token_ttl_days', '30')).toMatchObject({ kind: 'written', row: { deleted_flag: true } });
		expect(server.tables.get('origin_settings')!.get(`${originHash}|review_token_ttl_days`)).toMatchObject({ value: '30', deleted_flag: true });
	});

	it('a venue row with a forged owner certificate or another signer does not verify', async () => {
		const { server, vo, originHash } = await setup();
		const row = server.tables.get('origins')!.get(originHash)!;
		const venuePkey = String(server.tables.get('user_cards')!.get(originHash)!.sign_pkey);
		const stranger = openIdentity(generateIdentityKeys());
		expect(verifyOriginRow({ ...row, owner_cert: toBase64(stranger.sign(new Uint8Array([1]))) }, { venueSignPkey: venuePkey, ownerSignPkey: vo.owner.signPkey }))
			.toEqual({ status: 'invalid', reason: 'bad_owner_cert' });
		const resigned = stranger.signRow('origins', { ...row });
		expect(verifyOriginRow(resigned, { venueSignPkey: venuePkey, ownerSignPkey: vo.owner.signPkey })).toMatchObject({ status: 'invalid', reason: 'bad_signature' });
	});
});
