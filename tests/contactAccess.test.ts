import { describe, expect, it } from 'vitest';
import {
	classifySlotPrior,
	contactAccessView,
	contactsPriorOf,
	initialAccessDecision,
	verifyContactConfirmation,
	type ContactAccessSnapshot,
} from '@buckitup/pq-client/contactAccess';
import type { IdentityHandle } from '@buckitup/pq-client/identity';
import { storageScope } from '@buckitup/pq-client/vouch';
import { verifyRow } from '@buckitup/pq-client/rows';
import { createWorld, DEVICE, freeze, type World } from './helpers/contactAccessHarness';

const READ = storageScope(DEVICE, 'read');
const WRITE = storageScope(DEVICE, 'write');
const OTHER_DEVICE = 'Other_test_node';

const flags = (world: World, issuer: IdentityHandle, subject: IdentityHandle) =>
	[READ, WRITE].map((kind) => world.vouch(kind, issuer, subject)?.deleted_flag);

const ownerAndBob = async () => {
	const world = createWorld();
	const owner = await world.identity('Owner');
	const bob = await world.identity('Bob');
	world.device.current = { deviceId: DEVICE, adminHash: owner.userHash };
	return { world, owner, bob };
};

const confirmation = (world: World, subject: IdentityHandle) => {
	const card = world.server.tables.get('user_cards')!.get(subject.userHash) as never;
	const contactPkey = String((card as { contact_pkey: string }).contact_pkey);
	return { card, contactPkey, verdict: verifyContactConfirmation(card, subject.userHash, contactPkey) };
};

const granted = async (world: World, owner: IdentityHandle, bob: IdentityHandle) => {
	const { contactPkey, verdict } = confirmation(world, bob);
	const decision = await world.service().afterConfirmation(world.session(owner), {
		confirmation: verdict, prior: { state: 'new' }, subjectHash: bob.userHash, contactPkey,
	});
	expect(decision).toMatchObject({ grant: true, result: 'resolved' });
	expect(flags(world, owner, bob)).toEqual([false, false]);
	return contactPkey;
};

describe('initial access after a QR confirmation', () => {
	const ok = { ok: true } as const;
	const subjectHash = 'u_' + 'b'.repeat(128);

	it('is decided by the verified card and the contacts list the confirmation was written over', () => {
		expect(initialAccessDecision({ confirmation: { ok: false, why: 'another-key' }, prior: { state: 'new' }, subjectHash, contactPkey: 'pk' }))
			.toEqual({ grant: false, reason: 'not-verified' });
		expect(initialAccessDecision({ confirmation: ok, prior: { state: 'new' }, subjectHash, contactPkey: 'pk' })).toEqual({ grant: true });
		expect(initialAccessDecision({ confirmation: ok, prior: { state: 'readable', contacts: {} }, subjectHash, contactPkey: 'pk' })).toEqual({ grant: true });
		expect(initialAccessDecision({ confirmation: ok, prior: { state: 'readable', contacts: { [subjectHash]: { contact_pkey: 'pk' } } }, subjectHash, contactPkey: 'pk' }))
			.toEqual({ grant: true });
		expect(initialAccessDecision({ confirmation: ok, prior: { state: 'readable', contacts: { [subjectHash]: { confirmed: true, contact_pkey: 'old' } } }, subjectHash, contactPkey: 'pk' }))
			.toEqual({ grant: true });
		expect(initialAccessDecision({ confirmation: ok, prior: { state: 'readable', contacts: { [subjectHash]: { confirmed: true, contact_pkey: 'pk' } } }, subjectHash, contactPkey: 'pk' }))
			.toEqual({ grant: false, reason: 'already-confirmed' });
	});

	it('never takes an unknown or malformed prior list for an empty one', () => {
		for (const prior of [undefined, null, {}, { state: 'unknown' }, { state: 'readable' }, { state: 'readable', contacts: null }, { previous: {} }]) {
			expect(initialAccessDecision({ confirmation: ok, prior, subjectHash, contactPkey: 'pk' })).toEqual({ grant: false, reason: 'unknown-prior' });
		}
	});

	it('a malformed record, list or entry never authorizes a grant; well-formed ones still decide as before', () => {
		const decide = (base: unknown, createdByThisWrite = false) => initialAccessDecision({
			confirmation: ok, prior: contactsPriorOf(classifySlotPrior({ base, createdByThisWrite })), subjectHash, contactPkey: 'pk',
		});
		const unknown = { grant: false, reason: 'unknown-prior' };
		for (const base of ['text', 7, true, [], ['x'], { contacts: 'x' }, { contacts: [] }, { contacts: [{ confirmed: true }] }, { contacts: null }, { contacts: 5 },
			{ contacts: { other: 'x' } }, { contacts: { other: [] } }, { contacts: { [subjectHash]: null } }, { contacts: { [subjectHash]: 'confirmed' } },
			{ contacts: { [subjectHash]: { confirmed: 'true', contact_pkey: 'pk' } } }, { contacts: { [subjectHash]: { confirmed: true, contact_pkey: 7 } } },
			{ contacts: { [subjectHash]: { confirmed: true } } }, { contacts: Object.assign(Object.create({ inherited: true }), {}) }]) {
			expect(decide(base), JSON.stringify(base)).toEqual(unknown);
		}
		expect(decide(null, true)).toEqual({ grant: true });
		expect(decide({})).toEqual({ grant: true });
		expect(decide({ contacts: {} })).toEqual({ grant: true });
		expect(decide({ contacts: { other: { confirmed: true, contact_pkey: 'pk' } } })).toEqual({ grant: true });
		expect(decide({ contacts: { [subjectHash]: { name: 'Added by id', contact_pkey: 'pk' } } })).toEqual({ grant: true });
		expect(decide({ contacts: { [subjectHash]: { confirmed: false } } })).toEqual({ grant: true });
		expect(decide({ contacts: { [subjectHash]: { confirmed: true, contact_pkey: 'pk' } } })).toEqual({ grant: false, reason: 'already-confirmed' });
		expect(contactsPriorOf({ state: 'readable', value: {} })).toEqual({ state: 'readable', contacts: {} });
	});

	it('validates a prior passed straight to the decision, not only one built by contactsPriorOf', () => {
		for (const prior of [{ state: 'readable', contacts: [] }, { state: 'readable', contacts: 'x' }, { state: 'readable', contacts: { [subjectHash]: [] } }, ['new'], 'new']) {
			expect(initialAccessDecision({ confirmation: ok, prior, subjectHash, contactPkey: 'pk' }), JSON.stringify(prior)).toEqual({ grant: false, reason: 'unknown-prior' });
		}
	});

	it('a slot a write created is known empty; an existing slot with no readable row is unknown', () => {
		expect(classifySlotPrior({ base: { contacts: { a: 1 } }, createdByThisWrite: false })).toEqual({ state: 'readable', value: { contacts: { a: 1 } } });
		expect(classifySlotPrior({ base: null, createdByThisWrite: true })).toEqual({ state: 'new' });
		expect(classifySlotPrior({ base: null, createdByThisWrite: false })).toEqual({ state: 'unknown' });
		expect(contactsPriorOf({ state: 'readable', value: { contacts: { a: { confirmed: true } } } })).toEqual({ state: 'readable', contacts: { a: { confirmed: true } } });
		expect(contactsPriorOf({ state: 'readable', value: {} })).toEqual({ state: 'readable', contacts: {} });
		expect(contactsPriorOf({ state: 'unknown' })).toEqual({ state: 'unknown' });
	});

	it('a first confirmation publishes both scopes, signed by the issuer, confirmed through the rows', async () => {
		const { world, owner, bob } = await ownerAndBob();
		await granted(world, owner, bob);
		for (const kind of [READ, WRITE]) {
			const row = world.vouch(kind, owner, bob)!;
			expect(verifyRow('vouch_tokens', row, owner.signPkey).status).toBe('ok');
		}
		expect(world.open(owner.userHash)).toEqual([]);
		expect(world.resolved(owner.userHash).map((r) => r.outcome)).toEqual(['applied']);
	});

	it('a malformed stored list after a revoke restores nothing, while the first confirmation over a valid list granted', async () => {
		const { world, owner, bob } = await ownerAndBob();
		const { contactPkey, verdict } = confirmation(world, bob);
		const service = world.service();
		const first = await service.afterConfirmation(world.session(owner), {
			confirmation: verdict, prior: contactsPriorOf(classifySlotPrior({ base: { contacts: {} }, createdByThisWrite: false })), subjectHash: bob.userHash, contactPkey,
		});
		expect(first).toMatchObject({ grant: true, result: 'resolved' });
		expect(await service.request(world.session(owner), bob.userHash, false, DEVICE)).toBe('resolved');
		const before = world.server.requests.length;

		for (const base of [{ contacts: [] }, { contacts: 'x' }, [{ contacts: {} }], { contacts: { [bob.userHash]: { confirmed: 'yes', contact_pkey: contactPkey } } }]) {
			const decision = await service.afterConfirmation(world.session(owner), {
				confirmation: verdict, prior: contactsPriorOf(classifySlotPrior({ base, createdByThisWrite: false })), subjectHash: bob.userHash, contactPkey,
			});
			expect(decision).toEqual({ grant: false, reason: 'unknown-prior' });
		}
		expect(world.server.requests.slice(before).filter((r) => r.path.includes('ingest'))).toEqual([]);
		expect(flags(world, owner, bob)).toEqual([true, true]);
	});

	it('a confirmation over a list that already confirmed the key restores nothing after a revoke', async () => {
		const { world, owner, bob } = await ownerAndBob();
		const contactPkey = await granted(world, owner, bob);
		const service = world.service();
		expect(await service.request(world.session(owner), bob.userHash, false, DEVICE)).toBe('resolved');
		expect(flags(world, owner, bob)).toEqual([true, true]);
		const before = world.server.requests.length;

		const decision = await service.afterConfirmation(world.session(owner), {
			confirmation: confirmation(world, bob).verdict,
			prior: { state: 'readable', contacts: { [bob.userHash]: { confirmed: true, contact_pkey: contactPkey } } },
			subjectHash: bob.userHash, contactPkey,
		});
		expect(decision).toEqual({ grant: false, reason: 'already-confirmed' });
		const unknown = await service.afterConfirmation(world.session(owner), { confirmation: confirmation(world, bob).verdict, prior: { state: 'unknown' }, subjectHash: bob.userHash, contactPkey });
		expect(unknown).toEqual({ grant: false, reason: 'unknown-prior' });
		expect(world.server.requests.slice(before).filter((r) => r.path.includes('ingest'))).toEqual([]);
		expect(flags(world, owner, bob)).toEqual([true, true]);
	});
});

describe('explicit grant and revoke', () => {
	it('revoke tombstones both scopes above the grants; regrant restores them above the tombstones', async () => {
		const { world, owner, bob } = await ownerAndBob();
		await granted(world, owner, bob);
		const grants = [READ, WRITE].map((k) => Number(world.vouch(k, owner, bob)!.owner_timestamp));
		const service = world.service();

		expect(await service.request(world.session(owner), bob.userHash, false, DEVICE)).toBe('resolved');
		const tombstones = [READ, WRITE].map((k) => Number(world.vouch(k, owner, bob)!.owner_timestamp));
		expect(flags(world, owner, bob)).toEqual([true, true]);
		tombstones.forEach((t, i) => expect(t).toBeGreaterThan(grants[i]));

		expect(await service.request(world.session(owner), bob.userHash, true, DEVICE)).toBe('resolved');
		expect(flags(world, owner, bob)).toEqual([false, false]);
		[READ, WRITE].forEach((k, i) => expect(Number(world.vouch(k, owner, bob)!.owner_timestamp)).toBeGreaterThan(tombstones[i]));
		expect(world.server.tables.get('vouch_tokens')!.size).toBe(2);
	});

	it('changes only the issuer\'s own rows; another issuer\'s grant to the contact stays', async () => {
		const { world, owner, bob } = await ownerAndBob();
		const carol = await world.identity('Carol');
		await granted(world, owner, bob);
		world.device.current = { deviceId: DEVICE, adminHash: carol.userHash };
		await granted(world, carol, bob);
		const carols = () => [READ, WRITE].map((k) => ({ ...world.vouch(k, carol, bob)! }));
		const before = carols();

		world.device.current = { deviceId: DEVICE, adminHash: owner.userHash };
		expect(await world.service().request(world.session(owner), bob.userHash, false, DEVICE)).toBe('resolved');
		expect(flags(world, owner, bob)).toEqual([true, true]);
		expect(carols()).toEqual(before);
	});

	it('an issuer that holds no access on the device is not allowed to grant, and nothing is sent', async () => {
		const { world, owner, bob } = await ownerAndBob();
		const stranger = await world.identity('Stranger');
		world.device.current = { deviceId: DEVICE, adminHash: stranger.userHash };
		const service = world.service();
		expect(await service.issuerMayGrant(owner.userHash, world.device.current)).toBe(false);

		expect(await service.request(world.session(owner), bob.userHash, true, DEVICE)).toBe('resolved');
		expect(world.resolved(owner.userHash).map((r) => r.outcome)).toEqual(['skipped:not-vouched']);
		expect(world.server.tables.get('vouch_tokens')!.size).toBe(0);
		const view = contactAccessView(await service.snapshot(owner.userHash, bob.userHash));
		expect(view).toMatchObject({ confirmed: 'not-granted', canChange: false, notice: 'cannot-grant' });
	});
});

describe('a request is complete only when the verified rows show it', () => {
	it('server acceptance with a stale shape stays pending, and resolves once the rows are served', async () => {
		const { world, owner, bob } = await ownerAndBob();
		await granted(world, owner, bob);
		freeze(world);
		const service = world.service();

		expect(await service.request(world.session(owner), bob.userHash, false, DEVICE)).toBe('retry');
		expect(flags(world, owner, bob)).toEqual([true, true]);
		expect(world.open(owner.userHash)).toHaveLength(1);
		expect(contactAccessView(await service.snapshot(owner.userHash, bob.userHash)))
			.toMatchObject({ confirmed: 'granted', pending: { granted: false }, canChange: false });

		world.shape.frozen = null;
		await world.settle(owner);
		expect(world.open(owner.userHash)).toEqual([]);
		expect(contactAccessView(await service.snapshot(owner.userHash, bob.userHash))).toMatchObject({ confirmed: 'revoked', pending: null, canChange: true });
	});

	it('a missing row is not a confirmed tombstone of a revoke this request sent', async () => {
		const { world, owner, bob } = await ownerAndBob();
		await granted(world, owner, bob);
		freeze(world);
		expect(await world.service().request(world.session(owner), bob.userHash, false, DEVICE)).toBe('retry');
		world.shape.frozen = new Map();
		await world.settle(owner);
		expect(world.open(owner.userHash)).toHaveLength(1);
		world.shape.frozen = null;
		await world.settle(owner);
		expect(world.open(owner.userHash)).toEqual([]);
	});

	it('one scope confirmed and the other failing stays pending and partial, and survives a reload', async () => {
		const { world, owner, bob } = await ownerAndBob();
		await granted(world, owner, bob);
		let writeDown = true;
		world.ingest.down = (write) => write.row.kind === WRITE && writeDown;

		expect(await world.service().request(world.session(owner), bob.userHash, false, DEVICE)).toBe('retry');
		expect(flags(world, owner, bob)).toEqual([true, false]);
		await world.settle(owner);
		const reloaded = world.service();
		expect(contactAccessView(await reloaded.snapshot(owner.userHash, bob.userHash)))
			.toMatchObject({ confirmed: 'partial', partialScope: 'write', pending: { granted: false } });

		writeDown = false;
		await world.settle(owner);
		expect(flags(world, owner, bob)).toEqual([true, true]);
		expect(contactAccessView(await reloaded.snapshot(owner.userHash, bob.userHash))).toMatchObject({ confirmed: 'revoked', pending: null });
	});

	it('a row that does not verify is shown as unknown, and its scope is not built on', async () => {
		const { world, owner, bob } = await ownerAndBob();
		await granted(world, owner, bob);
		const rows = world.server.tables.get('vouch_tokens')!;
		const key = `${READ}|${owner.userHash}|${bob.userHash}`;
		rows.set(key, { ...rows.get(key)!, deleted_flag: true });
		const service = world.service();
		expect(contactAccessView(await service.snapshot(owner.userHash, bob.userHash))).toMatchObject({ confirmed: 'unknown', canChange: false, notice: 'unverified' });
		expect(await service.request(world.session(owner), bob.userHash, false, DEVICE)).toBe('retry');
		expect(world.open(owner.userHash)).toHaveLength(1);
	});

	it('an account switch before the rows are signed sends nothing', async () => {
		const { world, owner, bob } = await ownerAndBob();
		await granted(world, owner, bob);
		const before = world.server.tables.get('vouch_tokens')!.size;
		let current = true;
		const session = world.session(owner, () => current);
		current = false;
		expect(await world.service().request(session, bob.userHash, false, DEVICE)).toBe('retry');
		expect(flags(world, owner, bob)).toEqual([false, false]);
		expect(world.server.tables.get('vouch_tokens')!.size).toBe(before);
		expect(world.durable.outbox.size).toBe(0);
	});
});

describe('requests are queued per issuer, device and contact', () => {
	it('a request for another device is not applied here and does not cancel this device\'s request', async () => {
		const { world, owner, bob } = await ownerAndBob();
		await granted(world, owner, bob);
		world.shape.down = true;
		const service = world.service();
		expect(await service.request(world.session(owner), bob.userHash, false, DEVICE)).toBe('retry');
		expect(await service.request(world.session(owner), bob.userHash, true, OTHER_DEVICE)).toBe('resolved');
		expect(world.resolved(owner.userHash).map((r) => r.outcome)).toContain('skipped:device-changed');
		expect(world.open(owner.userHash).map((e) => (e.intent as { deviceId: string }).deviceId)).toEqual([DEVICE]);

		world.shape.down = false;
		await world.settle(owner);
		expect(flags(world, owner, bob)).toEqual([true, true]);
		expect([...world.server.tables.get('vouch_tokens')!.values()].some((r) => String(r.kind).includes(OTHER_DEVICE))).toBe(false);
	});

	it('a request made for one device signs nothing when the backend answers as another', async () => {
		const { world, owner, bob } = await ownerAndBob();
		await granted(world, owner, bob);
		world.shape.down = true;
		expect(await world.service().request(world.session(owner), bob.userHash, false, DEVICE)).toBe('retry');
		world.device.current = { deviceId: OTHER_DEVICE, adminHash: owner.userHash };
		world.shape.down = false;
		await world.settle(owner);
		expect(world.resolved(owner.userHash).map((r) => r.outcome)).toContain('skipped:device-changed');
		expect(flags(world, owner, bob)).toEqual([false, false]);
		expect([...world.server.tables.get('vouch_tokens')!.values()].some((r) => String(r.kind).includes(OTHER_DEVICE))).toBe(false);
	});

	it('a device that changes between the queue check and the signing signs nothing', async () => {
		const { world, owner, bob } = await ownerAndBob();
		world.device.answers = [{ deviceId: DEVICE, adminHash: owner.userHash }, { deviceId: OTHER_DEVICE, adminHash: owner.userHash }];
		expect(await world.service().request(world.session(owner), bob.userHash, true, DEVICE)).toBe('resolved');
		expect(world.resolved(owner.userHash).map((r) => r.outcome)).toEqual(['skipped:device-changed']);
		expect(world.server.tables.get('vouch_tokens')!.size).toBe(0);
		expect(world.durable.outbox.size).toBe(0);
	});

	it('a request stored without a device binds to the answering device before anything is signed', async () => {
		const { world, owner, bob } = await ownerAndBob();
		const service = world.service();
		world.durable.intents.set('legacy', { id: 'legacy', issuerHash: owner.userHash, createdAt: 1, intent: { kind: 'contact-access', subjectHash: bob.userHash, granted: true } });
		expect(await service.apply({ id: 'legacy', createdAt: 1, intent: world.durable.intents.get('legacy')!.intent }, world.session(owner))).toBe('resolved');
		expect(world.resolved(owner.userHash)).toEqual([{ resolved: true, outcome: 'applied', purpose: `contact-access|${DEVICE}|${bob.userHash}|grant` }]);
		expect(flags(world, owner, bob)).toEqual([false, false]);
	});

	it('a newer request for the same device supersedes an older one; it never reaches across devices', async () => {
		const { world, owner, bob } = await ownerAndBob();
		const intent = (deviceId: string | undefined, granted: boolean) => ({ kind: 'contact-access', subjectHash: bob.userHash, granted, ...(deviceId ? { deviceId } : {}) });
		world.durable.intents.set('a', { id: 'a', issuerHash: owner.userHash, createdAt: 1, intent: intent(DEVICE, true) });
		world.durable.intents.set('b', { id: 'b', issuerHash: owner.userHash, createdAt: 2, intent: intent(OTHER_DEVICE, false) });
		const service = world.service();
		expect(await service.apply({ id: 'a', createdAt: 1, intent: intent(DEVICE, true) }, world.session(owner))).toBe('resolved');
		expect(world.durable.intents.get('a')!.intent).toMatchObject({ resolved: true, outcome: 'applied' });

		world.durable.intents.set('c', { id: 'c', issuerHash: owner.userHash, createdAt: 3, intent: intent(DEVICE, true) });
		world.durable.intents.set('d', { id: 'd', issuerHash: owner.userHash, createdAt: 4, intent: intent(undefined, false) });
		expect(await service.apply({ id: 'c', createdAt: 3, intent: intent(DEVICE, true) }, world.session(owner))).toBe('resolved');
		expect(world.durable.intents.get('c')!.intent).toMatchObject({ resolved: true, outcome: 'superseded' });
	});
});

describe('the view a client renders', () => {
	const snapshot = (over: Partial<ContactAccessSnapshot>): ContactAccessSnapshot => ({
		issuerHash: 'i', subjectHash: 's', identity: { deviceId: DEVICE, adminHash: 'i' },
		scopes: { read: 'granted', write: 'granted' }, requests: { pending: null, last: null }, mayGrant: true, ...over,
	});

	it('shows confirmed state apart from the request in flight, and blocks the switch while one is', () => {
		expect(contactAccessView(null)).toMatchObject({ loading: true, canChange: false });
		expect(contactAccessView(snapshot({}))).toMatchObject({ confirmed: 'granted', switchOn: true, canChange: true, notice: null });
		expect(contactAccessView(snapshot({}), { submitting: { granted: false } })).toMatchObject({ confirmed: 'granted', pending: { granted: false }, switchOn: false, canChange: false });
		expect(contactAccessView(snapshot({ scopes: { read: 'absent', write: 'absent' } }))).toMatchObject({ confirmed: 'not-granted', switchOn: false });
		expect(contactAccessView(snapshot({ scopes: { read: 'revoked', write: 'absent' } }))).toMatchObject({ confirmed: 'not-granted' });
		expect(contactAccessView(snapshot({ scopes: null }))).toMatchObject({ confirmed: 'unavailable', canChange: false, notice: 'unavailable' });
		expect(contactAccessView(snapshot({ identity: { deviceId: DEVICE, adminHash: null }, scopes: { read: 'absent', write: 'absent' } }))).toMatchObject({ canChange: false, notice: 'no-owner' });
		expect(contactAccessView(snapshot({ mayGrant: false }))).toMatchObject({ confirmed: 'granted', inEffect: false, canChange: true, notice: 'grant-not-in-effect' });
		expect(contactAccessView(snapshot({ scopes: { read: 'revoked', write: 'revoked' }, requests: { pending: null, last: { granted: true, outcome: 'skipped:not-vouched' } } })))
			.toMatchObject({ confirmed: 'revoked', notice: 'last:skipped:not-vouched' });
	});
});
