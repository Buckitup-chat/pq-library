import assert from 'node:assert/strict';
import { generateIdentityKeys, openIdentity, verifyUserCard, type IdentityHandle } from '@buckitup/pq-client/identity';
import { createPrfVault, openVaultIdentity, type PrfVault } from '@buckitup/pq-client/vault';
import { rowMutation, signRow, verifyRow, type OriginRow, type SignedRow } from '@buckitup/pq-client/rows';
import { classifyRowResult, createReadSessions, createTransport, subscribeShape, type Transport } from '@buckitup/pq-client/transport';
import { buildDialogKeyRow, buildMessageRow, dialogHash, openMessageRow } from '@buckitup/pq-client/dialogs';
import { createOrigin, originRow, verifyOriginRow, type CreateOrigin } from '@buckitup/pq-client/origins';
import { issueVouch, storageScope, vouchRow, type VouchWrite } from '@buckitup/pq-client/vouch';
import { createUserStorage, deriveStorageKey, mergeJson, openJson, sealJson } from '@buckitup/pq-client/storage';
import {
	contactAccessView,
	createContactAccess,
	initialAccessDecision,
	verifyContactConfirmation,
	verifyVouchRowWith,
	type ContactAccessIntent,
	type StoredContactAccessIntent,
	type ContactAccessWrite,
} from '@buckitup/pq-client/contactAccess';

const MODULES = ['identity', 'vault', 'rows', 'transport', 'dialogs', 'origins', 'vouch', 'storage', 'contactAccess'];

const typesOnly = (transport: Transport, me: IdentityHandle) => {
	const signed: SignedRow<OriginRow> = signRow('origins', {} as OriginRow, new Uint8Array());
	const signB64: string = signed.sign_b64;
	const sessions = createReadSessions({ transport, identity: { userHash: me.userHash, sign: me.sign } });
	const storage = createUserStorage({ transport, owner: me });
	const created: Promise<CreateOrigin> = createOrigin({ transport, owner: me, storage }, { name: 'Cafe' });
	const vouched: Promise<VouchWrite> = issueVouch({ transport, issuer: me }, storageScope('Server_x', 'write'), me.userHash);
	const vault: Promise<{ vault: PrfVault }> = createPrfVault({ name: 'x', credentials: navigator.credentials, rpId: 'example.invalid' });
	const handle: Promise<IdentityHandle> = vault.then(({ vault: v }) => openVaultIdentity(v));
	return [signB64, sessions, subscribeShape(transport, { table: 'user_cards', sessions }), created, vouched, handle];
};

const main = async () => {
	for (const name of MODULES) {
		const mod = (await import(`@buckitup/pq-client/${name}`)) as Record<string, unknown>;
		assert.ok(Object.keys(mod).length > 0, `${name} exports nothing`);
		const resolved = import.meta.resolve(`@buckitup/pq-client/${name}`);
		assert.ok(resolved.includes('/node_modules/@buckitup/pq-client/dist/'), `${name} resolved to ${resolved}`);
		console.log(`import @buckitup/pq-client/${name}: ${Object.keys(mod).length} exports`);
	}
	assert.equal((globalThis as { sodium?: unknown }).sodium, undefined);
	assert.equal(typeof typesOnly, 'function');

	const ann = openIdentity(generateIdentityKeys());
	const bob = openIdentity(generateIdentityKeys());
	const card = ann.userCard({ name: 'Ann', ownerTimestamp: 1 });
	assert.equal(verifyUserCard(card).status, 'verified');
	assert.equal(rowMutation('user_cards', card).type, 'insert');

	const keyRow = ann.signRow('dialog_keys', await buildDialogKeyRow({
		senderHash: ann.userHash, peerHash: bob.userHash, senderMsgKey: ann.senderMsgKey(bob.userHash), peerCryptPkey: bob.cryptPkey, ownerTimestamp: 2,
	}));
	const message = ann.signRow('dialog_messages', await buildMessageRow(ann.senderMsgKey(bob.userHash), {
		senderHash: ann.userHash, dialogHash: dialogHash(ann.userHash, bob.userHash), parts: [{ kind: 'text', text: 'hello' }], refs: {}, ownerTimestamp: 3,
	}));
	assert.equal(verifyRow('dialog_keys', keyRow, ann.signPkey).status, 'ok');
	const opened = await openMessageRow(message, { senderSignPkey: ann.signPkey, senderMsgKey: await bob.unwrapPeerKey(keyRow) });
	assert.deepEqual(opened.status === 'ok' ? opened.parts : null, [{ kind: 'text', text: 'hello' }]);

	const key = await deriveStorageKey(ann.exportKeys().cryptSkey);
	assert.deepEqual(await openJson(key, await sealJson(key, { a: 1 })), { a: 1 });
	assert.deepEqual(mergeJson({ a: 1 }, { a: null, b: 2 }), { b: 2 });

	const row = vouchRow({ kind: storageScope('Server_x', 'write', 'dialog_messages'), issuerHash: ann.userHash, subjectHash: bob.userHash }, { granted: true, ownerTimestamp: 4 });
	assert.equal(row.deleted_flag, false);

	const venue = openIdentity(generateIdentityKeys());
	const origin = venue.signRow('origins', originRow(venue, ann, { name: 'Cafe', ownerTimestamp: 5 }));
	assert.deepEqual(verifyOriginRow(origin, { venueSignPkey: venue.signPkey, ownerSignPkey: ann.signPkey }), { status: 'ok', signer: 'venue' });

	const gate = classifyRowResult({ index: 0, status: 'error', error: 'not_in_trust_chain' });
	assert.equal(gate.kind === 'rejected' ? gate.rejection.kind : null, 'gate');
	assert.equal(typeof createTransport({ baseUrl: 'https://example.invalid/electric/v1' }).ingest, 'function');
	await contactAccessSmoke(ann, bob);
	console.log('functional smoke: ok');
};

const contactAccessSmoke = async (owner: IdentityHandle, peer: IdentityHandle) => {
	const device = 'Server_x';
	const rows = new Map<string, Record<string, unknown>>();
	let served: Map<string, Record<string, unknown>> | null = null;
	const intents = new Map<string, StoredContactAccessIntent>();
	let sequence = 0;
	const ownerCard = owner.userCard({ name: 'Owner', ownerTimestamp: 1 });
	const access = createContactAccess({
		readDeviceIdentity: async () => ({ deviceId: device, adminHash: owner.userHash }),
		readVouchRows: async ({ subjectHash }) => ({ kind: 'rows', rows: [...(served ?? rows).values()].filter((r) => r.subject_hash === subjectHash) }),
		verifyVouchRow: verifyVouchRowWith(async (userHash) => (userHash === owner.userHash ? String(ownerCard.sign_pkey) : null)),
		intents: {
			list: async (_issuer, { includeResolved }) => [...intents.values()].filter((e) => includeResolved || !(e.intent as { resolved?: boolean }).resolved),
			get: async (id) => intents.get(id) ?? null,
			enqueue: async (_issuer, intent) => {
				const id = `i${++sequence}`;
				intents.set(id, { id, createdAt: sequence, intent });
				return id;
			},
			update: async (id, intent) => (intents.set(id, { ...intents.get(id)!, intent }), true),
			resolve: async (id, outcome) => {
				const e = intents.get(id)!;
				intents.set(id, { ...e, intent: { resolved: true, outcome, purpose: (e.intent as ContactAccessIntent).purpose } });
				return true;
			},
		},
		outbox: {
			send: async (write: ContactAccessWrite) => {
				rows.set(`${write.row.kind}|${write.row.issuer_hash}|${write.row.subject_hash}`, { ...write.row });
				return { kind: 'accepted', outboxId: `o${++sequence}` };
			},
			queued: async () => [],
			refused: async () => [],
			discard: async () => {},
		},
		lock: async (_key, work) => work(),
	});
	const session = { issuerHash: owner.userHash, signingKey: async () => owner.exportKeys().signSkey, stillCurrent: () => true };
	const peerCard = peer.userCard({ name: 'Peer', ownerTimestamp: 1 });
	const peerKey = peerCard.contact_pkey;
	assert.ok(peerKey);
	const confirmation = verifyContactConfirmation(peerCard, peer.userHash, peerKey);
	assert.equal(confirmation.ok, true);

	const first = await access.afterConfirmation(session, { confirmation, prior: { state: 'new' }, subjectHash: peer.userHash, contactPkey: peerKey });
	assert.deepEqual(first, { grant: true, result: 'resolved' });
	assert.equal(contactAccessView(await access.snapshot(owner.userHash, peer.userHash)).confirmed, 'granted');

	assert.equal(await access.request(session, peer.userHash, false, device), 'resolved');
	assert.equal(contactAccessView(await access.snapshot(owner.userHash, peer.userHash)).confirmed, 'revoked');
	const again = initialAccessDecision({
		confirmation, subjectHash: peer.userHash, contactPkey: peerKey,
		prior: { state: 'readable', contacts: { [peer.userHash]: { confirmed: true, contact_pkey: peerKey } } },
	});
	assert.deepEqual(again, { grant: false, reason: 'already-confirmed' });
	assert.deepEqual(initialAccessDecision({ confirmation, prior: { state: 'unknown' }, subjectHash: peer.userHash, contactPkey: peerKey }), { grant: false, reason: 'unknown-prior' });

	served = new Map([...rows].map(([k, v]) => [k, { ...v }]));
	assert.equal(await access.request(session, peer.userHash, true, device), 'retry');
	assert.deepEqual(contactAccessView(await access.snapshot(owner.userHash, peer.userHash)).pending, { granted: true });
	served = null;
	for (const entry of [...intents.values()]) await access.apply(entry, session);
	const view = contactAccessView(await access.snapshot(owner.userHash, peer.userHash));
	assert.equal(view.confirmed, 'granted');
	assert.equal(view.pending, null);
	console.log('contact access: ok');
};

await main();
