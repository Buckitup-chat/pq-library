import assert from 'node:assert/strict';
import { generateIdentityKeys, openIdentity, verifyUserCard, type IdentityHandle } from '@buckitup/pq-client/identity';
import { createPrfVault, openVaultIdentity, type PrfVault } from '@buckitup/pq-client/vault';
import { rowMutation, signRow, verifyRow, type OriginRow, type SignedRow } from '@buckitup/pq-client/rows';
import { classifyRowResult, createReadSessions, createTransport, subscribeShape, type Transport } from '@buckitup/pq-client/transport';
import { buildDialogKeyRow, buildMessageRow, dialogHash, openMessageRow } from '@buckitup/pq-client/dialogs';
import { createOrigin, originRow, verifyOriginRow, type CreateOrigin } from '@buckitup/pq-client/origins';
import { issueVouch, storageScope, vouchRow, type VouchWrite } from '@buckitup/pq-client/vouch';
import { createUserStorage, deriveStorageKey, mergeJson, openJson, sealJson } from '@buckitup/pq-client/storage';

const MODULES = ['identity', 'vault', 'rows', 'transport', 'dialogs', 'origins', 'vouch', 'storage'];

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
	console.log('functional smoke: ok');
};

await main();
