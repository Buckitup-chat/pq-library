import { describe, it, expect } from 'vitest';
import { sha3_256 } from '@noble/hashes/sha3';
import { hmac } from '@noble/hashes/hmac';
import { bytesToHex } from '@noble/hashes/utils';
import {
	generateIdentityKeys,
	identityKeysFromSecrets,
	openIdentity,
	type IdentityHandle,
	type IdentityKeys,
} from '@buckitup/pq-client/identity';
import {
	buildDialogKeyRow,
	buildMessageRow,
	buildRevisionRow,
	checkRefs,
	decryptRefs,
	deriveSenderMsgKey,
	dialogHash,
	DialogRowError,
	newMessageId,
	openMessageRow,
	wrapSenderMsgKey,
	type RefsMap,
} from '@buckitup/pq-client/dialogs';
import { canEditText, isWireMessageId, withEditedText, type ContentPart } from '@buckitup/pq-client/content';
import { rowMutation, verifyRow, toBase64 } from '@buckitup/pq-client/rows';
import { hkdfDerive } from '@buckitup/pq-client/hkdf';

const utf8 = (s: string) => new TextEncoder().encode(s);

interface Client {
	keys: IdentityKeys;
	me: IdentityHandle;
}

const client = (keys: IdentityKeys = generateIdentityKeys()): Client => ({ keys, me: openIdentity(keys) });

const signed = <T extends Record<string, unknown>>(c: Client, relation: string, row: T) => c.me.signRow(relation, row);

const publishKey = async (author: Client, peer: Client, ownerTimestamp = 100) =>
	signed(author, 'dialog_keys', await buildDialogKeyRow({
		senderHash: author.me.userHash,
		peerHash: peer.me.userHash,
		senderMsgKey: author.me.senderMsgKey(peer.me.userHash),
		peerCryptPkey: peer.me.cryptPkey,
		ownerTimestamp,
	}));

const send = async (author: Client, peer: Client, parts: ContentPart[], refs: RefsMap = {}, ownerTimestamp = 200) =>
	signed(author, 'dialog_messages', await buildMessageRow(author.me.senderMsgKey(peer.me.userHash), {
		senderHash: author.me.userHash,
		dialogHash: dialogHash(author.me.userHash, peer.me.userHash),
		parts,
		refs,
		ownerTimestamp,
	}));

const readAsPeer = async (reader: Client, keyRow: Record<string, unknown>, message: Record<string, unknown>, author: Client) => {
	expect(verifyRow('dialog_keys', keyRow, author.me.signPkey)).toEqual({ status: 'ok' });
	const key = await reader.me.unwrapPeerKey(keyRow as { peer_kem_wrap_key_b64: string; peer_wrapped_msg_key_b64: string });
	return openMessageRow(message, { senderSignPkey: author.me.signPkey, senderMsgKey: key });
};

describe('sender_msg_key', () => {
	it('is HKDF-SHA3-256 over sign_skey || crypt_skey || peer_user_hash, in the SDK and an identity handle alike', () => {
		const ann = client();
		const bobHash = client().me.userHash;
		const ikm = new Uint8Array([...ann.keys.signSkey, ...ann.keys.cryptSkey, ...utf8(bobHash)]);
		const prk = hmac(sha3_256, utf8('buckitup/dialog-mk/v1'), ikm);
		const spec = hmac(sha3_256, prk, new Uint8Array([...utf8('dialog-mk'), 0x01]));
		expect(bytesToHex(deriveSenderMsgKey(ann.keys.signSkey, ann.keys.cryptSkey, bobHash))).toBe(bytesToHex(spec));
		expect(bytesToHex(ann.me.senderMsgKey(bobHash))).toBe(bytesToHex(spec));
	});
});

describe('a dialog between two independent clients', () => {
	it('each writes its key row and a message; each reads the other', async () => {
		const ann = client();
		const bob = client();
		const annKey = await publishKey(ann, bob);
		const annMsg = await send(ann, bob, [{ kind: 'text', text: 'Hi Bob' }]);
		expect(await readAsPeer(bob, annKey, annMsg, ann)).toMatchObject({ status: 'ok', parts: [{ kind: 'text', text: 'Hi Bob' }], refs: {} });

		const bobKey = await publishKey(bob, ann);
		const bobMsg = await send(bob, ann, [{ kind: 'text', text: 'Hi Ann' }], { [annMsg.message_id]: annMsg.sign_hash! });
		expect(bobKey.dialog_hash).toBe(annKey.dialog_hash);
		expect(await readAsPeer(ann, bobKey, bobMsg, bob)).toMatchObject({
			status: 'ok', parts: [{ kind: 'text', text: 'Hi Ann' }], refs: { [annMsg.message_id]: annMsg.sign_hash },
		});
	});

	it('the same identity reopened on another client reads its own history and writes as itself', async () => {
		const ann = client();
		const bob = client();
		const first = await send(ann, bob, [{ kind: 'text', text: 'from the laptop' }]);
		const exported = ann.me.exportKeys();
		const phone = client(identityKeysFromSecrets({
			signSkey: toBase64(exported.signSkey),
			cryptSkey: toBase64(exported.cryptSkey),
			contactSkey: bytesToHex(exported.contactSkey),
		}, { userHash: ann.me.userHash }));
		const own = await openMessageRow(first, { senderSignPkey: phone.me.signPkey, senderMsgKey: phone.me.senderMsgKey(bob.me.userHash) });
		expect(own).toMatchObject({ status: 'ok', parts: [{ kind: 'text', text: 'from the laptop' }] });

		const second = await send(phone, bob, [{ kind: 'text', text: 'from the phone' }], { [first.message_id]: first.sign_hash! }, 201);
		const annKey = await publishKey(ann, bob);
		expect(await readAsPeer(bob, annKey, second, ann)).toMatchObject({ status: 'ok', parts: [{ text: 'from the phone' }] });
	});
});

describe('message rows', () => {
	it('a new message: dmsg_ UUIDv7, no parent, encrypted refs, a dms_ sign_hash, a signature the author\'s card verifies', async () => {
		const ann = client();
		const bob = client();
		const msg = await send(ann, bob, [{ kind: 'text', text: 'one' }]);
		expect(isWireMessageId(msg.message_id)).toBe(true);
		expect(msg.parent_sign_hash).toBeNull();
		expect(msg.sign_hash).toMatch(/^dms_[0-9a-f]{128}$/);
		expect(verifyRow('dialog_messages', msg, ann.me.signPkey)).toEqual({ status: 'ok' });
		expect(verifyRow('dialog_messages', msg, bob.me.signPkey)).toMatchObject({ status: 'invalid', reason: 'bad_signature' });
		expect(new Set(Array.from({ length: 50 }, () => newMessageId())).size).toBe(50);
	});

	it('an edit chains to the tip it replaces, needs a newer timestamp, and carries its own refs', async () => {
		const ann = client();
		const bob = client();
		const key = ann.me.senderMsgKey(bob.me.userHash);
		const tip = await send(ann, bob, [{ kind: 'text', text: 'draft' }], {}, 300);
		const other = await send(bob, ann, [{ kind: 'text', text: 'meanwhile' }], {}, 301);
		const edit = signed(ann, 'dialog_messages', await buildRevisionRow(key, tip, {
			parts: [{ kind: 'text', text: 'final' }], refs: { [other.message_id]: other.sign_hash! }, ownerTimestamp: 301,
		}));
		expect(edit.message_id).toBe(tip.message_id);
		expect(edit.parent_sign_hash).toBe(tip.sign_hash);
		expect(edit.sign_hash).not.toBe(tip.sign_hash);
		expect(await openMessageRow(edit, { senderSignPkey: ann.me.signPkey, senderMsgKey: key }))
			.toMatchObject({ status: 'ok', parts: [{ text: 'final' }], refs: { [other.message_id]: other.sign_hash } });

		await expect(buildRevisionRow(key, tip, { parts: [], refs: {}, ownerTimestamp: 300 })).rejects.toThrow(DialogRowError);
		await expect(buildRevisionRow(key, { ...tip, sign_hash: null }, { parts: [], refs: {}, ownerTimestamp: 400 })).rejects.toThrow(/signed tip/);
	});

	it('a deletion is a signed tombstone revision with no content', async () => {
		const ann = client();
		const bob = client();
		const key = ann.me.senderMsgKey(bob.me.userHash);
		const tip = await send(ann, bob, [{ kind: 'text', text: 'oops' }]);
		const tomb = signed(ann, 'dialog_messages', await buildRevisionRow(key, tip, { deleted: true, refs: {}, ownerTimestamp: 500 }));
		expect(tomb).toMatchObject({ content_b64: null, deleted_flag: true, parent_sign_hash: tip.sign_hash });
		expect(await openMessageRow(tomb, { senderSignPkey: ann.me.signPkey, senderMsgKey: key })).toMatchObject({ status: 'ok', deleted: true, parts: [] });
	});

	it('refuses refs that are not message revisions, and tells a forged row from an unreadable one', async () => {
		const ann = client();
		const bob = client();
		expect(() => checkRefs({ dmsg_1: 'dms_x' })).toThrow(DialogRowError);
		expect(() => checkRefs(['dmsg_1'])).toThrow(DialogRowError);
		await expect(send(ann, bob, [], { not_an_id: 'dms_' + 'a'.repeat(128) })).rejects.toThrow(DialogRowError);
		const msg = await send(ann, bob, [{ kind: 'text', text: 'x' }]);
		const key = ann.me.senderMsgKey(bob.me.userHash);
		expect(await openMessageRow({ ...msg, owner_timestamp: 999 }, { senderSignPkey: ann.me.signPkey, senderMsgKey: key }))
			.toMatchObject({ status: 'invalid', reason: 'bad_signature' });
		expect(await openMessageRow(msg, { senderSignPkey: ann.me.signPkey, senderMsgKey: new Uint8Array(32) }))
			.toMatchObject({ status: 'undecryptable' });
		expect(await decryptRefs(key, msg.refs_map_b64)).toEqual({});
	});

	it('travels as the mutations the app sends: insert, then update named by message, sender and dialog', async () => {
		const ann = client();
		const bob = client();
		const msg = await send(ann, bob, [{ kind: 'text', text: 'x' }]);
		const insert = rowMutation('dialog_messages', { ...msg, local_only: 1 });
		expect(insert).toMatchObject({ type: 'insert', syncMetadata: { relation: 'dialog_messages' } });
		expect(insert.type === 'insert' && Object.keys(insert.modified)).not.toContain('local_only');
		const update = rowMutation('dialog_messages', msg, 'update');
		expect(update.type === 'update' && update.original).toEqual({ message_id: msg.message_id, sender_hash: msg.sender_hash, dialog_hash: msg.dialog_hash });
		expect(() => rowMutation('dialog_messages', { ...msg, sign_b64: null })).toThrow(/not signed/);
	});
});

describe('editing text keeps what the user did not change', () => {
	const quote: ContentPart = {
		kind: 'quote',
		authorHash: 'u_' + 'b'.repeat(128),
		messageId: 'dmsg_0192aaaa-aaaa-7aaa-8aaa-aaaaaaaaaaaa',
		signHash: 'dms_' + 'c'.repeat(128),
		snapshot: [{ kind: 'text', text: 'quoted' }],
	};
	const file: ContentPart = {
		kind: 'file', name: 'a.pdf', size: 3, mimeType: 'application/pdf', createdAt: 1715000000, fileId: 'f_' + 'a'.repeat(32), encSecretB64: 'AAAA',
	};

	it('replaces the text part and keeps the quote and the attachment, in place', () => {
		expect(withEditedText([quote, { kind: 'text', text: 'old' }, file], 'new')).toEqual([quote, { kind: 'text', text: 'new' }, file]);
		expect(withEditedText([quote, file], 'caption')).toEqual([quote, file, { kind: 'text', text: 'caption' }]);
	});

	it('refuses an edit that could not keep every part', () => {
		expect(canEditText([{ kind: 'text', text: 'a' }, { kind: 'text', text: 'b' }])).toBe(false);
		const avatar = { kind: 'avatar' } as unknown as ContentPart;
		expect(canEditText([avatar])).toBe(false);
		expect(() => withEditedText([avatar], 'x')).toThrow(/cannot be edited/);
	});

	it('round-trips the kept parts through a signed revision', async () => {
		const ann = client();
		const bob = client();
		const key = ann.me.senderMsgKey(bob.me.userHash);
		const tip = await send(ann, bob, [quote, { kind: 'text', text: 'old' }, file]);
		const opened = await openMessageRow(tip, { senderSignPkey: ann.me.signPkey, senderMsgKey: key });
		if (opened.status !== 'ok') throw new Error('expected the tip to open');
		const edit = signed(ann, 'dialog_messages', await buildRevisionRow(key, tip, {
			parts: withEditedText(opened.parts, 'new'), refs: {}, ownerTimestamp: 900,
		}));
		const reopened = await openMessageRow(edit, { senderSignPkey: ann.me.signPkey, senderMsgKey: key });
		expect(reopened.status === 'ok' && reopened.parts.map((p) => p.kind)).toEqual(['quote', 'text', 'file']);
		expect(reopened.status === 'ok' && reopened.parts).toEqual([quote, { kind: 'text', text: 'new' }, file]);
	});
});

describe('a dialog_keys row published before the derivation change', () => {
	const legacyKey = (author: IdentityKeys, evmSkey: Uint8Array, peerHash: string) =>
		hkdfDerive(new Uint8Array([...author.signSkey, ...author.cryptSkey, ...evmSkey, ...utf8(peerHash)]), 'buckitup/dialog-mk/v1', 'dialog-mk', 32);

	it('wraps a key the author no longer encrypts with: the peer cannot read new messages until the row is republished', async () => {
		const ann = client();
		const bob = client();
		const old = legacyKey(ann.keys, crypto.getRandomValues(new Uint8Array(32)), bob.me.userHash);
		const oldRow = signed(ann, 'dialog_keys', {
			dialog_hash: dialogHash(ann.me.userHash, bob.me.userHash),
			sender_hash: ann.me.userHash,
			peer_hash: bob.me.userHash,
			...(await wrapSenderMsgKey(old, bob.me.cryptPkey)),
			owner_timestamp: 100,
			deleted_flag: false,
		});
		const fresh = await send(ann, bob, [{ kind: 'text', text: 'after the switch' }]);
		expect(await readAsPeer(bob, oldRow, fresh, ann)).toMatchObject({ status: 'undecryptable' });

		const republished = await publishKey(ann, bob, 101);
		expect(republished.owner_timestamp).toBeGreaterThan(oldRow.owner_timestamp as number);
		expect(await readAsPeer(bob, republished, fresh, ann)).toMatchObject({ status: 'ok', parts: [{ text: 'after the switch' }] });
	});
});
