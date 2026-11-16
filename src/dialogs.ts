// The cryptography of a two-person dialog (chat/docs/pq/reqs/pq_dialogs.done.md):
// the dialog's hash, each author's message key, its wrapping for the peer,
// message content, and the keyed hashes of reactions and receipts.
//
// Every author has one sender_msg_key per peer, derived from its own secret
// keys, so any device holding them derives the same key. The peer gets it
// wrapped under ML-KEM-1024 in the author's dialog_keys row.
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { sha3_512 } from '@noble/hashes/sha3';
import { hmac } from '@noble/hashes/hmac';
import { bytesToHex } from '@noble/hashes/utils';
import { openAesGcm as open, sealAesGcm as seal } from './aesGcm.js';
import { hkdfDerive } from './hkdf.js';
import { toBase64, toBytes } from './signature.js';
import { decodeContent, encodeContent, isWireMessageId, type ContentPart } from './content.js';
import { rowMutation, verifyRow, wireBool, type RowVerdict } from './rows.js';
import { verifyUserCard } from './verifyCard.js';
import type { IdentityHandle } from './identity.js';
import type { ReadSessions } from './readSessions.js';
import type { Transport, WriteRejection } from './transport.js';
import type { DialogKeyRow, DialogMessageRow, UserCardRow } from './types.js';

const utf8 = (s: string) => new TextEncoder().encode(s);

const concat = (...parts: Uint8Array[]): Uint8Array => {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let at = 0;
	for (const p of parts) {
		out.set(p, at);
		at += p.length;
	}
	return out;
};

/**
 * A binary column as it arrives: base64 with or without padding (rows written
 * and rows read from a shape), or PostgreSQL's `\x` hex.
 */
export const decodeColumn = (value: string): Uint8Array => toBytes(value);

/** `di_` + hex(SHA3-512(the two user hashes, sorted, concatenated as UTF-8)). */
export const dialogHash = (userA: string, userB: string): string => {
	const [first, second] = [userA, userB].sort();
	return 'di_' + bytesToHex(sha3_512(utf8(first + second)));
};

/**
 * An author's key for every message it writes to `peerHash`:
 * HKDF-SHA3-256(sign_skey || crypt_skey || peer_user_hash), salt
 * "buckitup/dialog-mk/v1", info "dialog-mk", 32 bytes. Post-quantum keys only.
 */
export const deriveSenderMsgKey = (signSkey: Uint8Array, cryptSkey: Uint8Array, peerHash: string): Uint8Array =>
	hkdfDerive(concat(signSkey, cryptSkey, utf8(peerHash)), 'buckitup/dialog-mk/v1', 'dialog-mk', 32);

const wrapKeyOf = (sharedSecret: Uint8Array) => hkdfDerive(sharedSecret, 'buckitup/dialog-wrap/v1', 'wrap', 32);

/**
 * The two dialog_keys columns that carry `senderMsgKey` to the peer:
 * an ML-KEM-1024 encapsulation to its crypt_pkey, and the key sealed under a
 * wrap key derived from the shared secret. Padded base64, as rows are written.
 */
export const wrapSenderMsgKey = async (
	senderMsgKey: Uint8Array,
	peerCryptPkey: Uint8Array,
): Promise<{ peer_kem_wrap_key_b64: string; peer_wrapped_msg_key_b64: string }> => {
	const { cipherText, sharedSecret } = ml_kem1024.encapsulate(peerCryptPkey);
	return {
		peer_kem_wrap_key_b64: toBase64(cipherText),
		peer_wrapped_msg_key_b64: toBase64(await seal(wrapKeyOf(sharedSecret), senderMsgKey)),
	};
};

/** The peer's sender_msg_key out of its dialog_keys row, with this identity's crypt_skey. */
export const unwrapSenderMsgKey = async (
	ownCryptSkey: Uint8Array,
	peerKemWrapKey: string,
	peerWrappedMsgKey: string,
): Promise<Uint8Array> => {
	const sharedSecret = ml_kem1024.decapsulate(decodeColumn(peerKemWrapKey), ownCryptSkey);
	return open(wrapKeyOf(sharedSecret), decodeColumn(peerWrappedMsgKey));
};

/** A message's content_b64: the JSON content sealed under the author's sender_msg_key. */
export const encryptContent = async (senderMsgKey: Uint8Array, plaintext: string): Promise<string> =>
	toBase64(await seal(senderMsgKey, utf8(plaintext)));

/** The JSON content of a message; "" for a deleted one, whose content_b64 is empty. */
export const decryptContent = async (senderMsgKey: Uint8Array, contentB64: string | null | undefined): Promise<string> => {
	if (!contentB64) return '';
	return new TextDecoder().decode(await open(senderMsgKey, decodeColumn(contentB64)));
};

/**
 * `dmr_` + hex(HMAC-SHA3-512(sender_msg_key, message_id || reactor_hash || type)):
 * keyed, so an observer cannot test guesses of the reaction type.
 */
export const reactionHash = (senderMsgKey: Uint8Array, messageId: string, reactorHash: string, type: string): string =>
	'dmr_' + bytesToHex(hmac(sha3_512, senderMsgKey, utf8(messageId + reactorHash + type)));

/** `dmrc_` + hex(SHA3-512(message_id || message_sign_hash || peer_hash || type)). */
export const receiptHash = (messageId: string, messageSignHash: string, peerHash: string, type: string): string =>
	'dmrc_' + bytesToHex(sha3_512(utf8(`${messageId}${messageSignHash}${peerHash}${type}`)));

export class DialogRowError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'DialogRowError';
	}
}

const SIGN_HASH = /^dms_[0-9a-f]{128}$/;

const hex = (bytes: Uint8Array) => bytesToHex(bytes);

export const newMessageId = (nowMs: number = Date.now()): string => {
	const b = crypto.getRandomValues(new Uint8Array(16));
	let ms = Math.floor(nowMs);
	for (let i = 5; i >= 0; i--) {
		b[i] = ms % 256;
		ms = Math.floor(ms / 256);
	}
	b[6] = (b[6] & 0x0f) | 0x70;
	b[8] = (b[8] & 0x3f) | 0x80;
	const h = hex(b);
	return `dmsg_${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
};

export type RefsMap = Record<string, string>;

export const checkRefs = (refs: unknown): RefsMap => {
	if (!refs || typeof refs !== 'object' || Array.isArray(refs)) throw new DialogRowError('refs: not a {message_id: sign_hash} map');
	for (const [messageId, signHash] of Object.entries(refs)) {
		if (!isWireMessageId(messageId) || typeof signHash !== 'string' || !SIGN_HASH.test(signHash)) {
			throw new DialogRowError(`refs: ${JSON.stringify(messageId)} → ${JSON.stringify(signHash)} is not a message revision`);
		}
	}
	return refs as RefsMap;
};

export interface DialogRowCrypto {
	encrypt?: (senderMsgKey: Uint8Array, plaintext: string) => Promise<string>;
	wrap?: (senderMsgKey: Uint8Array, peerCryptPkey: Uint8Array) => Promise<{ peer_kem_wrap_key_b64: string; peer_wrapped_msg_key_b64: string }>;
}

export const encryptRefs = (senderMsgKey: Uint8Array, refs: RefsMap, crypto: DialogRowCrypto = {}): Promise<string> =>
	(crypto.encrypt ?? encryptContent)(senderMsgKey, JSON.stringify(checkRefs(refs)));

export const decryptRefs = async (senderMsgKey: Uint8Array, refsMapB64: string | null | undefined): Promise<RefsMap> => {
	const json = await decryptContent(senderMsgKey, refsMapB64);
	return json ? checkRefs(JSON.parse(json)) : {};
};

const assertTimestamp = (ownerTimestamp: number) => {
	if (!Number.isSafeInteger(ownerTimestamp) || ownerTimestamp <= 0) throw new DialogRowError('owner_timestamp must be a positive integer');
};

export interface DialogKeyInput {
	senderHash: string;
	peerHash: string;
	dialogHash?: string;
	senderMsgKey: Uint8Array;
	peerCryptPkey: Uint8Array | string;
	ownerTimestamp: number;
}

export const buildDialogKeyRow = async (input: DialogKeyInput, crypto: DialogRowCrypto = {}): Promise<DialogKeyRow> => {
	assertTimestamp(input.ownerTimestamp);
	const wrapped = await (crypto.wrap ?? wrapSenderMsgKey)(input.senderMsgKey, toBytes(input.peerCryptPkey));
	return {
		dialog_hash: input.dialogHash ?? dialogHash(input.senderHash, input.peerHash),
		sender_hash: input.senderHash,
		peer_hash: input.peerHash,
		...wrapped,
		owner_timestamp: input.ownerTimestamp,
		deleted_flag: false,
		sign_b64: null,
	};
};

export interface NewMessageInput {
	senderHash: string;
	dialogHash: string;
	messageId?: string;
	parts: ContentPart[];
	refs: RefsMap;
	ownerTimestamp: number;
}

export const buildMessageRow = async (
	senderMsgKey: Uint8Array,
	input: NewMessageInput,
	crypto: DialogRowCrypto = {},
): Promise<DialogMessageRow> => {
	assertTimestamp(input.ownerTimestamp);
	const messageId = input.messageId ?? newMessageId();
	if (!isWireMessageId(messageId)) throw new DialogRowError(`message_id ${JSON.stringify(messageId)} is not dmsg_ + UUIDv7`);
	return {
		message_id: messageId,
		dialog_hash: input.dialogHash,
		sender_hash: input.senderHash,
		content_b64: await (crypto.encrypt ?? encryptContent)(senderMsgKey, encodeContent(input.parts)),
		deleted_flag: false,
		refs_map_b64: await encryptRefs(senderMsgKey, input.refs, crypto),
		parent_sign_hash: null,
		owner_timestamp: input.ownerTimestamp,
		sign_b64: null,
		sign_hash: null,
	};
};

export interface RevisionBase {
	message_id: string;
	dialog_hash: string;
	sender_hash: string;
	sign_hash?: string | null;
	owner_timestamp: number | string | null;
}

export type RevisionChange =
	| { parts: ContentPart[]; refs: RefsMap; ownerTimestamp: number }
	| { deleted: true; refs: RefsMap; ownerTimestamp: number };

export const buildRevisionRow = async (
	senderMsgKey: Uint8Array,
	base: RevisionBase,
	change: RevisionChange,
	crypto: DialogRowCrypto = {},
): Promise<DialogMessageRow> => {
	assertTimestamp(change.ownerTimestamp);
	if (!base.sign_hash || !SIGN_HASH.test(base.sign_hash)) throw new DialogRowError('a revision needs the signed tip it replaces');
	if (change.ownerTimestamp <= Number(base.owner_timestamp)) {
		throw new DialogRowError(`owner_timestamp ${change.ownerTimestamp} is not newer than the tip's ${base.owner_timestamp}`);
	}
	const deleted = 'deleted' in change;
	return {
		message_id: base.message_id,
		dialog_hash: base.dialog_hash,
		sender_hash: base.sender_hash,
		content_b64: deleted ? null : await (crypto.encrypt ?? encryptContent)(senderMsgKey, encodeContent(change.parts)),
		deleted_flag: deleted,
		refs_map_b64: await encryptRefs(senderMsgKey, change.refs, crypto),
		parent_sign_hash: base.sign_hash,
		owner_timestamp: change.ownerTimestamp,
		sign_b64: null,
		sign_hash: null,
	};
};

export type OpenedMessage =
	| { status: 'ok'; parts: ContentPart[]; refs: RefsMap; deleted: boolean }
	| Extract<RowVerdict, { status: 'invalid' }>
	| { status: 'undecryptable'; error: unknown };

export const openMessageRow = async (
	row: DialogMessageRow | Record<string, unknown>,
	{ senderSignPkey, senderMsgKey }: { senderSignPkey: string | Uint8Array; senderMsgKey: Uint8Array },
): Promise<OpenedMessage> => {
	const verdict = verifyRow('dialog_messages', row as Record<string, unknown>, senderSignPkey);
	if (verdict.status !== 'ok') return verdict;
	try {
		const deleted = wireBool(row.deleted_flag);
		const json = deleted ? '' : await decryptContent(senderMsgKey, row.content_b64 as string | null);
		return {
			status: 'ok',
			parts: json ? decodeContent(json) : [],
			refs: await decryptRefs(senderMsgKey, row.refs_map_b64 as string | null),
			deleted,
		};
	} catch (error) {
		return { status: 'undecryptable', error };
	}
};

type RowInvalid = Extract<RowVerdict, { status: 'invalid' }>['reason'];

export type DialogContextInvalid = 'peer_card' | 'sender_card' | 'wrong_sender' | 'wrong_peer' | 'wrong_dialog';

export type PeerDialogKey =
	| { status: 'ok'; senderMsgKey: Uint8Array }
	| { status: 'deleted' }
	| { status: 'invalid'; reason: DialogContextInvalid | RowInvalid }
	| { status: 'undecryptable'; error: unknown };

const verifiedCardOf = (card: UserCardRow | Record<string, unknown> | null | undefined, userHash: string): UserCardRow | null =>
	card && card.user_hash === userHash && typeof card.sign_pkey === 'string' && verifyUserCard(card as UserCardRow).status === 'verified'
		? (card as UserCardRow)
		: null;

export const openPeerDialogKey = async (
	reader: Pick<IdentityHandle, 'userHash' | 'unwrapPeerKey'>,
	row: DialogKeyRow | Record<string, unknown>,
	{ peerHash, peerCard }: { peerHash: string; peerCard: UserCardRow | Record<string, unknown> | null | undefined },
): Promise<PeerDialogKey> => {
	const card = verifiedCardOf(peerCard, peerHash);
	if (!card) return { status: 'invalid', reason: 'peer_card' };
	if (row.sender_hash !== peerHash) return { status: 'invalid', reason: 'wrong_sender' };
	if (row.peer_hash !== reader.userHash) return { status: 'invalid', reason: 'wrong_peer' };
	if (row.dialog_hash !== dialogHash(reader.userHash, peerHash)) return { status: 'invalid', reason: 'wrong_dialog' };
	const verdict = verifyRow('dialog_keys', row as Record<string, unknown>, card.sign_pkey!);
	if (verdict.status !== 'ok') return verdict;
	if (wireBool(row.deleted_flag)) return { status: 'deleted' };
	try {
		return { status: 'ok', senderMsgKey: await reader.unwrapPeerKey(row as DialogKeyRow) };
	} catch (error) {
		return { status: 'undecryptable', error };
	}
};

export type DialogMessage = OpenedMessage | { status: 'invalid'; reason: DialogContextInvalid };

export const openDialogMessage = async (
	row: DialogMessageRow | Record<string, unknown>,
	{ me, peerHash, senderCard, senderMsgKey }: {
		me: string;
		peerHash: string;
		senderCard: UserCardRow | Record<string, unknown> | null | undefined;
		senderMsgKey: Uint8Array;
	},
): Promise<DialogMessage> => {
	if (row.dialog_hash !== dialogHash(me, peerHash)) return { status: 'invalid', reason: 'wrong_dialog' };
	const sender = row.sender_hash;
	if (sender !== me && sender !== peerHash) return { status: 'invalid', reason: 'wrong_sender' };
	const card = verifiedCardOf(senderCard, sender);
	if (!card) return { status: 'invalid', reason: 'sender_card' };
	return openMessageRow(row, { senderSignPkey: card.sign_pkey!, senderMsgKey });
};

export type EnsureDialogKey =
	| { kind: 'present'; row: Record<string, unknown> }
	| { kind: 'written'; row: DialogKeyRow; txid: number }
	| { kind: 'deleted'; row: Record<string, unknown> }
	| { kind: 'rejected'; rejection: WriteRejection }
	| { kind: 'unknown'; error: unknown }
	| { kind: 'unavailable'; error: unknown }
	| { kind: 'invalid'; reason: 'peer_card' | 'wrong_peer' | RowInvalid; row?: Record<string, unknown> };

export interface EnsureDialogKeyOptions {
	transport: Pick<Transport, 'readShapeOnce' | 'ingest'>;
	identity: IdentityHandle;
	peerHash: string;
	peerCard: UserCardRow | Record<string, unknown> | null | undefined;
	sessions?: ReadSessions | null;
	now?: () => number;
}

type OwnKeyRead = { kind: 'row'; row: Record<string, unknown> | null } | { kind: 'unavailable'; error: unknown };

const readOwnKeyRow = async ({ transport, identity, peerHash, sessions }: EnsureDialogKeyOptions): Promise<OwnKeyRead> => {
	const dialog = dialogHash(identity.userHash, peerHash);
	const where = `dialog_hash = '${dialog}' AND sender_hash = '${identity.userHash}'`;
	try {
		const read = () => transport.readShapeOnce<Record<string, unknown>>('dialog_keys', where, { authorization: sessions?.bearer('dialog_keys') ?? undefined });
		let res = await read();
		if (res.kind === 'read_session_required' && sessions && (await sessions.reopen(res.shape, 'dialog_keys')).kind === 'opened') res = await read();
		if (res.kind !== 'rows') return { kind: 'unavailable', error: res };
		return { kind: 'row', row: res.rows.find((r) => r.dialog_hash === dialog && r.sender_hash === identity.userHash) ?? null };
	} catch (error) {
		return { kind: 'unavailable', error };
	}
};

const judgeOwnKeyRow = (options: EnsureDialogKeyOptions, row: Record<string, unknown>): EnsureDialogKey => {
	const verdict = verifyRow('dialog_keys', row, options.identity.signPkey);
	if (verdict.status !== 'ok') return { kind: 'invalid', reason: verdict.reason, row };
	if (row.peer_hash !== options.peerHash) return { kind: 'invalid', reason: 'wrong_peer', row };
	return wireBool(row.deleted_flag) ? { kind: 'deleted', row } : { kind: 'present', row };
};

export const ensureDialogKey = async (options: EnsureDialogKeyOptions): Promise<EnsureDialogKey> => {
	const { transport, identity, peerHash } = options;
	const card = verifiedCardOf(options.peerCard, peerHash);
	if (!card || !card.crypt_pkey) return { kind: 'invalid', reason: 'peer_card' };
	const existing = await readOwnKeyRow(options);
	if (existing.kind === 'unavailable') return existing;
	if (existing.row) return judgeOwnKeyRow(options, existing.row);
	const row = identity.signRow('dialog_keys', await buildDialogKeyRow({
		senderHash: identity.userHash,
		peerHash,
		senderMsgKey: identity.senderMsgKey(peerHash),
		peerCryptPkey: card.crypt_pkey,
		ownerTimestamp: (options.now ?? (() => Math.floor(Date.now() / 1000)))(),
	})) as DialogKeyRow;
	let outcome: Awaited<ReturnType<Transport['ingest']>>;
	try {
		outcome = await transport.ingest([rowMutation('dialog_keys', row)], identity.sign);
	} catch (error) {
		return { kind: 'unknown', error };
	}
	if (outcome.kind === 'written') return { kind: 'written', row, txid: outcome.txid };
	if (outcome.rejection.kind !== 'exists') return { kind: 'rejected', rejection: outcome.rejection };
	const after = await readOwnKeyRow(options);
	if (after.kind === 'row' && after.row) return judgeOwnKeyRow(options, after.row);
	return { kind: 'rejected', rejection: outcome.rejection };
};
