import { describe, it, expect, expectTypeOf } from 'vitest';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { sha3_512 } from '@noble/hashes/sha3';
import { bytesToHex } from '@noble/hashes/utils';
import {
	canonicalPayload,
	rowSignableFields,
	rowMutation,
	type RowMutation,
	signRow,
	verifyRow,
	toBase64,
	toBase64Unpadded,
	ENUM_VALUES,
	SIGN_HASH_PREFIX,
	SIGNABLE,
	type OriginRow,
	type OriginSettingRow,
	type RowVerdict,
} from '@buckitup/pq-client/rows';
import { verifyMessageRow } from '@buckitup/pq-client/verifyDialogRow';

const framed = (...values: string[]): number[] =>
	values.flatMap((v) => {
		const bytes = Array.from(new TextEncoder().encode(v));
		const n = bytes.length;
		return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff, ...bytes];
	});

const keypair = (seed: number) => ml_dsa87.keygen(new Uint8Array(32).fill(seed));
const venue = keypair(1);
const owner = keypair(2);
const stranger = keypair(3);

const originHash = 'u_' + 'a1'.repeat(64);
const ownerHash = 'u_' + 'b2'.repeat(64);
const ownerCert = ml_dsa87.sign(venue.publicKey, owner.secretKey);

const without = (row: Record<string, unknown>, column: string): Record<string, unknown> => {
	const copy = { ...row };
	delete copy[column];
	return copy;
};

const originRow = (overrides: Partial<OriginRow> = {}): OriginRow => ({
	origin_hash: originHash,
	owner_hash: ownerHash,
	owner_cert: toBase64(ownerCert),
	name: 'Café ☕',
	moderation_mode: 'post',
	deleted_flag: false,
	owner_timestamp: 1_700_000_000,
	sign_b64: null,
	sign_hash: null,
	...overrides,
});

describe('generated schema tables', () => {
	it('includes origins and origin_settings with the backend field sets', () => {
		expect(SIGNABLE.origins).toEqual({
			origin_hash: 'text',
			owner_hash: 'text',
			owner_cert: 'binary',
			name: 'text',
			moderation_mode: 'text',
			deleted_flag: 'bool',
			owner_timestamp: 'int',
		});
		expect(SIGNABLE.origin_settings).toEqual({
			origin_hash: 'text',
			key: 'text',
			value: 'text',
			deleted_flag: 'bool',
			owner_timestamp: 'int',
		});
	});

	it('carries the moderation_mode enum and every sign_hash prefix', () => {
		expect(ENUM_VALUES).toEqual({ origins: { moderation_mode: ['none', 'post', 'pre'] } });
		expect(SIGN_HASH_PREFIX).toEqual({
			user_storage: 'uss_',
			dialog_messages: 'dms_',
			dialog_messages_versions: 'dms_',
			origins: 'ors_',
		});
	});
});

describe('origins canonical payload', () => {
	it('sorts the columns and signs the enum as its text', () => {
		const row = originRow();
		expect(Array.from(canonicalPayload(rowSignableFields('origins', row)))).toEqual(
			framed(
				'false',
				'post',
				'Café ☕',
				originHash,
				toBase64(ownerCert),
				ownerHash,
				'1700000000',
			),
		);
	});

	it('is the same for owner_cert as raw bytes, padded or as served unpadded', () => {
		const expected = canonicalPayload(rowSignableFields('origins', originRow()));
		const unpadded = toBase64Unpadded(ownerCert);
		expect(unpadded).not.toBe(toBase64(ownerCert));
		for (const owner_cert of [unpadded, ownerCert]) {
			const fields = rowSignableFields('origins', { ...originRow(), owner_cert } as Record<string, unknown>);
			expect(canonicalPayload(fields)).toEqual(expected);
		}
	});
});

describe('signRow / verifyRow', () => {
	it('signs an origin with V and derives an ors_ sign_hash from the signature bytes', () => {
		const signed = signRow('origins', originRow(), venue.secretKey);
		const sigBytes = Uint8Array.from(atob(signed.sign_b64), (c) => c.charCodeAt(0));
		expect(signed.sign_hash).toBe('ors_' + bytesToHex(sha3_512(sigBytes)));
		expect(verifyRow('origins', signed, venue.publicKey)).toEqual({ status: 'ok' });
		expect(verifyRow('origins', signed, stranger.publicKey)).toEqual({ status: 'invalid', reason: 'bad_signature' });
	});

	it('verifies an update signed by the owner against the owner key only', () => {
		const signed = signRow('origins', originRow({ name: 'Renamed', owner_timestamp: 1_700_000_001 }), owner.secretKey);
		expect(verifyRow('origins', signed, owner.publicKey).status).toBe('ok');
		expect(verifyRow('origins', signed, venue.publicKey).status).toBe('invalid');
	});

	it('verifies a row as a shape serves it: unpadded binaries, boolean as t/f', () => {
		const signed = signRow('origins', originRow(), venue.secretKey);
		const served = {
			...signed,
			owner_cert: toBase64Unpadded(ownerCert),
			sign_b64: signed.sign_b64.replace(/=+$/, ''),
			deleted_flag: 'f',
			owner_timestamp: '1700000000',
			_local: 1,
		};
		expect(verifyRow('origins', served, toBase64Unpadded(venue.publicKey))).toEqual({ status: 'ok' });
	});

	it('refuses tampered fields, a forged sign_hash and missing columns', () => {
		const signed = signRow('origins', originRow(), venue.secretKey);
		expect(verifyRow('origins', { ...signed, moderation_mode: 'none' }, venue.publicKey))
			.toEqual({ status: 'invalid', reason: 'bad_signature' });
		expect(verifyRow('origins', { ...signed, sign_hash: 'ors_' + '0'.repeat(128) }, venue.publicKey))
			.toEqual({ status: 'invalid', reason: 'sign_hash_mismatch' });
		expect(verifyRow('origins', { ...signed, sign_b64: null }, venue.publicKey))
			.toEqual({ status: 'invalid', reason: 'missing_signature' });
		expect(verifyRow('origins', without(signed, 'owner_cert'), venue.publicKey))
			.toEqual({ status: 'invalid', reason: 'missing_fields' });
	});

	it('refuses a row of a sign_hash relation whose sign_hash is absent or empty', () => {
		const signed = signRow('origins', originRow(), venue.secretKey);
		for (const sign_hash of [null, undefined, '', 0, false]) {
			expect(verifyRow('origins', { ...signed, sign_hash }, venue.publicKey))
				.toEqual({ status: 'invalid', reason: 'missing_sign_hash' });
		}
		expect(verifyRow('origins', without(signed, 'sign_hash'), venue.publicKey))
			.toEqual({ status: 'invalid', reason: 'missing_sign_hash' });
		expect(verifyRow('origins', { ...signed, sign_hash: signed.sign_hash!.replace('ors_', 'dms_') }, venue.publicKey))
			.toEqual({ status: 'invalid', reason: 'sign_hash_mismatch' });
	});

	it('requires sign_hash on dialog message revisions and user_storage too', () => {
		const storage = signRow('user_storage', {
			user_hash: ownerHash,
			uuid: '0190f0a0-0000-7000-8000-000000000001',
			value_b64: toBase64(new Uint8Array([4, 5])),
			deleted_flag: false,
			parent_sign_hash: null,
			owner_timestamp: 1_700_000_004,
		}, owner.secretKey);
		expect(storage.sign_hash).toMatch(/^uss_[0-9a-f]{128}$/);
		expect(verifyRow('user_storage', storage, owner.publicKey)).toEqual({ status: 'ok' });
		expect(verifyRow('user_storage', { ...storage, sign_hash: null }, owner.publicKey))
			.toEqual({ status: 'invalid', reason: 'missing_sign_hash' });
		expect(verifyRow('dialog_messages_versions', { ...storage, sign_hash: null }, owner.publicKey))
			.toEqual({ status: 'invalid', reason: 'missing_sign_hash' });
	});

	it('types a signed row with sign_b64: string even when the input held null', () => {
		const signed = signRow('origins', originRow(), venue.secretKey);
		expectTypeOf(signed.sign_b64).toEqualTypeOf<string>();
		expectTypeOf(signed.sign_hash).toEqualTypeOf<string | undefined>();
		expectTypeOf(signed.name).toEqualTypeOf<string>();
		const literal = signRow('origin_settings', {
			origin_hash: originHash, key: 'k', value: 'v', deleted_flag: false, owner_timestamp: 1,
			sign_b64: null, sign_hash: null,
		}, venue.secretKey);
		expectTypeOf(literal.sign_b64).toEqualTypeOf<string>();
		expect(literal).not.toHaveProperty('sign_hash');
		expectTypeOf<RowVerdict>().toMatchTypeOf<{ status: 'ok' } | { status: 'invalid'; reason: string }>();
	});

	it('refuses to sign a moderation_mode the server cannot cast', () => {
		expect(() => signRow('origins', originRow({ moderation_mode: 'strict' as never }), venue.secretKey))
			.toThrow(/moderation_mode must be one of none, post, pre/);
	});

	it('names the missing columns and rejects an unknown relation', () => {
		expect(() => signRow('origins', without(originRow(), 'owner_cert'), venue.secretKey)).toThrow(/lacks signable field\(s\): owner_cert/);
		expect(() => signRow('origin', originRow(), venue.secretKey)).toThrow(/unknown relation "origin"/);
		expect(() => verifyRow('origin', originRow(), venue.publicKey)).toThrow(/unknown relation/);
	});

	it('signs origin_settings without a sign_hash', () => {
		const setting: OriginSettingRow = {
			origin_hash: originHash,
			key: 'review_access',
			value: 'invite_only',
			deleted_flag: false,
			owner_timestamp: 1_700_000_002,
			sign_b64: null,
		};
		const signed = signRow('origin_settings', setting, venue.secretKey);
		expect(signed).not.toHaveProperty('sign_hash');
		expect(verifyRow('origin_settings', signed, venue.publicKey)).toEqual({ status: 'ok' });
		expect(verifyRow('origin_settings', { ...signed, value: 'open' }, venue.publicKey).status).toBe('invalid');
	});

	it('keeps verifyMessageRow on the same check, malformed signature included', () => {
		const message = signRow('dialog_messages', {
			message_id: 'dmsg_' + '01'.repeat(16),
			dialog_hash: 'di_' + 'c3'.repeat(64),
			sender_hash: originHash,
			content_b64: toBase64(new Uint8Array([1, 2, 3])),
			deleted_flag: false,
			refs_map_b64: null,
			parent_sign_hash: null,
			owner_timestamp: 1_700_000_003,
		}, venue.secretKey);
		expect(message.sign_hash).toMatch(/^dms_[0-9a-f]{128}$/);
		const pkey = toBase64(venue.publicKey);
		expect(verifyMessageRow(message as never, pkey)).toEqual({ status: 'ok' });
		expect(verifyMessageRow({ ...message, sign_b64: '!!' } as never, pkey))
			.toEqual({ status: 'invalid', reason: 'bad_signature' });
	});
});

// Update mutations must carry `original` with the row's identifying fields —
// the server routes them to update_changeset (edit/tombstone semantics),
// while inserts on an existing PK are rejected outright.
const signedMutation = (relation: string, row: Record<string, unknown>, signSkey: Uint8Array, type: 'insert' | 'update') =>
	rowMutation(relation, signRow(relation, row, signSkey), type);
type UpdateMutation = Extract<RowMutation, { type: 'update' }>;

describe('ready-row update shape', () => {
	const { secretKey } = ml_dsa87.keygen();

	it('builds an update with original identity fields', () => {
		const m = signedMutation('dialog_message_reactions', {
			reaction_hash: 'dmr_' + 'cd'.repeat(64),
			dialog_hash: 'di_' + 'ab'.repeat(64),
			message_id: 'dmsg_1',
			message_sign_hash: 'dms_' + 'ef'.repeat(64),
			reactor_hash: 'u_' + 'ab'.repeat(64),
			type_b64: '',
			deleted_flag: true,
			owner_timestamp: 1785000001,
		}, secretKey, 'update') as UpdateMutation;

		expect(m.type).toBe('update');
		expect(m.original).toMatchObject({
			reaction_hash: expect.stringMatching(/^dmr_/),
			dialog_hash: expect.stringMatching(/^di_/),
			message_id: 'dmsg_1',
		});
		expect(m.changes.deleted_flag).toBe(true);
		expect(m.changes.sign_b64).toBeTruthy();
	});

	it('builds a dialog_messages edit as update with parent_sign_hash', () => {
		const m = signedMutation('dialog_messages', {
			message_id: 'dmsg_2',
			dialog_hash: 'di_' + 'ab'.repeat(64),
			sender_hash: 'u_' + 'ab'.repeat(64),
			content_b64: 'bmV3',
			deleted_flag: false,
			refs_map_b64: 'cmVmcw',
			parent_sign_hash: 'dms_' + '12'.repeat(64),
			owner_timestamp: 1785000002,
		}, secretKey, 'update') as UpdateMutation;

		expect(m.type).toBe('update');
		expect(m.original.message_id).toBe('dmsg_2');
		expect(m.changes.parent_sign_hash).toMatch(/^dms_/);
	});
});

// --- user_storage mutation: must match the server's Signable/Integrity impl ---
// Reference: chat/lib/chat/data/schemas/user_storage.ex (signable_fields drops
// sign_b64 + sign_hash) and chat/lib/chat/data/integrity.ex (sorted keys,
// per-suffix encoding). Getting this wrong yields "invalid_signature".
describe('user_storage mutation signing', () => {
	const { publicKey, secretKey } = ml_dsa87.keygen();
	const userHash = 'u_' + 'ab'.repeat(64);
	const uuid = '00000000-0000-4000-8000-000000000001';
	const valueB64 = 'aGVsbG8gd29ybGQ=';
	const ownerTimestamp = 1785000000;

	const serverEncodeField = (key: string, value: unknown): string => {
		if (value === null || value === undefined) return 'null';
		if (key.endsWith('_b64') || key.endsWith('_cert') || key.endsWith('_pkey')) return String(value);
		if (value === true) return 'true';
		if (value === false) return 'false';
		return String(value);
	};

	// Exactly the fields the server keeps, in its sort order, each
	// u32be(byte length) || UTF-8 value.
	const serverPayload = (fields: Record<string, unknown>): Uint8Array =>
		Uint8Array.from(
			Object.keys(fields)
				.sort()
				.flatMap((k) => {
					const bytes = Array.from(new TextEncoder().encode(serverEncodeField(k, fields[k])));
					const n = bytes.length;
					return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff, ...bytes];
				}),
		);

	const build = () => signedMutation('user_storage', {
		user_hash: userHash, uuid, value_b64: valueB64, deleted_flag: false, owner_timestamp: ownerTimestamp, parent_sign_hash: null,
	}, secretKey, 'insert') as Extract<RowMutation, { type: 'insert' }> & { modified: { sign_b64: string; sign_hash: string } };

	it('derives sign_hash as "uss_" + SHA3-512 of the raw signature', () => {
		const m = build();
		const signBytes = Uint8Array.from(atob(m.modified.sign_b64), (c) => c.charCodeAt(0));
		expect(m.modified.sign_hash).toBe('uss_' + bytesToHex(sha3_512(signBytes)));
		expect(m.modified.sign_hash).toMatch(/^uss_[0-9a-f]{128}$/);
	});

	it('signs exactly the field set the server verifies', () => {
		const m = build();
		const payload = serverPayload({
			deleted_flag: false,
			owner_timestamp: ownerTimestamp,
			parent_sign_hash: null,
			user_hash: userHash,
			uuid,
			value_b64: valueB64,
		});
		const signBytes = Uint8Array.from(atob(m.modified.sign_b64), (c) => c.charCodeAt(0));
		const ok = ml_dsa87.verify(signBytes, payload, publicKey);
		expect(ok).toBe(true);
	});
});
