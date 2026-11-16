import {
	canonicalPayload,
	deriveSignHash,
	encodeField,
	fromBase64,
	padBase64,
	signFields,
	toBase64,
	toBase64Unpadded,
	toBase64Url,
	toBytes,
	verifyFields,
	type SignableFields,
	type SignableValue,
} from './signature.js';
import {
	ENUM_VALUES,
	SIGN_HASH_PREFIX,
	SIGNABLE,
	signableFields,
	wireBool,
	type FieldType,
	type SignableSchema,
} from './schema.js';

export {
	canonicalPayload,
	deriveSignHash,
	encodeField,
	fromBase64,
	padBase64,
	signFields,
	toBase64,
	toBase64Unpadded,
	toBase64Url,
	toBytes,
	verifyFields,
	ENUM_VALUES,
	SIGN_HASH_PREFIX,
	SIGNABLE,
	signableFields,
	wireBool,
	type FieldType,
	type SignableFields,
	type SignableSchema,
	type SignableValue,
};

export type {
	UserCardRow,
	UserStorageRow,
	DialogKeyRow,
	DialogMessageRow,
	DialogMessageVersionRow,
	DialogMessageReactionRow,
	DialogMessageReceiptRow,
	OriginRow,
	OriginSettingRow,
	ModerationMode,
} from './types.js';

export type RowVerdict =
	| { status: 'ok' }
	| {
			status: 'invalid';
			reason: 'missing_signature' | 'missing_sign_hash' | 'bad_signature' | 'sign_hash_mismatch' | 'missing_fields';
	  };

export type SignedRow<T> = {
	[K in keyof T as K extends 'sign_b64' | 'sign_hash' ? never : K]: T[K];
} & { sign_b64: string; sign_hash?: string };

const schemaOf = (relation: string): SignableSchema => {
	const schema = SIGNABLE[relation];
	if (!schema) throw new TypeError(`unknown relation "${relation}"`);
	return schema;
};

export const rowSignableFields = (relation: string, row: Record<string, unknown>): SignableFields => {
	const schema = schemaOf(relation);
	const fields = signableFields(relation, row);
	if (!fields) {
		const missing = Object.keys(schema).filter((field) => !(field in row));
		throw new TypeError(`${relation} row lacks signable field(s): ${missing.join(', ')}`);
	}
	for (const [field, allowed] of Object.entries(ENUM_VALUES[relation] ?? {})) {
		if (!allowed.includes(fields[field] as string)) {
			throw new TypeError(`${relation}.${field} must be one of ${allowed.join(', ')}, got ${JSON.stringify(fields[field])}`);
		}
	}
	return fields as SignableFields;
};

export const signRow = <T extends Record<string, unknown>>(
	relation: string,
	row: T,
	signSkey: Uint8Array,
): SignedRow<T> => {
	const sign_b64 = signFields(rowSignableFields(relation, row), signSkey);
	const prefix = SIGN_HASH_PREFIX[relation];
	if (prefix) return { ...row, sign_b64, sign_hash: deriveSignHash(prefix, sign_b64) };
	const signed: Record<string, unknown> = { ...row, sign_b64 };
	delete signed.sign_hash;
	return signed as SignedRow<T>;
};

export const verifyRow = (
	relation: string,
	row: Record<string, unknown>,
	signPkey: string | Uint8Array,
): RowVerdict => {
	schemaOf(relation);
	const signB64 = row.sign_b64;
	if (!signB64 || (typeof signB64 !== 'string' && !(signB64 instanceof Uint8Array))) {
		return { status: 'invalid', reason: 'missing_signature' };
	}
	const prefix = SIGN_HASH_PREFIX[relation];
	if (prefix) {
		if (typeof row.sign_hash !== 'string' || !row.sign_hash) {
			return { status: 'invalid', reason: 'missing_sign_hash' };
		}
		let expected: string;
		try {
			expected = deriveSignHash(prefix, signB64);
		} catch {
			return { status: 'invalid', reason: 'bad_signature' };
		}
		if (row.sign_hash !== expected) return { status: 'invalid', reason: 'sign_hash_mismatch' };
	}
	const fields = signableFields(relation, row);
	if (!fields) return { status: 'invalid', reason: 'missing_fields' };
	if (!verifyFields(fields as SignableFields, signB64, signPkey)) {
		return { status: 'invalid', reason: 'bad_signature' };
	}
	return { status: 'ok' };
};

const MUTATION_KEYS: Record<string, readonly string[]> = {
	user_cards: ['user_hash'],
	user_storage: ['user_hash', 'uuid'],
	dialog_keys: ['dialog_hash', 'sender_hash'],
	dialog_messages: ['message_id', 'sender_hash', 'dialog_hash'],
	dialog_messages_versions: ['message_id', 'sign_hash'],
	dialog_message_reactions: ['reaction_hash', 'reactor_hash', 'dialog_hash', 'message_id'],
	dialog_message_receipts: ['receipt_hash', 'peer_hash', 'dialog_hash', 'message_id'],
	files: ['file_id'],
	file_chunks: ['file_id', 'chunk_index'],
	vouch_tokens: ['kind', 'issuer_hash', 'subject_hash'],
	origins: ['origin_hash'],
	origin_settings: ['origin_hash', 'key'],
};

export type RowMutation =
	| { type: 'insert'; modified: Record<string, unknown>; syncMetadata: { relation: string } }
	| { type: 'update'; original: Record<string, unknown>; changes: Record<string, unknown>; syncMetadata: { relation: string } };

export const rowMutation = (relation: string, signedRow: Record<string, unknown>, type: 'insert' | 'update' = 'insert'): RowMutation => {
	const schema = schemaOf(relation);
	const signB64 = signedRow.sign_b64;
	if (typeof signB64 !== 'string' || !signB64) throw new TypeError(`${relation} mutation: the row is not signed`);
	const wire: Record<string, unknown> = {};
	for (const field of Object.keys(schema)) {
		if (!(field in signedRow)) throw new TypeError(`${relation} mutation: the row lacks ${field}`);
		wire[field] = signedRow[field];
	}
	wire.sign_b64 = signB64;
	const prefix = SIGN_HASH_PREFIX[relation];
	if (prefix) wire.sign_hash = deriveSignHash(prefix, signB64);
	if (type === 'insert') return { type, modified: wire, syncMetadata: { relation } };
	const original: Record<string, unknown> = {};
	for (const field of MUTATION_KEYS[relation] ?? []) {
		if (signedRow[field] !== undefined) original[field] = signedRow[field];
	}
	return { type, original, changes: wire, syncMetadata: { relation } };
};
