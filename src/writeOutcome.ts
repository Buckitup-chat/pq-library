import type { IngestRowResult } from './types.js';

export type ValidationDetails = Record<string, unknown>;

export type WriteRejection =
	| { kind: 'gate'; error: 'not_in_trust_chain'; maxDepth: number | null }
	| { kind: 'stale_timestamp'; details: ValidationDetails }
	| { kind: 'missing_parent'; fields: string[]; details: ValidationDetails }
	| { kind: 'exists'; conflicted: boolean }
	| { kind: 'unique_conflict'; fields: string[]; details: ValidationDetails }
	| { kind: 'pub_key_taken' }
	| { kind: 'validation'; details: ValidationDetails }
	| { kind: 'proof_rejected'; error: string }
	| { kind: 'bad_request'; error: string }
	| { kind: 'rejected'; error: string };

export type RowOutcome =
	| { index: number; kind: 'written'; txid: number | null }
	| { index: number; kind: 'rejected'; rejection: WriteRejection };

const GATE_ERROR = 'not_in_trust_chain';
const STALE_MESSAGE = /timestamp not newer/i;
const MISSING_PARENT_MESSAGE = /^does not exist$/i;
const UNIQUE_MESSAGE = /has already been taken/i;

const messagesOf = (value: unknown): string[] =>
	Array.isArray(value) ? value.filter((m): m is string => typeof m === 'string') : [];

const fieldsWith = (details: ValidationDetails, pattern: RegExp): string[] =>
	Object.entries(details)
		.filter(([, messages]) => messagesOf(messages).some((m) => pattern.test(m)))
		.map(([field]) => field);

export type ValidationReason = 'missing_parent' | 'stale_timestamp' | 'unique_conflict';

const detailsOf = (details: unknown): ValidationDetails => (details && typeof details === 'object' ? (details as ValidationDetails) : {});

export const validationReasons = (details: unknown): Set<ValidationReason> => {
	const d = detailsOf(details);
	const reasons = new Set<ValidationReason>();
	if (fieldsWith(d, MISSING_PARENT_MESSAGE).length) reasons.add('missing_parent');
	if (messagesOf(d.owner_timestamp).some((m) => STALE_MESSAGE.test(m))) reasons.add('stale_timestamp');
	if (fieldsWith(d, UNIQUE_MESSAGE).length) reasons.add('unique_conflict');
	return reasons;
};

export const classifyValidation = (details: unknown): WriteRejection => {
	const d = detailsOf(details);
	const reasons = validationReasons(d);
	if (reasons.has('missing_parent')) return { kind: 'missing_parent', fields: fieldsWith(d, MISSING_PARENT_MESSAGE), details: d };
	if (reasons.has('stale_timestamp')) return { kind: 'stale_timestamp', details: d };
	if (reasons.has('unique_conflict')) return { kind: 'unique_conflict', fields: fieldsWith(d, UNIQUE_MESSAGE), details: d };
	return { kind: 'validation', details: d };
};

const maxDepthOf = (body: unknown): number | null => {
	const value = (body as { max_depth?: unknown } | null)?.max_depth;
	return typeof value === 'number' ? value : null;
};

export const classifyErrorBody = (body: { error?: unknown; details?: unknown; max_depth?: unknown }): WriteRejection => {
	const error = typeof body.error === 'string' ? body.error : 'unknown_error';
	if (error === GATE_ERROR) return { kind: 'gate', error: GATE_ERROR, maxDepth: maxDepthOf(body) };
	if (error === 'pub_key_taken') return { kind: 'pub_key_taken' };
	if (error === 'validation_failed') return classifyValidation(body.details);
	return { kind: 'rejected', error };
};

export const classifyRowResult = (row: IngestRowResult): RowOutcome => {
	if (row.status === 'ok') return { index: row.index, kind: 'written', txid: typeof row.txid === 'number' ? row.txid : null };
	if (row.status === 'exists') return { index: row.index, kind: 'rejected', rejection: { kind: 'exists', conflicted: row.conflicted !== false } };
	return { index: row.index, kind: 'rejected', rejection: classifyErrorBody(row as unknown as { error?: unknown; details?: unknown }) };
};
