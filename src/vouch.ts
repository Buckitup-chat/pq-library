import type { IdentityHandle } from './identity.js';
import { rowMutation, verifyRow, wireBool } from './rows.js';
import type { Transport, WriteRejection } from './transport.js';

export type ScopeAccess = 'read' | 'write';

export const storageScope = (deviceId: string, access: ScopeAccess, shape?: string, suffix?: string): string =>
	['device', deviceId, 'storage', access, shape, suffix].filter((part): part is string => !!part).join('.');

export const adminScope = (deviceId: string): string => `device.${deviceId}.admin`;

export interface VouchRow {
	kind: string;
	issuer_hash: string;
	subject_hash: string;
	owner_timestamp: number;
	deleted_flag: boolean;
	sign_b64?: string | null;
}

export interface VouchKey {
	kind: string;
	issuerHash: string;
	subjectHash: string;
}

const USER_HASH = /^u_[0-9a-f]{128}$/;

export const vouchRow = (key: VouchKey, { granted, ownerTimestamp }: { granted: boolean; ownerTimestamp: number }): VouchRow => {
	if (!key.kind) throw new TypeError('vouch: the scope must not be empty');
	if (!USER_HASH.test(key.issuerHash) || !USER_HASH.test(key.subjectHash)) throw new TypeError('vouch: issuer and subject must be user hashes');
	if (!Number.isSafeInteger(ownerTimestamp) || ownerTimestamp <= 0) throw new TypeError('vouch: owner_timestamp must be a positive integer');
	return {
		kind: key.kind,
		issuer_hash: key.issuerHash,
		subject_hash: key.subjectHash,
		owner_timestamp: ownerTimestamp,
		deleted_flag: !granted,
	};
};

export type VouchRead =
	| { kind: 'absent' }
	| { kind: 'found'; row: VouchRow }
	| { kind: 'unverified'; row: Record<string, unknown> }
	| { kind: 'unavailable'; error: unknown };

export type VouchWrite =
	| { kind: 'written'; row: VouchRow; txid: number }
	| { kind: 'unchanged'; row: VouchRow }
	| { kind: 'rejected'; rejection: WriteRejection }
	| Exclude<VouchRead, { kind: 'found' } | { kind: 'absent' }>;

export interface VouchOptions {
	transport: Pick<Transport, 'readShapeOnce' | 'ingest'>;
	issuer: IdentityHandle;
	now?: () => number;
	maxAttempts?: number;
}

export const readVouch = async (
	{ transport, issuer }: VouchOptions,
	kind: string,
	subjectHash: string,
): Promise<VouchRead> => {
	const where = `issuer_hash = '${issuer.userHash}' AND subject_hash = '${subjectHash}' AND kind = '${kind.replace(/'/g, "''")}'`;
	try {
		const res = await transport.readShapeOnce<Record<string, unknown>>('vouch_tokens', where);
		if (res.kind !== 'rows') return { kind: 'unavailable', error: res };
		const row = res.rows.find((r) => r.kind === kind && r.issuer_hash === issuer.userHash && r.subject_hash === subjectHash);
		if (!row) return { kind: 'absent' };
		if (verifyRow('vouch_tokens', row, issuer.signPkey).status !== 'ok') return { kind: 'unverified', row };
		return {
			kind: 'found',
			row: {
				kind,
				issuer_hash: issuer.userHash,
				subject_hash: subjectHash,
				owner_timestamp: Number(row.owner_timestamp),
				deleted_flag: wireBool(row.deleted_flag),
				sign_b64: String(row.sign_b64),
			},
		};
	} catch (error) {
		return { kind: 'unavailable', error };
	}
};

const setVouch = async (options: VouchOptions, kind: string, subjectHash: string, granted: boolean): Promise<VouchWrite> => {
	const { transport, issuer } = options;
	const now = options.now ?? (() => Math.floor(Date.now() / 1000));
	const maxAttempts = options.maxAttempts ?? 3;
	for (let attempt = 1; ; attempt++) {
		const current = await readVouch(options, kind, subjectHash);
		if (current.kind === 'unverified' || current.kind === 'unavailable') return current;
		if (current.kind === 'found' && current.row.deleted_flag === !granted) return { kind: 'unchanged', row: current.row };
		const previous = current.kind === 'found' ? current.row.owner_timestamp : 0;
		const signed = issuer.signRow('vouch_tokens', {
			...vouchRow({ kind, issuerHash: issuer.userHash, subjectHash }, { granted, ownerTimestamp: Math.max(now(), previous + 1) }),
		});
		const outcome = await transport.ingest([rowMutation('vouch_tokens', signed, current.kind === 'found' ? 'update' : 'insert')], issuer.sign);
		if (outcome.kind === 'written') return { kind: 'written', row: signed as VouchRow, txid: outcome.txid };
		const retry = outcome.rejection.kind === 'exists' || outcome.rejection.kind === 'stale_timestamp';
		if (!retry || attempt >= maxAttempts) return { kind: 'rejected', rejection: outcome.rejection };
	}
};

export const issueVouch = (options: VouchOptions, kind: string, subjectHash: string): Promise<VouchWrite> =>
	setVouch(options, kind, subjectHash, true);

export const retractVouch = (options: VouchOptions, kind: string, subjectHash: string): Promise<VouchWrite> =>
	setVouch(options, kind, subjectHash, false);
