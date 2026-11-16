import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { generateIdentityKeys, userHashOf, wipeIdentityKeys, type IdentityHandle } from './identity.js';
import type { ReadSessions } from './readSessions.js';
import { rowMutation, toBase64, toBytes, verifyRow, wireBool, type RowVerdict } from './rows.js';
import { loadOriginKeys, originKeysRecord, putOriginKeys, type UserStorage } from './storage.js';
import type { Transport, WriteRejection } from './transport.js';
import type { ModerationMode, OriginRow, OriginSettingRow, UserCardRow } from './types.js';
import { verifyUserCard } from './verifyCard.js';

export type { ModerationMode, OriginRow, OriginSettingRow };

export const MODERATION_MODES: readonly ModerationMode[] = ['none', 'post', 'pre'];
export const PENDING_MODERATION_ERROR = 'Cannot modify origin while reviews are pending moderation';

export const ownerCert = (owner: IdentityHandle, venueSignPkey: Uint8Array): string => toBase64(owner.sign(venueSignPkey));

export const verifyOwnerCert = (cert: string | Uint8Array, venueSignPkey: string | Uint8Array, ownerSignPkey: string | Uint8Array): boolean => {
	try {
		return ml_dsa87.verify(toBytes(cert), toBytes(venueSignPkey), toBytes(ownerSignPkey));
	} catch {
		return false;
	}
};

export interface OriginInput {
	name: string;
	moderationMode?: ModerationMode;
	ownerTimestamp: number;
}

export const originRow = (venue: IdentityHandle, owner: IdentityHandle, input: OriginInput): OriginRow => {
	if (!input.name) throw new TypeError('origin: the name must not be empty');
	const moderationMode = input.moderationMode ?? 'none';
	if (!MODERATION_MODES.includes(moderationMode)) throw new TypeError(`origin: moderation_mode must be one of ${MODERATION_MODES.join(', ')}`);
	return {
		origin_hash: venue.userHash,
		owner_hash: owner.userHash,
		owner_cert: ownerCert(owner, venue.signPkey),
		name: input.name,
		moderation_mode: moderationMode,
		deleted_flag: false,
		owner_timestamp: input.ownerTimestamp,
		sign_b64: null,
		sign_hash: null,
	};
};

export type OriginVerdict =
	| { status: 'ok'; signer: 'venue' | 'owner' }
	| { status: 'invalid'; reason: 'bad_owner_cert' | Extract<RowVerdict, { status: 'invalid' }>['reason'] };

export const verifyOriginRow = (
	row: Record<string, unknown>,
	{ venueSignPkey, ownerSignPkey }: { venueSignPkey: string | Uint8Array; ownerSignPkey: string | Uint8Array },
): OriginVerdict => {
	if (typeof row.owner_cert !== 'string' || !verifyOwnerCert(row.owner_cert, venueSignPkey, ownerSignPkey)) {
		return { status: 'invalid', reason: 'bad_owner_cert' };
	}
	const byVenue = verifyRow('origins', row, venueSignPkey);
	if (byVenue.status === 'ok') return { status: 'ok', signer: 'venue' };
	if (byVenue.reason !== 'bad_signature') return byVenue;
	const byOwner = verifyRow('origins', row, ownerSignPkey);
	return byOwner.status === 'ok' ? { status: 'ok', signer: 'owner' } : byOwner;
};

export interface OriginContext {
	transport: Pick<Transport, 'readShapeOnce' | 'ingest'>;
	owner: IdentityHandle;
	storage: UserStorage;
	sessions?: ReadSessions | null;
	now?: () => number;
	maxAttempts?: number;
}

const assertContext = (ctx: OriginContext) => {
	if (ctx.storage.ownerHash !== ctx.owner.userHash) throw new TypeError('origins: the storage belongs to another identity than the owner');
	if (ctx.sessions && ctx.sessions.userHash !== ctx.owner.userHash) throw new TypeError('origins: the read sessions belong to another identity than the owner');
};

type Ingested = Awaited<ReturnType<Transport['ingest']>> | { kind: 'unknown'; error: unknown };

const tryIngest = async (ctx: OriginContext, ...args: Parameters<Transport['ingest']>): Promise<Ingested> => {
	try {
		return await ctx.transport.ingest(...args);
	} catch (error) {
		return { kind: 'unknown', error };
	}
};

const nowOf = (ctx: OriginContext) => (ctx.now ?? (() => Math.floor(Date.now() / 1000)))();

type Read<T> = { kind: 'found'; row: T } | { kind: 'absent' } | { kind: 'unverified'; row: Record<string, unknown> } | { kind: 'unavailable'; error: unknown };

const readOne = async (ctx: OriginContext, table: string, where: string, pick: (row: Record<string, unknown>) => boolean) => {
	try {
		const read = () => ctx.transport.readShapeOnce<Record<string, unknown>>(table, where, { authorization: ctx.sessions?.bearer(table) ?? undefined });
		let res = await read();
		if (res.kind === 'read_session_required' && ctx.sessions && (await ctx.sessions.reopen(res.shape, table)).kind === 'opened') res = await read();
		if (res.kind !== 'rows') return { kind: 'unavailable' as const, error: res };
		return { kind: 'rows' as const, row: res.rows.find(pick) ?? null };
	} catch (error) {
		return { kind: 'unavailable' as const, error };
	}
};

const readVenueCard = async (ctx: OriginContext, originHash: string): Promise<Read<UserCardRow>> => {
	const res = await readOne(ctx, 'user_cards', `user_hash = '${originHash}'`, (r) => r.user_hash === originHash);
	if (res.kind === 'unavailable') return res;
	if (!res.row) return { kind: 'absent' };
	return verifyUserCard(res.row as UserCardRow).status === 'verified' ? { kind: 'found', row: res.row as UserCardRow } : { kind: 'unverified', row: res.row };
};

export const readOrigin = async (ctx: OriginContext, originHash: string): Promise<Read<OriginRow> & { signer?: 'venue' | 'owner' }> => {
	const res = await readOne(ctx, 'origins', `origin_hash = '${originHash}'`, (r) => r.origin_hash === originHash);
	if (res.kind === 'unavailable') return res;
	if (!res.row) return { kind: 'absent' };
	if (res.row.owner_hash !== ctx.owner.userHash) return { kind: 'unverified', row: res.row };
	const card = await readVenueCard(ctx, originHash);
	if (card.kind === 'unavailable') return card;
	if (card.kind !== 'found' || !card.row.sign_pkey) return { kind: 'unverified', row: res.row };
	const verdict = verifyOriginRow(res.row, { venueSignPkey: card.row.sign_pkey, ownerSignPkey: ctx.owner.signPkey });
	if (verdict.status !== 'ok') return { kind: 'unverified', row: res.row };
	return {
		kind: 'found',
		signer: verdict.signer,
		row: { ...(res.row as OriginRow), deleted_flag: wireBool(res.row.deleted_flag), owner_timestamp: Number(res.row.owner_timestamp) },
	};
};

export type OriginStep = 'keys' | 'card' | 'origin';

export type OriginFailure =
	| { kind: 'rejected'; rejection: WriteRejection }
	| { kind: 'unknown'; detail?: unknown }
	| { kind: 'unavailable' | 'unverified' | 'undecryptable' | 'mismatch' | 'absent'; detail?: unknown };

export type CreateOrigin =
	| { kind: 'created'; originHash: string; venue: IdentityHandle; row: OriginRow }
	| { kind: 'incomplete'; originHash: string | null; completed: OriginStep[]; failed: OriginStep; reason: OriginFailure };

export const createOrigin = async (ctx: OriginContext, input: Omit<OriginInput, 'ownerTimestamp'>): Promise<CreateOrigin> => {
	assertContext(ctx);
	const keys = generateIdentityKeys();
	const originHash = userHashOf(keys.signPkey);
	const record = originKeysRecord(input.name, keys);
	wipeIdentityKeys(keys);
	const stored = await putOriginKeys(ctx.storage, originHash, record);
	if (stored.kind === 'written') return resumeOrigin(ctx, originHash, input);
	if (stored.kind === 'unknown') return { kind: 'incomplete', originHash, completed: [], failed: 'keys', reason: { kind: 'unknown', detail: stored.error } };
	return {
		kind: 'incomplete',
		originHash: null,
		completed: [],
		failed: 'keys',
		reason: stored.kind === 'rejected' ? { kind: 'rejected', rejection: stored.rejection } : { kind: stored.kind, detail: stored },
	};
};

const ingestFailure = (outcome: Exclude<Ingested, { kind: 'written' }>): OriginFailure =>
	outcome.kind === 'unknown' ? { kind: 'unknown', detail: outcome.error } : { kind: 'rejected', rejection: outcome.rejection };

const publishVenue = async (ctx: OriginContext, originHash: string, input: Omit<OriginInput, 'ownerTimestamp'>, venue: IdentityHandle): Promise<CreateOrigin> => {
	const incomplete = (completed: OriginStep[], failed: OriginStep, reason: OriginFailure): CreateOrigin =>
		({ kind: 'incomplete', originHash, completed, failed, reason });

	let card = await readVenueCard(ctx, originHash);
	if (card.kind === 'absent') {
		const outcome = await tryIngest(
			ctx,
			[rowMutation('user_cards', venue.userCard({ name: input.name, ownerTimestamp: nowOf(ctx) }))],
			venue.sign,
		);
		if (outcome.kind !== 'written' && !(outcome.kind === 'rejected' && outcome.rejection.kind === 'exists')) {
			return incomplete(['keys'], 'card', ingestFailure(outcome));
		}
		if (outcome.kind === 'rejected') card = await readVenueCard(ctx, originHash);
	}
	if (card.kind !== 'found' && card.kind !== 'absent') return incomplete(['keys'], 'card', { kind: card.kind, detail: card });

	const existing = await readOrigin(ctx, originHash);
	if (existing.kind === 'found') return { kind: 'created', originHash, venue, row: existing.row };
	if (existing.kind !== 'absent') return incomplete(['keys', 'card'], 'origin', { kind: existing.kind, detail: existing });
	const signed = venue.signRow('origins', originRow(venue, ctx.owner, { ...input, ownerTimestamp: nowOf(ctx) }));
	const outcome = await tryIngest(ctx, [rowMutation('origins', signed)], venue.sign);
	if (outcome.kind === 'written') return { kind: 'created', originHash, venue, row: { ...(signed as OriginRow) } };
	if (outcome.kind === 'rejected' && outcome.rejection.kind === 'exists') {
		const after = await readOrigin(ctx, originHash);
		if (after.kind === 'found') return { kind: 'created', originHash, venue, row: after.row };
	}
	return incomplete(['keys', 'card'], 'origin', ingestFailure(outcome));
};

export const resumeOrigin = async (
	ctx: OriginContext,
	originHash: string,
	input: Omit<OriginInput, 'ownerTimestamp'>,
): Promise<CreateOrigin> => {
	assertContext(ctx);
	const loaded = await loadOriginKeys(ctx.storage, originHash);
	if (loaded.kind !== 'found') {
		return { kind: 'incomplete', originHash, completed: [], failed: 'keys', reason: { kind: loaded.kind, detail: loaded } };
	}
	const result = await publishVenue(ctx, originHash, input, loaded.identity).catch((error: unknown) => {
		loaded.identity.close();
		throw error;
	});
	if (result.kind !== 'created') loaded.identity.close();
	return result;
};

export const openOrigin = async (ctx: OriginContext, originHash: string) => loadOriginKeys(ctx.storage, originHash);

export type OriginWrite<T> =
	| { kind: 'written'; row: T; txid: number }
	| { kind: 'pending_moderation' }
	| { kind: 'rejected'; rejection: WriteRejection }
	| { kind: 'unknown'; detail?: unknown }
	| { kind: 'absent' | 'unverified' | 'unavailable' | 'no_venue_keys'; detail?: unknown };

const venueHandle = async (ctx: OriginContext, originHash: string): Promise<IdentityHandle | null> => {
	const loaded = await loadOriginKeys(ctx.storage, originHash);
	return loaded.kind === 'found' ? loaded.identity : null;
};

const withVenue = async <T>(ctx: OriginContext, originHash: string, use: (venue: IdentityHandle | null) => Promise<T>): Promise<T> => {
	const venue = await venueHandle(ctx, originHash);
	try {
		return await use(venue);
	} finally {
		venue?.close();
	}
};

export interface OriginChange {
	name?: string;
	moderationMode?: ModerationMode;
	deleted?: boolean;
}

export const updateOrigin = async (
	ctx: OriginContext,
	originHash: string,
	change: OriginChange,
	{ signer = 'owner' }: { signer?: 'owner' | 'venue' } = {},
): Promise<OriginWrite<OriginRow>> => {
	assertContext(ctx);
	if (change.moderationMode && !MODERATION_MODES.includes(change.moderationMode)) {
		throw new TypeError(`origin: moderation_mode must be one of ${MODERATION_MODES.join(', ')}`);
	}
	if (signer === 'owner') return writeOrigin(ctx, originHash, change, ctx.owner);
	return withVenue(ctx, originHash, (venue) => (venue ? writeOrigin(ctx, originHash, change, venue) : Promise.resolve({ kind: 'no_venue_keys' as const })));
};

const writeOrigin = async (ctx: OriginContext, originHash: string, change: OriginChange, by: IdentityHandle): Promise<OriginWrite<OriginRow>> => {
	for (let attempt = 1; ; attempt++) {
		const current = await readOrigin(ctx, originHash);
		if (current.kind !== 'found') return { kind: current.kind, detail: current };
		const next: OriginRow = {
			...current.row,
			name: change.name ?? current.row.name,
			moderation_mode: change.moderationMode ?? current.row.moderation_mode,
			deleted_flag: change.deleted ?? current.row.deleted_flag,
			owner_timestamp: Math.max(nowOf(ctx), current.row.owner_timestamp + 1),
			sign_b64: null,
			sign_hash: null,
		};
		const signed = by.signRow('origins', next);
		const outcome = await tryIngest(ctx, [rowMutation('origins', signed, 'update')], ctx.owner.sign);
		if (outcome.kind === 'unknown') return { kind: 'unknown', detail: outcome.error };
		if (outcome.kind === 'written') return { kind: 'written', row: signed as OriginRow, txid: outcome.txid };
		if (outcome.rejection.kind === 'rejected' && outcome.rejection.error === PENDING_MODERATION_ERROR) return { kind: 'pending_moderation' };
		if (outcome.rejection.kind !== 'stale_timestamp' || attempt >= (ctx.maxAttempts ?? 3)) return { kind: 'rejected', rejection: outcome.rejection };
	}
};

export class OriginSettingError extends Error {
	constructor(readonly key: string, message: string) {
		super(message);
		this.name = 'OriginSettingError';
	}
}

export const checkOriginSetting = (key: string, value: string): void => {
	if (!key) throw new OriginSettingError(key, 'origin setting: the key must not be empty');
	if (key === 'review_access' && !['open', 'invite_only'].includes(value)) {
		throw new OriginSettingError(key, 'origin setting review_access must be open or invite_only');
	}
	if (key === 'review_token_ttl_days') {
		const days = Number(value);
		if (!/^\d+$/.test(value) || days < 1 || days > 365) throw new OriginSettingError(key, 'origin setting review_token_ttl_days must be an integer in 1..365');
	}
};

const readSetting = async (ctx: OriginContext, originHash: string, key: string, venueSignPkey: Uint8Array): Promise<Read<OriginSettingRow>> => {
	const res = await readOne(ctx, 'origin_settings', `origin_hash = '${originHash}' AND key = '${key.replace(/'/g, "''")}'`, (r) => r.origin_hash === originHash && r.key === key);
	if (res.kind === 'unavailable') return res;
	if (!res.row) return { kind: 'absent' };
	const ok = verifyRow('origin_settings', res.row, venueSignPkey).status === 'ok' || verifyRow('origin_settings', res.row, ctx.owner.signPkey).status === 'ok';
	if (!ok) return { kind: 'unverified', row: res.row };
	return { kind: 'found', row: { ...(res.row as OriginSettingRow), deleted_flag: wireBool(res.row.deleted_flag), owner_timestamp: Number(res.row.owner_timestamp) } };
};

export const setOriginSetting = async (
	ctx: OriginContext,
	originHash: string,
	key: string,
	value: string,
	{ signer = 'venue', prover = signer, deleted = false }: { signer?: 'owner' | 'venue'; prover?: 'owner' | 'venue'; deleted?: boolean } = {},
): Promise<OriginWrite<OriginSettingRow>> => {
	assertContext(ctx);
	checkOriginSetting(key, value);
	return withVenue(ctx, originHash, async (venue) => {
		if (!venue) return { kind: 'no_venue_keys' };
		const by = signer === 'owner' ? ctx.owner : venue;
		const proof = prover === 'owner' ? ctx.owner : venue;
		for (let attempt = 1; ; attempt++) {
			const current = await readSetting(ctx, originHash, key, venue.signPkey);
			if (current.kind === 'unverified' || current.kind === 'unavailable') return { kind: current.kind, detail: current };
			const insert = current.kind === 'absent';
			if (insert && signer !== 'venue') throw new OriginSettingError(key, 'an origin setting is created signed by the origin itself');
			const signed = by.signRow('origin_settings', {
				origin_hash: originHash,
				key,
				value,
				deleted_flag: deleted,
				owner_timestamp: Math.max(nowOf(ctx), insert ? 0 : current.row.owner_timestamp + 1),
			});
			const outcome = await tryIngest(ctx, [rowMutation('origin_settings', signed, insert ? 'insert' : 'update')], proof.sign);
			if (outcome.kind === 'unknown') return { kind: 'unknown', detail: outcome.error };
			if (outcome.kind === 'written') return { kind: 'written', row: signed as OriginSettingRow, txid: outcome.txid };
			const retry = outcome.rejection.kind === 'stale_timestamp' || outcome.rejection.kind === 'exists';
			if (!retry || attempt >= (ctx.maxAttempts ?? 3)) return { kind: 'rejected', rejection: outcome.rejection };
		}
	});
};

export const removeOriginSetting = (
	ctx: OriginContext,
	originHash: string,
	key: string,
	value: string,
	opts: { signer?: 'owner' | 'venue'; prover?: 'owner' | 'venue' } = {},
) => setOriginSetting(ctx, originHash, key, value, { ...opts, deleted: true });
