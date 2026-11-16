import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from '@noble/hashes/utils';
import { createTransport, type Mutation } from '@buckitup/pq-client/transport';
import { SIGNABLE, toBytes, verifyRow } from '@buckitup/pq-client/rows';
import { verifyUserCard } from '@buckitup/pq-client/verifyCard';
import type { UserCardRow } from '@buckitup/pq-client/types';

type Row = Record<string, unknown>;

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const text = (status: number, body: string) => new Response(body, { status, headers: { 'content-type': 'text/plain' } });

const KEYS: Record<string, string[]> = {
	user_cards: ['user_hash'],
	user_storage: ['user_hash', 'uuid'],
	vouch_tokens: ['kind', 'issuer_hash', 'subject_hash'],
	origins: ['origin_hash'],
	origin_settings: ['origin_hash', 'key'],
	dialog_keys: ['dialog_hash', 'sender_hash'],
	dialog_messages: ['message_id'],
};

const VERSIONED = new Set(['user_storage', 'dialog_messages']);

const SHAPE_NAMES: Record<string, string> = {
	user_cards: 'user_card',
	vouch_tokens: 'vouch_token',
	user_storage: 'user_storage',
	origins: 'origin',
	origin_settings: 'origin_setting',
	dialog_keys: 'dialog_keys',
	dialog_messages: 'dialog_messages',
};

const UNGATED_SHAPES = new Set(['user_card', 'vouch_token']);

const keyOf = (relation: string, row: Row) => KEYS[relation].map((k) => String(row[k])).join('|');
const fromB64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const sameBinary = (a: unknown, b: unknown) =>
	typeof a === 'string' && typeof b === 'string' && a.replace(/=+$/, '') === b.replace(/=+$/, '');

class Refusal {
	constructor(readonly response: () => Response, readonly row: Row) {}
}

const refuse = (status: number, body: Row) => new Refusal(() => json(status, body), body);
const refuseText = (message: string) => new Refusal(() => text(400, message), { error: message });
const validation = (details: Record<string, string[]>) => refuse(422, { error: 'validation_failed', details });

export type FaultMode = 'before-commit' | 'after-commit';

export interface FakePqServerOptions {
	trust?: { readers: Set<string> };
}

export interface FakePqServer {
	transport: ReturnType<typeof createTransport>;
	tables: Map<string, Map<string, Row>>;
	requests: Array<{ path: string; body: Row | null; authorization: string | null }>;
	pendingReviews: Set<string>;
	hold(match: (path: string, body: Row | null) => boolean): () => void;
	fault(match: (path: string, body: Row | null) => boolean, mode: FaultMode): void;
	fetch: typeof fetch;
}

const timeoutError = () => new DOMException('The operation timed out.', 'TimeoutError');

export function createFakePqServer(options: FakePqServerOptions = {}): FakePqServer {
	const tables = new Map<string, Map<string, Row>>(Object.keys(KEYS).map((t) => [t, new Map()]));
	const challenges = new Map<string, string>();
	const sessions = new Map<string, string>();
	const requests: FakePqServer['requests'] = [];
	const pendingReviews = new Set<string>();
	const holds: Array<{ match: (path: string, body: Row | null) => boolean; gate: Promise<void> }> = [];
	const faults: Array<{ match: (path: string, body: Row | null) => boolean; mode: FaultMode }> = [];
	let n = 0;
	let txid = 1000;

	const card = (userHash: unknown) => tables.get('user_cards')!.get(String(userHash)) as UserCardRow | undefined;
	const pkeyOf = (userHash: unknown) => card(userHash)?.sign_pkey ?? null;
	const signedBy = (relation: string, row: Row, userHash: unknown) => {
		const pkey = pkeyOf(userHash);
		return !!pkey && verifyRow(relation, row, pkey).status === 'ok';
	};
	const proves = (challenge: string, signature: string, pkey: string | null) =>
		!!pkey && ml_dsa87.verify(fromB64(signature), new TextEncoder().encode(challenge), toBytes(pkey));

	const proverFor = (relation: string, type: string, row: Row, existing: Row | undefined): Array<string | null> => {
		switch (relation) {
			case 'user_cards': return [String(row.sign_pkey)];
			case 'user_storage': return [pkeyOf(row.user_hash)];
			case 'vouch_tokens': return [pkeyOf(row.issuer_hash)];
			case 'dialog_keys':
			case 'dialog_messages': return [pkeyOf(row.sender_hash)];
			case 'origins': return type === 'insert' ? [pkeyOf(row.origin_hash)] : [pkeyOf(existing?.owner_hash)];
			case 'origin_settings': {
				const origin = tables.get('origins')!.get(String(row.origin_hash));
				return [pkeyOf(row.origin_hash), pkeyOf(origin?.owner_hash)];
			}
			default: return [];
		}
	};

	const check = (relation: string, type: string, row: Row, existing: Row | undefined): Refusal | null => {
		if (!VERSIONED.has(relation) && type === 'update' && existing && Number(row.owner_timestamp) <= Number(existing.owner_timestamp)) {
			return validation({ owner_timestamp: ['timestamp not newer'] });
		}
		const badSignature = () => validation({ sign_b64: ['invalid signature: invalid_signature'] });
		switch (relation) {
			case 'user_cards':
				return verifyUserCard(row as UserCardRow).status === 'verified' ? null : badSignature();
			case 'user_storage':
				return signedBy(relation, row, row.user_hash) ? null : badSignature();
			case 'vouch_tokens':
				return signedBy(relation, row, row.issuer_hash) ? null : badSignature();
			case 'dialog_keys':
				return signedBy(relation, row, row.sender_hash) ? null : badSignature();
			case 'dialog_messages':
				if (!tables.get('dialog_keys')!.has(`${row.dialog_hash}|${row.sender_hash}`)) return refuseText('dialog_key required before posting to dialog');
				return signedBy(relation, row, row.sender_hash) ? null : badSignature();
			case 'origins': {
				if (!['none', 'post', 'pre'].includes(String(row.moderation_mode))) return validation({ moderation_mode: ['is invalid'] });
				if (type === 'insert') {
					const venue = pkeyOf(row.origin_hash);
					const owner = pkeyOf(row.owner_hash);
					if (!venue || !owner || !ml_dsa87.verify(toBytes(String(row.owner_cert)), toBytes(venue), toBytes(owner))) {
						return validation({ owner_cert: ['invalid owner certificate'] });
					}
					return signedBy(relation, row, row.origin_hash) ? null : badSignature();
				}
				return signedBy(relation, row, row.origin_hash) || signedBy(relation, row, existing?.owner_hash) ? null : badSignature();
			}
			case 'origin_settings': {
				if (!tables.get('origins')!.has(String(row.origin_hash))) return refuseText('Invalid operation');
				if (row.key === 'review_access' && !['open', 'invite_only'].includes(String(row.value))) return validation({ value: ['is invalid'] });
				if (row.key === 'review_token_ttl_days') {
					const days = Number(row.value);
					if (!/^\d+$/.test(String(row.value)) || days < 1 || days > 365) return validation({ value: ['must be an integer in 1..365'] });
				}
				const owner = tables.get('origins')!.get(String(row.origin_hash))?.owner_hash;
				if (type === 'insert') return signedBy(relation, row, row.origin_hash) ? null : badSignature();
				return signedBy(relation, row, row.origin_hash) || signedBy(relation, row, owner) ? null : badSignature();
			}
			default:
				return refuseText(`unknown relation ${relation}`);
		}
	};

	const apply = (m: Mutation, challenge: string, signature: string): Refusal | null => {
		const relation = String((m.syncMetadata as Row).relation);
		const table = tables.get(relation);
		if (!table) return refuseText(`unknown relation ${relation}`);
		const type = String(m.type);
		const incoming = { ...((type === 'insert' ? m.modified : m.changes) as Row) };
		const key = keyOf(relation, type === 'insert' ? incoming : { ...incoming, ...(m.original as Row) });
		const existing = table.get(key);
		if (type === 'update' && !existing) return refuseText('Invalid operation');
		const row = type === 'insert' ? incoming : { ...existing, ...incoming };
		if (!proverFor(relation, type, row, existing).some((pkey) => proves(challenge, signature, pkey))) {
			return refuseText('Invalid operation');
		}
		if (relation === 'origins' && type === 'update' && pendingReviews.has(String(row.origin_hash))) {
			return refuseText('Cannot modify origin while reviews are pending moderation');
		}
		const refusal = check(relation, type, row, existing);
		if (refusal) return refusal;
		if (VERSIONED.has(relation) && existing) {
			if (Number(row.owner_timestamp) <= Number(existing.owner_timestamp)) return validation({ owner_timestamp: ['timestamp not newer'] });
			row.parent_sign_hash = existing.sign_hash;
		}
		if (type === 'insert' && existing) {
			const fingerprint = (r: Row) => (r.sign_hash !== undefined && r.sign_hash !== null ? r.sign_hash : r.sign_b64);
			const conflicted = VERSIONED.has(relation) ? fingerprint(existing) !== fingerprint(row) : !sameBinary(existing.sign_b64, row.sign_b64);
			return refuse(409, { status: 'exists', conflicted });
		}
		const stored: Row = {};
		for (const field of [...Object.keys(SIGNABLE[relation]), 'sign_b64', ...(row.sign_hash !== undefined ? ['sign_hash'] : [])]) stored[field] = row[field];
		table.set(key, stored);
		return null;
	};

	const takeChallenge = (auth: Row | undefined) => {
		const challenge = challenges.get(String(auth?.challenge_id));
		challenges.delete(String(auth?.challenge_id));
		return challenge;
	};

	const shapeRows = (table: string, where: string) => {
		const conditions = where.split(' AND ').map((c) => c.trim()).filter((c) => !/^\d+=\d+$/.test(c));
		const wanted = conditions.map((c) => {
			const m = /^(\w+)\s*=\s*'((?:[^']|'')*)'$/.exec(c);
			if (!m) throw new Error(`fake server cannot parse where: ${c}`);
			return [m[1], m[2].replace(/''/g, "'")] as const;
		});
		return [...tables.get(table)!.values()].filter((row) => wanted.every(([col, val]) => String(row[col]) === val));
	};

	const onWire = (table: string, row: Row): Row => {
		const out: Row = {};
		for (const [k, v] of Object.entries(row)) {
			const binary = SIGNABLE[table]?.[k] === 'binary' || k === 'sign_b64';
			out[k] = typeof v === 'boolean' ? (v ? 't' : 'f') : binary && typeof v === 'string' ? v.replace(/=+$/, '') : typeof v === 'number' ? String(v) : v;
		}
		return out;
	};

	const takeFault = (path: string, body: Row | null) => {
		const index = faults.findIndex((f) => f.match(path, body));
		return index >= 0 ? faults.splice(index, 1)[0].mode : null;
	};

	const fetchImpl = (async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
		if (init?.signal?.aborted) throw init.signal.reason ?? new DOMException('aborted', 'AbortError');
		const url = new URL(String(input));
		const path = url.pathname.replace('/electric/v1', '');
		const body = init?.body ? (JSON.parse(String(init.body)) as Row) : null;
		const authorization = new Headers(init?.headers).get('authorization');
		requests.push({ path, body, authorization });
		for (const h of holds) if (h.match(path, body)) await h.gate;
		const fault = takeFault(path, body);
		if (fault === 'before-commit') throw timeoutError();
		if (path === '/challenge') {
			const id = `c${++n}`;
			challenges.set(id, Array.from(randomBytes(32), (b) => b.toString(16).padStart(2, '0')).join(''));
			return json(200, { challenge_id: id, challenge: challenges.get(id), expires_in: 60 });
		}
		if (path === '/device_identity') return json(200, { device_id: 'Server_test_example', admin: null, sync_bot: null });
		if (path === '/read_session') {
			const shape = String(body?.shape);
			if (!Object.values(SHAPE_NAMES).includes(shape)) return json(400, { error: 'unknown_shape' });
			const challenge = takeChallenge(body ?? undefined);
			if (!challenge) return json(401, { error: 'Invalid or expired challenge' });
			if (!card(body?.user_hash)) return json(401, { error: 'unknown_user' });
			if (!proves(challenge, String(body?.signature), pkeyOf(body?.user_hash))) return json(401, { error: 'invalid_signature' });
			if (!options.trust?.readers.has(String(body?.user_hash))) return json(403, { error: 'not_in_trust_chain', max_depth: 7 });
			const token = `t${++n}`;
			sessions.set(token, shape);
			return json(200, { token, shape, expires_in: 300 });
		}
		if (path === '/shapes') {
			const table = url.searchParams.get('table')!;
			const shape = SHAPE_NAMES[table];
			if (options.trust && !UNGATED_SHAPES.has(shape)) {
				const token = authorization?.startsWith('Bearer ') ? authorization.slice(7) : null;
				if (!token || sessions.get(token) !== shape) return json(401, { error: 'read_session_required', shape });
			}
			const rows = shapeRows(table, url.searchParams.get('where') ?? '');
			return json(200, [...rows.map((row) => ({ key: keyOf(table, row), value: onWire(table, row), headers: { operation: 'insert' } })), { headers: { control: 'up-to-date' } }]);
		}
		const auth = body?.auth as Row | undefined;
		const challenge = takeChallenge(auth);
		if (!challenge) return json(401, { error: 'Invalid or expired challenge' });
		const mutations = (body?.mutations ?? []) as Mutation[];
		if (path === '/ingest') {
			const snapshot = new Map([...tables].map(([t, m]) => [t, new Map(m)]));
			for (const m of mutations) {
				const refusal = apply(m, challenge, String(auth?.signature));
				if (refusal) {
					for (const [t, m2] of snapshot) tables.set(t, m2);
					return refusal.response();
				}
			}
			if (fault === 'after-commit') throw timeoutError();
			return json(200, { txid: ++txid });
		}
		if (path === '/ingest_each') {
			const results = mutations.map((m, index) => {
				const refusal = apply(m, challenge, String(auth?.signature));
				if (!refusal) return { index, status: 'ok', txid: ++txid };
				return 'status' in refusal.row ? { index, ...refusal.row } : { index, status: 'error', ...refusal.row };
			});
			if (fault === 'after-commit') throw timeoutError();
			const failed = results.filter((r) => r.status === 'error');
			return json(failed.length ? 422 : 200, { results });
		}
		return json(404, { error: 'not found' });
	}) as typeof fetch;

	return {
		transport: createTransport({ baseUrl: 'https://fake.example/electric/v1', fetch: fetchImpl }),
		tables,
		requests,
		pendingReviews,
		fetch: fetchImpl,
		hold(match) {
			let release!: () => void;
			const gate = new Promise<void>((r) => (release = r));
			const entry = { match, gate };
			holds.push(entry);
			return () => {
				holds.splice(holds.indexOf(entry), 1);
				release();
			};
		},
		fault(match, mode) {
			faults.push({ match, mode });
		},
	};
}
