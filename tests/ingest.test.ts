import { describe, it, expect } from 'vitest';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from '@noble/hashes/utils';
import {
	createTransport,
	classifyRowResult,
	TransportError,
	type Mutation,
	type WriteRejection,
} from '@buckitup/pq-client/transport';

const owner = ml_dsa87.keygen(randomBytes(32));
const stranger = ml_dsa87.keygen(randomBytes(32));
const signAs = (secretKey: Uint8Array) => (m: Uint8Array) => ml_dsa87.sign(m, secretKey);

const fromB64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
	new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
const text = (status: number, body: string) => new Response(body, { status, headers: { 'content-type': 'text/plain' } });

interface Row { id: string; owner_timestamp: number }
const insert = (id: string, owner_timestamp = 1): Mutation => ({
	type: 'insert',
	syncMetadata: { relation: 'things' },
	modified: { id, owner_timestamp },
});

type Verdict = { ok: true } | { ok: false; row: Record<string, unknown>; status: number; body: unknown };

const server = () => {
	const challenges = new Map<string, string>();
	const table = new Map<string, Row>();
	let txid = 100;
	let n = 0;
	const calls: string[] = [];
	const proofOk = (auth: { challenge_id?: string; signature?: string } | undefined) => {
		const challenge = challenges.get(String(auth?.challenge_id));
		challenges.delete(String(auth?.challenge_id));
		if (!challenge || !auth?.signature || auth.signature.endsWith('=')) return false;
		return ml_dsa87.verify(fromB64(auth.signature), new TextEncoder().encode(challenge), owner.publicKey);
	};
	const check = (m: Mutation): Verdict => {
		const row = (m as { modified: Row }).modified;
		const existing = table.get(row.id);
		if (row.id.startsWith('gate')) return { ok: false, row: { error: 'not_in_trust_chain', max_depth: 7 }, status: 403, body: { error: 'not_in_trust_chain', max_depth: 7 } };
		if (row.id.startsWith('orphan')) {
			const details = { parent_sign_hash: ['does not exist'] };
			return { ok: false, row: { error: 'validation_failed', details }, status: 422, body: { error: 'validation_failed', details } };
		}
		if (existing && existing.owner_timestamp === row.owner_timestamp) {
			return { ok: false, row: { status: 'exists', conflicted: false }, status: 409, body: { status: 'exists', conflicted: false } };
		}
		if (existing && row.owner_timestamp <= existing.owner_timestamp) {
			const details = { owner_timestamp: ['timestamp not newer'] };
			return { ok: false, row: { error: 'validation_failed', details }, status: 422, body: { error: 'validation_failed', details } };
		}
		return { ok: true };
	};
	const fetchImpl = (async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
		const path = new URL(String(input), 'http://h').pathname.replace(/^\/api/, '');
		calls.push(path);
		if (path === '/challenge') {
			const id = `c${++n}`;
			challenges.set(id, Array.from(randomBytes(32), (b) => b.toString(16).padStart(2, '0')).join(''));
			return json(200, { challenge_id: id, challenge: challenges.get(id), expires_in: 60 });
		}
		const body = JSON.parse(String(init?.body)) as { auth?: { challenge_id?: string; signature?: string }; mutations: Mutation[] };
		if (!proofOk(body.auth)) return json(401, { error: 'Invalid or expired challenge' });
		if (path === '/ingest') {
			const verdicts = body.mutations.map(check);
			const refused = verdicts.find((v): v is Extract<Verdict, { ok: false }> => !v.ok);
			if (refused) return json(refused.status, refused.body);
			for (const m of body.mutations) {
				const row = (m as { modified: Row }).modified;
				table.set(row.id, row);
			}
			return json(200, { txid: ++txid });
		}
		const results = body.mutations.map((m, index) => {
			const verdict = check(m);
			if (!verdict.ok) {
				const r = verdict.row;
				return 'status' in r ? { index, ...r } : { index, status: 'error', ...r };
			}
			const row = (m as { modified: Row }).modified;
			table.set(row.id, row);
			return { index, status: 'ok', txid: ++txid };
		});
		const failed = results.filter((r) => r.status === 'error');
		const status = !failed.length ? 200 : failed.every((r) => (r as { error?: string }).error === 'not_in_trust_chain') ? 403 : 422;
		return json(status, { results });
	}) as typeof fetch;
	return { fetchImpl, table, calls };
};

const transportOn = (s: ReturnType<typeof server>) => createTransport({ baseUrl: '/api', fetch: s.fetchImpl });

describe('POST /ingest: one transaction', () => {
	it('writes every row and returns the txid', async () => {
		const s = server();
		expect(await transportOn(s).ingest([insert('a'), insert('b')], signAs(owner.secretKey))).toEqual({ kind: 'written', txid: 101 });
		expect([...s.table.keys()]).toEqual(['a', 'b']);
		expect(s.calls).toEqual(['/challenge', '/ingest']);
	});

	it('writes nothing when one row is refused, where ingest_each writes the others', async () => {
		const atomic = server();
		atomic.table.set('a', { id: 'a', owner_timestamp: 5 });
		const outcome = await transportOn(atomic).ingest([insert('b'), insert('a', 5 - 1)], signAs(owner.secretKey));
		expect(outcome).toMatchObject({ kind: 'rejected', status: 422, rejection: { kind: 'stale_timestamp' } });
		expect(atomic.table.has('b')).toBe(false);

		const each = server();
		each.table.set('a', { id: 'a', owner_timestamp: 5 });
		const rows = await transportOn(each).ingestEach([insert('b'), insert('a', 4)], signAs(owner.secretKey));
		expect(rows).toMatchObject({
			kind: 'results',
			status: 422,
			rows: [{ index: 0, kind: 'written', txid: 101 }, { index: 1, kind: 'rejected', rejection: { kind: 'stale_timestamp' } }],
		});
		expect(each.table.has('b')).toBe(true);
	});

	it('ingest_each answers 403 when the gate is the only refusal, and names a missing parent per row', async () => {
		const gated = await transportOn(server()).ingestEach([insert('gate-1'), insert('gate-2')], signAs(owner.secretKey));
		expect(gated).toMatchObject({ kind: 'results', status: 403 });
		expect(gated.kind === 'results' && gated.rows.map((r) => r.kind === 'rejected' && r.rejection.kind)).toEqual(['gate', 'gate']);
		const orphan = await transportOn(server()).ingestEach([insert('gate-1'), insert('orphan-1')], signAs(owner.secretKey));
		expect(orphan).toMatchObject({ status: 422, rows: [{ rejection: { kind: 'gate', maxDepth: 7 } }, { rejection: { kind: 'missing_parent' } }] });
	});

	it('is proved by the identity whose signer it is given', async () => {
		const s = server();
		const outcome = await transportOn(s).ingest([insert('a')], signAs(stranger.secretKey));
		expect(outcome).toEqual({ kind: 'rejected', status: 401, rejection: { kind: 'proof_rejected', error: 'Invalid or expired challenge' } });
		expect(s.table.size).toBe(0);
	});
});

describe('write rejections, as electric_controller.ex answers them', () => {
	const answerWith = (response: () => Response) =>
		createTransport({
			baseUrl: 'https://x.example/electric/v1',
			fetch: (async (input: Parameters<typeof fetch>[0]) =>
				String(input).endsWith('/challenge') ? json(200, { challenge_id: 'c', challenge: 'ab'.repeat(32) }) : response()) as typeof fetch,
		});
	const rejectionOf = async (response: () => Response): Promise<WriteRejection> => {
		const outcome = await answerWith(response).ingest([insert('a')], signAs(owner.secretKey));
		if (outcome.kind !== 'rejected') throw new Error('expected a rejection');
		return outcome.rejection;
	};

	it.each<[string, () => Response, WriteRejection]>([
		['403 gate', () => json(403, { error: 'not_in_trust_chain', max_depth: 7 }), { kind: 'gate', error: 'not_in_trust_chain', maxDepth: 7 }],
		['422 stale timestamp', () => json(422, { error: 'validation_failed', details: { owner_timestamp: ['timestamp not newer'] } }),
			{ kind: 'stale_timestamp', details: { owner_timestamp: ['timestamp not newer'] } }],
		['422 missing parent', () => json(422, { error: 'validation_failed', details: { parent_sign_hash: ['does not exist'] } }),
			{ kind: 'missing_parent', fields: ['parent_sign_hash'], details: { parent_sign_hash: ['does not exist'] } }],
		['422 unique key', () => json(422, { error: 'validation_failed', details: { reaction_hash: ['has already been taken'] } }),
			{ kind: 'unique_conflict', fields: ['reaction_hash'], details: { reaction_hash: ['has already been taken'] } }],
		['422 other validation', () => json(422, { error: 'validation_failed', details: { value: ['is invalid'] } }),
			{ kind: 'validation', details: { value: ['is invalid'] } }],
		['409 exact retry', () => json(409, { status: 'exists', conflicted: false }), { kind: 'exists', conflicted: false }],
		['409 another revision', () => json(409, { status: 'exists', conflicted: true }), { kind: 'exists', conflicted: true }],
		['409 pub_key_taken', () => json(409, { error: 'pub_key_taken' }), { kind: 'pub_key_taken' }],
		['401 proof', () => json(401, { error: 'Missing user PoP auth' }), { kind: 'proof_rejected', error: 'Missing user PoP auth' }],
		['400 malformed request', () => json(400, { error: 'invalid mutation' }), { kind: 'bad_request', error: 'invalid mutation' }],
		['400 row check, plain text', () => text(400, 'Invalid operation'), { kind: 'rejected', error: 'Invalid operation' }],
	])('%s', async (_name, response, expected) => {
		expect(await rejectionOf(response)).toEqual(expected);
	});

	it('maps the per-row results of ingest_each the same way', () => {
		expect(classifyRowResult({ index: 0, status: 'error', error: 'not_in_trust_chain' })).toEqual({
			index: 0, kind: 'rejected', rejection: { kind: 'gate', error: 'not_in_trust_chain', maxDepth: null },
		});
		expect(classifyRowResult({ index: 1, status: 'exists', conflicted: false })).toEqual({
			index: 1, kind: 'rejected', rejection: { kind: 'exists', conflicted: false },
		});
		expect(classifyRowResult({ index: 2, status: 'error', error: 'validation_failed', details: { parent_sign_hash: ['does not exist'] } }))
			.toMatchObject({ rejection: { kind: 'missing_parent', fields: ['parent_sign_hash'] } });
		expect(classifyRowResult({ index: 3, status: 'error', error: 'unknown_error' })).toMatchObject({ rejection: { kind: 'rejected', error: 'unknown_error' } });
	});

	it('a 503 is a transport error carrying retry-after, and nothing is retried behind the caller', async () => {
		let writes = 0;
		const t = createTransport({
			baseUrl: '/api',
			fetch: (async (input: Parameters<typeof fetch>[0]) => {
				if (String(input).endsWith('/challenge')) return json(200, { challenge_id: 'c', challenge: 'ab'.repeat(32) });
				writes++;
				return json(503, { error: 'database_timeout', message: 'busy' }, { 'retry-after': '5' });
			}) as typeof fetch,
		});
		for (const write of [() => t.ingest([insert('a')], signAs(owner.secretKey)), () => t.ingestEach([insert('a')], signAs(owner.secretKey))]) {
			const e = (await write().catch((err: unknown) => err)) as TransportError;
			expect(e).toBeInstanceOf(TransportError);
			expect(e).toMatchObject({ kind: 'http', status: 503, retryAfter: 5, network: false, body: { error: 'database_timeout' } });
		}
		expect(writes).toBe(2);
	});

	it('an answer that is not the API\'s is malformed, not a rejection', async () => {
		const e = (await answerWith(() => json(200, { ok: true })).ingest([insert('a')], signAs(owner.secretKey)).catch((err: unknown) => err)) as TransportError;
		expect(e).toMatchObject({ name: 'TransportError', kind: 'malformed', status: 200 });
		const each = (await answerWith(() => json(422, { nope: 1 })).ingestEach([insert('a')], signAs(owner.secretKey)).catch((err: unknown) => err)) as TransportError;
		expect(each).toMatchObject({ kind: 'malformed', status: 422 });
		expect(await answerWith(() => json(401, { error: 'Invalid or expired challenge' })).ingestEach([insert('a')], signAs(owner.secretKey)))
			.toEqual({ kind: 'rejected', status: 401, rejection: { kind: 'proof_rejected', error: 'Invalid or expired challenge' } });
	});

	it('tells a network failure, a timeout and the caller\'s abort apart', async () => {
		const failing = createTransport({ baseUrl: '/api', fetch: (async () => { throw new TypeError('Failed to fetch'); }) as typeof fetch });
		expect(await failing.challenge().catch((e: unknown) => e)).toMatchObject({ kind: 'network', network: true });

		const hanging = createTransport({
			baseUrl: '/api',
			timeoutMs: 20,
			fetch: ((_: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => new Promise((_, reject) => {
				init?.signal?.addEventListener('abort', () => reject(init.signal!.reason ?? new DOMException('aborted', 'AbortError')));
			})) as typeof fetch,
		});
		expect(await hanging.challenge().catch((e: unknown) => e)).toMatchObject({ kind: 'timeout' });
		const controller = new AbortController();
		const pending = hanging.challenge({ signal: controller.signal }).catch((e: unknown) => e);
		controller.abort();
		expect(await pending).toMatchObject({ kind: 'aborted' });
	});
});
