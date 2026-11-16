import { describe, it, expect, vi } from 'vitest';
import {
	createTransport,
	createReadSessions,
	subscribeShape,
	type ShapeMessage,
	type ShapeSubscriptionError,
} from '@buckitup/pq-client/transport';

interface Thing { id: string; name?: string; n?: number }

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
	new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

interface Request { url: URL; authorization: string | null; signal: AbortSignal | null | undefined }

const electric = ({ pageSize = 1000, token = null as string | null } = {}) => {
	let handle = 'h1';
	const log: ShapeMessage<Thing>[] = [];
	const requests: Request[] = [];
	const waiters: Array<() => void> = [];
	let failNext: Array<() => Response> = [];
	let beforeRequest: ((count: number) => void) | null = null;
	const offsetOf = (index: number) => `${index}_0`;
	const indexOf = (offset: string) => (offset === '-1' ? -1 : Number(offset.split('_')[0]));
	const page = (from: number) => {
		const messages = log.slice(from + 1, from + 1 + pageSize);
		const last = from + messages.length;
		const done = last >= log.length - 1;
		const headers: Record<string, string> = { 'electric-handle': handle, 'electric-offset': offsetOf(last), 'electric-cursor': `cur${last}` };
		if (done) headers['electric-up-to-date'] = '';
		return json(200, done ? [...messages, { headers: { control: 'up-to-date' } }] : messages, headers);
	};
	const fetchImpl = (async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
		const url = new URL(String(input));
		const authorization = new Headers(init?.headers).get('authorization');
		requests.push({ url, authorization, signal: init?.signal });
		beforeRequest?.(requests.length);
		if (failNext.length) return failNext.shift()!();
		if (token && authorization !== `Bearer ${token}`) return json(401, { error: 'read_session_required', shape: 'things' });
		const p = url.searchParams;
		const asked = p.get('handle');
		if (asked && asked !== handle) return json(409, [{ headers: { control: 'must-refetch' } }], { 'electric-handle': handle });
		const from = indexOf(p.get('offset')!);
		if (p.get('live') !== 'true' || from < log.length - 1) return page(from);
		await new Promise<void>((resolve, reject) => {
			waiters.push(resolve);
			init?.signal?.addEventListener('abort', () => reject(init.signal!.reason ?? new DOMException('aborted', 'AbortError')));
		});
		return asked && asked !== handle ? json(409, [], { 'electric-handle': handle }) : page(from);
	}) as typeof fetch;
	const wake = () => waiters.splice(0).forEach((w) => w());
	return {
		transport: createTransport({ baseUrl: 'https://x.example/electric/v1', fetch: fetchImpl }),
		requests,
		seed(count: number) {
			for (let i = 0; i < count; i++) log.push({ key: `k${i}`, value: { id: `k${i}`, n: i }, headers: { operation: 'insert' } });
		},
		push(message: ShapeMessage<Thing>) {
			log.push(message);
			wake();
		},
		rotate() {
			handle = `h${Number(handle.slice(1)) + 1}`;
			wake();
		},
		failWith(...responses: Array<() => Response>) {
			failNext = responses;
		},
		onRequest(hook: (count: number) => void) {
			beforeRequest = hook;
		},
		get pendingPolls() {
			return waiters.length;
		},
	};
};

const until = async (check: () => boolean) => {
	for (let i = 0; i < 200 && !check(); i++) await new Promise((r) => setTimeout(r, 2));
	expect(check()).toBe(true);
};

describe('readShapeOnce: a complete snapshot', () => {
	it('follows the handle and offset until up-to-date, across pages', async () => {
		const server = electric({ pageSize: 1000 });
		server.seed(2500);
		const res = await server.transport.readShapeOnce<Thing>('things', 'true');
		expect(res.kind === 'rows' && res.rows.length).toBe(2500);
		expect(res.kind === 'rows' && new Set(res.rows.map((r) => r.id)).size).toBe(2500);
		expect(server.requests.map((r) => [r.url.searchParams.get('offset'), r.url.searchParams.get('handle')]))
			.toEqual([['-1', null], ['999_0', 'h1'], ['1999_0', 'h1']]);
		const wheres = new Set(server.requests.map((r) => r.url.searchParams.get('where')));
		expect(wheres.size).toBe(1);
	});

	it('starts over when the shape is replaced mid-snapshot, without duplicates', async () => {
		const server = electric({ pageSize: 1000 });
		server.seed(2500);
		server.onRequest((count) => { if (count === 2) server.rotate(); });
		const res = await server.transport.readShapeOnce<Thing>('things', 'true');
		expect(res.kind === 'rows' && res.rows.length).toBe(2500);
		expect(server.requests.map((r) => [r.url.searchParams.get('offset'), r.url.searchParams.get('handle')]))
			.toEqual([['-1', null], ['999_0', 'h1'], ['-1', 'h2'], ['999_0', 'h2'], ['1999_0', 'h2']]);
	});
});

describe('readShapeOnce: no success without up-to-date', () => {
	const answering = (...bodies: Array<() => Response>) => {
		let calls = 0;
		const transport = createTransport({
			baseUrl: 'https://x.example/electric/v1',
			fetch: (async () => bodies[Math.min(calls++, bodies.length - 1)]()) as typeof fetch,
		});
		return { transport, calls: () => calls };
	};

	it('refuses rows from a response that is not up to date and names no way to continue', async () => {
		const { transport } = answering(() => json(200, [{ key: 'a', value: { id: 'a' } }]));
		await expect(transport.readShapeOnce<Thing>('things', 'true')).rejects.toMatchObject({ name: 'TransportError', kind: 'malformed' });
	});

	it('refuses a snapshot whose last page carries a handle but no offset', async () => {
		const { transport, calls } = answering(
			() => json(200, [{ key: 'a', value: { id: 'a' } }], { 'electric-handle': 'h1', 'electric-offset': '0_0' }),
			() => json(200, [{ key: 'b', value: { id: 'b' } }], { 'electric-handle': 'h1' }),
		);
		await expect(transport.readShapeOnce<Thing>('things', 'true')).rejects.toMatchObject({ kind: 'malformed' });
		expect(calls()).toBe(2);
	});

	it('accepts an up-to-date answer even without continuation headers', async () => {
		const { transport } = answering(() => json(200, [{ key: 'a', value: { id: 'a' } }, { headers: { control: 'up-to-date' } }]));
		expect(await transport.readShapeOnce<Thing>('things', 'true')).toEqual({ kind: 'rows', rows: [{ id: 'a' }] });
	});
});

describe('subscribeShape', () => {
	it('loads the snapshot, then follows inserts, updates and deletes live', async () => {
		const server = electric({ pageSize: 2 });
		server.seed(5);
		const updates: number[] = [];
		const sub = subscribeShape<Thing>(server.transport, { table: 'things', where: 'true', onChange: (u) => updates.push(u.changes.length) });
		expect(await sub.ready).toBe(true);
		expect(sub.rows.size).toBe(5);
		await until(() => server.pendingPolls === 1);
		const live = server.requests.at(-1)!.url.searchParams;
		expect([live.get('live'), live.get('handle'), live.get('offset'), live.get('cursor')]).toEqual(['true', 'h1', '4_0', 'cur4']);

		server.push({ key: 'k1', value: { id: 'k1', name: 'renamed' }, headers: { operation: 'update' } });
		await until(() => sub.rows.get('k1')?.name === 'renamed');
		expect(sub.rows.get('k1')).toEqual({ id: 'k1', n: 1, name: 'renamed' });
		server.push({ key: 'k2', headers: { operation: 'delete' } });
		await until(() => !sub.rows.has('k2'));
		server.push({ key: 'k9', value: { id: 'k9' }, headers: { operation: 'insert' } });
		await until(() => sub.rows.has('k9'));
		expect(sub.upToDate).toBe(true);
		sub.dispose();
		expect(await sub.done).toEqual({ kind: 'disposed' });
	});

	it('resets and reloads when the server replaces the shape during a live poll', async () => {
		const server = electric({ pageSize: 10 });
		server.seed(3);
		const onReset = vi.fn();
		const sub = subscribeShape<Thing>(server.transport, { table: 'things', onReset });
		await sub.ready;
		await until(() => server.pendingPolls === 1);
		server.rotate();
		await until(() => onReset.mock.calls.length === 1 && sub.upToDate && server.pendingPolls === 1);
		expect(sub.handle).toBe('h2');
		expect(sub.rows.size).toBe(3);
		sub.dispose();
	});

	it('retries a server or network failure with backoff and carries on', async () => {
		const server = electric();
		server.seed(2);
		server.failWith(() => json(503, { error: 'busy' }), () => { throw new TypeError('Failed to fetch'); });
		const errors: ShapeSubscriptionError[] = [];
		const sub = subscribeShape<Thing>(server.transport, { table: 'things', retryDelayMs: () => 0, onError: (e) => errors.push(e) });
		expect(await sub.ready).toBe(true);
		expect(errors.map((e) => [e.kind, e.retrying])).toEqual([['server', true], ['transport', true]]);
		expect(sub.rows.size).toBe(2);
		sub.dispose();
	});

	it('ends on an answer that is not a shape log, without retrying it, and cleans up', async () => {
		let requests = 0;
		const transport = createTransport({
			baseUrl: 'https://x.example/electric/v1',
			fetch: (async () => { requests++; return json(200, { not: 'a log' }); }) as typeof fetch,
		});
		const errors: ShapeSubscriptionError[] = [];
		const sub = subscribeShape<Thing>(transport, { table: 'things', retryDelayMs: () => 0, onError: (e) => errors.push(e) });
		expect(await sub.ready).toBe(false);
		const end = await sub.done;
		expect(end).toMatchObject({ kind: 'failed', error: { kind: 'protocol', retrying: false, error: { name: 'TransportError', kind: 'malformed' } } });
		expect(errors).toHaveLength(1);
		await new Promise((r) => setTimeout(r, 20));
		expect(requests).toBe(1);
		sub.dispose();
		expect(await sub.done).toBe(end);
	});

	it('ends on a page that is not up to date and names no way to continue', async () => {
		const transport = createTransport({
			baseUrl: 'https://x.example/electric/v1',
			fetch: (async () => json(200, [{ key: 'a', value: { id: 'a' } }])) as typeof fetch,
		});
		const sub = subscribeShape<Thing>(transport, { table: 'things' });
		expect(await sub.done).toMatchObject({ kind: 'failed', error: { kind: 'protocol' } });
		expect(await sub.ready).toBe(false);
	});

	it('stops on a refusal that another attempt cannot change', async () => {
		const server = electric();
		server.failWith(() => json(400, { message: 'bad where' }));
		const sub = subscribeShape<Thing>(server.transport, { table: 'things', where: 'nope(' });
		expect(await sub.ready).toBe(false);
		expect(await sub.done).toEqual({ kind: 'failed', error: { kind: 'server', status: 400, error: 'bad where', retrying: false } });
		expect(server.requests).toHaveLength(1);
	});

	it('dispose and the caller\'s signal abort the poll in flight and send nothing after', async () => {
		for (const stop of ['dispose', 'signal'] as const) {
			const server = electric();
			server.seed(1);
			const controller = new AbortController();
			const sub = subscribeShape<Thing>(server.transport, { table: 'things', signal: controller.signal });
			await sub.ready;
			await until(() => server.pendingPolls === 1);
			const poll = server.requests.at(-1)!;
			if (stop === 'dispose') sub.dispose();
			else controller.abort();
			expect(poll.signal?.aborted).toBe(true);
			expect(await sub.done).toEqual({ kind: 'disposed' });
			const sent = server.requests.length;
			await new Promise((r) => setTimeout(r, 20));
			expect(server.requests).toHaveLength(sent);
		}
	});

	describe('in trust mode', () => {
		const sessionTransport = (grant: () => Response) =>
			createTransport({
				baseUrl: 'https://x.example/electric/v1',
				fetch: (async (input: Parameters<typeof fetch>[0]) =>
					String(input).endsWith('/challenge') ? json(200, { challenge_id: 'c', challenge: 'ab'.repeat(32) }) : grant()) as typeof fetch,
			});

		it('opens a read session on 401 and reads with its bearer', async () => {
			const server = electric({ token: 'tok-1' });
			server.seed(2);
			let opens = 0;
			const sessions = createReadSessions({
				transport: sessionTransport(() => { opens++; return json(200, { token: 'tok-1', shape: 'things', expires_in: 300 }); }),
				identity: { userHash: 'u_' + 'a'.repeat(128), sign: () => new Uint8Array([1]) },
			});
			const sub = subscribeShape<Thing>(server.transport, { table: 'things', sessions });
			expect(await sub.ready).toBe(true);
			expect(opens).toBe(1);
			expect(server.requests[0].authorization).toBeNull();
			expect(server.requests[1].authorization).toBe('Bearer tok-1');
			sub.dispose();
			sessions.dispose();
		});

		it('a second 401 in a row ends the subscription instead of looping', async () => {
			const server = electric({ token: 'never' });
			let opens = 0;
			const sessions = createReadSessions({
				transport: sessionTransport(() => { opens++; return json(200, { token: 'tok-1', shape: 'things', expires_in: 300 }); }),
				identity: { userHash: 'u_' + 'a'.repeat(128), sign: () => new Uint8Array([1]) },
			});
			const sub = subscribeShape<Thing>(server.transport, { table: 'things', sessions });
			expect(await sub.done).toMatchObject({ kind: 'failed', error: { kind: 'read_session_required', shape: 'things' } });
			expect(opens).toBe(1);
			expect(server.requests).toHaveLength(2);
			sessions.dispose();
		});

		it('a session the server refuses ends the subscription with its outcome', async () => {
			const server = electric({ token: 'tok-1' });
			const sessions = createReadSessions({
				transport: sessionTransport(() => json(403, { error: 'not_in_trust_chain', max_depth: 7 })),
				identity: { userHash: 'u_' + 'a'.repeat(128), sign: () => new Uint8Array([1]) },
			});
			const sub = subscribeShape<Thing>(server.transport, { table: 'things', sessions });
			expect(await sub.done).toEqual({
				kind: 'failed',
				error: { kind: 'read_session', shape: 'things', result: { kind: 'not_in_trust_chain' }, retrying: false },
			});
			sessions.dispose();
		});

		it('logout while a session opens ends the read as disposed, with no token used', async () => {
			const server = electric({ token: 'tok-1' });
			const sessions = createReadSessions({
				transport: sessionTransport(() => json(200, { token: 'tok-1', shape: 'things', expires_in: 300 })),
				identity: { userHash: 'u_' + 'a'.repeat(128), sign: () => { sessions.dispose(); return new Uint8Array([1]); } },
			});
			const sub = subscribeShape<Thing>(server.transport, { table: 'things', sessions });
			expect(await sub.done).toMatchObject({ kind: 'failed', error: { kind: 'read_session', result: { kind: 'disposed' } } });
			expect(server.requests.every((r) => r.authorization === null)).toBe(true);
		});
	});
});
