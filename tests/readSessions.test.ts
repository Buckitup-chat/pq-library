import { describe, it, expect, vi, afterEach } from 'vitest';
import { createTransport, createReadSessions, type ReadSessionOutcome } from '@buckitup/pq-client/transport';

const USER_A = 'u_' + 'a'.repeat(128);
const USER_B = 'u_' + 'b'.repeat(128);

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

interface Opened { user: string; shape: string; token: string }

const sessionServer = (host: string, reply?: (body: { user_hash: string; shape: string }) => Response | Promise<Response>) => {
	const opened: Opened[] = [];
	const signals: AbortSignal[] = [];
	let n = 0;
	const fetchImpl = (async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
		if (init?.signal) signals.push(init.signal);
		const path = new URL(String(input)).pathname.replace('/electric/v1', '');
		if (path === '/challenge') return json(200, { challenge_id: `c${++n}`, challenge: 'ab'.repeat(32), expires_in: 60 });
		const body = JSON.parse(String(init?.body)) as { user_hash: string; shape: string };
		if (reply) return reply(body);
		const token = `${host}:${body.user_hash.slice(0, 3)}:${body.shape}:${++n}`;
		opened.push({ user: body.user_hash, shape: body.shape, token });
		return json(200, { token, shape: body.shape, expires_in: 300 });
	}) as typeof fetch;
	return { transport: createTransport({ baseUrl: `https://${host}/electric/v1`, fetch: fetchImpl }), opened, signals };
};

const signer = () => {
	const calls: Uint8Array[] = [];
	return { calls, sign: (m: Uint8Array) => { calls.push(m); return new Uint8Array([1, 2, 3]); } };
};

afterEach(() => {
	vi.useRealTimers();
});

describe('createReadSessions', () => {
	it('shares one open between concurrent requests for a shape and hands out its bearer', async () => {
		const server = sessionServer('one.example');
		const sessions = createReadSessions({ transport: server.transport, identity: { userHash: USER_A, ...signer() } });
		const results = await Promise.all([sessions.open('dialog_messages'), sessions.open('dialog_messages'), sessions.open('dialog_keys')]);
		expect(server.opened.map((o) => o.shape)).toEqual(['dialog_messages', 'dialog_keys']);
		expect(results[0]).toBe(results[1]);
		expect(sessions.bearer('dialog_messages')).toBe(`Bearer ${server.opened[0].token}`);
		expect(sessions.bearer('dialog_keys')).toBe(`Bearer ${server.opened[1].token}`);
		sessions.dispose();
	});

	it('keeps tokens apart by server, identity and shape', async () => {
		const first = sessionServer('one.example');
		const second = sessionServer('two.example');
		const a1 = createReadSessions({ transport: first.transport, identity: { userHash: USER_A, ...signer() } });
		const b1 = createReadSessions({ transport: first.transport, identity: { userHash: USER_B, ...signer() } });
		const a2 = createReadSessions({ transport: second.transport, identity: { userHash: USER_A, ...signer() } });
		await Promise.all([a1.open('dialog_keys'), b1.open('dialog_keys'), a2.open('dialog_keys')]);
		const bearers = [a1, b1, a2].map((s) => s.bearer('dialog_keys'));
		expect(new Set(bearers).size).toBe(3);
		expect(a1.bearer('dialog_keys')).toContain('one.example:u_a');
		expect(b1.bearer('dialog_keys')).toContain('one.example:u_b');
		expect(a2.bearer('dialog_keys')).toContain('two.example:u_a');
		expect(a1.bearer('dialog_messages')).toBeNull();
		for (const s of [a1, b1, a2]) s.dispose();
	});

	it('renews 60 s before expiry, replaces the token, and stops renewing once disposed', async () => {
		vi.useFakeTimers();
		const server = sessionServer('one.example');
		const sessions = createReadSessions({ transport: server.transport, identity: { userHash: USER_A, ...signer() } });
		await sessions.open('dialog_keys');
		const first = sessions.bearer('dialog_keys');
		await vi.advanceTimersByTimeAsync(239_000);
		expect(server.opened).toHaveLength(1);
		await vi.advanceTimersByTimeAsync(1_000);
		expect(server.opened).toHaveLength(2);
		expect(sessions.bearer('dialog_keys')).not.toBe(first);
		sessions.dispose();
		expect(sessions.bearer('dialog_keys')).toBeNull();
		await vi.advanceTimersByTimeAsync(600_000);
		expect(server.opened).toHaveLength(2);
		expect(vi.getTimerCount()).toBe(0);
	});

	it('gives no bearer for an expired token', async () => {
		let now = 1_000_000;
		const server = sessionServer('one.example');
		const sessions = createReadSessions({ transport: server.transport, identity: { userHash: USER_A, ...signer() }, now: () => now });
		await sessions.open('dialog_keys');
		now = Date.now() + 300_000;
		expect(sessions.bearer('dialog_keys')).toBeNull();
		expect(sessions.hasValidToken('dialog_keys')).toBe(false);
		sessions.dispose();
	});

	it('reopens after a 401 and learns which shape a table reads through', async () => {
		const server = sessionServer('one.example');
		const sessions = createReadSessions({ transport: server.transport, identity: { userHash: USER_A, ...signer() } });
		await sessions.open('user_storage');
		const stale = sessions.bearer('user_storage');
		const result = await sessions.reopen('user_storage', 'user_storage_versions');
		expect(result.kind).toBe('opened');
		expect(sessions.bearer('user_storage_versions')).toBe(sessions.bearer('user_storage'));
		expect(sessions.bearer('user_storage')).not.toBe(stale);
		sessions.dispose();
	});

	it('asks the caller to publish the card once on unknown_user, then retries; without it gives the outcome back', async () => {
		let cardKnown = false;
		const server = sessionServer('one.example', (body) =>
			cardKnown ? json(200, { token: 't', shape: body.shape, expires_in: 300 }) : json(401, { error: 'unknown_user' }));
		const onUnknownUser = vi.fn(async () => { cardKnown = true; return true; });
		const sessions = createReadSessions({ transport: server.transport, identity: { userHash: USER_A, ...signer() }, onUnknownUser });
		expect(await sessions.open('dialog_keys')).toMatchObject({ kind: 'opened', token: 't' });
		expect(onUnknownUser).toHaveBeenCalledTimes(1);

		cardKnown = false;
		const plain = createReadSessions({ transport: server.transport, identity: { userHash: USER_A, ...signer() } });
		expect(await plain.open('dialog_keys')).toEqual({ kind: 'unknown_user' });
		sessions.dispose();
		plain.dispose();
	});

	it('reports not_in_trust_chain without a token, through onOutcome', async () => {
		const server = sessionServer('one.example', () => json(403, { error: 'not_in_trust_chain', max_depth: 7 }));
		const outcomes: Array<[string, ReadSessionOutcome]> = [];
		const sessions = createReadSessions({
			transport: server.transport, identity: { userHash: USER_A, ...signer() }, onOutcome: (shape, o) => outcomes.push([shape, o]),
		});
		expect(await sessions.open('dialog_keys')).toEqual({ kind: 'not_in_trust_chain' });
		expect(outcomes).toEqual([['dialog_keys', { kind: 'not_in_trust_chain' }]]);
		expect(sessions.bearer('dialog_keys')).toBeNull();
		sessions.dispose();
	});

	it('logout during an open: the request is aborted, nothing is signed after it, no token is kept', async () => {
		let release!: () => void;
		const held = new Promise<void>((r) => (release = r));
		const signals: AbortSignal[] = [];
		const s = signer();
		const transport = createTransport({
			baseUrl: 'https://one.example/electric/v1',
			fetch: (async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
				if (init?.signal) signals.push(init.signal);
				if (String(input).endsWith('/challenge')) {
					await held;
					return json(200, { challenge_id: 'c', challenge: 'ab'.repeat(32) });
				}
				return json(200, { token: 'late', shape: 'dialog_keys', expires_in: 300 });
			}) as typeof fetch,
		});
		const sessions = createReadSessions({ transport, identity: { userHash: USER_A, sign: s.sign } });
		const pending = sessions.open('dialog_keys');
		await Promise.resolve();
		sessions.dispose();
		expect(signals[0].aborted).toBe(true);
		release();
		expect(await pending).toEqual({ kind: 'disposed' });
		expect(s.calls).toHaveLength(0);
		expect(sessions.bearer('dialog_keys')).toBeNull();
		expect(await sessions.open('dialog_keys')).toEqual({ kind: 'disposed' });
	});

	it('puts a timeout on each open even though the caller passes no signal', async () => {
		const transport = createTransport({
			baseUrl: 'https://one.example/electric/v1',
			fetch: ((_: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => new Promise((_, reject) => {
				init?.signal?.addEventListener('abort', () => reject(new DOMException('timed out', 'TimeoutError')));
			})) as typeof fetch,
		});
		const sessions = createReadSessions({ transport, identity: { userHash: USER_A, ...signer() }, timeoutMs: 20 });
		await expect(sessions.open('dialog_keys')).rejects.toMatchObject({ name: 'TransportError', kind: 'timeout', network: true });
		sessions.dispose();
	});

	it('tells a timeout from an explicit cancellation when the signal combines both', async () => {
		const hanging = createTransport({
			baseUrl: 'https://one.example/electric/v1',
			fetch: ((_: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => new Promise((_, reject) => {
				init?.signal?.addEventListener('abort', () => reject(init.signal!.reason));
			})) as typeof fetch,
		});
		const timedOut = AbortSignal.any([new AbortController().signal, AbortSignal.timeout(20)]);
		expect(await hanging.challenge({ signal: timedOut }).catch((e: unknown) => e)).toMatchObject({ kind: 'timeout' });

		const cancel = new AbortController();
		const cancelled = hanging.challenge({ signal: AbortSignal.any([cancel.signal, AbortSignal.timeout(10_000)]) }).catch((e: unknown) => e);
		cancel.abort();
		expect(await cancelled).toMatchObject({ kind: 'aborted' });

		const plain = new AbortController();
		const plainCancel = hanging.challenge({ signal: plain.signal }).catch((e: unknown) => e);
		plain.abort();
		expect(await plainCancel).toMatchObject({ kind: 'aborted' });
	});
});
