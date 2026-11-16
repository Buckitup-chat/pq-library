// HTTP transport to a BuckitUp server's /electric/v1 API: challenges and key
// proofs, row writes, device identity, read sessions and one-shot shape
// reads. The wire format is in chat/docs/pq/reqs/.
//
// No policy lives here — what to retry, when to wait for approval, which
// identity signs — only the requests and what their answers mean. The server
// is a parameter, not a build constant, so one process can talk to several.
import { proveChallenge } from './challengeProof.js';
import { applyShapeMessages, isControl, type ShapeMessage } from './shapeLog.js';
import type { IngestRowResult } from './types.js';
import { classifyErrorBody, classifyRowResult, type RowOutcome, type WriteRejection } from './writeOutcome.js';

export * from './writeOutcome.js';
export * from './shapeLog.js';
export * from './readSessions.js';
export * from './shapeStream.js';

/** ML-DSA-87 over a message, under the identity's sign_skey. */
export type Signer = (message: Uint8Array) => Uint8Array | Promise<Uint8Array>;

export interface Challenge {
	challenge_id: string;
	challenge: string;
	expires_in?: number;
}

export interface DeviceIdentity {
	device_id: string;
	admin: { user_hash: string; sign_pkey: string } | null;
	sync_bot: { user_hash: string; sign_pkey: string } | null;
}

/** A row write: a TanStack DB mutation as /ingest takes it. */
export type Mutation = Record<string, unknown>;

export type IngestEachOutcome =
	| {
			kind: 'results';
			/** 200 all written, 403 every failure is the access gate, 422 otherwise. */
			status: number;
			results: IngestRowResult[];
			rows: RowOutcome[];
	  }
	| { kind: 'rejected'; status: number; rejection: WriteRejection };

export type IngestOutcome =
	| { kind: 'written'; txid: number }
	| { kind: 'rejected'; status: number; rejection: WriteRejection };

/** Why the server refuses a write or a read session to an identity the access mode does not admit. */
export const NOT_IN_TRUST_CHAIN = 'not_in_trust_chain';

export type ReadSessionOutcome =
	| { kind: 'opened'; token: string; shape: string; expiresAt: number }
	/** The server has no user_cards row for this identity: write the card, then open again. */
	| { kind: 'unknown_user' }
	/** No vouch chain from the owner for device.<id>.storage.read.<shape>. */
	| { kind: 'not_in_trust_chain' }
	/** The challenge was unknown, expired or used, or the signature did not verify: prove again. */
	| { kind: 'bad_proof' }
	/** The server has no shape by that name. */
	| { kind: 'unknown_shape' }
	/** An answer the protocol does not define. */
	| { kind: 'refused'; status: number; error: string | null };

export type TransportErrorKind = 'network' | 'timeout' | 'aborted' | 'http' | 'malformed';

/** The request got no answer, or an answer that is not the API's. */
export class TransportError extends Error {
	readonly status: number | null;
	/** No answer at all: fetch failed, timed out or was aborted. */
	readonly network: boolean;
	readonly kind: TransportErrorKind;
	readonly retryAfter: number | null;
	readonly body: unknown;

	constructor(
		message: string,
		opts: { status?: number | null; network?: boolean; kind?: TransportErrorKind; retryAfter?: number | null; body?: unknown } = {},
	) {
		super(message);
		this.name = 'TransportError';
		this.status = opts.status ?? null;
		this.kind = opts.kind ?? (opts.network ? 'network' : this.status !== null ? 'http' : 'malformed');
		this.network = opts.network ?? (this.kind === 'network' || this.kind === 'timeout' || this.kind === 'aborted');
		this.retryAfter = opts.retryAfter ?? null;
		this.body = opts.body;
	}
}

export interface TransportOptions {
	/**
	 * The /electric/v1 base: absolute, or a path on the page's origin ("/api"
	 * behind a dev proxy). Requests go to base + path as given — a browser
	 * resolves a relative one; outside a browser pass an absolute base.
	 */
	baseUrl: string;
	/** Defaults to the global fetch, looked up on each call. */
	fetch?: typeof fetch;
	/** Per-request timeout unless a call passes its own signal. */
	timeoutMs?: number;
}

export interface RequestOptions {
	signal?: AbortSignal;
	timeoutMs?: number;
}

export interface Transport {
	/** Absolute URL of a path under the base, for clients that need one (Electric's ShapeStream). */
	url(path: string): string;
	challenge(opts?: RequestOptions): Promise<Challenge>;
	/** A fresh challenge, signed: the `auth` object a write carries. */
	prove(sign: Signer, opts?: RequestOptions): Promise<{ challenge_id: string; signature: string }>;
	/** POST /ingest_each, answered as it came: callers that classify failures themselves read the body. */
	ingestEachResponse(mutations: Mutation[], sign: Signer, opts?: RequestOptions): Promise<Response>;
	/** POST /ingest_each with the per-row results checked against the request. */
	ingestEach(mutations: Mutation[], sign: Signer, opts?: RequestOptions): Promise<IngestEachOutcome>;
	ingest(mutations: Mutation[], sign: Signer, opts?: RequestOptions): Promise<IngestOutcome>;
	deviceIdentity(opts?: RequestOptions): Promise<DeviceIdentity>;
	openReadSession(userHash: string, shape: string, sign: Signer, opts?: RequestOptions): Promise<ReadSessionOutcome>;
	/** GET a shape's current rows once, with a bearer token when the caller has one. */
	readShapeOnce<T>(table: string, where: string, opts?: RequestOptions & { authorization?: string }): Promise<ShapeReadResponse<T>>;
	readShapeChunk<T>(request: ShapeRequest, opts?: RequestOptions & { authorization?: string }): Promise<ShapeChunk<T>>;
}

export interface ShapeRequest {
	table: string;
	where?: string;
	columns?: string[];
	offset: string;
	handle?: string | null;
	live?: boolean;
	cursor?: string | null;
}

export type ShapeChunk<T> =
	| {
			kind: 'chunk';
			status: number;
			handle: string | null;
			offset: string | null;
			cursor: string | null;
			upToDate: boolean;
			messages: ShapeMessage<T>[];
	  }
	| { kind: 'must_refetch'; handle: string | null }
	| { kind: 'read_session_required'; shape: string }
	| { kind: 'failed'; status: number; error: string | null };

export type ShapeReadResponse<T> =
	| { kind: 'rows'; rows: T[] }
	/** Access mode trust: open a read session for `shape` and read again. */
	| { kind: 'read_session_required'; shape: string }
	| { kind: 'failed'; status: number };

const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_SNAPSHOT_PAGES = 10_000;
const MAX_SNAPSHOT_RESTARTS = 3;

const parseJson = (text: string): unknown => {
	try {
		return text ? JSON.parse(text) : null;
	} catch {
		return null;
	}
};

const headerOf = (resp: Response, name: string): string | null => resp.headers?.get(name) ?? null;

const retryAfterOf = (resp: Response): number | null => {
	const value = Number(headerOf(resp, 'retry-after') ?? NaN);
	return Number.isFinite(value) && value >= 0 ? value : null;
};

const requestRejection = (status: number, body: unknown, text: string): WriteRejection => {
	const parsed = body && typeof body === 'object' ? (body as { error?: unknown; status?: unknown; conflicted?: unknown }) : null;
	const error = typeof parsed?.error === 'string' ? parsed.error : text || `HTTP ${status}`;
	if (status === 401) return { kind: 'proof_rejected', error };
	if (status === 409 && parsed?.status === 'exists') return { kind: 'exists', conflicted: parsed.conflicted !== false };
	if (status === 400) return parsed ? { kind: 'bad_request', error } : { kind: 'rejected', error };
	if (parsed && typeof parsed.error === 'string') return classifyErrorBody(parsed);
	return { kind: 'rejected', error };
};

/** The request got no answer: fetch failed, timed out or was aborted. */
export const isNoAnswer = (e: unknown): boolean =>
	e instanceof TypeError || (e as Error)?.name === 'TimeoutError' || (e as Error)?.name === 'AbortError';

/**
 * A where clause nobody is subscribed to. Shapes are cached per (table,
 * where), and one without a live subscriber does not advance its log: a plain
 * re-read can miss rows committed seconds earlier, while a fresh where gets a
 * fresh snapshot. The literal stays under 2^31 — the server's where parser
 * refuses a wider integer with HTTP 500 — and one value is used on both sides,
 * so the predicate is true for every row.
 */
let probe = 0;
export const freshWhere = (where: string): string => {
	const salt = Math.floor(Math.random() * 1e6) * 1000 + (++probe % 1000);
	return `${where} AND ${salt}=${salt}`;
};

export function createTransport(options: TransportOptions): Transport {
	const base = options.baseUrl.replace(/\/+$/, '');
	const doFetch: typeof fetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));

	const url = (path: string): string => {
		const u = `${base}${path}`;
		if (/^https?:\/\//.test(u)) return u;
		const origin = typeof location !== 'undefined' ? location.origin : 'http://localhost';
		return `${origin}${u}`;
	};

	const send = async (path: string, init: NonNullable<Parameters<typeof fetch>[1]>, opts: RequestOptions = {}): Promise<Response> => {
		const signal = opts.signal ?? AbortSignal.timeout(opts.timeoutMs ?? options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
		try {
			return await doFetch(`${base}${path}`, { ...init, signal });
		} catch (e) {
			if (isNoAnswer(e)) {
				const reason = (opts.signal?.reason as Error | undefined)?.name;
				const kind: TransportErrorKind = opts.signal?.aborted
					? reason === 'TimeoutError' ? 'timeout' : 'aborted'
					: (e as Error)?.name === 'TimeoutError' || ((e as Error)?.name === 'AbortError' && signal.aborted)
						? 'timeout'
						: 'network';
				throw new TransportError(`${path}: no answer (${(e as Error)?.message ?? e})`, { network: true, kind });
			}
			throw e;
		}
	};

	const json = async <T>(resp: Response, path: string): Promise<T> => {
		try {
			return (await resp.json()) as T;
		} catch {
			throw new TransportError(`${path}: HTTP ${resp.status} without a JSON body`, { status: resp.status, kind: 'malformed' });
		}
	};

	const serverError = (resp: Response, path: string, body: unknown) =>
		new TransportError(`${path}: HTTP ${resp.status}`, { status: resp.status, kind: 'http', retryAfter: retryAfterOf(resp), body });

	const challenge = async (opts?: RequestOptions): Promise<Challenge> => {
		const resp = await send('/challenge', { headers: { accept: 'application/json' } }, opts);
		if (!resp.ok) throw new TransportError(`challenge: HTTP ${resp.status}`, { status: resp.status });
		return json<Challenge>(resp, '/challenge');
	};

	const prove = async (sign: Signer, opts?: RequestOptions) => {
		const { challenge_id, challenge: text } = await challenge(opts);
		return { challenge_id, signature: await proveChallenge(text, sign) };
	};

	const write = async (path: string, mutations: Mutation[], sign: Signer, opts?: RequestOptions): Promise<Response> => {
		const auth = await prove(sign, opts);
		return send(path, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ auth, mutations }),
		}, opts);
	};

	const ingestEachResponse = (mutations: Mutation[], sign: Signer, opts?: RequestOptions): Promise<Response> =>
		write('/ingest_each', mutations, sign, opts);

	const readShapeChunk = async <T>(request: ShapeRequest, opts: RequestOptions & { authorization?: string } = {}): Promise<ShapeChunk<T>> => {
		const params = [`table=${encodeURIComponent(request.table)}`];
		if (request.where) params.push(`where=${encodeURIComponent(request.where)}`);
		params.push(`offset=${encodeURIComponent(request.offset)}`);
		if (request.handle) params.push(`handle=${encodeURIComponent(request.handle)}`);
		if (request.columns?.length) params.push(`columns=${encodeURIComponent(request.columns.join(','))}`);
		if (request.live) {
			params.push('live=true');
			if (request.cursor) params.push(`cursor=${encodeURIComponent(request.cursor)}`);
		}
		const resp = await send(`/shapes?${params.join('&')}`, {
			headers: opts.authorization ? { Authorization: opts.authorization } : undefined,
		}, opts);
		const handle = headerOf(resp, 'electric-handle');
		if (resp.status === 409) return { kind: 'must_refetch', handle };
		if (resp.status === 401) {
			const body = (await resp.json().catch(() => null)) as { error?: string; shape?: string } | null;
			if (body?.error === 'read_session_required' && body.shape) return { kind: 'read_session_required', shape: body.shape };
			return { kind: 'failed', status: 401, error: body?.error ?? null };
		}
		if (!resp.ok) {
			const body = (await resp.json().catch(() => null)) as { error?: unknown; message?: unknown } | null;
			const error = typeof body?.error === 'string' ? body.error : typeof body?.message === 'string' ? body.message : null;
			return { kind: 'failed', status: resp.status, error };
		}
		const messages = resp.status === 204 ? [] : await json<ShapeMessage<T>[]>(resp, '/shapes');
		if (!Array.isArray(messages)) throw new TransportError('/shapes: the body is not a shape log', { status: resp.status, kind: 'malformed' });
		if (messages.some((m) => isControl(m, 'must-refetch'))) return { kind: 'must_refetch', handle };
		return {
			kind: 'chunk',
			status: resp.status,
			handle,
			offset: headerOf(resp, 'electric-offset'),
			cursor: headerOf(resp, 'electric-cursor'),
			upToDate: resp.status === 204 || headerOf(resp, 'electric-up-to-date') !== null || messages.some((m) => isControl(m, 'up-to-date')),
			messages,
		};
	};

	return {
		url,
		challenge,
		prove,
		ingestEachResponse,

		async ingestEach(mutations, sign, opts) {
			const resp = await ingestEachResponse(mutations, sign, opts);
			const text = await resp.text();
			const body = parseJson(text) as { results?: unknown } | null;
			if (resp.status >= 500) throw serverError(resp, '/ingest_each', body ?? text);
			if (Array.isArray(body?.results)) {
				const results = checkResults(body.results, mutations.length, resp.status);
				return { kind: 'results', status: resp.status, results, rows: results.map(classifyRowResult) };
			}
			if (resp.status === 400 || resp.status === 401) {
				return { kind: 'rejected', status: resp.status, rejection: requestRejection(resp.status, body, text) };
			}
			throw new TransportError(`ingest_each HTTP ${resp.status}: no per-row results`, { status: resp.status, kind: 'malformed', body: body ?? text });
		},

		async ingest(mutations, sign, opts) {
			const resp = await write('/ingest', mutations, sign, opts);
			const text = await resp.text();
			const body = parseJson(text) as { txid?: unknown } | null;
			if (resp.status >= 500) throw serverError(resp, '/ingest', body ?? text);
			if (resp.ok) {
				if (typeof body?.txid !== 'number') {
					throw new TransportError(`ingest: HTTP ${resp.status} without a txid`, { status: resp.status, kind: 'malformed', body: body ?? text });
				}
				return { kind: 'written', txid: body.txid };
			}
			return { kind: 'rejected', status: resp.status, rejection: requestRejection(resp.status, body, text) };
		},

		readShapeChunk,

		async deviceIdentity(opts) {
			const resp = await send('/device_identity', { headers: { accept: 'application/json' } }, opts);
			if (!resp.ok) throw new TransportError(`device_identity: HTTP ${resp.status}`, { status: resp.status });
			return json<DeviceIdentity>(resp, '/device_identity');
		},

		async openReadSession(userHash, shape, sign, opts) {
			const { challenge_id, signature } = await prove(sign, opts);
			const resp = await send('/read_session', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ user_hash: userHash, shape, challenge_id, signature }),
			}, opts);
			if (resp.ok) {
				const body = await json<{ token: string; shape: string; expires_in: number }>(resp, '/read_session');
				return { kind: 'opened', token: body.token, shape: body.shape, expiresAt: Date.now() + body.expires_in * 1000 };
			}
			if (resp.status >= 500) throw new TransportError(`read_session for ${shape}: HTTP ${resp.status}`, { status: resp.status });
			const error = ((await resp.json().catch(() => null)) as { error?: string } | null)?.error ?? null;
			if (resp.status === 401 && error === 'unknown_user') return { kind: 'unknown_user' };
			if (resp.status === 401) return { kind: 'bad_proof' };
			if (resp.status === 403 && error === NOT_IN_TRUST_CHAIN) return { kind: 'not_in_trust_chain' };
			if (resp.status === 400) return { kind: 'unknown_shape' };
			return { kind: 'refused', status: resp.status, error };
		},

		async readShapeOnce<T>(table: string, where: string, opts: RequestOptions & { authorization?: string } = {}): Promise<ShapeReadResponse<T>> {
			const fresh = freshWhere(where);
			const rows = new Map<string, T>();
			let handle: string | null = null;
			let offset = '-1';
			let restarts = 0;
			for (let page = 0; ; page++) {
				const chunk: ShapeChunk<T> = await readShapeChunk<T>({ table, where: fresh, offset, handle }, opts);
				if (chunk.kind === 'read_session_required') return chunk;
				if (chunk.kind === 'failed') return { kind: 'failed', status: chunk.status };
				if (chunk.kind === 'must_refetch') {
					if (++restarts > MAX_SNAPSHOT_RESTARTS) {
						throw new TransportError(`/shapes ${table}: the snapshot kept restarting`, { status: 409, kind: 'malformed' });
					}
					rows.clear();
					handle = chunk.handle;
					offset = '-1';
					continue;
				}
				applyShapeMessages(rows, chunk.messages);
				if (chunk.upToDate) break;
				if (!chunk.handle || !chunk.offset) {
					throw new TransportError(`/shapes ${table}: the snapshot is not up to date and the response names no handle or offset to continue from`, {
						status: chunk.status,
						kind: 'malformed',
					});
				}
				if (page + 1 >= MAX_SNAPSHOT_PAGES) {
					throw new TransportError(`/shapes ${table}: the snapshot did not complete`, { status: chunk.status, kind: 'malformed' });
				}
				handle = chunk.handle;
				offset = chunk.offset;
			}
			return { kind: 'rows', rows: [...rows.values()] };
		},
	};
}

/**
 * The per-row results of /ingest_each, checked against the request: one
 * result per mutation, each index once, a known status. Anything else is a
 * server answer the client cannot act on.
 */
export function checkResults(results: unknown, mutationCount: number, status: number): IngestRowResult[] {
	if (!Array.isArray(results)) throw new TransportError(`ingest HTTP ${status}: no per-row results`, { status, kind: 'malformed' });
	if (results.length !== mutationCount) {
		throw new TransportError(`ingest: expected ${mutationCount} results, got ${results.length}`, { status, kind: 'malformed' });
	}
	const seen = new Set<number>();
	for (const r of results) {
		const index = (r as { index?: unknown } | null)?.index;
		if (typeof index !== 'number' || !Number.isInteger(index) || index < 0 || index >= mutationCount) {
			throw new TransportError(`ingest: malformed result index ${JSON.stringify(index)}`, { status, kind: 'malformed' });
		}
		if (seen.has(index)) throw new TransportError(`ingest: duplicate result index ${index}`, { status, kind: 'malformed' });
		seen.add(index);
		const rowStatus = (r as { status?: unknown } | null)?.status;
		if (rowStatus !== 'ok' && rowStatus !== 'error' && rowStatus !== 'exists') {
			throw new TransportError(`ingest: unknown result status ${JSON.stringify(rowStatus)} at index ${index}`, { status, kind: 'malformed' });
		}
	}
	return results as IngestRowResult[];
}
