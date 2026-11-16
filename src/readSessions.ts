import { withTimeout } from './abortSignals.js';
import type { ReadSessionOutcome, RequestOptions, Signer, Transport } from './transport.js';

export interface ReadSessionIdentity {
	userHash: string;
	sign: Signer;
}

export interface ReadSessionOpenContext {
	userHash: string;
	sign: Signer;
	signal: AbortSignal;
	timeoutMs?: number;
}

export type ReadSessionResult = ReadSessionOutcome | { kind: 'disposed' };

export interface ReadSessionsOptions {
	transport: Pick<Transport, 'openReadSession'>;
	identity: ReadSessionIdentity;
	onUnknownUser?: (shape: string) => Promise<boolean>;
	openSession?: (shape: string, context: ReadSessionOpenContext) => Promise<ReadSessionOutcome>;
	onOutcome?: (shape: string, outcome: ReadSessionOutcome) => void;
	renewAheadMs?: number;
	minRenewDelayMs?: number;
	timeoutMs?: number;
	now?: () => number;
}

export interface ReadSessions {
	readonly userHash: string;
	readonly disposed: boolean;
	bearer(shapeOrTable: string): string | null;
	hasValidToken(shapeOrTable: string): boolean;
	open(shape: string): Promise<ReadSessionResult>;
	reopen(shape: string, table?: string): Promise<ReadSessionResult>;
	invalidate(shape: string): void;
	dispose(): void;
}

export class ReadSessionsDisposedError extends Error {
	constructor() {
		super('read sessions: disposed');
		this.name = 'ReadSessionsDisposedError';
	}
}

interface Entry {
	token: string;
	shape: string;
	expiresAt: number;
	renewTimer: ReturnType<typeof setTimeout> | null;
}

const DEFAULT_RENEW_AHEAD_MS = 60_000;
const DEFAULT_MIN_RENEW_DELAY_MS = 1_000;
const DEFAULT_OPEN_TIMEOUT_MS = 15_000;

export function createReadSessions(options: ReadSessionsOptions): ReadSessions {
	const { transport, identity } = options;
	const now = options.now ?? (() => Date.now());
	const renewAheadMs = options.renewAheadMs ?? DEFAULT_RENEW_AHEAD_MS;
	const minRenewDelayMs = options.minRenewDelayMs ?? DEFAULT_MIN_RENEW_DELAY_MS;
	const sessions = new Map<string, Entry>();
	const inflight = new Map<string, Promise<ReadSessionResult>>();
	const tableShapes = new Map<string, string>();
	const lifetime = new AbortController();
	let disposed = false;

	const sign: Signer = (message) => {
		if (disposed) throw new ReadSessionsDisposedError();
		return identity.sign(message);
	};

	const defaultOpen = async (shape: string, context: ReadSessionOpenContext): Promise<ReadSessionOutcome> => {
		const request: RequestOptions = { signal: context.signal };
		const first = await transport.openReadSession(context.userHash, shape, context.sign, request);
		if (first.kind !== 'unknown_user' || !options.onUnknownUser) return first;
		if (!(await options.onUnknownUser(shape)) || context.signal.aborted) return first;
		return transport.openReadSession(context.userHash, shape, context.sign, request);
	};
	const openWith = options.openSession ?? defaultOpen;

	const shapeOf = (shapeOrTable: string) => tableShapes.get(shapeOrTable) ?? shapeOrTable;

	const live = (shapeOrTable: string): Entry | null => {
		const entry = sessions.get(shapeOf(shapeOrTable));
		return entry && now() < entry.expiresAt ? entry : null;
	};

	const drop = (shape: string) => {
		const entry = sessions.get(shape);
		if (entry?.renewTimer) clearTimeout(entry.renewTimer);
		sessions.delete(shape);
	};

	const scheduleRenewal = (entry: Entry) => {
		const delay = Math.max(entry.expiresAt - now() - renewAheadMs, minRenewDelayMs);
		entry.renewTimer = setTimeout(() => {
			entry.renewTimer = null;
			if (disposed || sessions.get(entry.shape) !== entry) return;
			open(entry.shape).catch(() => undefined);
		}, delay);
	};

	const run = async (shape: string): Promise<ReadSessionResult> => {
		let outcome: ReadSessionOutcome;
		try {
			const timeoutMs = options.timeoutMs ?? DEFAULT_OPEN_TIMEOUT_MS;
			outcome = await openWith(shape, { userHash: identity.userHash, sign, signal: withTimeout(lifetime.signal, timeoutMs), timeoutMs });
		} catch (e) {
			if (disposed) return { kind: 'disposed' };
			throw e;
		}
		if (disposed) return { kind: 'disposed' };
		if (outcome.kind === 'opened') {
			drop(outcome.shape);
			const entry: Entry = { token: outcome.token, shape: outcome.shape, expiresAt: outcome.expiresAt, renewTimer: null };
			sessions.set(outcome.shape, entry);
			if (outcome.shape !== shape) tableShapes.set(shape, outcome.shape);
			scheduleRenewal(entry);
		}
		options.onOutcome?.(shape, outcome);
		return outcome;
	};

	const open = (shape: string): Promise<ReadSessionResult> => {
		if (disposed) return Promise.resolve({ kind: 'disposed' });
		const existing = inflight.get(shape);
		if (existing) return existing;
		const promise = run(shape).finally(() => {
			if (inflight.get(shape) === promise) inflight.delete(shape);
		});
		inflight.set(shape, promise);
		return promise;
	};

	return {
		userHash: identity.userHash,
		get disposed() {
			return disposed;
		},
		bearer(shapeOrTable) {
			const entry = live(shapeOrTable);
			return entry ? `Bearer ${entry.token}` : null;
		},
		hasValidToken: (shapeOrTable) => live(shapeOrTable) !== null,
		open,
		reopen(shape, table) {
			if (table && !disposed) tableShapes.set(table, shape);
			drop(shape);
			return open(shape);
		},
		invalidate: drop,
		dispose() {
			if (disposed) return;
			disposed = true;
			for (const shape of [...sessions.keys()]) drop(shape);
			tableShapes.clear();
			inflight.clear();
			lifetime.abort();
		},
	};
}
