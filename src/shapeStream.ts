import { abortableDelay, withTimeout } from './abortSignals.js';
import type { ReadSessionResult, ReadSessions } from './readSessions.js';
import { applyShapeMessages, type ShapeChange } from './shapeLog.js';
import type { ShapeChunk, Transport } from './transport.js';

export interface ShapeUpdate<T> {
	changes: ShapeChange<T>[];
	rows: ReadonlyMap<string, T>;
	upToDate: boolean;
}

export type ShapeSubscriptionError =
	| { kind: 'transport'; error: unknown; retrying: true }
	| { kind: 'server'; status: number; error: string | null; retrying: boolean }
	| { kind: 'read_session_required'; shape: string; retrying: false }
	| { kind: 'read_session'; shape: string; result: ReadSessionResult; retrying: false }
	| { kind: 'protocol'; error: unknown; retrying: false }
	| { kind: 'internal'; error: unknown; retrying: false };

export type ShapeEnd = { kind: 'disposed' } | { kind: 'failed'; error: ShapeSubscriptionError };

export interface ShapeSubscriptionOptions<T> {
	table: string;
	where?: string;
	columns?: string[];
	sessions?: ReadSessions | null;
	signal?: AbortSignal;
	requestTimeoutMs?: number;
	liveTimeoutMs?: number;
	retryDelayMs?: (attempt: number) => number;
	onChange?: (update: ShapeUpdate<T>) => void;
	onReset?: () => void;
	onError?: (error: ShapeSubscriptionError) => void;
}

export interface ShapeSubscription<T> {
	readonly rows: ReadonlyMap<string, T>;
	readonly upToDate: boolean;
	readonly handle: string | null;
	readonly offset: string;
	readonly ready: Promise<boolean>;
	readonly done: Promise<ShapeEnd>;
	dispose(): void;
}

const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_LIVE_TIMEOUT_MS = 60_000;
const defaultRetryDelay = (attempt: number) => Math.min(30_000, 500 * 2 ** attempt);

const isTransient = (status: number) => status >= 500 || status === 429;

const TRANSIENT_TRANSPORT = new Set(['network', 'timeout', 'http']);
const transportKindOf = (error: unknown): string | null =>
	(error as { name?: unknown })?.name === 'TransportError' ? String((error as { kind?: unknown }).kind) : null;

export function subscribeShape<T>(
	transport: Pick<Transport, 'readShapeChunk'>,
	options: ShapeSubscriptionOptions<T>,
): ShapeSubscription<T> {
	const rows = new Map<string, T>();
	const controller = new AbortController();
	const retryDelay = options.retryDelayMs ?? defaultRetryDelay;
	let handle: string | null = null;
	let offset = '-1';
	let cursor: string | null = null;
	let upToDate = false;
	let stopped = false;

	let resolveReady!: (value: boolean) => void;
	const ready = new Promise<boolean>((resolve) => (resolveReady = resolve));
	let resolveDone!: (end: ShapeEnd) => void;
	const done = new Promise<ShapeEnd>((resolve) => (resolveDone = resolve));

	const end = (result: ShapeEnd) => {
		if (stopped) return;
		stopped = true;
		controller.abort();
		options.signal?.removeEventListener('abort', dispose);
		resolveReady(false);
		resolveDone(result);
	};

	function dispose() {
		end({ kind: 'disposed' });
	}

	const fail = (error: ShapeSubscriptionError) => {
		if (stopped) return;
		options.onError?.(error);
		end({ kind: 'failed', error });
	};

	const reset = (nextHandle: string | null) => {
		rows.clear();
		handle = nextHandle;
		offset = '-1';
		cursor = null;
		upToDate = false;
		options.onReset?.();
	};

	const request = (): Promise<ShapeChunk<T>> => {
		const timeoutMs = upToDate
			? (options.liveTimeoutMs ?? DEFAULT_LIVE_TIMEOUT_MS)
			: (options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS);
		return transport.readShapeChunk<T>(
			{ table: options.table, where: options.where, columns: options.columns, offset, handle, live: upToDate, cursor },
			{ signal: withTimeout(controller.signal, timeoutMs), authorization: options.sessions?.bearer(options.table) ?? undefined },
		);
	};

	const retryOrFail = async (error: unknown, attempt: number): Promise<boolean> => {
		const kind = transportKindOf(error);
		if (kind === 'malformed') {
			fail({ kind: 'protocol', error, retrying: false });
			return false;
		}
		if (!kind || !TRANSIENT_TRANSPORT.has(kind)) {
			fail({ kind: 'internal', error, retrying: false });
			return false;
		}
		options.onError?.({ kind: 'transport', error, retrying: true });
		await abortableDelay(retryDelay(attempt), controller.signal);
		return true;
	};

	const loop = async () => {
		let attempt = 0;
		let sessionReopened = false;
		while (!stopped) {
			let chunk: ShapeChunk<T>;
			try {
				chunk = await request();
			} catch (error) {
				if (stopped || !(await retryOrFail(error, attempt++))) return;
				continue;
			}
			if (stopped) return;
			switch (chunk.kind) {
				case 'must_refetch':
					reset(chunk.handle);
					continue;
				case 'read_session_required': {
					if (!options.sessions) return fail({ kind: 'read_session_required', shape: chunk.shape, retrying: false });
					if (sessionReopened) return fail({ kind: 'read_session_required', shape: chunk.shape, retrying: false });
					sessionReopened = true;
					let result: ReadSessionResult;
					try {
						result = await options.sessions.reopen(chunk.shape, options.table);
					} catch (error) {
						sessionReopened = false;
						if (stopped || !(await retryOrFail(error, attempt++))) return;
						continue;
					}
					if (stopped) return;
					if (result.kind !== 'opened') return fail({ kind: 'read_session', shape: chunk.shape, result, retrying: false });
					continue;
				}
				case 'failed':
					if (!isTransient(chunk.status)) return fail({ kind: 'server', status: chunk.status, error: chunk.error, retrying: false });
					options.onError?.({ kind: 'server', status: chunk.status, error: chunk.error, retrying: true });
					await abortableDelay(retryDelay(attempt++), controller.signal);
					continue;
				case 'chunk': {
					attempt = 0;
					sessionReopened = false;
					if (!chunk.handle || !chunk.offset) {
						return fail({ kind: 'protocol', error: new Error('the shape response carries no handle or offset'), retrying: false });
					}
					handle = chunk.handle;
					offset = chunk.offset;
					cursor = chunk.cursor;
					const changes = applyShapeMessages(rows, chunk.messages);
					const reachedUpToDate = chunk.upToDate && !upToDate;
					if (chunk.upToDate) upToDate = true;
					if (changes.length || reachedUpToDate) options.onChange?.({ changes, rows, upToDate });
					if (upToDate) resolveReady(true);
				}
			}
		}
	};

	if (options.signal?.aborted) dispose();
	else {
		options.signal?.addEventListener('abort', dispose, { once: true });
		void loop().catch((error) => fail({ kind: 'internal', error, retrying: false }));
	}

	return {
		rows,
		get upToDate() {
			return upToDate;
		},
		get handle() {
			return handle;
		},
		get offset() {
			return offset;
		},
		ready,
		done,
		dispose,
	};
}
