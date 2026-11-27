import { describe, it, expect, vi, afterEach } from 'vitest';
import { sha3_512 } from '@noble/hashes/sha3';
import { generateIdentityKeys, openIdentity, type IdentityHandle } from '@buckitup/pq-client/identity';
import { CHUNK_SIZE, chunkDataHash, decryptChunk, generateEncSecret, newFileId } from '@buckitup/pq-client/fileCrypto';
import { toBase64, toBase64Unpadded, toBytes, verifyRow } from '@buckitup/pq-client/rows';
import { FileIdTakenError, NoWriteRightsError, uploadFileChunks } from '@buckitup/pq-client/fileUpload';

type Row = Record<string, unknown>;

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
	new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

const ann = openIdentity(generateIdentityKeys());
const bob = openIdentity(generateIdentityKeys());
const API = 'http://device.test/electric/v1';

let uuidSeq = 0;
const freshFileId = () => newFileId(`0192cccc-0000-7000-8000-${String(++uuidSeq).padStart(12, '0')}`);
const resigned = (row: Row): Row => ({ ...row, sign_b64: ann.signRow('file_chunks', row).sign_b64 });
const signHashOf = (signB64: unknown) => toBase64(sha3_512(toBytes(String(signB64))));

const device = () => {
	const cards = new Map<string, Uint8Array>([[ann.userHash, ann.signPkey], [bob.userHash, bob.signPkey]]);
	const files = new Map<string, Map<number, { row: Row; body: Uint8Array }>>();
	const denied = new Set<string>();
	const puts: number[] = [];
	let busy: Array<string | null> = [];
	let override: (() => Response) | null = null;

	const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
		const m = /\/file_chunk\/([^/]+)\/(\d+)$/.exec(String(input));
		if (!m || init?.method !== 'PUT') return json(404, { error: 'not found' });
		const [, fileId, indexText] = m;
		const index = Number(indexText);
		puts.push(index);
		init.signal?.throwIfAborted();
		if (override) return override();
		if (busy.length) {
			const retryAfter = busy.shift()!;
			return json(429, { error: 'too many requests' }, retryAfter === null ? {} : { 'retry-after': retryAfter });
		}
		const h = new Headers(init.headers);
		const row: Row = {
			file_id: fileId,
			chunk_index: index,
			data_hash: h.get('x-data-hash'),
			size: Number(h.get('x-size')),
			uploader_hash: h.get('x-uploader-hash'),
			owner_timestamp: Number(h.get('x-owner-timestamp')),
			sign_b64: h.get('x-signature'),
		};
		const pkey = cards.get(String(row.uploader_hash));
		if (!pkey || verifyRow('file_chunks', row, pkey).status !== 'ok') return json(401, { error: 'invalid signature' });
		if (denied.has(String(row.uploader_hash))) return json(403, { error: 'not_in_trust_chain', max_depth: 3 });
		const chunks = files.get(fileId) ?? new Map();
		if ([...chunks.values()].some((c) => c.row.uploader_hash !== row.uploader_hash)) return json(403, { error: 'uploader mismatch' });
		const existing = chunks.get(index);
		if (existing) return signHashOf(existing.row.sign_b64) === signHashOf(row.sign_b64) ? json(200, { status: 'ok' }) : json(409, { error: 'chunk exists' });
		const body = new Uint8Array(init.body as Uint8Array);
		if (chunkDataHash(body) !== row.data_hash || body.length !== row.size) return json(422, { error: 'body hash mismatch' });
		chunks.set(index, { row, body });
		files.set(fileId, chunks);
		return json(200, { status: 'ok' });
	}) as typeof fetch;

	const readChunkRows = async (fileId: string) => new Map([...(files.get(fileId)?.entries() ?? [])].map(([i, c]) => [i, {
		...c.row,
		chunk_index: String(i),
		size: String(c.row.size),
		owner_timestamp: String(c.row.owner_timestamp),
		sign_b64: toBase64Unpadded(toBytes(String(c.row.sign_b64))),
	} as Row]));

	return {
		fetchImpl, files, denied, puts, readChunkRows,
		setBusy: (answers: Array<string | null>) => { busy = [...answers]; },
		answer: (fn: () => Response) => { override = fn; },
	};
};

type Device = ReturnType<typeof device>;

const fileOf = (size: number) => {
	const bytes = new Uint8Array(size);
	for (let i = 0; i < size; i++) bytes[i] = (i * 7 + 3) & 0xff;
	return bytes;
};

type Options = Parameters<typeof uploadFileChunks>[0];
const run = (d: Device, overrides: Partial<Options> = {}, as: IdentityHandle = ann) => {
	const options: Options = {
		apiUrl: API,
		fetch: d.fetchImpl,
		bytes: fileOf(10),
		uploaderHash: as.userHash,
		signSkey: as.exportKeys().signSkey,
		signPkey: as.signPkey,
		fileId: freshFileId(),
		encSecretB64: toBase64(generateEncSecret()),
		readChunkRows: d.readChunkRows,
		...overrides,
	};
	return { options, result: uploadFileChunks(options) };
};

const storeFirstChunk = async (d: Device, as: IdentityHandle, fileId: string, encSecretB64: string, bytes: Uint8Array) => {
	await run(d, { fileId, encSecretB64, bytes: bytes.subarray(0, Math.min(CHUNK_SIZE, bytes.length)) }, as).result.catch(() => {});
	d.puts.length = 0;
	return d.files.get(fileId)!.get(0)!.row;
};

const waits = () => {
	const asked: number[] = [];
	const realSetTimeout = globalThis.setTimeout;
	vi.spyOn(globalThis, 'setTimeout').mockImplementation(((fn: () => void, ms?: number) => {
		asked.push(Number(ms));
		return realSetTimeout(fn, 0);
	}) as typeof setTimeout);
	return asked;
};

afterEach(() => {
	vi.restoreAllMocks();
});

describe('uploadFileChunks', () => {
	it('stores every chunk and returns a signed manifest that binds the stored signatures', async () => {
		const d = device();
		const cached: number[] = [];
		const progress: number[] = [];
		const { options, result } = run(d, {
			bytes: fileOf(CHUNK_SIZE + 10),
			onChunkStored: (_fileId, index) => { cached.push(index); },
			onProgress: (p) => progress.push(p.done),
		});
		const out = await result;

		expect(d.puts).toEqual([0, 1]);
		expect(cached).toEqual([0, 1]);
		expect(progress).toEqual([1, 2]);
		const manifest = (out.manifest as { modified: Row }).modified;
		expect(out.manifest.syncMetadata).toEqual({ relation: 'files' });
		expect(verifyRow('files', manifest, ann.signPkey)).toEqual({ status: 'ok' });
		expect(manifest).toMatchObject({ file_id: options.fileId, uploader_hash: ann.userHash, total_size: CHUNK_SIZE + 10, chunk_size: CHUNK_SIZE, chunk_count: 2, deleted_flag: false });
		const stored = d.files.get(options.fileId)!;
		expect(manifest.chunk_sign_hashes).toEqual([signHashOf(stored.get(0)!.row.sign_b64), signHashOf(stored.get(1)!.row.sign_b64)]);
		const secret = toBytes(options.encSecretB64);
		const first = await decryptChunk(secret, stored.get(0)!.body);
		const second = await decryptChunk(secret, stored.get(1)!.body);
		expect(Buffer.from(first).equals(Buffer.from(options.bytes.subarray(0, CHUNK_SIZE)))).toBe(true);
		expect(Buffer.from(second).equals(Buffer.from(options.bytes.subarray(CHUNK_SIZE)))).toBe(true);
	});

	it('uploads an empty file as one sealed chunk', async () => {
		const d = device();
		const out = await run(d, { bytes: new Uint8Array(0) }).result;
		expect((out.manifest as { modified: Row }).modified).toMatchObject({ total_size: 0, chunk_count: 1 });
		expect(d.files.get(out.fileId)!.get(0)!.row.size).toBe(28);
	});

	it('binds the stored chunk after a 409 and never hands on the refused body', async () => {
		const d = device();
		const fileId = freshFileId();
		const encSecretB64 = toBase64(generateEncSecret());
		const bytes = fileOf(CHUNK_SIZE + 10);
		const earlier = await storeFirstChunk(d, ann, fileId, encSecretB64, bytes);
		const cached: number[] = [];

		const out = await run(d, { fileId, encSecretB64, bytes, onChunkStored: (_f, index) => { cached.push(index); } }).result;

		expect(d.puts).toEqual([0, 1]);
		expect(cached).toEqual([1]);
		expect((out.manifest as { modified: Row }).modified.chunk_sign_hashes).toEqual([
			signHashOf(earlier.sign_b64),
			signHashOf(d.files.get(fileId)!.get(1)!.row.sign_b64),
		]);
	});

	it.each([
		['another uploader', (row: Row): Row => resigned({ ...row, uploader_hash: bob.userHash })],
		['a forged signature', (row: Row): Row => ({ ...row, sign_b64: bob.signRow('file_chunks', row).sign_b64 })],
		['a tampered data hash', (row: Row): Row => ({ ...row, data_hash: 'fd_' + '0'.repeat(128) })],
		['another size', (row: Row): Row => resigned({ ...row, size: String(Number(row.size) + 1) })],
		['another file', (row: Row): Row => resigned({ ...row, file_id: freshFileId() })],
		['another index', (row: Row): Row => resigned({ ...row, chunk_index: '1' })],
	])('refuses to bind a 409 whose stored row has %s', async (_what, tamper) => {
		const d = device();
		const fileId = freshFileId();
		const encSecretB64 = toBase64(generateEncSecret());
		await storeFirstChunk(d, ann, fileId, encSecretB64, fileOf(10));
		const tampered = async (id: string) => new Map([...await d.readChunkRows(id)].map(([i, row]) => [i, tamper(row)]));

		await expect(run(d, { fileId, encSecretB64, readChunkRows: tampered }).result).rejects.toThrow(/chunk 0 of .* is held by another upload/);
		expect(d.puts).toEqual([0]);
	});

	it('reads the stored row again, a bounded number of times, while the shape has not delivered it', async () => {
		const d = device();
		const fileId = freshFileId();
		const encSecretB64 = toBase64(generateEncSecret());
		const earlier = await storeFirstChunk(d, ann, fileId, encSecretB64, fileOf(10));
		const asked = waits();
		let reads = 0;
		const lagging = async (id: string) => (++reads < 3 ? new Map() : d.readChunkRows(id));

		const out = await run(d, { fileId, encSecretB64, readChunkRows: lagging }).result;
		expect(reads).toBe(3);
		expect(asked).toEqual([2000, 2000]);
		expect((out.manifest as { modified: Row }).modified.chunk_sign_hashes).toEqual([signHashOf(earlier.sign_b64)]);
	});

	it.each([
		['never arrives', async () => new Map()],
		['cannot be read', async () => { throw new TypeError('Failed to fetch'); }],
	])('fails after a 409 when the stored row %s', async (_what, reader) => {
		const d = device();
		const fileId = freshFileId();
		const encSecretB64 = toBase64(generateEncSecret());
		await storeFirstChunk(d, ann, fileId, encSecretB64, fileOf(10));
		waits();
		const readChunkRows = vi.fn(reader as () => Promise<Map<number, Row>>);

		await expect(run(d, { fileId, encSecretB64, readChunkRows }).result).rejects.toThrow(/held on the device, but its row has not arrived/);
		expect(readChunkRows).toHaveBeenCalledTimes(3);
	});

	it('throws FileIdTakenError for a file_id another uploader holds, without retrying', async () => {
		const d = device();
		const fileId = freshFileId();
		await storeFirstChunk(d, bob, fileId, toBase64(generateEncSecret()), fileOf(10));

		const failure = run(d, { fileId }).result;
		await expect(failure).rejects.toBeInstanceOf(FileIdTakenError);
		await expect(failure).rejects.toMatchObject({ fileId });
		expect(d.puts).toEqual([0]);
	});

	it('throws NoWriteRightsError for an account the write gate refuses, without retrying', async () => {
		const d = device();
		d.denied.add(ann.userHash);
		const cached: number[] = [];
		await expect(run(d, { onChunkStored: (_f, index) => { cached.push(index); } }).result).rejects.toBeInstanceOf(NoWriteRightsError);
		expect(d.puts).toEqual([0]);
		expect(cached).toEqual([]);
	});

	it.each([
		['another 403', () => json(403, { error: 'forbidden' }), /HTTP 403 forbidden/],
		['a 403 with a text body', () => new Response('<html>no</html>', { status: 403 }), /HTTP 403 <html>no<\/html>/],
		['a 403 with no body', () => new Response(null, { status: 403 }), /HTTP 403/],
		['a deleted file', () => json(410, { error: 'file deleted' }), /HTTP 410/],
		['a 5xx', () => json(503, { error: 'storage not ready' }), /HTTP 503/],
	])('fails on %s once, with the status in the message', async (_what, answer, message) => {
		const d = device();
		d.answer(answer);
		const failure = await run(d).result.catch((e: unknown) => e);
		expect(failure).toBeInstanceOf(Error);
		expect(failure).not.toBeInstanceOf(TypeError);
		expect(failure).not.toBeInstanceOf(FileIdTakenError);
		expect(failure).not.toBeInstanceOf(NoWriteRightsError);
		expect(String((failure as Error).message)).toMatch(message);
		expect(d.puts).toEqual([0]);
	});

	it('waits out 429s as told and sends the same signed chunk again', async () => {
		const d = device();
		const asked = waits();
		d.setBusy(['2', null, '0']);
		await run(d).result;
		expect(d.puts).toEqual([0, 0, 0, 0]);
		expect(asked).toEqual([2000, 1000, 0]);
	});

	it.each([['abc', 1000], ['-5', 1000], ['Infinity', 1000], ['', 1000], ['1e12', 10000]])('bounds the wait for Retry-After %j', async (retryAfter, ms) => {
		const d = device();
		const asked = waits();
		d.setBusy([retryAfter]);
		await run(d).result;
		expect(asked).toEqual([ms]);
	});

	it('gives up after eight 429s', async () => {
		const d = device();
		waits();
		d.setBusy(Array(9).fill('0'));
		await expect(run(d).result).rejects.toThrow(/chunk 0 rejected: HTTP 429/);
		expect(d.puts).toEqual(Array(9).fill(0));
	});

	it('stops waiting on abort and sends nothing more', async () => {
		const d = device();
		d.setBusy(['5']);
		const ctrl = new AbortController();
		const { result } = run(d, { signal: ctrl.signal });
		await vi.waitFor(() => expect(d.puts).toHaveLength(1));
		ctrl.abort();
		await expect(result).rejects.toMatchObject({ name: 'AbortError' });
		expect(d.puts).toEqual([0]);
	});

	it('sends nothing when aborted before the first chunk', async () => {
		const d = device();
		const ctrl = new AbortController();
		ctrl.abort();
		await expect(run(d, { signal: ctrl.signal }).result).rejects.toMatchObject({ name: 'AbortError' });
		expect(d.puts).toEqual([]);
	});

	it('does not return a manifest when cancelled during the last occupied chunk read', async () => {
		const d = device();
		const fileId = freshFileId();
		const encSecretB64 = toBase64(generateEncSecret());
		await storeFirstChunk(d, ann, fileId, encSecretB64, fileOf(10));
		const ctrl = new AbortController();
		const reason = new DOMException('cancelled', 'AbortError');
		const readChunkRows = async (id: string) => {
			ctrl.abort(reason);
			return d.readChunkRows(id);
		};
		await expect(run(d, { fileId, encSecretB64, signal: ctrl.signal, readChunkRows }).result).rejects.toBe(reason);
		expect(d.puts).toEqual([0]);
	});

	it.each([true, false])('cancels a pending stored-row read even when the reader ignores abort (resuming=%s)', async (resuming) => {
		const d = device();
		if (!resuming) d.answer(() => json(409, { error: 'chunk exists' }));
		const ctrl = new AbortController();
		const reason = new DOMException('cancelled', 'AbortError');
		let started!: () => void;
		let release!: () => void;
		const reading = new Promise<void>((resolve) => { started = resolve; });
		const readChunkRows = vi.fn((_id: string, _signal?: AbortSignal) => new Promise<Map<number, Row>>((resolve) => {
			release = () => resolve(new Map());
			started();
		}));
		let outcome: unknown = 'pending';
		const { result } = run(d, { resuming, signal: ctrl.signal, readChunkRows });
		const observed = result.then(() => { outcome = 'resolved'; }, (error) => { outcome = error; });
		await reading;
		ctrl.abort(reason);
		await new Promise<void>((resolve) => setImmediate(resolve));
		try {
			expect(outcome).toBe(reason);
			expect(readChunkRows).toHaveBeenCalledWith(expect.any(String), ctrl.signal);
			expect(d.puts).toEqual(resuming ? [] : [0]);
		} finally {
			release();
			await observed;
		}
	});

	it.each([true, false])('does not return a manifest when cancelled on the last progress callback (resuming=%s)', async (resuming) => {
		const d = device();
		const fileId = freshFileId();
		const encSecretB64 = toBase64(generateEncSecret());
		if (resuming) await storeFirstChunk(d, ann, fileId, encSecretB64, fileOf(10));
		const ctrl = new AbortController();
		const reason = new DOMException('cancelled', 'AbortError');
		await expect(run(d, { fileId, encSecretB64, resuming, signal: ctrl.signal, onProgress: () => ctrl.abort(reason) }).result).rejects.toBe(reason);
	});

	it('resumes by binding verified stored rows and sending only the rest', async () => {
		const d = device();
		const fileId = freshFileId();
		const encSecretB64 = toBase64(generateEncSecret());
		const bytes = fileOf(CHUNK_SIZE + 10);
		const earlier = await storeFirstChunk(d, ann, fileId, encSecretB64, bytes);

		const out = await run(d, { fileId, encSecretB64, bytes, resuming: true }).result;
		expect(d.puts).toEqual([1]);
		expect((out.manifest as { modified: Row }).modified.chunk_sign_hashes).toEqual([
			signHashOf(earlier.sign_b64),
			signHashOf(d.files.get(fileId)!.get(1)!.row.sign_b64),
		]);
	});

	it('does not trust a forged row on resume: it sends the chunk and checks what the device holds', async () => {
		const d = device();
		const fileId = freshFileId();
		const encSecretB64 = toBase64(generateEncSecret());
		await storeFirstChunk(d, ann, fileId, encSecretB64, fileOf(10));
		const forged = async (id: string) => new Map([...await d.readChunkRows(id)].map(([i, row]) => [i, { ...row, data_hash: 'fd_' + 'f'.repeat(128) }]));

		await expect(run(d, { fileId, encSecretB64, resuming: true, readChunkRows: forged }).result).rejects.toThrow(/held by another upload/);
		expect(d.puts).toEqual([0]);
	});

	it('resumes through the 409 path when the stored rows cannot be read up front', async () => {
		const d = device();
		const fileId = freshFileId();
		const encSecretB64 = toBase64(generateEncSecret());
		const earlier = await storeFirstChunk(d, ann, fileId, encSecretB64, fileOf(10));
		let reads = 0;
		const flaky = async (id: string) => {
			if (++reads === 1) throw new TypeError('Failed to fetch');
			return d.readChunkRows(id);
		};

		const out = await run(d, { fileId, encSecretB64, resuming: true, readChunkRows: flaky }).result;
		expect(d.puts).toEqual([0]);
		expect((out.manifest as { modified: Row }).modified.chunk_sign_hashes).toEqual([signHashOf(earlier.sign_b64)]);
	});

	it('PUTs the chunk to the device under apiUrl with the signed row in its headers', async () => {
		const d = device();
		const seen: Array<{ url: string; init?: RequestInit }> = [];
		const recording = (async (input: RequestInfo | URL, init?: RequestInit) => {
			seen.push({ url: String(input), init });
			return d.fetchImpl(input, init);
		}) as typeof fetch;
		const { options, result } = run(d, { fetch: recording });
		await result;
		expect(seen[0].url).toBe(`${API}/file_chunk/${options.fileId}/0`);
		expect(seen[0].init?.method).toBe('PUT');
		const row = d.files.get(options.fileId)!.get(0)!.row;
		expect(seen[0].init?.headers).toEqual({
			'Content-Type': 'application/octet-stream',
			'x-data-hash': chunkDataHash(seen[0].init?.body as Uint8Array),
			'x-size': '38',
			'x-uploader-hash': ann.userHash,
			'x-owner-timestamp': String(row.owner_timestamp),
			'x-signature': row.sign_b64,
		});
		expect(verifyRow('file_chunks', row, ann.signPkey)).toEqual({ status: 'ok' });
	});
});
