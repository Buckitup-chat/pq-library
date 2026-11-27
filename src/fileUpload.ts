// File upload over the chunk endpoint (chat docs: reqs/pq_files.md §4).
//
// Upload: encrypt each 4 MiB chunk client-side, PUT the raw bytes with the
// signed metadata in headers — the chunk signature binds the uploader key to
// the exact bytes and position, which is why this endpoint needs no
// challenge. When every chunk is on the device, the caller commits the signed
// manifest through its write path; the server verifies each stored chunk
// against chunk_sign_hashes before accepting it.
//
// Resume is client-driven (§4.1): re-read which chunk indexes the device
// already holds through the file_chunks shape and re-PUT only the gaps.
// Progress is reported in chunks, not guessed percentages (§2.1).

import { sha3_512 } from '@noble/hashes/sha3';
import { abortableDelay } from './abortSignals.js';
import { CHUNK_SIZE, chunkCountOf, chunkDataHash, encryptChunk } from './fileCrypto.js';
import { rowMutation, signRow, verifyRow, type RowMutation } from './rows.js';
import { fromBase64, toBase64, toBytes } from './signature.js';

/** Another uploader holds this file_id on the device (pq_files §4): only a fresh pair can upload. */
export class FileIdTakenError extends Error {
	constructor(readonly fileId: string) {
		super(`file ${fileId} belongs to another uploader on this device`);
		this.name = 'FileIdTakenError';
	}
}

/** The device's trust chain does not let this account store files. */
export class NoWriteRightsError extends Error {
	constructor() {
		super('this account has no write rights on this device');
		this.name = 'NoWriteRightsError';
	}
}

const SEAL_OVERHEAD = 12 + 16;
const STORED_ROW_READS = 3;
const STORED_ROW_REREAD_MS = 2000;

const sleep = async (ms: number, signal?: AbortSignal) => {
	if (!signal) return new Promise((r) => setTimeout(r, ms));
	await abortableDelay(ms, signal);
	signal.throwIfAborted();
};

const retryAfterSeconds = (value: string | null): number => {
	const seconds = Number(value);
	return value && Number.isFinite(seconds) && seconds >= 0 ? seconds : 1;
};

const errorOf = async (r: Response): Promise<string> => {
	const text = await r.text();
	try {
		return String(JSON.parse(text).error ?? text);
	} catch {
		return text;
	}
};

// 'occupied': the device already stores another body at this index (409) and
// never replaces it — the caller decides from the stored row.
const putChunk = async (
	put: { apiUrl: string; fetch?: typeof fetch },
	fileId: string,
	index: number,
	body: Uint8Array,
	headers: Record<string, string>,
	signal?: AbortSignal,
): Promise<'stored' | 'occupied'> => {
	for (let attempt = 0; ; attempt++) {
		signal?.throwIfAborted();
		const r = await (put.fetch ?? globalThis.fetch)(`${put.apiUrl}/file_chunk/${fileId}/${index}`, {
			method: 'PUT',
			headers: { 'Content-Type': 'application/octet-stream', ...headers },
			body: body as unknown as NonNullable<Parameters<typeof fetch>[1]>['body'],
			signal,
		});
		signal?.throwIfAborted();
		if (r.ok) return 'stored';
		if (r.status === 409) return 'occupied';
		if (r.status === 403) {
			const error = await errorOf(r);
			if (error === 'not_in_trust_chain') throw new NoWriteRightsError();
			if (error === 'uploader mismatch') throw new FileIdTakenError(fileId);
			throw new Error(`chunk ${index} rejected: HTTP 403 ${error.slice(0, 120)}`);
		}
		// 429: the drive's single-writer upload lane is busy — the protocol
		// answer is to wait as told and retry, not to fail the file (§4).
		if (r.status === 429 && attempt < 8) {
			const after = retryAfterSeconds(r.headers.get('Retry-After'));
			await sleep(Math.min(after, 10) * 1000, signal);
			continue;
		}
		throw new Error(`chunk ${index} rejected: HTTP ${r.status} ${(await r.text()).slice(0, 120)}`);
	}
};

export const uploadFileChunks = async (opts: {
	apiUrl: string;
	fetch?: typeof fetch;
	bytes: Uint8Array;
	uploaderHash: string;
	signSkey: Uint8Array;
	signPkey: string | Uint8Array;
	/** Minted by the caller and kept from before the first PUT; the same pair resumes an interrupted upload. */
	fileId: string;
	encSecretB64: string;
	readChunkRows: (fileId: string, signal?: AbortSignal) => Promise<Map<number, Record<string, unknown>>>;
	/**
	 * Set when chunks may already be on the device (retry after a failure):
	 * the stored indexes are read first and not sent again. A stored chunk
	 * missed by that read is not lost — the device never replaces it and
	 * answers 409, and the upload then binds the stored row instead.
	 */
	resuming?: boolean;
	onProgress?: (p: { fileId: string; done: number; total: number }) => void;
	onChunkStored?: (fileId: string, index: number, encrypted: Uint8Array, dataHash: string) => unknown;
	signal?: AbortSignal;
}): Promise<{ fileId: string; encSecretB64: string; size: number; chunkCount: number; manifest: RowMutation }> => {
	const { bytes, uploaderHash, signSkey, signPkey, fileId, onProgress, signal } = opts;
	const encSecret = fromBase64(opts.encSecretB64);
	const total = chunkCountOf(bytes.length);
	const ownerTimestamp = Math.floor(Date.now() / 1000);
	const chunkSignHashes: string[] = [];

	/** Chunk rows the device already verified and stored for this file, by index.
	 * Resume needs the stored sign_b64, not just presence: a re-encrypted chunk
	 * gets a fresh nonce and therefore a different hash — the manifest must bind
	 * the bytes that are actually on the device. */
	// An unreachable shape reads as an empty map; the PUTs below are idempotent anyway.
	const existingChunks = async (): Promise<Map<number, Record<string, unknown>>> => {
		signal?.throwIfAborted();
		let onAbort: (() => void) | undefined;
		try {
			const read = Promise.resolve().then(() => {
				signal?.throwIfAborted();
				return opts.readChunkRows(fileId, signal);
			});
			const rows = signal ? await Promise.race([
				read,
				new Promise<never>((_, reject) => {
					onAbort = () => reject(signal.reason);
					signal.addEventListener('abort', onAbort, { once: true });
				}),
			]) : await read;
			signal?.throwIfAborted();
			return rows;
		} catch {
			signal?.throwIfAborted();
			return new Map();
		} finally {
			if (onAbort) signal?.removeEventListener('abort', onAbort);
		}
	};

	const isOwnStoredChunk = (row: Record<string, unknown>, i: number): boolean =>
		row.file_id === fileId
		&& Number(row.chunk_index) === i
		&& row.uploader_hash === uploaderHash
		&& Number(row.size) === Math.min((i + 1) * CHUNK_SIZE, bytes.length) - i * CHUNK_SIZE + SEAL_OVERHEAD
		&& verifyRow('file_chunks', row, signPkey).status === 'ok';

	const heldChunk = async (i: number): Promise<Record<string, unknown>> => {
		for (let read = 0; read < STORED_ROW_READS; read++) {
			if (read) await sleep(STORED_ROW_REREAD_MS, signal);
			const held = (await existingChunks()).get(i);
			if (!held) continue;
			if (!isOwnStoredChunk(held, i)) throw new Error(`chunk ${i} of ${fileId} is held by another upload`);
			return held;
		}
		throw new Error(`chunk ${i} of ${fileId} is held on the device, but its row has not arrived`);
	};

	// A fresh-where snapshot (see existingChunks) reflects the device's actual
	// state, so one read suffices for both the fresh and the resume path.
	const already = opts.resuming ? await existingChunks() : new Map<number, Record<string, unknown>>();

	for (let i = 0; i < total; i++) {
		signal?.throwIfAborted();

		const stored = already.get(i);
		if (stored && isOwnStoredChunk(stored, i)) {
			// The device already holds these bytes; the manifest must bind
			// their stored signature — re-encrypting would change the hash.
			chunkSignHashes.push(toBase64(sha3_512(toBytes(stored.sign_b64 as string))));
			onProgress?.({ fileId, done: i + 1, total });
			continue;
		}

		const plain = bytes.slice(i * CHUNK_SIZE, Math.min((i + 1) * CHUNK_SIZE, bytes.length));
		const encrypted = await encryptChunk(encSecret, plain);
		const dataHash = chunkDataHash(encrypted);

		// The signed payload is the chunk's manifest row (pq_files §1.2);
		// canonicalPayload sorts the fields, so order here is cosmetic.
		const { sign_b64: signB64 } = signRow(
			'file_chunks',
			{
				chunk_index: i,
				data_hash: dataHash,
				file_id: fileId,
				owner_timestamp: ownerTimestamp,
				size: encrypted.length,
				uploader_hash: uploaderHash,
			},
			signSkey,
		);
		const put = await putChunk(opts, fileId, i, encrypted, {
			'x-data-hash': dataHash,
			'x-size': String(encrypted.length),
			'x-uploader-hash': uploaderHash,
			'x-owner-timestamp': String(ownerTimestamp),
			'x-signature': signB64,
		}, signal);
		if (put === 'occupied') {
			// The device kept an earlier body for this index; the manifest must
			// bind that one, and the cache must not hold the refused bytes.
			const held = await heldChunk(i);
			chunkSignHashes.push(toBase64(sha3_512(toBytes(held.sign_b64 as string))));
			onProgress?.({ fileId, done: i + 1, total });
			continue;
		}
		// The manifest binds SHA3-512 of the RAW signature bytes per chunk.
		chunkSignHashes.push(toBase64(sha3_512(fromBase64(signB64))));
		// Seed the caller's chunk cache: the sender should never re-download
		// bytes it just encrypted. Fire-and-forget — caching must not slow
		// or fail the upload.
		void opts.onChunkStored?.(fileId, i, encrypted, dataHash);
		onProgress?.({ fileId, done: i + 1, total });
	}

	signal?.throwIfAborted();
	// Manifest: the trust anchor other devices use to accept chunks.
	const manifestFields = {
		chunk_count: total,
		chunk_sign_hashes: chunkSignHashes,
		chunk_size: CHUNK_SIZE,
		deleted_flag: false,
		file_id: fileId,
		owner_timestamp: ownerTimestamp,
		total_size: bytes.length,
		uploader_hash: uploaderHash,
	};
	return {
		fileId,
		encSecretB64: opts.encSecretB64,
		size: bytes.length,
		chunkCount: total,
		manifest: rowMutation('files', signRow('files', manifestFields, signSkey)),
	};
};
