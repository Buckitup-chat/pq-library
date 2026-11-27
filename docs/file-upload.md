# File upload

`@buckitup/pq-client/fileUpload` uploads a file's encrypted chunks to a device
and returns the signed `files` manifest that commits them. The wire protocol is
the service's file storage specification,
[`pq_files.done.md` §2 and §4](https://github.com/Buckitup-chat/chat/blob/b1a11dd01c06d07ac7ed0132b02509fe36efd43d/docs/pq/reqs/files/pq_files.done.md),
answered by
[`FileChunkController.create/2`](https://github.com/Buckitup-chat/chat/blob/b1a11dd01c06d07ac7ed0132b02509fe36efd43d/lib/chat_web/controllers/file_chunk_controller.ex)
and
[`UploadOwner`](https://github.com/Buckitup-chat/chat/blob/b1a11dd01c06d07ac7ed0132b02509fe36efd43d/lib/chat/data/file/upload_owner.ex).

## What the SDK does and what the application keeps

`uploadFileChunks` encrypts each 4 MiB chunk under the file's secret, signs its
`file_chunks` row, PUTs the bytes with the signed row in the headers, and signs
the `files` manifest over the chunk signatures the device holds.

The application keeps:

- `file_id` and `enc_secret`, minted together and stored durably before the
  first PUT (§4.1), so an interrupted upload resumes with the same pair;
- the file's bytes, its queue, progress display and cancellation;
- reading the device's `file_chunks` rows (`readChunkRows`);
- its chunk cache (`onChunkStored`);
- what to do after `FileIdTakenError` or `NoWriteRightsError`;
- committing the manifest. The SDK returns it as a mutation and does not send
  it: an HTTP answer to one request is not the application's durable delivery
  or the device's acceptance of the file.

## API

```ts
uploadFileChunks(opts): Promise<{ fileId, encSecretB64, size, chunkCount, manifest }>
```

| Option | Meaning |
| --- | --- |
| `apiUrl` | The server's `/electric/v1` base; chunks go to `PUT {apiUrl}/file_chunk/{file_id}/{index}` |
| `fetch` | Optional; the global `fetch` otherwise |
| `bytes` | The whole file; an empty file is one sealed chunk |
| `uploaderHash`, `signSkey`, `signPkey` | The uploading identity: its `user_hash`, the key that signs chunk rows and the manifest, and the key stored rows are verified under |
| `fileId`, `encSecretB64` | The pair the application keeps |
| `readChunkRows(fileId, signal?)` | The device's `file_chunks` rows of the file by index, as the shape serves them (§ Stored rows); pass the signal to the underlying read |
| `resuming` | Chunks may already be on the device: read them first and skip the ones that verify |
| `onProgress({ fileId, done, total })` | After each chunk is on the device, in chunks |
| `onChunkStored(fileId, index, encrypted, dataHash)` | Only for a chunk the device accepted from this call; not awaited |
| `signal` | Aborts the PUT in flight, any wait, and every later step |

`manifest` is the `files` insert mutation (`rowMutation`), signed with
`signSkey`; `chunk_sign_hashes[i]` is base64 SHA3-512 of the raw signature bytes
of the chunk the device holds at index `i`.

## Answers

| Device answer | Result |
| --- | --- |
| 200 | The chunk is stored |
| 409 `chunk exists` | The device holds another signed chunk at that index and never replaces it: the stored row is bound (§ Stored rows) |
| 403 `uploader mismatch` | `FileIdTakenError`: another uploader holds `fileId`. Only a new `file_id` and `enc_secret` can upload the file; the SDK does not mint them |
| 403 `not_in_trust_chain` | `NoWriteRightsError`: the device's write gate refuses this identity |
| 429 | Waited out as `Retry-After` says (whole seconds, at most 10 s; 1 s when missing, negative or not a number), up to 8 times per chunk |
| Anything else | `Error` with `chunk {index} rejected: HTTP {status} {error}` |

Neither 403 is retried: another PUT gets the same answer. A body that is not
JSON or has no `error` is read as text, so the message still names the status.

## Stored rows, 409 and resume

After a 409 the manifest must bind the stored chunk's signature, never the one
just refused, and the refused bytes are not passed to `onChunkStored`.

`readChunkRows` should read a fresh snapshot of the `file_chunks` shape
(`file_id='…'`). Binary columns may be unpadded base64, `\x` hex or bytes;
integers may be strings. A read that fails counts as no rows, except cancellation,
which rejects the upload with the signal's reason. Cancellation ends the upload's
wait even if the reader ignores the signal; such an underlying read can still run
until it settles. A row missing
after a 409 is read again, three reads two seconds apart, and the upload then
fails with `chunk {i} of {file} is held on the device, but its row has not
arrived`.

A stored row is bound only when it names this `file_id` and index, this
uploader, the size this chunk has when sealed, and its signature verifies under
`signPkey`. `uploader_hash` alone proves nothing, since anyone can write it into
a row. After a 409 a row that fails ends the upload with `chunk {i} of {file}
is held by another upload`. On resume a row that fails is not bound; the chunk
is sent and the device's answer decides, so resume is never weaker than the 409
path.

A verified row proves that this identity signed a chunk of this size for this
`file_id` and index. It does not prove that the chunk was sealed under
`encSecretB64`: the SDK does not download stored ciphertext. That rests on the
application's pairing rule: a `file_id` is minted with its `enc_secret`, kept
with it before the first PUT, and never used with another secret. A reader of
the file detects a chunk sealed under another secret when it does not decrypt.

## Example

```ts
import { generateEncSecret, newFileId } from '@buckitup/pq-client/fileCrypto';
import { toBase64 } from '@buckitup/pq-client/signature';
import { FileIdTakenError, uploadFileChunks } from '@buckitup/pq-client/fileUpload';

const fileId = newFileId(uuidV7());
const encSecretB64 = toBase64(generateEncSecret());
await keepDurably({ fileId, encSecretB64 });

const { manifest } = await uploadFileChunks({
	apiUrl: 'https://device.example/electric/v1',
	bytes,
	uploaderHash: identity.userHash,
	signSkey,
	signPkey: identity.signPkey,
	fileId,
	encSecretB64,
	readChunkRows: async (id, signal) => {
		const read = await server.readShapeOnce<Record<string, unknown>>('file_chunks', `file_id='${id}'`, { signal });
		if (read.kind !== 'rows') throw new Error(`file_chunks read: ${read.kind}`);
		return new Map(read.rows.map((row) => [Number(row.chunk_index), row]));
	},
	signal,
});
await commitDurably(manifest);
```

`keepDurably` and `commitDurably` are the application's. On access mode
`trust`, read the shape with a read session's bearer token.
