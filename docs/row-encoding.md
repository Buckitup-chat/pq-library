# Row encoding and schema ownership

## Base64: the signature carries padding, the shape does not

**Since:** 2026-08-26

The same bytes arrive in two different encodings, and you can only confuse them
once per debugging session — the signature simply does not verify, with no hint
as to why.

| Where | Encoding | SDK contract |
|---|---|---|
| signature payload | **with** padding (`=`) | Canonical binary field encoding in `src/signature.ts` |
| binary columns from `/shapes` | **without** padding | Transport decoding and normalization in `src/signature.ts` |

**Consequence.** A value taken from a shape cannot go into a signature payload
as-is — it has to be padded with `=` to a multiple of four. This applies to
producing a signature and to checking one: when verifying a received row the
payload is assembled from the padded form, or not a single row will verify.

`encodeField` in [`src/signature.ts`](../src/signature.ts) pads `_cert`, `_pkey` and `_b64`
values and each element of a binary array (`files.chunk_sign_hashes`), so the
payload is the same whether a row is being signed or verified.


## Schema ownership

The released field table is `src/schema.generated.ts`. `signRow` and
`rowMutation` select fields according to that versioned table. Do not infer
one relation's fields from another. The conformance tests pin canonical
payloads and hashes.

`scripts/gen-pq-schema.mjs` is optional compatibility tooling for importing
Ecto service schemas. Use `CHAT_REPO` and `npm run schema:check` when validating
that integration. Updating a service schema does not automatically change a
published SDK; review any generated change against the versioned contract.
