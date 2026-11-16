# Row encoding and schema ownership

## Base64: the signature carries padding, the shape does not

**Since:** 2026-08-26

The same bytes arrive in two different encodings, and you can only confuse them
once per debugging session — the signature simply does not verify, with no hint
as to why.

| Where | Encoding | Source |
|---|---|---|
| signature payload | **with** padding (`=`) | `chat/lib/chat/data/integrity.ex:89,93` — `Base.encode64/1`, which is `padding: true` in Elixir |
| binary columns from `/shapes` | **without** padding | `chat/lib/chat_web/plugs/hex_to_base64_adapter.ex:122,157` — `Base.encode64(bin, padding: false)` |

**Consequence.** A value taken from a shape cannot go into a signature payload
as-is — it has to be padded with `=` to a multiple of four. This applies to
producing a signature and to checking one: when verifying a received row the
payload is assembled from the padded form, or not a single row will verify.

`encodeField` in [`src/signature.ts`](../src/signature.ts) pads `_cert`, `_pkey` and `_b64`
values and each element of a binary array (`files.chunk_sign_hashes`), so the
payload is the same whether a row is being signed or verified.


## Schema ownership

The backend Ecto schemas define wire fields. The SDK generates its table in
`src/schema.generated.ts` with `scripts/gen-pq-schema.mjs`; use `CHAT_REPO`
and `npm run schema:check` to verify it. `signRow` and `rowMutation` select
fields according to that table. Do not infer one relation’s fields from another.
