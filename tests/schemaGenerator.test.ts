// Guards the generated signable-field table against drift from the backend.
//
// Tooling check: runs the real generator (scripts/gen-pq-schema.mjs) against
// a backend checkout (CHAT_REPO or ../chat) and asserts the committed
// schema.generated.ts is its exact output. Skipped when no checkout is
// present — the SDK suite still pins the table through the conformance
// vectors and the relation checks in packages/pq-client/tests/schema.test.ts;
// this test adds the backend comparison on machines that have both repos.
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import { generateSchema, findChatRepo, OUTPUT_PATH } from '../scripts/gen-pq-schema.mjs';

const chatRepo = findChatRepo();

describe('schema.generated.ts', () => {
	it.skipIf(!chatRepo)('is exactly what the backend schemas generate', () => {
		expect(fs.readFileSync(OUTPUT_PATH, 'utf8')).toBe(generateSchema(chatRepo!));
	});
});
