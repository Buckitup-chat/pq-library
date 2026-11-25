import { describe, expect, it } from 'vitest';
import { classifySlotPrior, contactsPriorOf, initialAccessDecision } from '@buckitup/pq-client/contactAccess';

describe('review: malformed stored contacts must not authorize an initial grant', () => {
	it.each([
		{ base: { contacts: 'not-a-contact-map' } },
		{ base: { contacts: [] } },
		{ base: ['not-a-contacts-record'] },
	])('treats malformed readable data as unknown: %j', ({ base }) => {
		const prior = contactsPriorOf(classifySlotPrior({ base, createdByThisWrite: false }));
		const decision = initialAccessDecision({
			confirmation: { ok: true }, prior,
			subjectHash: 'u_' + 'b'.repeat(128), contactPkey: 'verified-contact-key',
		});
		expect(decision).toEqual({ grant: false, reason: 'unknown-prior' });
	});
});
