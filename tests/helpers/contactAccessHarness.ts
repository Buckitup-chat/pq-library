import { expect } from 'vitest';
import {
	createContactAccess,
	type ContactAccess,
	type ContactAccessAdapters,
	type ContactAccessDevice,
	type ContactAccessIntent,
	type ContactAccessSession,
	type QueuedVouch,
	type RefusedVouch,
	type StoredContactAccessIntent,
	type ContactAccessDelivery,
	type ContactAccessWrite,
	verifyVouchRowWith,
} from '@buckitup/pq-client/contactAccess';
import { generateIdentityKeys, openIdentity, type IdentityHandle } from '@buckitup/pq-client/identity';
import { rowMutation } from '@buckitup/pq-client/rows';
import { TransportError } from '@buckitup/pq-client/transport';
import { createFakePqServer, type FakePqServer } from './fakePqServer';

export const DEVICE = 'Server_test_node';

type Entry = { id: string; issuerHash: string; write: ContactAccessWrite; signer: IdentityHandle; status: 'pending' | 'refused'; conflict: boolean };

export interface Durable {
	intents: Map<string, StoredContactAccessIntent & { issuerHash: string }>;
	outbox: Map<string, Entry>;
	sequence: number;
}

export interface World {
	server: FakePqServer;
	durable: Durable;
	device: { current: ContactAccessDevice | null; answers: ContactAccessDevice[] };
	shape: { frozen: Map<string, Record<string, unknown>> | null; down: boolean };
	ingest: { down: ((write: ContactAccessWrite) => boolean) | null };
	identities: Map<string, IdentityHandle>;
	service(): ContactAccess;
	session(who: IdentityHandle, stillCurrent?: () => boolean): ContactAccessSession;
	drain(): Promise<void>;
	settle(who: IdentityHandle, rounds?: number): Promise<void>;
	vouch(kind: string, issuer: IdentityHandle, subject: IdentityHandle): Record<string, unknown> | undefined;
	open(issuerHash: string): StoredContactAccessIntent[];
	resolved(issuerHash: string): Array<{ outcome: string; purpose?: string }>;
	identity(name: string): Promise<IdentityHandle>;
}

const keyOf = (row: Record<string, unknown>) => `${row.kind}|${row.issuer_hash}|${row.subject_hash}`;

export const createWorld = (): World => {
	const server = createFakePqServer();
	const durable: Durable = { intents: new Map(), outbox: new Map(), sequence: 0 };
	const identities = new Map<string, IdentityHandle>();
	const device: World['device'] = { current: null, answers: [] };
	const shape: World['shape'] = { frozen: null, down: false };
	const ingest: World['ingest'] = { down: null };

	const vouchRows = () => server.tables.get('vouch_tokens')!;

	const deliver = async (entry: Entry): Promise<ContactAccessDelivery> => {
		if (ingest.down?.(entry.write)) return { kind: 'failed', outboxId: entry.id, error: new TransportError('ingest is down', { kind: 'network' }) };
		let outcome;
		try {
			outcome = await server.transport.ingest([rowMutation('vouch_tokens', entry.write.row as never, entry.write.type)], entry.signer.sign);
		} catch (error) {
			return { kind: 'failed', outboxId: entry.id, error };
		}
		if (outcome.kind === 'written') {
			durable.outbox.delete(entry.id);
			return { kind: 'accepted', outboxId: entry.id };
		}
		entry.status = 'refused';
		entry.conflict = outcome.rejection.kind === 'exists';
		return entry.conflict && entry.write.type === 'insert'
			? { kind: 'conflict', outboxId: entry.id, error: outcome.rejection }
			: { kind: 'rejected', outboxId: entry.id, error: outcome.rejection };
	};

	const adapters = (): ContactAccessAdapters => ({
		readDeviceIdentity: async () => {
			const answer = device.answers.shift();
			if (answer) device.current = answer;
			return device.current ? { ...device.current } : null;
		},
		readVouchRows: async ({ issuerHash, subjectHash }) => {
			if (shape.down) throw new TransportError('shape unavailable', { kind: 'http', status: 503 });
			const source = shape.frozen ?? vouchRows();
			const rows = [...source.values()].filter((r) => r.subject_hash === subjectHash && (!issuerHash || r.issuer_hash === issuerHash));
			return { kind: 'rows', rows: rows.map((r) => ({ ...r, sign_b64: String(r.sign_b64).replace(/=+$/, ''), owner_timestamp: String(r.owner_timestamp), deleted_flag: String(r.deleted_flag) })) };
		},
		verifyVouchRow: verifyVouchRowWith(async (userHash) => {
			const card = server.tables.get('user_cards')!.get(userHash);
			return card ? String(card.sign_pkey) : null;
		}),
		intents: {
			list: async (issuerHash, { includeResolved }) => [...durable.intents.values()]
				.filter((e) => e.issuerHash === issuerHash && (includeResolved || (e.intent as { resolved?: boolean }).resolved !== true))
				.map(({ id, createdAt, intent }) => ({ id, createdAt, intent: structuredClone(intent) })),
			get: async (id) => {
				const e = durable.intents.get(id);
				return e ? { id: e.id, createdAt: e.createdAt, intent: structuredClone(e.intent) } : null;
			},
			enqueue: async (issuerHash, intent) => {
				const id = `intent-${++durable.sequence}`;
				durable.intents.set(id, { id, issuerHash, createdAt: durable.sequence, intent: structuredClone(intent) });
				return id;
			},
			update: async (id, intent) => {
				const e = durable.intents.get(id);
				if (!e || (e.intent as { resolved?: boolean }).resolved) return false;
				e.intent = structuredClone(intent);
				return true;
			},
			resolve: async (id, outcome) => {
				const e = durable.intents.get(id);
				if (!e) return true;
				const purpose = (e.intent as ContactAccessIntent).purpose;
				e.intent = { resolved: true, outcome, ...(purpose ? { purpose } : {}) };
				return true;
			},
		},
		outbox: {
			send: async (write, session) => {
				const signer = identities.get(session.issuerHash)!;
				const entry: Entry = { id: `outbox-${++durable.sequence}`, issuerHash: session.issuerHash, write, signer, status: 'pending', conflict: false };
				durable.outbox.set(entry.id, entry);
				const delivery = await deliver(entry);
				return delivery.kind === 'failed' ? { kind: 'queued', outboxId: entry.id } : delivery;
			},
			queued: async (issuerHash): Promise<QueuedVouch[]> => [...durable.outbox.values()]
				.filter((e) => e.issuerHash === issuerHash && e.status === 'pending')
				.map((e) => ({
					outboxId: e.id, kind: e.write.row.kind, issuerHash: e.write.row.issuer_hash, subjectHash: e.write.row.subject_hash,
					ownerTimestamp: e.write.row.owner_timestamp, settled: false,
				})),
			refused: async (issuerHash): Promise<RefusedVouch[]> => [...durable.outbox.values()]
				.filter((e) => e.issuerHash === issuerHash && e.status === 'refused')
				.map((e) => ({ outboxId: e.id, conflict: e.conflict })),
			discard: async (outboxId) => { durable.outbox.delete(outboxId); },
		},
		lock: async (_key, work) => work(),
	});

	const world: World = {
		server,
		durable,
		device,
		shape,
		ingest,
		identities,
		service: () => createContactAccess(adapters()),
		session: (who, stillCurrent = () => true) => ({
			issuerHash: who.userHash,
			signingKey: async () => who.exportKeys().signSkey,
			stillCurrent,
		}),
		drain: async () => {
			for (const entry of [...durable.outbox.values()]) if (entry.status === 'pending') await deliver(entry);
		},
		settle: async (who, rounds = 3) => {
			const service = world.service();
			for (let i = 0; i < rounds; i++) {
				await world.drain();
				for (const entry of world.open(who.userHash)) await service.apply(entry, world.session(who));
			}
		},
		vouch: (kind, issuer, subject) => vouchRows().get(keyOf({ kind, issuer_hash: issuer.userHash, subject_hash: subject.userHash })),
		open: (issuerHash) => [...durable.intents.values()]
			.filter((e) => e.issuerHash === issuerHash && (e.intent as { resolved?: boolean }).resolved !== true)
			.map(({ id, createdAt, intent }) => ({ id, createdAt, intent })),
		resolved: (issuerHash) => [...durable.intents.values()]
			.filter((e) => e.issuerHash === issuerHash && (e.intent as { resolved?: boolean }).resolved === true)
			.map((e) => e.intent as { outcome: string; purpose?: string }),
		identity: async (name) => {
			const me = openIdentity(generateIdentityKeys());
			const outcome = await server.transport.ingest([rowMutation('user_cards', me.userCard({ name, ownerTimestamp: 1 }))], me.sign);
			expect(outcome.kind).toBe('written');
			identities.set(me.userHash, me);
			return me;
		},
	};
	return world;
};

export const freeze = (world: World) => {
	world.shape.frozen = new Map([...world.server.tables.get('vouch_tokens')!.entries()].map(([k, v]) => [k, { ...v }]));
};
