import { signRow, verifyRow, wireBool } from './rows.js';
import { contactKeyVouch, type ContactKeyVouch } from './verifyCard.js';
import { storageScope } from './vouch.js';

export const CONTACT_ACCESS_INTENT = 'contact-access';

export const CONTACT_ACCESS_SCOPES = ['read', 'write'] as const;
export type ContactAccessScope = typeof CONTACT_ACCESS_SCOPES[number];

const USER_HASH = /^u_[0-9a-f]{128}$/;

/** The backend a client is talking to, as its /device_identity answers. */
export interface ContactAccessDevice {
	deviceId: string;
	adminHash: string | null;
}

export type VouchRowsRead = { kind: 'rows'; rows: Record<string, unknown>[] } | { kind: 'forbidden' };

export interface SignedVouchRow {
	kind: string;
	issuer_hash: string;
	subject_hash: string;
	owner_timestamp: number;
	deleted_flag: boolean;
	sign_b64: string;
}

export type VouchKeyFields = Pick<SignedVouchRow, 'kind' | 'issuer_hash' | 'subject_hash'>;

/** One signed vouch_tokens write, for the application's durable delivery. */
export type ContactAccessWrite =
	| { type: 'insert'; row: SignedVouchRow }
	| { type: 'update'; key: VouchKeyFields; changes: Pick<SignedVouchRow, 'deleted_flag' | 'owner_timestamp' | 'sign_b64'>; row: SignedVouchRow };

/**
 * How durable delivery answered a write. `failed` is transient: an entry it
 * kept is retried by the outbox. `conflict` is an insert that met a stored row
 * of the same key; `rejected` is any other final refusal.
 */
export type ContactAccessDelivery =
	| { kind: 'accepted'; outboxId: string | null }
	| { kind: 'queued'; outboxId: string | null }
	| { kind: 'failed'; outboxId: string | null; error: unknown }
	| { kind: 'conflict'; outboxId: string | null; error: unknown }
	| { kind: 'rejected'; outboxId: string | null; error: unknown };

/** A vouch write still in the outbox; `settled` once the server accepted it. */
export interface QueuedVouch {
	outboxId: string;
	kind: string;
	issuerHash: string;
	subjectHash: string;
	ownerTimestamp: number;
	settled: boolean;
}

/** A vouch write the outbox gave up on; `conflict` when the server held a row of its key. */
export interface RefusedVouch {
	outboxId: string;
	conflict: boolean;
}

export interface ContactAccessSession {
	issuerHash: string;
	signingKey: () => Promise<Uint8Array>;
	stillCurrent: () => boolean;
}

export interface ContactAccessIntent {
	kind: typeof CONTACT_ACCESS_INTENT;
	subjectHash: string;
	granted: boolean;
	deviceId?: string;
	purpose?: string;
	dispatched?: DispatchedVouch[];
	open?: boolean;
	learned?: { kind: string; floor: number; exists: boolean }[];
}

/** A stored intent: a pending request, or the marker it leaves when resolved (`{ resolved: true, outcome, purpose }`). */
export interface StoredContactAccessIntent {
	id: string;
	createdAt: number;
	intent: unknown;
}

export interface ContactAccessIntentStore {
	list(issuerHash: string, opts: { includeResolved: boolean }): Promise<StoredContactAccessIntent[]>;
	get(id: string): Promise<StoredContactAccessIntent | null>;
	enqueue(issuerHash: string, intent: ContactAccessIntent): Promise<string | null>;
	update(id: string, intent: ContactAccessIntent): Promise<boolean>;
	/** Replaces the intent by a resolved marker that keeps its `purpose`. */
	resolve(id: string, outcome: string): Promise<boolean>;
}

export interface ContactAccessOutbox {
	send(write: ContactAccessWrite, session: ContactAccessSession): Promise<ContactAccessDelivery>;
	queued(issuerHash: string): Promise<QueuedVouch[]>;
	refused(issuerHash: string): Promise<RefusedVouch[]>;
	discard(outboxId: string): Promise<void>;
}

export interface ContactAccessAdapters {
	readDeviceIdentity(): Promise<ContactAccessDevice | null>;
	/** Current vouch_tokens rows matching the filter; throws when they cannot be read. */
	readVouchRows(filter: { issuerHash?: string; subjectHash: string }): Promise<VouchRowsRead>;
	/** Whether a replicated vouch row verifies against its issuer's card; false when it does not or cannot yet. */
	verifyVouchRow(row: Record<string, unknown>): Promise<boolean>;
	intents: ContactAccessIntentStore;
	outbox: ContactAccessOutbox;
	lock<T>(key: string, work: () => Promise<T>): Promise<T>;
	/** Wall clock in seconds. */
	now?: () => number;
}

export class ContactAccessFencedError extends Error {
	constructor(message = 'contact access: the account changed before the rows were sent') {
		super(message);
		this.name = 'ContactAccessFencedError';
	}
}

export type VouchStep = 'inserted' | 'updated' | 'unchanged' | 'unverified';

export interface DispatchedVouch {
	kind: string;
	outboxId: string;
	timestamp: number;
	accepted: boolean;
}

export type SkipReason = 'no-owner' | 'not-vouched' | 'identity-unavailable' | 'device-changed';

export type ContactVouchOutcome =
	| { kind: 'done'; steps: Record<string, VouchStep>; dispatched: DispatchedVouch[] }
	| { kind: 'skipped'; reason: SkipReason };

export type ContactAccessResult = 'resolved' | 'retry';

export type ScopeState = 'granted' | 'revoked' | 'absent' | 'unverified';

export interface ContactAccessScopes {
	read: ScopeState;
	write: ScopeState;
}

export interface ContactAccessRequests {
	pending: { granted: boolean } | null;
	last: { granted: boolean; outcome: string } | null;
}

export interface ContactAccessSnapshot {
	issuerHash: string;
	subjectHash: string;
	identity: ContactAccessDevice | null;
	scopes: ContactAccessScopes | null;
	requests: ContactAccessRequests | null;
	mayGrant: boolean | null;
}

/** The prior contents of a slot a write landed on. */
export type SlotPrior = { state: 'readable'; value: unknown } | { state: 'new' } | { state: 'unknown' };

/** The contacts list a confirmation was written over. */
export type ContactsPrior = { state: 'readable'; contacts: Record<string, unknown> } | { state: 'new' } | { state: 'unknown' };

export type InitialAccessDecision =
	| { grant: true }
	| { grant: false; reason: 'not-verified' | 'unknown-prior' | 'already-confirmed' };

/**
 * What a slot held before a write: the value read, a slot this write created
 * (an empty list that is known to be empty), or unknown — an existing slot
 * whose row this client cannot read is not an empty one.
 */
export const classifySlotPrior = ({ base, createdByThisWrite }: { base: unknown; createdByThisWrite: boolean }): SlotPrior => {
	if (base !== null && base !== undefined) return { state: 'readable', value: base };
	return createdByThisWrite ? { state: 'new' } : { state: 'unknown' };
};

const isRecord = (value: unknown): value is Record<string, unknown> => {
	if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
	const proto = Object.getPrototypeOf(value);
	return proto === Object.prototype || proto === null;
};

const isContactMap = (value: unknown): value is Record<string, Record<string, unknown>> =>
	isRecord(value) && Object.values(value).every(isRecord);

/**
 * The contacts list of a contacts-slot prior. A readable record without a
 * list holds none; a record, list or entry of any other shape is unknown.
 */
export const contactsPriorOf = (prior: SlotPrior): ContactsPrior => {
	if (prior.state !== 'readable') return { state: prior.state };
	if (!isRecord(prior.value)) return { state: 'unknown' };
	const { contacts } = prior.value;
	if (contacts === undefined) return { state: 'readable', contacts: {} };
	return isContactMap(contacts) ? { state: 'readable', contacts } : { state: 'unknown' };
};

const isContactsPrior = (prior: unknown): prior is Exclude<ContactsPrior, { state: 'unknown' }> => {
	if (!isRecord(prior)) return false;
	if (prior.state === 'new') return true;
	return prior.state === 'readable' && isContactMap(prior.contacts);
};

type PriorEntry = { kind: 'absent' } | { kind: 'entry'; confirmed: boolean; contactPkey: string | undefined } | { kind: 'malformed' };

const priorEntryOf = (entry: unknown): PriorEntry => {
	if (entry === undefined) return { kind: 'absent' };
	if (!isRecord(entry)) return { kind: 'malformed' };
	const { confirmed, contact_pkey: contactPkey } = entry;
	if (confirmed !== undefined && typeof confirmed !== 'boolean') return { kind: 'malformed' };
	if (contactPkey !== undefined && typeof contactPkey !== 'string') return { kind: 'malformed' };
	if (confirmed === true && contactPkey === undefined) return { kind: 'malformed' };
	return { kind: 'entry', confirmed: confirmed === true, contactPkey };
};

/**
 * Whether a QR confirmation issues the contact's initial device access: only
 * a confirmation the card verifies, made over a contacts list known to hold
 * no confirmation of that key. Anything else — an unknown list, or one that
 * already confirmed this key — grants nothing, so a repeated confirmation
 * never restores access the issuer took back.
 */
export const initialAccessDecision = (input: {
	confirmation: ContactKeyVouch;
	prior: unknown;
	subjectHash: string;
	contactPkey: string;
}): InitialAccessDecision => {
	if (!input.confirmation.ok) return { grant: false, reason: 'not-verified' };
	if (!isContactsPrior(input.prior)) return { grant: false, reason: 'unknown-prior' };
	if (input.prior.state === 'new') return { grant: true };
	const before = priorEntryOf(Object.hasOwn(input.prior.contacts, input.subjectHash) ? input.prior.contacts[input.subjectHash] : undefined);
	if (before.kind === 'malformed') return { grant: false, reason: 'unknown-prior' };
	if (before.kind === 'entry' && before.confirmed && before.contactPkey === input.contactPkey) return { grant: false, reason: 'already-confirmed' };
	return { grant: true };
};

export { contactKeyVouch as verifyContactConfirmation };

export type ConfirmedAccess = 'granted' | 'revoked' | 'not-granted' | 'partial' | 'unknown' | 'unavailable';

export const confirmedAccessOf = (scopes: ContactAccessScopes): Exclude<ConfirmedAccess, 'unavailable'> => {
	const states = [scopes.read, scopes.write];
	if (states.includes('unverified')) return 'unknown';
	if (states.every((s) => s === 'granted')) return 'granted';
	if (states.includes('granted')) return 'partial';
	if (states.every((s) => s === 'revoked')) return 'revoked';
	return 'not-granted';
};

export type ContactAccessNotice =
	| 'unavailable'
	| 'unverified'
	| 'no-owner'
	| 'grant-not-in-effect'
	| 'cannot-grant'
	| `last:${string}`;

export interface ContactAccessView {
	loading: boolean;
	deviceId: string | null;
	confirmed: ConfirmedAccess | 'loading';
	/** The scope still granted when the state is partial. */
	partialScope: ContactAccessScope | null;
	/** False when the issuer's own access on the device is gone, so its grant gives nothing. */
	inEffect: boolean | null;
	pending: { granted: boolean } | null;
	switchOn: boolean;
	canChange: boolean;
	notice: ContactAccessNotice | null;
}

const LAST_NOTICES = new Set(['skipped:not-vouched', 'skipped:no-owner', 'skipped:device-changed', 'overridden']);

/** The access state a client shows: confirmed rows, the request in flight, and whether the switch may be used. */
export const contactAccessView = (snapshot: ContactAccessSnapshot | null, opts: { submitting?: { granted: boolean } | null } = {}): ContactAccessView => {
	const pending = snapshot?.requests?.pending ?? opts.submitting ?? null;
	if (!snapshot) {
		return { loading: true, deviceId: null, confirmed: 'loading', partialScope: null, inEffect: null, pending, switchOn: pending?.granted ?? false, canChange: false, notice: null };
	}
	const confirmed: ConfirmedAccess = !snapshot.identity || !snapshot.scopes ? 'unavailable' : confirmedAccessOf(snapshot.scopes);
	const hasGrant = confirmed === 'granted' || confirmed === 'partial';
	const noOwner = snapshot.identity?.adminHash === null;
	const known = confirmed === 'granted' || confirmed === 'partial' || confirmed === 'revoked' || confirmed === 'not-granted';
	const canChange = !pending && known && !noOwner && (hasGrant || snapshot.mayGrant !== false);
	const last = pending ? null : snapshot.requests?.last ?? null;
	let notice: ContactAccessNotice | null = null;
	if (confirmed === 'unavailable') notice = 'unavailable';
	else if (confirmed === 'unknown') notice = 'unverified';
	else if (noOwner) notice = 'no-owner';
	else if (snapshot.mayGrant === false) notice = hasGrant ? 'grant-not-in-effect' : 'cannot-grant';
	else if (last && last.granted !== hasGrant && LAST_NOTICES.has(last.outcome)) notice = `last:${last.outcome}`;
	return {
		loading: false,
		deviceId: snapshot.identity?.deviceId ?? null,
		confirmed,
		partialScope: confirmed === 'partial' ? (snapshot.scopes?.read === 'granted' ? 'read' : 'write') : null,
		inEffect: hasGrant ? snapshot.mayGrant : null,
		pending,
		switchOn: pending?.granted ?? hasGrant,
		canChange,
		notice,
	};
};

type Stored = { state: 'verified'; row: SignedVouchRow } | { state: 'unverified' };

interface Superseded {
	floor: number;
	exists?: boolean;
}

type Plan =
	| { write: ContactAccessWrite; step: 'inserted' | 'updated' }
	| { write: null; step: 'unchanged' | 'unverified' };

const coversDeviceStorage = (kind: string, deviceId: string) => {
	const wanted = ['device', deviceId, 'storage'];
	return kind.split('.').every((seg, i) => i >= wanted.length || seg === '*' || seg === wanted[i]);
};

const raise = (map: Map<string, Superseded>, kind: string, timestamp: number, exists = false) => {
	const was = map.get(kind);
	map.set(kind, { floor: Math.max(was?.floor ?? 0, timestamp), exists: (was?.exists ?? false) || exists });
};

const purposeFor = (deviceId: string, subjectHash: string, granted: boolean) =>
	[CONTACT_ACCESS_INTENT, deviceId, subjectHash, granted ? 'grant' : 'revoke'].join('|');

const parsePurpose = (purpose: unknown): { deviceId: string; subjectHash: string; granted: boolean } | null => {
	if (typeof purpose !== 'string') return null;
	const parts = purpose.split('|');
	const op = parts[parts.length - 1];
	if (parts.length < 4 || parts[0] !== CONTACT_ACCESS_INTENT || (op !== 'grant' && op !== 'revoke')) return null;
	return { deviceId: parts.slice(1, -2).join('|'), subjectHash: parts[parts.length - 2], granted: op === 'grant' };
};

/** A `verifyVouchRow` adapter from a lookup of verified card sign keys. */
export const verifyVouchRowWith = (signPkeyOf: (userHash: string) => Promise<string | null>) =>
	async (row: Record<string, unknown>): Promise<boolean> => {
		try {
			const signPkey = await signPkeyOf(String(row.issuer_hash ?? ''));
			return !!signPkey && verifyRow('vouch_tokens', row, signPkey).status === 'ok';
		} catch {
			return false;
		}
	};

export const isContactAccessIntent = (intent: unknown, subjectHash?: string): intent is ContactAccessIntent =>
	(intent as ContactAccessIntent | null)?.kind === CONTACT_ACCESS_INTENT
	&& (subjectHash === undefined || (intent as ContactAccessIntent).subjectHash === subjectHash);

const reaches = (state: ScopeState, granted: boolean) => (granted ? state === 'granted' : state === 'revoked' || state === 'absent');

type BoundIntent = ContactAccessIntent & { deviceId: string };

export interface ContactAccess {
	/** Stores a grant or revoke durably and tries it once. `deviceId` binds it to the device the caller showed. */
	request(session: ContactAccessSession, subjectHash: string, granted: boolean, deviceId?: string): Promise<ContactAccessResult>;
	/** Issues the initial grant a verified QR confirmation calls for, if any. */
	afterConfirmation(session: ContactAccessSession, input: { confirmation: ContactKeyVouch; prior: unknown; subjectHash: string; contactPkey: string }): Promise<InitialAccessDecision & { result?: ContactAccessResult }>;
	/** Advances a stored request: supersession, device binding, sending, and confirmation through verified rows. */
	apply(entry: StoredContactAccessIntent, session: ContactAccessSession): Promise<ContactAccessResult>;
	readScopes(issuerHash: string, subjectHash: string, deviceId: string): Promise<ContactAccessScopes>;
	readRequests(issuerHash: string, subjectHash: string, deviceId: string): Promise<ContactAccessRequests>;
	issuerMayGrant(issuerHash: string, identity: ContactAccessDevice): Promise<boolean>;
	snapshot(issuerHash: string, subjectHash: string): Promise<ContactAccessSnapshot>;
}

export function createContactAccess(adapters: ContactAccessAdapters): ContactAccess {
	const now = adapters.now ?? (() => Math.floor(Date.now() / 1000));
	const nextTimestamp = (after: number) => Math.max(now(), Number(after || 0) + 1);

	const verifies = async (row: Record<string, unknown>): Promise<boolean> => {
		try {
			return await adapters.verifyVouchRow(row);
		} catch {
			return false;
		}
	};

	const holdsDeviceVouch = async (userHash: string, deviceId: string): Promise<boolean> => {
		const read = await adapters.readVouchRows({ subjectHash: userHash });
		if (read.kind === 'forbidden') return false;
		for (const row of read.rows) {
			if (row.subject_hash !== userHash || typeof row.kind !== 'string' || wireBool(row.deleted_flag)) continue;
			if (!coversDeviceStorage(row.kind, deviceId)) continue;
			if (await verifies(row)) return true;
		}
		return false;
	};

	const readStored = async (issuerHash: string, subjectHash: string): Promise<Map<string, Stored>> => {
		const read = await adapters.readVouchRows({ issuerHash, subjectHash });
		if (read.kind === 'forbidden') throw new Error('contact access: the vouch rows are not readable for this account');
		const stored = new Map<string, Stored>();
		for (const row of read.rows) {
			if (row.issuer_hash !== issuerHash || row.subject_hash !== subjectHash || typeof row.kind !== 'string') continue;
			stored.set(row.kind, await verifies(row)
				? {
					state: 'verified',
					row: {
						kind: row.kind,
						issuer_hash: issuerHash,
						subject_hash: subjectHash,
						owner_timestamp: Number(row.owner_timestamp),
						deleted_flag: wireBool(row.deleted_flag),
						sign_b64: String(row.sign_b64),
					},
				}
				: { state: 'unverified' });
		}
		return stored;
	};

	const readScopeStates = async (issuerHash: string, subjectHash: string, deviceId: string) => {
		const stored = await readStored(issuerHash, subjectHash);
		const reading = (scope: ContactAccessScope): { state: ScopeState; timestamp: number } => {
			const found = stored.get(storageScope(deviceId, scope));
			if (!found) return { state: 'absent', timestamp: 0 };
			if (found.state === 'unverified') return { state: 'unverified', timestamp: 0 };
			return { state: found.row.deleted_flag ? 'revoked' : 'granted', timestamp: found.row.owner_timestamp };
		};
		return { read: reading('read'), write: reading('write') };
	};

	const supersedeQueued = async (issuerHash: string, keys: VouchKeyFields[], into: Map<string, Superseded>, keep: Set<string>) => {
		const kinds = new Set(keys.map((k) => k.kind));
		for (const queued of await adapters.outbox.queued(issuerHash)) {
			if (queued.subjectHash !== keys[0].subject_hash || queued.issuerHash !== issuerHash || !kinds.has(queued.kind)) continue;
			raise(into, queued.kind, queued.ownerTimestamp);
			if (!keep.has(queued.kind)) await adapters.outbox.discard(queued.outboxId);
		}
	};

	const signed = (fields: Omit<SignedVouchRow, 'sign_b64'>, signSkey: Uint8Array): SignedVouchRow =>
		signRow('vouch_tokens', fields, signSkey) as unknown as SignedVouchRow;

	const insert = (key: VouchKeyFields, granted: boolean, after: number, signSkey: Uint8Array): Plan => ({
		write: { type: 'insert', row: signed({ ...key, owner_timestamp: nextTimestamp(after), deleted_flag: !granted }, signSkey) },
		step: 'inserted',
	});

	const update = (key: VouchKeyFields, granted: boolean, after: number, signSkey: Uint8Array): Plan => {
		const row = signed({ ...key, owner_timestamp: nextTimestamp(after), deleted_flag: !granted }, signSkey);
		return {
			write: { type: 'update', key, changes: { deleted_flag: row.deleted_flag, owner_timestamp: row.owner_timestamp, sign_b64: row.sign_b64 }, row },
			step: 'updated',
		};
	};

	const planFor = (key: VouchKeyFields, stored: Stored | undefined, granted: boolean, superseded: Superseded | undefined, signSkey: Uint8Array): Plan => {
		if (stored?.state === 'unverified') return { write: null, step: 'unverified' };
		const floor = superseded?.floor ?? 0;
		if (!stored) {
			if (superseded?.exists) return update(key, granted, floor, signSkey);
			if (!granted && !superseded) return { write: null, step: 'unchanged' };
			return insert(key, granted, floor, signSkey);
		}
		if (!superseded && stored.row.deleted_flag === !granted) return { write: null, step: 'unchanged' };
		return update(key, granted, Math.max(stored.row.owner_timestamp, floor), signSkey);
	};

	const setScopes = async (
		session: ContactAccessSession,
		subjectHash: string,
		deviceId: string,
		granted: boolean,
		refused: Map<string, Superseded>,
	): Promise<ContactVouchOutcome> => {
		const { issuerHash, stillCurrent } = session;
		const identity = await adapters.readDeviceIdentity();
		if (!stillCurrent()) throw new ContactAccessFencedError();
		if (!identity) return { kind: 'skipped', reason: 'identity-unavailable' };
		if (identity.deviceId !== deviceId) return { kind: 'skipped', reason: 'device-changed' };
		if (identity.adminHash === null) return { kind: 'skipped', reason: 'no-owner' };
		if (!USER_HASH.test(subjectHash)) throw new Error('contact access: the subject is not a user hash');
		if (granted && identity.adminHash !== issuerHash) {
			const vouched = await holdsDeviceVouch(issuerHash, identity.deviceId);
			if (!stillCurrent()) throw new ContactAccessFencedError();
			if (!vouched) return { kind: 'skipped', reason: 'not-vouched' };
		}

		const keys: VouchKeyFields[] = CONTACT_ACCESS_SCOPES.map((scope) => ({
			kind: storageScope(identity.deviceId, scope),
			issuer_hash: issuerHash,
			subject_hash: subjectHash,
		}));
		const stored = await readStored(issuerHash, subjectHash);
		if (!stillCurrent()) throw new ContactAccessFencedError();
		const signSkey = await session.signingKey();
		const superseded = new Map(refused);
		const unverified = new Set(keys.filter((k) => stored.get(k.kind)?.state === 'unverified').map((k) => k.kind));
		await supersedeQueued(issuerHash, keys, superseded, unverified);
		if (!stillCurrent()) throw new ContactAccessFencedError();

		const plans = keys.map((key) => planFor(key, stored.get(key.kind), granted, superseded.get(key.kind), signSkey));
		const dispatched: DispatchedVouch[] = [];
		const send = async (write: ContactAccessWrite, kind: string): Promise<ContactAccessDelivery> => {
			const delivery = await adapters.outbox.send(write, session);
			if (delivery.outboxId && (delivery.kind === 'accepted' || delivery.kind === 'queued' || delivery.kind === 'failed')) {
				dispatched.push({ kind, outboxId: delivery.outboxId, timestamp: write.row.owner_timestamp, accepted: delivery.kind === 'accepted' });
			}
			return delivery;
		};

		if (!stillCurrent()) throw new ContactAccessFencedError();
		const deliveries = await Promise.all(plans.map((plan, i) => (plan.write ? send(plan.write, keys[i].kind) : Promise.resolve(null))));

		const steps: Record<string, VouchStep> = {};
		let failure: unknown = null;
		for (const [i, key] of keys.entries()) {
			const plan = plans[i];
			const delivery = deliveries[i];
			if (!delivery || delivery.kind === 'accepted' || delivery.kind === 'queued' || (delivery.kind === 'failed' && delivery.outboxId)) {
				steps[key.kind] = plan.step;
				continue;
			}
			if (plan.step !== 'inserted' || delivery.kind !== 'conflict') {
				failure ??= delivery.error ?? new Error(`contact access: the ${key.kind} row was not taken`);
				continue;
			}
			if (!stillCurrent()) throw new ContactAccessFencedError();
			if (delivery.outboxId) await adapters.outbox.discard(delivery.outboxId);
			const again = (await readStored(issuerHash, subjectHash)).get(key.kind);
			const next = again
				? planFor(key, again, granted, superseded.get(key.kind), signSkey)
				: update(key, granted, superseded.get(key.kind)?.floor ?? 0, signSkey);
			if (!next.write) {
				steps[key.kind] = next.step;
				continue;
			}
			if (!stillCurrent()) throw new ContactAccessFencedError();
			const retried = await send(next.write, key.kind);
			if (retried.kind === 'conflict' || retried.kind === 'rejected' || (retried.kind === 'failed' && !retried.outboxId)) {
				failure ??= retried.error;
				continue;
			}
			steps[key.kind] = next.step;
		}
		if (failure) throw failure;
		return { kind: 'done', steps, dispatched };
	};

	const queueFor = async (issuerHash: string, subjectHash: string, deviceId: string) =>
		(await adapters.intents.list(issuerHash, { includeResolved: false }))
			.filter((e): e is StoredContactAccessIntent & { intent: ContactAccessIntent } => isContactAccessIntent(e.intent, subjectHash))
			.filter((e) => (e.intent.deviceId ?? deviceId) === deviceId)
			.sort((a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1));

	const bindDevice = async (entry: StoredContactAccessIntent & { intent: ContactAccessIntent }, deviceId: string): Promise<BoundIntent | null> => {
		const { intent } = entry;
		if (intent.deviceId !== undefined) return intent as BoundIntent;
		const bound: BoundIntent = { ...intent, deviceId, purpose: purposeFor(deviceId, intent.subjectHash, intent.granted) };
		return (await adapters.intents.update(entry.id, bound)) ? bound : null;
	};

	const settleOnRows = async (id: string, intent: BoundIntent, session: ContactAccessSession, dispatched: DispatchedVouch[]): Promise<ContactAccessResult> => {
		let scopes: Awaited<ReturnType<typeof readScopeStates>> | null = null;
		try {
			scopes = await readScopeStates(session.issuerHash, intent.subjectHash, intent.deviceId);
		} catch {
			scopes = null;
		}
		if (!session.stillCurrent()) return 'retry';
		if (scopes) {
			const read = scopes;
			const ownTimestamp = (scope: ContactAccessScope) => Math.max(0, ...dispatched
				.filter((d) => d.kind === storageScope(intent.deviceId, scope))
				.map((d) => d.timestamp));
			const settled = (scope: ContactAccessScope) => {
				const sent = ownTimestamp(scope);
				const { state, timestamp } = read[scope];
				if (sent === 0) return reaches(state, intent.granted);
				return state === (intent.granted ? 'granted' : 'revoked') && timestamp >= sent;
			};
			if (CONTACT_ACCESS_SCOPES.every(settled)) {
				await adapters.intents.resolve(id, 'applied');
				return 'resolved';
			}
			const overridden = CONTACT_ACCESS_SCOPES.some((scope) => {
				const sent = ownTimestamp(scope);
				const { state, timestamp } = read[scope];
				return sent > 0 && state !== 'unverified' && !reaches(state, intent.granted) && timestamp > sent;
			});
			if (overridden) {
				await adapters.intents.resolve(id, 'overridden');
				return 'resolved';
			}
		}
		await adapters.intents.update(id, { ...intent, dispatched, open: false, learned: [] });
		return 'retry';
	};

	const apply = async (entry: StoredContactAccessIntent, session: ContactAccessSession): Promise<ContactAccessResult> => {
		if (!isContactAccessIntent(entry.intent)) return 'resolved';
		const { subjectHash } = entry.intent;
		return adapters.lock(`contact-access|${session.issuerHash}|${subjectHash}`, async () => {
			const identity = await adapters.readDeviceIdentity();
			if (!identity || !session.stillCurrent()) return 'retry';
			const queue = await queueFor(session.issuerHash, subjectHash, identity.deviceId);
			const own = queue.find((e) => e.id === entry.id);
			if (!own) {
				const stored = await adapters.intents.get(entry.id);
				if (isContactAccessIntent(stored?.intent) && stored.intent.deviceId !== undefined && stored.intent.deviceId !== identity.deviceId) {
					await adapters.intents.resolve(entry.id, 'skipped:device-changed');
				}
				return 'resolved';
			}
			if (queue[queue.length - 1].id !== own.id) {
				await adapters.intents.resolve(own.id, 'superseded');
				return 'resolved';
			}
			const intent = await bindDevice(own, identity.deviceId);
			if (!intent) return 'retry';
			const { granted, deviceId } = intent;

			const dispatched = intent.dispatched ?? [];
			const refused = new Map<string, Superseded>();
			for (const l of intent.learned ?? []) raise(refused, l.kind, l.floor, l.exists);
			if (dispatched.length > 0) {
				const queued = await adapters.outbox.queued(session.issuerHash);
				const unsettled = new Set(queued.filter((q) => !q.settled).map((q) => q.outboxId));
				if (dispatched.some((d) => unsettled.has(d.outboxId))) return 'retry';
				const gaveUp = new Map((await adapters.outbox.refused(session.issuerHash)).map((r) => [r.outboxId, r]));
				for (const d of dispatched) {
					const refusal = gaveUp.get(d.outboxId);
					if (!refusal) continue;
					raise(refused, d.kind, d.timestamp, refusal.conflict);
					await adapters.outbox.discard(d.outboxId);
				}
				if (refused.size === 0 && !intent.open) return settleOnRows(own.id, intent, session, dispatched);
			}

			let outcome: ContactVouchOutcome;
			try {
				outcome = await setScopes(session, subjectHash, deviceId, granted, refused);
			} catch {
				if (refused.size > 0) {
					const learned = [...refused].map(([kind, r]) => ({ kind, floor: r.floor, exists: r.exists ?? false }));
					await adapters.intents.update(own.id, { ...intent, dispatched: [], open: true, learned });
				}
				return 'retry';
			}
			if (outcome.kind === 'skipped') {
				if (outcome.reason === 'identity-unavailable') return 'retry';
				await adapters.intents.resolve(own.id, `skipped:${outcome.reason}`);
				return 'resolved';
			}
			const open = Object.values(outcome.steps).includes('unverified');
			if (!open && outcome.dispatched.every((d) => d.accepted)) return settleOnRows(own.id, intent, session, outcome.dispatched);
			await adapters.intents.update(own.id, { ...intent, dispatched: outcome.dispatched, open, learned: [] });
			return 'retry';
		});
	};

	const request: ContactAccess['request'] = async (session, subjectHash, granted, deviceId) => {
		const intent: ContactAccessIntent = {
			kind: CONTACT_ACCESS_INTENT,
			subjectHash,
			granted,
			...(deviceId !== undefined ? { deviceId, purpose: purposeFor(deviceId, subjectHash, granted) } : {}),
		};
		const id = await adapters.intents.enqueue(session.issuerHash, intent);
		if (!id) throw new Error('contact access: the request could not be stored on this device');
		return apply({ id, createdAt: Date.now(), intent }, session);
	};

	const readScopes: ContactAccess['readScopes'] = async (issuerHash, subjectHash, deviceId) => {
		const { read, write } = await readScopeStates(issuerHash, subjectHash, deviceId);
		return { read: read.state, write: write.state };
	};

	const readRequests: ContactAccess['readRequests'] = async (issuerHash, subjectHash, deviceId) => {
		let pending: ContactAccessRequests['pending'] = null;
		let last: ContactAccessRequests['last'] = null;
		const entries = (await adapters.intents.list(issuerHash, { includeResolved: true }))
			.sort((a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1));
		for (const { intent } of entries) {
			const marker = intent as { resolved?: unknown; purpose?: unknown; outcome?: unknown } | null;
			if (marker?.resolved === true) {
				const about = parsePurpose(marker.purpose);
				if (about?.subjectHash !== subjectHash || about.deviceId !== deviceId) continue;
				last = { granted: about.granted, outcome: String(marker.outcome) };
				pending = null;
				continue;
			}
			if (!isContactAccessIntent(intent, subjectHash)) continue;
			if (intent.deviceId !== undefined && intent.deviceId !== deviceId) continue;
			pending = { granted: intent.granted };
		}
		return { pending, last };
	};

	const issuerMayGrant: ContactAccess['issuerMayGrant'] = async (issuerHash, identity) => {
		if (identity.adminHash === null) return false;
		if (identity.adminHash === issuerHash) return true;
		return holdsDeviceVouch(issuerHash, identity.deviceId);
	};

	return {
		request,
		apply,
		readScopes,
		readRequests,
		issuerMayGrant,
		async afterConfirmation(session, input) {
			const decision = initialAccessDecision(input);
			if (!decision.grant) return decision;
			return { ...decision, result: await request(session, input.subjectHash, true) };
		},
		async snapshot(issuerHash, subjectHash) {
			const identity = await adapters.readDeviceIdentity().catch(() => null);
			if (!identity) return { issuerHash, subjectHash, identity: null, scopes: null, requests: null, mayGrant: null };
			const [scopes, requests, mayGrant] = await Promise.all([
				readScopes(issuerHash, subjectHash, identity.deviceId).catch(() => null),
				readRequests(issuerHash, subjectHash, identity.deviceId).catch(() => null),
				issuerMayGrant(issuerHash, identity).catch(() => null),
			]);
			return { issuerHash, subjectHash, identity, scopes, requests, mayGrant };
		},
	};
}
