import { describe, it, expect, vi } from 'vitest';
import { generateIdentityKeys, openIdentity, type IdentityHandle } from '@buckitup/pq-client/identity';
import { adminScope, issueVouch, readVouch, retractVouch, storageScope } from '@buckitup/pq-client/vouch';
import { rowMutation } from '@buckitup/pq-client/rows';
import { createFakePqServer, type FakePqServer } from './helpers/fakePqServer';

const DEVICE = 'Server_test_example';

const identityOn = async (server: FakePqServer, name: string): Promise<IdentityHandle> => {
	const me = openIdentity(generateIdentityKeys());
	const outcome = await server.transport.ingest([rowMutation('user_cards', me.userCard({ name, ownerTimestamp: 1 }))], me.sign);
	expect(outcome.kind).toBe('written');
	return me;
};

const stored = (server: FakePqServer) => [...server.tables.get('vouch_tokens')!.values()];

describe('scopes', () => {
	it('name the server by its device id; a suffix only makes the row distinct', () => {
		expect(storageScope(DEVICE, 'write', 'dialog_messages')).toBe('device.Server_test_example.storage.write.dialog_messages');
		expect(storageScope(DEVICE, 'write', 'dialog_messages', 'code-7')).toBe('device.Server_test_example.storage.write.dialog_messages.code-7');
		expect(storageScope(DEVICE, 'read')).toBe('device.Server_test_example.storage.read');
		expect(adminScope(DEVICE)).toBe('device.Server_test_example.admin');
	});
});

describe('issue and retract', () => {
	it('issues once, retracts with a newer tombstone, re-issues, each proved and signed by the issuer', async () => {
		const server = createFakePqServer();
		const issuer = await identityOn(server, 'Bot');
		const guest = await identityOn(server, 'Guest');
		const kind = storageScope(DEVICE, 'write', 'dialog_messages', 'code-1');
		const opts = { transport: server.transport, issuer };

		const issued = await issueVouch(opts, kind, guest.userHash);
		expect(issued).toMatchObject({ kind: 'written', row: { kind, issuer_hash: issuer.userHash, subject_hash: guest.userHash, deleted_flag: false } });
		const writes = server.requests.filter((r) => r.path === '/ingest').length;
		expect(await issueVouch(opts, kind, guest.userHash)).toMatchObject({ kind: 'unchanged' });
		expect(server.requests.filter((r) => r.path === '/ingest').length).toBe(writes);

		const retracted = await retractVouch(opts, kind, guest.userHash);
		expect(retracted).toMatchObject({ kind: 'written', row: { deleted_flag: true } });
		expect(retracted.kind === 'written' && issued.kind === 'written' && retracted.row.owner_timestamp > issued.row.owner_timestamp).toBe(true);
		expect(await retractVouch(opts, kind, guest.userHash)).toMatchObject({ kind: 'unchanged' });
		expect(await issueVouch(opts, kind, guest.userHash)).toMatchObject({ kind: 'written', row: { deleted_flag: false } });
		expect(stored(server)).toHaveLength(1);
		expect(await readVouch(opts, kind, guest.userHash)).toMatchObject({ kind: 'found', row: { deleted_flag: false } });
	});

	it('retracting a scope never granted writes a tombstone row of its own', async () => {
		const server = createFakePqServer();
		const owner = await identityOn(server, 'Owner');
		const guest = await identityOn(server, 'Guest');
		const wide = storageScope(DEVICE, 'write', 'dialog_messages');
		expect(await retractVouch({ transport: server.transport, issuer: owner }, wide, guest.userHash))
			.toMatchObject({ kind: 'written', row: { kind: wide, deleted_flag: true } });
	});

	it('a proof by another identity is refused, and nothing is written', async () => {
		const server = createFakePqServer();
		const issuer = await identityOn(server, 'Bot');
		const stranger = await identityOn(server, 'Stranger');
		const guest = await identityOn(server, 'Guest');
		const forged: IdentityHandle = { ...issuer, sign: stranger.sign, signRow: issuer.signRow };
		const outcome = await issueVouch({ transport: server.transport, issuer: forged }, storageScope(DEVICE, 'write'), guest.userHash);
		expect(outcome).toMatchObject({ kind: 'rejected', rejection: { kind: 'rejected', error: 'Invalid operation' } });
		expect(stored(server)).toHaveLength(0);
	});

	it('two devices of one issuer issuing at once end with one row; the later sees it and changes nothing', async () => {
		const server = createFakePqServer();
		const issuer = await identityOn(server, 'Bot');
		const guest = await identityOn(server, 'Guest');
		const kind = storageScope(DEVICE, 'write', 'dialog_keys');
		let armed = true;
		const release = server.hold((path) => {
			if (!armed || path !== '/ingest') return false;
			armed = false;
			return true;
		});
		const first = issueVouch({ transport: server.transport, issuer }, kind, guest.userHash);
		await vi.waitFor(() => expect(armed).toBe(false));
		expect(await issueVouch({ transport: server.transport, issuer }, kind, guest.userHash)).toMatchObject({ kind: 'written' });
		release();
		expect(await first).toMatchObject({ kind: 'unchanged', row: { deleted_flag: false } });
		expect(stored(server)).toHaveLength(1);
	});

	it('a write overtaken by a newer one is rebuilt on it, and a row that does not verify is not built on', async () => {
		const server = createFakePqServer();
		const issuer = await identityOn(server, 'Bot');
		const guest = await identityOn(server, 'Guest');
		const kind = storageScope(DEVICE, 'read', 'dialog_keys');
		await issueVouch({ transport: server.transport, issuer }, kind, guest.userHash);
		let armed = true;
		const release = server.hold((path) => {
			if (!armed || path !== '/ingest') return false;
			armed = false;
			return true;
		});
		const slow = retractVouch({ transport: server.transport, issuer, now: () => 100 }, kind, guest.userHash);
		await vi.waitFor(() => expect(armed).toBe(false));
		await retractVouch({ transport: server.transport, issuer, now: () => 5_000_000_000 }, kind, guest.userHash);
		await issueVouch({ transport: server.transport, issuer, now: () => 5_000_000_001 }, kind, guest.userHash);
		release();
		expect(await slow).toMatchObject({ kind: 'written', row: { deleted_flag: true, owner_timestamp: 5_000_000_002 } });

		const row = stored(server)[0];
		row.owner_timestamp = 9_000_000_000;
		expect(await issueVouch({ transport: server.transport, issuer }, kind, guest.userHash)).toMatchObject({ kind: 'unverified' });
	});
});
