import sodium from 'libsodium-wrappers';
import { generateIdentityKeys, openIdentity } from '@buckitup/pq-client/identity';
import { createPrfVault, openPrfVault, openVaultIdentity, prfLockOf, writeIdentityKeys } from '@buckitup/pq-client/vault';
import { buildDialogKeyRow, buildMessageRow, dialogHash, openMessageRow } from '@buckitup/pq-client/dialogs';
import { deriveStorageKey, openJson, sealJson } from '@buckitup/pq-client/storage';
import { verifyRow } from '@buckitup/pq-client/rows';

type Check = [string, boolean | string];

const run = async (): Promise<Check[]> => {
	const checks: Check[] = [];
	try {
		const ann = openIdentity(generateIdentityKeys());
		const bob = openIdentity(generateIdentityKeys());
		const keyRow = ann.signRow('dialog_keys', await buildDialogKeyRow({
			senderHash: ann.userHash, peerHash: bob.userHash, senderMsgKey: ann.senderMsgKey(bob.userHash), peerCryptPkey: bob.cryptPkey, ownerTimestamp: 2,
		}));
		const message = ann.signRow('dialog_messages', await buildMessageRow(ann.senderMsgKey(bob.userHash), {
			senderHash: ann.userHash, dialogHash: dialogHash(ann.userHash, bob.userHash), parts: [{ kind: 'text', text: 'hi' }], refs: {}, ownerTimestamp: 3,
		}));
		const opened = await openMessageRow(message, { senderSignPkey: ann.signPkey, senderMsgKey: await bob.unwrapPeerKey(keyRow) });
		checks.push(['dialogs', opened.status === 'ok' && verifyRow('dialog_keys', keyRow, ann.signPkey).status === 'ok']);

		const key = await deriveStorageKey(ann.exportKeys().cryptSkey);
		checks.push(['storage', (await openJson<{ a: number }>(key, await sealJson(key, { a: 1 }))).a === 1]);

		await sodium.ready;
		(globalThis as { sodium?: unknown }).sodium = sodium;
		const keys = generateIdentityKeys();
		const { vault } = await createPrfVault({ name: 'Consumer', credentials: navigator.credentials, rpId: location.hostname });
		await writeIdentityKeys(vault, keys);
		vault.lock();
		const lock = await prfLockOf(vault.id);
		if (!lock) throw new Error('no lock record');
		const reopened = await openPrfVault(vault.id, lock, { credentials: navigator.credentials });
		checks.push(['vault', (await openVaultIdentity(reopened)).userHash === openIdentity(keys).userHash]);
	} catch (e) {
		checks.push(['error', String((e as Error)?.stack ?? e)]);
	}
	return checks;
};

(window as unknown as { __checks: Promise<Check[]> }).__checks = run();
