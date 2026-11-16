import { generateIdentityKeys, openIdentity } from '@buckitup/pq-client/identity';
import { createTransport } from '@buckitup/pq-client/transport';
import { issueVouch, storageScope } from '@buckitup/pq-client/vouch';

const bot = openIdentity(generateIdentityKeys());
const transport = createTransport({ baseUrl: 'https://example.invalid/electric/v1' });
export const pending = () => issueVouch({ transport, issuer: bot }, storageScope('Server_x', 'write', 'dialog_messages', 'code-1'), bot.userHash);
