import { deriveAccount, identityFamily, wipeAccount, type DerivedAccount, type ParentKeys } from './derivedIdentity.js';

export const PERSONA_SALT = 'buckitup/persona/v1';

export const MAX_PERSONA_INDEX = 0xffff_ffff;

export interface Persona extends DerivedAccount {
	index: number;
}

export interface AccountPersonas {
	persona(index: number): Persona;
	userHash(index: number): string;
	wipe(): void;
}

export const isPersonaIndex = (v: unknown): v is number =>
	typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= MAX_PERSONA_INDEX;

export const personaPrefix = (index: number): Uint8Array => {
	if (!isPersonaIndex(index)) throw new RangeError(`persona index: an integer from 0 to ${MAX_PERSONA_INDEX}`);
	const prefix = new Uint8Array(4);
	new DataView(prefix.buffer).setUint32(0, index, false);
	return prefix;
};

export const accountPersonas = (account: ParentKeys): AccountPersonas => {
	const family = identityFamily(account, PERSONA_SALT);
	return {
		persona: (index) => ({ ...family.account(personaPrefix(index)), index }),
		userHash: (index) => family.userHash(personaPrefix(index)),
		wipe: () => family.wipe(),
	};
};

export const derivePersona = (account: ParentKeys, index: number): Persona => ({
	...deriveAccount(account, PERSONA_SALT, personaPrefix(index)),
	index,
});

export const wipePersona = (persona: Persona): void => wipeAccount(persona);
