import { createHash } from 'node:crypto';
// Account identity helpers.
//
// An OAuth account is identified by its Anthropic account UUID (the *person*)
// plus the organization it is scoped to. The same email/person can belong to
// multiple organizations — e.g. a corporate Pro org and a personal Max org —
// each with its own OAuth token and quota. The org must therefore be part of
// the identity; otherwise multi-org logins overwrite each other, removals match
// the wrong entry, and token rotation persists onto the wrong account.
//
// The org discriminator prefers the org UUID but falls back to the org name
// (the profile endpoint has always returned a name), so identity still works on
// entries created before org UUIDs were stored.
//
// Provider is part of it too: a Codex account has no Anthropic UUID at all, so
// without it one email's Claude and ChatGPT subscriptions compare as one account.

import { providerOf } from './provider.js';

/**
 * Identity-bearing fields shared by config entries and live accounts.
 * @typedef {{ provider?: string | null, accountId?: string | null, accountUuid?: string | null, orgUuid?: string | null, orgName?: string | null, name?: string | null }} IdentityAccount
 * @typedef {Readonly<
 *   { tag: 'provider-account', provider: 'codex', providerAccountId: string } |
 *   { tag: 'provider-name', provider: 'codex', name: string } |
 *   { tag: 'uuid-org-uuid', accountUuid: string, orgUuid: string } |
 *   { tag: 'uuid-org-name', accountUuid: string, orgName: string } |
 *   { tag: 'uuid-org-unknown', accountUuid: string } |
 *   { tag: 'name', name: string }
 * >} AccountId
 */

/**
 * Thrown when an incomplete identity would make a boundary operation target an
 * account other than the caller intended.
 */
export class IdentityAmbiguityError extends Error {
  constructor(message = 'Account identity is ambiguous') {
    super(message);
    this.name = 'IdentityAmbiguityError';
  }
}

/** @param {unknown} value @returns {string | null} */
function normalized(value) {
  if (typeof value !== 'string') return null;
  const result = value.normalize('NFKC').trim();
  return result ? result.toLowerCase() : null;
}

/** Stable org discriminator for display and legacy callers.
 * @param {IdentityAccount | null | undefined} account
 */
export function orgKey(account) {
  return normalized(account?.orgUuid) || normalized(account?.orgName) || null;
}

/**
 * Whether two records name the same organization: true, false, or null when
 * they carry no field in common to compare.
 *
 * Compared field by field rather than through orgKey. Which field a record
 * carries depends on what the profile returned when the account was added, so
 * one record holding only the uuid and another holding only the name describe
 * one organization while their keys differ — and comparing those keys called
 * one account two, which on the save path carried its row over a second time
 * (#328). The uuid decides when both sides have one; the name decides when
 * both have one and either lacks a uuid; a uuid against a name is no evidence
 * either way.
 * @param {IdentityAccount | null | undefined} a
 * @param {IdentityAccount | null | undefined} b
 */
export function sameOrg(a, b) {
  if (a?.orgUuid && b?.orgUuid) return a.orgUuid === b.orgUuid;
  if (a?.orgName && b?.orgName) return a.orgName === b.orgName;
  return null;
}

/**
 * Produce a tagged canonical identity. Existing Claude keys remain stable;
 * Codex keys occupy a separate provider namespace and retain opaque account IDs.
 * @param {IdentityAccount | null | undefined} account
 * @returns {AccountId}
 */
export function accountId(account) {
  if (providerOf(account) === 'codex') {
    const providerAccountId = typeof account?.accountId === 'string' ? account.accountId.trim() : null;
    if (providerAccountId) return Object.freeze({ tag: 'provider-account', provider: 'codex', providerAccountId });
    const name = normalized(account?.name);
    if (!name) throw new IdentityAmbiguityError('Codex account has neither an account ID nor a name');
    return Object.freeze({ tag: 'provider-name', provider: 'codex', name });
  }
  const accountUuid = normalized(account?.accountUuid);
  const orgUuid = normalized(account?.orgUuid);
  const orgName = normalized(account?.orgName);
  if (accountUuid && orgUuid) return Object.freeze({ tag: 'uuid-org-uuid', accountUuid, orgUuid });
  if (accountUuid && orgName) return Object.freeze({ tag: 'uuid-org-name', accountUuid, orgName });
  if (accountUuid) return Object.freeze({ tag: 'uuid-org-unknown', accountUuid });
  const name = normalized(account?.name);
  if (!name) throw new IdentityAmbiguityError('Account has neither an account UUID nor a name');
  return Object.freeze({ tag: 'name', name });
}

export const canonicalAccountId = accountId;

/** @param {AccountId | IdentityAccount} idOrAccount @returns {string} */
export function accountIdKey(idOrAccount) {
  const supplied = idOrAccount && 'tag' in idOrAccount ? idOrAccount : accountId(idOrAccount);
  const id = supplied.tag === 'uuid-org-uuid'
    ? { tag: supplied.tag, accountUuid: normalized(supplied.accountUuid), orgUuid: normalized(supplied.orgUuid) }
    : supplied.tag === 'uuid-org-name'
      ? { tag: supplied.tag, accountUuid: normalized(supplied.accountUuid), orgName: normalized(supplied.orgName) }
      : supplied.tag === 'uuid-org-unknown'
        ? { tag: supplied.tag, accountUuid: normalized(supplied.accountUuid) }
        : supplied.tag === 'name' ? { tag: supplied.tag, name: normalized(supplied.name) } : supplied;
  switch (id.tag) {
    case 'provider-account':
      if (id.provider === 'codex' && id.providerAccountId) return `p:codex:c:${encodeURIComponent(id.providerAccountId)}`;
      break;
    case 'provider-name': {
      const name = normalized(id.name);
      if (id.provider === 'codex' && name) return `p:codex:n:${encodeURIComponent(name)}`;
      break;
    }
    case 'uuid-org-uuid':
      if (id.accountUuid && id.orgUuid) return `u:${id.accountUuid}:o:${id.orgUuid}`;
      break;
    case 'uuid-org-name':
      if (id.accountUuid && id.orgName) return `u:${id.accountUuid}:n:${id.orgName}`;
      break;
    case 'uuid-org-unknown':
      if (id.accountUuid) return `u:${id.accountUuid}:?`;
      break;
    case 'name':
      if (id.name) return `n:${id.name}`;
      break;
    default:
      break;
  }
  throw new IdentityAmbiguityError('Invalid AccountId tag');
}

/** @param {unknown} key @returns {AccountId} */
export function parseAccountIdKey(key) {
  if (typeof key !== 'string') throw new IdentityAmbiguityError('Invalid AccountId key');
  const provider = /^p:codex:([cn]):(.+)$/.exec(key);
  if (provider) {
    let value;
    try { value = decodeURIComponent(provider[2]); } catch { throw new IdentityAmbiguityError('Invalid AccountId key'); }
    return Object.freeze(provider[1] === 'c'
      ? { tag: 'provider-account', provider: 'codex', providerAccountId: value }
      : { tag: 'provider-name', provider: 'codex', name: value });
  }
  const uuid = /^u:([^:]+):([on?]):(.*)$/.exec(key);
  if (uuid) {
    if (uuid[2] === 'o' && uuid[3]) return Object.freeze({ tag: 'uuid-org-uuid', accountUuid: uuid[1], orgUuid: uuid[3] });
    if (uuid[2] === 'n' && uuid[3]) return Object.freeze({ tag: 'uuid-org-name', accountUuid: uuid[1], orgName: uuid[3] });
  }
  const unknown = /^u:([^:]+):\?$/.exec(key);
  if (unknown) return Object.freeze({ tag: 'uuid-org-unknown', accountUuid: unknown[1] });
  const name = /^n:(.+)$/.exec(key);
  if (name) return Object.freeze({ tag: 'name', name: name[1] });
  throw new IdentityAmbiguityError('Invalid AccountId key');
}

/** @param {AccountId | IdentityAccount} idOrAccount */
export function digestAccountId(idOrAccount) {
  return createHash('sha256').update(accountIdKey(idOrAccount)).digest('hex');
}


/**
 * Build an immutable identity registry.  Complete duplicate identities and
 * unknown-org UUID entries are rejected rather than guessed.
 * @template {IdentityAccount} T
 * @param {readonly T[] | null | undefined} accounts
 * @returns {Readonly<{ get: (idOrAccount: AccountId | IdentityAccount) => T | null, entries: () => [string, T][] }>}
 */
export function createIdentityRegistry(accounts) {
  /** @type {Map<string, T>} */
  const byKey = new Map();
  /** @type {Map<string, T>} */
  const unknownByUuid = new Map();
  /** @type {Map<string, T>} */
  const completeByUuid = new Map();
  for (const account of accounts || []) {
    const id = accountId(account);
    const key = accountIdKey(id);
    if (byKey.has(key)) throw new IdentityAmbiguityError(`Duplicate complete account identity (${key})`);
    if (id.tag === 'uuid-org-unknown') {
      if (unknownByUuid.has(id.accountUuid) || completeByUuid.has(id.accountUuid)) {
        throw new IdentityAmbiguityError('Ambiguous unknown-org account UUID');
      }
      unknownByUuid.set(id.accountUuid, account);
    } else if (id.tag === 'uuid-org-uuid' || id.tag === 'uuid-org-name') {
      if (unknownByUuid.has(id.accountUuid)) throw new IdentityAmbiguityError('Ambiguous unknown-org account UUID');
      completeByUuid.set(id.accountUuid, account);
    }
    byKey.set(key, account);
  }
  return Object.freeze({
    /** @param {AccountId | IdentityAccount} idOrAccount @returns {T | null} */
    get(idOrAccount) {
      const id = idOrAccount && 'tag' in idOrAccount ? idOrAccount : accountId(idOrAccount);
      const exact = byKey.get(accountIdKey(id));
      if (exact) return exact;
      if ('accountUuid' in id && unknownByUuid.has(id.accountUuid)) {
        throw new IdentityAmbiguityError('Unknown-org account cannot be resolved as a complete identity');
      }
      return null;
    },
    entries() { return [...byKey.entries()]; },
  });
}

/**
 * @template {IdentityAccount} T
 * @param {readonly T[]} accounts
 * @param {AccountId | IdentityAccount} ref
 * @returns {T | null}
 */
export function resolveAccount(accounts, ref) {
  return createIdentityRegistry(accounts).get(ref);
}

/** Exact canonical equality; incomplete UUID identities do not backfill.
 * @param {AccountId | IdentityAccount} a
 * @param {AccountId | IdentityAccount} b
 */
export function sameIdentity(a, b) {
  try {
    return accountIdKey(a) === accountIdKey(b);
  } catch {
    return false;
  }
}

/**
 * Are these two records definitely NOT the same account? True only when both
 * sides are fully identified and point at different account+org pairs — an
 * unknown UUID or org on either side means "cannot tell", never "different".
 * Two providers are the exception: separate plans, whoever holds them.
 * @param {IdentityAccount | null | undefined} a
 * @param {IdentityAccount | null | undefined} b
 */
export function distinctAccounts(a, b) {
  if (providerOf(a) !== providerOf(b)) return true;
  if (a?.accountId && b?.accountId) return a.accountId !== b.accountId;
  if (!a?.accountUuid || !b?.accountUuid) return false;
  if (a.accountUuid !== b.accountUuid) return true;
  return sameOrg(a, b) === false;
}

/**
 * Index of the config entry an incoming login should UPDATE, or -1 to add it as
 * a new one.
 *
 * Identity decides first: the same account+org is the same entry. A bare display
 * name match is accepted only when nothing contradicts it — one person's two
 * organizations share an email, and the display name is derived from that email,
 * so treating equal names as one account overwrites the other org's entry and
 * silently drops an account from the config. The account keeps working until the
 * process that still holds it in memory restarts, which is what makes the loss
 * hard to trace back to the login that caused it.
 * @param {IdentityAccount[]} accounts
 * @param {IdentityAccount} incoming
 */
export function findUpsertTarget(accounts, incoming) {
  // A UUID match is evidence; a name match is a guess, and sameIdentity makes
  // both in one pass — it compares UUIDs only when BOTH records carry one and
  // falls back to the name otherwise. So an entry with no UUID matched any
  // incoming record sharing its name, and if it sat earlier in the list it won
  // over the entry whose account+org actually matched, landing the credential on
  // the namesake row (#236). Two entries with one name where the earlier has no
  // UUID is just a hand-added entry beside a logged-in one, or an account added
  // before its first probe.
  //
  // So look for the evidence before accepting the guess — and the strongest
  // evidence first. The uuid pass below still takes sameIdentity's tolerant
  // answer, which says yes to an entry that never stored an organization, so a
  // legacy entry sitting earlier in the list won over the one whose
  // organization actually matched (#327). An entry with no organization ahead
  // of one that has it is a hand-added entry beside a logged-in one, or any
  // account before its first probe.
  if (incoming?.accountUuid) {
    const exact = accounts.findIndex(a => providerOf(a) === providerOf(incoming) && a?.accountUuid === incoming.accountUuid && sameOrg(a, incoming) === true);
    if (exact >= 0) return exact;
    const byUuid = accounts.findIndex(a => a?.accountUuid && sameIdentity(a, incoming));
    if (byUuid >= 0) return byUuid;
  }
  const byIdentity = accounts.findIndex(a => sameIdentity(a, incoming));
  if (byIdentity >= 0) return byIdentity;
  return accounts.findIndex(a => a.name === incoming.name && !distinctAccounts(a, incoming));
}

/**
 * The entry to store at a `findUpsertTarget` hit: `incoming` over `prev`, with
 * two of the existing entry's fields pinned.
 *
 * `name` because a login should not rename an account the operator named. `id`
 * because a running server holds an account built from this entry and finds it
 * again by that id (see account-pairing.js) — reissuing it here would strand
 * that account with no entry to be saved onto, and the token it refreshes next
 * would be dropped instead of persisted. An `incoming` record carrying neither
 * field already leaves both alone; pinning them says so, and keeps saying so if
 * one day it carries them.
 * @template {IdentityAccount & { id?: string | null }} T
 * @template {IdentityAccount} U
 * @param {T} prev
 * @param {U} incoming
 */
export function updateAccountEntry(prev, incoming) {
  return { ...prev, ...incoming, name: prev.name, id: prev.id };
}

/** The email portion of a display name, stripping any " (org)" suffix.
 * @param {IdentityAccount | null | undefined} account
 */
export function emailOf(account) {
  return (account?.name || '').replace(/ \(.*\)$/, '');
}

/** Find accounts matching a name-or-email query, optionally narrowed by org.
 * @template {IdentityAccount} T
 * @param {T[]} accounts
 * @param {string} query
 * @param {string | null} [orgFilter]
 * @returns {T[]}
 */
export function matchAccounts(accounts, query, orgFilter) {
  let matches = accounts.filter(account => account.name === query);
  if (matches.length === 0) matches = accounts.filter(account => emailOf(account) === query);
  const filter = normalized(orgFilter);
  if (filter) {
    matches = matches.filter(account => {
      const name = normalized(account.orgName);
      const uuid = normalized(account.orgUuid);
      return name === filter || (uuid && uuid.startsWith(filter));
    });
  }
  return matches;
}

/**
 * Automatic naming is safe only when the profile identifies the account.
 * An explicit name is the caller's opt-in to importing without detection.
 * @param {{ error?: unknown, accountUuid?: unknown, email?: unknown } | null | undefined} profile
 * @param {unknown} userNamed
 */
export function canUpsertOAuthAccount(profile, userNamed) {
  return Boolean(
    userNamed
    || (profile && !profile.error && (profile.accountUuid || profile.email))
  );
}

/**
 * Copy only known profile identity fields. Omitting unavailable fields keeps a
 * named re-import from erasing identity already stored on the account.
 */
/**
 * @param {{ error?: unknown, accountUuid?: string | null, orgUuid?: string | null, orgName?: string | null } | null | undefined} profile
 * @returns {{ accountUuid?: string, orgUuid?: string, orgName?: string }}
 */
export function oauthIdentityFields(profile) {
  if (!profile || profile.error) return {};
  return Object.fromEntries(
    /** @type {const} */ (['accountUuid', 'orgUuid', 'orgName'])
      .filter(key => profile[key])
      .map(key => [key, profile[key]])
  );
}
