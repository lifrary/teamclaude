import { createHash } from 'node:crypto';

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

function normalized(value) {
  if (typeof value !== 'string') return null;
  const result = value.normalize('NFKC').trim();
  return result ? result.toLowerCase() : null;
}

/** Stable org discriminator for display and legacy callers. */
export function orgKey(account) {
  return normalized(account?.orgUuid) || normalized(account?.orgName) || null;
}

/**
 * Produce the canonical tagged AccountId.  The tag prevents a UUID from ever
 * colliding with an org name or a credential-less account name.
 */
export function accountId(account) {
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

export function accountIdKey(idOrAccount) {
  const supplied = idOrAccount?.tag ? idOrAccount : accountId(idOrAccount);
  const id = supplied.tag === 'uuid-org-uuid'
    ? { tag: supplied.tag, accountUuid: normalized(supplied.accountUuid), orgUuid: normalized(supplied.orgUuid) }
    : supplied.tag === 'uuid-org-name'
      ? { tag: supplied.tag, accountUuid: normalized(supplied.accountUuid), orgName: normalized(supplied.orgName) }
      : supplied.tag === 'uuid-org-unknown'
        ? { tag: supplied.tag, accountUuid: normalized(supplied.accountUuid) }
        : supplied.tag === 'name' ? { tag: supplied.tag, name: normalized(supplied.name) } : supplied;
  switch (id.tag) {
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

export function parseAccountIdKey(key) {
  if (typeof key !== 'string') throw new IdentityAmbiguityError('Invalid AccountId key');
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

export function digestAccountId(idOrAccount) {
  return createHash('sha256').update(accountIdKey(idOrAccount)).digest('hex');
}


/**
 * Build an immutable identity registry.  Complete duplicate identities and
 * unknown-org UUID entries are rejected rather than guessed.
 */
export function createIdentityRegistry(accounts) {
  const byKey = new Map();
  const unknownByUuid = new Map();
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
    } else if (id.accountUuid) {
      if (unknownByUuid.has(id.accountUuid)) throw new IdentityAmbiguityError('Ambiguous unknown-org account UUID');
      completeByUuid.set(id.accountUuid, account);
    }
    byKey.set(key, account);
  }
  return Object.freeze({
    get(idOrAccount) {
      const id = idOrAccount?.tag ? idOrAccount : accountId(idOrAccount);
      const exact = byKey.get(accountIdKey(id));
      if (exact) return exact;
      if (id.accountUuid && unknownByUuid.has(id.accountUuid)) {
        throw new IdentityAmbiguityError('Unknown-org account cannot be resolved as a complete identity');
      }
      return null;
    },
    entries() { return [...byKey.entries()]; },
  });
}

export function resolveAccount(accounts, ref) {
  return createIdentityRegistry(accounts).get(ref);
}

/** Exact canonical equality; incomplete UUID identities do not backfill. */
export function sameIdentity(a, b) {
  try {
    return accountIdKey(a) === accountIdKey(b);
  } catch {
    return false;
  }
}

/** The email portion of a display name, stripping any " (org)" suffix. */
export function emailOf(account) {
  return (account?.name || '').replace(/ \(.*\)$/, '');
}

/** Find accounts matching a name-or-email query, optionally narrowed by org. */
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