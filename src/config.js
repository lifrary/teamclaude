import { readFile, writeFile, mkdir, rm, chmod, open, rename, unlink, realpath } from 'node:fs/promises';
import { openSync, writeSync, closeSync, readFileSync, statSync } from 'node:fs';
import { join, dirname, basename } from 'node:path';
import { homedir } from 'node:os';
import { createHash, randomBytes } from 'node:crypto';
import { accountId, accountIdKey, createIdentityRegistry, parseAccountIdKey } from './identity.js';
import { resolveUpstreamProxy, setUpstreamProxy } from './upstream-proxy.js';
import { ensureAccountIds } from './account-id.js';

/**
 * Credential-free state sections remain runtime-validated against the allowlists.
 * @typedef {import('./identity.js').IdentityAccount & { type?: string | null }} ConfigIdentity
 * @typedef {ConfigIdentity & Record<string, unknown> & {
 *   id?: string, name?: string, type?: string, apiKey?: string,
 *   accessToken?: string, refreshToken?: string | null, expiresAt?: number | null,
 *   importFrom?: string, priority?: number | null, disabled?: boolean, enabled?: boolean,
 *   maxConcurrent?: number, maxUsage?: number | Record<string, number> | null, upstream?: string | null,
 *   modelMap?: Record<string, string> | null, stripRequestFields?: string[] | null,
 *   messageThreads?: boolean, organizationType?: string | null, rateLimitTier?: string | null,
 *   seatTier?: string | null, hasClaudeMax?: boolean | null, hasClaudePro?: boolean | null
 * }} ConfigAccount
 * @typedef {Record<string, unknown> & {
 *   accounts: ConfigAccount[],
 *   routes?: { name: string, match: string | string[], accounts?: string[], bucket?: string, color?: string }[],
 *   quotaProbeSeconds?: number, warmupSeconds?: number,
 *   warmupSchedule?: { resetTime: string, timezone: string, mode?: 'daily' | 'rolling', anchorResetAt?: number },
 *   switchThreshold?: number | Record<string, number>, distributeSessions?: boolean | 'adaptive'
 * }} ConfigMutation
 * @typedef {{ completed: boolean, sourceDigests: Record<string, string> }} StateMigration
 * @typedef {Record<string, unknown>} StateSection
 * @typedef {Record<string, StateSection>} CounterMap
 * @typedef {{ version: 2, writtenAt: number, migration: StateMigration, activeAccountId: string | null, accounts: Record<string, StateSection>, template: StateSection | null, clients?: CounterMap, usageDimensions?: Record<string, CounterMap> }} CanonicalState
 * @typedef {Partial<Omit<CanonicalState, 'version'>>} CanonicalStateOptions
 * @typedef {{ mkdir: typeof mkdir, open: typeof open, rename: typeof rename, rm: typeof rm }} AtomicFs
 * @typedef {{ path?: string, fs?: AtomicFs }} AtomicWriteOptions
 * @typedef {{ path?: string, fs?: AtomicFs & { chmod: typeof chmod } }} ConfigWriteOptions
 * @typedef {{ oldAccountIdDigest: string, newAccountIdDigest: string, oldTupleDigest: string, newTupleDigest: string, oldConfigIdentityDigest: string, newConfigIdentityDigest: string, oldStateDigest: string, newStateDigest: string, phase: 'prepared' | 'config-committed' | 'state-committed' }} RekeyRecord
 */

export function getConfigPath() {
  if (process.env.TEAMCLAUDE_CONFIG) return process.env.TEAMCLAUDE_CONFIG;
  const configDir = process.env.XDG_CONFIG_HOME || join(homedir(), '.config');
  return join(configDir, 'teamclaude.json');
}

// Runtime state for the running server (pid/port), kept separate from volatile
// quota state so lifecycle commands can safely discover the bound process.
export function getServerStatePath() {
  return getConfigPath().replace(/\.json$/, '') + '.server.json';
}

class ServerStateOperationError extends Error {
  /** @param {string} operation @param {unknown} cause */
  constructor(operation, cause) {
    super(`Server state ${operation} failed`, { cause });
    this.operation = operation;
    this.errorClass = errorProperty(cause, 'code') || errorProperty(cause, 'name') || 'Error';
  }
}
class ConfigOperationError extends Error {
  /** @param {string} operation @param {unknown} error */
  constructor(operation, error) {
    super(`Config ${operation} failed`);
    this.operation = operation;
    this.errorClass = errorProperty(error, 'code') || errorProperty(error, 'name') || 'Error';
  }
}

/** @param {unknown} error @param {string} key @returns {unknown} */
function errorProperty(error, key) {
  return error != null && (typeof error === 'object' || typeof error === 'function') && key in error
    ? Reflect.get(error, key) : undefined;
}

/** @template T @param {string} operation @param {() => T | Promise<T>} fn */
async function serverStateOperation(operation, fn) {
  try {
    return await fn();
  } catch (error) {
    throw new ServerStateOperationError(operation, error);
  }
}

/** @param {unknown} error */
export function formatServerStateFailure(error) {
  const operation = errorProperty(error, 'operation') || 'write';
  const errorClass = errorProperty(error, 'errorClass') || errorProperty(error, 'code') || errorProperty(error, 'name') || 'Error';
  return `[TeamClaude] Server state ${operation} failed (${errorClass}).`;
}

/** @param {unknown} state */
export async function writeServerState(state, {
  path = getServerStatePath(),
  fs = { mkdir, writeFile, chmod },
} = {}) {
  await serverStateOperation('mkdir', () => fs.mkdir(dirname(path), { recursive: true }));
  await serverStateOperation('write', () => fs.writeFile(path, JSON.stringify(state, null, 2) + '\n', { mode: 0o600 }));
  await serverStateOperation('chmod', () => fs.chmod(path, 0o600));
}

/** @param {string} operation @param {unknown} err */
function reportPersistenceError(operation, err) {
  const detail = err instanceof SyntaxError
    ? 'invalid JSON'
    : errorProperty(err, 'code') ? `filesystem error (${errorProperty(err, 'code')})` : 'filesystem error';
  console.warn(`[TeamClaude] Unable to ${operation}: ${detail}.`);
}

/** @param {string} path @param {string} label */
async function readPersistedJson(path, label) {
  let raw;
  try {
    raw = await readFile(path, 'utf-8');
  } catch (err) {
    if (errorProperty(err, 'code') === 'ENOENT') return null;
    reportPersistenceError(`read ${label}`, err);
    return null;
  }

  try {
    return JSON.parse(raw);
  } catch (err) {
    reportPersistenceError(`read ${label}`, err);
    return null;
  }
}

export async function readServerState() {
  return readPersistedJson(getServerStatePath(), 'server state');
}

export async function clearServerState({
  path = getServerStatePath(),
  fs = { rm },
} = {}) {
  try {
    await fs.rm(path, { force: true });
  } catch (error) {
    if (errorProperty(error, 'code') === 'ENOENT') return;
    throw new ServerStateOperationError('clear', error);
  }
}

// Credential-free snapshot including quota and the accepted probe template.
export function getQuotaCachePath() {
  return getConfigPath().replace(/\.json$/, '') + '.quota.json';
}

export async function readQuotaCache() {
  return readPersistedJson(getQuotaCachePath(), 'quota cache');
}

// Legacy quota state is read-only migration input.
// Historic state paths are read-only migration inputs.
export function getStatePath() {
  const configPath = getConfigPath();
  return configPath.endsWith('.json')
    ? configPath.replace(/\.json$/, '.state.json') : `${configPath}.state`;
}

export function getCanonicalStatePath() {
  const configPath = getConfigPath();
  return configPath.endsWith('.json')
    ? configPath.replace(/\.json$/, '.state.v2.json') : `${configPath}.state.v2.json`;
}

/**
 * Where a fatal error is recorded before the server process exits. A sibling of
 * the config, so it follows TEAMCLAUDE_CONFIG / XDG_CONFIG_HOME wherever they
 * point. `.log`, not `.json`: it is appended to and holds stacks, not a document.
 */
export function getCrashLogPath() {
  const configPath = getConfigPath();
  return configPath.endsWith('.json')
    ? configPath.replace(/\.json$/, '.crash.log') : `${configPath}.crash.log`;
}

export function getRekeyPath() {
  return `${getCanonicalStatePath()}.rekey`;
}

export class CanonicalStateError extends Error {
  /** @param {string} operation @param {unknown} [cause] */
  constructor(operation, cause) {
    super(`Canonical state ${operation} failed`);
    this.name = 'CanonicalStateError';
    this.operation = operation;
    this.errorClass = cause && typeof cause === 'object'
      ? ('code' in cause && cause.code) || ('name' in cause && cause.name) || 'InvalidState'
      : 'InvalidState';
  }
}

const STATE_FIELDS = new Set(['version', 'writtenAt', 'migration', 'activeAccountId', 'accounts', 'template', 'clients', 'usageDimensions']);
const MIGRATION_FIELDS = new Set(['completed', 'sourceDigests']);
const ACCOUNT_STATE_FIELDS = new Set(['quota', 'usage', 'throttle', 'convergence', 'reset', 'profile', 'adaptive']);
const PROFILE_FIELDS = new Set(['organizationType', 'rateLimitTier', 'seatTier', 'hasClaudeMax', 'hasClaudePro']);
const ADAPTIVE_FIELDS = new Set(['burnRate', 'concCap']);
const BURN_RATE_FIELDS = new Set(['burnRate', 'lastU', 'lastAt', 'burnAnchorU', 'burnAnchorAt']);
const QUOTA_FIELDS = new Set([
  'tokensLimit', 'tokensRemaining', 'requestsLimit', 'requestsRemaining',
  'unified5h', 'unified7d', 'unified7dSonnet', 'unified7dFable',
  'unified5hReset', 'unified7dReset', 'unified7dSonnetReset', 'unified7dFableReset',
  'resetsAt', 'modelWeekly', 'scopedWeekly', 'unified7dSonnetSeenAt', 'unified7dFableSeenAt',
]);
const USAGE_FIELDS = new Set(['totalInputTokens', 'totalOutputTokens', 'totalRequests', 'lastUsed', 'totalCacheReadTokens', 'totalCacheCreationTokens', 'byBucket']);
const BUCKET_USAGE_FIELDS = new Set(['inputTokens', 'outputTokens', 'requests', 'cacheReadTokens', 'cacheCreationTokens']);
const CLIENT_USAGE_FIELDS = new Set(['requests', 'connections', 'inputTokens', 'outputTokens', 'lastUsed']);
const THROTTLE_FIELDS = new Set(['until']);
const CONVERGENCE_FIELDS = new Set(['attempts', 'lastAttemptAt', 'lastSuccessAt', 'status']);
const RESET_FIELDS = new Set(['at', 'reason']);
const TEMPLATE_FIELDS = new Set(['model', 'version', 'beta', 'system', '_elicitsModelWeekly', '_restored']);
const MODEL_WEEKLY_FIELDS = new Set(['utilization', 'reset']);
const TRANSIENT_STATE_FIELDS = new Set([
  'credential', 'accessToken', 'refreshToken', 'apiKey', 'name', 'accountUuid', 'orgUuid', 'orgName',
]);

/** @param {unknown} value @returns {boolean} */
function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * @param {unknown} object
 * @param {ReadonlySet<string>} fields
 * @param {string} label
 * @returns {asserts object is Record<string, unknown>}
 */
function assertAllowed(object, fields, label) {
  if (!isObject(object)) throw new CanonicalStateError('validate');
  for (const key of Object.keys(/** @type {object} */ (object))) {
    if (!fields.has(key) || TRANSIENT_STATE_FIELDS.has(key)) throw new CanonicalStateError(`validate ${label}`);
  }
}
/** @param {unknown} value @param {string} label */
function assertScalar(value, label) {
  if (value === undefined || value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return;
  throw new CanonicalStateError(`validate ${label}`);
}

/** @param {unknown} value */
function validateTemplateSystem(value) {
  if (value === null || typeof value === 'string') return;
  if (!Array.isArray(value)) throw new CanonicalStateError('validate template.system');
  for (const block of value) {
    assertAllowed(block, new Set(['type', 'text', 'cache_control']), 'template.system');
    if (typeof block.type !== 'string' || typeof block.text !== 'string') {
      throw new CanonicalStateError('validate template.system');
    }
    if (block.cache_control !== undefined) {
      // `ttl` ('5m'/'1h') rides on ephemeral cache_control for extended prompt
      // caching. The captured template must keep it verbatim — it is part of
      // the known-accepted request shape — and rejecting it here made EVERY
      // canonical-state save fail once 1h-TTL traffic became the template
      // (state file frozen at its pre-TTL write, restarts restoring stale quota).
      assertAllowed(block.cache_control, new Set(['type', 'ttl']), 'template.system.cache_control');
      if (block.cache_control.type !== 'ephemeral') throw new CanonicalStateError('validate template.system.cache_control');
      if (block.cache_control.ttl !== undefined && typeof block.cache_control.ttl !== 'string') {
        throw new CanonicalStateError('validate template.system.cache_control');
      }
    }
  }
}

/** @param {unknown} value */
function validateAccountState(value) {
  assertAllowed(value, ACCOUNT_STATE_FIELDS, 'account');
  if (value.profile !== undefined) {
    assertAllowed(value.profile, PROFILE_FIELDS, 'profile');
    for (const scalar of Object.values(value.profile)) assertScalar(scalar, 'profile');
  }
  if (value.adaptive !== undefined) {
    assertAllowed(value.adaptive, ADAPTIVE_FIELDS, 'adaptive');
    if (value.adaptive.burnRate !== undefined) validateCounterMap(value.adaptive.burnRate, BURN_RATE_FIELDS, 'adaptive.burnRate');
    assertScalar(value.adaptive.concCap, 'adaptive.concCap');
  }
  if (value.quota !== undefined) {
    assertAllowed(value.quota, QUOTA_FIELDS, 'quota');
    for (const [field, nested] of Object.entries(value.quota)) {
      if (field !== 'modelWeekly' && field !== 'scopedWeekly') assertScalar(nested, `quota.${field}`);
    }
    if (value.quota.modelWeekly !== undefined) {
      if (!isObject(value.quota.modelWeekly)) throw new CanonicalStateError('validate quota.modelWeekly');
      for (const [name, window] of Object.entries(/** @type {Record<string, unknown>} */ (value.quota.modelWeekly))) {
        if (!/^[a-z0-9_]+$/i.test(name)) throw new CanonicalStateError('validate quota.modelWeekly');
        assertAllowed(window, MODEL_WEEKLY_FIELDS, 'quota.modelWeekly');
        for (const nested of Object.values(window)) assertScalar(nested, 'quota.modelWeekly');
      }
    }
    if (value.quota.scopedWeekly !== undefined) {
      validateCounterMap(value.quota.scopedWeekly, new Set(['utilization', 'resetAt']), 'quota.scopedWeekly');
    }
  }
  /** @type {Array<[string, Set<string>]>} */
  const sections = [['usage', USAGE_FIELDS], ['throttle', THROTTLE_FIELDS], ['convergence', CONVERGENCE_FIELDS], ['reset', RESET_FIELDS]];
  for (const [field, fields] of sections) {
    if (value[field] === undefined) continue;
    assertAllowed(value[field], fields, field);
    for (const [key, nested] of Object.entries(value[field])) {
      if (field === 'usage' && key === 'byBucket') validateCounterMap(nested, BUCKET_USAGE_FIELDS, 'usage.byBucket');
      else assertScalar(nested, field);
    }
  }
}

/** @param {unknown} value @param {ReadonlySet<string>} fields @param {string} label */
function validateCounterMap(value, fields, label) {
  if (!isObject(value)) throw new CanonicalStateError(`validate ${label}`);
  for (const counters of Object.values(/** @type {Record<string, unknown>} */ (value))) {
    assertAllowed(counters, fields, label);
    for (const scalar of Object.values(counters)) assertScalar(scalar, label);
  }
}

/** @param {unknown} template */
function validateTemplate(template) {
  if (template === null) return;
  assertAllowed(template, TEMPLATE_FIELDS, 'template');
  for (const [field, value] of Object.entries(template)) {
    if (field === 'system') validateTemplateSystem(value);
    else assertScalar(value, `template.${field}`);
  }
}

/** @param {unknown} value @returns {string | undefined} */
function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const object = /** @type {Record<string, unknown>} */ (value);
    return `{${Object.keys(object).sort().map(key => `${JSON.stringify(key)}:${stableJson(object[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

/** @param {string} domain @param {unknown} value */
function digestRekeyValue(domain, value) {
  return createHash('sha256')
    .update(`teamclaude:${domain}:v1\0${stableJson(value)}`, 'utf8')
    .digest('hex');
}

/** @param {unknown} value @returns {string | null} */
function normalizedIdentityValue(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.normalize('NFKC').trim().toLowerCase();
  return normalized || null;
}

/** @param {ConfigIdentity} account */
function identityTuple(account) {
  const id = accountId(account);
  if (id.tag === 'provider-account' || id.tag === 'provider-name') return id;
  if (id.tag === 'uuid-org-uuid') {
    return { type: 'oauth', accountUuid: id.accountUuid, org: { kind: 'uuid', value: id.orgUuid } };
  }
  if (id.tag === 'uuid-org-name') {
    return { type: 'oauth', accountUuid: id.accountUuid, org: { kind: 'name', value: id.orgName } };
  }
  if (id.tag === 'uuid-org-unknown') {
    return { type: 'oauth', accountUuid: id.accountUuid, org: { kind: 'unknown', value: null } };
  }
  return { type: 'local', name: id.name };
}

/** @param {ConfigIdentity} account */
function configIdentity(account) {
  const type = normalizedIdentityValue(account?.type);
  const name = normalizedIdentityValue(account?.name);
  const accountUuid = normalizedIdentityValue(account?.accountUuid);
  const orgUuid = normalizedIdentityValue(account?.orgUuid);
  const orgName = normalizedIdentityValue(account?.orgName);
  return {
    ...(account?.provider === 'codex' ? { provider: 'codex', accountId: account.accountId ?? null } : {}),
    type,
    name,
    accountUuid,
    orgUuid,
    orgName,
  };
}

/** @param {Partial<CanonicalState> | null | undefined} state */
export function statePayloadDigest(state) {
  return digestRekeyValue('canonical-state', {
    activeAccountId: state?.activeAccountId ?? null,
    accounts: state?.accounts ?? {},
    template: state?.template ?? null,
    ...(state?.clients === undefined ? {} : { clients: state.clients }),
    ...(state?.usageDimensions === undefined ? {} : { usageDimensions: state.usageDimensions }),
  });
}

/** @param {import('./identity.js').AccountId | ConfigIdentity} account */
export function accountIdDigest(account) {
  return digestRekeyValue('account-id', accountIdKey(account));
}

/** @param {ConfigIdentity} account */
export function identityTupleDigest(account) {
  return digestRekeyValue('identity-tuple', identityTuple(account));
}

/** @param {ConfigIdentity} account */
export function configIdentityDigest(account) {
  return digestRekeyValue('config-identity', configIdentity(account));
}

/** @param {CanonicalState} state @returns {CanonicalState} */
export function validateCanonicalState(state) {
  assertAllowed(state, STATE_FIELDS, 'root');
  if (state.version !== 2 || !Number.isFinite(state.writtenAt) || state.writtenAt < 0) throw new CanonicalStateError('validate');
  assertAllowed(state.migration, MIGRATION_FIELDS, 'migration');
  if (state.migration.completed !== true || !isObject(state.migration.sourceDigests)) throw new CanonicalStateError('validate');
  for (const digest of Object.values(state.migration.sourceDigests)) {
    if (typeof digest !== 'string' || !/^[a-f0-9]{64}$/i.test(digest)) throw new CanonicalStateError('validate');
  }
  if (!isObject(state.accounts)) throw new CanonicalStateError('validate');
  for (const [key, value] of Object.entries(state.accounts)) {
    if (accountIdKey(accountIdFromKey(key)) !== key) throw new CanonicalStateError('validate');
    validateAccountState(value);
  }
  if (state.activeAccountId !== null && !Object.hasOwn(state.accounts, state.activeAccountId)) throw new CanonicalStateError('validate');
  validateTemplate(state.template);
  if (state.clients !== undefined) validateCounterMap(state.clients, CLIENT_USAGE_FIELDS, 'clients');
  if (state.usageDimensions !== undefined) {
    if (!isObject(state.usageDimensions)) throw new CanonicalStateError('validate usageDimensions');
    for (const entries of Object.values(state.usageDimensions)) validateCounterMap(entries, CLIENT_USAGE_FIELDS, 'usageDimensions');
  }
  return state;
}

/** @param {string} key */
function accountIdFromKey(key) {
  try {
    return parseAccountIdKey(key);
  } catch (error) {
    throw new CanonicalStateError('validate', error);
  }
}

/** @param {CanonicalStateOptions} [options] @returns {CanonicalState} */
export function createCanonicalState({
  accounts = {},
  activeAccountId = null,
  template = null,
  migration = { completed: true, sourceDigests: {} },
  writtenAt = Date.now(),
  clients,
  usageDimensions,
} = {}) {
  return validateCanonicalState({
    version: 2, writtenAt, migration, activeAccountId, accounts, template,
    ...(clients === undefined ? {} : { clients }),
    ...(usageDimensions === undefined ? {} : { usageDimensions }),
  });
}

const defaultAtomicFs = { mkdir, open, rename, rm };

/** @param {string} path @param {unknown} value @param {{ fs?: AtomicFs }} [options] */
async function atomicJsonWrite(path, value, { fs = defaultAtomicFs } = {}) {
  const directory = dirname(path);
  const tempPath = join(directory, `.${basename(path)}.${randomBytes(12).toString('hex')}.tmp`);
  let handle;
  try {
    await fs.mkdir(directory, { recursive: true });
    handle = await fs.open(tempPath, 'w', 0o600);
    await handle.writeFile(JSON.stringify(value, null, 2) + '\n', 'utf8');
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.rename(tempPath, path);
    const directoryHandle = await fs.open(directory, 'r');
    try {
      await directoryHandle.sync();
    } finally {
      await directoryHandle.close();
    }
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    await fs.rm(tempPath, { force: true }).catch(() => {});
    throw new CanonicalStateError('write', error);
  }
}

let canonicalWriteChain = Promise.resolve();

/**
 * @template T
 * @param {() => Promise<T>} write
 * @returns {Promise<T>}
 */
function serializedCanonicalWrite(write) {
  const result = canonicalWriteChain.then(write, write);
  canonicalWriteChain = result.then(() => {}, () => {});
  return result;
}

/** @param {CanonicalState} state @param {AtomicWriteOptions} [options] */
export function saveCanonicalState(state, { path = getCanonicalStatePath(), fs } = {}) {
  validateCanonicalState(state);
  return serializedCanonicalWrite(() => atomicJsonWrite(path, state, { fs }));
}

/** @param {string} path @param {{ readFile: typeof readFile }} fs */
async function readCanonicalFile(path, fs) {
  try {
    return await fs.readFile(path, 'utf8');
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') return null;
    throw new CanonicalStateError('read', error);
  }
}

/** @param {{ path?: string, legacyPath?: string, fs?: { readFile: typeof readFile } }} [options] */
export async function loadCanonicalState({
  path = getCanonicalStatePath(),
  legacyPath = getStatePath(),
  fs = { readFile },
} = {}) {
  const raw = await readCanonicalFile(path, fs);
  if (raw !== null) {
    try {
      return validateCanonicalState(JSON.parse(raw));
    } catch (error) {
      if (error instanceof CanonicalStateError) throw error;
      throw new CanonicalStateError('parse', error);
    }
  }
  const legacy = await readCanonicalFile(legacyPath, fs);
  if (legacy === null) return null;
  let parsed;
  try {
    parsed = JSON.parse(legacy);
  } catch (error) {
    throw new CanonicalStateError('parse legacy', error);
  }
  return migrateLegacyState(parsed, { legacyBytes: legacy });
}

export const loadV2State = loadCanonicalState;

const LEGACY_ROOT_FIELDS = new Set(['accounts', 'quota', 'template', 'clients', 'usageDimensions']);
const LEGACY_ACCOUNT_FIELDS = new Set([
  'type', 'name', 'accountUuid', 'orgUuid', 'orgName', 'provider', 'accountId', 'id',
  'quota', 'usage', 'rateLimitedUntil', 'profile', 'adaptive',
]);

/** @param {unknown} object @param {ReadonlySet<string>} allowed @param {string} operation */
function assertLegacyFields(object, allowed, operation) {
  if (!isObject(object)) throw new CanonicalStateError(operation);
  for (const field of Object.keys(/** @type {Record<string, unknown>} */ (object))) {
    if (!allowed.has(field)) throw new CanonicalStateError(operation);
  }
}

/** @param {unknown} quota @returns {StateSection | undefined} */
function migrateLegacyQuota(quota) {
  if (!isObject(quota)) return undefined;
  /** @type {StateSection} */
  const migrated = {};
  for (const [field, value] of Object.entries(/** @type {StateSection} */ (quota))) {
    if (field === 'unifiedStatus') {
      if (value !== null && typeof value !== 'string') throw new CanonicalStateError('migrate quota');
      continue;
    }
    if (!QUOTA_FIELDS.has(field)) throw new CanonicalStateError('migrate quota');
    migrated[field] = value;
  }
  return migrated;
}

export function migrateLegacyState(legacy, { legacyBytes = stableJson(legacy) } = {}) {
  if (legacyBytes === undefined) throw new CanonicalStateError('migrate');
  const sourceDigest = createHash('sha256').update(legacyBytes).digest('hex');
  if (!Array.isArray(legacy)) assertLegacyFields(legacy, LEGACY_ROOT_FIELDS, 'migrate root');
  const entries = Array.isArray(legacy) ? legacy : legacy?.accounts ?? legacy?.quota;
  if (!Array.isArray(entries)) throw new CanonicalStateError('migrate');
  /** @type {CanonicalState['accounts']} */
  const accounts = {};
  createIdentityRegistry(entries);
  for (const entry of entries) {
    assertLegacyFields(entry, LEGACY_ACCOUNT_FIELDS, 'migrate account');
    if (Object.hasOwn(entry, 'quota') && !isObject(entry.quota)) throw new CanonicalStateError('migrate quota');
    if (Object.hasOwn(entry, 'usage') && !isObject(entry.usage)) throw new CanonicalStateError('migrate usage');
    if (Object.hasOwn(entry, 'rateLimitedUntil') && !Number.isFinite(entry.rateLimitedUntil)) {
      throw new CanonicalStateError('migrate throttle');
    }
    const key = accountIdKey(entry);
    if (Object.hasOwn(accounts, key)) throw new CanonicalStateError('migrate duplicate identity');
    /** @type {StateSection} */
    const state = {};
    if (entry.profile !== undefined) state.profile = entry.profile;
    if (entry.adaptive !== undefined) state.adaptive = entry.adaptive;
    const quota = migrateLegacyQuota(entry.quota);
    if (quota) state.quota = quota;
    if (isObject(entry.usage)) state.usage = entry.usage;
    if (Number.isFinite(entry.rateLimitedUntil)) state.throttle = { until: entry.rateLimitedUntil };
    accounts[key] = state;
  }
  return createCanonicalState({
    accounts,
    template: legacy?.template ?? null,
    clients: legacy?.clients,
    usageDimensions: legacy?.usageDimensions,
    migration: { completed: true, sourceDigests: { legacy: sourceDigest } },
  });
}

export async function loadState() {
  return loadCanonicalState();
}

export async function saveState(state) {
  const canonical = state?.version === 2 ? state : migrateLegacyState(state);
  await saveCanonicalState(canonical);
}

/** @param {{ from: ConfigIdentity, to: ConfigIdentity, beforeState: CanonicalState, afterState: CanonicalState, phase?: 'prepared' }} options
 * @returns {Readonly<RekeyRecord>}
 */
export function createRekeyRecord({ from, to, beforeState, afterState, phase = 'prepared' }) {
  if (phase !== 'prepared') throw new CanonicalStateError('rekey validate');
  return Object.freeze({
    oldAccountIdDigest: accountIdDigest(from),
    newAccountIdDigest: accountIdDigest(to),
    oldTupleDigest: identityTupleDigest(from),
    newTupleDigest: identityTupleDigest(to),
    oldConfigIdentityDigest: configIdentityDigest(from),
    newConfigIdentityDigest: configIdentityDigest(to),
    oldStateDigest: statePayloadDigest(beforeState),
    newStateDigest: statePayloadDigest(afterState),
    phase,
  });
}

const REKEY_RECORD_FIELDS = new Set([
  'oldAccountIdDigest', 'newAccountIdDigest',
  'oldTupleDigest', 'newTupleDigest',
  'oldConfigIdentityDigest', 'newConfigIdentityDigest',
  'oldStateDigest', 'newStateDigest', 'phase',
]);

/** @param {RekeyRecord} record @returns {RekeyRecord} */
export function validateRekeyRecord(record) {
  assertAllowed(record, REKEY_RECORD_FIELDS, 'rekey');
  if (!['prepared', 'config-committed', 'state-committed'].includes(record.phase)) {
    throw new CanonicalStateError('rekey validate');
  }
  for (const field of /** @type {Set<keyof RekeyRecord>} */ (REKEY_RECORD_FIELDS)) {
    if (field === 'phase') continue;
    if (typeof record[field] !== 'string' || !/^[a-f0-9]{64}$/i.test(record[field])) {
      throw new CanonicalStateError('rekey validate');
    }
  }
  if (record.oldAccountIdDigest === record.newAccountIdDigest ||
      record.oldStateDigest === record.newStateDigest) {
    throw new CanonicalStateError('rekey validate');
  }
  return record;
}

/** @param {RekeyRecord} record @param {readonly ConfigIdentity[]} authoritativeAccounts @param {'old' | 'new'} side */
function matchingAuthoritativeIdentity(record, authoritativeAccounts, side) {
  /** @type {Array<keyof RekeyRecord>} */
  const fields = side === 'old'
    ? ['oldAccountIdDigest', 'oldTupleDigest', 'oldConfigIdentityDigest']
    : ['newAccountIdDigest', 'newTupleDigest', 'newConfigIdentityDigest'];
  return createIdentityRegistry(authoritativeAccounts).entries()
    .map(([, account]) => account)
    .filter(account =>
      accountIdDigest(account) === record[fields[0]] &&
      identityTupleDigest(account) === record[fields[1]] &&
      configIdentityDigest(account) === record[fields[2]]);
}

/** @param {RekeyRecord} record @param {readonly ConfigIdentity[]} authoritativeAccounts */
function authoritativeRekeySide(record, authoritativeAccounts) {
  const oldMatches = matchingAuthoritativeIdentity(record, authoritativeAccounts, 'old');
  const newMatches = matchingAuthoritativeIdentity(record, authoritativeAccounts, 'new');
  if (oldMatches.length + newMatches.length !== 1) throw new CanonicalStateError('rekey authority');
  return oldMatches.length ? { side: 'old', account: oldMatches[0] } : { side: 'new', account: newMatches[0] };
}

/** @param {CanonicalState} state @param {string} digest */
function matchingStateKeys(state, digest) {
  return Object.keys(state.accounts)
    .filter(key => accountIdDigest(parseAccountIdKey(key)) === digest);
}
/** @param {CanonicalState} state @param {string} fromKey @param {string} toKey */
export function rekeyCanonicalState(state, fromKey, toKey) {
  if (fromKey === toKey) return state;
  if (Object.hasOwn(state.accounts, toKey)) throw new CanonicalStateError('rekey collision');
  if (!Object.hasOwn(state.accounts, fromKey)) throw new CanonicalStateError('rekey authority');
  const accounts = { ...state.accounts, [toKey]: state.accounts[fromKey] };
  delete accounts[fromKey];
  return createCanonicalState({
    ...state,
    activeAccountId: state.activeAccountId === fromKey ? toKey : state.activeAccountId,
    accounts,
  });
}

/** @param {RekeyRecord} record @param {CanonicalState} state @param {readonly ConfigIdentity[]} authoritativeAccounts */
export function reconcileRekeyRecord(record, state, authoritativeAccounts) {
  validateRekeyRecord(record);
  validateCanonicalState(state);

  const authority = authoritativeRekeySide(record, authoritativeAccounts);
  if (record.phase !== 'prepared' && authority.side !== 'new') {
    throw new CanonicalStateError('rekey authority');
  }
  const expectedConfigKey = accountIdKey(authority.account);
  const oldKeys = matchingStateKeys(state, record.oldAccountIdDigest);
  const newKeys = matchingStateKeys(state, record.newAccountIdDigest);
  if (oldKeys.length > 1 || newKeys.length > 1 || (oldKeys.length && newKeys.length) ||
      (!oldKeys.length && !newKeys.length)) {
    throw new CanonicalStateError('rekey authority');
  }

  const currentDigest = statePayloadDigest(state);
  if (authority.side === 'old') {
    if (expectedConfigKey !== oldKeys[0] || currentDigest !== record.oldStateDigest) {
      throw new CanonicalStateError('rekey payload');
    }
    return { state, complete: true };
  }

  if (expectedConfigKey !== newKeys[0] && newKeys.length) {
    throw new CanonicalStateError('rekey authority');
  }
  if (currentDigest === record.newStateDigest && newKeys.length === 1) {
    return { state, complete: true };
  }
  if (currentDigest !== record.oldStateDigest || oldKeys.length !== 1) {
    throw new CanonicalStateError('rekey payload');
  }
  const next = rekeyCanonicalState(state, oldKeys[0], expectedConfigKey);
  if (statePayloadDigest(next) !== record.newStateDigest) {
    throw new CanonicalStateError('rekey payload');
  }
  return { state: next, complete: true };
}

/** @param {{ path?: string, fs?: { readFile: typeof readFile } }} [options] */
export async function loadRekeyRecord({
  path = getRekeyPath(),
  fs = { readFile },
} = {}) {
  const raw = await readCanonicalFile(path, fs);
  if (raw === null) return null;
  try {
    return validateRekeyRecord(JSON.parse(raw));
  } catch (error) {
    if (error instanceof CanonicalStateError) throw error;
    throw new CanonicalStateError('rekey parse', error);
  }
}

/** @param {{ state: CanonicalState | null | undefined, record: RekeyRecord | null, authoritativeAccounts: readonly ConfigIdentity[] }} options */
export function reconcileStartupState({ state, record, authoritativeAccounts }) {
  if (!record) return { state, complete: true };
  if (!state) throw new CanonicalStateError('rekey authority');
  return reconcileRekeyRecord(record, state, authoritativeAccounts);
}

/** @param {{ state?: CanonicalState | null, authoritativeAccounts?: readonly ConfigIdentity[], statePath?: string, rekeyPath?: string }} [options] */
export async function reconcilePendingRekey({
  state,
  authoritativeAccounts,
  statePath = getCanonicalStatePath(),
  rekeyPath = getRekeyPath(),
} = {}) {
  const record = await loadRekeyRecord({ path: rekeyPath });
  if (!record) return state;
  if (!state || !authoritativeAccounts) throw new CanonicalStateError('rekey authority');
  const reconciled = reconcileStartupState({ state, record, authoritativeAccounts });
  if (reconciled.state && reconciled.state !== state) await saveCanonicalState(reconciled.state, { path: statePath });
  await rm(rekeyPath, { force: true });
  return reconciled.state;
}

/** @param {RekeyRecord} record @param {AtomicWriteOptions} [options] */
export function saveRekeyRecord(record, { path = getRekeyPath(), fs } = {}) {
  validateRekeyRecord(record);
  return serializedCanonicalWrite(() => atomicJsonWrite(path, record, { fs }));
}

export function createDefaultConfig() {
  return {
    proxy: {
      port: 3456,
      apiKey: 'tc-' + randomBytes(24).toString('base64url'),
    },
    upstream: 'https://api.anthropic.com',
    switchThreshold: 0.98,
    maxConcurrentPerAccount: 3,
    sessionAffinity: true,
    overflowQueueTimeoutMs: 15000,
    overflowQueueMaxDepth: 16,
    maxRequestBytes: 33554432,
    holdSeconds: 0,
    distributeSessions: false,
    sessionTitles: { enabled: false, width: 18 },
    eventLogging: 'hide',
    defaultClientMode: 'mitm',
    blockedModels: [],
    accounts: [],
  };
}

export class ConfigValidationError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = 'ConfigValidationError';
  }
}

const SX_MODES = new Set(['off', '429', 'always']);

/**
 * Normalize the legacy top-level sxMode field at the config boundary. All
 * callers receive and persist only the canonical nested sx.mode form.
 */
export function normalizeConfig(config) {
  if (!isObject(config)) throw new ConfigValidationError('Config must be an object');

  const hasLegacyMode = Object.hasOwn(config, 'sxMode');
  const sx = config.sx;
  if (sx !== undefined && !isObject(sx)) {
    throw new ConfigValidationError('Config sx must be an object');
  }

  const hasCanonicalMode = !!sx && Object.hasOwn(sx, 'mode');
  if (hasLegacyMode && sx !== undefined) {
    throw new ConfigValidationError('Config cannot contain both sx and legacy sxMode');
  }
  if (sx && !hasCanonicalMode) {
    throw new ConfigValidationError('Config sx.mode is required when sx is configured');
  }

  const mode = hasCanonicalMode ? sx.mode : hasLegacyMode ? config.sxMode : undefined;
  if ((hasCanonicalMode || hasLegacyMode) &&
      (typeof mode !== 'string' || !SX_MODES.has(mode))) {
    throw new ConfigValidationError('Config sx.mode must be one of: off, 429, always');
  }

  const normalizedSx = hasLegacyMode ? { mode } : sx;

  if (!hasLegacyMode && normalizedSx === sx) return config;
  const normalized = { ...config };
  delete normalized.sxMode;
  if (normalizedSx !== undefined) normalized.sx = normalizedSx;
  return normalized;
}

export async function loadConfig() {
  const path = getConfigPath();
  try {
    const config = normalizeConfig(JSON.parse(await readFile(path, 'utf-8')));
    if (!Array.isArray(config.accounts)) config.accounts = [];
    ensureAccountIds(config.accounts);
    applyUpstreamProxy(config);
    return config;
  } catch (err) {
    if (errorProperty(err, 'code') === 'ENOENT') return null;
    throw err;
  }
}

/**
 * Publish the config's egress proxy to the process-wide setting.
 *
 * Done here, in the one place every command loads its config, rather than at
 * each of the sixteen call sites: `login`, `import`, `accounts`, `probe` and the
 * server all reach the network, and a proxy that applied to only some of them
 * would be worse than none — the account list would refresh while logging in
 * failed, or vice versa.
 *
 * A bad value is fatal on purpose. Falling back to a direct connection on a host
 * that has no route to the internet would turn one clear error into a pile of
 * ETIMEDOUTs pointing nowhere near the typo that caused them.
 */
function applyUpstreamProxy(config) {
  try {
    setUpstreamProxy(resolveUpstreamProxy(config));
  } catch (err) {
    console.error(`[TeamClaude] Bad proxy setting in ${getConfigPath()}: ${errorProperty(err, 'message')}`);
    process.exit(1);
  }
}

export async function loadOrCreateConfig() {
  let config = await loadConfig();
  if (!config) {
    config = createDefaultConfig();
    await saveConfig(config);
    console.log(`Created config at ${getConfigPath()}`);
    // loadConfig applies this only when a file already existed — it returns
    // early on ENOENT. Without it here, the FIRST run of a network command
    // (`login` on a fresh install) leaves the process-wide setting unset, and
    // the lazy fallback resolves it from the environment against an EMPTY
    // config. That fallback has no listener to compare against, so the
    // self-proxy guard cannot fire: an operator whose HTTPS_PROXY points at
    // their own TeamClaude gets a CONNECT back into the proxy and a timeout,
    // on the one run where there is no config to explain it.
    applyUpstreamProxy(config);
  }
  return config;
}

let credentialWriteChain = Promise.resolve();

/** @param {Record<string, unknown>} config @param {ConfigWriteOptions} [options] */
function writeConfig(config, {
  path = getConfigPath(),
  fs = { mkdir, open, rename, rm, chmod },
} = {}) {
  const normalizedConfig = normalizeConfig(config);
  const write = async () => {
    const directory = dirname(path);
    const tempPath = join(directory, `.${basename(path)}.${randomBytes(12).toString('hex')}.tmp`);
    let handle;
    try {
      await fs.mkdir(directory, { recursive: true });
      handle = await fs.open(tempPath, 'w', 0o600);
      // The temp file must be private before credentials are written or renamed.
      await fs.chmod(tempPath, 0o600);
      await handle.writeFile(JSON.stringify(normalizedConfig, null, 2) + '\n', 'utf8');
      await handle.sync();
      await handle.close();
      handle = null;
      await fs.rename(tempPath, path);
      const directoryHandle = await fs.open(directory, 'r');
      try {
        await directoryHandle.sync();
      } finally {
        await directoryHandle.close();
      }
    } catch (error) {
      if (handle) await handle.close().catch(() => {});
      await fs.rm(tempPath, { force: true }).catch(() => {});
      throw new ConfigOperationError('write', error);
    }
  };
  const result = credentialWriteChain.then(write, write);
  credentialWriteChain = result.then(() => {}, () => {});
  return result;
}

// Every writer of the config — the server rotating a refresh token, a CLI
// command, a GUI client — does its own read-modify-write with a temp+rename.
// Two of them racing keep only the later write, and the edit that is lost is
// as likely as not a freshly rotated refresh token, which costs a re-login.
// The lock below is the coordination point. It is advisory and file-based so
// that clients outside this package can honour it with no shared code:
//
//   path     <configPath>.lock
//   acquire  open(O_CREAT|O_EXCL, 0600), then write {"pid":<pid>,"at":<ms epoch>}
//   stale    `at` older than 10 s, or the pid no longer alive: unlink and retry
//   busy     poll every 25 ms for at most 2 s, then write WITHOUT the lock
//   release  unlink
//
// The 2 s cap is deliberate: a writer must never hang on a lock, so contention
// past it degrades to today's behaviour (a possible lost update) plus one
// warning line, rather than to a stuck server or CLI.
const LOCK_STALE_MS = 10_000;
const LOCK_WAIT_MS = 2_000;
const LOCK_POLL_MS = 25;

/** @param {string} lockPath */
function lockIsStale(lockPath) {
  let pid, at;
  try {
    ({ pid, at } = JSON.parse(readFileSync(lockPath, 'utf8')));
  } catch (err) {
    if (errorProperty(err, 'code') === 'ENOENT') return false; // released under us; the retry takes it
    // Empty or garbled: the holder is between its open and its write, or died
    // there. Only the file's age can tell those apart.
    try { return Date.now() - statSync(lockPath).mtimeMs > LOCK_STALE_MS; } catch { return false; }
  }
  if (Date.now() - at > LOCK_STALE_MS) return true;
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return false; } catch (err) { return errorProperty(err, 'code') === 'ESRCH'; }
}

/** True when the lock is ours; false when we gave up and proceed without it.
 * @param {string} lockPath
 */
async function acquireConfigLock(lockPath) {
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (;;) {
    try {
      const fd = openSync(lockPath, 'wx', 0o600);
      try { writeSync(fd, JSON.stringify({ pid: process.pid, at: Date.now() })); } finally { closeSync(fd); }
      return true;
    } catch (err) {
      if (errorProperty(err, 'code') !== 'EEXIST') {
        console.error(`[TeamClaude] Cannot create ${lockPath} (${errorProperty(err, 'code') || errorProperty(err, 'message')}); writing the config without it`);
        return false;
      }
    }
    if (lockIsStale(lockPath)) {
      await unlink(lockPath).catch(() => {});
      continue;
    }
    if (Date.now() >= deadline) {
      console.error(`[TeamClaude] ${lockPath} is still held by another process after ${LOCK_WAIT_MS}ms; writing the config without it`);
      return false;
    }
    await new Promise(resolve => setTimeout(resolve, LOCK_POLL_MS));
  }
}

// One queue per lock path inside this process: same-process callers (the TUI
// saving while a token refresh runs) would otherwise spin against their own
// live lock file for the full 2 s.
/** @type {Map<string, Promise<void>>} */
const lockQueues = new Map();

/**
 * Run `fn` while holding the advisory lock for `configPath` (protocol above).
 * Same-process callers are queued; other processes are held off by the file.
 * The lock is released whether `fn` resolves or throws.
 * @template T
 * @param {string} configPath
 * @param {() => T | Promise<T>} fn
 * @returns {Promise<T>}
 */
export function withConfigLock(configPath, fn) {
  const lockPath = `${configPath}.lock`;
  const run = async () => {
    await mkdir(dirname(lockPath), { recursive: true });
    const held = await acquireConfigLock(lockPath);
    try {
      return await fn();
    } finally {
      if (held) await unlink(lockPath).catch(() => {});
    }
  };
  const prev = lockQueues.get(lockPath) || Promise.resolve();
  const result = prev.then(run, run);
  lockQueues.set(lockPath, result.then(() => {}, () => {}));
  return result;
}

/** @param {Record<string, unknown>} config @param {ConfigWriteOptions} [options] */
export async function saveConfig(config, options = {}) {
  const path = options.path ?? getConfigPath();
  // Config credentials use a private, fsynced temp file and atomic rename.
  const normalizedConfig = normalizeConfig(config);
  if (!Array.isArray(normalizedConfig.accounts)) normalizedConfig.accounts = [];
  ensureAccountIds(normalizedConfig.accounts);
  // An injected filesystem owns the entire write; do not touch the host's
  // directories or lock files while exercising its failure paths.
  if (options.fs) return writeConfig(normalizedConfig, { ...options, path });
  const target = await realpath(path).catch(() => path);
  await withConfigLock(target, () => writeConfig(normalizedConfig, { ...options, path: target }));
}

/**
 * Atomically update the config: re-reads from disk, calls updater(config),
 * then saves. Returns the updated config. This prevents overwriting changes
 * made by other processes (e.g. `teamclaude import` while the server runs), and
 * holds the config lock across the read and the write so a concurrent writer —
 * in this process or another — waits its turn instead of clobbering the update.
 * @param {(config: ConfigMutation) => unknown | Promise<unknown>} updater
 * @returns {Promise<ConfigMutation>}
 */
export async function atomicConfigUpdate(updater) {
  const path = await realpath(getConfigPath()).catch(() => getConfigPath());
  return withConfigLock(path, async () => {
    const config = await loadConfig() || createDefaultConfig();
    await updater(config);
    const normalizedConfig = normalizeConfig(config);
    if (!Array.isArray(normalizedConfig.accounts)) normalizedConfig.accounts = [];
    ensureAccountIds(normalizedConfig.accounts);
    await writeConfig(normalizedConfig, { path });
    return normalizedConfig;
  });
}
