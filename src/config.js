import { readFile, writeFile, mkdir, rm, chmod, open, rename } from 'node:fs/promises';
import { join, dirname, basename } from 'node:path';
import { homedir } from 'node:os';
import { createHash, randomBytes } from 'node:crypto';
import { accountId, accountIdKey, createIdentityRegistry, parseAccountIdKey } from './identity.js';

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
  constructor(operation, cause) {
    super(`Server state ${operation} failed`, { cause });
    this.operation = operation;
    this.errorClass = cause?.code || cause?.name || 'Error';
  }
}
class ConfigOperationError extends Error {
  constructor(operation, error) {
    super(`Config ${operation} failed`);
    this.operation = operation;
    this.errorClass = error?.code || error?.name || 'Error';
  }
}

async function serverStateOperation(operation, fn) {
  try {
    return await fn();
  } catch (error) {
    throw new ServerStateOperationError(operation, error);
  }
}

export function formatServerStateFailure(error) {
  const operation = error?.operation || 'write';
  const errorClass = error?.errorClass || error?.code || error?.name || 'Error';
  return `[TeamClaude] Server state ${operation} failed (${errorClass}).`;
}

export async function writeServerState(state, {
  path = getServerStatePath(),
  fs = { mkdir, writeFile, chmod },
} = {}) {
  await serverStateOperation('mkdir', () => fs.mkdir(dirname(path), { recursive: true }));
  await serverStateOperation('write', () => fs.writeFile(path, JSON.stringify(state, null, 2) + '\n', { mode: 0o600 }));
  await serverStateOperation('chmod', () => fs.chmod(path, 0o600));
}

function reportPersistenceError(operation, err) {
  const detail = err instanceof SyntaxError
    ? 'invalid JSON'
    : err?.code ? `filesystem error (${err.code})` : 'filesystem error';
  console.warn(`[TeamClaude] Unable to ${operation}: ${detail}.`);
}

async function readPersistedJson(path, label) {
  let raw;
  try {
    raw = await readFile(path, 'utf-8');
  } catch (err) {
    if (err?.code === 'ENOENT') return null;
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
    if (error?.code === 'ENOENT') return;
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
  constructor(operation, cause) {
    super(`Canonical state ${operation} failed`);
    this.name = 'CanonicalStateError';
    this.operation = operation;
    this.errorClass = cause?.code || cause?.name || 'InvalidState';
  }
}

const STATE_FIELDS = new Set(['version', 'writtenAt', 'migration', 'activeAccountId', 'accounts', 'template']);
const MIGRATION_FIELDS = new Set(['completed', 'sourceDigests']);
const ACCOUNT_STATE_FIELDS = new Set(['quota', 'usage', 'throttle', 'convergence', 'reset']);
const QUOTA_FIELDS = new Set([
  'tokensLimit', 'tokensRemaining', 'requestsLimit', 'requestsRemaining',
  'unified5h', 'unified7d', 'unified7dSonnet', 'unified7dFable',
  'unified5hReset', 'unified7dReset', 'unified7dSonnetReset', 'unified7dFableReset',
  'resetsAt', 'modelWeekly',
]);
const USAGE_FIELDS = new Set(['totalInputTokens', 'totalOutputTokens', 'totalRequests', 'lastUsed']);
const THROTTLE_FIELDS = new Set(['until']);
const CONVERGENCE_FIELDS = new Set(['attempts', 'lastAttemptAt', 'lastSuccessAt', 'status']);
const RESET_FIELDS = new Set(['at', 'reason']);
const TEMPLATE_FIELDS = new Set(['model', 'version', 'beta', 'system', '_elicitsModelWeekly', '_restored']);
const MODEL_WEEKLY_FIELDS = new Set(['utilization', 'reset']);
const TRANSIENT_STATE_FIELDS = new Set([
  'credential', 'accessToken', 'refreshToken', 'apiKey', 'name', 'accountUuid', 'orgUuid', 'orgName',
]);

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function assertAllowed(object, fields, label) {
  if (!isObject(object)) throw new CanonicalStateError('validate');
  for (const key of Object.keys(object)) {
    if (!fields.has(key) || TRANSIENT_STATE_FIELDS.has(key)) throw new CanonicalStateError(`validate ${label}`);
  }
}
function assertScalar(value, label) {
  if (value === undefined || value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return;
  throw new CanonicalStateError(`validate ${label}`);
}

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

function validateAccountState(value) {
  assertAllowed(value, ACCOUNT_STATE_FIELDS, 'account');
  if (value.quota !== undefined) {
    assertAllowed(value.quota, QUOTA_FIELDS, 'quota');
    for (const [field, nested] of Object.entries(value.quota)) {
      if (field !== 'modelWeekly') assertScalar(nested, `quota.${field}`);
    }
    if (value.quota.modelWeekly !== undefined) {
      if (!isObject(value.quota.modelWeekly)) throw new CanonicalStateError('validate quota.modelWeekly');
      for (const [name, window] of Object.entries(value.quota.modelWeekly)) {
        if (!/^[a-z0-9_]+$/i.test(name)) throw new CanonicalStateError('validate quota.modelWeekly');
        assertAllowed(window, MODEL_WEEKLY_FIELDS, 'quota.modelWeekly');
        for (const nested of Object.values(window)) assertScalar(nested, 'quota.modelWeekly');
      }
    }
  }
  for (const [field, fields] of [['usage', USAGE_FIELDS], ['throttle', THROTTLE_FIELDS], ['convergence', CONVERGENCE_FIELDS], ['reset', RESET_FIELDS]]) {
    if (value[field] === undefined) continue;
    assertAllowed(value[field], fields, field);
    for (const nested of Object.values(value[field])) assertScalar(nested, field);
  }
}

function validateTemplate(template) {
  if (template === null) return;
  assertAllowed(template, TEMPLATE_FIELDS, 'template');
  for (const [field, value] of Object.entries(template)) {
    if (field === 'system') validateTemplateSystem(value);
    else assertScalar(value, `template.${field}`);
  }
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (isObject(value)) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function digestRekeyValue(domain, value) {
  return createHash('sha256')
    .update(`teamclaude:${domain}:v1\0${stableJson(value)}`, 'utf8')
    .digest('hex');
}

function normalizedIdentityValue(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.normalize('NFKC').trim().toLowerCase();
  return normalized || null;
}

function identityTuple(account) {
  const id = accountId(account);
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

function configIdentity(account) {
  const type = normalizedIdentityValue(account?.type);
  const name = normalizedIdentityValue(account?.name);
  const accountUuid = normalizedIdentityValue(account?.accountUuid);
  const orgUuid = normalizedIdentityValue(account?.orgUuid);
  const orgName = normalizedIdentityValue(account?.orgName);
  return {
    type,
    name,
    accountUuid,
    orgUuid,
    orgName,
  };
}

export function statePayloadDigest(state) {
  return digestRekeyValue('canonical-state', {
    activeAccountId: state?.activeAccountId ?? null,
    accounts: state?.accounts ?? {},
    template: state?.template ?? null,
  });
}

export function accountIdDigest(account) {
  return digestRekeyValue('account-id', accountIdKey(account));
}

export function identityTupleDigest(account) {
  return digestRekeyValue('identity-tuple', identityTuple(account));
}

export function configIdentityDigest(account) {
  return digestRekeyValue('config-identity', configIdentity(account));
}

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
  return state;
}

function accountIdFromKey(key) {
  try {
    return parseAccountIdKey(key);
  } catch (error) {
    throw new CanonicalStateError('validate', error);
  }
}

export function createCanonicalState({
  accounts = {},
  activeAccountId = null,
  template = null,
  migration = { completed: true, sourceDigests: {} },
  writtenAt = Date.now(),
} = {}) {
  return validateCanonicalState({ version: 2, writtenAt, migration, activeAccountId, accounts, template });
}

const defaultAtomicFs = { mkdir, open, rename, rm };

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

function serializedCanonicalWrite(write) {
  const result = canonicalWriteChain.then(write, write);
  canonicalWriteChain = result.then(() => {}, () => {});
  return result;
}

export function saveCanonicalState(state, { path = getCanonicalStatePath(), fs } = {}) {
  validateCanonicalState(state);
  return serializedCanonicalWrite(() => atomicJsonWrite(path, state, { fs }));
}

async function readCanonicalFile(path, fs) {
  try {
    return await fs.readFile(path, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw new CanonicalStateError('read', error);
  }
}

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

const LEGACY_ROOT_FIELDS = new Set(['accounts', 'quota', 'template']);
const LEGACY_ACCOUNT_FIELDS = new Set([
  'type', 'name', 'accountUuid', 'orgUuid', 'orgName',
  'quota', 'usage', 'rateLimitedUntil',
]);

function assertLegacyFields(object, allowed, operation) {
  if (!isObject(object)) throw new CanonicalStateError(operation);
  for (const field of Object.keys(object)) {
    if (!allowed.has(field)) throw new CanonicalStateError(operation);
  }
}

function migrateLegacyQuota(quota) {
  if (!isObject(quota)) return undefined;
  const migrated = {};
  for (const [field, value] of Object.entries(quota)) {
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
  const sourceDigest = createHash('sha256').update(legacyBytes).digest('hex');
  if (!Array.isArray(legacy)) assertLegacyFields(legacy, LEGACY_ROOT_FIELDS, 'migrate root');
  const entries = Array.isArray(legacy) ? legacy : legacy?.accounts ?? legacy?.quota;
  if (!Array.isArray(entries)) throw new CanonicalStateError('migrate');
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
    const state = {};
    const quota = migrateLegacyQuota(entry.quota);
    if (quota) state.quota = quota;
    if (isObject(entry.usage)) state.usage = entry.usage;
    if (Number.isFinite(entry.rateLimitedUntil)) state.throttle = { until: entry.rateLimitedUntil };
    accounts[key] = state;
  }
  return createCanonicalState({
    accounts,
    template: legacy?.template ?? null,
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

export function validateRekeyRecord(record) {
  assertAllowed(record, REKEY_RECORD_FIELDS, 'rekey');
  if (!['prepared', 'config-committed', 'state-committed'].includes(record.phase)) {
    throw new CanonicalStateError('rekey validate');
  }
  for (const field of REKEY_RECORD_FIELDS) {
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

function matchingAuthoritativeIdentity(record, authoritativeAccounts, side) {
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

function authoritativeRekeySide(record, authoritativeAccounts) {
  const oldMatches = matchingAuthoritativeIdentity(record, authoritativeAccounts, 'old');
  const newMatches = matchingAuthoritativeIdentity(record, authoritativeAccounts, 'new');
  if (oldMatches.length + newMatches.length !== 1) throw new CanonicalStateError('rekey authority');
  return oldMatches.length ? { side: 'old', account: oldMatches[0] } : { side: 'new', account: newMatches[0] };
}

function matchingStateKeys(state, digest) {
  return Object.keys(state.accounts)
    .filter(key => accountIdDigest(parseAccountIdKey(key)) === digest);
}
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

export function reconcileStartupState({ state, record, authoritativeAccounts }) {
  return record ? reconcileRekeyRecord(record, state, authoritativeAccounts) : { state, complete: true };
}

export async function reconcilePendingRekey({
  state,
  authoritativeAccounts,
  statePath = getCanonicalStatePath(),
  rekeyPath = getRekeyPath(),
} = {}) {
  const record = await loadRekeyRecord({ path: rekeyPath });
  if (!record) return state;
  const reconciled = reconcileStartupState({ state, record, authoritativeAccounts });
  if (reconciled.state !== state) await saveCanonicalState(reconciled.state, { path: statePath });
  await rm(rekeyPath, { force: true });
  return reconciled.state;
}

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
    accounts: [],
  };
}

export class ConfigValidationError extends Error {
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
    return normalizeConfig(JSON.parse(await readFile(path, 'utf-8')));
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
}

export async function loadOrCreateConfig() {
  let config = await loadConfig();
  if (!config) {
    config = createDefaultConfig();
    await saveConfig(config);
    console.log(`Created config at ${getConfigPath()}`);
  }
  return config;
}

let credentialWriteChain = Promise.resolve();

export function saveConfig(config, {
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

// Atomic read-modify-write operations must remain serialized: concurrent OAuth
// refreshes otherwise lose rotated tokens and make accounts unrecoverable.
let configUpdateChain = Promise.resolve();

export function atomicConfigUpdate(updater) {
  const run = async () => {
    const config = await loadConfig() || createDefaultConfig();
    await updater(config);
    const normalizedConfig = normalizeConfig(config);
    await saveConfig(normalizedConfig);
    return normalizedConfig;
  };
  const result = configUpdateChain.then(run, run);
  configUpdateChain = result.then(() => {}, () => {});
  return result;
}
