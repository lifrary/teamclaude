import { normalizeExpiresAt } from './oauth.js';
import { accountIdKey, sameIdentity, distinctAccounts, IdentityAmbiguityError } from './identity.js';
import { providerOf } from './provider.js';
import { resolveAccounts } from './resolve-accounts.js';
import { safeLine } from './safe-text.js';
import { removedAccountIds, addedAccountIds, configIndexFor } from './account-pairing.js';
import { ensureAccountIds } from './account-id.js';
import { accountSwitchThreshold, accountAllowsExtraUsage, accountRouting } from './account-manager.js';
import { localListener } from './upstream-proxy.js';

/**
 * @typedef {Parameters<typeof resolveAccounts>[0]} AccountsConfig
 * @typedef {AccountsConfig['accounts'][number]} ConfigAccount
 * @typedef {import('./account-manager.js').AccountManager} AccountManager
 * @typedef {AccountManager['accounts'][number]} LiveAccount
 * @typedef {{ migration?: import('./config.js').StateMigration, template?: import('./config.js').StateSection | null }} StateContext
 * @typedef {StateContext & { accountManager: AccountManager, previous: LiveAccount, target: ConfigAccount, authoritativeConfig: AccountsConfig }} RekeyOptions
 * @typedef {StateContext & { rekey?: (options: RekeyOptions) => Promise<LiveAccount> }} SyncOptions
 */

// Stable entry IDs decide first. Legacy fixtures/configs without IDs may pair
// only on unique evidence; never guess between two organizations or providers.
/**
 * @template {import('./identity.js').IdentityAccount & { id?: string | null }} T
 * @param {T[]} accounts
 * @param {ConfigAccount} disk
 * @param {Set<T>} claimed
 * @returns {T | null}
 */
function claimAccount(accounts, disk, claimed) {
  const available = accounts.filter(account => !claimed.has(account));
  const byId = disk.id ? available.filter(account => account.id === disk.id) : [];
  let matches = byId;
  if (!matches.length) {
    const legacy = available.filter(account => !disk.id || !account.id);
    matches = legacy.filter(account => sameIdentity(account, disk));
    if (!matches.length) {
      matches = legacy.filter(account => providerOf(account) === providerOf(disk)
        && !distinctAccounts(account, disk)
        && ((disk.accountUuid && account.accountUuid === disk.accountUuid) || account.name === disk.name));
    }
  }
  if (matches.length > 1) throw new IdentityAmbiguityError('Ambiguous config reload pairing');
  const match = matches[0] || null;
  if (match) claimed.add(match);
  return match;
}

/** Reconcile disk entries without replacing live token lineage or identity in place.
 * Returns { added, removed }: accounts picked up from disk, and running
 * accounts dropped because their disk entry is gone.
 * @param {AccountsConfig} diskConfig
 * @param {AccountsConfig} memConfig
 * @param {AccountManager} accountManager
 * @param {SyncOptions} [options]
 * @returns {Promise<{ added: number, removed: number }>}
 */
export async function syncAccountsFromDisk(diskConfig, memConfig, accountManager, { migration, template, rekey } = {}) {
  let added = 0;
  const withoutId = new Set(diskConfig.accounts.filter(account => typeof account.id !== 'string' || account.id === ''));
  ensureAccountIds(diskConfig.accounts);
  /** @type {Set<LiveAccount>} */
  const claimed = new Set();
  /** @type {Set<ConfigAccount>} */
  const configClaimed = new Set();
  // The TUI's remove changes memory first and saves second. A reload landing
  // between the two reads a row the save has not rewritten yet and would add
  // it straight back. The ids are recorded for exactly that window (cleared
  // once the save lands), so a row naming one is the removal itself (#422).
  // Only an id the row carried on disk counts; a freshly minted one is not evidence.
  const removedIds = removedAccountIds(memConfig);
  for (const disk of diskConfig.accounts) {
    if (!withoutId.has(disk) && removedIds.has(disk.id)) continue;
    // A freshly minted ID is not pairing evidence. Repeated reloads of an
    // ID-less row must reuse its uniquely matched live ID, not admit a copy.
    const pairing = withoutId.has(disk) ? { ...disk, id: undefined } : disk;
    let manager = claimAccount(accountManager.accounts, pairing, claimed);
    const memory = claimAccount(memConfig.accounts, pairing, configClaimed);
    if (withoutId.has(disk)) disk.id = manager?.id || memory?.id || disk.id;
    if (memory && !memory.id) memory.id = disk.id;
    const credential = manager?.credential;
    const refreshToken = manager?.refreshToken;
    const [resolved] = await resolveAccounts({ accounts: [disk] });
    // A refresh, removal, or replacement while an import awaited owns the live
    // lineage. The next reload can retry against a fresh disk snapshot.
    if (manager && (!accountManager.accounts.includes(manager)
      || manager.credential !== credential || manager.refreshToken !== refreshToken)) continue;

    if (!manager) {
      if (!memory) {
        const row = { ...disk };
        memConfig.accounts.push(row);
        configClaimed.add(row);
      }
      if (!resolved) continue;
      if (memory) {
        // A previously tokenless import may return as an inline account.
        // Do not let the stale memory row resurrect its old importFrom on save.
        for (const field of Object.keys(memory)) {
          if (!Object.hasOwn(disk, field)) delete memory[field];
        }
        Object.assign(memory, disk);
      }
      const index = accountManager.addAccount(resolved);
      claimed.add(accountManager.accounts[index]);
      added++;
      console.log(`[TeamClaude] Picked up account "${safeLine(disk.name, 64)}" from config`);
      continue;
    }
    if (!manager.id) manager.id = disk.id;

    const diskExpiry = normalizeExpiresAt(resolved?.expiresAt);
    const liveExpiry = normalizeExpiresAt(manager.expiresAt);
    const stale = liveExpiry !== null && (diskExpiry === null || diskExpiry < liveExpiry);
    if (accountIdKey(manager) !== accountIdKey(resolved || disk)) {
      if (!resolved || stale) continue;
      if (!rekey) throw new IdentityAmbiguityError('Identity changes require durable rekey');
      manager = await rekey({
        accountManager, previous: manager, target: resolved,
        authoritativeConfig: diskConfig, migration, template,
      });
      claimed.add(manager);
    }

    const priority = Number.isFinite(disk.priority) ? Math.floor(disk.priority) : null;
    if (manager.priority !== priority) accountManager.setPriority(manager, priority);
    const disabled = disk.disabled === true || disk.enabled === false;
    if (manager.disabled !== disabled) accountManager.setDisabled(manager.index, disabled);
    manager.maxConcurrent = Number.isFinite(disk.maxConcurrent) && disk.maxConcurrent >= 1
      ? Math.floor(disk.maxConcurrent) : accountManager.maxConcurrentDefault;
    if (manager.upstream !== (disk.upstream || null)
      || manager.messageThreads !== (disk.messageThreads === true)) manager.threadRefusalReported = false;
    for (const field of /** @type {const} */ (['upstream', 'modelMap', 'stripRequestFields'])) manager[field] = disk[field] || null;
    manager.messageThreads = disk.messageThreads === true;
    manager.maxUsage = disk.maxUsage ?? null;
    manager.maxSpend = disk.maxSpend ?? null;
    // Per-account gates read live, each through the same check the constructor
    // applies, so a value refused at startup is refused (and reported) on reload.
    manager.switchThreshold = accountSwitchThreshold(disk);
    manager.allowExtraUsage = accountAllowsExtraUsage(disk);
    // memConfig's port is the one this server is bound to; a port edit on disk needs a restart.
    accountManager.setRouting(manager.index, accountRouting(disk, localListener(memConfig)));
    // Negative-only: only `false` exempts the account from autoRedeemResets.
    manager.autoRedeemReset = disk.autoRedeemReset !== false;
    // Display only; `null` puts an account whose field was deleted back among the unplaced.
    manager.displayOrder = Number.isFinite(disk.displayOrder) ? disk.displayOrder : null;
    for (const field of /** @type {const} */ (['organizationType', 'rateLimitTier', 'seatTier', 'hasClaudeMax', 'hasClaudePro'])) {
      if (disk[field] != null) manager[field] = disk[field];
    }
    // Display renames are safe only after the canonical key has been reconciled.
    manager.name = disk.name;
    if (memory) {
      for (const field of ['name', 'accountUuid', 'orgUuid', 'orgName', 'accountId', 'provider',
        'priority', 'disabled', 'enabled', 'maxConcurrent', 'maxUsage', 'upstream', 'modelMap',
        'stripRequestFields', 'messageThreads', 'organizationType', 'rateLimitTier', 'seatTier', 'hasClaudeMax', 'hasClaudePro',
        'maxSpend', 'switchThreshold', 'routing', 'displayOrder', 'allowExtraUsage', 'autoRedeemReset']) {
        const source = resolved || disk;
        if (Object.hasOwn(source, field)) memory[field] = source[field];
        else delete memory[field];
      }
    }
    if (resolved?.accessToken && !stale
      && (manager.credential !== resolved.accessToken || manager.refreshToken !== resolved.refreshToken)) {
      accountManager.updateAccountTokens(manager.index, {
        accessToken: resolved.accessToken,
        refreshToken: resolved.refreshToken,
        expiresAt: diskExpiry,
      });
    } else if (resolved?.apiKey && manager.credential !== resolved.apiKey) {
      manager.credential = resolved.apiKey;
      if (manager.status === 'error') { manager.status = 'active'; Reflect.deleteProperty(manager, '_errorFromRefresh'); }
      // A different key is a different credential: the 401 hold was about the old one.
      accountManager.clearCredentialRejected(manager.index);
    }
  }
  // Running accounts that no disk row claims any more were removed on disk (a
  // `teamclaude remove` from another process, or a hand edit): drop them from
  // the manager and the in-memory config, highest index first so the indices
  // still to visit stay valid (#465). The TUI and the MCP endpoint add into
  // memory first and save second; the ids recorded for that window are the
  // addition itself, not a removal. The config row goes by id (configIndexFor),
  // resolved before removeAccount renumbers the manager list.
  const pendingAdds = addedAccountIds(memConfig);
  let removed = 0;
  for (let i = accountManager.accounts.length - 1; i >= 0; i--) {
    const gone = accountManager.accounts[i];
    if (claimed.has(gone) || pendingAdds.has(gone.id)) continue;
    const cfgIdx = configIndexFor(memConfig.accounts, accountManager.accounts, i);
    console.log(`[TeamClaude] Removed account "${safeLine(gone.name, 64)}": its config entry is gone from disk`);
    accountManager.removeAccount(i);
    if (cfgIdx >= 0) memConfig.accounts.splice(cfgIdx, 1);
    removed++;
  }
  accountManager._drainWaiters();
  return { added, removed };
}
