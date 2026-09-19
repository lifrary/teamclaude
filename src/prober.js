// Zero-spend quota reads share maintenance scheduling, never inference admission.
import { fetchUsage, isTokenExpired } from './oauth.js';
import { MaintenanceCoordinator } from './maintenance-coordinator.js';
import { fetchBackendQuota, hasBackendQuota } from './backend-quota.js';
import { providerOf } from './provider.js';
import { fetchCodexUsage } from './codex-usage.js';

export const MAX_PROBE_INTERVAL_MS = 7 * 24 * 60 * 60 * 1000;
/** @param {number} ms */
function clampInterval(ms) { return ms > 0 ? Math.min(ms, MAX_PROBE_INTERVAL_MS) : 0; }

export class Prober {
  /**
   * @param {import('./account-manager.js').AccountManager} accountManager
   * @param {object} [options]
   * @param {number} [options.intervalMs]
   * @param {typeof fetchUsage} [options.probeFn]
   * @param {typeof fetchCodexUsage} [options.codexProbeFn]
   * @param {typeof import('./oauth.js').fetchProfile | null} [options.profileFn]
   * @param {typeof fetchBackendQuota} [options.backendFn]
   * @param {number} [options.timeoutMs]
   * @param {(...args: any[]) => void} [options.log]
   * @param {MaintenanceCoordinator} [options.coordinator]
   * @param {boolean} [options.ownCoordinator]
   */
  constructor(accountManager, {
    intervalMs = 0, probeFn = fetchUsage, codexProbeFn = fetchCodexUsage,
    profileFn = null, backendFn = fetchBackendQuota, timeoutMs = 10_000,
    log = console.log, coordinator, ownCoordinator = false,
  } = {}) {
    this.am = accountManager;
    this.intervalMs = clampInterval(intervalMs);
    this.probeFn = probeFn;
    this.codexProbeFn = codexProbeFn;
    this.profileFn = profileFn;
    this.backendFn = backendFn;
    this.timeoutMs = timeoutMs;
    this.log = log;
    if (!coordinator && !ownCoordinator) throw new Error('Prober requires a MaintenanceCoordinator');
    this.ownsCoordinator = !coordinator;
    this.coordinator = coordinator || new MaintenanceCoordinator(accountManager, { log });
    this.scheduleName = `quota-probe-${Math.random()}`;
    this._runPromise = null;
    this.lastRunStartedAt = null;
    this.lastRunFinishedAt = null;
    this.nextRunAt = this.intervalMs > 0 ? Date.now() + this.intervalMs : null;
    this.accountStatus = new Map();
  }

  start() { if (this.intervalMs > 0) this.reschedule(this.intervalMs, { immediate: true }); }

  /** @param {number} intervalMs @param {{ immediate?: boolean }} [options] */
  reschedule(intervalMs, { immediate } = {}) {
    const wasOn = this.intervalMs > 0;
    this.intervalMs = clampInterval(intervalMs);
    this.coordinator.unschedule(this.scheduleName);
    this.nextRunAt = this.intervalMs > 0 ? Date.now() + this.intervalMs : null;
    if (this.intervalMs > 0) {
      this.coordinator.schedule(this.scheduleName, this.intervalMs, () => this.probeAll(), { immediate: immediate ?? !wasOn });
      this.log(`[TeamClaude] Quota probe enabled (every ${Math.round(this.intervalMs / 1000)}s)`);
    } else if (wasOn) this.log('[TeamClaude] Quota probe disabled');
  }

  stop() {
    this.coordinator.unschedule(this.scheduleName);
    this.nextRunAt = null;
    if (this.ownsCoordinator) this.coordinator.shutdown();
  }

  async probeAll() {
    if (this._runPromise) return this._runPromise;
    this._runPromise = (async () => {
      this.lastRunStartedAt = Date.now();
      this.nextRunAt = this.intervalMs > 0 ? this.lastRunStartedAt + this.intervalMs : null;
      try {
        const accounts = this.am.accounts.filter(account => this._probeable(account) && this._isTarget(account));
        await Promise.all(accounts.map(account => this.coordinator.run(account, 'quota-probe', 30,
          signal => this.probeAccount(account, signal), { zeroSpend: true })));
      } finally {
        this.lastRunFinishedAt = Date.now();
        this._runPromise = null;
      }
    })();
    return this._runPromise;
  }

  _isProbeTarget(account) {
    return !!account && providerOf(account) === 'anthropic'
      && account.type === 'oauth' && !!account.credential && !account.upstream;
  }

  _isCodexProbeTarget(account) {
    return !!account && providerOf(account) === 'codex'
      && account.type === 'oauth' && !!account.credential && !!account.accountId && !account.upstream;
  }

  _isBackendTarget(account) { return !!account?.credential && hasBackendQuota(account); }
  _isTarget(account) { return this._isProbeTarget(account) || this._isCodexProbeTarget(account) || this._isBackendTarget(account); }

  _probeable(account) {
    if (!account?.credential) return false;
    if (account._deadRefreshToken && account._deadRefreshToken === account.refreshToken) return false;
    // Disabled means out of rotation, not out of monitoring. Never rotate its
    // OAuth lineage from a quota read; the separate keep-alive sweep owns that.
    if (account.disabled && account.type === 'oauth' && isTokenExpired(account.expiresAt)) return false;
    return true;
  }

  async probeAccount(account, signal) {
    if (!this._probeable(account) || !this._isTarget(account)) return false;
    const startedAt = Date.now();
    this._recordAccount(account, { status: 'running', startedAt });
    try {
      this._throwIfAborted(signal);
      let reading;
      if (this._isBackendTarget(account)) {
        reading = await this._withTimeout(probeSignal => this.backendFn(account, { timeoutMs: this.timeoutMs, signal: probeSignal }), signal);
      } else {
        if (!account.disabled) await this.am.ensureTokenFresh(account);
        this._throwIfAborted(signal);
        if (!this._probeable(account)) throw new Error('quota probe requires a live credential');
        const read = probeSignal => this._isCodexProbeTarget(account)
          ? this.codexProbeFn(account, { timeoutMs: this.timeoutMs, signal: probeSignal })
          : this.probeFn(account.credential, probeSignal);
        reading = await this._withTimeout(read, signal);
        if (reading?.status === 401 && !account.disabled) {
          const refreshed = await this.am.ensureTokenFresh(account, true);
          this._throwIfAborted(signal);
          if (refreshed?.ok && !refreshed.suppressed && this._probeable(account)) reading = await this._withTimeout(read, signal);
        }
      }
      this._throwIfAborted(signal);
      if (!reading || reading.error) {
        const finishedAt = Date.now();
        this._recordAccount(account, { status: reading?.error ? 'error' : 'timeout', error: reading?.error || 'probe timed out', startedAt, finishedAt, durationMs: finishedAt - startedAt });
        return false;
      }
      if (this._isBackendTarget(account)) this.am.applyBackendQuota(account, reading);
      else if (this._isCodexProbeTarget(account)) this.am.applyCodexUsageData(account, reading);
      else {
        this.am.applyUsageData(account, reading);
        const missingTier = !account.rateLimitTier && !account.seatTier
          && account.hasClaudeMax == null && account.hasClaudePro == null;
        if (missingTier && this.profileFn) {
          const profile = await this._withTimeout(probeSignal => this.profileFn(account.credential, probeSignal), signal);
          this.am.applyProfileData(account, profile);
        }
      }
      const finishedAt = Date.now();
      this._recordAccount(account, { status: 'ok', error: null, startedAt, finishedAt, durationMs: finishedAt - startedAt });
      return true;
    } catch (err) {
      const finishedAt = Date.now();
      this._recordAccount(account, { status: signal?.aborted ? 'cancelled' : 'error', error: signal?.aborted ? null : err?.message || String(err), startedAt, finishedAt, durationMs: finishedAt - startedAt });
      return false;
    }
  }

  getStatus() {
    return { enabled: this.intervalMs > 0, intervalSeconds: Math.round(this.intervalMs / 1000), running: !!this._runPromise,
      lastRunStartedAt: iso(this.lastRunStartedAt), lastRunFinishedAt: iso(this.lastRunFinishedAt), nextRunAt: iso(this.nextRunAt),
      accounts: this.am.accounts.map(account => {
        const status = this.accountStatus.get(account);
        return { name: account.name, status: this._isTarget(account) ? (status?.status || 'never') : 'not-applicable', lastProbedAt: iso(status?.finishedAt), startedAt: iso(status?.startedAt), durationMs: status?.durationMs ?? null, error: status?.error || null };
      }) };
  }

  _recordAccount(account, status) { this.accountStatus.set(account, { ...(this.accountStatus.get(account) || {}), ...status }); }
  _throwIfAborted(signal) { if (signal?.aborted) throw signal.reason || new Error('quota probe aborted'); }

  async _withTimeout(probe, parentSignal) {
    const controller = new AbortController();
    let timer;
    let settledByAbort = false;
    const abortSentinel = Symbol('quota probe aborted');
    let resolveAborted;
    const aborted = parentSignal && new Promise(resolve => { resolveAborted = resolve; });
    const abort = () => {
      settledByAbort = true;
      controller.abort(parentSignal.reason || new Error('quota probe aborted'));
      resolveAborted?.(abortSentinel);
    };
    if (parentSignal?.aborted) abort();
    else parentSignal?.addEventListener('abort', abort, { once: true });
    const probePromise = Promise.resolve().then(() => probe(controller.signal));
    const timeout = new Promise(resolve => {
      timer = setTimeout(() => { controller.abort(new Error(`quota probe timed out after ${this.timeoutMs}ms`)); resolve(null); }, this.timeoutMs);
      timer.unref?.();
    });
    try {
      const result = await Promise.race([probePromise, timeout, aborted].filter(Boolean));
      if (result !== null && result !== abortSentinel) return result;
      // Do not free the maintenance reservation while the cancelled I/O is live.
      await probePromise.catch(() => {});
      if (settledByAbort) this._throwIfAborted(parentSignal);
      return null;
    } finally {
      clearTimeout(timer);
      parentSignal?.removeEventListener('abort', abort);
    }
  }
}
function iso(ts) { return ts ? new Date(ts).toISOString() : null; }
