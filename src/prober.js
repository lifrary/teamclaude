// Zero-spend quota reads share maintenance scheduling, never inference admission.
import { fetchUsage, isTokenExpired } from './oauth.js';
import { MaintenanceCoordinator } from './maintenance-coordinator.js';
import { fetchBackendQuota, hasBackendQuota } from './backend-quota.js';
import { providerOf } from './provider.js';
import { fetchCodexUsage } from './codex-usage.js';

export const MAX_PROBE_INTERVAL_MS = 7 * 24 * 60 * 60 * 1000;
/** @param {number} ms */
function clampInterval(ms) { return ms > 0 ? Math.min(ms, MAX_PROBE_INTERVAL_MS) : 0; }

// A probe still unsettled this many read timeouts after it started is abandoned.
// Each read and each token refresh carries its own abort deadline, but
// _withTimeout then waits out the cancelled read with none, so a read whose
// transport ignores the abort holds the probe forever. On 2026-09-29 one probe
// never settled: its lane kept the account's slot and blocked its warm-ups, and
// the run it belonged to never finished, so no account was probed for eleven
// hours. Twelve leaves room for the slowest healthy probe (a read, a 30 s forced
// refresh, a re-read and a profile read) plus event-loop stalls.
const PROBE_DEADLINE_TIMEOUTS = 12;
// An abandoned probe is not waited for forever: a read whose transport ignored
// its abort may never settle at all. On 2026-10-06 the reads of all ten accounts
// hung that way, and because each account waited for its stuck read to come back
// before sending another, none was probed for 33 hours, although fresh reads
// worked at once (the restart that ended it probed all ten in under five
// seconds). So an account is tried again this many deadlines after its latest
// abandonment, and is left alone only once this many probes in a row were
// abandoned and are still out, which bounds what one stretch of a transport that
// never settles can leak. A probe that settles within its deadline ends the
// stretch.
const ABANDONED_RETRY_DEADLINES = 5;
const MAX_ABANDONED_PROBES = 3;
const ABANDONED = Symbol('abandoned');

/**
 * `promise`'s value, or `fallback` once `ms` pass first.
 * @template T, F
 * @param {Promise<T>} promise
 * @param {number} ms
 * @param {F} fallback
 * @returns {Promise<T|F>}
 */
function settleWithin(promise, ms, fallback) {
  /** @type {ReturnType<typeof setTimeout>|undefined} */
  let timer;
  const expiry = /** @type {Promise<F>} */ (new Promise(resolve => {
    timer = setTimeout(() => resolve(fallback), ms);
    timer.unref?.();
  }));
  return Promise.race([promise, expiry]).finally(() => clearTimeout(timer));
}

export class Prober {
  // `log` resolves the console per call rather than capturing it. A default
  // parameter is evaluated when the constructor runs, and the server builds its
  // prober in the same tick as `server.listen()` — before the listen callback
  // reaches `tui.start()`, which swaps `console.log` for the activity log. The
  // notices below are produced later still, by a reload that changes the probe
  // interval, so a captured `console.log` would put them on a terminal the
  // alternate screen has already covered.
  /**
   * @param {import('./account-manager.js').AccountManager} accountManager
   * @param {object} [options]
   * @param {number} [options.intervalMs]
   * @param {typeof fetchUsage} [options.probeFn] called as (credential, signal, routing)
   * @param {typeof fetchCodexUsage} [options.codexProbeFn]
   * @param {typeof import('./oauth.js').fetchProfile | null} [options.profileFn] called as (credential, signal, routing)
   * @param {typeof fetchBackendQuota} [options.backendFn]
   * @param {number} [options.timeoutMs]
   * @param {(...args: any[]) => void} [options.log]
   * @param {MaintenanceCoordinator} [options.coordinator]
   * @param {boolean} [options.ownCoordinator]
   * @param {() => number} [options.now] clock for the wait before an account whose probe was abandoned is tried again
   */
  constructor(accountManager, {
    intervalMs = 0, probeFn = fetchUsage, codexProbeFn = fetchCodexUsage,
    profileFn = null, backendFn = fetchBackendQuota, timeoutMs = 10_000,
    log = (/** @type {string} */ line) => console.log(line), coordinator, ownCoordinator = false,
    now = () => Date.now(),
  } = {}) {
    this.am = accountManager;
    this.intervalMs = clampInterval(intervalMs);
    this.probeFn = probeFn;
    this.codexProbeFn = codexProbeFn;
    this.profileFn = profileFn;
    this.backendFn = backendFn;
    this.timeoutMs = timeoutMs;
    this.log = log;
    this._now = now;
    if (!coordinator && !ownCoordinator) throw new Error('Prober requires a MaintenanceCoordinator');
    this.ownsCoordinator = !coordinator;
    this.coordinator = coordinator || new MaintenanceCoordinator(accountManager, { log });
    this.scheduleName = `quota-probe-${Math.random()}`;
    this._runPromise = null;
    this.lastRunStartedAt = null;
    this.lastRunFinishedAt = null;
    this.nextRunAt = this.intervalMs > 0 ? Date.now() + this.intervalMs : null;
    this.accountStatus = new Map();
    /** @type {Map<object, { at: number }[]>} account -> when each probe of its current stretch of abandonments was abandoned, oldest first, while that probe is still out */
    this._abandoned = new Map();
    // Orders an account's probes, so one abandoned earlier that settles after a
    // newer probe has started cannot overwrite the newer probe's record.
    this._probeSeq = 0;
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
        // Bounded twice: the probe itself (_probeWithDeadline), and the wait for a
        // lane some other maintenance holds, which a probe deadline cannot reach.
        // A job left waiting stays queued and coalesces with the next run's.
        const laneWaitMs = this._deadlineMs() * 2;
        await Promise.all(accounts.map(account => settleWithin(this.coordinator.run(account, 'quota-probe', 30,
          signal => this._probeWithDeadline(account, signal), { zeroSpend: true }), laneWaitMs, false)));
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

  _deadlineMs() { return this.timeoutMs * PROBE_DEADLINE_TIMEOUTS; }

  /**
   * probeAccount, abandoned once it outlives its deadline so the account's lane
   * and slot come back. The abandoned probe is left to settle on its own. The
   * account is tried again ABANDONED_RETRY_DEADLINES deadlines after its latest
   * abandonment whether or not that probe ever comes back, and is skipped
   * outright only once MAX_ABANDONED_PROBES probes in a row were abandoned and
   * are still out, so a read that never settles costs a bounded number of leaked
   * reads per stretch, never the account's monitoring for good. A probe that
   * settles within its deadline ends the stretch: the transport works again,
   * and reads abandoned before it stop counting. A probe abandoned in its token
   * refresh leaves the account's shared refresh pending, so a retry joins that
   * refresh and gets no further: it sends no read of its own when the token had
   * expired, and one read first when the hung refresh was forced by a 401. Three
   * such retries skip the account like any other stretch. Each skipped run says so
   * in the account's status rather than leaving an old result to age in silence.
   * @param {import('./account-manager.js').AccountManager['accounts'][number]} account
   * @param {AbortSignal} signal
   */
  async _probeWithDeadline(account, signal) {
    const outstanding = this._abandoned.get(account) || [];
    if (outstanding.length >= MAX_ABANDONED_PROBES) {
      this._recordAccount(account, { status: 'stalled',
        error: `${outstanding.length} probes in a row were abandoned since ${iso(outstanding[0].at)} and have not come back; skipped until one does or the proxy restarts` });
      return false;
    }
    const latest = outstanding[outstanding.length - 1];
    const retryAt = latest ? latest.at + this._deadlineMs() * ABANDONED_RETRY_DEADLINES : 0;
    if (this._now() < retryAt) {
      this._recordAccount(account, { status: 'stalled',
        error: `a probe abandoned at ${iso(latest.at)} has not come back; next try after ${iso(retryAt)}` });
      return false;
    }
    const probe = this.probeAccount(account, signal);
    const outcome = await settleWithin(probe, this._deadlineMs(), ABANDONED);
    if (outcome !== ABANDONED) {
      // Back in time, so the transport works: reads abandoned before this one
      // settle or leak on their own and no longer hold the account.
      this._abandoned.delete(account);
      return outcome;
    }
    const finishedAt = Date.now();
    const entry = { at: this._now() };
    // Re-read: an older abandoned probe may have settled during this one.
    this._abandoned.set(account, [...(this._abandoned.get(account) || []), entry]);
    const settled = () => {
      const left = (this._abandoned.get(account) || []).filter(other => other !== entry);
      if (left.length) this._abandoned.set(account, left);
      else this._abandoned.delete(account);
    };
    probe.then(settled, settled);
    const { startedAt, phase } = this.accountStatus.get(account) || {};
    const durationMs = startedAt ? finishedAt - startedAt : null;
    // Shutdown cancelled it and its read ignored the cancel: not a timeout.
    if (signal.aborted) {
      this._recordAccount(account, { status: 'cancelled', error: null, finishedAt, durationMs });
      return false;
    }
    const error = `quota probe abandoned after ${Math.round(this._deadlineMs() / 1000)}s in its ${phase || 'start'}`;
    this._recordAccount(account, { status: 'timeout', error, finishedAt, durationMs });
    this.log(`[TeamClaude] ${error} for "${account.name}"`);
    return false;
  }

  async probeAccount(account, signal) {
    if (!this._probeable(account) || !this._isTarget(account)) return false;
    const startedAt = Date.now();
    const seq = ++this._probeSeq;
    const record = (/** @type {Record<string, any>} */ status) => this._recordAccount(account, { ...status, seq });
    record({ status: 'running', startedAt, phase: 'start' });
    try {
      this._throwIfAborted(signal);
      let reading;
      if (this._isBackendTarget(account)) {
        record({ phase: 'usage read' });
        reading = await this._withTimeout(probeSignal => this.backendFn(account, { timeoutMs: this.timeoutMs, signal: probeSignal }), signal);
      } else {
        record({ phase: 'token refresh' });
        if (!account.disabled) await this.am.ensureTokenFresh(account);
        this._throwIfAborted(signal);
        if (!this._probeable(account)) throw new Error('quota probe requires a live credential');
        // The account's own egress proxy rides third: the injected probe
        // functions take the abort signal second (see oauth.js routingAndSignal).
        const read = probeSignal => this._isCodexProbeTarget(account)
          ? this.codexProbeFn(account, { timeoutMs: this.timeoutMs, signal: probeSignal })
          : this.probeFn(account.credential, probeSignal, account.routing ?? null);
        record({ phase: 'usage read' });
        reading = await this._withTimeout(read, signal);
        if (reading?.status === 401 && !account.disabled) {
          // Token rejected: force refresh and retry once — unless the manager
          // declined to renew a refresh token upstream already rejected.
          record({ phase: 'token refresh' });
          const refreshed = await this.am.ensureTokenFresh(account, true);
          this._throwIfAborted(signal);
          record({ phase: 'usage read' });
          if (refreshed?.ok && !refreshed.suppressed && this._probeable(account)) reading = await this._withTimeout(read, signal);
        }
      }
      this._throwIfAborted(signal);
      if (!reading || reading.error) {
        const finishedAt = Date.now();
        record({ status: reading?.error ? 'error' : 'timeout', error: reading?.error || 'probe timed out', startedAt, finishedAt, durationMs: finishedAt - startedAt });
        return false;
      }
      if (this._isBackendTarget(account)) this.am.applyBackendQuota(account, reading);
      else if (this._isCodexProbeTarget(account)) this.am.applyCodexUsageData(account, reading);
      else {
        this.am.applyUsageData(account, reading);
        const missingTier = !account.rateLimitTier && !account.seatTier
          && account.hasClaudeMax == null && account.hasClaudePro == null;
        if (missingTier && this.profileFn) {
          record({ phase: 'profile read' });
          const profile = await this._withTimeout(probeSignal => this.profileFn(account.credential, probeSignal, account.routing ?? null), signal);
          this.am.applyProfileData(account, profile);
        }
      }
      const finishedAt = Date.now();
      record({ status: 'ok', error: null, startedAt, finishedAt, durationMs: finishedAt - startedAt });
      return true;
    } catch (err) {
      const finishedAt = Date.now();
      record({ status: signal?.aborted ? 'cancelled' : 'error', error: signal?.aborted ? null : err?.message || String(err), startedAt, finishedAt, durationMs: finishedAt - startedAt });
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

  // A write from an older probe of the account is dropped: one abandoned earlier
  // that settles after a newer probe started must not overwrite that record.
  _recordAccount(account, status) {
    const current = this.accountStatus.get(account);
    if (status.seq != null && current?.seq != null && status.seq < current.seq) return;
    this.accountStatus.set(account, { ...(current || {}), ...status });
  }
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
      // Do not free the maintenance reservation while the cancelled I/O is live,
      // until the probe deadline gives up on it (see _probeWithDeadline).
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
