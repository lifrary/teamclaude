// Zero-spend quota probe adapter. Scheduling and admission are owned by a
// MaintenanceCoordinator; this class only describes the quota-probe task.
import { fetchUsage } from './oauth.js';
import { MaintenanceCoordinator } from './maintenance-coordinator.js';

export class Prober {
  constructor(accountManager, {
    intervalMs = 0, probeFn = fetchUsage, timeoutMs = 10_000, log = console.log, coordinator, ownCoordinator = false,
  } = {}) {
    this.am = accountManager;
    this.intervalMs = intervalMs;
    this.probeFn = probeFn;
    this.timeoutMs = timeoutMs;
    this.log = log;
    if (!coordinator && !ownCoordinator) throw new Error('Prober requires a MaintenanceCoordinator');
    this.ownsCoordinator = !coordinator;
    this.coordinator = coordinator || new MaintenanceCoordinator(accountManager, { log });
    this.scheduleName = `quota-probe-${Math.random()}`;
    this._runPromise = null;
    this.lastRunStartedAt = null;
    this.lastRunFinishedAt = null;
    this.nextRunAt = intervalMs > 0 ? Date.now() + intervalMs : null;
    this.accountStatus = new Map();
  }

  // Probe once right away, then on the interval. Without the explicit flag this could
  // never happen: the constructor has already stored intervalMs, so reschedule() sees
  // wasOn === true and its !wasOn default suppresses the immediate run — meaning every
  // restart left quota unread for a full interval, exactly when the values restored
  // from disk are least trustworthy.
  start() { if (this.intervalMs > 0) this.reschedule(this.intervalMs, { immediate: true }); }

  reschedule(intervalMs, { immediate } = {}) {
    const wasOn = this.intervalMs > 0;
    this.intervalMs = intervalMs;
    this.coordinator.unschedule(this.scheduleName);
    if (intervalMs > 0) {
      this.nextRunAt = Date.now() + intervalMs;
      this.coordinator.schedule(this.scheduleName, intervalMs, () => this.probeAll(), { immediate: immediate ?? !wasOn });
      this.log(`[TeamClaude] Quota probe enabled (every ${Math.round(intervalMs / 1000)}s)`);
    } else if (wasOn) {
      this.nextRunAt = null;
      this.log('[TeamClaude] Quota probe disabled');
    }
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
        const accounts = this.am.accounts.filter(account => account.type === 'oauth' && account.credential);
        // zeroSpend: the usage endpoint is a read, not an inference — see _drain for
        // what the coordinator does with that.
        await Promise.all(accounts.map(account => this.coordinator.run(account, 'quota-probe', 30,
          signal => this.probeAccount(account, signal), { zeroSpend: true })));
      } finally {
        this.lastRunFinishedAt = Date.now();
        this._runPromise = null;
      }
    })();
    return this._runPromise;
  }

  async probeAccount(account, signal) {
    const startedAt = Date.now();
    this._recordAccount(account, { status: 'running', startedAt });
    try {
      await this.am.ensureTokenFresh(account.index);
      this._throwIfAborted(signal);
      let usage = await this._withTimeout(probeSignal => this.probeFn(account.credential, probeSignal), signal);
      if (usage?.status === 401) {
        const refreshed = await this.am.ensureTokenFresh(account.index, true);
        this._throwIfAborted(signal);
        // A floor-suppressed forced refresh minted no new token — re-probing
        // with the same credential is guaranteed to repeat the 401.
        if (!refreshed?.suppressed) {
          usage = await this._withTimeout(probeSignal => this.probeFn(account.credential, probeSignal), signal);
        }
      }
      const finishedAt = Date.now();
      if (!usage || usage.error) {
        this._recordAccount(account, { status: usage?.error ? 'error' : 'timeout', error: usage?.error || 'probe timed out', startedAt, finishedAt, durationMs: finishedAt - startedAt });
        return false;
      }
      this.am.applyUsageData(account.index, usage);
      this._recordAccount(account, { status: 'ok', error: null, startedAt, finishedAt, durationMs: finishedAt - startedAt });
      return true;
    } catch (err) {
      const finishedAt = Date.now();
      if (signal?.aborted) {
        this._recordAccount(account, { status: 'cancelled', error: null, startedAt, finishedAt, durationMs: finishedAt - startedAt });
      } else {
        this._recordAccount(account, { status: 'error', error: err?.message || String(err), startedAt, finishedAt, durationMs: finishedAt - startedAt });
      }
      return false;
    }
  }

  getStatus() {
    return { enabled: this.intervalMs > 0, intervalSeconds: Math.round(this.intervalMs / 1000), running: !!this._runPromise,
      lastRunStartedAt: iso(this.lastRunStartedAt), lastRunFinishedAt: iso(this.lastRunFinishedAt), nextRunAt: iso(this.nextRunAt),
      accounts: this.am.accounts.map(account => {
        const status = this.accountStatus.get(account.name);
        return { name: account.name, status: account.type === 'oauth' ? (status?.status || 'never') : 'not-applicable', lastProbedAt: iso(status?.finishedAt), startedAt: iso(status?.startedAt), durationMs: status?.durationMs ?? null, error: status?.error || null };
      }) };
  }

  _recordAccount(account, status) { this.accountStatus.set(account.name, { ...(this.accountStatus.get(account.name) || {}), ...status }); }

  _throwIfAborted(signal) {
    if (signal?.aborted) throw signal.reason || new Error('quota probe aborted');
  }

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
      timer = setTimeout(() => {
        controller.abort(new Error(`quota probe timed out after ${this.timeoutMs}ms`));
        resolve(null);
      }, this.timeoutMs);
      timer.unref?.();
    });

    try {
      const result = await Promise.race([probePromise, timeout, aborted].filter(Boolean));
      if (result !== null && result !== abortSentinel) return result;
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
