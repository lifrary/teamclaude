// Single owner for every background upstream-maintenance action.
// It serializes work per account, coalesces duplicate work deterministically, and
// takes the same AccountManager admission slot used by ordinary requests — except for
// a `zeroSpend` job, which prefers a slot but is not cancelled without one, because it
// sends no /v1/messages at all. See _drain.
/**
 * @typedef {import('./account-manager.js').AccountManager} AccountManager
 * @typedef {AccountManager['accounts'][number]} MaintenanceAccount
 * @typedef {boolean|void} MaintenanceResult
 * @typedef {(signal: AbortSignal) => MaintenanceResult|Promise<MaintenanceResult>} MaintenanceTask
 * @typedef {() => void|Promise<void|null>} ScheduleCallback
 * @typedef {{unref?: () => unknown}} TimerHandle
 * @typedef {{callback: ScheduleCallback, running: boolean, pending: boolean}} Schedule
 * @typedef {{kind: string, priority: number, task: MaintenanceTask, zeroSpend: boolean,
 * sequence: number, promise: Promise<MaintenanceResult>, resolve: (result: MaintenanceResult) => void}} Job
 * @typedef {{running: boolean, runningJobs: Map<string, Job>, pending: Map<string, Job>}} AccountJobs
 */
/**
 * @template {TimerHandle} T
 * @typedef {{setTimeoutFn: (callback: () => void, delay: number) => T,
 * clearTimeoutFn: (timer: T) => void}} TimerPair
 */
/**
 * @template {TimerHandle} [T=NodeJS.Timeout]
 * @typedef {TimerPair<T>|{setTimeoutFn?: undefined, clearTimeoutFn?: undefined}} TimerOptions
 */
export class MaintenanceCoordinator {
  /** @param {AccountManager} accountManager @param {{log?: (message: string) => void}} [options] */
  constructor(accountManager, { log = console.error } = {}) {
    this.accountManager = accountManager;
    this.log = log;
    this.closed = false;
    this.abortController = new AbortController();
    /** @type {Map<string, TimerHandle>} */
    this.timers = new Map();
    /** @type {Map<string, () => void>} */
    this.timerClearers = new Map();
    /** @type {Map<string, Schedule>} */
    this.schedules = new Map();
    /** @type {Map<MaintenanceAccount, AccountJobs>} */
    this.accounts = new Map();
    this.sequence = 0;
  }

  /** @param {string} name @param {number} intervalMs @param {ScheduleCallback} callback @param {{immediate?: boolean}} [options] */
  schedule(name, intervalMs, callback, { immediate = false } = {}) {
    this.unschedule(name);
    if (this.closed || !(intervalMs > 0)) return;
    const schedule = { callback, running: false, pending: false };
    this.schedules.set(name, schedule);
    if (immediate) Promise.resolve().then(() => this._requestScheduleRun(name, schedule));
    const timer = setInterval(() => this._requestScheduleRun(name, schedule), intervalMs);
    timer.unref?.();
    this.timers.set(name, timer);
    this.timerClearers.set(name, () => clearInterval(timer));
  }

  // Calendar/rolling maintenance uses one-shot timers but shares the same
  // shutdown, cancellation, and error handling as periodic maintenance.
  /**
   * @template {TimerHandle} T
   * @param {string} name
   * @param {number} delayMs
   * @param {ScheduleCallback} callback
   * @param {TimerOptions<T>} [options]
   * @returns {TimerHandle|null}
   */
  scheduleOnce(name, delayMs, callback, options = {}) {
    // Keep each timer factory paired with the clearer for its exact handle type.
    if (options.setTimeoutFn && options.clearTimeoutFn) {
      return this._scheduleOnce(name, delayMs, callback, {
        setTimeoutFn: options.setTimeoutFn, clearTimeoutFn: options.clearTimeoutFn,
      });
    }
    /** @type {TimerPair<NodeJS.Timeout>} */
    const nativeTimers = {
      setTimeoutFn: (fn, delay) => setTimeout(fn, delay),
      clearTimeoutFn: timer => clearTimeout(timer),
    };
    return this._scheduleOnce(name, delayMs, callback, nativeTimers);
  }

  /**
   * @template {TimerHandle} T
   * @param {string} name
   * @param {number} delayMs
   * @param {ScheduleCallback} callback
   * @param {TimerPair<T>} timers
   */
  _scheduleOnce(name, delayMs, callback, { setTimeoutFn, clearTimeoutFn }) {
    this.unschedule(name);
    if (this.closed || !Number.isFinite(delayMs) || delayMs < 0) return null;
    const timer = setTimeoutFn(async () => {
      if (this.closed || this.timers.get(name) !== timer) return;
      this.timers.delete(name);
      this.timerClearers.delete(name);
      await this._invoke(callback);
    }, Math.min(delayMs, 2 ** 31 - 1));
    timer.unref?.();
    this.timers.set(name, timer);
    this.timerClearers.set(name, () => clearTimeoutFn(timer));
    return timer;
  }

  /** @param {string} name */
  unschedule(name) {
    const timer = this.timers.get(name);
    if (timer != null) this.timerClearers.get(name)?.();
    this.timers.delete(name);
    this.timerClearers.delete(name);
    this.schedules.delete(name);
  }

  // Queue one targeted upstream operation.  A later request for the same kind is
  // coalesced; different kinds are ordered by priority then insertion order.
  // `zeroSpend` declares that the task sends no /v1/messages request (today: the
  // /api/oauth/usage quota read).  Such work still takes an admission slot when one
  // is free, but is not cancelled when the account cannot give it one.  See _drain.
  /**
   * @param {MaintenanceAccount|null|undefined} account
   * @param {string} kind
   * @param {number} priority
   * @param {MaintenanceTask} task
   * @param {{zeroSpend?: boolean}} [options]
   * @returns {Promise<MaintenanceResult>}
   */
  run(account, kind, priority, task, { zeroSpend = false } = {}) {
    if (this.closed || !account || this.abortController.signal.aborted) return Promise.resolve(false);
    let state = this.accounts.get(account);
    if (!state) {
      state = { running: false, runningJobs: new Map(), pending: new Map() };
      this.accounts.set(account, state);
    }
    const existing = state.runningJobs.get(kind) || state.pending.get(kind);
    if (existing) return existing.promise;
    /** @type {(result: MaintenanceResult) => void} */
    let resolve;
    /** @type {Promise<MaintenanceResult>} */
    const promise = new Promise(r => {
      resolve = r;
    });
    // The Promise executor runs synchronously; enqueue with its captured resolver.
    state.pending.set(kind, { kind, priority, task, zeroSpend, sequence: this.sequence++, promise,
      resolve: result => resolve(result) });
    this._drain(account, state);
    return promise;
  }

  /** @param {MaintenanceAccount} account @param {AccountJobs} state */
  async _drain(account, state) {
    if (state.running) return;
    state.running = true;
    try {
      while (!this.closed && state.pending.size) {
        const job = [...state.pending.values()].sort((a, b) => a.priority - b.priority || a.sequence - b.sequence)[0];
        state.pending.delete(job.kind);
        state.runningJobs.set(job.kind, job);
        let reserved = null;
        try {
          // Maintenance never gets an extra slot. Pinning preserves the caller's
          // target while acquireAccount remains the canonical cap/admission gate.
          reserved = await this.accountManager.acquireAccount(
            null, 0, this.abortController.signal, null,
            { pinnedAccount: account, revalidate: true },
          );
          // A null reservation means acquireAccount refused the pinned account for ANY
          // reason — disabled, throttled, parked, over threshold, or merely capped. For
          // zero-spend work that refusal is the wrong answer: those are exactly the
          // accounts whose quota there is no other cheap way to re-read, so gating on it
          // silently disabled the probe precisely where it earns its keep (measured
          // 2026-07-30: 0 of 6 accounts probed across 30min of live uptime). Liveness is
          // the only requirement left; a slot is still taken when one is free, so
          // `inflight` never exceeds `maxConcurrent` either way.
          const runnable = reserved === account
            || (job.zeroSpend && this.accountManager.accounts.includes(account));
          if (!runnable || this.closed) {
            job.resolve(false);
            continue;
          }
          job.resolve(await job.task(this.abortController.signal));
        } catch (err) {
          if (!this.abortController.signal.aborted) this.log(`[TeamClaude] Maintenance ${job.kind} failed for "${account.name}": ${err instanceof Error ? err.message : String(err)}`);
          job.resolve(false);
        } finally {
          state.runningJobs.delete(job.kind);
          if (reserved) this.accountManager.releaseAccount(reserved);
        }
      }
    } finally {
      state.running = false;
      if (!state.pending.size) this.accounts.delete(account);
    }
  }

  /** @param {string} name @param {Schedule} schedule */
  _requestScheduleRun(name, schedule) {
    if (this.closed || this.schedules.get(name) !== schedule) return;
    if (schedule.running) {
      schedule.pending = true;
      return;
    }
    schedule.running = true;
    Promise.resolve().then(async () => {
      if (this.closed || this.schedules.get(name) !== schedule) return;
      await this._invoke(schedule.callback);
    }).finally(() => {
      schedule.running = false;
      if (schedule.pending && !this.closed && this.schedules.get(name) === schedule) {
        schedule.pending = false;
        this._requestScheduleRun(name, schedule);
      }
    });
  }

  /** @param {ScheduleCallback} callback */
  async _invoke(callback) {
    if (this.closed) return;
    try { await callback(); } catch (err) {
      if (!this.abortController.signal.aborted) this.log(`[TeamClaude] Maintenance schedule failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  shutdown() {
    if (this.closed) return;
    this.closed = true;
    this.abortController.abort();
    for (const name of this.timers.keys()) this.unschedule(name);
    this.schedules.clear();
    for (const state of this.accounts.values()) {
      for (const job of state.pending.values()) job.resolve(false);
      state.pending.clear();
    }
  }
}
