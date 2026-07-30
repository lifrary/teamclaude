// Single owner for every background upstream-maintenance action.
// It serializes work per account, coalesces duplicate work deterministically, and
// takes the same AccountManager admission slot used by ordinary requests.
export class MaintenanceCoordinator {
  constructor(accountManager, { log = console.error } = {}) {
    this.accountManager = accountManager;
    this.log = log;
    this.closed = false;
    this.abortController = new AbortController();
    this.timers = new Map();
    this.schedules = new Map();
    this.accounts = new Map();
    this.sequence = 0;
  }

  schedule(name, intervalMs, callback, { immediate = false } = {}) {
    this.unschedule(name);
    if (this.closed || !(intervalMs > 0)) return;
    const schedule = { callback, running: false, pending: false };
    this.schedules.set(name, schedule);
    if (immediate) Promise.resolve().then(() => this._requestScheduleRun(name, schedule));
    const timer = setInterval(() => this._requestScheduleRun(name, schedule), intervalMs);
    timer.unref?.();
    this.timers.set(name, timer);
  }

  unschedule(name) {
    const timer = this.timers.get(name);
    if (timer) clearInterval(timer);
    this.timers.delete(name);
    this.schedules.delete(name);
  }

  // Queue one targeted upstream operation.  A later request for the same kind is
  // coalesced; different kinds are ordered by priority then insertion order.
  // `zeroSpend` declares that the task sends no /v1/messages request (today: the
  // /api/oauth/usage quota read).  Such work still takes an admission slot when one
  // is free, but is not cancelled when the account cannot give it one.  See _drain.
  run(account, kind, priority, task, { zeroSpend = false } = {}) {
    if (this.closed || !account || this.abortController.signal.aborted) return Promise.resolve(false);
    let state = this.accounts.get(account);
    if (!state) {
      state = { running: false, runningJobs: new Map(), pending: new Map() };
      this.accounts.set(account, state);
    }
    const existing = state.runningJobs.get(kind) || state.pending.get(kind);
    if (existing) return existing.promise;
    let resolve;
    const promise = new Promise(r => { resolve = r; });
    state.pending.set(kind, { kind, priority, task, zeroSpend, sequence: this.sequence++, promise, resolve });
    this._drain(account, state);
    return promise;
  }

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
          if (!this.abortController.signal.aborted) this.log(`[TeamClaude] Maintenance ${job.kind} failed for "${account.name}": ${err.message}`);
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

  async _invoke(callback) {
    if (this.closed) return;
    try { await callback(); } catch (err) {
      if (!this.abortController.signal.aborted) this.log(`[TeamClaude] Maintenance schedule failed: ${err.message}`);
    }
  }

  shutdown() {
    if (this.closed) return;
    this.closed = true;
    this.abortController.abort();
    for (const timer of this.timers.values()) clearInterval(timer);
    this.timers.clear();
    this.schedules.clear();
    for (const state of this.accounts.values()) {
      for (const job of state.pending.values()) job.resolve(false);
      state.pending.clear();
    }
  }
}
