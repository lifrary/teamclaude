// Message-spending keep-warm adapter. Its coordinator owns timers, aborting,
// per-account serialization, and AccountManager capacity admission.
import { spawn } from 'node:child_process';
import { MaintenanceCoordinator } from './maintenance-coordinator.js';
import { accountIdKey } from './identity.js';
import { providerOf } from './provider.js';
import {
  ROLLING_NEAR_RESET_TOLERANCE_MS,
  ROLLING_POST_RESET_BUFFER_MS,
  resolveWarmupSchedule,
} from './warmup-schedule.js';

const SCHEDULE_TIMER_GRACE_MS = 60_000;

/**
 * @typedef {import('./maintenance-coordinator.js').MaintenanceAccount} WarmAccount
 * @typedef {import('./maintenance-coordinator.js').TimerHandle} TimerHandle
 * @typedef {{resetTime: string, timezone: string, mode?: string, anchorResetAt?: string}} WarmupSchedule
 * @typedef {ReturnType<typeof resolveWarmupSchedule>} ScheduleStatus
 * @typedef {{command: string, args: string[], env: NodeJS.ProcessEnv, timeoutMs: number, signal?: AbortSignal}} SpawnSpec
 * @typedef {{status: 'running'|'ok'|'error'|'cancelled'|'timeout', startedAt: number,
 * finishedAt?: number, durationMs?: number, error?: string|null}} WarmStatus
 */
/**
 * @typedef {object} WarmerOptions
 * @property {number} [intervalMs]
 * @property {WarmupSchedule|null} [schedule]
 * @property {number} [port]
 * @property {string|null} [apiKey]
 * @property {string} [model]
 * @property {string} [prompt]
 * @property {(spec: SpawnSpec) => Promise<number>|number} [spawnFn]
 * @property {number} [timeoutMs]
 * @property {(message: string) => void} [log]
 * @property {() => number} [nowFn]
 * @property {MaintenanceCoordinator} [coordinator]
 * @property {boolean} [ownCoordinator]
 */
/** @template {TimerHandle} [T=NodeJS.Timeout] */
export class Warmer {
  /**
   * @param {import('./account-manager.js').AccountManager} accountManager
   * @param {WarmerOptions & import('./maintenance-coordinator.js').TimerOptions<T>} [opts]
   */
  constructor(accountManager, opts = {}) {
    const {
      intervalMs = 0,
      schedule = null,
      port,
      apiKey = null,
      model = 'haiku',
      prompt = 'hi',
      spawnFn = defaultSpawn,
      timeoutMs = 120_000,
      log = console.log,
      nowFn = Date.now,
      coordinator, ownCoordinator = false,
    } = opts;
    this.am = accountManager;
    this.intervalMs = intervalMs;
    this.schedule = schedule;
    this.port = port;
    this.apiKey = apiKey;
    this.model = model;
    this.prompt = prompt;
    this.spawnFn = spawnFn;
    this.timeoutMs = timeoutMs;
    this.log = log;
    if (!coordinator && !ownCoordinator) throw new Error('Warmer requires a MaintenanceCoordinator');
    this.ownsCoordinator = !coordinator;
    this.coordinator = coordinator || new MaintenanceCoordinator(accountManager, { log });
    this.scheduleName = `keep-warm-${Math.random()}`;
    this.nowFn = nowFn;
    /** @type {import('./maintenance-coordinator.js').TimerOptions<T>} */
    this.timerOptions = opts.setTimeoutFn
      ? { setTimeoutFn: opts.setTimeoutFn, clearTimeoutFn: opts.clearTimeoutFn }
      : {};
    /** @type {TimerHandle|null} */
    this.timer = null;
    this._stopped = false;
    this._scheduleGeneration = 0;
    this._running = false;
    /** @type {Promise<void>|null} */
    this._runFinished = null;
    /** @type {AbortController|null} */
    this._abort = null; // AbortController for the in-flight sweep (see warmAll/stop)
    /** @type {Map<WarmAccount, TimerHandle|null>} */
    this._deferredWarmups = new Map();
    /** @type {number|null} */
    this.lastRunStartedAt = null;
    /** @type {number|null} */
    this.lastRunFinishedAt = null;
    this.nextRunAt = intervalMs > 0 ? this.nowFn() + intervalMs : null;
    /** @type {ScheduleStatus|null} */
    this.scheduleStatus = null;
    /** @type {Map<string, WarmStatus>} */
    this.accountStatus = new Map();
  }

  start() {
    this._stopped = false;
    if (this.schedule) this.rescheduleSchedule(this.schedule);
    else if (this.intervalMs > 0) this.reschedule(this.intervalMs);
  }

  /** Change interval at runtime (0 = off). Warms once immediately when turned on.
   * @param {number} intervalMs */
  reschedule(intervalMs) {
    // A configured interval is already on at startup: never spend at boot.
    const wasOn = !this.schedule && this.intervalMs > 0;
    this._scheduleGeneration += 1;
    this._stopped = false;
    this.schedule = null;
    this.scheduleStatus = null;
    this.intervalMs = intervalMs;
    this.coordinator.unschedule(this.scheduleName);
    this.timer = null;
    this._clearDeferredWarmups();
    this._abort?.abort();

    if (intervalMs > 0) {
      this.nextRunAt = this.nowFn() + intervalMs;
      // Immediate sweep only on an off→on transition. Re-running it on every
      // interval *change* would spend quota each time the interval is edited.
      this.coordinator.schedule(this.scheduleName, intervalMs, () => this.warmAll(), { immediate: !wasOn });
      this.log(`[TeamClaude] Keep-warm enabled (every ${Math.round(intervalMs / 1000)}s)`);
    } else if (wasOn) {
      this.nextRunAt = null;
      this.log('[TeamClaude] Keep-warm disabled');
    }
  }

  /** Change to a reset-target schedule without replaying missed runs.
   * @param {WarmupSchedule|null} schedule */
  rescheduleSchedule(schedule) {
    const scheduleStatus = schedule ? resolveWarmupSchedule(schedule, this.nowFn()) : null;
    const generation = ++this._scheduleGeneration;
    this._stopped = false;
    this.intervalMs = 0;
    this.schedule = schedule;
    this.coordinator.unschedule(this.scheduleName);
    this.timer = null;
    this._clearDeferredWarmups();
    this._abort?.abort();
    if (!schedule) {
      this.scheduleStatus = null;
      this.nextRunAt = null;
      return;
    }
    this._armSchedule(generation, scheduleStatus);
  }

  /** @param {number} generation @param {ScheduleStatus|null} [scheduleStatus] */
  _armSchedule(generation, scheduleStatus = null) {
    if (generation !== this._scheduleGeneration || this._stopped || !this.schedule) return;
    this.scheduleStatus = scheduleStatus || resolveWarmupSchedule(this.schedule, this.nowFn());
    this.nextRunAt = Date.parse(this.scheduleStatus.nextWarmupAt);
    const delay = Math.max(0, this.nextRunAt - this.nowFn());
    const intendedAt = this.nextRunAt;
    const timer = this.coordinator.scheduleOnce(this.scheduleName, delay, async () => {
      if (generation !== this._scheduleGeneration || this._stopped || !this.schedule) return;
      if (this.timer === timer) this.timer = null;
      const firedAt = this.nowFn();
      if (firedAt < intendedAt || firedAt >= intendedAt + SCHEDULE_TIMER_GRACE_MS) {
        this._armSchedule(generation);
        return;
      }
      await this.warmAll();
      if (generation === this._scheduleGeneration && !this._stopped && this.schedule) {
        this._armSchedule(generation);
      }
    }, this.timerOptions);
    this.timer = timer;
    this.log(`[TeamClaude] Keep-warm scheduled for ${this.scheduleStatus.nextWarmupAt}`);
  }

  stop() {
    this._scheduleGeneration += 1;
    this._stopped = true;
    this.timer = null;
    this._clearDeferredWarmups();
    this.coordinator.unschedule(this.scheduleName);
    this._abort?.abort();
    this.nextRunAt = null;
    if (this.ownsCoordinator) this.coordinator.shutdown();
  }

  /**
   * True when `account` is a healthy, idle Anthropic OAuth account whose 5h
   * window is NOT already running. We skip:
   *  - non-OAuth and third-party-backend accounts (`upstream` set) — the 5h
   *    concept is Anthropic-specific;
   *  - disabled / errored / exhausted / throttled accounts — warming them is
   *    pointless or would just 429;
   *  - accounts with a live 5h window — already warm, so warming again only burns
   *    quota for nothing.
   * @param {WarmAccount} account
   */
  _isWarmCandidate(account) {
    if (providerOf(account) !== 'anthropic') return false;
    if (!this.am.accounts.includes(account)) return false;
    if (account.type !== 'oauth' || !account.credential) return false;
    if (account.upstream) return false;
    if (account.disabled) return false;
    if (account.status === 'error' || account.status === 'exhausted' || account.status === 'throttled') return false;
    return true;
  }

  /** @param {WarmAccount} account @param {number} [now] */
  _isWarmTarget(account, now = this.nowFn()) {
    if (!this._isWarmCandidate(account)) return false;
    const reset = account.quota?.unified5hReset;
    return !(reset && now < reset); // a future reset ⇒ session already running
  }

  async warmAll() {
    if (this._running) return this._runFinished;
    const now = this.nowFn();
    const generation = this._scheduleGeneration;
    const targets = [];
    const deferred = [];
    for (const account of this.am.accounts) {
      if (!this._isWarmCandidate(account)) continue;
      const resetAt = Number(account.quota?.unified5hReset);
      const resetRemaining = resetAt - now;
      if (this.schedule?.mode === 'rolling'
        && Number.isFinite(resetAt)
        && resetRemaining > 0
        && resetRemaining <= ROLLING_NEAR_RESET_TOLERANCE_MS) {
        deferred.push({ account, runAt: resetAt + ROLLING_POST_RESET_BUFFER_MS });
      } else if (this._isWarmTarget(account, now)) {
        targets.push(account);
      }
    }

    await this._warmTargets(targets, { generation });
    for (const item of deferred) {
      this._deferWarmAccount(item.account, item.runAt, generation);
    }
  }

  /** @param {WarmAccount[]} targets @param {{generation?: number, waitForRunning?: boolean, deadline?: number|null}} [options] */
  async _warmTargets(targets, {
    generation = this._scheduleGeneration,
    waitForRunning = false,
    deadline = null,
  } = {}) {
    while (this._running) {
      if (!waitForRunning) return false;
      await this._runFinished;
    }
    if (generation !== this._scheduleGeneration || this._stopped) return false;
    if (deadline !== null && this.nowFn() >= deadline) return false;
    this._running = true;
    /** @type {() => void} */
    let finishRun = () => {};
    /** @type {Promise<void>} */
    const runFinished = new Promise(resolve => { finishRun = resolve; });
    this._runFinished = runFinished;
    const abort = this._abort = new AbortController();
    const parentSignal = this.coordinator.abortController.signal;
    const onAbort = () => abort.abort(parentSignal.reason);
    if (parentSignal.aborted) onAbort();
    else parentSignal.addEventListener('abort', onAbort, { once: true });
    this.lastRunStartedAt = this.nowFn();
    if (this.intervalMs > 0) this.nextRunAt = this.lastRunStartedAt + this.intervalMs;
    try {
      for (const account of targets) {
        const canContinue = () => generation === this._scheduleGeneration
          && !this._stopped
          && (deadline === null || this.nowFn() < deadline);
        if (abort.signal.aborted || !canContinue()) break;
        const isStillEligible = () => this._isWarmTarget(account);
        if (!isStillEligible()) continue;
        await this.coordinator.run(account, 'keep-warm', 40, () => {
          if (abort.signal.aborted || !canContinue() || !isStillEligible()) return false;
          return this.warmAccount(account, abort.signal, canContinue, isStillEligible);
        });
      }
      return true;
    } finally {
      parentSignal.removeEventListener('abort', onAbort);
      this.lastRunFinishedAt = this.nowFn();
      this._running = false;
      if (this._abort === abort) this._abort = null;
      if (this._runFinished === runFinished) this._runFinished = null;
      finishRun();
    }
  }

  /** @param {WarmAccount} account @param {number} runAt @param {number} generation */
  _deferWarmAccount(account, runAt, generation) {
    if (generation !== this._scheduleGeneration || this._stopped || this.schedule?.mode !== 'rolling') return;
    if (this._deferredWarmups.has(account)) return;
    const delay = Math.max(0, runAt - this.nowFn());
    const name = `${this.scheduleName}:${accountIdKey(account)}`;
    const timer = this.coordinator.scheduleOnce(name, delay, async () => {
      if (this._deferredWarmups.get(account) === timer) this._deferredWarmups.delete(account);
      if (generation !== this._scheduleGeneration || this._stopped || this.schedule?.mode !== 'rolling') return;
      const remaining = runAt - this.nowFn();
      if (remaining > 0) {
        this._deferWarmAccount(account, runAt, generation);
        return;
      }
      const deadline = runAt + SCHEDULE_TIMER_GRACE_MS;
      if (this.nowFn() >= deadline) return;
      if (!this._isWarmTarget(account)) return;
      await this._warmTargets([account], {
        generation,
        waitForRunning: true,
        deadline,
      });
    }, this.timerOptions);
    this._deferredWarmups.set(account, timer);
    this.log(`[TeamClaude] Keep-warm delaying "${account.name}" until ${new Date(runAt).toISOString()} (5h reset within 2m)`);
  }

  _clearDeferredWarmups() {
    for (const account of this._deferredWarmups.keys()) this.coordinator.unschedule(`${this.scheduleName}:${accountIdKey(account)}`);
    this._deferredWarmups.clear();
  }

  /** @param {WarmAccount} account @param {AbortSignal} [signal] @param {() => boolean} [shouldContinue] @param {() => boolean} [isStillEligible] */
  async warmAccount(account, signal, shouldContinue = () => true, isStillEligible = () => true) {
    const startedAt = Date.now();
    const previousStatus = this.accountStatus.get(account.name);
    this._record(account, { status: 'running', startedAt });
    try {
      await this.am.ensureTokenFresh(account);
      if (signal?.aborted || !shouldContinue()) {
        if (previousStatus) this.accountStatus.set(account.name, previousStatus);
        else this.accountStatus.delete(account.name);
        return;
      }
      if (account.status === 'error') {
        const finishedAt = Date.now();
        this._record(account, {
          status: 'error',
          error: 'token refresh rejected; re-login required',
          startedAt, finishedAt, durationMs: finishedAt - startedAt,
        });
        return;
      }
      if (!isStillEligible()) {
        if (previousStatus) this.accountStatus.set(account.name, previousStatus);
        else this.accountStatus.delete(account.name);
        return;
      }
      const code = await this.spawnFn(this._spawnSpec(account, signal));
      const finishedAt = Date.now();
      this._record(account, { status: code === 0 ? 'ok' : 'error', error: code === 0 ? null : `claude exited ${code}`, startedAt, finishedAt, durationMs: finishedAt - startedAt });
      return code === 0;
    } catch (err) {
      const finishedAt = Date.now();
      if (signal?.aborted) {
        this._record(account, { status: 'cancelled', error: null, startedAt, finishedAt, durationMs: finishedAt - startedAt });
      } else if (isTimeoutError(err)) {
        this._record(account, { status: 'timeout', error: err.message, startedAt, finishedAt, durationMs: finishedAt - startedAt });
      } else {
        this._record(account, { status: 'error', error: err instanceof Error ? err.message : String(err), startedAt, finishedAt, durationMs: finishedAt - startedAt });
      }
      return false;
    }
  }

  /** @param {WarmAccount} account @param {AbortSignal} [signal] @returns {SpawnSpec} */
  _spawnSpec(account, signal) {
    // Canonical pins qualify both provider and organization, never array position.
    const pin = encodeURIComponent(accountIdKey(account));
    const baseUrl = `http://127.0.0.1:${this.port}/tc-acct/${pin}`;
    return {
      command: 'claude',
      // `--bare -p`: minimal, non-interactive, auth strictly via ANTHROPIC_API_KEY
      // (which this proxy strips and replaces with the pinned account's token).
      args: ['-p', '--bare', '--model', this.model, '--output-format', 'text', this.prompt],
      env: {
        ...process.env,
        ANTHROPIC_BASE_URL: baseUrl,
        ANTHROPIC_API_KEY: this.apiKey || 'tc-warm',
      },
      timeoutMs: this.timeoutMs,
      signal, // aborts (and kills the child) when the warmer is stopped
    };
  }

  getStatus() {
    const schedule = this.scheduleStatus || null;
    return {
      intervalSeconds: Math.round(this.intervalMs / 1000),
      ...(schedule || {
        enabled: !!this.schedule || this.intervalMs > 0,
        mode: this.schedule ? 'reset' : (this.intervalMs > 0 ? 'interval' : 'off'),
      }),
      running: this._running,
      lastRunStartedAt: iso(this.lastRunStartedAt),
      lastRunFinishedAt: iso(this.lastRunFinishedAt),
      nextRunAt: iso(this.nextRunAt),
      accounts: this.am.accounts.map(account => {
        const status = this.accountStatus.get(account.name);
        const applicable = providerOf(account) === 'anthropic' && account.type === 'oauth' && !account.upstream;
        return {
          name: account.name,
          status: applicable ? (status?.status || 'never') : 'not-applicable',
          lastWarmedAt: iso(status?.finishedAt),
          startedAt: iso(status?.startedAt),
          durationMs: status?.durationMs ?? null,
          error: status?.error || null,
        };
      }),
    };
  }

  /** @param {WarmAccount} account @param {WarmStatus} status */
  _record(account, status) {
    this.accountStatus.set(account.name, {
      ...(this.accountStatus.get(account.name) || {}),
      ...status,
    });
  }
}

/** @param {SpawnSpec} spec @returns {Promise<number>} */
function defaultSpawn({ command, args, env, timeoutMs, signal }) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(new Error('warm-up aborted')); return; }
    let child;
    try { child = spawn(command, args, { env, stdio: 'ignore' }); } catch (err) { reject(err); return; }
    const onAbort = () => child.kill('SIGKILL');
    signal?.addEventListener('abort', onAbort, { once: true });
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error(`warm-up timed out after ${timeoutMs}ms`)); }, timeoutMs);
    timer.unref?.();
    const cleanup = () => { clearTimeout(timer); signal?.removeEventListener('abort', onAbort); };
    child.once('error', err => { cleanup(); reject(err); });
    child.once('exit', (code, sigName) => { cleanup(); if (sigName) reject(new Error(`claude terminated by ${sigName}`)); else resolve(code ?? 0); });
  });
}
/** @param {unknown} err @returns {err is {message: string}} */
function isTimeoutError(err) {
  return typeof err === 'object' && err !== null
    && 'message' in err && typeof err.message === 'string'
    && (('name' in err && err.name === 'TimeoutError') || /warm-up timed out/.test(err.message));
}

/** @param {number|null|undefined} ts */
function iso(ts) { return ts ? new Date(ts).toISOString() : null; }
