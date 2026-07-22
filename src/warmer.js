// Message-spending keep-warm adapter. Its coordinator owns timers, aborting,
// per-account serialization, and AccountManager capacity admission.
import { spawn } from 'node:child_process';
import { MaintenanceCoordinator } from './maintenance-coordinator.js';
import { accountIdKey } from './identity.js';

export class Warmer {
  constructor(accountManager, {
    intervalMs = 0, port, apiKey = null, model = 'haiku', prompt = 'hi', spawnFn = defaultSpawn,
    timeoutMs = 120_000, log = console.log, coordinator, ownCoordinator = false,
  } = {}) {
    this.am = accountManager;
    this.intervalMs = intervalMs;
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
    this._runPromise = null;
    this.lastRunStartedAt = null;
    this.lastRunFinishedAt = null;
    this.nextRunAt = intervalMs > 0 ? Date.now() + intervalMs : null;
    this.accountStatus = new Map();
  }

  start() { if (this.intervalMs > 0) this.reschedule(this.intervalMs); }
  reschedule(intervalMs) {
    const wasOn = this.intervalMs > 0;
    this.intervalMs = intervalMs;
    this.coordinator.unschedule(this.scheduleName);
    if (intervalMs > 0) {
      this.nextRunAt = Date.now() + intervalMs;
      this.coordinator.schedule(this.scheduleName, intervalMs, () => this.warmAll(), { immediate: !wasOn });
      this.log(`[TeamClaude] Keep-warm enabled (every ${Math.round(intervalMs / 1000)}s)`);
    } else if (wasOn) {
      this.nextRunAt = null;
      this.log('[TeamClaude] Keep-warm disabled');
    }
  }
  stop() {
    this.coordinator.unschedule(this.scheduleName);
    this.nextRunAt = null;
    if (this.ownsCoordinator) this.coordinator.shutdown();
  }

  _isWarmTarget(account) {
    if (account.type !== 'oauth' || !account.credential || account.upstream || account.disabled) return false;
    if (account.status === 'error' || account.status === 'exhausted' || account.status === 'throttled') return false;
    const reset = account.quota?.unified5hReset;
    return !(reset && Date.now() < reset);
  }

  async warmAll() {
    if (this._runPromise) return this._runPromise;
    this._runPromise = (async () => {
      this.lastRunStartedAt = Date.now();
      this.nextRunAt = this.intervalMs > 0 ? this.lastRunStartedAt + this.intervalMs : null;
      try {
        for (const account of this.am.accounts.filter(account => this._isWarmTarget(account))) {
          await this.coordinator.run(account, 'keep-warm', 40, signal => this.warmAccount(account, signal));
        }
      } finally {
        this.lastRunFinishedAt = Date.now();
        this._runPromise = null;
      }
    })();
    return this._runPromise;
  }

  async warmAccount(account, signal) {
    const startedAt = Date.now();
    this._record(account, { status: 'running', startedAt });
    try {
      await this.am.ensureTokenFresh(account);
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
        this._record(account, { status: 'error', error: err?.message || String(err), startedAt, finishedAt, durationMs: finishedAt - startedAt });
      }
      return false;
    }
  }

  _spawnSpec(account, signal) {
    const baseUrl = `http://127.0.0.1:${this.port}/tc-acct/${encodeURIComponent(accountIdKey(account))}`;
    return { command: 'claude', args: ['-p', '--bare', '--model', this.model, '--output-format', 'text', this.prompt],
      env: { ...process.env, ANTHROPIC_BASE_URL: baseUrl, ANTHROPIC_API_KEY: this.apiKey || 'tc-warm' }, timeoutMs: this.timeoutMs, signal };
  }

  getStatus() {
    return { enabled: this.intervalMs > 0, intervalSeconds: Math.round(this.intervalMs / 1000), running: !!this._runPromise,
      lastRunStartedAt: iso(this.lastRunStartedAt), lastRunFinishedAt: iso(this.lastRunFinishedAt), nextRunAt: iso(this.nextRunAt),
      accounts: this.am.accounts.map(account => { const status = this.accountStatus.get(account.name); const applicable = account.type === 'oauth' && !account.upstream;
        return { name: account.name, status: applicable ? (status?.status || 'never') : 'not-applicable', lastWarmedAt: iso(status?.finishedAt), startedAt: iso(status?.startedAt), durationMs: status?.durationMs ?? null, error: status?.error || null }; }) };
  }
  _record(account, status) { this.accountStatus.set(account.name, { ...(this.accountStatus.get(account.name) || {}), ...status }); }
}

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
function isTimeoutError(err) { return err?.name === 'TimeoutError' || /warm-up timed out/.test(err?.message || ''); }

function iso(ts) { return ts ? new Date(ts).toISOString() : null; }
