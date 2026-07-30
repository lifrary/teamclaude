import { refreshAccessToken, isTokenExpiringSoon, isTokenExpired } from './oauth.js';

function coerceMaxConcurrent(value, fallback) { return Number.isFinite(value) && value >= 1 ? Math.floor(value) : fallback; }
import { accountId, accountIdKey, createIdentityRegistry, sameIdentity } from './identity.js';
import { weeklyBucketForModel, modelGlobMatches } from './model.js';
import { SessionTracker } from './session-tracker.js';

// How long after a successful token refresh a forced (post-401) refresh is
// suppressed. Long enough to cover the 401s from requests already in flight
// when the token turned over, short enough that a genuinely bad new token
// recovers on the next request rather than staying stuck.
const FORCED_REFRESH_FLOOR_MS = 10_000;

// Re-exported for callers that import these model helpers from here.
export { isFableModel, parseRequestModel, parseAdvisorModel } from './model.js';

// Quota fields that survive a restart: utilization levels and their reset
// windows, learned passively from upstream responses. Transient/derived state
// (probing, requalify, rateLimitedUntil) is intentionally excluded.
const PERSISTED_QUOTA_FIELDS = [
  'unified5h', 'unified7d', 'unified7dSonnet', 'unified7dFable',
  'unified5hReset', 'unified7dReset', 'unified7dSonnetReset', 'unified7dFableReset',
  'tokensLimit', 'tokensRemaining', 'requestsLimit', 'requestsRemaining', 'resetsAt', 'modelWeekly',
];

function emptyQuota() {
  return {
    // Standard API rate limits (API key accounts)
    tokensLimit: null,
    tokensRemaining: null,
    requestsLimit: null,
    requestsRemaining: null,
    // Unified rate limits (Claude Max accounts)
    unified5h: null,            // utilization 0-1
    unified7d: null,            // utilization 0-1
    unified7dSonnet: null,      // utilization 0-1 (Sonnet-specific weekly bucket)
    unified7dFable: null,       // utilization 0-1 (Fable-specific weekly bucket)
    unified5hReset: null,       // ms timestamp
    unified7dReset: null,       // ms timestamp
    unified7dSonnetReset: null, // ms timestamp
    unified7dFableReset: null,  // ms timestamp
    unifiedStatus: null,        // live response status; never persisted
    // Transient ownership for independently reported bucket fields. A newer
    // observation wins; equal timestamps prefer response, then usage, then migration.
    observations: {},
    modelWeekly: {},
    resetsAt: null,
  };
}
const QUOTA_SOURCE_PRIORITY = Object.freeze({ migration: 1, usage: 2, response: 3 });
// Hard ceiling on the overflow queue, independent of `overflowQueueMaxDepth`: the
// queue is a memory bound (totalCapacity x maxRequestBytes), not a tuning dial.
// Named because it silently overrode a configured 256 — see the constructor.
export const QUEUE_DEPTH_CEILING = 16;
function finiteHeaderNumber(value) {
  if (typeof value !== 'string' || value.trim() === '') return NaN;
  return Number(value);
}

function observeQuotaField(quota, bucket, field, value, source, observedAt) {
  if (value == null || (field === 'status' ? typeof value !== 'string' || value === '' : !Number.isFinite(value))) return false;
  const observations = quota.observations ||= {};
  const bucketObservations = observations[bucket] ||= {};
  const previous = bucketObservations[field];
  const priority = QUOTA_SOURCE_PRIORITY[source] || 0;
  if (previous && (previous.observedAt > observedAt
      || (previous.observedAt === observedAt && previous.priority > priority))) return false;
  bucketObservations[field] = {
    observedAt,
    expiresAt: field === 'reset' ? value : bucketObservations.reset?.expiresAt || null,
    source,
    priority,
  };
  return true;
}

function observeUnifiedBucket(quota, bucket, utilizationKey, resetKey, statusKey, values, source, observedAt) {
  const acceptedUtilization = observeQuotaField(quota, bucket, 'utilization', values.utilization, source, observedAt);
  const acceptedReset = observeQuotaField(quota, bucket, 'reset', values.reset, source, observedAt);
  if (acceptedUtilization) quota[utilizationKey] = values.utilization;
  if (acceptedReset) quota[resetKey] = values.reset;
  if (acceptedReset && quota.observations[bucket]?.utilization) quota.observations[bucket].utilization.expiresAt = values.reset;
  // A newer utilization with no reset cannot safely borrow a reset observed for
  // an earlier window.
  if (acceptedUtilization && values.reset == null) {
    const resetObservation = quota.observations[bucket]?.reset;
    if (resetObservation && (resetObservation.observedAt < observedAt
        || (resetObservation.observedAt === observedAt
          && resetObservation.priority < (QUOTA_SOURCE_PRIORITY[source] || 0)))) {
      quota[resetKey] = null;
      delete quota.observations[bucket].reset;
    }
  }
  if (statusKey && observeQuotaField(quota, bucket, 'status', values.status, source, observedAt)) quota[statusKey] = values.status;
}

// Build a fresh in-memory account record from a config/disk account object.
// Shared by the constructor and addAccount() so the field set can never drift
// between startup accounts and runtime-added ones (a divergence here once left
// runtime-added accounts without `inFlight`, hanging every request in acquireAccount()).
function makeAccount(acct, index) {
  const id = accountId(acct);
  const account = {
    index, accountId: id, accountIdKey: accountIdKey(id),
    name: acct.name, type: acct.type, accountUuid: acct.accountUuid || null,
    orgUuid: acct.orgUuid || null, orgName: acct.orgName || null,
    priority: Number.isFinite(acct.priority) ? Math.floor(acct.priority) : null,
    disabled: acct.disabled === true || acct.enabled === false,
    upstream: acct.upstream || null, modelMap: acct.modelMap || null, models: acct.models || null,
    credential: acct.accessToken || acct.apiKey, refreshToken: acct.refreshToken || null,
    expiresAt: acct.expiresAt || null, status: 'active', probing: true, quota: emptyQuota(),
    usage: { totalInputTokens: 0, totalOutputTokens: 0, totalRequests: 0, lastUsed: null },
    rateLimitedUntil: null, throttledAt: null, inFlight: 0, rampStartedAt: null,
    pausedUntil: null, maxConcurrent: 3,
    // When this account's token was last successfully refreshed. Gates forced
    // (post-401) refreshes so a burst of stale in-flight requests can't rotate
    // the refresh-token family once per request — see ensureTokenFresh.
    _lastRefreshAt: null,
  };
  Object.defineProperties(account, {
    enabled: { enumerable: true, get: () => !account.disabled, set: value => { account.disabled = value === false; } },
    inflight: { enumerable: true, get: () => account.inFlight, set: value => { account.inFlight = value; } },
  });
  return account;
}

// Does a declared `models` entry name `model`? The declared side may carry a
// trailing [Nm] context-length suffix (e.g. "deepseek-v4-pro[1m]"); we match it
// against a bare request too. Shared by _accountOwnsModel's two lookups so the
// predicate can't drift.
function modelMatches(declared, model) {
  return declared === model || declared.replace(/\[\d+m\]$/, '') === model;
}

export class AccountManager {
  constructor(accounts, switchThreshold = 0.98, options = {}) {
    // The public contract is the options object below. Positional values remain
    // accepted only long enough to normalize older callers into that same policy.
    // They must never select a different routing engine.
    const positional = typeof options === 'number';
    const trailingOptions = positional && arguments[5] && typeof arguments[5] === 'object'
      ? arguments[5] : {};
    const opts = positional
      ? {
        ...trailingOptions,
        reevalIntervalMs: options,
        maxConcurrent: arguments[3],
        maxQueueDepth: arguments[4],
      }
      : (options && typeof options === 'object' ? options : {});
    const {
      refreshFn = refreshAccessToken,
      throttleProbeFloorMs,
      forcedRefreshFloorMs = FORCED_REFRESH_FLOOR_MS,
      reevalIntervalMs = 5 * 60 * 1000,
      maxConcurrent = 3,
      maxQueueDepth = QUEUE_DEPTH_CEILING,
      queueTimeoutMs = 0,
      routes,
      stormRamp,
      ramp,
      distributeSessions = false,
      sessionTracker,
    } = opts;

    // How long a just-minted token is trusted against a forced refresh.
    this._forcedRefreshFloorMs = forcedRefreshFloorMs;
    this._refreshFn = refreshFn;
    this.maxConcurrentDefault = coerceMaxConcurrent(maxConcurrent, 3);
    // A configured depth above the ceiling used to be discarded in silence, so
    // `overflowQueueMaxDepth: 256` read as accepted while the effective queue was 16.
    // Say so once at startup rather than letting the knob lie.
    const requestedQueueDepth = Number.isFinite(maxQueueDepth) && maxQueueDepth >= 0
      ? Math.floor(maxQueueDepth) : QUEUE_DEPTH_CEILING;
    this.maxQueueDepth = Math.min(QUEUE_DEPTH_CEILING, requestedQueueDepth);
    if (requestedQueueDepth > this.maxQueueDepth) {
      console.log(`[TeamClaude] overflowQueueMaxDepth ${requestedQueueDepth} exceeds the hard ceiling — using ${this.maxQueueDepth}`);
    }
    this.queueTimeoutMs = Number.isFinite(queueTimeoutMs) && queueTimeoutMs >= 0 ? Math.floor(queueTimeoutMs) : 0;
    this.accounts = accounts.map((acct, index) => { const account = makeAccount(acct, index); account.maxConcurrent = coerceMaxConcurrent(acct.maxConcurrent, this.maxConcurrentDefault); return account; });
    createIdentityRegistry(this.accounts);
    this._waiters = [];
    // Reservations bound requests while their body is buffered, then while their
    // exact routing shape waits for an account. They share maxQueueDepth with the
    // normal overflow queue; server code must not maintain a second queue budget.
    this._admissionPrebuffered = 0;
    this._admissionShapes = new Map();
    this._admissionExact = 0;
    this._drainTimer = null;
    this._affinity = new WeakMap();
    this.currentIndex = 0;
    // Session awareness (issue #109). The tracker is always on (passive — it just
    // observes the x-claude-code-session-id header for the status readout).
    // `distributeSessions` gates the behavioural change: keep each session on its
    // account for cache reuse, but spread NEW sessions across equal-priority
    // accounts by load instead of funnelling them all onto the current one.
    this.sessionTracker = sessionTracker || new SessionTracker();
    this._sessionAccounts = new Map();
    this.distributeSessions = !!distributeSessions;
    // Ephemeral per-route manual pins retain account objects, never mutable array
    // positions, so a reload/remove cannot redirect a pin to another account.
    this.routePins = new Map();
    this.switchThreshold = switchThreshold;
    this.reevalIntervalMs = Number.isFinite(reevalIntervalMs) ? reevalIntervalMs : 5 * 60 * 1000;
    this.lastEvalAt = 0;
    this.maxWarmupTries = 3;
    this.probeRetryAfterMs = 15 * 60 * 1000;
    this._warmupCursor = 0;
    this.setRoutes(routes);
    // Storm control: when rotation switches to a fresh account, a burst of
    // in-flight requests (e.g. dozens of agents failing over together) would all
    // hit it at once and instantly throttle it — cascading down the fleet
    // (issue #84). acquireAccount() owns this cap with the normal reservation.
    this.ramp = {
      enabled: !!(stormRamp || ramp),
      startConc: 1,
      stepConc: 1,
      stepMs: 250,
      windowMs: 30_000,
      pollMs: 50,
      ...(stormRamp || ramp),
    };
    // When every account reads as over-quota we would otherwise refuse locally
    // forever (a stale cached utilization is never re-validated because no
    // request is ever sent). Instead, allow one real upstream probe at most this
    // often to refresh the cached quota. See _selectProbe.
    this.probeIntervalMs = 60_000;
    this._nextProbeAt = 0;
    this.throttleProbeFloorMs = throttleProbeFloorMs
      ?? (Number(process.env.TEAMCLAUDE_THROTTLE_PROBE_FLOOR_MS) || 60_000);
  }

  /** Start (or restart) the ramp window for an account that just became current,
   * so a failover burst is paced onto it rather than all landing at once. */
  _beginRamp(account) {
    if (account && this.ramp.enabled) account.rampStartedAt = Date.now();
  }

  /** Max concurrent upstream requests allowed to `account` right now. Infinity
   * once the ramp window has elapsed (or ramping is off / never started). */
  _rampCap(account, now = Date.now()) {
    if (!this.ramp.enabled || account.rampStartedAt == null) return Infinity;
    // Clamp to 0: pauseAccount arms rampStartedAt in the FUTURE (pause-end), so a
    // call during the pause would otherwise yield a negative elapsed → negative
    // cap. acquireAccount() handles pauses, but keep _rampCap sound on its own —
    // a future start simply means "cap is at its floor (startConc)".
    const elapsed = Math.max(0, now - account.rampStartedAt);
    if (elapsed >= this.ramp.windowMs) { account.rampStartedAt = null; return Infinity; }
    return this.ramp.startConc + Math.floor(elapsed / this.ramp.stepMs) * this.ramp.stepConc;
  }

  /**
   * Pause an account after a rate-limit (non-quota) 429 so concurrent requests
   * wait in acquireAccount() instead of piling on. Unlike markRateLimited this does NOT
   * set `throttled`/rateLimitedUntil, so _isAvailable still returns true and
   * selection never rotates away — rotation is reserved for quota exhaustion.
   * When the pause lifts, the held requests are released through a fresh ramp
   * window (storm control) so they trickle out rather than flood. Extends an
   * existing pause rather than shortening it.
   */
  pauseAccount(accountOrIndex, seconds) {
    const account = this._resolveLive(accountOrIndex);
    if (!account) return;
    const until = Date.now() + Math.max(0, seconds) * 1000;
    account.pausedUntil = Math.max(account.pausedUntil || 0, until);
    if (this.ramp.enabled) account.rampStartedAt = account.pausedUntil;
    this._scheduleDrain();
  }


  _selectBest(exclude = null, routingContext = {}) {
    const { model = null, advisorModel = null } = routingContext;
    const has = a => !!exclude && (exclude.has(a) || exclude.has(a.index));
    let eligible = this.accounts.filter(a => this._isAvailable(a, model, advisorModel) && !has(a));
    if (eligible.length === 0) return null;

    // When no third-party account explicitly owns this model, prefer native
    // Anthropic accounts while any are healthy. Third-party backends remain a
    // fallback once native capacity/quota is unavailable.
    const claimed = model && this.accounts.some(a =>
      a.models?.some(declared => modelMatches(declared, model)));
    if (model && !claimed) {
      const native = eligible.filter(a => !a.models?.length);
      if (native.length) eligible = native;
    }

    eligible.sort((a, b) => this._compareSelection(a, b, model));
    return eligible[0];
  }

  _compareSelection(a, b, model = null) {
    const pa = this._priority(a);
    const pb = this._priority(b);
    if (pa !== pb) return pa - pb;
    const wa = this._selectionWeeklyReset(a, model);
    const wb = this._selectionWeeklyReset(b, model);
    if (wa !== wb) return wa - wb;
    const ra = this._sessionResetTime(a);
    const rb = this._sessionResetTime(b);
    if (ra !== rb) return ra - rb;
    return this._sessionUtilization(a) - this._sessionUtilization(b);
  }
  _selectionWeeklyReset(account, model = null) {
    const utilization = this._governingWeekly(account, model);
    const reset = this._governingWeeklyReset(account, model);
    return utilization != null && reset > Date.now() ? reset : Infinity;
  }


  /**
   * Explicit selection priority: lower = preferred. Unset (null) sorts last
   * (Infinity) so an account WITH any finite priority — however large — is chosen
   * ahead of those without. When no account sets a priority, every account ties
   * here (Infinity === Infinity) and the sort falls through to use-or-lose, i.e.
   * the original behavior unchanged. The callers compare with a `pa !== pb` guard
   * before any subtraction, so Infinity never produces a NaN sort key.
   */
  _priority(account) {
    return Number.isFinite(account.priority) ? account.priority : Infinity;
  }

  /**
   * The automatic ("auto") use-or-lose comparator, shared by selection and the
   * TUI display order: soonest WEEKLY reset (drain what renews first) → soonest
   * session reset → lowest session utilization. Returns 0 on a full tie, so a
   * stable sort keeps ties in array order (the pre-weekly behavior for API-key
   * fleets and unmeasured accounts).
   */
  autoCompare(a, b) {
    const wa = this._weeklyResetTime(a);
    const wb = this._weeklyResetTime(b);
    if (wa !== wb) return wa - wb;
    const ra = this._sessionResetTime(a);
    const rb = this._sessionResetTime(b);
    if (ra !== rb) return ra - rb;
    return this._sessionUtilization(a) - this._sessionUtilization(b);
  }

  /**
   * Weekly reset timestamp (ms): unified 7d (Max) → Infinity. API-key accounts
   * have no weekly window, so they tie at Infinity and the session tiebreak
   * decides — exactly the pre-weekly-ordering behavior. The window counts only
   * when BOTH utilization and reset are present: a partial/garbled header pair
   * (reset without utilization) must not outrank accounts with no 7d data,
   * matching the documented "no weekly data ranks at Infinity" semantics.
   *
   * A timestamp that has PASSED ranks at Infinity too: the moment a window
   * rolls over, the account's old "resets soonest" claim is void (its fresh
   * window is unknown until re-measured) — without this, the past timestamp
   * (smallest value) would pin the account at the top of the order until a
   * request-path sweep happened to clear it, so the order would NOT follow
   * reset rollovers. The lazy sweep in _isNearQuota still clears the fields;
   * this just makes ORDERING (selection and the TUI display, which has no
   * sweep) reflect the rollover instantly.
   */
  _weeklyResetTime(account) {
    const q = account.quota;
    const r = (q.unified7d != null && q.unified7dReset) ? q.unified7dReset : Infinity;
    return r > Date.now() ? r : Infinity;
  }

  /**
   * Session reset timestamp (ms): unified 5h (Max) → standard reset → Infinity.
   * Expired timestamps rank at Infinity for the same rollover reason as
   * _weeklyResetTime above.
   */
  _sessionResetTime(account) {
    const q = account.quota;
    const r = q.unified5hReset
      || (q.resetsAt ? new Date(q.resetsAt).getTime() : Infinity);
    return r > Date.now() ? r : Infinity;
  }

  /** Session utilization 0–1: unified 5h (Max) → standard token/request usage → 0. */
  _sessionUtilization(account) {
    const q = account.quota;
    if (q.unified5h != null) return q.unified5h;
    if (q.tokensLimit != null && q.tokensRemaining != null) {
      return 1 - q.tokensRemaining / q.tokensLimit;
    }
    if (q.requestsLimit != null && q.requestsRemaining != null) {
      return 1 - q.requestsRemaining / q.requestsLimit;
    }
    return 0;
  }

  /**
   * Clear every account's expired quota windows NOW. The lazy sweep inside
   * _isNearQuota only runs on selection paths (i.e. when a request flows), so
   * on an idle proxy a rolled-over window would keep its stale values — and
   * stay "measured", which prevents the periodic active warm-up from
   * re-probing it. The server's warm-up timer calls this first, closing the
   * loop: rollover → sweep → unmeasured → probe → fresh data → order updates.
   * Idempotent and cheap (pure field clears).
   */
  sweepExpired() {
    for (const a of this.accounts) this._isNearQuota(a);
  }

  /** True once we have any quota data for this account (rate-limit headers seen). */
  _isMeasured(account) {
    const q = account.quota;
    return q.unified5h != null || q.unified7d != null
      || q.tokensLimit != null || q.requestsLimit != null;
  }

  /**
   * Fully measured, for ACTIVE warm-up candidacy: an OAuth (Max) response
   * always carries both the 5h and the 7d window, so a missing half — e.g. a
   * weekly rollover swept `unified7d` while the session window survived —
   * means the account needs a re-probe or its weekly quota/ordering stays
   * unknown until real traffic reaches it. One probe repopulates both windows,
   * so candidacy converges. API-key accounts keep the any-data semantics.
   */
  _fullyMeasured(account) {
    if (account.type === 'oauth') {
      // A window counts only when COMPLETE (utilization AND reset) — the same
      // semantics the ordering helpers use. Utilization without its reset
      // timestamp gives use-or-lose nothing to sort on, so such an account
      // still needs a re-probe.
      const q = account.quota;
      return q.unified5h != null && q.unified5hReset != null
        && q.unified7d != null && q.unified7dReset != null;
    }
    return this._isMeasured(account);
  }

  /**
   * A fully-measured OAuth account whose model-scoped weekly window (the Fable
   * `7d_oi` limit) is still absent. Such a window only appears on responses to
   * Fable-tier requests, so an account that was measured by lower-tier traffic
   * or a lower-tier probe keeps its `Fbl` bar blank — and because it IS fully
   * measured for 5h/7d, ordinary warm-up (which only targets unmeasured
   * accounts) never re-probes it. This flags it for a bounded model-weekly
   * top-up probe, run ONLY when the committed probe template can actually
   * elicit the window (see server.js). The `_mwProbes` cap stops an account
   * whose upstream genuinely never reports the window from being probed every
   * interval forever; it resets when the window populates or a quota window is
   * swept (a fresh week is a fresh reason to look).
   */
  needsModelWeekly(account) {
    return account.type === 'oauth'
      && this._fullyMeasured(account)
      && Object.keys(account.quota.modelWeekly).length === 0
      && (account._mwProbes || 0) < this.maxWarmupTries;
  }

  /**
   * An account still needing warm-up: available, not yet MEASURED, under the
   * per-account attempt cap.
   *
   * Keying on `!_isMeasured` (not on "has it made a request") is deliberate: a
   * request can return *no* rate-limit headers — a `HEAD /` health check, a
   * 404, an auth failure — which would leave the account unmeasured. Gating
   * warm-up on `totalRequests === 0` used to permanently disqualify such an
   * account after that single header-less request, trapping it as "unmeasured"
   * forever: it then sorts to the bottom of use-or-lose priority (no reset
   * data) and the unmeasured-rebalance bounces any switch away from it, so it
   * never gets used again — and its token never gets refreshed, so it expires.
   *
   * maxWarmupTries provides the loop-safety instead: a genuinely dead account
   * (always header-less / 401) is abandoned after a few attempts rather than
   * looping forever. (An expired-token account is resolved on its first warm-up
   * routing anyway — ensureTokenFresh either refreshes it into a measurable
   * state or marks it `error`, which makes it unavailable here.)
   */
  _isWarmupTarget(account) {
    return this._isAvailable(account)
      && !this._isMeasured(account)
      && (account._warmupTries || 0) < this.maxWarmupTries;
  }

  /**
   * Next account to warm up, round-robin across the warm-up targets so a burst
   * spreads evenly. Advances the cursor and bumps the chosen account's attempt
   * counter synchronously, so concurrent calls pick different accounts even
   * before any response arrives. Returns null when no target remains.
   */
  _nextWarmup(routingContext = {}) {
    const { model = null, advisorModel = null } = routingContext;
    const n = this.accounts.length;
    for (let i = 0; i < n; i++) {
      const idx = (this._warmupCursor + i) % n;
      const a = this.accounts[idx];
      if (this._isWarmupTarget(a) && this._isAvailable(a, model, advisorModel)) {
        this._warmupCursor = idx + 1;
        a._warmupTries = (a._warmupTries || 0) + 1;
        return a;
      }
    }
    return null;
  }
  /**
   * Accounts eligible for an active quota measurement. Probes are deliberately
   * independent of client slots: only an idle account is eligible, so client
   * capacity is never consumed by a background measurement.
   *
   * A complete OAuth measurement needs both unified windows and their resets.
   * Deterministic fruitless results are capped, but retried slowly so a
   * temporarily header-less upstream can recover without a restart.
   */
  warmupCandidates() {
    const now = Date.now();
    return this.accounts.filter(account =>
      this._isAvailable(account)
      && !this._fullyMeasured(account)
      && account.inFlight === 0
      && ((account._partialProbes || 0) < this.maxWarmupTries
        || now - (account._lastFruitlessProbeAt || 0) >= this.probeRetryAfterMs));
  }


  // ── Concurrency layer: per-account in-flight cap + overflow queue ──────────
  //
  // getActiveAccount() above picks ONE account (sticky, use-or-lose). On its own
  // that funnels every concurrent terminal onto the same account, which then hits
  // Anthropic's per-account rate / concurrency limit (429) while other accounts
  // sit idle with quota to spare. The layer below fixes that PROACTIVELY: each
  // account carries an `inFlight` counter and a `maxConcurrent` cap, and
  // acquireAccount() treats a capped account as momentarily unavailable (folds it
  // into the exclude set). The existing priority logic then naturally spreads
  // load to the next account — filling A up to its cap, then B, then C, by
  // use-or-lose priority. When every available account is at its cap the request
  // waits briefly for a slot to free (overflow queue) instead of 429-storming.

  /** Has this account a reservable slot now, including pause and storm-ramp gates. */
  _hasCapacity(account, now = Date.now()) {
    return !!account
      && (!account.pausedUntil || now >= account.pausedUntil)
      && account.inFlight < Math.min(account.maxConcurrent, this._rampCap(account, now));
  }
  /** A pinned request may reserve only this still-live account object. */
  _pinnedAccount(routingContext = {}) {
    const account = routingContext.pinnedAccount;
    return account && this.accounts[account.index] === account ? account : null;
  }

  /**
   * Resolve an account handle to the live account object. Accepts the object
   * itself (reindex-safe — what server.js passes) or a numeric index (legacy /
   * tests). All public per-account methods route their first arg through this so
   * a stale index captured before a removeAccount() can't hit the wrong account.
   */
  _resolve(accountOrIndex) {
    return typeof accountOrIndex === 'number' ? this.accounts[accountOrIndex] : accountOrIndex;
  }

  _resolveLive(accountOrIndex) {
    let account = this._resolve(accountOrIndex);
    while (account?._replacement) account = account._replacement;
    return account;
  }

  /**
   * Available accounts currently at their concurrency cap, as a Set of account
   * OBJECTS (not indexes). Object identity is stable across a removeAccount()
   * re-index, so an exclude/capped set captured before the request awaits
   * upstream can't later point at the wrong account.
   */
  _cappedSet(exclude = null, routingContext = {}) {
    const { model = null, advisorModel = null } = routingContext;
    const pinned = this._pinnedAccount(routingContext);
    const candidates = routingContext.pinnedAccount ? (pinned ? [pinned] : []) : this.accounts;
    const capped = new Set();
    for (const a of candidates) {
      if (exclude && (exclude.has(a) || exclude.has(a.index))) continue;
      if (this._isAvailable(a, model, advisorModel) && !this._hasCapacity(a)) capped.add(a.index);
    }
    return capped;
  }

  /** Is there an available account with a free slot (not excluded)? Non-mutating. */
  anyUsable(exclude = null, routingContext = {}) {
    const { model = null, advisorModel = null } = routingContext;
    const pinned = this._pinnedAccount(routingContext);
    const candidates = routingContext.pinnedAccount ? (pinned ? [pinned] : []) : this.accounts;
    return candidates.some(a =>
      this._isAvailable(a, model, advisorModel) && this._hasCapacity(a)
      && !(exclude && (exclude.has(a) || exclude.has(a.index))));
  }

  /** Is there an available-but-capped account (not excluded)? */
  anyCapped(exclude = null, routingContext = {}) {
    const { model = null, advisorModel = null } = routingContext;
    const pinned = this._pinnedAccount(routingContext);
    const candidates = routingContext.pinnedAccount ? (pinned ? [pinned] : []) : this.accounts;
    return candidates.some(a =>
      this._isAvailable(a, model, advisorModel) && !this._hasCapacity(a)
      && !(exclude && (exclude.has(a) || exclude.has(a.index))));
  }

  /**
   * Synchronously pick + reserve the best account that is available AND has a
   * free concurrency slot, honoring `exclude`. Capped accounts are folded into
   * the exclusion so the existing getActiveAccount / _selectBest priority logic
   * (warm-up, use-or-lose, recover) only ever chooses an account that can take
   * the request. Increments the chosen account's inFlight. Returns null when
   * nothing is currently acquirable (all exhausted, excluded, or capped).
   *
   * Single-threaded JS keeps this race-free: there is no await between selecting
   * the account and the inFlight++ that reserves its slot.
   */
  _tryAcquire(exclude = null, affinityKey = null, routingContext = {}) {
    // Only an object/function is a valid WeakMap key. Ignore anything else (a
    // primitive key from an external caller would otherwise throw on get/set).
    const affOk = affinityKey != null
      && (typeof affinityKey === 'object' || typeof affinityKey === 'function');

    // Connection affinity (cache locality): prefer the account this connection
    // already used — but only as a *soft* hint, and DEFER to cold-start warm-up.
    // While any account still needs measuring, skip affinity so it can't pin all
    // of a connection's traffic to one account and starve the others of quota
    // data (warm-up round-robins the unmeasured accounts instead). Once measured,
    // affinity is honored only when that account is still available, has a free
    // slot, and isn't excluded for this request; otherwise it falls through to
    // normal selection. So it never exceeds a cap, revives an exhausted account,
    // or disturbs use-or-lose for new connections. (`accounts[idx] === a` rejects
    // a stale entry left by a removeAccount that re-indexed the array.)
    const { model = null, advisorModel = null } = routingContext;
    // A route pin is a hard identity constraint, unlike soft connection affinity:
    // it may wait for its own pause/ramp/cap slot, but never falls through.
    if (routingContext.pinnedAccount) {
      const pinned = this._pinnedAccount(routingContext);
      if (pinned && this._isAvailable(pinned, model, advisorModel)
          && this._hasCapacity(pinned)
          && !(exclude && (exclude.has(pinned) || exclude.has(pinned.index)))) {
        pinned.inFlight++;
        return pinned;
      }
      return null;
    }

    if (affOk && !this.accounts.some(acc => this._isWarmupTarget(acc))) {
      const a = this._affinity.get(affinityKey);
      // Require the home to be MEASURED — not just past its warm-up tries. A
      // headerless account stays unmeasured forever; pinning a connection to it
      // would bypass getActiveAccount's unmeasured-rebalance (which keeps
      // spreading to gather quota data / let tokens refresh on use). Once an
      // account returns rate-limit headers (every real Anthropic response does),
      // affinity engages normally.
      if (a && this.accounts[a.index] === a && this._isMeasured(a) && this._isAvailable(a, model, advisorModel)
          && this._hasCapacity(a) && !(exclude && (exclude.has(a) || exclude.has(a.index)))) {
        a.inFlight++;
        return a;
      }
    }

    const capped = this._cappedSet(exclude, routingContext);
    const eff = ((exclude && exclude.size) || capped.size)
      ? new Set([...(exclude || []), ...capped])
      : null;
    // eff === null → full sticky / warm-up path (cold start, nothing capped).
    // eff set → getActiveAccount routes to _selectBest(eff), which already skips
    // every excluded + capped account.
    const account = this.getActiveAccount(eff, routingContext);
    const available = this._isAvailable(account, model, advisorModel);
    // A stale-quota probe is an explicit server revalidation operation, never an
    // implicit fallback from ordinary request routing.
    const probe = !!routingContext.revalidate && !available && this._isProbeable(account);
    if (account && (available || probe) && this._hasCapacity(account)
        && !(eff && eff.has(account))) {
      account.inFlight++;
      // (Re)write affinity ONLY when the connection has no still-usable home.
      // Reaching this fall-through path means we left the home account — but that
      // can be merely transient: the home may be momentarily capped (overflow
      // spill) or failover-excluded for THIS request, yet still perfectly
      // available. Overwriting it then would let one blip permanently evict the
      // connection from its cache-warm account. So keep an available home (even
      // capped/excluded right now); replace it only when it's genuinely gone
      // (removed, unavailable, or exhausted — `_isAvailable` is false).
      if (affOk) {
        const home = this._affinity.get(affinityKey);
        const homeUsable = home && this.accounts[home.index] === home && this._isAvailable(home, model, advisorModel);
        if (!homeUsable) this._affinity.set(affinityKey, account);
      }
      return account;
    }
    return null;
  }

  /**
   * Acquire an account for a request, reserving one of its concurrency slots.
   * If none is immediately acquirable but an available account is merely at its
   * cap (overflow), wait up to `timeoutMs` for a slot to free — a releaseAccount
   * elsewhere wakes the waiter. Returns null when every account is genuinely
   * unavailable (quota-exhausted / auth-error / excluded) or the wait times out,
   * so the caller surfaces a 429 for the client to back off on.
   *
   * The caller MUST releaseAccount(account) exactly once when the request
   * (including any streamed body) finishes — pass the returned account OBJECT,
   * not its index, so a concurrent removeAccount() can't misattribute the slot.
   * `exclude` is a Set of account OBJECTS (per-request failover).
   */
  async acquireAccount(exclude = null, timeoutMs = this.queueTimeoutMs, signal = null, affinityKey = null, routingContext = {}) {
    if (signal?.aborted) return null;
    const account = this._tryAcquire(exclude, affinityKey, routingContext);
    if (account) return account;
    // Queue only when the blockage is cap-saturation (a slot WILL free as
    // in-flight requests finish) AND the queue isn't already full. If no
    // available account exists at all, or the queue is at its depth cap, return
    // null and let the caller 429 — never grow the backlog without bound.
    if (timeoutMs <= 0 || !this.anyCapped(exclude, routingContext) || this.isQueueFull()) return null;
    return this._enqueue(exclude, timeoutMs, signal, affinityKey, routingContext);
  }

  /** Is the overflow queue at its depth cap? */
  isQueueFull() {
    return this._waiters.length >= this.maxQueueDepth;
  }

  /**
   * Upper bound on concurrent in-flight requests the proxy may admit (server.js
   * caps `inFlightProxied` to this to bound buffered memory): each ENABLED
   * account contributes its full cap (capacity it can still take), each DISABLED
   * account contributes only its *current* in-flight (requests still draining —
   * it accepts no new ones), plus the queue depth.
   *
   * This is the tightest bound that's still safe: it covers the draining requests
   * on a just-disabled account (so they can't push inFlightProxied over the
   * ceiling and 429 traffic the enabled accounts could serve), without admitting
   * fresh requests against a disabled account's dead future capacity (which could
   * only be buffered and then 429'd at acquire). As those draining requests
   * finish, the disabled account's contribution falls to zero.
   */
  totalCapacity() {
    const caps = this.accounts.reduce(
      (sum, a) => sum + (a.disabled === true ? a.inFlight : a.maxConcurrent), 0);
    return caps + this.maxQueueDepth;
  }

  /** Full-request capacity for an exact routing shape. */
  eligibleCapacity(routingContext = {}) {
    const { model = null, advisorModel = null } = routingContext;
    const pinned = this._pinnedAccount(routingContext);
    const candidates = routingContext.pinnedAccount ? (pinned ? [pinned] : []) : this.accounts;
    return candidates.reduce((sum, account) => (
      this._isAvailable(account, model, advisorModel) ? sum + account.maxConcurrent : sum
    ), 0);
  }

  /** Conservative capacity before a JSON body has disclosed its model shape. */
  conservativeCapacity(routingContext = {}) {
    const pinned = this._pinnedAccount(routingContext);
    if (routingContext.pinnedAccount) return pinned && this._isAvailable(pinned) ? pinned.maxConcurrent : 0;
    const caps = this.accounts.filter(account => this._isAvailable(account)).map(account => account.maxConcurrent);
    return caps.length ? Math.min(...caps) : 0;
  }
  /**
   * Reserve conservative pre-body capacity. Once the request body identifies its
   * route/model shape, transferAdmissionReservation() atomically replaces this
   * reservation with an exact one.
   */
  reserveAdmissionPrebuffer(routingContext = {}) {
    const total = this._admissionPrebuffered + this._admissionExact;
    if (total >= this._admissionGlobalCapacity()
        || this._admissionPrebuffered >= this._admissionCapacity(routingContext, true)) return null;
    this._admissionPrebuffered++;
    return { phase: 'prebuffer', key: null };
  }

  /**
   * Atomically transfer a pre-body reservation to its exact normalized shape.
   * A shape with no eligible account receives no overflow allowance: queue depth
   * only extends capacity that can eventually serve the request.
   */
  transferAdmissionReservation(reservation, key, routingContext = {}) {
    if (!reservation || reservation.phase !== 'prebuffer') return false;
    const used = this._admissionShapes.get(key) || 0;
    if (used >= this._admissionCapacity(routingContext)) return false;
    this._admissionPrebuffered--;
    this._admissionExact++;
    this._admissionShapes.set(key, used + 1);
    reservation.phase = 'exact';
    reservation.key = key;
    return true;
  }

  /** Release an admission reservation exactly once. */
  releaseAdmissionReservation(reservation) {
    if (!reservation || reservation.phase === 'released') return;
    if (reservation.phase === 'prebuffer') {
      this._admissionPrebuffered = Math.max(0, this._admissionPrebuffered - 1);
    } else if (reservation.phase === 'exact') {
      const used = this._admissionShapes.get(reservation.key) || 0;
      if (used <= 1) this._admissionShapes.delete(reservation.key);
      else this._admissionShapes.set(reservation.key, used - 1);
      this._admissionExact = Math.max(0, this._admissionExact - 1);
    }
    reservation.phase = 'released';
  }

  _admissionRoutableCapacity(routingContext = {}, conservative = false) {
    const { model = null, advisorModel = null } = routingContext;
    const pinned = this._pinnedAccount(routingContext);
    const candidates = routingContext.pinnedAccount ? (pinned ? [pinned] : []) : this.accounts;
    const capacities = candidates
      .filter(account => !account.disabled && account.status !== 'error')
      .filter(account => !model || this._routeAllows(account, model))
      .filter(account => !advisorModel || this._routeAllows(account, advisorModel))
      .map(account => account.maxConcurrent);
    if (capacities.length === 0) return 0;
    return conservative ? Math.min(...capacities) : capacities.reduce((sum, capacity) => sum + capacity, 0);
  }

  _admissionGlobalCapacity() {
    return this._admissionRoutableCapacity({}) + this.maxQueueDepth;
  }

  _admissionCapacity(routingContext = {}, conservative = false) {
    const capacity = this._admissionRoutableCapacity(routingContext, conservative);
    return capacity > 0 ? capacity + this.maxQueueDepth : 0;
  }

  _enqueue(exclude, timeoutMs, signal = null, affinityKey = null, routingContext = {}) {
    return new Promise(resolve => {
      const waiter = { exclude, resolve, done: false, timer: null, signal, onAbort: null, affinityKey, routingContext };
      waiter.timer = setTimeout(() => this._settleWaiter(waiter, null), timeoutMs);
      if (signal) {
        waiter.onAbort = () => this._settleWaiter(waiter, null);
        signal.addEventListener('abort', waiter.onAbort, { once: true });
      }
      this._waiters.push(waiter);
      this._scheduleDrain();
    });
  }

  _scheduleDrain() {
    if (this._drainTimer || this._waiters.length === 0) return;
    const now = Date.now();
    const pauseEnds = this.accounts.map(account => account.pausedUntil).filter(until => until && until > now);
    const delay = pauseEnds.length ? Math.min(Math.min(...pauseEnds) - now, this.ramp.pollMs) : this.ramp.pollMs;
    this._drainTimer = setTimeout(() => {
      this._drainTimer = null;
      this._drainWaiters();
    }, Math.max(1, delay));
  }

  /** Resolve a queued waiter exactly once, cleaning up its timer/abort listener. */
  _settleWaiter(waiter, value) {
    if (waiter.done) return false;
    waiter.done = true;
    clearTimeout(waiter.timer);
    if (waiter.signal && waiter.onAbort) waiter.signal.removeEventListener('abort', waiter.onAbort);
    const i = this._waiters.indexOf(waiter);
    if (i >= 0) this._waiters.splice(i, 1);
    waiter.resolve(value);
    return true;
  }

  /**
   * Release a concurrency slot held by a request and hand any freed capacity to
   * the longest-waiting overflow request that can use it (FIFO, but a waiter
   * whose exclude set can't currently be satisfied is skipped rather than
   * head-of-line blocking a later waiter that can run).
   */
  releaseAccount(accountOrIndex) {
    // Resolve to the account OBJECT (what the server holds — reindex-safe across a
    // removeAccount) so a release decrements the slot of the *account that was
    // acquired*, never whatever happens to sit at that index now. A numeric index
    // is still accepted for convenience/tests.
    const account = this._resolve(accountOrIndex);
    if (account && account.inFlight > 0) {
      account.inFlight--;
      // A live account can itself be rekeyed before an older request drains.
      // Propagate this one release through every replacement generation.
      for (let replacement = account._replacement; replacement?.inFlight > 0; replacement = replacement._replacement) {
        replacement.inFlight--;
      }
    }
    this._drainWaiters();
  }

  _drainWaiters() {
    for (let i = 0; i < this._waiters.length;) {
      const waiter = this._waiters[i];
      const account = this._tryAcquire(waiter.exclude, waiter.affinityKey, waiter.routingContext);
      if (account) {
        // _settleWaiter splices the waiter out, so don't advance i. If it was
        // already settled (shouldn't happen — settled waiters aren't in the list),
        // give the slot back instead of leaking it.
        if (!this._settleWaiter(waiter, account)) { account.inFlight--; i++; }
        continue;
      }
      // No slot right now. If no account this waiter could use is even
      // available-but-capped, nothing will ever free for it (e.g. the account it
      // was queued for just got disabled or exhausted) — settle it null so it
      // releases its finite queue slot instead of blocking later, satisfiable
      // overflow requests until its timeout. A waiter that still has a cappable
      // account to hope for is left in place.
      if (!this.anyCapped(waiter.exclude, waiter.routingContext)) {
        // Try once more before giving up. `_tryAcquire` above and `anyCapped` here each
        // take their OWN Date.now(), and `_hasCapacity` flips at a `pausedUntil` /
        // throttle boundary — so a drain landing on that boundary sees "still paused"
        // in the first call and "no longer capped" in the second, and would settle the
        // waiter null at the exact instant its account became servable, costing the
        // client a 429 it did not earn. (Observed as a rare suite failure: a 40ms pause
        // with a 500ms budget resolved null at 41ms.) If the retry also fails we settle
        // null exactly as before — this branch deliberately does not claim more than the
        // original did. A null `_tryAcquire` is NOT by itself proof that no account is
        // usable (it re-checks capacity after selection, so it can decline while another
        // account is fine); all this removes is the case where the first call was simply
        // reading a stale clock.
        const late = this._tryAcquire(waiter.exclude, waiter.affinityKey, waiter.routingContext);
        if (late) {
          if (!this._settleWaiter(waiter, late)) { late.inFlight--; i++; }
          continue;
        }
        this._settleWaiter(waiter, null);
        continue;
      }
      i++;
    }
    this._scheduleDrain();
  }


  /**
   * Get the best available account, rotating if the current one is near quota.
   * Returns null if all accounts are exhausted.
   *
   * `advisorModel` is the second model an advisor request carries (Claude Code's
   * advisor tool, nested in tools[] — see parseAdvisorModel): the advisor
   * sub-inference runs on the SAME account and spends that model's family
   * bucket, so the account must be eligible for both models. When no account
   * satisfies both, selection degrades to executor-only routing so the main
   * request keeps flowing (upstream then fails just the advisor call).
   */
  getActiveAccount(exclude = null, modelOrContext = null, advisorModel = null, sessionId = null) {
    // The options object is the canonical request context. Keep the positional
    // form as a compatibility adapter so every caller still reaches this one
    // selection engine.
    const routingContext = modelOrContext && typeof modelOrContext === 'object'
      ? modelOrContext
      : { model: modelOrContext, advisorModel, sessionId };
    const {
      model = null,
      advisorModel: advisor = null,
      sessionId: session = null,
      revalidate = true,
    } = routingContext;
    const context = { ...routingContext, model, advisorModel: advisor, sessionId: session, revalidate };

    this.refreshExpiredQuotas();

    // Per-request failover must not disturb sticky state, but it still applies all
    // model/route eligibility before use-or-lose preference ordering.
    if (exclude?.size) return this._selectBest(exclude, context);

    // Route pins and session affinity are request constraints/preferences that
    // must be honored before a generic warm-up can consume unrelated traffic.
    const pinned = this._pinnedAccountForModel(model, advisor);
    if (pinned && this._isAvailable(pinned, model, advisor)) return pinned;
    if (this.distributeSessions && session && !pinned) {
      const account = this._selectForSession(session, null, model, advisor);
      if (account) return account;
    }

    // Model- and session-scoped requests already carry hard routing constraints;
    // leave their choice to the constrained selector rather than probing a
    // different eligible account first.
    const warmup = !model && !session ? this._nextWarmup(context) : null;
    if (warmup) {
      if (warmup.index !== this.currentIndex) {
        this.currentIndex = warmup.index;
        this._beginRamp(warmup);
      }
      return warmup;
    }

    const current = this.accounts[this.currentIndex];
    const modelClaimed = model && this.accounts.some(a =>
      a.models?.some(declared => modelMatches(declared, model)));
    const nativeAlternative = model && !modelClaimed && current?.models?.length
      && this.accounts.some(a => !a.models?.length && this._isAvailable(a, model, advisor));
    if (!this._isAvailable(current, model, advisor) || nativeAlternative) {
      const next = this._selectBest(null, context);
      if (next) {
        this.currentIndex = next.index;
        this.lastEvalAt = Date.now();
        this._beginRamp(next);
      }
      if (next) return next;
      if (advisor) return this.getActiveAccount(null, { ...context, advisorModel: null });
      return revalidate ? this._selectProbe(null, model) : null;
    }

    const now = Date.now();
    if (current.requalify || (this.reevalIntervalMs > 0 && now - this.lastEvalAt >= this.reevalIntervalMs)) {
      this.lastEvalAt = now;
      const next = this._selectBest(null, context);
      current.requalify = false;
      // A request-scoped route/session remains on its eligible current account
      // unless an explicit priority preempts it. This keeps model and session
      // affinity from being displaced by unrelated quota ordering.
      if (next && next.index !== current.index
          && (!model && !session || this._priority(next) < this._priority(current))) {
        this.currentIndex = next.index;
        this._beginRamp(next);
        return next;
      }
    }

    // Header-less accounts remain unmeasured after their bounded warm-up attempts.
    // Keep rotating among them rather than pinning all traffic to the last one.
    if (!model && !session && !this._isMeasured(current)) {
      const candidates = this.accounts.filter(account =>
        this._isAvailable(account, model, advisor) && !this._isMeasured(account));
      const next = candidates.find(account => account.index > current.index) || candidates[0] || current;
      this.currentIndex = next.index;
      return next;
    }

    // Keep the chosen account sticky between re-evaluations for cache locality.
    return current;
  }

  /** Session-affinity selection (opt-in, issue #109). Honor a known session's
   * pin when that account is still eligible and not preempted by a
   * higher-priority one; otherwise route the session to the least-loaded
   * eligible account. Returns null if nothing is eligible, so the caller falls
   * back to the normal quota-driven walk. Does NOT record the pin — that happens
   * on the actual route (recordSession), so retries/failover re-pin naturally. */
  _selectForSession(sessionId, exclude, model, advisorModel) {
    const tracked = this.sessionTracker.pinnedAccount(sessionId);
    if (tracked == null) this._sessionAccounts.delete(sessionId);
    const pinned = this._sessionAccounts.get(sessionId);
    if (pinned && this.accounts.includes(pinned)
        && this._isAvailable(pinned, model, advisorModel) && !exclude?.has(pinned)) {
      // Mirror _select's priority preemption so an operator's priority order
      // still wins over a session's stickiness.
      const betterExists = this.accounts.some(a =>
        this._isAvailable(a, model, advisorModel) && !exclude?.has(a) && this._priority(a) < this._priority(pinned));
      if (!betterExists) return pinned;
    }
    return this._pickLeastLoaded(exclude, model, advisorModel);
  }

  /** Best-available biased toward the fewest active sessions, so new sessions
   * spread across equal-priority accounts instead of funnelling onto one. Order:
   * priority → fewest active sessions → fewest in-flight → soonest weekly reset
   * (the existing tiebreak). */
  _pickLeastLoaded(exclude = null, model = null, advisorModel = null) {
    let best = null;
    let bestPriority = Infinity;
    let bestSessions = Infinity;
    let bestInFlight = Infinity;
    let bestReset = Infinity;
    for (const account of this.accounts) {
      if (exclude?.has(account) || exclude?.has(account.index)) continue;
      if (!this._isAvailable(account, model, advisorModel)) continue;
      const priority = this._priority(account);
      const sessions = [...this._sessionAccounts.values()].filter(a => a === account).length;
      const inFlight = account.inFlight || 0;
      const reset = this._governingWeeklyReset(account, model) || -Infinity;
      if (priority < bestPriority
        || (priority === bestPriority && sessions < bestSessions)
        || (priority === bestPriority && sessions === bestSessions && inFlight < bestInFlight)
        || (priority === bestPriority && sessions === bestSessions && inFlight === bestInFlight && reset < bestReset)) {
        best = account;
        bestPriority = priority;
        bestSessions = sessions;
        bestInFlight = inFlight;
        bestReset = reset;
      }
    }
    return best;
  }

  /** Record that a session's request was served by an account (always on, even
   * when distribution is off — the readout is passive). This is what pins a
   * session for future affinity. */
  recordSession(sessionId, accountOrIndex) {
    const account = this._resolve(accountOrIndex);
    if (sessionId && account && this.accounts.includes(account)) {
      this._sessionAccounts.set(sessionId, account);
      this.sessionTracker.touch(sessionId, account.index);
    }
  }

  /** Mark a session request as in flight / finished. Paired around the whole
   * client request (including retries) so a long streaming completion keeps the
   * session counted as active for its full duration. */
  beginSession(sessionId) {
    if (sessionId) this.sessionTracker.beginRequest(sessionId);
  }

  endSession(sessionId) {
    if (sessionId) this.sessionTracker.endRequest(sessionId);
  }

  /** { known, active, perAccount } session counts for status/TUI. */
  sessionStats() {
    return this.sessionTracker.stats();
  }

  /**
   * Like getActiveAccount, but if the selected account's OAuth token has ALREADY
   * expired it blocks on a refresh before returning — so a caller that injects
   * the token immediately (the MITM relay) never sends a dead token and eats a
   * 401. A token that is merely expiring soon (still valid) is left to the
   * caller's opportunistic background refresh; only a hard-expired one blocks.
   */
  async getActiveAccountFresh(exclude = null, model = null, advisorModel = null, sessionId = null) {
    const account = this.getActiveAccount(exclude, model, advisorModel, sessionId);
    if (account && account.type === 'oauth' && account.refreshToken
        && isTokenExpired(account.expiresAt)) {
      await this.ensureTokenFresh(account.index); // coalesces with any in-flight refresh
    }
    return account;
  }

  /**
   * Read-only: the index of the account a request for `model` would be served by
   * right now — the same decision getActiveAccount makes (manual pin → the global
   * current account if it can serve the model → best-available), but WITHOUT
   * mutating currentIndex and without the exhausted-fleet probe fallback. Returns
   * null when nothing can serve `model` at the moment. The TUI uses this to mark
   * the single account each secondary bucket (Fable/Sonnet) currently routes to —
   * the F7/S7 analogue of the ► that marks the default route's current account.
   */
  previewRouteIndex(model) {
    const pinned = this._pinnedAccountForModel(model);
    if (pinned && this._isAvailable(pinned, model)) return pinned.index;
    const current = this.accounts[this.currentIndex];
    if (current && this._isAvailable(current, model)) return current.index;
    const best = this._selectBest(null, { model });
    return best ? best.index : null;
  }

  _isProbeable(account) {
    if (!account) return false;
    // Never probe an account the operator has taken out of rotation or one
    // whose token is broken — those are hard states, not stale guesses.
    if (account.disabled) return false;
    if (account.status === 'error' || account.status === 'exhausted') return false;
    // A 429 hold is respected verbatim at first, but a hold is a snapshot: the
    // 429 that armed it may itself have been transient (e.g. the retry burst
    // after a network flap), and while it lasts NOTHING revalidates it — so a
    // stale hold pins the fleet in synthetic 429s for up to an hour and only a
    // restart (which wipes the in-memory hold) recovers. After the floor, let
    // the account be probed: the probe's real response either clears the hold
    // (any non-429 → clearRateLimited) or re-arms it with a fresh retry-after.
    if (account.status === 'throttled' && account.rateLimitedUntil
        && Date.now() < account.rateLimitedUntil) {
      return Date.now() >= (account.throttledAt || 0) + this.throttleProbeFloorMs;
    }
    return true;
  }

  /** Highest utilization across the quota dimensions that govern `model` (0-1),
   * used to pick the least-exhausted probe target. Mirrors _isNearQuota: the
   * shared 5-hour bucket plus the model's governing weekly bucket. With no model
   * it falls back to the shared weekly. */
  _maxUtilization(account, model = null) {
    const q = account.quota;
    let max = 0;
    if (q.unified5h != null) max = Math.max(max, q.unified5h);
    const weeklyVal = this._governingWeekly(account, model);
    if (weeklyVal != null) max = Math.max(max, weeklyVal);
    if (q.tokensLimit != null && q.tokensRemaining != null) {
      max = Math.max(max, 1 - q.tokensRemaining / q.tokensLimit);
    }
    if (q.requestsLimit != null && q.requestsRemaining != null) {
      max = Math.max(max, 1 - q.requestsRemaining / q.requestsLimit);
    }
    return max;
  }

  /** Utilization (0-1) of the weekly bucket that governs `model` on this account:
   * unified7dFable for Fable, unified7dSonnet for Sonnet, unified7d otherwise.
   * Falls back to the shared unified7d when a family-specific bucket isn't
   * reported. Returns null when nothing is known. */
  _governingWeekly(account, model) {
    const q = account.quota;
    const key = this._weeklyBucketFor(model);
    if (q[key] != null) return q[key];
    return key !== 'unified7d' ? q.unified7d : null;
  }

  /** Reset timestamp (ms) of the weekly bucket that governs `model`, falling back
   * to the shared weekly reset. Used to spend the soonest-expiring quota first. */
  _governingWeeklyReset(account, model) {
    const q = account.quota;
    const key = this._weeklyBucketFor(model);
    return q[`${key}Reset`] || q.unified7dReset || null;
  }

  /** True when the family-specific weekly bucket that governs `model` is spent.
   * Unlike _isNearQuota this ignores the shared 5h/weekly caps — it is only used
   * to skip an account for a probe of a model it definitely can't serve. Returns
   * false for families without a dedicated bucket (they share unified7d, already
   * covered by _isNearQuota). */
  _modelWeeklyExhausted(account, model) {
    const q = account.quota;
    const key = this._weeklyBucketFor(model);
    if (key === 'unified7d') return false;
    return q[key] != null && q[key] >= this.switchThreshold;
  }

  /**
   * Pick an account to send a single revalidation probe upstream when every
   * account reads as over the switch threshold. Throttled to one probe per
   * probeIntervalMs so a genuinely-exhausted fleet isn't hammered — between
   * probes this returns null and the caller falls back to the synthetic 429.
   * The chosen account is the least-utilized probeable one (most likely to have
   * stale headroom), so the refreshed quota corrects the cache fastest.
   */
  _selectProbe(exclude = null, model = null) {
    const now = Date.now();
    if (now < this._nextProbeAt) return null;

    let best = null;
    let bestPriority = Infinity;
    let bestUsage = Infinity;
    for (const account of this.accounts) {
      if (exclude?.has(account.index)) continue;
      if (!this._isProbeable(account)) continue;
      // A healthy account blocked only by its live 5-hour session window has
      // authoritative near-term exhaustion, not a stale weekly snapshot. Do
      // not probe it until rollover; weekly and aged-throttle evidence remain
      // eligible for bounded revalidation.
      if (account.status !== 'throttled'
          && account.quota.unified5h != null
          && account.quota.unified5h >= this.switchThreshold
          && this._governingWeekly(account, model) == null) continue;
      // A family-exhausted account can't serve that family even as a probe — it
      // would just 429 again — so skip it (Fable/Sonnet) and let the caller emit
      // the synthetic 429 when no other account is available.
      if (model && this._modelWeeklyExhausted(account, model)) continue;
      // Same for routing/ownership: a probe for a routed or owned model must not
      // land on an ineligible account (it would just reject the unknown model id).
      if (model && !this._routeAllows(account, model)) continue;
      const priority = this._priority(account);
      const usage = this._maxUtilization(account, model);
      if (priority < bestPriority ||
          (priority === bestPriority && usage < bestUsage)) {
        bestPriority = priority;
        bestUsage = usage;
        best = account;
      }
    }
    if (!best) return null;

    this._nextProbeAt = now + this.probeIntervalMs;
    this.currentIndex = best.index;
    this._beginRamp(best);
    if (best.status === 'throttled') {
      console.log(`[TeamClaude] All accounts unavailable — revalidating throttled "${best.name}" with a live request`);
    } else {
      console.log(`[TeamClaude] All accounts over threshold — probing "${best.name}" to refresh quota`);
    }
    return best;
  }

  /**
   * WHY this account cannot serve the request right now, as a short stable slug, or
   * null when it can. This is the single source of truth for availability —
   * `_isAvailable` is just `=== null` on it — and `getStatus` publishes the slug as
   * `benchedReason`, so an operator reads the server's own verdict instead of
   * re-deriving it from the quota numbers — a re-derivation silently misses
   * `disabled`, `throttled` and `error`, and calls accounts usable that the server
   * benches. Know the two limits of the published slug: `getStatus` calls this with
   * NO model, so `route`/`advisor-*` cannot appear there (the model-scoped verdict is
   * `routes[].accounts[].eligible`, which passes a sample model), and capacity is not
   * checked here at all — `pausedUntil` and the storm ramp live in `_hasCapacity`, so
   * an account can read `available: true` while admission would still refuse it.
   */
  _unavailableReason(account, model = null, advisorModel = null) {
    if (!account) return 'missing';

    // Manually disabled accounts are skipped entirely until re-enabled.
    if (account.disabled) return 'disabled';

    // Check rate limit expiry
    if (account.status === 'throttled' && account.rateLimitedUntil) {
      if (Date.now() < account.rateLimitedUntil) return 'throttled';
      account.status = 'active';
      account.rateLimitedUntil = null;
      account.throttledAt = null;
      console.log(`[TeamClaude] Account "${account.name}" rate limit expired, marking active`);
    }

    if (account.status === 'exhausted' || account.status === 'error') return account.status;
    // Model-scoped: _isNearQuota checks the shared 5h bucket plus only the weekly
    // bucket that governs this model, so a spent Fable/Sonnet bucket bars just
    // that family — the account still serves every other model normally.
    if (this._isNearQuota(account, model)) return 'quota';

    // Route/ownership restriction: a configured route can pin a model pattern to
    // an exclusive set of accounts; failing that, a per-account `models` claim
    // restricts an owned model to its owners. Either way an account not eligible
    // for this model is skipped so the request never lands somewhere it can't run.
    if (model && !this._routeAllows(account, model)) return 'route';

    // An advisor request additionally needs the account to serve the ADVISOR's
    // model: its family bucket must have headroom (the shared buckets were
    // already checked above for the executor) and any route/ownership rule for
    // it must allow this account.
    if (advisorModel) {
      if (this._modelWeeklyExhausted(account, advisorModel)) return 'advisor-quota';
      if (!this._routeAllows(account, advisorModel)) return 'advisor-route';
    }

    return null;
  }

  _isAvailable(account, model = null, advisorModel = null) {
    return this._unavailableReason(account, model, advisorModel) === null;
  }

  /**
   * Normalize and store the configurable routing table. A route pins a set of
   * model globs to an exclusive set of accounts (and may override the governing
   * quota bucket). Called from the constructor and on config reload.
   *   { name, match: string|string[], accounts?: (name|index)[], bucket? }
   */
  setRoutes(routes) {
    this.routes = (Array.isArray(routes) ? routes : []).map((r, i) => ({
      name: r.name || `route-${i + 1}`,
      match: (Array.isArray(r.match) ? r.match : [r.match]).filter(g => typeof g === 'string' && g),
      accounts: Array.isArray(r.accounts) ? r.accounts.map(String) : [],
      bucket: r.bucket || null,
      color: r.color || null, // display-only accent for the route's inline marker
    })).filter(r => r.match.length);
    // Drop pins for routes that no longer exist after a reload.
    if (this.routePins?.size) {
      const names = new Set(this.routes.map(r => r.name));
      for (const name of [...this.routePins.keys()]) {
        if (name !== 'fable' && name !== 'sonnet' && !names.has(name)) this.routePins.delete(name);
      }
    }
  }

  /** The first configured route whose globs match `model`, or null. */
  _routeForModel(model) {
    if (!model || !this.routes?.length) return null;
    return this.routes.find(r => r.match.some(g => modelGlobMatches(g, model))) || null;
  }

  /** The weekly quota bucket that governs `model` — a matching route's `bucket`
   * override wins, otherwise the model family's default bucket. */
  _weeklyBucketFor(model) {
    const route = this._routeForModel(model);
    return route?.bucket || weeklyBucketForModel(model);
  }

  /** Whether `account` may serve `model`. A matching route with an `accounts`
   * list is exclusive (only listed accounts, by name or index). With no matching
   * route — or a route that lists no accounts — it falls back to the per-account
   * `models` ownership claim so PR #74 configs keep working. */
  _routeAllows(account, model) {
    const route = this._routeForModel(model);
    if (route && route.accounts.length) {
      return route.accounts.includes(account.name) || route.accounts.includes(String(account.index));
    }
    return this._accountOwnsModel(account, model);
  }

  /** Returns true if no account claims model ownership, or this account does. */
  _accountOwnsModel(account, model) {
    for (const a of this.accounts) {
      if (a.models && a.models.some(m => modelMatches(m, model))) {
        // Some other account owns this model — this account must own it too.
        return !!(account.models && account.models.some(m => modelMatches(m, model)));
      }
    }
    return true; // no one claims ownership → any account is fine
  }

  /**
   * The routing table for display: every configured route plus an ephemeral,
   * auto-created route for each model family that some account meters with its
   * own weekly bucket but no configured route already covers. Auto-created routes
   * carry `autocreated: true` and are never persisted — they simply surface the
   * per-model quota the server already respects. Each route lists the accounts it
   * can use with a live eligibility flag.
   */
  getRoutes() {
    const out = this.routes.map(r => ({
      name: r.name, match: r.match, bucket: r.bucket, color: r.color || null, autocreated: false,
      pinned: this._pinnedName(r.name),
      accounts: this._routeAccountsView(r),
    }));

    const detected = [];
    if (this.accounts.some(a => a.quota.unified7dFable != null)) {
      detected.push({ name: 'fable', match: ['*fable*'], sample: 'claude-fable-5' });
    }
    if (this.accounts.some(a => a.quota.unified7dSonnet != null)) {
      detected.push({ name: 'sonnet', match: ['*sonnet*'], sample: 'claude-sonnet-4-6' });
    }
    for (const d of detected) {
      if (this._routeForModel(d.sample)) continue; // already covered by a configured route
      out.push({
        name: d.name, match: d.match, bucket: null, color: null, autocreated: true,
        pinned: this._pinnedName(d.name),
        accounts: this.accounts.map(a => ({ name: a.name, eligible: this._isAvailable(a, d.sample) })),
      });
    }
    return out;
  }

  /** The name of the account this route is manually pinned to, or null. */
  _pinnedName(routeName) {
    const account = this.routePins.get(routeName);
    return account && this.accounts.includes(account) ? account.name : null;
  }

  /** Accounts a configured route can use (all accounts when it lists none), each
   * with a live eligibility flag for a representative model of the route. */
  _routeAccountsView(route) {
    const sample = route.match[0].replace(/\*/g, '') || 'model';
    const inRoute = a => !route.accounts.length
      || route.accounts.includes(a.name) || route.accounts.includes(String(a.index));
    return this.accounts.filter(inRoute).map(a => ({ name: a.name, eligible: this._isAvailable(a, sample) }));
  }

  /** A representative model id for a route name (configured or auto fable/sonnet),
   * used to test route-allowance when pinning. Null for an unknown route. */
  _routeSample(routeName) {
    const r = this.routes.find(x => x.name === routeName);
    if (r) return r.match[0]?.replace(/\*/g, '') || 'model';
    if (routeName === 'fable') return 'claude-fable-5';
    if (routeName === 'sonnet') return 'claude-sonnet-4-6';
    return null;
  }

  /**
   * Manually pin a route to an account (ephemeral runtime override). Rejects an
   * account the route's exclusivity/ownership rules disallow. Pinning an account
   * that is merely near-quota/throttled is allowed — it acts as a preference and
   * routing falls back to best-available until the pinned account is eligible.
   * Returns { ok, reason? }.
   */
  setRoutePin(routeName, accountIndex) {
    const account = this._resolve(accountIndex);
    if (!account || !this.accounts.includes(account)) return { ok: false, reason: 'no such account' };
    const sample = this._routeSample(routeName);
    if (sample && !this._routeAllows(account, sample)) {
      return { ok: false, reason: `route "${routeName}" does not allow "${account.name}"` };
    }
    this.routePins.set(routeName, account);
    return { ok: true };
  }

  clearRoutePin(routeName) { this.routePins.delete(routeName); }

  /** The account a route is pinned to, or null. */
  getRoutePin(routeName) {
    const account = this.routePins.get(routeName);
    return account && this.accounts.includes(account) ? account : null;
  }

  /** The manually-pinned account governing `model`, if any: a configured route's
   * pin wins, else an auto fable/sonnet family pin (only when no configured route
   * covers the model). For an advisor request the executor's pin wins (it is the
   * bulk of the spend); the advisor model's pin applies only when nothing pins
   * the executor. Returns null when nothing is pinned for this model. */
  _pinnedAccountForModel(model, advisorModel = null) {
    return this._pinnedFor(model)
      || (advisorModel ? this._pinnedFor(advisorModel) : null);
  }

  _pinnedFor(model) {
    if (!model || !this.routePins.size) return null;
    const route = this._routeForModel(model);
    if (route) {
      const account = this.routePins.get(route.name);
      return account && this.accounts.includes(account) ? account : null;
    }
    for (const name of ['fable', 'sonnet']) {
      if (this.routePins.has(name) && modelGlobMatches(`*${name}*`, model)) {
        const account = this.routePins.get(name);
        return account && this.accounts.includes(account) ? account : null;
      }
    }
    return null;
  }

  /**
   * Clear any quota counters whose reset time has passed. Cheap and safe to
   * call frequently (e.g. from the TUI render loop) — once a counter is cleared
   * it stays null until the next upstream response repopulates it, so the
   * "reset" log fires at most once per window.
   * @returns {{changed: boolean, session: boolean}} what was cleared.
   */
  _clearExpiredQuotas(account) {
    const q = account.quota;
    const now = Date.now();
    let changed = false;
    let session = false;

    // Clear expired unified quotas
    if (q.unified5hReset && now >= q.unified5hReset) {
      console.log(`[TeamClaude] Account "${account.name}" session quota reset`);
      q.unified5h = null;
      q.unified5hReset = null;
      account._partialProbes = 0;
      account._warmupTries = 0;
      changed = true;
      session = true;
    }
    if (q.unified7dReset && now >= q.unified7dReset) {
      console.log(`[TeamClaude] Account "${account.name}" weekly quota reset`);
      q.unified7d = null;
      q.unified7dReset = null;
      q.unifiedStatus = null;
      account._partialProbes = 0;
      account._warmupTries = 0;
      changed = true;
    }
    if (q.unified7dSonnetReset && now >= q.unified7dSonnetReset) {
      q.unified7dSonnet = null;
      q.unified7dSonnetReset = null;
      changed = true;
    }
    if (q.unified7dFableReset && now >= q.unified7dFableReset) {
      q.unified7dFable = null;
      q.unified7dFableReset = null;
      changed = true;
    }
    for (const [label, window] of Object.entries(q.modelWeekly)) {
      if (window.reset && now >= window.reset) {
        delete q.modelWeekly[label];
        account._mwProbes = 0;
        changed = true;
      }
    }

    // Clear expired standard quotas
    if (q.resetsAt && now >= new Date(q.resetsAt).getTime()) {
      q.tokensRemaining = null;
      q.tokensLimit = null;
      q.requestsRemaining = null;
      q.requestsLimit = null;
      q.resetsAt = null;
      changed = true;
    }

    return { changed, session };
  }

  /**
   * Clear expired quotas across all accounts. Called from the display loop and
   * the request path so a window expiry (e.g. the 5-hour session quota) resets
   * the view instantly rather than waiting for the next request.
   *
   * When an account's session quota resets, it may have become the better
   * choice — switch to it if its weekly limit expires sooner than the current
   * account's (and it still has weekly quota), so we spend the quota closest to
   * refreshing first.
   */
  refreshExpiredQuotas() {
    let changed = false;
    const sessionReset = [];
    for (const account of this.accounts) {
      const r = this._clearExpiredQuotas(account);
      if (r.changed) changed = true;
      if (r.session) sessionReset.push(account);
    }
    if (sessionReset.length) this._switchOnSessionReset(sessionReset);
    return changed;
  }

  /**
   * Given accounts whose session quota just reset, switch to the one whose
   * weekly limit expires soonest — but only if that is sooner than the current
   * account's weekly limit and the account still has weekly quota to spend.
   */
  _switchOnSessionReset(candidates) {
    const current = this.accounts[this.currentIndex];
    // Need a known weekly reset on the current account to compare against;
    // if it is unknown we are still probing it, so leave it alone.
    if (!current || current.quota.unified7dReset == null) return;

    let best = null;
    let bestWeekly = current.quota.unified7dReset;
    for (const acc of candidates) {
      if (acc.index === this.currentIndex) continue;
      if (!this._isAvailable(acc)) continue; // enough session & weekly quota left
      // Don't demote to a lower-priority (higher value) account on a reset.
      if (this._priority(acc) > this._priority(current)) continue;
      const weekly = acc.quota.unified7dReset;
      if (weekly == null) continue; // need a known weekly to compare
      if (weekly < bestWeekly) {
        bestWeekly = weekly;
        best = acc;
      }
    }

    if (best) {
      this.currentIndex = best.index;
      this._beginRamp(best);
      console.log(`[TeamClaude] Account "${best.name}" session quota reset and weekly expires sooner — switching to it`);
    }
  }

  _isNearQuota(account, model = null) {
    const q = account.quota;
    this._clearExpiredQuotas(account);

    // Shared 5-hour bucket gates every request regardless of model.
    if (q.unified5h != null && q.unified5h >= this.switchThreshold) return true;

    // Only the weekly bucket that GOVERNS this model is checked: Fable and Sonnet
    // meter their own weekly quota, so a spent Fable bucket must not bar an Opus
    // or Sonnet request (and vice versa). When the family bucket isn't reported
    // (e.g. the plan doesn't expose it), fall back to the shared weekly so an
    // account over its overall cap is still treated as near-quota.
    const weeklyVal = this._governingWeekly(account, model);
    if (weeklyVal != null && weeklyVal >= this.switchThreshold) return true;

    // Standard quotas (API key accounts)
    if (q.tokensLimit != null && q.tokensRemaining != null) {
      const used = 1 - (q.tokensRemaining / q.tokensLimit);
      if (used >= this.switchThreshold) return true;
    }

    if (q.requestsLimit != null && q.requestsRemaining != null) {
      const used = 1 - (q.requestsRemaining / q.requestsLimit);
      if (used >= this.switchThreshold) return true;
    }

    return false;
  }

  /**
   * Pick the best available account by selection order, WITHOUT mutating state:
   *   1. explicit finite `priority` values (lower = preferred; unranked = Infinity)
   *   2. then the account with no known weekly limit — using it lets us
   *      discover its quota
   *   3. then the account whose weekly limit expires soonest: that quota is
   *      closest to refreshing, so spending it first preserves accounts whose
   *      weekly window resets further out.
   * With every account unranked, this reduces to the weekly-reset heuristic.
   * Returns the account or null if none are available.
   */
  _pickBestAvailable(exclude = null, model = null, advisorModel = null) {
    return this._selectBest(exclude, { model, advisorModel });
  }

  /**
   * Select the active account up front (e.g. on daemon launch, once persisted
   * quota has been restored) so we start on the highest-priority / soonest-
   * resetting account instead of blindly on index 0. Mirrors rotation order.
   * Returns the chosen account, or the existing current one if none are
   * available (the server still starts; requests 429 until a window resets).
   */
  selectActiveAccount() {
    this.refreshExpiredQuotas(); // drop any restored windows that already expired
    const best = this._pickBestAvailable();
    if (!best) return this.accounts[this.currentIndex] || null;
    this.currentIndex = best.index;
    this._beginRamp(best);
    best.probing = best.quota.unified7dReset == null;
    const wk = best.quota.unified7d != null
      ? `${(best.quota.unified7d * 100).toFixed(1)}% weekly used`
      : 'weekly quota unknown';
    console.log(`[TeamClaude] Starting on account "${best.name}" (priority ${best.priority ?? 'auto'}, ${wk})`);
    return best;
  }


  /**
   * Update an account's quota tracking from upstream response headers.
   */
  updateQuota(accountOrIndex, headers) {
    const account = this._resolveLive(accountOrIndex);
    if (!account) return;

    const observedAt = Date.now();
    const updateUnified = (bucket, utilizationKey, resetKey, utilizationHeader, resetHeader) => {
      const utilization = finiteHeaderNumber(headers[utilizationHeader]);
      const reset = finiteHeaderNumber(headers[resetHeader]);
      observeUnifiedBucket(account.quota, bucket, utilizationKey, resetKey, null, {
        utilization: Number.isFinite(utilization) ? utilization : null,
        reset: Number.isFinite(reset) ? reset * 1000 : null,
      }, 'response', observedAt);
    };
    updateUnified('5h', 'unified5h', 'unified5hReset',
      'anthropic-ratelimit-unified-5h-utilization', 'anthropic-ratelimit-unified-5h-reset');
    updateUnified('7d', 'unified7d', 'unified7dReset',
      'anthropic-ratelimit-unified-7d-utilization', 'anthropic-ratelimit-unified-7d-reset');
    updateUnified('7d_oi', 'unified7dFable', 'unified7dFableReset',
      'anthropic-ratelimit-unified-7d_oi-utilization', 'anthropic-ratelimit-unified-7d_oi-reset');

    for (const [key, value] of Object.entries(headers)) {
      const m = /^anthropic-ratelimit-unified-(7d_[a-z0-9_]+)-(utilization|reset)$/.exec(key);
      if (!m) continue;
      const field = m[2] === 'utilization' ? 'utilization' : 'reset';
      const numeric = finiteHeaderNumber(value);
      if (!Number.isFinite(numeric)) continue;
      const normalized = field === 'reset' ? Math.trunc(numeric) * 1000 : numeric;
      const window = account.quota.modelWeekly[m[1]] ||= { utilization: null, reset: null };
      const accepted = observeQuotaField(account.quota, `model:${m[1]}`, field, normalized, 'response', observedAt);
      if (accepted) window[field] = normalized;
      if (accepted && field === 'utilization') {
        const resetObservation = account.quota.observations[`model:${m[1]}`]?.reset;
        if (resetObservation && resetObservation.observedAt < observedAt) {
          window.reset = null;
          delete account.quota.observations[`model:${m[1]}`].reset;
        }
      }
    }

    // We switched to this account to discover its weekly quota; now that we
    // know it, flag for re-evaluation so selection can pick the best account.
    if (account.probing && account.quota.unified7dReset != null) {
      account.probing = false;
      account.requalify = true;
      console.log(`[TeamClaude] Learned weekly quota for "${account.name}", re-evaluating selection`);
    }

    const uStatus = headers['anthropic-ratelimit-unified-status']
      || headers['anthropic-ratelimit-unified-5h-status'];
    if (observeQuotaField(account.quota, 'unified', 'status', uStatus, 'response', observedAt)) account.quota.unifiedStatus = uStatus;

    // Standard rate limits (API key accounts)
    const tokensLimit = parseInt(headers['anthropic-ratelimit-tokens-limit'], 10);
    const tokensRemaining = parseInt(headers['anthropic-ratelimit-tokens-remaining'], 10);
    const tokensReset = headers['anthropic-ratelimit-tokens-reset'];
    const requestsLimit = parseInt(headers['anthropic-ratelimit-requests-limit'], 10);
    const requestsRemaining = parseInt(headers['anthropic-ratelimit-requests-remaining'], 10);
    const requestsReset = headers['anthropic-ratelimit-requests-reset'];

    if (!isNaN(tokensLimit)) account.quota.tokensLimit = tokensLimit;
    if (!isNaN(tokensRemaining)) account.quota.tokensRemaining = tokensRemaining;
    if (!isNaN(requestsLimit)) account.quota.requestsLimit = requestsLimit;
    if (!isNaN(requestsRemaining)) account.quota.requestsRemaining = requestsRemaining;

    if (tokensReset) account.quota.resetsAt = tokensReset;
    else if (requestsReset) account.quota.resetsAt = requestsReset;

    account.usage.totalRequests++;
    account.usage.lastUsed = new Date().toISOString();

    // Log when approaching quota
    if (this._isNearQuota(account)) {
      const pct = account.quota.unified7d != null
        ? (account.quota.unified7d * 100).toFixed(1)
        : account.quota.tokensLimit
          ? ((1 - account.quota.tokensRemaining / account.quota.tokensLimit) * 100).toFixed(1)
          : '?';
      console.log(`[TeamClaude] Account "${account.name}" at ${pct}% usage — will switch on next request`);
    }
  }

  /**
   * Update cumulative token usage from response body data.
   */
  updateUsage(accountOrIndex, inputTokens, outputTokens) {
    const account = this._resolveLive(accountOrIndex);
    if (!account) return;
    if (inputTokens) account.usage.totalInputTokens += inputTokens;
    if (outputTokens) account.usage.totalOutputTokens += outputTokens;
  }

  /**
   * Enable or disable an account. A disabled account is skipped by rotation
   * until re-enabled. Re-enabling also clears a stuck 'error' state (and any
   * lingering rate-limit hold) so the account is retried immediately.
   */
  setDisabled(accountIndex, disabled) {
    const account = this.accounts[accountIndex];
    if (!account) return;
    account.disabled = disabled;
    if (!disabled && account.status === 'error') {
      account.status = 'active';
      account.rateLimitedUntil = null;
      console.log(`[TeamClaude] Account "${account.name}" re-enabled — clearing error state`);
    }
  }

  /**
   * Apply quota learned from the OAuth usage endpoint (the background probe).
   * Updates utilization/reset for the 5h, 7d, Sonnet-7d, and Fable-7d buckets WITHOUT
   * touching usage counters — a probe is not real client traffic.
   */
  applyUsageData(accountIndex, usage) {
    const account = this.accounts[accountIndex];
    if (!account || !usage) return;
    const q = account.quota;

    const observedAt = Date.now();
    const apply = (bucket, utilizationKey, resetKey, value) => {
      if (!value) return;
      observeUnifiedBucket(q, bucket, utilizationKey, resetKey, null, {
        utilization: Number.isFinite(value.utilization) ? value.utilization : null,
        reset: Number.isFinite(value.resetAt) ? value.resetAt : null,
      }, 'usage', observedAt);
    };
    apply('5h', 'unified5h', 'unified5hReset', usage.fiveHour);
    apply('7d', 'unified7d', 'unified7dReset', usage.sevenDay);
    apply('7d_sonnet', 'unified7dSonnet', 'unified7dSonnetReset', usage.sevenDaySonnet);
    apply('7d_oi', 'unified7dFable', 'unified7dFableReset', usage.sevenDayFable);

    // If we just learned this account's weekly window while probing, re-evaluate
    // selection (same path as learning it from a live response).
    if (account.probing && q.unified7dReset != null) {
      account.probing = false;
      account.requalify = true;
    }
  }

  /**
   * Mark an account as rate-limited for a given duration.
   */
  markRateLimited(accountOrIndex, retryAfterSeconds) {
    const account = this._resolveLive(accountOrIndex);
    if (!account) return;
    account.status = 'throttled';
    account.rateLimitedUntil = Date.now() + (retryAfterSeconds * 1000);
    // Marks when the hold was (re-)armed: a revalidation probe is allowed only
    // after throttleProbeFloorMs from here, so a probe that 429s again pushes
    // the next probe out by a full floor rather than hammering upstream.
    account.throttledAt = Date.now();
    console.log(`[TeamClaude] Account "${account.name}" rate limited for ${retryAfterSeconds}s`);
  }

  /**
   * Clear a rate-limit hold after live proof it no longer binds: any non-429
   * upstream response on a throttled account (a revalidation probe reaching
   * here, or a hold armed moments before traffic resumed). No-op otherwise.
   */
  clearRateLimited(accountOrIndex) {
    const account = this._resolveLive(accountOrIndex);
    if (!account || account.status !== 'throttled') return;
    account.status = 'active';
    account.rateLimitedUntil = null;
    account.throttledAt = null;
    console.log(`[TeamClaude] Account "${account.name}" revalidated — rate limit no longer applies, back in rotation`);
  }

  /**
   * Ensure an OAuth account's token is fresh, refreshing if needed.
   * Pass force=true to refresh regardless of expiry (e.g. after a 401).
   * Concurrent calls for the same account coalesce into a single refresh.
   */
  async ensureTokenFresh(accountOrIndex, force = false) {
    const account = this._resolveLive(accountOrIndex);
    if (!account || account.type !== 'oauth' || !account.refreshToken) return { ok: true };

    if (!force && !isTokenExpiringSoon(account.expiresAt)) return { ok: true };

    // A forced refresh answers a 401, but 401s arrive in bursts: every request
    // already in flight when the token went bad comes back rejected, and each
    // one would force its own refresh. Coalescing only covers refreshes that
    // OVERLAP — these arrive staggered, so they would rotate the refresh-token
    // family once per request and make the proxy the very "other holder
    // rotating the family" that causes this failure in the first place. A 401
    // for a token minted moments ago is stale news from a request sent before
    // the refresh landed, so trust the new token and let the caller retry with
    // it. Only an expiry-driven refresh (force=false) bypasses this — it isn't
    // reacting to a response and can't stampede.
    if (force && account._lastRefreshAt !== null
        && Date.now() - account._lastRefreshAt < this._forcedRefreshFloorMs) {
      // `suppressed` lets callers that follow a forced refresh with a retry
      // (the usage prober) know no new token was minted — retrying with the
      // same credential is guaranteed to repeat the 401.
      return { ok: true, suppressed: true };
    }

    // Coalesce concurrent refreshes
    if (account._refreshPromise) return account._refreshPromise;

    account._refreshPromise = (async () => {
      console.log(`[TeamClaude] Refreshing token for account "${account.name}"...`);
      try {
        const newTokens = await this._refreshFn(account.refreshToken);
        account.credential = newTokens.accessToken;
        account.refreshToken = newTokens.refreshToken;
        account.expiresAt = newTokens.expiresAt;
        account._lastRefreshAt = Date.now();
        // A successful refresh heals ONLY a refresh-caused 'error' (a refresh
        // that failed while e.g. the network was down): the refresh succeeding
        // is exactly the thing that failed, so the account rejoins rotation
        // without a proxy restart. An error set by the REQUEST path (upstream
        // 401 despite a fresh token, non-transient send failure — see server.js)
        // is NOT cleared here: the token endpoint accepting a rotation does not
        // prove the API accepts the account, and blanket-reviving it would flap
        // it back into rotation to fail real client requests every sweep. Those
        // heal only via new credentials (updateAccountTokens) or a restart.
        if (account.status === 'error' && account._errorFromRefresh) {
          account.status = 'active';
          delete account._errorFromRefresh;
        }
        console.log(`[TeamClaude] Token refreshed for account "${account.name}"`);
        if (this.accounts[account.index] === account) this._onTokenRefresh?.(account.index, newTokens);
        return { ok: true };
      } catch (err) {
        console.error(`[TeamClaude] Token refresh failed for "${account.name}": ${err.message}`);
        // Park the account only when it is actually unusable: a GENUINE auth
        // rejection (the refresh token is dead — revoked, or invalidated by an
        // account/plan migration), or a refresh failure on an already-expired
        // access token (nothing valid left to serve with). A transient failure
        // (network, 5xx, timeout) on a still-valid token must NOT sideline a
        // healthy account — keep the token and retry on the next request; this
        // is what kept accounts wrongly "errored" after a momentary blip.
        // Either park is tagged refresh-caused so the keep-alive sweep revives
        // it the moment a refresh succeeds — but only on the TRANSITION: if the
        // account was already 'error' from the request path (upstream 401 /
        // send failure), a later failed sweep refresh must not relabel it, or
        // the next successful refresh would wrongly revive a rejected account.
        const isAuthRejection = err.status === 400 || err.status === 401 || err.status === 403;
        // isTokenExpired normalizes seconds-vs-milliseconds; a raw comparison
        // here reads a seconds-valued still-valid token as expired, parks the
        // account on a transient blip, and the sweep (which normalizes) then
        // sees a valid token and never attempts the heal — a permanent park.
        const accessExpired = !account.expiresAt || isTokenExpired(account.expiresAt);
        if (isAuthRejection || accessExpired) {
          if (account.status !== 'error') {
            account.status = 'error';
            account._errorFromRefresh = true;
          }
          if (isAuthRejection) console.error(`[TeamClaude] Account "${account.name}" needs re-login (refresh token rejected) — run: teamclaude login`);
        }
        return { ok: false, error: err.message };
      } finally {
        account._refreshPromise = null;
      }
    })();

    return account._refreshPromise;
  }

  /**
   * Periodic token keep-alive + recovery sweep (ported from teamclaude-cloud's
   * recovery timer). Anthropic rotates the refresh token on every refresh, and a
   * chain that never rotates — an account that sits idle because no client
   * traffic routes there, while warm-up probes deliberately never refresh
   * tokens — can eventually be invalidated upstream, permanently killing the
   * account until a manual re-login. This sweep keeps every account's chain
   * rotating even with zero traffic:
   *  - an OAuth account whose access token is expiring (or already expired) is
   *    refreshed proactively — that's ~once per access-token lifetime, NOT once
   *    per tick (a fresh token is a no-op inside ensureTokenFresh);
   *  - an account stuck in 'error' is swept too, so even a parked account's
   *    chain stays alive — but only a REFRESH-caused error is returned to
   *    rotation on success (see ensureTokenFresh; an upstream-auth error stays
   *    parked). An account whose refresh token is genuinely revoked just stays
   *    'error' (one failed attempt per sweep) until re-imported / re-logged-in.
   * Disabled accounts are swept too: disable means "out of rotation", not "let
   * the token chain die" — re-enabling must yield a working account.
   * Refreshes run SEQUENTIALLY (not Promise.all): a fleet-wide lapse after long
   * downtime must not burst N concurrent POSTs at the token endpoint — a
   * provider rate-limit there could fail every refresh and error the whole
   * fleet. Overlapping sweeps are skipped (`_sweepInFlight`); a slow sweep is
   * bounded by the per-refresh timeout, and coalescing keeps a concurrent
   * request-path refresh safe either way.
   * Never throws; failures are handled (and classified) inside ensureTokenFresh.
   * Returns the number of accounts selected for a refresh attempt (an attempt
   * may still no-op inside ensureTokenFresh, e.g. a parked account whose token
   * is not yet expiring).
   */
  async refreshLapsedTokens() {
    if (this._sweepInFlight) return 0;
    this._sweepInFlight = true;
    try {
      const targets = this.accounts.filter(a =>
        a.type === 'oauth' && a.refreshToken
        && (a.status === 'error' || !a.expiresAt || isTokenExpiringSoon(a.expiresAt)));
      for (const a of targets) {
        // Non-forced is enough for every lapsed token (ensureTokenFresh's own
        // expiry gate passes); it also makes an 'error' account with a
        // still-valid token a no-op — no pointless rotation churn each sweep.
        // Force only when the expiry is UNKNOWN (no expiresAt): the non-forced
        // gate would never fire for it (isTokenExpiringSoon(null) is false), so
        // its chain would silently lapse. One successful refresh learns the
        // real expiry and moves the account onto the normal non-forced path.
        await this.ensureTokenFresh(a, !a.expiresAt)
          .catch(() => { /* stays error until the refresh token heals */ });
      }
      return targets.length;
    } finally {
      this._sweepInFlight = false;
    }
  }

  /**
   * Set a callback to persist refreshed tokens to config.
   */
  onTokenRefresh(callback) {
    this._onTokenRefresh = callback;
  }

  /**
   * Update a specific account's OAuth tokens (e.g. after intercepting a token refresh).
   */
  updateAccountTokens(accountIndex, { accessToken, refreshToken, expiresAt }) {
    const account = this._resolveLive(accountIndex);
    if (!account || account.type !== 'oauth') return;

    account.credential = accessToken;
    if (refreshToken) account.refreshToken = refreshToken;
    account.expiresAt = expiresAt;
    // New externally-supplied credentials are a verified heal for ANY error
    // cause (unlike the sweep's refresh-success, which only heals refresh-caused
    // errors) — the auth material actually changed.
    if (account.status === 'error') { account.status = 'active'; delete account._errorFromRefresh; }
    console.log(`[TeamClaude] Updated tokens for account "${account.name}"`);
    if (this.accounts[account.index] === account) this._onTokenRefresh?.(account.index, {
      accessToken,
      refreshToken: account.refreshToken,
      expiresAt: account.expiresAt,
    });
  }

  /**
   * Add a new account at runtime.
   */
  addAccount(acctData) {
    const index = this.accounts.length;
    const account = makeAccount(acctData, index);
    account.maxConcurrent = coerceMaxConcurrent(acctData.maxConcurrent, this.maxConcurrentDefault);
    createIdentityRegistry([...this.accounts, account]);
    this.accounts.push(account);
    this._drainWaiters();
    return index;
  }

  /**
   * Replace a published account with a fresh canonical identity without changing
   * the object held by in-flight requests. The retired object remains releasable;
   * new selection sees only the replacement.
   */
  replaceAccount(accountOrIndex, acctData) {
    const previous = this._resolve(accountOrIndex);
    if (!previous || !this.accounts.includes(previous)) return null;
    const replacement = makeAccount(acctData, previous.index);
    replacement.maxConcurrent = coerceMaxConcurrent(acctData.maxConcurrent, this.maxConcurrentDefault);
    const prospective = [...this.accounts];
    prospective[previous.index] = replacement;
    createIdentityRegistry(prospective);
    replacement.quota = {
      ...emptyQuota(),
      ...previous.quota,
      modelWeekly: Object.fromEntries(Object.entries(previous.quota.modelWeekly || {}).map(([key, value]) => [key, { ...value }])),
    };
    replacement.usage = { ...previous.usage };
    replacement.rateLimitedUntil = previous.rateLimitedUntil;
    replacement.throttledAt = previous.throttledAt;
    replacement.status = previous.status;
    replacement.probing = previous.probing;
    replacement.pausedUntil = previous.pausedUntil;
    replacement.rampStartedAt = previous.rampStartedAt;
    // Retired requests still hold slots. Seed the replacement with that occupancy
    // and mirror each retired release below, so copy-on-write identity changes
    // cannot admit more than the account's cap.
    replacement.inFlight = previous.inFlight;
    previous._replacement = replacement;
    this.accounts[previous.index] = replacement;
    for (const [name, account] of this.routePins) {
      if (account === previous) this.routePins.set(name, replacement);
    }
    for (const [sessionId, account] of this._sessionAccounts) {
      if (account === previous) this._sessionAccounts.set(sessionId, replacement);
    }
    this._drainWaiters();
    return replacement;
  }
  /**
   * Remove an account by index.
   */
  removeAccount(index) {
    if (index < 0 || index >= this.accounts.length) return;
    const removed = this.accounts[index];
    this.accounts.splice(index, 1);
    this.accounts.forEach((account, i) => { account.index = i; });
    if (this.currentIndex >= this.accounts.length) this.currentIndex = Math.max(0, this.accounts.length - 1);
    else if (this.currentIndex > index) this.currentIndex--;
    for (const [name, account] of this.routePins) {
      if (account === removed) this.routePins.delete(name);
    }
  }

  /**
   * Serialize credential-free runtime state keyed exclusively by canonical
   * AccountId. This is the only shape used by the v2 durable-state writer.
   */
  exportCanonicalState(template = null) {
    const accounts = {};
    for (const account of this.accounts) {
      const quota = {};
      for (const field of PERSISTED_QUOTA_FIELDS) quota[field] = account.quota[field];
      const state = {
        quota: { ...quota, modelWeekly: Object.fromEntries(Object.entries(account.quota.modelWeekly || {}).map(([key, value]) => [key, { ...value }])) },
        usage: { ...account.usage },
      };
      if (Number.isFinite(account.rateLimitedUntil)) state.throttle = { until: account.rateLimitedUntil };
      accounts[account.accountIdKey] = state;
    }
    return {
      accounts,
      activeAccountId: this.accounts[this.currentIndex]?.accountIdKey || null,
      template,
    };
  }

  /** Restore a validated canonical state. Unknown/departed identities are ignored. */
  restoreCanonicalState(state) {
    if (!state || typeof state !== 'object' || !state.accounts || typeof state.accounts !== 'object') return;
    const byId = new Map(this.accounts.map(account => [account.accountIdKey, account]));
    for (const [id, snapshot] of Object.entries(state.accounts)) {
      const account = byId.get(id);
      if (!account || !snapshot || typeof snapshot !== 'object') continue;
      if (snapshot.quota && typeof snapshot.quota === 'object') {
        account.quota = { ...emptyQuota(), ...snapshot.quota, unifiedStatus: null,
          observations: {},
          modelWeekly: Object.fromEntries(Object.entries(snapshot.quota.modelWeekly || {}).map(([key, value]) => [key, { ...value }])) };
        const migratedAt = Date.now();
        for (const [bucket, utilizationKey, resetKey] of [
          ['5h', 'unified5h', 'unified5hReset'],
          ['7d', 'unified7d', 'unified7dReset'],
          ['7d_sonnet', 'unified7dSonnet', 'unified7dSonnetReset'],
          ['7d_oi', 'unified7dFable', 'unified7dFableReset'],
        ]) {
          observeQuotaField(account.quota, bucket, 'utilization', account.quota[utilizationKey], 'migration', migratedAt);
          observeQuotaField(account.quota, bucket, 'reset', account.quota[resetKey], 'migration', migratedAt);
        }
      }
      if (snapshot.usage && typeof snapshot.usage === 'object') account.usage = { ...account.usage, ...snapshot.usage };
      const until = snapshot.throttle?.until;
      if (Number.isFinite(until) && until > Date.now()) {
        account.rateLimitedUntil = until;
        account.status = 'throttled';
      }
      if (account.quota.unified7dReset != null) account.probing = false;
    }
    const active = byId.get(state.activeAccountId);
    if (active) this.currentIndex = active.index;
  }

  /**
   * Compatibility migration input for pre-v2 quota cache files. It is deliberately
   * read-only and requires exact canonical identity, never UUID/name guessing.
   */
  importQuotaState(saved) {
    for (const snapshot of Array.isArray(saved) ? saved : []) {
      if (!snapshot || typeof snapshot !== 'object') continue;
      const account = this.accounts.find(candidate => sameIdentity(snapshot, candidate));
      if (!account) continue;
      this.restoreCanonicalState({
        accounts: { [account.accountIdKey]: {
          quota: snapshot.quota,
          usage: snapshot.usage,
          throttle: Number.isFinite(snapshot.rateLimitedUntil) ? { until: snapshot.rateLimitedUntil } : undefined,
        } },
        activeAccountId: null,
      });
    }
  }


  /**
   * Return a status summary of all accounts (safe to expose, no credentials).
   */
  _resolveRef(ref) {
    if (typeof ref === 'string') return this.accounts.find(account => account.name === ref) || null;
    return ref && typeof ref === 'object' && this.accounts.includes(ref) ? ref : null;
  }

  _reprioritize() {
    const current = this.accounts[this.currentIndex];
    const best = this._selectBest();
    if (!best || best === current || (this._isAvailable(current) && !this._strictlyPrefer(best, current))) return;
    this.currentIndex = best.index;
    this.lastEvalAt = Date.now();
  }

  _strictlyPrefer(a, b) { return this._priority(a) < this._priority(b) || (this._priority(a) === this._priority(b) && this.autoCompare(a, b) < 0); }

  setEnabled(ref, enabled) {
    // Legacy object/name handles are reindex-safe. The older TUI passes an
    // API-key account index; accept that compatibility form without exposing
    // numeric mutation for OAuth account handles.
    const account = typeof ref === 'number' && this.accounts[ref]?.type === 'apikey'
      ? this.accounts[ref] : this._resolveRef(ref);
    if (!account) return null;
    account.enabled = enabled !== false;
    this._drainWaiters(); this._reprioritize();
    return account;
  }

  setPriority(ref, priority) {
    const account = this._resolveRef(ref);
    if (!account) return null;
    account.priority = Number.isFinite(priority) ? Math.floor(priority) : null;
    this._reprioritize();
    return account;
  }


  getStatus() {
    const sessions = this.sessionTracker.stats();
    return {
      currentAccount: this.accounts[this.currentIndex]?.name,
      switchThreshold: this.switchThreshold,
      routes: this.getRoutes(),
      sessions: { ...sessions, distribute: this.distributeSessions },
      accounts: this.accounts.map(a => {
        const benchedReason = this._unavailableReason(a);
        return {
        name: a.name,
        type: a.type,
        orgName: a.orgName || null,
        priority: a.priority ?? null,
        enabled: !a.disabled,
        disabled: a.disabled || false,
        status: a.status,
        // The server's OWN rotation verdict, not a number to re-interpret. `status` is
        // not a substitute: an account reading `active` is still benched when it is
        // over threshold. Scope: rotation eligibility WITHOUT a model — not capacity
        // (see inflight below) and not per-model routing (see routes[].accounts[]).
        available: benchedReason === null,
        benchedReason,
        sessions: sessions.perAccount[a.index] || 0,
        // Slot occupancy. `sessions` counts pinned sessions, most of them idle between
        // turns, so it cannot say whether requests are queueing behind a full account —
        // and no surface reported this before, the TUI included. Note maxConcurrent is
        // the CONFIGURED cap: _hasCapacity admits on min(maxConcurrent, _rampCap) and
        // also gates on pausedUntil, so an account can be at its effective limit while
        // inflight still reads below this number.
        inflight: a.inflight,
        maxConcurrent: a.maxConcurrent,
        quota: { ...a.quota, modelWeekly: Object.fromEntries(Object.entries(a.quota.modelWeekly || {}).map(([key, value]) => [key, { ...value }])) },
        usage: { ...a.usage },
        rateLimitedUntil: a.rateLimitedUntil
          ? new Date(a.rateLimitedUntil).toISOString()
          : null,
        pausedUntil: a.pausedUntil && a.pausedUntil > Date.now()
          ? new Date(a.pausedUntil).toISOString()
          : null,
        };
      }),
    };
  }
}
