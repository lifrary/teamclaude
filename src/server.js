import http from 'node:http';
import https from 'node:https';
import { timingSafeEqual } from 'node:crypto';
import { writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { ensureCerts, createConnectHandler } from './mitm.js';
import { patchAccountUuid } from './account-uuid-rewrite.js';
import { parseRequestModel, parseAdvisorModel, weeklyBucketForModel } from './model.js';
import { sanitizeToolPairs } from './tool-pair-sanitize.js';
import { upstreamFetch } from './upstream-fetch.js';
import { connectThroughProxy, tunnelTls } from './sx.js';
import { isTokenExpiringSoon, normalizeExpiresAt } from './oauth.js';
import { parseAccountIdKey, resolveAccount } from './identity.js';
import { MaintenanceCoordinator } from './maintenance-coordinator.js';


const HOP_BY_HOP_HEADERS = new Set([
  'host', 'connection', 'keep-alive', 'transfer-encoding',
  'te', 'trailer', 'upgrade', 'proxy-authorization', 'proxy-authenticate',
]);
const CONNECTION_SPECIFIC_HEADERS = new Set([
  'connection', 'keep-alive', 'transfer-encoding', 'upgrade',
  'proxy-connection', 'te', 'trailer',
]);


function admissionShape(req, ctx) {
  const route = (req.url || '').split('?')[0];
  const pin = ctx.pinnedAccount?.accountIdKey || null;
  return JSON.stringify([ctx.model || null, ctx.advisorModel || null, route, pin]);
}
function createLiveRequestContext(req, body, {
  queueTimeoutMs = 15_000,
  abortSignal = null,
  affinityKey = null,
  pinnedAccount = null,
  transport = null,
} = {}) {
  const sanitizedBody = sanitizeToolPairs(body, req.url, req.headers['content-type']);
  const sessionHeader = req.headers['x-claude-code-session-id'];
  const sessionId = Array.isArray(sessionHeader) ? sessionHeader[0] : sessionHeader;
  const model = parseRequestModel(sanitizedBody);
  const advisorModel = parseAdvisorModel(sanitizedBody);
  return {
    body: sanitizedBody,
    model,
    advisorModel,
    sessionId: typeof sessionId === 'string' && sessionId ? sessionId : null,
    account: null,
    status: null,
    authRetried: new Set(),
    tried429: new Set(),
    tried5xx: new Set(),
    tried403: new Set(),
    overloadRetries: 0,
    held: null,
    queueTimeoutMs,
    abortSignal,
    affinityKey,
    sawModelWeekly: false,
    pinnedAccount,
    transport,
    holdUntil: null,
    sessionRecorded: false,
  };
}

export function safeKeyEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

export function isLoopbackAddr(addr) {
  return addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1';
}
const RETRY_AFTER_FALLBACK_SECONDS = 60;
const RETRY_AFTER_MAX_SECONDS = 300;
// A concurrency cap frees the moment an in-flight request finishes — seconds, not the
// minute a quota window needs. Both capped-fleet 429s (pinned and general) use this,
// so the two cannot drift apart the way their messages once did.
const CAPPED_RETRY_AFTER_SECONDS = 1;
// Sleep PAST a throttle deadline, never exactly to it. `setTimeout` fires on libuv's
// cached loop clock while the availability check re-reads `Date.now()`, and a loaded
// event loop leaves that cache behind wall time — so the sleep can return while the
// account still reads `throttled`. With `maxRetries = accounts.length`, a one-account
// fleet spends its entire retry budget on that single early wake and answers 429 after
// having waited the full window. Margin is negligible against waits measured in
// seconds. (Same class as the `_drainWaiters` pause boundary: sleep to a deadline,
// then re-read a different clock and find it has not arrived.)
const THROTTLE_WAKE_MARGIN_MS = 5;
const MODEL_RESPONSE_BUCKETS = Object.freeze({
  unified7dFable: '7d_oi',
  unified7dSonnet: '7d_sonnet',
});

export function parseRetryAfter(value, now = Date.now()) {
  if (typeof value !== 'string') return RETRY_AFTER_FALLBACK_SECONDS;
  const scalar = value.trim();
  let seconds;
  if (/^-?\d+$/.test(scalar)) {
    seconds = Number(scalar);
  } else if (/^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(scalar)) {
    const when = Date.parse(scalar);
    seconds = Number.isFinite(when) ? Math.ceil((when - now) / 1000) : NaN;
  } else {
    seconds = NaN;
  }
  if (!Number.isFinite(seconds)) return RETRY_AFTER_FALLBACK_SECONDS;
  return Math.min(Math.max(seconds, 1), RETRY_AFTER_MAX_SECONDS);
}

function isBindingModelBucket(headers, model, threshold) {
  const label = MODEL_RESPONSE_BUCKETS[weeklyBucketForModel(model)];
  if (!label) return false;
  const utilization = Number.parseFloat(headers[`anthropic-ratelimit-unified-${label}-utilization`]);
  return Number.isFinite(utilization) && utilization >= threshold;
}

/**
 * Classify only the current 429 response. Account status/quota cache is
 * deliberately excluded: retained headers cannot classify a later response.
 */
export function classify429(headers, { model = null, advisorModel = null, switchThreshold = 0.98 } = {}) {
  const shared5hRejected = headers['anthropic-ratelimit-unified-5h-status'] === 'rejected';
  const modelBinding = isBindingModelBucket(headers, model, switchThreshold)
    || isBindingModelBucket(headers, advisorModel, switchThreshold);
  const unifiedRejected = headers['anthropic-ratelimit-unified-status'] === 'rejected';
  if (shared5hRejected || (unifiedRejected && !modelBinding)) return 'account-quota';
  if (modelBinding) return 'model-quota';
  return 'residual';
}

export function createProxyServer(accountManager, config, hooks = {}, sx = null) {
  const upstream = config.upstream || 'https://api.anthropic.com';
  const proxyApiKey = config.proxy?.apiKey;
  const logDir = config.logDir || null;
  // How long a request may wait for a per-account concurrency slot to free when
  // every available account is at its cap, before giving up with a 429. 0 = never
  // queue (fail fast). Default 15s.
  const queueTimeoutMs = Number.isFinite(config.overflowQueueTimeoutMs)
    ? Math.max(0, config.overflowQueueTimeoutMs)
    : 15000;
  // Cap the buffered request body. The proxy must buffer the whole body to replay
  // it across accounts on a 429/5xx, so an unbounded body is an unbounded buffer.
  const maxBodyBytes = Number.isFinite(config.maxRequestBytes) && config.maxRequestBytes > 0
    ? config.maxRequestBytes
    : 32 * 1024 * 1024;
  // Connection affinity: keep one client connection's sequential requests on the
  // same account for prompt-cache locality (HTTP/1.1 keep-alive reuses the socket
  // for a session's sequential turns). Soft — overflow still spreads. Set
  // `sessionAffinity: false` to route purely by use-or-lose every request instead.
  const sessionAffinity = config.sessionAffinity !== false;
  const transport = {
    sx,
    fetchImpl: hooks.fetch || null,
    headersTimeoutMs: positiveTimeout(config.upstreamHeadersTimeoutMs ?? config.headersTimeoutMs),
    bodyTimeoutMs: positiveTimeout(config.upstreamBodyTimeoutMs ?? config.bodyTimeoutMs),
    holdMs: positiveTimeout(config.holdMs) ?? Math.max(0, Number(config.holdSeconds) || 0) * 1000,
  };
  let requestCounter = 0;

  if (logDir) {
    mkdir(logDir, { recursive: true }).catch(() => {});
  }

  // ── Active warm-up ─────────────────────────────────────────────────────────
  // Quota is only learned from real upstream rate-limit headers (Anthropic has no
  // "get my quota" endpoint), so a freshly (re)started proxy shows the whole fleet
  // as "—" until client traffic happens to flow through every account. Active
  // warm-up fixes that: it stages a request template from the first genuine
  // /v1/messages and COMMITS it only after upstream accepts that request (2xx) —
  // so a model/header combo upstream would reject can't seed a template that makes
  // every probe fail. The committed template (exact model + anthropic-version +
  // anthropic-beta + Claude-Code system) is replayed as a minimal probe
  // (max_tokens: 1) against each still-unmeasured account to populate its quota.
  // It fans out once the instant the template commits (right after the first
  // post-restart request) AND periodically (config.warmupIntervalMs, default 5m;
  // 0 = startup-only). Each probe is best-effort and side-effect-light: it never
  // account status, reserves the same canonical capacity slot as client work,
  // and only learns from a 2xx (or an account-level quota 429).
  const activeWarmup = config.activeWarmup !== false;
  const warmupIntervalMs = Number.isFinite(config.warmupIntervalMs)
    ? Math.max(0, config.warmupIntervalMs)
    : 5 * 60 * 1000;
  let probeTemplate = null;   // committed { model, version, beta, system } — only after a 2xx
  let warmupClosed = false;   // set on server close: stop scheduling, abort in-flight probes
  const maintenance = hooks.maintenanceCoordinator || new MaintenanceCoordinator(accountManager);

  // Stage a candidate template from a genuine /v1/messages request WITHOUT
  // committing — we only trust the shape once upstream has accepted it (see
  // commitProbeTemplate). Path-exact so /v1/messages/count_tokens isn't taken for
  // inference. Returns the candidate (or null). Called AFTER the response (the
  // caller decides whether a commit/upgrade is even possible), so the body
  // parse is only ever paid for the one or two requests that actually commit.
  function stageProbeTemplate(req, body) {
    if (!activeWarmup) return null;
    if (req.method !== 'POST' || req.url.split('?')[0] !== '/v1/messages') return null;
    let json;
    try { json = JSON.parse(body.toString()); } catch { return null; }
    if (!json || typeof json.model !== 'string') return null;
    return {
      model: json.model,
      version: req.headers['anthropic-version'] || '2023-06-01',
      beta: req.headers['anthropic-beta'] || null,
      system: json.system ?? null,
    };
  }

  // Commit a staged template once its request succeeded (2xx), then fan out so
  // the rest of the fleet is measured within seconds of the first post-restart
  // request. The MODEL matters beyond acceptance: model-scoped weekly windows
  // (7d_oi — the "Fable" weekly limit) only appear on responses to requests for
  // that model tier, so probes replaying e.g. a haiku-shaped template can never
  // refresh the Fbl numbers. Therefore exactly one one-way UPGRADE is allowed:
  // a shape whose own response carried a 7d_* window (elicitsModelWeekly)
  // replaces a committed shape that didn't. No model names are hardcoded — the
  // template converges to whatever tier actually reports the extra window.
  function commitProbeTemplate(candidate, status, elicitsModelWeekly = false) {
    if (!activeWarmup || warmupClosed) return;
    if (!(status >= 200 && status < 300)) return; // only trust an accepted shape
    // A template RESTORED from the last run's snapshot is provisional: it let
    // probes work before any traffic, but upstream accepted it in a previous
    // process — the model may have been retired since. The first freshly
    // accepted shape therefore always replaces it (fresh evidence wins; the
    // Fable-window upgrade then re-applies organically among fresh commits).
    if (probeTemplate && !probeTemplate._restored
        && (probeTemplate._elicitsModelWeekly || !elicitsModelWeekly)) return;
    probeTemplate = { ...candidate, _elicitsModelWeekly: elicitsModelWeekly };
    Promise.resolve().then(() => warmupUnmeasured()).catch(err => {
      console.error(`[TeamClaude] Warm-up scheduling failed: ${err.message}`);
    });
    // Note: the already-measured accounts still missing their Fable window are
    // healed by the periodic top-up pass (topUpModelWeekly) and by an on-demand
    // R — NOT here. Kicking a top-up off this commit would race a concurrent R's
    // refreshQuotaAll (both set `_warming`), skewing its M/N count for no real
    // gain, since the periodic pass fills the same windows within one interval.
  }

  function buildProbeBody(t) {
    const b = { model: t.model, max_tokens: 1, messages: [{ role: 'user', content: 'ping' }] };
    if (t.system != null) b.system = t.system; // mirror the real request (OAuth requires the system prompt)
    return JSON.stringify(b);
  }

  // The coordinator's shared abort signal bounds all maintenance work and is
  // aborted synchronously during server shutdown.

  // Probe one account: send a minimal /v1/messages with its own auth and fold the
  // rate-limit headers into its quota. Best-effort and side-effect-light:
  //  - Never refreshes tokens — a background refresh failure could mark the account
  //    'error' and pull it from rotation before any real request proved auth. An
  //    OAuth account with an expiring token is left to the client path (which has
  //    the proper 401 → forced-refresh → error handling).
  //  - Reserves the same canonical per-account capacity slot as client traffic
  //    through MaintenanceCoordinator. A probe waits rather than oversubscribing
  //    the account, and shutdown aborts any queued maintenance work.
  //  - Learns ONLY from a response upstream accepted (2xx) or an account-level
  //    quota 429 ('rejected') — a 4xx / non-exhaustion 429 / 5xx never mutates state.
  async function performWarmupAccount(account, { force: _force = false, onFailure } = {}) {
    if (!probeTemplate || warmupClosed) return;
    // Don't refresh from a background probe; skip an OAuth account that needs one.
    if (account.type === 'oauth' && isTokenExpiringSoon(account.expiresAt)) return;
    // Eligibility is checked before queuing. Once the coordinator has reserved
    // the canonical slot this account is necessarily in-flight, so re-running
    // warmupCandidates() here would reject the task itself.
    const probe = { signal: maintenance.abortController.signal, cleanup() {} };
    try {
      const headers = { 'content-type': 'application/json', 'anthropic-version': probeTemplate.version };
      if (probeTemplate.beta) headers['anthropic-beta'] = probeTemplate.beta;
      if (account.type === 'oauth') headers['authorization'] = `Bearer ${account.credential}`;
      else headers['x-api-key'] = account.credential;

      const res = await fetchUpstream(`${upstream}/v1/messages`, {
        method: 'POST', headers, body: buildProbeBody(probeTemplate), signal: probe.signal,
      }, {
        transport,
        useSx: transport.sx?.useByDefault?.() === true,
      });
      const rl = {};
      for (const [k, v] of res.headers.entries()) {
        if (k.startsWith('anthropic-ratelimit-')) rl[k] = v;
      }
      await res.body?.cancel();
      // Learn ONLY from a response upstream accepted (2xx) or an *account-level*
      // quota 429 — one whose unified or shared-5h status is `rejected` (the
      // account is genuinely over its limit). A non-exhaustion 429 (request-rate /
      // global / transient) carries rate-limit headers too but is NOT account state;
      // folding it in would wrongly mark the account measured/unavailable and
      // break best-effort. updateQuota by OBJECT is reindex-safe; still skip a
      // detached (removed-mid-fetch) account.
      const accountExhausted429 = res.status === 429
        && (rl['anthropic-ratelimit-unified-status'] === 'rejected'
          || rl['anthropic-ratelimit-unified-5h-status'] === 'rejected');
      if ((res.ok || accountExhausted429) && Object.keys(rl).length
          && accountManager.accounts.includes(account)) {
        accountManager.updateQuota(account, rl);
        // Convergence accounting: a probe that leaves the account fully
        // measured resets the fruitless-probe counter; one that leaves it
        // half-measured (a header family missing) counts toward the cap.
        if (accountManager._fullyMeasured(account)) {
          account._partialProbes = 0;
        } else {
          account._partialProbes = (account._partialProbes || 0) + 1;
          account._lastFruitlessProbeAt = Date.now(); // paces the slow retry backstop
        }
        // Model-weekly (Fable) top-up accounting: if this probe's response
        // carried the window, clear the top-up budget; if it did NOT (this
        // account/tier just doesn't report it) count toward the cap so the
        // top-up pass below doesn't probe it forever.
        if (Object.keys(account.quota.modelWeekly).length > 0) account._mwProbes = 0;
        else account._mwProbes = (account._mwProbes || 0) + 1;
        console.log(`[TeamClaude] Warm-up measured account "${account.name}"`);
        return true; // quota actually folded — the forced-refresh path counts these
      } else if (accountManager.accounts.includes(account)
          && (res.ok || (res.status >= 400 && res.status < 500 && res.status !== 429))) {
        // The probe COMPLETED with a DETERMINISTIC fruitless outcome — a 2xx
        // with no rate-limit headers (contract violation that will repeat), or
        // a 4xx (bad shape / revoked auth — same next time). Count it toward
        // the convergence cap so such an upstream/account is not probed every
        // interval forever. Transient trouble — 5xx, a non-exhaustion 429, or
        // a network failure (the catch below) — is deliberately NOT counted: a
        // fully unmeasured account has no reset timestamp, so no sweep would
        // ever clear its counter, and counting a passing blip would abandon it
        // permanently even after upstream recovers.
        account._partialProbes = (account._partialProbes || 0) + 1;
        account._lastFruitlessProbeAt = Date.now(); // paces the slow retry backstop
      }
    } catch (err) {
      onFailure?.({ stage: 'probe', message: err.message });
      // Best-effort: leave the account unmeasured (exactly as before warm-up).
      console.error(`[TeamClaude] Warm-up probe failed for "${account.name}": ${err.message}`);
    } finally {
      probe.cleanup();
    }
    return false; // skipped, fruitless, or failed — nothing was measured
  }
  // All active template probes pass through the coordinator, which serializes
  // per-account work and reserves the ordinary AccountManager capacity slot.
  function warmupAccount(account, options = {}) {
    return maintenance.run(account, options.force ? 'forced-refresh' : 'active-warmup',
      options.force ? 0 : 20, () => performWarmupAccount(account, options));
  }

  // Forced fleet re-measure (TUI Reload / R): probe EVERY idle account —
  // measured or not, ENABLED OR DISABLED — so the dashboard reflects fresh
  // upstream numbers on demand. Usage spent from other devices/sessions never
  // flows through this proxy, so the displayed values can silently drift until
  // the next organic measurement. Disabled accounts are out of *rotation*, not
  // out of *monitoring*: R is an explicit "show me everything" action, and a
  // probe is read-only (it reserves no rotation slot and routes no client
  // traffic), so refreshing a disabled account's dashboard row is safe and is
  // what the user expects. Throttled/near-quota accounts are included on purpose
  // (their exhausted-429 responses still carry authoritative quota headers);
  // only accounts with a request in flight are skipped (that response refreshes
  // them anyway). The convergence budgets are renewed first — an explicit user
  // action is a fresh reason to probe. Returns { targets, measured }, or -1 when
  // no probe template exists yet (nothing has flowed through the proxy, so there
  // is no known-accepted request shape to replay). When a refresh cannot complete,
  // `failures` names the affected account and stage without hiding successful work.
  async function refreshQuotaAll() {
    if (!activeWarmup || warmupClosed || !probeTemplate) return -1;
    const targets = accountManager.accounts.filter(a =>
      a.status !== 'error' && a.inflight === 0);
    const failures = [];
    const outcomes = await Promise.all(targets.map(a => maintenance.run(a, 'forced-refresh', 0, async () => {
      let tokenRefresh;
      try {
        tokenRefresh = await accountManager.ensureTokenFresh(a);
      } catch (err) {
        failures.push({ account: a.name, stage: 'token-refresh', message: err.message });
        return false;
      }
      if (tokenRefresh?.ok === false || a.status === 'error') {
        failures.push({
          account: a.name,
          stage: 'token-refresh',
          message: tokenRefresh?.error || 'account entered an authentication error state',
        });
        return false;
      }
      a._partialProbes = 0;
      a._mwProbes = 0;
      return performWarmupAccount(a, {
        force: true,
        onFailure: failure => failures.push({ account: a.name, ...failure }),
      });
    })));
    const result = { targets: targets.length, measured: outcomes.filter(Boolean).length };
    if (failures.length) result.failures = failures;
    return result;
  }

  // Model-weekly (Fable) top-up: an account fully measured for 5h/7d but missing
  // its 7d_oi window (measured by lower-tier traffic/probe) is NOT an ordinary
  // warm-up candidate, so nothing re-probes it — its `Fbl` bar stays blank
  // indefinitely. Once the committed template is known to elicit the window,
  // re-probe such accounts (bounded by _mwProbes) so the Fable numbers self-heal
  // within a warm-up interval instead of waiting for the user to press R while
  // that exact account is idle. Force-probes so the fully-measured guard doesn't
  // exclude them; still skips in-flight/disabled/error accounts.
  async function topUpModelWeekly() {
    if (!activeWarmup || warmupClosed || !probeTemplate || !probeTemplate._elicitsModelWeekly) return;
    const targets = accountManager.accounts.filter(a =>
      a.enabled !== false && a.status !== 'error' && a.inflight === 0
      && accountManager.needsModelWeekly(a));
    if (!targets.length) return;
    await Promise.all(targets.map(a => maintenance.run(a, 'model-weekly-topup', 10,
      () => performWarmupAccount(a, { force: true }))));
  }

  // Queue every currently-unmeasured idle account. Per-account jobs are
  // coalesced by the coordinator, so simultaneous template commits are harmless.
  async function warmupUnmeasured() {
    if (!activeWarmup || warmupClosed || !probeTemplate || typeof accountManager.warmupCandidates !== 'function') return;
    await Promise.all(accountManager.warmupCandidates().map(a => warmupAccount(a)));
  }

  // The coordinator is the sole timer owner for maintenance.
  if (activeWarmup && warmupIntervalMs > 0) {
    maintenance.schedule('active-warmup', warmupIntervalMs, async () => {
      accountManager.sweepExpired();
      await warmupUnmeasured();
      await topUpModelWeekly();
    });
  }

  const server = http.createServer(async (req, res) => {
    try {
      // Auth check — skip for localhost connections
      const clientKey = req.headers['x-api-key'];
      const remoteAddr = req.socket.remoteAddress;
      const isLocal = isLoopbackAddr(remoteAddr);
      if (proxyApiKey && !safeKeyEqual(clientKey, proxyApiKey) && !isLocal) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          type: 'error',
          error: { type: 'authentication_error', message: 'Invalid proxy API key' },
        }));
        return;
      }

      // Status endpoint
      if (req.method === 'GET' && req.url === '/teamclaude/status') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ...(hooks.getStatusExtra?.() || {}), ...accountManager.getStatus() }, null, 2));
        return;
      }
      if (req.method === 'POST' && req.url === '/teamclaude/reload') {
        if (!hooks.reload) {
          res.writeHead(501, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'reload not supported' }));
          return;
        }
        try {
          const added = await hooks.reload();
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, added: added || 0 }));
        } catch (err) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: err.message }));
        }
        return;
      }

      if (CLIENT_CREDENTIAL_PATHS.some((path) => (req.url || '').startsWith(path))) {
        relayStream(req, res, upstream);
        return;
      }

      // A model is inside JSON, so reserve only the conservative unknown-shape
      // budget before collecting bytes. The exact shape replaces this reservation
      // before any upstream work starts.
      const admissionReservation = accountManager.reserveAdmissionPrebuffer({});
      if (!admissionReservation) {
        req.resume();
        res.writeHead(429, { 'Content-Type': 'application/json', 'retry-after': '5' });
        res.end(JSON.stringify({ type: 'error', error: { type: 'rate_limit_error', message: 'Proxy at capacity; retry shortly.' } }));
        return;
      }
      try {
        // Let client token refresh requests pass through to upstream untouched.
        // The proxy manages its own tokens via ensureTokenFresh(); intercepting
        // or rewriting client refreshes would cause token rotation conflicts.
        if (req.method === 'POST' && req.url === '/v1/oauth/token') {
          if (!accountManager.transferAdmissionReservation(admissionReservation, 'oauth-token', {})) {
            req.resume(); res.writeHead(429, { 'Content-Type': 'application/json', 'retry-after': '5' }); res.end(); return;
          }
          await relayRaw(req, res, upstream, maxBodyBytes);
          return;
        }
        let pinnedAccount = null;
        const pin = (req.url || '').match(/^\/tc-acct\/([^/]+)(\/.*)$/);
        if (pin) {
          const token = decodeURIComponent(pin[1]);
          const resolvedPinnedAccount = resolveAccountPin(accountManager, token);
          if (!resolvedPinnedAccount) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ type: 'error', error: { type: 'not_found_error', message: `Unknown account pin "${token}"` } }));
            return;
          }
          pinnedAccount = resolvedPinnedAccount;
          req.url = pin[2];
        }


        const reqId = ++requestCounter;
        let ctx = null;
        try {
          // Buffer request body (needed for retry on 429), bounded by maxBodyBytes.
          const bodyChunks = [];
          let bodyLen = 0;
          let bodyTooLarge = false;
          for await (const chunk of req) {
            bodyLen += chunk.length;
            if (bodyLen > maxBodyBytes) { bodyTooLarge = true; break; }
            bodyChunks.push(chunk);
          }
          if (bodyTooLarge) {
            req.destroy();
            if (!res.headersSent) {
              res.writeHead(413, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({
                type: 'error',
                error: { type: 'invalid_request_error', message: `Request body exceeds ${maxBodyBytes} bytes.` },
              }));
            }
            return;
          }
          const body = Buffer.concat(bodyChunks);

          // Tie an abort signal to client disconnect so a request that's only
          // WAITING in the overflow queue is cancelled if the client goes away —
          // otherwise it would acquire a slot later and be dispatched upstream,
          // burning quota for a response nobody is listening for.
          const ac = new AbortController();
          const onClose = () => ac.abort();
          res.on('close', onClose);
          ctx = createLiveRequestContext(req, body, {
            queueTimeoutMs,
            abortSignal: ac.signal,
            affinityKey: sessionAffinity ? req.socket : null,
            transport,
            pinnedAccount,
          });
          const shapeContext = { model: ctx.model, advisorModel: ctx.advisorModel, pinnedAccount: ctx.pinnedAccount };
          if (!accountManager.transferAdmissionReservation(admissionReservation, admissionShape(req, ctx), shapeContext)) {
            req.destroy();
            res.writeHead(429, { 'Content-Type': 'application/json', 'retry-after': '5' });
            res.end(JSON.stringify({ type: 'error', error: { type: 'rate_limit_error', message: 'Proxy at capacity; retry shortly.' } }));
            return;
          }
          accountManager.beginSession(ctx.sessionId);
          hooks.onRequestStart?.(reqId, {
            method: req.method, path: req.url, model: ctx.model,
            advisorModel: ctx.advisorModel, sessionId: ctx.sessionId,
          });
          try {
            await forwardRequest(req, res, ctx.body, accountManager, upstream, 0, hooks, reqId, ctx, logDir);
            // Stage + commit the warm-up template AFTER the response: only an
            // upstream-accepted shape (2xx via ctx.status) is trusted, and the
            // response also tells us whether this request's model tier reports
            // the model-scoped weekly windows (ctx.sawModelWeekly → the Fable
            // limit) — the one property worth a one-way template upgrade.
            if (!probeTemplate || probeTemplate._restored
                || (!probeTemplate._elicitsModelWeekly && ctx.sawModelWeekly)) {
              const candidate = stageProbeTemplate(req, ctx.body);
              if (candidate) commitProbeTemplate(candidate, ctx.status, ctx.sawModelWeekly === true);
            }
          } finally {
            res.removeListener('close', onClose);
          }
        } catch (err) {
          if (ctx) ctx.status = ctx.status || 502;
          console.error('[TeamClaude] Unhandled error:', err);
          if (!res.headersSent) {
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              type: 'error',
              error: { type: 'proxy_error', message: 'Internal proxy error' },
            }));
          }
        } finally {
          // Release the concurrency slot held by this request (if any). A failover
          // releases the previous account before re-acquiring, so at this point only
          // the last-held slot remains; releaseAccount guards against double-release.
          if (ctx?.held != null) {
            accountManager.releaseAccount(ctx.held);
            ctx.held = null;
          }
          if (ctx) {
            accountManager.endSession(ctx.sessionId);
            hooks.onRequestEnd?.(reqId, {
              method: req.method, path: req.url, account: ctx.account, status: ctx.status,
              model: ctx.model, advisorModel: ctx.advisorModel, sessionId: ctx.sessionId,
            });
          }
        }
      } finally {
        accountManager.releaseAdmissionReservation(admissionReservation);
      }
    } catch (err) {
      console.error('[TeamClaude] Unhandled error:', err);
    }
  });

  // Stop scheduling and abort in-flight maintenance synchronously when close is
  // requested, not after keep-alive connections drain.
  const shutdownWarmup = () => {
    if (warmupClosed) return;
    warmupClosed = true;
    maintenance.shutdown();
  };
  const closeServer = server.close.bind(server);
  server.close = (cb) => { shutdownWarmup(); return closeServer(cb); };
  server.on('close', shutdownWarmup);

  // Exposed for the TUI Reload path (and tests): forced fleet-wide quota
  // re-measure. Kept off the HTTP surface — it spends real upstream requests,
  // so only a deliberate local action should trigger it.
  server.refreshQuotaAll = refreshQuotaAll;
  server.maintenanceCoordinator = maintenance;

  // Probe-template persistence (wired into the quota snapshot by index.js).
  // The template is the only known-accepted request shape — without persisting
  // it, a freshly restarted idle proxy can't probe at all: quota restores from
  // the snapshot (accounts read "measured"), no traffic flows, so forced
  // re-measure (TUI R) returns -1 until the first genuine request. Restoring
  // the last run's template closes that gap; it is marked `_restored` so the
  // first freshly accepted shape replaces it (see commitProbeTemplate).
  server.exportProbeTemplate = () => (probeTemplate ? { ...probeTemplate } : null);
  server.importProbeTemplate = (t) => {
    // Never clobber live evidence: a committed-in-this-process template wins.
    if (!activeWarmup || warmupClosed || probeTemplate) return false;
    if (!t || typeof t !== 'object' || typeof t.model !== 'string' || !t.model) return false;
    probeTemplate = {
      model: t.model,
      version: typeof t.version === 'string' && t.version ? t.version : '2023-06-01',
      beta: typeof t.beta === 'string' && t.beta ? t.beta : null,
      system: t.system ?? null,
      _elicitsModelWeekly: t._elicitsModelWeekly === true,
      _restored: true,
    };
    return true;
  };
  const mitmHost = (() => { try { return new URL(upstream).hostname; } catch { return 'api.anthropic.com'; } })();
  let certsPromise = null;
  const ensureLeaf = async () => {
    certsPromise ||= ensureCerts(mitmHost).catch((err) => {
      certsPromise = null;
      throw err;
    });
    const certs = await certsPromise;
    return { key: certs.leafKeyPem, cert: certs.leafCertPem };
  };
  server.on('connect', createConnectHandler({ config, accountManager, ensureLeaf, log: console.error, logDir, hooks, sx }));
  server.on('upgrade', (req, socket, head) => relayUpgrade(req, socket, head, upstream, sx, transport.headersTimeoutMs));

  return server;
}

/**
 * Relay a request to upstream with no header rewriting — pure passthrough.
 * Buffers the body bounded by maxBodyBytes (else 413) so the untouched
 * `/v1/oauth/token` path can't be used to exhaust proxy memory.
 */
async function relayRaw(req, res, upstream, maxBodyBytes = Infinity) {
  const bodyChunks = [];
  let bodyLen = 0;
  let tooLarge = false;
  for await (const chunk of req) {
    bodyLen += chunk.length;
    if (bodyLen > maxBodyBytes) { tooLarge = true; break; }
    bodyChunks.push(chunk);
  }
  if (tooLarge) {
    req.destroy();
    if (!res.headersSent) {
      res.writeHead(413, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ type: 'error', error: { type: 'invalid_request_error', message: `Request body exceeds ${maxBodyBytes} bytes.` } }));
    }
    return;
  }
  const body = Buffer.concat(bodyChunks);

  // Abort the relay if the client disconnects, so a hung upstream OAuth endpoint
  // can't pin this connection (and its admission-control inFlightProxied slot)
  // forever. Tied to res 'close'; the listener is removed once we're done.
  const ac = new AbortController();
  const onClose = () => ac.abort();
  res.on('close', onClose);
  try {
    const upstreamRes = await fetch(`${upstream}${req.url}`, {
      method: req.method,
      headers: {
        'content-type': req.headers['content-type'] || 'application/json',
        'accept': req.headers['accept'] || 'application/json',
        'user-agent': req.headers['user-agent'] || 'node',
      },
      body: body.length > 0 ? body : undefined,
      signal: ac.signal,
    });

    const responseBody = await upstreamRes.text();
    const responseHeaders = {};
    for (const [key, value] of upstreamRes.headers.entries()) {
      if (CONNECTION_SPECIFIC_HEADERS.has(key) || key === 'content-encoding' || key === 'content-length') continue;
      responseHeaders[key] = value;
    }
    res.writeHead(upstreamRes.status, responseHeaders);
    res.end(responseBody);
  } catch (err) {
    // Client disconnected → we aborted the relay; nothing to respond to.
    if (ac.signal.aborted || err?.name === 'AbortError' || err?.code === 'ABORT_ERR' || res.destroyed) {
      if (!res.writableEnded) res.destroy();
      return;
    }
    console.error('[TeamClaude] Raw relay error:', err.message);
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: 'Upstream unreachable' } }));
    }
  } finally {
    res.removeListener('close', onClose);
  }
}


function logTimestamp() {
  const d = new Date();
  const pad = (n, w = 2) => String(n).padStart(w, '0');
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
}

async function writeRequestLog(logDir, reqId, sections) {
  if (!logDir) return;
  const ts = logTimestamp();
  const filename = `${ts}_${String(reqId).padStart(5, '0')}.log`;
  try {
    await writeFile(join(logDir, filename), sections.join('\n\n'), 'utf-8');
  } catch (err) {
    console.error(`[TeamClaude] Failed to write log: ${err.message}`);
  }
}

function formatHeaders(headers) {
  if (headers.entries) {
    return [...headers.entries()].map(([k, v]) => `  ${k}: ${v}`).join('\n');
  }
  return Object.entries(headers).map(([k, v]) => `  ${k}: ${v}`).join('\n');
}

// Upstream statuses that are transient and safe to retry instead of surfacing to
// the client. 529 = "Overloaded" (Anthropic at capacity); 500/502/503/504 =
// gateway / availability blips. Passing these straight through fails the client's
// turn — e.g. Claude Code prints "API Error: 529 Overloaded" and stops — so
// forwardRequest fails them over to another account and, when the whole fleet is
// overloaded, retries with a bounded exponential backoff before giving up.
const RETRYABLE_STATUS = new Set([500, 502, 503, 504, 529]);

// Upstream refusal (403) cooldown ladder. Base doubles per consecutive refusal
// round, capped at the same ceiling the 429 throttle path uses.
export const REFUSAL_BASE_SECONDS = 60;
export const REFUSAL_MAX_SECONDS = 300;

/**
 * How long to cool an account down after its Nth consecutive upstream refusal,
 * and whether that cooldown may replace a hold already in place.
 *
 * Pure, and takes `now` rather than reading the clock, for two reasons. The
 * "don't shorten" answer guards against a concurrent quota 429 arming a much
 * longer retry-after on the same account between our dispatch and our response —
 * a race no deterministic integration test can stage, so the only way to pin it
 * is to test the decision directly. And a second clock read here would compare
 * `existingUntil` against a different instant than the one the caller arms from.
 *
 * @param {number} strikes consecutive refusal rounds, 1-based
 * @param {number|null} existingUntil epoch ms of a hold already armed, if any
 * @param {number} now epoch ms, read once by the caller
 */
export function refusalCooldown(strikes, existingUntil, now) {
  const seconds = Math.min(REFUSAL_MAX_SECONDS, REFUSAL_BASE_SECONDS * 2 ** Math.max(0, strikes - 1));
  return { seconds, arm: !(existingUntil > now + seconds * 1000) };
}
// Sleep that also resolves immediately if `signal` aborts — so a client that
// disconnects during an overload backoff doesn't keep its account slot reserved
// for the whole (up to multi-second) wait. Cleans up its timer/listener either way.
function sleepOrAbort(ms, signal) {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve();
    const cleanup = () => { clearTimeout(t); signal?.removeEventListener('abort', onAbort); };
    const onAbort = () => { cleanup(); resolve(); };
    const t = setTimeout(() => { cleanup(); resolve(); }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

// Await `promise`, but stop waiting the instant `signal` aborts (client gone).
// The underlying op (e.g. a coalesced token refresh shared by other requests)
// is NOT cancelled — we only stop *this* request from blocking on it, so its
// account slot can be released promptly. Rejections still propagate.
function raceAbort(promise, signal) {
  if (!signal) return promise;
  if (signal.aborted) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const cleanup = () => signal.removeEventListener('abort', onAbort);
    const onAbort = () => { cleanup(); resolve(); };
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (v) => { cleanup(); resolve(v); },
      (e) => { cleanup(); reject(e); },
    );
  });
}

// parseInt with a default that HONORS an explicit 0 — unlike `parseInt(...) || def`,
// which discards a valid 0 (0 is falsy). e.g. TEAMCLAUDE_OVERLOAD_RETRIES=0 must
// actually disable proxy-held backoff retries during an incident, not fall back to
// the default. Mirrors the Number.isFinite guard used for reevalIntervalMs in index.js.
const envInt = (name, def) => {
  const v = parseInt(process.env[name], 10);
  return Number.isFinite(v) ? v : def;
};
function positiveTimeout(value) {
  return Number.isFinite(value) && value > 0 ? value : null;
}

function fetchUpstream(url, options, ctx) {
  const transport = ctx.transport || {};
  if (transport.fetchImpl) return transport.fetchImpl(url, options);
  return upstreamFetch(url, {
    ...options,
    headersTimeoutMs: transport.headersTimeoutMs ?? undefined,
  }, transport.sx, ctx.useSx === true);
}

async function forwardRequest(req, res, body, accountManager, upstream, retryCount, hooks, reqId, ctx, logDir) {
  const maxRetries = accountManager.accounts.length;
  if (ctx.useSx == null) ctx.useSx = ctx.transport?.sx?.useByDefault?.() === true;

  // Select account. On a failover retry (a prior account 429'd / 5xx'd / 403'd for
  // this request) ctx.tried* is non-empty → pick a different account, skipping the
  // ones already tried.
  const excludeForSelect = (ctx.tried429.size || ctx.tried5xx.size || ctx.tried403.size)
    ? new Set([...ctx.tried429, ...ctx.tried5xx, ...ctx.tried403])
    : null;

  // Reserve a per-account concurrency slot. On a 401 same-account refresh-retry
  // the slot is already held (ctx.held set, exclude unchanged) → reuse it.
  // Otherwise acquire a fresh slot, waiting briefly if every available account is
  // at its cap (overflow queue) before giving up with a 429. Releasing this slot
  // before any account-switching retry is the caller's job, via releaseHeld().
  let account;
  if (ctx.held != null) {
    account = ctx.held;
  } else {
    account = await accountManager.acquireAccount(
      excludeForSelect, ctx.queueTimeoutMs, ctx.abortSignal, ctx.affinityKey,
      {
        model: ctx.model,
        advisorModel: ctx.advisorModel,
        sessionId: ctx.sessionId,
        revalidate: true,
        pinnedAccount: ctx.pinnedAccount,
      },
    );
    if (account) ctx.held = account;
  }
  const releaseHeld = () => {
    if (ctx.held != null) {
      accountManager.releaseAccount(ctx.held);
      ctx.held = null;
    }
  };

  // The client disconnected while this request was queued (acquireAccount was
  // cancelled by the abort signal) — nothing to respond to.
  if (!account && (ctx.abortSignal?.aborted || res.destroyed)) return;
  if (account && ctx.egressAccountKey !== account.accountIdKey) {
    ctx.egressAccountKey = account.accountIdKey;
    ctx.useSx = ctx.transport?.sx?.useByDefault?.() === true;
  }
  if (!ctx.sxTriedIdentities) ctx.sxTriedIdentities = new Set();

  if (!account && ctx.pinnedAccount) {
    ctx.account = ctx.pinnedAccount.name;
    const capped = accountManager.anyCapped(excludeForSelect, {
      model: ctx.model,
      advisorModel: ctx.advisorModel,
      pinnedAccount: ctx.pinnedAccount,
    });
    ctx.status = capped ? 429 : 503;
    res.writeHead(ctx.status, {
      'Content-Type': 'application/json',
      ...(capped ? { 'retry-after': String(CAPPED_RETRY_AFTER_SECONDS) } : {}),
    });
    res.end(JSON.stringify({
      type: 'error',
      error: {
        type: capped ? 'rate_limit_error' : 'pinned_account_unavailable_error',
        message: capped
          ? `Pinned account "${ctx.pinnedAccount.name}" is busy. Retry shortly.`
          : `Pinned account "${ctx.pinnedAccount.name}" is unavailable.`,
      },
    }));
    return;
  }
  if (!account) {
    ctx.account = '(none available)';
    // If every account is in auth-error state, this is an authentication
    // problem (revoked/expired tokens needing re-login), not a rate limit —
    // return 401 so the client surfaces it instead of pointlessly backing off.
    const accts = accountManager.accounts;
    if (accts.length > 0 && accts.every(a => a.status === 'error')) {
      ctx.status = 401;
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        type: 'error',
        error: {
          type: 'authentication_error',
          message: `All ${accts.length} accounts failed authentication. Re-login required.`,
        },
      }));
      return;
    }
    const waitingUntil = accts
      .filter(a => a.status === 'throttled' && a.rateLimitedUntil > Date.now())
      .reduce((soonest, a) => Math.min(soonest, a.rateLimitedUntil), Infinity);
    const holdMs = ctx.transport?.holdMs || 0;
    if (holdMs > 0 && ctx.holdUntil == null) ctx.holdUntil = Date.now() + holdMs;
    const holdRemaining = ctx.holdUntil == null ? 0 : ctx.holdUntil - Date.now();
    if (Number.isFinite(waitingUntil) && (retryCount < maxRetries || holdRemaining > 0)) {
      await sleepOrAbort(Math.min(waitingUntil - Date.now() + THROTTLE_WAKE_MARGIN_MS, holdRemaining > 0 ? holdRemaining : Infinity), ctx.abortSignal);
      if (ctx.abortSignal?.aborted || res.destroyed) return;
      return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
    }
    ctx.status = 429;
    // "No quota left anywhere" and "every account is momentarily at its concurrency
    // cap" call for opposite responses — add accounts or wait for a reset, versus
    // reduce concurrency — so reporting the first when it is the second sends the
    // reader hunting quota that is in fact 90% unspent. A request that released its
    // slot for an overload backoff and then lost the race to re-acquire it lands
    // here, which is how the wrong label gets in front of a client. The pinned-account
    // branch above already draws this line; draw it on the general path too — and in
    // the retry-after as well as the wording, or the client is still told to wait a
    // minute for something that frees when any in-flight request finishes.
    const merelyCapped = !ctx.terminalQuotaExhaustion && accountManager.anyCapped(excludeForSelect, {
      model: ctx.model,
      advisorModel: ctx.advisorModel,
    });
    const retryAfter = ctx.terminalQuotaExhaustion
      ? computeRetryAfter(accountManager.getStatus().accounts, accountManager.switchThreshold)
      : merelyCapped ? CAPPED_RETRY_AFTER_SECONDS : RETRY_AFTER_FALLBACK_SECONDS;
    res.writeHead(429, {
      'Content-Type': 'application/json',
      'retry-after': String(retryAfter),
    });
    res.end(JSON.stringify({
      type: 'error',
      error: {
        type: 'rate_limit_error',
        // A refusal is a third cause with its own operator response — check the
        // subscription, not add accounts and not lower concurrency — so it does not
        // share either string, for the same reason those two do not share one.
        message: ctx.tried403.size
          ? `Upstream refused ${ctx.tried403.size} of ${accts.length} accounts (${[...ctx.tried403].map(a => a.name).join(', ')}) and the rest are unavailable. Retry in ${retryAfter}s.`
          : merelyCapped
            ? `All ${accts.length} accounts are at their concurrency cap. Retry in ${retryAfter}s.`
            : `All ${accts.length} accounts exhausted. Retry in ${retryAfter}s.`,
      },
    }));
    return;
  }

  // Track which account handles this request.
  ctx.account = account.name;
  if (!ctx.sessionRecorded) {
    accountManager.recordSession(ctx.sessionId, account);
    ctx.sessionRecorded = true;
  }
  hooks.onRequestRouted?.(reqId, { account: account.name });

  // Refresh OAuth token if needed. Stop waiting if the client disconnects (the
  // refresh is coalesced/shared, so we don't cancel it — we just don't pin this
  // request's account slot on a possibly-hung token endpoint).
  await raceAbort(accountManager.ensureTokenFresh(account), ctx.abortSignal);
  if (res.destroyed || ctx.abortSignal?.aborted) return; // client gone — outer finally frees the slot

  // The account may have been REMOVED (TUI/CLI delete) during the awaited refresh
  // above (or the 401 forced-refresh that recurses back here). A detached account
  // must not be used to dispatch upstream — its slot release is a no-op and we'd
  // be sending traffic on a credential the operator just retired. Re-select a live
  // account instead. (accounts[i] === account holds only while it's still live.)
  if (!accountManager.accounts.includes(account)) {
    releaseHeld();
    if (res.destroyed) return; // client gone — outer finally cleans up
    if (retryCount < maxRetries) {
      return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
    }
    // Out of retry budget after repeated removals — respond rather than hang.
    ctx.status = 503;
    if (!res.headersSent) {
      res.writeHead(503, { 'Content-Type': 'application/json', 'retry-after': '5' });
      res.end(JSON.stringify({
        type: 'error',
        error: { type: 'overloaded_error', message: 'Account removed mid-request; retry shortly.' },
      }));
    }
    return;
  }

  if (account.status === 'error' && retryCount < maxRetries) {
    releaseHeld(); // failing over to a different account
    return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
  }

  // Build upstream request headers
  const isOAuth = account.type === 'oauth';
  const headers = {};
  for (const [key, value] of Object.entries(req.headers)) {
    const lk = key.toLowerCase();
    if (lk.startsWith(':') || HOP_BY_HOP_HEADERS.has(lk)) continue;
    if (lk === 'x-api-key') continue;
    // Strip accept-encoding: Node fetch auto-decompresses, which would
    // mismatch the Content-Encoding header we forward to the client
    if (lk === 'accept-encoding') continue;
    headers[key] = value;
  }

  if (isOAuth) {
    headers['authorization'] = `Bearer ${account.credential}`;
  } else {
    headers['x-api-key'] = account.credential;
  }

  const upstreamUrl = `${account.upstream || upstream}${req.url}`;
  const method = req.method;
  const outboundBody = rewriteModel(patchAccountUuid(body, account.accountUuid), account.modelMap);
  if (outboundBody !== body) headers['content-length'] = String(outboundBody.length);

  // Build log sections
  const logSections = [];
  if (logDir) {
    const safeHeaders = { ...headers };
    // Mask credentials in logs
    if (safeHeaders['x-api-key']) {
      safeHeaders['x-api-key'] = safeHeaders['x-api-key'].slice(0, 15) + '...';
    }
    if (safeHeaders['authorization']) {
      safeHeaders['authorization'] = safeHeaders['authorization'].slice(0, 20) + '...';
    }
    logSections.push(
      `=== REQUEST (account: ${account.name}, retry: ${retryCount}) ===\n${method} ${upstreamUrl}\n${formatHeaders(safeHeaders)}`,
    );
    if (body.length > 0) {
      try {
        logSections.push(`=== REQUEST BODY ===\n${JSON.stringify(JSON.parse(body.toString()), null, 2)}`);
      } catch {
        logSections.push(`=== REQUEST BODY (${body.length} bytes) ===\n${body.toString().slice(0, 4096)}`);
      }
    }
  }

  try {
    // When THIS attempt left for upstream. The 403 branch below compares it against
    // the account's last recorded refusal to tell a fresh refusal round from the
    // echo of one already counted — read once here, never re-read from the clock.
    const sentAt = Date.now();
    const upstreamRes = await fetchUpstream(upstreamUrl, {
      method,
      headers,
      body: ['GET', 'HEAD'].includes(method) ? undefined : outboundBody,
      redirect: 'manual',
      // Abort the upstream call when the client disconnects (ctx.abortSignal is
      // tied to res 'close'). Without this, a client that drops mid-SSE while the
      // upstream stalls would leave streamResponse blocked in reader.read(), so
      // the per-account slot and inFlightProxied never release — repeated stalls
      // would leak the proxy to capacity. Aborting rejects the read and unwinds
      // the finally that frees the slot.
      signal: ctx.abortSignal,
    }, ctx);

    // Extract rate limit headers
    const rateLimitHeaders = {};
    for (const [key, value] of upstreamRes.headers.entries()) {
      if (key.startsWith('anthropic-ratelimit-')) {
        rateLimitHeaders[key] = value;
      }
    }
    // Did this request's model tier report a model-scoped weekly window
    // (anthropic-ratelimit-unified-7d_<label>-*)? Only such requests can teach
    // probes to refresh the Fable weekly numbers — used by the template-upgrade
    // decision in the request handler. Request-scoped: any attempt's headers
    // prove the property, since the request shape is identical across failovers.
    if (Object.keys(rateLimitHeaders).some(k => k.startsWith('anthropic-ratelimit-unified-7d_'))) {
      ctx.sawModelWeekly = true;
    }
    const response429 = upstreamRes.status === 429
      ? classify429(rateLimitHeaders, {
        model: ctx.model,
        advisorModel: ctx.advisorModel,
        switchThreshold: accountManager.switchThreshold,
      })
      : null;
    accountManager.updateQuota(account, rateLimitHeaders);
    // A non-429 is normally live proof a hold no longer binds — but a 403 is proof
    // of the opposite: upstream is refusing this account, not serving it. Clearing
    // here would also erase the deadline the 403 branch must not shorten, leaving it
    // unable to tell its own 60s refusal cooldown from a much longer quota throttle
    // a concurrent request had just armed on the same account.
    if (upstreamRes.status !== 429 && upstreamRes.status !== 403) accountManager.clearRateLimited(account);

    // 403 = upstream authenticated the credential but refuses to SERVE it — a
    // lapsed subscription, an org that turned off Claude Code access, an edge/WAF
    // block. Unlike a 401 there is no token to refresh, so re-authenticating cannot
    // clear it. How long it lasts is NOT knowable from here, which is why the
    // cooldown below re-probes instead of concluding. There was no branch at all, so a 403
    // fell through to the pass-through response below, which hands it to the client
    // AND leaves the account 'active' — neither throttled nor errored, so the very
    // next request selects it again and fails the same way. One lapsed account
    // served every request while the healthy ones sat idle.
    //
    // Two things this branch will not do:
    //   - Hand the 403 to the client. The client never sees the credential we
    //     inject, so a refusal of it is not actionable there — and the upstream
    //     project reports (KarpelesLab#149) that Claude Code reads a 403 as its own
    //     session dying and drops its login over it. That second half is their
    //     observation, not ours; the first half alone already settles the choice.
    //   - Park the account. Which upstream conditions mean "lapsed" is not knowable
    //     from here, and every account in a fleet leaves through one egress IP, so
    //     an IP-level block would park them one by one. Parking is one-way and
    //     costs a human re-login; this branch only ever arms a self-expiring
    //     cooldown. A permanently dead account then costs one wasted round-trip per
    //     cooldown window rather than one per request, which is what the bug was.
    if (upstreamRes.status === 403) {
      await upstreamRes.body?.cancel();

      // One clock read for the whole branch: the strike stamp, the round test and
      // the "don't shorten" comparison must all describe the same instant.
      const refusedAt = Date.now();

      // A strike counts a refusal ROUND, not a response. This account can hold
      // maxConcurrent requests at once and one upstream blip returns 403 to all of
      // them; counting each would jump the cooldown to its ceiling on a single
      // incident. A response dispatched at or before the last recorded refusal is
      // an echo of that same round, so it re-arms the cooldown but earns no strike.
      if (!(account._403LastAt >= sentAt)) {
        account._403Strikes = (account._403Strikes || 0) + 1;
        account._403LastAt = refusedAt;
      }
      const strikes = account._403Strikes || 0;
      // Never SHORTEN a hold already in place — see refusalCooldown's contract.
      const { seconds: cool, arm } = refusalCooldown(strikes, account.rateLimitedUntil, refusedAt);
      if (arm) {
        accountManager.markRateLimited(account, cool);
        // Records that THIS deadline came from a refusal, so replacing the
        // credentials can lift it without releasing a real quota throttle.
        account._403CooldownUntil = account.rateLimitedUntil;
      }
      console.log(`[TeamClaude] 403 on "${account.name}" ×${strikes} — upstream refused the account, cooling down ${cool}s`);
      if (logDir) {
        logSections.push(`=== RESPONSE 403 — refused, strike ${strikes}, cooling down ${cool}s ===\n${formatHeaders(upstreamRes.headers)}`);
        writeRequestLog(logDir, reqId, logSections);
      }
      if (res.destroyed) return;

      ctx.tried403.add(account);
      if (retryCount < maxRetries) {
        releaseHeld(); // this account is cooling down; fail over to another
        return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
      }
      // Out of retry budget with every attempt refused. Answer with a shortage the
      // client can back off from, never the 403 itself (see above). The retry-after
      // is THIS account's cooldown — a safe upper bound, not the exact soonest:
      // accounts refused earlier in this request were armed earlier and so free up
      // sooner. Waiting slightly too long is the harmless direction.
      ctx.status = 503;
      if (!res.headersSent) {
        res.writeHead(503, { 'Content-Type': 'application/json', 'retry-after': String(cool) });
        res.end(JSON.stringify({
          type: 'error',
          error: {
            type: 'upstream_refused_error',
            message: `Upstream refused every account tried (${[...ctx.tried403].map(a => a.name).join(', ')}). Check the subscription, then re-add with: teamclaude login`,
          },
        }));
      }
      return;
    }

    // 401 = auth failure (stale or revoked token). For OAuth, attempt one
    // forced token refresh and retry the same account (the token may be stale
    // but still refreshable). If that doesn't fix it — refresh fails, the token
    // is revoked, or it's an API-key account — mark the account 'error' so it's
    // excluded from BOTH selection and warm-up, then switch to another account.
    // Without this, warm-up would keep routing client traffic to a revoked
    // account (it stays unmeasured/active), yielding repeated 401s.
    if (upstreamRes.status === 401) {
      await upstreamRes.body?.cancel();

      if (account.type === 'oauth' && account.refreshToken
          && !ctx.authRetried.has(account)
          && retryCount < maxRetries && !res.destroyed) {
        ctx.authRetried.add(account);
        console.log(`[TeamClaude] 401 on "${account.name}" — forcing token refresh and retrying`);
        await raceAbort(accountManager.ensureTokenFresh(account, true), ctx.abortSignal);
        if (res.destroyed || ctx.abortSignal?.aborted) return; // client gone during refresh
        // ensureTokenFresh only marks 'error' for an expired token; a successful
        // (or non-fatal) refresh leaves status intact → retry the same account.
        if (account.status !== 'error') {
          if (logDir) {
            logSections.push(`=== RESPONSE 401 — forced token refresh, retrying ===`);
            writeRequestLog(logDir, reqId, logSections);
          }
          return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
        }
      }

      // Refresh didn't help (failed / already retried / revoked-but-unexpired)
      // or it's an API-key account — fail this account out and switch.
      if (account.status !== 'error') {
        account.status = 'error';
        // Upstream rejected the account (401 despite a fresh token) — NOT a
        // refresh failure. The token sweep must not revive it just because the
        // token endpoint still rotates; only new credentials or a restart do.
        account._errorFromRefresh = false;
        console.log(`[TeamClaude] 401 on "${account.name}" — auth failed, marking account error`);
      } else if (account.expiresAt && Date.now() < normalizeExpiresAt(account.expiresAt)) {
        // Already parked (e.g. a sweep refresh failed first), but THIS 401 came
        // back on a still-valid token — that is account-level rejection
        // evidence, so demote a refresh-caused label: the sweep must not revive
        // the account on the next token-endpoint success. (A 401 on an EXPIRED
        // token proves nothing beyond the expiry and keeps its label.)
        account._errorFromRefresh = false;
      }
      if (logDir) {
        logSections.push(`=== RESPONSE 401 — auth failure, account marked error ===\n${formatHeaders(upstreamRes.headers)}`);
        writeRequestLog(logDir, reqId, logSections);
      }
      if (res.destroyed) return;
      if (retryCount < maxRetries) {
        releaseHeld(); // this account is now 'error'; fail over to another
        return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
      }
      // Every account failed auth — surface the 401 to the client.
      ctx.status = 401;
      if (!res.headersSent) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          type: 'error',
          error: { type: 'authentication_error', message: 'All accounts failed authentication.' },
        }));
      }
      return;
    }

    if (upstreamRes.status === 429) {
      const retryAfter = parseRetryAfter(upstreamRes.headers.get('retry-after'));
      await upstreamRes.body?.cancel();

      if (response429 === 'account-quota') {
        ctx.terminalQuotaExhaustion = true;
        accountManager.markRateLimited(account, retryAfter);
        if (res.destroyed) return;
        if (retryCount >= maxRetries) {
          ctx.status = 429;
          const ra = computeRetryAfter(accountManager.getStatus().accounts, accountManager.switchThreshold);
          if (!res.headersSent) {
            res.writeHead(429, { 'Content-Type': 'application/json', 'retry-after': String(ra) });
            res.end(JSON.stringify({
              type: 'error',
              error: { type: 'rate_limit_error', message: `All accounts throttled. Retry in ${ra}s.` },
            }));
          }
          return;
        }
        releaseHeld();
        return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
      }

      if (response429 === 'model-quota') {
        ctx.tried429.add(account);
        const excluded = new Set(ctx.tried429);
        if (!res.destroyed && retryCount < maxRetries
            && (accountManager.anyUsable(excluded) || accountManager.anyCapped(excluded))) {
          releaseHeld();
          return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
        }
        ctx.status = 429;
        if (!res.destroyed && !res.headersSent) {
          res.writeHead(429, { 'Content-Type': 'application/json', 'retry-after': String(retryAfter) });
          res.end(JSON.stringify({
            type: 'error',
            error: { type: 'rate_limit_error', message: `Model quota exhausted (retry in ${retryAfter}s).` },
          }));
        }
        return;
      }

      if (!ctx.useSx && ctx.transport?.sx?.useOn429?.()
          && !ctx.sxTriedIdentities.has(account.accountIdKey)) {
        ctx.sxTriedIdentities.add(account.accountIdKey);
        ctx.transport.sx.noteRateLimited?.(retryAfter);
        ctx.useSx = true;
        return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
      }

      accountManager.pauseAccount(account, retryAfter);
      ctx.tried429.add(account);
      const excluded = new Set(ctx.tried429);
      if (!res.destroyed && retryCount < maxRetries
          && (accountManager.anyUsable(excluded) || accountManager.anyCapped(excluded))) {
        releaseHeld();
        return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
      }

      ctx.status = 429;
      if (!res.destroyed && !res.headersSent) {
        res.writeHead(429, { 'Content-Type': 'application/json', 'retry-after': String(retryAfter) });
        res.end(JSON.stringify({
          type: 'error',
          error: { type: 'rate_limit_error', message: `Upstream rate limited (retry in ${retryAfter}s).` },
        }));
      }
      return;
    }

    // Handle retryable upstream 5xx (notably 529 "Overloaded" — Anthropic is over
    // capacity). Unlike a 429, a 529 is NOT account-specific: every account hits
    // the same overloaded upstream. Surfacing it fails the client's turn, so:
    //   (1) fail this request over to another account (cheap; for 500/502/503/504 a
    //       different account/region is occasionally healthier), then
    //   (2) once every account has 5xx'd for this request, wait a bounded
    //       exponential backoff and retry the whole fleet — the client transparently
    //       gets the eventual success instead of an error.
    // Only after the backoff budget is spent is the 5xx surfaced (so the client is
    // never left hanging indefinitely). No account state is mutated — a 529 is
    // upstream overload, not a bad account.
    if (RETRYABLE_STATUS.has(upstreamRes.status)) {
      const code = upstreamRes.status;
      await upstreamRes.body?.cancel();

      const maxOverload = Math.max(0, envInt('TEAMCLAUDE_OVERLOAD_RETRIES', 6));
      const backoffBase = Math.max(50, envInt('TEAMCLAUDE_OVERLOAD_BACKOFF_BASE_MS', 1000));
      const backoffCap = Math.max(backoffBase, envInt('TEAMCLAUDE_OVERLOAD_BACKOFF_CAP_MS', 10000));

      // (1) Per-request failover to an account not yet 5xx'd (or 429'd) this request.
      ctx.tried5xx.add(account);
      const exclude5xx = new Set([...ctx.tried429, ...ctx.tried5xx]);
      if (!res.destroyed && retryCount < maxRetries
          && (accountManager.anyUsable(exclude5xx) || accountManager.anyCapped(exclude5xx))) {
        console.log(`[TeamClaude] ${code} on "${account.name}" — switching account for this request`);
        if (logDir) {
          logSections.push(`=== RESPONSE ${code} — transient upstream 5xx, switching account ===\n${formatHeaders(upstreamRes.headers)}`);
          writeRequestLog(logDir, reqId, logSections);
        }
        releaseHeld(); // free this account's slot before trying another
        return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
      }

      // (2) Every account 5xx'd for this request → upstream overload. Back off and
      // retry the whole fleet so the client transparently rides out the blip.
      if (!res.destroyed && ctx.overloadRetries < maxOverload) {
        const waitMs = Math.min(backoffBase * 2 ** ctx.overloadRetries, backoffCap);
        ctx.overloadRetries += 1;
        // Say how many accounts actually 5xx'd, not "every account": when quota has
        // benched the rest of the fleet the eligible set can be a single account, and
        // "every account" then reads as a fleet-wide upstream outage — which sends the
        // next person debugging this at api.anthropic.com instead of at the empty pool.
        const tried = ctx.tried5xx.size;
        console.log(`[TeamClaude] ${code} on all ${tried} eligible account(s) — upstream overloaded, backing off ${waitMs}ms (retry ${ctx.overloadRetries}/${maxOverload})`);
        if (logDir) {
          logSections.push(`=== RESPONSE ${code} — all ${tried} eligible account(s) overloaded, backoff ${waitMs}ms (retry ${ctx.overloadRetries}/${maxOverload}) ===`);
          writeRequestLog(logDir, reqId, logSections);
        }
        // Release the slot BEFORE sleeping, not after. A backing-off request needs no
        // upstream capacity, but the slot it holds is capacity on the one account every
        // other request is queued behind — so each concurrent backoff removes
        // 1/maxConcurrent of the usable fleet for the whole wait and times waiters out
        // (overflowQueueTimeoutMs) into 429s that a free slot would have served. The
        // next round re-acquires from the full set anyway, so nothing is lost by
        // queueing fairly for it.
        ctx.tried5xx.clear(); // fresh round: let every account be tried again
        releaseHeld();
        await sleepOrAbort(waitMs, ctx.abortSignal);
        if (res.destroyed || ctx.abortSignal?.aborted) return; // client gone mid-backoff
        return forwardRequest(req, res, body, accountManager, upstream, 0, hooks, reqId, ctx, logDir);
      }

      // (3) Backoff budget spent — surface the 5xx rather than hold the client forever.
      console.log(`[TeamClaude] ${code} on "${account.name}" — overload persisted after ${ctx.overloadRetries} backoffs, passing through`);
      ctx.status = code;
      if (logDir) {
        logSections.push(`=== RESPONSE ${code} — overload persisted after ${ctx.overloadRetries} backoffs, passed through ===\n${formatHeaders(upstreamRes.headers)}`);
        writeRequestLog(logDir, reqId, logSections);
      }
      if (res.destroyed) return;
      // Carry a retry-after: without one the client SDK falls back to its own backoff,
      // which on an early attempt is ~0s ("Retrying in 0s"), so the moment we give up it
      // re-floods an upstream we just measured as overloaded for every backoff round —
      // and each such retry walks the whole ladder again. parseRetryAfter honors the
      // 529's own guidance when it carries any, falls back to RETRY_AFTER_FALLBACK_SECONDS
      // when it does not, and bounds the result at RETRY_AFTER_MAX_SECONDS — so "a client
      // cannot sleep past its own request watchdog" is enforced by the code rather than
      // asserted by this comment.
      const overloadRetryAfter = parseRetryAfter(upstreamRes.headers.get('retry-after'));
      if (!res.headersSent) {
        res.writeHead(code, {
          'Content-Type': 'application/json',
          'retry-after': String(overloadRetryAfter),
        });
        res.end(JSON.stringify({
          type: 'error',
          error: { type: 'overloaded_error', message: `Upstream overloaded (HTTP ${code}). Retried ${ctx.overloadRetries}x, retry in ${overloadRetryAfter}s.` },
        }));
      }
      return;
    }

    // Log response headers
    if (logDir) {
      logSections.push(`=== RESPONSE ${upstreamRes.status} ===\n${formatHeaders(upstreamRes.headers)}`);
    }

    ctx.status = upstreamRes.status;

    // Build response headers (skip hop-by-hop and encoding headers)
    const responseHeaders = {};
    for (const [key, value] of upstreamRes.headers.entries()) {
      if (CONNECTION_SPECIFIC_HEADERS.has(key)) continue;
      // Strip content-encoding/content-length since fetch may auto-decompress
      if (key === 'content-encoding' || key === 'content-length') continue;
      responseHeaders[key] = value;
    }

    res.writeHead(upstreamRes.status, responseHeaders);

    if (!upstreamRes.body) {
      if (logDir) {
        logSections.push(`=== RESPONSE BODY ===\n(empty)`);
        writeRequestLog(logDir, reqId, logSections);
      }
      res.end();
      return;
    }

    const isStreaming = (upstreamRes.headers.get('content-type') || '').includes('text/event-stream');

    if (isStreaming) {
      const streamLog = logDir ? [] : null;
      await streamResponse(upstreamRes.body, res, account, accountManager, streamLog, ctx.transport?.bodyTimeoutMs);
      if (logDir) {
        logSections.push(`=== RESPONSE BODY (streamed) ===\n${streamLog.join('')}`);
        writeRequestLog(logDir, reqId, logSections);
      }
    } else {
      const buf = Buffer.from(await upstreamRes.arrayBuffer());
      extractUsageFromBody(buf, account, accountManager);
      if (logDir) {
        try {
          logSections.push(`=== RESPONSE BODY ===\n${JSON.stringify(JSON.parse(buf.toString()), null, 2)}`);
        } catch {
          logSections.push(`=== RESPONSE BODY (${buf.length} bytes) ===\n${buf.toString().slice(0, 8192)}`);
        }
        writeRequestLog(logDir, reqId, logSections);
      }
      res.end(buf);
    }
  } catch (err) {
    // Client disconnected → we aborted the upstream fetch (ctx.abortSignal). This
    // is not the account's fault: don't mark it 'error' or fail over (the client
    // is gone). Just unwind — the outer finally releases the slot / inFlightProxied.
    if (ctx.abortSignal?.aborted || err?.name === 'AbortError' || err?.code === 'ABORT_ERR' || res.destroyed) {
      if (!res.writableEnded) res.destroy();
      return;
    }

    console.error(`[TeamClaude] Upstream error (account "${account.name}"):`, err.message);

    if (logDir) {
      logSections.push(`=== ERROR ===\n${err.stack || err.message}`);
      writeRequestLog(logDir, reqId, logSections);
    }

    const isTransient = err instanceof Error &&
      (err.message.includes('fetch failed') ||
        err.code === 'ECONNRESET' || err.code === 'ECONNREFUSED' ||
        err.code === 'ETIMEDOUT' || err.code === 'UND_ERR_CONNECT_TIMEOUT' ||
        err.code === 'UND_ERR_HEADERS_TIMEOUT' || err.code === 'UND_ERR_BODY_TIMEOUT' ||
        err.code === 'TEAMCLAUDE_HEADERS_TIMEOUT' || err.code === 'TEAMCLAUDE_BODY_TIMEOUT');

    // Transient network errors: just close the connection and let the client retry
    if (isTransient) {
      res.destroy();
      return;
    }

    if (retryCount < maxRetries && !res.headersSent) {
      // Same cause-tagging as the 401 path: a non-transient SEND failure is not
      // a refresh failure, so the token sweep must not auto-revive it. Only tag
      // on the transition, preserving an earlier refresh-caused label.
      // Deliberately NO valid-token demotion here (unlike the 401 path): a send
      // failure is a transport observation, not deterministic account-level
      // rejection evidence, so it must not permanently park an account whose
      // only proven defect was a failed refresh. If the sweep later revives it
      // and the transport problem persists, the first real request re-parks it
      // — this time labeled send-caused (the transition above fires from
      // 'active') — so mislabeling self-corrects in at most one bounded flap,
      // whereas demoting would trade that for permanent in-run capacity loss.
      if (account.status !== 'error') account._errorFromRefresh = false;
      account.status = 'error';
      releaseHeld(); // this account errored; fail over to another
      return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
    }
    ctx.status = 502;

    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        type: 'error',
        error: { type: 'proxy_error', message: `Upstream error: ${err.message}` },
      }));
    }
  }
}

/**
 * Stream an SSE response to the client, parsing usage data along the way.
 */
async function streamResponse(webStream, res, account, accountManager, streamLog, bodyTimeoutMs = null) {
  const reader = webStream.getReader();
  const decoder = new TextDecoder();
  let sseBuffer = '';
  let completed = false;

  try {
    while (true) {
      const { done, value } = await readWithIdleTimeout(reader, bodyTimeoutMs ?? resolveBodyIdleTimeout());
      if (done) break;

      // Client disconnected — stop reading from upstream
      if (res.destroyed) break;

      // Forward chunk immediately
      const ok = res.write(value);

      const text = decoder.decode(value, { stream: true });

      // Capture for logging
      if (streamLog) streamLog.push(text);

      // Parse SSE events for usage tracking
      sseBuffer += text;
      const events = sseBuffer.split('\n\n');
      sseBuffer = events.pop(); // keep incomplete event

      for (const event of events) {
        parseSSEUsage(event, account, accountManager);
      }

      // Handle backpressure — also bail out if client disconnects,
      // because 'drain' will never fire on a destroyed socket
      if (!ok) {
        await new Promise(resolve => {
          res.once('drain', resolve);
          res.once('close', resolve);
        });
        if (res.destroyed) break;
      }
    }

    // Parse any remaining buffer
    if (sseBuffer.trim()) {
      parseSSEUsage(sseBuffer, account, accountManager);
    }
    completed = true;
  } finally {
    // Cancel upstream reader to stop consuming data nobody needs
    reader.cancel().catch(() => {});
    if (!completed && !res.destroyed) res.destroy();
    if (completed && !res.writableEnded) res.end();
  }
}

function parseSSEUsage(event, account, accountManager) {
  const dataLine = event.split('\n').find(l => l.startsWith('data: '));
  if (!dataLine) return;

  try {
    const data = JSON.parse(dataLine.slice(6));
    if (data.type === 'message_start' && data.message?.usage) {
      accountManager.updateUsage(account, data.message.usage.input_tokens, 0);
    } else if (data.type === 'message_delta' && data.usage) {
      accountManager.updateUsage(account, 0, data.usage.output_tokens);
    }
  } catch {
    // not valid JSON, skip
  }
}

function extractUsageFromBody(buffer, account, accountManager) {
  try {
    const json = JSON.parse(buffer.toString());
    if (json.usage) {
      accountManager.updateUsage(account, json.usage.input_tokens, json.usage.output_tokens);
    }
  } catch {
    // not JSON or no usage
  }
}

// Seconds a client should wait before ANY account can serve again, derived from
// *why* each account is currently unusable — so an all-exhausted fleet tells the
// client the real (often hours-long) wait instead of a flat 60s it would just
// re-flood against every minute:
// An account is usable again only once BOTH its throttle AND every quota window
// it is currently past `threshold` on have cleared — so we take the LATEST (max)
// of them per account:
//   - an explicit throttle (a live exhaustion 429 → markRateLimited) is clamped
//     to <=5m, but the binding 5h/7d window that 429 came with may reset hours
//     later; the account stays `_isNearQuota` until then, so returning the
//     throttle alone made the client re-flood every 5 min while still exhausted;
//   - the quota reset is the unified 5h/7d reset the dashboard shows, NOT
//     `resetsAt` (a standard/API-key-only field the old code looked at, so a
//     utilization-exhausted Max fleet always fell through to the 60s default).
// A window UNDER threshold is not binding, so its (always-future) reset is
// ignored — and an account with NO binding constraint at all (quota-healthy,
// merely concurrency-capped or overflow-queued) contributes a short 60s
// candidate instead: its slot frees in seconds, so one healthy account caps the
// whole fleet's wait at the short fallback even when every other account is
// hours from reset. Disabled/auth-error accounts never return on a timer, so
// they're skipped. Falls back to 60s when nothing contributes anything.
export function computeRetryAfter(accounts, threshold = 0.98, now = Date.now()) {
  let soonest = Infinity;
  const consider = ms => { if (ms > 0 && ms < soonest) soonest = ms; };
  for (const acct of accounts) {
    if (acct.enabled === false || acct.status === 'error') continue;
    // freeAt = max(throttle, every over-threshold quota reset). The account is
    // blocked until the LAST of these clears; taking the min across accounts
    // then gives the soonest the fleet has anything to serve.
    let freeAt = 0;
    if (acct.rateLimitedUntil) freeAt = Math.max(freeAt, new Date(acct.rateLimitedUntil).getTime());
    const q = acct.quota || {};
    if (q.unified5h != null && q.unified5h >= threshold && q.unified5hReset)
      freeAt = Math.max(freeAt, q.unified5hReset);
    if (q.unified7d != null && q.unified7d >= threshold && q.unified7dReset)
      freeAt = Math.max(freeAt, q.unified7dReset);
    // Standard windows reset independently — use each window's OWN reset
    // (falling back to the collapsed resetsAt for snapshots predating the
    // split fields), so when both are binding the LATER one wins instead of
    // resetsAt's preference for the sooner token reset.
    const tokensReset = q.tokensReset || q.resetsAt;
    if (q.tokensLimit != null && q.tokensRemaining != null && tokensReset
        && 1 - q.tokensRemaining / q.tokensLimit >= threshold)
      freeAt = Math.max(freeAt, new Date(tokensReset).getTime());
    const requestsReset = q.requestsReset || q.resetsAt;
    if (q.requestsLimit != null && q.requestsRemaining != null && requestsReset
        && 1 - q.requestsRemaining / q.requestsLimit >= threshold)
      freeAt = Math.max(freeAt, new Date(requestsReset).getTime());
    if (freeAt > 0) consider(freeAt - now);
    else consider(60_000); // quota-healthy (merely capped/queued): a slot frees in seconds — cap the fleet wait at the short fallback
  }
  return soonest === Infinity ? 60 : Math.max(1, Math.ceil(soonest / 1000));
}
const CLIENT_CREDENTIAL_PATHS = ['/v1/code/', '/api/oauth/files/', '/api/oauth/file_upload'];

export function resolveAccountPin(accountManager, token) {
  if (typeof token !== 'string' || /^\d+$/.test(token)) return null;
  let accountId;
  try {
    accountId = parseAccountIdKey(token);
  } catch {
    const matches = accountManager.accounts.filter(account => account.name === token);
    return matches.length === 1 ? matches[0] : null;
  }
  try {
    return resolveAccount(accountManager.accounts, accountId);
  } catch {
    return null;
  }
}

export function rewriteModel(body, modelMap) {
  if (!modelMap) return body;
  try {
    const parsed = JSON.parse(body.toString('utf8'));
    if (!parsed.model || !modelMap[parsed.model]) return body;
    return Buffer.from(JSON.stringify({ ...parsed, model: modelMap[parsed.model] }));
  } catch {
    return body;
  }
}

const DEFAULT_BODY_IDLE_TIMEOUT_MS = 120_000;
function resolveBodyIdleTimeout() {
  const configured = Number(process.env.TEAMCLAUDE_UPSTREAM_BODY_TIMEOUT_MS);
  return configured > 0 ? configured : DEFAULT_BODY_IDLE_TIMEOUT_MS;
}

export function readWithIdleTimeout(reader, ms) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const error = new Error(`upstream stream idle for ${ms}ms`);
      error.code = 'TEAMCLAUDE_BODY_TIMEOUT';
      reject(error);
    }, ms);
    timer.unref?.();
  });
  const read = reader.read();
  read.catch(() => {});
  return Promise.race([read, timeout]).finally(() => clearTimeout(timer));
}

function relayStream(req, res, upstream) {
  const target = new URL(`${upstream}${req.url}`);
  const headers = {};
  for (const [key, value] of Object.entries(req.headers)) {
    const lower = key.toLowerCase();
    if (lower.startsWith(':') || HOP_BY_HOP_HEADERS.has(lower) || lower === 'accept-encoding') continue;
    headers[key] = value;
  }
  const transport = target.protocol === 'http:' ? http : https;
  const upstreamReq = transport.request(target, { method: req.method, headers }, (upstreamRes) => {
    const responseHeaders = {};
    for (const [key, value] of Object.entries(upstreamRes.headers)) {
      if (!CONNECTION_SPECIFIC_HEADERS.has(key) && key !== 'content-encoding' && key !== 'content-length') responseHeaders[key] = value;
    }
    res.writeHead(upstreamRes.statusCode, responseHeaders);
    upstreamRes.pipe(res);
  });
  upstreamReq.on('error', (err) => {
    if (!res.headersSent) {
      console.error('[TeamClaude] Remote Control relay error:', err.message);
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: 'Upstream unreachable' } }));
    }
  });
  res.once('close', () => upstreamReq.destroy());
  if (['GET', 'HEAD'].includes(req.method)) upstreamReq.end();
  else req.pipe(upstreamReq);
}

export function relayUpgrade(req, socket, head, upstream, sx = null, headersTimeoutMs = null) {
  const target = new URL(`${upstream}${req.url}`);
  const headers = {};
  for (const [key, value] of Object.entries(req.headers)) {
    if (!key.startsWith(':') && key.toLowerCase() !== 'host') headers[key] = value;
  }
  const transport = target.protocol === 'http:' ? http : https;
  const useSx = sx?.useForConnect?.() === true;
  const proxy = useSx ? sx.getProxy() : null;
  const agent = proxy ? createUpgradeProxyAgent(target, proxy, sx) : undefined;
  const upstreamReq = transport.request(target, { method: req.method, headers, agent });
  const timeoutMs = positiveTimeout(headersTimeoutMs);
  const timer = timeoutMs && setTimeout(() => {
    const err = new Error(`upstream response headers timed out after ${timeoutMs}ms`);
    err.code = 'TEAMCLAUDE_HEADERS_TIMEOUT';
    upstreamReq.destroy(err);
    socket.destroy();
  }, timeoutMs);
  timer?.unref?.();
  const clearTimer = () => { if (timer) clearTimeout(timer); };
  upstreamReq.on('upgrade', (upstreamRes, upstreamSocket, upstreamHead) => {
    clearTimer();
    const lines = Object.entries(upstreamRes.headers)
      .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : value}`).join('\r\n');
    socket.write(`HTTP/1.1 ${upstreamRes.statusCode} ${upstreamRes.statusMessage}\r\n${lines}\r\n\r\n`);
    if (upstreamHead?.length) socket.write(upstreamHead);
    if (head?.length) upstreamSocket.write(head);
    socket.pipe(upstreamSocket);
    upstreamSocket.pipe(socket);
    socket.on('end', () => upstreamSocket.destroy());
    upstreamSocket.on('end', () => socket.destroy());
    socket.on('close', () => {
      upstreamSocket.destroy();
      agent?.destroy();
    });
    upstreamSocket.on('close', () => {
      socket.destroy();
      agent?.destroy();
    });
    // The 101 detaches this socket from upstreamReq, so the request's 'error'
    // listener below no longer covers it — and `pipe()` does not handle errors on
    // its destination either. A link that flaps mid-session then raises 'error'
    // (ECONNRESET / EPIPE) on a stream with no listener, which Node escalates to
    // an uncaught exception: one dropped upgraded connection would take the whole
    // proxy down, and with it every other session it was routing. Close the pair
    // instead; `socket.destroy()` reaches the agent through the 'close' handler
    // just above. The client side is already covered outside this callback.
    upstreamSocket.on('error', () => socket.destroy());
  });
  upstreamReq.once('response', () => { clearTimer(); socket.destroy(); });
  upstreamReq.on('error', () => { clearTimer(); socket.destroy(); });
  socket.on('error', () => upstreamReq.destroy());
  socket.on('close', () => upstreamReq.destroy());
  upstreamReq.end();
}

function createUpgradeProxyAgent(target, proxy, sx) {
  const Agent = target.protocol === 'http:' ? http.Agent : https.Agent;
  const agent = new Agent({ keepAlive: false });
  agent.createConnection = (_options, callback) => {
    const connect = target.protocol === 'http:'
      ? connectThroughProxy({
        proxyHost: proxy.host,
        proxyPort: proxy.port,
        auth: proxy.username ? `${proxy.username}:${proxy.password}` : null,
        targetHost: target.hostname,
        targetPort: Number(target.port) || 80,
      })
      : tunnelTls({
        proxy,
        targetHost: target.hostname,
        targetPort: Number(target.port) || 443,
        tlsOptions: sx.tlsOptions || {},
      });
    connect.then(socket => {
      if (target.protocol === 'http:') socket.resume();
      callback(null, socket);
    }, callback);
    return undefined;
  };
  return agent;
}

export function createProxyRequestListener({
  accountManager,
  upstream,
  logDir = null,
  hooks = {},
  maxBodyBytes = 32 * 1024 * 1024,
  sx = null,
  useSx = null,
  holdMs = 0,
  headersTimeoutMs = null,
  bodyTimeoutMs = null,
}) {
  const transport = {
    sx,
    fetchImpl: hooks.fetch || null,
    headersTimeoutMs: positiveTimeout(headersTimeoutMs),
    bodyTimeoutMs: positiveTimeout(bodyTimeoutMs),
    holdMs: positiveTimeout(holdMs) || 0,
  };
  let counter = 0;
  return async (req, res) => {
    const reqId = ++counter;
    const abort = new AbortController();
    const onClose = () => abort.abort();
    res.once('close', onClose);
    if (CLIENT_CREDENTIAL_PATHS.some((path) => (req.url || '').startsWith(path))) {
      relayStream(req, res, upstream);
      return;
    }
    try {
      const chunks = [];
      let bodyLength = 0;
      for await (const chunk of req) {
        bodyLength += chunk.length;
        if (bodyLength > maxBodyBytes) {
          req.destroy();
          if (!res.headersSent) {
            res.writeHead(413, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              type: 'error',
              error: { type: 'invalid_request_error', message: `Request body exceeds ${maxBodyBytes} bytes.` },
            }));
          }
          return;
        }
        chunks.push(chunk);
      }
      const ctx = createLiveRequestContext(req, Buffer.concat(chunks), {
        abortSignal: abort.signal,
        transport,
      });
      ctx.useSx = typeof useSx === 'function' ? useSx() : useSx;
      accountManager.beginSession(ctx.sessionId);
      hooks.onRequestStart?.(reqId, {
        method: req.method, path: req.url, model: ctx.model,
        advisorModel: ctx.advisorModel, sessionId: ctx.sessionId,
      });
      try {
        await forwardRequest(req, res, ctx.body, accountManager, upstream, 0, hooks, reqId, ctx, logDir);
      } finally {
        if (ctx.held) accountManager.releaseAccount(ctx.held);
        accountManager.endSession(ctx.sessionId);
        hooks.onRequestEnd?.(reqId, {
          method: req.method, path: req.url, account: ctx.account, status: ctx.status,
          model: ctx.model, advisorModel: ctx.advisorModel, sessionId: ctx.sessionId,
        });
      }
    } catch (err) {
      if (!res.headersSent && !res.destroyed) {
        console.error('[TeamClaude] Unhandled error:', err);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: 'Internal proxy error' } }));
      }
    } finally {
      res.removeListener('close', onClose);
    }
  };
}
