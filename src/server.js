import http from 'node:http';
import https from 'node:https';
import { timingSafeEqual } from 'node:crypto';
import { createWriteStream, mkdirSync, writeSync } from 'node:fs';
import { readdir, stat, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { ensureCerts, createConnectHandler, mitmHosts } from './mitm.js';
import { patchAccountUuid } from './account-uuid-rewrite.js';
import { parseRequestModel, parseAdvisorModel, weeklyBucketForModel, resolveSwitchThreshold } from './model.js';
import { sanitizeToolPairs } from './tool-pair-sanitize.js';
import { isTokenExpiringSoon } from './oauth.js';
import { parseAccountIdKey, resolveAccount } from './identity.js';
import { MaintenanceCoordinator } from './maintenance-coordinator.js';
import { sanitizeCacheControl, cacheControlSubfieldsToStrip } from './cache-control-sanitize.js';
import { sanitizeContentBlocks, contentBlockTypesToStrip } from './content-block-sanitize.js';
import { TopLevelFieldFinder, modelGlobMatches, parseRequestStream } from './model.js';
import { conversationDigest, pinKeyFor } from './conversation.js';
import { BodyWriter, truncationNote } from './request-log.js';
import { upstreamFetch, upstreamPoolStatus } from './upstream-fetch.js';
import { applyAuthHeaders, upstreamFor, rewritesBody, defaultHeadersTimeoutFor, providerForPath, providerOf, isSubscriptionAccount, canServeProvider, DEFAULT_PROVIDER, PROVIDERS } from './provider.js';
import { connectThroughProxy, tunnelTls } from './sx.js';
import { createEgressGuard } from './egress-guard.js';
import { isRoutingFailure, describeRouting } from './account-routing.js';
import { safeLine } from './safe-text.js';
import { forwardRefusal, guardedLookup, FORBIDDEN_FORWARD } from './forward-target.js';
import { renderDashboardHtml, dashboardCsp } from './dashboard.js';
import { createUsageRecorder, resolveUsageDimensions, usageDimensionHeaderNames } from './client-usage.js';
import { responsesEventUsage, isResponsesBody, normalizeResponsesUsage } from './responses-usage.js';
import { classificationPath } from './classification-path.js';
import { serveManagementMcp } from './mcp-tools.js';
import { codexSpentWindows, isAccountWideCodexWindow } from './codex-quota.js';
import { atomicConfigUpdate } from './config.js';
import { ConfigOpError, setThreshold, thresholdRatio } from './config-ops.js';
import { envVar, legacyControlUrl } from './brand.js';
/** @typedef {import('./types.js').CodedError} CodedError */
/**
 * @typedef {import('./account-manager.js').AccountManager} AccountManager
 * @typedef {AccountManager['accounts'][number]} ManagedAccount
 * @typedef {import('./sx.js').SxManager} SxManager
 * @typedef {import('./client-usage.js').ClientUsageTracker} ClientUsageTracker
 * @typedef {import('./client-usage.js').UsageDimensionTracker} UsageDimensionTracker
 * @typedef {http.IncomingMessage & {tcClient?: string|null}} ProxyRequest
 * @typedef {http.ServerResponse & {stream?: import('node:http2').ServerHttp2Stream}} ProxyResponse
 * @typedef {{method?: string, path?: string, account?: string|null, status?: number|null, model?: string|null, sessionId?: string|null, pinned?: boolean, client?: string|null}} RequestInfo
 * @typedef {object} ProxyHooks
 * @property {(id: number, info: RequestInfo) => void} [onRequestStart]
 * @property {(id: number, info: RequestInfo) => void} [onRequestEnd]
 * @property {(id: number, info: {model: string}) => void} [onRequestModel]
 * @property {(id: number, info: {account: string}) => void} [onRequestRouted]
 * @property {typeof fetch} [fetch]
 * @property {MaintenanceCoordinator} [maintenanceCoordinator]
 * @property {() => object} [getStatusExtra]
 * @property {() => object} [getQuotaExtra]
 * @property {() => Promise<{added?: number, removed?: number}|void>} [reload]
 * @property {() => Promise<unknown>} [probeQuota]
 * @property {(account: string, ...args: any[]) => Promise<any>} [setAccountPriority]
 * @property {(account: string, ...args: any[]) => Promise<any>} [setAccountDisabled]
 * @property {(accounts: ManagedAccount[]) => Promise<{redeemed?: boolean}|null|undefined>} [redeemCodexResetForPool]
 * @typedef {{apiKey?: string, clientKeys?: {name: string, key: string}[], trustLoopback?: boolean, host?: string, sessionDetail?: boolean, maxBodyBytes?: number|string, usageDimensions?: {name: string, header: string}[]}} ProxyConfig
 * @typedef {object} ServerConfig
 * @property {ProxyConfig} [proxy]
 * @property {string} [upstream]
 * @property {string|null} [logDir]
 * @property {string} [logLevel]
 * @property {number|string} [logMaxBodyBytes]
 * @property {number|string} [logRetentionHours]
 * @property {number} [maxRequestBytes]
 * @property {boolean} [activeWarmup]
 * @property {number} [warmupIntervalMs]
 * @property {number} [holdSeconds]
 * @property {number} [holdMs]
 * @property {number} [upstreamHeadersTimeoutMs]
 * @property {number} [upstreamBodyTimeoutMs]
 * @property {number} [headersTimeoutMs]
 * @property {number} [bodyTimeoutMs]
 * @property {string} [eventLogging]
 * @property {string[]} [blockedModels]
 * @property {number|null} [overflowQueueTimeoutMs]
 * @property {number} [maxPredispatchWaitMs]
 * @property {boolean} [sessionAffinity]
 * @property {string|null} [overloadFallbackModel]
 * @property {number} [transientRetries]
 * @property {boolean} [messageThreads]
 * @property {boolean} [stripOverageHeaders]
 * @typedef {{sx: SxManager|null, fetchImpl: typeof fetch|null, holdMs: number, headersTimeoutMs: number|null, bodyTimeoutMs: number|null}} RequestTransport
 * @typedef {object} LiveContextOptions
 * @property {number} [queueTimeoutMs]
 * @property {AbortSignal|null} [abortSignal]
 * @property {object|null} [affinityKey]
 * @property {ManagedAccount|null} [pinnedAccount]
 * @property {RequestTransport|null} [transport]
 * @property {string|null} [overloadFallbackModel]
 * @property {number} [transientRetries]
 * @property {number} [maxPredispatchWaitMs]
 * @typedef {object} LiveRequestContext
 * @property {Buffer} body
 * @property {string|null} model
 * @property {string|null} advisorModel
 * @property {string|null} sessionId
 * @property {string|null} account
 * @property {number|null} status
 * @property {Set<ManagedAccount>} authRetried
 * @property {Set<ManagedAccount>} tried429
 * @property {Set<ManagedAccount>} tried5xx
 * @property {Set<ManagedAccount>} tried403
 * @property {Set<ManagedAccount>} tried401
 * @property {Set<ManagedAccount>} triedSend
 * @property {number} overloadRetries
 * @property {ManagedAccount|null} held
 * @property {number} queueTimeoutMs
 * @property {number} maxPredispatchWaitMs
 * @property {number|null} predispatchWaitDeadline
 * @property {AbortSignal|null} abortSignal
 * @property {object|null} affinityKey
 * @property {boolean} sawModelWeekly
 * @property {ManagedAccount|null} pinnedAccount
 * @property {RequestTransport|null} transport
 * @property {string|null} overloadFallbackModel
 * @property {boolean} overloadFallbackAttempted
 * @property {number} transientRetries
 * @property {number} maxTransientRetries
 * @property {number|null} holdUntil
 * @property {boolean|null} [useSx]
 * @property {boolean} [proxyClosed]
 * @property {AbortSignal} [signal]
 */


export const HOP_BY_HOP_HEADERS = new Set([
  'host', 'connection', 'keep-alive', 'transfer-encoding',
  'te', 'trailer', 'upgrade', 'proxy-authorization', 'proxy-authenticate',
]);
// Path prefix for the deprecated URL-based account pin (superseded by TC_ACCT).
const PIN_PREFIX = '/tc-acct/';

/**
 * Does the request path carry a dot-segment (`.` or `..`, in any percent-encoded
 * spelling, on either slash)?
 *
 * Every path classification in the listener — the Codex pool, the
 * client-credential relay, the `/tc-acct/` pin — is a prefix test, while the
 * path itself is forwarded verbatim and resolved elsewhere. So
 * `/backend-api/codex/../conversations` classifies as Codex and reaches
 * chatgpt.com as `/backend-api/conversations`, pooled token attached;
 * `/v1/messages/../../api/oauth/profile` does not start with `/api/oauth/`,
 * takes the pool path, and reaches the profile endpoint with a rotated token —
 * the exact thing the relay exists to prevent for the literal path. No client
 * of ours ever sends such a path; refusing the request is the whole fix.
 *
 * Read on the classification path, which is decoded once and has its
 * backslashes folded (the URL parser treats one as a slash for http(s), so
 * `new URL()` folds it on the way out too). `..%2f..%2f` and `..\..\` are
 * therefore the same request as `../../` here, as they are to whatever
 * resolves them — and splitting on `/` alone is enough, since no separator
 * survives classificationPath in any other spelling.
 */
/** @param {string|undefined} url */
export function hasDotSegment(url) {
  return classificationPath(url).split('/').some((s) => s === '.' || s === '..');
}
// How long to wait before the one retry of a headerless 429 — a 429 carrying no
// retry-after and no anthropic-ratelimit-* headers at all.
//
// Observed over a 32-minute window on a live fleet: these land about once every
// 8 minutes on Fable traffic and never on any other model; they follow the
// request onto whichever account the failover hop moves it to; consecutive
// refusals arrive 0.6-0.8s apart; and the client's own retry, after the 2m 38s
// backoff Claude Code applies, usually succeeds.
//
// 2s is chosen against those numbers rather than measured from them — nothing
// observed says how long the limit actually lasts. It sits above the 0.6-0.8s
// the hop already re-asked across and was refused, and far below the backoff the
// client would otherwise serve out. That is the entire argument for it, which is
// why it is an env var: TEAMCLAUDE_HEADERLESS_429_RETRY_DELAY_MS.
//
// One delay, not a ladder: the limit's window is unknown, and a second guess at
// it would cost the client the wait without evidence that it helps. So the worst
// case is the retry being refused too, and the client getting the 429 it gets
// today about 2s later.
const DEFAULT_HEADERLESS_429_RETRY_DELAY_MS = 2000;

/**
 * The wait before a headerless 429 is re-asked, in ms — or 0 for "do not retry".
 *
 * 0 is a setting, not a missing value: an operator who would rather have the
 * 429 at once than have the transient absorbed needs a way to say so, and a
 * delay of nothing is the natural spelling. Unset, empty, negative or
 * unparseable all mean the default, so a typo cannot switch the retry off.
 *
 * @returns {number}
 */
function resolveHeaderless429RetryDelayMs() {
  const raw = envVar('HEADERLESS_429_RETRY_DELAY_MS');
  if (raw == null || raw.trim() === '') return DEFAULT_HEADERLESS_429_RETRY_DELAY_MS;
  const env = Number(raw);
  if (env === 0) return 0;
  return env > 0 ? env : DEFAULT_HEADERLESS_429_RETRY_DELAY_MS;
}
const OAUTH_ENTITLEMENT_ERROR_CODE = 'oauth_not_allowed_for_organization';
const ERROR_BODY_INSPECTION_LIMIT = 64 * 1024;
// How long an idle keep-alive connection is held open.
//
// Node's default is 5s, but a client's connection pool may hold the same socket
// far longer, and whoever closes first wins: when the server does, the client
// finds out only by writing to a socket that is already gone, which surfaces as
// a request that fails in ~130ms with no upstream involvement. The Codex
// sidecar is such a client — reqwest's pool_idle_timeout defaults to 90s and it
// never overrides it — so outlive the longest pool and let the client always be
// the one to close. headersTimeout bounds an in-progress request's headers, not
// the idle gap between them (measured), so it is deliberately left alone.
export const KEEP_ALIVE_TIMEOUT_MS = 120_000;

// The `unavailableReason` verdicts a redeemed Codex reset credit actually
// clears, and therefore the only ones worth spending one over. A redemption
// re-reads the account's quota and drops its rate-limit hold, which answers
// exactly these two; every other reason survives it untouched — an operator's
// own decision (disabled, capped), a credential or policy problem (error,
// entitlement), or an eligibility rule (route) that no quota window governs.
const RESET_CLEARS = new Set(['quota', 'throttled']);

/** Classify only the structured organization-policy denial observed upstream.
 * Message text and generic permission errors are deliberately not enough. */
/** @param {Uint8Array} body */
export function isOAuthEntitlementDenied(body) {
  try {
    const parsed = JSON.parse(Buffer.from(body).toString('utf8'));
    return parsed?.error?.details?.error_code === OAUTH_ENTITLEMENT_ERROR_CODE;
  } catch {
    return false;
  }
}

// Error payloads are normally tiny, but an alternate upstream is configurable.
// Bound the diagnostic read so a hostile chunked 403 cannot make the proxy buffer
// an arbitrary response merely to decide whether it should quarantine an account.
/** @param {ReadableStream<Uint8Array>|null} body @param {number} [limit] */
async function readErrorBody(body, limit = ERROR_BODY_INSPECTION_LIMIT) {
  if (!body) return Buffer.alloc(0);
  const reader = body.getReader();
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) return Buffer.concat(chunks, length);
      length += value.byteLength;
      if (length > limit) {
        await reader.cancel();
        return null;
      }
      chunks.push(Buffer.from(value));
    }
  } catch {
    await reader.cancel().catch(() => {});
    return null;
  } finally {
    reader.releaseLock();
  }
}

// Response header names that are connection-specific and thus illegal on an
// HTTP/2 response (Node's Http2ServerResponse.writeHead rejects them). Also
// hop-by-hop on h1, so stripping them is correct on both paths.
const CONNECTION_SPECIFIC_HEADERS = new Set([
  'connection', 'keep-alive', 'transfer-encoding', 'upgrade',
  'proxy-connection', 'te', 'trailer',
]);

// Response headers describing the SERVING organization's billing state:
// whether extra usage (overage) is enabled, why it is not, whether it is in
// use, and what the org could upgrade to. A pool whose accounts belong to
// several organizations returns these for whichever org served the response,
// and Claude Code caches them as if they described the user's own org. After a
// response from an org with extra usage disabled, the client can report "no
// usage credits", block a model the pool still has plan quota for, or show a
// consent dialog offering to enable paid overage on the wrong org.
//
// With `stripOverageHeaders: true` in the config, only this family
// (anthropic-ratelimit-unified-overage-* and
// anthropic-ratelimit-unified-upgrade-paths) is removed, and only from the
// client-bound copy. The plan-quota headers (5h, 7d and 7d_oi status,
// utilization and reset, the overall status, representative-claim, fallback)
// always pass through: the client needs them for its usage readout, and they
// describe the account that actually served the request. updateQuota receives
// the unfiltered headers either way and does not persist the overage family.
// The default (false) passes everything through unchanged.
// relayHttpForward (absolute-form relay) is filtered too, for consistency:
// Claude Code reaches Anthropic via CONNECT, so in practice it does not carry
// these headers.
const OVERAGE_HEADER_PREFIX = 'anthropic-ratelimit-unified-overage-';
const OVERAGE_HEADER_NAMES = new Set(['anthropic-ratelimit-unified-upgrade-paths']);

/**
 * @param {string} name
 * @returns {boolean}
 */
export function isOverageHeader(name) {
  const lk = String(name).toLowerCase();
  return lk.startsWith(OVERAGE_HEADER_PREFIX) || OVERAGE_HEADER_NAMES.has(lk);
}

// Read off the shared config object (like eventLogging) when a request is
// dispatched, so a reload applies to subsequent requests without a restart; a
// request already in flight keeps the value it was dispatched with. Off
// unless explicitly enabled.
/**
 * @param {unknown} config
 * @returns {boolean}
 */
export function shouldStripOverageHeaders(config) {
  return /** @type {{ stripOverageHeaders?: unknown } | null | undefined} */ (config)?.stripOverageHeaders === true;
}

// undici wraps every transport failure as a bare TypeError("fetch failed") and
// puts the real reason (ECONNRESET, socket hang up, TLS, DNS) on err.cause. The
// handler below classified and logged only err.message, so every distinct
// transport fault reached the operator as the same three words and err.code
// checks never matched. Flatten the chain so both the log and the classifier
// see the actual cause.
// Node's happy-eyeballs dialer (autoSelectFamily, on by default) reports a
// connect where EVERY address failed as an AggregateError whose own message is
// EMPTY — the per-address reasons sit in `.errors`. api.anthropic.com is
// multi-address (measured: an A and an AAAA record), so this is reachable here,
// and walking only the cause chain prints the useless "AggregateError: " with
// nothing after it. Expanding `.errors` is upstream's describeConnectError
// (KarpelesLab 44477b1); the per-link name/code that the chain adds is ours and
// is what makes a log line say which fault class it was. Keep both: the chain
// gives the shape, the expansion gives the reasons.
export function describeErrorChain(err) {
  const parts = [];
  let e = err, depth = 0;
  while (e && depth++ < 5) {
    const reasons = Array.isArray(e.errors)
      ? e.errors.map(c => c?.message).filter(Boolean).join('; ')
      : '';
    const detail = e.message || reasons;
    parts.push(`${e.name || 'Error'}: ${detail}${reasons && e.message ? ` [${reasons}]` : ''}${e.code ? ` (code=${e.code})` : ''}`);
    e = e.cause;
  }
  return parts.join(' <- ');
}

function rootErrorCode(err) {
  let e = err, depth = 0;
  while (e && depth++ < 5) {
    if (e.code) return e.code;
    e = e.cause;
  }
  return undefined;
}

/** @param {ProxyRequest} req @param {LiveRequestContext & {provider?: string}} ctx */
function admissionShape(req, ctx) {
  const route = (req.url || '').split('?')[0];
  const pin = ctx.pinnedAccount?.accountIdKey || null;
  return JSON.stringify([ctx.provider || null, ctx.model || null, ctx.advisorModel || null, route, pin]);
}
/** @param {ProxyRequest} req @param {ProxyResponse} res */
function refuseAdmission(req, res) {
  req.resume();
  res.writeHead(429, { 'Content-Type': 'application/json', 'retry-after': '5' });
  res.end(JSON.stringify({ type: 'error', error: {
    type: 'rate_limit_error', message: 'Proxy at capacity; retry shortly.',
  } }));
}
/** @param {ProxyRequest} req @param {Buffer} body
 * @param {LiveContextOptions} [options] @returns {LiveRequestContext} */
function createLiveRequestContext(req, body, {
  queueTimeoutMs = 15_000,
  abortSignal = null,
  affinityKey = null,
  pinnedAccount = null,
  transport = null,
  overloadFallbackModel = null,
  transientRetries = 1,
  maxPredispatchWaitMs = DEFAULT_MAX_PREDISPATCH_WAIT_MS,
} = {}) {
  const sanitizedBody = body;
  const sessionId = clientSessionId(req.headers);
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
    tried401: new Set(),
    triedSend: new Set(),
    overloadRetries: 0,
    held: null,
    queueTimeoutMs,
    maxPredispatchWaitMs,
    predispatchWaitDeadline: null,
    abortSignal,
    affinityKey,
    sawModelWeekly: false,
    pinnedAccount,
    transport,
    overloadFallbackModel: resolveOverloadFallbackModel(model, overloadFallbackModel),
    overloadFallbackAttempted: false,
    transientRetries: 0,
    maxTransientRetries: Math.max(0, transientRetries),
    holdUntil: null,
  };
}

/** @param {unknown} a @param {unknown} b */
export function safeKeyEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

/** @param {string|undefined} addr */
export function isLoopbackAddr(addr) {
  return addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1';
}
const RETRY_AFTER_FALLBACK_SECONDS = 60;
const RETRY_AFTER_MAX_SECONDS = 300;
// A short backoff for requests that cannot enter the bounded queue. This does not
// solve capacity shortages; admitted requests should wait for a slot instead.
const CAPPED_RETRY_AFTER_SECONDS = 5;
// Sleep PAST a throttle deadline, never exactly to it. `setTimeout` fires on libuv's
// cached loop clock while the availability check re-reads `Date.now()`, and a loaded
// event loop leaves that cache behind wall time — so the sleep can return while the
// account still reads `throttled`. With `maxRetries = accounts.length`, a one-account
// fleet spends its entire retry budget on that single early wake and answers 429 after
// having waited the full window. Margin is negligible against waits measured in
// seconds. (Same class as the `_drainWaiters` pause boundary: sleep to a deadline,
// then re-read a different clock and find it has not arrived.)
const THROTTLE_WAKE_MARGIN_MS = 5;
// A request may wait through several throttle windows before an account frees.
// Each individual sleep is correctly bounded by the soonest deadline, but the SUM
// was not: with `maxRetries = accounts.length` the loop can sleep once per account,
// and throughout it the client receives NOTHING — no status line, no headers, no
// body. Claude Code's watchdog then reports "Waiting for API response ... check
// your network", which names neither the cause (no quota left) nor the cure, and
// sends the reader after a network fault that does not exist.
//
// A 429 carrying a real retry-after is strictly more useful than silence: the
// client already knows how to honour it. So bound the total time a request may
// spend waiting before it MUST answer. Riding out a short throttle still works —
// only a wait longer than the budget is converted into an answer.
// 2x the overflow queue timeout (15s), the existing precedent for how long a
// request may wait before it owes the client a 429.
const DEFAULT_MAX_PREDISPATCH_WAIT_MS = 30_000;

// Remaining wait budget in ms. The deadline is armed on first use rather than at
// request start, so a request that never waits is unaffected, and time already
// spent talking to upstream never counts against a later throttle wait.
/** @param {Pick<LiveRequestContext, 'maxPredispatchWaitMs'|'predispatchWaitDeadline'>} ctx */
function remainingWaitBudget(ctx) {
  if (!(ctx.maxPredispatchWaitMs > 0)) return Infinity;
  if (ctx.predispatchWaitDeadline == null) {
    ctx.predispatchWaitDeadline = Date.now() + ctx.maxPredispatchWaitMs;
  }
  return ctx.predispatchWaitDeadline - Date.now();
}
const MODEL_RESPONSE_BUCKETS = Object.freeze({
  unified7dFable: '7d_oi',
  unified7dSonnet: '7d_sonnet',
});

/** @param {unknown} value @param {number} [now] */
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
  const bucket = weeklyBucketForModel(model);
  const label = MODEL_RESPONSE_BUCKETS[bucket];
  if (!label) return false;
  const utilization = Number.parseFloat(headers[`anthropic-ratelimit-unified-${label}-utilization`]);
  return Number.isFinite(utilization) && utilization >= resolveSwitchThreshold(threshold, bucket);
}

/**
 * Classify only the current 429 response. Account status/quota cache is
 * deliberately excluded: retained headers cannot classify a later response.
 */
export function classify429(headers, { model = null, advisorModel = null, switchThreshold = 0.98 } = {}) {
  const shared5hRejected = headers['anthropic-ratelimit-unified-5h-status'] === 'rejected'
    || headers['anthropic-ratelimit-unified-7d-status'] === 'rejected';
  const modelBinding = isBindingModelBucket(headers, model, switchThreshold)
    || isBindingModelBucket(headers, advisorModel, switchThreshold);
  const unifiedRejected = headers['anthropic-ratelimit-unified-status'] === 'rejected';
  if (shared5hRejected || (unifiedRejected && !modelBinding)) return 'account-quota';
  if (modelBinding) return 'model-quota';
  return 'residual';
}

// Headers a forwarding proxy adds to name the caller it forwards for. Any of
// them on a loopback-sourced request says the socket's peer is a proxy on this
// host, not the caller.
const FORWARDED_HEADERS = ['x-forwarded-for', 'x-real-ip', 'forwarded'];

/** Whether the request carries a forwarding proxy's mark. */
/** @param {http.IncomingHttpHeaders} headers */
export function isForwardedRequest(headers) {
  return FORWARDED_HEADERS.some(h => headers?.[h] != null && headers[h] !== '');
}

/**
 * Whether a key-less caller is admitted on the strength of its address alone.
 * All three gates — HTTP, CONNECT and the WebSocket upgrade — ask this one
 * question, so they cannot drift apart.
 *
 * The exemption is trying to answer "is this caller on this machine", and the
 * socket address stops answering that as soon as anything forwards. The
 * ordinary way this proxy is deployed on a public name is nginx or Caddy
 * terminating TLS in front of a listener bound to 127.0.0.1 — and then every
 * caller on the internet is loopback-sourced, the key gate never runs, and an
 * anonymous POST /v1/messages spends the fleet's quota (#324). The browser
 * checks that sit behind this one (Origin, Host) do not catch it: curl sends
 * neither, and the Host header is written by the operator's own reverse proxy,
 * so it reports the proxy's configuration rather than the request's provenance.
 *
 * Two answers, cheapest first:
 *   - A request carrying a forwarding header (X-Forwarded-For, X-Real-IP,
 *     Forwarded) is refused the exemption. Costs nothing to configure and fails
 *     closed on exactly the deployments that are exposed; a reverse proxy set
 *     up to send none of them is the case the setting below is for.
 *   - `proxy.trustLoopback: false` switches the exemption off outright. The CLI
 *     presents the proxy key on every call of its own, so a local install keeps
 *     working with it; documented as required behind a reverse proxy.
 */
/** @param {http.IncomingHttpHeaders} headers @param {string|undefined} remoteAddress @param {ProxyConfig|undefined} proxyConfig */
export function loopbackExempt(headers, remoteAddress, proxyConfig) {
  if (proxyConfig?.trustLoopback === false) return false;
  if (!isLoopbackAddr(remoteAddress)) return false;
  return !isForwardedRequest(headers);
}

/**
 * Why the MCP endpoint refuses a request when the config holds no key at all,
 * or null when it may be served. With a key configured this is always null:
 * the key gate has already decided.
 *
 * Without one the key gate admits everybody, which is tolerable for forwarding
 * on a private network and is not for tools that remove accounts. So the
 * caller has to be on this machine, by the same test the loopback exemption
 * uses — a loopback peer, no forwarding header, and `trustLoopback` not
 * switched off. The Host check alone does not say that: it is there for
 * browsers, and on a non-loopback bind anything that is not a browser can
 * simply send `Host: localhost`. It is still asked, because a page rebound to
 * 127.0.0.1 does arrive from loopback.
 * @param {import('node:http').IncomingHttpHeaders} headers
 * @param {string|undefined} remoteAddress
 * @param {Record<string, any>|undefined} proxyConfig
 * @param {string|null} [boundHost]  the address the server bound, when it is not `proxyConfig.host`
 * @returns {string|null}
 */
export function keylessMcpRefusal(headers, remoteAddress, proxyConfig, boundHost = null) {
  if (!resolveClientAuth(proxyConfig, undefined).ok) return null;
  if (!loopbackExempt(headers, remoteAddress, proxyConfig)) {
    return 'request refused: with no proxy key configured the MCP endpoint serves only this machine; set proxy.apiKey to reach it from elsewhere';
  }
  // The address actually bound, when the caller knows it (TEAMCLAUDE_HOST can
  // differ from proxy.host — see createProxyServer's `bindHost`).
  if (!isLocalHostHeader(headers.host ?? headers[':authority'], boundHost || proxyConfig?.host)) {
    return 'request refused: the Host header does not name this proxy';
  }
  return null;
}

/**
 * Which identity a presented key authenticates as, checked against the shared
 * `proxy.apiKey` and every `proxy.clientKeys` entry ({ name, key }).
 *
 * Returns { ok, client }: ok=false → reject; `client` is the matching entry's
 * name (per-client usage is booked against it), or null for the shared key —
 * the shared key predates client identities and stays unattributed rather than
 * inventing one. With no keys configured at all the gate is open (unchanged
 * behavior), also unattributed.
 *
 * Client keys are checked first so a clientKeys entry that duplicates the
 * shared key still yields its name. Every candidate uses the constant-time
 * compare; the key count is operator-controlled and small, so scanning all of
 * them leaks nothing useful.
 */
// Config arrays already checked for shape, so the warnings below fire once per
// loaded list (a reload hands over a new array) rather than once per request.
const checkedClientKeys = new WeakSet();
/** @param {{name: string, key: string}[]} clientKeys */
function usableClientKeys(clientKeys) {
  if (!checkedClientKeys.has(clientKeys)) {
    checkedClientKeys.add(clientKeys);
    const seen = new Set();
    for (const entry of clientKeys) {
      const name = typeof entry?.name === 'string' ? entry.name.trim() : '';
      if (!name || !entry?.key) {
        console.error('[TeamClaude] proxy.clientKeys: an entry without a name and a key is ignored (usage is attributed by name)');
      } else if (seen.has(name)) {
        console.error(`[TeamClaude] proxy.clientKeys: duplicate name "${name}" — its keys share one usage counter`);
      }
      seen.add(name);
    }
  }
  return clientKeys.filter(e => typeof e?.name === 'string' && e.name.trim() && e.key);
}

/** @param {ProxyConfig|undefined} proxyConfig @param {unknown} presented */
export function resolveClientAuth(proxyConfig, presented) {
  const shared = proxyConfig?.apiKey;
  const clientKeys = Array.isArray(proxyConfig?.clientKeys) ? usableClientKeys(proxyConfig.clientKeys) : [];
  if (!shared && clientKeys.length === 0) return { ok: true, client: null };
  for (const entry of clientKeys) {
    if (safeKeyEqual(presented, entry.key)) {
      return { ok: true, client: entry.name.trim() };
    }
  }
  if (shared && safeKeyEqual(presented, shared)) return { ok: true, client: null };
  return { ok: false, client: null };
}

// Control-plane writes that change the config file, with the refusal a
// caller holding a client key (rather than the operator's proxy.apiKey) gets.
// See the check in createProxyServer for why a tenant may not reach these.
const CLIENT_KEY_REFUSED_PATHS = new Map([
  ['/teamclaude/threshold', 'a client key cannot change settings'],
  ['/teamclaude/priority', 'a client key cannot change accounts'],
  ['/teamclaude/disable', 'a client key cannot change accounts'],
]);

/**
 * @typedef {{model: string, version: string, beta: string|null, system: unknown, _elicitsModelWeekly?: boolean, _restored?: boolean}} ProbeTemplate
 * @typedef {{account: string, stage: string, message: string}} RefreshFailure
 * @typedef {import('node:http').Server & {
 * refreshQuotaAll: () => Promise<number | {targets: number, measured: number, failures?: RefreshFailure[]}>,
 * maintenanceCoordinator: MaintenanceCoordinator,
 * exportProbeTemplate: () => ProbeTemplate|null,
 * importProbeTemplate: (template: Partial<ProbeTemplate>|null) => boolean
 * }} ProxyServer
 * @param {AccountManager} accountManager
 * @param {ServerConfig} config
 * @param {ProxyHooks} [hooks]
 * @param {SxManager|null} [sx]
 * @param {ClientUsageTracker|null} [clientUsage]
 * @param {UsageDimensionTracker|null} [dimensionUsage]
 * @param {{ bindHost?: string|null }} [opts]  `bindHost`: the address the caller
 *   binds, when it is not `config.proxy.host` (TEAMCLAUDE_HOST overrides it). The
 *   DNS-rebinding Host check accepts that address as naming this machine; given
 *   only the config value, a server bound off-box through the env var refused a
 *   key-less caller naming the very address it listens on (#423).
 * @returns {ProxyServer}
 */
export function createProxyServer(accountManager, config, hooks = {}, sx = null, clientUsage = null, dimensionUsage = null, { bindHost = null } = {}) {
  const boundHost = () => bindHost || config.proxy?.host;
  const upstream = config.upstream || 'https://api.anthropic.com';
  const holdMs = (config.holdSeconds || 0) * 1000;
  const transport = {
    sx, fetchImpl: hooks.fetch || null,
    headersTimeoutMs: positiveTimeout(config.upstreamHeadersTimeoutMs ?? config.headersTimeoutMs),
    bodyTimeoutMs: positiveTimeout(config.upstreamBodyTimeoutMs ?? config.bodyTimeoutMs),
    holdMs: positiveTimeout(config.holdMs) ?? holdMs,
  };

  // The log directory is made up front and synchronously, so a path that
  // cannot be a directory (a file sitting there, no permission) is reported
  // ONCE here and logging is switched off — instead of the server looking
  // healthy while every request discovers the failure on its own. Never fatal:
  // a broken log directory is no reason to refuse traffic. 0700 because the
  // files hold full prompts and responses; an existing directory keeps its mode.
  let logDir = config.logDir || null;
  if (logDir) {
    try {
      mkdirSync(logDir, { recursive: true, mode: 0o700 });
    } catch (err) {
      console.error(`[TeamClaude] Request logging disabled: cannot create logDir ${logDir}: ${err.message}`);
      logDir = null;
    }
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
  const warmupIntervalMs = typeof config.warmupIntervalMs === 'number' && Number.isFinite(config.warmupIntervalMs)
    ? Math.max(0, config.warmupIntervalMs)
    : 5 * 60 * 1000;
  /** @type {ProbeTemplate|null} */
  let probeTemplate = null;   // committed { model, version, beta, system } — only after a 2xx
  let warmupClosed = false;   // set on server close: stop scheduling, abort in-flight probes
  const maintenance = hooks.maintenanceCoordinator || new MaintenanceCoordinator(accountManager);

  // Stage a candidate template from a genuine /v1/messages request WITHOUT
  // committing — we only trust the shape once upstream has accepted it (see
  // commitProbeTemplate). Path-exact so /v1/messages/count_tokens isn't taken for
  // inference. Returns the candidate (or null). Called AFTER the response (the
  // caller decides whether a commit/upgrade is even possible), so the body
  // parse is only ever paid for the one or two requests that actually commit.
  /** @param {ProxyRequest} req @param {Buffer} body @returns {ProbeTemplate|null} */
  function stageProbeTemplate(req, body) {
    if (!activeWarmup) return null;
    if (req.method !== 'POST' || (req.url || '').split('?')[0] !== '/v1/messages') return null;
    let json;
    try { json = JSON.parse(body.toString()); } catch { return null; }
    if (!json || typeof json.model !== 'string') return null;
    return {
      model: json.model,
      version: typeof req.headers['anthropic-version'] === 'string' ? req.headers['anthropic-version'] : '2023-06-01',
      beta: typeof req.headers['anthropic-beta'] === 'string' ? req.headers['anthropic-beta'] : null,
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
  /** @param {ProbeTemplate} candidate @param {number|null} status @param {boolean} [elicitsModelWeekly] */
  function commitProbeTemplate(candidate, status, elicitsModelWeekly = false) {
    if (!activeWarmup || warmupClosed) return;
    if (status == null || !(status >= 200 && status < 300)) return; // only trust an accepted shape
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

  /** @param {ProbeTemplate} t */
  function buildProbeBody(t) {
    /** @type {{model: string, max_tokens: number, messages: {role: string, content: string}[], system?: unknown}} */
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
  /** @param {import('./account-manager.js').AccountManager['accounts'][number]} account
   * @param {{force?: boolean, onFailure?: (failure: {stage: string, message: string}) => void}} [options] */
  async function performWarmupAccount(account, { force: _force = false, onFailure } = {}) {
    if (!probeTemplate || warmupClosed || !canReplayAnthropicTemplate(account)) return;
    // Don't refresh from a background probe; skip an OAuth account that needs one.
    if (account.type === 'oauth' && isTokenExpiringSoon(account.expiresAt)) return;
    // Eligibility is checked before queuing. Once the coordinator has reserved
    // the canonical slot this account is necessarily in-flight, so re-running
    // warmupCandidates() here would reject the task itself.
    const probe = { signal: maintenance.abortController.signal, cleanup() {} };
    try {
      /** @type {Record<string, string>} */
      const headers = { 'content-type': 'application/json', 'anthropic-version': probeTemplate.version };
      if (probeTemplate.beta) headers['anthropic-beta'] = probeTemplate.beta;
      applyAuthHeaders(headers, account);

      const res = await fetchUpstream(`${upstreamFor(account, upstream)}/v1/messages`, {
        method: 'POST', headers, body: buildProbeBody(probeTemplate), signal: probe.signal,
        // The account's own egress proxy (accounts[].routing, #441): a probe
        // spends this account's credential, so it leaves the way its requests do.
        routing: account.routing || null,
      }, {
        transport,
        useSx: transport.sx?.useByDefault?.() === true,
      });
      /** @type {Record<string, string>} */
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
  /** @param {ManagedAccount} account @param {{force?: boolean}} [options] */
  function warmupAccount(account, options = {}) {
    if (!canReplayAnthropicTemplate(account)) return false;
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
      canReplayAnthropicTemplate(a) && a.status !== 'error' && a.inflight === 0);
    /** @type {RefreshFailure[]} */
    const failures = [];
    const outcomes = await Promise.all(targets.map(a => maintenance.run(a, 'forced-refresh', 0, async () => {
      if (!canReplayAnthropicTemplate(a)) return false;
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
    /** @type {{targets: number, measured: number, failures?: RefreshFailure[]}} */
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
      canReplayAnthropicTemplate(a) && a.enabled !== false && a.status !== 'error' && a.inflight === 0
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

  const server = /** @type {ProxyServer} */ (http.createServer(async (/** @type {ProxyRequest} */ req, res) => {
    try {
      // The control plane answers to its new name as well (issue #72): a URL
      // under /teamrouter/ is rewritten to /teamclaude/ once, here, so every
      // route below keeps matching the one spelling it always has. Only the
      // proxy's own prefix is touched; nothing forwarded upstream starts with it.
      const legacyUrl = legacyControlUrl(req.url);
      if (legacyUrl) req.url = legacyUrl;

      // Dashboard page — served BEFORE the auth gate on purpose. The page is a
      // static asset containing no data: everything it shows comes from
      // /teamclaude/status, which stays behind the gate and is fetched by the
      // page's own script with the key. A browser address bar cannot send
      // x-api-key, so gating the asset would just 401 every remote browser
      // without protecting anything.
      if (req.method === 'GET' && req.url === '/teamclaude/dashboard') {
        // The page keeps the proxy key in localStorage; the policy is what
        // stops any script but its own from ever running next to it.
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-store',
          'Content-Security-Policy': dashboardCsp(),
          'X-Content-Type-Options': 'nosniff',
        });
        res.end(renderDashboardHtml());
        return;
      }

      // Auth check — skip for localhost connections. `config.proxy` is read per
      // request (not captured at creation) so a reload that edits clientKeys
      // applies to a running server, matching how eventLogging/blockedModels
      // are read live further down the pipeline.
      const clientKey = req.headers['x-api-key'];
      const isLocal = loopbackExempt(req.headers, req.socket.remoteAddress, config.proxy);
      const auth = resolveClientAuth(config.proxy, clientKey);
      if (!auth.ok && !isLocal) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          type: 'error',
          error: { type: 'authentication_error', message: 'Invalid proxy API key' },
        }));
        return;
      }
      // Client identity for per-client usage. A loopback caller that presented
      // a valid client key is attributed like any other; loopback without one
      // passed only via the exemption and stays unattributed.
      Object.assign(req, { tcClient: auth.ok ? auth.client : null });

      // Control-plane mutations are refused when the request was issued by a web
      // page. The gate above exempts loopback from the API key, so without this
      // any site the operator happens to visit can POST here cross-origin: a
      // `fetch(..., {mode:'no-cors', body})` with a text/plain content type is a
      // CORS "simple request", so no preflight is sent and the request lands.
      // The page cannot read the reply, but the side effect is the point —
      // forcing the whole fleet onto one named account is a targeted quota
      // drain, and reload is reachable the same way.
      //
      // Origin (and Sec-Fetch-Site) are set by the browser and cannot be
      // forged from page JavaScript, while curl and the CLI send neither — so
      // this costs legitimate callers nothing. Deliberately not a content-type
      // requirement, which would also close the hole but would break the
      // documented `curl -X POST .../teamclaude/reload` that sends no body.
      const crossOrigin = !isSameOriginControlRequest(req);
      if (crossOrigin && req.method === 'POST' && (req.url || '').startsWith('/teamclaude/')) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          ok: false,
          error: 'cross-origin request refused: the control plane is not reachable from a web page',
        }));
        return;
      }

      // A client key (proxy.clientKeys) names a tenant of the proxy, not its
      // operator: it may spend quota under its own name, read status and nudge
      // the running fleet (switch, reload — runtime-only and older than client
      // keys), but not rewrite what the config file says. The switch threshold
      // is a SETTING governing every account, and one tenant must not be able
      // to retire the whole fleet for the others; the account controls decide
      // which accounts rotation may reach at all. The shared proxy.apiKey and
      // the key-exempt loopback caller are the operator and stay allowed.
      // Refused here, before the body is read, so a request that will not be
      // honoured is never parsed.
      const clientKeyRefusal = req.method === 'POST' ? CLIENT_KEY_REFUSED_PATHS.get(req.url || '') : undefined;
      if (req.tcClient && clientKeyRefusal) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: clientKeyRefusal }));
        return;
      }

      // Forward-proxy request (HTTP_PROXY): an absolute-form URL is a tool
      // proxying plain HTTP to some host. Account logic is only for hosts we
      // manage (the Anthropic upstream, which is HTTPS-only and never arrives
      // this way); forward anything else transparently instead of hijacking it.
      // Dispatched BEFORE the loopback-only checks below: a page cannot make a
      // browser emit an absolute-form request line, the relay injects no fleet
      // credential, and its Host header names the TARGET, not this proxy.
      if (/^https?:\/\//i.test(req.url || '')) { relayHttpForward(req, res, shouldStripOverageHeaders(config)); return; }

      // A request admitted ONLY by the loopback exemption — no valid key — is
      // held to two more conditions. Both target the same actor: a web page in
      // the operator's browser, whose requests are loopback-sourced too. A
      // caller that presented a valid key has proven itself and skips both.
      if (!auth.ok) {
        // Cross-origin, for every method and path this time. The control-plane
        // gate above covers its mutations, but the same no-cors trick reaches
        // POST /v1/messages, where the proxy injects a fleet credential (a quota
        // drain, with prompt content booked to the operator), and a GET of
        // /teamclaude/status is unreadable to the page only for as long as no
        // CORS header ever leaks. Same browser-set headers, same zero cost to
        // curl, the CLI and Node clients, which send neither.
        if (crossOrigin) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            type: 'error',
            error: { type: 'permission_error', message: 'cross-origin request refused: a web page cannot use the proxy without a key' },
          }));
          return;
        }
        // DNS rebinding. A page at attacker.example whose name flips to
        // 127.0.0.1 sends requests that are loopback-sourced AND same-origin as
        // far as the browser can tell, and it can read the answers. What it
        // cannot forge is the Host header, which the browser derives from its
        // own URL bar — so a key-less loopback request must name this machine.
        if (!isLocalHostHeader(req.headers.host ?? req.headers[':authority'], boundHost())) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            type: 'error',
            error: { type: 'permission_error', message: 'request refused: the Host header does not name this proxy' },
          }));
          return;
        }
      }

      // Status endpoint
      if (req.method === 'GET' && req.url === '/teamclaude/status') {
        const status = accountManager.getStatus({ sessionDetail: config.proxy?.sessionDetail === true });
        const extra = hooks.getStatusExtra?.() || {};
        res.writeHead(200, { 'Content-Type': 'application/json' });
        // Counters only: how full the upstream admission gate is (see
        // upstream-fetch.js), never which origins or requests.
        res.end(JSON.stringify({ ...extra, ...status, upstreamPool: upstreamPoolStatus() }, null, 2));
        return;
      }

      // Tier-weighted fleet quota for lightweight consumers such as a shell or
      // Claude Code status line. Unlike /teamclaude/status this omits routing,
      // usage counters and server diagnostics, and never reaches upstream.
      if (req.method === 'GET' && req.url === '/teamclaude/quota') {
        const extra = hooks.getQuotaExtra?.() || {};
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ...accountManager.getQuotaSummary(), ...extra }, null, 2));
        return;
      }
      if (req.method === 'POST' && req.url === '/teamclaude/reload') {
        if (!hooks.reload) {
          res.writeHead(501, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'reload not supported' }));
          return;
        }
        try {
          const { added = 0, removed = 0 } = await hooks.reload() || {};
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, added, removed }));
        } catch (err) {
          // The reason belongs in the log, not the reply: a reload failure
          // names config paths and account details, and this endpoint is
          // reachable by anyone holding a client key.
          console.error('[TeamClaude] Reload failed:', err.message);
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'reload failed; see the proxy log' }));
        }
        return;
      }

      // Account controls — the web equivalent of `teamclaude priority` and
      // `teamclaude disable` / `enable`. Local control only (no upstream
      // calls); the auth and cross-origin gates above already apply, and the
      // hook writes through atomicConfigUpdate so a refusal leaves the file
      // untouched. Both answer with the account as it now stands, because a
      // relative move ('first'/'last') picks a number the caller did not send.
      if (req.method === 'POST' && (req.url === '/teamclaude/priority' || req.url === '/teamclaude/disable')) {
        const isPriority = req.url === '/teamclaude/priority';
        const hook = isPriority ? hooks.setAccountPriority : hooks.setAccountDisabled;
        if (!hook) {
          res.writeHead(501, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: `${isPriority ? 'priority' : 'enable/disable'} not supported` }));
          return;
        }
        // Checked before the write, not after: a change that lands on disk but
        // never takes effect in the running server is the worst of both, and
        // a server with no reload hook has nothing to make it take effect.
        if (!hooks.reload) {
          res.writeHead(501, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'reload not supported' }));
          return;
        }
        let body;
        try {
          // `?? {}`: JSON.parse('null') is a value, and `.account` of it throws.
          body = JSON.parse(await readControlBody(req) || '{}') ?? {};
        } catch (err) {
          const tooLarge = /** @type {Error} */ (err).message === 'body too large';
          res.writeHead(tooLarge ? 413 : 400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: tooLarge ? 'request body too large' : 'invalid request body' }));
          return;
        }
        if (typeof body.account !== 'string' || !body.account.trim()) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'missing "account"' }));
          return;
        }
        try {
          const result = isPriority
            ? await hook(body.account.trim(), { priority: body.priority, place: body.place, orgFilter: body.org })
            : await hook(body.account.trim(), body.disabled, { orgFilter: body.org });
          // The write is on disk; the reload is what makes it live. Same
          // split as the MCP changeSetting tool: a reload failure is reported
          // as such, not as a refused change, because the file did change.
          try {
            await hooks.reload();
          } catch (err) {
            console.error('[TeamClaude] Reload after an account change failed:', /** @type {Error} */ (err).message);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: false, error: 'saved to the config file, but the reload failed; see the proxy log' }));
            return;
          }
          // Leave a trace where the manual switch already leaves one: on a
          // headless deployment this endpoint is the only way the change
          // happens, and an account leaving rotation should never be silent.
          console.log(`[TeamClaude] ${isPriority
            ? `Set priority of "${result.name}" to ${result.priority}`
            : `${result.disabled ? 'Disabled' : 'Enabled'} account "${result.name}"`} (control endpoint)`);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true, ...result }));
        } catch (err) {
          // A ConfigOpError is the caller's own input (unknown or ambiguous
          // account, bad priority) and is safe to echo; anything else is ours.
          const known = err instanceof ConfigOpError;
          const message = /** @type {Error} */ (err).message;
          if (!known) console.error('[TeamClaude] Account control failed:', message);
          res.writeHead(known ? 400 : 500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: known ? message : 'account change failed; see the proxy log' }));
        }
        return;
      }

      // One-shot quota probe — the web equivalent of the TUI's `p` key. It is
      // zero-spend and only available when the running server has a prober.
      if (req.method === 'POST' && req.url === '/teamclaude/probe') {
        if (!hooks.probeQuota) {
          res.writeHead(501, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'quota probe not supported' }));
          return;
        }
        try {
          await hooks.probeQuota();
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true }));
        } catch (err) {
          console.error('[TeamClaude] Quota probe failed:', err.message);
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'quota probe failed; see the proxy log' }));
        }
        return;
      }

      // Switch endpoint — make one account the preferred one, the headless
      // equivalent of picking it with 's' in the TUI. Both do the same single
      // thing: move currentIndex. That is a preference, and a weak one: _select
      // abandons it as soon as the account is unavailable, and also whenever any
      // available account carries a strictly lower priority value. So the answer
      // reports whether the choice will actually take effect rather than only
      // that it was recorded. Body:
      // {"account": "<name|email|accountUuid|accountUuid/orgUuid|orgUuid>"}.
      // Local control only (no upstream calls); the auth gate above applies.
      if (req.method === 'POST' && req.url === '/teamclaude/switch') {
        const names = () => (accountManager.accounts || []).map(a => a.name);
        let target;
        try {
          const raw = await readControlBody(req);
          target = JSON.parse(raw || '{}')?.account;
        } catch (err) {
          // Say which of the two it was, but never echo the parser's own message
          // back to a caller — that is our internals, not their input.
          const tooLarge = err.message === 'body too large';
          res.writeHead(tooLarge ? 413 : 400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: tooLarge ? 'request body too large' : 'invalid request body' }));
          return;
        }
        if (typeof target !== 'string' || !target.trim()) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'missing "account"', accounts: names() }));
          return;
        }
        const selected = resolveAccountPin(accountManager, target);
        const index = selected == null ? null : accountManager.accounts.indexOf(selected);
        if (index == null) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: `no such account "${target}"`, accounts: names() }));
          return;
        }
        accountManager.setCurrentAccount(index);
        const name = accountManager.accounts[index].name;
        // Recording the choice and the choice taking effect are two different
        // things: selection skips an account it cannot use on the very next
        // request, so a bare "ok" would be a lie for a disabled or spent target.
        // The switch still happens (that is the TUI's behaviour) and the answer
        // says whether traffic will follow it.
        const { eligible, reason } = accountManager.eligibility(index);
        // Leave a trace where every other account change already leaves one: the
        // TUI swaps console.log for its activity pane and headless mode tees it
        // to the activity log, so this one line covers both. Without it a manual
        // switch is the only account change that happens invisibly — on exactly
        // the background-service deployment this endpoint exists for.
        console.log(`[TeamClaude] Switched to account "${name}" (manual)`
          + (eligible ? '' : ` — ${reason}, so rotation will not use it`));
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, account: name, eligible, ...(reason ? { reason } : {}) }));
        return;
      }

      // Threshold endpoint — the utilization at which rotation leaves an
      // account, the web equivalent of `teamclaude threshold <1-100>` and of the
      // set_threshold MCP tool. Unlike /switch, which only moves currentIndex in
      // the running manager, this is a SETTING: it goes through the config file
      // under its lock and a reload applies it, so it survives a restart and
      // does not clobber a concurrent writer (changeSetting in mcp-tools.js
      // takes the same two steps for the same reason).
      // Body: {"percent": <1-100>}. Local control only; the gates above apply,
      // including the cross-origin refusal — the dashboard's own fetch is
      // same-origin, so it passes while another site's no-cors POST does not —
      // and the client-key refusal, since this is a setting and not a nudge.
      if (req.method === 'POST' && req.url === '/teamclaude/threshold') {
        let percent;
        try {
          const raw = await readControlBody(req);
          percent = JSON.parse(raw || '{}')?.percent;
        } catch (err) {
          const message = /** @type {Error} */ (err).message;
          const tooLarge = message === 'body too large';
          res.writeHead(tooLarge ? 413 : 400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: tooLarge ? 'request body too large' : 'invalid request body' }));
          return;
        }
        // What counts as a percentage is the shared rule's to say (1–100, kept
        // to tenths); restating the range here would let the two drift. Checked
        // before the write so a bad number never takes the config lock.
        if (thresholdRatio(percent) === null) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'percent must be a number from 1 to 100' }));
          return;
        }
        // Without a reload hook the setting could be saved but never applied:
        // the file would claim a number the running fleet ignored until the
        // next restart. Refused up front, as /probe refuses without a prober,
        // rather than written and then reported as half-done.
        if (!hooks.reload) {
          res.writeHead(501, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'threshold change not supported' }));
          return;
        }
        /** @type {string[]} */ let dropped = [];
        let saved;
        try {
          const disk = await atomicConfigUpdate((/** @type {Record<string, any>} */ c) => { ({ dropped } = setThreshold(c, percent)); });
          saved = /** @type {number} */ (disk.switchThreshold); // setThreshold wrote a number
        } catch (err) {
          const message = /** @type {Error} */ (err).message;
          // A ConfigOpError is the caller's input being refused and says so in
          // words meant for them; anything else is ours and goes to the log.
          const bad = err instanceof ConfigOpError;
          console.error('[TeamClaude] Threshold change failed:', message);
          res.writeHead(bad ? 400 : 500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: bad ? message : 'threshold change failed; see the proxy log' }));
          return;
        }
        // Saved is not applied: rotation reads the threshold off the manager,
        // which a reload refreshes (reloadAccounts in index.js assigns
        // switchThreshold onto it). Without this the file would claim a number
        // the running fleet ignored until the next restart.
        try {
          await hooks.reload();
        } catch (err) {
          const message = /** @type {Error} */ (err).message;
          console.error('[TeamClaude] Reload after a threshold change failed:', message);
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'saved to the config file, but the reload failed; see the proxy log' }));
          return;
        }
        // The same trace a manual switch leaves, and for the same reason: on the
        // background-service deployment this endpoint exists for, a threshold
        // that quietly retires an account would otherwise change nothing visible.
        console.log(`[TeamClaude] Switch threshold set to ${Math.round(saved * 1000) / 10}% (dashboard)`
          + (dropped.length ? ` — dropped the per-bucket thresholds (${dropped.join(', ')})` : ''));
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, switchThreshold: saved, dropped }));
        return;
      }

      // MCP management endpoint — the tool-shaped face of this control plane,
      // off unless proxy.mcp says otherwise. The gates above are the same ones
      // the other /teamclaude/ routes pass, with one addition: a config with no
      // key at all admits every caller as authenticated, from any address and
      // without the rebinding check on key-less loopback requests — so
      // keylessMcpRefusal asks both here.
      // A trailing slash and a query string are matched too: this URL is typed
      // into a client by hand, and a near miss would fall through to the
      // forwarder below with a fleet credential attached.
      if (/^\/teamclaude\/mcp\/?(\?|$)/.test(req.url || '')) {
        const refusal = keylessMcpRefusal(req.headers, req.socket.remoteAddress, config.proxy, boundHost());
        if (refusal) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: refusal }));
          return;
        }
        await serveManagementMcp(req, res, { accountManager, config, hooks, client: req.tcClient, readBody: readControlBody });
        return;
      }

      // Every control route above matches an exact method and path, so a typo —
      // or just the wrong verb, `GET /teamclaude/reload` — fell through to the
      // forwarder: the request went upstream under a fleet account's credential
      // and the client got THAT server's 404 (#420). The prefix is ours, so
      // whatever under it no route claimed is answered here. Read on the
      // classification path like every other prefix test; `/tc-acct/` and an
      // absolute-form proxy URL do not start with it and are untouched.
      const controlPath = classificationPath(req.url);
      // Both prefixes: an encoded spelling of the new one (`/%74eamrouter/`)
      // escapes the rewrite above and must not reach the forwarder either.
      if (controlPath === '/teamclaude' || controlPath.startsWith('/teamclaude/')
        || controlPath === '/teamrouter' || controlPath.startsWith('/teamrouter/')) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'unknown teamclaude control route (check the path and the method)' }));
        return;
      }

      return forward(req, res);
    } catch (err) {
      reportFailure('[TeamClaude] Unhandled error:', err);
      // The window above throws for real: `getStatusExtra` is a hook the
      // application installs, and reload/switch reach the account manager.
      answerUnhandled(res);
    }
  }));

  // Outlive the client's connection pool on an idle keep-alive socket (see
  // KEEP_ALIVE_TIMEOUT_MS): Node's 5s default loses the race to a pool that
  // holds sockets longer, and the request then dies before any upstream.
  server.keepAliveTimeout = KEEP_ALIVE_TIMEOUT_MS;

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
  // Resolved per call, not captured. This server is built before `tui.start()`
  // replaces `console.error` with the activity log, so handing a collaborator
  // the function object binds the pre-TUI console — and everything the two
  // below report (egress holds, CONNECT refusals, tunnel and MITM failures)
  // happens at request time, long after the swap, on a terminal the alternate
  // screen has already covered.
  const logLine = (/** @type {string} */ line) => console.error(line);

  // Opt-in egress pin: null unless config.egress.pin is set, and then shared by
  // the base listener and the MITM one so both honour the same hold.
  const egress = createEgressGuard(config, logLine);
  const forward = createProxyRequestListener({
    accountManager, upstream, logDir, hooks, sx, holdMs, config, egress, clientUsage, dimensionUsage,
    onResponse: (req, ctx) => {
      if (!probeTemplate || probeTemplate._restored || (!probeTemplate._elicitsModelWeekly && ctx.sawModelWeekly)) {
        const candidate = stageProbeTemplate(req, ctx.body);
        if (candidate) commitProbeTemplate(candidate, ctx.status, ctx.sawModelWeekly === true);
      }
    },
  });

  // What bounds a directory of one-shot dumps is deleting the expired ones, not
  // rotating a growing file. Swept once at startup, because a backlog is usually
  // already sitting behind the restart that enables this, then on a timer. The
  // interval is unref'd so it never holds the process open.
  if (logDir) {
    const requestLogDir = logDir;
    const sweep = () => {
      // The message names the setting that stops it: the proxy self-updates, so
      // the first sweep can arrive with a release the operator never read about.
      const hours = resolveLogRetentionHours(config);
      return sweepRequestLogs(requestLogDir, hours)
        .then((n) => {
          if (n) console.log(`[TeamClaude] Removed ${n} expired request log(s) from ${logDir} (logRetentionHours=${hours}, set 0 to keep them)`);
        })
        .catch(() => {});
    };
    sweep();
    const sweepTimer = setInterval(sweep, LOG_SWEEP_INTERVAL_MS);
    sweepTimer.unref();
    server.on('close', () => clearInterval(sweepTimer));
  }

  // Forward-proxy support (always on, so multiple claude instances can use
  // either ANTHROPIC_BASE_URL or HTTPS_PROXY against the same server). A CONNECT
  // to the upstream host is a transparent MITM relay (rewrite only auth); the
  // test host is answered locally; anything else is blind-tunneled. Certs are
  // minted lazily on the first intercepted CONNECT.
  // Every host the leaf must cover, not just the Anthropic upstream: a Codex
  // account is reached on chatgpt.com, and MITM cannot intercept a host its
  // certificate does not name.
  const mitmHostList = mitmHosts(config);
  let certsPromise = null;
  const ensureLeaf = async () => {
    // Reset the memo on failure so a transient cert error doesn't wedge the MITM
    // path permanently (a cached rejected promise would re-throw on every CONNECT).
    certsPromise ||= ensureCerts(mitmHostList).catch((err) => { certsPromise = null; throw err; });
    const c = await certsPromise;
    return { key: c.leafKeyPem, cert: c.leafCertPem };
  };
  server.on('connect', createConnectHandler({ config, accountManager, ensureLeaf, logDir, hooks, log: logLine, sx, egress, clientUsage, dimensionUsage }));
  // Remote Control's real-time channel is a WebSocket, not a request/response
  // call — Node fires 'upgrade' for that handshake, never 'request', so it
  // needs its own listener (base-URL routing path; the MITM path wires the
  // same relayUpgrade onto its own terminating server in mitm.js).
  // Guarded like requestHandler and the connect handler are: this process
  // exits on any uncaught throw (see crash-log.js), and a listener handed a raw
  // socket has nothing else standing between a bad handshake and that exit.
  server.on('upgrade', (req, socket, head) => {
    try {
      // The upgrade handshake never reaches requestHandler, so it does not
      // inherit the key gate above — it has to ask for itself. Without this a
      // WebSocket handshake is an unauthenticated relay to `upstream`: the
      // handshake carries no pooled credential (relayUpgrade forwards the
      // client's own headers), so it is not a way to spend the fleet's quota,
      // but it is a way to reach the upstream on this host's address and
      // bandwidth. A deployment on a public hostname hands that to anyone.
      const auth = resolveUpgradeAuth(req, socket, config.proxy, boundHost());
      if (!auth.ok) {
        // Logged as well as answered: a WebSocket client discards the status
        // line, so the 401 alone leaves an operator with a channel that is
        // silently dead — the same shape as the outage this gate could cause if
        // a client turns out not to send the key.
        console.log(`[TeamClaude] WebSocket upgrade refused (no proxy key) from ${safeLine(/** @type {import('node:net').Socket} */ (socket)?.remoteAddress || 'unknown')} for ${safeLine(req.url)}`);
        try { socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n'); } catch { /* already gone */ }
        socket.destroy();
        return;
      }
      // The identity the gate resolved rides along, as it does on the request
      // path (req.tcClient): a handshake authenticated with a client key is
      // attributed to that client, or it is a channel the operator cannot see
      // under `clients` at all (#325).
      relayUpgrade(req, socket, head, upstream, sx, {
        client: auth.client, clientUsage, headersTimeoutMs: transport.headersTimeoutMs,
        stripOverage: shouldStripOverageHeaders(config),
      });
    } catch (err) {
      console.error(`[TeamClaude] WebSocket upgrade handler failed for ${safeLine(req?.url)}: ${err?.message || err}`);
      try { socket.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'); } catch { /* already gone */ }
      socket.destroy();
    }
  });

  return server;
}

/**
 * Whether a control-plane POST did NOT come from a web page.
 *
 * Both headers are browser-set and unforgeable from page JavaScript:
 *   - `Sec-Fetch-Site` is the explicit answer where it exists (Chrome, Safari,
 *     Firefox). Anything but `same-origin` / `none` is a page reaching across.
 *   - `Origin` is the fallback for browsers that send no Sec-Fetch-Site. Its
 *     mere presence on a POST to a local control endpoint means a page issued
 *     it; matching it against our own host would mean guessing which of
 *     localhost / 127.0.0.1 / [::1] / a LAN address the caller used, so the
 *     Origin-only fallback admits no page at all.
 *
 * The dashboard's switch button is a browser-issued same-origin call and is
 * admitted by the Sec-Fetch-Site branch alone. A browser that sends Origin
 * without Sec-Fetch-Site (or a proxy that strips it) lands in the fallback
 * and is refused — deliberately: widening the fallback to guess our own host
 * is the trade this comment declines.
 *
 * Non-browser callers (curl, the CLI, `teamclaude attach`) send neither and are
 * unaffected.
 */
/** @param {Pick<ProxyRequest, 'headers'>} req */
export function isSameOriginControlRequest(req) {
  const site = req.headers['sec-fetch-site'];
  if (site) return site === 'same-origin' || site === 'none';
  return !req.headers.origin;
}

// Names a browser can reach this machine by. `::ffff:127.0.0.1` is how a
// dual-stack listener reports loopback and is accepted for symmetry with
// isLoopbackAddr, though no browser writes it in a URL.
const LOCAL_HOSTNAMES = new Set(['localhost', '127.0.0.1', '::1', '::ffff:127.0.0.1']);
// Binding to a wildcard says nothing about what name reaches us, so it does
// not widen the set.
const WILDCARD_BINDS = new Set(['0.0.0.0', '::', '']);

// The hostname part of a Host header (or a bind address): port stripped, IPv6
// brackets removed, lowercased. null when the value cannot be one.
function hostnameOf(host) {
  const h = String(host).trim().toLowerCase();
  if (h.startsWith('[')) {
    const end = h.indexOf(']');
    return end < 0 ? null : h.slice(1, end);
  }
  // A bare IPv6 address (how config.proxy.host spells one) has several colons
  // and no port to strip; a `name:port` has exactly one.
  const colon = h.indexOf(':');
  if (colon >= 0 && h.indexOf(':', colon + 1) >= 0) return h;
  return colon >= 0 ? h.slice(0, colon) : h;
}

/**
 * Whether a request's Host header names this proxy, for the DNS-rebinding
 * check on key-less loopback requests.
 *
 * Accepted: localhost, 127.0.0.1, ::1 (bracketed or not), and the address the
 * proxy is bound to (`config.proxy.host`) unless that is a wildcard. Port and
 * case are ignored.
 *
 * A MISSING Host header is accepted. Only an HTTP/1.0 client can omit it (Node
 * rejects an HTTP/1.1 request without one before this code runs), and no
 * browser speaks HTTP/1.0 — while a hand-rolled local tool might. Refusing it
 * would break that tool without closing anything.
 */
export function isLocalHostHeader(host, bindHost = null) {
  if (host == null || host === '') return true;
  const name = hostnameOf(host);
  if (name == null) return false;
  if (LOCAL_HOSTNAMES.has(name)) return true;
  const bound = typeof bindHost === 'string' ? hostnameOf(bindHost) : null;
  return bound != null && !WILDCARD_BINDS.has(bound) && bound === name;
}

// Read a control-endpoint body as text. Capped, unlike the proxied request path:
// these endpoints carry a couple of fields, so anything larger is a mistake or an
// attack and buffering it whole would be the wrong answer either way.
async function readControlBody(req, limit = 64 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw new Error('body too large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/**
 * Resolve an account pin to the exact live object, or null.
 *
 * Canonical keys are exact; friendly forms must match exactly one account:
 *   - `accountUuid/orgUuid` — fully qualified, the only form that distinguishes
 *     one person's accounts across several orgs
 *   - `accountUuid`
 *   - `orgUuid`
 *   - the display name (`email` or `email (Org)`), or the bare email
 *
 * UUIDs are the identity to use for anything scripted or long-lived: display
 * names are rewritten in place when an email gains a second org (see
 * accountsCommand), so a name is a convenience, not an identifier.
 *
 * The rotation index is deliberately NOT accepted. It is array position, so
 * deleting an account would silently repoint every later pin at a DIFFERENT
 * account — a wrong-account misroute rather than an honest failure.
 */
export function resolveAccountPin(accountManager, token) {
  if (typeof token !== 'string' || !token.trim() || /^\d+$/.test(token.trim())) return null;
  let canonicalId;
  try {
    canonicalId = parseAccountIdKey(token);
  } catch {
    const key = token.trim().toLowerCase();
    const matches = accountManager.accounts.filter(account => [
      account.name, account.email, account.name?.split(' (')[0], account.accountUuid, account.orgUuid,
      account.accountUuid && account.orgUuid ? `${account.accountUuid}/${account.orgUuid}` : null,
    ].some(value => typeof value === 'string' && value.toLowerCase() === key));
    return matches.length === 1 ? matches[0] : null;
  }
  try {
    return resolveAccount(accountManager.accounts, canonicalId);
  } catch {
    return null;
  }
}

/**
 * What actually went wrong on a failed connect, as a string worth printing.
 *
 * Node's happy-eyeballs dialer (`autoSelectFamily`, on by default across the
 * versions this package supports; `package.json` declares `node >=20`, measured
 * here on 24) reports a connect where every address failed as an AggregateError.
 * Node builds that error with an empty `message`; the per-address reasons are in
 * `.errors`. Any multi-address host reaches this, and the upstream is one, so
 * `err.message` prints nothing for the failure operators most need to read.
 *
 * Looked for one level down as well, because `TEAMCLAUDE_UPSTREAM_GLOBAL_FETCH`
 * routes through global fetch, which wraps the same failure in a TypeError whose
 * own message is the equally unhelpful "fetch failed".
 *
 * The `err.message` fallback is required: with `autoSelectFamily` off, and on
 * every single-address failure, the reason arrives as a plain Error in
 * `message`. It also covers a wrapper whose `.cause` carries no reasons.
 */
export function describeConnectError(err) {
  const reasons = (e) => (Array.isArray(e?.errors) ? e.errors.map(c => c?.message).filter(Boolean) : []);
  const own = reasons(err);
  // A wrapper with a non-aggregated cause (global fetch's TypeError('fetch
  // failed') around a single-address connect error) still says only 'fetch
  // failed' by itself; the cause's message is the reason.
  return (own.length ? own : reasons(err?.cause)).join('; ') || err?.cause?.message || err?.message;
}

// Paths that must reach upstream with the client's own credential (never a
// rotated account token): the Remote Control channel and attachment transfers.
// teamclaude applies its account logic (rotation, exhaustion, token injection)
// ONLY to hosts it manages — the Anthropic upstream. Anything else must be
// forwarded transparently, never hijacked into "all accounts exhausted". For
// HTTPS this is already true (the CONNECT tunnel in mitm.js blind-relays
// non-upstream hosts). This is the plain-HTTP counterpart: a tool honoring
// HTTP_PROXY sends an ABSOLUTE-form request (`GET http://host/path`), which
// otherwise gets misrouted to Anthropic. Blind-relay it to its target with the
// client's own headers — no account selection, no token injection,
// content-encoding passed through (a transparent forward proxy). Anthropic is
// HTTPS-only, so in practice this only ever sees third-party hosts.
export function relayHttpForward(req, res, stripOverage = false) {
  let target;
  try { target = new URL(req.url); } catch {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ type: 'error', error: { type: 'invalid_request_error', message: 'Malformed forward-proxy URL' } }));
    return;
  }
  // Destination policy, same as the CONNECT tunnel's (forward-target.js): a
  // relay may not target this machine's loopback, the unspecified address, or
  // link-local. `GET http://127.0.0.1:<our port>/teamclaude/status` would
  // otherwise arrive at our own listener from a loopback socket and pass the
  // API-key gate as a local caller. Refused by literal name here; the guarded
  // lookup below refuses by resolved address, so a DNS alias for 127.0.0.1 does
  // not get past either. Launched clients carry NO_PROXY for loopback, so no
  // legitimate request is lost.
  const hostname = target.hostname.replace(/^\[|\]$/g, '');
  const refuse = (why) => {
    console.error(`[TeamClaude] HTTP forward to ${target.host} refused: ${why}`);
    if (res.headersSent) { res.destroy(); return; }
    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ type: 'error', error: { type: 'permission_error', message: `Forward to ${target.host} refused: ${why}` } }));
  };
  const refused = forwardRefusal(hostname, null, req.socket);
  if (refused) { refuse(refused); return; }

  const transport = target.protocol === 'http:' ? http : https;
  /** @type {import('node:http').OutgoingHttpHeaders} */
  const headers = {};
  for (const [key, value] of Object.entries(req.headers)) {
    const lk = key.toLowerCase();
    // Drop hop-by-hop + proxy-control headers; `host` is reset from the target.
    if (lk.startsWith(':') || HOP_BY_HOP_HEADERS.has(lk) || lk === 'proxy-connection') continue;
    headers[key] = value;
  }

  const upstreamReq = transport.request(target, { method: req.method, headers, lookup: guardedLookup(req.socket) }, (upstreamRes) => {
    const responseHeaders = {};
    for (const [key, value] of Object.entries(upstreamRes.headers)) {
      if (CONNECTION_SPECIFIC_HEADERS.has(key)) continue;
      if (stripOverage && isOverageHeader(key)) continue;
      responseHeaders[key] = value;
    }
    res.writeHead(upstreamRes.statusCode, responseHeaders);
    upstreamRes.pipe(res);
  });
  upstreamReq.on('error', (/** @type {CodedError} */ err) => {
    if (err.code === FORBIDDEN_FORWARD) { refuse(err.message); return; }
    console.error(`[TeamClaude] HTTP forward to ${target.host} failed:`, describeConnectError(err));
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: 'Upstream unreachable' } }));
    }
  });
  res.on('close', () => upstreamReq.destroy());
  if (['GET', 'HEAD'].includes(req.method)) upstreamReq.end();
  else req.pipe(upstreamReq);
}

// Paths relayed with the CLIENT's own credential, never a rotated account token.
// Everything under /api/oauth/ is the client's identity/control plane — profile
// ("who am I"), file uploads, and whatever Claude Code adds next — not inference.
// Injecting a fleet token here makes Claude Code believe it IS the rotated
// account: the cached oauthAccount profile gets overwritten with a stranger's
// identity, the Claude-in-Chrome extension refuses to pair ("token belongs to a
// different account than the one you're logged in as"), Remote Control binds to
// the wrong account, and artifacts get published under it. Observed on a live
// fleet; the whole prefix is the fix, not a growing allowlist of sub-paths.
const CLIENT_CREDENTIAL_PATHS = ['/v1/code/', '/api/oauth/'];

// Claude Code's startup preconnect: every process sends one `HEAD /api/hello` to
// ANTHROPIC_BASE_URL with a 10s timeout and discards the result (2.1.282; skipped
// when HTTPS_PROXY is set, so MITM clients never send it). It needs no account and
// spends no quota, but it used to take an inference slot like any request: on
// 2026-09-25, with the fleet's 9 slots full, 164 of 263 sat in the overflow queue
// until the client dropped them at 10s and 51 were refused with a 429, holding
// queue positions real requests needed. Relayed to upstream as sent, so any other
// client that asks this path still learns whether the API is reachable.
const PRECONNECT_PATH = '/api/hello';

// Claude Code's session id is a UUID, but other clients tag sessions too, so
// the shape is a conservative charset rather than the UUID grammar: wide enough
// that a non-UUID client keeps its session tracking, tight enough that nothing
// odd gets in. The value becomes a Map key in the session tracker (the length
// cap is what bounds that map per client) and a column in the TUI, where Node's
// header parser would otherwise let C1 control bytes through untouched.
const SESSION_ID_SHAPE = /^[A-Za-z0-9._-]{1,128}$/;

/** The session id a request carries, or null when the header is absent or
 *  malformed — a malformed one is treated as no session, not rejected.
 *
 *  Claude Code sends `x-claude-code-session-id`, the Codex CLI `session-id`.
 *  Reading only the first left every Codex request untagged, so
 *  `distributeSessions` had nothing to place and a Codex pool stayed on one
 *  account until the switch threshold. The specific header wins when both are
 *  present: `session-id` is generic enough for a proxy in front to set. */
/** @param {http.IncomingHttpHeaders} headers */
export function clientSessionId(headers) {
  const raw = headers['x-claude-code-session-id'] ?? headers['session-id'];
  return typeof raw === 'string' && SESSION_ID_SHAPE.test(raw) ? raw : null;
}

/**
 * Build the core proxy request listener — buffer the body, then forward with
 * account selection + retry (forwardRequest). Shared by the base HTTP server and
 * the MITM's terminating h2/h1 server, so both get identical buffering, model-
 * aware routing, and retry-on-quota behavior. Control endpoints (status/reload)
 * and the proxy-API-key gate live in the base server's wrapper, not here.
 */
/**
 * @param {Object} opts
 * @param {AccountManager} opts.accountManager
 * @param {string} opts.upstream
 * @param {string|null} [opts.logDir]
 * @param {ProxyHooks} [opts.hooks]  activity callbacks, all optional
 * @param {SxManager|null} [opts.sx]
 * @param {number} [opts.holdMs]
 * @param {ServerConfig} [opts.config]  the live config object; read per request, never copied
 * @param {string|null} [opts.forcedPin]
 * @param {ReturnType<typeof createEgressGuard>} [opts.egress]
 * @param {ClientUsageTracker|null} [opts.clientUsage]
 * @param {string|null} [opts.forcedClient]
 * @param {UsageDimensionTracker|null} [opts.dimensionUsage]
 * @param {((req: ProxyRequest, ctx: LiveRequestContext) => void)|null} [opts.onResponse]
 * @param {number|null} [opts.maxBodyBytes]
 * @param {boolean|(() => boolean)|null} [opts.useSx]
 * @param {number|null} [opts.headersTimeoutMs]
 * @param {number|null} [opts.bodyTimeoutMs]
 * @returns {(req: ProxyRequest, res: ProxyResponse) => Promise<void>}
 */
export function createProxyRequestListener({ accountManager, upstream, logDir = null, hooks = {}, sx = null, holdMs = 0, config = {}, forcedPin = null, egress = null, clientUsage = null, forcedClient = null, dimensionUsage = null, onResponse = null, maxBodyBytes = null, useSx = null, headersTimeoutMs = null, bodyTimeoutMs = null }) {
  let counter = 0;
  return async (req, res) => {
    // The activity entry this request opened, while it is still open. Every
    // consumer holds the row until it is told the request ended, so exactly one
    // path must close it. Each closing site clears this first, which is how the
    // outer catch tells an entry it still has to account for from one that is
    // already closed.
    let openEntry = null;
    let admissionReservation = null;
    try {
      // Refused before any path-prefix classification below, so each of those
      // sees the path upstream will see (see hasDotSegment). Logged like the
      // unknown-pin 404: an operator should see a client probing the boundary.
      if (hasDotSegment(req.url)) {
        const reqId = ++counter;
        const sessionId = clientSessionId(req.headers);
        hooks.onRequestEnd?.(reqId, { method: req.method, path: safeLine(req.url), account: '(refused: dot-segment in path)', status: 400, model: null, sessionId, pinned: false });
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ type: 'error', error: { type: 'invalid_request_error', message: 'Request path must not contain dot-segments' } }));
        recordEarlyOutcome(accountManager, { sessionId }, req.url, true);
        return;
      }

      // Claude Code's telemetry (`/api/event_logging/*`) is high-volume noise in
      // the activity log. `config.eventLogging` (read live so the TUI toggle takes
      // effect immediately): 'show' forwards + displays; 'hide' (default) forwards
      // but suppresses the activity entry; 'block' answers 200 locally without
      // forwarding (no upstream round-trip, no account/token spent).
      const eventLogging = config?.eventLogging || 'hide';
      const isEventLog = (req.url || '').startsWith('/api/event_logging');
      if (isEventLog && eventLogging === 'block') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{}');
        return;
      }
      const hideActivity = isEventLog && eventLogging !== 'show';
      // Egress pin (opt-in): with the exit IP off the pinned one — a VPN that
      // dropped — hold rather than send. Upstream answers a request from an
      // unexpected region with a 403 that Claude Code reports as a dead session,
      // so sending it costs a re-login while waiting costs latency. Checked here
      // rather than per-account: it is a property of the connection, and this is
      // the one path every request takes, MITM included.
      if (egress?.enabled()) {
        const state = await egress.waitUntilPinned({ isAborted: () => clientGone(res) });
        if (clientGone(res)) return;
        if (!state.ok) {
          recordEarlyOutcome(accountManager, { sessionId: clientSessionId(req.headers) }, req.url, false);
          res.writeHead(503, { 'Content-Type': 'application/json', 'retry-after': '30' });
          res.end(JSON.stringify({
            type: 'error',
            error: {
              type: 'proxy_error',
              message: `Egress is ${state.ip || 'unknown'}, not the pinned ${state.expected.join(', ')} — not sending this request. Check the VPN.`,
            },
          }));
          return;
        }
      }
      // Client token refresh: pass through untouched (the proxy manages its own
      // tokens via ensureTokenFresh; rewriting client refreshes would conflict).
      if (req.method === 'POST' && classificationPath(req.url) === '/v1/oauth/token') {
        admissionReservation = accountManager.reserveAdmissionPrebuffer({});
        if (!admissionReservation) { refuseAdmission(req, res); return; }
        if (!accountManager.transferAdmissionReservation(admissionReservation, 'oauth-token', {})) {
          refuseAdmission(req, res); return;
        }
        await relayRaw(req, res, upstream, sx, maxBodyBytes ?? resolveMaxBodyBytes(config), shouldStripOverageHeaders(config));
        return;
      }
      // Account pin: a request to `/tc-acct/<name-or-index>/...` (e.g. via
      // ANTHROPIC_BASE_URL=http://host:port/tc-acct/deepseek) is forced onto that
      // one account, bypassing rotation. Used by the keep-warm scheduler and for
      // manual per-account testing. The prefix is stripped before forwarding.
      let pinnedAccount = null;
      // DEPRECATED: the path-prefix pin. Superseded by TC_ACCT, which works in
      // MITM mode too (this form cannot — inside a CONNECT tunnel the path is
      // the real upstream one). Kept for the warmer and for direct API callers.
      // One segment only, so the fully-qualified `accountUuid/orgUuid` form is
      // not expressible here; use TC_ACCT for that.
      const url = req.url || '';
      const afterPrefix = url.startsWith(PIN_PREFIX) ? url.slice(PIN_PREFIX.length) : null;
      // The token runs to the next '/', which also begins the real request path.
      const tokenEnd = afterPrefix == null ? -1 : afterPrefix.indexOf('/');
      if (afterPrefix != null && tokenEnd > 0) {
        // The escaping of this segment is the CLIENT's, so a malformed one
        // ("/tc-acct/%/v1/messages") makes decodeURIComponent throw URIError.
        // That is an ordinary bad request, not an internal error: decode
        // defensively and fall through to the unknown-pin 404 below, which is
        // what a pin nobody can resolve already means. An undecodable token is
        // reported as it arrived, since there is no decoded form to name.
        const raw = afterPrefix.slice(0, tokenEnd);
        let token = null;
        try { token = decodeURIComponent(raw); } catch { token = null; }
        pinnedAccount = token == null ? null : resolveAccountPin(accountManager, token);
        if (pinnedAccount == null) {
          // Client-supplied and already percent-decoded, so this is the one
          // value on the path that can carry raw control bytes.
          const shown = safeLine(token ?? raw);
          const reqId = ++counter;
          const sessionId = clientSessionId(req.headers);
          if (!hideActivity) hooks.onRequestEnd?.(reqId, { method: req.method, path: req.url, account: `(unknown pin: "${shown}")`, status: 404, model: null, sessionId, pinned: false });
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ type: 'error', error: { type: 'not_found_error', message: `Unknown account pin "${shown}"` } }));
          recordEarlyOutcome(accountManager, { sessionId }, req.url, true);
          return;
        }
        req.url = afterPrefix.slice(tokenEnd);
      }

      // Remote Control (/v1/code/*) is bound to the session's paired claude.ai
      // identity — forward with the client's OWN credential (streamed), never a
      // rotated account token, which would 403 the worker event stream.
      // Attachment transfers (/api/oauth/files/*, /api/oauth/file_upload) are
      // likewise account-bound: files uploaded from claude.ai belong to the
      // paired identity, so fetching them with a rotated token 403s and Claude
      // Code silently drops the image from the message.
      //
      // Below the pin strip, so this reads the path that will actually be sent,
      // and on its classification form: `/%61pi/oauth/…`, `/api/oauth%2fprofile`,
      // `/api\oauth\profile` and `/tc-acct/<acct>/api/oauth/profile` all leave
      // here as the identity plane, so all of them take the relay. A pinned
      // account's token is a rotated token like any other — the pin says which
      // account serves INFERENCE, and no version of it should put a fleet
      // identity on /api/oauth/*. Above the strip this test still saw the
      // prefix and matched nothing, while `provider` further down is built from
      // the stripped url: the two disagreed about the same request.
      //
      // Still ABOVE the TC_ACCT branch below, which does not touch req.url —
      // moving past it would turn an unknown TC_ACCT pin on an identity-plane
      // request into a 404 that it does not return today.
      const classifiedPath = classificationPath(req.url);
      if (CLIENT_CREDENTIAL_PATHS.some((p) => classifiedPath.startsWith(p))) { await relayStream(req, res, upstream, sx, 'Remote Control relay', shouldStripOverageHeaders(config)); return; }
      if (classifiedPath === PRECONNECT_PATH) { await relayStream(req, res, upstream, sx, 'Preconnect relay', shouldStripOverageHeaders(config)); return; }

      // MITM-mode pin. A CONNECT carrying `Proxy-Authorization: Basic <acct>:…`
      // has no URL to hang a `/tc-acct/` prefix on — the path inside the tunnel
      // is the real Anthropic one — so the pin arrives as a listener bound to
      // that account (see createConnectHandler). Resolved per request rather
      // than at CONNECT time: a hot reload can renumber accounts while a tunnel
      // is open, and a name outliving an index is the safer half of that race.
      if (pinnedAccount == null && forcedPin != null) {
        pinnedAccount = resolveAccountPin(accountManager, forcedPin);
        if (pinnedAccount == null) {
          const reqId = ++counter;
          const sessionId = clientSessionId(req.headers);
          if (!hideActivity) hooks.onRequestEnd?.(reqId, { method: req.method, path: req.url, account: `(unknown pin: "${safeLine(forcedPin)}")`, status: 404, model: null, sessionId, pinned: false });
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ type: 'error', error: { type: 'not_found_error', message: `Unknown account pin "${forcedPin}" (from TC_ACCT)` } }));
          recordEarlyOutcome(accountManager, { sessionId }, req.url, true);
          return;
        }
      }

      const provider = providerForPath(req.url);
      if (pinnedAccount && isSubscriptionAccount(pinnedAccount) && providerOf(pinnedAccount) !== provider) {
        req.resume();
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ type: 'error', error: { type: 'invalid_request_error',
          message: `Pinned account "${pinnedAccount.name}" is a ${providerOf(pinnedAccount)} subscription and cannot serve a ${provider} request.` } }));
        return;
      }
      const candidates = pinnedAccount ? [pinnedAccount]
        : accountManager.accounts.filter(a => !isSubscriptionAccount(a) || providerOf(a) === provider);
      if (candidates.length && candidates.every(a => a.status === 'error')) {
        recordEarlyOutcome(accountManager, { sessionId: clientSessionId(req.headers) }, req.url, false);
        req.resume();
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ type: 'error', error: { type: 'authentication_error',
          message: 'All accounts failed authentication. Re-login required.' } }));
        return;
      }

      admissionReservation = accountManager.reserveAdmissionPrebuffer({ provider, pinnedAccount });
      if (!admissionReservation) {
        refuseAdmission(req, res);
        recordEarlyOutcome(accountManager, { sessionId: clientSessionId(req.headers) }, req.url, false);
        return;
      }

      const reqId = ++counter;
      // Claude Code tags each session's requests with this header (present on
      // /v1/messages and count_tokens). Read from headers up front so it drives
      // session-aware routing (issue #109) and colors the TUI activity stream.
      const sessionId = clientSessionId(req.headers);
      if (!hideActivity) {
        // Marked open BEFORE the hook runs. The shipped TUI hook registers its
        // row and then renders, and the render can rethrow, so a hook that
        // throws part way through has already opened a row that something must
        // close. The cost of this order is one spurious close if the hook threw
        // before registering anything, which every consumer already tolerates.
        openEntry = { reqId, sessionId };
        hooks.onRequestStart?.(reqId, { method: req.method, path: req.url, sessionId, pinned: pinnedAccount != null, client: req.tcClient ?? forcedClient ?? null });
      }

      // Buffer request body (needed to resend on a different account after a 429).
      // Peek the top-level `model` field incrementally as chunks arrive so the
      // TUI can show it the instant it appears in the stream — usually the first
      // frame — rather than waiting for the whole body and the request to finish.
      const bodyChunks = [];
      const modelFinder = new TopLevelFieldFinder('model');
      const bodyLimit = maxBodyBytes ?? resolveMaxBodyBytes(config);
      let bodyBytes = 0;
      for await (const chunk of req) {
        bodyBytes += chunk.length;
        // Buffering is what makes retry possible, and also what lets one client
        // hold as much memory as it cares to send. Past the cap, stop reading
        // and say so; the request is torn down once the answer is out.
        if (bodyBytes > bodyLimit) {
          await refuseOversizedBody(req, res);
          openEntry = null;   // this path owns the close below; the outer catch must not repeat it
          if (!hideActivity) hooks.onRequestEnd?.(reqId, { method: req.method, path: req.url, account: '(too large)', status: 413, model: modelFinder.done ? modelFinder.value : null, sessionId, pinned: pinnedAccount != null });
          return;
        }
        bodyChunks.push(chunk);
        if (!modelFinder.done) {
          const found = modelFinder.push(chunk);
          if (found && !hideActivity) hooks.onRequestModel?.(reqId, { model: found });
        }
      }
      const body = Buffer.concat(bodyChunks);

      const model = modelFinder.done ? modelFinder.value : parseRequestModel(body);
      // An advisor request (Claude Code's advisor tool) carries a SECOND model
      // nested in tools[]; the advisor sub-inference runs on the selected
      // account, so selection must be eligible for it too (issue #98).
      const advisorModel = parseAdvisorModel(body);

      // What session-aware routing pins on. The session id names the CLIENT
      // session, which is one id for a Claude Code session AND every subagent it
      // launches; the conversation within it is what owns a prompt cache, so it
      // is what a pin has to follow (see conversation.js). The session id is
      // kept beside it, unnarrowed, for everything that reports rather than
      // routes: the activity log, the TUI's session column, the per-session
      // readout. Degrades to the session id when the body names no conversation.
      // Only when there is a session to narrow: with no session id there is no
      // pin either way, and digesting would walk a body for an answer nobody reads.
      // And only for an Anthropic request: the path already says which provider
      // this is, and a Codex Responses body carries `input`/`instructions` and
      // no `messages`, so the walk could only ever come back empty-handed — after
      // reading as far into a multi-megabyte body as its bound allows (`provider`
      // is the path's, read above for the pinned-account check).
      const conversation = sessionId && provider === DEFAULT_PROVIDER ? conversationDigest(body) : null;
      const pinKey = pinKeyFor(sessionId, conversation);

      // Model blocklist (issue #116): reject a request for a blocked model right
      // here instead of forwarding it. A model no account can serve (e.g. Fable
      // once it left base plans) otherwise gets rate-limited upstream and hangs
      // the pipeline; a fast, non-retryable 400 lets the client move on. Read
      // live from the shared config so the TUI editor takes effect immediately.
      const blockedBy = model ? (config?.blockedModels || []).find((p) => modelGlobMatches(p, model)) : null;
      if (blockedBy) {
        if (!res.headersSent) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ type: 'error', error: { type: 'invalid_request_error', message: `Model "${model}" is blocked by teamclaude (matched "${blockedBy}").` } }));
        }
        recordEarlyOutcome(accountManager, { pinKey, sessionId }, req.url, true);
        openEntry = null;   // this path owns the close below; the outer catch must not repeat it
        hooks.onRequestEnd?.(reqId, { method: req.method, path: req.url, account: '(blocked)', status: 400, model, sessionId });
        return;
      }

      // Per-client attribution: the base server stamps req.tcClient from the
      // key that authenticated; the MITM terminating server has no per-request
      // key (auth happened at CONNECT time) and carries it as forcedClient
      // instead — the same split as the account pin. onUsage lets the usage
      // extraction deep in the response path book tokens against the client
      // without threading the name through every layer.
      //
      // Usage dimensions (proxy.usageDimensions) ride the same hook: each
      // configured header the caller sent becomes one more counter the response
      // tokens are booked against, so one CI key can still be split by project.
      const client = req.tcClient ?? forcedClient ?? null;
      const usageDimensions = resolveUsageDimensions(config.proxy, req.headers);
      const usageRecorder = createUsageRecorder({ client, clientUsage, dimensions: usageDimensions, dimensionUsage });
      usageRecorder.recordRequest();

      // The dimension headers are ours, not upstream's: they exist to label
      // traffic for this proxy. Forwarding them would leak an operator's
      // internal project and branch names to Anthropic for no benefit, so they
      // are dropped with the other proxy-control headers.
      const stripHeaders = usageDimensionHeaderNames(config.proxy);

      const ctx = Object.assign(createLiveRequestContext(req, body, {
        queueTimeoutMs: config.overflowQueueTimeoutMs === null ? Infinity
          : typeof config.overflowQueueTimeoutMs === 'number' && Number.isFinite(config.overflowQueueTimeoutMs) ? Math.max(0, config.overflowQueueTimeoutMs) : 15_000,
        maxPredispatchWaitMs: typeof config.maxPredispatchWaitMs === 'number' && Number.isFinite(config.maxPredispatchWaitMs)
          ? Math.max(0, config.maxPredispatchWaitMs) : DEFAULT_MAX_PREDISPATCH_WAIT_MS,
        pinnedAccount,
        affinityKey: config.sessionAffinity !== false ? req.socket : null,
        overloadFallbackModel: config.overloadFallbackModel,
        transientRetries: Number.isFinite(config.transientRetries) ? config.transientRetries : 1,
        transport: {
          sx, fetchImpl: hooks.fetch || null,
          holdMs: positiveTimeout(config.holdMs) ?? holdMs,
          headersTimeoutMs: positiveTimeout(headersTimeoutMs ?? config.upstreamHeadersTimeoutMs ?? config.headersTimeoutMs),
          bodyTimeoutMs: positiveTimeout(bodyTimeoutMs ?? config.upstreamBodyTimeoutMs ?? config.bodyTimeoutMs),
        },
      }), {
        // `sessionId` names the client session for the readout; `pinKey` is what
        // routing pins, holds and books on (the conversation, see above).
        model, advisorModel, sessionId, pinKey, provider, client,
        streamRequested: parseRequestStream(body), fleetMessageThreads: config?.messageThreads === true,
        delivered: false, abandoned: false, onUsage: usageRecorder.onUsage, stripHeaders,
        // stripOverage is sampled once here, at dispatch: retries and holds of
        // this request keep it, and a reload applies to subsequent requests.
        stripOverage: shouldStripOverageHeaders(config),
        logLevel: resolveLogLevel(config), logMaxBodyBytes: resolveLogMaxBodyBytes(config),
      });
      ctx.useSx = typeof useSx === 'function' ? useSx() : useSx;
      if (!accountManager.transferAdmissionReservation(admissionReservation, admissionShape(req, ctx), {
        model, advisorModel, pinnedAccount, provider: ctx.provider,
      })) {
        refuseAdmission(req, res);
        recordEarlyOutcome(accountManager, { pinKey, sessionId }, req.url, false);
        openEntry = null;
        if (!hideActivity) hooks.onRequestEnd?.(reqId, {
          method: req.method, path: req.url, account: '(at capacity)', status: 429,
          model, sessionId, pinned: pinnedAccount != null, client,
        });
        return;
      }

      // Hold the session "in flight" across the WHOLE request (incl. retries and
      // a multi-minute streaming completion) so it stays counted as active and
      // never expires mid-request.
      accountManager.beginSession(pinKey, {
        client,
        // The key is the conversation; these name it for the readout, which
        // groups by the session an operator recognises and needs the
        // conversation to tell one of its agents from another.
        sessionId,
        conversation,
        dimensions: Object.fromEntries(usageDimensions.map(d => [d.name, d.key])),
      });
      // Everything forwardRequest waits on — the upstream admission queue, the
      // upstream request itself, a quota-hold or rate-limit timer, a silent SSE
      // read — is cancelled the moment the client goes away, so a departed
      // client keeps neither an upstream slot nor a timer alive. Two closes are
      // NOT departures and must never abort: the 'close' that follows a normal
      // res.end() (writableEnded), and the one the proxy causes itself when it
      // destroys the socket on a dead stream (ctx.proxyClosed) — that is the
      // worst failure, not "the user left".
      const requestAbort = new AbortController();
      const onRequestClose = () => { if (!res.writableEnded && !ctx.proxyClosed) requestAbort.abort(clientGoneError()); };
      ctx.signal = requestAbort.signal;
      ctx.abortSignal = requestAbort.signal;
      res.once('close', onRequestClose);
      if (clientGone(res)) onRequestClose();
      try {
        await forwardRequest(req, res, ctx.body, accountManager, upstream, 0, hooks, reqId, ctx, logDir);
        onResponse?.(req, ctx);
      } catch (err) {
        ctx.status = ctx.status || 502;
        // Same rule as the two outer catches: a recovery path does not report
        // through a console that may be the thing that failed. Here it also
        // decides which error gets reported at all, since a throw from the
        // report would carry the render failure outward in place of this one.
        reportFailure('[TeamClaude] Unhandled error:', err);
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: 'Internal proxy error' } }));
        }
      } finally {
        res.off('close', onRequestClose);
        if (ctx.held) { accountManager.releaseAccount(ctx.held); ctx.held = null; }
        // The signal fires only for a departure (see above), so this is the
        // status of a row whose client will never read anything. It says
        // nothing about abandonment: that is still marked where it is observed.
        if (requestAbort.signal.aborted) ctx.status = 499;
        // null = record nothing: the client walked away (neither an answer nor a
        // starvation), or this was not a completion at all. Abandonment is
        // observed where it happens, never inferred here: the proxy destroys the
        // socket itself on a dead stream, so a clientGone check at this point
        // would reclassify the worst failure as "the user left".
        accountManager.endSession(pinKey,
          !isCompletionPath(classificationPath(req.url)) ? null : (ctx.delivered ? true : (ctx.abandoned ? null : false)));
        // Cleared BEFORE the hook, because the hook can throw: leaving the entry
        // marked open would send the outer catch to call that same throwing hook
        // a second time for one request.
        openEntry = null;
        if (!hideActivity) hooks.onRequestEnd?.(reqId, { method: req.method, path: req.url, account: ctx.account, status: ctx.status, model: ctx.model, sessionId, pinned: ctx.pinnedAccount != null, client });
      }
    } catch (err) {
      reportFailure('[TeamClaude] Unhandled error:', err);
      // Close the activity entry. Only the inner path has a `finally`, so a
      // throw above it opens a row that nothing else will ever close, and every
      // consumer holds an open row indefinitely: the TUI keeps it in `active`
      // and never idles its animation, a headless consumer's in-flight count
      // grows by one. `for await (const chunk of req)` rejects when a client
      // cancels mid-body, which Ctrl+C in Claude Code does, on a daemon that
      // runs for weeks.
      if (openEntry) {
        // 499 when nothing was sent and nothing will be, either because the
        // client is gone or because the response is past the point of saying
        // anything; 502 is what the answer below is about to write.
        const status = res.headersSent || clientGone(res) ? 499 : 502;
        const entry = openEntry;
        openEntry = null;
        // Guarded, because the throw that landed here may be this hook. Escaping
        // this catch means escaping an async request listener with nothing above
        // it, which is an unhandled rejection, and crash-log.js turns that into
        // exit(1). A broken activity hook must not take the daemon down, and it
        // must not cost the socket its answer below either.
        try {
          hooks.onRequestEnd?.(entry.reqId, {
            method: req.method, path: req.url, account: null, status,
            model: null, sessionId: entry.sessionId, pinned: false,
          });
        } catch (hookErr) {
          reportFailure('[TeamClaude] activity hook failed while closing a request:', hookErr);
        }
      }
      // The code above the inner try (the egress hold, the pin parsing, body
      // buffering, the activity hooks) runs outside the 502 that guards
      // forwardRequest, and the inner `finally` calls onRequestEnd after the
      // response has streamed.
      answerUnhandled(res);
    } finally {
      if (admissionReservation) accountManager.releaseAdmissionReservation(admissionReservation);
    }
  };
}

/**
 * Report a failure without depending on the console to survive it.
 *
 * Under the TUI the console is the TUI: `console.error` appends to the activity
 * log and repaints, so a render that throws makes `console.error` throw. That
 * matters because these reports are the FIRST statement of the paths that
 * recover from a throw, and the throw being recovered from is often the same
 * broken render. An unguarded report there skips the whole recovery.
 *
 * Falls back to stderr rather than swallowing, so a render bug still leaves a
 * diagnostic. The TUI already does this when its own activity stream fails.
 *
 * `writeSync` rather than `process.stderr.write`, because the fallback has to
 * fail the way this function promises to. A closed stderr makes the stream
 * surface EPIPE asynchronously, as an error event no `try` around the call can
 * see, and this daemon treats an uncaught EPIPE as fatal. `writeSync` throws
 * where it is called, so the catch below is real.
 */
function reportFailure(...args) {
  try {
    console.error(...args);
  } catch {
    try {
      writeSync(2, `${args.map(a => a?.stack || String(a)).join(' ')}\n`);
    } catch { /* nothing left to report with */ }
  }
}

// A status the client can act on: upstream said something about THIS request.
// A 4xx IS an answer — it tells the client something true about what it sent,
// and a session getting legitimate 400s is working, not starving. A 429 is a
// refusal to answer and a 5xx is a failure to.
/** @param {number} status */
function answeredStatus(status) {
  // 401 is excluded on purpose. It is about the credential the PROXY injected,
  // which the client never sees and cannot act on — a fleet whose keys have all
  // been rotated out answers 401 to everything, forever, and that is the
  // canonical starving session rather than an answered one.
  return status < 500 && status !== 429 && status !== 401;
}

// Only a completion is something a session can starve for. Claude Code sends
// `count_tokens` under the SAME session id as the completions it is sizing up,
// and that endpoint keeps working when completions do not — so counting it
// would let a healthy trickle reset the streak of a session that is getting
// nothing. Measured before this guard: ten failed completions interleaved with
// their count_tokens calls reported a streak of one.
/** @param {string|undefined} url */
function isCompletionPath(url) {
  const path = String(url || '').split('?')[0];
  return path.endsWith('/v1/messages') || path.endsWith('/responses');
}

// Outcomes for the exits that return BEFORE the ordinary beginSession. Each one
// opens and immediately closes a hold of its own: that creates the record even
// when no request of it ever reached an account, and never releases a
// concurrent request's hold. No routing attempt is recorded. A prompt local
// answer (a blocked model, an unknown pin) clears a stale streak; a refusal
// (egress unpinned, no admission) counts as getting nothing.
//
// Which record it lands on depends on how far the request got. Past the body
// there is a pin key naming the one conversation that asked, and the outcome is
// that conversation's. Before the body there is only a session id — the
// conversation is named by bytes nobody has read yet — so every live
// conversation of that session takes it, which is what those exits are actually
// saying: an egress that is not up is not up for any of them. The session's
// own record is opened first and labelled with its id, so a session refused
// before any conversation of it was seen is still counted, and exactly once.
/**
 * @param {AccountManager} accountManager
 * @param {{ pinKey?: string|null, sessionId?: string|null }} names
 * @param {string|undefined} url
 * @param {boolean} usable
 */
function recordEarlyOutcome(accountManager, { pinKey = null, sessionId = null }, url, usable) {
  // On the classification path, like every other decision here: `\v1\messages`
  // goes out as `/v1/messages` and is a completion for the streak too (#377).
  if (!isCompletionPath(classificationPath(url))) return;
  if (pinKey) {
    accountManager.beginSession(pinKey, { sessionId });
    accountManager.endSession(pinKey, usable);
  } else if (sessionId) {
    accountManager.beginSession(sessionId, { sessionId });
    accountManager.recordOutcomeForSession(sessionId, usable);
    accountManager.endSession(sessionId, null);
  }
}

/**
 * Has the client gone away?
 *
 * `res.destroyed` answers that on the base HTTP/1 listener and not on the MITM
 * one: `Http2ServerResponse` has no `destroyed` property at all, so the read is
 * `undefined` and the question is answered "no" for every h2 request, on the
 * path that carries most of the traffic. The h2 equivalent lives on the
 * underlying stream.
 *
 * Asked wherever the answer decides whether to spend something the client will
 * never receive. On the retry ladder that is an upstream call and a slice of an
 * account's weekly quota per rung, which is the opposite of what rotation is
 * for. In practice the ladder is cut short by the abort probe handed to
 * `admit()`, which is polled while a request waits for a concurrency slot; the
 * reads on the individual rungs are the backstop for a request that never
 * waited.
 *
 * In `streamResponse` the cost is the handler itself. Writing to a cancelled
 * stream returns false, and the backpressure wait below then listens for a
 * `drain` or a `close` that has already happened and will not happen again, so
 * the handler never returns and its activity entry never closes.
 */
// The reason a request's AbortSignal carries when the client went away. Every
// wait in forwardRequest either resolves to a clientGone check or rejects with
// this, and the catch recognises it by code.
function clientGoneError() {
  const err = /** @type {CodedError} */ (new Error('client disconnected'));
  err.code = 'TEAMCLAUDE_CLIENT_GONE';
  return err;
}

/** @param {ProxyResponse} res */
function clientGone(res) {
  return !!res.destroyed || !!res.stream?.destroyed;
}

/**
 * The last response an outer catch can send. Three states:
 *
 *   - Nothing written yet: send a 502. Guarded on headersSent, because a second
 *     writeHead raises ERR_HTTP_HEADERS_SENT from inside the catch.
 *   - Headers sent, body unfinished: destroy. There is no status left to send,
 *     and end() would present the truncated bytes as a complete reply.
 *   - Response already ended: leave it alone, the client has its answer.
 *
 * `forwardRequest`'s own catch already carries the same pair of arms.
 */
/** @param {ProxyResponse} res */
function answerUnhandled(res) {
  if (!res.headersSent && !clientGone(res)) {
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: 'Internal proxy error' } }));
  } else if (!res.writableEnded) {
    res.destroy();
  }
}

// Per-request https.Agent tunneled through sx.org — one-shot (no keep-alive
// reuse, matching upstream-fetch.js's proxiedFetch), so a fresh sx tunnel is
// dialed for this connection only.
function sxAgent(sx, targetHost) {
  const proxy = sx.getProxy();
  const agent = new https.Agent({ keepAlive: false });
  agent.createConnection = (_options, cb) => {
    tunnelTls({ proxy, targetHost, targetPort: 443, tlsOptions: sx.tlsOptions || {} })
      .then((sock) => cb(null, sock))
      .catch((err) => cb(err, null));
    return undefined;
  };
  return agent;
}

/**
 * Relay a request to upstream with the client's OWN headers intact (including
 * its authorization) — used for Remote Control (/v1/code/*), whose event
 * stream is a long-poll: the client keeps the request open indefinitely and
 * the upstream may withhold response headers for minutes between events. No
 * buffering, no timeout, no reconstruction — just pipe bytes both ways as they
 * arrive, exactly like a transparent proxy would. `label` names the caller in the
 * error log, since the preconnect relay shares this path.
 */
function relayStream(req, res, upstream, sx, label = 'Remote Control relay', stripOverage = false) {
  const target = new URL(`${upstream}${req.url}`);
  /** @type {import('node:http').OutgoingHttpHeaders} */
  const headers = {};
  for (const [key, value] of Object.entries(req.headers)) {
    const lk = key.toLowerCase();
    if (lk.startsWith(':') || HOP_BY_HOP_HEADERS.has(lk) || lk === 'accept-encoding') continue;
    // The client's identity on this path is its bearer; x-api-key is how it
    // authenticated to THIS proxy, so relaying it would hand the operator's
    // proxy key to upstream.
    if (lk === 'x-api-key') continue;
    headers[key] = value;
  }

  const useProxy = !!(sx?.useByDefault() && sx.isProvisioned());
  const agent = useProxy ? sxAgent(sx, target.hostname) : undefined;
  const transport = target.protocol === 'http:' ? http : https;

  const upstreamReq = transport.request(target, { method: req.method, headers, agent }, (upstreamRes) => {
    const responseHeaders = {};
    for (const [key, value] of Object.entries(upstreamRes.headers)) {
      if (CONNECTION_SPECIFIC_HEADERS.has(key) || key === 'content-encoding' || key === 'content-length') continue;
      if (stripOverage && isOverageHeader(key)) continue;
      responseHeaders[key] = value;
    }
    res.writeHead(upstreamRes.statusCode, responseHeaders);
    upstreamRes.pipe(res);
    // pipe() only propagates 'end'. If the upstream leg dies mid-response
    // (network blip, upstream restart), upstreamRes emits 'aborted'/'error'
    // and the pipe just stops — the client's long-poll stays open forever and
    // the CLI keeps waiting on a channel that can no longer deliver events.
    // Destroying res closes the client socket, which is the one signal its
    // reconnect logic reacts to.
    upstreamRes.on('aborted', () => res.destroy());
    upstreamRes.on('error', () => res.destroy());
  });

  upstreamReq.on('error', (err) => {
    console.error(`[TeamClaude] ${label} error:`, describeConnectError(err));
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: 'Upstream unreachable' } }));
    } else {
      // Headers already went out (the long-poll was live), so a 502 body can't
      // be written anymore. Close the client socket instead of leaving it
      // half-dead: seen in production as a `socket hang up` logged here while
      // the CLI's Remote Control stream silently waited on it for 45+ minutes.
      res.destroy();
    }
  });
  // Client disconnected (e.g. Claude Code closed the channel): tear down the
  // upstream side too instead of leaking an open connection.
  res.on('close', () => upstreamReq.destroy());

  if (['GET', 'HEAD'].includes(req.method)) upstreamReq.end();
  else req.pipe(upstreamReq);
}

/**
 * The key gate for a WebSocket upgrade, in the shape of the CONNECT one.
 *
 * Separate from `resolveClientAuth` only because the answer depends on the
 * socket's address as well as the header, and separate from the request path
 * because `server.on('upgrade')` is a different event that no part of
 * `requestHandler` runs for.
 *
 * `x-api-key` only. A browser cannot set that header on a WebSocket
 * handshake, so a browser client cannot authenticate here — deliberately.
 * The obvious alternative, reading the key out of `Sec-WebSocket-Protocol`,
 * is worse than not supporting browsers: relayUpgrade forwards that header to
 * the upstream (it strips `x-api-key`, which is the whole reason the
 * handshake carries no operator credential today), the offer list is
 * attacker-sized so it turns one guess per connection into thousands, and the
 * proxy cannot honour the negotiation anyway because it relays the handshake
 * rather than answering it.
 */
export function resolveUpgradeAuth(req, socket, proxyConfig, boundHost = null) {
  const auth = resolveClientAuth(proxyConfig, req?.headers?.['x-api-key']);
  if (auth.ok) return auth;
  // Loopback is exempt from the key requirement, exactly as the HTTP and
  // CONNECT gates are — with the request path's two conditions on top, for
  // the same actor: a web page in the operator's browser. A page can open a
  // WebSocket to 127.0.0.1 with no CORS check at all, and its handshake is
  // loopback-sourced too. What it cannot forge is `Origin`, which a browser
  // sets on every handshake and a CLI never sends, nor `Host`, which a
  // rebound name (attacker.example → 127.0.0.1) leaves naming the attacker.
  if (!loopbackExempt(req?.headers, socket?.remoteAddress, proxyConfig)) return auth;
  const bindHost = boundHost || proxyConfig?.host;
  const origin = req?.headers?.origin;
  if (origin) {
    let originHost;
    try { originHost = new URL(origin).host; } catch { return auth; }
    if (!isLocalHostHeader(originHost, bindHost)) return auth;
  }
  if (!isLocalHostHeader(req?.headers?.host, bindHost)) return auth;
  return { ok: true, client: null };
}

/**
 * Relay a WebSocket upgrade (e.g. Remote Control's real-time
 * `/v1/session_ingress/ws/*` channel) to upstream with the client's own
 * headers intact. An HTTP server never emits 'request' for an Upgrade
 * handshake — only 'upgrade', with a raw socket instead of a response object —
 * so this needs its own relay rather than going through relayStream/res.
 * Reuses Node's http(s) client, which already knows how to speak the Upgrade
 * handshake (emits its own 'upgrade' event on a 101); once that fires it's
 * just two raw sockets spliced together.
 */
/**
 * The URL a WebSocket upgrade for `url` is relayed to on `upstream`, or null
 * when it cannot be — an answer, never a throw.
 *
 * This was `new URL(upstream + req.url)`. With an upstream that carries a port
 * (`http://127.0.0.1:4000`, or a redundant `:443`) and a request target that
 * is not a plain path — the absolute form `GET http://x/ HTTP/1.1`, ordinary
 * proxy traffic — the concatenation ran straight on from the port digits and
 * `new URL()` threw. The upgrade listener was the one entry point with no
 * try/catch around it, so the throw was an uncaughtException and the daemon
 * exited: one crafted handshake, every session gone (#340).
 *
 * Only the origin form is relayed, and the result is pinned to the upstream's
 * origin: resolving the target against the upstream as a base would turn
 * `http://x/` or `//evil.example/p` into a relay to that host instead. The
 * concatenation itself is kept for an origin-form path, because an upstream
 * may carry a path prefix of its own (`https://gateway.example/anthropic`)
 * that resolution would discard.
 */
/** @param {string} upstream @param {string|undefined} url */
export function upgradeTarget(upstream, url) {
  // Origin form: a single leading slash. `//host` is scheme-relative, and the
  // URL parser reads a backslash as a slash for http(s), so `/\host` is too.
  if (typeof url !== 'string' || !/^\/(?![\/\\])/.test(url)) return null;
  let base, target;
  try {
    base = new URL(upstream);
    target = new URL(`${upstream}${url}`);
  } catch { return null; }
  if (target.origin !== base.origin) return null;
  return target;
}

/** @param {ProxyRequest} req @param {import('node:stream').Duplex} socket @param {Buffer} head
 * @param {string} upstream @param {SxManager|null} sx
 * @param {{client?: string|null, clientUsage?: ClientUsageTracker|null, log?: (line: string) => void, headersTimeoutMs?: number|null, stripOverage?: boolean}} [options] */
export function relayUpgrade(req, socket, head, upstream, sx, { client = null, clientUsage = null, log = console.log, headersTimeoutMs = null, stripOverage = false } = {}) {
  const target = upgradeTarget(upstream, req.url);
  if (!target) {
    log(`[TeamClaude] WebSocket upgrade refused: request target ${JSON.stringify(safeLine(req.url, 128))} is not a path on the upstream`);
    try { socket.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'); } catch { /* already gone */ }
    socket.destroy();
    return;
  }
  // The channel's log lines, prefixed `[name]` like a request line when a
  // client key authenticated the handshake, so an operator reading per-client
  // activity sees the channel beside the requests. Booked only once upstream
  // accepts: a handshake it refuses opened nothing.
  const tag = client ? `[${safeLine(client, 64)}] ` : '';
  const path = safeLine(req.url);
  /** @type {import('node:http').OutgoingHttpHeaders} */
  const headers = {};
  for (const [key, value] of Object.entries(req.headers)) {
    const lk = key.toLowerCase();
    // Unlike relayStream, do NOT strip 'upgrade'/'connection' here — they ARE
    // the handshake. Only 'host' (the client transport reconstructs it from
    // `target`), h2 pseudo-headers and the proxy's own x-api-key (the client's
    // credential to us, not to upstream) are dropped.
    if (lk.startsWith(':') || lk === 'host' || lk === 'x-api-key') continue;
    headers[key] = value;
  }

  const useProxy = sx?.useForConnect?.() === true || !!(sx?.useByDefault?.() && sx.isProvisioned());
  const agent = useProxy && sx ? createUpgradeProxyAgent(target, sx.getProxy(), sx) : undefined;
  // One module's signature stands for both: the options this call passes are
  // the same for http and https, and a union of the two `request` overload sets
  // is not callable as such.
  const transport = /** @type {typeof https} */ (target.protocol === 'http:' ? http : https);

  const upstreamReq = transport.request(target, { method: req.method, headers, agent });
  const timeoutMs = positiveTimeout(headersTimeoutMs);
  const timer = timeoutMs ? setTimeout(() => {
    const err = /** @type {import('./types.js').CodedError} */ (new Error(`upstream response headers timed out after ${timeoutMs}ms`));
    err.code = 'TEAMCLAUDE_HEADERS_TIMEOUT';
    upstreamReq.destroy(err);
    socket.destroy();
  }, timeoutMs) : null;
  timer?.unref?.();
  const clearTimer = () => { if (timer) clearTimeout(timer); };
  socket.once('close', () => { clearTimer(); upstreamReq.destroy(); agent?.destroy(); });

  upstreamReq.on('upgrade', (upstreamRes, upstreamSocket, upstreamHead) => {
    clearTimer();
    const headerLines = Object.entries(upstreamRes.headers)
      .filter(([k]) => !(stripOverage && isOverageHeader(k)))
      .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`);
    // Lines joined, one terminator: an empty header set must not leave a blank
    // line inside (or an extra CRLF after) the response head.
    socket.write([`HTTP/1.1 ${upstreamRes.statusCode} ${upstreamRes.statusMessage}`, ...headerLines].join('\r\n') + '\r\n\r\n');
    if (upstreamHead?.length) socket.write(upstreamHead);
    if (head?.length) upstreamSocket.write(head);
    socket.pipe(upstreamSocket);
    upstreamSocket.pipe(socket);
    clientUsage?.record(client, { connections: 1 });
    const opened = Date.now();
    log(`[TeamClaude] ${tag}WebSocket ${path} connected`);
    socket.once('close', () => log(`[TeamClaude] ${tag}WebSocket ${path} closed (${((Date.now() - opened) / 1000).toFixed(1)}s)`));
    // An upgraded socket defaults to half-open: the peer's FIN only ends the
    // READABLE side ('end'), it does NOT destroy the socket or fire 'close' —
    // so without this, one side hanging up (dropped wifi, killed CLI) leaves
    // the other socket open forever. destroy() is idempotent, so reacting to
    // both 'end' and 'close' on each side is a safe, redundant backstop.
    socket.on('end', () => upstreamSocket.destroy());
    upstreamSocket.on('end', () => socket.destroy());
    socket.on('close', () => upstreamSocket.destroy());
    upstreamSocket.on('close', () => socket.destroy());
    // The 101 detaches this socket from upstreamReq, so the request's 'error'
    // listener no longer covers it. A link that flaps mid-session then raises
    // 'error' (write EPIPE / read ECONNRESET) on a socket nobody listens to,
    // which Node escalates to an uncaught exception — one dropped WebSocket
    // would kill the proxy for every other session. Close the pair instead.
    upstreamSocket.on('error', () => socket.destroy());
  });

  // Upstream answered with a plain response instead of the 101: the handshake
  // was refused (an expired credential, an unknown session). Without this the
  // client socket hung with no answer until it timed out, and nothing was
  // logged. Relay the status so the client sees the refusal it was given.
  upstreamReq.on('response', (upstreamRes) => {
    clearTimer();
    log(`[TeamClaude] ${tag}WebSocket ${path} refused by upstream (${upstreamRes.statusCode})`);
    const headerLines = Object.entries(upstreamRes.headers)
      .filter(([k]) => !CONNECTION_SPECIFIC_HEADERS.has(k.toLowerCase()) && k.toLowerCase() !== 'content-length')
      .filter(([k]) => !(stripOverage && isOverageHeader(k)))
      .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`);
    try {
      socket.write([`HTTP/1.1 ${upstreamRes.statusCode} ${upstreamRes.statusMessage}`, ...headerLines, 'Connection: close'].join('\r\n') + '\r\n\r\n');
    } catch { /* already gone */ }
    upstreamRes.resume();
    socket.destroy();
  });

  upstreamReq.on('error', (err) => {
    clearTimer();
    console.error('[TeamClaude] Remote Control WebSocket relay error:', describeConnectError(err));
    socket.destroy();
  });
  socket.on('error', () => upstreamReq.destroy());

  upstreamReq.end();
}

/**
 * Refuse a request whose body ran past the buffering cap.
 *
 * The 413 goes out first and the request is torn down only once it has been
 * flushed. The order matters: destroying first races the answer off the
 * socket, while merely ending the response makes Node drain (read and discard)
 * the rest of the body, which is exactly the traffic the cap exists to stop.
 * 'close' is raced against the flush so a client that has already gone away
 * cannot hold the handler open waiting for a 'finish' that never comes.
 * Mid-stream (headers already out) there is no status left to send.
 */
async function refuseOversizedBody(req, res) {
  if (!res.headersSent) {
    res.writeHead(413, { 'Content-Type': 'application/json' });
    await new Promise((resolve) => {
      res.once('close', resolve);
      res.end(JSON.stringify({
        type: 'error',
        error: { type: 'invalid_request_error', message: 'Request body too large' },
      }), resolve);
    });
  }
  req.destroy();
}

/**
 * Relay a request to upstream on the client's own terms: no pooled account
 * credentials are injected and the body goes through unchanged, with only
 * content-type, accept and user-agent forwarded. On the way back the
 * connection-specific and stale framing headers (transfer-encoding,
 * connection, content-encoding, content-length) are dropped, and so is the
 * per-org billing family when `stripOverage` is set (see isOverageHeader).
 * Buffers the body bounded by maxBodyBytes (else 413) so the untouched
 * `/v1/oauth/token` path can't be used to exhaust proxy memory.
 */
async function relayRaw(req, res, upstream, sx, maxBodyBytes = DEFAULT_MAX_BODY_BYTES, stripOverage = false) {
  const bodyChunks = [];
  let bodyBytes = 0;
  for await (const chunk of req) {
    bodyBytes += chunk.length;
    // Same cap as the forward path: this buffers too, and a token exchange is
    // a few hundred bytes.
    if (bodyBytes > maxBodyBytes) { await refuseOversizedBody(req, res); return; }
    bodyChunks.push(chunk);
  }
  const body = Buffer.concat(bodyChunks);

  // Abort the relay if the client disconnects, so a hung upstream OAuth endpoint
  // can't pin this connection (and its admission-control inFlightProxied slot)
  // forever. Tied to res 'close'; the listener is removed once we're done.
  const ac = new AbortController();
  const onClose = () => ac.abort();
  res.on('close', onClose);
  try {
    const upstreamRes = await upstreamFetch(`${upstream}${req.url}`, {
      method: req.method,
      headers: {
        'content-type': req.headers['content-type'] || 'application/json',
        'accept': req.headers['accept'] || 'application/json',
        'user-agent': req.headers['user-agent'] || 'node',
      },
      body: body.length > 0 ? body : undefined,
      signal: ac.signal,
      redirect: 'manual',
    }, sx);

    const responseBody = await upstreamRes.text();
    const responseHeaders = {};
    for (const [key, value] of upstreamRes.headers.entries()) {
      if (CONNECTION_SPECIFIC_HEADERS.has(key) || key === 'content-encoding' || key === 'content-length') continue;
      if (stripOverage && isOverageHeader(key)) continue;
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
  const pad = (/** @type {number} */ n, w = 2) => String(n).padStart(w, '0');
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
}

// How much of each request the `logDir` log records. 'body' is what the logger
// has always done; 'headers' drops both body sections, which is the difference
// between a kilobyte and a megabyte per request.
const LOG_LEVELS = new Set(['off', 'headers', 'body']);
const DEFAULT_LOG_LEVEL = 'body';

/** @param {ServerConfig|null|undefined} config */
export function resolveLogLevel(config) {
  const level = config?.logLevel;
  return level && LOG_LEVELS.has(level) ? level : DEFAULT_LOG_LEVEL;
}

// Bodies are what make the log large, and a cap bounds nothing unless it
// actually applies: at 256 KiB the kept head and tail are each larger than
// anyone reads by eye, while a request log stops scaling with the context the
// request carried. 0 opts out, as with the other bounding settings.
const DEFAULT_LOG_MAX_BODY_BYTES = 262_144;

export function resolveLogMaxBodyBytes(config) {
  const raw = config?.logMaxBodyBytes;
  // A quoted number in hand-edited JSON is a common slip, so read it. A blank
  // string is not a number and means "unset", which must reach the default:
  // Number('') is 0, and 0 here would be the unbounded logging this bounds.
  // Number() on null or true would likewise read as 0 and 1 rather than junk.
  const max = typeof raw === 'string' && raw.trim() !== '' ? Number(raw) : raw;
  if (max === 0) return 0;
  return Number.isFinite(max) && max > 0 ? max : DEFAULT_LOG_MAX_BODY_BYTES;
}

// Bound every buffered body, including OAuth token relays. The local
// maxRequestBytes setting takes precedence over proxy.maxBodyBytes; zero
// never opts out of the memory bound.
export const DEFAULT_MAX_BODY_BYTES = 32 * 1024 * 1024;

export function resolveMaxBodyBytes(config) {
  if (Number.isFinite(config?.maxRequestBytes) && config.maxRequestBytes > 0) return config.maxRequestBytes;
  const raw = config?.proxy?.maxBodyBytes;
  // Same reading rules as resolveLogMaxBodyBytes: a quoted number counts, a
  // blank string means unset. Zero retains the default memory bound.
  const max = typeof raw === 'string' && raw.trim() !== '' ? Number(raw) : raw;
  if (max === 0) return DEFAULT_MAX_BODY_BYTES;
  return Number.isFinite(max) && max > 0 ? max : DEFAULT_MAX_BODY_BYTES;
}

// The names openRequestLog writes, and nothing else. Deletion keys off this
// pattern rather than off mtime so a file the logger did not create cannot
// match: the directory is one the operator named, and may hold anything.
const LOG_FILE_RE = /^(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})\.(\d{3})_\d{5,}\.log$/;
const LOG_SWEEP_INTERVAL_MS = 10 * 60_000;
const DEFAULT_LOG_RETENTION_HOURS = 72;

export function resolveLogRetentionHours(config) {
  const raw = config?.logRetentionHours;
  // Strings only, and it matters most here: this is the setting that deletes.
  // A quoted "0" must mean "keep everything" rather than falling back to the
  // default and deleting, and a quoted "720" must not silently become 72. A
  // blank string means "unset" and reaches the default, since Number('') is 0.
  // Number() on null or true would instead read as 0 and 1.
  const hours = typeof raw === 'string' && raw.trim() !== '' ? Number(raw) : raw;
  if (hours === 0) return 0;
  return Number.isFinite(hours) && hours > 0 ? hours : DEFAULT_LOG_RETENTION_HOURS;
}

/**
 * Delete expired request logs from `logDir`, returning how many were removed.
 *
 * Candidates come from the filename, which openRequestLog stamps in local time,
 * so the scan costs one readdir and no stat for everything it skips — it has to
 * stay cheap over a directory holding tens of thousands of files. Anything that
 * is not a file, not name-matched, or inside a subdirectory is left alone.
 *
 * Only names already past the cutoff are stat'd, and mtime has to agree before
 * the unlink. The name's clock is local, so a machine that changes timezone (a
 * laptop does it by itself) can age a file by hours; mtime is absolute. Every
 * disagreement between the two therefore keeps the file, which is the bias this
 * operation needs — including for a file still being appended to, whose mtime
 * is fresh however old its name looks.
 */
/** @param {string} logDir @param {number} retentionHours @param {number} [now] */
export async function sweepRequestLogs(logDir, retentionHours, now = Date.now()) {
  if (!(retentionHours > 0)) return 0;
  const cutoff = now - retentionHours * 3600_000;
  let entries;
  try {
    entries = await readdir(logDir, { withFileTypes: true });
  } catch {
    return 0;
  }
  let removed = 0;
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const m = LOG_FILE_RE.exec(entry.name);
    if (!m) continue;
    const started = new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], +m[7]).getTime();
    // Negated so anything not definitively older than the cutoff is skipped.
    // The pattern admits only digits and Date rolls every such combination into
    // a real time, so this cannot be indeterminate today; the shape keeps the
    // bias toward skipping if the pattern is ever loosened.
    if (!(started < cutoff)) continue;
    const path = join(logDir, entry.name);
    try {
      const { mtimeMs } = await stat(path);
      if (!(mtimeMs < cutoff)) continue;
    } catch {
      continue;
    }
    try {
      await unlink(path);
      removed++;
    } catch { /* already gone, or a concurrent sweep won the race */ }
  }
  return removed;
}

// A per-request log that streams to disk as the request/response flow, instead
// of buffering the whole body in memory and writing once at the end. The file
// is opened on first write; header sections are written verbatim and bodies are
// streamed through BodyWriter (JSON pretty-printed on the fly, SSE/other raw),
// so even a ~1M-token response costs only the current chunk.
// Process-wide sequence for log file names. The per-request id is per
// listener (the base server and each MITM pin server count from zero), so two
// listeners could open the same "<ms-timestamp>_<id>" name in one millisecond
// and interleave two requests in one file. A single counter cannot collide.
let logFileSeq = 0;

/** @param {string} logDir @param {number} _reqId @param {{level?: string, maxBodyBytes?: number}} [options] */
function openRequestLog(logDir, _reqId, { level = DEFAULT_LOG_LEVEL, maxBodyBytes = DEFAULT_LOG_MAX_BODY_BYTES } = {}) {
  const filename = `${logTimestamp()}_${String(++logFileSeq).padStart(5, '0')}.log`;
  // 0600: the file holds the full request and response bodies.
  const ws = createWriteStream(join(logDir, filename), { flags: 'a', mode: 0o600 });
  let ended = false;
  let failed = false;
  // Whether the last write was queued rather than flushed. The streaming path
  // asks drain() so a disk that cannot keep up with upstream pauses the relay
  // instead of the body piling up in the stream's buffer — the "only the
  // current chunk in memory" promise has to hold for the socket underneath the
  // formatter too.
  let backlogged = false;
  const fail = (/** @type {unknown} */ err) => {
    if (failed) return;
    failed = true;
    console.error(`[TeamClaude] Request log ${filename} abandoned: ${err instanceof Error ? err.message : String(err)}`);
  };
  ws.on('error', fail);
  const write = (/** @type {string} */ s) => {
    if (ended || failed || !s) return;
    backlogged = !ws.write(Buffer.from(String(s), 'latin1'));
  };
  // Logging must never fail the request it describes. The formatter runs on
  // whatever bytes the client or upstream produced, so a throw here is a log
  // problem, not a request problem: record it once and go on relaying.
  /** @template T @param {() => T} fn @returns {T|undefined} */
  const guarded = (fn) => { try { return fn(); } catch (err) { fail(err); return undefined; } };
  /** @returns {Promise<void>|null} */
  const drain = () => {
    if (!backlogged || ended || failed || ws.destroyed) return null;
    return new Promise((resolve) => {
      const done = () => { ws.off('drain', done); ws.off('close', done); ws.off('error', done); backlogged = false; resolve(); };
      ws.once('drain', done);
      ws.once('close', done);
      ws.once('error', done);
    });
  };
  return {
    write,
    // Stream a complete body buffer under a section header.
    /** @param {string} label @param {Buffer|null} buf @param {string|null|undefined} contentType */
    body(label, buf, contentType) { guarded(() => this._body(label, buf, contentType)); },
    /** @param {string} label @param {Buffer|null} buf @param {string|null|undefined} contentType */
    _body(label, buf, contentType) {
      if (level === 'headers') return;
      if (!buf || !buf.length) { write(`\n\n=== ${label} ===\n(empty)`); return; }
      if (maxBodyBytes > 0) {
        // A complete body is already held whole, so keeping its tail costs no
        // extra memory — and the tail is where the newest message and the latest
        // tool result sit, which is usually what the log was opened for.
        const half = Math.max(1, Math.floor(maxBodyBytes / 2));
        const dropped = buf.length - 2 * half;
        if (dropped > 0) {
          // The tail goes in raw. Replaying it through the head's formatter would
          // carry that formatter's depth and in-string state across the gap: the
          // indentation would be wrong, and once the tail's closing brackets
          // outnumber the depth it throws on a negative repeat count.
          const head = new BodyWriter(write, label, contentType || '');
          head.chunk(buf.subarray(0, half));
          head.end();
          write(`\n${truncationNote(dropped)}\n`);
          write(buf.subarray(buf.length - half).toString('latin1'));
          return;
        }
      }
      const whole = new BodyWriter(write, label, contentType || '');
      whole.chunk(buf);
      whole.end();
    },
    // A BodyWriter to append chunks incrementally (e.g. an SSE response), or
    // null when the level records no bodies — streamResponse takes either.
    /** @param {string} label @param {string|null|undefined} contentType */
    bodyWriter(label, contentType) {
      if (level === 'headers') return null;
      const bw = new BodyWriter(write, label, contentType || '', maxBodyBytes);
      return {
        chunk: (/** @type {Buffer} */ buf) => guarded(() => bw.chunk(buf)),
        end: () => guarded(() => bw.end()),
        drain,
      };
    },
    end() { if (!ended) { ended = true; if (!failed) ws.end('\n'); else ws.destroy(); } },
  };
}

function formatHeaders(headers) {
  if (headers.entries) {
    return [...headers.entries()].map(([k, v]) => `  ${k}: ${v}`).join('\n');
  }
  return Object.entries(headers).map(([k, v]) => `  ${k}: ${v}`).join('\n');
}

// Failures that say nothing about the ACCOUNT, only about the socket. Retrying
// can succeed where failing over cannot, and closing fast lets Node evict the
// dead socket so the client's retry reconnects cleanly. EPIPE joins the set as
// the write-side sibling of ECONNRESET.
//
// ECONNREFUSED sits here despite being arguably a property of the host. It is
// already unconditionally transient, so making it conditional converts every gap
// in that condition into a regression instead of leaving an unfixed case. One
// such gap was measurable before the other-host scan gated on selection's own
// eligibility predicate: a disabled account carrying its own `upstream` was
// never selected, never entered `ctx.tried`, and satisfied the condition
// indefinitely — a four-account fleet spent three accounts on a refused
// connection and answered rate_limit_error. That instance is closed; keeping
// ECONNREFUSED unconditional means any future gap stays a non-regression.
const SOCKET_TRANSIENT = new Set([
  'ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'EPIPE',
  'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT',
  'TEAMCLAUDE_HEADERS_TIMEOUT', 'TEAMCLAUDE_BODY_TIMEOUT',
]);

// Failures that are a property of the HOST being dialled: name resolution and
// routing. The hostname has no per-account component, so every account produces
// the same failure, and walking the fleet spends an upstream call per account to
// learn the same thing. The client is then told its quota is exhausted because a
// name would not resolve.
//
// Conditional, because an account may name its own `upstream` for a third-party
// backend. Where an untried account would dial a different host, this failure
// says nothing about that one, and failing over is correct.
const HOST_TRANSIENT = new Set(['ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH', 'ENETUNREACH', 'ENETDOWN']);

/**
 * Every error code a failure carries: its own, its `cause`'s, and its
 * children's. Node's global fetch puts the real error on `cause`, and the
 * happy-eyeballs dialer reports an all-addresses-failed connect as an
 * AggregateError that may carry no top-level code at all, with the reason
 * recorded once per address.
 */
function errorCodes(err) {
  const codes = [err?.code, err?.cause?.code];
  for (const child of err?.errors || []) codes.push(child?.code);
  for (const child of err?.cause?.errors || []) codes.push(child?.code);
  return codes.filter(Boolean);
}

/**
 * Should this upstream failure close the connection for the client to retry,
 * instead of being failed over to the next account?
 *
 * `otherHostAvailable` states whether an untried account would dial a different
 * host, which is what makes a host-scoped failure worth failing over. Exported
 * for its own tests.
 */
export function isTransientUpstreamError(err, { otherHostAvailable = false } = {}) {
  if (!(err instanceof Error)) return false;
  // The account's OWN routing proxy could not be reached. Read before the
  // socket codes, which the failure also carries (on `cause`) and which say
  // the opposite: an ECONNREFUSED is "the same for every account" only when it
  // comes from the host they all dial. From one account's proxy it describes
  // that account alone, the next account leaves by another path, and nothing
  // of the request has been sent, so failing over is both safe and the fix.
  // Closing for the client to retry would hand the retry to the same account.
  if (isRoutingFailure(err)) return false;
  if (err.name === 'TimeoutError' || err.name === 'AbortError') return true;
  const codes = errorCodes(err);
  if (codes.some(c => SOCKET_TRANSIENT.has(c))) return true;
  if (codes.some(c => HOST_TRANSIENT.has(c))) return !otherHostAvailable;
  // Read last, and only once no code has been found. Node's global fetch, which
  // `TEAMCLAUDE_UPSTREAM_GLOBAL_FETCH` selects, reports every failure with this
  // message and the real error on `.cause`; checking it earlier would answer for
  // the whole transport before the codes above were consulted, so a host-scoped
  // failure there would never reach its conditional arm.
  if (typeof err.message === 'string' && err.message.includes('fetch failed')) return true;
  return false;
}

/**
 * The accounts this request could ever have landed on, disabled ones included.
 *
 * Both halves of the exhaustion answer — how many accounts ran out, and how long
 * until one of them is back — used to be read off the whole fleet. On a mixed
 * fleet that is the wrong pool twice over: a Codex request has no claim on the
 * Anthropic subscriptions beside it, so neither their capacity nor their reset
 * windows say anything about why it was refused.
 *
 * Eligibility here is only the two gates a request cannot argue with, the ones
 * that hold however rotation goes: the provider partition (a Claude Max token
 * and a ChatGPT token are each issued to one app and cannot be spent by the
 * other) and the route/ownership rule that decides which accounts a model id may
 * use at all. Everything else selection weighs — quota, throttles, priority,
 * session affinity — is a reason an eligible account is unavailable RIGHT NOW,
 * which is the very thing the caller is measuring; folding those in would leave
 * an empty set and nothing to measure.
 *
 * Disabled accounts stay in, because the message counts them separately: they
 * are the aside that says the fleet is smaller than the config looks.
 *
 * @param {import('./account-manager.js').AccountManager} accountManager
 * @param {string|null|undefined} model
 * @param {string|undefined} provider
 * @returns {Record<string, any>[]}
 */
export function candidateAccounts(accountManager, model, provider) {
  return (accountManager.accounts || []).filter(a =>
    canServeProvider(a, provider || DEFAULT_PROVIDER) && accountManager._routeAllows(a, model));
}

/**
 * A wait in seconds, written the way a person would say it.
 *
 * The retry-after is now the real window, which can be days, and "resets in
 * 259200s" makes the operator do the division before they learn whether to get
 * a coffee or go home. Short waits stay in seconds, since that is the unit the
 * header beside the message carries and the two are easy to match up by eye.
 * Everything longer is rounded UP to the unit shown, so the text never promises
 * capacity sooner than the header does.
 *
 * Not `formatDuration` from status-renderer.js: that one is private to the
 * status view, packs its units together ("2d3h") for a narrow column, and
 * leaves seconds at one minute. This is a sentence, not a column.
 *
 * @param {number} seconds
 * @returns {string}
 */
export function formatWait(seconds) {
  if (seconds < 120) return `${seconds}s`;
  const minutes = Math.ceil(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  if (minutes < 24 * 60) {
    const rest = minutes % 60;
    const hours = Math.floor(minutes / 60);
    return rest ? `${hours}h ${rest}m` : `${hours}h`;
  }
  // Past a day the minutes are noise, so they are folded up into the hour.
  const hours = Math.ceil(minutes / 60);
  const rest = hours % 24;
  const days = Math.floor(hours / 24);
  return rest ? `${days}d ${rest}h` : `${days}d`;
}

// How many credential-dead accounts the synthetic 429 names before it says
// "and N more". The sentence is read in a client's one-line error, not a report.
const EXHAUSTED_MESSAGE_MAX_NAMES = 3;

/**
 * The message behind the synthetic 429, when no account can serve the request.
 *
 * The old wording — `All N accounts exhausted. Retry in 60s.` — was wrong in
 * three ways at once, and each one pushed the operator somewhere unhelpful
 * (#168):
 *
 *   - N counted every configured account, including ones the operator had
 *     disabled. An account deliberately out of rotation is not capacity that
 *     ran out.
 *   - it never named the model, so a family-specific refusal (Fable spent,
 *     Opus fine) read as the whole proxy being out of capacity.
 *   - "exhausted" reads terminal while "retry in 60s" reads transient, so the
 *     operator retried by hand instead of looking at what was actually blocked.
 *
 * Counts only the accounts that were candidates, names the model when the
 * request carried one, and says plainly that the wait is until a window resets.
 *
 * "Candidates" was the word but not the behaviour: the count went on filtering
 * the whole fleet by `disabled` alone, so a Codex request with three accounts to
 * its name reported all twelve as being at their quota — nine of them Anthropic
 * accounts it could never have used, and an operator reading that goes looking
 * for a fleet-wide outage. The set now arrives from the caller, already narrowed
 * (`candidateAccounts`), and is the same set the retry-after beside it was
 * measured from, so the number and the wait cannot disagree about who was even
 * asked.
 *
 * That wording was then wrong a different way (#407). One account at a real
 * family quota, another with headroom but in `error` — typically
 * `invalid_grant`, after a Claude Code `/login` elsewhere rotated the refresh
 * token — and the proxy rightly skips both, yet the client read "all 2 accounts
 * are at their quota or rate limit". The TUI went on showing the errored
 * account's quota bars with room in them, so the operator waited out a reset
 * that was never going to help, when the fix was `teamclaude login`.
 *
 * Blockers are told apart by the next step they call for, and there are three:
 * log in again, fix the account's routing proxy, or wait. A dead credential is read off `status === 'error'`
 * directly rather than through `unavailableReason`, for two reasons. It is
 * exactly the test `computeRetryAfter` uses to leave an account's clocks out of
 * the wait, so the accounts named here and the accounts the wait ignores are
 * one set by construction. And `unavailableReason` reports a budget cap or an
 * entitlement cooldown ahead of `error`, which would file a dead token under
 * "wait for the reset" whenever the two coincide. Everything that is not a dead
 * credential — quota, throttle, upstream rejection, a cap, and an OAuth
 * entitlement denial, which is an org-policy 403 on a timed cooldown and not
 * something a new login repairs — stays in the quota/rate-limit group.
 *
 * An account inside its routing cooldown (its own proxy could not be reached)
 * is the third: no quota is resetting, so "Quota resets in 28s" over a proxy
 * that is down would send the operator to the wrong screen.
 *
 * @param {Record<string, any>[]} candidates
 * @param {string|null|undefined} model
 * @param {number} retryAfter
 * @returns {string}
 */
export function exhaustedMessage(candidates, model, retryAfter) {
  const eligible = candidates.filter(a => !a.disabled);
  const disabled = candidates.length - eligible.length;

  const scope = model ? ` for ${model}` : '';
  // No eligible account is not exhaustion. Nothing is going to reset, so a wait
  // is the wrong advice and "all 0 accounts are at their quota" is the wrong
  // sentence: either the operator disabled the ones that qualify, or none
  // qualifies at all — a route's account list crossed with the provider
  // partition, which leaves a route that looks healthy in `teamclaude status`
  // and can serve nothing.
  if (!eligible.length) {
    return disabled
      ? `No account can serve this request${scope}: every account eligible for it is disabled (${disabled}).`
      : `No account can serve this request${scope}: no configured account is eligible for it — check the model's route and which provider its accounts belong to.`;
  }
  const aside = disabled ? ` (${disabled} more disabled)` : '';
  const when = retryAfter > 0
    ? ` Quota resets in ${formatWait(retryAfter)}.`
    : ' Retry shortly.';

  const dead = eligible.filter(a => a.status === 'error');
  const now = Date.now();
  const unreachable = eligible.filter(a => a.status !== 'error' && a.routingFailedUntil > now);
  if (!dead.length && !unreachable.length) {
    const pool = eligible.length === 1 ? '1 account' : `${eligible.length} accounts`;
    return `No account can serve this request${scope}: all ${pool}${aside} are at their quota or rate limit.${when}`;
  }

  // Named, because "one of your accounts" sends the operator off to the status
  // view to learn which. Capped, because this text lands in a client's error
  // line and a fleet that lost every token at once would fill it. Sanitised,
  // because an account name comes out of an OAuth payload and is not ours.
  const named = (/** @type {Record<string, any>[]} */ list) => {
    const shown = list.slice(0, EXHAUSTED_MESSAGE_MAX_NAMES).map(a => `"${safeLine(a.name, 64)}"`).join(', ');
    const unnamed = Math.max(0, list.length - EXHAUSTED_MESSAGE_MAX_NAMES);
    return `${list.length === 1 ? 'account' : 'accounts'} ${shown}${unnamed ? ` and ${unnamed} more` : ''}`;
  };
  const blockers = [];
  if (dead.length) blockers.push(`${named(dead)} ${dead.length === 1 ? 'needs' : 'need'} re-login (run: teamclaude login)`);
  if (unreachable.length) {
    blockers.push(`${named(unreachable)} cannot reach ${unreachable.length === 1 ? 'its' : 'their'} routing proxy (see: teamclaude routing <name>)`);
  }

  // Every account that could take this request is blocked by something a wait
  // does not fix. No reset clause: no window is being waited on, and the
  // retry-after the caller worked out is only the interval it falls back to.
  const waiting = eligible.length - dead.length - unreachable.length;
  if (!waiting) {
    return `No account can serve this request${scope}: ${blockers.join('; ')}, and no other account is eligible for it.${aside}`;
  }

  const rest = waiting === 1
    ? '1 account is at its quota or rate limit'
    : `${waiting} accounts are at their quota or rate limit`;
  return `No account can serve this request${scope}: ${blockers.join('; ')}; ${rest}.${when}${aside}`;
}

// ── A refusal reported inside a 200 stream ───────────────────────────────────
//
// Every failover in forwardRequest keys on the upstream status, and the
// Responses API does not always use one: it answers 200, opens the SSE stream,
// and then reports "the selected model is at capacity" as an event in the body
// before any output. Measured on a five-account Codex pool, that was every
// refusal the pool saw — 937 × 200 and not one status-shaped failure — so the
// proxy relayed each one as an answer, on an account that may have been the
// only one refusing. The head of the stream is therefore read BEFORE its
// headers go out to the client: nothing has been written at that point, so the
// request is still retryable.

// The lifecycle events a Responses stream emits before it has committed to any
// output. While only these have been seen the stream is undecided and the peek
// keeps reading; the first event that is not one of them decides it.
const SSE_UNCOMMITTED_EVENTS = new Set(['response.created', 'response.queued', 'response.in_progress']);

/**
 * The failure codes that name the provider or the account rather than the
 * request. A stream whose first decisive event is a `response.failed` or
 * `error` carrying one of these takes one hop to a sibling. Any other code
 * (`invalid_prompt`, `invalid_request`, a content filter, ...) would be refused
 * identically by every account, so it is relayed and no sibling is spent.
 *
 * - `server_is_overloaded` — the Responses API's "selected model is at
 *   capacity", the case this exists for.
 * - `server_error` — the Responses API's own 5xx, reported in-band.
 * - `rate_limit_exceeded` — a throttle that arrived after the 200.
 * - `overloaded_error` — Anthropic's `error.type` for a 529 reported inside a
 *   stream that had already opened.
 */
export const STREAM_FAILURE_CODES = new Set(['server_is_overloaded', 'server_error', 'rate_limit_exceeded', 'overloaded_error']);

// How much of a stream the peek may hold before releasing it undecided. The
// Codex lifecycle envelopes echo the whole request back, instructions included,
// so `response.created` alone can run to tens of KiB.
const DEFAULT_STREAM_PEEK_BUDGET_BYTES = 256 * 1024;
// How long the peek may hold the headers back. A slow first token is not a
// failure, and a stream that says nothing is released rather than waited on.
const DEFAULT_STREAM_PEEK_HOLD_MS = 10_000;

/**
 * The peek's two bounds. Read per call like the body idle timeout, so a test
 * can shrink them through TEAMCLAUDE_STREAM_PEEK_BUDGET_BYTES and
 * TEAMCLAUDE_STREAM_PEEK_HOLD_MS without reloading the module. Unset, empty or
 * non-positive means the default.
 * @returns {{ budgetBytes: number, holdMs: number }}
 */
export function resolveStreamPeekBounds() {
  const budget = Number(envVar('STREAM_PEEK_BUDGET_BYTES'));
  const hold = Number(envVar('STREAM_PEEK_HOLD_MS'));
  return {
    budgetBytes: budget > 0 ? budget : DEFAULT_STREAM_PEEK_BUDGET_BYTES,
    holdMs: hold > 0 ? hold : DEFAULT_STREAM_PEEK_HOLD_MS,
  };
}

// What the wall clock resolves to when it beats a read.
const STREAM_PEEK_TIMED_OUT = Symbol('stream peek timed out');

/**
 * The failure code a stream event reports, or null when it reports none.
 *
 * Three spellings: `response.failed` carries it under `response.error.code`;
 * the Responses API's `error` event carries it at the top level (`code`), or
 * nested under `error.code` on some backends; an Anthropic `error` event names
 * it by `error.type`.
 * @param {any} data
 * @returns {string|null}
 */
function streamFailureCode(data) {
  const code = data.response?.error?.code ?? data.error?.code ?? data.code ?? data.error?.type;
  return typeof code === 'string' ? code : null;
}

/**
 * @typedef {object} PeekedStream
 * @property {string|null} failureCode the code that decided a hop, or null to release
 * @property {ReadableStream<Uint8Array>} body the bytes already read, then the rest of the same stream
 * @property {() => Promise<void>} cancel drop the stream without relaying it
 */

/**
 * Read the head of an SSE body before its headers reach the client and say
 * whether it reports its own failure.
 *
 * Reads until the first event that is not a lifecycle envelope, or until
 * `budgetBytes` are held or `holdMs` has passed, whichever comes first. The
 * verdict is the failure code when that event is a `response.failed` or
 * `error` naming one of STREAM_FAILURE_CODES, and null for everything else: a
 * delta (output is committed, and there is no retry behind committed output),
 * a request-fault error, an Anthropic `message_start`, a stream that ended,
 * either bound, a read error. Order decides this, not presence.
 *
 * Events are found by the same line scanner the usage parser uses and judged
 * on the parsed event's `type` alone: the lifecycle envelopes echo the whole
 * request back, so text inside `instructions` must never be able to look like
 * an event.
 *
 * The returned body replays what was read and then continues the same stream,
 * so a released peek costs the client nothing. A read the wall clock abandoned
 * is still pending on the reader, and the chunk it resolves with is real: the
 * replay awaits it before reading again rather than dropping it.
 *
 * @param {ReadableStream<Uint8Array>} stream
 * @param {{ budgetBytes?: number, holdMs?: number }} [bounds] defaults from resolveStreamPeekBounds
 * @returns {Promise<PeekedStream>}
 */
export async function peekStreamFailure(stream, bounds = {}) {
  const defaults = resolveStreamPeekBounds();
  const budgetBytes = bounds.budgetBytes ?? defaults.budgetBytes;
  const holdMs = bounds.holdMs ?? defaults.holdMs;
  const reader = stream.getReader();
  /** @type {Uint8Array[]} */
  const chunks = [];
  /** @type {Promise<ReadableStreamReadResult<Uint8Array>>|null} */
  let pending = null;
  let ended = false;
  let held = 0;
  // Mutated by the scanner's callback below, so an object rather than a
  // reassigned binding: the checker cannot see a closure's assignments.
  /** @type {{ decided: boolean, failureCode: string|null }} */
  const verdict = { decided: false, failureCode: null };
  const decoder = new TextDecoder();
  const scanner = createSseLineScanner((/** @type {string} */ line) => {
    if (verdict.decided || !line.startsWith('data: ')) return;
    /** @type {any} */
    let data;
    try { data = JSON.parse(line.slice(6)); } catch { verdict.decided = true; return; }
    const type = typeof data?.type === 'string' ? data.type : '';
    if (SSE_UNCOMMITTED_EVENTS.has(type)) return;
    const code = type === 'response.failed' || type === 'error' ? streamFailureCode(data) : null;
    verdict.decided = true;
    verdict.failureCode = code && STREAM_FAILURE_CODES.has(code) ? code : null;
  });

  const deadline = Date.now() + holdMs;
  try {
    while (!verdict.decided && !ended && held < budgetBytes) {
      const left = deadline - Date.now();
      if (left <= 0) break;
      const read = pending ?? reader.read();
      // Kept if the clock wins below, for the replay to consume first. Its
      // rejection is observed there — or nowhere, once the peek is cancelled.
      read.catch(() => {});
      pending = read;
      /** @type {ReturnType<typeof setTimeout>|undefined} */
      let timer;
      const clock = new Promise((resolve) => { timer = setTimeout(() => resolve(STREAM_PEEK_TIMED_OUT), left); });
      const next = await Promise.race([read, clock]).finally(() => clearTimeout(timer));
      if (next === STREAM_PEEK_TIMED_OUT) break;
      pending = null;
      if (next.done) { ended = true; break; }
      chunks.push(next.value);
      held += next.value.byteLength;
      scanner.push(decoder.decode(next.value, { stream: true }));
    }
  } catch {
    // A read that failed mid-peek: release. The replay's next read reports the
    // same failure to streamResponse, which handles it as it always has.
    pending = null;
  }

  return {
    failureCode: verdict.failureCode,
    body: new ReadableStream({
      start(controller) {
        for (const chunk of chunks) controller.enqueue(chunk);
        if (ended) controller.close();
      },
      async pull(controller) {
        const read = pending ?? reader.read();
        pending = null;
        const { done, value } = await read;
        if (done) controller.close();
        else controller.enqueue(value);
      },
      cancel(reason) { return reader.cancel(reason); },
    }),
    cancel: () => reader.cancel().catch(() => {}),
  };
}

/**
 * The message behind the synthetic 429 when every account that could serve the
 * request is at its concurrency cap.
 *
 * It used to read `All N accounts are at their concurrency cap` with N counting
 * every account of the provider. On 2026-09-25 a 10-account fleet had 7 accounts
 * benched at 98-100% of their weekly quota and 3 holding 3 of 3 slots each, so
 * the operator was told ten accounts were busy and went looking for seven idle
 * ones that did not exist. Counts only the accounts that can serve, names why the
 * others cannot in the reason tokens `/teamclaude/status` publishes as
 * `benchedReason`, and says when a full overflow queue is what refused the wait.
 * @param {AccountManager} accountManager
 * @param {ManagedAccount[]} accounts the provider's candidate accounts
 * @param {{ exclude?: Set<unknown>|null, model?: string|null, advisorModel?: string|null }} context
 * @param {number} retryAfter
 */
export function cappedMessage(accountManager, accounts, { exclude = null, model = null, advisorModel = null }, retryAfter) {
  let available = 0;
  /** @type {Map<string, number>} */
  const others = new Map();
  for (const account of accounts) {
    const reason = exclude && (exclude.has(account) || exclude.has(account.index)) ? 'already tried'
      : accountManager.unavailableReason(account, model, advisorModel);
    if (reason == null) available++;
    else {
      // 'capped' is the operator's budget cap, a different thing from the
      // concurrency cap this message is about.
      const label = reason === 'capped' ? 'budget cap' : reason;
      others.set(label, (others.get(label) || 0) + 1);
    }
  }
  const busy = available === 1 ? 'All 1 available account is at its concurrency cap'
    : `All ${available} available accounts are at their concurrency cap`;
  const queue = accountManager.isQueueFull()
    ? `, and the overflow queue is full (${accountManager.maxQueueDepth} waiting)` : '';
  const benched = [...others.values()].reduce((sum, n) => sum + n, 0);
  const rest = benched
    ? `; the other ${benched} cannot serve ${model || 'this request'} (${[...others].map(([r, n]) => `${r}: ${n}`).join(', ')})`
    : '';
  return `${busy}${queue}${rest}. Retry in ${retryAfter}s.`;
}

// Upstream statuses that are transient and safe to retry. 500/502/503/504 may
// differ by account or edge, so they use the fleet failover below. 529 is
// different: it is Anthropic model capacity, not account health, and Claude Code
// already retries it. Fan-out plus proxy retries plus client retries multiplies
// one turn into hundreds of identical upstream calls and prolongs the incident.
const RETRYABLE_STATUS = new Set([500, 502, 503, 504, 529]);
const OVERLOAD_RETRY_AFTER_MIN_SECONDS = 10;

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
  return { seconds, arm: !((existingUntil ?? 0) > now + seconds * 1000) };
}
// Sleep that also resolves immediately if `signal` aborts — so a client that
// disconnects during an overload backoff doesn't keep its account slot reserved
// for the whole (up to multi-second) wait. Cleans up its timer/listener either way.
/** @param {number} ms @param {AbortSignal|null|undefined} signal @returns {Promise<void>} */
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
/** @template T @param {Promise<T>} promise @param {AbortSignal|null|undefined} signal @returns {Promise<T|void>} */
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
/** @param {string} name @param {number} def */
const envInt = (name, def) => {
  const v = parseInt(process.env[name] || '', 10);
  return Number.isFinite(v) ? v : def;
};
/** @param {unknown} value @returns {number|null} */
function positiveTimeout(value) {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : null;
}

function fetchUpstream(url, options, ctx) {
  const transport = ctx.transport || {};
  if (transport.fetchImpl) return transport.fetchImpl(url, options);
  return upstreamFetch(url, {
    ...options,
    headersTimeoutMs: transport.headersTimeoutMs ?? undefined,
  }, transport.sx, ctx.useSx === true);
}

export async function forwardRequest(req, res, body, accountManager, upstream, retryCount, hooks, reqId, ctx, logDir) {
  const maxRetries = accountManager.accounts.length;
  ctx.logLevel ??= DEFAULT_LOG_LEVEL;
  ctx.logMaxBodyBytes ??= DEFAULT_LOG_MAX_BODY_BYTES;
  if (ctx.useSx == null) ctx.useSx = ctx.transport?.sx?.useByDefault?.() === true;

  // Select account. On a failover retry (a prior account 429'd / 5xx'd / 403'd /
  // 401'd / failed to send for this request) ctx.tried* is non-empty → pick a
  // different account, skipping the ones already tried.
  const excludeForSelect = (ctx.tried429.size || ctx.tried5xx.size || ctx.tried403.size || ctx.tried401.size || ctx.triedSend.size)
    ? new Set([...ctx.tried429, ...ctx.tried5xx, ...ctx.tried403, ...ctx.tried401, ...ctx.triedSend,
      ...(ctx.detour ? ctx.rolledOff || [] : [])])
    : null;
  const restingGen = ctx.held != null ? ctx.restingGen
    : !ctx.pinnedAccount && !ctx.detour
      ? accountManager.observedGeneration(ctx.pinKey, ctx.model) : null;

  if (ctx.pinnedAccount && isSubscriptionAccount(ctx.pinnedAccount)
      && providerOf(ctx.pinnedAccount) !== (ctx.provider || DEFAULT_PROVIDER)) {
    ctx.status = 400;
    ctx.delivered = true;
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ type: 'error', error: { type: 'invalid_request_error',
      message: `Pinned account "${ctx.pinnedAccount.name}" is a ${providerOf(ctx.pinnedAccount)} subscription and cannot serve a ${ctx.provider} request.` } }));
    return;
  }

  // Reserve a per-account concurrency slot. On a 401 same-account refresh-retry
  // the slot is already held (ctx.held set, exclude unchanged) → reuse it.
  // Otherwise acquire a fresh slot, waiting briefly if every available account is
  // at its cap (overflow queue) before giving up with a 429. Releasing this slot
  // before any account-switching retry is the caller's job, via releaseHeld().
  let account;
  if (ctx.held != null) {
    account = ctx.held;
  } else {
    // Clamp the overflow-queue wait by the request's remaining wait budget. This
    // wait is the OTHER silent path, and the larger one: overflowQueueTimeoutMs is
    // 60s in production here (repo default 15s), and forwardRequest recurses once
    // per account on failover, so the queue wait alone can hold a request quiet for
    // minutes. Bounding only the throttle sleep left that untouched — measured
    // after that fix, 4 of 6 probes still returned nothing before the client gave
    // up at 60s, and the two that answered took 28-45s to say the pool was
    // exhausted. The budget has to cover every pre-header wait, not one of them.
    // A capacity wait is not quota exhaustion. In wait-until-free mode it must
    // not inherit the throttle deadline and turn healthy queued work into 429s.
    const acquireWaitMs = ctx.queueTimeoutMs == null || ctx.queueTimeoutMs === Infinity ? null
      : Math.max(0, Math.min(ctx.queueTimeoutMs, remainingWaitBudget(ctx)));
    /** @type {{ rolledOff?: Set<number> }} */
    const decision = {};
    account = await accountManager.acquireAccount(
      excludeForSelect, acquireWaitMs, ctx.abortSignal, ctx.affinityKey,
      {
        model: ctx.model,
        provider: ctx.provider,
        advisorModel: ctx.advisorModel,
        // The session key routing keeps pins and home waits under: the
        // conversation (ctx.pinKey), not the client session that names it.
        sessionId: ctx.pinKey,
        pinnedAccount: ctx.pinnedAccount,
        detour: ctx.detour,
        decision,
        // Only a completion has a cache worth waiting for (see _waitingForHome).
        homeWaitUntil: isCompletionPath(classificationPath(req.url)) ? undefined : null,
      },
    );
    if (decision.rolledOff) {
      ctx.rolledOff ??= new Set();
      for (const index of decision.rolledOff) {
        const rolled = accountManager.accounts[index];
        if (rolled) ctx.rolledOff.add(rolled);
      }
    }
    if (account) {
      ctx.held = account;
      ctx.restingGen = ctx.pinnedAccount ? null : restingGen;
    }
  }
  const releaseHeld = () => {
    if (ctx.held != null) {
      accountManager.releaseAccount(ctx.held);
      ctx.held = null;
    }
  };

  // The client disconnected while this request was queued (acquireAccount was
  // cancelled by the abort signal) — nothing to respond to.
  if (!account && (ctx.abortSignal?.aborted || clientGone(res))) {
    ctx.abandoned = true;
    return;
  }
  if (account && ctx.egressAccountKey !== account.accountIdKey) {
    if (ctx.egressAccountKey != null) ctx.useSx = ctx.transport?.sx?.useByDefault?.() === true;
    ctx.egressAccountKey = account.accountIdKey;
  }
  if (!ctx.sxTriedIdentities) ctx.sxTriedIdentities = new Set();

  if (!account && ctx.entitlementDenied?.size
      && (ctx.pinnedAccount ? ctx.entitlementDenied.has(ctx.pinnedAccount)
        : accountManager.accounts.filter(a =>
          !isSubscriptionAccount(a) || providerOf(a) === (ctx.provider || DEFAULT_PROVIDER))
          .every(a => ctx.entitlementDenied.has(a)))) {
    ctx.status = 502;
    const names = [...ctx.entitlementDenied].map(a => `"${a.name}"`).join(', ');
    const message = ctx.pinnedAccount
      ? `No account served this request. The pinned account ${names} returned OAuth entitlement denial (${OAUTH_ENTITLEMENT_ERROR_CODE}). Choose another eligible account or change its organization's OAuth policy.`
      : `No account served this request. Every configured account returned OAuth entitlement denial (${OAUTH_ENTITLEMENT_ERROR_CODE}): ${names}. Retry after the cooldown or choose another eligible account.`;
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message } }));
    return;
  }

  if (!account && ctx.pinnedAccount) {
    ctx.account = ctx.pinnedAccount.name;
    const capped = accountManager.anyCapped(excludeForSelect, {
      provider: ctx.provider,
      model: ctx.model,
      advisorModel: ctx.advisorModel,
      pinnedAccount: ctx.pinnedAccount,
    });
    const quotaCapped = accountManager.capExceeded(ctx.pinnedAccount, ctx.model)
      || (ctx.advisorModel && accountManager.capExceeded(ctx.pinnedAccount, ctx.advisorModel));
    ctx.status = capped || quotaCapped ? 429 : 503;
    res.writeHead(ctx.status, {
      'Content-Type': 'application/json',
      ...(capped || quotaCapped ? { 'retry-after': String(quotaCapped ? RETRY_AFTER_FALLBACK_SECONDS : CAPPED_RETRY_AFTER_SECONDS) } : {}),
    });
    res.end(JSON.stringify({
      type: 'error',
      error: {
        type: capped || quotaCapped ? 'rate_limit_error' : 'pinned_account_unavailable_error',
        message: quotaCapped
          ? `Pinned account "${ctx.pinnedAccount.name}" has reached its usage cap.`
          : capped
          ? `Pinned account "${ctx.pinnedAccount.name}" is busy. Retry shortly.`
          : `Pinned account "${ctx.pinnedAccount.name}" is unavailable.`,
      },
    }));
    return;
  }
  if (!account) {
    ctx.account = '(none available)';
    const accts = accountManager.accounts.filter(a =>
      !isSubscriptionAccount(a) || providerOf(a) === (ctx.provider || DEFAULT_PROVIDER));
    // If every account is in auth-error state, this is an authentication
    // problem (revoked/expired tokens needing re-login), not a rate limit —
    // return 401 so the client surfaces it instead of pointlessly backing off.
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
    // Every candidate's credential was rejected (401) during THIS request.
    // Waiting will not help — the accounts need attention, not a retry — so say
    // so plainly rather than reporting a rate limit, and not with a 401 either:
    // Claude Code reads that as its own login having died. Only when the
    // rejections are the whole story: if some accounts are merely out of quota,
    // the paths below still wait for or report the reset. After the all-error
    // check above: an account left needing a re-login is that case, and this one
    // is for rejections that may still clear on their own (an API key's
    // cooldown, an OAuth account that holds a refresh token).
    if (accts.length > 0 && accts.every(a => ctx.tried401.has(a))) {
      ctx.status = 502;
      const names = [...ctx.tried401].map(a => `"${a.name}"`).join(', ');
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        type: 'error',
        error: {
          type: 'proxy_error',
          message: `No account served this request. Upstream rejected the credential of every account tried (${names}). Check the account, then re-add it with: teamclaude login`,
        },
      }));
      return;
    }

    // A Codex pool that is dry because its weekly windows are spent is the one
    // exhaustion here that a free reset credit can undo — and THIS is where it
    // has to be offered. On a fully spent pool selection refuses the request
    // before an account is chosen, so nothing is ever sent and nothing comes
    // back 429: hooking the refusal states the policy's own precondition
    // ("every Codex account is out") directly. Ahead of the throttle wait below,
    // because the redemption IS the recovery for this request.
    //
    // Only the accounts a redemption would actually return to service: an
    // operator's own decision (disabled, capped) and a structural refusal
    // (entitlement, an error state needing a re-login) survive a cleared quota
    // window, and an account this request has already tried stays excluded from
    // the re-selection whatever its windows then say. A credit spent on any of
    // those buys this request nothing.
    const resettable = hooks.redeemCodexResetForPool && !ctx.resetRedeemTried
      && (ctx.provider || DEFAULT_PROVIDER) === 'codex'
      ? accountManager.accounts.filter(a =>
        providerOf(a) === 'codex' && !excludeForSelect?.has(a)
        && RESET_CLEARS.has(accountManager.unavailableReason(a, ctx.model) ?? ''))
      : [];
    if (resettable.length) {
      // Once per request, whatever it decides: a redemption that reports success
      // but leaves the account unselectable (upstream not yet caught up with its
      // own reset) must cost this request one re-selection, not a loop of them.
      ctx.resetRedeemTried = true;
      let redeemed = false;
      try {
        redeemed = !!(await hooks.redeemCodexResetForPool(resettable))?.redeemed;
      } catch { /* a failed redemption must leave the refusal exactly as it was */ }
      if (redeemed) {
        // No upstream attempt was made, so this costs no retry from the budget:
        // re-select against the account whose windows were just cleared.
        if (ctx.abortSignal?.aborted || clientGone(res)) { ctx.abandoned = true; return; }
        return forwardRequest(req, res, body, accountManager, upstream, retryCount, hooks, reqId, ctx, logDir);
      }
    }

    const waitingUntil = accts
      .filter(a => a.status === 'throttled' && a.rateLimitedUntil > Date.now())
      .reduce((soonest, a) => Math.min(soonest, a.rateLimitedUntil), Infinity);
    const holdMs = ctx.transport?.holdMs || 0;
    if (holdMs > 0 && ctx.holdUntil == null) ctx.holdUntil = Date.now() + holdMs;
    const holdRemaining = ctx.holdUntil == null ? 0 : ctx.holdUntil - Date.now();
    const waitBudgetLeft = remainingWaitBudget(ctx);
    if ((Number.isFinite(waitingUntil) || holdRemaining > 0) && waitBudgetLeft > 0
        && (retryCount < maxRetries || holdRemaining > 0)) {
      // Clamp by the budget as well as by the deadline. When the budget is what
      // ran out, the recursion below re-enters with waitBudgetLeft <= 0 and falls
      // through to the 429 under it, which already computes the right retry-after.
      await sleepOrAbort(Math.min(
        Number.isFinite(waitingUntil) ? waitingUntil - Date.now() + THROTTLE_WAKE_MARGIN_MS : 60_000,
        holdRemaining > 0 ? holdRemaining : Infinity,
        waitBudgetLeft,
      ), ctx.abortSignal);
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
      provider: ctx.provider,
      model: ctx.model,
      advisorModel: ctx.advisorModel,
    });
    // Measured once and used twice: the accounts the message counts and the
    // windows the retry-after is read from have to be the same accounts, or the
    // two halves of one sentence contradict each other. Read off the windows that
    // actually block each candidate (computeRetryAfter), so a pool whose quota is
    // spent answers with its real reset rather than a 60s default the client would
    // obey forever. A merely capped fleet keeps its short wait: a slot frees as
    // soon as any in-flight request finishes.
    const candidates = candidateAccounts(accountManager, ctx.model, ctx.provider);
    const retryAfter = merelyCapped ? CAPPED_RETRY_AFTER_SECONDS
      : computeRetryAfter(accountManager, candidates, ctx.model);
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
        // share either string, for the same reason those two do not share one. A
        // rejected credential (401, failed over rather than relayed) is named the
        // same way: re-login, not wait.
        message: ctx.tried403.size
          ? `Upstream refused ${ctx.tried403.size} of ${accts.length} accounts (${[...ctx.tried403].map(a => a.name).join(', ')}) and the rest are unavailable. Retry in ${formatWait(retryAfter)}.`
          : ctx.tried401.size
            ? `Upstream rejected the credential of ${ctx.tried401.size} of ${accts.length} accounts (${[...ctx.tried401].map(a => a.name).join(', ')}) and the rest are unavailable. Retry in ${formatWait(retryAfter)}.`
            : merelyCapped
              ? cappedMessage(accountManager, accts, { exclude: excludeForSelect, model: ctx.model, advisorModel: ctx.advisorModel }, retryAfter)
              : exhaustedMessage(candidates, ctx.model, retryAfter),
      },
    }));
    return;
  }

  // Track which account handles this request. Only a completion pins: its cache
  // is what the pin keeps warm, and a count_tokens sent wherever there was room
  // would otherwise drag the session's next completion to an account without it.
  ctx.account = account.name;
  // Pinned per conversation (ctx.pinKey), for the model's weekly bucket, and kept
  // "active" in the running-sessions readout; passive when distribution is off.
  if (isCompletionPath(classificationPath(req.url))) accountManager.recordSession(ctx.pinKey, account, ctx.model);
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
  // The refresh just found this account's routing proxy down (it arms the
  // cooldown). The forward would leave by the same proxy and fail the same
  // way, up to a full connect timeout later, so move on now. A pin still
  // targets exactly the account it names. Skipped for this request only, like a
  // send failure: the cooldown the refresh armed is what keeps later requests off.
  if (!ctx.pinnedAccount && retryCount < maxRetries && accountManager.isRoutingDown(account.index)) {
    ctx.triedSend.add(account);
    releaseHeld(); // failing over to a different account
    return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
  }

  // Build upstream request headers
  /** @type {import('node:http').OutgoingHttpHeaders} */
  const headers = {};
  for (const [key, value] of Object.entries(req.headers)) {
    const lk = key.toLowerCase();
    // HTTP/2 pseudo-headers (:method, :path, :authority, :scheme) live in
    // req.headers on the h2 server path; fetch rejects `:`-prefixed names.
    if (lk.startsWith(':')) continue;
    if (HOP_BY_HOP_HEADERS.has(lk)) continue;
    // Both credential headers are dropped, not just the one the account will
    // set: applyAuthHeaders overwrites `authorization` only for bearer-token
    // accounts, so on an API-key account the CLIENT's own
    // `Authorization: Bearer <its Anthropic OAuth token>` would otherwise ride
    // along untouched — to whatever host that account's `upstream` names.
    if (lk === 'x-api-key' || lk === 'authorization') continue;
    // Strip accept-encoding: Node fetch auto-decompresses, which would
    // mismatch the Content-Encoding header we forward to the client
    if (lk === 'accept-encoding') continue;
    // Headers configured as usage dimensions are addressed to this proxy and
    // carry the operator's own labels (project, branch, team). They are
    // consumed here, so they do not travel upstream.
    if (ctx.stripHeaders?.has(lk)) continue;
    headers[key] = value;
  }

  // Credential presentation is provider-specific: Anthropic OAuth and Codex
  // both use a bearer token, Anthropic API keys use x-api-key, and Codex also
  // needs ChatGPT-Account-Id to scope the token to one account.
  applyAuthHeaders(headers, account);

  const upstreamUrl = `${upstreamFor(account, upstream)}${req.url}`;
  const method = req.method;
  let outboundBody = rewriteRequestBody(body, account, req.url, req.headers['content-type']);
  outboundBody = ctx.overloadFallbackAttempted
    ? setRequestModel(outboundBody, ctx.overloadFallbackModel)
    : outboundBody;
  // The forwarded content-length MUST describe the bytes this proxy actually
  // sends, not the bytes the client sent us. undici enforces that and aborts a
  // disagreeing request with UND_ERR_REQ_CONTENT_LENGTH_MISMATCH, surfaced to the
  // operator as a bare TypeError("fetch failed") and to Claude Code as a 503 —
  // per-request and seemingly random, since only some turns carry a body whose
  // length the client's own header disagrees with. The proxy buffers the whole
  // body, so it always knows the true length: derive the header unconditionally.
  // The old form updated it only when a rewrite changed the buffer, leaving a
  // stale client-supplied length in place on every other request.
  const bodylessMethod = ['GET', 'HEAD'].includes(method);
  const inboundContentLength = headers['content-length'];
  if (bodylessMethod) {
    delete headers['content-length'];
  } else {
    headers['content-length'] = String(outboundBody.length);
    if (inboundContentLength != null && String(inboundContentLength) !== headers['content-length']) {
      console.log(`[TeamClaude] content-length corrected ${inboundContentLength} -> ${outboundBody.length} (account "${account.name}")`);
    }
  }

  // An upstream that keeps no thread state would receive only this turn's delta
  // and answer it as the whole conversation. Refusing makes the client resend
  // the full history (see refusesThreadContinue). Placed before admit() so the
  // early return holds no concurrency slot, and after recordSession so the
  // resend that follows lands on this same account and reuses its cache.
  if (refusesThreadContinue(body, account, req.url, upstream, ctx.fleetMessageThreads) && !res.headersSent && !clientGone(res)) {
    ctx.status = 400;
    ctx.delivered = true;   // a 4xx IS an answer — see answeredStatus
    // Said once per account: the client stops sending threads for that model
    // after the first refusal, so a line per refusal would be a line per model,
    // not per turn — and an operator watching tokens rise needs to find this.
    // The flag lives on the account so a reload clears it with the setting it
    // reports on (see syncAccountsFromDisk).
    if (!account.threadRefusalReported) {
      account.threadRefusalReported = true;
      console.error(`[TeamClaude] ${safeLine(account.name, 64)}: refusing message-thread continues (this upstream keeps no thread state; set "messageThreads": true ${account.upstream ? 'on the account' : 'at the top level of the config'} if it does)`);
    }
    res.writeHead(400, { 'Content-Type': 'application/json', 'x-should-retry': 'false' });
    res.end(JSON.stringify({
      type: 'error',
      error: {
        type: 'invalid_request_error',
        message: 'thread: this upstream does not keep thread state; resend the conversation',
        // Read by the client as "stop threading this model for the session"
        // rather than "retry this one turn", which is the difference between
        // one refusal and one per turn.
        details: { error_code: 'thread_unsupported_request' },
      },
    }));
    return;
  }

  // Every rewrite below runs inside rewriteRequestBody (exported for tests);
  // Content-Length is refreshed below because the body can shrink.
  const sendBody = outboundBody;
  // If the body changed length (sanitize, model rewrite, or field strip), update
  // Content-Length so the upstream doesn't receive a mismatched framing and
  // truncate or stall.
  if (!bodylessMethod && sendBody !== body) headers['content-length'] = String(sendBody.length);

  // Streaming request log, opened lazily on the first terminal outcome (a
  // pure-429-then-retry attempt writes no file, matching prior behavior). The
  // request head+body are written once, just before the response is logged.
  /** @type {ReturnType<typeof openRequestLog>|null} */
  let log = null;
  let reqLogged = false;
  const getLog = () => (logDir && ctx.logLevel !== 'off'
    ? (log ||= openRequestLog(logDir, reqId, { level: ctx.logLevel, maxBodyBytes: ctx.logMaxBodyBytes }))
    : null);
  const logRequestHead = () => {
    const l = getLog();
    if (!l || reqLogged) return;
    reqLogged = true;
    const safeHeaders = { ...headers };
    if (safeHeaders['x-api-key']) safeHeaders['x-api-key'] = String(safeHeaders['x-api-key']).slice(0, 15) + '...';
    if (safeHeaders['authorization']) safeHeaders['authorization'] = String(safeHeaders['authorization']).slice(0, 20) + '...';
    l.write(`=== REQUEST (account: ${account.name}, retry: ${retryCount}) ===\n${method} ${upstreamUrl}\n${formatHeaders(safeHeaders)}`);
    // The body that went upstream, not the one the client sent: they differ
    // exactly when the proxy rewrote it (tool-pair sanitising, account_uuid,
    // modelMap, cache_control strip), which is the first thing to check when
    // upstream rejects it.
    if (sendBody !== body) l.write(`\n(body rewritten by the proxy before sending: ${body.length} → ${sendBody.length} bytes; the upstream copy follows)`);
    if (sendBody.length > 0) l.body('REQUEST BODY', sendBody, req.headers['content-type']);
  };

  const logAttempt = section => {
    logRequestHead();
    getLog()?.write(`\n\n${section}`);
  };

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
      // This account's own egress proxy, when the operator pinned one
      // (accounts[].routing): every attempt for the account — this one, and
      // any failover that lands back on it — leaves through that proxy, and
      // sx's per-attempt policy does not apply to it. Null for every other
      // account, where the fleet path is unchanged.
      routing: account.routing || null,
      // How long the head may stay silent before the socket is called dead,
      // when the operator has set no override. It is the account's provider
      // that knows: Codex reasons with the head held open, so its first byte
      // arrives minutes in and a two-minute deadline would cut a healthy
      // request — and the client would only re-send and reason again.
      defaultHeadersTimeoutMs: defaultHeadersTimeoutFor(account),
    }, ctx);

    // Extract rate limit headers. Anthropic states its quota under
    // `anthropic-ratelimit-*` and Codex under `x-codex-*`; `updateQuota` picks
    // the parser by provider, so keeping only Anthropic's prefix handed a Codex
    // account an empty object and its quota never landed.
    /** @type {Record<string, string>} */
    const rateLimitHeaders = {};
    for (const [key, value] of upstreamRes.headers.entries()) {
      if (key.startsWith('anthropic-ratelimit-') || key.startsWith('x-codex-')) {
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
    // A spent Codex window says the same thing as a rejected unified status, in
    // the only vocabulary that backend has: a used-percent at its limit. Read
    // through the same parser the quota sweep uses, so every family is covered —
    // a subscription states its only 5-hour window inside a NAMED one. Without
    // this a Codex 429 classified as a transient throttle: the account was never
    // held, the pause lapsed, and the spent subscription was selected again.
    // Only the account-wide windows are a quota rejection of the account. A named
    // family's weekly bucket is model-scoped, like Anthropic's `7d_oi`: the account
    // still serves every other model, so this request moves on and the account
    // is left alone.
    const spentCodexWindows = upstreamRes.status === 429 ? codexSpentWindows(rateLimitHeaders) : [];
    const response429 = upstreamRes.status !== 429 ? null
      : spentCodexWindows.some(isAccountWideCodexWindow) ? 'account-quota'
        : spentCodexWindows.length ? 'model-quota'
          : classify429(rateLimitHeaders, {
            model: ctx.model,
            advisorModel: ctx.advisorModel,
            switchThreshold: accountManager.switchThreshold,
          });
    accountManager.updateQuota(account, rateLimitHeaders, ctx.model);

    // Any response at all came back through the account's routing proxy.
    accountManager.clearRoutingFailed(account.index);

    // And a response that is not an error is proof its API key works: the 401
    // cooldown and the count behind its length start over (#473). Only that —
    // a 429 or a 5xx says nothing about the key either way.
    if (upstreamRes.status < 400) accountManager.clearCredentialRejected(account.index);

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
      const responseBody = await readErrorBody(upstreamRes.body);
      if (account.type === 'oauth' && responseBody && isOAuthEntitlementDenied(responseBody)) {
        accountManager.markEntitlementDenied(account);
        (ctx.entitlementDenied ??= new Set()).add(account);
        ctx.tried403.add(account);
        releaseHeld();
        return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
      }

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
        logAttempt(`=== RESPONSE 403 — refused, strike ${strikes}, cooling down ${cool}s ===\n${formatHeaders(upstreamRes.headers)}`);
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

    // 401 = the credential we injected was rejected. For an OAuth account holding
    // a refresh token, force one refresh and retry the same account (the token
    // may be stale but still refreshable). Only a refresh that did not fail earns
    // that retry: the dead-refresh-token guard answers ok:false without asking
    // upstream at all (the token was already rejected), and a failed refresh
    // leaves the same access token in place, so either retry would carry the
    // credential upstream just refused. A refresh upstream REJECTS parks the
    // account inside ensureTokenFresh (refresh-caused, so new credentials heal it)
    // and arms that guard; that park is the refresh's verdict, not this 401's.
    if (upstreamRes.status === 401) {
      await upstreamRes.body?.cancel();

      if (account.type === 'oauth' && account.refreshToken
          && !ctx.authRetried.has(account)
          && retryCount < maxRetries && !res.destroyed) {
        ctx.authRetried.add(account);
        console.log(`[TeamClaude] 401 on "${account.name}" — forcing token refresh and retrying`);
        const refresh = await raceAbort(accountManager.ensureTokenFresh(account, true), ctx.abortSignal);
        if (res.destroyed || ctx.abortSignal?.aborted) return; // client gone during refresh
        if (refresh?.ok !== false && account.status !== 'error') {
          if (logDir) {
            logAttempt(`=== RESPONSE 401 — forced token refresh, retrying ===`);
          }
          return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
        }
      }

      // A 401 the refresh above did not take, or one that came BACK after it.
      // Like the 403 above, the client must not see it: Claude Code reads a 401
      // as its own login having died. So the account is skipped for the rest of
      // THIS request and the request fails over. It leaves rotation only when
      // nothing here can repair it: an OAuth account with no refresh token, for
      // good, and an API key for a cooldown that lengthens while it keeps being
      // rejected — a gateway answers 401 with a good key when its own upstream is
      // down (see markCredentialRejected). An account that DOES hold a refresh
      // token only fails over: its second 401 can be stale news — a forced
      // refresh is suppressed for a short floor after a successful one, so the
      // retry may have gone out on the same token — and parking it on that took
      // a healthy account out until a restart. Bounded without the retry budget
      // because every pass adds its account to tried401, which selection skips;
      // the no-account branch answers once none is left.
      if (account.type !== 'oauth' || !account.refreshToken) {
        accountManager.markCredentialRejected(account.index, account.type !== 'oauth'
          ? 'upstream rejected its API key (401)'
          : 'upstream rejected its token (401) and it has no refresh token');
      }
      console.error(`[TeamClaude] 401 on "${safeLine(account.name, 64)}"; failing over to another account`);
      if (logDir) {
        logAttempt(`=== RESPONSE 401 — credential rejected, failing over ===\n${formatHeaders(upstreamRes.headers)}`);
      }
      if (res.destroyed) return;
      ctx.tried401.add(account);
      releaseHeld(); // skip this account for this request; fail over to another
      return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
    }

    if (upstreamRes.status === 429) {
      const requestScoped = upstreamRes.headers.get('retry-after') == null
        && Object.keys(rateLimitHeaders).length === 0;
      if (requestScoped) {
        const raw = await readErrorBody(upstreamRes.body);
        let message = 'Upstream refused this request (429) without rate-limit headers.';
        try { message = JSON.parse(raw?.toString('utf8'))?.error?.message || message; } catch { /* bounded diagnostic only */ }
        ctx.tried429.add(account);
        if (!ctx.requestScopedHopped && !ctx.pinnedAccount && retryCount < maxRetries
            && accountManager.anyUsable(ctx.tried429, ctx)) {
          ctx.requestScopedHopped = true;
          ctx.detour = true;
          releaseHeld();
          return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
        }
        // One short retry per request, whichever side of the hop spends it. With
        // no sibling it covers a momentary blip. After the hop it covers what was
        // measured on a live fleet: a headerless 429 that follows the request onto
        // a second account (about once every 8 minutes on Fable traffic), which
        // the client's own retry usually clears — sent straight back, Claude Code
        // sat on "will retry in 2m 38s" with nothing in the transcript to explain
        // it. The first account stays excluded: the limit is scoped to neither
        // account, and going back would only repeat what the hop established.
        // This request may retry the same healthy account, but must compete for
        // capacity again after its backoff rather than reserve a slot.
        // TEAMCLAUDE_HEADERLESS_429_RETRY_DELAY_MS moves the wait; 0 turns the
        // retry off and the 429 goes back at once.
        const retryDelayMs = resolveHeaderless429RetryDelayMs();
        if (retryDelayMs > 0 && !ctx.requestScopedRetried && retryCount < maxRetries
            && !res.headersSent && !clientGone(res) && !ctx.abortSignal?.aborted) {
          ctx.requestScopedRetried = true;
          console.log(`[TeamClaude] 429 ${ctx.requestScopedHopped ? 'followed the request onto' : 'on'} "${account.name}" with no rate-limit headers — retrying once in ${retryDelayMs}ms (${safeLine(message)})`);
          ctx.tried429.delete(account);
          releaseHeld();
          await sleepOrAbort(retryDelayMs, ctx.abortSignal);
          if (ctx.abortSignal?.aborted || res.destroyed) return;
          return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
        }
        ctx.status = 429;
        // A reply already on the wire stands (#431): writing a second head would throw.
        if (!res.headersSent && !clientGone(res)) {
          res.writeHead(429, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ type: 'error', error: { type: 'rate_limit_error', message } }));
        }
        return;
      }
      const retryAfter = parseRetryAfter(upstreamRes.headers.get('retry-after'));
      await upstreamRes.body?.cancel();

      if (response429 === 'account-quota') {
        ctx.terminalQuotaExhaustion = true;
        // Name the spent window when the headers said which: "which one" is the
        // first thing an operator asks of a rejection, and a 5-hour window reads
        // very differently from a weekly one.
        if (spentCodexWindows.length) {
          console.log(`[TeamClaude] Quota rejection (429) on "${account.name}" (${safeLine(spentCodexWindows.join(', '), 80)} spent) — switching account`);
        }
        accountManager.markRateLimited(account, retryAfter);
        if (res.destroyed) return;
        if (retryCount >= maxRetries) {
          ctx.status = 429;
          const ra = computeRetryAfter(accountManager, candidateAccounts(accountManager, ctx.model, ctx.provider), ctx.model);
          if (!res.headersSent) {
            res.writeHead(429, { 'Content-Type': 'application/json', 'retry-after': String(ra) });
            res.end(JSON.stringify({
              type: 'error',
              error: { type: 'rate_limit_error', message: `All accounts throttled. Retry in ${formatWait(ra)}.` },
            }));
          }
          return;
        }
        releaseHeld();
        return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
      }

      if (response429 === 'model-quota') {
        if (spentCodexWindows.length) {
          console.log(`[TeamClaude] ${safeLine(spentCodexWindows.join(', '), 80)} spent on "${account.name}" — switching account for this request`);
        }
        ctx.tried429.add(account);
        const excluded = new Set(ctx.tried429);
        if (!res.destroyed && retryCount < maxRetries
            && (accountManager.anyUsable(excluded, ctx) || accountManager.anyCapped(excluded, ctx))) {
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

      // sx.org fresh-IP retry — never for an account with its own routing. It
      // leaves through its own proxy on every attempt (upstreamFetch ranks
      // `routing` above sx), so this 429 was earned by ITS exit address: an "sx
      // retry" would re-send at once through the very proxy just refused, and
      // noting the limit would push other accounts onto metered sx.org over a
      // limit none of them share.
      if (!account.routing && !ctx.useSx && ctx.transport?.sx?.useOn429?.()
          && !ctx.sxTriedIdentities.has(account.accountIdKey)) {
        ctx.sxTriedIdentities.add(account.accountIdKey);
        ctx.transport.sx.noteRateLimited?.(retryAfter);
        ctx.useSx = true;
        console.log(`[TeamClaude] 429 on "${account.name}" — retrying via sx.org (fresh egress IP)`);
        return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
      }

      accountManager.pauseAccount(account, retryAfter);
      ctx.tried429.add(account);
      ctx.detour = true;
      const excluded = new Set(ctx.tried429);
      if (!res.destroyed && retryCount < maxRetries
          && (accountManager.anyUsable(excluded, ctx) || accountManager.anyCapped(excluded, ctx))) {
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

    // Handle retryable upstream 5xx. A 529 is shared model capacity and takes
    // the no-fanout branch below. Other server errors may be account-local:
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

      // A 529 is global model capacity, not an account-specific failure. Do not
      // fan it out across accounts and do not nest an internal retry ladder under
      // Claude Code's own retry ladder. A live incident showed one 120-second
      // client turn producing 118 upstream calls through that multiplication.
      // Preserve a longer upstream deadline, but reject its common 1-second hint:
      // it is too short once many clients are already retrying the same model.
      if (code === 529) {
        if (ctx.overloadFallbackModel && !ctx.overloadFallbackAttempted && !res.destroyed) {
          ctx.overloadFallbackAttempted = true;
          console.log(`[TeamClaude] 529 on "${account.name}" for "${ctx.model}" — retrying once as "${ctx.overloadFallbackModel}"`);
          if (logDir) {
            logAttempt(`=== RESPONSE 529 — retrying once with fallback model ${ctx.overloadFallbackModel} ===\n${formatHeaders(upstreamRes.headers)}`);
          }
          return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
        }
        const retryAfter = Math.max(
          OVERLOAD_RETRY_AFTER_MIN_SECONDS,
          parseRetryAfter(upstreamRes.headers.get('retry-after')),
        );
        console.log(`[TeamClaude] 529 on "${account.name}" — model capacity overloaded, passing through with ${retryAfter}s retry-after`);
        ctx.status = code;
        if (logDir) {
          logAttempt(`=== RESPONSE 529 — model capacity overloaded, no account fan-out, retry after ${retryAfter}s ===\n${formatHeaders(upstreamRes.headers)}`);
        }
        if (!res.destroyed && !res.headersSent) {
          res.writeHead(code, {
            'Content-Type': 'application/json',
            'retry-after': String(retryAfter),
          });
          res.end(JSON.stringify({
            type: 'error',
            error: { type: 'overloaded_error', message: `Upstream overloaded (HTTP 529). Retry in ${retryAfter}s.` },
          }));
        }
        return;
      }

      const maxOverload = Math.max(0, envInt('TEAMCLAUDE_OVERLOAD_RETRIES', 6));
      const backoffBase = Math.max(50, envInt('TEAMCLAUDE_OVERLOAD_BACKOFF_BASE_MS', 1000));
      const backoffCap = Math.max(backoffBase, envInt('TEAMCLAUDE_OVERLOAD_BACKOFF_CAP_MS', 10000));

      // (1) Per-request failover to an account not yet 5xx'd (or 429'd) this request.
      ctx.tried5xx.add(account);
      ctx.detour = true;
      const exclude5xx = new Set([...ctx.tried429, ...ctx.tried5xx]);
      if (!res.destroyed && retryCount < maxRetries
          && (accountManager.anyUsable(exclude5xx, ctx) || accountManager.anyCapped(exclude5xx, ctx))) {
        console.log(`[TeamClaude] ${code} on "${account.name}" — switching account for this request`);
        if (logDir) {
          logAttempt(`=== RESPONSE ${code} — transient upstream 5xx, switching account ===\n${formatHeaders(upstreamRes.headers)}`);
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
          logAttempt(`=== RESPONSE ${code} — all ${tried} eligible account(s) overloaded, backoff ${waitMs}ms (retry ${ctx.overloadRetries}/${maxOverload}) ===`);
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
        logAttempt(`=== RESPONSE ${code} — overload persisted after ${ctx.overloadRetries} backoffs, passed through ===\n${formatHeaders(upstreamRes.headers)}`);
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

    // The ChatGPT backend answers a Codex Responses stream with no Content-Type
    // at all (issue #456). Keyed on the header alone, such a reply took the
    // buffered branch: the client saw nothing until the turn was over, and the
    // usage booking, which lives on the streaming branch, never ran. A headerless
    // success to a request that asked for a stream is relayed as one, and told
    // so (when the response headers are built below), since the client keys on
    // the same header. Computed here, before the peek, because the peek keys on
    // the same reading — a headerless Codex stream is exactly where the
    // in-band refusal arrives — and reused by the relay after it.
    let contentType = upstreamRes.headers.get('content-type') || '';
    const streamAssumed = !contentType && upstreamRes.status < 400 && ctx.streamRequested;
    if (streamAssumed) contentType = 'text/event-stream';
    const isStreaming = contentType.includes('text/event-stream');
    // The body the relay reads: the upstream's own, or, after a released peek,
    // the same bytes replayed ahead of the rest of the same stream.
    let upstreamBody = upstreamRes.body;

    // The 5xx failover above never sees "the selected model is at capacity": the
    // Responses API answers it with a 200, opens the stream, and reports the
    // refusal as an event in the body before any output (see peekStreamFailure).
    // Same failover, same budget, same reason — a second account refusing the
    // same way is the provider talking, not the account — keyed on the first
    // decisive event instead of the status, and at most once per request. A
    // sibling has to exist before the head is held, so a request with nowhere to
    // fail over to is never held for nothing.
    if (isStreaming && upstreamRes.status < 400 && upstreamBody && !res.headersSent
        && !ctx.streamFailureHopped && retryCount < maxRetries) {
      const excludeStream = new Set([...(excludeForSelect || []), account]);
      const siblingLeft = () => accountManager.anyUsable(excludeStream, ctx)
        || accountManager.anyCapped(excludeStream, ctx);
      if (siblingLeft()) {
        const peeked = await peekStreamFailure(upstreamBody);
        upstreamBody = peeked.body;
        if (peeked.failureCode && siblingLeft()) {
          await peeked.cancel();
          ctx.streamFailureHopped = true;
          ctx.tried5xx.add(account);
          ctx.detour = true;
          console.log(`[TeamClaude] Stream failed inside a ${upstreamRes.status} on "${account.name}" (${peeked.failureCode}) — switching account for this request`);
          if (logDir) {
            logAttempt(`=== RESPONSE ${upstreamRes.status} — stream reported ${peeked.failureCode} before any output, switching account ===\n${formatHeaders(upstreamRes.headers)}`);
          }
          if (res.destroyed) return;
          releaseHeld(); // free this account's slot before trying another
          return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
        }
        // The hold was real time, and the client may have left during it.
        if (clientGone(res)) { await peeked.cancel(); ctx.abandoned = true; return; }
      }
    }

    logRequestHead();
    getLog()?.write(`\n\n=== RESPONSE ${upstreamRes.status} ===\n${formatHeaders(upstreamRes.headers)}`);

    ctx.status = upstreamRes.status;

    // Build response headers (skip hop-by-hop and encoding headers)
    /** @type {Record<string, string>} */
    const responseHeaders = {};
    for (const [key, value] of upstreamRes.headers.entries()) {
      if (CONNECTION_SPECIFIC_HEADERS.has(key)) continue;
      // Strip content-encoding/content-length since fetch may auto-decompress
      if (key === 'content-encoding' || key === 'content-length') continue;
      // Per-org billing state, dropped when stripOverageHeaders is on (see
      // isOverageHeader); updateQuota above already saw the full header set.
      if (ctx.stripOverage === true && isOverageHeader(key)) continue;
      responseHeaders[key] = value;
    }

    // A headerless stream is told it is one (see `streamAssumed` above).
    if (streamAssumed) responseHeaders['content-type'] = contentType;

    res.writeHead(upstreamRes.status, responseHeaders);

    if (upstreamRes.status < 400) {
      accountManager.confirmStay(account, ctx.restingGen, ctx.pinKey, ctx.provider);
    }
    if (!upstreamBody) {
      const l = getLog();
      if (l) { l.body('RESPONSE BODY', null, undefined); l.end(); }
      res.end();
      ctx.delivered = answeredStatus(upstreamRes.status);
      return;
    }

    if (isStreaming) {
      // Stream each chunk straight to the log as it is relayed — never hold the
      // whole (potentially ~1M-token) SSE body in memory.
      const l = getLog();
      const bw = l ? l.bodyWriter('RESPONSE BODY (streamed)', contentType) : null;
      try {
        await streamResponse(upstreamBody, res, account, accountManager, bw, ctx.onUsage, ctx.pinKey, ctx.model, ctx.transport?.bodyTimeoutMs);
        // Reached only when the stream completed. A stream that dies upstream
        // throws out of streamResponse, so it never marks itself delivered —
        // which is the failure the token counters cannot see, since a stream
        // that emitted message_start has already recorded a usage report.
        if (clientGone(res)) ctx.abandoned = true;
        else ctx.delivered = answeredStatus(upstreamRes.status);
      } finally {
        // Also on the failure path: without the note a capped body reads as a
        // stream that simply stopped, which is the other thing that happens here.
        bw?.end();
      }
      l?.end();
    } else {
      const buf = Buffer.from(await upstreamRes.arrayBuffer());
      extractUsageFromBody(buf, account, accountManager, ctx.onUsage, ctx.pinKey, ctx.model);
      const l = getLog();
      if (l) { l.body('RESPONSE BODY', buf, contentType); l.end(); }
      res.end(buf);
      ctx.delivered = answeredStatus(upstreamRes.status);
    }
  } catch (err) {
    // Client disconnected → we aborted the upstream fetch (ctx.abortSignal). This
    // is not the account's fault: don't mark it 'error' or fail over (the client
    // is gone). Just unwind — the outer finally releases the slot / inFlightProxied.
    if (ctx.abortSignal?.aborted || err?.name === 'AbortError' || err?.code === 'ABORT_ERR' || res.destroyed) {
      ctx.abandoned = ctx.abortSignal?.aborted === true && !ctx.proxyClosed;
      if (!res.writableEnded) res.destroy();
      return;
    }

    // The account's own routing proxy failed, not the upstream: hold the account
    // out of rotation briefly so the requests behind this one do not each pay the
    // same connect failure. isTransientUpstreamError reads it as not transient, so
    // this request fails over below — skipped for this request, never parked.
    if (isRoutingFailure(err)) {
      const until = accountManager.markRoutingFailed(account.index);
      const hold = until ? `; out of rotation for ${Math.max(1, Math.round((until - Date.now()) / 1000))}s` : '';
      // err.message, not the cause chain: the chain ends at the bare socket
      // error, which does not say a routing proxy was involved.
      console.error(`[TeamClaude] Routing proxy failed for account "${safeLine(account.name, 64)}" (${describeRouting(account.routing) || 'routing'}): ${safeLine(err instanceof Error ? err.message : String(err), 300)}${hold}`);
    } else console.error(`[TeamClaude] Upstream error (account "${account.name}"):`, describeErrorChain(err));

    if (err?.code === 'TEAMCLAUDE_UPSTREAM_OVERLOADED') {
      ctx.status = 503;
      ctx.account = '(upstream queue full)';
      if (!res.headersSent && !clientGone(res)) {
        res.writeHead(503, { 'Content-Type': 'application/json', 'retry-after': '1' });
        res.end(JSON.stringify({ type: 'error', error: { type: 'overloaded_error',
          message: 'Proxy upstream queue is full; retry shortly.' } }));
      }
      return;
    }

    if (logDir) {
      logAttempt(`=== ERROR ===\n${err.stack || err.message}`);
    }

    const errCode = rootErrorCode(err);
    const hostOf = value => { try { return new URL(value).hostname; } catch { return value; } };
    const otherHostAvailable = !ctx.pinnedAccount && accountManager.accounts.some(a =>
      a !== account && !excludeForSelect?.has(a)
      && hostOf(upstreamFor(a, upstream)) !== hostOf(upstreamUrl)
      && accountManager._contextAvailable(a, { ...ctx, advisorModel: null }));
    const isTransient = isTransientUpstreamError(err, { otherHostAvailable });

    // A pre-headers timeout on an Opus request is indistinguishable to the client
    // from the capacity incident that commonly precedes it. When an explicit
    // overload fallback is configured, use the same single same-account fallback
    // as a 529 instead of making Claude Code wait through another outer retry.
    if (isTransient && errCode === 'TEAMCLAUDE_HEADERS_TIMEOUT'
        && ctx.overloadFallbackModel && !ctx.overloadFallbackAttempted
        && !res.headersSent) {
      ctx.overloadFallbackAttempted = true;
      console.log(`[TeamClaude] headers timeout on "${account.name}" for "${ctx.model}" — retrying once as "${ctx.overloadFallbackModel}"`);
      return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
    }

    // Retry a pre-headers transport reset inside the proxy. The request body is
    // already buffered and no response reached the client, so replay is safe.
    // Closing the client socket here used to make Claude Code print
    // "Connection dropped (ECONNRESET)" and immediately start its own retry
    // ladder, multiplying a single stale pooled socket into repeated turns.
    if (isTransient && !res.headersSent && ctx.transientRetries < ctx.maxTransientRetries) {
      ctx.transientRetries += 1;
      console.log(`[TeamClaude] transient upstream error on "${account.name}" (${errCode || err.message}) — retrying internally (${ctx.transientRetries}/${ctx.maxTransientRetries})`);
      return forwardRequest(req, res, body, accountManager, upstream, retryCount, hooks, reqId, ctx, logDir);
    }

    // If an Opus transport retry also failed, make one configured model fallback
    // before giving the client an error. This stays on the same account and is
    // bounded by overloadFallbackAttempted.
    if (isTransient && !res.headersSent && ctx.overloadFallbackModel
        && !ctx.overloadFallbackAttempted) {
      ctx.overloadFallbackAttempted = true;
      console.log(`[TeamClaude] persistent transient error on "${account.name}" for "${ctx.model}" — retrying once as "${ctx.overloadFallbackModel}"`);
      return forwardRequest(req, res, body, accountManager, upstream, retryCount, hooks, reqId, ctx, logDir);
    }

    // Never turn an upstream reset into a downstream reset. A structured 503
    // carries an actual backoff deadline and preserves the diagnostic.
    if (isTransient) {
      if (res.headersSent) {
        ctx.proxyClosed = true;
        res.destroy();
        return;
      }
      ctx.status = 503;
      res.writeHead(503, { 'Content-Type': 'application/json', 'retry-after': '5' });
      res.end(JSON.stringify({
        type: 'error',
        error: { type: 'overloaded_error', message: `Upstream connection failed after ${ctx.transientRetries} internal retry attempt(s). Retry in 5s.` },
      }));
      return;
    }

    if (retryCount < maxRetries && !res.headersSent) {
      // A thrown send failure is a transport observation, not evidence against
      // the account: a bad credential comes back as a 401 RESPONSE, never a
      // throw. So skip the account for the rest of THIS request only and fail
      // over; it stays in rotation. Parking it in 'error' here took healthy
      // accounts out until a restart, since nothing heals a request-path error,
      // and a host that sleeps or changes networks can abort sockets with codes
      // the transient set does not list (ECONNABORTED, EADDRNOTAVAIL). On
      // 2026-09-23 that left 5 of 10 accounts parked while each still served a
      // direct request on the token the proxy held.
      ctx.triedSend.add(account);
      releaseHeld(); // skip this account for this request; fail over to another
      return forwardRequest(req, res, body, accountManager, upstream, retryCount + 1, hooks, reqId, ctx, logDir);
    }
    ctx.status = 502;

    if (!res.headersSent) {
      // Generic on purpose, as relayStream's 502 already is: the described
      // error names the resolved upstream hosts and ports (per-account
      // upstreams included), which is the operator's business — it went to
      // the log above — and not the client's.
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        type: 'error',
        error: { type: 'proxy_error', message: 'Upstream error; see the proxy log' },
      }));
    } else if (!res.writableEnded) {
      // Error after headers were already sent (mid-stream) and it wasn't
      // classified transient: we can't send a status or fail over, and
      // streamResponse deliberately skipped res.end(). Destroy so the client
      // sees a broken response and retries instead of hanging on an open socket.
      ctx.proxyClosed = true;
      res.destroy();
    }
  } finally {
    log?.end();
  }
}

// Idle deadline for the RESPONSE BODY, complementing the headers timeout in
// upstream-fetch.js. The headers guard only covers time-to-first-byte; once
// headers arrive it is disarmed, so a network drop AFTER the stream starts would
// otherwise hang the read forever (the SSE completion just goes silent mid-way).
// This watchdog resets on every chunk, so a long but healthy stream is never
// cut — it fires only when the socket produces nothing for the whole window,
// converting a mid-stream hang into a fast failure that evicts the dead socket
// (reader.cancel destroys the underlying connection on both the direct-fetch and
// the sx-tunnel path, since both hand back a web ReadableStream). Override with
// TEAMCLAUDE_UPSTREAM_BODY_TIMEOUT_MS.
const DEFAULT_BODY_IDLE_TIMEOUT_MS = 120_000;

function resolveBodyIdleTimeout() {
  const env = Number(envVar('UPSTREAM_BODY_TIMEOUT_MS'));
  return env > 0 ? env : DEFAULT_BODY_IDLE_TIMEOUT_MS;
}

// Race a single reader.read() against an inactivity deadline. Resolves to the
// read result, or rejects with a transient TEAMCLAUDE_BODY_TIMEOUT if no chunk
// arrives within `ms`. The pending read is abandoned on timeout; the caller
// cancels the reader (evicting the socket) in its finally block.
/** @param {ReadableStreamDefaultReader<Uint8Array>} reader @param {number} ms */
export function readWithIdleTimeout(reader, ms) {
  /** @type {ReturnType<typeof setTimeout>|undefined} */
  let timer;
  /** @type {Promise<never>} */
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const err = /** @type {CodedError} */ (new Error(`upstream stream idle for ${ms}ms`));
      err.code = 'TEAMCLAUDE_BODY_TIMEOUT';
      reject(err);
    }, ms);
    timer.unref?.();
  });
  const read = reader.read();
  // If the timeout wins the race, `read` is abandoned; swallow any later
  // rejection so it can't surface as an unhandledRejection.
  read.catch(() => {});
  return Promise.race([read, timeout]).finally(() => clearTimeout(timer));
}

/**
 * Stream an SSE response to the client, parsing usage data along the way.
 * @param {ReadableStream<Uint8Array>} webStream
 * @param {ProxyResponse} res
 * @param {ManagedAccount|number} accountIndex
 * @param {AccountManager} accountManager
 * @param {{chunk: (buf: Buffer) => void, drain?: () => Promise<void>|null}|null} bodyWriter
 * @param {((input: number, output: number) => void)|null} [onUsage]
 * @param {string|null} [pinKey] the conversation the usage is booked to
 * @param {string|null} [model]
 * @param {number|null} [bodyTimeoutMs]
 */
export async function streamResponse(webStream, res, accountIndex, accountManager, bodyWriter, onUsage = null, pinKey = null, model = null, bodyTimeoutMs = null) {
  const reader = webStream.getReader();
  // A client that leaves while upstream is silent must not hold the pending
  // read — and with it the upstream socket and its admission permit — until
  // the idle watchdog fires: the clientGone check below runs only after a
  // chunk. Cancelling the reader settles the pending read as done, and the
  // loop exits through the same clientGone break. Optional-chained because
  // tests drive this with a bare Writable.
  const onClose = () => { reader.cancel().catch(() => {}); };
  res.once?.('close', onClose);
  if (clientGone(res)) onClose();
  const decoder = new TextDecoder();
  let errored = false;
  // The message's usage, merged across its two reports and recorded once below.
  /** @type {Record<string, number>} */
  const merged = {};
  // A Responses turn settles both sides on ONE terminal event, so this stream
  // remembers that it did — the incremental counters would book the turn again
  // if a second terminal event arrived. See parseSSEDataLine.
  const responsesTurn = { settled: false };
  const usage = createSseLineScanner(line => parseSSEDataLine(line, accountIndex, accountManager, onUsage, merged, responsesTurn));

  try {
    while (true) {
      const { done, value } = await readWithIdleTimeout(reader, bodyTimeoutMs ?? resolveBodyIdleTimeout());
      if (done) break;

      // Client disconnected — stop reading from upstream
      if (clientGone(res)) break;

      // Forward chunk immediately
      const ok = res.write(value);

      // Append to the log as it streams (no whole-body buffering)
      if (bodyWriter) bodyWriter.chunk(Buffer.from(value));
      // ...and let the log's disk keep up: a write the file stream had to queue
      // pauses the relay until it drains, so a slow disk bounds memory instead
      // of the stream's buffer absorbing the body. Resolves on error/close too.
      const logPending = bodyWriter?.drain?.();
      if (logPending) await logPending;

      // Parse the SSE data lines for usage tracking, as they arrive. The relay
      // above is done with the chunk by now; this reads it and retains at most
      // one bounded partial line, never the response.
      usage.push(decoder.decode(value, { stream: true }));

      // Handle backpressure — also bail out if client disconnects,
      // because 'drain' will never fire on a destroyed socket
      if (!ok) {
        await new Promise(resolve => {
          res.once('drain', resolve);
          res.once('close', resolve);
        });
        if (clientGone(res)) break;
      }
    }

    // A final data line without a trailing newline.
    usage.push(decoder.decode());
    usage.flush();
  } catch (err) {
    // A mid-stream idle timeout (or any read error) means the upstream went
    // silent after headers. Rethrow to the caller's transient handler, which
    // destroys the client connection so the truncated stream is NOT ended
    // cleanly (a clean res.end() would look like a complete response and
    // suppress the client's retry). reader.cancel() in finally evicts the socket.
    errored = true;
    throw err;
  } finally {
    res.off?.('close', onClose);
    // Record the message once, on every exit path. A stream that died after
    // `message_start` still spent the input it reported, so the merge is written
    // even when no `message_delta` ever arrived. An empty merge is written
    // nowhere rather than written as zeroes: plenty of streams carry no usage at
    // all (a ping and some text deltas, or an upstream error after the headers),
    // and recording those would report an observation that never happened.
    if (Object.keys(merged).length) {
      accountManager.recordTokenUsage(accountIndex, pinKey, model, merged);
    }
    // Cancel upstream reader to stop consuming data nobody needs (and, on the
    // timeout path, to destroy the dead socket so the pool drops it).
    reader.cancel().catch(() => {});
    if (!errored && !res.writableEnded) res.end();
  }
}

// The longest line the usage scanner will hold while waiting for its newline.
// A real Anthropic SSE line is a single JSON event of at most a few kilobytes,
// so this sits three orders of magnitude above anything legitimate.
export const SSE_MAX_LINE_CHARS = 1 << 20;

/**
 * A line scanner for the usage parser: `push(text)` hands every complete line
 * to `onLine` as it arrives and retains only the trailing partial one; `flush()`
 * delivers that partial at end of stream.
 *
 * The parser used to accumulate the whole response into one string and drain
 * it on the `\n\n` event boundary. An upstream that sends
 * `text/event-stream` and never a blank line — a stuck or garbage stream, a
 * misbehaving third-party backend — therefore grew that string for the whole
 * response, re-split on every chunk, until V8 aborted the process on its heap
 * limit: uncatchable, and it took every account and every session down with
 * it (#341). The relay never needed the buffer; only the accounting did, and
 * the accounting reads single lines.
 *
 * So the retained state is one line, and even that is bounded: a partial line
 * that outgrows `maxChars` is dropped, and the rest of that line is discarded
 * up to its newline. Only that line's usage figure is lost, which the caller
 * already tolerates; the bytes themselves were relayed before they came here.
 */
/** @param {(line: string) => void} onLine @param {number} [maxChars] */
export function createSseLineScanner(onLine, maxChars = SSE_MAX_LINE_CHARS) {
  let partial = '';
  let dropping = false; // inside a line already judged too long
  return {
    /** @param {string} text */
    push(text) {
      let start = 0;
      for (;;) {
        const nl = text.indexOf('\n', start);
        if (nl < 0) break;
        if (!dropping) {
          const line = partial + text.slice(start, nl);
          if (line.length <= maxChars) onLine(line);
        }
        partial = '';
        dropping = false;
        start = nl + 1;
      }
      if (dropping) return;
      partial += text.slice(start);
      if (partial.length > maxChars) { partial = ''; dropping = true; }
    },
    flush() {
      if (!dropping && partial.trim()) onLine(partial);
      partial = '';
      dropping = false;
    },
    /** Characters currently retained, for tests that pin the bound. */
    pending() { return partial.length; },
  };
}

// A streaming response reports its usage twice. `message_start` carries the
// input side, including the two cache fields, with an output figure that is only
// a placeholder. `message_delta` then reports figures that are cumulative for
// the whole message, so every field it carries supersedes the earlier one rather
// than adding to it.
//
// The two counters therefore consume the stream differently. `updateUsage` is
// incremental, so it takes each side at the event that settles it: input at
// `message_start`, output at `message_delta`. `merged` instead accumulates the
// message's final figures for a single `recordTokenUsage` once the stream is
// over. One record per message is what makes double counting unrepresentable
// rather than merely avoided.
//
// A Responses stream (the Codex path) instead reports once, at the end, and in
// OpenAI's own vocabulary — so it is rewritten into Anthropic's disjoint shape
// before it reaches either counter (src/responses-usage.js explains why the two
// disagree). It rides this function rather than a parser of its own because the
// line is ALREADY parsed here: the branch costs a Set lookup on a string, not a
// second pass over the stream. Nothing else would be cheap — a Responses stream
// is mostly text deltas, and the settled figures arrive on one event near the end
// with no header or marker to find it by.
//
// Reads one `data:` line. Both dialects carry exactly one per event, so a line
// is an event for this purpose, and the scanner above never has to hold more.
/** @param {string} line @param {ManagedAccount|number} accountIndex @param {AccountManager} accountManager
 * @param {((input: number, output: number) => void)|null} [onUsage]
 * @param {Record<string, number>|null} [merged]
 * @param {{settled: boolean}|null} [responsesTurn] this stream's "already booked" flag */
function parseSSEDataLine(line, accountIndex, accountManager, onUsage = null, merged = null, responsesTurn = null) {
  if (!line.startsWith('data: ')) return;

  try {
    const data = JSON.parse(line.slice(6));
    if (data.type === 'message_start' && data.message?.usage) {
      accountManager.updateUsage(accountIndex, data.message.usage.input_tokens, 0);
      onUsage?.(data.message.usage.input_tokens || 0, 0);
      if (merged) Object.assign(merged, data.message.usage);
    } else if (data.type === 'message_delta' && data.usage) {
      accountManager.updateUsage(accountIndex, 0, data.usage.output_tokens);
      onUsage?.(0, data.usage.output_tokens || 0);
      if (merged) Object.assign(merged, data.usage);
    } else if (!responsesTurn?.settled) {
      // Both sides settle at once here, so unlike the Anthropic branches above
      // this is a single incremental update rather than one per side — and it
      // runs for the FIRST terminal event only. The event names bound what may
      // report, not how often: a backend that re-sent `response.completed`, or a
      // relay that replayed the tail of the stream, would otherwise add the
      // whole turn to the account and per-client counters a second time.
      const usage = responsesEventUsage(data);
      if (usage) {
        if (responsesTurn) responsesTurn.settled = true;
        accountManager.updateUsage(accountIndex, usage.input_tokens, usage.output_tokens);
        onUsage?.(usage.input_tokens, usage.output_tokens);
        if (merged) Object.assign(merged, usage);
      }
    }
  } catch {
    // not valid JSON, skip
  }
}

/** @param {Buffer} buffer @param {ManagedAccount|number} accountIndex @param {AccountManager} accountManager
 * @param {((input: number, output: number) => void)|null} [onUsage]
 * @param {string|null} [pinKey] @param {string|null} [model] */
function extractUsageFromBody(buffer, accountIndex, accountManager, onUsage = null, pinKey = null, model = null) {
  try {
    const json = JSON.parse(buffer.toString());
    if (json.usage) {
      // A buffered Responses body reports under the same two field NAMES with a
      // different meaning, so reading it as Anthropic's would book the cached
      // prefix as fresh input and never book it as a cache read at all. The
      // discriminator picks the reading, and it picks once: a body that is NOT a
      // Responses one falls through to the reading this had before, unchanged,
      // while a body that is one but whose figures do not survive the normaliser
      // (a negative, a NaN, nothing at all) books nothing. Falling back there
      // would book exactly the number the normaliser exists to stop.
      const usage = isResponsesBody(json) ? normalizeResponsesUsage(json.usage) : json.usage;
      if (!usage) return;
      accountManager.updateUsage(accountIndex, usage.input_tokens, usage.output_tokens);
      onUsage?.(usage.input_tokens || 0, usage.output_tokens || 0);
      accountManager.recordTokenUsage(accountIndex, pinKey, model, usage);
    }
  } catch {
    // not JSON or no usage
  }
}

// Apply every request-body rewrite for the account about to serve it, in
// forward order. Pure (buffer in, buffer out) and exported for tests —
// forwardRequest only threads the result into Content-Length and the log.
// Each step is a no-op returning the same Buffer when it has nothing to do,
// so untouched bodies keep their exact bytes.
/** @param {Buffer} body @param {ManagedAccount} account @param {string|undefined} url @param {string|undefined} contentType */
export function rewriteRequestBody(body, account, url, contentType) {
  let sendBody = body;
  // The rewrites below are Anthropic-shaped and must not touch another
  // provider's payload: a Responses API body has no metadata.user_id to patch
  // and no Anthropic tool-pairing rule to repair, so running them would at
  // best waste a pass and at worst corrupt a valid request.
  if (rewritesBody(account)) {
    // Strip orphaned tool_use / tool_result blocks so a client that compacted or
    // interrupted a turn can't wedge the session with Anthropic's non-retryable
    // 400 ("tool_use ids were found without tool_result blocks").
    sendBody = sanitizeToolPairs(sendBody, url, contentType);
    // Align the body's account_uuid (in metadata.user_id) with the account whose
    // token we're injecting (same-length patch; no-op if absent).
    if (account.accountUuid) {
      const patched = patchAccountUuid(sendBody, account.accountUuid);
      sendBody = Buffer.isBuffer(patched) ? patched : Buffer.from(patched);
    }
    // Block types a strict upstream rejects (`tool_addition` once a tool appears
    // mid-conversation) stay in the history, so one of them fails every later
    // turn too. Opt-in: `stripRequestFields: ["content.tool_addition"]`. Runs
    // before the cache_control pass because it can move a breakpoint onto a
    // block that stays, and that breakpoint still needs its subfields stripped.
    const blockTypes = contentBlockTypesToStrip(account.stripRequestFields);
    if (blockTypes.size) sendBody = sanitizeContentBlocks(sendBody, url, contentType, blockTypes);
    // Some strict Anthropic-compatible upstreams reject `cache_control`
    // subfields Claude Code sends (`scope`; `ttl: "1h"` on a few) with a
    // non-retryable 400, breaking EVERY request once such an account is
    // selected. Opt-in per account, like every other rewrite keyed on
    // `upstream`: `stripRequestFields: ["cache_control.scope"]`. A first-party
    // relay that honours every subfield loses nothing by default.
    const ccSubfields = cacheControlSubfieldsToStrip(account.stripRequestFields);
    if (ccSubfields.size) sendBody = sanitizeCacheControl(sendBody, url, contentType, ccSubfields);
  }
  // Rewrite the model name for accounts that target a different upstream (e.g.
  // GLM), which uses different model identifiers than Anthropic.
  if (account.modelMap) sendBody = rewriteModel(sendBody, account.modelMap);
  // Third-party upstreams (e.g. OpenCode Zen, GLM) implement the Anthropic
  // message API but reject fields Claude Code legitimately sends — observed:
  // `context_management` -> 400 "Extra inputs are not permitted", which breaks
  // EVERY request once such an account is selected. Drop the configured
  // top-level fields for those accounts only (the `cache_control.<sub>` entries
  // were consumed above); Anthropic accounts are untouched.
  const topLevel = Array.isArray(account.stripRequestFields)
    ? account.stripRequestFields.filter(f => typeof f === 'string' && !f.includes('.')) : [];
  if (topLevel.length) sendBody = stripBodyFields(sendBody, topLevel);
  return sendBody;
}

// A continue must carry both of these exact JSON substrings, so a Buffer scan
// skips the parse for any body missing either. Necessary, not sufficient: a
// create whose message text is the word "continue" carries both as well and
// gets parsed for nothing. The parse below is what decides.
const THREAD_MARKER = Buffer.from('"thread"');
const CONTINUE_MARKER = Buffer.from('"continue"');

/**
 * Whether an `upstream` names Anthropic itself — a region pin or a mirror rather
 * than a different backend. Those reach the real thread store, so refusing their
 * continues would be overhead the operator has to discover and opt out of by
 * hand. The HOST decides: a third-party API serving the Anthropic shape does it
 * under its own host, usually with a path prefix.
 *
 * @param {unknown} upstream
 */
function pointsAtAnthropic(upstream) {
  try {
    return new URL(String(upstream)).hostname === new URL(PROVIDERS.anthropic.upstream).hostname;
  } catch {
    return false; // unparseable is not evidence of a thread store
  }
}

// Capture/replay templates describe Anthropic's native messages protocol, not
// a Codex or third-party account's accepted request shape. Filter before taking
// maintenance capacity or refreshing credentials, and recheck at dispatch.
/** @param {ManagedAccount} account */
function canReplayAnthropicTemplate(account) {
  return providerOf(account) === DEFAULT_PROVIDER
    && (!account.upstream || pointsAtAnthropic(account.upstream));
}

/**
 * Whether a request must be refused instead of forwarded, because it continues
 * an Anthropic message thread on an upstream that keeps no thread state.
 *
 * Claude Code stores the conversation on Anthropic's side once a thread exists:
 * the first /v1/messages body carries thread:{type:"create"} with the whole
 * messages array, later ones thread:{type:"continue"} with only the new delta.
 * A third-party upstream ignores the unknown field and answers the delta alone,
 * so from the second turn on the model no longer sees the conversation — with
 * no error anywhere. Anthropic itself answers 400 when a thread cannot be
 * continued, and the client reacts by resending the whole conversation, so
 * refusing here is what puts the upstream back on a complete one.
 *
 * The body carries `details.error_code: "thread_unsupported_request"`, which the
 * client reads as "this model keeps no thread state": it resends the turn in
 * full and then drops the `thread` field entirely for the rest of the session,
 * so the refusals are counted per agent and model rather than per turn, and cost
 * no tokens. A relay that does reach Anthropic keeps working threads and opts
 * out with `messageThreads: true`.
 *
 * Exported for tests.
 *
 * @param {Buffer|null|undefined} body fully-buffered request body
 * @param {Record<string, any>|null|undefined} account the account about to serve it
 * @param {string|undefined} url req.url
 * @param {string|null} [configuredUpstream] the fleet's global `upstream`, for an account without its own
 * @param {boolean} [fleetKeepsThreads] the top-level `messageThreads`: the global upstream keeps thread state
 * @returns {boolean}
 */
export function refusesThreadContinue(body, account, url, configuredUpstream = null, fleetKeepsThreads = false) {
  if (!account || !rewritesBody(account)) return false;
  if (account.messageThreads) return false;
  // An account without an upstream of its own goes wherever the fleet points
  // (the global `upstream`), and a fleet sent to a third party has the same
  // problem as one account sent there (#379). The top-level `messageThreads`
  // is the fleet-wide counterpart of the per-account flag for that case.
  if (!account.upstream && fleetKeepsThreads) return false;
  if (!Buffer.isBuffer(body) || body.length === 0) return false;
  // Only a completion continues a thread. count_tokens carries a body of the
  // same shape, and a refusal there is unrecoverable — there is no conversation
  // to resend for a token count. Classified on the folded, once-decoded path
  // like every other refusal here: `\v1\messages` is what this process itself
  // will send as `/v1/messages`, so the test has to read it the same way.
  if (!isCompletionPath(classificationPath(url))) return false;
  if (!body.includes(THREAD_MARKER) || !body.includes(CONTINUE_MARKER)) return false;
  // Last of the cheap gates because it parses two URLs: by here the request is
  // already known to be a completion whose body could carry a continue. The
  // effective upstream, so a fleet on a third-party global `upstream` is
  // covered too; the default is Anthropic's own host, which is exempt.
  if (pointsAtAnthropic(upstreamFor(account, configuredUpstream))) return false;
  try {
    return JSON.parse(body.toString('utf8'))?.thread?.type === 'continue';
  } catch {
    return false; // not JSON we can reason about — never break it
  }
}

// Remove top-level fields from a JSON request body (see stripRequestFields).
// Returns the original buffer when nothing changed or the body isn't JSON, so
// non-messages endpoints pass through untouched. Exported for tests.
/** @param {Buffer} body @param {string[]} fields */
export function stripBodyFields(body, fields) {
  try {
    const obj = JSON.parse(body.toString('utf8'));
    let changed = false;
    for (const f of fields) {
      if (Object.prototype.hasOwnProperty.call(obj, f)) { delete obj[f]; changed = true; }
    }
    if (changed) return Buffer.from(JSON.stringify(obj), 'utf8');
  } catch { /* not JSON — pass through unchanged */ }
  return body;
}

// Rewrite the `model` field in a JSON request body using a per-account map.
// Returns the original buffer unchanged if the model isn't in the map or the
// body isn't valid JSON, so non-messages endpoints pass through safely.
// Exported for tests.
/** @param {Buffer} body @param {string|null} model */
export function setRequestModel(body, model) {
  if (!model) return body;
  try {
    const parsed = JSON.parse(body.toString('utf8'));
    if (!parsed.model || parsed.model === model) return body;
    return Buffer.from(JSON.stringify({ ...parsed, model }));
  } catch {
    return body;
  }
}

/** @param {unknown} requestedModel @param {unknown} configuredModel */
export function resolveOverloadFallbackModel(requestedModel, configuredModel) {
  if (typeof requestedModel !== 'string' || !requestedModel.toLowerCase().includes('opus')) return null;
  if (typeof configuredModel !== 'string' || !configuredModel.trim()) return null;
  const fallback = configuredModel.trim();
  return requestedModel.endsWith('[1m]') && !fallback.endsWith('[1m]')
    ? `${fallback}[1m]`
    : fallback;
}


/** @param {Buffer} body @param {Record<string, string>} modelMap */
export function rewriteModel(body, modelMap) {
  try {
    const obj = JSON.parse(body.toString('utf8'));
    // Own keys only: the map is a plain object, so a model named
    // "constructor" or "toString" would otherwise look up a prototype
    // function, which JSON.stringify then drops — the request goes upstream
    // with no model at all.
    if (modelMap && typeof obj.model === 'string' && Object.hasOwn(modelMap, obj.model) && typeof modelMap[obj.model] === 'string') {
      obj.model = modelMap[obj.model];
      return Buffer.from(JSON.stringify(obj), 'utf8');
    }
  } catch { /* not JSON — pass through unchanged */ }
  return body;
}

/**
 * The resets that are actually holding `account` back, each read off the window
 * that imposes it.
 *
 * The quota half is `_isNearQuota`'s gate — its checks, in its order, against
 * the same per-bucket, per-account `switchThreshold` — with one addition: every
 * check hands back the reset belonging to the window it just tripped on. A bucket that is not
 * blocking has no business naming the moment this request becomes servable
 * again.
 *
 * Timestamps come back in whatever form the account holds them — epoch millis on
 * the holds and the unified windows, a date string on `resetsAt`, which is kept
 * as the header spelled it. `new Date` takes either, and the caller drops
 * anything that will not parse or has already passed.
 *
 * @param {import('./account-manager.js').AccountManager} accountManager
 * @param {Record<string, any>} account
 * @param {string|null|undefined} model
 * @returns {any[]}
 */
function blockingResets(accountManager, account, model) {
  const q = account.quota || {};
  /** @type {any[]} */
  const resets = [account.rateLimitedUntil, account.entitlementDeniedUntil, account.routingFailedUntil,
    account.credentialRejectedUntil];

  if (q.unified5h != null && q.unified5h >= accountManager.thresholdFor('unified5h', account)) {
    resets.push(q.unified5hReset);
  }

  // The weekly gate, asked of `_governingWeekly` so the question is
  // `_isNearQuota`'s verbatim, then resolved to a time by the buckets that gate
  // is a maximum over: the one metering this model's family, the shared one its
  // spend also meters into, and — for a family with no dedicated bucket — the
  // scoped bucket upstream reports for it. EVERY bucket at or over the threshold
  // contributes, because the account only frees when the LAST of them rolls.
  // `modelRoutingLine` derives its recovery time by the same rule, for the same
  // reason: naming the family reset beside a block the shared weekly produced
  // tells the operator a week-long wait clears tomorrow.
  const bucket = accountManager._weeklyBucketFor(model);
  const weeklyThreshold = accountManager.thresholdFor(bucket, account);
  const weekly = accountManager._governingWeekly(account, model);
  if (weekly != null && weekly >= weeklyThreshold) {
    if (q[bucket] != null && q[bucket] >= weeklyThreshold) resets.push(q[`${bucket}Reset`]);
    if (bucket !== 'unified7d' && q.unified7d != null && q.unified7d >= weeklyThreshold) {
      resets.push(q.unified7dReset);
    }
    const scoped = bucket === 'unified7d' ? accountManager._scopedWeekly(account, model) : null;
    if (scoped?.utilization != null && scoped.utilization >= weeklyThreshold) resets.push(scoped.resetAt);
  }

  // The tokens and requests windows reset independently, so each answers with
  // its own reset and only while it binds (an API-key account throttled for a
  // minute with most of its tokens left is not held until its next refill).
  // Both binding means the LATER one: `resetsAt` alone prefers the sooner token
  // reset and would re-flood while the request window still blocks. A snapshot
  // without the split fields falls back to `resetsAt`, which is set from those
  // same headers.
  const tokens = q.tokensLimit != null && q.tokensRemaining != null
    ? 1 - q.tokensRemaining / q.tokensLimit : null;
  const requests = q.requestsLimit != null && q.requestsRemaining != null
    ? 1 - q.requestsRemaining / q.requestsLimit : null;
  if (tokens != null && tokens >= accountManager.thresholdFor('tokens', account)) {
    resets.push(q.tokensReset || q.resetsAt);
  }
  if (requests != null && requests >= accountManager.thresholdFor('requests', account)) {
    resets.push(q.requestsReset || q.resetsAt);
  }

  return resets;
}

// What a block with no clock is worth: the interval the synthetic 429 always
// fell back to, short enough that a transient fault is retried promptly.
const UNTIMED_RETRY_AFTER_SECONDS = 60;

/**
 * How long before this request is worth sending again: the seconds that become
 * the synthetic 429's `retry-after`, which Claude Code obeys to the letter.
 *
 * It used to read three fields per account, and on a fleet of subscriptions all
 * three are routinely null — `quota.resetsAt` is set from the tokens/requests
 * headers an API key returns, and a subscription is metered by the unified
 * windows instead. So an account sitting at `unified7d` 1.00 with three days to
 * go looked like an account that knew nothing, every account did, and the
 * function fell through to its 60s default. The client honoured that default
 * forever: one silent retry a minute, a spinner, and no error ever reaching the
 * operator.
 *
 * Two rules keep the number honest.
 *
 * A window may only speak for a block it is imposing (`blockingResets`). A
 * 5-hour bucket at 12% that happens to refresh in four minutes is not why the
 * request was refused, and letting it answer would put the client back in the
 * one-minute loop wearing a different number.
 *
 * An account is blocked until the LAST of its blocks clears, so its own clocks
 * are taken at their maximum, while the fleet recovers when the FIRST account
 * does, so accounts are taken at their minimum. Mixing those up is how this
 * failure survives a half-fix: a spent subscription is usually throttled as
 * well, for the few minutes the 429 path holds it, and reading the sooner of the
 * two would advertise minutes on a window with three days left on it.
 *
 * A candidate that is out of this request with NO clock still bounds the wait,
 * at the old 60s default. Plenty of refusals carry no timestamp: an account this
 * very request already tried and lost to a socket error, an upstream `rejected`
 * verdict, an `exhausted` status, an operator cap, an advisor's spent bucket.
 * Such an account may well serve the next attempt, so letting it contribute
 * nothing hands the answer to whichever neighbour does have a clock — one
 * account spent for three days beside a healthy one that just dropped a
 * connection told the client to come back in three days, where it used to say a
 * minute. Only accounts that will not come back on their own are left out: the
 * disabled, and those in an error state waiting on a re-login. (An entitlement
 * quarantine always has a clock, so it answers with that.) With nobody left to
 * ask, the answer is still 60s.
 *
 * Deliberately uncapped: the truthful value is the whole point, and a ceiling
 * would rebuild the silent loop at whatever interval the ceiling was. Nothing
 * here sleeps on it: every wait before an answer is bounded by the request's
 * own predispatch budget (remainingWaitBudget), and this number only goes to the
 * client. Exported for tests.
 *
 * @param {import('./account-manager.js').AccountManager} accountManager
 * @param {Record<string, any>[]} candidates
 * @param {string|null|undefined} [model]
 * @param {number} [now] epoch ms, for tests
 * @returns {number}
 */
export function computeRetryAfter(accountManager, candidates, model = null, now = Date.now()) {
  let soonest = Infinity;
  for (const acct of candidates) {
    if (acct.disabled || acct.enabled === false || acct.status === 'error') continue;
    let blockedFor = 0;
    for (const reset of blockingResets(accountManager, acct, model)) {
      const ms = new Date(reset).getTime() - now;
      // Skips what will not parse (NaN fails both comparisons) and what has
      // already lapsed: a hold that expired is not a hold.
      if (ms > 0 && ms > blockedFor) blockedFor = ms;
    }
    // No live clock means blocked by something untimed, which is worth a retry
    // at the default interval rather than being silent in the minimum.
    if (blockedFor <= 0) blockedFor = UNTIMED_RETRY_AFTER_SECONDS * 1000;
    if (blockedFor < soonest) soonest = blockedFor;
  }
  return soonest === Infinity
    ? UNTIMED_RETRY_AFTER_SECONDS
    : Math.max(1, Math.ceil(soonest / 1000));
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
    }, err => callback(err, null));
    return undefined;
  };
  return agent;
}
