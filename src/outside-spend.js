// Outside spend: the share of an account's weekly window that was spent
// somewhere other than this proxy (#475).
//
// An account in a pool can also be used elsewhere — a local login, a
// credentials file copied to another machine — and that spend lands on the
// same weekly limit while none of the proxy's counters see it. The proxy holds
// both halves of the answer: a fresh utilization reading per window, and
// whether it served anything on the account between two readings.
//
// Between two fresh readings of one window on one account:
//
//   the utilization rose and the proxy served nothing  -> outside, the whole rise
//   the proxy served at least one request              -> unattributable, not counted
//
// So the figure is a FLOOR, not an estimate. It cannot be tightened by reading
// more often, only by the proxy being idle on the account more often. The unit
// is a share of the week (a week is 1.0): subscription accounts report no token
// limit, so there is nothing to convert a percentage into.
//
// Three states, explicit in the payload, so no reader ever shows 0% for an
// answer it does not have:
//
//   measured        at least one idle interval was observed in this window;
//                   `share` is the sum of the rises over those intervals (0 is
//                   a real answer here: idle, and nothing moved)
//   not_measurable  fresh readings exist, but the proxy was serving across
//                   every interval between them
//   not_observed    fewer than two fresh readings in this window — the probe is
//                   off and the account was not routed to
//
// Only weekly windows: the all-models weekly and any family bucket the account
// reports. The 5h window rolls over too often for a floor to say anything.

/** A reset this far from the stored one starts a new window. Reset stamps for
 * one window agree to the second, so this only absorbs clock rounding. */
const WINDOW_RESET_TOLERANCE_MS = 60 * 60 * 1000;

/** A drop larger than this is a window reset even when no reset stamp moved
 * (an unstarted window reports none). Smaller drops are reading noise and only
 * rebaseline: a spurious restart would throw away the window's sum. */
const RESET_DROP = 0.05;

/**
 * @typedef {object} OutsideSpendSlot
 * @property {number} lastU
 * @property {number} peakU  highest reading of the window so far
 * @property {number} lastAt
 * @property {string} lastActivity
 * @property {number|null} resetAt
 * @property {number} share
 * @property {number} idleIntervals
 * @property {number} intervals
 * @property {number} since
 */

/** @typedef {{ share: number|null, state: string, since: string|null }} OutsideSpendView */

/** How long after a request ends the account still counts as busy: the
 * usage endpoint can trail a response by a little, and a reading taken before
 * our own spend has landed must not open an "idle" interval that then shows it. */
export const OUTSIDE_SPEND_SETTLE_MS = 2 * 60 * 1000;

/**
 * One key per weekly window. A probe reports Fable (and Sonnet) both in its
 * dedicated field and in `scopedWeekly`; both name the same window, so they
 * map to the dedicated field's name.
 * @param {string} bucket
 * @returns {string}
 */
export function outsideSpendKey(bucket) {
  if (bucket === 'scoped:fable') return 'unified7dFable';
  if (bucket === 'scoped:sonnet') return 'unified7dSonnet';
  return bucket;
}

export const OUTSIDE_SPEND_STATES = Object.freeze({
  MEASURED: 'measured',
  NOT_MEASURABLE: 'not_measurable',
  NOT_OBSERVED: 'not_observed',
});

/**
 * @param {number} utilization
 * @param {number|null|undefined} resetAt
 * @param {string} activity
 * @param {number} now
 * @returns {OutsideSpendSlot}
 */
function freshSlot(utilization, resetAt, activity, now) {
  return {
    lastU: utilization,
    peakU: utilization,
    lastAt: now,
    lastActivity: activity,
    resetAt: resetAt ?? null,
    share: 0,
    idleIntervals: 0,
    intervals: 0,
    since: now,
  };
}

export class OutsideSpendTracker {
  constructor() {
    /** @type {Map<string, OutsideSpendSlot>} "index:bucket" -> slot */
    this.state = new Map();
  }

  /**
   * Record a fresh reading of one weekly window.
   *
   * `activity` is the account's activity stamp at the time of the reading: it
   * changes whenever a request is dispatched to the account, and a request
   * still open at the reading counts as activity too (see AccountManager's
   * activity counters). Equal stamps at both ends of an interval mean the proxy
   * served nothing on the account in between.
   *
   * @param {number} index
   * @param {string} bucket  'unified7d', 'unified7dFable', 'unified7dSonnet' or 'scoped:<family>'
   * @param {number} utilization  0-1 (may exceed 1 in overage)
   * @param {number|null} resetAt  ms timestamp of the window's reset, if known
   * @param {string} activity
   * @param {number} [now]
   */
  observe(index, bucket, utilization, resetAt, activity, now = Date.now()) {
    if (!Number.isFinite(utilization)) return;
    const key = `${index}:${bucket}`;
    const s = this.state.get(key);
    if (!s) {
      this.state.set(key, freshSlot(utilization, resetAt, activity, now));
      return;
    }

    // Windows only move forward. A reset reported EARLIER than the stored one
    // is a disagreeing source, not a new window, and must not throw away the
    // sum; it is ignored.
    const resetMoved = resetAt != null && s.resetAt != null
      && resetAt - s.resetAt > WINDOW_RESET_TOLERANCE_MS;
    const resetPassed = s.resetAt != null && now >= s.resetAt;
    const dropped = utilization < s.lastU - RESET_DROP;
    if (resetMoved || resetPassed || dropped) {
      this.state.set(key, freshSlot(utilization, resetAt, activity, now));
      return;
    }

    s.intervals++;
    if (activity === s.lastActivity) {
      s.idleIntervals++;
      // Only a rise above the window's highest reading is new spend. Measured
      // from the last reading instead, a reading that wobbles down and back up
      // would count the same spend again on every bounce; a small drop is
      // reading noise, never negative spend.
      const rise = utilization - s.peakU;
      if (rise > 0) s.share += rise;
    }
    // Every reading raises the mark, served or not: spend this proxy caused
    // must never be counted again by a later idle interval.
    if (utilization > s.peakU) s.peakU = utilization;
    s.lastU = utilization;
    s.lastAt = now;
    s.lastActivity = activity;
    if (resetAt != null && (s.resetAt == null || resetAt > s.resetAt)) s.resetAt = resetAt;
  }

  /**
   * The public view of one window: `{ share, state, since }`. `share` is null
   * unless the state is `measured`, so a reader cannot mistake "no answer" for
   * zero. A window whose reset has passed with no new reading reads as not
   * observed, rather than carrying the old window's sum into the new one.
   * @param {number} index
   * @param {string} bucket
   * @param {number} [now]
   * @returns {OutsideSpendView}
   */
  view(index, bucket, now = Date.now()) {
    const s = this.state.get(`${index}:${bucket}`);
    if (!s || (s.resetAt != null && now >= s.resetAt)) {
      return { share: null, state: OUTSIDE_SPEND_STATES.NOT_OBSERVED, since: null };
    }
    const since = new Date(s.since).toISOString();
    if (s.idleIntervals > 0) {
      return { share: s.share, state: OUTSIDE_SPEND_STATES.MEASURED, since };
    }
    if (s.intervals > 0) {
      return { share: null, state: OUTSIDE_SPEND_STATES.NOT_MEASURABLE, since };
    }
    return { share: null, state: OUTSIDE_SPEND_STATES.NOT_OBSERVED, since };
  }

  /** Every window tracked for an account, as `{ [bucket]: view }`.
   * @param {number} index
   * @param {number} [now]
   * @returns {Record<string, OutsideSpendView>} */
  viewAll(index, now = Date.now()) {
    /** @type {Record<string, OutsideSpendView>} */
    const out = {};
    const prefix = `${index}:`;
    for (const key of this.state.keys()) {
      if (!key.startsWith(prefix)) continue;
      const bucket = key.slice(prefix.length);
      out[bucket] = this.view(index, bucket, now);
    }
    return out;
  }

  /** Forget an account's windows (config reload dropped or replaced it).
   * @param {number} index */
  forget(index) {
    for (const key of [...this.state.keys()]) {
      if (key.startsWith(`${index}:`)) this.state.delete(key);
    }
  }

  /** Follow an account-list reindexing. `remap` returns the new index, or null
   * for a removed account.
   * @param {(index: number) => number|null} remap */
  remapAccounts(remap) {
    const next = new Map();
    for (const [key, value] of this.state) {
      const colon = key.indexOf(':');
      const mapped = remap(Number(key.slice(0, colon)));
      if (mapped != null) next.set(`${mapped}:${key.slice(colon + 1)}`, value);
    }
    this.state = next;
  }

  /** Serializable per-account state for the identity-keyed state file. The
   * activity stamp is process-local, so it is not saved: after a restart the
   * first reading of each window only rebaselines it (see restore).
   * @param {number} index
   * @returns {Record<string, Omit<OutsideSpendSlot, 'lastActivity'>>} */
  export(index) {
    /** @type {Record<string, Omit<OutsideSpendSlot, 'lastActivity'>>} */
    const result = {};
    const prefix = `${index}:`;
    for (const [key, s] of this.state) {
      if (!key.startsWith(prefix)) continue;
      result[key.slice(prefix.length)] = {
        lastU: s.lastU, peakU: s.peakU, lastAt: s.lastAt, resetAt: s.resetAt,
        share: s.share, idleIntervals: s.idleIntervals, intervals: s.intervals, since: s.since,
      };
    }
    return result;
  }

  /**
   * Restore saved windows. The saved activity stamp is replaced by a value no
   * live stamp can equal, so the interval spanning the restart is counted as
   * served — the proxy cannot know what it did while it was down, and an
   * unknown interval must never be attributed to the outside.
   * @param {number} index
   * @param {unknown} saved
   * @param {number} [now]
   */
  restore(index, saved, now = Date.now()) {
    if (!saved || typeof saved !== 'object' || Array.isArray(saved)) return;
    for (const [bucket, v] of Object.entries(saved)) {
      if (!bucket || !v || typeof v !== 'object' || Array.isArray(v)) continue;
      const num = (/** @type {unknown} */ x) => (typeof x === 'number' && Number.isFinite(x) ? x : null);
      const lastU = num(v.lastU);
      const lastAt = num(v.lastAt);
      const since = num(v.since);
      if (lastU == null || lastAt == null || since == null) continue;
      const resetAt = num(v.resetAt);
      if (resetAt != null && now >= resetAt) continue; // that window is over
      const peakU = num(v.peakU);
      this.state.set(`${index}:${bucket}`, {
        lastU,
        peakU: peakU != null && peakU >= lastU ? peakU : lastU,
        lastAt,
        lastActivity: 'restored',
        resetAt,
        share: Math.max(0, num(v.share) ?? 0),
        idleIntervals: Math.max(0, Math.trunc(num(v.idleIntervals) ?? 0)),
        intervals: Math.max(0, Math.trunc(num(v.intervals) ?? 0)),
        since,
      });
    }
  }
}
