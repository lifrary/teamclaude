// Where the rest of a JSON string ends, found with native byte searches instead
// of a JavaScript step per byte. The request-path scanners (the model, stream
// and advisor finders in model.js, the account-uuid patcher) walk every
// multi-megabyte body, and nearly all of its bytes are string contents they
// never read: message text, tool results, the system prompt. Measured
// 2026-09-30 on the MacBook proxy (a 15 s CPU profile of the live process),
// stepping through those bytes one method call at a time was about two thirds
// of the main thread's samples, enough to hold the event loop for seconds at a
// time under a fleet's load.
//
// Both functions take `from`, the first byte still inside the string, and
// assume the byte before it does not escape it: a caller holding a pending
// escape from the previous chunk consumes that one byte itself first.

const QUOTE = 0x22;
const BACKSLASH = 0x5c;

/** Length of the run of backslashes ending just before `at`, never reaching below `floor`.
 * @param {Uint8Array} buf @param {number} at @param {number} floor */
function backslashRunBefore(buf, at, floor) {
  let n = 0;
  for (let k = at - 1; k >= floor && buf[k] === BACKSLASH; k--) n++;
  return n;
}

/**
 * Index of the quote that closes the string, or -1 when `buf` ends first. A
 * quote is escaped exactly when the backslashes right before it are odd in
 * number, since each backslash escapes the one byte after it.
 *
 * @param {Uint8Array} buf @param {number} from
 * @returns {number}
 */
export function jsonStringEnd(buf, from) {
  let at = from;
  for (;;) {
    const quote = buf.indexOf(QUOTE, at);
    if (quote === -1) return -1;
    if (backslashRunBefore(buf, quote, from) % 2 === 0) return quote;
    at = quote + 1;
  }
}

/**
 * Whether `buf` ends on an unpaired backslash, which escapes the first byte of
 * the next chunk. Meaningful after jsonStringEnd returned -1 for the same span.
 *
 * @param {Uint8Array} buf @param {number} from
 * @returns {boolean}
 */
export function endsInEscape(buf, from) {
  return backslashRunBefore(buf, buf.length, from) % 2 === 1;
}
