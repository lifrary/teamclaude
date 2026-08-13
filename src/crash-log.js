import { appendFileSync } from 'node:fs';

/**
 * Build the handler that records a fatal error before the process dies.
 *
 * Node prints an uncaught exception to stderr and exits, which is invisible in
 * this deployment: the server runs under a full-screen TUI that repaints over
 * the stack, and its stderr goes to a launchd log that is truncated on every
 * kickstart. The one artifact that could explain a proxy which vanished
 * overnight has to outlive the process, so it goes to a file.
 *
 * Separated from installCrashHandlers so the behaviour can be tested without
 * registering real process-level listeners, which would outlive the test and
 * swallow genuine failures in the same file. `exit` and `log` are injectable
 * for the same reason.
 */
export function createCrashReporter(path, { exit = process.exit, log = process.stderr } = {}) {
  return (kind) => (err) => {
    const stack = err?.stack || String(err);
    const entry = `\n=== ${new Date().toISOString()} ${kind} ===\n${stack}\n`;
    // Appended, never truncated: the FIRST crash of a repeating cycle is the one
    // that explains it. 0600 because a stack can carry request context. A write
    // failure (read-only home, full disk) must not mask the crash itself, so
    // stderr gets the entry either way.
    try { appendFileSync(path, entry, { mode: 0o600 }); } catch { /* reported to stderr below */ }
    log.write(entry);
    exit(1);
  };
}

/**
 * Record fatal errors to `path`, then exit non-zero.
 *
 * Handling these events replaces Node's own behaviour, so this must do what Node
 * would: report and exit non-zero. Continuing after an uncaught exception would
 * leave the proxy serving on unknown state. Note the exit skips the awaited
 * state persistence in shutdown() — the same loss a SIGKILL takes, bounded by
 * the once-a-minute canonical-state write.
 */
export function installCrashHandlers(path, options = {}) {
  const report = createCrashReporter(path, options);
  process.on('uncaughtException', report('uncaughtException'));
  process.on('unhandledRejection', report('unhandledRejection'));
}
