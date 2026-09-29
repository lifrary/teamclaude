// The project's name, in one place. TeamClaude is being renamed to TeamRouter
// over several releases (issue #72): this module is where the new and the old
// spellings live, so that each phase of the rename is an edit here plus the
// code that reads it, rather than a sweep.
//
// Phase 1 (this release): the new name is accepted everywhere the old one is
// read — environment variables, the control routes, the config path, the CLI
// name — while the old one stays the canonical spelling in everything the
// proxy writes. Nothing an existing install has on disk, in a service unit or
// in a script changes meaning.

/** The name to come: CLI, package, config basename, route prefix. */
export const NAME = 'teamrouter';
/** The name today. Canonical until the rename's second phase. */
export const LEGACY_NAME = 'teamclaude';

/** Prefix of the environment variables, new spelling first. */
export const ENV_PREFIX = 'TEAMROUTER_';
export const LEGACY_ENV_PREFIX = 'TEAMCLAUDE_';

/** Prefix of the control routes (`/teamrouter/status`, …). */
export const ROUTE_PREFIX = `/${NAME}`;
export const LEGACY_ROUTE_PREFIX = `/${LEGACY_NAME}`;

/**
 * Read one of the proxy's own environment variables by its unprefixed name:
 * `envVar('CONFIG')` is `TEAMROUTER_CONFIG`, or `TEAMCLAUDE_CONFIG` when only
 * that one is set. A variable that is set wins over one that is not, even
 * when set to the empty string, so a shell that exports `TEAMROUTER_HOST=`
 * to unset an inherited `TEAMCLAUDE_HOST` gets what it asked for; callers
 * that treat the empty string as "not given" (`|| default`) still do.
 *
 * @param {string} name  the part after the prefix, e.g. 'CONFIG'
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {string|undefined}
 */
export function envVar(name, env = process.env) {
  const renamed = env[ENV_PREFIX + name];
  return renamed !== undefined ? renamed : env[LEGACY_ENV_PREFIX + name];
}

/**
 * The legacy spelling of a control-route URL given in the new one, or null
 * when `url` is not under the new prefix. `/teamrouter/status?x` becomes
 * `/teamclaude/status?x`; `/teamrouterx` is not the prefix and stays as is.
 * The request handler rewrites with this once, at entry, so every control
 * route keeps matching the one spelling it always has.
 *
 * @param {string|undefined} url
 * @returns {string|null}
 */
export function legacyControlUrl(url) {
  if (!url || !url.startsWith(ROUTE_PREFIX)) return null;
  const rest = url.slice(ROUTE_PREFIX.length);
  if (rest !== '' && rest[0] !== '/' && rest[0] !== '?') return null;
  return LEGACY_ROUTE_PREFIX + rest;
}
