/**
 * Post-login redirect validation.
 *
 * By default, `returnTo` must be a same-site path (e.g. `"/dashboard"`). To
 * allow redirecting to another origin after login, list it in
 * {@link OidcCoreOptions.allowedReturnToOrigins}.
 */

import { OidcError } from "./errors";

/** Used to resolve a relative `returnTo` and check where it actually navigates. */
const PROBE_ORIGIN = "https://return-to.invalid";

/**
 * Control characters, spaces, and backslashes (read as a slash by URL
 * parsers, so a quiet way to write `//evil.example`).
 */
// biome-ignore lint/suspicious/noControlCharactersInRegex: catching them is the point
const FORBIDDEN_CHARACTERS = /[\u0000-\u0020\u007f\\]/;

/** Thrown when a post-login redirect target isn't one this configuration permits. */
export class OidcReturnToError extends OidcError {
  /** The rejected value, for logging. Never redirect to it. */
  readonly returnTo: string;

  constructor(returnTo: string, message: string) {
    super(message);
    this.name = "OidcReturnToError";
    this.returnTo = returnTo;
  }
}

export type ReturnToPolicy = {
  /** Origins an absolute `returnTo` may name. Empty means same-site paths only. */
  allowedOrigins: readonly string[];
};

export function buildReturnToPolicy(opts: {
  allowedReturnToOrigins?: readonly string[];
}): ReturnToPolicy {
  const origins = (opts.allowedReturnToOrigins ?? []).map((entry) => {
    let origin: string;
    try {
      origin = new URL(entry).origin;
    } catch {
      throw new TypeError(
        `invalid allowedReturnToOrigins entry ("${entry}"): expected an absolute URL such as "https://app.example.com"`,
      );
    }
    if (origin === "null") {
      throw new TypeError(
        `invalid allowedReturnToOrigins entry ("${entry}"): this URL has no origin to compare against`,
      );
    }
    return origin;
  });
  return { allowedOrigins: origins };
}

function assertNoForbiddenCharacters(value: string): void {
  const forbidden = FORBIDDEN_CHARACTERS.exec(value);
  if (!forbidden) return;
  throw new OidcReturnToError(
    value,
    `invalid returnTo ("${value}"): contains ${
      forbidden[0] === "\\"
        ? "a backslash, which a URL parser reads as a slash"
        : `the character U+${value.codePointAt(forbidden.index)?.toString(16).padStart(4, "0").toUpperCase()}, which a browser would strip or refuse`
    }`,
  );
}

/**
 * A relative target must be a path beginning with a single `/`. Rejects
 * values that only look relative, like `//evil.example`.
 */
function assertSafeRelativeReturnTo(returnTo: string): void {
  let resolved: URL;
  try {
    resolved = new URL(returnTo, PROBE_ORIGIN);
  } catch {
    throw new OidcReturnToError(
      returnTo,
      `invalid returnTo ("${returnTo}"): not a usable path`,
    );
  }
  if (resolved.origin !== PROBE_ORIGIN) {
    throw new OidcReturnToError(
      returnTo,
      `refusing returnTo ("${returnTo}"): it looks relative but navigates to ${resolved.origin}. Only same-site paths are allowed unless the origin is listed in "allowedReturnToOrigins".`,
    );
  }
}

/**
 * An absolute target must be an `http`/`https` URL without embedded
 * credentials, on an origin the allowlist names.
 */
function assertSafeAbsoluteReturnTo(
  returnTo: string,
  policy: ReturnToPolicy,
): void {
  let absolute: URL;
  try {
    absolute = new URL(returnTo);
  } catch {
    throw new OidcReturnToError(
      returnTo,
      `invalid returnTo ("${returnTo}"): expected a path beginning with "/", or an absolute URL on an allowed origin`,
    );
  }

  if (absolute.protocol !== "https:" && absolute.protocol !== "http:") {
    throw new OidcReturnToError(
      returnTo,
      `refusing returnTo ("${returnTo}"): only http and https URLs may be redirected to`,
    );
  }

  if (!policy.allowedOrigins.includes(absolute.origin)) {
    throw new OidcReturnToError(
      returnTo,
      policy.allowedOrigins.length
        ? `refusing returnTo ("${returnTo}"): ${absolute.origin} is not one of the allowed origins (${policy.allowedOrigins.join(", ")})`
        : `refusing returnTo ("${returnTo}"): absolute redirect targets need their origin listed in "allowedReturnToOrigins". A same-site path such as "/dashboard" needs no configuration.`,
    );
  }

  if (absolute.username || absolute.password) {
    throw new OidcReturnToError(
      returnTo,
      `refusing returnTo ("${returnTo}"): it embeds credentials, which disguise the origin it actually points at (${absolute.origin})`,
    );
  }
}

/**
 * Validates a post-login redirect target and returns it unchanged, or
 * throws {@link OidcReturnToError}. Accepts a same-site path
 * (`"/dashboard"`) or, if listed in
 * {@link OidcCoreOptions.allowedReturnToOrigins}, an absolute `http`/`https`
 * URL. `startSignin` and `resolveSignin` already call this for you.
 */
export function assertSafeReturnTo(
  returnTo: string,
  policy: ReturnToPolicy,
): string {
  if (typeof returnTo !== "string" || returnTo.length === 0) {
    throw new OidcReturnToError(
      String(returnTo),
      'invalid returnTo: expected a non-empty path such as "/dashboard"',
    );
  }

  assertNoForbiddenCharacters(returnTo);

  if (returnTo.startsWith("/")) {
    assertSafeRelativeReturnTo(returnTo);
    return returnTo;
  }

  assertSafeAbsoluteReturnTo(returnTo, policy);
  return returnTo;
}

/**
 * Validates an absolute redirect URI (an OAuth `redirect_uri` or
 * `post_logout_redirect_uri`) and returns it unchanged, or throws
 * {@link OidcReturnToError}.
 */
export function assertSafeRedirectUri(uri: string, label: string): string {
  if (typeof uri !== "string" || uri.length === 0) {
    throw new OidcReturnToError(
      String(uri),
      `invalid ${label}: expected an absolute URL such as "https://app.example.com/callback"`,
    );
  }

  if (FORBIDDEN_CHARACTERS.test(uri)) {
    throw new OidcReturnToError(
      uri,
      `invalid ${label} ("${uri}"): contains a control character, a space or a backslash`,
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    throw new OidcReturnToError(
      uri,
      `invalid ${label} ("${uri}"): expected an absolute URL such as "https://app.example.com/callback"`,
    );
  }

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new OidcReturnToError(
      uri,
      `refusing ${label} ("${uri}"): only http and https URLs may be redirected to`,
    );
  }

  if (parsed.username || parsed.password) {
    throw new OidcReturnToError(
      uri,
      `refusing ${label} ("${uri}"): it embeds credentials, which disguise the origin it actually points at (${parsed.origin})`,
    );
  }

  return uri;
}
