/**
 * Post-login redirect validation.
 *
 * `returnTo` usually starts as attacker-influenced input (`/login?next=...`),
 * travels through the IdP inside the OAuth `state`, and comes back out of
 * `resolveSignin` to be redirected to — the textbook open-redirect shape,
 * and an especially useful one for phishing since the victim arrives already
 * authenticated. The `state` check doesn't help here: it protects against a
 * *foreign* authorization response, not a value the app itself put inside it.
 *
 * So the value is validated on the way in (`startSignin`) and again on the
 * way out (`resolveSignin`), since a stored `state` may predate this check or
 * come from a caller that bypassed `startSignin`.
 *
 * The default policy is "a path on this site and nothing else". Cross-origin
 * landings need {@link OidcCoreOptions.allowedReturnToOrigins} — an allowlist
 * rather than a flag, since "off" isn't a coherent middle ground here.
 */

import { OidcError } from "./errors";

/**
 * A relative `returnTo` is resolved against this to see where it would
 * actually navigate. `.invalid` is reserved by RFC 2606 and can never
 * resolve.
 */
const PROBE_ORIGIN = "https://return-to.invalid";

/**
 * Anything a browser would strip, normalize, or treat as a header break,
 * plus the backslash — which a URL parser reads as a slash, making it the
 * quiet way to write `//evil.example`.
 */
// biome-ignore lint/suspicious/noControlCharactersInRegex: catching them is the point
const FORBIDDEN_CHARACTERS = /[\u0000-\u0020\u007f\\]/;

/**
 * Thrown when a post-login redirect target is not one this configuration
 * permits. Raised by `startSignin` for a caller-supplied target, and by
 * `resolveSignin` for one read back out of the `state`.
 */
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
 * A relative target must be a path beginning with a single `/`. Checked by
 * resolving it against a probe origin and confirming the origin didn't
 * change — which is what catches the forms that only *look* relative:
 * `//evil.example`, and `/\evil.example` (backslash read as a second slash).
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

  // Checked before the allowlist: `blob:https://app.example.com/…` reports
  // the *inner* URL's origin, so an origin match alone would pass a scheme
  // this policy never meant to permit.
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

  // The reverse of `user@evil.example` (already caught by the allowlist):
  // credentials *on* an allowed origin still disguise the navigation.
  if (absolute.username || absolute.password) {
    throw new OidcReturnToError(
      returnTo,
      `refusing returnTo ("${returnTo}"): it embeds credentials, which disguise the origin it actually points at (${absolute.origin})`,
    );
  }
}

/**
 * Validates a post-login redirect target against {@link ReturnToPolicy} and
 * returns it unchanged, or throws {@link OidcReturnToError}.
 *
 * Accepts a same-site path (`"/dashboard"`) or, if listed in
 * {@link OidcCoreOptions.allowedReturnToOrigins}, an absolute `http`/`https`
 * URL. Call this on any `returnTo` value before using it — see
 * {@link OidcCore.startSignin} and {@link OidcCore.resolveSignin} for where
 * this library calls it.
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
 * Validates an absolute redirect URI — the app's own OAuth `redirect_uri` or
 * RP-initiated logout `post_logout_redirect_uri` — and returns it unchanged,
 * or throws {@link OidcReturnToError}.
 *
 * Weaker than {@link assertSafeReturnTo} on purpose: both values must be
 * registered with the provider, which is what actually decides where the
 * user can land, so there's no origin allowlist here. This only refuses what
 * a provider might echo back unvalidated: non-http(s) schemes
 * (`javascript:`, `data:`), embedded credentials, and control/space
 * characters.
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
