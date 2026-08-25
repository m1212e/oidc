/**
 * Post-login redirect validation.
 *
 * `returnTo` is the one value in this library's flow that starts life as
 * whatever the application had lying around — very often a query parameter
 * (`/login?next=...`) — travels through the IdP inside the OAuth `state`, and
 * comes back out of {@link OidcCore.resolveSignin} to be handed to a redirect.
 * That is the textbook open-redirect shape: a post-login redirect is the most
 * useful kind for phishing, because the victim arrives at the attacker's page
 * having just authenticated and expecting to land somewhere trusted.
 *
 * The `state` check does not help. `state` protects against a *foreign*
 * authorization response being replayed at the callback; it says nothing about
 * a value the application itself put in there. Whatever went in comes back
 * intact, which is the entire point of it.
 *
 * So the value is validated where it enters ({@link OidcCore.startSignin}) and
 * again where it leaves ({@link OidcCore.resolveSignin}) — the second time
 * because a `state` may have been minted by an older version, by another
 * process with a different configuration, or by a caller that reached past
 * `startSignin`.
 *
 * The default policy is "a path on this site and nothing else". Cross-origin
 * landings need {@link OidcCoreOptions.allowedReturnToOrigins}, which is an
 * allowlist rather than a flag because "off" is not a coherent middle ground
 * here.
 */

import { OidcError } from "./errors";

/**
 * A relative `returnTo` is resolved against this to find out where it would
 * actually navigate. `.invalid` is reserved by RFC 2606 and can never resolve,
 * so nothing can be reached through it even if a value escapes.
 */
const PROBE_ORIGIN = "https://return-to.invalid";

/**
 * Anything a browser would strip, normalize, or treat as a header break —
 * control characters (`\n`, `\r`, `\t`, NUL, ...), space and `DEL` — plus the
 * backslash, which a URL parser reads as a slash and which is therefore the
 * quiet way to write `//evil.example`.
 */
// biome-ignore lint/suspicious/noControlCharactersInRegex: catching them is the point
const FORBIDDEN_CHARACTERS = /[\u0000-\u0020\u007f\\]/;

/**
 * Thrown when a post-login redirect target is not one this configuration
 * permits. Raised by {@link OidcCore.startSignin} for a target the caller
 * supplied, and by {@link OidcCore.resolveSignin} for one that came back out
 * of the `state`.
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

/**
 * Returns `returnTo` unchanged if it is a target this policy permits, and
 * throws {@link OidcReturnToError} otherwise.
 *
 * A relative target must be a path beginning with a single `/`, and is checked
 * by resolving it and confirming it did not change origin — which is what
 * catches the forms that only *look* relative: `//evil.example`, and
 * `/\evil.example`, whose backslash the URL parser reads as a second slash.
 * Query and fragment are left alone; they cannot move the navigation.
 *
 * An absolute target must be an `http`/`https` URL without embedded
 * credentials, on an origin the allowlist names. The scheme is checked
 * separately from the origin because the two are not the same question:
 * `blob:` and `filesystem:` URLs report the origin of the URL *inside* them,
 * so an origin match alone would let one through.
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

  const forbidden = FORBIDDEN_CHARACTERS.exec(returnTo);
  if (forbidden) {
    throw new OidcReturnToError(
      returnTo,
      `invalid returnTo ("${returnTo}"): contains ${
        forbidden[0] === "\\"
          ? "a backslash, which a URL parser reads as a slash"
          : `the character U+${returnTo.codePointAt(forbidden.index)?.toString(16).padStart(4, "0").toUpperCase()}, which a browser would strip or refuse`
      }`,
    );
  }

  if (returnTo.startsWith("/")) {
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
    return returnTo;
  }

  let absolute: URL;
  try {
    absolute = new URL(returnTo);
  } catch {
    throw new OidcReturnToError(
      returnTo,
      `invalid returnTo ("${returnTo}"): expected a path beginning with "/", or an absolute URL on an allowed origin`,
    );
  }

  // Checked before the allowlist, because an origin is not the whole of a URL:
  // `blob:https://app.example.com/…` reports the *inner* URL's origin, so a
  // scheme that is not a navigation this policy means to permit would otherwise
  // pass on the strength of an origin it only inherited.
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

  // `https://app.example.com@evil.example` is already refused by the allowlist,
  // which sees `evil.example` — but the reverse spelling of the same trick,
  // credentials *on* an allowed origin, is a navigation no application means to
  // hand a user, and it is refused for the app's own redirect URIs too. See
  // {@link assertSafeRedirectUri}.
  if (absolute.username || absolute.password) {
    throw new OidcReturnToError(
      returnTo,
      `refusing returnTo ("${returnTo}"): it embeds credentials, which disguise the origin it actually points at (${absolute.origin})`,
    );
  }

  return returnTo;
}

/**
 * Returns an absolute redirect URI unchanged if it is one a browser could
 * safely be sent to, and throws {@link OidcReturnToError} otherwise.
 *
 * This is the weaker sibling of {@link assertSafeReturnTo}, for the two URIs
 * that are the *application's own* rather than a landing spot chosen per
 * request: the OAuth `redirect_uri` and the RP-initiated logout's
 * `post_logout_redirect_uri`. Both must be registered with the provider, which
 * is the check that decides where the user may actually end up, so there is no
 * origin allowlist here — requiring one would mean every caller had to list
 * their own callback origin in `allowedReturnToOrigins` to log anybody in.
 *
 * What is left is still worth refusing outright, because both values land in a
 * URL this library hands back for a redirect and neither is guaranteed to be a
 * constant in the calling app:
 *
 * - a scheme other than `http`/`https` — `javascript:`, `data:` — which some
 *   providers will echo back into a `Location` unvalidated,
 * - embedded credentials (`https://app.example.com@evil.example`), the classic
 *   way to make a foreign origin read as a familiar one,
 * - control characters and spaces, which are the header-splitting shapes.
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
