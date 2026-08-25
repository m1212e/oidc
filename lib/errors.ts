import type {
  TokenEndpointResponse,
  TokenEndpointResponseHelpers,
} from "openid-client";

/** Which policy applies to a given set of claims. */
export type TokenKind = "access" | "id";

/** A token-endpoint response with `openid-client`'s claim/expiry helpers. */
export type RefreshedTokenSet = TokenEndpointResponse &
  TokenEndpointResponseHelpers;

/**
 * Base class for every error this library raises. Catch this to treat any
 * rejection — a bad token, a failed grant, a stale OAuth state — as "this
 * login/session needs to be redone", typically by answering 401 or restarting
 * the flow.
 */
export class OidcError extends Error {
  /**
   * A token set minted while handling the call that went on to throw.
   *
   * `processTokens` may spend the refresh token before a later check rejects
   * the result; if the provider rotates refresh tokens, the one you passed in
   * is already dead. Persist this exactly as you would a successful
   * `refreshedTokens` result before handling the error, or the session becomes
   * unrecoverable. Never set on {@link OidcSubjectError}, whose token set
   * belongs to someone else and must not be stored.
   */
  refreshedTokens?: RefreshedTokenSet;

  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "OidcError";
  }
}

/**
 * A token this client must permanently refuse: it names another client, or
 * isn't the kind of token it was presented as. The validation fallback chain
 * stops on this rather than trying another strategy or spending a refresh.
 */
export class OidcTokenError extends OidcError {
  readonly tokenKind: TokenKind;
  /** The claim or header that failed, for logging — `"aud"`, `"azp"`, `"typ"`, ... */
  readonly claim: string;

  constructor(tokenKind: TokenKind, claim: string, message: string) {
    super(message);
    this.name = "OidcTokenError";
    this.tokenKind = tokenKind;
    this.claim = claim;
  }
}

/** One strategy's failure to validate one token, kept for diagnostics. */
export type TokenValidationFailure = {
  tokenKind: TokenKind;
  /** The strategy that failed — `"JWT verification"` or `"introspection"`. */
  stage: string;
  error: unknown;
};

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * A token the caller supplied could not be validated by any strategy, and no
 * refresh could replace it. Carries every strategy's failure — each is only
 * logged at debug level individually, so this is the one place a caller can
 * see the full cause.
 */
export class OidcTokenValidationError extends OidcError {
  /** The supplied tokens that never validated. */
  readonly tokenKinds: readonly TokenKind[];
  /** Every recorded failure for those tokens, in the order they occurred. */
  readonly failures: readonly TokenValidationFailure[];

  constructor(
    tokenKinds: readonly TokenKind[],
    failures: readonly TokenValidationFailure[],
  ) {
    const relevant = failures.filter((failure) =>
      tokenKinds.includes(failure.tokenKind),
    );
    const detail = relevant.length
      ? relevant
          .map(
            (failure) =>
              `${failure.tokenKind} token ${failure.stage} failed (${describe(failure.error)})`,
          )
          .join("; ")
      : "no validation strategy was available for it";

    super(
      `could not validate the ${tokenKinds.join(" and ")} token${tokenKinds.length > 1 ? "s" : ""}: ${detail}`,
      { cause: relevant[0]?.error },
    );
    this.name = "OidcTokenValidationError";
    this.tokenKinds = tokenKinds;
    this.failures = relevant;
  }
}

/**
 * The tokens in play don't all describe the same user — the access and id
 * token name different subjects, or a refresh returned a token set for
 * someone other than the caller's session.
 *
 * Never carries {@link OidcError.refreshedTokens}: a set minted for the wrong
 * subject is not one the caller may persist.
 */
export class OidcSubjectError extends OidcError {
  /** The subject the token set was bound to. */
  readonly expected: string;
  /** The subject that turned up instead. */
  readonly actual: string;

  constructor(message: string, expected: string, actual: string) {
    super(message);
    this.name = "OidcSubjectError";
    this.expected = expected;
    this.actual = actual;
  }
}

/**
 * A token-endpoint exchange the provider refused, or that couldn't be made at
 * all — an expired authorization code, a mismatched `state`, an expired or
 * revoked refresh token, a network fault. The provider's own error is kept as
 * `cause`.
 *
 * Exists so ordinary session failures (an expired refresh token is the most
 * common one in production) stay inside this error hierarchy instead of
 * surfacing as `openid-client`'s own error type.
 */
export class OidcGrantError extends OidcError {
  /** Which exchange failed. */
  readonly grant: "authorization_code" | "refresh_token";

  constructor(
    grant: "authorization_code" | "refresh_token",
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "OidcGrantError";
    this.grant = grant;
  }
}

/**
 * The OAuth `state` this library round-trips could not be read back — a
 * truncated cookie, a value from another library, or one rewritten in
 * transit.
 */
export class OidcStateError extends OidcError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "OidcStateError";
  }
}

/**
 * Validated claims could not be read as a user — most often a `sub` that is
 * absent (legal in an RFC 7662 introspection response) or not a string.
 */
export class OidcClaimsError extends OidcError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "OidcClaimsError";
  }
}

/**
 * A UserInfo request that failed, or whose response didn't describe the
 * subject it was asked about. The provider's own error is kept as `cause`.
 */
export class OidcUserInfoError extends OidcError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "OidcUserInfoError";
  }
}

/**
 * Attaches a token set minted before `error` was raised, so a caller handling
 * the rejection can still persist the refresh that already happened.
 *
 * Skips {@link OidcSubjectError} — see {@link OidcError.refreshedTokens} —
 * and applies to every other class by construction rather than an explicit
 * list, so a future error type isn't silently excluded.
 */
export function attachRefreshedTokens<E>(
  error: E,
  refreshedTokens?: RefreshedTokenSet,
): E {
  if (
    refreshedTokens &&
    error instanceof OidcError &&
    !(error instanceof OidcSubjectError)
  ) {
    error.refreshedTokens = refreshedTokens;
  }
  return error;
}
