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
 * Base class for every error this library throws. Catch this to treat any
 * failure (bad token, failed grant, stale OAuth state) as "this login or
 * session needs to be redone": answer 401, or restart the flow.
 */
export class OidcError extends Error {
  /**
   * A token set minted while handling the call that threw.
   *
   * If your provider rotates refresh tokens, a failed call can still have
   * spent the old one. Check this field and persist it just like a
   * successful `refreshedTokens` result, or the session becomes stuck.
   * Never set on {@link OidcSubjectError}.
   */
  refreshedTokens?: RefreshedTokenSet;

  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "OidcError";
  }
}

/**
 * Thrown when a per-request call was given input it cannot work with: a
 * token slot that is `null` or `""`, no token at all, a `subject` that
 * isn't a non-empty string.
 *
 * It is an {@link OidcError} on purpose. Usually it means the caller has
 * no usable session, which belongs on the same 401 path as a token that
 * failed to validate, not on the 500 path a bare `TypeError` would take.
 *
 * Startup mistakes are the other case, and stay a plain `TypeError`:
 * anything `createOidcCore` rejects (an empty `clientId`, an unparseable
 * `clockTolerance`, a bad `allowedReturnToOrigins` entry) is a bug in your
 * configuration that should stop the process, not answer a request.
 */
export class OidcInputError extends OidcError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "OidcInputError";
  }
}

/**
 * Thrown when a token names another client, or isn't the kind of token it
 * claims to be. Treat this as a permanent rejection, not a retryable error.
 */
export class OidcTokenError extends OidcError {
  readonly tokenKind: TokenKind;
  /** The claim or header that failed, e.g. `"aud"`, `"azp"`, `"typ"`. */
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
  /** The strategy that failed: `"JWT verification"` or `"introspection"`. */
  stage: string;
  error: unknown;
};

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Thrown when a supplied token couldn't be validated by any strategy and no
 * refresh could replace it. `failures` lists what each strategy tried and
 * why it failed, so you don't need to dig through debug logs to find out.
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
 * Thrown when the access and id token name different subjects, or a refresh
 * returned a token set for someone other than the caller's session.
 *
 * Never carries {@link OidcError.refreshedTokens}: don't persist a token
 * set minted for the wrong subject.
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
 * Thrown when a token-endpoint exchange was refused or failed to complete
 * (expired authorization code, mismatched `state`, expired refresh token,
 * network fault). The provider's own error is available as `cause`.
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
 * Thrown when the OAuth `state` this library round-trips can't be read back
 * (a truncated cookie, a value from another library, one rewritten in
 * transit).
 */
export class OidcStateError extends OidcError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "OidcStateError";
  }
}

/**
 * Thrown when validated claims can't be read as a user, most often a
 * missing or non-string `sub`.
 */
export class OidcClaimsError extends OidcError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "OidcClaimsError";
  }
}

/**
 * Thrown when a UserInfo request failed, or its response didn't describe
 * the subject it was asked about. The provider's own error is available as
 * `cause`.
 */
export class OidcUserInfoError extends OidcError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "OidcUserInfoError";
  }
}

/**
 * Thrown when an RP-initiated logout URL could not be built, almost always
 * because the issuer advertises no `end_session_endpoint`. Providers that
 * don't support RP-initiated logout need their own vendor-specific logout
 * URL instead. The underlying error is available as `cause`.
 */
export class OidcLogoutError extends OidcError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "OidcLogoutError";
  }
}

/**
 * Attaches a token set minted before `error` was thrown, so callers can
 * still persist a refresh that already happened. Skips
 * {@link OidcSubjectError}, see {@link OidcError.refreshedTokens}.
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
