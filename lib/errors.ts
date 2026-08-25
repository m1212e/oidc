/**
 * The rejections this library raises, split by whether anything could ever
 * make the token acceptable.
 *
 * {@link OidcTokenError} is a *permanent* rejection: the token is not one this
 * client may accept, whatever else is true of it, so the validation fallback
 * chain must stop rather than try another strategy or spend a refresh token.
 * {@link OidcTokenValidationError} is the other end — it is only thrown once
 * every strategy has already run and a token the caller supplied still did not
 * validate.
 */

import type {
  TokenEndpointResponse,
  TokenEndpointResponseHelpers,
} from "openid-client";

/** Which policy applies to a given set of claims. */
export type TokenKind = "access" | "id";

/** A token-endpoint response with `openid-client`'s claim/expiry helpers. */
export type RefreshedTokenSet = TokenEndpointResponse &
  TokenEndpointResponseHelpers;

/** Base class for every token rejection this library raises. */
export class OidcError extends Error {
  /**
   * A token set minted while handling the call that went on to throw.
   *
   * {@link OidcCore.processTokens} may spend the refresh token before a later
   * check rejects the result. Wherever the provider rotates refresh tokens the
   * one the caller passed in is dead from that moment on, so the replacement
   * has to reach the caller even on the failure path — otherwise the session is
   * unrecoverable, and on a provider with reuse detection retrying the old
   * token revokes the entire grant.
   *
   * Persist it exactly as you would `ProcessTokensResult.refreshedTokens`, then
   * handle the error as the rejection it is. Never set on
   * {@link OidcSubjectError}: a set minted for a different subject is not one
   * the caller may store.
   */
  refreshedTokens?: RefreshedTokenSet;

  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "OidcError";
  }
}

/**
 * A token this client must never accept: it names another client, or it is not
 * the kind of token it was presented as. Retrying cannot help, so the
 * validation fallback chain must not try another strategy or spend a refresh
 * token on it.
 */
export class OidcTokenError extends OidcError {
  readonly tokenKind: TokenKind;
  /** The claim or header that failed, for logging — `"aud"`, `"azp"`, `"at_hash"`, `"typ"`, ... */
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
 * refresh could replace it. Carries every failure that got it here, because
 * the individual strategies only log theirs at debug level — without this, an
 * unvalidatable token is a rejection with no stated cause.
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
 * The tokens in play do not all describe the same user — either the access and
 * id token name different subjects, or a refresh replaced the set with one
 * belonging to somebody other than the tokens that were passed in.
 *
 * Deliberately never carries {@link OidcError.refreshedTokens}: the set that
 * triggered this is not the caller's to persist, and storing it would swap the
 * session's identity for the one the mismatch was raised about.
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
 * A token-endpoint exchange the provider refused, or that could not be made at
 * all: an expired authorization code, a `state` that did not match the one the
 * callback carried, a refresh token that has expired or been revoked, a
 * network fault.
 *
 * Exists so that the routine failures of an ordinary session stay inside this
 * hierarchy. An expired refresh token is the single most common thing
 * {@link OidcCore.processTokens} meets in production, and without this it
 * surfaced as `openid-client`'s own error — so a caller catching
 * {@link OidcError} to answer 401 answered 500 instead, to a user who only
 * needed to log in again.
 *
 * The provider's own error (`invalid_grant`, ...) is preserved as `cause`.
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
 * truncated cookie, a value from another library, or one that was rewritten in
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
 * A UserInfo request that failed, or whose response did not describe the
 * subject it was asked about.
 *
 * Exists for the same reason {@link OidcGrantError} does: a UserInfo call is a
 * network exchange with the provider, and its failures — an access token the
 * OP no longer accepts, a `sub` that does not match the one asserted — are
 * ordinary things for a live session to meet. Without this they surfaced as
 * `openid-client`'s own errors, so a caller catching {@link OidcError} to
 * answer 401 answered 500 instead.
 *
 * The provider's own error is preserved as `cause`.
 */
export class OidcUserInfoError extends OidcError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "OidcUserInfoError";
  }
}

/**
 * Hands a token set minted before `error` was raised back to the caller, when
 * the error is one that may carry it.
 *
 * Every rejection in this hierarchy may carry it *except*
 * {@link OidcSubjectError} — see {@link OidcError.refreshedTokens} for why that
 * one must not. The rule is deliberately "all but one" rather than a list of
 * permitted classes: the obligation exists because the refresh token has
 * already been spent, which is true regardless of what went wrong afterwards.
 * A narrower list silently dropped the replacement for the failures nobody
 * thought to enumerate — a provider shape surprise raising
 * {@link OidcClaimsError}, say — and a dropped replacement is an unrecoverable
 * session, since the token the caller still has on file is dead.
 *
 * Argument errors (`TypeError`) are excluded by construction: they are raised
 * before anything is spent.
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
