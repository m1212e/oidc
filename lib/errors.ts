import type {
  TokenEndpointResponse,
  TokenEndpointResponseHelpers,
} from "openid-client";

export type TokenKind = "access" | "id";

export type RefreshedTokenSet = TokenEndpointResponse &
  TokenEndpointResponseHelpers;

export class OidcError extends Error {
  refreshedTokens?: RefreshedTokenSet;

  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "OidcError";
  }
}

export class OidcInputError extends OidcError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "OidcInputError";
  }
}

export class OidcTokenError extends OidcError {
  readonly tokenKind: TokenKind;
  readonly claim: string;

  constructor(tokenKind: TokenKind, claim: string, message: string) {
    super(message);
    this.name = "OidcTokenError";
    this.tokenKind = tokenKind;
    this.claim = claim;
  }
}

export type TokenValidationFailure = {
  tokenKind: TokenKind;
  stage: string;
  error: unknown;
  /**
   * The provider couldn't be asked: the key set fetch or the introspection
   * request failed. Says nothing about the token itself.
   */
  transient: boolean;
};

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export class OidcTokenValidationError extends OidcError {
  readonly tokenKinds: readonly TokenKind[];
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
 * Thrown instead of a plain {@link OidcTokenValidationError} when a token
 * couldn't be validated because the provider couldn't be reached (its key
 * set or introspection endpoint failed), not because anything was wrong
 * with the token. The refresh token was not spent on it.
 *
 * Answer 503 and keep the session: the same tokens may well validate once
 * the provider is back.
 */
export class OidcProviderUnavailableError extends OidcTokenValidationError {
  constructor(
    tokenKinds: readonly TokenKind[],
    failures: readonly TokenValidationFailure[],
  ) {
    super(tokenKinds, failures);
    this.name = "OidcProviderUnavailableError";
    this.message = `the identity provider could not be reached, so ${this.message}`;
  }
}

/**
 * Whether every one of these unvalidated tokens failed only because the
 * provider couldn't be reached. Refreshing wouldn't help those: the new
 * tokens would need the same provider to validate. One token that failed
 * for a reason of its own makes it an ordinary validation failure, or a
 * forged token next to an unreachable endpoint would pass for an outage.
 */
export function providerUnavailable(
  tokenKinds: readonly TokenKind[],
  failures: readonly TokenValidationFailure[],
): boolean {
  return tokenKinds.every((kind) => {
    const own = failures.filter((failure) => failure.tokenKind === kind);
    return own.length > 0 && own.every((failure) => failure.transient);
  });
}

/**
 * Thrown when the access and id token name different subjects, or a refresh
 * returned a token set for someone other than the caller's session.
 *
 * Never carries {@link OidcError.refreshedTokens}: don't persist a token
 * set minted for the wrong subject.
 */
export class OidcSubjectError extends OidcError {
  readonly expected: string;
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
 * a token exchange the provider doesn't permit, network fault). The
 * provider's own error is available as `cause`.
 */
export class OidcGrantError extends OidcError {
  /** Which exchange failed. */
  readonly grant: "authorization_code" | "refresh_token" | "token_exchange";

  constructor(
    grant: "authorization_code" | "refresh_token" | "token_exchange",
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "OidcGrantError";
    this.grant = grant;
  }
}

export class OidcStateError extends OidcError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "OidcStateError";
  }
}

export class OidcClaimsError extends OidcError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "OidcClaimsError";
  }
}

export class OidcUserInfoError extends OidcError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "OidcUserInfoError";
  }
}

export class OidcLogoutError extends OidcError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "OidcLogoutError";
  }
}

export function attachRefreshedTokens<E>(
  error: E,
  refreshedTokens?: RefreshedTokenSet,
): E {
  if (
    refreshedTokens &&
    error instanceof OidcError &&
    // Tokens for a different subject must not be handed back for the caller to store.
    !(error instanceof OidcSubjectError)
  ) {
    error.refreshedTokens = refreshedTokens;
  }
  return error;
}
