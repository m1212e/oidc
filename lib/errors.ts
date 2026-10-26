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

export class OidcGrantError extends OidcError {
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
