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

/** Which policy applies to a given set of claims. */
export type TokenKind = "access" | "id";

/** Base class for every token rejection this library raises. */
export class OidcError extends Error {
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
