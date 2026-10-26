import { actorsOf, assertDelegationAllowed } from "../delegation";
import {
  attachRefreshedTokens,
  OidcInputError,
  OidcProviderUnavailableError,
  OidcSubjectError,
  OidcTokenValidationError,
  providerUnavailable,
  type RefreshedTokenSet,
  type TokenKind,
  type TokenValidationFailure,
} from "../errors";
import type { Logger } from "../logger";
import { assertTenantAllowed, resolvedIssuer } from "../tenant";
import {
  introspectTokens,
  looksLikeJwt,
  subjectOf,
  unverifiedSubject,
  verifyTokensLocally,
} from "../tokenValidation";
import {
  type AccessTokenClaims,
  type IdTokenClaims,
  mergeTokenClaims,
  parseOIDCUser,
} from "../types";
import type { CoreContext } from "./context";
import { jwtVerifyOptions } from "./grant";
import type { ProcessTokensInput, ProcessTokensResult } from "./options";

/**
 * `undefined` means the caller doesn't have this token at all and it's
 * skipped. Anything else, `null` or `""`, means the caller does have a
 * slot for it but it came out empty (an unset cookie read as `null`, a
 * template literal that resolved to `""`), which is a bug worth surfacing
 * rather than silently validating fewer tokens than intended.
 */
function assertOptionalToken(
  value: string | null | undefined,
  label: string,
): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0) {
    throw new OidcInputError(
      `processTokens was given a malformed \`${label}\`: expected a non-empty string, or \`undefined\` to omit it, got ${
        value === null ? "null" : JSON.stringify(value)
      }. Pass \`undefined\`, not \`null\`/\`""\`, when you don't have this token.`,
    );
  }
  return value;
}

/**
 * Warns once that a sender-constrained access token (one with a `cnf`
 * claim, i.e. DPoP or mTLS bound) is being accepted as a plain bearer
 * token, since this library has no request to check the proof against.
 */
function createSenderConstrainedWarning(log: Logger) {
  let warned = false;
  return (claims: AccessTokenClaims): void => {
    if (warned) return;
    const cnf = (claims as Record<string, unknown> | undefined)?.cnf;
    if (cnf === undefined || cnf === null) return;
    warned = true;
    log.warn(
      '[oidc] this access token carries a "cnf" claim: the issuer bound it to a key (DPoP or mTLS), and that binding is not being checked. Validating it needs the proof that travels with the HTTP request, which this library never sees. The token is accepted as an ordinary bearer token, so a stolen one is usable by anyone. Verify the proof at your edge if you accept tokens from callers you do not control.',
    );
  };
}

/** The tokens one validation pass looks at. */
type TokenPair = { access?: string; id?: string };

/** What one validation pass established about a {@link TokenPair}. */
type Validation = {
  access: AccessTokenClaims;
  id: IdTokenClaims;
  failures: TokenValidationFailure[];
  /** A token failed local verification only because it expired. */
  expired: boolean;
};

/** The checked arguments of one `processTokens` call. */
type ProcessTokensRequest = {
  tokens: TokenPair;
  refreshToken: string | undefined;
  subject: string | undefined;
};

function readProcessTokensInput(
  input: ProcessTokensInput,
): ProcessTokensRequest {
  const access = assertOptionalToken(input.access_token, "access_token");
  const id = assertOptionalToken(input.id_token, "id_token");
  const refreshToken = assertOptionalToken(
    input.refresh_token,
    "refresh_token",
  );
  if (!access && !id) {
    throw new OidcInputError(
      "processTokens needs an access token, an id token, or both. Validating neither is meaningless",
    );
  }
  const { subject } = input;
  if (subject !== undefined && (typeof subject !== "string" || !subject)) {
    throw new OidcInputError(
      "processTokens was given a `subject` that is not a non-empty string",
    );
  }
  return { tokens: { access, id }, refreshToken, subject };
}

/** The supplied tokens that no strategy validated. */
function unvalidatedKinds(
  tokens: TokenPair,
  validation: Validation,
): TokenKind[] {
  const kinds: TokenKind[] = [];
  if (tokens.access && !validation.access) kinds.push("access");
  if (tokens.id && !validation.id) kinds.push("id");
  return kinds;
}

/**
 * A refresh only helps when the tokens were the problem. If the provider
 * couldn't be reached, it would spend the refresh token on a set that
 * can't validate either.
 */
function worthRefreshing(tokens: TokenPair, validation: Validation): boolean {
  const unvalidated = unvalidatedKinds(tokens, validation);
  return (
    unvalidated.length > 0 &&
    !providerUnavailable(unvalidated, validation.failures)
  );
}

/**
 * Builds `processTokens`: validates an access and/or id token, falling
 * back from local JWKS verification to introspection, and refreshing once
 * if needed.
 *
 * Pass a `refresh_token` so an expired or unverifiable token set can be
 * refreshed automatically. Pass `subject` (the `sub` you have on file) so a
 * refresh can't quietly hand back a different user's tokens. Without it,
 * a mismatch only logs a warning.
 *
 * When {@link ProcessTokensResult.refreshed} is `true`, persist
 * `refreshedTokens` in place of the old token set. If this throws after a
 * refresh happened, the new token set is attached to the error as
 * `err.refreshedTokens`. Persist that too, or the session gets stuck.
 *
 * Call this once per request, not concurrently for the same session:
 * concurrent calls against an expired token set can each try to spend the
 * same refresh token, and some providers revoke the whole session when
 * that happens.
 */
export function createProcessTokens(
  ctx: CoreContext,
  refresh: (args: { refreshToken: string }) => Promise<RefreshedTokenSet>,
) {
  const warnIfSenderConstrained = createSenderConstrainedWarning(ctx.log);

  function assertVerifiedClaims(claims: unknown, tokenKind: TokenKind): void {
    assertTenantAllowed(claims, tokenKind, ctx.tenantPolicy);
    assertDelegationAllowed(claims, tokenKind, ctx.delegationPolicy);
  }

  /** See {@link OidcCoreOptions.introspection}. */
  function worthIntrospecting(token: string | undefined): boolean {
    if (!token || ctx.introspectionMode === "never") return false;
    return (
      ctx.introspectionMode === "auto" || !ctx.jwks || !looksLikeJwt(token)
    );
  }

  /** Strategy 1, when the issuer has a JWKS to verify against. */
  async function verifyLocally(tokens: TokenPair): Promise<Validation> {
    if (!ctx.jwks) {
      return { access: undefined, id: undefined, failures: [], expired: false };
    }
    const local = await verifyTokensLocally(
      ctx.jwks,
      tokens,
      (tokenKind, token) => jwtVerifyOptions(ctx, tokenKind, token),
      ctx.tokenTypePolicy,
      ctx.audiencePolicy,
      assertVerifiedClaims,
      ctx.log,
    );
    return {
      access: local.accessTokenValue,
      id: local.idTokenValue,
      failures: local.failures,
      expired: local.expired,
    };
  }

  /** Strategy 2, for whichever tokens strategy 1 left unvalidated. */
  async function introspectRemaining(
    tokens: TokenPair,
    validation: Validation,
  ): Promise<Validation> {
    const which = {
      access: !validation.access && worthIntrospecting(tokens.access),
      id: !validation.id && worthIntrospecting(tokens.id),
    };
    if (!which.access && !which.id) return validation;

    ctx.log.debug(
      "[oidc] could not verify tokens locally, trying introspection...",
    );
    const introspected = await introspectTokens(
      ctx.config,
      tokens,
      which,
      ctx.tokenTypePolicy,
      ctx.audiencePolicy,
      assertVerifiedClaims,
      ctx.log,
    );
    return {
      access: validation.access ?? introspected.accessTokenValue,
      id: validation.id ?? introspected.idTokenValue,
      failures: validation.failures.concat(introspected.failures),
      expired: validation.expired,
    };
  }

  /**
   * One validation pass. An expired token with a refresh token at hand
   * goes straight to the refresh instead of also trying introspection.
   */
  async function validate(
    tokens: TokenPair,
    refreshable: boolean,
  ): Promise<Validation> {
    const local = await verifyLocally(tokens);
    if (local.expired && refreshable) return local;
    return introspectRemaining(tokens, local);
  }

  return async function processTokens(
    input: ProcessTokensInput,
  ): Promise<ProcessTokensResult> {
    const { tokens, refreshToken, subject } = readProcessTokensInput(input);
    let newTokens: RefreshedTokenSet | undefined;

    try {
      let current = tokens;
      let validation = await validate(current, !!refreshToken);
      // A caller-supplied subject is authoritative. Otherwise prefer what
      // the tokens verifiably claim over what they merely claim.
      const boundSubject =
        subject ??
        subjectOf(validation.access) ??
        subjectOf(validation.id) ??
        unverifiedSubject(tokens.id) ??
        unverifiedSubject(tokens.access);

      if (refreshToken && worthRefreshing(current, validation)) {
        ctx.log.debug(
          validation.expired
            ? "[oidc] token expired, refreshing directly..."
            : "[oidc] a token could not be validated, refreshing as a last resort...",
        );
        newTokens = await refresh({ refreshToken });
        current = { access: newTokens.access_token, id: newTokens.id_token };
        validation = await validate(current, true);
      }

      assertValidated(current, validation);
      const finalSubject = agreedSubject(validation);
      assertSessionSubject(finalSubject, {
        refreshed: !!newTokens,
        boundSubject,
        subject,
        log: ctx.log,
      });
      warnIfSenderConstrained(validation.access);
      return buildResult(validation, newTokens, {
        issuer: resolvedIssuer(
          ctx.issuer,
          ctx.tenantPolicy,
          validation.access,
          validation.id,
        ),
        finalSubject,
        log: ctx.log,
      });
    } catch (err) {
      throw attachRefreshedTokens(err, newTokens);
    }
  };
}

/** Throws unless every supplied token validated. */
function assertValidated(tokens: TokenPair, validation: Validation): void {
  const unvalidated = unvalidatedKinds(tokens, validation);
  if (!unvalidated.length) return;
  throw providerUnavailable(unvalidated, validation.failures)
    ? new OidcProviderUnavailableError(unvalidated, validation.failures)
    : new OidcTokenValidationError(unvalidated, validation.failures);
}

/** The subject the tokens name, throwing if the two name different ones. */
function agreedSubject(validation: Validation): string | undefined {
  const accessSub = subjectOf(validation.access);
  const idSub = subjectOf(validation.id);
  if (accessSub && idSub && accessSub !== idSub) {
    throw new OidcSubjectError(
      `subject in access token and id token do not match (${accessSub} vs ${idSub})`,
      accessSub,
      idSub,
    );
  }
  return accessSub ?? idSub;
}

/** Checks the tokens' subject against the one the session is bound to. */
function assertSessionSubject(
  finalSubject: string | undefined,
  {
    refreshed,
    boundSubject,
    subject,
    log,
  }: {
    refreshed: boolean;
    boundSubject: string | undefined;
    subject: string | undefined;
    log: Logger;
  },
): void {
  if (refreshed && !boundSubject) {
    log.warn(
      "[oidc] refreshed a token set whose original subject could not be determined. The supplied tokens were opaque or unreadable, so the refreshed set could not be checked against them. Pass `subject` to processTokens to enforce it.",
    );
  }
  if (!finalSubject) return;

  if (refreshed && boundSubject && finalSubject !== boundSubject) {
    throw new OidcSubjectError(
      `refresh returned a token set for a different subject (${finalSubject}) than the tokens it replaced (${boundSubject}). The refresh token does not belong to this session`,
      boundSubject,
      finalSubject,
    );
  }
  if (subject && finalSubject !== subject) {
    throw new OidcSubjectError(
      `the tokens describe subject ${finalSubject}, not the ${subject} they were presented for`,
      subject,
      finalSubject,
    );
  }
}

function buildResult(
  validation: Validation,
  newTokens: RefreshedTokenSet | undefined,
  {
    issuer,
    finalSubject,
    log,
  }: { issuer: string; finalSubject: string | undefined; log: Logger },
): ProcessTokensResult {
  const base = {
    user: parseOIDCUser({
      ...mergeTokenClaims(
        validation.access as Record<string, unknown> | undefined,
        validation.id as Record<string, unknown> | undefined,
        (claim) =>
          log.warn(
            `[oidc] the access token and the id token disagree on "${claim}" for subject ${finalSubject ?? "(unknown)"}. Using the id token's value, and dropping any verification flag that did not come with it. One of the two is stale.`,
          ),
      ),
      iss: issuer,
    }),
    accessTokenClaims: validation.access,
    idTokenClaims: validation.id,
    // Whoever is calling: the access token's chain when there is one.
    actors: validation.access
      ? actorsOf(validation.access, "access")
      : actorsOf(validation.id, "id"),
  };

  if (newTokens) {
    return { ...base, refreshed: true, refreshedTokens: newTokens };
  }
  return { ...base, refreshed: false };
}
