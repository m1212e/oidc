import {
  attachRefreshedTokens,
  OidcInputError,
  OidcSubjectError,
  OidcTokenValidationError,
  type RefreshedTokenSet,
  type TokenKind,
  type TokenValidationFailure,
} from "../errors";
import type { Logger } from "../logger";
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

export function createProcessTokens(
  ctx: CoreContext,
  refresh: (args: { refreshToken: string }) => Promise<RefreshedTokenSet>,
) {
  const warnIfSenderConstrained = createSenderConstrainedWarning(ctx.log);

  function worthIntrospecting(token: string): boolean {
    return (
      ctx.introspectionMode !== "never" &&
      (ctx.introspectionMode === "auto" || !ctx.jwks || !looksLikeJwt(token))
    );
  }

  return async function processTokens(
    input: ProcessTokensInput,
  ): Promise<ProcessTokensResult> {
    const access_token = assertOptionalToken(
      input.access_token,
      "access_token",
    );
    const id_token = assertOptionalToken(input.id_token, "id_token");
    const refresh_token = assertOptionalToken(
      input.refresh_token,
      "refresh_token",
    );
    const { subject } = input;

    if (!access_token && !id_token) {
      throw new OidcInputError(
        "processTokens needs an access token, an id token, or both. Validating neither is meaningless",
      );
    }
    if (subject !== undefined && (typeof subject !== "string" || !subject)) {
      throw new OidcInputError(
        "processTokens was given a `subject` that is not a non-empty string",
      );
    }

    let currentAccessToken = access_token;
    let currentIdToken = id_token;
    let newTokens: RefreshedTokenSet | undefined;
    let accessTokenValue: AccessTokenClaims;
    let idTokenValue: IdTokenClaims;
    let failures: TokenValidationFailure[] = [];
    let boundSubject =
      subject ?? unverifiedSubject(id_token) ?? unverifiedSubject(access_token);

    try {
      for (let attempt = 0; attempt < 2; attempt++) {
        accessTokenValue = undefined;
        idTokenValue = undefined;
        failures = [];
        let expired = false;

        if (ctx.jwks) {
          const local = await verifyTokensLocally(
            ctx.jwks,
            { access: currentAccessToken, id: currentIdToken },
            (tokenKind) => jwtVerifyOptions(ctx, tokenKind),
            ctx.tokenTypePolicy,
            ctx.audiencePolicy,
            ctx.log,
          );
          accessTokenValue = local.accessTokenValue;
          idTokenValue = local.idTokenValue;
          failures = local.failures;
          expired = local.expired;
        }

        const shortcutToRefresh = expired && !!refresh_token;

        if (!shortcutToRefresh) {
          const introspectAccess =
            !accessTokenValue &&
            !!currentAccessToken &&
            worthIntrospecting(currentAccessToken);
          const introspectId =
            !idTokenValue &&
            !!currentIdToken &&
            worthIntrospecting(currentIdToken);

          if (introspectAccess || introspectId) {
            ctx.log.debug(
              "[oidc] could not verify tokens locally, trying introspection...",
            );
            const introspected = await introspectTokens(
              ctx.config,
              { access: currentAccessToken, id: currentIdToken },
              { access: introspectAccess, id: introspectId },
              ctx.tokenTypePolicy,
              ctx.audiencePolicy,
              ctx.log,
            );
            accessTokenValue ??= introspected.accessTokenValue;
            idTokenValue ??= introspected.idTokenValue;
            failures = failures.concat(introspected.failures);
          }
        }

        if (!newTokens && !subject) {
          boundSubject =
            subjectOf(accessTokenValue) ??
            subjectOf(idTokenValue) ??
            boundSubject;
        }

        const allValidated =
          (!currentAccessToken || !!accessTokenValue) &&
          (!currentIdToken || !!idTokenValue);
        const shouldRefresh = !newTokens && !!refresh_token && !allValidated;
        if (!shouldRefresh) break;

        ctx.log.debug(
          expired
            ? "[oidc] token expired, refreshing directly..."
            : "[oidc] a token could not be validated, refreshing as a last resort...",
        );
        newTokens = await refresh({ refreshToken: refresh_token as string });
        currentAccessToken = newTokens.access_token;
        currentIdToken = newTokens.id_token;
      }

      return finalizeProcessTokens({
        currentAccessToken,
        currentIdToken,
        accessTokenValue,
        idTokenValue,
        failures,
        newTokens,
        boundSubject,
        subject,
        issuer: ctx.issuer,
        log: ctx.log,
        warnIfSenderConstrained,
      });
    } catch (err) {
      throw attachRefreshedTokens(err, newTokens);
    }
  };
}

function finalizeProcessTokens({
  currentAccessToken,
  currentIdToken,
  accessTokenValue,
  idTokenValue,
  failures,
  newTokens,
  boundSubject,
  subject,
  issuer,
  log,
  warnIfSenderConstrained,
}: {
  currentAccessToken: string | undefined;
  currentIdToken: string | undefined;
  accessTokenValue: AccessTokenClaims;
  idTokenValue: IdTokenClaims;
  failures: TokenValidationFailure[];
  newTokens: RefreshedTokenSet | undefined;
  boundSubject: string | undefined;
  subject: string | undefined;
  issuer: string;
  log: Logger;
  warnIfSenderConstrained: (claims: AccessTokenClaims) => void;
}): ProcessTokensResult {
  const unvalidated: TokenKind[] = [];
  if (currentAccessToken && !accessTokenValue) unvalidated.push("access");
  if (currentIdToken && !idTokenValue) unvalidated.push("id");
  if (unvalidated.length) {
    throw new OidcTokenValidationError(unvalidated, failures);
  }

  const accessSub = subjectOf(accessTokenValue);
  const idSub = subjectOf(idTokenValue);
  if (accessSub && idSub && accessSub !== idSub) {
    throw new OidcSubjectError(
      `subject in access token and id token do not match (${accessSub} vs ${idSub})`,
      accessSub,
      idSub,
    );
  }

  const finalSubject = accessSub ?? idSub;
  if (
    newTokens &&
    boundSubject &&
    finalSubject &&
    finalSubject !== boundSubject
  ) {
    throw new OidcSubjectError(
      `refresh returned a token set for a different subject (${finalSubject}) than the tokens it replaced (${boundSubject}). The refresh token does not belong to this session`,
      boundSubject,
      finalSubject,
    );
  }

  if (subject && finalSubject && finalSubject !== subject) {
    throw new OidcSubjectError(
      `the tokens describe subject ${finalSubject}, not the ${subject} they were presented for`,
      subject,
      finalSubject,
    );
  }

  if (newTokens && !boundSubject) {
    log.warn(
      "[oidc] refreshed a token set whose original subject could not be determined. The supplied tokens were opaque or unreadable, so the refreshed set could not be checked against them. Pass `subject` to processTokens to enforce it.",
    );
  }

  warnIfSenderConstrained(accessTokenValue);

  const base = {
    user: parseOIDCUser({
      ...mergeTokenClaims(
        accessTokenValue as Record<string, unknown> | undefined,
        idTokenValue as Record<string, unknown> | undefined,
        (claim) =>
          log.warn(
            `[oidc] the access token and the id token disagree on "${claim}" for subject ${finalSubject ?? "(unknown)"}. Using the id token's value, and dropping any verification flag that did not come with it. One of the two is stale.`,
          ),
      ),
      iss: issuer,
    }),
    accessTokenClaims: accessTokenValue,
    idTokenClaims: idTokenValue,
  };

  if (newTokens) {
    return { ...base, refreshed: true, refreshedTokens: newTokens };
  }
  return { ...base, refreshed: false };
}
