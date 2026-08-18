import {
  createRemoteJWKSet,
  errors,
  type JWTVerifyOptions,
  jwtVerify,
} from "jose";
import {
  allowInsecureRequests,
  authorizationCodeGrant,
  buildAuthorizationUrl,
  buildEndSessionUrl,
  calculatePKCECodeChallenge,
  clockTolerance as clockToleranceOption,
  discovery,
  fetchUserInfo,
  randomNonce,
  randomPKCECodeVerifier,
  randomState,
  refreshTokenGrant,
  type TokenEndpointResponse,
  type TokenEndpointResponseHelpers,
  tokenIntrospection,
} from "openid-client";
import {
  type AudienceClaims,
  assertAudienceAfterJwtVerify,
  assertTokenAudience,
  audienceVerifyOption,
  buildAudiencePolicy,
  OidcAudienceError,
} from "./audience";
import {
  OidcTokenError,
  OidcTokenValidationError,
  type TokenKind,
  type TokenValidationFailure,
} from "./errors";
import { buildLogger, type Logger, type LogLevel } from "./logger";
import {
  assertTokenTypeAfterJwtVerify,
  assertTokenTypeFromClaims,
  buildTokenTypePolicy,
} from "./tokenType";
import {
  type AccessTokenClaims,
  type IdTokenClaims,
  parseOIDCFlowState,
  parseOIDCUser,
  type ValidationResult,
} from "./types";

export type OidcCoreOptions = {
  /** The OpenID Provider's issuer URL, used for discovery. */
  issuer: string;
  clientId: string;
  /** Omit for a public client (no client secret, PKCE-only). */
  clientSecret?: string;
  /**
   * Audience value(s) this resource server answers to, matched against an
   * access token's `aud`. Leave unset when the provider puts no resource
   * audience on access tokens — stock Keycloak (`aud: "account"`) and Cognito
   * (no `aud` at all) both need the authorized-party claim instead.
   *
   * Setting this makes the `aud` match the whole of the access-token binding,
   * so {@link authorizedPartyClaims} stops being compared to
   * {@link clientId}: an API is a different party from the client that called
   * it, and requiring both rejects every ordinary API/SPA split. Tokens from
   * any client the IdP lets request this audience are then accepted — supply
   * {@link verifyAudience} if you also need to restrict which client that was.
   *
   * Never compared against ID tokens, whose `aud` is always the client id.
   */
  expectedAudience?: string | string[];
  /**
   * Claims that may name the client an access token was issued to, in
   * priority order — the first one present must equal {@link clientId}.
   * Defaults to `["azp", "client_id", "cid", "appid"]`, which covers
   * RFC 9068, Keycloak, Auth0, Entra ID, Okta and Cognito.
   *
   * This is the binding used when {@link expectedAudience} is unset; with a
   * resource audience configured, that takes over and these are not consulted.
   */
  authorizedPartyClaims?: readonly string[];
  /**
   * Escape hatch for providers none of the above fits: replaces the built-in
   * audience policy entirely. Return `false` to reject the token.
   */
  verifyAudience?: (claims: AudienceClaims, tokenKind: TokenKind) => boolean;
  /**
   * Claims whose presence proves a JWT is an ID token, so a token presented as
   * an *access* token carrying any of them is rejected outright. Defaults to
   * `["nonce", "at_hash", "c_hash", "s_hash"]`.
   *
   * Only set this — to `[]`, or to a narrower list — if your provider is known
   * to put one of them on access tokens; some older Keycloak versions copied
   * `nonce` onto theirs.
   */
  idTokenOnlyClaims?: readonly string[];
  /**
   * Require this exact `typ` header on JWT access tokens: `"at+jwt"` for an
   * RFC 9068 provider, `"Bearer"` for Keycloak. The `application/` prefix is
   * optional either way.
   *
   * Unset by default, because Auth0 and Entra ID send a plain `"JWT"` on both
   * token kinds, leaving nothing to pin. Set it wherever your provider does
   * distinguish them: it is the only *complete* defence against an ID token
   * being replayed as an access token, since {@link idTokenOnlyClaims} can
   * only catch ID tokens that happen to carry one of those claims.
   */
  accessTokenTyp?: string;
  /**
   * Clock skew tolerance for `exp`/`nbf`, in seconds or as a duration string
   * (`"30 seconds"`, `"5m"`). Defaults to 30s — with no tolerance, ordinary
   * drift between your host and the IdP produces spurious expiry failures,
   * which this library answers by spending a refresh token.
   *
   * Applies to every timestamp this library checks: offline verification in
   * {@link OidcCore.processTokens} and the ID token validated inside the code
   * exchange and refresh alike.
   */
  clockTolerance?: string | number;
  /**
   * JWS algorithms accepted when verifying tokens offline. Defaults to the
   * issuer's advertised `id_token_signing_alg_values_supported`. Set this
   * explicitly if your provider signs access tokens with an algorithm it does
   * not advertise for ID tokens — discovery has no separate metadata field
   * for access tokens.
   */
  signingAlgorithms?: string[];
  /**
   * Allows discovery/token requests over plain HTTP. Only ever set this for a
   * local/dev IdP — never in production.
   *
   * Left unset, it is derived from the environment: on only when `NODE_ENV`
   * is exactly `"development"`. An unset `NODE_ENV` counts as production,
   * because that is the common deployment case and this switch must fail
   * closed.
   */
  development?: boolean;
  logger?: Logger;
  logLevel?: LogLevel;
};

export type StartSigninResult = {
  codeVerifier: string;
  authorizationUrl: URL;
  /** Opaque — pass through unchanged to the OAuth `state` param and back to {@link resolveSignin}. */
  state: string;
};

export type ResolveSigninResult = {
  tokens: TokenEndpointResponse & TokenEndpointResponseHelpers;
  /** The URL the user was trying to reach before being sent to the IdP. */
  returnTo: string;
};

/** At least one of the two tokens must be present — validating neither is meaningless. */
export type ProcessTokensInput =
  | { access_token: string; id_token?: string; refresh_token?: string }
  | { access_token?: string; id_token: string; refresh_token?: string };

/**
 * `refreshed` discriminates `refreshedTokens`: narrowing on it
 * (`if (result.refreshed)`) gives a definite token set, not `T | undefined` —
 * persist it in place of the old token set whenever `refreshed` is `true`.
 */
export type ProcessTokensResult = ValidationResult &
  (
    | {
        refreshed: true;
        refreshedTokens: TokenEndpointResponse & TokenEndpointResponseHelpers;
      }
    | { refreshed: false; refreshedTokens?: undefined }
  );

/**
 * Resolves {@link OidcCoreOptions.development} against the environment when it
 * was not passed explicitly.
 *
 * Only an exact `NODE_ENV=development` enables it. Deliberately not
 * `NODE_ENV !== "production"`: the variable is frequently unset in production,
 * and guessing wrong here means silently permitting plain-HTTP traffic to the
 * IdP. `process` itself is checked because it is absent on edge runtimes.
 */
export function resolveDevelopment(development?: boolean): boolean {
  if (development !== undefined) return development;
  if (typeof process === "undefined") return false;
  return process.env?.NODE_ENV === "development";
}

/** jose's duration grammar, minus the signed/relative forms a tolerance cannot use. */
const DURATION_MULTIPLIERS: Record<string, number> = {
  s: 1,
  m: 60,
  h: 3600,
  d: 86400,
  w: 604800,
  y: 31557600,
};
const DURATION =
  /^(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)$/i;

/**
 * Resolves {@link OidcCoreOptions.clockTolerance} to whole seconds.
 *
 * jose takes either a number or a duration string, `openid-client` only takes
 * seconds, and the two must agree — a tolerance that applied to offline
 * verification but not to the code exchange would leave exactly the drift it
 * exists to absorb able to fail a login.
 */
export function resolveClockTolerance(
  clockTolerance?: string | number,
): number {
  if (clockTolerance === undefined) return 30;

  if (typeof clockTolerance === "number") {
    if (!Number.isFinite(clockTolerance) || clockTolerance < 0) {
      throw new TypeError(
        `invalid clockTolerance (${clockTolerance}): expected a non-negative number of seconds`,
      );
    }
    return clockTolerance;
  }

  const matched = DURATION.exec(clockTolerance.trim());
  if (!matched) {
    throw new TypeError(
      `invalid clockTolerance ("${clockTolerance}"): expected seconds as a number, or a duration such as "30 seconds" or "5m"`,
    );
  }
  const unit = (matched[2] as string)[0]?.toLowerCase() as string;
  return Math.round(
    Number.parseFloat(matched[1] as string) *
      (DURATION_MULTIPLIERS[unit] as number),
  );
}

/**
 * Discovers an OIDC issuer and returns the framework-agnostic operations
 * needed to implement a login: PKCE authorization-code flow, offline token
 * validation with a graceful fallback chain (JWKS → introspection), refresh,
 * and RP-initiated logout.
 */
export async function createOidcCore(opts: OidcCoreOptions) {
  const log = buildLogger(opts.logger, opts.logLevel);
  const development = resolveDevelopment(opts.development);

  if (development) {
    log.warn(
      "[oidc] development mode is on: plain-HTTP requests to the IdP are allowed. Never enable this in production.",
    );
  }

  const clockTolerance = resolveClockTolerance(opts.clockTolerance);

  const config = await discovery(
    new URL(opts.issuer),
    opts.clientId,
    {
      client_secret: opts.clientSecret,
      token_endpoint_auth_method: opts.clientSecret ? undefined : "none",
      // Carries the tolerance into `openid-client`'s own timestamp checks —
      // the ID token it validates during the code exchange and every refresh.
      [clockToleranceOption]: clockTolerance,
    },
    undefined,
    { execute: development ? [allowInsecureRequests] : [] },
  );

  const jwksUri = config.serverMetadata().jwks_uri;
  const jwks = jwksUri ? createRemoteJWKSet(new URL(jwksUri)) : undefined;
  const issuer = config.serverMetadata().issuer;
  const audiencePolicy = buildAudiencePolicy(opts);
  const tokenTypePolicy = buildTokenTypePolicy(opts);

  const signingAlgorithms =
    opts.signingAlgorithms ??
    config
      .serverMetadata()
      .id_token_signing_alg_values_supported?.filter((alg) => alg !== "none");

  /**
   * Everything jose can check on its own, so this library doesn't reimplement
   * it: signature, `iss`, `aud`, expiry with skew tolerance, required claim
   * presence and algorithm pinning. What is left to this library is the
   * OIDC-specific authorized-party rule ({@link assertAudienceAfterJwtVerify})
   * and the token-type binding jose has no concept of
   * ({@link assertTokenTypeAfterJwtVerify}).
   */
  function jwtVerifyOptions(tokenKind: TokenKind): JWTVerifyOptions {
    return {
      issuer,
      audience: audienceVerifyOption(audiencePolicy, tokenKind),
      clockTolerance,
      algorithms: signingAlgorithms,
      // `issuer`/`audience` already force `iss`/`aud` presence. `exp` matters
      // most: without it jose happily accepts a token that never expires.
      requiredClaims:
        tokenKind === "id"
          ? ["iss", "sub", "aud", "exp", "iat"]
          : ["iss", "sub", "exp"],
    };
  }

  /**
   * `authorizationCodeGrant`/`refreshTokenGrant` already validate the ID
   * token's `aud`, but only consult `azp` when `aud` is a multi-element array.
   * Re-running our own policy closes that gap for the single-audience case.
   */
  function assertGrantedIdToken(
    tokens: TokenEndpointResponse & TokenEndpointResponseHelpers,
  ) {
    const claims = tokens.claims();
    if (claims) {
      assertTokenAudience(claims as AudienceClaims, "id", audiencePolicy);
    }
  }

  async function startSignin({
    redirectUri,
    returnTo,
    scope = "openid profile email",
  }: {
    /** The OAuth `redirect_uri` — this app's own callback endpoint. */
    redirectUri: string;
    /** Where to send the user after a successful login. */
    returnTo: string;
    /**
     * Space-separated OAuth scopes to request. Defaults to `"openid profile email"`.
     */
    scope?: string;
  }): Promise<StartSigninResult> {
    const codeVerifier = randomPKCECodeVerifier();
    const codeChallenge = await calculatePKCECodeChallenge(codeVerifier);
    // A value of its own rather than a second use of `random`: the two have
    // different jobs and different exposure, and sharing one across both is a
    // well-known anti-pattern.
    const nonce = randomNonce();
    const state = JSON.stringify({
      visitedUrl: returnTo,
      random: randomState(),
      nonce,
    });

    const authorizationUrl = buildAuthorizationUrl(config, {
      redirect_uri: redirectUri,
      scope,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state,
      nonce,
    });

    return { codeVerifier, authorizationUrl, state };
  }

  async function resolveSignin(
    callbackUrl: URL,
    codeVerifier: string,
    expectedState: string,
  ): Promise<ResolveSigninResult> {
    const parsedState = parseOIDCFlowState(JSON.parse(expectedState));
    const tokens = await authorizationCodeGrant(config, callbackUrl, {
      pkceCodeVerifier: codeVerifier,
      expectedState,
      // Binds the ID token to this authorization request. `undefined` is not
      // "unchecked": it makes `openid-client` require the ID token to carry no
      // `nonce` at all, which is the right expectation for a login started
      // before {@link OIDCFlowState.nonce} existed.
      expectedNonce: parsedState.nonce,
      // An ID token is the point of asking for `openid` scope, so a response
      // without one is a provider fault rather than a login with no subject.
      // Implied by a string `expectedNonce`, set explicitly so the guarantee
      // does not depend on one being present.
      idTokenExpected: true,
    });
    assertGrantedIdToken(tokens);
    return { tokens, returnTo: parsedState.visitedUrl };
  }

  async function refresh(refreshToken: string) {
    const tokens = await refreshTokenGrant(config, refreshToken);
    assertGrantedIdToken(tokens);
    return tokens;
  }

  /**
   * Runs the offline-first validation fallback chain (JWKS → introspection).
   * A JWKS failure specifically due to token expiry skips introspection and
   * refreshes immediately instead — introspection would either fail the same
   * way or waste a round trip on a token that's simply stale. Refreshing
   * supersedes both tokens, so this applies even if only one of the two had
   * expired. Any other failure mode (bad signature, unknown key, network
   * error, ...) still runs the full chain before falling back to a refresh.
   *
   * **Every token passed in must validate.** If one of them survives no
   * strategy and no refresh replaces it, this throws
   * {@link OidcTokenValidationError} rather than returning the other one's
   * claims — a result whose `accessTokenClaims` is missing because the access
   * token failed verification is indistinguishable from one where no access
   * token was supplied, which would leave the caller treating a token nobody
   * could validate as if it had been.
   *
   * The caller must persist {@link ProcessTokensResult.refreshedTokens} when
   * {@link ProcessTokensResult.refreshed} is `true`.
   */
  async function processTokens({
    access_token,
    id_token,
    refresh_token,
  }: ProcessTokensInput): Promise<ProcessTokensResult> {
    let currentAccessToken = access_token;
    let currentIdToken = id_token;
    let newTokens:
      | (TokenEndpointResponse & TokenEndpointResponseHelpers)
      | undefined;
    let accessTokenValue: AccessTokenClaims;
    let idTokenValue: IdTokenClaims;
    // Why the tokens of the *latest* attempt failed, for the error thrown at
    // the end. Reset per attempt: once a refresh has replaced the token set,
    // what the old one failed on says nothing about the new one.
    let failures: TokenValidationFailure[] = [];

    if (!currentAccessToken && !currentIdToken) {
      throw new TypeError(
        "processTokens needs an access token, an id token, or both — validating neither is meaningless",
      );
    }

    // At most two passes: the tokens as given, and — only once refreshed —
    // the new token set. `newTokens` itself guards against looping further.
    for (let attempt = 0; attempt < 2; attempt++) {
      accessTokenValue = undefined;
      idTokenValue = undefined;
      failures = [];
      let expired = false;
      // A token that names another client, or that isn't the kind of token it
      // was presented as, is a permanent rejection rather than a transient
      // failure: no other strategy and no refresh can turn it into ours.
      // Captured here rather than thrown inside the `.catch` below, which
      // `Promise.allSettled` would swallow.
      let fatal: OidcTokenError | undefined;
      const onStrategyError =
        (kind: TokenKind, stage: string) => (err: unknown) => {
          if (err instanceof OidcTokenError) {
            fatal ??= err;
            return;
          }
          if (
            err instanceof errors.JWTClaimValidationFailed &&
            err.claim === "aud"
          ) {
            fatal ??= new OidcAudienceError(kind, "aud", err.message);
            return;
          }
          if (err instanceof errors.JWTExpired) expired = true;
          failures.push({ tokenKind: kind, stage, error: err });
          log.debug(
            `[oidc] ${kind} token ${stage} failed:`,
            (err as Error).message,
          );
        };

      // Strategy 1: verify locally against the issuer's JWKS.
      if (jwks) {
        const promises: Promise<void>[] = [];
        if (currentAccessToken) {
          promises.push(
            jwtVerify(currentAccessToken, jwks, jwtVerifyOptions("access"))
              .then((result) => {
                assertTokenTypeAfterJwtVerify(
                  result.payload as AudienceClaims,
                  result.protectedHeader,
                  "access",
                  tokenTypePolicy,
                );
                assertAudienceAfterJwtVerify(
                  result.payload as AudienceClaims,
                  "access",
                  audiencePolicy,
                );
                accessTokenValue = result.payload;
              })
              .catch(onStrategyError("access", "JWT verification")),
          );
        }
        if (currentIdToken) {
          promises.push(
            jwtVerify(currentIdToken, jwks, jwtVerifyOptions("id"))
              .then((result) => {
                assertTokenTypeAfterJwtVerify(
                  result.payload as AudienceClaims,
                  result.protectedHeader,
                  "id",
                  tokenTypePolicy,
                );
                assertAudienceAfterJwtVerify(
                  result.payload as AudienceClaims,
                  "id",
                  audiencePolicy,
                );
                idTokenValue = result.payload;
              })
              .catch(onStrategyError("id", "JWT verification")),
          );
        }
        await Promise.allSettled(promises);
        if (fatal) throw fatal;
      }

      const shortcutToRefresh = expired && !!refresh_token;

      if (!shortcutToRefresh) {
        // Strategy 2: fall back to remote introspection (opaque tokens, or
        // local verification failed for a reason other than expiry).
        if (
          (!accessTokenValue && currentAccessToken) ||
          (!idTokenValue && currentIdToken)
        ) {
          log.debug(
            "[oidc] could not verify tokens locally, trying introspection...",
          );
          const promises: Promise<void>[] = [];
          if (!accessTokenValue && currentAccessToken) {
            promises.push(
              tokenIntrospection(config, currentAccessToken)
                .then((result) => {
                  if (!result.active) {
                    throw new Error("access token is not active");
                  }
                  // A response has no JWS header to pin `typ` against, but if
                  // the AS echoed the claims of an ID token submitted here,
                  // those still give it away.
                  assertTokenTypeFromClaims(
                    result as AudienceClaims,
                    "access",
                    tokenTypePolicy,
                  );
                  // `active: true` only means "live at this AS", not "issued
                  // to you" — RFC 7662 §4 leaves that check to the caller.
                  assertTokenAudience(
                    result as AudienceClaims,
                    "access",
                    audiencePolicy,
                  );
                  accessTokenValue = result;
                })
                .catch(onStrategyError("access", "introspection")),
            );
          }
          if (!idTokenValue && currentIdToken) {
            promises.push(
              tokenIntrospection(config, currentIdToken)
                .then((result) => {
                  if (!result.active) throw new Error("id token is not active");
                  // An introspection response speaks RFC 7662 (`client_id`,
                  // `aud`), not ID-token vocabulary, whichever token was
                  // introspected — so it gets the access-token policy. No
                  // token-type check either: a response describing an ID token
                  // may legitimately echo `nonce`/`at_hash`, and this is the
                  // one slot where an ID token is what we asked for.
                  assertTokenAudience(
                    result as AudienceClaims,
                    "access",
                    audiencePolicy,
                  );
                  idTokenValue = result;
                })
                .catch(onStrategyError("id", "introspection")),
            );
          }
          await Promise.allSettled(promises);
          if (fatal) throw fatal;
        }
      }

      // Every token still in play has to have validated. Anything less is
      // worth a refresh, since a token set is refreshed as a whole: a stale or
      // unverifiable access token alongside a good id token (or the reverse)
      // is exactly what a refresh repairs.
      const allValidated =
        (!currentAccessToken || !!accessTokenValue) &&
        (!currentIdToken || !!idTokenValue);
      const shouldRefresh = !newTokens && !!refresh_token && !allValidated;
      if (!shouldRefresh) break;

      log.debug(
        expired
          ? "[oidc] token expired, refreshing directly..."
          : "[oidc] a token could not be validated, refreshing as a last resort...",
      );
      newTokens = await refresh(refresh_token as string);
      currentAccessToken = newTokens.access_token;
      currentIdToken = newTokens.id_token;
    }

    // A token that reached here unvalidated is never silently dropped: the
    // caller cannot tell a missing claim set from a rejected one, so anything
    // still unaccounted for fails the whole call.
    const unvalidated: TokenKind[] = [];
    if (currentAccessToken && !accessTokenValue) unvalidated.push("access");
    if (currentIdToken && !idTokenValue) unvalidated.push("id");
    if (unvalidated.length) {
      throw new OidcTokenValidationError(unvalidated, failures);
    }

    const accessSub = (accessTokenValue as { sub?: string } | undefined)?.sub;
    if (accessSub && idTokenValue?.sub && accessSub !== idTokenValue.sub) {
      throw new Error("subject in access token and id token do not match");
    }

    const base = {
      user: parseOIDCUser({
        ...(accessTokenValue ?? {}),
        ...(idTokenValue ?? {}),
      }),
      accessTokenClaims: accessTokenValue,
      idTokenClaims: idTokenValue,
    };

    if (newTokens) {
      return { ...base, refreshed: true, refreshedTokens: newTokens };
    }
    return { ...base, refreshed: false };
  }

  async function getLogoutUrl(postLogoutRedirectUri: string): Promise<URL> {
    return buildEndSessionUrl(config, {
      post_logout_redirect_uri: postLogoutRedirectUri,
    });
  }

  async function fetchUserInfoFromIssuer(
    accessToken: string,
    expectedSubject: string,
  ) {
    return fetchUserInfo(config, accessToken, expectedSubject);
  }

  return {
    /** The discovered `openid-client` configuration, for advanced/escape-hatch use. */
    configuration: config,
    startSignin,
    resolveSignin,
    processTokens,
    refresh,
    getLogoutUrl,
    fetchUserInfoFromIssuer,
  };
}

export type OidcCore = Awaited<ReturnType<typeof createOidcCore>>;
