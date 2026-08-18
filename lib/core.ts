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
  discovery,
  fetchUserInfo,
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
  type TokenKind,
} from "./audience";
import { buildLogger, type Logger, type LogLevel } from "./logger";
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
   * Never compared against ID tokens, whose `aud` is always the client id.
   */
  expectedAudience?: string | string[];
  /**
   * Claims that may name the client an access token was issued to, in
   * priority order — the first one present must equal {@link clientId}.
   * Defaults to `["azp", "client_id", "cid", "appid"]`, which covers
   * RFC 9068, Keycloak, Auth0, Entra ID, Okta and Cognito.
   */
  authorizedPartyClaims?: readonly string[];
  /**
   * Escape hatch for providers none of the above fits: replaces the built-in
   * audience policy entirely. Return `false` to reject the token.
   */
  verifyAudience?: (claims: AudienceClaims, tokenKind: TokenKind) => boolean;
  /**
   * Clock skew tolerance for `exp`/`nbf`, in seconds or as a duration string
   * (`"30 seconds"`). Defaults to 30s — with no tolerance, ordinary drift
   * between your host and the IdP produces spurious expiry failures, which
   * this library answers by spending a refresh token.
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
 * Discovers an OIDC issuer and returns the framework-agnostic operations
 * needed to implement a login: PKCE authorization-code flow, offline token
 * validation with a graceful fallback chain (JWKS → introspection →
 * UserInfo), refresh, and RP-initiated logout.
 */
export async function createOidcCore(opts: OidcCoreOptions) {
  const log = buildLogger(opts.logger, opts.logLevel);

  const config = await discovery(
    new URL(opts.issuer),
    opts.clientId,
    {
      client_secret: opts.clientSecret,
      token_endpoint_auth_method: opts.clientSecret ? undefined : "none",
    },
    undefined,
    { execute: opts.development ? [allowInsecureRequests] : [] },
  );

  const jwksUri = config.serverMetadata().jwks_uri;
  const jwks = jwksUri ? createRemoteJWKSet(new URL(jwksUri)) : undefined;
  const issuer = config.serverMetadata().issuer;
  const audiencePolicy = buildAudiencePolicy(opts);

  const signingAlgorithms =
    opts.signingAlgorithms ??
    config
      .serverMetadata()
      .id_token_signing_alg_values_supported?.filter((alg) => alg !== "none");

  /**
   * Everything jose can check on its own, so this library doesn't reimplement
   * it: signature, `iss`, `aud`, expiry with skew tolerance, required claim
   * presence and algorithm pinning. Only the OIDC-specific authorized-party
   * rules are left to {@link assertAudienceAfterJwtVerify}.
   */
  function jwtVerifyOptions(tokenKind: TokenKind): JWTVerifyOptions {
    return {
      issuer,
      audience: audienceVerifyOption(audiencePolicy, tokenKind),
      clockTolerance: opts.clockTolerance ?? 30,
      algorithms: signingAlgorithms,
      // `issuer`/`audience` already force `iss`/`aud` presence. `exp` matters
      // most: without it jose happily accepts a token that never expires.
      requiredClaims:
        tokenKind === "id"
          ? ["iss", "sub", "aud", "exp", "iat"]
          : ["iss", "sub", "exp"],
    };
  }

  if (opts.development) {
    log.warn(
      "[oidc] development mode is on: plain-HTTP requests to the IdP are allowed. Never enable this in production.",
    );
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
    const state = JSON.stringify({
      visitedUrl: returnTo,
      random: randomState(),
    });

    const authorizationUrl = buildAuthorizationUrl(config, {
      redirect_uri: redirectUri,
      scope,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state,
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
   * Runs the offline-first validation fallback chain (JWKS → introspection →
   * UserInfo). A JWKS failure specifically due to token expiry skips the
   * remaining strategies and refreshes immediately instead — introspection
   * and UserInfo would either fail the same way or waste a round trip on a
   * token that's simply stale. Refreshing supersedes both tokens, so this
   * applies even if only one of the two had expired. Any other failure mode
   * (bad signature, unknown key, network error, ...) still runs the full
   * chain, falling back to a refresh only once nothing at all validated.
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

    // At most two passes: the tokens as given, and — only once refreshed —
    // the new token set. `newTokens` itself guards against looping further.
    for (let attempt = 0; attempt < 2; attempt++) {
      accessTokenValue = undefined;
      idTokenValue = undefined;
      let expired = false;
      // An audience mismatch is a permanent rejection, not a transient
      // failure: no other strategy and no refresh can turn someone else's
      // token into ours. Captured here rather than thrown inside the
      // `.catch` below, which `Promise.allSettled` would swallow.
      let fatal: OidcAudienceError | undefined;
      const onStrategyError =
        (kind: TokenKind, stage: string) => (err: unknown) => {
          if (err instanceof OidcAudienceError) {
            fatal ??= err;
            return;
          }
          // jose owns the `aud` match now, so its rejection has to be mapped
          // back onto the same permanent-failure path. `JWTExpired` does not
          // extend `JWTClaimValidationFailed`, so the expiry branch below is
          // unaffected by this.
          if (
            err instanceof errors.JWTClaimValidationFailed &&
            err.claim === "aud"
          ) {
            fatal ??= new OidcAudienceError(kind, "aud", err.message);
            return;
          }
          if (err instanceof errors.JWTExpired) expired = true;
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
                  // introspected — so it gets the access-token policy.
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

        // Strategy 3: last resort, ask the UserInfo endpoint (works for
        // identity claims even when neither local verification nor
        // introspection are available for this issuer). Only meaningful with
        // an access token.
        if (currentAccessToken && (!accessTokenValue || !idTokenValue)) {
          const userInfo = await fetchUserInfo(
            config,
            currentAccessToken,
            "unknown",
          ).catch((err) => {
            log.debug(
              "[oidc] UserInfo fallback failed:",
              (err as Error).message,
            );
            return undefined;
          });
          // A UserInfo response carries no `aud`/`azp`, so it cannot be bound
          // to this client — it only proves the AS still accepts the access
          // token, not that the token was issued to us. When nothing else
          // validated, that leaves the claims unbound; say so rather than
          // letting it pass silently.
          if (userInfo && !accessTokenValue) {
            log.warn(
              "[oidc] identity resolved from UserInfo alone: these claims are not bound to this client, since UserInfo responses carry no audience. Prefer an issuer with JWT access tokens or a reachable introspection endpoint.",
            );
          }
          idTokenValue = userInfo;
        }
      }

      const gotSomething = !!accessTokenValue || !!idTokenValue;
      const shouldRefresh =
        !newTokens && !!refresh_token && (expired || !gotSomething);
      if (!shouldRefresh) break;

      log.debug(
        expired
          ? "[oidc] token expired, refreshing directly..."
          : "[oidc] every validation strategy failed, refreshing as a last resort...",
      );
      newTokens = await refresh(refresh_token as string);
      currentAccessToken = newTokens.access_token;
      currentIdToken = newTokens.id_token;
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
