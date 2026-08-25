import { createRemoteJWKSet, type JWTVerifyOptions } from "jose";
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
} from "openid-client";
import {
  type AudienceClaims,
  assertTokenAudience,
  audienceVerifyOption,
  buildAudiencePolicy,
  idTokenIntrospectionPolicy,
} from "./audience";
import {
  assertDiscoveredIssuer,
  assertPkceSupported,
  DEFAULT_SIGNING_ALGORITHMS,
  isAsymmetricAlgorithm,
  resolveClockTolerance,
  resolveDevelopment,
  resolveJwksUri,
} from "./discovery";
import {
  attachRefreshedTokens,
  OidcGrantError,
  OidcSubjectError,
  OidcTokenValidationError,
  OidcUserInfoError,
  type RefreshedTokenSet,
  type TokenKind,
  type TokenValidationFailure,
} from "./errors";
import { buildLogger, type Logger, type LogLevel } from "./logger";
import {
  assertSafeRedirectUri,
  assertSafeReturnTo,
  buildReturnToPolicy,
} from "./returnTo";
import { buildTokenTypePolicy } from "./tokenType";
import {
  introspectTokens,
  looksLikeJwt,
  subjectOf,
  unverifiedSubject,
  verifyTokensLocally,
} from "./tokenValidation";
import {
  type AccessTokenClaims,
  type IdTokenClaims,
  mergeTokenClaims,
  parseOIDCFlowState,
  parseOIDCUser,
  type ValidationResult,
} from "./types";

export {
  assertDiscoveredIssuer,
  assertPkceSupported,
  DEFAULT_SIGNING_ALGORITHMS,
  resolveClockTolerance,
  resolveDevelopment,
  resolveJwksUri,
} from "./discovery";

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
   *
   * "Entirely" includes the ID-token rules, which are otherwise not
   * configurable at all — `aud` must contain {@link clientId}, a present `azp`
   * must equal it, and a multi-party `aud` must carry one. Nothing checks them
   * once this is set, so re-assert them in the callback rather than returning
   * `true` for `tokenKind === "id"` on the assumption that the library still
   * has that half covered.
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
   * Require this exact `typ` **JWS header** on JWT access tokens — normally
   * `"at+jwt"`, the RFC 9068 §2.1 value; the `application/` prefix is optional.
   *
   * Unset by default, because Auth0 and Entra ID send a plain `"JWT"` on both
   * token kinds, leaving nothing to pin. Set it wherever your provider does
   * distinguish them: pinning the header is the only defence that holds for an
   * ID token carrying no distinguishing claim at all.
   *
   * This is the *header*, not a claim. Keycloak's header says `"JWT"` unless
   * its RFC 9068 option is enabled, and the `"Bearer"` / `"ID"` / `"Refresh"`
   * value that does name the kind is a payload claim, checked automatically —
   * so `accessTokenTyp: "Bearer"` would reject every Keycloak access token.
   * Enable Keycloak's RFC 9068 header option and pin `"at+jwt"`, or leave this
   * unset and rely on the `typ` claim.
   */
  accessTokenTyp?: string;
  /**
   * Whether an RFC 7662 introspection response must affirmatively name the
   * kind of token it was presented as, via `token_type`, `typ` or `token_use`.
   * Defaults to `true`, and applies to both slots.
   *
   * `active: true` on its own does not say which kind of token was
   * introspected — one endpoint serves them all — so a **refresh** token
   * introspects just as successfully and satisfies the audience policy
   * identically, while typically outliving an access token by weeks.
   *
   * Turn this off only if your provider omits the type on genuine access
   * tokens; doing so re-opens refresh-token substitution in both slots, so
   * prefer pinning {@link expectedAudience} as well if you must.
   */
  requireIntrospectedTokenType?: boolean;
  /**
   * When to fall back to remote introspection. Defaults to `"opaque-only"`.
   *
   * - `"opaque-only"` — introspect only tokens local verification couldn't
   *   even attempt: those that aren't JWTs (plus everything, if the issuer
   *   advertises no JWKS). A JWT that failed against the issuer's own JWKS is
   *   not resurrected by introspection at a spec-compliant AS, so
   *   introspecting it anyway turns every junk bearer token an attacker sends
   *   into an outbound request to your IdP.
   * - `"auto"` — introspect anything local verification rejected. Needed only
   *   by providers that sign JWT access tokens with keys outside the JWKS
   *   published for ID tokens.
   * - `"never"` — offline verification only. Opaque tokens then cannot
   *   validate at all.
   */
  introspection?: "opaque-only" | "auto" | "never";
  /**
   * Origins an absolute `returnTo` may name, e.g.
   * `["https://app.example.com"]`. Empty by default, which permits same-site
   * paths (`"/dashboard"`) and nothing else.
   *
   * `returnTo` is attacker-supplied in the common case — apps take it from
   * `?next=` — and a post-login redirect is the most useful kind to hijack,
   * since the victim arrives already authenticated and expecting a trusted
   * page.
   */
  allowedReturnToOrigins?: readonly string[];
  /**
   * Clock skew tolerance for `exp`/`nbf`, in seconds or as a duration string
   * (`"30 seconds"`, `"5m"`). Defaults to 30s.
   *
   * Applies to every timestamp this library checks: offline verification in
   * {@link OidcCore.processTokens} and the ID token validated inside the code
   * exchange and refresh alike.
   */
  clockTolerance?: string | number;
  /**
   * JWS algorithms accepted when verifying tokens offline. Defaults to the
   * issuer's advertised `id_token_signing_alg_values_supported`, falling back
   * to {@link DEFAULT_SIGNING_ALGORITHMS} when it advertises none.
   *
   * Set it explicitly if your provider signs access tokens with an algorithm
   * it does not advertise for ID tokens; discovery has no separate metadata
   * field for access tokens. A list given here is taken as-is, including
   * symmetric algorithms — a discovered one is filtered, since every offline
   * verification here uses a key from the issuer's *public* JWKS.
   *
   * Scoped to {@link OidcCore.processTokens}. The ID token validated inside
   * the code exchange and a refresh arrives straight from the token endpoint
   * over TLS, and `openid-client` holds it to the issuer's own advertised
   * list.
   */
  signingAlgorithms?: string[];
  /**
   * Allows discovery/token requests over plain HTTP. Only ever set this for a
   * local/dev IdP — never in production.
   *
   * Left unset, it is derived from the environment: on only when `NODE_ENV`
   * is exactly `"development"`.
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

/**
 * The `sub` this token set is known to belong to, if the caller has it.
 *
 * Pass this wherever a refresh might replace the token set: without it, a
 * refresh token that got mixed into the wrong session would authenticate its
 * own owner instead, since an opaque refresh token names no subject this
 * library can otherwise read.
 */
type SubjectBinding = { subject?: string };

/** At least one of the two tokens must be present — validating neither is meaningless. */
export type ProcessTokensInput = SubjectBinding &
  (
    | { access_token: string; id_token?: string; refresh_token?: string }
    | { access_token?: string; id_token: string; refresh_token?: string }
  );

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

  // Every binding this library performs (an ID token's `aud`, an access
  // token's authorized party) compares against this — an empty one would
  // fail every comparison closed, which looks like a working, if strict,
  // deployment rather than a misconfiguration.
  if (typeof opts.clientId !== "string" || opts.clientId.length === 0) {
    throw new TypeError(
      "invalid clientId: expected a non-empty string. It is what every token is bound to, so there is nothing this library could check without it.",
    );
  }

  // `verifyAudience` replaces the audience policy outright; setting
  // `expectedAudience` alongside it configures a policy that is then never
  // consulted.
  if (opts.verifyAudience && opts.expectedAudience !== undefined) {
    log.warn(
      '[oidc] both "verifyAudience" and "expectedAudience" are set. "verifyAudience" replaces the audience policy entirely, so "expectedAudience" is not checked at all — assert it inside your callback, or drop one of the two.',
    );
  }

  const clockTolerance = resolveClockTolerance(opts.clockTolerance);

  const config = await discovery(
    new URL(opts.issuer),
    opts.clientId,
    {
      client_secret: opts.clientSecret,
      token_endpoint_auth_method: opts.clientSecret ? undefined : "none",
      [clockToleranceOption]: clockTolerance,
    },
    undefined,
    { execute: development ? [allowInsecureRequests] : [] },
  );

  assertDiscoveredIssuer(opts.issuer, config.serverMetadata().issuer);

  assertPkceSupported(
    config.serverMetadata().code_challenge_methods_supported,
    opts.clientSecret,
    log,
  );

  const jwksUri = config.serverMetadata().jwks_uri;
  const jwks = jwksUri
    ? createRemoteJWKSet(resolveJwksUri(jwksUri, development))
    : undefined;
  const issuer = config.serverMetadata().issuer;

  // An AS that issues only opaque tokens has no keys to publish, and
  // introspection validates those perfectly well — but it silently moves
  // every validation onto the network, invisibly from the outside.
  if (!jwksUri) {
    log.warn(
      `[oidc] the issuer advertises no "jwks_uri", so no token can be verified offline. Every validation will fall back to remote introspection${
        (opts.introspection ?? "opaque-only") === "never"
          ? ", which \"introspection: 'never'\" has switched off — no token will validate at all"
          : " — one round trip to the IdP per request"
      }.`,
    );
  }
  const audiencePolicy = buildAudiencePolicy(opts);
  const idIntrospectionPolicy = idTokenIntrospectionPolicy(audiencePolicy);
  const tokenTypePolicy = buildTokenTypePolicy(opts);
  const returnToPolicy = buildReturnToPolicy(opts);
  const introspectionMode = opts.introspection ?? "opaque-only";

  const signingAlgorithms = resolveSigningAlgorithms(config, opts, log);

  /**
   * Everything jose can check on its own: signature, `iss`, `aud`, expiry
   * with skew tolerance, required claim presence and algorithm pinning.
   * What's left to this library is the authorized-party rule and the
   * token-type binding jose has no concept of.
   */
  function jwtVerifyOptions(tokenKind: TokenKind): JWTVerifyOptions {
    return {
      issuer,
      audience: audienceVerifyOption(audiencePolicy, tokenKind),
      clockTolerance,
      algorithms: signingAlgorithms,
      // `exp` matters most: without it jose happily accepts a token that
      // never expires. `issuer`/`audience` already force `iss`/`aud`.
      requiredClaims:
        tokenKind === "id"
          ? ["iss", "sub", "aud", "exp", "iat"]
          : ["iss", "sub", "exp"],
    };
  }

  /**
   * Says out loud, once, that a sender-constrained access token is being
   * accepted as a plain bearer token.
   *
   * A `cnf` claim binds the token to a key (RFC 9449 DPoP or RFC 8705 mTLS),
   * and proving that binding needs the proof header or client certificate of
   * the request the token arrived on — which this library never sees, being
   * handed token strings rather than a request. Not a rejection: an AS may
   * issue DPoP-bound tokens to some clients while this deployment
   * legitimately validates sessions it obtained itself. Validate the proof at
   * your edge if the tokens you accept come from callers you don't control.
   */
  let warnedSenderConstrained = false;
  function warnIfSenderConstrained(claims: AccessTokenClaims): void {
    if (warnedSenderConstrained) return;
    const cnf = (claims as Record<string, unknown> | undefined)?.cnf;
    if (cnf === undefined || cnf === null) return;
    warnedSenderConstrained = true;
    log.warn(
      '[oidc] this access token carries a "cnf" claim: the issuer bound it to a key (DPoP or mTLS), and that binding is not being checked — validating it needs the proof that travels with the HTTP request, which this library never sees. The token is accepted as an ordinary bearer token, so a stolen one is usable by anyone. Verify the proof at your edge if you accept tokens from callers you do not control.',
    );
  }

  /**
   * `authorizationCodeGrant`/`refreshTokenGrant` already validate the ID
   * token's `aud`, but only consult `azp` when `aud` is a multi-element
   * array. Re-running our own policy closes that gap for the
   * single-audience case.
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
    /**
     * Where to send the user after a successful login: a same-site path such
     * as `"/dashboard"`, or an absolute URL on an origin listed in
     * {@link OidcCoreOptions.allowedReturnToOrigins}. Anything else throws
     * {@link OidcReturnToError} — this value is normally attacker-supplied
     * (`/login?next=...`) and comes back out of {@link resolveSignin} to be
     * redirected to.
     */
    returnTo: string;
    /**
     * Space-separated OAuth scopes to request. Defaults to
     * `"openid profile email"`, and must include `openid`: this is an OIDC
     * login, and {@link OidcCore.resolveSignin} requires the ID token that
     * scope is what asks for.
     */
    scope?: string;
  }): Promise<StartSigninResult> {
    // Rejected here rather than at the callback, so the caller learns about a
    // bad value on the request that supplied it rather than one redirect
    // later.
    assertSafeReturnTo(returnTo, returnToPolicy);
    assertSafeRedirectUri(redirectUri, "redirectUri");

    if (!scope.split(/\s+/).includes("openid")) {
      throw new TypeError(
        `invalid scope ("${scope}"): it must include "openid". This is an OIDC login — resolveSignin requires the ID token that scope asks for, and checks the nonce against it. Use configuration directly with openid-client for a plain OAuth grant.`,
      );
    }

    const codeVerifier = randomPKCECodeVerifier();
    const codeChallenge = await calculatePKCECodeChallenge(codeVerifier);
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
    // `openid-client` reads a falsy `pkceCodeVerifier` as "no PKCE was used"
    // and silently omits `code_verifier` from the exchange — so a callback
    // reached with a lost or empty cookie would drop the one thing binding
    // the code to the login that requested it.
    if (typeof codeVerifier !== "string" || codeVerifier.length === 0) {
      throw new TypeError(
        "resolveSignin was given no PKCE code verifier. Pass the `codeVerifier` startSignin returned, exactly as it was stored — without it the authorization code is not bound to the login that requested it, so the exchange is refused rather than attempted.",
      );
    }
    const parsedState = parseOIDCFlowState(expectedState);
    const returnTo = assertSafeReturnTo(parsedState.visitedUrl, returnToPolicy);

    let tokens: RefreshedTokenSet;
    try {
      tokens = await authorizationCodeGrant(config, callbackUrl, {
        pkceCodeVerifier: codeVerifier,
        expectedState,
        expectedNonce: parsedState.nonce,
        idTokenExpected: true,
      });
    } catch (err) {
      throw new OidcGrantError(
        "authorization_code",
        `could not complete the login: ${err instanceof Error ? err.message : String(err)}`,
        { cause: err },
      );
    }
    assertGrantedIdToken(tokens);
    return { tokens, returnTo };
  }

  /**
   * Exchanges a refresh token for a new token set and validates the ID token
   * that comes back.
   *
   * Pass `expectedSubject` — the `sub` you have on file for this session —
   * wherever the result is going to replace a stored token set. A refresh
   * token is a bearer credential like any other: the exchange proves the
   * token is live, not that it's the one belonging to the session about to
   * be overwritten. {@link OidcCore.processTokens} performs this check for
   * itself; a direct call is otherwise the one way into this library with no
   * subject binding at all.
   *
   * Throws {@link OidcSubjectError} on a mismatch. An `expectedSubject` given
   * for a response carrying no ID token can't be checked, and warns rather
   * than passing silently.
   */
  async function refresh(
    refreshToken: string,
    { expectedSubject }: { expectedSubject?: string } = {},
  ) {
    if (
      expectedSubject !== undefined &&
      (typeof expectedSubject !== "string" || !expectedSubject)
    ) {
      throw new TypeError(
        "refresh was given an `expectedSubject` that is not a non-empty string",
      );
    }

    let tokens: RefreshedTokenSet;
    try {
      tokens = await refreshTokenGrant(config, refreshToken);
    } catch (err) {
      throw new OidcGrantError(
        "refresh_token",
        `could not exchange the refresh token: ${err instanceof Error ? err.message : String(err)}`,
        { cause: err },
      );
    }
    assertGrantedIdToken(tokens);

    if (expectedSubject) {
      const actual = subjectOf(tokens.claims());
      if (!actual) {
        log.warn(
          "[oidc] refresh could not be checked against the expected subject: the provider returned no id token to read one from. The new token set is returned unchecked.",
        );
      } else if (actual !== expectedSubject) {
        throw new OidcSubjectError(
          `refresh returned a token set for a different subject (${actual}) than the ${expectedSubject} it was asked for — the refresh token does not belong to this session`,
          expectedSubject,
          actual,
        );
      }
    }

    return tokens;
  }

  /**
   * Whether asking the AS about this token can tell us anything the local
   * pass couldn't. See {@link OidcCoreOptions.introspection}.
   */
  function worthIntrospecting(token: string): boolean {
    return (
      introspectionMode !== "never" &&
      (introspectionMode === "auto" || !jwks || !looksLikeJwt(token))
    );
  }

  /**
   * Runs the offline-first validation fallback chain (JWKS → introspection),
   * refreshing once if the tokens supplied don't all validate.
   *
   * **Every token passed in must validate.** If one survives no strategy and
   * no refresh replaces it, this throws {@link OidcTokenValidationError}
   * rather than returning the other's claims — an `accessTokenClaims` that's
   * missing because verification failed must never look like one where no
   * access token was supplied.
   *
   * **The result describes the subject that was passed in.** A refresh may
   * replace the token set but not the user: if the refreshed tokens name a
   * different `sub`, this throws {@link OidcSubjectError} rather than
   * authenticating whoever the refresh token happened to belong to. Pass
   * {@link ProcessTokensInput.subject} where the supplied tokens may be
   * opaque, or this check has nothing to compare against and only warns.
   *
   * The caller must persist {@link ProcessTokensResult.refreshedTokens} when
   * {@link ProcessTokensResult.refreshed} is `true` — and
   * `err.refreshedTokens` when this throws after having refreshed, which is
   * the same obligation on the failure path.
   *
   * **Serialize this per session.** The refresh happens inside a call that
   * runs on every request, and nothing here can see other calls sharing a
   * session — concurrent requests against an expired token set each spend
   * the *same* refresh token. Where the provider merely rotates, that wastes
   * round trips; where it also detects reuse (Auth0, Okta, `oidc-provider`,
   * Keycloak with the option on), the replay is read as a stolen token and
   * the whole grant is revoked. Keep one in-flight call per session, or
   * refresh ahead of expiry from a path that's already serialized.
   */
  async function processTokens({
    access_token,
    id_token,
    refresh_token,
    subject,
  }: ProcessTokensInput): Promise<ProcessTokensResult> {
    if (!access_token && !id_token) {
      throw new TypeError(
        "processTokens needs an access token, an id token, or both — validating neither is meaningless",
      );
    }
    if (subject !== undefined && (typeof subject !== "string" || !subject)) {
      throw new TypeError(
        "processTokens was given a `subject` that is not a non-empty string",
      );
    }

    let currentAccessToken = access_token;
    let currentIdToken = id_token;
    let newTokens: RefreshedTokenSet | undefined;
    let accessTokenValue: AccessTokenClaims;
    let idTokenValue: IdTokenClaims;
    let failures: TokenValidationFailure[] = [];
    // Who this token set belongs to, so a refresh can't quietly return a
    // different user's. A caller-supplied `subject` is authoritative;
    // otherwise this starts from what the supplied tokens claim and upgrades
    // to a verified subject once one is available.
    let boundSubject =
      subject ?? unverifiedSubject(id_token) ?? unverifiedSubject(access_token);

    try {
      // At most two passes: the tokens as given, and — only once refreshed —
      // the new token set.
      for (let attempt = 0; attempt < 2; attempt++) {
        accessTokenValue = undefined;
        idTokenValue = undefined;
        failures = [];
        let expired = false;

        if (jwks) {
          const local = await verifyTokensLocally(
            jwks,
            { access: currentAccessToken, id: currentIdToken },
            jwtVerifyOptions,
            tokenTypePolicy,
            audiencePolicy,
            log,
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
            log.debug(
              "[oidc] could not verify tokens locally, trying introspection...",
            );
            const introspected = await introspectTokens(
              config,
              { access: currentAccessToken, id: currentIdToken },
              { access: introspectAccess, id: introspectId },
              tokenTypePolicy,
              audiencePolicy,
              idIntrospectionPolicy,
              log,
            );
            accessTokenValue ??= introspected.accessTokenValue;
            idTokenValue ??= introspected.idTokenValue;
            failures = failures.concat(introspected.failures);
          }
        }

        // A subject that's actually been verified beats the unverified read
        // the binding started from. Taken before any refresh, so it
        // describes the set the caller handed in — and never applied over a
        // caller-declared `subject`, which outranks anything read off a
        // token.
        if (!newTokens && !subject) {
          boundSubject =
            subjectOf(accessTokenValue) ??
            subjectOf(idTokenValue) ??
            boundSubject;
        }

        // A token set is refreshed as a whole: a stale or unverifiable
        // access token alongside a good id token (or the reverse) is exactly
        // what a refresh repairs.
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

      return finalizeProcessTokens({
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
      });
    } catch (err) {
      // The provider has very likely invalidated the refresh token by now,
      // so a replacement that already happened must travel with the error or
      // the session becomes unrecoverable.
      throw attachRefreshedTokens(err, newTokens);
    }
  }

  /**
   * Builds an RP-initiated logout URL (OIDC RP-Initiated Logout 1.0 §2).
   *
   * Pass `idTokenHint` wherever the ID token is still to hand: without it
   * the OP can't tell which session to end, and some providers (Keycloak
   * 18+) then ask the user to confirm, turning a clean logout into an
   * interstitial page.
   *
   * `postLogoutRedirectUri` must be an absolute http(s) URL without embedded
   * credentials, and must be registered with the provider — that
   * registration is what decides where the user may actually land.
   */
  async function getLogoutUrl(
    postLogoutRedirectUri: string,
    { idTokenHint, state }: { idTokenHint?: string; state?: string } = {},
  ): Promise<URL> {
    assertSafeRedirectUri(postLogoutRedirectUri, "postLogoutRedirectUri");
    return buildEndSessionUrl(config, {
      post_logout_redirect_uri: postLogoutRedirectUri,
      ...(idTokenHint ? { id_token_hint: idTokenHint } : {}),
      ...(state ? { state } : {}),
    });
  }

  /**
   * Fetches claims from the issuer's UserInfo endpoint.
   *
   * `expectedSubject` must be a `sub` this library already validated — the
   * response is checked against it, since a UserInfo response describes
   * whoever the access token belongs to, not necessarily the user the caller
   * asked for.
   */
  async function fetchUserInfoFromIssuer(
    accessToken: string,
    expectedSubject: string,
  ) {
    if (typeof expectedSubject !== "string" || !expectedSubject) {
      throw new TypeError(
        "fetchUserInfoFromIssuer needs the `sub` this token set was validated for, as a non-empty string — the response is only meaningful once it is known to describe that subject",
      );
    }
    try {
      return await fetchUserInfo(config, accessToken, expectedSubject);
    } catch (err) {
      throw new OidcUserInfoError(
        `could not fetch UserInfo claims for subject ${expectedSubject}: ${
          err instanceof Error ? err.message : String(err)
        }`,
        { cause: err },
      );
    }
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

/**
 * An explicit list is taken as given. A discovered one is filtered: `none`
 * isn't a signature, and a symmetric `alg` can't be verified with a key from
 * a JWKS.
 */
function resolveSigningAlgorithms(
  config: Awaited<ReturnType<typeof discovery>>,
  opts: Pick<OidcCoreOptions, "signingAlgorithms">,
  log: Logger,
): string[] {
  const advertised =
    config.serverMetadata().id_token_signing_alg_values_supported ?? [];
  const advertisedAlgorithms = advertised.filter(isAsymmetricAlgorithm);
  if (advertised.length !== advertisedAlgorithms.length) {
    log.debug(
      `[oidc] ignoring advertised signing algorithms that no JWKS key can verify: ${advertised
        .filter((alg) => !isAsymmetricAlgorithm(alg))
        .join(", ")}`,
    );
  }
  return (
    opts.signingAlgorithms ??
    (advertisedAlgorithms.length
      ? advertisedAlgorithms
      : [...DEFAULT_SIGNING_ALGORITHMS])
  );
}

/**
 * Runs every check that only makes sense once the validation loop is
 * finished: nothing was silently dropped, every subject binding agrees, and
 * the merged claims form a valid {@link ProcessTokensResult}.
 */
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
  // A token that reached here unvalidated is never silently dropped: the
  // caller can't tell a missing claim set from a rejected one.
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

  // A refresh must return the session it was handed, not merely *a* valid
  // session — the new token set is internally consistent and correctly
  // signed whoever it belongs to, so nothing else here would catch a
  // refresh token that got into this set from somewhere else.
  const finalSubject = accessSub ?? idSub;
  if (
    newTokens &&
    boundSubject &&
    finalSubject &&
    finalSubject !== boundSubject
  ) {
    throw new OidcSubjectError(
      `refresh returned a token set for a different subject (${finalSubject}) than the tokens it replaced (${boundSubject}) — the refresh token does not belong to this session`,
      boundSubject,
      finalSubject,
    );
  }

  // Same rule for the tokens as supplied, which only a caller-declared
  // subject can state: no refresh has to have happened for a token set to
  // be the wrong user's.
  if (subject && finalSubject && finalSubject !== subject) {
    throw new OidcSubjectError(
      `the tokens describe subject ${finalSubject}, not the ${subject} they were presented for`,
      subject,
      finalSubject,
    );
  }

  if (newTokens && !boundSubject) {
    log.warn(
      "[oidc] refreshed a token set whose original subject could not be determined — the supplied tokens were opaque or unreadable, so the refreshed set could not be checked against them. Pass `subject` to processTokens to enforce it.",
    );
  }

  warnIfSenderConstrained(accessTokenValue);

  const base = {
    user: parseOIDCUser({
      // Merged rather than spread: a verified flag must not survive from one
      // token beside a value from the other. See `mergeTokenClaims`.
      ...mergeTokenClaims(
        accessTokenValue as Record<string, unknown> | undefined,
        idTokenValue as Record<string, unknown> | undefined,
        (claim) =>
          log.warn(
            `[oidc] the access token and the id token disagree on "${claim}" for subject ${finalSubject ?? "(unknown)"}; using the id token's value, and dropping any verification flag that did not come with it. One of the two is stale.`,
          ),
      ),
      // Stated rather than carried over from the claims: this is the issuer
      // every claim set above was verified *against*.
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
