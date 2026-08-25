import {
  createRemoteJWKSet,
  decodeJwt,
  decodeProtectedHeader,
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
  idTokenIntrospectionPolicy,
  OidcAudienceError,
} from "./audience";
import {
  attachRefreshedTokens,
  OidcGrantError,
  OidcSubjectError,
  OidcTokenError,
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
import {
  assertIntrospectedAccessToken,
  assertIntrospectedIdToken,
  assertTokenTypeAfterJwtVerify,
  buildTokenTypePolicy,
} from "./tokenType";
import {
  type AccessTokenClaims,
  type IdTokenClaims,
  mergeTokenClaims,
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
   * identically, while typically outliving an access token by weeks. Since
   * RFC 7662 §2.2 reports `token_type` only for tokens that have one, an
   * absent type is in practice the refresh-token case.
   *
   * Turn this off only if your provider omits the type on genuine access
   * tokens; doing so re-opens refresh-token substitution in both slots, so
   * prefer pinning {@link expectedAudience} as well if you must.
   */
  requireIntrospectedTokenType?: boolean;
  /**
   * When to fall back to remote introspection. Defaults to `"opaque-only"`.
   *
   * - `"opaque-only"` — introspect only tokens local verification could not
   *   even attempt, i.e. those that are not JWTs (plus everything, if the
   *   issuer advertises no JWKS). A JWT that failed against the issuer's own
   *   JWKS is not resurrected by introspection at a spec-compliant AS —
   *   `oidc-provider`, for one, answers `unsupported_token_type` — and
   *   introspecting it anyway turns every junk bearer token an attacker sends
   *   into an outbound request to your IdP.
   * - `"auto"` — introspect anything local verification rejected. Needed only
   *   by providers that sign JWT access tokens with keys outside the JWKS
   *   published for ID tokens.
   * - `"never"` — offline verification only. Opaque tokens then cannot
   *   validate at all.
   *
   * Note that a token which really is opaque is indistinguishable from a
   * fabricated string without asking the AS, so no setting other than
   * `"never"` removes that round trip. Rate-limit unauthenticated requests.
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
   * page. The OAuth `state` check does not cover this: `state` stops a foreign
   * authorization response, not a value the app itself put inside it.
   */
  allowedReturnToOrigins?: readonly string[];
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
   * issuer's advertised `id_token_signing_alg_values_supported`, falling back
   * to {@link DEFAULT_SIGNING_ALGORITHMS} when it advertises none — leaving
   * this unpinned would let a token pick its own algorithm.
   *
   * Set it explicitly if your provider signs access tokens with an algorithm
   * it does not advertise for ID tokens; discovery has no separate metadata
   * field for access tokens. A list given here is taken as-is, including
   * symmetric algorithms — a discovered one is filtered, since every offline
   * verification here uses a key from the issuer's *public* JWKS and an `HS*`
   * verified against a published key is the algorithm-confusion shape.
   *
   * Scoped to {@link OidcCore.processTokens}. The ID token validated inside the
   * code exchange and a refresh arrives straight from the token endpoint over
   * TLS, and `openid-client` holds it to the issuer's own advertised list.
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

/**
 * The `sub` this token set is known to belong to, if the caller has it.
 *
 * Every claim set that validates is checked against it, and — the reason it is
 * here — so is anything a refresh returns. Without it that binding is inferred
 * from the tokens passed in, which works for JWTs but not for *opaque* ones:
 * an opaque token that no longer introspects (the ordinary expiry case) names
 * no subject this library can read, so a refresh token that got into the set
 * from somewhere else would authenticate its own owner instead. Pass the `sub`
 * you already have on file and that cannot happen.
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

/**
 * What to accept when the issuer advertises no
 * `id_token_signing_alg_values_supported`, which OIDC discovery makes REQUIRED
 * but plain OAuth AS metadata does not.
 *
 * Asymmetric only. A symmetric `alg` verified against a key fetched from a
 * JWKS is the algorithm-confusion shape — jose refuses to use a public key as
 * an HMAC secret, so it is not reachable here, but there is also no reason for
 * a resource server to allow it.
 */
export const DEFAULT_SIGNING_ALGORITHMS: readonly string[] = [
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES256K",
  "ES384",
  "ES512",
  "EdDSA",
  "Ed25519",
];

/**
 * Whether an `alg` is one a public key from a JWKS can verify.
 *
 * Everything this library checks offline is verified against a key fetched
 * from the issuer's JWKS, so a symmetric `alg` has no business in the accepted
 * list however the issuer advertises it — and several do advertise `HS256` in
 * `id_token_signing_alg_values_supported`, because they will also sign an ID
 * token with the client secret for clients that ask. Verifying one of those
 * against a *published* key is the algorithm-confusion shape; jose will not use
 * a public key as an HMAC secret, so it is not reachable today, but the
 * accepted list should not be the thing standing on that.
 */
function isAsymmetricAlgorithm(alg: string): boolean {
  return /^(RS|PS|ES|Ed)/.test(alg);
}

/**
 * The issuer's JWKS URL, refused unless the keys can be fetched from it safely.
 *
 * `openid-client` holds every request *it* makes to https, with
 * {@link OidcCoreOptions.development} as the only exception. The JWKS is the
 * one request this library makes through **jose**, which has no such switch:
 * `createRemoteJWKSet` fetches plain HTTP without complaint. It is also the
 * request that decides whether a signature verifies, so fetching it in the
 * clear is one MITM key substitution away from accepting forged tokens for any
 * subject — and it is reachable from a metadata document served over TLS, which
 * makes it an ordinary provider misconfiguration rather than an attack.
 */
export function resolveJwksUri(jwksUri: string, development: boolean): URL {
  let url: URL;
  try {
    url = new URL(jwksUri);
  } catch {
    throw new TypeError(
      `the issuer advertises a jwks_uri that is not a URL ("${jwksUri}")`,
    );
  }
  if (url.protocol === "https:") return url;
  if (development && url.protocol === "http:") return url;
  throw new TypeError(
    `refusing the issuer's jwks_uri ("${jwksUri}"): signing keys must be fetched over https, and this is ${url.protocol.replace(":", "")}. Every token signature is checked against those keys, so anyone on the network could substitute their own and mint tokens for any user. Set "development: true" only if this is a local IdP.`,
  );
}

/** Hosts `openid-client` deliberately exempts from its own issuer comparison. */
function issuerMatchExempt(url: URL): boolean {
  return (
    url.origin === "https://login.microsoftonline.com" ||
    url.hostname.endsWith(".b2clogin.com")
  );
}

const WELL_KNOWN = "/.well-known/";
const withoutTrailingSlash = (value: string) => value.replace(/\/+$/, "");

/**
 * Confirms the metadata document names the issuer that was actually asked for.
 *
 * `openid-client` performs this comparison itself — but only when it had to
 * *derive* the metadata URL from an issuer identifier. Hand it a URL that
 * already contains `/.well-known/`, which is an entirely ordinary way to
 * configure an OIDC client and one nothing here rejects, and it takes the
 * document's word instead (`resolve = !server.href.includes('/.well-known/')`).
 * {@link OidcCoreOptions.issuer} then stops being a pin and becomes a hint:
 * everything downstream is whatever the document said — the `iss` every token
 * is checked against, the `jwks_uri` those signatures are checked with, and the
 * token endpoint refresh tokens are spent at. A document that names a foreign
 * issuer is accepted in full.
 *
 * The well-known path is either *appended* to the issuer (OIDC Discovery 1.0
 * §4: `https://idp.example.com/realms/main/.well-known/openid-configuration`)
 * or *inserted* after the host (RFC 8414 §3.1:
 * `https://idp.example.com/.well-known/oauth-authorization-server/realms/main`).
 * The first form spells the issuer out, so it is compared exactly, as
 * `openid-client` would have. The second cannot be reversed — the boundary
 * between the well-known name and the issuer path is not recoverable — so it
 * falls back to requiring the same origin, which is what stops one host's
 * document from naming another's issuer either way.
 *
 * `login.microsoftonline.com` and `*.b2clogin.com` get the origin check too:
 * `openid-client` exempts both from its own comparison, because Entra ID's
 * `/common` and `/organizations` documents answer with a literal
 * `{tenantid}` placeholder in the issuer, and matching that exactly would
 * refuse a working deployment.
 */
export function assertDiscoveredIssuer(
  configured: string,
  discovered: string,
): void {
  let configuredUrl: URL;
  try {
    configuredUrl = new URL(configured);
  } catch {
    // `createOidcCore` parses this into a URL before discovery runs, so this is
    // only reachable by calling the helper directly — and a value that is not a
    // URL carries no `.well-known` path to decide anything from.
    return;
  }

  const path = configuredUrl.origin + configuredUrl.pathname;
  const wellKnownAt = path.indexOf(WELL_KNOWN);
  // No well-known segment means `openid-client` compared them itself, exactly,
  // including the exemptions above. Re-running that here would only reimplement
  // it — and get the exempted hosts wrong.
  if (wellKnownAt === -1) return;

  const suffix = withoutTrailingSlash(
    path.slice(wellKnownAt + WELL_KNOWN.length),
  );
  const appended = !suffix.includes("/") && !issuerMatchExempt(configuredUrl);

  if (appended) {
    const expected = withoutTrailingSlash(path.slice(0, wellKnownAt));
    if (withoutTrailingSlash(discovered) === expected) return;
    throw new TypeError(
      `the metadata document at "${configured}" names a different issuer ("${discovered}") than the "${expected}" it was fetched for. Every token is verified against the issuer the document declares, and its keys and endpoints come from the same document, so this is not a mismatch that can be accepted. Configure "issuer" as the issuer identifier itself rather than its .well-known URL, or point it at the provider that really serves "${discovered}".`,
    );
  }

  // The inserted form has only an origin to compare, so the document's issuer
  // has to be a URL for there to be a comparison at all. An unparseable one is
  // refused rather than stepped over: `openid-client` does not compare the
  // issuer for a `.well-known` URL, so this is the only thing holding the
  // document to the provider it was fetched from, and skipping it would let the
  // `iss` every token is checked against — plus the `jwks_uri` those signatures
  // are checked with — be whatever the document said.
  let discoveredUrl: URL;
  try {
    discoveredUrl = new URL(discovered);
  } catch {
    throw new TypeError(
      `the metadata document at "${configured}" names an issuer that is not a URL ("${discovered}"), so it cannot be checked against the provider it was fetched from. Every token is verified against the issuer the document declares, and its keys and endpoints come from the same document, so an issuer that cannot be compared cannot be accepted. Configure "issuer" as the issuer identifier itself rather than its .well-known URL.`,
    );
  }

  if (discoveredUrl.origin === configuredUrl.origin) return;
  throw new TypeError(
    `the metadata document at "${configured}" names an issuer on a different origin ("${discovered}"). Every token is verified against the issuer the document declares, and its keys and endpoints come from the same document, so a document that hands off to another host cannot be accepted. Configure "issuer" as the issuer identifier itself rather than its .well-known URL.`,
  );
}

/**
 * Refuses an issuer that cannot honour the PKCE challenge
 * {@link OidcCore.startSignin} sends.
 *
 * PKCE is what binds an authorization code to the login that requested it, and
 * for a public client — no `clientSecret`, `token_endpoint_auth_method: "none"`
 * — it is the *only* thing protecting the token endpoint: a code leaked
 * through a referrer, a proxy log or a hijacked redirect is otherwise
 * redeemable by anyone who has it.
 *
 * The failure mode this guards against is silent. An AS that does not
 * understand `code_challenge` ignores the parameter, answers the code exchange
 * normally, and leaves a flow that looks exactly like a protected one. So an
 * issuer that advertises its methods and does not list `S256` is refused
 * outright — `plain` is not a fallback, since a challenge equal to the verifier
 * defends against nothing.
 *
 * RFC 8414 reads an absent `code_challenge_methods_supported` as "no PKCE at
 * all", but several providers that do support it (Cognito among them) simply
 * omit the field, so that case warns rather than throws — there is nothing the
 * caller could configure to fix it, only an IdP setting to go and confirm.
 */
export function assertPkceSupported(
  methods: string[] | undefined,
  clientSecret: string | undefined,
  log: Logger,
): void {
  if (methods?.includes("S256")) return;
  if (methods?.length) {
    throw new TypeError(
      `the issuer does not support the S256 PKCE challenge method (it advertises: ${methods.join(", ")}). Without it an authorization code is not bound to the login that requested it, and this library sends S256 on every authorization request — an issuer that ignores it would leave the code redeemable by anyone who obtained it.`,
    );
  }
  log.warn(
    `[oidc] the issuer advertises no "code_challenge_methods_supported", so it cannot be confirmed that the PKCE challenge this library sends is honoured${
      clientSecret
        ? ""
        : " — and this is a public client, where PKCE is the only thing protecting the token endpoint"
    }. Verify that PKCE is enforced for this client at the IdP.`,
  );
}

/** Three base64url segments — the compact JWS serialization, shape only. */
const JWS_COMPACT = /^[\w-]+\.[\w-]*\.[\w-]+$/;

/**
 * Whether a token is a JWT at all, as opposed to an opaque handle.
 *
 * Decides whether introspection has anything to add: a JWT that the issuer's
 * own JWKS could not verify is not going to be rehabilitated by asking the AS
 * about it — spec-compliant servers answer `unsupported_token_type` for
 * structured tokens — so the round trip is pure cost, and cost an attacker
 * controls. The header is decoded rather than the shape merely matched,
 * because opaque tokens can and do contain dots.
 */
function looksLikeJwt(token: string): boolean {
  if (!JWS_COMPACT.test(token)) return false;
  try {
    return typeof decodeProtectedHeader(token).alg === "string";
  } catch {
    return false;
  }
}

/**
 * The `sub` a supplied JWT names, read without verifying anything.
 *
 * Sound only because of how it is used: as an *additional constraint* on what
 * a refresh is allowed to return, never as grounds for accepting anything. The
 * caller asserted that these tokens belong to one session; an unverified
 * subject is enough to notice when the refresh token in that set belongs to
 * somebody else, and a forged value can only make the check stricter.
 */
function unverifiedSubject(token?: string): string | undefined {
  if (!token || !looksLikeJwt(token)) return undefined;
  try {
    return subjectOf(decodeJwt(token));
  } catch {
    return undefined;
  }
}

function subjectOf(claims: unknown): string | undefined {
  const sub = (claims as { sub?: unknown } | undefined)?.sub;
  return typeof sub === "string" && sub.length > 0 ? sub : undefined;
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

  // The client id is one half of every binding this library performs — an ID
  // token's `aud`, an access token's authorized party — so an empty one would
  // turn each of those into a comparison against nothing. They all fail closed
  // as it happens, which is the problem: the deployment would look configured
  // and reject every token, rather than say what is wrong.
  if (typeof opts.clientId !== "string" || opts.clientId.length === 0) {
    throw new TypeError(
      "invalid clientId: expected a non-empty string. It is what every token is bound to, so there is nothing this library could check without it.",
    );
  }

  // `verifyAudience` replaces the audience policy outright, `expectedAudience`
  // configures the policy it replaces. Setting both is not a stricter
  // combination but a silently discarded one, and the discarded half is the
  // deliberately-configured resource audience.
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
      // Carries the tolerance into `openid-client`'s own timestamp checks —
      // the ID token it validates during the code exchange and every refresh.
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

  // Not fatal — an AS that issues only opaque tokens has no keys to publish,
  // and introspection validates those perfectly well. But it silently moves
  // every validation off the machine: with no JWKS there is no signature to
  // check locally, so `processTokens` reaches the IdP on every request that
  // carries a token, and `introspection: "never"` leaves it unable to validate
  // anything at all. Neither is visible from the outside.
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

  // An explicit list is taken as given — the caller has said what they accept.
  // A discovered one is filtered: `none` is not a signature, and a symmetric
  // `alg` cannot be verified with a key from a JWKS.
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
  const signingAlgorithms =
    opts.signingAlgorithms ??
    (advertisedAlgorithms.length
      ? advertisedAlgorithms
      : [...DEFAULT_SIGNING_ALGORITHMS]);

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
   * Says out loud, once, that a sender-constrained access token is being
   * accepted as a plain bearer token.
   *
   * A `cnf` claim is the AS stating that this token may only be used by whoever
   * holds a particular key — RFC 9449 DPoP (`cnf.jkt`) or RFC 8705 mTLS
   * (`cnf["x5t#S256"]`). Proving that takes the DPoP proof header or the TLS
   * client certificate of the request the token arrived on, and this library is
   * handed token strings, never a request; there is nothing here that *could*
   * check the binding. Every other check still passes — the signature, the
   * issuer, the audience, the type — so the token validates, and a stolen one
   * is then usable by anybody, which is the single thing the constraint was
   * turned on to prevent.
   *
   * Not a rejection: an AS may issue DPoP-bound tokens to some clients while
   * this deployment legitimately validates sessions it obtained itself, and
   * refusing would break that with no way to opt back in. Validate the proof at
   * your edge (a gateway, or `oauth4webapi`'s `validateJwtAccessToken`) if the
   * tokens you accept come from callers you do not control.
   *
   * Warned once per instance rather than per request: it is a property of the
   * provider's configuration, not of the request that happened to reveal it.
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
    // Rejected here rather than at the callback so the bad value never reaches
    // the browser, and so the caller learns about it on the request that
    // supplied it instead of one redirect later.
    assertSafeReturnTo(returnTo, returnToPolicy);
    assertSafeRedirectUri(redirectUri, "redirectUri");

    // `resolveSignin` requires an ID token and checks a `nonce` against it,
    // neither of which the provider owes a request that did not ask for
    // `openid`. Without this the login fails at the callback — or, on a lenient
    // AS, at the token endpoint — with whatever the provider chose to say,
    // one redirect after the mistake was made and nowhere near it.
    if (!scope.split(/\s+/).includes("openid")) {
      throw new TypeError(
        `invalid scope ("${scope}"): it must include "openid". This is an OIDC login — resolveSignin requires the ID token that scope asks for, and checks the nonce against it. Use configuration directly with openid-client for a plain OAuth grant.`,
      );
    }

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
    // `openid-client` reads a falsy `pkceCodeVerifier` as "this flow used no
    // PKCE" and omits `code_verifier` from the exchange entirely, so a callback
    // reached with a lost or empty cookie would *silently* drop the one thing
    // binding the code to the login that requested it. A spec-compliant AS
    // refuses the exchange anyway (RFC 7636 §4.6), but that is the provider
    // catching it, and `assertPkceSupported` exists precisely because this
    // library does not take the provider's word on PKCE.
    if (typeof codeVerifier !== "string" || codeVerifier.length === 0) {
      throw new TypeError(
        "resolveSignin was given no PKCE code verifier. Pass the `codeVerifier` startSignin returned, exactly as it was stored — without it the authorization code is not bound to the login that requested it, so the exchange is refused rather than attempted.",
      );
    }
    const parsedState = parseOIDCFlowState(expectedState);
    // Checked again on the way out, not only in `startSignin`: this state may
    // have been minted by an older version of this library, by a process
    // configured differently, or by a caller that built one by hand. The value
    // is about to be handed back for a redirect, so the guarantee has to hold
    // at the point of use.
    const returnTo = assertSafeReturnTo(parsedState.visitedUrl, returnToPolicy);

    // Wrapped so the ordinary failures of a callback endpoint — a code that
    // has already been used, a `state` that does not match, an IdP that
    // answered `access_denied` — reach the caller as an OidcError rather than
    // as `openid-client`'s own. See {@link OidcGrantError}.
    let tokens: RefreshedTokenSet;
    try {
      tokens = await authorizationCodeGrant(config, callbackUrl, {
        pkceCodeVerifier: codeVerifier,
        expectedState,
        // Binds the ID token to this authorization request. `undefined` is not
        // "unchecked": it makes `openid-client` require the ID token to carry
        // no `nonce` at all, which is the right expectation for a login
        // started before {@link OIDCFlowState.nonce} existed.
        expectedNonce: parsedState.nonce,
        // An ID token is the point of asking for `openid` scope, so a response
        // without one is a provider fault rather than a login with no subject.
        // Implied by a string `expectedNonce`, set explicitly so the guarantee
        // does not depend on one being present.
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
   * wherever the result is going to replace a stored token set. A refresh token
   * is a bearer credential like any other: the exchange proves the token is
   * live, not that it is the one belonging to the session about to be
   * overwritten, and the returned set is internally consistent and correctly
   * signed whoever it belongs to. OIDC Core 12.2 makes the `sub` comparison a
   * MUST for exactly this reason, and it is the check
   * {@link OidcCore.processTokens} performs for itself — a direct call is
   * otherwise the one way into this library that has no subject binding at all.
   *
   * Throws {@link OidcSubjectError} on a mismatch. An `expectedSubject` given
   * for a response carrying no ID token cannot be checked and says so at `warn`
   * level, rather than passing silently.
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

    // Only the exchange itself is wrapped: what `assertGrantedIdToken` raises
    // is a token rejection, and must stay one.
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
   * Runs the offline-first validation fallback chain (JWKS → introspection).
   * A JWKS failure specifically due to token expiry skips introspection and
   * refreshes immediately instead — introspection would either fail the same
   * way or waste a round trip on a token that's simply stale. Refreshing
   * supersedes both tokens, so this applies even if only one of the two had
   * expired. Any other failure mode (bad signature, unknown key, network
   * error, ...) still runs the full chain before falling back to a refresh.
   *
   * Which tokens reach introspection at all is governed by
   * {@link OidcCoreOptions.introspection}, and what an introspection response
   * has to say about itself before it counts as an access token by
   * {@link OidcCoreOptions.requireIntrospectedTokenType}.
   *
   * **Every token passed in must validate.** If one of them survives no
   * strategy and no refresh replaces it, this throws
   * {@link OidcTokenValidationError} rather than returning the other one's
   * claims — a result whose `accessTokenClaims` is missing because the access
   * token failed verification is indistinguishable from one where no access
   * token was supplied, which would leave the caller treating a token nobody
   * could validate as if it had been.
   *
   * **The result describes the subject that was passed in.** A refresh may
   * replace the token set but not the user: if the refreshed tokens name a
   * different `sub` than the tokens supplied, this throws
   * {@link OidcSubjectError} rather than authenticating whoever the refresh
   * token happened to belong to. That binding is read off the supplied tokens,
   * which requires them to be readable — pass {@link ProcessTokensInput.subject}
   * where they may be opaque, or the check has nothing to compare against and
   * says so at `warn` level.
   *
   * The caller must persist {@link ProcessTokensResult.refreshedTokens} when
   * {@link ProcessTokensResult.refreshed} is `true` — and
   * {@link OidcError.refreshedTokens} when this throws after having refreshed,
   * which is the same obligation on the failure path.
   *
   * **Serialize this per session.** The refresh happens inside a call that runs
   * on every request, and nothing here can see the other calls sharing a
   * session, so concurrent requests against an expired token set each spend the
   * *same* refresh token. Where the provider merely rotates, that wastes round
   * trips; where it also detects reuse — Auth0, Okta, `oidc-provider`, Keycloak
   * with the option on — the replay is read as a stolen token and the whole
   * grant is revoked, which is both an outage and the loss of the signal that
   * detection exists to raise. Keep one in-flight call per session (a promise
   * on the session, or a lock in a shared store), or refresh ahead of expiry
   * from a path that is already serialized.
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
    // Why the tokens of the *latest* attempt failed, for the error thrown at
    // the end. Reset per attempt: once a refresh has replaced the token set,
    // what the old one failed on says nothing about the new one.
    let failures: TokenValidationFailure[] = [];
    // Who this token set belongs to, so a refresh cannot quietly return a
    // different user's. A caller-supplied `subject` is authoritative and is
    // never overwritten; otherwise this is seeded from what the supplied
    // tokens claim and upgraded to a verified subject as soon as one is
    // available.
    let boundSubject =
      subject ?? unverifiedSubject(id_token) ?? unverifiedSubject(access_token);

    /**
     * Whether asking the AS about this token can tell us anything the local
     * pass could not. See {@link OidcCoreOptions.introspection}.
     */
    const worthIntrospecting = (token: string) =>
      introspectionMode !== "never" &&
      (introspectionMode === "auto" || !jwks || !looksLikeJwt(token));

    try {
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
            const promises: Promise<void>[] = [];
            if (introspectAccess) {
              promises.push(
                tokenIntrospection(config, currentAccessToken as string)
                  .then((result) => {
                    if (!result.active) {
                      throw new Error("access token is not active");
                    }
                    // `active: true` says the token is live at this AS — not
                    // that it is an *access* token, and not that it is ours.
                    // One endpoint answers for every token type the AS issues,
                    // so both have to be established separately.
                    assertIntrospectedAccessToken(
                      result as AudienceClaims,
                      tokenTypePolicy,
                    );
                    // RFC 7662 §4 leaves the "issued to you" half to the caller.
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
            if (introspectId) {
              promises.push(
                tokenIntrospection(config, currentIdToken as string)
                  .then((result) => {
                    if (!result.active)
                      throw new Error("id token is not active");
                    // Same reasoning as the access-token slot: `active: true`
                    // does not say *which* kind of token the AS just looked up,
                    // and an access or refresh token presented here satisfies
                    // the client binding identically.
                    assertIntrospectedIdToken(
                      result as AudienceClaims,
                      tokenTypePolicy,
                    );
                    // An introspection response speaks RFC 7662 (`client_id`,
                    // `aud`), not ID-token vocabulary, whichever token was
                    // introspected — so it gets the access-token policy, minus
                    // the resource audience, which an ID token's `aud` could
                    // never match (see `idTokenIntrospectionPolicy`).
                    assertTokenAudience(
                      result as AudienceClaims,
                      "access",
                      idIntrospectionPolicy,
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

        // A subject that has actually been verified beats the unverified read
        // the binding started from. Taken before any refresh, so it describes
        // the set the caller handed in rather than the one that replaced it —
        // and never applied over a declared `subject`, which is the caller's
        // own record and outranks anything read out of a token.
        if (!newTokens && !subject) {
          boundSubject =
            subjectOf(accessTokenValue) ??
            subjectOf(idTokenValue) ??
            boundSubject;
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
      // session. Nothing else checks this: the new token set is internally
      // consistent and signed by the right issuer whoever it belongs to, so a
      // refresh token that got into this token set from somewhere else would
      // otherwise authenticate its own owner in place of the user the caller
      // asked about.
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

      // The same rule for the tokens as supplied, which only a caller-declared
      // subject can state: no refresh has to have happened for a token set to
      // be the wrong user's.
      if (subject && finalSubject && finalSubject !== subject) {
        throw new OidcSubjectError(
          `the tokens describe subject ${finalSubject}, not the ${subject} they were presented for`,
          subject,
          finalSubject,
        );
      }

      // The binding above is only as good as the subject it started from, and
      // an opaque token that no longer introspects names none this library can
      // read. Silently skipping the check is what the warning is for: the
      // guarantee is documented unconditionally, and `subject` is what makes it
      // hold in this case.
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
          // every claim set above was verified *against* — jose's `issuer`
          // option for a JWT, and for an introspection response the AS that
          // answered. A `sub` is unique only within an issuer, so an identity
          // without one is not an identity; see {@link OIDCUser.iss}.
          iss: issuer,
        }),
        accessTokenClaims: accessTokenValue,
        idTokenClaims: idTokenValue,
      };

      if (newTokens) {
        return { ...base, refreshed: true, refreshedTokens: newTokens };
      }
      return { ...base, refreshed: false };
    } catch (err) {
      // A refresh that already happened is not undone by a later rejection:
      // by now the provider has very likely invalidated the refresh token the
      // caller passed in, so the replacement has to travel with the error or
      // the session is unrecoverable. See `attachRefreshedTokens` for which
      // errors may carry it.
      throw attachRefreshedTokens(err, newTokens);
    }
  }

  /**
   * Builds an RP-initiated logout URL (OIDC RP-Initiated Logout 1.0 §2).
   *
   * Pass `idTokenHint` wherever the ID token is still to hand: without it the
   * OP cannot tell which session to end, and §2 has it SHOULD then ask the
   * user to confirm — Keycloak 18+ and others do exactly that, turning a clean
   * logout into an interstitial page. `client_id` is added by `openid-client`
   * either way, which is what keeps `post_logout_redirect_uri` honoured.
   *
   * `postLogoutRedirectUri` must be an absolute http(s) URL without embedded
   * credentials, and has to be registered with the provider — registration is
   * what decides where the user may actually land, so there is no origin
   * allowlist here. See {@link assertSafeRedirectUri} for what is refused and
   * why the check exists at all when the provider also enforces one.
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
   * response is checked against it, since a UserInfo response is claims about
   * whoever the access token belongs to rather than about the user the caller
   * asked for.
   *
   * Wrapped like the grants are: this is a network exchange with the provider,
   * and its ordinary failures — an access token the OP has since revoked, a
   * subject that does not match — must stay inside this library's error
   * hierarchy rather than surfacing as `openid-client`'s own. See
   * {@link OidcUserInfoError}.
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
