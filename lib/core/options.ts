import type {
  TokenEndpointResponse,
  TokenEndpointResponseHelpers,
} from "openid-client";
import type { AudienceClaims } from "../audience";
import type { DelegationPolicy } from "../delegation";
import type { TokenKind } from "../errors";
import type { Logger, LogLevel } from "../logger";
import type { ValidationResult } from "../types";

export type OidcCoreOptions = {
  /** Your OpenID Provider's issuer URL, used for discovery. */
  issuer: string;
  clientId: string;
  /** Omit for a public client (no secret, PKCE only). */
  clientSecret?: string;
  /**
   * Audience value(s) this resource server accepts, checked against an
   * access token's `aud`. Leave unset unless your provider puts a resource
   * audience on access tokens. With stock Keycloak or Cognito, leave this
   * unset and use {@link authorizedPartyClaims} instead.
   *
   * Not checked against id tokens.
   */
  expectedAudience?: string | string[];
  /**
   * Claims that may name the client an access token was issued to, checked
   * in order. The first one present must equal {@link clientId}. Defaults
   * to `["azp", "client_id", "cid", "appid"]`, covering Keycloak, Auth0,
   * Entra ID, Okta, and Cognito. Ignored once {@link expectedAudience} is set.
   */
  authorizedPartyClaims?: readonly string[];
  /**
   * Escape hatch: replaces the built-in audience policy entirely for both
   * access and id tokens. Return `false` to reject the token. Use this if
   * your provider doesn't fit {@link expectedAudience} or
   * {@link authorizedPartyClaims}.
   */
  verifyAudience?: (claims: AudienceClaims, tokenKind: TokenKind) => boolean;
  /**
   * Required for a multi-tenant issuer (Entra ID's `/common` or
   * `/organizations`), and refused for any other. Every tenant's tokens
   * carry a valid signature there, so list the tenant ids (`tid`) you
   * accept, or pass `"any"` to accept every tenant, personal Microsoft
   * accounts included.
   */
  allowedTenants?: readonly string[] | "any";
  /**
   * What `processTokens` does with a delegated token, one whose RFC 8693
   * `act` claim names a party acting on the user's behalf. Defaults to
   * `"reject"`, since treating the actor's request as the user's own is
   * rarely what an app means. `"allow"` accepts any chain, a function
   * decides per chain (current actor first). Accepted chains are reported
   * as `result.actors`.
   */
  delegation?: DelegationPolicy;
  /**
   * Claims that only appear on id tokens. An access token carrying one of
   * these is rejected. Defaults to
   * `["nonce", "at_hash", "c_hash", "s_hash"]`. Only change this if your
   * provider is known to put one of these on access tokens too.
   */
  idTokenOnlyClaims?: readonly string[];
  /**
   * Require this exact `typ` JWS header on JWT access tokens, e.g.
   * `"at+jwt"` (RFC 9068). Unset by default since Auth0 and Entra ID send
   * `"JWT"` on both token kinds. Set this if your provider distinguishes
   * access and id tokens by header. For Keycloak, enable its RFC 9068
   * header option first and set this to `"at+jwt"`. Otherwise leave it
   * unset and rely on the `typ` claim instead.
   */
  accessTokenTyp?: string;
  /**
   * Require an introspection response to affirmatively name the kind of
   * token it describes (`token_type`, `typ`, or `token_use`). Defaults to
   * `true`. Turn off only if your provider omits the type on genuine
   * access tokens.
   */
  requireIntrospectedTokenType?: boolean;
  /**
   * When to fall back to remote introspection. Defaults to `"opaque-only"`.
   *
   * - `"opaque-only"`: introspect only tokens that aren't JWTs (or
   *   everything, if the issuer advertises no JWKS).
   * - `"auto"`: introspect anything local verification rejected. Needed
   *   only if your provider signs access tokens with keys outside the id
   *   token JWKS.
   * - `"never"`: offline verification only. Opaque tokens can't validate.
   */
  introspection?: "opaque-only" | "auto" | "never";
  /**
   * Origins an absolute `returnTo` may point to, e.g.
   * `["https://app.example.com"]`. Empty by default, which allows only
   * same-site paths like `"/dashboard"`.
   */
  allowedReturnToOrigins?: readonly string[];
  /**
   * Clock skew tolerance for `exp`/`nbf`, in seconds or as a duration
   * string (`"30 seconds"`, `"5m"`). Defaults to 30s.
   */
  clockTolerance?: string | number;
  /**
   * JWS algorithms accepted when verifying tokens offline. Defaults to the
   * issuer's advertised algorithms, falling back to
   * {@link DEFAULT_SIGNING_ALGORITHMS}. Set this explicitly if your
   * provider signs access tokens with an algorithm it doesn't advertise
   * for id tokens.
   */
  signingAlgorithms?: string[];
  /**
   * Allows discovery and token requests over plain HTTP. Only for a
   * local/dev IdP, never in production. Defaults to on when
   * `NODE_ENV=development`, off otherwise.
   */
  development?: boolean;
  logger?: Logger;
  logLevel?: LogLevel;
};

export type StartSigninResult = {
  codeVerifier: string;
  authorizationUrl: URL;
  /** Opaque: store it and pass it back to {@link resolveSignin} as `expectedState`. */
  state: string;
};

export type ResolveSigninResult = {
  tokens: TokenEndpointResponse & TokenEndpointResponseHelpers;
  /** The URL the user was trying to reach before being sent to the IdP. */
  returnTo: string;
};

/** The `sub` this token set is known to belong to, if you have it on file. */
type SubjectBinding = { subject?: string };

/**
 * At least one of `access_token` or `id_token` is required. For all three
 * token fields, `undefined` means "I don't have this token" and it is
 * skipped. `null` or `""` is treated as malformed input and throws
 * {@link OidcInputError}, so pass `undefined`, not a cookie-read `null`,
 * when a token is absent.
 */
export type ProcessTokensInput = SubjectBinding &
  (
    | {
        access_token: string | null;
        id_token?: string | null;
        refresh_token?: string | null;
      }
    | {
        access_token?: string | null;
        id_token: string | null;
        refresh_token?: string | null;
      }
  );

/**
 * Narrow on `refreshed` (`if (result.refreshed)`) to get a definite
 * `refreshedTokens`. Persist it in place of the old token set.
 */
export type ProcessTokensResult = ValidationResult &
  (
    | {
        refreshed: true;
        refreshedTokens: TokenEndpointResponse & TokenEndpointResponseHelpers;
      }
    | { refreshed: false; refreshedTokens?: undefined }
  );
