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
  issuer: string;
  clientId: string;
  clientSecret?: string;
  expectedAudience?: string | string[];
  authorizedPartyClaims?: readonly string[];
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
  accessTokenTyp?: string;
  requireIntrospectedTokenType?: boolean;
  introspection?: "opaque-only" | "auto" | "never";
  /**
   * Resource indicator(s) (RFC 8707) to request tokens for, sent with the
   * authorization request, the code exchange and every refresh. Set this
   * when the provider issues access tokens for an API resource: Logto, for
   * one, issues an opaque access token without it, which can only be
   * validated by introspection, a round trip to the IdP per request. With
   * it, the access token is a JWT for that resource, verified offline.
   *
   * The token's `aud` is then the resource, not the client id. That
   * passes the default {@link authorizedPartyClaims} check as long as the
   * token names the client (Logto's `client_id` does); set
   * {@link expectedAudience} to the resource to check `aud` instead.
   */
  resource?: string | readonly string[];
  /**
   * The `prompt` sent with every authorization request (space-separated
   * values: `"consent"`, `"login"`, `"select_account"`, `"none"`), unless
   * `startSignin` passes its own. OIDC Core §11 requires `"consent"` when
   * the scope asks for `offline_access`, and providers that follow it to
   * the letter (Logto, anything on node-oidc-provider) silently issue no
   * refresh token without it. Others (Google, Entra ID) show their consent
   * screen on every sign-in when it is sent, so it is not the default.
   */
  prompt?: string;
  allowedReturnToOrigins?: readonly string[];
  clockTolerance?: string | number;
  signingAlgorithms?: string[];
  development?: boolean;
  logger?: Logger;
  logLevel?: LogLevel;
};

export type StartSigninResult = {
  codeVerifier: string;
  authorizationUrl: URL;
  state: string;
};

export type ResolveSigninResult = {
  tokens: TokenEndpointResponse & TokenEndpointResponseHelpers;
  returnTo: string;
};

type SubjectBinding = { subject?: string };

// At least one token is required, which is checked at runtime.
export type ProcessTokensInput = SubjectBinding & {
  access_token?: string | null;
  id_token?: string | null;
  refresh_token?: string | null;
  /**
   * Replaces {@link OidcCoreOptions.delegation} for this call, e.g. to accept
   * an impersonation token only when its actor is the caller's own session.
   */
  delegation?: DelegationPolicy;
  /**
   * Refuse tokens that are not delegated. A `delegation` policy is only
   * consulted for tokens carrying `act`, so set this when an actor is the
   * point, e.g. for an impersonation session.
   */
  requireActor?: boolean;
};

export type ProcessTokensResult = ValidationResult &
  (
    | {
        refreshed: true;
        refreshedTokens: TokenEndpointResponse & TokenEndpointResponseHelpers;
      }
    | { refreshed: false; refreshedTokens?: undefined }
  );
