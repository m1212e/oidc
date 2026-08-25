import { createRemoteJWKSet } from "jose";
import {
  allowInsecureRequests,
  clockTolerance as clockToleranceOption,
  discovery,
} from "openid-client";
import { buildAudiencePolicy } from "../audience";
import {
  assertDiscoveredIssuer,
  assertPkceSupported,
  resolveClockTolerance,
  resolveDevelopment,
  resolveJwksUri,
  resolveSigningAlgorithms,
} from "../discovery";
import { buildLogger } from "../logger";
import { buildReturnToPolicy } from "../returnTo";
import { buildTokenTypePolicy } from "../tokenType";
import type { CoreContext } from "./context";
import { createLogout } from "./logout";
import { createProcessTokens } from "./processTokens";
import { createRefresh } from "./refresh";
import { createSignin } from "./signin";
import { createUserInfoFetcher } from "./userInfo";

export {
  assertDiscoveredIssuer,
  assertPkceSupported,
  DEFAULT_SIGNING_ALGORITHMS,
  resolveClockTolerance,
  resolveDevelopment,
  resolveJwksUri,
} from "../discovery";
export type {
  OidcCoreOptions,
  ProcessTokensInput,
  ProcessTokensResult,
  ResolveSigninResult,
  StartSigninResult,
} from "./options";

import type { OidcCoreOptions } from "./options";

/**
 * Discovers an OIDC issuer and returns the operations you need to
 * implement login: `startSignin`/`resolveSignin` for the authorization
 * code flow, `processTokens` for validation, `refresh`, `getLogoutUrl`,
 * and `fetchUserInfoFromIssuer`. Framework-agnostic: call it once at
 * startup with your issuer and client id, then use the returned object
 * wherever you need it.
 */
export async function createOidcCore(opts: OidcCoreOptions) {
  const log = buildLogger(opts.logger, opts.logLevel);
  const development = resolveDevelopment(opts.development);

  if (development) {
    log.warn(
      "[oidc] development mode is on: plain-HTTP requests to the IdP are allowed. Never enable this in production.",
    );
  }

  if (typeof opts.clientId !== "string" || opts.clientId.length === 0) {
    throw new TypeError(
      "invalid clientId: expected a non-empty string. It is what every token is bound to, so there is nothing this library could check without it.",
    );
  }

  if (opts.verifyAudience && opts.expectedAudience !== undefined) {
    log.warn(
      '[oidc] both "verifyAudience" and "expectedAudience" are set. "verifyAudience" replaces the audience policy entirely, so "expectedAudience" is not checked at all. Assert it inside your callback, or drop one of the two.',
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

  if (!jwksUri) {
    log.warn(
      `[oidc] the issuer advertises no "jwks_uri", so no token can be verified offline. Every validation will fall back to remote introspection${
        (opts.introspection ?? "opaque-only") === "never"
          ? ", which \"introspection: 'never'\" has switched off, so no token will validate at all"
          : ", one round trip to the IdP per request"
      }.`,
    );
  }

  const audiencePolicy = buildAudiencePolicy(opts);
  const ctx: CoreContext = {
    config,
    log,
    issuer,
    jwks,
    audiencePolicy,
    tokenTypePolicy: buildTokenTypePolicy(opts),
    returnToPolicy: buildReturnToPolicy(opts),
    introspectionMode: opts.introspection ?? "opaque-only",
    clockTolerance,
    signingAlgorithms: resolveSigningAlgorithms(
      config,
      opts.signingAlgorithms,
      log,
    ),
  };

  const { startSignin, resolveSignin } = createSignin(ctx);
  const refresh = createRefresh(ctx);
  const processTokens = createProcessTokens(ctx, refresh);
  const getLogoutUrl = createLogout(ctx);
  const fetchUserInfoFromIssuer = createUserInfoFetcher(ctx);

  return {
    /** The discovered `openid-client` configuration, for advanced use. */
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
