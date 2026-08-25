/**
 * Issuer-discovery helpers used internally by `createOidcCore` to validate
 * a provider's metadata at startup.
 */

import type { Configuration } from "openid-client";
import type { Logger } from "./logger";

/**
 * Resolves {@link OidcCoreOptions.development} from `NODE_ENV` when not
 * passed explicitly. Only `NODE_ENV=development` turns it on.
 */
export function resolveDevelopment(development?: boolean): boolean {
  if (development !== undefined) return development;
  if (typeof process === "undefined") return false;
  return process.env?.NODE_ENV === "development";
}

/**
 * Fallback signing algorithms used when the issuer advertises none.
 * Asymmetric only, since offline verification uses a public JWKS key.
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

/** Whether an `alg` is one a public JWKS key can verify. */
export function isAsymmetricAlgorithm(alg: string): boolean {
  return /^(RS|PS|ES|Ed)/.test(alg);
}

/** Rejects the issuer's `jwks_uri` unless it can be fetched safely. */
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

/** Hosts `openid-client` exempts from its own issuer comparison. */
function issuerMatchExempt(url: URL): boolean {
  return (
    url.origin === "https://login.microsoftonline.com" ||
    url.hostname.endsWith(".b2clogin.com")
  );
}

const WELL_KNOWN = "/.well-known/";
const withoutTrailingSlash = (value: string) => value.replace(/\/+$/, "");

/** Confirms the metadata document names the issuer that was actually asked for. */
export function assertDiscoveredIssuer(
  configured: string,
  discovered: string,
): void {
  let configuredUrl: URL;
  try {
    configuredUrl = new URL(configured);
  } catch {
    return;
  }

  const path = configuredUrl.origin + configuredUrl.pathname;
  const wellKnownAt = path.indexOf(WELL_KNOWN);
  // No well-known segment: `openid-client` already did this comparison.
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

/** Rejects an issuer that cannot honour the PKCE challenge {@link OidcCore.startSignin} sends. */
export function assertPkceSupported(
  methods: string[] | undefined,
  clientSecret: string | undefined,
  log: Logger,
): void {
  if (methods?.includes("S256")) return;
  if (methods?.length) {
    throw new TypeError(
      `the issuer does not support the S256 PKCE challenge method (it advertises: ${methods.join(", ")}). This library sends S256 on every authorization request, and without it an authorization code isn't bound to the login that requested it. An issuer that ignores it would leave the code redeemable by anyone who obtained it.`,
    );
  }
  log.warn(
    `[oidc] the issuer advertises no "code_challenge_methods_supported", so it cannot be confirmed that the PKCE challenge this library sends is honoured${
      clientSecret
        ? ""
        : ". This is a public client, where PKCE is the only thing protecting the token endpoint"
    }. Verify that PKCE is enforced for this client at the IdP.`,
  );
}

/** jose's duration grammar, minus forms a tolerance can't use. */
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

/** Resolves {@link OidcCoreOptions.clockTolerance} to whole seconds. */
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
 * The JWS algorithms offline verification accepts. An explicit list is
 * taken as-is. A discovered one is filtered to asymmetric algorithms only.
 */
export function resolveSigningAlgorithms(
  config: Configuration,
  signingAlgorithms: string[] | undefined,
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
    signingAlgorithms ??
    (advertisedAlgorithms.length
      ? advertisedAlgorithms
      : [...DEFAULT_SIGNING_ALGORITHMS])
  );
}
