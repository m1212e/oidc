/**
 * Issuer-discovery helpers: settling, once at construction time, the things
 * about a provider that have to hold before any token exchange is trusted —
 * that its signing keys can be fetched without a network attacker swapping
 * them, that the metadata document actually describes the issuer that was
 * asked for, and that it will honour the PKCE challenge every authorization
 * request carries. All three fail silently if left unchecked, which is why
 * they're refused at construction rather than surfacing later as a forged
 * token or a hijacked code.
 */

import type { Logger } from "./logger";

/**
 * Resolves {@link OidcCoreOptions.development} against the environment when
 * not passed explicitly. Only an exact `NODE_ENV=development` enables it —
 * an unset `NODE_ENV` must fail closed, since guessing wrong here means
 * silently permitting plain-HTTP traffic to the IdP in production.
 */
export function resolveDevelopment(development?: boolean): boolean {
  if (development !== undefined) return development;
  if (typeof process === "undefined") return false;
  return process.env?.NODE_ENV === "development";
}

/**
 * Accepted when the issuer advertises no
 * `id_token_signing_alg_values_supported` (REQUIRED by OIDC discovery, but
 * not by plain OAuth AS metadata). Asymmetric only — a symmetric `alg`
 * verified against a JWKS key is the algorithm-confusion shape.
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

/** Whether an `alg` is one a public key from a JWKS can verify. */
export function isAsymmetricAlgorithm(alg: string): boolean {
  return /^(RS|PS|ES|Ed)/.test(alg);
}

/**
 * Refuses the issuer's `jwks_uri` unless it can be fetched safely.
 *
 * `openid-client` holds every request it makes to https except in
 * {@link OidcCoreOptions.development}, but the JWKS fetch goes through jose's
 * `createRemoteJWKSet`, which has no such switch and will fetch plain HTTP
 * without complaint. That fetch decides whether a signature verifies, so
 * serving it over plain HTTP is one MITM key substitution away from forged
 * tokens for any subject.
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
 * Confirms the metadata document names the issuer that was actually asked
 * for.
 *
 * `openid-client` performs this comparison itself, but only when it had to
 * *derive* the metadata URL from an issuer identifier. If `issuer` already
 * contains `/.well-known/` — an entirely ordinary way to configure a client —
 * it takes the document's word instead, which turns {@link OidcCoreOptions.issuer}
 * from a pin into a hint: the `iss` every token is checked against, the
 * `jwks_uri`, and the token endpoint all become whatever the document said. A
 * document naming a foreign issuer would otherwise be accepted in full.
 *
 * The well-known path is either *appended* to the issuer (OIDC Discovery 1.0
 * §4) or *inserted* after the host (RFC 8414 §3.1). The appended form spells
 * the issuer out, so it's compared exactly. The inserted form can't be
 * reversed — the boundary between the well-known name and the issuer path
 * isn't recoverable — so it falls back to requiring the same origin.
 *
 * `login.microsoftonline.com` and `*.b2clogin.com` get the origin check too,
 * mirroring `openid-client`'s own exemption: Entra ID's `/common` and
 * `/organizations` documents answer with a literal `{tenantid}` placeholder.
 */
export function assertDiscoveredIssuer(
  configured: string,
  discovered: string,
): void {
  let configuredUrl: URL;
  try {
    configuredUrl = new URL(configured);
  } catch {
    // Only reachable by calling this helper directly with a non-URL —
    // `createOidcCore` always parses `issuer` into a URL before discovery
    // runs, and a value that isn't a URL carries no `.well-known` to decide
    // anything from.
    return;
  }

  const path = configuredUrl.origin + configuredUrl.pathname;
  const wellKnownAt = path.indexOf(WELL_KNOWN);
  // No well-known segment means `openid-client` already compared them,
  // exactly, exemptions included — re-running that here would only get the
  // exempted hosts wrong.
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

  // The inserted form has only an origin to compare, so the document's
  // issuer has to be a URL for there to be a comparison at all — stepping
  // over an unparseable one would leave nothing holding the document to the
  // provider it was fetched from.
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
 * For a public client (no `clientSecret`), PKCE is the *only* thing
 * protecting the token endpoint from a leaked authorization code. An AS that
 * doesn't understand `code_challenge` ignores it silently and answers the
 * exchange normally, so an issuer that doesn't list `S256` is refused
 * outright — `plain` is not a fallback, since a challenge equal to the
 * verifier defends against nothing.
 *
 * An absent `code_challenge_methods_supported` only warns: RFC 8414 reads
 * that as "no PKCE", but several providers that do support it (Cognito among
 * them) omit the field regardless, and there's no caller-side fix for that.
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

/** jose's duration grammar, minus the signed/relative forms a tolerance can't use. */
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
 * jose takes a number or a duration string, `openid-client` only seconds —
 * the two have to agree, or a tolerance that covers offline verification but
 * not the code exchange leaves exactly the drift it exists for able to fail a
 * login.
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
