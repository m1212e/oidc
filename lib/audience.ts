/**
 * Audience and authorized-party validation.
 *
 * `aud` says who a token is for. `azp` says who asked for it. Configure
 * this via {@link OidcCoreOptions.expectedAudience},
 * {@link OidcCoreOptions.authorizedPartyClaims}, or
 * {@link OidcCoreOptions.verifyAudience} on `createOidcCore`. You shouldn't
 * need to call the functions here directly.
 */

import { OidcTokenError, type TokenKind } from "./errors";

export type { TokenKind } from "./errors";

/**
 * Claims a provider may use to name the client a token was issued to,
 * checked in this order. The first one present wins.
 */
export const DEFAULT_AUTHORIZED_PARTY_CLAIMS: readonly string[] = [
  "azp",
  "client_id",
  "cid",
  "appid",
];

/** Anything claim-shaped: a verified JWT payload or an introspection response. */
export type AudienceClaims = Readonly<Record<string, unknown>>;

export type AudiencePolicy = {
  clientId: string;
  /** Normalized to a non-empty list, or `undefined` when not configured. */
  expectedAudience?: string[];
  authorizedPartyClaims: readonly string[];
  verifyAudience?: (claims: AudienceClaims, tokenKind: TokenKind) => boolean;
};

/** Thrown when a token cannot be bound to this client. */
export class OidcAudienceError extends OidcTokenError {
  constructor(tokenKind: TokenKind, claim: string, message: string) {
    super(tokenKind, claim, message);
    this.name = "OidcAudienceError";
  }
}

/** Normalizes `aud` (string, string array, or absent) to a list. */
function toAudienceList(aud: unknown): string[] {
  if (typeof aud === "string") return [aud];
  if (Array.isArray(aud))
    return aud.filter((entry): entry is string => typeof entry === "string");
  return [];
}

/**
 * The first authorized-party claim the token actually carries. A malformed
 * value still counts as present (and fails the comparison later) rather
 * than falling through to the next claim name.
 */
function findAuthorizedParty(
  claims: AudienceClaims,
  claimNames: readonly string[],
): { claim: string; value: unknown } | undefined {
  for (const claim of claimNames) {
    const value = claims[claim];
    if (value === undefined || value === null) continue;
    return { claim, value };
  }
  return undefined;
}

/**
 * What to pass as jose's `audience` verification option. Returns `undefined`
 * when `aud` shouldn't be checked at all (nothing configured, or
 * {@link AudiencePolicy.verifyAudience} replacing the whole policy).
 */
export function audienceVerifyOption(
  policy: AudiencePolicy,
  tokenKind: TokenKind,
): string | string[] | undefined {
  if (policy.verifyAudience) return undefined;
  return tokenKind === "id" ? policy.clientId : policy.expectedAudience;
}

/**
 * The `aud` check {@link audienceVerifyOption} would hand to jose, run
 * directly for claims that never go through `jwtVerify`.
 */
export function assertAudienceClaim(
  claims: AudienceClaims,
  tokenKind: TokenKind,
  policy: AudiencePolicy,
): void {
  const expected =
    tokenKind === "id" ? [policy.clientId] : policy.expectedAudience;
  if (!expected?.length) return;

  const aud = toAudienceList(claims.aud);
  if (!aud.some((entry) => expected.includes(entry))) {
    throw new OidcAudienceError(
      tokenKind,
      "aud",
      `${tokenKind} token "aud" (${aud.length ? aud.join(", ") : "absent"}) does not include any expected audience (${expected.join(", ")})`,
    );
  }
}

/**
 * Binds a token to this client via `azp` (id tokens) or an
 * authorized-party claim (access tokens). For access tokens, set
 * {@link AudiencePolicy.expectedAudience} if you're a resource server
 * checking `aud` instead. See {@link OidcCoreOptions.expectedAudience}.
 */
export function assertAuthorizedParty(
  claims: AudienceClaims,
  tokenKind: TokenKind,
  policy: AudiencePolicy,
): void {
  const { clientId, expectedAudience, authorizedPartyClaims } = policy;

  if (tokenKind === "id") {
    const azp = claims.azp;
    if (azp !== undefined && azp !== null) {
      if (azp !== clientId) {
        throw new OidcAudienceError(
          "id",
          "azp",
          `id token "azp" (${String(azp)}) is not this client id (${clientId})`,
        );
      }
      return;
    }
    const aud = toAudienceList(claims.aud);
    if (aud.length > 1) {
      throw new OidcAudienceError(
        "id",
        "azp",
        `id token "aud" names multiple parties (${aud.join(", ")}) but carries no "azp" claim identifying the authorized one`,
      );
    }
    return;
  }

  if (expectedAudience?.length) {
    assertAudienceClaim(claims, "access", policy);
    return;
  }

  const party = findAuthorizedParty(claims, authorizedPartyClaims);
  if (party) {
    if (typeof party.value !== "string" || party.value !== clientId) {
      throw new OidcAudienceError(
        "access",
        party.claim,
        `access token "${party.claim}" (${
          typeof party.value === "string"
            ? party.value
            : JSON.stringify(party.value)
        }) is not this client id (${clientId})`,
      );
    }
    return;
  }
  throw new OidcAudienceError(
    "access",
    "aud",
    `access token cannot be bound to this client: it carries none of the authorized-party claims (${authorizedPartyClaims.join(", ")}) and no "expectedAudience" is configured. Set "expectedAudience" to the value this resource server expects in "aud", extend "authorizedPartyClaims" with the claim your provider uses, or supply "verifyAudience".`,
  );
}

/**
 * Runs the authorized-party check for a token jose already verified `aud`
 * for via {@link audienceVerifyOption}.
 */
export function assertAudienceAfterJwtVerify(
  claims: AudienceClaims,
  tokenKind: TokenKind,
  policy: AudiencePolicy,
): void {
  if (policy.verifyAudience) {
    if (!policy.verifyAudience(claims, tokenKind)) {
      throw new OidcAudienceError(
        tokenKind,
        "aud",
        `verifyAudience rejected the ${tokenKind} token`,
      );
    }
    return;
  }
  assertAuthorizedParty(claims, tokenKind, policy);
}

/** The complete audience policy, for claims jose never saw (introspection responses). */
export function assertTokenAudience(
  claims: AudienceClaims,
  tokenKind: TokenKind,
  policy: AudiencePolicy,
): void {
  if (!policy.verifyAudience) assertAudienceClaim(claims, tokenKind, policy);
  assertAudienceAfterJwtVerify(claims, tokenKind, policy);
}

/**
 * The audience policy for an id token's introspection response, with any
 * configured resource audience dropped since an id token's `aud` is always
 * the client id.
 */
export function idTokenIntrospectionPolicy(
  policy: AudiencePolicy,
): AudiencePolicy {
  if (!policy.expectedAudience) return policy;
  return { ...policy, expectedAudience: undefined };
}

export function buildAudiencePolicy(opts: {
  clientId: string;
  expectedAudience?: string | string[];
  authorizedPartyClaims?: readonly string[];
  verifyAudience?: (claims: AudienceClaims, tokenKind: TokenKind) => boolean;
}): AudiencePolicy {
  const supplied =
    typeof opts.expectedAudience === "string"
      ? [opts.expectedAudience]
      : (opts.expectedAudience ?? []);

  const invalid = supplied.filter(
    (entry) => typeof entry !== "string" || entry.length === 0,
  );
  if (invalid.length) {
    throw new TypeError(
      `invalid expectedAudience: every entry must be a non-empty string, and ${invalid.length} of ${supplied.length} ${invalid.length === 1 ? "is" : "are"} not. An empty audience matches nothing, so it cannot be dropped without silently replacing the resource-audience binding with the authorized-party one. Omit "expectedAudience" entirely to use that binding on purpose.`,
    );
  }
  const expected = supplied;

  return {
    clientId: opts.clientId,
    expectedAudience: expected.length ? expected : undefined,
    authorizedPartyClaims:
      opts.authorizedPartyClaims ?? DEFAULT_AUTHORIZED_PARTY_CLAIMS,
    verifyAudience: opts.verifyAudience,
  };
}
