/**
 * Audience / authorized-party validation.
 *
 * `aud` answers "who is this token *for*", `azp` answers "who *asked* for
 * it". For access tokens those are routinely different, and the claim naming
 * the requesting client isn't consistent across providers (RFC 9068's
 * `client_id`, Keycloak/Auth0/Entra's `azp`, Okta's `cid`, Entra v1's
 * `appid`).
 *
 * Matching `aud` is generic JWT work, delegated to jose's `audience` option
 * wherever a token passes through `jwtVerify` (see {@link audienceVerifyOption}).
 * What stays here is the `azp` rule jose has no concept of, plus the checks
 * needed for claim sets jose never sees — RFC 7662 introspection responses.
 */

import { OidcTokenError, type TokenKind } from "./errors";

export type { TokenKind } from "./errors";

/**
 * Claims a provider may use to name the client a token was issued to,
 * consulted in this order — the first one present wins. `client_id` is the
 * RFC 9068 / RFC 7662 spelling; the rest are provider extensions.
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

/**
 * Thrown when a token cannot be bound to this client — a permanent
 * rejection, so the validation fallback chain must not retry another
 * strategy or spend a refresh token on it.
 */
export class OidcAudienceError extends OidcTokenError {
  constructor(tokenKind: TokenKind, claim: string, message: string) {
    super(tokenKind, claim, message);
    this.name = "OidcAudienceError";
  }
}

/** `aud` is a string, an array of strings, or absent. Normalize all three. */
function toAudienceList(aud: unknown): string[] {
  if (typeof aud === "string") return [aud];
  if (Array.isArray(aud))
    return aud.filter((entry): entry is string => typeof entry === "string");
  return [];
}

/**
 * The first authorized-party claim the token actually carries.
 *
 * A present-but-malformed binding (`azp: ["other-client"]`, `client_id: ""`)
 * must fail the comparison rather than fall through to the next claim name —
 * otherwise a token gets bound by a claim its issuer never intended as the
 * binding. `null` counts as absent, as JSON's way of spelling "not there".
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
 * What to pass as jose's `audience` verification option, which also makes
 * `aud` presence required.
 *
 * An access token's `aud` is only checked when {@link AudiencePolicy.expectedAudience}
 * is set: stock Keycloak issues access tokens with `aud: "account"` and the
 * real client in `azp`, so comparing against the client id here would reject
 * every default Keycloak deployment.
 *
 * Returns `undefined` when jose must not check `aud` at all — nothing
 * configured, or {@link AudiencePolicy.verifyAudience} replacing the whole
 * policy.
 */
export function audienceVerifyOption(
  policy: AudiencePolicy,
  tokenKind: TokenKind,
): string | string[] | undefined {
  if (policy.verifyAudience) return undefined;
  return tokenKind === "id" ? policy.clientId : policy.expectedAudience;
}

/**
 * The `aud` matching {@link audienceVerifyOption} would have handed to jose.
 * Only needed for claim sets that never pass through `jwtVerify`.
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
 * The half jose can't do: binding a token to us, by whichever of the two
 * available bindings the configuration makes possible.
 *
 * ID tokens (OIDC Core 3.1.3.7): a present `azp` MUST equal the client id,
 * and a multi-party `aud` MUST carry an `azp` to disambiguate.
 *
 * Access tokens ask a different question depending on
 * {@link AudiencePolicy.expectedAudience}:
 * - Configured: "was this token minted for me, the resource?" — `aud` must
 *   intersect it. The authorized-party claim is *not* compared to the client
 *   id, since for a resource server the requesting client is a different
 *   party by design.
 * - Not configured: "was this token issued to me, the client?" — the first
 *   present {@link AudiencePolicy.authorizedPartyClaims} claim MUST equal the
 *   client id.
 *
 * A configured `expectedAudience` is not just one way to pass: a token whose
 * `aud` names some other resource stays rejected even with a matching `azp`,
 * because that's audience confusion — one resource server replaying a token
 * meant for another.
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

  // Re-run rather than assumed already checked by jose, so this function is
  // sound when called on its own (e.g. from an introspection response).
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
 * The residual policy for a token jose has already verified — `aud` was
 * handled there via {@link audienceVerifyOption}, so only the
 * authorized-party half is left.
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

/**
 * The complete policy, for claim sets jose never saw — i.e. RFC 7662
 * introspection responses.
 */
export function assertTokenAudience(
  claims: AudienceClaims,
  tokenKind: TokenKind,
  policy: AudiencePolicy,
): void {
  if (!policy.verifyAudience) assertAudienceClaim(claims, tokenKind, policy);
  assertAudienceAfterJwtVerify(claims, tokenKind, policy);
}

/**
 * The policy to hold an *ID token's* introspection response to.
 *
 * Such a response speaks RFC 7662 vocabulary (`client_id`, `aud`), so it gets
 * the access-token policy — but a configured
 * {@link AudiencePolicy.expectedAudience} names the resource this server
 * answers to, and an ID token's `aud` is the client id by definition.
 * Matching one against the other can never succeed, so it's dropped here,
 * leaving just the client binding.
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

  // Dropping an invalid entry can't be done safely: dropping the only one
  // silently falls back to the authorized-party binding while the deployment
  // looks like it pinned an audience.
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
