/**
 * Audience / authorized-party validation.
 *
 * `aud` answers "who is this token *for*", `azp` answers "who *asked* for it".
 * For ID tokens those are normally the same party, which is why OIDC Core
 * makes the `aud` check a MUST and the `azp` check only a SHOULD-when-present.
 * For access tokens they are routinely different, and the claim naming the
 * requesting client is not consistent across providers: RFC 9068 specifies
 * `client_id`, while Keycloak, Auth0 and Entra ID use `azp`, Okta uses `cid`,
 * and Entra v1 uses `appid`.
 *
 * Matching `aud` is generic JWT work, so it is delegated to jose's `audience`
 * option wherever a token actually passes through `jwtVerify` — see
 * {@link audienceVerifyOption}. What stays here is the part jose has no
 * concept of (`azp` appears nowhere in jose) plus the checks for claim sets
 * jose never sees, i.e. RFC 7662 introspection responses.
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
 * Thrown when a token cannot be bound to this client. Distinct from a
 * signature/expiry failure: this is a *permanent* rejection, so the
 * validation fallback chain must not retry, try another strategy, or spend a
 * refresh token on it.
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

function findAuthorizedParty(
  claims: AudienceClaims,
  claimNames: readonly string[],
): { claim: string; value: string } | undefined {
  for (const claim of claimNames) {
    const value = claims[claim];
    if (typeof value === "string" && value.length > 0) return { claim, value };
  }
  return undefined;
}

/**
 * What to pass as jose's `audience` verification option, which also makes
 * `aud` presence required.
 *
 * An ID token's `aud` is always the client id, so that one is unconditional.
 * An access token's is only checked against an explicitly configured
 * `expectedAudience` — and is otherwise left unchecked on purpose. Stock
 * Keycloak issues access tokens with `aud: "account"` and the real client in
 * `azp`, so comparing an access token's `aud` to the client id would reject
 * every default Keycloak deployment.
 *
 * Returns `undefined` when jose must not check `aud` at all — either because
 * nothing is configured, or because {@link AudiencePolicy.verifyAudience}
 * has taken over the whole policy.
 */
export function audienceVerifyOption(
  policy: AudiencePolicy,
  tokenKind: TokenKind,
): string | string[] | undefined {
  if (policy.verifyAudience) return undefined;
  return tokenKind === "id" ? policy.clientId : policy.expectedAudience;
}

/**
 * The `aud` matching that {@link audienceVerifyOption} would have handed to
 * jose. Only needed for claim sets that never pass through `jwtVerify`.
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
 * The half jose cannot do: binding a token to us, by whichever of the two
 * available bindings the configuration makes possible.
 *
 * For ID tokens (OIDC Core 3.1.3.7): a present `azp` MUST equal the client id,
 * and a multi-party `aud` MUST carry an `azp` to disambiguate. Checking `azp`
 * whenever it is present is stricter than `oauth4webapi`, which only consults
 * it for multi-element `aud` — but no provider issues *you* a token carrying
 * someone else's `azp`, so there is nothing to lose.
 *
 * For access tokens the two bindings answer different questions, and which
 * one applies depends on {@link AudiencePolicy.expectedAudience}:
 *
 * - Configured: "was this token minted for me, the resource?" `aud` must
 *   intersect it, and the authorized-party claim is *not* compared to the
 *   client id — for a resource server the client that requested the token is
 *   a different party by design, so requiring both rejects every ordinary
 *   API/SPA split.
 * - Not configured: "was this token issued to me, the client?" The first
 *   present {@link AudiencePolicy.authorizedPartyClaims} claim MUST equal the
 *   client id — the only binding available when a provider puts no resource
 *   audience on access tokens at all.
 *
 * Note the asymmetry: a configured `expectedAudience` is not merely *one* way
 * to pass. A token whose `aud` names some other resource stays rejected even
 * when its `azp` is this client id, because that is the audience-confusion
 * case — one resource server replaying a token at another — and the client
 * binding says nothing about which resource the token was minted for.
 *
 * A token bindable neither way is rejected outright.
 */
export function assertAuthorizedParty(
  claims: AudienceClaims,
  tokenKind: TokenKind,
  policy: AudiencePolicy,
): void {
  const { clientId, expectedAudience, authorizedPartyClaims } = policy;

  if (tokenKind === "id") {
    const azp = claims.azp;
    if (azp !== undefined) {
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

  // A configured resource audience takes over the binding. The `aud` match is
  // re-run rather than assumed to have happened in jose, so that this function
  // is sound when called on its own.
  if (expectedAudience?.length) {
    assertAudienceClaim(claims, "access", policy);
    return;
  }

  const party = findAuthorizedParty(claims, authorizedPartyClaims);
  if (party) {
    if (party.value !== clientId) {
      throw new OidcAudienceError(
        "access",
        party.claim,
        `access token "${party.claim}" (${party.value}) is not this client id (${clientId})`,
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
  if (policy.verifyAudience) {
    assertAudienceAfterJwtVerify(claims, tokenKind, policy);
    return;
  }
  assertAudienceClaim(claims, tokenKind, policy);
  assertAuthorizedParty(claims, tokenKind, policy);
}

export function buildAudiencePolicy(opts: {
  clientId: string;
  expectedAudience?: string | string[];
  authorizedPartyClaims?: readonly string[];
  verifyAudience?: (claims: AudienceClaims, tokenKind: TokenKind) => boolean;
}): AudiencePolicy {
  const expected = (
    typeof opts.expectedAudience === "string"
      ? [opts.expectedAudience]
      : (opts.expectedAudience ?? [])
  ).filter((entry) => entry.length > 0);

  return {
    clientId: opts.clientId,
    expectedAudience: expected.length ? expected : undefined,
    authorizedPartyClaims:
      opts.authorizedPartyClaims ?? DEFAULT_AUTHORIZED_PARTY_CLAIMS,
    verifyAudience: opts.verifyAudience,
  };
}
