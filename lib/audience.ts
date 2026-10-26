import { OidcTokenError, type TokenKind } from "./errors";

export type { TokenKind } from "./errors";

export const DEFAULT_AUTHORIZED_PARTY_CLAIMS: readonly string[] = [
  "azp",
  "client_id",
  "cid",
  "appid",
];

export type AudienceClaims = Readonly<Record<string, unknown>>;

export type AudiencePolicy = {
  clientId: string;
  expectedAudience?: string[];
  authorizedPartyClaims: readonly string[];
  verifyAudience?: (claims: AudienceClaims, tokenKind: TokenKind) => boolean;
};

export class OidcAudienceError extends OidcTokenError {
  constructor(tokenKind: TokenKind, claim: string, message: string) {
    super(tokenKind, claim, message);
    this.name = "OidcAudienceError";
  }
}

function toAudienceList(aud: unknown): string[] {
  if (typeof aud === "string") return [aud];
  if (Array.isArray(aud))
    return aud.filter((entry): entry is string => typeof entry === "string");
  return [];
}

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

export function audienceVerifyOption(
  policy: AudiencePolicy,
  tokenKind: TokenKind,
): string | string[] | undefined {
  if (policy.verifyAudience) return undefined;
  return tokenKind === "id" ? policy.clientId : policy.expectedAudience;
}

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

// For claims that did not pass through jose's `audience` option (introspection, grant responses).
export function assertTokenAudience(
  claims: AudienceClaims,
  tokenKind: TokenKind,
  policy: AudiencePolicy,
): void {
  if (!policy.verifyAudience) assertAudienceClaim(claims, tokenKind, policy);
  assertAudienceAfterJwtVerify(claims, tokenKind, policy);
}

export function assertIntrospectedIdTokenAudience(
  claims: AudienceClaims,
  policy: AudiencePolicy,
): void {
  if (policy.verifyAudience) {
    if (!policy.verifyAudience(claims, "id")) {
      throw new OidcAudienceError(
        "id",
        "aud",
        "verifyAudience rejected the id token",
      );
    }
    return;
  }

  const aud = toAudienceList(claims.aud);
  if (aud.length && !aud.includes(policy.clientId)) {
    throw new OidcAudienceError(
      "id",
      "aud",
      `id token introspection response reports "aud" (${aud.join(", ")}), which does not include this client id (${policy.clientId})`,
    );
  }

  const claimNames = policy.authorizedPartyClaims.includes("azp")
    ? policy.authorizedPartyClaims
    : ["azp", ...policy.authorizedPartyClaims];

  const party = findAuthorizedParty(claims, claimNames);
  if (party) {
    if (typeof party.value !== "string" || party.value !== policy.clientId) {
      throw new OidcAudienceError(
        "id",
        party.claim,
        `id token introspection response reports "${party.claim}" (${
          typeof party.value === "string"
            ? party.value
            : JSON.stringify(party.value)
        }), which is not this client id (${policy.clientId})`,
      );
    }
    return;
  }

  if (aud.length > 1) {
    throw new OidcAudienceError(
      "id",
      "azp",
      `id token introspection response reports an "aud" naming multiple parties (${aud.join(", ")}) but nothing identifying the authorized one`,
    );
  }
  if (aud.length) return;

  throw new OidcAudienceError(
    "id",
    "aud",
    `id token introspection response cannot be bound to this client: it reports no "aud" and carries none of the authorized-party claims (${claimNames.join(", ")}). Extend "authorizedPartyClaims" with the claim your provider reports, or supply "verifyAudience".`,
  );
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
