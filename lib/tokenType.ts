/**
 * Token-type binding: is this JWT the kind of token it was presented as?
 *
 * Nothing in a JWT's signature says what the issuer minted it *for*. An ID
 * token and a JWT access token come off the same key, carry the same `iss`,
 * `sub` and `exp`, and — for the providers that put no resource audience on
 * access tokens, i.e. exactly the ones `expectedAudience` is documented as
 * unnecessary for — satisfy the same audience policy too. Left unchecked, an
 * ID token is therefore a usable bearer credential, which is the substitution
 * OAuth guidance is most emphatic about refusing: ID tokens are handed to
 * front ends, logged, and passed to third parties in ways access tokens are
 * not.
 *
 * RFC 9068 §2.1 answers this with a `typ` header of `at+jwt`, but that is only
 * usable where the provider sets it — Keycloak sends `Bearer`, Auth0 and Entra
 * ID send a plain `JWT` on both kinds — so it cannot be required by default.
 * What can be required by default are the signals that are conclusive wherever
 * they do appear:
 *
 * - `nonce`, `at_hash`, `c_hash` and `s_hash` are defined for ID tokens only
 *   (OIDC Core 3.1.3.6, 3.3.2.11). An access token has no nonce to echo and
 *   carries no hash of itself.
 * - `token_use` names the kind outright (Cognito).
 * - a `typ` of `at+jwt` names a JWT as an access token, so it is not an ID one.
 * - an `events` claim makes it a back-channel logout token (OIDC Back-Channel
 *   Logout 1.0 §2.4), which is otherwise shaped exactly like an ID token.
 *
 * None of those is universal, so {@link TokenTypePolicy.accessTokenTyp} exists
 * for deployments whose provider does distinguish the two by `typ`.
 */

import type { AudienceClaims } from "./audience";
import { OidcTokenError, type TokenKind } from "./errors";

/**
 * Claims whose presence proves a JWT is an ID token, so a token presented as
 * an access token carrying any of them is refused.
 */
export const DEFAULT_ID_TOKEN_ONLY_CLAIMS: readonly string[] = [
  "nonce",
  "at_hash",
  "c_hash",
  "s_hash",
];

/** The `typ` RFC 9068 §2.1 gives JWT access tokens, normalized. */
const ACCESS_TOKEN_TYP = "application/at+jwt";

/**
 * jose's own `typ` normalization: RFC 7515 §4.1.9 lets the `application/`
 * prefix be omitted, so `"at+jwt"` and `"application/at+jwt"` have to compare
 * equal however a provider or a caller spells it.
 */
function normalizeTyp(typ: unknown): string | undefined {
  if (typeof typ !== "string" || typ.length === 0) return undefined;
  const lower = typ.toLowerCase();
  return lower.includes("/") ? lower : `application/${lower}`;
}

/**
 * Thrown when a token is not the kind of token it was presented as — an ID
 * token in the access-token slot, most importantly. A permanent rejection:
 * no other strategy and no refresh can turn an ID token into an access token.
 */
export class OidcTokenTypeError extends OidcTokenError {
  constructor(tokenKind: TokenKind, claim: string, message: string) {
    super(tokenKind, claim, message);
    this.name = "OidcTokenTypeError";
  }
}

export type TokenTypePolicy = {
  idTokenOnlyClaims: readonly string[];
  /** Normalized required `typ` for access tokens, or `undefined` when not configured. */
  accessTokenTyp?: string;
};

export function buildTokenTypePolicy(opts: {
  idTokenOnlyClaims?: readonly string[];
  accessTokenTyp?: string;
}): TokenTypePolicy {
  return {
    idTokenOnlyClaims: opts.idTokenOnlyClaims ?? DEFAULT_ID_TOKEN_ONLY_CLAIMS,
    accessTokenTyp: normalizeTyp(opts.accessTokenTyp),
  };
}

/**
 * The claim-level half of the policy — everything decidable without the JWS
 * header, and therefore also the whole of what an RFC 7662 introspection
 * response can be held to. Such a response has no header, and its
 * `token_type` is the OAuth transport type (`"Bearer"`), not a discriminator
 * against ID tokens.
 */
export function assertTokenTypeFromClaims(
  claims: AudienceClaims,
  tokenKind: TokenKind,
  policy: TokenTypePolicy,
): void {
  const tokenUse = claims.token_use;

  if (tokenKind === "access") {
    for (const claim of policy.idTokenOnlyClaims) {
      if (claims[claim] === undefined) continue;
      throw new OidcTokenTypeError(
        "access",
        claim,
        `access token carries "${claim}", a claim defined for ID tokens only — an ID token must never be accepted as an access token`,
      );
    }
    if (typeof tokenUse === "string" && tokenUse !== "access") {
      throw new OidcTokenTypeError(
        "access",
        "token_use",
        `access token has "token_use" (${tokenUse}), so it is not an access token`,
      );
    }
    return;
  }

  if (typeof tokenUse === "string" && tokenUse !== "id") {
    throw new OidcTokenTypeError(
      "id",
      "token_use",
      `id token has "token_use" (${tokenUse}), so it is not an id token`,
    );
  }
  if (claims.events !== undefined) {
    throw new OidcTokenTypeError(
      "id",
      "events",
      `id token carries "events", making it a back-channel logout token rather than an ID token`,
    );
  }
}

/**
 * The complete policy, for a JWT jose has verified: the claim rules above plus
 * the `typ` rules, which need the protected header.
 */
export function assertTokenTypeAfterJwtVerify(
  claims: AudienceClaims,
  header: { typ?: string },
  tokenKind: TokenKind,
  policy: TokenTypePolicy,
): void {
  assertTokenTypeFromClaims(claims, tokenKind, policy);
  const typ = normalizeTyp(header.typ);

  if (tokenKind === "access") {
    if (policy.accessTokenTyp && typ !== policy.accessTokenTyp) {
      throw new OidcTokenTypeError(
        "access",
        "typ",
        `access token "typ" header (${typ ?? "absent"}) is not the required ${policy.accessTokenTyp}`,
      );
    }
    return;
  }

  if (typ === ACCESS_TOKEN_TYP) {
    throw new OidcTokenTypeError(
      "id",
      "typ",
      `id token "typ" header (${typ}) names an RFC 9068 access token, not an ID token`,
    );
  }
}
