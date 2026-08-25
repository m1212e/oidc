/**
 * Token-type binding: is this JWT — or this introspection response — the kind
 * of token it was presented as?
 *
 * Nothing in a JWT's signature says what it was minted *for*. An ID token and
 * a JWT access token come off the same key with the same `iss`/`sub`/`exp`,
 * so left unchecked, an ID token (routinely handed to front ends, logged,
 * passed to third parties) is a usable bearer credential — the exact
 * substitution OAuth guidance warns against. A refresh token is worse: it
 * typically outlives an access token by weeks.
 *
 * Three families of signal are checked, because no single one is universal:
 * ID-token-only claims (`nonce`, `at_hash`, ...), claims that name the kind
 * outright (`token_use`, the `typ` claim, `token_type`, `events`), and the
 * `typ` JWS header (RFC 9068, though Keycloak/Auth0/Entra send a bare `"JWT"`
 * on both kinds by default — see {@link TokenTypePolicy.accessTokenTyp}).
 *
 * Keycloak has two different `typ`s, easy to conflate: the JWS **header** is
 * `JWT` unless the RFC 9068 option is enabled, while the value naming the
 * kind (`Bearer`/`ID`/`Refresh`) is a **claim**. The claim is always checked;
 * `accessTokenTyp` pins the header and must never be `"Bearer"` for Keycloak.
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
 * What a value naming a token's kind means, whether it arrives as a `typ`
 * claim (Keycloak), a `token_type` (RFC 7662/6749), or a `token_use`
 * (Cognito). Compared after lowercasing; anything not listed is *unknown*
 * rather than wrong, so a provider's own vocabulary here isn't rejected.
 *
 * Keyed by the *bare* value (RFC 7515 §4.1.9 lets the `application/` prefix
 * be omitted) so each kind isn't spelled twice.
 *
 * A `Map`, not an object: the key comes straight out of a token and is
 * therefore attacker-chosen, and an object lookup would answer
 * `"constructor"`/`"__proto__"` from `Object.prototype`.
 */
const NAMED_TOKEN_KINDS = new Map<string, TokenKind | "other">([
  ["access", "access"],
  ["access_token", "access"],
  ["bearer", "access"],
  ["dpop", "access"],
  ["mac", "access"],
  ["n_a", "access"],
  ["at+jwt", "access"],
  ["id", "id"],
  ["id_token", "id"],
  ["id+jwt", "id"],
  ["logout", "other"],
  ["logout+jwt", "other"],
  ["offline", "other"],
  ["refresh", "other"],
  ["refresh_token", "other"],
  ["refresh+jwt", "other"],
  ["secevent+jwt", "other"],
  ["serialized-id", "other"],
]);

/**
 * The kind a value names, or `undefined` if it names none this library knows.
 * Strips a single leading `application/` (RFC 7515 §4.1.9 media-type
 * equivalence) before looking it up.
 */
function namedKind(value: unknown): TokenKind | "other" | undefined {
  if (typeof value !== "string" || value.length === 0) return undefined;
  const bare = value
    .trim()
    .toLowerCase()
    .replace(/^application\//, "");
  return NAMED_TOKEN_KINDS.get(bare);
}

/**
 * jose's own `typ` normalization, so `"at+jwt"` and `"application/at+jwt"`
 * compare equal however a provider or caller spells it.
 */
function normalizeTyp(typ: unknown): string | undefined {
  if (typeof typ !== "string" || typ.length === 0) return undefined;
  const lower = typ.toLowerCase();
  return lower.includes("/") ? lower : `application/${lower}`;
}

/**
 * Thrown when a token is not the kind it was presented as — an ID or refresh
 * token in the access-token slot, most importantly. A permanent rejection:
 * no other strategy and no refresh can turn one kind of token into another.
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
  /**
   * Whether an introspection response must affirmatively name the kind of
   * token it was presented as. See
   * {@link OidcCoreOptions.requireIntrospectedTokenType}.
   */
  requireIntrospectedTokenType: boolean;
};

export function buildTokenTypePolicy(opts: {
  idTokenOnlyClaims?: readonly string[];
  accessTokenTyp?: string;
  requireIntrospectedTokenType?: boolean;
}): TokenTypePolicy {
  return {
    idTokenOnlyClaims: opts.idTokenOnlyClaims ?? DEFAULT_ID_TOKEN_ONLY_CLAIMS,
    accessTokenTyp: normalizeTyp(opts.accessTokenTyp),
    requireIntrospectedTokenType: opts.requireIntrospectedTokenType ?? true,
  };
}

/**
 * The claim-level half of the policy — everything decidable without the JWS
 * header, and therefore what an RFC 7662 introspection response can also be
 * held to.
 */
export function assertTokenTypeFromClaims(
  claims: AudienceClaims,
  tokenKind: TokenKind,
  policy: TokenTypePolicy,
): void {
  if (tokenKind === "access") {
    for (const claim of policy.idTokenOnlyClaims) {
      if (claims[claim] === undefined) continue;
      throw new OidcTokenTypeError(
        "access",
        claim,
        `access token carries "${claim}", a claim defined for ID tokens only — an ID token must never be accepted as an access token`,
      );
    }
  }

  // Only consulted when the value names a kind this library recognizes — a
  // provider putting something else there (a plain "JWT") says nothing.
  for (const claim of ["token_use", "typ", "token_type"] as const) {
    const kind = namedKind(claims[claim]);
    if (kind === undefined || kind === tokenKind) continue;
    throw new OidcTokenTypeError(
      tokenKind,
      claim,
      `${tokenKind} token has "${claim}" (${String(claims[claim])}), naming ${
        kind === "other"
          ? "neither an access token nor an ID token"
          : `an ${kind} token`
      } — a token must be the kind it was presented as`,
    );
  }

  // Checked in both slots: a logout token is shaped like an ID token and
  // satisfies the access-token binding too (same iss/aud/azp), so `events` —
  // the claim that says it's neither — isn't the id slot's business alone.
  if (claims.events !== undefined) {
    throw new OidcTokenTypeError(
      tokenKind,
      "events",
      `${tokenKind} token carries "events", making it a back-channel logout token rather than ${
        tokenKind === "id" ? "an ID" : "an access"
      } token`,
    );
  }
}

/**
 * The complete policy for a JWT jose has verified: the claim rules above plus
 * the `typ` header rule.
 *
 * {@link TokenTypePolicy.accessTokenTyp} pins the header exactly where
 * configured. Where it isn't, the header is still read for a value naming a
 * kind outright, in both slots symmetrically — believing a header that names
 * the wrong kind is never a configuration choice, only requiring one is.
 */
export function assertTokenTypeAfterJwtVerify(
  claims: AudienceClaims,
  header: { typ?: string },
  tokenKind: TokenKind,
  policy: TokenTypePolicy,
): void {
  assertTokenTypeFromClaims(claims, tokenKind, policy);
  const typ = normalizeTyp(header.typ);

  if (tokenKind === "access" && policy.accessTokenTyp) {
    if (typ !== policy.accessTokenTyp) {
      throw new OidcTokenTypeError(
        "access",
        "typ",
        `access token "typ" header (${typ ?? "absent"}) is not the required ${policy.accessTokenTyp}`,
      );
    }
    return;
  }

  const named = namedKind(header.typ);
  if (named !== undefined && named !== tokenKind) {
    throw new OidcTokenTypeError(
      tokenKind,
      "typ",
      `${tokenKind} token "typ" header (${typ}) names ${
        named === "other"
          ? "neither an access token nor an ID token"
          : `an ${named} token`
      }${
        typ === ACCESS_TOKEN_TYP ? " (the RFC 9068 access token type)" : ""
      } — a token must be the kind it was presented as`,
    );
  }
}

/**
 * The policy for an introspection response presented as an *access* token.
 *
 * `active: true` only means the token is live at this AS, not that it's an
 * access token — one endpoint answers for every token type, so a refresh
 * token introspects just as successfully and satisfies the same audience
 * checks. An absent `token_type` is in practice the refresh-token case (RFC
 * 7662 §2.2 defines it only for tokens that have one), so requiring the
 * affirmative answer is what closes the substitution.
 */
export function assertIntrospectedAccessToken(
  claims: AudienceClaims,
  policy: TokenTypePolicy,
): void {
  assertTokenTypeFromClaims(claims, "access", policy);

  if (introspectedKind(claims) === "access") return;
  if (!policy.requireIntrospectedTokenType) return;

  throw new OidcTokenTypeError(
    "access",
    "token_type",
    `introspection response does not name an access token: it carries no recognized "token_type", "typ" or "token_use". RFC 7662 reports a "token_type" only for tokens that have one, so a response without it is as consistent with a refresh token as with an access token, and a refresh token must never be accepted as one. Set "requireIntrospectedTokenType: false" only if your provider omits the type on genuine access tokens.`,
  );
}

/**
 * The mirror of {@link assertIntrospectedAccessToken} for an introspection
 * response presented as an *ID* token — otherwise an access or refresh token
 * introspects successfully in the `id_token` slot and authenticates the
 * request just the same.
 *
 * Runs the claim rules for `"id"`, which only checks the kind-naming claims
 * plus `events` — the ID-token-only claims are gated behind the access-token
 * slot, so a response echoing `nonce`/`at_hash` is unaffected.
 */
export function assertIntrospectedIdToken(
  claims: AudienceClaims,
  policy: TokenTypePolicy,
): void {
  assertTokenTypeFromClaims(claims, "id", policy);

  if (introspectedKind(claims) === "id") return;
  if (!policy.requireIntrospectedTokenType) return;

  throw new OidcTokenTypeError(
    "id",
    "token_type",
    `introspection response does not name an ID token: it carries no recognized "token_type", "typ" or "token_use". One introspection endpoint answers for every token type an AS issues, so a response that does not say what it describes is as consistent with an access or refresh token as with an ID token, and neither may be accepted as one. Set "requireIntrospectedTokenType: false" only if your provider omits the type on genuine ID tokens.`,
  );
}

/** The kind an introspection response names, by whichever claim carries it. */
function introspectedKind(
  claims: AudienceClaims,
): TokenKind | "other" | undefined {
  return ["token_type", "typ", "token_use"]
    .map((claim) => namedKind(claims[claim]))
    .find((kind) => kind !== undefined);
}
