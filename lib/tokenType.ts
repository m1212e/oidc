/**
 * Checks that a JWT (or introspection response) is the kind of token it
 * was presented as, so an id token can't be used where an access token is
 * expected, and vice versa. Configure via
 * {@link OidcCoreOptions.idTokenOnlyClaims} and
 * {@link OidcCoreOptions.accessTokenTyp} on `createOidcCore`.
 */

import type { AudienceClaims } from "./audience";
import { OidcTokenError, type TokenKind } from "./errors";

/** Claims that only ever appear on an id token. */
export const DEFAULT_ID_TOKEN_ONLY_CLAIMS: readonly string[] = [
  "nonce",
  "at_hash",
  "c_hash",
  "s_hash",
];

/** The RFC 9068 `typ` for JWT access tokens, normalized. */
const ACCESS_TOKEN_TYP = "application/at+jwt";

/**
 * Maps the values providers use to name a token's kind (via `typ`,
 * `token_type`, or `token_use`) to the kind itself. A `Map` rather than an
 * object, since the key comes from the token and shouldn't touch
 * `Object.prototype`.
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

/** The kind a value names, or `undefined` if it names none this library knows. */
function namedKind(value: unknown): TokenKind | "other" | undefined {
  if (typeof value !== "string" || value.length === 0) return undefined;
  const bare = value
    .trim()
    .toLowerCase()
    .replace(/^application\//, "");
  return NAMED_TOKEN_KINDS.get(bare);
}

/** Normalizes `typ` so `"at+jwt"` and `"application/at+jwt"` compare equal. */
function normalizeTyp(typ: unknown): string | undefined {
  if (typeof typ !== "string" || typ.length === 0) return undefined;
  const lower = typ.toLowerCase();
  return lower.includes("/") ? lower : `application/${lower}`;
}

/** Thrown when a token isn't the kind it was presented as. */
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
  /** See {@link OidcCoreOptions.requireIntrospectedTokenType}. */
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
 * Checks everything decidable from claims alone, without a JWS header. Also
 * used for introspection responses, which have no header at all.
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

  // Only checked when the value names a kind this library recognizes.
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

  // A logout token is shaped like an id token, so check both slots.
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
 * The complete policy for a JWT jose has verified: the claim rules above,
 * plus the `typ` header rule.
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
 * The policy for an introspection response presented as an access token.
 * `active: true` alone doesn't mean it's an access token, since one
 * endpoint answers for every token type.
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
 * response presented as an id token.
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
