/**
 * Token-type binding: is this JWT — or this introspection response — the kind
 * of token it was presented as?
 *
 * Nothing in a JWT's signature says what the issuer minted it *for*. An ID
 * token and a JWT access token come off the same key, carry the same `iss`,
 * `sub` and `exp`, and — for the providers that put no resource audience on
 * access tokens, i.e. exactly the ones `expectedAudience` is documented as
 * unnecessary for — satisfy the same audience policy too. Left unchecked, an
 * ID token is therefore a usable bearer credential, which is the substitution
 * OAuth guidance is most emphatic about refusing: ID tokens are handed to
 * front ends, logged, and passed to third parties in ways access tokens are
 * not. The same goes for a *refresh* token, which is worse in one respect —
 * it typically outlives an access token by weeks.
 *
 * Three families of signal are checked, because no single one is universal:
 *
 * - **ID-token-only claims.** `nonce`, `at_hash`, `c_hash` and `s_hash` are
 *   defined for ID tokens only (OIDC Core 3.1.3.6, 3.3.2.11). An access token
 *   has no nonce to echo and carries no hash of itself.
 * - **Claims that name the kind outright.** `token_use` (Cognito), the `typ`
 *   *claim* (Keycloak: `Bearer` / `ID` / `Refresh` / `Offline`), `token_type`
 *   in an RFC 7662 response, and an `events` claim, which makes an
 *   ID-token-shaped JWT a back-channel logout token instead (OIDC Back-Channel
 *   Logout 1.0 §2.4).
 * - **The `typ` JWS header.** RFC 9068 §2.1 gives JWT access tokens
 *   `at+jwt`, which is conclusive where a provider sets it — but Keycloak's
 *   header says `JWT` by default and so do Auth0's and Entra ID's, on both
 *   kinds, so it cannot be *required* by default. That is what
 *   {@link TokenTypePolicy.accessTokenTyp} is for. A header that does name a
 *   kind is nonetheless read in both slots, symmetrically: requiring one is a
 *   configuration decision, but believing one that names the *wrong* kind never
 *   was.
 *
 * Note the split between Keycloak's two `typ`s, which is easy to conflate:
 * the JWS **header** is `JWT` unless the RFC 9068 option is enabled, while the
 * value that actually names the kind — `Bearer`, `ID`, `Refresh` — is a
 * **claim** in the payload. The claim is checked automatically here;
 * {@link TokenTypePolicy.accessTokenTyp} pins the header and must never be set
 * to `"Bearer"` for Keycloak, because no Keycloak header ever says that.
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
 * claim (Keycloak), a `token_type` (RFC 7662 §2.2 / RFC 6749 §7.1), or a
 * `token_use` (Cognito). Compared after lowercasing; anything not listed is
 * *unknown* rather than wrong, so a provider spelling its own vocabulary here
 * is not rejected for it.
 *
 * `mac` and `n_a` earn their place by being real `token_type` values that
 * describe an access token without saying `bearer`.
 *
 * Keyed by the *bare* value: RFC 7515 §4.1.9 lets a media type omit its
 * `application/` prefix, so {@link namedKind} strips one before looking a value
 * up rather than every entry being spelled twice — a table that listed only
 * `at+jwt` and `application/id+jwt` would answer differently for two spellings
 * of the same type, which is a bypass rather than a gap.
 *
 * A `Map` rather than an object, because the key is a claim value straight out
 * of a token and therefore attacker-chosen: an object lookup would answer
 * `"constructor"` and `"__proto__"` from `Object.prototype` and report a
 * function or a prototype as this token's kind. Both spellings fail closed as
 * it happens — an unrecognized kind is not the presented one, so the token is
 * rejected either way — but "rejected because `Object.prototype.constructor`
 * is not `"access"`" is not a check, and the next claim read this way might not
 * be so lucky.
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
 *
 * A single leading `application/` is stripped, because RFC 7515 §4.1.9 makes
 * `"at+jwt"` and `"application/at+jwt"` the same `typ` and a provider may send
 * either — so `"application/id+jwt"` in the access-token slot has to be the
 * same rejection as `"id+jwt"`. Only that one prefix, and only once: `foo/at+jwt`
 * and `application/application/at+jwt` are not the media type they resemble.
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
 * token or a refresh token in the access-token slot, most importantly. A
 * permanent rejection: no other strategy and no refresh can turn one kind of
 * token into another.
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
 * header, and therefore the part an RFC 7662 introspection response can also
 * be held to.
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

  // `typ` and `token_type` are only consulted when they name a kind this
  // library recognizes: a provider putting something else there (Keycloak's
  // registration tokens, or a plain `"JWT"`) says nothing either way.
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

  // Checked in both slots. A logout token is shaped like an ID token, so the
  // id slot is the obvious place for one — but it also satisfies the
  // access-token binding unchanged: same issuer, same `aud`, same `azp`, and
  // nothing in `idTokenOnlyClaims` (a logout token must *not* carry a `nonce`,
  // OIDC Back-Channel Logout 1.0 §2.4). `events` is what says it is neither
  // kind, so it is not the id slot's business alone.
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
 * the `typ` rules, which need the protected header.
 *
 * {@link TokenTypePolicy.accessTokenTyp} pins the header exactly where it is
 * configured. Where it is not — the default, because Auth0, Entra ID and stock
 * Keycloak all send a bare `"JWT"` on both kinds and so leave nothing to pin —
 * the header is still read for a value that names a kind *outright*, in both
 * slots and symmetrically: `typ` is the one header field a provider uses to say
 * what it minted, so a value naming another kind is the same substitution
 * {@link assertTokenTypeFromClaims} refuses, merely spelled in the header
 * instead of the payload. Values the vocabulary does not recognize — `"JWT"`
 * above all — say nothing either way and are left alone; that residual case is
 * what `accessTokenTyp` exists to close.
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
 * `active: true` is not "this is an access token" — RFC 7662 has one endpoint
 * for every token type an AS issues, so a **refresh** token introspects just
 * as successfully, and it satisfies the audience policy identically (same
 * `sub`, same `client_id`) while typically outliving the access token by
 * weeks. A response has no JWS header to pin, so the only thing standing
 * between the two is what the response says it describes.
 *
 * `token_type` is defined (RFC 7662 §2.2) as the RFC 6749 §7.1 type, which
 * only an access token has: a compliant AS describing a refresh token has
 * nothing to put there. So an *absent* type is the refresh-token case in
 * practice — `oidc-provider` returns `token_type: "Bearer"` for access tokens
 * and omits it entirely for refresh tokens; Keycloak distinguishes them by the
 * `typ` claim it echoes. Requiring the affirmative answer is therefore the
 * check that closes the substitution, and
 * {@link TokenTypePolicy.requireIntrospectedTokenType} exists only for
 * providers that omit it on access tokens too.
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
 * The policy for an introspection response presented as an *ID* token.
 *
 * The mirror of {@link assertIntrospectedAccessToken}, and needed for the same
 * reason: `active: true` says a token is live, not which kind it is, so without
 * this an access token — or, far worse, a **refresh** token — presented in the
 * `id_token` slot introspects successfully, satisfies the client binding
 * identically (same `sub`, same `client_id`) and authenticates the request.
 *
 * The claim rules are run for `"id"`, which checks only the claims that *name*
 * a kind (`typ: "Refresh"`, `token_use`, `token_type`) plus `events`. The
 * ID-token-only claims are deliberately not consulted — `assertTokenTypeFromClaims`
 * gates those behind the access-token slot — so a response echoing `nonce` or
 * `at_hash` is unaffected, which is what makes this safe to apply here.
 *
 * The affirmative requirement is stricter than the spec can justify on its own:
 * RFC 7662's `token_type` is the RFC 6749 §7.1 type, which an ID token does not
 * have, so a compliant AS has nothing standard to put there. It costs nothing
 * in practice because an ID token *is* a JWT by definition (OIDC Core 2), so
 * this path is only reached when local verification was impossible or failed —
 * and in that situation, a response that will not say what it describes is not
 * something to authenticate a user on. Providers that do answer here name the
 * kind: Keycloak echoes `typ: "ID"`, Cognito `token_use: "id"`.
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
