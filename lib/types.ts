import type { JWTPayload } from "jose";
import type { IntrospectionResponse, UserInfoResponse } from "openid-client";
import { Decode, type Static, type TSchema, Type } from "typebox";
import { Compile } from "typebox/compile";
import { Value } from "typebox/value";
import { OidcClaimsError, OidcStateError } from "./errors";

const nullable = <T extends TSchema>(t: T) =>
  Type.Optional(Type.Union([Type.Null(), t]));

// Decode-only codec: normalizes case on the way in. Emails are never encoded
// back out by this library, so an Encode side isn't needed.
const LowercaseEmail = Decode(Type.String(), (s) => s.toLowerCase());

/**
 * `email_verified` is a boolean claim that several providers send as the
 * *string* `"true"` (older Keycloak, Salesforce, assorted SAML bridges) or as
 * `1`/`0`, so accepting only a boolean would drop the claim exactly where it
 * matters. Any value that does not spell out truth decodes to `false`, which is
 * the safe direction: an unrecognized value must never read as verified.
 */
const VerifiedFlag = Decode(
  Type.Union([Type.Boolean(), Type.String(), Type.Number()]),
  (value): boolean => {
    if (typeof value === "boolean") return value;
    if (typeof value === "number") return value === 1;
    return value.trim().toLowerCase() === "true";
  },
);

const OIDCUserSchema = Type.Object({
  /**
   * The issuer that vouches for {@link OIDCUser.sub}.
   *
   * Kept in the whitelist because `sub` alone is not an identity: OIDC Core 2
   * makes it unique only *within* an issuer, and several providers mint ones
   * that are trivially guessable across issuers — a numeric id, a username, an
   * email. An application that talks to more than one IdP and keys accounts on
   * `sub` alone therefore lets a subject at one issuer collide with a different
   * person at another, which is account takeover with no forgery involved. That
   * is the same reasoning as {@link OIDCUser.email_verified}: the safe check
   * has to be reachable from the shape most callers ever look at, and a
   * whitelist that dropped this claim would leave it only in the raw token
   * claims. **Key accounts on `iss` *and* `sub`.**
   *
   * {@link OidcCore.processTokens} always sets this, to the issuer every claim
   * set it returned was actually verified against — not merely to whatever an
   * `iss` claim said. Optional only because {@link parseOIDCUser} is also
   * usable on claim sets that carry no issuer of their own, a UserInfo response
   * being the ordinary one (OIDC Core 5.3.2 gives it an `iss` only when it is
   * signed).
   */
  iss: Type.Optional(Type.String({ minLength: 1 })),
  /**
   * Non-empty by construction. `sub` is the identity everything else keys off,
   * so an empty one is refused rather than handed on as a subject that every
   * subject-less token set would share.
   */
  sub: Type.String({ minLength: 1 }),
  email: nullable(LowercaseEmail),
  /**
   * Whether the issuer vouches for {@link OIDCUser.email}.
   *
   * Present because `email` without it is a trap: keying application accounts
   * on an unverified address is a standard account-takeover route, and this
   * shape is the only claim set most callers ever look at — a whitelist that
   * dropped this one would make the safe check unreachable from the sanctioned
   * path. Absent when the issuer says nothing, which is *not* the same as
   * `false`; treat only `true` as verified.
   */
  email_verified: nullable(VerifiedFlag),
  preferred_username: nullable(Type.String()),
  family_name: nullable(Type.String()),
  given_name: nullable(Type.String()),
  locale: nullable(Type.String()),
  /** OIDC Core 5.1 spells this `phone_number`; there is no `phone` claim. */
  phone_number: nullable(Type.String()),
  phone_number_verified: nullable(VerifiedFlag),
});
export type OIDCUser = Static<typeof OIDCUserSchema>;
const CompiledOIDCUser = Compile(OIDCUserSchema);
const USER_CLAIM_SCHEMAS = OIDCUserSchema.properties as Record<string, TSchema>;
const OPTIONAL_USER_CLAIMS = Object.keys(USER_CLAIM_SCHEMAS).filter(
  (claim) => claim !== "sub",
);

/**
 * Parses the merged access/id token claims into a known shape, then strips
 * anything not in that shape. Issuers routinely carry extra — sometimes
 * sensitive (roles, internal ids) — claims on tokens; this is the boundary
 * that stops those from silently leaking into application code that only
 * asked for "the user".
 *
 * Each claim is matched against its own schema *before* anything is decoded,
 * rather than handing the whole claim set to TypeBox's `Decode`. That pipeline
 * converts on the way in — `sub: null` would arrive as the string `"null"`,
 * `email: true` as `"true"` — and a silently coerced identity claim is worse
 * than an absent one: `null` and `123` are subjects the rest of this library
 * (which requires a non-empty string, see `subjectOf`) would refuse to bind a
 * refresh to, while the caller would still see a `user.sub` to key on.
 *
 * A claim whose value does not fit is *dropped* rather than fatal; only `sub`
 * is required. A provider putting a number in `phone_number` should not fail
 * the request, but it should also not have it read back as though the issuer
 * had said something well-formed.
 */
export function parseOIDCUser(value: unknown): OIDCUser {
  const claims: Record<string, unknown> =
    typeof value === "object" && value !== null
      ? (value as Record<string, unknown>)
      : {};

  const candidate: Record<string, unknown> = { sub: claims.sub };
  for (const claim of OPTIONAL_USER_CLAIMS) {
    const supplied = claims[claim];
    if (supplied === undefined) continue;
    const schema = USER_CLAIM_SCHEMAS[claim] as TSchema;
    if (Value.Check(schema, supplied)) candidate[claim] = supplied;
  }

  // Reached with claims that already passed signature and policy checks, so a
  // failure here is a provider shape surprise rather than an attack — most
  // often a `sub` that is absent, which RFC 7662 permits in an introspection
  // response. It still has to surface as an OidcError: a caller catching
  // OidcError to answer 401 would otherwise see this escape as a 500.
  if (!CompiledOIDCUser.Check(candidate)) {
    const [first] = [...CompiledOIDCUser.Errors(candidate)];
    throw new OidcClaimsError(
      `could not read the validated claims as a user: ${
        first
          ? `${first.instancePath || "/"} ${first.message}`
          : "unknown claim shape"
      }`,
    );
  }
  return CompiledOIDCUser.Decode(candidate);
}

const OIDCFlowStateSchema = Type.Object({
  visitedUrl: Type.String(),
  random: Type.String(),
  /**
   * The OIDC `nonce` sent with the authorization request, to be compared
   * against the ID token's `nonce` claim.
   *
   * Optional so that a login already in flight when this field was introduced
   * still completes: state without one means no `nonce` was sent, which is
   * also the expectation `resolveSignin` then passes on. It rides in the state
   * rather than in a return value of its own because a nonce is not a secret —
   * it is a public single-use value whose only job is to be echoed back — and
   * the state is already the channel the caller must store and hand back
   * unchanged. The `code_verifier`, which *is* a secret, is kept out of it.
   */
  nonce: Type.Optional(Type.String()),
});
export type OIDCFlowState = Static<typeof OIDCFlowStateSchema>;
const CompiledOIDCFlowState = Compile(OIDCFlowStateSchema);

/**
 * Reads back the OAuth `state` this library minted.
 *
 * The value round-trips through the browser and the IdP, so it is
 * schema-validated rather than merely `JSON.parse`d before any field is
 * trusted — and both the parse and the validation report as
 * {@link OidcStateError}, since a truncated cookie is an ordinary thing to
 * meet at a callback endpoint and callers need to answer it rather than crash
 * on a bare `SyntaxError`.
 *
 * Checked rather than `Parse`d, for the same reason {@link parseOIDCUser}
 * builds its candidate by hand: `Parse` converts, and a `nonce` that arrived as
 * a number would be silently stringified into one that cannot match the ID
 * token's.
 */
export function parseOIDCFlowState(value: string): OIDCFlowState {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch (err) {
    throw new OidcStateError(
      "could not read the stored OAuth state: it is not the value startSignin returned. Hand it back exactly as it was stored, unmodified.",
      { cause: err },
    );
  }
  //TODO use decode instead of json parse
  if (!CompiledOIDCFlowState.Check(parsed)) {
    const [first] = [...CompiledOIDCFlowState.Errors(parsed)];
    throw new OidcStateError(
      `the stored OAuth state is not the shape startSignin produces: ${
        first
          ? `${first.instancePath || "/"} ${first.message}`
          : "unknown state shape"
      }`,
    );
  }
  return Value.Clean(OIDCFlowStateSchema, {
    ...(parsed as OIDCFlowState),
  }) as OIDCFlowState;
}

export type AccessTokenClaims = JWTPayload | IntrospectionResponse | undefined;
export type IdTokenClaims =
  | JWTPayload
  | IntrospectionResponse
  | UserInfoResponse
  | undefined;

export type ValidationResult = {
  user: OIDCUser;
  accessTokenClaims: AccessTokenClaims;
  idTokenClaims: IdTokenClaims;
};

/**
 * Claim pairs in which one claim is the issuer vouching for the other. Order is
 * `[value, flag]`.
 */
const VOUCHED_CLAIMS = [
  ["email", "email_verified"],
  ["phone_number", "phone_number_verified"],
] as const;

/**
 * Merges the two validated claim sets into the one {@link parseOIDCUser} reads,
 * with the ID token winning where both say something.
 *
 * A plain spread is not enough, and the reason is the whole point of this
 * function: the merge is per *claim*, so a verified flag from one token would
 * survive alongside a value from the other. An access token carrying
 * `email_verified: true` and an ID token carrying a different `email` and no
 * flag merge into an address the issuer never vouched for, marked as one it
 * did — and {@link OIDCUser.email_verified} is documented as the check to gate
 * account keying on, so that is the one claim that must not over-claim.
 *
 * This is not hypothetical for a long-lived session: a user who changes their
 * address gets a new ID token naming the new, *unverified* one, while the
 * access token still on file vouches for the old. Nothing else in the chain
 * notices — both tokens are signed by the issuer, name the same `sub`, and pass
 * every audience and type check — because both really were issued to this
 * client for this user. They just describe different moments.
 *
 * So a flag travels only with the value it was issued beside. Where the
 * surviving value's token said nothing, the flag is dropped rather than
 * inherited, which reads as "the issuer said nothing" — the safe direction, and
 * the one {@link OIDCUser.email_verified} already documents callers to treat as
 * unverified. A flag with no value at all is dropped for the same reason: it
 * vouches for nothing.
 *
 * `onConflict` reports a value the two tokens actively disagree on. For the
 * same subject at the same issuer that is an anomaly worth surfacing, whichever
 * way the merge resolves it.
 */
export function mergeTokenClaims(
  accessTokenClaims: Record<string, unknown> | undefined,
  idTokenClaims: Record<string, unknown> | undefined,
  onConflict?: (claim: string) => void,
): Record<string, unknown> {
  const access = accessTokenClaims ?? {};
  const id = idTokenClaims ?? {};
  const merged: Record<string, unknown> = { ...access, ...id };

  for (const [value, flag] of VOUCHED_CLAIMS) {
    if (
      onConflict &&
      access[value] !== undefined &&
      id[value] !== undefined &&
      access[value] !== id[value]
    ) {
      onConflict(value);
    }

    // Whichever claim set supplied the value that survived the spread is the
    // only one whose flag may be read as vouching for it.
    const source =
      id[value] !== undefined
        ? id
        : access[value] !== undefined
          ? access
          : undefined;

    if (source?.[flag] === undefined) delete merged[flag];
    else merged[flag] = source[flag];
  }

  return merged;
}
