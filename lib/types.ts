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

// Several providers (older Keycloak, Salesforce, SAML bridges) send
// `*_verified` as the string "true"/"1" rather than a boolean. Anything that
// doesn't spell out truth decodes to `false` — the safe direction.
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
   * `sub` is unique only *within* an issuer, and several providers mint ones
   * that are trivially guessable across issuers (a numeric id, a username).
   * An app keying accounts on `sub` alone across more than one IdP risks a
   * collision that reads as account takeover. **Key accounts on `iss` *and*
   * `sub`.**
   *
   * {@link OidcCore.processTokens} always sets this to the issuer the claims
   * were actually verified against, not to whatever an `iss` claim said.
   * Optional because {@link parseOIDCUser} also accepts claim sets with no
   * issuer of their own, such as an unsigned UserInfo response.
   */
  iss: Type.Optional(Type.String({ minLength: 1 })),
  sub: Type.String({ minLength: 1 }),
  email: nullable(LowercaseEmail),
  /**
   * Whether the issuer vouches for {@link OIDCUser.email}. Absent means the
   * issuer said nothing — treat that the same as `false`; only `true` means
   * verified. Keying accounts on an unverified email is a standard
   * account-takeover route.
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
 * Reads merged access/id token claims into an {@link OIDCUser}, stripping
 * everything not in that shape — issuers routinely carry extra, sometimes
 * sensitive, claims (roles, internal ids) that shouldn't leak into code that
 * only asked for "the user". Throws {@link OidcClaimsError} if `sub` is
 * missing or not a string; every other claim is simply dropped if malformed.
 */
export function parseOIDCUser(value: unknown): OIDCUser {
  const claims: Record<string, unknown> =
    typeof value === "object" && value !== null
      ? (value as Record<string, unknown>)
      : {};

  // Matched against each claim's own schema *before* anything is decoded,
  // rather than handing the whole object to TypeBox's `Decode` — that
  // pipeline coerces on the way in (`sub: null` would arrive as `"null"`),
  // and a silently coerced identity claim is worse than a dropped one.
  const candidate: Record<string, unknown> = { sub: claims.sub };
  for (const claim of OPTIONAL_USER_CLAIMS) {
    const supplied = claims[claim];
    if (supplied === undefined) continue;
    const schema = USER_CLAIM_SCHEMAS[claim] as TSchema;
    if (Value.Check(schema, supplied)) candidate[claim] = supplied;
  }

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
   * The OIDC `nonce` sent with the authorization request, compared against
   * the ID token's `nonce` claim. Optional so a login already in flight when
   * this field was introduced still completes.
   */
  nonce: Type.Optional(Type.String()),
});
export type OIDCFlowState = Static<typeof OIDCFlowStateSchema>;
const CompiledOIDCFlowState = Compile(OIDCFlowStateSchema);

/**
 * Reads back the OAuth `state` this library minted, from the value handed to
 * {@link OidcCore.resolveSignin}. Throws {@link OidcStateError} — never a bare
 * `SyntaxError` — for a value that isn't valid JSON or doesn't match the
 * shape {@link OidcCore.startSignin} produced, since a truncated cookie is an
 * ordinary thing to meet at a callback endpoint.
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
 * Claim pairs in which one claim is the issuer vouching for the other. Order
 * is `[value, flag]`.
 */
const VOUCHED_CLAIMS = [
  ["email", "email_verified"],
  ["phone_number", "phone_number_verified"],
] as const;

/**
 * Merges the two validated claim sets into what {@link parseOIDCUser} reads,
 * with the ID token winning where both say something.
 *
 * Merges per *claim* rather than spreading wholesale, because a verified flag
 * must never travel with a value from the other token. This matters for a
 * long-lived session: a user who changes their email gets a new,
 * *unverified* address in a fresh ID token, while an access token still on
 * file vouches for the old one — a plain spread would attach the stale
 * `email_verified: true` to the new address.
 *
 * A flag whose value didn't survive the merge is dropped rather than
 * inherited (reads as "issuer said nothing", the safe default). `onConflict`
 * reports when both tokens name a different value for the same claim, which
 * is worth surfacing regardless of how the merge resolves it.
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
