import type { JWTPayload } from "jose";
import type { IntrospectionResponse, UserInfoResponse } from "openid-client";
import { Decode, type Static, type TSchema, Type } from "typebox";
import { Compile } from "typebox/compile";
import { Value } from "typebox/value";
import type { Actor } from "./delegation";
import { OidcClaimsError, OidcStateError } from "./errors";

const nullable = <T extends TSchema>(t: T) =>
  Type.Optional(Type.Union([Type.Null(), t]));

// Lowercases emails on the way in. No Encode side needed since this library
// never writes emails back out.
const LowercaseEmail = Decode(Type.String(), (s) => s.toLowerCase());

// Some providers send `*_verified` as "true"/"1" instead of a boolean.
// Anything that isn't clearly true decodes to false.
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
   * `sub` is only unique within one issuer, so key accounts on `iss` and
   * `sub` together, not `sub` alone, if you support more than one IdP.
   */
  iss: Type.Optional(Type.String({ minLength: 1 })),
  sub: Type.String({ minLength: 1 }),
  email: nullable(LowercaseEmail),
  /**
   * Whether the issuer vouches for {@link OIDCUser.email}. Treat a missing
   * value the same as `false`. Only `true` means verified.
   */
  email_verified: nullable(VerifiedFlag),
  name: nullable(Type.String()),
  given_name: nullable(Type.String()),
  family_name: nullable(Type.String()),
  middle_name: nullable(Type.String()),
  nickname: nullable(Type.String()),
  preferred_username: nullable(Type.String()),
  profile: nullable(Type.String()),
  picture: nullable(Type.String()),
  website: nullable(Type.String()),
  gender: nullable(Type.String()),
  birthdate: nullable(Type.String()),
  zoneinfo: nullable(Type.String()),
  locale: nullable(Type.String()),
  phone_number: nullable(Type.String()),
  phone_number_verified: nullable(VerifiedFlag),
  address: nullable(
    Type.Object({
      formatted: Type.Optional(Type.String()),
      street_address: Type.Optional(Type.String()),
      locality: Type.Optional(Type.String()),
      region: Type.Optional(Type.String()),
      postal_code: Type.Optional(Type.String()),
      country: Type.Optional(Type.String()),
    }),
  ),
  updated_at: nullable(Type.Number()),
});
export type OIDCUser = Static<typeof OIDCUserSchema>;
const CompiledOIDCUser = Compile(OIDCUserSchema);
const USER_CLAIM_SCHEMAS = OIDCUserSchema.properties as Record<string, TSchema>;
const OPTIONAL_USER_CLAIMS = Object.keys(USER_CLAIM_SCHEMAS).filter(
  (claim) => claim !== "sub",
);

/**
 * Reads claims into an {@link OIDCUser}, dropping anything outside that
 * shape (roles, internal ids, and other extra claims your provider sends).
 * Throws {@link OidcClaimsError} if `sub` is missing or not a string. Any
 * other malformed claim is just dropped.
 */
export function parseOIDCUser(value: unknown): OIDCUser {
  const claims: Record<string, unknown> =
    typeof value === "object" && value !== null
      ? (value as Record<string, unknown>)
      : {};

  // Checked against each claim's schema before decoding, so a bad value
  // (e.g. `sub: null`) gets dropped instead of silently coerced.
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
  /** The OIDC `nonce` sent with the authorization request. */
  nonce: Type.Optional(Type.String()),
});
export type OIDCFlowState = Static<typeof OIDCFlowStateSchema>;
const CompiledOIDCFlowState = Compile(OIDCFlowStateSchema);

/**
 * Reads back the OAuth `state` this library minted. Throws
 * {@link OidcStateError} if the value isn't valid JSON or doesn't match
 * what {@link OidcCore.startSignin} produced.
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
  try {
    // Clean first to strip stray extra properties. Decode alone won't.
    return CompiledOIDCFlowState.Decode(CompiledOIDCFlowState.Clean(parsed));
  } catch (err) {
    const [first] = [...CompiledOIDCFlowState.Errors(parsed)];
    throw new OidcStateError(
      `the stored OAuth state is not the shape startSignin produces: ${
        first
          ? `${first.instancePath || "/"} ${first.message}`
          : "unknown state shape"
      }`,
      { cause: err },
    );
  }
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
  /**
   * The RFC 8693 delegation chain, current actor first: who is acting on
   * the subject's behalf. Empty unless the token is delegated, which
   * {@link OidcCoreOptions.delegation} has to allow.
   */
  actors: Actor[];
};

/** Claim/verified-flag pairs, as `[value, flag]`. */
const VOUCHED_CLAIMS = [
  ["email", "email_verified"],
  ["phone_number", "phone_number_verified"],
] as const;

/**
 * Merges access and id token claims into what {@link parseOIDCUser} reads,
 * with the id token winning where both set a value. Pass `onConflict` to be
 * notified when both tokens disagree on the same claim.
 *
 * Merges claim by claim rather than spreading wholesale, so a verified flag
 * never ends up attached to a value from the other token.
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

    // Only read the flag from whichever token's value actually survived.
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
