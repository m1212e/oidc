import type { JWTPayload } from "jose";
import type { IntrospectionResponse, UserInfoResponse } from "openid-client";
import { Decode, type Static, type TSchema, Type } from "typebox";
import { Compile } from "typebox/compile";
import { Value } from "typebox/value";
import { OidcClaimsError, OidcStateError } from "./errors";

const nullable = <T extends TSchema>(t: T) =>
  Type.Optional(Type.Union([Type.Null(), t]));

const LowercaseEmail = Decode(Type.String(), (s) => s.toLowerCase());

const VerifiedFlag = Decode(
  Type.Union([Type.Boolean(), Type.String(), Type.Number()]),
  (value): boolean => {
    if (typeof value === "boolean") return value;
    if (typeof value === "number") return value === 1;
    return value.trim().toLowerCase() === "true";
  },
);

const OIDCUserSchema = Type.Object({
  iss: Type.Optional(Type.String({ minLength: 1 })),
  sub: Type.String({ minLength: 1 }),
  email: nullable(LowercaseEmail),
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
  nonce: Type.Optional(Type.String()),
});
export type OIDCFlowState = Static<typeof OIDCFlowStateSchema>;
const CompiledOIDCFlowState = Compile(OIDCFlowStateSchema);

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
};

const VOUCHED_CLAIMS = [
  ["email", "email_verified"],
  ["phone_number", "phone_number_verified"],
] as const;

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
