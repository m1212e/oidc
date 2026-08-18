import type { JWTPayload } from "jose";
import type { IntrospectionResponse, UserInfoResponse } from "openid-client";
import { Decode, type Static, type TSchema, Type } from "typebox";
import { Compile } from "typebox/compile";
import { Value } from "typebox/value";

const nullable = <T extends TSchema>(t: T) =>
  Type.Optional(Type.Union([Type.Null(), t]));

// Decode-only codec: normalizes case on the way in. Emails are never encoded
// back out by this library, so an Encode side isn't needed.
const LowercaseEmail = Decode(Type.String(), (s) => s.toLowerCase());

const OIDCUserSchema = Type.Object({
  sub: Type.String(),
  email: nullable(LowercaseEmail),
  preferred_username: nullable(Type.String()),
  family_name: nullable(Type.String()),
  given_name: nullable(Type.String()),
  locale: nullable(Type.String()),
  phone: nullable(Type.String()),
});
export type OIDCUser = Static<typeof OIDCUserSchema>;
const CompiledOIDCUser = Compile(OIDCUserSchema);

/**
 * Parses the merged access/id token claims into a known shape, then strips
 * anything not in that shape. Issuers routinely carry extra — sometimes
 * sensitive (roles, internal ids) — claims on tokens; this is the boundary
 * that stops those from silently leaking into application code that only
 * asked for "the user".
 */
export function parseOIDCUser(value: unknown): OIDCUser {
  const v = CompiledOIDCUser.Decode(value);
  return Value.Clean(OIDCUserSchema, { ...v }) as typeof v;
}

const OIDCFlowStateSchema = Type.Object({
  visitedUrl: Type.String(),
  random: Type.String(),
});
export type OIDCFlowState = Static<typeof OIDCFlowStateSchema>;
const CompiledOIDCFlowState = Compile(OIDCFlowStateSchema);

/**
 * The OAuth `state` parameter round-trips through the browser and the IdP —
 * an attacker-influenced value on the way back — so it is schema-validated,
 * not just `JSON.parse`d, before any of its fields are trusted.
 */
export function parseOIDCFlowState(value: unknown): OIDCFlowState {
  return CompiledOIDCFlowState.Parse(value);
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
