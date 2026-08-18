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
