import type { JWTVerifyOptions } from "jose";
import type {
  TokenEndpointResponse,
  TokenEndpointResponseHelpers,
} from "openid-client";
import {
  type AudienceClaims,
  assertTokenAudience,
  audienceVerifyOption,
} from "../audience";
import type { TokenKind } from "../errors";
import type { CoreContext } from "./context";

export function jwtVerifyOptions(
  ctx: CoreContext,
  tokenKind: TokenKind,
): JWTVerifyOptions {
  return {
    issuer: ctx.issuer,
    audience: audienceVerifyOption(ctx.audiencePolicy, tokenKind),
    clockTolerance: ctx.clockTolerance,
    algorithms: ctx.signingAlgorithms,
    requiredClaims:
      tokenKind === "id"
        ? ["iss", "sub", "aud", "exp", "iat"]
        : ["iss", "sub", "exp"],
  };
}

export function assertGrantedIdToken(
  ctx: CoreContext,
  tokens: TokenEndpointResponse & TokenEndpointResponseHelpers,
): void {
  const claims = tokens.claims();
  if (claims) {
    assertTokenAudience(claims as AudienceClaims, "id", ctx.audiencePolicy);
  }
}
