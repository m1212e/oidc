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
import { assertTenantAllowed, expectedIssuerFor } from "../tenant";
import type { CoreContext } from "./context";

/** jose verification options: signature, issuer, audience, expiry, and required claims. */
export function jwtVerifyOptions(
  ctx: CoreContext,
  tokenKind: TokenKind,
  token: string,
): JWTVerifyOptions {
  return {
    issuer: expectedIssuerFor(ctx.issuer, ctx.tenantPolicy, token),
    audience: audienceVerifyOption(ctx.audiencePolicy, tokenKind),
    clockTolerance: ctx.clockTolerance,
    algorithms: ctx.signingAlgorithms,
    requiredClaims:
      tokenKind === "id"
        ? ["iss", "sub", "aud", "exp", "iat"]
        : ["iss", "sub", "exp"],
  };
}

/** Runs the audience and tenant policies against a granted id token's claims. */
export function assertGrantedIdToken(
  ctx: CoreContext,
  tokens: TokenEndpointResponse & TokenEndpointResponseHelpers,
): void {
  const claims = tokens.claims();
  if (claims) {
    assertTokenAudience(claims as AudienceClaims, "id", ctx.audiencePolicy);
    assertTenantAllowed(claims, "id", ctx.tenantPolicy);
  }
}
