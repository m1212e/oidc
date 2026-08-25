import type { jwtVerify } from "jose";
import type { Configuration } from "openid-client";
import type { AudiencePolicy } from "../audience";
import type { Logger } from "../logger";
import type { ReturnToPolicy } from "../returnTo";
import type { TokenTypePolicy } from "../tokenType";

/** Whatever `jwtVerify`'s key-resolution parameter accepts, usually a JWKS. */
type Jwks = Parameters<typeof jwtVerify>[1];

/** Everything discovery settles once, shared across every operation `createOidcCore` builds. */
export type CoreContext = {
  config: Configuration;
  log: Logger;
  issuer: string;
  /** `undefined` when the issuer advertises no `jwks_uri`. */
  jwks: Jwks | undefined;
  audiencePolicy: AudiencePolicy;
  tokenTypePolicy: TokenTypePolicy;
  returnToPolicy: ReturnToPolicy;
  introspectionMode: "opaque-only" | "auto" | "never";
  clockTolerance: number;
  signingAlgorithms: string[];
};
