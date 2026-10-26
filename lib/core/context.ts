import type { jwtVerify } from "jose";
import type { Configuration } from "openid-client";
import type { AudiencePolicy } from "../audience";
import type { DelegationPolicy } from "../delegation";
import type { Logger } from "../logger";
import type { ReturnToPolicy } from "../returnTo";
import type { TenantPolicy } from "../tenant";
import type { TokenTypePolicy } from "../tokenType";

type Jwks = Parameters<typeof jwtVerify>[1];

export type CoreContext = {
  config: Configuration;
  log: Logger;
  issuer: string;
  jwks: Jwks | undefined;
  audiencePolicy: AudiencePolicy;
  /** `undefined` unless the issuer is multi-tenant. */
  tenantPolicy: TenantPolicy;
  delegationPolicy: DelegationPolicy;
  tokenTypePolicy: TokenTypePolicy;
  returnToPolicy: ReturnToPolicy;
  introspectionMode: "opaque-only" | "auto" | "never";
  clockTolerance: number;
  signingAlgorithms: string[];
};
