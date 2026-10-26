/**
 * Multi-tenant issuers: Entra ID's `/common` and `/organizations`
 * endpoints publish one metadata document for every tenant, naming the
 * issuer `https://login.microsoftonline.com/{tenantid}/v2.0`. No token
 * carries that literal value. Each names its own tenant in `iss`, and the
 * same tenant id in `tid`. Configure via
 * {@link OidcCoreOptions.allowedTenants} on `createOidcCore`.
 */

import { decodeJwt } from "jose";
import { OidcTokenError, type TokenKind } from "./errors";

/** The placeholder a multi-tenant issuer carries in place of a tenant id. */
const TENANT_PLACEHOLDER = "{tenantid}";

/** Thrown when a token comes from a tenant this client doesn't accept. */
export class OidcTenantError extends OidcTokenError {
  /** The tenant the token came from, or `undefined` if it named none. */
  readonly tenant: string | undefined;

  constructor(
    tokenKind: TokenKind,
    tenant: string | undefined,
    message: string,
  ) {
    super(tokenKind, "tid", message);
    this.name = "OidcTenantError";
    this.tenant = tenant;
  }
}

/** `undefined` when the issuer is an ordinary single-tenant one. */
export type TenantPolicy =
  | {
      /** The discovered issuer, still carrying {@link TENANT_PLACEHOLDER}. */
      issuerTemplate: string;
      allowedTenants: readonly string[] | "any";
    }
  | undefined;

export function buildTenantPolicy(
  issuer: string,
  allowedTenants: readonly string[] | "any" | undefined,
  configuredIssuer: string,
): TenantPolicy {
  if (!issuer.includes(TENANT_PLACEHOLDER)) {
    if (allowedTenants !== undefined) {
      throw new TypeError(
        `"allowedTenants" is set, but the issuer "${issuer}" is not a multi-tenant one: it names a single tenant already, so there is nothing to choose between. Drop "allowedTenants", or point "issuer" at a multi-tenant endpoint such as "https://login.microsoftonline.com/common/v2.0".`,
      );
    }
    return undefined;
  }

  // openid-client only resolves the placeholder for id tokens when it
  // appended the .well-known path itself. Fetched directly, every login
  // would fail its issuer check.
  if (configuredIssuer.includes("/.well-known/")) {
    throw new TypeError(
      `the issuer "${configuredIssuer}" is the .well-known URL of a multi-tenant endpoint. Configure the issuer itself instead (e.g. "https://login.microsoftonline.com/common/v2.0"), otherwise no login can complete: the id token check would compare against the literal "${issuer}".`,
    );
  }

  if (allowedTenants === undefined) {
    throw new TypeError(
      `the issuer "${configuredIssuer}" is multi-tenant: its metadata names "${issuer}", so a token from any tenant would carry a valid signature. Set "allowedTenants" to the tenant ids you accept, or to "any" if you really mean every tenant, including personal Microsoft accounts.`,
    );
  }

  if (allowedTenants !== "any") {
    if (
      !Array.isArray(allowedTenants) ||
      allowedTenants.length === 0 ||
      allowedTenants.some(
        (tenant) => typeof tenant !== "string" || tenant.length === 0,
      )
    ) {
      throw new TypeError(
        'invalid allowedTenants: expected "any", or a non-empty list of non-empty tenant id strings',
      );
    }
  }

  return { issuerTemplate: issuer, allowedTenants };
}

function tenantOf(claims: unknown): string | undefined {
  const tid = (claims as { tid?: unknown } | undefined)?.tid;
  return typeof tid === "string" && tid.length > 0 ? tid : undefined;
}

/**
 * The issuer a token has to name, read from its unverified `tid`. Only
 * used to tell jose which `iss` to expect: the signature check still
 * applies, and {@link assertTenantAllowed} runs on the verified claims.
 * A token without a usable `tid` gets the template back, which no real
 * token matches, so it fails verification as an ordinary bad token.
 */
export function expectedIssuerFor(
  issuer: string,
  policy: TenantPolicy,
  token: string,
): string {
  if (!policy) return issuer;
  let tid: string | undefined;
  try {
    tid = tenantOf(decodeJwt(token));
  } catch {
    return policy.issuerTemplate;
  }
  return tid
    ? policy.issuerTemplate.replace(TENANT_PLACEHOLDER, tid)
    : policy.issuerTemplate;
}

/**
 * Checks a verified token's (or introspection response's) `tid` against
 * {@link TenantPolicy.allowedTenants}. A no-op for single-tenant issuers.
 */
export function assertTenantAllowed(
  claims: unknown,
  tokenKind: TokenKind,
  policy: TenantPolicy,
): void {
  if (!policy) return;
  const tid = tenantOf(claims);
  if (!tid) {
    throw new OidcTenantError(
      tokenKind,
      undefined,
      `${tokenKind} token from a multi-tenant issuer carries no "tid", so it cannot be checked against "allowedTenants"`,
    );
  }
  if (policy.allowedTenants === "any") return;
  if (!policy.allowedTenants.includes(tid)) {
    throw new OidcTenantError(
      tokenKind,
      tid,
      `${tokenKind} token comes from tenant ${tid}, which is not one of the allowed tenants (${policy.allowedTenants.join(", ")})`,
    );
  }
}

/**
 * The issuer to report on a validated user. For a multi-tenant issuer,
 * the tenant-specific `iss` the verified claims carry rather than the
 * placeholder template.
 */
export function resolvedIssuer(
  issuer: string,
  policy: TenantPolicy,
  ...claims: unknown[]
): string {
  if (!policy) return issuer;
  for (const set of claims) {
    const tid = tenantOf(set);
    if (tid) return policy.issuerTemplate.replace(TENANT_PLACEHOLDER, tid);
  }
  return issuer;
}
