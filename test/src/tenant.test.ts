/**
 * Multi-tenant issuers (Entra ID's `/common` and `/organizations`) publish
 * one metadata document for every tenant, with the placeholder issuer
 * `https://login.microsoftonline.com/{tenantid}/v2.0`. Every tenant's
 * tokens carry a valid signature, so the library has to resolve the issuer
 * per token and hold the tenant to an allow-list on every path that
 * accepts one: sign-in, refresh and `processTokens`.
 *
 * openid-client only recognizes Entra by its real origin, so this suite
 * serves a fake Entra behind `fetch` rather than on a local port.
 */

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { createOidcCore, type OidcCoreOptions } from "../../lib/core";
import { OidcTokenValidationError } from "../../lib/errors";
import { OidcTenantError } from "../../lib/tenant";

const ENTRA = "https://login.microsoftonline.com";
const COMMON = `${ENTRA}/common/v2.0`;
const TEMPLATE = `${ENTRA}/{tenantid}/v2.0`;
const CLIENT_ID = "11111111-1111-1111-1111-111111111111";
const REDIRECT_URI = "https://app.example.com/callback";
const TENANT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const TENANT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

const realFetch = globalThis.fetch;
const { privateKey, publicKey } = await generateKeyPair("RS256");
const jwk = { ...(await exportJWK(publicKey)), kid: "entra-key", use: "sig" };

/** What the fake token endpoint answers with next, and how often it was hit. */
let mintTokenResponse: (grant: URLSearchParams) => Promise<object>;
let tokenCalls = 0;

const silent = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    headers: { "content-type": "application/json" },
  });
}

/** `/common`, `/organizations` or a tenant id, as the first path segment. */
function metadataFor(segment: string) {
  const multiTenant = segment === "common" || segment === "organizations";
  return {
    issuer: multiTenant ? TEMPLATE : `${ENTRA}/${segment}/v2.0`,
    authorization_endpoint: `${ENTRA}/${segment}/oauth2/v2.0/authorize`,
    token_endpoint: `${ENTRA}/${segment}/oauth2/v2.0/token`,
    jwks_uri: `${ENTRA}/${segment}/discovery/v2.0/keys`,
    id_token_signing_alg_values_supported: ["RS256"],
    code_challenge_methods_supported: ["S256"],
  };
}

async function fakeEntra(url: URL, init?: RequestInit): Promise<Response> {
  const [segment = "", ...rest] = url.pathname.slice(1).split("/");
  const path = rest.join("/");
  if (path === "v2.0/.well-known/openid-configuration") {
    return json(metadataFor(segment));
  }
  if (path === "discovery/v2.0/keys") return json({ keys: [jwk] });
  if (path === "oauth2/v2.0/token") {
    tokenCalls++;
    return json(
      await mintTokenResponse(new URLSearchParams(String(init?.body))),
    );
  }
  return new Response("not found", { status: 404 });
}

beforeAll(() => {
  globalThis.fetch = (async (
    input: string | URL | Request,
    init?: RequestInit,
  ) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.origin === ENTRA) return fakeEntra(url, init);
    return realFetch(input, init);
  }) as typeof fetch;
});

afterAll(() => {
  globalThis.fetch = realFetch;
});

/** Signs a token the way Entra does: `iss` and `tid` name the same tenant. */
function sign(
  tenant: string | undefined,
  claims: Record<string, unknown> = {},
  issuerTenant = tenant,
) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    ...(tenant ? { tid: tenant } : {}),
    sub: "user-1",
    iat: now,
    ...claims,
  })
    .setProtectedHeader({ alg: "RS256", kid: jwk.kid, typ: "JWT" })
    .setIssuer(`${ENTRA}/${issuerTenant ?? "{tenantid}"}/v2.0`)
    .setExpirationTime(now + 3600)
    .sign(privateKey);
}

const idToken = (tenant?: string, claims?: Record<string, unknown>) =>
  sign(tenant, { aud: CLIENT_ID, ...claims });
const accessToken = (tenant?: string) =>
  sign(tenant, { aud: "api://orders", azp: CLIENT_ID, scp: "read" });

function core(options: Partial<OidcCoreOptions> = {}) {
  return createOidcCore({
    issuer: COMMON,
    clientId: CLIENT_ID,
    logger: silent,
    ...options,
  });
}

describe("createOidcCore with a multi-tenant issuer", () => {
  test("refuses to start without allowedTenants", async () => {
    await expect(core()).rejects.toThrow(/Set "allowedTenants"/);
  });

  test("refuses the .well-known form, which openid-client cannot resolve", async () => {
    await expect(
      core({
        issuer: `${COMMON}/.well-known/openid-configuration`,
        allowedTenants: [TENANT_A],
      }),
    ).rejects.toThrow(/Configure the issuer itself/);
  });

  test("refuses an empty or malformed allow-list", async () => {
    await expect(core({ allowedTenants: [] })).rejects.toThrow(
      /invalid allowedTenants/,
    );
    await expect(core({ allowedTenants: [""] })).rejects.toThrow(
      /invalid allowedTenants/,
    );
  });

  test("refuses allowedTenants on a single-tenant issuer", async () => {
    await expect(
      core({ issuer: `${ENTRA}/${TENANT_A}/v2.0`, allowedTenants: [TENANT_A] }),
    ).rejects.toThrow(/is not a multi-tenant one/);
  });

  test("leaves a single-tenant issuer alone", async () => {
    const oidc = await core({ issuer: `${ENTRA}/${TENANT_A}/v2.0` });
    const result = await oidc.processTokens({
      access_token: await accessToken(TENANT_A),
      id_token: await idToken(TENANT_A),
    });
    expect(result.user.iss).toBe(`${ENTRA}/${TENANT_A}/v2.0`);
  });
});

describe("processTokens with a multi-tenant issuer", () => {
  test("accepts an allowed tenant and reports its own issuer", async () => {
    const oidc = await core({ allowedTenants: [TENANT_A] });
    const result = await oidc.processTokens({
      access_token: await accessToken(TENANT_A),
      id_token: await idToken(TENANT_A),
    });
    expect(result.user.sub).toBe("user-1");
    expect(result.user.iss).toBe(`${ENTRA}/${TENANT_A}/v2.0`);
  });

  test("rejects another tenant permanently, without spending the refresh token", async () => {
    const oidc = await core({ allowedTenants: [TENANT_A] });
    const before = tokenCalls;
    const error = await oidc
      .processTokens({
        access_token: await accessToken(TENANT_B),
        refresh_token: "rt",
      })
      .catch((err) => err);
    expect(error).toBeInstanceOf(OidcTenantError);
    expect(error.tenant).toBe(TENANT_B);
    expect(error.tokenKind).toBe("access");
    expect(tokenCalls).toBe(before);
  });

  test('accepts any tenant with "any"', async () => {
    const oidc = await core({ allowedTenants: "any" });
    const result = await oidc.processTokens({
      id_token: await idToken(TENANT_B),
    });
    expect(result.user.iss).toBe(`${ENTRA}/${TENANT_B}/v2.0`);
  });

  test("rejects a token whose iss names a different tenant than its tid", async () => {
    // Signed by the shared key, so only the iss/tid binding stops a token
    // issued to an unlisted tenant from claiming a listed one.
    const oidc = await core({ allowedTenants: [TENANT_A] });
    await expect(
      oidc.processTokens({
        id_token: await sign(TENANT_A, { aud: CLIENT_ID }, TENANT_B),
      }),
    ).rejects.toBeInstanceOf(OidcTokenValidationError);
  });

  test("rejects a token without tid, which cannot match its issuer", async () => {
    const oidc = await core({ allowedTenants: "any" });
    await expect(
      oidc.processTokens({
        id_token: await sign(undefined, { aud: CLIENT_ID }, TENANT_A),
      }),
    ).rejects.toBeInstanceOf(OidcTokenValidationError);
  });

  test("rejects a token naming the placeholder issuer itself", async () => {
    // It passes the iss check, since without a tid the expected issuer is
    // the template. The tenant check on the verified claims still holds.
    const oidc = await core({ allowedTenants: "any" });
    await expect(
      oidc.processTokens({ id_token: await idToken(undefined) }),
    ).rejects.toBeInstanceOf(OidcTenantError);
  });
});

describe("sign-in and refresh with a multi-tenant issuer", () => {
  async function signIn(tenant: string) {
    const oidc = await core({ allowedTenants: [TENANT_A] });
    const { authorizationUrl, codeVerifier, state } = await oidc.startSignin({
      redirectUri: REDIRECT_URI,
      returnTo: "/dashboard",
    });
    const nonce = authorizationUrl.searchParams.get("nonce");
    mintTokenResponse = async () => ({
      token_type: "Bearer",
      expires_in: 3600,
      access_token: await accessToken(tenant),
      id_token: await idToken(tenant, { nonce }),
    });
    const callbackUrl = new URL(REDIRECT_URI);
    callbackUrl.searchParams.set("code", "code-1");
    callbackUrl.searchParams.set("state", state);
    return oidc.resolveSignin({
      callbackUrl,
      codeVerifier,
      expectedState: state,
    });
  }

  test("signs in a user from an allowed tenant", async () => {
    const { tokens } = await signIn(TENANT_A);
    expect(tokens.claims()?.tid).toBe(TENANT_A);
  });

  test("refuses a login from another tenant", async () => {
    // openid-client accepts every tenant on its own. Without this check a
    // user from any tenant could complete the login.
    const error = await signIn(TENANT_B).catch((err) => err);
    expect(error).toBeInstanceOf(OidcTenantError);
    expect(error.tenant).toBe(TENANT_B);
  });

  test("refuses a refresh that comes back for another tenant", async () => {
    const oidc = await core({ allowedTenants: [TENANT_A] });
    mintTokenResponse = async () => ({
      token_type: "Bearer",
      expires_in: 3600,
      access_token: await accessToken(TENANT_B),
      id_token: await idToken(TENANT_B),
    });
    await expect(oidc.refresh({ refreshToken: "rt" })).rejects.toBeInstanceOf(
      OidcTenantError,
    );
  });
});
