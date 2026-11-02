import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createOidcCore, type OidcCore } from "../../lib/core";
import {
  startTestOidcProvider,
  type TestOidcProvider,
} from "./testOidcProvider";

const RESOURCE = "https://api.example.com";

let idp: TestOidcProvider;

beforeAll(async () => {
  idp = await startTestOidcProvider({ resourceIndicator: RESOURCE });
});

afterAll(async () => {
  await idp.close();
});

function coreFor(resource?: string | string[]) {
  return createOidcCore({
    issuer: idp.issuer,
    clientId: idp.clientId,
    development: true,
    resource,
  });
}

async function login(core: OidcCore) {
  const { codeVerifier, authorizationUrl, state } = await core.startSignin({
    redirectUri: idp.redirectUri,
    returnTo: "/",
    scope: "openid email offline_access api:read",
  });
  authorizationUrl.searchParams.set("prompt", "consent");
  const callbackUrl = await idp.runAuthorizationFlow(
    authorizationUrl,
    "user-resource",
  );
  return core.resolveSignin({
    callbackUrl,
    codeVerifier,
    expectedState: state,
  });
}

const looksLikeJwt = (token: string) => token.split(".").length === 3;

describe("resource", () => {
  test("is sent with the authorization request, once per indicator", async () => {
    const core = await coreFor([RESOURCE, "https://other.example.com"]);
    const { authorizationUrl } = await core.startSignin({
      redirectUri: idp.redirectUri,
      returnTo: "/",
    });
    expect(authorizationUrl.searchParams.getAll("resource")).toEqual([
      RESOURCE,
      "https://other.example.com",
    ]);
  });

  test("is left out when unset", async () => {
    const core = await coreFor();
    const { authorizationUrl } = await core.startSignin({
      redirectUri: idp.redirectUri,
      returnTo: "/",
    });
    expect(authorizationUrl.searchParams.has("resource")).toBe(false);
  });

  test("refuses an indicator that is not an absolute URI, or has a fragment", async () => {
    await expect(coreFor("api")).rejects.toThrow(TypeError);
    await expect(coreFor(`${RESOURCE}#part`)).rejects.toThrow(TypeError);
  });

  test("without it, the provider issues an opaque access token that needs introspection", async () => {
    const core = await coreFor();
    const { tokens } = await login(core);
    expect(looksLikeJwt(tokens.access_token)).toBe(false);

    const before = idp.calls.introspection;
    await core.processTokens({ access_token: tokens.access_token });
    expect(idp.calls.introspection).toBe(before + 1);
  });

  test("with it, the access token is a JWT for the resource, verified offline", async () => {
    const core = await coreFor(RESOURCE);
    const { tokens } = await login(core);
    expect(looksLikeJwt(tokens.access_token)).toBe(true);

    const before = idp.calls.introspection;
    const result = await core.processTokens({
      access_token: tokens.access_token,
      id_token: tokens.id_token,
    });
    expect(idp.calls.introspection).toBe(before);
    expect(result.accessTokenClaims?.aud).toBe(RESOURCE);
  });

  test("a refresh asks for the resource again, so the new access token stays a JWT", async () => {
    const core = await coreFor(RESOURCE);
    const { tokens } = await login(core);
    const refreshed = await core.refresh({
      refreshToken: tokens.refresh_token as string,
    });
    expect(looksLikeJwt(refreshed.access_token)).toBe(true);

    const before = idp.calls.introspection;
    await core.processTokens({ access_token: refreshed.access_token });
    expect(idp.calls.introspection).toBe(before);
  });
});
