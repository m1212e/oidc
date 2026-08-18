import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createOidcCore, type OidcCore } from "../../lib/core";
import {
  startTestOidcProvider,
  type TestOidcProvider,
} from "./testOidcProvider";

let idp: TestOidcProvider;
let core: OidcCore;

beforeAll(async () => {
  idp = await startTestOidcProvider();
  core = await createOidcCore({
    issuer: idp.issuer,
    clientId: idp.clientId,
    development: true,
  });
});

afterAll(async () => {
  await idp.close();
});

/** Runs a full authorization-code + PKCE login against the real provider and returns the exchanged tokens. */
async function login(accountId: string, scope?: string) {
  const { codeVerifier, authorizationUrl, state } = await core.startSignin({
    redirectUri: idp.redirectUri,
    returnTo: "/dashboard",
    scope,
  });
  if (scope?.includes("offline_access")) {
    authorizationUrl.searchParams.set("prompt", "consent");
  }
  const callbackUrl = await idp.runAuthorizationFlow(
    authorizationUrl,
    accountId,
  );
  return core.resolveSignin(callbackUrl, codeVerifier, state);
}

describe("startSignin", () => {
  test("builds a PKCE authorization request", async () => {
    const result = await core.startSignin({
      redirectUri: idp.redirectUri,
      returnTo: "/dashboard",
    });

    expect(result.codeVerifier.length).toBeGreaterThan(20);
    const parsedState = JSON.parse(result.state);
    expect(parsedState.visitedUrl).toBe("/dashboard");
    expect(typeof parsedState.random).toBe("string");

    const params = result.authorizationUrl.searchParams;
    expect(params.get("redirect_uri")).toBe(idp.redirectUri);
    expect(params.get("scope")).toBe("openid profile email");
    expect(params.get("code_challenge_method")).toBe("S256");
    expect(params.get("code_challenge")).toBeTruthy();
    expect(params.get("state")).toBe(result.state);
  });

  test("accepts a custom scope", async () => {
    const result = await core.startSignin({
      redirectUri: idp.redirectUri,
      returnTo: "/",
      scope: "openid",
    });
    expect(result.authorizationUrl.searchParams.get("scope")).toBe("openid");
  });
});

describe("resolveSignin", () => {
  test("drives a real login against the provider and returns the original returnTo", async () => {
    const result = await login("user-resolve");

    expect(result.returnTo).toBe("/dashboard");
    expect(result.tokens.access_token).toBeTruthy();
    expect(result.tokens.id_token).toBeTruthy();
  });
});

describe("processTokens", () => {
  test("validates a real token set: id token via JWKS, opaque access token via introspection", async () => {
    const introspectionCallsBefore = idp.calls.introspection;
    const { tokens } = await login("user-1");

    const result = await core.processTokens({
      access_token: tokens.access_token,
      id_token: tokens.id_token,
    });

    expect(result.refreshed).toBe(false);
    expect(result.user.sub).toBe("user-1");
    expect(result.user.email).toBe("user-1@example.com");
    // oidc-provider's default access tokens are opaque, not JWTs — this can
    // only have succeeded by falling back to real introspection.
    expect(idp.calls.introspection).toBeGreaterThan(introspectionCallsBefore);
  });

  test("shortcuts straight to refresh on an expired id token, skipping introspection/UserInfo", async () => {
    const { tokens } = await login(
      "user-2",
      "openid profile email offline_access",
    );
    expect(tokens.refresh_token).toBeTruthy();

    const expiredIdToken = await idp.sign({ sub: "user-2" }, { expired: true });

    const introspectionCallsBefore = idp.calls.introspection;
    const userinfoCallsBefore = idp.calls.userinfo;

    const result = await core.processTokens({
      id_token: expiredIdToken,
      refresh_token: tokens.refresh_token as string,
    });

    expect(result.refreshed).toBe(true);
    expect(result.refreshedTokens?.access_token).toBeTruthy();
    expect(result.user.sub).toBe("user-2");
    // The shortcut skips introspection/UserInfo *for the stale expired
    // token* — it does not exempt the fresh token set from validation.
    // oidc-provider's access tokens are opaque, so the new access token
    // still needs exactly one legitimate introspection call; if the
    // shortcut had NOT engaged, the stale token would have cost at least
    // one more (the id token has no opaque fallback), so this stays a
    // meaningful lower bound.
    expect(idp.calls.introspection).toBe(introspectionCallsBefore + 1);
    expect(idp.calls.userinfo).toBe(userinfoCallsBefore);
  });

  test("falls back to refresh as a last resort when the id token's signature can't be verified at all", async () => {
    const { tokens } = await login(
      "user-3",
      "openid profile email offline_access",
    );

    // Signed with a key the provider's JWKS doesn't have — not an expiry
    // failure, so this must exhaust the full fallback chain before refreshing.
    const badToken = await idp.sign({ sub: "user-3" }, { badKid: true });

    const result = await core.processTokens({
      id_token: badToken,
      refresh_token: tokens.refresh_token as string,
    });

    expect(result.refreshed).toBe(true);
    expect(result.user.sub).toBe("user-3");
  });

  test("throws when the token can't be validated and there is nothing to refresh", async () => {
    const badToken = await idp.sign({ sub: "user-4" }, { badKid: true });
    await expect(core.processTokens({ id_token: badToken })).rejects.toThrow();
  });

  test("throws when access and id token subjects disagree", async () => {
    const { tokens: tokensA } = await login("user-a");
    const { tokens: tokensB } = await login("user-b");

    await expect(
      core.processTokens({
        access_token: tokensA.access_token,
        id_token: tokensB.id_token,
      }),
    ).rejects.toThrow("subject in access token and id token do not match");
  });
});

describe("refresh", () => {
  test("exchanges a refresh token for a new token set", async () => {
    const { tokens } = await login(
      "user-refresh",
      "openid profile email offline_access",
    );
    const refreshed = await core.refresh(tokens.refresh_token as string);
    expect(refreshed.access_token).toBeTruthy();
  });
});

describe("getLogoutUrl", () => {
  test("builds an RP-initiated logout URL", async () => {
    const url = await core.getLogoutUrl(idp.postLogoutRedirectUri);
    expect(url.origin).toBe(idp.issuer);
    expect(url.searchParams.get("post_logout_redirect_uri")).toBe(
      idp.postLogoutRedirectUri,
    );
  });
});

describe("fetchUserInfoFromIssuer", () => {
  test("fetches claims from the real UserInfo endpoint", async () => {
    const { tokens } = await login("user-userinfo");
    const info = await core.fetchUserInfoFromIssuer(
      tokens.access_token as string,
      "user-userinfo",
    );
    expect(info.sub).toBe("user-userinfo");
  });
});
