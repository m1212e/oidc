import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createOidcCore, type OidcCore } from "../../lib/core";
import {
  OidcGrantError,
  OidcInputError,
  OidcTokenValidationError,
} from "../../lib/errors";
import { OidcTokenTypeError } from "../../lib/tokenType";
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
  return core.resolveSignin({
    callbackUrl,
    codeVerifier,
    expectedState: state,
  });
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

  test("sends a nonce, and carries it in the state for the callback to check", async () => {
    const result = await core.startSignin({
      redirectUri: idp.redirectUri,
      returnTo: "/",
    });

    const nonce = result.authorizationUrl.searchParams.get("nonce");
    expect(nonce).toBeTruthy();
    // Stored in the state, so the caller has nothing extra to persist.
    expect(JSON.parse(result.state).nonce).toBe(nonce);
    // A value of its own, not a second use of the state's randomness.
    expect(JSON.parse(result.state).random).not.toBe(nonce);
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

describe("nonce", () => {
  test("the issued ID token echoes the nonce that was sent", async () => {
    const { codeVerifier, authorizationUrl, state } = await core.startSignin({
      redirectUri: idp.redirectUri,
      returnTo: "/",
    });
    const callbackUrl = await idp.runAuthorizationFlow(
      authorizationUrl,
      "user-nonce",
    );
    const { tokens } = await core.resolveSignin({
      callbackUrl,
      codeVerifier,
      expectedState: state,
    });
    expect(tokens.claims()?.nonce).toBe(JSON.parse(state).nonce);
  });

  test("rejects an ID token whose nonce is not the one we asked for", async () => {
    const { codeVerifier, authorizationUrl, state } = await core.startSignin({
      redirectUri: idp.redirectUri,
      returnTo: "/",
    });
    // The authorization request goes out with someone else's nonce while our
    // stored state still holds ours, so the ID token comes back bound to a
    // request that was not this one.
    authorizationUrl.searchParams.set("nonce", "not-the-nonce-we-stored");
    const callbackUrl = await idp.runAuthorizationFlow(
      authorizationUrl,
      "user-nonce-mismatch",
    );

    // The exchange failure surfaces as an OidcGrantError so that one
    // `instanceof OidcError` covers it. `openid-client` reports the failed
    // comparison by code, which rides along as the cause.
    const err = (await core
      .resolveSignin({ callbackUrl, codeVerifier, expectedState: state })
      .catch((e: unknown) => e)) as OidcGrantError;
    expect(err).toBeInstanceOf(OidcGrantError);
    expect(err.grant).toBe("authorization_code");
    expect((err.cause as { code?: string }).code).toBe(
      "OAUTH_JWT_CLAIM_COMPARISON_FAILED",
    );
  });

  test("rejects an ID token carrying no nonce when one was sent", async () => {
    const { codeVerifier, authorizationUrl, state } = await core.startSignin({
      redirectUri: idp.redirectUri,
      returnTo: "/",
    });
    authorizationUrl.searchParams.delete("nonce");
    const callbackUrl = await idp.runAuthorizationFlow(
      authorizationUrl,
      "user-nonce-absent",
    );

    // Sending a nonce makes the claim required, so an ID token without one is
    // rejected as an invalid response rather than quietly accepted.
    const err = (await core
      .resolveSignin({ callbackUrl, codeVerifier, expectedState: state })
      .catch((e: unknown) => e)) as OidcGrantError;
    expect(err).toBeInstanceOf(OidcGrantError);
    expect((err.cause as { code?: string }).code).toBe(
      "OAUTH_INVALID_RESPONSE",
    );
  });

  test("a login started before the nonce existed still completes", async () => {
    // State from the previous release: no `nonce` field, and no nonce sent.
    // The expectation has to follow the state, not the current code.
    const legacyState = JSON.stringify({
      visitedUrl: "/legacy",
      random: "legacy-random",
    });
    const { codeVerifier, authorizationUrl } = await core.startSignin({
      redirectUri: idp.redirectUri,
      returnTo: "/ignored",
    });
    authorizationUrl.searchParams.set("state", legacyState);
    authorizationUrl.searchParams.delete("nonce");

    const callbackUrl = await idp.runAuthorizationFlow(
      authorizationUrl,
      "user-legacy-state",
    );
    const result = await core.resolveSignin({
      callbackUrl,
      codeVerifier,
      expectedState: legacyState,
    });
    expect(result.returnTo).toBe("/legacy");
    expect(result.tokens.claims()?.nonce).toBeUndefined();
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
    // oidc-provider's default access tokens are opaque, not JWTs. This can
    // only have succeeded by falling back to real introspection.
    expect(idp.calls.introspection).toBeGreaterThan(introspectionCallsBefore);
  });

  test("shortcuts straight to refresh on an expired id token, skipping introspection", async () => {
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
    // The shortcut skips introspection only for the stale expired token, not
    // for the fresh token set. oidc-provider's access tokens are opaque, so
    // exactly one legitimate introspection call is expected here.
    expect(idp.calls.introspection).toBe(introspectionCallsBefore + 1);
    expect(idp.calls.userinfo).toBe(userinfoCallsBefore);
  });

  test("falls back to refresh as a last resort when the id token's signature can't be verified at all", async () => {
    const { tokens } = await login(
      "user-3",
      "openid profile email offline_access",
    );

    // Signed with a key the provider's JWKS doesn't have (not an expiry
    // failure), so this must exhaust the full fallback chain before refreshing.
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

describe("processTokens token-type binding", () => {
  test("refuses an ID token presented as an access token, without spending the refresh token", async () => {
    const { tokens } = await login(
      "user-typeconfusion",
      "openid profile email offline_access",
    );

    // A textbook ID token: signed by the issuer, `aud` and `azp` both this
    // client, unexpired. Everything the access-token audience policy asks
    // for. The substitution is only visible in the ID-token-only claims.
    const idTokenAsAccessToken = await idp.sign({
      sub: "user-typeconfusion",
      azp: idp.clientId,
      nonce: "n-0S6_WzA2Mj",
      at_hash: "MTIzNDU2Nzg5MDEyMzQ1Ng",
    });

    const tokenCallsBefore = idp.calls.token;
    const introspectionCallsBefore = idp.calls.introspection;

    const rejection = core
      .processTokens({
        access_token: idTokenAsAccessToken,
        refresh_token: tokens.refresh_token as string,
      })
      .catch((err: unknown) => err);

    const err = (await rejection) as OidcTokenTypeError;
    expect(err).toBeInstanceOf(OidcTokenTypeError);
    expect(err.tokenKind).toBe("access");
    expect(err.claim).toBe("nonce");

    // A permanent rejection short-circuits the chain: no introspection round
    // trip, and no refresh token spent on a token that can never be ours.
    expect(idp.calls.token).toBe(tokenCallsBefore);
    expect(idp.calls.introspection).toBe(introspectionCallsBefore);
  });

  test("refuses an RFC 9068 access token presented as an id token", async () => {
    const accessTokenAsIdToken = await idp.sign(
      { sub: "user-typ", azp: idp.clientId },
      { typ: "at+jwt" },
    );

    const err = (await core
      .processTokens({ id_token: accessTokenAsIdToken })
      .catch((e: unknown) => e)) as OidcTokenTypeError;
    expect(err).toBeInstanceOf(OidcTokenTypeError);
    expect(err.tokenKind).toBe("id");
    expect(err.claim).toBe("typ");
  });

  test("accepts a real token set, so the checks are not simply rejecting everything", async () => {
    const { tokens } = await login("user-typ-ok");
    const result = await core.processTokens({
      access_token: tokens.access_token,
      id_token: tokens.id_token,
    });
    expect(result.user.sub).toBe("user-typ-ok");
  });
});

describe("processTokens rejects partially-validated token sets", () => {
  test("throws when one supplied token validated and the other never could", async () => {
    const { tokens } = await login("user-partial");
    // Signed with a key the provider's JWKS doesn't have. The id token beside
    // it is genuine, so validating only that one would hand back a `user`
    // while silently dropping an access token nobody could verify.
    const forgedAccessToken = await idp.sign(
      { sub: "user-partial", azp: idp.clientId },
      { badKid: true },
    );

    const introspectionCallsBefore = idp.calls.introspection;
    const err = (await core
      .processTokens({
        access_token: forgedAccessToken,
        id_token: tokens.id_token as string,
      })
      .catch((e: unknown) => e)) as OidcTokenValidationError;

    expect(err).toBeInstanceOf(OidcTokenValidationError);
    expect(err.tokenKinds).toEqual(["access"]);
    expect(err.failures.map((failure) => failure.stage)).toEqual([
      "JWT verification",
    ]);
    expect(err.message).toContain("access token JWT verification failed");
    expect(err.cause).toBeDefined();
    // A JWT the issuer's own JWKS rejected is not introspected under the
    // default `"opaque-only"` mode: the AS has nothing to add about a
    // structured token, and asking anyway would let any bearer string an
    // attacker sends cost an outbound request.
    expect(idp.calls.introspection).toBe(introspectionCallsBefore);
  });

  test("still reports every strategy that ran when introspection is 'auto'", async () => {
    const eager = await createOidcCore({
      issuer: idp.issuer,
      clientId: idp.clientId,
      development: true,
      introspection: "auto",
    });
    const forgedAccessToken = await idp.sign(
      { sub: "user-partial-auto", azp: idp.clientId },
      { badKid: true },
    );

    const introspectionCallsBefore = idp.calls.introspection;
    const err = (await eager
      .processTokens({ access_token: forgedAccessToken })
      .catch((e: unknown) => e)) as OidcTokenValidationError;

    expect(err).toBeInstanceOf(OidcTokenValidationError);
    expect(err.failures.map((failure) => failure.stage)).toEqual([
      "JWT verification",
      "introspection",
    ]);
    expect(idp.calls.introspection).toBe(introspectionCallsBefore + 1);
  });

  test("names both tokens when neither validated", async () => {
    const badAccessToken = await idp.sign({ sub: "u" }, { badKid: true });
    const badIdToken = await idp.sign({ sub: "u" }, { badKid: true });

    const err = (await core
      .processTokens({
        access_token: badAccessToken,
        id_token: badIdToken,
      })
      .catch((e: unknown) => e)) as OidcTokenValidationError;

    expect(err).toBeInstanceOf(OidcTokenValidationError);
    expect(err.tokenKinds).toEqual(["access", "id"]);
    expect(err.message).toContain(
      "could not validate the access and id tokens",
    );
  });

  test("spends the refresh token to repair a partially-unvalidatable set", async () => {
    const { tokens } = await login(
      "user-partial-refresh",
      "openid profile email offline_access",
    );
    const forgedAccessToken = await idp.sign(
      { sub: "user-partial-refresh", azp: idp.clientId },
      { badKid: true },
    );

    const result = await core.processTokens({
      access_token: forgedAccessToken,
      id_token: tokens.id_token as string,
      refresh_token: tokens.refresh_token as string,
    });

    expect(result.refreshed).toBe(true);
    expect(result.user.sub).toBe("user-partial-refresh");
    expect(result.accessTokenClaims).toBeDefined();
    expect(result.idTokenClaims).toBeDefined();
  });

  test("rejects a call carrying no tokens at all", async () => {
    await expect(
      // The types forbid this. A JS caller can still do it.
      core.processTokens({} as { id_token: string }),
    ).rejects.toThrow(OidcInputError);
  });

  test("an omitted access token (undefined) is skipped, not an error", async () => {
    const { tokens } = await login("user-access-token-omitted");
    const result = await core.processTokens({
      access_token: undefined,
      id_token: tokens.id_token as string,
    });
    expect(result.accessTokenClaims).toBeUndefined();
    expect(result.idTokenClaims).toBeDefined();
  });

  test("rejects a `null` access token even with a valid id token present", async () => {
    const { tokens } = await login("user-access-token-null");
    await expect(
      core.processTokens({
        access_token: null,
        id_token: tokens.id_token as string,
      }),
    ).rejects.toThrow(OidcInputError);
  });

  test("rejects an empty-string access token even with a valid id token present", async () => {
    const { tokens } = await login("user-access-token-empty");
    await expect(
      core.processTokens({
        access_token: "",
        id_token: tokens.id_token as string,
      }),
    ).rejects.toThrow(OidcInputError);
  });

  test("rejects a `null` id token even with a valid access token present", async () => {
    const { tokens } = await login("user-id-token-null");
    await expect(
      core.processTokens({
        access_token: tokens.access_token as string,
        id_token: null,
      }),
    ).rejects.toThrow(OidcInputError);
  });

  test("rejects a `null` refresh token", async () => {
    const { tokens } = await login("user-refresh-token-null");
    await expect(
      core.processTokens({
        access_token: tokens.access_token as string,
        refresh_token: null,
      }),
    ).rejects.toThrow(OidcInputError);
  });
});

describe("clockTolerance", () => {
  test("applies the configured tolerance to expiry, in jose's duration grammar", async () => {
    const tolerant = await createOidcCore({
      issuer: idp.issuer,
      clientId: idp.clientId,
      clockTolerance: "5 minutes",
      development: true,
    });

    // exp is 60s in the past: outside the 30s default, inside 5 minutes.
    const staleIdToken = await idp.sign(
      { sub: "user-skew", email: "user-skew@example.com" },
      { expired: true },
    );

    const result = await tolerant.processTokens({ id_token: staleIdToken });
    expect(result.user.sub).toBe("user-skew");

    await expect(
      core.processTokens({ id_token: staleIdToken }),
    ).rejects.toThrow(OidcTokenValidationError);
  });

  test("refuses a tolerance openid-client could not accept", async () => {
    // A startup misconfiguration, so a plain TypeError rather than an
    // OidcInputError: it should stop the process, not answer a request.
    await expect(
      createOidcCore({
        issuer: idp.issuer,
        clientId: idp.clientId,
        clockTolerance: "whenever",
        development: true,
      }),
    ).rejects.toThrow(TypeError);
  });
});

describe("refresh", () => {
  test("exchanges a refresh token for a new token set", async () => {
    const { tokens } = await login(
      "user-refresh",
      "openid profile email offline_access",
    );
    const refreshed = await core.refresh({
      refreshToken: tokens.refresh_token as string,
    });
    expect(refreshed.access_token).toBeTruthy();
  });
});

describe("getLogoutUrl", () => {
  test("builds an RP-initiated logout URL", async () => {
    const url = await core.getLogoutUrl({
      postLogoutRedirectUri: idp.postLogoutRedirectUri,
    });
    expect(url.origin).toBe(idp.issuer);
    expect(url.searchParams.get("post_logout_redirect_uri")).toBe(
      idp.postLogoutRedirectUri,
    );
  });
});

describe("fetchUserInfoFromIssuer", () => {
  test("fetches claims from the real UserInfo endpoint", async () => {
    const { tokens } = await login("user-userinfo");
    const info = await core.fetchUserInfoFromIssuer({
      accessToken: tokens.access_token as string,
      expectedSubject: "user-userinfo",
    });
    expect(info.sub).toBe("user-userinfo");
  });
});
