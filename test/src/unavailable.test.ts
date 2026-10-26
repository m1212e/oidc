/**
 * A provider outage is not a bad token. When the key set or the
 * introspection endpoint can't be reached, refreshing would spend (and,
 * with rotation, invalidate) the refresh token on a set that can't
 * validate either. So processTokens leaves the session alone and says the
 * provider was unavailable, which a caller can answer with a 503 instead
 * of logging the user out.
 */

import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  test,
} from "bun:test";
import { createOidcCore } from "../../lib/core";
import {
  OidcProviderUnavailableError,
  OidcTokenValidationError,
} from "../../lib/errors";
import {
  startTestOidcProvider,
  type TestOidcProvider,
} from "./testOidcProvider";

let idp: TestOidcProvider;
const realFetch = globalThis.fetch;

beforeAll(async () => {
  idp = await startTestOidcProvider();
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

afterAll(async () => {
  globalThis.fetch = realFetch;
  await idp.close();
});

/** A fresh core, so nothing is cached from an earlier JWKS fetch. */
function core() {
  return createOidcCore({
    issuer: idp.issuer,
    clientId: idp.clientId,
    development: true,
    logLevel: "silent",
  });
}

/** Makes requests to `endpoint` fail the way `outage` says, and nothing else. */
function breakEndpoint(endpoint: string, outage: () => Response) {
  globalThis.fetch = (async (
    input: string | URL | Request,
    init?: RequestInit,
  ) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url === endpoint) return outage();
    return realFetch(input, init);
  }) as typeof fetch;
}

const refused = (): Response => {
  throw new TypeError("fetch failed");
};
const serverError = () => new Response("unavailable", { status: 503 });

/** A real token set with a refresh token, from a full login. */
async function login(accountId: string) {
  const oidc = await core();
  const { codeVerifier, authorizationUrl, state } = await oidc.startSignin({
    redirectUri: idp.redirectUri,
    returnTo: "/",
    scope: "openid offline_access",
  });
  authorizationUrl.searchParams.set("prompt", "consent");
  const callbackUrl = await idp.runAuthorizationFlow(
    authorizationUrl,
    accountId,
  );
  const { tokens } = await oidc.resolveSignin({
    callbackUrl,
    codeVerifier,
    expectedState: state,
  });
  return tokens;
}

describe("processTokens during a provider outage", () => {
  for (const [name, outage] of [
    ["refuses connections", refused],
    ["answers 503", serverError],
  ] as const) {
    test(`does not refresh when the key set ${name}`, async () => {
      const tokens = await login(`jwks-${name}`);
      const oidc = await core();
      breakEndpoint(
        oidc.configuration.serverMetadata().jwks_uri as string,
        outage,
      );
      const tokenCallsBefore = idp.calls.token;

      const error = await oidc
        .processTokens({
          id_token: tokens.id_token as string,
          refresh_token: tokens.refresh_token as string,
        })
        .catch((err) => err);

      expect(error).toBeInstanceOf(OidcProviderUnavailableError);
      // Still a validation error, for callers that only know that one.
      expect(error).toBeInstanceOf(OidcTokenValidationError);
      expect(error.message).toMatch(/could not be reached/);
      expect(error.failures[0].transient).toBe(true);
      expect(error.refreshedTokens).toBeUndefined();
      expect(idp.calls.token).toBe(tokenCallsBefore);
    });
  }

  test("does not refresh when introspection is down", async () => {
    const tokens = await login("introspection-down");
    const oidc = await core();
    breakEndpoint(
      oidc.configuration.serverMetadata().introspection_endpoint as string,
      serverError,
    );
    const tokenCallsBefore = idp.calls.token;

    const error = await oidc
      .processTokens({
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token as string,
      })
      .catch((err) => err);

    expect(error).toBeInstanceOf(OidcProviderUnavailableError);
    expect(error.failures[0].stage).toBe("introspection");
    expect(idp.calls.token).toBe(tokenCallsBefore);
  });

  test("still refreshes a token the provider says is bad", async () => {
    // The counterpart: a bad signature is the token's fault, so a refresh
    // is the right answer and the provider was reachable for it.
    const tokens = await login("bad-token");
    const oidc = await core();
    const badIdToken = await idp.sign({ sub: "bad-token" }, { badKid: true });

    const result = await oidc.processTokens({
      id_token: badIdToken,
      refresh_token: tokens.refresh_token as string,
    });
    expect(result.refreshed).toBe(true);
    expect(result.user.sub).toBe("bad-token");
  });

  test("validates again once the provider is back", async () => {
    const tokens = await login("recovers");
    const oidc = await core();
    breakEndpoint(
      oidc.configuration.serverMetadata().jwks_uri as string,
      refused,
    );
    await expect(
      oidc.processTokens({ id_token: tokens.id_token as string }),
    ).rejects.toBeInstanceOf(OidcProviderUnavailableError);

    globalThis.fetch = realFetch;
    const result = await oidc.processTokens({
      id_token: tokens.id_token as string,
    });
    expect(result.user.sub).toBe("recovers");
  });
});
