import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createOidcCore } from "../../lib/core";
import { OidcInputError } from "../../lib/errors";
import {
  startTestOidcProvider,
  type TestOidcProvider,
} from "./testOidcProvider";

let idp: TestOidcProvider;

beforeAll(async () => {
  idp = await startTestOidcProvider();
});

afterAll(async () => {
  await idp.close();
});

function coreFor(prompt?: string) {
  const warnings: string[] = [];
  const logger = {
    debug: () => {},
    info: () => {},
    warn: (...args: unknown[]) => {
      const message = args.join(" ");
      if (message.includes("no refresh token")) warnings.push(message);
    },
    error: () => {},
  };
  return createOidcCore({
    issuer: idp.issuer,
    clientId: idp.clientId,
    development: true,
    prompt,
    logger,
  }).then((core) => ({ core, warnings }));
}

async function login(
  core: Awaited<ReturnType<typeof coreFor>>["core"],
  scope = "openid email offline_access",
) {
  const { codeVerifier, authorizationUrl, state } = await core.startSignin({
    redirectUri: idp.redirectUri,
    returnTo: "/",
    scope,
  });
  const callbackUrl = await idp.runAuthorizationFlow(
    authorizationUrl,
    "user-prompt",
  );
  return core.resolveSignin({
    callbackUrl,
    codeVerifier,
    expectedState: state,
  });
}

describe("prompt", () => {
  test("is left out unless configured", async () => {
    const { core } = await coreFor();
    const { authorizationUrl } = await core.startSignin({
      redirectUri: idp.redirectUri,
      returnTo: "/",
    });
    expect(authorizationUrl.searchParams.has("prompt")).toBe(false);
  });

  test("is sent with every authorization request when configured", async () => {
    const { core } = await coreFor("consent");
    const { authorizationUrl } = await core.startSignin({
      redirectUri: idp.redirectUri,
      returnTo: "/",
    });
    expect(authorizationUrl.searchParams.get("prompt")).toBe("consent");
  });

  test("startSignin can replace it for one sign-in", async () => {
    const { core } = await coreFor("consent");
    const { authorizationUrl } = await core.startSignin({
      redirectUri: idp.redirectUri,
      returnTo: "/",
      prompt: "login consent",
    });
    expect(authorizationUrl.searchParams.get("prompt")).toBe("login consent");
  });

  test("refuses an empty value, or none combined with others", async () => {
    await expect(coreFor("  ")).rejects.toThrow(OidcInputError);
    await expect(coreFor("none consent")).rejects.toThrow(OidcInputError);
  });

  test("without consent, a strict provider issues no refresh token, and that is warned about", async () => {
    const { core, warnings } = await coreFor();
    const { tokens } = await login(core);
    expect(tokens.refresh_token).toBeUndefined();
    expect(warnings).toHaveLength(1);
  });

  test("with consent, the provider issues a refresh token", async () => {
    const { core, warnings } = await coreFor("consent");
    const { tokens } = await login(core);
    expect(tokens.refresh_token).toBeString();
    expect(warnings).toEqual([]);
  });

  test("a sign-in without offline_access is not warned about", async () => {
    const { core, warnings } = await coreFor();
    const { tokens } = await login(core, "openid email");
    expect(tokens.refresh_token).toBeUndefined();
    expect(warnings).toEqual([]);
  });
});
