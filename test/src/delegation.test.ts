/**
 * RFC 8693 delegation: a token whose `act` claim names someone acting on
 * the subject's behalf. The subject is still the user, so an app that
 * ignores `act` would treat the actor's request as the user's own. That's
 * why delegated tokens are refused unless the app opts in.
 */

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createOidcCore, type OidcCoreOptions } from "../../lib/core";
import { actorsOf, OidcDelegationError } from "../../lib/delegation";
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

function core(options: Partial<OidcCoreOptions> = {}) {
  return createOidcCore({
    issuer: idp.issuer,
    clientId: idp.clientId,
    development: true,
    logLevel: "silent",
    ...options,
  });
}

/** An RFC 9068 access token for this client, optionally delegated. */
function accessToken(act?: unknown) {
  return idp.sign(
    { sub: "user-1", azp: idp.clientId, ...(act === undefined ? {} : { act }) },
    { typ: "at+jwt" },
  );
}

/** `service-b` acting now, on behalf of `service-a`, which acted for the user. */
const CHAIN = {
  sub: "service-b",
  iss: "https://other-issuer.example",
  act: { sub: "service-a" },
};

describe("actorsOf", () => {
  test("lists the chain current actor first", () => {
    expect(actorsOf({ act: CHAIN }, "access")).toEqual([
      { sub: "service-b", iss: "https://other-issuer.example" },
      { sub: "service-a" },
    ]);
  });

  test("is empty for an ordinary token", () => {
    expect(actorsOf({ sub: "user-1" }, "access")).toEqual([]);
    expect(actorsOf(undefined, "id")).toEqual([]);
  });

  test("refuses malformed actors", () => {
    for (const act of [
      "service-b",
      ["service-b"],
      {},
      { sub: "" },
      { sub: 1 },
    ]) {
      expect(() => actorsOf({ act }, "access")).toThrow(OidcDelegationError);
    }
    expect(() =>
      actorsOf({ act: { sub: "service-b", iss: 1 } }, "access"),
    ).toThrow(/malformed "act"/);
  });

  test("refuses a chain too long to be real", () => {
    let act: Record<string, unknown> = { sub: "actor-0" };
    for (let i = 1; i <= 16; i++) act = { sub: `actor-${i}`, act };
    expect(() => actorsOf({ act }, "access")).toThrow(/longer than 16/);
  });
});

describe("processTokens with a delegated token", () => {
  test("refuses it by default, without spending the refresh token", async () => {
    const oidc = await core();
    const tokenCallsBefore = idp.calls.token;

    const error = await oidc
      .processTokens({
        access_token: await accessToken(CHAIN),
        refresh_token: "rt",
      })
      .catch((err) => err);

    expect(error).toBeInstanceOf(OidcDelegationError);
    expect(error.claim).toBe("act");
    expect(error.actors.map((actor: { sub: string }) => actor.sub)).toEqual([
      "service-b",
      "service-a",
    ]);
    expect(idp.calls.token).toBe(tokenCallsBefore);
  });

  test('accepts it with "allow" and reports the chain', async () => {
    const oidc = await core({ delegation: "allow" });
    const result = await oidc.processTokens({
      access_token: await accessToken(CHAIN),
    });
    expect(result.user.sub).toBe("user-1");
    expect(result.actors).toEqual([
      { sub: "service-b", iss: "https://other-issuer.example" },
      { sub: "service-a" },
    ]);
  });

  test("lets a function decide per chain", async () => {
    const oidc = await core({
      delegation: (actors) => actors[0]?.sub === "service-b",
    });
    const accepted = await oidc.processTokens({
      access_token: await accessToken(CHAIN),
    });
    expect(accepted.actors[0]?.sub).toBe("service-b");

    await expect(
      oidc.processTokens({
        access_token: await accessToken({ sub: "service-x" }),
      }),
    ).rejects.toThrow(/rejected the access token's actor chain \(service-x\)/);
  });

  test("refuses a malformed act even when delegation is allowed", async () => {
    const oidc = await core({ delegation: "allow" });
    await expect(
      oidc.processTokens({ access_token: await accessToken("service-b") }),
    ).rejects.toBeInstanceOf(OidcDelegationError);
  });

  test("checks id tokens too", async () => {
    const oidc = await core();
    const idToken = await idp.sign({
      sub: "user-1",
      act: { sub: "service-b" },
    });
    await expect(
      oidc.processTokens({ id_token: idToken }),
    ).rejects.toBeInstanceOf(OidcDelegationError);
  });

  test("reports no actors for an ordinary token", async () => {
    const oidc = await core();
    const result = await oidc.processTokens({
      access_token: await accessToken(),
    });
    expect(result.actors).toEqual([]);
  });
});

test("createOidcCore refuses an unknown delegation policy", async () => {
  await expect(
    core({ delegation: "maybe" as unknown as "allow" }),
  ).rejects.toThrow(/invalid delegation/);
});
