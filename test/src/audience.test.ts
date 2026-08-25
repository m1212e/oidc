import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
  assertTokenAudience,
  buildAudiencePolicy,
  idTokenIntrospectionPolicy,
  OidcAudienceError,
} from "../../lib/audience";
import { createOidcCore, type OidcCore } from "../../lib/core";
import {
  startTestOidcProvider,
  type TestOidcProvider,
} from "./testOidcProvider";

let idp: TestOidcProvider;
/** The normal case: this app is the client, no resource audience configured. */
let core: OidcCore;

beforeAll(async () => {
  idp = await startTestOidcProvider();
  core = await createOidcCore({
    issuer: idp.issuer,
    clientId: idp.clientId,
    development: true,
    logLevel: "silent",
  });
});

afterAll(async () => {
  await idp.close();
});

describe("id token audience", () => {
  test("rejects a token minted for a different client at the same issuer", async () => {
    // The cross-client replay: same issuer, valid signature, wrong `aud`.
    const foreign = await idp.sign(
      { sub: "victim" },
      { audience: "some-other-client" },
    );

    const err = await core
      .processTokens({ id_token: foreign })
      .then(() => undefined)
      .catch((e) => e);

    expect(err).toBeInstanceOf(OidcAudienceError);
    expect((err as OidcAudienceError).claim).toBe("aud");
    expect((err as OidcAudienceError).tokenKind).toBe("id");
  });

  test("accepts a token whose aud is this client", async () => {
    const ok = await idp.sign({ sub: "user-ok", email: "User-OK@Example.com" });
    const result = await core.processTokens({ id_token: ok });
    expect(result.user.sub).toBe("user-ok");
  });

  test("rejects a correct aud when azp names a different client", async () => {
    // Keycloak-style azp, but the token was obtained by someone else and
    // merely lists us as an audience.
    const token = await idp.sign({ sub: "user-azp", azp: "another-client" });

    const err = await core
      .processTokens({ id_token: token })
      .then(() => undefined)
      .catch((e) => e);

    expect(err).toBeInstanceOf(OidcAudienceError);
    expect((err as OidcAudienceError).claim).toBe("azp");
  });

  test("accepts multiple audiences when azp identifies this client", async () => {
    const token = await idp.sign(
      { sub: "user-multi", azp: idp.clientId },
      { audience: [idp.clientId, "another-client"] },
    );
    const result = await core.processTokens({ id_token: token });
    expect(result.user.sub).toBe("user-multi");
  });

  test("rejects multiple audiences with no azp to disambiguate", async () => {
    const token = await idp.sign(
      { sub: "user-multi-noazp" },
      { audience: [idp.clientId, "another-client"] },
    );

    const err = await core
      .processTokens({ id_token: token })
      .then(() => undefined)
      .catch((e) => e);

    expect(err).toBeInstanceOf(OidcAudienceError);
    expect((err as OidcAudienceError).claim).toBe("azp");
  });
});

describe("access token audience — provider shapes", () => {
  test("Keycloak: aud is 'account', azp names the client", async () => {
    const token = await idp.sign(
      { sub: "kc-user", azp: idp.clientId },
      { audience: "account" },
    );
    const result = await core.processTokens({ access_token: token });
    expect(result.user.sub).toBe("kc-user");
  });

  test("Keycloak: rejects when azp names a different client", async () => {
    const token = await idp.sign(
      { sub: "kc-attacker", azp: "evil-client" },
      { audience: "account" },
    );

    const err = await core
      .processTokens({ access_token: token })
      .then(() => undefined)
      .catch((e) => e);

    expect(err).toBeInstanceOf(OidcAudienceError);
    expect((err as OidcAudienceError).claim).toBe("azp");
  });

  test("Okta: client identified by 'cid'", async () => {
    const token = await idp.sign(
      { sub: "okta-user", cid: idp.clientId },
      { audience: "api://default" },
    );
    const result = await core.processTokens({ access_token: token });
    expect(result.user.sub).toBe("okta-user");
  });

  test("Entra v1: client identified by 'appid'", async () => {
    const token = await idp.sign(
      { sub: "entra-user", appid: idp.clientId },
      { audience: "00000003-0000-0000-c000-000000000000" },
    );
    const result = await core.processTokens({ access_token: token });
    expect(result.user.sub).toBe("entra-user");
  });

  test("Cognito: RFC 9068 'client_id', no aud at all", async () => {
    const token = await idp.sign(
      { sub: "cognito-user", client_id: idp.clientId },
      { audience: [] },
    );
    const result = await core.processTokens({ access_token: token });
    expect(result.user.sub).toBe("cognito-user");
  });

  test("never compares an access token's aud against the client id", async () => {
    // The Keycloak trap in isolation: aud is *not* the client id and there is
    // no expectedAudience — this must still pass on the strength of azp alone.
    const token = await idp.sign(
      { sub: "no-aud-match", azp: idp.clientId },
      { audience: "totally-unrelated-resource" },
    );
    await expect(
      core.processTokens({ access_token: token }),
    ).resolves.toBeDefined();
  });
});

describe("access token audience — backstop", () => {
  test("rejects a token that names no client and matches no configured audience", async () => {
    const token = await idp.sign(
      { sub: "unbindable" },
      { audience: "account" },
    );

    const err = await core
      .processTokens({ access_token: token })
      .then(() => undefined)
      .catch((e) => e);

    expect(err).toBeInstanceOf(OidcAudienceError);
    expect((err as OidcAudienceError).message).toContain("expectedAudience");
  });

  test("an unbindable token does not burn a refresh token", async () => {
    const token = await idp.sign(
      { sub: "unbindable-2" },
      { audience: "account" },
    );
    const tokenCallsBefore = idp.calls.token;

    await expect(
      core.processTokens({
        access_token: token,
        refresh_token: "some-refresh-token",
      }),
    ).rejects.toBeInstanceOf(OidcAudienceError);

    // An audience mismatch is permanent — refreshing cannot fix it, so the
    // fallback chain must short-circuit rather than spend the refresh token.
    expect(idp.calls.token).toBe(tokenCallsBefore);
  });
});

describe("expectedAudience", () => {
  test("refuses an entry that is not a usable audience value", () => {
    // Silently dropping the only entry left the policy comparing the
    // authorized party to `clientId` instead — a different question, against a
    // value the caller never configured — while the deployment read as though
    // it had pinned a resource audience.
    for (const expectedAudience of [
      "",
      [""],
      ["api://orders", ""],
      [undefined as unknown as string],
    ]) {
      expect(() =>
        buildAudiencePolicy({ clientId: "my-app", expectedAudience }),
      ).toThrowError(TypeError);
    }
    // An empty list is "not configured", which is a coherent thing to mean.
    expect(
      buildAudiencePolicy({ clientId: "my-app", expectedAudience: [] })
        .expectedAudience,
    ).toBeUndefined();
    expect(
      buildAudiencePolicy({ clientId: "my-app", expectedAudience: "api://a" })
        .expectedAudience,
    ).toEqual(["api://a"]);
  });

  test("accepts a resource-bound token with no authorized-party claim", async () => {
    const bound = await createOidcCore({
      issuer: idp.issuer,
      clientId: idp.clientId,
      expectedAudience: "api://orders",
      development: true,
      logLevel: "silent",
    });
    const token = await idp.sign(
      { sub: "resource-user" },
      { audience: "api://orders" },
    );
    const result = await bound.processTokens({ access_token: token });
    expect(result.user.sub).toBe("resource-user");
  });

  test("accepts a resource-bound token that another client obtained", async () => {
    // The ordinary API/SPA split: the orders API validates a token its own
    // clientId did not request. Requiring `azp === clientId` on top of the
    // audience match is what used to reject this.
    const api = await createOidcCore({
      issuer: idp.issuer,
      clientId: "orders-api",
      expectedAudience: "api://orders",
      development: true,
      logLevel: "silent",
    });
    const token = await idp.sign(
      { sub: "spa-user", azp: "the-spa", scope: "orders.read" },
      { audience: "api://orders" },
    );

    const result = await api.processTokens({ access_token: token });
    expect(result.user.sub).toBe("spa-user");
    expect(
      (result.accessTokenClaims as { azp?: string } | undefined)?.azp,
    ).toBe("the-spa");
  });

  test("a configured audience makes authorizedPartyClaims inert", async () => {
    // `consumer_key` names a client that is not this one; the audience match
    // is the binding, so it is never consulted.
    const api = await createOidcCore({
      issuer: idp.issuer,
      clientId: "orders-api",
      expectedAudience: "api://orders",
      authorizedPartyClaims: ["consumer_key"],
      development: true,
      logLevel: "silent",
    });
    const token = await idp.sign(
      { sub: "inert-user", consumer_key: "somebody-else" },
      { audience: "api://orders" },
    );
    await expect(
      api.processTokens({ access_token: token }),
    ).resolves.toBeDefined();
  });

  test("still rejects a token minted for a different resource", async () => {
    const api = await createOidcCore({
      issuer: idp.issuer,
      clientId: "orders-api",
      expectedAudience: "api://orders",
      development: true,
      logLevel: "silent",
    });
    const token = await idp.sign(
      { sub: "wrong-resource-user", azp: "the-spa" },
      { audience: "api://billing" },
    );

    const err = await api
      .processTokens({ access_token: token })
      .then(() => undefined)
      .catch((e) => e);
    expect(err).toBeInstanceOf(OidcAudienceError);
    expect((err as OidcAudienceError).claim).toBe("aud");
  });

  test("rejects a mismatched aud even when azp is correct", async () => {
    const bound = await createOidcCore({
      issuer: idp.issuer,
      clientId: idp.clientId,
      expectedAudience: ["api://orders"],
      development: true,
      logLevel: "silent",
    });
    const token = await idp.sign(
      { sub: "wrong-resource", azp: idp.clientId },
      { audience: "api://billing" },
    );

    await expect(
      bound.processTokens({ access_token: token }),
    ).rejects.toBeInstanceOf(OidcAudienceError);
  });
});

describe("checks delegated to jose", () => {
  test("an id token aud failure still short-circuits instead of refreshing", async () => {
    // Now raised by jose's `audience` option rather than our own code — the
    // permanent-failure mapping has to survive that hand-off.
    const foreign = await idp.sign(
      { sub: "victim-2" },
      { audience: "some-other-client" },
    );
    const tokenCallsBefore = idp.calls.token;

    await expect(
      core.processTokens({
        id_token: foreign,
        refresh_token: "some-refresh-token",
      }),
    ).rejects.toBeInstanceOf(OidcAudienceError);
    expect(idp.calls.token).toBe(tokenCallsBefore);
  });

  test("clock tolerance absorbs small skew rather than forcing a refresh", async () => {
    const token = await idp.sign({ sub: "skewed" }, { expiresIn: -10 });
    const result = await core.processTokens({ id_token: token });
    expect(result.user.sub).toBe("skewed");
    expect(result.refreshed).toBe(false);
  });

  test("clockTolerance: 0 rejects the same token", async () => {
    const strict = await createOidcCore({
      issuer: idp.issuer,
      clientId: idp.clientId,
      clockTolerance: 0,
      development: true,
      logLevel: "silent",
    });
    const token = await idp.sign({ sub: "skewed-2" }, { expiresIn: -10 });
    await expect(strict.processTokens({ id_token: token })).rejects.toThrow();
  });

  test("rejects a token with no exp, which would otherwise never expire", async () => {
    const token = await idp.sign({ sub: "eternal" }, { noExpiry: true });
    await expect(core.processTokens({ id_token: token })).rejects.toThrow();
  });

  test("signingAlgorithms pins the accepted JWS algorithm", async () => {
    const esOnly = await createOidcCore({
      issuer: idp.issuer,
      clientId: idp.clientId,
      signingAlgorithms: ["ES256"],
      development: true,
      logLevel: "silent",
    });
    // The provider signs RS256.
    const token = await idp.sign({ sub: "rs256-user" });
    await expect(esOnly.processTokens({ id_token: token })).rejects.toThrow();
    // ...and the same token is fine under the discovered defaults.
    await expect(
      core.processTokens({ id_token: token }),
    ).resolves.toBeDefined();
  });
});

describe("escape hatches", () => {
  test("authorizedPartyClaims can name a provider-specific claim", async () => {
    const custom = await createOidcCore({
      issuer: idp.issuer,
      clientId: idp.clientId,
      authorizedPartyClaims: ["consumer_key"],
      development: true,
      logLevel: "silent",
    });
    const token = await idp.sign(
      { sub: "custom-user", consumer_key: idp.clientId },
      { audience: "whatever" },
    );
    const result = await custom.processTokens({ access_token: token });
    expect(result.user.sub).toBe("custom-user");
  });

  test("verifyAudience replaces the built-in policy for both token kinds", async () => {
    const seen: string[] = [];
    const custom = await createOidcCore({
      issuer: idp.issuer,
      clientId: idp.clientId,
      verifyAudience: (claims, kind) => {
        seen.push(kind);
        return claims.sub === "allowed";
      },
      development: true,
      logLevel: "silent",
    });

    // Would fail the built-in id-token policy outright (wrong aud).
    const allowed = await idp.sign(
      { sub: "allowed" },
      { audience: "some-other-client" },
    );
    const result = await custom.processTokens({ id_token: allowed });
    expect(result.user.sub).toBe("allowed");
    expect(seen).toContain("id");

    const denied = await idp.sign({ sub: "denied" });
    await expect(
      custom.processTokens({ id_token: denied }),
    ).rejects.toBeInstanceOf(OidcAudienceError);
  });
});

describe("idTokenIntrospectionPolicy", () => {
  test("drops a resource audience an ID token could never carry", () => {
    const policy = buildAudiencePolicy({
      clientId: "my-app",
      expectedAudience: "api://orders",
    });
    const introspected = {
      active: true,
      sub: "u",
      client_id: "my-app",
      // What an AS reports for an ID token: the audience is the client.
      aud: "my-app",
    };

    // Held to the access-token policy as-is, the resource audience makes this
    // unvalidatable — "api://orders" is not something an ID token ever says.
    expect(() => assertTokenAudience(introspected, "access", policy)).toThrow(
      OidcAudienceError,
    );
    // With the resource audience dropped, the client binding still applies.
    expect(() =>
      assertTokenAudience(
        introspected,
        "access",
        idTokenIntrospectionPolicy(policy),
      ),
    ).not.toThrow();
    expect(() =>
      assertTokenAudience(
        { ...introspected, client_id: "another-app" },
        "access",
        idTokenIntrospectionPolicy(policy),
      ),
    ).toThrow(OidcAudienceError);
  });

  test("is a no-op when no resource audience is configured", () => {
    const policy = buildAudiencePolicy({ clientId: "my-app" });
    expect(idTokenIntrospectionPolicy(policy)).toBe(policy);
  });
});

describe("a malformed authorized-party claim is not stepped over", () => {
  const policy = buildAudiencePolicy({ clientId: "test-client" });

  test("refuses an azp that is present but not a string", () => {
    // The claim the issuer meant as the binding is there; it just is not a
    // usable one. Skipping to the next claim name would let the token be bound
    // by a claim its issuer did not intend for that, so it fails instead.
    expect(() =>
      assertTokenAudience(
        { azp: ["test-client"], client_id: "test-client", sub: "u" },
        "access",
        policy,
      ),
    ).toThrow(OidcAudienceError);
  });

  test("refuses an empty azp", () => {
    expect(() =>
      assertTokenAudience(
        { azp: "", client_id: "test-client", sub: "u" },
        "access",
        policy,
      ),
    ).toThrow(OidcAudienceError);
  });

  test("treats a null azp as absent, as JSON spells it", () => {
    expect(() =>
      assertTokenAudience(
        { azp: null, client_id: "test-client", sub: "u" },
        "access",
        policy,
      ),
    ).not.toThrow();
  });

  test("and the same in an id token", () => {
    expect(() =>
      assertTokenAudience(
        { azp: ["test-client"], aud: "test-client", sub: "u" },
        "id",
        policy,
      ),
    ).toThrow(OidcAudienceError);
    expect(() =>
      assertTokenAudience(
        { azp: null, aud: "test-client", sub: "u" },
        "id",
        policy,
      ),
    ).not.toThrow();
  });
});
