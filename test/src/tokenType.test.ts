import { describe, expect, test } from "bun:test";
import { OidcError, OidcTokenError } from "../../lib/errors";
import {
  assertIntrospectedAccessToken,
  assertIntrospectedIdToken,
  assertTokenTypeAfterJwtVerify,
  assertTokenTypeFromClaims,
  buildTokenTypePolicy,
  DEFAULT_ID_TOKEN_ONLY_CLAIMS,
  OidcTokenTypeError,
} from "../../lib/tokenType";

const policy = buildTokenTypePolicy({});
const noHeader = {};

describe("buildTokenTypePolicy", () => {
  test("defaults to the ID-token-only claim list and pins no typ", () => {
    expect(policy.idTokenOnlyClaims).toEqual(DEFAULT_ID_TOKEN_ONLY_CLAIMS);
    expect(policy.accessTokenTyp).toBeUndefined();
  });

  test("requires an introspected token to name its type by default", () => {
    expect(policy.requireIntrospectedTokenType).toBe(true);
    expect(
      buildTokenTypePolicy({ requireIntrospectedTokenType: false })
        .requireIntrospectedTokenType,
    ).toBe(false);
  });

  test("normalizes a configured typ the way jose does", () => {
    expect(
      buildTokenTypePolicy({ accessTokenTyp: "at+jwt" }).accessTokenTyp,
    ).toBe("application/at+jwt");
    expect(
      buildTokenTypePolicy({ accessTokenTyp: "Application/AT+JWT" })
        .accessTokenTyp,
    ).toBe("application/at+jwt");
    expect(
      buildTokenTypePolicy({ accessTokenTyp: "Bearer" }).accessTokenTyp,
    ).toBe("application/bearer");
  });
});

describe("access token slot", () => {
  test.each([...DEFAULT_ID_TOKEN_ONLY_CLAIMS])(
    'rejects a token carrying "%s"',
    (claim: string) => {
      const claims = { sub: "u", azp: "my-app", [claim]: "whatever" };
      expect(() =>
        assertTokenTypeFromClaims(claims, "access", policy),
      ).toThrowError(OidcTokenTypeError);
      try {
        assertTokenTypeFromClaims(claims, "access", policy);
      } catch (err) {
        expect(err).toBeInstanceOf(OidcTokenError);
        expect(err).toBeInstanceOf(OidcError);
        expect((err as OidcTokenTypeError).tokenKind).toBe("access");
        expect((err as OidcTokenTypeError).claim).toBe(claim);
      }
    },
  );

  test("accepts an ordinary access token", () => {
    expect(() =>
      assertTokenTypeFromClaims(
        { sub: "u", azp: "my-app", scope: "orders.read" },
        "access",
        policy,
      ),
    ).not.toThrow();
  });

  test("rejects Cognito's token_use: id, accepts token_use: access", () => {
    expect(() =>
      assertTokenTypeFromClaims(
        { sub: "u", token_use: "id" },
        "access",
        policy,
      ),
    ).toThrowError(/token_use/);
    expect(() =>
      assertTokenTypeFromClaims(
        { sub: "u", token_use: "access" },
        "access",
        policy,
      ),
    ).not.toThrow();
  });

  test("an empty idTokenOnlyClaims opts out of the claim check", () => {
    const relaxed = buildTokenTypePolicy({ idTokenOnlyClaims: [] });
    expect(() =>
      assertTokenTypeFromClaims({ sub: "u", nonce: "abc" }, "access", relaxed),
    ).not.toThrow();
  });

  test("accessTokenTyp pins the typ header when configured", () => {
    const strict = buildTokenTypePolicy({ accessTokenTyp: "at+jwt" });
    const claims = { sub: "u", azp: "my-app" };

    expect(() =>
      assertTokenTypeAfterJwtVerify(
        claims,
        { typ: "at+jwt" },
        "access",
        strict,
      ),
    ).not.toThrow();
    expect(() =>
      assertTokenTypeAfterJwtVerify(
        claims,
        { typ: "application/at+jwt" },
        "access",
        strict,
      ),
    ).not.toThrow();
    expect(() =>
      assertTokenTypeAfterJwtVerify(claims, { typ: "JWT" }, "access", strict),
    ).toThrowError(/"typ" header/);
    expect(() =>
      assertTokenTypeAfterJwtVerify(claims, noHeader, "access", strict),
    ).toThrowError(/absent/);
  });

  test("any header value can be pinned, whatever it spells", () => {
    const strict = buildTokenTypePolicy({ accessTokenTyp: "Bearer" });
    expect(() =>
      assertTokenTypeAfterJwtVerify(
        { sub: "u" },
        { typ: "Bearer" },
        "access",
        strict,
      ),
    ).not.toThrow();
    expect(() =>
      assertTokenTypeAfterJwtVerify(
        { sub: "u" },
        { typ: "JWT" },
        "access",
        strict,
      ),
    ).toThrow();
  });

  test("an unpinned typ is not checked, so Keycloak and Auth0 both pass", () => {
    for (const typ of ["Bearer", "JWT", undefined]) {
      expect(() =>
        assertTokenTypeAfterJwtVerify({ sub: "u" }, { typ }, "access", policy),
      ).not.toThrow();
    }
  });
});

describe("id token slot", () => {
  test("accepts an ordinary ID token, nonce and at_hash included", () => {
    expect(() =>
      assertTokenTypeAfterJwtVerify(
        { sub: "u", nonce: "abc", at_hash: "xyz" },
        { typ: "JWT" },
        "id",
        policy,
      ),
    ).not.toThrow();
  });

  test("rejects an RFC 9068 access token by its typ header", () => {
    for (const typ of ["at+jwt", "application/at+jwt", "AT+JWT"]) {
      expect(() =>
        assertTokenTypeAfterJwtVerify({ sub: "u" }, { typ }, "id", policy),
      ).toThrowError(/RFC 9068 access token/);
    }
  });

  test("rejects any header typ that names another kind, in either slot", () => {
    for (const typ of ["id+jwt", "id_token", "refresh+jwt", "logout+jwt"]) {
      expect(() =>
        assertTokenTypeAfterJwtVerify({ sub: "u" }, { typ }, "access", policy),
      ).toThrowError(/"typ" header/);
    }
    for (const typ of ["bearer", "dpop", "refresh", "logout+jwt"]) {
      expect(() =>
        assertTokenTypeAfterJwtVerify({ sub: "u" }, { typ }, "id", policy),
      ).toThrowError(/"typ" header/);
    }
  });

  test("reads a media type the same however its application/ prefix is spelled", () => {
    for (const bare of [
      "id+jwt",
      "refresh+jwt",
      "logout+jwt",
      "secevent+jwt",
    ]) {
      for (const typ of [bare, `application/${bare}`, `APPLICATION/${bare}`]) {
        expect(() =>
          assertTokenTypeAfterJwtVerify(
            { sub: "u" },
            { typ },
            "access",
            policy,
          ),
        ).toThrowError(/"typ" header/);
      }
    }
    for (const typ of [
      "at+jwt",
      "application/at+jwt",
      "application/refresh+jwt",
    ]) {
      expect(() =>
        assertTokenTypeAfterJwtVerify({ sub: "u" }, { typ }, "id", policy),
      ).toThrowError(/"typ" header/);
    }
    for (const typ of ["id+jwt", "application/id+jwt"]) {
      expect(() =>
        assertTokenTypeFromClaims({ sub: "u", typ }, "access", policy),
      ).toThrowError(/"typ"/);
    }
    for (const typ of ["application/application/id+jwt", "foo/id+jwt"]) {
      expect(() =>
        assertTokenTypeAfterJwtVerify({ sub: "u" }, { typ }, "access", policy),
      ).not.toThrow();
    }
  });

  test("still says nothing about a header typ it does not recognize", () => {
    for (const slot of ["access", "id"] as const) {
      for (const header of [{ typ: "JWT" }, { typ: "dpop+jwt" }, {}]) {
        expect(() =>
          assertTokenTypeAfterJwtVerify({ sub: "u" }, header, slot, policy),
        ).not.toThrow();
      }
    }
    expect(() =>
      assertTokenTypeAfterJwtVerify(
        { sub: "u", azp: "my-app" },
        { typ: "at+jwt" },
        "access",
        policy,
      ),
    ).not.toThrow();
  });

  test("rejects Cognito's token_use: access", () => {
    expect(() =>
      assertTokenTypeFromClaims(
        { sub: "u", token_use: "access" },
        "id",
        policy,
      ),
    ).toThrowError(/token_use/);
  });

  test("rejects a back-channel logout token", () => {
    const logoutToken = {
      sub: "u",
      aud: "my-app",
      events: { "http://schemas.openid.net/event/backchannel-logout": {} },
    };
    expect(() =>
      assertTokenTypeFromClaims(logoutToken, "id", policy),
    ).toThrowError(/logout token/);
  });
});

describe("the typ claim, which is where Keycloak names the kind", () => {
  test.each([
    ["Refresh", "access"],
    ["Offline", "access"],
    ["ID", "access"],
    ["Logout", "access"],
    ["Bearer", "id"],
    ["Refresh", "id"],
  ] as const)('rejects typ "%s" in the %s slot', (typ, slot) => {
    expect(() =>
      assertTokenTypeFromClaims({ sub: "u", typ }, slot, policy),
    ).toThrowError(/"typ"/);
  });

  test.each(["Bearer", "bearer", "DPoP", "at+jwt"])(
    'accepts typ "%s" in the access slot',
    (typ) => {
      expect(() =>
        assertTokenTypeFromClaims({ sub: "u", typ }, "access", policy),
      ).not.toThrow();
    },
  );

  test("says nothing about a value it does not recognize", () => {
    for (const slot of ["access", "id"] as const) {
      for (const typ of ["JWT", "Registration Access Token", "", 7, null]) {
        expect(() =>
          assertTokenTypeFromClaims({ sub: "u", typ }, slot, policy),
        ).not.toThrow();
      }
    }
  });
});

describe("assertIntrospectedAccessToken", () => {
  const active = { active: true, sub: "u", client_id: "my-app" };

  test("accepts a response that names an access token", () => {
    for (const named of [
      { token_type: "Bearer" },
      { token_type: "bearer" },
      { token_type: "DPoP" },
      { typ: "Bearer" },
      { token_use: "access" },
    ]) {
      expect(() =>
        assertIntrospectedAccessToken({ ...active, ...named }, policy),
      ).not.toThrow();
    }
  });

  test("refuses a response that names no type at all", () => {
    const err = (() => {
      try {
        assertIntrospectedAccessToken(active, policy);
      } catch (e) {
        return e as OidcTokenTypeError;
      }
    })();
    expect(err).toBeInstanceOf(OidcTokenTypeError);
    expect(err?.claim).toBe("token_type");
    expect(err?.tokenKind).toBe("access");
  });

  test("refuses a response that names another type outright", () => {
    for (const named of [
      { typ: "Refresh" },
      { typ: "Offline" },
      { token_type: "Refresh" },
      { token_use: "id" },
    ]) {
      expect(() =>
        assertIntrospectedAccessToken({ ...active, ...named }, policy),
      ).toThrow(OidcTokenTypeError);
    }
  });

  test("still applies the ID-token-only claim rules", () => {
    expect(() =>
      assertIntrospectedAccessToken(
        { ...active, token_type: "Bearer", at_hash: "abc" },
        policy,
      ),
    ).toThrow(OidcTokenTypeError);
  });

  test("waiving the requirement waives only the absent-type case", () => {
    const lax = buildTokenTypePolicy({ requireIntrospectedTokenType: false });
    expect(() => assertIntrospectedAccessToken(active, lax)).not.toThrow();
    expect(() =>
      assertIntrospectedAccessToken({ ...active, typ: "Refresh" }, lax),
    ).toThrow(OidcTokenTypeError);
  });
});

describe("assertIntrospectedIdToken", () => {
  test("accepts a response that names an ID token", () => {
    for (const named of [
      { typ: "ID" },
      { token_use: "id" },
      { token_type: "id_token" },
    ]) {
      expect(() =>
        assertIntrospectedIdToken({ active: true, sub: "u", ...named }, policy),
      ).not.toThrow();
    }
  });

  test("refuses a response that names an access or refresh token", () => {
    for (const named of [
      { token_type: "Bearer" },
      { typ: "Refresh" },
      { token_use: "access" },
    ]) {
      expect(() =>
        assertIntrospectedIdToken({ active: true, sub: "u", ...named }, policy),
      ).toThrow(OidcTokenTypeError);
    }
  });

  test("refuses a response that names nothing at all", () => {
    const err = (() => {
      try {
        assertIntrospectedIdToken({ active: true, sub: "u" }, policy);
      } catch (e) {
        return e as OidcTokenTypeError;
      }
    })();
    expect(err).toBeInstanceOf(OidcTokenTypeError);
    expect(err?.tokenKind).toBe("id");
    expect(err?.claim).toBe("token_type");
  });

  test("waives the requirement with requireIntrospectedTokenType off", () => {
    const lax = buildTokenTypePolicy({ requireIntrospectedTokenType: false });
    expect(() =>
      assertIntrospectedIdToken({ active: true, sub: "u" }, lax),
    ).not.toThrow();
    expect(() =>
      assertIntrospectedIdToken(
        { active: true, sub: "u", typ: "Refresh" },
        lax,
      ),
    ).toThrow(OidcTokenTypeError);
  });

  test("does not hold an ID token to the ID-token-only claims", () => {
    expect(() =>
      assertIntrospectedIdToken(
        { active: true, sub: "u", typ: "ID", nonce: "n", at_hash: "h" },
        policy,
      ),
    ).not.toThrow();
  });
});

describe("the kind-name table is not the prototype chain", () => {
  const policy = buildTokenTypePolicy({});

  test('a "typ" naming an Object.prototype member is unknown, not a kind', () => {
    for (const value of ["constructor", "__proto__", "toString", "valueOf"]) {
      expect(() =>
        assertTokenTypeFromClaims({ sub: "u", typ: value }, "access", policy),
      ).not.toThrow();
      expect(() =>
        assertTokenTypeFromClaims({ sub: "u", typ: value }, "id", policy),
      ).not.toThrow();
    }
  });

  test("an introspection response cannot name its kind that way either", () => {
    for (const value of ["constructor", "__proto__", "hasOwnProperty"]) {
      expect(() =>
        assertIntrospectedAccessToken(
          { active: true, sub: "u", token_type: value },
          policy,
        ),
      ).toThrow(OidcTokenTypeError);
      expect(() =>
        assertIntrospectedAccessToken(
          { active: true, sub: "u", token_type: value },
          buildTokenTypePolicy({ requireIntrospectedTokenType: false }),
        ),
      ).not.toThrow();
    }
  });
});
