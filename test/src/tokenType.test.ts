import { describe, expect, test } from "bun:test";
import { OidcError, OidcTokenError } from "../../lib/errors";
import {
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
    // An absent header cannot satisfy an explicitly required typ.
    expect(() =>
      assertTokenTypeAfterJwtVerify(claims, noHeader, "access", strict),
    ).toThrowError(/absent/);
  });

  test("Keycloak's typ: Bearer can be pinned too", () => {
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
