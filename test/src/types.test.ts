import { describe, expect, test } from "bun:test";
import {
  attachRefreshedTokens,
  OidcClaimsError,
  OidcGrantError,
  OidcStateError,
  OidcSubjectError,
  OidcTokenError,
  OidcTokenValidationError,
} from "../../lib/errors";
import {
  mergeTokenClaims,
  parseOIDCFlowState,
  parseOIDCUser,
} from "../../lib/types";

describe("parseOIDCUser", () => {
  test("keeps known claims and lowercases the email", () => {
    const user = parseOIDCUser({
      sub: "abc123",
      email: "USER@Example.COM",
      preferred_username: "jdoe",
      family_name: "Doe",
      given_name: "Jane",
      locale: null,
      phone_number: null,
    });

    expect(user.sub).toBe("abc123");
    expect(user.email).toBe("user@example.com");
    expect(user.preferred_username).toBe("jdoe");
  });

  test("strips claims not in the schema", () => {
    const user = parseOIDCUser({
      sub: "abc123",
      email: null,
      preferred_username: null,
      family_name: null,
      given_name: null,
      locale: null,
      phone_number: null,
      realm_access: { roles: ["admin"] },
      azp: "some-client",
    });

    expect("realm_access" in user).toBe(false);
    expect("azp" in user).toBe(false);
  });

  test("keeps email_verified, so the email is usable safely", () => {
    expect(
      parseOIDCUser({ sub: "u", email: "u@example.com", email_verified: true })
        .email_verified,
    ).toBe(true);
    // Absent is not false — the issuer simply said nothing.
    expect(
      parseOIDCUser({ sub: "u", email: "u@example.com" }).email_verified,
    ).toBeUndefined();
  });

  test("normalizes the providers that send email_verified as a string", () => {
    expect(
      parseOIDCUser({ sub: "u", email_verified: "true" }).email_verified,
    ).toBe(true);
    expect(
      parseOIDCUser({ sub: "u", email_verified: "TRUE" }).email_verified,
    ).toBe(true);
    // Anything that does not spell out truth must not read as verified.
    expect(
      parseOIDCUser({ sub: "u", email_verified: "false" }).email_verified,
    ).toBe(false);
    expect(
      parseOIDCUser({ sub: "u", email_verified: "yes" }).email_verified,
    ).toBe(false);
  });

  test("reads the phone claim under its OIDC Core name", () => {
    const user = parseOIDCUser({
      sub: "u",
      phone_number: "+49 123",
      phone_number_verified: false,
    });
    expect(user.phone_number).toBe("+49 123");
    expect(user.phone_number_verified).toBe(false);
  });

  test("reports a claim set it cannot read as an OidcError", () => {
    // `sub` is optional in an RFC 7662 response, so this is reachable with
    // claims that already passed every signature and policy check — it has to
    // land in the same catch block as any other rejection.
    expect(() => parseOIDCUser({ email: "x@example.com" })).toThrow(
      OidcClaimsError,
    );
    expect(() => parseOIDCUser("not-an-object")).toThrow(OidcClaimsError);
    expect(() => parseOIDCUser(null)).toThrow(OidcClaimsError);
  });
});

describe("parseOIDCFlowState", () => {
  test("parses a valid state", () => {
    const state = parseOIDCFlowState(
      JSON.stringify({ visitedUrl: "/dashboard", random: "abc" }),
    );
    expect(state).toEqual({ visitedUrl: "/dashboard", random: "abc" });
  });

  test("rejects a state missing required fields", () => {
    expect(() =>
      parseOIDCFlowState(JSON.stringify({ visitedUrl: "/dashboard" })),
    ).toThrow(OidcStateError);
  });

  test("rejects a state with the wrong field types", () => {
    expect(() =>
      parseOIDCFlowState(JSON.stringify({ visitedUrl: 123, random: "abc" })),
    ).toThrow(OidcStateError);
  });

  test("reports an unparseable state as an OidcError, not a SyntaxError", () => {
    // A truncated cookie is an ordinary thing to meet at a callback endpoint.
    const err = (() => {
      try {
        parseOIDCFlowState('{"visitedUrl":"/dash');
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(OidcStateError);
    expect((err as Error).cause).toBeInstanceOf(SyntaxError);
  });
});

describe("claims are validated, never coerced", () => {
  /**
   * TypeBox's `Decode` pipeline converts on the way in, which for an identity
   * claim is worse than a rejection: `sub: null` arrived as the string
   * `"null"` — a subject every subject-less token set would share — while
   * `subjectOf` in the validation chain, which demands a non-empty string, saw
   * nothing there to bind a refresh against.
   */
  test.each([
    ["absent", {}],
    ["null", { sub: null }],
    ["a number", { sub: 12345 }],
    ["a boolean", { sub: true }],
    ["empty", { sub: "" }],
    ["an object", { sub: {} }],
    ["an array", { sub: ["abc"] }],
  ])("refuses a sub that is %s", (_label, claims) => {
    expect(() => parseOIDCUser(claims)).toThrow(OidcClaimsError);
  });

  test("drops an optional claim of the wrong shape rather than stringifying it", () => {
    const user = parseOIDCUser({
      sub: "abc123",
      email: true,
      phone_number: 4915112345,
    });
    expect(user.sub).toBe("abc123");
    expect(user.email).toBeUndefined();
    expect(user.phone_number).toBeUndefined();
  });

  test("reads the verified flags every provider spells differently", () => {
    const cases: [unknown, boolean | undefined][] = [
      [true, true],
      [false, false],
      ["true", true],
      ["TRUE ", true],
      ["false", false],
      ["anything else", false],
      [1, true],
      // Used to convert to `null`, i.e. "the issuer said nothing" — which is
      // the one reading a `0` must never get.
      [0, false],
      [{}, undefined],
    ];
    for (const [value, expected] of cases) {
      const user = parseOIDCUser({ sub: "abc123", email_verified: value });
      expect(user.email_verified ?? undefined).toBe(expected);
    }
  });
});

describe("parseOIDCFlowState is not coerced either", () => {
  test("refuses a nonce that is not a string", () => {
    // Converted to `"12345"` before, producing a nonce that cannot match the
    // one the ID token echoes.
    expect(() =>
      parseOIDCFlowState(
        JSON.stringify({ visitedUrl: "/", random: "r", nonce: 12345 }),
      ),
    ).toThrow(OidcStateError);
  });

  test("still reads the state startSignin produces", () => {
    const state = parseOIDCFlowState(
      JSON.stringify({ visitedUrl: "/dashboard", random: "r", nonce: "n" }),
    );
    expect(state).toEqual({
      visitedUrl: "/dashboard",
      random: "r",
      nonce: "n",
    });
  });
});

describe("mergeTokenClaims", () => {
  test("lets the id token win, as a plain spread would", () => {
    const merged = mergeTokenClaims(
      { sub: "a", preferred_username: "from-access", locale: "de" },
      { sub: "a", preferred_username: "from-id" },
    );

    expect(merged.preferred_username).toBe("from-id");
    expect(merged.locale).toBe("de");
  });

  test("drops a flag whose value the other token supplied", () => {
    const merged = mergeTokenClaims(
      { email: "old@example.com", email_verified: true },
      { email: "new@example.com" },
    );

    expect(merged.email).toBe("new@example.com");
    expect(merged.email_verified).toBeUndefined();
  });

  test("keeps a flag that came beside the surviving value", () => {
    const merged = mergeTokenClaims(
      { email: "old@example.com", email_verified: true },
      { email: "new@example.com", email_verified: false },
    );

    expect(merged.email).toBe("new@example.com");
    expect(merged.email_verified).toBe(false);
  });

  test("keeps the access token's pair when the id token names no value", () => {
    const merged = mergeTokenClaims(
      { email: "only@example.com", email_verified: true },
      { sub: "a" },
    );

    expect(merged.email).toBe("only@example.com");
    expect(merged.email_verified).toBe(true);
  });

  test("drops a flag that vouches for nothing", () => {
    const merged = mergeTokenClaims(
      { email_verified: true, phone_number_verified: true },
      undefined,
    );

    expect(merged.email_verified).toBeUndefined();
    expect(merged.phone_number_verified).toBeUndefined();
  });

  test("treats the phone pair the same way", () => {
    const merged = mergeTokenClaims(
      { phone_number: "+1000", phone_number_verified: true },
      { phone_number: "+2000" },
    );

    expect(merged.phone_number).toBe("+2000");
    expect(merged.phone_number_verified).toBeUndefined();
  });

  test("reports only values the two tokens actively disagree on", () => {
    const conflicts: string[] = [];
    mergeTokenClaims(
      { email: "a@example.com", phone_number: "+1000" },
      { email: "b@example.com", phone_number: "+1000" },
      (claim) => conflicts.push(claim),
    );

    expect(conflicts).toEqual(["email"]);
  });

  test("handles both sides being absent", () => {
    expect(mergeTokenClaims(undefined, undefined)).toEqual({});
  });
});

describe("attachRefreshedTokens", () => {
  const tokenSet = { access_token: "new" } as never;

  test("carries the replacement on any rejection that follows a refresh", () => {
    // The obligation comes from the refresh token already having been spent,
    // which is true whatever went wrong afterwards — including a provider
    // shape surprise that has nothing to do with the tokens themselves.
    for (const error of [
      new OidcClaimsError("unreadable claims"),
      new OidcTokenValidationError(["access"], []),
      new OidcTokenError("access", "aud", "wrong client"),
      new OidcGrantError("refresh_token", "refused"),
      new OidcStateError("unreadable state"),
    ]) {
      expect(attachRefreshedTokens(error, tokenSet).refreshedTokens).toBe(
        tokenSet,
      );
    }
  });

  test("never carries it on a subject mismatch", () => {
    const error = attachRefreshedTokens(
      new OidcSubjectError("wrong user", "a", "b"),
      tokenSet,
    );

    expect(error.refreshedTokens).toBeUndefined();
  });

  test("carries nothing when no refresh happened", () => {
    expect(
      attachRefreshedTokens(new OidcClaimsError("x"), undefined)
        .refreshedTokens,
    ).toBeUndefined();
  });
});
