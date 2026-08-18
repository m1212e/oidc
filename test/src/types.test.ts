import { describe, expect, test } from "bun:test";
import { parseOIDCFlowState, parseOIDCUser } from "../../lib/types";

describe("parseOIDCUser", () => {
  test("keeps known claims and lowercases the email", () => {
    const user = parseOIDCUser({
      sub: "abc123",
      email: "USER@Example.COM",
      preferred_username: "jdoe",
      family_name: "Doe",
      given_name: "Jane",
      locale: null,
      phone: null,
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
      phone: null,
      realm_access: { roles: ["admin"] },
      azp: "some-client",
    });

    expect("realm_access" in user).toBe(false);
    expect("azp" in user).toBe(false);
  });

  test("throws when sub is missing", () => {
    expect(() => parseOIDCUser({ email: "x@example.com" })).toThrow();
  });

  test("throws on a non-object value", () => {
    expect(() => parseOIDCUser("not-an-object")).toThrow();
    expect(() => parseOIDCUser(null)).toThrow();
  });
});

describe("parseOIDCFlowState", () => {
  test("parses a valid state object", () => {
    const state = parseOIDCFlowState({
      visitedUrl: "/dashboard",
      random: "abc",
    });
    expect(state).toEqual({ visitedUrl: "/dashboard", random: "abc" });
  });

  test("rejects a state object missing required fields", () => {
    expect(() => parseOIDCFlowState({ visitedUrl: "/dashboard" })).toThrow();
  });

  test("rejects a state object with the wrong field types", () => {
    expect(() =>
      parseOIDCFlowState({ visitedUrl: 123, random: "abc" }),
    ).toThrow();
  });
});
