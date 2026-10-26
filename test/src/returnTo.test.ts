import { describe, expect, test } from "bun:test";
import {
  assertSafeRedirectUri,
  assertSafeReturnTo,
  buildReturnToPolicy,
  OidcReturnToError,
} from "../../lib/returnTo";

const sameSiteOnly = buildReturnToPolicy({});
const withOrigins = buildReturnToPolicy({
  allowedReturnToOrigins: ["https://app.example.com"],
});

describe("assertSafeReturnTo", () => {
  test("passes ordinary same-site paths through untouched", () => {
    for (const path of [
      "/",
      "/dashboard",
      "/dashboard?tab=1&q=a%20b",
      "/dashboard#section",
      "/a/b/c",
      "/@handle",
      "/:weird:/path",
      "/path/with/../dots",
    ]) {
      expect(assertSafeReturnTo(path, sameSiteOnly)).toBe(path);
    }
  });

  test("refuses the targets that only look relative", () => {
    for (const hostile of [
      "//evil.example.com",
      "//evil.example.com/path",
      "/\\evil.example.com",
      "/\\/evil.example.com",
      "\\\\evil.example.com",
      "/path\\..\\..",
    ]) {
      expect(() => assertSafeReturnTo(hostile, sameSiteOnly)).toThrow(
        OidcReturnToError,
      );
    }
  });

  test("refuses absolute URLs when no origin is allowed", () => {
    for (const hostile of [
      "https://evil.example.com/phish",
      "http://evil.example.com",
      "javascript:alert(1)",
      "data:text/html,<script>alert(1)</script>",
      "//evil.example.com",
    ]) {
      expect(() => assertSafeReturnTo(hostile, sameSiteOnly)).toThrow(
        OidcReturnToError,
      );
    }
  });

  test("refuses values a browser would rewrite or split", () => {
    for (const hostile of [
      "/dash\nboard",
      "/dash\rboard",
      "/dash\tboard",
      "/dash board",
      " /dashboard",
      "/dashboard\u0000",
      "/dashboard\u007f",
    ]) {
      expect(() => assertSafeReturnTo(hostile, sameSiteOnly)).toThrow(
        OidcReturnToError,
      );
    }
  });

  test("refuses the empty and non-string cases", () => {
    expect(() => assertSafeReturnTo("", sameSiteOnly)).toThrow(
      OidcReturnToError,
    );
    expect(() =>
      assertSafeReturnTo(undefined as unknown as string, sameSiteOnly),
    ).toThrow(OidcReturnToError);
    expect(() => assertSafeReturnTo("dashboard", sameSiteOnly)).toThrow(
      OidcReturnToError,
    );
    expect(() => assertSafeReturnTo("?next=/x", sameSiteOnly)).toThrow(
      OidcReturnToError,
    );
  });

  test("carries the rejected value for logging", () => {
    const err = (() => {
      try {
        assertSafeReturnTo("https://evil.example.com/phish", sameSiteOnly);
      } catch (e) {
        return e as OidcReturnToError;
      }
    })();
    expect(err).toBeInstanceOf(OidcReturnToError);
    expect(err?.returnTo).toBe("https://evil.example.com/phish");
  });

  test("allows an absolute URL on an allowed origin, and nothing next to it", () => {
    expect(
      assertSafeReturnTo("https://app.example.com/dashboard", withOrigins),
    ).toBe("https://app.example.com/dashboard");
    expect(() =>
      assertSafeReturnTo("http://app.example.com/dashboard", withOrigins),
    ).toThrow(OidcReturnToError);
    expect(() =>
      assertSafeReturnTo("https://app.example.com:8443/x", withOrigins),
    ).toThrow(OidcReturnToError);
    expect(() =>
      assertSafeReturnTo("https://app.example.com.evil.test/x", withOrigins),
    ).toThrow(OidcReturnToError);
    expect(() =>
      assertSafeReturnTo("https://evil.test/app.example.com", withOrigins),
    ).toThrow(OidcReturnToError);
    expect(() =>
      assertSafeReturnTo("https://app.example.com@evil.test/x", withOrigins),
    ).toThrow(OidcReturnToError);
    expect(assertSafeReturnTo("/dashboard", withOrigins)).toBe("/dashboard");
  });

  test("refuses a scheme that only borrows an allowed origin", () => {
    for (const hostile of [
      "blob:https://app.example.com/0d5a-1",
      "filesystem:https://app.example.com/temporary/x",
      "view-source:https://app.example.com/x",
    ]) {
      expect(() => assertSafeReturnTo(hostile, withOrigins)).toThrow(
        OidcReturnToError,
      );
    }
  });

  test("refuses credentials embedded in an otherwise allowed target", () => {
    expect(() =>
      assertSafeReturnTo("https://user:pw@app.example.com/x", withOrigins),
    ).toThrow(OidcReturnToError);
    expect(() =>
      assertSafeReturnTo("https://user@app.example.com/x", withOrigins),
    ).toThrow(OidcReturnToError);
  });
});

describe("buildReturnToPolicy", () => {
  test("normalizes entries to bare origins", () => {
    expect(
      buildReturnToPolicy({
        allowedReturnToOrigins: ["https://app.example.com/ignored/path"],
      }).allowedOrigins,
    ).toEqual(["https://app.example.com"]);
  });

  test("refuses configuration it could never compare against", () => {
    expect(() =>
      buildReturnToPolicy({ allowedReturnToOrigins: ["app.example.com"] }),
    ).toThrow(TypeError);
    expect(() =>
      buildReturnToPolicy({ allowedReturnToOrigins: ["data:text/html,x"] }),
    ).toThrow(TypeError);
  });
});

describe("assertSafeRedirectUri", () => {
  test("passes the ordinary registered callback and logout URIs", () => {
    for (const uri of [
      "https://app.example.com/callback",
      "https://app.example.com/logged-out?from=logout",
      "http://localhost:3000/callback",
    ]) {
      expect(assertSafeRedirectUri(uri, "redirectUri")).toBe(uri);
    }
  });

  test("refuses a scheme a browser must never be redirected to", () => {
    for (const uri of [
      "javascript:alert(1)",
      "data:text/html,<script>alert(1)</script>",
      "file:///etc/passwd",
    ]) {
      expect(() => assertSafeRedirectUri(uri, "redirectUri")).toThrow(
        OidcReturnToError,
      );
    }
  });

  test("refuses embedded credentials, which disguise the real origin", () => {
    expect(() =>
      assertSafeRedirectUri(
        "https://app.example.com@evil.example/callback",
        "postLogoutRedirectUri",
      ),
    ).toThrow(OidcReturnToError);
  });

  test("refuses relative values and header-splitting shapes", () => {
    for (const uri of [
      "/callback",
      "",
      "https://app.example.com/call\nback",
      "https://app.example.com/call back",
    ]) {
      expect(() => assertSafeRedirectUri(uri, "redirectUri")).toThrow(
        OidcReturnToError,
      );
    }
  });
});
