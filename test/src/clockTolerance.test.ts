import { describe, expect, test } from "bun:test";
import { resolveClockTolerance } from "../../lib/core";

describe("resolveClockTolerance", () => {
  test("defaults to 30 seconds", () => {
    expect(resolveClockTolerance()).toBe(30);
    expect(resolveClockTolerance(undefined)).toBe(30);
  });

  test("passes a number of seconds through", () => {
    expect(resolveClockTolerance(0)).toBe(0);
    expect(resolveClockTolerance(120)).toBe(120);
  });

  test("parses jose's duration grammar into seconds", () => {
    expect(resolveClockTolerance("30 seconds")).toBe(30);
    expect(resolveClockTolerance("30s")).toBe(30);
    expect(resolveClockTolerance("5m")).toBe(300);
    expect(resolveClockTolerance("5 minutes")).toBe(300);
    expect(resolveClockTolerance("2 hrs")).toBe(7200);
    expect(resolveClockTolerance("1 day")).toBe(86400);
    expect(resolveClockTolerance("1.5m")).toBe(90);
  });

  test("rejects what openid-client could not accept anyway", () => {
    expect(() => resolveClockTolerance(-1)).toThrow(TypeError);
    expect(() => resolveClockTolerance(Number.NaN)).toThrow(TypeError);
    expect(() => resolveClockTolerance(Number.POSITIVE_INFINITY)).toThrow(
      TypeError,
    );
    // Signed and relative forms are jose-valid but meaningless as a tolerance.
    expect(() => resolveClockTolerance("-30 seconds")).toThrow(TypeError);
    expect(() => resolveClockTolerance("30 seconds ago")).toThrow(TypeError);
    expect(() => resolveClockTolerance("soon")).toThrow(TypeError);
  });
});
