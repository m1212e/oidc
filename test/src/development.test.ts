import { afterEach, describe, expect, test } from "bun:test";
import { resolveDevelopment } from "../../lib/core";

const original = process.env.NODE_ENV;

afterEach(() => {
  if (original === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = original;
});

describe("resolveDevelopment", () => {
  test("an explicit value wins over the environment", () => {
    process.env.NODE_ENV = "production";
    expect(resolveDevelopment(true)).toBe(true);
    process.env.NODE_ENV = "development";
    expect(resolveDevelopment(false)).toBe(false);
  });

  test("derives from NODE_ENV=development when unset", () => {
    process.env.NODE_ENV = "development";
    expect(resolveDevelopment()).toBe(true);
    expect(resolveDevelopment(undefined)).toBe(true);
  });

  test("fails closed for production, test, and an absent NODE_ENV", () => {
    process.env.NODE_ENV = "production";
    expect(resolveDevelopment()).toBe(false);
    process.env.NODE_ENV = "test";
    expect(resolveDevelopment()).toBe(false);
    process.env.NODE_ENV = "";
    expect(resolveDevelopment()).toBe(false);
    delete process.env.NODE_ENV;
    expect(resolveDevelopment()).toBe(false);
  });
});
