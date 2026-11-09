import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createOidcCore, type OidcCore } from "../../lib/core";
import { OidcInputError } from "../../lib/errors";
import {
  startTestOidcProvider,
  type TestOidcProvider,
} from "./testOidcProvider";

let idp: TestOidcProvider;
let core: OidcCore;

beforeAll(async () => {
  idp = await startTestOidcProvider();
  core = await createOidcCore({
    issuer: idp.issuer,
    clientId: idp.clientId,
    development: true,
  });
});

afterAll(async () => {
  await idp.close();
});

const signin = (uiLocales?: string | readonly string[]) =>
  core.startSignin({ redirectUri: idp.redirectUri, returnTo: "/", uiLocales });
const logout = (uiLocales?: string | readonly string[]) =>
  core.getLogoutUrl({
    postLogoutRedirectUri: idp.postLogoutRedirectUri,
    uiLocales,
  });

describe("uiLocales", () => {
  test("is left out unless given", async () => {
    expect(
      (await signin()).authorizationUrl.searchParams.has("ui_locales"),
    ).toBe(false);
    expect((await logout()).searchParams.has("ui_locales")).toBe(false);
  });

  test("a single tag is sent as ui_locales on sign-in and logout", async () => {
    expect(
      (await signin("de")).authorizationUrl.searchParams.get("ui_locales"),
    ).toBe("de");
    expect((await logout("de-DE")).searchParams.get("ui_locales")).toBe(
      "de-DE",
    );
  });

  test("a list is sent space separated, most preferred first", async () => {
    expect(
      (await signin(["de-DE", "de", "en"])).authorizationUrl.searchParams.get(
        "ui_locales",
      ),
    ).toBe("de-DE de en");
    expect((await logout("de   en")).searchParams.get("ui_locales")).toBe(
      "de en",
    );
  });

  test("a rejected value never reaches the url", async () => {
    for (const bad of ["", "  ", [], ["de en"], ["de", ""], "de_DE", "d e!"]) {
      await expect(signin(bad)).rejects.toThrow(OidcInputError);
      await expect(logout(bad)).rejects.toThrow(OidcInputError);
    }
  });
});
