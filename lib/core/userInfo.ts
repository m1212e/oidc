import { fetchUserInfo } from "openid-client";
import { OidcInputError, OidcUserInfoError } from "../errors";
import type { CoreContext } from "./context";

export function createUserInfoFetcher(ctx: CoreContext) {
  /**
   * Fetches the UserInfo endpoint, checking the response is for `expectedSubject`.
   * @example const info = await oidc.fetchUserInfoFromIssuer({ accessToken, expectedSubject: user.sub });
   */
  return async function fetchUserInfoFromIssuer({
    accessToken,
    expectedSubject,
  }: {
    accessToken: string;
    expectedSubject: string;
  }) {
    if (typeof expectedSubject !== "string" || !expectedSubject) {
      throw new OidcInputError(
        "fetchUserInfoFromIssuer needs the `sub` this token set was validated for, as a non-empty string. The response is only meaningful once it is known to describe that subject",
      );
    }
    try {
      return await fetchUserInfo(ctx.config, accessToken, expectedSubject);
    } catch (err) {
      throw new OidcUserInfoError(
        `could not fetch UserInfo claims for subject ${expectedSubject}: ${
          err instanceof Error ? err.message : String(err)
        }`,
        { cause: err },
      );
    }
  };
}
