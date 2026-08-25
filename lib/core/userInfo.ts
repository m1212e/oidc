import { fetchUserInfo } from "openid-client";
import { OidcUserInfoError } from "../errors";
import type { CoreContext } from "./context";

/**
 * Fetches claims from the issuer's UserInfo endpoint. `expectedSubject`
 * should be the `sub` you already validated this access token for. The
 * response is checked against it.
 */
export function createUserInfoFetcher(ctx: CoreContext) {
  return async function fetchUserInfoFromIssuer({
    accessToken,
    expectedSubject,
  }: {
    accessToken: string;
    expectedSubject: string;
  }) {
    if (typeof expectedSubject !== "string" || !expectedSubject) {
      throw new TypeError(
        "fetchUserInfoFromIssuer needs the `sub` this token set was validated for, as a non-empty string — the response is only meaningful once it is known to describe that subject",
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
