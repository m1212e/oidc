import { refreshTokenGrant } from "openid-client";
import {
  OidcGrantError,
  OidcInputError,
  OidcSubjectError,
  type RefreshedTokenSet,
} from "../errors";
import { subjectOf } from "../tokenValidation";
import type { CoreContext } from "./context";
import { assertGrantedIdToken } from "./grant";

export function createRefresh(ctx: CoreContext) {
  /**
   * Exchanges a refresh token for a new token set.
   * @example const tokens = await oidc.refresh({ refreshToken, expectedSubject: user.sub });
   */
  return async function refresh({
    refreshToken,
    expectedSubject,
  }: {
    refreshToken: string;
    expectedSubject?: string;
  }): Promise<RefreshedTokenSet> {
    if (
      expectedSubject !== undefined &&
      (typeof expectedSubject !== "string" || !expectedSubject)
    ) {
      throw new OidcInputError(
        "refresh was given an `expectedSubject` that is not a non-empty string",
      );
    }

    let tokens: RefreshedTokenSet;
    try {
      tokens = await refreshTokenGrant(ctx.config, refreshToken);
    } catch (err) {
      throw new OidcGrantError(
        "refresh_token",
        `could not exchange the refresh token: ${err instanceof Error ? err.message : String(err)}`,
        { cause: err },
      );
    }
    assertGrantedIdToken(ctx, tokens);

    if (expectedSubject) {
      const actual = subjectOf(tokens.claims());
      if (!actual) {
        ctx.log.warn(
          "[oidc] refresh could not be checked against the expected subject: the provider returned no id token to read one from. The new token set is returned unchecked.",
        );
      } else if (actual !== expectedSubject) {
        throw new OidcSubjectError(
          `refresh returned a token set for a different subject (${actual}) than the ${expectedSubject} it was asked for. The refresh token does not belong to this session`,
          expectedSubject,
          actual,
        );
      }
    }

    return tokens;
  };
}
