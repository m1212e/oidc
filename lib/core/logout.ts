import { buildEndSessionUrl } from "openid-client";
import { OidcLogoutError } from "../errors";
import { assertSafeRedirectUri } from "../returnTo";
import type { CoreContext } from "./context";

export function createLogout(ctx: CoreContext) {
  /**
   * Builds the provider's RP-initiated logout URL.
   * @example const url = await oidc.getLogoutUrl({ postLogoutRedirectUri: "https://app.example.com/", idTokenHint: id_token });
   */
  return async function getLogoutUrl({
    postLogoutRedirectUri,
    idTokenHint,
    state,
  }: {
    postLogoutRedirectUri: string;
    idTokenHint?: string;
    state?: string;
  }): Promise<URL> {
    assertSafeRedirectUri(postLogoutRedirectUri, "postLogoutRedirectUri");
    try {
      return buildEndSessionUrl(ctx.config, {
        post_logout_redirect_uri: postLogoutRedirectUri,
        ...(idTokenHint ? { id_token_hint: idTokenHint } : {}),
        ...(state ? { state } : {}),
      });
    } catch (err) {
      throw new OidcLogoutError(
        `could not build a logout URL for ${ctx.issuer}: ${
          err instanceof Error ? err.message : String(err)
        }. If the issuer advertises no "end_session_endpoint" it does not support RP-initiated logout, so you need its own logout URL instead. Destroying your session locally is all this library can do for you.`,
        { cause: err },
      );
    }
  };
}
