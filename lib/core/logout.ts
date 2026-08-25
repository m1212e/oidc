import { buildEndSessionUrl } from "openid-client";
import { assertSafeRedirectUri } from "../returnTo";
import type { CoreContext } from "./context";

/**
 * Builds an RP-initiated logout URL. Redirect the user to it to end their
 * session at the IdP.
 *
 * `postLogoutRedirectUri` must be an absolute http(s) URL, registered with
 * your provider. Pass `idTokenHint` when you still have the id token.
 * Some providers otherwise show a confirmation page instead of logging out
 * directly.
 */
export function createLogout(ctx: CoreContext) {
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
    return buildEndSessionUrl(ctx.config, {
      post_logout_redirect_uri: postLogoutRedirectUri,
      ...(idTokenHint ? { id_token_hint: idTokenHint } : {}),
      ...(state ? { state } : {}),
    });
  };
}
