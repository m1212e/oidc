import { buildEndSessionUrl } from "openid-client";
import { OidcLogoutError } from "../errors";
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
 *
 * Throws {@link OidcLogoutError} if the issuer advertises no
 * `end_session_endpoint`, since there is then no URL to build.
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
