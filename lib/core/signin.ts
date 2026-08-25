import {
  authorizationCodeGrant,
  buildAuthorizationUrl,
  calculatePKCECodeChallenge,
  randomNonce,
  randomPKCECodeVerifier,
  randomState,
} from "openid-client";
import {
  OidcGrantError,
  OidcInputError,
  type RefreshedTokenSet,
} from "../errors";
import { assertSafeRedirectUri, assertSafeReturnTo } from "../returnTo";
import { parseOIDCFlowState } from "../types";
import type { CoreContext } from "./context";
import { assertGrantedIdToken } from "./grant";
import type { ResolveSigninResult, StartSigninResult } from "./options";

/** The PKCE authorization-code flow. */
export function createSignin(ctx: CoreContext) {
  async function startSignin({
    redirectUri,
    returnTo,
    scope = "openid profile email",
  }: {
    /** This app's own OAuth callback endpoint. */
    redirectUri: string;
    /**
     * Where to send the user after a successful login: a same-site path
     * such as `"/dashboard"`, or an absolute URL on an origin listed in
     * {@link OidcCoreOptions.allowedReturnToOrigins}.
     */
    returnTo: string;
    /**
     * Space-separated OAuth scopes to request. Defaults to
     * `"openid profile email"` and must include `openid`.
     */
    scope?: string;
  }): Promise<StartSigninResult> {
    assertSafeReturnTo(returnTo, ctx.returnToPolicy);
    assertSafeRedirectUri(redirectUri, "redirectUri");

    if (!scope.split(/\s+/).includes("openid")) {
      throw new OidcInputError(
        `invalid scope ("${scope}"): it must include "openid"`,
      );
    }

    const codeVerifier = randomPKCECodeVerifier();
    const codeChallenge = await calculatePKCECodeChallenge(codeVerifier);
    const nonce = randomNonce();
    const state = JSON.stringify({
      visitedUrl: returnTo,
      random: randomState(),
      nonce,
    });

    const authorizationUrl = buildAuthorizationUrl(ctx.config, {
      redirect_uri: redirectUri,
      scope,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state,
      nonce,
    });

    return { codeVerifier, authorizationUrl, state };
  }

  async function resolveSignin({
    callbackUrl,
    codeVerifier,
    expectedState,
  }: {
    /** The full callback URL the IdP redirected to, including its query string. */
    callbackUrl: URL;
    /** The `codeVerifier` `startSignin` returned, stored and handed back unmodified. */
    codeVerifier: string;
    /** The `state` `startSignin` returned, stored and handed back unmodified. */
    expectedState: string;
  }): Promise<ResolveSigninResult> {
    if (typeof codeVerifier !== "string" || codeVerifier.length === 0) {
      throw new OidcInputError(
        "resolveSignin was given no PKCE code verifier. Pass the `codeVerifier` startSignin returned, exactly as it was stored.",
      );
    }
    const parsedState = parseOIDCFlowState(expectedState);
    const returnTo = assertSafeReturnTo(
      parsedState.visitedUrl,
      ctx.returnToPolicy,
    );

    let tokens: RefreshedTokenSet;
    try {
      tokens = await authorizationCodeGrant(ctx.config, callbackUrl, {
        pkceCodeVerifier: codeVerifier,
        expectedState,
        expectedNonce: parsedState.nonce,
        idTokenExpected: true,
      });
    } catch (err) {
      throw new OidcGrantError(
        "authorization_code",
        `could not complete the login: ${err instanceof Error ? err.message : String(err)}`,
        { cause: err },
      );
    }
    assertGrantedIdToken(ctx, tokens);
    return { tokens, returnTo };
  }

  return { startSignin, resolveSignin };
}
