/**
 * Regression tests for the substitutions and state-handling faults that the
 * validation chain used to let through. Each one is driven against the real
 * provider, so the token being substituted is a token the provider actually
 * issued rather than a hand-rolled approximation.
 */

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createOidcCore, type OidcCore } from "../../lib/core";
import {
  OidcError,
  OidcGrantError,
  OidcSubjectError,
  OidcTokenValidationError,
  OidcUserInfoError,
} from "../../lib/errors";
import { OidcReturnToError } from "../../lib/returnTo";
import { OidcTokenTypeError } from "../../lib/tokenType";
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

async function login(accountId: string, scope?: string) {
  const { codeVerifier, authorizationUrl, state } = await core.startSignin({
    redirectUri: idp.redirectUri,
    returnTo: "/dashboard",
    scope,
  });
  if (scope?.includes("offline_access")) {
    authorizationUrl.searchParams.set("prompt", "consent");
  }
  const callbackUrl = await idp.runAuthorizationFlow(
    authorizationUrl,
    accountId,
  );
  return core.resolveSignin({
    callbackUrl,
    codeVerifier,
    expectedState: state,
  });
}

const OFFLINE = "openid profile email offline_access";

describe("refresh tokens are not access tokens", () => {
  test("refuses a real refresh token presented in the access_token slot", async () => {
    const { tokens } = await login("user-rt-substitution", OFFLINE);
    const refreshToken = tokens.refresh_token as string;
    expect(refreshToken).toBeTruthy();

    // Opaque, so it reaches introspection — where `active: true`, this
    // client's `client_id` and the user's `sub` all check out. Only the
    // absence of an affirmative token type gives it away, and without that
    // check a 14-day credential would pass as a 1-hour one.
    const err = (await core
      .processTokens({ access_token: refreshToken })
      .catch((e: unknown) => e)) as OidcTokenTypeError;

    expect(err).toBeInstanceOf(OidcTokenTypeError);
    expect(err.tokenKind).toBe("access");
    expect(err.claim).toBe("token_type");
  });

  test("the token-type requirement is what rejects it, and can be waived", async () => {
    const { tokens } = await login("user-rt-waived", OFFLINE);
    const lax = await createOidcCore({
      issuer: idp.issuer,
      clientId: idp.clientId,
      development: true,
      requireIntrospectedTokenType: false,
    });

    // Pinning the escape hatch's cost: with the requirement off, the very same
    // refresh token is accepted. Anyone setting this must know that.
    const result = await lax.processTokens({
      access_token: tokens.refresh_token as string,
    });
    expect(result.user.sub).toBe("user-rt-waived");
  });

  test("accepts a genuine opaque access token, so the check is not blanket", async () => {
    const { tokens } = await login("user-at-ok");
    const result = await core.processTokens({
      access_token: tokens.access_token,
    });
    expect(result.user.sub).toBe("user-at-ok");
  });
});

describe("token-type claims that name the kind", () => {
  test("refuses a Keycloak-shaped refresh token in the access slot", async () => {
    // Keycloak signs refresh tokens with the same key as everything else and
    // names the kind in a payload `typ` claim — the JWS header just says
    // "JWT", so pinning the header cannot catch this one.
    const refreshShaped = await idp.sign({
      sub: "user-typ-refresh",
      azp: idp.clientId,
      typ: "Refresh",
    });

    const err = (await core
      .processTokens({ access_token: refreshShaped })
      .catch((e: unknown) => e)) as OidcTokenTypeError;
    expect(err).toBeInstanceOf(OidcTokenTypeError);
    expect(err.claim).toBe("typ");
  });

  test("refuses a Keycloak-shaped ID token in the access slot", async () => {
    // No nonce, no at_hash — the previously documented gap. The `typ` claim
    // closes it wherever the provider sets one.
    const idShaped = await idp.sign({
      sub: "user-typ-id",
      azp: idp.clientId,
      typ: "ID",
    });

    const err = (await core
      .processTokens({ access_token: idShaped })
      .catch((e: unknown) => e)) as OidcTokenTypeError;
    expect(err).toBeInstanceOf(OidcTokenTypeError);
    expect(err.claim).toBe("typ");
  });

  test("refuses a Keycloak-shaped access token in the id slot", async () => {
    const accessShaped = await idp.sign({
      sub: "user-typ-swap",
      azp: idp.clientId,
      typ: "Bearer",
    });

    const err = (await core
      .processTokens({ id_token: accessShaped })
      .catch((e: unknown) => e)) as OidcTokenTypeError;
    expect(err).toBeInstanceOf(OidcTokenTypeError);
    expect(err.tokenKind).toBe("id");
    expect(err.claim).toBe("typ");
  });

  test("ignores a typ claim that names nothing it knows", async () => {
    // Providers put their own vocabulary here; an unrecognized value is not
    // evidence either way and must not become a rejection.
    const token = await idp.sign({
      sub: "user-typ-unknown",
      azp: idp.clientId,
      typ: "JWT",
    });
    const result = await core.processTokens({ access_token: token });
    expect(result.user.sub).toBe("user-typ-unknown");
  });
});

describe("a spent refresh token is never lost", () => {
  /**
   * Forces the shape the fix exists for: the supplied token cannot validate,
   * so the refresh token is spent, and the *replacement* is then rejected too
   * (its `aud` cannot match a resource audience this provider knows nothing
   * about). The old refresh token is dead either way — the question is only
   * whether the caller is handed what replaced it.
   */
  async function spendThenFail() {
    const strict = await createOidcCore({
      issuer: idp.issuer,
      clientId: idp.clientId,
      development: true,
      expectedAudience: "api://not-this-provider",
    });
    const { tokens } = await login("user-refresh-rescue", OFFLINE);
    const forged = await idp.sign(
      { sub: "user-refresh-rescue", azp: idp.clientId },
      { badKid: true },
    );
    const err = (await strict
      .processTokens({
        access_token: forged,
        refresh_token: tokens.refresh_token as string,
      })
      .catch((e: unknown) => e)) as OidcError;
    return { err, originalRefreshToken: tokens.refresh_token as string };
  }

  test("hands the new token set back on the error that rejected it", async () => {
    const { err, originalRefreshToken } = await spendThenFail();

    expect(err).toBeInstanceOf(OidcError);
    expect(err.refreshedTokens).toBeDefined();
    expect(err.refreshedTokens?.access_token).toBeTruthy();
    expect(err.refreshedTokens?.refresh_token).toBeTruthy();
    // It is genuinely the replacement, not an echo of what was passed in.
    expect(err.refreshedTokens?.refresh_token).not.toBe(originalRefreshToken);
  });

  test("and the token it replaced really is gone, which is why that matters", async () => {
    const { originalRefreshToken } = await spendThenFail();
    // Rotation already happened inside the failed call, so without the set
    // above the session would be unrecoverable.
    await expect(
      core.refresh({ refreshToken: originalRefreshToken }),
    ).rejects.toThrow();
  });

  test("carries nothing when no refresh was attempted", async () => {
    const forged = await idp.sign({ sub: "user-no-refresh" }, { badKid: true });
    const err = (await core
      .processTokens({ id_token: forged })
      .catch((e: unknown) => e)) as OidcError;
    expect(err).toBeInstanceOf(OidcTokenValidationError);
    expect(err.refreshedTokens).toBeUndefined();
  });
});

describe("a refresh cannot change who is signed in", () => {
  test("refuses a refresh token belonging to another subject", async () => {
    const attacker = await login("user-swap-attacker", OFFLINE);
    // The victim's token cannot be verified, so the chain reaches for the
    // refresh token beside it — which belongs to somebody else entirely. The
    // resulting token set is perfectly valid; it is just not this session's.
    const victimToken = await idp.sign(
      { sub: "user-swap-victim" },
      { badKid: true },
    );

    const err = (await core
      .processTokens({
        id_token: victimToken,
        refresh_token: attacker.tokens.refresh_token as string,
      })
      .catch((e: unknown) => e)) as OidcSubjectError;

    expect(err).toBeInstanceOf(OidcSubjectError);
    expect(err.expected).toBe("user-swap-victim");
    expect(err.actual).toBe("user-swap-attacker");
    // The set belongs to the other subject, so it is explicitly not offered
    // for the caller to persist.
    expect(err.refreshedTokens).toBeUndefined();
  });

  test("still allows a refresh that returns the same subject", async () => {
    const { tokens } = await login("user-swap-ok", OFFLINE);
    const expired = await idp.sign({ sub: "user-swap-ok" }, { expired: true });

    const result = await core.processTokens({
      id_token: expired,
      refresh_token: tokens.refresh_token as string,
    });
    expect(result.refreshed).toBe(true);
    expect(result.user.sub).toBe("user-swap-ok");
  });

  test("reports mismatched access and id tokens as an OidcError", async () => {
    const { tokens: a } = await login("user-mismatch-a");
    const { tokens: b } = await login("user-mismatch-b");

    const err = (await core
      .processTokens({ access_token: a.access_token, id_token: b.id_token })
      .catch((e: unknown) => e)) as OidcSubjectError;
    expect(err).toBeInstanceOf(OidcSubjectError);
    expect(err).toBeInstanceOf(OidcError);
  });
});

describe("returnTo through the real flow", () => {
  test("refuses an off-site target before the browser ever sees it", async () => {
    await expect(
      core.startSignin({
        redirectUri: idp.redirectUri,
        returnTo: "https://evil.example.com/phish",
      }),
    ).rejects.toThrow(OidcReturnToError);
    await expect(
      core.startSignin({
        redirectUri: idp.redirectUri,
        returnTo: "//evil.example.com",
      }),
    ).rejects.toThrow(OidcReturnToError);
  });

  test("refuses one that arrives back inside a hand-made state", async () => {
    // A state this library never minted — an older release, another process,
    // or a caller that built one itself. The value is about to be redirected
    // to, so the callback re-checks rather than trusting the round trip.
    const hostileState = JSON.stringify({
      visitedUrl: "https://evil.example.com/phish",
      random: "r",
    });
    const { codeVerifier, authorizationUrl } = await core.startSignin({
      redirectUri: idp.redirectUri,
      returnTo: "/ignored",
    });
    authorizationUrl.searchParams.set("state", hostileState);
    authorizationUrl.searchParams.delete("nonce");
    const callbackUrl = await idp.runAuthorizationFlow(
      authorizationUrl,
      "user-hostile-state",
    );

    await expect(
      core.resolveSignin({
        callbackUrl,
        codeVerifier,
        expectedState: hostileState,
      }),
    ).rejects.toThrow(OidcReturnToError);
  });

  test("allows an absolute target once its origin is configured", async () => {
    const cross = await createOidcCore({
      issuer: idp.issuer,
      clientId: idp.clientId,
      development: true,
      allowedReturnToOrigins: ["https://app.example.com"],
    });
    const started = await cross.startSignin({
      redirectUri: idp.redirectUri,
      returnTo: "https://app.example.com/dashboard",
    });
    const callbackUrl = await idp.runAuthorizationFlow(
      started.authorizationUrl,
      "user-cross-origin",
    );
    const { returnTo } = await cross.resolveSignin({
      callbackUrl,
      codeVerifier: started.codeVerifier,
      expectedState: started.state,
    });
    expect(returnTo).toBe("https://app.example.com/dashboard");
  });
});

describe("logout", () => {
  test("passes an id_token_hint so the OP knows which session to end", async () => {
    const { tokens } = await login("user-logout");
    const url = await core.getLogoutUrl({
      postLogoutRedirectUri: idp.postLogoutRedirectUri,
      idTokenHint: tokens.id_token as string,
      state: "back-to-home",
    });

    expect(url.searchParams.get("id_token_hint")).toBe(
      tokens.id_token as string,
    );
    expect(url.searchParams.get("state")).toBe("back-to-home");
    expect(url.searchParams.get("post_logout_redirect_uri")).toBe(
      idp.postLogoutRedirectUri,
    );
    // Still added by openid-client, which is what keeps the redirect honoured
    // when no hint is available.
    expect(url.searchParams.get("client_id")).toBe(idp.clientId);
  });

  test("still works with no hint at all", async () => {
    const url = await core.getLogoutUrl({
      postLogoutRedirectUri: idp.postLogoutRedirectUri,
    });
    expect(url.searchParams.has("id_token_hint")).toBe(false);
    expect(url.searchParams.get("post_logout_redirect_uri")).toBe(
      idp.postLogoutRedirectUri,
    );
  });
});

describe("user claims", () => {
  test("surfaces email_verified alongside email", async () => {
    const token = await idp.sign({
      sub: "user-claims",
      email: "USER-Claims@Example.COM",
      email_verified: true,
      phone_number: "+49 30 123",
    });
    const { user } = await core.processTokens({ id_token: token });

    expect(user.email).toBe("user-claims@example.com");
    expect(user.email_verified).toBe(true);
    expect(user.phone_number).toBe("+49 30 123");
  });

  test("does not invent verification the issuer never claimed", async () => {
    const token = await idp.sign({
      sub: "user-claims-unverified",
      email: "u@example.com",
    });
    const { user } = await core.processTokens({ id_token: token });
    expect(user.email).toBe("u@example.com");
    expect(user.email_verified).toBeUndefined();
  });
});

describe("the id_token slot is not a way in either", () => {
  test("refuses a real refresh token presented as an id token", async () => {
    const { tokens } = await login("user-rt-in-id-slot", OFFLINE);
    // The mirror of the access-token case above, and it used to be the way
    // round the whole check: the id slot ran the audience policy but no
    // token-type check at all, so a 14-day credential authenticated a request.
    const err = (await core
      .processTokens({ id_token: tokens.refresh_token as string })
      .catch((e: unknown) => e)) as OidcTokenTypeError;

    expect(err).toBeInstanceOf(OidcTokenTypeError);
    expect(err.tokenKind).toBe("id");
    expect(err.claim).toBe("token_type");
  });

  test("refuses a real access token presented as an id token", async () => {
    const { tokens } = await login("user-at-in-id-slot");
    const err = (await core
      .processTokens({ id_token: tokens.access_token })
      .catch((e: unknown) => e)) as OidcTokenTypeError;

    expect(err).toBeInstanceOf(OidcTokenTypeError);
    expect(err.tokenKind).toBe("id");
    // `token_type: "Bearer"` names the kind outright, so the claim rules catch
    // this one before the affirmative-naming requirement has to.
    expect(err.claim).toBe("token_type");
  });

  test("accepts a genuine id token, so the check is not blanket", async () => {
    const { tokens } = await login("user-id-ok");
    const result = await core.processTokens({
      id_token: tokens.id_token as string,
    });
    expect(result.user.sub).toBe("user-id-ok");
  });
});

describe("introspection stays within the configured mode", () => {
  test("does not introspect a failed JWT id token beside an opaque access token", async () => {
    const { tokens } = await login("user-mode-mix");
    // A JWT the issuer's own JWKS rejected. Under "opaque-only" it must not be
    // introspected — but the id slot used to skip the mode check entirely, so
    // an introspectable access token beside it was enough to send this to the
    // AS anyway, which is the amplification the mode exists to prevent.
    const forgedId = await idp.sign(
      { sub: "user-mode-mix", azp: idp.clientId },
      { badKid: true },
    );

    const before = idp.calls.introspection;
    await core
      .processTokens({
        access_token: tokens.access_token,
        id_token: forgedId,
      })
      .catch(() => undefined);

    // Exactly one: the opaque access token, and nothing for the id token.
    expect(idp.calls.introspection).toBe(before + 1);
  });
});

describe("the subject binding holds for opaque tokens too", () => {
  test("a declared subject catches a foreign refresh token", async () => {
    const attacker = await login("user-opaque-attacker", OFFLINE);
    // Neither supplied token can be read: an opaque string that no longer
    // introspects names no subject, which is the ordinary expiry case for a
    // provider issuing opaque access tokens. Inference has nothing to work
    // with, so the caller's own record of who this session belongs to is what
    // makes the check possible.
    const err = (await core
      .processTokens({
        access_token: "opaque-and-no-longer-active-0123456789",
        refresh_token: attacker.tokens.refresh_token as string,
        subject: "user-opaque-victim",
      })
      .catch((e: unknown) => e)) as OidcSubjectError;

    expect(err).toBeInstanceOf(OidcSubjectError);
    expect(err.expected).toBe("user-opaque-victim");
    expect(err.actual).toBe("user-opaque-attacker");
    // Never handed back: a set minted for somebody else is not the caller's
    // to store.
    expect(err.refreshedTokens).toBeUndefined();
  });

  test("a declared subject is checked without any refresh happening", async () => {
    const { tokens } = await login("user-declared-mismatch");
    const err = (await core
      .processTokens({
        id_token: tokens.id_token as string,
        subject: "somebody-else",
      })
      .catch((e: unknown) => e)) as OidcSubjectError;

    expect(err).toBeInstanceOf(OidcSubjectError);
    expect(err.expected).toBe("somebody-else");
    expect(err.actual).toBe("user-declared-mismatch");
  });

  test("agrees with the tokens when it is the right subject", async () => {
    const { tokens } = await login("user-declared-ok");
    const result = await core.processTokens({
      id_token: tokens.id_token as string,
      subject: "user-declared-ok",
    });
    expect(result.user.sub).toBe("user-declared-ok");
  });

  test("warns when a refresh could not be checked against anything", async () => {
    const warnings: string[] = [];
    const quiet = await createOidcCore({
      issuer: idp.issuer,
      clientId: idp.clientId,
      development: true,
      logger: {
        debug: () => {},
        info: () => {},
        warn: (...args: unknown[]) => warnings.push(args.join(" ")),
        error: () => {},
      },
    });
    const { tokens } = await login("user-unbindable", OFFLINE);

    // Same shape as above but with no `subject` to compare against: the call
    // succeeds, and says out loud that the guarantee could not be enforced.
    const result = await quiet.processTokens({
      access_token: "opaque-and-no-longer-active-9876543210",
      refresh_token: tokens.refresh_token as string,
    });

    expect(result.refreshed).toBe(true);
    expect(warnings.join(" ")).toContain(
      "original subject could not be determined",
    );
  });
});

describe("token-endpoint failures stay inside the error hierarchy", () => {
  test("an unusable refresh token is an OidcError, not a provider error", async () => {
    const expired = await idp.sign(
      { sub: "user-dead-refresh", azp: idp.clientId },
      { expired: true },
    );
    // The most common failure a live session meets. Escaping as
    // `openid-client`'s own error meant a caller catching OidcError to answer
    // 401 answered 500 to a user who only needed to log in again.
    const err = (await core
      .processTokens({
        id_token: expired,
        refresh_token: "not-a-refresh-token-at-all",
      })
      .catch((e: unknown) => e)) as OidcGrantError;

    expect(err).toBeInstanceOf(OidcError);
    expect(err).toBeInstanceOf(OidcGrantError);
    expect(err.grant).toBe("refresh_token");
    // The provider's own diagnosis is not thrown away.
    expect(err.cause).toBeDefined();
  });

  test("the same for a direct refresh call", async () => {
    const err = (await core
      .refresh({ refreshToken: "not-a-refresh-token-at-all" })
      .catch((e: unknown) => e)) as OidcGrantError;
    expect(err).toBeInstanceOf(OidcGrantError);
    expect(err.grant).toBe("refresh_token");
  });
});

describe("redirect URIs handed to the provider", () => {
  test("refuses a post-logout redirect that is not http(s)", async () => {
    await expect(
      core.getLogoutUrl({
        postLogoutRedirectUri: "javascript:alert(document.domain)",
      }),
    ).rejects.toBeInstanceOf(OidcReturnToError);
  });

  test("refuses a post-logout redirect that disguises its origin", async () => {
    await expect(
      core.getLogoutUrl({
        postLogoutRedirectUri: "https://app.example.com@evil.example/goodbye",
      }),
    ).rejects.toBeInstanceOf(OidcReturnToError);
  });

  test("still builds the ordinary logout URL", async () => {
    const url = await core.getLogoutUrl({
      postLogoutRedirectUri: idp.postLogoutRedirectUri,
    });
    expect(url.searchParams.get("post_logout_redirect_uri")).toBe(
      idp.postLogoutRedirectUri,
    );
  });

  test("refuses a callback URI that is not http(s)", async () => {
    await expect(
      core.startSignin({
        redirectUri: "javascript:alert(1)",
        returnTo: "/dashboard",
      }),
    ).rejects.toBeInstanceOf(OidcReturnToError);
  });
});

describe("a verification flag never vouches for the other token's value", () => {
  /**
   * The realistic shape: a long-lived session whose access token still carries
   * the address the issuer verified, beside a newer id token naming the address
   * the user has just changed to and has *not* verified. Both tokens are
   * genuine, both name the same subject, and both pass every audience and
   * type check — they simply describe different moments. A per-claim merge
   * hands the new address back marked as verified, which is the account
   * takeover the flag exists to prevent.
   */
  test("drops a flag whose value came from the other token", async () => {
    const access = await idp.sign({
      sub: "vouch-user",
      email: "old-verified@corp.example",
      email_verified: true,
      azp: idp.clientId,
    });
    const id = await idp.sign({
      sub: "vouch-user",
      email: "just-changed@corp.example",
      nonce: "n",
      azp: idp.clientId,
    });

    const result = await core.processTokens({
      access_token: access,
      id_token: id,
    });

    expect(result.user.email).toBe("just-changed@corp.example");
    expect(result.user.email_verified).toBeUndefined();
  });

  test("keeps a flag that arrived beside its own value", async () => {
    const access = await idp.sign({
      sub: "vouch-user-2",
      email: "stale@corp.example",
      email_verified: true,
      azp: idp.clientId,
    });
    const id = await idp.sign({
      sub: "vouch-user-2",
      email: "current@corp.example",
      email_verified: true,
      nonce: "n",
      azp: idp.clientId,
    });

    const result = await core.processTokens({
      access_token: access,
      id_token: id,
    });

    expect(result.user.email).toBe("current@corp.example");
    expect(result.user.email_verified).toBe(true);
  });

  test("takes the access token's pair when the id token says nothing", async () => {
    const access = await idp.sign({
      sub: "vouch-user-3",
      email: "only-here@corp.example",
      email_verified: true,
      azp: idp.clientId,
    });
    const id = await idp.sign({
      sub: "vouch-user-3",
      nonce: "n",
      azp: idp.clientId,
    });

    const result = await core.processTokens({
      access_token: access,
      id_token: id,
    });

    expect(result.user.email).toBe("only-here@corp.example");
    expect(result.user.email_verified).toBe(true);
  });

  test("drops a flag that vouches for no address at all", async () => {
    const access = await idp.sign({
      sub: "vouch-user-4",
      email_verified: true,
      phone_number_verified: true,
      azp: idp.clientId,
    });

    const result = await core.processTokens({ access_token: access });

    expect(result.user.email).toBeUndefined();
    expect(result.user.email_verified).toBeUndefined();
    expect(result.user.phone_number_verified).toBeUndefined();
  });
});

describe("a direct refresh can be bound to a subject too", () => {
  test("refuses a refresh token belonging to somebody else", async () => {
    const { tokens } = await login("direct-refresh-owner", OFFLINE);

    await expect(
      core.refresh({
        refreshToken: tokens.refresh_token as string,
        expectedSubject: "somebody-else",
      }),
    ).rejects.toThrow(OidcSubjectError);
  });

  test("allows the subject it really belongs to", async () => {
    const { tokens } = await login("direct-refresh-owner-2", OFFLINE);

    const refreshed = await core.refresh({
      refreshToken: tokens.refresh_token as string,
      expectedSubject: "direct-refresh-owner-2",
    });

    expect(refreshed.access_token).toBeString();
  });

  test("still refreshes unchecked when no subject is asserted", async () => {
    const { tokens } = await login("direct-refresh-owner-3", OFFLINE);

    const refreshed = await core.refresh({
      refreshToken: tokens.refresh_token as string,
    });

    expect(refreshed.access_token).toBeString();
  });
});

describe("a back-channel logout token is neither kind of token", () => {
  test("refuses one in the access slot, where it satisfies every other check", async () => {
    // Shaped as OIDC Back-Channel Logout 1.0 §2.4 requires: no nonce, so
    // nothing in `idTokenOnlyClaims` catches it, and an `azp` that binds it to
    // this client exactly as a real access token's would.
    const logoutToken = await idp.sign({
      sub: "logout-user",
      azp: idp.clientId,
      events: { "http://schemas.openid.net/event/backchannel-logout": {} },
    });

    await expect(
      core.processTokens({ access_token: logoutToken }),
    ).rejects.toThrow(OidcTokenTypeError);
  });

  test("refuses one in the id slot", async () => {
    const logoutToken = await idp.sign({
      sub: "logout-user-2",
      events: { "http://schemas.openid.net/event/backchannel-logout": {} },
    });

    await expect(core.processTokens({ id_token: logoutToken })).rejects.toThrow(
      OidcTokenTypeError,
    );
  });
});

describe("PKCE is not silently skipped", () => {
  test("refuses a callback with no code verifier rather than exchanging without one", async () => {
    const { authorizationUrl, state } = await core.startSignin({
      redirectUri: idp.redirectUri,
      returnTo: "/dashboard",
    });
    const callbackUrl = await idp.runAuthorizationFlow(
      authorizationUrl,
      "pkce-user",
    );

    // What a lost or expired verifier cookie actually looks like at the
    // callback. `openid-client` reads a falsy verifier as "no PKCE was used"
    // and omits `code_verifier` from the exchange entirely.
    await expect(
      core.resolveSignin({
        callbackUrl,
        codeVerifier: undefined as unknown as string,
        expectedState: state,
      }),
    ).rejects.toThrow(TypeError);
    await expect(
      core.resolveSignin({
        callbackUrl,
        codeVerifier: "",
        expectedState: state,
      }),
    ).rejects.toThrow(TypeError);
  });
});

describe("construction and argument guards", () => {
  test("refuses a scope that cannot produce an id token", async () => {
    await expect(
      core.startSignin({
        redirectUri: idp.redirectUri,
        returnTo: "/dashboard",
        scope: "profile email",
      }),
    ).rejects.toThrow(/must include "openid"/);
  });

  test("accepts a scope that merely reorders it", async () => {
    const { authorizationUrl } = await core.startSignin({
      redirectUri: idp.redirectUri,
      returnTo: "/dashboard",
      scope: "email  openid",
    });
    expect(authorizationUrl.searchParams.get("scope")).toBe("email  openid");
  });

  test("refuses an empty client id, which would bind tokens to nothing", async () => {
    await expect(
      createOidcCore({
        issuer: idp.issuer,
        clientId: "",
        development: true,
      }),
    ).rejects.toThrow(TypeError);
  });

  test("warns that verifyAudience discards expectedAudience", async () => {
    const warnings: string[] = [];
    await createOidcCore({
      issuer: idp.issuer,
      clientId: idp.clientId,
      development: true,
      expectedAudience: "https://api.example.com",
      verifyAudience: () => true,
      logger: {
        debug: () => {},
        info: () => {},
        warn: (...args) => warnings.push(args.join(" ")),
        error: () => {},
      },
    });
    expect(warnings.some((line) => line.includes("expectedAudience"))).toBe(
      true,
    );
  });

  test("requires the subject a UserInfo response is to be checked against", async () => {
    await expect(
      core.fetchUserInfoFromIssuer({
        accessToken: "some-token",
        expectedSubject: "",
      }),
    ).rejects.toThrow(TypeError);
  });

  test("reports a failed UserInfo call inside the error hierarchy", async () => {
    await expect(
      core.fetchUserInfoFromIssuer({
        accessToken: "not-a-real-token",
        expectedSubject: "some-subject",
      }),
    ).rejects.toThrow(OidcUserInfoError);
  });
});

describe("an identity is an issuer plus a subject", () => {
  test("the user carries the issuer it was verified against", async () => {
    // `sub` is unique only within an issuer (OIDC Core 2), and several
    // providers mint guessable ones — a numeric id, a username, an email. An
    // application talking to two IdPs and keying accounts on `sub` alone lets a
    // subject at one collide with a different person at the other, so the claim
    // that scopes it has to be reachable from the shape callers actually read.
    const { tokens } = await login("issuer-scoped-user");
    const result = await core.processTokens({
      access_token: tokens.access_token as string,
      id_token: tokens.id_token as string,
    });
    expect(result.user.iss).toBe(idp.issuer);
  });

  test("the issuer is the verified one, not whatever a claim said", async () => {
    // The only claim set a caller can steer here is an introspection response,
    // which need not carry `iss` at all — and if it did, it would be the AS
    // describing itself rather than something this library checked. The value
    // reported is the issuer every strategy was pinned to.
    const opaque = await createOidcCore({
      issuer: idp.issuer,
      clientId: idp.clientId,
      development: true,
      logLevel: "silent",
    });
    const { tokens } = await login("issuer-opaque-user");
    const result = await opaque.processTokens({
      access_token: tokens.access_token as string,
    });
    expect(result.user.iss).toBe(idp.issuer);
  });
});

describe("sender-constrained tokens are not silently downgraded", () => {
  test("warns when an access token carries a cnf claim", async () => {
    // A `cnf` claim is the issuer binding the token to a key (RFC 9449 DPoP,
    // RFC 8705 mTLS). Checking that needs the proof travelling with the HTTP
    // request, which this library never sees — so the token validates and is
    // then usable by anyone who stole it, which is the one thing the constraint
    // exists to prevent. It cannot be checked here, so it is said out loud.
    const warnings: string[] = [];
    const bound = await createOidcCore({
      issuer: idp.issuer,
      clientId: idp.clientId,
      development: true,
      logger: {
        debug: () => {},
        info: () => {},
        warn: (...args) => warnings.push(args.join(" ")),
        error: () => {},
      },
    });
    const token = await idp.sign({
      sub: "dpop-user",
      azp: idp.clientId,
      cnf: { jkt: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" },
    });

    const result = await bound.processTokens({ access_token: token });
    expect(result.user.sub).toBe("dpop-user");
    expect(warnings.some((line) => line.includes('"cnf"'))).toBe(true);

    // Once per instance: it describes the provider's configuration, not the
    // request that happened to reveal it.
    const before = warnings.length;
    await bound.processTokens({ access_token: token });
    expect(warnings.length).toBe(before);
  });

  test("says nothing for an ordinary bearer token", async () => {
    const warnings: string[] = [];
    const plain = await createOidcCore({
      issuer: idp.issuer,
      clientId: idp.clientId,
      development: true,
      logger: {
        debug: () => {},
        info: () => {},
        warn: (...args) => warnings.push(args.join(" ")),
        error: () => {},
      },
    });
    const { tokens } = await login("plain-bearer-user");
    await plain.processTokens({
      access_token: tokens.access_token as string,
    });
    expect(warnings.some((line) => line.includes('"cnf"'))).toBe(false);
  });
});
