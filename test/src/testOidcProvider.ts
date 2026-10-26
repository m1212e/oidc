import http from "node:http";
import type { AddressInfo } from "node:net";
import { type CryptoKey, exportJWK, generateKeyPair, SignJWT } from "jose";
import { Provider } from "oidc-provider";

export type TestOidcProvider = {
  issuer: string;
  clientId: string;
  redirectUri: string;
  postLogoutRedirectUri: string;
  close: () => Promise<void>;
  /** Number of times each real provider endpoint has been hit so far. */
  calls: { introspection: number; userinfo: number; token: number };
  /**
   * Drives a real authorization-code + PKCE flow against the provider,
   * following redirects and auto-completing the login/consent interactions
   * like a browser would (without a browser or form-filling). Returns the
   * final redirect back to `redirectUri`, carrying the real `code`/`state`
   * the provider issued.
   */
  runAuthorizationFlow: (
    authorizationUrl: URL,
    accountId?: string,
  ) => Promise<URL>;
  /**
   * Mints a JWT with the same key the provider signs its own ID tokens with
   * (or, with `badKid`, a key the provider's JWKS doesn't have), for
   * exercising expiry/signature-failure paths a real login can't produce
   * on demand.
   */
  sign: (
    claims: { sub: string; email?: string } & Record<string, unknown>,
    opts?: {
      expired?: boolean;
      badKid?: boolean;
      /** Overrides the default `aud` of the registered client id. */
      audience?: string | string[];
      /** Seconds from now until `exp`. Negative for an already-expired token. */
      expiresIn?: number;
      /** Omits `exp` entirely, for a token that never expires. */
      noExpiry?: boolean;
      /** Sets the JWS `typ` header, e.g. `"at+jwt"` for an RFC 9068 access token. */
      typ?: string;
    },
  ) => Promise<string>;
};

const DEFAULT_ACCOUNT = "test-user";

export async function startTestOidcProvider(opts?: {
  /**
   * Whether to advertise an `end_session_endpoint`. Turn it off to stand in
   * for a provider that has no RP-initiated logout at all. Defaults to on.
   */
  rpInitiatedLogout?: boolean;
}): Promise<TestOidcProvider> {
  const clientId = "test-client";
  const redirectUri = "https://app.example.com/callback";
  const postLogoutRedirectUri = "https://app.example.com/logged-out";

  // The issuer has to be known up front to construct `Provider`, so bind an
  // ephemeral port first and derive the issuer URL from it.
  const server = http.createServer();
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
  const { port } = server.address() as AddressInfo;
  const issuer = `http://127.0.0.1:${port}`;

  // Supplying our own signing key (rather than letting the provider generate
  // one) means the test harness can mint tokens with that same key later,
  // e.g. a validly-signed-but-expired ID token, which a real login can't
  // produce on demand.
  const kid = "test-key";
  const badKid = "not-in-jwks";
  const { privateKey } = await generateKeyPair("RS256", { extractable: true });
  const privateJwk = await exportJWK(privateKey as CryptoKey);
  const { privateKey: badPrivateKey } = await generateKeyPair("RS256", {
    extractable: true,
  });

  const provider = new Provider(issuer, {
    cookies: { keys: ["test-only-cookie-key"] },
    jwks: { keys: [{ ...privateJwk, kid, alg: "RS256", use: "sig" }] },
    // Without this, oidc-provider only puts requested claims on the ID token
    // for flows where the client can't also call /userinfo. It otherwise
    // expects a userinfo round-trip. Tests want the claims on the ID token
    // itself, so a JWKS-only test doesn't need a UserInfo call to succeed.
    conformIdTokenClaims: false,
    clients: [
      {
        client_id: clientId,
        redirect_uris: [redirectUri],
        post_logout_redirect_uris: [postLogoutRedirectUri],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
      },
    ],
    claims: {
      openid: ["sub"],
      email: ["email"],
    },
    features: {
      introspection: { enabled: true },
      devInteractions: { enabled: false },
      rpInitiatedLogout: { enabled: opts?.rpInitiatedLogout ?? true },
    },
    async findAccount(_ctx, sub) {
      return {
        accountId: sub,
        async claims() {
          return { sub, email: `${sub}@example.com` };
        },
      };
    },
  });

  const oidcCallback = provider.callback();
  const calls = { introspection: 0, userinfo: 0, token: 0 };
  const countedEndpoints: Record<string, keyof typeof calls> = {
    "/token/introspection": "introspection",
    "/me": "userinfo",
    "/token": "token",
  };

  type Interaction = Awaited<ReturnType<typeof provider.interactionDetails>>;

  /** Grants whatever the consent prompt says is missing. */
  async function grantConsent({ prompt, params, session }: Interaction) {
    const grant = new provider.Grant({
      accountId: session?.accountId,
      clientId: params.client_id as string,
    });
    const { missingOIDCScope, missingOIDCClaims } = prompt.details;
    if (missingOIDCScope) {
      grant.addOIDCScope((missingOIDCScope as string[]).join(" "));
    }
    if (missingOIDCClaims) {
      grant.addOIDCClaims(missingOIDCClaims as string[]);
    }
    return grant.save();
  }

  /** Completes a login or consent prompt the way a user clicking through would. */
  async function completeInteraction(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ) {
    const details = await provider.interactionDetails(req, res);
    const { prompt, params } = details;

    if (prompt.name === "login") {
      const accountId = String(params.login_hint ?? DEFAULT_ACCOUNT);
      await provider.interactionFinished(
        req,
        res,
        { login: { accountId } },
        { mergeWithLastSubmission: false },
      );
      return;
    }
    if (prompt.name === "consent") {
      const grantId = await grantConsent(details);
      await provider.interactionFinished(
        req,
        res,
        { consent: { grantId } },
        { mergeWithLastSubmission: true },
      );
      return;
    }
    res.statusCode = 400;
    res.end(`test oidc provider: unexpected prompt "${prompt.name}"`);
  }

  server.on("request", async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", issuer);
      const counted = countedEndpoints[url.pathname];
      if (counted) calls[counted]++;

      if (req.method === "GET" && /^\/interaction\/[^/]+$/.test(url.pathname)) {
        await completeInteraction(req, res);
      } else {
        await oidcCallback(req, res);
      }
    } catch (err) {
      if (!res.headersSent) {
        res.statusCode = 500;
        res.end(`test oidc provider error: ${(err as Error).message}`);
      }
    }
  });

  /** Keeps the cookies a response sets, like a browser's cookie jar. */
  function storeCookies(cookies: Map<string, string>, res: Response) {
    for (const setCookie of res.headers.getSetCookie()) {
      const pair = setCookie.split(";")[0] ?? "";
      const eq = pair.indexOf("=");
      if (eq === -1) continue;
      cookies.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
    }
  }

  /** Where a redirect response points, or a thrown error for anything else. */
  async function redirectTarget(res: Response, current: URL): Promise<URL> {
    const location = res.headers.get("location");
    if (res.status >= 300 && res.status < 400 && location) {
      return new URL(location, current);
    }
    const body = await res.text().catch(() => "");
    throw new Error(
      `unexpected ${res.status} response at ${current} while driving the authorization flow: ${body.slice(0, 300)}`,
    );
  }

  async function runAuthorizationFlow(
    authorizationUrl: URL,
    accountId?: string,
  ): Promise<URL> {
    let current = new URL(authorizationUrl);
    if (accountId) current.searchParams.set("login_hint", accountId);

    const cookies = new Map<string, string>();
    const redirectTargetOrigin = new URL(redirectUri).origin;

    for (let hop = 0; hop < 20; hop++) {
      const cookie = [...cookies.entries()]
        .map(([key, value]) => `${key}=${value}`)
        .join("; ");
      const res = await fetch(current, {
        redirect: "manual",
        headers: cookie ? { cookie } : undefined,
      });
      storeCookies(cookies, res);

      current = await redirectTarget(res, current);
      if (current.origin === redirectTargetOrigin) return current;
    }

    throw new Error("too many redirects while driving the authorization flow");
  }

  type SignOptions = {
    expired?: boolean;
    badKid?: boolean;
    audience?: string | string[];
    expiresIn?: number;
    noExpiry?: boolean;
    typ?: string;
  };

  /** `exp` for a minted token: explicit, already passed, or an hour out. */
  function expirationFor(now: number, opts: SignOptions): number {
    if (opts.expiresIn !== undefined) return now + opts.expiresIn;
    return opts.expired ? now - 60 : now + 3600;
  }

  const signingKeys = {
    jwks: { key: privateKey as CryptoKey, kid },
    unknown: { key: badPrivateKey as CryptoKey, kid: badKid },
  };

  async function sign(
    claims: { sub: string; email?: string } & Record<string, unknown>,
    opts: SignOptions = {},
  ): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const signing = opts.badKid ? signingKeys.unknown : signingKeys.jwks;
    const jwt = new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", kid: signing.kid, typ: opts.typ })
      .setIssuer(issuer)
      .setAudience(opts.audience ?? clientId)
      .setSubject(claims.sub)
      .setIssuedAt(opts.expired ? now - 120 : now);
    if (!opts.noExpiry) jwt.setExpirationTime(expirationFor(now, opts));
    return jwt.sign(signing.key);
  }

  return {
    issuer,
    clientId,
    redirectUri,
    postLogoutRedirectUri,
    calls,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
    runAuthorizationFlow,
    sign,
  };
}
