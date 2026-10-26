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
  calls: { introspection: number; userinfo: number; token: number };
  runAuthorizationFlow: (
    authorizationUrl: URL,
    accountId?: string,
  ) => Promise<URL>;
  sign: (
    claims: { sub: string; email?: string } & Record<string, unknown>,
    opts?: {
      expired?: boolean;
      badKid?: boolean;
      audience?: string | string[];
      expiresIn?: number;
      noExpiry?: boolean;
      typ?: string;
    },
  ) => Promise<string>;
};

const DEFAULT_ACCOUNT = "test-user";

export async function startTestOidcProvider(opts?: {
  rpInitiatedLogout?: boolean;
}): Promise<TestOidcProvider> {
  const clientId = "test-client";
  const redirectUri = "https://app.example.com/callback";
  const postLogoutRedirectUri = "https://app.example.com/logged-out";

  const server = http.createServer();
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
  const { port } = server.address() as AddressInfo;
  const issuer = `http://127.0.0.1:${port}`;

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
