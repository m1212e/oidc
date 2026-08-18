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
   * Drives a real authorization-code + PKCE flow against the provider —
   * following redirects and auto-completing the login/consent interactions
   * exactly as a browser would, but without a browser or form-filling —
   * and returns the final redirect back to `redirectUri`, carrying the
   * real `code`/`state` the provider issued.
   */
  runAuthorizationFlow: (
    authorizationUrl: URL,
    accountId?: string,
  ) => Promise<URL>;
  /**
   * Mints a JWT with the same key the provider signs its own ID tokens
   * with (or, with `badKid`, a key the provider's JWKS doesn't have) — for
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
      /** Seconds from now until `exp`; negative for an already-expired token. */
      expiresIn?: number;
      /** Omits `exp` entirely, for a token that never expires. */
      noExpiry?: boolean;
      /** Sets the JWS `typ` header — e.g. `"at+jwt"` for an RFC 9068 access token. */
      typ?: string;
    },
  ) => Promise<string>;
};

const DEFAULT_ACCOUNT = "test-user";

export async function startTestOidcProvider(): Promise<TestOidcProvider> {
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
  // one) means the test harness can mint tokens with that same key later —
  // e.g. a validly-signed-but-expired ID token — which a real login can't
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
    // for flows where the client can't also call /userinfo — it otherwise
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

  server.on("request", async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", issuer);
      if (url.pathname === "/token/introspection") calls.introspection++;
      if (url.pathname === "/me") calls.userinfo++;
      if (url.pathname === "/token") calls.token++;

      const interactionMatch = url.pathname.match(/^\/interaction\/([^/]+)$/);

      if (req.method === "GET" && interactionMatch) {
        const { prompt, params, session } = await provider.interactionDetails(
          req,
          res,
        );

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
          const grant = new provider.Grant({
            accountId: session?.accountId,
            clientId: params.client_id as string,
          });
          if (prompt.details.missingOIDCScope) {
            grant.addOIDCScope(
              (prompt.details.missingOIDCScope as string[]).join(" "),
            );
          }
          if (prompt.details.missingOIDCClaims) {
            grant.addOIDCClaims(prompt.details.missingOIDCClaims as string[]);
          }
          const grantId = await grant.save();
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
        return;
      }

      await oidcCallback(req, res);
    } catch (err) {
      if (!res.headersSent) {
        res.statusCode = 500;
        res.end(`test oidc provider error: ${(err as Error).message}`);
      }
    }
  });

  async function runAuthorizationFlow(
    authorizationUrl: URL,
    accountId?: string,
  ): Promise<URL> {
    let current = new URL(authorizationUrl);
    if (accountId) current.searchParams.set("login_hint", accountId);

    const cookies = new Map<string, string>();
    const cookieHeader = () =>
      [...cookies.entries()]
        .map(([key, value]) => `${key}=${value}`)
        .join("; ");

    const redirectTargetOrigin = new URL(redirectUri).origin;

    for (let hop = 0; hop < 20; hop++) {
      const res = await fetch(current, {
        redirect: "manual",
        headers: cookieHeader() ? { cookie: cookieHeader() } : undefined,
      });

      for (const setCookie of res.headers.getSetCookie()) {
        const pair = setCookie.split(";")[0];
        const eq = pair.indexOf("=");
        if (eq === -1) continue;
        cookies.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
      }

      if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get("location");
        if (!location)
          throw new Error("redirect response without a Location header");
        const next = new URL(location, current);
        if (next.origin === redirectTargetOrigin) return next;
        current = next;
        continue;
      }

      const body = await res.text().catch(() => "");
      throw new Error(
        `unexpected ${res.status} response at ${current} while driving the authorization flow: ${body.slice(0, 300)}`,
      );
    }

    throw new Error("too many redirects while driving the authorization flow");
  }

  async function sign(
    claims: { sub: string; email?: string } & Record<string, unknown>,
    opts?: {
      expired?: boolean;
      badKid?: boolean;
      audience?: string | string[];
      expiresIn?: number;
      noExpiry?: boolean;
      typ?: string;
    },
  ): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const signingKey = opts?.badKid
      ? (badPrivateKey as CryptoKey)
      : (privateKey as CryptoKey);
    const jwt = new SignJWT(claims)
      .setProtectedHeader({
        alg: "RS256",
        kid: opts?.badKid ? badKid : kid,
        ...(opts?.typ ? { typ: opts.typ } : {}),
      })
      .setIssuer(issuer)
      .setAudience(opts?.audience ?? clientId)
      .setSubject(claims.sub)
      .setIssuedAt(opts?.expired ? now - 120 : now);
    if (!opts?.noExpiry) {
      jwt.setExpirationTime(
        opts?.expiresIn !== undefined
          ? now + opts.expiresIn
          : opts?.expired
            ? now - 60
            : now + 3600,
      );
    }
    return jwt.sign(signingKey);
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
