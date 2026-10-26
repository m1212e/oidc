/**
 * RFC 8693 token exchange against a minimal issuer that records what it
 * was sent, since the test provider doesn't implement the grant.
 */

import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  test,
} from "bun:test";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { createOidcCore, type OidcCore } from "../../lib/core";
import { OidcGrantError, OidcInputError } from "../../lib/errors";

const CLIENT_ID = "exchange-client";
const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

let issuer: string;
let server: http.Server;
let oidc: OidcCore;
/** The form body of the last token request. */
let received: URLSearchParams;
/** What the token endpoint answers with next. */
let respond: () => Promise<{ status: number; body: object }>;

const { privateKey, publicKey } = await generateKeyPair("RS256");
const jwk = { ...(await exportJWK(publicKey)), kid: "k1", use: "sig" };

beforeAll(async () => {
  server = http.createServer(async (req, res) => {
    const reply = (status: number, body: object) => {
      res.writeHead(status, {
        "content-type": "application/json",
        "cache-control": "no-store",
      });
      res.end(JSON.stringify(body));
    };
    if (req.url === "/.well-known/openid-configuration") {
      return reply(200, {
        issuer,
        authorization_endpoint: `${issuer}/auth`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        code_challenge_methods_supported: ["S256"],
        id_token_signing_alg_values_supported: ["RS256"],
      });
    }
    if (req.url === "/jwks") return reply(200, { keys: [jwk] });
    if (req.url === "/token") {
      let body = "";
      for await (const chunk of req) body += chunk;
      received = new URLSearchParams(body);
      const { status, body: json } = await respond();
      return reply(status, json);
    }
    reply(404, {});
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  oidc = await createOidcCore({
    issuer,
    clientId: CLIENT_ID,
    development: true,
    logLevel: "silent",
  });
});

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

beforeEach(() => {
  respond = async () => ({
    status: 200,
    body: {
      access_token: "exchanged-access-token",
      issued_token_type: ACCESS_TOKEN_TYPE,
      token_type: "Bearer",
      expires_in: 300,
    },
  });
});

function idToken(aud: string) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ sub: "user-1" })
    .setProtectedHeader({ alg: "RS256", kid: jwk.kid })
    .setIssuer(issuer)
    .setAudience(aud)
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(privateKey);
}

describe("exchangeToken", () => {
  test("sends an impersonation request: a subject token and no actor", async () => {
    const tokens = await oidc.exchangeToken({
      subjectToken: "user-token",
      audience: "orders-api",
    });

    expect(tokens.access_token).toBe("exchanged-access-token");
    expect(received.get("grant_type")).toBe(
      "urn:ietf:params:oauth:grant-type:token-exchange",
    );
    expect(received.get("subject_token")).toBe("user-token");
    expect(received.get("subject_token_type")).toBe(ACCESS_TOKEN_TYPE);
    expect(received.get("audience")).toBe("orders-api");
    expect(received.has("actor_token")).toBe(false);
  });

  test("sends a delegation request with every optional parameter", async () => {
    await oidc.exchangeToken({
      subjectToken: "user-token",
      subjectTokenType: "urn:ietf:params:oauth:token-type:id_token",
      actorToken: "service-token",
      audience: ["orders-api", "billing-api"],
      resource: "https://orders.example.com",
      scope: "orders:read",
      requestedTokenType: ACCESS_TOKEN_TYPE,
      additionalParameters: { requested_subject: "user-2" },
    });

    expect(received.get("subject_token_type")).toBe(
      "urn:ietf:params:oauth:token-type:id_token",
    );
    expect(received.get("actor_token")).toBe("service-token");
    expect(received.get("actor_token_type")).toBe(ACCESS_TOKEN_TYPE);
    expect(received.getAll("audience")).toEqual(["orders-api", "billing-api"]);
    expect(received.get("resource")).toBe("https://orders.example.com");
    expect(received.get("scope")).toBe("orders:read");
    expect(received.get("requested_token_type")).toBe(ACCESS_TOKEN_TYPE);
    expect(received.get("requested_subject")).toBe("user-2");
  });

  test("never lets additionalParameters override the standard ones", async () => {
    await oidc.exchangeToken({
      subjectToken: "user-token",
      additionalParameters: { subject_token: "someone-elses-token" },
    });
    expect(received.getAll("subject_token")).toEqual(["user-token"]);
  });

  test('accepts the "N_A" token type RFC 8693 allows for non-access tokens', async () => {
    respond = async () => ({
      status: 200,
      body: {
        access_token: "a-jwt-assertion",
        issued_token_type: "urn:ietf:params:oauth:token-type:jwt",
        token_type: "N_A",
      },
    });
    const tokens = await oidc.exchangeToken({ subjectToken: "user-token" });
    expect(tokens.issued_token_type).toBe(
      "urn:ietf:params:oauth:token-type:jwt",
    );
  });

  test("validates an id token in the response", async () => {
    respond = async () => ({
      status: 200,
      body: {
        access_token: "exchanged-access-token",
        token_type: "Bearer",
        id_token: await idToken("another-client"),
      },
    });
    await expect(
      oidc.exchangeToken({ subjectToken: "user-token" }),
    ).rejects.toBeInstanceOf(OidcGrantError);
  });

  test("wraps a refusal from the provider", async () => {
    respond = async () => ({
      status: 400,
      body: { error: "unauthorized_client" },
    });
    const error = await oidc
      .exchangeToken({ subjectToken: "user-token" })
      .catch((err) => err);
    expect(error).toBeInstanceOf(OidcGrantError);
    expect(error.grant).toBe("token_exchange");
  });

  test("refuses malformed input before calling the provider", async () => {
    for (const input of [
      { subjectToken: "" },
      { subjectToken: "t", actorToken: "" },
      { subjectToken: "t", actorTokenType: ACCESS_TOKEN_TYPE },
    ]) {
      await expect(oidc.exchangeToken(input)).rejects.toBeInstanceOf(
        OidcInputError,
      );
    }
  });
});
