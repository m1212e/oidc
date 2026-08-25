/**
 * The two things about an issuer that have to be settled before it is used at
 * all: that its signing keys can be fetched without a network attacker being
 * able to swap them, and that it will honour the PKCE challenge every
 * authorization request carries.
 *
 * Both are checked once, in `createOidcCore`, because both are properties of
 * the deployment rather than of a request — and both fail *silently* if left
 * unchecked, which is what makes construction the right place to refuse.
 */

import { describe, expect, test } from "bun:test";
import http from "node:http";
import type { AddressInfo } from "node:net";
import {
  assertDiscoveredIssuer,
  assertPkceSupported,
  createOidcCore,
  resolveJwksUri,
} from "../../lib/core";
import { buildLogger } from "../../lib/logger";

/** Collects what the library logged, so a warning can be asserted on. */
function recordingLogger() {
  const warnings: string[] = [];
  return {
    warnings,
    logger: {
      debug: () => {},
      info: () => {},
      warn: (...args: unknown[]) => warnings.push(args.join(" ")),
      error: () => {},
    },
  };
}

/**
 * An issuer that serves nothing but a metadata document, so the fields this
 * suite is about can be set to values a real provider would not offer.
 */
async function startMetadataOnlyIssuer(
  metadata: (issuer: string) => Record<string, unknown>,
) {
  const server = http.createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  const issuer = `http://127.0.0.1:${port}`;
  server.on("request", (_req, res) => {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ issuer, ...metadata(issuer) }));
  });
  return {
    issuer,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      ),
  };
}

describe("resolveJwksUri", () => {
  test("requires https, because jose has no development switch of its own", () => {
    expect(resolveJwksUri("https://idp.example.com/jwks", false).href).toBe(
      "https://idp.example.com/jwks",
    );
    // The dangerous case: metadata served over TLS that points the key fetch
    // at plain HTTP. Nothing downstream notices, and every signature is then
    // only as trustworthy as the network.
    expect(() => resolveJwksUri("http://idp.example.com/jwks", false)).toThrow(
      /must be fetched over https/,
    );
  });

  test("permits plain HTTP only in development", () => {
    expect(resolveJwksUri("http://127.0.0.1:8080/jwks", true).href).toBe(
      "http://127.0.0.1:8080/jwks",
    );
  });

  test("refuses schemes that are not a fetch at all", () => {
    for (const uri of [
      "ftp://idp.example.com/jwks",
      "file:///etc/jwks.json",
      "data:application/json,{}",
    ]) {
      expect(() => resolveJwksUri(uri, true)).toThrow(TypeError);
    }
    expect(() => resolveJwksUri("not-a-url", true)).toThrow(/not a URL/);
  });
});

describe("assertPkceSupported", () => {
  test("accepts an issuer that advertises S256", () => {
    const { logger, warnings } = recordingLogger();
    expect(() =>
      assertPkceSupported(["plain", "S256"], undefined, logger),
    ).not.toThrow();
    expect(warnings).toHaveLength(0);
  });

  test("refuses one that advertises its methods and omits S256", () => {
    // `plain` is not a fallback: a challenge equal to the verifier binds the
    // code to nothing. And an AS that does not understand `code_challenge`
    // ignores it and answers the exchange normally, so the flow *looks*
    // protected — which is why this has to be a refusal, not a warning.
    const { logger } = recordingLogger();
    expect(() => assertPkceSupported(["plain"], undefined, logger)).toThrow(
      /does not support the S256 PKCE challenge method/,
    );
  });

  test("warns, rather than throwing, when the issuer advertises nothing", () => {
    // RFC 8414 reads an absent field as "no PKCE", but providers that do
    // support it omit it too, and there is no caller-side configuration that
    // would fix it — only an IdP setting to go and confirm.
    const { logger, warnings } = recordingLogger();
    expect(() =>
      assertPkceSupported(undefined, undefined, logger),
    ).not.toThrow();
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("public client");

    const confidential = recordingLogger();
    assertPkceSupported([], "s3cret", confidential.logger);
    expect(confidential.warnings[0]).not.toContain("public client");
  });
});

describe("assertDiscoveredIssuer", () => {
  test("leaves an issuer identifier alone — openid-client compared that itself", () => {
    // Nothing here re-runs that comparison: it is exact, and it carries
    // provider exemptions this function would only get wrong.
    expect(() =>
      assertDiscoveredIssuer(
        "https://idp.example.com",
        "https://elsewhere.example",
      ),
    ).not.toThrow();
  });

  test("accepts the issuer its .well-known URL was built from", () => {
    for (const [configured, discovered] of [
      [
        "https://idp.example.com/.well-known/openid-configuration",
        "https://idp.example.com",
      ],
      // A trailing slash on either side is the same issuer.
      [
        "https://idp.example.com/.well-known/openid-configuration",
        "https://idp.example.com/",
      ],
      [
        "https://idp.example.com/realms/main/.well-known/openid-configuration",
        "https://idp.example.com/realms/main",
      ],
      [
        "https://idp.example.com/.well-known/oauth-authorization-server",
        "https://idp.example.com",
      ],
    ] as const) {
      expect(() =>
        assertDiscoveredIssuer(configured, discovered),
      ).not.toThrow();
    }
  });

  test("refuses a document that names an issuer it was not fetched for", () => {
    // The whole point: openid-client skips its own check for a .well-known URL,
    // so without this the document decides what `iss` every token is pinned to.
    expect(() =>
      assertDiscoveredIssuer(
        "https://idp.example.com/.well-known/openid-configuration",
        "https://evil.example",
      ),
    ).toThrow(/names a different issuer/);
    // Same host, different realm — still not the issuer that was asked for.
    expect(() =>
      assertDiscoveredIssuer(
        "https://idp.example.com/realms/main/.well-known/openid-configuration",
        "https://idp.example.com/realms/other",
      ),
    ).toThrow(/names a different issuer/);
  });

  test("falls back to the origin for the RFC 8414 inserted form", () => {
    // `/.well-known/oauth-authorization-server/realms/main` cannot be reversed
    // into its issuer — the boundary between the well-known name and the issuer
    // path is not recoverable — so the origin is what is left to check.
    expect(() =>
      assertDiscoveredIssuer(
        "https://idp.example.com/.well-known/oauth-authorization-server/realms/main",
        "https://idp.example.com/realms/main",
      ),
    ).not.toThrow();
    expect(() =>
      assertDiscoveredIssuer(
        "https://idp.example.com/.well-known/oauth-authorization-server/realms/main",
        "https://evil.example/realms/main",
      ),
    ).toThrow(/different origin/);
  });

  test("refuses an issuer it cannot compare rather than stepping over it", () => {
    // A document naming an issuer that is not a URL at all passes
    // `openid-client` — it asserts a string, not a URL, and skips the
    // comparison entirely for a .well-known URL. If the origin fallback then
    // waved it through for being unparseable, the one check holding the
    // document to the provider it came from would fail open, and `iss`,
    // `jwks_uri` and the token endpoint would all be whatever it said.
    for (const discovered of ["", "not-a-url", "idp.example.com"]) {
      expect(() =>
        assertDiscoveredIssuer(
          "https://idp.example.com/.well-known/oauth-authorization-server/realms/main",
          discovered,
        ),
      ).toThrow(/is not a URL/);
    }
    // The appended form compares the issuer as a string, so it was already
    // closed — but it must stay a rejection rather than becoming the new error.
    expect(() =>
      assertDiscoveredIssuer(
        "https://idp.example.com/.well-known/openid-configuration",
        "not-a-url",
      ),
    ).toThrow(/names a different issuer/);
  });

  test("lets Entra ID and B2C answer with their tenant placeholder", () => {
    // openid-client exempts both hosts from its own comparison, because the
    // `/common` and `/organizations` documents really do answer with a literal
    // `{tenantid}`. Matching that exactly would refuse a working deployment,
    // so these get the origin check.
    expect(() =>
      assertDiscoveredIssuer(
        "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
        "https://login.microsoftonline.com/{tenantid}/v2.0",
      ),
    ).not.toThrow();
    expect(() =>
      assertDiscoveredIssuer(
        "https://contoso.b2clogin.com/contoso.onmicrosoft.com/b2c_1_si/v2.0/.well-known/openid-configuration",
        "https://contoso.b2clogin.com/9f4f4/v2.0/",
      ),
    ).not.toThrow();
    // The exemption is the host's, not a licence to hand off to another one.
    expect(() =>
      assertDiscoveredIssuer(
        "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
        "https://evil.example/{tenantid}/v2.0",
      ),
    ).toThrow(/different origin/);
  });
});

describe("createOidcCore applies both at construction", () => {
  test("refuses an issuer whose PKCE support excludes S256", async () => {
    const idp = await startMetadataOnlyIssuer((issuer) => ({
      authorization_endpoint: `${issuer}/auth`,
      token_endpoint: `${issuer}/token`,
      jwks_uri: `${issuer}/jwks`,
      code_challenge_methods_supported: ["plain"],
      response_types_supported: ["code"],
    }));
    try {
      await expect(
        createOidcCore({
          issuer: idp.issuer,
          clientId: "test-client",
          development: true,
        }),
      ).rejects.toThrow(/S256/);
    } finally {
      await idp.close();
    }
  });

  test("refuses an issuer that points the key fetch somewhere unfetchable", async () => {
    const idp = await startMetadataOnlyIssuer((issuer) => ({
      authorization_endpoint: `${issuer}/auth`,
      token_endpoint: `${issuer}/token`,
      jwks_uri: "ftp://idp.example.com/jwks",
      code_challenge_methods_supported: ["S256"],
      response_types_supported: ["code"],
    }));
    try {
      await expect(
        createOidcCore({
          issuer: idp.issuer,
          clientId: "test-client",
          development: true,
        }),
      ).rejects.toThrow(/jwks_uri/);
    } finally {
      await idp.close();
    }
  });

  test("refuses a .well-known document that names a foreign issuer", async () => {
    // The case openid-client does not cover: hand it a URL that already
    // contains /.well-known/ and it takes the document's word for the issuer,
    // which is then what every token is verified against.
    const idp = await startMetadataOnlyIssuer((issuer) => ({
      issuer: "https://evil.example",
      authorization_endpoint: `${issuer}/auth`,
      token_endpoint: `${issuer}/token`,
      jwks_uri: `${issuer}/jwks`,
      code_challenge_methods_supported: ["S256"],
      response_types_supported: ["code"],
    }));
    try {
      await expect(
        createOidcCore({
          issuer: `${idp.issuer}/.well-known/openid-configuration`,
          clientId: "test-client",
          development: true,
          logLevel: "silent",
        }),
      ).rejects.toThrow(/names a different issuer/);
      // The same document reached by its issuer identifier was already refused,
      // one layer down — which is exactly the asymmetry the check above closes.
      await expect(
        createOidcCore({
          issuer: idp.issuer,
          clientId: "test-client",
          development: true,
          logLevel: "silent",
        }),
      ).rejects.toThrow();
    } finally {
      await idp.close();
    }
  });

  test("accepts a .well-known URL for the issuer it really belongs to", async () => {
    const idp = await startMetadataOnlyIssuer((issuer) => ({
      authorization_endpoint: `${issuer}/auth`,
      token_endpoint: `${issuer}/token`,
      jwks_uri: `${issuer}/jwks`,
      code_challenge_methods_supported: ["S256"],
      response_types_supported: ["code"],
    }));
    try {
      const core = await createOidcCore({
        issuer: `${idp.issuer}/.well-known/openid-configuration`,
        clientId: "test-client",
        development: true,
        logLevel: "silent",
      });
      expect(core.configuration.serverMetadata().issuer).toBe(idp.issuer);
    } finally {
      await idp.close();
    }
  });

  test("warns when there are no keys to verify anything against", async () => {
    // Not a refusal — an AS issuing only opaque tokens has no keys to publish.
    // But it moves every validation onto the network, silently.
    const idp = await startMetadataOnlyIssuer((issuer) => ({
      authorization_endpoint: `${issuer}/auth`,
      token_endpoint: `${issuer}/token`,
      introspection_endpoint: `${issuer}/introspect`,
      code_challenge_methods_supported: ["S256"],
      response_types_supported: ["code"],
    }));
    const { logger, warnings } = recordingLogger();
    try {
      await createOidcCore({
        issuer: idp.issuer,
        clientId: "test-client",
        development: true,
        logger,
      });
      expect(warnings.some((line) => line.includes("jwks_uri"))).toBe(true);
      expect(
        warnings.some((line) => line.includes("no token will validate")),
      ).toBe(false);

      const off = recordingLogger();
      await createOidcCore({
        issuer: idp.issuer,
        clientId: "test-client",
        development: true,
        introspection: "never",
        logger: off.logger,
      });
      expect(
        off.warnings.some((line) => line.includes("no token will validate")),
      ).toBe(true);
    } finally {
      await idp.close();
    }
  });

  test("warns about an issuer that advertises no PKCE methods at all", async () => {
    const idp = await startMetadataOnlyIssuer((issuer) => ({
      authorization_endpoint: `${issuer}/auth`,
      token_endpoint: `${issuer}/token`,
      jwks_uri: `${issuer}/jwks`,
      response_types_supported: ["code"],
    }));
    const { logger, warnings } = recordingLogger();
    try {
      await createOidcCore({
        issuer: idp.issuer,
        clientId: "test-client",
        development: true,
        logger,
      });
      expect(
        warnings.some((line) =>
          line.includes("code_challenge_methods_supported"),
        ),
      ).toBe(true);
    } finally {
      await idp.close();
    }
  });
});

describe("buildLogger", () => {
  test("silences everything below the threshold", () => {
    const silent = buildLogger(undefined, "silent");
    expect(() => {
      silent.debug("x");
      silent.info("x");
      silent.warn("x");
      silent.error("x");
    }).not.toThrow();
  });
});
