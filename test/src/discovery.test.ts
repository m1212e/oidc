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
    const { logger } = recordingLogger();
    expect(() => assertPkceSupported(["plain"], undefined, logger)).toThrow(
      /does not support the S256 PKCE challenge method/,
    );
  });

  test("warns, rather than throwing, when the issuer advertises nothing", () => {
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
  test("leaves an issuer identifier alone, openid-client compared that itself", () => {
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
    expect(() =>
      assertDiscoveredIssuer(
        "https://idp.example.com/.well-known/openid-configuration",
        "https://evil.example",
      ),
    ).toThrow(/names a different issuer/);
    expect(() =>
      assertDiscoveredIssuer(
        "https://idp.example.com/realms/main/.well-known/openid-configuration",
        "https://idp.example.com/realms/other",
      ),
    ).toThrow(/names a different issuer/);
  });

  test("falls back to the origin for the RFC 8414 inserted form", () => {
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
    for (const discovered of ["", "not-a-url", "idp.example.com"]) {
      expect(() =>
        assertDiscoveredIssuer(
          "https://idp.example.com/.well-known/oauth-authorization-server/realms/main",
          discovered,
        ),
      ).toThrow(/is not a URL/);
    }
    expect(() =>
      assertDiscoveredIssuer(
        "https://idp.example.com/.well-known/openid-configuration",
        "not-a-url",
      ),
    ).toThrow(/names a different issuer/);
  });

  test("lets Entra ID and B2C answer with their tenant placeholder", () => {
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
