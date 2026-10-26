# oidc

OpenID Connect login and token validation for server-side apps.

Built for the **Authorization Code flow with PKCE** (sign-in), plus validating bearer tokens in APIs. It wraps the whole flow in a few calls and is strict by default: it verifies JWTs locally, falls back to introspection for opaque tokens, refreshes automatically, and rejects tokens issued to another client, the wrong kind of token, mixed-up users and open redirects.

```sh
npm i @m1212e/oidc
```

Requires Node 22.12+ (or Bun).

## Setup

```ts
import { createOidcCore } from "@m1212e/oidc";

const oidc = await createOidcCore({
  issuer: "https://auth.example.com",
  clientId: "my-app",
  clientSecret: process.env.OIDC_SECRET, // omit for public clients
});
```

## Sign in

**1. Redirect to the provider**

```ts
const { authorizationUrl, codeVerifier, state } = await oidc.startSignin({
  redirectUri: "https://app.example.com/callback",
  returnTo: "/dashboard",
});

// store codeVerifier + state (e.g. in an httpOnly cookie), then:
return Response.redirect(authorizationUrl);
```

**2. Handle the callback**

```ts
const { tokens, returnTo } = await oidc.resolveSignin({
  callbackUrl: new URL(request.url),
  codeVerifier, // from step 1
  expectedState: state, // from step 1
});

// store tokens.access_token, tokens.id_token, tokens.refresh_token
return Response.redirect(returnTo);
```

## Authenticate requests

```ts
const result = await oidc.processTokens({
  access_token: session.access_token,
  id_token: session.id_token,
  refresh_token: session.refresh_token, // optional: auto-refreshes expired tokens
});

result.user; // { sub, email, name, ... }

if (result.refreshed) {
  // save result.refreshedTokens to the session
}
```

Pass at least one of `access_token` / `id_token`. Use `undefined` (not `null` or `""`) for tokens you don't have.

> [!IMPORTANT]
> You **must** save refreshed tokens after every `processTokens` call, including when it throws (then they are on `error.refreshedTokens`). Providers rotate refresh tokens, so the old one stops working once it has been used.

### Bearer tokens (APIs)

```ts
const oidc = await createOidcCore({
  issuer: "https://auth.example.com",
  clientId: "my-api",
  expectedAudience: "https://api.example.com", // the `aud` your API's tokens carry
});

const token = request.headers.get("authorization")?.replace(/^Bearer /i, "");
if (!token) return new Response("Unauthorized", { status: 401 });

try {
  const { user } = await oidc.processTokens({ access_token: token });
} catch {
  return new Response("Unauthorized", { status: 401 });
}
```

Without `expectedAudience`, the token's `azp` / `client_id` claim must equal `clientId`.

## Sign out

```ts
const url = await oidc.getLogoutUrl({
  postLogoutRedirectUri: "https://app.example.com/",
  idTokenHint: session.id_token,
});
```

## Other methods

```ts
await oidc.refresh({ refreshToken, expectedSubject: user.sub });
await oidc.fetchUserInfoFromIssuer({ accessToken, expectedSubject: user.sub });
```

## Options

| Option | Default | Use it when |
| --- | --- | --- |
| `issuer` | required | |
| `clientId` | required | |
| `clientSecret` | | confidential client |
| `expectedAudience` | | your API's access tokens carry a specific `aud`, e.g. `"https://api.example.com"` |
| `authorizedPartyClaims` | `["azp", "client_id", "cid", "appid"]` | your provider puts the client id in a different claim |
| `verifyAudience` | | you need a custom check: `(claims, kind) => claims.aud === "x"` |
| `allowedReturnToOrigins` | `[]` | `returnTo` should allow absolute URLs, e.g. `["https://admin.example.com"]` |
| `scope` (on `startSignin`) | `"openid profile email offline_access"` | set `"openid profile email"` if you don't want a refresh token |
| `introspection` | `"opaque-only"` | `"auto"`: also introspect JWTs that fail locally. `"never"`: never call the introspection endpoint |
| `requireIntrospectedTokenType` | `true` | set `false` if your provider's introspection omits `token_type` |
| `accessTokenTyp` | | require a JWT `typ` header, e.g. `"at+jwt"` |
| `idTokenOnlyClaims` | `["nonce", "at_hash", "c_hash", "s_hash"]` | |
| `signingAlgorithms` | from discovery | restrict accepted algorithms, e.g. `["RS256"]` |
| `clockTolerance` | `30` | seconds, or a string like `"1m"` |
| `development` | `NODE_ENV === "development"` | `true` allows a local IdP over plain HTTP |
| `logLevel` | `"warn"` | `"silent" \| "error" \| "warn" \| "info" \| "debug"` |
| `logger` | `console` | `{ debug, info, warn, error }` |

## Errors

Every error extends `OidcError`:

```ts
import { OidcError, OidcTokenValidationError } from "@m1212e/oidc";

try {
  await oidc.processTokens(session);
} catch (err) {
  if (err instanceof OidcTokenValidationError) {
    // not logged in / tokens invalid: redirect to sign in
  }
}
```

| Error | Thrown when |
| --- | --- |
| `OidcTokenValidationError` | a token could not be validated |
| `OidcTokenError` (`OidcAudienceError`, `OidcTokenTypeError`) | a token is valid but not meant for this client or not the expected kind |
| `OidcSubjectError` | tokens belong to different users |
| `OidcGrantError` | code exchange or refresh failed |
| `OidcStateError` | the stored `state` was modified |
| `OidcReturnToError` | `returnTo` / redirect URI is not allowed |
| `OidcInputError` | invalid arguments |
| `OidcUserInfoError`, `OidcLogoutError`, `OidcClaimsError` | the respective call failed |

## License

Apache-2.0

## AI disclaimer

AI tools assisted in writing this code. All of it has been reviewed and validated by a human.
