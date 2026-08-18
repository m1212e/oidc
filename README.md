# @m1212e/oidc

Issuer-agnostic OIDC token handling for resource servers: discovery, offline JWT validation with introspection fallback, refresh, and claim normalization.

## Install

```sh
npm install @m1212e/oidc
# or: bun add @m1212e/oidc
```

Requires Node 20+ (or Bun). ESM and CJS builds are both published.

## Setup

Create one core per issuer/client pair, at startup, `createOidcCore` performs OIDC discovery over the network, so it must be awaited once and reused for the lifetime of the process rather than created per request.

```ts
import { createOidcCore } from "@m1212e/oidc";

const oidc = await createOidcCore({
  issuer: "https://kc.example.com/realms/main",
  clientId: "my-app",
  clientSecret: process.env.OIDC_CLIENT_SECRET, // omit for a public/PKCE-only client'

  // Set only if your IdP puts a resource audience on access tokens
  expectedAudience: "api://orders",
});
```
Everything else is optional.

See [Configuration](#configuration) for the full list.

## Signing a user in

The login is two HTTP endpoints in your app: one that starts the flow, one that the IdP redirects back to. The library gives you a function for each; you own the storage in between.

### 1. Start the flow

```ts
// GET /login
const { authorizationUrl, codeVerifier, state } = await oidc.startSignin({
  // your own callback endpoint => Where should the user land for login resolve?
  // Must match a handler calling the resolve function from this library
  redirectUri: "https://app.example.com/callback", 
  // where to land after completing the login? (user home page/dashboard etc.)
  returnTo: req.query.next ?? "/",                 
  // this is the default
  scope: "openid profile email",                   
});
```

You must persist `codeVerifier` and `state` somewhere tied to this browser, a signed/encrypted cookie or a server-side session are good options. You need the values to complete the login. Then redirect the user to `authorizationUrl`.

```ts
setCookie("oidc_verifier", codeVerifier, { httpOnly: true, secure: true, sameSite: "lax" });
setCookie("oidc_state", state, { httpOnly: true, secure: true, sameSite: "lax" });
redirect(authorizationUrl.toString());
```

`state` is an opaque string, it is already embedded in `authorizationUrl`, so do not modify it, just store it and hand it back unchanged.`

It carries the OIDC `nonce` alongside the return URL, which is why handing it back unchanged matters: `resolveSignin` reads the nonce out of it to check the ID token against the request that started the login. There is nothing extra for you to store. A nonce is not a secret, only a single-use value that has to be echoed back, so travelling in `state` costs nothing — unlike `codeVerifier`, which is a secret and never goes near the URL.

### 2. Handle the callback

```ts
// GET /callback
const { tokens, returnTo } = await oidc.resolveSignin(
  // the full callback URL, incl. ?code=&state=
  new URL(req.url, "https://app.example.com"),
  getCookie("oidc_verifier"),
  getCookie("oidc_state"),
);
```

`resolveSignin` verifies `state`, exchanges the code, and validates the ID token, including its `nonce` against the one `startSignin` sent. It also requires the provider to return an ID token at all: since every request asks for `openid` scope, a response without one is a provider fault, not a login with no subject. Store the token set and redirect to `returnTo`:

```ts
// http only cookies are also a good option, if you do not have a session store
await session.set({
  access_token: tokens.access_token,
  id_token: tokens.id_token,
  refresh_token: tokens.refresh_token,
});
clearCookie("oidc_verifier");
clearCookie("oidc_state");
redirect(returnTo);
```

## Validating tokens on a request

`processTokens` is the function to call on every authenticated request. Pass whatever you stored; at least one of `access_token` or `id_token` is required. If you want to authenticate/authorize a request, it is recommended to pass at least the access token.

```ts
const result = await oidc.processTokens({
  access_token: session.access_token,
  id_token: session.id_token,
  refresh_token: session.refresh_token, // optional, see below
});

result.user;              // normalized, whitelisted user claims
result.accessTokenClaims; // raw claims / introspection response, or undefined
result.idTokenClaims;     // raw claims / introspection response, or undefined
```

It validates offline against the issuer's JWKS first, falls back to
introspection for opaque tokens, and, if a `refresh_token` was supplied, refreshes when the token set has expired or nothing else could validate it.

**Every token you pass in has to validate.** If one of them survives no strategy and no refresh replaces it, the call throws `OidcTokenValidationError` rather than returning the other one's claims. A result whose `accessTokenClaims` is missing because the access token failed verification would be indistinguishable from one where you passed no access token at all, which leaves you treating a token nobody could validate as if it had been. So `accessTokenClaims` is present whenever you passed an `access_token`, and `idTokenClaims` whenever you passed an `id_token` — unless a refresh replaced the set with one that has no ID token.

One consequence worth knowing before you ship: if your provider issues *opaque* access tokens and its introspection endpoint is unreachable or refuses your client's credentials, `processTokens` now fails instead of quietly falling back to the ID token alone. That is the intended behaviour — the alternative is an unvalidated access token in your session — but it means opaque access tokens need a working introspection endpoint.

### You must persist a refreshed token set

`processTokens` may transparently refresh the tokens it was given. When that happens it returns the new token set, and **the tokens you passed in are no longer usable**. Most providers rotate (and invalidate) the refresh token on use, so dropping the result means the next request fails and the user is logged out. Always write it back to wherever you keep the session:

```ts
const result = await oidc.processTokens({
  access_token: session.access_token,
  id_token: session.id_token,
  refresh_token: session.refresh_token,
});

if (result.refreshed) {
  await session.set({
    access_token: result.refreshedTokens.access_token,
    id_token: result.refreshedTokens.id_token,
    refresh_token: result.refreshedTokens.refresh_token,
  });
}

return result.user;
```

Note that a refresh replaces the *whole* token set, even when only one of the two tokens had expired persist all three fields, not just the one you think changed. If your session store is a cookie, this means setting the cookie again on that response.

A good idea is to wrap this in a single helper and use it everywhere, so no call site can forget:

```ts
async function requireUser(session) {
  const result = await oidc.processTokens(session.tokens);
  if (result.refreshed) await session.set(result.refreshedTokens);
  return result.user;
}
```
Alternatively, put it inside some middleware or context function so it runs automatically without you having to remember to call it.

### Refreshing explicitly

If you want to drive the refresh yourself (e.g. proactively, before calling a downstream API), `refresh` exchanges a refresh token for a new token set and validates the returned ID token. The same rule applies, persist what you get back:
```ts
const tokens = await oidc.refresh(session.refresh_token);
await session.set(tokens);
```

## Logging out

```ts
const url = await oidc.getLogoutUrl("https://app.example.com/goodbye");
await session.destroy();
redirect(url.toString());
```

This builds an RP-initiated logout URL at the IdP; clear your own session before redirecting. The post-logout redirect URI has to be registered with the provider.

## Fetching UserInfo

`processTokens` never calls UserInfo. If you need claims the tokens don't carry, ask for them explicitly. `expectedSubject` guards against a mismatched response and should be the `sub` you already validated:
```ts
const info = await oidc.fetchUserInfoFromIssuer(session.access_token, result.user.sub);
```

## Errors

Every rejection extends `OidcError`, so one `instanceof` covers them all. They split by whether anything could have made the token acceptable:

- `OidcTokenError` a *permanent* rejection: this token is not one your client may accept, whatever else is true of it. The library does not retry, try another strategy, or spend a refresh token on it. Carries `tokenKind` (`"access"` | `"id"`) and the `claim` or header that failed. Two subclasses:
  - `OidcAudienceError` the token could not be bound to your client, i.e. the wrong `aud`, or an authorized-party claim naming another client.
  - `OidcTokenTypeError` the token is not the *kind* of token it was presented as, e.g. an ID token in the `access_token` slot. See [Token-type binding](#token-type-binding).
- `OidcTokenValidationError` a token you supplied could not be validated by any strategy, and no refresh replaced it. Carries `tokenKinds` (which of the two failed) and `failures` (every strategy's error, with the stage it failed at) — the individual strategies only log theirs at `debug`, so this is where the reason lives.

All of them are a 401. `OidcTokenError` additionally means retrying with the same token is pointless: start a fresh login.

```ts
import { OidcError, OidcTokenError } from "@m1212e/oidc";

try {
  const result = await oidc.processTokens(session.tokens);
  // ...
} catch (err) {
  if (err instanceof OidcTokenError) {
    log.warn(`rejected ${err.tokenKind} token on ${err.claim}: ${err.message}`);
  } else if (err instanceof OidcError) {
    log.warn(err.message); // carries every strategy's failure
  }
  return unauthorized();
}
```

## Local development

Plain-HTTP requests to the IdP are rejected unless development mode is on. It is derived from the environment, enabled only when `NODE_ENV` is exactly `"development"` or set explicitly:

```ts
const oidc = await createOidcCore({
  issuer: "http://localhost:8080/realms/main",
  clientId: "my-app",
  development: true, // never in production; logs a warning when enabled
});
```

An unset `NODE_ENV` counts as production: this switch fails closed on purpose.

## Configuration

| Option | Default | What it does |
| --- | --- | --- |
| `issuer` | — | Issuer URL used for discovery. Required. |
| `clientId` | — | Required. |
| `clientSecret` | — | Omit for a public client (PKCE only, `token_endpoint_auth_method: "none"`). |
| `expectedAudience` | unset | Audience value(s) this resource server answers to, matched against an access token's `aud`. Takes over the access-token binding, so `authorizedPartyClaims` is then not compared to `clientId`. Never applied to ID tokens. |
| `authorizedPartyClaims` | `["azp", "client_id", "cid", "appid"]` | Claims that may name the client an access token was issued to, in priority order; the first present one must equal `clientId`. Used when `expectedAudience` is unset. |
| `verifyAudience` | unset | `(claims, tokenKind) => boolean`. Replaces the built-in audience policy entirely; return `false` to reject. |
| `idTokenOnlyClaims` | `["nonce", "at_hash", "c_hash", "s_hash"]` | Claims whose presence proves a JWT is an ID token, so a token presented as an access token carrying any of them is rejected. |
| `accessTokenTyp` | unset | Require this exact `typ` header on JWT access tokens — `"at+jwt"` (RFC 9068) or `"Bearer"` (Keycloak). |
| `clockTolerance` | `30` | Skew tolerance for `exp`/`nbf`, in seconds or as a duration (`"30 seconds"`, `"5m"`). Applies to offline verification *and* to the ID token validated inside the code exchange and refresh. |
| `signingAlgorithms` | issuer's `id_token_signing_alg_values_supported` | JWS algorithms accepted for offline verification. |
| `development` | from `NODE_ENV` | Allows plain HTTP to the IdP. |
| `logger` | `console` | `{ debug, info, warn, error }`. Overrides `logLevel`. |
| `logLevel` | `"warn"` | `"silent" \| "error" \| "warn" \| "info" \| "debug"`. |

## Audience validation

Every token is checked against the client it was issued to, so a token minted
for a *different* client at the same issuer is rejected. ID tokens and access
tokens get different policies, because the specs give them different rules.

**ID tokens** strict, no configuration:

- `aud` must contain your `clientId`.
- If `azp` is present it must equal `clientId`.
- If `aud` names more than one party, `azp` must be there to say which one requested the token.

**Access tokens** two possible bindings, answering different questions. Which one applies depends on whether you set `expectedAudience`:

- **`expectedAudience` set** *"was this token minted for me, the resource?"* `aud` must intersect it, and `authorizedPartyClaims` is **not** compared to `clientId`. An API is a different party from the client that called it, so requiring both would reject every ordinary API/SPA split: a token with `aud: "api://orders"` and `azp: "the-spa"` is exactly what an orders API should accept.
- **`expectedAudience` unset** *"was this token issued to me, the client?"* The first present claim from `authorizedPartyClaims` must equal `clientId`. This is the only binding available when a provider puts no resource audience on access tokens at all. The default list covers most providers.

A token bindable neither way is rejected, that is the cross-client replay case.

Note the asymmetry: a configured `expectedAudience` is not merely *one* way to pass. A token whose `aud` names some other resource stays rejected even when its `azp` is your `clientId`, because that is audience confusion, one resource server replaying a token at another, and the client binding says nothing about which resource the token was minted for.

Setting `expectedAudience` therefore accepts tokens from any client your IdP lets request that audience, which is normally what a resource server wants: the IdP decides who may ask. If you also need to restrict *which* client called you, `verifyAudience` is the place for it. Remember that it replaces the policy for both token kinds, so re-assert the ID token's `aud` yourself:

```ts
verifyAudience: (claims, tokenKind) => {
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (tokenKind === "id") return aud.includes("my-app");
  return aud.includes("api://orders") && claims.azp === "the-spa";
},
```

## Token-type binding

Nothing in a JWT's signature says what the issuer minted it *for*. An ID token and a JWT access token come off the same key and carry the same `iss`, `sub` and `exp` — and for the providers where `expectedAudience` is unnecessary (stock Keycloak, Cognito), they satisfy the same audience policy too. Unchecked, that makes an ID token a usable bearer credential, which is the one substitution to refuse outright: ID tokens get handed to front ends, logged, and passed to third parties in ways access tokens are not.

RFC 9068 answers this with a `typ` header of `at+jwt`, but that is only usable where the provider sets it — Keycloak sends `Bearer`, Auth0 and Entra ID send a plain `JWT` on both kinds — so it cannot be required by default. What is checked by default are the signals that are conclusive wherever they appear:

**In the `access_token` slot:**

- `nonce`, `at_hash`, `c_hash`, `s_hash` are defined for ID tokens only. An access token has no nonce to echo and carries no hash of itself, so any of them present means an ID token was presented. Configurable via `idTokenOnlyClaims`.
- `token_use` must not say otherwise (Cognito spells the kind out).
- If `accessTokenTyp` is set, the `typ` header must match it.

**In the `id_token` slot:**

- A `typ` of `at+jwt` names an RFC 9068 access token, not an ID token.
- `token_use` must not say otherwise.
- An `events` claim makes it a back-channel logout token, which is otherwise shaped exactly like an ID token.

Failures throw `OidcTokenTypeError`, a permanent rejection — no other strategy and no refresh can turn an ID token into an access token, so nothing is retried and no refresh token is spent.

```ts
const oidc = await createOidcCore({
  issuer: "https://kc.example.com/realms/main",
  clientId: "my-app",

  // Recommended where your provider distinguishes the two by `typ`:
  // "at+jwt" for an RFC 9068 provider, "Bearer" for Keycloak. This is the
  // only *complete* defence — the default claim checks can only catch ID
  // tokens that happen to carry one of those claims.
  accessTokenTyp: "Bearer",
});
```

### Known gap

With `accessTokenTyp` unset, an ID token carrying none of `nonce`, `at_hash`, `c_hash`, `s_hash` or `token_use` is indistinguishable from a JWT access token, and will be accepted as one. Auth0 and Entra ID are the likely cases, since both send `typ: "JWT"` on either kind, and whether their ID tokens carry `at_hash` depends on the flow and configuration. If you accept bearer tokens from callers you do not control, pin `accessTokenTyp`.

## Escape hatch

`oidc.configuration` is the discovered `openid-client` `Configuration`. If you need an endpoint this library doesn't wrap (device flow, client credentials, token revocation), use it directly with `openid-client`'s own functions rather
than re-running discovery.
