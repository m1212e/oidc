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

The login is two HTTP endpoints in your app: one that starts the flow, one that the IdP redirects back to. The library gives you a function for each but you own the storage in between.

### 1. Start the flow

```ts
// GET /login
const { authorizationUrl, codeVerifier, state } = await oidc.startSignin({
  // your own callback endpoint => Where should the user land for login resolve?
  // Must match a handler calling the resolve function from this library
  redirectUri: "https://app.example.com/callback", 
  // where to land after completing the login? (user home page/dashboard etc.)
  // A same-site path. Taking it from the request is a good approach.
  returnTo: req.query.next ?? "/dashboard",                 
  // this is the default and will determine what kind of information ends up in your tokens or what 
  // the issues session is allowed to do
  scope: "openid profile email",                   
});
```

`returnTo` must be a same-site path such as `"/dashboard"`, or an absolute URL
on an origin you listed in [`allowedReturnToOrigins`](#configuration). Anything
else throws `OidcReturnToError`.

You must persist `codeVerifier` and `state` somewhere tied to this browser, a signed/encrypted cookie or a server-side session are good options. You need the values to complete the login. Then redirect the user to `authorizationUrl`.

```ts
// can be stored elsewhere, but must be tied to the browser. In this example we use cookies
setCookie("oidc_verifier", codeVerifier, { httpOnly: true, secure: true, sameSite: "lax" });
setCookie("oidc_state", state, { httpOnly: true, secure: true, sameSite: "lax" });
redirect(authorizationUrl.toString());
```

### 2. Handle the callback

```ts
// GET /callback
const { tokens, returnTo } = await oidc.resolveSignin({
  // the full callback URL, (including query params like ?code=&state=)
  callbackUrl: new URL(req.url),
  codeVerifier: getCookie("oidc_verifier"), // the code verifier you stored in the first step
  expectedState: getCookie("oidc_state"),   // the state you stored in the first step
});
```
Store the token set somewhere (cookies/session store are viable options) and redirect the user to `returnTo`.

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

`processTokens` is the function to call on every authenticated request. Pass whatever tokens you stored, at least one of `access_token` or `id_token` is required. If you want to authenticate/authorize a request, it is recommended to pass at least the access token.

```ts
const result = await oidc.processTokens({
  access_token: session.access_token ?? null, // when we do not have an access token, pass null to ensure that processTokens throws an error
  id_token: session.id_token,
  refresh_token: session.refresh_token, // optional, see below
  subject: session.sub,                 // optional, recommended, the user ID you expect to be in the tokens
});

result.user;              // normalized, whitelisted user claims (iss + sub + profile)
result.accessTokenClaims; // raw claims / introspection response, or undefined
result.idTokenClaims;     // raw claims / introspection response, or undefined
```
> If you would like to ensure that a value is present, defaulting to an invalid value if undefined is a good idea. For example, if you want to ensure that `access_token` is present and a valid value, you can pass `{ access_token: session.access_token ?? null }` which will pass `null` instead of `undefined` if the value is not present. This will ensure that `processTokens` will throw an error if the user does not provide a valid access token. Ofcourse you can (and should) check the token presence in your store manually before calling the processTokens function, but this is a good safety net to ensure that the function will throw an error if the token is not present.


It validates offline against the issuer's JWKS first, falls back to
introspection for opaque tokens, and, if a `refresh_token` was supplied, refreshes when the token set has expired or nothing else could validate it.

### Persisting refreshed tokens

`processTokens` may transparently refresh the tokens it was given. When that happens it returns the new token set, and **the tokens you passed in are no longer usable**. Most providers rotate (and invalidate) the refresh token on use, so dropping the result means the next request fails and the user is logged out. Always write it back to wherever you keep the session:

```ts
const result = await oidc.processTokens({
  access_token: session.access_token,
  id_token: session.id_token,
  refresh_token: session.refresh_token, // when the validation fails, this will be used to refresh the tokens
});

if (result.refreshed) {
  await session.set({
    access_token: result.refreshedTokens.access_token,
    id_token: result.refreshedTokens.id_token,
    refresh_token: result.refreshedTokens.refresh_token,
  });
  // or in cookies if you use that
}

return result.user;
```

Note that a refresh replaces the *whole* token set, even when only one of the two tokens had expired persist all three fields, not just the one you think changed. If your session store is a cookie, this means setting the cookie again on that response.

**This applies to the failure path too.** `processTokens` can spend the refresh
token and *then* reject what came back. Your stored refresh token is dead from
that moment on wherever the provider rotates it, so the replacement rides on the
error as `err.refreshedTokens`. Persist it there as well, or the session is
lost.

```ts
try {
  const result = await oidc.processTokens(session.tokens);
  if (result.refreshed) await session.set(result.refreshedTokens);
  return result.user;
} catch (err) {
  if (err instanceof OidcError && err.refreshedTokens) {
    await session.set(err.refreshedTokens);
  }
  throw err;
}
```

> A good idea is to wrap this in a single helper and use it everywhere, so no call site can forget. Alternatively, put it inside some middleware or context function so it runs automatically without you having to remember to call it.

### Refreshing explicitly

If you want to drive the refresh yourself (e.g. proactively, before calling a downstream API), `refresh` exchanges a refresh token for a new token set and validates the returned ID token. The same rule applies, persist what you get back:
```ts
const tokens = await oidc.refresh({
  refreshToken: session.refresh_token,
  expectedSubject: session.sub, // what you expect for the subject value (often the user ID)
});
await session.set(tokens);
```

## Logging out

```ts
const url = await oidc.getLogoutUrl({
  postLogoutRedirectUri: "https://app.example.com/goodbye",
  idTokenHint: session.id_token, // recommended to set
});
await session.destroy(); // or delete cookies
redirect(url.toString());
```

This builds an RP-initiated logout URL at the IdP, clear your own session before redirecting.

## Fetching UserInfo

`processTokens` never calls UserInfo. If you need claims the tokens don't carry, ask for them explicitly. `expectedSubject` guards against a mismatched response and should be the `sub` you already validated:
```ts
const info = await oidc.fetchUserInfoFromIssuer({
  accessToken: session.access_token,
  expectedSubject: session.sub,
});
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

## Escape hatch

`oidc.configuration` is the discovered `openid-client` `Configuration`. If you need an endpoint this library doesn't wrap (device flow, client credentials, token revocation), use it directly with `openid-client`'s own functions rather
than re-running discovery.
