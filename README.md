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

Discovery also refuses three issuers outright, because all three faults are
invisible afterwards:

- one whose metadata document names a different `issuer` than the one asked for.
  `openid-client` makes that comparison itself — but only when it had to *derive*
  the metadata URL. Configure `issuer` as a `/.well-known/openid-configuration`
  URL, which nothing stops you doing, and it takes the document's word instead:
  `issuer` becomes a hint rather than a pin, and the document then decides the
  `iss` every token is verified against, the `jwks_uri` those signatures are
  checked with, and the endpoint refresh tokens are spent at. Prefer the issuer
  identifier itself; a `.well-known` URL is compared against the issuer it was
  built from. Entra ID and B2C are checked by origin, since their `/common`
  documents legitimately answer with a `{tenantid}` placeholder.
- one whose `jwks_uri` is not `https` — every token signature is checked against
  the keys fetched from there, so a plaintext fetch is one network attacker away
  from tokens minted for any user. `development: true` permits `http` for a
  local IdP.
- one that advertises `code_challenge_methods_supported` without `S256`. An AS
  that does not understand `code_challenge` simply ignores it and answers the
  code exchange normally, leaving a flow that looks protected and is not — and
  `plain` is no fallback, since a challenge equal to the verifier binds the code
  to nothing. An issuer that advertises the field at all and omits `S256` is
  therefore a refusal rather than a warning; one that advertises no methods at
  all (Cognito, among others, supports PKCE without saying so) logs a warning to
  go and confirm the setting at the IdP.

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
  // A same-site path. Taking it from the request is fine — see below.
  returnTo: req.query.next ?? "/",                 
  // this is the default
  scope: "openid profile email",                   
});
```

`scope` must include `openid`. This is an OIDC login: `resolveSignin` requires
an ID token and checks the `nonce` against it, and neither is something the
provider owes a request that did not ask for `openid`. Omitting it throws a
`TypeError` at `startSignin` rather than failing a redirect later, with whatever
the provider chose to say. For a plain OAuth grant, use
[`oidc.configuration`](#escape-hatch) with `openid-client` directly.

`returnTo` must be a same-site path such as `"/dashboard"`, or an absolute URL
on an origin you listed in [`allowedReturnToOrigins`](#configuration). Anything
else throws `OidcReturnToError` — including `//evil.example.com`, `/\evil.example.com`
and any value carrying a newline or a stray space. An allowlisted absolute
target must also be an `http`/`https` URL with no embedded credentials —
`blob:` and `filesystem:` URLs report the origin of the URL *inside* them, so an
origin match alone is not enough to say where a value navigates.

That check is the reason `req.query.next` above is safe to pass straight
through. Left unvalidated it would be an open redirect, and a post-login one at
that: the victim arrives at the attacker's page having just authenticated and
expecting to land somewhere trusted. `state` does not help here — it stops a
*foreign* authorization response reaching your callback, not a value your own
app put inside it, which comes back intact by design. Catch the error and answer
400 if `next` comes from user input.

You must persist `codeVerifier` and `state` somewhere tied to this browser, a signed/encrypted cookie or a server-side session are good options. You need the values to complete the login. Then redirect the user to `authorizationUrl`.

```ts
setCookie("oidc_verifier", codeVerifier, { httpOnly: true, secure: true, sameSite: "lax" });
setCookie("oidc_state", state, { httpOnly: true, secure: true, sameSite: "lax" });
redirect(authorizationUrl.toString());
```

`state` is an opaque string, it is already embedded in `authorizationUrl`, so do not modify it, just store it and hand it back unchanged.

It carries the OIDC `nonce` alongside the return URL, which is why handing it back unchanged matters: `resolveSignin` reads the nonce out of it to check the ID token against the request that started the login. There is nothing extra for you to store. A nonce is not a secret, only a single-use value that has to be echoed back, so travelling in `state` costs nothing — unlike `codeVerifier`, which is a secret and never goes near the URL.

Because the state is embedded in the authorization URL, the `returnTo` inside it
travels to the IdP and lands in its request logs. Nothing about that is unsafe,
but if the path or its query string carries anything you would rather the
provider not record, put a key in `returnTo` and look the real URL up at the
callback.

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

All three arguments are required. In particular, hand back the `codeVerifier`
you stored: a lost or expired verifier cookie throws a `TypeError` rather than
attempting the exchange, because the underlying client reads a missing verifier
as *"this flow used no PKCE"* and would drop `code_verifier` from the request
entirely — silently unbinding the code from the login that requested it. A
compliant provider refuses that exchange anyway, but PKCE is not a guarantee
this library leaves to the provider.

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
  subject: session.sub,                 // optional, recommended, see below
});

result.user;              // normalized, whitelisted user claims (iss + sub + profile)
result.accessTokenClaims; // raw claims / introspection response, or undefined
result.idTokenClaims;     // raw claims / introspection response, or undefined
```

It validates offline against the issuer's JWKS first, falls back to
introspection for opaque tokens, and, if a `refresh_token` was supplied, refreshes when the token set has expired or nothing else could validate it.

**Key accounts on `result.user.iss` *and* `result.user.sub`.** A `sub` is unique
only *within* an issuer (OIDC Core 2), and plenty of providers mint ones that are
trivially guessable across issuers — a numeric id, a username, an email address.
An application that talks to two IdPs and keys accounts on `sub` alone therefore
lets a subject at one collide with a different person at the other, which is
account takeover with nothing forged. `user.iss` is the issuer every claim set in
the result was actually verified against, not merely what an `iss` claim said, and
`processTokens` always sets it.

`result.user.email` comes with `result.user.email_verified`. Check it before you
key anything on the address: an unverified email is not an identity, and keying
accounts on one is a standard takeover route. Absent means the issuer said
nothing, which is not the same as `false` — treat only `true` as verified.

**A verification flag only ever describes the value it was issued beside.** The
two claim sets are merged with the ID token winning, but per *token* for these
pairs rather than per claim: if the surviving `email` came from the ID token and
that token carried no `email_verified`, the flag is dropped rather than inherited
from the access token. Same for `phone_number` / `phone_number_verified`.

That matters for any session that outlives a profile change. A user who switches
to `ceo@yourcorp.com` gets an ID token naming the new, **unverified** address
while the access token on file still vouches for the old one. Both tokens are
genuine, name the same `sub`, and pass every audience and type check — they just
describe different moments — so a per-claim merge would hand back the new address
marked as verified. A dropped flag reads as "the issuer said nothing", which is
the direction that fails safe. A disagreement between the two is logged at
`warn`.

**Every token you pass in has to validate.** If one of them survives no strategy and no refresh replaces it, the call throws `OidcTokenValidationError` rather than returning the other one's claims. A result whose `accessTokenClaims` is missing because the access token failed verification would be indistinguishable from one where you passed no access token at all, which leaves you treating a token nobody could validate as if it had been. So `accessTokenClaims` is present whenever you passed an `access_token`, and `idTokenClaims` whenever you passed an `id_token` — unless a refresh replaced the set with one that has no ID token.

One consequence worth knowing before you ship: if your provider issues *opaque* access tokens and its introspection endpoint is unreachable or refuses your client's credentials, `processTokens` now fails instead of quietly falling back to the ID token alone. That is the intended behaviour — the alternative is an unvalidated access token in your session — but it means opaque access tokens need a working introspection endpoint.

**The subject cannot change under you.** A refresh replaces the token set, not
the user: if the refreshed tokens name a different `sub` than the ones you
passed in, the call throws `OidcSubjectError` rather than authenticating
whoever the refresh token turned out to belong to.

That comparison needs a subject to compare *against*, and it is read off the
tokens you supplied — which works for JWTs and not for opaque ones. An opaque
access token that no longer introspects (the ordinary expiry case) names no
subject this library can read, so with nothing else in the set there is nothing
to check the refreshed tokens against, and the call says so at `warn` level.
Pass `subject` — the `sub` you already have on file — and the guarantee holds
whatever your provider issues. It is checked even when no refresh happens, so
it also catches a session whose tokens were swapped for another user's:

```ts
const result = await oidc.processTokens({
  access_token: session.access_token,
  refresh_token: session.refresh_token,
  subject: session.sub, // throws OidcSubjectError if the tokens say otherwise
});
```

### Introspection costs a round trip

By default (`introspection: "opaque-only"`) only tokens that are *not* JWTs are
introspected. A JWT the issuer's own JWKS rejected has nothing to gain from it —
spec-compliant servers answer `unsupported_token_type` for structured tokens —
and asking anyway means every junk bearer string an attacker sends becomes an
outbound request to your IdP.

Set `introspection: "auto"` if your provider signs JWT access tokens with keys
outside the JWKS it publishes for ID tokens, or `"never"` to stay fully offline.
Note that a genuinely opaque token is indistinguishable from a fabricated one
without asking the AS, so nothing but `"never"` removes that round trip
entirely — rate-limit unauthenticated requests.

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

**This applies to the failure path too.** `processTokens` can spend the refresh
token and *then* reject what came back. Your stored refresh token is dead from
that moment on wherever the provider rotates it, so the replacement rides on the
error as `err.refreshedTokens`. Persist it there as well, or the session is
unrecoverable — and on a provider with reuse detection, retrying the old token
revokes the whole grant:

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

Every rejection in the hierarchy may carry it, because the obligation comes from
the refresh token having been spent — which is true whatever went wrong
afterwards. The one exception is `OidcSubjectError`: a set minted for a
different subject is not yours to store.

A good idea is to wrap this in a single helper and use it everywhere, so no call site can forget:

```ts
async function requireUser(session) {
  const result = await oidc.processTokens(session.tokens);
  if (result.refreshed) await session.set(result.refreshedTokens);
  return result.user;
}
```
Alternatively, put it inside some middleware or context function so it runs automatically without you having to remember to call it.

### Refresh one session at a time

`processTokens` refreshes whenever the tokens it was handed do not all validate,
and it has no view of the other requests using the same session. A browser that
fires several requests at once against an expired token set therefore starts
several refreshes with the *same* refresh token — one succeeds and the rest
present a token that has just been rotated away.

Where the provider only rotates, that costs a few wasted round trips and leaves
whichever set landed in your store last. Where it also does **reuse detection**
(Auth0, Okta, Keycloak with the option on, `oidc-provider`), a replayed refresh
token is treated as a stolen one and the *entire grant* is revoked — every
session for that user, and no error you can distinguish from a genuine theft.
Reuse detection is a theft alarm; routinely tripping it yourself is both an
outage and the loss of the signal.

The library cannot fix this, because it does not own your session store. Make
the refresh single-flight per session — keep the in-progress promise on the
session and let concurrent callers await the same one:

```ts
const inFlight = new Map<string, Promise<ProcessTokensResult>>();

function processTokensOnce(sessionId: string, tokens: ProcessTokensInput) {
  const existing = inFlight.get(sessionId);
  if (existing) return existing;

  const pending = oidc.processTokens(tokens).finally(() => {
    inFlight.delete(sessionId);
  });
  inFlight.set(sessionId, pending);
  return pending;
}
```

That map is per-process. If you run more than one instance against a shared
session store, the lock has to live there too — a short-lived lock around the
whole "read tokens, validate, write back" step, keyed by session. The other
option is to keep the refresh off the request path entirely: rotate the set
yourself before it expires with [`refresh`](#refreshing-explicitly), from one
place that is already serialized per session.

### Refreshing explicitly

If you want to drive the refresh yourself (e.g. proactively, before calling a downstream API), `refresh` exchanges a refresh token for a new token set and validates the returned ID token. The same rule applies, persist what you get back:
```ts
const tokens = await oidc.refresh(session.refresh_token, {
  expectedSubject: session.sub, // recommended whenever the result replaces a stored set
});
await session.set(tokens);
```

Pass `expectedSubject` wherever the result is going to overwrite a stored token
set. A refresh token is a bearer credential like any other: the exchange proves
it is live, not that it belongs to the session about to be replaced, and what
comes back is correctly signed and internally consistent whoever it belongs to.
OIDC Core 12.2 makes that `sub` comparison a MUST, and it is the check
`processTokens` performs for itself — a direct `refresh` call is otherwise the
one way into this library with no subject binding at all. A mismatch throws
`OidcSubjectError`; a response carrying no ID token cannot be checked and says
so at `warn`.

## Logging out

```ts
const url = await oidc.getLogoutUrl("https://app.example.com/goodbye", {
  idTokenHint: session.id_token, // strongly recommended, see below
});
await session.destroy();
redirect(url.toString());
```

This builds an RP-initiated logout URL at the IdP; clear your own session before redirecting. The post-logout redirect URI has to be registered with the provider — that registration is what decides where the user may actually land, so there is no origin allowlist for it here. It must still be an absolute `http`/`https` URL without embedded credentials (`https://app.example.com@evil.example/`), or `getLogoutUrl` throws `OidcReturnToError`; the same check applies to the `redirectUri` you pass `startSignin`.

Pass `idTokenHint` whenever the ID token is still to hand. Without it the OP
cannot tell which session to end, and RP-Initiated Logout §2 says it SHOULD then
ask the user to confirm — Keycloak 18+ does exactly that, turning a clean logout
into an interstitial page. `client_id` is sent either way, which is what keeps
`post_logout_redirect_uri` honoured. An optional `state` is passed through to
your post-logout endpoint.

One thing logout cannot do: offline JWT validation has no revocation channel, so
an access token already issued stays valid until its `exp` no matter what the
session does. Keep access-token lifetimes short, and use `introspection: "auto"`
if you need every request checked against the AS.

## Fetching UserInfo

`processTokens` never calls UserInfo. If you need claims the tokens don't carry, ask for them explicitly. `expectedSubject` guards against a mismatched response and should be the `sub` you already validated:
```ts
const info = await oidc.fetchUserInfoFromIssuer(session.access_token, result.user.sub);
```

It is a network exchange with the provider, so its failures — a token the OP has
since revoked, a response describing a different subject — arrive as
`OidcUserInfoError`, not as the underlying client's own error.

## Errors

Every rejection extends `OidcError`, so one `instanceof` covers them all. They split by whether anything could have made the token acceptable:

- `OidcTokenError` a *permanent* rejection: this token is not one your client may accept, whatever else is true of it. The library does not retry, try another strategy, or spend a refresh token on it. Carries `tokenKind` (`"access"` | `"id"`) and the `claim` or header that failed. Two subclasses:
  - `OidcAudienceError` the token could not be bound to your client, i.e. the wrong `aud`, or an authorized-party claim naming another client.
  - `OidcTokenTypeError` the token is not the *kind* of token it was presented as, e.g. an ID token or a refresh token in the `access_token` slot. See [Token-type binding](#token-type-binding).
- `OidcTokenValidationError` a token you supplied could not be validated by any strategy, and no refresh replaced it. Carries `tokenKinds` (which of the two failed) and `failures` (every strategy's error, with the stage it failed at) — the individual strategies only log theirs at `debug`, so this is where the reason lives.
- `OidcSubjectError` the tokens do not all describe the same user: the access and ID token disagree, a refresh returned somebody else's session, or they are not the `subject` you said they were. Carries `expected` and `actual`.
- `OidcGrantError` a token-endpoint exchange the provider refused, or that could not be made at all: an expired authorization code, a `state` that did not match the callback's, an IdP that answered `access_denied`, **a refresh token that has expired or been revoked**, a network fault. Carries `grant` (`"authorization_code"` | `"refresh_token"`) and the provider's own error as `cause`. The refresh case is the most common failure a live session meets, and it is a 401 (start a fresh login), not a 500.
- `OidcReturnToError` a redirect target this configuration does not permit. Thrown by `startSignin` for a `returnTo` or `redirectUri` you passed, by `resolveSignin` for a `returnTo` that came back out of the `state`, and by `getLogoutUrl` for a `postLogoutRedirectUri`. Carries the rejected value as `returnTo` — for logging only, never redirect to it. This one is a 400, not a 401.
- `OidcStateError` the stored `state` could not be read back: a truncated cookie, or a value that is not the one `startSignin` returned. A 400.
- `OidcClaimsError` validated claims could not be read as a user, most often an absent `sub` (which RFC 7662 permits in an introspection response).
- `OidcUserInfoError` a `fetchUserInfoFromIssuer` call the provider refused, that could not be made, or whose response did not describe the `expectedSubject` it was asked about. Carries the provider's own error as `cause`.

The token rejections are a 401. `OidcTokenError` additionally means retrying with the same token is pointless: start a fresh login.

Nothing this library does throws a provider error at you: every failure of a
network exchange arrives as `OidcGrantError` or `OidcUserInfoError`, so one
`instanceof OidcError` really is the whole surface. Bad *arguments* stay
`TypeError`s — an unparseable `clockTolerance`, a `processTokens` call with no
tokens at all, a `startSignin` scope without `openid`, a callback with no
`codeVerifier`. Those are bugs, not rejections.

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
It is also what allows a local IdP's `http` `jwks_uri`, which is otherwise refused at discovery.

## Configuration

| Option | Default | What it does |
| --- | --- | --- |
| `issuer` | — | Issuer URL used for discovery. Required. |
| `clientId` | — | Required. |
| `clientSecret` | — | Omit for a public client (PKCE only, `token_endpoint_auth_method: "none"`). |
| `expectedAudience` | unset | Audience value(s) this resource server answers to, matched against an access token's `aud`. Takes over the access-token binding, so `authorizedPartyClaims` is then not compared to `clientId`. Never applied to ID tokens. Every entry must be a non-empty string — an empty one is refused rather than dropped, since dropping the last one would silently swap this binding for the authorized-party one. |
| `authorizedPartyClaims` | `["azp", "client_id", "cid", "appid"]` | Claims that may name the client an access token was issued to, in priority order; the first present one must equal `clientId`. Used when `expectedAudience` is unset. |
| `verifyAudience` | unset | `(claims, tokenKind) => boolean`. Replaces the built-in audience policy entirely — including the otherwise non-configurable ID-token rules, so re-assert those too; return `false` to reject. Setting it alongside `expectedAudience` discards the latter, and warns. |
| `idTokenOnlyClaims` | `["nonce", "at_hash", "c_hash", "s_hash"]` | Claims whose presence proves a JWT is an ID token, so a token presented as an access token carrying any of them is rejected. |
| `accessTokenTyp` | unset | Require this exact `typ` **JWS header** on JWT access tokens — normally `"at+jwt"` (RFC 9068). Not a claim; see the note under [Token-type binding](#token-type-binding) before setting it for Keycloak. |
| `requireIntrospectedTokenType` | `true` | An introspection response must name the kind it was presented as (`token_type`/`typ`/`token_use`), in both the access and the id slot. Turning this off re-opens refresh-token substitution. |
| `introspection` | `"opaque-only"` | When to fall back to introspection: `"opaque-only"`, `"auto"`, or `"never"`. |
| `allowedReturnToOrigins` | `[]` | Origins an absolute `returnTo` may name; it must also be `http`/`https` and carry no credentials. Empty means same-site paths only. |
| `clockTolerance` | `30` | Skew tolerance for `exp`/`nbf`, in seconds or as a duration (`"30 seconds"`, `"5m"`). Applies to offline verification *and* to the ID token validated inside the code exchange and refresh. |
| `signingAlgorithms` | issuer's `id_token_signing_alg_values_supported`, else `DEFAULT_SIGNING_ALGORITHMS` | JWS algorithms accepted for offline verification. Never left unpinned. A discovered list is filtered to what a public key can actually verify — `none` and the symmetric `HS*` algorithms several providers advertise are dropped. An explicit list is taken as given, symmetric algorithms included — every offline verification uses a key from the issuer's *public* JWKS, so pinning an `HS*` there is asking for algorithm confusion. Scoped to `processTokens`: the ID token inside the code exchange and a refresh comes straight from the token endpoint over TLS and is held to the issuer's own advertised list by `openid-client`. |
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

Setting `expectedAudience` therefore accepts tokens from any client your IdP lets request that audience, which is normally what a resource server wants: the IdP decides who may ask. If you also need to restrict *which* client called you, `verifyAudience` is the place for it. Remember that it replaces the policy for both token kinds — including any `expectedAudience` you set, which is then not checked at all, and warns — so re-assert both yourself:

```ts
verifyAudience: (claims, tokenKind) => {
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (tokenKind === "id") return aud.includes("my-app");
  return aud.includes("api://orders") && claims.azp === "the-spa";
},
```

## Token-type binding

Nothing in a JWT's signature says what the issuer minted it *for*. An ID token and a JWT access token come off the same key and carry the same `iss`, `sub` and `exp` — and for the providers where `expectedAudience` is unnecessary (stock Keycloak, Cognito), they satisfy the same audience policy too. Unchecked, that makes an ID token a usable bearer credential, which is the one substitution to refuse outright: ID tokens get handed to front ends, logged, and passed to third parties in ways access tokens are not.

The same goes for a **refresh token**, and worse: it typically outlives an access
token by weeks. It fails offline verification if it is opaque — but then reaches
introspection, where `active: true`, your `client_id` and the user's `sub` all
check out.

What is checked by default are the signals that are conclusive wherever they
appear:

**In the `access_token` slot:**

- `nonce`, `at_hash`, `c_hash`, `s_hash` are defined for ID tokens only. An access token has no nonce to echo and carries no hash of itself, so any of them present means an ID token was presented. Configurable via `idTokenOnlyClaims`.
- A `typ` *claim* naming another kind — Keycloak's `ID`, `Refresh`, `Offline`. Values it does not recognize (a bare `JWT`, a provider's own vocabulary) are ignored rather than treated as evidence.
- `token_use` must not say otherwise (Cognito spells the kind out).
- An `events` claim, which makes it a back-channel logout token. Checked in this slot too, not only the obvious one: a logout token must *not* carry a `nonce` (OIDC Back-Channel Logout 1.0 §2.4), so nothing above catches it, and it satisfies the access-token binding unchanged — same issuer, same `aud`, same `azp`.
- For an introspection response: it must *affirmatively* name an access token via `token_type`, `typ` or `token_use`. See below.
- If `accessTokenTyp` is set, the `typ` header must match it.

**In the `id_token` slot:**

- A `typ` header of `at+jwt` names an RFC 9068 access token, not an ID token.
- A `typ` claim naming another kind (Keycloak's `Bearer`, `Refresh`).
- `token_use` must not say otherwise.
- An `events` claim makes it a back-channel logout token, which is otherwise shaped exactly like an ID token.
- For an introspection response: it must *affirmatively* name an ID token, exactly as the access slot must name an access token. The ID-token-only claims above are of course **not** applied here — a response echoing `nonce` or `at_hash` is an ID token doing what ID tokens do.

Both slots matter. An access token — or, far worse, a refresh token — put in
the `id_token` slot introspects just as successfully as in the other one and
satisfies the client binding identically, so leaving that slot unchecked simply
moves the substitution one field to the right.

Failures throw `OidcTokenTypeError`, a permanent rejection — no other strategy and no refresh can turn one kind of token into another, so nothing is retried and no refresh token is spent.

### Introspection responses must name their type

RFC 7662 has one endpoint for every token type an AS issues, so `active: true`
says the token is live — not *which kind* it is. Since §2.2 defines
`token_type` as the RFC 6749 §7.1 type, which only an access token has, a
compliant AS describing a refresh token has nothing to put there. An absent type
is therefore the refresh-token case in practice: `oidc-provider` returns
`token_type: "Bearer"` for access tokens and omits it entirely for refresh
tokens; Keycloak distinguishes them by the `typ` claim it echoes.

So a response has to say what it describes, in either slot. For the ID-token
slot that is stricter than the spec can justify on its own — an AS has no
standard field naming an ID token — but it costs nothing in practice, because
an ID token *is* a JWT by definition and is verified against the JWKS; the
introspection path is only reached when that was impossible or failed, and a
response that will not say what it describes is not something to authenticate a
user on. Providers that answer at all do name the kind: Keycloak echoes
`typ: "ID"`, Cognito `token_use: "id"`.

Set `requireIntrospectedTokenType: false` only if your provider omits the type
on genuine tokens — that re-opens the substitution in both slots, so pin
`expectedAudience` as well if you must.

### `accessTokenTyp` is the header, not the claim

Easy to conflate, and Keycloak is where it bites. Keycloak names the kind
(`Bearer` / `ID` / `Refresh`) in a **payload claim** — checked automatically, per
the lists above — while its JWS **header** says `JWT` unless you enable its
RFC 9068 option. `accessTokenTyp` pins the header, so `accessTokenTyp: "Bearer"`
would reject every Keycloak access token.

```ts
const oidc = await createOidcCore({
  issuer: "https://kc.example.com/realms/main",
  clientId: "my-app",

  // Only where the provider really does set an RFC 9068 header: an
  // RFC 9068-native AS, or Keycloak with its "add typ header" option on.
  accessTokenTyp: "at+jwt",
});
```

A header that *does* name a kind is read in both slots even with
`accessTokenTyp` unset — `typ: "id+jwt"` in the access slot and `typ: "at+jwt"`
in the id slot are the same substitution as the claim cases above, merely spelled
in the header. Requiring a header is a configuration decision; believing one that
names the wrong kind never was. Values the vocabulary does not recognize — `"JWT"`
above all — say nothing either way and are not rejections.

### Residual gap

An ID token carrying *none* of the above — no `nonce`, no `at_hash`, no `typ` or
`token_use` claim, and a header that names nothing — presented as a JWT access
token is still indistinguishable from one. Auth0 and Entra ID are the likely
cases: both send `typ: "JWT"` in the header, neither sets a payload type claim,
and whether their ID tokens carry `at_hash` depends on the flow. If you accept
bearer tokens from callers you do not control, pin `expectedAudience` (an ID
token's `aud` is your client id, so it cannot match a resource audience) or
`accessTokenTyp`.

### Sender-constrained tokens are not verified as such

If the issuer bound an access token to a key — RFC 9449 DPoP (`cnf.jkt`) or
RFC 8705 mTLS (`cnf["x5t#S256"]`) — this library cannot check that binding, and
does not pretend to. Proving it needs the DPoP proof header or the TLS client
certificate of the request the token arrived on, and `processTokens` is handed
token strings, never a request.

Everything else still passes: the signature, the issuer, the audience, the type.
So the token validates and is then usable by anyone who stole it, which is the one
thing the constraint was turned on to prevent. The first time a `cnf` claim is
seen, `processTokens` says so at `warn` level, once per instance — a
sender-constrained token silently degrading to a bearer token is not something to
find out from an incident.

If you accept access tokens from callers you do not control and your AS issues
bound ones, verify the proof at the edge — a gateway that does DPoP, or
`oauth4webapi`'s `validateJwtAccessToken` with the DPoP options — and use this
library for what it does check.

## Escape hatch

`oidc.configuration` is the discovered `openid-client` `Configuration`. If you need an endpoint this library doesn't wrap (device flow, client credentials, token revocation), use it directly with `openid-client`'s own functions rather
than re-running discovery.
