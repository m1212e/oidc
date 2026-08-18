# @m1212e/oidc

Issuer-agnostic OIDC token handling for resource servers: discovery, offline
JWT validation with introspection fallback, refresh, and claim normalization.

## Audience validation

Every token is checked against the client it was issued to, so a token minted
for a *different* client at the same issuer is rejected. ID tokens and access
tokens get different policies, because the specs give them different rules.

**ID tokens** — strict, no configuration:

- `aud` must contain your `clientId` (OIDC Core 3.1.3.7 step 3).
- If `azp` is present it must equal `clientId`.
- If `aud` names more than one party, `azp` must be there to say which one
  requested the token.

**Access tokens** — configurable, because providers disagree. RFC 9068
specifies a `client_id` claim, but Keycloak, Auth0 and Entra ID use `azp`,
Okta uses `cid`, and Entra v1 uses `appid`:

- The first present claim from `authorizedPartyClaims` must equal `clientId`.
  Defaults to `["azp", "client_id", "cid", "appid"]`, which covers all of the
  above with no configuration.
- If `expectedAudience` is set, `aud` must intersect it.
- At least one of those two checks must actually run. A token that can be
  bound to neither a client nor a resource is rejected — that is exactly the
  cross-client replay case.

An access token's `aud` is **never** compared against `clientId`. Stock
Keycloak issues access tokens with `aud: "account"` and the real client in
`azp`, so that comparison would reject every default Keycloak deployment.

```ts
const core = await createOidcCore({
  issuer: "https://kc.example.com/realms/main",
  clientId: "my-app",

  // Optional. Set this only if your IdP puts a resource audience on access
  // tokens — e.g. an Auth0 API identifier, or Keycloak with an Audience
  // protocol mapper. Leave unset for stock Keycloak or Cognito.
  expectedAudience: "api://orders",

  // Optional. Add a provider-specific claim, or reorder the defaults.
  authorizedPartyClaims: ["azp", "client_id", "cid", "appid"],

  // Optional. Replaces the built-in policy entirely, for providers that fit
  // none of the above. Return false to reject.
  verifyAudience: (claims, tokenKind) => claims.azp === "my-app",

  // Optional. Clock skew tolerance for exp/nbf. Defaults to 30s.
  clockTolerance: 30,

  // Optional. Defaults to the issuer's advertised
  // id_token_signing_alg_values_supported.
  signingAlgorithms: ["RS256"],
});
```

### What this library actually implements

Generic JWT validation is delegated to `jose` rather than reimplemented here:
signature, `iss`, `aud`, expiry with skew tolerance, required-claim presence
and algorithm pinning all go through `jwtVerify`'s options.

What remains in this codebase is the part no library covers, because it isn't
standardized: resolving *which client* an access token was issued to across
providers that spell it `azp`, `client_id`, `cid` or `appid`. `azp` appears
nowhere in `jose`, `oauth4webapi`'s `validateJwtAccessToken` hard-requires
RFC 9068's `typ: at+jwt` (Keycloak sends `Bearer`), and `openid-client`
exposes no resource-server entrypoint at all.

Introspection responses are the one place the full `aud` check still runs
locally — they never pass through `jwtVerify`.

Failures throw `OidcAudienceError`, which carries `tokenKind` (`"access"` or
`"id"`) and the `claim` that failed. It is treated as a **permanent**
rejection: unlike a signature or expiry failure, it short-circuits the
validation fallback chain rather than trying introspection, UserInfo, or
spending a refresh token — none of which can turn someone else's token into
yours.

### Known gap

`processTokens` can fall back to the UserInfo endpoint when a token is opaque
and introspection is unavailable. UserInfo responses carry no `aud` or `azp`,
so those claims cannot be bound to your client — they only prove the AS still
accepts the access token. When identity resolves from UserInfo alone, the
library logs a warning. Prefer an issuer with JWT access tokens or a reachable
introspection endpoint.
