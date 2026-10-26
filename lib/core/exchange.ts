import { genericGrantRequest } from "openid-client";
import {
  OidcGrantError,
  OidcInputError,
  type RefreshedTokenSet,
} from "../errors";
import type { CoreContext } from "./context";
import { assertGrantedIdToken } from "./grant";

const TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

export type ExchangeTokenInput = {
  /** The token of the user the new one is for. */
  subjectToken: string;
  /** Defaults to `urn:ietf:params:oauth:token-type:access_token`. */
  subjectTokenType?: string;
  /**
   * The token of the party acting on the user's behalf. With it, the
   * exchange is a delegation and the issued token names the actor in its
   * `act` claim. Without it, the exchange is an impersonation and the
   * issued token is indistinguishable from the user's own.
   */
  actorToken?: string;
  /** Defaults to `urn:ietf:params:oauth:token-type:access_token`. */
  actorTokenType?: string;
  /** Logical name(s) of the service the token is for, e.g. a client id. */
  audience?: string | readonly string[];
  /** URI(s) of the resource the token is for (RFC 8707). */
  resource?: string | readonly string[];
  scope?: string;
  /** The kind of token to issue, e.g. `urn:ietf:params:oauth:token-type:access_token`. */
  requestedTokenType?: string;
  /**
   * Provider-specific extras, e.g. Keycloak's `requested_subject` to
   * impersonate a user without their token.
   */
  additionalParameters?: Readonly<Record<string, string>>;
};

function assertNonEmpty(value: unknown, label: string): void {
  if (value !== undefined && (typeof value !== "string" || !value)) {
    throw new OidcInputError(
      `exchangeToken was given a \`${label}\` that is not a non-empty string`,
    );
  }
}

function toList(value: string | readonly string[] | undefined): string[] {
  if (value === undefined) return [];
  return typeof value === "string" ? [value] : [...value];
}

/**
 * Parameters the request sets itself or takes from a named input. Passing
 * them through `additionalParameters` would sneak past those inputs'
 * checks, so they are refused there.
 */
const RESERVED_PARAMETERS = new Set([
  "grant_type",
  "subject_token",
  "subject_token_type",
  "actor_token",
  "actor_token_type",
  "audience",
  "resource",
  "scope",
  "requested_token_type",
  "client_id",
  "client_secret",
  "client_assertion",
  "client_assertion_type",
]);

function assertExchangeInput(input: ExchangeTokenInput): void {
  if (typeof input.subjectToken !== "string" || !input.subjectToken) {
    throw new OidcInputError(
      "exchangeToken needs a `subjectToken`: the token of the user the new one is for",
    );
  }
  assertNonEmpty(input.subjectTokenType, "subjectTokenType");
  assertNonEmpty(input.actorToken, "actorToken");
  assertNonEmpty(input.actorTokenType, "actorTokenType");
  assertNonEmpty(input.requestedTokenType, "requestedTokenType");
  for (const key of Object.keys(input.additionalParameters ?? {})) {
    if (RESERVED_PARAMETERS.has(key)) {
      throw new OidcInputError(
        `exchangeToken was given \`${key}\` in \`additionalParameters\`. Use its own option instead, where there is one`,
      );
    }
  }
  if (input.actorTokenType && !input.actorToken) {
    throw new OidcInputError(
      "exchangeToken was given an `actorTokenType` without an `actorToken`",
    );
  }
}

/**
 * The token request body, as URLSearchParams since `audience` and
 * `resource` may repeat.
 */
function exchangeParameters(input: ExchangeTokenInput): URLSearchParams {
  const parameters = new URLSearchParams({
    ...input.additionalParameters,
    subject_token: input.subjectToken,
    subject_token_type: input.subjectTokenType ?? ACCESS_TOKEN_TYPE,
  });
  if (input.actorToken) {
    parameters.set("actor_token", input.actorToken);
    parameters.set(
      "actor_token_type",
      input.actorTokenType ?? ACCESS_TOKEN_TYPE,
    );
  }
  for (const audience of toList(input.audience)) {
    parameters.append("audience", audience);
  }
  for (const resource of toList(input.resource)) {
    parameters.append("resource", resource);
  }
  if (input.scope) parameters.set("scope", input.scope);
  if (input.requestedTokenType) {
    parameters.set("requested_token_type", input.requestedTokenType);
  }
  return parameters;
}

/**
 * RFC 8693 token exchange: trades a user's token for a new one, usually
 * for another audience, either as the user (impersonation) or with an
 * actor named in `act` (delegation).
 *
 * The issued token is returned as is. It is usually meant for another
 * service, so this client's audience policy doesn't apply to it. An id
 * token in the response is still validated like any other grant's.
 */
export function createExchangeToken(ctx: CoreContext) {
  return async function exchangeToken(
    input: ExchangeTokenInput,
  ): Promise<RefreshedTokenSet> {
    assertExchangeInput(input);

    let tokens: RefreshedTokenSet;
    try {
      tokens = await genericGrantRequest(
        ctx.config,
        TOKEN_EXCHANGE_GRANT,
        exchangeParameters(input),
      );
    } catch (err) {
      throw new OidcGrantError(
        "token_exchange",
        `could not exchange the token: ${err instanceof Error ? err.message : String(err)}`,
        { cause: err },
      );
    }
    // The `access_token` field holds whatever was issued (RFC 8693 2.2.1), so
    // a different kind of token must not pass for an access token.
    const expected = input.requestedTokenType ?? ACCESS_TOKEN_TYPE;
    const issued = tokens.issued_token_type;
    if (issued !== undefined && issued !== expected) {
      throw new OidcGrantError(
        "token_exchange",
        `the provider issued a ${String(issued)} instead of the requested ${expected}`,
      );
    }
    assertGrantedIdToken(ctx, tokens);
    return tokens;
  };
}
