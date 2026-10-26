/**
 * Delegation, as RFC 8693 (Token Exchange) defines it: a token whose `act`
 * claim names a party acting on the subject's behalf. The subject is still
 * the user, but the caller is someone else, and an app that ignores `act`
 * treats the actor's request as the user's own. Configure via
 * {@link OidcCoreOptions.delegation} on `createOidcCore`.
 *
 * Impersonation, the other half of RFC 8693, leaves no trace in the token
 * at all, so there is nothing to check for it here.
 */

import { OidcTokenError, type TokenKind } from "./errors";

/** One party in a delegation chain. */
export type Actor = {
  /** The actor's subject identifier at {@link iss}. */
  sub: string;
  /** The issuer `sub` belongs to, when the token names one. */
  iss?: string;
};

/**
 * What to do with a delegated token: `"reject"` (the default), `"allow"`,
 * or a function returning `true` to accept the given chain.
 */
export type DelegationPolicy =
  | "reject"
  | "allow"
  | ((actors: readonly Actor[], tokenKind: TokenKind) => boolean);

/** Thrown when a delegated token isn't accepted, or its `act` is malformed. */
export class OidcDelegationError extends OidcTokenError {
  /** The chain the token carried, current actor first. Empty if malformed. */
  readonly actors: readonly Actor[];

  constructor(tokenKind: TokenKind, actors: readonly Actor[], message: string) {
    super(tokenKind, "act", message);
    this.name = "OidcDelegationError";
    this.actors = actors;
  }
}

/** Deeper chains than this are refused rather than walked. */
const MAX_CHAIN_LENGTH = 16;

/**
 * The delegation chain a token's claims carry, current actor first: the
 * outer `act` is whoever is calling now, each nested `act` the party that
 * delegated to it before. Empty for an ordinary token.
 */
export function actorsOf(claims: unknown, tokenKind: TokenKind): Actor[] {
  const actors: Actor[] = [];
  let act = (claims as { act?: unknown } | undefined)?.act;

  while (act !== undefined && act !== null) {
    if (actors.length === MAX_CHAIN_LENGTH) {
      throw new OidcDelegationError(
        tokenKind,
        [],
        `${tokenKind} token "act" chain is longer than ${MAX_CHAIN_LENGTH} actors`,
      );
    }
    const { sub, iss } = act as { sub?: unknown; iss?: unknown };
    if (
      typeof act !== "object" ||
      Array.isArray(act) ||
      typeof sub !== "string" ||
      sub.length === 0 ||
      (iss !== undefined && typeof iss !== "string")
    ) {
      throw new OidcDelegationError(
        tokenKind,
        [],
        `${tokenKind} token carries a malformed "act" claim: each actor must be an object with a non-empty string "sub"`,
      );
    }
    actors.push(iss === undefined ? { sub } : { sub, iss });
    act = (act as { act?: unknown }).act;
  }

  return actors;
}

/**
 * Checks a verified token's (or introspection response's) delegation
 * chain against the policy, and returns it.
 */
export function assertDelegationAllowed(
  claims: unknown,
  tokenKind: TokenKind,
  policy: DelegationPolicy,
): Actor[] {
  const actors = actorsOf(claims, tokenKind);
  if (!actors.length || policy === "allow") return actors;

  if (policy === "reject") {
    throw new OidcDelegationError(
      tokenKind,
      actors,
      `${tokenKind} token is delegated: ${actors[0]?.sub} is acting on behalf of the subject. Delegated tokens are refused unless "delegation" is set to "allow" or a function that accepts this chain.`,
    );
  }
  if (!policy(actors, tokenKind)) {
    throw new OidcDelegationError(
      tokenKind,
      actors,
      `the "delegation" policy rejected the ${tokenKind} token's actor chain (${actors.map((actor) => actor.sub).join(" <- ")})`,
    );
  }
  return actors;
}

export function buildDelegationPolicy(
  delegation: DelegationPolicy | undefined,
): DelegationPolicy {
  if (delegation === undefined) return "reject";
  if (
    delegation !== "reject" &&
    delegation !== "allow" &&
    typeof delegation !== "function"
  ) {
    throw new TypeError(
      `invalid delegation (${JSON.stringify(delegation)}): expected "reject", "allow", or a function`,
    );
  }
  return delegation;
}
