/**
 * The two offline-first validation strategies `processTokens` falls back
 * through: local JWKS verification, then remote introspection. Split out of
 * `core.ts` so each strategy can be read (and reasoned about) on its own —
 * both report through the same shape so `processTokens` can treat them
 * identically.
 */

import {
  decodeJwt,
  decodeProtectedHeader,
  errors,
  type JWTVerifyOptions,
  jwtVerify,
} from "jose";
import type { Configuration } from "openid-client";
import { tokenIntrospection } from "openid-client";
import {
  type AudienceClaims,
  type AudiencePolicy,
  assertAudienceAfterJwtVerify,
  assertTokenAudience,
  OidcAudienceError,
} from "./audience";
import {
  OidcTokenError,
  type TokenKind,
  type TokenValidationFailure,
} from "./errors";
import type { Logger } from "./logger";
import {
  assertIntrospectedAccessToken,
  assertIntrospectedIdToken,
  assertTokenTypeAfterJwtVerify,
  type TokenTypePolicy,
} from "./tokenType";
import type { AccessTokenClaims, IdTokenClaims } from "./types";

/** Three base64url segments — the compact JWS serialization, shape only. */
const JWS_COMPACT = /^[\w-]+\.[\w-]*\.[\w-]+$/;

/**
 * Whether a token is a JWT at all, as opposed to an opaque handle.
 *
 * Decides whether introspection has anything to add: a JWT the issuer's own
 * JWKS couldn't verify won't be rehabilitated by asking the AS about it — a
 * spec-compliant server answers `unsupported_token_type` for structured
 * tokens — so that round trip is pure cost, and cost an attacker controls.
 */
export function looksLikeJwt(token: string): boolean {
  if (!JWS_COMPACT.test(token)) return false;
  try {
    return typeof decodeProtectedHeader(token).alg === "string";
  } catch {
    return false;
  }
}

export function subjectOf(claims: unknown): string | undefined {
  const sub = (claims as { sub?: unknown } | undefined)?.sub;
  return typeof sub === "string" && sub.length > 0 ? sub : undefined;
}

/**
 * The `sub` a supplied JWT names, read without verifying anything.
 *
 * Sound only because of how it's used: as an *additional constraint* on what
 * a refresh may return, never as grounds for accepting anything — a forged
 * value can only make the later check stricter.
 */
export function unverifiedSubject(token?: string): string | undefined {
  if (!token || !looksLikeJwt(token)) return undefined;
  try {
    return subjectOf(decodeJwt(token));
  } catch {
    return undefined;
  }
}

/**
 * Collects the outcome of running one validation strategy across both token
 * slots, distinguishing a permanent rejection (`fatal`) from an ordinary
 * failure that another strategy or a refresh might still resolve.
 */
class StrategyOutcome {
  accessTokenValue: AccessTokenClaims;
  idTokenValue: IdTokenClaims;
  failures: TokenValidationFailure[] = [];
  expired = false;
  fatal: OidcTokenError | undefined;

  constructor(private log: Logger) {}

  /**
   * A token that names another client, or isn't the kind it was presented
   * as, is a permanent rejection — no other strategy and no refresh can turn
   * it into ours. Captured here rather than thrown directly, since
   * `Promise.allSettled` would otherwise swallow it.
   */
  onError(kind: TokenKind, stage: string) {
    return (err: unknown) => {
      if (err instanceof OidcTokenError) {
        this.fatal ??= err;
        return;
      }
      if (
        err instanceof errors.JWTClaimValidationFailed &&
        err.claim === "aud"
      ) {
        this.fatal ??= new OidcAudienceError(kind, "aud", err.message);
        return;
      }
      if (err instanceof errors.JWTExpired) this.expired = true;
      this.failures.push({ tokenKind: kind, stage, error: err });
      this.log.debug(
        `[oidc] ${kind} token ${stage} failed:`,
        (err as Error).message,
      );
    };
  }
}

/**
 * Strategy 1: verify both tokens locally against the issuer's JWKS.
 *
 * A JWKS-detected expiry is reported via `expired` so `processTokens` can
 * skip straight to a refresh instead of also trying introspection, which
 * would either fail the same way or waste a round trip on a token that's
 * simply stale.
 */
export async function verifyTokensLocally(
  jwks: Parameters<typeof jwtVerify>[1],
  tokens: { access?: string; id?: string },
  jwtVerifyOptionsFor: (tokenKind: TokenKind) => JWTVerifyOptions,
  tokenTypePolicy: TokenTypePolicy,
  audiencePolicy: AudiencePolicy,
  log: Logger,
): Promise<StrategyOutcome> {
  const outcome = new StrategyOutcome(log);
  const promises: Promise<void>[] = [];

  if (tokens.access) {
    promises.push(
      jwtVerify(tokens.access, jwks, jwtVerifyOptionsFor("access"))
        .then((result) => {
          assertTokenTypeAfterJwtVerify(
            result.payload as AudienceClaims,
            result.protectedHeader,
            "access",
            tokenTypePolicy,
          );
          assertAudienceAfterJwtVerify(
            result.payload as AudienceClaims,
            "access",
            audiencePolicy,
          );
          outcome.accessTokenValue = result.payload;
        })
        .catch(outcome.onError("access", "JWT verification")),
    );
  }
  if (tokens.id) {
    promises.push(
      jwtVerify(tokens.id, jwks, jwtVerifyOptionsFor("id"))
        .then((result) => {
          assertTokenTypeAfterJwtVerify(
            result.payload as AudienceClaims,
            result.protectedHeader,
            "id",
            tokenTypePolicy,
          );
          assertAudienceAfterJwtVerify(
            result.payload as AudienceClaims,
            "id",
            audiencePolicy,
          );
          outcome.idTokenValue = result.payload;
        })
        .catch(outcome.onError("id", "JWT verification")),
    );
  }

  await Promise.allSettled(promises);
  if (outcome.fatal) throw outcome.fatal;
  return outcome;
}

/**
 * Strategy 2: fall back to remote introspection for whichever token local
 * verification couldn't validate.
 *
 * An introspection response speaks RFC 7662 vocabulary regardless of which
 * slot it was requested for, so the id slot is checked with the access-token
 * audience policy minus the resource audience (see
 * `idTokenIntrospectionPolicy`) — an ID token's `aud` could never match a
 * configured resource audience.
 */
export async function introspectTokens(
  config: Configuration,
  tokens: { access?: string; id?: string },
  which: { access: boolean; id: boolean },
  tokenTypePolicy: TokenTypePolicy,
  audiencePolicy: AudiencePolicy,
  idIntrospectionPolicy: AudiencePolicy,
  log: Logger,
): Promise<StrategyOutcome> {
  const outcome = new StrategyOutcome(log);
  const promises: Promise<void>[] = [];

  if (which.access && tokens.access) {
    promises.push(
      tokenIntrospection(config, tokens.access)
        .then((result) => {
          if (!result.active) throw new Error("access token is not active");
          // `active: true` says the token is live — not that it's an
          // *access* token, and not that it's ours. Both are established
          // separately since one endpoint answers for every token type.
          assertIntrospectedAccessToken(
            result as AudienceClaims,
            tokenTypePolicy,
          );
          // RFC 7662 §4 leaves the "issued to you" half to the caller.
          assertTokenAudience(
            result as AudienceClaims,
            "access",
            audiencePolicy,
          );
          outcome.accessTokenValue = result;
        })
        .catch(outcome.onError("access", "introspection")),
    );
  }
  if (which.id && tokens.id) {
    promises.push(
      tokenIntrospection(config, tokens.id)
        .then((result) => {
          if (!result.active) throw new Error("id token is not active");
          assertIntrospectedIdToken(result as AudienceClaims, tokenTypePolicy);
          assertTokenAudience(
            result as AudienceClaims,
            "access",
            idIntrospectionPolicy,
          );
          outcome.idTokenValue = result;
        })
        .catch(outcome.onError("id", "introspection")),
    );
  }

  await Promise.allSettled(promises);
  if (outcome.fatal) throw outcome.fatal;
  return outcome;
}

export type { StrategyOutcome };
