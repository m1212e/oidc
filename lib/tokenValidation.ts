/**
 * The two validation strategies `processTokens` falls back through: local
 * JWKS verification, then remote introspection.
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
  assertIntrospectedIdTokenAudience,
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

/** Three base64url segments: the shape of a compact JWS, nothing more. */
const JWS_COMPACT = /^[\w-]+\.[\w-]*\.[\w-]+$/;

/** Whether a token is a JWT at all, as opposed to an opaque handle. */
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
 * The `sub` a supplied JWT names, read without verifying anything. Used
 * only as an extra constraint on what a refresh may return, never to
 * accept a token on its own.
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
 * Collects the outcome of running one validation strategy across both
 * token slots.
 */
class StrategyOutcome {
  accessTokenValue: AccessTokenClaims;
  idTokenValue: IdTokenClaims;
  failures: TokenValidationFailure[] = [];
  expired = false;
  fatal: OidcTokenError | undefined;

  constructor(private log: Logger) {}

  /**
   * Captures a permanent rejection (wrong client, wrong token kind) rather
   * than throwing directly, since `Promise.allSettled` would swallow it.
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
 * Reports expiry via `expired` so `processTokens` can skip straight to a
 * refresh instead of also trying introspection.
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
 */
export async function introspectTokens(
  config: Configuration,
  tokens: { access?: string; id?: string },
  which: { access: boolean; id: boolean },
  tokenTypePolicy: TokenTypePolicy,
  audiencePolicy: AudiencePolicy,
  log: Logger,
): Promise<StrategyOutcome> {
  const outcome = new StrategyOutcome(log);
  const promises: Promise<void>[] = [];

  if (which.access && tokens.access) {
    promises.push(
      tokenIntrospection(config, tokens.access)
        .then((result) => {
          if (!result.active) throw new Error("access token is not active");
          assertIntrospectedAccessToken(
            result as AudienceClaims,
            tokenTypePolicy,
          );
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
          assertIntrospectedIdTokenAudience(
            result as AudienceClaims,
            audiencePolicy,
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
