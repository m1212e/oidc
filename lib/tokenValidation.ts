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
 * Policies that hold for any verified claims, however they were verified
 * (tenant, delegation). Throws an {@link OidcTokenError} to reject.
 */
export type VerifiedClaimsCheck = (
  claims: unknown,
  tokenKind: TokenKind,
) => void;

/**
 * Whether a local verification failure came from fetching the key set
 * rather than from the token. jose raises its base `JOSEError` only for a
 * key set response it couldn't use, and passes fetch failures through as
 * they are.
 */
function keySetUnavailable(err: unknown): boolean {
  if (err instanceof errors.JWKSTimeout || err instanceof errors.JWKSInvalid) {
    return true;
  }
  if (err instanceof errors.JOSEError) {
    return err.constructor === errors.JOSEError;
  }
  return true;
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
   * `transient` says whether the failure reached the provider at all, see
   * {@link TokenValidationFailure.transient}.
   */
  onError(
    kind: TokenKind,
    stage: string,
    transient: (err: unknown) => boolean = () => false,
  ) {
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
      this.failures.push({
        tokenKind: kind,
        stage,
        error: err,
        transient: transient(err),
      });
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
 * refresh instead of also trying introspection. Opaque tokens are skipped
 * rather than failed: there is nothing local to verify them against.
 */
export async function verifyTokensLocally(
  jwks: Parameters<typeof jwtVerify>[1],
  tokens: { access?: string; id?: string },
  jwtVerifyOptionsFor: (
    tokenKind: TokenKind,
    token: string,
  ) => JWTVerifyOptions,
  tokenTypePolicy: TokenTypePolicy,
  audiencePolicy: AudiencePolicy,
  assertVerifiedClaims: VerifiedClaimsCheck,
  log: Logger,
): Promise<StrategyOutcome> {
  const outcome = new StrategyOutcome(log);
  const promises: Promise<void>[] = [];

  if (tokens.access && looksLikeJwt(tokens.access)) {
    const token = tokens.access;
    promises.push(
      jwtVerify(token, jwks, jwtVerifyOptionsFor("access", token))
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
          assertVerifiedClaims(result.payload, "access");
          outcome.accessTokenValue = result.payload;
        })
        .catch(
          outcome.onError("access", "JWT verification", keySetUnavailable),
        ),
    );
  }
  if (tokens.id && looksLikeJwt(tokens.id)) {
    const token = tokens.id;
    promises.push(
      jwtVerify(token, jwks, jwtVerifyOptionsFor("id", token))
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
          assertVerifiedClaims(result.payload, "id");
          outcome.idTokenValue = result.payload;
        })
        .catch(outcome.onError("id", "JWT verification", keySetUnavailable)),
    );
  }

  await Promise.allSettled(promises);
  if (outcome.fatal) throw outcome.fatal;
  return outcome;
}

/**
 * Strategy 2: fall back to remote introspection for whichever token local
 * verification couldn't validate. The endpoint answers `active: false` for
 * a bad token, so a request that fails outright says nothing about the
 * token and is recorded as transient.
 */
export async function introspectTokens(
  config: Configuration,
  tokens: { access?: string; id?: string },
  which: { access: boolean; id: boolean },
  tokenTypePolicy: TokenTypePolicy,
  audiencePolicy: AudiencePolicy,
  assertVerifiedClaims: VerifiedClaimsCheck,
  log: Logger,
): Promise<StrategyOutcome> {
  const outcome = new StrategyOutcome(log);
  const promises: Promise<void>[] = [];

  if (which.access && tokens.access) {
    promises.push(
      tokenIntrospection(config, tokens.access)
        .then(
          (result) => {
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
            assertVerifiedClaims(result, "access");
            outcome.accessTokenValue = result;
          },
          outcome.onError("access", "introspection", () => true),
        )
        .catch(outcome.onError("access", "introspection")),
    );
  }
  if (which.id && tokens.id) {
    promises.push(
      tokenIntrospection(config, tokens.id)
        .then(
          (result) => {
            if (!result.active) throw new Error("id token is not active");
            assertIntrospectedIdToken(
              result as AudienceClaims,
              tokenTypePolicy,
            );
            assertIntrospectedIdTokenAudience(
              result as AudienceClaims,
              audiencePolicy,
            );
            assertVerifiedClaims(result, "id");
            outcome.idTokenValue = result;
          },
          outcome.onError("id", "introspection", () => true),
        )
        .catch(outcome.onError("id", "introspection")),
    );
  }

  await Promise.allSettled(promises);
  if (outcome.fatal) throw outcome.fatal;
  return outcome;
}

export type { StrategyOutcome };
