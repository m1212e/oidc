import type {
  TokenEndpointResponse,
  TokenEndpointResponseHelpers,
} from "openid-client";
import type { AudienceClaims } from "../audience";
import type { TokenKind } from "../errors";
import type { Logger, LogLevel } from "../logger";
import type { ValidationResult } from "../types";

export type OidcCoreOptions = {
  issuer: string;
  clientId: string;
  clientSecret?: string;
  expectedAudience?: string | string[];
  authorizedPartyClaims?: readonly string[];
  verifyAudience?: (claims: AudienceClaims, tokenKind: TokenKind) => boolean;
  idTokenOnlyClaims?: readonly string[];
  accessTokenTyp?: string;
  requireIntrospectedTokenType?: boolean;
  introspection?: "opaque-only" | "auto" | "never";
  allowedReturnToOrigins?: readonly string[];
  clockTolerance?: string | number;
  signingAlgorithms?: string[];
  development?: boolean;
  logger?: Logger;
  logLevel?: LogLevel;
};

export type StartSigninResult = {
  codeVerifier: string;
  authorizationUrl: URL;
  state: string;
};

export type ResolveSigninResult = {
  tokens: TokenEndpointResponse & TokenEndpointResponseHelpers;
  returnTo: string;
};

type SubjectBinding = { subject?: string };

export type ProcessTokensInput = SubjectBinding &
  (
    | {
        access_token: string | null;
        id_token?: string | null;
        refresh_token?: string | null;
      }
    | {
        access_token?: string | null;
        id_token: string | null;
        refresh_token?: string | null;
      }
  );

export type ProcessTokensResult = ValidationResult &
  (
    | {
        refreshed: true;
        refreshedTokens: TokenEndpointResponse & TokenEndpointResponseHelpers;
      }
    | { refreshed: false; refreshedTokens?: undefined }
  );
