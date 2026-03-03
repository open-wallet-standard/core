/**
 * LWS error types matching lws-core/src/error.rs.
 */

/** Error codes returned by the LWS API (SCREAMING_SNAKE_CASE). */
export const LwsErrorCode = {
  WALLET_NOT_FOUND: "WALLET_NOT_FOUND",
  CHAIN_NOT_SUPPORTED: "CHAIN_NOT_SUPPORTED",
  POLICY_DENIED: "POLICY_DENIED",
  INSUFFICIENT_FUNDS: "INSUFFICIENT_FUNDS",
  INVALID_PASSPHRASE: "INVALID_PASSPHRASE",
  VAULT_LOCKED: "VAULT_LOCKED",
  BROADCAST_FAILED: "BROADCAST_FAILED",
  TIMEOUT: "TIMEOUT",
  INVALID_INPUT: "INVALID_INPUT",
  CAIP_PARSE_ERROR: "CAIP_PARSE_ERROR",
} as const;

export type LwsErrorCode = (typeof LwsErrorCode)[keyof typeof LwsErrorCode];

/** Exception raised for LWS API errors. */
export class LwsError extends Error {
  readonly code: string;
  readonly statusCode: number;

  constructor(code: string, message: string, statusCode: number = 0) {
    super(message);
    this.name = "LwsError";
    this.code = code;
    this.statusCode = statusCode;
  }

  static fromResponse(
    statusCode: number,
    body: { code?: string; message?: string },
  ): LwsError {
    return new LwsError(
      body.code ?? "UNKNOWN",
      body.message ?? "Unknown error",
      statusCode,
    );
  }
}
