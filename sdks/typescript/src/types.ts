/**
 * LWS type definitions matching lws-core/src/types.rs.
 *
 * Field names use snake_case to match Rust serde output.
 */

/** Blockchain type identifier. */
export type ChainType = "evm" | "solana" | "cosmos" | "bitcoin" | "tron";

/** Message encoding for sign-message requests. */
export type MessageEncoding = "utf8" | "hex" | "base64";

/** Status of a submitted transaction. */
export type TransactionStatus = "pending" | "confirmed" | "failed";

/** Type of state change from simulation. */
export type StateChangeType =
  | "balance_change"
  | "token_transfer"
  | "approval"
  | "contract_call";

/** An account derived from a wallet on a specific chain. */
export interface AccountDescriptor {
  chain: string;
  address: string;
  derivation_path: string;
  account_id: string;
}

/** High-level wallet descriptor. */
export interface WalletDescriptor {
  id: string;
  name: string;
  chains: ChainType[];
  accounts: AccountDescriptor[];
  created_at: string;
  updated_at?: string;
}

/** A state change from simulation. */
export interface StateChange {
  change_type: StateChangeType;
  address: string;
  amount?: string;
  token?: string;
}

/** Simulation result for a transaction. */
export interface SimulationResult {
  success: boolean;
  state_changes: StateChange[];
  gas_estimate?: number;
  error?: string;
}

/** Result of signing a transaction. */
export interface SignResult {
  signed_transaction: string;
  simulation?: SimulationResult;
}

/** Result of sign-and-send. */
export interface SignAndSendResult {
  tx_hash: string;
  status: TransactionStatus;
  simulation?: SimulationResult;
}

/** Result of signing a message. */
export interface SignMessageResult {
  signature: string;
}

/** Policy definition. */
export interface Policy {
  id: string;
  name: string;
  executable: string;
  timeout_ms?: number;
}

/** API key descriptor. */
export interface ApiKey {
  id: string;
  name: string;
  key_hash: string;
  scoped_wallets: string[];
  created_at: string;
  expires_at?: string;
  /** Raw key, only present at creation time. */
  key?: string;
}

// -- Request parameter types for client methods --

/** Parameters for creating a wallet. */
export interface CreateWalletParams {
  name: string;
  chains: ChainType[];
}

/** Parameters for signing a transaction. */
export interface SignParams {
  wallet_id: string;
  chain: string;
  transaction: Record<string, unknown>;
  simulate?: boolean;
}

/** Parameters for sign-and-send. */
export interface SignAndSendParams {
  wallet_id: string;
  chain: string;
  transaction: Record<string, unknown>;
  simulate?: boolean;
  max_retries?: number;
  confirmations?: number;
}

/** Parameters for signing a message. */
export interface SignMessageParams {
  wallet_id: string;
  chain: string;
  message: string;
  encoding?: MessageEncoding;
}

/** Parameters for creating an API key. */
export interface CreateApiKeyParams {
  name: string;
  wallet_ids: string[];
  expires_at?: string;
  policies?: string[];
}
