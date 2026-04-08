import type { Keypair } from "@solana/web3.js";
export interface OwsSolanaOptions { passphrase?: string; vaultPath?: string; }
export declare function owsToSolanaKeypair(walletNameOrId: string, options?: OwsSolanaOptions): Keypair;
