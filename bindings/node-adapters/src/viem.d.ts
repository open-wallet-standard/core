import type { Account } from "viem";
export interface OwsViemAccountOptions { chain?: string; passphrase?: string; index?: number; vaultPath?: string; }
export declare function owsToViemAccount(walletNameOrId: string, options?: OwsViemAccountOptions): Account;
