export interface OwsWdkAccountOptions {
  passphrase?: string;
  index?: number;
  rpcUrl?: string;
  vaultPath?: string;
}

export interface WdkCompatibleAccount {
  index: number;
  path: string;
  keyPair: { publicKey: null; privateKey: null };
  getAddress(): Promise<string>;
  sign(message: Uint8Array | Buffer | string): Promise<Uint8Array>;
  signTransaction(txData: Uint8Array | Buffer | string): Promise<Uint8Array>;
  sendTransaction(txData: Uint8Array | Buffer | string): Promise<string>;
  dispose(): void;
}

export declare const CHAIN_MAP: Record<string, string>;

export declare function owsToWdkAccount(
  walletNameOrId: string,
  chain: string,
  options?: OwsWdkAccountOptions,
): WdkCompatibleAccount;
