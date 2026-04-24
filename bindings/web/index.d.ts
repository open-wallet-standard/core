export type OwsCollection = "keys" | "policies" | "wallets";

export interface OwsWebStore {
  ensureCollection(kind: OwsCollection): Promise<void>;
  list(kind: OwsCollection): Promise<string[]>;
  read(kind: OwsCollection, id: string): Promise<string | null>;
  remove(kind: OwsCollection, id: string): Promise<void>;
  write(kind: OwsCollection, id: string, json: string): Promise<void>;
}

export interface AccountInfo {
  address: string;
  chainId: string;
  derivationPath: string;
}

export interface WalletInfo {
  accounts: AccountInfo[];
  createdAt: string;
  id: string;
  name: string;
}

export interface SignResult {
  recoveryId?: number;
  signature: string;
}

export interface ApiKeyResult {
  id: string;
  name: string;
  token: string;
}

export interface PublicApiKey {
  createdAt: string;
  expiresAt?: string;
  id: string;
  name: string;
  policyIds: string[];
  tokenHash: string;
  walletIds: string[];
}

export interface CreateOwsWebOptions {
  store?: OwsWebStore;
}

export class OwsWebError extends Error {
  code: string;
  constructor(code: string, message: string);
  static from(error: unknown): OwsWebError;
}

export class OwsWeb {
  constructor(store: OwsWebStore);
  createApiKey(
    name: string,
    walletIds: string[],
    policyIds: string[],
    passphrase?: string,
    expiresAt?: string,
  ): Promise<ApiKeyResult>;
  createPolicy(policy: object | string): Promise<object>;
  createWallet(name: string, passphrase?: string, words?: number): Promise<WalletInfo>;
  deletePolicy(id: string): Promise<void>;
  deleteWallet(nameOrId: string): Promise<void>;
  deriveAddress(mnemonic: string, chain: string, index?: number): string;
  exportWallet(nameOrId: string, passphrase?: string): Promise<string>;
  generateMnemonic(words?: number): string;
  getPolicy(id: string): Promise<object>;
  getWallet(nameOrId: string): Promise<WalletInfo>;
  importWalletMnemonic(
    name: string,
    mnemonic: string,
    passphrase?: string,
    index?: number,
  ): Promise<WalletInfo>;
  importWalletPrivateKey(
    name: string,
    privateKeyHex: string,
    passphrase?: string,
    chain?: string,
    secp256k1Key?: string,
    ed25519Key?: string,
  ): Promise<WalletInfo>;
  listApiKeys(): Promise<PublicApiKey[]>;
  listPolicies(): Promise<object[]>;
  listWallets(): Promise<WalletInfo[]>;
  renameWallet(nameOrId: string, newName: string): Promise<WalletInfo>;
  revokeApiKey(id: string): Promise<void>;
  signAndSend(): Promise<never>;
  signAuthorization(
    wallet: string,
    chain: string,
    address: string,
    nonce: string,
    passphrase?: string,
    index?: number,
  ): Promise<SignResult>;
  signHash(
    wallet: string,
    chain: string,
    hashHex: string,
    passphrase?: string,
    index?: number,
  ): Promise<SignResult>;
  signMessage(
    wallet: string,
    chain: string,
    message: string,
    passphrase?: string,
    encoding?: "hex" | "utf8",
    index?: number,
  ): Promise<SignResult>;
  signTransaction(
    wallet: string,
    chain: string,
    txHex: string,
    passphrase?: string,
    index?: number,
  ): Promise<SignResult>;
  signTypedData(
    wallet: string,
    chain: string,
    typedDataJson: object | string,
    passphrase?: string,
    index?: number,
  ): Promise<SignResult>;
}

export class IndexedDbOwsStore implements OwsWebStore {
  constructor(options?: { name?: string; version?: number });
  ensureCollection(kind: OwsCollection): Promise<void>;
  list(kind: OwsCollection): Promise<string[]>;
  read(kind: OwsCollection, id: string): Promise<string | null>;
  remove(kind: OwsCollection, id: string): Promise<void>;
  write(kind: OwsCollection, id: string, json: string): Promise<void>;
}

export class LightningFsOwsStore implements OwsWebStore {
  constructor(fs: unknown, options?: { root?: string });
  ensureCollection(kind: OwsCollection): Promise<void>;
  list(kind: OwsCollection): Promise<string[]>;
  read(kind: OwsCollection, id: string): Promise<string | null>;
  remove(kind: OwsCollection, id: string): Promise<void>;
  write(kind: OwsCollection, id: string, json: string): Promise<void>;
}

export class MemoryOwsStore implements OwsWebStore {
  ensureCollection(kind: OwsCollection): Promise<void>;
  list(kind: OwsCollection): Promise<string[]>;
  read(kind: OwsCollection, id: string): Promise<string | null>;
  remove(kind: OwsCollection, id: string): Promise<void>;
  write(kind: OwsCollection, id: string, json: string): Promise<void>;
}

export function createOwsWeb(options?: CreateOwsWebOptions): Promise<OwsWeb>;
