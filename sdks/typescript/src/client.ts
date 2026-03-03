/**
 * LWS REST API client — uses native fetch (Node 18+).
 */

import { LwsError } from "./errors.js";
import type {
  ApiKey,
  ChainType,
  CreateApiKeyParams,
  CreateWalletParams,
  Policy,
  SignAndSendParams,
  SignAndSendResult,
  SignMessageParams,
  SignMessageResult,
  SignParams,
  SignResult,
  WalletDescriptor,
} from "./types.js";

const DEFAULT_BASE_URL = "http://127.0.0.1:8402";

export interface LWSClientOptions {
  apiKey?: string;
  baseUrl?: string;
}

export class LWSClient {
  private readonly baseUrl: string;
  private authHeader: string | undefined;

  constructor(options: LWSClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    if (options.apiKey) {
      this.authHeader = `Bearer ${options.apiKey}`;
    }
  }

  // -- internal helpers --

  private async request<T>(
    method: string,
    path: string,
    options: { body?: unknown; params?: Record<string, string> } = {},
  ): Promise<T> {
    let url = `${this.baseUrl}${path}`;
    if (options.params) {
      const search = new URLSearchParams(options.params);
      url += `?${search.toString()}`;
    }

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.authHeader) {
      headers["Authorization"] = this.authHeader;
    }

    const response = await fetch(url, {
      method,
      headers,
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    });

    if (response.status === 204) {
      return undefined as T;
    }

    const body = await response.json();

    if (!response.ok) {
      throw LwsError.fromResponse(response.status, body);
    }

    return body as T;
  }

  // -- auth --

  async unlock(passphrase: string): Promise<string> {
    const data = await this.request<{ session_token: string }>(
      "POST",
      "/v1/auth/unlock",
      { body: { passphrase } },
    );
    this.authHeader = `Bearer ${data.session_token}`;
    return data.session_token;
  }

  // -- wallets --

  async listWallets(chainType?: ChainType): Promise<WalletDescriptor[]> {
    const params = chainType ? { chain_type: chainType } : undefined;
    return this.request<WalletDescriptor[]>("GET", "/v1/wallets", { params });
  }

  async getWallet(walletId: string): Promise<WalletDescriptor> {
    return this.request<WalletDescriptor>("GET", `/v1/wallets/${walletId}`);
  }

  async createWallet(params: CreateWalletParams): Promise<WalletDescriptor> {
    return this.request<WalletDescriptor>("POST", "/v1/wallets", {
      body: params,
    });
  }

  // -- signing --

  async sign(params: SignParams): Promise<SignResult> {
    const { wallet_id, ...body } = params;
    return this.request<SignResult>("POST", `/v1/wallets/${wallet_id}/sign`, {
      body,
    });
  }

  async signAndSend(params: SignAndSendParams): Promise<SignAndSendResult> {
    const { wallet_id, ...body } = params;
    return this.request<SignAndSendResult>(
      "POST",
      `/v1/wallets/${wallet_id}/sign-and-send`,
      { body },
    );
  }

  async signMessage(params: SignMessageParams): Promise<SignMessageResult> {
    const { wallet_id, ...body } = params;
    return this.request<SignMessageResult>(
      "POST",
      `/v1/wallets/${wallet_id}/sign-message`,
      { body },
    );
  }

  // -- policies --

  async getPolicy(walletId: string): Promise<Policy[]> {
    return this.request<Policy[]>("GET", `/v1/wallets/${walletId}/policy`);
  }

  // -- API keys (owner only) --

  async createApiKey(params: CreateApiKeyParams): Promise<ApiKey> {
    return this.request<ApiKey>("POST", "/v1/keys", { body: params });
  }

  async listApiKeys(): Promise<ApiKey[]> {
    return this.request<ApiKey[]>("GET", "/v1/keys");
  }

  async getApiKey(keyId: string): Promise<ApiKey> {
    return this.request<ApiKey>("GET", `/v1/keys/${keyId}`);
  }

  async revokeApiKey(keyId: string): Promise<void> {
    await this.request<void>("DELETE", `/v1/keys/${keyId}`);
  }
}
