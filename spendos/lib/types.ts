export interface Agent {
  id: string;
  name: string;
  apiKey?: string;
  apiKeyPrefix: string;
  wallet: string;
  dailyLimit: number;
  monthlyLimit: number;
  chains: string;
  status: 'active' | 'paused' | 'revoked';
  totalSpent: number;
  createdAt: string;
}

export interface Transaction {
  id: string;
  agentId: string;
  hash: string;
  chain: string;
  amount: number;
  currency: string;
  toAddress: string;
  status: 'pending' | 'confirmed' | 'failed';
  createdAt: string;
}

export interface SpendLog {
  id: string;
  agentId: string;
  amount: number;
  currency: string;
  action: string;
  details: string;
  createdAt: string;
}
