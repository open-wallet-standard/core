'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Wallet, Plus, Shield, Activity, AlertTriangle, 
  CheckCircle, XCircle, Clock, Key, Settings,
  Eye, EyeOff, Bot, Copy, 
  ShieldCheck, RotateCcw, X, DollarSign
} from 'lucide-react';
import { Agent, Transaction } from '@/lib/types';

const mockAgents: Agent[] = [
  {
    id: '1',
    name: 'Content Writer Agent',
    apiKey: 'sk_spendos_cwr7x9kz2m4p8q',
    apiKeyPrefix: 'sk_spendos_',
    wallet: '0x742d35Cc6634C0532925a3b844Bc9e7595f8fE21',
    dailyLimit: 50,
    monthlyLimit: 500,
    chains: 'ethereum,polygon',
    status: 'active',
    totalSpent: 32.50,
    createdAt: '2026-04-01T10:00:00Z',
  },
  {
    id: '2',
    name: 'Image Generator Agent',
    apiKey: 'sk_spendos_img3x5y7z9a1b2',
    apiKeyPrefix: 'sk_spendos_',
    wallet: '0x8Ba1f109551bD432803012645Hac136E65fE1D24',
    dailyLimit: 100,
    monthlyLimit: 2000,
    chains: 'ethereum,solana',
    status: 'active',
    totalSpent: 92.00,
    createdAt: '2026-04-02T14:30:00Z',
  },
  {
    id: '3',
    name: 'Research Agent',
    apiKey: 'sk_spendos_res4e6g8h0j2l4',
    apiKeyPrefix: 'sk_spendos_',
    wallet: '0x5B38Da6a701c568545dCfcB03FcB875f56bed6C5',
    dailyLimit: 25,
    monthlyLimit: 250,
    chains: 'ethereum',
    status: 'paused',
    totalSpent: 24.00,
    createdAt: '2026-04-03T09:15:00Z',
  },
];

const mockTransactions: Transaction[] = [
  {
    id: '1',
    agentId: '1',
    hash: '0x8a9b2c1d3e4f5g6h7i8j9k0l1m2n3o4p5q6r7s8t9u0v1w2x3y4z5',
    chain: 'ethereum',
    amount: 5.50,
    currency: 'USDC',
    toAddress: '0x742d...8fE21',
    status: 'confirmed',
    createdAt: '2026-04-04T15:30:00Z',
  },
  {
    id: '2',
    agentId: '2',
    hash: '0x1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7',
    chain: 'polygon',
    amount: 25.00,
    currency: 'USDC',
    toAddress: '0x3BcD...2XyZ',
    status: 'pending',
    createdAt: '2026-04-04T16:45:00Z',
  },
  {
    id: '3',
    agentId: '1',
    hash: '0x9z8y7x6w5v4u3t2s1r0q9p8o7n6m5l4k3j2i1h0g9f8e7d6c5b4a3',
    chain: 'ethereum',
    amount: 2.25,
    currency: 'USDC',
    toAddress: '0x4Ef2...9AbC',
    status: 'confirmed',
    createdAt: '2026-04-04T14:20:00Z',
  },
  {
    id: '4',
    agentId: '2',
    hash: '0xabcd1234efgh5678ij90kl12mn3456op7890qr12st3456uv7890wx12',
    chain: 'solana',
    amount: 150.00,
    currency: 'USDC',
    toAddress: '7Ec...hJk',
    status: 'confirmed',
    createdAt: '2026-04-04T12:00:00Z',
  },
];

function ProgressBar({ value, max }: { value: number; max: number }) {
  const percentage = Math.min((value / max) * 100, 100);
  
  let colorClass = 'bg-emerald-500';
  if (percentage >= 90) {
    colorClass = 'bg-rose-500';
  } else if (percentage >= 70) {
    colorClass = 'bg-amber-500';
  }
  
  return (
    <div className="w-full h-2 bg-zinc-200 dark:bg-zinc-800 rounded-full overflow-hidden">
      <motion.div
        initial={{ width: 0 }}
        animate={{ width: `${percentage}%` }}
        transition={{ duration: 0.8, ease: 'easeOut' }}
        className={`h-full ${colorClass} rounded-full`}
      />
    </div>
  );
}

function AgentCard({ 
  agent, 
  onManageKey 
}: { 
  agent: Agent; 
  onManageKey: () => void;
}) {
  const percentage = (agent.totalSpent / agent.dailyLimit) * 100;
  
  let statusColor = 'bg-emerald-500/10 text-emerald-600 dark:bg-emerald-500/20 dark:text-emerald-400';
  let statusIcon = <CheckCircle className="w-3 h-3" />;
  
  if (agent.status === 'paused') {
    statusColor = 'bg-amber-500/10 text-amber-600 dark:bg-amber-500/20 dark:text-amber-400';
    statusIcon = <Clock className="w-3 h-3" />;
  }

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="p-5 rounded-xl border bg-white dark:bg-zinc-900/80 backdrop-blur-sm border-zinc-200 dark:border-zinc-800/50 hover:border-violet-300 dark:hover:border-violet-500/50 hover:shadow-lg hover:shadow-violet-500/5 transition-all"
    >
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
            agent.status === 'active' ? 'bg-emerald-50 dark:bg-emerald-500/10' : 'bg-amber-50 dark:bg-amber-500/10'
          }`}>
            <Bot className={`w-5 h-5 ${
              agent.status === 'active' ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'
            }`} />
          </div>
          <div>
            <h3 className="font-semibold text-zinc-900 dark:text-white">{agent.name}</h3>
            <p className="text-xs text-zinc-500 font-mono">
              {agent.wallet.slice(0, 8)}...{agent.wallet.slice(-6)}
            </p>
          </div>
        </div>
        <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${statusColor}`}>
          {statusIcon}
          <span className="capitalize">{agent.status}</span>
        </div>
      </div>

      <div className="space-y-3">
        <div>
          <div className="flex items-center justify-between text-xs mb-1.5">
            <span className="text-zinc-500 dark:text-zinc-400">Daily Spending</span>
            <span className="font-medium text-zinc-700 dark:text-zinc-300">
              ${agent.totalSpent.toFixed(2)} / ${agent.dailyLimit}
            </span>
          </div>
          <ProgressBar value={agent.totalSpent} max={agent.dailyLimit} />
        </div>

        <div className="flex items-center justify-between pt-2 border-t border-zinc-100 dark:border-zinc-800/50">
          <div className="flex items-center gap-2">
            {agent.chains.split(',').map(chain => (
              <span 
                key={chain} 
                className="px-2 py-0.5 text-xs rounded bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400 capitalize"
              >
                {chain}
              </span>
            ))}
          </div>
          <button
            onClick={onManageKey}
            className="flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded-lg bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400 hover:bg-zinc-200 dark:hover:bg-zinc-700 transition-colors"
          >
            <Key className="w-3 h-3" />
            API Key
          </button>
        </div>
      </div>
    </motion.div>
  );
}

function ActivityItem({ transaction }: { transaction: Transaction }) {
  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      className="p-4 border-b border-zinc-100 dark:border-zinc-800/50 last:border-0"
    >
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          {transaction.status === 'confirmed' ? (
            <div className="w-5 h-5 rounded-full bg-emerald-100 dark:bg-emerald-500/20 flex items-center justify-center">
              <CheckCircle className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
            </div>
          ) : transaction.status === 'pending' ? (
            <div className="w-5 h-5 rounded-full bg-amber-100 dark:bg-amber-500/20 flex items-center justify-center">
              <Clock className="w-3 h-3 text-amber-600 dark:text-amber-400" />
            </div>
          ) : (
            <div className="w-5 h-5 rounded-full bg-rose-100 dark:bg-rose-500/20 flex items-center justify-center">
              <XCircle className="w-3 h-3 text-rose-600 dark:text-rose-400" />
            </div>
          )}
          <span className="text-sm font-semibold text-zinc-900 dark:text-white">
            ${transaction.amount.toFixed(2)} {transaction.currency}
          </span>
        </div>
        <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
          transaction.chain === 'ethereum' ? 'bg-blue-100 dark:bg-blue-500/20 text-blue-700 dark:text-blue-400' : 'bg-purple-100 dark:bg-purple-500/20 text-purple-700 dark:text-purple-400'
        }`}>
          {transaction.chain}
        </span>
      </div>
      
      <div className="flex items-center gap-2 ml-7">
        <code className="text-xs text-zinc-500 font-mono">
          To: {transaction.toAddress}
        </code>
        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/30">
          <ShieldCheck className="w-2.5 h-2.5" />
          OWS
        </span>
      </div>
      
      <p className="text-[10px] text-zinc-400 ml-7 mt-1">
        {new Date(transaction.createdAt).toLocaleString()}
      </p>
    </motion.div>
  );
}

function ApiKeyModal({ 
  agent, 
  onClose, 
  onRotate 
}: { 
  agent: Agent; 
  onClose: () => void; 
  onRotate: () => void;
}) {
  const [showKey, setShowKey] = useState(false);
  const [copied, setCopied] = useState(false);
  
  const maskedKey = agent.apiKey?.replace(agent.apiKey.slice(9, -6), '••••••••••') || '';

  const copyToClipboard = () => {
    if (agent.apiKey) navigator.clipboard.writeText(agent.apiKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.95, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.95, opacity: 0 }}
        className="bg-white dark:bg-zinc-900 rounded-2xl border border-zinc-200 dark:border-zinc-800 shadow-2xl w-full max-w-md overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-6 border-b border-zinc-100 dark:border-zinc-800">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-violet-100 dark:bg-violet-500/20 flex items-center justify-center">
                <Key className="w-5 h-5 text-violet-600 dark:text-violet-400" />
              </div>
              <div>
                <h3 className="font-semibold text-zinc-900 dark:text-white">API Key</h3>
                <p className="text-xs text-zinc-500">{agent.name}</p>
              </div>
            </div>
            <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors">
              <X className="w-5 h-5 text-zinc-400" />
            </button>
          </div>
        </div>

        <div className="p-6 space-y-4">
          <div>
            <label className="text-xs font-medium text-zinc-500 dark:text-zinc-400 mb-2 block">Secret Key</label>
            <div className="flex items-center gap-2">
              <code className="flex-1 px-4 py-3 rounded-lg bg-zinc-50 dark:bg-zinc-800/50 border border-zinc-200 dark:border-zinc-700 text-sm font-mono text-emerald-600 dark:text-emerald-400">
                {showKey ? agent.apiKey : maskedKey}
              </code>
              <button
                onClick={() => setShowKey(!showKey)}
                className="p-2.5 rounded-lg bg-zinc-100 dark:bg-zinc-800 hover:bg-zinc-200 dark:hover:bg-zinc-700 transition-colors"
              >
                {showKey ? <EyeOff className="w-4 h-4 text-zinc-600 dark:text-zinc-400" /> : <Eye className="w-4 h-4 text-zinc-600 dark:text-zinc-400" />}
              </button>
            </div>
          </div>

          <div className="flex items-center gap-2 p-3 rounded-lg bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30">
            <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 flex-shrink-0" />
            <p className="text-xs text-amber-700 dark:text-amber-400">
              Store this key securely. It will not be shown again after closing.
            </p>
          </div>

          <div className="flex items-center gap-2 p-3 rounded-lg bg-emerald-50 dark:bg-emerald-500/10 border border-emerald-200 dark:border-emerald-500/30">
            <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400 flex-shrink-0" />
            <p className="text-xs text-emerald-700 dark:text-emerald-400">
              All requests signed and verified by Open Wallet Standard
            </p>
          </div>

          <div className="flex gap-3 pt-2">
            <button onClick={copyToClipboard} className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 hover:bg-zinc-200 dark:hover:bg-zinc-700 transition-colors text-sm font-medium">
              <Copy className="w-4 h-4" />
              {copied ? 'Copied!' : 'Copy Key'}
            </button>
            <button onClick={onRotate} className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-rose-50 dark:bg-rose-500/20 text-rose-600 dark:text-rose-400 hover:bg-rose-100 dark:hover:bg-rose-500/30 transition-colors text-sm font-medium border border-rose-200 dark:border-rose-500/30">
              <RotateCcw className="w-4 h-4" />
              Rotate Key
            </button>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
}

export default function Dashboard() {
  const [agents, setAgents] = useState<Agent[]>(mockAgents);
  const [transactions] = useState<Transaction[]>(mockTransactions);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showApiKeyModal, setShowApiKeyModal] = useState<Agent | null>(null);
  const [newAgent, setNewAgent] = useState({ name: '', dailyLimit: 50, monthlyLimit: 500, chains: 'ethereum' });

  const totalSpent = agents.reduce((sum, a) => sum + a.totalSpent, 0);
  const activeAgents = agents.filter(a => a.status === 'active').length;
  const pendingTx = transactions.filter(t => t.status === 'pending').length;

  const createAgent = () => {
    const apiKey = `sk_spendos_${Math.random().toString(36).substring(2, 15)}`;
    const agent: Agent = {
      id: Math.random().toString(36).substring(7),
      name: newAgent.name,
      apiKey,
      apiKeyPrefix: 'sk_spendos_',
      wallet: `0x${Math.random().toString(16).substring(2, 42)}`,
      dailyLimit: newAgent.dailyLimit,
      monthlyLimit: newAgent.monthlyLimit,
      chains: newAgent.chains,
      status: 'active',
      totalSpent: 0,
      createdAt: new Date().toISOString(),
    };
    setAgents([...agents, agent]);
    setShowCreateModal(false);
    setNewAgent({ name: '', dailyLimit: 50, monthlyLimit: 500, chains: 'ethereum' });
  };

  const rotateApiKey = (agentId: string) => {
    const newKey = `sk_spendos_${Math.random().toString(36).substring(2, 15)}`;
    setAgents(agents.map(a => a.id === agentId ? { ...a, apiKey: newKey, apiKeyPrefix: 'sk_spendos_' } : a));
    setShowApiKeyModal(null);
  };

  return (
    <div className="min-h-screen bg-zinc-50 dark:bg-zinc-950">
      <header className="sticky top-0 z-40 bg-white/80 dark:bg-zinc-950/80 backdrop-blur-xl border-b border-zinc-200 dark:border-zinc-800/50">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-500 to-purple-600 flex items-center justify-center shadow-lg shadow-violet-500/25">
                <Wallet className="w-5 h-5 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-zinc-900 dark:text-white">SpendOS</h1>
                <p className="text-xs text-zinc-500">Agent Wallet Management</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <button className="p-2 rounded-lg hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors">
                <Settings className="w-5 h-5 text-zinc-500" />
              </button>
              <button onClick={() => setShowCreateModal(true)} className="px-4 py-2 bg-gradient-to-r from-violet-600 to-purple-600 hover:from-violet-500 hover:to-purple-500 text-white text-sm font-medium rounded-lg flex items-center gap-2 shadow-lg shadow-violet-500/25 transition-all">
                <Plus className="w-4 h-4" />
                Create Agent
              </button>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="bg-white dark:bg-zinc-900/80 backdrop-blur-sm border border-zinc-200 dark:border-zinc-800/50 rounded-2xl p-5 shadow-sm">
            <div className="flex items-center justify-between mb-3">
              <span className="text-sm text-zinc-500">Total Spend</span>
              <div className="w-8 h-8 rounded-lg bg-emerald-50 dark:bg-emerald-500/10 flex items-center justify-center">
                <DollarSign className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
              </div>
            </div>
            <p className="text-3xl font-bold text-zinc-900 dark:text-white">${totalSpent.toFixed(2)}</p>
            <p className="text-xs text-zinc-500 mt-1">Across {agents.length} agents</p>
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="bg-white dark:bg-zinc-900/80 backdrop-blur-sm border border-zinc-200 dark:border-zinc-800/50 rounded-2xl p-5 shadow-sm">
            <div className="flex items-center justify-between mb-3">
              <span className="text-sm text-zinc-500">Active Agents</span>
              <div className="w-8 h-8 rounded-lg bg-violet-50 dark:bg-violet-500/10 flex items-center justify-center">
                <Bot className="w-4 h-4 text-violet-600 dark:text-violet-400" />
              </div>
            </div>
            <p className="text-3xl font-bold text-zinc-900 dark:text-white">{activeAgents}</p>
            <p className="text-xs text-zinc-500 mt-1">{agents.length - activeAgents} paused</p>
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="bg-white dark:bg-zinc-900/80 backdrop-blur-sm border border-zinc-200 dark:border-zinc-800/50 rounded-2xl p-5 shadow-sm">
            <div className="flex items-center justify-between mb-3">
              <span className="text-sm text-zinc-500">Pending Txns</span>
              <div className="w-8 h-8 rounded-lg bg-amber-50 dark:bg-amber-500/10 flex items-center justify-center">
                <Clock className="w-4 h-4 text-amber-600 dark:text-amber-400" />
              </div>
            </div>
            <p className="text-3xl font-bold text-zinc-900 dark:text-white">{pendingTx}</p>
            <p className="text-xs text-zinc-500 mt-1">Awaiting confirmation</p>
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="bg-white dark:bg-zinc-900/80 backdrop-blur-sm border border-zinc-200 dark:border-zinc-800/50 rounded-2xl p-5 shadow-sm">
            <div className="flex items-center justify-between mb-3">
              <span className="text-sm text-zinc-500">Security</span>
              <div className="w-8 h-8 rounded-lg bg-blue-50 dark:bg-blue-500/10 flex items-center justify-center">
                <Shield className="w-4 h-4 text-blue-600 dark:text-blue-400" />
              </div>
            </div>
            <p className="text-3xl font-bold text-emerald-600 dark:text-emerald-400">Protected</p>
            <p className="text-xs text-zinc-500 mt-1">OWS Policy Engine</p>
          </motion.div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <div className="bg-white dark:bg-zinc-900/80 backdrop-blur-sm border border-zinc-200 dark:border-zinc-800/50 rounded-2xl overflow-hidden shadow-sm">
              <div className="p-5 border-b border-zinc-100 dark:border-zinc-800/50">
                <h2 className="text-lg font-semibold text-zinc-900 dark:text-white flex items-center gap-2">
                  <div className="w-8 h-8 rounded-lg bg-violet-50 dark:bg-violet-500/10 flex items-center justify-center">
                    <Bot className="w-4 h-4 text-violet-600 dark:text-violet-400" />
                  </div>
                  Agent Wallets
                </h2>
              </div>
              <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                {agents.map((agent) => (
                  <AgentCard key={agent.id} agent={agent} onManageKey={() => setShowApiKeyModal(agent)} />
                ))}
              </div>
            </div>
          </div>

          <div className="lg:col-span-1">
            <div className="bg-white dark:bg-zinc-900/80 backdrop-blur-sm border border-zinc-200 dark:border-zinc-800/50 rounded-2xl overflow-hidden shadow-sm sticky top-24">
              <div className="p-5 border-b border-zinc-100 dark:border-zinc-800/50">
                <h2 className="text-lg font-semibold text-zinc-900 dark:text-white flex items-center gap-2">
                  <div className="w-8 h-8 rounded-lg bg-emerald-50 dark:bg-emerald-500/10 flex items-center justify-center">
                    <Activity className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                  </div>
                  Recent Activity
                </h2>
              </div>
              <div className="max-h-[600px] overflow-y-auto">
                {transactions.map((tx) => (
                  <ActivityItem key={tx.id} transaction={tx} />
                ))}
              </div>
            </div>
          </div>
        </div>
      </main>

      <AnimatePresence>
        {showApiKeyModal && (
          <ApiKeyModal agent={showApiKeyModal} onClose={() => setShowApiKeyModal(null)} onRotate={() => rotateApiKey(showApiKeyModal.id)} />
        )}
      </AnimatePresence>

      <AnimatePresence>
        {showCreateModal && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={() => setShowCreateModal(false)}>
            <motion.div initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.95, opacity: 0 }} className="bg-white dark:bg-zinc-900 rounded-2xl border border-zinc-200 dark:border-zinc-800 p-6 w-full max-w-md shadow-2xl" onClick={(e) => e.stopPropagation()}>
              <h2 className="text-xl font-semibold text-zinc-900 dark:text-white mb-6">Create New Agent</h2>
              <div className="space-y-4">
                <div>
                  <label className="text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-2 block">Agent Name</label>
                  <input type="text" value={newAgent.name} onChange={(e) => setNewAgent({ ...newAgent, name: e.target.value })} placeholder="e.g., Image Generator Agent" className="w-full px-4 py-3 rounded-lg border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white placeholder:text-zinc-400 focus:outline-none focus:ring-2 focus:ring-violet-500" />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-2 block">Daily Limit ($)</label>
                    <input type="number" value={newAgent.dailyLimit} onChange={(e) => setNewAgent({ ...newAgent, dailyLimit: Number(e.target.value) })} className="w-full px-4 py-3 rounded-lg border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-violet-500" />
                  </div>
                  <div>
                    <label className="text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-2 block">Monthly Limit ($)</label>
                    <input type="number" value={newAgent.monthlyLimit} onChange={(e) => setNewAgent({ ...newAgent, monthlyLimit: Number(e.target.value) })} className="w-full px-4 py-3 rounded-lg border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-violet-500" />
                  </div>
                </div>
                <div>
                  <label className="text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-2 block">Allowed Chains</label>
                  <select value={newAgent.chains} onChange={(e) => setNewAgent({ ...newAgent, chains: e.target.value })} className="w-full px-4 py-3 rounded-lg border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-violet-500">
                    <option value="ethereum">Ethereum</option>
                    <option value="ethereum,polygon">Ethereum + Polygon</option>
                    <option value="ethereum,solana">Ethereum + Solana</option>
                    <option value="ethereum,polygon,solana">All Chains</option>
                  </select>
                </div>
              </div>
              <div className="flex gap-3 mt-6">
                <button onClick={() => setShowCreateModal(false)} className="flex-1 px-4 py-3 rounded-lg border border-zinc-200 dark:border-zinc-700 text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800 transition-colors">Cancel</button>
                <button onClick={createAgent} disabled={!newAgent.name} className="flex-1 px-4 py-3 rounded-lg bg-gradient-to-r from-violet-600 to-purple-600 hover:from-violet-500 hover:to-purple-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium transition-all shadow-lg shadow-violet-500/25">Create Agent</button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
