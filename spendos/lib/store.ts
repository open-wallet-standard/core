import { create } from 'zustand';
import { Agent, Transaction } from '@/lib/types';

interface SpendOSStore {
  agents: Agent[];
  selectedAgent: Agent | null;
  transactions: Transaction[];
  setAgents: (agents: Agent[]) => void;
  setSelectedAgent: (agent: Agent | null) => void;
  setTransactions: (txs: Transaction[]) => void;
  addAgent: (agent: Agent) => void;
  updateAgent: (id: string, updates: Partial<Agent>) => void;
  addTransaction: (tx: Transaction) => void;
}

export const useSpendOSStore = create<SpendOSStore>((set) => ({
  agents: [],
  selectedAgent: null,
  transactions: [],
  setAgents: (agents) => set({ agents }),
  setSelectedAgent: (agent) => set({ selectedAgent: agent }),
  setTransactions: (txs) => set({ transactions: txs }),
  addAgent: (agent) => set((state) => ({ agents: [...state.agents, agent] })),
  updateAgent: (id, updates) =>
    set((state) => ({
      agents: state.agents.map((a) => (a.id === id ? { ...a, ...updates } : a)),
      selectedAgent:
        state.selectedAgent?.id === id
          ? { ...state.selectedAgent, ...updates }
          : state.selectedAgent,
    })),
  addTransaction: (tx) =>
    set((state) => ({ transactions: [tx, ...state.transactions] })),
}));
