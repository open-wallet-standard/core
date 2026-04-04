# SpendOS - Agent Wallet Management

**Stripe Dashboard for AI Agents** - Give agents wallets, not blank checks.

SpendOS is a dashboard for managing AI agent spending limits, API keys, and transaction policies. Built for the [Open Wallet Standard](https://github.com/open-wallet-standard/core) hackathon.

## Live Demo

🔗 **https://spendos-ten.vercel.app**

## What is SpendOS?

SpendOS solves the problem of giving AI agents access to wallets without giving them unlimited funds. It's the missing trust layer for autonomous agents.

```
┌─────────────┐      ┌──────────────┐      ┌─────────┐
│  AI Agent  │ ──── │   SpendOS   │ ──── │   OWS   │
│             │      │  Dashboard  │      │ Wallet  │
└─────────────┘      │             │      └─────────┘
                      │ • API Keys  │
                      │ • Limits    │
                      │ • Policies  │
                      │ • Audit Logs│
                      └──────────────┘
```

## Features

- **Agent Wallet Management** - Create and manage multiple agent wallets
- **Spending Limits** - Set daily/monthly limits per agent
- **Chain Restrictions** - Control which chains each agent can use
- **API Key Generation** - Secure API keys for agent authentication
- **Real-time Activity** - Monitor all transactions
- **Policy Enforcement** - Pause, resume, or revoke agents instantly

## Track 02: Agent Spend Governance & Identity

This project demonstrates:
- Dead man's switch for autonomous agents
- Policy-based spending controls
- Agent identity and access management

## Tech Stack

- **Framework:** Next.js 16 + TypeScript
- **Styling:** Tailwind CSS (Institutional Stripe aesthetic)
- **Animations:** Framer Motion
- **Icons:** Lucide React
- **Database:** SQLite (Prisma) - production-ready for Supabase/PostgreSQL

## Getting Started

```bash
# Clone the repo
git clone https://github.com/dolepee/spendos.git
cd spendos

# Install dependencies
npm install

# Run development server
npm run dev

# Open http://localhost:3000
```

## OWS Integration

SpendOS is designed to work with the [Open Wallet Standard](https://github.com/open-wallet-standard/core) CLI (`ows`):

```bash
# Create an agent wallet
ows wallet create --name "content-agent"

# Issue an API key
ows policy create-key --wallet content-agent --limit 50 --chain ethereum

# Agent uses the API key to spend
ows sign tx --chain ethereum --tx <hex> --wallet content-agent
```

## Hackathon Demo Flow

1. **Create an Agent** → Click "Create Agent" with name, limits, and chains
2. **Get API Key** → Click "API Key" on the agent card
3. **Monitor Spending** → Watch the progress bar fill as transactions occur
4. **Control Access** → Pause, resume, or revoke agents instantly
5. **View Activity** → See all transactions in real-time with OWS verification

## Screenshots

### Dashboard
- Total spend across all agents
- Active/paused agent counts
- Pending transaction alerts
- Security status indicator

### Agent Cards
- Visual spending progress bars
- Chain indicators
- Status badges (active/paused/revoked)
- Quick API key access

### Activity Feed
- Transaction amounts and statuses
- Chain-specific badges
- OWS verification badges
- Timestamps

## Future Enhancements

- [ ] Connect to real OWS wallet
- [ ] Multi-signature support (leverage guardian shards)
- [ ] Time-based spending windows
- [ ] Vendor allowlists
- [ ] Anomaly detection alerts
- [ ] Agent reputation scoring

## License

MIT
