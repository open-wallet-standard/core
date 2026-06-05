#!/usr/bin/env node
/**
 * x402-upto-settlement.js
 *
 * Makes paid requests via ows pay request and tracks
 * authorized / settled / released amounts per session.
 *
 * Usage:
 *   node examples/x402-upto-settlement.js
 */

import { execSync } from "child_process";

const WALLET = process.env.OWS_WALLET || "agent-treasury";

class UptoBillingTracker {
  constructor() { this.entries = []; }

  record(taskId, maxAmount, output) {
    // Parse settled amount from ows pay request output
    const match = output.match(/amount[:\s]+([\d.]+)/i);
    const settled = match ? parseFloat(match[1]) : 0;
    const authorized = parseFloat(maxAmount);
    const released = Math.max(0, authorized - settled);
    this.entries.push({ taskId, authorized, settled, released });
    return { authorized, settled, released };
  }

  summary() {
    return {
      totalAuthorized : this.entries.reduce((s, e) => s + e.authorized, 0),
      totalSettled    : this.entries.reduce((s, e) => s + e.settled, 0),
      totalReleased   : this.entries.reduce((s, e) => s + e.released, 0),
    };
  }
}

function owsPay(url, method, body) {
  const args = [
    "ows", "pay", "request",
    "--wallet", WALLET,
    "--method", method,
    url,
  ];
  if (body) { args.push("--body", body); }
  return execSync(args.join(" "), { encoding: "utf8" });
}

const tracker = new UptoBillingTracker();

const tasks = [
  { id: "task-1", url: "https://api.example.com/summarize", maxAmount: "1.00", method: "POST", body: JSON.stringify({ text: "hello" }) },
  { id: "task-2", url: "https://api.example.com/translate", maxAmount: "0.50", method: "POST", body: JSON.stringify({ text: "hello" }) },
];

console.log("Wallet:", WALLET);
console.log("-".repeat(50));

for (const task of tasks) {
  console.log("
[" + task.id + "] " + task.url);
  try {
    const output = owsPay(task.url, task.method, task.body);
    const acc = tracker.record(task.id, task.maxAmount, output);
    console.log("  Authorized : $" + acc.authorized.toFixed(4));
    console.log("  Settled    : $" + acc.settled.toFixed(4));
    console.log("  Released   : $" + acc.released.toFixed(4));
  } catch (err) {
    console.error("  Error:", err.message);
  }
}

const s = tracker.summary();
console.log("
" + "=".repeat(50));
console.log("Total authorized : $" + s.totalAuthorized.toFixed(4));
console.log("Total settled    : $" + s.totalSettled.toFixed(4));
console.log("Total released   : $" + s.totalReleased.toFixed(4));
