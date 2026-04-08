Object.defineProperty(exports, "owsToViemAccount", {
  enumerable: true,
  get() { return require("./viem").owsToViemAccount; },
});

Object.defineProperty(exports, "owsToSolanaKeypair", {
  enumerable: true,
  get() { return require("./solana").owsToSolanaKeypair; },
});

Object.defineProperty(exports, "owsToWdkAccount", {
  enumerable: true,
  get() { return require("./wdk").owsToWdkAccount; },
});
