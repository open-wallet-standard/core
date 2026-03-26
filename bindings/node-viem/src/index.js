/**
 * @open-wallet-standard/viem
 *
 * Creates a viem Account backed by an OWS wallet.
 * All signing is delegated to OWS — the key never leaves the vault.
 */

const { getWallet, signMessage, signTypedData, signTransaction } = require("@open-wallet-standard/core");
const { toAccount } = require("viem/accounts");

/**
 * Create a viem Account from an OWS wallet.
 *
 * @param {string} walletNameOrId - OWS wallet name or UUID
 * @param {object} [options]
 * @param {string} [options.chain] - CAIP-2 chain ID (default: "eip155:1")
 * @param {string} [options.passphrase] - Vault passphrase
 * @param {number} [options.index] - BIP-44 account index
 * @param {string} [options.vaultPath] - Custom vault path
 * @returns {import("viem").Account}
 */
function owsToViemAccount(walletNameOrId, options = {}) {
  const chain = options.chain ?? "eip155:1";
  const wallet = getWallet(walletNameOrId, options.vaultPath);

  const evmAccount =
    wallet.accounts.find((a) => a.chainId === chain) ??
    wallet.accounts.find((a) => a.chainId.startsWith("eip155:"));

  if (!evmAccount) {
    throw new Error(
      `No EVM account found in wallet "${walletNameOrId}". ` +
        `Available chains: ${wallet.accounts.map((a) => a.chainId).join(", ")}`
    );
  }

  const address = evmAccount.address;

  return toAccount({
    address,

    async signMessage({ message }) {
      const msg =
        typeof message === "string"
          ? message
          : Buffer.from(message.raw ?? message).toString("hex");
      const result = signMessage(
        walletNameOrId, chain, msg,
        options.passphrase,
        typeof message === "string" ? undefined : "hex",
        options.index, options.vaultPath
      );
      return result.signature.startsWith("0x")
        ? result.signature
        : `0x${result.signature}`;
    },

    async signTransaction(transaction) {
      const txHex =
        typeof transaction === "string"
          ? transaction
          : JSON.stringify(transaction);
      const result = signTransaction(
        walletNameOrId, chain, txHex,
        options.passphrase, options.index, options.vaultPath
      );
      return result.signature.startsWith("0x")
        ? result.signature
        : `0x${result.signature}`;
    },

    async signTypedData(typedData) {
      const result = signTypedData(
        walletNameOrId, chain, JSON.stringify(typedData),
        options.passphrase, options.index, options.vaultPath
      );
      return result.signature.startsWith("0x")
        ? result.signature
        : `0x${result.signature}`;
    },
  });
}

module.exports = { owsToViemAccount };
