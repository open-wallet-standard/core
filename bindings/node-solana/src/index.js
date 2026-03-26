/**
 * @open-wallet-standard/solana
 *
 * Creates a Solana Keypair backed by an OWS wallet.
 */

const { exportWallet } = require("@open-wallet-standard/core");

/**
 * Create a Solana Keypair from an OWS wallet.
 *
 * @param {string} walletNameOrId - OWS wallet name or UUID
 * @param {object} [options]
 * @param {string} [options.passphrase] - Vault passphrase
 * @param {string} [options.vaultPath] - Custom vault path
 * @returns {import("@solana/web3.js").Keypair}
 */
function owsToSolanaKeypair(walletNameOrId, options = {}) {
  const { Keypair } = require("@solana/web3.js");

  const exported = exportWallet(
    walletNameOrId,
    options.passphrase,
    options.vaultPath
  );

  let secretKey;
  try {
    const keys = JSON.parse(exported);
    const hex = keys.ed25519 ?? "";
    const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
    secretKey = Uint8Array.from(
      clean.match(/.{2}/g).map((b) => parseInt(b, 16))
    );
  } catch {
    throw new Error(
      "Mnemonic wallets: use @open-wallet-standard/core signMessage/signTransaction " +
        "directly, or import with a private key for Keypair access."
    );
  }

  return Keypair.fromSecretKey(secretKey);
}

module.exports = { owsToSolanaKeypair };
