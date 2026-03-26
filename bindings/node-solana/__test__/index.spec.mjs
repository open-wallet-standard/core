import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  createWallet,
  getWallet,
  importWalletPrivateKey,
  signMessage,
} from '@open-wallet-standard/core';
import { owsToSolanaKeypair } from '../src/index.js';

describe('@open-wallet-standard/solana', () => {
  let vaultDir;
  const walletName = 'solana-test';
  // Known test Ed25519 private key (64 bytes hex)
  const testEd25519Key = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';

  before(() => {
    vaultDir = mkdtempSync(join(tmpdir(), 'ows-solana-test-'));
    // Import a known Ed25519 key so we can test Keypair extraction
    importWalletPrivateKey(walletName, testEd25519Key, undefined, undefined, vaultDir, undefined, undefined);
  });

  after(() => {
    rmSync(vaultDir, { recursive: true, force: true });
  });

  it('creates keypair with correct public key', () => {
    const wallet = getWallet(walletName, vaultDir);
    const solAccount = wallet.accounts.find(a => a.chainId.startsWith('solana:'));
    const keypair = owsToSolanaKeypair(walletName, { vaultPath: vaultDir });
    assert.equal(keypair.publicKey.toBase58(), solAccount.address);
  });

  it('keypair can sign messages', () => {
    const keypair = owsToSolanaKeypair(walletName, { vaultPath: vaultDir });
    const message = Buffer.from('hello solana');
    const { sign } = require('tweetnacl');
    const signature = sign.detached(message, keypair.secretKey);
    assert.equal(signature.length, 64);
  });

  it('same wallet produces same keypair', () => {
    const kp1 = owsToSolanaKeypair(walletName, { vaultPath: vaultDir });
    const kp2 = owsToSolanaKeypair(walletName, { vaultPath: vaultDir });
    assert.equal(kp1.publicKey.toBase58(), kp2.publicKey.toBase58());
  });

  it('throws for nonexistent wallet', () => {
    assert.throws(() => owsToSolanaKeypair('nonexistent', { vaultPath: vaultDir }));
  });

  it('throws for mnemonic wallets', () => {
    const mnemonicWallet = 'mnemonic-test';
    createWallet(mnemonicWallet, undefined, 12, vaultDir);
    assert.throws(
      () => owsToSolanaKeypair(mnemonicWallet, { vaultPath: vaultDir }),
      /Mnemonic wallets/
    );
  });

  it('keypair matches OWS signMessage output', () => {
    const keypair = owsToSolanaKeypair(walletName, { vaultPath: vaultDir });
    const message = 'verify-match';
    const messageHex = Buffer.from(message).toString('hex');

    // Sign via OWS native
    const owsResult = signMessage(
      walletName, 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
      messageHex, undefined, 'hex', undefined, vaultDir
    );

    // Sign via extracted Keypair
    const { sign } = require('tweetnacl');
    const keypairSig = Buffer.from(
      sign.detached(Buffer.from(messageHex, 'hex'), keypair.secretKey)
    ).toString('hex');

    assert.equal(keypairSig, owsResult.signature);
  });
});
