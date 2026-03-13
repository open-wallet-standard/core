import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  generateMnemonic,
  deriveAddress,
  createWallet,
  listWallets,
  getWallet,
  deleteWallet,
  exportWallet,
  renameWallet,
  importWalletMnemonic,
  importWalletPrivateKey,
  signTransaction,
  signMessage,
} from '../index.js';

describe('@open-wallet-standard/node', () => {
  let vaultDir;

  before(() => {
    vaultDir = mkdtempSync(join(tmpdir(), 'ows-node-test-'));
  });

  after(() => {
    rmSync(vaultDir, { recursive: true, force: true });
  });

  // ---- Mnemonic ----

  it('generates a 12-word mnemonic', () => {
    const phrase = generateMnemonic(12);
    assert.equal(phrase.split(' ').length, 12);
  });

  it('generates a 24-word mnemonic', () => {
    const phrase = generateMnemonic(24);
    assert.equal(phrase.split(' ').length, 24);
  });

  it('derives addresses for all chains', () => {
    const phrase = generateMnemonic(12);
    for (const chain of ['evm', 'solana', 'bitcoin', 'cosmos', 'tron', 'ton']) {
      const addr = deriveAddress(phrase, chain);
      assert.ok(addr.length > 0, `address should be non-empty for ${chain}`);
    }
  });

  // ---- Universal wallet lifecycle ----

  it('creates a universal wallet with 6 accounts', () => {
    const wallet = createWallet('lifecycle-test', undefined, 12, vaultDir);
    assert.equal(wallet.name, 'lifecycle-test');
    assert.equal(wallet.accounts.length, 6);

    const chainIds = wallet.accounts.map((a) => a.chainId);
    assert.ok(chainIds.some((c) => c.startsWith('eip155:')));
    assert.ok(chainIds.some((c) => c.startsWith('solana:')));
    assert.ok(chainIds.some((c) => c.startsWith('bip122:')));
    assert.ok(chainIds.some((c) => c.startsWith('cosmos:')));
    assert.ok(chainIds.some((c) => c.startsWith('tron:')));
    assert.ok(chainIds.some((c) => c.startsWith('ton:')));

    // List
    const wallets = listWallets(vaultDir);
    assert.equal(wallets.length, 1);
    assert.equal(wallets[0].id, wallet.id);

    // Get by name
    const found = getWallet('lifecycle-test', vaultDir);
    assert.equal(found.id, wallet.id);

    // Rename
    renameWallet('lifecycle-test', 'renamed', vaultDir);
    const renamed = getWallet('renamed', vaultDir);
    assert.equal(renamed.id, wallet.id);

    // Export mnemonic
    const secret = exportWallet('renamed', undefined, vaultDir);
    assert.equal(secret.split(' ').length, 12);

    // Delete
    deleteWallet('renamed', vaultDir);
    assert.equal(listWallets(vaultDir).length, 0);
  });

  // ---- Mnemonic import round-trip ----

  it('imports a mnemonic and produces same addresses', () => {
    const phrase = generateMnemonic(12);
    const expectedEvm = deriveAddress(phrase, 'evm');
    const expectedSol = deriveAddress(phrase, 'solana');

    const wallet = importWalletMnemonic('mn-import', phrase, undefined, undefined, vaultDir);
    assert.equal(wallet.name, 'mn-import');
    assert.equal(wallet.accounts.length, 6);

    const evmAcct = wallet.accounts.find((a) => a.chainId.startsWith('eip155:'));
    assert.equal(evmAcct.address, expectedEvm);

    const solAcct = wallet.accounts.find((a) => a.chainId.startsWith('solana:'));
    assert.equal(solAcct.address, expectedSol);

    deleteWallet('mn-import', vaultDir);
  });

  // ---- Private key import (secp256k1) ----

  it('imports a secp256k1 private key with all 6 accounts', () => {
    const privkey = '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
    const wallet = importWalletPrivateKey('pk-secp', privkey, undefined, vaultDir, 'evm');

    assert.equal(wallet.name, 'pk-secp');
    assert.equal(wallet.accounts.length, 6, 'should have all 6 chain accounts');

    // Sign on EVM (provided key's curve)
    const evmSig = signMessage('pk-secp', 'evm', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(evmSig.signature.length > 0);

    // Sign on Solana (generated key's curve)
    const solSig = signMessage('pk-secp', 'solana', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(solSig.signature.length > 0);

    // Export returns JSON with both keys
    const exported = JSON.parse(exportWallet('pk-secp', undefined, vaultDir));
    assert.equal(exported.secp256k1, privkey);
    assert.ok(exported.ed25519.length === 64, 'should have 32-byte ed25519 key in hex');

    deleteWallet('pk-secp', vaultDir);
  });

  // ---- Private key import (ed25519) ----

  it('imports an ed25519 private key with all 6 accounts', () => {
    const privkey = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
    const wallet = importWalletPrivateKey('pk-ed', privkey, undefined, vaultDir, 'solana');

    assert.equal(wallet.accounts.length, 6);

    // Sign on Solana (provided key)
    const solSig = signMessage('pk-ed', 'solana', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(solSig.signature.length > 0);

    // Sign on EVM (generated key)
    const evmSig = signMessage('pk-ed', 'evm', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(evmSig.signature.length > 0);

    // Sign on TON (same ed25519 key)
    const tonSig = signMessage('pk-ed', 'ton', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(tonSig.signature.length > 0);

    deleteWallet('pk-ed', vaultDir);
  });

  // ---- Private key import (both curves) ----

  it('imports both curve keys explicitly', () => {
    const secpKey = '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
    const edKey = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';

    const wallet = importWalletPrivateKey(
      'pk-both', '', undefined, vaultDir, undefined, secpKey, edKey
    );

    assert.equal(wallet.name, 'pk-both');
    assert.equal(wallet.accounts.length, 6, 'should have all 6 chain accounts');

    // Sign on EVM (secp256k1 key)
    const evmSig = signMessage('pk-both', 'evm', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(evmSig.signature.length > 0);

    // Sign on Solana (ed25519 key)
    const solSig = signMessage('pk-both', 'solana', 'hello', undefined, undefined, undefined, vaultDir);
    assert.ok(solSig.signature.length > 0);

    // Export returns both provided keys
    const exported = JSON.parse(exportWallet('pk-both', undefined, vaultDir));
    assert.equal(exported.secp256k1, secpKey);
    assert.equal(exported.ed25519, edKey);

    deleteWallet('pk-both', vaultDir);
  });

  // ---- Signing all chains ----

  it('signs messages on all chains', () => {
    createWallet('all-chain-signer', undefined, 12, vaultDir);

    for (const chain of ['evm', 'solana', 'bitcoin', 'cosmos', 'tron', 'ton']) {
      const result = signMessage('all-chain-signer', chain, 'test', undefined, undefined, undefined, vaultDir);
      assert.ok(result.signature.length > 0, `signature should be non-empty for ${chain}`);
    }

    deleteWallet('all-chain-signer', vaultDir);
  });

  it('signs transactions on all chains', () => {
    createWallet('tx-signer', undefined, 12, vaultDir);
    const txHex = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';

    for (const chain of ['evm', 'solana', 'bitcoin', 'cosmos', 'tron', 'ton']) {
      const result = signTransaction('tx-signer', chain, txHex, undefined, undefined, vaultDir);
      assert.ok(result.signature.length > 0, `signature should be non-empty for ${chain}`);
    }

    deleteWallet('tx-signer', vaultDir);
  });

  // ---- Determinism ----

  it('produces deterministic signatures', () => {
    createWallet('det-test', undefined, 12, vaultDir);

    const sig1 = signMessage('det-test', 'evm', 'hello', undefined, undefined, undefined, vaultDir);
    const sig2 = signMessage('det-test', 'evm', 'hello', undefined, undefined, undefined, vaultDir);
    assert.equal(sig1.signature, sig2.signature);

    deleteWallet('det-test', vaultDir);
  });

  // ---- Error handling ----

  it('rejects duplicate wallet names', () => {
    createWallet('dup-name', undefined, 12, vaultDir);
    assert.throws(() => createWallet('dup-name', undefined, 12, vaultDir));
    deleteWallet('dup-name', vaultDir);
  });

  it('rejects non-existent wallet', () => {
    assert.throws(() => getWallet('nonexistent', vaultDir));
    assert.throws(() => signMessage('nonexistent', 'evm', 'x', undefined, undefined, undefined, vaultDir));
  });

  it('rejects invalid private key hex', () => {
    assert.throws(() => importWalletPrivateKey('bad', 'not-hex', undefined, vaultDir));
  });
});
