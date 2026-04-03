import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
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
  createPolicy,
  listPolicies,
  getPolicy,
  deletePolicy,
  createApiKey,
  listApiKeys,
  revokeApiKey,
} from '../index.js';

describe('@open-wallet-standard/core', () => {
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
    for (const chain of ['evm', 'solana', 'sui', 'bitcoin', 'cosmos', 'tron', 'ton', 'filecoin', 'xrpl']) {
      const addr = deriveAddress(phrase, chain);
      assert.ok(addr.length > 0, `address should be non-empty for ${chain}`);
    }
  });

  // ---- Universal wallet lifecycle ----

  it('creates a universal wallet with 9 accounts', () => {
    const wallet = createWallet('lifecycle-test', undefined, 12, vaultDir);
    assert.equal(wallet.name, 'lifecycle-test');
    assert.equal(wallet.accounts.length, 9);

    const chainIds = wallet.accounts.map((a) => a.chainId);
    assert.ok(chainIds.some((c) => c.startsWith('eip155:')));
    assert.ok(chainIds.some((c) => c.startsWith('solana:')));
    assert.ok(chainIds.some((c) => c.startsWith('sui:')));
    assert.ok(chainIds.some((c) => c.startsWith('bip122:')));
    assert.ok(chainIds.some((c) => c.startsWith('cosmos:')));
    assert.ok(chainIds.some((c) => c.startsWith('tron:')));
    assert.ok(chainIds.some((c) => c.startsWith('ton:')));
    assert.ok(chainIds.some((c) => c.startsWith('fil:')));
    assert.ok(chainIds.some((c) => c.startsWith('xrpl:')));

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
    assert.equal(wallet.accounts.length, 9);

    const evmAcct = wallet.accounts.find((a) => a.chainId.startsWith('eip155:'));
    assert.equal(evmAcct.address, expectedEvm);

    const solAcct = wallet.accounts.find((a) => a.chainId.startsWith('solana:'));
    assert.equal(solAcct.address, expectedSol);

    deleteWallet('mn-import', vaultDir);
  });

  // ---- Private key import (secp256k1) ----

  it('imports a secp256k1 private key with all 9 accounts', () => {
    const privkey = '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
    const wallet = importWalletPrivateKey('pk-secp', privkey, undefined, vaultDir, 'evm');

    assert.equal(wallet.name, 'pk-secp');
    assert.equal(wallet.accounts.length, 9, 'should have all 9 chain accounts');

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

  it('imports an ed25519 private key with all 9 accounts', () => {
    const privkey = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
    const wallet = importWalletPrivateKey('pk-ed', privkey, undefined, vaultDir, 'solana');

    assert.equal(wallet.accounts.length, 9);

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
    assert.equal(wallet.accounts.length, 9, 'should have all 9 chain accounts');

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

    for (const chain of ['evm', 'solana', 'sui', 'bitcoin', 'cosmos', 'tron', 'ton', 'filecoin']) {
      const result = signMessage('all-chain-signer', chain, 'test', undefined, undefined, undefined, vaultDir);
      assert.ok(result.signature.length > 0, `signature should be non-empty for ${chain}`);
    }

    deleteWallet('all-chain-signer', vaultDir);
  });

  it('signs transactions on all chains', () => {
    createWallet('tx-signer', undefined, 12, vaultDir);
    const txHex = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
    // Solana extract_signable_bytes expects a valid wire format:
    // [compact-u16 sig count][64-byte sig slots...][message...]
    // Build a minimal tx with 1 sig slot (0x01) + 64 zero bytes + a message.
    const solTxHex = '01' + '00'.repeat(64) + 'deadbeefdeadbeef';

    for (const chain of ['evm', 'solana', 'sui', 'bitcoin', 'cosmos', 'tron', 'ton', 'filecoin', 'xrpl']) {
      const hex = chain === 'solana' ? solTxHex : txHex;
      const result = signTransaction('tx-signer', chain, hex, undefined, undefined, vaultDir);
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

  // ---- Policy engine: API key signing ----

  it('creates a policy, API key by wallet name, and signs with the token', () => {
    const wallet = createWallet('policy-test', undefined, 12, vaultDir);

    // Register a policy allowing only Base
    createPolicy(JSON.stringify({
      id: 'test-base-only',
      name: 'Base Only',
      version: 1,
      created_at: '2026-03-22T00:00:00Z',
      rules: [
        { type: 'allowed_chains', chain_ids: ['eip155:8453', 'eip155:84532'] },
      ],
      action: 'deny',
    }), vaultDir);

    // Create API key by wallet name
    const key = createApiKey('test-agent', [wallet.id], ['test-base-only'], '', null, vaultDir);
    assert.ok(key.token.startsWith('ows_key_'));
    assert.equal(key.name, 'test-agent');

    // Sign on allowed chain — should succeed
    const sig = signTransaction(wallet.id, 'base', 'deadbeef', key.token, null, vaultDir);
    assert.ok(sig.signature.length > 0);

    // Sign on denied chain — should fail
    assert.throws(
      () => signTransaction(wallet.id, 'ethereum', 'deadbeef', key.token, null, vaultDir),
      (err) => err.message.includes('not in allowlist'),
    );

    // Owner mode still works on any chain
    const ownerSig = signTransaction(wallet.id, 'ethereum', 'deadbeef', '', null, vaultDir);
    assert.ok(ownerSig.signature.length > 0);

    // Revoke and verify token is dead
    revokeApiKey(key.id, vaultDir);
    assert.throws(
      () => signTransaction(wallet.id, 'base', 'deadbeef', key.token, null, vaultDir),
      (err) => err.message.includes('API key not found'),
    );

    // Cleanup
    deletePolicy('test-base-only', vaultDir);
    deleteWallet(wallet.id, vaultDir);
  });

  it('signs with an API key for a wallet imported from a private key', () => {
    createPolicy(JSON.stringify({
      id: 'test-imported-wallet',
      name: 'Imported Wallet',
      version: 1,
      created_at: '2026-03-31T00:00:00Z',
      rules: [
        { type: 'allowed_chains', chain_ids: ['eip155:8453'] },
      ],
      action: 'deny',
    }), vaultDir);

    const wallet = importWalletPrivateKey(
      'policy-imported-wallet',
      'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
      '',
      vaultDir,
      'evm',
    );
    const key = createApiKey(
      'imported-wallet-agent',
      [wallet.id],
      ['test-imported-wallet'],
      '',
      null,
      vaultDir,
    );

    const msgSig = signMessage(
      wallet.id,
      'base',
      'hello',
      key.token,
      undefined,
      undefined,
      vaultDir,
    );
    assert.ok(msgSig.signature.length > 0);

    const txSig = signTransaction(wallet.id, 'base', 'deadbeef', key.token, null, vaultDir);
    assert.ok(txSig.signature.length > 0);

    revokeApiKey(key.id, vaultDir);
    deletePolicy('test-imported-wallet', vaultDir);
    deleteWallet(wallet.id, vaultDir);
  });

  it('executable policy gates signing', () => {
    const wallet = createWallet('exe-test', undefined, 12, vaultDir);

    // Write a deny script
    const scriptPath = join(vaultDir, 'deny.sh');
    writeFileSync(scriptPath, '#!/bin/sh\ncat > /dev/null\necho \'{"allow":false,"reason":"custom: blocked"}\'\n', { mode: 0o755 });

    createPolicy(JSON.stringify({
      id: 'test-exe-deny',
      name: 'Executable Deny',
      version: 1,
      created_at: '2026-03-22T00:00:00Z',
      rules: [],
      executable: scriptPath,
      action: 'deny',
    }), vaultDir);

    const key = createApiKey('exe-agent', [wallet.id], ['test-exe-deny'], '', null, vaultDir);

    assert.throws(
      () => signTransaction(wallet.id, 'evm', 'deadbeef', key.token, null, vaultDir),
      (err) => err.message.includes('custom: blocked'),
    );

    revokeApiKey(key.id, vaultDir);
    deletePolicy('test-exe-deny', vaultDir);
    deleteWallet(wallet.id, vaultDir);
  });
});
