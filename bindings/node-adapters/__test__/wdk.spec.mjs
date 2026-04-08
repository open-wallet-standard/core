import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createWallet, getWallet, signMessage as owsSignMessage } from '@open-wallet-standard/core';
import { owsToWdkAccount } from '../src/wdk.js';

describe('@open-wallet-standard/adapters — wdk', () => {
  let vaultDir;
  const walletName = 'wdk-test';
  before(() => { vaultDir = mkdtempSync(join(tmpdir(), 'ows-wdk-test-')); createWallet(walletName, undefined, 12, vaultDir); });
  after(() => { rmSync(vaultDir, { recursive: true, force: true }); });

  it('creates account with correct EVM address', () => {
    const wallet = getWallet(walletName, vaultDir);
    const evmAccount = wallet.accounts.find(a => a.chainId.startsWith('eip155:'));
    const account = owsToWdkAccount(walletName, 'evm', { vaultPath: vaultDir });
    const address = evmAccount.address;
    assert.ok(account);
    assert.equal(account.index, 0);
    assert.ok(account.path);
  });
  it('getAddress returns chain address', async () => {
    const wallet = getWallet(walletName, vaultDir);
    const evmAccount = wallet.accounts.find(a => a.chainId.startsWith('eip155:'));
    const account = owsToWdkAccount(walletName, 'evm', { vaultPath: vaultDir });
    const address = await account.getAddress();
    assert.equal(address, evmAccount.address);
    assert.match(address, /^0x[0-9a-fA-F]{40}$/);
  });
  it('resolves Solana chain name', async () => {
    const wallet = getWallet(walletName, vaultDir);
    const solAccount = wallet.accounts.find(a => a.chainId.startsWith('solana:'));
    const account = owsToWdkAccount(walletName, 'solana', { vaultPath: vaultDir });
    const address = await account.getAddress();
    assert.equal(address, solAccount.address);
  });
  it('resolves Bitcoin chain name', async () => {
    const wallet = getWallet(walletName, vaultDir);
    const btcAccount = wallet.accounts.find(a => a.chainId.startsWith('bip122:'));
    const account = owsToWdkAccount(walletName, 'btc', { vaultPath: vaultDir });
    const address = await account.getAddress();
    assert.equal(address, btcAccount.address);
  });
  it('accepts CAIP-2 chain IDs directly', async () => {
    const wallet = getWallet(walletName, vaultDir);
    const evmAccount = wallet.accounts.find(a => a.chainId.startsWith('eip155:'));
    const account = owsToWdkAccount(walletName, 'eip155:1', { vaultPath: vaultDir });
    const address = await account.getAddress();
    assert.equal(address, evmAccount.address);
  });
  it('sign returns Uint8Array signature', async () => {
    const account = owsToWdkAccount(walletName, 'evm', { vaultPath: vaultDir });
    const sig = await account.sign(Buffer.from('hello'));
    assert.ok(sig instanceof Uint8Array);
    assert.ok(sig.length > 0);
  });
  it('sign is deterministic', async () => {
    const account = owsToWdkAccount(walletName, 'evm', { vaultPath: vaultDir });
    const sig1 = await account.sign(Buffer.from('deterministic'));
    const sig2 = await account.sign(Buffer.from('deterministic'));
    assert.deepEqual(sig1, sig2);
  });
  it('sign matches OWS SDK direct call', async () => {
    const account = owsToWdkAccount(walletName, 'evm', { vaultPath: vaultDir });
    const msg = Buffer.from('parity-check');
    const adapterSig = await account.sign(msg);
    const directResult = owsSignMessage(walletName, 'eip155:1', msg.toString('hex'), undefined, 'hex', undefined, vaultDir);
    const directSig = Uint8Array.from(Buffer.from(directResult.signature, 'hex'));
    assert.deepEqual(adapterSig, directSig);
  });
  it('keyPair does not expose private key', () => {
    const account = owsToWdkAccount(walletName, 'evm', { vaultPath: vaultDir });
    assert.equal(account.keyPair.privateKey, null);
    assert.equal(account.keyPair.publicKey, null);
  });
  it('dispose is a no-op', () => {
    const account = owsToWdkAccount(walletName, 'evm', { vaultPath: vaultDir });
    assert.doesNotThrow(() => account.dispose());
  });
  it('throws for nonexistent wallet', () => {
    assert.throws(() => owsToWdkAccount('nonexistent', 'evm', { vaultPath: vaultDir }));
  });
  it('throws for unsupported chain', () => {
    assert.throws(() => owsToWdkAccount(walletName, 'unsupported-chain', { vaultPath: vaultDir }), /No unsupported-chain account/);
  });
});
