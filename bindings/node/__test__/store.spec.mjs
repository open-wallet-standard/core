import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { createOws } from '../index.js';

describe('OWS with custom store', () => {

  it('creates and lists wallets with an in-memory JS store', () => {
    const data = new Map();

    const ows = createOws({
      store: {
        get: (key) => data.get(key) ?? null,
        set: (key, value) => { data.set(key, value); },
        remove: (key) => { data.delete(key); },
        list: (prefix) => [...data.keys()].filter(k => k.startsWith(prefix + '/')),
      }
    });

    // Create a wallet
    const wallet = ows.createWallet('test-wallet', 'pass123');
    assert.ok(wallet.id, 'wallet should have an id');
    assert.equal(wallet.name, 'test-wallet');
    assert.ok(wallet.accounts.length > 0, 'wallet should have accounts');

    // List wallets
    const wallets = ows.listWallets();
    assert.equal(wallets.length, 1);
    assert.equal(wallets[0].name, 'test-wallet');

    // Get wallet by id
    const fetched = ows.getWallet(wallet.id);
    assert.equal(fetched.id, wallet.id);

    // Get wallet by name
    const byName = ows.getWallet('test-wallet');
    assert.equal(byName.id, wallet.id);

    // Verify data is in our Map (not on the filesystem)
    assert.ok(data.size > 0, 'store should contain data');
    const walletKey = [...data.keys()].find(k => k.startsWith('wallets/'));
    assert.ok(walletKey, 'should have a wallets/ key');
    const walletJson = JSON.parse(data.get(walletKey));
    assert.equal(walletJson.name, 'test-wallet');

    console.log(`  stored ${data.size} entries in JS Map:`);
    for (const key of data.keys()) {
      console.log(`    ${key}`);
    }
  });

  it('exports and re-imports a wallet via custom store', () => {
    const data = new Map();
    const store = {
      get: (key) => data.get(key) ?? null,
      set: (key, value) => { data.set(key, value); },
      remove: (key) => { data.delete(key); },
      list: (prefix) => [...data.keys()].filter(k => k.startsWith(prefix + '/')),
    };
    const ows = createOws({ store });

    const wallet = ows.createWallet('exportable', 'mypass');

    // Export the mnemonic
    const mnemonic = ows.exportWallet(wallet.id, 'mypass');
    assert.equal(mnemonic.split(' ').length, 12, 'should export a 12-word mnemonic');

    // Delete it
    ows.deleteWallet(wallet.id);
    assert.equal(ows.listWallets().length, 0);

    // Re-import
    const reimported = ows.importWalletMnemonic('reimported', mnemonic, 'newpass');
    assert.equal(reimported.name, 'reimported');
    assert.equal(ows.listWallets().length, 1);
  });

  it('signs a message with a wallet in a custom store', () => {
    const data = new Map();
    const ows = createOws({
      store: {
        get: (key) => data.get(key) ?? null,
        set: (key, value) => { data.set(key, value); },
        remove: (key) => { data.delete(key); },
        list: (prefix) => [...data.keys()].filter(k => k.startsWith(prefix + '/')),
      }
    });

    const wallet = ows.createWallet('signer', 'pass');
    const result = ows.signMessage(wallet.id, 'evm', 'hello world', 'pass');
    assert.ok(result.signature, 'should return a signature');
    assert.ok(result.signature.length > 0, 'signature should be non-empty');
    console.log(`  signature: ${result.signature.substring(0, 40)}...`);
  });

  it('works with a store that has no list method (uses index)', () => {
    const data = new Map();

    // No `list` method — library should maintain _index keys automatically
    const ows = createOws({
      store: {
        get: (key) => data.get(key) ?? null,
        set: (key, value) => { data.set(key, value); },
        remove: (key) => { data.delete(key); },
      }
    });

    ows.createWallet('w1', 'p');
    ows.createWallet('w2', 'p');

    const wallets = ows.listWallets();
    assert.equal(wallets.length, 2, 'should list both wallets using index');

    // Verify the index key exists
    const indexKey = '_index/wallets';
    const indexValue = data.get(indexKey);
    assert.ok(indexValue, 'should have an _index/wallets key');
    const index = JSON.parse(indexValue);
    assert.equal(index.length, 2, 'index should have 2 entries');
    console.log(`  index keys: ${JSON.stringify(index)}`);
  });

  it('default store (no options) uses filesystem', () => {
    // Just verify it constructs without error
    const ows = createOws();
    assert.ok(ows, 'should create with default FsStore');
  });
});
