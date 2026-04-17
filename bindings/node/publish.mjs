#!/usr/bin/env node
/**
 * Publishes @goplausible/ows-core packages to npm.
 *
 * Builds the native module for all 4 target platforms, copies each binary
 * into the corresponding npm/<platform> directory, and publishes all platform
 * packages + the main package.
 *
 * Cross-compilation requirements:
 *   - rustup target add x86_64-apple-darwin aarch64-apple-darwin
 *     x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
 *   - cargo install cross --git https://github.com/cross-rs/cross
 *   - Docker Desktop running (for Linux targets)
 *
 * Usage:
 *   node publish.mjs            # publish all
 *   node publish.mjs --dry-run  # preview without publishing
 *   node publish.mjs --build-only # build binaries, skip publish
 */

import { execSync } from 'node:child_process';
import { copyFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const dryRun = process.argv.includes('--dry-run');
const buildOnly = process.argv.includes('--build-only');
const flag = dryRun ? '--dry-run' : '';

// Mapping: Rust target triple → napi platform directory name
const TARGETS = [
  { triple: 'aarch64-apple-darwin', platform: 'darwin-arm64', cross: false },
  { triple: 'x86_64-apple-darwin', platform: 'darwin-x64', cross: false },
  { triple: 'x86_64-unknown-linux-gnu', platform: 'linux-x64-gnu', cross: true },
  { triple: 'aarch64-unknown-linux-gnu', platform: 'linux-arm64-gnu', cross: true },
];

function run(cmd, opts = {}) {
  console.log(`\x1b[1;34m==>\x1b[0m ${cmd}`);
  return execSync(cmd, { stdio: 'inherit', cwd: __dirname, ...opts });
}

function info(msg) {
  console.log(`\x1b[1;34m==>\x1b[0m ${msg}`);
}

// 1. Build the native module for all 4 targets
for (const { triple, platform, cross } of TARGETS) {
  info(`Building for ${triple} (${platform})`);
  // For Linux targets, use `cross` (Docker-based) instead of `cargo` by setting CARGO env.
  const env = cross ? { ...process.env, CARGO: 'cross' } : process.env;
  run(`npx napi build --platform --release --target ${triple}`, { env });

  // napi build emits ows-node.<platform>.node at the root
  const nodeFile = `ows-node.${platform}.node`;
  const srcPath = join(__dirname, nodeFile);
  if (!existsSync(srcPath)) {
    console.error(`Expected ${nodeFile} after build, not found`);
    process.exit(1);
  }

  const platformDir = join(__dirname, 'npm', platform);
  if (!existsSync(platformDir)) {
    console.error(`Platform directory npm/${platform} does not exist`);
    process.exit(1);
  }

  copyFileSync(srcPath, join(platformDir, nodeFile));
  info(`Copied ${nodeFile} → npm/${platform}/`);
}

if (buildOnly) {
  console.log('\n\x1b[1;32mBuild complete.\x1b[0m');
  process.exit(0);
}

// 2. Publish all platform packages (main package depends on them via optionalDependencies)
for (const { platform } of TARGETS) {
  const platformDir = join(__dirname, 'npm', platform);
  info(`Publishing @goplausible/ows-core-${platform}`);
  run(`npm publish ${flag} --access public`, { cwd: platformDir });
}

// 3. Publish the main package
info('Publishing @goplausible/ows-core (main)');
run(`npm publish ${flag} --access public`);

console.log('\n\x1b[1;32mDone!\x1b[0m');
