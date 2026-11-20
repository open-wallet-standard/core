//! Milestone gate: ows-midnight derives and holds NO key material.
//!
//! After the seed-free refactor, every ows-midnight entry point takes a `&MidnightCryptoProvider`
//! (built once in ows-lib, which owns the credential) rather than a raw `&SecretBytes`. All
//! key/seed derivation lives in ows-signer's `MidnightCryptoProvider`; ows-midnight only ever
//! borrows the already-built provider and receives public outputs.
//!
//! One channel does carry secrets through ows-midnight: proving. The signer builds each spend's proof
//! preimage, whose witnesses include the key that authorizes it (the coin secret key of a shielded
//! spend, the dust secret key of a DUST spend), and hands it to ows-midnight's `Prover`, which proves
//! it in process or posts it to the proof server the vault's config names. The second test gates that
//! channel.
//!
//! These tests fail if any credential/key-derivation marker reappears in ows-midnight's *production*
//! source (`src`, outside `#[cfg(test)]` blocks), or if the proving channel widens. They are
//! regression tripwires, not proofs — but a reintroduced `SecretBytes` param, a seed-decoding helper,
//! a new preimage sink or a default proof server will trip them.
//!
//! Implementation invariant: the `#[cfg(test)]`-stripping brace-counts from each attribute to
//! end-of-file, so it relies on every test module being the file's last top-level item (all
//! currently are). If a file ever places production code after a test module, revisit this.
//!
//! Scope note on `[u8; 32]`: it is deliberately **not** a gate marker. Production ows-midnight has
//! legitimate non-secret 32-byte arrays — a `TokenType::Custom([u8; 32])` token id and a decoded
//! bech32m address payload (`UserAddress`), both public. The gate targets key/credential markers,
//! not every 32-byte buffer; a secret would arrive as `SecretBytes` (which IS gated), never as a
//! bare array.

use std::fs;
use std::path::{Path, PathBuf};

/// Key/credential markers that must not appear in ows-midnight production code. Each names either a
/// raw credential type (`SecretBytes`), a seed/key-decoding helper (`decode_keys`,
/// `derive_secret_key`, `zswap_secret_keys_from_seed`, `shielded_keys_for`), a secret-bearing key
/// type (`MidnightRoleSeeds`, `ZswapSecretKeys`, `DustSecretKey`), or a builder of spend preimages
/// (`build_preimage_`), which carry the secret key as a proof witness — fee sizing gets mock-proven
/// sections from the provider instead. All of these now live only in ows-signer.
const FORBIDDEN_MARKERS: &[&str] = &[
    "SecretBytes",
    "decode_keys",
    "derive_secret_key",
    "zswap_secret_keys_from_seed",
    "MidnightRoleSeeds",
    "ZswapSecretKeys",
    "DustSecretKey",
    "shielded_keys_for",
    "build_preimage_",
];

/// Recursively collect every `.rs` file under `dir`.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Strip every `#[cfg(test)]`-gated item (module or fn) from `source`, returning only the production
/// lines paired with their 1-based line numbers. When a `#[cfg(test)]` attribute is seen, the
/// following braced item is skipped in its entirety by brace counting — so inline `mod tests { … }`
/// and any `#[cfg(test)] fn …` are excluded, along with everything they contain.
fn production_lines(source: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut lines = source.lines().enumerate().peekable();

    while let Some((idx, line)) = lines.next() {
        if line.trim_start().starts_with("#[cfg(test)]") {
            // Consume up to and including the first `{`, then balance braces to the matching `}`.
            let mut depth: i32 = 0;
            let mut opened = false;
            // The attribute line itself carries no brace; scan forward from the next line.
            for (_, item_line) in lines.by_ref() {
                for ch in item_line.chars() {
                    match ch {
                        '{' => {
                            depth += 1;
                            opened = true;
                        }
                        '}' => depth -= 1,
                        _ => {}
                    }
                }
                if opened && depth <= 0 {
                    break;
                }
            }
            continue;
        }
        out.push((idx + 1, line));
    }
    out
}

/// Drop the `//`-comment tail of a line, respecting neither strings nor block comments — a marker in
/// a `//` doc/line comment is not code, so it must not trip the gate. (Block comments `/* … */` are
/// not used to hold these markers in this crate; if that changes, extend this.)
fn strip_line_comment(line: &str) -> &str {
    match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    }
}

/// Every production `.rs` file under `src`, by its path relative to `src`, with its source.
fn production_sources() -> Vec<(String, String)> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    assert!(!files.is_empty(), "found no source files under {src:?}");
    files
        .iter()
        .map(|file| {
            let relative = file.strip_prefix(&src).expect("file under src");
            (
                relative.to_string_lossy().replace('\\', "/"),
                fs::read_to_string(file).expect("read source file"),
            )
        })
        .collect()
}

#[test]
fn ows_midnight_production_holds_no_key_material() {
    let mut violations: Vec<String> = Vec::new();

    for (file, source) in &production_sources() {
        for (lineno, line) in production_lines(source) {
            let code = strip_line_comment(line);
            for marker in FORBIDDEN_MARKERS {
                if code.contains(marker) {
                    violations.push(format!(
                        "{file}:{lineno}: forbidden key-material marker `{marker}` in production code:\n    {}",
                        line.trim()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "ows-midnight production code must hold no key material — the crypto provider is built in \
         ows-lib and only `&MidnightCryptoProvider` crosses into ows-midnight. Found:\n{}",
        violations.join("\n")
    );
}

/// The proving channel, the one place a spend's secret key passes through ows-midnight, stays as narrow
/// as it is: only the prover and the outputs-only mock prover take preimages as a `ProvingProvider`, no
/// production code Debug-formats a preimage (into an error, a log or stderr), the prover serializes a
/// preimage only into the request buffer it wipes after sending, and a remote proof server is used only
/// when the vault's config names one, never by default.
#[test]
fn the_proving_channel_is_confined_and_remote_proving_is_opt_in() {
    const PROVING_PROVIDERS: &[&str] = &["prover.rs", "dapp_connector/build.rs"];
    let mut violations: Vec<String> = Vec::new();
    let mut remote_sites = Vec::new();

    for (file, source) in &production_sources() {
        let code: Vec<(usize, &str)> = production_lines(source)
            .into_iter()
            .map(|(lineno, line)| (lineno, strip_line_comment(line)))
            .collect();
        for &(lineno, line) in &code {
            let at = || format!("{file}:{lineno}: {}", line.trim());
            if line.contains("ProvingProvider for") && !PROVING_PROVIDERS.contains(&file.as_str()) {
                violations.push(format!(
                    "a new ProvingProvider receives preimages: {}",
                    at()
                ));
            }
            if line.to_lowercase().contains("preimage") && line.contains(":?") {
                violations.push(format!("a preimage is Debug-formatted: {}", at()));
            }
            if line.contains("Prover::remote(") {
                remote_sites.push(at());
            }
        }
        if file == "prover.rs" {
            let serializations = code
                .iter()
                .filter(|(_, line)| line.contains("tagged_serialize("))
                .count();
            if serializations != 1 {
                violations.push(format!(
                    "prover.rs serializes in {serializations} places; a preimage must only go \
                     through request_body's wiped buffer"
                ));
            }
            for &(lineno, line) in &code {
                if line.contains(".body(") && !line.contains("from_owner(") {
                    violations.push(format!(
                        "prover.rs:{lineno}: a proof-server body the client cannot wipe: {}",
                        line.trim()
                    ));
                }
            }
        }
    }

    if remote_sites.len() != 1 || !remote_sites[0].starts_with("balance_tx.rs:") {
        violations.push(format!(
            "a remote prover must be built only by midnight_prover, from the vault's `:prover` \
             entry; found: {remote_sites:?}"
        ));
    }
    let defaults = ows_core::Config::default();
    for key in defaults.rpc.keys().filter(|k| k.ends_with(":prover")) {
        violations.push(format!("the built-in config names a proof server: {key}"));
    }

    assert!(
        violations.is_empty(),
        "the proving channel widened:\n{}",
        violations.join("\n")
    );
}
