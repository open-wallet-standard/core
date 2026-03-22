use std::io::IsTerminal;

use crate::audit;
use crate::CliError;
use zeroize::Zeroize;

pub fn create(name: &str, words: u32, show_mnemonic: bool) -> Result<(), CliError> {
    // Generate mnemonic, then import it to create the wallet
    let mut mnemonic_phrase = ows_lib::generate_mnemonic(words)?;
    let passphrase = super::read_new_passphrase()?;
    let info = ows_lib::import_wallet_mnemonic(
        name,
        &mnemonic_phrase,
        Some(passphrase.as_str()),
        Some(0),
        None,
    )?;

    audit::log_wallet_created(&info);

    println!("Wallet created: {}", info.id);
    println!("Name:           {name}");
    println!();
    for acct in &info.accounts {
        println!("  {} → {}", acct.chain_id, acct.address);
        if !acct.derivation_path.is_empty() {
            println!("    Path: {}", acct.derivation_path);
        }
    }

    if show_mnemonic {
        eprintln!();
        eprintln!("⚠️  WARNING: The mnemonic below provides FULL ACCESS to this wallet.");
        eprintln!("⚠️  Store it securely offline. It will NOT be shown again.");
        eprintln!();
        println!("{mnemonic_phrase}");
    } else if passphrase.is_empty() {
        eprintln!();
        eprintln!("Wallet saved without a passphrase.");
        eprintln!("Set OWS_PASSPHRASE when creating wallets to avoid accidental empty-passphrase storage.");
    } else {
        eprintln!();
        eprintln!("Mnemonic encrypted and saved to vault.");
        eprintln!(
            "Use `ows wallet unlock --wallet {name}` to cache the passphrase in your OS keyring."
        );
        eprintln!("Use --show-mnemonic at creation time if you need a backup copy.");
    }

    mnemonic_phrase.zeroize();
    Ok(())
}

pub fn import(
    name: &str,
    use_mnemonic: bool,
    use_private_key: bool,
    chain: Option<&str>,
    index: u32,
) -> Result<(), CliError> {
    // Read curve-specific keys from environment variables (cleared immediately after reading)
    let secp256k1_key = ows_signer::process_hardening::clear_env_var("OWS_SECP256K1_KEY");
    let ed25519_key = ows_signer::process_hardening::clear_env_var("OWS_ED25519_KEY");
    let secp256k1_key = secp256k1_key.as_deref().filter(|s| !s.is_empty());
    let ed25519_key = ed25519_key.as_deref().filter(|s| !s.is_empty());

    let has_curve_keys = secp256k1_key.is_some() || ed25519_key.is_some();
    let both_curve_keys = secp256k1_key.is_some() && ed25519_key.is_some();

    // Must specify exactly one import mode: --mnemonic, --private-key, or both curve keys (via env)
    if use_mnemonic && (use_private_key || has_curve_keys) {
        return Err(CliError::InvalidArgs(
            "cannot combine --mnemonic with --private-key or curve-specific keys".into(),
        ));
    }
    if !use_mnemonic && !use_private_key && !both_curve_keys {
        return Err(CliError::InvalidArgs(
            "specify --mnemonic, --private-key, or set OWS_SECP256K1_KEY and OWS_ED25519_KEY"
                .into(),
        ));
    }
    let passphrase = super::read_new_passphrase()?;

    let info = if use_mnemonic {
        let phrase = super::read_mnemonic()?;
        ows_lib::import_wallet_mnemonic(
            name,
            &phrase,
            Some(passphrase.as_str()),
            Some(index),
            None,
        )?
    } else {
        // Read from env/stdin only when both curve keys are not already provided
        let private_key_hex = if both_curve_keys {
            zeroize::Zeroizing::new(String::new())
        } else {
            super::read_private_key()?
        };
        ows_lib::import_wallet_private_key(
            name,
            &private_key_hex,
            chain,
            Some(passphrase.as_str()),
            None,
            secp256k1_key,
            ed25519_key,
        )?
    };

    audit::log_wallet_imported(&info);

    println!("Wallet imported: {}", info.id);
    println!("Name:            {name}");
    println!();
    for acct in &info.accounts {
        println!("  {} → {}", acct.chain_id, acct.address);
        if !acct.derivation_path.is_empty() {
            println!("    Path: {}", acct.derivation_path);
        }
    }

    Ok(())
}

pub fn export(wallet_name: &str) -> Result<(), CliError> {
    if !std::io::stdin().is_terminal() {
        return Err(CliError::InvalidArgs(
            "wallet export requires an interactive terminal (do not pipe stdin)".into(),
        ));
    }

    let passphrase = super::resolve_wallet_passphrase(wallet_name)?;
    let mut exported = ows_lib::export_wallet(wallet_name, Some(passphrase.as_str()), None)?;

    let is_key_pair = exported.starts_with('{');
    eprintln!();
    if is_key_pair {
        eprintln!("WARNING: The private key below provides FULL ACCESS to this wallet.");
    } else {
        eprintln!("WARNING: The mnemonic below provides FULL ACCESS to this wallet.");
    }
    eprintln!("Do not share it. Store it securely offline.");
    eprintln!();
    println!("{exported}");
    exported.zeroize();

    let info = ows_lib::get_wallet(wallet_name, None)?;
    audit::log_wallet_exported(&info.id);
    Ok(())
}

pub fn unlock(wallet_name: &str) -> Result<(), CliError> {
    let wallet = crate::vault::load_wallet_by_name_or_id(wallet_name)?;

    if super::wallet_accepts_passphrase(&wallet, "")? {
        println!(
            "Wallet '{}' uses an empty passphrase. Nothing was cached.",
            wallet.name
        );
        return Ok(());
    }

    let passphrase = super::read_passphrase()?;
    super::ensure_wallet_passphrase(&wallet, passphrase.as_str())?;
    crate::passphrase_cache::store(passphrase.as_str(), None)?;

    println!("Vault unlocked.");
    println!("Passphrase cached in the OS keyring for interactive CLI workflows.");
    Ok(())
}

pub fn lock() -> Result<(), CliError> {
    if crate::passphrase_cache::delete(None)? {
        println!("Cleared cached vault passphrase.");
    } else {
        println!("No cached vault passphrase found.");
    }
    Ok(())
}

pub fn status() -> Result<(), CliError> {
    if crate::passphrase_cache::status(None)? {
        println!("Vault status: unlocked (passphrase cached in OS keyring)");
    } else {
        println!("Vault status: locked");
    }
    Ok(())
}

pub fn delete(wallet_name: &str, confirm: bool) -> Result<(), CliError> {
    if !confirm {
        eprintln!("To delete a wallet, pass --confirm.");
        eprintln!("Consider exporting it first: ows wallet export --wallet {wallet_name}");
        return Err(CliError::InvalidArgs(
            "--confirm is required to delete a wallet".into(),
        ));
    }

    let info = ows_lib::get_wallet(wallet_name, None)?;
    ows_lib::delete_wallet(wallet_name, None)?;
    audit::log_wallet_deleted(&info.id, &info.name);

    println!("Wallet deleted: {} ({})", info.id, info.name);
    Ok(())
}

pub fn rename(wallet_name: &str, new_name: &str) -> Result<(), CliError> {
    let info = ows_lib::get_wallet(wallet_name, None)?;
    ows_lib::rename_wallet(wallet_name, new_name, None)?;
    audit::log_wallet_renamed(&info.id, &info.name, new_name);

    println!("Wallet renamed: '{}' -> '{}'", info.name, new_name);
    Ok(())
}

pub fn list() -> Result<(), CliError> {
    let wallets = ows_lib::list_wallets(None)?;

    if wallets.is_empty() {
        println!("No wallets found.");
        return Ok(());
    }

    for w in &wallets {
        println!("ID:      {}", w.id);
        println!("Name:    {}", w.name);
        println!("Secured: ✓ (encrypted)");
        for acct in &w.accounts {
            println!("  {} → {}", acct.chain_id, acct.address);
        }
        println!("Created: {}", w.created_at);
        println!();
    }

    Ok(())
}
