mod commands;
mod vault;

use clap::{Parser, Subcommand};
use lws_core::{ChainType, LwsError};
use lws_signer::hd::HdError;
use lws_signer::mnemonic::MnemonicError;
use lws_signer::SignerError;

/// Lightweight Wallet Signer CLI
#[derive(Parser)]
#[command(name = "lws", version, about, long_version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("LWS_GIT_COMMIT"), ")"))]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new BIP-39 mnemonic phrase
    Generate {
        /// Number of words (12 or 24)
        #[arg(long, default_value = "12")]
        words: u32,
    },
    /// Derive an address from a mnemonic (reads from LWS_MNEMONIC env or stdin)
    Derive {
        /// Chain type (evm, solana, bitcoin, cosmos, tron)
        #[arg(long)]
        chain: String,
        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
    },
    /// Sign a message with a mnemonic-derived key (reads from LWS_MNEMONIC env or stdin)
    Sign {
        /// Chain type (evm, solana, bitcoin, cosmos, tron)
        #[arg(long)]
        chain: String,
        /// Message to sign
        #[arg(long)]
        message: String,
        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
    },
    /// Show vault path and supported chains
    Info,
    /// Create a new wallet (generates mnemonic, saves descriptor)
    CreateWallet {
        /// Wallet name
        #[arg(long)]
        name: String,
        /// Chain type (evm, solana, bitcoin, cosmos, tron)
        #[arg(long)]
        chain: String,
        /// Number of words (12 or 24)
        #[arg(long, default_value = "12")]
        words: u32,
    },
    /// List all saved wallets
    ListWallets,
    /// Update lws to the latest version
    Update {
        /// Force rebuild even if already on the latest commit
        #[arg(long)]
        force: bool,
    },
    /// Uninstall lws from the system
    Uninstall {
        /// Also remove all wallet data and config (~/.lws)
        #[arg(long)]
        purge: bool,
    },
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}")]
    Lws(#[from] LwsError),
    #[error("{0}")]
    Mnemonic(#[from] MnemonicError),
    #[error("{0}")]
    Hd(#[from] HdError),
    #[error("{0}")]
    Signer(#[from] SignerError),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    InvalidArgs(String),
}

fn parse_chain(s: &str) -> Result<ChainType, CliError> {
    s.parse::<ChainType>()
        .map_err(|e| CliError::InvalidArgs(e))
}

fn main() {
    lws_signer::process_hardening::harden_process();

    // Eagerly initialize the global key cache and register it for zeroization
    // on termination signals (SIGTERM, SIGINT, SIGHUP).
    let cache = lws_signer::global_key_cache();
    lws_signer::process_hardening::register_cleanup(move || cache.clear());
    lws_signer::process_hardening::install_signal_handlers();

    let cli = Cli::parse();
    let code = match run(cli) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    };

    // Explicitly zeroize all cached key material before exiting.
    lws_signer::global_key_cache().clear();
    std::process::exit(code);
}

fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Commands::Generate { words } => commands::generate::run(words),
        Commands::Derive { chain, index } => commands::derive::run(&chain, index),
        Commands::Sign {
            chain,
            message,
            index,
        } => commands::sign::run(&chain, &message, index),
        Commands::Info => commands::info::run(),
        Commands::CreateWallet {
            name,
            chain,
            words,
        } => commands::wallet::create(&name, &chain, words),
        Commands::ListWallets => commands::wallet::list(),
        Commands::Update { force } => commands::update::run(force),
        Commands::Uninstall { purge } => commands::uninstall::run(purge),
    }
}
