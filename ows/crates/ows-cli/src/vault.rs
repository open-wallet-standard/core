use ows_core::EncryptedWallet;

use crate::CliError;

// Delegate vault operations to ows-lib, using the default vault path.

pub fn load_wallet_by_name_or_id(name_or_id: &str) -> Result<EncryptedWallet, CliError> {
    Ok(ows_lib::vault::load_wallet_by_name_or_id(name_or_id, None)?)
}
