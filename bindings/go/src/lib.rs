//! Go FFI bindings for the Open Wallet Standard (OWS)
//!
//! ## ABI Overview
//!
//! This crate exposes a minimal C-compatible FFI surface for Go via cgo.
//! All functions use `#[no_mangle]` and `extern "C"` ABI.
//!
//! ## Memory Ownership Rules
//!
//! - **Input strings**: Borrowed from caller; Rust does not free them.
//! - **Output strings**: Heap-allocated by Rust via CString::into_raw();
//!   ownership is transferred to caller. Caller MUST call
//!   `ows_go_free_string()` to release.
//! - **Error state**: Thread-local cell; overwritten on each FFI call.
//!   Retrieve via `ows_go_get_last_error()` / `ows_go_get_last_error_code()`.

use std::ffi::{CStr, CString};
use std::fmt::Write as FmtWrite;
use std::os::raw::c_char;
use std::path::Path;
use std::ptr;

mod error;
pub use error::OwsGoError;

/// Sentinel value for "no index provided" (uses account index 0).
const INDEX_NONE: u32 = u32::MAX;

// ---------------------------------------------------------------------------
// Thread-local error state
// ---------------------------------------------------------------------------

thread_local! {
    static LAST_ERROR_CODE: std::cell::Cell<i32> = const { std::cell::Cell::new(0) };
    static LAST_ERROR_MSG: std::cell::RefCell<Option<CString>> = const { std::cell::RefCell::new(None) };
}

fn set_error(code: i32, msg: &str) {
    let cmsg = CString::new(msg.to_string()).unwrap_or_else(|_| CString::new("unknown").unwrap());
    LAST_ERROR_MSG.with(|cell| {
        *cell.borrow_mut() = Some(cmsg);
    });
    LAST_ERROR_CODE.with(|cell| {
        cell.set(code);
    });
}

fn clear_error() {
    LAST_ERROR_MSG.with(|cell| {
        *cell.borrow_mut() = None;
    });
    LAST_ERROR_CODE.with(|cell| {
        cell.set(0);
    });
}

// ---------------------------------------------------------------------------
// Memory management
// ---------------------------------------------------------------------------

/// Free a heap-allocated string returned by this library.
///
/// # Safety
/// - `s` must be a pointer returned by a function in this library.
/// - After calling this, do not use the pointer again.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn ows_go_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(s);
    }
}

/// Get the last error message, or NULL if no error.
/// The returned pointer is valid until the next ows_go_* call in this thread.
#[no_mangle]
pub extern "C" fn ows_go_get_last_error() -> *const c_char {
    LAST_ERROR_MSG.with(|cell| match &*cell.borrow() {
        Some(cstr) => cstr.as_ptr(),
        None => ptr::null(),
    })
}

/// Get the error code of the last error (0 = success).
#[no_mangle]
pub extern "C" fn ows_go_get_last_error_code() -> i32 {
    LAST_ERROR_CODE.with(|cell| cell.get())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn opt_path(s: *const c_char) -> Option<&'static Path> {
    if s.is_null() {
        None
    } else {
        Some(Path::new(
            unsafe { CStr::from_ptr(s) }.to_str().unwrap_or(""),
        ))
    }
}

fn opt_str(s: *const c_char) -> Option<&'static str> {
    if s.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(s) }.to_str().unwrap_or(""))
    }
}

/// Serialize WalletInfo to JSON without serde_json.
fn wallet_info_to_json(info: &ows_lib::WalletInfo) -> String {
    let mut json = String::new();
    json.push('{');
    write!(&mut json, r#""id":"{}","#, info.id).unwrap();
    write!(&mut json, r#""name":"{}","#, info.name).unwrap();
    json.push_str(r#""accounts":["#);
    for (i, acct) in info.accounts.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        json.push('{');
        write!(&mut json, r#""chain_id":"{}","#, acct.chain_id).unwrap();
        write!(&mut json, r#""address":"{}","#, acct.address).unwrap();
        write!(&mut json, r#""derivation_path":"{}""#, acct.derivation_path).unwrap();
        json.push('}');
    }
    json.push_str("],");
    write!(&mut json, r#""created_at":"{}""#, info.created_at).unwrap();
    json.push('}');
    json
}

// ---------------------------------------------------------------------------
// Wallet Operations (v1)
// ---------------------------------------------------------------------------

/// Create a new universal wallet.
///
/// # Parameters
/// - `name`: Wallet name (UTF-8)
/// - `passphrase`: Encryption passphrase, or NULL for empty
/// - `words`: BIP-39 word count (12/15/18/21/24); 0 = default (12)
/// - `vault_path`: Vault directory, or NULL for default (~/.ows)
///
/// # Returns
/// JSON WalletInfo on success, NULL on failure.
/// Retrieve error via `ows_go_get_last_error_code()` / `ows_go_get_last_error()`.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn ows_go_create_wallet(
    name: *const c_char,
    passphrase: *const c_char,
    words: u32,
    vault_path: *const c_char,
) -> *mut c_char {
    let name = unsafe { CStr::from_ptr(name) }.to_str().unwrap_or("");
    let vault_path = opt_path(vault_path);

    let result = ows_lib::create_wallet(
        name,
        if words == 0 { None } else { Some(words) },
        opt_str(passphrase),
        vault_path,
    );

    match result {
        Ok(info) => {
            clear_error();
            let json = wallet_info_to_json(&info);
            CString::new(json)
                .unwrap_or_else(|_| CString::new("{}").unwrap())
                .into_raw()
        }
        Err(e) => {
            let msg = e.to_string();
            set_error(OwsGoError::from_error_msg(&msg) as i32, &msg);
            ptr::null_mut()
        }
    }
}

/// List all wallets in the vault.
///
/// # Parameters
/// - `vault_path`: Vault directory, or NULL for default (~/.ows)
///
/// # Returns
/// JSON array of WalletInfo objects on success, NULL on failure.
#[no_mangle]
pub extern "C" fn ows_go_list_wallets(vault_path: *const c_char) -> *mut c_char {
    let vault_path = opt_path(vault_path);

    match ows_lib::list_wallets(vault_path) {
        Ok(wallets) => {
            clear_error();
            let json_list: Vec<String> = wallets.iter().map(wallet_info_to_json).collect();
            let json = format!("[{}]", json_list.join(","));
            CString::new(json)
                .unwrap_or_else(|_| CString::new("[]").unwrap())
                .into_raw()
        }
        Err(e) => {
            let msg = e.to_string();
            set_error(OwsGoError::from_error_msg(&msg) as i32, &msg);
            ptr::null_mut()
        }
    }
}

// ---------------------------------------------------------------------------
// Signing Operations (v1)
// ---------------------------------------------------------------------------

/// Sign a message for a given chain.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn ows_go_sign_message(
    wallet: *const c_char,
    chain: *const c_char,
    message: *const c_char,
    passphrase: *const c_char,
    encoding: *const c_char,
    index: u32,
    vault_path: *const c_char,
) -> *mut c_char {
    let wallet = unsafe { CStr::from_ptr(wallet) }.to_str().unwrap_or("");
    let chain = unsafe { CStr::from_ptr(chain) }.to_str().unwrap_or("");
    let message = unsafe { CStr::from_ptr(message) }.to_str().unwrap_or("");
    let vault_path = opt_path(vault_path);
    let index = if index == INDEX_NONE {
        None
    } else {
        Some(index)
    };

    match ows_lib::sign_message(
        wallet,
        chain,
        message,
        opt_str(passphrase),
        opt_str(encoding),
        index,
        vault_path,
    ) {
        Ok(result) => {
            clear_error();
            let json = format!(
                r#"{{"signature":"{}","recovery_id":{}}}"#,
                result.signature,
                result
                    .recovery_id
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "null".to_string())
            );
            CString::new(json)
                .unwrap_or_else(|_| CString::new("{}").unwrap())
                .into_raw()
        }
        Err(e) => {
            let msg = e.to_string();
            set_error(OwsGoError::from_error_msg(&msg) as i32, &msg);
            ptr::null_mut()
        }
    }
}

/// Sign a raw transaction.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn ows_go_sign_transaction(
    wallet: *const c_char,
    chain: *const c_char,
    tx_hex: *const c_char,
    passphrase: *const c_char,
    index: u32,
    vault_path: *const c_char,
) -> *mut c_char {
    let wallet = unsafe { CStr::from_ptr(wallet) }.to_str().unwrap_or("");
    let chain = unsafe { CStr::from_ptr(chain) }.to_str().unwrap_or("");
    let tx_hex = unsafe { CStr::from_ptr(tx_hex) }.to_str().unwrap_or("");
    let vault_path = opt_path(vault_path);
    let index = if index == INDEX_NONE {
        None
    } else {
        Some(index)
    };

    match ows_lib::sign_transaction(
        wallet,
        chain,
        tx_hex,
        opt_str(passphrase),
        index,
        vault_path,
    ) {
        Ok(result) => {
            clear_error();
            let json = format!(
                r#"{{"signature":"{}","recovery_id":{}}}"#,
                result.signature,
                result
                    .recovery_id
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "null".to_string())
            );
            CString::new(json)
                .unwrap_or_else(|_| CString::new("{}").unwrap())
                .into_raw()
        }
        Err(e) => {
            let msg = e.to_string();
            set_error(OwsGoError::from_error_msg(&msg) as i32, &msg);
            ptr::null_mut()
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_from_msg_wallet_not_found() {
        assert_eq!(
            OwsGoError::from_error_msg("wallet not found: 'foo'"),
            OwsGoError::WalletNotFound
        );
    }

    #[test]
    fn test_error_code_unknown() {
        assert_eq!(
            OwsGoError::from_error_msg("totally unknown error"),
            OwsGoError::Unknown
        );
    }

    #[test]
    fn test_clear_and_set_error() {
        clear_error();
        assert_eq!(ows_go_get_last_error_code(), 0);
        assert!(ows_go_get_last_error().is_null());

        set_error(42, "test error");
        assert_eq!(ows_go_get_last_error_code(), 42);
        let err_ptr = ows_go_get_last_error();
        assert!(!err_ptr.is_null());
        let err_str = unsafe { CStr::from_ptr(err_ptr) }.to_str().unwrap();
        assert_eq!(err_str, "test error");

        set_error(1, "another error");
        assert_eq!(ows_go_get_last_error_code(), 1);
    }

    #[test]
    fn test_index_none_constant() {
        assert_eq!(INDEX_NONE, u32::MAX);
    }
}
