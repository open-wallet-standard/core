use stellar_xdr::curr::{Limits, ReadXdr, TransactionResult, TransactionResultCode};

/// Enrich a Stellar transaction-level result code with a human-readable explanation.
pub fn enrich_tx_error<'a>(code: &'a str) -> &'a str {
    match code {
        "tx_failed" => "One of the operations failed (none applied). Check per-operation errors.",
        "tx_too_early" => "Transaction submitted too early (before minTime). Wait or set minTime to 0.",
        "tx_too_late" => "Transaction expired (after maxTime). Rebuild with a longer timeout.",
        "tx_bad_seq" => "Wrong sequence number. Re-fetch the account sequence and rebuild.",
        "tx_bad_auth" => "Invalid signature(s) or wrong network passphrase. Re-sign with the correct key.",
        "tx_insufficient_balance" => "Fee would drop the account below the XLM reserve. Add more XLM.",
        "tx_no_source_account" => "Source account does not exist. Fund it with CreateAccount (min 1 XLM).",
        "tx_insufficient_fee" => "Fee too low. Increase the fee (min 100 stroops/op, more during congestion).",
        "tx_bad_auth_extra" => "Extra unused signatures attached. Remove signatures not matching any signer.",
        "tx_internal_error" => "Unknown Stellar Core error. Retry; if persistent, the network may have issues.",
        "tx_not_supported" => "Transaction type not supported at this protocol version.",
        "tx_fee_bump_inner_failed" => "Fee bump failed because the inner transaction failed. Check inner results.",
        "tx_bad_sponsorship" => "Sponsorship not confirmed. Pair BeginSponsoring with EndSponsoring.",
        "tx_malformed" => "Transaction preconditions are malformed. Validate timebounds, ledger bounds, etc.",
        "tx_soroban_invalid" => "Soroban preconditions not met. Run simulateTransaction first to set resources.",
        _ => code,
    }
}

/// Enrich a Stellar operation-level result code with a human-readable explanation.
pub fn enrich_op_error<'a>(code: &'a str) -> &'a str {
    match code {
        // Generic
        "op_bad_auth" => "Operation needs more signatures or was signed for wrong network.",
        "op_no_source_account" => "The operation's source account does not exist on the ledger.",
        "op_too_many_subentries" => "Account has 1000 subentries (max). Remove trustlines/offers/data first.",
        // Payment
        "op_underfunded" => "Not enough funds (after reserves). Add more or reduce amount.",
        "op_src_no_trust" => "Sender has no trustline for this asset. Add one with ChangeTrust first.",
        "op_no_destination" => "Destination account does not exist. Create it first with CreateAccount.",
        "op_no_trust" => "Receiver has no trustline for this asset. They must add one first.",
        "op_not_authorized" => "Receiver is not authorized to hold this asset. Issuer must authorize.",
        "op_line_full" => "Receiver's trustline limit would be exceeded. They must raise the limit.",
        "op_no_issuer" => "The asset issuer does not exist. Check asset code and issuer address.",
        // CreateAccount
        "op_already_exists" => "Destination account already exists. Use Payment instead of CreateAccount.",
        "op_low_reserve" => "Starting balance is below the minimum reserve (1 XLM). Increase it.",
        // ChangeTrust
        "op_invalid_limit" => "Trustline limit too low for current balance + buying liabilities.",
        "op_self_not_allowed" => "Cannot create a trustline to yourself.",
        // Catch-all
        "op_malformed" => "Operation input is malformed. Check addresses, amounts, and asset codes.",
        _ => code,
    }
}

/// Map a `TransactionResultCode` enum to its canonical string name.
fn tx_result_code_to_str(code: &TransactionResultCode) -> &'static str {
    match code {
        TransactionResultCode::TxFeeBumpInnerSuccess => "tx_fee_bump_inner_success",
        TransactionResultCode::TxSuccess => "tx_success",
        TransactionResultCode::TxFailed => "tx_failed",
        TransactionResultCode::TxTooEarly => "tx_too_early",
        TransactionResultCode::TxTooLate => "tx_too_late",
        TransactionResultCode::TxMissingOperation => "tx_missing_operation",
        TransactionResultCode::TxBadSeq => "tx_bad_seq",
        TransactionResultCode::TxBadAuth => "tx_bad_auth",
        TransactionResultCode::TxInsufficientBalance => "tx_insufficient_balance",
        TransactionResultCode::TxNoAccount => "tx_no_source_account",
        TransactionResultCode::TxInsufficientFee => "tx_insufficient_fee",
        TransactionResultCode::TxBadAuthExtra => "tx_bad_auth_extra",
        TransactionResultCode::TxInternalError => "tx_internal_error",
        TransactionResultCode::TxNotSupported => "tx_not_supported",
        TransactionResultCode::TxFeeBumpInnerFailed => "tx_fee_bump_inner_failed",
        TransactionResultCode::TxBadSponsorship => "tx_bad_sponsorship",
        TransactionResultCode::TxBadMinSeqAgeOrGap => "tx_malformed",
        TransactionResultCode::TxMalformed => "tx_malformed",
        TransactionResultCode::TxSorobanInvalid => "tx_soroban_invalid",
        _ => "tx_unknown",
    }
}

/// Decode a base64-encoded `errorResultXdr` and return an enriched error string.
/// Falls back to the raw XDR string if decoding fails.
pub fn enrich_error_xdr(error_xdr: &str) -> String {
    use base64::Engine;

    let bytes = match base64::engine::general_purpose::STANDARD.decode(error_xdr) {
        Ok(b) => b,
        Err(_) => return format!("{error_xdr} (decode at lab.stellar.org/xdr/view)"),
    };

    let tx_result = match TransactionResult::from_xdr(&bytes, Limits::none()) {
        Ok(r) => r,
        Err(_) => return format!("{error_xdr} (decode at lab.stellar.org/xdr/view)"),
    };

    let code_str = tx_result_code_to_str(&tx_result.result.discriminant());
    let enriched = enrich_tx_error(code_str);
    format!("{code_str}: {enriched}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enrich_tx_error_known_codes() {
        assert_eq!(
            enrich_tx_error("tx_bad_seq"),
            "Wrong sequence number. Re-fetch the account sequence and rebuild."
        );
        assert_eq!(
            enrich_tx_error("tx_no_source_account"),
            "Source account does not exist. Fund it with CreateAccount (min 1 XLM)."
        );
        assert_eq!(
            enrich_tx_error("tx_too_late"),
            "Transaction expired (after maxTime). Rebuild with a longer timeout."
        );
        assert_eq!(
            enrich_tx_error("tx_insufficient_fee"),
            "Fee too low. Increase the fee (min 100 stroops/op, more during congestion)."
        );
    }

    #[test]
    fn test_enrich_tx_error_unknown_passthrough() {
        assert_eq!(enrich_tx_error("tx_some_future_code"), "tx_some_future_code");
        assert_eq!(enrich_tx_error(""), "");
    }

    #[test]
    fn test_enrich_op_error_known_codes() {
        assert_eq!(
            enrich_op_error("op_no_trust"),
            "Receiver has no trustline for this asset. They must add one first."
        );
        assert_eq!(
            enrich_op_error("op_no_destination"),
            "Destination account does not exist. Create it first with CreateAccount."
        );
        assert_eq!(
            enrich_op_error("op_low_reserve"),
            "Starting balance is below the minimum reserve (1 XLM). Increase it."
        );
    }

    #[test]
    fn test_enrich_op_error_unknown_passthrough() {
        assert_eq!(enrich_op_error("op_future_code"), "op_future_code");
    }

    #[test]
    fn test_enrich_error_xdr_invalid_base64_fallback() {
        let result = enrich_error_xdr("not-valid-base64!!!");
        assert!(result.contains("not-valid-base64!!!"));
        assert!(result.contains("lab.stellar.org"));
    }

    #[test]
    fn test_enrich_error_xdr_invalid_xdr_fallback() {
        use base64::Engine;
        // Valid base64 but not valid TransactionResult XDR
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"not xdr");
        let result = enrich_error_xdr(&b64);
        assert!(result.contains("lab.stellar.org"));
    }

    #[test]
    fn test_enrich_error_xdr_valid_tx_bad_seq() {
        // Build a minimal TransactionResult with TxBadSeq
        use stellar_xdr::curr::{
            TransactionResult, TransactionResultExt, TransactionResultResult, WriteXdr,
        };

        let tx_result = TransactionResult {
            fee_charged: 100,
            result: TransactionResultResult::TxBadSeq,
            ext: TransactionResultExt::V0,
        };
        let xdr_bytes = tx_result.to_xdr(Limits::none()).unwrap();

        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&xdr_bytes);

        let enriched = enrich_error_xdr(&b64);
        assert!(
            enriched.contains("tx_bad_seq"),
            "should contain error code, got: {enriched}"
        );
        assert!(
            enriched.contains("sequence number"),
            "should contain enriched explanation, got: {enriched}"
        );
    }

    #[test]
    fn test_enrich_error_xdr_valid_tx_no_account() {
        use stellar_xdr::curr::{
            TransactionResult, TransactionResultExt, TransactionResultResult, WriteXdr,
        };

        let tx_result = TransactionResult {
            fee_charged: 100,
            result: TransactionResultResult::TxNoAccount,
            ext: TransactionResultExt::V0,
        };
        let xdr_bytes = tx_result.to_xdr(Limits::none()).unwrap();

        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&xdr_bytes);

        let enriched = enrich_error_xdr(&b64);
        assert!(enriched.contains("tx_no_source_account"));
        assert!(enriched.contains("Fund it with CreateAccount"));
    }
}
