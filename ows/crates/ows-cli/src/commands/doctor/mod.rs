//! `ows doctor` — Diagnostic command for OWS installation health.
//!
//! This module provides a read-only diagnostic system that checks:
//! - Vault path resolution
//! - Vault and subdirectory existence
//! - Config file validity
//! - File permissions (Unix)
//! - Wallet, key, and policy file integrity
//! - Environment configuration
//!
//! All checks are read-only and do not modify any files.
//!
//! # Architecture
//!
//! - [`report`] — Domain types: `DoctorStatus`, `DoctorFinding`, `DoctorReport`
//! - [`checks`] — Individual check implementations
//! - [`vault_inspector`] — Read-only vault artifact inspection (wallets/keys/policies)
//!
//! # Stability
//!
//! The check IDs, status enums, and report structure are considered stable
//! and will not change in a breaking way. Output formatting is separate
//! and can evolve independently.

pub mod checks;
pub mod report;
pub mod vault_inspector;

// Re-exports for CLI and tests.
#[allow(unused)]
pub use report::{DoctorCheckId, DoctorFinding, DoctorReport, DoctorStatus, DoctorSummary};

use crate::CliError;

/// Run the `ows doctor` diagnostic command.
///
/// Executes all checks, formats the report as human-readable output,
/// and returns the appropriate exit code via `Err` when errors are found.
pub fn run() -> Result<(), CliError> {
    let report = checks::run_all_checks();
    print_report(&report);

    if report.has_errors() {
        Err(CliError::InvalidArgs("diagnostic checks failed".into()))
    } else {
        Ok(())
    }
}

/// Print a human-readable diagnostic report to stdout.
fn print_report(report: &DoctorReport) {
    use ows_core::Config;

    println!();
    println!("{}", "=".repeat(60));
    println!("  OWS Doctor");
    println!("{}", "=".repeat(60));
    println!();

    // Vault path
    let config = Config::default();
    println!("  Vault path: {}", config.vault_path.display());
    println!();

    // Group findings by status
    let errors: Vec<_> = report.findings_with_status(DoctorStatus::Error);
    let warnings: Vec<_> = report.findings_with_status(DoctorStatus::Warning);
    let skipped: Vec<_> = report.findings_with_status(DoctorStatus::Skipped);
    let ok: Vec<_> = report.findings_with_status(DoctorStatus::Ok);

    // Print errors first
    if !errors.is_empty() {
        println!("  Errors:");
        println!("  {}", "-".repeat(40));
        for f in &errors {
            print_finding(f);
        }
        println!();
    }

    // Then warnings
    if !warnings.is_empty() {
        println!("  Warnings:");
        println!("  {}", "-".repeat(40));
        for f in &warnings {
            print_finding(f);
        }
        println!();
    }

    // Then skipped (informational)
    if !skipped.is_empty() {
        println!("  Skipped:");
        println!("  {}", "-".repeat(40));
        for f in &skipped {
            print_finding(f);
        }
        println!();
    }

    // Then ok findings (brief, condensed)
    if !ok.is_empty() {
        println!("  Passed:");
        println!("  {}", "-".repeat(40));
        for f in &ok {
            println!("    {} {}", status_icon(DoctorStatus::Ok), f.title);
        }
        println!();
    }

    // Summary
    println!("{}", "=".repeat(60));
    println!(
        "  {} passed   {} warnings   {} errors   {} skipped",
        report.summary.ok, report.summary.warnings, report.summary.errors, report.summary.skipped
    );
    println!();

    if report.has_errors() {
        println!("  Result: FAILED — errors found");
    } else if report.has_warnings() {
        println!(
            "  Result: OK — {} warning(s) found",
            report.summary.warnings
        );
    } else if report.summary.ok == 0 && report.summary.skipped > 0 {
        println!("  Result: SKIPPED — no checks could run");
    } else {
        println!("  Result: OK — all checks passed");
    }
    println!();
}

fn print_finding(f: &DoctorFinding) {
    println!("    {} {}: {}", status_icon(f.status), f.title, f.detail);
    if let Some(ref suggestion) = f.suggestion {
        println!("         → {}", suggestion);
    }
}

fn status_icon(status: DoctorStatus) -> &'static str {
    match status {
        DoctorStatus::Ok => "✓",
        DoctorStatus::Warning => "⚠",
        DoctorStatus::Error => "✗",
        DoctorStatus::Skipped => "○",
    }
}
