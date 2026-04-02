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

// Re-exports for the CLI command (Phase 3).
#[allow(unused)]
pub use report::{DoctorCheckId, DoctorFinding, DoctorReport, DoctorStatus, DoctorSummary};
