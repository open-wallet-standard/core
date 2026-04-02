//! `ows doctor` — Diagnostic command for OWS installation health.
//!
//! This module provides a read-only diagnostic system that checks:
//! - Vault path resolution
//! - Vault and subdirectory existence
//! - Config file validity
//! - File permissions (Unix)
//! - Environment configuration
//!
//! All checks are read-only and do not modify any files.
//!
//! # Architecture
//!
//! - [`report`] — Domain types: `DoctorStatus`, `DoctorFinding`, `DoctorReport`
//! - [`checks`] — Individual check implementations
//! - [`run_all_checks()`] — Aggregates all findings into a report
//!
//! # Stability
//!
//! The check IDs, status enums, and report structure are considered stable
//! and will not change in a breaking way. Output formatting is separate
//! and can evolve independently.

pub mod checks;
pub mod report;

// Re-exported for use by the CLI command (Phase 3) and integration tests.
#[allow(unused)]
pub use report::{DoctorCheckId, DoctorFinding, DoctorReport, DoctorStatus, DoctorSummary};
pub use checks::run_all_checks;

/// Aggregated diagnostic report — the output of [`run_all_checks()`].
pub type DoctorResult = DoctorReport;
