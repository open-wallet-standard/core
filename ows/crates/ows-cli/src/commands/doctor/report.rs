//! Diagnostic report types for `ows doctor`.

use std::fmt;

// ---------------------------------------------------------------------------
// Stable finding codes
// ---------------------------------------------------------------------------

// Taxonomy: every actionable finding carries a stable code. Ok findings
// (purely informational, no action needed) do not use codes.
//
// Prefix map:
//   OWS_DOCTOR_ENV_*        — environment / path resolution
//   OWS_DOCTOR_VAULT_*      — vault-level structural checks
//   OWS_DOCTOR_CONFIG_*     — config file parsing
//   OWS_DOCTOR_PERM_*       — Unix file permissions
//   OWS_DOCTOR_WALLET_*     — wallet file validation
//   OWS_DOCTOR_POLICY_*     — policy file validation
//   OWS_DOCTOR_KEY_*        — API key file validation

/// HOME environment variable is not set.
pub const OWS_DOCTOR_ENV_HOME_NOT_SET: &str = "OWS_DOCTOR_ENV_HOME_NOT_SET";
/// Vault directory does not exist.
pub const OWS_DOCTOR_VAULT_MISSING: &str = "OWS_DOCTOR_VAULT_MISSING";
/// Vault logs subdirectory is absent.
pub const OWS_DOCTOR_LOGS_DIR_MISSING: &str = "OWS_DOCTOR_LOGS_DIR_MISSING";
/// Config file is absent; built-in defaults are in use.
pub const OWS_DOCTOR_CONFIG_MISSING: &str = "OWS_DOCTOR_CONFIG_MISSING";
/// Config file is present but malformed (invalid JSON or schema).
pub const OWS_DOCTOR_CONFIG_INVALID: &str = "OWS_DOCTOR_CONFIG_INVALID";
/// A vault subdirectory cannot be read due to permissions or I/O errors.
pub const OWS_DOCTOR_DIR_UNREADABLE: &str = "OWS_DOCTOR_DIR_UNREADABLE";
/// Vault directory permissions are insecure (Unix).
#[allow(dead_code)]
pub const OWS_DOCTOR_PERM_VAULT_INSECURE: &str = "OWS_DOCTOR_PERM_VAULT_INSECURE";
/// wallets/ directory permissions are insecure (Unix).
#[allow(dead_code)]
pub const OWS_DOCTOR_PERM_WALLETS_INSECURE: &str = "OWS_DOCTOR_PERM_WALLETS_INSECURE";
/// A wallet file has permissions insecure for a secret file (Unix).
#[allow(dead_code)]
pub const OWS_DOCTOR_PERM_WALLET_FILE_INSECURE: &str = "OWS_DOCTOR_PERM_WALLET_FILE_INSECURE";
/// No wallet files present in the vault.
pub const OWS_DOCTOR_WALLET_NONE: &str = "OWS_DOCTOR_WALLET_NONE";
/// A wallet file cannot be read.
pub const OWS_DOCTOR_WALLET_FILE_UNREADABLE: &str = "OWS_DOCTOR_WALLET_FILE_UNREADABLE";
/// A wallet file is not valid JSON.
pub const OWS_DOCTOR_WALLET_FILE_INVALID: &str = "OWS_DOCTOR_WALLET_FILE_INVALID";
/// A wallet file has invalid or missing metadata (empty ID, empty/invalid created_at).
pub const OWS_DOCTOR_WALLET_METADATA_CORRUPT: &str = "OWS_DOCTOR_WALLET_METADATA_CORRUPT";
/// Some wallet files are corrupted while others are valid.
pub const OWS_DOCTOR_WALLET_SOME_CORRUPT: &str = "OWS_DOCTOR_WALLET_SOME_CORRUPT";
/// No policy files present.
pub const OWS_DOCTOR_POLICY_NONE: &str = "OWS_DOCTOR_POLICY_NONE";
/// A policy file cannot be read.
pub const OWS_DOCTOR_POLICY_FILE_UNREADABLE: &str = "OWS_DOCTOR_POLICY_FILE_UNREADABLE";
/// A policy file is not valid JSON.
pub const OWS_DOCTOR_POLICY_FILE_INVALID: &str = "OWS_DOCTOR_POLICY_FILE_INVALID";
/// Some policy files are corrupted while others are valid.
pub const OWS_DOCTOR_POLICY_SOME_CORRUPT: &str = "OWS_DOCTOR_POLICY_SOME_CORRUPT";
/// No API key files present.
pub const OWS_DOCTOR_KEY_NONE: &str = "OWS_DOCTOR_KEY_NONE";
/// An API key file cannot be read.
pub const OWS_DOCTOR_KEY_FILE_UNREADABLE: &str = "OWS_DOCTOR_KEY_FILE_UNREADABLE";
/// An API key file is not valid JSON.
pub const OWS_DOCTOR_KEY_FILE_INVALID: &str = "OWS_DOCTOR_KEY_FILE_INVALID";
/// Some API key files are corrupted while others are valid.
pub const OWS_DOCTOR_KEY_SOME_CORRUPT: &str = "OWS_DOCTOR_KEY_SOME_CORRUPT";

// ---------------------------------------------------------------------------
// Check IDs
// ---------------------------------------------------------------------------

/// Unique identifier for a diagnostic check.
///
/// Check IDs are stable, dotted identifiers used to group findings
/// and as a stable anchor for structured output (future JSON mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DoctorCheckId(&'static str);

impl DoctorCheckId {
    pub const fn new(code: &'static str) -> Self {
        DoctorCheckId(code)
    }

    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

impl fmt::Display for DoctorCheckId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Status
// --------------------------------------------------------------------------

/// Status of a single diagnostic check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DoctorStatus {
    /// Check succeeded with no issues.
    Ok,
    /// Check passed but a minor concern was detected.
    Warning,
    /// Check failed; a problem requires attention.
    Error,
    /// Check was skipped because it does not apply on this platform
    /// or because the prerequisite state is absent.
    Skipped,
}

// ---------------------------------------------------------------------------
// Finding
// --------------------------------------------------------------------------

/// A single diagnostic finding from one check.
#[derive(Debug, Clone)]
pub struct DoctorFinding {
    /// Unique identifier for the check that produced this finding.
    pub id: DoctorCheckId,
    /// Status of the check.
    pub status: DoctorStatus,
    /// Short title for the finding (suitable for display).
    pub title: String,
    /// Detailed explanation of the finding.
    pub detail: String,
    /// Actionable suggestion for remediation, if applicable.
    pub suggestion: Option<String>,
    /// Path to the file or directory involved, if applicable.
    pub path: Option<std::path::PathBuf>,
    /// Stable code for machine processing. Always present for Error,
    /// Warning, and Skipped findings. Absent for informational Ok findings.
    pub code: Option<&'static str>,
}

impl DoctorFinding {
    /// Create an informational Ok finding (no code needed).
    pub fn ok(id: DoctorCheckId, title: &str, detail: &str) -> Self {
        DoctorFinding {
            id,
            status: DoctorStatus::Ok,
            title: title.to_string(),
            detail: detail.to_string(),
            suggestion: None,
            path: None,
            code: None,
        }
    }

    /// Create a Skipped finding with a stable code.
    pub fn skipped(id: DoctorCheckId, code: &'static str, title: &str, detail: &str) -> Self {
        DoctorFinding {
            id,
            status: DoctorStatus::Skipped,
            title: title.to_string(),
            detail: detail.to_string(),
            suggestion: None,
            path: None,
            code: Some(code),
        }
    }

    /// Create a Warning finding with a stable code.
    pub fn warning(
        id: DoctorCheckId,
        code: &'static str,
        title: &str,
        detail: &str,
        suggestion: &str,
    ) -> Self {
        DoctorFinding {
            id,
            status: DoctorStatus::Warning,
            title: title.to_string(),
            detail: detail.to_string(),
            suggestion: Some(suggestion.to_string()),
            path: None,
            code: Some(code),
        }
    }

    /// Create an Error finding with a stable code.
    pub fn error(
        id: DoctorCheckId,
        code: &'static str,
        title: &str,
        detail: &str,
        suggestion: &str,
    ) -> Self {
        DoctorFinding {
            id,
            status: DoctorStatus::Error,
            title: title.to_string(),
            detail: detail.to_string(),
            suggestion: Some(suggestion.to_string()),
            path: None,
            code: Some(code),
        }
    }

    /// Builder-style method to attach a path to the finding.
    pub fn with_path(mut self, path: std::path::PathBuf) -> Self {
        self.path = Some(path);
        self
    }
}

/// Summary counts across all findings.
#[derive(Debug, Clone, Default)]
pub struct DoctorSummary {
    pub ok: usize,
    pub warnings: usize,
    pub errors: usize,
    pub skipped: usize,
}

impl DoctorSummary {
    pub fn total(&self) -> usize {
        self.ok + self.warnings + self.errors + self.skipped
    }

    pub fn has_failures(&self) -> bool {
        self.errors > 0
    }
}

/// Aggregated diagnostic report from all checks.
#[derive(Debug, Clone)]
pub struct DoctorReport {
    /// The most severe status across all findings.
    pub overall_status: DoctorStatus,
    /// All individual findings in the order they were produced.
    pub findings: Vec<DoctorFinding>,
    /// Summary counts.
    pub summary: DoctorSummary,
}

impl DoctorReport {
    /// Create a new report from a list of findings.
    ///
    /// Findings are preserved in order. Overall status is derived as:
    /// - `Error` if any error exists
    /// - `Warning` if any warning exists (and no errors)
    /// - `Ok` if only ok/skipped findings
    /// - `Skipped` if only skipped findings
    pub fn new(findings: Vec<DoctorFinding>) -> Self {
        let summary = DoctorSummary {
            ok: findings
                .iter()
                .filter(|f| f.status == DoctorStatus::Ok)
                .count(),
            warnings: findings
                .iter()
                .filter(|f| f.status == DoctorStatus::Warning)
                .count(),
            errors: findings
                .iter()
                .filter(|f| f.status == DoctorStatus::Error)
                .count(),
            skipped: findings
                .iter()
                .filter(|f| f.status == DoctorStatus::Skipped)
                .count(),
        };

        let overall_status = if summary.errors > 0 {
            DoctorStatus::Error
        } else if summary.warnings > 0 {
            DoctorStatus::Warning
        } else if summary.ok == 0 && summary.skipped > 0 {
            DoctorStatus::Skipped
        } else {
            DoctorStatus::Ok
        };

        DoctorReport {
            overall_status,
            findings,
            summary,
        }
    }

    /// Return true if the report indicates any errors.
    pub fn has_errors(&self) -> bool {
        self.summary.errors > 0
    }

    /// Return true if the report indicates any warnings.
    pub fn has_warnings(&self) -> bool {
        self.summary.warnings > 0
    }

    /// Return the appropriate exit code for this report.
    pub fn exit_code(&self) -> i32 {
        if self.has_errors() {
            1
        } else {
            0
        }
    }

    /// Return findings filtered by a given status.
    pub fn findings_with_status(&self, status: DoctorStatus) -> Vec<&DoctorFinding> {
        self.findings
            .iter()
            .filter(|f| f.status == status)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: DoctorCheckId = DoctorCheckId::new("test.check");

    #[test]
    fn test_summary_counts() {
        let findings = vec![
            DoctorFinding::ok(ID, "Good", "All good"),
            DoctorFinding::skipped(ID, OWS_DOCTOR_VAULT_MISSING, "Skipped", "Not applicable"),
            DoctorFinding::warning(ID, OWS_DOCTOR_WALLET_NONE, "Warn", "Minor issue", "Fix it"),
        ];
        let report = DoctorReport::new(findings);
        assert_eq!(report.summary.ok, 1);
        assert_eq!(report.summary.warnings, 1);
        assert_eq!(report.summary.errors, 0);
        assert_eq!(report.summary.skipped, 1);
        assert_eq!(report.summary.total(), 3);
    }

    #[test]
    fn test_overall_status_error_wins() {
        let findings = vec![
            DoctorFinding::ok(ID, "Good", "All good"),
            DoctorFinding::error(ID, OWS_DOCTOR_VAULT_MISSING, "Bad", "Critical", "Fix it"),
            DoctorFinding::warning(ID, OWS_DOCTOR_WALLET_NONE, "Warn", "Minor", "Fix it"),
        ];
        let report = DoctorReport::new(findings);
        assert_eq!(report.overall_status, DoctorStatus::Error);
        assert!(report.has_errors());
        assert!(report.has_warnings());
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn test_overall_status_warning_without_error() {
        let findings = vec![
            DoctorFinding::ok(ID, "Good", "All good"),
            DoctorFinding::warning(ID, OWS_DOCTOR_WALLET_NONE, "Warn", "Minor", "Fix it"),
        ];
        let report = DoctorReport::new(findings);
        assert_eq!(report.overall_status, DoctorStatus::Warning);
        assert!(!report.has_errors());
        assert!(report.has_warnings());
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn test_overall_status_all_skipped() {
        let findings = vec![
            DoctorFinding::skipped(ID, OWS_DOCTOR_VAULT_MISSING, "Skipped", "Not applicable"),
            DoctorFinding::skipped(
                ID,
                OWS_DOCTOR_CONFIG_MISSING,
                "Skipped 2",
                "Also not applicable",
            ),
        ];
        let report = DoctorReport::new(findings);
        assert_eq!(report.overall_status, DoctorStatus::Skipped);
        assert!(!report.has_errors());
        assert!(!report.has_warnings());
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn test_overall_status_mixed_but_passing() {
        let findings = vec![
            DoctorFinding::ok(ID, "Good", "All good"),
            DoctorFinding::skipped(ID, OWS_DOCTOR_CONFIG_MISSING, "Skipped", "Not applicable"),
        ];
        let report = DoctorReport::new(findings);
        assert_eq!(report.overall_status, DoctorStatus::Ok);
        assert!(!report.has_errors());
        assert!(!report.has_warnings());
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn test_findings_with_status() {
        let findings = vec![
            DoctorFinding::ok(ID, "Good", "All good"),
            DoctorFinding::warning(ID, OWS_DOCTOR_WALLET_NONE, "Warn", "Minor", "Fix it"),
            DoctorFinding::error(ID, OWS_DOCTOR_VAULT_MISSING, "Bad", "Critical", "Fix it"),
            DoctorFinding::skipped(ID, OWS_DOCTOR_CONFIG_MISSING, "Skipped", "Not applicable"),
        ];
        let report = DoctorReport::new(findings);
        assert_eq!(report.findings_with_status(DoctorStatus::Ok).len(), 1);
        assert_eq!(report.findings_with_status(DoctorStatus::Warning).len(), 1);
        assert_eq!(report.findings_with_status(DoctorStatus::Error).len(), 1);
        assert_eq!(report.findings_with_status(DoctorStatus::Skipped).len(), 1);
    }

    #[test]
    fn test_finding_builder_with_path() {
        let finding = DoctorFinding::ok(ID, "Title", "Detail")
            .with_path(std::path::PathBuf::from("/test/path"));
        assert!(finding.path.is_some());
        assert_eq!(
            finding.path.unwrap(),
            std::path::PathBuf::from("/test/path")
        );
    }

    #[test]
    fn test_skipped_has_code() {
        let finding =
            DoctorFinding::skipped(ID, OWS_DOCTOR_VAULT_MISSING, "Skipped", "Vault absent");
        assert_eq!(finding.code, Some(OWS_DOCTOR_VAULT_MISSING));
        assert_eq!(finding.status, DoctorStatus::Skipped);
    }

    #[test]
    fn test_error_has_code() {
        let finding =
            DoctorFinding::error(ID, OWS_DOCTOR_VAULT_MISSING, "Title", "Detail", "Fix it");
        assert_eq!(finding.code, Some(OWS_DOCTOR_VAULT_MISSING));
        assert_eq!(finding.status, DoctorStatus::Error);
    }

    #[test]
    fn test_doctor_check_id_display() {
        let id = DoctorCheckId::new("vault.exists");
        assert_eq!(id.to_string(), "vault.exists");
        assert_eq!(id.as_str(), "vault.exists");
    }
}
