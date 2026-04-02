//! Diagnostic report types for `ows doctor`.

use std::fmt;

/// Unique identifier for a diagnostic check.
///
/// Codes are stable, human-readable identifiers used for:
/// - Structured output (future JSON mode)
/// - Test identification
/// - Cross-referencing findings
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
    /// Check was skipped because it does not apply (e.g., no wallets exist).
    Skipped,
}

impl DoctorStatus {
    pub fn is_passing(&self) -> bool {
        matches!(self, DoctorStatus::Ok | DoctorStatus::Skipped)
    }
}

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
    /// Stable error code for machine processing (future JSON output).
    pub code: Option<&'static str>,
}

impl DoctorFinding {
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

    pub fn skipped(id: DoctorCheckId, title: &str, detail: &str) -> Self {
        DoctorFinding {
            id,
            status: DoctorStatus::Skipped,
            title: title.to_string(),
            detail: detail.to_string(),
            suggestion: None,
            path: None,
            code: None,
        }
    }

    pub fn warning(id: DoctorCheckId, title: &str, detail: &str, suggestion: &str) -> Self {
        DoctorFinding {
            id,
            status: DoctorStatus::Warning,
            title: title.to_string(),
            detail: detail.to_string(),
            suggestion: Some(suggestion.to_string()),
            path: None,
            code: None,
        }
    }

    pub fn error(id: DoctorCheckId, title: &str, detail: &str, suggestion: &str) -> Self {
        DoctorFinding {
            id,
            status: DoctorStatus::Error,
            title: title.to_string(),
            detail: detail.to_string(),
            suggestion: Some(suggestion.to_string()),
            path: None,
            code: None,
        }
    }

    /// Builder-style method to attach a path to the finding.
    pub fn with_path(mut self, path: std::path::PathBuf) -> Self {
        self.path = Some(path);
        self
    }

    /// Builder-style method to attach an error code to the finding.
    pub fn with_code(mut self, code: &'static str) -> Self {
        self.code = Some(code);
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
            ok: findings.iter().filter(|f| f.status == DoctorStatus::Ok).count(),
            warnings: findings.iter().filter(|f| f.status == DoctorStatus::Warning).count(),
            errors: findings.iter().filter(|f| f.status == DoctorStatus::Error).count(),
            skipped: findings.iter().filter(|f| f.status == DoctorStatus::Skipped).count(),
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
        self.findings.iter().filter(|f| f.status == status).collect()
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
            DoctorFinding::skipped(ID, "Skipped", "Not applicable"),
            DoctorFinding::warning(ID, "Warn", "Minor issue", "Fix it"),
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
            DoctorFinding::error(ID, "Bad", "Critical", "Fix it"),
            DoctorFinding::warning(ID, "Warn", "Minor", "Fix it"),
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
            DoctorFinding::warning(ID, "Warn", "Minor", "Fix it"),
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
            DoctorFinding::skipped(ID, "Skipped", "Not applicable"),
            DoctorFinding::skipped(ID, "Skipped 2", "Also not applicable"),
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
            DoctorFinding::skipped(ID, "Skipped", "Not applicable"),
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
            DoctorFinding::warning(ID, "Warn", "Minor", "Fix it"),
            DoctorFinding::error(ID, "Bad", "Critical", "Fix it"),
            DoctorFinding::skipped(ID, "Skipped", "Not applicable"),
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
        assert_eq!(finding.path.unwrap(), std::path::PathBuf::from("/test/path"));
    }

    #[test]
    fn test_finding_builder_with_code() {
        let finding = DoctorFinding::error(ID, "Title", "Detail", "Fix it")
            .with_code("ERR_VAULT_MISSING");
        assert_eq!(finding.code, Some("ERR_VAULT_MISSING"));
    }

    #[test]
    fn test_doctor_check_id_display() {
        let id = DoctorCheckId::new("vault.exists");
        assert_eq!(id.to_string(), "vault.exists");
        assert_eq!(id.as_str(), "vault.exists");
    }
}
