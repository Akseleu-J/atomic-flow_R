//! Bounded executable adapter for a host-approved, independently maintained oracle.
//! The project provides the working directory only. A configured oracle must be
//! trusted to avoid executing project code or loading mutable project dependencies
//! unless that execution has been separately isolated. JobRunner owns process
//! lifetime and durable records, and does not sandbox the trusted host process.

use af_evidence::{
    CheckExecution, CheckKind, EvidenceError, HostRequirementChecker, RequirementScope,
};
use af_exec::{JobRunner, JobSpec};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
};

const MAX_ORACLE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_RECEIPT_BYTES: u64 = 16 * 1024;
const MAX_ASSERTIONS: usize = 128;

pub struct ExecutableChecker {
    executable: PathBuf,
    executable_sha256: String,
    assertions: BTreeSet<String>,
    inventory_sha256: String,
    cwd: PathBuf,
    job_store: PathBuf,
    timeout_secs: u64,
    last_job_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OracleReport {
    schema_version: u32,
    assertions: Vec<OracleAssertion>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OracleAssertion {
    id: String,
    status: OracleStatus,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OracleStatus {
    Passed,
    Failed,
    Skipped,
}

impl ExecutableChecker {
    pub fn new(
        executable: PathBuf,
        executable_sha256: String,
        assertion_ids: Vec<String>,
        cwd: PathBuf,
        job_store: PathBuf,
        timeout_secs: u64,
    ) -> Result<Self, EvidenceError> {
        if !executable.is_absolute() || !cwd.is_absolute() || !job_store.is_absolute() {
            return Err(EvidenceError::Invalid(
                "absolute oracle, project and job store paths required",
            ));
        }
        if executable_sha256.len() != 64
            || !executable_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !(1..=120).contains(&timeout_secs)
            || !(1..=MAX_ASSERTIONS).contains(&assertion_ids.len())
        {
            return Err(EvidenceError::Invalid(
                "oracle pin, timeout or assertion inventory invalid",
            ));
        }
        let mut assertions = BTreeSet::new();
        for id in assertion_ids {
            if id.is_empty()
                || id.len() > 64
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                || !assertions.insert(id)
            {
                return Err(EvidenceError::Invalid(
                    "oracle assertion IDs must be distinct bounded identifiers",
                ));
            }
        }

        #[cfg(windows)]
        if !executable
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
        {
            return Err(EvidenceError::Invalid(
                "oracle must be a native .exe on Windows",
            ));
        }

        let executable = canonical_unlinked(&executable)?;
        let cwd = canonical_unlinked(&cwd)?;
        if !cwd.is_dir() || contains_path(&cwd, &executable) {
            return Err(EvidenceError::Invalid(
                "oracle must reside outside the project",
            ));
        }
        // Check the proposed destination before creating it. Reject traversal so
        // a nonexistent directory cannot mask the intended path relation.
        let proposed_store = store_destination(&job_store)?;
        if contains_path(&cwd, &proposed_store) || contains_path(&proposed_store, &cwd) {
            return Err(EvidenceError::Invalid(
                "oracle job store and project must be disjoint",
            ));
        }
        if executable.to_str().is_none() {
            return Err(EvidenceError::Invalid("oracle path must be valid Unicode"));
        }
        let inventory_sha256 = af_evidence::sha256(&serde_json::to_vec(&json!({
            "schema_version": 1,
            "oracle_sha256": executable_sha256,
            "assertion_ids": assertions,
            "timeout_secs": timeout_secs,
        }))?);
        let result = Self {
            executable,
            executable_sha256,
            assertions,
            inventory_sha256,
            cwd,
            job_store: proposed_store,
            timeout_secs,
            last_job_id: None,
        };
        result.verify_oracle()?;
        Ok(result)
    }

    pub fn check_inventory_sha256(&self) -> &str {
        &self.inventory_sha256
    }

    /// Host job record for the last admitted invocation, if one was attempted.
    pub fn last_job_id(&self) -> Option<&str> {
        self.last_job_id.as_deref()
    }

    fn verify_oracle(&self) -> Result<(), EvidenceError> {
        if canonical_unlinked(&self.executable)? != self.executable {
            return Err(EvidenceError::Invalid("oracle path identity changed"));
        }
        let path_metadata = fs::metadata(&self.executable)
            .map_err(|_| EvidenceError::Invalid("oracle metadata unavailable"))?;
        if !path_metadata.is_file() || path_metadata.len() > MAX_ORACLE_BYTES {
            return Err(EvidenceError::Invalid(
                "oracle executable is not a bounded file",
            ));
        }
        let file = File::open(&self.executable)
            .map_err(|_| EvidenceError::Invalid("oracle executable unavailable"))?;
        let metadata = file
            .metadata()
            .map_err(|_| EvidenceError::Invalid("oracle metadata unavailable"))?;
        if !metadata.is_file() || metadata.len() > MAX_ORACLE_BYTES {
            return Err(EvidenceError::Invalid(
                "oracle executable is not a bounded file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return Err(EvidenceError::Invalid("oracle executable has an alias"));
            }
        }
        let mut hash = Sha256::new();
        let size = io::copy(&mut file.take(MAX_ORACLE_BYTES + 1), &mut hash)
            .map_err(|_| EvidenceError::Invalid("oracle executable unreadable"))?;
        if size > MAX_ORACLE_BYTES || format!("{:x}", hash.finalize()) != self.executable_sha256 {
            return Err(EvidenceError::Invalid(
                "oracle executable digest differs from the host pin",
            ));
        }
        Ok(())
    }

    fn parse_report(&self, bytes: &[u8]) -> Result<(u64, u64, u64), EvidenceError> {
        if bytes.len() as u64 > MAX_RECEIPT_BYTES {
            return Err(EvidenceError::Invalid(
                "oracle report exceeds its byte bound",
            ));
        }
        let report: OracleReport = serde_json::from_slice(bytes)
            .map_err(|_| EvidenceError::Invalid("oracle must emit one strict assertion report"))?;
        if report.schema_version != 1 || report.assertions.len() != self.assertions.len() {
            return Err(EvidenceError::Invalid(
                "oracle report version or assertion count differs",
            ));
        }
        let mut seen = BTreeSet::new();
        let (mut passed, mut failed, mut skipped) = (0, 0, 0);
        for assertion in report.assertions {
            if !self.assertions.contains(&assertion.id) || !seen.insert(assertion.id) {
                return Err(EvidenceError::Invalid(
                    "oracle reported an unexpected or duplicate assertion",
                ));
            }
            match assertion.status {
                OracleStatus::Passed => passed += 1,
                OracleStatus::Failed => failed += 1,
                OracleStatus::Skipped => skipped += 1,
            }
        }
        Ok((passed, failed, skipped))
    }
}

impl HostRequirementChecker for ExecutableChecker {
    fn expected_checks(&self) -> u64 {
        self.assertions.len() as u64
    }

    fn execute(&mut self, scope: &RequirementScope) -> Result<CheckExecution, EvidenceError> {
        self.last_job_id = None;
        if scope.check_inventory_sha256 != self.inventory_sha256
            || scope.expected_checks != self.expected_checks()
        {
            return Err(EvidenceError::Invalid(
                "requirement scope does not match the pinned oracle inventory",
            ));
        }
        if canonical_unlinked(&self.cwd)? != self.cwd
            || store_destination(&self.job_store)? != self.job_store
        {
            return Err(EvidenceError::Invalid(
                "oracle project or job store path changed",
            ));
        }
        af_sandbox::registry::ensure_no_links(&self.job_store.join("jobs"))
            .map_err(|_| EvidenceError::Invalid("unsafe oracle job store"))?;
        self.verify_oracle()?;
        let runner = JobRunner::open(&self.job_store)
            .map_err(|_| EvidenceError::Invalid("oracle job store unavailable"))?;
        if !runner
            .unresolved_unknown_ids()
            .map_err(|_| EvidenceError::CheckerOutcomeUnknown)?
            .is_empty()
        {
            return Err(EvidenceError::CheckerOutcomeUnknown);
        }
        let spec = JobSpec::new(
            vec![self
                .executable
                .to_str()
                .ok_or(EvidenceError::Invalid("oracle path must be Unicode"))?
                .into()],
            self.cwd.clone(),
            self.timeout_secs,
        )
        .map_err(|_| EvidenceError::Invalid("oracle job is inadmissible"))?;
        self.last_job_id = Some(spec.job_id.clone());
        let status = runner
            .run(&spec)
            .map_err(|_| EvidenceError::CheckerOutcomeUnknown)?;
        if status["job_id"].as_str() != Some(&spec.job_id)
            || status["cleanup_confirmed"] != json!(true)
            || status["reconcile_required"] != json!(false)
        {
            return Err(EvidenceError::CheckerOutcomeUnknown);
        }
        self.verify_oracle()
            .map_err(|_| EvidenceError::CheckerOutcomeUnknown)?;
        if status["status"] != "succeeded"
            || status["exit_code"] != 0
            || status["timed_out"] != false
            || status["stdout_truncated"] != false
            || status["stderr_truncated"] != false
        {
            return Err(EvidenceError::Invalid(
                "oracle process did not complete cleanly",
            ));
        }

        let output = self
            .job_store
            .join("jobs")
            .join(format!("{}.out", spec.job_id));
        let mut bytes = Vec::new();
        File::open(canonical_unlinked(&output).map_err(|_| EvidenceError::CheckerOutcomeUnknown)?)
            .and_then(|f| f.take(MAX_RECEIPT_BYTES + 1).read_to_end(&mut bytes))
            .map_err(|_| EvidenceError::CheckerOutcomeUnknown)?;
        let (passed, failed, skipped) = self.parse_report(&bytes)?;
        let evidence = json!({
            "job_id": spec.job_id,
            "inventory_sha256": self.inventory_sha256,
            "source_inventory_sha256": scope.binding.inventory_sha256,
            "oracle_stdout_sha256": af_evidence::sha256(&bytes),
        });
        Ok(CheckExecution {
            task_id: scope.task_id.clone(),
            requirement_contract_sha256: scope.requirement_contract_sha256.clone(),
            checker_id: scope.checker_id.clone(),
            binding: scope.binding.clone(),
            requirement_id: scope.requirement_id.clone(),
            check_inventory_sha256: self.inventory_sha256.clone(),
            kind: CheckKind::IndependentBehavioral,
            completed: true,
            checked: passed + failed,
            passed,
            failed,
            skipped,
            evidence_sha256: af_evidence::sha256(&serde_json::to_vec(&evidence)?),
        })
    }
}

fn canonical_unlinked(path: &Path) -> Result<PathBuf, EvidenceError> {
    af_sandbox::registry::ensure_no_links(path)
        .map_err(|_| EvidenceError::Invalid("oracle paths may not contain links"))?;
    let resolved = path
        .canonicalize()
        .map_err(|_| EvidenceError::Invalid("oracle path unavailable"))?;
    af_sandbox::registry::ensure_no_links(&resolved)
        .map_err(|_| EvidenceError::Invalid("resolved oracle path contains links"))?;
    Ok(resolved)
}

fn store_destination(path: &Path) -> Result<PathBuf, EvidenceError> {
    if path
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(EvidenceError::Invalid(
            "oracle job store may not traverse parents",
        ));
    }
    af_sandbox::registry::ensure_no_links(path)
        .map_err(|_| EvidenceError::Invalid("unsafe oracle job store"))?;
    let mut ancestor = path;
    while !ancestor.exists() {
        ancestor = ancestor.parent().ok_or(EvidenceError::Invalid(
            "oracle job store ancestor unavailable",
        ))?;
    }
    if !ancestor.is_dir() {
        return Err(EvidenceError::Invalid(
            "oracle job store must be a directory",
        ));
    }
    let tail = path
        .strip_prefix(ancestor)
        .map_err(|_| EvidenceError::Invalid("invalid oracle job store"))?;
    Ok(canonical_unlinked(ancestor)?.join(tail))
}

fn contains_path(root: &Path, path: &Path) -> bool {
    #[cfg(not(windows))]
    {
        path.starts_with(root)
    }
    #[cfg(windows)]
    {
        let mut path_parts = path.components();
        root.components().all(|part| {
            path_parts.next().is_some_and(|other| {
                part.as_os_str().to_string_lossy().to_lowercase()
                    == other.as_os_str().to_string_lossy().to_lowercase()
            })
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        dir: PathBuf,
        project: PathBuf,
        executable: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("af-oracle-{}", af_entropy::token()));
            let project = dir.join("project");
            let executable = dir.join("oracle.exe");
            fs::create_dir_all(&project).unwrap();
            fs::write(&executable, b"oracle pin fixture").unwrap();
            Self {
                dir,
                project,
                executable,
            }
        }

        fn checker(&self, ids: &[&str]) -> Result<ExecutableChecker, EvidenceError> {
            ExecutableChecker::new(
                self.executable.clone(),
                af_evidence::sha256(b"oracle pin fixture"),
                ids.iter().map(|id| (*id).to_owned()).collect(),
                self.project.clone(),
                self.dir.join("job-store"),
                5,
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn receipt_requires_exact_pinned_assertions_and_strict_json() {
        let fixture = Fixture::new();
        let checker = fixture.checker(&["a", "b"]).unwrap();
        assert_eq!(checker.expected_checks(), 2);
        assert_eq!(
            checker.check_inventory_sha256(),
            fixture
                .checker(&["b", "a"])
                .unwrap()
                .check_inventory_sha256()
        );
        assert_ne!(
            checker.check_inventory_sha256(),
            fixture
                .checker(&["a", "c"])
                .unwrap()
                .check_inventory_sha256()
        );
        let pass = br#"{"schema_version":1,"assertions":[{"id":"b","status":"passed"},{"id":"a","status":"passed"}]}"#;
        assert_eq!(checker.parse_report(pass).unwrap(), (2, 0, 0));
        let witnessed_nonpass = br#"{"schema_version":1,"assertions":[{"id":"b","status":"skipped"},{"id":"a","status":"failed"}]}"#;
        assert_eq!(checker.parse_report(witnessed_nonpass).unwrap(), (0, 1, 1));
        for malformed in [
            &b""[..],
            br#"{"schema_version":1,"assertions":[]}"#,
            br#"{"schema_version":1,"assertions":[{"id":"a","status":"passed"},{"id":"a","status":"passed"}]}"#,
            br#"{"schema_version":1,"assertions":[{"id":"b","status":"passed"},{"id":"c","status":"passed"}]}"#,
            br#"{"schema_version":1,"schema_version":1,"assertions":[{"id":"a","status":"passed"},{"id":"b","status":"passed"}]}"#,
            br#"{"schema_version":1,"assertions":[{"id":"a","status":"failed","status":"passed"},{"id":"b","status":"passed"}]}"#,
            br#"{"schema_version":1,"assertions":[{"id":"a","status":"passed","verified":true},{"id":"b","status":"passed"}]}"#,
            br#"{"schema_version":1,"assertions":[{"id":"a","status":"passed"},{"id":"b","status":"passed"}]}{}"#,
        ] {
            assert!(checker.parse_report(malformed).is_err());
        }
        assert!(checker
            .parse_report(&vec![b' '; MAX_RECEIPT_BYTES as usize + 1])
            .is_err());
    }

    #[test]
    fn oracle_pin_refuses_mutation_and_project_owned_programs() {
        let fixture = Fixture::new();
        let checker = fixture.checker(&["behavior"]).unwrap();
        assert!(fixture.checker(&[]).is_err());
        assert!(fixture.checker(&["behavior", "behavior"]).is_err());
        let inside = fixture.project.join("oracle.exe");
        fs::write(&inside, b"oracle pin fixture").unwrap();
        assert!(ExecutableChecker::new(
            inside,
            af_evidence::sha256(b"oracle pin fixture"),
            vec!["behavior".into()],
            fixture.project.clone(),
            fixture.dir.join("job-store"),
            5
        )
        .is_err());
        assert!(ExecutableChecker::new(
            fixture.executable.clone(),
            af_evidence::sha256(b"oracle pin fixture"),
            vec!["behavior".into()],
            fixture.project.clone(),
            fixture.project.join("job-store"),
            5
        )
        .is_err());
        assert!(!fixture.project.join("job-store").exists());
        fs::write(&fixture.executable, b"changed").unwrap();
        assert!(checker.verify_oracle().is_err());
    }
}
