//! Host-admitted behavioral checker (N03 slice): executes a host-configured
//! test command through the durable job runner, parses the machine-readable
//! JUnit report the command must produce, and refuses unless the suite ran,
//! passed completely, and the source inventory did not move during execution.
//! The adapter is a trusted host boundary — it pins the oracle by running
//! exactly the admitted argv, nothing invented, no model text involved.
use af_evidence::{CheckExecution, CheckKind, EvidenceError, RequirementScope};
use std::path::PathBuf;

const MAX_JUNIT_BYTES: usize = 1024 * 1024;

pub struct CommandBehavioralChecker {
    pub checker_id: String,
    pub runner: af_exec::JobRunner,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    /// JUnit XML report the command must (re)produce.
    pub junit_path: PathBuf,
}

/// Minimal bounded reader for `<testsuite tests=".." failures=".." errors=".."
/// skipped="..">` — the attributes real runners (pytest-junit, cargo2junit,
/// jest-junit) always emit. No XML tree is built; nothing is executed from
/// the report.
fn junit_counts(bytes: &[u8]) -> Option<(u64, u64, u64, u64)> {
    let text = std::str::from_utf8(bytes).ok()?;
    let start = text.find("<testsuite")?;
    let rest = &text[start..];
    let end = rest.find('>')?;
    let tag = &rest[..=end];
    let attr = |name: &str| -> Option<u64> {
        let pattern = format!("{name}=\"");
        let at = tag.find(&pattern)? + pattern.len();
        let tail = &tag[at..];
        let close = tail.find('"')?;
        tail[..close].trim().parse::<u64>().ok()
    };
    Some((
        attr("tests")?,
        attr("failures")?,
        attr("errors")?,
        attr("skipped")?,
    ))
}

impl CommandBehavioralChecker {
    fn refusal(message: String) -> EvidenceError {
        EvidenceError::CheckerUnavailable(message)
    }
}

impl af_evidence::HostRequirementChecker for CommandBehavioralChecker {
    fn execute(
        &mut self,
        scope: &RequirementScope,
    ) -> std::result::Result<CheckExecution, EvidenceError> {
        if scope.checker_id != self.checker_id {
            return Err(Self::refusal(
                "scope names a different checker than this adapter".into(),
            ));
        }
        let before = af_sandbox::manifest(&self.cwd)
            .map_err(|error| Self::refusal(format!("source audit failed: {error}")))?;
        let spec = af_exec::JobSpec::new(self.argv.clone(), self.cwd.clone(), 600)
            .map_err(|error| Self::refusal(format!("check spec refused: {error}")))?;
        let status = self
            .runner
            .run(&spec)
            .map_err(|error| Self::refusal(format!("check execution unresolved: {error}")))?;
        if status["status"] != serde_json::json!("succeeded")
            || status["cleanup_confirmed"] != serde_json::json!(true)
            || status["timed_out"] == serde_json::json!(true)
        {
            return Err(Self::refusal(format!(
                "requirement checks did not complete cleanly: status={}",
                status["status"]
            )));
        }
        let after = af_sandbox::manifest(&self.cwd)
            .map_err(|error| Self::refusal(format!("post-check audit failed: {error}")))?;
        if before != after {
            return Err(Self::refusal(
                "source mutated during requirement execution; oracle unpinned".into(),
            ));
        }
        let junit = std::fs::read(&self.junit_path).map_err(|error| {
            Self::refusal(format!(
                "behavioral report unavailable at {}: {error}",
                self.junit_path.to_string_lossy()
            ))
        })?;
        if junit.len() > MAX_JUNIT_BYTES {
            return Err(Self::refusal("behavioral report exceeds its bound".into()));
        }
        let (tests, failures, errors, skipped) = junit_counts(&junit)
            .ok_or_else(|| Self::refusal("behavioral report is not parseable JUnit".into()))?;
        if tests == 0 {
            return Err(EvidenceError::Invalid(
                "zero-check behavioral report cannot verify a requirement",
            ));
        }
        if failures + errors + skipped > 0 {
            return Err(Self::refusal(format!(
                "requirement suite not fully green: {failures} failures, {errors} errors, {skipped} skipped"
            )));
        }
        Ok(CheckExecution {
            task_id: scope.task_id.clone(),
            requirement_contract_sha256: scope.requirement_contract_sha256.clone(),
            checker_id: scope.checker_id.clone(),
            binding: scope.binding.clone(),
            requirement_id: scope.requirement_id.clone(),
            check_inventory_sha256: scope.check_inventory_sha256.clone(),
            kind: CheckKind::IndependentBehavioral,
            completed: true,
            checked: tests,
            passed: tests,
            failed: 0,
            skipped: 0,
            evidence_sha256: af_evidence::sha256(&junit),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use af_evidence::HostRequirementChecker;
    use std::path::Path;

    fn workspace(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "af-behavioral-{}-{}-{name}",
            std::process::id(),
            af_entropy::token()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn checker_for(dir: &Path, argv: Vec<String>) -> CommandBehavioralChecker {
        // The job store lives OUTSIDE the audited source directory: runner
        // bookkeeping must never look like source mutation.
        let jobs = dir
            .parent()
            .unwrap()
            .join(format!("af-behavioral-jobs-{}", af_entropy::token()));
        CommandBehavioralChecker {
            checker_id: "host-tests".into(),
            runner: af_exec::JobRunner::open(&jobs).unwrap(),
            argv,
            cwd: dir.to_path_buf(),
            junit_path: dir.join("report.xml"),
        }
    }

    const GREEN: &[u8] = br#"<testsuite name="s" tests="3" failures="0" errors="0" skipped="0"><testcase name="a"/></testsuite>"#;
    const RED: &[u8] = br#"<testsuite name="s" tests="3" failures="1" errors="0" skipped="0"><failure/></testsuite>"#;

    fn scope(_dir: &PathBuf) -> RequirementScope {
        RequirementScope {
            task_id: "t1".into(),
            requirement_id: "tests-pass".into(),
            requirement_contract_sha256: af_evidence::sha256(b"contract"),
            checker_id: "host-tests".into(),
            binding: af_evidence::SourceBinding {
                workspace_id: "default".into(),
                source_revision: "staged".into(),
                inventory_sha256: af_evidence::sha256(b"inventory"),
                runtime_id: "af-cli".into(),
            },
            check_inventory_sha256: af_evidence::sha256(b"junit"),
            expected_checks: 3,
        }
    }

    #[test]
    fn green_suite_mints_a_behavioral_execution() {
        let dir = workspace("green");
        std::fs::write(dir.join("report.xml"), GREEN).unwrap();
        #[cfg(windows)]
        let argv = vec!["cmd".into(), "/C".into(), "exit 0".into()];
        #[cfg(not(windows))]
        let argv = vec!["sh".into(), "-c".into(), "exit 0".into()];
        let mut checker = checker_for(&dir, argv);
        let execution = checker.execute(&scope(&dir)).unwrap();
        assert_eq!(execution.kind, CheckKind::IndependentBehavioral);
        assert_eq!(execution.checked, 3);
        assert_eq!(execution.passed, 3);
        assert_eq!(execution.evidence_sha256, af_evidence::sha256(GREEN));
        // The minted receipt passes the strict gate end-to-end.
        let receipt = af_evidence::run_requirement_check(&scope(&dir), &mut checker).unwrap();
        assert!(!receipt.evidence_sha256().is_empty());
    }

    #[test]
    fn red_suite_zero_tests_and_failed_command_all_refuse() {
        let dir = workspace("red");
        std::fs::write(dir.join("report.xml"), RED).unwrap();
        #[cfg(windows)]
        let argv = vec!["cmd".into(), "/C".into(), "exit 0".into()];
        #[cfg(not(windows))]
        let argv = vec!["sh".into(), "-c".into(), "exit 0".into()];
        let mut checker = checker_for(&dir, argv);
        assert!(checker.execute(&scope(&dir)).is_err(), "failures refuse");

        std::fs::write(
            dir.join("report.xml"),
            br#"<testsuite name="s" tests="0" failures="0" errors="0" skipped="0"/>"#,
        )
        .unwrap();
        assert!(checker.execute(&scope(&dir)).is_err(), "zero tests refuse");

        std::fs::write(dir.join("report.xml"), GREEN).unwrap();
        #[cfg(windows)]
        let failing = vec!["cmd".into(), "/C".into(), "exit 3".into()];
        #[cfg(not(windows))]
        let failing = vec!["sh".into(), "-c".into(), "exit 3".into()];
        let mut checker = checker_for(&dir, failing);
        assert!(
            checker.execute(&scope(&dir)).is_err(),
            "failed command refuses"
        );
    }

    #[test]
    fn source_mutation_during_the_check_refuses_the_oracle() {
        let dir = workspace("mutate");
        std::fs::write(dir.join("report.xml"), GREEN).unwrap();
        std::fs::write(dir.join("lib.py"), b"def helper():\n    return 1\n").unwrap();
        #[cfg(windows)]
        let argv = vec!["cmd".into(), "/C".into(), "echo x>> lib.py".into()];
        #[cfg(not(windows))]
        let argv = vec!["sh".into(), "-c".into(), "echo x >> lib.py".into()];
        let mut checker = checker_for(&dir, argv);
        let error = checker.execute(&scope(&dir)).unwrap_err();
        assert!(error.to_string().contains("mutated") || error.to_string().contains("audit"));
    }
}
