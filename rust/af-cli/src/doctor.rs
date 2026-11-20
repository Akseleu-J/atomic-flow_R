//! `af doctor`: environment checks for the self-host kernel. Read-only —
//! reports what is present, what is missing, and never mutates anything.

use serde_json::{json, Value};
use std::path::PathBuf;

fn which(binary: &str) -> Option<PathBuf> {
    let path = std::env::var("PATH").unwrap_or_default();
    let separator = if cfg!(windows) { ';' } else { ':' };
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    for dir in path.split(separator) {
        if dir.is_empty() {
            continue;
        }
        let candidate = PathBuf::from(dir).join(format!("{binary}{suffix}"));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn command_version(binary: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(binary)
        .args(args)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    Some(text.lines().next().unwrap_or_default().trim().to_string())
}

/// Run all checks; every entry is independent — one failure never hides the
/// rest.
pub fn run_checks() -> Value {
    let mut checks: Vec<Value> = Vec::new();
    let mut check = |name: &str, ok: bool, detail: Value| {
        checks.push(json!({"name": name, "ok": ok, "detail": detail}));
    };

    check("kernel_version", true, json!(env!("CARGO_PKG_VERSION")));

    let home = af_sandbox::user_dir();
    let home_writable = std::fs::create_dir_all(&home).is_ok();
    check(
        "atomic_flow_home",
        home_writable,
        json!({"path": home.to_string_lossy(), "writable": home_writable}),
    );

    let sessions_dir = home.join("sessions");
    check(
        "sessions_dir",
        sessions_dir.is_dir(),
        json!({"path": sessions_dir.to_string_lossy(), "exists": sessions_dir.is_dir()}),
    );

    match which("git") {
        Some(path) => {
            let version = command_version("git", &["--version"]).unwrap_or_default();
            check(
                "git",
                true,
                json!({"path": path.to_string_lossy(), "version": version}),
            );
        }
        None => check("git", false, json!({"reason": "git not found on PATH"})),
    }

    match which("docker") {
        Some(path) => {
            let version =
                command_version("docker", &["version", "--format", "{{.Server.Version}}"]);
            check(
                "docker",
                version.is_some(),
                json!({"path": path.to_string_lossy(), "server_version": version}),
            );
        }
        None => check(
            "docker",
            false,
            json!({"reason": "docker not found; sandbox jobs fall back to local-trusted"}),
        ),
    }

    let firecracker = which("firecracker");
    check(
        "firecracker",
        firecracker.is_some() && cfg!(target_os = "linux"),
        json!({
            "on_path": firecracker.is_some(),
            "reason": if cfg!(target_os = "linux") { "microVM acceptance needs /dev/kvm" } else { "Linux-only runtime" },
        }),
    );

    let graphs_dir = home.join("graphs");
    check(
        "graphs_dir",
        graphs_dir.is_dir(),
        json!({"path": graphs_dir.to_string_lossy(), "exists": graphs_dir.is_dir()}),
    );

    // Journal health (P09): quick diagnostics on the newest sessions plus
    // one full-chain verify of the newest one. Structural problems (an
    // interrupted tail, a checkpoint that disagrees with the journal state,
    // a failed chain verification) fail the check; pending/unresolved call
    // ledgers are informational and never fail it.
    let mut sessions = Vec::new();
    let mut journal_ok = true;
    let mut newest: Option<String> = None;
    match af_journal::list_sessions(8) {
        Ok(entries) => {
            for entry in entries {
                let Some(session_id) = entry.get("session_id").and_then(Value::as_str) else {
                    continue;
                };
                if newest.is_none() {
                    newest = Some(session_id.to_string());
                }
                match af_journal::SessionJournal::open(session_id) {
                    Ok(mut journal) => match journal.diagnostics(false) {
                        Ok(report) => {
                            let healthy = report["state"]["tail_present"] == json!(false)
                                && report["checkpoint"]["matches_state"] == json!(true)
                                && report.get("refresh_error").is_none();
                            if !healthy {
                                journal_ok = false;
                            }
                            sessions.push(json!({
                                "session_id": session_id,
                                "ok": healthy,
                                "state": report["state"],
                                "checkpoint": report["checkpoint"],
                                "refresh_error": report.get("refresh_error"),
                            }));
                        }
                        Err(error) => {
                            journal_ok = false;
                            sessions.push(json!({
                                "session_id": session_id,
                                "ok": false,
                                "error": error.to_string(),
                            }));
                        }
                    },
                    Err(error) => {
                        journal_ok = false;
                        sessions.push(json!({
                            "session_id": session_id,
                            "ok": false,
                            "error": error.to_string(),
                        }));
                    }
                }
            }
        }
        Err(error) => {
            journal_ok = false;
            sessions.push(json!({"error": error.to_string()}));
        }
    }
    let mut verify_detail = json!({"verified": null, "reason": "no sessions"});
    if let Some(session_id) = newest {
        match af_journal::SessionJournal::open(&session_id) {
            Ok(mut journal) => match journal.diagnostics(true) {
                Ok(report) => verify_detail = report["integrity"].clone(),
                Err(error) => {
                    verify_detail = json!({"verified": false, "error": error.to_string()});
                    journal_ok = false;
                }
            },
            Err(error) => {
                verify_detail = json!({"verified": false, "error": error.to_string()});
                journal_ok = false;
            }
        }
    }
    check(
        "journal_health",
        journal_ok,
        json!({"sessions": sessions, "newest_verify": verify_detail}),
    );

    json!({
        "ok": checks.iter().all(|check| check["ok"] == json!(true)),
        "checks": checks,
    })
}
