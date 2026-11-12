//! `af evidence export` — one command, one cleaned feedback package for the
//! beta follow-up forum. Data-only by contract: event skeletons
//! (seq/event_type/call_id/outcome) without payloads unless explicitly
//! requested, plus doctor checks and the kernel version. Journal payloads
//! hold prompts and source snippets, so they stay out by default; provider
//! credentials never enter the journal at all.

use af_journal::SessionJournal;
use serde_json::{json, Value};
use std::path::PathBuf;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build and write the evidence package. Returns a human summary value.
pub fn export(
    session_id: Option<&str>,
    out: Option<PathBuf>,
    include_payloads: bool,
) -> Result<Value, String> {
    let session_id = match session_id {
        Some(id) => id.to_string(),
        None => {
            let sessions = af_journal::list_sessions(1).map_err(|e| e.0)?;
            let first = sessions
                .first()
                .ok_or("no sessions exist yet; run a task first")?;
            first
                .get("session_id")
                .and_then(|v| v.as_str())
                .ok_or("session list entry has no id")?
                .to_string()
        }
    };
    let mut journal = SessionJournal::open(&session_id).map_err(|e| e.0)?;
    let snapshot = journal.read().map_err(|e| e.0)?;
    let events: Vec<Value> = snapshot
        .events
        .iter()
        .map(|event| {
            let mut skeleton = json!({
                "seq": event.get("seq"),
                "event_type": event.get("event_type"),
                "call_id": event.get("call_id"),
                "outcome": event.get("outcome"),
            });
            if include_payloads {
                skeleton["payload"] = event.get("payload").cloned().unwrap_or(Value::Null);
            }
            skeleton
        })
        .collect();
    let package = json!({
        "schema": "atomic-flow/evidence-export/v1",
        "exported_at_unix": unix_now(),
        "kernel_version": env!("CARGO_PKG_VERSION"),
        "session_id": session_id,
        "event_count": snapshot.events.len(),
        "include_payloads": include_payloads,
        "events": events,
        "doctor": crate::doctor::run_checks(),
        "crashes": crate::crash_log::load_summary(),
        "note": "payloads excluded by default; provider credentials never enter the journal",
    });
    let out_path = out.unwrap_or_else(|| PathBuf::from(format!("af-evidence-{session_id}.json")));
    std::fs::write(
        &out_path,
        serde_json::to_string_pretty(&package).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("evidence write failed: {e}"))?;
    Ok(json!({
        "ok": true,
        "path": out_path.display().to_string(),
        "events": snapshot.events.len(),
        "include_payloads": include_payloads,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_redacts_payloads_by_default_and_includes_on_request() {
        std::env::set_var(
            "ATOMIC_FLOW_HOME",
            std::env::temp_dir().join(format!(
                "af-evidence-test-{}-{}",
                std::process::id(),
                unix_now()
            )),
        );
        let project = std::env::temp_dir().join("af-evidence-proj");
        std::fs::create_dir_all(&project).unwrap();
        let mut journal =
            af_journal::SessionJournal::create(&project, Some("evidence-test"), None).unwrap();
        journal
            .append(
                "user_input",
                &json!({"text": "SECRET-PLANT-MARKER"}),
                None,
                None,
                None,
            )
            .unwrap();
        let out =
            std::env::temp_dir().join(format!("af-evidence-out-{}-clean.json", std::process::id()));
        let summary = export(Some("evidence-test"), Some(out.clone()), false).unwrap();
        assert_eq!(summary["ok"], json!(true));
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(
            !text.contains("SECRET-PLANT-MARKER"),
            "payloads must be redacted"
        );
        assert!(text.contains("user_input"), "event types stay visible");
        // Opt-in payloads: the marker appears, honestly labelled.
        let out2 =
            std::env::temp_dir().join(format!("af-evidence-out-{}-full.json", std::process::id()));
        let summary2 = export(Some("evidence-test"), Some(out2.clone()), true).unwrap();
        assert_eq!(summary2["include_payloads"], json!(true));
        let text2 = std::fs::read_to_string(&out2).unwrap();
        assert!(text2.contains("SECRET-PLANT-MARKER"));
        assert!(text2.contains("atomic-flow/evidence-export/v1"));
        std::env::remove_var("ATOMIC_FLOW_HOME");
        std::fs::remove_file(&out).ok();
        std::fs::remove_file(&out2).ok();
    }
}
