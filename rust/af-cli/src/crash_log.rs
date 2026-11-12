//! Local crash capture (T1.9): panics append one JSON line to
//! `<user_dir>/crashes/crash.jsonl` and keep the default stderr behaviour.
//! Nothing is sent anywhere; `af evidence export` picks the summary up, so
//! a beta tester's "it crashed" arrives with the actual panic record
//! instead of a memory.
//!
//! The writer is deliberately paranoid-simple: a failed crash write must
//! never produce a second panic, so every fallible step is ignored on error
//! and the original panic continues through the preserved hook.

use serde_json::{json, Value};

const CRASH_DIR: &str = "crashes";
const CRASH_FILE: &str = "crash.jsonl";

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Append one crash record. Failures are swallowed by contract: the crash
/// logger never becomes the second crash.
fn write_crash_entry(message: &str, location: &str, thread: &str) {
    let record = json!({
        "at_unix": unix_now(),
        "message": message,
        "location": location,
        "thread": thread,
    });
    let dir = af_sandbox::user_dir().join(CRASH_DIR);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join(CRASH_FILE);
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(file, "{record}");
        let _ = file.flush();
    }
}

/// Install the crash-capture hook around the previous (default) hook.
/// Called once from main before any dispatch.
pub fn install_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let message = if let Some(text) = info.payload().downcast_ref::<&str>() {
            (*text).to_string()
        } else if let Some(text) = info.payload().downcast_ref::<String>() {
            text.clone()
        } else {
            "opaque panic payload".to_string()
        };
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".into());
        let thread = std::thread::current()
            .name()
            .unwrap_or("<unnamed>")
            .to_string();
        write_crash_entry(&message, &location, &thread);
        previous(info);
    }));
}

/// Summary for the evidence package: crash count and the last records.
/// The journal is capped at the newest 20 entries so the bundle stays small.
pub fn load_summary() -> Value {
    let path = af_sandbox::user_dir().join(CRASH_DIR).join(CRASH_FILE);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return json!({"count": 0, "recent": []});
    };
    let records: Vec<Value> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    let count = records.len();
    let recent: Vec<Value> = records.into_iter().rev().take(20).collect();
    json!({"count": count, "recent": recent})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_records_append_and_summarize() {
        // Isolated home for the test home directory.
        let home = std::env::temp_dir().join(format!(
            "af-crash-test-{}-{}",
            std::process::id(),
            unix_now()
        ));
        std::env::set_var("ATOMIC_FLOW_HOME", &home);
        write_crash_entry("boom: assertion failed", "src/lib.rs:10:5", "main");
        write_crash_entry("second boom", "src/loop.rs:22:1", "worker");
        let summary = load_summary();
        assert_eq!(summary["count"], json!(2));
        let recent = summary["recent"].as_array().unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0]["message"], json!("second boom"));
        // The export path reads the same file through load_summary.
        std::env::remove_var("ATOMIC_FLOW_HOME");
        std::fs::remove_dir_all(home).ok();
    }
}
