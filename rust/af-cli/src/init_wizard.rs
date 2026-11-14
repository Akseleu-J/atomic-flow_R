//! `af init` (T1.8): the first-run wizard for a beta tester's machine.
//! Three steps, all idempotent: (1) a providers.json template with a filled
//! example so the tester edits instead of authors; (2) the durable budget
//! ledger with a sane default ceiling unless it already exists; (3) the
//! doctor report as the final "is this machine ready" gate. Nothing here
//! touches the network or enables edits — the wizard only prepares config.

use serde_json::{json, Value};

const PROVIDER_EXAMPLE: &str = r#"{
  "schema_version": 1,
  "providers": [
    {
      "id": "my-provider",
      "label": "My OpenAI-compatible endpoint",
      "base_url": "https://api.example.com/v1",
      "api_key_env": "MY_PROVIDER_API_KEY",
      "models": ["model-name-1", "model-name-2"],
      "reservation_usd": "0.10"
    }
  ]
}"#;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Run the wizard. `budget_cap_usd` seeds the ledger when none exists;
/// `None` skips budget creation. Returns the human-readable report.
pub fn run(budget_cap_usd: Option<&str>) -> Result<Value, String> {
    let mut steps: Vec<Value> = Vec::new();

    // Step 1: providers.json template.
    let providers_path = af_sandbox::user_dir().join("providers.json");
    if providers_path.exists() {
        steps.push(json!({
            "step": "providers",
            "state": "exists",
            "path": providers_path.display().to_string(),
        }));
    } else {
        if let Some(parent) = providers_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&providers_path, PROVIDER_EXAMPLE)
            .map_err(|e| format!("providers template write failed: {e}"))?;
        steps.push(json!({
            "step": "providers",
            "state": "template_written",
            "path": providers_path.display().to_string(),
            "hint": "edit this file: replace the example provider with your real endpoint, model names and the NAME of the env variable that holds your key",
        }));
    }

    // Step 2: the budget ledger.
    let ledger_path = crate::trusted_provider::ledger_path();
    if ledger_path.exists() {
        steps.push(json!({
            "step": "budget",
            "state": "exists",
            "path": ledger_path.display().to_string(),
            "hint": "inspect with `af budget show`",
        }));
    } else if let Some(cap_text) = budget_cap_usd {
        let cap = af_budget::Money::from_usd_str(cap_text)
            .map_err(|_| "invalid --budget-cap-usd".to_string())?;
        if cap.0 == 0 {
            return Err("budget cap must be positive".into());
        }
        if let Some(parent) = ledger_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        af_budget::Ledger::create(&ledger_path, crate::trusted_provider::OWNER, cap, 64)
            .map_err(|e| e.0)?;
        steps.push(json!({
            "step": "budget",
            "state": "created",
            "cap_usd": cap_text,
            "max_calls": 64,
            "path": ledger_path.display().to_string(),
        }));
    } else {
        steps.push(json!({
            "step": "budget",
            "state": "skipped",
            "hint": "create one before live sends: af init --budget-cap-usd 1.00",
        }));
    }

    // Step 3: the doctor verdict as the final readiness gate.
    let checks = crate::doctor::run_checks();
    let failed: Vec<String> = checks["checks"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter(|entry| entry["ok"].as_bool() != Some(true))
        .filter_map(|entry| entry["name"].as_str().map(str::to_string))
        .collect();
    steps.push(json!({
        "step": "doctor",
        "state": if failed.is_empty() { "ready" } else { "attention" },
        "failing": failed,
        "hint": if failed.is_empty() { "run `af doctor` any time for the detailed report" } else { "run `af doctor` for the human-readable report with fix hints" },
    }));

    Ok(json!({
        "ok": true,
        "at_unix": unix_now(),
        "steps": steps,
        "next": [
            "pick a provider and model in Studio settings (or af task run --provider-id ...)",
            "live sends need a budget: af budget show",
            "feedback: af evidence export",
        ],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_is_idempotent_and_respects_the_cap() {
        let home = std::env::temp_dir().join(format!(
            "af-init-test-{}-{}",
            std::process::id(),
            unix_now()
        ));
        std::env::set_var("ATOMIC_FLOW_HOME", &home);
        // Providers template is written once, then reported as existing.
        let first = run(Some("1.00")).unwrap();
        let steps1 = first["steps"].as_array().unwrap();
        assert_eq!(steps1[0]["state"], json!("template_written"));
        assert_eq!(steps1[1]["state"], json!("created"));
        let second = run(Some("2.00")).unwrap();
        let steps2 = second["steps"].as_array().unwrap();
        assert_eq!(steps2[0]["state"], json!("exists"));
        assert_eq!(
            steps2[1]["state"],
            json!("exists"),
            "the ledger is never overwritten"
        );
        // The template parses as a valid providers config (schema-shaped).
        let text = std::fs::read_to_string(home.join("providers.json")).unwrap();
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["schema_version"], json!(1));
        // The template carries ONE example provider: the tester edits it
        // instead of authoring the schema from scratch.
        let providers = parsed["providers"].as_array().unwrap();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0]["id"], json!("my-provider"));
        std::env::remove_var("ATOMIC_FLOW_HOME");
        std::fs::remove_dir_all(home).ok();
    }
}
