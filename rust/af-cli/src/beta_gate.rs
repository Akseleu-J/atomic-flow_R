//! B1 client wiring (the issuance half lives in tools/issuance_server.py,
//! the verifier in af_program::beta_access). The official beta build pins
//! the issuer public key at packaging time; with a pinned key every new
//! product operation re-checks access ONLINE - the 30-second decision
//! freshness makes clock rollback unable to reuse a stale decision. Dev
//! builds without a pinned key are honestly ungated and report themselves
//! as such; offline strictness for real deployments stays an explicit owner
//! decision (ENGINEER_BETA_PLAN, B1).

use serde::Deserialize;
use serde_json::{json, Value};
use std::io::Read;

pub const BETA_ISSUER_PUBKEY_HEX: &str = match option_env!("AF_BETA_ISSUER_PUBKEY_HEX") {
    Some(value) => value,
    None => "",
};

const MAX_RESPONSE_BYTES: usize = 4096;
const OFFLINE_PASS_FILE: &str = "beta-pass.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateConfig {
    pub issuer_pubkey: [u8; 32],
    pub grant_id: String,
    pub release_id: String,
    pub service_url: String,
}

impl GateConfig {
    pub fn from_env() -> Option<Self> {
        let pubkey_hex = std::env::var("AF_BETA_ISSUER_PUBKEY")
            .unwrap_or_else(|_| BETA_ISSUER_PUBKEY_HEX.to_string());
        if pubkey_hex.is_empty() {
            return None;
        }
        let issuer_pubkey = hex_32(&pubkey_hex)?;
        Some(GateConfig {
            issuer_pubkey,
            grant_id: std::env::var("AF_BETA_GRANT").ok()?,
            release_id: std::env::var("AF_BETA_RELEASE").ok()?,
            service_url: std::env::var("AF_BETA_SERVICE").ok()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateOutcome {
    Active { expires_in_secs: u64 },
    Refused(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionEnvelope {
    decision_b64: String,
    signature_hex: String,
}

fn hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn hex_64(value: &str) -> Result<[u8; 64], String> {
    if value.len() != 128 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid signature encoding in beta decision".into());
    }
    let mut out = [0u8; 64];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
            .map_err(|_| "invalid signature encoding in beta decision".to_string())?;
    }
    Ok(out)
}

fn base64_decode(value: &str) -> Result<Vec<u8>, String> {
    let mut buffer = Vec::with_capacity(value.len() * 3 / 4);
    let mut accumulator: u32 = 0;
    let mut bits = 0u32;
    for symbol in value.chars().filter(|c| !c.is_whitespace()) {
        let v = match symbol {
            'A'..='Z' => symbol as u32 - 'A' as u32,
            'a'..='z' => symbol as u32 - 'a' as u32 + 26,
            '0'..='9' => symbol as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            '=' => break,
            _ => return Err("invalid base64 in beta decision".into()),
        };
        accumulator = (accumulator << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            buffer.push(((accumulator >> bits) & 0xFF) as u8);
        }
    }
    Ok(buffer)
}

fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

pub fn check(config: &GateConfig, now: u64) -> Result<GateOutcome, String> {
    let challenge = af_program::beta_access::Challenge::generate()
        .map_err(|_| "challenge generation failed".to_string())?;
    let url = format!(
        "{}/v1/decision?grant={}&challenge={}",
        config.service_url.trim_end_matches('/'),
        config.grant_id,
        challenge.wire_value()
    );
    let response = ureq::get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .call()
        .map_err(|error| format!("beta service unreachable: {error}"))?;
    let mut raw = Vec::new();
    response
        .into_reader()
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|error| format!("beta service response truncated: {error}"))?;
    if raw.len() > MAX_RESPONSE_BYTES {
        return Err("beta service response too large".into());
    }
    let envelope: DecisionEnvelope = serde_json::from_slice(&raw)
        .map_err(|_| "beta service response is not a decision envelope".to_string())?;
    let body = base64_decode(&envelope.decision_b64)?;
    let signature = hex_64(&envelope.signature_hex)?;
    match af_program::beta_access::verify_access(
        &config.issuer_pubkey,
        &body,
        &signature,
        &config.grant_id,
        &config.release_id,
        challenge,
        now,
    ) {
        Ok(decision) => Ok(GateOutcome::Active {
            expires_in_secs: decision.expires_at().saturating_sub(now),
        }),
        Err(af_program::beta_access::AccessError::Inactive) => {
            let spent_hours = decision_provenance(&body)
                .map(|(activated, _)| (now.saturating_sub(activated)) / 3600)
                .unwrap_or(0);
            Ok(GateOutcome::Refused(format!(
                "beta access is inactive or expired (about {spent_hours}h used of the 96h window); export your evidence with `af evidence export` and report back"
            )))
        }
        Err(af_program::beta_access::AccessError::Invalid) => Err(
            "beta access decision is invalid (wrong grant/release, stale response or tampering)"
                .into(),
        ),
    }
}

fn decision_provenance(body: &[u8]) -> Option<(u64, u64)> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    Some((
        value.get("activated_at")?.as_u64()?,
        value.get("expires_at")?.as_u64()?,
    ))
}

/// Verify the signed pass envelope file and return the trusted decision.
pub fn verify_pass_file(
    pass_path: &std::path::Path,
    now: u64,
) -> Result<af_program::beta_access::AccessDecision, String> {
    let text =
        std::fs::read_to_string(pass_path).map_err(|e| format!("beta pass read failed: {e}"))?;
    let pass: Value =
        serde_json::from_str(&text).map_err(|_| "beta pass is not valid JSON".to_string())?;
    let body_b64 = pass
        .get("decision_b64")
        .and_then(Value::as_str)
        .ok_or("beta pass missing decision_b64")?;
    let sig_hex = pass
        .get("signature_hex")
        .and_then(Value::as_str)
        .ok_or("beta pass missing signature_hex")?;
    let body = base64_decode(body_b64)?;
    let signature = hex_64(sig_hex)?;
    let pubkey_hex = std::env::var("AF_BETA_ISSUER_PUBKEY")
        .unwrap_or_else(|_| BETA_ISSUER_PUBKEY_HEX.to_string());
    let issuer_key = hex_32(&pubkey_hex).ok_or("beta issuer pubkey is invalid")?;
    let grant_id = pass
        .get("grant_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let release_id = pass
        .get("release_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    af_program::beta_access::verify_offline_pass(
        &issuer_key,
        &body,
        &signature,
        &grant_id,
        &release_id,
        now,
    )
    .map_err(|e| match e {
        af_program::beta_access::AccessError::Inactive => {
            "beta access expired - the pass window has closed".to_string()
        }
        _ => "beta pass is invalid (wrong grant/release or tampered)".to_string(),
    })
}

pub fn gate_offline_pass(pass_path: &std::path::Path, now: u64) -> Result<(), String> {
    verify_pass_file(pass_path, now).map(|_| ())
}

/// `af beta`: the offline pass first (the pivot made it the primary access
/// channel), then the online service, then the honest dev-build message.
pub fn status_report(now: u64) -> String {
    let pass_file = af_sandbox::user_dir().join(OFFLINE_PASS_FILE);
    if pass_file.exists() {
        return match verify_pass_file(&pass_file, now) {
            Ok(decision) => {
                let remaining = decision.expires_at().saturating_sub(now);
                format!(
                    "beta pass: ACTIVE, {}h {}m remaining (grant {}, release {})",
                    remaining / 3600,
                    (remaining % 3600) / 60,
                    decision.grant_id(),
                    decision.release_id()
                )
            }
            Err(message) => format!("beta pass: {message}"),
        };
    }
    match GateConfig::from_env() {
        None => "beta gate: disabled (dev build without a pinned issuer key)".into(),
        Some(config) => match check(&config, now) {
            Ok(GateOutcome::Active { expires_in_secs }) => format!(
                "beta access: ACTIVE, {}h {}m remaining (grant {})",
                expires_in_secs / 3600,
                (expires_in_secs % 3600) / 60,
                config.grant_id
            ),
            Ok(GateOutcome::Refused(message)) => format!("beta access: REFUSED - {message}"),
            Err(error) => format!("beta access: UNAVAILABLE - {error}"),
        },
    }
}

pub fn gate_new_operation(now: u64) -> Result<(), String> {
    // Offline mode: a signed pass file replaces the online service check.
    let pass_file = af_sandbox::user_dir().join(OFFLINE_PASS_FILE);
    if pass_file.exists() {
        return gate_offline_pass(&pass_file, now);
    }
    match GateConfig::from_env() {
        None => Ok(()),
        Some(config) => match check(&config, now)? {
            GateOutcome::Active { .. } => Ok(()),
            GateOutcome::Refused(message) => {
                let _report = self_destruct(&config.grant_id, now)?;
                let _ = open_feedback_email(&config.grant_id);
                Err(format!(
                    "{message} | Self-destruct complete. Your work is preserved in ~/.atomic_flow/beta-final-report/"
                ))
            }
        },
    }
}

pub fn self_destruct(grant_id: &str, now: u64) -> Result<Value, String> {
    let home = af_sandbox::user_dir();
    let preserve_dir = home.join("beta-final-report");
    std::fs::create_dir_all(&preserve_dir)
        .map_err(|e| format!("preserve dir creation failed: {e}"))?;

    let evidence =
        crate::evidence_export::export(None, Some(preserve_dir.join("evidence.json")), false);
    let evidence_note = match &evidence {
        Ok(summary) => format!(
            "evidence exported: {}",
            summary["path"].as_str().unwrap_or("")
        ),
        Err(e) => format!("evidence export failed: {e}"),
    };

    let crash_src = home.join("crashes").join("crash.jsonl");
    if crash_src.exists() {
        let _ = std::fs::copy(&crash_src, preserve_dir.join("crash.jsonl"));
    }

    let report = json!({
        "schema": "atomic-flow/self-destruct/v1",
        "grant_id": grant_id,
        "at_unix": now,
        "evidence_note": evidence_note,
        "message": "Your 96-hour beta window has expired. Your project files and evidence are preserved in this folder. The program binaries have been removed.",
    });
    std::fs::write(
        preserve_dir.join("self-destruct-report.json"),
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("self-destruct report write failed: {e}"))?;

    let exe = std::env::current_exe().map_err(|e| format!("cannot locate own exe: {e}"))?;
    let trash = exe.with_extension("af-beta-deleted");
    let _ = std::fs::rename(&exe, &trash);
    schedule_delete_on_reboot(&trash);

    let studio_dist = home.join("studio-dist");
    if studio_dist.exists() {
        let _ = std::fs::remove_dir_all(&studio_dist);
    }

    Ok(report)
}

#[cfg(windows)]
fn schedule_delete_on_reboot(path: &std::path::Path) {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    extern "system" {
        fn MoveFileExW(
            lpexistingfilename: *const u16,
            lpnewfilename: *const u16,
            dwflags: u32,
        ) -> i32;
    }
    unsafe {
        let _ = MoveFileExW(wide.as_ptr(), std::ptr::null(), 4);
    }
}

#[cfg(not(windows))]
fn schedule_delete_on_reboot(_path: &std::path::Path) {}

pub fn open_feedback_email(grant_id: &str) -> Result<(), String> {
    let subject = format!("Atomic Flow beta feedback - {grant_id}");
    let body = "My 96-hour beta window has expired.\n\nThe self-destruct report and evidence are saved at:\n  ~/.atomic_flow/beta-final-report/\n\nFeedback:\n1. Installed from first attempt? yes/no\n2. Time to first success: <10min / <30min / longer\n3. What did you abandon and why\n4. False positives from the checker\n5. Anything else\n\n(attach the evidence.json and self-destruct-report.json from the beta-final-report folder)";
    let mailto = format!(
        "mailto:beta-feedback@atomic-flow.dev?subject={}&body={}",
        urlencode(&subject),
        urlencode(body)
    );
    let output = if cfg!(windows) {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", &mailto])
            .output()
    } else {
        std::process::Command::new("xdg-open").arg(&mailto).output()
    };
    match output {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("cannot open email client: {e}")),
    }
}
