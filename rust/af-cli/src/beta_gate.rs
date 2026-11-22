//! Official beta builds require an offline pass signed by the pinned issuer.
//! Unpinned builds may opt in to the legacy development issuance service.

use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::Path;

const MAX_CLOCK_ROLLBACK_SECS: u64 = 300;
const LAST_SEEN_FILE: &str = "beta-last-seen";

const PINNED_ISSUER: Option<&str> = option_env!("AF_BETA_ISSUER_PUBKEY_HEX");
const PINNED_RELEASE: Option<&str> = option_env!("AF_BETA_RELEASE");

fn issuer_key(pinned: Option<&str>) -> Result<Option<[u8; 32]>, String> {
    if let Some(key) = pinned {
        return hex_32(key)
            .map(Some)
            .ok_or("invalid pinned beta issuer key".into());
    }
    #[cfg(feature = "dev-gate")]
    match std::env::var("AF_BETA_ISSUER_PUBKEY") {
        Ok(key) => {
            return hex_32(&key)
                .map(Some)
                .ok_or("invalid dev beta issuer key".into())
        }
        Err(std::env::VarError::NotPresent) => {}
        Err(std::env::VarError::NotUnicode(_)) => return Err("invalid dev beta issuer key".into()),
    }
    Ok(None)
}

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
    fn from_env(issuer_pubkey: [u8; 32]) -> Option<Self> {
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
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
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

/// Verify the signed pass envelope file and return the trusted window terms.
fn verify_pass_file(
    pass_path: &Path,
    issuer_key: &[u8; 32],
    release: Option<&str>,
    now: u64,
) -> Result<af_program::beta_access::OfflinePass, String> {
    let file = std::fs::File::open(pass_path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            "beta pass required: install beta-pass.json".into()
        } else {
            format!("beta pass read failed: {error}")
        }
    })?;
    let mut raw = Vec::new();
    file.take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|error| format!("beta pass read failed: {error}"))?;
    if raw.len() > MAX_RESPONSE_BYTES {
        return Err("beta pass is too large".into());
    }
    #[derive(Deserialize)]
    struct OfflineEnvelope {
        decision_b64: String,
        signature_hex: String,
    }
    let pass: OfflineEnvelope = serde_json::from_slice(&raw)
        .map_err(|_| "beta pass is not a valid envelope".to_string())?;
    let body = base64_decode(&pass.decision_b64)?;
    let signature = hex_64(&pass.signature_hex)?;
    af_program::beta_access::authenticate_pass(issuer_key, &body, &signature, release, now)
        .map_err(|_| "beta pass is invalid (wrong release or tampered)".to_string())
}

fn offline_required(
    pass_file: &Path,
    pinned_issuer: Option<&str>,
    pinned_release: Option<&str>,
    now: u64,
) -> Result<Option<(af_program::beta_access::OfflinePass, [u8; 32])>, String> {
    let Some(issuer) = issuer_key(pinned_issuer)? else {
        return Ok(None);
    };
    if pinned_issuer.is_some() {
        let release = pinned_release
            .filter(|release| !release.is_empty())
            .ok_or("missing pinned beta release ID")?;
        return verify_pass_file(pass_file, &issuer, Some(release), now)
            .map(|pass| Some((pass, issuer)));
    }
    if pass_file.exists() {
        return verify_pass_file(pass_file, &issuer, None, now).map(|pass| Some((pass, issuer)));
    }
    Ok(None)
}

fn effective_time(home: &Path, now: u64, persist: bool) -> Result<u64, String> {
    let _lease = if persist {
        Some(af_entropy::FileLease::acquire(
            &home.join("beta-last-seen.lock"),
            true,
            "beta clock marker is busy",
        )?)
    } else {
        None
    };
    let marker = home.join(LAST_SEEN_FILE);
    let previous = match std::fs::File::open(&marker) {
        Ok(file) => {
            let mut value = String::new();
            file.take(21)
                .read_to_string(&mut value)
                .map_err(|e| format!("beta clock marker read failed: {e}"))?;
            value
                .parse::<u64>()
                .map_err(|_| "invalid beta clock marker")?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => return Err(format!("beta clock marker read failed: {error}")),
    };
    if previous.saturating_sub(now) > MAX_CLOCK_ROLLBACK_SECS {
        return Err("beta access refused: clock rollback detected".into());
    }
    if persist && now > previous {
        let temporary = home.join(format!("beta-last-seen-{}.tmp", af_entropy::token()));
        let save = (|| -> std::io::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            write!(file, "{now}")?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&temporary, &marker)
        })();
        if let Err(error) = save {
            let _ = std::fs::remove_file(temporary);
            return Err(format!("beta clock marker write failed: {error}"));
        }
    }
    Ok(now.max(previous))
}

fn development_service() -> Option<GateConfig> {
    issuer_key(None)
        .ok()
        .flatten()
        .and_then(GateConfig::from_env)
}

const ACTIVATION_FILE: &str = "beta-activated-at";
const CRL_CACHE_FILE: &str = "beta-crl-cache.json";
const CRL_FETCH_SECONDS: u64 = 3;

const PINNED_CRL_URL: Option<&str> = option_env!("AF_BETA_CRL_URL");

fn crl_url() -> Option<String> {
    if let Some(url) = PINNED_CRL_URL {
        return Some(url.to_string());
    }
    #[cfg(feature = "dev-gate")]
    match std::env::var("AF_BETA_CRL_URL") {
        Ok(url) => return Some(url),
        Err(std::env::VarError::NotPresent) => {}
        Err(std::env::VarError::NotUnicode(_)) => return None,
    }
    None
}

fn load_crl_cache(home: &Path) -> Option<(u64, Vec<String>)> {
    let raw = std::fs::read(home.join(CRL_CACHE_FILE)).ok()?;
    let value: Value = serde_json::from_slice(&raw).ok()?;
    let sequence = value.get("sequence")?.as_u64()?;
    let revoked = value
        .get("revoked")?
        .as_array()?
        .iter()
        .filter_map(|grant| grant.as_str().map(str::to_string))
        .collect();
    Some((sequence, revoked))
}

fn save_crl_cache(home: &Path, crl: &af_program::beta_access::CrlBody) -> Result<(), String> {
    let record = json!({"sequence": crl.sequence(), "revoked": crl.revoked()});
    let temporary = home.join(format!("beta-crl-{}.tmp", af_entropy::token()));
    let save = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(
            serde_json::to_vec(&record)
                .map_err(std::io::Error::other)?
                .as_slice(),
        )?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, home.join(CRL_CACHE_FILE))
    })();
    if let Err(error) = save {
        let _ = std::fs::remove_file(temporary);
        return Err(format!("beta CRL cache write failed: {error}"));
    }
    Ok(())
}

/// Revocation check (А-2): accept only strictly newer signed lists than the
/// cached one; unavailable network, an unparsable list or a stale sequence
/// fails OPEN to the cache — the same-privilege anchor never bricks the gate.
fn crl_check(home: &Path, issuer_key: &[u8; 32], grant_id: &str, now: u64) -> Result<(), String> {
    let cached = load_crl_cache(home);
    let best_sequence = cached.as_ref().map(|(sequence, _)| *sequence).unwrap_or(0);
    let mut best_revoked = cached.map(|(_, revoked)| revoked).unwrap_or_default();
    if let Some(url) = crl_url() {
        let fetched = ureq::get(&url)
            .timeout(std::time::Duration::from_secs(CRL_FETCH_SECONDS))
            .call();
        if let Ok(response) = fetched {
            let mut raw = Vec::new();
            if response
                .into_reader()
                .take(MAX_RESPONSE_BYTES as u64 + 1)
                .read_to_end(&mut raw)
                .is_ok()
                && raw.len() <= MAX_RESPONSE_BYTES
            {
                if let Ok(envelope) = serde_json::from_slice::<DecisionEnvelope>(&raw) {
                    if let (Ok(body), Ok(signature)) = (
                        base64_decode(&envelope.decision_b64),
                        hex_64(&envelope.signature_hex),
                    ) {
                        if let Ok(crl) = af_program::beta_access::authenticate_crl(
                            issuer_key, &body, &signature, now,
                        ) {
                            if crl.sequence() > best_sequence {
                                let _ = save_crl_cache(home, &crl);
                                best_revoked = crl.revoked().to_vec();
                            }
                        }
                    }
                }
            }
        }
    }
    if best_revoked.iter().any(|revoked| revoked == grant_id) {
        return Err(format!(
            "beta pass revoked (grant {grant_id}); export your evidence with `af evidence export` and report back"
        ));
    }
    Ok(())
}

/// The activation marker starts the signed window at the participant's first
/// gated operation. It is written exactly once while the signed
/// activate_by deadline is open; deleting it later cannot extend exposure
/// beyond the signed hard_expires_at ceiling.
fn activation_time(
    home: &Path,
    pass: &af_program::beta_access::OfflinePass,
    now: u64,
) -> Result<u64, String> {
    let _lease = Some(af_entropy::FileLease::acquire(
        &home.join("beta-activation.lock"),
        true,
        "beta activation is busy",
    )?);
    let marker = home.join(ACTIVATION_FILE);
    let previous = match std::fs::File::open(&marker) {
        Ok(file) => {
            let mut value = String::new();
            file.take(21)
                .read_to_string(&mut value)
                .map_err(|e| format!("beta activation marker read failed: {e}"))?;
            value
                .trim()
                .parse::<u64>()
                .map_err(|_| "invalid beta activation marker")?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => return Err(format!("beta activation marker read failed: {error}")),
    };
    if previous > 0 {
        return Ok(previous);
    }
    if now > pass.activate_by() {
        return Err("beta pass activation window closed; the pass was never activated".into());
    }
    let temporary = home.join(format!("beta-activate-{}.tmp", af_entropy::token()));
    let save = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        write!(file, "{now}")?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, &marker)
    })();
    if let Err(error) = save {
        let _ = std::fs::remove_file(temporary);
        return Err(format!("beta activation marker write failed: {error}"));
    }
    Ok(now)
}

/// Report the same offline admission decision used by product operations.
/// A status check never activates a pass and never persists the clock marker.
pub fn status_report(now: u64) -> String {
    let home = af_sandbox::user_dir();
    let pass_file = home.join(OFFLINE_PASS_FILE);
    match offline_required(&pass_file, PINNED_ISSUER, PINNED_RELEASE, now) {
        Ok(Some((pass, issuer))) => {
            let now = if PINNED_ISSUER.is_some() {
                match effective_time(&home, now, false) {
                    Ok(now) => now,
                    Err(message) => return format!("beta pass: REFUSED - {message}"),
                }
            } else {
                now
            };
            if let Err(message) = crl_check(&home, &issuer, pass.grant_id(), now) {
                return format!("beta pass: REFUSED - {message}");
            }
            if now < pass.not_before() {
                return "beta pass: REFUSED - the pass is not valid yet".into();
            }
            let marker = std::fs::File::open(home.join(ACTIVATION_FILE))
                .ok()
                .and_then(|file| {
                    let mut text = String::new();
                    file.take(21).read_to_string(&mut text).ok()?;
                    Some(text)
                })
                .and_then(|text| text.trim().parse::<u64>().ok());
            let Some(activated) = marker else {
                if now > pass.activate_by() {
                    return "beta pass: REFUSED - the activation window closed; the pass was never activated".into();
                }
                let left = pass.activate_by() - now;
                return format!(
                    "beta pass: READY, {}h {}m left to activate (grant {}, release {}); the 96h window starts at first product operation",
                    left / 3600,
                    (left % 3600) / 60,
                    pass.grant_id(),
                    pass.release_id()
                );
            };
            let expires = activated
                .saturating_add(af_program::beta_access::MAX_BETA_SECONDS)
                .min(pass.hard_expires_at());
            if now >= expires {
                return "beta pass: REFUSED - the pass window has closed".into();
            }
            let remaining = expires - now;
            return format!(
                "beta pass: ACTIVE, {}h {}m remaining (grant {}, release {})",
                remaining / 3600,
                (remaining % 3600) / 60,
                pass.grant_id(),
                pass.release_id()
            );
        }
        Err(message) => return format!("beta pass: REFUSED - {message}"),
        Ok(None) => {}
    }
    match development_service() {
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

pub fn require_current_access() -> Result<(), String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system time is before the Unix epoch")?
        .as_secs();
    gate_new_operation(now)
}

fn gate_new_operation(now: u64) -> Result<(), String> {
    let home = af_sandbox::user_dir();
    let pass_file = home.join(OFFLINE_PASS_FILE);
    if let Some((pass, issuer)) = offline_required(&pass_file, PINNED_ISSUER, PINNED_RELEASE, now)?
    {
        return enforce_offline_window(&home, &pass, issuer, PINNED_ISSUER.is_some(), now);
    }
    match development_service() {
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

/// The pinned offline admission: rollback-guarded clock, revocation check,
/// one-time activation, and the effective expiry
/// min(activation + MAX_BETA_SECONDS, hard_expires_at). `pinned` selects the
/// retirement behavior on expiry and whether the clock marker persists.
fn enforce_offline_window(
    home: &Path,
    pass: &af_program::beta_access::OfflinePass,
    issuer: [u8; 32],
    pinned: bool,
    now: u64,
) -> Result<(), String> {
    let now = if pinned {
        effective_time(home, now, true)?
    } else {
        now
    };
    crl_check(home, &issuer, pass.grant_id(), now)?;
    let activated = activation_time(home, pass, now)?;
    let expires = activated
        .saturating_add(af_program::beta_access::MAX_BETA_SECONDS)
        .min(pass.hard_expires_at());
    if now >= expires {
        let message = "beta access expired - the pass window has closed";
        if pinned {
            let _retirement = af_entropy::FileLease::acquire(
                &home.join("beta-retirement.lock"),
                true,
                "beta retirement is busy",
            )?;
            self_destruct(pass.grant_id(), now)?;
            return Err(format!(
                "{message}. See beta-final-report in the Atomic Flow state directory."
            ));
        }
        return Err(message.into());
    }
    Ok(())
}

fn self_destruct(grant_id: &str, now: u64) -> Result<Value, String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate own exe: {e}"))?;
    if !exe
        .try_exists()
        .map_err(|e| format!("cannot inspect own exe: {e}"))?
    {
        return Err("beta access expired; this binary path is already unavailable".into());
    }
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

    let mut report = json!({
        "schema": "atomic-flow/self-destruct/v1",
        "grant_id": grant_id,
        "at_unix": now,
        "evidence_note": evidence_note,
        "message": "Your beta window has expired. Project files and local journals remain in their original locations.",
        "binary_retired": false,
    });
    let report_path = preserve_dir.join("self-destruct-report.json");
    let write_report = |report: &Value| {
        let bytes = serde_json::to_vec_pretty(report).map_err(|e| e.to_string())?;
        std::fs::write(&report_path, bytes)
            .map_err(|e| format!("self-destruct report write failed: {e}"))
    };
    write_report(&report)?;

    let trash = exe.with_extension(format!("{}.af-beta-deleted", af_entropy::token()));
    std::fs::rename(&exe, &trash)
        .map_err(|e| format!("beta access expired; binary retirement failed: {e}"))?;
    schedule_delete_on_reboot(&trash);
    report["binary_retired"] = json!(true);
    write_report(&report)?;

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
fn schedule_delete_on_reboot(path: &Path) {
    let _ = std::fs::remove_file(path);
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_home() -> std::path::PathBuf {
        let home = std::env::temp_dir().join(format!("af-beta-gate-{}", af_entropy::token()));
        std::fs::create_dir_all(&home).unwrap();
        home
    }

    #[test]
    fn pinned_build_requires_a_pass_and_release() {
        let pass = std::env::temp_dir()
            .join(format!("af-missing-pass-{}", af_entropy::token()))
            .join(OFFLINE_PASS_FILE);
        let issuer = "42".repeat(32);
        assert_eq!(
            offline_required(&pass, Some(&issuer), Some("beta-rc2"), 100).unwrap_err(),
            "beta pass required: install beta-pass.json"
        );
        assert_eq!(
            offline_required(&pass, Some(&issuer), None, 100).unwrap_err(),
            "missing pinned beta release ID"
        );
        assert!(offline_required(&pass, Some(""), Some("beta-rc2"), 100).is_err());
    }

    #[test]
    fn clock_marker_persists_the_maximum_and_rejects_rollback() {
        let home = std::env::temp_dir().join(format!("af-beta-clock-{}", af_entropy::token()));
        assert_eq!(effective_time(&home, 1000, true).unwrap(), 1000);
        assert_eq!(effective_time(&home, 701, true).unwrap(), 1000);
        assert_eq!(
            effective_time(&home, 699, true).unwrap_err(),
            "beta access refused: clock rollback detected"
        );
        assert_eq!(effective_time(&home, 1200, true).unwrap(), 1200);
        assert_eq!(effective_time(&home, 1000, false).unwrap(), 1200);
        std::fs::write(home.join(LAST_SEEN_FILE), "corrupt").unwrap();
        assert!(effective_time(&home, 1300, true).is_err());
        std::fs::remove_file(home.join(LAST_SEEN_FILE)).unwrap();
        std::fs::remove_file(home.join("beta-last-seen.lock")).unwrap();
        std::fs::remove_dir(home).unwrap();
    }

    #[test]
    fn issuer_override_is_opt_in_and_cannot_replace_a_pin() {
        // Isolate process-wide environment changes from every other test.
        const CHILD: &str = "AF_TEST_BETA_ISSUER_CHILD";
        let pinned = "42".repeat(32);
        if std::env::var_os(CHILD).is_some() {
            assert_eq!(issuer_key(Some(&pinned)).unwrap(), Some([0x42; 32]));
            let dev = cfg!(feature = "dev-gate").then_some([0x19; 32]);
            assert_eq!(issuer_key(None).unwrap(), dev);
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "beta_gate::tests::issuer_override_is_opt_in_and_cannot_replace_a_pin",
            ])
            .env(CHILD, "1")
            .env("AF_BETA_ISSUER_PUBKEY", "19".repeat(32))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Independent copy of the frozen signing domain: if af-program ever
    /// changes it, this test breaks loudly instead of silently trusting.
    const TEST_DOMAIN: &[u8] = b"atomic-flow/beta-access/v1\0";

    fn mint_pass(home: &std::path::Path, grant: &str, not_before: u64, activate_by: u64) -> String {
        use ring::signature::KeyPair;
        let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
        let body = serde_json::to_vec(&json!({
            "schema_version": 2, "grant_id": grant, "release_id": "beta-rc1",
            "issued_at": not_before, "not_before": not_before,
            "activate_by": activate_by,
            "hard_expires_at": activate_by + af_program::beta_access::MAX_BETA_SECONDS,
        }))
        .unwrap();
        let signature = pair.sign(&[TEST_DOMAIN, &body].concat());
        let envelope = json!({
            "decision_b64": base64_encode(&body),
            "signature_hex": signature.as_ref().iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "grant_id": grant,
            "release_id": "beta-rc1",
        });
        std::fs::create_dir_all(home.join("sessions")).unwrap();
        std::fs::write(
            home.join(OFFLINE_PASS_FILE),
            serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap();
        pair.public_key()
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn base64_encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let group = chunk.iter().map(|b| *b as u32).collect::<Vec<_>>();
            let packed = (group[0] << 16)
                | (group.get(1).copied().unwrap_or(0) << 8)
                | group.get(2).copied().unwrap_or(0);
            out.push(ALPHABET[(packed >> 18) as usize & 63] as char);
            out.push(ALPHABET[(packed >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[(packed >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[packed as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    #[test]
    fn pass_v2_activates_on_first_operation_and_respects_the_ceiling() {
        let home = temp_home();
        let t0 = 1_000_000u64;
        let pinned = mint_pass(&home, "engineer-x", t0, t0 + 3600);
        let pass_file = home.join(OFFLINE_PASS_FILE);
        // First gated operation starts the window.
        let (pass, issuer) = offline_required(&pass_file, Some(&pinned), Some("beta-rc1"), t0)
            .unwrap()
            .unwrap();
        enforce_offline_window(&home, &pass, issuer, true, t0).unwrap();
        let marker: u64 = std::fs::read_to_string(home.join(ACTIVATION_FILE))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(marker, t0, "the window starts at the first operation");
        // Later operations reuse the recorded activation.
        let (pass, issuer) = offline_required(&pass_file, Some(&pinned), Some("beta-rc1"), t0 + 60)
            .unwrap()
            .unwrap();
        enforce_offline_window(&home, &pass, issuer, true, t0 + 60).unwrap();
        assert_eq!(
            std::fs::read_to_string(home.join(ACTIVATION_FILE))
                .unwrap()
                .trim()
                .parse::<u64>()
                .unwrap(),
            t0,
            "activation is written exactly once"
        );
        // The ceiling is activate_by + 96h, regardless of the marker.
        let ceiling = t0 + 3600 + af_program::beta_access::MAX_BETA_SECONDS;
        let (pass, issuer) =
            offline_required(&pass_file, Some(&pinned), Some("beta-rc1"), ceiling + 1)
                .unwrap()
                .unwrap();
        let error = enforce_offline_window(&home, &pass, issuer, false, ceiling + 1).unwrap_err();
        assert!(
            error.contains("window has closed"),
            "past the signed ceiling the gate refuses: {error}"
        );
    }

    #[test]
    fn late_activation_is_refused_once_the_signed_window_closes() {
        let home = temp_home();
        let t0 = 2_000_000u64;
        let pinned = mint_pass(&home, "engineer-late", t0, t0 + 3600);
        let pass_file = home.join(OFFLINE_PASS_FILE);
        let (pass, issuer) =
            offline_required(&pass_file, Some(&pinned), Some("beta-rc1"), t0 + 3600 + 1)
                .unwrap()
                .unwrap();
        let error = enforce_offline_window(&home, &pass, issuer, true, t0 + 3600 + 1).unwrap_err();
        assert!(
            error.contains("activation window closed"),
            "never-activated passes past activate_by are refused: {error}"
        );
        assert!(!home.join(ACTIVATION_FILE).exists());
    }

    #[test]
    fn crl_cache_accepts_only_newer_sequences_and_revokes_grants() {
        let home = temp_home();
        let t0 = 3_000_000u64;
        let pinned = mint_pass(&home, "engineer-good", t0, t0 + 3600);
        let pass_file = home.join(OFFLINE_PASS_FILE);
        let admit = |now: u64| {
            let (pass, issuer) = offline_required(&pass_file, Some(&pinned), Some("beta-rc1"), now)
                .unwrap()
                .unwrap();
            enforce_offline_window(&home, &pass, issuer, false, now)
        };
        // No cache, no fetch URL: the gate passes.
        admit(t0).unwrap();
        // A cache revoking this grant blocks continuation (no fetch is
        // configured, so the cache is the best knowledge).
        std::fs::write(
            home.join(CRL_CACHE_FILE),
            json!({"sequence": 3, "revoked": ["engineer-good"]}).to_string(),
        )
        .unwrap();
        let error = admit(t0 + 60).unwrap_err();
        assert!(
            error.contains("beta pass revoked"),
            "the cached revocation list blocks the grant: {error}"
        );
        // A newer list without the revocation unblocks: strictly newer
        // sequences replace the cached set.
        std::fs::write(
            home.join(CRL_CACHE_FILE),
            json!({"sequence": 4, "revoked": ["engineer-other"]}).to_string(),
        )
        .unwrap();
        admit(t0 + 120).unwrap();
        // A corrupt cache is ignored (fail-open to no knowledge).
        std::fs::write(home.join(CRL_CACHE_FILE), "corrupt").unwrap();
        admit(t0 + 180).unwrap();
    }
}
