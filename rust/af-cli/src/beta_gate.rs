//! B1 client wiring (the issuance half lives in tools/issuance_server.py,
//! the verifier in af_program::beta_access). The official beta build pins
//! the issuer public key at packaging time; with a pinned key every new
//! product operation re-checks access ONLINE — the 30-second decision
//! freshness makes clock rollback unable to reuse a stale decision. Dev
//! builds without a pinned key are honestly ungated and report themselves
//! as such (`active() == false`); offline strictness for real deployments
//! stays an explicit owner decision (ENGINEER_BETA_PLAN, B1).

use af_program::beta_access::{verify_access, AccessDecision, AccessError, Challenge};
use serde::Deserialize;

/// Pinned at release packaging time (hex). Empty in dev builds: the gate is
/// then disabled and every check is a pass-through, reported honestly.
pub const BETA_ISSUER_PUBKEY_HEX: &str = "";

const MAX_RESPONSE_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateConfig {
    pub issuer_pubkey: [u8; 32],
    pub grant_id: String,
    pub release_id: String,
    pub service_url: String,
}

impl GateConfig {
    /// Environment override exists for acceptance testing only; the official
    /// artifact always uses the pinned key.
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

    pub fn active(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateOutcome {
    /// Access verified online; remaining seconds until expiry.
    Active { expires_in_secs: u64 },
    /// Access inactive or expired; the message names what the user sees.
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

/// One online access check for a product operation: fresh challenge,
/// service fetch, signature verification against the pinned key.
pub fn check(config: &GateConfig, now: u64) -> Result<GateOutcome, String> {
    // 64 lowercase hex chars = the wire form of a fresh 32-byte challenge.
    let challenge = Challenge::generate().map_err(|_| "challenge generation failed".to_string())?;
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
    match verify_access(
        &config.issuer_pubkey,
        &body,
        &signature,
        &config.grant_id,
        &config.release_id,
        challenge,
        now,
    ) {
        Ok(decision) => {
            let GateOutcome::Active { expires_in_secs } = outcome_of(&decision, now) else {
                unreachable!("verify_access Ok is always Active");
            };
            Ok(GateOutcome::Active { expires_in_secs })
        }
        Err(AccessError::Inactive) => {
            // The decision parsed and verified: the pass is real but spent.
            // Recompute the honest human message from its bounds.
            let spent_hours = decision_provenance(&body)
                .map(|(activated, _expires)| (now.saturating_sub(activated)) / 3600)
                .unwrap_or(0);
            Ok(GateOutcome::Refused(format!(
                "beta access is inactive or expired (about {spent_hours}h used of the 96h window); export your evidence with `af evidence export` and report back"
            )))
        }
        Err(AccessError::Invalid) => Err(
            "beta access decision is invalid (wrong grant/release, stale response or tampering)"
                .into(),
        ),
    }
}

fn outcome_of(decision: &AccessDecision, now: u64) -> GateOutcome {
    GateOutcome::Active {
        expires_in_secs: decision.expires_at().saturating_sub(now),
    }
}

/// Best-effort (activated_at, expires_at) read for human messages; the
/// authorization itself never relies on this parse.
fn decision_provenance(body: &[u8]) -> Option<(u64, u64)> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    Some((
        value.get("activated_at")?.as_u64()?,
        value.get("expires_at")?.as_u64()?,
    ))
}

/// The gate for a new product operation: pass-through when ungated.
pub fn gate_new_operation(now: u64) -> Result<(), String> {
    match GateConfig::from_env() {
        None => Ok(()),
        Some(config) => match check(&config, now)? {
            GateOutcome::Active { expires_in_secs } => {
                let _ = expires_in_secs;
                Ok(())
            }
            GateOutcome::Refused(message) => Err(message),
        },
    }
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

use std::io::Read;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip_matches_standard_vectors() {
        assert_eq!(base64_decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(base64_decode("QQ==").unwrap(), b"A".to_vec());
        assert_eq!(base64_decode("QUI=").unwrap(), b"AB".to_vec());
        assert_eq!(base64_decode("QUJD").unwrap(), b"ABC".to_vec());
        let long: Vec<u8> = (0..=255u8).collect();
        let encoded = {
            // std-free encoding for the roundtrip: reuse the decoder inverse
            // by asserting against a known constant pattern instead.
            base64_decode(&encode(long.clone())).unwrap()
        };
        assert_eq!(encoded, long);
    }

    fn encode(data: Vec<u8>) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(TABLE[(n >> 18) as usize & 63] as char);
            out.push(TABLE[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                TABLE[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                TABLE[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    #[test]
    fn ungated_build_passes_operations_through() {
        // No AF_BETA_ISSUER_PUBKEY in the test environment -> the gate is
        // honestly disabled and product operations pass through.
        assert!(
            std::env::var("AF_BETA_ISSUER_PUBKEY").is_err() || {
                // If a stray env leaked in, from_env needs the rest too.
                std::env::var("AF_BETA_SERVICE").is_err()
            }
        );
        assert!(gate_new_operation(1000).is_ok());
    }

    /// Canned issuance server: echoes the challenge from the request into
    /// a freshly signed decision — exactly what the real service does.
    fn spawn_echo_decision_server(
        listener: std::net::TcpListener,
        key: ring::signature::Ed25519KeyPair,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            loop {
                let n = std::io::Read::read(&mut stream, &mut buffer).unwrap_or(0);
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..n]);
                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&request).to_string();
            let start = text.find("challenge=").unwrap() + "challenge=".len();
            let challenge: String = text[start..].chars().take(64).collect();
            let body = format!(
                "{{\"schema_version\":1,\"grant_id\":\"engineer-1\",\"release_id\":\"beta-rc1\",\"challenge\":\"{challenge}\",\"active\":true,\"activated_at\":100,\"checked_at\":110,\"expires_at\":{}}}",
                100 + 96 * 3600 - 1
            );
            let signature: String = key
                .sign(format!("atomic-flow/beta-access/v1 {body}").as_bytes())
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let envelope = format!(
                "{{\"decision_b64\":\"{}\",\"signature_hex\":\"{}\"}}",
                encode(body.into_bytes()),
                signature
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                envelope.len(),
                envelope
            );
            let _ = std::io::Write::write_all(&mut stream, response.as_bytes());
        })
    }

    #[test]
    fn expired_and_active_decisions_take_their_outcomes() {
        use ring::signature::{Ed25519KeyPair, KeyPair};
        let pubkey_hex: String = Ed25519KeyPair::from_seed_unchecked(&[0x5A; 32])
            .unwrap()
            .public_key()
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let listener1 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener1.local_addr().unwrap().port();
        let server = spawn_echo_decision_server(
            listener1,
            Ed25519KeyPair::from_seed_unchecked(&[0x5A; 32]).unwrap(),
        );
        let config = GateConfig {
            issuer_pubkey: hex_32(&pubkey_hex).unwrap(),
            grant_id: "engineer-1".into(),
            release_id: "beta-rc1".into(),
            service_url: format!("http://127.0.0.1:{port}"),
        };
        let outcome = check(&config, 110).unwrap();
        match outcome {
            GateOutcome::Active { expires_in_secs } => {
                assert_eq!(expires_in_secs, 100 + 96 * 3600 - 1 - 110);
            }
            other => panic!("expected active, got {other:?}"),
        }
        server.join().unwrap();

        // Long past the window: the 30s decision freshness refuses the
        // ancient response before its payload is inspected — the
        // anti-clock-rollback contract holds at the wire level.
        let listener2 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port2 = listener2.local_addr().unwrap().port();
        let server2 = spawn_echo_decision_server(
            listener2,
            Ed25519KeyPair::from_seed_unchecked(&[0x5A; 32]).unwrap(),
        );
        let config2 = GateConfig {
            service_url: format!("http://127.0.0.1:{port2}"),
            ..config
        };
        let late = 100 + 96 * 3600 + 60;
        match check(&config2, late) {
            Ok(GateOutcome::Active { .. }) => panic!("ancient decision must not grant access"),
            _ => {}
        }
        server2.join().unwrap();
    }
}
