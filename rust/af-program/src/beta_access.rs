//! Verifies a signed, online beta access decision. The caller pins the issuer
//! key and supplies a fresh challenge for every decision it uses.

use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::Deserialize;

pub const MAX_BETA_SECONDS: u64 = 96 * 60 * 60;
const MAX_RESPONSE_BYTES: usize = 2048;
const MAX_DECISION_AGE_SECONDS: u64 = 30;
const SIGNING_DOMAIN: &[u8] = b"atomic-flow/beta-access/v1\0";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessDecision {
    schema_version: u32,
    grant_id: String,
    release_id: String,
    challenge: String,
    active: bool,
    activated_at: u64,
    expires_at: u64,
    checked_at: u64,
}

impl AccessDecision {
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    pub fn release_id(&self) -> &str {
        &self.release_id
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AccessError {
    #[error("invalid beta access decision")]
    Invalid,
    #[error("beta access is inactive or expired")]
    Inactive,
}

fn identifier(value: &str) -> bool {
    (1..=96).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// A random challenge is sent to the issuer and consumed by one verification.
pub struct Challenge([u8; 32]);

impl Challenge {
    pub fn generate() -> Result<Self, AccessError> {
        let mut bytes = [0; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| AccessError::Invalid)?;
        Ok(Self(bytes))
    }

    pub fn wire_value(&self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

/// Authenticate an offline pass and validate its signed activation window.
/// An authenticated pass may have expired. The caller must check expires_at
/// against its effective clock before authorizing any operation.
pub fn authenticate_offline_pass(
    issuer_key: &[u8; 32],
    body: &[u8],
    signature: &[u8; 64],
    expected_release: Option<&str>,
    now: u64,
) -> Result<AccessDecision, AccessError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(AccessError::Invalid);
    }
    let message = [SIGNING_DOMAIN, body].concat();
    UnparsedPublicKey::new(&ED25519, issuer_key)
        .verify(message.as_slice(), signature.as_slice())
        .map_err(|_| AccessError::Invalid)?;
    let decision: AccessDecision =
        serde_json::from_slice(body).map_err(|_| AccessError::Invalid)?;
    if decision.schema_version != 1
        || !identifier(&decision.grant_id)
        || !identifier(&decision.release_id)
        || expected_release.is_some_and(|release| decision.release_id != release)
        || now < decision.activated_at
        || decision.activated_at > decision.checked_at
        || !(1..=MAX_BETA_SECONDS)
            .contains(&decision.expires_at.saturating_sub(decision.activated_at))
    {
        return Err(AccessError::Invalid);
    }
    if !decision.active {
        return Err(AccessError::Inactive);
    }
    Ok(decision)
}

/// Offline pass schema v2 (А-1): the signed body carries the activation
/// window and the cryptographic exposure ceiling instead of a pre-computed
/// expiry. The window starts at the participant's FIRST gated operation
/// (a local marker written by the gate) and is bounded by hard_expires_at.
pub const PASS_SCHEMA_VERSION: u32 = 2;
/// The pass must be activated within this window after issuance.
pub const MAX_ACTIVATION_WINDOW_SECONDS: u64 = 7 * 24 * 60 * 60;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflinePass {
    schema_version: u32,
    grant_id: String,
    release_id: String,
    issued_at: u64,
    not_before: u64,
    activate_by: u64,
    hard_expires_at: u64,
}

impl OfflinePass {
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    pub fn release_id(&self) -> &str {
        &self.release_id
    }

    pub fn not_before(&self) -> u64 {
        self.not_before
    }

    pub fn activate_by(&self) -> u64 {
        self.activate_by
    }

    pub fn hard_expires_at(&self) -> u64 {
        self.hard_expires_at
    }
}

/// Authenticate a schema-2 offline pass. Authentication proves the issuer
/// signed these window terms; it does NOT prove the pass is unexpired — the
/// caller derives the effective expiry from its local activation marker:
/// min(marker + MAX_BETA_SECONDS, hard_expires_at).
pub fn authenticate_pass(
    issuer_key: &[u8; 32],
    body: &[u8],
    signature: &[u8; 64],
    expected_release: Option<&str>,
    now: u64,
) -> Result<OfflinePass, AccessError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(AccessError::Invalid);
    }
    let message = [SIGNING_DOMAIN, body].concat();
    UnparsedPublicKey::new(&ED25519, issuer_key)
        .verify(message.as_slice(), signature.as_slice())
        .map_err(|_| AccessError::Invalid)?;
    let pass: OfflinePass = serde_json::from_slice(body).map_err(|_| AccessError::Invalid)?;
    if pass.schema_version != PASS_SCHEMA_VERSION
        || !identifier(&pass.grant_id)
        || !identifier(&pass.release_id)
        || expected_release.is_some_and(|release| pass.release_id != release)
        || pass.not_before > pass.issued_at
        || pass.issued_at > pass.activate_by
        || !(1..=MAX_ACTIVATION_WINDOW_SECONDS)
            .contains(&pass.activate_by.saturating_sub(pass.issued_at))
        || pass.hard_expires_at != pass.activate_by.saturating_add(MAX_BETA_SECONDS)
    {
        return Err(AccessError::Invalid);
    }
    if now < pass.not_before {
        return Err(AccessError::Invalid);
    }
    Ok(pass)
}

/// Certificate revocation list for offline passes (А-2): a signed, static,
/// monotonically-numbered artifact. The gate accepts only sequences beyond
/// its cache and fails open to the cache when the network is unavailable.
pub const CRL_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrlBody {
    schema_version: u32,
    sequence: u64,
    issued_at: u64,
    revoked: Vec<String>,
}

impl CrlBody {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn revoked(&self) -> &[String] {
        &self.revoked
    }

    pub fn revokes(&self, grant_id: &str) -> bool {
        self.revoked.iter().any(|revoked| revoked == grant_id)
    }
}

/// Authenticate a signed CRL body. Recency and monotonic ordering are the
/// caller's policy (cache comparison); here only issuer identity and shape
/// are proven.
pub fn authenticate_crl(
    issuer_key: &[u8; 32],
    body: &[u8],
    signature: &[u8; 64],
    now: u64,
) -> Result<CrlBody, AccessError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(AccessError::Invalid);
    }
    let message = [SIGNING_DOMAIN, body].concat();
    UnparsedPublicKey::new(&ED25519, issuer_key)
        .verify(message.as_slice(), signature.as_slice())
        .map_err(|_| AccessError::Invalid)?;
    let crl: CrlBody = serde_json::from_slice(body).map_err(|_| AccessError::Invalid)?;
    if crl.schema_version != CRL_SCHEMA_VERSION
        || crl.sequence == 0
        || crl.issued_at > now
        || crl.revoked.iter().any(|grant| !identifier(grant))
    {
        return Err(AccessError::Invalid);
    }
    Ok(crl)
}

pub fn verify_access(
    issuer_key: &[u8; 32],
    body: &[u8],
    signature: &[u8; 64],
    expected_grant: &str,
    expected_release: &str,
    challenge: Challenge,
    now: u64,
) -> Result<AccessDecision, AccessError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(AccessError::Invalid);
    }
    let message = [SIGNING_DOMAIN, body].concat();
    UnparsedPublicKey::new(&ED25519, issuer_key)
        .verify(&message, signature)
        .map_err(|_| AccessError::Invalid)?;
    let decision: AccessDecision =
        serde_json::from_slice(body).map_err(|_| AccessError::Invalid)?;
    if decision.schema_version != 1
        || !identifier(&decision.grant_id)
        || !identifier(&decision.release_id)
        || decision.grant_id != expected_grant
        || decision.release_id != expected_release
        || decision.challenge != challenge.wire_value()
        || decision.activated_at > decision.checked_at
        || !(1..=MAX_BETA_SECONDS)
            .contains(&decision.expires_at.saturating_sub(decision.activated_at))
        || decision.checked_at > now
        || now - decision.checked_at > MAX_DECISION_AGE_SECONDS
    {
        return Err(AccessError::Invalid);
    }
    if !decision.active || now >= decision.expires_at {
        return Err(AccessError::Inactive);
    }
    Ok(decision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::json;

    #[test]
    fn access_requires_exact_current_signed_decision() {
        let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let verify = |body: &[u8], release, challenge, now| {
            let signature = key.sign(&[SIGNING_DOMAIN, body].concat());
            verify_access(
                key.public_key().as_ref().try_into().unwrap(),
                body,
                signature.as_ref().try_into().unwrap(),
                "engineer-1",
                release,
                Challenge(challenge),
                now,
            )
        };
        let mut body = json!({
            "schema_version": 1, "grant_id": "engineer-1", "release_id": "beta-rc1",
            "challenge": "ab".repeat(32), "active": true,
            "activated_at": 100, "checked_at": 110, "expires_at": 120,
        });
        let bytes = |body: &serde_json::Value| serde_json::to_vec(body).unwrap();
        let challenge = [0xab; 32];
        let call = |body: &[u8], now| verify(body, "beta-rc1", challenge, now);
        assert_eq!(call(&bytes(&body), 119).unwrap().expires_at(), 120);
        assert_eq!(call(&bytes(&body), 120).unwrap_err(), AccessError::Inactive);
        assert_eq!(call(&bytes(&body), 109).unwrap_err(), AccessError::Invalid);
        assert_eq!(call(&bytes(&body), 141).unwrap_err(), AccessError::Invalid);
        assert!(verify(&bytes(&body), "beta-rc2", challenge, 110).is_err());
        assert!(verify(&bytes(&body), "beta-rc1", [0; 32], 110).is_err());
        assert!(verify_access(
            key.public_key().as_ref().try_into().unwrap(),
            &bytes(&body),
            &[0; 64],
            "engineer-1",
            "beta-rc1",
            Challenge(challenge),
            110,
        )
        .is_err());
        body["active"] = json!(false);
        assert_eq!(call(&bytes(&body), 110).unwrap_err(), AccessError::Inactive);
        body["expires_at"] = json!(101 + MAX_BETA_SECONDS);
        assert_eq!(call(&bytes(&body), 110).unwrap_err(), AccessError::Invalid);
    }

    #[test]
    fn offline_pass_uses_signed_grant_and_the_build_release() {
        let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let body = serde_json::to_vec(&json!({
            "schema_version": 1, "grant_id": "engineer-1", "release_id": "beta-rc1",
            "challenge": "ab".repeat(32), "active": true,
            "activated_at": 100, "checked_at": 100, "expires_at": 120,
        }))
        .unwrap();
        let signature = key.sign(&[SIGNING_DOMAIN, &body].concat());
        let verify = |release, now| {
            authenticate_offline_pass(
                key.public_key().as_ref().try_into().unwrap(),
                &body,
                signature.as_ref().try_into().unwrap(),
                Some(release),
                now,
            )
        };
        assert_eq!(verify("beta-rc1", 100).unwrap().grant_id(), "engineer-1");
        assert_eq!(verify("beta-rc2", 100).unwrap_err(), AccessError::Invalid);
        assert_eq!(verify("beta-rc1", 99).unwrap_err(), AccessError::Invalid);
        assert_eq!(verify("beta-rc1", 120).unwrap().expires_at(), 120);
    }

    #[test]
    fn pass_v2_authenticates_window_terms_and_pins_the_release() {
        let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let signed = |body: &serde_json::Value| {
            let bytes = serde_json::to_vec(body).unwrap();
            let signature = key.sign(&[SIGNING_DOMAIN, &bytes].concat());
            (bytes, signature)
        };
        let verify = |body: &[u8], signature: &[u8], now: u64| {
            authenticate_pass(
                key.public_key().as_ref().try_into().unwrap(),
                body,
                signature.try_into().unwrap(),
                Some("beta-rc1"),
                now,
            )
        };
        let body = json!({
            "schema_version": PASS_SCHEMA_VERSION, "grant_id": "engineer-1",
            "release_id": "beta-rc1",
            "issued_at": 100, "not_before": 100,
            "activate_by": 100 + MAX_ACTIVATION_WINDOW_SECONDS,
            "hard_expires_at": 100 + MAX_ACTIVATION_WINDOW_SECONDS + MAX_BETA_SECONDS,
        });
        let (bytes, signature) = signed(&body);
        let pass = verify(&bytes, signature.as_ref(), 100).unwrap();
        assert_eq!(pass.grant_id(), "engineer-1");
        assert_eq!(
            pass.hard_expires_at(),
            100 + MAX_ACTIVATION_WINDOW_SECONDS + MAX_BETA_SECONDS
        );
        // An authenticated pass never carries a pre-computed expiry verdict:
        // "expired" is the caller's policy over the local activation marker.
        assert!(verify(&bytes, signature.as_ref(), u64::MAX / 2).is_ok());

        let mut drifted = body.clone();
        drifted["release_id"] = json!("beta-rc2");
        let (drifted_bytes, drifted_sig) = signed(&drifted);
        assert!(verify(&drifted_bytes, drifted_sig.as_ref(), 100).is_err());

        let mut early = body.clone();
        early["not_before"] = json!(99);
        let (early_bytes, early_sig) = signed(&early);
        assert!(verify(&early_bytes, early_sig.as_ref(), 99).is_ok());
        assert_eq!(
            verify(&early_bytes, early_sig.as_ref(), 98).unwrap_err(),
            AccessError::Invalid
        );
        assert!(verify(&early_bytes, early_sig.as_ref(), 100).is_ok());

        let mut long_window = body.clone();
        long_window["activate_by"] = json!(100 + MAX_ACTIVATION_WINDOW_SECONDS + 1);
        long_window["hard_expires_at"] =
            json!(100 + MAX_ACTIVATION_WINDOW_SECONDS + 1 + MAX_BETA_SECONDS);
        let (window_bytes, window_sig) = signed(&long_window);
        assert!(verify(&window_bytes, window_sig.as_ref(), 100).is_err());

        let mut loose_ceiling = body.clone();
        loose_ceiling["hard_expires_at"] =
            json!(100 + MAX_ACTIVATION_WINDOW_SECONDS + MAX_BETA_SECONDS + 1);
        let (ceiling_bytes, ceiling_sig) = signed(&loose_ceiling);
        assert!(verify(&ceiling_bytes, ceiling_sig.as_ref(), 100).is_err());

        let mut future = body.clone();
        future["issued_at"] = json!(500);
        future["not_before"] = json!(500);
        future["activate_by"] = json!(500 + MAX_ACTIVATION_WINDOW_SECONDS);
        future["hard_expires_at"] = json!(500 + MAX_ACTIVATION_WINDOW_SECONDS + MAX_BETA_SECONDS);
        let (future_bytes, future_sig) = signed(&future);
        assert_eq!(
            verify(&future_bytes, future_sig.as_ref(), 400).unwrap_err(),
            AccessError::Invalid
        );

        let (v1_bytes, _) = signed(&json!({
            "schema_version": 1, "grant_id": "engineer-1", "release_id": "beta-rc1",
            "challenge": "ab".repeat(32), "active": true,
            "activated_at": 100, "checked_at": 100, "expires_at": 120,
        }));
        assert!(verify(&v1_bytes, &[0; 64], 100).is_err());
    }

    #[test]
    fn crl_authenticates_signed_revocation_lists() {
        let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let signed = |body: &serde_json::Value| {
            let bytes = serde_json::to_vec(body).unwrap();
            let signature = key.sign(&[SIGNING_DOMAIN, &bytes].concat());
            (bytes, signature)
        };
        let verify = |body: &[u8], signature: &[u8], now: u64| {
            authenticate_crl(
                key.public_key().as_ref().try_into().unwrap(),
                body,
                signature.try_into().unwrap(),
                now,
            )
        };
        let body = json!({
            "schema_version": CRL_SCHEMA_VERSION, "sequence": 4, "issued_at": 200,
            "revoked": ["engineer-9", "engineer-3"],
        });
        let (bytes, signature) = signed(&body);
        let crl = verify(&bytes, signature.as_ref(), 300).unwrap();
        assert_eq!(crl.sequence(), 4);
        assert!(crl.revokes("engineer-3"));
        assert!(!crl.revokes("engineer-1"));

        let mut tampered = body.clone();
        tampered["sequence"] = json!(5);
        let (tampered_bytes, _) = signed(&tampered);
        assert!(verify(&tampered_bytes, signature.as_ref(), 300).is_err());

        let mut stale = body.clone();
        stale["issued_at"] = json!(400);
        let (stale_bytes, stale_sig) = signed(&stale);
        assert!(verify(&stale_bytes, stale_sig.as_ref(), 300).is_err());

        let mut zero = body.clone();
        zero["sequence"] = json!(0);
        let (zero_bytes, zero_sig) = signed(&zero);
        assert!(verify(&zero_bytes, zero_sig.as_ref(), 300).is_err());

        let mut malformed = body.clone();
        malformed["revoked"] = json!(["bad id!"]);
        let (malformed_bytes, malformed_sig) = signed(&malformed);
        assert!(verify(&malformed_bytes, malformed_sig.as_ref(), 300).is_err());

        let (empty_bytes, empty_sig) = signed(&json!({
            "schema_version": CRL_SCHEMA_VERSION, "sequence": 5, "issued_at": 200,
            "revoked": [],
        }));
        let empty = verify(&empty_bytes, empty_sig.as_ref(), 300).unwrap();
        assert!(!empty.revokes("engineer-9"));
    }

    fn hex_bytes(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn frozen_issuance_vector_verifies_cross_language() {
        // The issuance service (tools/issuance_server.py, openssl-backed)
        // produced this vector: the domain-separated decision bytes it signs
        // must satisfy the ring verifier byte-for-byte, and any tampering
        // with the body must invalidate it (B1 cross-language contract).
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/beta-access-v1.json")).unwrap();
        let seed: [u8; 32] = hex_bytes(vector["seed_hex"].as_str().unwrap())
            .try_into()
            .unwrap();
        let signature: [u8; 64] = hex_bytes(vector["signature_hex"].as_str().unwrap())
            .try_into()
            .unwrap();
        let body = vector["body"].as_str().unwrap().as_bytes().to_vec();
        let expected = &vector["expected"];
        let challenge: [u8; 32] = hex_bytes(expected["challenge"].as_str().unwrap())
            .try_into()
            .unwrap();
        // Decisive experiment: does ring, from the same seed, produce the
        // same deterministic ed25519 signature as openssl did?
        let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let ring_sig = pair.sign(&[SIGNING_DOMAIN, body.as_slice()].concat());
        // Cross-implementation determinism: ring, from the same seed, must
        // reproduce byte-for-byte the signature the openssl issuer minted.
        assert_eq!(ring_sig.as_ref(), signature.as_slice());
        // The verifier pins the ISSUER PUBLIC KEY (never the seed) —
        // exactly what the official beta build embeds.
        let issuer_key: [u8; 32] = hex_bytes(vector["pub_hex"].as_str().unwrap())
            .try_into()
            .unwrap();
        let decision = verify_access(
            &issuer_key,
            &body,
            &signature,
            expected["grant_id"].as_str().unwrap(),
            expected["release_id"].as_str().unwrap(),
            Challenge(challenge),
            expected["now"].as_u64().unwrap(),
        )
        .unwrap();
        assert_eq!(decision.expires_at(), 100 + MAX_BETA_SECONDS - 1);
        let mut tampered = body.clone();
        let pos = body
            .windows(6)
            .position(|window| window == b"active")
            .unwrap();
        tampered[pos] ^= 1;
        assert!(verify_access(
            &issuer_key,
            &tampered,
            &signature,
            expected["grant_id"].as_str().unwrap(),
            expected["release_id"].as_str().unwrap(),
            Challenge(challenge),
            expected["now"].as_u64().unwrap(),
        )
        .is_err());
    }
}
