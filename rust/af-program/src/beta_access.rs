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
