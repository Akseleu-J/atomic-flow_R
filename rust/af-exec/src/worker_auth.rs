//! Worker authentication for remote microVM workers (the S0 remainder).
//! Transport-independent: both sides verify signatures over canonical
//! payload bytes with pinned ed25519 keys, so any carrier (HTTP, ssh, pipe)
//! inherits the same guarantees. An unverified worker is unavailable for
//! tasks; a wrong project, a stale envelope or a bad signature refuse
//! before any launch. The durable admission journal (worker.rs) stays the
//! single lifecycle authority — this layer only gates who may talk to it.
//!
//! Enrollment contract: the controller pins each worker (id, ed25519 public
//! key, allowed project ids, validity window). The worker pins the
//! controller's public key. Both directions sign with the same domain
//! prefix, so a request can never be replayed as an acknowledgement.

use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const AUTH_DOMAIN: &[u8] = b"atomic-flow/worker-auth/v1\0";
pub const MAX_ENVELOPE_TTL_SECS: u64 = 30;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct AuthError(pub String);
type Result<T> = std::result::Result<T, AuthError>;

/// The controller's pinned view of one worker (S0: enrollment).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerEnrollment {
    pub worker_id: String,
    /// Raw 32-byte ed25519 public key of the worker.
    pub worker_pubkey: Vec<u8>,
    /// Project ids this worker may receive; anything else refuses pre-launch.
    pub allowed_project_ids: Vec<String>,
    pub valid_from: u64,
    pub valid_until: u64,
}

impl WorkerEnrollment {
    fn validate(&self) -> Result<()> {
        require(
            identifier(&self.worker_id)
                && self.worker_pubkey.len() == 32
                && !self.allowed_project_ids.is_empty()
                && self.allowed_project_ids.len() <= 16
                && self.allowed_project_ids.iter().all(|p| identifier(p))
                && self.valid_from < self.valid_until,
            "invalid worker enrollment",
        )
    }
    fn covers(&self, project_id: &str, now: u64) -> bool {
        self.allowed_project_ids.iter().any(|p| p == project_id)
            && self.valid_from <= now
            && now < self.valid_until
    }
}

/// What the worker verifies: the controller's signed job offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobOffer {
    pub spec: crate::worker::JobSpec,
    pub issued_at: u64,
}

/// Controller → worker: signed job offer envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedJobOffer {
    pub offer: JobOffer,
    /// Ed25519 signature over AUTH_DOMAIN ++ canonical(offer) by the pinned
    /// controller key.
    pub controller_signature: String,
}

/// Worker → controller: the signed acknowledgement payload (no signature
/// field — canonical bytes of exactly this struct are what gets signed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerAckPayload {
    pub worker_id: String,
    pub operation_id: String,
    /// The durable lifecycle state this ack certifies (e.g. "running",
    /// "finished:<receipt_sha256>", "cleanup_confirmed").
    pub state: String,
    pub issued_at: u64,
    pub worker_signature: String,
}

fn require(ok: bool, why: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(AuthError(why.into()))
    }
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
}

fn canonical(payload: &impl Serialize) -> Result<Vec<u8>> {
    // Struct-field order is deterministic in serde_json; no maps anywhere.
    serde_json::to_vec(payload).map_err(|_| AuthError("canonical encoding failed".into()))
}

fn ed25519_verify(key: &[u8], message: &[u8], signature: &str) -> bool {
    let Ok(sig) = hex_64(signature) else {
        return false;
    };
    UnparsedPublicKey::new(&ED25519, key)
        .verify(message, &sig)
        .is_ok()
}

fn hex_64(value: &str) -> std::result::Result<[u8; 64], ()> {
    if value.len() != 128 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(());
    }
    let mut out = [0u8; 64];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
    }
    Ok(out)
}

/// Worker → controller: signed acknowledgement envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedWorkerAck {
    pub ack: WorkerAckPayload,
    pub worker_signature: String,
}

/// Controller side: produce the bytes to sign for one job offer.
pub fn sign_job_offer_payload(offer: &JobOffer) -> Result<Vec<u8>> {
    let mut message = AUTH_DOMAIN.to_vec();
    message.extend_from_slice(&canonical(offer)?);
    Ok(message)
}

/// Worker side: verify an incoming signed job offer against the pinned
/// controller key and this worker's enrollment. Every refusal happens
/// before any launch (S0).
pub fn worker_verify_job_offer<'a>(
    enrollment: &'a WorkerEnrollment,
    controller_pubkey: &[u8],
    offer: &'a SignedJobOffer,
    now: u64,
) -> Result<&'a crate::worker::JobSpec> {
    require(offer.offer.issued_at <= now, "offer from the future")?;
    require(
        now - offer.offer.issued_at <= MAX_ENVELOPE_TTL_SECS,
        "stale job offer",
    )?;
    let mut message = AUTH_DOMAIN.to_vec();
    message.extend_from_slice(&canonical(&offer.offer)?);
    require(
        ed25519_verify(controller_pubkey, &message, &offer.controller_signature),
        "controller signature rejected",
    )?;
    enrollment.validate()?;
    require(
        enrollment.covers(&offer.offer.spec.project_id, now),
        "project outside this worker's scope or enrollment expired",
    )?;
    Ok(&offer.offer.spec)
}

/// Worker side: mint the signed ack for one lifecycle state.
pub fn worker_sign_ack(
    worker_id: &str,
    operation_id: &str,
    state: &str,
    issued_at: u64,
    key: &ring::signature::Ed25519KeyPair,
) -> Result<SignedWorkerAck> {
    require(
        identifier(worker_id) && identifier(operation_id),
        "invalid ack ids",
    )?;
    require(
        !state.is_empty() && state.len() <= 256 && !state.contains('\n'),
        "invalid ack state",
    )?;
    let payload = WorkerAckPayload {
        worker_id: worker_id.to_string(),
        operation_id: operation_id.to_string(),
        state: state.to_string(),
        issued_at,
        worker_signature: String::new(),
    };
    let mut message = AUTH_DOMAIN.to_vec();
    message.extend_from_slice(&canonical(&payload)?);
    let signature = key.sign(&message);
    Ok(SignedWorkerAck {
        ack: payload,
        worker_signature: signature
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    })
}

/// Controller side: verify a worker ack against the pinned worker key.
pub fn controller_verify_ack(worker_pubkey: &[u8], ack: &SignedWorkerAck, now: u64) -> Result<()> {
    require(ack.ack.issued_at <= now, "ack from the future")?;
    require(
        now - ack.ack.issued_at <= MAX_ENVELOPE_TTL_SECS,
        "stale ack",
    )?;
    let mut message = AUTH_DOMAIN.to_vec();
    message.extend_from_slice(&canonical(&ack.ack)?);
    require(
        ed25519_verify(worker_pubkey, &message, &ack.worker_signature),
        "worker signature rejected",
    )
}

/// Digest binding a signed offer to its durable admission entry: the offer
/// is only admitted when this matches the pre-submitted spec digest.
pub fn offer_digest(spec: &crate::worker::JobSpec) -> String {
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(spec).unwrap_or_default());
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::JobSpec;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn keypair(seed_byte: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed_byte; 32]).unwrap()
    }

    fn spec(project: &str) -> JobSpec {
        serde_json::from_value(json_spec(project)).unwrap()
    }

    fn json_spec(project: &str) -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "operation_id": format!("op-{project}"),
            "project_id": project,
            "profile_sha256": "a".repeat(64),
            "input_manifest_sha256": "b".repeat(64),
            "input_bytes": 128,
            "limits": {"vcpus": 2, "memory_mib": 512, "scratch_mib": 256, "timeout_secs": 60, "output_bytes": 4096},
        })
    }

    fn enrollment() -> WorkerEnrollment {
        WorkerEnrollment {
            worker_id: "worker-1".into(),
            worker_pubkey: keypair(0xB).public_key().as_ref().to_vec(),
            allowed_project_ids: vec!["proj-a".into()],
            valid_from: 100,
            valid_until: 100_000,
        }
    }

    fn signed_offer(project: &str, issued_at: u64, key: &Ed25519KeyPair) -> SignedJobOffer {
        let offer = JobOffer {
            spec: spec(project),
            issued_at,
        };
        let signature = key.sign(&sign_job_offer_payload(&offer).unwrap());
        SignedJobOffer {
            offer,
            controller_signature: signature
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        }
    }

    #[test]
    fn verified_offer_reaches_admission_and_impostors_refuse_pre_launch() {
        let controller = keypair(0xA);
        let enrollment = enrollment();
        let now = 200;
        // Happy path: the verified offer yields the spec for admission.
        let offer = signed_offer("proj-a", now - 1, &controller);
        let spec =
            worker_verify_job_offer(&enrollment, controller.public_key().as_ref(), &offer, now)
                .unwrap();
        assert_eq!(spec.project_id, "proj-a");
        // Impostor controller key: refusal before any launch.
        let impostor = keypair(0xC);
        let bad = signed_offer("proj-a", now - 1, &impostor);
        assert!(
            worker_verify_job_offer(&enrollment, controller.public_key().as_ref(), &bad, now)
                .is_err()
        );
        // Wrong project: outside the enrollment scope.
        let other = signed_offer("proj-z", now - 1, &controller);
        assert!(worker_verify_job_offer(
            &enrollment,
            controller.public_key().as_ref(),
            &other,
            now
        )
        .is_err());
        // Stale envelope: older than MAX_ENVELOPE_TTL_SECS.
        let stale = signed_offer("proj-a", now - MAX_ENVELOPE_TTL_SECS - 1, &controller);
        assert!(worker_verify_job_offer(
            &enrollment,
            controller.public_key().as_ref(),
            &stale,
            now
        )
        .is_err());
        // Enrollment not yet valid / expired: the worker is unavailable.
        let early = signed_offer("proj-a", now - 1, &controller);
        let mut closed = enrollment.clone();
        closed.valid_from = now + 10;
        assert!(
            worker_verify_job_offer(&closed, controller.public_key().as_ref(), &early, now)
                .is_err()
        );
        // Tampered payload bytes: signature must break.
        let mut tampered = signed_offer("proj-a", now - 1, &controller);
        tampered.offer.spec.input_bytes += 1;
        assert!(worker_verify_job_offer(
            &enrollment,
            controller.public_key().as_ref(),
            &tampered,
            now
        )
        .is_err());
    }

    #[test]
    fn worker_ack_roundtrip_and_forgeries() {
        let worker = keypair(0xB);
        let ack = worker_sign_ack("worker-1", "op-proj-a", "finished:abc", 500, &worker).unwrap();
        controller_verify_ack(worker.public_key().as_ref(), &ack, 501).unwrap();
        // A forged ack (wrong key) is rejected.
        let forged =
            worker_sign_ack("worker-1", "op-proj-a", "finished:abc", 500, &keypair(0xC)).unwrap();
        assert!(controller_verify_ack(worker.public_key().as_ref(), &forged, 501).is_err());
        // A tampered state is rejected.
        let mut tampered = ack.clone();
        tampered.ack.state = "finished:deadbeef".into();
        assert!(controller_verify_ack(worker.public_key().as_ref(), &tampered, 501).is_err());
        // A stale ack is rejected.
        assert!(controller_verify_ack(
            worker.public_key().as_ref(),
            &ack,
            501 + MAX_ENVELOPE_TTL_SECS + 5
        )
        .is_err());
    }

    #[test]
    fn offer_digest_binds_the_spec_bytes() {
        let a = offer_digest(&spec("proj-a"));
        let b = offer_digest(&spec("proj-a"));
        assert_eq!(a, b);
        let c = offer_digest(&spec("proj-b"));
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
    }
}
