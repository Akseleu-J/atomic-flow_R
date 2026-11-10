//! Host-owned admission contract for the initial microVM worker profile.
//! This module records lifecycle evidence. A runtime adapter must actually
//! observe execution and cleanup before writing their receipts.
use crate::durable_queue::{DurableAdmission, DurableQueueError, Entry};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const WIRE_LIMIT: usize = 8192;
type Result<T> = std::result::Result<T, DurableQueueError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobSpec {
    pub schema_version: u32,
    pub operation_id: String,
    pub project_id: String,
    pub profile_sha256: String,
    pub input_manifest_sha256: String,
    pub input_bytes: u64,
    pub limits: Limits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub vcpus: u16,
    pub memory_mib: u32,
    pub scratch_mib: u32,
    pub timeout_secs: u32,
    pub output_bytes: u64,
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
}

fn sha256_label(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl JobSpec {
    /// Typed parsing rejects duplicate keys, unknown keys and wrong numeric types.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > WIRE_LIMIT {
            return Err(DurableQueueError("worker request too large".into()));
        }
        let spec: Self = serde_json::from_slice(bytes)
            .map_err(|_| DurableQueueError("invalid worker request schema".into()))?;
        spec.validate()?;
        Ok(spec)
    }

    fn validate(&self) -> Result<()> {
        let l = &self.limits;
        if self.schema_version != 1
            || !identifier(&self.operation_id)
            || !identifier(&self.project_id)
            || !sha256_label(&self.profile_sha256)
            || !sha256_label(&self.input_manifest_sha256)
            || !(1..=128 * 1024 * 1024).contains(&self.input_bytes)
            || !(1..=8).contains(&l.vcpus)
            || !(128..=16384).contains(&l.memory_mib)
            || !(1..=32768).contains(&l.scratch_mib)
            || !(1..=1800).contains(&l.timeout_secs)
            || !(1..=4 * 1024 * 1024).contains(&l.output_bytes)
        {
            return Err(DurableQueueError(
                "worker request outside supported bounds".into(),
            ));
        }
        Ok(())
    }

    fn digest(&self) -> Result<String> {
        let canonical = serde_json::to_vec(self)
            .map_err(|_| DurableQueueError("cannot encode worker request".into()))?;
        Ok(format!("{:x}", Sha256::digest(canonical)))
    }
}

/// Transport manifest for one opaque input bundle. Extraction and guest
/// provisioning are separate operations.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InputManifest {
    schema_version: u32,
    bundle_sha256: String,
    bundle_bytes: u64,
}

/// Owns the exact bytes that were verified, so an adapter need not reopen a
/// filesystem path after checking its contents.
pub struct VerifiedInput {
    spec_digest: String,
    bundle: Vec<u8>,
}

impl VerifiedInput {
    pub fn verify(spec: &JobSpec, manifest: &[u8], bundle: Vec<u8>) -> Result<Self> {
        spec.validate()?;
        if manifest.len() > WIRE_LIMIT
            || bundle.len() as u64 != spec.input_bytes
            || format!("{:x}", Sha256::digest(manifest)) != spec.input_manifest_sha256
        {
            return Err(DurableQueueError(
                "worker input does not match request".into(),
            ));
        }
        let parsed: InputManifest = serde_json::from_slice(manifest)
            .map_err(|_| DurableQueueError("invalid worker input manifest".into()))?;
        if parsed.schema_version != 1
            || parsed.bundle_bytes != spec.input_bytes
            || format!("{:x}", Sha256::digest(&bundle)) != parsed.bundle_sha256
        {
            return Err(DurableQueueError(
                "worker bundle does not match manifest".into(),
            ));
        }
        Ok(Self {
            spec_digest: spec.digest()?,
            bundle,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bundle
    }
}

/// One trusted host configuration. Authentication and actual profile provisioning
/// belong to the service that constructs it, outside the request body.
pub struct Admission {
    ledger: DurableAdmission,
    ledger_path: PathBuf,
    project_id: String,
    profile_sha256: String,
    worker_id: String,
    max_limits: Limits,
}

#[derive(Debug)]
pub struct Reservation {
    id: String,
    worker_id: String,
    epoch: u64,
    ledger_path: PathBuf,
    payload_digest: String,
}

impl Admission {
    pub fn open(
        ledger: &Path,
        project_id: String,
        profile_sha256: String,
        worker_id: String,
        max_limits: Limits,
    ) -> Result<Self> {
        if !identifier(&project_id) || !identifier(&worker_id) || !sha256_label(&profile_sha256) {
            return Err(DurableQueueError(
                "invalid host worker configuration".into(),
            ));
        }
        Ok(Self {
            ledger: DurableAdmission::open(ledger)?,
            ledger_path: ledger
                .canonicalize()
                .map_err(|_| DurableQueueError("worker ledger path unavailable".into()))?,
            project_id,
            profile_sha256,
            worker_id,
            max_limits,
        })
    }

    pub fn submit(&mut self, spec: &JobSpec) -> Result<Entry> {
        spec.validate()?;
        let requested = &spec.limits;
        let max = &self.max_limits;
        if spec.project_id != self.project_id
            || spec.profile_sha256 != self.profile_sha256
            || requested.vcpus > max.vcpus
            || requested.memory_mib > max.memory_mib
            || requested.scratch_mib > max.scratch_mib
            || requested.timeout_secs > max.timeout_secs
            || requested.output_bytes > max.output_bytes
        {
            return Err(DurableQueueError(
                "worker project, profile or limits not admitted".into(),
            ));
        }
        let snapshot = self.ledger.transition(json!({
            "kind":"worker_submit", "entry_id":spec.operation_id, "task_id":spec.project_id,
            "idempotency_key":spec.operation_id, "priority":0, "payload_digest":spec.digest()?
        }))?;
        snapshot
            .entries
            .get(&spec.operation_id)
            .cloned()
            .ok_or_else(|| DurableQueueError("worker entry unavailable".into()))
    }

    pub fn inspect(&self, id: &str) -> Result<Entry> {
        self.ledger
            .snapshot()?
            .entries
            .get(id)
            .filter(|entry| entry.kind == "worker" && entry.task_id == self.project_id)
            .cloned()
            .ok_or_else(|| DurableQueueError("worker entry unavailable".into()))
    }

    pub fn reserve(&mut self, spec: &JobSpec) -> Result<Reservation> {
        // Re-admit the exact request against current host limits and profile.
        let entry = self.submit(spec)?;
        let snapshot = self.ledger.reserve(&entry.entry_id, &self.worker_id)?;
        let epoch = snapshot.entries[&entry.entry_id]
            .reservation_fence
            .ok_or_else(|| DurableQueueError("reservation fence unavailable".into()))?;
        Ok(Reservation {
            id: entry.entry_id,
            worker_id: self.worker_id.clone(),
            epoch,
            ledger_path: self.ledger_path.clone(),
            payload_digest: entry.payload_digest,
        })
    }

    /// Record a unique, host-selected runtime ID before any runtime effect.
    pub fn start(
        &mut self,
        reservation: &Reservation,
        runtime_id: &str,
        input: &VerifiedInput,
    ) -> Result<Entry> {
        if input.spec_digest != reservation.payload_digest {
            return Err(DurableQueueError(
                "verified input belongs to a different request".into(),
            ));
        }
        self.record(
            reservation,
            "worker_start",
            Some(("runtime_id", runtime_id)),
        )
    }

    pub fn finish(&mut self, reservation: &Reservation, receipt_sha256: &str) -> Result<Entry> {
        self.record(
            reservation,
            "worker_finish",
            Some(("receipt_digest", receipt_sha256)),
        )
    }

    pub fn confirm_cleanup(
        &mut self,
        reservation: &Reservation,
        receipt_sha256: &str,
    ) -> Result<Entry> {
        self.record(
            reservation,
            "worker_cleanup",
            Some(("cleanup_digest", receipt_sha256)),
        )
    }

    /// An uncertain effect latches the attempt. No automatic re-reservation.
    pub fn mark_unknown(&mut self, reservation: &Reservation) -> Result<Entry> {
        self.record(reservation, "worker_unknown", None)
    }

    fn record(
        &mut self,
        reservation: &Reservation,
        kind: &str,
        field: Option<(&str, &str)>,
    ) -> Result<Entry> {
        if reservation.worker_id != self.worker_id {
            return Err(DurableQueueError(
                "reservation belongs to a different worker".into(),
            ));
        }
        let entry = self.inspect(&reservation.id)?;
        if reservation.ledger_path != self.ledger_path
            || reservation.payload_digest != entry.payload_digest
        {
            return Err(DurableQueueError(
                "reservation belongs to a different ledger or request".into(),
            ));
        }
        let mut operation = json!({"kind":kind, "entry_id":reservation.id,
            "worker":reservation.worker_id, "reservation_fence":reservation.epoch});
        if let Some((name, value)) = field {
            operation[name] = json!(value);
        }
        let snapshot = self.ledger.transition(operation)?;
        Ok(snapshot.entries[&reservation.id].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::durable_queue::EntryState;

    fn fixture() -> (JobSpec, Vec<u8>, Vec<u8>) {
        let bundle = b"sample source".to_vec();
        let manifest = serde_json::to_vec(&InputManifest {
            schema_version: 1,
            bundle_sha256: format!("{:x}", Sha256::digest(&bundle)),
            bundle_bytes: bundle.len() as u64,
        })
        .unwrap();
        let spec = JobSpec {
            schema_version: 1,
            operation_id: "op-1".into(),
            project_id: "project".into(),
            profile_sha256: "a".repeat(64),
            input_manifest_sha256: format!("{:x}", Sha256::digest(&manifest)),
            input_bytes: bundle.len() as u64,
            limits: Limits {
                vcpus: 1,
                memory_mib: 512,
                scratch_mib: 128,
                timeout_secs: 60,
                output_bytes: 1024,
            },
        };
        (spec, manifest, bundle)
    }

    #[test]
    fn durable_admission_separates_completion_from_cleanup_and_holds_unknown() {
        let dir = std::env::temp_dir().join(format!("af-worker-test-{}", af_entropy::token()));
        std::fs::create_dir(&dir).unwrap();
        struct Temp(std::path::PathBuf);
        impl Drop for Temp {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _temp = Temp(dir.clone());
        let path = dir.join("ledger.jsonl");
        DurableAdmission::create(&path).unwrap();
        let (first, manifest, bundle) = fixture();
        let input = VerifiedInput::verify(&first, &manifest, bundle.clone()).unwrap();
        let open = |worker: &str| {
            Admission::open(
                &path,
                first.project_id.clone(),
                first.profile_sha256.clone(),
                worker.into(),
                first.limits.clone(),
            )
            .unwrap()
        };
        let mut a = open("worker-a");
        let mut b = open("worker-b");
        assert_eq!(a.submit(&first).unwrap().state, EntryState::Submitted);
        assert_eq!(b.submit(&first).unwrap().state, EntryState::Submitted);
        let mut conflict = first.clone();
        conflict.input_manifest_sha256 = "c".repeat(64);
        assert!(b.submit(&conflict).is_err());
        conflict.project_id = "elsewhere".into();
        assert!(b.submit(&conflict).is_err());
        let claim = a.reserve(&first).unwrap();
        assert!(b.reserve(&first).is_err());
        assert!(b.start(&claim, "vm-1", &input).is_err());
        let other_path = dir.join("other.jsonl");
        DurableAdmission::create(&other_path).unwrap();
        let mut other = Admission::open(
            &other_path,
            first.project_id.clone(),
            first.profile_sha256.clone(),
            "worker-a".into(),
            first.limits.clone(),
        )
        .unwrap();
        let _other_claim = other.reserve(&first).unwrap();
        assert!(other.start(&claim, "vm-1", &input).is_err());
        assert!(a.confirm_cleanup(&claim, &"c".repeat(64)).is_err());
        a.start(&claim, "vm-1", &input).unwrap();
        a.finish(&claim, &"d".repeat(64)).unwrap();
        assert_eq!(
            open("worker-a").inspect("op-1").unwrap().state,
            EntryState::Finished
        );
        a.confirm_cleanup(&claim, &"e".repeat(64)).unwrap();
        assert_eq!(
            b.submit(&first).unwrap().state,
            EntryState::CleanupConfirmed
        );
        let mut second = first.clone();
        second.operation_id = "op-2".into();
        let second_claim = a.reserve(&second).unwrap();
        assert!(a.start(&second_claim, "vm-2", &input).is_err());
        let second_input = VerifiedInput::verify(&second, &manifest, bundle).unwrap();
        assert!(a.start(&second_claim, "vm-1", &second_input).is_err());
        a.start(&second_claim, "vm-2", &second_input).unwrap();
        a.mark_unknown(&second_claim).unwrap();
        let mut reopened = open("worker-a");
        assert_eq!(reopened.inspect("op-2").unwrap().state, EntryState::Unknown);
        assert!(reopened.reserve(&second).is_err());
        assert!(reopened.finish(&second_claim, &"d".repeat(64)).is_err());
    }

    #[test]
    fn input_verification_rejects_substitution() {
        let (mut spec, mut manifest, mut bundle) = fixture();
        let input = VerifiedInput::verify(&spec, &manifest, bundle.clone()).unwrap();
        assert_eq!(input.bytes(), bundle);
        bundle[0] ^= 1;
        assert!(VerifiedInput::verify(&spec, &manifest, bundle.clone()).is_err());
        bundle.pop();
        assert!(VerifiedInput::verify(&spec, &manifest, bundle.clone()).is_err());
        bundle = input.bytes().to_vec();
        manifest.push(b' ');
        assert!(VerifiedInput::verify(&spec, &manifest, bundle.clone()).is_err());
        let invalid_manifest = br#"{"schema_version":1,"schema_version":1}"#;
        spec.input_manifest_sha256 = format!("{:x}", Sha256::digest(invalid_manifest));
        assert!(VerifiedInput::verify(&spec, invalid_manifest, bundle).is_err());
    }

    #[test]
    fn wire_refuses_duplicates_unknown_fields_and_invalid_limits() {
        let (spec, _, _) = fixture();
        let raw = serde_json::to_string(&spec).unwrap();
        assert_eq!(JobSpec::parse(raw.as_bytes()).unwrap(), spec);
        assert!(JobSpec::parse(
            raw.replace(
                "\"schema_version\":1",
                "\"schema_version\":1,\"schema_version\":1"
            )
            .as_bytes()
        )
        .is_err());
        assert!(JobSpec::parse(raw.replace("\"vcpus\":1", "\"vcpus\":0").as_bytes()).is_err());
        assert!(JobSpec::parse(
            raw.replace("\"vcpus\":1", "\"vcpus\":1,\"network\":true")
                .as_bytes()
        )
        .is_err());
    }
}
