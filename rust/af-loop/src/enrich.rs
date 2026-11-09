//! Enrichment scaffolding for N05 (ADR-0002, slice S1a): the deterministic
//! data model and the revision-bound cache for live-model context
//! enrichment. No model call happens here — this module only defines what an
//! enrichment *is*, when a cached one may be reused, and how a "no answer"
//! stays a first-class recorded outcome instead of a silent absence.
//!
//! Contracts honored from ADR-0002:
//! - D2: an unavailable enrichment is never cached (it is a transient state,
//!   the deterministic path continues without it).
//! - D3: cache keys are revision-bound — a new graph/commit revision never
//!   sees entries minted for an older revision.
//! - D4: `NoAnswer` is cached and journaled exactly like a successful tour;
//!   absence of a record must never be read as "the model was not asked".
//! - D5: every answer carries explicit completeness and coverage.
//! - D6: no live send exists in this module; slice S2 wires the accounted
//!   backend and fills `call_ref`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::{LoopError, LoopResult};

/// What kind of enrichment was requested (ADR-0002: tours/impact).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrichmentKind {
    /// Guided tour of the target area: what lives there, how it is arranged.
    Tour,
    /// Impact sketch: what the planned edit can touch beyond the target.
    Impact,
}

/// Explicit completeness of an answer (ADR-0002 D5): data, never prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Completeness {
    Full,
    Partial { missing: Vec<String> },
    None,
}

/// Why the model returned no usable answer (ADR-0002 D4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoAnswerReason {
    /// The model explicitly said nothing relevant exists for the target.
    NotRelevant,
    /// The response was empty or unparseable as an enrichment.
    EmptyResponse,
    /// Any other host-observed reason, recorded verbatim.
    Other(String),
}

/// Why no enrichment attempt happened at all (ADR-0002 D2). Transient by
/// definition: any of these may disappear next run, so none is cached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableReason {
    NoProvider,
    BudgetHold,
    BudgetRefused,
    Disabled,
    Other(String),
}

/// A usable enrichment answer with explicit coverage (ADR-0002 D5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrichmentAnswer {
    pub text: String,
    /// Paths/symbols the enrichment claims to have covered.
    pub coverage: Vec<String>,
    pub completeness: Completeness,
}

/// The outcome of one enrichment attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum EnrichmentOutcome {
    Answer(EnrichmentAnswer),
    NoAnswer { reason: NoAnswerReason },
    Unavailable { reason: UnavailableReason },
}

impl EnrichmentOutcome {
    /// Only real model outcomes are cache-worthy (ADR-0002 D2/D4): answers
    /// and no-answers are pinned facts about (revision, target, model);
    /// unavailability is a transient state of the host.
    pub fn is_cache_worthy(&self) -> bool {
        !matches!(self, EnrichmentOutcome::Unavailable { .. })
    }
}

/// Revision-bound cache key (ADR-0002 D3). The digest is the identity; the
/// fields are kept alongside for human inspection and audit dumps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrichmentKey {
    pub root_id: String,
    /// Graph/commit revision the entry was minted for.
    pub revision: String,
    /// Canonicalized target paths/symbols (sorted, deduped).
    pub target: Vec<String>,
    pub kind: EnrichmentKind,
    pub model: String,
    /// Prompt schema version; bump when the enrichment prompt changes so
    /// stale entries can never satisfy a new schema.
    pub prompt_schema: u32,
}

impl EnrichmentKey {
    /// Build a key with a canonical target list (sorted, deduped) so caller
    /// ordering can never split one logical request into two cache entries.
    pub fn new(
        root_id: impl Into<String>,
        revision: impl Into<String>,
        mut target: Vec<String>,
        kind: EnrichmentKind,
        model: impl Into<String>,
        prompt_schema: u32,
    ) -> Self {
        target.sort();
        target.dedup();
        EnrichmentKey {
            root_id: root_id.into(),
            revision: revision.into(),
            target,
            kind,
            model: model.into(),
            prompt_schema,
        }
    }

    /// Stable identity: sha256 over the canonical field serialization.
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.root_id.as_bytes());
        hasher.update([0]);
        hasher.update(self.revision.as_bytes());
        hasher.update([0]);
        hasher.update(self.target.join("\n").as_bytes());
        hasher.update([0]);
        hasher.update(format!("{:?}", self.kind).as_bytes());
        hasher.update([0]);
        hasher.update(self.model.as_bytes());
        hasher.update([0]);
        hasher.update(self.prompt_schema.to_le_bytes());
        to_hex(&hasher.finalize())
    }
}

/// One recorded enrichment attempt (ADR-0002 D4: no-answer is first-class).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrichmentRecord {
    pub key_digest: String,
    /// The key fields, kept for audit even though the digest is the identity.
    pub key: EnrichmentKey,
    pub outcome: EnrichmentOutcome,
    /// Ledger call reference; always `None` until slice S2 wires the
    /// accounted backend (ADR-0002 D1/D6).
    pub call_ref: Option<String>,
    pub created_unix: u64,
}

impl EnrichmentRecord {
    pub fn mint(key: EnrichmentKey, outcome: EnrichmentOutcome) -> Self {
        EnrichmentRecord {
            key_digest: key.digest(),
            key,
            call_ref: None,
            created_unix: unix_now(),
            outcome,
        }
    }
}

/// Append-only file-backed cache (JSONL, last-wins on load). This is a cache:
/// losing it costs re-computation, never correctness, so there is no fsync
/// ceremony here — but a torn tail must not hide earlier entries (they are
/// kept and the damage is reported, not swallowed).
pub struct EnrichmentCache {
    path: PathBuf,
    entries: HashMap<String, EnrichmentRecord>,
    skipped_malformed: usize,
}

/// Result of opening a cache file: how much survived and what did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheLoadStats {
    pub records: usize,
    pub skipped_malformed: usize,
}

impl EnrichmentCache {
    /// Open (or start) the cache. A missing file is an empty cache; a torn
    /// or malformed line is skipped and counted, never fatal.
    pub fn open(path: impl Into<PathBuf>) -> (Self, CacheLoadStats) {
        let path = path.into();
        let mut entries = HashMap::new();
        let mut skipped = 0usize;
        if let Ok(text) = std::fs::read_to_string(&path) {
            for line in text.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<EnrichmentRecord>(line) {
                    Ok(record) => {
                        entries.insert(record.key_digest.clone(), record);
                    }
                    Err(_) => skipped += 1,
                }
            }
        }
        let stats = CacheLoadStats {
            records: entries.len(),
            skipped_malformed: skipped,
        };
        (
            EnrichmentCache {
                path,
                entries,
                skipped_malformed: skipped,
            },
            stats,
        )
    }

    /// Look up by revision-bound key. A hit proves the entry was minted for
    /// exactly this (root, revision, target, kind, model, schema).
    pub fn get(&self, key: &EnrichmentKey) -> Option<&EnrichmentRecord> {
        self.entries.get(&key.digest())
    }

    /// Record an outcome. Unavailable outcomes are refused (ADR-0002 D2);
    /// the `bool` says whether anything was cached.
    pub fn insert(&mut self, record: EnrichmentRecord) -> LoopResult<bool> {
        if !record.outcome.is_cache_worthy() {
            return Ok(false);
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| LoopError(format!("enrichment cache open: {e}")))?;
        let line = serde_json::to_string(&record)
            .map_err(|e| LoopError(format!("enrichment cache encode: {e}")))?;
        writeln!(file, "{line}").map_err(|e| LoopError(format!("enrichment cache write: {e}")))?;
        self.entries.insert(record.key_digest.clone(), record);
        Ok(true)
    }

    pub fn skipped_malformed(&self) -> usize {
        self.skipped_malformed
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "af-enrich-test-{}-{}-{tag}",
            std::process::id(),
            unix_now()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn key(revision: &str) -> EnrichmentKey {
        EnrichmentKey::new(
            "main",
            revision,
            vec!["src/lib.rs".to_string(), "src/graph".to_string()],
            EnrichmentKind::Tour,
            "kernel-scripted",
            1,
        )
    }

    #[test]
    fn key_digest_is_canonical_and_revision_bound() {
        let a = key("rev1");
        let reordered = EnrichmentKey::new(
            "main",
            "rev1",
            vec!["src/graph".to_string(), "src/lib.rs".to_string()],
            EnrichmentKind::Tour,
            "kernel-scripted",
            1,
        );
        assert_eq!(a, reordered, "target order must not split entries");
        assert_eq!(a.digest(), reordered.digest());

        assert_ne!(a.digest(), key("rev2").digest(), "revision must invalidate");
        let impact = EnrichmentKey::new(
            "main",
            "rev1",
            a.target.clone(),
            EnrichmentKind::Impact,
            "kernel-scripted",
            1,
        );
        assert_ne!(a.digest(), impact.digest(), "kind must invalidate");
        let other_model = EnrichmentKey::new(
            "main",
            "rev1",
            a.target.clone(),
            EnrichmentKind::Tour,
            "other-model",
            1,
        );
        assert_ne!(a.digest(), other_model.digest(), "model must invalidate");
        let other_schema = EnrichmentKey::new(
            "main",
            "rev1",
            a.target.clone(),
            EnrichmentKind::Tour,
            "kernel-scripted",
            2,
        );
        assert_ne!(a.digest(), other_schema.digest(), "schema must invalidate");
    }

    #[test]
    fn answer_roundtrip_and_no_answer_are_first_class() {
        let dir = temp_dir("roundtrip");
        let path = dir.join("cache.jsonl");
        let answer = EnrichmentOutcome::Answer(EnrichmentAnswer {
            text: "tour: three modules, one entry".to_string(),
            coverage: vec!["src/lib.rs".to_string()],
            completeness: Completeness::Partial {
                missing: vec!["src/graph/delta.rs".to_string()],
            },
        });
        {
            let (mut cache, stats) = EnrichmentCache::open(&path);
            assert_eq!(
                stats,
                CacheLoadStats {
                    records: 0,
                    skipped_malformed: 0
                }
            );
            assert!(cache
                .insert(EnrichmentRecord::mint(key("rev1"), answer.clone()))
                .unwrap());
            let no = EnrichmentOutcome::NoAnswer {
                reason: NoAnswerReason::NotRelevant,
            };
            assert!(cache
                .insert(EnrichmentRecord::mint(key("rev2"), no))
                .unwrap());
        }
        let (cache, stats) = EnrichmentCache::open(&path);
        assert_eq!(stats.records, 2, "no-answer must be cached like an answer");
        let hit = cache.get(&key("rev1")).expect("hit");
        match &hit.outcome {
            EnrichmentOutcome::Answer(a) => {
                assert_eq!(a.text, "tour: three modules, one entry");
                assert_eq!(
                    a.completeness,
                    Completeness::Partial {
                        missing: vec!["src/graph/delta.rs".to_string()]
                    }
                );
            }
            other => panic!("expected answer, got {other:?}"),
        }
        let no_hit = cache.get(&key("rev2")).expect("no-answer hit");
        match &no_hit.outcome {
            EnrichmentOutcome::NoAnswer { reason } => {
                assert_eq!(reason, &NoAnswerReason::NotRelevant);
            }
            other => panic!("expected no-answer, got {other:?}"),
        }
        assert!(
            cache.get(&key("rev3")).is_none(),
            "unseen revision must miss"
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn unavailable_is_never_cached() {
        let dir = temp_dir("unavailable");
        let path = dir.join("cache.jsonl");
        let (mut cache, _) = EnrichmentCache::open(&path);
        let refused = EnrichmentOutcome::Unavailable {
            reason: UnavailableReason::BudgetHold,
        };
        assert!(!cache
            .insert(EnrichmentRecord::mint(key("rev1"), refused))
            .unwrap());
        assert!(
            cache.get(&key("rev1")).is_none(),
            "transient state must not be cached"
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn torn_tail_does_not_hide_earlier_entries() {
        let dir = temp_dir("torn");
        let path = dir.join("cache.jsonl");
        {
            let (mut cache, _) = EnrichmentCache::open(&path);
            cache
                .insert(EnrichmentRecord::mint(
                    key("rev1"),
                    EnrichmentOutcome::NoAnswer {
                        reason: NoAnswerReason::EmptyResponse,
                    },
                ))
                .unwrap();
        }
        // Simulate a torn write: a truncated trailing JSON line.
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("{\"key_digest\":\"deadbe");
        std::fs::write(&path, text).unwrap();
        let (cache, stats) = EnrichmentCache::open(&path);
        assert_eq!(stats.records, 1, "earlier record must survive");
        assert_eq!(stats.skipped_malformed, 1, "damage must be reported");
        assert!(cache.get(&key("rev1")).is_some());
        std::fs::remove_dir_all(dir).ok();
    }
}
