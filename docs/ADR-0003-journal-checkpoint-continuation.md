# ADR-0003: Journal append continuation without prefix rehash (P09)

Status: accepted (2026-11-19)
Closes the roadmap P09 item "quadratic journal prefix reread" for the live
`SessionJournal` hot path; `af-journal/src/segments.rs` remains the
experimental long-session substrate and is not authority for effects.

## Problem

`append_position` rehashed the entire validated prefix on every append and
re-parsed every prior event (the tail loop validated the full history each
time via `read()`-equivalent state). A long beta session (96h, hundreds of
turns, 64 MiB cap) pays O(N) work per append — quadratic overall. The code
marked this explicitly as P09 debt.

## Decision

1. **Per-append work is O(new bytes).** After the initial full validation
   (which `open()`/`read()` still perform once per process), an append:
   - stats the file (size guard: `MAX_SESSION_BYTES`; truncation guard:
     `len < offset` refuses),
   - reads and validates only bytes past the validated offset (foreign
     events from a cooperating writer are discovered there),
   - continues the SHA-256 chain from the in-memory hasher state,
   - fsyncs the event, then writes a **checkpoint sidecar**.

2. **Checkpoint sidecar** (`sessions/session_<id>.jsonl.checkpoint`):
   `{schema_version, session_id, sequence, offset, prefix_sha256}`, written
   atomically (tmp + fsync + rename + parent sync) after every append. It is
   an **accelerator and tripwire, never a correctness authority**:
   - missing/corrupt sidecar → no tripwire, in-memory state trusted (the
     baseline trust);
   - sidecar `(sequence, offset)` disagreeing with the in-memory continuation
     state → one full `read()` revalidation before appending (fail-safe);
   - sidecar write failure is deliberately non-fatal: the durable append has
     already happened and the tripwire converts any resulting staleness into
     revalidation, never into silent trust.

3. **Trust model (explicit, per the roadmap requirement):**
   - *Accidental corruption / process kill* — structural validation at every
     full read; an unterminated last line is uncommitted tail and blocks
     appends until `recover_tail()` (unchanged).
   - *Concurrent cooperating writers* — `FileLease` serializes appends
     (unchanged); foreign events are discovered in the tail or via tripwire
     revalidation; `expected_sequence` fencing is unchanged.
   - *Truncation of validated bytes* — refused at the next append via the
     size guard.
   - *Same-length in-place edits of old bytes* — **not detected per append**
     (detection would require re-reading, which is the quadratic cost this
     ADR removes). They remain tamper-evident at every full read: any
     `open()`, `read()`, or export re-derives the whole chain and rejects
     validation failures. The exposure window is bounded by the owning
     process's lifetime. This is honest tamper-*evidence*, not
     tamper-*prevention* — consistent with the roadmap note that a hash
     chain without a trusted anchor is not attestation.
   - Stat-only checks are used only as size/truncation guards, never as a
     substitute for hashing.

4. **Diagnostics:** `SessionJournal::tail_bytes_scanned` counts tail bytes
   parsed since open. For appends that discover no foreign events it stays 0
   — the deterministic proof that no prefix rehash happens (asserted by a
   unit test; no timing-sensitive benchmarks).

## Consequences

- Appends are O(new bytes) instead of O(session size); the 64 MiB session
  cap no longer makes late-session turns expensive.
- Cross-process continuation still validates the whole file once at
  `open()`; a cooperating writer's appends between our appends trigger one
  full revalidation (lease-serialized, so at most once per interleaving) —
  the realistic deployment is one owning process per session.
- Legacy journals (no sidecar) work unchanged: the first append takes the
  existing full-read path and the sidecar appears after the first append.
- The per-effect `read()` in `begin_effect`/`finish_effect` remains a full
  validation per host effect; that is the next P09 sub-item (incremental
  unresolved-ledger cache) and is intentionally not bundled here because its
  fail-closed semantics deserve their own review.
