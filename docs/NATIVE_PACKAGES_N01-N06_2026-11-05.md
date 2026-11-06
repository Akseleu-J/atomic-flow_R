# Native packages N01–N06 — engineering increment, 5 November 2026

This record states what the working tree now implements against the ordered
packages in [PRODUCTION_STATUS_2026-11-04.md](PRODUCTION_STATUS_2026-11-04.md).
It is an engineering increment, not a chapter acceptance: every full chapter
gate of P00–P14 / E00–E08 remains open until its named evidence exists. Local
verification: full workspace suite green on this tree (see commit message for
exact counts), af-cli zero warnings, `cargo fmt --check` clean.

## N01 — Frozen claims and evidence contracts (P00, E00, E01)

Implemented: `af-evidence` (data-only VerificationReport with bounded
fields and strict schema), requirement receipts minted only through
`run_requirement_check`, completion decisions separated from evidence.
Remaining for the gate: cross-crate consumption audit (loop/journal still
carry ad-hoc JSON payloads alongside), compatibility vector freeze across
Rust/TS, claims audit trail.

## N02 — Durable task boundary (P09, E04)

Implemented: `af-exec::durable_queue::DurableAdmission` — append-only JSONL
ledger with sequence numbers, per-op strict key sets (hand-written schema
gate), unique idempotency keys/entry ids, monotonic writer fence (+1 exactly),
lease-locked read-modify-append, size bounds, poison-on-uncertain-append,
torn-tail refusal without truncation. Seven negative/happy tests including
the concurrent single-winner reservation race. Publication recovery (the
other N02 half) landed 04.11 (`af-sandbox::recovery`, operator CLI).
Remaining: persistent authenticated outbox fan-out and cross-store task
idempotency remain slices, deliberately not fabricated.

## N03 — Requirement checker and reviewed apply (P04, P13, E01)

Implemented: `af_loop::edit::EditRequirement` + final-gate integration — a
supplied in-process `HostRequirementChecker` runs against the post-edit
source inventory (`af_sandbox::manifest` digest); a minted receipt flips the
outcome to `Completed` and is journaled; refusal/unavailability keeps the
task `Unverified` with the reason surfaced in `requirement_check`. Git
auto-commit now happens ONLY on a verified receipt (failure recorded
honestly, never flips the verdict). Wire-constructed receipts stay data and
are refused as authorization. The safe-apply surface remains disabled
wherever no checker is admitted.
Implemented: `af-cli::behavioral_checker::CommandBehavioralChecker` — the first
admitted behavioral checker adapter. It runs the host-configured argv through
the durable job runner, requires a fully green JUnit report (zero tests,
failures, errors or skips all refuse), pins the oracle by refusing source
mutation during execution, and mints the receipt through
`run_requirement_check`. `af task run --check-argv <cmd> --junit <path>` now
can end `completed` when the real suite is green; without the flags the
UnavailableChecker path still refuses by contract.

## N04 — Graph delta parity (P01, P02, E02)

Implemented: `af-graph/tests/delta_parity.rs` — a one-file structural delta
and a delete delta must land the store on byte-identical canonical output
versus a clean rebuild of the same inputs, with stale-base refusal. This is
the equality `perf.rs` counters previously only implied.
Remaining: mixed-language adapter cutovers and conflict/migration receipts.

## N06 — Native TaskRunner vertical slice (P05, P06, P07)

Implemented: `af task run` — durable queue admission (idempotency key binds
the exact reviewed plan) → reservation with writer fence → guided edit
journey with the requirement gate → queue resolution (`completed` only on a
verified receipt; every other outcome recorded as `fail` with its honest
reason). The Python TaskRunner pilot remains the accepted P07 engineering
authority; this slice is the native harness it will cutover into.
Remaining: real native FAIL → repair → fresh-check publication journeys and
mixed Rust/TS target checks.

## N05 — Semantic understanding (P03, P04, E02)

Deliberately NOT started: dependency/revision-bound enrichment requires the
live-model budget gate (protocol); deterministic layers/summaries stay the
implemented subset. No enrichment claims are made.

## TypeScript surface (P13)

`ts/af-studio` — bounded React app (Vite + vitest, node ≥ 22) over
`@atomic-flow/af-client`: three-zone layout on the Dark Carbon tokens,
dialog/tasks/explorer/verification surfaces, honest empty states. TS-client
hardening (wire validators for every endpoint, no unchecked casts) and the
CI job wiring land with the next push of this branch.

## What would close full chapters (unchanged, owner-gated)

Live-model research programs (N05/N12) under the accepted budget protocol;
real Linux worker evidence (N08) beyond the Docker acceptance; installed
signed consumers (N09/N10); two-principal corporate profile (N11); measured
utility with independent grades (N12/N14). This increment provides none of
those claims.
