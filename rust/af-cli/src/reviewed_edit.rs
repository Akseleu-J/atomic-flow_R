//! One operator-pinned source replacement with a private candidate oracle.
use super::{api_error, auth_denied, ServerState};
use af_evidence::{EvidenceError, RequirementScope, SourceBinding};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    schema_version: u32,
    root_id: String,
    root_generation: String,
    file: String,
    before_sha256: String,
    replacement_sha256: String,
    requirement_id: String,
    requirement_contract_sha256: String,
    executable: PathBuf,
    executable_sha256: String,
    assertions: Vec<String>,
    timeout_secs: u64,
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Profile {
    pub(super) fn load(path: &Path) -> Result<Self, String> {
        af_sandbox::registry::ensure_no_links(path).map_err(|e| e.0)?;
        if !path.is_file() {
            return Err("reviewed edit profile must be a file".into());
        }
        let mut raw = Vec::new();
        std::fs::File::open(path)
            .and_then(|file| file.take(16385).read_to_end(&mut raw))
            .map_err(|_| "cannot read reviewed edit profile")?;
        if raw.len() > 16384 {
            return Err("reviewed edit profile exceeds limit".into());
        }
        let profile: Self =
            serde_json::from_slice(&raw).map_err(|_| "invalid reviewed edit profile")?;
        if profile.schema_version != 1
            || !af_sandbox::registry::valid_identifier(&profile.root_id)
            || profile.root_generation.is_empty()
            || profile.root_generation.len() > 128
            || profile.file.is_empty()
            || profile.file.len() > 512
            || profile.requirement_id.is_empty()
            || profile.requirement_id.len() > 256
            || profile.requirement_id.chars().any(char::is_control)
            || !profile.executable.is_absolute()
            || !(1..=120).contains(&profile.timeout_secs)
            || [
                &profile.before_sha256,
                &profile.replacement_sha256,
                &profile.requirement_contract_sha256,
                &profile.executable_sha256,
            ]
            .iter()
            .any(|value| !digest(value))
            || profile.before_sha256 == profile.replacement_sha256
        {
            return Err("invalid reviewed edit profile scope".into());
        }
        Ok(profile)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    session_id: String,
    replacement: String,
}

type ApiError = (StatusCode, Json<Value>);
type ApiResult = Result<Json<Value>, ApiError>;

pub(super) async fn inspect(State(state): State<ServerState>, headers: HeaderMap) -> ApiResult {
    if let Some(status) = auth_denied(&state, &headers) {
        return Err(api_error(status, "authorization required"));
    }
    let profile = state
        .reviewed_edit
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "no host-reviewed edit configured"))?;
    Ok(Json(
        json!({"schema_version":1,"root_id":profile.root_id,"file":profile.file,
        "before_sha256":profile.before_sha256,"replacement_sha256":profile.replacement_sha256,
        "requirement_id":profile.requirement_id}),
    ))
}

pub(super) async fn apply(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<Request>,
) -> ApiResult {
    if let Some(status) = auth_denied(&state, &headers) {
        return Err(api_error(status, "authorization required"));
    }
    let profile = state
        .reviewed_edit
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "no host-reviewed edit configured"))?;
    if request.replacement.len() > 512 * 1024
        || af_evidence::sha256(request.replacement.as_bytes()) != profile.replacement_sha256
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "replacement differs from host review",
        ));
    }
    let permit = state
        .edits
        .try_acquire_owned()
        .map_err(|_| api_error(StatusCode::TOO_MANY_REQUESTS, "another edit is active"))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        run(&profile, request)
    })
    .await
    .map_err(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "edit interrupted; inspect session",
        )
    })?
}

struct Candidate(PathBuf);
impl Drop for Candidate {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(profile: &Profile, request: Request) -> ApiResult {
    let conflict = |message| api_error(StatusCode::CONFLICT, message);
    let internal = |message| api_error(StatusCode::INTERNAL_SERVER_ERROR, message);
    let registry = af_sandbox::SandboxRegistry::new("default")
        .map_err(|_| internal("workspace unavailable"))?;
    let grant = registry
        .get(&profile.root_id)
        .map_err(|_| conflict("reviewed root unavailable"))?;
    if grant["generation"] != profile.root_generation {
        return Err(conflict("reviewed root grant changed"));
    }
    let root = PathBuf::from(
        grant["path"]
            .as_str()
            .ok_or_else(|| conflict("invalid grant path"))?,
    );
    let mut journal = af_journal::SessionJournal::open(&request.session_id)
        .map_err(|_| conflict("use a session bound to the reviewed root"))?;
    let snapshot = journal
        .read()
        .map_err(|_| conflict("session cannot be read"))?;
    let metadata = snapshot
        .events
        .first()
        .and_then(|event| event.pointer("/payload/metadata"));
    if !metadata.is_some_and(|value| {
        value["root_id"] == profile.root_id && value["root_generation"] == profile.root_generation
    }) {
        return Err(conflict(
            "session root or grant generation differs from review",
        ));
    }
    journal
        .require_effects_clear()
        .map_err(|_| conflict("session requires reconciliation"))?;
    registry
        .require_root_effects_clear(&profile.root_id)
        .map_err(|_| conflict("root requires reconciliation"))?;

    let mut sandbox =
        af_sandbox::SandboxSession::new(&registry).map_err(|_| conflict("sandbox unavailable"))?;
    let mut offset = 0;
    loop {
        let page = sandbox
            .read(&profile.root_id, &profile.file, offset, 12000, true)
            .map_err(|_| conflict("reviewed source unavailable"))?;
        if page["content_hash"] != profile.before_sha256 {
            return Err(conflict("reviewed source changed"));
        }
        if page["read_complete"] == true {
            break;
        }
        let next = page["next_offset"]
            .as_u64()
            .and_then(|value| usize::try_from(value).ok())
            .filter(|value| *value > offset && *value <= 1_000_000)
            .ok_or_else(|| conflict("incomplete source proof"))?;
        offset = next;
    }
    let changes = BTreeMap::from([(profile.file.clone(), Some(request.replacement.clone()))]);
    let preview = sandbox
        .preview(&profile.root_id, &changes)
        .map_err(|_| conflict("cannot prepare reviewed changeset"))?;
    let preview_token = preview["preview_token"]
        .as_str()
        .ok_or_else(|| internal("changeset preview unavailable"))?;

    if registry.get(&profile.root_id).ok().as_ref() != Some(&grant) {
        return Err(conflict("reviewed root grant changed during preview"));
    }
    let home = af_sandbox::user_dir();
    let candidates = home.join("review-candidates");
    af_sandbox::registry::ensure_no_links(&candidates)
        .map_err(|_| internal("unsafe candidate store"))?;
    std::fs::create_dir_all(&candidates).map_err(|_| internal("candidate store unavailable"))?;
    let path = candidates.join(af_entropy::token());
    std::fs::create_dir(&path).map_err(|_| internal("candidate workspace unavailable"))?;
    let candidate = Candidate(path);
    let file = af_sandbox::admission::admit_rel(&candidate.0, &profile.file)
        .map_err(|_| conflict("invalid candidate path"))?;
    let parent = file
        .parent()
        .ok_or_else(|| internal("candidate path unavailable"))?;
    std::fs::create_dir_all(parent)
        .and_then(|_| std::fs::write(&file, request.replacement.as_bytes()))
        .map_err(|_| internal("cannot write private candidate"))?;

    let executable = profile
        .executable
        .canonicalize()
        .map_err(|_| conflict("host oracle unavailable"))?;
    af_sandbox::registry::ensure_no_links(&profile.executable)
        .map_err(|_| conflict("unsafe host oracle"))?;
    if executable.starts_with(
        root.canonicalize()
            .map_err(|_| conflict("reviewed root unavailable"))?,
    ) {
        return Err(conflict("oracle must be outside the live project"));
    }
    let mut checker = af_loop::requirement::ExecutableChecker::new(
        executable,
        profile.executable_sha256.clone(),
        profile.assertions.clone(),
        candidate.0.clone(),
        home.join("jobs"),
        profile.timeout_secs,
    )
    .map_err(|_| conflict("host oracle configuration refused"))?;
    let scope = RequirementScope {
        task_id: journal.session_id.clone(),
        requirement_id: profile.requirement_id.clone(),
        requirement_contract_sha256: profile.requirement_contract_sha256.clone(),
        checker_id: "reviewed-candidate-v1".into(),
        binding: SourceBinding {
            workspace_id: profile.root_id.clone(),
            source_revision: profile.before_sha256.clone(),
            inventory_sha256: af_evidence::sha256(
                &serde_json::to_vec(&changes).map_err(|_| internal("candidate encoding failed"))?,
            ),
            runtime_id: "single-file-candidate-v1".into(),
        },
        check_inventory_sha256: checker.check_inventory_sha256().into(),
        expected_checks: profile.assertions.len() as u64,
    };
    let check_call = af_entropy::token();
    journal
        .begin_effect(
            "tool_request",
            &check_call,
            &json!({"name":"reviewed_candidate_check","source":scope.binding}),
        )
        .map_err(|_| conflict("check checkpoint refused"))?;
    let checked = af_evidence::run_requirement_check(&scope, &mut checker);
    let (receipt, outcome, status) = match checked {
        Ok(receipt) => (Some(receipt), "success", "passed"),
        Err(EvidenceError::CheckerOutcomeUnknown) => (None, "unknown", "hold"),
        Err(_) => (None, "error", "refused"),
    };
    journal.finish_effect(if outcome == "unknown" { "tool_effect_unknown" } else { "tool_result" }, &check_call,
        &json!({"phase":"reviewed_candidate_check","status":status,"job_id":checker.last_job_id(),"check_inventory_sha256":scope.check_inventory_sha256,"evidence_sha256":receipt.as_ref().map(|r|r.evidence_sha256())}), outcome)
        .map_err(|_| internal("check result persistence failed; inspect session"))?;
    let Some(receipt) = receipt else {
        return Ok(Json(
            json!({"schema_version":1,"status":status,"published":false}),
        ));
    };
    if af_sandbox::registry::ensure_no_links(&file).is_err()
        || !file.is_file()
        || std::fs::File::open(&file)
            .and_then(|f| {
                let mut bytes = Vec::new();
                f.take(512 * 1024 + 1).read_to_end(&mut bytes)?;
                Ok(bytes)
            })
            .ok()
            .as_deref()
            != Some(request.replacement.as_bytes())
    {
        return Err(conflict("checked candidate changed"));
    }

    let publish_call = af_entropy::token();
    journal
        .begin_effect(
            "tool_request",
            &publish_call,
            &json!({"name":"reviewed_source_publication",
        "root_id":profile.root_id,"file":profile.file,"after_sha256":profile.replacement_sha256,
        "evidence_sha256":receipt.evidence_sha256()}),
        )
        .map_err(|_| conflict("publication checkpoint refused"))?;
    let published = sandbox.apply(preview_token, true);
    match published {
        Ok(report) => {
            journal
                .finish_effect(
                    "tool_result",
                    &publish_call,
                    &json!({"publication":report}),
                    "success",
                )
                .map_err(|_| internal("publication record incomplete; inspect session and root"))?;
            Ok(Json(
                json!({"schema_version":1,"status":"published","published":true,
                "evidence_sha256":receipt.evidence_sha256(),"publication":report}),
            ))
        }
        Err(_) => {
            journal
                .finish_effect(
                    "tool_effect_unknown",
                    &publish_call,
                    &json!({"reason":"publication requires inspection"}),
                    "unknown",
                )
                .map_err(|_| internal("publication record incomplete; inspect session and root"))?;
            Ok(Json(
                json!({"schema_version":1,"status":"hold","published":false}),
            ))
        }
    }
}
