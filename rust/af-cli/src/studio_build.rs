//! Serve an operator-selected, bounded build snapshot without request-time filesystem access.
use super::ServerState;
use axum::{
    extract::{Path as AxPath, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use std::{collections::BTreeMap, io::Read, path::Path};

const MAX_FILE: usize = 2 * 1024 * 1024;
const MAX_ASSETS: usize = 32;
const MAX_TOTAL: usize = 8 * 1024 * 1024;

pub(super) struct StudioBuild {
    index: Vec<u8>,
    assets: BTreeMap<String, (&'static str, Vec<u8>)>,
}

fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    af_sandbox::registry::ensure_no_links(path).map_err(|e| e.0)?;
    if !path.is_file() {
        return Err("Studio asset must be a regular file".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(MAX_FILE as u64 + 1).read_to_end(&mut bytes))
        .map_err(|_| "cannot read Studio asset")?;
    if bytes.len() > MAX_FILE {
        return Err("Studio asset exceeds size limit".into());
    }
    std::str::from_utf8(&bytes).map_err(|_| "Studio asset must be UTF-8")?;
    Ok(bytes)
}

impl StudioBuild {
    pub(super) fn load(root: &Path) -> Result<Self, String> {
        af_sandbox::registry::ensure_no_links(root).map_err(|e| e.0)?;
        let index = read_file(&root.join("index.html"))?;
        let directory = root.join("assets");
        af_sandbox::registry::ensure_no_links(&directory).map_err(|e| e.0)?;
        let mut assets = BTreeMap::new();
        let mut total = index.len();
        for entry in
            std::fs::read_dir(directory).map_err(|_| "Studio assets directory unavailable")?
        {
            if assets.len() >= MAX_ASSETS {
                return Err("too many Studio assets".into());
            }
            let entry = entry.map_err(|_| "cannot enumerate Studio assets")?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "invalid Studio asset name")?;
            if name.len() > 128
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            {
                return Err("invalid Studio asset name".into());
            }
            let kind = if name.ends_with(".js") {
                "text/javascript; charset=utf-8"
            } else if name.ends_with(".css") {
                "text/css; charset=utf-8"
            } else {
                return Err("unexpected Studio asset type".into());
            };
            let bytes = read_file(&entry.path())?;
            total += bytes.len();
            if total > MAX_TOTAL {
                return Err("Studio build exceeds size limit".into());
            }
            assets.insert(name, (kind, bytes));
        }
        if !assets
            .values()
            .any(|(kind, _)| kind.starts_with("text/javascript"))
        {
            return Err("Studio build has no JavaScript entry".into());
        }
        Ok(Self { index, assets })
    }
}

pub(super) async fn index(State(state): State<ServerState>) -> Response {
    let Some(build) = state.studio else {
        return StatusCode::NOT_FOUND.into_response();
    };
    ([
        (header::CONTENT_TYPE, "text/html; charset=utf-8"),
        (header::CONTENT_SECURITY_POLICY, "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"),
    ], build.index.clone()).into_response()
}

pub(super) async fn asset(
    State(state): State<ServerState>,
    AxPath(name): AxPath<String>,
) -> Response {
    let Some(build) = state.studio else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match build.assets.get(&name) {
        Some((kind, bytes)) => ([(header::CONTENT_TYPE, *kind)], bytes.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
