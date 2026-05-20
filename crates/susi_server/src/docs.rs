//! Documentation knowledge-base endpoints.
//!
//! Public read-only API serves per-release pages and assets at
//! `/api/v1/docs/...`. Admin endpoints (JWT) allow upserting pages,
//! uploading assets, and bulk-importing a generated doc set.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Multipart, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use susi_core::error::LicenseError;

use crate::{
    error_response, release_reader_check, release_writer_check, validate_principal, AppState,
    ErrorResponse, Principal,
};

// ---------------------------------------------------------------------------
// Disk layout
// ---------------------------------------------------------------------------

fn docs_root(state: &AppState) -> std::path::PathBuf {
    std::path::Path::new(&state.data_dir).join("docs")
}

fn assets_dir(state: &AppState, tag: &str) -> std::path::PathBuf {
    docs_root(state).join(tag).join("assets")
}

/// Reject path components that could escape the asset directory.
pub(crate) fn safe_filename(name: &str) -> Result<&str, (StatusCode, Json<ErrorResponse>)> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name == "."
        || name == ".."
    {
        return Err(error_response(StatusCode::BAD_REQUEST, "Invalid filename"));
    }
    Ok(name)
}

pub(crate) fn safe_tag(tag: &str) -> Result<&str, (StatusCode, Json<ErrorResponse>)> {
    if tag.is_empty()
        || tag.contains('/')
        || tag.contains('\\')
        || tag.contains('\0')
        || tag == "."
        || tag == ".."
    {
        return Err(error_response(StatusCode::BAD_REQUEST, "Invalid release tag"));
    }
    Ok(tag)
}

fn content_type_for(name: &str) -> &'static str {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".png") { "image/png" }
    else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") { "image/jpeg" }
    else if lower.ends_with(".gif") { "image/gif" }
    else if lower.ends_with(".svg") { "image/svg+xml" }
    else if lower.ends_with(".webp") { "image/webp" }
    else if lower.ends_with(".pdf") { "application/pdf" }
    else if lower.ends_with(".md") { "text/markdown; charset=utf-8" }
    else if lower.ends_with(".json") { "application/json" }
    else { "application/octet-stream" }
}

fn db_err(e: LicenseError) -> (StatusCode, Json<ErrorResponse>) {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())
}

/// Seed a release that was just created with `origin='user'` doc pages +
/// assets from the most recent prior release in the same scope (workspace or
/// global). Physical asset files are copied on disk alongside the DB rows.
/// Idempotent: `INSERT OR IGNORE` makes a second call a no-op. Call from any
/// code path that creates a release row (binary-asset upload, docs editor,
/// docs bulk import) so user docs always carry forward — but never across
/// workspaces.
pub(crate) fn seed_user_docs_into_release(
    state: &AppState,
    dst_id: i64,
    dst_tag: &str,
    workspace_id: Option<&str>,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let (src_tag, asset_names) = {
        let mut db = state.db.lock().unwrap();
        let prior = db
            .latest_prior_release_with_user_docs(dst_id, workspace_id)
            .map_err(db_err)?;
        let Some((src_id, src_tag)) = prior else {
            return Ok(());
        };
        let n = db.copy_user_doc_pages(src_id, dst_id).map_err(db_err)?;
        let asset_names = db.copy_user_doc_asset_rows(src_id, dst_id).map_err(db_err)?;
        log::info!(
            "Seeded release {} from {}: {} user page(s), {} user asset(s)",
            dst_tag, src_tag, n, asset_names.len()
        );
        (src_tag, asset_names)
    };

    if !asset_names.is_empty() {
        let src_dir = assets_dir(state, &src_tag);
        let dst_dir = assets_dir(state, dst_tag);
        if let Err(e) = std::fs::create_dir_all(&dst_dir) {
            log::warn!("Could not create asset dir {}: {}", dst_dir.display(), e);
        } else {
            for name in &asset_names {
                let sp = src_dir.join(name);
                let dp = dst_dir.join(name);
                if let Err(e) = std::fs::copy(&sp, &dp) {
                    log::warn!(
                        "Asset {} copy {} -> {} failed: {}",
                        name, sp.display(), dp.display(), e
                    );
                }
            }
        }
    }
    Ok(())
}

/// Permission gate for doc write endpoints that may auto-create a release.
/// Admin-only. Returns the existing release's workspace id (if any) so seeding
/// stays scope-correct; returns `None` if the release does not yet exist (the
/// caller will create it as a global release).
fn release_writer_check_or_admin_create(
    state: &AppState,
    principal: &Principal,
    tag: &str,
) -> Result<Option<String>, (StatusCode, Json<ErrorResponse>)> {
    crate::require_admin_full(state, principal)?;
    let db = state.db.lock().unwrap();
    let scoped_ws = db
        .get_release_workspace_id(tag)
        .map_err(db_err)?
        .flatten();
    Ok(scoped_ws)
}

/// Ensure the release row for `tag` exists and, if it was just created, seed
/// it with hand-authored content from the most recent prior release in the
/// same scope. Returns the release id.
fn ensure_release_with_seed(
    state: &AppState,
    tag: &str,
    name: &str,
    workspace_id: Option<&str>,
) -> Result<i64, (StatusCode, Json<ErrorResponse>)> {
    let (dst_id, newly_created) = {
        let db = state.db.lock().unwrap();
        db.ensure_release_created_scoped(tag, name, workspace_id)
            .map_err(db_err)?
    };
    if newly_created {
        seed_user_docs_into_release(state, dst_id, tag, workspace_id)?;
    }
    Ok(dst_id)
}

// ---------------------------------------------------------------------------
// Public read endpoints
// ---------------------------------------------------------------------------

pub async fn handle_list_doc_releases(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let db = state.db.lock().unwrap();
    let rows = db.list_doc_releases().map_err(db_err)?;
    let releases: Vec<_> = rows
        .into_iter()
        .map(|(_id, tag, name, created_at, page_count)| {
            json!({
                "tag": tag,
                "name": name,
                "published_at": created_at,
                "page_count": page_count,
            })
        })
        .collect();
    Ok(Json(json!({ "releases": releases })))
}

pub async fn handle_latest_doc_release(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let db = state.db.lock().unwrap();
    let mut rows = db.list_doc_releases().map_err(db_err)?;
    if rows.is_empty() {
        return Err(error_response(StatusCode::NOT_FOUND, "No documentation releases"));
    }
    let (_id, tag, name, created_at, page_count) = rows.remove(0);
    Ok(Json(json!({
        "tag": tag,
        "name": name,
        "published_at": created_at,
        "page_count": page_count,
    })))
}

pub async fn handle_list_doc_pages(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tag): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    safe_tag(&tag)?;
    let principal_opt = validate_principal(&headers, &state).ok();
    release_reader_check(&state, principal_opt.as_ref(), &tag)?;
    let db = state.db.lock().unwrap();
    let release_id = db
        .get_release_by_tag(&tag)
        .map_err(db_err)?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Release not found"))?;
    let pages = db.list_doc_pages(release_id).map_err(db_err)?;
    let assets = db.list_doc_assets(release_id).map_err(db_err)?;
    let pages_json: Vec<_> = pages
        .into_iter()
        .map(|(slug, title, parent_slug, ord, updated_at)| {
            json!({
                "slug": slug,
                "title": title,
                "parent_slug": parent_slug,
                "ord": ord,
                "updated_at": updated_at,
            })
        })
        .collect();
    let assets_json: Vec<_> = assets
        .into_iter()
        .map(|(name, size)| json!({ "name": name, "size": size }))
        .collect();
    Ok(Json(json!({
        "tag": tag,
        "pages": pages_json,
        "assets": assets_json,
    })))
}

pub async fn handle_get_doc_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((tag, slug)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    safe_tag(&tag)?;
    let principal_opt = validate_principal(&headers, &state).ok();
    release_reader_check(&state, principal_opt.as_ref(), &tag)?;
    let db = state.db.lock().unwrap();
    let release_id = db
        .get_release_by_tag(&tag)
        .map_err(db_err)?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Release not found"))?;
    let page = db
        .get_doc_page(release_id, &slug)
        .map_err(db_err)?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Page not found"))?;
    let (title, body_md, parent_slug, ord, updated_at) = page;
    Ok(Json(json!({
        "tag": tag,
        "slug": slug,
        "title": title,
        "body_md": body_md,
        "parent_slug": parent_slug,
        "ord": ord,
        "updated_at": updated_at,
    })))
}

#[derive(Deserialize)]
pub struct AssetAuthQuery {
    /// Bearer token passed via query string. Browser <img> requests can't set
    /// an Authorization header, so workspace-scoped doc images need this
    /// fallback. Identical validation path as the header form.
    #[serde(default)]
    auth: Option<String>,
}

pub async fn handle_get_doc_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<AssetAuthQuery>,
    Path((tag, file_name)): Path<(String, String)>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    safe_tag(&tag)?;
    safe_filename(&file_name)?;
    let mut auth_headers = headers.clone();
    if !auth_headers.contains_key("authorization") {
        if let Some(tok) = q.auth.as_deref().filter(|s| !s.is_empty()) {
            if let Ok(v) = HeaderValue::from_str(&format!("Bearer {}", tok)) {
                auth_headers.insert("authorization", v);
            }
        }
    }
    let principal_opt = validate_principal(&auth_headers, &state).ok();
    release_reader_check(&state, principal_opt.as_ref(), &tag)?;

    let path = assets_dir(&state, &tag).join(&file_name);
    if !path.exists() {
        return Err(error_response(StatusCode::NOT_FOUND, "Asset not found"));
    }
    // Async read so the disk I/O doesn't block a runtime worker. Doc assets
    // are typically small images, so buffering into a Vec is fine.
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("Read: {}", e)))?;

    let mut resp = HeaderMap::new();
    resp.insert(header::CONTENT_TYPE, content_type_for(&file_name).parse().unwrap());
    resp.insert(header::CONTENT_LENGTH, bytes.len().into());
    // Allow inline display; long max-age since assets are immutable per release
    resp.insert(header::CACHE_CONTROL, "public, max-age=86400".parse().unwrap());
    Ok((resp, bytes))
}

// ---------------------------------------------------------------------------
// Admin write endpoints (JWT)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct UpsertPageRequest {
    pub title: String,
    pub body_md: String,
    #[serde(default)]
    pub parent_slug: Option<String>,
    #[serde(default)]
    pub ord: i64,
    /// Optional: create the release row if it doesn't exist yet.
    #[serde(default)]
    pub release_name: Option<String>,
}

pub async fn handle_upsert_doc_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((tag, slug)): Path<(String, String)>,
    Json(req): Json<UpsertPageRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    safe_tag(&tag)?;
    let workspace_id = release_writer_check_or_admin_create(&state, &principal, &tag)?;

    let release_id = ensure_release_with_seed(
        &state,
        &tag,
        req.release_name.as_deref().unwrap_or(""),
        workspace_id.as_deref(),
    )?;
    let id = {
        let db = state.db.lock().unwrap();
        db.upsert_doc_page(
            release_id,
            &slug,
            &req.title,
            &req.body_md,
            req.parent_slug.as_deref(),
            req.ord,
        )
        .map_err(db_err)?
    };
    Ok(Json(json!({ "id": id, "tag": tag, "slug": slug })))
}

#[derive(Deserialize)]
pub struct RenamePageRequest {
    pub new_slug: String,
}

pub async fn handle_rename_doc_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((tag, slug)): Path<(String, String)>,
    Json(req): Json<RenamePageRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    safe_tag(&tag)?;
    release_writer_check(&state, &principal, &tag)?;
    let new_slug = req.new_slug.trim();
    if new_slug.is_empty() || new_slug.contains('/') || new_slug.contains('\\') || new_slug.contains('\0') {
        return Err(error_response(StatusCode::BAD_REQUEST, "Invalid slug"));
    }

    let mut db = state.db.lock().unwrap();
    let release_id = db
        .get_release_by_tag(&tag)
        .map_err(db_err)?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Release not found"))?;
    match db.rename_doc_page(release_id, &slug, new_slug) {
        Ok(true) => Ok(Json(json!({ "tag": tag, "slug": new_slug }))),
        Ok(false) => Err(error_response(StatusCode::NOT_FOUND, "Page not found")),
        Err(e) => {
            let msg = format!("{}", e);
            if msg.contains("UNIQUE") {
                Err(error_response(StatusCode::CONFLICT, "Target slug already exists"))
            } else {
                Err(error_response(StatusCode::INTERNAL_SERVER_ERROR, &msg))
            }
        }
    }
}

pub async fn handle_delete_doc_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((tag, slug)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    safe_tag(&tag)?;
    release_writer_check(&state, &principal, &tag)?;

    let db = state.db.lock().unwrap();
    let release_id = db
        .get_release_by_tag(&tag)
        .map_err(db_err)?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Release not found"))?;
    let removed = db.delete_doc_page(release_id, &slug).map_err(db_err)?;
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Page not found"));
    }
    Ok(Json(json!({ "status": "OK" })))
}

#[derive(Deserialize, Default)]
struct PageManifestEntry {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    parent_slug: Option<String>,
    #[serde(default)]
    ord: Option<i64>,
}

/// Bulk import: upserts pages and assets for a release tag from a multipart
/// upload. Existing pages/assets that are not present in the upload are left
/// alone, so hand-authored content (e.g. the General section) survives a
/// release pipeline run.
pub async fn handle_bulk_import_docs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tag): Path<String>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    safe_tag(&tag)?;
    let workspace_id = release_writer_check_or_admin_create(&state, &principal, &tag)?;

    let mut release_name = String::new();
    let mut manifest: HashMap<String, PageManifestEntry> = HashMap::new();
    let mut pages: Vec<(String, String)> = Vec::new(); // (slug, body_md)
    let mut assets: Vec<(String, Vec<u8>)> = Vec::new();

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("Multipart: {}", e)))?
    {
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "release_name" => {
                release_name = field
                    .text()
                    .await
                    .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;
            }
            "manifest" => {
                let txt = field
                    .text()
                    .await
                    .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;
                manifest = serde_json::from_str(&txt).map_err(|e| {
                    error_response(StatusCode::BAD_REQUEST, &format!("Manifest JSON: {}", e))
                })?;
            }
            "page" => {
                let file_name = field.file_name().unwrap_or("").to_string();
                if !file_name.to_ascii_lowercase().ends_with(".md") {
                    return Err(error_response(
                        StatusCode::BAD_REQUEST,
                        &format!("Page '{}' must end in .md", file_name),
                    ));
                }
                let slug = file_name.trim_end_matches(".md").trim_end_matches(".MD").to_string();
                if slug.is_empty() {
                    return Err(error_response(StatusCode::BAD_REQUEST, "Empty page slug"));
                }
                let body = field
                    .text()
                    .await
                    .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;
                pages.push((slug, body));
            }
            "asset" => {
                let file_name = field.file_name().unwrap_or("").to_string();
                safe_filename(&file_name)?;
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;
                assets.push((file_name, bytes.to_vec()));
            }
            _ => {}
        }
    }

    if pages.is_empty() && assets.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "No pages or assets uploaded"));
    }

    // Build the (slug, title, body_md, parent_slug, ord) tuples.
    let row_data: Vec<(String, String, String, Option<String>, i64)> = pages
        .into_iter()
        .map(|(slug, body)| {
            let entry = manifest.remove(&slug).unwrap_or_default();
            let title = entry.title.unwrap_or_else(|| derive_title(&slug, &body));
            let parent_slug = entry.parent_slug;
            let ord = entry.ord.unwrap_or(0);
            (slug, title, body, parent_slug, ord)
        })
        .collect();

    let release_id = ensure_release_with_seed(&state, &tag, &release_name, workspace_id.as_deref())?;
    let (written_pages, skipped_user_slugs) = {
        let mut db = state.db.lock().unwrap();
        db.upsert_doc_pages(release_id, &row_data).map_err(db_err)?
    };

    // Pipeline-side asset upsert on disk + DB. User-owned assets with the same
    // file_name are left alone (both on disk and in DB).
    let asset_path = assets_dir(&state, &tag);
    let mut written_assets = 0usize;
    let mut skipped_user_assets: Vec<String> = Vec::new();
    if !assets.is_empty() {
        std::fs::create_dir_all(&asset_path).map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Cannot create assets dir: {}", e),
            )
        })?;
        let db = state.db.lock().unwrap();
        for (name, bytes) in &assets {
            let wrote = db
                .upsert_doc_asset_pipeline(release_id, name, bytes.len() as u64)
                .map_err(db_err)?;
            if !wrote {
                skipped_user_assets.push(name.clone());
                continue;
            }
            let p = asset_path.join(name);
            std::fs::write(&p, bytes).map_err(|e| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Write asset {}: {}", name, e),
                )
            })?;
            written_assets += 1;
        }
    }

    log::info!(
        "Docs imported for release {}: {} page(s) written, {} skipped (user-owned); {} asset(s) written, {} skipped",
        tag, written_pages, skipped_user_slugs.len(), written_assets, skipped_user_assets.len(),
    );

    Ok(Json(json!({
        "status": "OK",
        "tag": tag,
        "pages_written": written_pages,
        "pages_skipped_user": skipped_user_slugs,
        "assets_written": written_assets,
        "assets_skipped_user": skipped_user_assets,
    })))
}

/// Upload (or overwrite) a single asset for a release. Used by the in-browser editor.
pub async fn handle_upload_doc_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tag): Path<String>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    safe_tag(&tag)?;
    let workspace_id = release_writer_check_or_admin_create(&state, &principal, &tag)?;

    // Pull the first "file" field from the multipart body.
    let mut file_name = String::new();
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("Multipart: {}", e)))?
    {
        if field.name() == Some("file") {
            file_name = field.file_name().unwrap_or("").to_string();
            let data = field
                .bytes()
                .await
                .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;
            bytes = data.to_vec();
            break;
        }
    }
    if file_name.is_empty() || bytes.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Missing 'file' field"));
    }
    safe_filename(&file_name)?;

    // Ensure the release exists so the asset has a valid parent row.
    let release_id = ensure_release_with_seed(&state, &tag, "", workspace_id.as_deref())?;

    let dir = assets_dir(&state, &tag);
    std::fs::create_dir_all(&dir).map_err(|e| {
        error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("mkdir: {}", e))
    })?;
    let path = dir.join(&file_name);
    std::fs::write(&path, &bytes).map_err(|e| {
        error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("write: {}", e))
    })?;

    {
        let db = state.db.lock().unwrap();
        db.upsert_doc_asset(release_id, &file_name, bytes.len() as u64)
            .map_err(db_err)?;
    }

    let url = format!("/api/v1/docs/{}/assets/{}", tag, file_name);
    log::info!("Doc asset uploaded: {} ({} bytes) for release {}", file_name, bytes.len(), tag);
    Ok(Json(json!({ "name": file_name, "size": bytes.len(), "url": url })))
}

pub async fn handle_delete_doc_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((tag, file_name)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    safe_tag(&tag)?;
    safe_filename(&file_name)?;
    release_writer_check(&state, &principal, &tag)?;

    let release_id = {
        let db = state.db.lock().unwrap();
        db.get_release_by_tag(&tag)
            .map_err(db_err)?
            .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Release not found"))?
    };
    let removed = {
        let db = state.db.lock().unwrap();
        db.delete_doc_asset(release_id, &file_name).map_err(db_err)?
    };
    let _ = std::fs::remove_file(assets_dir(&state, &tag).join(&file_name));
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Asset not found"));
    }
    Ok(Json(json!({ "status": "OK" })))
}

/// Pick a title: first H1 in the markdown, else humanize the slug.
fn derive_title(slug: &str, body: &str) -> String {
    for line in body.lines() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("# ") {
            return rest.trim().to_string();
        }
    }
    let mut chars = slug.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_filename_rejects_traversal() {
        assert!(safe_filename("../etc/passwd").is_err());
        assert!(safe_filename("foo/bar").is_err());
        assert!(safe_filename("foo\\bar").is_err());
        assert!(safe_filename("..").is_err());
        assert!(safe_filename(".").is_err());
        assert!(safe_filename("").is_err());
        assert!(safe_filename("ok.png").is_ok());
    }

    #[test]
    fn safe_tag_rejects_bad_paths() {
        assert!(safe_tag("v1.0").is_ok());
        assert!(safe_tag("..").is_err());
        assert!(safe_tag("v/1").is_err());
    }

    #[test]
    fn derive_title_prefers_first_h1() {
        let body = "Some prelude\n# The Real Title\nmore";
        assert_eq!(derive_title("anything", body), "The Real Title");
    }

    #[test]
    fn derive_title_falls_back_to_capitalized_slug() {
        assert_eq!(derive_title("imu", "no header here"), "Imu");
    }

    #[test]
    fn content_type_basic_mappings() {
        assert_eq!(content_type_for("a.PNG"), "image/png");
        assert_eq!(content_type_for("a.jpeg"), "image/jpeg");
        assert_eq!(content_type_for("a.unknown"), "application/octet-stream");
    }
}
