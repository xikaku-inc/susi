//! Documentation knowledge-base endpoints.
//!
//! Public read-only API serves per-release pages and assets at
//! `/api/v1/docs/...`. Admin endpoints (JWT) allow upserting pages,
//! uploading assets, and bulk-importing a generated doc set.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Multipart, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use susi_core::error::LicenseError;

use crate::{
    assert_workspace_member, error_response, require_admin_full, require_password_changed,
    validate_principal, AppState, ErrorResponse,
};
use crate::workspaces::safe_workspace_id;

// ---------------------------------------------------------------------------
// Disk layout
// ---------------------------------------------------------------------------

fn docs_root(state: &AppState) -> std::path::PathBuf {
    std::path::Path::new(&state.data_dir).join("docs")
}

/// On-disk asset directory for a release. FusionHub keeps its historical flat
/// layout (`docs/{tag}/assets`) so existing asset files stay addressable with
/// no migration; every other product is namespaced (`docs/{product}/{tag}/...`)
/// to avoid tag collisions. Back-compat shim: remove the special-case once all
/// products use the namespaced layout.
pub(crate) fn release_assets_dir(state: &AppState, product: &str, tag: &str) -> std::path::PathBuf {
    if product == susi_core::db::DEFAULT_PRODUCT {
        docs_root(state).join(tag).join("assets")
    } else {
        docs_root(state).join(product).join(tag).join("assets")
    }
}

/// On-disk asset directory for a workspace's documentation.
pub(crate) fn ws_doc_assets_dir(state: &AppState, workspace_id: &str) -> std::path::PathBuf {
    std::path::Path::new(&state.data_dir)
        .join("workspaces")
        .join(workspace_id)
        .join("docs")
        .join("assets")
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

pub(crate) fn safe_product(product: &str) -> Result<&str, (StatusCode, Json<ErrorResponse>)> {
    if product.is_empty()
        || product.contains('/')
        || product.contains('\\')
        || product.contains('\0')
        || product == "."
        || product == ".."
    {
        return Err(error_response(StatusCode::BAD_REQUEST, "Invalid product"));
    }
    Ok(product)
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

/// Uploaded SVG can carry <script>; navigating to the asset URL would run it
/// in the site's origin. Browsers ignore Content-Disposition on subresource
/// loads, so <img> embedding keeps rendering - only direct navigation turns
/// from "execute" into "download". The sandbox CSP (which overrides the
/// site-wide header) additionally neuters scripts in any context that still
/// renders the document.
pub(crate) fn harden_svg_response(file_name: &str, resp: &mut HeaderMap) {
    if file_name.to_ascii_lowercase().ends_with(".svg") {
        resp.insert(header::CONTENT_DISPOSITION, HeaderValue::from_static("attachment"));
        resp.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'none'; sandbox"),
        );
    }
}

fn db_err(e: LicenseError) -> (StatusCode, Json<ErrorResponse>) {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())
}

/// Seed a release that was just created with `origin='user'` doc pages +
/// assets from the most recent prior release of the same product. Physical
/// asset files are copied on disk alongside the DB rows. Idempotent:
/// `INSERT OR IGNORE` makes a second call a no-op. Call from any code path
/// that creates a release row (binary-asset upload, docs editor, docs bulk
/// import) so user docs always carry forward.
pub(crate) fn seed_user_docs_into_release(
    state: &AppState,
    dst_id: i64,
    product: &str,
    dst_tag: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let (src_tag, asset_names) = {
        let mut db = state.db.lock();
        let prior = db
            .latest_prior_release_with_user_docs(dst_id, product)
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
        let src_dir = release_assets_dir(state, product, &src_tag);
        let dst_dir = release_assets_dir(state, product, dst_tag);
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

/// Ensure the release row for `(product, tag)` exists and, if it was just
/// created, seed it with hand-authored content from the most recent prior
/// release of the product. Returns the release id.
fn ensure_release_with_seed(
    state: &AppState,
    product: &str,
    tag: &str,
    name: &str,
) -> Result<i64, (StatusCode, Json<ErrorResponse>)> {
    let (dst_id, newly_created) = {
        let db = state.db.lock();
        db.ensure_release_created_for(product, tag, name).map_err(db_err)?
    };
    if newly_created {
        seed_user_docs_into_release(state, dst_id, product, tag)?;
    }
    Ok(dst_id)
}

// ---------------------------------------------------------------------------
// Public read endpoints
// ---------------------------------------------------------------------------

// Each public read endpoint has a product-scoped axum handler
// (`/api/v1/docs/{product}/...`) and a legacy tag-only wrapper
// (`/api/v1/docs/...`) that pins the default product, so already-deployed
// FusionHubs keep working. Both delegate to a shared `_impl`.
// Back-compat shim: drop the legacy wrappers once every client sends a product.

use susi_core::db::DEFAULT_PRODUCT;

async fn list_doc_releases_impl(
    state: &Arc<AppState>,
    product: &str,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let db = state.db.lock();
    let rows = db.list_doc_releases(product).map_err(db_err)?;
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

pub async fn handle_list_doc_releases(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    list_doc_releases_impl(&state, DEFAULT_PRODUCT).await
}

pub async fn handle_list_doc_releases_p(
    State(state): State<Arc<AppState>>,
    Path(product): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    safe_product(&product)?;
    list_doc_releases_impl(&state, &product).await
}

async fn latest_doc_release_impl(
    state: &Arc<AppState>,
    product: &str,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let db = state.db.lock();
    let mut rows = db.list_doc_releases(product).map_err(db_err)?;
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

pub async fn handle_latest_doc_release(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    latest_doc_release_impl(&state, DEFAULT_PRODUCT).await
}

pub async fn handle_latest_doc_release_p(
    State(state): State<Arc<AppState>>,
    Path(product): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    safe_product(&product)?;
    latest_doc_release_impl(&state, &product).await
}

async fn list_doc_pages_impl(
    state: &Arc<AppState>,
    product: &str,
    tag: &str,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    safe_tag(tag)?;
    let db = state.db.lock();
    let release_id = db
        .get_release_by_product_tag(product, tag)
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

pub async fn handle_list_doc_pages(
    State(state): State<Arc<AppState>>,
    Path(tag): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    list_doc_pages_impl(&state, DEFAULT_PRODUCT, &tag).await
}

pub async fn handle_list_doc_pages_p(
    State(state): State<Arc<AppState>>,
    Path((product, tag)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    safe_product(&product)?;
    list_doc_pages_impl(&state, &product, &tag).await
}

async fn get_doc_page_impl(
    state: &Arc<AppState>,
    product: &str,
    tag: &str,
    slug: &str,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    safe_tag(tag)?;
    let db = state.db.lock();
    let release_id = db
        .get_release_by_product_tag(product, tag)
        .map_err(db_err)?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Release not found"))?;
    let page = db
        .get_doc_page(release_id, slug)
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

pub async fn handle_get_doc_page(
    State(state): State<Arc<AppState>>,
    Path((tag, slug)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    get_doc_page_impl(&state, DEFAULT_PRODUCT, &tag, &slug).await
}

pub async fn handle_get_doc_page_p(
    State(state): State<Arc<AppState>>,
    Path((product, tag, slug)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    safe_product(&product)?;
    get_doc_page_impl(&state, &product, &tag, &slug).await
}

/// Build an `attachment` Content-Disposition for `file_name` that can never
/// panic or smuggle header syntax: quotes and backslashes are escaped, control
/// bytes dropped, and a non-ASCII name falls back to a generic filename (the
/// upload validators only admit ASCII names anyway).
pub(crate) fn content_disposition_attachment(file_name: &str) -> HeaderValue {
    let cleaned: String = file_name
        .chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control())
        .map(|c| if c == '"' || c == '\\' { '_' } else { c })
        .collect();
    let name = if cleaned.is_empty() { "download" } else { &cleaned };
    HeaderValue::from_str(&format!("attachment; filename=\"{}\"", name))
        .unwrap_or_else(|_| HeaderValue::from_static("attachment; filename=\"download\""))
}

async fn get_doc_asset_impl(
    state: &Arc<AppState>,
    product: &str,
    tag: &str,
    file_name: &str,
) -> Result<(HeaderMap, Vec<u8>), (StatusCode, Json<ErrorResponse>)> {
    safe_tag(tag)?;
    safe_filename(file_name)?;

    let path = release_assets_dir(state, product, tag).join(file_name);
    if !path.exists() {
        return Err(error_response(StatusCode::NOT_FOUND, "Asset not found"));
    }
    // Async read so the disk I/O doesn't block a runtime worker. Doc assets
    // are typically small images, so buffering into a Vec is fine.
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("Read: {}", e)))?;

    let mut resp = HeaderMap::new();
    resp.insert(header::CONTENT_TYPE, content_type_for(file_name).parse().unwrap());
    resp.insert(header::CONTENT_LENGTH, bytes.len().into());
    // Allow inline display; long max-age since assets are immutable per release
    resp.insert(header::CACHE_CONTROL, "public, max-age=86400".parse().unwrap());
    harden_svg_response(file_name, &mut resp);
    Ok((resp, bytes))
}

pub async fn handle_get_doc_asset(
    State(state): State<Arc<AppState>>,
    Path((tag, file_name)): Path<(String, String)>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    get_doc_asset_impl(&state, DEFAULT_PRODUCT, &tag, &file_name).await
}

pub async fn handle_get_doc_asset_p(
    State(state): State<Arc<AppState>>,
    Path((product, tag, file_name)): Path<(String, String, String)>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    safe_product(&product)?;
    get_doc_asset_impl(&state, &product, &tag, &file_name).await
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

async fn upsert_doc_page_impl(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    product: &str,
    tag: &str,
    slug: &str,
    req: UpsertPageRequest,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(headers, state)?;
    safe_tag(tag)?;
    require_admin_full(state, &principal)?;

    let release_id =
        ensure_release_with_seed(state, product, tag, req.release_name.as_deref().unwrap_or(""))?;
    let id = {
        let db = state.db.lock();
        db.upsert_doc_page(
            release_id,
            slug,
            &req.title,
            &req.body_md,
            req.parent_slug.as_deref(),
            req.ord,
        )
        .map_err(db_err)?
    };
    Ok(Json(json!({ "id": id, "tag": tag, "slug": slug })))
}

pub async fn handle_upsert_doc_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((tag, slug)): Path<(String, String)>,
    Json(req): Json<UpsertPageRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    upsert_doc_page_impl(&state, &headers, DEFAULT_PRODUCT, &tag, &slug, req).await
}

pub async fn handle_upsert_doc_page_p(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((product, tag, slug)): Path<(String, String, String)>,
    Json(req): Json<UpsertPageRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    safe_product(&product)?;
    upsert_doc_page_impl(&state, &headers, &product, &tag, &slug, req).await
}

#[derive(Deserialize)]
pub struct RenamePageRequest {
    pub new_slug: String,
}

async fn rename_doc_page_impl(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    product: &str,
    tag: &str,
    slug: &str,
    req: RenamePageRequest,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(headers, state)?;
    safe_tag(tag)?;
    require_admin_full(state, &principal)?;
    let new_slug = req.new_slug.trim();
    if new_slug.is_empty() || new_slug.contains('/') || new_slug.contains('\\') || new_slug.contains('\0') {
        return Err(error_response(StatusCode::BAD_REQUEST, "Invalid slug"));
    }

    let mut db = state.db.lock();
    let release_id = db
        .get_release_by_product_tag(product, tag)
        .map_err(db_err)?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Release not found"))?;
    match db.rename_doc_page(release_id, slug, new_slug) {
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

pub async fn handle_rename_doc_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((tag, slug)): Path<(String, String)>,
    Json(req): Json<RenamePageRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    rename_doc_page_impl(&state, &headers, DEFAULT_PRODUCT, &tag, &slug, req).await
}

pub async fn handle_rename_doc_page_p(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((product, tag, slug)): Path<(String, String, String)>,
    Json(req): Json<RenamePageRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    safe_product(&product)?;
    rename_doc_page_impl(&state, &headers, &product, &tag, &slug, req).await
}

async fn delete_doc_page_impl(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    product: &str,
    tag: &str,
    slug: &str,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(headers, state)?;
    safe_tag(tag)?;
    require_admin_full(state, &principal)?;

    let db = state.db.lock();
    let release_id = db
        .get_release_by_product_tag(product, tag)
        .map_err(db_err)?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Release not found"))?;
    let removed = db.delete_doc_page(release_id, slug).map_err(db_err)?;
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Page not found"));
    }
    Ok(Json(json!({ "status": "OK" })))
}

pub async fn handle_delete_doc_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((tag, slug)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    delete_doc_page_impl(&state, &headers, DEFAULT_PRODUCT, &tag, &slug).await
}

pub async fn handle_delete_doc_page_p(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((product, tag, slug)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    safe_product(&product)?;
    delete_doc_page_impl(&state, &headers, &product, &tag, &slug).await
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
async fn bulk_import_docs_impl(
    state: Arc<AppState>,
    headers: HeaderMap,
    product: &str,
    tag: String,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    safe_tag(&tag)?;
    require_admin_full(&state, &principal)?;

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

    let release_id = ensure_release_with_seed(&state, product, &tag, &release_name)?;
    let (written_pages, skipped_user_slugs) = {
        let mut db = state.db.lock();
        db.upsert_doc_pages(release_id, &row_data).map_err(db_err)?
    };

    // Pipeline-side asset upsert on disk + DB. User-owned assets with the same
    // file_name are left alone (both on disk and in DB).
    let asset_path = release_assets_dir(&state, product, &tag);
    let mut written_assets = 0usize;
    let mut skipped_user_assets: Vec<String> = Vec::new();
    if !assets.is_empty() {
        std::fs::create_dir_all(&asset_path).map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Cannot create assets dir: {}", e),
            )
        })?;
        let db = state.db.lock();
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

/// Bulk import: upserts pages and assets for a release tag from a multipart
/// upload. Existing pages/assets not present in the upload are left alone, so
/// hand-authored content survives a release pipeline run.
pub async fn handle_bulk_import_docs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tag): Path<String>,
    multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    bulk_import_docs_impl(state, headers, DEFAULT_PRODUCT, tag, multipart).await
}

pub async fn handle_bulk_import_docs_p(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((product, tag)): Path<(String, String)>,
    multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    safe_product(&product)?;
    bulk_import_docs_impl(state, headers, &product, tag, multipart).await
}

/// Upload (or overwrite) a single asset for a release. Used by the in-browser editor.
async fn upload_doc_asset_impl(
    state: Arc<AppState>,
    headers: HeaderMap,
    product: &str,
    tag: String,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    safe_tag(&tag)?;
    require_admin_full(&state, &principal)?;

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
    let release_id = ensure_release_with_seed(&state, product, &tag, "")?;

    let dir = release_assets_dir(&state, product, &tag);
    std::fs::create_dir_all(&dir).map_err(|e| {
        error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("mkdir: {}", e))
    })?;
    let path = dir.join(&file_name);
    std::fs::write(&path, &bytes).map_err(|e| {
        error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("write: {}", e))
    })?;

    {
        let db = state.db.lock();
        db.upsert_doc_asset(release_id, &file_name, bytes.len() as u64)
            .map_err(db_err)?;
    }

    // FusionHub keeps the flat asset URL so its markdown rewrite still resolves;
    // other products carry the product segment.
    let url = if product == DEFAULT_PRODUCT {
        format!("/api/v1/docs/{}/assets/{}", tag, file_name)
    } else {
        format!("/api/v1/docs/{}/{}/assets/{}", product, tag, file_name)
    };
    log::info!("Doc asset uploaded: {} ({} bytes) for release {}", file_name, bytes.len(), tag);
    Ok(Json(json!({ "name": file_name, "size": bytes.len(), "url": url })))
}

pub async fn handle_upload_doc_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tag): Path<String>,
    multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    upload_doc_asset_impl(state, headers, DEFAULT_PRODUCT, tag, multipart).await
}

pub async fn handle_upload_doc_asset_p(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((product, tag)): Path<(String, String)>,
    multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    safe_product(&product)?;
    upload_doc_asset_impl(state, headers, &product, tag, multipart).await
}

async fn delete_doc_asset_impl(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    product: &str,
    tag: &str,
    file_name: &str,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(headers, state)?;
    safe_tag(tag)?;
    safe_filename(file_name)?;
    require_admin_full(state, &principal)?;

    let release_id = {
        let db = state.db.lock();
        db.get_release_by_product_tag(product, tag)
            .map_err(db_err)?
            .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Release not found"))?
    };
    let removed = {
        let db = state.db.lock();
        db.delete_doc_asset(release_id, file_name).map_err(db_err)?
    };
    let _ = std::fs::remove_file(release_assets_dir(state, product, tag).join(file_name));
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Asset not found"));
    }
    Ok(Json(json!({ "status": "OK" })))
}

pub async fn handle_delete_doc_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((tag, file_name)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    delete_doc_asset_impl(&state, &headers, DEFAULT_PRODUCT, &tag, &file_name).await
}

pub async fn handle_delete_doc_asset_p(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((product, tag, file_name)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    safe_product(&product)?;
    delete_doc_asset_impl(&state, &headers, &product, &tag, &file_name).await
}

// ---------------------------------------------------------------------------
// Workspace docs: one flat page tree per workspace, member-writable. Reads
// and writes both require workspace membership (site admins pass via
// workspace_access).
// ---------------------------------------------------------------------------

fn ws_member_check(
    state: &AppState,
    headers: &HeaderMap,
    workspace_id: &str,
) -> Result<crate::Principal, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(headers, state)?;
    require_password_changed(state, &principal)?;
    assert_workspace_member(state, workspace_id, &principal)?;
    Ok(principal)
}

pub async fn handle_ws_list_doc_pages(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    ws_member_check(&state, &headers, &workspace_id)?;
    let db = state.db.lock();
    let pages = db.list_ws_doc_pages(&workspace_id).map_err(db_err)?;
    let assets = db.list_ws_doc_assets(&workspace_id).map_err(db_err)?;
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
    Ok(Json(json!({ "pages": pages_json, "assets": assets_json })))
}

pub async fn handle_ws_get_doc_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, slug)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    ws_member_check(&state, &headers, &workspace_id)?;
    let db = state.db.lock();
    let page = db
        .get_ws_doc_page(&workspace_id, &slug)
        .map_err(db_err)?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Page not found"))?;
    let (title, body_md, parent_slug, ord, updated_at) = page;
    Ok(Json(json!({
        "slug": slug,
        "title": title,
        "body_md": body_md,
        "parent_slug": parent_slug,
        "ord": ord,
        "updated_at": updated_at,
    })))
}

pub async fn handle_ws_upsert_doc_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, slug)): Path<(String, String)>,
    Json(req): Json<UpsertPageRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    ws_member_check(&state, &headers, &workspace_id)?;
    let id = {
        let db = state.db.lock();
        db.upsert_ws_doc_page(
            &workspace_id,
            &slug,
            &req.title,
            &req.body_md,
            req.parent_slug.as_deref(),
            req.ord,
        )
        .map_err(db_err)?
    };
    Ok(Json(json!({ "id": id, "slug": slug })))
}

pub async fn handle_ws_rename_doc_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, slug)): Path<(String, String)>,
    Json(req): Json<RenamePageRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    ws_member_check(&state, &headers, &workspace_id)?;
    let new_slug = req.new_slug.trim();
    if new_slug.is_empty() || new_slug.contains('/') || new_slug.contains('\\') || new_slug.contains('\0') {
        return Err(error_response(StatusCode::BAD_REQUEST, "Invalid slug"));
    }
    let mut db = state.db.lock();
    match db.rename_ws_doc_page(&workspace_id, &slug, new_slug) {
        Ok(true) => Ok(Json(json!({ "slug": new_slug }))),
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

pub async fn handle_ws_delete_doc_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, slug)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    ws_member_check(&state, &headers, &workspace_id)?;
    let removed = {
        let db = state.db.lock();
        db.delete_ws_doc_page(&workspace_id, &slug).map_err(db_err)?
    };
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Page not found"));
    }
    Ok(Json(json!({ "status": "OK" })))
}

pub async fn handle_ws_upload_doc_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    ws_member_check(&state, &headers, &workspace_id)?;
    safe_workspace_id(&workspace_id)?;

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

    let dir = ws_doc_assets_dir(&state, &workspace_id);
    std::fs::create_dir_all(&dir).map_err(|e| {
        error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("mkdir: {}", e))
    })?;
    std::fs::write(dir.join(&file_name), &bytes).map_err(|e| {
        error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("write: {}", e))
    })?;
    {
        let db = state.db.lock();
        db.upsert_ws_doc_asset(&workspace_id, &file_name, bytes.len() as u64)
            .map_err(db_err)?;
    }
    let url = format!("/api/v1/workspaces/{}/docs/assets/{}", workspace_id, file_name);
    Ok(Json(json!({ "name": file_name, "size": bytes.len(), "url": url })))
}

pub async fn handle_ws_get_doc_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, file_name)): Path<(String, String)>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // Header auth only. The docs shell fetches these with the Authorization
    // header and swaps in blob URLs - no JWT in the query string.
    ws_member_check(&state, &headers, &workspace_id)?;
    safe_workspace_id(&workspace_id)?;
    safe_filename(&file_name)?;

    let path = ws_doc_assets_dir(&state, &workspace_id).join(&file_name);
    if !path.exists() {
        return Err(error_response(StatusCode::NOT_FOUND, "Asset not found"));
    }
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("Read: {}", e)))?;

    let mut resp = HeaderMap::new();
    resp.insert(header::CONTENT_TYPE, content_type_for(&file_name).parse().unwrap());
    resp.insert(header::CONTENT_LENGTH, bytes.len().into());
    // Private: workspace assets are membership-gated, so no shared caches.
    resp.insert(header::CACHE_CONTROL, "private, max-age=3600".parse().unwrap());
    harden_svg_response(&file_name, &mut resp);
    Ok((resp, bytes))
}

pub async fn handle_ws_delete_doc_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, file_name)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    ws_member_check(&state, &headers, &workspace_id)?;
    safe_workspace_id(&workspace_id)?;
    safe_filename(&file_name)?;
    let removed = {
        let db = state.db.lock();
        db.delete_ws_doc_asset(&workspace_id, &file_name).map_err(db_err)?
    };
    let _ = std::fs::remove_file(ws_doc_assets_dir(&state, &workspace_id).join(&file_name));
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
// SEO-facing SSR:
//   GET /docs               -> viewer shell with default head
//   GET /docs/{slug}        -> shell + rendered page (latest release), canonical
//   GET /docs/{tag}/{slug}  -> shell + rendered page (pinned release),
//                              canonical -> latest form when the slug exists there
//   GET /llms-full.txt      -> full latest-release markdown for AI crawlers
// Hash URLs (/docs#/{tag}/{slug}) stay the in-app navigation form; the path
// URLs above are what crawlers index. Default product only.
// ---------------------------------------------------------------------------

use axum::body::Bytes;
use std::sync::LazyLock;

use crate::website::{derive_description, html_escape, iso8601_z, render_body_html};

/// Canonical public base for documentation URLs (sitemap, canonical, llms).
pub(crate) const DOCS_PUBLIC_BASE: &str = "https://susi.lp-research.com";

const DOCS_HTML: &str = include_str!("docs.html");

const DOCS_DEFAULT_DESCRIPTION: &str = "Official FusionHub documentation: setup guides, \
headset use-cases, calibration tutorials and the full node reference for Xikaku's \
real-time sensor-fusion engine.";

static SHELL_DEFAULT: LazyLock<Bytes> = LazyLock::new(|| {
    let head = format!(
        "<title>FusionHub Documentation</title>\n<meta name=\"description\" content=\"{}\">\n",
        html_escape(DOCS_DEFAULT_DESCRIPTION),
    );
    Bytes::from(render_docs_shell(&head, ""))
});

fn render_docs_shell(head: &str, content: &str) -> String {
    DOCS_HTML
        .replacen("<!--SEO_HEAD-->", head, 1)
        .replacen("<!--SSR_CONTENT-->", content, 1)
}

fn docs_html_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, "text/html; charset=utf-8".parse().unwrap());
    h.insert(header::CACHE_CONTROL, "public, max-age=300".parse().unwrap());
    h
}

pub async fn handle_docs_shell() -> impl IntoResponse {
    (docs_html_headers(), SHELL_DEFAULT.clone())
}

/// Rewrite relative markdown link targets so SSR output is crawlable: bare
/// asset names -> the release asset endpoint, bare page slugs -> /docs/{slug}.
/// Absolute, anchor and mailto targets pass through untouched.
fn rewrite_doc_links(md: &str, tag: &str) -> String {
    const ASSET_EXT: &[&str] = &[".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".pdf"];
    let mut out = String::with_capacity(md.len() + 256);
    let mut rest = md;
    while let Some(p) = rest.find("](") {
        let start = p + 2;
        let Some(len) = rest[start..].find(')') else { break };
        let target = rest[start..start + len].trim();
        out.push_str(&rest[..start]);
        let lower = target.to_ascii_lowercase();
        if target.is_empty()
            || lower.starts_with("http://")
            || lower.starts_with("https://")
            || lower.starts_with("mailto:")
            || target.starts_with('/')
            || target.starts_with('#')
        {
            out.push_str(target);
        } else if ASSET_EXT.iter().any(|e| lower.ends_with(e)) {
            out.push_str(&format!("/api/v1/docs/{}/assets/{}", tag, target));
        } else {
            out.push_str(&format!("/docs/{}", target));
        }
        rest = &rest[start + len..];
    }
    out.push_str(rest);
    out
}

/// Drop viewer-only `[TOC]` markers.
fn strip_toc(body_md: &str) -> String {
    body_md
        .lines()
        .filter(|l| l.trim() != "[TOC]")
        .collect::<Vec<_>>()
        .join("\n")
}

/// Markdown as fed to the SSR renderer: no `[TOC]`, absolute link targets.
fn docs_md_for_ssr(body_md: &str, tag: &str) -> String {
    rewrite_doc_links(&strip_toc(body_md), tag)
}

fn docs_seo_head(title: &str, description: &str, canonical: &str, updated_at: &str, tag: &str, slug: &str) -> String {
    let full_title = format!("{} - FusionHub Documentation", title);
    let mut head = format!(
        concat!(
            "<title>{title}</title>\n",
            "<meta name=\"description\" content=\"{desc}\">\n",
            "<link rel=\"canonical\" href=\"{canonical}\">\n",
            "<meta property=\"og:type\" content=\"article\">\n",
            "<meta property=\"og:site_name\" content=\"FusionHub Documentation\">\n",
            "<meta property=\"og:title\" content=\"{title}\">\n",
            "<meta property=\"og:description\" content=\"{desc}\">\n",
            "<meta property=\"og:url\" content=\"{canonical}\">\n",
            "<meta name=\"twitter:card\" content=\"summary\">\n",
        ),
        title = html_escape(&full_title),
        desc = html_escape(description),
        canonical = html_escape(canonical),
    );
    let date_mod = if updated_at.is_empty() {
        String::new()
    } else {
        format!(",\"dateModified\":\"{}\"", html_escape(&iso8601_z(updated_at)))
    };
    head.push_str(&format!(
        concat!(
            r#"<script type="application/ld+json">{{"@context":"https://schema.org","#,
            r#""@type":"TechArticle","headline":"{h}","description":"{d}","#,
            r#""mainEntityOfPage":"{c}"{dm},"publisher":{{"@type":"Organization","#,
            r#""name":"Xikaku","url":"https://xikaku.com"}}}}</script>"#,
            "\n",
        ),
        h = html_escape(title),
        d = html_escape(description),
        c = html_escape(canonical),
        dm = date_mod,
    ));
    // One-shot boot info so the viewer routes to this page without a hash.
    // `<` is escaped so a pathological slug cannot close the script tag.
    let boot = json!({ "tag": tag, "slug": slug }).to_string().replace('<', "\\u003c");
    head.push_str(&format!("<script>window.__SSR={};</script>\n", boot));
    head
}

fn docs_ssr_not_found() -> axum::response::Response {
    (StatusCode::NOT_FOUND, docs_html_headers(), SHELL_DEFAULT.clone()).into_response()
}

fn latest_public_tag(state: &AppState) -> Option<String> {
    let db = state.db.lock();
    db.list_doc_releases(DEFAULT_PRODUCT)
        .ok()?
        .into_iter()
        .next()
        .map(|(_id, tag, ..)| tag)
}

fn docs_ssr_response(
    state: &Arc<AppState>,
    req_tag: Option<String>,
    slug: String,
) -> axum::response::Response {
    let Some(latest) = latest_public_tag(state) else { return docs_ssr_not_found() };
    let tag = req_tag.unwrap_or_else(|| latest.clone());
    if safe_tag(&tag).is_err() {
        return docs_ssr_not_found();
    }
    let (page, in_latest) = {
        let db = state.db.lock();
        let Ok(Some(release_id)) = db.get_release_by_product_tag(DEFAULT_PRODUCT, &tag) else {
            return docs_ssr_not_found();
        };
        let Ok(Some(page)) = db.get_doc_page(release_id, &slug) else {
            return docs_ssr_not_found();
        };
        let in_latest = if tag == latest {
            true
        } else {
            db.get_release_by_product_tag(DEFAULT_PRODUCT, &latest)
                .ok()
                .flatten()
                .and_then(|id| db.get_doc_page(id, &slug).ok().flatten())
                .is_some()
        };
        (page, in_latest)
    };
    let (title, body_md, _parent, _ord, updated_at) = page;
    // Older-release URLs canonicalize to the latest form so search engines
    // index one URL per page.
    let canonical = if in_latest {
        format!("{}/docs/{}", DOCS_PUBLIC_BASE, slug)
    } else {
        format!("{}/docs/{}/{}", DOCS_PUBLIC_BASE, tag, slug)
    };
    let description = {
        let d = derive_description(&strip_toc(&body_md));
        if d.is_empty() { DOCS_DEFAULT_DESCRIPTION.to_string() } else { d }
    };
    let head = docs_seo_head(&title, &description, &canonical, &updated_at, &tag, &slug);
    let content = render_body_html(&docs_md_for_ssr(&body_md, &tag));
    let html = render_docs_shell(&head, &content);
    (docs_html_headers(), Bytes::from(html)).into_response()
}

pub async fn handle_docs_ssr_latest(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
) -> axum::response::Response {
    docs_ssr_response(&state, None, slug)
}

pub async fn handle_docs_ssr_tagged(
    State(state): State<Arc<AppState>>,
    Path((tag, slug)): Path<(String, String)>,
) -> axum::response::Response {
    docs_ssr_response(&state, Some(tag), slug)
}

/// (url, updated_at) for every page of the latest public release; consumed by
/// the sitemap when it is served on the docs host.
pub(crate) fn docs_sitemap_entries(state: &AppState) -> Vec<(String, String)> {
    let Some(tag) = latest_public_tag(state) else { return Vec::new() };
    let db = state.db.lock();
    let Ok(Some(release_id)) = db.get_release_by_product_tag(DEFAULT_PRODUCT, &tag) else {
        return Vec::new();
    };
    let Ok(pages) = db.list_doc_pages(release_id) else { return Vec::new() };
    pages
        .into_iter()
        .map(|(slug, _t, _p, _o, upd)| (format!("{}/docs/{}", DOCS_PUBLIC_BASE, slug), upd))
        .collect()
}

/// "## FusionHub Documentation" section appended to llms.txt on every host.
pub(crate) fn docs_llms_section(state: &AppState) -> String {
    let Some(tag) = latest_public_tag(state) else { return String::new() };
    let db = state.db.lock();
    let Ok(Some(release_id)) = db.get_release_by_product_tag(DEFAULT_PRODUCT, &tag) else {
        return String::new();
    };
    let Ok(pages) = db.list_doc_pages(release_id) else { return String::new() };
    let mut out = String::from("\n## FusionHub Documentation\n");
    for (slug, title, _parent, _ord, _upd) in &pages {
        let desc = db
            .get_doc_page(release_id, slug)
            .ok()
            .flatten()
            .map(|(_t, body, ..)| derive_description(&strip_toc(&body)))
            .unwrap_or_default();
        let url = format!("{}/docs/{}", DOCS_PUBLIC_BASE, slug);
        if desc.is_empty() {
            out.push_str(&format!("- [{}]({})\n", title, url));
        } else {
            out.push_str(&format!("- [{}]({}): {}\n", title, url, desc));
        }
    }
    out.push_str(&format!(
        "\nThe complete documentation as a single markdown file: {}/llms-full.txt\n",
        DOCS_PUBLIC_BASE,
    ));
    out
}

/// Every page of the latest public release as one markdown document.
pub async fn handle_llms_full_txt(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, "text/plain; charset=utf-8".parse().unwrap());
    h.insert(header::CACHE_CONTROL, "public, max-age=600".parse().unwrap());
    let mut body = String::new();
    if let Some(tag) = latest_public_tag(&state) {
        let db = state.db.lock();
        if let Ok(Some(release_id)) = db.get_release_by_product_tag(DEFAULT_PRODUCT, &tag) {
            body.push_str(&format!(
                "# FusionHub Documentation ({})\n\nComplete documentation for FusionHub, \
                 Xikaku's real-time sensor-fusion engine. Canonical page URLs follow the \
                 pattern {}/docs/<slug>.\n",
                tag, DOCS_PUBLIC_BASE,
            ));
            if let Ok(pages) = db.list_doc_pages(release_id) {
                for (slug, title, _parent, _ord, _upd) in &pages {
                    if let Ok(Some((_t, body_md, ..))) = db.get_doc_page(release_id, slug) {
                        body.push_str(&format!(
                            "\n---\n\n# {}\nURL: {}/docs/{}\n\n{}\n",
                            title, DOCS_PUBLIC_BASE, slug, body_md,
                        ));
                    }
                }
            }
        }
    }
    (h, body)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_doc_links_classifies_targets() {
        let md = "![](shot.png) [other page](other-page) [ext](https://x.y/z) [anchor](#sec) [abs](/docs/foo)";
        let out = rewrite_doc_links(md, "v1");
        assert!(out.contains("](/api/v1/docs/v1/assets/shot.png)"));
        assert!(out.contains("](/docs/other-page)"));
        assert!(out.contains("](https://x.y/z)"));
        assert!(out.contains("](#sec)"));
        assert!(out.contains("](/docs/foo)"));
    }

    #[test]
    fn docs_md_for_ssr_strips_toc() {
        let out = docs_md_for_ssr("# T\n[TOC]\n\nBody.", "v1");
        assert!(!out.contains("[TOC]"));
        assert!(out.contains("Body."));
    }

    #[test]
    fn docs_seo_head_has_canonical_and_boot() {
        let h = docs_seo_head("Page", "Desc.", "https://susi.lp-research.com/docs/page", "2026-07-21 10:00:00", "v1", "page");
        assert!(h.contains("<link rel=\"canonical\" href=\"https://susi.lp-research.com/docs/page\">"));
        assert!(h.contains("Page - FusionHub Documentation</title>"));
        assert!(h.contains("window.__SSR={\"slug\":\"page\",\"tag\":\"v1\"}"));
        assert!(h.contains("\"dateModified\":\"2026-07-21T10:00:00Z\""));
    }

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
