//! Public website endpoints.
//!
//! Simple single-site page store at `/api/v1/website/...`. Public reads for
//! viewing pages + assets; admin writes (JWT/API-token) for editing. Unlike
//! `docs`, there's no release concept and no pipeline/user origin split —
//! all content is hand-authored via the in-browser editor.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant};

use axum::{
    body::Bytes,
    extract::{Multipart, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use susi_core::error::LicenseError;

use crate::docs::{safe_filename};
use crate::{error_response, require_admin_full, validate_principal, AppState, ErrorResponse};

fn assets_dir(state: &AppState) -> std::path::PathBuf {
    std::path::Path::new(&state.data_dir).join("website").join("assets")
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

fn safe_slug(slug: &str) -> Result<&str, (StatusCode, Json<ErrorResponse>)> {
    if slug.is_empty()
        || slug.contains('/')
        || slug.contains('\\')
        || slug.contains('\0')
    {
        return Err(error_response(StatusCode::BAD_REQUEST, "Invalid slug"));
    }
    Ok(slug)
}

// ---------------------------------------------------------------------------
// Public read endpoints
// ---------------------------------------------------------------------------

pub async fn handle_list_pages(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let db = state.db.lock().unwrap();
    let pages = db.list_website_pages().map_err(db_err)?;
    let assets = db.list_website_assets().map_err(db_err)?;
    let pages_json: Vec<_> = pages
        .into_iter()
        .map(|(slug, title, parent_slug, ord, updated_at, meta_description)| {
            json!({
                "slug": slug,
                "title": title,
                "parent_slug": parent_slug,
                "ord": ord,
                "updated_at": updated_at,
                "meta_description": meta_description,
            })
        })
        .collect();
    let assets_json: Vec<_> = assets
        .into_iter()
        .map(|(name, size)| json!({ "name": name, "size": size }))
        .collect();
    Ok(Json(json!({
        "pages": pages_json,
        "assets": assets_json,
    })))
}

pub async fn handle_get_page(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    safe_slug(&slug)?;
    let db = state.db.lock().unwrap();
    let page = db
        .get_website_page(&slug)
        .map_err(db_err)?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Page not found"))?;
    let (title, body_md, parent_slug, ord, updated_at, meta_description) = page;
    Ok(Json(json!({
        "slug": slug,
        "title": title,
        "body_md": body_md,
        "parent_slug": parent_slug,
        "ord": ord,
        "updated_at": updated_at,
        "meta_description": meta_description,
    })))
}

pub async fn handle_get_asset(
    State(state): State<Arc<AppState>>,
    Path(file_name): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    safe_filename(&file_name)?;
    let path = assets_dir(&state).join(&file_name);
    if !path.exists() {
        return Err(error_response(StatusCode::NOT_FOUND, "Asset not found"));
    }
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("Read: {}", e)))?;

    let mut resp = HeaderMap::new();
    resp.insert(header::CONTENT_TYPE, content_type_for(&file_name).parse().unwrap());
    resp.insert(header::CONTENT_LENGTH, bytes.len().into());
    resp.insert(header::CACHE_CONTROL, "public, max-age=300".parse().unwrap());
    Ok((resp, bytes))
}

// ---------------------------------------------------------------------------
// Admin write endpoints
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct UpsertPageRequest {
    pub title: String,
    pub body_md: String,
    #[serde(default)]
    pub parent_slug: Option<String>,
    #[serde(default)]
    pub ord: i64,
    #[serde(default)]
    pub meta_description: String,
}

pub async fn handle_upsert_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Json(req): Json<UpsertPageRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    safe_slug(&slug)?;

    let (id, is_home) = {
        let mut db = state.db.lock().unwrap();
        let id = db.upsert_website_page(
            &slug,
            &req.title,
            &req.body_md,
            req.parent_slug.as_deref(),
            req.ord,
            &req.meta_description,
            Some(&principal.username),
        )
        .map_err(db_err)?;
        let pages = db.list_website_pages().unwrap_or_default();
        let is_home = first_default_slug(&pages) == Some(slug.as_str());
        (id, is_home)
    };
    invalidate_page_cache();
    ping_indexnow(&state, vec![canonical_page_url(&slug, is_home)]);
    Ok(Json(json!({ "id": id, "slug": slug })))
}

// ---------------------------------------------------------------------------
// Page revisions (history)
// ---------------------------------------------------------------------------

pub async fn handle_list_page_revisions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    safe_slug(&slug)?;
    let db = state.db.lock().unwrap();
    let rows = db.list_page_revisions(&slug).map_err(db_err)?;
    let revisions: Vec<_> = rows
        .into_iter()
        .map(|(id, captured_at, author, title, body_len)| json!({
            "id": id,
            "captured_at": captured_at,
            "author": author,
            "title": title,
            "body_length": body_len,
        }))
        .collect();
    Ok(Json(json!({ "slug": slug, "revisions": revisions })))
}

pub async fn handle_get_page_revision(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((slug, id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    safe_slug(&slug)?;
    let db = state.db.lock().unwrap();
    let row = db
        .get_page_revision(&slug, id)
        .map_err(db_err)?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Revision not found"))?;
    let (title, body_md, parent_slug, ord, captured_at, author) = row;
    Ok(Json(json!({
        "slug": slug, "id": id,
        "title": title, "body_md": body_md,
        "parent_slug": parent_slug, "ord": ord,
        "captured_at": captured_at, "author": author,
    })))
}

pub async fn handle_restore_page_revision(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((slug, id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    safe_slug(&slug)?;
    let mut db = state.db.lock().unwrap();
    let rev = db
        .get_page_revision(&slug, id)
        .map_err(db_err)?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Revision not found"))?;
    let (title, body_md, parent_slug, ord, _captured_at, _author) = rev;
    // Preserve the current meta_description when restoring prior body/title.
    let existing_meta = db
        .get_website_page(&slug)
        .map_err(db_err)?
        .map(|(_t, _b, _p, _o, _u, m)| m)
        .unwrap_or_default();
    let new_id = db.upsert_website_page(
        &slug, &title, &body_md, parent_slug.as_deref(), ord,
        &existing_meta,
        Some(&principal.username),
    ).map_err(db_err)?;
    let pages = db.list_website_pages().unwrap_or_default();
    let is_home = first_default_slug(&pages) == Some(slug.as_str());
    drop(db);
    invalidate_page_cache();
    ping_indexnow(&state, vec![canonical_page_url(&slug, is_home)]);
    Ok(Json(json!({ "id": new_id, "slug": slug, "restored_from": id })))
}

// ---------------------------------------------------------------------------
// Asset admin
// ---------------------------------------------------------------------------

pub async fn handle_list_assets_with_usage(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    let db = state.db.lock().unwrap();
    let rows = db.list_website_assets_with_usage().map_err(db_err)?;
    let assets: Vec<_> = rows
        .into_iter()
        .map(|(name, size, usage_count, pages_csv)| {
            let pages: Vec<&str> = if pages_csv.is_empty() {
                Vec::new()
            } else {
                pages_csv.split(',').collect()
            };
            json!({
                "name": name, "size": size,
                "usage_count": usage_count,
                "pages": pages,
            })
        })
        .collect();
    Ok(Json(json!({ "assets": assets })))
}

#[derive(Deserialize)]
pub struct RenameAssetRequest {
    pub new_name: String,
}

pub async fn handle_rename_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(file_name): Path<String>,
    Json(req): Json<RenameAssetRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    safe_filename(&file_name)?;
    let new_name = req.new_name.trim();
    safe_filename(new_name)?;

    let (ok, n_pages) = {
        let mut db = state.db.lock().unwrap();
        db.rename_website_asset(&file_name, new_name).map_err(|e| {
            let msg = e.to_string();
            if msg.contains("already exists") {
                error_response(StatusCode::CONFLICT, &msg)
            } else {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, &msg)
            }
        })?
    };
    if !ok {
        return Err(error_response(StatusCode::NOT_FOUND, "Asset not found"));
    }
    // Move file on disk.
    let dir = assets_dir(&state);
    let old_path = dir.join(&file_name);
    let new_path = dir.join(new_name);
    if old_path.exists() {
        if let Err(e) = std::fs::rename(&old_path, &new_path) {
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("fs rename: {}", e),
            ));
        }
    }
    // Asset URLs may appear in any page's body; bust the SSR cache so the
    // updated filename is reflected on next request.
    if n_pages > 0 {
        invalidate_page_cache();
    }
    Ok(Json(json!({
        "name": new_name,
        "pages_updated": n_pages,
    })))
}

#[derive(Deserialize)]
pub struct RenamePageRequest {
    pub new_slug: String,
}

pub async fn handle_rename_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Json(req): Json<RenamePageRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    let new_slug = req.new_slug.trim();
    if new_slug.is_empty() || new_slug.contains('/') || new_slug.contains('\\') || new_slug.contains('\0') {
        return Err(error_response(StatusCode::BAD_REQUEST, "Invalid slug"));
    }

    let result = {
        let mut db = state.db.lock().unwrap();
        db.rename_website_page(&slug, new_slug)
    };
    match result {
        Ok(true) => {
            invalidate_page_cache();
            ping_indexnow(
                &state,
                vec![
                    canonical_page_url(&slug, false),
                    canonical_page_url(new_slug, false),
                ],
            );
            Ok(Json(json!({ "slug": new_slug })))
        }
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

pub async fn handle_delete_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    safe_slug(&slug)?;

    let removed = {
        let db = state.db.lock().unwrap();
        db.delete_website_page(&slug).map_err(db_err)?
    };
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Page not found"));
    }
    invalidate_page_cache();
    ping_indexnow(&state, vec![canonical_page_url(&slug, false)]);
    Ok(Json(json!({ "status": "OK" })))
}

pub async fn handle_upload_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

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

    let dir = assets_dir(&state);
    std::fs::create_dir_all(&dir).map_err(|e| {
        error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("mkdir: {}", e))
    })?;
    let path = dir.join(&file_name);
    std::fs::write(&path, &bytes).map_err(|e| {
        error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("write: {}", e))
    })?;

    {
        let db = state.db.lock().unwrap();
        db.upsert_website_asset(&file_name, bytes.len() as u64)
            .map_err(db_err)?;
    }

    let url = format!("/api/v1/website/assets/{}", file_name);
    log::info!("Website asset uploaded: {} ({} bytes)", file_name, bytes.len());
    Ok(Json(json!({ "name": file_name, "size": bytes.len(), "url": url })))
}

pub async fn handle_delete_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(file_name): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    safe_filename(&file_name)?;

    let removed = {
        let db = state.db.lock().unwrap();
        db.delete_website_asset(&file_name).map_err(db_err)?
    };
    let _ = std::fs::remove_file(assets_dir(&state).join(&file_name));
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Asset not found"));
    }
    Ok(Json(json!({ "status": "OK" })))
}

// ---------------------------------------------------------------------------
// Public SEO-facing endpoints:
//   GET /site              -> HTML with head injected for default page
//   GET /site/{slug}       -> HTML with head injected for {slug}
//   GET /robots.txt        -> static allow-list for AI crawlers + sitemap
//   GET /sitemap.xml       -> auto from website_pages
//   GET /llms.txt          -> auto from website_pages (llms.txt convention)
// ---------------------------------------------------------------------------

pub(crate) const WEBSITE_HTML: &str = include_str!("website.html");
const SITE_NAME: &str = "Xikaku";
const SITE_TAGLINE: &str = "Sight beyond Sight";
const ORG_LEGAL_NAME: &str = "LP-Research Inc.";
const ORG_ADDR_LOCALITY: &str = "Tokyo";
const ORG_ADDR_COUNTRY: &str = "JP";
const CONTACT_EMAIL: &str = "info@xikaku.com";

/// Canonical public domain. All canonical/og:url/sitemap/breadcrumb URLs
/// point here regardless of which host served the request, consolidating
/// SEO equity to xikaku.com. Clean slug form: /{slug} (no /site/ prefix).
const PUBLIC_BASE: &str = "https://xikaku.com";

/// Brand asset URLs. og-image is the 1200x630 social-card; logo is the
/// horizontal wordmark used by Google's knowledge-panel via Organization.logo.
const LOGO_URL: &str = "https://xikaku.com/static/logo.png";
const OG_IMAGE_URL: &str = "https://xikaku.com/static/og-image.png";

/// Public profile URLs included as Organization.sameAs in JSON-LD.
const SOCIAL_LINKS: &[&str] = &[
    "https://github.com/xikaku-inc",
    "https://www.linkedin.com/company/xikaku",
];

/// Embedded brand assets, served at /static/* (and /favicon.ico).
const LOGO_PNG: &[u8] = include_bytes!("assets/xikaku-logo.png");
const LOGO_DARK_PNG: &[u8] = include_bytes!("assets/xikaku-logo-dark.png");
const OG_IMAGE_PNG: &[u8] = include_bytes!("assets/xikaku-og-image.png");
const ICON_PNG: &[u8] = include_bytes!("assets/xikaku-icon.png");
const FAVICON_32_PNG: &[u8] = include_bytes!("assets/xikaku-favicon-32.png");
const FAVICON_180_PNG: &[u8] = include_bytes!("assets/xikaku-favicon-180.png");
const FAVICON_ICO: &[u8] = include_bytes!("assets/favicon.ico");

// SEO blocks that are identical across every page. Build once at startup so
// the per-request render path doesn't re-`format!` ~1 KB of JSON-LD.
static SAME_AS_JOINED: LazyLock<String> = LazyLock::new(|| {
    SOCIAL_LINKS
        .iter()
        .map(|u| format!("\"{}\"", html_escape(u)))
        .collect::<Vec<_>>()
        .join(",")
});

static ORG_JSONLD: LazyLock<String> = LazyLock::new(|| {
    format!(
        r#"{{"@context":"https://schema.org","@type":"Organization","name":"{name}","legalName":"{legal}","url":"{url}","logo":"{logo}","slogan":"{slogan}","email":"{email}","address":{{"@type":"PostalAddress","addressLocality":"{loc}","addressCountry":"{country}"}},"contactPoint":{{"@type":"ContactPoint","contactType":"customer support","email":"{email}","areaServed":["US","CA"]}},"sameAs":[{same_as}]}}"#,
        name = html_escape(SITE_NAME),
        legal = html_escape(ORG_LEGAL_NAME),
        url = html_escape(PUBLIC_BASE),
        logo = html_escape(LOGO_URL),
        slogan = html_escape(SITE_TAGLINE),
        email = html_escape(CONTACT_EMAIL),
        loc = html_escape(ORG_ADDR_LOCALITY),
        country = html_escape(ORG_ADDR_COUNTRY),
        same_as = &*SAME_AS_JOINED,
    )
});

// Per-slug rendered HTML cache. The full SSR pipeline (DB reads, two pulldown
// passes, JSON-LD format!, three replacen over a 100 KB shell) takes hundreds
// of µs to a few ms per hit; this cache turns 95%+ of public traffic into a
// hashmap lookup. Bounded TTL covers admin edits without explicit
// invalidation; explicit invalidation kicks in on writes for immediate effect.
const PAGE_CACHE_TTL: Duration = Duration::from_secs(300);
const PAGE_CACHE_MAX: usize = 1024;

struct CachedPage {
    inserted: Instant,
    html: Bytes,
}

static PAGE_CACHE: LazyLock<RwLock<HashMap<String, CachedPage>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

fn page_cache_get(key: &str) -> Option<Bytes> {
    let cache = PAGE_CACHE.read().ok()?;
    let entry = cache.get(key)?;
    if entry.inserted.elapsed() < PAGE_CACHE_TTL {
        Some(entry.html.clone())
    } else {
        None
    }
}

fn page_cache_put(key: String, html: Bytes) {
    let Ok(mut cache) = PAGE_CACHE.write() else { return };
    if cache.len() >= PAGE_CACHE_MAX {
        let now = Instant::now();
        cache.retain(|_, v| now.duration_since(v.inserted) < PAGE_CACHE_TTL);
    }
    cache.insert(key, CachedPage { inserted: Instant::now(), html });
}

/// Drop every cached SSR page. Called by every admin write that affects
/// content, schema, or analytics so the next request re-renders fresh.
pub fn invalidate_page_cache() {
    if let Ok(mut cache) = PAGE_CACHE.write() {
        cache.clear();
    }
}

// Returns the static byte slice unchanged — axum's IntoResponse for
// `&'static [u8]` wraps it via `Body::from_static`, so no per-request copy.
fn cached_image(content_type: &'static str, bytes: &'static [u8]) -> (HeaderMap, &'static [u8]) {
    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    h.insert(header::CACHE_CONTROL, "public, max-age=86400, immutable".parse().unwrap());
    (h, bytes)
}

pub async fn handle_logo_png() -> impl IntoResponse { cached_image("image/png", LOGO_PNG) }
pub async fn handle_logo_dark_png() -> impl IntoResponse { cached_image("image/png", LOGO_DARK_PNG) }
pub async fn handle_og_image_png() -> impl IntoResponse { cached_image("image/png", OG_IMAGE_PNG) }
pub async fn handle_icon_png() -> impl IntoResponse { cached_image("image/png", ICON_PNG) }
pub async fn handle_favicon_32_png() -> impl IntoResponse { cached_image("image/png", FAVICON_32_PNG) }
pub async fn handle_favicon_180_png() -> impl IntoResponse { cached_image("image/png", FAVICON_180_PNG) }
pub async fn handle_favicon_ico() -> impl IntoResponse { cached_image("image/x-icon", FAVICON_ICO) }

/// Build the canonical URL for a website page. The home slug renders as the
/// bare domain (`https://xikaku.com/`); other slugs render as `/{slug}`.
fn canonical_page_url(slug: &str, is_home: bool) -> String {
    if is_home {
        format!("{}/", PUBLIC_BASE)
    } else {
        format!("{}/{}", PUBLIC_BASE, slug)
    }
}

/// Convert SQLite's "YYYY-MM-DD HH:MM:SS" timestamp to ISO 8601 with a Z
/// suffix so schema.org consumers (Google, Bing) parse it correctly.
fn iso8601_z(sqlite_ts: &str) -> String {
    if sqlite_ts.is_empty() { return String::new(); }
    if sqlite_ts.contains('T') { return sqlite_ts.to_string(); }
    format!("{}Z", sqlite_ts.replacen(' ', "T", 1))
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn xml_escape(s: &str) -> String { html_escape(s) }

/// Strip markdown to a plain-text description. Good-enough heuristic for SEO:
/// drop ATX headings, images, code fences, HTML tags, and link syntax, collapse
/// whitespace, take the first non-empty paragraph, cap length.
fn derive_description(body_md: &str) -> String {
    let mut cleaned = String::with_capacity(body_md.len());
    let mut in_code_fence = false;
    for line in body_md.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            in_code_fence = !in_code_fence;
            continue;
        }
        if in_code_fence { continue; }
        if trimmed.starts_with('#') { continue; }
        if trimmed.starts_with("![") { continue; }
        if trimmed.starts_with('>') { continue; }
        cleaned.push_str(line);
        cleaned.push('\n');
    }
    // Collapse markdown link syntax [text](url) -> text, strip inline emphasis,
    // drop HTML tags. Char-based to stay UTF-8 safe.
    let mut out = String::with_capacity(cleaned.len());
    let chars: Vec<char> = cleaned.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '[' {
            if let Some(close) = chars[i + 1..].iter().position(|&x| x == ']') {
                let close_idx = i + 1 + close;
                if close_idx + 1 < chars.len() && chars[close_idx + 1] == '(' {
                    if let Some(paren) = chars[close_idx + 2..].iter().position(|&x| x == ')') {
                        out.extend(&chars[i + 1..close_idx]);
                        i = close_idx + 2 + paren + 1;
                        continue;
                    }
                }
            }
        }
        if c == '*' || c == '_' || c == '`' { i += 1; continue; }
        if c == '<' {
            if let Some(close) = chars[i + 1..].iter().position(|&x| x == '>') {
                i += 1 + close + 1; continue;
            }
        }
        out.push(c);
        i += 1;
    }
    // First non-empty paragraph, whitespace-collapsed.
    let mut first_para = String::new();
    for para in out.split("\n\n") {
        let collapsed: String = para.split_whitespace().collect::<Vec<_>>().join(" ");
        if !collapsed.is_empty() {
            first_para = collapsed;
            break;
        }
    }
    if first_para.chars().count() > 300 {
        let truncated: String = first_para.chars().take(297).collect();
        // Prefer ending on a sentence boundary so the description reads as a
        // complete thought, not "...software. Pick a…". Fall back to a word
        // boundary if no sentence end is reachable in the budget.
        let sentence_end = [". ", "! ", "? "]
            .iter()
            .filter_map(|sep| truncated.rfind(sep).map(|i| i + 1))
            .max();
        if let Some(cut) = sentence_end {
            if cut > 80 {
                return truncated[..cut].trim_end().to_string();
            }
        }
        let cut = truncated.rfind(' ').unwrap_or(truncated.len());
        return format!("{}…", &truncated[..cut]);
    }
    first_para
}

/// Extract the first image URL from a markdown body. Used to set per-page
/// `og:image` so social previews don't all share the generic site card.
/// Returns the absolute URL when the source is already absolute, or
/// `{PUBLIC_BASE}/{path}` when relative.
fn first_image_url(body_md: &str) -> Option<String> {
    use pulldown_cmark::{Event, Parser, Tag};
    for ev in Parser::new(body_md) {
        if let Event::Start(Tag::Image { dest_url, .. }) = ev {
            let s = dest_url.into_string();
            if s.is_empty() { continue; }
            if s.starts_with("http://") || s.starts_with("https://") {
                return Some(s);
            }
            let path = if s.starts_with('/') { s } else { format!("/{}", s) };
            return Some(format!("{}{}", PUBLIC_BASE, path));
        }
    }
    None
}

/// Rewrite pandoc-style image attribute spans (`![alt](url){width=Npx .class}`)
/// into raw HTML `<img>` tags so the attributes survive into the SSR body.
/// pulldown-cmark doesn't understand pandoc syntax; without this the `{...}`
/// either rendered as literal text or (when only stripped) dropped classes
/// like `.logo-light`/`.logo-dark` that the page CSS uses to pick the right
/// asset for the active theme — causing both logos to flash on load.
fn rewrite_pandoc_image_attrs(body_md: &str) -> String {
    let bytes = body_md.as_bytes();
    let mut out = String::with_capacity(body_md.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'!'
            && i + 1 < bytes.len()
            && bytes[i + 1] == b'['
            && (i == 0 || bytes[i - 1] != b'\\')
        {
            if let Some((consumed, replacement)) = try_rewrite_image_at(&body_md[i..]) {
                out.push_str(&replacement);
                i += consumed;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Try to parse `![alt](url){attrs}?` starting at the beginning of `s`.
/// Returns (bytes consumed, replacement string) when matched, else None.
/// When no `{attrs}` follows (or no recognized attrs are present) the
/// original markdown image syntax is preserved so pulldown-cmark renders
/// it normally.
fn try_rewrite_image_at(s: &str) -> Option<(usize, String)> {
    let bytes = s.as_bytes();
    if bytes.len() < 5 || bytes[0] != b'!' || bytes[1] != b'[' {
        return None;
    }
    let alt_end = bytes[2..].iter().position(|&b| b == b']' || b == b'\n')?;
    if bytes[2 + alt_end] != b']' {
        return None;
    }
    let after_alt = 2 + alt_end + 1;
    if after_alt >= bytes.len() || bytes[after_alt] != b'(' {
        return None;
    }
    let url_start = after_alt + 1;
    let url_end_off = bytes[url_start..]
        .iter()
        .position(|&b| b == b')' || b == b'\n')?;
    if bytes[url_start + url_end_off] != b')' {
        return None;
    }
    let alt = &s[2..2 + alt_end];
    let url = &s[url_start..url_start + url_end_off];
    let mut consumed = url_start + url_end_off + 1;

    if consumed >= bytes.len() || bytes[consumed] != b'{' {
        return None;
    }
    let attrs_off = bytes[consumed + 1..]
        .iter()
        .position(|&b| b == b'}' || b == b'\n')?;
    if bytes[consumed + 1 + attrs_off] != b'}' {
        return None;
    }
    let attrs = &s[consumed + 1..consumed + 1 + attrs_off];
    consumed += 1 + attrs_off + 1;

    let mut classes: Vec<&str> = Vec::new();
    let mut width: Option<&str> = None;
    let mut height: Option<&str> = None;
    for tok in attrs.split_whitespace() {
        if let Some(c) = tok.strip_prefix('.') {
            if !c.is_empty()
                && c.chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
            {
                classes.push(c);
            }
        } else if let Some(v) = tok.strip_prefix("width=") {
            width = Some(v.trim_matches('"'));
        } else if let Some(v) = tok.strip_prefix("height=") {
            height = Some(v.trim_matches('"'));
        }
    }

    if classes.is_empty() && width.is_none() && height.is_none() {
        return Some((consumed, format!("![{}]({})", alt, url)));
    }

    let mut html = format!(
        r#"<img alt="{}" src="{}""#,
        html_escape(alt),
        html_escape(url),
    );
    if let Some(w) = width {
        html.push_str(&format!(r#" width="{}""#, html_escape(w)));
    }
    if let Some(h) = height {
        html.push_str(&format!(r#" height="{}""#, html_escape(h)));
    }
    if !classes.is_empty() {
        html.push_str(&format!(r#" class="{}""#, html_escape(&classes.join(" "))));
    }
    html.push('>');
    Some((consumed, html))
}

/// Render markdown body into HTML for SSR injection. Pages are admin-edited
/// so we don't sanitize — we just render with tables, footnotes, strikethrough,
/// and task lists enabled. Relative image src/href stay relative; the existing
/// page CSS handles image sizing.
fn render_body_html(body_md: &str) -> String {
    use pulldown_cmark::{html, Options, Parser};
    let cleaned = rewrite_pandoc_image_attrs(body_md);
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_FOOTNOTES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_TASKLISTS);
    opts.insert(Options::ENABLE_SMART_PUNCTUATION);
    let parser = Parser::new_ext(&cleaned, opts);
    let mut out = String::with_capacity(cleaned.len() * 2);
    html::push_html(&mut out, parser);
    out
}

fn first_default_slug(pages: &[(String, String, Option<String>, i64, String, String)]) -> Option<&str> {
    let mut top: Vec<&(String, String, Option<String>, i64, String, String)> =
        pages.iter().filter(|p| p.2.is_none()).collect();
    top.sort_by(|a, b| a.3.cmp(&b.3).then_with(|| a.1.cmp(&b.1)));
    top.first().map(|p| p.0.as_str()).or_else(|| pages.first().map(|p| p.0.as_str()))
}

fn build_breadcrumbs(
    pages: &[(String, String, Option<String>, i64, String, String)],
    slug: &str,
    home_slug: Option<&str>,
) -> String {
    let by_slug: std::collections::HashMap<&str, &(String, String, Option<String>, i64, String, String)> =
        pages.iter().map(|p| (p.0.as_str(), p)).collect();
    let mut chain: Vec<&(String, String, Option<String>, i64, String, String)> = Vec::new();
    let mut cur = by_slug.get(slug).copied();
    while let Some(p) = cur {
        chain.push(p);
        cur = p.2.as_deref().and_then(|pp| by_slug.get(pp).copied());
    }
    chain.reverse();
    // Prepend Home so deep pages emit Home › Sensors › LPMS-B2 instead of
    // starting at Sensors. Skip when we're already on the home page or the
    // chain root already is home.
    let home_already = chain.first().map(|p| Some(p.0.as_str()) == home_slug).unwrap_or(false);
    let mut items: Vec<String> = Vec::with_capacity(chain.len() + 1);
    let mut pos = 1;
    if !home_already {
        if let Some(hs) = home_slug {
            if let Some(home_page) = by_slug.get(hs) {
                items.push(format!(
                    r#"{{"@type":"ListItem","position":{},"name":"{}","item":"{}"}}"#,
                    pos,
                    html_escape(&home_page.1),
                    html_escape(&canonical_page_url(hs, true)),
                ));
                pos += 1;
            }
        }
    }
    for p in &chain {
        let is_home = home_slug == Some(p.0.as_str());
        items.push(format!(
            r#"{{"@type":"ListItem","position":{},"name":"{}","item":"{}"}}"#,
            pos,
            html_escape(&p.1),
            html_escape(&canonical_page_url(&p.0, is_home)),
        ));
        pos += 1;
    }
    format!(
        r#"{{"@context":"https://schema.org","@type":"BreadcrumbList","itemListElement":[{}]}}"#,
        items.join(",")
    )
}

fn render_seo_head(
    slug: &str,
    page_title: &str,
    description: &str,
    updated_at: &str,
    og_image_override: Option<&str>,
    pages: &[(String, String, Option<String>, i64, String, String)],
    products: &[(String, String, String, i64, String, Option<String>, String, bool, i64, String)],
) -> String {
    let home_slug = first_default_slug(pages);
    let is_home = home_slug == Some(slug);
    let canonical = canonical_page_url(slug, is_home);
    let full_title = if is_home {
        format!("{} — {}", SITE_NAME, SITE_TAGLINE)
    } else {
        format!("{} — {}", page_title, SITE_NAME)
    };

    // Organization JSON-LD is identical across every page — built once at
    // module init by `ORG_JSONLD: LazyLock<String>`.
    let org_jsonld: &str = &ORG_JSONLD;

    // Per-page schema: WebSite (with sitelinks search action stub) for the
    // home page, WebPage for everything else. This matches what Google's
    // structured-data parser expects and powers rich results.
    let date_modified = iso8601_z(updated_at);
    let page_jsonld = if is_home {
        format!(
            r#"{{"@context":"https://schema.org","@type":"WebSite","name":"{name}","url":"{url}","description":"{desc}","publisher":{{"@type":"Organization","name":"{name}","url":"{url}"}}}}"#,
            name = html_escape(SITE_NAME),
            url = html_escape(PUBLIC_BASE),
            desc = html_escape(description),
        )
    } else {
        format!(
            r#"{{"@context":"https://schema.org","@type":"WebPage","name":"{title}","description":"{desc}","url":"{url}","dateModified":"{date}","isPartOf":{{"@type":"WebSite","name":"{site}","url":"{base}"}},"publisher":{{"@type":"Organization","name":"{site}","url":"{base}"}}}}"#,
            title = html_escape(page_title),
            desc = html_escape(description),
            url = html_escape(&canonical),
            date = html_escape(&date_modified),
            site = html_escape(SITE_NAME),
            base = html_escape(PUBLIC_BASE),
        )
    };

    let breadcrumb_jsonld = build_breadcrumbs(pages, slug, home_slug);

    // Product schema: emit one Product per matching shop SKU. A page slug
    // like `lpms-curs3` matches every shop product whose SKU starts with the
    // slug (e.g., lpms-curs3-can, lpms-curs3-rs232) so the page describes the
    // family with one Offer per variant.
    let product_blocks = build_product_jsonld(slug, products);

    let og_image = og_image_override.unwrap_or(OG_IMAGE_URL);
    // Per-page hero image keeps standard 1200x630 dimensions only when we
    // fall back to the bundled site card; for body-derived images we omit
    // the dimensions to avoid lying about the source image.
    let omit_og_dims = og_image_override.is_some();

    let og_dims = if omit_og_dims {
        String::new()
    } else {
        "<meta property=\"og:image:width\" content=\"1200\">\n\
         <meta property=\"og:image:height\" content=\"630\">\n".to_string()
    };
    let mut head = format!(
        concat!(
            "<title>{title}</title>\n",
            "<meta name=\"description\" content=\"{desc}\">\n",
            "<link rel=\"canonical\" href=\"{canonical}\">\n",
            "<meta property=\"og:type\" content=\"website\">\n",
            "<meta property=\"og:site_name\" content=\"{site}\">\n",
            "<meta property=\"og:title\" content=\"{title}\">\n",
            "<meta property=\"og:description\" content=\"{desc}\">\n",
            "<meta property=\"og:url\" content=\"{canonical}\">\n",
            "<meta property=\"og:image\" content=\"{og_image}\">\n",
            "{og_dims}",
            "<meta name=\"twitter:card\" content=\"summary_large_image\">\n",
            "<meta name=\"twitter:title\" content=\"{title}\">\n",
            "<meta name=\"twitter:description\" content=\"{desc}\">\n",
            "<meta name=\"twitter:image\" content=\"{og_image}\">\n",
            "<script type=\"application/ld+json\">{org_ld}</script>\n",
            "<script type=\"application/ld+json\">{page_ld}</script>\n",
            "<script type=\"application/ld+json\">{bc_ld}</script>\n",
        ),
        title = html_escape(&full_title),
        desc = html_escape(description),
        canonical = html_escape(&canonical),
        site = html_escape(SITE_NAME),
        og_image = html_escape(og_image),
        og_dims = og_dims,
        org_ld = org_jsonld,
        page_ld = page_jsonld,
        bc_ld = breadcrumb_jsonld,
    );
    for block in product_blocks {
        head.push_str(&format!("<script type=\"application/ld+json\">{}</script>\n", block));
    }
    head
}

/// Emit a Product JSON-LD block for each shop SKU whose key matches the page
/// slug (slug is a prefix of SKU). Returns an empty Vec if no products match,
/// so non-product pages render no extra schema.
fn build_product_jsonld(
    slug: &str,
    products: &[(String, String, String, i64, String, Option<String>, String, bool, i64, String)],
) -> Vec<String> {
    let mut out = Vec::new();
    for (sku, title, desc_md, price_cents, currency, image_url, _tax, active, _ord, _upd) in products {
        if !active { continue; }
        let sku_lc = sku.to_lowercase();
        let slug_lc = slug.to_lowercase();
        if sku_lc != slug_lc && !sku_lc.starts_with(&format!("{}-", slug_lc)) { continue; }
        let price = format!("{}.{:02}", price_cents / 100, (price_cents % 100).abs());
        let cur_upper = currency.to_uppercase();
        let desc = derive_description(desc_md);
        let img = image_url.as_deref().filter(|s| !s.is_empty()).map(|s| {
            if s.starts_with("http://") || s.starts_with("https://") {
                s.to_string()
            } else if s.starts_with('/') {
                format!("{}{}", PUBLIC_BASE, s)
            } else {
                format!("{}/{}", PUBLIC_BASE, s)
            }
        }).unwrap_or_else(|| OG_IMAGE_URL.to_string());
        out.push(format!(
            r#"{{"@context":"https://schema.org","@type":"Product","name":"{name}","description":"{desc}","sku":"{sku}","brand":{{"@type":"Brand","name":"Xikaku"}},"image":"{img}","offers":{{"@type":"Offer","price":"{price}","priceCurrency":"{cur}","availability":"https://schema.org/InStock","url":"{url}","seller":{{"@type":"Organization","name":"Xikaku","url":"{base}"}}}}}}"#,
            name = html_escape(title),
            desc = html_escape(&desc),
            sku = html_escape(sku),
            img = html_escape(&img),
            price = price,
            cur = html_escape(&cur_upper),
            url = html_escape(&format!("{}/shop/{}", PUBLIC_BASE, sku)),
            base = html_escape(PUBLIC_BASE),
        ));
    }
    out
}

pub async fn handle_website_render_root(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> axum::response::Response {
    render_website(&state, &headers, None).into_response()
}

pub async fn handle_website_render_slug(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> axum::response::Response {
    render_website(&state, &headers, Some(slug)).into_response()
}

fn render_website(
    state: &Arc<AppState>,
    _headers: &HeaderMap,
    requested_slug: Option<String>,
) -> (HeaderMap, Bytes) {
    // Build the cache key first so we can short-circuit on a hit. Use the raw
    // requested slug (None → "" for the home shell). When the slug resolves to
    // home via `first_default_slug`, the cache still keys on what the client
    // asked for; this is correct because invalidation is global and TTL is short.
    let cache_key = requested_slug.clone().unwrap_or_default();
    if let Some(cached) = page_cache_get(&cache_key) {
        return (build_html_headers(), cached);
    }

    let (pages, products) = {
        let db = state.db.lock().unwrap();
        (
            db.list_website_pages().unwrap_or_default(),
            db.list_products(true).unwrap_or_default(),
        )
    };
    let slug_owned: Option<String> = requested_slug.or_else(|| {
        first_default_slug(&pages).map(|s| s.to_string())
    });
    // If the requested slug is unknown, render the shell anyway (SPA shows "Page not found")
    // but omit the SEO head — better than 500'ing.
    let (title, description, updated_at, valid_slug, body_md):
        (String, String, String, Option<String>, String) =
        if let Some(s) = slug_owned.as_deref() {
            let row = {
                let db = state.db.lock().unwrap();
                db.get_website_page(s).unwrap_or(None)
            };
            if let Some((t, body, _p, _o, upd, meta)) = row {
                let desc = if !meta.trim().is_empty() {
                    meta
                } else {
                    let d = derive_description(&body);
                    if d.is_empty() { SITE_TAGLINE.to_string() } else { d }
                };
                (t, desc, upd, Some(s.to_string()), body)
            } else {
                (SITE_NAME.to_string(), SITE_TAGLINE.to_string(), String::new(), None, String::new())
            }
        } else {
            (SITE_NAME.to_string(), SITE_TAGLINE.to_string(), String::new(), None, String::new())
        };

    let og_image = first_image_url(&body_md);
    let injected = match valid_slug.as_deref() {
        Some(s) => render_seo_head(s, &title, &description, &updated_at, og_image.as_deref(), &pages, &products),
        None => format!(
            "<title>{}</title>\n<meta name=\"description\" content=\"{}\">\n",
            html_escape(SITE_NAME),
            html_escape(SITE_TAGLINE),
        ),
    };

    let body_html = if body_md.is_empty() {
        "<div class=\"empty-state\">Loading…</div>".to_string()
    } else {
        render_body_html(&body_md)
    };

    let analytics = analytics_head(state);
    let html: Bytes = WEBSITE_HTML
        .replacen("<!--SEO_HEAD-->", &injected, 1)
        .replacen("<!--ANALYTICS-->", &analytics, 1)
        .replacen("<!--BODY_CONTENT-->", &body_html, 1)
        .into();
    page_cache_put(cache_key, html.clone());
    (build_html_headers(), html)
}

fn build_html_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, "text/html; charset=utf-8".parse().unwrap());
    h.insert(header::CACHE_CONTROL, "public, max-age=60".parse().unwrap());
    h
}

pub const SETTING_GOOGLE_ANALYTICS_ID: &str = "google_analytics_id";

/// Validate a Google Analytics Measurement ID. Restrict to `[A-Za-z0-9_-]`
/// so it can be safely interpolated into the gtag.js URL and `gtag('config', ...)`
/// call without escaping. Length cap keeps stored values sane.
fn is_valid_analytics_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Render the analytics `<script>` block from the configured Measurement ID,
/// or empty string when unset. Called per-request — DB lookup is cheap.
pub fn analytics_head(state: &Arc<AppState>) -> String {
    let id = {
        let db = state.db.lock().unwrap();
        db.get_site_setting(SETTING_GOOGLE_ANALYTICS_ID).ok().flatten()
    };
    let Some(id) = id else { return String::new() };
    if !is_valid_analytics_id(&id) { return String::new() }
    format!(
        "<link rel=\"preconnect\" href=\"https://www.googletagmanager.com\" crossorigin>\n\
         <!-- Google tag (gtag.js) -->\n\
         <script async src=\"https://www.googletagmanager.com/gtag/js?id={id}\"></script>\n\
         <script>\n\
         window.dataLayer = window.dataLayer || [];\n\
         function gtag(){{dataLayer.push(arguments);}}\n\
         gtag('js', new Date());\n\
         gtag('config', '{id}');\n\
         </script>\n",
        id = id,
    )
}

pub async fn handle_robots_txt(_headers: HeaderMap) -> impl IntoResponse {
    let body = format!(
        concat!(
            "User-agent: *\n",
            "Allow: /\n\n",
            "User-agent: GPTBot\nAllow: /\n\n",
            "User-agent: ChatGPT-User\nAllow: /\n\n",
            "User-agent: OAI-SearchBot\nAllow: /\n\n",
            "User-agent: ClaudeBot\nAllow: /\n\n",
            "User-agent: Claude-Web\nAllow: /\n\n",
            "User-agent: anthropic-ai\nAllow: /\n\n",
            "User-agent: PerplexityBot\nAllow: /\n\n",
            "User-agent: Perplexity-User\nAllow: /\n\n",
            "User-agent: Google-Extended\nAllow: /\n\n",
            "User-agent: Applebot-Extended\nAllow: /\n\n",
            "User-agent: CCBot\nAllow: /\n\n",
            "User-agent: cohere-ai\nAllow: /\n\n",
            "User-agent: DuckAssistBot\nAllow: /\n\n",
            "User-agent: YouBot\nAllow: /\n\n",
            "Sitemap: {base}/sitemap.xml\n",
        ),
        base = PUBLIC_BASE,
    );
    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, "text/plain; charset=utf-8".parse().unwrap());
    h.insert(header::CACHE_CONTROL, "public, max-age=3600".parse().unwrap());
    (h, body)
}

pub async fn handle_sitemap_xml(
    State(state): State<Arc<AppState>>,
    _headers: HeaderMap,
) -> impl IntoResponse {
    let pages = {
        let db = state.db.lock().unwrap();
        db.list_website_pages().unwrap_or_default()
    };
    let home_slug = first_default_slug(&pages).map(|s| s.to_string());
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n",
    );
    for (slug, _title, _parent, _ord, updated_at, _meta) in &pages {
        let is_home = home_slug.as_deref() == Some(slug.as_str());
        xml.push_str("  <url>\n");
        xml.push_str(&format!(
            "    <loc>{}</loc>\n",
            xml_escape(&canonical_page_url(slug, is_home)),
        ));
        if !updated_at.is_empty() {
            xml.push_str(&format!("    <lastmod>{}</lastmod>\n", xml_escape(&iso8601_z(updated_at))));
        }
        xml.push_str("  </url>\n");
    }
    xml.push_str("</urlset>\n");

    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, "application/xml; charset=utf-8".parse().unwrap());
    h.insert(header::CACHE_CONTROL, "public, max-age=600".parse().unwrap());
    (h, xml)
}

pub async fn handle_llms_txt(
    State(state): State<Arc<AppState>>,
    _headers: HeaderMap,
) -> impl IntoResponse {
    let pages = {
        let db = state.db.lock().unwrap();
        db.list_website_pages().unwrap_or_default()
    };
    let home_slug = first_default_slug(&pages).map(|s| s.to_string());

    let mut body = String::new();
    body.push_str(&format!("# {}\n\n", SITE_NAME));
    body.push_str(&format!("> {}\n\n", SITE_TAGLINE));
    body.push_str(&format!(
        "{} ({}) builds sensor-fusion and perception software for autonomous systems. \
         The pages listed below are the authoritative source for products, documentation, \
         and company information.\n\n",
        SITE_NAME, ORG_LEGAL_NAME,
    ));

    body.push_str("## Pages\n");
    for (slug, title, parent, _ord, _upd, meta) in &pages {
        let desc_source = if !meta.trim().is_empty() {
            meta.clone()
        } else {
            let row = {
                let db = state.db.lock().unwrap();
                db.get_website_page(slug).unwrap_or(None)
            };
            row.map(|(_t, body, _p, _o, _u, _m)| derive_description(&body))
                .unwrap_or_default()
        };
        let indent = if parent.is_some() { "  " } else { "" };
        let is_home = home_slug.as_deref() == Some(slug.as_str());
        let url = canonical_page_url(slug, is_home);
        if desc_source.is_empty() {
            body.push_str(&format!("{}- [{}]({})\n", indent, title, url));
        } else {
            body.push_str(&format!("{}- [{}]({}): {}\n", indent, title, url, desc_source));
        }
    }

    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, "text/plain; charset=utf-8".parse().unwrap());
    h.insert(header::CACHE_CONTROL, "public, max-age=600".parse().unwrap());
    (h, body)
}

// ---------------------------------------------------------------------------
// Site settings admin (JWT)
// ---------------------------------------------------------------------------

const KNOWN_SITE_SETTING_KEYS: &[&str] = &[SETTING_GOOGLE_ANALYTICS_ID];

pub async fn handle_admin_get_site_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    let pairs = {
        let db = state.db.lock().unwrap();
        db.list_site_settings().map_err(db_err)?
    };
    let mut out = serde_json::Map::new();
    for k in KNOWN_SITE_SETTING_KEYS {
        out.insert((*k).to_string(), serde_json::Value::String(String::new()));
    }
    for (k, v) in pairs {
        out.insert(k, serde_json::Value::String(v));
    }
    Ok(Json(serde_json::Value::Object(out)))
}

#[derive(Deserialize)]
pub struct UpdateSiteSettingsRequest {
    #[serde(flatten)]
    pub fields: std::collections::HashMap<String, String>,
}

pub async fn handle_admin_put_site_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<UpdateSiteSettingsRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    for (k, v) in &req.fields {
        if !KNOWN_SITE_SETTING_KEYS.contains(&k.as_str()) {
            return Err(error_response(StatusCode::BAD_REQUEST, &format!("Unknown setting: {}", k)));
        }
        let trimmed = v.trim();
        if k == SETTING_GOOGLE_ANALYTICS_ID && !trimmed.is_empty() && !is_valid_analytics_id(trimmed) {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "google_analytics_id must contain only letters, digits, '-' or '_' (max 64 chars)",
            ));
        }
        let db = state.db.lock().unwrap();
        db.set_site_setting(k, trimmed).map_err(db_err)?;
    }
    invalidate_page_cache();
    Ok(Json(json!({ "status": "OK" })))
}

// ---------------------------------------------------------------------------
// IndexNow — push page changes to Bing/Yandex/Naver/Seznam (Google opts out).
//
// Spec: https://www.indexnow.org/documentation
// We generate a 32-hex-char key on first use, persist it in site_settings,
// and serve the verification file at /indexnow/{key}.txt. Page mutations
// (upsert / rename / delete / restore) fire-and-forget POST to the IndexNow
// endpoint so the admin response isn't blocked by network latency.
// ---------------------------------------------------------------------------

pub const SETTING_INDEXNOW_KEY: &str = "indexnow_key";
const INDEXNOW_ENDPOINT: &str = "https://api.indexnow.org/indexnow";

fn generate_indexnow_key() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Fetch the configured IndexNow key, lazily creating one the first time.
fn get_or_create_indexnow_key(state: &Arc<AppState>) -> Option<String> {
    let existing = {
        let db = state.db.lock().unwrap();
        db.get_site_setting(SETTING_INDEXNOW_KEY).ok().flatten()
    };
    if let Some(k) = existing.filter(|k| !k.is_empty()) {
        return Some(k);
    }
    let key = generate_indexnow_key();
    let db = state.db.lock().unwrap();
    db.set_site_setting(SETTING_INDEXNOW_KEY, &key).ok()?;
    Some(key)
}

pub async fn handle_indexnow_key_file(
    State(state): State<Arc<AppState>>,
    Path(filename): Path<String>,
) -> impl IntoResponse {
    let Some(key) = get_or_create_indexnow_key(&state) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "key unavailable").into_response();
    };
    let expected = format!("{}.txt", key);
    if filename != expected {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, "text/plain; charset=utf-8".parse().unwrap());
    h.insert(header::CACHE_CONTROL, "public, max-age=86400".parse().unwrap());
    (h, key).into_response()
}

/// Fire an async IndexNow notification for the given URLs. Returns immediately;
/// the network request runs in a background task. Silently no-ops when there's
/// no key (e.g., DB error during bootstrap).
pub fn ping_indexnow(state: &Arc<AppState>, urls: Vec<String>) {
    if urls.is_empty() { return; }
    let Some(key) = get_or_create_indexnow_key(state) else { return };
    let host = PUBLIC_BASE
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();
    // Root-level keyLocation so IndexNow accepts URLs under any path (the
    // service only accepts URLs at the same directory level or deeper than
    // the verification file). Nginx is configured to proxy
    // `^/[a-f0-9]{32}\.txt$` to the backend `/api/v1/indexnow/{filename}`
    // route.
    let key_location = format!("{}/{}.txt", PUBLIC_BASE, key);
    let body = serde_json::to_string(&json!({
        "host": host,
        "key": key,
        "keyLocation": key_location,
        "urlList": urls,
    })).unwrap_or_default();
    let http = state.http.clone();
    tokio::spawn(async move {
        let res = http
            .post(INDEXNOW_ENDPOINT)
            .header("Content-Type", "application/json; charset=utf-8")
            .body(body)
            .send()
            .await;
        match res {
            Ok(r) => {
                let status = r.status();
                if !status.is_success() {
                    let body = r.text().await.unwrap_or_default();
                    log::warn!("IndexNow non-2xx: {} body={}", status, body);
                } else {
                    log::info!("IndexNow accepted (status={})", status);
                }
            }
            Err(e) => log::warn!("IndexNow request failed: {}", e),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_description_cuts_on_sentence_boundary() {
        let md = "The Xikaku LPMS series delivers 9-axis and 6-axis inertial measurement \
            across a wide range of applications — from wearables to autonomous vehicles \
            to structural monitoring. All models expose raw data, Euler angles, and \
            quaternions, and are configurable through LPMS-Control software. \
            Pick a sensor to see specs, datasheets, and application notes.";
        let d = derive_description(md);
        assert!(d.ends_with('.'), "should end on a period, got: {}", d);
        assert!(!d.contains("Pick a…"), "should not truncate mid-phrase, got: {}", d);
    }

    #[test]
    fn derive_description_short_passes_through() {
        let d = derive_description("Hello world");
        assert_eq!(d, "Hello world");
    }

    #[test]
    fn derive_description_word_boundary_fallback() {
        let long: String = "x".repeat(400);
        let d = derive_description(&long);
        assert!(d.ends_with('…'));
    }

    #[test]
    fn first_image_url_extracts_relative() {
        let md = "# Title\n\nIntro text.\n\n![hero](/static/foo.png)\n\nMore text.\n";
        assert_eq!(
            first_image_url(md),
            Some("https://xikaku.com/static/foo.png".to_string())
        );
    }

    #[test]
    fn first_image_url_passes_absolute() {
        let md = "![hero](https://cdn.example.com/img.jpg)";
        assert_eq!(
            first_image_url(md),
            Some("https://cdn.example.com/img.jpg".to_string())
        );
    }

    #[test]
    fn first_image_url_none_when_no_images() {
        assert_eq!(first_image_url("# Just text\n\nNo images here."), None);
    }

    #[test]
    fn render_body_html_emits_headings_and_paras() {
        let h = render_body_html("# Title\n\nA paragraph.\n");
        assert!(h.contains("<h1>"));
        assert!(h.contains("Title"));
        assert!(h.contains("<p>"));
        assert!(h.contains("A paragraph"));
    }

    #[test]
    fn rewrite_pandoc_image_attrs_emits_class_and_width() {
        let md = "![logo](/static/logo.png){width=400px .logo-dark}\n\nText.";
        let cleaned = rewrite_pandoc_image_attrs(md);
        assert!(!cleaned.contains("{width"), "got: {}", cleaned);
        assert!(cleaned.contains(r#"<img alt="logo" src="/static/logo.png" width="400px" class="logo-dark">"#));
        assert!(cleaned.contains("Text."));
    }

    #[test]
    fn rewrite_pandoc_image_attrs_preserves_classes_in_ssr_html() {
        let md = "![Xikaku](/static/logo-dark.png){width=400px .logo-dark} ![Xikaku](/static/logo.png){width=400px .logo-light}";
        let html = render_body_html(md);
        assert!(html.contains(r#"class="logo-dark""#), "got: {}", html);
        assert!(html.contains(r#"class="logo-light""#), "got: {}", html);
    }

    #[test]
    fn rewrite_pandoc_image_attrs_keeps_plain_image_markdown() {
        let md = "![alt](/img.png) and more text";
        assert_eq!(rewrite_pandoc_image_attrs(md), md);
    }

    #[test]
    fn rewrite_pandoc_image_attrs_strips_unrecognized_attrs() {
        let md = "![alt](/img.png){foo=bar} text";
        let cleaned = rewrite_pandoc_image_attrs(md);
        assert_eq!(cleaned, "![alt](/img.png) text");
    }

    #[test]
    fn rewrite_pandoc_image_attrs_leaves_normal_text_intact() {
        let md = "Use the `{config}` field to configure.";
        assert_eq!(rewrite_pandoc_image_attrs(md), md);
    }

    #[test]
    fn iso8601_z_handles_naive_sqlite_format() {
        assert_eq!(iso8601_z("2026-04-26 23:21:37"), "2026-04-26T23:21:37Z");
        assert_eq!(iso8601_z("2026-04-29T23:35:28+00:00"), "2026-04-29T23:35:28+00:00");
        assert_eq!(iso8601_z(""), "");
    }

    #[test]
    fn analytics_id_validator() {
        assert!(is_valid_analytics_id("G-XSW6TEN1CZ"));
        assert!(is_valid_analytics_id("UA-12345-1"));
        assert!(!is_valid_analytics_id(""));
        assert!(!is_valid_analytics_id("evil';alert(1)"));
        assert!(!is_valid_analytics_id(&"x".repeat(65)));
    }
}
