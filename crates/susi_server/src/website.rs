//! Public website endpoints.
//!
//! Simple single-site page store at `/api/v1/website/...`. Public reads for
//! viewing pages + assets; admin writes (JWT/API-token) for editing. Unlike
//! `docs`, there's no release concept and no pipeline/user origin split —
//! all content is hand-authored via the in-browser editor.

use std::sync::Arc;

use axum::{
    extract::{Multipart, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use susi_core::error::LicenseError;

use crate::docs::{safe_filename};
use crate::{error_response, require_admin, require_password_changed, validate_principal, AppState, ErrorResponse};

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
    let bytes = std::fs::read(&path)
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
    require_password_changed(&state, &principal)?;
    require_admin(&state, &principal)?;
    safe_slug(&slug)?;

    let id = {
        let mut db = state.db.lock().unwrap();
        db.upsert_website_page(
            &slug,
            &req.title,
            &req.body_md,
            req.parent_slug.as_deref(),
            req.ord,
            &req.meta_description,
            Some(&principal.username),
        )
        .map_err(db_err)?
    };
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
    require_password_changed(&state, &principal)?;
    require_admin(&state, &principal)?;
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
    require_password_changed(&state, &principal)?;
    require_admin(&state, &principal)?;
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
    require_password_changed(&state, &principal)?;
    require_admin(&state, &principal)?;
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
    require_password_changed(&state, &principal)?;
    require_admin(&state, &principal)?;
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
    require_password_changed(&state, &principal)?;
    require_admin(&state, &principal)?;
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
    require_password_changed(&state, &principal)?;
    require_admin(&state, &principal)?;
    let new_slug = req.new_slug.trim();
    if new_slug.is_empty() || new_slug.contains('/') || new_slug.contains('\\') || new_slug.contains('\0') {
        return Err(error_response(StatusCode::BAD_REQUEST, "Invalid slug"));
    }

    let mut db = state.db.lock().unwrap();
    match db.rename_website_page(&slug, new_slug) {
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

pub async fn handle_delete_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    require_admin(&state, &principal)?;
    safe_slug(&slug)?;

    let db = state.db.lock().unwrap();
    let removed = db.delete_website_page(&slug).map_err(db_err)?;
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Page not found"));
    }
    Ok(Json(json!({ "status": "OK" })))
}

pub async fn handle_upload_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    require_admin(&state, &principal)?;

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
    require_password_changed(&state, &principal)?;
    require_admin(&state, &principal)?;
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

const WEBSITE_HTML: &str = include_str!("website.html");
const SITE_NAME: &str = "Xikaku";
const SITE_TAGLINE: &str = "Complete Perception for autonomous systems.";
const ORG_LEGAL_NAME: &str = "LP-Research Inc.";
const ORG_ADDR_LOCALITY: &str = "Tokyo";
const ORG_ADDR_COUNTRY: &str = "JP";

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
        let cut = truncated.rfind(' ').unwrap_or(truncated.len());
        return format!("{}…", &truncated[..cut]);
    }
    first_para
}

/// Build base URL from reverse-proxy headers. Falls back to Host + https.
fn base_url(headers: &HeaderMap) -> String {
    let host = headers
        .get("x-forwarded-host")
        .and_then(|h| h.to_str().ok())
        .or_else(|| headers.get(header::HOST).and_then(|h| h.to_str().ok()))
        .unwrap_or("staging.susi.lp-research.com");
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("https");
    format!("{}://{}", proto, host)
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
    base: &str,
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
    let items: Vec<String> = chain
        .iter()
        .enumerate()
        .map(|(i, p)| {
            format!(
                r#"{{"@type":"ListItem","position":{},"name":"{}","item":"{}/site/{}"}}"#,
                i + 1,
                html_escape(&p.1),
                base,
                html_escape(&p.0),
            )
        })
        .collect();
    format!(
        r#"{{"@context":"https://schema.org","@type":"BreadcrumbList","itemListElement":[{}]}}"#,
        items.join(",")
    )
}

fn render_seo_head(
    base: &str,
    slug: &str,
    page_title: &str,
    description: &str,
    updated_at: &str,
    pages: &[(String, String, Option<String>, i64, String, String)],
) -> String {
    let canonical = format!("{}/site/{}", base, slug);
    let is_home = pages
        .iter()
        .find(|p| p.2.is_none())
        .map(|p| p.0.as_str() == slug)
        .unwrap_or(false);
    let full_title = if is_home {
        format!("{} — {}", SITE_NAME, SITE_TAGLINE)
    } else {
        format!("{} — {}", page_title, SITE_NAME)
    };

    let org_jsonld = format!(
        r#"{{"@context":"https://schema.org","@type":"Organization","name":"{}","legalName":"{}","url":"{}","slogan":"{}","address":{{"@type":"PostalAddress","addressLocality":"{}","addressCountry":"{}"}}}}"#,
        html_escape(SITE_NAME),
        html_escape(ORG_LEGAL_NAME),
        html_escape(base),
        html_escape(SITE_TAGLINE),
        html_escape(ORG_ADDR_LOCALITY),
        html_escape(ORG_ADDR_COUNTRY),
    );
    let article_jsonld = format!(
        r#"{{"@context":"https://schema.org","@type":"Article","headline":"{}","description":"{}","url":"{}","dateModified":"{}","publisher":{{"@type":"Organization","name":"{}","url":"{}"}}}}"#,
        html_escape(page_title),
        html_escape(description),
        html_escape(&canonical),
        html_escape(updated_at),
        html_escape(SITE_NAME),
        html_escape(base),
    );
    let breadcrumb_jsonld = build_breadcrumbs(pages, slug, base);

    format!(
        concat!(
            "<title>{title}</title>\n",
            "<meta name=\"description\" content=\"{desc}\">\n",
            "<link rel=\"canonical\" href=\"{canonical}\">\n",
            "<meta property=\"og:type\" content=\"website\">\n",
            "<meta property=\"og:site_name\" content=\"{site}\">\n",
            "<meta property=\"og:title\" content=\"{title}\">\n",
            "<meta property=\"og:description\" content=\"{desc}\">\n",
            "<meta property=\"og:url\" content=\"{canonical}\">\n",
            "<meta name=\"twitter:card\" content=\"summary_large_image\">\n",
            "<meta name=\"twitter:title\" content=\"{title}\">\n",
            "<meta name=\"twitter:description\" content=\"{desc}\">\n",
            "<script type=\"application/ld+json\">{org_ld}</script>\n",
            "<script type=\"application/ld+json\">{article_ld}</script>\n",
            "<script type=\"application/ld+json\">{bc_ld}</script>\n",
        ),
        title = html_escape(&full_title),
        desc = html_escape(description),
        canonical = html_escape(&canonical),
        site = html_escape(SITE_NAME),
        org_ld = org_jsonld,
        article_ld = article_jsonld,
        bc_ld = breadcrumb_jsonld,
    )
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
    headers: &HeaderMap,
    requested_slug: Option<String>,
) -> (HeaderMap, String) {
    let base = base_url(headers);
    let pages = {
        let db = state.db.lock().unwrap();
        db.list_website_pages().unwrap_or_default()
    };
    let slug_owned: Option<String> = requested_slug.or_else(|| {
        first_default_slug(&pages).map(|s| s.to_string())
    });
    // If the requested slug is unknown, render the shell anyway (SPA shows "Page not found")
    // but omit the SEO head — better than 500'ing.
    let (title, description, updated_at, valid_slug): (String, String, String, Option<String>) =
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
                (t, desc, upd, Some(s.to_string()))
            } else {
                (SITE_NAME.to_string(), SITE_TAGLINE.to_string(), String::new(), None)
            }
        } else {
            (SITE_NAME.to_string(), SITE_TAGLINE.to_string(), String::new(), None)
        };

    let injected = match valid_slug {
        Some(s) => render_seo_head(&base, &s, &title, &description, &updated_at, &pages),
        None => format!(
            "<title>{}</title>\n<meta name=\"description\" content=\"{}\">\n",
            html_escape(SITE_NAME),
            html_escape(SITE_TAGLINE),
        ),
    };

    let html = WEBSITE_HTML.replacen("<!--SEO_HEAD-->", &injected, 1);

    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, "text/html; charset=utf-8".parse().unwrap());
    h.insert(header::CACHE_CONTROL, "public, max-age=60".parse().unwrap());
    (h, html)
}

pub async fn handle_robots_txt(headers: HeaderMap) -> impl IntoResponse {
    let base = base_url(&headers);
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
        base = base,
    );
    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, "text/plain; charset=utf-8".parse().unwrap());
    h.insert(header::CACHE_CONTROL, "public, max-age=3600".parse().unwrap());
    (h, body)
}

pub async fn handle_sitemap_xml(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let base = base_url(&headers);
    let pages = {
        let db = state.db.lock().unwrap();
        db.list_website_pages().unwrap_or_default()
    };
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n",
    );
    for (slug, _title, _parent, _ord, updated_at, _meta) in &pages {
        xml.push_str("  <url>\n");
        xml.push_str(&format!(
            "    <loc>{}/site/{}</loc>\n",
            xml_escape(&base),
            xml_escape(slug),
        ));
        if !updated_at.is_empty() {
            xml.push_str(&format!("    <lastmod>{}</lastmod>\n", xml_escape(updated_at)));
        }
        xml.push_str("    <changefreq>weekly</changefreq>\n");
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
    headers: HeaderMap,
) -> impl IntoResponse {
    let base = base_url(&headers);
    let pages = {
        let db = state.db.lock().unwrap();
        db.list_website_pages().unwrap_or_default()
    };

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
        if desc_source.is_empty() {
            body.push_str(&format!(
                "{}- [{}]({}/site/{})\n",
                indent, title, base, slug
            ));
        } else {
            body.push_str(&format!(
                "{}- [{}]({}/site/{}): {}\n",
                indent, title, base, slug, desc_source
            ));
        }
    }

    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, "text/plain; charset=utf-8".parse().unwrap());
    h.insert(header::CACHE_CONTROL, "public, max-age=600".parse().unwrap());
    (h, body)
}
