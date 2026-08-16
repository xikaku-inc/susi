//! Public website endpoints.
//!
//! Per-site page store at `/api/v1/website/...` (see `sites.rs` for the
//! registry and how a request resolves to a site). Public reads for
//! viewing pages + assets; admin writes (JWT/API-token) for editing. Unlike
//! `docs`, there's no release concept and no pipeline/user origin split -
//! all content is hand-authored via the in-browser editor.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant};

use axum::{
    body::Bytes,
    extract::{Multipart, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use susi_core::error::LicenseError;

use crate::docs::{docs_llms_section, docs_sitemap_entries, harden_svg_response, safe_filename, DOCS_PUBLIC_BASE};
use crate::sites::{self, SiteConfig};
use crate::{error_response, require_admin_full, validate_principal, AppState, ErrorResponse};

fn assets_dir(state: &AppState, site: &SiteConfig) -> std::path::PathBuf {
    std::path::Path::new(&state.data_dir)
        .join("website")
        .join("assets")
        .join(site.id)
}

/// One-time disk layout migration: files that predate per-site asset
/// directories sit directly in `website/assets/` and belong to the default
/// site. Idempotent; called once at startup.
pub(crate) fn migrate_assets_layout(state: &AppState) {
    let root = std::path::Path::new(&state.data_dir).join("website").join("assets");
    let Ok(entries) = std::fs::read_dir(&root) else { return };
    let files: Vec<_> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .collect();
    if files.is_empty() {
        return;
    }
    let target = root.join(sites::default_site().id);
    if let Err(e) = std::fs::create_dir_all(&target) {
        log::error!("Asset layout migration: mkdir {}: {}", target.display(), e);
        return;
    }
    for f in files {
        let to = target.join(f.file_name());
        if let Err(e) = std::fs::rename(f.path(), &to) {
            log::error!("Asset layout migration: move {:?}: {}", f.file_name(), e);
        }
    }
    log::info!("Moved legacy website assets into {}", target.display());
}

/// Optional `?site=` query on website endpoints. The dashboard passes it
/// explicitly (its host resolves to no site); public traffic resolves via
/// the Host header and falls back to the default site.
#[derive(Deserialize)]
pub struct SiteQuery {
    site: Option<String>,
}

fn resolve_site(
    headers: &HeaderMap,
    q: &SiteQuery,
) -> Result<&'static SiteConfig, (StatusCode, Json<ErrorResponse>)> {
    match q.site.as_deref() {
        Some(id) => sites::site_by_id(id)
            .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, "Unknown site")),
        None => Ok(sites::site_from_headers(headers).unwrap_or_else(sites::default_site)),
    }
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

/// Row shape returned by `list_website_pages`:
/// (slug, title, parent_slug, ord, updated_at, meta_description, hidden,
///  page_kind, published_at, author_username, redirect_to).
type PageRow = (String, String, Option<String>, i64, String, String, bool, String, String, String, String);

/// True for a retired page: it 301s to `redirect_to` instead of rendering, and
/// stays out of nav, sitemap, llms.txt, the blog index and the feed.
fn is_retired(p: &PageRow) -> bool {
    !p.10.trim().is_empty()
}

/// True for blog-post rows (`page_kind == 'post'`).
fn is_post(p: &PageRow) -> bool {
    p.7 == "post"
}

/// Drop hidden and retired pages - applied before any public-facing use of the
/// page list (nav, SSR head, sitemap, llms.txt).
fn visible_pages(mut pages: Vec<PageRow>) -> Vec<PageRow> {
    pages.retain(|p| !p.6 && !is_retired(p));
    pages
}

/// Where a retired page sends visitors. Accepts an absolute URL, a site-root
/// path, or a bare slug (resolved to its own canonical path, so retiring onto
/// a post lands on /blog/...). Relative targets keep the `/site` prefix when
/// the request did not come in on the marketing host.
fn redirect_location(target: &str, pages: &[PageRow], marketing_host: bool) -> String {
    let target = target.trim();
    if target.starts_with("http://") || target.starts_with("https://") {
        return target.to_string();
    }
    let path = if let Some(rest) = target.strip_prefix('/') {
        format!("/{}", rest)
    } else if pages.iter().any(|p| p.0 == target && is_post(p)) {
        format!("/blog/{}", target)
    } else {
        format!("/{}", target)
    };
    if marketing_host { path } else { format!("/site{}", path) }
}

/// True when the request carries a valid full-admin principal. The public
/// read endpoints use this to include hidden pages for the dashboard/editor.
fn is_admin_request(headers: &HeaderMap, state: &AppState) -> bool {
    validate_principal(headers, state)
        .ok()
        .map(|p| require_admin_full(state, &p).is_ok())
        .unwrap_or(false)
}

pub async fn handle_list_pages(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let is_admin = is_admin_request(&headers, &state);
    let nav = nav_structure_json(&state, site);
    let db = state.db.lock();
    let mut pages = db.list_website_pages(site.id).map_err(db_err)?;
    if !is_admin {
        pages = visible_pages(pages);
    }
    let assets = db.list_website_assets(site.id).map_err(db_err)?;
    let pages_json: Vec<_> = pages
        .into_iter()
        .map(|(slug, title, parent_slug, ord, updated_at, meta_description, hidden, page_kind, published_at, author_username, redirect_to)| {
            let mut row = json!({
                "slug": slug,
                "title": title,
                "parent_slug": parent_slug,
                "ord": ord,
                "updated_at": updated_at,
                "meta_description": meta_description,
                "hidden": hidden,
                "page_kind": page_kind,
                "published_at": published_at,
                "author_name": display_name(&db, &author_username),
                "redirect_to": redirect_to,
            });
            // The account name behind a byline is only the editor's business.
            if is_admin {
                row["author_username"] = json!(author_username);
            }
            row
        })
        .collect();
    let assets_json: Vec<_> = assets
        .into_iter()
        .map(|(name, size)| json!({ "name": name, "size": size }))
        .collect();
    Ok(Json(json!({
        "site": site.id,
        "sites": sites::SITES.iter().map(|s| json!({ "id": s.id, "name": s.name })).collect::<Vec<_>>(),
        "pages": pages_json,
        "assets": assets_json,
        "nav": nav,
    })))
}

pub async fn handle_get_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Path(slug): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    safe_slug(&slug)?;
    let is_admin = is_admin_request(&headers, &state);
    let db = state.db.lock();
    let page = db
        .get_website_page(site.id, &slug)
        .map_err(db_err)?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Page not found"))?;
    let (title, body_md, parent_slug, ord, updated_at, meta_description, hidden, page_kind, published_at, author_username, redirect_to) = page;
    if hidden && !is_admin {
        return Err(error_response(StatusCode::NOT_FOUND, "Page not found"));
    }
    let mut out = json!({
        "slug": slug,
        "title": title,
        "body_md": body_md,
        "parent_slug": parent_slug,
        "ord": ord,
        "updated_at": updated_at,
        "meta_description": meta_description,
        "hidden": hidden,
        "page_kind": page_kind,
        "published_at": published_at,
        "author_name": display_name(&db, &author_username),
        "redirect_to": redirect_to,
    });
    if is_admin {
        out["author_username"] = json!(author_username);
    }
    Ok(Json(out))
}

/// Byline name for a page's author, or None when the page has no author, the
/// account is gone, or nobody filled in a real name.
fn display_name(db: &susi_core::db::LicenseDb, author_username: &str) -> Option<String> {
    if author_username.is_empty() {
        return None;
    }
    db.get_user_display_name(author_username).ok().flatten()
}

/// Wrap the first `<h1>` of a rendered post body in a link to its permalink,
/// so the headline on the blog index is the obvious thing to click and to copy
/// a shareable link from. Attributes on the tag are preserved; a body without
/// an h1 is returned untouched.
fn link_first_heading(html: &str, href: &str) -> String {
    let Some(open) = html.find("<h1") else { return html.to_string() };
    let Some(gt) = html[open..].find('>').map(|i| open + i) else { return html.to_string() };
    let Some(close) = html[gt..].find("</h1>").map(|i| gt + i) else { return html.to_string() };
    format!(
        "{}<a href=\"{}\">{}</a>{}",
        &html[..=gt],
        html_escape(href),
        &html[gt + 1..close],
        &html[close..],
    )
}

/// Byline appended to a post's date line; empty without a known author.
fn byline_suffix(author: Option<&str>) -> String {
    match author {
        Some(name) => format!(" &middot; by {}", html_escape(name)),
        None => String::new(),
    }
}

pub async fn handle_get_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Path(file_name): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    safe_filename(&file_name)?;
    let path = assets_dir(&state, site).join(&file_name);
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
    harden_svg_response(&file_name, &mut resp);
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
    // Omitted -> preserve the existing row's kind/date (new rows: 'page'/'').
    #[serde(default)]
    pub page_kind: Option<String>,
    #[serde(default)]
    pub published_at: Option<String>,
    // Omitted -> preserve the existing author (new posts: the editing user).
    #[serde(default)]
    pub author_username: Option<String>,
    // Retire the page: a non-empty target makes the slug 301 there. Omitted
    // preserves the current setting; an empty string un-retires the page.
    #[serde(default)]
    pub redirect_to: Option<String>,
}

pub async fn handle_upsert_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Path(slug): Path<String>,
    Json(req): Json<UpsertPageRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    safe_slug(&slug)?;

    let (id, url) = {
        let mut db = state.db.lock();
        let existing = db.get_website_page(site.id, &slug).map_err(db_err)?;
        let page_kind = req
            .page_kind
            .clone()
            .or_else(|| existing.as_ref().map(|r| r.7.clone()))
            .unwrap_or_else(|| "page".to_string());
        if page_kind != "page" && page_kind != "post" {
            return Err(error_response(StatusCode::BAD_REQUEST, "page_kind must be 'page' or 'post'"));
        }
        let mut published_at = req
            .published_at
            .clone()
            .or_else(|| existing.as_ref().map(|r| r.8.clone()))
            .unwrap_or_default()
            .trim()
            .to_string();
        if page_kind == "post" {
            if published_at.is_empty() {
                published_at = chrono::Utc::now().format("%Y-%m-%d").to_string();
            } else if chrono::NaiveDate::parse_from_str(&published_at, "%Y-%m-%d").is_err() {
                return Err(error_response(StatusCode::BAD_REQUEST, "published_at must be YYYY-MM-DD"));
            }
        } else {
            published_at.clear();
        }
        // A post without an explicit author is credited to whoever wrote it;
        // pages never carry a byline, so they stay unattributed.
        let mut author_username = req
            .author_username
            .clone()
            .or_else(|| existing.as_ref().map(|r| r.9.clone()))
            .unwrap_or_default()
            .trim()
            .to_string();
        if page_kind == "post" {
            if author_username.is_empty() {
                author_username = principal.username.clone();
            } else if !db.user_exists(&author_username).unwrap_or(false) {
                return Err(error_response(StatusCode::BAD_REQUEST, "Unknown author"));
            }
        } else {
            author_username.clear();
        }
        let redirect_to = req
            .redirect_to
            .clone()
            .or_else(|| existing.as_ref().map(|r| r.10.clone()))
            .unwrap_or_default()
            .trim()
            .to_string();
        // A page pointing at itself would 301 forever.
        if !redirect_to.is_empty()
            && (redirect_to == slug
                || redirect_to.trim_start_matches('/') == slug
                || redirect_to.trim_start_matches('/') == format!("blog/{}", slug))
        {
            return Err(error_response(StatusCode::BAD_REQUEST, "A page cannot redirect to itself"));
        }
        let id = db.upsert_website_page(
            site.id,
            &slug,
            &req.title,
            &req.body_md,
            req.parent_slug.as_deref(),
            req.ord,
            &req.meta_description,
            &page_kind,
            &published_at,
            &author_username,
            &redirect_to,
            Some(&principal.username),
        )
        .map_err(db_err)?;
        let url = if page_kind == "post" {
            canonical_post_url(site, &slug)
        } else {
            let pages = visible_pages(db.list_website_pages(site.id).unwrap_or_default());
            canonical_page_url(site, &slug, first_default_slug(&pages) == Some(slug.as_str()))
        };
        (id, url)
    };
    invalidate_page_cache();
    ping_indexnow(&state, site, vec![url]);
    Ok(Json(json!({ "id": id, "slug": slug })))
}

// ---------------------------------------------------------------------------
// Page revisions (history)
// ---------------------------------------------------------------------------

pub async fn handle_list_page_revisions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Path(slug): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    safe_slug(&slug)?;
    let db = state.db.lock();
    let rows = db.list_page_revisions(site.id, &slug).map_err(db_err)?;
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
    Query(sq): Query<SiteQuery>,
    Path((slug, id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    safe_slug(&slug)?;
    let db = state.db.lock();
    let row = db
        .get_page_revision(site.id, &slug, id)
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
    Query(sq): Query<SiteQuery>,
    Path((slug, id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    safe_slug(&slug)?;
    let mut db = state.db.lock();
    let rev = db
        .get_page_revision(site.id, &slug, id)
        .map_err(db_err)?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Revision not found"))?;
    let (title, body_md, parent_slug, ord, _captured_at, _author) = rev;
    // Preserve the current meta_description, kind, publish date and author
    // when restoring prior body/title.
    let (existing_meta, existing_kind, existing_pub, existing_author, existing_redirect) = db
        .get_website_page(site.id, &slug)
        .map_err(db_err)?
        .map(|(_t, _b, _p, _o, _u, m, _h, k, pd, au, rd)| (m, k, pd, au, rd))
        .unwrap_or_else(|| (String::new(), "page".to_string(), String::new(), String::new(), String::new()));
    let new_id = db.upsert_website_page(
        site.id, &slug, &title, &body_md, parent_slug.as_deref(), ord,
        &existing_meta,
        &existing_kind,
        &existing_pub,
        &existing_author,
        &existing_redirect,
        Some(&principal.username),
    ).map_err(db_err)?;
    let url = if existing_kind == "post" {
        canonical_post_url(site, &slug)
    } else {
        let pages = visible_pages(db.list_website_pages(site.id).unwrap_or_default());
        canonical_page_url(site, &slug, first_default_slug(&pages) == Some(slug.as_str()))
    };
    drop(db);
    invalidate_page_cache();
    ping_indexnow(&state, site, vec![url]);
    Ok(Json(json!({ "id": new_id, "slug": slug, "restored_from": id })))
}

// ---------------------------------------------------------------------------
// Asset admin
// ---------------------------------------------------------------------------

pub async fn handle_list_assets_with_usage(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    let db = state.db.lock();
    let rows = db.list_website_assets_with_usage(site.id).map_err(db_err)?;
    let assets: Vec<_> = rows
        .into_iter()
        .map(|(name, size, usage_count, pages_csv, products_csv)| {
            let pages: Vec<&str> = if pages_csv.is_empty() {
                Vec::new()
            } else {
                pages_csv.split(',').collect()
            };
            let products: Vec<&str> = if products_csv.is_empty() {
                Vec::new()
            } else {
                products_csv.split(',').collect()
            };
            json!({
                "name": name, "size": size,
                "usage_count": usage_count,
                "pages": pages,
                "products": products,
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
    Query(sq): Query<SiteQuery>,
    Path(file_name): Path<String>,
    Json(req): Json<RenameAssetRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    safe_filename(&file_name)?;
    let new_name = req.new_name.trim();
    safe_filename(new_name)?;

    let (ok, n_pages) = {
        let mut db = state.db.lock();
        db.rename_website_asset(site.id, &file_name, new_name).map_err(|e| {
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
    let dir = assets_dir(&state, site);
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
    Query(sq): Query<SiteQuery>,
    Path(slug): Path<String>,
    Json(req): Json<RenamePageRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    let new_slug = req.new_slug.trim();
    if new_slug.is_empty() || new_slug.contains('/') || new_slug.contains('\\') || new_slug.contains('\0') {
        return Err(error_response(StatusCode::BAD_REQUEST, "Invalid slug"));
    }

    let result = {
        let mut db = state.db.lock();
        db.rename_website_page(site.id, &slug, new_slug)
    };
    match result {
        Ok(true) => {
            let renamed_is_post = {
                let db = state.db.lock();
                db.get_website_page(site.id, new_slug).ok().flatten().map(|r| r.7 == "post").unwrap_or(false)
            };
            let urls = if renamed_is_post {
                vec![canonical_post_url(site, &slug), canonical_post_url(site, new_slug)]
            } else {
                vec![
                    canonical_page_url(site, &slug, false),
                    canonical_page_url(site, new_slug, false),
                ]
            };
            invalidate_page_cache();
            ping_indexnow(&state, site, urls);
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

#[derive(Deserialize)]
pub struct SetPageHiddenRequest {
    pub hidden: bool,
}

pub async fn handle_set_page_hidden(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Path(slug): Path<String>,
    Json(req): Json<SetPageHiddenRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    safe_slug(&slug)?;

    let (updated, was_post) = {
        let db = state.db.lock();
        let was_post = db.get_website_page(site.id, &slug).ok().flatten().map(|r| r.7 == "post").unwrap_or(false);
        (db.set_website_page_hidden(site.id, &slug, req.hidden).map_err(db_err)?, was_post)
    };
    if !updated {
        return Err(error_response(StatusCode::NOT_FOUND, "Page not found"));
    }
    invalidate_page_cache();
    let url = if was_post { canonical_post_url(site, &slug) } else { canonical_page_url(site, &slug, false) };
    ping_indexnow(&state, site, vec![url]);
    Ok(Json(json!({ "slug": slug, "hidden": req.hidden })))
}

pub async fn handle_delete_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Path(slug): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    safe_slug(&slug)?;

    let (removed, was_post) = {
        let db = state.db.lock();
        let was_post = db.get_website_page(site.id, &slug).ok().flatten().map(|r| r.7 == "post").unwrap_or(false);
        (db.delete_website_page(site.id, &slug).map_err(db_err)?, was_post)
    };
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Page not found"));
    }
    invalidate_page_cache();
    let url = if was_post { canonical_post_url(site, &slug) } else { canonical_page_url(site, &slug, false) };
    ping_indexnow(&state, site, vec![url]);
    Ok(Json(json!({ "status": "OK" })))
}

pub async fn handle_upload_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
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

    let dir = assets_dir(&state, site);
    std::fs::create_dir_all(&dir).map_err(|e| {
        error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("mkdir: {}", e))
    })?;
    let path = dir.join(&file_name);
    std::fs::write(&path, &bytes).map_err(|e| {
        error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("write: {}", e))
    })?;

    {
        let db = state.db.lock();
        db.upsert_website_asset(site.id, &file_name, bytes.len() as u64)
            .map_err(db_err)?;
    }

    let url = format!("/api/v1/website/assets/{}", file_name);
    log::info!("Website asset uploaded: {} ({} bytes)", file_name, bytes.len());
    Ok(Json(json!({ "name": file_name, "size": bytes.len(), "url": url })))
}

pub async fn handle_delete_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Path(file_name): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    safe_filename(&file_name)?;

    let removed = {
        let db = state.db.lock();
        db.delete_website_asset(site.id, &file_name).map_err(db_err)?
    };
    let _ = std::fs::remove_file(assets_dir(&state, site).join(&file_name));
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

/// Seed content for the legal pages (GDPR Art 13/14 transparency + imprint
/// duty). Inserted once on a database that lacks them; edits via the website
/// admin stick - the seed never overwrites an existing page.
const PRIVACY_MD: &str = include_str!("../../../content/privacy.md");
const IMPRINT_MD: &str = include_str!("../../../content/imprint.md");

/// The legal seed applies to the default site only; a migrated site brings
/// its own legal pages as content.
pub(crate) fn seed_legal_pages(state: &Arc<AppState>) {
    let site = sites::default_site();
    for (slug, title, body) in [
        ("privacy", "Privacy Policy", PRIVACY_MD),
        ("imprint", "Imprint", IMPRINT_MD),
    ] {
        let mut db = state.db.lock();
        let exists = db.get_website_page(site.id, slug).ok().flatten().is_some();
        if !exists {
            match db.upsert_website_page(site.id, slug, title, body, None, 900, "", "page", "", "", "", None) {
                Ok(_) => log::info!("Seeded website page '{}'", slug),
                Err(e) => log::error!("Failed to seed website page '{}': {}", slug, e),
            }
        }
    }
    invalidate_page_cache();
}

/// Embedded default-site brand assets, served at /static/* (and /favicon.ico).
const LOGO_PNG: &[u8] = include_bytes!("assets/xikaku-logo.png");
const LOGO_DARK_PNG: &[u8] = include_bytes!("assets/xikaku-logo-dark.png");
const OG_IMAGE_PNG: &[u8] = include_bytes!("assets/xikaku-og-image.png");
const ICON_PNG: &[u8] = include_bytes!("assets/xikaku-icon.png");
const FAVICON_32_PNG: &[u8] = include_bytes!("assets/xikaku-favicon-32.png");
const FAVICON_180_PNG: &[u8] = include_bytes!("assets/xikaku-favicon-180.png");
const FAVICON_ICO: &[u8] = include_bytes!("assets/favicon.ico");

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

// Returns the static byte slice unchanged - axum's IntoResponse for
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
fn canonical_page_url(site: &SiteConfig, slug: &str, is_home: bool) -> String {
    if is_home {
        format!("{}/", site.public_base)
    } else {
        format!("{}/{}", site.public_base, slug)
    }
}

/// Blog posts live under `/blog/{slug}`.
fn canonical_post_url(site: &SiteConfig, slug: &str) -> String {
    format!("{}/blog/{}", site.public_base, slug)
}

/// Format a YYYY-MM-DD publish date for display ("July 26, 2026"); returns
/// the raw string when it doesn't parse.
fn format_post_date(date: &str) -> String {
    match chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d") {
        Ok(d) => d.format("%B %-d, %Y").to_string(),
        Err(_) => date.to_string(),
    }
}

/// Convert SQLite's "YYYY-MM-DD HH:MM:SS" timestamp to ISO 8601 with a Z
/// suffix so schema.org consumers (Google, Bing) parse it correctly.
pub(crate) fn iso8601_z(sqlite_ts: &str) -> String {
    if sqlite_ts.is_empty() { return String::new(); }
    if sqlite_ts.contains('T') { return sqlite_ts.to_string(); }
    format!("{}Z", sqlite_ts.replacen(' ', "T", 1))
}

pub(crate) fn html_escape(s: &str) -> String {
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
pub(crate) fn derive_description(body_md: &str) -> String {
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
/// `{PUBLIC_BASE}{path}` for a rooted path. A bare filename is an uploaded
/// asset (the composer inserts `data.name`, not a URL) and resolves to the
/// asset store - crawlers get the page shell back otherwise.
fn first_image_url(site: &SiteConfig, body_md: &str) -> Option<String> {
    use pulldown_cmark::{Event, Parser, Tag};
    for ev in Parser::new(body_md) {
        if let Event::Start(Tag::Image { dest_url, .. }) = ev {
            let s = dest_url.into_string();
            if s.is_empty() { continue; }
            if s.starts_with("http://") || s.starts_with("https://") {
                return Some(s);
            }
            let path = if s.starts_with('/') {
                s
            } else {
                format!("/api/v1/website/assets/{}", s)
            };
            return Some(format!("{}{}", site.public_base, path));
        }
    }
    None
}

/// A video that the site embeds as a player, recognized from the URL an
/// author wrote in image syntax. The page renders an iframe; mail clients
/// strip those, so the newsletter uses the same recognition to fall back to a
/// poster frame and a link.
pub(crate) struct VideoRef {
    /// Canonical watch page, safe to open in any browser.
    pub(crate) page_url: String,
    /// oEmbed endpoint that yields the poster frame and title.
    pub(crate) oembed_url: String,
}

/// Recognize the URL shapes `videoEmbedSrc` in website.html accepts.
pub(crate) fn video_ref(url: &str) -> Option<VideoRef> {
    let u = url.trim();
    let rest = u.strip_prefix("https://").or_else(|| u.strip_prefix("http://"))?;
    let rest = rest.strip_prefix("www.").unwrap_or(rest);

    let leading = |s: &str, f: fn(&char) -> bool| -> String { s.chars().take_while(f).collect() };
    let yt_id = |s: &str| {
        let id = leading(s, |c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-');
        (!id.is_empty()).then_some(id)
    };

    let page = if let Some(p) = rest.strip_prefix("vimeo.com/") {
        let (path, query) = p.split_once('?').unwrap_or((p, ""));
        let mut segs = path.split('/');
        let id = leading(segs.next().unwrap_or(""), |c| c.is_ascii_digit());
        if id.is_empty() {
            return None;
        }
        // An unlisted video only plays with its hash, given either as a path
        // segment or as `?h=`.
        let hash = segs
            .next()
            .map(|s| leading(s, |c| c.is_ascii_hexdigit()))
            .or_else(|| query.split('&').find_map(|kv| kv.strip_prefix("h=")).map(str::to_string))
            .filter(|h| !h.is_empty());
        match hash {
            Some(h) => format!("https://vimeo.com/{}/{}", id, h),
            None => format!("https://vimeo.com/{}", id),
        }
    } else if let Some(p) = rest.strip_prefix("player.vimeo.com/video/") {
        let id = leading(p, |c| c.is_ascii_digit());
        if id.is_empty() {
            return None;
        }
        format!("https://vimeo.com/{}", id)
    } else if let Some(p) = rest.strip_prefix("youtube.com/watch?v=") {
        format!("https://www.youtube.com/watch?v={}", yt_id(p)?)
    } else if let Some(p) = rest.strip_prefix("youtu.be/") {
        format!("https://www.youtube.com/watch?v={}", yt_id(p)?)
    } else if let Some(p) = rest.strip_prefix("youtube.com/embed/") {
        format!("https://www.youtube.com/watch?v={}", yt_id(p)?)
    } else {
        return None;
    };

    let oembed = if page.starts_with("https://vimeo.com/") {
        // `width` sizes the poster; the play-badge variant comes with it.
        format!("https://vimeo.com/api/oembed.json?url={}&width=1280", query_escape(&page))
    } else {
        format!("https://www.youtube.com/oembed?url={}&format=json", query_escape(&page))
    };
    Some(VideoRef { page_url: page, oembed_url: oembed })
}

/// Percent-encode a URL so it can ride inside another URL's query string.
fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// One `![alt](url){attrs}` occurrence parsed out of markdown source.
pub(crate) struct PandocImage<'a> {
    pub(crate) alt: &'a str,
    pub(crate) url: &'a str,
    pub(crate) width: Option<&'a str>,
    pub(crate) height: Option<&'a str>,
    pub(crate) classes: Vec<&'a str>,
    /// Byte length of the whole occurrence, attribute span included.
    consumed: usize,
}

impl PandocImage<'_> {
    /// No attribute was recognized, so the image is best left as markdown.
    pub(crate) fn is_plain(&self) -> bool {
        self.width.is_none() && self.height.is_none() && self.classes.is_empty()
    }

    /// The image as plain markdown, attribute span dropped.
    pub(crate) fn markdown(&self) -> String {
        format!("![{}]({})", self.alt, self.url)
    }
}

/// Replace every pandoc-style image attribute span (`![alt](url){width=Npx .class}`)
/// with whatever `f` returns for it, copying the rest of the source verbatim.
/// pulldown-cmark doesn't understand pandoc syntax; without this the `{...}`
/// either rendered as literal text or (when only stripped) dropped classes
/// like `.logo-light`/`.logo-dark` that the page CSS uses to pick the right
/// asset for the active theme - causing both logos to flash on load.
/// The email renderer shares this so an author sizes an image the same way in
/// a newsletter as on a page.
pub(crate) fn rewrite_pandoc_images(
    body_md: &str,
    f: &mut dyn FnMut(&PandocImage) -> String,
) -> String {
    let bytes = body_md.as_bytes();
    let mut out = String::with_capacity(body_md.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'!'
            && i + 1 < bytes.len()
            && bytes[i + 1] == b'['
            && (i == 0 || bytes[i - 1] != b'\\')
        {
            if let Some(img) = scan_pandoc_image(&body_md[i..]) {
                out.push_str(&f(&img));
                i += img.consumed;
                continue;
            }
        }
        // Step by characters, not bytes: `push(byte as char)` would re-encode
        // every non-ASCII byte as its Latin-1 code point and mangle the text.
        let ch = body_md[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Rewrite attribute spans into raw HTML `<img>` tags so the attributes
/// survive into the SSR body.
fn rewrite_pandoc_image_attrs(body_md: &str) -> String {
    rewrite_pandoc_images(body_md, &mut |img| {
        if img.is_plain() {
            return img.markdown();
        }
        let mut html = format!(
            r#"<img alt="{}" src="{}""#,
            html_escape(img.alt),
            html_escape(img.url),
        );
        if let Some(w) = img.width {
            html.push_str(&format!(r#" width="{}""#, html_escape(w)));
        }
        if let Some(h) = img.height {
            html.push_str(&format!(r#" height="{}""#, html_escape(h)));
        }
        if !img.classes.is_empty() {
            html.push_str(&format!(r#" class="{}""#, html_escape(&img.classes.join(" "))));
        }
        html.push('>');
        html
    })
}

/// Try to parse `![alt](url)` with an optional `{attrs}` span at the
/// beginning of `s`. An image without a span still parses - the newsletter
/// has to recognize a video target whether or not it was given a size - and
/// callers that have nothing to change put back `markdown()`, which is
/// byte-identical to what they matched.
fn scan_pandoc_image(s: &str) -> Option<PandocImage<'_>> {
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

    let mut attrs = "";
    if consumed < bytes.len() && bytes[consumed] == b'{' {
        if let Some(off) = bytes[consumed + 1..].iter().position(|&b| b == b'}' || b == b'\n') {
            if bytes[consumed + 1 + off] == b'}' {
                attrs = &s[consumed + 1..consumed + 1 + off];
                consumed += 1 + off + 1;
            }
        }
    }

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

    Some(PandocImage { alt, url, width, height, classes, consumed })
}

/// Render markdown body into HTML for SSR injection, with tables, footnotes,
/// strikethrough, and task lists enabled. Relative image src/href stay
/// relative; the existing page CSS handles image sizing.
///
/// The output is sanitized: pages are admin-edited, but a leaked admin
/// credential (API tokens skip the TOTP gate) must not become persistent XSS
/// on the public site. Ammonia strips script/style/event handlers and
/// javascript: URLs while keeping document structure; `class`/`id` are
/// allowed so the image attributes emitted above survive. The client-side
/// renderer escapes raw HTML entirely, so nothing user-visible relies on
/// markup this strips.
pub(crate) fn render_body_html(body_md: &str) -> String {
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
    ammonia::Builder::default()
        .add_generic_attributes(&["class", "id"])
        .clean(&out)
        .to_string()
}

fn first_default_slug(pages: &[PageRow]) -> Option<&str> {
    // Posts never become the home page.
    let mut top: Vec<&PageRow> = pages.iter().filter(|p| p.2.is_none() && !is_post(p)).collect();
    top.sort_by(|a, b| a.3.cmp(&b.3).then_with(|| a.1.cmp(&b.1)));
    top.first()
        .map(|p| p.0.as_str())
        .or_else(|| pages.iter().find(|p| !is_post(p)).map(|p| p.0.as_str()))
}

/// Visible posts, newest first (ties broken by title).
fn sorted_posts(pages: &[PageRow]) -> Vec<&PageRow> {
    let mut posts: Vec<&PageRow> = pages.iter().filter(|p| is_post(p)).collect();
    posts.sort_by(|a, b| b.8.cmp(&a.8).then_with(|| a.1.cmp(&b.1)));
    posts
}

/// Post excerpt for index/feed surfaces: explicit meta_description when set,
/// otherwise derived from the post body.
fn post_excerpt(state: &Arc<AppState>, site: &SiteConfig, p: &PageRow) -> String {
    if !p.5.trim().is_empty() {
        return p.5.clone();
    }
    let db = state.db.lock();
    db.get_website_page(site.id, &p.0)
        .ok()
        .flatten()
        .map(|(_t, body, ..)| derive_description(&body))
        .unwrap_or_default()
}

fn build_breadcrumbs(
    site: &SiteConfig,
    pages: &[PageRow],
    slug: &str,
    home_slug: Option<&str>,
) -> String {
    let by_slug: std::collections::HashMap<&str, &PageRow> =
        pages.iter().map(|p| (p.0.as_str(), p)).collect();

    // Posts always crumb as Home › Blog › Post, independent of parent_slug.
    if by_slug.get(slug).map(|p| is_post(p)).unwrap_or(false) {
        let mut items: Vec<String> = Vec::new();
        let mut pos = 1;
        if let Some(hs) = home_slug {
            if let Some(home_page) = by_slug.get(hs) {
                items.push(format!(
                    r#"{{"@type":"ListItem","position":{},"name":"{}","item":"{}"}}"#,
                    pos,
                    html_escape(&home_page.1),
                    html_escape(&canonical_page_url(site, hs, true)),
                ));
                pos += 1;
            }
        }
        let blog_title = by_slug.get("blog").map(|p| p.1.as_str()).unwrap_or("Blog");
        items.push(format!(
            r#"{{"@type":"ListItem","position":{},"name":"{}","item":"{}"}}"#,
            pos,
            html_escape(blog_title),
            html_escape(&format!("{}/blog", site.public_base)),
        ));
        pos += 1;
        items.push(format!(
            r#"{{"@type":"ListItem","position":{},"name":"{}","item":"{}"}}"#,
            pos,
            html_escape(&by_slug[slug].1),
            html_escape(&canonical_post_url(site, slug)),
        ));
        return format!(
            r#"{{"@context":"https://schema.org","@type":"BreadcrumbList","itemListElement":[{}]}}"#,
            items.join(",")
        );
    }

    let mut chain: Vec<&PageRow> = Vec::new();
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
                    html_escape(&canonical_page_url(site, hs, true)),
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
            html_escape(&canonical_page_url(site, &p.0, is_home)),
        ));
        pos += 1;
    }
    format!(
        r#"{{"@context":"https://schema.org","@type":"BreadcrumbList","itemListElement":[{}]}}"#,
        items.join(",")
    )
}

fn render_seo_head(
    site: &SiteConfig,
    slug: &str,
    page_title: &str,
    description: &str,
    updated_at: &str,
    og_image_override: Option<&str>,
    pages: &[PageRow],
    products: &[(String, String, String, i64, String, Option<String>, String, bool, i64, String)],
    post_published: Option<&str>,
    post_author: Option<&str>,
) -> String {
    let home_slug = first_default_slug(pages);
    let is_home = home_slug == Some(slug);
    let canonical = if post_published.is_some() {
        canonical_post_url(site, slug)
    } else {
        canonical_page_url(site, slug, is_home)
    };
    let full_title = if is_home {
        format!("{} - {}", site.name, site.tagline)
    } else {
        format!("{} - {}", page_title, site.name)
    };

    // Organization JSON-LD is identical across a site's pages - built once
    // at module init in `sites.rs`.
    let org_jsonld: &str = sites::org_jsonld(site);

    // Per-page schema: WebSite (with sitelinks search action stub) for the
    // home page, BlogPosting for posts, WebPage for everything else. This
    // matches what Google's structured-data parser expects and powers rich
    // results.
    let date_modified = iso8601_z(updated_at);
    let page_jsonld = if let Some(published) = post_published {
        // A named author is a Person; without one the site itself takes the
        // credit, which is what Google expects an author field to hold.
        let author_ld = match post_author {
            Some(name) => format!(
                r#"{{"@type":"Person","name":"{}"}}"#,
                html_escape(name),
            ),
            None => format!(
                r#"{{"@type":"Organization","name":"{}","url":"{}"}}"#,
                html_escape(site.name),
                html_escape(site.public_base),
            ),
        };
        let publisher_logo = if site.logo_url.is_empty() {
            String::new()
        } else {
            format!(r#","logo":{{"@type":"ImageObject","url":"{}"}}"#, html_escape(site.logo_url))
        };
        format!(
            r#"{{"@context":"https://schema.org","@type":"BlogPosting","headline":"{title}","description":"{desc}","url":"{url}","mainEntityOfPage":{{"@type":"WebPage","@id":"{url}"}},"datePublished":"{published}","dateModified":"{date}","author":{author_ld},"publisher":{{"@type":"Organization","name":"{site_name}","url":"{base}"{publisher_logo}}}}}"#,
            title = html_escape(page_title),
            desc = html_escape(description),
            url = html_escape(&canonical),
            published = html_escape(published),
            date = html_escape(&date_modified),
            author_ld = author_ld,
            site_name = html_escape(site.name),
            base = html_escape(site.public_base),
            publisher_logo = publisher_logo,
        )
    } else if is_home {
        format!(
            r#"{{"@context":"https://schema.org","@type":"WebSite","name":"{name}","url":"{url}","description":"{desc}","publisher":{{"@type":"Organization","name":"{name}","url":"{url}"}}}}"#,
            name = html_escape(site.name),
            url = html_escape(site.public_base),
            desc = html_escape(description),
        )
    } else {
        format!(
            r#"{{"@context":"https://schema.org","@type":"WebPage","name":"{title}","description":"{desc}","url":"{url}","dateModified":"{date}","isPartOf":{{"@type":"WebSite","name":"{site_name}","url":"{base}"}},"publisher":{{"@type":"Organization","name":"{site_name}","url":"{base}"}}}}"#,
            title = html_escape(page_title),
            desc = html_escape(description),
            url = html_escape(&canonical),
            date = html_escape(&date_modified),
            site_name = html_escape(site.name),
            base = html_escape(site.public_base),
        )
    };

    let breadcrumb_jsonld = build_breadcrumbs(site, pages, slug, home_slug);

    // Product schema: emit one Product per matching shop SKU. A page slug
    // like `lpms-curs3` matches every shop product whose SKU starts with the
    // slug (e.g., lpms-curs3-can, lpms-curs3-rs232) so the page describes the
    // family with one Offer per variant.
    let product_blocks = build_product_jsonld(site, slug, products);

    // Per-page hero image, falling back to the site's social card; a site
    // without one omits the image tags entirely.
    let og_image = og_image_override
        .map(str::to_string)
        .or_else(|| (!site.og_image_url.is_empty()).then(|| site.og_image_url.to_string()));
    // Per-page hero image keeps standard 1200x630 dimensions only when we
    // fall back to the bundled site card; for body-derived images we omit
    // the dimensions to avoid lying about the source image.
    let og_image_meta = match og_image.as_deref() {
        Some(img) => {
            let mut m = format!("<meta property=\"og:image\" content=\"{}\">\n", html_escape(img));
            if og_image_override.is_none() {
                m.push_str(
                    "<meta property=\"og:image:width\" content=\"1200\">\n\
                     <meta property=\"og:image:height\" content=\"630\">\n",
                );
            }
            m.push_str(&format!(
                "<meta name=\"twitter:image\" content=\"{}\">\n",
                html_escape(img),
            ));
            m
        }
        None => String::new(),
    };
    // Posts advertise themselves as articles with publish/modified times.
    let article_meta = match post_published {
        Some(published) => format!(
            "<meta property=\"article:published_time\" content=\"{}\">\n\
             <meta property=\"article:modified_time\" content=\"{}\">\n",
            html_escape(published),
            html_escape(&date_modified),
        ),
        None => String::new(),
    };
    let mut head = format!(
        concat!(
            "<title>{title}</title>\n",
            "<meta name=\"description\" content=\"{desc}\">\n",
            "<link rel=\"canonical\" href=\"{canonical}\">\n",
            "<link rel=\"alternate\" type=\"application/rss+xml\" title=\"{site} Blog\" href=\"{base}/blog/rss.xml\">\n",
            "<meta property=\"og:type\" content=\"{og_type}\">\n",
            "<meta property=\"og:site_name\" content=\"{site}\">\n",
            "<meta property=\"og:title\" content=\"{title}\">\n",
            "<meta property=\"og:description\" content=\"{desc}\">\n",
            "<meta property=\"og:url\" content=\"{canonical}\">\n",
            "{article_meta}",
            "{og_image_meta}",
            "<meta name=\"twitter:card\" content=\"summary_large_image\">\n",
            "<meta name=\"twitter:title\" content=\"{title}\">\n",
            "<meta name=\"twitter:description\" content=\"{desc}\">\n",
            "<script type=\"application/ld+json\">{org_ld}</script>\n",
            "<script type=\"application/ld+json\">{page_ld}</script>\n",
            "<script type=\"application/ld+json\">{bc_ld}</script>\n",
        ),
        title = html_escape(&full_title),
        desc = html_escape(description),
        canonical = html_escape(&canonical),
        base = site.public_base,
        og_type = if post_published.is_some() { "article" } else { "website" },
        article_meta = article_meta,
        site = html_escape(site.name),
        og_image_meta = og_image_meta,
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
    site: &SiteConfig,
    slug: &str,
    products: &[(String, String, String, i64, String, Option<String>, String, bool, i64, String)],
) -> Vec<String> {
    let mut out = Vec::new();
    if !site.has_shop {
        return out;
    }
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
                format!("{}{}", site.public_base, s)
            } else {
                format!("{}/{}", site.public_base, s)
            }
        }).unwrap_or_else(|| site.og_image_url.to_string());
        out.push(format!(
            r#"{{"@context":"https://schema.org","@type":"Product","name":"{name}","description":"{desc}","sku":"{sku}","brand":{{"@type":"Brand","name":"{brand}"}},"image":"{img}","offers":{{"@type":"Offer","price":"{price}","priceCurrency":"{cur}","availability":"https://schema.org/InStock","url":"{url}","seller":{{"@type":"Organization","name":"{brand}","url":"{base}"}}}}}}"#,
            name = html_escape(title),
            desc = html_escape(&desc),
            sku = html_escape(sku),
            brand = html_escape(site.name),
            img = html_escape(&img),
            price = price,
            cur = html_escape(&cur_upper),
            url = html_escape(&format!("{}/shop/{}", site.public_base, sku)),
            base = html_escape(site.public_base),
        ));
    }
    out
}

pub async fn handle_website_render_root(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
) -> axum::response::Response {
    render_website(&state, &headers, &sq, None, false)
}

pub async fn handle_website_render_slug(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Path(slug): Path<String>,
) -> axum::response::Response {
    render_website(&state, &headers, &sq, Some(slug), false)
}

/// `/site/blog/{slug}` - blog posts under the /blog/ URL prefix.
pub async fn handle_website_render_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Path(slug): Path<String>,
) -> axum::response::Response {
    render_website(&state, &headers, &sq, Some(slug), true)
}

/// Per-site config injected into the shell so the client JS knows which site
/// it renders: canonical hosts (clean-URL detection), brand imagery, and
/// which fixed features exist.
fn site_config_script(site: &SiteConfig) -> String {
    format!(
        "<script>window.__SITE={};</script>",
        json!({
            "id": site.id,
            "name": site.name,
            "hosts": site.hosts,
            "brand_logo": site.brand_logo,
            "brand_logo_dark": site.brand_logo_dark,
            "has_shop": site.has_shop,
            "has_newsletter": site.has_newsletter,
        }),
    )
}

/// Inject head + body into the compiled-in shell.
pub(crate) fn render_shell(state: &Arc<AppState>, site: &SiteConfig, seo_head: &str, body_html: &str) -> Bytes {
    WEBSITE_HTML
        .replacen("<!--SEO_HEAD-->", seo_head, 1)
        .replacen("<!--SITE_CONFIG-->", &site_config_script(site), 1)
        .replacen("<!--ANALYTICS-->", &analytics_head(state, site), 1)
        .replacen("<!--BODY_CONTENT-->", body_html, 1)
        .into()
}

fn render_website(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    sq: &SiteQuery,
    requested_slug: Option<String>,
    post_path: bool,
) -> axum::response::Response {
    let site = match resolve_site(headers, sq) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    // Build the cache key first so we can short-circuit on a hit. Use the raw
    // requested slug (None → "" for the home shell). When the slug resolves to
    // home via `first_default_slug`, the cache still keys on what the client
    // asked for; this is correct because invalidation is global and TTL is short.
    let cache_key = if post_path {
        format!("{}|blog/{}", site.id, requested_slug.as_deref().unwrap_or_default())
    } else {
        format!("{}|{}", site.id, requested_slug.as_deref().unwrap_or_default())
    };
    if let Some(cached) = page_cache_get(&cache_key) {
        return (build_html_headers(), cached).into_response();
    }

    let (pages, products) = {
        let db = state.db.lock();
        (
            visible_pages(db.list_website_pages(site.id).unwrap_or_default()),
            if site.has_shop { db.list_products(true).unwrap_or_default() } else { Vec::new() },
        )
    };

    // A retired page 301s to its replacement. Checked before rendering and
    // never cached - retired slugs see little traffic, and a stale 301 is the
    // one redirect a browser will not re-ask about.
    if let Some(s) = requested_slug.as_deref() {
        let target = {
            let db = state.db.lock();
            db.get_website_page(site.id, s)
                .ok()
                .flatten()
                .map(|r| r.10)
                .filter(|t| !t.trim().is_empty())
        };
        if let Some(t) = target {
            let to = redirect_location(&t, &pages, is_marketing_host(headers));
            return (StatusCode::MOVED_PERMANENTLY, [(header::LOCATION, to)]).into_response();
        }
    }

    // /blog renders the reverse-chron post index; an optional "blog" page row
    // supplies the title/intro when present.
    if !post_path && requested_slug.as_deref() == Some("blog") {
        let html = render_blog_index(state, site, &pages, &products);
        page_cache_put(cache_key, html.clone());
        return (build_html_headers(), html).into_response();
    }

    // /newsletter renders the public newsletter archive; an optional
    // "newsletter" page row supplies the title/intro when present. Sites
    // without a newsletter treat the slug as a normal page.
    if !post_path && site.has_newsletter && requested_slug.as_deref() == Some("newsletter") {
        let html = render_newsletter_index(state, site, &pages, &products);
        page_cache_put(cache_key, html.clone());
        return (build_html_headers(), html).into_response();
    }

    let slug_owned: Option<String> = requested_slug.or_else(|| {
        first_default_slug(&pages).map(|s| s.to_string())
    });
    // If the requested slug is unknown, render the shell anyway (SPA shows "Page not found")
    // but omit the SEO head - better than 500'ing.
    let (title, description, updated_at, valid_slug, body_md, post_published, post_author):
        (String, String, String, Option<String>, String, Option<String>, Option<String>) =
        if let Some(s) = slug_owned.as_deref() {
            let (row, author) = {
                let db = state.db.lock();
                let row = db.get_website_page(site.id, s).unwrap_or(None);
                let author = row.as_ref().and_then(|r| display_name(&db, &r.9));
                (row, author)
            };
            // A hidden page renders like an unknown slug: bare shell, no SEO
            // head, no body - the SPA shows "Page not found" to visitors.
            // The /blog/ path only serves posts.
            match row {
                Some((t, body, _p, _o, upd, meta, false, kind, published, _au, _rd))
                    if !post_path || kind == "post" =>
                {
                    let desc = if !meta.trim().is_empty() {
                        meta
                    } else {
                        let d = derive_description(&body);
                        if d.is_empty() { site.tagline.to_string() } else { d }
                    };
                    let is_post_kind = kind == "post";
                    (t, desc, upd, Some(s.to_string()), body,
                     is_post_kind.then_some(published),
                     if is_post_kind { author } else { None })
                }
                _ => (site.name.to_string(), site.tagline.to_string(), String::new(), None, String::new(), None, None),
            }
        } else {
            (site.name.to_string(), site.tagline.to_string(), String::new(), None, String::new(), None, None)
        };

    let og_image = first_image_url(site, &body_md);
    let injected = match valid_slug.as_deref() {
        Some(s) => render_seo_head(
            site, s, &title, &description, &updated_at, og_image.as_deref(), &pages, &products,
            post_published.as_deref(), post_author.as_deref(),
        ),
        None => format!(
            "<title>{}</title>\n<meta name=\"description\" content=\"{}\">\n",
            html_escape(site.name),
            html_escape(site.tagline),
        ),
    };

    let body_html = if body_md.is_empty() {
        "<div class=\"empty-state\">Loading…</div>".to_string()
    } else {
        let mut h = String::new();
        if let Some(published) = post_published.as_deref() {
            h.push_str(&format!(
                "<div class=\"meta\">{}{}</div>",
                html_escape(&format_post_date(published)),
                byline_suffix(post_author.as_deref()),
            ));
        }
        h.push_str(&absolutize_bare_img_srcs(&render_body_html(&body_md)));
        h
    };

    let html = render_shell(state, site, &injected, &body_html);
    page_cache_put(cache_key, html.clone());
    (build_html_headers(), html).into_response()
}

/// SSR body + head for the /blog index: intro from the optional "blog" page
/// row, then every visible post newest-first with date and excerpt.
fn render_blog_index(
    state: &Arc<AppState>,
    site: &SiteConfig,
    pages: &[PageRow],
    products: &[(String, String, String, i64, String, Option<String>, String, bool, i64, String)],
) -> Bytes {
    let row = {
        let db = state.db.lock();
        db.get_website_page(site.id, "blog").unwrap_or(None)
    };
    let (title, intro_md, updated_at, meta) = match row {
        Some((t, body, _p, _o, upd, m, false, _k, _pd, _au, _rd)) => (t, body, upd, m),
        _ => ("Blog".to_string(), String::new(), String::new(), String::new()),
    };
    let posts = sorted_posts(pages);

    let description = if !meta.trim().is_empty() {
        meta
    } else {
        let d = derive_description(&intro_md);
        if d.is_empty() { format!("News and updates from {}.", site.name) } else { d }
    };

    let mut body_html = if intro_md.is_empty() {
        format!("<h1>{}</h1>", html_escape(&title))
    } else {
        render_body_html(&intro_md)
    };
    if posts.is_empty() {
        body_html.push_str("<p>No posts yet.</p>");
    } else {
        // Full posts inline, newest first - the date links to the permalink.
        body_html.push_str("<div class=\"blog-index\">");
        for p in &posts {
            let (post_body, author) = {
                let db = state.db.lock();
                let body = db
                    .get_website_page(site.id, &p.0)
                    .ok()
                    .flatten()
                    .map(|(_t, body, ..)| body)
                    .unwrap_or_default();
                (body, display_name(&db, &p.9))
            };
            let permalink = format!("/blog/{}", p.0);
            body_html.push_str(&format!(
                "<article class=\"blog-index-item\"><div class=\"meta\">\
                 <a href=\"{link}\">{date}</a>{byline}</div>{body}</article>",
                link = html_escape(&permalink),
                date = html_escape(&format_post_date(&p.8)),
                byline = byline_suffix(author.as_deref()),
                body = link_first_heading(&render_body_html(&post_body), &permalink),
            ));
        }
        body_html.push_str("</div>");
    }

    // dateModified for the index: the newest post, else the intro page edit.
    let updated = posts.first().map(|p| p.4.clone()).unwrap_or(updated_at);
    let injected = render_seo_head(site, "blog", &title, &description, &updated, None, pages, products, None, None);
    render_shell(state, site, &injected, &body_html)
}

/// Newsletter bodies reference uploaded images by bare filename (the composer
/// upload hook inserts `data.name`, not a URL). The SPA resolves those
/// client-side; the SSR fallback must point them at the asset store
/// explicitly, or a crawler resolves them against /newsletter and gets the
/// page shell back.
fn absolutize_bare_img_srcs(html: &str) -> String {
    let mut out = String::with_capacity(html.len() + 64);
    let mut i = 0;
    while let Some(p) = html[i..].find("src=\"") {
        let start = i + p + 5;
        out.push_str(&html[i..start]);
        i = start;
        let Some(e) = html[start..].find('"') else { break };
        let url = &html[start..start + e];
        let lower = url.to_ascii_lowercase();
        if !(url.is_empty()
            || url.starts_with('/')
            || url.starts_with('#')
            || lower.starts_with("http://")
            || lower.starts_with("https://")
            || lower.starts_with("data:"))
        {
            out.push_str("/api/v1/website/assets/");
        }
    }
    out.push_str(&html[i..]);
    out
}

/// Markdown for a newsletter issue as shown on the website: the email-only
/// [TOC] marker lines are dropped - the site has its own TOC sidebar.
fn newsletter_web_md(body_md: &str) -> String {
    body_md
        .lines()
        .filter(|l| !crate::newsletter::is_toc_marker(l.trim()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// SSR body + head for the /newsletter archive: intro from the optional
/// "newsletter" page row, then every issue published to the site,
/// newest first.
fn render_newsletter_index(
    state: &Arc<AppState>,
    site: &SiteConfig,
    pages: &[PageRow],
    products: &[(String, String, String, i64, String, Option<String>, String, bool, i64, String)],
) -> Bytes {
    let (row, issues) = {
        let db = state.db.lock();
        (
            db.get_website_page(site.id, "newsletter").unwrap_or(None),
            db.list_public_newsletter_issues().unwrap_or_default(),
        )
    };
    let (title, intro_md, updated_at, meta) = match row {
        Some((t, body, _p, _o, upd, m, false, _k, _pd, _au, _rd)) => (t, body, upd, m),
        _ => ("Newsletter".to_string(), String::new(), String::new(), String::new()),
    };

    let description = if !meta.trim().is_empty() {
        meta
    } else {
        let d = derive_description(&intro_md);
        if d.is_empty() { format!("Past newsletters from {}.", site.name) } else { d }
    };

    let mut body_html = if intro_md.is_empty() {
        format!("<h1>{}</h1>", html_escape(&title))
    } else {
        render_body_html(&intro_md)
    };
    if issues.is_empty() {
        body_html.push_str("<p>No newsletters yet.</p>");
    } else {
        body_html.push_str("<div class=\"blog-index\">");
        for (_id, subject, body_md, sent_at) in &issues {
            let date = sent_at.get(..10).unwrap_or(sent_at);
            body_html.push_str(&format!(
                "<article class=\"blog-index-item\"><div class=\"meta\">{date}</div>\
                 <h1>{subject}</h1>{body}</article>",
                date = html_escape(&format_post_date(date)),
                subject = html_escape(subject),
                body = absolutize_bare_img_srcs(&render_body_html(&newsletter_web_md(body_md))),
            ));
        }
        body_html.push_str("</div>");
    }

    // dateModified for the archive: the newest issue, else the intro page edit.
    let updated = issues.first().map(|i| i.3.clone()).unwrap_or(updated_at);
    let injected =
        render_seo_head(site, "newsletter", &title, &description, &updated, None, pages, products, None, None);
    render_shell(state, site, &injected, &body_html)
}

/// RSS 2.0 feed of visible posts at /blog/rss.xml.
pub async fn handle_blog_rss(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
) -> impl IntoResponse {
    let site = match resolve_site(&headers, &sq) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let pages = {
        let db = state.db.lock();
        visible_pages(db.list_website_pages(site.id).unwrap_or_default())
    };
    let posts = sorted_posts(&pages);

    let mut xml = String::from(concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
        "<rss version=\"2.0\" xmlns:atom=\"http://www.w3.org/2005/Atom\">\n",
        "<channel>\n",
    ));
    xml.push_str(&format!("<title>{} Blog</title>\n", xml_escape(site.name)));
    xml.push_str(&format!("<link>{}/blog</link>\n", site.public_base));
    xml.push_str(&format!(
        "<atom:link href=\"{}/blog/rss.xml\" rel=\"self\" type=\"application/rss+xml\"/>\n",
        site.public_base,
    ));
    xml.push_str(&format!(
        "<description>News and updates from {}.</description>\n",
        xml_escape(site.name),
    ));
    xml.push_str("<language>en</language>\n");
    for p in &posts {
        let excerpt = post_excerpt(&state, site, p);
        let url = canonical_post_url(site, &p.0);
        xml.push_str("<item>\n");
        xml.push_str(&format!("<title>{}</title>\n", xml_escape(&p.1)));
        xml.push_str(&format!("<link>{}</link>\n", xml_escape(&url)));
        xml.push_str(&format!("<guid>{}</guid>\n", xml_escape(&url)));
        if let Ok(d) = chrono::NaiveDate::parse_from_str(&p.8, "%Y-%m-%d") {
            xml.push_str(&format!(
                "<pubDate>{}</pubDate>\n",
                d.format("%a, %d %b %Y 00:00:00 +0000"),
            ));
        }
        if !excerpt.is_empty() {
            xml.push_str(&format!("<description>{}</description>\n", xml_escape(&excerpt)));
        }
        xml.push_str("</item>\n");
    }
    xml.push_str("</channel>\n</rss>\n");

    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, "application/rss+xml; charset=utf-8".parse().unwrap());
    h.insert(header::CACHE_CONTROL, "public, max-age=600".parse().unwrap());
    (h, xml).into_response()
}

fn build_html_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, "text/html; charset=utf-8".parse().unwrap());
    h.insert(header::CACHE_CONTROL, "public, max-age=60".parse().unwrap());
    h
}

pub const SETTING_GOOGLE_ANALYTICS_ID: &str = "google_analytics_id";
pub const SETTING_GOOGLE_ADS_ID: &str = "google_ads_id";
pub const SETTING_GOOGLE_ADS_LABEL_CONTACT: &str = "google_ads_label_contact";
pub const SETTING_GOOGLE_ADS_LABEL_PURCHASE: &str = "google_ads_label_purchase";
pub const SETTING_REDDIT_PIXEL_ID: &str = "reddit_pixel_id";
pub const SETTING_NAV_STRUCTURE: &str = "nav_structure";

/// Sidebar nav config: JSON array of groups rendered between the ungrouped
/// pages and nothing else. Items are page slugs, plus the pseudo-slugs
/// "__blog__" and "__shop__" for the fixed Blog/Shop links.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NavGroup {
    title: String,
    items: Vec<String>,
}

fn is_valid_nav_structure(s: &str) -> bool {
    if s.len() > 4096 {
        return false;
    }
    match serde_json::from_str::<Vec<NavGroup>>(s) {
        Ok(groups) => {
            groups.len() <= 12
                && groups.iter().all(|g| {
                    !g.title.trim().is_empty()
                        && g.title.len() <= 40
                        && g.items.len() <= 50
                        && g.items.iter().all(|i| !i.is_empty() && i.len() <= 100)
                })
        }
        Err(_) => false,
    }
}

/// Parsed nav structure for the public pages response, or None when the
/// setting is unset/invalid (the site then falls back to a flat nav).
pub fn nav_structure_json(state: &Arc<AppState>, site: &SiteConfig) -> Option<serde_json::Value> {
    let raw = {
        let db = state.db.lock();
        db.get_site_setting(&sites::setting_key(site, SETTING_NAV_STRUCTURE)).ok().flatten()?
    };
    if !is_valid_nav_structure(&raw) {
        return None;
    }
    serde_json::from_str(&raw).ok()
}

/// Validate an analytics tag ID (GA Measurement ID, Reddit Pixel ID).
/// Restrict to `[A-Za-z0-9_-]` so it can be safely interpolated into
/// script URLs and inline JS without escaping. Length cap keeps stored
/// values sane.
fn is_valid_analytics_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Render the analytics `<script>` blocks from the configured tag IDs,
/// or empty string when unset. Called per-request - DB lookups are cheap.
pub fn analytics_head(state: &Arc<AppState>, site: &SiteConfig) -> String {
    let (ga_id, ads_id, ads_contact, ads_purchase, reddit_id) = {
        let db = state.db.lock();
        (
            db.get_site_setting(&sites::setting_key(site, SETTING_GOOGLE_ANALYTICS_ID)).ok().flatten(),
            db.get_site_setting(&sites::setting_key(site, SETTING_GOOGLE_ADS_ID)).ok().flatten(),
            db.get_site_setting(&sites::setting_key(site, SETTING_GOOGLE_ADS_LABEL_CONTACT)).ok().flatten(),
            db.get_site_setting(&sites::setting_key(site, SETTING_GOOGLE_ADS_LABEL_PURCHASE)).ok().flatten(),
            db.get_site_setting(&sites::setting_key(site, SETTING_REDDIT_PIXEL_ID)).ok().flatten(),
        )
    };
    render_analytics_head(
        site,
        ga_id.as_deref(),
        ads_id.as_deref(),
        ads_contact.as_deref(),
        ads_purchase.as_deref(),
        reddit_id.as_deref(),
    )
}

/// Pure renderer behind `analytics_head`. Nothing third-party loads at parse
/// time: the configured tag IDs are embedded as data and the vendors (gtag.js
/// for GA + Google Ads, the Reddit pixel) are only injected once the visitor's
/// consent state allows it. Prior opt-in via the banner is required in the
/// EEA/UK/CH (ePrivacy Art 5(3)), detected from the browser time zone and
/// failing safe to "required" when that is unreadable; elsewhere the vendors
/// load by default and the footer link re-opens the banner to opt out. The
/// choice is stored in localStorage; "decline" keeps the page free of any
/// third-party request. Conversion labels surface as `window.__adsConv`
/// post-consent, so the existing conversion-firing site JS needs no changes.
fn render_analytics_head(
    site: &SiteConfig,
    ga_id: Option<&str>,
    ads_id: Option<&str>,
    ads_contact: Option<&str>,
    ads_purchase: Option<&str>,
    reddit_id: Option<&str>,
) -> String {
    let ga_id = ga_id.filter(|s| is_valid_analytics_id(s));
    let ads_id = ads_id.filter(|s| is_valid_analytics_id(s));
    let reddit_id = reddit_id.filter(|s| is_valid_analytics_id(s));
    if ga_id.is_none() && ads_id.is_none() && reddit_id.is_none() {
        // No trackers configured - no third-party requests, no banner needed.
        return String::new();
    }

    let mut cfg = Vec::new();
    if let Some(id) = ga_id {
        cfg.push(format!("ga:'{id}'"));
    }
    if let Some(id) = ads_id {
        cfg.push(format!("ads:'{id}'"));
        let mut conv = Vec::new();
        if let Some(l) = ads_contact.filter(|s| is_valid_analytics_id(s)) {
            conv.push(format!("contact:'{id}/{l}'"));
        }
        if let Some(l) = ads_purchase.filter(|s| is_valid_analytics_id(s)) {
            conv.push(format!("purchase:'{id}/{l}'"));
        }
        if !conv.is_empty() {
            cfg.push(format!("conv:{{{}}}", conv.join(",")));
        }
    }
    if let Some(id) = reddit_id {
        cfg.push(format!("reddit:'{id}'"));
    }

    format!(
        "<!-- Analytics: consent-gated, loads nothing until accepted -->\n\
<script>\n\
(function() {{\n\
var cfg = {{{cfg}}};\n\
var loaded = false;\n\
function loadVendors() {{\n\
  loaded = true;\n\
  if (cfg.ga || cfg.ads) {{\n\
    var s = document.createElement('script');\n\
    s.async = true;\n\
    s.src = 'https://www.googletagmanager.com/gtag/js?id=' + (cfg.ga || cfg.ads);\n\
    document.head.appendChild(s);\n\
    window.dataLayer = window.dataLayer || [];\n\
    window.gtag = function() {{ dataLayer.push(arguments); }};\n\
    gtag('js', new Date());\n\
    if (cfg.ga) gtag('config', cfg.ga);\n\
    if (cfg.ads) {{ gtag('config', cfg.ads); if (cfg.conv) window.__adsConv = cfg.conv; }}\n\
  }}\n\
  if (cfg.reddit) {{\n\
    !function(w,d){{if(!w.rdt){{var p=w.rdt=function(){{p.sendEvent?p.sendEvent.apply(p,arguments):p.callQueue.push(arguments)}};p.callQueue=[];var t=d.createElement(\"script\");t.src=\"https://www.redditstatic.com/ads/pixel.js\",t.async=!0;var s=d.getElementsByTagName(\"script\")[0];s.parentNode.insertBefore(t,s)}}}}(window,document);\n\
    rdt('init', cfg.reddit);\n\
    rdt('track', 'PageVisit');\n\
  }}\n\
}}\n\
window.__applyConsent = function(granted) {{\n\
  try {{ localStorage.setItem('cookie_consent', granted ? 'accepted' : 'declined'); }} catch (e) {{}}\n\
  var b = document.getElementById('cookieConsent');\n\
  if (b) b.remove();\n\
  if (granted) loadVendors();\n\
  else if (loaded) location.reload();\n\
}};\n\
function showBanner() {{\n\
  if (document.getElementById('cookieConsent')) return;\n\
  var prefix = ({hosts}.indexOf(location.host) !== -1) ? '' : '/site';\n\
  var b = document.createElement('div');\n\
  b.id = 'cookieConsent';\n\
  b.style.cssText = 'position:fixed;left:0;right:0;bottom:0;z-index:9999;display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:center;padding:14px 16px;background:var(--bg2,#161922);border-top:1px solid var(--border,#262b38);color:var(--text1,#e6e8ec);font-size:14px;';\n\
  b.innerHTML = '<span>We use cookies for analytics and advertising. See our <a href=\"' + prefix + '/privacy\" style=\"color:var(--accent,#6aa9ff)\">privacy policy</a>.</span>'\n\
    + '<span style=\"display:flex;gap:8px\">'\n\
    + '<button id=\"ccDecline\" style=\"padding:6px 14px;border-radius:6px;border:1px solid var(--border,#262b38);background:transparent;color:inherit;cursor:pointer\">Decline</button>'\n\
    + '<button id=\"ccAccept\" style=\"padding:6px 14px;border-radius:6px;border:0;background:var(--accent,#6aa9ff);color:#0b1020;cursor:pointer\">Accept</button>'\n\
    + '</span>';\n\
  document.body.appendChild(b);\n\
  document.getElementById('ccAccept').onclick = function() {{ window.__applyConsent(true); }};\n\
  document.getElementById('ccDecline').onclick = function() {{ window.__applyConsent(false); }};\n\
}}\n\
var CONSENT_TZ = ['Atlantic/Reykjavik','Atlantic/Canary','Atlantic/Madeira','Atlantic/Azores','Atlantic/Faroe','Africa/Ceuta','Asia/Nicosia','Asia/Famagusta','America/Martinique','America/Guadeloupe','America/Cayenne','America/Miquelon','Indian/Reunion','Indian/Mayotte'];\n\
function consentRequired() {{\n\
  var tz = '';\n\
  try {{ tz = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; }} catch (e) {{ return true; }}\n\
  if (!tz) return true;\n\
  return tz.indexOf('Europe/') === 0 || CONSENT_TZ.indexOf(tz) !== -1;\n\
}}\n\
function onReady(fn) {{\n\
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn);\n\
  else fn();\n\
}}\n\
function wireSettingsLink() {{\n\
  var l = document.querySelector('[data-cookie-settings]');\n\
  if (!l) return;\n\
  l.style.display = '';\n\
  l.onclick = function(e) {{ e.preventDefault(); showBanner(); }};\n\
}}\n\
var choice = null;\n\
try {{ choice = localStorage.getItem('cookie_consent'); }} catch (e) {{}}\n\
if (choice === 'accepted') {{ loadVendors(); }}\n\
else if (choice === 'declined') {{}}\n\
else if (consentRequired()) {{ onReady(showBanner); }}\n\
else {{ loadVendors(); }}\n\
onReady(wireSettingsLink);\n\
}})();\n\
</script>\n",
        cfg = cfg.join(","),
        hosts = serde_json::to_string(site.hosts).unwrap_or_else(|_| "[]".to_string()),
    )
}

/// True when the request came in on a marketing-site host (clean slug URLs);
/// false on the dashboard/docs host, where the site lives under /site.
fn is_marketing_host(headers: &HeaderMap) -> bool {
    sites::site_from_headers(headers).is_some()
}

/// Google Search Console site-verification file for susi.lp-research.com.
pub async fn handle_google_site_verification() -> impl IntoResponse {
    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, "text/html; charset=utf-8".parse().unwrap());
    (h, "google-site-verification: googledb0d71a54eee8f70.html")
}

pub async fn handle_robots_txt(headers: HeaderMap) -> impl IntoResponse {
    let sitemap_base = match sites::site_from_headers(&headers) {
        Some(site) => site.public_base,
        None => DOCS_PUBLIC_BASE,
    };
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
        base = sitemap_base,
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
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n",
    );
    if let Some(site) = sites::site_from_headers(&headers) {
        let pages = {
            let db = state.db.lock();
            visible_pages(db.list_website_pages(site.id).unwrap_or_default())
        };
        let home_slug = first_default_slug(&pages).map(|s| s.to_string());
        for (slug, _title, _parent, _ord, updated_at, _meta, _hidden, kind, _published, _author, _rd) in &pages {
            let is_home = home_slug.as_deref() == Some(slug.as_str());
            let loc = if kind == "post" {
                canonical_post_url(site, slug)
            } else {
                canonical_page_url(site, slug, is_home)
            };
            xml.push_str("  <url>\n");
            xml.push_str(&format!("    <loc>{}</loc>\n", xml_escape(&loc)));
            if !updated_at.is_empty() {
                xml.push_str(&format!("    <lastmod>{}</lastmod>\n", xml_escape(&iso8601_z(updated_at))));
            }
            xml.push_str("  </url>\n");
        }
    } else {
        for (url, updated_at) in docs_sitemap_entries(&state) {
            xml.push_str("  <url>\n");
            xml.push_str(&format!("    <loc>{}</loc>\n", xml_escape(&url)));
            if !updated_at.is_empty() {
                xml.push_str(&format!("    <lastmod>{}</lastmod>\n", xml_escape(&iso8601_z(&updated_at))));
            }
            xml.push_str("  </url>\n");
        }
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
    let site = sites::site_from_headers(&headers).unwrap_or_else(sites::default_site);
    let pages = {
        let db = state.db.lock();
        visible_pages(db.list_website_pages(site.id).unwrap_or_default())
    };
    let home_slug = first_default_slug(&pages).map(|s| s.to_string());

    let mut body = String::new();
    body.push_str(&format!("# {}\n\n", site.name));
    body.push_str(&format!("> {}\n\n", site.tagline));
    body.push_str(&format!(
        "{} ({}) {}\n\n",
        site.name, site.org_legal_name, site.llms_blurb,
    ));

    body.push_str("## Pages\n");
    for (slug, title, parent, _ord, _upd, meta, _hidden, kind, _published, _author, _rd) in &pages {
        if kind == "post" {
            continue;
        }
        let desc_source = if !meta.trim().is_empty() {
            meta.clone()
        } else {
            let row = {
                let db = state.db.lock();
                db.get_website_page(site.id, slug).unwrap_or(None)
            };
            row.map(|(_t, body, ..)| derive_description(&body))
                .unwrap_or_default()
        };
        let indent = if parent.is_some() { "  " } else { "" };
        let is_home = home_slug.as_deref() == Some(slug.as_str());
        let url = canonical_page_url(site, slug, is_home);
        if desc_source.is_empty() {
            body.push_str(&format!("{}- [{}]({})\n", indent, title, url));
        } else {
            body.push_str(&format!("{}- [{}]({}): {}\n", indent, title, url, desc_source));
        }
    }
    let posts = sorted_posts(&pages);
    if !posts.is_empty() {
        body.push_str("\n## Blog\n");
        for p in &posts {
            let excerpt = post_excerpt(&state, site, p);
            let url = canonical_post_url(site, &p.0);
            if excerpt.is_empty() {
                body.push_str(&format!("- [{}]({}) ({})\n", p.1, url, p.8));
            } else {
                body.push_str(&format!("- [{}]({}) ({}): {}\n", p.1, url, p.8, excerpt));
            }
        }
    }
    // The product docs live on the dashboard host and belong to the default
    // site's llms.txt only.
    if site.id == sites::default_site().id {
        body.push_str(&docs_llms_section(&state));
    }

    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, "text/plain; charset=utf-8".parse().unwrap());
    h.insert(header::CACHE_CONTROL, "public, max-age=600".parse().unwrap());
    (h, body)
}

// ---------------------------------------------------------------------------
// Site settings admin (JWT)
// ---------------------------------------------------------------------------

const KNOWN_SITE_SETTING_KEYS: &[&str] = &[
    SETTING_GOOGLE_ANALYTICS_ID,
    SETTING_GOOGLE_ADS_ID,
    SETTING_GOOGLE_ADS_LABEL_CONTACT,
    SETTING_GOOGLE_ADS_LABEL_PURCHASE,
    SETTING_REDDIT_PIXEL_ID,
    SETTING_NAV_STRUCTURE,
];

pub async fn handle_admin_get_site_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    let mut out = serde_json::Map::new();
    let db = state.db.lock();
    for k in KNOWN_SITE_SETTING_KEYS {
        let v = db
            .get_site_setting(&sites::setting_key(site, k))
            .map_err(db_err)?
            .unwrap_or_default();
        out.insert((*k).to_string(), serde_json::Value::String(v));
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
    Query(sq): Query<SiteQuery>,
    Json(req): Json<UpdateSiteSettingsRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    for (k, v) in &req.fields {
        if !KNOWN_SITE_SETTING_KEYS.contains(&k.as_str()) {
            return Err(error_response(StatusCode::BAD_REQUEST, &format!("Unknown setting: {}", k)));
        }
        let trimmed = v.trim();
        if k == SETTING_NAV_STRUCTURE {
            if !trimmed.is_empty() && !is_valid_nav_structure(trimmed) {
                return Err(error_response(
                    StatusCode::BAD_REQUEST,
                    "nav_structure must be a JSON array of {\"title\", \"items\"} groups (max 4 KB)",
                ));
            }
        } else if !trimmed.is_empty() && !is_valid_analytics_id(trimmed) {
            // The remaining site settings are analytics tag IDs / labels.
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                &format!("{} must contain only letters, digits, '-' or '_' (max 64 chars)", k),
            ));
        }
        let db = state.db.lock();
        db.set_site_setting(&sites::setting_key(site, k), trimmed).map_err(db_err)?;
    }
    invalidate_page_cache();
    Ok(Json(json!({ "status": "OK" })))
}

// ---------------------------------------------------------------------------
// IndexNow - push page changes to Bing/Yandex/Naver/Seznam (Google opts out).
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

/// Fetch the site's IndexNow key, lazily creating one the first time.
fn get_or_create_indexnow_key(state: &Arc<AppState>, site: &SiteConfig) -> Option<String> {
    let setting = sites::setting_key(site, SETTING_INDEXNOW_KEY);
    let existing = {
        let db = state.db.lock();
        db.get_site_setting(&setting).ok().flatten()
    };
    if let Some(k) = existing.filter(|k| !k.is_empty()) {
        return Some(k);
    }
    let key = generate_indexnow_key();
    let db = state.db.lock();
    db.set_site_setting(&setting, &key).ok()?;
    Some(key)
}

pub async fn handle_indexnow_key_file(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(filename): Path<String>,
) -> impl IntoResponse {
    let site = sites::site_from_headers(&headers).unwrap_or_else(sites::default_site);
    let Some(key) = get_or_create_indexnow_key(&state, site) else {
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
pub fn ping_indexnow(state: &Arc<AppState>, site: &SiteConfig, urls: Vec<String>) {
    if urls.is_empty() { return; }
    let Some(key) = get_or_create_indexnow_key(state, site) else { return };
    let host = site.public_base
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();
    // Root-level keyLocation so IndexNow accepts URLs under any path (the
    // service only accepts URLs at the same directory level or deeper than
    // the verification file). Nginx is configured to proxy
    // `^/[a-f0-9]{32}\.txt$` to the backend `/api/v1/indexnow/{filename}`
    // route.
    let key_location = format!("{}/{}.txt", site.public_base, key);
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
            across a wide range of applications - from wearables to autonomous vehicles \
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
            first_image_url(sites::default_site(), md),
            Some("https://xikaku.com/static/foo.png".to_string())
        );
    }

    #[test]
    fn first_image_url_resolves_bare_asset_name() {
        let md = "# Title\n\n![hero](image-2026-07-29T00-31-54-518.png)\n";
        assert_eq!(
            first_image_url(sites::default_site(), md),
            Some("https://xikaku.com/api/v1/website/assets/image-2026-07-29T00-31-54-518.png".to_string())
        );
    }

    #[test]
    fn first_image_url_uses_site_base() {
        let md = "![hero](/media/foo.png)";
        assert_eq!(
            first_image_url(sites::site_by_id("lpr").unwrap(), md),
            Some("https://www.lp-research.com/media/foo.png".to_string())
        );
    }

    #[test]
    fn first_image_url_passes_absolute() {
        let md = "![hero](https://cdn.example.com/img.jpg)";
        assert_eq!(
            first_image_url(sites::default_site(), md),
            Some("https://cdn.example.com/img.jpg".to_string())
        );
    }

    #[test]
    fn first_image_url_none_when_no_images() {
        assert_eq!(first_image_url(sites::default_site(), "# Just text\n\nNo images here."), None);
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
    fn redirect_location_resolves_every_target_form() {
        let page = |slug: &str, kind: &str| (
            slug.to_string(), "T".to_string(), None, 0, String::new(), String::new(),
            false, kind.to_string(), String::new(), String::new(), String::new(),
        );
        let pages = vec![page("lpms-curs3", "page"), page("my-post", "post")];

        // A bare slug resolves through its own kind, so a post lands on /blog.
        assert_eq!(redirect_location("lpms-curs3", &pages, true), "/lpms-curs3");
        assert_eq!(redirect_location("my-post", &pages, true), "/blog/my-post");
        // An unknown slug is still treated as a page rather than dropped.
        assert_eq!(redirect_location("gone", &pages, true), "/gone");
        // Explicit paths are taken as given.
        assert_eq!(redirect_location("/blog/my-post", &pages, true), "/blog/my-post");
        // Off the marketing host the app lives under /site.
        assert_eq!(redirect_location("lpms-curs3", &pages, false), "/site/lpms-curs3");
        assert_eq!(redirect_location("my-post", &pages, false), "/site/blog/my-post");
        // Absolute URLs pass through untouched, prefix included.
        assert_eq!(
            redirect_location("https://lp-research.com/x", &pages, false),
            "https://lp-research.com/x"
        );
        assert_eq!(redirect_location("  lpms-curs3  ", &pages, true), "/lpms-curs3");
    }

    #[test]
    fn link_first_heading_wraps_only_the_first_h1() {
        let html = link_first_heading(
            "<h1>First post</h1>\n<p>Body.</p>\n<h1>Later heading</h1>",
            "/blog/first-post",
        );
        assert_eq!(
            html,
            "<h1><a href=\"/blog/first-post\">First post</a></h1>\n<p>Body.</p>\n<h1>Later heading</h1>"
        );

        // Attributes on the tag survive, and inline markup inside stays intact.
        let html = link_first_heading("<h1 id=\"t\">A <em>b</em></h1>", "/blog/x");
        assert_eq!(html, "<h1 id=\"t\"><a href=\"/blog/x\">A <em>b</em></a></h1>");

        // A body with no h1 is left exactly as it was.
        let plain = "<p>No heading here.</p>";
        assert_eq!(link_first_heading(plain, "/blog/x"), plain);
        assert_eq!(link_first_heading("<h1>unclosed", "/blog/x"), "<h1>unclosed");
    }

    #[test]
    fn render_body_html_strips_xss_vectors() {
        let md = "<script>alert(1)</script>\n\n\
                  <img src=\"/x.png\" onerror=\"alert(1)\">\n\n\
                  [link](javascript:alert(1))\n\n\
                  <iframe src=\"https://evil.example\"></iframe>";
        let h = render_body_html(md);
        assert!(!h.contains("<script"), "got: {}", h);
        assert!(!h.contains("onerror"), "got: {}", h);
        assert!(!h.to_lowercase().contains("javascript:"), "got: {}", h);
        assert!(!h.contains("<iframe"), "got: {}", h);
    }

    #[test]
    fn svg_assets_are_download_only() {
        let mut h = HeaderMap::new();
        harden_svg_response("diagram.SVG", &mut h);
        assert_eq!(h.get(header::CONTENT_DISPOSITION).unwrap(), "attachment");
        assert!(h.get(header::CONTENT_SECURITY_POLICY).is_some());

        let mut h = HeaderMap::new();
        harden_svg_response("photo.png", &mut h);
        assert!(h.is_empty());
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

    /// Every shape videoEmbedSrc() accepts on the page has to resolve to the
    /// same video here, or a newsletter silently ships a broken image.
    #[test]
    fn video_ref_matches_the_shapes_the_site_embeds() {
        let page = |u: &str| video_ref(u).map(|v| v.page_url);
        assert_eq!(page("https://vimeo.com/76979871").as_deref(), Some("https://vimeo.com/76979871"));
        assert_eq!(page("http://www.vimeo.com/76979871").as_deref(), Some("https://vimeo.com/76979871"));
        assert_eq!(
            page("https://vimeo.com/76979871/a1b2c3d4e5").as_deref(),
            Some("https://vimeo.com/76979871/a1b2c3d4e5"),
            "an unlisted video only plays with its hash"
        );
        assert_eq!(
            page("https://vimeo.com/76979871?h=a1b2c3d4e5").as_deref(),
            Some("https://vimeo.com/76979871/a1b2c3d4e5")
        );
        assert_eq!(
            page("https://player.vimeo.com/video/76979871").as_deref(),
            Some("https://vimeo.com/76979871")
        );
        for yt in [
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://youtu.be/dQw4w9WgXcQ",
            "https://www.youtube.com/embed/dQw4w9WgXcQ",
        ] {
            assert_eq!(
                page(yt).as_deref(),
                Some("https://www.youtube.com/watch?v=dQw4w9WgXcQ"),
                "{}",
                yt
            );
        }
    }

    /// Anything else stays an image; a false positive would replace a picture
    /// with a "watch the video" link.
    #[test]
    fn video_ref_ignores_plain_images() {
        for u in [
            "logo.png",
            "/static/logo.png",
            "https://example.org/vimeo.com/x.png",
            "https://vimeo.com/staffpicks",
            "https://youtu.be/",
        ] {
            assert!(video_ref(u).is_none(), "{} is not a video", u);
        }
    }

    #[test]
    fn video_ref_builds_an_oembed_endpoint() {
        let v = video_ref("https://vimeo.com/76979871").expect("vimeo");
        assert_eq!(
            v.oembed_url,
            "https://vimeo.com/api/oembed.json?url=https%3A%2F%2Fvimeo.com%2F76979871&width=1280"
        );
        let y = video_ref("https://youtu.be/dQw4w9WgXcQ").expect("youtube");
        assert!(y.oembed_url.starts_with("https://www.youtube.com/oembed?url=https%3A%2F%2F"), "got: {}", y.oembed_url);
    }

    /// The rewrite walks the source byte by byte, so multi-byte characters
    /// around an image must come through untouched.
    #[test]
    fn rewrite_pandoc_image_attrs_keeps_non_ascii() {
        let md = "Grüße ![logo](/l.png){width=50%} aus München … ✅";
        let cleaned = rewrite_pandoc_image_attrs(md);
        assert!(cleaned.starts_with("Grüße "), "got: {}", cleaned);
        assert!(cleaned.ends_with(" aus München … ✅"), "got: {}", cleaned);
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
        assert!(is_valid_analytics_id("AW-18330845601"));
        assert!(is_valid_analytics_id("a2_jdm5gdy9bfis"));
        assert!(!is_valid_analytics_id(""));
        assert!(!is_valid_analytics_id("evil';alert(1)"));
        assert!(!is_valid_analytics_id(&"x".repeat(65)));
    }

    #[test]
    fn analytics_head_single_loader_for_ga_and_ads() {
        let out = render_analytics_head(
            sites::default_site(),
            Some("G-XSW6TEN1CZ"),
            Some("AW-18330845601"),
            Some("ctLabel-1"),
            Some("buyLabel_2"),
            None,
        );
        // Consent-gated: no direct third-party <script src>; both IDs are
        // embedded as config for the post-consent loader.
        assert!(!out.contains("<script async src="), "got: {}", out);
        assert!(out.contains("ga:'G-XSW6TEN1CZ'"));
        assert!(out.contains("ads:'AW-18330845601'"));
        assert!(out.contains("conv:{contact:'AW-18330845601/ctLabel-1',purchase:'AW-18330845601/buyLabel_2'}"));
        assert!(out.contains("cookie_consent"));
    }

    #[test]
    fn analytics_head_ads_only() {
        let out = render_analytics_head(sites::default_site(), None, Some("AW-18330845601"), None, None, None);
        assert!(out.contains("ads:'AW-18330845601'"));
        assert!(!out.contains("conv:{"));
        assert!(!out.contains("ga:'"));
    }

    #[test]
    fn analytics_head_labels_ignored_without_ads_id() {
        let out = render_analytics_head(sites::default_site(), Some("G-XSW6TEN1CZ"), None, Some("ctLabel-1"), None, None);
        assert!(!out.contains("conv:{"));
    }

    #[test]
    fn analytics_head_empty_when_unset() {
        assert_eq!(render_analytics_head(sites::default_site(), None, None, None, None, None), "");
    }

    #[test]
    fn analytics_head_banner_prefix_uses_site_hosts() {
        let out = render_analytics_head(sites::default_site(), None, Some("AW-18330845601"), None, None, None);
        assert!(out.contains(r#"["xikaku.com","www.xikaku.com"].indexOf(location.host)"#), "got: {}", out);
        let out = render_analytics_head(sites::site_by_id("lpr").unwrap(), None, Some("AW-18330845601"), None, None, None);
        assert!(out.contains(r#"["lp-research.com","www.lp-research.com"].indexOf(location.host)"#), "got: {}", out);
    }

    #[test]
    fn analytics_head_geo_gates_consent() {
        let out = render_analytics_head(sites::default_site(), None, Some("AW-18330845601"), Some("ctLabel-1"), None, None);
        // EEA/UK/CH sees the banner first; everyone else loads by default.
        assert!(out.contains("tz.indexOf('Europe/') === 0"), "got: {}", out);
        assert!(out.contains("Asia/Nicosia"), "Cyprus is EU but not under Europe/");
        // Unreadable time zone must fall back to requiring consent.
        assert!(out.contains("catch (e) { return true; }"), "got: {}", out);
        assert!(out.contains("if (!tz) return true;"), "got: {}", out);
        // A stored decline still blocks both paths.
        assert!(out.contains("else if (choice === 'declined') {}"), "got: {}", out);
        assert!(out.contains("data-cookie-settings"), "opt-out link must be wired");
    }

    #[test]
    fn nav_structure_validator_accepts_groups() {
        assert!(is_valid_nav_structure(
            r#"[{"title":"Products","items":["sensors","fusionhub","__shop__"]},
                {"title":"Resources","items":["downloads","use-cases","__blog__"]},
                {"title":"Company","items":["our-story","contact"]}]"#
        ));
        assert!(is_valid_nav_structure("[]"));
    }

    #[test]
    fn nav_structure_validator_rejects_bad_shapes() {
        assert!(!is_valid_nav_structure("not json"));
        assert!(!is_valid_nav_structure(r#"{"title":"x","items":[]}"#));
        assert!(!is_valid_nav_structure(r#"[{"title":"","items":["a"]}]"#));
        assert!(!is_valid_nav_structure(r#"[{"title":"x","items":[""]}]"#));
        assert!(!is_valid_nav_structure(r#"[{"title":"x","items":["a"],"extra":1}]"#));
        let long_title = format!(r#"[{{"title":"{}","items":["a"]}}]"#, "t".repeat(41));
        assert!(!is_valid_nav_structure(&long_title));
        let too_big = format!(r#"[{{"title":"x","items":["{}"]}}]"#, "a".repeat(5000));
        assert!(!is_valid_nav_structure(&too_big));
    }
}
