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
    body::{Body, Bytes},
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
use crate::{error_response, require_admin_full, require_owner, validate_principal, AppState, ErrorResponse};

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
    // Blog index page number (ignored everywhere else).
    page: Option<usize>,
    // Content language; nginx injects it for /{lang}/ prefixed URLs, the
    // dashboard passes it when editing a translation. Empty/absent or a code
    // the site doesn't declare = the default language.
    lang: Option<String>,
}

/// The effective content language of a request: one of the site's declared
/// extra languages, or "" for the default.
fn resolve_lang(site: &SiteConfig, sq: &SiteQuery) -> String {
    match sq.lang.as_deref() {
        Some(l) if site.langs.contains(&l) => l.to_string(),
        _ => String::new(),
    }
}

/// Like `resolve_lang`, but an unknown language is an error rather than the
/// default - admin writes must never land in the wrong language silently.
fn require_lang(
    site: &SiteConfig,
    sq: &SiteQuery,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    match sq.lang.as_deref() {
        None | Some("") => Ok(String::new()),
        Some(l) if site.langs.contains(&l) => Ok(l.to_string()),
        Some(_) => Err(error_response(StatusCode::BAD_REQUEST, "Unknown language for this site")),
    }
}

pub fn resolve_site(
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
    else if lower.ends_with(".ico") { "image/x-icon" }
    else if lower.ends_with(".mp4") { "video/mp4" }
    else if lower.ends_with(".webm") { "video/webm" }
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
///  page_kind, published_at, author_username, redirect_to, lang,
///  translation_of).
type PageRow = (String, String, Option<String>, i64, String, String, bool, String, String, String, String, String, String);

/// The rows belonging to one content language ("" = default).
fn pages_in_lang(pages: &[PageRow], lang: &str) -> Vec<PageRow> {
    pages.iter().filter(|p| p.11 == lang).cloned().collect()
}

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
        .map(|(slug, title, parent_slug, ord, updated_at, meta_description, hidden, page_kind, published_at, author_username, redirect_to, lang, translation_of)| {
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
                "lang": lang,
                "translation_of": translation_of,
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
        "sites": sites::all_sites().iter().map(|s| json!({ "id": s.id, "name": s.name, "langs": s.langs })).collect::<Vec<_>>(),
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
    let lang = require_lang(site, &sq)?;
    safe_slug(&slug)?;
    let is_admin = is_admin_request(&headers, &state);
    let db = state.db.lock();
    let page = db
        .get_website_page(site.id, &lang, &slug)
        .map_err(db_err)?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Page not found"))?;
    let (title, body_md, parent_slug, ord, updated_at, meta_description, hidden, page_kind, published_at, author_username, redirect_to, translation_of) = page;
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
        "lang": lang,
        "translation_of": translation_of,
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

/// A `Range: bytes=...` request header resolved against a resource size.
#[derive(Debug, PartialEq)]
enum ByteRange {
    /// No (or an ignorable) Range header: serve the whole file with 200.
    Full,
    /// Inclusive byte window to serve with 206.
    Window(u64, u64),
    /// Syntactically valid but beyond EOF: answer 416.
    Unsatisfiable,
}

/// Multi-range and malformed specs fall back to `Full` - a server may ignore
/// the Range header, and every real media client sends a single range.
fn byte_range(headers: &HeaderMap, total: u64) -> ByteRange {
    let Some(spec) = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("bytes="))
    else {
        return ByteRange::Full;
    };
    if spec.contains(',') {
        return ByteRange::Full;
    }
    let Some((a, b)) = spec.trim().split_once('-') else { return ByteRange::Full };
    // (start, end) as a half-open window; clamp end to EOF per RFC 9110.
    let (start, end) = if a.is_empty() {
        match b.parse::<u64>() {
            Ok(n) if n > 0 => (total.saturating_sub(n), total),
            _ => return ByteRange::Full,
        }
    } else {
        let Ok(start) = a.parse::<u64>() else { return ByteRange::Full };
        let end = if b.is_empty() {
            total
        } else {
            match b.parse::<u64>() {
                Ok(e) if e >= start => e.saturating_add(1).min(total),
                _ => return ByteRange::Full,
            }
        };
        (start, end)
    };
    if start >= total {
        return ByteRange::Unsatisfiable;
    }
    ByteRange::Window(start, end - 1)
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
    let meta = match tokio::fs::metadata(&path).await {
        Ok(m) if m.is_file() => m,
        _ => return Err(error_response(StatusCode::NOT_FOUND, "Asset not found")),
    };
    let total = meta.len();

    let mut resp = HeaderMap::new();
    resp.insert(header::CONTENT_TYPE, content_type_for(&file_name).parse().unwrap());
    resp.insert(header::CACHE_CONTROL, "public, max-age=300".parse().unwrap());
    resp.insert(header::ACCEPT_RANGES, "bytes".parse().unwrap());
    harden_svg_response(&file_name, &mut resp);

    // A validator lets browsers revalidate with a 304 after max-age instead
    // of re-downloading - assets were fire-and-forget images before, but a
    // hero video is tens of MB per miss.
    if let Ok(modified) = meta.modified() {
        let lm = chrono::DateTime::<chrono::Utc>::from(modified)
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        resp.insert(header::LAST_MODIFIED, lm.parse().unwrap());
        let since = headers.get(header::IF_MODIFIED_SINCE).and_then(|v| v.to_str().ok());
        if since == Some(lm.as_str()) {
            return Ok((StatusCode::NOT_MODIFIED, resp, Body::empty()));
        }
    }

    // Byte ranges are load-bearing for video: Safari refuses to play media
    // from a server that answers a Range request with a plain 200.
    let (status, start, len) = match byte_range(&headers, total) {
        ByteRange::Full => (StatusCode::OK, 0, total),
        ByteRange::Window(s, e) => {
            resp.insert(
                header::CONTENT_RANGE,
                format!("bytes {}-{}/{}", s, e, total).parse().unwrap(),
            );
            (StatusCode::PARTIAL_CONTENT, s, e - s + 1)
        }
        ByteRange::Unsatisfiable => {
            resp.insert(header::CONTENT_RANGE, format!("bytes */{}", total).parse().unwrap());
            return Ok((StatusCode::RANGE_NOT_SATISFIABLE, resp, Body::empty()));
        }
    };
    let io_err =
        |e: std::io::Error| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("Read: {}", e));
    let mut file = tokio::fs::File::open(&path).await.map_err(io_err)?;
    if start > 0 {
        use tokio::io::AsyncSeekExt;
        file.seek(std::io::SeekFrom::Start(start)).await.map_err(io_err)?;
    }
    resp.insert(header::CONTENT_LENGTH, len.into());
    use tokio::io::AsyncReadExt;
    let body = Body::from_stream(tokio_util::io::ReaderStream::new(file.take(len)));
    Ok((status, resp, body))
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
    // For a translated page (?lang= set): the default-language slug it
    // mirrors. Omitted preserves the current link; empty clears it.
    #[serde(default)]
    pub translation_of: Option<String>,
}

pub async fn handle_upsert_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Path(slug): Path<String>,
    Json(req): Json<UpsertPageRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let lang = require_lang(site, &sq)?;
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    safe_slug(&slug)?;

    let (id, url) = {
        let mut db = state.db.lock();
        let existing = db.get_website_page(site.id, &lang, &slug).map_err(db_err)?;
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
        // Translation links only exist on translated pages, and must point at
        // a default-language page so hreflang pairs stay resolvable.
        let translation_of = if lang.is_empty() {
            String::new()
        } else {
            let t = req
                .translation_of
                .clone()
                .or_else(|| existing.as_ref().map(|r| r.11.clone()))
                .unwrap_or_default()
                .trim()
                .to_string();
            if !t.is_empty() && db.get_website_page(site.id, "", &t).map_err(db_err)?.is_none() {
                return Err(error_response(
                    StatusCode::BAD_REQUEST,
                    "translation_of must name a default-language page",
                ));
            }
            t
        };
        let id = db.upsert_website_page(
            site.id,
            &lang,
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
            &translation_of,
            Some(&principal.username),
        )
        .map_err(db_err)?;
        let url = if page_kind == "post" {
            canonical_post_url(site, &lang, &slug)
        } else if lang.is_empty() {
            let pages = visible_pages(db.list_website_pages(site.id).unwrap_or_default());
            canonical_page_url(site, "", &slug, first_default_slug(&pages) == Some(slug.as_str()))
        } else {
            canonical_page_url(site, &lang, &slug, false)
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
    let rows = db.list_page_revisions(site.id, &require_lang(site, &sq)?, &slug).map_err(db_err)?;
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
    let lang = require_lang(site, &sq)?;
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    safe_slug(&slug)?;
    let db = state.db.lock();
    let row = db
        .get_page_revision(site.id, &lang, &slug, id)
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
    let lang = require_lang(site, &sq)?;
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    safe_slug(&slug)?;
    let mut db = state.db.lock();
    let rev = db
        .get_page_revision(site.id, &lang, &slug, id)
        .map_err(db_err)?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Revision not found"))?;
    let (title, body_md, parent_slug, ord, _captured_at, _author) = rev;
    // Preserve the current meta_description, kind, publish date and author
    // when restoring prior body/title.
    let (existing_meta, existing_kind, existing_pub, existing_author, existing_redirect, existing_tr) = db
        .get_website_page(site.id, &lang, &slug)
        .map_err(db_err)?
        .map(|(_t, _b, _p, _o, _u, m, _h, k, pd, au, rd, tr)| (m, k, pd, au, rd, tr))
        .unwrap_or_else(|| (String::new(), "page".to_string(), String::new(), String::new(), String::new(), String::new()));
    let new_id = db.upsert_website_page(
        site.id, &lang, &slug, &title, &body_md, parent_slug.as_deref(), ord,
        &existing_meta,
        &existing_kind,
        &existing_pub,
        &existing_author,
        &existing_redirect,
        &existing_tr,
        Some(&principal.username),
    ).map_err(db_err)?;
    let url = if existing_kind == "post" {
        canonical_post_url(site, &lang, &slug)
    } else if lang.is_empty() {
        let pages = visible_pages(db.list_website_pages(site.id).unwrap_or_default());
        canonical_page_url(site, "", &slug, first_default_slug(&pages) == Some(slug.as_str()))
    } else {
        canonical_page_url(site, &lang, &slug, false)
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

    let lang = require_lang(site, &sq)?;
    let result = {
        let mut db = state.db.lock();
        db.rename_website_page(site.id, &lang, &slug, new_slug)
    };
    match result {
        Ok(true) => {
            let renamed_is_post = {
                let db = state.db.lock();
                db.get_website_page(site.id, &lang, new_slug).ok().flatten().map(|r| r.7 == "post").unwrap_or(false)
            };
            let urls = if renamed_is_post {
                vec![canonical_post_url(site, &lang, &slug), canonical_post_url(site, &lang, new_slug)]
            } else {
                vec![
                    canonical_page_url(site, &lang, &slug, false),
                    canonical_page_url(site, &lang, new_slug, false),
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

    let lang = require_lang(site, &sq)?;
    let (updated, was_post) = {
        let db = state.db.lock();
        let was_post = db.get_website_page(site.id, &lang, &slug).ok().flatten().map(|r| r.7 == "post").unwrap_or(false);
        (db.set_website_page_hidden(site.id, &lang, &slug, req.hidden).map_err(db_err)?, was_post)
    };
    if !updated {
        return Err(error_response(StatusCode::NOT_FOUND, "Page not found"));
    }
    invalidate_page_cache();
    let url = if was_post { canonical_post_url(site, &lang, &slug) } else { canonical_page_url(site, &lang, &slug, false) };
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

    let lang = require_lang(site, &sq)?;
    let (removed, was_post) = {
        let db = state.db.lock();
        let was_post = db.get_website_page(site.id, &lang, &slug).ok().flatten().map(|r| r.7 == "post").unwrap_or(false);
        (db.delete_website_page(site.id, &lang, &slug).map_err(db_err)?, was_post)
    };
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Page not found"));
    }
    invalidate_page_cache();
    let url = if was_post { canonical_post_url(site, &lang, &slug) } else { canonical_page_url(site, &lang, &slug, false) };
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
        let exists = db.get_website_page(site.id, "", slug).ok().flatten().is_some();
        if !exists {
            match db.upsert_website_page(site.id, "", slug, title, body, None, 900, "", "page", "", "", "", "", None) {
                Ok(_) => log::info!("Seeded website page '{}'", slug),
                Err(e) => log::error!("Failed to seed website page '{}': {}", slug, e),
            }
        }
    }
    invalidate_page_cache();
}

/// Logos and favicons live on the site (see sites.rs); the social card is
/// still shared until each site has its own.
const OG_IMAGE_PNG: &[u8] = include_bytes!("assets/xikaku-og-image.png");

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
// Brand artwork does change (a logo swap once stranded browsers on the
// previous image for a day under `max-age=86400, immutable`), so the cache
// is short-lived and revalidates by ETag after that.
fn image_headers(
    req_headers: &HeaderMap,
    content_type: &'static str,
    cache_control: &'static str,
    bytes: &[u8],
) -> (HeaderMap, bool) {
    use sha2::{Digest, Sha256};
    let etag = format!("\"{}\"", hex::encode(&Sha256::digest(bytes)[..8]));
    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    h.insert(header::CACHE_CONTROL, cache_control.parse().unwrap());
    h.insert(header::ETAG, etag.parse().unwrap());
    let matched = req_headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map_or(false, |v| v.split(',').any(|t| t.trim().trim_start_matches("W/") == etag));
    (h, matched)
}

fn cached_image(
    req_headers: &HeaderMap,
    content_type: &'static str,
    bytes: &'static [u8],
) -> axum::response::Response {
    let (h, matched) = image_headers(req_headers, content_type, "public, max-age=3600", bytes);
    if matched {
        return (StatusCode::NOT_MODIFIED, h).into_response();
    }
    (h, bytes).into_response()
}

// Admin-swappable artwork: the shell references it through a versioned URL
// (see bg_version), so a long browser cache is safe.
fn cached_image_owned(
    req_headers: &HeaderMap,
    content_type: &'static str,
    bytes: Vec<u8>,
) -> axum::response::Response {
    let (h, matched) = image_headers(req_headers, content_type, "public, max-age=86400", &bytes);
    if matched {
        return (StatusCode::NOT_MODIFIED, h).into_response();
    }
    (h, bytes).into_response()
}

/// Brand images are per site: the paths are shared, the bytes come from the
/// site an explicit `?site=` names (the dashboard preview host resolves to
/// no site) or the Host header. Unknown values fall back to the default site
/// rather than failing a favicon fetch.
fn brand_site(headers: &HeaderMap, sq: &SiteQuery) -> &'static SiteConfig {
    sq.site
        .as_deref()
        .and_then(sites::site_by_id)
        .or_else(|| sites::site_from_headers(headers))
        .unwrap_or_else(sites::default_site)
}

/// Compiled artwork for the resolved site, falling back to the default
/// site's set so favicon requests never 404 on a young site.
fn compiled_or_default_brand(site: &SiteConfig) -> &'static sites::CompiledBrand {
    sites::compiled_brand(site.id)
        .unwrap_or_else(|| sites::compiled_brand(sites::DEFAULT_SITE_ID).expect("default brand"))
}

/// An uploaded per-site asset chosen by a setting (logo/bg), read from the
/// site's asset store: (file name, bytes).
fn custom_asset(state: &AppState, site: &SiteConfig, setting: &str) -> Option<(String, Vec<u8>)> {
    let name = {
        let db = state.db.lock();
        db.get_site_setting(&sites::setting_key(site, setting)).ok().flatten()
    }
    .filter(|v| !v.is_empty())?;
    if safe_filename(&name).is_err() {
        return None;
    }
    let bytes = std::fs::read(assets_dir(state, site).join(&name)).ok()?;
    Some((name, bytes))
}

pub async fn handle_logo_png(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
) -> axum::response::Response {
    let site = brand_site(&headers, &sq);
    if let Some((name, bytes)) = custom_asset(&state, site, SETTING_LOGO_IMAGE) {
        return cached_image_owned(&headers, content_type_for(&name), bytes);
    }
    match sites::compiled_brand(site.id) {
        Some(b) => cached_image(&headers, "image/png", b.logo),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
pub async fn handle_logo_dark_png(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
) -> axum::response::Response {
    let site = brand_site(&headers, &sq);
    // A site with only a light upload uses it for both themes.
    if let Some((name, bytes)) = custom_asset(&state, site, SETTING_LOGO_DARK_IMAGE)
        .or_else(|| custom_asset(&state, site, SETTING_LOGO_IMAGE))
    {
        return cached_image_owned(&headers, content_type_for(&name), bytes);
    }
    match sites::compiled_brand(site.id) {
        Some(b) => cached_image(&headers, "image/png", b.logo_dark),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
pub async fn handle_og_image_png(headers: HeaderMap) -> impl IntoResponse {
    cached_image(&headers, "image/png", OG_IMAGE_PNG)
}
/// One uploaded favicon serves every icon route; browsers scale it.
fn favicon_response(
    state: &AppState,
    headers: &HeaderMap,
    sq: &SiteQuery,
    compiled: fn(&sites::CompiledBrand) -> &'static [u8],
    compiled_type: &'static str,
) -> axum::response::Response {
    let site = brand_site(headers, sq);
    if let Some((name, bytes)) = custom_asset(state, site, SETTING_FAVICON_IMAGE) {
        return cached_image_owned(headers, content_type_for(&name), bytes);
    }
    cached_image(headers, compiled_type, compiled(compiled_or_default_brand(site)))
}

pub async fn handle_icon_png(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
) -> axum::response::Response {
    favicon_response(&state, &headers, &sq, |b| b.icon, "image/png")
}
pub async fn handle_favicon_32_png(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
) -> axum::response::Response {
    favicon_response(&state, &headers, &sq, |b| b.favicon_32, "image/png")
}
pub async fn handle_favicon_180_png(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
) -> axum::response::Response {
    favicon_response(&state, &headers, &sq, |b| b.favicon_180, "image/png")
}
pub async fn handle_favicon_ico(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
) -> axum::response::Response {
    favicon_response(&state, &headers, &sq, |b| b.favicon_ico, "image/x-icon")
}

/// Cache-busting version for an uploaded asset's URL: changes on any upload,
/// re-upload, or revert.
fn asset_version(state: &AppState, site: &SiteConfig, custom: &str) -> String {
    use sha2::{Digest, Sha256};
    let (len, mtime) = std::fs::metadata(assets_dir(state, site).join(custom))
        .map(|m| {
            let t = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            (m.len(), t)
        })
        .unwrap_or((0, 0));
    hex::encode(&Sha256::digest(format!("{custom}|{len}|{mtime}"))[..4])
}

fn bytes_version(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(&Sha256::digest(bytes)[..4])
}

// Header logo URLs per compiled brand, hashed once - a deploy with new art
// re-versions them automatically.
static COMPILED_LOGO_VERSIONS: LazyLock<HashMap<&'static str, (String, String)>> =
    LazyLock::new(|| {
        ["xikaku", "lpr"]
            .iter()
            .filter_map(|id| {
                let b = sites::compiled_brand(id)?;
                Some((*id, (bytes_version(b.logo), bytes_version(b.logo_dark))))
            })
            .collect()
    });

/// Header logo URLs for the client shell; empty = render the site name as text.
fn brand_logo_urls(state: &AppState, site: &SiteConfig) -> (String, String) {
    let (light, dark) = {
        let db = state.db.lock();
        let get = |k: &str| {
            db.get_site_setting(&sites::setting_key(site, k)).ok().flatten().unwrap_or_default()
        };
        (get(SETTING_LOGO_IMAGE), get(SETTING_LOGO_DARK_IMAGE))
    };
    if !light.is_empty() {
        let lv = asset_version(state, site, &light);
        let dv = if dark.is_empty() { lv.clone() } else { asset_version(state, site, &dark) };
        return (
            format!("/static/logo.png?v={}", lv),
            format!("/static/logo-dark.png?v={}", dv),
        );
    }
    match COMPILED_LOGO_VERSIONS.get(site.id) {
        Some((lv, dv)) => (
            format!("/static/logo.png?v={}", lv),
            format!("/static/logo-dark.png?v={}", dv),
        ),
        None => (String::new(), String::new()),
    }
}

pub async fn handle_bg_jpg(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
) -> axum::response::Response {
    let site = brand_site(&headers, &sq);
    match custom_asset(&state, site, SETTING_BG_IMAGE) {
        Some((name, bytes)) => cached_image_owned(&headers, content_type_for(&name), bytes),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Percent-encode a slug for use as a URL path segment: non-ASCII slugs
/// (Japanese page names) are stored raw and carried encoded in URLs, the way
/// WordPress served them. ASCII slugs pass through unchanged.
fn encode_slug(slug: &str) -> String {
    let mut out = String::with_capacity(slug.len());
    for b in slug.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// URL path prefix for a content language: "" for the default, "/ja" style
/// for translations.
fn lang_prefix(lang: &str) -> String {
    if lang.is_empty() { String::new() } else { format!("/{}", lang) }
}

/// Build the canonical URL for a website page. The home slug renders as the
/// bare domain (`https://xikaku.com/`, `/ja/` for translations); other slugs
/// render as `[/{lang}]/{slug}`.
fn canonical_page_url(site: &SiteConfig, lang: &str, slug: &str, is_home: bool) -> String {
    if is_home {
        format!("{}{}/", site.public_base, lang_prefix(lang))
    } else {
        format!("{}{}/{}", site.public_base, lang_prefix(lang), encode_slug(slug))
    }
}

/// Blog posts live under `[/{lang}]/blog/{slug}`.
fn canonical_post_url(site: &SiteConfig, lang: &str, slug: &str) -> String {
    format!("{}{}/blog/{}", site.public_base, lang_prefix(lang), encode_slug(slug))
}

/// (hreflang code, url) pairs for a page and its translations, ending with
/// x-default = the default-language URL. Empty when the page has no complete
/// pair. The default language is advertised as "en".
fn hreflang_pairs(site: &SiteConfig, pages: &[PageRow], lang: &str, slug: &str, is_post: bool) -> Vec<(String, String)> {
    let default_slug = if lang.is_empty() {
        slug.to_string()
    } else {
        match pages.iter().find(|p| p.11 == lang && p.0 == slug).map(|p| p.12.clone()) {
            Some(t) if !t.is_empty() => t,
            _ => return Vec::new(),
        }
    };
    if !pages.iter().any(|p| p.11.is_empty() && p.0 == default_slug) {
        return Vec::new();
    }
    let is_home = first_default_slug(&pages_in_lang(pages, "")) == Some(default_slug.as_str());
    let url_for = |l: &str, s: &str| {
        if is_post {
            canonical_post_url(site, l, s)
        } else {
            canonical_page_url(site, l, s, is_home)
        }
    };
    let default_url = url_for("", &default_slug);
    let mut alts = vec![("en".to_string(), default_url.clone())];
    for l in site.langs {
        if let Some(t) = pages.iter().find(|p| p.11 == *l && p.12 == default_slug) {
            alts.push((l.to_string(), url_for(l, &t.0)));
        }
    }
    if alts.len() < 2 {
        return Vec::new();
    }
    alts.push(("x-default".to_string(), default_url));
    alts
}

/// The `<link rel="alternate" hreflang=...>` head lines for a page, or "".
fn hreflang_links(site: &SiteConfig, pages: &[PageRow], lang: &str, slug: &str, is_post: bool) -> String {
    hreflang_pairs(site, pages, lang, slug, is_post)
        .iter()
        .map(|(code, url)| {
            format!(
                "<link rel=\"alternate\" hreflang=\"{}\" href=\"{}\">\n",
                html_escape(code),
                html_escape(url),
            )
        })
        .collect()
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
            if s.is_empty() || is_video_file(&s) { continue; }
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

/// An uploaded video file written in image syntax embeds as an ambient
/// (autoplay/muted/loop) player instead of an `<img>`.
pub(crate) fn is_video_file(url: &str) -> bool {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".mp4") || lower.ends_with(".webm")
}

/// Rewrite attribute spans into raw HTML `<img>` tags so the attributes
/// survive into the SSR body. Video files become ambient `<video>` loops;
/// the client renderer in website.html emits the same markup.
fn rewrite_pandoc_image_attrs(body_md: &str) -> String {
    rewrite_pandoc_images(body_md, &mut |img| {
        if is_video_file(img.url) {
            let mut html = format!(r#"<video src="{}""#, html_escape(img.url));
            if let Some(w) = img.width {
                html.push_str(&format!(r#" width="{}""#, html_escape(w)));
            }
            if let Some(h) = img.height {
                html.push_str(&format!(r#" height="{}""#, html_escape(h)));
            }
            if !img.classes.is_empty() {
                html.push_str(&format!(r#" class="{}""#, html_escape(&img.classes.join(" "))));
            }
            html.push_str(" autoplay muted loop playsinline></video>");
            return html;
        }
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
    let events = grid_tables_to_divs(parser);
    let mut out = String::with_capacity(cleaned.len() * 2);
    html::push_html(&mut out, events.into_iter());
    let clean = ammonia::Builder::default()
        .add_generic_attributes(&["class", "id"])
        .add_tags(&["video"])
        .add_tag_attributes("video", &["src", "autoplay", "muted", "loop", "playsinline", "width", "height"])
        .clean(&out)
        .to_string();
    obfuscate_email_shortcodes(&absolutize_bare_img_srcs(&clean))
}

/// Rewrite tables whose header cells are all empty - the "grid table"
/// authoring convention for side-by-side content - into div-based CSS grids
/// that reflow on narrow screens. Mirrors the client-side renderer in
/// website.html, which emits the same `div.grid.cols-N` markup.
fn grid_tables_to_divs<'a>(
    parser: impl Iterator<Item = pulldown_cmark::Event<'a>>,
) -> Vec<pulldown_cmark::Event<'a>> {
    use pulldown_cmark::{html, Event, Tag, TagEnd};
    let mut out = Vec::new();
    let mut it = parser;
    while let Some(ev) = it.next() {
        let cols = match &ev {
            Event::Start(Tag::Table(aligns)) => aligns.len(),
            _ => {
                out.push(ev);
                continue;
            }
        };
        // Buffer the whole table (tables don't nest in markdown).
        let mut buf = Vec::new();
        while let Some(e) = it.next() {
            let done = matches!(e, Event::End(TagEnd::Table));
            buf.push(e);
            if done {
                break;
            }
        }
        let mut in_head = false;
        let mut head_empty = true;
        for e in &buf {
            match e {
                Event::Start(Tag::TableHead) => in_head = true,
                Event::End(TagEnd::TableHead) => in_head = false,
                Event::Start(Tag::TableCell) | Event::End(TagEnd::TableCell) => {}
                _ if in_head => head_empty = false,
                _ => {}
            }
        }
        if !head_empty || cols < 2 {
            out.push(ev);
            out.extend(buf);
            continue;
        }
        let mut div = format!("<div class=\"grid cols-{cols}\">");
        let mut in_head = false;
        let mut cell: Option<Vec<Event>> = None;
        for e in buf {
            match e {
                Event::Start(Tag::TableHead) => in_head = true,
                Event::End(TagEnd::TableHead) => in_head = false,
                Event::Start(Tag::TableCell) if !in_head => cell = Some(Vec::new()),
                Event::End(TagEnd::TableCell) if !in_head => {
                    div.push_str("<div>");
                    html::push_html(&mut div, cell.take().unwrap_or_default().into_iter());
                    div.push_str("</div>");
                }
                e => {
                    if let Some(c) = cell.as_mut() {
                        c.push(e);
                    }
                }
            }
        }
        div.push_str("</div>\n");
        out.push(Event::Html(div.into()));
    }
    out
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
    db.get_website_page(site.id, &p.11, &p.0)
        .ok()
        .flatten()
        .map(|(_t, body, ..)| derive_description(&body))
        .unwrap_or_default()
}

fn build_breadcrumbs(
    site: &SiteConfig,
    lang: &str,
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
                    html_escape(&canonical_page_url(site, lang, hs, true)),
                ));
                pos += 1;
            }
        }
        let blog_title = by_slug.get("blog").map(|p| p.1.as_str()).unwrap_or("Blog");
        items.push(format!(
            r#"{{"@type":"ListItem","position":{},"name":"{}","item":"{}"}}"#,
            pos,
            html_escape(blog_title),
            html_escape(&format!("{}{}/blog", site.public_base, lang_prefix(lang))),
        ));
        pos += 1;
        items.push(format!(
            r#"{{"@type":"ListItem","position":{},"name":"{}","item":"{}"}}"#,
            pos,
            html_escape(&by_slug[slug].1),
            html_escape(&canonical_post_url(site, lang, slug)),
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
                    html_escape(&canonical_page_url(site, lang, hs, true)),
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
            html_escape(&canonical_page_url(site, lang, &p.0, is_home)),
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
    lang: &str,
    hreflang_links: &str,
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
        canonical_post_url(site, lang, slug)
    } else {
        canonical_page_url(site, lang, slug, is_home)
    };
    let full_title = if is_home {
        format!("{} - {}", site.name, site.tagline)
    } else {
        format!("{} - {}", page_title, site.name)
    };

    // Organization JSON-LD is identical across a site's pages - built once
    // at module init in `sites.rs`.
    let org_jsonld: &str = sites::org_jsonld(site);

    // Per-page hero image, falling back to the site's social card; a site
    // without one omits the image tags entirely.
    let og_image = og_image_override
        .map(str::to_string)
        .or_else(|| (!site.og_image_url.is_empty()).then(|| site.og_image_url.to_string()));

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
        // Google's Article rich result wants an image on the BlogPosting;
        // reuse the page's og:image so both channels stay in sync.
        let image_ld = match og_image.as_deref() {
            Some(img) => format!(r#","image":"{}""#, html_escape(img)),
            None => String::new(),
        };
        format!(
            r#"{{"@context":"https://schema.org","@type":"BlogPosting","headline":"{title}","description":"{desc}","url":"{url}"{image_ld},"mainEntityOfPage":{{"@type":"WebPage","@id":"{url}"}},"datePublished":"{published}","dateModified":"{date}","author":{author_ld},"publisher":{{"@type":"Organization","name":"{site_name}","url":"{base}"{publisher_logo}}}}}"#,
            title = html_escape(page_title),
            desc = html_escape(description),
            url = html_escape(&canonical),
            image_ld = image_ld,
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

    let breadcrumb_jsonld = build_breadcrumbs(site, lang, pages, slug, home_slug);

    // Product schema: emit one Product per matching shop SKU. A page slug
    // like `lpms-curs3` matches every shop product whose SKU starts with the
    // slug (e.g., lpms-curs3-can, lpms-curs3-rs232) so the page describes the
    // family with one Offer per variant.
    let product_blocks = build_product_jsonld(site, slug, products);

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
            "{hreflang}",
            "<link rel=\"alternate\" type=\"application/rss+xml\" title=\"{site} Blog\" href=\"{base}{lang_pfx}/blog/rss.xml\">\n",
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
        hreflang = hreflang_links,
        base = site.public_base,
        lang_pfx = lang_prefix(lang),
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
    // /site/{lang} is a translation's home page, not a slug.
    if let Ok(site) = resolve_site(&headers, &sq) {
        if site.langs.contains(&slug.as_str()) {
            let sq2 = SiteQuery { site: sq.site.clone(), page: sq.page, lang: Some(slug) };
            return render_website(&state, &headers, &sq2, None, false);
        }
    }
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
fn site_config_script(
    state: &AppState,
    site: &SiteConfig,
    lang: &str,
    theme: &str,
    no_topbar: bool,
    sidebar_logo: bool,
) -> String {
    let (brand_logo, brand_logo_dark) = brand_logo_urls(state, site);
    format!(
        "<script>window.__SITE={};</script>",
        json!({
            "id": site.id,
            "name": site.name,
            "hosts": site.hosts,
            "brand_logo": brand_logo,
            "brand_logo_dark": brand_logo_dark,
            "has_shop": site.has_shop,
            "has_newsletter": site.has_newsletter,
            "has_blog": site.has_blog,
            "theme": theme,
            "no_topbar": no_topbar,
            "sidebar_logo": sidebar_logo,
            "langs": site.langs,
            "lang": lang,
        }),
    )
}

/// Inject head + body into the compiled-in shell. A site with background
/// artwork (uploaded or compiled-in) gets the photo layer and the veil
/// styles keyed on it.
pub(crate) fn render_shell(state: &Arc<AppState>, site: &SiteConfig, lang: &str, seo_head: &str, body_html: &str) -> Bytes {
    let (custom_bg, veil, parallax, theme, no_topbar, sidebar_logo, favicon) = {
        let db = state.db.lock();
        let get = |k: &str| {
            db.get_site_setting(&sites::setting_key(site, k)).ok().flatten().unwrap_or_default()
        };
        (
            get(SETTING_BG_IMAGE),
            get(SETTING_BG_VEIL),
            get(SETTING_BG_PARALLAX),
            get(SETTING_THEME_MODE),
            get(SETTING_NO_TOPBAR) == "1",
            get(SETTING_SIDEBAR_LOGO) == "1",
            get(SETTING_FAVICON_IMAGE),
        )
    };
    let theme = if matches!(theme.as_str(), "light" | "dark") { theme } else { String::new() };
    let mut html = WEBSITE_HTML
        .replacen("<!--SEO_HEAD-->", seo_head, 1)
        .replacen("<!--SITE_CONFIG-->", &site_config_script(state, site, lang, &theme, no_topbar, sidebar_logo), 1)
        .replacen("<!--ANALYTICS-->", &analytics_head(state, site), 1)
        .replacen("<!--BODY_CONTENT-->", body_html, 1);
    // One rewrite covers both html-tag concerns: the document language of a
    // translated page, and the pinned light palette before first paint (the
    // client script sees the theme lock and never overrides it; dark is the
    // default palette, so a dark pin needs no attribute).
    let html_lang = if lang.is_empty() { "en" } else { lang };
    if html_lang != "en" || theme == "light" {
        let tag = format!(
            r#"<html lang="{}"{}>"#,
            html_escape(html_lang),
            if theme == "light" { r#" data-theme="light""# } else { "" },
        );
        html = html.replacen("<html lang=\"en\">", &tag, 1);
    }
    // An uploaded favicon re-versions the shell's icon links so browsers
    // fetch the change at once; compiled artwork keeps the static ?v.
    if !favicon.is_empty() {
        let v = asset_version(state, site, &favicon);
        html = html
            .replacen("href=\"/favicon.ico\"", &format!("href=\"/favicon.ico?v={}\"", v), 1)
            .replacen("/static/favicon-32.png?v=2", &format!("/static/favicon-32.png?v={}", v), 1)
            .replacen("/static/favicon-180.png?v=2", &format!("/static/favicon-180.png?v={}", v), 1);
    }
    // The brand renders above the sidebar nav, and the sidebar column shows
    // immediately instead of waiting for the client nav render.
    if sidebar_logo {
        let name = html_escape(site.name);
        let (logo, logo_dark) = brand_logo_urls(state, site);
        let brand = if logo.is_empty() {
            name.clone()
        } else {
            format!(
                r#"<img class="logo-dark" src="{}" alt="{}"><img class="logo-light" src="{}" alt="{}">"#,
                html_escape(&logo_dark),
                name,
                html_escape(&logo),
                name,
            )
        };
        html = html
            .replacen(
                r#"<aside class="sidebar" id="sidebar"></aside>"#,
                &format!(
                    r#"<aside class="sidebar" id="sidebar"><a href="/site" class="sidebar-brand" aria-label="{}">{}</a></aside>"#,
                    name, brand,
                ),
                1,
            )
            .replacen(
                r#"<div class="layout no-sidebar no-toc" id="layout">"#,
                r#"<div class="layout no-toc" id="layout">"#,
                1,
            );
    }
    let mut classes = Vec::new();
    if !custom_bg.is_empty() {
        classes.push("has-bg");
        if parallax == "1" {
            classes.push("bg-parallax");
        }
    }
    if no_topbar {
        classes.push("no-topbar");
    }
    if classes.is_empty() {
        return html.into();
    }
    // No uploaded background = flat theme; the veil layer is only injected
    // for sites that chose an image.
    let body = if custom_bg.is_empty() {
        format!(r#"<body class="{}">"#, classes.join(" "))
    } else {
        let veil = veil.parse::<u8>().ok().filter(|v| *v <= 100).unwrap_or(72);
        // The versioned URL busts browser caches the moment the bg changes;
        // the inline style overrides only background-image, keeping the CSS
        // sizing.
        format!(
            r#"<body class="{}" style="--bg-veil:{}%"><div class="site-bg" aria-hidden="true" style="background-image:url('/static/bg.jpg?v={}')"></div>"#,
            classes.join(" "),
            veil,
            asset_version(state, site, &custom_bg),
        )
    };
    html.replacen("<body>", &body, 1).into()
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
    let lang = resolve_lang(site, sq);
    // Build the cache key first so we can short-circuit on a hit. Use the raw
    // requested slug (None → "" for the home shell). When the slug resolves to
    // home via `first_default_slug`, the cache still keys on what the client
    // asked for; this is correct because invalidation is global and TTL is short.
    // The blog index keys on its page number too, or page 2 would serve a
    // cached page 1.
    let blog_page = sq.page.unwrap_or(1).max(1);
    let cache_key = if post_path {
        format!("{}|{}|blog/{}", site.id, lang, requested_slug.as_deref().unwrap_or_default())
    } else if requested_slug.as_deref() == Some("blog") {
        format!("{}|{}|blog|p={}", site.id, lang, blog_page)
    } else {
        format!("{}|{}|{}", site.id, lang, requested_slug.as_deref().unwrap_or_default())
    };
    if let Some(cached) = page_cache_get(&cache_key) {
        return (build_html_headers(), cached).into_response();
    }

    // All languages stay loaded - translation links cross the sets; rendering
    // and nav work from the request language's slice.
    let (pages, products) = {
        let db = state.db.lock();
        (
            visible_pages(db.list_website_pages(site.id).unwrap_or_default()),
            if site.has_shop { db.list_products(true).unwrap_or_default() } else { Vec::new() },
        )
    };
    let lang_pages = pages_in_lang(&pages, &lang);

    // A retired page 301s to its replacement; an unknown slug may still be
    // covered by the redirect map. Both are checked before rendering and
    // never cached - a stale 301 is the one redirect a browser will not
    // re-ask about.
    if let Some(s) = requested_slug.as_deref() {
        let row_redirect = {
            let db = state.db.lock();
            db.get_website_page(site.id, &lang, s).ok().flatten().map(|r| r.10)
        };
        match row_redirect {
            Some(t) if !t.trim().is_empty() => {
                let to = redirect_location(&t, &pages, is_marketing_host(headers));
                return (StatusCode::MOVED_PERMANENTLY, [(header::LOCATION, to)]).into_response();
            }
            Some(_) => {}
            None => {
                let path = if post_path { format!("/blog/{}", s) } else { format!("/{}", s) };
                if let Some(to) = lookup_site_redirect(state, site, &path) {
                    let loc = redirect_map_location(&to, is_marketing_host(headers));
                    return (StatusCode::MOVED_PERMANENTLY, [(header::LOCATION, loc)]).into_response();
                }
            }
        }
    }

    // /blog renders the reverse-chron post index; an optional "blog" page row
    // supplies the title/intro when present.
    if !post_path && requested_slug.as_deref() == Some("blog") {
        let html = render_blog_index(state, site, &lang, &pages, &products, blog_page);
        page_cache_put(cache_key, html.clone());
        return (build_html_headers(), html).into_response();
    }

    // /newsletter renders the public newsletter archive; an optional
    // "newsletter" page row supplies the title/intro when present. Sites
    // without a newsletter treat the slug as a normal page. The archive
    // exists in the default language only.
    if !post_path && site.has_newsletter && lang.is_empty() && requested_slug.as_deref() == Some("newsletter") {
        let html = render_newsletter_index(state, site, &pages, &products);
        page_cache_put(cache_key, html.clone());
        return (build_html_headers(), html).into_response();
    }

    // The home of a translation is the translated home page: the row that
    // mirrors the default language's home slug, else the language's first
    // top-level page.
    let had_requested_slug = requested_slug.is_some();
    let slug_owned: Option<String> = requested_slug.or_else(|| {
        if lang.is_empty() {
            first_default_slug(&pages).map(|s| s.to_string())
        } else {
            let default_home = first_default_slug(&pages_in_lang(&pages, "")).map(str::to_string);
            pages
                .iter()
                .find(|p| p.11 == lang && !p.12.is_empty() && Some(&p.12) == default_home.as_ref())
                .map(|p| p.0.clone())
                .or_else(|| first_default_slug(&lang_pages).map(|s| s.to_string()))
        }
    });
    // If the requested slug is unknown, render the shell anyway (SPA shows "Page not found")
    // but omit the SEO head - better than 500'ing.
    let (title, description, updated_at, valid_slug, body_md, post_published, post_author):
        (String, String, String, Option<String>, String, Option<String>, Option<String>) =
        if let Some(s) = slug_owned.as_deref() {
            let (row, author) = {
                let db = state.db.lock();
                let row = db.get_website_page(site.id, &lang, s).unwrap_or(None);
                let author = row.as_ref().and_then(|r| display_name(&db, &r.9));
                (row, author)
            };
            // A hidden page renders like an unknown slug: bare shell, no SEO
            // head, no body - the SPA shows "Page not found" to visitors.
            // The /blog/ path only serves posts.
            match row {
                Some((t, body, _p, _o, upd, meta, false, kind, published, _au, _rd, _tr))
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

    // A requested slug that resolves to no page is a real 404: rendered as
    // the shell (the SPA shows "Page not found") but with the right status
    // and a noindex, and never cached - a cache hit would revive it as 200.
    let not_found = had_requested_slug && valid_slug.is_none();
    let og_image = first_image_url(site, &body_md);
    let injected = match valid_slug.as_deref() {
        Some(s) => {
            let alt = hreflang_links(site, &pages, &lang, s, post_published.is_some());
            render_seo_head(
                site, &lang, &alt, s, &title, &description, &updated_at, og_image.as_deref(),
                &lang_pages, &products,
                post_published.as_deref(), post_author.as_deref(),
            )
        }
        None => format!(
            "<title>{}</title>\n<meta name=\"description\" content=\"{}\">\n{}",
            html_escape(site.name),
            html_escape(site.tagline),
            if not_found { "<meta name=\"robots\" content=\"noindex\">\n" } else { "" },
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
        h.push_str(&render_body_html(&body_md));
        h
    };

    let html = render_shell(state, site, &lang, &injected, &body_html);
    if not_found {
        return (StatusCode::NOT_FOUND, build_html_headers(), html).into_response();
    }
    page_cache_put(cache_key, html.clone());
    (build_html_headers(), html).into_response()
}

const POSTS_PER_PAGE: usize = 3;

/// `/blog` URL for the given page, for pager links.
fn blog_index_href(lang: &str, page_num: usize) -> String {
    let base = format!("{}/blog", lang_prefix(lang));
    if page_num > 1 { format!("{}?page={}", base, page_num) } else { base }
}

/// SSR body + head for the /blog index: intro from the optional "blog" page
/// row, then a page of full posts newest-first.
fn render_blog_index(
    state: &Arc<AppState>,
    site: &SiteConfig,
    lang: &str,
    pages: &[PageRow],
    products: &[(String, String, String, i64, String, Option<String>, String, bool, i64, String)],
    page_num: usize,
) -> Bytes {
    let row = {
        let db = state.db.lock();
        db.get_website_page(site.id, lang, "blog").unwrap_or(None)
    };
    let (title, intro_md, updated_at, meta) = match row {
        Some((t, body, _p, _o, upd, m, false, _k, _pd, _au, _rd, _tr)) => (t, body, upd, m),
        _ => ("Blog".to_string(), String::new(), String::new(), String::new()),
    };
    let lang_pages = pages_in_lang(pages, lang);
    let all_posts = sorted_posts(&lang_pages);

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

    let posts = &all_posts;

    if posts.is_empty() {
        body_html.push_str("<p>No posts yet.</p>");
    } else {
        let total_pages = posts.len().div_ceil(POSTS_PER_PAGE);
        let page_num = page_num.min(total_pages);
        let start = (page_num - 1) * POSTS_PER_PAGE;
        // Full posts inline, newest first - the date links to the permalink.
        body_html.push_str("<div class=\"blog-index\">");
        for p in posts.iter().skip(start).take(POSTS_PER_PAGE) {
            let (post_body, author) = {
                let db = state.db.lock();
                let body = db
                    .get_website_page(site.id, lang, &p.0)
                    .ok()
                    .flatten()
                    .map(|(_t, body, ..)| body)
                    .unwrap_or_default();
                (body, display_name(&db, &p.9))
            };
            let permalink = format!("{}/blog/{}", lang_prefix(lang), encode_slug(&p.0));
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

        if total_pages > 1 {
            let mut pager = String::from("<nav class=\"blog-pager\">");
            if page_num > 1 {
                pager.push_str(&format!(
                    "<a href=\"{}\">← Newer</a>",
                    html_escape(&blog_index_href(lang, page_num - 1)),
                ));
            }
            pager.push_str(&format!("<span>Page {} of {}</span>", page_num, total_pages));
            if page_num < total_pages {
                pager.push_str(&format!(
                    "<a href=\"{}\">Older →</a>",
                    html_escape(&blog_index_href(lang, page_num + 1)),
                ));
            }
            pager.push_str("</nav>");
            body_html.push_str(&pager);
        }
    }

    // dateModified for the index: the newest post, else the intro page edit.
    let updated = all_posts.first().map(|p| p.4.clone()).unwrap_or(updated_at);
    let injected = render_seo_head(site, lang, "", "blog", &title, &description, &updated, None, &lang_pages, products, None, None);
    render_shell(state, site, lang, &injected, &body_html)
}

/// Bodies reference uploaded images by bare filename (the composer upload hook
/// inserts `data.name`, not a URL). The SPA resolves those client-side; the SSR
/// output must point them at the asset store explicitly, or a crawler resolves
/// them against the current path and gets the page shell back. Applied to every
/// SSR body via `render_body_html` - docs bodies arrive with rooted paths
/// already and pass through untouched.
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

/// Replace {{email:user@domain}} shortcodes with the same click-to-reveal
/// span the client renderer emits, so the SSR HTML never carries the plain
/// address. Runs after ammonia (which would strip the data-* attributes).
fn obfuscate_email_shortcodes(html: &str) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut out = String::with_capacity(html.len());
    let mut i = 0;
    while let Some(p) = html[i..].find("{{email:") {
        let start = i + p;
        out.push_str(&html[i..start]);
        let addr_start = start + 8;
        let Some(e) = html[addr_start..].find("}}") else {
            out.push_str(&html[start..]);
            return out;
        };
        let addr = &html[addr_start..addr_start + e];
        let at = addr.find('@');
        match at {
            Some(at)
                if at > 0
                    && at < addr.len() - 1
                    && !addr.contains(['<', '>', '&', ' ', '"']) =>
            {
                out.push_str(&format!(
                    "<span class=\"email-obf\" data-u=\"{}\" data-d=\"{}\" tabindex=\"0\" role=\"button\">show email</span>",
                    b64.encode(&addr[..at]),
                    b64.encode(&addr[at + 1..])
                ));
            }
            _ => out.push_str(&html[start..addr_start + e + 2]),
        }
        i = addr_start + e + 2;
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
            db.get_website_page(site.id, "", "newsletter").unwrap_or(None),
            db.list_public_newsletter_issues().unwrap_or_default(),
        )
    };
    let (title, intro_md, updated_at, meta) = match row {
        Some((t, body, _p, _o, upd, m, false, _k, _pd, _au, _rd, _tr)) => (t, body, upd, m),
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
                body = render_body_html(&newsletter_web_md(body_md)),
            ));
        }
        body_html.push_str("</div>");
    }

    // dateModified for the archive: the newest issue, else the intro page edit.
    let updated = issues.first().map(|i| i.3.clone()).unwrap_or(updated_at);
    let injected =
        render_seo_head(site, "", "", "newsletter", &title, &description, &updated, None, pages, products, None, None);
    render_shell(state, site, "", &injected, &body_html)
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
    let lang = resolve_lang(site, &sq);
    let pages = {
        let db = state.db.lock();
        visible_pages(db.list_website_pages(site.id).unwrap_or_default())
    };
    let lang_pages = pages_in_lang(&pages, &lang);
    let posts = sorted_posts(&lang_pages);

    let mut xml = String::from(concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
        "<rss version=\"2.0\" xmlns:atom=\"http://www.w3.org/2005/Atom\">\n",
        "<channel>\n",
    ));
    xml.push_str(&format!("<title>{} Blog</title>\n", xml_escape(site.name)));
    xml.push_str(&format!("<link>{}{}/blog</link>\n", site.public_base, lang_prefix(&lang)));
    xml.push_str(&format!(
        "<atom:link href=\"{}{}/blog/rss.xml\" rel=\"self\" type=\"application/rss+xml\"/>\n",
        site.public_base,
        lang_prefix(&lang),
    ));
    xml.push_str(&format!(
        "<description>News and updates from {}.</description>\n",
        xml_escape(site.name),
    ));
    xml.push_str(&format!(
        "<language>{}</language>\n",
        if lang.is_empty() { "en" } else { lang.as_str() },
    ));
    for p in &posts {
        let excerpt = post_excerpt(&state, site, p);
        let url = canonical_post_url(site, &lang, &p.0);
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
/// Asset file name serving as the site background; empty = compiled-in default.
pub const SETTING_BG_IMAGE: &str = "bg_image";
/// Asset file names serving as the site logo (light / dark theme); empty =
/// compiled-in artwork where the site has it, text brand otherwise.
pub const SETTING_LOGO_IMAGE: &str = "logo_image";
pub const SETTING_LOGO_DARK_IMAGE: &str = "logo_dark_image";
/// Asset file name serving as the favicon (all sizes and /favicon.ico -
/// browsers scale it); empty = compiled artwork, default-site fallback.
pub const SETTING_FAVICON_IMAGE: &str = "favicon_image";
/// Veil strength over the background photo, 0-100 percent; empty = 72.
pub const SETTING_BG_VEIL: &str = "bg_veil";
/// "1" = the background drifts opposite to the scroll direction.
pub const SETTING_BG_PARALLAX: &str = "bg_parallax";
/// "light" / "dark" = pin that palette and hide the theme toggle;
/// empty = both themes with the visitor's toggle.
pub const SETTING_THEME_MODE: &str = "theme_mode";
/// "1" = drop the top bar for visitors. Admins keep it - the edit controls
/// live there.
pub const SETTING_NO_TOPBAR: &str = "no_topbar";
/// "1" = the brand logo renders above the sidebar nav.
pub const SETTING_SIDEBAR_LOGO: &str = "sidebar_logo";

/// Sidebar nav config: JSON array of groups rendered between the ungrouped
/// pages and nothing else. Items are page slugs, plus the pseudo-slugs
/// "__blog__" and "__shop__" for the fixed Blog/Shop links, or
/// `{"title", "url"}` objects for links off the site (docs, external shop).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NavGroup {
    title: String,
    items: Vec<NavItem>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NavLink {
    title: String,
    url: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum NavItem {
    Slug(String),
    Link(NavLink),
}

impl NavItem {
    fn is_valid(&self) -> bool {
        match self {
            NavItem::Slug(s) => !s.is_empty() && s.len() <= 100,
            // Only http(s) and site-rooted targets: a `javascript:` URL here
            // would end up in an href on every page of the site.
            NavItem::Link(l) => {
                !l.title.trim().is_empty()
                    && l.title.len() <= 40
                    && l.url.len() <= 200
                    && (l.url.starts_with("https://")
                        || l.url.starts_with("http://")
                        || l.url.starts_with('/'))
            }
        }
    }
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
                        && g.items.iter().all(NavItem::is_valid)
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
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\" xmlns:xhtml=\"http://www.w3.org/1999/xhtml\">\n",
    );
    if let Some(site) = sites::site_from_headers(&headers) {
        let pages = {
            let db = state.db.lock();
            visible_pages(db.list_website_pages(site.id).unwrap_or_default())
        };
        let home_slug = first_default_slug(&pages_in_lang(&pages, "")).map(|s| s.to_string());
        for (slug, _title, _parent, _ord, updated_at, _meta, _hidden, kind, _published, _author, _rd, lang, translation_of) in &pages {
            let is_post_kind = kind == "post";
            // Home detection: the default home, or a translation of it.
            let is_home = if lang.is_empty() {
                home_slug.as_deref() == Some(slug.as_str())
            } else {
                !translation_of.is_empty() && home_slug.as_deref() == Some(translation_of.as_str())
            };
            let loc = if is_post_kind {
                canonical_post_url(site, lang, slug)
            } else {
                canonical_page_url(site, lang, slug, is_home)
            };
            xml.push_str("  <url>\n");
            xml.push_str(&format!("    <loc>{}</loc>\n", xml_escape(&loc)));
            if !updated_at.is_empty() {
                xml.push_str(&format!("    <lastmod>{}</lastmod>\n", xml_escape(&iso8601_z(updated_at))));
            }
            // hreflang alternates, mirroring the on-page link pairs.
            for (code, href) in hreflang_pairs(site, &pages, lang, slug, is_post_kind) {
                xml.push_str(&format!(
                    "    <xhtml:link rel=\"alternate\" hreflang=\"{}\" href=\"{}\"/>\n",
                    xml_escape(&code),
                    xml_escape(&href),
                ));
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
    // The default language is the canonical content; translations follow in
    // their own section so language-aware AI crawlers find them too.
    let all_pages = {
        let db = state.db.lock();
        visible_pages(db.list_website_pages(site.id).unwrap_or_default())
    };
    let pages = pages_in_lang(&all_pages, "");
    let home_slug = first_default_slug(&pages).map(|s| s.to_string());

    let mut body = String::new();
    body.push_str(&format!("# {}\n\n", site.name));
    body.push_str(&format!("> {}\n\n", site.tagline));
    body.push_str(&format!(
        "{} ({}) {}\n\n",
        site.name, site.org_legal_name, site.llms_blurb,
    ));

    body.push_str("## Pages\n");
    for (slug, title, parent, _ord, _upd, meta, _hidden, kind, _published, _author, _rd, _lang, _tr) in &pages {
        if kind == "post" {
            continue;
        }
        let desc_source = if !meta.trim().is_empty() {
            meta.clone()
        } else {
            let row = {
                let db = state.db.lock();
                db.get_website_page(site.id, "", slug).unwrap_or(None)
            };
            row.map(|(_t, body, ..)| derive_description(&body))
                .unwrap_or_default()
        };
        let indent = if parent.is_some() { "  " } else { "" };
        let is_home = home_slug.as_deref() == Some(slug.as_str());
        let url = canonical_page_url(site, "", slug, is_home);
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
            let url = canonical_post_url(site, "", &p.0);
            if excerpt.is_empty() {
                body.push_str(&format!("- [{}]({}) ({})\n", p.1, url, p.8));
            } else {
                body.push_str(&format!("- [{}]({}) ({}): {}\n", p.1, url, p.8, excerpt));
            }
        }
    }
    // Translated pages, one section per declared language.
    for l in site.langs {
        let lang_rows: Vec<&PageRow> = all_pages
            .iter()
            .filter(|p| p.11 == *l && p.7 != "post")
            .collect();
        if lang_rows.is_empty() {
            continue;
        }
        body.push_str(&format!("\n## Pages ({})\n", l));
        for p in lang_rows {
            let is_home = !p.12.is_empty() && home_slug.as_deref() == Some(p.12.as_str());
            let url = canonical_page_url(site, l, &p.0, is_home);
            if p.5.trim().is_empty() {
                body.push_str(&format!("- [{}]({})\n", p.1, url));
            } else {
                body.push_str(&format!("- [{}]({}): {}\n", p.1, url, p.5.trim()));
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
    SETTING_BG_IMAGE,
    SETTING_BG_VEIL,
    SETTING_BG_PARALLAX,
    SETTING_THEME_MODE,
    SETTING_NO_TOPBAR,
    SETTING_SIDEBAR_LOGO,
    SETTING_LOGO_IMAGE,
    SETTING_LOGO_DARK_IMAGE,
    SETTING_FAVICON_IMAGE,
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
        } else if k == SETTING_BG_IMAGE
            || k == SETTING_LOGO_IMAGE
            || k == SETTING_LOGO_DARK_IMAGE
            || k == SETTING_FAVICON_IMAGE
        {
            if !trimmed.is_empty() {
                safe_filename(trimmed)?;
                if !assets_dir(&state, site).join(trimmed).is_file() {
                    return Err(error_response(StatusCode::BAD_REQUEST, "Unknown asset"));
                }
            }
        } else if k == SETTING_BG_VEIL {
            if !trimmed.is_empty() && !trimmed.parse::<u8>().map_or(false, |v| v <= 100) {
                return Err(error_response(StatusCode::BAD_REQUEST, "bg_veil must be 0-100"));
            }
        } else if k == SETTING_BG_PARALLAX || k == SETTING_NO_TOPBAR || k == SETTING_SIDEBAR_LOGO {
            if !matches!(trimmed, "" | "0" | "1") {
                return Err(error_response(StatusCode::BAD_REQUEST, &format!("{} must be \"1\" or empty", k)));
            }
        } else if k == SETTING_THEME_MODE {
            if !matches!(trimmed, "" | "light" | "dark") {
                return Err(error_response(StatusCode::BAD_REQUEST, "theme_mode must be \"light\", \"dark\" or empty"));
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
    // A logo change flips the JSON-LD logo URL baked into the registry.
    if req.fields.contains_key(SETTING_LOGO_IMAGE) || req.fields.contains_key(SETTING_LOGO_DARK_IMAGE) {
        sites::reload_from_db(&state.db.lock());
    }
    invalidate_page_cache();
    Ok(Json(json!({ "status": "OK" })))
}

// ---------------------------------------------------------------------------
// Site registry admin (owner)
// ---------------------------------------------------------------------------

/// Hosts that must never be claimed by a site, or the dashboard becomes
/// unreachable on them.
const RESERVED_HOSTS: &[&str] =
    &["susi.lp-research.com", "staging.susi.lp-research.com", "localhost", "127.0.0.1"];

fn normalize_and_validate_site(
    id: &str,
    def: &mut sites::SiteDef,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    def.name = def.name.trim().to_string();
    if def.name.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "name is required"));
    }
    def.public_base = def.public_base.trim().trim_end_matches('/').to_string();
    if !def.public_base.starts_with("http://") && !def.public_base.starts_with("https://") {
        return Err(error_response(StatusCode::BAD_REQUEST, "public_base must be an http(s) URL"));
    }
    // Tolerate pasted URLs: strip a scheme and anything after the host.
    def.hosts = def
        .hosts
        .iter()
        .map(|h| {
            let h = h.trim().to_ascii_lowercase();
            let h = h.strip_prefix("https://").or_else(|| h.strip_prefix("http://")).unwrap_or(&h);
            h.split('/').next().unwrap_or("").to_string()
        })
        .filter(|h| !h.is_empty())
        .collect();
    if def.hosts.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "at least one host is required"));
    }
    for h in &def.hosts {
        if !h.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-') {
            return Err(error_response(StatusCode::BAD_REQUEST, &format!("invalid host: {}", h)));
        }
        if RESERVED_HOSTS.contains(&h.as_str()) {
            return Err(error_response(StatusCode::BAD_REQUEST, &format!("host {} is reserved", h)));
        }
    }
    for other in sites::all_sites() {
        if other.id == id {
            continue;
        }
        if let Some(h) = def.hosts.iter().find(|h| other.hosts.contains(&h.as_str())) {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                &format!("host {} already belongs to site {}", h, other.id),
            ));
        }
    }
    for v in [
        &mut def.tagline,
        &mut def.contact_email,
        &mut def.org_legal_name,
        &mut def.addr_locality,
        &mut def.addr_country,
        &mut def.og_image_url,
        &mut def.llms_blurb,
    ] {
        *v = v.trim().to_string();
    }
    def.social_links =
        def.social_links.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    def.area_served =
        def.area_served.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    // Language codes become URL path prefixes (/{lang}/), so they must be
    // simple codes and must not shadow a real top-level path.
    def.langs = def
        .langs
        .iter()
        .map(|l| l.trim().to_ascii_lowercase())
        .filter(|l| !l.is_empty())
        .collect();
    const RESERVED_LANG_PATHS: &[&str] = &[
        "site", "shop", "api", "static", "docs", "blog", "newsletter", "health",
    ];
    for l in &def.langs {
        let valid = (2..=8).contains(&l.len())
            && l.chars().all(|c| c.is_ascii_lowercase() || c == '-');
        if !valid || RESERVED_LANG_PATHS.contains(&l.as_str()) {
            return Err(error_response(StatusCode::BAD_REQUEST, &format!("invalid language: {}", l)));
        }
    }
    Ok(())
}

pub async fn handle_admin_list_sites(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    let rows = {
        let db = state.db.lock();
        db.list_sites().map_err(db_err)?
    };
    let sites_json: Vec<_> = rows
        .iter()
        .filter_map(|(id, json_str)| {
            let def: sites::SiteDef = serde_json::from_str(json_str).ok()?;
            Some(json!({ "id": id, "is_default": id == sites::DEFAULT_SITE_ID, "def": def }))
        })
        .collect();
    Ok(Json(json!({ "sites": sites_json })))
}

#[derive(Deserialize)]
pub struct CreateSiteRequest {
    pub id: String,
    #[serde(flatten)]
    pub def: sites::SiteDef,
}

pub async fn handle_admin_create_site(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(mut req): Json<CreateSiteRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_owner(&state, &p)?;
    let id = req.id.trim().to_ascii_lowercase();
    if id.is_empty()
        || id.len() > 32
        || id.starts_with('-')
        || !id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(error_response(StatusCode::BAD_REQUEST, "id must be a short lowercase slug"));
    }
    if sites::site_by_id(&id).is_some() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Site id already exists"));
    }
    normalize_and_validate_site(&id, &mut req.def)?;
    {
        let db = state.db.lock();
        db.upsert_site(&id, None, &serde_json::to_string(&req.def).unwrap()).map_err(db_err)?;
        sites::reload_from_db(&db);
    }
    invalidate_page_cache();
    log::info!("Site '{}' created", id);
    Ok(Json(json!({ "status": "OK", "id": id })))
}

pub async fn handle_admin_update_site(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(mut def): Json<sites::SiteDef>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_owner(&state, &p)?;
    if sites::site_by_id(&id).is_none() {
        return Err(error_response(StatusCode::NOT_FOUND, "Unknown site"));
    }
    normalize_and_validate_site(&id, &mut def)?;
    {
        let db = state.db.lock();
        db.upsert_site(&id, None, &serde_json::to_string(&def).unwrap()).map_err(db_err)?;
        sites::reload_from_db(&db);
    }
    invalidate_page_cache();
    log::info!("Site '{}' updated", id);
    Ok(Json(json!({ "status": "OK" })))
}

// ---------------------------------------------------------------------------
// Path-level 301 redirects
//
// Page slugs can't contain '/', so legacy URLs (WordPress permalinks like
// /products/imu/lpms-ig1/) live in a per-site path->target map instead.
// Multi-segment paths land in `handle_website_render_path` (the /site/{*path}
// fallback route); single-segment misses are checked in `render_website`.
// ---------------------------------------------------------------------------

/// Query/fragment stripped, leading slash ensured, trailing slashes dropped.
fn normalize_redirect_path(path: &str) -> String {
    let p = path.split(['?', '#']).next().unwrap_or("").trim();
    let mut p = if p.starts_with('/') { p.to_string() } else { format!("/{}", p) };
    while p.len() > 1 && p.ends_with('/') {
        p.pop();
    }
    p
}

fn lookup_site_redirect(state: &Arc<AppState>, site: &SiteConfig, path: &str) -> Option<String> {
    let db = state.db.lock();
    db.get_site_redirect(site.id, &normalize_redirect_path(path)).ok().flatten()
}

/// Where a mapped redirect sends the visitor: absolute URLs pass through,
/// rooted paths keep the /site prefix off the marketing hosts.
fn redirect_map_location(target: &str, marketing_host: bool) -> String {
    let t = target.trim();
    if t.starts_with("http://") || t.starts_with("https://") {
        return t.to_string();
    }
    let path = if t.starts_with('/') { t.to_string() } else { format!("/{}", t) };
    if marketing_host { path } else { format!("/site{}", path) }
}

fn validate_redirect_pair(from_path: &str, to_path: &str) -> Result<(String, String), (StatusCode, Json<ErrorResponse>)> {
    let from = normalize_redirect_path(from_path);
    if from == "/" || from.len() > 512 || from.contains('\0') {
        return Err(error_response(StatusCode::BAD_REQUEST, &format!("Invalid from_path: {}", from_path)));
    }
    let to = to_path.trim();
    if to.is_empty() || to.len() > 1024 || to.contains('\0') {
        return Err(error_response(StatusCode::BAD_REQUEST, &format!("Invalid to_path for {}", from_path)));
    }
    let to = if to.starts_with("http://") || to.starts_with("https://") || to.starts_with('/') {
        to.to_string()
    } else {
        format!("/{}", to)
    };
    if normalize_redirect_path(&to) == from {
        return Err(error_response(StatusCode::BAD_REQUEST, &format!("{} would redirect to itself", from)));
    }
    Ok((from, to))
}

/// GET /site/{head}/{*rest} - anything deeper than one segment. Only
/// redirect-map entries live here; everything else is a hard 404 (with the
/// site shell so a human still gets navigation).
pub async fn handle_website_render_path(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Path((head, rest)): Path<(String, String)>,
) -> axum::response::Response {
    let site = match resolve_site(&headers, &sq) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    // /site/{lang}/... serves the translation: the same URL space as the
    // default language, one segment deeper. Deeper paths fall through to the
    // redirect map (WordPress-era /ja/... permalinks).
    if site.langs.contains(&head.as_str()) {
        let rest = rest.trim_end_matches('/');
        let sq2 = SiteQuery { site: sq.site.clone(), page: sq.page, lang: Some(head.clone()) };
        if rest == "blog/rss.xml" {
            return handle_blog_rss(State(state), headers, Query(sq2)).await.into_response();
        }
        if rest == "blog" {
            return render_website(&state, &headers, &sq2, Some("blog".to_string()), false);
        }
        if let Some(post) = rest.strip_prefix("blog/") {
            if !post.contains('/') {
                return render_website(&state, &headers, &sq2, Some(post.to_string()), true);
            }
        }
        if !rest.is_empty() && !rest.contains('/') {
            return render_website(&state, &headers, &sq2, Some(rest.to_string()), false);
        }
    }
    let path = format!("{}/{}", head, rest);
    if let Some(to) = lookup_site_redirect(&state, site, &path) {
        let loc = redirect_map_location(&to, is_marketing_host(&headers));
        return (StatusCode::MOVED_PERMANENTLY, [(header::LOCATION, loc)]).into_response();
    }
    let head = format!(
        "<title>{}</title>\n<meta name=\"robots\" content=\"noindex\">\n",
        html_escape(site.name),
    );
    let html = render_shell(&state, site, "", &head, "<div class=\"empty-state\">Page not found</div>");
    (StatusCode::NOT_FOUND, build_html_headers(), html).into_response()
}

pub async fn handle_list_redirects(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    let rows = {
        let db = state.db.lock();
        db.list_site_redirects(site.id).map_err(db_err)?
    };
    let redirects: Vec<_> = rows
        .into_iter()
        .map(|(id, from, to, updated_at)| json!({
            "id": id, "from_path": from, "to_path": to, "updated_at": updated_at,
        }))
        .collect();
    Ok(Json(json!({ "site": site.id, "redirects": redirects })))
}

#[derive(Deserialize)]
pub struct RedirectEntry {
    pub from_path: String,
    pub to_path: String,
}

pub async fn handle_upsert_redirect(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Json(req): Json<RedirectEntry>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    let (from, to) = validate_redirect_pair(&req.from_path, &req.to_path)?;
    {
        let db = state.db.lock();
        db.upsert_site_redirect(site.id, &from, &to).map_err(db_err)?;
    }
    Ok(Json(json!({ "from_path": from, "to_path": to })))
}

pub async fn handle_delete_redirect(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    let removed = {
        let db = state.db.lock();
        db.delete_site_redirect(site.id, id).map_err(db_err)?
    };
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Redirect not found"));
    }
    Ok(Json(json!({ "status": "OK" })))
}

#[derive(Deserialize)]
pub struct ImportRedirectsRequest {
    pub redirects: Vec<RedirectEntry>,
}

pub async fn handle_import_redirects(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Json(req): Json<ImportRedirectsRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    if req.redirects.len() > 5000 {
        return Err(error_response(StatusCode::BAD_REQUEST, "At most 5000 redirects per import"));
    }
    // Validate everything before writing anything.
    let mut pairs = Vec::with_capacity(req.redirects.len());
    for r in &req.redirects {
        pairs.push(validate_redirect_pair(&r.from_path, &r.to_path)?);
    }
    {
        let db = state.db.lock();
        for (from, to) in &pairs {
            db.upsert_site_redirect(site.id, from, to).map_err(db_err)?;
        }
    }
    log::info!("Imported {} redirect(s) for site {}", pairs.len(), site.id);
    Ok(Json(json!({ "imported": pairs.len() })))
}

// ---------------------------------------------------------------------------
// Bulk page import - the WordPress-migration counterpart of the docs importer.
// Multipart: `manifest` (JSON keyed by slug), many `page` fields (slug.md),
// many `asset` file fields. Pages are upserted (revisions captured), assets
// overwritten, and any `redirect_from` paths land in the redirect map
// pointing at the page's canonical path.
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct ImportPageEntry {
    pub title: Option<String>,
    pub parent_slug: Option<String>,
    pub ord: Option<i64>,
    #[serde(default)]
    pub meta_description: String,
    pub page_kind: Option<String>,
    pub published_at: Option<String>,
    #[serde(default)]
    pub redirect_from: Vec<String>,
    #[serde(default)]
    pub hidden: bool,
    /// Retires the page: it 301s here and leaves nav, sitemap and llms.txt,
    /// but keeps its content so it can be brought back.
    #[serde(default)]
    pub redirect_to: String,
    /// Content language ("" = the site default); must be one the site
    /// declares.
    #[serde(default)]
    pub lang: String,
    /// For a translated page: the default-language slug it mirrors.
    #[serde(default)]
    pub translation_of: String,
}

pub async fn handle_import_pages(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let mut manifest: HashMap<String, ImportPageEntry> = HashMap::new();
    let mut page_bodies: Vec<(String, String)> = Vec::new();
    let mut assets: Vec<(String, Vec<u8>)> = Vec::new();

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("Multipart: {}", e)))?
    {
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
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
                let slug = file_name[..file_name.len() - 3].to_string();
                safe_slug(&slug)?;
                let body = field
                    .text()
                    .await
                    .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;
                page_bodies.push((slug, body));
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

    if page_bodies.is_empty() && assets.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "No pages or assets uploaded"));
    }

    // Validate every page before writing anything.
    struct ImportRow {
        slug: String,
        title: String,
        body: String,
        parent_slug: Option<String>,
        ord: i64,
        meta_description: String,
        page_kind: String,
        published_at: String,
        redirect_from: Vec<String>,
        hidden: bool,
        redirect_to: String,
        lang: String,
        translation_of: String,
    }
    let mut rows: Vec<ImportRow> = Vec::with_capacity(page_bodies.len());
    for (slug, body) in page_bodies {
        let entry = manifest.remove(&slug).unwrap_or_default();
        if !entry.lang.is_empty() && !site.langs.contains(&entry.lang.as_str()) {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                &format!("{}: unknown language '{}' for this site", slug, entry.lang),
            ));
        }
        let page_kind = entry.page_kind.unwrap_or_else(|| "page".to_string());
        if page_kind != "page" && page_kind != "post" {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                &format!("{}: page_kind must be 'page' or 'post'", slug),
            ));
        }
        let mut published_at = entry.published_at.unwrap_or_default().trim().to_string();
        if page_kind == "post" {
            if published_at.is_empty() {
                published_at = chrono::Utc::now().format("%Y-%m-%d").to_string();
            } else if chrono::NaiveDate::parse_from_str(&published_at, "%Y-%m-%d").is_err() {
                return Err(error_response(
                    StatusCode::BAD_REQUEST,
                    &format!("{}: published_at must be YYYY-MM-DD", slug),
                ));
            }
        } else {
            published_at.clear();
        }
        let mut redirect_from = Vec::with_capacity(entry.redirect_from.len());
        let canonical_path = if page_kind == "post" {
            format!("{}/blog/{}", lang_prefix(&entry.lang), slug)
        } else {
            format!("{}/{}", lang_prefix(&entry.lang), slug)
        };
        for from in &entry.redirect_from {
            let (from, _to) = validate_redirect_pair(from, &canonical_path)?;
            redirect_from.push(from);
        }
        let redirect_to = entry.redirect_to.trim().to_string();
        if !redirect_to.is_empty() {
            validate_redirect_pair(&canonical_path, &redirect_to)?;
        }
        let title = entry.title.unwrap_or_else(|| crate::docs::derive_title(&slug, &body));
        rows.push(ImportRow {
            slug,
            title,
            body,
            parent_slug: entry.parent_slug,
            ord: entry.ord.unwrap_or(0),
            meta_description: entry.meta_description,
            page_kind,
            published_at,
            redirect_from,
            hidden: entry.hidden,
            redirect_to,
            lang: entry.lang,
            translation_of: entry.translation_of,
        });
    }

    let mut urls: Vec<String> = Vec::with_capacity(rows.len());
    {
        let mut db = state.db.lock();
        for r in &rows {
            db.upsert_website_page(
                site.id,
                &r.lang,
                &r.slug,
                &r.title,
                &r.body,
                r.parent_slug.as_deref(),
                r.ord,
                &r.meta_description,
                &r.page_kind,
                &r.published_at,
                "",
                &r.redirect_to,
                &r.translation_of,
                Some(&principal.username),
            )
            .map_err(db_err)?;
            db.set_website_page_hidden(site.id, &r.lang, &r.slug, r.hidden).map_err(db_err)?;
            let canonical_path = if r.page_kind == "post" {
                format!("{}/blog/{}", lang_prefix(&r.lang), r.slug)
            } else {
                format!("{}/{}", lang_prefix(&r.lang), r.slug)
            };
            for from in &r.redirect_from {
                db.upsert_site_redirect(site.id, from, &canonical_path).map_err(db_err)?;
            }
            if !r.hidden && r.redirect_to.is_empty() {
                urls.push(if r.page_kind == "post" {
                    canonical_post_url(site, &r.lang, &r.slug)
                } else {
                    canonical_page_url(site, &r.lang, &r.slug, false)
                });
            }
        }
    }

    let mut assets_written = 0usize;
    if !assets.is_empty() {
        let dir = assets_dir(&state, site);
        std::fs::create_dir_all(&dir).map_err(|e| {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("mkdir: {}", e))
        })?;
        let db = state.db.lock();
        for (name, bytes) in &assets {
            std::fs::write(dir.join(name), bytes).map_err(|e| {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("write {}: {}", name, e))
            })?;
            db.upsert_website_asset(site.id, name, bytes.len() as u64).map_err(db_err)?;
            assets_written += 1;
        }
    }

    invalidate_page_cache();
    let n_pages = rows.len();
    let n_redirects: usize = rows.iter().map(|r| r.redirect_from.len()).sum();
    ping_indexnow(&state, site, urls);
    log::info!(
        "Website import for site {}: {} page(s), {} asset(s), {} redirect(s)",
        site.id, n_pages, assets_written, n_redirects,
    );
    Ok(Json(json!({
        "pages_written": n_pages,
        "assets_written": assets_written,
        "redirects_written": n_redirects,
    })))
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
    fn first_image_url_skips_video_files() {
        let md = "![film](showreel.mp4)\n\n![hero](/static/foo.png)";
        assert_eq!(
            first_image_url(sites::default_site(), md),
            Some("https://xikaku.com/static/foo.png".to_string())
        );
    }

    #[test]
    fn mp4_in_image_syntax_renders_ambient_video() {
        let html = render_body_html("![Showreel](showreel.mp4)\n");
        assert!(html.contains("<video"), "no video tag: {html}");
        assert!(
            html.contains(r#"src="/api/v1/website/assets/showreel.mp4""#),
            "bare name not absolutized: {html}"
        );
        for attr in ["autoplay", "muted", "loop", "playsinline"] {
            assert!(html.contains(attr), "{attr} stripped: {html}");
        }
        assert!(!html.contains("<img"), "{html}");
    }

    #[test]
    fn video_keeps_pandoc_size_and_class_attrs() {
        let html = render_body_html("![x](/media/film.webm){width=1280 .wide}\n");
        assert!(html.contains(r#"width="1280""#), "{html}");
        assert!(html.contains(r#"class="wide""#), "{html}");
        assert!(html.contains(r#"src="/media/film.webm""#), "{html}");
    }

    fn range_of(value: Option<&str>, total: u64) -> ByteRange {
        let mut h = HeaderMap::new();
        if let Some(v) = value {
            h.insert(header::RANGE, v.parse().unwrap());
        }
        byte_range(&h, total)
    }

    #[test]
    fn byte_range_parses_the_shapes_media_clients_send() {
        assert_eq!(range_of(None, 10), ByteRange::Full);
        // Safari probes with bytes=0-1 before streaming.
        assert_eq!(range_of(Some("bytes=0-1"), 10), ByteRange::Window(0, 1));
        assert_eq!(range_of(Some("bytes=0-"), 10), ByteRange::Window(0, 9));
        assert_eq!(range_of(Some("bytes=4-"), 10), ByteRange::Window(4, 9));
        assert_eq!(range_of(Some("bytes=-4"), 10), ByteRange::Window(6, 9));
        // End clamps to EOF; start past EOF is unsatisfiable.
        assert_eq!(range_of(Some("bytes=5-100"), 10), ByteRange::Window(5, 9));
        assert_eq!(range_of(Some("bytes=10-"), 10), ByteRange::Unsatisfiable);
        assert_eq!(range_of(Some("bytes=0-"), 0), ByteRange::Unsatisfiable);
        // Malformed or multi-range specs fall back to the whole file.
        assert_eq!(range_of(Some("bytes=3-1"), 10), ByteRange::Full);
        assert_eq!(range_of(Some("bytes=0-1,5-6"), 10), ByteRange::Full);
        assert_eq!(range_of(Some("lines=0-1"), 10), ByteRange::Full);
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
            String::new(), String::new(),
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
    fn render_body_html_resolves_bare_image_names() {
        // Bare filenames are uploaded assets; every other form is left alone.
        let h = render_body_html(
            "![](shot.png)\n\n![](/api/v1/docs/v1/assets/doc.png)\n\n![](https://x.example/a.png)\n",
        );
        assert!(h.contains(r#"src="/api/v1/website/assets/shot.png""#), "{}", h);
        assert!(h.contains(r#"src="/api/v1/docs/v1/assets/doc.png""#), "{}", h);
        assert!(h.contains(r#"src="https://x.example/a.png""#), "{}", h);
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
    fn empty_header_table_renders_as_reflowing_grid() {
        let md = "|  |  |  |\n| --- | --- | --- |\n| ![a](/a.png){width=100%} **A** | ![b](/b.png){width=100%} **B** | |\n";
        let html = render_body_html(md);
        assert!(html.contains(r#"class="grid cols-3""#), "got: {}", html);
        assert!(!html.contains("<table"), "got: {}", html);
        assert!(html.contains(r#"src="/a.png""#), "got: {}", html);
        assert!(html.contains("<strong>A</strong>"), "got: {}", html);
    }

    #[test]
    fn normal_table_still_renders_as_table() {
        let md = "| A | B |\n| --- | --- |\n| 1 | 2 |\n";
        let html = render_body_html(md);
        assert!(html.contains("<table"), "got: {}", html);
        assert!(!html.contains("class=\"grid"), "got: {}", html);
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
    fn brand_site_honors_explicit_site_param() {
        let q = |s: Option<&str>| SiteQuery { site: s.map(String::from), page: None, lang: None };
        let bare = HeaderMap::new();
        assert_eq!(brand_site(&bare, &q(Some("lpr"))).id, "lpr");
        // Unknown or missing param falls back to Host resolution, then default.
        assert_eq!(brand_site(&bare, &q(Some("nope"))).id, "xikaku");
        assert_eq!(brand_site(&bare, &q(None)).id, "xikaku");
        let mut lpr_host = HeaderMap::new();
        lpr_host.insert(header::HOST, "lp-research.com".parse().unwrap());
        assert_eq!(brand_site(&lpr_host, &q(None)).id, "lpr");
        // An explicit param wins over the Host header.
        assert_eq!(brand_site(&lpr_host, &q(Some("xikaku"))).id, "xikaku");
    }

    #[test]
    fn analytics_head_banner_prefix_uses_site_hosts() {
        let out = render_analytics_head(sites::default_site(), None, Some("AW-18330845601"), None, None, None);
        assert!(
            out.contains(r#"["xikaku.com","www.xikaku.com","staging.xikaku.com"].indexOf(location.host)"#),
            "got: {}", out
        );
        let out = render_analytics_head(sites::site_by_id("lpr").unwrap(), None, Some("AW-18330845601"), None, None, None);
        assert!(
            out.contains(r#"["lp-research.com","www.lp-research.com","staging.lp-research.com"].indexOf(location.host)"#),
            "got: {}", out
        );
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
    fn normalize_redirect_path_canonicalizes() {
        assert_eq!(normalize_redirect_path("/products/imu/lpms-ig1/"), "/products/imu/lpms-ig1");
        assert_eq!(normalize_redirect_path("products/imu"), "/products/imu");
        assert_eq!(normalize_redirect_path("/category/blog/?utm=x#frag"), "/category/blog");
        assert_eq!(normalize_redirect_path("/"), "/");
        assert_eq!(normalize_redirect_path("///"), "/");
    }

    #[test]
    fn redirect_pair_validation() {
        let (f, t) = validate_redirect_pair("/old-page/", "new-page").ok().unwrap();
        assert_eq!(f, "/old-page");
        assert_eq!(t, "/new-page");
        let (_, t) = validate_redirect_pair("/x", "https://example.com/y").ok().unwrap();
        assert_eq!(t, "https://example.com/y");
        assert!(validate_redirect_pair("/", "/x").is_err());
        assert!(validate_redirect_pair("/x", "").is_err());
        assert!(validate_redirect_pair("/same", "/same/").is_err());
    }

    #[test]
    fn redirect_map_location_prefixes_off_marketing() {
        assert_eq!(redirect_map_location("/lpms-ig1", true), "/lpms-ig1");
        assert_eq!(redirect_map_location("/lpms-ig1", false), "/site/lpms-ig1");
        assert_eq!(redirect_map_location("https://a.example/b", false), "https://a.example/b");
    }

    #[test]
    fn blog_index_hrefs_carry_page_state() {
        assert_eq!(blog_index_href("", 1), "/blog");
        assert_eq!(blog_index_href("", 3), "/blog?page=3");
        assert_eq!(blog_index_href("ja", 1), "/ja/blog");
        assert_eq!(blog_index_href("ja", 2), "/ja/blog?page=2");
    }

    #[test]
    fn email_shortcode_obfuscates_ssr_html() {
        let html = render_body_html("Write to {{email:info@lp-research.com}} today.");
        assert!(!html.contains("info@lp-research.com"), "plain address must not survive SSR");
        assert!(!html.contains("{{email:"), "shortcode literal must not survive SSR");
        assert!(html.contains("class=\"email-obf\""));
        assert!(html.contains("data-u=\"aW5mbw==\""));
        // Malformed shortcode stays literal.
        let bad = render_body_html("{{email:not-an-address}}");
        assert!(bad.contains("{{email:not-an-address}}"));
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
    fn nav_structure_validator_accepts_external_links() {
        assert!(is_valid_nav_structure(
            r#"[{"title":"Support","items":[{"title":"Documentation","url":"https://wiki.example/space"},
                {"title":"Customer Area","url":"/customer-area/dashboard"},"contact"]}]"#
        ));
        // A link item must carry a title, a safe URL scheme and nothing else.
        assert!(!is_valid_nav_structure(
            r#"[{"title":"S","items":[{"title":"X","url":"javascript:alert(1)"}]}]"#
        ));
        assert!(!is_valid_nav_structure(r#"[{"title":"S","items":[{"title":"","url":"/x"}]}]"#));
        assert!(!is_valid_nav_structure(r#"[{"title":"S","items":[{"url":"/x"}]}]"#));
        assert!(!is_valid_nav_structure(
            r#"[{"title":"S","items":[{"title":"X","url":"/x","target":"_blank"}]}]"#
        ));
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
