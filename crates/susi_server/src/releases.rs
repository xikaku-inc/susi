//! Product catalog + release upload/download handlers.

use crate::*;

/// Public list of products so doc clients can populate a product picker.
pub(crate) async fn handle_list_products(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let db = state.db.lock();
    let rows = db
        .list_release_products()
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    let products: Vec<_> = rows
        .into_iter()
        .map(|(slug, name, description, ord, download_public)| {
            serde_json::json!({ "slug": slug, "name": name, "description": description, "ord": ord, "download_public": download_public })
        })
        .collect();
    Ok(Json(serde_json::json!({ "products": products })))
}

/// Create a product. Admin only (JWT).
pub(crate) async fn handle_create_product(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ProductRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    let slug = req.slug.trim();
    docs::safe_product(slug)?;
    if req.name.trim().is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Missing product name"));
    }
    let db = state.db.lock();
    if db
        .product_exists(slug)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    {
        return Err(error_response(StatusCode::CONFLICT, "Product already exists"));
    }
    db.upsert_release_product(slug, req.name.trim(), req.description.trim(), req.ord, req.download_public)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    Ok(Json(serde_json::json!({ "status": "OK", "slug": slug })))
}

/// Update a product's metadata (slug is immutable). Admin only (JWT).
pub(crate) async fn handle_update_product(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(product): Path<String>,
    Json(req): Json<UpdateProductRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    docs::safe_product(&product)?;
    let db = state.db.lock();
    if !db
        .product_exists(&product)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    {
        return Err(error_response(StatusCode::NOT_FOUND, "Product not found"));
    }
    db.upsert_release_product(&product, req.name.trim(), req.description.trim(), req.ord, req.download_public)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    Ok(Json(serde_json::json!({ "status": "OK", "slug": product })))
}

/// Delete a product. Admin only (JWT). Rejected if it still owns releases, and
/// the default product cannot be removed.
pub(crate) async fn handle_delete_product(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(product): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    if product == DEFAULT_PRODUCT {
        return Err(error_response(StatusCode::BAD_REQUEST, "Cannot delete the default product"));
    }
    let db = state.db.lock();
    let n = db
        .count_releases_for_product(&product)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    if n > 0 {
        return Err(error_response(
            StatusCode::CONFLICT,
            "Product still has releases; delete them first",
        ));
    }
    if !db
        .delete_release_product(&product)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    {
        return Err(error_response(StatusCode::NOT_FOUND, "Product not found"));
    }
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

/// List releases — available to licensed clients or authenticated users
pub(crate) async fn handle_get_releases(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(pq): Query<ProductQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let product = pq.slug();
    // A publicly-downloadable product lists its global releases anonymously so
    // the marketing site can render download buttons. Otherwise accept either a
    // license key or a bearer token.
    let is_public = { state.db.lock().get_product_download_public(product).unwrap_or(false) };
    if !is_public && validate_license_key(&state, &headers).is_err() {
        validate_principal(&headers, &state)?;
    }

    let (rows, mut assets_by_id) = {
        let db = state.db.lock();
        let rows = db
            .list_releases()
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        let ids: Vec<i64> = rows.iter().filter(|r| r.6.is_none()).map(|r| r.0).collect();
        let assets_by_id = db.get_assets_for_releases(&ids).unwrap_or_default();
        (rows, assets_by_id)
    };

    let mut releases = Vec::new();
    for (id, tag, name, body, prerelease, created_at, workspace_id, product_col) in &rows {
        if workspace_id.is_some() || product_col != product { continue; }
        let assets = assets_by_id.remove(id).unwrap_or_default();
        releases.push(serde_json::json!({
            "tag": tag,
            "name": name,
            "body": body,
            "published_at": created_at,
            "prerelease": prerelease,
            "assets": assets.iter().map(|(name, size)| serde_json::json!({
                "name": name,
                "size": size,
            })).collect::<Vec<_>>(),
        }));
    }

    Ok(Json(serde_json::json!({ "releases": releases })))
}

/// Mint a short-lived, single-asset ticket the browser can include as a query
/// parameter on the download URL — needed because `<a href>` clicks can't
/// attach Authorization headers, but only `<a href>`-style navigation hands
/// the response off to the browser's native download UI.
pub(crate) async fn handle_mint_download_ticket(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<DownloadTicketRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let safe_tag = docs::safe_tag(&body.tag)?;
    let safe_asset = docs::safe_filename(&body.asset)?;
    let product = body.product.as_deref().filter(|s| !s.is_empty()).unwrap_or(DEFAULT_PRODUCT);
    docs::safe_product(product)?;
    let sub = authorize_release_download(&state, &headers, product, safe_tag)?;
    let ticket = mint_download_ticket(&state.jwt_secret, &sub, product, safe_tag, safe_asset)?;
    Ok(Json(serde_json::json!({
        "ticket": ticket,
        "expires_in": DOWNLOAD_TICKET_TTL_SECS,
    })))
}

pub(crate) async fn handle_download_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((tag, asset_name)): Path<(String, String)>,
    Query(q): Query<DownloadQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let product = q.product.as_deref().filter(|s| !s.is_empty()).unwrap_or(DEFAULT_PRODUCT);
    docs::safe_product(product)?;
    if let Some(ref ticket) = q.ticket {
        validate_download_ticket(&state.jwt_secret, ticket, product, &tag, &asset_name)?;
    } else {
        authorize_release_download(&state, &headers, product, &tag)?;
    }

    // Reject traversal / empty / nul before building the path, and confirm the
    // canonicalized result stays inside the releases directory. Defense in depth
    // against a future regression in the name checks.
    let safe_tag = docs::safe_tag(&tag)?;
    let safe_asset = docs::safe_filename(&asset_name)?;

    let base = releases_dir(&state).canonicalize()
        .map_err(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "Releases directory unavailable"))?;
    let file_path = release_tag_dir(&state, product, safe_tag).join(safe_asset);
    let canonical = match file_path.canonicalize() {
        Ok(p) => p,
        Err(_) => return Err(error_response(StatusCode::NOT_FOUND, "Asset not found")),
    };
    if !canonical.starts_with(&base) {
        return Err(error_response(StatusCode::BAD_REQUEST, "Invalid asset path"));
    }

    // Stream the file body so we don't fully buffer release artifacts (which
    // can be hundreds of MiB) into memory before responding. Open via
    // tokio::fs so the open syscall doesn't block a runtime worker either.
    let file = tokio::fs::File::open(&canonical)
        .await
        .map_err(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "Read error"))?;
    let metadata = file
        .metadata()
        .await
        .map_err(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "Read error"))?;

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(header::CONTENT_TYPE, "application/octet-stream".parse().unwrap());
    resp_headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{}\"", asset_name).parse().unwrap(),
    );
    resp_headers.insert(header::CONTENT_LENGTH, metadata.len().into());

    let stream = tokio_util::io::ReaderStream::new(file);
    let body = axum::body::Body::from_stream(stream);
    Ok((resp_headers, body))
}

/// Percent-encode a path/query segment, keeping only RFC 3986 unreserved
/// characters. Release tags and asset names are validated to be traversal-safe
/// but may still hold characters that need escaping in a redirect Location.
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Public "latest installer" redirect for a publicly-downloadable product:
/// `GET /download/{product}/{platform}` 302s to the newest release's asset for
/// that platform. Prefers a stable release, falling back to the newest
/// prerelease when no stable one ships that platform yet. Lets xikaku.com link
/// a stable URL (e.g. /download/fusionhub/macos) that never needs editing when
/// a new version is cut.
pub(crate) async fn handle_public_latest_download(
    State(state): State<Arc<AppState>>,
    Path((product, platform)): Path<(String, String)>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    docs::safe_product(&product)?;
    let exts: &[&str] = match platform.to_ascii_lowercase().as_str() {
        "windows" | "win" => &[".msi", ".exe"],
        "macos" | "mac" | "osx" | "darwin" => &[".dmg", ".pkg"],
        "linux" => &[".appimage", ".deb", ".rpm"],
        _ => return Err(error_response(StatusCode::BAD_REQUEST, "Unknown platform")),
    };

    let (tag, asset) = {
        let db = state.db.lock();
        if !db.get_product_download_public(&product).unwrap_or(false) {
            return Err(error_response(StatusCode::NOT_FOUND, "Not found"));
        }
        // list_releases is ordered newest-first (id DESC). Keep global releases
        // for this product; walk newest-first and take the first stable match,
        // remembering the first prerelease match as a fallback.
        let rows = db.list_releases().unwrap_or_default();
        let ids: Vec<i64> = rows
            .iter()
            .filter(|r| r.6.is_none() && r.7 == product)
            .map(|r| r.0)
            .collect();
        let assets_by_id = db.get_assets_for_releases(&ids).unwrap_or_default();
        let mut fallback: Option<(String, String)> = None;
        let mut chosen: Option<(String, String)> = None;
        for r in rows.iter().filter(|r| r.6.is_none() && r.7 == product) {
            let Some(assets) = assets_by_id.get(&r.0) else { continue };
            let Some((name, _)) = assets.iter().find(|(n, _)| {
                let lower = n.to_ascii_lowercase();
                exts.iter().any(|e| lower.ends_with(e))
            }) else { continue };
            if !r.4 {
                chosen = Some((r.1.clone(), name.clone()));
                break;
            }
            if fallback.is_none() {
                fallback = Some((r.1.clone(), name.clone()));
            }
        }
        chosen.or(fallback).ok_or_else(|| {
            error_response(StatusCode::NOT_FOUND, "No download available for this platform")
        })?
    };

    let url = format!(
        "/api/v1/updates/download/{}/{}?product={}",
        pct_encode(&tag),
        pct_encode(&asset),
        pct_encode(&product),
    );
    Ok(axum::response::Redirect::to(&url))
}

/// List releases — admin view (JWT)
pub(crate) async fn handle_list_releases_admin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let (rows, mut assets_by_id) = {
        let db = state.db.lock();
        let rows = db
            .list_releases()
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        let ids: Vec<i64> = rows.iter().map(|r| r.0).collect();
        let assets_by_id = db.get_assets_for_releases(&ids).unwrap_or_default();
        (rows, assets_by_id)
    };

    let mut releases = Vec::with_capacity(rows.len());
    for (id, tag, name, body, prerelease, created_at, workspace_id, product) in &rows {
        let assets = assets_by_id.remove(id).unwrap_or_default();
        releases.push(serde_json::json!({
            "tag": tag,
            "name": name,
            "body": body,
            "published_at": created_at,
            "prerelease": prerelease,
            "workspace_id": workspace_id,
            "product": product,
            "assets": assets.iter().map(|(name, size)| serde_json::json!({
                "name": name,
                "size": size,
            })).collect::<Vec<_>>(),
        }));
    }

    Ok(Json(serde_json::json!({ "releases": releases })))
}

/// Upload a new release — admin only (JWT)
pub(crate) async fn handle_upload_release(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let mut tag = String::new();
    let mut name = String::new();
    let mut body = String::new();
    let mut prerelease = false;
    let mut product = DEFAULT_PRODUCT.to_string();
    let mut workspace_id: Option<String> = None;
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();

    while let Some(field) = multipart.next_field().await
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("Multipart error: {}", e)))?
    {
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "tag" => {
                tag = field.text().await
                    .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;
            }
            "product" => {
                let val = field.text().await
                    .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;
                if !val.trim().is_empty() {
                    product = val.trim().to_string();
                }
            }
            "name" => {
                name = field.text().await
                    .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;
            }
            "body" => {
                body = field.text().await
                    .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;
            }
            "prerelease" => {
                let val = field.text().await
                    .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;
                prerelease = val == "true" || val == "1";
            }
            "workspace_id" => {
                let val = field.text().await
                    .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;
                if !val.is_empty() {
                    workspace_id = Some(val);
                }
            }
            "file" => {
                let file_name = field.file_name().unwrap_or("unknown").to_string();
                let data = field.bytes().await
                    .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("File read error: {}", e)))?;
                files.push((file_name, data.to_vec()));
            }
            _ => {}
        }
    }

    if tag.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Missing 'tag' field"));
    }
    if files.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "No files uploaded"));
    }
    docs::safe_tag(&tag)?;
    docs::safe_product(&product)?;
    for (file_name, _) in &files {
        docs::safe_filename(file_name)?;
    }

    // Upsert release metadata — re-running a release (e.g. a CI retry) must
    // reuse the existing release_id so doc_pages and assets hanging off this
    // release survive. Previously the handler rejected existing tags with 409
    // and the caller was forced to DELETE first, which cascaded and wiped
    // hand-authored documentation pages.
    let (release_id, newly_created) = {
        let db = state.db.lock();
        match db.get_release_by_product_tag(&product, &tag)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        {
            Some(existing_id) => {
                db.update_release_metadata(existing_id, &name, &body, prerelease, workspace_id.as_deref())
                    .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
                // Binaries are being attached, so a doc-only collection with
                // this tag becomes a software release.
                db.set_release_kind(existing_id, "software")
                    .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
                (existing_id, false)
            }
            None => {
                let id = db.insert_release(&product, &tag, &name, &body, prerelease, workspace_id.as_deref(), "software")
                    .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
                (id, true)
            }
        }
    };

    // Carry hand-authored doc pages forward when this is the first time the
    // release tag is seen. The CI release pipeline calls /api/v1/releases
    // (binaries) before /api/v1/docs/.../import, so the docs handler's own
    // seed step would otherwise see an existing release row and skip seeding.
    if newly_created {
        docs::seed_user_docs_into_release(&state, release_id, &product, &tag, workspace_id.as_deref())?;
    }

    // Save files to disk
    let tag_dir = release_tag_dir(&state, &product, &tag);
    std::fs::create_dir_all(&tag_dir)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("Cannot create dir: {}", e)))?;

    let mut asset_names = Vec::new();
    for (file_name, data) in &files {
        let file_path = tag_dir.join(file_name);
        std::fs::write(&file_path, data)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("Write error: {}", e)))?;

        let db = state.db.lock();
        db.add_release_asset(release_id, file_name, data.len() as u64)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        asset_names.push(file_name.clone());
    }

    log::info!("Release {} created with assets: {}", tag, asset_names.join(", "));
    audit(
        &state,
        &principal.username,
        "release.upload",
        &tag,
        &format!("product={} assets={}", product, asset_names.join(",")),
    );

    Ok(Json(serde_json::json!({
        "status": "OK",
        "tag": tag,
        "assets": asset_names,
    })))
}

/// Update a release's metadata (name/body/prerelease) without touching the
/// binary assets or its workspace scope. Admin only (JWT).
pub(crate) async fn handle_update_release(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tag): Path<String>,
    Query(pq): Query<ProductQuery>,
    Json(req): Json<UpdateReleaseRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    let product = pq.slug();

    let db = state.db.lock();
    let release_id = db
        .get_release_by_product_tag(product, &tag)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Release not found"))?;
    let existing_ws = db
        .get_release_workspace_id(product, &tag)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .flatten();
    db.update_release_metadata(release_id, &req.name, &req.body, req.prerelease, existing_ws.as_deref())
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    audit_db(&db, &principal.username, "release.update", &tag, &format!("product={}", product));
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

/// Move a release to a different workspace (or to global). Admin only.
/// Files on disk stay put — releases are keyed by tag, not workspace.
pub(crate) async fn handle_move_release(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tag): Path<String>,
    Query(pq): Query<ProductQuery>,
    Json(req): Json<MoveReleaseRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    let product = pq.slug();

    let target = req
        .workspace_id
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());

    let db = state.db.lock();
    if let Some(ws) = target {
        if db
            .get_workspace(ws)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .is_none()
        {
            return Err(error_response(StatusCode::NOT_FOUND, "Target workspace not found"));
        }
    }
    let release_id = db
        .get_release_by_product_tag(product, &tag)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Release not found"))?;
    db.set_release_workspace(release_id, target)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    log::info!("Release {} moved to workspace {:?}", tag, target);
    audit_db(
        &db,
        &principal.username,
        "release.move",
        &tag,
        &format!("product={} workspace={}", product, target.unwrap_or("global")),
    );
    Ok(Json(serde_json::json!({
        "status": "OK",
        "tag": tag,
        "workspace_id": target,
    })))
}

/// Delete a release — admin only (JWT)
pub(crate) async fn handle_delete_release(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tag): Path<String>,
    Query(pq): Query<ProductQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    let product = pq.slug();

    let db = state.db.lock();
    if !db.delete_release(product, &tag)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    {
        return Err(error_response(StatusCode::NOT_FOUND, "Release not found"));
    }
    drop(db);

    // Remove files from disk
    let tag_dir = release_tag_dir(&state, product, &tag);
    let _ = std::fs::remove_dir_all(&tag_dir);

    log::info!("Release {} deleted", tag);
    audit(&state, &principal.username, "release.delete", &tag, &format!("product={}", product));

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

/// Delete a single binary asset from a release. Admin only (JWT).
pub(crate) async fn handle_delete_release_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((tag, file_name)): Path<(String, String)>,
    Query(pq): Query<ProductQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    docs::safe_tag(&tag)?;
    docs::safe_filename(&file_name)?;
    let product = pq.slug();

    let release_id = {
        let db = state.db.lock();
        db.get_release_by_product_tag(product, &tag)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Release not found"))?
    };
    let removed = {
        let db = state.db.lock();
        db.delete_release_asset(release_id, &file_name)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    let _ = std::fs::remove_file(release_tag_dir(&state, product, &tag).join(&file_name));
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Asset not found"));
    }
    log::info!("Release {} asset {} deleted", tag, file_name);
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

/// Replace a single binary asset on a release with a newly uploaded file.
/// The old asset row + file are removed; the new file is written under its
/// own name (which may differ from the old one). Admin only (JWT).
pub(crate) async fn handle_replace_release_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((tag, old_file_name)): Path<(String, String)>,
    Query(pq): Query<ProductQuery>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    docs::safe_tag(&tag)?;
    docs::safe_filename(&old_file_name)?;
    let product = pq.slug();

    let mut new_file_name = String::new();
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(field) = multipart.next_field().await
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("Multipart: {}", e)))?
    {
        if field.name() == Some("file") {
            new_file_name = field.file_name().unwrap_or("").to_string();
            let data = field.bytes().await
                .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;
            bytes = data.to_vec();
            break;
        }
    }
    if new_file_name.is_empty() || bytes.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Missing 'file' field"));
    }
    docs::safe_filename(&new_file_name)?;

    let release_id = {
        let db = state.db.lock();
        db.get_release_by_product_tag(product, &tag)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Release not found"))?
    };

    let tag_dir = release_tag_dir(&state, product, &tag);
    std::fs::create_dir_all(&tag_dir)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("mkdir: {}", e)))?;
    let new_path = tag_dir.join(&new_file_name);
    std::fs::write(&new_path, &bytes)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("write: {}", e)))?;

    {
        let db = state.db.lock();
        db.add_release_asset(release_id, &new_file_name, bytes.len() as u64)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        // Drop the old row only if the new file landed under a different name —
        // otherwise add_release_asset's upsert already updated the row in place.
        if new_file_name != old_file_name {
            db.delete_release_asset(release_id, &old_file_name)
                .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        }
    }
    if new_file_name != old_file_name {
        let _ = std::fs::remove_file(tag_dir.join(&old_file_name));
    }

    log::info!("Release {} asset {} replaced by {} ({} bytes)", tag, old_file_name, new_file_name, bytes.len());
    Ok(Json(serde_json::json!({
        "status": "OK",
        "name": new_file_name,
        "size": bytes.len(),
    })))
}
