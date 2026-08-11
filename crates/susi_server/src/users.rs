//! User management, API tokens, email, trusted devices, and session handlers.

use crate::*;

pub(crate) async fn handle_list_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    let db = state.db.lock();
    let users = db
        .list_users()
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    let mut licenses_by_user: HashMap<String, Vec<serde_json::Value>> = HashMap::new();
    for (username, license_key, product) in db.list_all_license_assignments().unwrap_or_default() {
        licenses_by_user.entry(username).or_default().push(
            serde_json::json!({ "license_key": license_key, "product": product }),
        );
    }
    let out = users
        .into_iter()
        .map(|u| {
            let pending = db.has_pending_invitation(&u.username).unwrap_or(false);
            let licenses = licenses_by_user.remove(&u.username).unwrap_or_default();
            serde_json::json!({
                "username": u.username,
                "role": u.role,
                "totp_enabled": u.totp_enabled,
                "must_change_password": u.must_change_password,
                "created_at": u.created_at,
                "email": u.email,
                "newsletter_opt_in": u.newsletter_opt_in,
                "first_name": u.first_name,
                "last_name": u.last_name,
                "pending_invitation": pending,
                "licenses": licenses,
            })
        })
        .collect();
    Ok(Json(out))
}

pub(crate) async fn handle_create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let username = req.username.trim();
    if username.is_empty() || username.len() > 64 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Username must be 1-64 characters"));
    }
    if !is_valid_role(&req.role) {
        return Err(error_response(StatusCode::BAD_REQUEST, "Role must be owner, admin or user"));
    }
    // Creating an owner is granting ownership, so it needs the same gate.
    if is_owner_role(&req.role) {
        require_owner(&state, &principal)?;
    }
    let email = normalize_email(&req.email)?
        .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, "Email is required"))?;

    // One account per address: a duplicate email is almost always a stale UI
    // acting on outdated data (the Quartermaster double-account incident).
    {
        let db = state.db.lock();
        if let Some(existing) = db
            .any_username_by_email(&email)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        {
            return Err(error_response(
                StatusCode::CONFLICT,
                &format!("A user with this email already exists: {}", existing),
            ));
        }
    }

    // Two paths: explicit manual password from admin, or invite-by-email
    // (default). Manual path needs the usual length floor; invite path stores
    // a random unusable hash so password login is impossible until the
    // invitee sets one via the reset link.
    let (pw_hash, send_invite) = match req.password.as_deref().map(str::trim) {
        Some(p) if !p.is_empty() => {
            if p.len() < 8 {
                return Err(error_response(StatusCode::BAD_REQUEST, "Password must be at least 8 characters"));
            }
            (hash_password(p).await?, false)
        }
        _ => {
            if signin_code_disabled(&state) {
                return Err(error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Email is not configured - pass a password to create users without invitation email",
                ));
            }
            // Random secret the admin never sees. Hashing matches every other
            // password path so a brute-force attempt on this row is as
            // expensive as any other.
            let mut bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            let random = hex::encode(bytes);
            (hash_password(&random).await?, true)
        }
    };

    {
        let db = state.db.lock();
        db.create_user(username, &pw_hash, &req.role)
            .map_err(|e| error_response(StatusCode::CONFLICT, &e.to_string()))?;
        db.set_user_email(username, Some(&email))
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        db.set_user_name(username, &req.first_name, &req.last_name)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    }

    if send_invite {
        issue_and_send_invitation(&state, username, &email).await?;
    }

    audit(&state, &principal.username, "user.create", username, &format!("role={}", req.role));
    Ok(Json(serde_json::json!({
        "status": "OK",
        "username": username,
        "role": req.role,
        "email": email,
        "invitation_sent": send_invite,
    })))
}

pub(crate) async fn handle_resend_invitation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    if signin_code_disabled(&state) {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Email is not configured on this server",
        ));
    }

    let email_addr = {
        let db = state.db.lock();
        if !db.user_exists(&username).unwrap_or(false) {
            return Err(error_response(StatusCode::NOT_FOUND, "User not found"));
        }
        db.get_user_email(&username)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, "User has no email on file"))?
    };

    issue_and_send_invitation(&state, &username, &email_addr).await?;

    audit(&state, &principal.username, "user.resend_invitation", &username, "");
    Ok(Json(serde_json::json!({ "status": "OK", "invitation_sent": true })))
}

pub(crate) async fn handle_delete_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    if principal.username == username {
        return Err(error_response(StatusCode::BAD_REQUEST, "Cannot delete your own account"));
    }
    require_owner_for_owner_target(&state, &principal, &username)?;

    let db = state.db.lock();
    db.delete_user(&username)
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;

    audit_db(&db, &principal.username, "user.delete", &username, "");
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

pub(crate) async fn handle_rename_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Json(req): Json<RenameUserRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let new = req.new_username.trim().to_string();
    if new.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Username cannot be empty"));
    }
    if new == username {
        return Err(error_response(StatusCode::BAD_REQUEST, "New username is the same"));
    }

    {
        let db = state.db.lock();
        if db.user_exists(&new).unwrap_or(false) {
            return Err(error_response(StatusCode::CONFLICT, "Username already taken"));
        }
        db.rename_user(&username, &new)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    }
    // API tokens stay valid (the rows were migrated) but the auth hot-path
    // cache still maps them to the old username for up to its TTL.
    api_token_cache_clear();

    audit(&state, &principal.username, "user.rename", &username, &format!("new={}", new));

    // Renaming yourself invalidates the current JWT (its subject is the old
    // name) - tell the frontend so it can force a re-login.
    let self_renamed = principal.username == username;
    Ok(Json(serde_json::json!({ "status": "OK", "self_renamed": self_renamed })))
}

pub(crate) async fn handle_set_user_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Json(req): Json<SetUserRoleRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    if !is_valid_role(&req.role) {
        return Err(error_response(StatusCode::BAD_REQUEST, "Role must be owner, admin or user"));
    }
    // Block self-demotion so an admin can't lock the org out of admin access.
    if principal.username == username {
        return Err(error_response(StatusCode::BAD_REQUEST, "Cannot change your own role"));
    }

    // Ownership is closed: only an owner may grant it, and only an owner may
    // take it away. Without the second rule any admin could demote every owner
    // and seize the newsletter - the privilege would only look elevated.
    let target_is_owner = {
        let db = state.db.lock();
        db.get_user_role(&username).map(|r| is_owner_role(&r)).unwrap_or(false)
    };
    if is_owner_role(&req.role) || target_is_owner {
        require_owner(&state, &principal)?;
    }

    let db = state.db.lock();
    if !db.user_exists(&username).unwrap_or(false) {
        return Err(error_response(StatusCode::NOT_FOUND, "User does not exist"));
    }
    db.set_user_role(&username, &req.role)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    audit_db(&db, &principal.username, "user.set_role", &username, &format!("role={}", req.role));
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

pub(crate) async fn handle_reset_user_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Json(req): Json<ResetPasswordRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    if req.new_password.len() < 8 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Password must be at least 8 characters"));
    }
    require_owner_for_owner_target(&state, &principal, &username)?;

    let pw_hash = hash_password(&req.new_password).await?;
    let db = state.db.lock();
    db.reset_user_password(&username, &pw_hash)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    audit_db(&db, &principal.username, "user.reset_password", &username, "");
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

pub(crate) async fn handle_create_api_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateApiTokenRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    // Token management is intentionally JWT-only - using one API token to mint
    // another would let a leaked token persist beyond a single revoke.
    if principal.source != AuthSource::Jwt {
        return Err(error_response(StatusCode::FORBIDDEN, "API tokens can only be managed from a browser session"));
    }

    // A PAT carries the account's full authority while bypassing the
    // interactive gates, so it may only be minted once the account itself
    // satisfies them: password changed, and 2FA enabled for admin accounts.
    // Without this, the seeded must-change-password owner could mint a PAT
    // and reach every admin endpoint past both gates.
    let row = {
        let db = state.db.lock();
        db.get_user_admin_check(&principal.username)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    let Some((role, must_change, totp_enabled)) = row else {
        return Err(error_response(StatusCode::UNAUTHORIZED, "Unknown user"));
    };
    if must_change {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "Password change required before creating API tokens",
        ));
    }
    if is_admin_role(&role) && !totp_enabled {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "Admin accounts must enable two-factor authentication before creating API tokens",
        ));
    }

    let name = req.name.trim();
    if name.is_empty() || name.len() > 80 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Name must be 1-80 characters"));
    }

    let raw = generate_api_token();
    let token_hash = hash_token(&raw);
    // Prefix shown in lists so humans can tell tokens apart without seeing the
    // secret. 12 chars = "susi_pat_" + 3 hex chars.
    let prefix = raw.chars().take(12).collect::<String>();

    let id = {
        let db = state.db.lock();
        db.insert_api_token(&principal.username, name, &token_hash, &prefix, API_TOKEN_TTL_DAYS)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };

    log::info!("API token '{}' (id={}) created by {}", name, id, principal.username);
    audit(&state, &principal.username, "api_token.create", &prefix, &format!("name={} id={}", name, id));

    Ok(Json(serde_json::json!({
        "id": id,
        "name": name,
        "token": raw,
        "token_prefix": prefix,
    })))
}

pub(crate) async fn handle_list_my_api_tokens(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<susi_core::db::ApiTokenInfo>>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    let db = state.db.lock();
    let rows = db
        .list_api_tokens_for_user(&principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    Ok(Json(rows))
}

pub(crate) async fn handle_revoke_my_api_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    if principal.source != AuthSource::Jwt {
        return Err(error_response(StatusCode::FORBIDDEN, "API tokens can only be managed from a browser session"));
    }
    let owner = {
        let db = state.db.lock();
        db.get_api_token_owner(id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    let Some(owner) = owner else {
        return Err(error_response(StatusCode::NOT_FOUND, "Token not found"));
    };
    if owner != principal.username {
        return Err(error_response(StatusCode::FORBIDDEN, "Token belongs to another user"));
    }
    let revoked = {
        let db = state.db.lock();
        db.revoke_api_token(id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    if !revoked {
        return Err(error_response(StatusCode::CONFLICT, "Token already revoked"));
    }
    api_token_cache_clear();
    log::info!("API token id={} revoked by {}", id, principal.username);
    audit(&state, &principal.username, "api_token.revoke", &id.to_string(), "");
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

pub(crate) async fn handle_list_all_api_tokens(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<susi_core::db::ApiTokenInfo>>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    let db = state.db.lock();
    let rows = db
        .list_all_api_tokens()
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    Ok(Json(rows))
}

pub(crate) async fn handle_revoke_any_api_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    let revoked = {
        let db = state.db.lock();
        db.revoke_api_token(id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    if !revoked {
        return Err(error_response(StatusCode::CONFLICT, "Token already revoked or not found"));
    }
    api_token_cache_clear();
    log::info!("API token id={} revoked by admin {}", id, principal.username);
    audit(&state, &principal.username, "api_token.revoke_any", &id.to_string(), "");
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

pub(crate) async fn handle_set_my_email(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SetEmailRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    let normalized = match req.email.as_deref() {
        Some(s) => normalize_email(s)?,
        None => None,
    };
    let db = state.db.lock();
    // Same one-account-per-address rule as user creation - a duplicate would
    // also break email-based login, which requires a unique match.
    if let Some(ref email) = normalized {
        if let Some(existing) = db
            .any_username_by_email(email)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        {
            if existing != principal.username {
                return Err(error_response(
                    StatusCode::CONFLICT,
                    "This email is already used by another account",
                ));
            }
        }
    }
    db.set_user_email(&principal.username, normalized.as_deref())
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    audit_db(&db, &principal.username, "user.set_my_email", &principal.username, "");
    Ok(Json(serde_json::json!({ "status": "OK", "email": normalized })))
}

/// Self-serve newsletter consent from the account settings page. Consent is
/// off until explicitly granted, so this is the only path a user has to
/// subscribe themselves.
pub(crate) async fn handle_set_my_newsletter(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SetNewsletterRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    let db = state.db.lock();
    db.set_user_newsletter_opt_in(&principal.username, req.opt_in)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    audit_db(
        &db,
        &principal.username,
        "user.set_my_newsletter",
        &principal.username,
        &format!("opt_in={}", req.opt_in),
    );
    Ok(Json(serde_json::json!({ "status": "OK", "newsletter_opt_in": req.opt_in })))
}

pub(crate) async fn handle_set_user_newsletter(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Json(req): Json<SetNewsletterRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    // Managing who receives the newsletter is part of the newsletter
    // feature, so it carries the same owner gate as sending it.
    require_owner(&state, &principal)?;

    let db = state.db.lock();
    if !db
        .set_user_newsletter_opt_in(&username, req.opt_in)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    {
        return Err(error_response(StatusCode::NOT_FOUND, "User not found"));
    }
    audit_db(
        &db,
        &principal.username,
        "user.set_newsletter",
        &username,
        &format!("opt_in={}", req.opt_in),
    );
    Ok(Json(serde_json::json!({ "status": "OK", "newsletter_opt_in": req.opt_in })))
}

/// Flip consent for a whole cohort in one call. The admin UI uses this after
/// selecting rows, so building a list from consent gathered elsewhere (a
/// contract, a trade show sign-up sheet) doesn't take one request per user.
pub(crate) async fn handle_set_newsletter_bulk(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SetNewsletterBulkRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    // Managing who receives the newsletter is part of the newsletter
    // feature, so it carries the same owner gate as sending it.
    require_owner(&state, &principal)?;

    if req.usernames.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "No usernames given"));
    }
    if req.usernames.len() > 5000 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Too many usernames in one call"));
    }

    let db = state.db.lock();
    let changed = db
        .set_newsletter_opt_in_bulk(&req.usernames, req.opt_in)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    audit_db(
        &db,
        &principal.username,
        "user.set_newsletter_bulk",
        "",
        &format!("opt_in={} requested={} changed={}", req.opt_in, req.usernames.len(), changed),
    );
    Ok(Json(serde_json::json!({
        "status": "OK",
        "newsletter_opt_in": req.opt_in,
        "changed": changed,
        "requested": req.usernames.len(),
    })))
}

/// Self-serve rename from the account settings page. Same cascade as the
/// admin rename; hands back a fresh JWT because the old one is bound to the
/// previous username.
pub(crate) async fn handle_rename_self(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<RenameUserRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;

    let new = req.new_username.trim().to_string();
    if new.is_empty() || new.len() > 64 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Username must be 1-64 characters"));
    }
    if new == principal.username {
        return Err(error_response(StatusCode::BAD_REQUEST, "New username is the same"));
    }

    {
        let db = state.db.lock();
        if db.user_exists(&new).unwrap_or(false) {
            return Err(error_response(StatusCode::CONFLICT, "Username already taken"));
        }
        db.rename_user(&principal.username, &new)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    }
    api_token_cache_clear();
    audit(&state, &new, "user.rename_self", &principal.username, &format!("new={}", new));

    let device_label = summarize_user_agent(
        headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
    );
    let token = create_session_jwt(&state, &new, &device_label, client_ip(peer, &headers))?;
    Ok(Json(serde_json::json!({ "status": "OK", "username": new, "token": token })))
}

/// Self-serve name from the account settings page - the byline a user's own
/// blog posts carry, so they shouldn't need an admin to fix a typo in it.
pub(crate) async fn handle_set_my_name(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SetNameRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    let (first, last) = validate_name(&req.first_name, &req.last_name)?;
    {
        let db = state.db.lock();
        db.set_user_name(&principal.username, &first, &last)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        audit_db(&db, &principal.username, "user.set_my_name", &principal.username, "");
    }
    // Bylines are rendered from the name, so cached post HTML is now stale.
    crate::website::invalidate_page_cache();
    Ok(Json(serde_json::json!({
        "status": "OK", "first_name": first, "last_name": last,
    })))
}

/// Name + email in one call, backing the admin Edit User dialog.
pub(crate) async fn handle_set_user_profile(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Json(req): Json<SetProfileRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    require_owner_for_owner_target(&state, &principal, &username)?;

    let (first, last) = validate_name(&req.first_name, &req.last_name)?;
    // An absent email means "not editing it" - a name-only update must never
    // wipe the address the account signs in and receives mail with.
    let email_edit = match req.email.as_deref() {
        Some(s) => Some(normalize_email(s)?),
        None => None,
    };

    let db = state.db.lock();
    if !db.user_exists(&username).unwrap_or(false) {
        return Err(error_response(StatusCode::NOT_FOUND, "User not found"));
    }
    // Same one-account-per-address rule as user creation.
    if let Some(Some(ref email)) = email_edit {
        if let Some(existing) = db
            .any_username_by_email(email)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        {
            if existing != username {
                return Err(error_response(
                    StatusCode::CONFLICT,
                    &format!("A user with this email already exists: {}", existing),
                ));
            }
        }
    }
    db.set_user_name(&username, &first, &last)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    if let Some(ref normalized) = email_edit {
        db.set_user_email(&username, normalized.as_deref())
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    }
    audit_db(&db, &principal.username, "user.set_profile", &username, "");
    let email = match email_edit {
        Some(normalized) => normalized,
        None => db.get_user_email(&username).ok().flatten(),
    };
    drop(db);
    // Bylines are rendered from the name, so cached post HTML is now stale.
    crate::website::invalidate_page_cache();
    Ok(Json(serde_json::json!({
        "status": "OK", "first_name": first, "last_name": last, "email": email,
    })))
}

fn validate_name(
    first: &str,
    last: &str,
) -> Result<(String, String), (StatusCode, Json<ErrorResponse>)> {
    let first = first.trim().to_string();
    let last = last.trim().to_string();
    if first.chars().count() > 64 || last.chars().count() > 64 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Name must be at most 64 characters"));
    }
    Ok((first, last))
}

pub(crate) async fn handle_set_user_email(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Json(req): Json<SetEmailRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let normalized = match req.email.as_deref() {
        Some(s) => normalize_email(s)?,
        None => None,
    };
    require_owner_for_owner_target(&state, &principal, &username)?;
    let db = state.db.lock();
    if !db.user_exists(&username).unwrap_or(false) {
        return Err(error_response(StatusCode::NOT_FOUND, "User not found"));
    }
    db.set_user_email(&username, normalized.as_deref())
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    audit_db(&db, &principal.username, "user.set_email", &username, "");
    Ok(Json(serde_json::json!({ "status": "OK", "email": normalized })))
}

pub(crate) async fn handle_list_my_devices(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<susi_core::db::DeviceInfo>>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    let db = state.db.lock();
    let devices = db
        .list_devices(&principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    Ok(Json(devices))
}

pub(crate) async fn handle_revoke_my_device(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(fingerprint): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    let db = state.db.lock();
    let removed = db
        .revoke_device(&principal.username, &fingerprint)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Device not found"));
    }
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

pub(crate) async fn handle_list_my_sessions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    let current_jti = current_session_jti(&state, &headers)?;
    let rows = {
        let db = state.db.lock();
        db.list_sessions(&principal.username, SESSION_JWT_TTL_DAYS)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    let sessions: Vec<serde_json::Value> = rows
        .iter()
        .map(|s| {
            serde_json::json!({
                "id": s.id,
                "created_at": s.created_at,
                "last_seen": s.last_seen,
                "device_label": s.device_label,
                "ip": s.ip,
                "current": s.jti == current_jti,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "sessions": sessions })))
}

pub(crate) async fn handle_revoke_my_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    current_session_jti(&state, &headers)?;
    let revoked = {
        let db = state.db.lock();
        db.revoke_session(&principal.username, id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    if !revoked {
        return Err(error_response(StatusCode::NOT_FOUND, "Session not found"));
    }
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

pub(crate) async fn handle_revoke_other_sessions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    let current_jti = current_session_jti(&state, &headers)?;
    let revoked = {
        let db = state.db.lock();
        db.revoke_other_sessions(&principal.username, &current_jti)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    Ok(Json(serde_json::json!({ "status": "OK", "revoked": revoked })))
}

/// Subject-access export (GDPR Art 15 / Art 20): every row the account can
/// be tied to, as one JSON document.
pub(crate) async fn handle_export_my_data(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl axum::response::IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    let u = &principal.username;

    let db = state.db.lock();
    let email = db.get_user_email(u).ok().flatten();
    let (first_name, last_name) = db.get_user_name(u).unwrap_or_default();
    let role = db.get_user_role(u).unwrap_or_default();
    let totp_enabled = db.user_totp_enabled(u).unwrap_or(false);
    let newsletter_opt_in = db.get_user_newsletter_opt_in(u).unwrap_or(false);
    let devices = db.list_devices(u).unwrap_or_default();
    let sessions = db.list_sessions(u, SESSION_JWT_TTL_DAYS).unwrap_or_default();
    let api_tokens = db.list_api_tokens_for_user(u).unwrap_or_default();
    let licenses: Vec<serde_json::Value> = db
        .list_licenses_for_user(u)
        .unwrap_or_default()
        .iter()
        .map(|l| {
            serde_json::json!({
                "license_key": l.license_key,
                "product": l.product,
                "customer": l.customer,
                "created": l.created.to_rfc3339(),
            })
        })
        .collect();
    let newsletter_deliveries: Vec<serde_json::Value> = db
        .list_newsletter_deliveries_for_user(u)
        .unwrap_or_default()
        .into_iter()
        .map(|(issue_id, status, sent_at)| {
            serde_json::json!({ "issue_id": issue_id, "status": status, "sent_at": sent_at })
        })
        .collect();
    let audit = db.list_audit_for_user(u).unwrap_or_default();
    let orders: Vec<serde_json::Value> = email
        .as_deref()
        .map(|e| db.list_order_summaries_by_email(e).unwrap_or_default())
        .unwrap_or_default()
        .into_iter()
        .map(|(id, created_at, o_email, o_name, cents, currency, status)| {
            serde_json::json!({
                "id": id, "created_at": created_at, "customer_email": o_email,
                "customer_name": o_name, "amount_total_cents": cents,
                "currency": currency, "status": status,
            })
        })
        .collect();
    drop(db);

    let body = serde_json::json!({
        "exported_at": Utc::now().to_rfc3339(),
        "account": {
            "username": u,
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
            "role": role,
            "totp_enabled": totp_enabled,
            "newsletter_opt_in": newsletter_opt_in,
        },
        "known_devices": devices,
        "active_sessions": sessions,
        "api_tokens": api_tokens,
        "licenses": licenses,
        "newsletter_deliveries": newsletter_deliveries,
        "audit_log_entries": audit,
        "shop_orders": orders,
    });
    let json = serde_json::to_string_pretty(&body)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"susi-data-export.json\""),
        ],
        json,
    ))
}

#[derive(Deserialize)]
pub(crate) struct DeleteMeRequest {
    #[serde(default)]
    password: String,
}

/// Self-serve account deletion (GDPR Art 17). Password-confirmed so a stolen
/// session alone cannot erase the account. Runs the same cascade + scrub as
/// the admin delete.
pub(crate) async fn handle_delete_me(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<DeleteMeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    if principal.source != AuthSource::Jwt {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "Account deletion requires a browser session",
        ));
    }

    let (hash, role) = {
        let db = state.db.lock();
        let hash = db
            .get_user_password_hash(&principal.username)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        let role = db.get_user_role(&principal.username).unwrap_or_default();
        (hash, role)
    };
    if !verify_password(&req.password, &hash).await? {
        return Err(error_response(StatusCode::UNAUTHORIZED, "Password is incorrect"));
    }
    // The last owner deleting themselves would orphan the instance.
    if is_owner_role(&role) {
        let owners = { state.db.lock().count_owners().unwrap_or(0) };
        if owners <= 1 {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "The last owner account cannot delete itself",
            ));
        }
    }

    {
        let db = state.db.lock();
        db.delete_user(&principal.username)
            .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;
        audit_db(&db, "[deleted]", "user.delete_self", "[deleted]", "");
    }
    api_token_cache_clear();
    Ok(Json(serde_json::json!({ "status": "OK" })))
}
