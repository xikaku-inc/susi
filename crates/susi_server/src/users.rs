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
    if !matches!(req.role.as_str(), "admin" | "user") {
        return Err(error_response(StatusCode::BAD_REQUEST, "Role must be admin or user"));
    }
    let email = normalize_email(&req.email)?
        .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, "Email is required"))?;

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

    if !matches!(req.role.as_str(), "admin" | "user") {
        return Err(error_response(StatusCode::BAD_REQUEST, "Role must be admin or user"));
    }
    // Block self-demotion so an admin can't lock the org out of admin access.
    if principal.username == username {
        return Err(error_response(StatusCode::BAD_REQUEST, "Cannot change your own role"));
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
    // Token management is intentionally JWT-only — using one API token to mint
    // another would let a leaked token persist beyond a single revoke.
    if principal.source != AuthSource::Jwt {
        return Err(error_response(StatusCode::FORBIDDEN, "API tokens can only be managed from a browser session"));
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
        db.insert_api_token(&principal.username, name, &token_hash, &prefix)
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
    db.set_user_email(&principal.username, normalized.as_deref())
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    Ok(Json(serde_json::json!({ "status": "OK", "email": normalized })))
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
