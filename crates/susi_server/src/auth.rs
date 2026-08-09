//! Authentication handlers: login, sign-in codes, magic links, 2FA, password change/reset.

use crate::*;

pub(crate) async fn handle_login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let ip = client_ip(peer, &headers);
    check_login_rate_limit(&state, ip)?;

    // Collapse the raw browser UA into a short "Browser N / OS" label once,
    // up front. Used by the DB token row, the trusted-devices entry, and the
    // sign-in code email so all three show the same readable string.
    let device_label = summarize_user_agent(&req.device_label);

    // Phase 1 - password check. Pull every DB row we need under one lock, drop
    // the lock, then run Argon2 verify off-thread so the ~50 ms CPU spend
    // doesn't serialise every other request behind us.
    let (username, hash, must_change, role, totp_enabled, user_email, device_known) = {
        let db = state.db.lock();
        // The identifier may be a username or an email. Exact username wins
        // (usernames can themselves be email addresses); otherwise fall back
        // to a unique-email lookup. Unresolvable identifiers fall through and
        // fail the password-hash fetch generically (no enumeration).
        let username = if req.username.contains('@')
            && !db.user_exists(&req.username).unwrap_or(false)
        {
            db.find_unique_username_by_email(&req.username)
                .ok()
                .flatten()
                .unwrap_or_else(|| req.username.clone())
        } else {
            req.username.clone()
        };
        let hash = db.get_user_password_hash(&username).ok();
        let must_change = db.user_must_change_password(&username).unwrap_or(false);
        let role = db.get_user_role(&username).unwrap_or_else(|_| "user".into());
        let totp_enabled = db.user_totp_enabled(&username).unwrap_or(false);
        let email = db.get_user_email(&username).ok().flatten();
        let device_known = !req.device_fp.is_empty()
            && db.is_device_known(&username, &req.device_fp).unwrap_or(false);
        (username, hash, must_change, role, totp_enabled, email, device_known)
    };
    // Per-account lockout, checked before the (expensive) password verify so
    // a locked account rejects cheaply and uniformly.
    check_account_lockout(&state, &username)?;
    let Some(hash) = hash else {
        record_failed_account_auth(&state, &username);
        return Err(error_response(StatusCode::UNAUTHORIZED, "Invalid credentials"));
    };
    if !verify_password(&req.password, &hash).await? {
        record_failed_account_auth(&state, &username);
        return Err(error_response(StatusCode::UNAUTHORIZED, "Invalid credentials"));
    }

    // Phase 2 - decide what the new-device gate demands.
    //
    //   known device                → password only, issue JWT
    //   new device + email + SMTP   → require sign-in code (and TOTP if enabled)
    //   new device + no email/SMTP  → bootstrap: just issue JWT, but log warning
    if !device_known {
        let code_disabled = signin_code_disabled(&state);
        if let (Some(email_addr), false) = (user_email.as_ref(), code_disabled) {
            // Issue a 6-digit sign-in code. Do NOT issue JWT yet - the user
            // has to type the code back, which proves email control.
            let code = random_signin_code();
            let Some(email_service) = state.email.clone() else {
                // Unreachable while `code_disabled` is false, but a panic here
                // would be a self-inflicted outage on the login path.
                return Err(error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Email is not configured on this server",
                ));
            };

            // Await the send rather than detaching it. This used to be a
            // fire-and-forget task whose response claimed success regardless,
            // so a dead relay left the user waiting for a code that never left
            // the building - the failure mode most easily mistaken for being
            // locked out, and invisible outside the container logs.
            //
            // Reporting the failure leaks nothing: the caller has already
            // proved the password, and the success response hands back a
            // masked form of the same address anyway.
            if let Err(e) = email_service
                .send_signin_code(email_addr, &username, &code, SIGNIN_CODE_TTL_MINUTES)
                .await
            {
                log::error!("Failed to send sign-in code email to {}: {:#}", email_addr, e);
                audit(&state, &username, "auth.signin_code_send_failed", &username, "");
                return Err(error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Could not send the sign-in code. Please try again, or contact your administrator if it keeps failing.",
                ));
            }

            // Recorded only once the code is genuinely on its way, so a failed
            // send leaves no orphaned login token behind.
            let token_hash = hash_signin_code(&username, &code);
            {
                let db = state.db.lock();
                let _ = db.purge_old_login_tokens();
                db.insert_login_token(
                    &token_hash,
                    &username,
                    &req.device_fp,
                    &device_label,
                    SIGNIN_CODE_TTL_MINUTES * 60,
                )
                .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
            }

            return Ok(Json(serde_json::json!({
                "signin_code_sent": true,
                "email_hint": mask_email(email_addr),
                "ttl_minutes": SIGNIN_CODE_TTL_MINUTES,
                "totp_required_after_code": totp_enabled,
            })));
        }

        // Bootstrap path - no email on file or SMTP disabled.
        //
        // This is a genuine downgrade: the device below is registered as
        // trusted permanently, so for an account without TOTP it is a silent
        // move to single-factor. It exists so a fresh server can be set up
        // before SMTP is, but it also fires if SMTP config is ever lost or
        // SUSI_MAGIC_LINK_BASE_URL is cleared - a config slip that weakens
        // authentication and, before this audit row, showed up nowhere except
        // a container log line nobody reads.
        log::warn!(
            "New-device login for user '{}' accepted without email verification (email set: {}, smtp enabled: {})",
            username,
            user_email.is_some(),
            !signin_code_disabled(&state),
        );
        audit(
            &state,
            &username,
            "auth.unverified_new_device",
            &username,
            &format!(
                "email_set={} signin_code_enabled={} device={}",
                user_email.is_some(),
                !signin_code_disabled(&state),
                device_label,
            ),
        );
    }

    // Phase 3 - TOTP. Only enforced on new devices when enabled.
    if totp_enabled && !device_known {
        match &req.totp_code {
            None => {
                return Ok(Json(serde_json::json!({
                    "error": "TOTP code required",
                    "totp_required": true
                })));
            }
            Some(code) => {
                verify_totp_or_backup(&state, &username, code).inspect_err(|_| {
                    record_failed_account_auth(&state, &username);
                })?;
            }
        }
    }

    // Phase 4 - register this device as trusted (if fp provided) and issue JWT.
    if !req.device_fp.is_empty() {
        let db = state.db.lock();
        if device_known {
            let _ = db.touch_device(&username, &req.device_fp);
        } else {
            let _ = db.register_device(&username, &req.device_fp, &device_label);
        }
    }

    clear_account_failures(&state, &username);
    let token = create_session_jwt(&state, &username, &device_label, ip)?;
    Ok(Json(serde_json::json!({
        "token": token,
        "must_change_password": must_change,
        "totp_enabled": totp_enabled,
        "role": role,
        "username": username
    })))
}

pub(crate) async fn handle_signin_code_exchange(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<SigninCodeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let ip = client_ip(peer, &headers);
    check_login_rate_limit(&state, ip)?;

    // Strip any spaces / dashes the user may have typed when copying the
    // code out of the email.
    let code: String = req.code.chars().filter(|c| c.is_ascii_digit()).collect();

    // Logins may identify by email; resolve to the username the code was
    // scoped to. Exact username wins (usernames can themselves be email
    // addresses). Unresolvable identifiers fall through and fail the token
    // lookup generically (no enumeration).
    let username = {
        let db = state.db.lock();
        if req.username.contains('@') && !db.user_exists(&req.username).unwrap_or(false) {
            db.find_unique_username_by_email(&req.username)
                .ok()
                .flatten()
                .unwrap_or_else(|| req.username.clone())
        } else {
            req.username.clone()
        }
    };
    check_signin_guess_limit(&state, &username)?;
    check_account_lockout(&state, &username)?;
    let token_hash = hash_signin_code(&username, &code);

    // Peek first so we can surface a TOTP prompt without consuming the
    // code. Consuming on the first call would leave a TOTP-enabled user
    // stuck if they entered the code and then had to fetch their auth-app
    // code.
    let row = {
        let db = state.db.lock();
        db.peek_login_token(&token_hash)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    let row = row.ok_or_else(|| {
        record_failed_signin_guess(&state, &username);
        error_response(StatusCode::UNAUTHORIZED, "Code is invalid, already used, or expired")
    })?;

    let (must_change, role, totp_enabled) = {
        let db = state.db.lock();
        (
            db.user_must_change_password(&row.username).unwrap_or(false),
            db.get_user_role(&row.username).unwrap_or_else(|_| "user".into()),
            db.user_totp_enabled(&row.username).unwrap_or(false),
        )
    };
    if totp_enabled {
        let Some(tcode) = req.totp_code.as_deref() else {
            return Ok(Json(serde_json::json!({
                "error": "TOTP code required",
                "totp_required": true,
            })));
        };
        verify_totp_or_backup(&state, &row.username, tcode).inspect_err(|_| {
            record_failed_account_auth(&state, &username);
        })?;
    }

    // All gates passed - NOW consume the code (atomic flip; guards against
    // a concurrent second submission). Anything below this point must
    // succeed, since after consumption a retry would fail.
    let consumed = {
        let db = state.db.lock();
        db.consume_login_token(&token_hash)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    if consumed.is_none() {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "Code is invalid, already used, or expired",
        ));
    }
    clear_signin_guesses(&state, &username);
    clear_account_failures(&state, &username);

    // Trust this device going forward.
    if !row.device_fp.is_empty() {
        let db = state.db.lock();
        let _ = db.register_device(&row.username, &row.device_fp, &row.device_label);
    }

    let jwt = create_session_jwt(&state, &row.username, &row.device_label, ip)?;
    Ok(Json(serde_json::json!({
        "token": jwt,
        "must_change_password": must_change,
        "totp_enabled": totp_enabled,
        "role": role,
        "username": row.username,
    })))
}

pub(crate) async fn handle_request_signin_code(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<RequestCodeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let ip = client_ip(peer, &headers);
    check_login_rate_limit(&state, ip)?;

    let ok = || {
        Json(serde_json::json!({
            "status": "OK",
            "ttl_minutes": SIGNIN_CODE_TTL_MINUTES,
        }))
    };

    let identifier = req.identifier.trim().to_string();
    if identifier.is_empty() || signin_code_disabled(&state) {
        return Ok(ok());
    }

    let device_label = summarize_user_agent(&req.device_label);
    let (username, email_addr) = {
        let db = state.db.lock();
        // Exact username wins (usernames can themselves be email addresses).
        let resolved = if db.user_exists(&identifier).unwrap_or(false) {
            Some(identifier.clone())
        } else if identifier.contains('@') {
            db.find_unique_username_by_email(&identifier).ok().flatten()
        } else {
            None
        };
        let Some(uname) = resolved else { return Ok(ok()); };
        let Some(email) = db.get_user_email(&uname).ok().flatten() else {
            return Ok(ok());
        };
        (uname, email)
    };

    let code = random_signin_code();
    let token_hash = hash_signin_code(&username, &code);
    {
        let db = state.db.lock();
        let _ = db.purge_old_login_tokens();
        db.insert_login_token(
            &token_hash,
            &username,
            &req.device_fp,
            &device_label,
            SIGNIN_CODE_TTL_MINUTES * 60,
        )
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    }

    let email_service = state.email.clone().expect("checked above");
    tokio::spawn(async move {
        if let Err(e) = email_service
            .send_signin_code(&email_addr, &username, &code, SIGNIN_CODE_TTL_MINUTES)
            .await
        {
            log::error!("Failed to send sign-in code email to {}: {:#}", email_addr, e);
        }
    });

    Ok(ok())
}

pub(crate) async fn handle_magic_login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<MagicLoginRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let ip = client_ip(peer, &headers);
    check_login_rate_limit(&state, ip)?;

    let token_hash = hash_token(&req.token);
    let invalid = || error_response(StatusCode::UNAUTHORIZED, "Link is invalid, already used, or expired");

    let (username, role) = {
        let db = state.db.lock();
        let username = db
            .peek_invitation_token(&token_hash)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(invalid)?;
        let role = db.get_user_role(&username).unwrap_or_else(|_| "user".into());
        if role == "admin" {
            // Admin invites must go through password setup; their link points
            // at /#/reset/<token>, so landing here means a tampered URL.
            return Err(invalid());
        }
        // All gates passed - consume (atomic; guards a concurrent second click).
        if db
            .consume_password_reset_token(&token_hash)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .is_none()
        {
            return Err(invalid());
        }
        // The invitee proved inbox control and stays passwordless; without
        // this the dashboard would trap them in the change-password gate.
        let _ = db.clear_must_change_password(&username);
        if !req.device_fp.is_empty() {
            let _ = db.register_device(
                &username,
                &req.device_fp,
                &summarize_user_agent(&req.device_label),
            );
        }
        (username.clone(), role)
    };

    let jwt = create_session_jwt(&state, &username, &summarize_user_agent(&req.device_label), ip)?;
    Ok(Json(serde_json::json!({
        "token": jwt,
        "must_change_password": false,
        "totp_enabled": false,
        "role": role,
        "username": username,
    })))
}

pub(crate) async fn handle_auth_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    let db = state.db.lock();
    let must_change = db.user_must_change_password(&principal.username).unwrap_or(false);
    let totp_enabled = db.user_totp_enabled(&principal.username).unwrap_or(false);
    let role = db.get_user_role(&principal.username).unwrap_or_else(|_| "user".into());
    let email = db.get_user_email(&principal.username).ok().flatten();
    let backup_codes_remaining = db.count_unused_backup_codes(&principal.username).unwrap_or(0);
    let newsletter_opt_in = db.get_user_newsletter_opt_in(&principal.username).unwrap_or(false);
    let must_enable_totp = role == "admin" && !totp_enabled;
    Ok(Json(serde_json::json!({
        "must_change_password": must_change,
        "totp_enabled": totp_enabled,
        "username": principal.username,
        "role": role,
        "email": email,
        "newsletter_opt_in": newsletter_opt_in,
        "signin_code_enabled": !signin_code_disabled(&state),
        "must_enable_totp": must_enable_totp,
        "backup_codes_remaining": backup_codes_remaining,
    })))
}

pub(crate) async fn handle_change_password(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;

    if req.new_password.len() < 8 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Password must be at least 8 characters"));
    }

    let hash = {
        let db = state.db.lock();
        db.get_user_password_hash(&principal.username)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };

    if !verify_password(&req.current_password, &hash).await? {
        return Err(error_response(StatusCode::UNAUTHORIZED, "Current password is incorrect"));
    }

    let new_hash = hash_password(&req.new_password).await?;
    {
        let db = state.db.lock();
        db.update_user_password(&principal.username, &new_hash)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    }

    // The password change bumped token_version, revoking every outstanding
    // session (including this one) - hand back a fresh token so the caller
    // stays signed in.
    let device_label = summarize_user_agent(
        headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
    );
    let token = create_session_jwt(&state, &principal.username, &device_label, client_ip(peer, &headers))?;
    Ok(Json(serde_json::json!({ "status": "OK", "token": token })))
}

pub(crate) async fn handle_forgot_password(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ForgotPasswordRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let ip = client_ip(peer, &headers);
    check_login_rate_limit(&state, ip)?;

    // Generic OK response - never leak whether identifier/email/SMTP are set up.
    let ok = || Json(serde_json::json!({ "status": "OK" }));

    let identifier = req.identifier.trim().to_string();
    if identifier.is_empty() {
        return Ok(ok());
    }
    if signin_code_disabled(&state) {
        return Ok(ok());
    }

    // Resolve identifier → (username, email). Anything containing '@' is
    // treated as an email; otherwise as a username.
    let (username, email_addr) = {
        let db = state.db.lock();
        // Exact username wins (usernames can themselves be email addresses).
        let resolved = if db.user_exists(&identifier).unwrap_or(false) {
            Some(identifier.clone())
        } else if identifier.contains('@') {
            db.find_unique_username_by_email(&identifier).ok().flatten()
        } else {
            None
        };
        let Some(uname) = resolved else { return Ok(ok()); };
        let email = db.get_user_email(&uname).ok().flatten();
        (uname, email)
    };
    let Some(email_addr) = email_addr else {
        return Ok(ok());
    };

    let raw_token = random_magic_token();
    let token_hash = hash_token(&raw_token);
    {
        let db = state.db.lock();
        let _ = db.purge_old_login_tokens();
        db.insert_password_reset_token(
            &token_hash,
            &username,
            PASSWORD_RESET_TTL_MINUTES * 60,
        )
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    }

    let link = format!(
        "{}/#/reset/{}",
        state.magic_link_base_url.trim_end_matches('/'),
        raw_token
    );
    let email_service = state.email.clone().expect("checked above");
    let to = email_addr.clone();
    let uname = username.clone();
    let ip_str = ip.to_string();
    tokio::spawn(async move {
        if let Err(e) = email_service
            .send_password_reset(&to, &uname, &link, PASSWORD_RESET_TTL_MINUTES, &ip_str)
            .await
        {
            log::error!("Failed to send password-reset email to {}: {:#}", to, e);
        }
    });

    Ok(ok())
}

pub(crate) async fn handle_reset_password_submit(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ResetPasswordSubmitRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    if req.new_password.len() < 8 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Password must be at least 8 characters"));
    }
    let token_hash = hash_token(&req.token);
    let new_hash = hash_password(&req.new_password).await?;

    let (username, role) = {
        let db = state.db.lock();
        let username = db
            .consume_password_reset_token(&token_hash)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "Link is invalid, already used, or expired"))?;
        db.update_user_password(&username, &new_hash)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        // The link came from the user's inbox, so email control is proven -
        // register the device and sign them in directly, exactly like
        // magic-login. Without this, invitees set a password and are then
        // dumped on the login form for an immediate re-type.
        if !req.device_fp.is_empty() {
            let _ = db.register_device(
                &username,
                &req.device_fp,
                &summarize_user_agent(&req.device_label),
            );
        }
        let role = db.get_user_role(&username).unwrap_or_else(|_| "user".into());
        (username, role)
    };

    let jwt = create_session_jwt(
        &state,
        &username,
        &summarize_user_agent(&req.device_label),
        client_ip(peer, &headers),
    )?;
    Ok(Json(serde_json::json!({
        "status": "OK",
        "token": jwt,
        "role": role,
        "username": username,
    })))
}

pub(crate) async fn handle_setup_2fa(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let secret_bytes: [u8; 20] = rand::thread_rng().gen();
    let secret = Secret::Raw(secret_bytes.to_vec());
    let secret_b32 = secret.to_encoded().to_string();

    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes.to_vec(),
        Some("Susi License Server".into()), principal.username.clone().into())
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let qr_code = totp
        .get_qr_base64()
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let db = state.db.lock();
    db.set_user_totp_secret(&principal.username, &secret_b32)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({
        "secret": secret_b32,
        "qr_code": format!("data:image/png;base64,{}", qr_code),
        "otpauth_uri": totp.get_url()
    })))
}

pub(crate) async fn handle_verify_2fa(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<TotpCodeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;

    let db = state.db.lock();
    let secret_b32 = db
        .get_user_totp_secret(&principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, "No 2FA setup in progress"))?;

    let secret = Secret::Encoded(secret_b32)
        .to_bytes()
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret,
        Some("Susi License Server".into()), principal.username.clone().into())
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    if !totp.check_current(&req.totp_code).unwrap_or(false) {
        return Err(error_response(StatusCode::BAD_REQUEST, "Invalid TOTP code"));
    }

    db.enable_user_totp(&principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    drop(db);

    // Generate fresh backup codes atomically with enable - the user should
    // see them once, right now, and have no chance of losing access later
    // because they never saved them.
    let raw_codes = generate_backup_codes(8);
    let mut hashes = Vec::with_capacity(raw_codes.len());
    for c in &raw_codes {
        hashes.push(hash_backup_code(c)?);
    }
    {
        let db = state.db.lock();
        db.replace_backup_codes(&principal.username, &hashes)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    }

    audit(&state, &principal.username, "auth.2fa_enabled", &principal.username, "");
    let display_codes: Vec<String> =
        raw_codes.iter().map(|c| format_backup_code_for_display(c)).collect();
    Ok(Json(serde_json::json!({
        "status": "OK",
        "backup_codes": display_codes,
    })))
}

pub(crate) async fn handle_disable_2fa(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<TotpCodeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;

    let db = state.db.lock();
    let secret_b32 = db
        .get_user_totp_secret(&principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, "2FA is not enabled"))?;

    let secret = Secret::Encoded(secret_b32)
        .to_bytes()
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret,
        Some("Susi License Server".into()), principal.username.clone().into())
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    if !totp.check_current(&req.totp_code).unwrap_or(false) {
        return Err(error_response(StatusCode::UNAUTHORIZED, "Invalid TOTP code"));
    }

    db.disable_user_totp(&principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    // Wipe backup codes too - they were bound to the (now gone) 2FA factor.
    let _ = db.clear_backup_codes(&principal.username);

    audit_db(&db, &principal.username, "auth.2fa_disabled", &principal.username, "");
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

pub(crate) async fn handle_regenerate_backup_codes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<RegenerateBackupCodesRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;

    let (hash, totp_enabled) = {
        let db = state.db.lock();
        let hash = db
            .get_user_password_hash(&principal.username)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        let totp_enabled = db.user_totp_enabled(&principal.username).unwrap_or(false);
        (hash, totp_enabled)
    };
    if !verify_password(&req.current_password, &hash).await? {
        return Err(error_response(StatusCode::UNAUTHORIZED, "Password is incorrect"));
    }
    if !totp_enabled {
        return Err(error_response(StatusCode::BAD_REQUEST, "Enable 2FA first"));
    }

    let raw_codes = generate_backup_codes(8);
    let mut hashes = Vec::with_capacity(raw_codes.len());
    for c in &raw_codes {
        hashes.push(hash_backup_code(c)?);
    }
    {
        let db = state.db.lock();
        db.replace_backup_codes(&principal.username, &hashes)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    }

    let display_codes: Vec<String> =
        raw_codes.iter().map(|c| format_backup_code_for_display(c)).collect();
    Ok(Json(serde_json::json!({
        "status": "OK",
        "backup_codes": display_codes,
    })))
}
