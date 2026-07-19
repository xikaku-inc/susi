//! Admin license management + self-serve portal handlers.

use crate::*;

pub(crate) async fn handle_list_licenses(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<LicenseSummary>>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock();
    let licenses = db
        .list_licenses()
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let summaries: Vec<LicenseSummary> = licenses
        .iter()
        .map(|l| license_to_summary(l, db.list_license_users(&l.id).unwrap_or_default()))
        .collect();
    Ok(Json(summaries))
}

pub(crate) async fn handle_get_license(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<Json<LicenseSummary>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock();
    let license = db
        .get_license_by_key(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License key not found"))?;

    let users = db.list_license_users(&license.id).unwrap_or_default();
    Ok(Json(license_to_summary(&license, users)))
}

pub(crate) async fn handle_create_license(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateLicenseRequest>,
) -> Result<(StatusCode, Json<LicenseSummary>), (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let expires_dt = if req.perpetual {
        None
    } else {
        Some(match (req.expires, req.days) {
            (Some(date_str), _) => {
                let date = NaiveDate::parse_from_str(&date_str, "%Y-%m-%d")
                    .map_err(|_| error_response(StatusCode::BAD_REQUEST, &format!("Invalid date format: {}. Use YYYY-MM-DD.", date_str)))?;
                date.and_hms_opt(23, 59, 59)
                    .unwrap()
                    .and_utc()
            }
            (_, Some(d)) => Utc::now() + Duration::days(d),
            _ => Utc::now() + Duration::days(365),
        })
    };

    let mut license = License::new(
        req.product,
        req.customer,
        expires_dt,
        req.features,
        req.max_machines,
    );
    license.lease_duration_hours = req.lease_duration_hours;
    license.lease_grace_hours = req.lease_grace_hours;
    license.require_signed_binary = req.require_signed_binary;

    let db = state.db.lock();
    for username in &req.assign_to {
        if !db.user_exists(username).unwrap_or(false) {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                &format!("Cannot assign license: user '{}' does not exist", username),
            ));
        }
    }
    db.insert_license(&license)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    for username in &req.assign_to {
        db.assign_license_user(&license.id, username)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    }

    audit_db(
        &db,
        &principal.username,
        "license.create",
        &license.license_key,
        &format!("product={} customer={}", license.product, license.customer),
    );
    let users = db.list_license_users(&license.id).unwrap_or_default();
    Ok((StatusCode::CREATED, Json(license_to_summary(&license, users))))
}

pub(crate) async fn handle_revoke_license(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock();
    let revoked = db
        .revoke_license(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    if !revoked {
        return Err(error_response(StatusCode::NOT_FOUND, "License key not found"));
    }

    audit_db(&db, &principal.username, "license.revoke", &key, "");
    Ok(Json(serde_json::json!({ "status": "revoked" })))
}

pub(crate) async fn handle_delete_license(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock();
    let deleted = db
        .delete_license(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    if !deleted {
        return Err(error_response(StatusCode::NOT_FOUND, "License key not found"));
    }

    audit_db(&db, &principal.username, "license.delete", &key, "");
    Ok(Json(serde_json::json!({ "status": "deleted" })))
}

pub(crate) async fn handle_update_license(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Json(req): Json<UpdateLicenseRequest>,
) -> Result<Json<LicenseSummary>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock();
    let license = db
        .get_license_by_key(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License key not found"))?;

    let customer = req.customer.as_deref().unwrap_or(&license.customer);
    let product = req.product.as_deref().unwrap_or(&license.product);
    let features = req.features.as_deref().unwrap_or(&license.features);
    let max_machines = req.max_machines.unwrap_or(license.max_machines);

    let expires_rfc = if let Some(ref exp) = req.expires {
        if exp == "perpetual" {
            None
        } else {
            let date = NaiveDate::parse_from_str(exp, "%Y-%m-%d")
                .map_err(|_| error_response(StatusCode::BAD_REQUEST, &format!("Invalid date: {}. Use YYYY-MM-DD.", exp)))?;
            Some(date.and_hms_opt(23, 59, 59).unwrap().and_utc().to_rfc3339())
        }
    } else {
        license.expires.map(|dt| dt.to_rfc3339())
    };

    let require_signed_binary = req.require_signed_binary.unwrap_or(license.require_signed_binary);
    db.update_license(&key, customer, product, expires_rfc.as_deref(), features, max_machines, require_signed_binary)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let updated = db
        .get_license_by_key(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License not found after update"))?;

    audit_db(&db, &principal.username, "license.update", &key, "");
    let users = db.list_license_users(&updated.id).unwrap_or_default();
    Ok(Json(license_to_summary(&updated, users)))
}

pub(crate) async fn handle_export_license(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Json(req): Json<ExportRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    export_license_file(&state, &key, &req)
}

pub(crate) async fn handle_export_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Json(req): Json<ExportTokenRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let usb_serial = req.usb_serial.trim().to_string();
    if usb_serial.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "USB serial is required"));
    }

    let db = state.db.lock();
    let license = db
        .get_license_by_key(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License key not found"))?;

    if license.revoked {
        return Err(error_response(StatusCode::FORBIDDEN, "License has been revoked"));
    }
    if license.is_expired() {
        return Err(error_response(StatusCode::FORBIDDEN, "License has expired"));
    }

    let activation_code = format!("usb:{}", usb_serial);

    if !license.is_machine_activated(&activation_code) && !license.can_add_machine() {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            &format!("Machine limit reached (max {})", license.max_machines),
        ));
    }

    let name = if req.friendly_name.is_empty() {
        format!("USB Token: {}", usb_serial)
    } else {
        req.friendly_name.clone()
    };

    db.add_machine_activation(&license.id, &activation_code, &name, None)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let payload = susi_core::LicensePayload {
        id: license.id.clone(),
        product: license.product.clone(),
        customer: license.customer.clone(),
        license_key: license.license_key.clone(),
        created: license.created,
        expires: license.expires,
        features: license.features.clone(),
        machine_codes: vec![activation_code],
        lease_expires: None,
        lease_grace_period: None,
        require_signed_binary: license.require_signed_binary
    };

    let signed = sign_license(&state.private_key, &payload)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let blob = susi_core::encrypt_token(&signed, &usb_serial)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"license.bin\"",
            ),
        ],
        blob,
    ))
}

pub(crate) async fn handle_deactivate_machine(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((key, machine_code)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock();
    let license = db
        .get_license_by_key(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License key not found"))?;

    db.remove_machine_activation(&license.id, &machine_code)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    // Admin removals are "sticky": the client can't silently re-add itself
    // for a while. Client-initiated /deactivate does NOT tombstone, so a user
    // who intentionally resets their own install can immediately re-activate.
    db.add_machine_tombstone(&license.id, &machine_code, TOMBSTONE_TTL_HOURS)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({
        "status": "deactivated",
        "tombstone_hours": TOMBSTONE_TTL_HOURS,
    })))
}

/// Admin escape hatch: clear a tombstone so the machine can re-activate
/// immediately after an accidental removal.
pub(crate) async fn handle_clear_machine_tombstone(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((key, machine_code)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock();
    let license = db
        .get_license_by_key(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License key not found"))?;

    db.clear_machine_tombstone(&license.id, &machine_code)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "cleared" })))
}

pub(crate) async fn handle_assign_license_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Json(req): Json<AssignLicenseUserRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock();
    let license = db
        .get_license_by_key(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License key not found"))?;
    let username = req.username.trim();
    if !db.user_exists(username).unwrap_or(false) {
        return Err(error_response(StatusCode::NOT_FOUND, "User not found"));
    }
    db.assign_license_user(&license.id, username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    audit_db(&db, &principal.username, "license.assign_user", &key, username);
    let users = db.list_license_users(&license.id).unwrap_or_default();
    Ok(Json(serde_json::json!({ "status": "OK", "users": users })))
}

pub(crate) async fn handle_unassign_license_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((key, username)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock();
    let license = db
        .get_license_by_key(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License key not found"))?;
    db.unassign_license_user(&license.id, &username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    audit_db(&db, &principal.username, "license.unassign_user", &key, &username);
    let users = db.list_license_users(&license.id).unwrap_or_default();
    Ok(Json(serde_json::json!({ "status": "OK", "users": users })))
}

pub(crate) async fn handle_my_licenses(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<LicenseSummary>>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;

    let db = state.db.lock();
    let licenses = db
        .list_licenses_for_user(&principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    let summaries: Vec<LicenseSummary> = licenses
        .iter()
        .map(|l| license_to_summary(l, db.list_license_users(&l.id).unwrap_or_default()))
        .collect();
    Ok(Json(summaries))
}

pub(crate) async fn handle_my_export_license(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Json(req): Json<ExportRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    {
        let db = state.db.lock();
        get_owned_license(&db, &key, &principal)?;
    }
    export_license_file(&state, &key, &req)
}

pub(crate) async fn handle_my_deactivate_machine(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((key, machine_code)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;

    let db = state.db.lock();
    let license = get_owned_license(&db, &key, &principal)?;

    db.remove_machine_activation(&license.id, &machine_code)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    // Same stickiness as the admin removal: the removed machine must not
    // silently re-add itself on its next heartbeat, otherwise "move the
    // license to a new machine" never frees the slot.
    db.add_machine_tombstone(&license.id, &machine_code, TOMBSTONE_TTL_HOURS)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({
        "status": "deactivated",
        "tombstone_hours": TOMBSTONE_TTL_HOURS,
    })))
}
