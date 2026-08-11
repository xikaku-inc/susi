//! Public licensing client endpoints: activate / verify / deactivate / status.

use crate::*;

pub(crate) async fn handle_activate(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ActivateRequest>,
) -> Result<Json<susi_core::SignedLicense>, (StatusCode, Json<ErrorResponse>)> {
    check_license_api_rate_limit(&state, client_ip(peer, &headers))?;
    // Hold the lock only for the DB-bound section; release before the RSA
    // sign so the heartbeat path doesn't serialise every other request.
    let license = {
        let db = state.db.lock();

        let license = db
            .get_license_by_key(&req.license_key)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License key not found"))?;

        if license.revoked {
            return Err(error_response(StatusCode::FORBIDDEN, "License has been revoked"));
        }

        if license.is_expired() {
            return Err(error_response(StatusCode::FORBIDDEN, "License has expired"));
        }

        if license.require_signed_binary {
            // Fail closed: a license that demands a signed binary must never
            // pass because the server happens to lack a pinned CA.
            let Some(ca_der) = &state.trusted_signing_ca else {
                return Err(error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "This license requires binary signature verification, but the server has no trusted signing CA configured",
                ));
            };
            let chain = decode_cert_chain(req.signing_cert_chain.as_deref())?;
            if !verify_chain_to_ca(&chain, ca_der) {
                return Err(error_response(
                    StatusCode::FORBIDDEN,
                    "Binary signing certificate chain does not terminate at the trusted CA",
                ));
            }
        }

        // Block auto-reactivation if this machine was removed by an admin within
        // the tombstone window. Without this, a running client re-adds itself on
        // the next startup and the admin's removal effectively never sticks.
        if let Some(expires_at) = db
            .machine_tombstone_expires_at(&license.id, &req.machine_code)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        {
            let remaining = (expires_at - Utc::now()).num_minutes().max(0);
            return Err(error_response(
                StatusCode::FORBIDDEN,
                &format!(
                    "Machine was removed by an administrator; re-activation is blocked for {} more minutes",
                    remaining
                ),
            ));
        }

        if !license.is_machine_activated(&req.machine_code) && !license.can_add_machine() {
            return Err(error_response(
                StatusCode::FORBIDDEN,
                &format!("Machine limit reached (max {})", license.max_machines),
            ));
        }

        let name = if req.friendly_name.is_empty() {
            "Unknown".to_string()
        } else {
            req.friendly_name.clone()
        };

        let lease_expires = compute_lease_expires(&license);
        db.add_machine_activation(&license.id, &req.machine_code, &name, lease_expires)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

        db.get_license_by_key(&req.license_key)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .unwrap()
    };

    let payload = license.to_payload_for(Some(&req.machine_code));
    let signed = sign_license(&state.private_key, &payload)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(signed))
}

pub(crate) async fn handle_verify(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<susi_core::SignedLicense>, (StatusCode, Json<ErrorResponse>)> {
    check_license_api_rate_limit(&state, client_ip(peer, &headers))?;
    let license = {
        let db = state.db.lock();

        let license = db
            .get_license_by_key(&req.license_key)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License key not found"))?;

        if license.revoked {
            return Err(error_response(StatusCode::FORBIDDEN, "License has been revoked"));
        }

        if license.is_expired() {
            return Err(error_response(StatusCode::FORBIDDEN, "License has expired"));
        }

        if license.require_signed_binary {
            // Fail closed: a license that demands a signed binary must never
            // pass because the server happens to lack a pinned CA.
            let Some(ca_der) = &state.trusted_signing_ca else {
                return Err(error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "This license requires binary signature verification, but the server has no trusted signing CA configured",
                ));
            };
            let chain = decode_cert_chain(req.signing_cert_chain.as_deref())?;
            if !verify_chain_to_ca(&chain, ca_der) {
                return Err(error_response(
                    StatusCode::FORBIDDEN,
                    "Binary signing certificate chain does not terminate at the trusted CA",
                ));
            }
        }

        if !license.is_machine_activated(&req.machine_code) {
            return Err(error_response(
                StatusCode::FORBIDDEN,
                "Machine not authorized for this license",
            ));
        }

        // Renew the lease on verify (acts as heartbeat)
        if license.uses_leases() {
            let lease_expires = compute_lease_expires(&license);
            let activation = license.machines.iter().find(|m| m.machine_code == req.machine_code);
            let name = activation.map(|a| a.friendly_name.as_str()).unwrap_or("Unknown");
            db.add_machine_activation(&license.id, &req.machine_code, name, lease_expires)
                .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        }

        // Re-fetch to get updated lease.
        db.get_license_by_key(&req.license_key)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .unwrap()
    };

    let payload = license.to_payload_for(Some(&req.machine_code));
    let signed = sign_license(&state.private_key, &payload)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(signed))
}

pub(crate) async fn handle_deactivate(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<DeactivateRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    check_license_api_rate_limit(&state, client_ip(peer, &headers))?;
    let db = state.db.lock();

    let license = db
        .get_license_by_key(&req.license_key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License key not found"))?;

    db.remove_machine_activation(&license.id, &req.machine_code)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "deactivated" })))
}

pub(crate) async fn handle_license_status(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<Json<PublicLicenseStatus>, (StatusCode, Json<ErrorResponse>)> {
    // The license key in the path is the credential: 100 bits of entropy,
    // same bearer semantics as activate/verify. The per-IP rate limit above
    // is what makes enumeration impractical. (Deployed FusionHub clients
    // call this with the bare URL, so no extra header can be demanded.)
    check_license_api_rate_limit(&state, client_ip(peer, &headers))?;

    let db = state.db.lock();

    let license = db
        .get_license_by_key(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License key not found"))?;

    let now = Utc::now();
    Ok(Json(PublicLicenseStatus {
        license_key: license.license_key.clone(),
        product: license.product.clone(),
        customer: license.customer.clone(),
        expires: license
            .expires
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "perpetual".to_string()),
        features: license.features.clone(),
        max_machines: license.max_machines,
        active_machines: license
            .machines
            .iter()
            .filter(|m| m.is_lease_active(now))
            .map(|m| PublicMachineSummary {
                machine_code: m.machine_code.clone(),
                friendly_name: m.friendly_name.clone(),
                lease_expires_at: m.lease_expires_at.map(|dt| dt.to_rfc3339()),
                lease_active: m.is_lease_active(now),
            })
            .collect(),
        revoked: license.revoked,
    }))
}
