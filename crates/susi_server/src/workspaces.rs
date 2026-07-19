//! Workspace, member, config-revision, recording, federation, and graph handlers.

use crate::*;

pub(crate) async fn handle_create_workspace(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateWorkspaceRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    if req.name.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Workspace name is required"));
    }

    let id = uuid::Uuid::new_v4().to_string();
    let db = state.db.lock();
    db.create_workspace(&id, &req.name, &req.product, &req.description, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    log::info!("Workspace '{}' ({}) created by {}", req.name, id, principal.username);
    audit_db(&db, &principal.username, "workspace.create", &id, &format!("name={}", req.name));

    Ok((StatusCode::CREATED, Json(serde_json::json!({
        "id": id,
        "name": req.name,
        "product": req.product,
        "description": req.description,
        "created_by": principal.username,
    }))))
}

pub(crate) async fn handle_list_workspaces(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock();
    let is_admin = db.get_user_role(&principal.username)
        .map(|r| r == "admin")
        .unwrap_or(false);
    let rows = if is_admin {
        db.list_all_workspaces()
    } else {
        db.list_workspaces_for_user(&principal.username)
    }
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let workspaces: Vec<_> = rows.iter().map(|(id, name, product, desc, created_by, created_at, updated_at)| {
        serde_json::json!({
            "id": id,
            "name": name,
            "product": product,
            "description": desc,
            "created_by": created_by,
            "created_at": created_at,
            "updated_at": updated_at,
        })
    }).collect();

    Ok(Json(serde_json::json!({ "workspaces": workspaces })))
}

pub(crate) async fn handle_get_workspace(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock();
    db.workspace_access(&id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;

    let ws = db.get_workspace(&id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Workspace not found"))?;

    let members = db.list_workspace_members(&id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({
        "id": ws.0,
        "name": ws.1,
        "product": ws.2,
        "description": ws.3,
        "created_by": ws.4,
        "created_at": ws.5,
        "updated_at": ws.6,
        "members": members.iter().map(|(u, a)| serde_json::json!({
            "username": u, "added_at": a,
        })).collect::<Vec<_>>(),
    })))
}

pub(crate) async fn handle_update_workspace(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<UpdateWorkspaceRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock();
    db.workspace_access(&id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;

    // Re-assigning the "created by" attribution is admin-only (the field is
    // mostly cosmetic but we want admins to be the gate). Validate the target
    // user exists before persisting.
    let new_created_by = match req.created_by.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(target) => {
            let is_admin = db.get_user_role(&principal.username).map(|r| r == "admin").unwrap_or(false);
            if !is_admin {
                return Err(error_response(StatusCode::FORBIDDEN, "Only site admins can change 'created by'"));
            }
            if !db.user_exists(target).map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))? {
                return Err(error_response(StatusCode::BAD_REQUEST, "Target user does not exist"));
            }
            Some(target.to_string())
        }
        None => None,
    };

    db.update_workspace(&id, &req.name, &req.product, &req.description, new_created_by.as_deref())
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

pub(crate) async fn handle_delete_workspace(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock();
    db.delete_workspace(&id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    log::info!("Workspace {} deleted by {}", id, principal.username);
    audit_db(&db, &principal.username, "workspace.delete", &id, "");
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

pub(crate) async fn handle_add_workspace_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(req): Json<AddMemberRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock();

    if !db.user_exists(&req.username).unwrap_or(false) {
        return Err(error_response(StatusCode::NOT_FOUND, "User does not exist"));
    }

    db.add_workspace_member(&workspace_id, &req.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    audit_db(&db, &principal.username, "workspace.add_member", &workspace_id, &req.username);
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

pub(crate) async fn handle_remove_workspace_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, username)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock();
    db.remove_workspace_member(&workspace_id, &username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    audit_db(&db, &principal.username, "workspace.remove_member", &workspace_id, &username);
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

pub(crate) async fn handle_push_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(req): Json<PushConfigRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock();
    db.workspace_access(&workspace_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;

    // Validate JSON
    serde_json::from_str::<serde_json::Value>(&req.config_json)
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {}", e)))?;

    let id = db.push_config_revision(&workspace_id, &req.config_json, &req.name, &req.description, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok((StatusCode::CREATED, Json(serde_json::json!({
        "id": id,
        "workspace_id": workspace_id,
    }))))
}

pub(crate) async fn handle_list_configs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock();
    db.workspace_access(&workspace_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;

    let rows = db.list_config_revisions(&workspace_id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let configs: Vec<_> = rows.iter().map(|(id, name, desc, author, created_at)| {
        serde_json::json!({
            "id": id,
            "name": name,
            "description": desc,
            "author": author,
            "created_at": created_at,
        })
    }).collect();

    Ok(Json(serde_json::json!({ "configs": configs })))
}

pub(crate) async fn handle_get_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, config_id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock();
    db.workspace_access(&workspace_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;

    let rev = db.get_config_revision(&workspace_id, config_id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Config revision not found"))?;

    Ok(Json(serde_json::json!({
        "id": rev.0,
        "config_json": rev.1,
        "name": rev.2,
        "description": rev.3,
        "author": rev.4,
        "created_at": rev.5,
    })))
}

pub(crate) async fn handle_get_latest_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock();
    db.workspace_access(&workspace_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;

    let rev = db.get_latest_config_revision(&workspace_id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "No config revisions in this workspace"))?;

    Ok(Json(serde_json::json!({
        "id": rev.0,
        "config_json": rev.1,
        "name": rev.2,
        "description": rev.3,
        "author": rev.4,
        "created_at": rev.5,
    })))
}

pub(crate) async fn handle_update_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, config_id)): Path<(String, i64)>,
    Json(req): Json<UpdateConfigRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock();
    db.workspace_access(&workspace_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;

    let updated = db.update_config_revision(&workspace_id, config_id, &req.name, &req.description, req.config_json.as_deref())
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    if !updated {
        return Err(error_response(StatusCode::NOT_FOUND, "Config revision not found"));
    }

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

pub(crate) async fn handle_delete_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, config_id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock();
    db.workspace_access(&workspace_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;

    let deleted = db.delete_config_revision(&workspace_id, config_id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    if !deleted {
        return Err(error_response(StatusCode::NOT_FOUND, "Config revision not found"));
    }

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

pub(crate) async fn handle_init_recording(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(req): Json<InitRecordingRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    assert_workspace_member(&state, &workspace_id, &principal)?;

    let s3 = state.s3.as_ref().ok_or_else(s3_unavailable)?;

    let safe_name = sanitize_filename(&req.file_name);
    let uuid = uuid::Uuid::new_v4().to_string();
    // workspace_id is the prefix the IAM policy is scoped to — keeping it
    // first means a misconfigured client can't write outside its workspace
    // even with a leaked presigned URL.
    let s3_key = format!("workspaces/{}/recordings/{}-{}", workspace_id, uuid, safe_name);

    let upload_url = s3
        .presign_put(&s3_key, RECORDING_CONTENT_TYPE, RECORDING_PUT_TTL)
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let id = {
        let db = state.db.lock();
        db.create_recording(&workspace_id, &s3_key, &safe_name, &req.description, &principal.username)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };

    Ok((StatusCode::CREATED, Json(serde_json::json!({
        "id": id,
        "s3_key": s3_key,
        "upload_url": upload_url,
        "content_type": RECORDING_CONTENT_TYPE,
        "expires_in_secs": RECORDING_PUT_TTL.as_secs(),
    }))))
}

pub(crate) async fn handle_complete_recording(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, recording_id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    assert_workspace_member(&state, &workspace_id, &principal)?;

    let s3 = state.s3.as_ref().ok_or_else(s3_unavailable)?;

    // Look up the row to learn the s3_key.
    let row = {
        let db = state.db.lock();
        db.get_recording(&workspace_id, recording_id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Recording not found"))?
    };

    let size = s3
        .head_size(&row.s3_key)
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::CONFLICT, "Object not yet present in S3"))?;

    {
        let db = state.db.lock();
        let ok = db.complete_recording(&workspace_id, recording_id, size)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        if !ok {
            return Err(error_response(StatusCode::NOT_FOUND, "Recording not found"));
        }
    }

    Ok(Json(serde_json::json!({
        "id": recording_id,
        "file_size": size,
        "status": "uploaded",
    })))
}

pub(crate) async fn handle_list_recordings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    assert_workspace_member(&state, &workspace_id, &principal)?;

    let rows = {
        let db = state.db.lock();
        db.list_recordings(&workspace_id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };

    Ok(Json(serde_json::json!({ "recordings": rows })))
}

pub(crate) async fn handle_get_recording_download(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, recording_id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    assert_workspace_member(&state, &workspace_id, &principal)?;

    let s3 = state.s3.as_ref().ok_or_else(s3_unavailable)?;

    let row = {
        let db = state.db.lock();
        db.get_recording(&workspace_id, recording_id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Recording not found"))?
    };
    if row.status != "uploaded" {
        return Err(error_response(StatusCode::CONFLICT, "Recording upload not complete"));
    }

    let url = s3
        .presign_get(&row.s3_key, Some(&row.file_name), RECORDING_GET_TTL)
        .await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({
        "id": row.id,
        "file_name": row.file_name,
        "file_size": row.file_size,
        "download_url": url,
        "expires_in_secs": RECORDING_GET_TTL.as_secs(),
    })))
}

pub(crate) async fn handle_delete_recording(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, recording_id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    assert_workspace_member(&state, &workspace_id, &principal)?;

    // Tear down DB first to release the s3_key for cleanup; if S3 delete
    // fails the worst case is an orphan object — we log but don't surface.
    let s3_key = {
        let db = state.db.lock();
        db.delete_recording(&workspace_id, recording_id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Recording not found"))?
    };

    if let Some(s3) = state.s3.as_ref() {
        if let Err(e) = s3.delete_object(&s3_key).await {
            log::warn!("S3 delete_object failed for {}: {:#}", s3_key, e);
        }
    }

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

/// Returns the workspace's federation channel secret and the live peer list.
/// Any workspace member can read — the secret is the symmetric
/// key for the ZMQ data plane that all member fusionhubs need to participate.
pub(crate) async fn handle_get_workspace_federation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock();
    db.workspace_access(&workspace_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;

    let secret = db.get_or_create_workspace_federation_secret(&workspace_id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    let peers = db.list_workspace_peers(&workspace_id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    // Cheap version-only fetch — body is fetched separately via GET /graph
    // when the polling peer notices its `applied_graph_version` is behind.
    let graph_version = db.get_workspace_graph_version(&workspace_id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let peer_json: Vec<_> = peers.iter().map(|(host_id, url, label, network_id, registered_by, last_seen)| {
        serde_json::json!({
            "host_id": host_id,
            "url": url,
            "label": label,
            "network_id": network_id,
            "registered_by": registered_by,
            "last_seen": last_seen,
        })
    }).collect();

    Ok(Json(serde_json::json!({
        "channel_secret": secret,
        "peers": peer_json,
        // Empty string when this susi instance isn't configured with a
        // relay URL. Workspace members treat the empty string the same
        // as "field missing" and fall back to FUSIONHUB_RELAY_URL set
        // locally on each member, or "no relay" if that's also unset.
        "relay_url": state.relay_url,
        // `null` when no graph has been pushed yet (workspace is "empty").
        // Polling peers compare to their local `applied_graph_version` and
        // pull `GET /graph` whenever the susi version is newer.
        "graph_version": graph_version,
    })))
}

/// Returns the workspace's full graph + version, or 404 when no graph has been
/// pushed yet. Any workspace member can read.
pub(crate) async fn handle_get_workspace_graph(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock();
    db.workspace_access(&workspace_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;

    let row = db.get_workspace_graph(&workspace_id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Workspace has no graph yet"))?;
    let (graph_version, config_json, updated_by, updated_at) = row;
    let config: serde_json::Value = serde_json::from_str(&config_json)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("Stored graph JSON corrupt: {}", e)))?;

    Ok(Json(serde_json::json!({
        "graph_version": graph_version,
        "config": config,
        "updated_by": updated_by,
        "updated_at": updated_at,
    })))
}

/// Optimistic-lock upsert of the workspace's graph. The request body carries
/// the version the editor was loaded with; mismatch ⇒ 409 with the current
/// version so the editor can refresh + reapply.
pub(crate) async fn handle_put_workspace_graph(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(req): Json<PutGraphRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock();
    db.workspace_access(&workspace_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;

    let config_str = serde_json::to_string(&req.config)
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("config not serialisable: {}", e)))?;

    match db.upsert_workspace_graph(&workspace_id, req.expected_version, &config_str, &principal.username) {
        Ok(new_version) => Ok(Json(serde_json::json!({ "graph_version": new_version }))),
        Err(susi_core::error::LicenseError::GraphConflict { current }) => Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: format!(
                    "Graph version conflict - current is {}; reload and reapply",
                    current
                ),
            }),
        )),
        Err(e) => Err(error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
    }
}

/// Register (or refresh) a FusionHub peer for this workspace. Idempotent on
/// `(workspace_id, host_id)` — re-registration updates `url`/`label`/`last_seen`.
pub(crate) async fn handle_register_workspace_peer(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(req): Json<RegisterPeerRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    if req.host_id.trim().is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "host_id is required"));
    }
    if req.url.trim().is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "url is required"));
    }

    let db = state.db.lock();
    db.workspace_access(&workspace_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;

    db.upsert_workspace_peer(&workspace_id, &req.host_id, &req.url, &req.label, &req.network_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

/// Remove a FusionHub peer from this workspace.
pub(crate) async fn handle_delete_workspace_peer(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, host_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock();
    db.workspace_access(&workspace_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;

    let removed = db.delete_workspace_peer(&workspace_id, &host_id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Peer not registered"));
    }

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

/// Rotate the workspace's federation channel secret. Forces every connected
/// FusionHub to re-fetch on next poll and rekey. Any workspace member.
pub(crate) async fn handle_rotate_workspace_federation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock();
    db.workspace_access(&workspace_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;

    let new_secret = db.rotate_workspace_federation_secret(&workspace_id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    audit_db(&db, &principal.username, "workspace.rotate_federation", &workspace_id, "");
    Ok(Json(serde_json::json!({ "status": "OK", "channel_secret": new_secret })))
}

/// List releases visible to a workspace (workspace-specific + global).
pub(crate) async fn handle_workspace_releases(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let (rows, mut assets_by_id) = {
        let db = state.db.lock();
        db.workspace_access(&workspace_id, &principal.username)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;

        let rows = db
            .list_releases_for_workspace(&workspace_id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        let ids: Vec<i64> = rows.iter().map(|r| r.0).collect();
        let assets_by_id = db.get_assets_for_releases(&ids).unwrap_or_default();
        (rows, assets_by_id)
    };

    let mut releases = Vec::new();
    for (id, tag, name, body, prerelease, created_at) in &rows {
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

/// List doc-bearing releases scoped to a single workspace. Workspace members
/// and site admins may call this; non-members get 403. Mirrors
/// `handle_list_doc_releases` but filtered to one workspace.
pub(crate) async fn handle_list_workspace_doc_releases(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    {
        let db = state.db.lock();
        db.workspace_access(&workspace_id, &principal.username)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;
    }

    let db = state.db.lock();
    let rows = db.list_doc_releases_for_workspace(&workspace_id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    let releases: Vec<_> = rows
        .into_iter()
        .map(|(_id, tag, name, created_at, page_count)| {
            serde_json::json!({
                "tag": tag,
                "name": name,
                "published_at": created_at,
                "page_count": page_count,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "releases": releases })))
}

/// Create a workspace-scoped doc release. Site admins and workspace members
/// may call this (members author their workspace's documentation). Re-using a
/// tag that belongs to a different workspace (or to global) is rejected.
pub(crate) async fn handle_create_workspace_doc_release(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(req): Json<CreateWorkspaceDocReleaseRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    {
        let db = state.db.lock();
        db.workspace_access(&workspace_id, &principal.username)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;
    }

    let tag = req.tag.trim().to_string();
    docs::safe_tag(&tag)?;
    if tag.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Missing 'tag'"));
    }

    // Idempotent within a single workspace: if the tag already lives in this
    // workspace (e.g. created by a prior software upload), we just return the
    // existing release so the caller can attach docs. Cross-scope collisions
    // (different workspace, or a global release with the same tag) are
    // rejected — those would change ownership semantics.
    let existing_ws = {
        let db = state.db.lock();
        db.get_release_workspace_id(DEFAULT_PRODUCT, &tag)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    if let Some(ref existing) = existing_ws {
        match existing {
            Some(ws) if ws == &workspace_id => {
                let id = {
                    let db = state.db.lock();
                    db.get_release_by_product_tag(DEFAULT_PRODUCT, &tag)
                        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
                        .ok_or_else(|| error_response(StatusCode::INTERNAL_SERVER_ERROR, "Release vanished"))?
                };
                // Seeding is INSERT OR IGNORE, so calling again is a no-op
                // when user pages already exist for this release.
                docs::seed_user_docs_into_release(&state, id, DEFAULT_PRODUCT, &tag, Some(&workspace_id))?;
                return Ok(Json(serde_json::json!({
                    "tag": tag,
                    "name": req.name,
                    "workspace_id": workspace_id,
                    "id": id,
                    "already_existed": true,
                })));
            }
            _ => {
                return Err(error_response(StatusCode::CONFLICT, "Release tag already exists in another scope"));
            }
        }
    }

    let release_id = {
        let db = state.db.lock();
        db.insert_release(DEFAULT_PRODUCT, &tag, &req.name, "", false, Some(&workspace_id), "docs")
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    docs::seed_user_docs_into_release(&state, release_id, DEFAULT_PRODUCT, &tag, Some(&workspace_id))?;

    Ok(Json(serde_json::json!({
        "tag": tag,
        "name": req.name,
        "workspace_id": workspace_id,
        "id": release_id,
    })))
}
