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

    {
        let db = state.db.lock();
        db.delete_workspace(&id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    }
    // Remove the workspace's on-disk files + doc assets.
    if safe_workspace_id(&id).is_ok() {
        let _ = std::fs::remove_dir_all(std::path::Path::new(&state.data_dir).join("workspaces").join(&id));
    }

    log::info!("Workspace {} deleted by {}", id, principal.username);
    audit(&state, &principal.username, "workspace.delete", &id, "");
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
    // workspace_id is the prefix the IAM policy is scoped to - keeping it
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
    // fails the worst case is an orphan object - we log but don't surface.
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
/// Any workspace member can read - the secret is the symmetric
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
    // Cheap version-only fetch - body is fetched separately via GET /graph
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
/// `(workspace_id, host_id)` - re-registration updates `url`/`label`/`last_seen`.
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

// ---------------------------------------------------------------------------
// Workspace files: flat per-workspace file share (replaces the retired
// workspace-scoped releases). Bytes live on disk under
// data_dir/workspaces/{id}/files; any workspace member may read and write.
// ---------------------------------------------------------------------------

/// Deployed FusionHub UIs still poll this endpoint. Workspace releases were
/// folded into workspace files, so answer with an empty list instead of 404.
/// Back-compat shim: remove once fielded FusionHubs use the files endpoint.
pub(crate) async fn handle_workspace_releases(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    assert_workspace_member(&state, &workspace_id, &principal)?;
    Ok(Json(serde_json::json!({ "releases": [] })))
}

pub(crate) fn workspace_files_dir(state: &AppState, workspace_id: &str) -> std::path::PathBuf {
    std::path::Path::new(&state.data_dir)
        .join("workspaces")
        .join(workspace_id)
        .join("files")
}

/// Workspace ids are server-minted UUIDs, but they arrive as a path segment -
/// reject anything that could escape the workspaces directory before using
/// one in a filesystem path.
pub(crate) fn safe_workspace_id(id: &str) -> Result<&str, (StatusCode, Json<ErrorResponse>)> {
    if id.is_empty()
        || id.contains('/')
        || id.contains('\\')
        || id.contains('\0')
        || id == "."
        || id == ".."
    {
        return Err(error_response(StatusCode::BAD_REQUEST, "Invalid workspace id"));
    }
    Ok(id)
}

pub(crate) async fn handle_list_workspace_files(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    assert_workspace_member(&state, &workspace_id, &principal)?;

    let rows = {
        let db = state.db.lock();
        db.list_workspace_files(&workspace_id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    let files: Vec<_> = rows
        .into_iter()
        .map(|(name, size, author, created_at)| {
            serde_json::json!({
                "name": name,
                "size": size,
                "author": author,
                "created_at": created_at,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "files": files })))
}

/// Upload one or more files (repeated multipart `file` fields). Re-uploading
/// an existing name overwrites it.
pub(crate) async fn handle_upload_workspace_files(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    assert_workspace_member(&state, &workspace_id, &principal)?;
    safe_workspace_id(&workspace_id)?;

    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    while let Some(field) = multipart.next_field().await
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("Multipart error: {}", e)))?
    {
        if field.name() == Some("file") {
            let file_name = field.file_name().unwrap_or("unknown").to_string();
            docs::safe_filename(&file_name)?;
            let data = field.bytes().await
                .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("File read error: {}", e)))?;
            files.push((file_name, data.to_vec()));
        }
    }
    if files.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "No files uploaded"));
    }

    let dir = workspace_files_dir(&state, &workspace_id);
    std::fs::create_dir_all(&dir)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("Cannot create dir: {}", e)))?;

    let mut names = Vec::new();
    for (file_name, data) in &files {
        std::fs::write(dir.join(file_name), data)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("Write error: {}", e)))?;
        let db = state.db.lock();
        db.upsert_workspace_file(&workspace_id, file_name, data.len() as u64, &principal.username)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        names.push(file_name.clone());
    }

    audit(&state, &principal.username, "workspace.file_upload", &workspace_id, &names.join(","));
    Ok(Json(serde_json::json!({ "status": "OK", "files": names })))
}

pub(crate) async fn handle_download_workspace_file(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, file_name)): Path<(String, String)>,
    Query(q): Query<docs::AssetAuthQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // Browser <a href> downloads can't set an Authorization header, so accept
    // the JWT via ?auth= as well - same fallback the doc asset endpoint uses.
    let auth_headers = docs::headers_with_query_auth(&headers, &q);
    let principal = validate_principal(&auth_headers, &state)?;
    require_password_changed(&state, &principal)?;
    assert_workspace_member(&state, &workspace_id, &principal)?;
    safe_workspace_id(&workspace_id)?;
    docs::safe_filename(&file_name)?;

    let path = workspace_files_dir(&state, &workspace_id).join(&file_name);
    let file = tokio::fs::File::open(&path)
        .await
        .map_err(|_| error_response(StatusCode::NOT_FOUND, "File not found"))?;
    let metadata = file
        .metadata()
        .await
        .map_err(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "Read error"))?;

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(header::CONTENT_TYPE, "application/octet-stream".parse().unwrap());
    resp_headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{}\"", file_name).parse().unwrap(),
    );
    resp_headers.insert(header::CONTENT_LENGTH, metadata.len().into());
    let stream = tokio_util::io::ReaderStream::new(file);
    Ok((resp_headers, axum::body::Body::from_stream(stream)))
}

pub(crate) async fn handle_delete_workspace_file(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, file_name)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    assert_workspace_member(&state, &workspace_id, &principal)?;
    safe_workspace_id(&workspace_id)?;
    docs::safe_filename(&file_name)?;

    let removed = {
        let db = state.db.lock();
        db.delete_workspace_file(&workspace_id, &file_name)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    let _ = std::fs::remove_file(workspace_files_dir(&state, &workspace_id).join(&file_name));
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "File not found"));
    }
    audit(&state, &principal.username, "workspace.file_delete", &workspace_id, &file_name);
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

// ---------------------------------------------------------------------------
// One-time startup migration: fold the retired workspace-scoped releases into
// workspace files (binary assets) and workspace docs (pages + assets), then
// delete the release rows. Idempotent - a run with no scoped rows is a no-op.
// ---------------------------------------------------------------------------

pub(crate) fn migrate_workspace_releases(state: &AppState) {
    let scoped = {
        let db = state.db.lock();
        match db.list_workspace_scoped_releases() {
            Ok(v) => v,
            Err(e) => {
                log::error!("Workspace release migration: listing failed: {}", e);
                return;
            }
        }
    };
    if scoped.is_empty() {
        return;
    }
    log::info!("Migrating {} workspace-scoped release(s) into workspace files/docs", scoped.len());

    // Newest first (list is ordered id DESC): on name/slug collisions within a
    // workspace the newest release wins; older files fall back to a tag prefix.
    for (release_id, tag, product, ws_id, created_at) in scoped {
        let res = migrate_one_workspace_release(state, release_id, &tag, &product, &ws_id, &created_at);
        if let Err(e) = res {
            log::error!("Workspace release migration: {} ({}): {}", tag, ws_id, e);
        }
    }
}

fn migrate_one_workspace_release(
    state: &AppState,
    release_id: i64,
    tag: &str,
    product: &str,
    ws_id: &str,
    created_at: &str,
) -> Result<(), String> {
    if safe_workspace_id(ws_id).is_err() || docs::safe_tag(tag).is_err() || docs::safe_product(product).is_err() {
        return Err("unsafe path component".into());
    }

    // Binary assets -> workspace files (move on disk, keep the release date).
    let assets = {
        let db = state.db.lock();
        db.get_release_assets(release_id).map_err(|e| e.to_string())?
    };
    let files_dir = workspace_files_dir(state, ws_id);
    if !assets.is_empty() {
        std::fs::create_dir_all(&files_dir).map_err(|e| e.to_string())?;
    }
    let src_dir = crate::release_tag_dir(state, product, tag);
    for (name, size) in &assets {
        let taken = {
            let db = state.db.lock();
            db.workspace_file_exists(ws_id, name).map_err(|e| e.to_string())?
        };
        let dst_name = if taken { format!("{}-{}", tag, name) } else { name.clone() };
        let src = src_dir.join(name);
        let dst = files_dir.join(&dst_name);
        if src.exists() {
            if let Err(e) = std::fs::rename(&src, &dst) {
                log::warn!("Migration: move {} -> {} failed: {}", src.display(), dst.display(), e);
                continue;
            }
        }
        let db = state.db.lock();
        db.migrate_workspace_file_row(ws_id, &dst_name, *size, created_at)
            .map_err(|e| e.to_string())?;
    }

    // Doc pages + assets -> workspace docs (rows via SQL, asset files on disk).
    let doc_asset_names = {
        let db = state.db.lock();
        db.migrate_release_docs_to_workspace(release_id, ws_id)
            .map_err(|e| e.to_string())?
    };
    if !doc_asset_names.is_empty() {
        let dst_dir = docs::ws_doc_assets_dir(state, ws_id);
        std::fs::create_dir_all(&dst_dir).map_err(|e| e.to_string())?;
        let src_assets = docs::release_assets_dir(state, product, tag);
        for name in &doc_asset_names {
            let src = src_assets.join(name);
            let dst = dst_dir.join(name);
            if src.exists() && !dst.exists() {
                if let Err(e) = std::fs::copy(&src, &dst) {
                    log::warn!("Migration: copy doc asset {} failed: {}", name, e);
                }
            }
        }
    }

    // Drop the release row (children cascade) and its leftover directories.
    {
        let db = state.db.lock();
        db.delete_release_by_id(release_id).map_err(|e| e.to_string())?;
    }
    let _ = std::fs::remove_dir_all(&src_dir);
    let _ = std::fs::remove_dir_all(docs::release_assets_dir(state, product, tag));
    log::info!("Migrated workspace release {} -> workspace {}", tag, ws_id);
    Ok(())
}
