//! Per-workspace tickets: the shared record of customer-reported problems.
//!
//! Every workspace member reads and writes every ticket and comment in their
//! workspace - there are no internal-only notes, so nothing written here is
//! hidden from the customer. Site admins reach every workspace (that is what
//! `workspace_access` already grants) and additionally get a cross-workspace
//! list at `GET /api/v1/admin/tickets`.
//!
//! Destructive actions (deleting a ticket or a comment) are restricted to the
//! author or a site admin; everything else is open to any member so status
//! changes don't need an admin round-trip.
//!
//! Notification email is currently switched OFF - see `SEND_TICKET_EMAILS`.

use crate::*;

/// Master switch for ticket notification email. While `false`, no ticket
/// event (create, comment, status change) sends anything; the delivery path
/// in `notify_workspace` is kept intact and compiled, so re-enabling is a
/// one-line change plus a rebuild.
///
/// Only ticket mail is affected. Sign-in codes, invitations, password
/// resets, shop and contact-form email are unrelated and still send.
const SEND_TICKET_EMAILS: bool = false;

const MAX_TITLE: usize = 200;
const MAX_BODY: usize = 20_000;
const MAX_COMMENT: usize = 20_000;

/// Body excerpt length in notification emails. Long enough to convey the
/// report, short enough that the mail stays scannable.
const EXCERPT_LEN: usize = 600;

#[derive(Deserialize)]
pub(crate) struct CreateTicketRequest {
    title: String,
    #[serde(default)]
    body: String,
}

#[derive(Deserialize)]
pub(crate) struct UpdateTicketRequest {
    title: String,
    #[serde(default)]
    body: String,
    status: String,
}

#[derive(Deserialize)]
pub(crate) struct AddCommentRequest {
    body: String,
}

#[derive(Deserialize)]
pub(crate) struct AdminTicketQuery {
    #[serde(default)]
    status: Option<String>,
}

fn validate_title(s: &str) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let t = s.trim();
    if t.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Title is required"));
    }
    if t.chars().count() > MAX_TITLE {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "Title is too long (max 200 characters)",
        ));
    }
    Ok(t.to_string())
}

fn validate_body(s: &str) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let b = s.trim();
    if b.chars().count() > MAX_BODY {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "Description is too long (max 20000 characters)",
        ));
    }
    Ok(b.to_string())
}

/// True when the principal is a site admin. Callers must not hold the DB
/// guard - this takes it itself.
fn is_site_admin(state: &AppState, principal: &Principal) -> bool {
    let db = state.db.lock();
    db.get_user_role(&principal.username)
        .map(|r| is_admin_role(&r))
        .unwrap_or(false)
}

pub(crate) async fn handle_list_tickets(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    assert_workspace_member(&state, &workspace_id, &principal)?;

    let rows = {
        let db = state.db.lock();
        db.list_tickets(&workspace_id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };

    Ok(Json(serde_json::json!({ "tickets": rows })))
}

pub(crate) async fn handle_get_ticket(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, ticket_id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    assert_workspace_member(&state, &workspace_id, &principal)?;

    let (ticket, comments) = {
        let db = state.db.lock();
        let ticket = db
            .get_ticket(&workspace_id, ticket_id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Ticket not found"))?;
        let comments = db
            .list_ticket_comments(ticket_id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        (ticket, comments)
    };

    Ok(Json(serde_json::json!({ "ticket": ticket, "comments": comments })))
}

pub(crate) async fn handle_create_ticket(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(req): Json<CreateTicketRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    assert_workspace_member(&state, &workspace_id, &principal)?;

    let title = validate_title(&req.title)?;
    let body = validate_body(&req.body)?;

    let (id, ws_name) = {
        let db = state.db.lock();
        let id = db
            .create_ticket(&workspace_id, &title, &body, &principal.username)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        let ws_name = db
            .get_workspace(&workspace_id)
            .ok()
            .flatten()
            .map(|w| w.1)
            .unwrap_or_default();
        audit_db(
            &db,
            &principal.username,
            "ticket.create",
            &workspace_id,
            &format!("#{} {}", id, title),
        );
        (id, ws_name)
    };

    notify_workspace(
        &state,
        &workspace_id,
        id,
        &principal.username,
        &format!("New ticket: {}", title),
        "New ticket",
        &format!("{} opened a ticket in workspace {}.", principal.username, ws_name),
        vec![
            ("Workspace".to_string(), ws_name.clone()),
            ("Ticket".to_string(), format!("#{} {}", id, title)),
            ("Opened by".to_string(), principal.username.clone()),
        ],
        &body,
    );

    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id }))))
}

pub(crate) async fn handle_update_ticket(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, ticket_id)): Path<(String, i64)>,
    Json(req): Json<UpdateTicketRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    assert_workspace_member(&state, &workspace_id, &principal)?;

    let title = validate_title(&req.title)?;
    let body = validate_body(&req.body)?;
    let status = req.status.trim();
    if !susi_core::db::is_valid_ticket_status(status) {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "Status must be one of: open, in_progress, closed",
        ));
    }

    let (prev_status, ws_name) = {
        let db = state.db.lock();
        let prev = db
            .get_ticket(&workspace_id, ticket_id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Ticket not found"))?;
        if !db
            .update_ticket(&workspace_id, ticket_id, &title, &body, status)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        {
            return Err(error_response(StatusCode::NOT_FOUND, "Ticket not found"));
        }
        audit_db(
            &db,
            &principal.username,
            "ticket.update",
            &workspace_id,
            &format!("#{} status={}", ticket_id, status),
        );
        (prev.status, prev.workspace_name)
    };

    // Only a status transition is worth an email; retitling or fixing a typo
    // in the body is not.
    if prev_status != status {
        notify_workspace(
            &state,
            &workspace_id,
            ticket_id,
            &principal.username,
            &format!("Ticket #{} is now {}: {}", ticket_id, status_label(status), title),
            "Ticket status changed",
            &format!(
                "{} moved this ticket from {} to {}.",
                principal.username,
                status_label(&prev_status),
                status_label(status)
            ),
            vec![
                ("Workspace".to_string(), ws_name.clone()),
                ("Ticket".to_string(), format!("#{} {}", ticket_id, title)),
                ("Status".to_string(), status_label(status).to_string()),
                ("Changed by".to_string(), principal.username.clone()),
            ],
            "",
        );
    }

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

pub(crate) async fn handle_delete_ticket(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, ticket_id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    assert_workspace_member(&state, &workspace_id, &principal)?;

    let admin = is_site_admin(&state, &principal);
    {
        let db = state.db.lock();
        let ticket = db
            .get_ticket(&workspace_id, ticket_id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Ticket not found"))?;
        if !admin && ticket.author != principal.username {
            return Err(error_response(
                StatusCode::FORBIDDEN,
                "Only the ticket author or an admin can delete this ticket",
            ));
        }
        db.delete_ticket(&workspace_id, ticket_id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        audit_db(
            &db,
            &principal.username,
            "ticket.delete",
            &workspace_id,
            &format!("#{} {}", ticket_id, ticket.title),
        );
    }

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

pub(crate) async fn handle_add_ticket_comment(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, ticket_id)): Path<(String, i64)>,
    Json(req): Json<AddCommentRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    assert_workspace_member(&state, &workspace_id, &principal)?;

    let body = req.body.trim();
    if body.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Comment cannot be empty"));
    }
    if body.chars().count() > MAX_COMMENT {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "Comment is too long (max 20000 characters)",
        ));
    }

    let (id, title, ws_name) = {
        let db = state.db.lock();
        let ticket = db
            .get_ticket(&workspace_id, ticket_id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Ticket not found"))?;
        let id = db
            .add_ticket_comment(&workspace_id, ticket_id, body, &principal.username)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Ticket not found"))?;
        audit_db(
            &db,
            &principal.username,
            "ticket.comment",
            &workspace_id,
            &format!("#{}", ticket_id),
        );
        (id, ticket.title, ticket.workspace_name)
    };

    notify_workspace(
        &state,
        &workspace_id,
        ticket_id,
        &principal.username,
        &format!("New comment on ticket #{}: {}", ticket_id, title),
        "New comment",
        &format!("{} commented on a ticket in workspace {}.", principal.username, ws_name),
        vec![
            ("Workspace".to_string(), ws_name.clone()),
            ("Ticket".to_string(), format!("#{} {}", ticket_id, title)),
            ("Comment by".to_string(), principal.username.clone()),
        ],
        body,
    );

    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id }))))
}

pub(crate) async fn handle_delete_ticket_comment(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, ticket_id, comment_id)): Path<(String, i64, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    assert_workspace_member(&state, &workspace_id, &principal)?;

    let admin = is_site_admin(&state, &principal);
    {
        let db = state.db.lock();
        // Scope the comment to the addressed ticket AND workspace, so a
        // member of workspace A can't delete a comment in workspace B by
        // guessing ids.
        db.get_ticket(&workspace_id, ticket_id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Ticket not found"))?;
        let author = db
            .list_ticket_comments(ticket_id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .into_iter()
            .find(|c| c.id == comment_id)
            .map(|c| c.author)
            .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Comment not found"))?;
        if !admin && author != principal.username {
            return Err(error_response(
                StatusCode::FORBIDDEN,
                "Only the comment author or an admin can delete this comment",
            ));
        }
        db.delete_ticket_comment(ticket_id, comment_id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        audit_db(
            &db,
            &principal.username,
            "ticket.comment_delete",
            &workspace_id,
            &format!("#{} comment {}", ticket_id, comment_id),
        );
    }

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

/// Cross-workspace ticket list for admins.
pub(crate) async fn handle_admin_list_tickets(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<AdminTicketQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let status = q.status.as_deref().map(str::trim).filter(|s| !s.is_empty());
    if let Some(s) = status {
        if !susi_core::db::is_valid_ticket_status(s) {
            return Err(error_response(StatusCode::BAD_REQUEST, "Unknown status filter"));
        }
    }

    let rows = {
        let db = state.db.lock();
        db.list_all_tickets(status)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };

    Ok(Json(serde_json::json!({ "tickets": rows })))
}

fn status_label(s: &str) -> &str {
    match s {
        "open" => "Open",
        "in_progress" => "In progress",
        "closed" => "Closed",
        other => other,
    }
}

/// Truncate on a char boundary, appending an ellipsis marker when cut.
fn excerpt(s: &str) -> String {
    if s.chars().count() <= EXCERPT_LEN {
        return s.to_string();
    }
    let mut out: String = s.chars().take(EXCERPT_LEN).collect();
    out.push_str(" [...]");
    out
}

/// Email every workspace member plus every site admin except the actor.
///
/// Currently a no-op: `SEND_TICKET_EMAILS` is `false`, so this returns before
/// resolving recipients or touching the DB.
///
/// Fire-and-forget once enabled: recipients are resolved under a short DB
/// lock, then one task per address is spawned. A missing SMTP config, a member
/// without an email address, or a failing send never fails the request that
/// triggered it.
#[allow(clippy::too_many_arguments)]
fn notify_workspace(
    state: &Arc<AppState>,
    workspace_id: &str,
    ticket_id: i64,
    actor: &str,
    subject: &str,
    heading: &str,
    intro: &str,
    rows: Vec<(String, String)>,
    body: &str,
) {
    if !SEND_TICKET_EMAILS {
        return;
    }
    let Some(svc) = state.email.clone() else {
        return;
    };

    let recipients = {
        let db = state.db.lock();
        let members: Vec<String> = db
            .list_workspace_members(workspace_id)
            .unwrap_or_default()
            .into_iter()
            .map(|(username, _)| username)
            .collect();
        let users = db.list_users().unwrap_or_default();
        // Site admins reach every workspace without a membership row, so the
        // member list alone would leave them out of their own notifications.
        let actor_email = users
            .iter()
            .find(|u| u.username == actor)
            .and_then(|u| u.email.clone())
            .map(|e| e.trim().to_lowercase());

        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut out: Vec<String> = Vec::new();
        for u in &users {
            if u.username == actor {
                continue;
            }
            if !(is_admin_role(&u.role) || members.iter().any(|m| m == &u.username)) {
                continue;
            }
            let Some(addr) = u.email.as_deref().map(str::trim).filter(|e| !e.is_empty()) else {
                continue;
            };
            let key = addr.to_lowercase();
            // A second account sharing the actor's address is still the actor.
            if actor_email.as_deref() == Some(key.as_str()) {
                continue;
            }
            if seen.insert(key) {
                out.push(addr.to_string());
            }
        }
        out
    };

    if recipients.is_empty() {
        return;
    }

    // An empty base URL would produce a scheme-less link that is dead in a
    // mail client - omit the CTA entirely instead.
    let base = state.magic_link_base_url.trim_end_matches('/');
    let link = if base.is_empty() {
        None
    } else {
        Some(format!(
            "{}/#/workspaces/{}/tickets/{}",
            base,
            urlencode(workspace_id),
            ticket_id
        ))
    };

    let excerpt_text = excerpt(body);
    for to in recipients {
        let svc = svc.clone();
        let subject = subject.to_string();
        let heading = heading.to_string();
        let intro = intro.to_string();
        let rows = rows.clone();
        let excerpt_text = excerpt_text.clone();
        let link = link.clone();
        tokio::spawn(async move {
            if let Err(e) = svc
                .send_ticket_notification(
                    &to,
                    &subject,
                    &heading,
                    &intro,
                    &rows,
                    &excerpt_text,
                    link.as_deref(),
                )
                .await
            {
                log::error!("Failed to send ticket notification to {}: {:#}", to, e);
            }
        });
    }
}

/// Percent-encode the few characters that would break a hash-route segment.
/// Workspace ids are UUIDs today, so this is belt-and-braces.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => out.push(c),
            _ => {
                let mut buf = [0u8; 4];
                for b in c.encode_utf8(&mut buf).as_bytes() {
                    out.push_str(&format!("%{:02X}", b));
                }
            }
        }
    }
    out
}
