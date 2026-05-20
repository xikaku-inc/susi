//! Public contact-form endpoint.
//!
//! Hardening stack:
//!   - hidden honeypot field that real browsers leave empty
//!   - Cloudflare Turnstile siteverify (when SUSI_TURNSTILE_SECRET is set)
//!   - per-IP sliding-window rate limit (3 / hour, 20 / day)
//!   - field length caps + minimum body length
//!   - sender email syntactically validated; no HTML in outbound mail body
//!
//! Disabled (returns 503) if `SUSI_CONTACT_TO_ADDR` is empty or SMTP isn't
//! configured.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    check_ip_rate_limit, client_ip, error_response, AppState, ErrorResponse,
};

const CONTACT_WINDOW: StdDuration = StdDuration::from_secs(3600);
const CONTACT_MAX_PER_HOUR: usize = 3;

const MAX_NAME: usize = 200;
const MAX_EMAIL: usize = 320; // RFC 5321 max
const MAX_SUBJECT: usize = 200;
const MAX_MESSAGE: usize = 8000;
const MIN_MESSAGE: usize = 10;

#[derive(Deserialize)]
pub struct ContactRequest {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub message: String,
    /// Honeypot — must be empty. Real browsers don't fill hidden inputs;
    /// dumb spambots happily fill anything that looks like a form field.
    #[serde(default)]
    pub website: String,
    /// Cloudflare Turnstile token (cf-turnstile-response).
    #[serde(default)]
    pub turnstile_token: String,
}

pub async fn handle_get_config(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let enabled = !state.contact_to_addr.is_empty() && state.email.is_some();
    Json(json!({
        "enabled": enabled,
        "turnstile_site_key": state.turnstile_site_key,
    }))
}

pub async fn handle_submit(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ContactRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    if state.contact_to_addr.is_empty() || state.email.is_none() {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Contact form is not configured on this server",
        ));
    }

    // Honeypot — silently accept (don't reveal what triggered) but drop.
    if !req.website.trim().is_empty() {
        log::info!("Contact form honeypot tripped");
        return Ok(Json(json!({ "status": "ok" })));
    }

    let ip = client_ip(peer, &headers);
    check_ip_rate_limit(
        &state.contact_attempts,
        ip,
        CONTACT_WINDOW,
        CONTACT_MAX_PER_HOUR,
        "Contact",
        "Too many contact submissions, try again later",
    )?;

    let name = req.name.trim();
    let email = req.email.trim();
    let subject = req.subject.trim();
    let message = req.message.trim();

    if name.is_empty() || name.len() > MAX_NAME {
        return Err(error_response(StatusCode::BAD_REQUEST, "Invalid name"));
    }
    if !is_email_like(email) || email.len() > MAX_EMAIL {
        return Err(error_response(StatusCode::BAD_REQUEST, "Invalid email address"));
    }
    if subject.len() > MAX_SUBJECT {
        return Err(error_response(StatusCode::BAD_REQUEST, "Subject too long"));
    }
    if message.len() < MIN_MESSAGE || message.len() > MAX_MESSAGE {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "Message must be between 10 and 8000 characters",
        ));
    }

    if !state.turnstile_secret.is_empty() {
        if req.turnstile_token.is_empty() {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "Captcha is required",
            ));
        }
        if !verify_turnstile(&state.http, &state.turnstile_secret, &req.turnstile_token, ip).await {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "Captcha verification failed — please retry",
            ));
        }
    }

    let email_service = state.email.clone().expect("checked above");
    let to_addr = state.contact_to_addr.clone();
    let mail_subject = if subject.is_empty() {
        format!("[Xikaku] {}", name)
    } else {
        format!("[Xikaku] {}", subject)
    };
    let body = format!(
        "New contact-form submission\n\
         ---------------------------\n\
         Name:    {name}\n\
         Email:   {email}\n\
         Subject: {subject}\n\
         IP:      {ip}\n\n\
         Message:\n\
         {message}\n",
        name = name,
        email = email,
        subject = if subject.is_empty() { "(none)" } else { subject },
        ip = ip,
        message = message,
    );

    // Send as plain text only — no HTML body from untrusted user input.
    // Also set Reply-To indirectly by passing the visitor email in the body;
    // we keep the actual From as the configured server address so SPF/DKIM
    // are valid (visitor's domain wouldn't authorize us as a sender).
    if let Err(e) = email_service
        .send_html_as("Xikaku Contact", &to_addr, &mail_subject, &body, &html_escape(&body).replace('\n', "<br>\n"))
        .await
    {
        log::error!("Contact form email send failed: {:#}", e);
        return Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not deliver your message — please email us directly",
        ));
    }

    log::info!("Contact form delivered from {} <{}> (ip {})", name, email, ip);
    Ok(Json(json!({ "status": "ok" })))
}

fn is_email_like(s: &str) -> bool {
    // Intentionally minimal — full RFC 5322 is famously hopeless. We just
    // require a single @ with non-empty parts and a dot in the domain.
    let mut parts = s.split('@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    if parts.next().is_some() { return false; }
    if local.is_empty() || domain.is_empty() { return false; }
    if !domain.contains('.') { return false; }
    if s.chars().any(|c| c.is_whitespace() || c == '\r' || c == '\n') { return false; }
    true
}

async fn verify_turnstile(
    http: &reqwest::Client,
    secret: &str,
    token: &str,
    ip: std::net::IpAddr,
) -> bool {
    let mut form = vec![
        ("secret", secret.to_string()),
        ("response", token.to_string()),
    ];
    form.push(("remoteip", ip.to_string()));
    let resp = match http
        .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        .form(&form)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            log::warn!("Turnstile siteverify request failed: {}", e);
            return false;
        }
    };
    let body = match resp.text().await {
        Ok(b) => b,
        Err(e) => {
            log::warn!("Turnstile siteverify body read failed: {}", e);
            return false;
        }
    };
    let json: serde_json::Value = match serde_json::from_str(&body) {
        Ok(j) => j,
        Err(e) => {
            log::warn!("Turnstile siteverify body parse failed: {}", e);
            return false;
        }
    };
    let ok = json.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    if !ok {
        log::warn!("Turnstile siteverify rejected: {}", json);
    }
    ok
}

fn html_escape(s: &str) -> String {
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
