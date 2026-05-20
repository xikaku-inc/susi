mod docs;
mod website;
mod email;
mod shop;
mod invoice_pdf;
mod contact;
mod s3;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};

use anyhow::{Context, Result};
use argon2::{self, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Multipart, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use clap::Parser;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
use susi_core::crypto::{private_key_from_pem, sign_license};
use susi_core::db::LicenseDb;
use susi_core::{License, DEFAULT_LEASE_DURATION_HOURS, DEFAULT_LEASE_GRACE_HOURS};
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::email::{EmailConfig, EmailService};
#[derive(Parser)]
#[command(name = "susi-server", about = "Susi License Server")]
struct Cli {
    /// Path to private key PEM file
    #[arg(long, default_value = "private.pem")]
    private_key: String,

    /// Path to SQLite database
    #[arg(long, default_value = "licenses.db")]
    db: String,

    /// Listen address
    #[arg(long, default_value = "0.0.0.0:3100")]
    listen: String,

    /// Directory for persistent data (keys, database, release assets)
    #[arg(long, default_value = "/data")]
    data_dir: String,

    /// Path to PEM file containing the trusted code-signing CA certificate.
    /// When set, every activate and verify request must include a signing
    /// certificate chain that terminates at this CA, or it is rejected with
    /// HTTP 403.  Only the immediate issuer of the leaf cert needs to match
    /// (single-level pinning).
    #[arg(long)]
    trusted_signing_ca: Option<String>,
    
    // -------- SMTP / magic-link settings --------
    //
    // If `smtp_host` is empty, magic-link verification is disabled entirely
    // and new devices are accepted without email confirmation (bootstrap mode).
    // Enabling requires `smtp_host`, `smtp_user`, `smtp_password`, and
    // `magic_link_base_url` to all be set.

    /// SMTP relay host (e.g. smtp.gmail.com). Empty = disable magic-link.
    #[arg(long, env = "SUSI_SMTP_HOST", default_value = "")]
    smtp_host: String,

    /// SMTP relay port.
    #[arg(long, env = "SUSI_SMTP_PORT", default_value_t = 587)]
    smtp_port: u16,

    /// SMTP auth username (e.g. klaus@lp-research.com).
    #[arg(long, env = "SUSI_SMTP_USER", default_value = "")]
    smtp_user: String,

    /// SMTP auth password (Google App Password). Prefer setting via env.
    #[arg(long, env = "SUSI_SMTP_PASSWORD", default_value = "")]
    smtp_password: String,

    /// Display name used in the From header.
    #[arg(long, env = "SUSI_SMTP_FROM_NAME", default_value = "Susi")]
    smtp_from_name: String,

    /// Sender address for outbound mail (typically an alias of `smtp_user`).
    #[arg(long, env = "SUSI_SMTP_FROM_ADDR", default_value = "")]
    smtp_from_addr: String,

    /// Public base URL where the dashboard is reachable. Used to build magic
    /// links in outbound email. Must include scheme, e.g. `https://susi.lp-research.com`.
    #[arg(long, env = "SUSI_MAGIC_LINK_BASE_URL", default_value = "")]
    magic_link_base_url: String,

    /// WebSocket URL of the FusionHub relay this susi instance points
    /// workspace members at. Returned verbatim in
    /// `GET /workspaces/{id}/federation` so each member's
    /// workspace_federation poller can spawn its relay client without
    /// hard-coding the URL. Empty ⇒ no relay; members are expected to
    /// reach each other directly (or fall back to `FUSIONHUB_RELAY_URL`
    /// set locally on each member). Typically
    /// `wss://fusionhub.lp-research.com/api/relay`.
    #[arg(long, env = "SUSI_RELAY_URL", default_value = "")]
    relay_url: String,

    // -------- Shop / Stripe --------
    //
    // Both empty ⇒ shop checkout + webhook endpoints respond with 503.
    // Product listing remains available so product pages still render.

    /// Stripe secret key (sk_live_… or sk_test_…). Empty disables checkout.
    #[arg(long, env = "STRIPE_SECRET_KEY", default_value = "")]
    stripe_secret_key: String,

    /// Stripe webhook endpoint signing secret (whsec_…). Empty disables webhook verification.
    #[arg(long, env = "STRIPE_WEBHOOK_SECRET", default_value = "")]
    stripe_webhook_secret: String,

    /// Public URL prefix used for Stripe success_url / cancel_url. Defaults
    /// to `magic_link_base_url` when empty. Must include scheme.
    #[arg(long, env = "SUSI_SHOP_BASE_URL", default_value = "")]
    shop_base_url: String,

    /// Where "new order" email notifications are sent after a successful
    /// checkout. Empty = don't send. Falls back to smtp_from_addr if blank.
    #[arg(long, env = "SUSI_SHOP_NOTIFY_ADDR", default_value = "")]
    shop_notify_addr: String,

    // -------- Contact form --------
    //
    // All three may be empty. If `contact_to_addr` is empty (or SMTP isn't
    // configured) the form endpoint returns 503 and the frontend hides the
    // form. If `turnstile_secret`+`turnstile_site_key` are empty the form is
    // still served but with no captcha (honeypot + rate-limit only).

    /// Recipient address for contact-form submissions.
    #[arg(long, env = "SUSI_CONTACT_TO_ADDR", default_value = "")]
    contact_to_addr: String,

    /// Cloudflare Turnstile secret key (server-side siteverify).
    #[arg(long, env = "SUSI_TURNSTILE_SECRET", default_value = "")]
    turnstile_secret: String,

    /// Cloudflare Turnstile site key (public, embedded in the form).
    #[arg(long, env = "SUSI_TURNSTILE_SITE_KEY", default_value = "")]
    turnstile_site_key: String,
}

struct AppState {
    db: Mutex<LicenseDb>,
    private_key: RsaPrivateKey,
    jwt_secret: [u8; 32],
    data_dir: String,
    /// DER bytes of the trusted code-signing CA cert, if configured.
    trusted_signing_ca: Option<Vec<u8>>,
    login_attempts: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    checkout_attempts: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    webhook_attempts: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    contact_attempts: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    email: Option<EmailService>,
    magic_link_base_url: String,
    /// FusionHub relay URL handed to workspace members via
    /// `GET /workspaces/{id}/federation`. Empty when not configured.
    relay_url: String,
    stripe_secret_key: String,
    stripe_webhook_secret: String,
    shop_base_url: String,
    shop_notify_addr: String,
    contact_to_addr: String,
    turnstile_secret: String,
    turnstile_site_key: String,
    http: reqwest::Client,
    s3: Option<s3::S3Storage>,
}

// Magic-link TTL: long enough for a user to switch to their mail client and
// back, short enough that a leaked link is useless a few minutes later.
const MAGIC_LINK_TTL_MINUTES: i64 = 15;


// Sliding-window rate limit on /api/v1/auth/login — throttles brute force
// against weak passwords and caps credential-stuffing throughput.
const LOGIN_WINDOW: StdDuration = StdDuration::from_secs(60);
const LOGIN_MAX_ATTEMPTS: usize = 10;

// Shop checkout creates a Stripe Checkout Session per call (outbound API
// cost + DB lock). Cap per-IP burst so a script can't run our Stripe quota
// down or starve the SQLite connection.
const CHECKOUT_WINDOW: StdDuration = StdDuration::from_secs(60);
const CHECKOUT_MAX_ATTEMPTS: usize = 10;

// Generous limit on the Stripe webhook endpoint: legitimate Stripe delivery
// burst-fires retries from a small IP set, so we keep the cap loose. The
// signature check is the real gate — this is just defense in depth against
// spam from a single source.
const WEBHOOK_WINDOW: StdDuration = StdDuration::from_secs(60);
const WEBHOOK_MAX_ATTEMPTS: usize = 300;

// How often we'll walk the rate-limit map to drop empty/expired entries.
// Cleanup is O(map.len()) so under burst traffic the previous trigger
// (`map.len() > 4096`) ran on every subsequent request — turning a cheap
// per-request check into a full scan under the shared mutex. Gating on
// elapsed seconds amortises that work to once per CLEANUP_PERIOD regardless
// of map size.
const RATE_LIMIT_CLEANUP_PERIOD_SECS: u64 = 60;

fn check_ip_rate_limit(
    map_lock: &Mutex<HashMap<IpAddr, Vec<Instant>>>,
    ip: IpAddr,
    window: StdDuration,
    max_attempts: usize,
    label: &str,
    user_message: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    // One static cleanup deadline shared across all rate-limit maps. The
    // maps are all bounded by IP-set size and they all have ≤60 s windows;
    // a single timer keeps the bookkeeping trivial.
    static NEXT_CLEANUP_UNIX_SECS: AtomicU64 = AtomicU64::new(0);

    let mut map = map_lock.lock().unwrap();
    let now = Instant::now();
    let entry = map.entry(ip).or_default();
    entry.retain(|t| now.duration_since(*t) < window);
    if entry.len() >= max_attempts {
        log::warn!("{} rate limit exceeded for {}", label, ip);
        return Err(error_response(StatusCode::TOO_MANY_REQUESTS, user_message));
    }
    entry.push(now);

    // Periodic GC. Use wall-clock seconds via SystemTime so the deadline is a
    // plain integer (Instant doesn't fit in an AtomicU64).
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let deadline = NEXT_CLEANUP_UNIX_SECS.load(Ordering::Relaxed);
    if now_unix >= deadline {
        // Race-free: only the thread that successfully advances the deadline
        // performs the sweep. Late arrivals see the new deadline and skip.
        if NEXT_CLEANUP_UNIX_SECS
            .compare_exchange(
                deadline,
                now_unix + RATE_LIMIT_CLEANUP_PERIOD_SECS,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            map.retain(|_, v| {
                v.retain(|t| now.duration_since(*t) < window);
                !v.is_empty()
            });
        }
    }
    Ok(())
}

fn check_login_rate_limit(
    state: &AppState,
    ip: IpAddr,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    check_ip_rate_limit(
        &state.login_attempts,
        ip,
        LOGIN_WINDOW,
        LOGIN_MAX_ATTEMPTS,
        "Login",
        "Too many login attempts, try again later",
    )
}

fn check_checkout_rate_limit(
    state: &AppState,
    ip: IpAddr,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    check_ip_rate_limit(
        &state.checkout_attempts,
        ip,
        CHECKOUT_WINDOW,
        CHECKOUT_MAX_ATTEMPTS,
        "Checkout",
        "Too many checkout requests, try again in a minute",
    )
}

fn check_webhook_rate_limit(
    state: &AppState,
    ip: IpAddr,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    check_ip_rate_limit(
        &state.webhook_attempts,
        ip,
        WEBHOOK_WINDOW,
        WEBHOOK_MAX_ATTEMPTS,
        "Webhook",
        "Too many webhook requests",
    )
}

// Extract the originating client IP. When the Rust server is fronted by a
// trusted reverse proxy (nginx on the host, or Docker's bridge gateway) the
// TCP peer is loopback or RFC1918-private; in that case we consult
// X-Forwarded-For / X-Real-IP. For requests that arrive directly from the
// public internet we use the TCP peer and ignore the forwarded headers
// (they would be attacker-controlled).
fn client_ip(peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    let peer_ip = peer.ip();
    if is_trusted_proxy_peer(peer_ip) {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = xff.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
        if let Some(xri) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            if let Ok(ip) = xri.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    peer_ip
}

fn is_trusted_proxy_peer(ip: IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        // For IPv6 only loopback is treated as trusted; the unique-local /
        // link-local stable APIs aren't on stable Rust yet, and Docker bridges
        // are IPv4 in our deployment.
        IpAddr::V6(_) => false,
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iat: i64,
    exp: i64,
}

/// Short-lived, single-asset download ticket. Lets the dashboard trigger a
/// native browser download via plain `<a href>` (which can't carry an
/// Authorization header) without exposing the user's session JWT in the URL.
/// The `aud` claim makes it impossible to mistake an auth JWT for a ticket.
#[derive(Debug, Serialize, Deserialize)]
struct DownloadTicketClaims {
    sub: String,
    tag: String,
    asset: String,
    aud: String,
    exp: i64,
}

const DOWNLOAD_TICKET_AUDIENCE: &str = "release-download";
const DOWNLOAD_TICKET_TTL_SECS: i64 = 60;

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ActivateRequest {
    license_key: String,
    machine_code: String,
    #[serde(default)]
    friendly_name: String,
    /// DER-encoded certificate chain, base64-encoded, leaf cert first.
    /// Sent by the client when the binary is code-signed.
    #[serde(default)]
    signing_cert_chain: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct VerifyRequest {
    license_key: String,
    machine_code: String,
    /// DER-encoded certificate chain, base64-encoded, leaf cert first.
    #[serde(default)]
    signing_cert_chain: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct DeactivateRequest {
    license_key: String,
    machine_code: String,
}

#[derive(Deserialize)]
struct CreateLicenseRequest {
    #[serde(default = "default_product")]
    product: String,
    customer: String,
    /// Expiry date as "YYYY-MM-DD", or null/missing for perpetual
    #[serde(default)]
    expires: Option<String>,
    /// Days until expiry (alternative to `expires`)
    #[serde(default)]
    days: Option<i64>,
    /// If true, license never expires
    #[serde(default)]
    perpetual: bool,
    #[serde(default)]
    features: Vec<String>,
    #[serde(default = "default_max_machines")]
    max_machines: u32,
    /// Lease duration in hours. 0 = no lease enforcement. Default: 168 (7 days).
    #[serde(default = "default_lease_duration")]
    lease_duration_hours: u32,
    /// Grace period in hours after lease expires. Default: 24.
    #[serde(default = "default_lease_grace")]
    lease_grace_hours: u32,
    /// Require valid binary code signature. Default: false.
    #[serde(default = "default_require_signed_binary")]
    require_signed_binary: bool,
}

fn default_product() -> String {
    "FusionHub".to_string()
}
fn default_max_machines() -> u32 {
    1
}
fn default_lease_duration() -> u32 {
    DEFAULT_LEASE_DURATION_HOURS
}
fn default_lease_grace() -> u32 {
    DEFAULT_LEASE_GRACE_HOURS
}
fn default_require_signed_binary() -> bool {
    false
}

#[derive(Deserialize)]
struct UpdateLicenseRequest {
    #[serde(default)]
    customer: Option<String>,
    #[serde(default)]
    product: Option<String>,
    /// "YYYY-MM-DD", "perpetual", or null to leave unchanged
    #[serde(default)]
    expires: Option<String>,
    #[serde(default)]
    features: Option<Vec<String>>,
    #[serde(default)]
    max_machines: Option<u32>,
    #[serde(default)]
    require_signed_binary: Option<bool>,
}

#[derive(Deserialize)]
struct ExportRequest {
    machine_code: String,
    #[serde(default)]
    friendly_name: String,
}

#[derive(Deserialize)]
struct ExportTokenRequest {
    usb_serial: String,
    #[serde(default)]
    friendly_name: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct LicenseSummary {
    id: String,
    license_key: String,
    product: String,
    customer: String,
    created: String,
    expires: String,
    features: Vec<String>,
    max_machines: u32,
    lease_duration_hours: u32,
    lease_grace_hours: u32,
    active_machine_count: usize,
    total_machine_count: usize,
    machines: Vec<MachineSummary>,
    revoked: bool,
    require_signed_binary: bool,
}

#[derive(Serialize)]
struct MachineSummary {
    machine_code: String,
    friendly_name: String,
    activated_at: String,
    lease_expires_at: Option<String>,
    lease_active: bool,
}

fn license_to_summary(lic: &License) -> LicenseSummary {
    let now = Utc::now();
    LicenseSummary {
        id: lic.id.clone(),
        license_key: lic.license_key.clone(),
        product: lic.product.clone(),
        customer: lic.customer.clone(),
        created: lic.created.to_rfc3339(),
        expires: lic
            .expires
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "perpetual".to_string()),
        features: lic.features.clone(),
        max_machines: lic.max_machines,
        lease_duration_hours: lic.lease_duration_hours,
        lease_grace_hours: lic.lease_grace_hours,
        active_machine_count: lic.active_machine_count(),
        total_machine_count: lic.machines.len(),
        machines: lic
            .machines
            .iter()
            .map(|m| MachineSummary {
                machine_code: m.machine_code.clone(),
                friendly_name: m.friendly_name.clone(),
                activated_at: m.activated_at.to_rfc3339(),
                lease_expires_at: m.lease_expires_at.map(|dt| dt.to_rfc3339()),
                lease_active: m.is_lease_active(now),
            })
            .collect(),
        revoked: lic.revoked,
        require_signed_binary: lic.require_signed_binary,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn error_response(status: StatusCode, msg: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: msg.to_string(),
        }),
    )
}

fn create_jwt(secret: &[u8; 32], username: &str) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: username.into(),
        iat: now,
        exp: now + 86400, // 24h
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret))
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))
}

fn mint_download_ticket(
    secret: &[u8; 32],
    sub: &str,
    tag: &str,
    asset: &str,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let claims = DownloadTicketClaims {
        sub: sub.into(),
        tag: tag.into(),
        asset: asset.into(),
        aud: DOWNLOAD_TICKET_AUDIENCE.into(),
        exp: Utc::now().timestamp() + DOWNLOAD_TICKET_TTL_SECS,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret))
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))
}

fn validate_download_ticket(
    secret: &[u8; 32],
    token: &str,
    expected_tag: &str,
    expected_asset: &str,
) -> Result<DownloadTicketClaims, (StatusCode, Json<ErrorResponse>)> {
    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_audience(&[DOWNLOAD_TICKET_AUDIENCE]);
    let claims = decode::<DownloadTicketClaims>(token, &DecodingKey::from_secret(secret), &validation)
        .map(|d| d.claims)
        .map_err(|_| error_response(StatusCode::UNAUTHORIZED, "Invalid or expired download ticket"))?;
    if claims.tag != expected_tag || claims.asset != expected_asset {
        return Err(error_response(StatusCode::FORBIDDEN, "Ticket does not match requested asset"));
    }
    Ok(claims)
}

fn validate_jwt(
    headers: &HeaderMap,
    jwt_secret: &[u8; 32],
) -> Result<Claims, (StatusCode, Json<ErrorResponse>)> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth.strip_prefix("Bearer ").unwrap_or("");
    if token.is_empty() {
        return Err(error_response(StatusCode::UNAUTHORIZED, "Missing authentication token"));
    }
    let validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    decode::<Claims>(token, &DecodingKey::from_secret(jwt_secret), &validation)
        .map(|data| data.claims)
        .map_err(|e| {
            let msg = match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => "Token expired",
                _ => "Invalid token",
            };
            error_response(StatusCode::UNAUTHORIZED, msg)
        })
}

// Authenticated source — JWT means an interactive browser session (subject to
// password-change and TOTP gates), ApiToken means a long-lived bearer issued
// via the management UI (intended for service accounts; bypasses interactive gates).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthSource {
    Jwt,
    ApiToken,
}

#[derive(Debug)]
pub(crate) struct Principal {
    pub(crate) username: String,
    source: AuthSource,
}

const API_TOKEN_PREFIX: &str = "susi_pat_";

// Short TTL on the auth-hot-path cache. Long enough to absorb polling clients
// (cron jobs, dashboards) that reuse the same bearer many times per minute;
// short enough that an admin's revoke takes effect before any human notices.
const API_TOKEN_CACHE_TTL: StdDuration = StdDuration::from_secs(30);
const API_TOKEN_CACHE_MAX: usize = 4096;

struct CachedToken {
    inserted: Instant,
    username: String,
}

static API_TOKEN_CACHE: std::sync::LazyLock<std::sync::RwLock<HashMap<String, CachedToken>>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(HashMap::new()));

fn api_token_cache_get(hash: &str) -> Option<String> {
    let cache = API_TOKEN_CACHE.read().ok()?;
    let entry = cache.get(hash)?;
    if entry.inserted.elapsed() < API_TOKEN_CACHE_TTL {
        Some(entry.username.clone())
    } else {
        None
    }
}

fn api_token_cache_put(hash: String, username: String) {
    let Ok(mut cache) = API_TOKEN_CACHE.write() else { return };
    if cache.len() >= API_TOKEN_CACHE_MAX {
        // Drop expired entries when the bound is hit; if everything is still
        // fresh, clear half the map at random (HashMap iteration order) so we
        // bound the worst case to O(N) once per cap miss.
        let now = Instant::now();
        cache.retain(|_, v| now.duration_since(v.inserted) < API_TOKEN_CACHE_TTL);
        if cache.len() >= API_TOKEN_CACHE_MAX {
            let drop_n = cache.len() / 2;
            let keys: Vec<String> = cache.keys().take(drop_n).cloned().collect();
            for k in keys {
                cache.remove(&k);
            }
        }
    }
    cache.insert(hash, CachedToken { inserted: Instant::now(), username });
}

/// Drop a single token from the auth cache (called when revoked so the bearer
/// stops working immediately, not after the TTL).
#[allow(dead_code)]
fn api_token_cache_invalidate(hash: &str) {
    if let Ok(mut cache) = API_TOKEN_CACHE.write() {
        cache.remove(hash);
    }
}

/// Drop every cached token. Called by revoke handlers — we don't store the
/// raw hash on the row and revokes are rare, so a global flush is simpler
/// than mapping `id → hash`. Cache is bounded to API_TOKEN_CACHE_MAX entries.
fn api_token_cache_clear() {
    if let Ok(mut cache) = API_TOKEN_CACHE.write() {
        cache.clear();
    }
}

/// Verify the Authorization header and resolve to a Principal. Accepts either:
///   - Bearer <JWT>      → AuthSource::Jwt
///   - Bearer susi_pat_… → AuthSource::ApiToken
pub(crate) fn validate_principal(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<Principal, (StatusCode, Json<ErrorResponse>)> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth.strip_prefix("Bearer ").unwrap_or("");
    if token.is_empty() {
        return Err(error_response(StatusCode::UNAUTHORIZED, "Missing authentication token"));
    }

    if token.starts_with(API_TOKEN_PREFIX) {
        let token_hash = hash_token(token);

        // Hot-path cache: most authenticated polling clients reuse the same
        // bearer many times per minute. Skip the DB hit + lock for cache hits
        // within `API_TOKEN_CACHE_TTL`. Revocation lag is bounded by the TTL.
        if let Some(username) = api_token_cache_get(&token_hash) {
            return Ok(Principal { username, source: AuthSource::ApiToken });
        }

        // Single round-trip: validate the hash AND bump last_used_at.
        let row = {
            let db = state.db.lock().unwrap();
            db.find_and_touch_api_token(&token_hash)
                .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        };
        let Some(row) = row else {
            return Err(error_response(StatusCode::UNAUTHORIZED, "Invalid API token"));
        };
        if row.revoked {
            return Err(error_response(StatusCode::UNAUTHORIZED, "API token revoked"));
        }
        api_token_cache_put(token_hash, row.username.clone());
        return Ok(Principal { username: row.username, source: AuthSource::ApiToken });
    }

    let claims = validate_jwt(headers, &state.jwt_secret)?;
    Ok(Principal { username: claims.sub, source: AuthSource::Jwt })
}

/// Combined password-changed + admin-role + admin-2FA gate. Uses one DB
/// round-trip and one mutex cycle instead of the three the legacy
/// `require_password_changed` + `require_admin` pair did. Use this for any
/// handler that ends up calling both helpers back-to-back (the typical admin
/// case) — the old helpers stay around for the few sites that need only one.
pub(crate) fn require_admin_full(
    state: &AppState,
    principal: &Principal,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    // API tokens skip both the password-change gate (UI-only) and the
    // TOTP requirement (the bearer is itself a strong factor).
    let row = {
        let db = state.db.lock().unwrap();
        db.get_user_admin_check(&principal.username)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    let Some((role, must_change, totp_enabled)) = row else {
        return Err(error_response(StatusCode::FORBIDDEN, "Admin access required"));
    };
    if principal.source == AuthSource::Jwt && must_change {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "Password change required before accessing admin features",
        ));
    }
    if role != "admin" {
        return Err(error_response(StatusCode::FORBIDDEN, "Admin access required"));
    }
    if principal.source == AuthSource::Jwt && !totp_enabled {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "Admin accounts must enable two-factor authentication before performing this action",
        ));
    }
    Ok(())
}

pub(crate) fn require_password_changed(
    state: &AppState,
    principal: &Principal,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    // API tokens are minted explicitly per service account. Whether the
    // owning user "must change password" is a UI bootstrap concept that
    // doesn't apply to a headless caller.
    if principal.source == AuthSource::ApiToken {
        return Ok(());
    }
    let db = state.db.lock().unwrap();
    if db.user_must_change_password(&principal.username).unwrap_or(true) {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "Password change required before accessing admin features",
        ));
    }
    Ok(())
}

/// Check if a principal is a site admin (without enforcing TOTP).
fn is_site_admin(state: &AppState, principal: &Principal) -> bool {
    let db = state.db.lock().unwrap();
    db.get_user_role(&principal.username)
        .map(|r| r == "admin")
        .unwrap_or(false)
}

/// Permission gate for editing a doc release. Admin-only (TOTP enforced),
/// regardless of whether the release is workspace-scoped or global. Returns
/// the release's workspace id (if any) so callers can keep doc seeding scope-
/// correct.
pub(crate) fn release_writer_check(
    state: &AppState,
    principal: &Principal,
    tag: &str,
) -> Result<Option<String>, (StatusCode, Json<ErrorResponse>)> {
    require_admin_full(state, principal)?;
    let scoped_ws = {
        let db = state.db.lock().unwrap();
        db.get_release_workspace_id(tag)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .flatten()
    };
    Ok(scoped_ws)
}

/// Permission gate for reading a doc release. Workspace releases require
/// admin or any-role membership; global releases are public.
pub(crate) fn release_reader_check(
    state: &AppState,
    principal_opt: Option<&Principal>,
    tag: &str,
) -> Result<Option<String>, (StatusCode, Json<ErrorResponse>)> {
    let scoped_ws = {
        let db = state.db.lock().unwrap();
        db.get_release_workspace_id(tag)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .flatten()
    };
    let Some(ws_id) = scoped_ws else { return Ok(None); };

    let principal = principal_opt
        .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "Authentication required"))?;
    if is_site_admin(state, principal) {
        return Ok(Some(ws_id));
    }
    let role = {
        let db = state.db.lock().unwrap();
        db.get_workspace_member_role(&ws_id, &principal.username)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    if role.is_none() {
        return Err(error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"));
    }
    Ok(Some(ws_id))
}

// Argon2 hash + verify are CPU-bound and take ~50–100 ms per call. Run them on
// a `spawn_blocking` worker so they don't stall a Tokio runtime worker thread
// (which would freeze every other handler scheduled on it). Callers must await.
async fn hash_password(password: &str) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let owned = password.to_owned();
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut rand::thread_rng());
        Argon2::default()
            .hash_password(owned.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))
    })
    .await
    .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
}

async fn verify_password(
    password: &str,
    hash: &str,
) -> Result<bool, (StatusCode, Json<ErrorResponse>)> {
    let pw = password.to_owned();
    let hash = hash.to_owned();
    tokio::task::spawn_blocking(move || {
        let parsed = PasswordHash::new(&hash)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        Ok(Argon2::default()
            .verify_password(pw.as_bytes(), &parsed)
            .is_ok())
    })
    .await
    .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
}

// ---------------------------------------------------------------------------
// Auth endpoints
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
    totp_code: Option<String>,
    /// Client-generated stable identifier for this browser. Stored in
    /// localStorage. When absent, every login counts as a new device.
    #[serde(default)]
    device_fp: String,
    /// Optional human-readable label ("Chrome / Linux") shown in the devices
    /// list and in the new-device email.
    #[serde(default)]
    device_label: String,
}

fn hash_token(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    hex::encode(h.finalize())
}

fn random_magic_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn mask_email(addr: &str) -> String {
    // "klaus@lp-research.com" -> "k***@lp-research.com" — shown to the user so
    // they can confirm they're checking the right inbox without leaking the
    // full address to someone who's only guessed a username.
    if let Some((local, domain)) = addr.split_once('@') {
        let first = local.chars().next().unwrap_or('*');
        format!("{}***@{}", first, domain)
    } else {
        "***".into()
    }
}

fn magic_link_disabled(state: &AppState) -> bool {
    state.email.is_none() || state.magic_link_base_url.is_empty()
}

async fn handle_login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let ip = client_ip(peer, &headers);
    check_login_rate_limit(&state, ip)?;

    // Phase 1 — password check. Pull every DB row we need under one lock, drop
    // the lock, then run Argon2 verify off-thread so the ~50 ms CPU spend
    // doesn't serialise every other request behind us.
    let (hash, must_change, role, totp_enabled, user_email, device_known) = {
        let db = state.db.lock().unwrap();
        let hash = db
            .get_user_password_hash(&req.username)
            .map_err(|_| error_response(StatusCode::UNAUTHORIZED, "Invalid credentials"))?;
        let must_change = db.user_must_change_password(&req.username).unwrap_or(false);
        let role = db.get_user_role(&req.username).unwrap_or_else(|_| "user".into());
        let totp_enabled = db.user_totp_enabled(&req.username).unwrap_or(false);
        let email = db.get_user_email(&req.username).ok().flatten();
        let device_known = !req.device_fp.is_empty()
            && db.is_device_known(&req.username, &req.device_fp).unwrap_or(false);
        (hash, must_change, role, totp_enabled, email, device_known)
    };
    if !verify_password(&req.password, &hash).await? {
        return Err(error_response(StatusCode::UNAUTHORIZED, "Invalid credentials"));
    }

    // Phase 2 — decide what the new-device gate demands.
    //
    //   known device                → password only, issue JWT
    //   new device + email + SMTP   → require magic link (and TOTP if enabled)
    //   new device + no email/SMTP  → bootstrap: just issue JWT, but log warning
    if !device_known {
        let magic_disabled = magic_link_disabled(&state);
        if let (Some(email_addr), false) = (user_email.as_ref(), magic_disabled) {
            // Issue magic link. Do NOT issue JWT yet — the user has to click
            // the link in their inbox, which proves email control.
            let raw_token = random_magic_token();
            let token_hash = hash_token(&raw_token);
            {
                let db = state.db.lock().unwrap();
                let _ = db.purge_old_login_tokens();
                db.insert_login_token(
                    &token_hash,
                    &req.username,
                    &req.device_fp,
                    &req.device_label,
                    MAGIC_LINK_TTL_MINUTES * 60,
                )
                .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
            }

            let link = format!(
                "{}/#/magic/{}",
                state.magic_link_base_url.trim_end_matches('/'),
                raw_token
            );

            // Fire off the email. We log but don't leak failures back to the
            // caller — telling an unauthenticated client that an address is
            // unreachable would be a small info leak.
            let email_service = state.email.clone().expect("checked above");
            let to = email_addr.clone();
            let uname = req.username.clone();
            let device_label = if req.device_label.is_empty() {
                "(unknown device)".to_string()
            } else {
                req.device_label.clone()
            };
            let ip_str = ip.to_string();
            tokio::spawn(async move {
                if let Err(e) = email_service
                    .send_magic_link(&to, &uname, &link, MAGIC_LINK_TTL_MINUTES, &device_label, &ip_str)
                    .await
                {
                    log::error!("Failed to send magic-link email to {}: {:#}", to, e);
                }
            });

            return Ok(Json(serde_json::json!({
                "magic_link_sent": true,
                "email_hint": mask_email(email_addr),
                "ttl_minutes": MAGIC_LINK_TTL_MINUTES,
                "totp_required_after_magic": totp_enabled,
            })));
        }

        // Bootstrap path — no email on file or SMTP disabled.
        log::warn!(
            "New-device login for user '{}' accepted without email verification (email set: {}, smtp enabled: {})",
            req.username,
            user_email.is_some(),
            !magic_link_disabled(&state),
        );
    }

    // Phase 3 — TOTP. Only enforced on new devices when enabled.
    if totp_enabled && !device_known {
        match &req.totp_code {
            None => {
                return Ok(Json(serde_json::json!({
                    "error": "TOTP code required",
                    "totp_required": true
                })));
            }
            Some(code) => {
                verify_totp_or_backup(&state, &req.username, code)?;
            }
        }
    }

    // Phase 4 — register this device as trusted (if fp provided) and issue JWT.
    if !req.device_fp.is_empty() {
        let db = state.db.lock().unwrap();
        if device_known {
            let _ = db.touch_device(&req.username, &req.device_fp);
        } else {
            let _ = db.register_device(&req.username, &req.device_fp, &req.device_label);
        }
    }

    let token = create_jwt(&state.jwt_secret, &req.username)?;
    Ok(Json(serde_json::json!({
        "token": token,
        "must_change_password": must_change,
        "totp_enabled": totp_enabled,
        "role": role
    })))
}

// Check a 6-digit TOTP code only (used by 2FA enable/disable paths where
// backup codes are not accepted).
fn verify_totp_code(
    state: &AppState,
    username: &str,
    code: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let db = state.db.lock().unwrap();
    let secret_b32 = db
        .get_user_totp_secret(username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::INTERNAL_SERVER_ERROR, "TOTP secret missing"))?;
    let secret_bytes = Secret::Encoded(secret_b32)
        .to_bytes()
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some("Susi License Server".into()),
        username.to_string(),
    )
    .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    if !totp.check_current(code).unwrap_or(false) {
        return Err(error_response(StatusCode::UNAUTHORIZED, "Invalid TOTP code"));
    }
    Ok(())
}

// Verify either a 6-digit TOTP or a backup code. Backup codes are consumed
// on success. Used by login + magic-exchange, where the user may have lost
// their authenticator.
fn verify_totp_or_backup(
    state: &AppState,
    username: &str,
    code: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let trimmed = code.trim();
    // TOTP is always exactly 6 digits. Anything else is treated as a backup code.
    if trimmed.len() == 6 && trimmed.chars().all(|c| c.is_ascii_digit()) {
        return verify_totp_code(state, username, trimmed);
    }
    // Backup-code path — strip separators users might type in (space or dash).
    let normalized: String = trimmed
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_uppercase();
    if normalized.is_empty() {
        return Err(error_response(StatusCode::UNAUTHORIZED, "Invalid 2FA code"));
    }
    let candidates = {
        let db = state.db.lock().unwrap();
        db.list_unused_backup_codes(username)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    for (id, hash) in candidates {
        let Ok(parsed) = PasswordHash::new(&hash) else { continue };
        if Argon2::default()
            .verify_password(normalized.as_bytes(), &parsed)
            .is_ok()
        {
            let db = state.db.lock().unwrap();
            let consumed = db
                .consume_backup_code(id)
                .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
            if consumed {
                return Ok(());
            } else {
                // Race: someone else just used this code. Treat as failure;
                // the user can try another backup code.
                break;
            }
        }
    }
    Err(error_response(StatusCode::UNAUTHORIZED, "Invalid 2FA code"))
}

// Generate N fresh backup codes. Each is 10 characters from an unambiguous
// alphabet (no 0/O/1/I/L), displayed to the user in "XXXXX-XXXXX" form.
// ~50 bits of entropy per code — plenty given login rate limiting.
fn generate_backup_codes(n: usize) -> Vec<String> {
    const ALPHA: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..n)
        .map(|_| {
            (0..10)
                .map(|_| ALPHA[rng.gen_range(0..ALPHA.len())] as char)
                .collect::<String>()
        })
        .collect()
}

fn format_backup_code_for_display(code: &str) -> String {
    // Insert a dash in the middle so it's easier to read/type.
    if code.len() == 10 {
        format!("{}-{}", &code[..5], &code[5..])
    } else {
        code.to_string()
    }
}

fn hash_backup_code(code: &str) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let salt = SaltString::generate(&mut rand::thread_rng());
    Argon2::default()
        .hash_password(code.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))
}

// Exchange a magic-link token for a JWT. Also registers the device as trusted.
#[derive(Deserialize)]
struct MagicExchangeRequest {
    token: String,
    #[serde(default)]
    totp_code: Option<String>,
}

async fn handle_magic_exchange(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<MagicExchangeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let ip = client_ip(peer, &headers);
    check_login_rate_limit(&state, ip)?;

    let token_hash = hash_token(&req.token);

    // Peek first so we can surface a TOTP prompt without consuming the token.
    // Consuming on the first call would leave a TOTP-enabled user stuck if
    // they clicked the link and then had to fetch their auth-app code.
    let row = {
        let db = state.db.lock().unwrap();
        db.peek_login_token(&token_hash)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    let row = row.ok_or_else(|| {
        error_response(StatusCode::UNAUTHORIZED, "Link is invalid, already used, or expired")
    })?;

    let (must_change, role, totp_enabled) = {
        let db = state.db.lock().unwrap();
        (
            db.user_must_change_password(&row.username).unwrap_or(false),
            db.get_user_role(&row.username).unwrap_or_else(|_| "user".into()),
            db.user_totp_enabled(&row.username).unwrap_or(false),
        )
    };
    if totp_enabled {
        let Some(code) = req.totp_code.as_deref() else {
            return Ok(Json(serde_json::json!({
                "error": "TOTP code required",
                "totp_required": true,
                "token": req.token,
            })));
        };
        verify_totp_or_backup(&state, &row.username, code)?;
    }

    // All gates passed — NOW consume the token (atomic flip; guards against
    // a concurrent second click). Anything below this point must succeed,
    // since after consumption a retry would fail.
    let consumed = {
        let db = state.db.lock().unwrap();
        db.consume_login_token(&token_hash)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    if consumed.is_none() {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "Link is invalid, already used, or expired",
        ));
    }

    // Trust this device going forward.
    if !row.device_fp.is_empty() {
        let db = state.db.lock().unwrap();
        let _ = db.register_device(&row.username, &row.device_fp, &row.device_label);
    }

    let jwt = create_jwt(&state.jwt_secret, &row.username)?;
    Ok(Json(serde_json::json!({
        "token": jwt,
        "must_change_password": must_change,
        "totp_enabled": totp_enabled,
        "role": role,
        "username": row.username,
    })))
}

async fn handle_auth_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    let db = state.db.lock().unwrap();
    let must_change = db.user_must_change_password(&principal.username).unwrap_or(false);
    let totp_enabled = db.user_totp_enabled(&principal.username).unwrap_or(false);
    let role = db.get_user_role(&principal.username).unwrap_or_else(|_| "user".into());
    let email = db.get_user_email(&principal.username).ok().flatten();
    let backup_codes_remaining = db.count_unused_backup_codes(&principal.username).unwrap_or(0);
    let must_enable_totp = role == "admin" && !totp_enabled;
    Ok(Json(serde_json::json!({
        "must_change_password": must_change,
        "totp_enabled": totp_enabled,
        "username": principal.username,
        "role": role,
        "email": email,
        "magic_link_enabled": !magic_link_disabled(&state),
        "must_enable_totp": must_enable_totp,
        "backup_codes_remaining": backup_codes_remaining,
    })))
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

async fn handle_change_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;

    if req.new_password.len() < 8 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Password must be at least 8 characters"));
    }

    let hash = {
        let db = state.db.lock().unwrap();
        db.get_user_password_hash(&principal.username)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };

    if !verify_password(&req.current_password, &hash).await? {
        return Err(error_response(StatusCode::UNAUTHORIZED, "Current password is incorrect"));
    }

    let new_hash = hash_password(&req.new_password).await?;
    {
        let db = state.db.lock().unwrap();
        db.update_user_password(&principal.username, &new_hash)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    }

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

// ---------------------------------------------------------------------------
// Password reset (forgot-password) flow
// ---------------------------------------------------------------------------
//
// 1. POST /auth/forgot-password { identifier } — identifier is either a
//    username or an email address. Always responds 200 (no enumeration).
//    If the account is found and has an email and SMTP is configured, a
//    one-time reset link is sent to the on-file address.
// 2. User clicks the link, lands at /#/reset/<token>. Frontend prompts for a
//    new password and POSTs it to /auth/reset-password.
// 3. POST /auth/reset-password { token, new_password } — consumes the token,
//    updates the password, clears must_change_password (since the user just
//    proved control of the inbox).
//
// Reset tokens are stored in `login_tokens` with kind='reset' so they can't
// be replayed against the magic-link-sign-in endpoint.

const PASSWORD_RESET_TTL_MINUTES: i64 = 30;

#[derive(Deserialize)]
struct ForgotPasswordRequest {
    /// Username OR email — users may not remember their login name.
    identifier: String,
}

async fn handle_forgot_password(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ForgotPasswordRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let ip = client_ip(peer, &headers);
    check_login_rate_limit(&state, ip)?;

    // Generic OK response — never leak whether identifier/email/SMTP are set up.
    let ok = || Json(serde_json::json!({ "status": "OK" }));

    let identifier = req.identifier.trim().to_string();
    if identifier.is_empty() {
        return Ok(ok());
    }
    if magic_link_disabled(&state) {
        return Ok(ok());
    }

    // Resolve identifier → (username, email). Anything containing '@' is
    // treated as an email; otherwise as a username.
    let (username, email_addr) = {
        let db = state.db.lock().unwrap();
        let resolved = if identifier.contains('@') {
            db.find_unique_username_by_email(&identifier).ok().flatten()
        } else if db.user_exists(&identifier).unwrap_or(false) {
            Some(identifier.clone())
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
        let db = state.db.lock().unwrap();
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

#[derive(Deserialize)]
struct ResetPasswordSubmitRequest {
    token: String,
    new_password: String,
}

async fn handle_reset_password_submit(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ResetPasswordSubmitRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    if req.new_password.len() < 8 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Password must be at least 8 characters"));
    }
    let token_hash = hash_token(&req.token);
    let new_hash = hash_password(&req.new_password).await?;

    let db = state.db.lock().unwrap();
    let username = db
        .consume_password_reset_token(&token_hash)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "Link is invalid, already used, or expired"))?;
    db.update_user_password(&username, &new_hash)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "OK", "username": username })))
}

async fn handle_setup_2fa(
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

    let db = state.db.lock().unwrap();
    db.set_user_totp_secret(&principal.username, &secret_b32)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({
        "secret": secret_b32,
        "qr_code": format!("data:image/png;base64,{}", qr_code),
        "otpauth_uri": totp.get_url()
    })))
}

#[derive(Deserialize)]
struct TotpCodeRequest {
    totp_code: String,
}

async fn handle_verify_2fa(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<TotpCodeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;

    let db = state.db.lock().unwrap();
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

    // Generate fresh backup codes atomically with enable — the user should
    // see them once, right now, and have no chance of losing access later
    // because they never saved them.
    let raw_codes = generate_backup_codes(8);
    let mut hashes = Vec::with_capacity(raw_codes.len());
    for c in &raw_codes {
        hashes.push(hash_backup_code(c)?);
    }
    {
        let db = state.db.lock().unwrap();
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

async fn handle_disable_2fa(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<TotpCodeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;

    let db = state.db.lock().unwrap();
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
    // Wipe backup codes too — they were bound to the (now gone) 2FA factor.
    let _ = db.clear_backup_codes(&principal.username);

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

// Regenerate backup codes. Password-gated so a stolen session alone can't
// rotate them out from under the real user.
#[derive(Deserialize)]
struct RegenerateBackupCodesRequest {
    current_password: String,
}

async fn handle_regenerate_backup_codes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<RegenerateBackupCodesRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;

    let (hash, totp_enabled) = {
        let db = state.db.lock().unwrap();
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
        let db = state.db.lock().unwrap();
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

// ---------------------------------------------------------------------------
// CA pinning helpers
// ---------------------------------------------------------------------------

/// Decode the first PEM block in `text` to raw DER bytes.
fn pem_to_der(text: &str) -> anyhow::Result<Vec<u8>> {
    let b64: String = text.lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .context("base64 decode of PEM body failed")
}

/// Decode a `signing_cert_chain` request field (base64-encoded DER strings)
/// into raw DER bytes. Returns a 403 error response if the field is missing
/// or contains invalid base64.
fn decode_cert_chain(
    chain: Option<&[String]>,
) -> Result<Vec<Vec<u8>>, (StatusCode, Json<ErrorResponse>)> {
    let strings = match chain {
        Some(v) if !v.is_empty() => v,
        _ => return Err(error_response(
            StatusCode::FORBIDDEN,
            "Binary signing certificate chain required by server policy but not provided",
        )),
    };
    use base64::Engine;
    let mut result = Vec::with_capacity(strings.len());
    for b64 in strings {
        let der = base64::engine::general_purpose::STANDARD.decode(b64)
            .map_err(|_| error_response(
                StatusCode::FORBIDDEN,
                "Invalid base64 in signing certificate chain",
            ))?;
        result.push(der);
    }
    Ok(result)
}

/// Return `true` if at least one cert in `chain_der` was signed by the public
/// key in `ca_der`.  Accepts any ordering of certs in the chain.
///
/// Supports RSA (PKCS#1v15 with SHA-256 or SHA-384 or SHA-512) and ECDSA
/// (P-256 or P-384 with SHA-256 or SHA-384) signing algorithms, which covers
/// the algorithms used by all major commercial code-signing CAs.
fn verify_chain_to_ca(chain_der: &[Vec<u8>], ca_der: &[u8]) -> bool {
    use x509_cert::Certificate;
    use x509_cert::der::{Decode, Encode};

    // OIDs for common signature algorithms
    const SHA256_WITH_RSA:     &str = "1.2.840.113549.1.1.11";
    const SHA384_WITH_RSA:     &str = "1.2.840.113549.1.1.12";
    const SHA512_WITH_RSA:     &str = "1.2.840.113549.1.1.13";
    const ECDSA_WITH_SHA256:   &str = "1.2.840.10045.4.3.2";
    const ECDSA_WITH_SHA384:   &str = "1.2.840.10045.4.3.3";

    let ca_cert = match Certificate::from_der(ca_der) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let ca_spki_der = match ca_cert.tbs_certificate.subject_public_key_info.to_der() {
        Ok(d) => d,
        Err(_) => return false,
    };

    for cert_der in chain_der {
        let cert = match Certificate::from_der(cert_der) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let tbs_raw = match cert.tbs_certificate.to_der() {
            Ok(b) => b,
            Err(_) => continue,
        };
        let sig_bytes = cert.signature.raw_bytes();
        let alg_oid = cert.signature_algorithm.oid.to_string();

        let verified = match alg_oid.as_str() {
            SHA256_WITH_RSA | SHA384_WITH_RSA | SHA512_WITH_RSA => {
                verify_rsa(&ca_spki_der, &tbs_raw, sig_bytes, &alg_oid)
            }
            ECDSA_WITH_SHA256 | ECDSA_WITH_SHA384 => {
                verify_ecdsa(&ca_spki_der, &tbs_raw, sig_bytes, &alg_oid)
            }
            _ => false,
        };

        if verified { return true; }
    }
    false
}

fn verify_rsa(ca_spki_der: &[u8], tbs: &[u8], sig: &[u8], alg_oid: &str) -> bool {
    use rsa::RsaPublicKey;
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::signature::Verifier;
    use pkcs8::DecodePublicKey;

    const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
    const SHA384_WITH_RSA: &str = "1.2.840.113549.1.1.12";

    let ca_pub = match RsaPublicKey::from_public_key_der(ca_spki_der) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig_obj = match rsa::pkcs1v15::Signature::try_from(sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    match alg_oid {
        SHA256_WITH_RSA => VerifyingKey::<rsa::sha2::Sha256>::new(ca_pub).verify(tbs, &sig_obj).is_ok(),
        SHA384_WITH_RSA => VerifyingKey::<rsa::sha2::Sha384>::new(ca_pub).verify(tbs, &sig_obj).is_ok(),
        _               => VerifyingKey::<rsa::sha2::Sha512>::new(ca_pub).verify(tbs, &sig_obj).is_ok(),
    }
}

fn verify_ecdsa(ca_spki_der: &[u8], tbs: &[u8], sig: &[u8], alg_oid: &str) -> bool {
    // Use ring for ECDSA verification — it is already in the dependency graph
    // via rcgen.
    use ring::signature::{self, UnparsedPublicKey};

    const ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";

    // ring needs the raw public key bits from the SPKI, not the full SPKI DER.
    // We extract the SubjectPublicKey bit-string from the SPKI using x509-cert.
    use x509_cert::der::Decode;
    use spki::SubjectPublicKeyInfoRef;
    let spki = match SubjectPublicKeyInfoRef::from_der(ca_spki_der) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let pub_key_bytes = spki.subject_public_key.raw_bytes();

    let alg = if alg_oid == ECDSA_WITH_SHA256 {
        &signature::ECDSA_P256_SHA256_ASN1
    } else {
        &signature::ECDSA_P384_SHA384_ASN1
    };

    UnparsedPublicKey::new(alg, pub_key_bytes).verify(tbs, sig).is_ok()
}

// ---------------------------------------------------------------------------
// Public endpoints (client-facing)
// ---------------------------------------------------------------------------

/// How long an admin-initiated machine removal blocks silent self-reactivation.
const TOMBSTONE_TTL_HOURS: i64 = 24;

fn compute_lease_expires(license: &License) -> Option<DateTime<Utc>> {
    if license.lease_duration_hours == 0 {
        None
    } else {
        Some(Utc::now() + Duration::hours(license.lease_duration_hours as i64))
    }
}

async fn handle_activate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ActivateRequest>,
) -> Result<Json<susi_core::SignedLicense>, (StatusCode, Json<ErrorResponse>)> {
    // Hold the lock only for the DB-bound section; release before the RSA
    // sign so the heartbeat path doesn't serialise every other request.
    let license = {
        let db = state.db.lock().unwrap();

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

        if let Some(ca_der) = &state.trusted_signing_ca {
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

async fn handle_verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<susi_core::SignedLicense>, (StatusCode, Json<ErrorResponse>)> {
    let license = {
        let db = state.db.lock().unwrap();

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

        if let Some(ca_der) = &state.trusted_signing_ca {
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

async fn handle_deactivate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DeactivateRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let db = state.db.lock().unwrap();

    let license = db
        .get_license_by_key(&req.license_key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License key not found"))?;

    db.remove_machine_activation(&license.id, &req.machine_code)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "deactivated" })))
}

#[derive(Serialize)]
struct PublicLicenseStatus {
    license_key: String,
    product: String,
    customer: String,
    expires: String,
    features: Vec<String>,
    max_machines: u32,
    active_machines: Vec<PublicMachineSummary>,
    revoked: bool,
}

#[derive(Serialize)]
struct PublicMachineSummary {
    machine_code: String,
    friendly_name: String,
    lease_expires_at: Option<String>,
    lease_active: bool,
}

async fn handle_license_status(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> Result<Json<PublicLicenseStatus>, (StatusCode, Json<ErrorResponse>)> {
    let db = state.db.lock().unwrap();

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

// ---------------------------------------------------------------------------
// Admin endpoints
// ---------------------------------------------------------------------------

async fn handle_list_licenses(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<LicenseSummary>>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock().unwrap();
    let licenses = db
        .list_licenses()
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let summaries: Vec<LicenseSummary> = licenses.iter().map(license_to_summary).collect();
    Ok(Json(summaries))
}

async fn handle_get_license(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<Json<LicenseSummary>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock().unwrap();
    let license = db
        .get_license_by_key(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License key not found"))?;

    Ok(Json(license_to_summary(&license)))
}

async fn handle_create_license(
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

    let db = state.db.lock().unwrap();
    db.insert_license(&license)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok((StatusCode::CREATED, Json(license_to_summary(&license))))
}

async fn handle_revoke_license(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock().unwrap();
    let revoked = db
        .revoke_license(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    if !revoked {
        return Err(error_response(StatusCode::NOT_FOUND, "License key not found"));
    }

    Ok(Json(serde_json::json!({ "status": "revoked" })))
}

async fn handle_delete_license(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock().unwrap();
    let deleted = db
        .delete_license(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    if !deleted {
        return Err(error_response(StatusCode::NOT_FOUND, "License key not found"));
    }

    Ok(Json(serde_json::json!({ "status": "deleted" })))
}

async fn handle_update_license(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Json(req): Json<UpdateLicenseRequest>,
) -> Result<Json<LicenseSummary>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock().unwrap();
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

    Ok(Json(license_to_summary(&updated)))
}

async fn handle_export_license(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Json(req): Json<ExportRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock().unwrap();
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

    // Re-fetch with the activation
    let license = db
        .get_license_by_key(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .unwrap();

    let payload = license.to_payload_for(Some(&req.machine_code));
    let signed = sign_license(&state.private_key, &payload)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let json = serde_json::to_string_pretty(&signed)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"license.json\"",
            ),
        ],
        json,
    ))
}

async fn handle_export_token(
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

    let db = state.db.lock().unwrap();
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

async fn handle_deactivate_machine(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((key, machine_code)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock().unwrap();
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
async fn handle_clear_machine_tombstone(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((key, machine_code)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock().unwrap();
    let license = db
        .get_license_by_key(&key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License key not found"))?;

    db.clear_machine_tombstone(&license.id, &machine_code)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "cleared" })))
}

// ---------------------------------------------------------------------------
// User management endpoints
// ---------------------------------------------------------------------------

async fn handle_list_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<susi_core::db::UserInfo>>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    let db = state.db.lock().unwrap();
    let users = db
        .list_users()
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    Ok(Json(users))
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
    #[serde(default = "default_user_role")]
    role: String,
    email: String,
}

fn default_user_role() -> String {
    "user".to_string()
}

async fn handle_create_user(
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
    if req.password.len() < 8 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Password must be at least 8 characters"));
    }
    if !matches!(req.role.as_str(), "admin" | "user") {
        return Err(error_response(StatusCode::BAD_REQUEST, "Role must be admin or user"));
    }
    let email = normalize_email(&req.email)?
        .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, "Email is required"))?;

    let pw_hash = hash_password(&req.password).await?;
    let db = state.db.lock().unwrap();
    db.create_user(username, &pw_hash, &req.role)
        .map_err(|e| error_response(StatusCode::CONFLICT, &e.to_string()))?;
    db.set_user_email(username, Some(&email))
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({
        "status": "OK",
        "username": username,
        "role": req.role,
        "email": email,
    })))
}

async fn handle_delete_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    if principal.username == username {
        return Err(error_response(StatusCode::BAD_REQUEST, "Cannot delete your own account"));
    }

    let db = state.db.lock().unwrap();
    db.delete_user(&username)
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

#[derive(Deserialize)]
struct RenameUserRequest {
    new_username: String,
}

async fn handle_rename_user(
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

    let db = state.db.lock().unwrap();
    if db.user_exists(&new).unwrap_or(false) {
        return Err(error_response(StatusCode::CONFLICT, "Username already taken"));
    }
    db.rename_user(&username, &new)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

#[derive(Deserialize)]
struct ResetPasswordRequest {
    new_password: String,
}

async fn handle_reset_user_password(
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
    let db = state.db.lock().unwrap();
    db.reset_user_password(&username, &pw_hash)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

// ---------------------------------------------------------------------------
// API tokens (long-lived bearer tokens for service accounts)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateApiTokenRequest {
    name: String,
}

fn generate_api_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("{}{}", API_TOKEN_PREFIX, hex::encode(bytes))
}

async fn handle_create_api_token(
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
        let db = state.db.lock().unwrap();
        db.insert_api_token(&principal.username, name, &token_hash, &prefix)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };

    log::info!("API token '{}' (id={}) created by {}", name, id, principal.username);

    Ok(Json(serde_json::json!({
        "id": id,
        "name": name,
        "token": raw,
        "token_prefix": prefix,
    })))
}

async fn handle_list_my_api_tokens(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<susi_core::db::ApiTokenInfo>>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    let db = state.db.lock().unwrap();
    let rows = db
        .list_api_tokens_for_user(&principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    Ok(Json(rows))
}

async fn handle_revoke_my_api_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    if principal.source != AuthSource::Jwt {
        return Err(error_response(StatusCode::FORBIDDEN, "API tokens can only be managed from a browser session"));
    }
    let owner = {
        let db = state.db.lock().unwrap();
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
        let db = state.db.lock().unwrap();
        db.revoke_api_token(id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    if !revoked {
        return Err(error_response(StatusCode::CONFLICT, "Token already revoked"));
    }
    api_token_cache_clear();
    log::info!("API token id={} revoked by {}", id, principal.username);
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

async fn handle_list_all_api_tokens(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<susi_core::db::ApiTokenInfo>>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    let db = state.db.lock().unwrap();
    let rows = db
        .list_all_api_tokens()
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    Ok(Json(rows))
}

async fn handle_revoke_any_api_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    let revoked = {
        let db = state.db.lock().unwrap();
        db.revoke_api_token(id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    if !revoked {
        return Err(error_response(StatusCode::CONFLICT, "Token already revoked or not found"));
    }
    api_token_cache_clear();
    log::info!("API token id={} revoked by admin {}", id, principal.username);
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

// ---------------------------------------------------------------------------
// Email + trusted devices
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SetEmailRequest {
    /// Pass `null` or empty string to clear.
    #[serde(default)]
    email: Option<String>,
}

fn normalize_email(raw: &str) -> Result<Option<String>, (StatusCode, Json<ErrorResponse>)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    // Very light validation — the real check is "does the magic link arrive".
    // We just catch obvious typos so we don't store garbage.
    if !trimmed.contains('@') || trimmed.contains(' ') || trimmed.len() > 254 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Invalid email address"));
    }
    Ok(Some(trimmed.to_string()))
}

async fn handle_set_my_email(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SetEmailRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    let normalized = match req.email.as_deref() {
        Some(s) => normalize_email(s)?,
        None => None,
    };
    let db = state.db.lock().unwrap();
    db.set_user_email(&principal.username, normalized.as_deref())
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    Ok(Json(serde_json::json!({ "status": "OK", "email": normalized })))
}

async fn handle_set_user_email(
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
    let db = state.db.lock().unwrap();
    if !db.user_exists(&username).unwrap_or(false) {
        return Err(error_response(StatusCode::NOT_FOUND, "User not found"));
    }
    db.set_user_email(&username, normalized.as_deref())
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    Ok(Json(serde_json::json!({ "status": "OK", "email": normalized })))
}

async fn handle_list_my_devices(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<susi_core::db::DeviceInfo>>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    let db = state.db.lock().unwrap();
    let devices = db
        .list_devices(&principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    Ok(Json(devices))
}

async fn handle_revoke_my_device(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(fingerprint): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    let db = state.db.lock().unwrap();
    let removed = db
        .revoke_device(&principal.username, &fingerprint)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Device not found"));
    }
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

// ---------------------------------------------------------------------------
// Release endpoints
// ---------------------------------------------------------------------------

fn validate_license_key(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let key = headers
        .get("x-license-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if key.is_empty() {
        return Err(error_response(StatusCode::UNAUTHORIZED, "Missing X-License-Key header"));
    }

    let db = state.db.lock().unwrap();
    let license = db
        .get_license_by_key(key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "Invalid license key"))?;

    if license.revoked {
        return Err(error_response(StatusCode::FORBIDDEN, "License has been revoked"));
    }
    if license.is_expired() {
        return Err(error_response(StatusCode::FORBIDDEN, "License has expired"));
    }

    Ok(())
}

fn releases_dir(state: &AppState) -> std::path::PathBuf {
    std::path::Path::new(&state.data_dir).join("releases")
}

/// List releases — available to licensed clients or authenticated users
async fn handle_get_releases(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // Accept either license key or bearer token
    if validate_license_key(&state, &headers).is_err() {
        validate_principal(&headers, &state)?;
    }

    let (rows, mut assets_by_id) = {
        let db = state.db.lock().unwrap();
        let rows = db
            .list_releases()
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        let ids: Vec<i64> = rows.iter().filter(|r| r.6.is_none()).map(|r| r.0).collect();
        let assets_by_id = db.get_assets_for_releases(&ids).unwrap_or_default();
        (rows, assets_by_id)
    };

    let mut releases = Vec::new();
    for (id, tag, name, body, prerelease, created_at, workspace_id) in &rows {
        if workspace_id.is_some() { continue; }
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

/// Verify the caller is allowed to download `tag`. Returns the principal
/// username if authentication used a bearer token, or `"license"` if it used a
/// license key. Encapsulates the license/principal + workspace membership
/// rules shared by the download endpoint and the ticket mint endpoint.
fn authorize_release_download(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    tag: &str,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let license_ok = validate_license_key(state, headers).is_ok();
    let principal_opt = validate_principal(headers, state).ok();
    if !license_ok && principal_opt.is_none() {
        return Err(error_response(StatusCode::UNAUTHORIZED, "Authentication required"));
    }

    let scoped_ws = {
        let db = state.db.lock().unwrap();
        db.get_release_workspace_id(tag)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .flatten()
    };
    if let Some(ws_id) = scoped_ws {
        let principal = principal_opt.as_ref()
            .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Workspace membership required"))?;
        let db = state.db.lock().unwrap();
        let is_admin = db.get_user_role(&principal.username)
            .map(|r| r == "admin")
            .unwrap_or(false);
        if !is_admin {
            let role = db.get_workspace_member_role(&ws_id, &principal.username)
                .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
            if role.is_none() {
                return Err(error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"));
            }
        }
    }

    Ok(principal_opt
        .map(|p| p.username)
        .unwrap_or_else(|| "license".into()))
}

#[derive(Deserialize)]
struct DownloadTicketRequest {
    tag: String,
    asset: String,
}

/// Mint a short-lived, single-asset ticket the browser can include as a query
/// parameter on the download URL — needed because `<a href>` clicks can't
/// attach Authorization headers, but only `<a href>`-style navigation hands
/// the response off to the browser's native download UI.
async fn handle_mint_download_ticket(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<DownloadTicketRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let safe_tag = docs::safe_tag(&body.tag)?;
    let safe_asset = docs::safe_filename(&body.asset)?;
    let sub = authorize_release_download(&state, &headers, &safe_tag)?;
    let ticket = mint_download_ticket(&state.jwt_secret, &sub, &safe_tag, &safe_asset)?;
    Ok(Json(serde_json::json!({
        "ticket": ticket,
        "expires_in": DOWNLOAD_TICKET_TTL_SECS,
    })))
}

#[derive(Deserialize)]
struct DownloadQuery {
    #[serde(default)]
    ticket: Option<String>,
}

async fn handle_download_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((tag, asset_name)): Path<(String, String)>,
    Query(q): Query<DownloadQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    if let Some(ref ticket) = q.ticket {
        validate_download_ticket(&state.jwt_secret, ticket, &tag, &asset_name)?;
    } else {
        authorize_release_download(&state, &headers, &tag)?;
    }

    // Reject traversal / empty / nul before building the path, and confirm the
    // canonicalized result stays inside the releases directory. Defense in depth
    // against a future regression in the name checks.
    let safe_tag = docs::safe_tag(&tag)?;
    let safe_asset = docs::safe_filename(&asset_name)?;

    let base = releases_dir(&state).canonicalize()
        .map_err(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "Releases directory unavailable"))?;
    let file_path = base.join(safe_tag).join(safe_asset);
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

/// List releases — admin view (JWT)
async fn handle_list_releases_admin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let (rows, mut assets_by_id) = {
        let db = state.db.lock().unwrap();
        let rows = db
            .list_releases()
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        let ids: Vec<i64> = rows.iter().map(|r| r.0).collect();
        let assets_by_id = db.get_assets_for_releases(&ids).unwrap_or_default();
        (rows, assets_by_id)
    };

    let mut releases = Vec::with_capacity(rows.len());
    for (id, tag, name, body, prerelease, created_at, workspace_id) in &rows {
        let assets = assets_by_id.remove(id).unwrap_or_default();
        releases.push(serde_json::json!({
            "tag": tag,
            "name": name,
            "body": body,
            "published_at": created_at,
            "prerelease": prerelease,
            "workspace_id": workspace_id,
            "assets": assets.iter().map(|(name, size)| serde_json::json!({
                "name": name,
                "size": size,
            })).collect::<Vec<_>>(),
        }));
    }

    Ok(Json(serde_json::json!({ "releases": releases })))
}

/// Upload a new release — admin only (JWT)
async fn handle_upload_release(
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

    // Upsert release metadata — re-running a release (e.g. a CI retry) must
    // reuse the existing release_id so doc_pages and assets hanging off this
    // release survive. Previously the handler rejected existing tags with 409
    // and the caller was forced to DELETE first, which cascaded and wiped
    // hand-authored documentation pages.
    let (release_id, newly_created) = {
        let db = state.db.lock().unwrap();
        match db.get_release_by_tag(&tag)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        {
            Some(existing_id) => {
                db.update_release_metadata(existing_id, &name, &body, prerelease, workspace_id.as_deref())
                    .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
                (existing_id, false)
            }
            None => {
                let id = db.insert_release(&tag, &name, &body, prerelease, workspace_id.as_deref())
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
        docs::seed_user_docs_into_release(&state, release_id, &tag, workspace_id.as_deref())?;
    }

    // Save files to disk
    let tag_dir = releases_dir(&state).join(&tag);
    std::fs::create_dir_all(&tag_dir)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("Cannot create dir: {}", e)))?;

    let mut asset_names = Vec::new();
    for (file_name, data) in &files {
        let file_path = tag_dir.join(file_name);
        std::fs::write(&file_path, data)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("Write error: {}", e)))?;

        let db = state.db.lock().unwrap();
        db.add_release_asset(release_id, file_name, data.len() as u64)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        asset_names.push(file_name.clone());
    }

    log::info!("Release {} created with assets: {}", tag, asset_names.join(", "));

    Ok(Json(serde_json::json!({
        "status": "OK",
        "tag": tag,
        "assets": asset_names,
    })))
}

#[derive(Deserialize)]
struct UpdateReleaseRequest {
    name: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    prerelease: bool,
}

/// Update a release's metadata (name/body/prerelease) without touching the
/// binary assets or its workspace scope. Admin only (JWT).
async fn handle_update_release(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tag): Path<String>,
    Json(req): Json<UpdateReleaseRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock().unwrap();
    let release_id = db
        .get_release_by_tag(&tag)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Release not found"))?;
    let existing_ws = db
        .get_release_workspace_id(&tag)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .flatten();
    db.update_release_metadata(release_id, &req.name, &req.body, req.prerelease, existing_ws.as_deref())
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

#[derive(Deserialize)]
struct MoveReleaseRequest {
    /// Target workspace id, or empty/null to make the release global.
    #[serde(default)]
    workspace_id: Option<String>,
}

/// Move a release to a different workspace (or to global). Admin only.
/// Files on disk stay put — releases are keyed by tag, not workspace.
async fn handle_move_release(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tag): Path<String>,
    Json(req): Json<MoveReleaseRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let target = req
        .workspace_id
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());

    let db = state.db.lock().unwrap();
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
        .get_release_by_tag(&tag)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Release not found"))?;
    db.set_release_workspace(release_id, target)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    log::info!("Release {} moved to workspace {:?}", tag, target);
    Ok(Json(serde_json::json!({
        "status": "OK",
        "tag": tag,
        "workspace_id": target,
    })))
}

/// Delete a release — admin only (JWT)
async fn handle_delete_release(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tag): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock().unwrap();
    if !db.delete_release(&tag)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    {
        return Err(error_response(StatusCode::NOT_FOUND, "Release not found"));
    }
    drop(db);

    // Remove files from disk
    let tag_dir = releases_dir(&state).join(&tag);
    let _ = std::fs::remove_dir_all(&tag_dir);

    log::info!("Release {} deleted", tag);

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

/// Delete a single binary asset from a release. Admin only (JWT).
async fn handle_delete_release_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((tag, file_name)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    docs::safe_tag(&tag)?;
    docs::safe_filename(&file_name)?;

    let release_id = {
        let db = state.db.lock().unwrap();
        db.get_release_by_tag(&tag)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Release not found"))?
    };
    let removed = {
        let db = state.db.lock().unwrap();
        db.delete_release_asset(release_id, &file_name)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    let _ = std::fs::remove_file(releases_dir(&state).join(&tag).join(&file_name));
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Asset not found"));
    }
    log::info!("Release {} asset {} deleted", tag, file_name);
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

/// Replace a single binary asset on a release with a newly uploaded file.
/// The old asset row + file are removed; the new file is written under its
/// own name (which may differ from the old one). Admin only (JWT).
async fn handle_replace_release_asset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((tag, old_file_name)): Path<(String, String)>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    docs::safe_tag(&tag)?;
    docs::safe_filename(&old_file_name)?;

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
        let db = state.db.lock().unwrap();
        db.get_release_by_tag(&tag)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Release not found"))?
    };

    let tag_dir = releases_dir(&state).join(&tag);
    std::fs::create_dir_all(&tag_dir)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("mkdir: {}", e)))?;
    let new_path = tag_dir.join(&new_file_name);
    std::fs::write(&new_path, &bytes)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("write: {}", e)))?;

    {
        let db = state.db.lock().unwrap();
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

// ---------------------------------------------------------------------------
// Workspace endpoints (JWT-protected)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateWorkspaceRequest {
    name: String,
    #[serde(default)]
    product: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
struct UpdateWorkspaceRequest {
    name: String,
    #[serde(default)]
    product: String,
    #[serde(default)]
    description: String,
    /// Optional: re-assign the "created by" attribution to a different
    /// existing user. Workspace membership is unaffected; this only changes
    /// the display label and is admin-only.
    #[serde(default)]
    created_by: Option<String>,
}

#[derive(Deserialize)]
struct AddMemberRequest {
    username: String,
    #[serde(default = "default_member_role")]
    role: String,
}

fn default_member_role() -> String {
    "viewer".to_string()
}

#[derive(Deserialize)]
struct PushConfigRequest {
    config_json: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
struct UpdateConfigRequest {
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    config_json: Option<String>,
}

async fn handle_create_workspace(
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
    let db = state.db.lock().unwrap();
    db.create_workspace(&id, &req.name, &req.product, &req.description, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    log::info!("Workspace '{}' ({}) created by {}", req.name, id, principal.username);

    Ok((StatusCode::CREATED, Json(serde_json::json!({
        "id": id,
        "name": req.name,
        "product": req.product,
        "description": req.description,
        "created_by": principal.username,
    }))))
}

async fn handle_list_workspaces(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock().unwrap();
    let rows = db.list_workspaces_for_user(&principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let workspaces: Vec<_> = rows.iter().map(|(id, name, product, desc, created_by, created_at, updated_at, role)| {
        serde_json::json!({
            "id": id,
            "name": name,
            "product": product,
            "description": desc,
            "created_by": created_by,
            "created_at": created_at,
            "updated_at": updated_at,
            "role": role,
        })
    }).collect();

    Ok(Json(serde_json::json!({ "workspaces": workspaces })))
}

async fn handle_get_workspace(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock().unwrap();
    let role = db.get_workspace_member_role(&id, &principal.username)
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
        "role": role,
        "members": members.iter().map(|(u, r, a)| serde_json::json!({
            "username": u, "role": r, "added_at": a,
        })).collect::<Vec<_>>(),
    })))
}

async fn handle_update_workspace(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<UpdateWorkspaceRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock().unwrap();
    let role = db.get_workspace_member_role(&id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;
    if role != "owner" && role != "editor" {
        return Err(error_response(StatusCode::FORBIDDEN, "Insufficient permissions"));
    }

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

async fn handle_delete_workspace(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock().unwrap();
    db.delete_workspace(&id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    log::info!("Workspace {} deleted by {}", id, principal.username);
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

// ---------------------------------------------------------------------------
// Workspace member endpoints
// ---------------------------------------------------------------------------

async fn handle_add_workspace_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(req): Json<AddMemberRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock().unwrap();

    if !matches!(req.role.as_str(), "owner" | "editor" | "viewer") {
        return Err(error_response(StatusCode::BAD_REQUEST, "Role must be owner, editor, or viewer"));
    }

    if !db.user_exists(&req.username).unwrap_or(false) {
        return Err(error_response(StatusCode::NOT_FOUND, "User does not exist"));
    }

    db.add_workspace_member(&workspace_id, &req.username, &req.role)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

async fn handle_remove_workspace_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, username)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

    let db = state.db.lock().unwrap();
    db.remove_workspace_member(&workspace_id, &username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

// ---------------------------------------------------------------------------
// Config revision endpoints
// ---------------------------------------------------------------------------

async fn handle_push_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(req): Json<PushConfigRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock().unwrap();
    let role = db.get_workspace_member_role(&workspace_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;
    if role == "viewer" {
        return Err(error_response(StatusCode::FORBIDDEN, "Viewers cannot push configs"));
    }

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

async fn handle_list_configs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock().unwrap();
    db.get_workspace_member_role(&workspace_id, &principal.username)
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

async fn handle_get_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, config_id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock().unwrap();
    db.get_workspace_member_role(&workspace_id, &principal.username)
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

async fn handle_get_latest_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock().unwrap();
    db.get_workspace_member_role(&workspace_id, &principal.username)
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

async fn handle_update_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, config_id)): Path<(String, i64)>,
    Json(req): Json<UpdateConfigRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock().unwrap();
    let role = db.get_workspace_member_role(&workspace_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;
    if role == "viewer" {
        return Err(error_response(StatusCode::FORBIDDEN, "Viewers cannot edit configs"));
    }

    let updated = db.update_config_revision(&workspace_id, config_id, &req.name, &req.description, req.config_json.as_deref())
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    if !updated {
        return Err(error_response(StatusCode::NOT_FOUND, "Config revision not found"));
    }

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

async fn handle_delete_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, config_id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock().unwrap();
    let role = db.get_workspace_member_role(&workspace_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;
    if role == "viewer" {
        return Err(error_response(StatusCode::FORBIDDEN, "Viewers cannot delete configs"));
    }

    let deleted = db.delete_config_revision(&workspace_id, config_id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    if !deleted {
        return Err(error_response(StatusCode::NOT_FOUND, "Config revision not found"));
    }

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

// ---------------------------------------------------------------------------
// Workspace recordings: presigned-URL upload/download to S3.
// ---------------------------------------------------------------------------

/// Lifetime of presigned PUT and GET URLs. 15 min for PUT is enough for a
/// few hundred MB at modest bandwidth; clients should request a fresh URL
/// if they need longer. GET is shorter (5 min) since downloads start
/// immediately after the user clicks.
const RECORDING_PUT_TTL: StdDuration = StdDuration::from_secs(15 * 60);
const RECORDING_GET_TTL: StdDuration = StdDuration::from_secs(5 * 60);
const RECORDING_CONTENT_TYPE: &str = "application/x-ndjson";

#[derive(Deserialize)]
struct InitRecordingRequest {
    file_name: String,
    #[serde(default)]
    description: String,
}

/// Replace anything that isn't an S3-friendly filename character so the
/// object key doesn't surprise downstream tooling. Whitespace collapses to
/// `_`; control chars are dropped.
fn sanitize_filename(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '-' | '_' => out.push(c),
            ' ' | '\t' => out.push('_'),
            _ => {}
        }
    }
    if out.is_empty() { "recording".to_string() } else { out }
}

fn s3_unavailable() -> (StatusCode, Json<ErrorResponse>) {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "S3 storage is not configured on this server",
    )
}

fn assert_workspace_writer(
    state: &AppState,
    workspace_id: &str,
    principal: &Principal,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let db = state.db.lock().unwrap();
    let role = db
        .get_workspace_member_role(workspace_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;
    if role == "viewer" {
        return Err(error_response(StatusCode::FORBIDDEN, "Viewers cannot modify recordings"));
    }
    Ok(())
}

fn assert_workspace_member(
    state: &AppState,
    workspace_id: &str,
    principal: &Principal,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let db = state.db.lock().unwrap();
    db.get_workspace_member_role(workspace_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;
    Ok(())
}

async fn handle_init_recording(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(req): Json<InitRecordingRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    assert_workspace_writer(&state, &workspace_id, &principal)?;

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
        let db = state.db.lock().unwrap();
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

async fn handle_complete_recording(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, recording_id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    assert_workspace_writer(&state, &workspace_id, &principal)?;

    let s3 = state.s3.as_ref().ok_or_else(s3_unavailable)?;

    // Look up the row to learn the s3_key.
    let row = {
        let db = state.db.lock().unwrap();
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
        let db = state.db.lock().unwrap();
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

async fn handle_list_recordings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    assert_workspace_member(&state, &workspace_id, &principal)?;

    let rows = {
        let db = state.db.lock().unwrap();
        db.list_recordings(&workspace_id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };

    Ok(Json(serde_json::json!({ "recordings": rows })))
}

async fn handle_get_recording_download(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, recording_id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    assert_workspace_member(&state, &workspace_id, &principal)?;

    let s3 = state.s3.as_ref().ok_or_else(s3_unavailable)?;

    let row = {
        let db = state.db.lock().unwrap();
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

async fn handle_delete_recording(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, recording_id)): Path<(String, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    assert_workspace_writer(&state, &workspace_id, &principal)?;

    // Tear down DB first to release the s3_key for cleanup; if S3 delete
    // fails the worst case is an orphan object — we log but don't surface.
    let s3_key = {
        let db = state.db.lock().unwrap();
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

// ---------------------------------------------------------------------------
// Workspace federation: channel secret + peer registry
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RegisterPeerRequest {
    host_id: String,
    url: String,
    #[serde(default)]
    label: String,
    /// Peer-side federation scope. Workspace members federate only with
    /// other members that share this exact string. Empty ⇒ isolated.
    #[serde(default)]
    network_id: String,
}

/// Returns the workspace's federation channel secret and the live peer list.
/// Any workspace member (incl. viewers) can read — the secret is the symmetric
/// key for the ZMQ data plane that all member fusionhubs need to participate.
async fn handle_get_workspace_federation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock().unwrap();
    db.get_workspace_member_role(&workspace_id, &principal.username)
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

// ---------------------------------------------------------------------------
// Workspace graph (shared node-graph, version-tracked)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct PutGraphRequest {
    /// Version the editor was loaded with. `None` is only valid for the
    /// very first push of a workspace (no row yet). Mismatch ⇒ 409.
    #[serde(default)]
    expected_version: Option<u32>,
    /// Raw config JSON — same shape the editor exports / loads.
    config: serde_json::Value,
}

/// Returns the workspace's full graph + version, or 404 when no graph has been
/// pushed yet. Any workspace member can read.
async fn handle_get_workspace_graph(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock().unwrap();
    db.get_workspace_member_role(&workspace_id, &principal.username)
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
/// version so the editor can refresh + reapply. Viewers cannot write.
async fn handle_put_workspace_graph(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(req): Json<PutGraphRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock().unwrap();
    let role = db.get_workspace_member_role(&workspace_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;
    if role == "viewer" {
        return Err(error_response(StatusCode::FORBIDDEN, "Viewers cannot edit the workspace graph"));
    }

    let config_str = serde_json::to_string(&req.config)
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("config not serialisable: {}", e)))?;

    match db.upsert_workspace_graph(&workspace_id, req.expected_version, &config_str, &principal.username) {
        Ok(new_version) => Ok(Json(serde_json::json!({ "graph_version": new_version }))),
        Err(susi_core::error::LicenseError::GraphConflict { current }) => Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: format!(
                    "Graph version conflict — current is {}; reload and reapply",
                    current
                ),
            }),
        )),
        Err(e) => Err(error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
    }
}

/// Register (or refresh) a FusionHub peer for this workspace. Idempotent on
/// `(workspace_id, host_id)` — re-registration updates `url`/`label`/`last_seen`.
/// Viewers cannot register peers (read-only role).
async fn handle_register_workspace_peer(
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

    let db = state.db.lock().unwrap();
    let role = db.get_workspace_member_role(&workspace_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;
    if role == "viewer" {
        return Err(error_response(StatusCode::FORBIDDEN, "Viewers cannot register peers"));
    }

    db.upsert_workspace_peer(&workspace_id, &req.host_id, &req.url, &req.label, &req.network_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

/// Remove a FusionHub peer from this workspace. Viewers cannot revoke.
async fn handle_delete_workspace_peer(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workspace_id, host_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock().unwrap();
    let role = db.get_workspace_member_role(&workspace_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;
    if role == "viewer" {
        return Err(error_response(StatusCode::FORBIDDEN, "Viewers cannot remove peers"));
    }

    let removed = db.delete_workspace_peer(&workspace_id, &host_id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Peer not registered"));
    }

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

/// Rotate the workspace's federation channel secret. Forces every connected
/// FusionHub to re-fetch on next poll and rekey. Owner/editor only.
async fn handle_rotate_workspace_federation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let db = state.db.lock().unwrap();
    let role = db.get_workspace_member_role(&workspace_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;
    if role == "viewer" {
        return Err(error_response(StatusCode::FORBIDDEN, "Viewers cannot rotate secrets"));
    }

    let new_secret = db.rotate_workspace_federation_secret(&workspace_id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "OK", "channel_secret": new_secret })))
}

/// List releases visible to a workspace (workspace-specific + global).
async fn handle_workspace_releases(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;

    let (rows, mut assets_by_id) = {
        let db = state.db.lock().unwrap();
        db.get_workspace_member_role(&workspace_id, &principal.username)
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
/// (any role) and site admins may call this; non-members get 403. Mirrors
/// `handle_list_doc_releases` but filtered to one workspace.
async fn handle_list_workspace_doc_releases(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_password_changed(&state, &principal)?;
    if !is_site_admin(&state, &principal) {
        let db = state.db.lock().unwrap();
        db.get_workspace_member_role(&workspace_id, &principal.username)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;
    }

    let db = state.db.lock().unwrap();
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

#[derive(serde::Deserialize)]
struct CreateWorkspaceDocReleaseRequest {
    tag: String,
    #[serde(default)]
    name: String,
}

/// Create a workspace-scoped doc release. Admin-only. Re-using a tag that
/// belongs to a different workspace (or to global) is rejected.
async fn handle_create_workspace_doc_release(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(req): Json<CreateWorkspaceDocReleaseRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;

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
        let db = state.db.lock().unwrap();
        db.get_release_workspace_id(&tag)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    if let Some(ref existing) = existing_ws {
        match existing {
            Some(ws) if ws == &workspace_id => {
                let id = {
                    let db = state.db.lock().unwrap();
                    db.get_release_by_tag(&tag)
                        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
                        .ok_or_else(|| error_response(StatusCode::INTERNAL_SERVER_ERROR, "Release vanished"))?
                };
                // Seeding is INSERT OR IGNORE, so calling again is a no-op
                // when user pages already exist for this release.
                docs::seed_user_docs_into_release(&state, id, &tag, Some(&workspace_id))?;
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
        let db = state.db.lock().unwrap();
        db.insert_release(&tag, &req.name, "", false, Some(&workspace_id))
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    docs::seed_user_docs_into_release(&state, release_id, &tag, Some(&workspace_id))?;

    Ok(Json(serde_json::json!({
        "tag": tag,
        "name": req.name,
        "workspace_id": workspace_id,
        "id": release_id,
    })))
}

// ---------------------------------------------------------------------------
// Dashboard (embedded HTML)
// ---------------------------------------------------------------------------

async fn handle_dashboard() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}

/// Load the JWT secret from disk, or generate and persist one on first boot.
/// Persisting it across restarts means dashboard sessions survive deploys.
fn load_or_create_jwt_secret(data_dir: &str) -> Result<[u8; 32]> {
    let path = std::path::Path::new(data_dir).join("jwt_secret.bin");
    if path.exists() {
        let bytes = std::fs::read(&path)
            .with_context(|| format!("Failed to read JWT secret at {}", path.display()))?;
        if bytes.len() == 32 {
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&bytes);
            log::info!("Loaded JWT secret from {}", path.display());
            return Ok(secret);
        }
        log::warn!("JWT secret at {} has wrong length ({} bytes); regenerating", path.display(), bytes.len());
    }
    let secret: [u8; 32] = rand::random();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&path, secret)
        .with_context(|| format!("Failed to write JWT secret to {}", path.display()))?;
    // Best-effort lock down permissions on Unix; Windows ignores the mode.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    log::info!("Generated new JWT secret and saved to {}", path.display());
    Ok(secret)
}

async fn handle_docs_page() -> Html<&'static str> {
    Html(include_str!("docs.html"))
}


async fn handle_easymde_js() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/javascript; charset=utf-8".parse().unwrap());
    headers.insert(header::CACHE_CONTROL, "public, max-age=604800".parse().unwrap());
    (headers, include_str!("vendor/easymde.min.js"))
}

async fn handle_easymde_css() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "text/css; charset=utf-8".parse().unwrap());
    headers.insert(header::CACHE_CONTROL, "public, max-age=604800".parse().unwrap());
    (headers, include_str!("vendor/easymde.min.css"))
}

async fn handle_health() -> &'static str {
    "OK"
}

async fn handle_features() -> Json<Vec<susi_core::features::FeatureInfo>> {
    Json(susi_core::features::ALL_FEATURES.to_vec())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    log::info!("Loading private key from {}", cli.private_key);
    let priv_pem = std::fs::read_to_string(&cli.private_key)
        .with_context(|| format!("Failed to read private key from {}", cli.private_key))?;
    let private_key = private_key_from_pem(&priv_pem)
        .context("Failed to parse private key")?;

    log::info!("Opening database at {}", cli.db);
    let db = LicenseDb::open(&cli.db).context("Failed to open database")?;

    let default_hash = hash_password("changeme")
        .await
        .map_err(|_| anyhow::anyhow!("Failed to hash default password"))?;
    if db.seed_admin(&default_hash).context("Failed to seed admin")? {
        log::info!("Default admin user created (password: changeme)");
    }
    if db.user_must_change_password("admin").unwrap_or(false) {
        log::warn!("=== Default admin password is active. Change it at the dashboard! ===");
    }

    let jwt_secret = load_or_create_jwt_secret(&cli.data_dir)
        .context("Failed to load or create JWT secret")?;

    // Ensure releases asset directory exists
    let releases_dir = std::path::Path::new(&cli.data_dir).join("releases");
    std::fs::create_dir_all(&releases_dir)
        .with_context(|| format!("Failed to create releases dir at {}", releases_dir.display()))?;
    let docs_dir = std::path::Path::new(&cli.data_dir).join("docs");
    std::fs::create_dir_all(&docs_dir)
        .with_context(|| format!("Failed to create docs dir at {}", docs_dir.display()))?;

    let email_service = if cli.smtp_host.is_empty() {
        log::info!("SMTP not configured (--smtp-host empty) — magic-link login disabled");
        None
    } else if cli.smtp_user.is_empty() || cli.smtp_password.is_empty() || cli.smtp_from_addr.is_empty() {
        log::warn!(
            "--smtp-host set but --smtp-user / --smtp-password / --smtp-from-addr not all set; magic-link disabled"
        );
        None
    } else {
        let cfg = EmailConfig::from_parts(
            cli.smtp_host.clone(),
            cli.smtp_port,
            cli.smtp_user.clone(),
            cli.smtp_password.clone(),
            &cli.smtp_from_name,
            &cli.smtp_from_addr,
        )
        .context("Invalid SMTP configuration")?;
        match EmailService::new(cfg) {
            Ok(svc) => {
                log::info!(
                    "SMTP ready: relay {}:{}, from {} <{}>",
                    cli.smtp_host, cli.smtp_port, cli.smtp_from_name, cli.smtp_from_addr
                );
                Some(svc)
            }
            Err(e) => {
                log::error!("Failed to init SMTP transport: {:#} — magic-link disabled", e);
                None
            }
        }
    };

    if email_service.is_some() && cli.magic_link_base_url.is_empty() {
        log::warn!("SMTP is configured but --magic-link-base-url is empty; magic-link login will NOT be enforced");
    }

    if cli.stripe_secret_key.is_empty() {
        log::info!("Stripe not configured — /api/v1/shop/checkout will respond 503");
    } else {
        log::info!(
            "Stripe configured (key prefix: {})",
            &cli.stripe_secret_key[..cli.stripe_secret_key.len().min(8)],
        );
        if cli.stripe_webhook_secret.is_empty() {
            log::warn!("STRIPE_SECRET_KEY is set but STRIPE_WEBHOOK_SECRET is not — webhook will reject all events");
        }
    }

    let shop_notify_addr = if !cli.shop_notify_addr.is_empty() {
        cli.shop_notify_addr.clone()
    } else {
        cli.smtp_from_addr.clone()
    };

    let http = reqwest::Client::builder()
        .timeout(StdDuration::from_secs(15))
        .build()
        .context("Failed to build HTTP client")?;

    // S3 for workspace recordings. Missing env (bucket/region/creds) is
    // tolerated at startup — the recording endpoints respond 503 instead
    // and the rest of the server stays up.
    let s3_storage = match s3::S3Storage::from_env().await {
        Ok(Some(s)) => {
            log::info!("S3 ready: bucket={}, region={}", s.bucket(), s.region());
            Some(s)
        }
        Ok(None) => {
            log::info!("S3 not configured (SUSI_S3_BUCKET/REGION empty) — recording endpoints will respond 503");
            None
        }
        Err(e) => {
            log::error!("S3 init failed: {:#} — recording endpoints will respond 503", e);
            None
        }
    };

    if cli.contact_to_addr.is_empty() {
        log::info!("Contact form disabled (SUSI_CONTACT_TO_ADDR empty)");
    } else if email_service.is_none() {
        log::warn!("Contact form: SUSI_CONTACT_TO_ADDR is set but SMTP isn't configured — endpoint will respond 503");
    } else if cli.turnstile_secret.is_empty() || cli.turnstile_site_key.is_empty() {
        log::warn!("Contact form enabled with NO captcha (turnstile keys empty) — relying on honeypot + rate-limit only");
    } else {
        log::info!("Contact form enabled, recipient = {}, Turnstile active", cli.contact_to_addr);
    }

    let trusted_signing_ca = match cli.trusted_signing_ca {
        None => None,
        Some(ref path) => {
            let pem_text = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read trusted CA cert from {}", path))?;
            Some(pem_to_der(&pem_text)
                .with_context(|| format!("Failed to decode PEM CA cert from {}", path))?)
        }
    };

    let state = Arc::new(AppState {
        db: Mutex::new(db),
        private_key,
        jwt_secret,
        data_dir: cli.data_dir,
        trusted_signing_ca,
        login_attempts: Mutex::new(HashMap::new()),
        checkout_attempts: Mutex::new(HashMap::new()),
        webhook_attempts: Mutex::new(HashMap::new()),
        contact_attempts: Mutex::new(HashMap::new()),
        email: email_service,
        magic_link_base_url: cli.magic_link_base_url.clone(),
        relay_url: cli.relay_url.clone(),
        stripe_secret_key: cli.stripe_secret_key,
        stripe_webhook_secret: cli.stripe_webhook_secret,
        shop_base_url: if cli.shop_base_url.is_empty() { cli.magic_link_base_url.clone() } else { cli.shop_base_url },
        shop_notify_addr,
        contact_to_addr: cli.contact_to_addr,
        turnstile_secret: cli.turnstile_secret,
        turnstile_site_key: cli.turnstile_site_key,
        http,
        s3: s3_storage,
    });

    // Periodic lease cleanup. Replaces the per-read DELETE that ran inside
    // every `get_license_by_key` call: under load, every heartbeat issued a
    // DELETE on the licenses table competing for the global write lock.
    {
        let state_bg = Arc::clone(&state);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(StdDuration::from_secs(300));
            tick.tick().await; // skip immediate fire
            loop {
                tick.tick().await;
                let removed = {
                    let db = state_bg.db.lock().unwrap();
                    db.cleanup_all_expired_leases().unwrap_or(0)
                };
                if removed > 0 {
                    log::info!("Lease cleanup: removed {} expired activations", removed);
                }
            }
        });
    }

    let app = Router::new()
        // Dashboard
        .route("/", get(handle_dashboard))
        // Public documentation viewer + vendored editor assets
        .route("/docs", get(handle_docs_page))
        .route("/docs/easymde.js", get(handle_easymde_js))
        .route("/docs/easymde.css", get(handle_easymde_css))
        // Public Xikaku website (same EasyMDE assets reused from /docs).
        // Both `/site` and `/site/{slug}` render the same SPA shell with
        // per-page SEO head (title, description, OG, JSON-LD) injected.
        .route("/site", get(website::handle_website_render_root))
        .route("/site/{slug}", get(website::handle_website_render_slug))
        // Brand assets referenced from <head> (og:image, Organization.logo, favicons)
        .route("/static/logo.png", get(website::handle_logo_png))
        .route("/static/logo-dark.png", get(website::handle_logo_dark_png))
        .route("/static/og-image.png", get(website::handle_og_image_png))
        .route("/static/icon.png", get(website::handle_icon_png))
        .route("/static/favicon-32.png", get(website::handle_favicon_32_png))
        .route("/static/favicon-180.png", get(website::handle_favicon_180_png))
        .route("/favicon.ico", get(website::handle_favicon_ico))
        // SEO / AI-crawler endpoints
        .route("/robots.txt", get(website::handle_robots_txt))
        .route("/sitemap.xml", get(website::handle_sitemap_xml))
        .route("/llms.txt", get(website::handle_llms_txt))
        // IndexNow key file — Bing/Yandex/etc. fetch this to verify ownership
        // before accepting our URL update notifications. Lives under /api/v1
        // so the standard nginx /api proxy reaches it without extra routing.
        .route("/api/v1/indexnow/{filename}", get(website::handle_indexnow_key_file))
        // Health
        .route("/health", get(handle_health))
        // Available license features
        .route("/api/v1/features", get(handle_features))
        // Auth endpoints
        .route("/api/v1/auth/login", post(handle_login))
        .route("/api/v1/auth/magic", post(handle_magic_exchange))
        .route("/api/v1/auth/forgot-password", post(handle_forgot_password))
        .route("/api/v1/auth/reset-password", post(handle_reset_password_submit))
        .route("/api/v1/auth/status", get(handle_auth_status))
        .route("/api/v1/auth/change-password", post(handle_change_password))
        .route("/api/v1/auth/setup-2fa", post(handle_setup_2fa))
        .route("/api/v1/auth/verify-2fa", post(handle_verify_2fa))
        .route("/api/v1/auth/disable-2fa", post(handle_disable_2fa))
        .route("/api/v1/auth/regenerate-backup-codes", post(handle_regenerate_backup_codes))
        .route("/api/v1/auth/me/email", axum::routing::put(handle_set_my_email))
        .route("/api/v1/auth/me/devices", get(handle_list_my_devices))
        .route("/api/v1/auth/me/devices/{fingerprint}", axum::routing::delete(handle_revoke_my_device))
        // API tokens (long-lived bearer tokens for headless clients)
        .route("/api/v1/auth/api-tokens", post(handle_create_api_token).get(handle_list_my_api_tokens))
        .route("/api/v1/auth/api-tokens/{id}", axum::routing::delete(handle_revoke_my_api_token))
        .route("/api/v1/auth/api-tokens/all", get(handle_list_all_api_tokens))
        .route("/api/v1/auth/api-tokens/all/{id}", axum::routing::delete(handle_revoke_any_api_token))
        // User management
        .route("/api/v1/auth/users", get(handle_list_users))
        .route("/api/v1/auth/users", post(handle_create_user))
        .route("/api/v1/auth/users/{username}", axum::routing::delete(handle_delete_user))
        .route("/api/v1/auth/users/{username}/email", axum::routing::put(handle_set_user_email))
        .route("/api/v1/auth/users/{username}/rename", post(handle_rename_user))
        .route("/api/v1/auth/users/{username}/reset-password", post(handle_reset_user_password))
        // Public client endpoints
        .route("/api/v1/activate", post(handle_activate))
        .route("/api/v1/verify", post(handle_verify))
        .route("/api/v1/deactivate", post(handle_deactivate))
        .route("/api/v1/licenses/{key}/status", get(handle_license_status))
        // Admin endpoints (JWT-protected)
        .route("/api/v1/licenses", get(handle_list_licenses))
        .route("/api/v1/licenses", post(handle_create_license))
        .route("/api/v1/licenses/{key}", get(handle_get_license).put(handle_update_license).delete(handle_delete_license))
        .route("/api/v1/licenses/{key}/revoke", post(handle_revoke_license))
        .route("/api/v1/licenses/{key}/export", post(handle_export_license))
        .route("/api/v1/licenses/{key}/export-token", post(handle_export_token))
        .route(
            "/api/v1/licenses/{key}/machines/{machine_code}",
            axum::routing::delete(handle_deactivate_machine),
        )
        .route(
            "/api/v1/licenses/{key}/machines/{machine_code}/tombstone",
            axum::routing::delete(handle_clear_machine_tombstone),
        )
        // Releases — client endpoints (license-key protected)
        .route("/api/v1/updates/releases", get(handle_get_releases))
        .route("/api/v1/updates/download/{tag}/{asset}", get(handle_download_asset))
        .route("/api/v1/updates/download-ticket", post(handle_mint_download_ticket))
        // Releases — admin endpoints (JWT protected)
        .route("/api/v1/releases", get(handle_list_releases_admin))
        .merge(
            Router::new()
                .route("/api/v1/releases", post(handle_upload_release))
                .route("/api/v1/releases/{tag}/assets/{file}/replace", post(handle_replace_release_asset))
                .layer(DefaultBodyLimit::max(500 * 1024 * 1024))
        )
        .route("/api/v1/releases/{tag}", axum::routing::put(handle_update_release).delete(handle_delete_release))
        .route("/api/v1/releases/{tag}/move", post(handle_move_release))
        .route("/api/v1/releases/{tag}/assets/{file}", axum::routing::delete(handle_delete_release_asset))
        // Workspace endpoints (JWT protected)
        .route("/api/v1/workspaces", get(handle_list_workspaces).post(handle_create_workspace))
        .route("/api/v1/workspaces/{id}", get(handle_get_workspace).put(handle_update_workspace).delete(handle_delete_workspace))
        .route("/api/v1/workspaces/{id}/members", post(handle_add_workspace_member))
        .route("/api/v1/workspaces/{id}/members/{username}", axum::routing::delete(handle_remove_workspace_member))
        // Config revision endpoints (JWT protected)
        .route("/api/v1/workspaces/{id}/configs", get(handle_list_configs).post(handle_push_config))
        .route("/api/v1/workspaces/{id}/configs/latest", get(handle_get_latest_config))
        .route("/api/v1/workspaces/{id}/configs/{config_id}", get(handle_get_config).put(handle_update_config).delete(handle_delete_config))
        // FusionHub federation: shared channel secret + peer registry
        .route("/api/v1/workspaces/{id}/federation", get(handle_get_workspace_federation))
        .route("/api/v1/workspaces/{id}/federation/rotate", post(handle_rotate_workspace_federation))
        .route("/api/v1/workspaces/{id}/peers", post(handle_register_workspace_peer))
        .route("/api/v1/workspaces/{id}/peers/{host_id}", axum::routing::delete(handle_delete_workspace_peer))
        // Shared workspace graph (one node-graph per workspace, version-tracked
        // for optimistic-lock concurrent edits between member fusionhubs).
        .route("/api/v1/workspaces/{id}/graph", get(handle_get_workspace_graph).put(handle_put_workspace_graph))
        // Workspace recordings: presigned-URL upload/download to S3.
        .route("/api/v1/workspaces/{id}/recordings", get(handle_list_recordings).post(handle_init_recording))
        .route("/api/v1/workspaces/{id}/recordings/{rid}", axum::routing::delete(handle_delete_recording))
        .route("/api/v1/workspaces/{id}/recordings/{rid}/complete", post(handle_complete_recording))
        .route("/api/v1/workspaces/{id}/recordings/{rid}/download", get(handle_get_recording_download))
        .route("/api/v1/workspaces/{id}/releases", get(handle_workspace_releases))
        .route(
            "/api/v1/workspaces/{id}/docs/releases",
            get(handle_list_workspace_doc_releases).post(handle_create_workspace_doc_release),
        )
        // Docs — public read endpoints
        .route("/api/v1/docs/releases", get(docs::handle_list_doc_releases))
        .route("/api/v1/docs/releases/latest", get(docs::handle_latest_doc_release))
        .route("/api/v1/docs/{tag}/pages", get(docs::handle_list_doc_pages))
        .route("/api/v1/docs/{tag}/pages/{slug}", get(docs::handle_get_doc_page))
        .route(
            "/api/v1/docs/{tag}/assets/{file}",
            get(docs::handle_get_doc_asset).delete(docs::handle_delete_doc_asset),
        )
        // Docs — admin write endpoints (JWT). Bulk import + asset upload get the larger body limit.
        .merge(
            Router::new()
                .route("/api/v1/docs/{tag}/import", post(docs::handle_bulk_import_docs))
                .route("/api/v1/docs/{tag}/assets", post(docs::handle_upload_doc_asset))
                .layer(DefaultBodyLimit::max(100 * 1024 * 1024))
        )
        .route(
            "/api/v1/docs/{tag}/pages/{slug}",
            axum::routing::put(docs::handle_upsert_doc_page)
                .delete(docs::handle_delete_doc_page),
        )
        .route(
            "/api/v1/docs/{tag}/pages/{slug}/rename",
            post(docs::handle_rename_doc_page),
        )
        // Website — public read
        .route("/api/v1/website/pages", get(website::handle_list_pages))
        .route("/api/v1/website/pages/{slug}", get(website::handle_get_page))
        .route("/api/v1/website/assets/{file}", get(website::handle_get_asset))
        // Website — admin write (asset upload gets the larger body limit)
        .merge(
            Router::new()
                .route("/api/v1/website/assets", post(website::handle_upload_asset))
                .layer(DefaultBodyLimit::max(100 * 1024 * 1024))
        )
        .route(
            "/api/v1/website/pages/{slug}",
            axum::routing::put(website::handle_upsert_page)
                .delete(website::handle_delete_page),
        )
        .route(
            "/api/v1/website/pages/{slug}/rename",
            post(website::handle_rename_page),
        )
        .route(
            "/api/v1/website/assets/{file}",
            axum::routing::delete(website::handle_delete_asset),
        )
        // Website admin — page revisions (history)
        .route(
            "/api/v1/website/pages/{slug}/revisions",
            get(website::handle_list_page_revisions),
        )
        .route(
            "/api/v1/website/pages/{slug}/revisions/{id}",
            get(website::handle_get_page_revision),
        )
        .route(
            "/api/v1/website/pages/{slug}/revisions/{id}/restore",
            post(website::handle_restore_page_revision),
        )
        // Website admin — asset admin (usage, rename)
        .route(
            "/api/v1/website/admin/assets",
            get(website::handle_list_assets_with_usage),
        )
        // Public contact form
        .route("/api/v1/contact/config", get(contact::handle_get_config))
        .route("/api/v1/contact", post(contact::handle_submit))
        .route(
            "/api/v1/website/assets/{file}/rename",
            post(website::handle_rename_asset),
        )
        // ---- Shop ----
        // Public HTML shell — same shell serves /shop, /shop/{sku}, /shop/success, /shop/cancel.
        .route("/shop", get(shop::handle_shop_page))
        .route("/shop/success", get(shop::handle_shop_page))
        .route("/shop/cancel", get(shop::handle_shop_page))
        .route("/shop/{sku}", get(shop::handle_shop_page))
        // Public JSON API
        .route("/api/v1/shop/products", get(shop::handle_list_products))
        .route("/api/v1/shop/products/{sku}", get(shop::handle_get_product))
        .route("/api/v1/shop/checkout", post(shop::handle_create_checkout_session))
        .route("/api/v1/shop/webhook", post(shop::handle_stripe_webhook))
        // Admin (JWT)
        .route(
            "/api/v1/shop/admin/products",
            get(shop::handle_admin_list_products),
        )
        .route(
            "/api/v1/shop/admin/products/{sku}",
            axum::routing::put(shop::handle_upsert_product)
                .delete(shop::handle_delete_product),
        )
        .route(
            "/api/v1/shop/admin/shipping_rates",
            get(shop::handle_list_shipping_rates_admin)
                .post(shop::handle_create_shipping_rate),
        )
        .route(
            "/api/v1/shop/admin/shipping_rates/{id}",
            axum::routing::put(shop::handle_update_shipping_rate)
                .delete(shop::handle_delete_shipping_rate),
        )
        // Orders (JWT) — Stripe is the source of truth for payment, susi
        // tracks fulfillment state on top of it.
        .route("/api/v1/shop/admin/orders", get(shop::handle_admin_list_orders))
        .route("/api/v1/shop/admin/orders/{id}", get(shop::handle_admin_get_order))
        .route("/api/v1/shop/admin/orders/{id}/ship", post(shop::handle_admin_mark_shipped))
        .route("/api/v1/shop/admin/orders/{id}/notes", axum::routing::put(shop::handle_admin_update_order_notes))
        // Shop settings (JWT) — admin notification recipients, customer email
        // toggles, support contact, etc.
        .route(
            "/api/v1/shop/admin/settings",
            get(shop::handle_admin_get_settings)
                .put(shop::handle_admin_put_settings),
        )
        // Site-wide settings (JWT) — analytics IDs and other site-level config.
        .route(
            "/api/v1/site/admin/settings",
            get(website::handle_admin_get_site_settings)
                .put(website::handle_admin_put_site_settings),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&cli.listen)
        .await
        .with_context(|| format!("Failed to bind to {}", cli.listen))?;

    log::info!("License server listening on {}", cli.listen);
    log::info!("Dashboard: http://{}", cli.listen);
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .context("Server error")?;

    Ok(())
}
