mod docs;
mod website;
mod email;
mod shop;
mod invoice_pdf;
mod contact;
mod s3;
mod auth;
mod backup;
mod client_api;
mod licenses;
mod users;
mod releases;
mod workspaces;
mod tickets;
mod newsletter;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};

use anyhow::{Context, Result};
// Poison-free Mutex: a panic while holding the DB lock must not turn every
// subsequent request into a 500 the way a poisoned std::sync::Mutex would.
use parking_lot::Mutex;
use argon2::{self, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Multipart, Path, Query, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use tower_http::set_header::SetResponseHeaderLayer;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use clap::Parser;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
use susi_core::crypto::{private_key_from_pem, sign_license};
use susi_core::db::{
    is_admin_role, is_owner_role, is_valid_role, LicenseDb, DEFAULT_PRODUCT,
};
use susi_core::{License, DEFAULT_LEASE_DURATION_HOURS, DEFAULT_LEASE_GRACE_HOURS};
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::email::{EmailConfig, EmailService};
#[derive(Parser)]
#[command(name = "susi-server", about = "Susi License Server")]
struct Cli {
    #[command(subcommand)]
    command: Option<CliCommand>,

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
    
    // -------- SMTP / sign-in code settings --------
    //
    // If `smtp_host` is empty, sign-in-code verification is disabled
    // entirely and new devices are accepted without email confirmation
    // (bootstrap mode). Enabling requires `smtp_host`, `smtp_user`,
    // `smtp_password`, and `magic_link_base_url` to all be set
    // (`magic_link_base_url` is still consulted for password-reset and
    // invitation links, which remain link-based).

    /// SMTP relay host (e.g. smtp.gmail.com). Empty = disable sign-in code.
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

    // -------- Newsletter SMTP (deliberately separate credentials) --------
    //
    // Bulk campaign mail does NOT fall back to the SUSI_SMTP_* relay. That
    // relay carries sign-in codes, password resets and invitations; tripping a
    // provider's recipient cap or reputation filter with a campaign would lock
    // users out of the portal. With these unset, newsletter sending is disabled
    // and the send endpoint reports it - never a silent fallback.

    /// SMTP relay host for newsletters. Empty = newsletter sending disabled.
    #[arg(long, env = "SUSI_NEWSLETTER_SMTP_HOST", default_value = "")]
    newsletter_smtp_host: String,

    #[arg(long, env = "SUSI_NEWSLETTER_SMTP_PORT", default_value_t = 587)]
    newsletter_smtp_port: u16,

    #[arg(long, env = "SUSI_NEWSLETTER_SMTP_USER", default_value = "")]
    newsletter_smtp_user: String,

    /// Prefer setting via env.
    #[arg(long, env = "SUSI_NEWSLETTER_SMTP_PASSWORD", default_value = "")]
    newsletter_smtp_password: String,

    #[arg(long, env = "SUSI_NEWSLETTER_SMTP_FROM_NAME", default_value = "Susi by LP-Research")]
    newsletter_smtp_from_name: String,

    #[arg(long, env = "SUSI_NEWSLETTER_SMTP_FROM_ADDR", default_value = "")]
    newsletter_smtp_from_addr: String,

    /// Addresses attempted per minute by the newsletter sender. Kept low by
    /// default: every send opens a full TCP+STARTTLS+AUTH handshake.
    #[arg(long, env = "SUSI_NEWSLETTER_RATE_PER_MIN", default_value_t = 30)]
    newsletter_rate_per_min: u32,

    // -------- Google OAuth for the newsletter relay (optional) --------
    //
    // An alternative to SUSI_NEWSLETTER_SMTP_USER/_PASSWORD: an admin connects
    // a Google Workspace account from the dashboard and susi sends through
    // Gmail with XOAUTH2, so no app password is stored on the host. The
    // gmail.send scope is restricted, so the OAuth client must be an
    // "Internal" app in the Workspace org - an External app would need Google
    // verification. Static SMTP credentials, if set, take precedence.

    /// OAuth client ID (Google Cloud console, application type "Web").
    #[arg(long, env = "SUSI_GOOGLE_CLIENT_ID", default_value = "")]
    google_client_id: String,

    /// OAuth client secret. Prefer setting via env.
    #[arg(long, env = "SUSI_GOOGLE_CLIENT_SECRET", default_value = "")]
    google_client_secret: String,

    /// Comma-separated emails promoted to the `owner` role at every startup.
    ///
    /// Ownership can otherwise only be granted by an existing owner, so this
    /// is how the first one comes into being on a database that predates the
    /// role - and the way back in if the last owner is ever lost. Applied
    /// idempotently; accounts already owners are left alone.
    #[arg(long, env = "SUSI_OWNER_EMAILS", default_value = "")]
    owner_emails: String,

    /// Public base URL where the dashboard is reachable. Used to build the
    /// password-reset and invitation links in outbound email (sign-in itself
    /// uses a code, not a link). Must include scheme, e.g.
    /// `https://susi.lp-research.com`.
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

    // -------- Dropbox backups --------
    //
    // All three must be set to enable the feature; the admin then connects
    // the Dropbox account once via the dashboard (Backups page).

    /// Dropbox app key (scoped app with app-folder access). Empty disables backups.
    #[arg(long, env = "SUSI_DROPBOX_APP_KEY", default_value = "")]
    dropbox_app_key: String,

    /// Dropbox app secret.
    #[arg(long, env = "SUSI_DROPBOX_APP_SECRET", default_value = "")]
    dropbox_app_secret: String,

    /// 64 hex chars (32 bytes). Archives are encrypted with this key before
    /// upload; keep a copy off-server or the backups are unreadable.
    #[arg(long, env = "SUSI_BACKUP_KEY", default_value = "")]
    backup_key: String,

    /// Archive name prefix, distinguishes instances sharing one app folder
    /// (e.g. `prod` / `staging`).
    #[arg(long, env = "SUSI_BACKUP_PREFIX", default_value = "susi")]
    backup_prefix: String,

    /// Comma-separated CIDRs of reverse proxies whose X-Forwarded-For /
    /// X-Real-IP headers are trusted (e.g. `172.28.0.0/24`). Empty keeps the
    /// default: loopback plus all IPv4 private ranges.
    #[arg(long, env = "SUSI_TRUSTED_PROXIES", default_value = "")]
    trusted_proxies: String,

    /// Override Dropbox endpoints (integration tests only).
    #[arg(long, env = "SUSI_DROPBOX_API_BASE", default_value = "https://api.dropboxapi.com", hide = true)]
    dropbox_api_base: String,

    #[arg(long, env = "SUSI_DROPBOX_CONTENT_BASE", default_value = "https://content.dropboxapi.com", hide = true)]
    dropbox_content_base: String,
}

#[derive(clap::Subcommand)]
enum CliCommand {
    /// Decrypt a Dropbox backup archive produced by this server.
    /// Restore: decrypt, then untar into a fresh data volume.
    DecryptBackup {
        /// Path to the downloaded .tar.gz.enc archive.
        input: String,
        /// Output path (default: input without the .enc suffix).
        #[arg(long, short)]
        output: Option<String>,
        /// The 64-hex-char backup key (SUSI_BACKUP_KEY).
        #[arg(long, env = "SUSI_BACKUP_KEY")]
        key: String,
    },
}

struct AppState {
    db: Mutex<LicenseDb>,
    private_key: RsaPrivateKey,
    jwt_secret: [u8; 32],
    data_dir: String,
    /// DER bytes of the trusted code-signing CA cert, if configured.
    trusted_signing_ca: Option<Vec<u8>>,
    login_attempts: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    /// Per-IP limiter for the unauthenticated license client API
    /// (activate / verify / deactivate / status).
    license_attempts: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    /// Per-account wrong-guess timestamps for the emailed sign-in code,
    /// keyed by resolved username (or the raw identifier when unresolvable).
    signin_guesses: Mutex<HashMap<String, Vec<Instant>>>,
    /// Per-account failed password/2FA attempts at login, same keying.
    auth_failures: Mutex<HashMap<String, Vec<Instant>>>,
    checkout_attempts: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    webhook_attempts: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    contact_attempts: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    email: Option<EmailService>,
    /// Separate transport for bulk campaign mail. Never falls back to `email`:
    /// isolating reputation from authentication mail is the whole point.
    newsletter_email: Option<EmailService>,
    newsletter_rate_per_min: u32,
    /// Google OAuth client for the newsletter relay, plus the cached access
    /// token. Only consulted when `newsletter_email` is None.
    google_oauth: newsletter::GoogleOAuthConfig,
    newsletter_token_cache: tokio::sync::Mutex<Option<newsletter::CachedToken>>,
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
    backup: backup::BackupConfig,
    /// Guards against concurrent backup runs (scheduler + manual trigger).
    backup_running: AtomicBool,
    /// Guards against overlapping newsletter drain ticks.
    newsletter_sending: AtomicBool,
    /// Wakes the drain loop the moment a campaign is queued, so Send acts
    /// immediately instead of waiting out the tick interval.
    newsletter_wake: tokio::sync::Notify,
}

// Sign-in code TTL: long enough for a user to switch to their mail client and
// back, short enough that a leaked code is useless a few minutes later.
const SIGNIN_CODE_TTL_MINUTES: i64 = 15;

// Content-Security-Policy applied to every response. 'unsafe-inline' is
// required by the inline-heavy HTML shells; everything else is locked down:
// no external scripts beyond the analytics/captcha allow-list, no plugins,
// no framing of our pages (clickjacking), images from anywhere over https
// (site authors may hotlink), fetches only to self + analytics.
const SECURITY_CSP: &str = "default-src 'self'; \
    script-src 'self' 'unsafe-inline' https://www.googletagmanager.com https://tagassistant.google.com https://www.googleadservices.com https://googleads.g.doubleclick.net https://www.redditstatic.com https://challenges.cloudflare.com; \
    style-src 'self' 'unsafe-inline' https://www.googletagmanager.com; \
    img-src 'self' data: blob: https:; \
    font-src 'self' data:; \
    connect-src 'self' https://*.google-analytics.com https://*.analytics.google.com https://www.googletagmanager.com https://www.googleadservices.com https://*.doubleclick.net https://*.google.com https://*.reddit.com; \
    frame-src 'self' https://www.googletagmanager.com https://www.youtube.com https://player.vimeo.com https://challenges.cloudflare.com https://*.doubleclick.net; \
    object-src 'none'; \
    frame-ancestors 'none'; \
    base-uri 'self'; \
    form-action 'self'";


// Sliding-window rate limit on /api/v1/auth/login - throttles brute force
// against weak passwords and caps credential-stuffing throughput.
const LOGIN_WINDOW: StdDuration = StdDuration::from_secs(60);
const LOGIN_MAX_ATTEMPTS: usize = 10;

// License client API (activate/verify/deactivate/status): unauthenticated,
// so cap per-IP throughput. Verify doubles as the lease heartbeat; a whole
// lab powering on behind one NAT bursts many verifies at once, so the cap is
// generous - it exists to stop scripted abuse, not legitimate fleets.
const LICENSE_API_WINDOW: StdDuration = StdDuration::from_secs(60);
const LICENSE_API_MAX_ATTEMPTS: usize = 60;

// Data-retention windows (GDPR Art 5(1)(e) storage limitation). Enforced by
// the periodic cleanup task.
const AUDIT_LOG_RETENTION_DAYS: i64 = 365;
const KNOWN_DEVICE_RETENTION_DAYS: i64 = 180;
const NEWSLETTER_DELIVERY_RETENTION_DAYS: i64 = 365;
// Orders keep amounts and line items for accounting; customer name, email
// and shipping address are scrubbed once fulfillment disputes are long over.
const SHOP_ORDER_PII_RETENTION_DAYS: i64 = 3 * 365;

/// Known-device trust window: a fingerprint last seen longer ago than this
/// counts as a new device again (fresh sign-in code required).
const DEVICE_TRUST_DAYS: i64 = 30;

/// Sessions idle longer than this are dead even before the JWT's absolute
/// 30-day expiry (ASVS V3.3 inactivity timeout).
const SESSION_IDLE_TIMEOUT_DAYS: i64 = 7;

/// API tokens expire after a year; the dashboard shows the date so owners
/// can rotate in time.
const API_TOKEN_TTL_DAYS: i64 = 365;

// Per-account cap on sign-in-code guesses. The per-IP login limit alone
// can't stop a distributed IP pool from brute-forcing a live 6-digit code
// within its 15-minute TTL; after this many wrong guesses every outstanding
// code for the account is invalidated and the exchange endpoint stays locked
// for the account until the window drains.
const SIGNIN_GUESS_WINDOW: StdDuration =
    StdDuration::from_secs(SIGNIN_CODE_TTL_MINUTES as u64 * 60);
const SIGNIN_MAX_GUESSES: usize = 5;

// Per-account lockout on failed interactive auth (wrong password or wrong
// 2FA code at login). The per-IP limit alone can't stop a distributed IP
// pool from targeting one account.
const ACCOUNT_FAILURE_WINDOW: StdDuration = StdDuration::from_secs(15 * 60);
const ACCOUNT_MAX_FAILURES: usize = 8;

// Shop checkout creates a Stripe Checkout Session per call (outbound API
// cost + DB lock). Cap per-IP burst so a script can't run our Stripe quota
// down or starve the SQLite connection.
const CHECKOUT_WINDOW: StdDuration = StdDuration::from_secs(60);
const CHECKOUT_MAX_ATTEMPTS: usize = 10;

// Generous limit on the Stripe webhook endpoint: legitimate Stripe delivery
// burst-fires retries from a small IP set, so we keep the cap loose. The
// signature check is the real gate - this is just defense in depth against
// spam from a single source.
const WEBHOOK_WINDOW: StdDuration = StdDuration::from_secs(60);
const WEBHOOK_MAX_ATTEMPTS: usize = 300;

// How often we'll walk the rate-limit map to drop empty/expired entries.
// Cleanup is O(map.len()) so under burst traffic the previous trigger
// (`map.len() > 4096`) ran on every subsequent request - turning a cheap
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

    let mut map = map_lock.lock();
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

// Sliding-window failure counter keyed by account name. Errors with 429
// once the account has burned `max` failures inside `window`.
fn check_account_failure_limit(
    map_lock: &Mutex<HashMap<String, Vec<Instant>>>,
    key: &str,
    window: StdDuration,
    max: usize,
    label: &str,
    user_message: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let mut map = map_lock.lock();
    let now = Instant::now();
    if let Some(times) = map.get_mut(key) {
        times.retain(|t| now.duration_since(*t) < window);
        if times.len() >= max {
            log::warn!("{} limit exceeded for account {}", label, key);
            return Err(error_response(StatusCode::TOO_MANY_REQUESTS, user_message));
        }
        if times.is_empty() {
            map.remove(key);
        }
    }
    Ok(())
}

// Record one failure for the account; returns true when this failure reached
// the cap.
fn record_account_failure(
    map_lock: &Mutex<HashMap<String, Vec<Instant>>>,
    key: &str,
    window: StdDuration,
    max: usize,
) -> bool {
    let mut map = map_lock.lock();
    let now = Instant::now();
    // Opportunistic GC: keys are attacker-supplied strings, so drop drained
    // entries before inserting to keep the map bounded.
    if map.len() > 1024 {
        map.retain(|_, v| {
            v.retain(|t| now.duration_since(*t) < window);
            !v.is_empty()
        });
    }
    let entry = map.entry(key.to_string()).or_default();
    entry.retain(|t| now.duration_since(*t) < window);
    entry.push(now);
    entry.len() >= max
}

// Reject a sign-in code exchange for an account that already burned its
// guesses. Checked before the token lookup so a lockout also covers codes
// minted after it (an attacker can trigger fresh emails at will).
fn check_signin_guess_limit(
    state: &AppState,
    username: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    check_account_failure_limit(
        &state.signin_guesses,
        username,
        SIGNIN_GUESS_WINDOW,
        SIGNIN_MAX_GUESSES,
        "Sign-in code guess",
        "Too many attempts, request a new code later",
    )
}

// Count a wrong sign-in code guess. On the guess that reaches the cap, every
// outstanding code for the account is invalidated in the DB so the lockout
// survives a server restart for the remainder of the code TTL.
fn record_failed_signin_guess(state: &AppState, username: &str) {
    if record_account_failure(
        &state.signin_guesses,
        username,
        SIGNIN_GUESS_WINDOW,
        SIGNIN_MAX_GUESSES,
    ) {
        let db = state.db.lock();
        if let Err(e) = db.invalidate_signin_codes(username) {
            log::error!("Failed to invalidate sign-in codes for {}: {}", username, e);
        } else {
            log::warn!(
                "Invalidated outstanding sign-in codes for account {} after {} wrong guesses",
                username,
                SIGNIN_MAX_GUESSES
            );
        }
    }
}

fn clear_signin_guesses(state: &AppState, username: &str) {
    state.signin_guesses.lock().remove(username);
}

// Reject interactive auth for an account that already burned its failures
// (wrong password or wrong 2FA). Complements the per-IP limit: a distributed
// IP pool gets at most ACCOUNT_MAX_FAILURES guesses per window against any
// one account.
fn check_account_lockout(
    state: &AppState,
    username: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    check_account_failure_limit(
        &state.auth_failures,
        username,
        ACCOUNT_FAILURE_WINDOW,
        ACCOUNT_MAX_FAILURES,
        "Account auth failure",
        "Too many failed login attempts, try again later",
    )
}

fn record_failed_account_auth(state: &AppState, username: &str) {
    if record_account_failure(
        &state.auth_failures,
        username,
        ACCOUNT_FAILURE_WINDOW,
        ACCOUNT_MAX_FAILURES,
    ) {
        log::warn!(
            "Account {} locked out after {} failed auth attempts",
            username,
            ACCOUNT_MAX_FAILURES
        );
    }
}

fn clear_account_failures(state: &AppState, username: &str) {
    state.auth_failures.lock().remove(username);
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

pub(crate) fn check_license_api_rate_limit(
    state: &AppState,
    ip: IpAddr,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    check_ip_rate_limit(
        &state.license_attempts,
        ip,
        LICENSE_API_WINDOW,
        LICENSE_API_MAX_ATTEMPTS,
        "License API",
        "Too many requests, try again later",
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

/// Trusted reverse-proxy peers, from SUSI_TRUSTED_PROXIES (comma-separated
/// CIDRs). When set, only loopback + these ranges may supply forwarded-IP
/// headers - any other RFC1918 peer can no longer forge rate-limit keys.
/// Unset keeps the historical default (loopback + all IPv4 private ranges,
/// which covers the Docker bridge).
static TRUSTED_PROXY_CIDRS: std::sync::OnceLock<Vec<(IpAddr, u8)>> = std::sync::OnceLock::new();

fn parse_cidr_list(raw: &str) -> Vec<(IpAddr, u8)> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| {
            let (addr, bits) = match s.split_once('/') {
                Some((a, b)) => (a, b.parse::<u8>().ok()?),
                None => (s, if s.contains(':') { 128 } else { 32 }),
            };
            let ip = addr.parse::<IpAddr>().ok()?;
            Some((ip, bits))
        })
        .collect()
}

fn cidr_contains(net: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            let p = prefix.min(32) as u32;
            if p == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - p);
            (u32::from(n) & mask) == (u32::from(i) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            let p = prefix.min(128) as u32;
            if p == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - p);
            (u128::from(n) & mask) == (u128::from(i) & mask)
        }
        _ => false,
    }
}

fn is_trusted_proxy_peer(ip: IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    if let Some(cidrs) = TRUSTED_PROXY_CIDRS.get() {
        if !cidrs.is_empty() {
            return cidrs.iter().any(|(net, bits)| cidr_contains(*net, *bits, ip));
        }
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
    /// Session version, checked against users.token_version on every request.
    /// Bumped on password change/reset so outstanding tokens can be revoked;
    /// tokens issued before the field existed default to 0 and fail the check.
    #[serde(default)]
    tv: i64,
    /// Session id, checked against the sessions table on every request so
    /// individual sessions can be listed and revoked. Tokens issued before
    /// the field existed default to "" and fail the check.
    #[serde(default)]
    jti: String,
}

/// Session JWT lifetime. Also bounds how long a sessions-table row can
/// matter: anything older holds an expired token.
const SESSION_JWT_TTL_DAYS: i64 = 30;

/// Short-lived, single-asset download ticket. Lets the dashboard trigger a
/// native browser download via plain `<a href>` (which can't carry an
/// Authorization header) without exposing the user's session JWT in the URL.
/// The `aud` claim makes it impossible to mistake an auth JWT for a ticket.
#[derive(Debug, Serialize, Deserialize)]
struct DownloadTicketClaims {
    sub: String,
    #[serde(default)]
    product: String,
    tag: String,
    asset: String,
    aud: String,
    exp: i64,
}

const DOWNLOAD_TICKET_AUDIENCE: &str = "release-download";
const DOWNLOAD_TICKET_TTL_SECS: i64 = 60;

/// Claims for the unsubscribe link embedded in every newsletter. A dedicated
/// audience keeps a leaked token useless anywhere else in the API, and there is
/// deliberately no `exp`: an unsubscribe link must keep working for as long as
/// the mail exists in someone's archive.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct UnsubscribeClaims {
    pub sub: String,
    pub aud: String,
}

pub(crate) const UNSUBSCRIBE_AUDIENCE: &str = "newsletter-unsubscribe";

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
    /// Lease duration in hours. 0 = no lease enforcement. Default: 72 (3 days).
    #[serde(default = "default_lease_duration")]
    lease_duration_hours: u32,
    /// Grace period in hours after lease expires. Default: 24.
    #[serde(default = "default_lease_grace")]
    lease_grace_hours: u32,
    /// Require valid binary code signature. Default: false.
    #[serde(default = "default_require_signed_binary")]
    require_signed_binary: bool,
    /// Usernames to assign the license to on creation (self-serve portal access).
    #[serde(default)]
    assign_to: Vec<String>,
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
    /// Portal usernames the license is assigned to.
    users: Vec<String>,
}

#[derive(Serialize)]
struct MachineSummary {
    machine_code: String,
    friendly_name: String,
    activated_at: String,
    last_seen_at: String,
    lease_expires_at: Option<String>,
    lease_active: bool,
}

fn license_to_summary(lic: &License, users: Vec<String>) -> LicenseSummary {
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
                last_seen_at: m.last_seen().to_rfc3339(),
                lease_expires_at: m.lease_expires_at.map(|dt| dt.to_rfc3339()),
                lease_active: m.is_lease_active(now),
            })
            .collect(),
        revoked: lic.revoked,
        require_signed_binary: lic.require_signed_binary,
        users,
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

fn create_jwt(
    secret: &[u8; 32],
    username: &str,
    token_version: i64,
    jti: &str,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: username.into(),
        iat: now,
        exp: now + SESSION_JWT_TTL_DAYS * 86_400,
        tv: token_version,
        jti: jti.into(),
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret))
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))
}

/// Mint a session JWT carrying the user's current token_version and a fresh
/// session id, and register the session so it shows up in (and can be
/// revoked from) the active-sessions list.
fn create_session_jwt(
    state: &AppState,
    username: &str,
    device_label: &str,
    ip: IpAddr,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let jti = uuid::Uuid::new_v4().to_string();
    let tv = {
        let db = state.db.lock();
        let tv = db
            .get_user_token_version(username)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "Unknown user"))?;
        db.create_session(&jti, username, device_label, &ip.to_string())
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        tv
    };
    create_jwt(&state.jwt_secret, username, tv, &jti)
}

fn mint_download_ticket(
    secret: &[u8; 32],
    sub: &str,
    product: &str,
    tag: &str,
    asset: &str,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let claims = DownloadTicketClaims {
        sub: sub.into(),
        product: product.into(),
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
    expected_product: &str,
    expected_tag: &str,
    expected_asset: &str,
) -> Result<DownloadTicketClaims, (StatusCode, Json<ErrorResponse>)> {
    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_audience(&[DOWNLOAD_TICKET_AUDIENCE]);
    let claims = decode::<DownloadTicketClaims>(token, &DecodingKey::from_secret(secret), &validation)
        .map(|d| d.claims)
        .map_err(|_| error_response(StatusCode::UNAUTHORIZED, "Invalid or expired download ticket"))?;
    // Empty `product` in older tickets means the default product.
    let ticket_product = if claims.product.is_empty() { DEFAULT_PRODUCT } else { &claims.product };
    if ticket_product != expected_product || claims.tag != expected_tag || claims.asset != expected_asset {
        return Err(error_response(StatusCode::FORBIDDEN, "Ticket does not match requested asset"));
    }
    Ok(claims)
}

/// Short-lived single-file ticket for workspace file downloads - same idea as
/// the release download ticket: lets `<a href>` navigation work without a
/// session JWT in the URL.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct WorkspaceFileTicketClaims {
    pub(crate) sub: String,
    pub(crate) workspace_id: String,
    pub(crate) file: String,
    pub(crate) aud: String,
    pub(crate) exp: i64,
}

pub(crate) const WORKSPACE_FILE_TICKET_AUDIENCE: &str = "workspace-file-download";

pub(crate) fn mint_workspace_file_ticket(
    secret: &[u8; 32],
    sub: &str,
    workspace_id: &str,
    file: &str,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let claims = WorkspaceFileTicketClaims {
        sub: sub.into(),
        workspace_id: workspace_id.into(),
        file: file.into(),
        aud: WORKSPACE_FILE_TICKET_AUDIENCE.into(),
        exp: Utc::now().timestamp() + DOWNLOAD_TICKET_TTL_SECS,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret))
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))
}

pub(crate) fn validate_workspace_file_ticket(
    secret: &[u8; 32],
    token: &str,
    expected_workspace: &str,
    expected_file: &str,
) -> Result<WorkspaceFileTicketClaims, (StatusCode, Json<ErrorResponse>)> {
    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_audience(&[WORKSPACE_FILE_TICKET_AUDIENCE]);
    let claims =
        decode::<WorkspaceFileTicketClaims>(token, &DecodingKey::from_secret(secret), &validation)
            .map(|d| d.claims)
            .map_err(|_| error_response(StatusCode::UNAUTHORIZED, "Invalid or expired download ticket"))?;
    if claims.workspace_id != expected_workspace || claims.file != expected_file {
        return Err(error_response(StatusCode::FORBIDDEN, "Ticket does not match requested file"));
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

// Authenticated source - JWT means an interactive browser session (subject to
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

/// Drop every cached token. Called by revoke handlers - we don't store the
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
            let db = state.db.lock();
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
    // Session revocation: the token is only valid while its embedded version
    // matches the user's current one (rejects tokens of deleted users too)
    // AND its session row is alive (rejects individually revoked sessions).
    {
        let db = state.db.lock();
        let current_tv = db
            .get_user_token_version(&claims.sub)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        if current_tv != Some(claims.tv) {
            return Err(error_response(StatusCode::UNAUTHORIZED, "Session revoked"));
        }
        if !db
            .session_valid(&claims.jti, &claims.sub, SESSION_IDLE_TIMEOUT_DAYS)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        {
            return Err(error_response(StatusCode::UNAUTHORIZED, "Session revoked"));
        }
    }
    Ok(Principal { username: claims.sub, source: AuthSource::Jwt })
}

/// The explicit public surface of /api/v1: everything else requires a valid
/// principal at the middleware layer, before any handler runs. GET-only
/// entries stay GET-only - a write verb on the same path is not public.
fn is_public_api_route(method: &Method, path: &str) -> bool {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    // All API routes start with ["api", "v1"].
    if segs.len() < 3 || segs[0] != "api" || segs[1] != "v1" {
        // Non-API paths (site shells, static assets, health) are public.
        return true;
    }
    let get = *method == Method::GET;
    let post = *method == Method::POST;
    match &segs[2..] {
        ["features"] => get,
        ["auth", ep] => {
            post && matches!(
                *ep,
                "login" | "signin-code" | "request-code" | "magic-login"
                    | "forgot-password" | "reset-password"
            )
        }
        ["activate"] | ["verify"] | ["deactivate"] => post,
        // License-key / ticket authenticated or intentionally public reads;
        // each handler enforces its own credential.
        ["licenses", _, "status"] => get,
        ["updates", "releases"] => get,
        ["updates", "download", _, _] => get,
        ["updates", "download-ticket"] => post,
        ["indexnow", _] => get,
        ["newsletter", "unsubscribe"] => get || post,
        ["newsletter", "google", "callback"] => get,
        ["website", "pages"] => get,
        ["website", "pages", _] => get,
        ["website", "assets", _] => get,
        ["shop", "products"] | ["shop", "products", _] => get,
        ["shop", "checkout"] | ["shop", "webhook"] => post,
        ["contact"] => post,
        ["contact", "config"] => get,
        // Public docs viewer (global product docs only - workspace docs are
        // behind membership).
        ["products"] => get,
        ["docs", "releases"] | ["docs", "releases", "latest"] => get,
        ["docs", _, "pages"] | ["docs", _, "pages", _] => get,
        ["docs", _, "assets", _] => get,
        ["products", _, "docs", "releases"] | ["products", _, "docs", "releases", "latest"] => get,
        ["products", _, "docs", _, "pages"] | ["products", _, "docs", _, "pages", _] => get,
        ["products", _, "docs", _, "assets", _] => get,
        // Ticket-authenticated download (the ticket in the query string is
        // the credential; minting it required a session).
        ["workspaces", _, "files", _] => get,
        _ => false,
    }
}

async fn enforce_api_auth(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if !is_public_api_route(req.method(), req.uri().path()) {
        if let Err(e) = validate_principal(req.headers(), &state) {
            return e.into_response();
        }
    }
    next.run(req).await
}

/// Combined password-changed + admin-role + admin-2FA gate. Uses one DB
/// round-trip and one mutex cycle instead of the three the legacy
/// `require_password_changed` + `require_admin` pair did. Use this for any
/// handler that ends up calling both helpers back-to-back (the typical admin
/// case) - the old helpers stay around for the few sites that need only one.
pub(crate) fn require_admin_full(
    state: &AppState,
    principal: &Principal,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    // API tokens skip both the password-change gate (UI-only) and the
    // TOTP requirement (the bearer is itself a strong factor).
    let row = {
        let db = state.db.lock();
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
    if !is_admin_role(&role) {
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

/// Administering an owner account requires being an owner.
///
/// Without this, ownership would only look closed: an admin could reset an
/// owner's password, or repoint their email and drive a password reset, and
/// log in as them. Applied to every operation that can take over or remove an
/// owner account - delete, reset password, set email, change role.
pub(crate) fn require_owner_for_owner_target(
    state: &AppState,
    principal: &Principal,
    target: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let target_is_owner = {
        let db = state.db.lock();
        db.get_user_role(target).map(|r| is_owner_role(&r)).unwrap_or(false)
    };
    if target_is_owner {
        require_owner(state, principal)?;
    }
    Ok(())
}

/// Owner-only gate: the newsletter, and changing who is an owner.
///
/// Layered on top of `require_admin_full` rather than replacing it, so owners
/// still clear the password-change and TOTP requirements that apply to every
/// administrator.
pub(crate) fn require_owner(
    state: &AppState,
    principal: &Principal,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    require_admin_full(state, principal)?;
    let role = {
        let db = state.db.lock();
        db.get_user_role(&principal.username).unwrap_or_default()
    };
    if !is_owner_role(&role) {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "Owner access required",
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
    let db = state.db.lock();
    if db.user_must_change_password(&principal.username).unwrap_or(true) {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "Password change required before accessing admin features",
        ));
    }
    Ok(())
}

/// Best-effort audit-trail write. Never fails the request - a broken audit
/// insert is logged and swallowed. Use `audit` when no DB guard is held,
/// `audit_db` when one already is (the mutex is not reentrant).
pub(crate) fn audit(state: &AppState, actor: &str, action: &str, target: &str, details: &str) {
    audit_db(&state.db.lock(), actor, action, target, details);
}

pub(crate) fn audit_db(db: &LicenseDb, actor: &str, action: &str, target: &str, details: &str) {
    if let Err(e) = db.insert_audit(actor, action, target, details) {
        log::error!("audit write failed ({} {} {}): {}", actor, action, target, e);
    }
}

/// Admin view of the audit trail, newest first. `before` is the keyset
/// cursor (smallest id of the previous page).
#[derive(Deserialize)]
struct AuditQuery {
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    before: Option<i64>,
}

async fn handle_list_audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<AuditQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_admin_full(&state, &principal)?;
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let rows = {
        let db = state.db.lock();
        db.list_audit(limit, q.before)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    Ok(Json(serde_json::json!({ "entries": rows })))
}

// Argon2 hash + verify are CPU-bound and take ~50-100 ms per call. Run them on
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

// Generate a 6-digit numeric sign-in code (zero-padded). 20 bits of entropy
// is intentional - short enough to type by hand from an email, gated by IP
// rate limiting + per-user scoping so brute force is impractical.
fn random_signin_code() -> String {
    let n: u32 = rand::thread_rng().gen_range(0..1_000_000);
    format!("{:06}", n)
}

// Scope the stored token hash by username so two concurrent users picking
// the same 6-digit code don't collide in `login_tokens`. Keyed with the
// server secret (HMAC): a 6-digit code has only 20 bits of entropy, so an
// unkeyed digest would let anyone reading the DB or a backup recover a live
// code in ~10^6 hashes. The prefix is a domain tag so this can't be confused
// with `hash_token` digests.
fn hash_signin_code(secret: &[u8; 32], username: &str, code: &str) -> String {
    use hmac::Mac;
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(secret).expect("any key length is valid");
    mac.update(b"susi-signin:");
    mac.update(username.as_bytes());
    mac.update(b":");
    mac.update(code.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn mask_email(addr: &str) -> String {
    // "klaus@lp-research.com" -> "k***@lp-research.com" - shown to the user so
    // they can confirm they're checking the right inbox without leaking the
    // full address to someone who's only guessed a username.
    if let Some((local, domain)) = addr.split_once('@') {
        let first = local.chars().next().unwrap_or('*');
        format!("{}***@{}", first, domain)
    } else {
        "***".into()
    }
}

/// Collapse a raw `navigator.userAgent` string into a short "Browser N / OS"
/// label suitable for the trusted-devices list and sign-in code emails.
/// Reduces the noise the user sees and also drops the `Chrome/N.N.N.N`
/// pattern that Gmail otherwise auto-linkifies as an IPv4 address.
/// Falls back to a length-capped copy of the raw input when no known
/// browser/OS tokens match.
fn summarize_user_agent(raw: &str) -> String {
    let s = raw.trim();
    if s.is_empty() {
        return "(unknown device)".to_string();
    }

    let browser = if let Some(v) = ua_version_after(s, "Edg/") {
        Some(format!("Edge {}", v))
    } else if let Some(v) = ua_version_after(s, "OPR/") {
        Some(format!("Opera {}", v))
    } else if let Some(v) = ua_version_after(s, "Firefox/") {
        Some(format!("Firefox {}", v))
    } else if let Some(v) = ua_version_after(s, "Chrome/") {
        Some(format!("Chrome {}", v))
    } else if s.contains("Safari/") {
        ua_version_after(s, "Version/").map(|v| format!("Safari {}", v))
    } else {
        None
    };

    let os = if s.contains("Windows NT") {
        Some("Windows")
    } else if s.contains("iPhone OS") || s.contains("iPad") {
        Some("iOS")
    } else if s.contains("Mac OS X") {
        Some("macOS")
    } else if s.contains("Android") {
        Some("Android")
    } else if s.contains("Linux") {
        Some("Linux")
    } else {
        None
    };

    match (browser, os) {
        (Some(b), Some(o)) => format!("{} / {}", b, o),
        (Some(b), None) => b,
        (None, Some(o)) => o.to_string(),
        (None, None) => s.chars().take(80).collect(),
    }
}

/// Return the major-version digits found immediately after `marker` (e.g.
/// `"Chrome/"` -> `"148"`). Stops at the first non-digit so `148.0.0.0`
/// collapses to `148`.
fn ua_version_after(ua: &str, marker: &str) -> Option<String> {
    let rest = ua.split(marker).nth(1)?;
    let major: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    (!major.is_empty()).then_some(major)
}

fn signin_code_disabled(state: &AppState) -> bool {
    // The base URL is still consulted because password-reset + invitation
    // mails (issued from the same SMTP path) need it. Without an outbound
    // URL the whole email-bound auth surface is off.
    state.email.is_none() || state.magic_link_base_url.is_empty()
}


/// Replay protection: a verified TOTP code is only accepted once. The current
/// 30-second timestep is recorded per user and codes for an already-consumed
/// timestep are rejected, so a shoulder-surfed or intercepted code is dead
/// the moment its owner used it. Call ONLY after the code itself verified.
pub(crate) fn consume_totp_step(
    db: &LicenseDb,
    username: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let step = Utc::now().timestamp() / 30;
    let fresh = db
        .try_advance_totp_step(username, step)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    if !fresh {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "This code was already used - wait for the next one",
        ));
    }
    Ok(())
}

// Check a 6-digit TOTP code only (used by 2FA enable/disable paths where
// backup codes are not accepted).
fn verify_totp_code(
    state: &AppState,
    username: &str,
    code: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let db = state.db.lock();
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
    consume_totp_step(&db, username)?;
    Ok(())
}

// Verify either a 6-digit TOTP or a backup code. Backup codes are consumed
// on success. Used by login + sign-in code exchange, where the user may
// have lost their authenticator.
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
    // Backup-code path - strip separators users might type in (space or dash).
    let normalized: String = trimmed
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_uppercase();
    if normalized.is_empty() {
        return Err(error_response(StatusCode::UNAUTHORIZED, "Invalid 2FA code"));
    }
    let candidates = {
        let db = state.db.lock();
        db.list_unused_backup_codes(username)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    };
    for (id, hash) in candidates {
        let Ok(parsed) = PasswordHash::new(&hash) else { continue };
        if Argon2::default()
            .verify_password(normalized.as_bytes(), &parsed)
            .is_ok()
        {
            let db = state.db.lock();
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
// ~50 bits of entropy per code - plenty given login rate limiting.
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

// Exchange a sign-in code for a JWT. Also registers the device as trusted.
// `username` is required so the lookup can be scoped per user - two users
// can hold the same 6-digit code in flight without colliding.
#[derive(Deserialize)]
struct SigninCodeRequest {
    username: String,
    code: String,
    #[serde(default)]
    totp_code: Option<String>,
}


// Passwordless login, step 1: request a sign-in code by email or username.
// Admins qualify too: the code exchange enforces TOTP for TOTP-enabled
// accounts, so an admin sign-in is still two factors (inbox + authenticator).
// The response is always the same generic OK so the endpoint can't be used
// to enumerate accounts.
#[derive(Deserialize)]
struct RequestCodeRequest {
    /// Email address or username.
    identifier: String,
    #[serde(default)]
    device_fp: String,
    #[serde(default)]
    device_label: String,
}


// Invitation magic-login: a non-admin invitee clicks the emailed link and is
// signed in directly - no password setup. Single-use; consumes the invite
// token. Admin invitations keep the password-setup link instead.
#[derive(Deserialize)]
struct MagicLoginRequest {
    token: String,
    #[serde(default)]
    device_fp: String,
    #[serde(default)]
    device_label: String,
}



#[derive(Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}


// ---------------------------------------------------------------------------
// Password reset (forgot-password) flow
// ---------------------------------------------------------------------------
//
// 1. POST /auth/forgot-password { identifier } - identifier is either a
//    username or an email address. Always responds 200 (no enumeration).
//    If the account is found and has an email and SMTP is configured, a
//    one-time reset link is sent to the on-file address.
// 2. User clicks the link, lands at /#/reset/<token>. Frontend prompts for a
//    new password and POSTs it to /auth/reset-password.
// 3. POST /auth/reset-password { token, new_password } - consumes the token,
//    updates the password, clears must_change_password (since the user just
//    proved control of the inbox).
//
// Reset tokens are stored in `login_tokens` with kind='reset' so they can't
// be replayed against the sign-in code endpoint.

const PASSWORD_RESET_TTL_MINUTES: i64 = 30;
const INVITE_TTL_HOURS: i64 = 24 * 7;

#[derive(Deserialize)]
struct ForgotPasswordRequest {
    /// Username OR email - users may not remember their login name.
    identifier: String,
}


#[derive(Deserialize)]
struct ResetPasswordSubmitRequest {
    token: String,
    new_password: String,
    #[serde(default)]
    device_fp: String,
    #[serde(default)]
    device_label: String,
}



#[derive(Deserialize)]
struct TotpCodeRequest {
    totp_code: String,
}



// Regenerate backup codes. Password-gated so a stolen session alone can't
// rotate them out from under the real user.
#[derive(Deserialize)]
struct RegenerateBackupCodesRequest {
    current_password: String,
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
    // Use ring for ECDSA verification - it is already in the dependency graph
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


// ---------------------------------------------------------------------------
// Admin endpoints
// ---------------------------------------------------------------------------







/// Activate `machine_code` on the license and return the signed license file
/// as a download. Shared by the admin export and the self-serve portal export
/// (offline activation); callers do their own permission gating.
fn export_license_file(
    state: &AppState,
    key: &str,
    req: &ExportRequest,
) -> Result<(StatusCode, [(axum::http::HeaderName, &'static str); 2], String), (StatusCode, Json<ErrorResponse>)> {
    let db = state.db.lock();
    let license = db
        .get_license_by_key(key)
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

    // Offline exports carry no lease: the machine cannot phone home to renew,
    // so a leased file would stop validating after lease + grace. Same policy
    // as USB token exports. The seat is held until the machine is removed in
    // the dashboard; the license expiry date still applies.
    db.add_machine_activation(&license.id, &req.machine_code, &name, None)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    // Re-fetch with the activation
    let license = db
        .get_license_by_key(key)
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





// ---------------------------------------------------------------------------
// License <-> user assignment (admin) and self-serve portal endpoints
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AssignLicenseUserRequest {
    username: String,
}



/// Resolve `key` to a license owned by `principal`. Returns 404 (not 403) on
/// foreign licenses so the endpoint doesn't confirm key existence.
fn get_owned_license(
    db: &LicenseDb,
    key: &str,
    principal: &Principal,
) -> Result<License, (StatusCode, Json<ErrorResponse>)> {
    let license = db
        .get_license_by_key(key)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "License key not found"))?;
    if !db
        .is_license_assigned(&license.id, &principal.username)
        .unwrap_or(false)
    {
        return Err(error_response(StatusCode::NOT_FOUND, "License key not found"));
    }
    Ok(license)
}




// ---------------------------------------------------------------------------
// User management endpoints
// ---------------------------------------------------------------------------


#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    /// Optional. When absent, the user is created with an unusable random
    /// password and an invitation email is sent - the recommended flow.
    /// When set (admin chose "set password manually"), no email is sent and
    /// the admin must courier the temp password out-of-band.
    #[serde(default)]
    password: Option<String>,
    #[serde(default = "default_user_role")]
    role: String,
    email: String,
    #[serde(default)]
    first_name: String,
    #[serde(default)]
    last_name: String,
}

fn default_user_role() -> String {
    "user".to_string()
}

/// Mint a one-time invitation link for `username` and email it. Replaces any
/// outstanding reset/invite tokens for that user so only the freshest link
/// works. Caller is expected to have held the DB lock briefly *before* this
/// - we re-acquire it here and drop it before spawning the SMTP task.
async fn issue_and_send_invitation(
    state: &AppState,
    username: &str,
    email_addr: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let raw_token = random_magic_token();
    let token_hash = hash_token(&raw_token);
    {
        let db = state.db.lock();
        let _ = db.purge_old_login_tokens();
        db.invalidate_setup_tokens(username)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
        db.insert_invitation_token(&token_hash, username, INVITE_TTL_HOURS * 3600)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    }

    // Every invitee sets a password first, then is signed in directly by
    // the reset submit - otherwise customer accounts end up passwordless
    // and locked out once the one-shot link is spent.
    let link = format!(
        "{}/#/reset/{}",
        state.magic_link_base_url.trim_end_matches('/'),
        raw_token
    );
    let Some(email_service) = state.email.clone() else {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Email is not configured on this server - cannot send invitation",
        ));
    };
    let to = email_addr.to_string();
    let uname = username.to_string();
    tokio::spawn(async move {
        if let Err(e) = email_service
            .send_invitation(&to, &uname, &link, INVITE_TTL_HOURS)
            .await
        {
            log::error!("Failed to send invitation email to {}: {:#}", to, e);
        }
    });
    Ok(())
}




#[derive(Deserialize)]
struct RenameUserRequest {
    new_username: String,
}


#[derive(Deserialize)]
struct SetUserRoleRequest {
    role: String,
}


#[derive(Deserialize)]
struct ResetPasswordRequest {
    new_password: String,
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






// ---------------------------------------------------------------------------
// Email + trusted devices
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SetEmailRequest {
    /// Pass `null` or empty string to clear.
    #[serde(default)]
    email: Option<String>,
}

#[derive(Deserialize)]
struct SetNewsletterRequest {
    opt_in: bool,
}

/// Real name, used for blog bylines. Both halves are optional so clearing one
/// is a normal edit rather than a delete.
#[derive(Deserialize)]
struct SetNameRequest {
    #[serde(default)]
    first_name: String,
    #[serde(default)]
    last_name: String,
}

/// Everything the admin Edit User dialog can change, applied together so a
/// rejected email doesn't leave a half-saved row.
#[derive(Deserialize)]
struct SetProfileRequest {
    #[serde(default)]
    first_name: String,
    #[serde(default)]
    last_name: String,
    /// Omit to leave the address untouched; pass an empty string to clear it.
    #[serde(default)]
    email: Option<String>,
}

#[derive(Deserialize)]
struct SetNewsletterBulkRequest {
    usernames: Vec<String>,
    opt_in: bool,
}

fn normalize_email(raw: &str) -> Result<Option<String>, (StatusCode, Json<ErrorResponse>)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    // Very light validation - the real check is "does the sign-in email arrive".
    // We just catch obvious typos so we don't store garbage.
    if !trimmed.contains('@') || trimmed.contains(' ') || trimmed.len() > 254 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Invalid email address"));
    }
    Ok(Some(trimmed.to_string()))
}





// ---------------------------------------------------------------------------
// Active sessions (list / revoke). JWT-only: API tokens have no session and
// get their own revocation flow.
// ---------------------------------------------------------------------------

/// The caller's own session id, for marking "this session" in lists and
/// keeping it alive on revoke-others. Errors for non-JWT principals.
fn current_session_jti(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let claims = validate_jwt(headers, &state.jwt_secret).map_err(|_| {
        error_response(
            StatusCode::FORBIDDEN,
            "Sessions can only be managed from a browser session",
        )
    })?;
    Ok(claims.jti)
}




// ---------------------------------------------------------------------------
// Release endpoints
// ---------------------------------------------------------------------------

/// Validate the `X-License-Key` header and return the product the license is
/// for, so callers can scope what the key entitles.
fn validate_license_key(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let key = headers
        .get("x-license-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if key.is_empty() {
        return Err(error_response(StatusCode::UNAUTHORIZED, "Missing X-License-Key header"));
    }

    let db = state.db.lock();
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

    Ok(license.product)
}

fn releases_dir(state: &AppState) -> std::path::PathBuf {
    std::path::Path::new(&state.data_dir).join("releases")
}

/// On-disk binary directory for a release. FusionHub keeps its historical flat
/// layout (`releases/{tag}`) so existing artifacts and the public download
/// endpoint stay valid with no migration; other products are namespaced.
/// Back-compat shim, mirrors `docs::assets_dir`.
fn release_tag_dir(state: &AppState, product: &str, tag: &str) -> std::path::PathBuf {
    if product == DEFAULT_PRODUCT {
        releases_dir(state).join(tag)
    } else {
        releases_dir(state).join(product).join(tag)
    }
}

// ---------------------------------------------------------------------------
// Products (catalog dimension that scopes releases + docs)
// ---------------------------------------------------------------------------


#[derive(Deserialize)]
struct ProductRequest {
    slug: String,
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    ord: i64,
    #[serde(default)]
    download_public: bool,
}


#[derive(Deserialize)]
struct UpdateProductRequest {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    ord: i64,
    #[serde(default)]
    download_public: bool,
}




/// Case-insensitive match between a license's free-text `product` field
/// (display names like "FusionHub") and a release-product slug
/// ("fusionhub"). The catalog display name for the slug is accepted too.
fn license_covers_product(db: &LicenseDb, license_product: &str, product_slug: &str) -> bool {
    let lp = license_product.trim();
    if lp.eq_ignore_ascii_case(product_slug) {
        return true;
    }
    db.get_product_name(product_slug)
        .ok()
        .flatten()
        .is_some_and(|name| lp.eq_ignore_ascii_case(name.trim()))
}

/// Verify the caller is allowed to download `tag`. Returns the principal
/// username if authentication used a bearer token, or `"license"` if it used a
/// license key. Encapsulates the license/principal + workspace membership
/// rules shared by the download endpoint and the ticket mint endpoint.
fn authorize_release_download(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    product: &str,
    _tag: &str,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    // A publicly-downloadable product exposes its releases with no auth -
    // the free FusionHub installer linked from xikaku.com.
    if state.db.lock().get_product_download_public(product).unwrap_or(false) {
        return Ok("public".into());
    }

    let license_product = validate_license_key(state, headers).ok();
    let principal_opt = validate_principal(headers, state).ok();
    if license_product.is_none() && principal_opt.is_none() {
        return Err(error_response(StatusCode::UNAUTHORIZED, "Authentication required"));
    }

    // A license key only entitles its own product's binaries. A session must
    // be admin or belong to a customer of the product - a live assigned
    // license or membership in a workspace scoped to it.
    let db = state.db.lock();
    let license_entitled = license_product
        .as_deref()
        .is_some_and(|lp| license_covers_product(&db, lp, product));
    if !license_entitled {
        let principal = principal_opt.as_ref().ok_or_else(|| {
            error_response(StatusCode::FORBIDDEN, "License does not cover this product")
        })?;
        let is_admin = db.get_user_role(&principal.username)
            .map(|r| is_admin_role(&r))
            .unwrap_or(false);
        if !is_admin {
            let licensed = db
                .list_licenses_for_user(&principal.username)
                .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
                .iter()
                .any(|l| !l.revoked && !l.is_expired() && license_covers_product(&db, &l.product, product));
            let entitled = licensed
                || db
                    .user_in_product_workspace(&principal.username, product)
                    .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
            if !entitled {
                return Err(error_response(StatusCode::FORBIDDEN, "No license for this product"));
            }
        }
    }
    drop(db);

    Ok(principal_opt
        .map(|p| p.username)
        .unwrap_or_else(|| "license".into()))
}

#[derive(Deserialize)]
struct DownloadTicketRequest {
    tag: String,
    asset: String,
    #[serde(default)]
    product: Option<String>,
}

/// Optional `?product=` selector for release-admin and download routes. Absent
/// means the default product, so deployed FusionHub clients keep working.
#[derive(Deserialize)]
struct ProductQuery {
    #[serde(default)]
    product: Option<String>,
}

impl ProductQuery {
    fn slug(&self) -> &str {
        self.product.as_deref().filter(|s| !s.is_empty()).unwrap_or(DEFAULT_PRODUCT)
    }
}


#[derive(Deserialize)]
struct DownloadQuery {
    #[serde(default)]
    ticket: Option<String>,
    #[serde(default)]
    product: Option<String>,
}




#[derive(Deserialize)]
struct UpdateReleaseRequest {
    name: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    prerelease: bool,
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






// ---------------------------------------------------------------------------
// Workspace member endpoints
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// Config revision endpoints
// ---------------------------------------------------------------------------







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

fn assert_workspace_member(
    state: &AppState,
    workspace_id: &str,
    principal: &Principal,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let db = state.db.lock();
    db.workspace_access(workspace_id, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::FORBIDDEN, "Not a member of this workspace"))?;
    Ok(())
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


// ---------------------------------------------------------------------------
// Workspace graph (shared node-graph, version-tracked)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct PutGraphRequest {
    /// Version the editor was loaded with. `None` is only valid for the
    /// very first push of a workspace (no row yet). Mismatch ⇒ 409.
    #[serde(default)]
    expected_version: Option<u32>,
    /// Raw config JSON - same shape the editor exports / loads.
    config: serde_json::Value,
}










// ---------------------------------------------------------------------------
// Dashboard (embedded HTML)
// ---------------------------------------------------------------------------

async fn handle_dashboard() -> impl IntoResponse {
    // no-cache = revalidate before reuse, not "don't cache". Without it the
    // response carries no caching headers at all, and browsers are free to
    // heuristically reuse a stale copy after a deploy - which shows up as
    // fixes that "didn't take" until a hard refresh.
    (
        [(header::CACHE_CONTROL, "no-cache")],
        Html(include_str!("dashboard.html")),
    )
}

/// Load the JWT secret from disk, or generate and persist one on first boot.
/// Persisting it across restarts means dashboard sessions survive deploys.
/// Load a 32-byte secret from `data_dir/<file_name>`, generating and
/// persisting a fresh one on first boot. Used for the JWT signing key and
/// the DB at-rest encryption key.
fn load_or_create_secret(data_dir: &str, file_name: &str, label: &str) -> Result<[u8; 32]> {
    let path = std::path::Path::new(data_dir).join(file_name);
    if path.exists() {
        let bytes = std::fs::read(&path)
            .with_context(|| format!("Failed to read {} at {}", label, path.display()))?;
        if bytes.len() == 32 {
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&bytes);
            log::info!("Loaded {} from {}", label, path.display());
            return Ok(secret);
        }
        log::warn!("{} at {} has wrong length ({} bytes); regenerating", label, path.display(), bytes.len());
    }
    let secret: [u8; 32] = rand::random();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&path, secret)
        .with_context(|| format!("Failed to write {} to {}", label, path.display()))?;
    // Best-effort lock down permissions on Unix; Windows ignores the mode.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    log::info!("Generated new {} and saved to {}", label, path.display());
    Ok(secret)
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

    if let Some(CliCommand::DecryptBackup { input, output, key }) = &cli.command {
        return backup::cli_decrypt(input, output.as_deref(), key);
    }

    log::info!("Loading private key from {}", cli.private_key);
    let priv_pem = std::fs::read_to_string(&cli.private_key)
        .with_context(|| format!("Failed to read private key from {}", cli.private_key))?;
    let private_key = private_key_from_pem(&priv_pem)
        .context("Failed to parse private key")?;

    log::info!("Opening database at {}", cli.db);
    let mut db = LicenseDb::open(&cli.db).context("Failed to open database")?;

    // At-rest encryption for stored secrets (TOTP seeds, federation channel
    // secrets): a leaked DB or backup must not yield working 2FA seeds.
    let db_key = load_or_create_secret(&cli.data_dir, "db_secret.bin", "DB at-rest key")?;
    let converted = db
        .set_at_rest_key(db_key)
        .context("Failed to encrypt stored secrets at rest")?;
    if converted > 0 {
        log::info!("Encrypted {} stored secrets at rest", converted);
    }
    let db = db;

    // First boot seeds the initial owner with a RANDOM one-time password,
    // printed to the log exactly once - there is no static default credential.
    // SUSI_SEED_ADMIN_PASSWORD overrides the random value (integration tests).
    {
        let (seed_password, from_env) = match std::env::var("SUSI_SEED_ADMIN_PASSWORD") {
            Ok(p) if !p.is_empty() => (p, true),
            _ => {
                let mut bytes = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut bytes);
                (hex::encode(bytes), false)
            }
        };
        let seed_hash = hash_password(&seed_password)
            .await
            .map_err(|_| anyhow::anyhow!("Failed to hash seed password"))?;
        if db.seed_admin(&seed_hash).context("Failed to seed admin")? {
            if from_env {
                log::warn!("=== First boot: created 'admin' owner account with the password from SUSI_SEED_ADMIN_PASSWORD ===");
            } else {
                log::warn!(
                    "=== First boot: created 'admin' owner account with one-time password: {} ===",
                    seed_password
                );
                log::warn!("=== Sign in and change it now - it is stored only as a hash and will not be shown again. ===");
            }
        }
    }

    let jwt_secret = load_or_create_secret(&cli.data_dir, "jwt_secret.bin", "JWT secret")
        .context("Failed to load or create JWT secret")?;

    // Trusted reverse-proxy ranges for forwarded-IP headers.
    {
        let cidrs = parse_cidr_list(&cli.trusted_proxies);
        if !cidrs.is_empty() {
            log::info!("Trusting forwarded-IP headers only from: {}", cli.trusted_proxies);
        }
        let _ = TRUSTED_PROXY_CIDRS.set(cidrs);
    }

    // Ensure releases asset directory exists
    let releases_dir = std::path::Path::new(&cli.data_dir).join("releases");
    std::fs::create_dir_all(&releases_dir)
        .with_context(|| format!("Failed to create releases dir at {}", releases_dir.display()))?;
    let docs_dir = std::path::Path::new(&cli.data_dir).join("docs");
    std::fs::create_dir_all(&docs_dir)
        .with_context(|| format!("Failed to create docs dir at {}", docs_dir.display()))?;

    let email_service = if cli.smtp_host.is_empty() {
        log::info!("SMTP not configured (--smtp-host empty) - sign-in code login disabled");
        None
    } else if cli.smtp_user.is_empty() || cli.smtp_password.is_empty() || cli.smtp_from_addr.is_empty() {
        log::warn!(
            "--smtp-host set but --smtp-user / --smtp-password / --smtp-from-addr not all set; sign-in code disabled"
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
                log::error!("Failed to init SMTP transport: {:#} - sign-in code disabled", e);
                None
            }
        }
    };

    if email_service.is_some() && cli.magic_link_base_url.is_empty() {
        log::warn!("SMTP is configured but --magic-link-base-url is empty; sign-in code login will NOT be enforced");
    }

    let newsletter_email_service = if cli.newsletter_smtp_host.is_empty() {
        log::info!("Newsletter SMTP not configured - newsletter sending disabled");
        None
    } else if cli.newsletter_smtp_user.is_empty()
        || cli.newsletter_smtp_password.is_empty()
        || cli.newsletter_smtp_from_addr.is_empty()
    {
        log::warn!(
            "--newsletter-smtp-host set but user / password / from-addr not all set; newsletter sending disabled"
        );
        None
    } else {
        let cfg = EmailConfig::from_parts(
            cli.newsletter_smtp_host.clone(),
            cli.newsletter_smtp_port,
            cli.newsletter_smtp_user.clone(),
            cli.newsletter_smtp_password.clone(),
            &cli.newsletter_smtp_from_name,
            &cli.newsletter_smtp_from_addr,
        )
        .context("Invalid newsletter SMTP configuration")?;
        match EmailService::new(cfg) {
            Ok(svc) => {
                log::info!(
                    "Newsletter SMTP ready: relay {}:{}, from {} <{}>, {}/min",
                    cli.newsletter_smtp_host,
                    cli.newsletter_smtp_port,
                    cli.newsletter_smtp_from_name,
                    cli.newsletter_smtp_from_addr,
                    cli.newsletter_rate_per_min,
                );
                Some(svc)
            }
            Err(e) => {
                log::error!("Failed to init newsletter SMTP transport: {:#} - sending disabled", e);
                None
            }
        }
    };

    if cli.stripe_secret_key.is_empty() {
        log::info!("Stripe not configured - /api/v1/shop/checkout will respond 503");
    } else {
        log::info!(
            "Stripe configured (key prefix: {})",
            &cli.stripe_secret_key[..cli.stripe_secret_key.len().min(8)],
        );
        if cli.stripe_webhook_secret.is_empty() {
            log::warn!("STRIPE_SECRET_KEY is set but STRIPE_WEBHOOK_SECRET is not - webhook will reject all events");
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
    // tolerated at startup - the recording endpoints respond 503 instead
    // and the rest of the server stays up.
    let s3_storage = match s3::S3Storage::from_env().await {
        Ok(Some(s)) => {
            log::info!("S3 ready: bucket={}, region={}", s.bucket(), s.region());
            Some(s)
        }
        Ok(None) => {
            log::info!("S3 not configured (SUSI_S3_BUCKET/REGION empty) - recording endpoints will respond 503");
            None
        }
        Err(e) => {
            log::error!("S3 init failed: {:#} - recording endpoints will respond 503", e);
            None
        }
    };

    if cli.contact_to_addr.is_empty() {
        log::info!("Contact form disabled (SUSI_CONTACT_TO_ADDR empty)");
    } else if email_service.is_none() {
        log::warn!("Contact form: SUSI_CONTACT_TO_ADDR is set but SMTP isn't configured - endpoint will respond 503");
    } else if cli.turnstile_secret.is_empty() || cli.turnstile_site_key.is_empty() {
        log::warn!("Contact form enabled with NO captcha (turnstile keys empty) - relying on honeypot + rate-limit only");
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

    // Dropbox backups. Uploads need far longer per-request timeouts than the
    // shared 15 s client, so the backup module gets its own client.
    let backup_config = backup::BackupConfig {
        app_key: cli.dropbox_app_key,
        app_secret: cli.dropbox_app_secret,
        archive_key: backup::parse_archive_key(&cli.backup_key)
            .context("Invalid SUSI_BACKUP_KEY")?,
        prefix: cli.backup_prefix,
        private_key_path: cli.private_key.clone(),
        api_base: cli.dropbox_api_base.trim_end_matches('/').to_string(),
        content_base: cli.dropbox_content_base.trim_end_matches('/').to_string(),
        http: reqwest::Client::builder()
            .connect_timeout(StdDuration::from_secs(15))
            .timeout(StdDuration::from_secs(300))
            .build()
            .context("Failed to build backup HTTP client")?,
    };
    if backup_config.configured() {
        log::info!("Dropbox backups configured (prefix `{}`)", backup_config.prefix);
        match db.mark_interrupted_backup_runs() {
            Ok(n) if n > 0 => log::warn!("Marked {} interrupted backup run(s) from a previous process", n),
            Err(e) => log::warn!("Could not mark interrupted backup runs: {}", e),
            _ => {}
        }
    } else {
        log::info!("Dropbox backups not configured (SUSI_DROPBOX_APP_KEY / SUSI_DROPBOX_APP_SECRET / SUSI_BACKUP_KEY)");
    }

    let state = Arc::new(AppState {
        db: Mutex::new(db),
        private_key,
        jwt_secret,
        data_dir: cli.data_dir,
        trusted_signing_ca,
        login_attempts: Mutex::new(HashMap::new()),
        license_attempts: Mutex::new(HashMap::new()),
        signin_guesses: Mutex::new(HashMap::new()),
        auth_failures: Mutex::new(HashMap::new()),
        checkout_attempts: Mutex::new(HashMap::new()),
        webhook_attempts: Mutex::new(HashMap::new()),
        contact_attempts: Mutex::new(HashMap::new()),
        email: email_service,
        newsletter_email: newsletter_email_service,
        newsletter_rate_per_min: cli.newsletter_rate_per_min.max(1),
        google_oauth: newsletter::GoogleOAuthConfig {
            client_id: cli.google_client_id.clone(),
            client_secret: cli.google_client_secret.clone(),
            from_name: cli.newsletter_smtp_from_name.clone(),
            from_addr_override: cli.newsletter_smtp_from_addr.clone(),
        },
        newsletter_token_cache: tokio::sync::Mutex::new(None),
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
        backup: backup_config,
        backup_running: AtomicBool::new(false),
        newsletter_sending: AtomicBool::new(false),
        newsletter_wake: tokio::sync::Notify::new(),
    });

    // Owner bootstrap. Ownership can otherwise only come from an existing
    // owner, so a database predating the role would have none and the
    // newsletter would be unreachable for everyone.
    {
        let db = state.db.lock();
        for email in cli.owner_emails.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            match db.promote_owner_by_email(email) {
                Ok(names) if !names.is_empty() => {
                    log::info!("Promoted to owner via SUSI_OWNER_EMAILS: {}", names.join(", "));
                    for n in &names {
                        audit_db(&db, "system", "user.set_role", n, "role=owner source=env");
                    }
                }
                Ok(_) => {}
                Err(e) => log::error!("Owner promotion failed for {}: {}", email, e),
            }
        }
        match db.count_owners() {
            Ok(0) => log::warn!(
                "No owner account exists - newsletter features are unavailable. \
                 Set SUSI_OWNER_EMAILS to an existing user's email and restart."
            ),
            Ok(n) => log::info!("{} owner account(s) configured", n),
            Err(_) => {}
        }
    }

    // One-time migration: fold retired workspace-scoped releases into
    // workspace files + workspace docs. No-op once no scoped rows remain.
    workspaces::migrate_workspace_releases(&state);

    // Nightly Dropbox backup scheduler (no-op until enabled + connected).
    if state.backup.configured() {
        backup::spawn_scheduler(Arc::clone(&state));
    }

    // Newsletter drain loop. Independent of backups; self-disables when
    // newsletter SMTP is unconfigured.
    newsletter::spawn_sender(Arc::clone(&state));

    // Seed the legal pages (privacy policy + imprint) on first boot so the
    // public site always carries them; an admin can edit the content later.
    website::seed_legal_pages(&state);

    // Periodic session cleanup + data-retention enforcement (GDPR Art
    // 5(1)(e)). Lease-expired machine activations are NOT deleted - they
    // persist as "seen but stale" history for the dashboard and simply stop
    // counting toward the seat limit.
    {
        let state_bg = Arc::clone(&state);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(StdDuration::from_secs(300));
            tick.tick().await; // skip immediate fire
            loop {
                tick.tick().await;
                let (stale_sessions, old_audit, stale_devices, old_deliveries, scrubbed_orders) = {
                    let db = state_bg.db.lock();
                    (
                        db.purge_stale_sessions(SESSION_JWT_TTL_DAYS + 1).unwrap_or(0),
                        db.purge_audit_log(AUDIT_LOG_RETENTION_DAYS).unwrap_or(0),
                        db.purge_stale_devices(KNOWN_DEVICE_RETENTION_DAYS).unwrap_or(0),
                        db.purge_newsletter_deliveries(NEWSLETTER_DELIVERY_RETENTION_DAYS)
                            .unwrap_or(0),
                        db.scrub_old_orders(SHOP_ORDER_PII_RETENTION_DAYS).unwrap_or(0),
                    )
                };
                if stale_sessions > 0 {
                    log::info!("Session cleanup: purged {} stale sessions", stale_sessions);
                }
                if old_audit + stale_devices + old_deliveries + scrubbed_orders > 0 {
                    log::info!(
                        "Retention cleanup: {} audit entries, {} stale devices, {} newsletter deliveries, {} order PII scrubs",
                        old_audit, stale_devices, old_deliveries, scrubbed_orders
                    );
                }
            }
        });
    }

    let app = Router::new()
        // Dashboard
        .route("/", get(handle_dashboard))
        // Public documentation viewer + vendored editor assets
        .route("/docs", get(docs::handle_docs_shell))
        .route("/docs/easymde.js", get(handle_easymde_js))
        .route("/docs/easymde.css", get(handle_easymde_css))
        .route("/docs/{slug}", get(docs::handle_docs_ssr_latest))
        .route("/docs/{tag}/{slug}", get(docs::handle_docs_ssr_tagged))
        // Public Xikaku website (same EasyMDE assets reused from /docs).
        // Both `/site` and `/site/{slug}` render the same SPA shell with
        // per-page SEO head (title, description, OG, JSON-LD) injected.
        .route("/site", get(website::handle_website_render_root))
        .route("/site/{slug}", get(website::handle_website_render_slug))
        // Blog: /blog on xikaku.com rewrites to /site/blog (post index, handled
        // by the {slug} route above); posts live under /site/blog/{slug}.
        .route("/site/blog/rss.xml", get(website::handle_blog_rss))
        .route("/site/blog/{slug}", get(website::handle_website_render_post))
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
        .route("/llms-full.txt", get(docs::handle_llms_full_txt))
        .route("/googledb0d71a54eee8f70.html", get(website::handle_google_site_verification))
        // IndexNow key file - Bing/Yandex/etc. fetch this to verify ownership
        // before accepting our URL update notifications. Lives under /api/v1
        // so the standard nginx /api proxy reaches it without extra routing.
        .route("/api/v1/indexnow/{filename}", get(website::handle_indexnow_key_file))
        // Health
        .route("/health", get(handle_health))
        // Available license features
        .route("/api/v1/features", get(handle_features))
        // Auth endpoints
        .route("/api/v1/auth/login", post(auth::handle_login))
        .route("/api/v1/auth/signin-code", post(auth::handle_signin_code_exchange))
        .route("/api/v1/auth/request-code", post(auth::handle_request_signin_code))
        .route("/api/v1/auth/magic-login", post(auth::handle_magic_login))
        .route("/api/v1/auth/forgot-password", post(auth::handle_forgot_password))
        .route("/api/v1/auth/reset-password", post(auth::handle_reset_password_submit))
        .route("/api/v1/auth/status", get(auth::handle_auth_status))
        .route("/api/v1/auth/logout", post(auth::handle_logout))
        .route("/api/v1/auth/change-password", post(auth::handle_change_password))
        .route("/api/v1/auth/setup-2fa", post(auth::handle_setup_2fa))
        .route("/api/v1/auth/verify-2fa", post(auth::handle_verify_2fa))
        .route("/api/v1/auth/disable-2fa", post(auth::handle_disable_2fa))
        .route("/api/v1/auth/regenerate-backup-codes", post(auth::handle_regenerate_backup_codes))
        .route("/api/v1/auth/me/email", axum::routing::put(users::handle_set_my_email))
        .route("/api/v1/auth/me/name", axum::routing::put(users::handle_set_my_name))
        .route("/api/v1/auth/me/newsletter", axum::routing::put(users::handle_set_my_newsletter))
        .route("/api/v1/auth/me/username", axum::routing::put(users::handle_rename_self))
        // Data-subject rights: JSON export (Art 15/20) + self-serve account
        // deletion (Art 17).
        .route("/api/v1/auth/me/export", get(users::handle_export_my_data))
        .route("/api/v1/auth/me", axum::routing::delete(users::handle_delete_me))
        .route("/api/v1/auth/me/devices", get(users::handle_list_my_devices))
        .route("/api/v1/auth/me/devices/{fingerprint}", axum::routing::delete(users::handle_revoke_my_device))
        // Active sessions (list / revoke)
        .route("/api/v1/auth/me/sessions", get(users::handle_list_my_sessions))
        .route("/api/v1/auth/me/sessions/{id}", axum::routing::delete(users::handle_revoke_my_session))
        .route("/api/v1/auth/me/sessions/revoke-others", post(users::handle_revoke_other_sessions))
        // API tokens (long-lived bearer tokens for headless clients)
        .route("/api/v1/auth/api-tokens", post(users::handle_create_api_token).get(users::handle_list_my_api_tokens))
        .route("/api/v1/auth/api-tokens/{id}", axum::routing::delete(users::handle_revoke_my_api_token))
        .route("/api/v1/auth/api-tokens/all", get(users::handle_list_all_api_tokens))
        .route("/api/v1/auth/api-tokens/all/{id}", axum::routing::delete(users::handle_revoke_any_api_token))
        // User management
        .route("/api/v1/auth/users", get(users::handle_list_users))
        .route("/api/v1/auth/users", post(users::handle_create_user))
        .route("/api/v1/auth/users/{username}", axum::routing::delete(users::handle_delete_user))
        .route("/api/v1/auth/users/{username}/email", axum::routing::put(users::handle_set_user_email))
        .route("/api/v1/auth/users/{username}/profile", axum::routing::put(users::handle_set_user_profile))
        .route("/api/v1/auth/users/{username}/rename", post(users::handle_rename_user))
        .route("/api/v1/auth/users/{username}/role", axum::routing::put(users::handle_set_user_role))
        .route("/api/v1/auth/users/{username}/reset-password", post(users::handle_reset_user_password))
        .route("/api/v1/auth/users/{username}/resend-invitation", post(users::handle_resend_invitation))
        .route("/api/v1/auth/users/{username}/newsletter", axum::routing::put(users::handle_set_user_newsletter))
        // Sits above /users/ so the static segment can't shadow {username}.
        .route("/api/v1/auth/newsletter-bulk", post(users::handle_set_newsletter_bulk))
        // Newsletters (admin)
        .route("/api/v1/newsletter/config", get(newsletter::handle_newsletter_config))
        .route("/api/v1/newsletter/google/authorize", get(newsletter::handle_google_authorize))
        .route("/api/v1/newsletter/google/disconnect", post(newsletter::handle_google_disconnect))
        // Public: Google redirects the browser here, so no Authorization
        // header is possible - the signed `state` parameter is the proof.
        .route("/api/v1/newsletter/google/callback", get(newsletter::handle_google_callback))
        .route("/api/v1/newsletter/audience", get(newsletter::handle_newsletter_audience))
        .route("/api/v1/newsletter/preview", post(newsletter::handle_newsletter_preview))
        .route("/api/v1/newsletter/issues", get(newsletter::handle_list_issues).post(newsletter::handle_create_issue))
        .route(
            "/api/v1/newsletter/issues/{id}",
            get(newsletter::handle_get_issue)
                .put(newsletter::handle_update_issue)
                .delete(newsletter::handle_delete_issue),
        )
        .route("/api/v1/newsletter/issues/{id}/deliveries", get(newsletter::handle_list_deliveries))
        .route("/api/v1/newsletter/issues/{id}/test", post(newsletter::handle_test_send))
        .route("/api/v1/newsletter/issues/{id}/send", post(newsletter::handle_send_issue))
        // Public: an <a> click from a mail client carries no auth header, so
        // the signed token in the query string is the credential.
        .route(
            "/api/v1/newsletter/unsubscribe",
            get(newsletter::handle_unsubscribe).post(newsletter::handle_unsubscribe),
        )
        // Public client endpoints
        .route("/api/v1/activate", post(client_api::handle_activate))
        .route("/api/v1/verify", post(client_api::handle_verify))
        .route("/api/v1/deactivate", post(client_api::handle_deactivate))
        .route("/api/v1/licenses/{key}/status", get(client_api::handle_license_status))
        // Admin endpoints (JWT-protected)
        .route("/api/v1/licenses", get(licenses::handle_list_licenses))
        .route("/api/v1/licenses", post(licenses::handle_create_license))
        .route("/api/v1/licenses/{key}", get(licenses::handle_get_license).put(licenses::handle_update_license).delete(licenses::handle_delete_license))
        .route("/api/v1/licenses/{key}/revoke", post(licenses::handle_revoke_license))
        .route("/api/v1/licenses/{key}/export", post(licenses::handle_export_license))
        .route("/api/v1/licenses/{key}/users", post(licenses::handle_assign_license_user))
        .route("/api/v1/licenses/{key}/users/{username}", axum::routing::delete(licenses::handle_unassign_license_user))
        // Self-serve portal: read/manage only the caller's assigned licenses.
        .route("/api/v1/my/licenses", get(licenses::handle_my_licenses))
        .route("/api/v1/my/licenses/{key}/export", post(licenses::handle_my_export_license))
        .route("/api/v1/my/licenses/{key}/machines/{machine_code}", axum::routing::delete(licenses::handle_my_deactivate_machine))
        .route("/api/v1/licenses/{key}/export-token", post(licenses::handle_export_token))
        .route(
            "/api/v1/licenses/{key}/machines/{machine_code}",
            axum::routing::delete(licenses::handle_deactivate_machine),
        )
        .route(
            "/api/v1/licenses/{key}/machines/{machine_code}/tombstone",
            axum::routing::delete(licenses::handle_clear_machine_tombstone),
        )
        // Releases - client endpoints (license-key protected)
        .route("/api/v1/updates/releases", get(releases::handle_get_releases))
        .route("/api/v1/updates/download/{tag}/{asset}", get(releases::handle_download_asset))
        .route("/api/v1/updates/download-ticket", post(releases::handle_mint_download_ticket))
        // Public "latest installer" redirect for publicly-downloadable products,
        // e.g. /download/fusionhub/windows -> newest matching asset. Lets the
        // marketing site link a stable URL that never needs editing per release.
        .route("/download/{product}/{platform}", get(releases::handle_public_latest_download))
        // Releases - admin endpoints (JWT protected)
        .route("/api/v1/releases", get(releases::handle_list_releases_admin))
        .merge(
            Router::new()
                .route("/api/v1/releases", post(releases::handle_upload_release))
                .route("/api/v1/releases/{tag}/assets/{file}/replace", post(releases::handle_replace_release_asset))
                .layer(DefaultBodyLimit::max(500 * 1024 * 1024))
        )
        .route("/api/v1/releases/{tag}", axum::routing::put(releases::handle_update_release).delete(releases::handle_delete_release))
        .route("/api/v1/releases/{tag}/assets/{file}", axum::routing::delete(releases::handle_delete_release_asset))
        // Workspace endpoints (JWT protected)
        .route("/api/v1/workspaces", get(workspaces::handle_list_workspaces).post(workspaces::handle_create_workspace))
        .route("/api/v1/workspaces/{id}", get(workspaces::handle_get_workspace).put(workspaces::handle_update_workspace).delete(workspaces::handle_delete_workspace))
        .route("/api/v1/workspaces/{id}/members", post(workspaces::handle_add_workspace_member))
        .route("/api/v1/workspaces/{id}/members/{username}", axum::routing::delete(workspaces::handle_remove_workspace_member))
        // Config revision endpoints (JWT protected)
        .route("/api/v1/workspaces/{id}/configs", get(workspaces::handle_list_configs).post(workspaces::handle_push_config))
        .route("/api/v1/workspaces/{id}/configs/latest", get(workspaces::handle_get_latest_config))
        .route("/api/v1/workspaces/{id}/configs/{config_id}", get(workspaces::handle_get_config).put(workspaces::handle_update_config).delete(workspaces::handle_delete_config))
        // FusionHub federation: shared channel secret + peer registry
        .route("/api/v1/workspaces/{id}/federation", get(workspaces::handle_get_workspace_federation))
        .route("/api/v1/workspaces/{id}/federation/rotate", post(workspaces::handle_rotate_workspace_federation))
        .route("/api/v1/workspaces/{id}/peers", post(workspaces::handle_register_workspace_peer))
        .route("/api/v1/workspaces/{id}/peers/{host_id}", axum::routing::delete(workspaces::handle_delete_workspace_peer))
        // Shared workspace graph (one node-graph per workspace, version-tracked
        // for optimistic-lock concurrent edits between member fusionhubs).
        .route("/api/v1/workspaces/{id}/graph", get(workspaces::handle_get_workspace_graph).put(workspaces::handle_put_workspace_graph))
        // Workspace recordings: presigned-URL upload/download to S3.
        .route("/api/v1/workspaces/{id}/recordings", get(workspaces::handle_list_recordings).post(workspaces::handle_init_recording))
        .route("/api/v1/workspaces/{id}/recordings/{rid}", axum::routing::delete(workspaces::handle_delete_recording))
        .route("/api/v1/workspaces/{id}/recordings/{rid}/complete", post(workspaces::handle_complete_recording))
        .route("/api/v1/workspaces/{id}/recordings/{rid}/download", get(workspaces::handle_get_recording_download))
        // Back-compat shim: deployed FusionHub UIs still poll this; answers [].
        .route("/api/v1/workspaces/{id}/releases", get(workspaces::handle_workspace_releases))
        // Workspace files: flat member-writable file share (upload gets the
        // large body limit release uploads use).
        .route("/api/v1/workspaces/{id}/files", get(workspaces::handle_list_workspace_files))
        .merge(
            Router::new()
                .route("/api/v1/workspaces/{id}/files", post(workspaces::handle_upload_workspace_files))
                .layer(DefaultBodyLimit::max(500 * 1024 * 1024))
        )
        .route(
            "/api/v1/workspaces/{id}/files/{file}",
            get(workspaces::handle_download_workspace_file).delete(workspaces::handle_delete_workspace_file),
        )
        // Short-lived download ticket so the dashboard can hand the file URL
        // to the browser's native download UI without a JWT in the URL.
        .route(
            "/api/v1/workspaces/{id}/files/{file}/ticket",
            post(workspaces::handle_mint_workspace_file_ticket),
        )
        // Workspace docs: one flat page tree per workspace, member-writable.
        .route("/api/v1/workspaces/{id}/docs/pages", get(docs::handle_ws_list_doc_pages))
        .route(
            "/api/v1/workspaces/{id}/docs/pages/{slug}",
            get(docs::handle_ws_get_doc_page)
                .put(docs::handle_ws_upsert_doc_page)
                .delete(docs::handle_ws_delete_doc_page),
        )
        .route("/api/v1/workspaces/{id}/docs/pages/{slug}/rename", post(docs::handle_ws_rename_doc_page))
        .merge(
            Router::new()
                .route("/api/v1/workspaces/{id}/docs/assets", post(docs::handle_ws_upload_doc_asset))
                .layer(DefaultBodyLimit::max(100 * 1024 * 1024))
        )
        .route(
            "/api/v1/workspaces/{id}/docs/assets/{file}",
            get(docs::handle_ws_get_doc_asset).delete(docs::handle_ws_delete_doc_asset),
        )
        // Workspace tickets: member-writable issue list, comments visible to
        // every member. Cross-workspace admin view lives at /admin/tickets.
        .route(
            "/api/v1/workspaces/{id}/tickets",
            get(tickets::handle_list_tickets).post(tickets::handle_create_ticket),
        )
        .route(
            "/api/v1/workspaces/{id}/tickets/{tid}",
            get(tickets::handle_get_ticket)
                .put(tickets::handle_update_ticket)
                .delete(tickets::handle_delete_ticket),
        )
        .route(
            "/api/v1/workspaces/{id}/tickets/{tid}/comments",
            post(tickets::handle_add_ticket_comment),
        )
        .route(
            "/api/v1/workspaces/{id}/tickets/{tid}/comments/{cid}",
            axum::routing::delete(tickets::handle_delete_ticket_comment),
        )
        // Products catalog
        .route("/api/v1/products", get(releases::handle_list_products).post(releases::handle_create_product))
        .route(
            "/api/v1/products/{product}",
            axum::routing::put(releases::handle_update_product).delete(releases::handle_delete_product),
        )
        // Docs - legacy tag-only endpoints (back-compat shim: pin the default
        // product so already-deployed FusionHubs keep working. Remove once every
        // client uses the product-scoped routes below).
        .route("/api/v1/docs/releases", get(docs::handle_list_doc_releases))
        .route("/api/v1/docs/releases/latest", get(docs::handle_latest_doc_release))
        .route("/api/v1/docs/{tag}/pages", get(docs::handle_list_doc_pages))
        .route("/api/v1/docs/{tag}/pages/{slug}", get(docs::handle_get_doc_page))
        .route(
            "/api/v1/docs/{tag}/assets/{file}",
            get(docs::handle_get_doc_asset).delete(docs::handle_delete_doc_asset),
        )
        // Docs - product-scoped endpoints (`/api/v1/products/{product}/docs/...`),
        // parallel to the workspace docs routes.
        .route("/api/v1/products/{product}/docs/releases", get(docs::handle_list_doc_releases_p))
        .route("/api/v1/products/{product}/docs/releases/latest", get(docs::handle_latest_doc_release_p))
        .route("/api/v1/products/{product}/docs/{tag}/pages", get(docs::handle_list_doc_pages_p))
        .route("/api/v1/products/{product}/docs/{tag}/pages/{slug}", get(docs::handle_get_doc_page_p))
        .route(
            "/api/v1/products/{product}/docs/{tag}/assets/{file}",
            get(docs::handle_get_doc_asset_p).delete(docs::handle_delete_doc_asset_p),
        )
        // Docs - admin write endpoints (JWT). Bulk import + asset upload get the larger body limit.
        .merge(
            Router::new()
                .route("/api/v1/docs/{tag}/import", post(docs::handle_bulk_import_docs))
                .route("/api/v1/docs/{tag}/assets", post(docs::handle_upload_doc_asset))
                .route("/api/v1/products/{product}/docs/{tag}/import", post(docs::handle_bulk_import_docs_p))
                .route("/api/v1/products/{product}/docs/{tag}/assets", post(docs::handle_upload_doc_asset_p))
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
        .route(
            "/api/v1/products/{product}/docs/{tag}/pages/{slug}",
            axum::routing::put(docs::handle_upsert_doc_page_p)
                .delete(docs::handle_delete_doc_page_p),
        )
        .route(
            "/api/v1/products/{product}/docs/{tag}/pages/{slug}/rename",
            post(docs::handle_rename_doc_page_p),
        )
        // Website - public read
        .route("/api/v1/website/pages", get(website::handle_list_pages))
        .route("/api/v1/website/pages/{slug}", get(website::handle_get_page))
        .route("/api/v1/website/assets/{file}", get(website::handle_get_asset))
        // Website - admin write (asset upload gets the larger body limit)
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
            "/api/v1/website/pages/{slug}/visibility",
            post(website::handle_set_page_hidden),
        )
        .route(
            "/api/v1/website/assets/{file}",
            axum::routing::delete(website::handle_delete_asset),
        )
        // Website admin - page revisions (history)
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
        // Website admin - asset admin (usage, rename)
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
        // Public HTML shell - same shell serves /shop, /shop/{sku}, /shop/success, /shop/cancel.
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
        // Orders (JWT) - Stripe is the source of truth for payment, susi
        // tracks fulfillment state on top of it.
        .route("/api/v1/shop/admin/orders", get(shop::handle_admin_list_orders))
        .route(
            "/api/v1/shop/admin/orders/{id}",
            get(shop::handle_admin_get_order).delete(shop::handle_admin_delete_order),
        )
        .route("/api/v1/shop/admin/orders/{id}/ship", post(shop::handle_admin_mark_shipped))
        .route("/api/v1/shop/admin/orders/{id}/notes", axum::routing::put(shop::handle_admin_update_order_notes))
        // Shop settings (JWT) - admin notification recipients, customer email
        // toggles, support contact, etc.
        .route(
            "/api/v1/shop/admin/settings",
            get(shop::handle_admin_get_settings)
                .put(shop::handle_admin_put_settings),
        )
        // Site-wide settings (JWT) - analytics IDs and other site-level config.
        .route(
            "/api/v1/site/admin/settings",
            get(website::handle_admin_get_site_settings)
                .put(website::handle_admin_put_site_settings),
        )
        // Dropbox backups (JWT, admin-only)
        .route("/api/v1/admin/backup/status", get(backup::handle_backup_status))
        .route(
            "/api/v1/admin/backup/settings",
            axum::routing::put(backup::handle_backup_put_settings),
        )
        .route("/api/v1/admin/backup/connect-url", get(backup::handle_backup_connect_url))
        .route("/api/v1/admin/backup/connect", post(backup::handle_backup_connect))
        .route("/api/v1/admin/backup/disconnect", post(backup::handle_backup_disconnect))
        .route("/api/v1/admin/backup/run", post(backup::handle_backup_run))
        // Admin audit trail (JWT, admin-only)
        .route("/api/v1/audit", get(handle_list_audit))
        // Cross-workspace ticket list (JWT, admin-only)
        .route("/api/v1/admin/tickets", get(tickets::handle_admin_list_tickets))
        // Default-deny auth gate for the API surface (ASVS V4.1 single
        // enforcement point): every /api request needs a valid principal
        // unless the (method, path) is on the explicit public allow-list.
        // Handlers keep their own fine-grained checks - this layer only
        // guarantees a forgotten one fails closed.
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            enforce_api_auth,
        ))
        // Output security headers on every response. Inline script/style stay
        // allowed (the dashboard/docs/site/shop shells are inline-heavy SPAs);
        // the external allow-list covers Google Analytics, Cloudflare
        // Turnstile, and YouTube/Vimeo embeds used by site content.
        // `if_not_present` lets an individual handler override.
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(SECURITY_CSP),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static(
                "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
            ),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        ))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarize_chrome_on_windows() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                  (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36";
        assert_eq!(summarize_user_agent(ua), "Chrome 148 / Windows");
        // No "148.0.0.0" pattern that Gmail would auto-linkify as an IP.
        assert!(!summarize_user_agent(ua).contains("148.0.0.0"));
    }

    #[test]
    fn summarize_edge_takes_precedence_over_chrome() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                  (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.2783.54";
        assert_eq!(summarize_user_agent(ua), "Edge 148 / Windows");
    }

    #[test]
    fn summarize_firefox_on_macos() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.6; rv:132.0) Gecko/20100101 Firefox/132.0";
        assert_eq!(summarize_user_agent(ua), "Firefox 132 / macOS");
    }

    #[test]
    fn summarize_safari_uses_version_marker() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 \
                  (KHTML, like Gecko) Version/17.6 Safari/605.1.15";
        assert_eq!(summarize_user_agent(ua), "Safari 17 / macOS");
    }

    #[test]
    fn summarize_chrome_on_android() {
        let ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 \
                  (KHTML, like Gecko) Chrome/148.0.0.0 Mobile Safari/537.36";
        assert_eq!(summarize_user_agent(ua), "Chrome 148 / Android");
    }

    #[test]
    fn summarize_empty_input_falls_back() {
        assert_eq!(summarize_user_agent(""), "(unknown device)");
        assert_eq!(summarize_user_agent("   "), "(unknown device)");
    }

    #[test]
    fn summarize_garbage_input_returns_trimmed_copy() {
        let custom = "MacBook in office";
        assert_eq!(summarize_user_agent(custom), custom);
    }
}
