//! The newsletter: compose in Markdown, send to everyone who subscribed.
//!
//! Consent is opt-in (`users.newsletter_opt_in`, default 0) and is the only
//! filter on the audience, so a user who never subscribed is never in a send
//! list. Transactional mail - sign-in codes, password resets, invitations -
//! ignores the flag entirely.
//!
//! The audience endpoint exists so a send is never confirmed blind: the admin
//! UI shows the resolved counts before anything goes out.

use crate::email::InlineImage;
use crate::*;

// ---------------------------------------------------------------------------
// Markdown -> email HTML
// ---------------------------------------------------------------------------

/// Per-tag inline styles. Email clients drop <style> blocks and never resolve
/// CSS custom properties, so `website::render_body_html` - whose output is
/// styled entirely by `.content` descendant selectors using var(--border) -
/// arrives completely unstyled in Outlook and the Gmail app. Every rule here
/// therefore has to ride on the element itself.
/// Sizes, spacing and the content width mirror the public site's `.content`
/// block in website.html, so a newsletter reads like the pages it links to.
/// Colours are the email palette (fixed dark-on-white), not the site's theme
/// variables, which do not resolve in a mail client.
const TAG_STYLES: &[(&str, &str)] = &[
    // website: .content h1 { font-size: 28px; font-weight: 400; line-height: 1.14 }
    ("h1", "margin:0 0 18px;font-weight:400;font-size:28px;line-height:1.14;"),
    // website h2 carries a bottom rule; keep it, it separates sections well.
    ("h2", "margin:32px 0 12px;font-weight:600;font-size:21px;line-height:1.3;\
            padding-bottom:6px;border-bottom:1px solid #e4e6ea;"),
    ("h3", "margin:24px 0 10px;font-weight:600;font-size:16px;line-height:1.3;"),
    ("h4", "margin:18px 0 8px;font-weight:600;font-size:14px;line-height:1.3;color:#5c6470;"),
    ("p", "margin:10px 0;"),
    ("ul", "margin:10px 0;padding-left:24px;"),
    ("ol", "margin:10px 0;padding-left:24px;"),
    ("li", "margin:4px 0;"),
    ("a", "color:#2563eb;text-decoration:none;"),
    // website: .content img { max-width:100%; margin:16px auto; display:block }
    ("img", "max-width:100%;height:auto;display:block;margin:16px auto;border:0;border-radius:8px;"),
    ("blockquote", "margin:14px 0;padding:8px 14px;border-left:3px solid #2563eb;\
                    background:#eef2ff;"),
    ("table", "border-collapse:collapse;margin:14px 0;width:100%;"),
    ("th", "border:1px solid #e4e6ea;padding:7px 11px;text-align:left;vertical-align:top;\
            background:#f3f4f6;font-weight:600;"),
    ("td", "border:1px solid #e4e6ea;padding:7px 11px;text-align:left;vertical-align:top;"),
    ("pre", "margin:14px 0;padding:14px 16px;background:#f3f4f6;border:1px solid #e4e6ea;\
             border-radius:8px;overflow-x:auto;\
             font-family:'SF Mono',Consolas,'Fira Code',monospace;font-size:13px;"),
    ("code", "font-family:'SF Mono',Consolas,'Fira Code',monospace;font-size:13px;\
              background:#f3f4f6;padding:1px 6px;border-radius:4px;"),
    ("hr", "border:0;border-top:1px solid #e4e6ea;margin:22px 0;"),
];

/// A <code> directly inside <pre> must not repeat the block's background and
/// padding, which would render as a box inside a box.
const PRE_CODE_STYLE: &str = "font-family:inherit;font-size:inherit;background:none;padding:0;";

/// Rewrite one URL from the markdown source into something an inbox can fetch.
///
/// Three shapes occur. Absolute and scheme-qualified URLs pass through.
/// Root-relative paths resolve against the site base. A bare filename is what
/// the EasyMDE upload hook writes (its onSuccess is handed `data.name`, not a
/// URL) - on the web a client-side `resolveAssetUrl` patches those up, but an
/// email client has no such hook, so an unresolved one is a broken image.
fn absolutize(url: &str, base_url: &str, asset_base: &str) -> String {
    let u = url.trim();
    if u.is_empty() {
        return String::new();
    }
    let lower = u.to_ascii_lowercase();
    if lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("mailto:")
        || lower.starts_with("tel:")
        || lower.starts_with("data:")
        || u.starts_with("//")
        || u.starts_with('#')
    {
        return u.to_string();
    }
    match u.strip_prefix('/') {
        Some(rest) => format!("{}/{}", base_url.trim_end_matches('/'), rest),
        None => format!("{}/{}", asset_base.trim_end_matches('/'), u),
    }
}

/// Insert `style="..."` into opening tags of already-sanitized HTML.
///
/// This runs AFTER ammonia deliberately. Allowing `style` through the sanitizer
/// would mean trusting author CSS; instead the markdown is cleaned with the
/// strict default allowlist (which drops every style attribute) and the styling
/// is applied to the known-good output. Attribute values in that output are
/// already entity-escaped, so scanning for `<tag` cannot match inside one.
fn inject_styles(html: &str) -> String {
    let bytes = html.as_bytes();
    let mut out = String::with_capacity(html.len() * 2);
    let mut i = 0;
    let mut in_pre = false;
    while i < bytes.len() {
        if bytes[i] != b'<' || i + 1 >= bytes.len() || !bytes[i + 1].is_ascii_alphabetic() {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut end = start;
        while end < bytes.len() && bytes[end].is_ascii_alphanumeric() {
            end += 1;
        }
        let name = &html[start..end];
        // Only a tag name followed by a delimiter counts; `<hr>` must not match
        // a rule for `<h`.
        let delimited = end >= bytes.len()
            || bytes[end] == b'>'
            || bytes[end] == b'/'
            || bytes[end].is_ascii_whitespace();
        let style = if !delimited {
            None
        } else if name.eq_ignore_ascii_case("code") && in_pre {
            Some(PRE_CODE_STYLE)
        } else {
            TAG_STYLES
                .iter()
                .find(|(t, _)| name.eq_ignore_ascii_case(t))
                .map(|(_, s)| *s)
        };
        out.push('<');
        out.push_str(name);
        if let Some(s) = style {
            out.push_str(" style=\"");
            out.push_str(s);
            out.push('"');
        }
        // pulldown-cmark emits <pre><code> adjacently, so a one-tag memory is
        // all the nesting state this needs.
        in_pre = name.eq_ignore_ascii_case("pre");
        i = end;
    }
    out
}

fn markdown_options() -> pulldown_cmark::Options {
    use pulldown_cmark::Options;
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    // ENABLE_SMART_PUNCTUATION is deliberately NOT set: it rewrites `--` into
    // an en dash and straight quotes into curly ones, and typographic dashes
    // are banned in customer-facing copy.
    opts
}

/// Render newsletter markdown into a complete, inbox-ready HTML body.
///
/// Pipeline order is load-bearing: absolutize URLs on the event stream, render,
/// sanitize with the strict default allowlist, and only then inject inline
/// styles. Sanitizing last would strip the styles; allowing `style` through the
/// sanitizer would trust author CSS.
pub(crate) fn render_email_html(
    body_md: &str,
    base_url: &str,
    asset_base: &str,
    footer_html: &str,
) -> String {
    render_email_html_with_images(body_md, base_url, asset_base, footer_html, None).0
}

/// As `render_email_html`, but when `assets_dir` is given, local images are
/// rewritten to `cid:` references and returned alongside the bytes to attach.
///
/// Remote images are blocked by default in Gmail and Outlook, so a URL-only
/// mail shows blank boxes until the recipient opts in - and a private or
/// not-yet-public host (a laptop, a staging box) can never serve them at all,
/// since Gmail fetches images through its own proxy rather than from the
/// reader's machine. Embedding sidesteps both. Only assets that resolve inside
/// `assets_dir` are embedded; anything else stays a plain URL.
pub(crate) fn render_email_html_with_images(
    body_md: &str,
    base_url: &str,
    asset_base: &str,
    footer_html: &str,
    assets_dir: Option<&std::path::Path>,
) -> (String, Vec<InlineImage>) {
    use pulldown_cmark::{html, Event, Parser, Tag};

    let mut inline: Vec<InlineImage> = Vec::new();
    let mut seen: HashMap<String, String> = HashMap::new();

    let parser = Parser::new_ext(body_md, markdown_options()).map(|ev| match ev {
        Event::Start(Tag::Link { link_type, dest_url, title, id }) => {
            Event::Start(Tag::Link {
                link_type,
                dest_url: absolutize(&dest_url, base_url, asset_base).into(),
                title,
                id,
            })
        }
        Event::Start(Tag::Image { link_type, dest_url, title, id }) => {
            let resolved = match assets_dir {
                Some(dir) => embed_local_image(&dest_url, dir, &mut inline, &mut seen)
                    .unwrap_or_else(|| absolutize(&dest_url, base_url, asset_base)),
                None => absolutize(&dest_url, base_url, asset_base),
            };
            Event::Start(Tag::Image { link_type, dest_url: resolved.into(), title, id })
        }
        other => other,
    });

    let mut raw = String::with_capacity(body_md.len() * 2);
    html::push_html(&mut raw, parser);
    // `cid` is not in ammonia's default scheme allowlist, so without this the
    // sanitizer silently strips the src of every embedded image. Safe to add:
    // a cid: URL can only address a part of this same message.
    let clean = ammonia::Builder::default()
        .add_url_schemes(&["cid"])
        .clean(&raw)
        .to_string();
    let styled = inject_styles(&clean);

    // Font stack, 16px base and 1.71 line-height come from the site's
    // `.content` rule. 640px rather than the site's 880px: that width assumes
    // a full browser window, while a mail client renders in a reading pane -
    // and Outlook ignores max-width entirely, so the number here is what its
    // fixed-width layout actually uses.
    let html = format!(
        "<div style=\"font-family:ui-sans-serif,-apple-system,BlinkMacSystemFont,'Segoe UI',\
         Ubuntu,'Helvetica Neue',sans-serif;font-size:16px;line-height:1.71;\
         max-width:640px;margin:0 auto;padding:0 16px;color:#1a1d23;\">{body}{footer}</div>",
        body = styled,
        footer = footer_html,
    );
    // Drop attachments the sanitizer removed, so a stripped <img> can't leave
    // an orphaned part inflating every message.
    inline.retain(|img| html.contains(&format!("cid:{}", img.content_id)));
    (html, inline)
}

/// Largest asset embedded in a message. Above this the image stays a URL: past
/// a few megabytes the per-recipient cost outweighs guaranteed display, and
/// some providers reject oversized messages outright.
const MAX_INLINE_IMAGE_BYTES: u64 = 4 * 1024 * 1024;

/// Turn one markdown image target into a `cid:` reference, reading the bytes
/// from the website asset store. Returns None when the target isn't a local
/// asset, is too large, or can't be read - the caller then falls back to a URL.
fn embed_local_image(
    dest: &str,
    assets_dir: &std::path::Path,
    inline: &mut Vec<InlineImage>,
    seen: &mut HashMap<String, String>,
) -> Option<String> {
    let raw = dest.trim();
    // Accept what the composer writes (a bare filename) and what an author may
    // paste (the asset URL). Anything else - external host, data:, mailto: -
    // is left alone.
    let name = raw
        .rsplit_once("/api/v1/website/assets/")
        .map(|(_, n)| n)
        .unwrap_or(raw);
    if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains("..") {
        return None;
    }
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("http") || lower.starts_with("data:") || lower.starts_with("cid:") {
        return None;
    }
    // Same file twice in one issue gets one attachment.
    if let Some(cid) = seen.get(name) {
        return Some(format!("cid:{}", cid));
    }

    let path = assets_dir.join(name);
    let meta = std::fs::metadata(&path).ok()?;
    if !meta.is_file() || meta.len() > MAX_INLINE_IMAGE_BYTES {
        return None;
    }
    let mime = image_mime(&lower)?;
    let bytes = std::fs::read(&path).ok()?;

    // Content-ID must be globally unique and free of angle brackets.
    let cid = format!("nl{}@susi", uuid::Uuid::new_v4().simple());
    inline.push(InlineImage {
        content_id: cid.clone(),
        mime_type: mime.to_string(),
        bytes: bytes.into(),
    });
    seen.insert(name.to_string(), cid.clone());
    Some(format!("cid:{}", cid))
}

/// Where the composer's uploaded images land - the website asset store, which
/// `website::assets_dir` owns. Mirrored rather than shared because that helper
/// is private to its module.
pub(crate) fn newsletter_assets_dir(state: &AppState) -> std::path::PathBuf {
    std::path::Path::new(&state.data_dir).join("website").join("assets")
}

/// Only real raster image types are embedded. SVG is deliberately excluded:
/// it can carry script, and mail clients handle it inconsistently.
fn image_mime(lower_name: &str) -> Option<&'static str> {
    if lower_name.ends_with(".png") {
        Some("image/png")
    } else if lower_name.ends_with(".jpg") || lower_name.ends_with(".jpeg") {
        Some("image/jpeg")
    } else if lower_name.ends_with(".gif") {
        Some("image/gif")
    } else if lower_name.ends_with(".webp") {
        Some("image/webp")
    } else {
        None
    }
}

/// Plain-text alternative. Every send is multipart/alternative, and a text part
/// that is just the raw markdown reads badly and hurts deliverability.
pub(crate) fn render_email_text(body_md: &str, base_url: &str, asset_base: &str) -> String {
    use pulldown_cmark::{Event, Parser, Tag, TagEnd};

    let mut out = String::with_capacity(body_md.len());
    let mut link_dest: Option<String> = None;
    for ev in Parser::new_ext(body_md, markdown_options()) {
        match ev {
            Event::Text(t) | Event::Code(t) => out.push_str(&t),
            Event::SoftBreak => out.push(' '),
            Event::HardBreak => out.push('\n'),
            Event::Rule => out.push_str("\n----------\n\n"),
            Event::Start(Tag::Item) => out.push_str("- "),
            Event::Start(Tag::Link { dest_url, .. }) => {
                link_dest = Some(absolutize(&dest_url, base_url, asset_base));
            }
            Event::Start(Tag::Image { dest_url, .. }) => {
                out.push_str(&format!("[image: {}]", absolutize(&dest_url, base_url, asset_base)));
            }
            Event::End(TagEnd::Link) => {
                if let Some(d) = link_dest.take() {
                    out.push_str(&format!(" ({})", d));
                }
            }
            Event::End(TagEnd::Item) => out.push('\n'),
            Event::End(TagEnd::Paragraph)
            | Event::End(TagEnd::Heading(_))
            | Event::End(TagEnd::List(_))
            | Event::End(TagEnd::BlockQuote(_))
            | Event::End(TagEnd::CodeBlock) => out.push_str("\n\n"),
            Event::End(TagEnd::TableRow) | Event::End(TagEnd::TableHead) => out.push('\n'),
            Event::End(TagEnd::TableCell) => out.push('\t'),
            _ => {}
        }
    }
    while out.contains("\n\n\n") {
        out = out.replace("\n\n\n", "\n\n");
    }
    out.trim().to_string()
}

/// Whether campaign mail can actually go out. The composer checks this on open
/// so an admin learns the relay is unconfigured before writing an issue, not
/// after clicking Send.
pub(crate) async fn handle_newsletter_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_owner(&state, &principal)?;
    let google = {
        let db = state.db.lock();
        db.get_newsletter_google_account().ok().flatten()
    };
    Ok(Json(serde_json::json!({
        "sending_configured": state.newsletter_email.is_some() || google.is_some(),
        "static_smtp_configured": state.newsletter_email.is_some(),
        "google_oauth_available": state.google_oauth.configured(),
        "google_account": google.as_ref().map(|(a, _)| a.clone()),
        "google_connected_at": google.as_ref().map(|(_, t)| t.clone()),
        "base_url_configured": !state.magic_link_base_url.trim().is_empty(),
        "rate_per_min": state.newsletter_rate_per_min,
    })))
}

pub(crate) async fn handle_newsletter_audience(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_owner(&state, &principal)?;

    let db = state.db.lock();
    let audience = db
        .newsletter_audience()
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({
        "recipients": audience.recipients.len(),
        "opted_out": audience.opted_out,
        "no_email": audience.no_email,
        // Addresses themselves stay out of the summary: the admin UI only needs
        // counts to decide, and a full customer email dump on every panel open
        // is a needless exposure.
        "sample": audience.recipients.iter().take(5).map(|r| &r.email).collect::<Vec<_>>(),
    })))
}

/// Base URL for links and root-relative assets, plus the public asset store
/// that bare filenames resolve against. Sending is refused when the base is
/// empty: there is no way to absolutize an image or build an unsubscribe link,
/// and a mail full of dead relative URLs is worse than no mail.
pub(crate) fn email_base_urls(
    state: &AppState,
) -> Result<(String, String), (StatusCode, Json<ErrorResponse>)> {
    let base = state.magic_link_base_url.trim_end_matches('/').to_string();
    if base.is_empty() {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "SUSI_MAGIC_LINK_BASE_URL is not configured - newsletter links and images would be dead",
        ));
    }
    let assets = format!("{}/api/v1/website/assets", base);
    Ok((base, assets))
}

// ---------------------------------------------------------------------------
// Unsubscribe
// ---------------------------------------------------------------------------

/// No expiry by design - the link has to keep working for as long as the mail
/// sits in an archive. It is single-purpose (a dedicated JWT audience) and its
/// only effect is clearing a consent flag, so an old one is harmless.
pub(crate) fn mint_unsubscribe_token(secret: &[u8; 32], username: &str) -> Option<String> {
    let claims = UnsubscribeClaims {
        sub: username.to_string(),
        aud: UNSUBSCRIBE_AUDIENCE.to_string(),
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret)).ok()
}

fn validate_unsubscribe_token(
    secret: &[u8; 32],
    token: &str,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_audience(&[UNSUBSCRIBE_AUDIENCE]);
    // Tokens carry no `exp`; without this jsonwebtoken rejects them outright.
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    decode::<UnsubscribeClaims>(token, &DecodingKey::from_secret(secret), &validation)
        .map(|d| d.claims.sub)
        .map_err(|_| error_response(StatusCode::BAD_REQUEST, "Invalid unsubscribe link"))
}

pub(crate) fn unsubscribe_url(state: &AppState, base: &str, username: &str) -> Option<String> {
    mint_unsubscribe_token(&state.jwt_secret, username)
        .map(|t| format!("{}/api/v1/newsletter/unsubscribe?token={}", base, t))
}

/// Footer carried by every campaign mail. States why the recipient is getting
/// it and how to stop, which is both a legal expectation and what keeps a
/// sending domain out of spam folders.
fn unsubscribe_footer(url: &str) -> String {
    format!(
        "<div style=\"margin:32px 0 0;padding:16px 0 0;border-top:1px solid #e4e6ea;\
         font-size:13px;line-height:1.5;\">\
           <p style=\"margin:0 0 6px;\">You are receiving this because you subscribed to the \
            newsletter from Susi by LP-Research.</p>\
           <p style=\"margin:0;\"><a href=\"{url}\" style=\"color:#2563eb;text-decoration:none;\">\
            Unsubscribe</a></p>\
         </div>",
        url = html_escape(url),
    )
}

fn unsubscribe_footer_text(url: &str) -> String {
    format!(
        "\n\n----------\nYou are receiving this because you subscribed to the newsletter from \
         Susi by LP-Research.\nUnsubscribe: {}\n",
        url
    )
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

#[derive(Deserialize)]
pub(crate) struct UnsubscribeQuery {
    token: String,
}

/// Public, unauthenticated, and reachable from a mail client. An `<a>` click
/// carries no Authorization header, so the token in the URL is the credential -
/// exactly the shape the release-download ticket already uses.
///
/// GET renders a confirmation page; POST is the RFC 8058 one-click path that
/// mailbox providers call on the recipient's behalf. Both are idempotent.
pub(crate) async fn handle_unsubscribe(
    State(state): State<Arc<AppState>>,
    Query(q): Query<UnsubscribeQuery>,
) -> Result<axum::response::Html<String>, (StatusCode, Json<ErrorResponse>)> {
    let username = validate_unsubscribe_token(&state.jwt_secret, &q.token)?;
    {
        let db = state.db.lock();
        db.set_user_newsletter_opt_in(&username, false)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    }
    log::info!("Newsletter unsubscribe: {}", username);

    // Inline styles only: the global CSP is default-src 'self', and this page
    // is opened straight from a mail client.
    Ok(axum::response::Html(format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>Unsubscribed</title></head>\
         <body style=\"font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;\
          max-width:540px;margin:60px auto;padding:0 20px;color:#1a1d23;line-height:1.55;\">\
           <h1 style=\"font-size:22px;font-weight:600;margin:0 0 14px;\">You have been unsubscribed</h1>\
           <p style=\"margin:0 0 14px;\">{user} will no longer receive the newsletter from \
            Susi by LP-Research.</p>\
           <p style=\"margin:0 0 14px;\">Account email such as sign-in codes and password resets \
            is unaffected.</p>\
           <p style=\"margin:0;font-size:13px;\">Changed your mind? Turn the newsletter back on \
            under Account Settings.</p>\
         </body></html>",
        user = html_escape(&username),
    )))
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Google OAuth connector (Gmail relay)
// ---------------------------------------------------------------------------
//
// An alternative to storing an app password on the host: an admin connects a
// Google Workspace account from the dashboard and campaign mail goes out over
// Gmail SMTP authenticated with XOAUTH2.
//
// The `gmail.send` scope is RESTRICTED. That is fine here because the OAuth
// client is an "Internal" app inside the lp-research.com Workspace org, which
// Google exempts from verification. Publishing the same client as "External"
// would require a security assessment, and leaving it in Testing mode would
// silently break the connection every 7 days when the refresh token expires.
//
// Unlike the Dropbox backup connector, this cannot use a copy-paste code flow:
// Google shut down the OOB (`urn:ietf:wg:oauth:2.0:oob`) flow, so a real
// redirect URI is required and must be registered in the Cloud console.

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v3/userinfo";
const GMAIL_SEND_SCOPE: &str = "https://www.googleapis.com/auth/gmail.send openid email";
const GMAIL_SMTP_HOST: &str = "smtp.gmail.com";
const GMAIL_SMTP_PORT: u16 = 587;

/// Refresh a little before the hour is up so a long campaign never trips over
/// an expiry mid-batch.
const TOKEN_EARLY_REFRESH_SECS: u64 = 120;

#[derive(Clone, Default)]
pub(crate) struct GoogleOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub from_name: String,
    /// Optional send-as alias. Empty means send as the connected account.
    pub from_addr_override: String,
}

impl GoogleOAuthConfig {
    pub fn configured(&self) -> bool {
        !self.client_id.is_empty() && !self.client_secret.is_empty()
    }
}

pub(crate) struct CachedToken {
    access_token: String,
    expires_at: std::time::Instant,
}

/// CSRF state for the OAuth round-trip. Short-lived and audience-scoped, so a
/// stray callback cannot bind someone else's Google account to this server.
#[derive(Debug, Serialize, Deserialize)]
struct OAuthStateClaims {
    sub: String,
    aud: String,
    exp: i64,
}

const OAUTH_STATE_AUDIENCE: &str = "newsletter-google-oauth";
const OAUTH_STATE_TTL_SECS: i64 = 900;

fn redirect_uri(state: &AppState) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let base = state.magic_link_base_url.trim_end_matches('/');
    if base.is_empty() {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "SUSI_MAGIC_LINK_BASE_URL must be set - it is the OAuth redirect URI Google sends the browser back to",
        ));
    }
    Ok(format!("{}/api/v1/newsletter/google/callback", base))
}

fn require_google_config(state: &AppState) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if !state.google_oauth.configured() {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Google OAuth is not configured (SUSI_GOOGLE_CLIENT_ID / SUSI_GOOGLE_CLIENT_SECRET)",
        ));
    }
    Ok(())
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Step 1: hand the admin a consent URL.
///
/// `access_type=offline` plus `prompt=consent` is what makes Google return a
/// refresh token. Without `prompt=consent` a re-authorisation returns only an
/// access token, and the connection silently stops working an hour later.
pub(crate) async fn handle_google_authorize(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_owner(&state, &principal)?;
    require_google_config(&state)?;
    let redirect = redirect_uri(&state)?;

    let claims = OAuthStateClaims {
        sub: principal.username.clone(),
        aud: OAUTH_STATE_AUDIENCE.to_string(),
        exp: Utc::now().timestamp() + OAUTH_STATE_TTL_SECS,
    };
    let csrf = encode(&Header::default(), &claims, &EncodingKey::from_secret(&state.jwt_secret))
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let url = format!(
        "{auth}?client_id={cid}&redirect_uri={redir}&response_type=code&scope={scope}\
         &access_type=offline&prompt=consent&include_granted_scopes=true&state={state_tok}",
        auth = GOOGLE_AUTH_URL,
        cid = urlencode(&state.google_oauth.client_id),
        redir = urlencode(&redirect),
        scope = urlencode(GMAIL_SEND_SCOPE),
        state_tok = urlencode(&csrf),
    );
    Ok(Json(serde_json::json!({ "url": url, "redirect_uri": redirect })))
}

async fn token_request(
    state: &AppState,
    form: &[(&str, &str)],
) -> Result<serde_json::Value, String> {
    let resp = state
        .http
        .post(GOOGLE_TOKEN_URL)
        .form(form)
        .send()
        .await
        .map_err(|e| format!("Google token endpoint unreachable: {}", e))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("Google token request failed ({}): {}", status, body));
    }
    serde_json::from_str(&body).map_err(|e| format!("Google token response is not JSON: {}", e))
}

async fn google_account_email(state: &AppState, access_token: &str) -> Option<String> {
    let resp = state
        .http
        .get(GOOGLE_USERINFO_URL)
        .bearer_auth(access_token)
        .send()
        .await
        .ok()?;
    let v: serde_json::Value = resp.json().await.ok()?;
    v["email"].as_str().map(str::to_string)
}

#[derive(Deserialize)]
pub(crate) struct GoogleCallbackQuery {
    #[serde(default)]
    code: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    error: String,
}

fn oauth_page(heading: &str, body: &str) -> axum::response::Html<String> {
    axum::response::Html(format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{h}</title></head>\
         <body style=\"font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;\
          max-width:540px;margin:60px auto;padding:0 20px;color:#1a1d23;line-height:1.55;\">\
           <h1 style=\"font-size:22px;font-weight:600;margin:0 0 14px;\">{h}</h1>\
           <p style=\"margin:0 0 14px;\">{b}</p>\
           <p style=\"margin:0;font-size:13px;\">You can close this tab and return to the \
            Newsletter page.</p>\
         </body></html>",
        h = html_escape(heading),
        b = html_escape(body),
    ))
}

/// Step 2: Google redirects the browser here. Public by necessity - a redirect
/// carries no Authorization header - so the signed `state` parameter is what
/// proves an admin started this flow.
pub(crate) async fn handle_google_callback(
    State(state): State<Arc<AppState>>,
    Query(q): Query<GoogleCallbackQuery>,
) -> Result<axum::response::Html<String>, (StatusCode, Json<ErrorResponse>)> {
    if !q.error.is_empty() {
        return Ok(oauth_page("Connection cancelled", &format!("Google reported: {}", q.error)));
    }
    require_google_config(&state)?;

    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_audience(&[OAUTH_STATE_AUDIENCE]);
    let claims = decode::<OAuthStateClaims>(
        &q.state,
        &DecodingKey::from_secret(&state.jwt_secret),
        &validation,
    )
    .map(|d| d.claims)
    .map_err(|_| {
        error_response(StatusCode::BAD_REQUEST, "Invalid or expired authorization state")
    })?;

    if q.code.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Missing authorization code"));
    }
    let redirect = redirect_uri(&state)?;
    let v = token_request(
        &state,
        &[
            ("grant_type", "authorization_code"),
            ("code", &q.code),
            ("client_id", &state.google_oauth.client_id),
            ("client_secret", &state.google_oauth.client_secret),
            ("redirect_uri", &redirect),
        ],
    )
    .await
    .map_err(|e| error_response(StatusCode::BAD_GATEWAY, &e))?;

    let refresh = v["refresh_token"].as_str().ok_or_else(|| {
        error_response(
            StatusCode::BAD_GATEWAY,
            "Google returned no refresh token. Revoke susi's access at \
             myaccount.google.com/permissions and connect again - Google only issues one on \
             first consent.",
        )
    })?;
    let access = v["access_token"].as_str().unwrap_or_default();
    let account = google_account_email(&state, access)
        .await
        .unwrap_or_else(|| "(unknown)".to_string());

    {
        let db = state.db.lock();
        db.set_newsletter_google_connection(refresh, &account)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    }
    // A newly connected account invalidates any token cached for the old one.
    *state.newsletter_token_cache.lock().await = None;
    audit(&state, &claims.sub, "newsletter.google_connect", &account, "");
    log::info!("Newsletter Gmail connected: {}", account);

    Ok(oauth_page(
        "Gmail connected",
        &format!("Newsletters will be sent from {}.", account),
    ))
}

pub(crate) async fn handle_google_disconnect(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_owner(&state, &principal)?;
    {
        let db = state.db.lock();
        db.clear_newsletter_google_connection()
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    }
    *state.newsletter_token_cache.lock().await = None;
    audit(&state, &principal.username, "newsletter.google_disconnect", "", "");
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

/// A valid access token, refreshed on demand and cached until shortly before
/// it expires. Returns None when no account is connected.
async fn google_access_token(state: &Arc<AppState>) -> Option<String> {
    {
        let cache = state.newsletter_token_cache.lock().await;
        if let Some(t) = cache.as_ref() {
            if t.expires_at > std::time::Instant::now() {
                return Some(t.access_token.clone());
            }
        }
    }
    // Read the refresh token under the DB lock, then drop it: the token
    // request below is an await, and this mutex is not reentrant.
    let refresh = {
        let db = state.db.lock();
        db.get_newsletter_google_refresh_token().ok().flatten()?
    };
    let v = token_request(
        state,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", &state.google_oauth.client_id),
            ("client_secret", &state.google_oauth.client_secret),
        ],
    )
    .await
    .map_err(|e| log::error!("Newsletter Gmail token refresh failed: {}", e))
    .ok()?;

    let access = v["access_token"].as_str()?.to_string();
    let ttl = v["expires_in"].as_u64().unwrap_or(3600);
    let lifetime = ttl.saturating_sub(TOKEN_EARLY_REFRESH_SECS).max(60);
    *state.newsletter_token_cache.lock().await = Some(CachedToken {
        access_token: access.clone(),
        expires_at: std::time::Instant::now() + std::time::Duration::from_secs(lifetime),
    });
    Some(access)
}

/// The transport campaign mail goes out on.
///
/// Static SMTP credentials win when set, so an existing app-password
/// deployment keeps working untouched; the Google connection is the fallback.
pub(crate) async fn newsletter_mailer(state: &Arc<AppState>) -> Option<EmailService> {
    if let Some(svc) = state.newsletter_email.clone() {
        return Some(svc);
    }
    if !state.google_oauth.configured() {
        return None;
    }
    let account = {
        let db = state.db.lock();
        db.get_newsletter_google_account().ok().flatten()?.0
    };
    let token = google_access_token(state).await?;
    let from_addr = if state.google_oauth.from_addr_override.is_empty() {
        // Gmail rewrites From to the authenticated account unless the address
        // is a verified send-as alias, so defaulting to the account itself is
        // the only choice that cannot surprise a recipient.
        account.clone()
    } else {
        state.google_oauth.from_addr_override.clone()
    };
    let cfg = EmailConfig::from_parts(
        GMAIL_SMTP_HOST.to_string(),
        GMAIL_SMTP_PORT,
        account,
        String::new(),
        &state.google_oauth.from_name,
        &from_addr,
    )
    .ok()?;
    EmailService::new_xoauth2(cfg, &token)
        .map_err(|e| log::error!("Newsletter Gmail transport init failed: {:#}", e))
        .ok()
}


// Sending
// ---------------------------------------------------------------------------

/// Drain pending deliveries at the configured rate.
///
/// Modelled on `backup::spawn_scheduler`: a fixed interval, all state derived
/// from the database, and an `AtomicBool` so a tick can never overlap itself.
/// Because progress lives in `newsletter_deliveries` rather than in memory, a
/// process killed mid-campaign resumes on the next boot instead of re-mailing
/// everyone who already received it.
pub(crate) fn spawn_sender(state: Arc<AppState>) {
    if state.newsletter_email.is_none() && !state.google_oauth.configured() {
        return;
    }
    tokio::spawn(async move {
        // Reconcile anything the previous process left behind before the first
        // batch, so a campaign that finished during a restart closes out.
        {
            let db = state.db.lock();
            let _ = db.finalize_newsletter_issues();
        }
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        tick.tick().await; // skip the immediate fire
        loop {
            // The interval paces an in-flight campaign; the notify makes a
            // freshly queued one start now rather than up to a tick later.
            tokio::select! {
                _ = tick.tick() => {}
                _ = state.newsletter_wake.notified() => {}
            }
            if state.newsletter_sending.swap(true, Ordering::SeqCst) {
                continue;
            }
            let sent = drain_once(&state).await;
            state.newsletter_sending.store(false, Ordering::SeqCst);
            if sent > 0 {
                log::info!("Newsletter: attempted {} deliveries this tick", sent);
            }
        }
    });
}

/// One tick's worth of work. Sequential on purpose - the two existing fan-out
/// sites in this codebase spawn one unbounded task per recipient, which against
/// a rate-limited relay is exactly how a campaign gets throttled or blocked.
async fn drain_once(state: &Arc<AppState>) -> usize {
    let Some(mailer) = newsletter_mailer(state).await else {
        return 0;
    };
    let batch = {
        let db = state.db.lock();
        match db.has_pending_newsletter_work() {
            Ok(false) | Err(_) => return 0,
            Ok(true) => {}
        }
        db.claim_pending_deliveries(state.newsletter_rate_per_min as i64)
            .unwrap_or_default()
    };
    if batch.is_empty() {
        let db = state.db.lock();
        let _ = db.finalize_newsletter_issues();
        return 0;
    }

    let base = state.magic_link_base_url.trim_end_matches('/').to_string();
    let assets = format!("{}/api/v1/website/assets", base);
    let asset_dir = newsletter_assets_dir(state);
    let mut attempted = 0;
    // Render once per issue, not once per recipient.
    let mut cache: HashMap<i64, Option<(String, String)>> = HashMap::new();

    for item in batch {
        let rendered = cache
            .entry(item.issue_id)
            .or_insert_with(|| {
                let db = state.db.lock();
                let issue = db.get_newsletter_issue(item.issue_id).ok().flatten()?;
                Some((issue.subject, issue.body_md))
            })
            .clone();
        let Some((subject, body_md)) = rendered else {
            let db = state.db.lock();
            let _ = db.mark_delivery_attempt_failed(item.id, "Issue disappeared");
            continue;
        };

        let Some(url) = unsubscribe_url(state, &base, &item.username) else {
            let db = state.db.lock();
            let _ = db.mark_delivery_attempt_failed(item.id, "Could not mint unsubscribe token");
            continue;
        };
        // Images are read from disk once per issue, not per recipient; the
        // Arc<[u8]> in InlineImage makes each clone a refcount bump.
        let (html, images) = render_email_html_with_images(
            &body_md,
            &base,
            &assets,
            &unsubscribe_footer(&url),
            Some(&asset_dir),
        );
        let text = format!(
            "{}{}",
            render_email_text(&body_md, &base, &assets),
            unsubscribe_footer_text(&url)
        );

        attempted += 1;
        // The DB guard is dropped before awaiting: parking_lot's mutex is not
        // reentrant and holding it across an SMTP round-trip would wedge every
        // other request for the duration.
        let result = mailer
            .send_newsletter(&item.email, &subject, &text, &html, &images, &url)
            .await;
        let db = state.db.lock();
        match result {
            Ok(()) => {
                let _ = db.mark_delivery_sent(item.id);
            }
            Err(e) => {
                log::warn!("Newsletter delivery to {} failed: {:#}", item.email, e);
                let _ = db.mark_delivery_attempt_failed(item.id, &format!("{:#}", e));
            }
        }
    }

    {
        let db = state.db.lock();
        let _ = db.finalize_newsletter_issues();
    }
    attempted
}

#[derive(Deserialize)]
pub(crate) struct PreviewRequest {
    #[serde(default)]
    body_md: String,
}

/// Render markdown exactly the way a send would. The admin UI shows this in a
/// sandboxed iframe rather than reusing a web renderer - dashboard.html's regex
/// renderMarkdown() and website.html's EasyMDE preview both style for the page,
/// so either would show a preview that lies about what subscribers receive.
pub(crate) async fn handle_newsletter_preview(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<PreviewRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_owner(&state, &principal)?;

    let (base, assets) = email_base_urls(&state)?;
    Ok(Json(serde_json::json!({
        "html": render_email_html(&req.body_md, &base, &assets, ""),
        "text": render_email_text(&req.body_md, &base, &assets),
    })))
}

// ---------------------------------------------------------------------------
// Issue CRUD (admin)
// ---------------------------------------------------------------------------

const MAX_SUBJECT: usize = 200;
const MAX_BODY_MD: usize = 200_000;

#[derive(Deserialize)]
pub(crate) struct IssueRequest {
    subject: String,
    #[serde(default)]
    body_md: String,
}

fn validate_issue(req: &IssueRequest) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let subject = req.subject.trim();
    if subject.is_empty() || subject.len() > MAX_SUBJECT {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            &format!("Subject must be 1-{} characters", MAX_SUBJECT),
        ));
    }
    if req.body_md.len() > MAX_BODY_MD {
        return Err(error_response(StatusCode::BAD_REQUEST, "Body is too large"));
    }
    Ok(())
}

pub(crate) async fn handle_list_issues(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<susi_core::db::NewsletterIssue>>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_owner(&state, &principal)?;
    let db = state.db.lock();
    let rows = db
        .list_newsletter_issues()
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    Ok(Json(rows))
}

pub(crate) async fn handle_get_issue(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<susi_core::db::NewsletterIssue>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_owner(&state, &principal)?;
    let db = state.db.lock();
    db.get_newsletter_issue(id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .map(Json)
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Issue not found"))
}

pub(crate) async fn handle_create_issue(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<IssueRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_owner(&state, &principal)?;
    validate_issue(&req)?;

    let db = state.db.lock();
    let id = db
        .create_newsletter_issue(req.subject.trim(), &req.body_md, &principal.username)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    audit_db(&db, &principal.username, "newsletter.create", &id.to_string(), req.subject.trim());
    Ok(Json(serde_json::json!({ "status": "OK", "id": id })))
}

pub(crate) async fn handle_update_issue(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<IssueRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_owner(&state, &principal)?;
    validate_issue(&req)?;

    let db = state.db.lock();
    if !db
        .update_newsletter_issue(id, req.subject.trim(), &req.body_md)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    {
        return Err(issue_not_editable(&db, id));
    }
    audit_db(&db, &principal.username, "newsletter.update", &id.to_string(), "");
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

pub(crate) async fn handle_delete_issue(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_owner(&state, &principal)?;

    let db = state.db.lock();
    if !db
        .delete_newsletter_issue(id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
    {
        return Err(issue_not_editable(&db, id));
    }
    audit_db(&db, &principal.username, "newsletter.delete", &id.to_string(), "");
    Ok(Json(serde_json::json!({ "status": "OK" })))
}

/// A guarded UPDATE that changed nothing is either a missing issue or one that
/// has left draft. Distinguishing the two turns a confusing 404 into an
/// explanation.
fn issue_not_editable(db: &LicenseDb, id: i64) -> (StatusCode, Json<ErrorResponse>) {
    match db.get_newsletter_issue(id) {
        Ok(Some(i)) => error_response(
            StatusCode::CONFLICT,
            &format!("Issue is '{}' - only drafts can be edited or deleted", i.status),
        ),
        _ => error_response(StatusCode::NOT_FOUND, "Issue not found"),
    }
}

pub(crate) async fn handle_list_deliveries(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Vec<susi_core::db::DeliveryRow>>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_owner(&state, &principal)?;
    let db = state.db.lock();
    let rows = db
        .list_newsletter_deliveries(id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    Ok(Json(rows))
}

// ---------------------------------------------------------------------------
// Test send + real send
// ---------------------------------------------------------------------------

async fn require_newsletter_mailer(
    state: &Arc<AppState>,
) -> Result<EmailService, (StatusCode, Json<ErrorResponse>)> {
    if let Some(svc) = newsletter_mailer(state).await {
        return Ok(svc);
    }
    let hint = if state.google_oauth.configured() {
        "Connect a Google account on the Newsletter page, or set SUSI_NEWSLETTER_SMTP_*."
    } else {
        "Set SUSI_NEWSLETTER_SMTP_*, or configure SUSI_GOOGLE_CLIENT_ID / \
         SUSI_GOOGLE_CLIENT_SECRET to connect a Google account from the dashboard."
    };
    Err(error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        &format!(
            "Newsletter sending is not configured. Campaign mail deliberately does not fall \
             back to the account-email relay. {}",
            hint
        ),
    ))
}

/// Send one copy to the calling admin's own address. Uses the real transport,
/// the real renderer and a real unsubscribe link, so what lands in the inbox is
/// exactly what subscribers would get.
pub(crate) async fn handle_test_send(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_owner(&state, &principal)?;
    let mailer = require_newsletter_mailer(&state).await?;
    let (base, assets) = email_base_urls(&state)?;

    let (issue, to) = {
        let db = state.db.lock();
        let issue = db
            .get_newsletter_issue(id)
            .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
            .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Issue not found"))?;
        let to = db
            .get_user_email(&principal.username)
            .ok()
            .flatten()
            .ok_or_else(|| {
                error_response(StatusCode::BAD_REQUEST, "Your account has no email on file")
            })?;
        (issue, to)
    };

    let url = unsubscribe_url(&state, &base, &principal.username)
        .ok_or_else(|| error_response(StatusCode::INTERNAL_SERVER_ERROR, "Token mint failed"))?;
    let (html, images) = render_email_html_with_images(
        &issue.body_md,
        &base,
        &assets,
        &unsubscribe_footer(&url),
        Some(&newsletter_assets_dir(&state)),
    );
    let text = format!(
        "{}{}",
        render_email_text(&issue.body_md, &base, &assets),
        unsubscribe_footer_text(&url)
    );
    let subject = format!("[TEST] {}", issue.subject);

    mailer
        .send_newsletter(&to, &subject, &text, &html, &images, &url)
        .await
        .map_err(|e| {
            error_response(StatusCode::BAD_GATEWAY, &format!("Test send failed: {:#}", e))
        })?;
    Ok(Json(serde_json::json!({ "status": "OK", "sent_to": to })))
}

#[derive(Deserialize)]
pub(crate) struct SendRequest {
    /// Recipient count the operator saw in the audience panel. The send is
    /// refused when it no longer matches, so a campaign can never go out
    /// against a materially different list than the one that was reviewed.
    #[serde(default)]
    expect_recipients: Option<usize>,
}

/// Snapshot the audience into delivery rows and hand the campaign to the
/// background sender. Returns immediately - a send of any size must not be
/// bounded by one HTTP request.
pub(crate) async fn handle_send_issue(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<SendRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let principal = validate_principal(&headers, &state)?;
    require_owner(&state, &principal)?;
    require_newsletter_mailer(&state).await?;
    email_base_urls(&state)?;

    let db = state.db.lock();
    let issue = db
        .get_newsletter_issue(id)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Issue not found"))?;
    if issue.status != "draft" {
        return Err(error_response(
            StatusCode::CONFLICT,
            &format!("Issue is already '{}'", issue.status),
        ));
    }

    let audience = db
        .newsletter_audience()
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    if audience.recipients.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "Nobody is subscribed - nothing would be sent",
        ));
    }
    if let Some(expected) = req.expect_recipients {
        if expected != audience.recipients.len() {
            return Err(error_response(
                StatusCode::CONFLICT,
                &format!(
                    "Audience changed since you reviewed it ({} now, {} expected) - reload and check again",
                    audience.recipients.len(),
                    expected
                ),
            ));
        }
    }

    let created = db
        .start_newsletter_send(id, &audience.recipients)
        .map_err(|e| error_response(StatusCode::CONFLICT, &e.to_string()))?;
    audit_db(
        &db,
        &principal.username,
        "newsletter.send",
        &id.to_string(),
        &format!("recipients={}", created),
    );
    log::info!("Newsletter issue {} queued for {} recipients", id, created);
    state.newsletter_wake.notify_one();
    Ok(Json(serde_json::json!({ "status": "OK", "queued": created })))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "https://susi.example.com";
    const ASSETS: &str = "https://susi.example.com/api/v1/website/assets";

    fn html(md: &str) -> String {
        render_email_html(md, BASE, ASSETS, "")
    }

    /// Every block tag a newsletter can produce must carry its own style.
    /// Nothing here is optional: an unstyled tag renders as browser-default in
    /// the inbox, looking broken next to the styled tags around it.
    #[test]
    fn styles_are_inlined_on_every_block_tag() {
        let out = html(
            "# Title\n\nA paragraph with a [link](/docs) and **bold**.\n\n\
             ## Section\n\n- one\n- two\n\n> quoted\n\n---\n\n\
             | a | b |\n|---|---|\n| 1 | 2 |\n",
        );
        for tag in ["h1", "h2", "p", "ul", "li", "a", "blockquote", "hr", "table", "th", "td"] {
            assert!(
                out.contains(&format!("<{} style=\"", tag)),
                "<{}> must carry an inline style, got: {}",
                tag,
                out
            );
        }
        assert!(out.starts_with("<div style=\"font-family:"));
        assert!(out.contains("max-width:640px"));
    }

    /// Body typography tracks the public site's `.content` block, so a
    /// newsletter reads like the pages it links to rather than as cramped
    /// small print. These are the values website.html actually uses.
    #[test]
    fn typography_matches_the_website() {
        let out = html("# Title\n\nBody text.\n\n## Section\n\nMore.\n");
        // website.html: body font stack, .content { font-size:16px; line-height:1.71 }
        assert!(out.contains("font-size:16px"), "base size must be 16px: {}", out);
        assert!(out.contains("line-height:1.71"), "line-height must be 1.71: {}", out);
        assert!(out.contains("ui-sans-serif"), "same font stack as the site: {}", out);
        // .content h1 { font-size:28px; font-weight:400 }
        assert!(out.contains("font-size:28px"), "h1 must be 28px: {}", out);
        assert!(out.contains("font-weight:400;font-size:28px"), "h1 weight 400: {}", out);
        // .content h2 { font-size:21px }
        assert!(out.contains("font-size:21px"), "h2 must be 21px: {}", out);
        // Wider than the old 540px, but still a readable measure in a pane.
        assert!(out.contains("max-width:640px"));
    }

    /// CLAUDE.md bans typographic dashes in customer-facing copy, and
    /// ENABLE_SMART_PUNCTUATION silently produces them. This is the guard.
    #[test]
    fn smart_punctuation_is_off() {
        let out = html("Latency is 100--500 ms -- measured end to end.\n\nHe said \"hi\".");
        assert!(!out.contains('\u{2013}'), "en dash leaked: {}", out);
        assert!(!out.contains('\u{2014}'), "em dash leaked: {}", out);
        assert!(!out.contains('\u{201c}'), "curly quote leaked: {}", out);
        assert!(out.contains("100--500 ms"), "got: {}", out);

        let text = render_email_text("Range 100--500 ms.", BASE, ASSETS);
        assert_eq!(text, "Range 100--500 ms.");
    }

    /// EasyMDE writes bare filenames for uploaded assets. On the web a
    /// client-side hook patches them up; an inbox has no such hook, so an
    /// unresolved filename is simply a broken image.
    #[test]
    fn urls_are_absolutized() {
        let out = html(
            "![shot](screenshot.png)\n\n\
             [rooted](/docs/intro) and [external](https://example.org/x) and \
             [mail](mailto:a@b.c) and [anchor](#part)\n",
        );
        assert!(
            out.contains("src=\"https://susi.example.com/api/v1/website/assets/screenshot.png\""),
            "got: {}", out
        );
        assert!(out.contains("href=\"https://susi.example.com/docs/intro\""), "got: {}", out);
        assert!(out.contains("href=\"https://example.org/x\""), "got: {}", out);
        assert!(out.contains("href=\"mailto:a@b.c\""), "got: {}", out);
        assert!(out.contains("href=\"#part\""), "got: {}", out);
        assert!(!out.contains("src=\"screenshot.png\""), "no relative URL may survive");
    }

    /// The markdown is admin-authored, but an API token skips the TOTP gate, so
    /// a leaked one must not become script in every subscriber's inbox.
    #[test]
    fn script_and_event_handlers_are_stripped() {
        let out = html(
            "<script>alert(1)</script>\n\n\
             <img src=x onerror=\"alert(1)\">\n\n\
             <div style=\"position:fixed\">styled</div>\n",
        );
        assert!(!out.contains("<script"), "got: {}", out);
        assert!(!out.contains("onerror"), "got: {}", out);
        assert!(!out.contains("position:fixed"), "author CSS must not survive: {}", out);
    }

    /// A <code> inside <pre> must not repeat the block background, or it
    /// renders as a grey box inside a grey box.
    #[test]
    fn code_inside_pre_does_not_double_style() {
        let out = html("```\nlet x = 1;\n```\n\nInline `y` here.\n");
        assert!(out.contains("<pre style=\""), "got: {}", out);
        assert!(out.contains(&format!("<code style=\"{}", PRE_CODE_STYLE)), "got: {}", out);
        assert!(out.contains("background:#f3f4f6;padding:1px 6px"), "inline code stays boxed: {}", out);
    }

    /// `<hr>` must not pick up the `<h1>` rule, and vice versa.
    #[test]
    fn tag_matching_is_exact() {
        let styled = inject_styles("<hr><h1>T</h1><p>x</p>");
        assert!(styled.contains("<hr style=\"border:0;"), "got: {}", styled);
        assert!(styled.contains("<h1 style=\"margin:0 0 18px"), "got: {}", styled);
    }

    /// Escaped markup in the sanitized output must not be mistaken for a tag.
    #[test]
    fn escaped_text_is_not_treated_as_markup() {
        let out = html("Use `<p>` in your template.\n");
        assert!(out.contains("&lt;p&gt;"), "got: {}", out);
    }

    #[test]
    fn plain_text_alternative_is_readable() {
        let text = render_email_text(
            "# Release 2.0\n\nWe shipped [docs](/docs).\n\n- faster\n- smaller\n",
            BASE,
            ASSETS,
        );
        assert!(text.starts_with("Release 2.0"), "got: {:?}", text);
        assert!(
            text.contains("We shipped docs (https://susi.example.com/docs)."),
            "got: {:?}", text
        );
        assert!(text.contains("- faster\n- smaller"), "got: {:?}", text);
        assert!(!text.contains('#'), "markdown syntax must not leak: {:?}", text);
        assert!(!text.contains("\n\n\n"), "no triple blank lines: {:?}", text);
    }

    #[test]
    fn empty_body_renders_an_empty_shell() {
        let out = html("");
        assert!(out.starts_with("<div style=\""));
        assert!(out.ends_with("</div>"));
        assert_eq!(render_email_text("", BASE, ASSETS), "");
    }

    #[test]
    fn footer_is_appended_inside_the_container() {
        let out = render_email_html("Hi.", BASE, ASSETS, "<p>unsubscribe</p>");
        assert!(out.ends_with("<p>unsubscribe</p></div>"), "got: {}", out);
    }

    /// The unsubscribe token is the credential on a public route, so its
    /// failure modes matter more than its happy path.

    // ---- Inline image embedding -------------------------------------------

    /// Minimal valid PNG bytes; content does not matter, only that a real file
    /// of a known size exists on disk.
    fn write_asset(dir: &std::path::Path, name: &str, len: usize) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, vec![0u8; len]).expect("write asset");
        p
    }

    fn render_with_dir(md: &str, dir: &std::path::Path) -> (String, Vec<InlineImage>) {
        render_email_html_with_images(md, BASE, ASSETS, "", Some(dir))
    }

    /// The composer inserts a bare filename. It must become a cid: reference
    /// with the bytes attached - a remote URL is blocked by default in Gmail
    /// and unreachable entirely from a private host.
    #[test]
    fn local_images_are_embedded_as_cid() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_asset(tmp.path(), "shot.png", 64);

        let (html, images) = render_with_dir("![alt](shot.png)", tmp.path());
        assert_eq!(images.len(), 1, "one attachment expected, got {:?}", images.len());
        assert_eq!(images[0].mime_type, "image/png");
        assert_eq!(images[0].bytes.len(), 64);
        assert!(
            html.contains(&format!("src=\"cid:{}\"", images[0].content_id)),
            "html must reference the attachment: {}",
            html
        );
        assert!(!html.contains("/api/v1/website/assets/shot.png"), "no URL should remain");
        // RFC 2392: the content id itself carries no angle brackets.
        assert!(!images[0].content_id.contains('<'));
        assert!(!images[0].content_id.contains('>'));
    }

    /// An author may paste the asset URL instead of the bare name; both are the
    /// same local file and must embed identically.
    #[test]
    fn asset_urls_are_embedded_too() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_asset(tmp.path(), "shot.png", 10);
        let md = format!("![alt]({}/shot.png)", ASSETS);
        let (html, images) = render_with_dir(&md, tmp.path());
        assert_eq!(images.len(), 1, "pasted asset URL should embed: {}", html);
        assert!(html.contains("src=\"cid:"));
    }

    /// The same picture used twice costs one attachment, not two.
    #[test]
    fn repeated_image_is_attached_once() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_asset(tmp.path(), "shot.png", 32);
        let (html, images) = render_with_dir("![a](shot.png)\n\n![b](shot.png)", tmp.path());
        assert_eq!(images.len(), 1, "duplicate must reuse the same attachment");
        let cid = format!("cid:{}", images[0].content_id);
        assert_eq!(html.matches(&cid).count(), 2, "both tags point at it: {}", html);
    }

    /// The filename comes from author-controlled markdown, so it must never be
    /// able to reach outside the asset store.
    #[test]
    fn path_traversal_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let outside = tmp.path().join("secret.png");
        std::fs::write(&outside, b"secret").expect("write");
        let assets = tmp.path().join("assets");
        std::fs::create_dir_all(&assets).expect("mkdir");

        for evil in ["../secret.png", "..\\secret.png", "sub/../../secret.png", "/etc/passwd"] {
            let (_, images) = render_with_dir(&format!("![x]({})", evil), &assets);
            assert!(images.is_empty(), "{:?} must not be embedded", evil);
        }
    }

    /// External images stay remote - we cannot attach what we do not host.
    #[test]
    fn remote_and_data_images_are_left_alone() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (html, images) = render_with_dir(
            "![a](https://example.org/x.png)\n\n![b](data:image/png;base64,AAAA)",
            tmp.path(),
        );
        assert!(images.is_empty(), "nothing local to attach");
        assert!(html.contains("https://example.org/x.png"));
    }

    /// A missing file falls back to a URL rather than dropping the image or
    /// failing the send.
    #[test]
    fn missing_asset_falls_back_to_url() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (html, images) = render_with_dir("![x](nope.png)", tmp.path());
        assert!(images.is_empty());
        assert!(
            html.contains("/api/v1/website/assets/nope.png"),
            "should degrade to the absolute URL: {}",
            html
        );
    }

    /// Past the cap the per-recipient cost outweighs guaranteed display.
    #[test]
    fn oversized_asset_falls_back_to_url() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_asset(tmp.path(), "huge.png", (MAX_INLINE_IMAGE_BYTES + 1) as usize);
        let (html, images) = render_with_dir("![x](huge.png)", tmp.path());
        assert!(images.is_empty(), "oversized image must not be attached");
        assert!(html.contains("/api/v1/website/assets/huge.png"));
    }

    /// Only raster types are embedded; SVG can carry script and renders
    /// inconsistently in mail clients.
    #[test]
    fn non_raster_assets_are_not_embedded() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_asset(tmp.path(), "vector.svg", 20);
        write_asset(tmp.path(), "notes.pdf", 20);
        for name in ["vector.svg", "notes.pdf"] {
            let (_, images) = render_with_dir(&format!("![x]({})", name), tmp.path());
            assert!(images.is_empty(), "{} must not be inlined", name);
        }
    }

    /// If the sanitizer removes an <img>, its attachment must go with it -
    /// otherwise every message carries bytes nothing references.
    #[test]
    fn attachments_dropped_when_tag_is_sanitized_away() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_asset(tmp.path(), "shot.png", 16);
        // Inside a fenced code block the image is text, never an <img> tag.
        let (html, images) = render_with_dir("```\n![x](shot.png)\n```", tmp.path());
        assert!(!html.contains("<img"), "no image tag: {}", html);
        assert!(images.is_empty(), "no orphaned attachment may survive");
    }

    /// Without an assets dir (the preview path) behaviour is unchanged: URLs,
    /// no attachments. A browser cannot render cid:, so the preview must keep
    /// using URLs - the rendered result is visually identical either way.
    #[test]
    fn preview_path_keeps_urls() {
        let (html, images) = render_email_html_with_images("![x](shot.png)", BASE, ASSETS, "", None);
        assert!(images.is_empty());
        assert!(html.contains("/api/v1/website/assets/shot.png"));
        // And the public wrapper still behaves exactly as before.
        assert_eq!(html, render_email_html("![x](shot.png)", BASE, ASSETS, ""));
    }

    #[test]
    fn unsubscribe_token_round_trips() {
        let secret = [7u8; 32];
        let token = mint_unsubscribe_token(&secret, "alice").expect("mint");
        // ErrorResponse has no Debug impl, so go through Option to unwrap.
        assert_eq!(validate_unsubscribe_token(&secret, &token).ok().expect("validate"), "alice");
    }

    #[test]
    fn unsubscribe_token_rejects_other_secrets_and_audiences() {
        let secret = [7u8; 32];
        let other = [8u8; 32];
        let token = mint_unsubscribe_token(&secret, "alice").expect("mint");

        assert!(
            validate_unsubscribe_token(&other, &token).is_err(),
            "a token signed with another secret must not validate"
        );
        assert!(validate_unsubscribe_token(&secret, "not-a-jwt").is_err());
        assert!(validate_unsubscribe_token(&secret, "").is_err());

        // A token minted for a different audience must not unsubscribe anyone -
        // this is what keeps the dedicated `aud` load-bearing.
        let wrong_aud = encode(
            &Header::default(),
            &UnsubscribeClaims { sub: "alice".into(), aud: "release-download".into() },
            &EncodingKey::from_secret(&secret),
        )
        .expect("encode");
        assert!(
            validate_unsubscribe_token(&secret, &wrong_aud).is_err(),
            "audience must be enforced"
        );
    }

    /// Tokens carry no `exp` on purpose - a mail sitting in an archive must
    /// still unsubscribe. Assert that directly, since a stray `validate_exp`
    /// would break links only for old mail, which is invisible in testing.
    #[test]
    fn unsubscribe_token_does_not_expire() {
        let secret = [7u8; 32];
        let token = mint_unsubscribe_token(&secret, "alice").expect("mint");
        let payload = token.split('.').nth(1).expect("payload segment");
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            payload,
        )
        .expect("base64");
        let claims: serde_json::Value = serde_json::from_slice(&decoded).expect("json");
        assert!(claims.get("exp").is_none(), "token must not carry an exp: {}", claims);
        assert_eq!(claims["aud"], serde_json::json!("newsletter-unsubscribe"));
    }

    #[test]
    fn footer_carries_the_unsubscribe_link() {
        let url = "https://susi.example.com/api/v1/newsletter/unsubscribe?token=abc";
        let html = unsubscribe_footer(url);
        assert!(html.contains(url), "got: {}", html);
        assert!(html.contains("Unsubscribe</a>"), "got: {}", html);

        let text = unsubscribe_footer_text(url);
        assert!(text.contains(&format!("Unsubscribe: {}", url)), "got: {}", text);
    }
}
