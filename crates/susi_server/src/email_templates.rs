//! Central registry of transactional email templates (newsletter issues
//! excluded - those have their own editor).
//!
//! Every template is a markdown body plus a one-line subject, both filled via
//! `email_md::apply_template` ({name} tokens, empty-var lines dropped). The
//! built-in defaults live in code; the DB stores only admin overrides, so
//! default improvements reach every un-customized install automatically.
//! Storage: shop templates keep their historical keys in shop_settings,
//! everything else uses site_settings (per-site prefix for per-site
//! templates, bare keys for global ones). An empty stored value means "use
//! the default".

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::email_md::{self, RenderedEmail};
use crate::sites::{self, SiteConfig};
use crate::website::{resolve_site, SiteQuery};
use crate::{
    error_response, require_admin_full, validate_principal, AppState, ErrorResponse,
    INVITE_TTL_HOURS, PASSWORD_RESET_TTL_MINUTES, SIGNIN_CODE_TTL_MINUTES,
};

#[derive(PartialEq)]
enum Store {
    /// shop_settings, keyed via shop::shop_setting_key (historical keys).
    Shop,
    /// site_settings; per-site templates use sites::setting_key.
    Site,
}

pub struct TemplateDef {
    pub id: &'static str,
    pub title: &'static str,
    pub group: &'static str,
    pub per_site: bool,
    pub subject_editable: bool,
    pub vars: &'static [&'static str],
    store: Store,
}

pub const VARS_CONFIRMATION: &[&str] =
    &["order", "date", "name", "site", "items", "totals", "addresses", "shipping_note", "support"];
pub const VARS_SHIPPED: &[&str] =
    &["order", "name", "site", "shipment", "tracking_button", "items", "total"];

pub static TEMPLATES: &[TemplateDef] = &[
    TemplateDef {
        id: "signin_code",
        title: "Sign-in code",
        group: "Account",
        per_site: false,
        subject_editable: true,
        vars: &["user", "code", "ttl"],
        store: Store::Site,
    },
    TemplateDef {
        id: "password_reset",
        title: "Password reset",
        group: "Account",
        per_site: false,
        subject_editable: true,
        vars: &["user", "link", "ttl", "ip"],
        store: Store::Site,
    },
    TemplateDef {
        id: "invitation",
        title: "Invitation",
        group: "Account",
        per_site: false,
        subject_editable: true,
        vars: &["user", "link", "ttl"],
        store: Store::Site,
    },
    TemplateDef {
        id: "ticket_notification",
        title: "Ticket notification",
        group: "Tickets",
        per_site: false,
        // The subject is event-specific ("New ticket #12: ..."), passed in as
        // a variable - only the body layout is editable.
        subject_editable: false,
        vars: &["subject", "heading", "intro", "rows", "excerpt", "button"],
        store: Store::Site,
    },
    TemplateDef {
        id: "newsletter_confirm",
        title: "Newsletter confirmation",
        group: "Newsletter",
        per_site: true,
        subject_editable: true,
        vars: &["url", "site"],
        store: Store::Site,
    },
    TemplateDef {
        id: "order_confirmation",
        title: "Order confirmation",
        group: "Shop",
        per_site: true,
        subject_editable: true,
        vars: VARS_CONFIRMATION,
        store: Store::Shop,
    },
    TemplateDef {
        id: "order_shipped",
        title: "Order shipped",
        group: "Shop",
        per_site: true,
        subject_editable: true,
        vars: VARS_SHIPPED,
        store: Store::Shop,
    },
];

fn find(id: &str) -> Option<&'static TemplateDef> {
    TEMPLATES.iter().find(|d| d.id == id)
}

// ---------------------------------------------------------------------------
// Built-in defaults
// ---------------------------------------------------------------------------

const TPL_CONFIRMATION_EN: &str = "# Thank you for your order\n\nOrder {order} · {date}\n\nHi {name},\n\nThanks for your purchase from {site} - we've received your order and are getting it ready.\n\n## Items\n\n{items}\n\n{totals}\n\n{addresses}\n\nA PDF invoice is attached to this email for your records.\n\n{shipping_note}\n\nQuestions? Reach us at [{support}](mailto:{support}).\n\n\\- The {site} team\n";

const TPL_CONFIRMATION_JA: &str = "# ご注文ありがとうございます\n\nご注文 {order} · {date}\n\n{name} 様\n\n{site}をご利用いただきありがとうございます。ご注文を承りました。\n\n## ご注文内容\n\n{items}\n\n{totals}\n\n{addresses}\n\n請求書（PDF）をこのメールに添付しています。\n\n{shipping_note}\n\nご不明な点は [{support}](mailto:{support}) までお問い合わせください。\n\n\\- {site}チーム\n";

const TPL_SHIPPED_EN: &str = "# Your order has shipped\n\nOrder {order}\n\nHi {name},\n\n{shipment}\n\n{tracking_button}\n\n## Items shipped\n\n{items}\n\nOrder total: {total}\n\nThanks for buying from {site}!\n\n\\- The {site} team\n";

const TPL_SHIPPED_JA: &str = "# 商品を発送しました\n\nご注文 {order}\n\n{name} 様\n\n{shipment}\n\n{tracking_button}\n\n## 発送した商品\n\n{items}\n\nご注文合計: {total}\n\n{site}をご利用いただきありがとうございます！\n\n\\- {site}チーム\n";

const TPL_SIGNIN_CODE: &str = "# Your sign-in code\n\n\
    {{code:{code}}}\n\n\
    Hi {user},\n\n\
    You recently tried to sign in to Susi by LP-Research from a new device. \
    Enter the code above in the browser tab where you started signing in to complete sign-in.\n\n\
    The code expires in {ttl} minutes. If this wasn't you, you can ignore this email - no sign-in will happen.\n\n\
    \\- Xikaku / LP-Research\n";

const TPL_PASSWORD_RESET: &str = "# Reset your password\n\n\
    Hi {user},\n\n\
    Someone requested a password reset for your **Susi by LP-Research** account from IP **{ip}**.\n\n\
    If this was you, click the button below within **{ttl} minutes** to set a new password:\n\n\
    {{button:Reset password|{link}}}\n\n\
    If this wasn't you, you can ignore this email - your password stays unchanged.\n\n\
    \\- Xikaku / LP-Research\n";

const TPL_INVITATION: &str = "# You've been invited to Susi by LP-Research\n\n\
    Hi {user},\n\n\
    A Susi by LP-Research account has been created for you. \
    Click the button below within {ttl} hours to set your password and sign in:\n\n\
    {{button:Set password|{link}}}\n\n\
    If you weren't expecting this invitation, you can ignore this email - \
    the link will expire and no account access will be granted.\n\n\
    \\- Xikaku / LP-Research\n";

const TPL_TICKET_NOTIFICATION: &str = "# {heading}\n\n\
    {intro}\n\n\
    {rows}\n\n\
    {excerpt}\n\n\
    {button}\n\n\
    You are receiving this because you are a member of this Susi by LP-Research workspace.\n\n\
    \\- Xikaku / LP-Research\n";

fn default_body(def: &TemplateDef, site: Option<&SiteConfig>, lang: &str) -> String {
    match (def.id, lang) {
        ("signin_code", _) => TPL_SIGNIN_CODE.into(),
        ("password_reset", _) => TPL_PASSWORD_RESET.into(),
        ("invitation", _) => TPL_INVITATION.into(),
        ("ticket_notification", _) => TPL_TICKET_NOTIFICATION.into(),
        ("newsletter_confirm", _) => {
            let site = site.expect("per-site template needs a site");
            // The default site's newsletter is a company list and signs per
            // the customer-email rules; every other subscriber site is a
            // personal brand, hence the first person - signed with the
            // sender's given name, the way a person signs.
            let (thanks, signed) = if site.id == sites::DEFAULT_SITE_ID {
                (
                    format!(
                        "Thank you for subscribing to {}!",
                        crate::newsletter::newsletter_source_phrase(site)
                    ),
                    "Xikaku / LP-Research".to_string(),
                )
            } else {
                let from = crate::newsletter::site_from_name(site);
                (
                    "Thank you for subscribing to my newsletter!".to_string(),
                    from.split_whitespace().next().unwrap_or(site.name).to_string(),
                )
            };
            format!(
                "# Confirm your subscription\n\n\
                 {thanks}\n\n\
                 {{{{button:Confirm subscription|{{url}}}}}}\n\n\
                 If this wasn't you, ignore this email and nothing will be sent.\n\n\
                 \\- {signed}\n",
            )
        }
        ("order_confirmation", "ja") => TPL_CONFIRMATION_JA.into(),
        ("order_confirmation", _) => TPL_CONFIRMATION_EN.into(),
        ("order_shipped", "ja") => TPL_SHIPPED_JA.into(),
        ("order_shipped", _) => TPL_SHIPPED_EN.into(),
        _ => unreachable!("unknown template id"),
    }
}

fn default_subject(def: &TemplateDef, lang: &str) -> String {
    match (def.id, lang) {
        ("signin_code", _) => "Susi by LP-Research: your sign-in code ({ttl} min)".into(),
        ("password_reset", _) => "Susi by LP-Research: password reset link ({ttl} min)".into(),
        ("invitation", _) => "You've been invited to Susi by LP-Research".into(),
        ("ticket_notification", _) => "{subject}".into(),
        ("newsletter_confirm", _) => "Confirm your {site} newsletter subscription".into(),
        ("order_confirmation", "ja") => "ご注文ありがとうございます - {site} {order}".into(),
        ("order_confirmation", _) => "Thanks for your order - {site} {order}".into(),
        ("order_shipped", "ja") => "{site} ご注文{order}の商品を発送しました".into(),
        ("order_shipped", _) => "Your {site} order {order} has shipped".into(),
        _ => unreachable!("unknown template id"),
    }
}

// ---------------------------------------------------------------------------
// Storage - override lookup
// ---------------------------------------------------------------------------

/// Base storage key for the body (subject key = body key + "_subject"). The
/// shop templates keep the keys the shop editor historically used.
fn body_key(def: &TemplateDef, lang: &str) -> String {
    let base = match def.id {
        "order_confirmation" => "email_order_confirmation".to_string(),
        "order_shipped" => "email_order_shipped".to_string(),
        id => format!("email_tpl_{}", id),
    };
    if lang == "ja" {
        format!("{}_ja", base)
    } else {
        base
    }
}

fn stored(state: &AppState, def: &TemplateDef, site: Option<&SiteConfig>, key: &str) -> String {
    let db = state.db.lock();
    let v = match def.store {
        Store::Shop => db.get_shop_setting(&crate::shop::shop_setting_key(
            site.expect("per-site template needs a site"),
            key,
        )),
        Store::Site if def.per_site => db.get_site_setting(&sites::setting_key(
            site.expect("per-site template needs a site"),
            key,
        )),
        Store::Site => db.get_site_setting(key),
    };
    v.ok().flatten().unwrap_or_default()
}

fn store(
    state: &AppState,
    def: &TemplateDef,
    site: Option<&SiteConfig>,
    key: &str,
    value: &str,
) -> Result<(), susi_core::error::LicenseError> {
    let db = state.db.lock();
    match def.store {
        Store::Shop => db.set_shop_setting(
            &crate::shop::shop_setting_key(site.expect("per-site template needs a site"), key),
            value,
        ),
        Store::Site if def.per_site => db.set_site_setting(
            &sites::setting_key(site.expect("per-site template needs a site"), key),
            value,
        ),
        Store::Site => db.set_site_setting(key, value),
    }
}

fn effective_body_tpl(
    state: &AppState,
    def: &TemplateDef,
    site: Option<&SiteConfig>,
    lang: &str,
) -> String {
    let s = stored(state, def, site, &body_key(def, lang));
    if s.trim().is_empty() {
        default_body(def, site, lang)
    } else {
        s
    }
}

fn effective_subject_tpl(
    state: &AppState,
    def: &TemplateDef,
    site: Option<&SiteConfig>,
    lang: &str,
) -> String {
    if !def.subject_editable {
        return default_subject(def, lang);
    }
    let s = stored(state, def, site, &format!("{}_subject", body_key(def, lang)));
    if s.trim().is_empty() {
        default_subject(def, lang)
    } else {
        s
    }
}

fn apply_subject(tpl: &str, vars: &[(&str, String)]) -> String {
    let filled = email_md::apply_template(tpl, vars);
    filled.lines().next().unwrap_or("").trim().to_string()
}

/// Effective (stored or default) body template - for send sites that fill
/// the body themselves.
pub fn effective_body(state: &AppState, id: &str, site: Option<&SiteConfig>, lang: &str) -> String {
    effective_body_tpl(state, find(id).expect("unknown email template id"), site, lang)
}

/// Effective subject with the template's variables applied.
pub fn subject_for(
    state: &AppState,
    id: &str,
    site: Option<&SiteConfig>,
    lang: &str,
    vars: &[(&str, String)],
) -> String {
    let def = find(id).expect("unknown email template id");
    apply_subject(&effective_subject_tpl(state, def, site, lang), vars)
}

/// Fill and render one template: subject line plus html/text bodies. Values
/// in `vars` that came from users must already be markdown-escaped
/// (`email_md::escape`). `logo` is the (content id, alt) of an inline image
/// the caller attaches to the outgoing mail.
pub fn render_email(
    state: &AppState,
    id: &str,
    site: Option<&SiteConfig>,
    lang: &str,
    vars: &[(&str, String)],
    logo: Option<(&str, &str)>,
) -> (String, RenderedEmail) {
    let def = find(id).expect("unknown email template id");
    let subject = apply_subject(&effective_subject_tpl(state, def, site, lang), vars);
    let md = email_md::apply_template(&effective_body_tpl(state, def, site, lang), vars);
    (subject, email_md::render(&md, logo))
}

// ---------------------------------------------------------------------------
// Sample data for preview / test-send
// ---------------------------------------------------------------------------

fn sample_base(state: &AppState) -> String {
    let b = state.magic_link_base_url.trim_end_matches('/');
    if b.is_empty() {
        "https://susi.example.com".into()
    } else {
        b.into()
    }
}

fn sample_vars(
    state: &AppState,
    def: &TemplateDef,
    site: &'static SiteConfig,
    lang: &str,
) -> Vec<(&'static str, String)> {
    let base = sample_base(state);
    match def.id {
        "signin_code" => vec![
            ("user", "Taro".into()),
            ("code", "483920".into()),
            ("ttl", SIGNIN_CODE_TTL_MINUTES.to_string()),
        ],
        "password_reset" => vec![
            ("user", "Taro".into()),
            ("link", format!("{}/#/reset/sample-token", base)),
            ("ttl", PASSWORD_RESET_TTL_MINUTES.to_string()),
            ("ip", "203.0.113.5".into()),
        ],
        "invitation" => vec![
            ("user", "Taro".into()),
            ("link", format!("{}/#/reset/sample-token", base)),
            ("ttl", INVITE_TTL_HOURS.to_string()),
        ],
        "ticket_notification" => vec![
            ("subject", "[Susi] New ticket #12: Sensor calibration drifts".into()),
            ("heading", "New ticket #12".into()),
            ("intro", "Taro opened a new ticket in workspace LP-Research.".into()),
            (
                "rows",
                "|  |  |\n| --- | --- |\n| Workspace | **LP-Research** |\n| Priority | **normal** |\n| Status | **open** |".into(),
            ),
            ("excerpt", "> The sensor drifts about 2 degrees after 20 minutes of streaming.".into()),
            ("button", format!("{{{{button:Open ticket|{}/#/workspaces/sample/tickets/12}}}}", base)),
        ],
        "newsletter_confirm" => vec![
            ("url", format!("{}/api/v1/newsletter/confirm?token=sample", base)),
            ("site", email_md::escape(site.name)),
        ],
        "order_confirmation" => crate::shop::sample_confirmation_vars(state, site, lang),
        "order_shipped" => crate::shop::sample_shipped_vars(site, lang),
        _ => unreachable!("unknown template id"),
    }
}

fn preview_logo(def: &TemplateDef, site: &SiteConfig) -> Option<(&'static str, &'static str)> {
    match def.id {
        "order_confirmation" | "order_shipped" => Some((crate::shop::LOGO_CID, site.name)),
        "newsletter_confirm" => Some(("nl-logo", site.name)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Admin API
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct EmailTemplateEditRequest {
    pub id: String,
    #[serde(default)]
    pub lang: String,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub body_md: String,
}

type ApiError = (StatusCode, Json<ErrorResponse>);

fn resolve_def(
    req_id: &str,
    site: &SiteConfig,
    lang: &str,
) -> Result<&'static TemplateDef, ApiError> {
    let def = find(req_id)
        .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, "Unknown template"))?;
    let lang_ok = match def.store {
        Store::Shop => lang.is_empty() || site.langs.iter().any(|l| *l == lang),
        Store::Site => lang.is_empty(),
    };
    if !lang_ok {
        return Err(error_response(StatusCode::BAD_REQUEST, "Unknown language for this template"));
    }
    Ok(def)
}

fn langs_for(def: &TemplateDef, site: &SiteConfig) -> Vec<&'static str> {
    match def.store {
        Store::Shop => site.langs.to_vec(),
        Store::Site => Vec::new(),
    }
}

pub async fn handle_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    let templates: Vec<Value> = TEMPLATES
        .iter()
        .map(|d| {
            json!({
                "id": d.id,
                "title": d.title,
                "group": d.group,
                "per_site": d.per_site,
                "subject_editable": d.subject_editable,
            })
        })
        .collect();
    Ok(Json(json!({ "templates": templates })))
}

/// Resolve one template with sample data. Empty `subject` / `body_md` mean
/// "the currently effective (stored or default) template".
fn render_sample(
    state: &AppState,
    site: &'static SiteConfig,
    req: &EmailTemplateEditRequest,
) -> Result<(String, String, String, RenderedEmail, &'static TemplateDef), ApiError> {
    let def = resolve_def(&req.id, site, &req.lang)?;
    let site_opt = Some(site);
    let subject_tpl = if def.subject_editable && !req.subject.trim().is_empty() {
        req.subject.clone()
    } else {
        effective_subject_tpl(state, def, site_opt, &req.lang)
    };
    let body_tpl = if req.body_md.trim().is_empty() {
        effective_body_tpl(state, def, site_opt, &req.lang)
    } else {
        req.body_md.clone()
    };
    let vars = sample_vars(state, def, site, &req.lang);
    let subject = apply_subject(&subject_tpl, &vars);
    let md = email_md::apply_template(&body_tpl, &vars);
    let doc = email_md::render(&md, preview_logo(def, site));
    Ok((subject, subject_tpl, body_tpl, doc, def))
}

pub async fn handle_preview(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Json(req): Json<EmailTemplateEditRequest>,
) -> Result<Json<Value>, ApiError> {
    let site = resolve_site(&headers, &sq)?;
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    let (subject, subject_tpl, body_tpl, doc, def) = render_sample(&state, site, &req)?;
    Ok(Json(json!({
        "subject": subject,
        "subject_template": subject_tpl,
        "default_subject": default_subject(def, &req.lang),
        "markdown": body_tpl,
        "default_markdown": default_body(def, Some(site), &req.lang),
        "html": doc.html,
        "text": doc.text,
        "variables": def.vars,
        "langs": langs_for(def, site),
        "subject_editable": def.subject_editable,
        "per_site": def.per_site,
    })))
}

pub async fn handle_test(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Json(req): Json<EmailTemplateEditRequest>,
) -> Result<Json<Value>, ApiError> {
    let site = resolve_site(&headers, &sq)?;
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    let svc = state.email.clone().ok_or_else(|| {
        error_response(StatusCode::SERVICE_UNAVAILABLE, "SMTP is not configured on this server")
    })?;
    let to = {
        let db = state.db.lock();
        db.get_user_email(&p.username).ok().flatten()
    }
    .filter(|e| !e.is_empty())
    .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, "Your account has no email address"))?;
    let (subject, _stpl, _btpl, doc, def) = render_sample(&state, site, &req)?;
    let (inline, from_name) = match def.id {
        "order_confirmation" | "order_shipped" => (
            vec![crate::shop::logo_inline_image(site)],
            Some(format!("{} Shop", site.name)),
        ),
        "newsletter_confirm" => {
            (crate::newsletter::site_email_logo(&state, site).into_iter().collect(), None)
        }
        _ => (Vec::new(), None),
    };
    svc.send_html_rich(
        &to,
        &format!("[Test] {}", subject),
        &doc.text,
        &doc.html,
        &inline,
        &[],
        from_name.as_deref(),
    )
    .await
    .map_err(|e| error_response(StatusCode::BAD_GATEWAY, &format!("Send failed: {}", e)))?;
    Ok(Json(json!({ "sent_to": to })))
}

pub async fn handle_save(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Json(req): Json<EmailTemplateEditRequest>,
) -> Result<Json<Value>, ApiError> {
    let site = resolve_site(&headers, &sq)?;
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    let def = resolve_def(&req.id, site, &req.lang)?;
    let site_opt = Some(site);
    let key = body_key(def, &req.lang);
    let db_err =
        |e: susi_core::error::LicenseError| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
    store(&state, def, site_opt, &key, req.body_md.trim()).map_err(db_err)?;
    if def.subject_editable {
        store(&state, def, site_opt, &format!("{}_subject", key), req.subject.trim())
            .map_err(db_err)?;
    }
    crate::audit(&state, &p.username, "email_template.save", &key, site.id);
    Ok(Json(json!({ "status": "OK" })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_render_for_every_template_and_lang() {
        for def in TEMPLATES {
            for lang in ["", "ja"] {
                let body = default_body(def, Some(sites::default_site()), lang);
                let subject = default_subject(def, lang);
                assert!(!body.trim().is_empty(), "{} body", def.id);
                assert!(!subject.trim().is_empty(), "{} subject", def.id);
                // Every default only references declared variables.
                let vars: Vec<_> = def.vars.iter().map(|v| (*v, "x".to_string())).collect();
                for tpl in [body, subject.clone()] {
                    let r = email_md::apply_template(&tpl, &vars);
                    let stripped = r.replace("{{", "").replace("}}", "");
                    assert!(!stripped.contains('{'), "{} has undeclared var: {}", def.id, r);
                }
            }
        }
    }

    #[test]
    fn signin_default_renders_code_box() {
        let vars = vec![
            ("user", "Taro".to_string()),
            ("code", "483920".to_string()),
            ("ttl", "15".to_string()),
        ];
        let def = find("signin_code").unwrap();
        let md = email_md::apply_template(&default_body(def, None, ""), &vars);
        let doc = email_md::render(&md, None);
        assert!(doc.html.contains(">483920</div>"));
        assert!(doc.text.contains("    483920"));
        let subject = apply_subject(&default_subject(def, ""), &vars);
        assert_eq!(subject, "Susi by LP-Research: your sign-in code (15 min)");
    }

    #[test]
    fn ticket_default_drops_empty_excerpt_and_button() {
        let def = find("ticket_notification").unwrap();
        let vars = vec![
            ("subject", "s".to_string()),
            ("heading", "New ticket #1".to_string()),
            ("intro", "Intro.".to_string()),
            ("rows", "|  |  |\n| --- | --- |\n| K | **V** |".to_string()),
            ("excerpt", String::new()),
            ("button", String::new()),
        ];
        let md = email_md::apply_template(&default_body(def, None, ""), &vars);
        assert!(!md.contains("{excerpt}"));
        assert!(!md.contains("{button}"));
        assert!(md.contains("New ticket #1"));
    }

    #[test]
    fn storage_keys_match_historical_shop_keys() {
        let c = find("order_confirmation").unwrap();
        assert_eq!(body_key(c, ""), "email_order_confirmation");
        assert_eq!(body_key(c, "ja"), "email_order_confirmation_ja");
        let s = find("order_shipped").unwrap();
        assert_eq!(body_key(s, ""), "email_order_shipped");
        assert_eq!(body_key(s, "ja"), "email_order_shipped_ja");
        let g = find("signin_code").unwrap();
        assert_eq!(body_key(g, ""), "email_tpl_signin_code");
    }
}
