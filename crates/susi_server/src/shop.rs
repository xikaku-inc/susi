//! Shop endpoints — Stripe-backed checkout for physical goods.
//!
//! - Public: list products, get product, create checkout session, webhook.
//! - Admin (JWT): CRUD for products + shipping rates.
//!
//! The cart lives entirely in the browser (localStorage). The checkout
//! endpoint accepts `[{sku, qty}]` + destination_country, looks up authoritative
//! prices from the DB, picks applicable shipping rates, and hands the cart to
//! Stripe Checkout with `automatic_tax: true`. Stripe collects address +
//! payment, computes tax, and redirects to success_url / cancel_url.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;
use susi_core::error::LicenseError;

use crate::email::{EmailAttachment, InlineImage};
use crate::invoice_pdf;
use crate::{
    check_checkout_rate_limit, check_webhook_rate_limit, client_ip, error_response, require_admin,
    require_password_changed, validate_principal, AppState, ErrorResponse,
};

/// Brand logo embedded in the binary so it ships with every customer email
/// without depending on remote-image fetches (most clients block those).
/// Wide horizontal logo; constrain via CSS height in the HTML.
const LOGO_PNG: &[u8] = include_bytes!("assets/xikaku-logo.png");
const LOGO_CID: &str = "xikaku-logo";

fn logo_inline_image() -> InlineImage {
    InlineImage {
        content_id: LOGO_CID.into(),
        mime_type: "image/png".into(),
        bytes: LOGO_PNG.to_vec(),
    }
}

type HmacSha256 = Hmac<Sha256>;

const STRIPE_API_BASE: &str = "https://api.stripe.com/v1";
// Reject webhook events whose signed timestamp drifts more than this far from
// `now`. 5 minutes matches Stripe's own CLI default and covers NTP skew.
const WEBHOOK_TOLERANCE_SECS: i64 = 300;

fn db_err(e: LicenseError) -> (StatusCode, Json<ErrorResponse>) {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())
}

fn shop_configured(state: &AppState) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if state.stripe_secret_key.is_empty() {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Shop checkout is not configured on this server",
        ));
    }
    Ok(())
}

fn product_to_json(
    row: (String, String, String, i64, String, Option<String>, String, bool, i64, String),
) -> Value {
    let (sku, title, description_md, price_cents, currency, image_asset, tax_code, active, ord, updated_at) = row;
    json!({
        "sku": sku,
        "title": title,
        "description_md": description_md,
        "price_cents": price_cents,
        "currency": currency,
        "image_asset": image_asset,
        "image_url": image_asset.as_ref().map(|n| format!("/api/v1/website/assets/{}", n)),
        "tax_code": tax_code,
        "active": active,
        "ord": ord,
        "updated_at": updated_at,
    })
}

fn rate_to_json(
    row: (i64, String, i64, String, Option<i64>, Option<i64>, String, bool, i64),
) -> Value {
    let (id, label, amount_cents, currency, delivery_min_days, delivery_max_days, regions_json, active, ord) = row;
    let regions: Vec<String> = serde_json::from_str(&regions_json).unwrap_or_else(|_| vec!["*".into()]);
    json!({
        "id": id,
        "label": label,
        "amount_cents": amount_cents,
        "currency": currency,
        "delivery_min_days": delivery_min_days,
        "delivery_max_days": delivery_max_days,
        "regions": regions,
        "active": active,
        "ord": ord,
    })
}

// ---------------------------------------------------------------------------
// Public read endpoints
// ---------------------------------------------------------------------------

pub async fn handle_list_products(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let rows = {
        let db = state.db.lock().unwrap();
        db.list_products(true).map_err(db_err)?
    };
    let products: Vec<Value> = rows.into_iter().map(product_to_json).collect();
    Ok(Json(json!({ "products": products })))
}

pub async fn handle_get_product(
    State(state): State<Arc<AppState>>,
    Path(sku): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let row = {
        let db = state.db.lock().unwrap();
        db.get_product(&sku).map_err(db_err)?
    }
    .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Product not found"))?;
    if !row.7 {
        return Err(error_response(StatusCode::NOT_FOUND, "Product not found"));
    }
    Ok(Json(product_to_json(row)))
}

// ---------------------------------------------------------------------------
// Checkout
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CheckoutItem {
    pub sku: String,
    pub qty: i64,
}

#[derive(Deserialize)]
pub struct CheckoutRequest {
    pub items: Vec<CheckoutItem>,
    #[serde(default)]
    pub destination_country: String,
}

/// Region match — `*` is a wildcard for "any country".
fn rate_applies(regions: &[String], country: &str) -> bool {
    regions.iter().any(|r| r == "*" || r.eq_ignore_ascii_case(country))
}

/// Collect the union of allowed countries across all active rates. Stripe
/// requires 2-letter ISO codes; if a rate declares `*`, we expand it to the
/// supported country list. Shop currently ships to US and Canada only.
fn allowed_countries_for_checkout(rates: &[(i64, String, i64, String, Option<i64>, Option<i64>, String, bool, i64)]) -> Vec<String> {
    let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut wildcard = false;
    for r in rates {
        let regions: Vec<String> = serde_json::from_str(&r.6).unwrap_or_default();
        for reg in regions {
            if reg == "*" { wildcard = true; }
            else {
                let up = reg.to_uppercase();
                if SUPPORTED_SHIPPING_COUNTRIES.contains(&up.as_str()) { set.insert(up); }
            }
        }
    }
    if wildcard {
        for c in SUPPORTED_SHIPPING_COUNTRIES { set.insert((*c).into()); }
    }
    set.into_iter().collect()
}

const SUPPORTED_SHIPPING_COUNTRIES: &[&str] = &["US", "CA"];

/// Push a (key, value) pair onto a form builder using Stripe's bracket syntax.
/// e.g. `push(&mut form, &["line_items", "0", "price_data", "currency"], "usd")`
/// produces `line_items[0][price_data][currency]=usd`.
fn push_form(form: &mut Vec<(String, String)>, path: &[&str], value: impl Into<String>) {
    let mut key = String::new();
    for (i, p) in path.iter().enumerate() {
        if i == 0 {
            key.push_str(p);
        } else {
            key.push('[');
            key.push_str(p);
            key.push(']');
        }
    }
    form.push((key, value.into()));
}

pub async fn handle_create_checkout_session(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<CheckoutRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let ip = client_ip(peer, &headers);
    check_checkout_rate_limit(&state, ip)?;
    shop_configured(&state)?;

    if req.items.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Cart is empty"));
    }
    if req.items.len() > 100 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Too many items"));
    }
    // ISO-3166-1 alpha-2 country codes are 2 letters; allow empty (initial
    // page load before the country selector is rendered). Shop only serves
    // the US and Canada — reject all other destinations.
    if !req.destination_country.is_empty() {
        if req.destination_country.len() != 2
            || !req.destination_country.chars().all(|c| c.is_ascii_alphabetic())
        {
            return Err(error_response(StatusCode::BAD_REQUEST, "Invalid destination country"));
        }
        let up = req.destination_country.to_uppercase();
        if !SUPPORTED_SHIPPING_COUNTRIES.contains(&up.as_str()) {
            return Err(error_response(StatusCode::BAD_REQUEST, "We only ship to the US and Canada"));
        }
    }

    // Look up each SKU, never trust client-supplied price.
    let mut resolved: Vec<(String, String, i64, String, String, i64)> = Vec::with_capacity(req.items.len()); // sku, title, price_cents, currency, tax_code, qty
    let mut cart_currency: Option<String> = None;
    {
        let db = state.db.lock().unwrap();
        for item in &req.items {
            if item.qty <= 0 || item.qty > 1000 {
                return Err(error_response(StatusCode::BAD_REQUEST, "Invalid quantity"));
            }
            // Mirror admin validate_sku — bound length and character set so a
            // pathological client can't waste a DB lookup with megabyte SKUs.
            if item.sku.is_empty()
                || item.sku.len() > 64
                || !item.sku.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(error_response(StatusCode::BAD_REQUEST, "Invalid SKU"));
            }
            let row = db
                .get_product(&item.sku)
                .map_err(db_err)?
                .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, &format!("Unknown SKU: {}", item.sku)))?;
            let (sku, title, _desc, price_cents, currency, _img, tax_code, active, _ord, _upd) = row;
            if !active {
                return Err(error_response(StatusCode::BAD_REQUEST, &format!("Product is unavailable: {}", sku)));
            }
            match &cart_currency {
                None => cart_currency = Some(currency.clone()),
                Some(c) if c.eq_ignore_ascii_case(&currency) => {}
                Some(c) => return Err(error_response(
                    StatusCode::BAD_REQUEST,
                    &format!("Mixed currencies in cart: {} vs {}", c, currency),
                )),
            }
            resolved.push((sku, title, price_cents, currency, tax_code, item.qty));
        }
    }
    let cart_currency = cart_currency.unwrap_or_else(|| "usd".to_string());

    // Pick applicable shipping rates. If destination_country is empty (first
    // load), pass all active rates and let Stripe's address step handle it;
    // the currency must still match.
    let active_rates = {
        let db = state.db.lock().unwrap();
        db.list_shipping_rates(true).map_err(db_err)?
    };
    let applicable: Vec<_> = active_rates
        .into_iter()
        .filter(|r| r.3.eq_ignore_ascii_case(&cart_currency))
        .filter(|r| {
            if req.destination_country.is_empty() { return true; }
            let regions: Vec<String> = serde_json::from_str(&r.6).unwrap_or_default();
            rate_applies(&regions, &req.destination_country)
        })
        .collect();

    // Build Stripe Checkout Session form body.
    let mut form: Vec<(String, String)> = Vec::with_capacity(64);
    form.push(("mode".into(), "payment".into()));

    let success = format!("{}/shop/success?session_id={{CHECKOUT_SESSION_ID}}", state.shop_base_url.trim_end_matches('/'));
    let cancel = format!("{}/shop/cancel", state.shop_base_url.trim_end_matches('/'));
    form.push(("success_url".into(), success));
    form.push(("cancel_url".into(), cancel));

    form.push(("automatic_tax[enabled]".into(), "true".into()));
    // Always collect a billing address so receipts / invoices have one,
    // and so we can show it separately from the shipping address.
    form.push(("billing_address_collection".into(), "required".into()));
    // Tell Stripe to generate a hosted invoice + PDF for every paid session.
    // The webhook event then references the invoice id, which we fetch and
    // attach to the customer email.
    form.push(("invoice_creation[enabled]".into(), "true".into()));
    form.push((
        "invoice_creation[invoice_data][description]".into(),
        "Thanks for your order from Xikaku.".into(),
    ));
    form.push((
        "invoice_creation[invoice_data][footer]".into(),
        "LP-Research Inc. — Tokyo, Japan. Questions? support@lp-research.com".into(),
    ));

    for (i, (sku, title, price_cents, currency, tax_code, qty)) in resolved.iter().enumerate() {
        let idx = i.to_string();
        push_form(&mut form, &["line_items", &idx, "quantity"], qty.to_string());
        push_form(&mut form, &["line_items", &idx, "price_data", "currency"], currency.to_lowercase());
        push_form(&mut form, &["line_items", &idx, "price_data", "unit_amount"], price_cents.to_string());
        push_form(&mut form, &["line_items", &idx, "price_data", "tax_behavior"], "exclusive");
        push_form(&mut form, &["line_items", &idx, "price_data", "product_data", "name"], title.clone());
        push_form(&mut form, &["line_items", &idx, "price_data", "product_data", "tax_code"], tax_code.clone());
        push_form(&mut form, &["line_items", &idx, "price_data", "product_data", "metadata", "sku"], sku.clone());
    }

    // Shipping options.
    for (i, rate) in applicable.iter().enumerate() {
        let idx = i.to_string();
        push_form(&mut form, &["shipping_options", &idx, "shipping_rate_data", "type"], "fixed_amount");
        push_form(&mut form, &["shipping_options", &idx, "shipping_rate_data", "display_name"], rate.1.clone());
        push_form(&mut form, &["shipping_options", &idx, "shipping_rate_data", "fixed_amount", "amount"], rate.2.to_string());
        push_form(&mut form, &["shipping_options", &idx, "shipping_rate_data", "fixed_amount", "currency"], rate.3.to_lowercase());
        push_form(&mut form, &["shipping_options", &idx, "shipping_rate_data", "tax_behavior"], "exclusive");
        if let Some(min) = rate.4 {
            push_form(&mut form, &["shipping_options", &idx, "shipping_rate_data", "delivery_estimate", "minimum", "unit"], "business_day");
            push_form(&mut form, &["shipping_options", &idx, "shipping_rate_data", "delivery_estimate", "minimum", "value"], min.to_string());
        }
        if let Some(max) = rate.5 {
            push_form(&mut form, &["shipping_options", &idx, "shipping_rate_data", "delivery_estimate", "maximum", "unit"], "business_day");
            push_form(&mut form, &["shipping_options", &idx, "shipping_rate_data", "delivery_estimate", "maximum", "value"], max.to_string());
        }
    }

    // Always enable shipping address collection so the customer can enter
    // a delivery address that's distinct from billing. When the merchant
    // has configured rates, use their regions; otherwise fall back to a
    // common-countries list so checkout still works during initial setup.
    let countries = if applicable.is_empty() {
        SUPPORTED_SHIPPING_COUNTRIES.iter().map(|c| (*c).to_string()).collect()
    } else {
        allowed_countries_for_checkout(&applicable)
    };
    for (i, c) in countries.iter().enumerate() {
        push_form(&mut form, &["shipping_address_collection", "allowed_countries", &i.to_string()], c.clone());
    }

    // Call Stripe.
    let resp = state
        .http
        .post(format!("{}/checkout/sessions", STRIPE_API_BASE))
        .basic_auth(&state.stripe_secret_key, Some(""))
        .form(&form)
        .send()
        .await
        .map_err(|e| {
            log::error!("Stripe request failed: {}", e);
            error_response(StatusCode::BAD_GATEWAY, "Unable to reach Stripe")
        })?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        log::error!("Stripe checkout.sessions create failed: {} — {}", status, body);
        let short = if body.len() > 400 { &body[..400] } else { &body };
        return Err(error_response(
            StatusCode::BAD_GATEWAY,
            &format!("Stripe error ({}): {}", status.as_u16(), short),
        ));
    }
    let session: Value = serde_json::from_str(&body)
        .map_err(|e| error_response(StatusCode::BAD_GATEWAY, &format!("Bad Stripe response: {}", e)))?;
    let url = session.get("url").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let id = session.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    if url.is_empty() {
        return Err(error_response(StatusCode::BAD_GATEWAY, "Stripe returned no checkout URL"));
    }
    Ok(Json(json!({ "url": url, "session_id": id })))
}

// ---------------------------------------------------------------------------
// Webhook
//
// Stripe signs each webhook with an HMAC-SHA256 over `{timestamp}.{raw_body}`.
// We verify using the whsec_… secret + constant-time tag compare, then act on
// `checkout.session.completed` by emailing a short order summary to the shop
// owner. No DB writes — Stripe is the source of truth for orders.
// ---------------------------------------------------------------------------

fn parse_stripe_signature_header(h: &str) -> (Option<i64>, Vec<String>) {
    let mut t: Option<i64> = None;
    let mut v1s: Vec<String> = Vec::new();
    for part in h.split(',') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("t=") {
            t = rest.parse().ok();
        } else if let Some(rest) = part.strip_prefix("v1=") {
            v1s.push(rest.to_string());
        }
    }
    (t, v1s)
}

fn verify_stripe_signature(
    secret: &str,
    signature_header: &str,
    payload: &[u8],
    now: i64,
) -> Result<(), &'static str> {
    let (t, v1s) = parse_stripe_signature_header(signature_header);
    let ts = t.ok_or("missing timestamp")?;
    if (now - ts).abs() > WEBHOOK_TOLERANCE_SECS {
        return Err("timestamp outside tolerance");
    }
    if v1s.is_empty() { return Err("missing v1 signature"); }

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| "invalid secret")?;
    mac.update(ts.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload);
    let expected_hex = hex::encode(mac.finalize().into_bytes());

    // Any of the v1 signatures can match (Stripe may rotate).
    for candidate in &v1s {
        // `Mac::verify_slice` would be constant-time but we've already
        // consumed the MAC. Do a manual constant-time compare via hex strings.
        if constant_time_eq(candidate.as_bytes(), expected_hex.as_bytes()) {
            return Ok(());
        }
    }
    Err("signature mismatch")
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut r = 0u8;
    for i in 0..a.len() { r |= a[i] ^ b[i]; }
    r == 0
}

pub async fn handle_stripe_webhook(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let ip = client_ip(peer, &headers);
    check_webhook_rate_limit(&state, ip)?;
    if state.stripe_webhook_secret.is_empty() {
        return Err(error_response(StatusCode::SERVICE_UNAVAILABLE, "Webhook not configured"));
    }
    let sig = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, "Missing Stripe-Signature"))?;

    let now = chrono::Utc::now().timestamp();
    verify_stripe_signature(&state.stripe_webhook_secret, sig, &body, now).map_err(|e| {
        log::warn!("Stripe webhook signature verify failed: {}", e);
        error_response(StatusCode::BAD_REQUEST, "Invalid signature")
    })?;

    let event: Value = serde_json::from_slice(&body)
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("Bad JSON: {}", e)))?;
    let event_type = event.get("type").and_then(|v| v.as_str()).unwrap_or("");
    log::info!("Stripe webhook received: {}", event_type);

    if event_type == "checkout.session.completed" {
        // Persist a shadow-row in shop_orders so we can drive fulfillment
        // from the admin UI without a round-trip to Stripe for every list.
        let order_id = persist_order_from_event(&state, &event).await;

        // Fetch line items + invoice PDF in parallel — both via Stripe API,
        // both best-effort (we still send emails even if one is unavailable).
        let session_id = event
            .pointer("/data/object/id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let invoice_id = event
            .pointer("/data/object/invoice")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let (line_items, invoice_obj, invoice_number) = {
            let li_fut = async {
                if session_id.is_empty() { Vec::new() } else { fetch_line_items(&state, &session_id).await }
            };
            let inv_fut = async {
                if invoice_id.is_empty() {
                    (Value::Null, String::new())
                } else {
                    // We need the Stripe invoice for its number + creation
                    // timestamp, but we render the PDF ourselves below — see
                    // invoice_pdf::generate for why.
                    let inv = fetch_invoice(&state, &invoice_id).await;
                    let number = inv.get("number").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    (inv, number)
                }
            };
            let (li, (inv, num)) = tokio::join!(li_fut, inv_fut);
            (li, inv, num)
        };

        // Render our own paid-invoice PDF. Stripe's PDF for Checkout-paid
        // invoices is rendered once at finalization (status=open) and never
        // refreshed, so it always carries a "Pay online" CTA — useless for
        // a post-payment receipt.
        let pdf_bytes = match invoice_pdf::generate(&event, &line_items, &invoice_obj, order_id) {
            Ok(b) => b,
            Err(e) => { log::error!("invoice PDF generation failed: {}", e); Vec::new() }
        };

        let pdf_attachment: Option<EmailAttachment> = if pdf_bytes.is_empty() {
            None
        } else {
            let fname = if invoice_number.is_empty() {
                format!("invoice-xikaku-{}.pdf", order_id.map(|i| i.to_string()).unwrap_or_else(|| "order".into()))
            } else {
                format!("invoice-{}.pdf", invoice_number)
            };
            Some(EmailAttachment {
                file_name: fname,
                mime_type: "application/pdf".into(),
                bytes: pdf_bytes,
            })
        };

        // ----- Admin notification (one or more recipients) -----
        let admin_recipients = effective_admin_recipients(&state);
        if let Some(svc) = &state.email {
            if !admin_recipients.is_empty() {
                let summary = format_order_summary(&event, &line_items, order_id);
                let subject = format!("[Xikaku] New order — {}", summary.0);
                let body = summary.1;
                for to in admin_recipients {
                    let svc = svc.clone();
                    let to = to.clone();
                    let subject = subject.clone();
                    let body = body.clone();
                    let attach = pdf_attachment.as_ref().map(|a| EmailAttachment {
                        file_name: a.file_name.clone(),
                        mime_type: a.mime_type.clone(),
                        bytes: a.bytes.clone(),
                    });
                    tokio::spawn(async move {
                        let attachments: Vec<EmailAttachment> = attach.into_iter().collect();
                        // Wrap the plain text in <pre> so the HTML alternative
                        // preserves newlines and the column alignment.
                        let html = format!(
                            "<pre style=\"font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;white-space:pre-wrap;margin:0;\">{}</pre>",
                            html_escape_local(&body),
                        );
                        let res = svc.send_html_rich(&to, &subject, &body, &html, &[], &attachments, Some("Xikaku Shop")).await;
                        if let Err(e) = res {
                            log::error!("Failed to send admin notification to {}: {}", to, e);
                        }
                    });
                }
            }
        }

        // ----- Customer order confirmation -----
        if customer_email_enabled(&state) {
            let customer_email = event
                .pointer("/data/object/customer_details/email")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if let Some(svc) = state.email.clone() {
                if !customer_email.is_empty() {
                    let (subject, text, html) =
                        build_customer_confirmation(&state, &event, &line_items, order_id);
                    let inline = vec![logo_inline_image()];
                    let attachments: Vec<EmailAttachment> = pdf_attachment.into_iter().collect();
                    tokio::spawn(async move {
                        let res = svc.send_html_rich(&customer_email, &subject, &text, &html, &inline, &attachments, Some("Xikaku Shop")).await;
                        if let Err(e) = res {
                            log::error!("Failed to send customer confirmation to {}: {}", customer_email, e);
                        }
                    });
                }
            }
        }
    }

    Ok(Json(json!({ "received": true })))
}

// ---------------------------------------------------------------------------
// Settings — well-known keys and lookup helpers
// ---------------------------------------------------------------------------

const SETTING_NOTIFY_EMAILS: &str = "notification_emails";
const SETTING_CUSTOMER_EMAIL_ENABLED: &str = "customer_email_enabled";
const SETTING_CUSTOMER_THANK_YOU: &str = "customer_thank_you_html";
const SETTING_SUPPORT_CONTACT: &str = "support_contact";

/// Comma-or-whitespace-split a recipients string, trim, and dedupe.
fn split_recipients(s: &str) -> Vec<String> {
    let mut out: Vec<String> = s
        .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .filter_map(|t| {
            let t = t.trim();
            if t.is_empty() || !t.contains('@') { None } else { Some(t.to_string()) }
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Resolve admin recipients: DB-stored setting wins; falls back to the
/// SUSI_SHOP_NOTIFY_ADDR env var (kept for back-compat with the bootstrap
/// install that hasn't visited the Settings tab yet).
fn effective_admin_recipients(state: &AppState) -> Vec<String> {
    let from_db = {
        let db = state.db.lock().unwrap();
        db.get_shop_setting(SETTING_NOTIFY_EMAILS).ok().flatten().unwrap_or_default()
    };
    let mut list = split_recipients(&from_db);
    if list.is_empty() && !state.shop_notify_addr.is_empty() {
        list = split_recipients(&state.shop_notify_addr);
    }
    list
}

fn customer_email_enabled(state: &AppState) -> bool {
    let v = {
        let db = state.db.lock().unwrap();
        db.get_shop_setting(SETTING_CUSTOMER_EMAIL_ENABLED).ok().flatten()
    };
    // Default ON when unset — most shops want customer confirmations.
    match v.as_deref() {
        Some("0") | Some("false") | Some("off") => false,
        _ => true,
    }
}

fn get_setting_str(state: &AppState, key: &str) -> String {
    let db = state.db.lock().unwrap();
    db.get_shop_setting(key).ok().flatten().unwrap_or_default()
}

fn build_customer_confirmation(
    state: &AppState,
    event: &Value,
    line_items: &[Value],
    order_id: Option<i64>,
) -> (String, String, String) {
    let obj = event.pointer("/data/object").cloned().unwrap_or(Value::Null);
    let name = obj.pointer("/customer_details/name").and_then(|v| v.as_str()).unwrap_or("");
    let amount_total = obj.get("amount_total").and_then(|v| v.as_i64()).unwrap_or(0);
    let amount_subtotal = obj.get("amount_subtotal").and_then(|v| v.as_i64()).unwrap_or(0);
    let currency = obj.get("currency").and_then(|v| v.as_str()).unwrap_or("usd");
    let total_details = obj.get("total_details").cloned().unwrap_or(Value::Null);
    let amount_shipping = total_details.get("amount_shipping").and_then(|v| v.as_i64()).unwrap_or(0);
    let amount_tax = total_details.get("amount_tax").and_then(|v| v.as_i64()).unwrap_or(0);

    let order_label = order_id.map(|i| format!("#{}", i)).unwrap_or_else(|| "—".into());

    let support = get_setting_str(state, SETTING_SUPPORT_CONTACT);
    let extra_html = get_setting_str(state, SETTING_CUSTOMER_THANK_YOU);

    let subject = format!("Thanks for your order — Xikaku {}", order_label);

    // -------- Plain text --------
    let mut text = String::new();
    text.push_str(&format!("Hi {},\n\n",
        if name.is_empty() { "there" } else { name }));
    text.push_str(&format!("Thank you for your order! Order {} has been received and we're getting it ready.\n\n", order_label));

    text.push_str("Items\n");
    if line_items.is_empty() {
        text.push_str("  (line items unavailable)\n");
    } else {
        for li in line_items {
            let qty = li.get("quantity").and_then(|v| v.as_i64()).unwrap_or(1);
            let desc = li.get("description").and_then(|v| v.as_str()).unwrap_or("(item)");
            let amt = li.get("amount_total").and_then(|v| v.as_i64()).unwrap_or(0);
            text.push_str(&format!("  {} × {}  —  {}\n", qty, desc, fmt_money(amt, currency)));
        }
    }
    text.push_str("\n");
    text.push_str(&format!("Subtotal:  {}\n", fmt_money(amount_subtotal, currency)));
    text.push_str(&format!("Shipping:  {}\n", fmt_money(amount_shipping, currency)));
    text.push_str(&format!("Tax:       {}\n", fmt_money(amount_tax, currency)));
    text.push_str(&format!("Total:     {}\n\n", fmt_money(amount_total, currency)));

    // Ship-to confirmation in the customer email — reassures them the address
    // we'll ship to is what they entered.
    let ship_text = address_block_text(obj.get("shipping_details"), name);
    let bill_text = address_block_text(obj.get("customer_details"), name);
    if !ship_text.is_empty() && !bill_text.is_empty() && ship_text != bill_text {
        text.push_str("Ship to\n");
        text.push_str(&indent2(&ship_text));
        text.push_str("\nBill to\n");
        text.push_str(&indent2(&bill_text));
        text.push_str("\n");
    } else if !ship_text.is_empty() {
        text.push_str("Ship to & bill to\n");
        text.push_str(&indent2(&ship_text));
        text.push_str("\n");
    } else if !bill_text.is_empty() {
        text.push_str("Bill to\n");
        text.push_str(&indent2(&bill_text));
        text.push_str("\n");
    }

    text.push_str("A PDF invoice is attached for your records.\n\n");
    text.push_str("We'll send another email with your tracking number once your order ships from our Los Angeles office.\n\n");
    if !support.is_empty() {
        text.push_str(&format!("Questions? Reach us at {}.\n\n", support));
    }
    text.push_str("— The Xikaku team\n");

    // -------- HTML --------
    let mut item_rows = String::new();
    for li in line_items {
        let qty = li.get("quantity").and_then(|v| v.as_i64()).unwrap_or(1);
        let desc = li.get("description").and_then(|v| v.as_str()).unwrap_or("(item)");
        let amt = li.get("amount_total").and_then(|v| v.as_i64()).unwrap_or(0);
        let cur = li.get("currency").and_then(|v| v.as_str()).unwrap_or(currency);
        item_rows.push_str(&format!(
            "<tr>\
              <td style=\"padding:8px 0;color:#5c6470;width:50px;\">{} ×</td>\
              <td style=\"padding:8px 0;\">{}</td>\
              <td style=\"padding:8px 0;text-align:right;font-variant-numeric:tabular-nums;\">{}</td>\
            </tr>",
            qty, html_escape_local(desc), html_escape_local(&fmt_money(amt, cur)),
        ));
    }

    // Build separate ship-to and bill-to blocks. Show both when they differ;
    // collapse to a single "Ship to & bill to" block when they match.
    let ship_html = address_block_html(obj.get("shipping_details"), name);
    let bill_html = address_block_html(obj.get("customer_details"), name);
    let addresses_match = ship_html == bill_html;

    let support_block = if support.is_empty() { String::new() } else {
        format!(
            "<p style=\"color:#5c6470;font-size:13px;margin-top:24px;\">Questions? Reach us at <a href=\"mailto:{s}\" style=\"color:#2d6fdc;\">{s}</a>.</p>",
            s = html_escape_local(&support),
        )
    };

    // Admin-supplied custom thank-you copy. Inserted as raw HTML — admin is
    // a trusted role so we don't need to sanitize, but we wrap it in a
    // styled block so it slots into the layout cleanly.
    let extra_block = if extra_html.trim().is_empty() { String::new() } else {
        format!(
            "<div style=\"background:#eef4ff;border-left:3px solid #2d6fdc;padding:12px 16px;margin:18px 0;color:#1a1d23;font-size:13px;line-height:1.55;\">{}</div>",
            extra_html,
        )
    };

    // Address sections — single block when shipping == billing, split when they differ.
    let address_section = if ship_html.is_empty() && bill_html.is_empty() {
        String::new()
    } else if addresses_match || bill_html.is_empty() {
        format!(
            "<h2 style=\"font-size:14px;margin:28px 0 8px;\">Ship to &amp; bill to</h2>\
             <div style=\"font-size:13px;line-height:1.55;\">{}</div>",
            ship_html,
        )
    } else if ship_html.is_empty() {
        format!(
            "<h2 style=\"font-size:14px;margin:28px 0 8px;\">Bill to</h2>\
             <div style=\"font-size:13px;line-height:1.55;\">{}</div>",
            bill_html,
        )
    } else {
        format!(
            "<table style=\"width:100%;border-collapse:separate;border-spacing:12px 0;margin-top:20px;\">\
               <tr>\
                 <td style=\"width:50%;vertical-align:top;\">\
                   <h2 style=\"font-size:14px;margin:0 0 8px;\">Ship to</h2>\
                   <div style=\"font-size:13px;line-height:1.55;\">{ship}</div>\
                 </td>\
                 <td style=\"width:50%;vertical-align:top;\">\
                   <h2 style=\"font-size:14px;margin:0 0 8px;\">Bill to</h2>\
                   <div style=\"font-size:13px;line-height:1.55;\">{bill}</div>\
                 </td>\
               </tr>\
             </table>",
            ship = ship_html,
            bill = bill_html,
        )
    };

    let html = format!(
        "<!doctype html><html><body style=\"margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#ffffff;color:#1a1d23;\">\
         <div style=\"max-width:600px;margin:0 auto;padding:32px 24px;\">\
           <div style=\"text-align:left;margin-bottom:24px;\">\
             <img src=\"cid:{logo_cid}\" alt=\"Xikaku\" style=\"height:36px;display:inline-block;\">\
           </div>\
           <h1 style=\"font-size:22px;margin:0 0 6px;\">Thank you for your order</h1>\
           <p style=\"color:#5c6470;margin:0 0 20px;\">Order {order} · {date}</p>\
           <p>Hi {name_html},</p>\
           <p>Thanks for your purchase from Xikaku — we've received your order and are getting it ready.</p>\
           {extra_block}\
           <h2 style=\"font-size:14px;margin:28px 0 8px;\">Items</h2>\
           <table style=\"width:100%;border-collapse:collapse;\">\
             <tbody>{rows}</tbody>\
           </table>\
           <table style=\"width:100%;margin-top:14px;font-size:13px;\">\
             <tr><td style=\"color:#5c6470;\">Subtotal</td><td style=\"text-align:right;\">{subtotal}</td></tr>\
             <tr><td style=\"color:#5c6470;\">Shipping</td><td style=\"text-align:right;\">{shipping}</td></tr>\
             <tr><td style=\"color:#5c6470;\">Tax</td><td style=\"text-align:right;\">{tax}</td></tr>\
             <tr><td style=\"font-weight:600;padding-top:6px;border-top:1px solid #d8dbe1;\">Total</td><td style=\"font-weight:600;text-align:right;padding-top:6px;border-top:1px solid #d8dbe1;\">{total}</td></tr>\
           </table>\
           {address_section}\
           <p style=\"margin-top:24px;font-size:13px;color:#5c6470;\">\
             We're processing your order now. You'll get a second email with your tracking number once it ships from our Los Angeles office.\
           </p>\
           <p style=\"color:#5c6470;font-size:12px;margin-top:18px;\">A PDF invoice is attached to this email for your records.</p>\
           {support_block}\
           <p style=\"color:#5c6470;font-size:12px;margin-top:32px;\">— The Xikaku team</p>\
         </div></body></html>",
        logo_cid = LOGO_CID,
        order = order_label,
        date = chrono::Utc::now().format("%Y-%m-%d"),
        name_html = html_escape_local(if name.is_empty() { "there" } else { name }),
        extra_block = extra_block,
        rows = if item_rows.is_empty() { "<tr><td style=\"padding:8px 0;color:#5c6470;\">(item details unavailable)</td></tr>".into() } else { item_rows },
        subtotal = html_escape_local(&fmt_money(amount_subtotal, currency)),
        shipping = html_escape_local(&fmt_money(amount_shipping, currency)),
        tax = html_escape_local(&fmt_money(amount_tax, currency)),
        total = html_escape_local(&fmt_money(amount_total, currency)),
        address_section = address_section,
        support_block = support_block,
    );

    (subject, text, html)
}

/// Plain-text equivalent of `address_block_html`, joining lines with `\n`.
fn address_block_text(details: Option<&Value>, fallback_name: &str) -> String {
    let Some(s) = details else { return String::new() };
    let a = s.get("address").cloned().unwrap_or(Value::Null);
    if a.is_null() { return String::new() }
    let line1 = a.get("line1").and_then(|v| v.as_str()).unwrap_or("");
    if line1.is_empty() { return String::new() }
    let ship_name = s.get("name").and_then(|v| v.as_str()).unwrap_or(fallback_name);
    let mut parts: Vec<String> = Vec::new();
    if !ship_name.is_empty() { parts.push(ship_name.to_string()); }
    parts.push(line1.to_string());
    if let Some(v) = a.get("line2").and_then(|v| v.as_str()) {
        if !v.is_empty() { parts.push(v.to_string()); }
    }
    let city = a.get("city").and_then(|v| v.as_str()).unwrap_or("");
    let state_ = a.get("state").and_then(|v| v.as_str()).unwrap_or("");
    let postal = a.get("postal_code").and_then(|v| v.as_str()).unwrap_or("");
    let csz: Vec<&str> = [city, state_, postal].iter().copied().filter(|s| !s.is_empty()).collect();
    if !csz.is_empty() { parts.push(csz.join(", ")); }
    if let Some(c) = a.get("country").and_then(|v| v.as_str()) {
        if !c.is_empty() { parts.push(c.to_string()); }
    }
    parts.join("\n")
}

fn indent2(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for line in s.lines() {
        out.push_str("  ");
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Build an HTML address block from a Stripe `customer_details` /
/// `shipping_details` object. Returns "" when the address is empty / absent.
fn address_block_html(details: Option<&Value>, fallback_name: &str) -> String {
    let Some(s) = details else { return String::new() };
    let a = s.get("address").cloned().unwrap_or(Value::Null);
    if a.is_null() { return String::new() }
    let line1 = a.get("line1").and_then(|v| v.as_str()).unwrap_or("");
    if line1.is_empty() { return String::new() } // Skip when there's no real street address.
    let ship_name = s.get("name").and_then(|v| v.as_str()).unwrap_or(fallback_name);
    let mut parts: Vec<String> = Vec::new();
    if !ship_name.is_empty() { parts.push(html_escape_local(ship_name)); }
    parts.push(html_escape_local(line1));
    if let Some(v) = a.get("line2").and_then(|v| v.as_str()) {
        if !v.is_empty() { parts.push(html_escape_local(v)); }
    }
    let city = a.get("city").and_then(|v| v.as_str()).unwrap_or("");
    let state_ = a.get("state").and_then(|v| v.as_str()).unwrap_or("");
    let postal = a.get("postal_code").and_then(|v| v.as_str()).unwrap_or("");
    let csz: Vec<&str> = [city, state_, postal].iter().copied().filter(|s| !s.is_empty()).collect();
    if !csz.is_empty() { parts.push(html_escape_local(&csz.join(", "))); }
    if let Some(c) = a.get("country").and_then(|v| v.as_str()) {
        if !c.is_empty() { parts.push(html_escape_local(c)); }
    }
    parts.join("<br>")
}

/// Fetch a Stripe Invoice object so we can extract its hosted PDF URL.
/// Returns Value::Null on any error so callers can degrade gracefully.
async fn fetch_invoice(state: &AppState, invoice_id: &str) -> Value {
    if state.stripe_secret_key.is_empty() || invoice_id.is_empty() {
        return Value::Null;
    }
    let url = format!("{}/invoices/{}", STRIPE_API_BASE, invoice_id);
    match state.http.get(url).basic_auth(&state.stripe_secret_key, Some("")).send().await {
        Ok(resp) if resp.status().is_success() => match resp.text().await {
            Ok(b) => serde_json::from_str(&b).unwrap_or(Value::Null),
            Err(e) => { log::warn!("invoice fetch read body: {}", e); Value::Null }
        },
        Ok(resp) => { log::warn!("invoice fetch HTTP {}", resp.status()); Value::Null }
        Err(e) => { log::warn!("invoice fetch: {}", e); Value::Null }
    }
}

/// Pull line items from the Stripe API (the webhook payload doesn't include
/// them — Stripe explicitly omits expandable fields on webhook events).
async fn fetch_line_items(state: &AppState, session_id: &str) -> Vec<Value> {
    if state.stripe_secret_key.is_empty() { return Vec::new(); }
    let url = format!("{}/checkout/sessions/{}/line_items?limit=100", STRIPE_API_BASE, session_id);
    match state.http.get(url).basic_auth(&state.stripe_secret_key, Some("")).send().await {
        Ok(resp) if resp.status().is_success() => {
            match resp.text().await {
                Ok(body) => match serde_json::from_str::<Value>(&body) {
                    Ok(v) => v.get("data").and_then(|d| d.as_array()).cloned().unwrap_or_default(),
                    Err(e) => { log::warn!("line_items: bad json: {}", e); Vec::new() }
                },
                Err(e) => { log::warn!("line_items: read body: {}", e); Vec::new() }
            }
        }
        Ok(resp) => { log::warn!("line_items: HTTP {}", resp.status()); Vec::new() }
        Err(e) => { log::warn!("line_items: {}", e); Vec::new() }
    }
}

/// Persist a Stripe Checkout Session as a shop_orders row. Returns the local
/// order id on success, None on any error (we still want the webhook to ack
/// 200 so Stripe doesn't keep retrying).
async fn persist_order_from_event(state: &AppState, event: &Value) -> Option<i64> {
    let obj = event.pointer("/data/object")?;
    let session_id = obj.get("id")?.as_str()?;

    let email = obj.pointer("/customer_details/email").and_then(|v| v.as_str()).unwrap_or("");
    let name = obj.pointer("/customer_details/name").and_then(|v| v.as_str()).unwrap_or("");
    let amount = obj.get("amount_total").and_then(|v| v.as_i64()).unwrap_or(0);
    let currency = obj.get("currency").and_then(|v| v.as_str()).unwrap_or("usd");

    // shipping_details is preferred (delivery address). Fall back to the
    // billing address from customer_details when shipping wasn't collected.
    let ship_to = obj.get("shipping_details")
        .or_else(|| obj.get("customer_details"))
        .cloned()
        .unwrap_or(Value::Null);
    let ship_to_json = serde_json::to_string(&ship_to).unwrap_or_else(|_| "{}".into());

    let line_items = fetch_line_items(state, session_id).await;
    let line_items_json = serde_json::to_string(&line_items).unwrap_or_else(|_| "[]".into());

    let now = chrono::Utc::now().to_rfc3339();
    let res = {
        let db = state.db.lock().unwrap();
        db.insert_order_if_absent(session_id, &now, email, name, amount, currency, &ship_to_json, &line_items_json)
    };
    match res {
        Ok(id) => Some(id),
        Err(e) => { log::error!("persist order: {}", e); None }
    }
}

/// Returns (short_summary, full_body). Now includes line items, shipping
/// address, totals breakdown, and a link to the local order in the dashboard.
fn format_order_summary(event: &Value, line_items: &[Value], order_id: Option<i64>) -> (String, String) {
    let obj = event.pointer("/data/object").cloned().unwrap_or(Value::Null);
    let session_id = obj.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
    let email = obj.pointer("/customer_details/email").and_then(|v| v.as_str()).unwrap_or("");
    let name = obj.pointer("/customer_details/name").and_then(|v| v.as_str()).unwrap_or("");
    let phone = obj.pointer("/customer_details/phone").and_then(|v| v.as_str()).unwrap_or("");

    let amount_total = obj.get("amount_total").and_then(|v| v.as_i64()).unwrap_or(0);
    let amount_subtotal = obj.get("amount_subtotal").and_then(|v| v.as_i64()).unwrap_or(0);
    let currency = obj.get("currency").and_then(|v| v.as_str()).unwrap_or("");

    let total_details = obj.get("total_details").cloned().unwrap_or(Value::Null);
    let amount_shipping = total_details.get("amount_shipping").and_then(|v| v.as_i64()).unwrap_or(0);
    let amount_tax      = total_details.get("amount_tax").and_then(|v| v.as_i64()).unwrap_or(0);
    let amount_discount = total_details.get("amount_discount").and_then(|v| v.as_i64()).unwrap_or(0);

    let display_name = if !name.is_empty() { name } else { email };
    let short = format!("{} — {}", fmt_money(amount_total, currency), display_name);

    let mut out = String::new();
    out.push_str(&format!("New order #{} from {} <{}>\n",
        order_id.map(|i| i.to_string()).unwrap_or_else(|| "—".into()),
        if !name.is_empty() { name } else { "(no name)" },
        email,
    ));
    if !phone.is_empty() {
        out.push_str(&format!("Phone:     {}\n", phone));
    }

    // Address blocks — split when shipping and billing differ so the
    // operator can spot a mismatched billing address before shipping.
    let ship_text = address_block_text(obj.get("shipping_details"), name);
    let bill_text = address_block_text(obj.get("customer_details"), name);
    if !ship_text.is_empty() && !bill_text.is_empty() && ship_text != bill_text {
        out.push_str("\n--- Ship to ---\n");
        out.push_str(&ship_text);
        out.push_str("\n\n--- Bill to ---\n");
        out.push_str(&bill_text);
        out.push('\n');
    } else if !ship_text.is_empty() {
        out.push_str("\n--- Ship to ---\n");
        out.push_str(&ship_text);
        out.push('\n');
    } else if !bill_text.is_empty() {
        out.push_str("\n--- Bill to ---\n");
        out.push_str(&bill_text);
        out.push('\n');
    } else {
        out.push_str("\n(no address on session)\n");
    }

    out.push_str("\n--- Items ---\n");
    if line_items.is_empty() {
        out.push_str("(line items unavailable — see Stripe dashboard)\n");
    } else {
        for li in line_items {
            let qty = li.get("quantity").and_then(|v| v.as_i64()).unwrap_or(1);
            let desc = li.get("description").and_then(|v| v.as_str()).unwrap_or("(item)");
            let amt = li.get("amount_total").and_then(|v| v.as_i64()).unwrap_or(0);
            let cur = li.get("currency").and_then(|v| v.as_str()).unwrap_or(currency);
            // Pull SKU from product metadata when present (we set it during checkout).
            let sku = li.pointer("/price/product").and_then(|p| {
                if let Some(s) = p.as_str() { Some(s.to_string()) } else {
                    p.pointer("/metadata/sku").and_then(|v| v.as_str()).map(String::from)
                }
            }).unwrap_or_default();
            if sku.is_empty() {
                out.push_str(&format!("  {} × {}  —  {}\n", qty, desc, fmt_money(amt, cur)));
            } else {
                out.push_str(&format!("  {} × {} ({})  —  {}\n", qty, desc, sku, fmt_money(amt, cur)));
            }
        }
    }

    out.push_str("\n--- Totals ---\n");
    out.push_str(&format!("Subtotal:  {}\n", fmt_money(amount_subtotal, currency)));
    if amount_discount != 0 { out.push_str(&format!("Discount:  -{}\n", fmt_money(amount_discount, currency))); }
    out.push_str(&format!("Shipping:  {}\n", fmt_money(amount_shipping, currency)));
    out.push_str(&format!("Tax:       {}\n", fmt_money(amount_tax, currency)));
    out.push_str(&format!("TOTAL:     {}\n", fmt_money(amount_total, currency)));

    out.push_str("\n--- Refs ---\n");
    out.push_str(&format!("Stripe session: {}\n", session_id));
    out.push_str(&format!("Stripe link:    https://dashboard.stripe.com/payments/{}\n", session_id));
    if let Some(i) = order_id {
        out.push_str(&format!("Susi order:     #{}  (mark shipped via the Shop → Orders tab)\n", i));
    }
    out.push_str("\n--- Action ---\nPack the items, ship them, then visit the Orders tab to record the tracking number.\n");
    out.push_str("The customer will get an automatic email with carrier + tracking when you do.\n");
    (short, out)
}

fn fmt_money(cents: i64, currency: &str) -> String {
    let whole = cents / 100;
    let frac = (cents.rem_euclid(100)).abs();
    format!("{}.{:02} {}", whole, frac, currency.to_uppercase())
}

// ---------------------------------------------------------------------------
// Admin endpoints (JWT)
// ---------------------------------------------------------------------------

pub async fn handle_admin_list_products(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_password_changed(&state, &p)?;
    require_admin(&state, &p)?;
    let rows = {
        let db = state.db.lock().unwrap();
        db.list_products(false).map_err(db_err)?
    };
    let products: Vec<Value> = rows.into_iter().map(product_to_json).collect();
    Ok(Json(json!({ "products": products })))
}

#[derive(Deserialize)]
pub struct UpsertProductRequest {
    pub title: String,
    #[serde(default)]
    pub description_md: String,
    pub price_cents: i64,
    #[serde(default = "default_currency")]
    pub currency: String,
    #[serde(default)]
    pub image_asset: Option<String>,
    #[serde(default = "default_tax_code")]
    pub tax_code: String,
    #[serde(default = "default_active")]
    pub active: bool,
    #[serde(default)]
    pub ord: i64,
}

fn default_currency() -> String { "usd".into() }
fn default_tax_code() -> String { "txcd_99999999".into() }
fn default_active() -> bool { true }

fn validate_sku(sku: &str) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if sku.is_empty()
        || sku.len() > 64
        || !sku.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(error_response(StatusCode::BAD_REQUEST, "Invalid SKU (ascii alnum, - or _, <=64 chars)"));
    }
    Ok(())
}

pub async fn handle_upsert_product(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(sku): Path<String>,
    Json(req): Json<UpsertProductRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_password_changed(&state, &p)?;
    require_admin(&state, &p)?;
    validate_sku(&sku)?;
    if req.title.trim().is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Title is required"));
    }
    if req.price_cents < 0 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Price cannot be negative"));
    }
    {
        let db = state.db.lock().unwrap();
        db.upsert_product(
            &sku,
            &req.title,
            &req.description_md,
            req.price_cents,
            &req.currency.to_lowercase(),
            req.image_asset.as_deref(),
            &req.tax_code,
            req.active,
            req.ord,
        )
        .map_err(db_err)?;
    }
    Ok(Json(json!({ "sku": sku })))
}

pub async fn handle_delete_product(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(sku): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_password_changed(&state, &p)?;
    require_admin(&state, &p)?;
    validate_sku(&sku)?;
    let removed = {
        let db = state.db.lock().unwrap();
        db.delete_product(&sku).map_err(db_err)?
    };
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Product not found"));
    }
    Ok(Json(json!({ "status": "OK" })))
}

pub async fn handle_list_shipping_rates_admin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_password_changed(&state, &p)?;
    require_admin(&state, &p)?;
    let rows = {
        let db = state.db.lock().unwrap();
        db.list_shipping_rates(false).map_err(db_err)?
    };
    let rates: Vec<Value> = rows.into_iter().map(rate_to_json).collect();
    Ok(Json(json!({ "rates": rates })))
}

#[derive(Deserialize)]
pub struct ShippingRateRequest {
    pub label: String,
    pub amount_cents: i64,
    #[serde(default = "default_currency")]
    pub currency: String,
    #[serde(default)]
    pub delivery_min_days: Option<i64>,
    #[serde(default)]
    pub delivery_max_days: Option<i64>,
    #[serde(default = "default_regions")]
    pub regions: Vec<String>,
    #[serde(default = "default_active")]
    pub active: bool,
    #[serde(default)]
    pub ord: i64,
}

fn default_regions() -> Vec<String> { vec!["*".into()] }

fn validate_rate_body(r: &ShippingRateRequest) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    if r.label.trim().is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Label is required"));
    }
    if r.amount_cents < 0 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Amount cannot be negative"));
    }
    for reg in &r.regions {
        if reg == "*" { continue; }
        if !(reg.len() == 2 && reg.chars().all(|c| c.is_ascii_alphabetic())) {
            return Err(error_response(StatusCode::BAD_REQUEST, &format!("Invalid region code: {}", reg)));
        }
        let up = reg.to_uppercase();
        if !SUPPORTED_SHIPPING_COUNTRIES.contains(&up.as_str()) {
            return Err(error_response(StatusCode::BAD_REQUEST, &format!("Unsupported region: {} (only US and CA are supported)", reg)));
        }
    }
    let normalized: Vec<String> = r.regions.iter()
        .map(|s| if s == "*" { s.clone() } else { s.to_uppercase() })
        .collect();
    serde_json::to_string(&normalized)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("JSON encode: {}", e)))
}

pub async fn handle_create_shipping_rate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ShippingRateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_password_changed(&state, &p)?;
    require_admin(&state, &p)?;
    let regions_json = validate_rate_body(&req)?;
    let id = {
        let db = state.db.lock().unwrap();
        db.insert_shipping_rate(
            &req.label,
            req.amount_cents,
            &req.currency.to_lowercase(),
            req.delivery_min_days,
            req.delivery_max_days,
            &regions_json,
            req.active,
            req.ord,
        ).map_err(db_err)?
    };
    Ok(Json(json!({ "id": id })))
}

pub async fn handle_update_shipping_rate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<ShippingRateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_password_changed(&state, &p)?;
    require_admin(&state, &p)?;
    let regions_json = validate_rate_body(&req)?;
    let ok = {
        let db = state.db.lock().unwrap();
        db.update_shipping_rate(
            id,
            &req.label,
            req.amount_cents,
            &req.currency.to_lowercase(),
            req.delivery_min_days,
            req.delivery_max_days,
            &regions_json,
            req.active,
            req.ord,
        ).map_err(db_err)?
    };
    if !ok {
        return Err(error_response(StatusCode::NOT_FOUND, "Shipping rate not found"));
    }
    Ok(Json(json!({ "id": id })))
}

pub async fn handle_delete_shipping_rate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_password_changed(&state, &p)?;
    require_admin(&state, &p)?;
    let removed = {
        let db = state.db.lock().unwrap();
        db.delete_shipping_rate(id).map_err(db_err)?
    };
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Shipping rate not found"));
    }
    Ok(Json(json!({ "status": "OK" })))
}

// ---------------------------------------------------------------------------
// Orders admin (JWT)
// ---------------------------------------------------------------------------

#[allow(clippy::type_complexity)]
fn order_to_json(
    row: (i64, String, String, String, String, i64, String, String, String, String, String, String, Option<String>, String),
) -> Value {
    let (id, sid, created_at, email, name, amount, currency, status, ship_to, line_items, carrier, tracking, shipped_at, notes) = row;
    let ship_to_v: Value = serde_json::from_str(&ship_to).unwrap_or(Value::Null);
    let line_items_v: Value = serde_json::from_str(&line_items).unwrap_or_else(|_| Value::Array(Vec::new()));
    json!({
        "id": id,
        "stripe_session_id": sid,
        "stripe_link": format!("https://dashboard.stripe.com/payments/{}", sid),
        "created_at": created_at,
        "customer_email": email,
        "customer_name": name,
        "amount_total_cents": amount,
        "currency": currency,
        "status": status,
        "ship_to": ship_to_v,
        "line_items": line_items_v,
        "tracking_carrier": carrier,
        "tracking_number": tracking,
        "tracking_url": tracking_url(&carrier, &tracking),
        "shipped_at": shipped_at,
        "notes": notes,
    })
}

/// Build a customer-facing tracking URL from carrier name + tracking number.
/// Returns None for unknown carriers — the email then shows just the number.
fn tracking_url(carrier: &str, tracking: &str) -> Option<String> {
    if tracking.is_empty() { return None; }
    let n = urlencoding_encode(tracking);
    let key = carrier.to_ascii_lowercase();
    let url = match key.as_str() {
        "usps" => format!("https://tools.usps.com/go/TrackConfirmAction?tLabels={}", n),
        "fedex" => format!("https://www.fedex.com/fedextrack/?trknbr={}", n),
        "ups" => format!("https://www.ups.com/track?tracknum={}", n),
        "dhl" => format!("https://www.dhl.com/global-en/home/tracking/tracking-express.html?tracking-id={}", n),
        "ems" | "japan post" | "japanpost" =>
            format!("https://trackings.post.japanpost.jp/services/srv/search/direct?reqCodeNo1={}&searchKind=S004", n),
        _ => return None,
    };
    Some(url)
}

/// Lightweight URL encoder — only escapes the ASCII chars that need escaping
/// in a query value. Avoids pulling in a separate dep just for this one use.
fn urlencoding_encode(s: &str) -> String {
    const HEX: &[u8] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(*b as char),
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0xf) as usize] as char);
            }
        }
    }
    out
}

pub async fn handle_admin_list_orders(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_password_changed(&state, &p)?;
    require_admin(&state, &p)?;
    let status = q.get("status").map(|s| s.as_str());
    let rows = {
        let db = state.db.lock().unwrap();
        db.list_orders(status).map_err(db_err)?
    };
    let orders: Vec<Value> = rows.into_iter().map(order_to_json).collect();
    Ok(Json(json!({ "orders": orders })))
}

pub async fn handle_admin_get_order(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_password_changed(&state, &p)?;
    require_admin(&state, &p)?;
    let row = {
        let db = state.db.lock().unwrap();
        db.get_order(id).map_err(db_err)?
    }.ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Order not found"))?;
    Ok(Json(order_to_json(row)))
}

#[derive(Deserialize)]
pub struct ShipOrderRequest {
    pub carrier: String,
    pub tracking_number: String,
    #[serde(default = "default_true")]
    pub notify_customer: bool,
}
fn default_true() -> bool { true }

pub async fn handle_admin_mark_shipped(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<ShipOrderRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_password_changed(&state, &p)?;
    require_admin(&state, &p)?;
    let carrier = req.carrier.trim();
    let tracking = req.tracking_number.trim();
    if carrier.is_empty() || tracking.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "carrier and tracking_number required"));
    }
    let now = chrono::Utc::now().to_rfc3339();
    let order = {
        let db = state.db.lock().unwrap();
        let ok = db.mark_order_shipped(id, carrier, tracking, &now).map_err(db_err)?;
        if !ok { return Err(error_response(StatusCode::NOT_FOUND, "Order not found")); }
        db.get_order(id).map_err(db_err)?
    };
    let order = order.ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Order vanished"))?;

    if req.notify_customer {
        let email = order.3.clone();
        if !email.is_empty() {
            if let Some(svc) = state.email.clone() {
                let body = build_shipped_email(&order);
                let subject = format!("Your Xikaku order #{} has shipped", order.0);
                tokio::spawn(async move {
                    if let Err(e) = svc.send_html_as("Xikaku Shop", &email, &subject, &body.0, &body.1).await {
                        log::error!("Failed to send shipped email to {}: {}", email, e);
                    }
                });
            }
        }
    }

    Ok(Json(order_to_json(order)))
}

#[derive(Deserialize)]
pub struct UpdateOrderNotesRequest {
    pub notes: String,
}

pub async fn handle_admin_update_order_notes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<UpdateOrderNotesRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_password_changed(&state, &p)?;
    require_admin(&state, &p)?;
    let ok = {
        let db = state.db.lock().unwrap();
        db.update_order_notes(id, &req.notes).map_err(db_err)?
    };
    if !ok { return Err(error_response(StatusCode::NOT_FOUND, "Order not found")); }
    Ok(Json(json!({ "id": id })))
}

#[allow(clippy::type_complexity)]
fn build_shipped_email(
    order: &(i64, String, String, String, String, i64, String, String, String, String, String, String, Option<String>, String),
) -> (String, String) {
    let (id, _sid, _created, _email, name, amount, currency, _status, _ship, line_items_json, carrier, tracking, _shipped, _notes) = order;
    let line_items: Value = serde_json::from_str(line_items_json).unwrap_or(Value::Array(Vec::new()));
    let url = tracking_url(carrier, tracking);

    let mut text = String::new();
    text.push_str(&format!("Hi {},\n\n", if name.is_empty() { "there" } else { name.as_str() }));
    text.push_str(&format!("Your Xikaku order #{} has shipped.\n\n", id));
    text.push_str(&format!("Carrier:  {}\n", carrier));
    text.push_str(&format!("Tracking: {}\n", tracking));
    if let Some(u) = &url { text.push_str(&format!("Track:    {}\n", u)); }
    text.push_str(&format!("\nOrder total: {}\n", fmt_money(*amount, currency)));
    if let Some(items) = line_items.as_array() {
        if !items.is_empty() {
            text.push_str("\nItems shipped:\n");
            for li in items {
                let qty = li.get("quantity").and_then(|v| v.as_i64()).unwrap_or(1);
                let desc = li.get("description").and_then(|v| v.as_str()).unwrap_or("(item)");
                text.push_str(&format!("  {} × {}\n", qty, desc));
            }
        }
    }
    text.push_str("\nThanks for buying from Xikaku!\n— The Xikaku team\n");

    let track_btn = match &url {
        Some(u) => format!(
            "<p style=\"margin:18px 0;\"><a href=\"{}\" style=\"display:inline-block;padding:10px 20px;background:#2d6fdc;color:#fff;text-decoration:none;border-radius:6px;font-weight:600;\">Track shipment</a></p>",
            html_escape_local(u),
        ),
        None => String::new(),
    };
    let mut item_rows = String::new();
    if let Some(items) = line_items.as_array() {
        for li in items {
            let qty = li.get("quantity").and_then(|v| v.as_i64()).unwrap_or(1);
            let desc = li.get("description").and_then(|v| v.as_str()).unwrap_or("(item)");
            item_rows.push_str(&format!(
                "<tr><td style=\"padding:6px 0;color:#5c6470;\">{} ×</td><td style=\"padding:6px 0;\">{}</td></tr>",
                qty, html_escape_local(desc),
            ));
        }
    }

    let html = format!(
        "<!doctype html><html><body style=\"margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#ffffff;color:#1a1d23;\">\
         <div style=\"max-width:560px;margin:0 auto;padding:32px 24px;\">\
           <h1 style=\"font-size:22px;margin:0 0 8px;\">Your order has shipped</h1>\
           <p style=\"color:#5c6470;margin:0 0 20px;\">Order #{id}</p>\
           <table style=\"width:100%;border-collapse:collapse;font-size:13px;\">\
             <tr><td style=\"padding:4px 0;color:#5c6470;width:120px;\">Carrier:</td><td style=\"padding:4px 0;font-weight:600;\">{carrier_html}</td></tr>\
             <tr><td style=\"padding:4px 0;color:#5c6470;\">Tracking:</td><td style=\"padding:4px 0;font-family:monospace;\">{tracking_html}</td></tr>\
           </table>\
           {track_btn}\
           {items_block}\
           <p style=\"color:#5c6470;font-size:13px;margin-top:32px;\">Thanks for buying from Xikaku!<br>— The Xikaku team</p>\
         </div></body></html>",
        id = id,
        carrier_html = html_escape_local(carrier),
        tracking_html = html_escape_local(tracking),
        track_btn = track_btn,
        items_block = if item_rows.is_empty() {
            String::new()
        } else {
            format!(
                "<h3 style=\"font-size:14px;margin:24px 0 8px;\">Items shipped</h3>\
                 <table style=\"width:100%;border-collapse:collapse;font-size:13px;\">{}</table>",
                item_rows,
            )
        },
    );
    (text, html)
}

fn html_escape_local(s: &str) -> String {
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

// ---------------------------------------------------------------------------
// Settings admin (JWT)
// ---------------------------------------------------------------------------

const KNOWN_SETTING_KEYS: &[&str] = &[
    SETTING_NOTIFY_EMAILS,
    SETTING_CUSTOMER_EMAIL_ENABLED,
    SETTING_CUSTOMER_THANK_YOU,
    SETTING_SUPPORT_CONTACT,
];

pub async fn handle_admin_get_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_password_changed(&state, &p)?;
    require_admin(&state, &p)?;
    let pairs = {
        let db = state.db.lock().unwrap();
        db.list_shop_settings().map_err(db_err)?
    };
    let mut out = serde_json::Map::new();
    for k in KNOWN_SETTING_KEYS {
        out.insert((*k).to_string(), Value::String(String::new()));
    }
    for (k, v) in pairs {
        out.insert(k, Value::String(v));
    }
    // Also surface the env-var fallback so the UI can hint at the
    // bootstrap default when notification_emails is unset.
    out.insert(
        "notification_emails_fallback".into(),
        Value::String(state.shop_notify_addr.clone()),
    );
    Ok(Json(Value::Object(out)))
}

#[derive(Deserialize)]
pub struct UpdateSettingsRequest {
    #[serde(flatten)]
    pub fields: std::collections::HashMap<String, String>,
}

pub async fn handle_admin_put_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<UpdateSettingsRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_password_changed(&state, &p)?;
    require_admin(&state, &p)?;

    // Normalize known fields before storing.
    for (k, v) in &req.fields {
        if !KNOWN_SETTING_KEYS.contains(&k.as_str()) {
            return Err(error_response(StatusCode::BAD_REQUEST, &format!("Unknown setting: {}", k)));
        }
        let normalized = match k.as_str() {
            SETTING_NOTIFY_EMAILS => {
                // Validate each address contains '@' but otherwise leave intact;
                // join with comma+space for canonical storage.
                let parts = split_recipients(v);
                if !v.trim().is_empty() && parts.is_empty() {
                    return Err(error_response(StatusCode::BAD_REQUEST, "No valid email addresses found"));
                }
                parts.join(", ")
            }
            SETTING_CUSTOMER_EMAIL_ENABLED => {
                match v.as_str() {
                    "1" | "0" | "true" | "false" | "" => v.clone(),
                    _ => return Err(error_response(StatusCode::BAD_REQUEST, "customer_email_enabled must be 0 or 1")),
                }
            }
            SETTING_SUPPORT_CONTACT => v.trim().to_string(),
            _ => v.clone(),
        };
        let db = state.db.lock().unwrap();
        db.set_shop_setting(k, &normalized).map_err(db_err)?;
    }
    Ok(Json(json!({ "status": "OK" })))
}

// ---------------------------------------------------------------------------
// Public shop HTML shell
//
// /shop URLs reuse the same single-page-app shell as the public website so
// that header / sidebar / cart drawer stay consistent. The SPA's `route()`
// detects a `/shop` path and renders product views into the content area.
// ---------------------------------------------------------------------------

const WEBSITE_HTML: &str = include_str!("website.html");

pub async fn handle_shop_page() -> axum::response::Html<String> {
    let head = "<title>Shop — Xikaku</title>\n\
                <meta name=\"description\" content=\"Order Xikaku IMU and inertial sensors directly. Shipped from our Los Angeles office.\">\n\
                <meta property=\"og:title\" content=\"Shop — Xikaku\">\n\
                <meta property=\"og:type\" content=\"website\">\n";
    let html = WEBSITE_HTML.replacen("<!--SEO_HEAD-->", head, 1);
    axum::response::Html(html)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_form_flat() {
        let mut f = Vec::new();
        push_form(&mut f, &["mode"], "payment");
        assert_eq!(f, vec![("mode".into(), "payment".into())]);
    }

    #[test]
    fn push_form_nested() {
        let mut f = Vec::new();
        push_form(&mut f, &["line_items", "0", "price_data", "currency"], "usd");
        assert_eq!(f, vec![("line_items[0][price_data][currency]".into(), "usd".into())]);
    }

    #[test]
    fn signature_header_parse() {
        let (t, v) = parse_stripe_signature_header("t=1492774577,v1=abc123,v0=old");
        assert_eq!(t, Some(1492774577));
        assert_eq!(v, vec!["abc123".to_string()]);
    }

    #[test]
    fn signature_verify_roundtrip() {
        let secret = "whsec_test";
        let payload = br#"{"id":"evt_1","type":"checkout.session.completed"}"#;
        let ts = 1_700_000_000i64;
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(ts.to_string().as_bytes());
        mac.update(b".");
        mac.update(payload);
        let sig = hex::encode(mac.finalize().into_bytes());
        let header = format!("t={},v1={}", ts, sig);
        verify_stripe_signature(secret, &header, payload, ts).unwrap();
    }

    #[test]
    fn signature_verify_rejects_stale() {
        let secret = "whsec_test";
        let payload = b"{}";
        let ts = 1_700_000_000i64;
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(ts.to_string().as_bytes());
        mac.update(b".");
        mac.update(payload);
        let sig = hex::encode(mac.finalize().into_bytes());
        let header = format!("t={},v1={}", ts, sig);
        // 10 min later — outside 5 min tolerance.
        assert!(verify_stripe_signature(secret, &header, payload, ts + 600).is_err());
    }

    #[test]
    fn signature_verify_rejects_bad_sig() {
        let header = "t=1700000000,v1=deadbeef";
        assert!(verify_stripe_signature("whsec_test", header, b"{}", 1_700_000_000).is_err());
    }

    #[test]
    fn rate_applies_wildcard() {
        assert!(rate_applies(&["*".into()], "US"));
        assert!(rate_applies(&["US".into(), "CA".into()], "us"));
        assert!(!rate_applies(&["US".into()], "GB"));
    }
}
