//! Shop endpoints - Stripe-backed checkout for physical goods.
//!
//! - Public: list products, get product, create checkout session, webhook.
//! - Admin (JWT): CRUD for products + shipping rates.
//!
//! The cart lives entirely in the browser (localStorage). The checkout
//! endpoint accepts `[{sku, qty}]` + destination_country, looks up authoritative
//! prices from the DB, picks applicable shipping rates, and hands the cart to
//! Stripe Checkout with `automatic_tax: true`. Stripe collects address +
//! payment, computes tax, and redirects to success_url / cancel_url.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock, Mutex};

use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    Json,
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;
use susi_core::error::LicenseError;

use crate::countries;
use crate::email::{EmailAttachment, InlineImage};
use crate::invoice_pdf;
use crate::sites::{self, SiteConfig, DEFAULT_SITE_ID};
use crate::website::{resolve_site, SiteQuery};
use crate::{
    check_checkout_rate_limit, check_webhook_rate_limit, client_ip, error_response,
    require_admin_full, validate_principal, AppState, ErrorResponse,
};

/// Brand logo embedded in the binary so it ships with every customer email
/// without depending on remote-image fetches (most clients block those).
/// Wide horizontal logo; constrain via CSS height in the HTML.
const LOGO_CID: &str = "shop-logo";

// One `Arc<[u8]>` per site logo. Each `logo_inline_image()` call then bumps
// the refcount instead of copying ~30 KB of bytes per email.
static LOGO_ARCS: LazyLock<Mutex<HashMap<String, Arc<[u8]>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn site_logo_png(site: &SiteConfig) -> &'static [u8] {
    sites::compiled_brand(site.id)
        .map(|b| b.logo)
        .unwrap_or(sites::compiled_brand(DEFAULT_SITE_ID).expect("default brand").logo)
}

fn logo_inline_image(site: &SiteConfig) -> InlineImage {
    let bytes = {
        let mut m = LOGO_ARCS.lock().unwrap();
        Arc::clone(m.entry(site.id.to_string()).or_insert_with(|| Arc::from(site_logo_png(site))))
    };
    InlineImage {
        content_id: LOGO_CID.into(),
        mime_type: "image/png".into(),
        bytes,
    }
}

/// Per-site Stripe credentials. The default site keeps the classic
/// STRIPE_SECRET_KEY / STRIPE_WEBHOOK_SECRET config; every other site reads
/// STRIPE_SECRET_KEY_{SITE} / STRIPE_WEBHOOK_SECRET_{SITE} from the
/// environment (site id uppercased, '-' becoming '_'). Empty = shop disabled
/// for checkout on that site.
fn stripe_env(site_id: &str, base: &str) -> String {
    let suffix = site_id.to_uppercase().replace('-', "_");
    std::env::var(format!("{}_{}", base, suffix)).unwrap_or_default()
}

fn stripe_secret_for(state: &AppState, site: &SiteConfig) -> String {
    if site.id == DEFAULT_SITE_ID {
        state.stripe_secret_key.clone()
    } else {
        stripe_env(site.id, "STRIPE_SECRET_KEY")
    }
}

fn stripe_webhook_secret_for(state: &AppState, site: &SiteConfig) -> String {
    if site.id == DEFAULT_SITE_ID {
        state.stripe_webhook_secret.clone()
    } else {
        stripe_env(site.id, "STRIPE_WEBHOOK_SECRET")
    }
}

/// Shop settings share one table across sites: the default site keeps its
/// bare keys (stored data predates multi-shop), other sites use
/// '{site}/{key}' - the same convention as site_settings.
fn shop_setting_key(site: &SiteConfig, key: &str) -> String {
    if site.id == DEFAULT_SITE_ID {
        key.to_string()
    } else {
        format!("{}/{}", site.id, key)
    }
}

fn require_shop(site: &SiteConfig) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if !site.has_shop {
        return Err(error_response(StatusCode::NOT_FOUND, "This site has no shop"));
    }
    Ok(())
}

/// Where Stripe sends the customer back to. The default site keeps the
/// configured shop_base_url; other sites return to the requesting host when
/// it belongs to the site (so staging checkouts land on staging), and the
/// canonical base otherwise.
fn shop_base_for(state: &AppState, site: &SiteConfig, headers: &HeaderMap) -> String {
    if site.id == DEFAULT_SITE_ID {
        return state.shop_base_url.clone();
    }
    if let Some(host) = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or("").to_string())
    {
        if site.hosts.iter().any(|h| *h == host) {
            return format!("https://{}", host);
        }
    }
    site.public_base.trim_end_matches('/').to_string()
}

type HmacSha256 = Hmac<Sha256>;

const STRIPE_API_BASE: &str = "https://api.stripe.com/v1";
// Reject webhook events whose signed timestamp drifts more than this far from
// `now`. 5 minutes matches Stripe's own CLI default and covers NTP skew.
const WEBHOOK_TOLERANCE_SECS: i64 = 300;

fn db_err(e: LicenseError) -> (StatusCode, Json<ErrorResponse>) {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())
}

fn shop_configured(state: &AppState, site: &SiteConfig) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if stripe_secret_for(state, site).is_empty() {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Shop checkout is not configured on this server",
        ));
    }
    Ok(())
}

fn product_to_json(row: susi_core::db::ShopProductRow) -> Value {
    let (sku, title, description_md, price_cents, currency, image_asset, tax_code, active, ord, updated_at, title_ja, description_md_ja, price_jpy) = row;
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
        "title_ja": title_ja,
        "description_md_ja": description_md_ja,
        "price_jpy": price_jpy,
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
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    require_shop(site)?;
    let rows = {
        let db = state.db.lock();
        db.list_products(site.id, true).map_err(db_err)?
    };
    let products: Vec<Value> = rows.into_iter().map(product_to_json).collect();
    Ok(Json(json!({ "products": products })))
}

pub async fn handle_get_product(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Path(sku): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    require_shop(site)?;
    let row = {
        let db = state.db.lock();
        db.get_product(site.id, &sku).map_err(db_err)?
    }
    .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Product not found"))?;
    if !row.7 {
        return Err(error_response(StatusCode::NOT_FOUND, "Product not found"));
    }
    Ok(Json(product_to_json(row)))
}

/// Destinations the shop currently serves, for the public country selector.
/// Ordered by display name so the dropdown reads naturally.
pub async fn handle_list_shipping_countries(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let mut list: Vec<Value> = enabled_shipping_countries(&state, site)
        .into_iter()
        .map(|code| {
            let name = countries::name(&code).unwrap_or("");
            json!({ "code": code, "name": name })
        })
        .collect();
    list.sort_by(|a, b| a["name"].as_str().unwrap_or("").cmp(b["name"].as_str().unwrap_or("")));
    Ok(Json(json!({ "countries": list })))
}

/// Full catalogue of shippable destinations, for the admin picker.
pub async fn handle_admin_list_countries(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    let mut list: Vec<(&str, &str)> = countries::SHIPPING_COUNTRIES.to_vec();
    list.sort_by_key(|(_, name)| *name);
    let out: Vec<Value> = list
        .into_iter()
        .map(|(code, name)| json!({ "code": code, "name": name }))
        .collect();
    Ok(Json(json!({ "countries": out })))
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
    // "jpy" charges each item's price_jpy (Japanese storefront); anything
    // else charges the base price in the product's own currency.
    #[serde(default)]
    pub currency: String,
}

/// Whole-unit currencies: Stripe amounts are NOT in hundredths for these.
fn zero_decimal(currency: &str) -> bool {
    currency.eq_ignore_ascii_case("jpy")
}

/// Region match - `*` is a wildcard for "any country".
fn rate_applies(regions: &[String], country: &str) -> bool {
    regions.iter().any(|r| r == "*" || r.eq_ignore_ascii_case(country))
}

/// Collect the union of allowed countries across all active rates. Stripe
/// requires 2-letter ISO codes; if a rate declares `*`, we expand it to the
/// shop's enabled destinations. A rate naming a country that is no longer
/// enabled contributes nothing.
fn allowed_countries_for_checkout(
    rates: &[(i64, String, i64, String, Option<i64>, Option<i64>, String, bool, i64)],
    enabled: &[String],
) -> Vec<String> {
    let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut wildcard = false;
    for r in rates {
        let regions: Vec<String> = serde_json::from_str(&r.6).unwrap_or_default();
        for reg in regions {
            if reg == "*" { wildcard = true; }
            else {
                let up = reg.to_uppercase();
                if enabled.contains(&up) { set.insert(up); }
            }
        }
    }
    if wildcard {
        for c in enabled { set.insert(c.clone()); }
    }
    set.into_iter().collect()
}

/// Destinations the shop serves before the admin has ever saved the setting.
const DEFAULT_SHIPPING_COUNTRIES: &[&str] = &["US", "CA"];

/// Parse the stored `shipping_countries` setting into canonical uppercase
/// codes, dropping anything Stripe won't accept. Falls back to the default
/// when unset or empty.
fn parse_shipping_countries(raw: &str) -> Vec<String> {
    let list: Vec<String> = raw
        .split(',')
        .map(|s| s.trim().to_uppercase())
        .filter(|s| countries::is_supported(s))
        .collect();
    if list.is_empty() {
        return DEFAULT_SHIPPING_COUNTRIES.iter().map(|c| (*c).to_string()).collect();
    }
    let mut list = list;
    list.sort();
    list.dedup();
    list
}

fn enabled_shipping_countries(state: &AppState, site: &SiteConfig) -> Vec<String> {
    let raw = {
        let db = state.db.lock();
        db.get_shop_setting(&shop_setting_key(site, SETTING_SHIPPING_COUNTRIES))
            .ok()
            .flatten()
            .unwrap_or_default()
    };
    parse_shipping_countries(&raw)
}

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
    Query(sq): Query<SiteQuery>,
    Json(req): Json<CheckoutRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let ip = client_ip(peer, &headers);
    check_checkout_rate_limit(&state, ip)?;
    let site = resolve_site(&headers, &sq)?;
    require_shop(site)?;
    shop_configured(&state, site)?;

    if req.items.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Cart is empty"));
    }
    if req.items.len() > 100 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Too many items"));
    }
    // ISO-3166-1 alpha-2 country codes are 2 letters; allow empty (initial
    // page load before the country selector is rendered). Reject destinations
    // the admin has not enabled.
    let enabled = enabled_shipping_countries(&state, site);
    if !req.destination_country.is_empty() {
        if req.destination_country.len() != 2
            || !req.destination_country.chars().all(|c| c.is_ascii_alphabetic())
        {
            return Err(error_response(StatusCode::BAD_REQUEST, "Invalid destination country"));
        }
        let up = req.destination_country.to_uppercase();
        if !enabled.contains(&up) {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                &format!("We don't ship to {}", countries::name(&up).unwrap_or(up.as_str())),
            ));
        }
    }

    // Validate every cart item before touching the DB so a single bad SKU
    // doesn't make us pay for a query.
    for item in &req.items {
        if item.qty <= 0 || item.qty > 1000 {
            return Err(error_response(StatusCode::BAD_REQUEST, "Invalid quantity"));
        }
        // Mirror admin validate_sku - bound length and character set so a
        // pathological client can't waste a DB lookup with megabyte SKUs.
        if item.sku.is_empty()
            || item.sku.len() > 64
            || !item.sku.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(error_response(StatusCode::BAD_REQUEST, "Invalid SKU"));
        }
    }

    // Single batch lookup instead of one round-trip per cart line. Releases
    // the DB lock before the Stripe HTTP call below - that call is 100-500 ms
    // and previously held every other handler off the connection.
    let skus: Vec<String> = req.items.iter().map(|i| i.sku.clone()).collect();
    let products = {
        let db = state.db.lock();
        db.get_products_by_skus(site.id, &skus).map_err(db_err)?
    };

    // Look up each SKU, never trust client-supplied price. The client only
    // picks the currency ("jpy" on the Japanese storefront); prices always
    // come from the DB. Line items keep the English title - Stripe's checkout
    // chrome localizes via `locale`, and the invoice PDF's built-in fonts
    // cannot render Japanese.
    let want_jpy = req.currency.eq_ignore_ascii_case("jpy");
    let mut resolved: Vec<(String, String, i64, String, String, i64)> = Vec::with_capacity(req.items.len()); // sku, title, amount, currency, tax_code, qty
    let mut cart_currency: Option<String> = None;
    for item in &req.items {
        let row = products
            .get(&item.sku)
            .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, &format!("Unknown SKU: {}", item.sku)))?;
        let (sku, title, _desc, price_cents, currency, _img, tax_code, active, _ord, _upd, _tja, _dja, price_jpy) = row;
        if !*active {
            return Err(error_response(StatusCode::BAD_REQUEST, &format!("Product is unavailable: {}", sku)));
        }
        let (amount, cur) = if want_jpy {
            if *price_jpy <= 0 {
                return Err(error_response(
                    StatusCode::BAD_REQUEST,
                    &format!("Not available in JPY: {}", sku),
                ));
            }
            // price_jpy is whole yen; JPY is zero-decimal, so it goes to
            // Stripe as-is.
            (*price_jpy, "jpy".to_string())
        } else {
            (*price_cents, currency.clone())
        };
        match &cart_currency {
            None => cart_currency = Some(cur.clone()),
            Some(c) if c.eq_ignore_ascii_case(&cur) => {}
            Some(c) => return Err(error_response(
                StatusCode::BAD_REQUEST,
                &format!("Mixed currencies in cart: {} vs {}", c, cur),
            )),
        }
        resolved.push((sku.clone(), title.clone(), amount, cur, tax_code.clone(), item.qty));
    }
    let cart_currency = cart_currency.unwrap_or_else(|| "usd".to_string());

    // Pick applicable shipping rates. If destination_country is empty (first
    // load), pass all active rates and let Stripe's address step handle it;
    // the currency must still match.
    let active_rates = {
        let db = state.db.lock();
        db.list_shipping_rates(site.id, true).map_err(db_err)?
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
    // Stamp the owning site so the order stays attributable in the Stripe
    // dashboard even across exports.
    form.push(("metadata[site]".into(), site.id.to_string()));
    // A translated storefront localizes the Stripe checkout chrome too.
    let lang = crate::website::resolve_lang(site, &sq);
    if !lang.is_empty() {
        form.push(("locale".into(), lang.clone()));
        form.push(("metadata[lang]".into(), lang.clone()));
    }

    // Return the customer to the storefront in the language they bought in.
    let base = shop_base_for(&state, site, &headers);
    let lang_seg = if lang.is_empty() { String::new() } else { format!("/{}", lang) };
    let success = format!("{}{}/shop/success?session_id={{CHECKOUT_SESSION_ID}}", base.trim_end_matches('/'), lang_seg);
    let cancel = format!("{}{}/shop/cancel", base.trim_end_matches('/'), lang_seg);
    form.push(("success_url".into(), success));
    form.push(("cancel_url".into(), cancel));

    form.push(("automatic_tax[enabled]".into(), "true".into()));
    // Always collect a billing address so receipts / invoices have one,
    // and so we can show it separately from the shipping address.
    form.push(("billing_address_collection".into(), "required".into()));
    // Require phone number - needed by carriers for shipping.
    form.push(("phone_number_collection[enabled]".into(), "true".into()));
    // Tell Stripe to generate a hosted invoice + PDF for every paid session.
    // The webhook event then references the invoice id, which we fetch and
    // attach to the customer email.
    form.push(("invoice_creation[enabled]".into(), "true".into()));
    form.push((
        "invoice_creation[invoice_data][description]".into(),
        format!("Thanks for your order from {}.", site.name),
    ));
    form.push((
        "invoice_creation[invoice_data][footer]".into(),
        format!(
            "{} - {}, {}. Questions? {}",
            site.org_legal_name, site.addr_locality, site.addr_country, site.contact_email,
        ),
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
    let allowed = if applicable.is_empty() {
        enabled.clone()
    } else {
        allowed_countries_for_checkout(&applicable, &enabled)
    };
    // Every rate could name only countries that were since disabled; fall back
    // so Stripe never sees an empty allowed_countries array.
    let allowed = if allowed.is_empty() { enabled.clone() } else { allowed };
    for (i, c) in allowed.iter().enumerate() {
        push_form(&mut form, &["shipping_address_collection", "allowed_countries", &i.to_string()], c.clone());
    }

    // Call Stripe.
    let resp = state
        .http
        .post(format!("{}/checkout/sessions", STRIPE_API_BASE))
        .basic_auth(stripe_secret_for(&state, site), Some(""))
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
        log::error!("Stripe checkout.sessions create failed: {} - {}", status, body);
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
// owner. No DB writes - Stripe is the source of truth for orders.
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
    let sig = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, "Missing Stripe-Signature"))?;

    // Each site's shop runs on its own Stripe account, and every account
    // posts to this one endpoint. The signing secret that verifies the
    // payload identifies the site the event belongs to.
    let now = chrono::Utc::now().timestamp();
    let mut any_secret = false;
    let mut matched: Option<&'static SiteConfig> = None;
    for site in sites::all_sites() {
        let secret = stripe_webhook_secret_for(&state, site);
        if secret.is_empty() {
            continue;
        }
        any_secret = true;
        if verify_stripe_signature(&secret, sig, &body, now).is_ok() {
            matched = Some(site);
            break;
        }
    }
    if !any_secret {
        return Err(error_response(StatusCode::SERVICE_UNAVAILABLE, "Webhook not configured"));
    }
    let site = matched.ok_or_else(|| {
        log::warn!("Stripe webhook signature verify failed for every configured site");
        error_response(StatusCode::BAD_REQUEST, "Invalid signature")
    })?;

    let event: Value = serde_json::from_slice(&body)
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("Bad JSON: {}", e)))?;
    let event_type = event.get("type").and_then(|v| v.as_str()).unwrap_or("");
    log::info!("Stripe webhook received: {}", event_type);
    // The storefront language the order was placed in (checkout stamps it).
    let meta_lang = event
        .pointer("/data/object/metadata/lang")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let lang = order_email_lang(site, meta_lang).to_string();

    match event_type {
        "checkout.session.completed" => {
            // Persist a shadow-row in shop_orders so we can drive fulfillment
            // from the admin UI without a round-trip to Stripe for every list.
            // Only sessions whose payment actually settled are recorded as
            // 'paid': delayed methods (ACH/SEPA/BNPL) complete the session
            // with payment_status='unpaid' and settle later via
            // checkout.session.async_payment_succeeded.
            let payment_status = event
                .pointer("/data/object/payment_status")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let settled = matches!(payment_status, "paid" | "no_payment_required");
            let status = if settled { "paid" } else { "pending_payment" };
            let persisted = persist_order_from_event(&state, site, &lang, &event, status).await;
            if !settled {
                log::info!(
                    "Checkout session completed with payment_status={} - order recorded as pending_payment, awaiting settlement",
                    payment_status
                );
                return Ok(Json(json!({ "received": true, "pending": true })));
            }
            // `inserted == false` means a previous delivery already created
            // the order - Stripe is retrying. Skip emails so the customer
            // doesn't get a duplicate confirmation.
            let order_id = persisted.map(|(id, _)| id);
            let is_new_order = persisted.map(|(_, ins)| ins).unwrap_or(false);
            if !is_new_order {
                log::info!("Stripe webhook retry for already-recorded session - skipping emails");
                return Ok(Json(json!({ "received": true, "duplicate": true })));
            }
            send_order_notifications(&state, site, &lang, &event, order_id).await;
        }
        "checkout.session.async_payment_succeeded" => {
            // A delayed payment settled. The conditional pending->paid
            // transition makes the email side effects run exactly once across
            // retries; insert-if-absent first covers a session whose
            // completed event was never delivered.
            let persisted = persist_order_from_event(&state, site, &lang, &event, "paid").await;
            let order_id = persisted.map(|(id, _)| id);
            let inserted = persisted.map(|(_, ins)| ins).unwrap_or(false);
            let session_id = event
                .pointer("/data/object/id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let flipped = {
                let db = state.db.lock();
                db.transition_order_status_by_session(session_id, "pending_payment", "paid")
                    .unwrap_or(false)
            };
            if inserted || flipped {
                send_order_notifications(&state, site, &lang, &event, order_id).await;
            } else {
                log::info!("async_payment_succeeded retry for already-paid session - skipping emails");
            }
        }
        "checkout.session.async_payment_failed" => {
            let session_id = event
                .pointer("/data/object/id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let failed = {
                let db = state.db.lock();
                db.transition_order_status_by_session(session_id, "pending_payment", "payment_failed")
                    .unwrap_or(false)
            };
            if failed {
                log::warn!(
                    "Delayed payment failed for session {} - order marked payment_failed",
                    session_id
                );
            }
        }
        _ => {}
    }

    Ok(Json(json!({ "received": true })))
}

/// Fetch line items + invoice and send the admin notification and customer
/// confirmation for a settled order. Callers must guarantee at-most-once
/// delivery (fresh insert or a conditional status transition).
async fn send_order_notifications(
    state: &Arc<AppState>,
    site: &'static SiteConfig,
    lang: &str,
    event: &Value,
    order_id: Option<i64>,
) {
    {
        // Fetch line items + invoice PDF in parallel - both via Stripe API,
        // both best-effort (we still send emails even if one is unavailable).
        let secret = stripe_secret_for(state, site);
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
                if session_id.is_empty() { Vec::new() } else { fetch_line_items(&state, &secret, &session_id).await }
            };
            let inv_fut = async {
                if invoice_id.is_empty() {
                    (Value::Null, String::new())
                } else {
                    // We need the Stripe invoice for its number + creation
                    // timestamp, but we render the PDF ourselves below - see
                    // invoice_pdf::generate for why.
                    let inv = fetch_invoice(&state, &secret, &invoice_id).await;
                    let number = inv.get("number").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    (inv, number)
                }
            };
            let (li, (inv, num)) = tokio::join!(li_fut, inv_fut);
            (li, inv, num)
        };

        // Render our own paid-invoice PDF. Stripe's PDF for Checkout-paid
        // invoices is rendered once at finalization (status=open) and never
        // refreshed, so it always carries a "Pay online" CTA - useless for
        // a post-payment receipt.
        let (from_name, from_lines) = invoice_from(state, site);
        let fallback_number = order_id
            .map(|i| format!("{}-{:04}", invoice_prefix(site), i))
            .unwrap_or_else(|| "-".into());
        let pdf_bytes = match invoice_pdf::generate(
            &from_name,
            &from_lines,
            site_logo_png(site),
            &fallback_number,
            &event,
            &line_items,
            &invoice_obj,
        ) {
            Ok(b) => b,
            Err(e) => { log::error!("invoice PDF generation failed: {}", e); Vec::new() }
        };

        let pdf_attachment: Option<EmailAttachment> = if pdf_bytes.is_empty() {
            None
        } else {
            let fname = if invoice_number.is_empty() {
                format!("invoice-{}-{}.pdf", site.id, order_id.map(|i| i.to_string()).unwrap_or_else(|| "order".into()))
            } else {
                format!("invoice-{}.pdf", invoice_number)
            };
            Some(EmailAttachment {
                file_name: fname,
                mime_type: "application/pdf".into(),
                bytes: Arc::<[u8]>::from(pdf_bytes.into_boxed_slice()),
            })
        };

        let sender = format!("{} Shop", site.name);

        // ----- Admin notification (one or more recipients) -----
        let admin_recipients = effective_admin_recipients(&state, site);
        if let Some(svc) = &state.email {
            if !admin_recipients.is_empty() {
                let summary = format_order_summary(&event, &line_items, order_id);
                let subject = format!("[{}] New order - {}", site.name, summary.0);
                let body = summary.1;
                for to in admin_recipients {
                    let svc = svc.clone();
                    let to = to.clone();
                    let subject = subject.clone();
                    let body = body.clone();
                    let sender = sender.clone();
                    // Refcount-bump clone - `bytes: Arc<[u8]>`, no PDF copy.
                    let attach = pdf_attachment.as_ref().map(|a| EmailAttachment {
                        file_name: a.file_name.clone(),
                        mime_type: a.mime_type.clone(),
                        bytes: Arc::clone(&a.bytes),
                    });
                    tokio::spawn(async move {
                        let attachments: Vec<EmailAttachment> = attach.into_iter().collect();
                        // Wrap the plain text in <pre> so the HTML alternative
                        // preserves newlines and the column alignment.
                        let html = format!(
                            "<pre style=\"font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;white-space:pre-wrap;margin:0;\">{}</pre>",
                            html_escape_local(&body),
                        );
                        let res = svc.send_html_rich(&to, &subject, &body, &html, &[], &attachments, Some(&sender)).await;
                        if let Err(e) = res {
                            log::error!("Failed to send admin notification to {}: {}", to, e);
                        }
                    });
                }
            }
        }

        // ----- Customer order confirmation -----
        if customer_email_enabled(&state, site) {
            let customer_email = event
                .pointer("/data/object/customer_details/email")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if let Some(svc) = state.email.clone() {
                if !customer_email.is_empty() {
                    let (subject, md) =
                        build_customer_confirmation(&state, site, &event, &line_items, order_id, lang);
                    let doc = crate::email_md::render(&md, Some((LOGO_CID, site.name)));
                    let inline = vec![logo_inline_image(site)];
                    let attachments: Vec<EmailAttachment> = pdf_attachment.into_iter().collect();
                    tokio::spawn(async move {
                        let res = svc.send_html_rich(&customer_email, &subject, &doc.text, &doc.html, &inline, &attachments, Some(&sender)).await;
                        if let Err(e) = res {
                            log::error!("Failed to send customer confirmation to {}: {}", customer_email, e);
                        }
                    });
                }
            }
        }
    }
}

/// The invoice "From" block: the per-shop `invoice_from` setting (first line
/// company name, rest address lines) or a per-site default.
fn invoice_from(state: &AppState, site: &SiteConfig) -> (String, Vec<String>) {
    let raw = get_setting_str(state, site, SETTING_INVOICE_FROM);
    let mut lines: Vec<String> = raw
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    if lines.is_empty() {
        if site.id == DEFAULT_SITE_ID {
            return (
                "Xikaku, Inc.".into(),
                [
                    "4136 Del Rey Ave",
                    "Marina Del Rey, California 90292",
                    "United States",
                    "+1 310-916-4636",
                    "info@xikaku.com",
                ]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            );
        }
        return (
            site.org_legal_name.to_string(),
            vec![
                format!("{}, {}", site.addr_locality, site.addr_country),
                site.contact_email.to_string(),
            ],
        );
    }
    let name = lines.remove(0);
    (name, lines)
}

/// Prefix for locally generated invoice numbers when Stripe's is unavailable.
fn invoice_prefix(site: &SiteConfig) -> String {
    if site.id == DEFAULT_SITE_ID {
        "XK".into()
    } else {
        site.id.to_uppercase().replace('-', "")
    }
}

// ---------------------------------------------------------------------------
// Settings - well-known keys and lookup helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Email templates
//
// The customer-facing shop emails are markdown templates (email_md): a
// per-shop override lives in shop_settings (email_order_confirmation[_ja],
// email_order_shipped[_ja]); an empty override falls back to the built-in
// default below. Variables are {name} tokens; a line whose variable resolves
// empty is dropped (email_md::apply_template).
// ---------------------------------------------------------------------------

const SETTING_TPL_CONFIRMATION: &str = "email_order_confirmation";
const SETTING_TPL_CONFIRMATION_JA: &str = "email_order_confirmation_ja";
const SETTING_TPL_SHIPPED: &str = "email_order_shipped";
const SETTING_TPL_SHIPPED_JA: &str = "email_order_shipped_ja";

const VARS_CONFIRMATION: &[&str] = &["order", "date", "name", "site", "items", "totals", "addresses", "shipping_note", "support"];
const VARS_SHIPPED: &[&str] = &["order", "name", "site", "shipment", "tracking_button", "items", "total"];

const TPL_CONFIRMATION_EN: &str = "# Thank you for your order\n\nOrder {order} · {date}\n\nHi {name},\n\nThanks for your purchase from {site} - we've received your order and are getting it ready.\n\n## Items\n\n{items}\n\n{totals}\n\n{addresses}\n\nA PDF invoice is attached to this email for your records.\n\n{shipping_note}\n\nQuestions? Reach us at [{support}](mailto:{support}).\n\n\\- The {site} team\n";

const TPL_CONFIRMATION_JA: &str = "# ご注文ありがとうございます\n\nご注文 {order} · {date}\n\n{name} 様\n\n{site}をご利用いただきありがとうございます。ご注文を承りました。\n\n## ご注文内容\n\n{items}\n\n{totals}\n\n{addresses}\n\n請求書（PDF）をこのメールに添付しています。\n\n{shipping_note}\n\nご不明な点は [{support}](mailto:{support}) までお問い合わせください。\n\n\\- {site}チーム\n";

const TPL_SHIPPED_EN: &str = "# Your order has shipped\n\nOrder {order}\n\nHi {name},\n\n{shipment}\n\n{tracking_button}\n\n## Items shipped\n\n{items}\n\nOrder total: {total}\n\nThanks for buying from {site}!\n\n\\- The {site} team\n";

const TPL_SHIPPED_JA: &str = "# 商品を発送しました\n\nご注文 {order}\n\n{name} 様\n\n{shipment}\n\n{tracking_button}\n\n## 発送した商品\n\n{items}\n\nご注文合計: {total}\n\n{site}をご利用いただきありがとうございます！\n\n\\- {site}チーム\n";

/// Chrome strings the template variables carry, localized per order language.
fn tr(lang: &str, en: &'static str) -> &'static str {
    if lang != "ja" {
        return en;
    }
    match en {
        "Subtotal" => "小計",
        "Shipping" => "送料",
        "Tax" => "税金",
        "Total" => "合計",
        "Ship to" => "お届け先",
        "Bill to" => "請求先",
        "Carrier" => "配送業者",
        "Tracking" => "追跡番号",
        "Track shipment" => "荷物を追跡",
        "there" => "お客様",
        "(item details unavailable)" => "（商品明細を取得できませんでした）",
        _ => en,
    }
}

fn template_key(base: &str, lang: &str) -> &'static str {
    match (base, lang) {
        (SETTING_TPL_CONFIRMATION, "ja") => SETTING_TPL_CONFIRMATION_JA,
        (SETTING_TPL_CONFIRMATION, _) => SETTING_TPL_CONFIRMATION,
        (_, "ja") => SETTING_TPL_SHIPPED_JA,
        _ => SETTING_TPL_SHIPPED,
    }
}

fn default_template(base: &str, lang: &str) -> &'static str {
    match (base, lang) {
        (SETTING_TPL_CONFIRMATION, "ja") => TPL_CONFIRMATION_JA,
        (SETTING_TPL_CONFIRMATION, _) => TPL_CONFIRMATION_EN,
        (_, "ja") => TPL_SHIPPED_JA,
        _ => TPL_SHIPPED_EN,
    }
}

fn effective_template(state: &AppState, site: &SiteConfig, base: &str, lang: &str) -> String {
    let stored = get_setting_str(state, site, template_key(base, lang));
    if stored.trim().is_empty() {
        default_template(base, lang).to_string()
    } else {
        stored
    }
}

/// The language an order's emails are written in: one the site declares, or
/// the default.
fn order_email_lang<'a>(site: &SiteConfig, lang: &'a str) -> &'a str {
    if site.langs.iter().any(|l| *l == lang) {
        lang
    } else {
        ""
    }
}

fn shipping_note(site: &SiteConfig, lang: &str, has_preorder: bool) -> String {
    if lang == "ja" {
        if has_preorder {
            "ご注文には予約商品が含まれており、商品欄に記載の時期に発送予定です。発送が完了しましたら、追跡番号をお知らせするメールをお送りします。".into()
        } else {
            "ただいま発送の準備を進めています。発送が完了しましたら、追跡番号をお知らせするメールをお送りします。".into()
        }
    } else {
        let origin = if site.id == DEFAULT_SITE_ID { " from our Los Angeles office" } else { "" };
        if has_preorder {
            format!("Your order includes a pre-order item and will ship within the window shown next to the item. We'll send another email with your tracking number as soon as it ships{}.", origin)
        } else {
            format!("We're processing your order now. You'll get a second email with your tracking number once it ships{}.", origin)
        }
    }
}

fn confirmation_vars(
    state: &AppState,
    site: &SiteConfig,
    event: &Value,
    line_items: &[Value],
    order_id: Option<i64>,
    lang: &str,
) -> Vec<(&'static str, String)> {
    let obj = event.pointer("/data/object").cloned().unwrap_or(Value::Null);
    let name = obj.pointer("/customer_details/name").and_then(|v| v.as_str()).unwrap_or("");
    let amount_total = obj.get("amount_total").and_then(|v| v.as_i64()).unwrap_or(0);
    let amount_subtotal = obj.get("amount_subtotal").and_then(|v| v.as_i64()).unwrap_or(0);
    let currency = obj.get("currency").and_then(|v| v.as_str()).unwrap_or("usd");
    let total_details = obj.get("total_details").cloned().unwrap_or(Value::Null);
    let amount_shipping = total_details.get("amount_shipping").and_then(|v| v.as_i64()).unwrap_or(0);
    let amount_tax = total_details.get("amount_tax").and_then(|v| v.as_i64()).unwrap_or(0);
    let e = crate::email_md::escape;

    let mut items = String::from("|  |  |\n| --- | ---: |\n");
    if line_items.is_empty() {
        items.push_str(&format!("| {} |  |\n", tr(lang, "(item details unavailable)")));
    } else {
        for li in line_items {
            let qty = li.get("quantity").and_then(|v| v.as_i64()).unwrap_or(1);
            let desc = li.get("description").and_then(|v| v.as_str()).unwrap_or("(item)");
            let amt = li.get("amount_total").and_then(|v| v.as_i64()).unwrap_or(0);
            let cur = li.get("currency").and_then(|v| v.as_str()).unwrap_or(currency);
            items.push_str(&format!("| {} × {} | {} |\n", qty, e(desc), fmt_money(amt, cur)));
        }
    }

    let totals = format!(
        "|  |  |\n| --- | ---: |\n| {} | {} |\n| {} | {} |\n| {} | {} |\n| **{}** | **{}** |",
        tr(lang, "Subtotal"), fmt_money(amount_subtotal, currency),
        tr(lang, "Shipping"), fmt_money(amount_shipping, currency),
        tr(lang, "Tax"), fmt_money(amount_tax, currency),
        tr(lang, "Total"), fmt_money(amount_total, currency),
    );

    // Always show ship-to and bill-to (even when they match) so the customer
    // can verify both at a glance.
    let mut addresses = String::new();
    for (title, block) in [
        (tr(lang, "Ship to"), address_block_text(obj.get("shipping_details"), name)),
        (tr(lang, "Bill to"), address_block_text(obj.get("customer_details"), name)),
    ] {
        if !block.is_empty() {
            addresses.push_str(&format!("## {}\n\n", title));
            let lines: Vec<String> = block.lines().map(e).collect();
            addresses.push_str(&lines.join("\\\n"));
            addresses.push_str("\n\n");
        }
    }

    vec![
        ("order", order_id.map(|i| format!("#{}", i)).unwrap_or_else(|| "-".into())),
        ("date", chrono::Utc::now().format("%Y-%m-%d").to_string()),
        ("name", e(if name.is_empty() { tr(lang, "there") } else { name })),
        ("site", e(site.name)),
        ("items", items.trim_end().to_string()),
        ("totals", totals),
        ("addresses", addresses.trim_end().to_string()),
        ("shipping_note", shipping_note(site, lang, line_items_have_preorder(line_items))),
        ("support", get_setting_str(state, site, SETTING_SUPPORT_CONTACT)),
    ]
}

fn confirmation_subject(site: &SiteConfig, lang: &str, order_label: &str) -> String {
    if lang == "ja" {
        format!("ご注文ありがとうございます - {} {}", site.name, order_label)
    } else {
        format!("Thanks for your order - {} {}", site.name, order_label)
    }
}

const SETTING_NOTIFY_EMAILS: &str = "notification_emails";
const SETTING_CUSTOMER_EMAIL_ENABLED: &str = "customer_email_enabled";
const SETTING_SUPPORT_CONTACT: &str = "support_contact";
const SETTING_SHIPPING_COUNTRIES: &str = "shipping_countries";
const SETTING_INVOICE_FROM: &str = "invoice_from";

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

/// Resolve admin recipients: DB-stored setting wins; the default site also
/// falls back to the SUSI_SHOP_NOTIFY_ADDR env var (kept for back-compat with
/// the bootstrap install that hasn't visited the Settings tab yet).
fn effective_admin_recipients(state: &AppState, site: &SiteConfig) -> Vec<String> {
    let from_db = {
        let db = state.db.lock();
        db.get_shop_setting(&shop_setting_key(site, SETTING_NOTIFY_EMAILS))
            .ok()
            .flatten()
            .unwrap_or_default()
    };
    let mut list = split_recipients(&from_db);
    if list.is_empty() && site.id == DEFAULT_SITE_ID && !state.shop_notify_addr.is_empty() {
        list = split_recipients(&state.shop_notify_addr);
    }
    list
}

fn customer_email_enabled(state: &AppState, site: &SiteConfig) -> bool {
    let v = {
        let db = state.db.lock();
        db.get_shop_setting(&shop_setting_key(site, SETTING_CUSTOMER_EMAIL_ENABLED)).ok().flatten()
    };
    // Default ON when unset - most shops want customer confirmations.
    match v.as_deref() {
        Some("0") | Some("false") | Some("off") => false,
        _ => true,
    }
}

fn get_setting_str(state: &AppState, site: &SiteConfig, key: &str) -> String {
    let db = state.db.lock();
    db.get_shop_setting(&shop_setting_key(site, key)).ok().flatten().unwrap_or_default()
}

/// The customer order confirmation: the shop's template filled with this
/// order's variables, in the language the order was placed in.
fn build_customer_confirmation(
    state: &AppState,
    site: &SiteConfig,
    event: &Value,
    line_items: &[Value],
    order_id: Option<i64>,
    lang: &str,
) -> (String, String) {
    let order_label = order_id.map(|i| format!("#{}", i)).unwrap_or_else(|| "-".into());
    let subject = confirmation_subject(site, lang, &order_label);
    let vars = confirmation_vars(state, site, event, line_items, order_id, lang);
    let tpl = effective_template(state, site, SETTING_TPL_CONFIRMATION, lang);
    (subject, crate::email_md::apply_template(&tpl, &vars))
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

/// Fetch a Stripe Invoice object so we can extract its hosted PDF URL.
/// Returns Value::Null on any error so callers can degrade gracefully.
async fn fetch_invoice(state: &AppState, secret: &str, invoice_id: &str) -> Value {
    if secret.is_empty() || invoice_id.is_empty() {
        return Value::Null;
    }
    let url = format!("{}/invoices/{}", STRIPE_API_BASE, invoice_id);
    match state.http.get(url).basic_auth(secret, Some("")).send().await {
        Ok(resp) if resp.status().is_success() => match resp.text().await {
            Ok(b) => serde_json::from_str(&b).unwrap_or(Value::Null),
            Err(e) => { log::warn!("invoice fetch read body: {}", e); Value::Null }
        },
        Ok(resp) => { log::warn!("invoice fetch HTTP {}", resp.status()); Value::Null }
        Err(e) => { log::warn!("invoice fetch: {}", e); Value::Null }
    }
}

/// Pull line items from the Stripe API (the webhook payload doesn't include
/// them - Stripe explicitly omits expandable fields on webhook events).
async fn fetch_line_items(state: &AppState, secret: &str, session_id: &str) -> Vec<Value> {
    if secret.is_empty() { return Vec::new(); }
    let url = format!("{}/checkout/sessions/{}/line_items?limit=100", STRIPE_API_BASE, session_id);
    match state.http.get(url).basic_auth(secret, Some("")).send().await {
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

/// Persist a Stripe Checkout Session as a shop_orders row with the given
/// status ('paid' or 'pending_payment'). Returns `(local_order_id, inserted)`
/// on success - `inserted == false` means the row already existed (Stripe
/// retry) and side effects (emails) should be skipped. Returns `None` on any
/// error (still ack 200 so Stripe stops retrying after the first DB success).
async fn persist_order_from_event(
    state: &AppState,
    site: &SiteConfig,
    lang: &str,
    event: &Value,
    status: &str,
) -> Option<(i64, bool)> {
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

    let line_items = fetch_line_items(state, &stripe_secret_for(state, site), session_id).await;
    let line_items_json = serde_json::to_string(&line_items).unwrap_or_else(|_| "[]".into());

    let now = chrono::Utc::now().to_rfc3339();
    let res = {
        let db = state.db.lock();
        db.insert_order_if_absent(site.id, lang, session_id, &now, email, name, amount, currency, status, &ship_to_json, &line_items_json)
    };
    match res {
        Ok((id, inserted)) => Some((id, inserted)),
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
    let short = format!("{} - {}", fmt_money(amount_total, currency), display_name);

    let mut out = String::new();
    out.push_str(&format!("New order #{} from {} <{}>\n",
        order_id.map(|i| i.to_string()).unwrap_or_else(|| "-".into()),
        if !name.is_empty() { name } else { "(no name)" },
        email,
    ));
    if !phone.is_empty() {
        out.push_str(&format!("Phone:     {}\n", phone));
    }

    // Always render ship-to and bill-to as separate sections so the operator
    // sees both - even when they match - and can spot a mismatch instantly.
    let ship_text = address_block_text(obj.get("shipping_details"), name);
    let bill_text = address_block_text(obj.get("customer_details"), name);
    if ship_text.is_empty() && bill_text.is_empty() {
        out.push_str("\n(no address on session)\n");
    } else {
        if !ship_text.is_empty() {
            out.push_str("\n--- Ship to ---\n");
            out.push_str(&ship_text);
            out.push('\n');
        }
        if !bill_text.is_empty() {
            out.push_str("\n--- Bill to ---\n");
            out.push_str(&bill_text);
            out.push('\n');
        }
    }

    out.push_str("\n--- Items ---\n");
    if line_items.is_empty() {
        out.push_str("(line items unavailable - see Stripe dashboard)\n");
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
                out.push_str(&format!("  {} × {}  -  {}\n", qty, desc, fmt_money(amt, cur)));
            } else {
                out.push_str(&format!("  {} × {} ({})  -  {}\n", qty, desc, sku, fmt_money(amt, cur)));
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

fn thousands(n: i64) -> String {
    let neg = n < 0;
    let digits = n.unsigned_abs().to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3 + 1);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    if neg { format!("-{}", out) } else { out }
}

/// JPY amounts are whole yen (zero-decimal); everything else is hundredths.
fn fmt_money(amount: i64, currency: &str) -> String {
    if zero_decimal(currency) {
        return format!("¥{}", thousands(amount));
    }
    let whole = amount / 100;
    let frac = (amount.rem_euclid(100)).abs();
    format!("{}.{:02} {}", whole, frac, currency.to_uppercase())
}

/// True when any line item's title carries a "pre-order" tag. Pre-order
/// products declare themselves via their shop title, so the flag survives
/// the round-trip through Stripe without extra metadata.
fn line_items_have_preorder(line_items: &[Value]) -> bool {
    line_items.iter().any(|li| {
        li.get("description")
            .and_then(|v| v.as_str())
            .map(|d| d.to_ascii_lowercase().contains("pre-order"))
            .unwrap_or(false)
    })
}

// ---------------------------------------------------------------------------
// Admin endpoints (JWT)
// ---------------------------------------------------------------------------

pub async fn handle_admin_list_products(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    let rows = {
        let db = state.db.lock();
        db.list_products(site.id, false).map_err(db_err)?
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
    #[serde(default)]
    pub title_ja: String,
    #[serde(default)]
    pub description_md_ja: String,
    /// Whole yen; 0 = not offered in JPY (the ja storefront falls back to USD).
    #[serde(default)]
    pub price_jpy: i64,
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
    Query(sq): Query<SiteQuery>,
    Path(sku): Path<String>,
    Json(req): Json<UpsertProductRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    validate_sku(&sku)?;
    if req.title.trim().is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Title is required"));
    }
    if req.price_cents < 0 {
        return Err(error_response(StatusCode::BAD_REQUEST, "Price cannot be negative"));
    }
    {
        let db = state.db.lock();
        if let Some(asset) = req.image_asset.as_deref() {
            if !asset.is_empty() && !db.website_asset_exists(site.id, asset).map_err(db_err)? {
                return Err(error_response(
                    StatusCode::BAD_REQUEST,
                    &format!("Unknown image_asset: {}", asset),
                ));
            }
        }
        db.upsert_product(
            site.id,
            &sku,
            &req.title,
            &req.description_md,
            req.price_cents,
            &req.currency.to_lowercase(),
            req.image_asset.as_deref(),
            &req.tax_code,
            req.active,
            req.ord,
            &req.title_ja,
            &req.description_md_ja,
            req.price_jpy.max(0),
        )
        .map_err(db_err)?;
    }
    crate::website::invalidate_page_cache();
    crate::audit(&state, &p.username, "shop.product_upsert", &sku, site.id);
    Ok(Json(json!({ "sku": sku })))
}

pub async fn handle_delete_product(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Path(sku): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    validate_sku(&sku)?;
    let removed = {
        let db = state.db.lock();
        db.delete_product(site.id, &sku).map_err(db_err)?
    };
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Product not found"));
    }
    crate::website::invalidate_page_cache();
    crate::audit(&state, &p.username, "shop.product_delete", &sku, site.id);
    Ok(Json(json!({ "status": "OK" })))
}

pub async fn handle_list_shipping_rates_admin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    let rows = {
        let db = state.db.lock();
        db.list_shipping_rates(site.id, false).map_err(db_err)?
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

fn validate_rate_body(
    r: &ShippingRateRequest,
    enabled: &[String],
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
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
        if !enabled.contains(&up) {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                &format!("{} is not one of the shop's shipping countries", up),
            ));
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
    Query(sq): Query<SiteQuery>,
    Json(req): Json<ShippingRateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    let regions_json = validate_rate_body(&req, &enabled_shipping_countries(&state, site))?;
    let id = {
        let db = state.db.lock();
        db.insert_shipping_rate(
            site.id,
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
    Query(sq): Query<SiteQuery>,
    Path(id): Path<i64>,
    Json(req): Json<ShippingRateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    let regions_json = validate_rate_body(&req, &enabled_shipping_countries(&state, site))?;
    let ok = {
        let db = state.db.lock();
        db.update_shipping_rate(
            site.id,
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
    Query(sq): Query<SiteQuery>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    let removed = {
        let db = state.db.lock();
        db.delete_shipping_rate(site.id, id).map_err(db_err)?
    };
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Shipping rate not found"));
    }
    Ok(Json(json!({ "status": "OK" })))
}

// ---------------------------------------------------------------------------
// Orders admin (JWT)
// ---------------------------------------------------------------------------

/// Erasure (GDPR Art 17): delete an order row, e.g. on a customer request.
pub async fn handle_admin_delete_order(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    let removed = {
        let db = state.db.lock();
        let removed = db.delete_order(site.id, id).map_err(db_err)?;
        if removed {
            crate::audit_db(&db, &p.username, "shop.order_delete", &id.to_string(), "");
        }
        removed
    };
    if !removed {
        return Err(error_response(StatusCode::NOT_FOUND, "Order not found"));
    }
    Ok(Json(json!({ "status": "OK" })))
}

fn order_to_json(row: OrderRow) -> Value {
    let (id, sid, created_at, email, name, amount, currency, status, ship_to, line_items, carrier, tracking, shipped_at, notes, lang) = row;
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
        "lang": lang,
    })
}

/// Build a customer-facing tracking URL from carrier name + tracking number.
/// Returns None for unknown carriers - the email then shows just the number.
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

/// Lightweight URL encoder - only escapes the ASCII chars that need escaping
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
    // The status filter shares the query string with ?site=, so resolve the
    // site from the same map instead of a second Query extractor.
    let sq = SiteQuery::for_site(q.get("site").cloned());
    let site = resolve_site(&headers, &sq)?;
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    let status = q.get("status").map(|s| s.as_str());
    let rows = {
        let db = state.db.lock();
        db.list_orders(site.id, status).map_err(db_err)?
    };
    let orders: Vec<Value> = rows.into_iter().map(order_to_json).collect();
    Ok(Json(json!({ "orders": orders })))
}

pub async fn handle_admin_get_order(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    let row = {
        let db = state.db.lock();
        db.get_order(site.id, id).map_err(db_err)?
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
    Query(sq): Query<SiteQuery>,
    Path(id): Path<i64>,
    Json(req): Json<ShipOrderRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    let carrier = req.carrier.trim();
    let tracking = req.tracking_number.trim();
    if carrier.is_empty() || tracking.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "carrier and tracking_number required"));
    }
    let now = chrono::Utc::now().to_rfc3339();
    let order = {
        let db = state.db.lock();
        let ok = db.mark_order_shipped(site.id, id, carrier, tracking, &now).map_err(db_err)?;
        if !ok { return Err(error_response(StatusCode::NOT_FOUND, "Order not found")); }
        db.get_order(site.id, id).map_err(db_err)?
    };
    let order = order.ok_or_else(|| error_response(StatusCode::NOT_FOUND, "Order vanished"))?;

    if req.notify_customer {
        let email = order.3.clone();
        if !email.is_empty() {
            if let Some(svc) = state.email.clone() {
                let lang = order_email_lang(site, &order.14).to_string();
                let vars = shipped_vars(site, &order, &lang);
                let tpl = effective_template(&state, site, SETTING_TPL_SHIPPED, &lang);
                let md = crate::email_md::apply_template(&tpl, &vars);
                let doc = crate::email_md::render(&md, Some((LOGO_CID, site.name)));
                let subject = shipped_subject(site, &lang, order.0);
                let sender = format!("{} Shop", site.name);
                let logo = logo_inline_image(site);
                tokio::spawn(async move {
                    let inline = vec![logo];
                    if let Err(e) = svc.send_html_rich(&email, &subject, &doc.text, &doc.html, &inline, &[], Some(&sender)).await {
                        log::error!("Failed to send shipped email to {}: {}", email, e);
                    }
                });
            }
        }
    }

    crate::audit(
        &state,
        &p.username,
        "order.ship",
        &id.to_string(),
        &format!("carrier={} tracking={}", carrier, tracking),
    );
    Ok(Json(order_to_json(order)))
}

#[derive(Deserialize)]
pub struct UpdateOrderNotesRequest {
    pub notes: String,
}

pub async fn handle_admin_update_order_notes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateOrderNotesRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    let ok = {
        let db = state.db.lock();
        db.update_order_notes(site.id, id, &req.notes).map_err(db_err)?
    };
    if !ok { return Err(error_response(StatusCode::NOT_FOUND, "Order not found")); }
    crate::audit(&state, &p.username, "order.notes", &id.to_string(), "");
    Ok(Json(json!({ "id": id })))
}

#[allow(clippy::type_complexity)]
/// A shop order row (see susi_core list_orders/get_order; lang is last).
type OrderRow = (i64, String, String, String, String, i64, String, String, String, String, String, String, Option<String>, String, String);

fn shipped_vars(site: &SiteConfig, order: &OrderRow, lang: &str) -> Vec<(&'static str, String)> {
    let (id, _sid, _created, _email, name, amount, currency, _status, _ship, line_items_json, carrier, tracking, _shipped, _notes, _lang) = order;
    let line_items: Value = serde_json::from_str(line_items_json).unwrap_or(Value::Array(Vec::new()));
    let e = crate::email_md::escape;

    let shipment = format!(
        "|  |  |\n| --- | --- |\n| {} | **{}** |\n| {} | {} |",
        tr(lang, "Carrier"), e(carrier), tr(lang, "Tracking"), e(tracking),
    );
    let tracking_button = tracking_url(carrier, tracking)
        .map(|u| format!("{{{{button:{}|{}}}}}", tr(lang, "Track shipment"), u))
        .unwrap_or_default();
    let mut items = String::new();
    if let Some(list) = line_items.as_array() {
        for li in list {
            let qty = li.get("quantity").and_then(|v| v.as_i64()).unwrap_or(1);
            let desc = li.get("description").and_then(|v| v.as_str()).unwrap_or("(item)");
            items.push_str(&format!("- {} × {}\n", qty, e(desc)));
        }
    }
    vec![
        ("order", format!("#{}", id)),
        ("name", e(if name.is_empty() { tr(lang, "there") } else { name.as_str() })),
        ("site", e(site.name)),
        ("shipment", shipment),
        ("tracking_button", tracking_button),
        ("items", items.trim_end().to_string()),
        ("total", fmt_money(*amount, currency)),
    ]
}

fn shipped_subject(site: &SiteConfig, lang: &str, order_id: i64) -> String {
    if lang == "ja" {
        format!("{} ご注文#{}の商品を発送しました", site.name, order_id)
    } else {
        format!("Your {} order #{} has shipped", site.name, order_id)
    }
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
    SETTING_SUPPORT_CONTACT,
    SETTING_SHIPPING_COUNTRIES,
    SETTING_INVOICE_FROM,
    SETTING_TPL_CONFIRMATION,
    SETTING_TPL_CONFIRMATION_JA,
    SETTING_TPL_SHIPPED,
    SETTING_TPL_SHIPPED_JA,
];

/// Normalize a submitted shipping-country list to canonical, sorted, deduped
/// uppercase codes. Rejects anything Stripe won't accept and refuses to leave
/// the shop with no destination at all.
fn normalize_shipping_countries(raw: &str) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let mut out: Vec<String> = Vec::new();
    for part in raw.split(',') {
        let code = part.trim();
        if code.is_empty() { continue; }
        if !countries::is_supported(code) {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                &format!("Not a shippable country code: {}", code),
            ));
        }
        out.push(code.to_uppercase());
    }
    out.sort();
    out.dedup();
    if out.is_empty() {
        return Err(error_response(StatusCode::BAD_REQUEST, "Select at least one shipping country"));
    }
    Ok(out.join(","))
}

pub async fn handle_admin_get_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    let pairs = {
        let db = state.db.lock();
        db.list_shop_settings().map_err(db_err)?
    };
    let mut out = serde_json::Map::new();
    for k in KNOWN_SETTING_KEYS {
        out.insert((*k).to_string(), Value::String(String::new()));
    }
    // Surface the effective default so the picker reflects what the shop
    // actually serves before the setting has ever been saved.
    out.insert(
        SETTING_SHIPPING_COUNTRIES.into(),
        Value::String(DEFAULT_SHIPPING_COUNTRIES.join(",")),
    );
    // One table holds every site's settings; keep only this site's rows and
    // strip the prefix so the client sees bare keys either way.
    for (k, v) in pairs {
        let bare = if site.id == DEFAULT_SITE_ID {
            if k.contains('/') { continue; }
            k
        } else {
            match k.strip_prefix(&format!("{}/", site.id)) {
                Some(rest) => rest.to_string(),
                None => continue,
            }
        };
        out.insert(bare, Value::String(v));
    }
    // Also surface the env-var fallback so the UI can hint at the
    // bootstrap default when notification_emails is unset.
    out.insert(
        "notification_emails_fallback".into(),
        Value::String(if site.id == DEFAULT_SITE_ID { state.shop_notify_addr.clone() } else { String::new() }),
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
    Query(sq): Query<SiteQuery>,
    Json(req): Json<UpdateSettingsRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;

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
            SETTING_SHIPPING_COUNTRIES => normalize_shipping_countries(v)?,
            _ => v.clone(),
        };
        let db = state.db.lock();
        db.set_shop_setting(&shop_setting_key(site, k), &normalized).map_err(db_err)?;
    }
    crate::audit(&state, &p.username, "shop.settings_update", "", site.id);
    Ok(Json(json!({ "status": "OK" })))
}

// ---------------------------------------------------------------------------
// Email template editor - preview and test-send
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct EmailTemplateRequest {
    pub template: String,
    #[serde(default)]
    pub lang: String,
    #[serde(default)]
    pub body_md: String,
}

/// A canned order for previews: realistic amounts in the storefront currency.
fn sample_order_event(lang: &str) -> (Value, Vec<Value>) {
    let (cur, item, sub, ship, tax, total) = if lang == "ja" {
        ("jpy", 63800i64, 58000i64, 1500i64, 5950i64, 65450i64)
    } else {
        ("usd", 32390, 29900, 1500, 2490, 33890)
    };
    let addr = json!({
        "line1": "3-10-4 Motoazabu", "line2": "RE-FLAT 201", "city": "Minato-ku",
        "state": "Tokyo", "postal_code": "106-0046", "country": "JP",
    });
    let event = json!({ "data": { "object": {
        "id": "cs_sample", "currency": cur,
        "amount_total": total, "amount_subtotal": sub,
        "total_details": { "amount_shipping": ship, "amount_tax": tax },
        "customer_details": { "name": "Taro Test", "email": "customer@example.com", "address": addr },
        "shipping_details": { "name": "Taro Test", "address": addr },
    }}});
    let items = vec![json!({
        "quantity": 1, "description": "LPMS-B2 - Wireless 9-Axis IMU (Bluetooth)",
        "amount_total": item, "currency": cur,
    })];
    (event, items)
}

fn sample_order_row(lang: &str) -> OrderRow {
    let (event, items) = sample_order_event(lang);
    let amount = event.pointer("/data/object/amount_total").and_then(|v| v.as_i64()).unwrap_or(0);
    let cur = event.pointer("/data/object/currency").and_then(|v| v.as_str()).unwrap_or("usd").to_string();
    (
        42, "cs_sample".into(), String::new(), "customer@example.com".into(), "Taro Test".into(),
        amount, cur, "shipped".into(), "{}".into(),
        serde_json::to_string(&items).unwrap_or_else(|_| "[]".into()),
        "EMS".into(), "EM123456789JP".into(), None, String::new(), lang.to_string(),
    )
}

/// Resolve and fill a template with sample data. `body_md` empty = the
/// currently effective (stored or default) template.
fn render_template_sample(
    state: &AppState,
    site: &'static SiteConfig,
    req: &EmailTemplateRequest,
) -> Result<(String, String, String), (StatusCode, Json<ErrorResponse>)> {
    let lang = match req.lang.as_str() {
        "" => "",
        l if site.langs.iter().any(|x| *x == l) => l,
        _ => return Err(error_response(StatusCode::BAD_REQUEST, "Unknown language for this site")),
    };
    let base = match req.template.as_str() {
        "order_confirmation" => SETTING_TPL_CONFIRMATION,
        "order_shipped" => SETTING_TPL_SHIPPED,
        _ => return Err(error_response(StatusCode::BAD_REQUEST, "Unknown template")),
    };
    let tpl = if req.body_md.trim().is_empty() {
        effective_template(state, site, base, lang)
    } else {
        req.body_md.clone()
    };
    let (subject, md) = if base == SETTING_TPL_CONFIRMATION {
        let (event, items) = sample_order_event(lang);
        let vars = confirmation_vars(state, site, &event, &items, Some(42), lang);
        (confirmation_subject(site, lang, "#42"), crate::email_md::apply_template(&tpl, &vars))
    } else {
        let order = sample_order_row(lang);
        let vars = shipped_vars(site, &order, lang);
        (shipped_subject(site, lang, 42), crate::email_md::apply_template(&tpl, &vars))
    };
    Ok((subject, md, tpl))
}

pub async fn handle_admin_email_preview(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Json(req): Json<EmailTemplateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let site = resolve_site(&headers, &sq)?;
    let p = validate_principal(&headers, &state)?;
    require_admin_full(&state, &p)?;
    let (subject, md, tpl) = render_template_sample(&state, site, &req)?;
    let doc = crate::email_md::render(&md, Some((LOGO_CID, site.name)));
    let base = if req.template == "order_confirmation" { SETTING_TPL_CONFIRMATION } else { SETTING_TPL_SHIPPED };
    let vars: &[&str] = if base == SETTING_TPL_CONFIRMATION { VARS_CONFIRMATION } else { VARS_SHIPPED };
    Ok(Json(json!({
        "subject": subject,
        "markdown": tpl,
        "default_markdown": default_template(base, order_email_lang(site, &req.lang)),
        "setting_key": template_key(base, order_email_lang(site, &req.lang)),
        "html": doc.html,
        "text": doc.text,
        "variables": vars,
        "langs": site.langs,
    })))
}

pub async fn handle_admin_email_test(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Json(req): Json<EmailTemplateRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
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
    let (subject, md, _tpl) = render_template_sample(&state, site, &req)?;
    let doc = crate::email_md::render(&md, Some((LOGO_CID, site.name)));
    let inline = vec![logo_inline_image(site)];
    let sender = format!("{} Shop", site.name);
    svc.send_html_rich(&to, &format!("[Test] {}", subject), &doc.text, &doc.html, &inline, &[], Some(&sender))
        .await
        .map_err(|e| error_response(StatusCode::BAD_GATEWAY, &format!("Send failed: {}", e)))?;
    Ok(Json(json!({ "sent_to": to })))
}

// ---------------------------------------------------------------------------
// Public shop HTML shell
//
// /shop URLs reuse the same single-page-app shell as the public website so
// that header / sidebar / cart drawer stay consistent. The SPA's `route()`
// detects a `/shop` path and renders product views into the content area.
// ---------------------------------------------------------------------------

pub async fn handle_shop_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let site = match resolve_site(&headers, &sq) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let lang = crate::website::resolve_lang(site, &sq);
    shop_shell_response(&state, site, &lang, "")
}

pub async fn handle_shop_product_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
    Path(sku): Path<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let site = match resolve_site(&headers, &sq) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let lang = crate::website::resolve_lang(site, &sq);
    shop_shell_response(&state, site, &lang, &sku)
}

/// The storefront SPA shell for a site, in the given content language.
/// Serves a 404 shell on shopless sites so /shop never shadows real content.
/// A non-empty `sku` marks a product detail URL: the shell then carries the
/// product's JSON-LD so Merchant Center can verify price and availability on
/// the landing page.
pub fn shop_shell_response(
    state: &Arc<AppState>,
    site: &'static SiteConfig,
    lang: &str,
    sku: &str,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if !site.has_shop {
        let head = format!(
            "<title>{}</title>\n<meta name=\"robots\" content=\"noindex\">\n",
            crate::website::html_escape(site.name),
        );
        let html = crate::website::render_shell(state, site, "", &head, "<div class=\"empty-state\">Page not found</div>");
        return (StatusCode::NOT_FOUND, axum::response::Html(String::from_utf8_lossy(&html).into_owned())).into_response();
    }
    let esc_name = crate::website::html_escape(site.name);
    let (title, desc) = if lang == "ja" {
        (
            format!("ショップ - {}", esc_name),
            format!("{}の製品を直接ご注文いただけます。", esc_name),
        )
    } else if site.id == DEFAULT_SITE_ID {
        (
            format!("Shop - {}", esc_name),
            format!("Order {} IMU and inertial sensors directly. Shipped from our Los Angeles office.", esc_name),
        )
    } else {
        (
            format!("Shop - {}", esc_name),
            format!("Order {} products directly.", esc_name),
        )
    };
    let mut head = format!(
        "<title>{title}</title>\n\
         <meta name=\"description\" content=\"{desc}\">\n\
         <meta property=\"og:title\" content=\"{title}\">\n\
         <meta property=\"og:type\" content=\"website\">\n",
    );
    if !sku.is_empty() {
        let row = {
            let db = state.db.lock();
            db.get_product(site.id, sku).ok().flatten().filter(|r| r.7)
        };
        if let Some(block) = row.and_then(|r| crate::website::product_jsonld_block(site, lang, &r)) {
            head.push_str(&format!("<script type=\"application/ld+json\">{}</script>\n", block));
        }
    }
    let html = String::from_utf8_lossy(&crate::website::render_shell(
        state,
        site,
        lang,
        &head,
        "<div class=\"empty-state\">Loading…</div>",
    ))
    .into_owned();
    axum::response::Html(html).into_response()
}

/// GET /shop/feed.xml - Google Merchant Center product feed (RSS 2.0 with the
/// g: namespace). `?lang=ja` (or /ja/shop/feed.xml via the marketing rewrite)
/// serves Japanese titles and JPY prices.
pub async fn handle_shop_feed(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(sq): Query<SiteQuery>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let site = match resolve_site(&headers, &sq) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let lang = crate::website::resolve_lang(site, &sq);
    shop_feed_response(&state, site, &lang)
}

/// The Merchant Center feed for a site in the given content language.
/// Pre-order items are omitted: Google requires an availability date for
/// `preorder`, which the catalog doesn't track.
pub fn shop_feed_response(
    state: &Arc<AppState>,
    site: &'static SiteConfig,
    lang: &str,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if !site.has_shop {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    }
    let rows = {
        let db = state.db.lock();
        db.list_products(site.id, true).unwrap_or_default()
    };
    let esc = crate::website::html_escape;
    let ja = lang == "ja";
    let lang_seg = if lang.is_empty() { String::new() } else { format!("/{}", lang) };
    let mut xml = String::with_capacity(4096);
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<rss version=\"2.0\" xmlns:g=\"http://base.google.com/ns/1.0\">\n<channel>\n");
    xml.push_str(&format!("<title>{} Shop</title>\n", esc(site.name)));
    xml.push_str(&format!("<link>{}{}/shop</link>\n", esc(site.public_base), lang_seg));
    xml.push_str(&format!("<description>{}</description>\n", esc(site.tagline)));
    for (sku, title_en, desc_md_en, price_cents, currency, image_asset, _tax, _active, _ord, _upd, title_ja, desc_md_ja, price_jpy) in &rows {
        let title = if ja && !title_ja.trim().is_empty() { title_ja } else { title_en };
        if title_en.to_ascii_lowercase().contains("pre-order")
            || title.to_ascii_lowercase().contains("pre-order")
        {
            continue;
        }
        let price = if ja {
            if *price_jpy <= 0 { continue; }
            format!("{} JPY", price_jpy)
        } else {
            if *price_cents <= 0 { continue; }
            format!("{}.{:02} {}", price_cents / 100, (price_cents % 100).abs(), currency.to_uppercase())
        };
        let desc_md = if ja && !desc_md_ja.trim().is_empty() { desc_md_ja } else { desc_md_en };
        let desc = crate::website::derive_description(desc_md);
        let desc = if desc.is_empty() { title.clone() } else { desc };
        let img = crate::website::product_image_abs_url(site, image_asset.as_deref());
        xml.push_str("<item>\n");
        xml.push_str(&format!("<g:id>{}</g:id>\n", esc(sku)));
        xml.push_str(&format!("<g:title>{}</g:title>\n", esc(title)));
        xml.push_str(&format!("<g:description>{}</g:description>\n", esc(&desc)));
        xml.push_str(&format!("<g:link>{}{}/shop/{}</g:link>\n", esc(site.public_base), lang_seg, esc(sku)));
        if !img.is_empty() {
            xml.push_str(&format!("<g:image_link>{}</g:image_link>\n", esc(&img)));
        }
        xml.push_str("<g:condition>new</g:condition>\n<g:availability>in_stock</g:availability>\n");
        xml.push_str(&format!("<g:price>{}</g:price>\n", price));
        xml.push_str(&format!("<g:brand>{}</g:brand>\n", esc(site.name)));
        xml.push_str(&format!("<g:mpn>{}</g:mpn>\n", esc(sku)));
        xml.push_str("</item>\n");
    }
    xml.push_str("</channel>\n</rss>\n");
    ([(header::CONTENT_TYPE, "application/xml; charset=utf-8")], xml).into_response()
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
        // 10 min later - outside 5 min tolerance.
        assert!(verify_stripe_signature(secret, &header, payload, ts + 600).is_err());
    }

    #[test]
    fn signature_verify_rejects_bad_sig() {
        let header = "t=1700000000,v1=deadbeef";
        assert!(verify_stripe_signature("whsec_test", header, b"{}", 1_700_000_000).is_err());
    }

    fn rate(regions_json: &str) -> (i64, String, i64, String, Option<i64>, Option<i64>, String, bool, i64) {
        (1, "Std".into(), 500, "usd".into(), None, None, regions_json.into(), true, 0)
    }

    #[test]
    fn shipping_countries_default_when_unset_or_junk() {
        assert_eq!(parse_shipping_countries(""), vec!["US", "CA"]);
        assert_eq!(parse_shipping_countries("  "), vec!["US", "CA"]);
        // Codes Stripe rejects are dropped; an all-junk list falls back.
        assert_eq!(parse_shipping_countries("KP,XX"), vec!["US", "CA"]);
    }

    #[test]
    fn shipping_countries_parse_is_canonical() {
        assert_eq!(parse_shipping_countries("il, us , IL"), vec!["IL", "US"]);
        assert_eq!(parse_shipping_countries("US,CA,IL,KP"), vec!["CA", "IL", "US"]);
    }

    #[test]
    fn normalize_shipping_countries_validates() {
        assert_eq!(normalize_shipping_countries("us, ca, il").ok(), Some("CA,IL,US".into()));
        assert_eq!(normalize_shipping_countries("IL,IL").ok(), Some("IL".into()));
        // Empty selection and codes Stripe refuses are hard errors, not silent drops.
        assert!(normalize_shipping_countries("").is_err());
        assert!(normalize_shipping_countries(" , ").is_err());
        assert!(normalize_shipping_countries("US,KP").is_err());
        assert!(normalize_shipping_countries("US,ZZ").is_err());
        assert!(normalize_shipping_countries("US,USA").is_err());
    }

    #[test]
    fn allowed_countries_track_the_enabled_list() {
        let enabled: Vec<String> = vec!["CA".into(), "IL".into(), "US".into()];
        // A wildcard rate expands to every enabled destination.
        assert_eq!(
            allowed_countries_for_checkout(&[rate(r#"["*"]"#)], &enabled),
            vec!["CA", "IL", "US"],
        );
        // Explicit regions are honoured, case-insensitively.
        assert_eq!(
            allowed_countries_for_checkout(&[rate(r#"["il","us"]"#)], &enabled),
            vec!["IL", "US"],
        );
        // A rate naming a country that was since disabled contributes nothing.
        assert_eq!(
            allowed_countries_for_checkout(&[rate(r#"["IL","GB"]"#)], &["IL".to_string()]),
            vec!["IL"],
        );
        assert!(allowed_countries_for_checkout(&[rate(r#"["GB"]"#)], &enabled).is_empty());
    }

    #[test]
    fn rate_regions_must_be_enabled_countries() {
        let enabled: Vec<String> = vec!["IL".into(), "US".into()];
        let mk = |regions: Vec<&str>| ShippingRateRequest {
            label: "Std".into(),
            amount_cents: 500,
            currency: "usd".into(),
            delivery_min_days: None,
            delivery_max_days: None,
            regions: regions.into_iter().map(String::from).collect(),
            active: true,
            ord: 0,
        };
        assert_eq!(validate_rate_body(&mk(vec!["il"]), &enabled).ok(), Some(r#"["IL"]"#.into()));
        assert_eq!(validate_rate_body(&mk(vec!["*"]), &enabled).ok(), Some(r#"["*"]"#.into()));
        // Valid ISO code, but the shop does not ship there.
        assert!(validate_rate_body(&mk(vec!["GB"]), &enabled).is_err());
        assert!(validate_rate_body(&mk(vec!["ILX"]), &enabled).is_err());
    }

    #[test]
    fn rate_applies_wildcard() {
        assert!(rate_applies(&["*".into()], "US"));
        assert!(rate_applies(&["US".into(), "CA".into()], "us"));
        assert!(!rate_applies(&["US".into()], "GB"));
    }

    #[test]
    fn preorder_detection_from_line_items() {
        let preorder = vec![
            json!({"description": "LPMS-B2 - Wireless 9-Axis IMU (Bluetooth)"}),
            json!({"description": "Xicap - Spatial Tracker for Apple Vision Pro (Pre-order - ships end of Oct / early Nov 2026)"}),
        ];
        assert!(line_items_have_preorder(&preorder));
        let regular = vec![json!({"description": "LPMS-B2 - Wireless 9-Axis IMU (Bluetooth)"})];
        assert!(!line_items_have_preorder(&regular));
        assert!(!line_items_have_preorder(&[]));
        assert!(!line_items_have_preorder(&[json!({"quantity": 1})]));
    }
}
