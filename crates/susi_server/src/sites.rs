//! Site registry: the public marketing sites served by this backend.
//!
//! Sites live in the `sites` DB table (one JSON `SiteDef` per site), seeded
//! from the built-in definitions on first startup and editable through the
//! owner API. The runtime registry hands out leaked `&'static SiteConfig`s so
//! request handlers keep their zero-cost borrows; a site edit rebuilds and
//! swaps the list (the few stale leaked bytes per edit are the price of
//! editable sites). Which site a request belongs to is resolved from the Host
//! header (exact match, port stripped), with an explicit `?site=` override
//! for the dashboard, which runs on a host that resolves to no site. Unknown
//! hosts fall back to the default site so existing single-site behavior
//! (localhost, susi.lp-research.com) is unchanged.

use std::sync::{LazyLock, RwLock};

use axum::http::{header, HeaderMap};
use serde::{Deserialize, Serialize};
use susi_core::db::LicenseDb;

/// The site owning unscoped legacy data (bare `site_settings` keys) and
/// unknown hosts. Fixed: bare keys are this site's stored data forever.
pub const DEFAULT_SITE_ID: &str = "xikaku";

/// The editable identity of a site, stored as JSON in the `sites` table.
#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct SiteDef {
    pub name: String,
    pub tagline: String,
    /// Exact hosts that resolve to this site, including the staging name so
    /// the staging box serves each site the way production does. Must never
    /// contain the dashboard/docs host (susi.lp-research.com).
    pub hosts: Vec<String>,
    /// Canonical public origin; every canonical/og:url/sitemap/RSS URL is
    /// built from this regardless of the requesting host.
    pub public_base: String,
    pub contact_email: String,
    pub org_legal_name: String,
    pub addr_locality: String,
    pub addr_country: String,
    /// Absolute og:image URL; empty = the tags that need it are omitted.
    pub og_image_url: String,
    pub social_links: Vec<String>,
    /// Organization.contactPoint.areaServed; empty = omit the field.
    pub area_served: Vec<String>,
    /// Intro paragraph for llms.txt.
    pub llms_blurb: String,
    pub has_shop: bool,
    pub has_newsletter: bool,
    /// Show the Blog link in the site nav. Defaults on: the blog is pure
    /// content, and configs stored before the flag existed must keep it.
    #[serde(default = "default_true")]
    pub has_blog: bool,
    /// Additional content languages beyond the site's default, served under
    /// a /{lang}/ URL prefix (e.g. ["ja"]). Empty = monolingual.
    #[serde(default)]
    pub langs: Vec<String>,
}

fn default_true() -> bool {
    true
}

/// The leaked runtime view of a site that request handlers borrow.
pub struct SiteConfig {
    pub id: &'static str,
    pub hosts: &'static [&'static str],
    pub name: &'static str,
    pub tagline: &'static str,
    pub org_legal_name: &'static str,
    pub addr_locality: &'static str,
    pub addr_country: &'static str,
    pub contact_email: &'static str,
    pub public_base: &'static str,
    /// Absolute logo URL for JSON-LD; empty when the site has no logo yet.
    pub logo_url: &'static str,
    pub og_image_url: &'static str,
    pub social_links: &'static [&'static str],
    pub area_served: &'static [&'static str],
    pub llms_blurb: &'static str,
    pub has_shop: bool,
    pub has_newsletter: bool,
    pub has_blog: bool,
    pub langs: &'static [&'static str],
    org_jsonld: &'static str,
}

/// Compiled-in brand artwork for the sites that shipped before uploads
/// existed. Dynamic sites have none and rely on uploaded assets.
pub struct CompiledBrand {
    pub logo: &'static [u8],
    pub logo_dark: &'static [u8],
    pub icon: &'static [u8],
    pub favicon_32: &'static [u8],
    pub favicon_180: &'static [u8],
    pub favicon_ico: &'static [u8],
}

static XIKAKU_BRAND: CompiledBrand = CompiledBrand {
    logo: include_bytes!("assets/xikaku-logo.png"),
    logo_dark: include_bytes!("assets/xikaku-logo-dark.png"),
    icon: include_bytes!("assets/xikaku-icon.png"),
    favicon_32: include_bytes!("assets/xikaku-favicon-32.png"),
    favicon_180: include_bytes!("assets/xikaku-favicon-180.png"),
    favicon_ico: include_bytes!("assets/favicon.ico"),
};

static LPR_BRAND: CompiledBrand = CompiledBrand {
    logo: include_bytes!("assets/lpr-logo.png"),
    // Same mark, in the brand hue lifted to stay legible on the black
    // dark theme (the delivered blue only reaches 2.3:1 contrast there).
    logo_dark: include_bytes!("assets/lpr-logo-dark.png"),
    icon: include_bytes!("assets/lpr-icon.png"),
    favicon_32: include_bytes!("assets/lpr-favicon-32.png"),
    favicon_180: include_bytes!("assets/lpr-favicon-180.png"),
    favicon_ico: include_bytes!("assets/lpr-favicon.ico"),
};

pub fn compiled_brand(id: &str) -> Option<&'static CompiledBrand> {
    match id {
        "xikaku" => Some(&XIKAKU_BRAND),
        "lpr" => Some(&LPR_BRAND),
        _ => None,
    }
}

fn builtin_defs() -> Vec<(&'static str, SiteDef)> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    vec![
        (
            "xikaku",
            SiteDef {
                name: "Xikaku".into(),
                tagline: "Sight beyond Sight".into(),
                hosts: s(&["xikaku.com", "www.xikaku.com", "staging.xikaku.com"]),
                public_base: "https://xikaku.com".into(),
                contact_email: "info@xikaku.com".into(),
                org_legal_name: "LP-Research Inc.".into(),
                addr_locality: "Tokyo".into(),
                addr_country: "JP".into(),
                og_image_url: "https://xikaku.com/static/og-image.png".into(),
                social_links: s(&[
                    "https://github.com/xikaku-inc",
                    "https://www.linkedin.com/company/xikaku",
                ]),
                area_served: s(&["US", "CA"]),
                llms_blurb: "builds sensor-fusion and perception software for autonomous systems. \
                 The pages listed below are the authoritative source for products, documentation, \
                 and company information."
                    .into(),
                has_shop: true,
                has_newsletter: true,
                has_blog: true,
                langs: Vec::new(),
            },
        ),
        (
            "lpr",
            SiteDef {
                name: "LP-Research".into(),
                tagline: "Advanced Sensor Fusion Solutions and IMUs".into(),
                hosts: s(&["lp-research.com", "www.lp-research.com", "staging.lp-research.com"]),
                public_base: "https://www.lp-research.com".into(),
                contact_email: "info@lp-research.com".into(),
                org_legal_name: "LP-Research Inc.".into(),
                addr_locality: "Tokyo".into(),
                addr_country: "JP".into(),
                og_image_url: String::new(),
                social_links: s(&[
                    "https://github.com/lp-research",
                    "https://www.linkedin.com/company/lp-research",
                ]),
                area_served: Vec::new(),
                llms_blurb: "develops inertial measurement units (IMUs), sensor-fusion algorithms \
                 and VR/AR tracking systems. The pages listed below are the authoritative source \
                 for products and company information."
                    .into(),
                has_shop: false,
                has_newsletter: false,
                has_blog: true,
                langs: s(&["ja"]),
            },
        ),
    ]
}

fn sstr(s: &str) -> &'static str {
    Box::leak(s.to_string().into_boxed_str())
}

fn svec(v: &[String]) -> &'static [&'static str] {
    Box::leak(v.iter().map(|s| sstr(s)).collect::<Vec<_>>().into_boxed_slice())
}

/// `has_logo` decides whether JSON-LD carries a logo URL: true for sites with
/// compiled artwork or an uploaded `logo_image` setting.
fn build_config(id: &str, def: &SiteDef, has_logo: bool) -> &'static SiteConfig {
    let logo_url = if has_logo {
        format!("{}/static/logo.png", def.public_base)
    } else {
        String::new()
    };
    let mut cfg = SiteConfig {
        id: sstr(id),
        hosts: svec(&def.hosts),
        name: sstr(&def.name),
        tagline: sstr(&def.tagline),
        org_legal_name: sstr(&def.org_legal_name),
        addr_locality: sstr(&def.addr_locality),
        addr_country: sstr(&def.addr_country),
        contact_email: sstr(&def.contact_email),
        public_base: sstr(def.public_base.trim_end_matches('/')),
        logo_url: sstr(&logo_url),
        og_image_url: sstr(&def.og_image_url),
        social_links: svec(&def.social_links),
        area_served: svec(&def.area_served),
        llms_blurb: sstr(&def.llms_blurb),
        has_shop: def.has_shop,
        has_newsletter: def.has_newsletter,
        has_blog: def.has_blog,
        langs: svec(&def.langs),
        org_jsonld: "",
    };
    cfg.org_jsonld = sstr(&build_org_jsonld(&cfg));
    Box::leak(Box::new(cfg))
}

// Boots from the built-in definitions so lookups work before (and without)
// DB init; `reload_from_db` swaps in the stored registry at startup.
static REGISTRY: LazyLock<RwLock<Vec<&'static SiteConfig>>> = LazyLock::new(|| {
    RwLock::new(builtin_defs().iter().map(|(id, d)| build_config(id, d, true)).collect())
});

pub fn all_sites() -> Vec<&'static SiteConfig> {
    REGISTRY.read().unwrap().clone()
}

pub fn default_site() -> &'static SiteConfig {
    let reg = REGISTRY.read().unwrap();
    reg.iter().find(|s| s.id == DEFAULT_SITE_ID).copied().unwrap_or(reg[0])
}

pub fn site_by_id(id: &str) -> Option<&'static SiteConfig> {
    REGISTRY.read().unwrap().iter().find(|s| s.id == id).copied()
}

/// Exact host match, port stripped. `susi.lp-research.com` (dashboard/docs)
/// deliberately matches nothing.
pub fn site_from_host(host: &str) -> Option<&'static SiteConfig> {
    let host = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
    REGISTRY.read().unwrap().iter().find(|s| s.hosts.contains(&host.as_str())).copied()
}

pub fn site_from_headers(headers: &HeaderMap) -> Option<&'static SiteConfig> {
    headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .and_then(site_from_host)
}

/// Seed the `sites` table from the built-in definitions on first startup,
/// then load the runtime registry from it.
pub fn init_from_db(db: &LicenseDb) {
    match db.sites_count() {
        Ok(0) => {
            for (i, (id, def)) in builtin_defs().iter().enumerate() {
                let json = serde_json::to_string(def).expect("serialize builtin site");
                if let Err(e) = db.upsert_site(id, Some(i as i64), &json) {
                    log::error!("Seeding site '{}': {}", id, e);
                }
            }
            log::info!("Seeded sites table from built-in definitions");
        }
        Ok(_) => {}
        Err(e) => log::error!("Counting sites: {}", e),
    }
    reload_from_db(db);
}

/// Rebuild the registry from the DB. Called at startup and after any write
/// to a site or its logo settings (the JSON-LD logo URL depends on both).
pub fn reload_from_db(db: &LicenseDb) {
    let rows = match db.list_sites() {
        Ok(r) => r,
        Err(e) => {
            log::error!("Loading sites: {}", e);
            return;
        }
    };
    let built: Vec<&'static SiteConfig> = rows
        .iter()
        .filter_map(|(id, json)| {
            let def: SiteDef = match serde_json::from_str(json) {
                Ok(d) => d,
                Err(e) => {
                    log::error!("Site '{}' config unreadable, keeping it out: {}", id, e);
                    return None;
                }
            };
            let has_logo = compiled_brand(id).is_some()
                || db
                    .get_site_setting(&scoped_key(id, crate::website::SETTING_LOGO_IMAGE))
                    .ok()
                    .flatten()
                    .map_or(false, |v| !v.is_empty());
            Some(build_config(id, &def, has_logo))
        })
        .collect();
    if built.is_empty() {
        log::error!("Site registry load produced no sites; keeping previous registry");
        return;
    }
    *REGISTRY.write().unwrap() = built;
}

fn scoped_key(id: &str, key: &str) -> String {
    if id == DEFAULT_SITE_ID {
        key.to_string()
    } else {
        format!("{}/{}", id, key)
    }
}

/// `site_settings` key for a per-site setting. The default site keeps bare
/// keys so existing stored settings remain valid.
pub fn setting_key(site: &SiteConfig, key: &str) -> String {
    scoped_key(site.id, key)
}

pub fn org_jsonld(site: &SiteConfig) -> &'static str {
    site.org_jsonld
}

fn build_org_jsonld(site: &SiteConfig) -> String {
    use crate::website::html_escape;
    let same_as = site
        .social_links
        .iter()
        .map(|u| format!("\"{}\"", html_escape(u)))
        .collect::<Vec<_>>()
        .join(",");
    let logo = if site.logo_url.is_empty() {
        String::new()
    } else {
        format!(r#""logo":"{}","#, html_escape(site.logo_url))
    };
    let area = if site.area_served.is_empty() {
        String::new()
    } else {
        format!(
            r#","areaServed":[{}]"#,
            site.area_served
                .iter()
                .map(|a| format!("\"{}\"", a))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    // Empty fields are omitted entirely; empty-string values read as noise
    // to structured-data parsers.
    let legal = if site.org_legal_name.is_empty() {
        String::new()
    } else {
        format!(r#""legalName":"{}","#, html_escape(site.org_legal_name))
    };
    let address = if site.addr_locality.is_empty() && site.addr_country.is_empty() {
        String::new()
    } else {
        format!(
            r#","address":{{"@type":"PostalAddress","addressLocality":"{}","addressCountry":"{}"}}"#,
            html_escape(site.addr_locality),
            html_escape(site.addr_country),
        )
    };
    let contact = if site.contact_email.is_empty() {
        String::new()
    } else {
        format!(
            r#","email":"{email}","contactPoint":{{"@type":"ContactPoint","contactType":"customer support","email":"{email}"{area}}}"#,
            email = html_escape(site.contact_email),
            area = area,
        )
    };
    let same_as = if same_as.is_empty() {
        String::new()
    } else {
        format!(r#","sameAs":[{}]"#, same_as)
    };
    format!(
        r#"{{"@context":"https://schema.org","@type":"Organization","name":"{name}",{legal}"url":"{url}",{logo}"slogan":"{slogan}"{address}{contact}{same_as}}}"#,
        name = html_escape(site.name),
        legal = legal,
        url = html_escape(site.public_base),
        logo = logo,
        slogan = html_escape(site.tagline),
        address = address,
        contact = contact,
        same_as = same_as,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_resolution_is_exact() {
        assert_eq!(site_from_host("xikaku.com").unwrap().id, "xikaku");
        assert_eq!(site_from_host("www.xikaku.com").unwrap().id, "xikaku");
        assert_eq!(site_from_host("XIKAKU.COM:443").unwrap().id, "xikaku");
        assert_eq!(site_from_host("lp-research.com").unwrap().id, "lpr");
        assert_eq!(site_from_host("www.lp-research.com").unwrap().id, "lpr");
        // Staging serves each site under its own name, as production does.
        assert_eq!(site_from_host("staging.xikaku.com").unwrap().id, "xikaku");
        assert_eq!(site_from_host("staging.lp-research.com").unwrap().id, "lpr");
        // The dashboard/docs host must never resolve to a marketing site.
        assert!(site_from_host("susi.lp-research.com").is_none());
        assert!(site_from_host("localhost").is_none());
    }

    #[test]
    fn setting_keys_stay_bare_for_default_site() {
        assert_eq!(setting_key(default_site(), "google_analytics_id"), "google_analytics_id");
        assert_eq!(setting_key(site_by_id("lpr").unwrap(), "google_analytics_id"), "lpr/google_analytics_id");
    }

    #[test]
    fn stored_configs_without_has_blog_keep_the_blog() {
        let def: SiteDef = serde_json::from_str(r#"{"name":"X","hosts":["x.com"],"public_base":"https://x.com"}"#).unwrap();
        assert!(def.has_blog);
    }

    #[test]
    fn org_jsonld_omits_empty_fields() {
        let x = org_jsonld(default_site());
        assert!(x.contains(r#""logo":"https://xikaku.com/static/logo.png""#));
        assert!(x.contains(r#""areaServed":["US","CA"]"#));
        let l = org_jsonld(site_by_id("lpr").unwrap());
        assert!(l.contains(r#""logo":"https://www.lp-research.com/static/logo.png""#));
        // areaServed and the og card are still unset for this site.
        assert!(!l.contains("areaServed"));
        assert!(l.contains(r#""name":"LP-Research""#));
    }

    #[test]
    fn org_jsonld_omits_empty_org_fields_for_personal_sites() {
        let def: SiteDef = serde_json::from_str(
            r#"{"name":"K","tagline":"t","hosts":["k.example.com"],"public_base":"https://k.example.com","social_links":["https://soundcloud.com/x"]}"#,
        )
        .unwrap();
        let cfg = build_config("ktest", &def, false);
        let j = org_jsonld(cfg);
        assert!(!j.contains("legalName"));
        assert!(!j.contains("email"));
        assert!(!j.contains("PostalAddress"));
        assert!(!j.contains("contactPoint"));
        assert!(j.contains(r#""sameAs":["https://soundcloud.com/x"]"#));
        serde_json::from_str::<serde_json::Value>(j).expect("org JSON-LD must stay valid JSON");
    }
}
