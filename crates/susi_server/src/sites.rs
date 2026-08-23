//! Site registry: the public marketing sites served by this backend.
//!
//! One backend hosts several sites; `website_pages` / `website_assets` /
//! `site_settings` rows are scoped by the site id. Which site a request
//! belongs to is resolved from the Host header (exact match, port stripped),
//! with an explicit `?site=` override for the dashboard, which runs on a
//! host that resolves to no site. Unknown hosts fall back to the default
//! site so existing single-site behavior (localhost, susi.lp-research.com)
//! is unchanged.

use std::collections::HashMap;
use std::sync::LazyLock;

use axum::http::{header, HeaderMap};

pub struct SiteConfig {
    pub id: &'static str,
    /// Exact hosts that resolve to this site, including the staging name so
    /// the staging box serves each site the way production does. Must never
    /// contain the dashboard/docs host (susi.lp-research.com).
    pub hosts: &'static [&'static str],
    pub name: &'static str,
    pub tagline: &'static str,
    pub org_legal_name: &'static str,
    pub addr_locality: &'static str,
    pub addr_country: &'static str,
    pub contact_email: &'static str,
    /// Canonical public origin; every canonical/og:url/sitemap/RSS URL is
    /// built from this regardless of the requesting host.
    pub public_base: &'static str,
    /// Absolute brand asset URLs for JSON-LD / og:image. Empty = not yet
    /// available; the tags that need them are omitted.
    pub logo_url: &'static str,
    pub og_image_url: &'static str,
    /// Relative brand image paths for the page header; empty = render the
    /// site name as text instead.
    pub brand_logo: &'static str,
    pub brand_logo_dark: &'static str,
    /// Bytes behind those paths. `/static/logo.png` serves whichever site the
    /// Host header resolves to, so both sites use the same URLs.
    pub logo_png: &'static [u8],
    /// Artwork for the dark theme.
    pub logo_dark_png: &'static [u8],
    pub icon_png: &'static [u8],
    pub favicon_32_png: &'static [u8],
    pub favicon_180_png: &'static [u8],
    pub favicon_ico: &'static [u8],
    /// Optional photo background for the public site, served at
    /// `/static/bg.jpg`. Empty = flat theme, no image layer in the shell.
    pub bg_image: &'static [u8],
    pub social_links: &'static [&'static str],
    /// Organization.contactPoint.areaServed; empty = omit the field.
    pub area_served: &'static [&'static str],
    /// Intro paragraph for llms.txt.
    pub llms_blurb: &'static str,
    pub has_shop: bool,
    pub has_newsletter: bool,
}

// Trial background artwork shared by both sites while the theme is evaluated.
const SITE_BG_JPG: &[u8] = include_bytes!("assets/site-bg.jpg");

pub static SITES: &[SiteConfig] = &[
    SiteConfig {
        id: "xikaku",
        hosts: &["xikaku.com", "www.xikaku.com", "staging.xikaku.com"],
        name: "Xikaku",
        tagline: "Sight beyond Sight",
        org_legal_name: "LP-Research Inc.",
        addr_locality: "Tokyo",
        addr_country: "JP",
        contact_email: "info@xikaku.com",
        public_base: "https://xikaku.com",
        logo_url: "https://xikaku.com/static/logo.png",
        og_image_url: "https://xikaku.com/static/og-image.png",
        // ?v=3 busts caches that pinned the logo before its white background
        // was removed for the photo-background theme.
        brand_logo: "/static/logo.png?v=3",
        brand_logo_dark: "/static/logo-dark.png",
        logo_png: include_bytes!("assets/xikaku-logo.png"),
        logo_dark_png: include_bytes!("assets/xikaku-logo-dark.png"),
        icon_png: include_bytes!("assets/xikaku-icon.png"),
        favicon_32_png: include_bytes!("assets/xikaku-favicon-32.png"),
        favicon_180_png: include_bytes!("assets/xikaku-favicon-180.png"),
        favicon_ico: include_bytes!("assets/favicon.ico"),
        bg_image: SITE_BG_JPG,
        social_links: &[
            "https://github.com/xikaku-inc",
            "https://www.linkedin.com/company/xikaku",
        ],
        area_served: &["US", "CA"],
        llms_blurb: "builds sensor-fusion and perception software for autonomous systems. \
         The pages listed below are the authoritative source for products, documentation, \
         and company information.",
        has_shop: true,
        has_newsletter: true,
    },
    SiteConfig {
        id: "lpr",
        hosts: &["lp-research.com", "www.lp-research.com", "staging.lp-research.com"],
        name: "LP-Research",
        tagline: "Advanced Sensor Fusion Solutions and IMUs",
        org_legal_name: "LP-Research Inc.",
        addr_locality: "Tokyo",
        addr_country: "JP",
        contact_email: "info@lp-research.com",
        public_base: "https://www.lp-research.com",
        logo_url: "https://www.lp-research.com/static/logo.png",
        // No og card artwork yet, so the tags that need it are omitted.
        og_image_url: "",
        // ?v=2 busts browser caches that pinned the shared pre-per-site logo
        // (it was served with a day of `immutable`).
        brand_logo: "/static/logo.png?v=2",
        brand_logo_dark: "/static/logo-dark.png?v=2",
        logo_png: include_bytes!("assets/lpr-logo.png"),
        // Same mark, in the brand hue lifted to stay legible on the black
        // dark theme (the delivered blue only reaches 2.3:1 contrast there).
        logo_dark_png: include_bytes!("assets/lpr-logo-dark.png"),
        icon_png: include_bytes!("assets/lpr-icon.png"),
        favicon_32_png: include_bytes!("assets/lpr-favicon-32.png"),
        favicon_180_png: include_bytes!("assets/lpr-favicon-180.png"),
        favicon_ico: include_bytes!("assets/lpr-favicon.ico"),
        bg_image: SITE_BG_JPG,
        social_links: &[
            "https://github.com/lp-research",
            "https://www.linkedin.com/company/lp-research",
        ],
        area_served: &[],
        llms_blurb: "develops inertial measurement units (IMUs), sensor-fusion algorithms \
         and VR/AR tracking systems. The pages listed below are the authoritative source \
         for products and company information.",
        has_shop: false,
        has_newsletter: false,
    },
];

/// The site that owns unscoped legacy data and unknown hosts.
pub fn default_site() -> &'static SiteConfig {
    &SITES[0]
}

pub fn site_by_id(id: &str) -> Option<&'static SiteConfig> {
    SITES.iter().find(|s| s.id == id)
}

/// Exact host match, port stripped. `susi.lp-research.com` (dashboard/docs)
/// deliberately matches nothing.
pub fn site_from_host(host: &str) -> Option<&'static SiteConfig> {
    let host = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
    SITES.iter().find(|s| s.hosts.contains(&host.as_str()))
}

pub fn site_from_headers(headers: &HeaderMap) -> Option<&'static SiteConfig> {
    headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .and_then(site_from_host)
}

/// `site_settings` key for a per-site setting. The default site keeps bare
/// keys so existing stored settings remain valid.
pub fn setting_key(site: &SiteConfig, key: &str) -> String {
    if site.id == default_site().id {
        key.to_string()
    } else {
        format!("{}/{}", site.id, key)
    }
}

// Organization JSON-LD is identical across a site's pages - built once.
static ORG_JSONLD: LazyLock<HashMap<&'static str, String>> = LazyLock::new(|| {
    SITES.iter().map(|s| (s.id, build_org_jsonld(s))).collect()
});

pub fn org_jsonld(site: &SiteConfig) -> &'static str {
    &ORG_JSONLD[site.id]
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
    format!(
        r#"{{"@context":"https://schema.org","@type":"Organization","name":"{name}","legalName":"{legal}","url":"{url}",{logo}"slogan":"{slogan}","email":"{email}","address":{{"@type":"PostalAddress","addressLocality":"{loc}","addressCountry":"{country}"}},"contactPoint":{{"@type":"ContactPoint","contactType":"customer support","email":"{email}"{area}}},"sameAs":[{same_as}]}}"#,
        name = html_escape(site.name),
        legal = html_escape(site.org_legal_name),
        url = html_escape(site.public_base),
        logo = logo,
        slogan = html_escape(site.tagline),
        email = html_escape(site.contact_email),
        loc = html_escape(site.addr_locality),
        country = html_escape(site.addr_country),
        area = area,
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
}
