#!/usr/bin/env python3
"""One-shot WordPress -> susi migrator for lp-research.com.

Steps (run separately so the bundle can be reviewed between them):

  python migrate.py fetch  --work DIR   # pull pages/posts/media/redirects from WP
  python migrate.py build  --work DIR   # convert to a susi import bundle
  python migrate.py push   --work DIR --susi URL --site lpr   # import the bundle

Credentials via env: WP_USER, WP_APP_PASSWORD (WordPress application password),
SUSI_TOKEN (susi admin JWT or susi_pat_ token). The script only ever reads
from WordPress.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.parse

import requests
from bs4 import BeautifulSoup
from markdownify import markdownify

WP_BASE = "https://www.lp-research.com"
POSTS_PER_IMPORT_CHUNK_BYTES = 40 * 1024 * 1024

# Pages under these slugs stay on WordPress (customer area) or are WP cruft.
EXCLUDE_ROOT_SLUGS = {"customer-area"}

# WordPress category archive paths all fold into /blog.
CATEGORY_SLUGS = ["blog", "event", "media", "product", "projects", "use-cases"]

# Curation (2026-08 crawl of the live site): empty WP container pages are
# dropped entirely, their paths redirected; pages no visitor can reach on the
# live site are imported hidden, their old URLs redirected to the relevant
# overview page.
DROPPED = {
    "products": "/",
    "company": "/about-us-lp-research",
    "order": "/distributors",
    "technology": "/sensor-fusion-solutions",
}
HIDDEN_SLUGS = {
    "lpms-b", "lpms-cu", "lpms-canal", "lpms-canal2", "lpms-usbal",
    "lpms-uartal", "lpms-nav2", "lpms-nav2-rs232", "lpms-nav2-rs422",
    "9-axis-waterproof-imu-lpms-al2-series", "lpms-me1-dk", "lpms-b2-holder",
    "packaging-environment-guide-eu",
}
# Flat xikaku-style layout: slug -> (parent_slug or None, ord).
PAGE_LAYOUT = {
    "lp-research": (None, 0),
    "inertial-measurement-units-imu": (None, 10),
    "vr-ar-tracking-solutions-lpvr": (None, 20),
    "lpnav": (None, 30),
    "lpms-inc1": (None, 40),
    "motion-capture-system-lpmocap": (None, 50),
    "lpiotsolution": (None, 60),
    "sensor-fusion-solutions": (None, 70),
    "customers": (None, 80),
    "about-us-lp-research": (None, 90),
    "contact": (None, 100),
    "distributors": (None, 110),
    "software-eula": (None, 900),
    "terms-of-service": (None, 910),
    # IMU children, in the live overview page's order.
    "lpms-b2": ("inertial-measurement-units-imu", 10),
    "lpms-u3-usb-and-can-bus-imu": ("inertial-measurement-units-imu", 20),
    "lpms-al3-9-axis-imu-sensor": ("inertial-measurement-units-imu", 30),
    "lpms-ig1": ("inertial-measurement-units-imu", 40),
    "lpms-ig1p": ("inertial-measurement-units-imu", 50),
    "lpms-ig1w": ("inertial-measurement-units-imu", 60),
    "lpms-nav3": ("inertial-measurement-units-imu", 70),
    "lpms-hr": ("inertial-measurement-units-imu", 80),
    "lpms-curs3-oem-9-axis-imu-ahrs-usb-can-uart": ("inertial-measurement-units-imu", 90),
    "9-axis-usb-and-can-bus-imu-lpmsu2-series": ("inertial-measurement-units-imu", 100),
    "lpms-me1": ("inertial-measurement-units-imu", 110),
    "lpvr-cad": ("vr-ar-tracking-solutions-lpvr", 10),
    "lpvr-duo": ("vr-ar-tracking-solutions-lpvr", 20),
    "lpvr-air": ("vr-ar-tracking-solutions-lpvr", 30),
    "lpvr-pos": ("vr-ar-tracking-solutions-lpvr", 40),
    # Hidden legacy pages keep a parent for the dashboard tree.
    "lpms-b": ("inertial-measurement-units-imu", 500),
    "lpms-cu": ("inertial-measurement-units-imu", 500),
    "lpms-canal": ("inertial-measurement-units-imu", 500),
    "lpms-canal2": ("inertial-measurement-units-imu", 500),
    "lpms-usbal": ("inertial-measurement-units-imu", 500),
    "lpms-uartal": ("inertial-measurement-units-imu", 500),
    "lpms-nav2": ("inertial-measurement-units-imu", 500),
    "lpms-nav2-rs232": ("inertial-measurement-units-imu", 500),
    "lpms-nav2-rs422": ("inertial-measurement-units-imu", 500),
    "9-axis-waterproof-imu-lpms-al2-series": ("inertial-measurement-units-imu", 500),
    "lpms-me1-dk": ("inertial-measurement-units-imu", 500),
    "lpms-b2-holder": ("motion-capture-system-lpmocap", 500),
    "packaging-environment-guide-eu": (None, 990),
}
# Concise nav/SEO titles; the body keeps its keyword-rich headings.
TITLE_OVERRIDES = {
    "lp-research": "Home",
    "inertial-measurement-units-imu": "IMU Sensors",
    "vr-ar-tracking-solutions-lpvr": "VR/AR Tracking - LPVR",
    "lpnav": "LPNAV - AGV Positioning",
    "lpms-inc1": "LPMS-INC1 Inclinometer",
    "motion-capture-system-lpmocap": "LPMOCAP - Motion Capture",
    "lpiotsolution": "LPIOT - Industrial Monitoring",
    "customers": "Customers",
    "lpms-b2": "LPMS-B2",
    "lpms-u3-usb-and-can-bus-imu": "LPMS-U3",
    "lpms-al3-9-axis-imu-sensor": "LPMS-AL3",
    "lpms-ig1": "LPMS-IG1",
    "lpms-ig1p": "LPMS-IG1P",
    "lpms-ig1w": "LPMS-IG1W",
    "lpms-nav3": "LPMS-NAV3",
    "lpms-hr": "LPMS-HR",
    "lpms-curs3-oem-9-axis-imu-ahrs-usb-can-uart": "LPMS-CURS3",
    "9-axis-usb-and-can-bus-imu-lpmsu2-series": "LPMS-U2",
    "lpms-me1": "LPMS-ME1",
    "lpvr-cad": "LPVR-CAD",
    "lpvr-duo": "LPVR-DUO",
    "lpvr-air": "LPVR-AIR",
    "lpvr-pos": "LPVR-POS",
}
EXTRA_REDIRECTS = [
    {"from_path": "/support",
     "to_path": "https://lp-research.atlassian.net/wiki/spaces/LKB/overview"},
    # Live alias URLs served by WP old-slug redirects, not in the Redirection
    # export (found by crawling the live site). Targets use the new layout.
    {"from_path": "/LPVR-CAD", "to_path": "/lpvr-cad"},
    {"from_path": "/lpvr", "to_path": "/lpvr-duo"},
    {"from_path": "/automatic-guided-vehicle-navigation-system-lpnav", "to_path": "/lpnav"},
    {"from_path": "/inertial-measurement-unit", "to_path": "/inertial-measurement-units-imu"},
    {"from_path": "/lpms-cu2", "to_path": "/9-axis-usb-and-can-bus-imu-lpmsu2-series"},
    {"from_path": "/imu", "to_path": "/blog/imu-based-dead-reckoning-displacement-tracking-revisited"},
    {"from_path": "/imu/lpms-al3", "to_path": "/lpms-al3-9-axis-imu-sensor"},
    {"from_path": "/imu/lpms-b2", "to_path": "/lpms-b2"},
    {"from_path": "/imu/lpms-ig1", "to_path": "/lpms-ig1"},
    {"from_path": "/imu/lpms-ig1w", "to_path": "/lpms-ig1w"},
    {"from_path": "/imu/lpms-nav3", "to_path": "/lpms-nav3"},
    {"from_path": "/products/lpvr-virtual-reality/lpvr-air", "to_path": "/lpvr-air"},
    {"from_path": "/products/lpvr-virtual-reality/lpvr-duo", "to_path": "/lpvr-duo"},
]


def wp_session():
    user = os.environ.get("WP_USER")
    pw = os.environ.get("WP_APP_PASSWORD")
    if not user or not pw:
        sys.exit("Set WP_USER and WP_APP_PASSWORD")
    s = requests.Session()
    s.auth = (user, pw)
    s.headers["User-Agent"] = "susi-migrator/1.0"
    return s


def fetch_all(s, endpoint):
    out = []
    page = 1
    while True:
        r = s.get(
            f"{WP_BASE}/wp-json/wp/v2/{endpoint}",
            params={"per_page": 100, "page": page, "status": "publish"},
            timeout=60,
        )
        if r.status_code == 400:  # past the last page
            break
        r.raise_for_status()
        batch = r.json()
        out.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return out


def cmd_fetch(work):
    s = wp_session()
    os.makedirs(work, exist_ok=True)
    pages = fetch_all(s, "pages")
    posts = fetch_all(s, "posts")
    print(f"fetched {len(pages)} pages, {len(posts)} posts")
    with open(os.path.join(work, "wp_pages.json"), "w", encoding="utf-8") as f:
        json.dump(pages, f)
    with open(os.path.join(work, "wp_posts.json"), "w", encoding="utf-8") as f:
        json.dump(posts, f)
    # Redirection plugin rules (best effort - the endpoint needs the plugin).
    r = s.get(f"{WP_BASE}/wp-json/redirection/v1/export/all/json", timeout=60)
    if r.ok:
        try:
            data = r.json()
        except ValueError:
            data = {"raw": r.text}
        with open(os.path.join(work, "wp_redirection.json"), "w", encoding="utf-8") as f:
            json.dump(data, f)
        n = len(data.get("redirects", data if isinstance(data, list) else []))
        print(f"fetched Redirection plugin export ({n} rules)")
    else:
        print(f"Redirection export unavailable: HTTP {r.status_code}")


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------

def link_path(link):
    p = urllib.parse.urlparse(link).path
    p = urllib.parse.unquote(p)
    if len(p) > 1 and p.endswith("/"):
        p = p[:-1]
    return p or "/"


def is_excluded(page, by_id):
    cur = page
    seen = set()
    while cur is not None and cur["id"] not in seen:
        seen.add(cur["id"])
        if cur["slug"] in EXCLUDE_ROOT_SLUGS:
            return True
        cur = by_id.get(cur.get("parent") or 0)
    return False


def strip_size_suffix(url):
    return re.sub(r"-\d+x\d+(\.\w+)$", r"\1", url)


class AssetStore:
    def __init__(self, s, work, report):
        self.s = s
        self.dir = os.path.join(work, "assets")
        os.makedirs(self.dir, exist_ok=True)
        self.by_url = {}
        self.names = {}  # name -> content hash
        self.report = report

    def grab(self, url):
        """Download url (preferring the un-resized original) and return the
        flat asset filename, or None when the download fails."""
        if url in self.by_url:
            return self.by_url[url]
        candidates = [strip_size_suffix(url), url] if strip_size_suffix(url) != url else [url]
        for cand in candidates:
            try:
                r = self.s.get(cand, timeout=120)
            except requests.RequestException:
                continue
            if not r.ok or not r.content:
                continue
            name = os.path.basename(urllib.parse.unquote(urllib.parse.urlparse(cand).path))
            name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
            digest = hashlib.sha1(r.content).hexdigest()[:8]
            if name in self.names and self.names[name] != digest:
                stem, ext = os.path.splitext(name)
                name = f"{stem}-{digest}{ext}"
            if name not in self.names:
                with open(os.path.join(self.dir, name), "wb") as f:
                    f.write(r.content)
                self.names[name] = digest
            self.by_url[url] = name
            return name
        self.report.append(f"DOWNLOAD FAILED: {url}")
        self.by_url[url] = None
        return None


VIDEO_RE = re.compile(r"(youtube\.com/embed/|youtube\.com/watch|youtu\.be/|player\.vimeo\.com/video/|vimeo\.com/\d)")


class MediaResolver:
    """Resolve WP attachment IDs (from vc_single_image) to their file URL."""

    def __init__(self, s):
        self.s = s
        self.cache = {}

    def lookup(self, media_id):
        if not media_id or not str(media_id).isdigit():
            return None
        if media_id in self.cache:
            return self.cache[media_id]
        info = None
        try:
            r = self.s.get(f"{WP_BASE}/wp-json/wp/v2/media/{media_id}", timeout=60)
            if r.ok:
                j = r.json()
                if isinstance(j, dict):
                    info = {"url": j.get("source_url", ""), "alt": j.get("alt_text") or ""}
        except requests.RequestException:
            pass
        self.cache[media_id] = info
        return info


# WPBakery attributes arrive wptexturized: quotes are curly, and at this
# stage still HTML-entity-encoded.
SC_QUOTES = "\"“”″′‘’"


def sc_attrs(attr_str):
    import html as html_mod

    attr_str = html_mod.unescape(attr_str)
    out = {}
    for m in re.finditer(rf"(\w+)\s*=\s*[{SC_QUOTES}]([^{SC_QUOTES}]*)[{SC_QUOTES}]", attr_str):
        out[m.group(1)] = m.group(2)
    return out


def expand_shortcodes(html, media, report, slug):
    """WPBakery shortcodes are not expanded in REST output. Images and videos
    carry content and are converted; the layout scaffolding is dropped."""

    def single_image(m):
        attrs = sc_attrs(m.group(1))
        info = media.lookup(attrs.get("image", ""))
        if not info or not info["url"]:
            report.append(f"{slug}: vc_single_image media {attrs.get('image')} unresolved")
            return ""
        img = f'<img src="{info["url"]}" alt="{info["alt"]}">'
        link = attrs.get("link", "")
        if link.startswith("http"):
            return f'<p><a href="{link}">{img}</a></p>'
        return f"<p>{img}</p>"

    def video(m):
        attrs = sc_attrs(m.group(1))
        link = attrs.get("link", "")
        if not VIDEO_RE.search(link):
            report.append(f"{slug}: vc_video without a usable link dropped")
            return ""
        return f'<p><img src="{link}" alt="video"></p>'

    html = re.sub(r"\[vc_single_image([^\]]*)\]", single_image, html)
    html = re.sub(r"\[vc_video([^\]]*)\]", video, html)
    html = re.sub(r"\[/?(?:vc_[a-z_]+|rev_slider)[^\]]*\]", "", html)
    return html


def clean_html(html, assets, media, report, slug):
    html = expand_shortcodes(html, media, report, slug)
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "link", "meta"]):
        tag.decompose()
    # Slider Revolution markup cannot be represented in markdown.
    for tag in soup.select('[class*="rev_slider"], [id*="rev_slider"]'):
        report.append(f"{slug}: dropped Slider Revolution block")
        tag.decompose()
    # Contact Form 7 -> susi's own contact form marker.
    for tag in soup.select("div.wpcf7, form.wpcf7-form"):
        marker = soup.new_tag("p")
        marker.string = "{{contact-form}}"
        tag.replace_with(marker)
        report.append(f"{slug}: replaced contact form with {{{{contact-form}}}}")
    # Video iframes -> susi's image-syntax video embed.
    for tag in soup.find_all("iframe"):
        src = tag.get("src") or ""
        if VIDEO_RE.search(src):
            p = soup.new_tag("p")
            img = soup.new_tag("img", src=src.split("?")[0], alt="video")
            p.append(img)
            tag.replace_with(p)
        else:
            report.append(f"{slug}: dropped iframe {src[:80]}")
            tag.decompose()
    # Images: download, prefer originals, reference by bare asset name.
    for img in soup.find_all("img"):
        src = img.get("src") or img.get("data-src") or ""
        if "/wp-content/" in src:
            name = assets.grab(src)
            if name:
                img["src"] = name
            else:
                img.decompose()
                continue
        for attr in ("srcset", "sizes", "width", "height", "class", "id", "loading", "decoding"):
            if img.has_attr(attr):
                del img[attr]
    # Uploaded files behind links (datasheets, 3D models) come along too.
    for a in soup.find_all("a", href=True):
        if "/wp-content/" in a["href"]:
            name = assets.grab(a["href"])
            if name:
                a["href"] = f"/api/v1/website/assets/{name}"
    if soup.find(attrs={"colspan": True}) or soup.find(attrs={"rowspan": True}):
        report.append(f"{slug}: table uses colspan/rowspan - REVIEW MANUALLY")
    return str(soup)


def rewrite_internal_links(md, link_map):
    def repl(m):
        url = m.group(2)
        parsed = urllib.parse.urlparse(url)
        if parsed.netloc not in ("lp-research.com", "www.lp-research.com"):
            return m.group(0)
        new = link_map.get(link_path(url))
        return f"{m.group(1)}{new}{m.group(3)}" if new else m.group(0)

    # Group 3 keeps an optional markdown title attribute intact.
    return re.sub(r"(\]\()(https?://[^)\s]+)((?:\s+\"[^\"]*\")?\))", repl, md)


def to_markdown(html):
    md = markdownify(html, heading_style="ATX", bullets="-")
    # Empty headings are WPBakery leftovers.
    md = re.sub(r"^#{1,6}\s*$", "", md, flags=re.M)
    md = re.sub(r"\n{3,}", "\n\n", md)
    return md.strip() + "\n"


def cmd_build(work):
    report = []
    s = wp_session()
    with open(os.path.join(work, "wp_pages.json"), encoding="utf-8") as f:
        wp_pages = json.load(f)
    with open(os.path.join(work, "wp_posts.json"), encoding="utf-8") as f:
        wp_posts = json.load(f)

    by_id = {p["id"]: p for p in wp_pages}
    pages = [p for p in wp_pages if not is_excluded(p, by_id) and p["slug"] not in DROPPED]
    skipped = [p["slug"] for p in wp_pages if is_excluded(p, by_id)]
    if skipped:
        report.append(f"skipped (customer area): {', '.join(sorted(skipped))}")
    report.append(f"dropped container pages: {', '.join(sorted(DROPPED))}")

    # Front page: lowest ord so susi picks it as home.
    front_slug = next((p["slug"] for p in pages if link_path(p["link"]) == "/"), None)

    # Flat slug namespace: detect collisions between pages and posts.
    used = {}
    def claim(slug, kind):
        base, n = slug, 2
        while slug in used:
            slug = f"{base}-{n}"
            n += 1
        used[slug] = kind
        if slug != base:
            report.append(f"slug collision: {base} ({kind}) -> {slug}")
        return slug

    items = []  # (kind, wp_obj, new_slug)
    for p in pages:
        items.append(("page", p, claim(p["slug"], "page")))
    for p in wp_posts:
        items.append(("post", p, claim(p["slug"], "post")))

    # Old path -> new path, for internal link rewriting and redirects.
    path_map = {}
    for kind, p, slug in items:
        new = f"/blog/{slug}" if kind == "post" else ("/" if slug == front_slug else f"/{slug}")
        path_map[link_path(p["link"])] = new

    # Standalone redirects: dropped containers, hidden pages' old URLs,
    # category archives, plus the Redirection plugin rules. Built before the
    # page loop so content links can be rewritten through them as well.
    redirects = [{"from_path": f"/category/{c}", "to_path": "/blog"} for c in CATEGORY_SLUGS]
    redirects.extend(EXTRA_REDIRECTS)
    for p in wp_pages:
        if p["slug"] in DROPPED:
            old = link_path(p["link"])
            path_map[old] = DROPPED[p["slug"]]
            redirects.append({"from_path": old, "to_path": DROPPED[p["slug"]]})
    for kind, p, slug in items:
        if kind == "page" and slug in HIDDEN_SLUGS:
            parent = PAGE_LAYOUT[slug][0]
            target = f"/{parent}" if parent else "/"
            old = link_path(p["link"])
            if old != "/":
                path_map[old] = target
                redirects.append({"from_path": old, "to_path": target})
    rp = os.path.join(work, "wp_redirection.json")
    if os.path.exists(rp):
        with open(rp, encoding="utf-8") as f:
            data = json.load(f)
        # The plugin wraps the export in {"data": "<json string>"}.
        if isinstance(data, dict) and isinstance(data.get("data"), str):
            data = json.loads(data["data"])
        rules = data.get("redirects", data if isinstance(data, list) else [])
        for r in rules:
            src = r.get("url") or r.get("source") or ""
            action = r.get("action_data") or {}
            dst = action.get("url") if isinstance(action, dict) else r.get("target")
            if not src or not dst or not r.get("enabled", True) or r.get("regex"):
                if r.get("regex"):
                    report.append(f"redirect rule is regex, skipped: {src}")
                continue
            # Internal targets become paths and follow the new URL layout, so
            # chained legacy rules keep resolving on the migrated site.
            parsed = urllib.parse.urlparse(dst) if dst.startswith("http") else None
            if parsed is None or parsed.netloc in ("lp-research.com", "www.lp-research.com"):
                dst_path = link_path(dst) if parsed else link_path(f"{WP_BASE}{dst}")
                dst = path_map.get(dst_path, dst_path)
            src = link_path(f"{WP_BASE}{src}") if src.startswith("/") else link_path(src)
            if src != "/" and src != dst and src not in path_map:
                redirects.append({"from_path": src, "to_path": dst})

    # Legacy alias paths (redirect sources) also show up in content links;
    # rewrite those straight to their final target. Real page paths win.
    link_map = {r["from_path"]: r["to_path"] for r in redirects}
    link_map.update(path_map)

    parent_slug_of = {}
    for kind, p, slug in items:
        if kind == "page" and p.get("parent"):
            parent = by_id.get(p["parent"])
            if parent and not is_excluded(parent, by_id):
                parent_slug_of[slug] = parent["slug"]

    assets = AssetStore(s, work, report)
    media = MediaResolver(s)
    pages_dir = os.path.join(work, "pages")
    os.makedirs(pages_dir, exist_ok=True)
    # Stale files from an earlier build would be pushed too - clear them.
    for n in os.listdir(pages_dir):
        if n.endswith(".md"):
            os.remove(os.path.join(pages_dir, n))
    manifest = {}
    for kind, p, slug in items:
        title = BeautifulSoup(p["title"]["rendered"], "html.parser").get_text().strip()
        if kind == "page":
            title = TITLE_OVERRIDES.get(slug, title)
        html = clean_html(p["content"]["rendered"], assets, media, report, slug)
        md = rewrite_internal_links(to_markdown(html), link_map)
        # The front page builds its own hero; pages that already open with an
        # H1 keep it instead of doubling up with the title.
        if slug == front_slug or md.startswith("# "):
            body = md
        else:
            body = f"# {title}\n\n{md}"
        with open(os.path.join(pages_dir, f"{slug}.md"), "w", encoding="utf-8", newline="\n") as f:
            f.write(body)
        meta = (p.get("yoast_head_json") or {}).get("description") or ""
        old_path = link_path(p["link"])
        hidden = kind == "page" and slug in HIDDEN_SLUGS
        new_path = path_map[old_path]
        entry = {
            "title": title,
            "ord": 0 if slug == front_slug else (p.get("menu_order") or 0) + 1,
            "meta_description": meta,
            "page_kind": kind,
            "redirect_from": [] if hidden else ([old_path] if old_path not in ("/", new_path) else []),
        }
        if hidden:
            entry["hidden"] = True
        if kind == "post":
            entry["published_at"] = p["date"][:10]
        if slug in parent_slug_of:
            entry["parent_slug"] = parent_slug_of[slug]
        if kind == "page" and slug in PAGE_LAYOUT:
            parent, ordv = PAGE_LAYOUT[slug]
            entry["ord"] = ordv
            if parent:
                entry["parent_slug"] = parent
            else:
                entry.pop("parent_slug", None)
        elif entry.get("parent_slug") in DROPPED:
            del entry["parent_slug"]
        manifest[slug] = entry

    with open(os.path.join(work, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1)

    with open(os.path.join(work, "redirects.json"), "w", encoding="utf-8") as f:
        json.dump(redirects, f, indent=1)

    n_assets = len(assets.names)
    asset_bytes = sum(
        os.path.getsize(os.path.join(assets.dir, n)) for n in os.listdir(assets.dir)
    )
    n_hidden = sum(1 for s, e in manifest.items() if e.get("hidden"))
    summary = (
        f"pages: {sum(1 for k, _, _ in items if k == 'page')} ({n_hidden} hidden), "
        f"posts: {sum(1 for k, _, _ in items if k == 'post')}, "
        f"assets: {n_assets} ({asset_bytes / 1e6:.1f} MB), "
        f"redirects: {len(redirects)} standalone + per-page redirect_from"
    )
    print(summary)
    with open(os.path.join(work, "report.txt"), "w", encoding="utf-8") as f:
        f.write(summary + "\n\n" + "\n".join(report) + "\n")
    print(f"report: {os.path.join(work, 'report.txt')} ({len(report)} notes)")


# ---------------------------------------------------------------------------
# push
# ---------------------------------------------------------------------------

def cmd_push(work, susi, site):
    token = os.environ.get("SUSI_TOKEN")
    if not token:
        sys.exit("Set SUSI_TOKEN (admin JWT or susi_pat_ token)")
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {token}"
    import_url = f"{susi}/api/v1/website/import?site={site}"

    # Assets first, chunked to stay under the 100 MB request limit.
    assets_dir = os.path.join(work, "assets")
    names = sorted(os.listdir(assets_dir)) if os.path.isdir(assets_dir) else []
    chunk, size, sent = [], 0, 0
    def flush():
        nonlocal chunk, size, sent
        if not chunk:
            return
        files = [
            ("asset", (n, open(os.path.join(assets_dir, n), "rb")))
            for n in chunk
        ]
        try:
            r = s.post(import_url, files=files, timeout=600)
        finally:
            for _, (_, fh) in files:
                fh.close()
        r.raise_for_status()
        sent += len(chunk)
        print(f"assets: {sent}/{len(names)}")
        chunk, size = [], 0
    for n in names:
        sz = os.path.getsize(os.path.join(assets_dir, n))
        if chunk and size + sz > POSTS_PER_IMPORT_CHUNK_BYTES:
            flush()
        chunk.append(n)
        size += sz
    flush()

    # All pages + manifest in one request (markdown is small).
    with open(os.path.join(work, "manifest.json"), encoding="utf-8") as f:
        manifest = f.read()
    pages_dir = os.path.join(work, "pages")
    files = [("manifest", (None, manifest))]
    for n in sorted(os.listdir(pages_dir)):
        files.append(("page", (n, open(os.path.join(pages_dir, n), "rb"))))
    try:
        r = s.post(import_url, files=files, timeout=600)
    finally:
        for key, v in files:
            if key == "page":
                v[1].close()
    r.raise_for_status()
    print(f"pages: {r.json()}")

    with open(os.path.join(work, "redirects.json"), encoding="utf-8") as f:
        redirects = json.load(f)
    r = s.post(
        f"{susi}/api/v1/website/redirects/import?site={site}",
        json={"redirects": redirects},
        timeout=120,
    )
    r.raise_for_status()
    print(f"redirects: {r.json()}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["fetch", "build", "push"])
    ap.add_argument("--work", default="wp_migrate_out")
    ap.add_argument("--susi", default="http://127.0.0.1:3199")
    ap.add_argument("--site", default="lpr")
    args = ap.parse_args()
    if args.step == "fetch":
        cmd_fetch(args.work)
    elif args.step == "build":
        cmd_build(args.work)
    else:
        cmd_push(args.work, args.susi.rstrip("/"), args.site)


if __name__ == "__main__":
    main()
