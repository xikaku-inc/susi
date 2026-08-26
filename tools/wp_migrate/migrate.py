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
    # System-level products the original menu never exposed; the Technology
    # page that linked them is retired.
    "lpnav", "motion-capture-system-lpmocap", "lpiotsolution",
}
# Retired pages keep their content but 301 to a replacement and drop out of
# nav, sitemap and llms.txt. The Technology page was a link list into the blog.
RETIRED = {"sensor-fusion-solutions": "/blog"}
# Images dropped outright, by file name: a 10 MB photo that sat among the
# customer logos.
DROP_IMAGES = {"Siemens.png"}
# Pages folded into one, target slug -> (title, [source slugs in order]). The
# sources 301 to the target and their headings are demoted one level.
MERGED_PAGES = {"legal": ("Legal", ["software-eula", "terms-of-service"])}
MERGED_SOURCES = {src: tgt for tgt, (_, srcs) in MERGED_PAGES.items() for src in srcs}
# Pages whose run of image links becomes a borderless grid, slug -> columns.
# Site images are block-level, so a plain list of logos stacks vertically.
LOGO_GRID_PAGES = {"customers": 5}
# Overview pages whose product blocks (image, linked heading, bullet specs)
# become cards side by side, slug -> columns.
PRODUCT_GRID_PAGES = {
    "inertial-measurement-units-imu": 2,
    "vr-ar-tracking-solutions-lpvr": 2,
}
# The home page was a Slider Revolution hero that markdown cannot carry, so it
# is rebuilt here in the house style: theme-aware logo, intro, product cards.
# The copy comes from the site's own about and overview pages.
HOME_MD = """\
![LP-Research](/static/logo-dark.png?v=2){width=380px .logo-dark} \
![LP-Research](/static/logo.png?v=2){width=380px .logo-light}

**LP-Research develops inertial measurement units and the sensor fusion \
software that turns their data into reliable orientation and position.**

Our sensors and algorithms are used in automotive, aerospace, robotics, \
industrial and mixed reality applications worldwide, from single OEM modules \
to complete tracking systems - with full technical support from one supplier.

[**Read the latest from our lab on the Blog**](/blog)

## Products

|  |  |
| --- | --- |
| ![Inertial Measurement Units](Sensor-whiteBG.png){width=100%} \
**[Inertial Measurement Units](/inertial-measurement-units-imu)** - fast and \
accurate 3D orientation sensing, in a range of communication interfaces and \
enclosure options, from OEM boards to IP67 units with GNSS. | \
![Mixed Reality Tracking](LP-Webpage-img-etc.png){width=100%} \
**[Mixed Reality Tracking](/vr-ar-tracking-solutions-lpvr)** - low-latency \
LPVR tracking for virtual and augmented reality, in vehicles, large spaces \
and motion simulators. |

## [Contact Us](/contact)

Contact us anytime for support inquiries or direct orders. We are happy to \
help you find the sensor system that is best suitable for your application.

## [Support](https://lp-research.atlassian.net/wiki/spaces/LKB/overview)

The connection to our customers doesn't end with the delivery of a product. \
We understand that thorough support for our products and services is essential.

## [Order](/distributors)

Check our list of distributors to find our components and solutions in your \
area. You can also order directly through our Zenshin Tech online shop.
"""
PAGE_BODY_OVERRIDES = {"lp-research": HOME_MD}
# Same for pages built of portrait + name + role blocks, slug -> columns.
PEOPLE_GRID_PAGES = {"about-us-lp-research": 3}
# Sensor detail pages open with photo + variant-name heading repeated
# (RS232 / CAN / RS485, ...) - same shape, so the same grid treatment. Pages
# with fewer than two such blocks pass through untouched.
VARIANT_GRID_COLUMNS = 2
# Page tree, mirroring the original WordPress header menu (WP REST menu id 3):
# only the pages that menu exposes are top level. Everything else hangs off the
# page that links to it on the live site - product detail pages under their
# overview, LPNAV/LPMOCAP/LPIOT under Technology, which is where the live
# sensor-fusion page links them. slug -> (parent_slug or None, ord).
PAGE_LAYOUT = {
    "lp-research": (None, 0),
    "sensor-fusion-solutions": (None, 10),
    "inertial-measurement-units-imu": (None, 20),
    "vr-ar-tracking-solutions-lpvr": (None, 30),
    "distributors": (None, 40),
    "legal": (None, 50),
    "about-us-lp-research": (None, 70),
    "contact": (None, 80),
    "customers": (None, 90),
    # Product children share one ord, so the sidebar sorts them by title.
    "lpms-b2": ("inertial-measurement-units-imu", 10),
    "lpms-u3-usb-and-can-bus-imu": ("inertial-measurement-units-imu", 10),
    "lpms-al3-9-axis-imu-sensor": ("inertial-measurement-units-imu", 10),
    "lpms-ig1": ("inertial-measurement-units-imu", 10),
    "lpms-ig1p": ("inertial-measurement-units-imu", 10),
    "lpms-ig1w": ("inertial-measurement-units-imu", 10),
    "lpms-nav3": ("inertial-measurement-units-imu", 10),
    "lpms-hr": ("inertial-measurement-units-imu", 10),
    "lpms-curs3-oem-9-axis-imu-ahrs-usb-can-uart": ("inertial-measurement-units-imu", 10),
    "9-axis-usb-and-can-bus-imu-lpmsu2-series": ("inertial-measurement-units-imu", 10),
    "lpms-me1": ("inertial-measurement-units-imu", 10),
    "lpms-inc1": ("inertial-measurement-units-imu", 10),
    "lpvr-cad": ("vr-ar-tracking-solutions-lpvr", 10),
    "lpvr-duo": ("vr-ar-tracking-solutions-lpvr", 10),
    "lpvr-air": ("vr-ar-tracking-solutions-lpvr", 10),
    "lpvr-pos": ("vr-ar-tracking-solutions-lpvr", 10),
    # Hidden legacy pages hang off a top-level parent so that unhiding one puts
    # it straight into the nav (the sidebar only nests two levels deep).
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
    "lpms-b2-holder": ("inertial-measurement-units-imu", 500),
    "lpnav": ("inertial-measurement-units-imu", 500),
    "motion-capture-system-lpmocap": ("inertial-measurement-units-imu", 500),
    "lpiotsolution": ("inertial-measurement-units-imu", 500),
    "packaging-environment-guide-eu": (None, 990),
}
# Nav labels. Menu pages take the original menu's own label; product pages get
# their short name. The body keeps its keyword-rich heading either way.
TITLE_OVERRIDES = {
    "lp-research": "Home",
    "sensor-fusion-solutions": "Technology",
    "inertial-measurement-units-imu": "Inertial Measurement Units",
    "vr-ar-tracking-solutions-lpvr": "Mixed Reality Tracking",
    "distributors": "Distributors",
    "software-eula": "Software EULA",
    "terms-of-service": "Hardware Terms of Service",
    "about-us-lp-research": "About Us",
    "contact": "Contact",
    "customers": "Our Customers",
    "lpnav": "LPNAV - AGV Positioning",
    "motion-capture-system-lpmocap": "LPMOCAP - Motion Capture",
    "lpiotsolution": "LPIOT - Industrial Monitoring",
    "lpms-inc1": "LPMS-INC1",
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
# Sidebar groups; Home is the only ungrouped page and renders above them.
# Items are listed alphabetically by the label the sidebar shows.
NAV_STRUCTURE = [
    {"title": "Product", "items": [
        "inertial-measurement-units-imu",
        "vr-ar-tracking-solutions-lpvr",
    ]},
    {"title": "Technology", "items": [
        "__blog__",
        "customers",
    ]},
    {"title": "Order", "items": [
        "distributors",
        "legal",
        {"title": "Online Shop", "url": "https://zenshin-tech.com"},
    ]},
    {"title": "Company", "items": [
        "about-us-lp-research",
        "contact",
    ]},
]
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
    # The Redirection plugin covered this family with a regex rule, which susi's
    # exact-match map cannot express - list the children instead.
    {"from_path": "/products/lpvr-virtual-reality/lpvr-air", "to_path": "/lpvr-air"},
    {"from_path": "/products/lpvr-virtual-reality/lpvr-duo", "to_path": "/lpvr-duo"},
    {"from_path": "/products/lpvr-virtual-reality/lpvr-cad", "to_path": "/lpvr-cad"},
    {"from_path": "/products/lpvr-virtual-reality/lpvr-pos", "to_path": "/lpvr-pos"},
]
# Old category archives had numbered pages; the blog index keeps ?page=.
CATEGORY_ARCHIVE_PAGES = 10


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
        # Reuse an earlier build's downloads: rebuilding the bundle otherwise
        # re-fetches every asset from WordPress.
        self.index_path = os.path.join(work, "assets_index.json")
        if os.path.exists(self.index_path):
            with open(self.index_path, encoding="utf-8") as f:
                cached = json.load(f)
            # Match the directory listing exactly: os.path.exists ignores case
            # on Windows and would keep an entry whose file is really another.
            on_disk = set(os.listdir(self.dir))
            self.names = {
                n: d for n, d in cached.get("names", {}).items() if n in on_disk
            }
            self.by_url = {
                u: n for u, n in cached.get("by_url", {}).items() if n in self.names
            }

    def save(self):
        with open(self.index_path, "w", encoding="utf-8") as f:
            json.dump({"by_url": self.by_url, "names": self.names}, f, indent=1)

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
            # Compare case-insensitively: WordPress serves Siemens.png and
            # siemens.png as different images, but they are one file on a
            # Windows build host - and 404 on the Linux server afterwards.
            taken = {n.lower(): d for n, d in self.names.items()}
            if taken.get(name.lower(), digest) != digest:
                stem, ext = os.path.splitext(name)
                name = f"{stem}-{digest}{ext}"
            if name.lower() not in taken:
                with open(os.path.join(self.dir, name), "wb") as f:
                    f.write(r.content)
                self.names[name] = digest
            self.by_url[url] = name
            return name
        self.report.append(f"DOWNLOAD FAILED: {url}")
        return None


VIDEO_RE = re.compile(r"(youtube\.com/embed/|youtube\.com/watch|youtu\.be/|player\.vimeo\.com/video/|vimeo\.com/\d)")


class MediaResolver:
    """Resolve WP attachment IDs (from vc_single_image) to their file URL."""

    def __init__(self, s, work=None):
        self.s = s
        self.cache = {}
        # Several hundred lookups per build, one HTTP round trip each.
        self.path = os.path.join(work, "media_index.json") if work else None
        if self.path and os.path.exists(self.path):
            with open(self.path, encoding="utf-8") as f:
                self.cache = json.load(f)

    def save(self):
        if self.path:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, indent=1)

    def lookup(self, media_id):
        if not media_id or not str(media_id).isdigit():
            return None
        media_id = str(media_id)
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
        base = os.path.basename(urllib.parse.urlparse(strip_size_suffix(src)).path)
        if base in DROP_IMAGES:
            report.append(f"{slug}: dropped image {base}")
            img.decompose()
            continue
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
    def absolute(m):
        url = m.group(2)
        parsed = urllib.parse.urlparse(url)
        if parsed.netloc not in ("lp-research.com", "www.lp-research.com"):
            return m.group(0)
        new = link_map.get(link_path(url))
        return f"{m.group(1)}{new}{m.group(3)}" if new else m.group(0)

    def rooted(m):
        new = link_map.get(link_path(m.group(2)))
        return f"{m.group(1)}{new}{m.group(3)}" if new else m.group(0)

    # Group 3 keeps an optional markdown title attribute intact. Root-relative
    # hrefs are rewritten too - WordPress content mixes both forms, and some
    # links carry a stray space after the opening paren.
    md = re.sub(r"(\]\()\s*(https?://[^)\s]+)((?:\s+\"[^\"]*\")?\))", absolute, md)
    return re.sub(r"(\]\()\s*(/[^)\s]*)((?:\s+\"[^\"]*\")?\))", rooted, md)


LOGO_LINK_RE = re.compile(r"^\[!\[([^\]]*)\]\(([^)\s]+)\)\]\(([^)\s]+)\)$")


def brand_from_file(name):
    """Alt text from a logo's file name: Hyundai-1-025f36a4.png -> Hyundai."""
    stem = os.path.splitext(name)[0]
    stem = re.sub(r"-(?:\d+|[0-9a-f]{8})$", "", stem)
    stem = re.sub(r"-(?:\d+|[0-9a-f]{8})$", "", stem)
    return " ".join(w.capitalize() if w.islower() else w for w in stem.split("-"))


def logo_grid(md, columns):
    """Turn a run of image links into a table with an empty header row, which
    the site renders as a borderless grid - block images would stack."""
    lines = md.split("\n")
    hits = [i for i, l in enumerate(lines) if LOGO_LINK_RE.match(l.strip())]
    if len(hits) < columns:
        return md
    start, end = hits[0], hits[-1]
    cells = []
    for i in hits:
        m = LOGO_LINK_RE.match(lines[i].strip())
        alt = m.group(1) or brand_from_file(m.group(2))
        cells.append(f"[![{alt}]({m.group(2)})" + "{width=100%}" + f"]({m.group(3)})")
    rows = ["| " + " | ".join(cells[i:i + columns]) + " |" for i in range(0, len(cells), columns)]
    if len(cells) % columns:
        rows[-1] = rows[-1][:-1] + "| " * (columns - len(cells) % columns) + "|"
    table = ["|" + "  |" * columns, "|" + " --- |" * columns] + rows
    return "\n".join(lines[:start] + table + lines[end + 1:])


CARD_IMG_RE = re.compile(r"^\[?!\[([^\]]*)\]\(([^)\s]+)\)(?:\]\([^)\s]+\))?$")
CARD_HEAD_RE = re.compile(r"^#{2,6}\s+\[([^\]]+)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)$")


def product_grid(md, columns):
    """Lay product blocks - image, linked heading, bullet specs - out as cards
    side by side, keeping the section headings that group them."""
    lines = md.split("\n")
    out, i = [], 0
    while i < len(lines):
        cards, j = [], i
        while True:
            k = _next_content(lines, j)
            if k >= len(lines):
                break
            img = CARD_IMG_RE.match(lines[k].strip())
            k2 = _next_content(lines, k + 1) if img else k
            head = CARD_HEAD_RE.match(lines[k2].strip()) if k2 < len(lines) else None
            if not head:
                break
            k = _next_content(lines, k2 + 1)
            specs = []
            while k < len(lines) and lines[k].strip().startswith("- "):
                specs.append(lines[k].strip()[2:].strip())
                k += 1
            cards.append((img.group(1) if img else "", img.group(2) if img else "",
                          head.group(1), head.group(2), specs))
            j = k
        if not cards:
            out.append(lines[i])
            i += 1
            continue
        rows = []
        for c in range(0, len(cards), columns):
            chunk = cards[c:c + columns]
            cells = []
            for alt, src, name, url, specs in chunk:
                cell = f"![{alt or name}]({src})" + "{width=100%} " if src else ""
                cell += f"**[{name}]({url})**"
                if specs:
                    cell += " - " + " · ".join(specs)
                cells.append(cell)
            cells += [""] * (columns - len(chunk))
            rows.append("| " + " | ".join(cells) + " |")
        # One table per run, so every card keeps the same column width.
        out += ["", "|" + "  |" * columns, "|" + " --- |" * columns] + rows + [""]
        i = j
    return "\n".join(out)


PERSON_IMG_RE = re.compile(r"^!\[([^\]]*)\]\(([^)\s]+)\)(?:\{[^}]*\})?$")
PERSON_NAME_RE = re.compile(r"^#{3,6}\s+(.+?)\s*$")


def _next_content(lines, i):
    while i < len(lines) and not lines[i].strip():
        i += 1
    return i


def people_grid(md, columns):
    """Portrait, name heading and optional role repeat down the page as full
    width blocks; lay each run out as a grid so the photos sit side by side at
    one size. Each person is a single cell (photo, name, role together) so the
    cards stay intact when the grid reflows on narrow screens."""
    lines = md.split("\n")
    out, i = [], 0
    while i < len(lines):
        run, j = [], i
        while True:
            k = _next_content(lines, j)
            m_img = PERSON_IMG_RE.match(lines[k].strip()) if k < len(lines) else None
            if not m_img:
                break
            k = _next_content(lines, k + 1)
            m_name = PERSON_NAME_RE.match(lines[k].strip()) if k < len(lines) else None
            if not m_name:
                break
            k += 1
            role, k2 = "", _next_content(lines, k)
            if k2 < len(lines) and lines[k2].strip()[:1] not in ("", "#", "!", "|", "-"):
                role, k = lines[k2].strip(), k2 + 1
            run.append((m_img.group(1) or m_name.group(1), m_img.group(2), m_name.group(1), role))
            j = k
        if len(run) < 2:
            out.append(lines[i])
            i += 1
            continue
        cells = []
        for a, u, n, r in run:
            cell = f"![{a}]({u})" + "{width=100%} " + f"**{n}**"
            if r:
                cell += " - " + r
            cells.append(cell)
        out += ["", "|" + "  |" * columns, "|" + " --- |" * columns]
        for c in range(0, len(cells), columns):
            chunk = cells[c:c + columns]
            chunk += [""] * (columns - len(chunk))
            out.append("| " + " | ".join(chunk) + " |")
        out.append("")
        i = j
    return "\n".join(out)


HEADING_RE = re.compile(r"^(#{1,6})(\s+\S)", re.M)


def strip_heading_emphasis(md):
    """Drop bold inside headings. WPBakery card titles arrive as bold links,
    which reads as double emphasis once they are headings and already linked."""
    return re.sub(
        r"^#{1,6}\s+.*$",
        lambda m: re.sub(r"\*\*(.+?)\*\*", r"\1", m.group(0)),
        md,
        flags=re.M,
    )


def normalize_heading_levels(md):
    """Close gaps in the heading hierarchy. WPBakery card titles land as h5
    under an h2, which reads as a level jump and drops out of the site's
    table of contents (it collects h1-h4). Relative depth is preserved."""
    fences = []
    def stash(m):
        fences.append(m.group(0))
        return f"\x00{len(fences) - 1}\x00"
    body = re.sub(r"```.*?```", stash, md, flags=re.S)

    levels = sorted({len(m.group(1)) for m in HEADING_RE.finditer(body)} - {1})
    if not levels or levels == list(range(2, 2 + len(levels))):
        return md
    mapping = {lvl: i + 2 for i, lvl in enumerate(levels)}
    body = HEADING_RE.sub(
        lambda m: "#" * mapping.get(len(m.group(1)), len(m.group(1))) + m.group(2), body
    )
    return re.sub(r"\x00(\d+)\x00", lambda m: fences[int(m.group(1))], body)


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
    redirects = []
    for c in CATEGORY_SLUGS:
        redirects.append({"from_path": f"/category/{c}", "to_path": "/blog"})
        for n in range(2, CATEGORY_ARCHIVE_PAGES + 1):
            redirects.append({
                "from_path": f"/category/{c}/page/{n}",
                "to_path": f"/blog?page={n}" if c == "blog" else "/blog",
            })
    redirects.extend(EXTRA_REDIRECTS)
    for p in wp_pages:
        if p["slug"] in DROPPED:
            old = link_path(p["link"])
            path_map[old] = DROPPED[p["slug"]]
            redirects.append({"from_path": old, "to_path": DROPPED[p["slug"]]})
    # Links into a hidden or retired page go to its replacement instead: the
    # hidden ones would render an empty shell, the retired ones an extra hop.
    diverted = {}
    for kind, p, slug in items:
        if kind != "page":
            continue
        if slug in HIDDEN_SLUGS:
            parent = PAGE_LAYOUT[slug][0]
            target = f"/{parent}" if parent else "/"
        elif slug in RETIRED:
            target = RETIRED[slug]
        elif slug in MERGED_SOURCES:
            target = f"/{MERGED_SOURCES[slug]}"
        else:
            continue
        diverted[f"/{slug}"] = target
        old = link_path(p["link"])
        if old != "/":
            path_map[old] = target
            redirects.append({"from_path": old, "to_path": target})
        # A merged source no longer exists as a page, so its own path needs a
        # redirect too; hidden pages keep their row and never reach the map.
        if slug in MERGED_SOURCES:
            redirects.append({"from_path": f"/{slug}", "to_path": target})
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
    # rewrite those straight to their final target. Absolute links that already
    # use a new-layout path become relative, and real page paths win over both.
    link_map = {r["from_path"]: r["to_path"] for r in redirects}
    link_map.update({new: new for new in path_map.values()})
    link_map.update(path_map)
    link_map.update(diverted)

    parent_slug_of = {}
    for kind, p, slug in items:
        if kind == "page" and p.get("parent"):
            parent = by_id.get(p["parent"])
            if parent and not is_excluded(parent, by_id):
                parent_slug_of[slug] = parent["slug"]

    assets = AssetStore(s, work, report)
    media = MediaResolver(s, work)
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
        md = normalize_heading_levels(rewrite_internal_links(to_markdown(html), link_map))
        md = strip_heading_emphasis(md)
        if kind == "page" and slug in PAGE_BODY_OVERRIDES:
            md = PAGE_BODY_OVERRIDES[slug]
        if slug in PRODUCT_GRID_PAGES:
            md = product_grid(md, PRODUCT_GRID_PAGES[slug])
        if slug in LOGO_GRID_PAGES:
            md = logo_grid(md, LOGO_GRID_PAGES[slug])
        if slug in PEOPLE_GRID_PAGES:
            md = people_grid(md, PEOPLE_GRID_PAGES[slug])
        if kind == "page" and PAGE_LAYOUT.get(slug, (None,))[0] and slug not in HIDDEN_SLUGS:
            md = people_grid(md, VARIANT_GRID_COLUMNS)
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
            # Hidden and retired pages get their old URL pointed at the
            # replacement instead, as a standalone redirect.
            "redirect_from": [] if (hidden or slug in RETIRED or slug in MERGED_SOURCES)
                             else ([old_path] if old_path not in ("/", new_path) else []),
        }
        if hidden:
            entry["hidden"] = True
        if kind == "page" and slug in RETIRED:
            entry["redirect_to"] = RETIRED[slug]
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

    # Fold merged pages together: one page per target, each source becoming a
    # section whose own headings drop a level.
    for target, (title, sources) in MERGED_PAGES.items():
        sections, metas = [], []
        for src in sources:
            path = os.path.join(pages_dir, f"{src}.md")
            if not os.path.exists(path):
                report.append(f"merge {target}: source {src} missing")
                continue
            with open(path, encoding="utf-8") as f:
                body = f.read()
            body = re.sub(r"\A#\s+.*\n+", "", body)
            body = re.sub(r"^(#{1,5})(\s+\S)", r"#\1\2", body, flags=re.M)
            sections.append(f"## {manifest[src]['title']}\n\n{body.strip()}\n")
            metas.append(manifest[src].get("meta_description", ""))
            os.remove(path)
            del manifest[src]
        with open(os.path.join(pages_dir, f"{target}.md"), "w", encoding="utf-8", newline="\n") as f:
            f.write(f"# {title}\n\n" + "\n".join(sections))
        parent, ordv = PAGE_LAYOUT.get(target, (None, 0))
        manifest[target] = {
            "title": title,
            "ord": ordv,
            "meta_description": next((m for m in metas if m), ""),
            "page_kind": "page",
            "redirect_from": [],
        }
        if parent:
            manifest[target]["parent_slug"] = parent
        report.append(f"merged into {target}: {', '.join(sources)}")

    with open(os.path.join(work, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1)

    with open(os.path.join(work, "redirects.json"), "w", encoding="utf-8") as f:
        json.dump(redirects, f, indent=1)

    with open(os.path.join(work, "settings.json"), "w", encoding="utf-8") as f:
        json.dump({"nav_structure": json.dumps(NAV_STRUCTURE, ensure_ascii=False)}, f, indent=1)

    assets.save()
    media.save()
    n_assets = len(assets.names)
    asset_bytes = sum(
        os.path.getsize(os.path.join(assets.dir, n)) for n in os.listdir(assets.dir)
    )
    n_hidden = sum(1 for s, e in manifest.items() if e.get("hidden"))
    n_retired = sum(1 for s, e in manifest.items() if e.get("redirect_to"))
    summary = (
        f"pages: {sum(1 for k, _, _ in items if k == 'page')} "
        f"({n_hidden} hidden, {n_retired} retired), "
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

def cmd_push(work, susi, site, all_assets=False):
    token = os.environ.get("SUSI_TOKEN")
    if not token:
        sys.exit("Set SUSI_TOKEN (admin JWT or susi_pat_ token)")
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {token}"
    import_url = f"{susi}/api/v1/website/import?site={site}"

    # Assets first, chunked to stay under the 100 MB request limit. Anything
    # already on the target with the same size is left alone - re-pushing a
    # bundle otherwise re-uploads every megabyte.
    assets_dir = os.path.join(work, "assets")
    names = sorted(os.listdir(assets_dir)) if os.path.isdir(assets_dir) else []
    if not all_assets:
        r = s.get(f"{susi}/api/v1/website/pages?site={site}", timeout=120)
        r.raise_for_status()
        have = {a["name"]: a["size"] for a in r.json().get("assets", [])}
        skip = [n for n in names
                if have.get(n) == os.path.getsize(os.path.join(assets_dir, n))]
        names = [n for n in names if n not in set(skip)]
        print(f"assets: {len(skip)} already on target, {len(names)} to upload")
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

    with open(os.path.join(work, "settings.json"), encoding="utf-8") as f:
        settings = json.load(f)
    r = s.put(f"{susi}/api/v1/site/admin/settings?site={site}", json=settings, timeout=60)
    r.raise_for_status()
    print(f"settings: {sorted(settings)}")


# ---------------------------------------------------------------------------
# Japanese site (fetch-ja / build-ja): the /ja/ translation of the site,
# mirroring the English curation. Every Japanese page is linked to the final
# susi slug of its English partner (translation_of), which drives hreflang
# pairs and the translated sidebar. Slugs are kept verbatim - including
# Japanese-character slugs - so today's ranking /ja/ URLs survive.
# ---------------------------------------------------------------------------

JA = "ja"
# ja slug -> final English susi slug. Only 1:1 partners are listed; ja-only
# legacy pages stay unlinked (and hidden).
JA_TRANSLATION_OF = {
    "lp-research": "lp-research",
    "inertial-measurement-unit-imu-series-2": "inertial-measurement-units-imu",
    "vrトラッキング-ハイブリッドシステム": "vr-ar-tracking-solutions-lpvr",
    "lpms-hr-jp": "lpms-hr",
    "lpms-curs3-oem-9-axis-imu-sensor": "lpms-curs3-oem-9-axis-imu-ahrs-usb-can-uart",
    "lpms-ig1p-jp": "lpms-ig1p",
    "lpms-nav3-robot-navigation-imu-sensor": "lpms-nav3",
    "lpms-al3-series": "lpms-al3-9-axis-imu-sensor",
    "lpms-u3-9-axis-imu": "lpms-u3-usb-and-can-bus-imu",
    "lpms-ig1-9-axis-imu-sensor": "lpms-ig1",
    "lpms-ig1w": "lpms-ig1w",
    "lpms-inc1": "lpms-inc1",
    "lpms-b2-bluetooth-imu-sensor": "lpms-b2",
    "lpms-cu2-jp": "9-axis-usb-and-can-bus-imu-lpmsu2-series",
    "lpms-me1": "lpms-me1",
    "lpvr-cad": "lpvr-cad",
    "lpvr-duo": "lpvr-duo",
    "lpvr-air": "lpvr-air",
    "lpvr-pos": "lpvr-pos",
    "lpnav": "lpnav",
    "モーションキャプチャ-システム-lpmocap": "motion-capture-system-lpmocap",
    "lpiotsolution-industrial-monitoring-automation": "lpiotsolution",
    "高精度rs422対応imuセンサー": "lpms-nav2-rs422",
    "lpms-nav2-rs232": "lpms-nav2-rs232",
    "lpms-usbal2": "lpms-usbal",
    "lpms-rs232al2-9-axis-imu-ahrs-motion-sensor-with-rs232-connectivity-and-waterproof-housing":
        "9-axis-waterproof-imu-lpms-al2-series",
    "lp-researchについて": "about-us-lp-research",
    "contact-lp-research": "contact",
    "lp-research-customers": "customers",
    "distributors-lp-research": "distributors",
    "terms-of-service": "hardware-terms",
    "センサーフュージョンソリューション": "sensor-fusion-solutions",
}
# Empty WordPress container pages, ja slug -> redirect target (mirrors the
# English DROPPED decisions; targets are percent-encoded for the 301 header).
JA_DROPPED = {
    "product": "/ja",
    "技術紹介": "/ja/blog",
    "注文": "/ja/distributors-lp-research",
    "会社情報": "/ja/lp-research%E3%81%AB%E3%81%A4%E3%81%84%E3%81%A6",
}
# Hidden beyond the mirrored English state: the stale duplicate of the about
# page and untranslated legacy product pages with no 1:1 English partner.
JA_HIDDEN_EXTRA = {"about-us", "lpms-uttl2", "lpms-urs2"}
# The Technology cluster is retired like its English partner: content kept,
# URL 301s to the blog.
JA_RETIRED = {"センサーフュージョンソリューション": "/ja/blog"}
# Nav labels (the body keeps its own keyword-rich heading).
JA_TITLE_OVERRIDES = {
    "lp-research": "ホーム",
    "inertial-measurement-unit-imu-series-2": "慣性計測装置（IMU）",
    "vrトラッキング-ハイブリッドシステム": "VR/ARトラッキング",
    "lp-researchについて": "会社概要",
    "contact-lp-research": "お問い合わせ",
    "lp-research-customers": "取引先一覧",
    "distributors-lp-research": "代理店",
    "terms-of-service": "ハードウェア利用規約",
    "privacy": "プライバシーポリシー",
    "imprint": "運営者情報",
    "software-eula": "ソフトウェア使用許諾契約",
    "センサーフュージョンソリューション": "技術紹介",
    "lpms-hr-jp": "LPMS-HR",
    "lpms-curs3-oem-9-axis-imu-sensor": "LPMS-CURS3",
    "lpms-ig1p-jp": "LPMS-IG1P",
    "lpms-nav3-robot-navigation-imu-sensor": "LPMS-NAV3",
    "lpms-al3-series": "LPMS-AL3",
    "lpms-u3-9-axis-imu": "LPMS-U3",
    "lpms-ig1-9-axis-imu-sensor": "LPMS-IG1",
    "lpms-ig1w": "LPMS-IG1W",
    "lpms-inc1": "LPMS-INC1",
    "lpms-b2-bluetooth-imu-sensor": "LPMS-B2",
    "lpms-cu2-jp": "LPMS-U2",
    "lpms-me1": "LPMS-ME1",
    "lpvr-cad": "LPVR-CAD",
    "lpvr-duo": "LPVR-DUO",
    "lpvr-air": "LPVR-AIR",
    "lpvr-pos": "LPVR-POS",
    "lpnav": "LPNAV",
    "モーションキャプチャ-システム-lpmocap": "LPMOCAP",
    "lpiotsolution-industrial-monitoring-automation": "LPIOT",
}
# The Japanese home, rebuilt like the English one (the WP original is a
# Slider Revolution hero markdown cannot carry).
JA_HOME_MD = """\
![LP-Research](/static/logo-dark.png?v=2){width=380px .logo-dark} \
![LP-Research](/static/logo.png?v=2){width=380px .logo-light}

**LP-RESEARCHは、慣性計測装置（IMU）と、そのデータを信頼性の高い姿勢・位置情報に変える\
センサーフュージョン・ソフトウェアを開発しています。**

当社のセンサーとアルゴリズムは、自動車、航空宇宙、ロボティクス、産業機器、\
複合現実（MR）など、世界中のさまざまな分野で採用されています。単体のOEMモジュールから\
完全なトラッキングシステムまで、一貫した技術サポートとともにワンストップでご提供します。

[**ブログで最新の研究開発情報を読む**](/ja/blog)

## 製品

|  |  |
| --- | --- |
| ![慣性計測装置（IMU）](Sensor-whiteBG.png){width=100%} \
**[慣性計測装置（IMU）](/ja/inertial-measurement-unit-imu-series-2)** - \
高速かつ高精度な3D姿勢センシング。OEMボードからGNSS搭載のIP67筐体まで、\
多彩な通信インターフェースと筐体オプションをご用意しています。 | \
![VR/ARトラッキング](LP-Webpage-img-etc.png){width=100%} \
**[VR/ARトラッキング](/ja/vrトラッキング-ハイブリッドシステム)** - \
車載、大空間、モーションシミュレーター向けの低遅延LPVRトラッキング。 |

## [お問い合わせ](/ja/contact-lp-research)

サポートに関するご相談や直接のご注文など、いつでもお気軽にお問い合わせください。\
お客様の用途に最適なセンサーシステムをご提案します。

## [サポート](https://lp-research.atlassian.net/wiki/spaces/LKB/overview)

お客様とのつながりは、製品の納品で終わりではありません。製品とサービスへの充実した\
サポートこそが重要だと考えています。

## [ご注文](/ja/distributors-lp-research)

お近くの販売代理店は代理店一覧をご覧ください。Zenshin Techオンラインショップから\
直接ご注文いただくことも可能です。
"""
JA_PAGE_BODY_OVERRIDES = {"lp-research": JA_HOME_MD}
# Recurring English section headings on the Japanese pages, translated
# globally (exact heading-line matches).
JA_HEADING_MAP = {
    "Downloads": "ダウンロード",
    "Specifications": "仕様",
    "Specification": "仕様",
    "Order": "ご注文",
    "System manual": "システムマニュアル",
    "Applications": "活用事例",
    "Download brochures": "資料ダウンロード",
}
# Old ja URL paths that appear in content links but were never REST-visible
# (WP alias permalinks); mapped for link rewriting AND emitted as redirects.
JA_LINK_ALIASES = {
    "/ja/distributors": "/ja/distributors-lp-research",
    "/ja/contact": "/ja/contact-lp-research",
    "/ja/product/lpvr/lpvr-air": "/ja/lpvr-air",
    "/ja/product/lpmocap": "/ja/inertial-measurement-unit-imu-series-2",
    "/ja/lpiotsolution": "/ja/inertial-measurement-unit-imu-series-2",
    "/ja/vr-large-room-scale-tracking": "/ja/blog/large-scale-vr-tracking-steamvr",
    "/ja/control-of-autonomous-drone-ihsmd": "/ja/blog/control-of-autonomous-drone-ihsmd",
    "/ja/middleware-full-solution-ar-vr": "/ja/blog/middleware-full-solution-ar-vr",
    "/ja/context-analysis": "/ja/blog/context-analysis",
    "/ja/machine-learning-for-context-analysis": "/ja/blog/context-analysis",
    "/ja/lpms-cu-in-eth-zuerich-formula-student-race-car-fluelela":
        "/ja/blog/race-car-stabilization-imu-case-study",
    "/ja/inertial-measurement-unit-imu-series-2/lpms-al3-series": "/ja/lpms-al3-series",
    "/ja/inertial-measurement-unit-imu-series-2/lpms-ig1w": "/ja/lpms-ig1w",
}
# Japanese pages with no WordPress source at all - they exist only as
# hand-maintained translations: slug -> (english partner slug, ord).
JA_EXTRA_PAGES = {
    "privacy": ("privacy", 910),
    "imprint": ("imprint", 920),
    "software-eula": ("software-eula", 50),
}
# Hand-maintained Japanese page bodies (tools/wp_migrate/ja_pages/{slug}.md):
# faithful translations of the English reference pages. When a file exists it
# IS the page - the WordPress content and every transform are skipped.
JA_PAGES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ja_pages")

# Proofreading corrections applied to the converted markdown, slug -> list of
# (exact old, new) replacements. Populated from the language review; a fix
# that no longer matches is reported so silent drift gets noticed.
JA_TEXT_FIXES = {
    "lp-researchについて": [
        ("## The LP-Research Team", "## LP-Researchチーム"),
        ("## With Team Alubi", "## チームAlubiと共に"),
        ("## Leadership Team", "## 経営陣"),
        ("## Scientific Advisors", "## 学術アドバイザー"),
        ("### Prof. Massimiliano Zecca", "### Massimiliano Zecca教授"),
        ("### Prof. Atsuo Takanishi", "### 高西淳夫教授"),
        # A '|' inside these titles split the three-column leadership grid.
        (" - Chief Financial Officer | Co-CEO", " - 最高財務責任者（CFO）／共同CEO"),
        (" - Chief Technology Officer | Co-CEO", " - 最高技術責任者（CTO）／共同CEO"),
        (" - Head of Software Engineering", " - ソフトウェア開発責任者"),
        ("車内VRトラッキングシステムの当機能が、ユーザーに没入感のある体験を提供するために必要不可欠です",
         "車載VRトラッキングシステムのこの機能が、ユーザーに没入感のある体験を提供するうえで欠かせません"),
    ],
    "inertial-measurement-unit-imu-series-2": [
        ("# Inertial Measurement Unit (IMU) Devices", "# 慣性計測装置（IMU）"),
        ("LPMS慣性測定ユニットは、高速で正確な3D方向検知が可能です。",
         "LPMS慣性計測装置（IMU）は、高速かつ高精度な3D姿勢計測が可能です。"),
    ],
    "vrトラッキング-ハイブリッドシステム": [
        ("## Virtual Reality / Augmented Reality Tracking Solutions",
         "## VR・ARトラッキング・ソリューション"),
    ],
    "lpvr-cad": [
        ("トラッキング・　ソリューション", "トラッキング・ソリューション"),
        ("そこで画像処理と信号ルーティングは、さらなる遅延をもたらす可能性があります。",
         "また、画像処理や信号ルーティングによって、さらなる遅延が生じる可能性があります。"),
        ("慣性測定データ", "慣性計測データ"),
    ],
    "terms-of-service": [
        ("## 利用規約\n\n## Refund Policy\n\n**保証及び返品ポリシー**", "## 保証及び返品ポリシー"),
        ("30歴日", "30暦日"),
        ("info  at lp-research.com", "info at lp-research.com"),
        ("国・地域にとよっては", "国・地域によっては"),
        ("梱包しなればなりません", "梱包しなければなりません"),
    ],
    "contact-lp-research": [
        ("〒 106-0046", "〒106-0046"),
    ],
    "distributors-lp-research": [
        ("Last/RM A27", "Flat/RM A27"),
        ("United State of America", "United States of America"),
        ("### アメリカ合衆国/ カナダ/ メキシコ", "### アメリカ合衆国・カナダ・メキシコ"),
        ("Email: <http://www.cyan-rs.com/publics/index/5/>",
         "お問い合わせ: <http://www.cyan-rs.com/publics/index/5/>"),
    ],
    "lp-research-customers": [
        ("# 顧客一覧", "# 取引先一覧"),
    ],
}


def enc_path(path):
    """Percent-encode a path for use in a redirect target (Location header
    values must stay ASCII); already-encoded input passes through."""
    return urllib.parse.quote(urllib.parse.unquote(path), safe="/%?=&")


def wp_session_ja():
    """Like wp_session, but the ja content endpoints are public - fall back
    to an anonymous session when no credentials are set."""
    if os.environ.get("WP_USER") and os.environ.get("WP_APP_PASSWORD"):
        return wp_session()
    s = requests.Session()
    s.headers["User-Agent"] = "susi-migrator/1.0"
    return s


def fetch_all_ja(s, endpoint):
    out = []
    page = 1
    while True:
        r = s.get(
            f"{WP_BASE}/wp-json/wp/v2/{endpoint}",
            params={"per_page": 100, "page": page, "status": "publish", "lang": JA},
            timeout=60,
        )
        if r.status_code == 400:
            break
        r.raise_for_status()
        batch = r.json()
        out.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return out


def cmd_fetch_ja(work):
    s = wp_session_ja()
    os.makedirs(work, exist_ok=True)
    pages = fetch_all_ja(s, "pages")
    posts = fetch_all_ja(s, "posts")
    # English post slugs pair the ja posts (75 of 76 share the slug).
    en_posts = fetch_all(s, "posts")
    print(f"fetched {len(pages)} ja pages, {len(posts)} ja posts, {len(en_posts)} en posts")
    with open(os.path.join(work, "wp_pages_ja.json"), "w", encoding="utf-8") as f:
        json.dump(pages, f)
    with open(os.path.join(work, "wp_posts_ja.json"), "w", encoding="utf-8") as f:
        json.dump(posts, f)
    with open(os.path.join(work, "wp_posts_en_slugs.json"), "w", encoding="utf-8") as f:
        json.dump(sorted(p["slug"] for p in en_posts), f)


def cmd_build_ja(work):
    report = []
    s = wp_session_ja()
    with open(os.path.join(work, "wp_pages_ja.json"), encoding="utf-8") as f:
        wp_pages = json.load(f)
    with open(os.path.join(work, "wp_posts_ja.json"), encoding="utf-8") as f:
        wp_posts = json.load(f)
    with open(os.path.join(work, "wp_posts_en_slugs.json"), encoding="utf-8") as f:
        en_post_slugs = set(json.load(f))

    def deslug(p):
        return urllib.parse.unquote(p["slug"])

    by_id = {p["id"]: p for p in wp_pages}
    pages = [p for p in wp_pages if not is_excluded(p, by_id) and deslug(p) not in JA_DROPPED]
    report.append(f"dropped ja container pages: {', '.join(sorted(JA_DROPPED))}")

    # Mirror the English visibility: a ja page whose partner is hidden in the
    # English curation is hidden too.
    hidden_slugs = set(JA_HIDDEN_EXTRA)
    for ja_slug, en_slug in JA_TRANSLATION_OF.items():
        if en_slug in HIDDEN_SLUGS:
            hidden_slugs.add(ja_slug)

    # Reverse map for parent mirroring: en slug -> ja slug.
    ja_of = {en: ja for ja, en in JA_TRANSLATION_OF.items()}

    front_slug = "lp-research"

    used = {}
    def claim(slug, kind):
        base, n = slug, 2
        while slug in used:
            slug = f"{base}-{n}"
            n += 1
        used[slug] = kind
        if slug != base:
            report.append(f"ja slug collision: {base} ({kind}) -> {slug}")
        return slug

    items = []
    for p in pages:
        items.append(("page", p, claim(deslug(p), "page")))
    for p in wp_posts:
        items.append(("post", p, claim(deslug(p), "post")))

    # Old ja path -> new /ja/ layout, for link rewriting and redirects.
    path_map = {}
    for kind, p, slug in items:
        new = f"/ja/blog/{slug}" if kind == "post" else ("/ja/" if slug == front_slug else f"/ja/{slug}")
        path_map[link_path(p["link"])] = new

    redirects = []
    for c in CATEGORY_SLUGS:
        redirects.append({"from_path": f"/ja/category/{c}", "to_path": "/ja/blog"})
    for p in wp_pages:
        if deslug(p) in JA_DROPPED:
            old = link_path(p["link"])
            path_map[old] = urllib.parse.unquote(JA_DROPPED[deslug(p)])
            redirects.append({"from_path": old, "to_path": JA_DROPPED[deslug(p)]})
    diverted = {}
    for kind, p, slug in items:
        if kind != "page":
            continue
        if slug in hidden_slugs:
            en = JA_TRANSLATION_OF.get(slug)
            parent_en = PAGE_LAYOUT.get(en, (None,))[0] if en else None
            parent_ja = ja_of.get(parent_en) if parent_en else None
            target = f"/ja/{parent_ja}" if parent_ja else "/ja"
        elif slug in JA_RETIRED:
            target = JA_RETIRED[slug]
        else:
            continue
        diverted[f"/ja/{slug}"] = urllib.parse.unquote(target)
        old = link_path(p["link"])
        if old not in ("/", "/ja"):
            path_map[old] = urllib.parse.unquote(target)
            redirects.append({"from_path": old, "to_path": enc_path(target)})

    for src, dst in JA_LINK_ALIASES.items():
        redirects.append({"from_path": src, "to_path": enc_path(dst)})

    link_map = {r["from_path"]: r["to_path"] for r in redirects}
    link_map.update({new: new for new in path_map.values()})
    link_map.update(path_map)
    link_map.update(diverted)
    link_map.update(JA_LINK_ALIASES)

    assets = AssetStore(s, work, report)
    media = MediaResolver(s, work)
    pages_dir = os.path.join(work, "pages")
    os.makedirs(pages_dir, exist_ok=True)
    for n in os.listdir(pages_dir):
        if n.endswith(".md"):
            os.remove(os.path.join(pages_dir, n))

    # Grid treatments mirror the English partner pages.
    en_product_grids = {ja_of.get(en): c for en, c in PRODUCT_GRID_PAGES.items() if ja_of.get(en)}
    en_logo_grids = {ja_of.get(en): c for en, c in LOGO_GRID_PAGES.items() if ja_of.get(en)}
    en_people_grids = {ja_of.get(en): c for en, c in PEOPLE_GRID_PAGES.items() if ja_of.get(en)}

    manifest = {}
    for kind, p, slug in items:
        title = BeautifulSoup(p["title"]["rendered"], "html.parser").get_text().strip()
        if kind == "page":
            title = JA_TITLE_OVERRIDES.get(slug, title)
        en_slug = JA_TRANSLATION_OF.get(slug)
        override_path = os.path.join(JA_PAGES_DIR, f"{slug}.md")
        if kind == "page" and os.path.exists(override_path):
            # Hand-maintained translation of the English reference page - it
            # IS the page; the WordPress content and every transform are
            # skipped.
            with open(override_path, encoding="utf-8") as f:
                md = f.read()
        else:
            html = clean_html(p["content"]["rendered"], assets, media, report, slug)
            md = normalize_heading_levels(rewrite_internal_links(to_markdown(html), link_map))
            md = strip_heading_emphasis(md)
            if kind == "page" and slug in JA_PAGE_BODY_OVERRIDES:
                md = JA_PAGE_BODY_OVERRIDES[slug]
            # Recurring English section headings -> Japanese, heading lines only.
            md = "\n".join(
                re.sub(r"^(#{1,5}) (.+?)\s*$", lambda m: f"{m.group(1)} {JA_HEADING_MAP.get(m.group(2), m.group(2))}", line)
                for line in md.split("\n")
            )
            if slug in en_product_grids:
                md = product_grid(md, en_product_grids[slug])
            if slug in en_logo_grids:
                md = logo_grid(md, en_logo_grids[slug])
            if slug in en_people_grids:
                md = people_grid(md, en_people_grids[slug])
            if (kind == "page" and en_slug and PAGE_LAYOUT.get(en_slug, (None,))[0]
                    and slug not in hidden_slugs):
                md = people_grid(md, VARIANT_GRID_COLUMNS)
            for old, new in JA_TEXT_FIXES.get(slug, []):
                if old not in md:
                    report.append(f"ja fix no longer matches on {slug}: {old[:40]}")
                md = md.replace(old, new)
        if slug == front_slug or md.startswith("# "):
            body = md
        else:
            body = f"# {title}\n\n{md}"
        with open(os.path.join(pages_dir, f"{slug}.md"), "w", encoding="utf-8", newline="\n") as f:
            f.write(body)
        meta = (p.get("yoast_head_json") or {}).get("description") or ""
        old_path = link_path(p["link"])
        hidden = kind == "page" and slug in hidden_slugs
        new_path = path_map[old_path]
        entry = {
            "title": title,
            "ord": 0 if slug == front_slug else (p.get("menu_order") or 0) + 1,
            "meta_description": meta,
            "page_kind": kind,
            "lang": JA,
            # The home serves at /ja/ AND its own slug - no self redirect.
            "redirect_from": [] if (hidden or slug in JA_RETIRED or slug == front_slug)
                             else ([old_path] if old_path not in ("/", "/ja", new_path) else []),
        }
        if hidden:
            entry["hidden"] = True
        if kind == "page" and slug in JA_RETIRED:
            entry["redirect_to"] = JA_RETIRED[slug]
        if kind == "post":
            entry["published_at"] = p["date"][:10]
            if slug in en_post_slugs:
                entry["translation_of"] = slug
        if kind == "page" and en_slug:
            entry["translation_of"] = en_slug
            if en_slug in PAGE_LAYOUT:
                parent_en, ordv = PAGE_LAYOUT[en_slug]
                entry["ord"] = ordv
                parent_ja = ja_of.get(parent_en) if parent_en else None
                if parent_ja:
                    entry["parent_slug"] = parent_ja
        manifest[slug] = entry

    # Pages that exist only as hand-maintained translations (the legal set)
    # join the bundle straight from ja_pages/.
    for slug, (tr, ordv) in JA_EXTRA_PAGES.items():
        src = os.path.join(JA_PAGES_DIR, f"{slug}.md")
        if not os.path.exists(src):
            report.append(f"ja extra page missing: {slug}")
            continue
        with open(src, encoding="utf-8") as f:
            body = f.read()
        with open(os.path.join(pages_dir, f"{slug}.md"), "w", encoding="utf-8", newline="\n") as f:
            f.write(body)
        manifest[slug] = {
            "title": JA_TITLE_OVERRIDES.get(slug, slug),
            "ord": ordv,
            "meta_description": "",
            "page_kind": "page",
            "lang": JA,
            "translation_of": tr,
            "redirect_from": [],
        }

    with open(os.path.join(work, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1)
    with open(os.path.join(work, "redirects.json"), "w", encoding="utf-8") as f:
        json.dump(redirects, f, indent=1)
    # No settings for the ja run - nav_structure is shared with English.
    with open(os.path.join(work, "settings.json"), "w", encoding="utf-8") as f:
        json.dump({}, f)

    assets.save()
    media.save()
    n_hidden = sum(1 for _, e in manifest.items() if e.get("hidden"))
    n_linked = sum(1 for _, e in manifest.items() if e.get("translation_of"))
    summary = (
        f"ja pages: {sum(1 for k, _, _ in items if k == 'page')} ({n_hidden} hidden), "
        f"ja posts: {sum(1 for k, _, _ in items if k == 'post')}, "
        f"linked to en: {n_linked}, "
        f"assets: {len(assets.names)}, redirects: {len(redirects)} standalone"
    )
    print(summary)
    with open(os.path.join(work, "report.txt"), "w", encoding="utf-8") as f:
        f.write(summary + "\n\n" + "\n".join(report) + "\n")
    print(f"report: {os.path.join(work, 'report.txt')} ({len(report)} notes)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["fetch", "build", "push", "fetch-ja", "build-ja"])
    ap.add_argument("--work", default="wp_migrate_out")
    ap.add_argument("--susi", default="http://127.0.0.1:3199")
    ap.add_argument("--site", default="lpr")
    ap.add_argument("--all-assets", action="store_true",
                    help="re-upload every asset instead of only the missing ones")
    args = ap.parse_args()
    if args.step == "fetch":
        cmd_fetch(args.work)
    elif args.step == "fetch-ja":
        cmd_fetch_ja(args.work)
    elif args.step == "build":
        cmd_build(args.work)
    elif args.step == "build-ja":
        cmd_build_ja(args.work)
    else:
        cmd_push(args.work, args.susi.rstrip("/"), args.site, args.all_assets)


if __name__ == "__main__":
    main()
