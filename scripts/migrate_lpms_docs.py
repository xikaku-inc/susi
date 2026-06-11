#!/usr/bin/env python3
"""Migrate the public LPMS Confluence documentation to susi docs.

Stages (each idempotent, controlled by --stage):
  fetch    Download the page tree + storage XHTML + attachments to --cache.
  convert  Convert cached pages to markdown under <cache>/md (+ manifest.json).
  import   Create the 'lpms' product (if needed) and bulk-import pages+assets.
  all      fetch + convert + import.

Usage:
  python migrate_lpms_docs.py --stage all --susi-url https://susi.lp-research.com \
      --username admin --password ... [--cache c:/tmp/lpms_migration]
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import re
import sys
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

WIKI = "https://lp-research.atlassian.net/wiki"
ROOT_PAGE_ID = "1100611840"
SKIP_PAGE_IDS = {"2524610561"}  # LPMS-IG1W manual (Japanese) - not migrated
PRODUCT_SLUG = "lpms"
PRODUCT_NAME = "LPMS"
RELEASE_TAG = "v1.0"
RELEASE_NAME = "LPMS Documentation"
# Absolute asset URL prefix: file links must bypass the renderer's slug routing.
ASSET_URL = f"/api/v1/products/{PRODUCT_SLUG}/docs/{RELEASE_TAG}/assets"

# External PDFs converted to native doc pages (<cache>/pdf_final/<slug>.md +
# <cache>/pdf_assets). Links to these URLs are rewritten to the page slug.
PDF_PAGES = {
    "lpms-nav2-datasheet": {
        "title": "LPMS-NAV2 Datasheet", "parent": "lpms-nav2-series-documentation", "ord": 5,
        "url": "https://lp-research.com/wp-content/uploads/2019/09/20190902LpmsNAV2FlyerEng.pdf"},
    "lpms-nav2-user-manual": {
        "title": "LPMS-NAV2 User Manual", "parent": "lpms-nav2-series-documentation", "ord": 6,
        "url": "https://www.lp-research.com/wp-content/uploads/2017/11/LPMS-NAV2Manual20171025.pdf"},
    "lpms-nav2-hardware-manual": {
        "title": "LPMS-NAV2 Hardware Manual", "parent": "lpms-nav2-series-documentation", "ord": 7,
        "url": "https://lp-research.com/wp-content/uploads/2020/07/20200108LpmsNav2SeriesHardwareManual.pdf"},
    "lpms-ig1-hardware-manual": {
        "title": "LPMS-IG1 Hardware Manual", "parent": "lpms-ig1-series-documentation", "ord": 5,
        "url": "https://lp-research.com/wp-content/uploads/2020/06/20200521LpmsIG1HardwareManual.pdf"},
    "lpms-ig1-quick-start-guide": {
        "title": "LPMS-IG1 Quick Start Guide", "parent": "lpms-ig1-series-documentation", "ord": 6,
        "url": "https://lp-research.com/wp-content/uploads/2020/03/20190801LpmsIG1QuickStartGuide.pdf"},
    "lpms-b2-quick-start-guide": {
        "title": "LPMS-B2 Quick Start Guide", "parent": "lpms2-series-documentation", "ord": 50,
        "url": "https://lp-research.com/wp-content/uploads/2020/10/LpmsB2AppManual20160901.pdf"},
    "lpms-curs2-quick-start-guide": {
        "title": "LPMS-CURS2 Quick Start Guide", "parent": "lpms2-series-documentation", "ord": 51,
        "url": "https://www.lp-research.com/wp-content/uploads/2016/10/LpmsCurs2QuickStartGuide20161013.pdf"},
    "lpms-usbal2-quick-start-guide": {
        "title": "LPMS-USBAL2 Quick Start Guide", "parent": "lpms2-series-documentation", "ord": 52,
        "url": "https://www.lp-research.com/wp-content/uploads/2016/10/LpmsUsbal2QuickStartGuide20161001.pdf"},
    "lpms-me1-manual": {
        "title": "LPMS-ME1 Manual", "parent": "lpms2-series-documentation", "ord": 53,
        "url": "https://lp-research.com/wp-content/uploads/2021/07/20191122LpmsMe1Manual.pdf"},
    "lpms-b2-hardware-manual": {
        "title": "LPMS-B2 Series Hardware Manual", "parent": "lpms2-series-documentation", "ord": 60,
        "url": "https://lp-research.com/wp-content/uploads/2020/03/20200310LpmsB2HardwareManual.pdf"},
    "lpms-u2-hardware-manual": {
        "title": "LPMS-U2 Series Hardware Manual", "parent": "lpms2-series-documentation", "ord": 61,
        "url": "https://lp-research.com/wp-content/uploads/2020/03/20200310LpmsU2SeriesHardwareManual.pdf"},
    "lpms-al2-hardware-manual": {
        "title": "LPMS-AL2 Series Hardware Manual", "parent": "lpms2-series-documentation", "ord": 62,
        "url": "https://lp-research.com/wp-content/uploads/2020/05/2020318LpmsAl2SeriesHardwareManual.pdf"},
    "lpms-me1-hardware-manual": {
        "title": "LPMS-ME1 Hardware Manual", "parent": "lpms2-series-documentation", "ord": 63,
        "url": "https://lp-research.com/wp-content/uploads/2021/07/20200914LpmsMe1HardwareManual.pdf"},
    "lpms-me1-dk-manual": {
        "title": "LPMS-ME1 Development Kit Manual", "parent": "lpms2-series-documentation", "ord": 64,
        "url": "https://lp-research.com/wp-content/uploads/2021/07/20191114LPMS-ME1_DKManual.pdf"},
}
PDF_URL_TO_SLUG = {v["url"]: k for k, v in PDF_PAGES.items()}


def api_get(path: str) -> dict:
    url = WIKI + path
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.load(r)


def download(url: str, dest: Path) -> None:
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as r:
        dest.write_bytes(r.read())


_title_url_cache = {}


def resolve_title_url(title: str, space: str = "LKB"):
    """Resolve a Confluence page title outside the migrated tree to its URL."""
    key = (space, title)
    if key in _title_url_cache:
        return _title_url_cache[key]
    url = None
    try:
        q = urllib.parse.urlencode({"title": title, "spaceKey": space, "type": "page"})
        d = api_get(f"/rest/api/content?{q}")
        if d.get("results"):
            url = WIKI + d["results"][0]["_links"]["webui"]
    except Exception:
        pass
    _title_url_cache[key] = url
    return url


def slugify(title: str) -> str:
    s = unicodedata.normalize("NFKD", title).encode("ascii", "ignore").decode()
    s = re.sub(r"[^a-zA-Z0-9]+", "-", s).strip("-").lower()
    return s or "page"


def fill_cell_image(img_md: str) -> str:
    """Make an image fill its table column (consistent product-table sizing)."""
    return re.sub(r"\{[^}]*\}$", "", img_md) + "{width=100%}"


def join_cell_lines(lines) -> str:
    """lines: [(text, is_list_item)]. Pure multi-item lists get '- ' markers
    so the renderer shows a bullet list; otherwise plain <br> stacking."""
    if len(lines) > 1 and all(li for _, li in lines):
        return "<br>".join("- " + t for t, _ in lines)
    return "<br>".join(t for t, _ in lines)


def text_outside_images(tag):
    """Visible text of a tag excluding anything inside ac:image (captions)."""
    bits = []
    for d in tag.descendants:
        if isinstance(d, NavigableString):
            if any(isinstance(p, Tag) and p.name == "ac:image" for p in d.parents):
                continue
            bits.append(str(d))
    return re.sub(r"\s+", " ", "".join(bits)).replace("|", "\\|").strip()


def heading_anchor(frag: str) -> str:
    """Confluence anchor fragment -> susi heading id (docs.html injectHeadingIds)."""
    s = urllib.parse.unquote(frag).lower()
    s = re.sub(r"[\W_]+", "-", s, flags=re.UNICODE).strip("-")
    return s or "section"


# ---------------------------------------------------------------------------
# Stage: fetch
# ---------------------------------------------------------------------------

def fetch_tree(cache: Path) -> None:
    pages_dir = cache / "pages"
    att_dir = cache / "attachments"
    pages_dir.mkdir(parents=True, exist_ok=True)
    att_dir.mkdir(parents=True, exist_ok=True)

    tree = []  # [{id, title, parent_id, ord}]

    def walk(pid: str, parent_id, ord_: int):
        d = api_get(f"/rest/api/content/{pid}?expand=body.storage")
        title = d["title"]
        tree.append({"id": pid, "title": title, "parent_id": parent_id, "ord": ord_})
        (pages_dir / f"{pid}.json").write_text(
            json.dumps({"id": pid, "title": title, "storage": d["body"]["storage"]["value"]}),
            encoding="utf-8",
        )
        print(f"page  {pid}  {title}")
        # Attachments for this page.
        start = 0
        while True:
            ad = api_get(f"/rest/api/content/{pid}/child/attachment?limit=100&start={start}")
            for att in ad["results"]:
                fname = att["title"]
                dl = att["_links"]["download"]
                page_att = att_dir / pid
                page_att.mkdir(exist_ok=True)
                dest = page_att / fname
                if not dest.exists():
                    try:
                        download(WIKI + dl, dest)
                        print(f"  att {fname} ({dest.stat().st_size} bytes)")
                    except urllib.error.HTTPError as e:
                        print(f"  att {fname} FAILED: {e}")
            if ad["size"] < 100:
                break
            start += 100
        # Children, in Confluence child-position order.
        cd = api_get(f"/rest/api/content/{pid}/child/page?limit=100")
        for n, child in enumerate(cd["results"]):
            if child["id"] in SKIP_PAGE_IDS:
                print(f"skip  {child['id']}  {child['title']}")
                continue
            walk(child["id"], pid, (n + 1) * 10)

    walk(ROOT_PAGE_ID, None, 0)
    (cache / "tree.json").write_text(json.dumps(tree, indent=1), encoding="utf-8")
    print(f"\n{len(tree)} pages fetched")


# ---------------------------------------------------------------------------
# Stage: convert  (Confluence storage XHTML -> susi mini-markdown)
#
# Target renderer constraints (susi docs.html renderMarkdown):
#   - GFM tables only, one line per row; no raw HTML anywhere (it gets escaped)
#   - no nested lists; flat - and 1. lists only
#   - images: ![alt](assetfile){width=N}; YouTube/Vimeo URLs embed as video
#   - internal links: [text](slug)
# ---------------------------------------------------------------------------

from bs4 import BeautifulSoup, NavigableString, Tag  # noqa: E402


class Converter:
    def __init__(self, page_id: str, title_to_slug: dict, id_to_slug: dict,
                 asset_names: dict):
        self.page_id = page_id
        self.title_to_slug = title_to_slug
        self.id_to_slug = id_to_slug
        self.asset_names = asset_names  # (page_id, filename) -> asset file name
        self.used_assets = set()

    # ---- inline ----------------------------------------------------------

    def inline(self, node, in_table=False) -> str:
        """Render children of node as inline markdown text."""
        parts = []
        for c in node.children:
            parts.append(self.inline_one(c, in_table))
        s = "".join(parts)
        return re.sub(r"\s+", " ", s) if in_table else s

    def inline_one(self, c, in_table=False) -> str:
        if isinstance(c, NavigableString):
            t = str(c)
            t = t.replace(" ", " ")
            if in_table:
                t = t.replace("|", "\\|")
            return t
        if not isinstance(c, Tag):
            return ""
        name = c.name
        if name in ("strong", "b"):
            inner = self.inline(c, in_table).strip()
            return f"**{inner}**" if inner else ""
        if name in ("em", "i"):
            inner = self.inline(c, in_table).strip()
            return f"*{inner}*" if inner else ""
        if name == "code":
            inner = c.get_text().strip()
            return f"`{inner}`" if inner else ""
        if name == "br":
            return "<br>" if in_table else "\n"
        if name == "a":
            href = c.get("href", "")
            text = self.inline(c, in_table).strip() or href
            return f"[{text}]({self.map_url(href)})" if href else text
        if name == "ac:link":
            return self.ac_link(c, in_table)
        if name == "ac:image":
            return self.ac_image(c)
        if name == "ri:attachment":
            return ""
        if name == "ac:structured-macro":
            return self.macro_inline(c, in_table)
        if name == "ac:emoticon":
            fallback = c.get("ac:emoji-fallback") or ""
            return fallback
        if name == "time":
            return c.get("datetime", c.get_text())
        if name in ("span", "u", "sub", "sup", "s", "del", "ac:inline-comment-marker"):
            return self.inline(c, in_table)
        # Block element encountered in inline context (e.g. <p> inside table cell).
        return self.inline(c, in_table)

    def map_url(self, href: str) -> str:
        """Map Confluence URLs to susi-internal slugs where possible."""
        norm = re.sub(r"^https?://(www\.)?", "", href)
        for url, slug in PDF_URL_TO_SLUG.items():
            if re.sub(r"^https?://(www\.)?", "", url) == norm:
                return slug
        base, _, frag = href.partition("#")
        if not base and frag:
            return "#" + heading_anchor(frag)
        m = re.search(r"/wiki/spaces/[^/]+/pages/(\d+)", base)
        if m and m.group(1) in self.id_to_slug:
            # Same-page section link -> susi heading anchor; cross-page -> slug.
            if frag and m.group(1) == self.page_id:
                return "#" + heading_anchor(frag)
            return self.id_to_slug[m.group(1)]
        if href.startswith("/wiki/"):
            return WIKI[: -len("/wiki")] + href
        return href

    def ac_link(self, c: Tag, in_table=False) -> str:
        page_ref = c.find("ri:page")
        att_ref = c.find("ri:attachment")
        body = c.find("ac:link-body") or c.find("ac:plain-text-link-body")
        text = body.get_text().strip() if body else ""
        if page_ref is not None:
            title = page_ref.get("ri:content-title", "")
            slug = self.title_to_slug.get(title)
            label = text or title
            if in_table:
                label = label.replace("|", "\\|")
            if slug:
                return f"[{label}]({slug})"
            url = resolve_title_url(title, page_ref.get("ri:space-key", "LKB"))
            return f"[{label}]({url})" if url else label
        if att_ref is not None:
            fname = att_ref.get("ri:filename", "")
            owner = att_ref.find("ri:page")
            owner_id = self.page_id
            if owner is not None and owner.get("ri:content-id"):
                owner_id = owner.get("ri:content-id")
            asset = self.asset_names.get((owner_id, fname)) or self.asset_names.get_by_name(fname)
            label = text or fname
            if in_table:
                label = label.replace("|", "\\|")
            if asset:
                self.used_assets.add(asset)
                return f"[{label}]({ASSET_URL}/{asset})"
            return label
        return text

    def ac_image(self, c: Tag) -> str:
        att = c.find("ri:attachment")
        url_ref = c.find("ri:url")
        width = c.get("ac:width")
        attrs = f"{{width={width}}}" if width else ""
        alt = c.get("ac:alt", "")
        if att is not None:
            fname = att.get("ri:filename", "")
            owner = att.find("ri:page")
            owner_id = self.page_id
            if owner is not None and owner.get("ri:content-id"):
                owner_id = owner.get("ri:content-id")
            asset = self.asset_names.get((owner_id, fname)) or self.asset_names.get_by_name(fname)
            if asset:
                self.used_assets.add(asset)
                return f"![{alt}]({asset}){attrs}"
            return ""
        if url_ref is not None:
            return f"![{alt}]({url_ref.get('ri:value', '')}){attrs}"
        return ""

    def macro_inline(self, c: Tag, in_table=False) -> str:
        name = c.get("ac:name", "")
        if name == "status":
            title = c.find("ac:parameter", {"ac:name": "title"})
            return f"**{title.get_text()}**" if title else ""
        if name in ("view-file", "viewpdf"):
            return self.attachment_link(c)
        body = c.find("ac:rich-text-body")
        if body is not None:
            return self.inline(body, in_table)
        return ""

    def attachment_link(self, c: Tag) -> str:
        att = c.find("ri:attachment")
        if att is None:
            return ""
        fname = att.get("ri:filename", "")
        asset = self.asset_names.get((self.page_id, fname)) or self.asset_names.get_by_name(fname)
        if asset:
            self.used_assets.add(asset)
            return f"[{fname}]({ASSET_URL}/{asset})"
        return fname

    # ---- blocks ----------------------------------------------------------

    def blocks(self, node) -> list:
        out = []
        for c in node.children:
            if isinstance(c, NavigableString):
                if str(c).strip():
                    out.append(str(c).strip())
                continue
            if not isinstance(c, Tag):
                continue
            out.extend(self.block_one(c))
        return out

    def block_one(self, c: Tag) -> list:
        name = c.name
        if name in ("h1", "h2", "h3", "h4", "h5", "h6"):
            level = min(int(name[1]) + 1, 6)  # page title is h1; shift down
            text = self.inline(c).strip().replace("\n", " ")
            return [f"{'#' * level} {text}"] if text else []
        if name == "p":
            return self.para(c)
        if name in ("ul", "ol"):
            return [self.list_block(c, name)]
        if name == "table":
            return self.table(c)
        if name == "blockquote":
            inner = self.blocks(c)
            return ["\n".join("> " + l for b in inner for l in b.split("\n"))]
        if name == "hr":
            return ["---"]
        if name == "pre":
            return [f"```\n{c.get_text().rstrip()}\n```"]
        if name == "ac:structured-macro":
            return self.macro_block(c)
        if name == "ac:layout-section":
            t = self.sensor_gallery_from_layout(c)
            if t is not None:
                return t
            return self.blocks(c)
        if name in ("div", "ac:layout", "ac:layout-cell", "ac:rich-text-body"):
            return self.blocks(c)
        if name == "ac:image":
            s = self.ac_image(c)
            return [s] if s else []
        if name == "ac:link":
            s = self.ac_link(c)
            return [s] if s else []
        if name == "ac:task-list":
            items = []
            for t in c.find_all("ac:task"):
                tb = t.find("ac:task-body")
                if tb is not None:
                    items.append("- " + self.inline(tb).strip())
            return ["\n".join(items)] if items else []
        # Fallback: inline-render.
        s = self.inline(c).strip()
        return [s] if s else []

    def para(self, c: Tag) -> list:
        """A <p> may mix text and images; keep images on their own lines."""
        out = []
        cur = []
        for child in c.children:
            if isinstance(child, Tag) and child.name == "ac:image":
                if cur:
                    txt = re.sub(r"[ \t]+", " ", "".join(cur)).strip()
                    if txt:
                        out.append(txt)
                    cur = []
                img = self.ac_image(child)
                if img:
                    out.append(img)
            else:
                cur.append(self.inline_one(child))
        if cur:
            txt = re.sub(r"[ \t]+", " ", "".join(cur)).strip()
            if txt:
                out.append(txt)
        return out

    def list_block(self, c: Tag, kind: str, depth: int = 0) -> str:
        lines = []
        n = 0
        for li in c.find_all("li", recursive=False):
            n += 1
            # Split nested lists out of the li.
            nested = []
            inline_parts = []
            for child in li.children:
                if isinstance(child, Tag) and child.name in ("ul", "ol"):
                    nested.append(child)
                else:
                    inline_parts.append(self.inline_one(child))
            text = re.sub(r"\s+", " ", "".join(inline_parts)).strip()
            marker = f"{n}." if kind == "ol" else "-"
            # Renderer has no nested lists: flatten with an en-dash prefix.
            prefix = "" if depth == 0 else "– "
            if text:
                lines.append(f"{marker} {prefix}{text}")
            for nl in nested:
                lines.append(self.list_block(nl, nl.name, depth + 1))
        return "\n".join(lines)

    def product_table(self, rows) -> list:
        """rows: [(image_md, names_md)] -> overview-style 2-column table."""
        products = all(n.lstrip("*[- ").startswith("LPMS") for _, n in rows)
        header = ("| **Product Image** | **Product Name** |" if products
                  else "| **Image** | **Description** |")
        out = [header, "|---|---|"]
        for img, names in rows:
            out.append(f"| {fill_cell_image(img)} | {names} |")
        return ["\n".join(out)]

    def sensor_gallery_from_layout(self, section: Tag):
        """A layout section whose every cell is image (+caption) + name list
        becomes an overview-style product table. Returns None if not matching."""
        rows = []
        for cell in section.find_all("ac:layout-cell", recursive=False):
            if not cell.get_text().strip() and cell.find("ac:image") is None:
                continue  # empty filler cell
            imgs = cell.find_all("ac:image")
            lis = cell.find_all("li")
            if len(imgs) != 1 or cell.find("table") is not None:
                return None
            # Anything beyond image + list + captions disqualifies the cell.
            for child in cell.children:
                if isinstance(child, Tag) and child.name not in ("ac:image", "ul", "ol", "p"):
                    return None
                if isinstance(child, Tag) and child.name == "p" and child.get_text().strip():
                    return None
            img_md = self.ac_image(imgs[0])
            names = [self.inline(li, in_table=True).strip() for li in lis]
            names = [n for n in names if n]
            if not names:
                cap = imgs[0].find("ac:caption")
                if cap is not None and cap.get_text().strip():
                    names = [self.inline(cap, in_table=True).strip()]
            if not img_md or not names:
                return None
            rows.append((img_md, join_cell_lines([(n, True) for n in names])))
        return self.product_table(rows) if len(rows) >= 2 else None

    def try_gallery_table(self, c: Tag):
        """A table whose every non-empty cell is image + short label becomes an
        overview-style product table. Returns None if not matching."""
        rows = []
        for tr in c.find_all("tr"):
            for cell in tr.find_all(["th", "td"], recursive=False):
                has_img = cell.find("ac:image") is not None
                if not has_img:
                    if cell.get_text().strip():
                        return None  # text-only cell: a real data table
                    continue
                imgs = cell.find_all("ac:image")
                if len(imgs) != 1 or cell.find("table") is not None:
                    return None
                img_md = self.ac_image(imgs[0])
                lis = cell.find_all("li")
                if lis:
                    names = [self.inline(li, in_table=True).strip() for li in lis]
                    label = join_cell_lines([(n, True) for n in names if n])
                else:
                    label = text_outside_images(cell)
                    if not label:
                        cap = imgs[0].find("ac:caption")
                        label = cap.get_text().strip() if cap is not None else ""
                if not img_md or not label:
                    return None
                rows.append((img_md, label))
        return self.product_table(rows) if len(rows) >= 2 else None

    def table(self, c: Tag) -> list:
        gallery = self.try_gallery_table(c)
        if gallery is not None:
            return gallery
        # Lift headings buried in cells (Confluence detail tables use them as
        # anchor targets) out as real headings so links and the TOC can hit them.
        lifted = []
        for h in c.find_all(["h1", "h2", "h3", "h4", "h5", "h6"]):
            text = self.inline(h).strip().replace("\n", " ")
            if text:
                level = min(int(h.name[1]) + 1, 4)
                lifted.append(f"{'#' * level} {text}")
        rows = []
        for tr in c.find_all("tr"):
            cells = []
            for cell in tr.find_all(["th", "td"], recursive=False):
                txt = self.cell_text(cell)
                cells.append(txt)
            if cells:
                rows.append(cells)
        if not rows:
            return lifted
        ncols = max(len(r) for r in rows)
        for r in rows:
            r.extend([""] * (ncols - len(r)))
        # Single-column "tables" read better as plain blocks.
        if ncols == 1:
            return lifted + [r[0] for r in rows if r[0]]
        out = ["| " + " | ".join(rows[0]) + " |",
               "|" + "---|" * ncols]
        for r in rows[1:]:
            out.append("| " + " | ".join(r) + " |")
        return lifted + ["\n".join(out)]

    def cell_text(self, cell: Tag) -> str:
        """Flatten a table cell to one line; block children stack via <br>.
        A cell that is purely a multi-item list becomes "- a<br>- b" which the
        renderer shows as a real bullet list."""
        lines = []  # (text, is_list_item)
        cur = []

        def flush():
            t = re.sub(r"\s+", " ", "".join(cur)).strip()
            if t:
                lines.append((t, False))
            cur.clear()

        def li_own_text(li):
            bits = []
            for ch in li.children:
                if isinstance(ch, Tag) and ch.name in ("ul", "ol"):
                    continue
                bits.append(self.inline_one(ch, in_table=True))
            return re.sub(r"\s+", " ", "".join(bits)).strip()

        for child in cell.children:
            if isinstance(child, Tag) and child.name in ("ul", "ol"):
                flush()
                lines.extend((i, True) for i in (li_own_text(li) for li in child.find_all("li")) if i)
            elif isinstance(child, Tag) and child.name in ("p", "h1", "h2", "h3", "h4", "h5", "h6"):
                flush()
                cur.append(self.inline(child, in_table=True))
                flush()
            else:
                cur.append(self.inline_one(child, in_table=True))
        flush()
        # An image-only cell fills its column for consistent gallery sizing.
        if len(lines) == 1 and re.fullmatch(r"!\[[^\]]*\]\([^)]+\)(\{[^}]*\})?", lines[0][0]):
            return fill_cell_image(lines[0][0])
        return join_cell_lines(lines)

    def macro_block(self, c: Tag) -> list:
        name = c.get("ac:name", "")
        if name == "code":
            lang_p = c.find("ac:parameter", {"ac:name": "language"})
            lang = lang_p.get_text() if lang_p else ""
            body = c.find("ac:plain-text-body")
            code = body.get_text() if body else ""
            return [f"```{lang}\n{code.rstrip()}\n```"]
        if name in ("info", "note", "tip", "warning", "panel"):
            body = c.find("ac:rich-text-body")
            if body is None:
                return []
            inner = self.blocks(body)
            return ["\n".join("> " + l for b in inner for l in b.split("\n"))]
        if name == "expand":
            title_p = c.find("ac:parameter", {"ac:name": "title"})
            body = c.find("ac:rich-text-body")
            out = []
            if title_p is not None and title_p.get_text().strip():
                out.append(f"**{title_p.get_text().strip()}**")
            if body is not None:
                out.extend(self.blocks(body))
            return out
        if name in ("toc", "children", "pagetree"):
            return ["[TOC]"] if name == "toc" else []
        if name == "view-file" or name == "viewpdf":
            s = self.attachment_link(c)
            return [s] if s else []
        if name == "widget" or name == "iframe":
            url_p = c.find("ac:parameter", {"ac:name": "url"})
            if url_p is not None:
                u = url_p.get_text().strip()
                if "youtube" in u or "youtu.be" in u or "vimeo" in u:
                    return [f"![video]({u})"]
                return [f"[{u}]({u})"]
            return []
        if name in ("anchor", "include", "excerpt-include", "jira", "profile-picture", "recently-updated"):
            return []
        # Unknown macro: render body if any.
        body = c.find("ac:rich-text-body")
        if body is not None:
            return self.blocks(body)
        return []

    def convert(self, storage_html: str) -> str:
        soup = BeautifulSoup(f"<root>{storage_html}</root>", "html.parser")
        root = soup.find("root")
        blocks = self.blocks(root)
        md = "\n\n".join(b.strip() for b in blocks if b.strip())
        md = re.sub(r"\n{3,}", "\n\n", md)
        # Separate directly adjacent links (e.g. two view-file macros in one paragraph).
        md = re.sub(r"\)\[", ") [", md)
        # Merge adjacent gallery tables (split tables in the Confluence source).
        for hdr in ("| **Product Image** | **Product Name** |", "| **Image** | **Description** |"):
            md = md.replace(f"|\n\n{hdr}\n|---|---|\n|", "|\n|")
        return md


class AssetNames(dict):
    """(page_id, filename) -> unique asset name, plus name-only lookup."""

    def __init__(self):
        super().__init__()
        self.by_name = {}

    def add(self, page_id: str, fname: str, asset: str):
        self[(page_id, fname)] = asset
        self.by_name.setdefault(fname, asset)

    def get_by_name(self, fname: str):
        return self.by_name.get(fname)


def asset_name_for(page_id: str, fname: str, taken: set) -> str:
    """Sanitize an attachment file name into a unique asset file name."""
    base = unicodedata.normalize("NFKD", fname).encode("ascii", "ignore").decode()
    base = re.sub(r"[^a-zA-Z0-9._-]+", "-", base).strip("-")
    if not base or base.startswith("."):
        base = "file-" + base
    if "." not in base:
        # Confluence pasted images often have no extension; assume png.
        base += ".png"
    if base.lower() in taken:
        stem, dot, ext = base.rpartition(".")
        base = f"{stem}-{page_id}{dot}{ext}" if stem else f"{page_id}-{base}"
    taken.add(base.lower())
    return base


def convert_all(cache: Path) -> None:
    tree = json.loads((cache / "tree.json").read_text(encoding="utf-8"))
    md_dir = cache / "md"
    md_dir.mkdir(exist_ok=True)
    assets_out = cache / "assets"
    assets_out.mkdir(exist_ok=True)

    # Slug assignment. Root page becomes "overview".
    id_to_slug, title_to_slug = {}, {}
    taken = set()
    for p in tree:
        slug = "overview" if p["id"] == ROOT_PAGE_ID else slugify(p["title"])
        while slug in taken:
            slug += "-2"
        taken.add(slug)
        id_to_slug[p["id"]] = slug
        title_to_slug[p["title"]] = slug

    # Asset name table from the attachments dir.
    att_dir = cache / "attachments"
    names = AssetNames()
    taken_assets = set()
    for page_dir in sorted(att_dir.iterdir()):
        for f in sorted(page_dir.iterdir()):
            asset = asset_name_for(page_dir.name, f.name, taken_assets)
            names.add(page_dir.name, f.name, asset)

    # Manifest: 2-level structure. Series pages -> top level; their children
    # keep them as parent; root page -> "overview" at ord 0.
    manifest = {}
    used_assets = set()
    for p in tree:
        slug = id_to_slug[p["id"]]
        parent = p["parent_id"]
        if p["id"] == ROOT_PAGE_ID:
            parent_slug = None
            ord_ = 0
            title = "Overview"
        elif parent == ROOT_PAGE_ID:
            parent_slug = None  # series pages are top-level section heads
            ord_ = p["ord"]
            title = p["title"]
        else:
            parent_slug = id_to_slug[parent]
            ord_ = p["ord"]
            title = p["title"]
        manifest[slug] = {"title": title, "parent_slug": parent_slug, "ord": ord_}

        data = json.loads((cache / "pages" / f"{p['id']}.json").read_text(encoding="utf-8"))
        conv = Converter(p["id"], title_to_slug, id_to_slug, names)
        md = conv.convert(data["storage"])
        if p["id"] == ROOT_PAGE_ID:
            # Drop the Confluence-specific note about saving pages as PDF.
            md = re.sub(r"^NOTE: The pages in this online documentation[^\n]*\n+", "", md)
        # Fix a source typo on the NAV2 page ("Hardware Manua](...)l").
        md = md.replace("[Hardware Manua](lpms-nav2-hardware-manual)l", "[Hardware Manual](lpms-nav2-hardware-manual)")
        (md_dir / f"{slug}.md").write_text(md, encoding="utf-8")
        used_assets |= conv.used_assets
        print(f"conv  {slug}.md ({len(md)} chars, {len(conv.used_assets)} assets)")

    # Copy only referenced assets into the flat assets dir.
    import shutil
    for (pid, fname), asset in names.items():
        if asset in used_assets:
            src = att_dir / pid / fname
            dst = assets_out / asset
            if src.exists() and not dst.exists():
                shutil.copy2(src, dst)
    (cache / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    n_assets = len(list(assets_out.iterdir()))
    print(f"\n{len(manifest)} pages converted, {n_assets} assets staged")


# ---------------------------------------------------------------------------
# Stage: import
# ---------------------------------------------------------------------------

def susi_request(susi_url: str, method: str, path: str, token: str = None,
                 body: bytes = None, content_type: str = None) -> dict:
    req = urllib.request.Request(susi_url + path, data=body, method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if content_type:
        req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        raise SystemExit(f"{method} {path} -> {e.code}: {detail}")


def susi_login(susi_url: str, username: str, password: str) -> str:
    body = json.dumps({"username": username, "password": password}).encode()
    d = susi_request(susi_url, "POST", "/api/v1/auth/login", body=body,
                     content_type="application/json")
    return d["token"]


def do_import(cache: Path, susi_url: str, token: str) -> None:
    # Ensure product exists.
    products = susi_request(susi_url, "GET", "/api/v1/products")["products"]
    if not any(p["slug"] == PRODUCT_SLUG for p in products):
        body = json.dumps({"slug": PRODUCT_SLUG, "name": PRODUCT_NAME, "ord": 10}).encode()
        susi_request(susi_url, "POST", "/api/v1/products", token=token, body=body,
                     content_type="application/json")
        print(f"product '{PRODUCT_SLUG}' created")
    else:
        print(f"product '{PRODUCT_SLUG}' already exists")

    manifest = json.loads((cache / "manifest.json").read_text(encoding="utf-8"))
    boundary = uuid.uuid4().hex
    parts = []

    def add_field(name: str, value: str):
        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode())

    def add_file(name: str, filename: str, data: bytes, ctype: str):
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n"
            f"Content-Type: {ctype}\r\n\r\n".encode() + data + b"\r\n")

    # Pages converted from external PDFs (produced by review agents). Their
    # image picks (<slug>.images.json: asset name -> source path) are staged
    # into pdf_assets here.
    pdf_final = cache / "pdf_final"
    if pdf_final.is_dir():
        import shutil
        pdf_assets = cache / "pdf_assets"
        pdf_assets.mkdir(exist_ok=True)
        for slug, meta in PDF_PAGES.items():
            if not (pdf_final / f"{slug}.md").exists():
                continue
            manifest[slug] = {"title": meta["title"], "parent_slug": meta["parent"], "ord": meta["ord"]}
            mapping_file = pdf_final / f"{slug}.images.json"
            if mapping_file.exists():
                for asset, src in json.loads(mapping_file.read_text(encoding="utf-8")).items():
                    if Path(src).exists():
                        shutil.copy2(src, pdf_assets / asset)
                    else:
                        print(f"WARN missing image source: {src}")

    add_field("release_name", RELEASE_NAME)
    add_field("manifest", json.dumps(manifest))
    for f in sorted((cache / "md").iterdir()):
        add_file("page", f.name, f.read_bytes(), "text/markdown")
    if pdf_final.is_dir():
        for f in sorted(pdf_final.glob("*.md")):
            add_file("page", f.name, f.read_bytes(), "text/markdown")
    for f in sorted((cache / "assets").iterdir()):
        ctype = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
        add_file("asset", f.name, f.read_bytes(), ctype)
    pdf_assets = cache / "pdf_assets"
    if pdf_assets.is_dir():
        for f in sorted(pdf_assets.iterdir()):
            ctype = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
            add_file("asset", f.name, f.read_bytes(), ctype)
    parts.append(f"--{boundary}--\r\n".encode())
    body = b"".join(parts)

    d = susi_request(susi_url, "POST",
                     f"/api/v1/products/{PRODUCT_SLUG}/docs/{RELEASE_TAG}/import",
                     token=token, body=body,
                     content_type=f"multipart/form-data; boundary={boundary}")
    print(json.dumps(d, indent=1))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", choices=["fetch", "convert", "import", "all"], default="all")
    ap.add_argument("--cache", default="c:/tmp/lpms_migration")
    ap.add_argument("--susi-url", default="https://susi.lp-research.com")
    ap.add_argument("--token")
    ap.add_argument("--username")
    ap.add_argument("--password")
    args = ap.parse_args()
    cache = Path(args.cache)

    if args.stage in ("fetch", "all"):
        fetch_tree(cache)
    if args.stage in ("convert", "all"):
        convert_all(cache)
    if args.stage in ("import", "all"):
        token = args.token
        if not token:
            if not (args.username and args.password):
                raise SystemExit("--token or --username/--password required for import")
            token = susi_login(args.susi_url, args.username, args.password)
        do_import(cache, args.susi_url, token)


if __name__ == "__main__":
    main()
