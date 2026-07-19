# Handoff: Public FusionHub downloads from xikaku.com

Status: **code complete and committed** (`35c6ae8` on `main`), **not yet built/tested end-to-end** on this machine because the disk filled to ~0 bytes free and the integration-test binary could not link. Continue on the more powerful workstation from the "What's left" section.

---

## Goal

Route the "software download" links on xikaku.com to **FusionHub** (the unified app that replaces the standalone LpmsControl). A sensor owner with no account and no license must be able to download and test FusionHub with zero friction - exactly like LpmsControl used to be.

Product decision already made by Klaus: **fully public download** (no login, no license). Licensing still gates premium features *inside* the app; only the installer download is open.

---

## Key facts about the existing system

- **FusionHub is the default product**, slug `fusionhub` (`susi_core::db::DEFAULT_PRODUCT`). The release system, docs, and in-app updater are all built around it.
- **xikaku.com is served by susi itself** (`crates/susi_server/src/website.rs`) - hand-authored markdown pages, server-side rendered, fully public. The markdown renderer **sanitizes with ammonia (strips `<script>`)** and does not apply attribute classes to links, so a dynamic download widget cannot live in page markdown. Static `<a href>` links work fine - which is why we added stable redirect URLs.
- **Before this change, all release binaries were gated**: `handle_download_asset` -> `authorize_release_download` required either a valid license key or a logged-in entitled user. There was no public download path.
- **Release asset naming** (from `fusionhub_rs_2/.github/workflows/publish-release.yml` and `scripts/package_macos.sh`):
  - Windows: `fusionhub-{version}-x86_64.msi`
  - macOS: `fusionhub-{version}-macos-{arch}.dmg` (arch = `arm64` on the Apple-Silicon self-hosted runner)
  - Android (ALVR client, unrelated): `alvr-client-{version}.apk` - deliberately NOT surfaced on the FusionHub download page.
  - The macOS build job has `continue-on-error: true`, so some releases ship **without** a dmg. The redirect handles this (see below).
- **Prerelease flag**: tags containing `-rc` or `-test` are marked prerelease. All current fusionhub releases are `-rc`, so they are prereleases.

---

## Design decisions

1. **Keep installers in the release system** (single source of truth, versioned, already feeds the in-app updater). Do NOT copy binaries into the public website asset store.
2. **Per-product `download_public` flag** rather than hardcoding `fusionhub`. Keeps the multi-product design honest and gives a reversible admin toggle. Migration enables it for `fusionhub` once, on first column creation, so a later admin toggle-off is not clobbered on restart.
3. **Public bypass only for *global* releases.** Workspace-scoped releases stay gated by membership even when the product is public.
4. **Extension-based platform detection** (`.msi`/`.exe` = Windows, `.dmg`/`.pkg` = macOS, `.appimage`/`.deb`/`.rpm` = Linux). Robust against the existing asset names; no need to rename anything.
5. **Stable "latest installer" redirect** `/download/{product}/{platform}` so xikaku.com links never need editing per release. It resolves newest-first, **prefers a stable release, falls back to the newest prerelease** (important right now because every release is an `-rc`). For macOS it walks back to the newest release that actually shipped a dmg, so the Mac button never dead-ends as long as *some* recent release built one.

---

## Code changes (all committed in `35c6ae8`)

### `crates/susi_core/src/db/mod.rs`
- New migration block (just before the `>> Add new migrations` marker): `ALTER TABLE products ADD COLUMN download_public INTEGER NOT NULL DEFAULT 0;` and a one-time `UPDATE products SET download_public = 1 WHERE slug = 'fusionhub'`, gated on the `ALTER` succeeding so it runs exactly once per DB.

### `crates/susi_core/src/db/products.rs`
- `list_release_products()` now returns `(slug, name, description, ord, download_public)` (added the bool; column added to the SELECT).
- New `get_product_download_public(slug) -> bool` (unknown product = false).
- `upsert_release_product(...)` gained a `download_public: bool` parameter (added to INSERT and the ON CONFLICT update).

### `crates/susi_server/src/releases.rs`
- `handle_list_products` JSON now includes `download_public`.
- `handle_create_product` / `handle_update_product` pass `req.download_public`.
- `handle_get_releases` - anonymous listing allowed when the product is public (otherwise still requires license key or bearer token).
- New `pct_encode()` helper and new `handle_public_latest_download()` (the `/download/{product}/{platform}` redirect).

### `crates/susi_server/src/main.rs`
- `ProductRequest` and `UpdateProductRequest` gained `#[serde(default)] download_public: bool`.
- `authorize_release_download` - early return `Ok("public")` for a global release of a `download_public` product, before the license/principal requirement. Workspace and global-entitlement branches unchanged.
- Registered route: `.route("/download/{product}/{platform}", get(releases::handle_public_latest_download))` next to the other `/api/v1/updates/...` routes.

### `crates/susi_server/src/dashboard.html`
- Products admin page: added a "Public DL" checkbox column to the add-product form and the product grid (grid template changed in 3 coordinated places), and wired `download_public` through `createProduct`, `saveProduct`, and `renderProducts`.

### `crates/susi_server/tests/integration.rs`
- New `test_public_product_download`: uploads a stable global fusionhub release with a `.msi` + `.dmg` (multipart body built by hand to avoid adding the reqwest `multipart` dev-dependency), then asserts:
  - anonymous listing works,
  - anonymous asset download returns the exact bytes,
  - `/download/fusionhub/windows` and `/download/fusionhub/macos` 302 to the right asset,
  - unknown platform = 400, non-public product download = 401 and its redirect = 404,
  - toggling `download_public` off re-gates (401) and on restores (200).

Note: `Cargo.toml` and `Cargo.lock` were intentionally left unchanged (a temporary `multipart` feature was reverted; the test builds the multipart body manually).

---

## What's already verified

- `cargo build -p susi_server` succeeded (full compile + link) before the disk filled.
- `cargo test -p susi_core --lib` -> **29 passed, 1 ignored** (covers the migration + product upsert/list changes).

## What's left (do on the powerful workstation)

1. **Build + run the integration test** (this is the only unverified piece):
   ```
   cargo test -p susi_server --test integration test_public_product_download -- --nocapture
   ```
   Then the full suite: `cargo test`.
2. **Author the public Downloads page** on xikaku.com via the website editor (admin dashboard -> Website). Suggested slug `downloads`. Ready-to-paste markdown is in the next section. The renderer strips scripts, so keep it to plain markdown links.
3. **Link the sensor product pages** to the downloads page, e.g. add `[Download FusionHub](/downloads)` (or link straight to `/download/fusionhub/windows`).
4. **Ensure a macOS dmg exists.** The Mac build is best-effort (`continue-on-error`). If no release has ever shipped a `*.dmg`, `/download/fusionhub/macos` returns 404. Cut/confirm at least one release with a dmg so the Mac button works (Klaus explicitly wanted the Mac download to work).
5. **Deploy.** On deploy the migration auto-adds the column and enables `fusionhub` public - no manual step. To change it later, use the "Public DL" toggle on the admin Products page.

---

## Ready-to-paste Downloads page (markdown)

```markdown
# Download FusionHub

FusionHub is the unified application for LP-Research sensors. It replaces the
standalone LpmsControl app - install it, connect your sensor, and start
streaming and recording right away.

## Windows

[Download for Windows](/download/fusionhub/windows)

Windows 10 or later, 64-bit.

## macOS

[Download for macOS](/download/fusionhub/macos)

Apple Silicon or Intel.
```

Each link 302-redirects to the newest matching installer, so the page never
needs editing when a new version is released.

---

## Public endpoints added / relevant

| Purpose | URL | Auth |
| --- | --- | --- |
| Latest Windows installer | `GET /download/fusionhub/windows` | none |
| Latest macOS installer | `GET /download/fusionhub/macos` | none |
| List releases (buttons/version) | `GET /api/v1/updates/releases?product=fusionhub` | none (public product) |
| Direct asset download | `GET /api/v1/updates/download/{tag}/{asset}?product=fusionhub` | none (global release of public product) |

Platform tokens accepted by the redirect: `windows`/`win`, `macos`/`mac`/`osx`/`darwin`, `linux`.

---

## Verification checklist (after deploy)

- [ ] `GET /download/fusionhub/windows` downloads the current `.msi` with no login.
- [ ] `GET /download/fusionhub/macos` downloads the current `.dmg` with no login.
- [ ] `GET /api/v1/updates/releases?product=fusionhub` returns 200 with no auth.
- [ ] A workspace-scoped release is still NOT downloadable anonymously.
- [ ] A second, non-public product's binaries are still gated (401/403).
- [ ] Admin Products page shows the "Public DL" toggle and it round-trips.

---

## The disk situation on this machine (why testing stalled)

`C:` reached **0 bytes free** during the test build; the linker failed with
`LNK1318: Unexpected PDB error; LIMIT`. Space breakdown at the time:

- `fusionhub_rs_2/target` = **13.7 GB** (a different project - left untouched)
- `susi/target` = **5.8 GB**

I only cleared regenerable susi caches (safe). To build the integration test
here you'd need to free a few GB - the obvious candidate is
`fusionhub_rs_2/target` (`cargo clean` in that repo) - but that's your call,
which is why it wasn't touched. On the more powerful workstation this is moot.
