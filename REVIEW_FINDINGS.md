# Susi backend - review findings

Licensing / releases / docs / website / shop platform (Rust). Review of security issues, code-quality improvements, and feature gaps.

> **Status update (2026-07-06):** security issues #1-#9 (High + all Medium)
> are fixed, one commit per issue: `7c2295b` (#1), `20b4302` (#2), `d673f80`
> (#3), `a04872b` (#4), `46517bb` (#5), `0d6f6a9` (#6), `21bafc4` (#7),
> `29d53ff` (#8), `9fa8cdf` (#9). Low findings (#10-#12), the quality /
> architecture items, and the feature ideas below remain open.

**Overall posture: strong.** No critical issues. SQL is fully parameterized (no injection), Stripe webhooks are signature-verified with constant-time compare, checkout prices are server-authoritative, passwords use Argon2id off-thread, API/reset/login tokens are stored only as hashes, path traversal is blocked (release downloads add `canonicalize` + prefix check), no SSRF/open-redirect, JWT pins HS256. Residual risk is auth-hardening gaps plus a missing output-security-header layer.

## Security issues (most important first)

| # | Sev | Issue | Location |
|---|-----|-------|----------|
| 1 | **High** | Emailed 6-digit sign-in code has no per-account/per-code brute-force lockout; wrong guesses aren't counted or invalidated (only per-IP limit 10/min). Distributed IP pool can brute a live 20-bit code within its 15-min TTL, giving passwordless takeover of non-TOTP accounts with an email on file. | `main.rs:1338-1384`, `db.rs:1444-1524` |
| 2 | Medium | No session/JWT revocation. 30-day stateless JWT, no `jti`/version; password reset / user delete / logout do not evict a stolen token. Token lives in `localStorage` (any XSS = full ATO). | `main.rs:566-575`, `760-761` |
| 3 | Medium | Mutex poisoning can wedge the server. One `Mutex<Connection>` unwrapped at 122 sites; a panic while holding it makes every DB endpoint 500 until restart. Also serializes all reads+writes (nullifies WAL). | `main.rs:160`; `db.rs:86-93` |
| 4 | Medium | No output security headers (CSP, X-Frame-Options, nosniff, Referrer-Policy) on app or dashboard nginx vhost. Dashboard is clickjackable; injected HTML/SVG executes unmitigated. | `main.rs:5314-5596`; `nginx/susi.lp-research.com.conf:13-14` |
| 5 | Medium | Stored XSS via admin content: website markdown body rendered raw; uploaded `.svg` served inline same-origin, no allow-list. Admin PATs skip TOTP/password gates, so a leaked PAT = persistent XSS on public site. | `website.rs:854`, `113`; `docs.rs:386` |
| 6 | Medium | Coarse release-download authz: for global releases, any valid license or any logged-in user can download every product's binaries - no per-product entitlement check. | `main.rs:3507`, `3552` |
| 7 | Medium | Brute-force protection is per-IP only, shared across all auth endpoints, with no per-account counter or global cap. Enables #1. | `main.rs:217-280` |
| 8 | Med (config) | Webhook records orders as `'paid'` on `checkout.session.completed` without checking `payment_status`. Safe only while card-only; any delayed method (ACH/SEPA/BNPL) would ship goods before settlement. | `shop.rs:490`; `db.rs:4548` |
| 9 | Med (latent) | TOTP secrets and federation channel secrets stored plaintext at rest; a DB/backup leak yields working 2FA seeds. | `db.rs:190`, `236` |
| 10 | Low | Unauthenticated `/api/v1/licenses/{key}/status` returns customer name, features, machine codes/friendly-names - no auth, no rate limit. | `main.rs:2244-2279` |
| 11 | Low | `require_signed_binary` fails open when no `trusted_signing_ca` is configured; client-side check returns `true` unconditionally on Linux. | `main.rs:2088-2098`; `binary_signing.rs:26` |
| 12 | Low | TOTP codes replayable within window; login timing enables username enumeration; default `admin`/`changeme` seed; contact-form daily cap unimplemented; sign-in JWT passed in `?auth=` query for doc assets. | `main.rs:1202-1215`, `1074-1087`, `5150`; `contact.rs`; `docs.html:861` |

**Best quick wins:** #1 (attempt counter + invalidate after ~5 wrong guesses), #4 (global `SetResponseHeaderLayer` + nginx `add_header`), #2 (`token_version`/`sessions_valid_after` in users, embed in JWT, bump on password change/delete).

## Quality / architecture ("do better")

- **Auth is per-handler opt-in, not middleware** - `validate_principal` hand-placed 77x; a forgotten check silently ships an unauthed route. Move protected routes under a nested router + auth `from_fn` layer.
- **DB concurrency** - move to `r2d2` + `rusqlite` pool (fixes #3, unlocks WAL reads). First wrap check-then-write spots in `BEGIN IMMEDIATE` (`push_config_revision` `db.rs:2610`; machine-limit `main.rs:2117`) - they rely on the global mutex and become TOCTOU races under a pool.
- **Migrations ad-hoc** - `migrate()` runs `ALTER TABLE`s with errors silently swallowed, re-run every startup, no version ledger. Adopt `PRAGMA user_version` numbered steps.
- **Monolith files** - `main.rs` 5,662 lines / 142 routes; `db.rs` 6,437 lines. Split following existing precedent (`shop.rs`, `website.rs`, etc.).
- **Commit `Cargo.lock`** (currently gitignored, so builds aren't reproducible). Add `.env` to `.gitignore` / `.dockerignore`.
- **Dead `SUSI_ADMIN_KEY`** - required by compose + echoed by `deploy.sh:111`, but the server never reads it. Remove or wire in; stop echoing secrets.
- **No pagination** on admin list endpoints (licenses / orders / tokens / users).
- **`rsa 0.9.10`** trips RUSTSEC-2023-0071 (Marvin); not practically exploitable here (sign/verify only) - track as accepted. Resolve stray transitive `rustls 0.21` vs `0.23`.
- **Stale docs** - README advertises workspace owner/editor/viewer roles, but the "Simplify workspace permissions" commit made it membership-boolean (every member can rotate federation secrets / delete others' configs). Reconcile docs; decide if a read-only viewer tier is still wanted.

## Feature ideas

- **Admin audit log** (who created/revoked licenses, changed roles, rotated secrets, shipped orders) - operational + security value.
- **Active-session management** (list / revoke sessions) - natural home for the #2 revocation fix.
- **License lifecycle automation** - expiry-reminder + renewal emails (email + PDF plumbing already exists).
- **Outbound webhooks** for license events (activation / seat / expiry) - mirror of the Stripe webhook you consume.
- **License analytics** - activations over time, seat utilization, version adoption.
- **Backup/restore tooling** - scheduled `VACUUM INTO` snapshots (SQLite is the single source of truth).
- **Observability** - `/metrics` (Prometheus), structured logging; throttle state is currently an unbounded in-memory `HashMap`.

---

*Method: findings from parallel focused reviews (auth, web surface, commerce/crypto, storage, deploy/infra); #1, Stripe verification, SQL parameterization, and path handling were independently spot-checked in code. All file:line references are against the state of the repo at review time.*
