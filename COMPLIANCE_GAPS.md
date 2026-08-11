# Susi - compliance gap analysis (ASVS Level 1 + GDPR)

Gap list for the personal data Susi stores: user accounts (email/username, real
names, Argon2 password hashes, TOTP secrets), shop orders (customer name, email,
shipping address), sessions (with IP), known devices, audit log, newsletter
deliveries (email), workspace files/recordings/tickets. Payments run through
Stripe Checkout - no card data is stored.

Method: three focused read-only passes over `crates/susi_core`, `crates/susi_server`,
`nginx/`, and the compose/deploy files - (a) auth/session/access-control, (b)
injection/encoding/headers/transport, (c) data-lifecycle/GDPR/ops. Findings below
are the residue after removing everything the code already does correctly.

## Posture: improved since the July review

The High/Medium items in `REVIEW_FINDINGS.md` (2026-07) are confirmed fixed in the
current tree: Argon2id off-thread hashing, TOTP secrets AES-256-GCM sealed at rest,
per-account sign-in-code lockout (5 guesses, invalidates outstanding codes),
security headers (CSP + X-Frame-Options DENY + nosniff + Referrer-Policy, HSTS at
nginx), `ammonia` markdown sanitization, SVG served `attachment` + `sandbox`,
session revocation via `token_version` on password change, fully parameterized SQL,
signature-verified Stripe webhooks with constant-time compare, path traversal
blocked by validators + `canonicalize`. No SQL injection, no reachable XSS sink, no
reachable SSRF, no CSRF (bearer-token auth, no ambient cookie).

Remaining work is auth-hardening + data-protection gaps, not structural holes.

---

## GDPR / data-protection gaps (most legally material first)

| # | Gap | GDPR basis | Sev | Evidence |
|---|-----|-----------|-----|----------|
| G1 | Non-essential tracking (GA4, Google Ads, doubleclick, Reddit pixel, Google Fonts CDN) loads on every public page with **no consent gate**; no cookie banner. | ePrivacy Art 5(3) + Art 6/7 (prior consent for non-essential cookies) | **High** | `website.rs:1808-1858`, `main.rs:339-345` (CSP allow-list); zero `consent|cookie` hits in `website.html` |
| G2 | No privacy policy, imprint (Impressum), or terms page anywhere - repo, DB seed, or footer. Only JSON-LD org name. | Art 13/14 transparency; also JP APPI + German-style Impressum duty for EU sales | **High** | `content/` empty; zero `privacy\|impressum\|imprint` matches; `website.rs:742-744` |
| G3 | No right-to-erasure that actually erases: admin delete keeps the person's **email in `newsletter_deliveries`**, plus `audit_log`, blog bylines, tickets/comments; `shop_orders` (name/email/address) can never be deleted; no self-serve deletion. | Art 17 erasure | **High** | `db/api_tokens.rs:201-220` (delete list); `mod.rs:854-866`; no `DELETE FROM shop_orders` anywhere |
| G4 | No data export / subject-access endpoint (only license-file export exists). | Art 15 access, Art 20 portability | Med | route table `main.rs:2930-3321`; no export handler |
| G5 | No retention limits: `audit_log`, `known_devices`, `newsletter_deliveries`, `shop_orders` grow forever and outlive the account. | Art 5(1)(e) storage limitation | Med | only `sessions` + `login_tokens` + `backup_runs` are pruned (`main.rs:2907-2926`, `backup.rs:630`) |
| G6 | Backup archive bundles `db_secret.bin` (the at-rest key that decrypts the TOTP seeds) + `private.pem` + `jwt_secret.bin` **alongside** the personal-data DB - one `SUSI_BACKUP_KEY` collapses all key separation. Encryption itself (chunked AES-256-GCM to Dropbox, sealed refresh token) is sound. | Art 32 security of processing | Med | `backup.rs:271-308`; `tests/integration.rs:2981` |
| G7 | Staging shares one `/opt/susi/.env` with prod - the lower-trust staging box holds prod SMTP creds, Stripe keys, the prod S3 recordings bucket, and the prod backup-decryption key. Volumes and newsletter sending are correctly isolated; no prod data is cloned. | Art 25 by-design / Art 32 | Med | `deploy.sh:108-116`; `docker-compose.staging.yml:16-60` |
| G8 | Personal data in logs with no retention: contact form writes name+company+email+IP to stdout; container logs use `json-file` with no `max-size`; nginx `access_log` left to distro default (IP+UA, undefined rotation). | Art 5(1)(e), Art 32 | Med | `contact.rs:143-176`; no `logging:` block in compose; no `access_log` in `nginx/*.conf` |
| - | Newsletter consent: opt-in default off, one-click RFC 8058 unsubscribe, flag cleared on unsubscribe. SMTP over STARTTLS, no cert bypass. No secrets committed. | Art 7 / Art 32 | OK | `newsletter.rs:457-516`, `email.rs:57-66` |

Process items (not code, but required to claim GDPR compliance): a Record of
Processing (Art 30), Data Processing Agreements with AWS, Stripe, Dropbox and the
Gmail relay (Art 28), a lawful basis stated per processing activity (Art 6), and a
written breach-response procedure (Art 33/34, 72-hour clock).

---

## ASVS Level 1 gaps (most impactful first)

| # | Gap | ASVS area | Sev | Evidence |
|---|-----|-----------|-----|----------|
| A1 | `handle_create_api_token` requires only a JWT session, **not** `require_password_changed` - so the seeded `admin`/`changeme` owner (must_change_password=1, no TOTP) can mint a PAT and reach every admin endpoint, bypassing both the forced password change and the "admins must enable 2FA" gate. | V2 auth / V4 access control | **High** | `users.rs:284-311` (verified); gates at `main.rs:1155-1180`, `1234-1236` |
| A2 | Default seeded credential `admin`/`changeme`, role=`owner`, logged at startup. Combined with A1 = network-reachable takeover if an operator ever skips the first-login change. | V2.1 | **High** | `main.rs:2641-2649`; `db/users.rs:22-24` |
| A3 | "Known device" step-up bypass: the trust decision is a **client-supplied `device_fp`** (a `localStorage` UUID). A known fingerprint skips **both** the emailed sign-in code and TOTP - password-only login for owner/admin. Trust is permanent, uncapped, minted by 4 flows incl. the un-rate-limited password-reset. | V2.2 anti-automation / V2.8 | **High** | `auth.rs:43-64` (verified); `auth.rs:581-587`; `dashboard.html:2578-2590` |
| A4 | License client API unauthenticated + unthrottled: `/activate`,`/verify`,`/deactivate`,`/licenses/{key}/status` have **no rate limit**; `/deactivate` needs no machine-ownership proof (any key holder evicts a customer's seats); `/status` discloses customer name + full machine inventory with no auth. | V2.2 / V4 / V13 | **High** | `client_api.rs:146-197` |
| A5 | No idle/inactivity session timeout (30-day absolute only) and **no server-side logout** - "logout" only clears `localStorage`; the session row + JWT stay valid for the full 30 days. | V3.3 session timeout/termination | Med | `db/sessions.rs:29-52`; router has no `/auth/logout` (`main.rs:2928-3343`) |
| A6 | API tokens are unscoped (full owner authority incl. admin), never expire, and `token_version` bump on password change does **not** revoke them - only JWTs. | V3.3 / V4.1 | Med | `main.rs:1098-1122`; `db/mod.rs:636-646` (no expiry/scope column) |
| A7 | Session JWT lives in `localStorage` (any XSS = full ATO) and is also accepted in the **URL query string** on two asset GETs (leaks to access logs, history, Referer). | V3.4 / V7.1 | Med | `dashboard.html:3422`; `docs.rs:371-392`, `workspaces.rs:826-831` |
| A8 | TOTP: no replay protection (a code is reusable for the full 90 s window); skew=1 window wider than recommended; `POST /auth/setup-2fa` clears `totp_enabled` with **no re-authentication** (session-level 2FA downgrade). | V2.8 | Med | `main.rs:1462-1471`; `auth.rs:606-627` |
| A9 | No central auth mechanism - ~150 handlers each repeat `validate_principal` + role/membership checks by hand. Coverage is currently complete, but a forgotten check ships an unauthed route silently. | V4.1 single enforcement point | Med | flat router `main.rs:2928-3343` |
| A10 | Rate-limit / lockout state is in-process `HashMap` (lost on restart, not multi-replica); keys are **forgeable from any RFC1918 peer** because `X-Forwarded-For` is trusted from the whole private range. | V2.2 / V11 | Med | `main.rs:289-297`, `641-652` |
| A11 | Sign-in codes are 20-bit and stored as **unsalted SHA-256** (DB/backup reader recovers a live code in ~10^6 hashes); protection is the in-memory guess counter. | V2.2 / V6 | Low | `main.rs:1350-1368` |
| A12 | CSP is neutered by `'unsafe-inline'` in `script-src` (deliberate for the inline SPA shells, but it removes CSP's XSS value); no `Permissions-Policy`, no `Cross-Origin-*`; HSTS has no `preload`. | V14.4 | Low | `main.rs:339-349`, `3327-3342` |
| A13 | Uploads have **no content-type / extension allow-list** on any path (only filename sanitization); `Content-Disposition` filename is interpolated unescaped and `.parse().unwrap()` with no `CatchPanicLayer` (member-controlled name can 500). | V12.1/12.2 | Low | `workspaces.rs:792-851`, `releases.rs:384-404` |
| A14 | `safe_product`/`safe_tag` missing on 3 release handlers (`delete`, `replace_asset`, `update`); traversal is DB-gated today (row must pre-exist) but the validator is absent. | V12.3 | Low | `releases.rs:485,507-518,573` |
| A15 | No global body limit (2 MB default off the explicit routes is fine); rate limiting exists on only 5 endpoints, none at the edge - no cap on authenticated or bulk-download traffic. | V11 / V12 | Low | `main.rs:393-442`; no `limit_req` in `nginx/*.conf` |
| A16 | Latent SSRF: `handle_register_workspace_peer` accepts `req.url` with only an emptiness check (no scheme/host/private-range filter) and redistributes it to clients. Not fetched server-side today, so not reachable - becomes live the moment anything fetches it. | V12.6 SSRF | Low | `workspaces.rs:632-657` |
| A17 | `require_signed_binary` fails open when no `trusted_signing_ca` is set; the Linux client-side binary check returns `true` unconditionally. (Open from July review #11.) | V10 | Low | `main.rs:2088-2098`; `binary_signing.rs:26` |

Password policy is minimal but not a hard fail: 8-char floor only, no max, no
breach/denylist check (V2.1). Access-control model itself is sound - 3 roles used
via `is_admin_role`, no workspace IDOR (every scoped query is `workspace_id`-predicated).

---

## Recommended sequence

**Do first (cheap, closes the sharpest holes):**
1. A1 - add `require_password_changed` (and the admin-2FA gate) to `handle_create_api_token`. One-line class of fix, kills the default-password escalation chain.
2. A2 - refuse to serve while any account still has the `changeme` password, or force a random seed printed once.
3. G1 - gate the analytics/pixel injection behind a consent flag + add a cookie banner. This is the largest legal exposure and is self-contained in `website.rs`.
4. G2 - author a privacy policy + imprint page (the DB-driven website-page system already supports it; just needs content + footer links).

**Do next (data-subject rights + retention):**
5. G3 - extend the delete path to scrub/anonymize `newsletter_deliveries`, tickets/comments, bylines; add shop-order deletion; add a self-serve `DELETE /auth/me`.
6. G4 - a simple JSON export of a user's own rows (Art 15/20).
7. G5 - retention timers for `audit_log`, `known_devices`, `newsletter_deliveries`, `shop_orders`.
8. A3, A4, A5 - reconsider the known-device 2FA skip; add rate limits + machine-ownership proof to the client license API; add a real logout that deletes the session row.

**Harden when convenient:**
9. G6/G7 - split backup keys out of the archive; give staging its own `.env`.
10. G8 - drop PII from stdout logs, set `json-file` `max-size`, declare nginx `access_log` policy.
11. A6-A17 as normal backlog.

**Standards positioning:** GDPR + JP APPI are obligations that already apply - the
above closes most of the technical side; the rest is process (Art 30 record, Art 28
DPAs, breach plan). For a security standard, an OWASP ASVS L1 self-assessment is the
right baseline now - this document is the start of it. Defer ISO 27001 / SOC 2 until
a customer contract requires one.
