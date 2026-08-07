use std::sync::Arc;

use anyhow::{Context, Result};
use lettre::message::{header::ContentType, Attachment, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

/// One inline image embedded in the HTML body via `cid:<id>`. The `id` must
/// match the `cid:` reference in the HTML (and contain no angle brackets).
/// `bytes` is `Arc<[u8]>` so cloning the attachment for fan-out (one task per
/// recipient) is a refcount bump rather than a full byte copy.
pub struct InlineImage {
    pub content_id: String,
    pub mime_type: String,
    pub bytes: Arc<[u8]>,
}

/// An attachment shown in the email's attachments list (e.g. invoice PDF).
pub struct EmailAttachment {
    pub file_name: String,
    pub mime_type: String,
    pub bytes: Arc<[u8]>,
}

#[derive(Clone)]
pub struct EmailConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from: Mailbox,
}

impl EmailConfig {
    pub fn from_parts(
        host: String,
        port: u16,
        username: String,
        password: String,
        from_name: &str,
        from_addr: &str,
    ) -> Result<Self> {
        let from: Mailbox = format!("{} <{}>", from_name, from_addr)
            .parse()
            .with_context(|| format!("Invalid SMTP From address: {} <{}>", from_name, from_addr))?;
        Ok(Self { host, port, username, password, from })
    }
}

#[derive(Clone)]
pub struct EmailService {
    cfg: EmailConfig,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl EmailService {
    pub fn new(cfg: EmailConfig) -> Result<Self> {
        let creds = Credentials::new(cfg.username.clone(), cfg.password.clone());
        let transport = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)
            .with_context(|| format!("Failed to init SMTP relay for {}", cfg.host))?
            .port(cfg.port)
            .credentials(creds)
            .build();
        Ok(Self { cfg, transport })
    }

    pub async fn send_signin_code(
        &self,
        to_addr: &str,
        username: &str,
        code: &str,
        ttl_minutes: i64,
    ) -> Result<()> {
        let to: Mailbox = to_addr
            .parse()
            .with_context(|| format!("Invalid recipient address: {}", to_addr))?;

        let subject = format!("Susi by LP-Research: your sign-in code ({} min)", ttl_minutes);
        let text = format!(
            "Your sign-in code\n\n    {code}\n\n\
             Hi {user},\n\n\
             You recently tried to sign in to Susi by LP-Research from a new device. \
             Enter the code above in the browser tab where you started signing in to complete sign-in.\n\n\
             The code expires in {ttl} minutes. If this wasn't you, you can ignore this email - no sign-in will happen.\n\n\
             - Xikaku / LP-Research\n",
            code = code, user = username, ttl = ttl_minutes
        );

        let html = format!(
            "<div style=\"font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:540px;margin:0 auto;color:#1a1d23;line-height:1.55;text-align:center;\">\
                <h2 style=\"margin:0 0 18px;font-weight:600;font-size:22px;\">Your sign-in code</h2>\
                <div style=\"margin:0 0 26px;padding:22px 12px;background:#f3f4f6;border-radius:10px;font-family:'SF Mono','Fira Code','Consolas',monospace;font-size:34px;font-weight:600;letter-spacing:10px;color:#1a1d23;\">{code}</div>\
                <div style=\"text-align:left;\">\
                    <p style=\"margin:0 0 14px;\">Hi {user},</p>\
                    <p style=\"margin:0 0 14px;\">You recently tried to sign in to Susi by LP-Research from a new device. Enter the code above in the browser tab where you started signing in to complete sign-in.</p>\
                    <p style=\"margin:0 0 4px;font-size:13px;\">The code expires in {ttl} minutes. If this wasn't you, you can ignore this email - no sign-in will happen.</p>\
                    <p style=\"margin:16px 0 0;font-size:13px;\">- Xikaku / LP-Research</p>\
                </div>\
             </div>",
            code = html_escape(code),
            user = html_escape(username),
            ttl = ttl_minutes,
        );

        let email = Message::builder()
            .from(self.cfg.from.clone())
            .to(to)
            .subject(subject)
            .multipart(
                lettre::message::MultiPart::alternative()
                    .singlepart(
                        lettre::message::SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(text),
                    )
                    .singlepart(
                        lettre::message::SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html),
                    ),
            )
            .context("Failed to build sign-in code email")?;

        self.transport
            .send(email)
            .await
            .context("SMTP send failed")?;
        Ok(())
    }

    pub async fn send_password_reset(
        &self,
        to_addr: &str,
        username: &str,
        link: &str,
        ttl_minutes: i64,
        ip: &str,
    ) -> Result<()> {
        let to: Mailbox = to_addr
            .parse()
            .with_context(|| format!("Invalid recipient address: {}", to_addr))?;

        let subject = format!("Susi by LP-Research: password reset link ({} min)", ttl_minutes);
        let text = format!(
            "Reset your password\n\n\
             Hi {user},\n\n\
             Someone requested a password reset for your Susi by LP-Research account from IP {ip}.\n\n\
             If this was you, click the link below within {ttl} minutes to set a new password:\n\n\
             {link}\n\n\
             If this wasn't you, you can ignore this email - your password stays unchanged.\n\n\
             - Xikaku / LP-Research\n",
            user = username, ip = ip, ttl = ttl_minutes, link = link
        );

        let html = format!(
            "<div style=\"font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:540px;margin:0 auto;color:#1a1d23;line-height:1.55;text-align:center;\">\
                <h2 style=\"margin:0 0 22px;font-weight:600;font-size:22px;\">Reset your password</h2>\
                <div style=\"text-align:left;\">\
                    <p style=\"margin:0 0 14px;\">Hi {user},</p>\
                    <p style=\"margin:0 0 16px;\">Someone requested a password reset for your <strong>Susi by LP-Research</strong> account from IP <strong>{ip}</strong>.</p>\
                    <p style=\"margin:0 0 16px;\">If this was you, click the button below within <strong>{ttl} minutes</strong> to set a new password:</p>\
                </div>\
                <p style=\"margin:0 0 22px;\"><a href=\"{link}\" style=\"display:inline-block;padding:11px 22px;background:#2563eb;color:#ffffff;text-decoration:none;border-radius:8px;font-weight:600;\">Reset password</a></p>\
                <div style=\"text-align:left;\">\
                    <p style=\"margin:0 0 6px;font-size:13px;\">Or paste this into your browser:</p>\
                    <p style=\"margin:0 0 18px;font-size:13px;word-break:break-all;\"><a href=\"{link}\" style=\"color:#2563eb;text-decoration:none;\">{link}</a></p>\
                    <p style=\"margin:0 0 4px;font-size:13px;\">If this wasn't you, you can ignore this email - your password stays unchanged.</p>\
                    <p style=\"margin:16px 0 0;font-size:13px;\">- Xikaku / LP-Research</p>\
                </div>\
             </div>",
            user = html_escape(username),
            ip = html_escape(ip),
            ttl = ttl_minutes,
            link = html_escape(link),
        );

        let email = Message::builder()
            .from(self.cfg.from.clone())
            .to(to)
            .subject(subject)
            .multipart(
                lettre::message::MultiPart::alternative()
                    .singlepart(
                        lettre::message::SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(text),
                    )
                    .singlepart(
                        lettre::message::SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html),
                    ),
            )
            .context("Failed to build password-reset email")?;

        self.transport
            .send(email)
            .await
            .context("SMTP send failed")?;
        Ok(())
    }

    /// Welcome email for an admin-created account. The link leads to
    /// password setup (`/#/reset/<token>`), which signs the invitee in
    /// once the password is saved.
    /// `ttl_hours` is shown in the body so the recipient knows the window.
    pub async fn send_invitation(
        &self,
        to_addr: &str,
        username: &str,
        link: &str,
        ttl_hours: i64,
    ) -> Result<()> {
        let to: Mailbox = to_addr
            .parse()
            .with_context(|| format!("Invalid recipient address: {}", to_addr))?;

        let action = "set your password and sign in";
        let subject = "You've been invited to Susi by LP-Research".to_string();
        let text = format!(
            "You've been invited to Susi by LP-Research\n\n\
             Hi {user},\n\n\
             A Susi by LP-Research account has been created for you. \
             Click the link below within {ttl} hours to {action}:\n\n\
             {link}\n\n\
             If you weren't expecting this invitation, you can ignore this email - \
             the link will expire and no account access will be granted.\n\n\
             - Xikaku / LP-Research\n",
            user = username, ttl = ttl_hours, link = link, action = action
        );

        let html = format!(
            "<div style=\"font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:540px;margin:0 auto;color:#1a1d23;line-height:1.55;text-align:center;\">\
                <h2 style=\"margin:0 0 22px;font-weight:600;font-size:22px;\">You've been invited to Susi by LP-Research</h2>\
                <div style=\"text-align:left;\">\
                    <p style=\"margin:0 0 14px;\">Hi {user},</p>\
                    <p style=\"margin:0 0 14px;\">A Susi by LP-Research account has been created for you. Click the button below within {ttl} hours to {action}:</p>\
                </div>\
                <p style=\"margin:0 0 22px;\"><a href=\"{link}\" style=\"display:inline-block;padding:11px 22px;background:#2563eb;color:#ffffff;text-decoration:none;border-radius:8px;font-weight:600;\">Set password</a></p>\
                <div style=\"text-align:left;\">\
                    <p style=\"margin:0 0 6px;font-size:13px;\">Or paste this into your browser:</p>\
                    <p style=\"margin:0 0 18px;font-size:13px;word-break:break-all;\"><a href=\"{link}\" style=\"color:#2563eb;text-decoration:none;\">{link}</a></p>\
                    <p style=\"margin:0 0 4px;font-size:13px;\">If you weren't expecting this invitation, you can ignore this email - the link will expire and no account access will be granted.</p>\
                    <p style=\"margin:16px 0 0;font-size:13px;\">- Xikaku / LP-Research</p>\
                </div>\
             </div>",
            user = html_escape(username),
            ttl = ttl_hours,
            link = html_escape(link),
            action = action,
        );

        let email = Message::builder()
            .from(self.cfg.from.clone())
            .to(to)
            .subject(subject)
            .multipart(
                lettre::message::MultiPart::alternative()
                    .singlepart(
                        lettre::message::SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(text),
                    )
                    .singlepart(
                        lettre::message::SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html),
                    ),
            )
            .context("Failed to build invitation email")?;

        self.transport
            .send(email)
            .await
            .context("SMTP send failed")?;
        Ok(())
    }

    /// Workspace-ticket notification: a new ticket, a new comment, or a
    /// status change. Layout matches the sign-in-code mail - centered
    /// heading, key/value table, primary CTA, fallback paste-link.
    ///
    /// `intro` is one sentence of context, `rows` the key/value pairs, and
    /// `excerpt` the quoted ticket body or comment (may be empty). `link` is
    /// omitted when the server has no public base URL configured, in which
    /// case the CTA and paste-link are left out entirely rather than emitting
    /// a dead relative URL.
    pub async fn send_ticket_notification(
        &self,
        to_addr: &str,
        subject: &str,
        heading: &str,
        intro: &str,
        rows: &[(String, String)],
        excerpt: &str,
        link: Option<&str>,
    ) -> Result<()> {
        let mut text = format!("{}\n\n{}\n\n", heading, intro);
        for (k, v) in rows {
            text.push_str(&format!("{}: {}\n", k, v));
        }
        if !excerpt.is_empty() {
            text.push_str(&format!("\n{}\n", excerpt));
        }
        if let Some(l) = link {
            text.push_str(&format!("\nOpen the ticket:\n{}\n", l));
        }
        text.push_str("\n- Xikaku / LP-Research\n");

        let rows_html = rows
            .iter()
            .map(|(k, v)| {
                format!(
                    "<tr><td style=\"padding:3px 12px 3px 0;\">{}</td>\
                     <td style=\"padding:3px 0;font-weight:600;\">{}</td></tr>",
                    html_escape(k),
                    html_escape(v)
                )
            })
            .collect::<String>();
        let excerpt_html = if excerpt.is_empty() {
            String::new()
        } else {
            format!(
                "<p style=\"margin:0 0 18px;padding:10px 14px;border-left:3px solid #d8dbe1;\
                 white-space:pre-wrap;\">{}</p>",
                html_escape(excerpt)
            )
        };
        let (cta_html, paste_html) = match link {
            Some(l) => (
                format!(
                    "<p style=\"margin:0 0 22px;\"><a href=\"{link}\" style=\"display:inline-block;\
                     padding:11px 22px;background:#2563eb;color:#ffffff;text-decoration:none;\
                     border-radius:8px;font-weight:600;\">Open ticket</a></p>",
                    link = html_escape(l)
                ),
                format!(
                    "<p style=\"margin:0 0 6px;font-size:13px;\">Or paste this into your browser:</p>\
                     <p style=\"margin:0 0 18px;font-size:13px;word-break:break-all;\">\
                     <a href=\"{link}\" style=\"color:#2563eb;text-decoration:none;\">{link}</a></p>",
                    link = html_escape(l)
                ),
            ),
            None => (String::new(), String::new()),
        };

        let html = format!(
            "<div style=\"font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;\
             max-width:540px;margin:0 auto;color:#1a1d23;line-height:1.55;text-align:center;\">\
                <h2 style=\"margin:0 0 22px;font-weight:600;font-size:22px;\">{heading}</h2>\
                <div style=\"text-align:left;\">\
                    <p style=\"margin:0 0 14px;\">{intro}</p>\
                    <table style=\"margin:0 0 18px;font-size:14px;\">{rows}</table>\
                    {excerpt}\
                </div>\
                {cta}\
                <div style=\"text-align:left;\">\
                    {paste}\
                    <p style=\"margin:0 0 4px;font-size:13px;\">You are receiving this because you \
                     are a member of this Susi by LP-Research workspace.</p>\
                    <p style=\"margin:16px 0 0;font-size:13px;\">- Xikaku / LP-Research</p>\
                </div>\
             </div>",
            heading = html_escape(heading),
            intro = html_escape(intro),
            rows = rows_html,
            excerpt = excerpt_html,
            cta = cta_html,
            paste = paste_html,
        );

        self.send_html_rich(to_addr, subject, &text, &html, &[], &[], None)
            .await
    }

    /// Send a multipart/alternative email with both plain-text and HTML
    /// bodies. Use for customer-facing transactional mails (shipped
    /// notifications, etc.) where HTML formatting is expected.
    /// Send a multipart/alternative email overriding the From display name
    /// (address part stays the configured one). Used by the shop flow so
    /// order emails appear from "Xikaku Shop" instead of "Susi".
    pub async fn send_html_as(
        &self,
        from_name: &str,
        to_addr: &str,
        subject: &str,
        text: &str,
        html: &str,
    ) -> Result<()> {
        self.send_html_rich(to_addr, subject, text, html, &[], &[], Some(from_name)).await
    }

    /// Send an HTML email with optional inline images (referenced from the
    /// HTML via `cid:<content_id>`) and optional file attachments.
    ///
    /// MIME structure follows RFC 2046:
    /// ```text
    /// multipart/mixed                 (only if attachments)
    ///   multipart/alternative
    ///     text/plain
    ///     multipart/related           (only if inline_images)
    ///       text/html
    ///       inline image…
    ///   attachment…
    /// ```
    pub async fn send_html_rich(
        &self,
        to_addr: &str,
        subject: &str,
        text: &str,
        html: &str,
        inline_images: &[InlineImage],
        attachments: &[EmailAttachment],
        from_name_override: Option<&str>,
    ) -> Result<()> {
        let to: Mailbox = to_addr
            .parse()
            .with_context(|| format!("Invalid recipient address: {}", to_addr))?;

        // ---- Body assembly: text + html (+ inline images) ----
        let text_part = SinglePart::builder()
            .header(ContentType::TEXT_PLAIN)
            .body(text.to_string());
        let html_part = SinglePart::builder()
            .header(ContentType::TEXT_HTML)
            .body(html.to_string());

        let body_part: MultiPart = if inline_images.is_empty() {
            MultiPart::alternative()
                .singlepart(text_part)
                .singlepart(html_part)
        } else {
            let mut related = MultiPart::related().singlepart(html_part);
            for img in inline_images {
                let ct = ContentType::parse(&img.mime_type)
                    .with_context(|| format!("Invalid mime type: {}", img.mime_type))?;
                related = related.singlepart(
                    Attachment::new_inline(img.content_id.clone()).body(img.bytes.to_vec(), ct),
                );
            }
            MultiPart::alternative()
                .singlepart(text_part)
                .multipart(related)
        };

        let from = match from_name_override {
            Some(name) => Mailbox::new(Some(name.to_string()), self.cfg.from.email.clone()),
            None => self.cfg.from.clone(),
        };
        let builder = Message::builder()
            .from(from)
            .to(to)
            .subject(subject.to_string());

        let email = if attachments.is_empty() {
            builder.multipart(body_part)
        } else {
            // Wrap everything in multipart/mixed and append attachments.
            let mut mixed = MultiPart::mixed().multipart(body_part);
            for a in attachments {
                let ct = ContentType::parse(&a.mime_type)
                    .with_context(|| format!("Invalid mime type: {}", a.mime_type))?;
                mixed = mixed.singlepart(
                    Attachment::new(a.file_name.clone()).body(a.bytes.to_vec(), ct),
                );
            }
            builder.multipart(mixed)
        }.context("Failed to build email")?;

        self.transport.send(email).await.context("SMTP send failed")?;
        Ok(())
    }
}

fn html_escape(s: &str) -> String {
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
