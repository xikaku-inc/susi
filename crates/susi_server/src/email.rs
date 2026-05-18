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

    pub async fn send_magic_link(
        &self,
        to_addr: &str,
        username: &str,
        link: &str,
        ttl_minutes: i64,
        device_label: &str,
        ip: &str,
    ) -> Result<()> {
        let to: Mailbox = to_addr
            .parse()
            .with_context(|| format!("Invalid recipient address: {}", to_addr))?;

        let subject = format!("Susi: sign in from a new device ({} min)", ttl_minutes);
        let text = format!(
            "Hi {user},\n\n\
             You (or someone) just tried to sign in to the Susi license server from a new device:\n\
             \n    Device: {dev}\n    IP:     {ip}\n\n\
             If this was you, click the link below within {ttl} minutes to authorize this device:\n\n\
             {link}\n\n\
             If this wasn't you, you can ignore this email — the link will expire and no sign-in will happen.\n\n\
             — Susi\n",
            user = username, dev = device_label, ip = ip, ttl = ttl_minutes, link = link
        );

        let html = format!(
            "<div style=\"font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:540px;color:#1a1d23;line-height:1.55;\">\
                <p style=\"margin:0 0 14px;\">Hi {user},</p>\
                <p style=\"margin:0 0 14px;\">Someone just tried to sign in to the Susi license server from a new device:</p>\
                <table style=\"border-collapse:collapse;margin:0 0 18px;\">\
                    <tr><td style=\"padding:3px 18px 3px 0;color:#5c6470;\">Device</td><td style=\"padding:3px 0;font-weight:600;\">{dev}</td></tr>\
                    <tr><td style=\"padding:3px 18px 3px 0;color:#5c6470;\">IP</td><td style=\"padding:3px 0;font-weight:600;\">{ip}</td></tr>\
                </table>\
                <p style=\"margin:0 0 16px;\">If this was you, click the button below within <strong>{ttl} minutes</strong> to authorize this device:</p>\
                <p style=\"margin:0 0 20px;\"><a href=\"{link}\" style=\"display:inline-block;padding:11px 22px;background:#2563eb;color:#ffffff;text-decoration:none;border-radius:8px;font-weight:600;\">Sign in</a></p>\
                <p style=\"margin:0 0 6px;font-size:13px;\">Or paste this into your browser:</p>\
                <p style=\"margin:0 0 20px;font-size:13px;word-break:break-all;\"><a href=\"{link}\" style=\"color:#2563eb;text-decoration:none;\">{link}</a></p>\
                <p style=\"margin:0 0 4px;font-size:13px;\">If this wasn't you, you can ignore this email — the link will expire and no sign-in will happen.</p>\
                <p style=\"margin:16px 0 0;font-size:13px;\">— Susi</p>\
             </div>",
            user = html_escape(username),
            dev = html_escape(device_label),
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
            .context("Failed to build magic-link email")?;

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

        let subject = format!("Susi: password reset link ({} min)", ttl_minutes);
        let text = format!(
            "Hi {user},\n\n\
             Someone requested a password reset for your Susi account from IP {ip}.\n\n\
             If this was you, click the link below within {ttl} minutes to set a new password:\n\n\
             {link}\n\n\
             If this wasn't you, you can ignore this email — your password stays unchanged.\n\n\
             — Susi\n",
            user = username, ip = ip, ttl = ttl_minutes, link = link
        );

        let html = format!(
            "<div style=\"font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:540px;color:#1a1d23;line-height:1.55;\">\
                <p style=\"margin:0 0 14px;\">Hi {user},</p>\
                <p style=\"margin:0 0 16px;\">Someone requested a password reset for your Susi account from IP <strong>{ip}</strong>.</p>\
                <p style=\"margin:0 0 16px;\">If this was you, click the button below within <strong>{ttl} minutes</strong> to set a new password:</p>\
                <p style=\"margin:0 0 20px;\"><a href=\"{link}\" style=\"display:inline-block;padding:11px 22px;background:#2563eb;color:#ffffff;text-decoration:none;border-radius:8px;font-weight:600;\">Reset password</a></p>\
                <p style=\"margin:0 0 6px;font-size:13px;\">Or paste this into your browser:</p>\
                <p style=\"margin:0 0 20px;font-size:13px;word-break:break-all;\"><a href=\"{link}\" style=\"color:#2563eb;text-decoration:none;\">{link}</a></p>\
                <p style=\"margin:0 0 4px;font-size:13px;\">If this wasn't you, you can ignore this email — your password stays unchanged.</p>\
                <p style=\"margin:16px 0 0;font-size:13px;\">— Susi</p>\
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
