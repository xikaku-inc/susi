use std::sync::Arc;

use anyhow::{Context, Result};
use lettre::message::header::{Header, HeaderName, HeaderValue};
use lettre::message::{header::ContentType, Attachment, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
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

    /// Authenticate with a Google OAuth2 access token instead of a password.
    ///
    /// The credential here is the short-lived access token (~1 hour), not the
    /// refresh token, so unlike `new` this transport cannot be built once at
    /// startup and reused forever - the caller has to rebuild it when the token
    /// expires. `cfg.password` is ignored.
    pub fn new_xoauth2(cfg: EmailConfig, access_token: &str) -> Result<Self> {
        let creds = Credentials::new(cfg.username.clone(), access_token.to_string());
        let transport = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)
            .with_context(|| format!("Failed to init SMTP relay for {}", cfg.host))?
            .port(cfg.port)
            .authentication(vec![Mechanism::Xoauth2])
            .credentials(creds)
            .build();
        Ok(Self { cfg, transport })
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
    /// Bulk campaign mail. Identical body handling to `send_html_rich`, plus
    /// the RFC 8058 one-click unsubscribe headers.
    ///
    /// These are not optional for bulk senders: without a header-level
    /// unsubscribe, mailbox providers treat the traffic as unsolicited and the
    /// sending domain's reputation degrades. `unsubscribe_url` must be an
    /// absolute https URL that honours a bare POST.
    pub async fn send_newsletter(
        &self,
        to_addr: &str,
        subject: &str,
        text: &str,
        html: &str,
        inline_images: &[InlineImage],
        unsubscribe_url: &str,
    ) -> Result<()> {
        self.send_message(
            to_addr,
            subject,
            text,
            html,
            inline_images,
            &[],
            None,
            Some(unsubscribe_url),
        )
        .await
    }

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
        self.send_message(
            to_addr,
            subject,
            text,
            html,
            inline_images,
            attachments,
            from_name_override,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_message(
        &self,
        to_addr: &str,
        subject: &str,
        text: &str,
        html: &str,
        inline_images: &[InlineImage],
        attachments: &[EmailAttachment],
        from_name_override: Option<&str>,
        unsubscribe_url: Option<&str>,
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
        let mut builder = Message::builder()
            .from(from)
            .to(to)
            .subject(subject.to_string());

        // RFC 8058: the URL must accept a bare POST so the client can
        // unsubscribe without the recipient leaving their inbox. Both headers
        // are required together - List-Unsubscribe-Post alone is ignored, and
        // List-Unsubscribe alone gets treated as a plain link.
        if let Some(url) = unsubscribe_url {
            builder = builder
                .header(ListUnsubscribe(format!("<{}>", url)))
                .header(ListUnsubscribePost("List-Unsubscribe=One-Click".to_string()));
        }

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

/// lettre exposes no generic custom-header hook, so each one is a small type.
macro_rules! string_header {
    ($ty:ident, $name:literal) => {
        #[derive(Clone)]
        struct $ty(String);

        impl Header for $ty {
            fn name() -> HeaderName {
                HeaderName::new_from_ascii_str($name)
            }
            fn parse(s: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
                Ok(Self(s.to_string()))
            }
            fn display(&self) -> HeaderValue {
                HeaderValue::new(Self::name(), self.0.clone())
            }
        }
    };
}

string_header!(ListUnsubscribe, "List-Unsubscribe");
string_header!(ListUnsubscribePost, "List-Unsubscribe-Post");
