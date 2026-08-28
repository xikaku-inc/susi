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
        let md = format!(
            "# Your sign-in code\n\n\
             {{{{code:{code}}}}}\n\n\
             Hi {user},\n\n\
             You recently tried to sign in to Susi by LP-Research from a new device. \
             Enter the code above in the browser tab where you started signing in to complete sign-in.\n\n\
             The code expires in {ttl} minutes. If this wasn't you, you can ignore this email - no sign-in will happen.\n\n\
             \\- Xikaku / LP-Research\n",
            code = code,
            user = crate::email_md::escape(username),
            ttl = ttl_minutes,
        );
        let doc = crate::email_md::render(&md, None);
        let (text, html) = (doc.text, doc.html);

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
        let md = format!(
            "# Reset your password\n\n\
             Hi {user},\n\n\
             Someone requested a password reset for your **Susi by LP-Research** account from IP **{ip}**.\n\n\
             If this was you, click the button below within **{ttl} minutes** to set a new password:\n\n\
             {{{{button:Reset password|{link}}}}}\n\n\
             If this wasn't you, you can ignore this email - your password stays unchanged.\n\n\
             \\- Xikaku / LP-Research\n",
            user = crate::email_md::escape(username),
            ip = crate::email_md::escape(ip),
            ttl = ttl_minutes,
            link = link,
        );
        let doc = crate::email_md::render(&md, None);
        let (text, html) = (doc.text, doc.html);

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
        let md = format!(
            "# You've been invited to Susi by LP-Research\n\n\
             Hi {user},\n\n\
             A Susi by LP-Research account has been created for you. \
             Click the button below within {ttl} hours to {action}:\n\n\
             {{{{button:Set password|{link}}}}}\n\n\
             If you weren't expecting this invitation, you can ignore this email - \
             the link will expire and no account access will be granted.\n\n\
             \\- Xikaku / LP-Research\n",
            user = crate::email_md::escape(username),
            ttl = ttl_hours,
            link = link,
            action = action,
        );
        let doc = crate::email_md::render(&md, None);
        let (text, html) = (doc.text, doc.html);

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
        let e = crate::email_md::escape;
        let mut md = format!("# {}\n\n{}\n\n", e(heading), e(intro));
        md.push_str("|  |  |\n| --- | --- |\n");
        for (k, v) in rows {
            md.push_str(&format!("| {} | **{}** |\n", e(k), e(v)));
        }
        md.push('\n');
        if !excerpt.is_empty() {
            for line in excerpt.lines() {
                md.push_str(&format!("> {}\n", e(line)));
            }
            md.push('\n');
        }
        if let Some(l) = link {
            md.push_str(&format!("{{{{button:Open ticket|{}}}}}\n\n", l));
        }
        md.push_str(
            "You are receiving this because you are a member of this Susi by LP-Research workspace.\n\n\
             \\- Xikaku / LP-Research\n",
        );
        let doc = crate::email_md::render(&md, None);

        self.send_html_rich(to_addr, subject, &doc.text, &doc.html, &[], &[], None)
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
