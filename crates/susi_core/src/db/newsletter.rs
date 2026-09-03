use std::collections::HashSet;

use super::*;

/// One deliverable address. `email` is lowercased and trimmed so the caller can
/// dedupe on it directly - `users.email` has no UNIQUE constraint and
/// `normalize_email` never lowercased, so mixed-case duplicates exist.
#[derive(Debug, Clone, Serialize)]
pub struct NewsletterRecipient {
    pub username: String,
    pub email: String,
}

#[derive(Debug, Default, Serialize)]
pub struct NewsletterAudience {
    /// Opted in, with a usable address. This is exactly what gets mailed.
    pub recipients: Vec<NewsletterRecipient>,
    /// Accounts that have not consented.
    pub opted_out: usize,
    /// Consented but unreachable - no email on file.
    pub no_email: usize,
}

impl LicenseDb {
    /// Resolve who receives the newsletter: every account that has opted in and
    /// has an address. There is one newsletter, so entitlement plays no part -
    /// consent is the only filter.
    pub fn newsletter_audience(&self) -> Result<NewsletterAudience, LicenseError> {
        let mut stmt = self
            .conn
            .prepare("SELECT username, email, newsletter_opt_in FROM users")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, i32>(2)? != 0,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok());

        let mut audience = NewsletterAudience::default();
        let mut seen_emails: HashSet<String> = HashSet::new();
        for (username, email, opt_in) in rows {
            if !opt_in {
                audience.opted_out += 1;
                continue;
            }
            match email.map(|e| e.trim().to_lowercase()).filter(|e| !e.is_empty()) {
                None => audience.no_email += 1,
                // Two accounts can share an address; mail it once.
                Some(addr) => {
                    if seen_emails.insert(addr.clone()) {
                        audience.recipients.push(NewsletterRecipient { username, email: addr });
                    }
                }
            }
        }
        audience.recipients.sort_by(|a, b| a.email.cmp(&b.email));
        Ok(audience)
    }
}

// ---------------------------------------------------------------------------
// Subscribers (per-site newsletters)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct NewsletterSubscriber {
    pub email: String,
    pub status: String,
    pub created_at: String,
    pub confirmed_at: Option<String>,
}

impl LicenseDb {
    /// Register a signup. Existing rows keep their status - re-subscribing a
    /// confirmed address is a no-op, a pending one stays pending. Returns the
    /// row's status after the call so the caller knows whether to (re)send a
    /// confirmation mail. The email must arrive normalized (trimmed,
    /// lowercased).
    pub fn upsert_newsletter_subscriber(
        &self,
        site: &str,
        email: &str,
    ) -> Result<String, LicenseError> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO newsletter_subscribers (site, email, created_at)
                 VALUES (?1, ?2, ?3)",
                params![site, email, Utc::now().to_rfc3339()],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert: {}", e)))?;
        self.conn
            .query_row(
                "SELECT status FROM newsletter_subscribers WHERE site = ?1 AND email = ?2",
                params![site, email],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))
    }

    /// Flip a signup to confirmed. Idempotent; false = no such signup (it was
    /// removed after the confirmation mail went out).
    pub fn confirm_newsletter_subscriber(
        &self,
        site: &str,
        email: &str,
    ) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "UPDATE newsletter_subscribers
                 SET status = 'confirmed', confirmed_at = COALESCE(confirmed_at, ?1)
                 WHERE site = ?2 AND email = ?3",
                params![Utc::now().to_rfc3339(), site, email],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(n > 0)
    }

    /// Unsubscribe = delete: the list holds nothing but consent, so withdrawn
    /// consent leaves nothing to keep.
    pub fn delete_newsletter_subscriber(
        &self,
        site: &str,
        email: &str,
    ) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "DELETE FROM newsletter_subscribers WHERE site = ?1 AND email = ?2",
                params![site, email],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(n > 0)
    }

    pub fn list_newsletter_subscribers(
        &self,
        site: &str,
    ) -> Result<Vec<NewsletterSubscriber>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT email, status, created_at, confirmed_at
                 FROM newsletter_subscribers WHERE site = ?1 ORDER BY created_at DESC",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![site], |r| {
                Ok(NewsletterSubscriber {
                    email: r.get(0)?,
                    status: r.get(1)?,
                    created_at: r.get(2)?,
                    confirmed_at: r.get(3)?,
                })
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// (confirmed, pending) counts for the admin audience panel.
    pub fn count_newsletter_subscribers(&self, site: &str) -> Result<(i64, i64), LicenseError> {
        self.conn
            .query_row(
                "SELECT COALESCE(SUM(status = 'confirmed'), 0),
                        COALESCE(SUM(status = 'pending'), 0)
                 FROM newsletter_subscribers WHERE site = ?1",
                params![site],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))
    }

    /// The audience of a subscriber-based newsletter: every confirmed address.
    /// Emails are stored normalized and UNIQUE, so no dedupe pass is needed.
    pub fn subscriber_audience(&self, site: &str) -> Result<NewsletterAudience, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT email FROM newsletter_subscribers
                 WHERE site = ?1 AND status = 'confirmed' ORDER BY email",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let recipients = stmt
            .query_map(params![site], |r| r.get::<_, String>(0))
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .map(|email| NewsletterRecipient { username: String::new(), email })
            .collect();
        Ok(NewsletterAudience { recipients, ..Default::default() })
    }
}

// ---------------------------------------------------------------------------
// Google OAuth connection for the newsletter relay
// ---------------------------------------------------------------------------

const GOOGLE_REFRESH_KEY: &str = "google_refresh_token";
const GOOGLE_ACCOUNT_KEY: &str = "google_account";
const GOOGLE_CONNECTED_AT_KEY: &str = "google_connected_at";

impl LicenseDb {
    fn get_newsletter_oauth(&self, key: &str) -> Result<Option<String>, LicenseError> {
        self.conn
            .query_row(
                "SELECT value FROM newsletter_oauth WHERE key = ?1",
                params![key],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))
    }

    fn set_newsletter_oauth(&self, key: &str, value: &str) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "INSERT INTO newsletter_oauth (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert: {}", e)))?;
        Ok(())
    }

    /// Store the Google refresh token, sealed with the same at-rest encryption
    /// used for TOTP seeds and the Dropbox backup token.
    pub fn set_newsletter_google_connection(
        &self,
        refresh_token: &str,
        account: &str,
    ) -> Result<(), LicenseError> {
        let sealed = self.seal_secret(refresh_token)?;
        self.set_newsletter_oauth(GOOGLE_REFRESH_KEY, &sealed)?;
        self.set_newsletter_oauth(GOOGLE_ACCOUNT_KEY, account)?;
        self.set_newsletter_oauth(GOOGLE_CONNECTED_AT_KEY, &Utc::now().to_rfc3339())
    }

    pub fn get_newsletter_google_refresh_token(&self) -> Result<Option<String>, LicenseError> {
        match self.get_newsletter_oauth(GOOGLE_REFRESH_KEY)? {
            Some(sealed) => Ok(Some(self.open_secret(&sealed)?)),
            None => Ok(None),
        }
    }

    /// (account, connected_at) for the admin UI. Never returns the token.
    pub fn get_newsletter_google_account(
        &self,
    ) -> Result<Option<(String, String)>, LicenseError> {
        match self.get_newsletter_oauth(GOOGLE_ACCOUNT_KEY)? {
            Some(acct) => Ok(Some((
                acct,
                self.get_newsletter_oauth(GOOGLE_CONNECTED_AT_KEY)?.unwrap_or_default(),
            ))),
            None => Ok(None),
        }
    }

    pub fn clear_newsletter_google_connection(&self) -> Result<(), LicenseError> {
        self.conn
            .execute("DELETE FROM newsletter_oauth", [])
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Campaigns
// ---------------------------------------------------------------------------

/// Attempts allowed per address before a delivery is written off. Bounded so a
/// permanently bad address cannot hold a campaign in `sending` forever.
pub const MAX_DELIVERY_ATTEMPTS: i64 = 3;

#[derive(Debug, Clone, Serialize)]
pub struct NewsletterIssue {
    pub id: i64,
    pub site: String,
    pub subject: String,
    pub body_md: String,
    pub status: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
    pub sent_at: Option<String>,
    pub public: bool,
    pub pending: i64,
    pub sent: i64,
    pub failed: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeliveryRow {
    pub id: i64,
    pub username: String,
    pub email: String,
    pub status: String,
    pub attempts: i64,
    pub error: String,
    pub sent_at: Option<String>,
}

/// One unit of work for the sender loop.
#[derive(Debug, Clone)]
pub struct PendingDelivery {
    pub id: i64,
    pub issue_id: i64,
    pub username: String,
    pub email: String,
}

const ISSUE_SELECT: &str = "SELECT i.id, i.site, i.subject, i.body_md, i.status, i.created_by,
        i.created_at, i.updated_at, i.sent_at, i.public,
        COALESCE(SUM(CASE WHEN d.status = 'pending' THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN d.status = 'sent'    THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN d.status = 'failed'  THEN 1 ELSE 0 END), 0)
     FROM newsletter_issues i
     LEFT JOIN newsletter_deliveries d ON d.issue_id = i.id";

fn row_to_issue(r: &rusqlite::Row<'_>) -> rusqlite::Result<NewsletterIssue> {
    Ok(NewsletterIssue {
        id: r.get(0)?,
        site: r.get(1)?,
        subject: r.get(2)?,
        body_md: r.get(3)?,
        status: r.get(4)?,
        created_by: r.get(5)?,
        created_at: r.get(6)?,
        updated_at: r.get(7)?,
        sent_at: r.get(8)?,
        public: r.get::<_, i64>(9)? != 0,
        pending: r.get(10)?,
        sent: r.get(11)?,
        failed: r.get(12)?,
    })
}

impl LicenseDb {
    pub fn create_newsletter_issue(
        &self,
        site: &str,
        subject: &str,
        body_md: &str,
        created_by: &str,
    ) -> Result<i64, LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO newsletter_issues (site, subject, body_md, status, created_by, created_at, updated_at)
                 VALUES (?1, ?2, ?3, 'draft', ?4, ?5, ?5)",
                params![site, subject, body_md, created_by, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert: {}", e)))?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Edit a draft. Returns false when the issue is missing or already sending
    /// or sent - what a subscriber received must stay exactly what was sent.
    pub fn update_newsletter_issue(
        &self,
        id: i64,
        subject: &str,
        body_md: &str,
    ) -> Result<bool, LicenseError> {
        let now = Utc::now().to_rfc3339();
        let n = self
            .conn
            .execute(
                "UPDATE newsletter_issues SET subject = ?1, body_md = ?2, updated_at = ?3
                 WHERE id = ?4 AND status = 'draft'",
                params![subject, body_md, now, id],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(n > 0)
    }

    pub fn get_newsletter_issue(&self, id: i64) -> Result<Option<NewsletterIssue>, LicenseError> {
        self.conn
            .query_row(
                &format!("{} WHERE i.id = ?1 GROUP BY i.id", ISSUE_SELECT),
                params![id],
                row_to_issue,
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))
    }

    pub fn list_newsletter_issues(&self, site: &str) -> Result<Vec<NewsletterIssue>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(&format!(
                "{} WHERE i.site = ?1 GROUP BY i.id ORDER BY i.created_at DESC",
                ISSUE_SELECT
            ))
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![site], row_to_issue)
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Toggle an issue's listing on the public website archive. Sent issues
    /// only - a draft is not a document anyone was sent.
    pub fn set_newsletter_issue_public(
        &self,
        id: i64,
        public: bool,
    ) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "UPDATE newsletter_issues SET public = ?1 WHERE id = ?2 AND status = 'sent'",
                params![public as i64, id],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(n > 0)
    }

    /// Issues shown on the public website archive: (id, subject, body_md,
    /// sent_at), newest first.
    pub fn list_public_newsletter_issues(
        &self,
        site: &str,
    ) -> Result<Vec<(i64, String, String, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, subject, body_md, COALESCE(sent_at, created_at)
                 FROM newsletter_issues
                 WHERE site = ?1 AND public = 1 AND status = 'sent'
                 ORDER BY COALESCE(sent_at, created_at) DESC",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![site], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Drafts only. A sent issue is a delivery record, not a document.
    pub fn delete_newsletter_issue(&self, id: i64) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "DELETE FROM newsletter_issues WHERE id = ?1 AND status = 'draft'",
                params![id],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(n > 0)
    }

    pub fn list_newsletter_deliveries(
        &self,
        issue_id: i64,
    ) -> Result<Vec<DeliveryRow>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, username, email, status, attempts, error, sent_at
                 FROM newsletter_deliveries WHERE issue_id = ?1 ORDER BY email",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![issue_id], |r| {
                Ok(DeliveryRow {
                    id: r.get(0)?,
                    username: r.get(1)?,
                    email: r.get(2)?,
                    status: r.get(3)?,
                    attempts: r.get(4)?,
                    error: r.get(5)?,
                    sent_at: r.get(6)?,
                })
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Retention: scrub address + username off delivery rows of issues sent
    /// before the cutoff. Row counts stay for campaign history; the unique
    /// (issue_id, email) key needs a distinct filler.
    pub fn purge_newsletter_deliveries(&self, max_age_days: i64) -> Result<usize, LicenseError> {
        let cutoff = (Utc::now() - Duration::days(max_age_days)).to_rfc3339();
        self.conn
            .execute(
                "UPDATE newsletter_deliveries SET email = 'deleted-' || id, username = ''
                 WHERE email NOT LIKE 'deleted-%'
                   AND issue_id IN (SELECT id FROM newsletter_issues
                                    WHERE status = 'sent' AND COALESCE(sent_at, '') != ''
                                      AND sent_at < ?1)",
                params![cutoff],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))
    }

    /// Delivery rows still holding a user's name, for the subject-access export.
    pub fn list_newsletter_deliveries_for_user(
        &self,
        username: &str,
    ) -> Result<Vec<(i64, String, Option<String>)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT issue_id, status, sent_at FROM newsletter_deliveries
                 WHERE username = ?1 ORDER BY issue_id",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![username], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Materialize the recipient list and flip the issue to `sending`, in one
    /// transaction. Returns the number of delivery rows created.
    ///
    /// Only a draft can start: the guarded UPDATE is what makes a double-click
    /// on Send a no-op instead of a second campaign. `INSERT OR IGNORE` against
    /// `UNIQUE(issue_id, email)` means even a retried call cannot duplicate an
    /// address.
    pub fn start_newsletter_send(
        &self,
        issue_id: i64,
        recipients: &[NewsletterRecipient],
    ) -> Result<usize, LicenseError> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| LicenseError::Other(format!("DB tx: {}", e)))?;
        let started = tx
            .execute(
                "UPDATE newsletter_issues SET status = 'sending', updated_at = ?1
                 WHERE id = ?2 AND status = 'draft'",
                params![Utc::now().to_rfc3339(), issue_id],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        if started == 0 {
            return Err(LicenseError::Other("Issue is not a draft".into()));
        }
        let mut created = 0;
        {
            let mut stmt = tx
                .prepare(
                    "INSERT OR IGNORE INTO newsletter_deliveries (issue_id, username, email)
                     VALUES (?1, ?2, ?3)",
                )
                .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
            for r in recipients {
                created += stmt
                    .execute(params![issue_id, r.username, r.email])
                    .map_err(|e| LicenseError::Other(format!("DB insert: {}", e)))?;
            }
        }
        tx.commit()
            .map_err(|e| LicenseError::Other(format!("DB commit: {}", e)))?;
        Ok(created)
    }

    /// Next batch of addresses to attempt, oldest first. Rows that have burned
    /// through their attempts are excluded here and swept to `failed` by
    /// `finalize_newsletter_issues`.
    pub fn claim_pending_deliveries(
        &self,
        limit: i64,
    ) -> Result<Vec<PendingDelivery>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT d.id, d.issue_id, d.username, d.email
                 FROM newsletter_deliveries d
                 JOIN newsletter_issues i ON i.id = d.issue_id
                 WHERE d.status = 'pending' AND d.attempts < ?1 AND i.status = 'sending'
                 ORDER BY d.id LIMIT ?2",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![MAX_DELIVERY_ATTEMPTS, limit], |r| {
                Ok(PendingDelivery {
                    id: r.get(0)?,
                    issue_id: r.get(1)?,
                    username: r.get(2)?,
                    email: r.get(3)?,
                })
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn mark_delivery_sent(&self, id: i64) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "UPDATE newsletter_deliveries
                 SET status = 'sent', attempts = attempts + 1, error = '', sent_at = ?1
                 WHERE id = ?2",
                params![Utc::now().to_rfc3339(), id],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(())
    }

    /// Record a failed attempt. The row stays `pending` while attempts remain,
    /// so the next tick retries it; the sweep writes it off once the budget is
    /// spent.
    pub fn mark_delivery_attempt_failed(&self, id: i64, error: &str) -> Result<(), LicenseError> {
        let trimmed: String = error.chars().take(500).collect();
        self.conn
            .execute(
                "UPDATE newsletter_deliveries
                 SET attempts = attempts + 1,
                     error = ?1,
                     status = CASE WHEN attempts + 1 >= ?2 THEN 'failed' ELSE 'pending' END
                 WHERE id = ?3",
                params![trimmed, MAX_DELIVERY_ATTEMPTS, id],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(())
    }

    /// Close out campaigns with no work left. Returns how many issues flipped
    /// to `sent`. Idempotent, so it is safe on every tick and at boot - which
    /// is also how a process killed mid-campaign reconciles itself.
    pub fn finalize_newsletter_issues(&self) -> Result<usize, LicenseError> {
        let now = Utc::now().to_rfc3339();
        // Anything still pending but out of attempts is a permanent failure.
        self.conn
            .execute(
                "UPDATE newsletter_deliveries SET status = 'failed'
                 WHERE status = 'pending' AND attempts >= ?1",
                params![MAX_DELIVERY_ATTEMPTS],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        let n = self
            .conn
            .execute(
                "UPDATE newsletter_issues SET status = 'sent', sent_at = ?1, updated_at = ?1
                 WHERE status = 'sending'
                   AND NOT EXISTS (
                       SELECT 1 FROM newsletter_deliveries d
                       WHERE d.issue_id = newsletter_issues.id AND d.status = 'pending'
                   )",
                params![now],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(n)
    }

    /// Whether any campaign still has work, so the sender loop can skip the
    /// batch query on the overwhelming majority of ticks.
    pub fn has_pending_newsletter_work(&self) -> Result<bool, LicenseError> {
        let n: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM newsletter_deliveries d
                 JOIN newsletter_issues i ON i.id = d.issue_id
                 WHERE d.status = 'pending' AND i.status = 'sending'",
                [],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        Ok(n > 0)
    }
}
