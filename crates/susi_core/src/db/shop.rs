use super::*;

impl LicenseDb {
    // ---------------------------------------------------------------------
    // Shop: products
    //
    // Tuple layout: (sku, title, description_md, price_cents, currency,
    //                image_asset, tax_code, active, ord, updated_at)
    // ---------------------------------------------------------------------

    pub fn list_products(
        &self,
        active_only: bool,
    ) -> Result<
        Vec<(
            String,
            String,
            String,
            i64,
            String,
            Option<String>,
            String,
            bool,
            i64,
            String,
        )>,
        LicenseError,
    > {
        let sql = if active_only {
            "SELECT sku, title, description_md, price_cents, currency, image_asset, tax_code, active, ord, updated_at
             FROM shop_products WHERE active = 1 ORDER BY ord, title"
        } else {
            "SELECT sku, title, description_md, price_cents, currency, image_asset, tax_code, active, ord, updated_at
             FROM shop_products ORDER BY ord, title"
        };
        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, i64>(7).map(|v| v != 0)?,
                    r.get::<_, i64>(8)?,
                    r.get::<_, String>(9)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Batch lookup. Returns a map of `sku → product row` for every requested
    /// SKU that exists. Use this for checkout / cart paths where a per-SKU
    /// `get_product` loop would issue one round-trip per item under the lock.
    pub fn get_products_by_skus(
        &self,
        skus: &[String],
    ) -> Result<
        std::collections::HashMap<
            String,
            (
                String,
                String,
                String,
                i64,
                String,
                Option<String>,
                String,
                bool,
                i64,
                String,
            ),
        >,
        LicenseError,
    > {
        let mut out = std::collections::HashMap::with_capacity(skus.len());
        if skus.is_empty() {
            return Ok(out);
        }
        // SQLite has no native array binding; build `?,?,?,…` placeholders.
        let placeholders = std::iter::repeat("?")
            .take(skus.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT sku, title, description_md, price_cents, currency, image_asset, tax_code, active, ord, updated_at
             FROM shop_products WHERE sku IN ({})",
            placeholders,
        );
        let mut stmt = self
            .conn
            .prepare(&sql)
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let params_iter: Vec<&dyn rusqlite::ToSql> =
            skus.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        let rows = stmt
            .query_map(&params_iter[..], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, i64>(7).map(|v| v != 0)?,
                    r.get::<_, i64>(8)?,
                    r.get::<_, String>(9)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        for row in rows.flatten() {
            out.insert(row.0.clone(), row);
        }
        Ok(out)
    }

    pub fn get_product(
        &self,
        sku: &str,
    ) -> Result<
        Option<(
            String,
            String,
            String,
            i64,
            String,
            Option<String>,
            String,
            bool,
            i64,
            String,
        )>,
        LicenseError,
    > {
        match self.conn.query_row(
            "SELECT sku, title, description_md, price_cents, currency, image_asset, tax_code, active, ord, updated_at
             FROM shop_products WHERE sku = ?1",
            params![sku],
            |r| Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, i64>(7).map(|v| v != 0)?,
                r.get::<_, i64>(8)?,
                r.get::<_, String>(9)?,
            )),
        ) {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB query: {}", e))),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_product(
        &self,
        sku: &str,
        title: &str,
        description_md: &str,
        price_cents: i64,
        currency: &str,
        image_asset: Option<&str>,
        tax_code: &str,
        active: bool,
        ord: i64,
    ) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO shop_products
               (sku, title, description_md, price_cents, currency, image_asset, tax_code, active, ord, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(sku) DO UPDATE SET
               title = excluded.title,
               description_md = excluded.description_md,
               price_cents = excluded.price_cents,
               currency = excluded.currency,
               image_asset = excluded.image_asset,
               tax_code = excluded.tax_code,
               active = excluded.active,
               ord = excluded.ord,
               updated_at = excluded.updated_at",
            params![
                sku, title, description_md, price_cents, currency,
                image_asset, tax_code, active as i64, ord, now,
            ],
        )
        .map_err(|e| LicenseError::Other(format!("DB upsert product: {}", e)))?;
        Ok(())
    }

    pub fn delete_product(&self, sku: &str) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute("DELETE FROM shop_products WHERE sku = ?1", params![sku])
            .map_err(|e| LicenseError::Other(format!("DB delete product: {}", e)))?;
        Ok(n > 0)
    }

    // ---------------------------------------------------------------------
    // Shop: shipping rates
    //
    // Tuple layout: (id, label, amount_cents, currency, delivery_min_days,
    //                delivery_max_days, regions_json, active, ord)
    // ---------------------------------------------------------------------

    pub fn list_shipping_rates(
        &self,
        active_only: bool,
    ) -> Result<
        Vec<(
            i64,
            String,
            i64,
            String,
            Option<i64>,
            Option<i64>,
            String,
            bool,
            i64,
        )>,
        LicenseError,
    > {
        let sql = if active_only {
            "SELECT id, label, amount_cents, currency, delivery_min_days, delivery_max_days, regions, active, ord
             FROM shop_shipping_rates WHERE active = 1 ORDER BY ord, amount_cents"
        } else {
            "SELECT id, label, amount_cents, currency, delivery_min_days, delivery_max_days, regions, active, ord
             FROM shop_shipping_rates ORDER BY ord, amount_cents"
        };
        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, i64>(7).map(|v| v != 0)?,
                    r.get::<_, i64>(8)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_shipping_rate(
        &self,
        label: &str,
        amount_cents: i64,
        currency: &str,
        delivery_min_days: Option<i64>,
        delivery_max_days: Option<i64>,
        regions_json: &str,
        active: bool,
        ord: i64,
    ) -> Result<i64, LicenseError> {
        self.conn.execute(
            "INSERT INTO shop_shipping_rates
               (label, amount_cents, currency, delivery_min_days, delivery_max_days, regions, active, ord)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                label, amount_cents, currency,
                delivery_min_days, delivery_max_days, regions_json,
                active as i64, ord,
            ],
        )
        .map_err(|e| LicenseError::Other(format!("DB insert shipping rate: {}", e)))?;
        Ok(self.conn.last_insert_rowid())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_shipping_rate(
        &self,
        id: i64,
        label: &str,
        amount_cents: i64,
        currency: &str,
        delivery_min_days: Option<i64>,
        delivery_max_days: Option<i64>,
        regions_json: &str,
        active: bool,
        ord: i64,
    ) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "UPDATE shop_shipping_rates
               SET label = ?2, amount_cents = ?3, currency = ?4,
                   delivery_min_days = ?5, delivery_max_days = ?6,
                   regions = ?7, active = ?8, ord = ?9
             WHERE id = ?1",
                params![
                    id,
                    label,
                    amount_cents,
                    currency,
                    delivery_min_days,
                    delivery_max_days,
                    regions_json,
                    active as i64,
                    ord,
                ],
            )
            .map_err(|e| LicenseError::Other(format!("DB update shipping rate: {}", e)))?;
        Ok(n > 0)
    }

    pub fn delete_shipping_rate(&self, id: i64) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute("DELETE FROM shop_shipping_rates WHERE id = ?1", params![id])
            .map_err(|e| LicenseError::Other(format!("DB delete shipping rate: {}", e)))?;
        Ok(n > 0)
    }

    // ---------------------------------------------------------------------
    // Shop: orders
    //
    // Tuple layout: (id, stripe_session_id, created_at, customer_email,
    //                customer_name, amount_total_cents, currency, status,
    //                ship_to_json, line_items_json, tracking_carrier,
    //                tracking_number, shipped_at, notes)
    // ---------------------------------------------------------------------

    /// Insert a shop order keyed on `stripe_session_id`. Returns `(id, inserted)`;
    /// `inserted == false` means the row already existed (Stripe webhook retry).
    /// Callers use that flag to skip side effects (emails) on retries.
    /// `status` is 'paid' for settled sessions, 'pending_payment' for delayed
    /// payment methods still awaiting settlement.
    pub fn insert_order_if_absent(
        &self,
        stripe_session_id: &str,
        created_at: &str,
        customer_email: &str,
        customer_name: &str,
        amount_total_cents: i64,
        currency: &str,
        status: &str,
        ship_to_json: &str,
        line_items_json: &str,
    ) -> Result<(i64, bool), LicenseError> {
        let n = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO shop_orders
               (stripe_session_id, created_at, customer_email, customer_name,
                amount_total_cents, currency, status, ship_to_json, line_items_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    stripe_session_id,
                    created_at,
                    customer_email,
                    customer_name,
                    amount_total_cents,
                    currency,
                    status,
                    ship_to_json,
                    line_items_json,
                ],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert order: {}", e)))?;
        let id = self
            .conn
            .query_row(
                "SELECT id FROM shop_orders WHERE stripe_session_id = ?1",
                params![stripe_session_id],
                |r| r.get::<_, i64>(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB lookup order: {}", e)))?;
        Ok((id, n > 0))
    }

    /// Conditionally flip an order's status from `from` to `to`, keyed by
    /// Stripe session id. Returns whether a row changed - false means the
    /// order is missing or already past `from` (e.g. a webhook retry), so
    /// side effects tied to the transition must be skipped.
    pub fn transition_order_status_by_session(
        &self,
        stripe_session_id: &str,
        from: &str,
        to: &str,
    ) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "UPDATE shop_orders SET status = ?3
                 WHERE stripe_session_id = ?1 AND status = ?2",
                params![stripe_session_id, from, to],
            )
            .map_err(|e| LicenseError::Other(format!("DB update order status: {}", e)))?;
        Ok(n > 0)
    }

    #[allow(clippy::type_complexity)]
    pub fn list_orders(
        &self,
        status_filter: Option<&str>,
    ) -> Result<
        Vec<(
            i64,
            String,
            String,
            String,
            String,
            i64,
            String,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            String,
        )>,
        LicenseError,
    > {
        let (sql, has_filter) = if status_filter.is_some() {
            (
                "SELECT id, stripe_session_id, created_at, customer_email, customer_name,
                        amount_total_cents, currency, status, ship_to_json, line_items_json,
                        tracking_carrier, tracking_number, shipped_at, notes
                 FROM shop_orders WHERE status = ?1 ORDER BY created_at DESC, id DESC",
                true,
            )
        } else {
            (
                "SELECT id, stripe_session_id, created_at, customer_email, customer_name,
                        amount_total_cents, currency, status, ship_to_json, line_items_json,
                        tracking_carrier, tracking_number, shipped_at, notes
                 FROM shop_orders ORDER BY created_at DESC, id DESC",
                false,
            )
        };
        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let row_map = |r: &rusqlite::Row<'_>| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, String>(8)?,
                r.get::<_, String>(9)?,
                r.get::<_, String>(10)?,
                r.get::<_, String>(11)?,
                r.get::<_, Option<String>>(12)?,
                r.get::<_, String>(13)?,
            ))
        };
        let rows: Vec<_> = if has_filter {
            stmt.query_map(params![status_filter.unwrap()], row_map)
                .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
                .filter_map(|r| r.ok())
                .collect()
        } else {
            stmt.query_map([], row_map)
                .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
                .filter_map(|r| r.ok())
                .collect()
        };
        Ok(rows)
    }

    #[allow(clippy::type_complexity)]
    pub fn get_order(
        &self,
        id: i64,
    ) -> Result<
        Option<(
            i64,
            String,
            String,
            String,
            String,
            i64,
            String,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            String,
        )>,
        LicenseError,
    > {
        match self.conn.query_row(
            "SELECT id, stripe_session_id, created_at, customer_email, customer_name,
                    amount_total_cents, currency, status, ship_to_json, line_items_json,
                    tracking_carrier, tracking_number, shipped_at, notes
             FROM shop_orders WHERE id = ?1",
            params![id],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, String>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, String>(10)?,
                    r.get::<_, String>(11)?,
                    r.get::<_, Option<String>>(12)?,
                    r.get::<_, String>(13)?,
                ))
            },
        ) {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB query: {}", e))),
        }
    }

    /// Erasure (GDPR Art 17): delete an order row entirely.
    pub fn delete_order(&self, id: i64) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute("DELETE FROM shop_orders WHERE id = ?1", params![id])
            .map_err(|e| LicenseError::Other(format!("DB delete order: {}", e)))?;
        Ok(n > 0)
    }

    /// Retention: strip customer PII (name, email, shipping address) off
    /// orders older than the cutoff. Amounts and line items stay for
    /// accounting.
    pub fn scrub_old_orders(&self, max_age_days: i64) -> Result<usize, LicenseError> {
        let cutoff = (Utc::now() - Duration::days(max_age_days)).to_rfc3339();
        self.conn
            .execute(
                "UPDATE shop_orders SET customer_email = '', customer_name = '', ship_to_json = '{}'
                 WHERE created_at < ?1
                   AND (customer_email != '' OR customer_name != '' OR ship_to_json != '{}')",
                params![cutoff],
            )
            .map_err(|e| LicenseError::Other(format!("DB scrub orders: {}", e)))
    }

    /// Orders placed with `email`, for the subject-access export.
    pub fn list_order_summaries_by_email(
        &self,
        email: &str,
    ) -> Result<Vec<(i64, String, String, String, i64, String, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, created_at, customer_email, customer_name, amount_total_cents, currency, status
                 FROM shop_orders WHERE LOWER(customer_email) = LOWER(?1) ORDER BY id",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![email], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Mark an order as shipped, recording carrier + tracking number.
    /// Sets shipped_at to the provided RFC3339 timestamp.
    pub fn mark_order_shipped(
        &self,
        id: i64,
        carrier: &str,
        tracking_number: &str,
        shipped_at: &str,
    ) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "UPDATE shop_orders
               SET status = 'shipped',
                   tracking_carrier = ?2,
                   tracking_number  = ?3,
                   shipped_at       = ?4
             WHERE id = ?1",
                params![id, carrier, tracking_number, shipped_at],
            )
            .map_err(|e| LicenseError::Other(format!("DB mark shipped: {}", e)))?;
        Ok(n > 0)
    }

    pub fn update_order_notes(&self, id: i64, notes: &str) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "UPDATE shop_orders SET notes = ?2 WHERE id = ?1",
                params![id, notes],
            )
            .map_err(|e| LicenseError::Other(format!("DB update notes: {}", e)))?;
        Ok(n > 0)
    }

    // ---------------------------------------------------------------------
    // Shop: settings (key/value)
    // ---------------------------------------------------------------------

    pub fn get_shop_setting(&self, key: &str) -> Result<Option<String>, LicenseError> {
        match self.conn.query_row(
            "SELECT value FROM shop_settings WHERE key = ?1",
            params![key],
            |r| r.get::<_, String>(0),
        ) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB get setting: {}", e))),
        }
    }

    pub fn set_shop_setting(&self, key: &str, value: &str) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "INSERT INTO shop_settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map_err(|e| LicenseError::Other(format!("DB set setting: {}", e)))?;
        Ok(())
    }

    pub fn list_shop_settings(&self) -> Result<Vec<(String, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare("SELECT key, value FROM shop_settings ORDER BY key")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn get_site_setting(&self, key: &str) -> Result<Option<String>, LicenseError> {
        match self.conn.query_row(
            "SELECT value FROM site_settings WHERE key = ?1",
            params![key],
            |r| r.get::<_, String>(0),
        ) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB get site setting: {}", e))),
        }
    }

    pub fn set_site_setting(&self, key: &str, value: &str) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "INSERT INTO site_settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map_err(|e| LicenseError::Other(format!("DB set site setting: {}", e)))?;
        Ok(())
    }

    pub fn list_site_settings(&self) -> Result<Vec<(String, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare("SELECT key, value FROM site_settings ORDER BY key")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

}
