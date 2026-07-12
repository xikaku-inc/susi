use super::*;

impl LicenseDb {
    // -----------------------------------------------------------------------
    // License listing
    // -----------------------------------------------------------------------

    pub fn list_licenses(&self) -> Result<Vec<License>, LicenseError> {
        self.collect_licenses(
            "SELECT id, product, customer, license_key, created, expires, features, max_machines, revoked, lease_duration_hours, lease_grace_hours, require_signed_binary
             FROM licenses ORDER BY created DESC",
            &[],
        )
    }

    /// Licenses assigned to `username` via `license_users`, machines included.
    pub fn list_licenses_for_user(&self, username: &str) -> Result<Vec<License>, LicenseError> {
        self.collect_licenses(
            "SELECT l.id, l.product, l.customer, l.license_key, l.created, l.expires, l.features, l.max_machines, l.revoked, l.lease_duration_hours, l.lease_grace_hours, l.require_signed_binary
             FROM licenses l JOIN license_users lu ON lu.license_id = l.id
             WHERE lu.username = ?1 ORDER BY l.created DESC",
            &[&username],
        )
    }

    fn collect_licenses(
        &self,
        sql: &str,
        params: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<License>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;

        let rows = stmt
            .query_map(params, |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, u32>(7)?,
                    row.get::<_, i32>(8)?,
                    row.get::<_, u32>(9)?,
                    row.get::<_, u32>(10)?,
                    row.get::<_, i32>(11)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;

        // Materialise the parent rows first so we can issue a single batch
        // query for activations instead of N round-trips. Lease-expired
        // activations are included on purpose: they are the "seen but stale"
        // history shown in the dashboard.
        let parents: Vec<_> = rows.filter_map(|r| r.ok()).collect();
        let ids: Vec<String> = parents.iter().map(|r| r.0.clone()).collect();
        let mut machines_by_id = self
            .get_machine_activations_for_licenses(&ids)
            .unwrap_or_default();

        let mut licenses = Vec::with_capacity(parents.len());
        for (
            id,
            product,
            customer,
            license_key,
            created_str,
            expires_str,
            features_json,
            max_machines,
            revoked,
            lease_duration_hours,
            lease_grace_hours,
            require_signed_binary,
        ) in parents
        {
            let features: Vec<String> = serde_json::from_str(&features_json).unwrap_or_default();
            let created = DateTime::parse_from_rfc3339(&created_str)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let expires = if expires_str.is_empty() {
                None
            } else {
                Some(
                    DateTime::parse_from_rfc3339(&expires_str)
                        .map(|d| d.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                )
            };

            let machines = machines_by_id.remove(&id).unwrap_or_default();

            licenses.push(License {
                id,
                product,
                customer,
                license_key,
                created,
                expires,
                features,
                max_machines,
                lease_duration_hours,
                lease_grace_hours,
                machines,
                revoked: revoked != 0,
                require_signed_binary: require_signed_binary != 0,
            });
        }

        Ok(licenses)
    }

}
