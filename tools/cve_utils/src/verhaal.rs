// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Greg Kroah-Hartman <gregkh@linuxfoundation.org>
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
//
//
// verhaal.rs - some common functions to help with digging information out of the verhaal database
//
//

use crate::common;
use crate::Kernel;
use anyhow::{anyhow, Result};
use log::debug;
use rusqlite::fallible_iterator::FallibleIterator;
use rusqlite::{Connection, ToSql};
use std::fs;
use std::sync::OnceLock;

// Location of the verhaal database we are working on.
static VERHAAL_DB: OnceLock<String> = OnceLock::new();

pub struct Verhaal {
    conn: Connection,
}

/// Generic SQL query function that can handle different return types and parameters
fn execute_query<T, P>(conn: &Connection, sql: &str, params: P) -> Vec<T>
where
    T: rusqlite::types::FromSql,
    P: rusqlite::Params,
{
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(e) => {
            debug!("SQL prepare error: {:?} for query: {}", e, sql);
            return vec![];
        }
    };

    let rows = match stmt.query(params) {
        Ok(r) => r,
        Err(e) => {
            debug!("SQL query error: {:?} for query: {}", e, sql);
            return vec![];
        }
    };

    rows.map(|row| row.get(0)).collect().unwrap_or_default()
}

/// Helper function that returns a vector of strings from a SQL query
fn query_strings(conn: &Connection, sql: &str, params: &[&dyn ToSql]) -> Vec<String> {
    execute_query(conn, sql, params)
}

/// Helper function that returns a vector of u32 from a SQL query
fn query_u32(conn: &Connection, sql: &str, params: &[&dyn ToSql]) -> Vec<u32> {
    execute_query(conn, sql, params)
}

/// Helper function that returns a single string from a SQL query, empty string if not found
fn query_string(conn: &Connection, sql: &str, params: &[&dyn ToSql]) -> String {
    let results: Vec<String> = execute_query(conn, sql, params);
    results.first().cloned().unwrap_or_default()
}

impl Verhaal {
    /// Create a new Verhaal object
    /// Will attempt to open a database connection with the file given
    pub fn new() -> Result<Self> {
        // Attempt to open the database connection
        let conn = Connection::open(Self::verhaal_database_file())?;

        Ok(Self { conn })
    }

    /// Returns the kernel version that this git sha is in
    /// If this is an invalid git sha, an error is returned
    pub fn get_version(&self, git_sha: &String) -> Result<String> {
        // Use our generic query function
        let versions = query_strings(
            &self.conn,
            "SELECT release from commits WHERE id=?1",
            &[&git_sha as &dyn ToSql],
        );

        if let Some(version) = versions.first() {
            debug!("\t\tget_version: '{}' => '{:?}'", git_sha, version);
            return Ok(version.clone());
        }

        debug!("\t\tget_version: '{}' => VERSION NOT FOUND", git_sha);
        Err(anyhow!("Version not found"))
    }

    /// Returns a vector of kernels that are fixes for this specific git id as listed in the database.
    /// All kernels returned are actual commits, they are validated before returned as the database can
    /// contain "bad" data for fixes lines.
    /// If an error happened, or there are no fixes, an "empty" vector is returned.
    pub fn get_fixes(&self, git_sha: &String) -> Vec<Kernel> {
        let mut fixed_kernels: Vec<Kernel> = vec![];

        let sql = "
            WITH fix_ids AS (
                SELECT value AS id
                FROM commits, json_each('[\"' || replace(fixes, ' ', '\",\"') || '\"]')
                WHERE commits.id = ?1 AND fixes IS NOT NULL AND fixes != ''
            )
            SELECT id, release
            FROM commits
            WHERE id IN (SELECT id FROM fix_ids)";

        if let Ok(mut stmt) = self.conn.prepare(sql) {
            if let Ok(rows) = stmt.query([git_sha]) {
                let mapped_rows =
                    rows.mapped(|row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)));

                for result in mapped_rows.flatten() {
                    if let Ok(k) = Kernel::new(result.1, result.0) {
                        fixed_kernels.push(k);
                    }
                }
            }
        }

        // Sort the list to be deterministic
        fixed_kernels.sort();
        fixed_kernels
    }

    /// Returns a sha for the revert if present
    /// If no revert is found, "" is returned, NOT an error, to make code flow easier.
    /// Errors are only returned if something went wrong with the sql stuff
    pub fn get_revert(&self, git_sha: &String) -> Result<String> {
        debug!("\tget_revert: '{}'", git_sha);

        // Use our query_string function to get a single result
        let revert = query_string(
            &self.conn,
            "SELECT reverts from commits WHERE id=?1",
            &[&git_sha as &dyn ToSql],
        );

        Ok(revert)
    }

    /// Determines the list of kernels where a specific git sha has been backported to, both
    /// mainline and stable kernel releases, if any.
    /// If an error happened, or there are no fixes, an "empty" vector is returned.
    pub fn found_in(&self, git_sha: &String, fixed_set: &[Kernel]) -> Vec<Kernel> {
        let mut kernels = Vec::new();

        // Find backported commits that aren't reverted in a single query
        let sql = "
            SELECT c.id, c.release, c.reverts
            FROM commits c
            LEFT JOIN commits rev ON rev.reverts = c.id
            WHERE c.mainline_id = ?1
            AND rev.id IS NULL
        ";

        let mut stmt = match self.conn.prepare(sql) {
            Ok(s) => s,
            Err(e) => {
                debug!("SQL prepare error: {:?} for query: {}", e, sql);
                return vec![];
            }
        };

        if let Ok(commit_rows) = stmt.query_map([git_sha], |row| {
            Ok((
                row.get::<_, String>(0)?,         // id
                row.get::<_, String>(1)?,         // release
                row.get::<_, Option<String>>(2)?, // reverts
            ))
        }) {
            for result in commit_rows.flatten() {
                // Unpack the tuple
                let (id, release, reverts) = result;

                // Skip if already in fixed set
                if fixed_set.iter().any(|k| k.git_id() == id) {
                    continue;
                }

                // For commits that are themselves reverts, check if they revert a stable commit
                if let Some(revert_id) = reverts {
                    // Fetch mainline status of the reverted commit
                    let sql_mainline = "SELECT mainline FROM commits WHERE id = ?";
                    let mainline_values =
                        query_u32(&self.conn, sql_mainline, &[&revert_id as &dyn ToSql]);

                    // Skip if this commit reverts a stable commit (mainline = 0)
                    if mainline_values.iter().any(|&mainline| mainline == 0) {
                        debug!(
                            "\t\tfound_in: skipping {:?} as it reverts a stable commit",
                            id
                        );
                        continue;
                    }
                }

                // Add valid commit to the list
                if let Ok(k) = Kernel::new(release, id) {
                    kernels.push(k);
                }
            }
        }

        // Also check for the mainline commit itself
        let sql_mainline = "SELECT id, release FROM commits WHERE id = ?1";
        if let Ok(mut stmt) = self.conn.prepare(sql_mainline) {
            if let Ok(mainline_rows) = stmt.query_map([git_sha], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            }) {
                for result in mainline_rows.flatten() {
                    if let Ok(k) = Kernel::new(result.1, result.0) {
                        kernels.push(k);
                    }
                }
            }
        }

        // Sort for deterministic results
        kernels.sort();
        debug!("\t\tfound_in: {:?}", kernels);

        kernels
    }

    // Helper function to get the path to the database
    // Logic taken from dyad source
    fn lookup_verhaal_database_file() -> String {
        let database_file: String;

        // Find the path to the verhaal.db database file using vulns dir
        let vulns_dir = match common::find_vulns_dir() {
            Ok(dir) => dir,
            Err(e) => panic!("Could not find vulns directory: {}", e),
        };

        let verhaal_db_path = vulns_dir.join("tools").join("verhaal").join("verhaal.db");
        match fs::exists(&verhaal_db_path) {
            Ok(true) => database_file = verhaal_db_path.to_string_lossy().into_owned(),
            Ok(false) => panic!(
                "The verhaal database 'verhaal.db' is not found at expected path: {}",
                verhaal_db_path.display()
            ),
            Err(e) => {
                panic!("Error {e}: Something went wrong trying to lookup the path for 'verhaal.db'")
            }
        }
        database_file
    }

    fn verhaal_database_file() -> &'static String {
        VERHAAL_DB.get_or_init(Self::lookup_verhaal_database_file)
    }

}

#[cfg(test)]
mod tests {
    use crate::Verhaal;

    fn get_version(git_id: String) -> String {
        let verhaal = match Verhaal::new() {
            Ok(verhaal) => verhaal,
            Err(error) => panic!("Can not open the database file {:?}", error),
        };

        let version = verhaal.get_version(&git_id);
        let version = match version {
            Ok(version) => version,
            Err(error) => panic!("{:?}", error),
        };
        version
    }

    #[test]
    fn get_version_test() {
        assert_eq!(
            get_version("28cd47f75185c4818b0fb1b46f2f02faaba96376".to_string()),
            "6.11"
        );
        assert_eq!(
            get_version("22207fd5c80177b860279653d017474b2812af5e".to_string()),
            "6.9"
        );
        assert_eq!(
            get_version("22f665ecfd1225afa1309ace623157d12bb9bb0c".to_string()),
            "6.8.3"
        );
        assert_eq!(
            get_version("af054a5fb24a144f99895afce9519d709891894c".to_string()),
            "6.7.12"
        );
        assert_eq!(
            get_version("2e13f88e01ae7e28a7e831bf5c2409c4748e0a60".to_string()),
            "6.1.132"
        );
        assert_eq!(
            get_version("e87e08c94c9541b4e18c4c13f2f605935f512605".to_string()),
            "6.6.24"
        );
    }

    #[test]
    #[should_panic(expected = "Version not found")]
    fn get_invalid_version_test() {
        assert_eq!(get_version("00000000".to_string()), "0.0");
    }
}
