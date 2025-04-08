// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Greg Kroah-Hartman <gregkh@linuxfoundation.org>
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
//
// dyad - create a listing of "pairs" of vulnerable:fixed kernels based on a
//        specific git SHA that purports to fix an issue.  Used in combination
//        with 'bippy' to create CVE entries for the Linux kernel.  Is VERY
//        specific to how the Linux kernel has its stable branches and how it
//        labels things.

use gumdrop::Options;
use log::{debug, error};
use rusqlite::fallible_iterator::FallibleIterator;
use rusqlite::{Connection, Result, ToSql};
use colored::Colorize;
use std::cmp::Ordering;
use std::env;
use std::fs;
use std::path::Path;
extern crate cve_utils;
use cve_utils::version_utils;

pub mod kernel;
use kernel::Kernel;
use kernel::KernelPair;

// Using more specific error types directly instead of a custom error enum

#[derive(Debug, Options)]
struct DyadArgs {
    #[options(free)]
    git_sha: String,

    #[options(help_flag, help = "Print this help message")]
    help: bool,

    #[options(short = "V", help = "Show version")]
    version: bool,

    #[options(help = "Show debugging information to stdout")]
    verbose: bool,

    #[options(
        no_short,
        help = "The kernel git sha1 that this issue became vulnerable at"
    )]
    vulnerable: Option<String>,
}

struct DyadState {
    kernel_tree: String,
    verhaal_db: String,
    has_vulnerable: bool,
    vulnerable_sha: String,
    git_sha_orig: String,
    git_sha_full: String,
    git_sha_short: String,
    fixed_set: Vec<Kernel>,
    vulnerable_set: Vec<Kernel>,
}

impl DyadState {
    pub fn new(git_sha: String) -> Self {
        Self {
            // Init with some "blank" default, the command line and
            // environment variables will override them
            kernel_tree: String::new(),
            verhaal_db: String::new(),
            has_vulnerable: false,
            vulnerable_sha: String::new(),
            git_sha_orig: git_sha,
            git_sha_full: String::new(),
            git_sha_short: String::new(),
            fixed_set: vec![],
            vulnerable_set: vec![],
        }
    }
}

fn validate_env_vars(state: &mut DyadState) {
    // Use cve_utils to get kernel tree path
    match cve_utils::common::get_kernel_tree() {
        Ok(path) => state.kernel_tree = path.to_string_lossy().into_owned(),
        Err(e) => panic!("Failed to get kernel tree: {}", e),
    };
    debug!("kernel_tree = {}", state.kernel_tree);

    // Find the path to the verhaal.db database file using vulns dir
    let vulns_dir = match cve_utils::common::find_vulns_dir() {
        Ok(dir) => dir,
        Err(e) => panic!("Could not find vulns directory: {}", e),
    };

    let verhaal_db_path = vulns_dir.join("tools").join("verhaal").join("verhaal.db");
    match fs::exists(&verhaal_db_path) {
        Ok(true) => state.verhaal_db = verhaal_db_path.to_string_lossy().into_owned(),
        Ok(false) => panic!(
            "The verhaal database 'verhaal.db' is not found at expected path: {}",
            verhaal_db_path.display()
        ),
        Err(e) => {
            panic!("Error {e}: Something went wrong trying to lookup the path for 'verhaal.db'")
        }
    }
    debug!("verhaal.db = {}", state.verhaal_db);
}

fn create_vulnerable_set(state: &mut DyadState, version: String, git_id: String) {
    let mainline = version_utils::version_is_mainline(&version);

    state
        .vulnerable_set
        .push(Kernel::new(version.clone(), git_id.clone()));
    debug!(
        "create_vulnerable_set: version: {}\tgit_id: {}\tmainline: {}",
        version.clone(),
        git_id.clone(),
        mainline
    );
}

/// Look up the "full" and "short" git ids for the one passed on the command line.
/// If the git id is not found, return None instead of aborting.
fn git_full_id(state: &DyadState, git_sha: &String) -> Option<String> {
    // Early check for obviously invalid SHA1s (like email addresses)
    if git_sha.contains('@') || git_sha.len() < 4 {
        debug!("Ignoring invalid git SHA1-like string: {}", git_sha);
        return None;
    }

    let repo_path = Path::new(&state.kernel_tree);

    // Use the cve_utils function to get the full SHA
    match cve_utils::common::get_full_git_sha(repo_path, git_sha) {
        Some(full_id) => Some(full_id),
        None => {
            debug!("Notice: git SHA1 {} not found", git_sha);
            None
        }
    }
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

    rows.map(|row| row.get(0))
        .collect()
        .unwrap_or_default()
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

/// Determines the list of kernels where a specific git sha has been backported to, both mainline
/// and stable kernel releases, if any.
fn found_in(state: &DyadState, git_sha: &String) -> Vec<Kernel> {
    let conn = match Connection::open(&state.verhaal_db) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let mut kernels = Vec::new();

    // Find backported commits
    let backported_ids = query_strings(
        &conn,
        "SELECT id from commits WHERE mainline_id=?1;",
        &[&git_sha as &dyn ToSql],
    );
    debug!("\t\tfound_in: backported_ids: {:?}", backported_ids);

    // Process backported commits
    for id in backported_ids {
        // Skip if already in fixed set
        if state.fixed_set.iter().any(|k| k.git_id == id) {
            continue;
        }

        debug!("\t\tfound_in: examining id {:?}", id);

        // Skip if this commit is reverted by another commit
        let reverts_this = query_strings(
            &conn,
            "SELECT id FROM commits WHERE reverts=?1;",
            &[&id as &dyn ToSql],
        );
        if !reverts_this.is_empty() {
            debug!("\t\tfound_in: {:?} is reverted by {:?}, skipping", id, reverts_this);
            continue;
        }

        // Check if this commit is itself a revert
        let reverts_other = query_strings(
            &conn,
            "SELECT reverts FROM commits WHERE id=?1;",
            &[&id as &dyn ToSql],
        );

        // Skip if this commit reverts a stable commit
        let should_skip = reverts_other.iter().any(|revert| {
            debug!("\t\tfound_in: {:?} reverts commit {:?}", id, revert);

            let mainlines = query_u32(
                &conn,
                "SELECT mainline FROM commits WHERE id=?1;",
                &[revert as &dyn ToSql],
            );
            debug!("\t\tfound_in: mainlines = {:?}", mainlines);

            mainlines.iter().any(|&mainline| mainline == 0)
        });

        if should_skip {
            debug!("\t\tfound_in: skipping {:?} as it reverts a stable commit", id);
            continue;
        }

        // Add valid commit to the list
        if let Ok(version) = get_version(state, &id) {
            kernels.push(Kernel::new(version, id));
        }
    }

    // Also check for the mainline commit itself
    let mainline_ids = query_strings(
        &conn,
        "SELECT id from commits WHERE id=?1;",
        &[&git_sha as &dyn ToSql],
    );
    debug!("\t\tfound_in: mainline id: {:?}", mainline_ids);

    for id in mainline_ids {
        if let Ok(version) = get_version(state, &id) {
            kernels.push(Kernel::new(version, id));
        }
    }

    // Sort for deterministic results
    kernels.sort();
    debug!("\t\tfound_in: {:?}", kernels);

    kernels
}

fn get_version(state: &DyadState, git_sha: &String) -> Result<String> {
    let verhaal_db = &state.verhaal_db;

    // Open db connection
    let conn = Connection::open(verhaal_db)?;

    // Use our generic query function
    let versions = query_strings(
        &conn,
        "SELECT release from commits WHERE id=?1",
        &[&git_sha as &dyn ToSql],
    );

    if let Some(version) = versions.first() {
        debug!(
            "\t\tverhaal_db: {}\tget_version: '{}' => '{:?}'",
            verhaal_db, git_sha, version
        );
        return Ok(version.clone());
    }

    debug!(
        "\t\tverhaal_db: {}\tget_version: '{}' => VERSION NOT FOUND",
        verhaal_db, git_sha
    );
    Err(rusqlite::Error::QueryReturnedNoRows)
}

/// Returns a vector of kernels that are fixes for this specific git id as listed in the database.
/// All kernels returned are actual commits, they are validated before returned as the database can
/// contain "bad" data for fixes lines.
/// If an error happened, or there are no fixes, an "empty" vector is returned.
fn get_fixes(state: &DyadState, git_sha: &String) -> Vec<Kernel> {
    let mut fixed_kernels: Vec<Kernel> = vec![];
    let verhaal_db = &state.verhaal_db;

    // Open db connection
    let conn = match Connection::open(verhaal_db) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    // Ask the db for the fixes for this commit
    let fixes = query_strings(
        &conn,
        "SELECT fixes FROM commits WHERE id=?1;",
        &[&git_sha as &dyn ToSql],
    );
    debug!("\t\tget_fixes: fixes: {:?}", fixes);
    for fix in fixes {
        // Fixes lines can have multiple ones, so split this into another list
        let fix_ids: Vec<String> = fix.split_whitespace().map(|s| s.to_string()).collect();
        debug!("\t\tget_fixes: fix_ids: {:?}", fix_ids);

        // Sometimes fixes lines lie, so verify that this REALLY is an actual commit in the kernel
        // tree before we add it to our list
        for id in fix_ids {
            if let Ok(version) = get_version(state, &id) {
                fixed_kernels.push(Kernel::new(version, id.to_string()));
            } else {
                debug!("Could not get version for commit {}", id);
            }
        }
    }

    // Sort the list to be deterministic
    fixed_kernels.sort();
    fixed_kernels
}

//
// Returns a sha for the revert if present
// If no revert is found, "" is returned, NOT an error, to make code flow easier.
// Errors are only returned if something went wrong with the sql stuff
fn get_revert(state: &DyadState, git_sha: &String) -> Result<String> {
    let verhaal_db = &state.verhaal_db;
    debug!("verhaal_db: {}\tget_revert: '{}'", verhaal_db, git_sha);

    // Open db connection
    let conn = Connection::open(verhaal_db)?;

    // Use our query_string function to get a single result
    let revert = query_string(
        &conn,
        "SELECT reverts from commits WHERE id=?1",
        &[&git_sha as &dyn ToSql],
    );

    Ok(revert)
}

fn main() {
    // Default to no logging, can turn it on based on the command line.
    // Note, RUST_LOG_LEVEL does NOT work here anymore.  See
    // https://docs.rs/env_logger/latest/env_logger/#specifying-defaults-for-environment-variables
    // for a possible way to fix this up if anyone gets bored.
    let mut logging_level: log::LevelFilter = log::LevelFilter::Error;

    let program_name = env!("CARGO_BIN_NAME");
    let program_version = env!("CARGO_PKG_VERSION");

    // Parse our command line
    let args = DyadArgs::parse_args_default_or_exit();

    // Will not work, move init of logger to above here if you want to see this
    debug!("{:#?}", args);

    // If the version is asked for, just print that and exit
    if args.version {
        println!("{} version: {}", program_name, program_version);
        std::process::exit(0);
    }

    // Verify we at least got a git sha passed to us
    // (not checking to see if it is valid just yet...)
    if args.git_sha.is_empty() {
        println!("Error: GIT_SHA required\n");
        std::process::exit(1);
    }

    // Set the logging level based on the command line option and turn on the logger
    if args.verbose {
        logging_level = log::LevelFilter::max();
    }
    env_logger::builder()
        .format_timestamp(None)
        .filter_level(logging_level)
        .init();

    // Copy the command line args to our local "state" so we can pass it around
    let mut state = DyadState::new(args.git_sha.clone());

    // Set up the locations of all of our external helper programs and databases are there before
    // we attempt to use any of them
    validate_env_vars(&mut state);

    // Calculate the short and long git sha that was passed to us so we can use it later
    match git_full_id(&state, &args.git_sha) {
        Some(full_id) => state.git_sha_full = full_id,
        None => {
            error!(
                "Error: The provided git SHA1 '{}' could not be found in the repository",
                args.git_sha
            );
            std::process::exit(1);
        }
    }

    // Truncate the git sha for use later
    state.git_sha_short = state.git_sha_full.clone();
    state.git_sha_short.truncate(12);
    debug!(" Full git id: '{}'", state.git_sha_full);
    debug!("Short git id: '{}'", state.git_sha_short);

    let vulnerable = args.vulnerable.unwrap_or_default();
    if !vulnerable.is_empty() {
        state.has_vulnerable = true;
        match git_full_id(&state, &vulnerable) {
            Some(full_id) => state.vulnerable_sha = full_id,
            None => {
                error!(
                    "Error: The provided vulnerable git SHA1 '{}' could not be found in the repository",
                    vulnerable
                );
                std::process::exit(1);
            }
        }
    }

    println!(
        "{} {} {} {}",
        "#".green(),
        program_name.purple(),
        "version:".green(),
        program_version.cyan()
    );
    println!(
        "{} {}",
        "# \tgetting vulnerable:fixed pairs for git id".green(),
        state.git_sha_full.cyan()
    );

    // Find all of the places where this git commit was backported to and save them off
    let kernels = found_in(&state, &state.git_sha_full);
    for kernel in kernels {
        state.fixed_set.push(kernel);
    }

    let num_fixed = state.fixed_set.len();
    debug!(
        "We have found {} fixed kernel version/commits by this git id:",
        num_fixed
    );
    if (num_fixed) == 0 {
        error!(
            "No vulnerable and then fixed pairs of kernels were found for commit {}",
            state.git_sha_orig
        );
        std::process::exit(1);
    }
    for k in &state.fixed_set {
        debug!("\t{:<12}{}\t{}", k.version, k.git_id, k.is_mainline());
    }

    // Print fixed kernels like the bash script does
    // This goes before the pairs output to match the bash script formatting
    let mut vulnerable_kernels: Vec<Kernel> = vec![];

    if state.has_vulnerable {
        // We are asked to set the original vulnerable kernel to be a specific
        // one, so no need to look it up.

        let version = get_version(&state, &state.vulnerable_sha);
        let version = match version {
            Ok(version) => version,
            Err(error) => panic!("Can not read the version from the db, error {:?}", error),
        };
        println!(
            "# 	Setting original vulnerable kernel to be kernel {} and git id {}",
            version.clone(),
            state.vulnerable_sha
        );
        // Save off this commit
        vulnerable_kernels.push(Kernel::new(version.clone(), state.vulnerable_sha.clone()));
    } else {
        // Get the list of all valid "Fixes:" entries for this commit
        let fix_ids = get_fixes(&state, &state.git_sha_full);
        if !fix_ids.is_empty() {
            for fix_id in fix_ids {
                // Find all places this fix commit was backported to
                let backports = found_in(&state, &fix_id.git_id);

                for kernel in backports {
                    let kernel_is_mainline = kernel.is_mainline();

                    if !kernel_is_mainline {
                        // For non-mainline kernels, use the backported ID
                        debug!(
                            "Creating vulnerable set (stable): {}:{}",
                            kernel.version, kernel.git_id
                        );
                        create_vulnerable_set(&mut state, kernel.version, kernel.git_id);
                    } else {
                        // For mainline kernels, use the original fix ID
                        debug!(
                            "Creating vulnerable set (mainline): {}:{}",
                            kernel.version, fix_id.git_id
                        );
                        create_vulnerable_set(&mut state, kernel.version, fix_id.git_id.clone());
                    }
                }
            }
        } else {
            // No fixes found, check if this is a revert commit
            let revert_result = get_revert(&state, &state.git_sha_full);
            match revert_result {
                Ok(revert) => {
                    debug!("Revert: '{}'", revert);
                    if !revert.is_empty() {
                        debug!("{} is a revert of {}", &state.git_sha_full, revert.clone());
                        if let Ok(version) = get_version(&state, &revert) {
                            let mainline = version_utils::version_is_mainline(&version);
                            debug!("R\t{:<12}{}\t{}", version, revert, mainline);

                            // Save off this commit
                            vulnerable_kernels.push(Kernel::new(version.clone(), revert.clone()));

                            // Find all backports of this revert
                            let backports = found_in(&state, &revert);
                            for kernel in backports {
                                let kernel_is_mainline = kernel.is_mainline();
                                if !kernel_is_mainline {
                                    // For non-mainline kernels, use the backported ID
                                    debug!(
                                        "Creating vulnerable set for revert (stable): {}:{}",
                                        kernel.version, kernel.git_id
                                    );
                                    create_vulnerable_set(
                                        &mut state,
                                        kernel.version,
                                        kernel.git_id,
                                    );
                                } else {
                                    // For mainline kernels, use the original revert ID
                                    debug!(
                                        "Creating vulnerable set for revert (mainline): {}:{}",
                                        kernel.version, revert
                                    );
                                    create_vulnerable_set(
                                        &mut state,
                                        kernel.version,
                                        revert.clone(),
                                    );
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("Error getting revert info: {:?}", e);
                }
            }
        }
    }

    debug!("vulnerable_kernels = {:?}", vulnerable_kernels);

    // Sort vulnerable kernels topologically
    let mut sorted_vulnerable_kernels = vulnerable_kernels.clone();
    sorted_vulnerable_kernels.sort();

    // We now have a list of "vulnerable" kernels in 'vulnerable_kernels', let's find out where
    // they were backported to and create the large list of all vulnerable branches
    for k in sorted_vulnerable_kernels {
        debug!("Finding kernels with id: {}", k.git_id);

        // Find all backports of the vulnerability
        let kernels = found_in(&state, &k.git_id);
        debug!("Found kernels: {:?}", kernels);

        for kernel in kernels {
            // Check if this is a mainline kernel or not
            let kernel_is_mainline = kernel.is_mainline();

            if !kernel_is_mainline {
                // For non-mainline kernels, use the kernel_git_id from found_in (the backported ID)
                debug!("Creating vulnerable set for stable: {:?}", kernel);
                create_vulnerable_set(&mut state, kernel.version, kernel.git_id);
            } else {
                // For mainline kernels, use the original full git ID that we're looking at
                debug!(
                    "Creating vulnerable set for mainline: {}:{}",
                    kernel.version, k.git_id
                );
                create_vulnerable_set(&mut state, kernel.version, k.git_id.clone());
            }
        }
    }
    debug!("vulnerable_set = {:?}", state.vulnerable_set);

    // Now that we have a list of vulnerable kernels, we need to find the "root"
    // mainline version that had the oldest issue in it.  We might have many
    // mainline kernels listed in here, but we only care about the "oldest" one, so
    // throw away all the rest.
    //
    // To do this, we create 2 lists, one for mainline kernels, and one for stable
    // kernels.  The stable kernel list we will keep "as is", but for the mainline
    // kernel list, we will sort it and then throw away everything EXCEPT the oldest
    // kernel.  After that, we will re-create the vulnerable set with the new
    // information.
    let mut vulnerable_set: Vec<Kernel> = vec![];
    let mut vulnerable_stable_set: Vec<Kernel> = vec![];
    let mut vulnerable_mainline_set: Vec<Kernel> = vec![];
    for k in &state.vulnerable_set {
        if k.is_mainline() {
            vulnerable_mainline_set.push(k.clone());
        } else {
            vulnerable_stable_set.push(k.clone());
        }
    }
    debug!("vuln_stable_set: {}", vulnerable_stable_set.len());
    for k in &vulnerable_stable_set {
        debug!("    {:?}", k);
    }
    debug!("vuln_mainline_set: {}", vulnerable_mainline_set.len());
    for k in &vulnerable_mainline_set {
        debug!("    {:?}", k);
    }

    // The "default" vulnerable point in mainline where this issue first showed up.
    // We need this for any fix that happened in a stable branch that happened AFTER
    // this point in time (i.e. fixed in 6.6.3 for an issue that showed up in 5.4).
    let mut oldest_mainline_kernel: Kernel = Kernel::empty_kernel();
    if !vulnerable_mainline_set.is_empty() {
        debug!("Trying to find the best mainline kernel to use...");
        let mut sorted_mainline_kernels = vulnerable_mainline_set.clone();
        sorted_mainline_kernels.sort();
        oldest_mainline_kernel = sorted_mainline_kernels[0].clone();

        debug!("vuln_mainline_pair={:?}", oldest_mainline_kernel);

        vulnerable_set.push(oldest_mainline_kernel.clone());
        // iterate over all of the stable entries, and only add the ones that
        // are "older" than the mainline release.
        for k in &vulnerable_stable_set {
            if oldest_mainline_kernel.compare(k) == Ordering::Greater {
                debug!(
                    "    {:?} is > {:?}",
                    oldest_mainline_kernel.version, k.version
                );
                vulnerable_set.push(k.clone());
            }
        }
    } else {
        // No mainline kernels, so just add all stable ones
        vulnerable_set = vulnerable_stable_set;
    }

    debug!("oldest mainline kernel = {:?}", oldest_mainline_kernel);
    debug!(
        "After winnowing, we have found {} sets of vulnerable kernels",
        vulnerable_set.len()
    );
    for k in &vulnerable_set {
        debug!("    {:?}", k);
    }

    state.vulnerable_set = vulnerable_set;

    // Our "pairs of vuln/fixed kernels
    let mut fixed_pairs: Vec<KernelPair> = vec![];

    // Now we have two lists, one where the kernel became vulnerable (could not be known, so we
    // assume 0), and where it was fixed (the id originally passed to us and where it has been
    // backported to.)  Take those two lists and start matching them up based on kernel versions in
    // order to get a set of vulnerable:fixed pairs

    // First iterate over all of the "fixed" kernel versions/ids and try to match them up with any
    // vulnerable kernel entries (if any)
    for k in &state.fixed_set {
        let mut create: bool = false;

        // See if we have ANY kernels where the vulnerability showed up.  If not, assume that it
        // "has always been there", so create our final set of vulnerable/fixed pairs straight from
        // the fixed list
        debug!("\t k={:?}", k);
        if state.vulnerable_set.is_empty() {
            fixed_pairs.push(KernelPair {
                vulnerable: Kernel::empty_kernel(),
                fixed: k.clone(),
            });
            //create = true;
            continue;
        }

        // We have some vulnerable entries, so let's try to match them up
        for v in &state.vulnerable_set {
            if k.version == v.version {
                // vulnerable and fixed in the same version.  Save this off as
                // it is needed for the git vulnerable information (small window
                // of where things went wrong).
                debug!("\t\t{} == {} save it", k.version, v.version);
                fixed_pairs.push(KernelPair {
                    vulnerable: v.clone(),
                    fixed: k.clone(),
                });
                create = true;
                break;
            }

            // If these are both mainline commits then create a matching pair
            if k.is_mainline() && v.is_mainline() {
                debug!(
                    "\t\t{} and {} are both mainline, save it",
                    k.version, v.version
                );
                fixed_pairs.push(KernelPair {
                    vulnerable: v.clone(),
                    fixed: k.clone(),
                });
                create = true;
                break;
            }

            // if this is the same X.Y version, make a pair
            if v.version_major_match(k) {
                debug!(
                    "\t\t{} and {} are same major release, save it",
                    k.version, v.version
                );
                fixed_pairs.push(KernelPair {
                    vulnerable: v.clone(),
                    fixed: k.clone(),
                });
                create = true;
                break;
            }
        }

        // We did not create any entry at all above, so we need to set the
        // "default" vulnerable point to the original vulnerable mainline pair
        // found way above as that's where the issue showed up (i.e before this
        // stable kernel branch was forked from mainline.)
        if !create {
            if oldest_mainline_kernel.is_mainline() {
                debug!(
                    "\tnothing found for {}, using default of {:?}",
                    k.version, oldest_mainline_kernel
                );
                fixed_pairs.push(KernelPair {
                    vulnerable: oldest_mainline_kernel.clone(),
                    fixed: k.clone(),
                });
            } else {
                debug!(
                    "\tno mainline pair vulnerable at this point in time (fix in the future?), so skipping {}",
                    k.version
                );
            }
        }
    }

    // Now the fun starts, which justified all of the hard work we did above.  We need to track the
    // places where we are vulnerable, but NOT fixed.  So walk the vulnerable list, see if anything
    // in the fixed_pair matches up, and if NOT, then add it to the list as an "unfixed" pair
    for v in &state.vulnerable_set {
        let mut found: bool = false;

        for e in &fixed_pairs {
            if v.version == e.vulnerable.version && v.git_id == e.vulnerable.git_id {
                found = true;
                break;
            }
            if v.version == e.fixed.version {
                found = true;
                break;
            }
        }
        if !found {
            debug!("not found {:?}", v);
            fixed_pairs.push(KernelPair {
                vulnerable: v.clone(),
                fixed: Kernel::empty_kernel(),
            });
        }
    }

    // We are done!
    // Print out the pairs we found so that bippy can do something with them.
    debug!(
        "Number of vulnerable / fixed kernel pairs: {}",
        fixed_pairs.len()
    );
    debug!("Final output:");
    for e in &fixed_pairs {
        //debug!("Pair: {}:{} => {}:{}", e.vulnerable.version, e.vulnerable.git_id, e.fixed.version, e.fixed.git_id);
        println!(
            "{}:{}:{}:{}",
            e.vulnerable.version.green(),
            e.vulnerable.git_id.cyan(),
            e.fixed.version.green(),
            e.fixed.git_id.cyan()
        );
    }
}
