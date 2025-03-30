// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Greg Kroah-Hartman <gregkh@linuxfoundation.org>
//
// dyad - create a listing of "pairs" of vulnerable:fixed kernels based on a
//        specific git SHA that purports to fix an issue.  Used in combination
//        with 'bippy' to create CVE entries for the Linux kernel.  Is VERY
//        specific to how the Linux kernel has its stable branches and how it
//        labels things.

use gumdrop::Options;
use log::{debug, error};
use rusqlite::fallible_iterator::FallibleIterator;
use rusqlite::{Connection, Result};
//use rusqlite::{params, Connection, Result};
//use std::collections::HashMap;
use colored::Colorize;
use git2::Repository;
use rusqlite::Error as SqliteError;
use std::cmp::Ordering;
use std::env;
use std::env::temp_dir;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Write;
use std::path::Path;
use std::process;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::path::PathBuf;

// Static counter for generating unique IDs for temp files
static TEMP_FILE_COUNTER: AtomicUsize = AtomicUsize::new(1);

pub mod kernel;
use kernel::Kernel;
use kernel::KernelPair;

// Custom error type for standardized error handling
#[derive(Debug)]
pub enum DyadError {
    Io(io::Error),
    Sqlite(SqliteError),
    Git(git2::Error),
    EnvVar(String),
    GitCommand(String),
    ParseError(String),
    NotFound(String),
}

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
    //    fixed_pairs: Vec<KernelPair>,
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
            //fixed_pairs: vec![],
        }
    }
}

// Find the vulns repository root directory by traversing up from current directory
fn find_vulns_dir() -> std::io::Result<PathBuf> {
    let mut current_dir = env::current_dir()?;

    // Check if we're already in the vulns repo
    if current_dir.file_name().is_some_and(|name| name == "vulns") {
        return Ok(current_dir);
    }

    // Traverse up the directory tree
    while current_dir.parent().is_some() {
        if current_dir.file_name().is_some_and(|name| name == "vulns") {
            return Ok(current_dir);
        }

        if !current_dir.pop() {
            break;
        }
    }

    Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Could not find vulns directory"))
}

fn validate_env_vars(state: &mut DyadState) {
    // CVEKERNELTREE environment variable must be set
    match env::var("CVEKERNELTREE") {
        Ok(val) => state.kernel_tree = val,
        Err(_error) => panic!("Environment variable CVEKERNELTREE not found, please set!"),
    };
    debug!("kernel_tree = {}", state.kernel_tree);

    // Validate that this really is a git directory by looking for .git/
    let git_dir = state.kernel_tree.clone() + "/.git";
    match fs::exists(git_dir.clone()) {
        Ok(true) => debug!("{} path found", git_dir),
        Ok(false) => panic!(
            "CVEKERNELTREE value of {} is not found, please set to valid git directory",
            git_dir
        ),
        Err(e) => panic!(
            "Error {e}: Something went wrong trying to lookup the path for '{}'",
            git_dir
        ),
    }

    // Find the path to the verhaal.db database file using vulns dir
    let vulns_dir = match find_vulns_dir() {
        Ok(dir) => dir,
        Err(_) => panic!("Could not find vulns directory"),
    };

    let verhaal_db_path = vulns_dir.join("tools").join("verhaal").join("verhaal.db");
    match fs::exists(&verhaal_db_path) {
        Ok(true) => state.verhaal_db = verhaal_db_path.to_string_lossy().into_owned(),
        Ok(false) => panic!(
            "The verhaal database 'verhaal.db' is not found at expected path: {}",
            verhaal_db_path.display()
        ),
        Err(e) => panic!(
            "Error {e}: Something went wrong trying to lookup the path for 'verhaal.db'"
        ),
    }
    debug!("verhaal.db = {}", state.verhaal_db);
}

/*
fn create_fix_set(state: &mut DyadState, version: String, git_id: String) {
    state.fixed_set.push(Kernel::new(version, git_id));
    //debug!("create_fix_set: version: {}\tgit_id: {}\tmainline: {}", version, git_id, mainline);
}
*/

fn create_vulnerable_set(state: &mut DyadState, version: String, git_id: String) {
    let mainline = Kernel::version_is_mainline(&version);

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

    let repo_path = &state.kernel_tree;

    // Try to open the git repository
    let repo = match Repository::open(repo_path) {
        Ok(repo) => repo,
        Err(e) => {
            error!("Error opening repository {}: {}", repo_path, e);
            std::process::exit(1);
        }
    };

    // Try to resolve the object ID (similar to git rev-parse)
    match repo.revparse_single(git_sha) {
        Ok(object) => {
            let full_id = object.id().to_string();
            Some(full_id)
        }
        Err(e) => {
            debug!("Notice: git SHA1 {} not found: {}", git_sha, e);
            None
        }
    }
}

/// Helper function to exec a sql statement that always returns a string vector, even if the sql
/// statement fails (meaning it didn't match anything).  Takes one param, really should just make
/// it all in the sql string one day...
fn sql_wrap(conn: &Connection, sql: String, param: &String) -> Vec<String> {
    let mut sql = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let rows = match sql.query(rusqlite::params![param]) {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    rows.map(|row| row.get(0)).collect().unwrap_or_default()
}

/// Helper function to exec a sql statement that always returns a u32 vector, even if the sql
/// statement fails (meaning it didn't match anything).  Takes one param, really should just make
/// it all in the sql string one day...
fn sql_wrap_u32(conn: &Connection, sql: String, param: &String) -> Vec<u32> {
    let mut sql = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let rows = match sql.query(rusqlite::params![param]) {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    rows.map(|row| row.get(0)).collect().unwrap_or_default()
}

/// Determines the list of kernels where a specific git sha has been backported to, both mainline
/// and stable kernel releases, if any.
fn found_in(state: &DyadState, git_sha: &String) -> Vec<Kernel> {
    let verhaal_db = &state.verhaal_db;
    let mut found_in: Vec<Kernel> = vec![];

    let conn = match Connection::open(verhaal_db) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let mut ids = sql_wrap(
        &conn,
        "SELECT id from commits WHERE mainline_id=?1;".to_string(),
        git_sha,
    );
    debug!("\t\tfound_in: ids: {:?}", ids);

    for id in ids {
        // First, check if this git id has already been added to the fixed list
        let mut skip = false;
        for existing in &state.fixed_set {
            if existing.git_id == id {
                skip = true;
                break;
            }
        }

        if skip {
            continue;
        }

        debug!("\t\tfound_in: looking at id {:?}", id);

        // Check for a revert before adding it to our list
        let reverts = sql_wrap(
            &conn,
            "SELECT id FROM commits WHERE reverts=?1;".to_string(),
            &id,
        );
        if !reverts.is_empty() {
            // we have a revert, so just skip this id entirely
            debug!(
                "\t\tfound_in: {:?} is a revert of {:?}, skipping",
                id, reverts
            );
            continue;
        }

        // See if this commit itself is a revert of something else (if so, let's not add it)
        let reverts = sql_wrap(
            &conn,
            "SELECT reverts FROM commits WHERE id=?1;".to_string(),
            &id,
        );
        for revert in reverts {
            debug!("\t\tfound_in: {:?} reverts commit {:?}", id, revert);
            // See if what we are reverting is a stable, or a mainline
            // commit.  If stable, skip it, if mainline, it's ok to add (as
            // this is just a backport of an upstream revert).
            let mainlines = sql_wrap_u32(
                &conn,
                "SELECT mainline FROM commits WHERE id=?1;".to_string(),
                &revert,
            );
            debug!("\t\tfound_in: mainlines = {:?}", mainlines);

            for mainline in mainlines {
                if mainline == 0 {
                    debug!(
                        "\t\tfound_in: {:?} reverts the stable commit {:?} so skip it",
                        id, revert
                    );
                    skip = true;
                }
            }
        }
        if skip {
            debug!("\t\tfound_in: skipping {:?}", id);
            continue;
        }

        // Get the version for this release and save it to the list
        if let Ok(version) = get_version(state, &id) {
            found_in.push(Kernel::new(version, id));
        }
    }

    // Grab the mainline commit if it is there as well
    ids = sql_wrap(
        &conn,
        "SELECT id from commits WHERE id=?1;".to_string(),
        git_sha,
    );
    debug!("\t\tfound_in: mainline id: {:?}", ids);
    for id in ids {
        // Get the version for this release and save it to the list
        if let Ok(version) = get_version(state, &id) {
            found_in.push(Kernel::new(version, id));
        }
    }

    // Sort the kernels to keep things sane and deterministic (the database does not always have
    // kernel ids sorted in order as we add new releases to the end from older kernel trees (i.e. a
    // new 6.1.y kernel is released every week.)
    found_in.sort();

    debug!("\t\tfound_in: {:?}", found_in);
    found_in
}

fn get_version(state: &DyadState, git_sha: &String) -> Result<String> {
    let verhaal_db = &state.verhaal_db;

    // Open db connection
    let conn = Connection::open(verhaal_db)?;
    let mut sql = conn.prepare("SELECT release from commits WHERE id=?1")?;
    let mut rows = sql.query(rusqlite::params![git_sha])?;

    // Check if we have a row and return it
    if let Some(row) = rows.next()? {
        let version = row.get(0);
        debug!(
            "\t\tverhaal_db: {}\tget_version: '{}' => '{:?}'",
            verhaal_db, git_sha, version
        );
        return version;
    }

    debug!(
        "\t\tverhaal_db: {}\tget_version: '{}' => VERSION NOT FOUND",
        verhaal_db, git_sha
    );
    Err(rusqlite::Error::QueryReturnedNoRows)
}

//
// Returns a ' ' separated list of Fixes
// If no fix is found "" is returned, NOT an error, to make code flow easier.
// Errors are only returned if something went wrong with the sql stuff
fn get_fixes(state: &DyadState, git_sha: &String) -> Result<String> {
    let verhaal_db = &state.verhaal_db;

    // Open db connection
    let conn = Connection::open(verhaal_db)?;
    let mut sql = conn.prepare("SELECT fixes FROM commits WHERE id=?1")?;
    let mut rows = sql.query(rusqlite::params![git_sha])?;

    // Check if we have a row and return it
    if let Some(row) = rows.next()? {
        let r: Result<String> = row.get(0);
        match r {
            Ok(r) => {
                debug!(
                    "\t\tverhaal_db: {}\tget_fixes: '{}' => '{}",
                    verhaal_db, git_sha, r
                );
                return Ok(r);
            }
            Err(_error) => {
                debug!("\t\tNo fixes found for {}", git_sha);
                return Ok("".to_string());
            }
        }
    }

    // If no rows found, return empty string instead of error
    debug!("\t\tNo row found for {} in fixes query", git_sha);
    Ok("".to_string())
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
    let mut sql = conn.prepare("SELECT reverts from commits WHERE id=?1")?;
    let mut rows = sql.query(rusqlite::params![git_sha])?;

    // Check if we have a row and return it
    if let Some(row) = rows.next()? {
        let r: Result<String> = row.get(0);
        match r {
            Ok(r) => return Ok(r),
            Err(_error) => return Ok("".to_string()),
        }
    }

    // If no rows found, return empty string instead of error
    Ok("".to_string())
}

// Add this function to topologically sort the fix commits, similar to the bash implementation's
// sort_order=$($git_cmd rev-list --topo-order $(cat "${v_file}") | grep --file="${v_file}" --max-count=${#v[@]} | tac)
fn sort_commits_topologically(state: &DyadState, commits: &Vec<Kernel>) -> Vec<Kernel> {
    // If we have 0 or 1 commits, no need to sort
    if commits.len() <= 1 {
        return commits.clone();
    }

    debug!("Need to sort {} commits", commits.len());
    for k in commits {
        debug!("To sort: {}:{}", k.version, k.git_id);
    }

    // Extract all git IDs for sorting
    let git_ids: Vec<String> = commits.iter().map(|k| k.git_id.clone()).collect();

    // Create a map from git ID to Kernel for later lookup
    let mut kernel_map = std::collections::HashMap::new();
    for kernel in commits {
        kernel_map.insert(kernel.git_id.clone(), kernel.clone());
    }

    // Instead of using libgit2's revwalk, use a direct call to git
    // This is much faster as it's similar to what the bash script does

    // Create a unique identifier for the temp file using PID and atomic counter
    let pid = process::id();
    let unique_id = TEMP_FILE_COUNTER.fetch_add(1, AtomicOrdering::SeqCst);
    let temp_filename = format!("dyad_sort_tmp_{}_{}", pid, unique_id);

    let mut temp_path = temp_dir();
    temp_path.push(temp_filename);
    let temp_file_path = temp_path.to_str().unwrap();

    let mut temp_file = File::create(&temp_path).unwrap();
    for id in &git_ids {
        writeln!(temp_file, "{}", id).unwrap();
    }

    // Execute the git command directly, like the bash script does
    // This exactly matches the bash implementation:
    // sort_order=$($git_cmd rev-list --topo-order $(cat "${v_file}") | grep --file="${v_file}" --max-count=${#v[@]} | tac)
    let git_cmd = format!(
        "git --git-dir={}/.git rev-list --topo-order $(cat {}) | grep --file={} --max-count={} | tac",
        state.kernel_tree,
        temp_file_path,
        temp_file_path,
        git_ids.len()
    );

    debug!("Running git command: {}", git_cmd);

    let output = Command::new("sh").arg("-c").arg(&git_cmd).output().unwrap();

    // Clean up the temp file
    if Path::new(&temp_path).exists() {
        std::fs::remove_file(&temp_path).unwrap_or_else(|e| {
            debug!("Warning: Could not remove temp file: {}", e);
        });
    }

    // Parse the output into a list of sorted IDs
    let sorted_ids: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    debug!("Topological sort_order={:?}", sorted_ids);

    // For each sorted commit, get its version and form version:id pairs
    let mut version_id_pairs: Vec<String> = Vec::new();
    for id in &sorted_ids {
        if let Ok(version) = get_version(state, id) {
            version_id_pairs.push(format!("{}:{}", version, id));
            debug!("Processing commit {}:{}", version, id);
        } else {
            debug!("Could not get version for commit {}", id);
        }
    }

    // Use bash's sort -V directly to ensure exact compatibility
    debug!("Version:id pairs before sorting: {:?}", version_id_pairs);

    // If no pairs, return empty result
    if version_id_pairs.is_empty() {
        return Vec::new();
    }

    // Run the bash sort -V command to get the first entry
    let sort_cmd = format!(
        "printf '%s\\n' {} | sort -V | head -n 1",
        version_id_pairs.join(" ")
    );
    debug!("Running bash sort command: {}", sort_cmd);

    let sort_output = Command::new("sh")
        .arg("-c")
        .arg(&sort_cmd)
        .output()
        .unwrap();

    let selected_pair = String::from_utf8_lossy(&sort_output.stdout)
        .trim()
        .to_string();
    debug!("Bash sort -V selected: {}", selected_pair);

    // Extract the ID part from the selected pair
    if !selected_pair.is_empty() {
        let parts: Vec<&str> = selected_pair.split(':').collect();
        if parts.len() >= 2 {
            let selected_id = parts[1];
            if let Some(kernel) = kernel_map.get(selected_id) {
                // Return just this one kernel as bash does
                debug!(
                    "Returning selected kernel: {}:{}",
                    kernel.version, kernel.git_id
                );
                return vec![kernel.clone()];
            }
        }
    }

    // Fallback to original list if something went wrong
    debug!("Falling back to original sort order");
    let mut sorted_kernels: Vec<Kernel> = sorted_ids
        .iter()
        .filter_map(|id| kernel_map.get(id).cloned())
        .collect();

    // Add any kernels that weren't found during sorting
    for kernel in commits {
        if !sorted_kernels.iter().any(|k| k.git_id == kernel.git_id) {
            sorted_kernels.push(kernel.clone());
        }
    }

    sorted_kernels
}

fn main() {
    // Default to no logging, can turn it on based on the command line.
    // Note, RUST_LOG_LEVEL does NOT work here anymore.  See
    // https://docs.rs/env_logger/latest/env_logger/#specifying-defaults-for-environment-variables
    // for a possible way to fix this up if anyone gets bored.
    let mut logging_level: log::LevelFilter = log::LevelFilter::Error;

    let program_name = env!("CARGO_PKG_NAME");
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
    //debug!("fixed= {:?}", state.fixed_set);
    for k in &state.fixed_set {
        debug!("\t{:<12}{}\t{}", k.version, k.git_id, k.is_mainline());
    }

    // Print fixed kernels like the bash script does
    // This goes before the pairs output to match the bash script formatting
    let mut vulnerable_kernels: Vec<Kernel> = vec![];
    // Track all fix entries across the function
    let fix_entries: Vec<String>;

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
        // In case we have multiple fix entries from things like "Fixes:" lines, use the one
        // that the bash script would use after sorting.
        let fixes_result = get_fixes(&state, &state.git_sha_full);
        match fixes_result {
            Ok(fixes) => {
                debug!("\tFixes vector: {:?}", fixes.split_whitespace().collect::<Vec<&str>>());

                // Process all fix entries similar to how the bash script does
                let fix_ids: Vec<String> = fixes.split_whitespace().map(|s| s.to_string()).collect();

                // If we have at least one fix, then sort them topologically
                if !fix_ids.is_empty() {
                    // Create a temp file with all fix_ids for the git command to use
                    let pid = process::id();
                    let unique_id = TEMP_FILE_COUNTER.fetch_add(1, AtomicOrdering::SeqCst);
                    let temp_filename = format!("dyad_fixes_tmp_{}_{}", pid, unique_id);
                    let mut temp_path = temp_dir();
                    temp_path.push(temp_filename);
                    let temp_file_path = temp_path.to_str().unwrap();

                    let mut temp_file = File::create(&temp_path).unwrap();
                    for id in &fix_ids {
                        writeln!(temp_file, "{}", id).unwrap();
                    }

                    // Run the git command to sort the fixes topologically
                    let git_cmd = format!(
                        "git --git-dir={}/.git rev-list --topo-order $(cat {}) | grep --file={} --max-count={} | tac",
                        state.kernel_tree,
                        temp_file_path,
                        temp_file_path,
                        fix_ids.len()
                    );
                    debug!("Running git command for fixes: {}", git_cmd);

                    let output = Command::new("sh").arg("-c").arg(&git_cmd).output().unwrap();

                    // Clean up the temp file
                    if Path::new(&temp_path).exists() {
                        std::fs::remove_file(&temp_path).unwrap_or_else(|e| {
                            debug!("Warning: Could not remove temp file: {}", e);
                        });
                    }

                    // Parse the output
                    let sorted_fixes: Vec<String> = String::from_utf8_lossy(&output.stdout)
                        .split_whitespace()
                        .map(|s| s.to_string())
                        .collect();

                    debug!("Sorted fixes: {:?}", sorted_fixes);

                    // Store all fix entries for later processing
                    fix_entries = sorted_fixes.clone();

                    // Directly emulate the bash script's handling of fixes
                    for fix_id in &fix_entries {
                        // Find all places this fix commit was backported to
                        let backports = found_in(&state, fix_id);

                        for kernel in backports {
                            let kernel_is_mainline = kernel.is_mainline();

                            if !kernel_is_mainline {
                                // For non-mainline kernels, use the backported ID
                                debug!("Creating vulnerable set (stable): {}:{}", kernel.version, kernel.git_id);
                                create_vulnerable_set(&mut state, kernel.version, kernel.git_id);
                            } else {
                                // For mainline kernels, use the original fix ID
                                debug!("Creating vulnerable set (mainline): {}:{}", kernel.version, fix_id);
                                create_vulnerable_set(&mut state, kernel.version, fix_id.clone());
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
                                    let mainline = Kernel::version_is_mainline(&version);
                                    debug!("R\t{:<12}{}\t{}", version, revert, mainline);

                                    // Save off this commit
                                    vulnerable_kernels.push(Kernel::new(version.clone(), revert.clone()));

                                    // Find all backports of this revert
                                    let backports = found_in(&state, &revert);
                                    for kernel in backports {
                                        let kernel_is_mainline = kernel.is_mainline();
                                        if !kernel_is_mainline {
                                            // For non-mainline kernels, use the backported ID
                                            debug!("Creating vulnerable set for revert (stable): {}:{}", kernel.version, kernel.git_id);
                                            create_vulnerable_set(&mut state, kernel.version, kernel.git_id);
                                        } else {
                                            // For mainline kernels, use the original revert ID
                                            debug!("Creating vulnerable set for revert (mainline): {}:{}", kernel.version, revert);
                                            create_vulnerable_set(&mut state, kernel.version, revert.clone());
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
            Err(e) => {
                debug!("No fixes found, error: {:?}", e);
            }
        }
    }

    debug!("vulnerable_kernels = {:?}", vulnerable_kernels);

    // Sort vulnerable kernels topologically, similar to bash's "sort_order" processing
    let sorted_vulnerable_kernels = sort_commits_topologically(&state, &vulnerable_kernels);

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

        // In the bash script:
        // temp+=$(echo -e "${vuln_entry} \n")
        // vuln_mainline_pair=$(printf "%s\n" ${temp} | sort -V | head -n 1)
        //
        // This sorts strings with embedded version numbers, and when versions
        // are the same, it does alphabetical sorting on the remainder of the string.

        // Create version:id pairs for sorting
        let mut version_id_pairs: Vec<String> = Vec::new();
        for k in &vulnerable_mainline_set {
            version_id_pairs.push(format!("{}:{}", k.version, k.git_id));
        }

        // Use bash's sort -V directly to ensure exact compatibility
        debug!("Version:id pairs before sorting: {:?}", version_id_pairs);

        // Run the bash sort -V command to get the first entry
        let sort_cmd = format!(
            "printf '%s\\n' {} | sort -V | head -n 1",
            version_id_pairs.join(" ")
        );
        debug!("Running bash sort command: {}", sort_cmd);

        let sort_output = Command::new("sh")
            .arg("-c")
            .arg(&sort_cmd)
            .output()
            .unwrap();

        let selected_pair = String::from_utf8_lossy(&sort_output.stdout)
            .trim()
            .to_string();
        debug!("Bash sort -V result (first entry): {}", selected_pair);

        // Extract the ID part from the selected pair
        if !selected_pair.is_empty() {
            let parts: Vec<&str> = selected_pair.split(':').collect();
            if parts.len() >= 2 {
                let selected_version = parts[0];
                let selected_id = parts[1];
                oldest_mainline_kernel = Kernel::new(selected_version.to_string(), selected_id.to_string());
                debug!("Using vulnerable kernel from sort -V: {}:{}", selected_version, selected_id);
            }
        } else {
            // Fallback to original sort
            let mut sorted_mainline_kernels = vulnerable_mainline_set.clone();
            sorted_mainline_kernels.sort();
            oldest_mainline_kernel = sorted_mainline_kernels[0].clone();
        }

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
