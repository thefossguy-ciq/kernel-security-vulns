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
//
// Usage: dyad --sha1 <git-sha> [--sha1 <git-sha> ...] [--vulnerable <git-sha> ...]

use colored::Colorize;
use gumdrop::Options;
use log::{debug, error};
use rusqlite::{Result};
use std::cmp::Ordering;
use std::env;
use std::fs;
use std::path::Path;
extern crate cve_utils;
use cve_utils::version_utils;
use cve_utils::Kernel;
use cve_utils::KernelPair;
use cve_utils::Verhaal;

// Using more specific error types directly instead of a custom error enum

#[derive(Debug, Options)]
struct DyadArgs {
    #[options(help_flag, help = "Print this help message")]
    help: bool,

    #[options(short = "V", help = "Show version")]
    version: bool,

    #[options(no_short, help = "Show debugging information to stdout")]
    verbose: bool,

    #[options(
        short = "s",
        help = "The kernel git sha1 that fixes this issue",
        multi = "push"
    )]
    sha1: Vec<String>,

    #[options(
        short = "v",
        help = "The kernel git sha1 that this issue became vulnerable at",
        multi = "push"
    )]
    vulnerable: Vec<String>,
}

struct DyadState {
    kernel_tree: String,
    verhaal_db: String,
    vulnerable_sha: Vec<String>,
    git_sha_full: Vec<String>,
    fixed_set: Vec<Kernel>,
    vulnerable_set: Vec<Kernel>,
}

impl DyadState {
    pub fn new() -> Self {
        Self {
            // Init with some "blank" default, the command line and
            // environment variables will override them
            kernel_tree: String::new(),
            verhaal_db: String::new(),
            vulnerable_sha: vec![],
            git_sha_full: vec![],
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

    if let Ok(k) = Kernel::new(version.clone(), git_id.clone()) {
        state.vulnerable_set.push(k);
        debug!(
            "create_vulnerable_set: version: {}\tgit_id: {}\tmainline: {}",
            version.clone(),
            git_id.clone(),
            mainline
        );
    } else {
        debug!(
            "create_vulnerable_set FAILED!: version: {}\tgit_id: {}\tmainline: {}",
            version.clone(),
            git_id.clone(),
            mainline
        );
    }
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

/// Determines the list of kernels where a specific git sha has been backported to, both mainline
/// and stable kernel releases, if any.
fn found_in(state: &DyadState, git_sha: &String) -> Vec<Kernel> {
    let verhaal = match Verhaal::new(state.verhaal_db.clone()) {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    return verhaal.found_in(git_sha, &state.fixed_set);
}

fn get_version(state: &DyadState, git_sha: &String) -> Result<String> {
    let verhaal = Verhaal::new(state.verhaal_db.clone())?;

    return verhaal.get_version(git_sha);
}

/// Returns a vector of kernels that are fixes for this specific git id as listed in the database.
/// All kernels returned are actual commits, they are validated before returned as the database can
/// contain "bad" data for fixes lines.
/// If an error happened, or there are no fixes, an "empty" vector is returned.
fn get_fixes(state: &DyadState, git_sha: &String) -> Vec<Kernel> {
    let verhaal = match Verhaal::new(state.verhaal_db.clone()) {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    return verhaal.get_fixes(git_sha);
}

//
// Returns a sha for the revert if present
// If no revert is found, "" is returned, NOT an error, to make code flow easier.
// Errors are only returned if something went wrong with the sql stuff
fn get_revert(state: &DyadState, git_sha: &String) -> Result<String> {
    let verhaal = Verhaal::new(state.verhaal_db.clone())?;

    return verhaal.get_revert(git_sha);
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

    // Verify we at least got a git sha passed to us using the --sha1 flag
    // (not checking to see if it is valid just yet...)
    if args.sha1.is_empty() {
        println!("Error: At least one --sha1 value is required\n");
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
    let mut state = DyadState::new();

    // Set up the locations of all of our external helper programs and databases are there before
    // we attempt to use any of them
    validate_env_vars(&mut state);

    // Calculate full git sha for each fixing SHA1 that was passed to us
    state.git_sha_full.clear(); // Clear any existing values
    for git_sha in &args.sha1 {
        match git_full_id(&state, git_sha) {
            Some(full_id) => state.git_sha_full.push(full_id),
            None => {
                error!(
                    "Error: The provided git SHA1 '{}' could not be found in the repository",
                    git_sha
                );
                std::process::exit(1);
            }
        }
    }

    for (idx, full_id) in state.git_sha_full.iter().enumerate() {
        debug!(" Full git id {}: '{}'", idx, full_id);
    }

    // Parse the vulnerable command line and create a vector of vulnerable kernel ids.
    let vuln_ids = args.vulnerable.clone();
    for vuln_id in vuln_ids {
        match git_full_id(&state, &vuln_id) {
            Some(id) => {
                state.vulnerable_sha.push(id);
            }
            None => {
                error!(
                    "Error: The provided vulnerable git SHA1 '{}' could not be found in the repository",
                    vuln_id
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

    // Print all fixing SHA1s
    for git_sha in &state.git_sha_full {
        println!(
            "{} {}",
            "# \tgetting vulnerable:fixed pairs for git id".green(),
            git_sha.cyan()
        );
    }

    // Find all of the places where each git commit was backported to and save them off
    for git_sha in &state.git_sha_full {
        let kernels = found_in(&state, git_sha);
        for kernel in kernels {
            // Check if we already have this kernel in our fixed set
            if !state.fixed_set.iter().any(|k| k.git_id == kernel.git_id && k.version == kernel.version) {
                state.fixed_set.push(kernel);
            }
        }
    }

    let num_fixed = state.fixed_set.len();
    debug!(
        "We have found {} fixed kernel version/commits by these git ids:",
        num_fixed
    );
    if (num_fixed) == 0 {
        error!(
            "No vulnerable and then fixed pairs of kernels were found for the provided commit(s)",
        );
        std::process::exit(1);
    }
    for k in &state.fixed_set {
        debug!("\t{:<12}{}\t{}", k.version, k.git_id, k.is_mainline());
    }

    // Print fixed kernels like the bash script does
    // This goes before the pairs output to match the bash script formatting
    let mut vulnerable_kernels: Vec<Kernel> = vec![];

    if !state.vulnerable_sha.is_empty() {
        // We are asked to set the original vulnerable kernel to be a specific
        // one, or many, so no need to look it up.
        for id in &state.vulnerable_sha {
            let version = get_version(&state, id);
            let version = match version {
                Ok(version) => version,
                Err(error) => panic!("Can not read the version from the db, error {:?}", error),
            };
            println!(
                "# \tSetting original vulnerable kernel to be kernel {} and git id {}",
                version.clone(),
                id
            );
            // Save off this commit
            if let Ok(k) = Kernel::new(version.clone(), id.to_string()) {
                vulnerable_kernels.push(k);
            }
        }
    }

    // Only derive vulnerabilities from the fixing SHA1s if no explicit vulnerable commits were provided
    let mut all_vulnerable_candidates = Vec::new();

    if state.vulnerable_sha.is_empty() {
        // Only try to derive vulnerabilities from the fixing SHA1s if no explicit vulnerable commits were provided
        for git_sha in &state.git_sha_full {
            // Get the list of all valid "Fixes:" entries for this commit
            let fix_ids = get_fixes(&state, git_sha);
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
                            all_vulnerable_candidates.push((kernel.version.clone(), kernel.git_id.clone()));
                        } else {
                            // For mainline kernels, use the original fix ID
                            debug!(
                                "Creating vulnerable set (mainline): {}:{}",
                                kernel.version, fix_id.git_id
                            );
                            all_vulnerable_candidates.push((kernel.version.clone(), fix_id.git_id.clone()));
                        }
                    }
                }
            } else {
                // No fixes found, check if this is a revert commit
                let revert_result = get_revert(&state, git_sha);
                match revert_result {
                    Ok(revert) => {
                        debug!("Revert: '{}'", revert);
                        if !revert.is_empty() {
                            debug!("{} is a revert of {}", git_sha, revert.clone());
                            if let Ok(version) = get_version(&state, &revert) {
                                let mainline = version_utils::version_is_mainline(&version);
                                debug!("R\t{:<12}{}\t{}", version, revert, mainline);

                                // Save off this commit
                                if let Ok(k) = Kernel::new(version.clone(), revert.clone()) {
                                    vulnerable_kernels.push(k);
                                }

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
                                        all_vulnerable_candidates.push((kernel.version.clone(), kernel.git_id.clone()));
                                    } else {
                                        // For mainline kernels, use the original revert ID
                                        debug!(
                                            "Creating vulnerable set for revert (mainline): {}:{}",
                                            kernel.version, revert
                                        );
                                        all_vulnerable_candidates.push((kernel.version.clone(), revert.clone()));
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

        // Now add all candidates to the state
        for (version, git_id) in all_vulnerable_candidates {
            create_vulnerable_set(&mut state, version, git_id);
        }
    } else {
        // When --vulnerable is provided, only use those specific commits
        debug!("Using only explicitly provided vulnerable commits, skipping 'Fixes:' tag processing");
        // Add the explicitly provided vulnerable commits directly to vulnerable_set
        for k in &vulnerable_kernels {
            state.vulnerable_set.push(k.clone());
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

        // Add both explicitly specified vulnerabilities and the oldest mainline kernel
        // for detected vulnerabilities
        if !vulnerable_kernels.is_empty() {
            // Add all explicitly specified vulnerabilities
            vulnerable_set.extend(vulnerable_kernels.clone());

            // Also add the oldest mainline kernel if it's not already included
            let already_included = vulnerable_kernels.iter().any(|k|
                k.version == oldest_mainline_kernel.version && k.git_id == oldest_mainline_kernel.git_id);
            if !already_included {
                vulnerable_set.push(oldest_mainline_kernel.clone());
            }
        } else {
            // For detected vulnerabilities, use the oldest as default
            vulnerable_set.push(oldest_mainline_kernel.clone());
        }

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

        // Also add any explicitly provided vulnerable kernels
        if !vulnerable_kernels.is_empty() {
            for k in &vulnerable_kernels {
                // Only add if not already in the set
                if !vulnerable_set.iter().any(|x| x.version == k.version && x.git_id == k.git_id) {
                    vulnerable_set.push(k.clone());
                }
            }
        }
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
            continue;
        }

        // Sort vulnerable kernels by version for more predictable pairing
        let mut sorted_vulnerabilities = state.vulnerable_set.clone();
        sorted_vulnerabilities.sort();

        // First, check if there are any mainline vulnerabilities in our set
        let mainline_vulns = sorted_vulnerabilities.iter()
            .filter(|k| k.is_mainline())
            .collect::<Vec<_>>();

        // Priority 1: Exact version match
        for v in &sorted_vulnerabilities {
            if k.version == v.version {
                debug!("\t\t{} == {} save it", k.version, v.version);
                fixed_pairs.push(KernelPair {
                    vulnerable: v.clone(),
                    fixed: k.clone(),
                });
                create = true;
                break;
            }
        }

        // If we haven't found a match yet, try other matching strategies
        if !create {
            // Priority 2: Mainline to mainline special case (both are mainline releases)
            if k.is_mainline() && !mainline_vulns.is_empty() {
                // For mainline fixes, pair with all mainline vulnerabilities
                // This ensures each mainline vulnerability gets a chance to pair with each mainline fix
                // The filtering step will remove duplicates later
                for mainline_vuln in &mainline_vulns {
                    // Only add pairs where fix version >= vulnerable version
                    if k.compare(mainline_vuln) != std::cmp::Ordering::Less {
                        debug!(
                            "\t\t{} and {} are both mainline, save it",
                            k.version, mainline_vuln.version
                        );
                        fixed_pairs.push(KernelPair {
                            vulnerable: (*mainline_vuln).clone(),
                            fixed: k.clone(),
                        });
                    }
                }
                create = true;
            }
            // Priority 3: Same major version line
            else if !create {
                for v in &sorted_vulnerabilities {
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
            }
        }

        // Priority 4: If still no match and we have mainline vulnerabilities,
        // always use the closest future mainline vulnerability regardless of version proximity
        if !create && !mainline_vulns.is_empty() {
            // Find the best mainline vulnerability match based on version proximity
            let mut best_match: Option<&Kernel> = None;
            let mut best_match_score = std::i32::MAX;

            for v in &mainline_vulns {
                // Convert versions to components for comparison
                let v_version_parts: Vec<i32> = v.version
                    .split('.')
                    .filter_map(|s| s.parse::<i32>().ok())
                    .collect();

                let k_version_parts: Vec<i32> = k.version
                    .split('.')
                    .filter_map(|s| s.parse::<i32>().ok())
                    .collect();

                if !v_version_parts.is_empty() && !k_version_parts.is_empty() {
                    let v_major = v_version_parts[0];
                    let k_major = k_version_parts[0];

                    // Only consider vulnerabilities that come before the fix
                    if v_major <= k_major {
                        // Calculate version distance - prioritize closeness
                        let mut distance = (k_major - v_major) * 100;

                        // Add minor version component
                        if v_version_parts.len() > 1 && k_version_parts.len() > 1 {
                            let v_minor = v_version_parts[1];
                            let k_minor = k_version_parts[1];
                            distance += (k_minor - v_minor).abs();
                        }

                        if distance < best_match_score {
                            best_match_score = distance;
                            best_match = Some(v);
                            debug!(
                                "\t\t\tFound better mainline match: {} -> {} (score: {})",
                                v.version, k.version, distance
                            );
                        }
                    }
                }
            }

            if let Some(best_v) = best_match {
                debug!(
                    "\t\tUsing closest mainline vulnerability {} for fix {} (score: {})",
                    best_v.version, k.version, best_match_score
                );

                fixed_pairs.push(KernelPair {
                    vulnerable: best_v.clone(),
                    fixed: k.clone(),
                });
                create = true;
            } else {
                // Fall back to oldest mainline if we couldn't find a better match
                let closest_mainline = mainline_vulns[0];
                debug!(
                    "\t\tFalling back to oldest mainline vulnerability {} for fix {}",
                    closest_mainline.version, k.version
                );

                fixed_pairs.push(KernelPair {
                    vulnerable: closest_mainline.clone(),
                    fixed: k.clone(),
                });
                create = true;
            }
        }

        // Priority 5: Distance-based scoring (only if no other match found)
        if !create {
            // Find the best matching vulnerability for this fix based on version proximity
            let mut best_match: Option<&Kernel> = None;
            let mut best_match_score = std::i32::MAX;

            // We have some vulnerable entries, so let's try to match them up
            for v in &sorted_vulnerabilities {
                // Get the numerical values for proper version comparison
                let v_version_parts: Vec<i32> = v.version
                    .split('.')
                    .filter_map(|s| s.parse::<i32>().ok())
                    .collect();

                let k_version_parts: Vec<i32> = k.version
                    .split('.')
                    .filter_map(|s| s.parse::<i32>().ok())
                    .collect();

                // Only compare if we have valid numbers and the vulnerable version is <= fixed version
                if !v_version_parts.is_empty() && !k_version_parts.is_empty() {
                    let v_major = v_version_parts[0];
                    let k_major = k_version_parts[0];

                    // Only consider vulnerabilities older than or same as fix
                    if v_major <= k_major {
                        // Calculate weighted distance - give more weight to major version match
                        let mut distance = (k_major - v_major) * 100;

                        // Add minor version distance if available
                        if v_version_parts.len() > 1 && k_version_parts.len() > 1 {
                            let v_minor = v_version_parts[1];
                            let k_minor = k_version_parts[1];
                            distance += (k_minor - v_minor).abs();
                        }

                        // Find closest vulnerability by version
                        if distance < best_match_score {
                            best_match_score = distance;
                            best_match = Some(v);
                            debug!(
                                "\t\t\tFound better version match: {} -> {} (score: {})",
                                v.version, k.version, distance
                            );
                        }
                    }
                }
            }

            // If we found a best match by version distance
            if let Some(v) = best_match {
                debug!(
                    "\t\tbest version match for {} is {}, score {}",
                    k.version, v.version, best_match_score
                );
                fixed_pairs.push(KernelPair {
                    vulnerable: v.clone(),
                    fixed: k.clone(),
                });
                create = true;
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

            // Attempt to find a matching fix for this vulnerable version
            let mut best_fix: Option<Kernel> = None;

            // Find a compatible kernel version in the fixed_set
            for fix in &state.fixed_set {
                // Check if this is a mainline fix for a mainline vulnerability
                if v.is_mainline() && fix.is_mainline() {
                    // For mainline vulnerable and fixed, pick the closest future release
                    if fix.compare(v) == std::cmp::Ordering::Greater {
                        if best_fix.is_none() || fix.compare(&best_fix.as_ref().unwrap()) == std::cmp::Ordering::Less {
                            best_fix = Some(fix.clone());
                        }
                    }
                }
            }

            // If we found a fix, create a pair
            if let Some(fix) = best_fix {
                debug!("Found compatible fix for {} in {}", v.version, fix.version);
                fixed_pairs.push(KernelPair {
                    vulnerable: v.clone(),
                    fixed: fix,
                });
            } else {
                // No fix found, mark as unfixed
                fixed_pairs.push(KernelPair {
                    vulnerable: v.clone(),
                    fixed: Kernel::empty_kernel(),
                });
            }
        }
    }

    // We need to filter out invalid pairs
    // For example, if we have a vulnerability in 6.6 and fixes in 6.7 and 6.13,
    // we shouldn't create a pair 6.6:6.13 if the version was fixed in 6.7
    let mut filtered_pairs: Vec<KernelPair> = Vec::new();

    // Track which vulnerable commits have already been paired with a mainline fix
    let mut vulnerable_commit_with_mainline_fix: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    // First, separate the pairs by vulnerable git id
    let mut pairs_by_vuln_id: std::collections::HashMap<String, Vec<KernelPair>> = std::collections::HashMap::new();

    for pair in &fixed_pairs {
        // Skip empty kernel pairs (unfixed)
        if pair.fixed.version == "0" {
            filtered_pairs.push(pair.clone());
            continue;
        }

        let vuln_id = pair.vulnerable.git_id.clone();
        pairs_by_vuln_id.entry(vuln_id).or_insert_with(Vec::new).push(pair.clone());
    }

    // Process each set of pairs for a specific vulnerability
    for (vuln_id, mut vuln_pairs) in pairs_by_vuln_id {
        // Sort the pairs within each vulnerability group
        vuln_pairs.sort_by(|a, b| {
            // First group by fix type: stable vs mainline
            if a.fixed.is_mainline() != b.fixed.is_mainline() {
                // For different types, prefer mainline
                return if a.fixed.is_mainline() {
                    Ordering::Less
                } else {
                    Ordering::Greater
                };
            }

            // If both are mainline, sort by version (ascending - we want closest future version first)
            if a.fixed.is_mainline() {
                return a.fixed.compare(&b.fixed);
            }

            // For stable kernels, compare versions normally (ascending)
            a.fixed.compare(&b.fixed)
        });

        // Debugging output
        debug!("Processing vulnerability ID {} pairs:", vuln_id);
        for pair in &vuln_pairs {
            debug!("  {} -> {}", pair.vulnerable.version, pair.fixed.version);
        }

        // Find the best mainline fix for this vulnerability
        let mut mainline_fix = None;
        for pair in &vuln_pairs {
            if pair.fixed.is_mainline() {
                mainline_fix = Some(pair.clone());
                break;
            }
        }

        // Record and add the mainline fix pair if found
        if let Some(mainline_pair) = mainline_fix {
            debug!("Selected mainline fix for {}:{} -> {}",
                  mainline_pair.vulnerable.version, vuln_id, mainline_pair.fixed.version);
            vulnerable_commit_with_mainline_fix.insert(vuln_id.clone(), mainline_pair.fixed.version.clone());
            filtered_pairs.push(mainline_pair);
        }

        // Add all stable fix pairs for this vulnerability
        for pair in &vuln_pairs {
            if !pair.fixed.is_mainline() {
                debug!("Added stable fix for {}:{} -> {}",
                      pair.vulnerable.version, vuln_id, pair.fixed.version);
                filtered_pairs.push(pair.clone());
            }
        }
    }

    // We are done!
    // Print out the pairs we found so that bippy can do something with them.
    debug!(
        "Number of vulnerable / fixed kernel pairs after filtering: {}",
        filtered_pairs.len()
    );
    debug!("Final output:");

    // Sort the filtered pairs by fixed kernel version to ensure consistent order
    filtered_pairs.sort_by(|a, b| {
        // First compare by fixed kernel version
        if a.fixed.version != "0" && b.fixed.version != "0" {
            return a.fixed.compare(&b.fixed);
        }

        // If one is unfixed (version "0"), it goes last
        if a.fixed.version == "0" {
            return Ordering::Greater;
        }
        if b.fixed.version == "0" {
            return Ordering::Less;
        }

        // Otherwise, sort by vulnerable version
        a.vulnerable.compare(&b.vulnerable)
    });

    for e in &filtered_pairs {
        println!(
            "{}:{}:{}:{}",
            e.vulnerable.version.green(),
            e.vulnerable.git_id.cyan(),
            e.fixed.version.green(),
            e.fixed.git_id.cyan()
        );
    }
}
