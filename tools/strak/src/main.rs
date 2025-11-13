// SPDX-License-Identifier: GPL-2.0-only
//
// strak - dig in the CVE database and either show what CVEs are fixed for a
// specific release, or what CVEs are still vulnerable for a specific commit
//
// "strak" meeans "fixed/tight" in Dutch
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
// Copyright (c) 2025 - Greg Kroah-Hartman <gregkh@linuxfoundation.org>

use anyhow::{anyhow, Result};
use clap::Parser;
use cve_utils::common;
use cve_utils::dyad::DyadEntry;
use cve_utils::get_kernel_tree;
use cve_utils::Kernel;
use log::debug;
use log::error;
use owo_colors::{OwoColorize, Stream::Stdout};
use std::fs;
use std::path::Path;
use std::time::Instant;

/// Dig in the CVE database for information about commits.
///
/// strak can be used to show what CVEs are fixed for a specific release,
/// or what CVEs are still vulnerable for a specific release/commit.
///
/// "strak" means "fixed/tight" in Dutch.
///
/// Examples:
///
///   strak --fixed 6.12.3
/// will show all CVE ids that are fixed for the 6.12.3 kernel release
///
///   strak v6.12.3
/// will show all CVE ids that are currently vulnerable in the 6.12.3 release
#[derive(Parser, Debug)]
#[clap(author, version, about, verbatim_doc_comment)]
struct Args {
    /// Git SHA to check for unfixed CVEs
    #[clap(index = 1)]
    git_sha: Option<String>,

    /// Kernel version to show what was fixed in it
    #[clap(long)]
    fixed: Option<String>,

    /// Enable verbose output
    #[clap(short, long)]
    verbose: bool,
}

/// A whole "dyad" record, assigned to a specific CVE id
#[derive(Debug, Clone)]
struct DyadRecord {
    /// CVE identifier (e.g., "CVE-2023-12345")
    pub cve_number: String,
    /// Dyad entries containing vulnerability and fix information
    pub dyad_entries: Vec<DyadEntry>,
}

impl DyadRecord {
    /// Create a new `DyadRecord` from a colon-separated string
    pub fn new(s: &str) -> Self {
        Self {
            cve_number: s.to_string(),
            dyad_entries: Vec::new(),
        }
    }
}

/// Read all dyad entries in the specified directory and the ones below it.
///
/// This will recurse, so be careful
fn read_dyad(published_dir: &Path) -> Result<Vec<DyadRecord>> {
    let mut dyad_records: Vec<DyadRecord> = Vec::new();

    // Iterate through all year directories
    let dir_result = match fs::read_dir(published_dir) {
        Ok(result) => result,
        Err(e) => {
            error!("Error reading published directory: {e}");
            return Err(anyhow!("Failed to read published directory: {e}"));
        }
    };

    for entry_result in dir_result {
        let entry = match entry_result {
            Ok(entry) => entry,
            Err(e) => {
                error!("Error reading directory entry: {e}");
                continue;
            }
        };

        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(e) => {
                error!("Error getting file type: {e}");
                continue;
            }
        };

        if file_type.is_dir() {
            let year_str = entry.file_name().to_string_lossy().to_string();
            debug!("{} Searching year {}", "#".cyan(), year_str);
            let subdir = published_dir.join(year_str);
            let mut subdir_records = match read_dyad(&subdir) {
                Ok(d) => d,
                Err(e) => {
                    error!("Error reading all dyad entries: {e}");
                    return Err(anyhow!("failed to read dyad entries: {e}"));
                }
            };
            dyad_records.append(&mut subdir_records);
        } else if file_type.is_file() {
            let file_name = entry.file_name().to_string_lossy().to_string();
            // Only look at files that end in .dyad
            if file_name.ends_with(".dyad") {
                //debug!("{} Reading {}", "#".cyan(), file_name);
                // strip the .dyad for the string
                let mut cve_name = file_name.to_string();
                let mut dot = cve_name.len();

                let dot_pos_check = cve_name.rfind('.');
                if let Some(dot_pos) = dot_pos_check {
                    dot = dot_pos;
                }
                cve_name.truncate(dot);

                // Create a new dyad record for this CVE id
                let mut dyad_record = DyadRecord::new(&cve_name);
                let full_path = published_dir.join(file_name);
                let dyad_content = fs::read_to_string(full_path)?;

                // Parse each dyad entry
                let mut entries: Vec<DyadEntry> = dyad_content
                    .lines()
                    .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
                    .filter_map(|line| match DyadEntry::new_no_validate(line) {
                        Ok(entry) => Some(entry),
                        Err(e) => {
                            error!("Error parsing dyad entry '{line}': {e}");
                            None
                        }
                    })
                    .collect();
                dyad_record.dyad_entries.append(&mut entries);
                dyad_records.push(dyad_record);
            }
        }
    }

    Ok(dyad_records)
}

fn print_fixed_commits(kernel_tree: &Path, dyad_records: &Vec<DyadRecord>, fixed_version: &str) {
    #[derive(Clone)]
    struct Fixes {
        cve_number: String,
        kernel: Kernel,
    }

    let mut fixes: Vec<Fixes> = Vec::new();

    for dyad_record in dyad_records {
        for dyad in &dyad_record.dyad_entries {
            if dyad.fixed.version() == fixed_version {
                let fix = Fixes {
                    kernel: dyad.fixed.clone(),
                    cve_number: dyad_record.cve_number.clone(),
                };
                fixes.push(fix.clone());
            }
        }
    }

    if fixes.is_empty() {
        println!(
            "Kernel version {} did not fix any CVE ids.",
            fixed_version.if_supports_color(Stdout, |x| x.cyan())
        );
        return;
    }

    println!(
        "Kernel version {} contains {} CVE fixes:",
        fixed_version.if_supports_color(Stdout, |x| x.blue()),
        fixes.len().if_supports_color(Stdout, |x| x.cyan())
    );
    for fix in fixes {
        let commit_details =
            match cve_utils::get_commit_details(kernel_tree, &fix.kernel.git_id(), None) {
                Ok(c) => c,
                Err(_e) => fix.kernel.git_id(),
            };
        println!(
            "  {} is fixed with commit {}",
            fix.cve_number.if_supports_color(Stdout, |x| x.green()),
            commit_details.if_supports_color(Stdout, |x| x.cyan())
        );
    }
}

/// Wrapper for is_ancestor() so we can get some debugging output easier.
fn do_is_ancestor(first: &Kernel, second: &Kernel) -> bool {
    // "Fast" hack for doing a `git merge-base --is-ancestor first second`
    //
    // We "know" how our tree works, so we can rely on major versions and the like to do a few
    // simple comparisons instead.

    if first.is_empty() {
        // The root of the tree, EVERYONE is an ancestor of that!
        return true;
    }

    // If both majors are the same, we can do a simple compare
    // Note, this can be slow for when these are both in a major kernel release.
    if first.version_major_match(second) && first < second {
        return true;
    }

    // If this is a "mainline" release, than any kernel version larger than it is part of the graph
    if first.is_mainline() {
        return first < second;
    }

    false
}

/// determine if the first kernel is an ancestor of the second
fn is_ancestor(first: &Kernel, second: &Kernel) -> bool {
    let result = do_is_ancestor(first, second);

    if result {
        debug!(
            "   {:>8} is ancestor of {:>8}: {}",
            first.version(),
            second.version(),
            "true".if_supports_color(Stdout, |x| x.green())
        );
    } else {
        debug!(
            "   {:>8} is ancestor of {:>8}: {}",
            first.version(),
            second.version(),
            "false".if_supports_color(Stdout, |x| x.red())
        );
    }

    result
}

fn print_unfixed_cves(dyad_records: &Vec<DyadRecord>, test_kernel: &Kernel) {
    let mut total_vulnerable = 0usize;

    for dyad_record in dyad_records {
        debug!("Checking {}:", dyad_record.cve_number);
        let mut must_look = false;
        let mut found_fix = false;

        for dyad in &dyad_record.dyad_entries {
            let vuln = &dyad.vulnerable;
            let fixed = &dyad.fixed;

            if is_ancestor(vuln, test_kernel) {
                // The vulnerable kernel is a root of our kernel, so we must determine if this is fixed or not.
                must_look = true;

                // If this is NOT fixed, then of course this is vulnerable
                if fixed.is_empty() {
                    continue;
                }

                // Check if the fixed git is a root of our test id
                if is_ancestor(fixed, test_kernel) {
                    found_fix = true;
                }
            }
        }

        debug!("    must_look={} found_fix={}", must_look, found_fix);
        if must_look && !found_fix {
            println!(
                "{} is vulnerable to {}",
                test_kernel
                    .version()
                    .if_supports_color(Stdout, |x| x.green()),
                dyad_record
                    .cve_number
                    .if_supports_color(Stdout, |x| x.red())
            );
            total_vulnerable += 1;
        }
    }

    println!(
        "\nTotal Vulnerable CVE's in {} : {}",
        test_kernel
            .version()
            .if_supports_color(Stdout, |x| x.green()),
        total_vulnerable
            .to_string()
            .if_supports_color(Stdout, |x| x.red())
    );
}

/// Initialize and configure the logging system
fn initialize_logging(verbose: bool) -> log::LevelFilter {
    let logging_level = if verbose {
        log::LevelFilter::max()
    } else {
        log::LevelFilter::Error
    };

    env_logger::builder()
        .format_timestamp(None)
        .filter_level(logging_level)
        .init();

    logging_level
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging system
    initialize_logging(args.verbose);

    // Make sure we can find our common directories
    let kernel_tree = get_kernel_tree()?;
    let vulns_dir = common::find_vulns_dir()?;

    let published_dir = vulns_dir.join("cve").join("published");

    let before_read_dyad = Instant::now();
    let dyads = match read_dyad(&published_dir) {
        Ok(d) => d,
        Err(e) => {
            error!("Error reading all dyad entries: {e}");
            return Err(anyhow!("failed to read dyad entries: {e}"));
        }
    };
    debug!(
        "Found {} cve ids in {:?}",
        dyads.len(),
        before_read_dyad.elapsed()
    );

    // Is this a "fixed" request?
    if let Some(fixed_version) = &args.fixed {
        // Show CVEs fixed in a specific version
        print_fixed_commits(&kernel_tree, &dyads, fixed_version);
        return Ok(());
    }

    if let Some(git_sha) = &args.git_sha {
        // We need to be explicit in our git_sha request.
        // If this is a tag, turn it into a commit, if it is a commit, force it to be a commit.
        // See `man git reference` for details about this format.
        let git_sha_commit = format!("{}^{{commit}}", git_sha);
        let git_full_sha = cve_utils::get_full_sha(&kernel_tree, &git_sha_commit)?;

        // Turn the git sha into a valid kernel object
        let test_kernel = match Kernel::from_id(&git_full_sha) {
            Ok(k) => k,
            Err(e) => {
                error!("Error creating a kernel for {git_sha}: {e}");
                return Err(anyhow!("Invalid git sha specified: {e}"));
            }
        };

        // Find all unfixed CVEs for a specific version
        print_unfixed_cves(&dyads, &test_kernel);
        return Ok(());
    }

    // No parameters provided, show help
    error!("Error: You must provide either a Git SHA or --fixed option.");
    error!("Run with --help for usage information.");
    std::process::exit(1);
}
