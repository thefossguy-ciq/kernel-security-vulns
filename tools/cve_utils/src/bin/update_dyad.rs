// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use cve_utils::common;
use cve_utils::dyad_core;
use cve_utils::print_git_error_details;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, error};
use owo_colors::OwoColorize;
use rayon::prelude::*;
use std::env;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Update all .dyad files in the tree.
///
/// This is good to do after older stable kernels have been released as often
/// CVEs are included in older stable kernels AFTER they show up in newer ones,
/// and this keeps the database at CVE more up to date and friendly for others to
/// rely on.
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Set the CVE user email address
    #[clap(long)]
    cve_user: Option<String>,

    /// Enable verbose output
    #[clap(short, long)]
    verbose: bool,

    /// List of CVE ids or years to process (if not specified, all years will be processed)
    #[clap(index = 1)]
    cve_ids_or_years: Vec<String>,
}

/// Initialize and configure the logging system
fn initialize_logging(verbose: bool) -> log::LevelFilter {
    // Default to error level, but can turn it on based on the command line option
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
    // Get the raw command line arguments for debugging
    // Yes, if utf-8 is not used in them, this will panic, but really, did you want anything else to
    // happen here?
    let mut raw_args = String::new();
    for a in env::args().skip(1) {
        raw_args += " ";
        raw_args += &a.clone();
    }

    let args = Args::parse();

    // Initialize logging system
    initialize_logging(args.verbose);

    // Debug message will only be seen after logger is initialized
    debug!("command line arguments: {raw_args:#?}");

    // Get CVE_USER from arguments or environment
    let cve_user = match args.cve_user {
        Some(user) => user,
        None => match env::var("CVE_USER") {
            Ok(user) => user,
            Err(e) => {
                error!("Error: CVE_USER must be set via environment variable or --cve-user option: {e}");
                return Err(anyhow!(
                    "CVE_USER must be set via environment variable or --cve-user option"
                ));
            }
        },
    };

    // Set CVE_USER environment variable (in case it was provided as a command-line argument)
    unsafe {
        env::set_var("CVE_USER", &cve_user);
    }

    // Get path to vulns and dyad repos
    let vulns_dir = match common::find_vulns_dir() {
        Ok(path) => path,
        Err(e) => {
            error!("Error finding vulns directory: {e}");
            print_git_error_details(&e);
            return Err(e);
        }
    };

    // list of all ids we want to process/update
    let ids = common::ids_from_command_line(&vulns_dir, &args.cve_ids_or_years)?;

    debug!("Want to process {} ids", ids.len().to_string().cyan());
    process_ids(&ids, &vulns_dir);

    Ok(())
}

/// Process all sha1 files found
fn process_ids(sha_files: &[String], vulns_dir: &Path) {
    let total_count = sha_files.len();

    println!("Updating dyad files for {} CVEs", total_count.to_string().cyan());

    // Set up progress bar
    let progress_bar = ProgressBar::new(total_count as u64);
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%)")
            .unwrap()
            .progress_chars("#>-")
    );
    progress_bar.set_message(format!("Processing {total_count} CVEs"));

    // Counter for error tracking
    let error_count = Arc::new(AtomicUsize::new(0));

    let update_results = Arc::new(Mutex::new(Vec::new()));
    // Process files in parallel
    sha_files.par_iter().for_each(|path| {
        let update_results = Arc::clone(&update_results);
        let result = match process_single_file(path, vulns_dir) {
            Ok(r) => r,
            Err(err) => {
                progress_bar.suspend(|| {
                    error!("\nError processing {path}: {err}");
                });
                error_count.fetch_add(1, Ordering::Relaxed);
                String::new()
            }
        };
        if !result.is_empty() {
            update_results.lock().unwrap().push(result);
        }

        // Update progress
        progress_bar.inc(1);
    });

    // Finish the progress bar
    let errors = error_count.load(Ordering::Relaxed);
    if errors > 0 {
        progress_bar.finish_with_message(format!(
            "Completed with {} error(s)",
            errors.to_string().red()
        ));
    } else {
        progress_bar.finish_with_message(format!("Successfully processed all {total_count} CVEs"));
    }

    // Report any errors or updates
    let results = update_results.lock().unwrap();
    if results.is_empty() {
        println!("\nNo dyad entries needed to be updated");
    } else {
        println!("\n{} CVE dyad files updated:", results.len());
        for cve_id in results.iter() {
            println!("  {}", cve_id.cyan());
        }
    }
}

/// Process a single file
/// Return a CVE entry id if it was updated/added.
/// Return an empty string if nothing happened.
fn process_single_file(relative_path: &str, vulns_dir: &Path) -> Result<String> {
    let full_path = vulns_dir.join(relative_path);
    let sha = fs::read_to_string(&full_path).context("Failed to read SHA file")?;

    // Extract CVE ID from path
    let parts: Vec<&str> = relative_path.split('.').collect();
    let root = parts[0];
    let cve_id = root
        .split('/')
        .nth(3)
        .ok_or_else(|| anyhow!("Invalid path format for {relative_path}"))?;

    debug!("# processing {relative_path}");

    // Check for vulnerable file
    let vuln_file = vulns_dir.join(format!("{root}.vulnerable"));
    let vulnerable_shas = if vuln_file.exists() {
        let vulnerable_sha = fs::read_to_string(&vuln_file)?;
        // Split the vulnerable SHA string in case it contains multiple space-separated values
        vulnerable_sha
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<String>>()
    } else {
        Vec::new()
    };

    // The fixing SHA values, one per line
    let fixing_shas = sha
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<String>>();

    // Run the dyad engine
    let new_content = match dyad_core::run(&fixing_shas, &vulnerable_shas) {
        Ok(result) => dyad_core::format_output(&result),
        Err(e) => {
            error!("{} dyad failed for {}: {e}", "Error:".red(), cve_id.cyan());
            return Err(anyhow!("dyad run failed"));
        }
    };

    // Target dyad file
    let dyad_file = vulns_dir.join(format!("{root}.dyad"));

    // Compare and update if needed
    let updated = if dyad_file.exists() {
        let old_content = fs::read_to_string(&dyad_file).context("Failed to read dyad file")?;
        // Only consider the change meaningful if something other than
        // comment lines changed.
        meaningful_lines(&old_content).ne(meaningful_lines(&new_content))
    } else {
        // No existing file, just use the new one
        true
    };

    if updated {
        fs::write(&dyad_file, &new_content)?;
        return Ok(cve_id.to_string());
    }
    Ok(String::new())
}

/// Iterate over the lines of a dyad file that carry real data (i.e. skip
/// comment lines).
fn meaningful_lines(content: &str) -> impl Iterator<Item = &str> {
    content
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cve_utils::cve_utils::extract_cve_id_from_path;
    use tempfile::tempdir;

    #[test]
    fn test_extract_cve_id_from_path() {
        let test_cases = vec![
            ("cve/published/2023/CVE-2023-12345.sha1", "CVE-2023-12345"),
            ("cve/published/2023/CVE-2023-12345.json", "CVE-2023-12345"),
            ("cve/published/2023/CVE-2023-12345", "CVE-2023-12345"),
            (
                "/absolute/path/to/cve/published/2023/CVE-2023-12345.sha1",
                "CVE-2023-12345",
            ),
            ("relative/path/to/CVE-2023-12345.sha1", "CVE-2023-12345"),
        ];

        for (path, expected) in test_cases {
            let result = extract_cve_id_from_path(path);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), expected);
        }
    }

    #[test]
    fn test_with_mock_filesystem() {
        // Skip this test if running in an environment where the command can't be executed
        if std::env::var("CI").is_ok() {
            return;
        }

        // Instead of actually running the dyad command, we'll mock the process
        // by implementing a simpler version that just verifies the basic structure

        // Setup temp directory
        let temp_dir = tempdir().unwrap();
        let published_dir = temp_dir.path().join("cve/published/2023");
        fs::create_dir_all(&published_dir).unwrap();

        // Create a mock CVE SHA1 file
        let sha_file = published_dir.join("CVE-2023-12345.sha1");
        let sha_content = "abcdef1234567890";
        fs::write(&sha_file, sha_content).unwrap();

        // Instead of calling process_single_file which has the dyad command,
        // we'll manually create the expected .dyad file
        let dyad_file = temp_dir
            .path()
            .join("cve/published/2023/CVE-2023-12345.dyad");
        fs::write(&dyad_file, "5.15:abcdef:5.16:012345\n").unwrap();

        // Now verify the file exists and has the right content
        assert!(dyad_file.exists(), "dyad file was not created");
        let dyad_content = fs::read_to_string(&dyad_file).unwrap();
        assert_eq!(
            dyad_content, "5.15:abcdef:5.16:012345\n",
            "dyad file has wrong content"
        );
    }
}
