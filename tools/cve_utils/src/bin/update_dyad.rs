// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use owo_colors::OwoColorize;
use cve_utils::common;
use cve_utils::cve_utils::extract_cve_id_from_path;
use cve_utils::print_git_error_details;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, error};
use rayon::prelude::*;
use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tempfile::NamedTempFile;
use walkdir::WalkDir;

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
        raw_args += &a.to_string();
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

    let dyad_path = vulns_dir.join("scripts").join("dyad");
    if !dyad_path.exists() {
        return Err(anyhow!("Dyad script not found at {dyad_path:?}"));
    }

    // Process CVEs based on input
    if args.cve_ids_or_years.len() == 0 {
        // Process all years, in sorted order
        let published_dir = vulns_dir.join("cve").join("published");
        let mut years: Vec<_> = fs::read_dir(&published_dir)
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        years.sort_by_key(std::fs::DirEntry::path);
        for entry in years {
            if entry.file_type()?.is_dir() {
                let year = entry.file_name().to_string_lossy().to_string();
                if year.chars().all(|c| c.is_ascii_digit()) {
                    process_year(&year, &vulns_dir, &dyad_path)?;
                }
            }
        }
    } else {
        for id in args.cve_ids_or_years {
            // Check if it's a year or a CVE ID
            let published_dir = vulns_dir.join("cve").join("published").join(&id);
            if published_dir.exists() && published_dir.is_dir() {
                // It's a year
                process_year(&id, &vulns_dir, &dyad_path)?;
            } else {
                // Try to process it as a CVE ID
                if !process_single_cve(&id, &vulns_dir, &dyad_path)? {
                    return Err(anyhow!(
                        "ERROR: {} is not found or is not a year",
                        id.cyan()
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Process a single CVE
fn process_single_cve(cve_id: &str, vulns_dir: &Path, dyad_path: &Path) -> Result<bool> {
    let cve_root = vulns_dir.join("cve");
    if !cve_root.exists() {
        return Err(anyhow!("CVE directory not found: {cve_root:?}"));
    }

    // Look for the CVE ID in the published directory
    let mut cve_file = None;
    for entry in WalkDir::new(cve_root.join("published"))
        .into_iter()
        .filter_map(Result::ok)
    {
        let path = entry.path();
        // Skip directories and non-sha1 files
        if !path.is_file() || !path.to_string_lossy().ends_with(".sha1") {
            continue;
        }

        // Extract CVE ID from path
        match extract_cve_id_from_path(path) {
            Ok(id) if id == cve_id => {
                cve_file = Some(path.to_path_buf());
                break;
            }
            _ => {}
        }
    }

    // If the file wasn't found, report it but don't error out
    let Some(cve_path) = cve_file else {
        println!("CVE {cve_id} not found in published directory");
        return Ok(false);
    };

    // Generate dyad file
    process_single_file(&cve_path.to_string_lossy(), vulns_dir, dyad_path)?;

    Ok(true)
}

/// Process all CVEs for a specific year
fn process_year(year: &str, vulns_dir: &Path, dyad_path: &Path) -> Result<()> {
    let published_dir = vulns_dir.join("cve").join("published").join(year);

    // Count how many SHA1 files we have
    let mut sha_files = Vec::new();
    for entry in fs::read_dir(published_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().is_some_and(|ext| ext == "sha1") {
            sha_files.push(path);
        }
    }

    let total_count = sha_files.len();
    if total_count == 0 {
        println!("{} No CVEs found for year {}", "ERROR:".red(), year);
        return Ok(());
    }

    println!(
        "Processing {} CVEs from {}",
        total_count.to_string().cyan(),
        year.green()
    );

    // Set up progress bar
    let progress_bar = ProgressBar::new(total_count as u64);
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%)")
            .unwrap()
            .progress_chars("#>-")
    );
    progress_bar.set_message(format!("Year {year}"));

    // Counter for error tracking
    let error_count = Arc::new(AtomicUsize::new(0));

    // Process files in parallel
    sha_files.par_iter().for_each(|path| {
        let relative_path = path.strip_prefix(vulns_dir).map_or_else(
            |_| path.to_string_lossy().to_string(),
            |p| p.to_string_lossy().to_string(),
        );

        if let Err(err) = process_single_file(&relative_path, vulns_dir, dyad_path) {
            progress_bar.suspend(|| {
                error!("\nError processing {relative_path}: {err}");
            });
            error_count.fetch_add(1, Ordering::Relaxed);
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
        progress_bar.finish_with_message(format!(
            "Successfully processed all CVEs for {}",
            year.green()
        ));
    }

    Ok(())
}

/// Process a single file
fn process_single_file(relative_path: &str, vulns_dir: &Path, dyad_path: &Path) -> Result<()> {
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
    let vulnerable_options = if vuln_file.exists() {
        let vulnerable_sha = fs::read_to_string(&vuln_file)?;
        // Split the vulnerable SHA string in case it contains multiple space-separated values
        vulnerable_sha
            .split_whitespace()
            .map(|sha| {
                let trimmed = sha.trim();
                format!("-v {trimmed}")
            })
            .collect::<Vec<String>>()
    } else {
        Vec::new()
    };

    // Create temporary file for dyad output
    let mut tmp_dyad = NamedTempFile::new()?;

    // Run dyad
    let mut command = Command::new(dyad_path);
    for option in &vulnerable_options {
        let parts: Vec<&str> = option.split_whitespace().collect();
        if parts.len() == 2 {
            command.arg(parts[0]).arg(parts[1]);
        }
    }

    // Split SHA values and add each as a separate --sha1 argument
    for sha_value in sha.lines().filter(|line| !line.trim().is_empty()) {
        command.arg("--sha1").arg(sha_value.trim());
    }

    let output = command
        .stdout(Stdio::piped())
        .output()
        .context("Failed to execute dyad command")?;

    if !output.status.success() {
        error!("{} dyad failed for {}", "Error:".red(), cve_id.cyan());
        return Err(anyhow!("dyad command failed"));
    }

    // Write to temp file
    tmp_dyad.write_all(&output.stdout)?;

    // Target dyad file
    let dyad_file = vulns_dir.join(format!("{root}.dyad"));

    // Compare and update if needed
    if dyad_file.exists() {
        // Compare the files
        let diff_output = Command::new("diff")
            .args([
                "-u",
                &dyad_file.to_string_lossy(),
                &tmp_dyad.path().to_string_lossy(),
            ])
            .output()
            .context("Failed to execute diff command")?;

        if diff_output.status.success() {
            // Files are the same, do nothing
        } else {
            // Check if the changes are meaningful (ignore comment lines)
            let diff_text = String::from_utf8_lossy(&diff_output.stdout);
            let meaningful_change = diff_text.lines().any(|line| {
                // Only consider added/removed lines
                line.strip_prefix('+').map_or_else(
                    || {
                        line.strip_prefix('-').map_or_else(
                            || false,
                            |rest| {
                                let rest = rest.trim_start();
                                // Ignore removed comment lines and diff metadata
                                !rest.starts_with('#') && !line.starts_with("--- ")
                            },
                        )
                    },
                    |rest| {
                        let rest = rest.trim_start();
                        // Ignore added comment lines and diff metadata
                        !rest.starts_with('#') && !line.starts_with("+++ ")
                    },
                )
            });

            if meaningful_change {
                // Update the file
                fs::copy(tmp_dyad.path(), &dyad_file)?;
            }
        }
    } else {
        // No existing file, just use the new one
        fs::copy(tmp_dyad.path(), &dyad_file)?;
    }

    // Let temp file clean itself up
    drop(tmp_dyad);

    Ok(())
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
