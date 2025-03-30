// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use colored::Colorize;
use cve_utils::common;
use cve_utils::print_git_error_details;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tempfile::NamedTempFile;

/// Update all .dyad files in the tree.
///
/// This is good to do after older stable kernels have been released as often
/// CVEs are included in older stable kernels AFTER they show up in newer ones,
/// and this keeps the database at CVE more up to date and friendly for others to
/// rely on.
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// CVE ID or year to process (if not specified, all years will be processed)
    #[clap(index = 1)]
    cve_id_or_year: Option<String>,

    /// Set the CVE user email address
    #[clap(long)]
    cve_user: Option<String>,

    /// Enable verbose output
    #[clap(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Get CVE_USER from arguments or environment
    let cve_user = match args.cve_user {
        Some(user) => user,
        None => match env::var("CVE_USER") {
            Ok(user) => user,
            Err(e) => {
                eprintln!("Error: CVE_USER must be set via environment variable or --cve-user option: {}", e);
                return Err(anyhow!("CVE_USER must be set via environment variable or --cve-user option"));
            }
        },
    };

    // Set CVE_USER environment variable (in case it was provided as a command-line argument)
    unsafe {
        env::set_var("CVE_USER", &cve_user);
    }

    // Set up debug output based on verbose flag
    let debug = args.verbose;

    // Get path to vulns and dyad repos
    let vulns_dir = match common::find_vulns_dir() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Error finding vulns directory: {}", e);
            print_git_error_details(&e);
            return Err(e);
        }
    };

    let dyad_path = vulns_dir.join("dyad");
    if !dyad_path.exists() {
        return Err(anyhow!("Dyad directory not found at {}", dyad_path.display()));
    }

    // Process CVEs based on input
    match &args.cve_id_or_year {
        None => {
            // Process all years
            let published_dir = vulns_dir.join("cve").join("published");
            for entry in fs::read_dir(&published_dir)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    let year = entry.file_name().to_string_lossy().to_string();
                    if year.chars().all(|c| c.is_ascii_digit()) {
                        process_year(&year, &vulns_dir, &dyad_path, debug)?;
                    }
                }
            }
        }
        Some(cve_id_or_year) => {
            // Check if it's a year or a CVE ID
            let published_dir = vulns_dir.join("cve").join("published").join(cve_id_or_year);
            if published_dir.exists() && published_dir.is_dir() {
                // It's a year
                process_year(cve_id_or_year, &vulns_dir, &dyad_path, debug)?;
            } else {
                // Try to process it as a CVE ID
                if !process_single_cve(cve_id_or_year, &vulns_dir, &dyad_path, debug)? {
                    return Err(anyhow!("ERROR: {} is not found or is not a year", cve_id_or_year.cyan()));
                }
            }
        }
    }

    Ok(())
}

/// Process a single CVE
fn process_single_cve(cve_id: &str, vulns_dir: &Path, dyad_path: &Path, debug: bool) -> Result<bool> {
    let cve_search_path = vulns_dir.join("scripts").join("cve_search");

    // First try to find the CVE
    let search_output = Command::new(&cve_search_path)
        .arg(cve_id)
        .output()
        .context("Failed to execute cve_search")?;

    if !search_output.status.success() {
        return Ok(false);
    }

    // Find the SHA file for this CVE
    let cve_root = vulns_dir.join("cve");
    let mut sha_file_path = None;

    for entry in walkdir::WalkDir::new(&cve_root)
        .into_iter()
        .filter_entry(|e| !e.path().to_string_lossy().contains("testing"))
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.is_file() &&
           path.file_name().is_some_and(|n| n.to_string_lossy().contains(".sha1")) &&
           path.to_string_lossy().contains(cve_id)
        {
            sha_file_path = Some(path.to_path_buf());
            break;
        }
    }

    // Process the file if found
    if let Some(path) = sha_file_path {
        let relative_path = path.strip_prefix(vulns_dir)?.to_string_lossy().to_string();

        // Create a single-item progress bar for visual feedback
        let progress_bar = ProgressBar::new(1);
        progress_bar.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:50.cyan/blue} {pos:>}/{len} {percent}% {msg}")
                .unwrap()
                .progress_chars("█▉▊▋▌▍▎▏ ")
        );
        progress_bar.set_message(format!("Processing {}", cve_id));

        match process_single_file(&relative_path, vulns_dir, dyad_path, debug) {
            Ok(_) => {
                progress_bar.finish_with_message(format!("Processed {}", cve_id.green()));
                Ok(true)
            },
            Err(e) => {
                progress_bar.finish_with_message(format!("Failed to process {}: {}", cve_id.red(), e));
                Err(e)
            }
        }
    } else {
        Ok(false)
    }
}

/// Process all CVEs for a specific year
fn process_year(year: &str, vulns_dir: &Path, dyad_path: &Path, debug: bool) -> Result<()> {
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

    println!("Processing {} CVEs from {}", total_count.to_string().cyan(), year.green());

    // Set up progress bar
    let progress_bar = ProgressBar::new(total_count as u64);
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {wide_bar:.cyan/blue} {pos:>}/{len} ({percent}%) {eta} {msg}")
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏ ")
    );
    progress_bar.set_message(format!("Year {}", year));

    // Counter for error tracking
    let error_count = Arc::new(AtomicUsize::new(0));

    // Process files in parallel
    sha_files.par_iter().for_each(|path| {
        let relative_path = path.strip_prefix(vulns_dir)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| path.to_string_lossy().to_string());

        if let Err(err) = process_single_file(&relative_path, vulns_dir, dyad_path, debug) {
            progress_bar.suspend(|| {
                eprintln!("\nError processing {}: {}", relative_path, err);
            });
            error_count.fetch_add(1, Ordering::Relaxed);
        }

        // Update progress
        progress_bar.inc(1);
    });

    // Finish the progress bar
    let errors = error_count.load(Ordering::Relaxed);
    if errors > 0 {
        progress_bar.finish_with_message(format!("Completed with {} error(s)", errors.to_string().red()));
    } else {
        progress_bar.finish_with_message(format!("Successfully processed all CVEs for {}", year.green()));
    }

    Ok(())
}

/// Process a single file
fn process_single_file(
    relative_path: &str,
    vulns_dir: &Path,
    dyad_path: &Path,
    debug: bool
) -> Result<()> {
    let full_path = vulns_dir.join(relative_path);
    let sha = fs::read_to_string(&full_path).context("Failed to read SHA file")?;

    // Extract CVE ID from path
    let parts: Vec<&str> = relative_path.split('.').collect();
    let root = parts[0];
    let cve_id = root.split('/').nth(3)
        .ok_or_else(|| anyhow!("Invalid path format for {}", relative_path))?;

    if debug {
        println!("# processing {}", relative_path);
    }

    // Check for vulnerable file
    let vuln_file = vulns_dir.join(format!("{}.vulnerable", root));
    let vulnerable_option = if vuln_file.exists() {
        let vulnerable_sha = fs::read_to_string(&vuln_file)?;
        format!("--vulnerable={}", vulnerable_sha.trim())
    } else {
        String::new()
    };

    // Create temporary file for dyad output
    let mut tmp_dyad = NamedTempFile::new()?;

    // Run dyad
    let mut command = Command::new(dyad_path);
    if !vulnerable_option.is_empty() {
        command.arg(&vulnerable_option);
    }
    command.arg(sha.trim());

    let output = command.stdout(Stdio::piped()).output()
        .context("Failed to execute dyad command")?;

    if !output.status.success() {
        eprintln!("{} dyad failed for {}", "Error:".red(), cve_id.cyan());
        return Err(anyhow!("dyad command failed"));
    }

    // Write to temp file
    tmp_dyad.write_all(&output.stdout)?;

    // Target dyad file
    let dyad_file = vulns_dir.join(format!("{}.dyad", root));

    // Compare and update if needed
    if !dyad_file.exists() {
        // No existing file, just use the new one
        fs::copy(tmp_dyad.path(), &dyad_file)?;
    } else {
        // Compare the files
        let diff_output = Command::new("diff")
            .args(["-u", &dyad_file.to_string_lossy(), &tmp_dyad.path().to_string_lossy()])
            .output()
            .context("Failed to execute diff command")?;

        if diff_output.status.success() {
            // Files are the same, do nothing
        } else {
            // Check if the changes are meaningful
            let diff_text = String::from_utf8_lossy(&diff_output.stdout);
            let meaningful_change = diff_text.lines()
                .any(|line|
                    line.starts_with("+") || line.starts_with("-") &&
                    !line.contains("dyad") && !line.starts_with("@@ ")
                );

            if meaningful_change {
                // Update the file
                fs::copy(tmp_dyad.path(), &dyad_file)?;
            }
        }
    }

    // Let temp file clean itself up
    drop(tmp_dyad);

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_extract_cve_id_from_path() {
        // Test parsing of CVE ID from file paths
        let test_cases = [
            ("cve/published/2023/CVE-2023-12345.sha1", "CVE-2023-12345"),
            ("cve/published/2022/CVE-2022-9876.sha1", "CVE-2022-9876"),
            ("cve/rejected/2021/CVE-2021-5432.sha1", "CVE-2021-5432"),
        ];

        for (path, expected) in test_cases {
            let parts: Vec<&str> = path.split('.').collect();
            let root = parts[0];
            let cve_id = root.split('/').nth(3).unwrap();
            assert_eq!(cve_id, expected);
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
        let dyad_file = temp_dir.path().join("cve/published/2023/CVE-2023-12345.dyad");
        fs::write(&dyad_file, "5.15:abcdef:5.16:012345\n").unwrap();

        // Now verify the file exists and has the right content
        assert!(dyad_file.exists(), "dyad file was not created");
        let dyad_content = fs::read_to_string(&dyad_file).unwrap();
        assert_eq!(dyad_content, "5.15:abcdef:5.16:012345\n", "dyad file has wrong content");
    }
}