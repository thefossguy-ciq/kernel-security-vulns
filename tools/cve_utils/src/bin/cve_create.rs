// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use owo_colors::OwoColorize;
use cve_utils::common::{find_cve_by_sha, get_cve_root, get_kernel_tree};
use cve_utils::cve_utils::find_next_free_cve_id;
use cve_utils::git_utils::get_full_sha;
use cve_utils::git_utils::{get_commit_details, get_commit_year};
use cve_utils::print_git_error_details;
use log::error;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Create a CVE entry based on a Git commit SHA
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Git SHA to create a CVE for
    #[clap(index = 1)]
    git_sha: Option<String>,

    /// Optional CVE ID to use (if not provided, next available reserved ID will be used)
    #[clap(index = 2)]
    cve_id: Option<String>,

    /// Process multiple Git SHAs from a file (one SHA per line)
    #[clap(long, short)]
    batch: Option<PathBuf>,
}

fn main() {
    let logging_level: log::LevelFilter = log::LevelFilter::Error;
    let args = Args::parse();

    env_logger::builder()
        .format_timestamp(None)
        .filter_level(logging_level)
        .init();

    // Validate we have either a git_sha or a batch file
    if args.git_sha.is_none() && args.batch.is_none() {
        error!("Either a Git SHA or --batch file must be provided");
        std::process::exit(1);
    }

    // Process a batch file if provided
    if let Some(batch_file) = args.batch {
        if let Err(e) = process_batch_file(&batch_file) {
            error!("Error processing batch file: {e}");
            print_git_error_details(&e);
            std::process::exit(1);
        }
        return;
    }

    // Process a single Git SHA
    if let Some(git_sha) = args.git_sha
        && let Err(e) = create_cve(&git_sha, args.cve_id.as_deref()) {
            error!("Error creating CVE: {e}");
            print_git_error_details(&e);
            std::process::exit(1);
        }
}

/// Process a batch file containing Git SHAs
///
/// Reads a file line by line, extracting Git SHAs and creating a CVE for each.
/// Lines starting with '-' or empty lines are skipped. For each valid line,
/// extracts the first word that looks like a Git SHA (at least 7 hex characters).
fn process_batch_file(batch_file: &Path) -> Result<()> {
    // Check if file exists
    if !batch_file.exists() {
        return Err(anyhow!(
            "Batch file does not exist: {}",
            batch_file.display()
        ));
    }

    let file = fs::File::open(batch_file).context(format!(
        "Failed to open batch file: {}",
        batch_file.display()
    ))?;

    let reader = BufReader::new(file);
    let mut shas = Vec::new();

    // Parse the file to extract Git SHAs
    for line in reader.lines() {
        let line = line.context("Failed to read line from batch file")?;
        let trimmed = line.trim();

        // Skip annotations or empty lines
        if trimmed.starts_with('-') || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Extract the first word that looks like a Git SHA (at least 7 hex characters)
        if let Some(sha) = line
            .split_whitespace()
            .find(|word| word.len() >= 7 && word.chars().all(|c| c.is_ascii_hexdigit()))
        {
            shas.push(sha.to_string());
        }
    }

    if shas.is_empty() {
        return Err(anyhow!("No valid Git SHAs found in batch file"));
    }

    println!(
        "Found {} Git SHAs to process",
        shas.len().to_string().cyan()
    );

    // Process each SHA
    for sha in shas {
        println!("Processing SHA: {}", sha.cyan());

        // Handle errors but continue processing the batch
        if let Err(e) = create_cve(&sha, None) {
            eprintln!(
                "{} Failed to create CVE for SHA {}: {}",
                "WARNING:".yellow(),
                sha.cyan(),
                e
            );
        }
    }

    Ok(())
}

/// Create a CVE entry for a given Git SHA
///
/// This function:
/// 1. Validates the Git SHA exists in the kernel tree
/// 2. Checks if a CVE already exists for this SHA
/// 3. Gets or finds a CVE ID
/// 4. Moves the CVE ID from reserved to published
/// 5. Creates the SHA1 file
/// 6. Generates JSON and mbox files using bippy
fn create_cve(git_sha: &str, requested_id: Option<&str>) -> Result<()> {
    // Get the kernel tree and CVE root paths
    let kernel_tree = get_kernel_tree()?;
    let cve_root = get_cve_root()?;

    // Get the full SHA and validate it exists in the kernel tree
    let git_sha_full = get_full_sha(&kernel_tree, git_sha).context(format!(
        "Git SHA {} not found in kernel tree",
        git_sha.cyan()
    ))?;

    // Get the commit details for display
    let git_commit = get_commit_details(&kernel_tree, &git_sha_full, None)?;

    // Get the commit year
    let year = get_commit_year(&kernel_tree, &git_sha_full)?;

    // Check if a CVE already exists for this SHA
    if let Some(existing_cve) = find_existing_cve(&git_sha_full)? {
        return Err(anyhow!(
            "The Git SHA {} is already assigned to {}",
            git_sha_full.cyan(),
            existing_cve.green()
        ));
    }

    // Set up directories
    let reserved_dir = cve_root.join("reserved").join(&year);
    let published_dir = cve_root.join("published").join(&year);

    // Check if reserved directory exists
    if !reserved_dir.exists() {
        return Err(anyhow!(
            "Directory {} not found, should you allocate more for that year?",
            reserved_dir.display().to_string().cyan()
        ));
    }

    // Get or find a CVE ID
    let cve_id = match requested_id {
        Some(id) => id.to_string(),
        None => find_next_free_cve_id(&reserved_dir)?,
    };

    // Create the published directory if needed
    fs::create_dir_all(&published_dir).context(format!(
        "Failed to create published directory: {}",
        published_dir.display()
    ))?;

    // Move the CVE ID from reserved to published
    let reserved_file = reserved_dir.join(&cve_id);
    let published_file = published_dir.join(&cve_id);

    fs::rename(&reserved_file, &published_file).context(format!(
        "Failed to move CVE ID from reserved to published: {cve_id}"
    ))?;

    // Create the SHA1 file
    let sha1_file = published_dir.join(format!("{cve_id}.sha1"));
    fs::write(&sha1_file, &git_sha_full).context(format!(
        "Failed to create SHA1 file: {}",
        sha1_file.display()
    ))?;

    // Check for .vulnerable file and collect SHAs
    let vulnerable_file = published_dir.join(format!("{cve_id}.vulnerable"));
    let mut vulnerable_shas = Vec::new();
    if vulnerable_file.exists() {
        let contents = fs::read_to_string(&vulnerable_file)?;
        for line in contents.lines() {
            let sha = line.trim();
            if !sha.is_empty() {
                vulnerable_shas.push(sha.to_string());
            }
        }
    }

    // Generate JSON and mbox files using bippy
    let json_file = published_dir.join(format!("{cve_id}.json"));
    let mbox_file = published_dir.join(format!("{cve_id}.mbox"));

    // Build bippy command with full path from vulns dir
    let vulns_dir = match cve_utils::common::find_vulns_dir() {
        Ok(dir) => dir,
        Err(e) => return Err(anyhow!("Failed to find vulns directory: {}", e)),
    };
    let bippy_path = vulns_dir.join("scripts").join("bippy");
    let bippy_path_str = bippy_path.to_string_lossy().to_string();

    // Build bippy command
    let mut bippy_cmd = Command::new(&bippy_path);
    bippy_cmd
        //.arg("--verbose")
        .arg(format!("--cve={cve_id}"))
        .arg(format!("--sha={git_sha_full}"))
        .arg(format!("--json={}", json_file.display()))
        .arg(format!("--mbox={}", mbox_file.display()));

    // Add vulnerable SHAs if any
    for sha in &vulnerable_shas {
        bippy_cmd.arg(format!("--vulnerable={sha}"));
    }

    //    println!("Running bippy command:");
    //    println!(
    //        "  {} --verbose --cve={} --sha={} --json={} --mbox={}",
    //        bippy_path.display(),
    //        cve_id,
    //        git_sha_full,
    //        json_file.display(),
    //        mbox_file.display()
    //    );

    let result = bippy_cmd
        .status()
        .context(format!("Failed to execute bippy: {bippy_path_str}"))?;

    // Handle bippy failure
    if !result.success() {
        // Revert changes
        fs::rename(&published_file, &reserved_file).context(format!(
            "Failed to revert CVE ID move after bippy failure: {cve_id}"
        ))?;

        fs::remove_file(sha1_file).context("Failed to remove SHA1 file after bippy failure")?;

        return Err(anyhow!(
            "bippy execution failed for {} (exit code: {})",
            cve_id.cyan(),
            result
                .code()
                .map_or_else(|| "unknown".to_string(), |c| c.to_string())
        ));
    }

    // Success
    println!(
        "{} is now allocated for commit {}",
        cve_id.cyan(),
        git_commit.green()
    );

    Ok(())
}

/// Find if a CVE already exists for a given Git SHA
///
/// Uses the common `find_cve_by_sha` function to check if a CVE exists for the given SHA.
fn find_existing_cve(git_sha: &str) -> Result<Option<String>> {
    let cve_root = get_cve_root()?;
    Ok(find_cve_by_sha(&cve_root, git_sha))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_next_free_cve_id() {
        // Create a temporary directory
        let temp_dir = tempfile::tempdir().unwrap();
        let reserved_dir = temp_dir.path();

        // Create some dummy CVE IDs
        fs::write(reserved_dir.join("CVE-2023-10001"), "").unwrap();
        fs::write(reserved_dir.join("CVE-2023-10002"), "").unwrap();
        fs::write(reserved_dir.join("CVE-2023-10003"), "").unwrap();

        // Test finding the next free ID
        let next_id = find_next_free_cve_id(reserved_dir).unwrap();
        // The library implementation finds the first empty file it finds, which could be any of them
        // depending on directory iteration order
        assert!(next_id.starts_with("CVE-2023-100"));
    }

    #[test]
    fn test_get_commit_year_from_date() {
        // Test parsing a date in the format YYYY-MM-DD
        let date = "2023-01-15";
        let year = date.split('-').next().unwrap_or("");
        assert_eq!(year, "2023");
    }

    #[test]
    fn test_process_batch_file() {
        // Create a temporary batch file
        let temp_dir = tempfile::tempdir().unwrap();
        let batch_file = temp_dir.path().join("batch.txt");

        let content = "
        # Valid SHAs
        abcdef123456 First commit
        1234567890ab Second commit

        # Invalid lines
        - This is an annotation
        Not a SHA
        ";

        fs::write(&batch_file, content).unwrap();

        // Mock the SHA processing function to check what's extracted
        let file = fs::File::open(&batch_file).unwrap();
        let reader = BufReader::new(file);
        let mut shas = Vec::new();

        for line in reader.lines().map_while(Result::ok) {
            let trimmed = line.trim();
            if trimmed.starts_with('-') || trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if let Some(sha) = line
                .split_whitespace()
                .find(|word| word.len() >= 7 && word.chars().all(|c| c.is_ascii_hexdigit()))
            {
                shas.push(sha.to_string());
            }
        }

        // Check extracted SHAs
        assert_eq!(shas.len(), 2);
        assert_eq!(shas[0], "abcdef123456");
        assert_eq!(shas[1], "1234567890ab");
    }

    #[test]
    fn test_batch_file_with_various_formats() {
        // Create a temporary batch file with different SHA formats
        let temp_dir = tempfile::tempdir().unwrap();
        let batch_file = temp_dir.path().join("complex_batch.txt");

        let content = "
        # Valid SHAs with different formats
        123456789abc - First commit with annotation
          def1234567 - Indented SHA with annotation

        # SHA with leading spaces and trailing comment
        aaaaaaa  This is a simple description

        # SHA within other text
        The commit bbbbbbbbbbb fixes the issue

        # Too short, should be ignored
        abc123

        # Annotation line, should be skipped
        - cccccccccc not a valid entry

        # Line with multiple SHAs, should only pick the first one
        ddddddd eeeeeee fffffff
        ";

        fs::write(&batch_file, content).unwrap();

        // Parse the file to extract Git SHAs
        let file = fs::File::open(&batch_file).unwrap();
        let reader = BufReader::new(file);
        let mut shas = Vec::new();

        for line in reader.lines().map_while(Result::ok) {
            let trimmed = line.trim();
            // Skip annotations or empty lines
            if trimmed.starts_with('-') || trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Extract the first word that looks like a Git SHA (at least 7 hex characters)
            if let Some(sha) = line
                .split_whitespace()
                .find(|word| word.len() >= 7 && word.chars().all(|c| c.is_ascii_hexdigit()))
            {
                shas.push(sha.to_string());
            }
        }

        // Check extracted SHAs
        assert_eq!(shas.len(), 5);
        assert_eq!(shas[0], "123456789abc");
        assert_eq!(shas[1], "def1234567");
        assert_eq!(shas[2], "aaaaaaa");
        assert_eq!(shas[3], "bbbbbbbbbbb");
        assert_eq!(shas[4], "ddddddd");
    }

    #[test]
    fn test_cve_directory_operations() {
        // Set up a mock CVE environment
        let temp_dir = tempfile::tempdir().unwrap();
        let cve_root = temp_dir.path();

        // Create the year structure
        let year = "2023";
        let reserved_dir = cve_root.join("reserved").join(year);
        let published_dir = cve_root.join("published").join(year);

        fs::create_dir_all(&reserved_dir).unwrap();
        fs::create_dir_all(&published_dir).unwrap();

        // Create a reserved CVE ID
        let cve_id = "CVE-2023-12345";
        fs::write(reserved_dir.join(cve_id), "").unwrap();

        // Test the find_next_free_cve_id function
        let next_id = find_next_free_cve_id(&reserved_dir).unwrap();
        assert_eq!(next_id, cve_id);

        // Mock the move operation from reserved to published
        let reserved_file = reserved_dir.join(cve_id);
        let published_file = published_dir.join(cve_id);

        assert!(reserved_file.exists());
        assert!(!published_file.exists());

        fs::rename(&reserved_file, &published_file).unwrap();

        assert!(!reserved_file.exists());
        assert!(published_file.exists());

        // Create a SHA1 file
        let sha1_file = published_dir.join(format!("{cve_id}.sha1"));
        let git_sha = "abcdef1234567890abcdef1234567890abcdef12";
        fs::write(&sha1_file, git_sha).unwrap();

        assert!(sha1_file.exists());

        // Test finding an existing CVE (manual implementation)
        let mut found_cve = None;
        for file in fs::read_dir(&published_dir).unwrap() {
            let file = file.unwrap().path();
            if file.is_file() && file.to_string_lossy().ends_with(".sha1") {
                let content = fs::read_to_string(&file).unwrap();
                if content.trim() == git_sha
                    && let Some(file_name) = file.file_stem() {
                        found_cve = Some(file_name.to_string_lossy().into_owned());
                        break;
                    }
            }
        }

        assert_eq!(found_cve, Some(cve_id.to_string()));

        // Clean up
        fs::remove_file(&sha1_file).unwrap();
        fs::remove_file(&published_file).unwrap();
    }
}
