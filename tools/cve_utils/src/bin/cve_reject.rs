// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use colored::Colorize;
use cve_utils::common;
use cve_utils::cve_validation;
use cve_utils::git_config;
use cve_utils::print_git_error_details;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Reject a reserved or published CVE entry
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// CVE entry to reject
    #[clap(index = 1)]
    cve_entry: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.cve_entry.is_empty() {
        return Err(anyhow!("No CVE entry provided"));
    }

    // Get the kernel tree and CVE root paths
    let _kernel_tree = match common::get_kernel_tree() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Error: {}", e);
            print_git_error_details(&e);
            return Err(e);
        }
    };
    let cve_root = match common::get_cve_root() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Error: {}", e);
            print_git_error_details(&e);
            return Err(e);
        }
    };

    // Make sure the CVE entry is valid
    let is_valid = match cve_validation::is_valid_cve(&cve_root, &args.cve_entry) {
        Ok(valid) => valid,
        Err(e) => {
            eprintln!("Error verifying CVE: {}", e);
            print_git_error_details(&e);
            return Err(e);
        }
    };

    if !is_valid {
        return Err(anyhow!("No CVE entry found for {}, are you sure it is correct?", args.cve_entry.cyan()));
    }

    // Extract year from CVE
    let year = match cve_validation::year_from_cve(&args.cve_entry) {
        Ok(year) => year,
        Err(e) => {
            eprintln!("Error extracting year from CVE: {}", e);
            print_git_error_details(&e);
            return Err(e);
        }
    };

    // Set up directory paths
    let published_dir = cve_root.join("published").join(&year);
    let reserved_dir = cve_root.join("reserved").join(&year);
    let rejected_dir = cve_root.join("rejected").join(&year);

    // Get user info from git config
    let user_email = match git_config::get_git_config("user.email") {
        Ok(email) => email,
        Err(e) => {
            eprintln!("Error getting git user email: {}", e);
            print_git_error_details(&e);
            return Err(e);
        }
    };
    let user_name = match git_config::get_git_config("user.name") {
        Ok(name) => name,
        Err(e) => {
            eprintln!("Error getting git user name: {}", e);
            print_git_error_details(&e);
            return Err(e);
        }
    };

    // First check if the CVE is in the published directory
    let published_files = find_cve_files(&published_dir, &args.cve_entry)?;

    if !published_files.is_empty() {
        reject_published_cve(
            &args.cve_entry,
            &published_files,
            &rejected_dir,
            &user_name,
            &user_email
        )?;
    } else {
        // Check if the CVE is in the reserved directory
        let reserved_files = find_cve_files(&reserved_dir, &args.cve_entry)?;

        if !reserved_files.is_empty() {
            reject_reserved_cve(&args.cve_entry, &reserved_files, &rejected_dir)?;
        } else {
            // Not found in published or reserved area
            return Err(anyhow!("CVE entry {} not found in published or reserved directories",
                               args.cve_entry.cyan()));
        }
    }

    // Print instructions for rejecting the CVE with cve.org
    println!("To reject the CVE with cve.org, please run:");
    println!("\t{}", format!("cve -o Linux reject {} -j '{{\"rejectedReasons\": [{{\"lang\": \"en\", \"value\": \"This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.\"}}]}}'", args.cve_entry).green());

    Ok(())
}

/// Rejects a published CVE by moving files to rejected directory and creating a rejection email
fn reject_published_cve(
    cve_entry: &str,
    published_files: &[PathBuf],
    rejected_dir: &Path,
    user_name: &str,
    user_email: &str
) -> Result<()> {
    // Verify we have at least 4 files (CVE, json, mbox, sha1)
    if published_files.len() < 4 {
        return Err(anyhow!(
            "Found only {} files for {}, expected at least 4 (CVE, json, mbox, sha1).\nFiles are:\n{}",
            published_files.len().to_string().cyan(),
            cve_entry.cyan(),
            published_files.iter().map(|f| format!("  {}", f.to_string_lossy().cyan())).collect::<Vec<_>>().join("\n")
        ));
    }

    // Make sure the rejected directory exists
    fs::create_dir_all(rejected_dir).context("Failed to create rejected directory")?;

    // Move all files to the rejected directory
    for file in published_files {
        let file_name = file.file_name().unwrap();
        let target = rejected_dir.join(file_name);
        fs::rename(file, &target).context(format!("Failed to move file {} to rejected directory", file.display()))?;
    }

    // Create the rejection email message
    let rejected_mbox_path = rejected_dir.join(format!("{}.mbox.rejected", cve_entry));

    // Get necessary info from the original mbox file
    let original_mbox_path = rejected_dir.join(format!("{}.mbox", cve_entry));
    let original_mbox_content = fs::read_to_string(&original_mbox_path)
        .context(format!("Failed to read original mbox file at {}", original_mbox_path.display()))?;

    let message_id = extract_header(&original_mbox_content, "Message-Id")
        .context("Failed to extract Message-Id from original mbox")?;
    let subject = extract_header(&original_mbox_content, "Subject")
        .context("Failed to extract Subject from original mbox")?;

    // Get script information
    let script_path = std::env::current_exe()
        .context("Failed to get current executable path")?
        .file_name()
        .context("Failed to get executable file name")?
        .to_string_lossy()
        .to_string();

    // Create and write the rejection email
    let rejection_content = format!(
        "From {}-version Mon Sep 17 00:00:00 2001
From: {} <{}>
To: <linux-cve-announce@vger.kernel.org>
Reply-to: <cve@kernel.org>, <linux-kernel@vger.kernel.org>
Subject: REJECTED:{}
In-Reply-To: {}


{} has now been rejected and is no longer a valid CVE.
",
        script_path, user_name, user_email, subject, message_id, cve_entry
    );

    fs::write(&rejected_mbox_path, rejection_content)
        .context(format!("Failed to write rejection email to {}", rejected_mbox_path.display()))?;

    println!("Rejected message is at {}", rejected_mbox_path.display().to_string().cyan());
    println!("To send it, please run:");
    println!("\t{}", format!("git send-email {}", rejected_mbox_path.display()).green());

    Ok(())
}

/// Rejects a reserved CVE by moving files to rejected directory
fn reject_reserved_cve(
    cve_entry: &str,
    reserved_files: &[PathBuf],
    rejected_dir: &Path
) -> Result<()> {
    println!("Found CVE {} in the reserved directory", cve_entry.cyan());

    // Make sure the rejected directory exists
    fs::create_dir_all(rejected_dir).context("Failed to create rejected directory")?;

    // Move all files to the rejected directory
    for file in reserved_files {
        let file_name = file.file_name().unwrap();
        let target = rejected_dir.join(file_name);
        fs::rename(file, &target).context(format!("Failed to move file {} to rejected directory", file.display()))?;
    }

    println!("Moved {} files from reserved to rejected directory", reserved_files.len().to_string().cyan());
    println!("Since this CVE was still reserved, no rejection email is needed.");

    Ok(())
}

/// Find all files related to a CVE entry in a directory
fn find_cve_files(dir: &Path, cve_entry: &str) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    if dir.exists() {
        for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() && path.file_name().unwrap().to_string_lossy().contains(cve_entry) {
                files.push(path.to_path_buf());
            }
        }
    }

    Ok(files)
}

/// Extract a header value from mbox content
fn extract_header<'a>(content: &'a str, header: &str) -> Result<&'a str> {
    for line in content.lines() {
        if line.starts_with(&format!("{}: ", header)) {
            return Ok(line.split_once(": ").map(|(_, v)| v).unwrap_or(""));
        }
    }

    Err(anyhow!("Header '{}' not found in content", header))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_year_from_cve() {
        assert_eq!(cve_validation::year_from_cve("CVE-2023-12345").unwrap(), "2023");
        assert_eq!(cve_validation::year_from_cve("CVE-2024-67890").unwrap(), "2024");
        assert!(cve_validation::year_from_cve("INVALID").is_err());
    }

    #[test]
    fn test_extract_header() {
        let content = "From: User <user@example.com>\nMessage-Id: <12345>\nSubject: Test CVE";
        assert_eq!(extract_header(content, "Message-Id").unwrap(), "<12345>");
        assert_eq!(extract_header(content, "Subject").unwrap(), "Test CVE");
        assert!(extract_header(content, "Non-Existent").is_err());
    }

    #[test]
    fn test_find_cve_files() {
        // Create a temporary directory and files for testing
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        // Create some test files
        let cve_id = "CVE-2023-TEST";
        fs::write(temp_path.join(cve_id.to_string()), "").unwrap();
        fs::write(temp_path.join(format!("{}.json", cve_id)), "").unwrap();
        fs::write(temp_path.join(format!("{}.mbox", cve_id)), "").unwrap();
        fs::write(temp_path.join(format!("{}.sha1", cve_id)), "").unwrap();
        fs::write(temp_path.join("unrelated.txt"), "").unwrap();

        // Test finding the files
        let files = find_cve_files(temp_path, cve_id).unwrap();
        assert_eq!(files.len(), 4, "Should find exactly 4 files");

        // Test with non-existent CVE
        let files = find_cve_files(temp_path, "NON-EXISTENT").unwrap();
        assert_eq!(files.len(), 0, "Should find 0 files for non-existent CVE");
    }

    #[test]
    fn test_is_valid_cve() {
        // Create a temporary directory structure for testing
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        // Create a CVE file
        let cve_id = "CVE-2023-TEST";
        fs::create_dir_all(temp_path.join("published/2023")).unwrap();
        fs::write(temp_path.join("published/2023").join(cve_id), "").unwrap();

        // Valid CVE should return true
        assert!(cve_validation::is_valid_cve(temp_path, cve_id).unwrap(), "Valid CVE should return true");

        // Invalid CVE should return false
        assert!(!cve_validation::is_valid_cve(temp_path, "NON-EXISTENT").unwrap(), "Invalid CVE should return false");
    }

    #[test]
    fn test_rejection_process() {
        // Set up a mock CVE directory structure
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        // Create the CVE entry
        let cve_id = "CVE-2023-REJECT";
        let year = "2023";
        let published_dir = temp_path.join("published").join(year);
        let rejected_dir = temp_path.join("rejected").join(year);

        fs::create_dir_all(&published_dir).unwrap();
        fs::create_dir_all(&rejected_dir).unwrap();

        // Create the CVE files
        fs::write(published_dir.join(cve_id), "").unwrap();
        fs::write(published_dir.join(format!("{}.json", cve_id)), "{}").unwrap();

        // Create a fake mbox file with the necessary headers
        let mbox_content = "From: Test User <test@example.com>
To: <linux-cve-announce@vger.kernel.org>
Subject: CVE-2023-REJECT: Test vulnerability
Message-Id: <test-message-id@example.com>

This is a test CVE entry.
";
        fs::write(published_dir.join(format!("{}.mbox", cve_id)), mbox_content).unwrap();
        fs::write(published_dir.join(format!("{}.sha1", cve_id)), "0123456789abcdef").unwrap();

        // Perform the rejection manually
        // 1. Move the files
        let published_files = find_cve_files(&published_dir, cve_id).unwrap();
        assert_eq!(published_files.len(), 4, "Should have 4 published files");

        for file in &published_files {
            let file_name = file.file_name().unwrap();
            let target = rejected_dir.join(file_name);
            fs::rename(file, &target).unwrap();
        }

        // 2. Create the rejection email
        let rejected_mbox_path = rejected_dir.join(format!("{}.mbox.rejected", cve_id));
        let message_id = extract_header(mbox_content, "Message-Id").unwrap();
        let subject = extract_header(mbox_content, "Subject").unwrap();

        let rejection_content = format!(
            "From test-script-version Mon Sep 17 00:00:00 2001
From: Test User <test@example.com>
To: <linux-cve-announce@vger.kernel.org>
Reply-to: <cve@kernel.org>, <linux-kernel@vger.kernel.org>
Subject: REJECTED:{}
In-Reply-To: {}


{} has now been rejected and is no longer a valid CVE.
",
            subject, message_id, cve_id
        );

        fs::write(&rejected_mbox_path, rejection_content).unwrap();

        // Verify the results
        // 1. Published directory should be empty
        let published_files_after = find_cve_files(&published_dir, cve_id).unwrap();
        assert_eq!(published_files_after.len(), 0, "Published directory should be empty");

        // 2. Rejected directory should have 5 files (4 original + the rejection email)
        let rejected_files = find_cve_files(&rejected_dir, cve_id).unwrap();
        assert_eq!(rejected_files.len(), 5, "Should have 5 files in rejected directory");

        // 3. Check if rejection email was created with the correct format
        let rejected_mbox_content = fs::read_to_string(&rejected_mbox_path).unwrap();
        assert!(rejected_mbox_content.contains("REJECTED:"), "Email should have REJECTED: in subject");
        assert!(rejected_mbox_content.contains(message_id), "Email should have original Message-Id");
        assert!(rejected_mbox_content.contains(format!("{} has now been rejected", cve_id).as_str()),
                "Email should state that the CVE is rejected");
    }

    #[test]
    fn test_full_rejection_workflow() {
        // Create a complete mock CVE environment
        let temp_dir = tempfile::tempdir().unwrap();
        let cve_root = temp_dir.path();
        let cve_id = "CVE-2023-WORKFLOW";
        let year = "2023";

        // Set up directory structure
        let published_dir = cve_root.join("published").join(year);
        let rejected_dir = cve_root.join("rejected").join(year);
        fs::create_dir_all(&published_dir).unwrap();

        // Create the CVE files
        fs::write(published_dir.join(cve_id), "").unwrap();
        fs::write(published_dir.join(format!("{}.json", cve_id)), "{}").unwrap();

        // Create a fake mbox file with the necessary headers
        let mbox_content = "From: Test User <test@example.com>
To: <linux-cve-announce@vger.kernel.org>
Subject: CVE-2023-WORKFLOW: Test vulnerability
Message-Id: <workflow-message-id@example.com>

This is a test CVE entry for workflow testing.
";
        fs::write(published_dir.join(format!("{}.mbox", cve_id)), mbox_content).unwrap();
        fs::write(published_dir.join(format!("{}.sha1", cve_id)), "0123456789abcdef").unwrap();

        // Execute the rejection logic directly

        // 1. Validate the CVE entry
        let is_valid = cve_validation::is_valid_cve(cve_root, cve_id).unwrap();
        assert!(is_valid, "CVE should be valid");

        // 2. Extract year
        let extracted_year = cve_validation::year_from_cve(cve_id).unwrap();
        assert_eq!(extracted_year, year, "Year should be extracted correctly");

        // 3. Find the files
        let files = find_cve_files(&published_dir, cve_id).unwrap();
        assert_eq!(files.len(), 4, "Should find exactly 4 files");

        // 4. Create rejected directory
        fs::create_dir_all(&rejected_dir).unwrap();

        // 5. Move the files
        for file in &files {
            let file_name = file.file_name().unwrap();
            let target = rejected_dir.join(file_name);
            fs::rename(file, &target).unwrap();
        }

        // 6. Create rejection email
        let rejected_mbox_path = rejected_dir.join(format!("{}.mbox.rejected", cve_id));

        // Get necessary info from the original mbox file
        let original_mbox_path = rejected_dir.join(format!("{}.mbox", cve_id));
        let original_mbox_content = fs::read_to_string(&original_mbox_path).unwrap();

        let message_id = extract_header(&original_mbox_content, "Message-Id").unwrap();
        let subject = extract_header(&original_mbox_content, "Subject").unwrap();

        // Create the rejection email
        let rejection_content = format!(
            "From test-workflow-version Mon Sep 17 00:00:00 2001
From: Test User <test@example.com>
To: <linux-cve-announce@vger.kernel.org>
Reply-to: <cve@kernel.org>, <linux-kernel@vger.kernel.org>
Subject: REJECTED:{}
In-Reply-To: {}


{} has now been rejected and is no longer a valid CVE.
",
            subject, message_id, cve_id
        );

        fs::write(&rejected_mbox_path, rejection_content).unwrap();

        // Verify the results
        // 1. All files should be moved
        let published_files_after = find_cve_files(&published_dir, cve_id).unwrap();
        assert_eq!(published_files_after.len(), 0, "Published directory should be empty");

        // 2. Rejected directory should have the files
        let rejected_files = find_cve_files(&rejected_dir, cve_id).unwrap();
        assert_eq!(rejected_files.len(), 5, "Should have 5 files in rejected directory (4 original + rejection)");

        // 3. Check rejection email content
        let rejected_mbox_content = fs::read_to_string(&rejected_mbox_path).unwrap();
        assert!(rejected_mbox_content.contains("REJECTED:"), "Email should have REJECTED: in subject");
        assert!(rejected_mbox_content.contains(message_id), "Email should include original Message-Id");
        assert!(rejected_mbox_content.contains(cve_id), "Email should mention the CVE ID");
    }

    #[test]
    fn test_reserved_cve_rejection() {
        // Create a mock CVE environment with a reserved CVE
        let temp_dir = tempfile::tempdir().unwrap();
        let cve_root = temp_dir.path();
        let cve_id = "CVE-2023-RESERVED";
        let year = "2023";

        // Set up directory structure
        let reserved_dir = cve_root.join("reserved").join(year);
        let rejected_dir = cve_root.join("rejected").join(year);
        fs::create_dir_all(&reserved_dir).unwrap();

        // Create the reserved CVE file
        fs::write(reserved_dir.join(cve_id), "").unwrap();

        // 1. Validate the CVE entry
        let is_valid = cve_validation::is_valid_cve(cve_root, cve_id).unwrap();
        assert!(is_valid, "CVE should be valid");

        // 2. Extract year
        let extracted_year = cve_validation::year_from_cve(cve_id).unwrap();
        assert_eq!(extracted_year, year, "Year should be extracted correctly");

        // 3. Create rejected directory if it doesn't exist
        fs::create_dir_all(&rejected_dir).unwrap();

        // 4. Move the reserved file to rejected
        let reserved_file = reserved_dir.join(cve_id);
        let rejected_file = rejected_dir.join(cve_id);
        fs::rename(&reserved_file, &rejected_file).unwrap();

        // 5. Verify the results
        assert!(!reserved_file.exists(), "Reserved file should not exist anymore");
        assert!(rejected_file.exists(), "Rejected file should exist");
    }
}