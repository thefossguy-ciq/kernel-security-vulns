// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use ::cve_utils::common;
use ::cve_utils::git_utils;
use ::cve_utils::cve_utils;
use ::cve_utils::print_git_error_details;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Publication mode for CVE entries
#[derive(Debug, Clone, Copy)]
enum PublishMode {
    /// Publish JSON files to the CVE database
    Json,
    /// Send mbox announcement emails
    Mbox,
    /// Publish both JSON files and send mbox emails
    All,
    /// No publication mode specified
    None,
}

/// Publish CVE entries to the CVE database and/or send announcement emails
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Publication mode for CVE entries
    #[clap(subcommand)]
    mode: Option<ModeCommand>,

    /// Dry run - show what would be published/sent but don't actually do it
    #[clap(long)]
    dry_run: bool,
}

#[derive(Parser, Debug)]
enum ModeCommand {
    /// Publish JSON files to the CVE database
    #[clap(name = "json")]
    Json,

    /// Send mbox announcement emails
    #[clap(name = "mbox")]
    Mbox,

    /// Publish both JSON files and send mbox emails
    #[clap(name = "all")]
    All,
}

impl Args {
    /// Determine the publish mode based on command-line arguments
    fn get_publish_mode(&self) -> PublishMode {
        match &self.mode {
            Some(ModeCommand::All) => PublishMode::All,
            Some(ModeCommand::Json) => PublishMode::Json,
            Some(ModeCommand::Mbox) => PublishMode::Mbox,
            None => PublishMode::None,
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let publish_mode = args.get_publish_mode();

    if let PublishMode::None = publish_mode {
        println!("{} No action specified. Use --json, --mbox, or --all", "WARNING:".yellow());
        println!("Run with --help for more information.");
        return Ok(());
    }

    // Get CVE root path
    let _cve_root = match common::get_cve_root() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Error getting CVE root path: {e}");
            print_git_error_details(&e);
            return Err(e);
        }
    };

    // Process according to the publish mode
    match publish_mode {
        PublishMode::Json | PublishMode::All => {
            println!("{}:", "Publishing JSON files to CVE database".green());
            if args.dry_run {
                println!("  {} Dry run mode - no actual publishing", "INFO:".blue());
            }
            publish_json_files(args.dry_run)?;
        },
        _ => {}
    }

    match publish_mode {
        PublishMode::Mbox | PublishMode::All => {
            println!("{}:", "Sending mbox announcement emails".green());
            if args.dry_run {
                println!("  {} Dry run mode - no actual emails sent", "INFO:".blue());
            }
            publish_mbox_files(args.dry_run)?;
        },
        _ => {}
    }

    Ok(())
}

/// Finds and publishes modified JSON files to the CVE database
///
/// Uses git status to identify modified JSON files and publishes each one
/// using the `cve` command. If `dry_run` is true, only shows what would be done.
fn publish_json_files(dry_run: bool) -> Result<()> {
    // Get a list of all modified JSON files using git status
    let modified_files = git_utils::get_modified_files(&["*.json"])?;

    if modified_files.is_empty() {
        println!("  No modified JSON files found");
        return Ok(());
    }

    println!("  Found {} modified JSON files to publish", modified_files.len().to_string().cyan());

    // Process each file
    for file_path in &modified_files {
        // Extract CVE ID from the file path
        let cve_id = cve_utils::extract_cve_id_from_path(file_path)?;

        // Get the associated SHA1 file
        let sha1_file = file_path.with_extension("sha1");
        let sha = fs::read_to_string(&sha1_file)
            .context(format!("Failed to read SHA1 file: {}", sha1_file.display()))?
            .trim()
            .to_string();

        println!("  Publishing {} for commit {}", cve_id.cyan(), sha.green());

        if !dry_run {
            // Call the CVE tool to publish the JSON file
            let output = Command::new("cve")
                .args(["-o", "Linux", "publish", &cve_id, "-f", &file_path.to_string_lossy()])
                .output()
                .context("Failed to execute 'cve' command")?;

            if output.status.success() {
                println!("    {} CVE published successfully at: https://cve.org/CVERecord/?id={}",
                         "SUCCESS:".green(), cve_id);
            } else {
                let error = String::from_utf8_lossy(&output.stderr);
                println!("    {} Failed to publish {}: {}",
                         "ERROR:".red(), cve_id.cyan(), error);
            }
        }
    }

    Ok(())
}

/// Finds and sends modified mbox files as announcement emails
///
/// Uses git status to identify modified mbox files, filters out rejected ones,
/// and sends emails using git send-email. If `dry_run` is true, only shows what would be done.
fn publish_mbox_files(dry_run: bool) -> Result<()> {
    // Get a list of all modified mbox files using git status
    let modified_files = git_utils::get_modified_files(&["*.mbox"])?;

    if modified_files.is_empty() {
        println!("  No modified mbox files found");
        return Ok(());
    }

    // Filter out rejected mbox files (those ending with .mbox.rejected)
    let mbox_files: Vec<PathBuf> = modified_files.into_iter()
        .filter(|f| {
            let file_name = f.file_name().unwrap().to_string_lossy();
            !file_name.ends_with(".rejected")
        })
        .collect();

    if mbox_files.is_empty() {
        println!("  No valid mbox files to send (filtered out rejected ones)");
        return Ok(());
    }

    println!("  Found {} mbox files to send", mbox_files.len().to_string().cyan());

    // Print list of files that will be sent
    for file_path in &mbox_files {
        // Extract CVE ID from the file path
        let cve_id = cve_utils::extract_cve_id_from_path(file_path)?;

        // Get the associated SHA1 file
        let sha1_file = file_path.with_extension("sha1");
        let sha = fs::read_to_string(&sha1_file)
            .context(format!("Failed to read SHA1 file: {}", sha1_file.display()))?
            .trim()
            .to_string();

        println!("  Sending email for {} for commit {}", cve_id.cyan(), sha.green());
    }

    // Send emails if not in dry run mode
    if !mbox_files.is_empty() && !dry_run {
        // Build file list for git send-email
        let file_list: Vec<String> = mbox_files.iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();

        // Execute git send-email
        let mut cmd = Command::new("git");
        cmd.args(["send-email", "--no-thread", "--to=linux-cve-announce@vger.kernel.org"]);

        for file in &file_list {
            cmd.arg(file);
        }

        let output = cmd.output()
            .context("Failed to execute git send-email command")?;

        if output.status.success() {
            println!("  {} Emails successfully sent", "SUCCESS:".green());
        } else {
            let error = String::from_utf8_lossy(&output.stderr);
            println!("  {} Failed to send emails: {}", "ERROR:".red(), error);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_match_pattern() {
        // These should match
        assert!(git_utils::match_pattern("foo.json", "*.json"));
        assert!(git_utils::match_pattern("path/to/foo.json", "*.json"));
        assert!(git_utils::match_pattern("exact", "exact"));

        // These should not match
        assert!(!git_utils::match_pattern("foo.txt", "*.json"));
        assert!(!git_utils::match_pattern("json.txt", "*.json"));
        assert!(!git_utils::match_pattern("notexact", "exact"));
    }

    #[test]
    fn test_extract_cve_id_from_path() {
        // Test with various file formats
        let cve_id = "CVE-2023-12345";

        // Create a temp directory
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Test with a JSON file
        let json_path = temp_path.join(format!("{}.json", cve_id));
        fs::write(&json_path, "test content").unwrap();
        assert_eq!(cve_utils::extract_cve_id_from_path(&json_path).unwrap(), cve_id);

        // Test with a mbox file
        let mbox_path = temp_path.join(format!("{}.mbox", cve_id));
        fs::write(&mbox_path, "test content").unwrap();
        assert_eq!(cve_utils::extract_cve_id_from_path(&mbox_path).unwrap(), cve_id);

        // Test with a rejected mbox file
        let rejected_path = temp_path.join(format!("{}.mbox.rejected", cve_id));
        fs::write(&rejected_path, "test content").unwrap();
        assert_eq!(cve_utils::extract_cve_id_from_path(&rejected_path).unwrap(), cve_id);
    }

    #[test]
    fn test_get_modified_files_mock() {
        // Create a temporary directory
        let temp_dir = TempDir::new().unwrap();
        let json_file = temp_dir.path().join("CVE-2023-12345.json");
        let mbox_file = temp_dir.path().join("CVE-2023-12345.mbox");

        // Create the test files
        fs::write(&json_file, "test content").unwrap();
        fs::write(&mbox_file, "test content").unwrap();

        // Note: We can't really test get_modified_files here as it requires a git repository
        // This is a placeholder test
    }

    #[test]
    fn test_dry_run() {
        // Test that dry run mode doesn't execute commands
        // This is a placeholder test for dry run functionality
        assert!(true);
    }
}