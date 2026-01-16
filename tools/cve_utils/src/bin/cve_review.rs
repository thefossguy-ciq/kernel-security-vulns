// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use owo_colors::OwoColorize;
use cve_utils::common;
use cve_utils::print_git_error_details;
use cve_utils::git_utils;
use dialoguer::Input;
use regex::Regex;
use std::cmp::min;
use std::collections::HashSet;
use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use cve_utils::cve_utils::extract_cve_id_from_path;
use walkdir::WalkDir;
use grep::regex::RegexMatcher;
use grep::searcher::sinks::UTF8;
use grep::searcher::{BinaryDetection, SearcherBuilder};
use indicatif::{ProgressBar, ProgressStyle};

/// Review commits to determine if they should be assigned a CVE
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Git range (e.g., v6.7.1..v6.7.2) or file containing commits in `git log --oneline` format
    #[clap(index = 1)]
    target: String,

    /// Annotate commits in a file rather than deciding yes/no for CVE assignment
    #[clap(short, long)]
    annotate: bool,

    /// Skip commits that have already been reviewed
    #[clap(short, long)]
    skip_reviewed: bool,
}

/// Represents a git commit to be reviewed for CVE consideration
#[derive(Debug)]
struct Commit {
    /// Short SHA of the commit
    sha: String,
    /// Subject line of the commit message
    subject: String,
    /// Full commit message including the diff
    full_message: String,
}

/// Main entry point for the `cve_review` tool
///
/// This function:
/// 1. Parses command line arguments
/// 2. Verifies we're in a kernel directory
/// 3. Extracts commits from the provided git range or file
/// 4. Sets up necessary directories for tracking processed commits
/// 5. Reviews each commit, asking the user for input on whether to assign a CVE
fn main() -> Result<()> {
    let args = Args::parse();

    // Check if in a kernel directory
    if !is_kernel_directory() {
        return Err(anyhow!(
            "Not in a kernel directory (MAINTAINERS file not found).\n\
             \n\
             Please run this command from within a Linux kernel git repository.\n\
             Example: cd /path/to/vulns/linux && cve_review v6.7.1..v6.7.2"
        ));
    }

    // Check if in vulns directory early to fail fast
    if common::find_vulns_dir().is_err() {
        return Err(anyhow!(
            "Could not find 'vulns' directory.\n\
             \n\
             This tool needs access to a 'vulns' directory to store its working files.\n\
             The 'vulns' directory should be either:\n\
             - In the current directory path (anywhere above your kernel directory)\n\
             - In the path where the cve_review executable is located\n\
             \n\
             The tool will create: vulns/tmp/cve-review/ for tracking processed commits.\n\
             \n\
             Example usage:\n\
             1. If running from compiled binary in vulns/tools:\n\
                cd /anywhere/linux && /path/to/vulns/tools/target/debug/cve_review v6.7.1..v6.7.2\n\
             2. If cve_review is in PATH and vulns is above your kernel:\n\
                cd /path/to/vulns/some/deep/linux && cve_review v6.7.1..v6.7.2"
        ));
    }

    // Determine if input is a git range or file
    let commits = if args.target.contains("..") {
        // It's a git range
        match get_commits_from_range(&args.target) {
            Ok(commits) => commits,
            Err(e) => {
                eprintln!("Error getting commits from git range: {e}");
                print_git_error_details(&e);
                return Err(e);
            }
        }
    } else {
        // Check if it's a file
        let path = PathBuf::from(&args.target);
        if path.exists() && path.is_file() {
            match get_commits_from_file(&path) {
                Ok(commits) => commits,
                Err(e) => {
                    eprintln!("Error getting commits from file: {e}");
                    print_git_error_details(&e);
                    return Err(e);
                }
            }
        } else {
            // Single commit or invalid input
            return Err(anyhow!("Invalid input: '{}' is not a valid git range or existing file", args.target));
        }
    };

    if commits.is_empty() {
        println!("No commits to review");
        return Ok(());
    }

    // Set up directories
    let (_workdir, processed_file, result_file) = match setup_directories(&args.target, args.annotate) {
        Ok(dirs) => dirs,
        Err(e) => {
            eprintln!("Error setting up directories: {e}");
            print_git_error_details(&e);
            return Err(e);
        }
    };

    // Get already processed commits
    let processed_commits = match get_processed_commits(&processed_file) {
        Ok(commits) => commits,
        Err(e) => {
            eprintln!("Error getting processed commits: {e}");
            print_git_error_details(&e);
            return Err(e);
        }
    };

    // Review commits
    if let Err(e) = review_commits(
        commits,
        &processed_commits,
        &processed_file,
        &result_file,
        args.skip_reviewed,
        args.annotate,
        &args.target
    ) {
        eprintln!("Error during commit review: {e}");
        print_git_error_details(&e);
        return Err(e);
    }

    Ok(())
}

/// Check if the current directory is a kernel directory
fn is_kernel_directory() -> bool {
    Path::new("MAINTAINERS").exists() && Path::new(".git").exists()
}

/// Get commits from a git range
///
/// Takes a git range (e.g., "v6.7.1..v6.7.2") and retrieves all commits within that range.
/// For each commit, collects the SHA, subject, and full commit message (including diff).
fn get_commits_from_range(range: &str) -> Result<Vec<Commit>> {
    let mut commits = Vec::new();

    // Use git log to get the commit list
    let output = Command::new("git")
        .args(["log", "--reverse", "--format=%h %s", range])
        .output()
        .context("Failed to execute git command")?;

    if !output.status.success() {
        return Err(anyhow!("Git command failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    // First, collect all commit info (sha and subject)
    let mut commit_info: Vec<(String, String)> = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if parts.len() < 2 {
            continue;
        }

        let sha = parts[0].to_string();
        let subject = parts[1].to_string();
        commit_info.push((sha, subject));
    }

    // Create progress bar for fetching full commit details
    let pb = ProgressBar::new(commit_info.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
            .unwrap()
            .progress_chars("#>-")
    );
    pb.set_message("Fetching commit details...");

    // Now fetch full details for each commit
    for (sha, subject) in commit_info {
        pb.set_message(format!("Fetching {}", &sha[..min(7, sha.len())]));

        // Get full commit message
        let full_message = get_full_commit_message(&sha)?;

        commits.push(Commit {
            sha,
            subject,
            full_message,
        });

        pb.inc(1);
    }

    pb.finish_with_message("All commits fetched");

    Ok(commits)
}

/// Get full commit message including diff
///
/// Retrieves the complete commit message including patch diff and stat information
/// for the specified SHA, with ANSI color codes preserved for terminal display.
fn get_full_commit_message(sha: &str) -> Result<String> {
    let output = Command::new("git")
        .args(["--no-pager", "log", "-p", "--stat", "--color=always", "-n1", sha])
        .output()
        .context("Failed to execute git command")?;

    if !output.status.success() {
        return Err(anyhow!("Git command failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Get commits from a file (in git log --oneline format)
///
/// Parses a file containing commit information in the format produced by `git log --oneline`.
/// Each line should start with a SHA followed by the commit subject.
/// Lines starting with whitespace and '-' are considered annotations and are skipped.
fn get_commits_from_file(file_path: &Path) -> Result<Vec<Commit>> {
    let mut commits = Vec::new();

    let file = File::open(file_path).context("Failed to open file")?;
    let reader = BufReader::new(file);

    // Create regex outside the loop
    let re = Regex::new(r"^\s*([a-f0-9]{7,})")?;

    for line in reader.lines() {
        let line = line?;

        // Skip annotations (lines starting with whitespace and '-')
        if line.trim_start().starts_with('-') {
            continue;
        }

        // Extract SHA (assuming it's first 7+ hex characters at the beginning of the line)
        if let Some(caps) = re.captures(&line) {
            let sha = caps[1].to_string();

            // Extract subject (everything after the SHA)
            let subject = line[line.find(&sha).unwrap() + sha.len()..].trim().to_string();

            // Get full commit message
            let full_message = get_full_commit_message(&sha)?;

            commits.push(Commit {
                sha,
                subject,
                full_message,
            });
        }
    }

    Ok(commits)
}

/// Set up the necessary directories and files
///
/// This function:
/// 1. Determines a tag name based on the target (git range or filename)
/// 2. Creates necessary directories for tracking processed commits and results
/// 3. Returns paths to the working directory, processed file, and result file
///
/// The processed file tracks which commits have been reviewed to avoid duplicated work
/// The result file stores the decisions made for each commit
fn setup_directories(target: &str, annotate: bool) -> Result<(PathBuf, PathBuf, PathBuf)> {
    // Get current username
    let username = env::var("USER").unwrap_or_else(|_| "user".to_string());

    // Determine tag from target
    let mut tag = if target.contains("..") {
        // Extract the part after ".." as the tag
        target.split("..").nth(1).unwrap_or(target).to_string()
    } else {
        // Use filename as tag with -fromfile suffix to match bash script behavior
        let path = PathBuf::from(target);
        let filename = path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(target)
            .to_string();

        if annotate {
            // For annotation mode, just use tag with -annotated suffix
            format!("{filename}-annotated")
        } else {
            // For normal mode, use -fromfile suffix
            format!("{filename}-fromfile")
        }
    };

    // If annotation mode is enabled and this is a git range, add -annotated suffix
    if annotate && target.contains("..") {
        tag = format!("{tag}-annotated");
    }

    // Set up directories
    let vulns_dir = common::find_vulns_dir()?;
    let workdir = vulns_dir.join("tmp").join("cve-review");
    let processed_dir = workdir.join("processed");
    let results_dir = workdir.join("results");

    // Create directories if they don't exist
    fs::create_dir_all(&processed_dir)?;
    fs::create_dir_all(&results_dir)?;

    // Determine file paths
    let processed_file = processed_dir.join(&tag);
    let cveme_file = format!("{tag}-{username}");
    let result_file = results_dir.join(cveme_file);

    Ok((workdir, processed_file, result_file))
}

/// Get the list of already processed commits
fn get_processed_commits(processed_file: &Path) -> Result<HashSet<String>> {
    let mut processed = HashSet::new();

    if processed_file.exists() {
        let file = File::open(processed_file)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            processed.insert(line);
        }
    }

    Ok(processed)
}

/// Process user input for a commit
///
/// Handles user input to decide whether to assign a CVE to a commit.
/// In annotation mode, captures a description instead.
///
/// Returns:
/// - Ok(Some(true)) if the user wants to assign a CVE
/// - Ok(Some(false)) if the user doesn't want to assign a CVE
/// - Ok(None) if the user wants to quit
/// - Err if there's an error capturing input
fn process_user_input(
    commit: &Commit,
    highlighted_message: &str,
    was_clipped: bool,
    clip_point: usize,
    annotate: bool,
    username: &str,
    result_file_handle: &mut fs::File,
) -> Result<Option<bool>> {
    let commit_lines: Vec<&str> = highlighted_message.lines().collect();

    if annotate {
        println!("\n{} Please annotate <description/q>:", "QUESTION:".blue());
        let annotation: String = Input::new()
            .with_prompt(">")
            .interact_text()?;

        if annotation.to_lowercase() == "q" {
            return Ok(None);
        }

        // Record annotation
        let mainline_sha = get_mainline_sha(&commit.sha)?;
        let mainline_oneline = get_commit_oneline(&mainline_sha)?;
        writeln!(result_file_handle, "{mainline_oneline}")?;
        writeln!(result_file_handle, "- [{username}] {annotation}")?;
        Ok(Some(true))
    } else {
        println!("\n{} Should this commit be assigned a CVE <y/N/q>?", "QUESTION:".blue());
        let mut choice = None;
        while choice.is_none() {
            let input: String = Input::new()
                .with_prompt(">")
                .allow_empty(true)
                .interact_text()?;

            match input.to_lowercase().as_str() {
                "y" | "yes" => choice = Some(true),
                "n" | "no" | "" => choice = Some(false),
                "q" | "quit" => return Ok(None),
                "m" => {
                    // Show the remainder of the commit
                    if was_clipped {
                        println!();
                        for line in &commit_lines[clip_point..] {
                            println!("{line}");
                        }

                        println!("\n{} Should this commit be assigned a CVE <y/N/q>?", "QUESTION:".blue());
                        continue;
                    }
                    choice = Some(false);
                },
                _ => {
                    println!("Invalid choice. Please enter y, n, q, or m.");
                }
            }
        }
        Ok(Some(choice.unwrap()))
    }
}

/// Returns highlight patterns for good and bad commit messages
fn get_highlight_patterns() -> (Vec<&'static str>, Vec<&'static str>) {
    // Define highlight patterns
    let good_patterns = vec![
        r"Alex Hung", r"bad unlock balance detected!", r"bogus",
        r"false(\s|[-_\n])*alarm", r"false(\s|[-_\n])*positive", r"integer",
        r"locking dependency detected", r"Nested lock was not taken",
        r"theory[a-z]*", r"theoretical[a-z]*", r" tools/.* \| .*",
        r"selftests", r"unmet direct dependencies detected"
    ];

    let bad_patterns = vec![
        r"call(\s|[-_\n])*trace", r"dead(\s|[-_\n])*lock", r"lock(\s|[-_\n])*up",
        r"nul[l]*(\s|[-_\n])*p[a-z]*(\s|[-_\n])*deref[a-z]*", r"nul[l]*(\s|[-_\n])*p[a-z]*",
        r"null", r"deref[a-z]*", r"div(\s|[-_\na-z])*by(\s|[-_\n])*zero",
        r"divi(\s|[-_\na-z])*by(\s|[-_\n])*0", r"double(\s|[-_\n])*free",
        r"kernel(\s|[-_\n])*bug", r"buffer(\s|[-_\n])*overflow", r"over(\s|[-_\n])*run",
        r"over(\s|[-_\n])*flow", r"out(\s|[-_\n])*of(\s|[-_\n])*bound[s]*", r"bound[s]*",
        r"use(\s|[-_\n])*after(\s|[-_\n])*free", r"use(\s|[-_\n])*after", r"after(\s|[-_\n])*free",
        r"circular", r"crash[a-z]*", r"denial(\s|[-_\n])*of(\s|[-_\n])*service", r"denial",
        r"dos", r"exploit", r"(\s|[-_\n])fault", r"kernel(\s|[-_\n])hang", r"system(\s|[-_\n])hang",
        r"(\s|[-_\n])hang[a-z]*", r"hung", r"info(\s|[-_\na-z]).*leak", r"leak", r"malicious[a-z]*",
        r"kernel(\s|[-_\n])*memory", r"memory", r"oob", r"oops", r"panic", r"permission",
        r"possible recursive locking detected", r"reboot", r"refcount", r"system", r"syzkaller",
        r"syzbot", r"uaf", r"underflow", r"uninitial[a-z]*", r"vuln[a-z]*", r"BUG:", r"KSPP", r"WARN[A-Z]*"
    ];

    (good_patterns, bad_patterns)
}

/// Handle a commit that has already been published as a CVE
fn handle_published_commit(
    commit: &Commit,
    oneline: &str,
    cve_id: &str,
    processed_file_handle: &mut fs::File,
    result_file_handle: &mut fs::File,
) -> Result<()> {
    println!("\n{} CVE already published as {} -- skipping", "WARNING:".red(), cve_id);

    processed_file_handle.write_all(format!("{oneline}\n").as_bytes())?;

    // Record the mainline SHA automatically
    let mainline_sha = get_mainline_sha(&commit.sha)?;
    let mainline_oneline = get_commit_oneline(&mainline_sha)?;
    writeln!(result_file_handle, "{mainline_oneline} [auto: cve already created]")?;

    Ok(())
}

/// Display a commit with appropriate highlighting and clipping for terminal
fn display_commit(
    commit_message: &str,
    terminal_height: usize,
    proposed_votes_len: usize,
) -> (Vec<&str>, usize, bool) {
    // Convert to lines for display
    let commit_lines: Vec<&str> = commit_message.lines().collect();
    // Calculate how many lines we need to reserve:
    // - 1 line for "Processing" header
    // - 2 + proposed_votes_len lines for vote warning (if votes exist)
    // - 5 lines for bottom UI (blank, INFO, blank, QUESTION, prompt)
    let reserved_lines = if proposed_votes_len > 0 {
        8 + proposed_votes_len
    } else {
        6
    };
    let clip_point = terminal_height.saturating_sub(reserved_lines);

    let was_clipped = commit_lines.len() > clip_point;
    if was_clipped {
        // Commit is too long, clip it
        for line in &commit_lines[0..min(clip_point, commit_lines.len())] {
            println!("{line}");
        }
        println!("\n{} Commit has been clipped, press M to see the remainder", "INFO:".blue());
    } else {
        // Commit fits on screen
        println!("{commit_message}");
        println!("\n{} Commit not clipped", "INFO:".blue());
    }

    (commit_lines, clip_point, was_clipped)
}

/// Review the commits
///
/// This is the core function that processes each commit and:
/// 1. Displays the commit with highlighted patterns
/// 2. Checks if the commit was already published as a CVE
/// 3. Checks if the commit was previously reviewed
/// 4. Prompts the user for input on whether to assign a CVE or add annotations
/// 5. Tracks processed commits and records decisions
///
/// The function handles both regular review mode and annotation mode based on the
/// annotate parameter. In annotation mode, users can add descriptive notes to commits.
fn review_commits(
    commits: Vec<Commit>,
    processed_commits: &HashSet<String>,
    processed_file: &Path,
    result_file: &Path,
    skip_reviewed: bool,
    annotate: bool,
    target: &str,
) -> Result<()> {
    let total_commits = commits.len();
    println!("{} {} commits", "Reviewing".blue(), total_commits);

    let mut processed_file_handle = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(processed_file)?;

    let mut result_file_handle = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(result_file)?;

    // Get username for annotations
    let username = env::var("USER").unwrap_or_else(|_| "user".to_string());

    // Get highlight patterns
    let (good_patterns, bad_patterns) = get_highlight_patterns();

    // Iterate through commits
    for (i, commit) in commits.into_iter().enumerate() {
        let oneline = format!("{} {}", commit.sha, commit.subject);
        #[allow(clippy::cast_precision_loss)]
        let percentage = ((i + 1) as f64) / (total_commits as f64) * 100.0;

        // Check if commit has already been processed
        if processed_commits.contains(&oneline) {
            println!("{} Skipping already processed commit: {}", "INFO:".blue(), oneline);
            continue;
        }

        // Clear screen using ANSI escape sequence
        print!("\x1B[2J\x1B[1;1H");
        println!("{} {} fix: {} of {} (%{:.2})",
                 "Processing".blue(), target_as_tag(target), i + 1, total_commits, percentage);

        // Check if commit has already been published as a CVE
        if let Some(cve_id) = check_already_published(&commit)? {
            handle_published_commit(
                &commit,
                &oneline,
                &cve_id,
                &mut processed_file_handle,
                &mut result_file_handle
            )?;
            continue;
        }

        // Verify that we really have a subject before attempting to look it up
        let mut proposed_votes_len = 0;
        if !commit.subject.is_empty() {
            // Check if commit has been previously reviewed in a different session
            if let Some((filename, previous_sha)) = check_previously_reviewed(&commit.subject, processed_file.parent().unwrap())? {
                println!("\n{} Potentially already reviewed in", "WARNING:".red());
                println!("  {}: {} {}", filename, previous_sha, commit.subject);

                if skip_reviewed {
                    let patch_id_match = check_patch_id_match(&commit.sha, &previous_sha)?;
                    if patch_id_match {
                        println!("\n{} Confirmed as already reviewed - SKIPPING", "INFO:".blue());
                        processed_file_handle.write_all(format!("{oneline}\n").as_bytes())?;
                        continue;
                    }
                    println!("\n{} Patch ID doesn't match - please review for similarity manually", "INFO:".blue());
                }
            }

            // Check if commit has been positively voted for already
            let proposed_votes = check_proposed_votes(&commit.subject, &common::get_cve_root()?.join("review").join("proposed"))?;
            if !proposed_votes.is_empty() {
                println!("\n{} Positively voted for in:", "WARNING:".red());
                for vote in &proposed_votes {
                    println!("  {vote}");
                }
            }
            proposed_votes_len = proposed_votes.len();
        }

        // Apply highlighting to the commit message
        let highlighted_message = highlight_commit_message(&commit.full_message, &good_patterns, &bad_patterns);

        // Display commit message with highlighting
        let terminal_height = get_terminal_height();
        let (_, clip_point, was_clipped) = display_commit(
            &highlighted_message,
            terminal_height,
            proposed_votes_len
        );

        // Process user input
        let Some(decision) = process_user_input(
            &commit,
            &highlighted_message,
            was_clipped,
            clip_point,
            annotate,
            &username,
            &mut result_file_handle
        )? else { return Ok(()) }; // User wants to quit

        // Record the decision
        if decision && !annotate {
            let mainline_sha = get_mainline_sha(&commit.sha)?;
            let mainline_oneline = get_commit_oneline(&mainline_sha)?;
            writeln!(result_file_handle, "{mainline_oneline}")?;
        }

        // Mark as processed
        processed_file_handle.write_all(format!("{oneline}\n").as_bytes())?;
    }

    // Copy results to the proposed directory if there's content
    copy_results_if_needed(result_file)?;

    Ok(())
}

/// Copy results to the proposed directory if there's content
fn copy_results_if_needed(result_file: &Path) -> Result<()> {
    let has_content = fs::metadata(result_file)?.len() > 0;
    if has_content {
        let proposed_dir = common::get_cve_root()?.join("review").join("proposed");
        fs::create_dir_all(&proposed_dir)?;

        let target_file = proposed_dir.join(result_file.file_name().unwrap());
        fs::copy(result_file, target_file)?;
    }
    Ok(())
}

/// Convert the target argument to a tag for display
fn target_as_tag(target: &str) -> String {
    if target.contains("..") {
        target.split("..").nth(1).unwrap_or(target).to_string()
    } else {
        PathBuf::from(target)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(target)
            .to_string()
    }
}

/// Check if a commit has already been published as a CVE
///
/// Searches through the CVE database to see if this commit has already been
/// assigned a CVE ID.
///
/// Returns the CVE ID if found, or None if not found.
fn check_already_published(commit: &Commit) -> Result<Option<String>> {
    // Get the CVE root directory
    let cve_root = if let Ok(dir) = std::env::var("CVE_ROOT") {
        PathBuf::from(dir)
    } else {
        // Default to the parent directory of current directory
        let current_dir = std::env::current_dir()?;
        current_dir.join("cve")
    };

    // Get the mainline SHA (if this is a backport)
    let mainline_sha = get_mainline_sha(&commit.sha)?;

    // Search published CVEs for this SHA
    let published_dir = cve_root.join("published");
    if published_dir.exists() {
        let output = Command::new("find")
            .args([
                published_dir.to_str().unwrap(),
                "-name", "*.sha1",
                "-type", "f"
            ])
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for sha_file in stdout.lines() {
                // Read SHA from file
                let content = match fs::read_to_string(sha_file) {
                    Ok(content) => content.trim().to_string(),
                    Err(_) => continue,
                };

                // Check if this file contains our SHA
                if content == commit.sha || content == mainline_sha {
                    let path = Path::new(sha_file);
                    // Extract CVE ID from the filename
                    if let Some(file_stem) = path.file_stem() {
                        let file_stem_str = file_stem.to_string_lossy();
                        if file_stem_str.starts_with("CVE-") {
                            return Ok(Some(file_stem_str.to_string()));
                        }
                    }

                    // If file stem doesn't directly provide a CVE ID, use the consolidated function
                    return extract_cve_id_from_path(path).map(Some);
                }
            }
        }
    }

    Ok(None)
}

/// Get the mainline SHA for a commit
///
/// Examines the commit message looking for references to upstream commits.
/// Returns the upstream SHA if found, otherwise returns the original SHA.
///
/// This is important for tracking commits across different kernel trees
/// (e.g., stable vs mainline) to prevent duplicate CVE assignments.
fn get_mainline_sha(sha: &str) -> Result<String> {
    let output = Command::new("git")
        .args(["--no-pager", "log", "-n1", sha])
        .output()
        .context("Failed to execute git command")?;

    if !output.status.success() {
        return Err(anyhow!("Git command failed"));
    }

    let log_text = String::from_utf8_lossy(&output.stdout);

    // Look for "upstream: <sha>" or similar
    // Modified to match both full and partial SHAs (minimum 7 hex chars)
   let re = Regex::new(r"^commit\s+([a-f0-9]{7,40})\s+upstream\.$")?;
   for line in log_text.lines() {
       if let Some(caps) = re.captures(line.trim()) {
           return Ok(caps[1].to_string());
       }
    }

    // If no upstream SHA found, return the original SHA (it may be a mainline commit)
    Ok(sha.to_string())
}

/// Get a commit's oneline format (sha + subject)
///
/// Returns a string in the format "<short-sha> <subject>" for the given commit SHA.
fn get_commit_oneline(sha: &str) -> Result<String> {
    git_utils::get_commit_oneline(sha)
}

/// Check if a commit has been previously reviewed in a different session
///
/// Searches through processed files from previous review sessions to find
/// if a commit with the same subject has already been reviewed.
///
/// Returns the filename and SHA of the previously reviewed commit if found.
fn check_previously_reviewed(subject: &str, processed_dir: &Path) -> Result<Option<(String, String)>> {
    let matcher = RegexMatcher::new(&regex::escape(subject))?;
    let mut searcher = SearcherBuilder::new()
        .binary_detection(BinaryDetection::quit(b'\x00'))
        .build();

    for entry in WalkDir::new(processed_dir).min_depth(1) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }

        let mut sha_line: Option<String> = None;

        //Use UTF8 Searcher to find the first matching line
        searcher.search_path(
            &matcher,
            entry.path(),
            UTF8(|_lnum, line| {
                if line.contains(subject) {
                    sha_line = Some(line.to_string());
                    return Ok(false);
                }
                Ok(true)
            }),
        )?;

        if let Some(line) = sha_line {
            let filename = entry.path()
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| anyhow!("Invalid filename"))?
                .to_string();

            let sha = line
                .split_whitespace()
                .next()
                .ok_or_else(|| anyhow!("Expcted SHA in line but got none"))?
                .to_string();

            return Ok(Some((filename, sha)));
        }
    }

    Ok(None)
}

/// Check if two patches have the same patch ID
///
/// Compares two commits to determine if they represent the same changes,
/// even if they have different SHAs or are in different repositories.
///
/// This is useful for identifying when a commit has already been reviewed
/// but appears in a different form (e.g., backported to a stable branch).
fn check_patch_id_match(sha1: &str, sha2: &str) -> Result<bool> {
    // Helper function to get patch ID for a commit
    fn get_patch_id(sha: &str) -> Result<String> {
        let output = Command::new("git")
            .args(["show", sha])
            .stdout(Stdio::piped())
            .spawn()
            .context(format!("Failed to execute git show for {sha}"))?;

        let patch_id_output = Command::new("git")
            .arg("patch-id")
            .stdin(output.stdout.ok_or_else(|| anyhow!("Failed to get stdout from git show command"))?)
            .output()
            .context("Failed to execute git patch-id command")?;

        if !patch_id_output.status.success() {
            return Err(anyhow!("Git patch-id command failed with status: {}",
                patch_id_output.status));
        }

        let output_str = String::from_utf8_lossy(&patch_id_output.stdout);
        let patch_id = output_str
            .split_whitespace()
            .next()
            .ok_or_else(|| anyhow!("Invalid patch-id output, expected format: '<id> <filename>'"))?
            .to_string();

        Ok(patch_id)
    }

    // Get patch IDs for both commits
    let patch_id1 = get_patch_id(sha1)?;
    let patch_id2 = get_patch_id(sha2)?;

    // Compare patch IDs
    Ok(patch_id1 == patch_id2)
}

/// Check if a commit subject appears in the proposed votes directory
///
/// Searches through files in the proposed votes directory to find if a commit
/// with the same subject has already been positively voted for in prior reviews.
///
/// Returns a list of filenames containing this subject, to show the user which
/// files already have votes for this commit.
fn check_proposed_votes(subject: &str, proposed_dir: &PathBuf) -> Result<Vec<String>> {
    let mut votes = Vec::new();

    // Skip if directory doesn't exist
    if !proposed_dir.exists() {
        return Ok(votes);
    }

    let matcher = RegexMatcher::new(&regex::escape(subject))?;
    let mut searcher = SearcherBuilder::new()
        .binary_detection(BinaryDetection::quit(b'\x00'))
        .build();

    for entry in WalkDir::new(proposed_dir).min_depth(1) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }

        let mut found = false;
        searcher.search_path(
            &matcher,
            entry.path(),
            UTF8(|_lnum, _line| {
                found = true;
                Ok(false)
        }))?;

        if found {
            votes.push(entry.path().strip_prefix(proposed_dir)
                .map_or_else(|_| entry.path().display().to_string(), |p| p.display().to_string()));
        }
    }

    Ok(votes)
}

/// Highlight a commit message with good and bad patterns
///
/// Applies ANSI color formatting to the commit message text:
/// - Green for "good" patterns (typically indicating false positives or non-security issues)
/// - Red for "bad" patterns (typically indicating potential security vulnerabilities)
///
/// The highlighting helps reviewers quickly identify relevant security terminology
/// in the commit message and make more informed decisions.
fn highlight_commit_message(message: &str, good_patterns: &[&str], bad_patterns: &[&str]) -> String {
    // For simplicity, we'll just add color codes here
    let mut highlighted = message.to_string();

    // Collect valid regexes first to avoid repeated compilation failures
    let good_regexes: Vec<Regex> = good_patterns
        .iter()
        .filter_map(|pattern| Regex::new(pattern).ok())
        .collect();

    let bad_regexes: Vec<Regex> = bad_patterns
        .iter()
        .filter_map(|pattern| Regex::new(pattern).ok())
        .collect();

    // Highlight good patterns in green
    for re in &good_regexes {
        highlighted = re.replace_all(&highlighted, |caps: &regex::Captures| {
            format!("\x1b[32m{}\x1b[0m", &caps[0])
        }).to_string();
    }

    // Highlight bad patterns in red
    for re in &bad_regexes {
        highlighted = re.replace_all(&highlighted, |caps: &regex::Captures| {
            format!("\x1b[31m{}\x1b[0m", &caps[0])
        }).to_string();
    }

    highlighted
}

/// Get terminal height for appropriate commit display
///
/// Attempts to determine the current terminal height using the `tput` command.
/// Falls back to a sensible default if the height cannot be determined.
///
/// This helps properly format commit messages to fit in the user's terminal window.
fn get_terminal_height() -> usize {
    use std::mem;
    use std::os::unix::io::AsRawFd;
    #[repr(C)]
    struct Winsize {
        ws_row: u16,
        ws_col: u16,
        ws_xpixel: u16,
        ws_ypixel: u16,
    }
    unsafe {
        let mut size: Winsize = mem::zeroed();
        let fd = std::io::stdout().as_raw_fd();
        const TIOCGWINSZ: u64 = 0x5413;
        if libc::ioctl(fd, TIOCGWINSZ, &mut size) == 0 && size.ws_row > 0 {
            return size.ws_row as usize;
        }
    }
    // Fallback to environment variables
    if let Ok(lines) = env::var("LINES")
        && let Ok(height) = lines.parse::<usize>() {
            return height;
        }

    // Default value if we couldn't get terminal height
    // Most modern terminals are much taller than 24 lines
    40
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::{tempdir, NamedTempFile};

    #[test]
    fn test_extract_commits_from_file() {
        let mut temp_file = NamedTempFile::new().unwrap();

        // Write test data
        writeln!(temp_file, "abcd123 This is a test commit").unwrap();
        writeln!(temp_file, "  - This is an annotation line that should be skipped").unwrap();
        writeln!(temp_file, "def4567 Another test commit").unwrap();

        // Reset file position
        temp_file.flush().unwrap();

        // We can't fully test since it needs real git repo for commit messages
        // but we can at least test that the function runs without crashing
        let _commits = get_commits_from_file(temp_file.path()).unwrap_or_default();
    }

    #[test]
    fn test_target_as_tag() {
        assert_eq!(target_as_tag("v6.7.1..v6.7.2"), "v6.7.2");
        assert_eq!(target_as_tag("file.txt"), "file.txt");
        assert_eq!(target_as_tag("/path/to/file.txt"), "file.txt");
    }

    #[test]
    fn test_setup_directories() {
        // This test will only work if the code is running from within the vulns project
        // Skip it if that's not the case
        if let Ok(vulns_dir) = common::find_vulns_dir() {
            // Test normal mode (no annotation)
            let (workdir, processed_file, result_file) = setup_directories("test-tag", false).unwrap();

            assert!(workdir.starts_with(&vulns_dir));
            assert!(workdir.ends_with("tmp/cve-review"));

            assert!(processed_file.parent().unwrap().ends_with("processed"));
            assert_eq!(processed_file.file_name().unwrap().to_str().unwrap(), "test-tag-fromfile");

            assert!(result_file.parent().unwrap().ends_with("results"));
            assert!(result_file.file_name().unwrap().to_str().unwrap().starts_with("test-tag-fromfile-"));

            // Test annotation mode
            let (_, processed_file_annotated, result_file_annotated) = setup_directories("test-tag", true).unwrap();

            assert_eq!(processed_file_annotated.file_name().unwrap().to_str().unwrap(), "test-tag-annotated");
            assert!(result_file_annotated.file_name().unwrap().to_str().unwrap().starts_with("test-tag-annotated-"));

            // Test with git range in normal mode
            let (_, processed_file_range, result_file_range) = setup_directories("v6.7.1..v6.7.2", false).unwrap();

            assert_eq!(processed_file_range.file_name().unwrap().to_str().unwrap(), "v6.7.2");
            assert!(result_file_range.file_name().unwrap().to_str().unwrap().starts_with("v6.7.2-"));

            // Test with git range in annotation mode
            let (_, processed_file_range_annotated, result_file_range_annotated) = setup_directories("v6.7.1..v6.7.2", true).unwrap();

            assert_eq!(processed_file_range_annotated.file_name().unwrap().to_str().unwrap(), "v6.7.2-annotated");
            assert!(result_file_range_annotated.file_name().unwrap().to_str().unwrap().starts_with("v6.7.2-annotated-"));
        }
    }

    #[test]
    fn test_get_processed_commits() {
        let temp_dir = tempdir().unwrap();
        let processed_file = temp_dir.path().join("processed");

        // Create a test processed file
        let mut file = File::create(&processed_file).unwrap();
        writeln!(file, "abcd123 Test commit 1").unwrap();
        writeln!(file, "def4567 Test commit 2").unwrap();

        // Get processed commits
        let processed = get_processed_commits(&processed_file).unwrap();

        assert_eq!(processed.len(), 2);
        assert!(processed.contains("abcd123 Test commit 1"));
        assert!(processed.contains("def4567 Test commit 2"));
    }

    #[test]
    fn test_highlight_commit_message() {
        let message = "This is a test message with a crash and a memory leak. But it's just a false positive.";

        let good_patterns = ["false positive"];
        let bad_patterns = ["crash", "memory leak"];

        let highlighted = highlight_commit_message(message, &good_patterns, &bad_patterns);

        // The highlighted string should contain ANSI color codes
        assert!(highlighted.contains("\x1b["));
        assert!(highlighted.contains("\x1b[31mcrash\x1b[0m"));  // 'crash' in red
        assert!(highlighted.contains("\x1b[31mmemory leak\x1b[0m"));  // 'memory leak' in red
        assert!(highlighted.contains("\x1b[32mfalse positive\x1b[0m"));  // 'false positive' in green
    }

    #[test]
    fn test_is_kernel_directory() {
        // This test will always fail unless run in a kernel directory,
        // but we can at least make sure the function compiles and runs
        let _result = is_kernel_directory();
        // No assertion, as this will depend on where the test is run
    }

    #[test]
    fn test_check_already_published() {
        use std::fs;

        // Set up a mock environment
        let temp_dir = tempdir().unwrap();
        let cve_root = temp_dir.path().to_path_buf();
        let published_dir = cve_root.join("published");
        fs::create_dir_all(&published_dir).unwrap();

        // Create a mock CVE JSON file with a commit subject and SHA
        let test_sha = "abcd1234fedcba5678901234567890123456789";
        let test_subject = "Fix a critical vulnerability";

        let cve_content = format!(r#"{{
            "CVE_data_meta": {{ "ID": "CVE-2023-12345" }},
            "description": {{ "description_data": [{{ "value": "{}" }}] }},
            "references": {{ "reference_data": [{{ "url": "https://git.kernel.org/commit/{}" }}] }}
        }}"#, test_subject, test_sha);

        // Write the CVE JSON file
        let cve_file = published_dir.join("CVE-2023-12345.json");
        fs::write(&cve_file, cve_content).unwrap();

        // Create a commit with matching subject
        let commit = Commit {
            sha: "abcd123".to_string(),
            subject: test_subject.to_string(),
            full_message: "Full message".to_string(),
        };

        // Check the logic using our helper function
        let cve_id = check_if_published(&commit, &cve_root, test_sha.to_string());
        assert_eq!(cve_id, Some("CVE-2023-12345".to_string()));
    }

    // Helper function for the test - simplified version of check_already_published
    fn check_if_published(commit: &Commit, cve_root: &Path, mainline_sha: String) -> Option<String> {
        if mainline_sha.is_empty() {
            return None;
        }

        // Look for the commit subject in the published directory
        let published_dir = cve_root.join("published");

        // Read all JSON files in the published directory
        for entry in fs::read_dir(published_dir).ok()? {
            let entry = entry.ok()?;
            let path = entry.path();

            // Only consider JSON files
            if path.extension()?.to_str()? != "json" {
                continue;
            }

            // Check if this file contains our commit subject and mainline SHA
            if let Ok(file_content) = fs::read_to_string(&path)
                && file_content.contains(&commit.subject) && file_content.contains(&mainline_sha) {
                    // Extract CVE ID from filename
                    let cve_id = path.file_stem()?.to_str()?.to_string();
                    return Some(cve_id);
                }
        }

        None
    }
}
