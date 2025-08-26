// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use anyhow::{anyhow, Context, Result};
use chrono::{Datelike, DateTime, NaiveDate, Utc};
use clap::Parser;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::str;
use walkdir::WalkDir;
use cve_utils::cve_utils::extract_cve_id_from_path;

#[derive(Parser)]
#[command(author, version, about = "CVE statistics utility")]
struct Args {
    /// Show general CVE statistics
    #[arg(long)]
    summary: bool,

    /// Show top N CVE commit authors (default: 10)
    #[arg(long, value_name = "N", default_missing_value = "10", num_args = 0..=1)]
    authors: Option<usize>,

    /// Show top M subsystems with S sub-subsystems each (default: M=10,S=3)
    #[arg(long, value_name = "M[,S]", value_parser = parse_subsystem_args, default_missing_value = "10,3", num_args = 0..=1)]
    subsystem: Option<(usize, usize)>,

    /// Show top N kernel versions with CVE fixes (default: 10)
    #[arg(long, value_name = "N", default_missing_value = "10", num_args = 0..=1)]
    versions: Option<usize>,

    /// Show Time to Fix analysis
    #[arg(long)]
    ttf: bool,
}

/// Parse the subsystem argument which can be either M or M,S
fn parse_subsystem_args(arg: &str) -> Result<(usize, usize), String> {
    if let Some((m, s)) = arg.split_once(',') {
        let m_value = m.parse::<usize>()
            .map_err(|_| format!("Invalid value for subsystems: {m}"))?;
        let s_value = s.parse::<usize>()
            .map_err(|_| format!("Invalid value for sub-subsystems: {s}"))?;
        Ok((m_value, s_value))
    } else {
        let m_value = arg.parse::<usize>()
            .map_err(|_| format!("Invalid value for subsystems: {arg}"))?;
        Ok((m_value, 3)) // Default to 3 sub-subsystems
    }
}

fn find_cve_root() -> Result<PathBuf> {
    // Start from the current directory
    let mut current_dir = env::current_dir().context("Failed to get current directory")?;

    // Keep going up the directory tree until we find the CVE root or hit the filesystem root
    loop {
        // Check if this could be the CVE root by looking for .git, scripts, and cve directories
        let has_git = current_dir.join(".git").exists();
        let has_scripts = current_dir.join("scripts").exists();
        let has_cve = current_dir.join("cve").exists();

        if has_git && has_scripts && has_cve {
            // This looks like the CVE root directory
            return Ok(current_dir);
        }

        // Move up one directory
        if let Some(parent) = current_dir.parent() {
            current_dir = parent.to_path_buf();
            // Check if we've hit the filesystem root
            if current_dir == Path::new("/") || current_dir.as_os_str().is_empty() {
                break;
            }
        } else {
            // We've hit the filesystem root
            break;
        }
    }

    // If we get here, we couldn't find the CVE root
    Err(anyhow!("Could not find CVE root directory. Please run this tool from within the vulnerability database repository."))
}

/// Main entry point for the CVE statistics utility
///
/// This function:
/// 1. Parses command line arguments
/// 2. Validates environment variables and paths
/// 3. Finds the CVE root directory
/// 4. Dispatches to the appropriate handlers based on arguments
fn main() {
    let cli = Args::parse();

    // Validate CVEKERNELTREE environment variable
    let kernel_tree = env::var("CVEKERNELTREE").map_or_else(
        |_| {
            eprintln!("Error: CVEKERNELTREE environment variable not set");
            eprintln!("Please set it to the location of your Linux kernel git tree");
            eprintln!("Example: export CVEKERNELTREE=/path/to/linux");
            std::process::exit(1);
        },
        PathBuf::from,
    );

    // Validate kernel tree path exists and is a directory
    if !kernel_tree.exists() || !kernel_tree.is_dir() {
        eprintln!("Error: {} is not a valid directory", kernel_tree.display());
        std::process::exit(1);
    }

    // Test opening the kernel repository to ensure it's a valid git repo
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .current_dir(&kernel_tree)
        .output();

    match output {
        Ok(output) if output.status.success() => {},
        _ => {
            eprintln!("Error: {} is not a valid git repository", kernel_tree.display());
            std::process::exit(1);
        }
    }

    // Find the CVE root directory by looking for specific markers
    let cve_root = match find_cve_root() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!("The CVE root directory should contain: .git, scripts, and cve directories");
            std::process::exit(1);
        }
    };

    // Verify the cve/published directory exists
    if !cve_root.join("cve").join("published").exists() {
        eprintln!("Error: Found potential CVE root at {}, but it does not contain a cve/published directory", cve_root.display());
        std::process::exit(1);
    }

    // Run the actual program with comprehensive error handling
    match run(&cli, &cve_root, &kernel_tree) {
        Ok(()) => {},
        Err(e) => {
            eprintln!("Error: {e}");

            // Provide additional context for git errors
            cve_utils::print_git_error_details(&e);

            std::process::exit(1);
        }
    }
}

fn run(args: &Args, cve_root: &Path, kernel_tree: &Path) -> Result<()> {
    // Only skip get_first_cve_date when only showing authors
    let start_date = if !args.summary && args.versions.is_none() && args.subsystem.is_none() && !args.ttf {
        // Skip get_first_cve_date entirely when only showing authors
        None
    } else {
        // Get date for other operations
        match get_first_cve_date(cve_root) {
            Ok(date) => {
                Some(date)
            }
            Err(e) => {
                return Err(e);
            }
        }
    };

    // Show summary stats if requested
    if args.summary {
        if let Some(date) = &start_date {
            show_summary_stats(cve_root, date)?;
        } else {
            return Err(anyhow!("First CVE date is required for summary statistics"));
        }
    }

    // Show author stats if requested
    if let Some(num_authors) = args.authors {
        show_author_stats(cve_root, kernel_tree, num_authors)?;
    }

    // Show subsystem stats if requested
    if let Some((num_subsystems, num_sub_subsystems)) = args.subsystem {
        show_subsystem_stats(
            cve_root,
            kernel_tree,
            num_subsystems,
            num_sub_subsystems,
            args.authors.is_some()
        );
    }

    // Show version stats if requested
    if let Some(num_versions) = args.versions {
        show_version_stats(cve_root, num_versions);
    }

    // Show time-to-fix analysis if requested
    if args.ttf {
        show_time_to_fix_stats(cve_root, kernel_tree);
    }

    // If no args specified, show usage
    if !args.summary && args.authors.is_none() && args.subsystem.is_none() &&
       args.versions.is_none() && !args.ttf {
        println!("Usage: cve_stats [--summary] [--authors[=N]] [--subsystem[=M[,S]]] [--versions[=N]] [--ttf]");
        println!("  --summary              Show general CVE statistics");
        println!("  --authors[=N]          Show top N CVE commit authors (default: 10)");
        println!("  --subsystem[=M[,S]]    Show top M subsystems with S sub-subsystems each (default: M=10,S=3)");
        println!("  --versions[=N]          Show top N kernel versions with CVE fixes (default: 10)");
        println!("  --ttf                  Show Time to Fix analysis");
    }

    Ok(())
}

fn get_first_cve_date(vulns_dir: &Path) -> Result<String> {
    // Use git log to find the first CVE date (matching bash script behavior)
    let output = std::process::Command::new("git")
        .args(["log", "--diff-filter=A", "--reverse", "--pretty=format:%ad", "--date=short", "cve/published/"])
        .current_dir(vulns_dir)
        .output()
        .context("Failed to run git log to find first CVE date")?;

    if !output.status.success() {
        return Err(anyhow!("Failed to get first CVE date from git history"));
    }

    let dates = String::from_utf8_lossy(&output.stdout);
    let first_date = dates.lines().next();

    match first_date {
        Some(date) if !date.is_empty() => Ok(date.to_string()),
        _ => {
            // Fallback: if no git history, use a default date
            // This matches the bash script's fallback behavior
            Ok("2019-01-01".to_string())
        }
    }
}

/// Count CVEs created in a specific time period
///
/// This function:
/// 1. Finds all commits in the given date range
/// 2. Examines which files were added in each commit
/// 3. Identifies files in the cve/published directory
/// 4. Counts unique CVE IDs from those files
/// 5. Returns the count of unique CVEs found
fn count_cves_in_range(vulns_dir: &Path, start_date: &str, end_date: &str) -> Result<usize> {
    let git_dir = vulns_dir;

    // Verify it's a git repository
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .current_dir(git_dir)
        .output()
        .context("Failed to verify git repository")?;

    if !output.status.success() {
        return Err(anyhow!("Not a valid git repository: {}", git_dir.display()));
    }

    let mut unique_cves = HashSet::new();

    // Get commit range
    let after_arg = format!("--after={start_date}");
    let before_arg = format!("--before={end_date}");

    // Use git rev-list to get commits in the range
    let output = std::process::Command::new("git")
        .args(["rev-list", "--all", &after_arg, &before_arg])
        .current_dir(git_dir)
        .output()
        .context("Failed to run git rev-list")?;

    let commits: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Process commits in parallel to find CVEs
    let cve_sets: Vec<HashSet<String>> = commits.par_iter()
        .map(|commit_sha| {
            let mut commit_cves = HashSet::new();

            // Get only ADDED files (not modified) for this commit in the vulns repo
            // Using --diff-filter=A to only count newly created CVEs, not updates
            let output = std::process::Command::new("git")
                .args(["show", "--pretty=format:", "--name-only", "--diff-filter=A", commit_sha])
                .current_dir(git_dir)
                .output();

            if let Ok(output) = output && output.status.success() {
                let files = String::from_utf8_lossy(&output.stdout);
                for file_path in files.lines() {
                    // Only count .json files (matching bash script behavior)
                    // This avoids counting duplicates and skips bulk .dyad additions
                    if file_path.starts_with("cve/published/") && file_path.ends_with(".json") && let Ok(cve_id) = extract_cve_id_from_path(file_path) {
                        commit_cves.insert(cve_id);
                    }
                }
            }
            commit_cves
        })
        .collect();

    // Merge all CVE sets into unique_cves
    for cve_set in cve_sets {
        unique_cves.extend(cve_set);
    }

    Ok(unique_cves.len())
}

/// Show summary statistics
fn show_summary_stats(cve_root: &Path, first_cve_date: &str) -> Result<()> {
    // Print header for yearly stats
    println!("\n=== CVEs Published Per Year ===");

    // Calculate statistics per year in parallel
    let current_year = Utc::now().year();
    let years: Vec<i32> = (2019..=current_year).collect();

    let year_counts: Vec<(i32, Result<usize>)> = years.par_iter()
        .map(|&year| {
            let start_date = format!("{year}-01-01");
            let next_year = year + 1;
            let end_date = format!("{next_year}-01-01");
            let count = count_cves_in_range(cve_root, &start_date, &end_date);
            (year, count)
        })
        .collect();

    // Print results in order
    for (year, count_result) in year_counts {
        match count_result {
            Ok(count) => println!("{year}: {count} CVEs"),
            Err(e) => eprintln!("Error calculating CVEs for {year}: {e}"),
        }
    }

    // Print header for last 6 months stats
    println!("\n=== CVEs Published in Last 6 Months ===");

    // Get current date components
    let now = Utc::now();
    let current_year = now.year();
    // Safe cast because month() always returns 1-12
    #[allow(clippy::cast_possible_wrap)]
    let current_month = now.month() as i32;

    // Build month ranges
    let month_ranges: Vec<(i32, i32, i32)> = (0..=5).rev()
        .map(|i| {
            let mut month = current_month - i;
            let mut year = current_year;

            if month <= 0 {
                month += 12;
                year -= 1;
            }
            (i, year, month)
        })
        .collect();

    // Calculate statistics for last 6 months in parallel
    let month_counts: Vec<(String, String, Result<usize>)> = month_ranges.par_iter()
        .map(|&(_i, year, month)| {
            let mut next_month = month + 1;
            let mut next_year = year;

            if next_month > 12 {
                next_month = 1;
                next_year += 1;
            }

            // Format dates
            let start_date = format!("{year}-{month:02}-01");
            let end_date = format!("{next_year}-{next_month:02}-01");

            // Get count for this month
            let count = count_cves_in_range(cve_root, &start_date, &end_date);

            // Use chrono to format the month name
            let date = NaiveDate::parse_from_str(&start_date, "%Y-%m-%d")
                .unwrap_or_else(|_| NaiveDate::from_ymd_opt(year, month as u32, 1).unwrap());
            let formatted_date = date.format("%B %Y").to_string();

            (start_date, formatted_date, count)
        })
        .collect();

    // Print results in order (they're already in chronological order from the collection)
    for (_start_date, formatted_date, count_result) in month_counts {
        match count_result {
            Ok(count) => println!("{:>15}: {} CVEs", formatted_date, count),
            Err(e) => eprintln!("Error calculating CVEs for {}: {}", formatted_date, e),
        }
    }

    // Calculate overall averages
    println!("\n=== Overall Averages ===");

    // Parse first CVE date
    let first_date = NaiveDate::parse_from_str(first_cve_date, "%Y-%m-%d")?;
    let now = Utc::now().naive_local().date();

    // Calculate total days and CVEs
    // Safe to ignore loss of precision for this calculation
    #[allow(clippy::cast_precision_loss)]
    let total_days = (now - first_date).num_days() as f64;

    #[allow(clippy::cast_precision_loss)]
    let total_cves = count_cves_in_range(cve_root, first_cve_date, &now.format("%Y-%m-%d").to_string())? as f64;

    // Calculate averages
    let avg_per_month = total_cves / (total_days / 30.44);
    let avg_per_week = total_cves / (total_days / 7.0);
    let avg_per_day = total_cves / total_days;

    println!("Average CVEs per month: {avg_per_month:.2}");
    println!("Average CVEs per week: {avg_per_week:.2}");
    println!("Average CVEs per day: {avg_per_day:.2}");

    Ok(())
}

/// Show author statistics
fn show_author_stats(cve_root: &Path, kernel_tree: &Path, num_authors: usize) -> Result<()> {
    println!("\n=== Top {num_authors} CVE Commit Authors ===");

    // Find all .sha1 files recursively in published directory
    let published_dir = cve_root.join("cve").join("published");
    let mut sha1_files = Vec::new();

    for entry in WalkDir::new(&published_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file() && e.path().extension().is_some_and(|ext| ext == "sha1"))
    {
        sha1_files.push(entry.path().to_path_buf());
    }

    println!("Found {} SHA1 files", sha1_files.len());

    // Process SHA1 files in parallel to get authors
    let author_results: Vec<Option<String>> = sha1_files.par_iter()
        .map(|sha1_file| {
            // Read the SHA1 from the file
            let sha1_content = fs::read_to_string(sha1_file).ok()?;
            let sha1_content = sha1_content.trim();

            if sha1_content.is_empty() {
                return None;
            }

            // Handle multiple SHAs in the file (split by newlines)
            let sha1 = sha1_content.lines().next().unwrap_or(sha1_content).trim();

            // Get the author name using git command
            let output = std::process::Command::new("git")
                .args(["show", "--format=%an", "-s", sha1])
                .current_dir(kernel_tree)
                .output()
                .ok()?;

            if output.status.success() {
                let author_name = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !author_name.is_empty() {
                    return Some(author_name);
                }
            }
            None
        })
        .collect();

    // Count authors from results
    let mut author_counts: HashMap<String, usize> = HashMap::new();
    for author_name in author_results.into_iter().flatten() {
        *author_counts.entry(author_name).or_insert(0) += 1;
    }

    // Sort authors by count (descending)
    let mut author_vec: Vec<_> = author_counts.iter().collect();
    author_vec.sort_by(|a, b| b.1.cmp(a.1));

    // Show the top N authors
    for (i, (author, count)) in author_vec.iter().take(num_authors).enumerate() {
        println!("{}. {} ({} commits)", i + 1, author, count);
    }

    Ok(())
}

/// Get the commit subsystem from a sha1 file
fn get_commit_subsystem(kernel_tree: &Path, sha1_file: &Path) -> Result<Option<(String, String)>> {
    // Read the sha1 from the file
    let sha1 = match fs::read_to_string(sha1_file) {
        Ok(content) => content.trim().to_string(),
        Err(e) => {
            return Err(anyhow!("Failed to read SHA1 from file: {} - {}", sha1_file.display(), e));
        }
    };

    if sha1.is_empty() {
        return Ok(None);
    }

    // Handle multiple SHAs in the file (take first line)
    let sha1 = sha1.lines().next().unwrap_or(&sha1).trim();

    // Get affected files using git show command
    let output = std::process::Command::new("git")
        .args(["show", "--pretty=format:", "--name-only", sha1])
        .current_dir(kernel_tree)
        .output();

    let Ok(output) = output else {
        return Ok(None);
    };

    if !output.status.success() {
        return Ok(None);
    }

    let files_output = String::from_utf8_lossy(&output.stdout);
    let affected_files: Vec<String> = files_output
        .lines()
        .filter(|line| !line.is_empty())
        .map(String::from)
        .collect();

    // Get the first file (if any)
    if let Some(path) = affected_files.first() {
        // Split path into parts to get main subsystem and sub-subsystem
        let parts: Vec<&str> = path.split('/').collect();

        if !parts.is_empty() {
            let main_subsystem = parts[0].to_string();
            let sub_subsystem = if parts.len() > 1 {
                format!("{}/{}", parts[0], parts[1])
            } else {
                main_subsystem.clone()
            };

            return Ok(Some((main_subsystem, sub_subsystem)));
        }
    }

    Ok(None)
}

/// Type alias for the complex return type of `collect_subsystem_data`
type SubsystemData = (
    Vec<PathBuf>,                  // SHA1 files
    HashMap<String, Vec<String>>,  // Main subsystems
    HashMap<String, Vec<String>>,  // Sub subsystems
    bool                           // Whether author stats are enabled
);

/// Collect subsystem data from SHA1 files
fn collect_subsystem_data(
    published_dir: &Path,
    kernel_tree: &Path,
    show_authors: bool
) -> SubsystemData {
    // Find all .sha1 files recursively in published directory
    let sha1_files: Vec<_> = WalkDir::new(published_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file() && e.path().extension().is_some_and(|ext| ext == "sha1"))
        .map(|e| e.path().to_path_buf())
        .collect();

    println!("Found {} SHA1 files", sha1_files.len());

    // Track subsystems and their CVEs
    let mut main_subsystems: HashMap<String, Vec<String>> = HashMap::new();
    let mut sub_subsystems: HashMap<String, Vec<String>> = HashMap::new();


    // Process files in parallel using rayon
    let results: Vec<(PathBuf, Option<(String, String)>)> = sha1_files.par_iter()
        .map(|sha1_file| {
            let subsystem = get_commit_subsystem(kernel_tree, sha1_file).unwrap_or_default();
            (sha1_file.clone(), subsystem)
        })
        .collect();

    // Aggregate results
    for (sha1_file, subsystem_info) in results {
        if let Some((main_subsystem, sub_subsystem)) = subsystem_info {
            let cve_id = sha1_file.file_stem().unwrap().to_string_lossy().to_string();

            // Add to main subsystem
            main_subsystems.entry(main_subsystem.clone())
                .or_default()
                .push(cve_id.clone());

            // Add to sub-subsystem if different from main
            if main_subsystem != sub_subsystem {
                let sub_key = sub_subsystem.replace('/', "_"); // Use underscore for filenames
                sub_subsystems.entry(sub_key)
                    .or_default()
                    .push(cve_id);
            }
        }
    }

    (sha1_files, main_subsystems, sub_subsystems, show_authors)
}

/// Get author statistics for a subsystem
fn get_author_stats(
    cve_list: &[String],
    sha1_files: &[PathBuf],
    kernel_tree: &Path,
) -> Vec<(String, usize)> {
    // Create a map to store author counts
    let mut author_counts: HashMap<String, usize> = HashMap::new();

    // Get authors for each CVE in parallel
    let author_results: Vec<Option<String>> = cve_list.par_iter()
        .map(|cve_id| {
            // Find the sha1 file for this CVE
            for sha1_file in sha1_files {
                if sha1_file.file_stem().unwrap().to_string_lossy() == *cve_id {
                    // Read the SHA1 from the file
                    if let Ok(sha1_content) = fs::read_to_string(sha1_file) {
                        let sha1_str = sha1_content.trim();
                        if !sha1_str.is_empty() {
                            // Handle multiple SHAs in the file (take first line)
                            let sha1 = sha1_str.lines().next().unwrap_or(sha1_str).trim();

                            // Get author using git command
                            let output = std::process::Command::new("git")
                                .args(["show", "--format=%an", "-s", sha1])
                                .current_dir(kernel_tree)
                                .output();

                            if let Ok(output) = output && output.status.success() {
                                let author_name = String::from_utf8_lossy(&output.stdout).trim().to_string();
                                if !author_name.is_empty() {
                                    return Some(author_name);
                                }
                            }
                        }
                    }
                    break;
                }
            }
            None
        })
        .collect();

    // Count authors from results
    for author_name in author_results.into_iter().flatten() {
        *author_counts.entry(author_name).or_insert(0) += 1;
    }

    // Sort authors by count
    let mut authors: Vec<_> = author_counts.into_iter().collect();
    authors.sort_by(|a, b| b.1.cmp(&a.1));

    authors
}

/// Show subsystem statistics
fn show_subsystem_stats(
    cve_root: &Path,
    kernel_tree: &Path,
    num_subsystems: usize,
    num_sub_subsystems: usize,
    show_authors: bool
) {
    println!("\n=== Top {num_subsystems} Subsystems with CVEs (showing top {num_sub_subsystems} sub-subsystems each) ===");

    // Find all .sha1 files recursively in published directory
    let published_dir = cve_root.join("cve").join("published");

    // Collect the subsystem data
    let (sha1_files, main_subsystems, sub_subsystems, _show_authors_flag) =
        collect_subsystem_data(&published_dir, kernel_tree, show_authors);

    // Convert to vec and sort by CVE count
    let mut subsystems: Vec<_> = main_subsystems.iter()
        .map(|(name, cves)| (name.clone(), cves.len()))
        .collect();
    subsystems.sort_by(|a, b| b.1.cmp(&a.1));

    // Display top subsystems
    for (subsystem, count) in subsystems.iter().take(num_subsystems) {
        println!("{subsystem}: {count} CVEs");

        // Find sub-subsystems for this main subsystem
        let sub_prefix = format!("{subsystem}_");
        let mut sub_entries: Vec<_> = sub_subsystems.iter()
            .filter(|(name, _)| name.starts_with(&sub_prefix))
            .map(|(name, cves)| (name.replace('_', "/"), cves.len()))
            .collect();
        sub_entries.sort_by(|a, b| b.1.cmp(&a.1));

        // Display top sub-subsystems
        for (sub_name, sub_count) in sub_entries.iter().take(num_sub_subsystems) {
            println!("    {sub_name}: {sub_count} CVEs");
        }

        // If authors flag is set, show top authors for this subsystem
        if show_authors {
            println!("  Top authors for {subsystem}:");

            // Get all CVE IDs for this subsystem
            if let Some(cve_list) = main_subsystems.get(subsystem) {
                // Get author statistics
                let authors = get_author_stats(cve_list, &sha1_files, kernel_tree);

                // Show top 5 authors
                if authors.is_empty() {
                    println!("    No author information available");
                } else {
                    for (author, count) in authors.iter().take(5) {
                        println!("    {author}: {count} CVEs");
                    }
                }
            }
            println!();
        }
        println!();
    }
}

/// Get kernel versions from a CVE's dyad file
fn get_kernel_versions(sha1_file: &Path, version_type: &str) -> Result<Option<String>> {
    let dyad_file = sha1_file.with_extension("dyad");

    if !dyad_file.exists() {
        return Ok(None);
    }

    // Read the dyad file
    let content = fs::read_to_string(&dyad_file)
        .with_context(|| format!("Failed to read dyad file: {}", dyad_file.display()))?;

    // Process each line in the dyad file
    for line in content.lines() {
        // Skip comments and empty lines
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }

        // Split line by colons to get version numbers
        let parts: Vec<&str> = line.split(':').collect();

        // Format appears to be: [vuln_ver]:[vuln_commit]:[fixed_ver]:[fixed_commit]
        if parts.len() == 4 {
            let (vuln_ver, fixed_ver) = (parts[0], parts[2]);

            // Skip lines with 0 (no version)
            if version_type == "vulnerable" && vuln_ver == "0" {
                continue;
            }
            if version_type == "fixed" && fixed_ver == "0" {
                continue;
            }

            // Get the version based on type
            let version_str = if version_type == "vulnerable" {
                vuln_ver
            } else {
                fixed_ver
            };

            // Skip -rc versions
            if version_str.contains("-rc") {
                continue;
            }

            // Match bash script behavior: only accept versions that are exactly major.minor format
            // (e.g., "6.1" but not "6.1.120")
            let parts: Vec<&str> = version_str.split('.').collect();
            if parts.len() == 2 {
                // Only accept if it matches the pattern ^\d+\.\d+$
                if parts[0].chars().all(|c| c.is_ascii_digit()) &&
                   parts[1].chars().all(|c| c.is_ascii_digit()) {
                    return Ok(Some(version_str.to_string()));
                }
            }
        }
    }

    Ok(None)
}

/// Show version statistics
fn show_version_stats(cve_root: &Path, num_versions: usize) {
    println!("\n=== Top {num_versions} Major Kernel Versions with CVE Fixes ===");

    // Find all .sha1 files recursively in published directory
    let published_dir = cve_root.join("cve").join("published");
    let sha1_files: Vec<_> = WalkDir::new(&published_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file() && e.path().extension().is_some_and(|ext| ext == "sha1"))
        .map(|e| e.path().to_path_buf())
        .collect();

    // Track fixed and vulnerable versions
    let mut fixed_versions: HashMap<String, usize> = HashMap::new();
    let mut vuln_versions: HashMap<String, usize> = HashMap::new();

    // Process files in parallel
    let fixed_results: Vec<_> = sha1_files.par_iter()
        .filter_map(|sha1_file| {
            match get_kernel_versions(sha1_file, "fixed") {
                Ok(Some(version)) => Some(version),
                _ => None,
            }
        })
        .collect();

    let vuln_results: Vec<_> = sha1_files.par_iter()
        .filter_map(|sha1_file| {
            match get_kernel_versions(sha1_file, "vulnerable") {
                Ok(Some(version)) => Some(version),
                _ => None,
            }
        })
        .collect();

    // Count each version
    for version in fixed_results {
        *fixed_versions.entry(version).or_insert(0) += 1;
    }

    for version in vuln_results {
        *vuln_versions.entry(version).or_insert(0) += 1;
    }

    // Sort by count (descending)
    let mut fixed_list: Vec<_> = fixed_versions.into_iter().collect();
    fixed_list.sort_by(|a, b| b.1.cmp(&a.1));

    let mut vuln_list: Vec<_> = vuln_versions.into_iter().collect();
    vuln_list.sort_by(|a, b| b.1.cmp(&a.1));

    // Show fixed versions
    println!("\nTop {num_versions} Major Kernel Versions Where CVEs Were Fixed:");
    for (version, count) in fixed_list.iter().take(num_versions) {
        if version == "0" {
            println!("Unknown: {count} CVEs fixed");
        } else {
            println!("Linux {version}:\t{count} CVEs fixed");
        }
    }

    // Show vulnerable versions
    println!("\nTop {num_versions} Major Kernel Versions Where CVEs Were Introduced:");
    for (version, count) in vuln_list.iter().take(num_versions) {
        if version == "0" {
            println!("Unknown: {count} CVEs introduced");
        } else {
            println!("Linux {version}:\t{count} CVEs introduced");
        }
    }
}

/// Collect time-to-fix data from dyad files
fn collect_time_to_fix_data(
    published_dir: &Path,
    kernel_tree: &Path,
) -> Vec<(String, Option<i64>)> {
    // Find all .sha1 files recursively in published directory
    let sha1_files: Vec<_> = WalkDir::new(published_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file() && e.path().extension().is_some_and(|ext| ext == "sha1"))
        .map(|e| e.path().to_path_buf())
        .collect();

    // Process files in parallel to get time-to-fix data
    println!("Processing {} SHA1 files to determine time-to-fix...", sha1_files.len());

    // Gather dyad files that correspond to sha1 files for easier processing
    // Since we'll need to check both vulnerable and fixed commits
    let dyad_files: Vec<_> = sha1_files.iter()
        .map(|f| (f.clone(), f.with_extension("dyad")))
        .filter(|(_, dyad)| dyad.exists())
        .collect();

    println!("Found {} dyad files", dyad_files.len());

    // Process dyad files in parallel to get TTF data
    let results: Vec<(String, Option<i64>)> = dyad_files.par_iter()
        .filter_map(|(sha1_file, dyad_file)| {
            let cve_id = sha1_file.file_stem().unwrap().to_string_lossy().to_string();

            // Read dyad file to get vulnerable and fixed commits
            if let Ok(content) = fs::read_to_string(dyad_file) {
                for line in content.lines() {
                    // Skip comments and empty lines
                    if line.starts_with('#') || line.trim().is_empty() {
                        continue;
                    }

                    // Dyad format: vulnerable_ver:vulnerable_commit:fixed_ver:fixed_commit
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() != 4 {
                        continue;
                    }

                    let vuln_commit = parts[1].trim();
                    let fix_commit = parts[3].trim();

                    // Skip if either commit is "0" (unknown)
                    if vuln_commit == "0" || fix_commit == "0" {
                        continue;
                    }

                    // Get the commit dates
                    let Ok(Some(vuln_date)) = get_commit_author_date_git(kernel_tree, vuln_commit) else { continue };
                    let Ok(Some(fix_date)) = get_commit_author_date_git(kernel_tree, fix_commit) else { continue };

                    // Calculate days between dates
                    let days = (fix_date - vuln_date).num_days();

                    // Only consider valid TTF (positive days)
                    if days > 0 {
                        return Some((cve_id, Some(days)));
                    }
                }
            }

            Some((cve_id, None))
        })
        .collect();

    results
}

/// Process and print time-to-fix statistics
fn process_time_to_fix_stats(results: &[(String, Option<i64>)]) {
    // Track time-to-fix data
    let mut ttf_days: Vec<i64> = Vec::new();
    let mut cves_by_category: HashMap<&str, Vec<String>> = HashMap::new();
    for category in &["1month", "3months", "6months", "1year", "over1year"] {
        cves_by_category.insert(category, Vec::new());
    }

    // Process results
    let mut valid_ttf_count = 0;
    for (cve_id, days_opt) in results {
        if let Some(days) = days_opt {
            valid_ttf_count += 1;
            ttf_days.push(*days);

            // Categorize by time range
            let category = match days {
                d if *d <= 30 => "1month",
                d if *d <= 90 => "3months",
                d if *d <= 180 => "6months",
                d if *d <= 365 => "1year",
                _ => "over1year",
            };

            if let Some(category_list) = cves_by_category.get_mut(category) {
                category_list.push(cve_id.clone());
            }
        }
    }

    println!("Found {valid_ttf_count} CVEs with valid TTF data");

    // Calculate statistics
    if ttf_days.is_empty() {
        println!("No CVEs found with both introduction and fix dates.");
    } else {
        let total_cves = ttf_days.len();

        // Safe to ignore precision loss for statistical calculations
        #[allow(clippy::cast_precision_loss)]
        let avg_days = ttf_days.iter().sum::<i64>() as f64 / total_cves as f64;

        // Calculate median
        ttf_days.sort_unstable();  // Using sort_unstable as it's faster for primitives
        let median_days = if total_cves % 2 == 0 {
            let mid = total_cves / 2;
            #[allow(clippy::cast_precision_loss)]
            let median = (ttf_days[mid - 1] + ttf_days[mid]) as f64 / 2.0;
            median
        } else {
            #[allow(clippy::cast_precision_loss)]
            let median = ttf_days[total_cves / 2] as f64;
            median
        };

        println!("Analysis based on {total_cves} CVEs with known introduction and fix dates");
        println!("Average time to fix: {avg_days:.1} days");
        println!("Median time to fix: {median_days:.1} days");
        println!();
        println!("Distribution:");

        // Print distribution
        for (category, label) in [
            ("1month", "≤ 30 days:    "),
            ("3months", "31-90 days:   "),
            ("6months", "91-180 days:  "),
            ("1year", "181-365 days: "),
            ("over1year", "> 365 days:   "),
        ] {
            let count = cves_by_category.get(category).map_or(0, Vec::len);

            // Safe to ignore precision loss for percentage calculation
            #[allow(clippy::cast_precision_loss)]
            let percentage = (count as f64 / total_cves as f64) * 100.0;

            println!("{label} {count} CVEs ({percentage:.1}%)");
        }

        // Add start and end date range
        let now = chrono::Local::now().naive_local().date();
        println!("\nStatistics calculated from {} to {}",
                NaiveDate::from_ymd_opt(2024, 1, 21).unwrap_or_else(|| now - chrono::Duration::days(365)),
                now);
    }
}

/// Show time to fix statistics
fn show_time_to_fix_stats(cve_root: &Path, kernel_tree: &Path) {
    println!("\n=== Time to Fix Analysis ===");

    // Find all .sha1 files recursively in published directory
    let published_dir = cve_root.join("cve").join("published");

    // Collect time-to-fix data
    let results = collect_time_to_fix_data(&published_dir, kernel_tree);

    // Process and display the statistics
    process_time_to_fix_stats(&results);
}

/// Get the author date for a commit by hash using git command
fn get_commit_author_date_git(kernel_tree: &Path, commit_hash: &str) -> Result<Option<chrono::NaiveDate>> {
    // Get the author date using git command
    // --format=%at gives us the author timestamp in Unix epoch seconds
    let output = std::process::Command::new("git")
        .args(["show", "--format=%at", "-s", commit_hash])
        .current_dir(kernel_tree)
        .output()
        .context("Failed to run git show command")?;

    if !output.status.success() {
        return Ok(None);
    }

    let timestamp_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let timestamp = timestamp_str.parse::<i64>()
        .context(format!("Failed to parse timestamp: {}", timestamp_str))?;

    // Convert to chrono date
    let dt = DateTime::<Utc>::from_timestamp(timestamp, 0)
        .context("Failed to convert git time to DateTime")?;

    Ok(Some(dt.naive_utc().date()))
}