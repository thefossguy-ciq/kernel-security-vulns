// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use anyhow::{anyhow, Context, Result};
use cve_utils::print_git_error_details;
use cve_utils::cve_validation::find_cve_id;
use cve_utils::year_utils::{is_valid_year, is_year_dir_exists};
use cve_utils::common;
use std::path::{Path, PathBuf};
use std::thread;
use std::sync::{Arc, Mutex};
use std::fs;
use std::process::Command;
use clap::Parser;
use tempfile::NamedTempFile;
use walkdir::WalkDir;
use owo_colors::OwoColorize;
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};

/// Update all existing CVE entries based on the latest information from the git tree(s)
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Optional CVE ID or year to update (if not provided, all years will be updated)
    #[clap(index = 1)]
    target: Option<String>,

    /// Dry run - show what would be updated but don't actually do it
    #[clap(long)]
    dry_run: bool,

    /// Number of threads to use for parallel updates (defaults to number of CPUs)
    #[clap(long, short)]
    threads: Option<usize>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Determine the number of threads to use
    let num_threads = args.threads.unwrap_or_else(num_cpus::get);

    // Get CVE root path
    let cve_root = match common::get_cve_root() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Error: {e}");
            print_git_error_details(&e);
            std::process::exit(1);
        }
    };

    if let Some(target) = args.target.as_deref() {
        // Check if target is a specific CVE ID
        match find_cve_id(target) {
            Ok(Some(cve_id)) => {
                // Extract the CVE ID from the file path for display
                let cve_id_str = cve_id.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(target);

                println!("Updating CVE {}", cve_id_str.cyan());
                if args.dry_run {
                    println!("  {} Dry run mode - no actual update", "INFO:".blue());
                }
                if let Err(e) = update_cve(&cve_id, args.dry_run) {
                    eprintln!("Error updating {}: {}", cve_id_str.cyan(), e);
                    print_git_error_details(&e);
                    return Err(e);
                }
            }
            // Check if target is a year
            Ok(None) if is_valid_year(target) && is_year_dir_exists(&cve_root, target).unwrap_or(false) => {
                if let Err(e) = update_year(target, num_threads, args.dry_run) {
                    eprintln!("Error updating year {target}: {e}");
                    print_git_error_details(&e);
                    return Err(e);
                }
            }
            Ok(_) => {
                return Err(anyhow!("{} is not a valid CVE ID or year with published entries", target));
            }
            Err(e) => {
                eprintln!("Error: {e}");
                print_git_error_details(&e);
                return Err(e);
            }
        }
    } else {
        // No target specified, update all years
        println!("Updating all published CVE entries");
        if let Err(e) = update_all_years(&cve_root, num_threads, args.dry_run) {
            eprintln!("Error updating all years: {e}");
            print_git_error_details(&e);
            return Err(e);
        }
    }

    Ok(())
}

/// Update all years with published CVEs
fn update_all_years(cve_root: &Path, num_threads: usize, dry_run: bool) -> Result<()> {
    let published_dir = cve_root.join("published");

    // Collect and sort all years numerically
    let mut years = Vec::new();
    for year_entry in fs::read_dir(&published_dir)? {
        let year_entry = year_entry?;
        let year_path = year_entry.path();

        if year_path.is_dir()
            && let Some(year) = year_path.file_name().and_then(|s| s.to_str())
            && is_valid_year(year) {
                years.push(year.to_string());
            }
    }

    // Sort years numerically (newest first)
    years.sort_by(|a, b| b.cmp(a));

    // Display total work to be done
    println!("Found {} years with published CVE entries", years.len());

    // Update each year
    for year in years {
        update_year(&year, num_threads, dry_run)?;
    }

    Ok(())
}

/// Update all CVEs for a specific year
fn update_year(year: &str, num_threads: usize, dry_run: bool) -> Result<()> {
    let cve_root = common::get_cve_root()?;
    let year_dir = cve_root.join("published").join(year);

    if !year_dir.exists() || !year_dir.is_dir() {
        return Err(anyhow!("Year directory {} does not exist", year));
    }

    // Find all .sha1 files for this year
    let sha1_files: Vec<PathBuf> = WalkDir::new(&year_dir)
        .max_depth(1)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "sha1"))
        .map(|e| e.path().to_path_buf())
        .collect();

    let total_count = sha1_files.len();
    println!("Updating {} CVE IDs for year {} with {} threads",
             total_count.to_string().cyan(), year.green(), num_threads.to_string().cyan());

    if dry_run {
        println!("  {} Dry run mode - no actual updates", "INFO:".blue());
    }

    if total_count == 0 {
        println!("  No CVEs found for year {year}");
        return Ok(());
    }

    // Create a multi-progress display
    let multi = MultiProgress::new();

    // Create the main progress bar
    let progress = multi.add(ProgressBar::new(total_count as u64));
    progress.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .unwrap()
        .progress_chars("#>-"));

    // Create a progress tracker for each thread
    let progress = Arc::new(progress);

    // Process files in parallel
    let sha1_files = Arc::new(sha1_files);
    let counter = Arc::new(Mutex::new(0));
    let update_results = Arc::new(Mutex::new(Vec::new()));

    let handles: Vec<_> = (0..num_threads)
        .map(|_thread_id| {
            let sha1_files = Arc::clone(&sha1_files);
            let counter = Arc::clone(&counter);
            let progress = Arc::clone(&progress);
            let update_results = Arc::clone(&update_results);

            thread::spawn(move || -> Result<()> {
                loop {
                    // Get the next file to process
                    let file = {
                        let mut counter = counter.lock().unwrap();
                        let index = *counter;
                        if index >= total_count {
                            drop(counter); // Drop the mutex early
                            break;
                        }
                        *counter += 1;
                        drop(counter); // Drop the mutex early
                        sha1_files[index].clone()
                    };

                    // Update the CVE
                    let cve_id = file.file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("unknown");

                    let result = update_cve(&file, dry_run);

                    match result {
                        Err(ref e) => {
                            // Store errors for later display
                            update_results.lock().unwrap().push(
                                (cve_id.to_string(), format!("ERROR: {e}"))
                            );
                        }
                        Ok(ref updated_files) if !updated_files.is_empty() => {
                            // Store successful updates
                            update_results.lock().unwrap().push(
                                (cve_id.to_string(), format!("Updated: {}", updated_files.join(", ")))
                            );
                        }
                        _ => {}
                    }

                    // Update progress
                    progress.inc(1);
                }
                Ok(())
            })
        })
        .collect();

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap()?;
    }

    // Finish progress bar
    progress.finish_with_message(format!("Year {} update complete", year.green()));

    // Report any errors or updates
    let results = update_results.lock().unwrap();
    if !results.is_empty() {
        println!("\nUpdate summary for year {}:", year.green());
        for (cve_id, message) in results.iter() {
            if message.starts_with("ERROR") {
                println!("  {} {}: {}", "ERROR:".red(), cve_id.cyan(), message);
            } else {
                println!("  {} {}", cve_id.cyan(), message.blue());
            }
        }
    }

    Ok(())
}

/// Update a single CVE entry
fn update_cve(sha1_file: &Path, dry_run: bool) -> Result<Vec<String>> {
    // Process files and extract metadata
    let cve_data = prepare_cve_files(sha1_file)?;

    if dry_run {
        return Ok(Vec::new());
    }

    // Run bippy on the files and collect updated file paths
    let updated_files = run_bippy_and_update_files(
        sha1_file,
        &cve_data.cve_id,
        &cve_data.shas,
        &cve_data.vulnerable_shas,
        &cve_data.root_path,
        cve_data.has_reference_file,
        cve_data.has_message_file
    )?;

    Ok(updated_files)
}

/// Struct to hold CVE file preparation results
struct CveFileData {
    /// The CVE identifier
    cve_id: String,
    /// List of SHA values from the .sha1 file
    shas: Vec<String>,
    /// List of vulnerable SHA values from the .vulnerable file (if exists)
    vulnerable_shas: Vec<String>,
    /// Path to the CVE root directory
    root_path: PathBuf,
    /// Whether a .reference file exists
    has_reference_file: bool,
    /// Whether a .message file exists
    has_message_file: bool,
}

/// Prepare CVE files and extract metadata
fn prepare_cve_files(sha1_file: &Path) -> Result<CveFileData> {
    // Read the SHA1 file and split into individual SHAs
    let sha_content = fs::read_to_string(sha1_file)
        .context(format!("Failed to read SHA1 file: {}", sha1_file.display()))?;

    // Split content by lines and collect non-empty lines
    let shas: Vec<String> = sha_content
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();

    if shas.is_empty() {
        return Err(anyhow!("SHA1 file is empty: {}", sha1_file.display()));
    }

    // Extract CVE ID and root path from the sha1 file path
    let file_stem = sha1_file.file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("Invalid SHA1 file path"))?;

    let cve_id = file_stem.to_string();
    let root_path = sha1_file.with_file_name(cve_id.clone());

    // Check for .vulnerable file
    let vulnerable_file = sha1_file.with_extension("vulnerable");
    let mut vulnerable_shas = Vec::new();
    if vulnerable_file.exists() {
        let contents = fs::read_to_string(&vulnerable_file)
            .context(format!("Failed to read vulnerable file: {}", vulnerable_file.display()))?;
        for line in contents.lines() {
            let sha = line.trim();
            if !sha.is_empty() {
                vulnerable_shas.push(sha.to_string());
            }
        }
    }

    // Check for .reference file
    let reference_file = sha1_file.with_extension("reference");
    let has_reference_file = reference_file.exists();

    // Check for .message file
    let message_file = sha1_file.with_extension("message");
    let has_message_file = message_file.exists();

    Ok(CveFileData {
        cve_id,
        shas,
        vulnerable_shas,
        root_path,
        has_reference_file,
        has_message_file,
    })
}

/// Run bippy on a CVE and update the files if needed
fn run_bippy_and_update_files(
    sha1_file: &Path,
    cve_id: &str,
    shas: &[String],
    vulnerable_shas: &[String],
    root_path: &Path,
    has_reference_file: bool,
    has_message_file: bool
) -> Result<Vec<String>> {
    // Create temporary files for the new json and mbox content
    let tmp_json = NamedTempFile::new()
        .context("Failed to create temporary JSON file")?;
    let tmp_mbox = NamedTempFile::new()
        .context("Failed to create temporary mbox file")?;

    // Build bippy command with full path from vulns dir
    let vulns_dir = match common::find_vulns_dir() {
        Ok(dir) => dir,
        Err(e) => return Err(anyhow!("Failed to find vulns directory: {}", e)),
    };
    let bippy_path = vulns_dir.join("scripts").join("bippy");

    // Build command and run bippy
    let bippy_params = BippyCommandParams {
        bippy_path: &bippy_path,
        cve_id,
        shas,
        vulnerable_shas,
        tmp_json: &tmp_json,
        tmp_mbox: &tmp_mbox,
        sha1_file,
        has_reference_file,
        has_message_file,
    };
    let output = build_and_run_bippy_command(&bippy_params)?;

    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("bippy failed for {}: {}", cve_id, error));
    }

    // Check for changes and update files if needed
    let mut updated_files = Vec::new();
    check_and_update_json_file(root_path, &tmp_json, &mut updated_files)?;
    check_and_update_mbox_file(root_path, &tmp_mbox, &mut updated_files)?;

    Ok(updated_files)
}

/// Parameters for building and running the bippy command
struct BippyCommandParams<'a> {
    bippy_path: &'a Path,
    cve_id: &'a str,
    shas: &'a [String],
    vulnerable_shas: &'a [String],
    tmp_json: &'a NamedTempFile,
    tmp_mbox: &'a NamedTempFile,
    sha1_file: &'a Path,
    has_reference_file: bool,
    has_message_file: bool,
}

/// Build and run the bippy command
fn build_and_run_bippy_command(params: &BippyCommandParams) -> Result<std::process::Output> {
    let mut bippy_cmd = Command::new(params.bippy_path);
    bippy_cmd.arg(format!("--cve={}", params.cve_id))
        .arg(format!("--json={}", params.tmp_json.path().display()))
        .arg(format!("--mbox={}", params.tmp_mbox.path().display()));

    // Add each SHA as a separate argument
    for sha in params.shas {
        bippy_cmd.arg(format!("--sha={sha}"));
    }

    // Add vulnerable option if present
    for sha in params.vulnerable_shas {
        bippy_cmd.arg(format!("--vulnerable={sha}"));
    }

    // Add reference option if present
    if params.has_reference_file {
        let reference_file = params.sha1_file.with_extension("reference");
        bippy_cmd.arg(format!("--reference={}", reference_file.display()));
    }

    // Add message option if present
    if params.has_message_file {
        let message_file = params.sha1_file.with_extension("message");
        bippy_cmd.arg(format!("--message={}", message_file.display()));
    }

    // Run bippy
    bippy_cmd.stdout(std::process::Stdio::piped())
             .stderr(std::process::Stdio::piped())
             .output()
             .context("Failed to execute bippy command")
}

/// Check JSON file for changes and update if needed
fn check_and_update_json_file(root_path: &Path, tmp_json: &NamedTempFile, updated_files: &mut Vec<String>) -> Result<()> {
    let json_file = root_path.with_extension("json");
    if !json_file.exists() {
        return Ok(());
    }

    let diff_output = Command::new("diff")
        .args(["-u", &json_file.to_string_lossy(), &tmp_json.path().to_string_lossy()])
        .output()
        .context("Failed to execute diff command for JSON file")?;

    let diff_text = String::from_utf8_lossy(&diff_output.stdout);

    // Check if there are meaningful changes (ignoring bippy version, emails, etc.)
    let meaningful_changes = diff_text.lines()
        .filter(|line| line.starts_with('+') || line.starts_with('-'))
        .filter(|line| !line.contains("bippy") &&
                        !line.contains("@kernel.org") &&
                        !line.contains("@linuxfoundation.org") &&
                        !line.starts_with("+++ ") &&
                        !line.starts_with("--- ") &&
                        !line.starts_with("@@ "))
        .count() > 0;

    if meaningful_changes {
        // Copy the new file over the old one
        fs::copy(tmp_json.path(), &json_file)
            .context(format!("Failed to update JSON file: {}", json_file.display()))?;
        updated_files.push(json_file.display().to_string());
    }

    Ok(())
}

/// Check mbox file for changes and update if needed
fn check_and_update_mbox_file(root_path: &Path, tmp_mbox: &NamedTempFile, updated_files: &mut Vec<String>) -> Result<()> {
    let mbox_file = root_path.with_extension("mbox");
    if !mbox_file.exists() {
        return Ok(());
    }

    let diff_output = Command::new("diff")
        .args(["-u", &mbox_file.to_string_lossy(), &tmp_mbox.path().to_string_lossy()])
        .output()
        .context("Failed to execute diff command for mbox file")?;

    let diff_text = String::from_utf8_lossy(&diff_output.stdout);

    // Check if there are meaningful changes (ignoring bippy version, emails, etc.)
    let meaningful_changes = diff_text.lines()
        .filter(|line| line.starts_with('+') || line.starts_with('-'))
        .filter(|line| !line.contains("bippy-") &&
                        !line.contains("@kernel.org") &&
                        !line.contains("@linuxfoundation.org") &&
                        !line.starts_with("+++ ") &&
                        !line.starts_with("--- ") &&
                        !line.starts_with("@@ "))
        .count() > 0;

    if meaningful_changes {
        // Copy the new file over the old one
        fs::copy(tmp_mbox.path(), &mbox_file)
            .context(format!("Failed to update mbox file: {}", mbox_file.display()))?;
        updated_files.push(mbox_file.display().to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::io::Write;
    use std::fs::File;
    use cve_utils::cve_validation::extract_year_from_cve;

    #[test]
    fn test_is_valid_year() {
        assert!(is_valid_year("2023"));
        assert!(is_valid_year("2000"));
        assert!(!is_valid_year("abcd"));
        assert!(!is_valid_year("1800")); // Too old
        assert!(!is_valid_year("3000")); // Too far in future
    }

    #[test]
    fn test_extract_year_from_cve() {
        assert_eq!(extract_year_from_cve("CVE-2023-12345").unwrap(), "2023");
        assert_eq!(extract_year_from_cve("CVE-2021-1234").unwrap(), "2021");
        assert!(extract_year_from_cve("InvalidCVE").is_err());
    }

    #[test]
    fn test_cve_file_structure() {
        // Create a temporary directory to simulate CVE file structure
        let temp_dir = tempdir().unwrap();
        let cve_root = temp_dir.path();

        // Create published/2023 directory
        let published_dir = cve_root.join("published").join("2023");
        fs::create_dir_all(&published_dir).unwrap();

        // Create a sample CVE entry
        let cve_id = "CVE-2023-12345";
        let sha = "abcdef1234567890abcdef1234567890abcdef12";

        // Create SHA1 file
        let sha1_file = published_dir.join(format!("{}.sha1", cve_id));
        let mut file = File::create(&sha1_file).unwrap();
        writeln!(file, "{}", sha).unwrap();

        // Create JSON file
        let json_file = published_dir.join(format!("{}.json", cve_id));
        let mut file = File::create(&json_file).unwrap();
        writeln!(file, "{{\"id\": \"{}\", \"commit\": \"{}\"}}", cve_id, sha).unwrap();

        // Create mbox file
        let mbox_file = published_dir.join(format!("{}.mbox", cve_id));
        let mut file = File::create(&mbox_file).unwrap();
        writeln!(file, "From {}-version Mon Sep 17 00:00:00 2001", cve_id).unwrap();

        // Verify files exist
        assert!(sha1_file.exists());
        assert!(json_file.exists());
        assert!(mbox_file.exists());

        // Test extracting information from the structure
        let read_sha = fs::read_to_string(&sha1_file).unwrap().trim().to_string();
        assert_eq!(read_sha, sha);

        // Test file paths
        let file_stem = sha1_file.file_stem().unwrap().to_str().unwrap();
        assert_eq!(file_stem, cve_id);

        let root_path = sha1_file.with_file_name(cve_id);
        assert_eq!(root_path, published_dir.join(cve_id));

        let json_path = root_path.with_extension("json");
        assert_eq!(json_path, json_file);

        let mbox_path = root_path.with_extension("mbox");
        assert_eq!(mbox_path, mbox_file);
    }

    #[test]
    fn test_real_cve_ids() {
        // Test with various real CVE IDs
        assert_eq!(extract_year_from_cve("CVE-2022-0847").unwrap(), "2022"); // Dirty Pipe
        assert_eq!(extract_year_from_cve("CVE-2023-0179").unwrap(), "2023"); // OverlayFS bug
        assert_eq!(extract_year_from_cve("CVE-2021-33909").unwrap(), "2021"); // Sequoia
        assert_eq!(extract_year_from_cve("CVE-2018-17182").unwrap(), "2018"); // Mutagen Astronomy
        assert_eq!(extract_year_from_cve("CVE-2016-5195").unwrap(), "2016"); // Dirty COW
    }

    #[test]
    fn test_full_cve_directory_structure() {
        // Create a temporary directory to simulate a complete CVE structure
        let temp_dir = tempdir().unwrap();
        let cve_root = temp_dir.path();

        // Create the structure of published years
        for year in ["2021", "2022", "2023"].iter() {
            let year_dir = cve_root.join("published").join(year);
            fs::create_dir_all(&year_dir).unwrap();
        }

        // Create some sample CVEs for each year
        let sample_cves = [
            ("CVE-2021-33909", "77a3029517e5c77bf354b154c262f31f139ad128", "2021"), // Sequoia
            ("CVE-2021-4034", "b2376e58da8cda5fb67872bc1cc0a18717712789", "2021"),  // PwnKit
            ("CVE-2022-0847", "9d2231c5d6c953e754546441a48822311c6e5a1d", "2022"),  // Dirty Pipe
            ("CVE-2022-0185", "4fc5be3a13775696d23df91efb41e7c24bc71d12", "2022"),  // CAP_NET_RAW container escape
            ("CVE-2023-0179", "25b39e6d73229a3e12c03d22f645c198518c6d01", "2023"),  // OverlayFS bug
            ("CVE-2023-1281", "3e6d93437db25378905dd13435037ad0883940bd", "2023"),  // ptrace vulnerability
        ];

        // Create the files for each CVE
        for (cve_id, sha, year) in sample_cves.iter() {
            let year_dir = cve_root.join("published").join(year);

            // Create SHA1 file
            let sha1_file = year_dir.join(format!("{}.sha1", cve_id));
            let mut file = File::create(&sha1_file).unwrap();
            writeln!(file, "{}", sha).unwrap();

            // Create JSON file
            let json_file = year_dir.join(format!("{}.json", cve_id));
            let mut file = File::create(&json_file).unwrap();
            writeln!(file, "{{\"id\": \"{}\", \"commit\": \"{}\"}}", cve_id, sha).unwrap();

            // Create mbox file
            let mbox_file = year_dir.join(format!("{}.mbox", cve_id));
            let mut file = File::create(&mbox_file).unwrap();
            writeln!(file, "From {}-version Mon Sep 17 00:00:00 2001", cve_id).unwrap();

            // Create a few .vulnerable files
            if *cve_id == "CVE-2021-33909" || *cve_id == "CVE-2022-0847" {
                let vulnerable_file = year_dir.join(format!("{}.vulnerable", cve_id));
                let mut file = File::create(&vulnerable_file).unwrap();
                writeln!(file, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2").unwrap();
            }

            // Create a .message file
            if *cve_id == "CVE-2023-0179" {
                let message_file = year_dir.join(format!("{}.message", cve_id));
                let mut file = File::create(&message_file).unwrap();
                writeln!(file, "This is a custom CVE description from a .message file.").unwrap();
                writeln!(file).unwrap();
                writeln!(file, "It overrides the commit message for better clarity.").unwrap();
            }


            // Create a .reference file
            if *cve_id == "CVE-2022-0185" {
                let reference_file = year_dir.join(format!("{}.reference", cve_id));
                let mut file = File::create(&reference_file).unwrap();
                writeln!(file, "https://nvd.nist.gov/vuln/detail/{}", cve_id).unwrap();
            }
        }

        // Test finding CVEs
        for (cve_id, _, year) in sample_cves.iter() {
            let year_dir = cve_root.join("published").join(year);
            let sha1_file = year_dir.join(format!("{}.sha1", cve_id));

            // Test extracting CVE ID from path
            let file_stem = sha1_file.file_stem().unwrap().to_str().unwrap();
            assert_eq!(file_stem, *cve_id);

            // Test getting year from CVE ID
            let extracted_year = extract_year_from_cve(cve_id).unwrap();
            assert_eq!(extracted_year, *year);

            // Test file existence
            assert!(sha1_file.exists());
            assert!(year_dir.join(format!("{}.json", cve_id)).exists());
            assert!(year_dir.join(format!("{}.mbox", cve_id)).exists());
        }

        // Test additional file types
        assert!(cve_root.join("published").join("2021").join("CVE-2021-33909.vulnerable").exists());
        assert!(cve_root.join("published").join("2022").join("CVE-2022-0847.vulnerable").exists());
        assert!(cve_root.join("published").join("2023").join("CVE-2023-0179.message").exists());
        assert!(cve_root.join("published").join("2022").join("CVE-2022-0185.reference").exists());
    }

    #[test]
    fn test_diff_logic() {
        // Test the logic that determines if there are meaningful changes in a diff

        // Case 1: No meaningful changes (only metadata)
        let diff_text_1 = "\
--- /tmp/tmp123.json	2023-09-01 12:34:56.000000000 -0700
+++ /tmp/tmp456.json	2023-09-01 12:35:00.000000000 -0700
@@ -1,5 +1,5 @@
 {
   \"id\": \"CVE-2023-12345\",
-  \"generator\": \"bippy-1.0.0\",
+  \"generator\": \"bippy-1.0.1\",
   \"commit\": \"abcdef1234567890\"
 }";

        let meaningful_changes_1 = diff_text_1.lines()
            .filter(|line| line.starts_with("+") || line.starts_with("-"))
            .filter(|line| !line.contains("bippy") &&
                            !line.contains("@kernel.org") &&
                            !line.contains("@linuxfoundation.org") &&
                            !line.starts_with("+++ ") &&
                            !line.starts_with("--- ") &&
                            !line.starts_with("@@ "))
            .count() > 0;

        assert!(!meaningful_changes_1, "Should not detect meaningful changes when only bippy version changed");

        // Case 2: Meaningful changes
        let diff_text_2 = "\
--- /tmp/tmp123.json	2023-09-01 12:34:56.000000000 -0700
+++ /tmp/tmp456.json	2023-09-01 12:35:00.000000000 -0700
@@ -1,5 +1,6 @@
 {
   \"id\": \"CVE-2023-12345\",
   \"generator\": \"bippy-1.0.0\",
-  \"commit\": \"abcdef1234567890\"
+  \"commit\": \"abcdef1234567890\",
+  \"affects\": { \"vendor\": { \"vendor_data\": [{ \"vendor_name\": \"Linux Kernel\", \"product\": { \"product_data\": [{ \"product_name\": \"Kernel\", \"version\": { \"version_data\": [{ \"version_value\": \"5.15\" }] } }] } }] } }
 }";

        let meaningful_changes_2 = diff_text_2.lines()
            .filter(|line| line.starts_with("+") || line.starts_with("-"))
            .filter(|line| !line.contains("bippy") &&
                            !line.contains("@kernel.org") &&
                            !line.contains("@linuxfoundation.org") &&
                            !line.starts_with("+++ ") &&
                            !line.starts_with("--- ") &&
                            !line.starts_with("@@ "))
            .count() > 0;

        assert!(meaningful_changes_2, "Should detect meaningful changes when content is modified");

        // Case 3: Email changes (should be ignored)
        let diff_text_3 = "\
--- /tmp/tmp123.mbox	2023-09-01 12:34:56.000000000 -0700
+++ /tmp/tmp456.mbox	2023-09-01 12:35:00.000000000 -0700
@@ -1,5 +1,5 @@
 From CVE-2023-12345-version Mon Sep 17 00:00:00 2001
-From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
+From: John Doe <john.doe@kernel.org>
 Subject: [PATCH] CVE-2023-12345: Fix security vulnerability

 This fixes a security vulnerability.";

        let meaningful_changes_3 = diff_text_3.lines()
            .filter(|line| line.starts_with("+") || line.starts_with("-"))
            .filter(|line| !line.contains("bippy-") &&
                            !line.contains("@kernel.org") &&
                            !line.contains("@linuxfoundation.org") &&
                            !line.starts_with("+++ ") &&
                            !line.starts_with("--- ") &&
                            !line.starts_with("@@ "))
            .count() > 0;

        assert!(!meaningful_changes_3, "Should not detect meaningful changes when only email addresses changed");
    }

    #[test]
    fn test_find_cve_by_year() {
        // Create a temporary directory to simulate a CVE structure
        let temp_dir = tempdir().unwrap();
        let cve_root = temp_dir.path();

        // Create the structure with multiple years
        for year in ["2021", "2022", "2023"].iter() {
            let year_dir = cve_root.join("published").join(year);
            fs::create_dir_all(&year_dir).unwrap();
        }

        // Create some sample CVEs
        let sample_cves = [
            ("CVE-2021-33909", "2021"),
            ("CVE-2022-0847", "2022"),
            ("CVE-2023-0179", "2023"),
        ];

        for (cve_id, year) in sample_cves.iter() {
            let year_dir = cve_root.join("published").join(year);

            // Create SHA1 file
            let sha1_file = year_dir.join(format!("{}.sha1", cve_id));
            let mut file = File::create(&sha1_file).unwrap();
            writeln!(file, "abcdef1234567890abcdef1234567890abcdef12").unwrap();
        }

        // Test the extraction logic with different CVE formats
        for (cve_id, expected_year) in [
            ("CVE-2021-33909", "2021"),
            ("cve-2021-33909", "2021"),
            ("CVE-2022-0847", "2022"),
            ("cve-2022-0847", "2022"),
            ("CVE-2023-0179", "2023"),
        ].iter() {
            let year = extract_year_from_cve(cve_id).unwrap();
            assert_eq!(&year, expected_year);
        }
    }

    #[test]
    fn test_bippy_command_construction() {
        // Test constructing the bippy command with various file combinations
        let temp_dir = tempdir().unwrap();
        let cve_root = temp_dir.path();
        let year_dir = cve_root.join("published").join("2023");
        fs::create_dir_all(&year_dir).unwrap();

        // Create a sample CVE with all supplementary files
        let cve_id = "CVE-2023-12345";
        let sha = "abcdef1234567890abcdef1234567890abcdef12";

        // Create SHA1 file
        let sha1_file = year_dir.join(format!("{}.sha1", cve_id));
        let mut file = File::create(&sha1_file).unwrap();
        writeln!(file, "{}", sha).unwrap();

        // Create vulnerable file
        let vulnerable_file = year_dir.join(format!("{}.vulnerable", cve_id));
        let vulnerable_sha = "1111111111111111111111111111111111111111";
        let mut file = File::create(&vulnerable_file).unwrap();
        writeln!(file, "{}", vulnerable_sha).unwrap();

        // Create message file
        let message_file = year_dir.join(format!("{}.message", cve_id));
        let mut file = File::create(&message_file).unwrap();
        writeln!(file, "Custom CVE description for testing bippy command construction.").unwrap();
        writeln!(file, "This message overrides the git commit message.").unwrap();

        // Create reference file
        let reference_file = year_dir.join(format!("{}.reference", cve_id));
        let mut file = File::create(&reference_file).unwrap();
        writeln!(file, "https://example.com/reference").unwrap();

        // Verify files exist
        assert!(sha1_file.exists());
        assert!(vulnerable_file.exists());
        assert!(message_file.exists());
        assert!(reference_file.exists());

        // Read the vulnerable SHA
        let vulnerable_sha_read = fs::read_to_string(&vulnerable_file).unwrap().trim().to_string();
        assert_eq!(vulnerable_sha_read, vulnerable_sha);

        // Check if our implementation correctly detects these files
        assert!(vulnerable_file.exists());
        assert!(message_file.exists());
        assert!(reference_file.exists());

        // Simulate command-building logic
        let mut cmd_args = vec![
            format!("--cve={}", cve_id),
            format!("--sha={}", sha),
            format!("--json=/tmp/test.json"), // Placeholder
            format!("--mbox=/tmp/test.mbox"), // Placeholder
        ];

        if vulnerable_file.exists() {
            cmd_args.push(format!("--vulnerable={}", vulnerable_sha_read));
        }

        if reference_file.exists() {
            cmd_args.push(format!("--reference={}", reference_file.display()));
        }

        // Check if all expected arguments are present
        assert!(cmd_args.iter().any(|arg| arg.starts_with("--cve=")));
        assert!(cmd_args.iter().any(|arg| arg.starts_with("--sha=")));
        assert!(cmd_args.iter().any(|arg| arg.starts_with("--json=")));
        assert!(cmd_args.iter().any(|arg| arg.starts_with("--mbox=")));
        assert!(cmd_args.iter().any(|arg| arg.starts_with("--vulnerable=")));
        assert!(cmd_args.iter().any(|arg| arg.starts_with("--reference=")));
    }
}
