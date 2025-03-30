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
use colored::Colorize;

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
            eprintln!("Error: {}", e);
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
                if let Err(e) = update_cve(&cve_id, "[1/1]", args.dry_run) {
                    eprintln!("Error updating {}: {}", cve_id_str.cyan(), e);
                    print_git_error_details(&e);
                    return Err(e);
                }
            }
            // Check if target is a year
            Ok(None) if is_valid_year(target) && is_year_dir_exists(&cve_root, target).unwrap_or(false) => {
                if let Err(e) = update_year(target, num_threads, args.dry_run) {
                    eprintln!("Error updating year {}: {}", target, e);
                    print_git_error_details(&e);
                    return Err(e);
                }
            }
            Ok(_) => {
                return Err(anyhow!("{} is not a valid CVE ID or year with published entries", target));
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                print_git_error_details(&e);
                return Err(e);
            }
        }
    } else {
        // No target specified, update all years
        println!("Updating all published CVE entries");
        if let Err(e) = update_all_years(&cve_root, num_threads, args.dry_run) {
            eprintln!("Error updating all years: {}", e);
            print_git_error_details(&e);
            return Err(e);
        }
    }

    Ok(())
}

/// Update all years with published CVEs
fn update_all_years(cve_root: &Path, num_threads: usize, dry_run: bool) -> Result<()> {
    let published_dir = cve_root.join("published");

    for year_entry in fs::read_dir(&published_dir)? {
        let year_entry = year_entry?;
        let year_path = year_entry.path();

        if year_path.is_dir() {
            let year = year_path.file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| anyhow!("Invalid year directory name"))?;

            update_year(year, num_threads, dry_run)?;
        }
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
        .filter_map(|e| e.ok())
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
        println!("  No CVEs found for year {}", year);
        return Ok(());
    }

    // Process files in parallel
    let sha1_files = Arc::new(sha1_files);
    let counter = Arc::new(Mutex::new(0));
    let handles: Vec<_> = (0..num_threads)
        .map(|_thread_id| {
            let sha1_files = Arc::clone(&sha1_files);
            let counter = Arc::clone(&counter);

            thread::spawn(move || -> Result<()> {
                loop {
                    // Get the next file to process
                    let (index, file) = {
                        let mut counter = counter.lock().unwrap();
                        let index = *counter;
                        if index >= total_count {
                            break;
                        }
                        *counter += 1;
                        (index, sha1_files[index].clone())
                    };

                    // Format the counter string
                    let count_string = format!("[{:04}/{:04}]", index + 1, total_count);

                    // Update the CVE
                    if let Err(e) = update_cve(&file, &count_string, dry_run) {
                        eprintln!("  {} Failed to update {}: {}",
                                 "ERROR:".red(), file.display(), e);
                    }
                }
                Ok(())
            })
        })
        .collect();

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap()?;
    }

    Ok(())
}

/// Update a single CVE entry
fn update_cve(sha1_file: &Path, count_string: &str, dry_run: bool) -> Result<()> {
    // Read the commit SHA
    let sha = fs::read_to_string(sha1_file)
        .context(format!("Failed to read SHA1 file: {}", sha1_file.display()))?
        .trim()
        .to_string();

    // Extract CVE ID and root path from the sha1 file path
    let file_stem = sha1_file.file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("Invalid SHA1 file path"))?;

    let cve_id = file_stem.to_string();
    let root_path = sha1_file.with_file_name(cve_id.clone());

    let mut message = format!("Updating {} {}...", cve_id.cyan(), count_string.yellow());

    // Check for .vulnerable file
    let vulnerable_file = sha1_file.with_extension("vulnerable");
    let vulnerable_sha = if vulnerable_file.exists() {
        Some(fs::read_to_string(&vulnerable_file)
            .context(format!("Failed to read vulnerable file: {}", vulnerable_file.display()))?
            .trim()
            .to_string())
    } else {
        None
    };

    // Check for .diff file
    let diff_file = sha1_file.with_extension("diff");
    let has_diff_file = diff_file.exists();

    // Check for .reference file
    let reference_file = sha1_file.with_extension("reference");
    let has_reference_file = reference_file.exists();

    if dry_run {
        println!("{}\t{}", message, "DRY RUN".blue());
        return Ok(());
    }

    // Create temporary files for the new json and mbox content
    let tmp_json = NamedTempFile::new()
        .context("Failed to create temporary JSON file")?;
    let tmp_mbox = NamedTempFile::new()
        .context("Failed to create temporary mbox file")?;

    // Build bippy command
    let mut bippy_cmd = Command::new("bippy");
    bippy_cmd.arg(format!("--cve={}", cve_id))
        .arg(format!("--sha={}", sha))
        .arg(format!("--json={}", tmp_json.path().display()))
        .arg(format!("--mbox={}", tmp_mbox.path().display()));

    // Add vulnerable option if present
    if let Some(vuln_sha) = &vulnerable_sha {
        bippy_cmd.arg(format!("--vulnerable={}", vuln_sha));
    }

    // Add diff option if present
    if has_diff_file {
        bippy_cmd.arg(format!("--diff={}", diff_file.display()));
    }

    // Add reference option if present
    if has_reference_file {
        bippy_cmd.arg(format!("--reference={}", reference_file.display()));
    }

    // Run bippy
    let status = bippy_cmd.status()
        .context("Failed to execute bippy command")?;

    if !status.success() {
        message.push_str(&format!("\t{} bippy failed", "ERROR:".red()));
        println!("{}", message);
        return Err(anyhow!("bippy failed for {}", cve_id));
    }

    // Check if files have changed
    let mut updated_files = Vec::new();

    // Check JSON file
    let json_file = root_path.with_extension("json");
    if json_file.exists() {
        let diff_output = Command::new("diff")
            .args(["-u", &json_file.to_string_lossy(), &tmp_json.path().to_string_lossy()])
            .output()
            .context("Failed to execute diff command for JSON file")?;

        let diff_text = String::from_utf8_lossy(&diff_output.stdout);

        // Check if there are meaningful changes (ignoring bippy version, emails, etc.)
        let meaningful_changes = diff_text.lines()
            .filter(|line| line.starts_with("+") || line.starts_with("-"))
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
    }

    // Check mbox file
    let mbox_file = root_path.with_extension("mbox");
    if mbox_file.exists() {
        let diff_output = Command::new("diff")
            .args(["-u", &mbox_file.to_string_lossy(), &tmp_mbox.path().to_string_lossy()])
            .output()
            .context("Failed to execute diff command for mbox file")?;

        let diff_text = String::from_utf8_lossy(&diff_output.stdout);

        // Check if there are meaningful changes (ignoring bippy version, emails, etc.)
        let meaningful_changes = diff_text.lines()
            .filter(|line| line.starts_with("+") || line.starts_with("-"))
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
    }

    // Report the update status
    if updated_files.is_empty() {
        message.push_str(&format!("\t{}", "Nothing changed".green()));
    } else {
        message.push_str(&format!("\tUpdated {}", updated_files.join(", ").blue()));
    }

    println!("{}", message);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cve_utils::cve_validation::extract_year_from_cve;
    use tempfile::tempdir;
    use std::fs::File;
    use std::io::Write;

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
        assert_eq!(extract_year_from_cve("CVE-2023-12345"), Some("2023".to_string()));
        assert_eq!(extract_year_from_cve("CVE-2021-1234"), Some("2021".to_string()));
        assert_eq!(extract_year_from_cve("InvalidCVE"), None);
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
        assert_eq!(extract_year_from_cve("CVE-2022-0847"), Some("2022".to_string())); // Dirty Pipe
        assert_eq!(extract_year_from_cve("CVE-2023-0179"), Some("2023".to_string())); // OverlayFS bug
        assert_eq!(extract_year_from_cve("CVE-2021-33909"), Some("2021".to_string())); // Sequoia
        assert_eq!(extract_year_from_cve("CVE-2018-17182"), Some("2018".to_string())); // Mutagen Astronomy
        assert_eq!(extract_year_from_cve("CVE-2016-5195"), Some("2016".to_string())); // Dirty COW
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

            // Create a .diff file
            if *cve_id == "CVE-2023-0179" {
                let diff_file = year_dir.join(format!("{}.diff", cve_id));
                let mut file = File::create(&diff_file).unwrap();
                writeln!(file, "diff --git a/file.c b/file.c").unwrap();
                writeln!(file, "--- a/file.c").unwrap();
                writeln!(file, "+++ b/file.c").unwrap();
                writeln!(file, "@@ -10,7 +10,7 @@").unwrap();
                writeln!(file, " context line").unwrap();
                writeln!(file, "-removed line").unwrap();
                writeln!(file, "+added line").unwrap();
                writeln!(file, " context line").unwrap();
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
        assert!(cve_root.join("published").join("2023").join("CVE-2023-0179.diff").exists());
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

        // Create diff file
        let diff_file = year_dir.join(format!("{}.diff", cve_id));
        let mut file = File::create(&diff_file).unwrap();
        writeln!(file, "diff --git a/file.c b/file.c").unwrap();

        // Create reference file
        let reference_file = year_dir.join(format!("{}.reference", cve_id));
        let mut file = File::create(&reference_file).unwrap();
        writeln!(file, "https://example.com/reference").unwrap();

        // Verify files exist
        assert!(sha1_file.exists());
        assert!(vulnerable_file.exists());
        assert!(diff_file.exists());
        assert!(reference_file.exists());

        // Read the vulnerable SHA
        let vulnerable_sha_read = fs::read_to_string(&vulnerable_file).unwrap().trim().to_string();
        assert_eq!(vulnerable_sha_read, vulnerable_sha);

        // Check if our implementation correctly detects these files
        assert!(vulnerable_file.exists());
        assert!(diff_file.exists());
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

        if diff_file.exists() {
            cmd_args.push(format!("--diff={}", diff_file.display()));
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
        assert!(cmd_args.iter().any(|arg| arg.starts_with("--diff=")));
        assert!(cmd_args.iter().any(|arg| arg.starts_with("--reference=")));
    }
}