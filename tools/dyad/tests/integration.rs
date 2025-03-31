// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use std::process::Command;
use std::path::{Path, PathBuf};
use std::env;
use std::sync::{Arc, Mutex};
use rayon::prelude::*;
use indicatif::{ProgressBar, ProgressStyle};

/// Integration test that verifies dyad doesn't introduce unexpected changes
///
/// This test:
/// 1. Only runs when explicitly requested with `cargo test -- --ignored --test integration`
/// 2. Skips if the CVE directory has uncommitted changes (unless forced)
/// 3. Fails if running dyad causes any changes to CVE files
/// 4. Cleans up by resetting git state in the CVE directory
#[test]
#[ignore]
fn test_dyad_consistency() {
    // Skip this test unless explicitly enabled
    if env::var("RUN_INTEGRATION_TESTS").is_err() {
        println!("Skipping integration test - set RUN_INTEGRATION_TESTS=1 to enable");
        return;
    }

    let force_run = env::var("FORCE_INTEGRATION_TEST").is_ok();
    let limit_tests = env::var("LIMIT_TEST_CASES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0); // 0 means no limit

    // Find and validate the CVE directory
    let cve_dir = match find_cve_dir() {
        Ok(dir) => dir,
        Err(err) => panic!("Failed to find CVE directory: {}", err),
    };
    println!("Running integration test in CVE directory: {}", cve_dir.display());

    // Check if Git repo is clean
    if !is_git_clean(&cve_dir) && !force_run {
        println!("CVE directory has uncommitted changes. To run anyway, set FORCE_INTEGRATION_TEST=1");
        return;
    }

    // Collect and prepare test cases
    let mut test_cases = get_test_cases(&cve_dir);
    if test_cases.is_empty() {
        panic!("No test cases found");
    }

    // Limit test cases if requested
    if limit_tests > 0 && test_cases.len() > limit_tests {
        println!("Limiting test to {} cases (out of {})", limit_tests, test_cases.len());
        test_cases.truncate(limit_tests);
    }
    println!("Found {} test cases", test_cases.len());

    // Prepare for testing
    let original_state = capture_git_state(&cve_dir);
    let failed_cases = Arc::new(Mutex::new(Vec::new()));
    let cve_dir = Arc::new(cve_dir);

    // Setup progress bar
    let pb = ProgressBar::new(test_cases.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta})")
        .unwrap()
        .progress_chars("#>-"));

    // Run tests in parallel
    test_cases.par_iter().for_each(|(cve_id, git_sha)| {
        let result = run_test_case(git_sha, &cve_dir);

        if !result.success {
            let mut failures = failed_cases.lock().unwrap();
            failures.push((cve_id.clone(), git_sha.clone(), result.error_message));
        }

        pb.inc(1);
    });

    pb.finish_with_message("Testing complete");

    // Always restore original git state
    restore_git_state(&cve_dir, &original_state);

    // Report results
    let failed_cases = failed_cases.lock().unwrap();
    if !failed_cases.is_empty() {
        println!("\n⚠️ Test failures detected:");
        for (cve_id, git_sha, error) in failed_cases.iter() {
            println!("❌ Failed: CVE {}, SHA: {}", cve_id, git_sha);
            if !error.is_empty() {
                println!("   Error: {}", error);
            }
        }

        panic!(
            "Integration test failed for {} cases. See details above.",
            failed_cases.len()
        );
    }

    println!("\n✅ All integration tests passed successfully");
}

/// Result of running a test case
struct TestResult {
    success: bool,
    error_message: String,
}

/// Run a single test case and check for changes
fn run_test_case(git_sha: &str, cve_dir: &Arc<PathBuf>) -> TestResult {
    // Find the dyad binary
    let dyad_path = match find_dyad_binary() {
        Some(path) => path,
        None => return TestResult {
            success: false,
            error_message: "Failed to find dyad binary".to_string(),
        },
    };

    // Run dyad with the git SHA
    let dyad_result = Command::new(&dyad_path)
        .arg(git_sha)
        .output();

    match dyad_result {
        Ok(_) => {
            // Check if any files changed
            if !is_git_clean(cve_dir) {
                // Capture the diff for error reporting
                let diff = match Command::new("git")
                    .args(["diff", cve_dir.to_str().unwrap_or(".")])
                    .output()
                {
                    Ok(output) => String::from_utf8_lossy(&output.stdout).to_string(),
                    Err(_) => "Unable to capture diff".to_string(),
                };

                // Reset git state after checking
                reset_git_state(cve_dir);

                TestResult {
                    success: false,
                    error_message: format!("Files were modified: {}", diff),
                }
            } else {
                TestResult {
                    success: true,
                    error_message: String::new(),
                }
            }
        },
        Err(err) => {
            // Reset git state after failure
            reset_git_state(cve_dir);

            TestResult {
                success: false,
                error_message: format!("Failed to execute dyad: {}", err),
            }
        }
    }
}

/// Find the CVE directory using cve_utils
fn find_cve_dir() -> Result<PathBuf, String> {
    match cve_utils::common::find_vulns_dir() {
        Ok(vulns_dir) => {
            let cve_dir = vulns_dir.join("cve");
            if cve_dir.exists() {
                return Ok(cve_dir);
            }
            Err(format!("CVE directory not found at: {}", cve_dir.display()))
        },
        Err(e) => Err(format!("Failed to find vulns directory: {}", e))
    }
}

/// Check if the git repository is in a clean state for the specific directory
fn is_git_clean(dir: &Path) -> bool {
    match Command::new("git")
        .args(["status", "--porcelain", dir.to_str().unwrap_or(".")])
        .output()
    {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout.trim().is_empty()
        },
        _ => false,
    }
}

/// Capture the current git state (to be used for restoring later)
fn capture_git_state(dir: &Path) -> String {
    match Command::new("git")
        .current_dir(dir)
        .args(["rev-parse", "HEAD"])
        .output()
    {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        },
        _ => "unknown".to_string(),
    }
}

/// Reset the git state to discard changes in the specified directory
fn reset_git_state(dir: &Path) {
    let dir_path = dir.to_str().unwrap_or(".");
    let _ = Command::new("git")
        .args(["checkout", "--", dir_path])
        .output();

    let _ = Command::new("git")
        .args(["clean", "-fd", dir_path])
        .output();
}

/// Restore git to a specific state for the directory
fn restore_git_state(dir: &Path, commit_hash: &str) {
    if commit_hash == "unknown" {
        return;
    }

    let _ = Command::new("git")
        .args(["checkout", commit_hash, "--", dir.to_str().unwrap_or(".")])
        .output();
}

/// Get a list of test cases (CVE ID and git SHA pairs)
fn get_test_cases(cve_dir: &Path) -> Vec<(String, String)> {
    let mut test_cases = Vec::new();
    let published_dir = cve_dir.join("published");

    if !published_dir.exists() {
        return test_cases;
    }

    // Process all years in the published directory
    if let Ok(year_entries) = std::fs::read_dir(&published_dir) {
        for year_entry in year_entries.filter_map(Result::ok) {
            let year_path = year_entry.path();

            // Skip non-directory entries and hidden files
            if !year_path.is_dir() || year_entry.file_name().to_string_lossy().starts_with('.') {
                continue;
            }

            // Process all CVEs in this year
            if let Ok(cve_entries) = std::fs::read_dir(&year_path) {
                for cve_entry in cve_entries.filter_map(Result::ok) {
                    let path = cve_entry.path();

                    // Only process .sha1 files
                    if path.extension().map_or(false, |ext| ext == "sha1") {
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            if let Some(cve_id) = path.file_stem().and_then(|s| s.to_str()) {
                                let git_sha = content.trim().to_string();
                                test_cases.push((cve_id.to_string(), git_sha));
                            }
                        }
                    }
                }
            }
        }
    }

    test_cases
}

/// Find the dyad binary
fn find_dyad_binary() -> Option<PathBuf> {
    // First check if we can build it using cargo
    if let Ok(output) = Command::new("cargo")
        .args(["build", "--bin", "dyad"])
        .output()
    {
        if output.status.success() {
            // Get the path from Cargo's output
            let target_dir = env::var("CARGO_TARGET_DIR")
                .unwrap_or_else(|_| "target".to_string());

            let dyad_path = PathBuf::from(target_dir)
                .join("debug")
                .join("dyad");

            if dyad_path.exists() {
                return Some(dyad_path);
            }
        }
    }

    // Try to find it in PATH
    if let Ok(output) = Command::new("which").arg("dyad").output() {
        if output.status.success() {
            let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            return Some(PathBuf::from(path_str));
        }
    }

    None
}
