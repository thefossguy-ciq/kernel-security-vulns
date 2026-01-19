// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

/// Integration test that verifies dyad produces expected output
///
/// This test:
/// 1. Only runs when explicitly requested with `cargo test -- --ignored --test integration`
/// 2. Runs dyad with sha1 and vulnerable file content (if it exists)
/// 3. Compares the output with existing .dyad files, skipping lines starting with "#"
/// 4. Fails if there are differences
#[test]
#[ignore]
fn test_dyad_consistency() {
    // Skip this test unless explicitly enabled
    if env::var("RUN_INTEGRATION_TESTS").is_err() {
        println!("Skipping integration test - set RUN_INTEGRATION_TESTS=1 to enable");
        return;
    }

    let limit_tests = env::var("LIMIT_TEST_CASES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0); // 0 means no limit

    // Find and validate the CVE directory
    let cve_dir = match find_cve_dir() {
        Ok(dir) => dir,
        Err(err) => panic!("Failed to find CVE directory: {}", err),
    };
    println!(
        "Running integration test in CVE directory: {}",
        cve_dir.display()
    );

    // Collect and prepare test cases
    let mut test_cases = get_test_cases(&cve_dir);
    if test_cases.is_empty() {
        panic!("No test cases found");
    }

    // Limit test cases if requested
    if limit_tests > 0 && test_cases.len() > limit_tests {
        println!(
            "Limiting test to {} cases (out of {})",
            limit_tests,
            test_cases.len()
        );
        test_cases.truncate(limit_tests);
    }
    println!("Found {} test cases", test_cases.len());

    // Prepare for testing
    let failed_cases = Arc::new(Mutex::new(Vec::new()));

    // Setup progress bar
    let pb = ProgressBar::new(test_cases.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .progress_chars("#>-"),
    );

    // Run tests in parallel
    test_cases.par_iter().for_each(|test_case| {
        let result = run_test_case(test_case);

        if !result.success {
            let mut failures = failed_cases.lock().unwrap();
            failures.push((test_case.cve_id.clone(), result.error_message));
        }

        pb.inc(1);
    });

    pb.finish_with_message("Testing complete");

    // Report results
    let failed_cases = failed_cases.lock().unwrap();
    if !failed_cases.is_empty() {
        println!("\n⚠️ Test failures detected:");
        for (cve_id, error) in failed_cases.iter() {
            println!("❌ Failed: CVE {}", cve_id);
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

/// Test case information
struct TestCase {
    cve_id: String,
    git_sha: String,
    vulnerable_path: Option<PathBuf>,
    dyad_path: Option<PathBuf>,
}

/// Result of running a test case
struct TestResult {
    success: bool,
    error_message: String,
}

/// Run a single test case and check output against expected .dyad file
fn run_test_case(test_case: &TestCase) -> TestResult {
    // Find the dyad binary
    let dyad_path = match find_dyad_binary() {
        Some(path) => path,
        None => {
            return TestResult {
                success: false,
                error_message: "Failed to find dyad binary".to_string(),
            }
        }
    };

    // Build command with git SHA(s) - handle multi-line SHA files
    let mut cmd = Command::new(&dyad_path);
    for sha in test_case.git_sha.lines() {
        let sha = sha.trim();
        if !sha.is_empty() {
            cmd.arg("--sha1").arg(sha);
        }
    }

    // If we have a .vulnerable file, read its content and pass it with --vulnerable
    // Handle multi-line files by passing each SHA as a separate argument
    if let Some(v_path) = &test_case.vulnerable_path
        && let Ok(content) = std::fs::read_to_string(v_path) {
            for sha in content.lines() {
                let sha = sha.trim();
                if !sha.is_empty() {
                    cmd.arg("--vulnerable").arg(sha);
                }
            }
        }

    // Run dyad
    let dyad_result = cmd.output();

    match dyad_result {
        Ok(output) => {
            if !output.status.success() {
                return TestResult {
                    success: false,
                    error_message: format!(
                        "Dyad command failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    ),
                };
            }

            let actual_output = String::from_utf8_lossy(&output.stdout).to_string();

            // If there's an existing .dyad file, compare with it
            if let Some(dyad_path) = &test_case.dyad_path {
                match fs::read_to_string(dyad_path) {
                    Ok(expected_output) => {
                        // Normalize line endings for comparison
                        let expected = expected_output.replace("\r\n", "\n").trim().to_string();
                        let actual = actual_output.replace("\r\n", "\n").trim().to_string();

                        // Filter out lines starting with "#" for comparison
                        let expected_filtered = expected
                            .lines()
                            .filter(|line| !line.trim_start().starts_with("#"))
                            .collect::<Vec<&str>>()
                            .join("\n");
                        let actual_filtered = actual
                            .lines()
                            .filter(|line| !line.trim_start().starts_with("#"))
                            .collect::<Vec<&str>>()
                            .join("\n");

                        if expected_filtered != actual_filtered {
                            // Write actual output to a temp file for debugging
                            let temp_path = dyad_path.with_extension("actual");
                            if let Ok(mut file) = fs::File::create(&temp_path) {
                                let _ = file.write_all(actual.as_bytes());
                            }

                            return TestResult {
                                success: false,
                                error_message: format!(
                                    "Output differs from expected. Expected in {}, actual in {}",
                                    dyad_path.display(),
                                    temp_path.display()
                                ),
                            };
                        }

                        // Output matches expected
                        TestResult {
                            success: true,
                            error_message: String::new(),
                        }
                    }
                    Err(e) => TestResult {
                        success: false,
                        error_message: format!("Failed to read expected .dyad file: {}", e),
                    },
                }
            } else {
                // No .dyad file exists, warn but don't fail
                TestResult {
                    success: true,
                    error_message: format!(
                        "Warning: No .dyad file exists for {}",
                        test_case.cve_id
                    ),
                }
            }
        }
        Err(err) => TestResult {
            success: false,
            error_message: format!("Failed to execute dyad: {}", err),
        },
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
        }
        Err(e) => Err(format!("Failed to find vulns directory: {}", e)),
    }
}

/// Get a list of test cases
fn get_test_cases(cve_dir: &Path) -> Vec<TestCase> {
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
                    if path.extension().is_some_and(|ext| ext == "sha1")
                        && let Ok(content) = std::fs::read_to_string(&path)
                        && let Some(cve_id) = path.file_stem().and_then(|s| s.to_str()) {
                            let git_sha = content.trim().to_string();

                            // Find corresponding vulnerable file if it exists
                            let vulnerable_path = path.with_extension("vulnerable");
                            let vulnerable_file = if vulnerable_path.exists() {
                                Some(vulnerable_path)
                            } else {
                                None
                            };

                            // Check for existing .dyad file
                            let dyad_path = path.with_extension("dyad");
                            let dyad_file = if dyad_path.exists() {
                                Some(dyad_path)
                            } else {
                                None
                            };

                            test_cases.push(TestCase {
                                cve_id: cve_id.to_string(),
                                git_sha,
                                vulnerable_path: vulnerable_file,
                                dyad_path: dyad_file,
                            });
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
        && output.status.success() {
            // Get the path from Cargo's output
            let target_dir = env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());

            let dyad_path = PathBuf::from(target_dir).join("debug").join("dyad");

            if dyad_path.exists() {
                return Some(dyad_path);
            }
    }

    // Try to find it in PATH
    if let Ok(output) = Command::new("which").arg("dyad").output()
        && output.status.success() {
            let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            return Some(PathBuf::from(path_str));
    }

    None
}
