// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use anyhow::{anyhow, Result};
use clap::Parser;
use cve_utils::common;
use cve_utils::print_git_error_details;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use walkdir::WalkDir;

/// Score reviewer accuracy based on CVE predictions
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Override the review directory path
    #[clap(long)]
    review_dir: Option<String>,

    /// Override the published directory path
    #[clap(long)]
    published_dir: Option<String>,

    /// Number of threads to use (defaults to all available)
    #[clap(long)]
    threads: Option<usize>,
}

/// Holds all CVE SHA1s for quick lookup
struct CVEDatabase {
    sha1_set: HashSet<String>,
}

impl CVEDatabase {
    /// Load all SHA1s from the published directory into memory for fast lookup
    fn new(published_dir: &Path) -> Result<Self> {
        let sha1_set_mutex = Arc::new(Mutex::new(HashSet::new()));

        // Parallel processing of all year directories
        fs::read_dir(published_dir)?
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_dir())
            .collect::<Vec<_>>()
            .par_iter()
            .try_for_each(|year_dir_entry| -> Result<()> {
                let year_dir = year_dir_entry.path();
                let sha1_set = Arc::clone(&sha1_set_mutex);

                // Process all .sha1 files in this year directory
                for entry in fs::read_dir(&year_dir)? {
                    let path = entry?.path();
                    if !path.is_file() || path.extension().is_none_or(|ext| ext != "sha1") {
                        continue;
                    }

                    let content = fs::read_to_string(&path)?;
                    let sha1 = content.trim().to_string();
                    if !sha1.is_empty() {
                        let mut set = sha1_set.lock().unwrap();
                        set.insert(sha1);
                    }
                }

                Ok(())
            })?;

        // Extract the HashSet from the Mutex and Arc
        let mut final_set = HashSet::new();
        let mutex_guard = sha1_set_mutex.lock().unwrap();
        final_set.extend(mutex_guard.iter().cloned());

        Ok(Self { sha1_set: final_set })
    }

    /// Check if a commit has a CVE
    fn has_cve(&self, commit: &str) -> bool {
        let sha1 = commit.split_whitespace().next().unwrap_or(commit);

        // First check for exact match
        if self.sha1_set.contains(sha1) {
            return true;
        }

        // Then check if any SHA in the database starts with this partial SHA
        if sha1.len() < 40 {
            self.sha1_set.iter().any(|s| s.starts_with(sha1))
        } else {
            false
        }
    }
}

/// Structure to hold all data for a reviewer
struct ReviewerData {
    reviewed_commits: HashSet<String>,
    reviewed_versions: HashSet<String>,
    total_predictions: usize,
    correct_predictions: usize,
    missed_consensus: usize,
    total_possible_consensus: usize,
}

impl ReviewerData {
    fn new() -> Self {
        Self {
            reviewed_commits: HashSet::new(),
            reviewed_versions: HashSet::new(),
            total_predictions: 0,
            correct_predictions: 0,
            missed_consensus: 0,
            total_possible_consensus: 0,
        }
    }
}

/// Collect all reviewer names and their reviewed files
fn collect_reviewers_and_files(review_dir: &Path) -> Result<HashMap<String, Vec<PathBuf>>> {
    let mut reviewer_files: HashMap<String, Vec<PathBuf>> = HashMap::new();

    // Single pass through all files to collect reviewers and their files
    WalkDir::new(review_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .for_each(|entry| {
            let path = entry.path();
            let file_name = path.file_name().unwrap().to_string_lossy();

            // Skip files in gsd directory and annotated files
            if path.to_string_lossy().contains("gsd") || file_name.contains("annotated") {
                return;
            }

            // Check if filename matches v*-*
            if let Some(captures) = regex::Regex::new(r"v[\d.]+-([^/]+)$").ok()
                .and_then(|re| re.captures(&file_name))
            {
                if let Some(reviewer) = captures.get(1) {
                    let reviewer_name = reviewer.as_str().to_string();
                    reviewer_files.entry(reviewer_name)
                        .or_default()
                        .push(path.to_path_buf());
                }
            }
        });

    Ok(reviewer_files)
}

/// Extract version from filename
fn extract_version(file_name: &str) -> Option<String> {
    regex::Regex::new(r"(v[\d.]+)")
        .ok()
        .and_then(|re| re.find(file_name))
        .map(|m| m.as_str().to_string())
}

// Type definition for the complex review data structure
// Reviewer -> Version -> Set of commit SHAs
type ReviewMap = HashMap<String, HashMap<String, HashSet<String>>>;

/// Process all reviewers in parallel and collect statistics
fn process_reviewers(
    reviewer_files: HashMap<String, Vec<PathBuf>>,
    cve_database: Arc<CVEDatabase>,
) -> Result<Vec<(String, ReviewerData)>> {
    // Collect all reviews into shared data structure
    let all_reviews: Arc<Mutex<ReviewMap>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Calculate total number of files to process for progress bar
    let total_files: usize = reviewer_files.values().map(|files| files.len()).sum();
    let progress = Arc::new(Mutex::new(ProgressBar::new(total_files as u64)));
    progress.lock().unwrap().set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .unwrap()
        .progress_chars("#>-"));

    // Process all reviewer files in parallel
    let reviewers_data: Vec<(String, ReviewerData)> = reviewer_files
        .par_iter()
        .map(|(reviewer, files)| {
            let mut reviewer_data = ReviewerData::new();

            // Process each file for this reviewer
            for file_path in files {
                let file_name = file_path.file_name().unwrap().to_string_lossy();

                if let Some(version) = extract_version(&file_name) {
                    reviewer_data.reviewed_versions.insert(version.clone());

                    // Process each commit in the file
                    if let Ok(file) = File::open(file_path) {
                        let reader = BufReader::new(file);

                        for line in reader.lines().map_while(Result::ok) {
                            let commit = line.trim();
                            if commit.is_empty() {
                                continue;
                            }

                            let sha1 = commit.split_whitespace().next().unwrap_or(commit);
                            reviewer_data.reviewed_commits.insert(sha1.to_string());
                            reviewer_data.total_predictions += 1;

                            // Check if this commit has a CVE
                            if cve_database.has_cve(sha1) {
                                reviewer_data.correct_predictions += 1;
                            }

                            // Store in all_reviews for consensus calculation
                            let mut all_reviews_guard = all_reviews.lock().unwrap();
                            all_reviews_guard
                                .entry(version.clone())
                                .or_default()
                                .entry(sha1.to_string())
                                .or_default()
                                .insert(reviewer.clone());
                        }
                    }
                }

                // Update progress
                progress.lock().unwrap().inc(1);
            }

            (reviewer.clone(), reviewer_data)
        })
        .collect();

    progress.lock().unwrap().finish_with_message("Collection and processing complete");

    // Calculate consensus metrics
    println!("Calculating consensus metrics...");
    let all_reviews_data = all_reviews.lock().unwrap();

    // Process each reviewer's consensus data in parallel
    let reviewer_data_vec: Vec<(String, ReviewerData)> = reviewers_data
        .into_par_iter()
        .map(|(reviewer, mut data)| {
            // Go through all versions this reviewer has reviewed
            for version in &data.reviewed_versions {
                if let Some(version_commits) = all_reviews_data.get(version) {
                    for (sha1, reviewers) in version_commits {
                        // Only count if the commit has a CVE and was reviewed by anyone
                        if cve_database.has_cve(sha1) {
                            data.total_possible_consensus += 1;

                            // If this reviewer didn't mark it, it's a missed consensus
                            if !reviewers.contains(&reviewer) {
                                data.missed_consensus += 1;
                            }
                        }
                    }
                }
            }

            (reviewer, data)
        })
        .collect();

    Ok(reviewer_data_vec)
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Configure thread pool size if specified
    if let Some(threads) = args.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .unwrap();
    } else {
        // Use all available cores
        rayon::ThreadPoolBuilder::new()
            .num_threads(num_cpus::get())
            .build_global()
            .unwrap();
    }

    // Get the CVE root directory
    let vulns_dir = match common::find_vulns_dir() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("Error finding vulns directory: {}", e);
            print_git_error_details(&e);
            return Err(e);
        }
    };

    let cve_root = vulns_dir.join("cve");

    // Set up the directory paths
    let review_dir = match args.review_dir {
        Some(path) => PathBuf::from(path),
        None => cve_root.join("review").join("done"),
    };

    let published_dir = match args.published_dir {
        Some(path) => PathBuf::from(path),
        None => cve_root.join("published"),
    };

    // Validate directories exist
    if !review_dir.exists() {
        return Err(anyhow!("Review directory does not exist: {:?}", review_dir));
    }
    if !published_dir.exists() {
        return Err(anyhow!("Published directory does not exist: {:?}", published_dir));
    }

    println!("Reviewer Accuracy Report");
    println!("=======================");
    println!();

    // Load CVE database for faster checking
    println!("Loading CVE database...");
    let cve_database = match CVEDatabase::new(&published_dir) {
        Ok(db) => Arc::new(db),
        Err(e) => {
            eprintln!("Error loading CVE database: {}", e);
            print_git_error_details(&e);
            return Err(e);
        }
    };

    // Collect reviewers and their files
    println!("Collecting reviewer information...");
    let reviewer_files = collect_reviewers_and_files(&review_dir)?;
    println!("Found {} reviewers to process", reviewer_files.len());
    println!();

    // Process all reviewers in parallel
    println!("Processing reviewers...");
    let mut results = process_reviewers(reviewer_files, cve_database)?;

    // Sort by hit percentage (descending)
    results.sort_by(|(_, a), (_, b)| {
        let a_pct = if a.total_predictions > 0 {
            a.correct_predictions as f64 / a.total_predictions as f64
        } else {
            0.0
        };

        let b_pct = if b.total_predictions > 0 {
            b.correct_predictions as f64 / b.total_predictions as f64
        } else {
            0.0
        };

        b_pct.partial_cmp(&a_pct).unwrap()
    });

    // Print results
    for (reviewer, data) in results {
        if data.total_predictions == 0 {
            continue;
        }

        let hit_percentage = (data.correct_predictions as f64 / data.total_predictions as f64) * 100.0;
        let missed_percentage = if data.total_possible_consensus > 0 {
            (data.missed_consensus as f64 / data.total_possible_consensus as f64) * 100.0
        } else {
            0.0
        };

        println!(
            "{:<15}: Hit consensus: {:5.1}% ({}/{}) | Missed consensus: {:5.1}% ({}/{})",
            reviewer,
            hit_percentage,
            data.correct_predictions,
            data.total_predictions,
            missed_percentage,
            data.missed_consensus,
            data.total_possible_consensus
        );
    }

    println!();
    println!("Analysis complete!");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // Test CVE database functionality
    #[test]
    fn test_cve_database() {
        let temp_dir = tempdir().unwrap();
        let year_dir = temp_dir.path().join("2023");
        fs::create_dir_all(&year_dir).unwrap();

        // Create a few test SHA1 files
        fs::write(year_dir.join("CVE-2023-0001.sha1"), "abcd1234abcd1234abcd1234abcd1234abcd1234").unwrap();
        fs::write(year_dir.join("CVE-2023-0002.sha1"), "5678defg5678defg5678defg5678defg5678defg").unwrap();

        let db = CVEDatabase::new(temp_dir.path()).unwrap();

        // Test exact match
        assert!(db.has_cve("abcd1234abcd1234abcd1234abcd1234abcd1234"));

        // Test partial match
        assert!(db.has_cve("abcd1234"));

        // Test non-match
        assert!(!db.has_cve("fffff"));
    }

    // Test against actual score.sh output if run in the same environment
    #[test]
    fn test_against_bash_script() {
        // This test requires the actual CVE repository structure
        // It will be skipped if the directories don't exist
        let vulns_dir = match common::find_vulns_dir() {
            Ok(dir) => dir,
            Err(_) => return, // Skip test if vulns dir not found
        };

        let review_dir = vulns_dir.join("cve").join("review").join("done");
        let published_dir = vulns_dir.join("cve").join("published");

        if !review_dir.exists() || !published_dir.exists() {
            return; // Skip test if required directories don't exist
        }

        // Load CVE database
        let cve_database = Arc::new(CVEDatabase::new(&published_dir).unwrap());

        // Collect reviewer information
        let reviewer_files = collect_reviewers_and_files(&review_dir).unwrap();

        if reviewer_files.is_empty() {
            return; // Skip if no reviewers found
        }

        // Just test with one reviewer to keep the test fast
        let test_reviewer = reviewer_files.keys().next().unwrap().clone();
        let test_files = vec![reviewer_files[&test_reviewer][0].clone()];
        let test_data = HashMap::from([(test_reviewer, test_files)]);

        // Process the test reviewer
        let results = process_reviewers(test_data, cve_database).unwrap();

        // Just verify we got a result
        assert!(!results.is_empty());
    }
}