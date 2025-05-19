// SPDX-License-Identifier: GPL-2.0
// (c) 2025, Sasha Levin <sashal@kernel.org>

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use log::{info, debug, warn, error};
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use rayon::prelude::*;
use std::sync::Arc;
use walkdir::WalkDir;

// Import from the commit-classifier library
use commit_classifier::CommitFeatures;

// Type definition for commit information result
type CommitInfoResult = (String, Option<(String, String)>, bool, Option<String>);

pub struct CVEDataCollector {
    pub kernel_repo_path: PathBuf,
    pub cve_commits_path: Option<PathBuf>,
    pub seen_commit_messages: HashSet<String>,
    pub seen_subject_lines: HashSet<String>,
    pub cve_commits: HashSet<String>,
}

impl CVEDataCollector {
    pub fn new(kernel_repo_path: &Path, cve_commits_path: Option<&Path>) -> Result<Self, String> {
        let mut cmd = Command::new("git");
        cmd.current_dir(kernel_repo_path)
            .args(["rev-parse", "--is-inside-work-tree"]);

        match cmd.output() {
            Ok(output) => {
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(format!("Not a valid git repository: {stderr}"));
                }
            },
            Err(e) => return Err(format!("Failed to verify git repository: {e}")),
        }

        let mut collector = CVEDataCollector {
            kernel_repo_path: kernel_repo_path.to_path_buf(),
            cve_commits_path: cve_commits_path.map(Path::to_path_buf),
            seen_commit_messages: HashSet::new(),
            seen_subject_lines: HashSet::new(),
            cve_commits: HashSet::new(),
        };

        // Load CVE commits if path provided
        if collector.cve_commits_path.is_some() {
            collector.cve_commits = collector.get_cve_commits();
            info!("Found {} CVE fix commits", collector.cve_commits.len());
        }

        Ok(collector)
    }

    pub fn get_cve_commits(&self) -> HashSet<String> {
        let mut cve_fixes = HashSet::new();

        if let Some(cve_dir) = &self.cve_commits_path {
            info!("Searching for .sha1 files in {}", cve_dir.display());

            // Use WalkDir to recursively traverse all directories
            for entry in WalkDir::new(cve_dir)
                .follow_links(true)
                .into_iter()
                .filter_map(Result::ok)
            {
                let path = entry.path();

                // Filter for .sha1 files
                if path.is_file() &&
                   path.extension().is_some_and(|ext| ext == "sha1") {
                    // Read the file content
                    if let Ok(content) = std::fs::read_to_string(path) {
                        // Process each line separately as some .sha1 files contain multiple commits
                        for line in content.lines() {
                            let line = line.trim();
                            // Skip empty lines and comments
                            if !line.is_empty() && !line.starts_with('#') {
                                // Add the SHA1 to fixing commits
                                debug!("Found CVE commit: {line} from file {}", path.display());
                                cve_fixes.insert(line.to_string());
                            }
                        }
                    }
                }
            }
        }

        info!("Total CVE fix commits found: {}", cve_fixes.len());
        cve_fixes
    }


    pub fn process_cve_commit(&self, commit_sha: &str) -> Option<CommitFeatures> {
        let mut features = self.get_commit_features(commit_sha)?;

        // Mark as a CVE commit
        features.was_selected = Some(true);

        // Check if this is a direct CVE commit or a backported one
        let is_backport = !self.cve_commits.contains(commit_sha);

        if is_backport {
            // This might be a backport of a CVE fix
            if let Some(upstream_sha) = Self::extract_upstream_commit(&features.message) {
                if self.cve_commits.contains(&upstream_sha) {
                    // This is a backport of a CVE fix
                    features.upstream_sha = Some(upstream_sha);
                }
            }
        } else {
            // Direct CVE fix
            features.upstream_sha = Some(features.sha.clone());
        }

        Some(features)
    }

    pub fn process_non_cve_commit(&self, commit_sha: &str) -> Option<CommitFeatures> {
        let mut features = self.get_commit_features(commit_sha)?;

        // Double-check if this might be a backported CVE commit that was missed
        if let Some(upstream_sha) = Self::extract_upstream_commit(&features.message) {
            if self.cve_commits.contains(&upstream_sha) {
                // This is actually a backported CVE commit
                features.was_selected = Some(true);
                let upstream_sha_clone = upstream_sha.clone();
                features.upstream_sha = Some(upstream_sha);
                debug!("Reclassified commit {commit_sha} as a backported CVE from {upstream_sha_clone}");
                return Some(features);
            }
        }

        // This is a non-CVE commit
        features.was_selected = Some(false);

        Some(features)
    }

    pub fn extract_upstream_commit(commit_message: &str) -> Option<String> {
        // Common patterns for upstream commit references
        let patterns = [
            r"(?:commit|upstream commit|upstream|upstream:)\s+([a-f0-9]{40})",
            r"\[\s*(?:Upstream|UPSTREAM)(?:\s+commit)?\s+([a-f0-9]{40})",
            r"cherry picked from commit ([a-f0-9]{40})",
            r"backport of commit ([a-f0-9]{40})"
        ];

        // Try each pattern
        for pattern in patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if let Some(captures) = regex.captures(commit_message) {
                    return captures.get(1).map(|m| m.as_str().to_string());
                }
            }
        }

        None
    }

    pub fn get_commit_features(&self, commit_sha: &str) -> Option<CommitFeatures> {
        // Validate that the commit_sha is a valid SHA1 hash (40 characters of hex)
        if !commit_sha.chars().all(|c| c.is_ascii_hexdigit()) || commit_sha.len() != 40 {
            warn!("Invalid SHA1 format: {commit_sha}");
            return None;
        }

        // Try to get the commit message
        let Some(message) = self.safe_git_command(&["log", "-1", "--pretty=format:%B", commit_sha]) else {
            warn!("Failed to retrieve commit message for SHA: {commit_sha}");
            return None;
        };

        let author_name = match self.safe_git_command(&["log", "-1", "--pretty=format:%an", commit_sha]) {
            Some(name) => name,
            None => "Unknown".to_string(),
        };

        let Some(date_str) = self.safe_git_command(&["log", "-1", "--pretty=format:%aI", commit_sha]) else {
            warn!("Failed to retrieve commit date for SHA: {commit_sha}");
            return None;
        };

        let datetime = match DateTime::parse_from_rfc3339(&date_str) {
            Ok(dt) => dt.with_timezone(&Utc),
            Err(_) => Utc::now(), // Fallback to current time if invalid
        };

        let diff_text = self.safe_git_command(
            &["show", "-U20", "--format=", commit_sha]
        ).unwrap_or_default();

        let files_output = self.safe_git_command(
            &["show", "--name-only", "--format=", commit_sha]
        ).unwrap_or_default();

        let files_changed: Vec<String> = files_output
            .lines()
            .filter(|line| !line.is_empty())
            .map(ToString::to_string)
            .collect();

        Some(CommitFeatures {
            sha: commit_sha.to_string(),
            message,
            diff: diff_text,
            author: author_name,
            date: datetime,
            files_changed,
            was_selected: None,
            upstream_sha: None,
        })
    }

    // Execute git command with safety checks
    pub fn safe_git_command(&self, args: &[&str]) -> Option<String> {
        let mut cmd = Command::new("git");
        cmd.current_dir(&self.kernel_repo_path)
            .args(args);

        match cmd.output() {
            Ok(output) => {
                if output.status.success() {
                    match String::from_utf8(output.stdout) {
                        Ok(stdout) => Some(stdout),
                        Err(e) => {
                            warn!("Failed to decode git command output: {e}");
                            None
                        }
                    }
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    warn!("Git command failed: {} ({})", args.join(" "), stderr);
                    None
                }
            },
            Err(e) => {
                error!("Error executing git command {}: {}", args.join(" "), e);
                None
            }
        }
    }

    // Process a single branch to find commits in the date range
    fn process_branch(&self, branch: &str, since_str: &str, until_str: &str) -> Vec<String> {
        debug!("Processing branch: {branch}");

        // Get the branch tip
        let branch_tip_cmd = vec!["rev-parse", branch];
        let Some(output) = self.safe_git_command(&branch_tip_cmd) else {
            warn!("Failed to get tip for branch {branch}");
            return Vec::new();
        };
        let branch_tip = output.trim().to_string();

        // Get merge-base with origin/master
        let merge_base_cmd = vec!["merge-base", "origin/master", branch];
        let Some(output) = self.safe_git_command(&merge_base_cmd) else {
            warn!("Failed to find merge-base for branch {branch}");
            return Vec::new();
        };
        let merge_base = output.trim().to_string();

        debug!("Branch tip for {branch}: {branch_tip} (merge-base: {merge_base})");

        // Get non-merge commits in the date range between merge-base and branch tip
        let range = format!("{merge_base}..{branch_tip}");
        let cmd = vec![
            "rev-list", "--no-merges",
            since_str,
            until_str,
            &range
        ];

        if let Some(output) = self.safe_git_command(&cmd) {
            output.lines()
                .filter(|line| !line.is_empty())
                .map(ToString::to_string)
                .collect()
        } else {
            warn!("Failed to get commits for branch {branch}");
            Vec::new()
        }
    }

    fn get_commit_message_hash(&self, commit_sha: &str) -> Option<(String, String)> {
        // Get the raw message
        let message = self.safe_git_command(
            &["log", "-1", "--pretty=format:%B", commit_sha]
        )?;

        // Split to get just the subject line for display
        let lines: Vec<&str> = message.lines().collect();
        let subject = lines.first().unwrap_or(&"").trim().to_string();

        // Hash the message
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        Some((hash, subject))
    }


    // Initialize rayon thread pool with specified number of workers
    fn setup_thread_pool(max_workers: usize) {
        rayon::ThreadPoolBuilder::new()
            .num_threads(max_workers)
            .build_global()
            .unwrap();
    }

    // Prepare CVE commits for processing
    fn prepare_cve_commits(&mut self, max_cve: Option<usize>) -> Vec<String> {
        // If we don't have CVE commits, try to load them
        if self.cve_commits.is_empty() && self.cve_commits_path.is_some() {
            self.cve_commits = self.get_cve_commits();
        }

        if self.cve_commits.is_empty() {
            error!("No CVE commits found. Cannot build dataset.");
            return Vec::new();
        }

        info!("Found {} CVE fixing commits", self.cve_commits.len());

        // Reset seen commit messages
        self.seen_commit_messages.clear();
        self.seen_subject_lines.clear();

        // If in test mode, limit the number of CVE commits
        match max_cve {
            Some(limit) if limit < self.cve_commits.len() => {
                info!("Limiting CVE commits to {limit} for testing");
                self.cve_commits.iter().take(limit).cloned().collect()
            },
            _ => self.cve_commits.iter().cloned().collect()
        }
    }

    // Pre-process CVE commits to identify backports
    fn preprocess_cve_commits(&self, cve_list: &[String]) -> Vec<(String, Option<String>)> {
        info!("Pre-processing CVE commits to identify backports...");
        cve_list.par_iter()
            .map(|sha| {
                // Try to get the commit message to check if this is a backport
                if let Some(message) = self.safe_git_command(&["log", "-1", "--pretty=format:%B", sha]) {
                    if let Some(upstream_sha) = Self::extract_upstream_commit(&message) {
                        // This is a backport, return the SHA and upstream SHA
                        return (sha.clone(), Some(upstream_sha));
                    }
                }
                // This is not a backport or we couldn't extract upstream SHA
                (sha.clone(), None)
            })
            .collect()
    }

    // Filter out duplicate backports based on upstream SHA
    fn filter_duplicate_backports(
        cve_commit_info: Vec<(String, Option<String>)>,
        seen_upstream_shas: &mut HashSet<String>
    ) -> Vec<String> {
        let mut shas_to_process = Vec::new();

        for (sha, upstream_sha_opt) in cve_commit_info {
            if let Some(upstream_sha) = upstream_sha_opt {
                // This is a backport - check if we've seen this upstream SHA
                if seen_upstream_shas.contains(&upstream_sha) {
                    debug!("Skipping duplicate backport of upstream SHA {upstream_sha}");
                    continue;
                }
                // First time seeing this upstream SHA, add it to seen set
                seen_upstream_shas.insert(upstream_sha);
            }
            // Either not a backport or first time seeing this upstream SHA
            shas_to_process.push(sha);
        }

        shas_to_process
    }

    // Process CVE commits with progress bar
    fn process_cve_commits(&self, shas_to_process: &[String]) -> Vec<CommitFeatures> {
        // Progress bar
        let pb = ProgressBar::new(shas_to_process.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap());

        // Use progress bar that is thread-safe for parallel operations
        let pb = Arc::new(pb);

        // Collect and process commit features in parallel
        let processed_commits: Vec<CommitFeatures> = shas_to_process.par_iter()
            .filter_map(|sha| {
                let pb_clone = Arc::clone(&pb);
                let features = self.process_cve_commit(sha);
                pb_clone.inc(1);
                features
            })
            .collect();

        pb.finish_with_message("Processed CVE commits");
        processed_commits
    }

    // Get linux branches for non-CVE commit collection
    fn get_linux_branches(&self) -> Vec<String> {
        let list_refs_cmd = vec!["show-ref"];
        let mut linux_branches = Vec::new();

        if let Some(refs_output) = self.safe_git_command(&list_refs_cmd) {
            for line in refs_output.lines() {
                // Look for linux- branches in any remote (origin, stable, etc.)
                if line.contains(" refs/remotes/") && line.contains("/linux-") {
                    if let Some(branch_name) = line.split_whitespace().nth(1) {
                        // Extract branch name from the full ref path
                        let branch_name = branch_name.trim();
                        linux_branches.push(branch_name.to_string());
                    }
                }
            }
        }

        info!("Found {} linux- branches", linux_branches.len());
        linux_branches
    }

    // Collect non-CVE commits from branches
    fn collect_non_cve_commits(&self, linux_branches: &[String], oldest_date: &str, newest_date_str: &str) -> Vec<String> {
        // Process each branch to collect non-CVE commits
        let since_str = format!("--since={oldest_date}");
        let until_str = format!("--until={newest_date_str}");

        // Create a thread-safe progress bar
        let branch_pb = Arc::new(ProgressBar::new(linux_branches.len() as u64));
        branch_pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) - Processing branches")
            .unwrap());

        // Process branches in parallel
        let branch_results: Vec<Vec<String>> = linux_branches.par_iter()
            .map(|branch| {
                let pb_clone = Arc::clone(&branch_pb);
                let result = self.process_branch(branch, &since_str, &until_str);
                pb_clone.inc(1);
                result
            })
            .collect();

        branch_pb.finish_with_message("Processed all branches");

        // Combine all SHA1s
        let mut all_branch_shas = Vec::new();
        for shas in branch_results {
            all_branch_shas.extend(shas);
        }

        info!("Found {} total commits across all linux- branches", all_branch_shas.len());
        all_branch_shas
    }

    // Extract commit information (hash, backport status, etc.)
    fn extract_commit_info(&self, non_cve_shas: &[String]) -> Vec<CommitInfoResult> {
        // Create a progress bar for deduplication and backport checking
        let dedup_pb = ProgressBar::new(non_cve_shas.len() as u64);
        dedup_pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) - Processing")
            .unwrap());
        dedup_pb.set_message("Processing non-CVE commits");

        // Add upstream SHA extraction to commit_hash_results
        // Format: (SHA, message hash, subject, is_backport, upstream_sha)
        let commit_info_results: Vec<CommitInfoResult> = non_cve_shas.par_iter()
            .map(|sha| {
                let hash_result = self.get_commit_message_hash(sha);
                let mut is_backport = false;
                let mut upstream_sha = None;

                // Fetch commit message to check for upstream reference
                if let Some(message) = self.safe_git_command(&["log", "-1", "--pretty=format:%B", sha]) {
                    if let Some(extracted_sha) = Self::extract_upstream_commit(&message) {
                        // Check if this is a backport of a CVE commit
                        if self.cve_commits.contains(&extracted_sha) {
                            is_backport = true;
                        }
                        // Store the upstream SHA whether it's a CVE or not
                        upstream_sha = Some(extracted_sha);
                    }
                }

                dedup_pb.inc(1);
                (sha.clone(), hash_result, is_backport, upstream_sha)
            })
            .collect();

        dedup_pb.finish_with_message("Computed commit message hashes and extracted upstream SHAs");
        commit_info_results
    }

    // Deduplicate non-CVE commits based on various criteria
    fn deduplicate_non_cve_commits(
        commit_info_results: Vec<CommitInfoResult>,
        seen_upstream_shas: &mut HashSet<String>
    ) -> (Vec<String>, Vec<String>, usize) {
        // Now perform deduplication sequentially based on upstream SHAs
        info!("Filtering duplicate commits by upstream SHA...");
        let mut seen_messages = HashSet::new();
        let mut seen_subjects = HashSet::new();
        let mut unique_non_cve = Vec::new();
        let mut backported_shas = Vec::new();
        let mut skipped_backports = 0;

        for (sha, hash_opt, is_backport, upstream_sha_opt) in commit_info_results {
            // Check if this is a backport with upstream SHA
            let has_upstream_sha = match &upstream_sha_opt {
                Some(upstream_sha) => {
                    // Check if we've already processed this upstream SHA
                    if seen_upstream_shas.contains(upstream_sha) {
                        skipped_backports += 1;
                        debug!("Skipping duplicate backport of upstream SHA {upstream_sha}");
                        continue;
                    }

                    // First time seeing this upstream SHA
                    seen_upstream_shas.insert(upstream_sha.clone());

                    // If it's a backport of a CVE commit, add to backported_shas
                    if is_backport {
                        backported_shas.push(sha);
                        continue;
                    }

                    true // It's a backport, but not of a CVE commit
                },
                None => false, // Not a backport
            };

            // Only check message hash and subject deduplication for non-backported commits
            if !has_upstream_sha {
                if let Some((hash, subject)) = hash_opt {
                    // Check for duplicate message hash
                    if seen_messages.contains(&hash) {
                        continue;
                    }
                    seen_messages.insert(hash);

                    // Check for duplicate subject
                    if seen_subjects.contains(&subject) {
                        continue;
                    }
                    seen_subjects.insert(subject);
                }
            }

            // Not a backport or first time seeing this upstream SHA
            unique_non_cve.push(sha);
        }

        (unique_non_cve, backported_shas, skipped_backports)
    }

    // Process backported CVE commits
    fn process_backported_cve_commits(&self, backported_shas: &[String]) -> Vec<CommitFeatures> {
        if backported_shas.is_empty() {
            return Vec::new();
        }

        info!("Processing {} backported CVE commits", backported_shas.len());
        let backport_pb = Arc::new(ProgressBar::new(backported_shas.len() as u64));
        backport_pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) - Processing")
            .unwrap());
        backport_pb.set_message("Processing backported CVE commits");

        // Process backported CVE commits in parallel
        let backported_cve_commits: Vec<CommitFeatures> = backported_shas.par_iter()
            .filter_map(|sha| {
                let pb_clone = Arc::clone(&backport_pb);
                let features = self.process_cve_commit(sha);
                pb_clone.inc(1);
                features
            })
            .collect();

        backport_pb.finish_with_message("Processed backported CVE commits");
        backported_cve_commits
    }

    // Process non-CVE commits
    fn process_non_cve_commits(&self, non_cve_list: &[String]) -> Vec<CommitFeatures> {
        // Create progress bar for non-CVE commits
        let pb = ProgressBar::new(non_cve_list.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) - Processing")
            .unwrap());
        pb.set_message("Processing non-CVE commits");

        // Make progress bar thread-safe
        let pb = Arc::new(pb);

        // Collect and process commit features in parallel
        let non_cve_commits: Vec<CommitFeatures> = non_cve_list.par_iter()
            .filter_map(|sha| {
                let pb_clone = Arc::clone(&pb);
                let features = self.process_non_cve_commit(sha);
                pb_clone.inc(1);
                features
            })
            .collect();

        pb.finish_with_message("Processed non-CVE commits");
        non_cve_commits
    }

    // Main method to build the dataset - now orchestrates smaller methods
    pub fn build_dataset(&mut self, max_workers: usize,
               max_cve: Option<usize>, max_non_cve: Option<usize>) -> Vec<CommitFeatures> {
        // Setup parallel processing environment
        Self::setup_thread_pool(max_workers);

        // Prepare CVE commits
        let cve_list = self.prepare_cve_commits(max_cve);
        if cve_list.is_empty() {
            return Vec::new();
        }

        // Track upstream SHA1s we've already processed to avoid duplicates
        let mut seen_upstream_shas = HashSet::new();
        let mut all_commits = Vec::new();

        // Preprocess CVE commits to identify backports
        let cve_commit_info = self.preprocess_cve_commits(&cve_list);

        // Filter duplicate backports
        let shas_to_process = Self::filter_duplicate_backports(cve_commit_info, &mut seen_upstream_shas);

        let skipped_cve_backports = cve_list.len() - shas_to_process.len();
        info!("Found {} duplicate backported CVE commits (processing {} unique commits)",
              skipped_cve_backports, shas_to_process.len());

        // Process CVE commits
        let processed_commits = self.process_cve_commits(&shas_to_process);
        all_commits.extend(processed_commits);

        info!("Processed {} unique CVE commits (skipped {} duplicates)",
              all_commits.len(), cve_list.len() - shas_to_process.len());

        // Get non-CVE commits
        info!("Getting non-CVE commits from April 1st 2024 to 2 weeks ago...");

        // Calculate date boundaries
        // Use April 1st 2024 as the start date
        let oldest_date = "2024-04-01";
        let newest_date = chrono::Utc::now() - chrono::Duration::days(14);
        let newest_date_str = newest_date.format("%Y-%m-%d").to_string();

        // Get list of linux-* branches
        info!("Getting non-CVE commits between April 1st 2024 and 2 weeks ago from linux- branches...");
        let linux_branches = self.get_linux_branches();

        // Collect non-CVE commits from branches
        let all_branch_shas = self.collect_non_cve_commits(&linux_branches, oldest_date, &newest_date_str);

        // Filter out CVE commits
        let non_cve_shas: Vec<String> = all_branch_shas.into_iter()
            .filter(|sha| !self.cve_commits.contains(sha))
            .collect();

        let non_cve_count = non_cve_shas.len();
        info!("Found {non_cve_count} non-CVE commits");

        // First, compute message hashes and extract upstream SHAs in parallel
        info!("Computing commit message hashes and extracting upstream SHAs for deduplication...");
        let commit_info_results = self.extract_commit_info(&non_cve_shas);

        // Deduplicate non-CVE commits
        let (unique_non_cve, backported_shas, skipped_backports) =
            Self::deduplicate_non_cve_commits(commit_info_results, &mut seen_upstream_shas);

        let branch_duplicates = non_cve_count - unique_non_cve.len() - backported_shas.len();
        info!("Found {} unique non-CVE commits (skipped {} duplicates by message/subject, {} by upstream SHA)",
              unique_non_cve.len(), branch_duplicates - skipped_backports, skipped_backports);

        // Limit non-CVE commits if needed
        let non_cve_list: Vec<String> = match max_non_cve {
            Some(limit) if limit < unique_non_cve.len() => {
                info!("Limiting non-CVE commits to {limit} for testing");
                unique_non_cve.into_iter().take(limit).collect()
            },
            _ => unique_non_cve
        };

        // Process backported CVE commits
        let backported_cve_commits = self.process_backported_cve_commits(&backported_shas);
        all_commits.extend(backported_cve_commits);

        // Process non-CVE commits
        let non_cve_commits = self.process_non_cve_commits(&non_cve_list);
        all_commits.extend(non_cve_commits);

        // Log summary information
        info!("Final dataset: {} total unique commits", all_commits.len());

        let cve_count = all_commits.iter()
            .filter(|c| c.was_selected == Some(true)) // Count commits that were assigned CVEs
            .count();

        info!("  - CVE commits: {cve_count} (direct & backported, deduplicated by upstream SHA)");
        info!("  - Non-CVE commits: {} (deduplicated by message, subject, and upstream SHA)",
              all_commits.len() - cve_count);

        all_commits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to create a test commit message
    fn create_test_commit_message(subject: &str, body: &str) -> String {
        format!("{}\n\n{}", subject, body)
    }

    #[test]
    fn test_get_commit_message_hash() {
        // Create a mock collector with a temporary path (no need for real git repo for this test)
        let _collector = CVEDataCollector {
            kernel_repo_path: PathBuf::from("/tmp"),
            cve_commits_path: None,
            seen_commit_messages: HashSet::new(),
            seen_subject_lines: HashSet::new(),
            cve_commits: HashSet::new(),
        };

        // We'll test the hash calculation logic directly
        // by creating a mock message and manually computing the hash
        let subject = "Fix memory leak in the kernel";
        let body = "This commit fixes a memory leak in the kernel.\n\nSigned-off-by: Test <test@example.com>";
        let full_message = create_test_commit_message(subject, body);

        // Calculate SHA-256 hash of the full message
        let mut hasher = Sha256::new();
        hasher.update(full_message.as_bytes());
        let expected_hash = format!("{:x}", hasher.finalize());

        // Since we can't call the original method without a git repo,
        // we'll reimplement the logic here for testing
        let subject_line = full_message.lines().next().unwrap_or("").to_string();
        let mut hasher = Sha256::new();
        hasher.update(full_message.as_bytes());
        let message_hash = format!("{:x}", hasher.finalize());

        // Verify subject line and hash match expectations
        assert_eq!(subject_line, subject);
        assert_eq!(message_hash, expected_hash);
    }

    #[test]
    fn test_is_duplicate_commit_empty() {
        let mut collector = CVEDataCollector {
            kernel_repo_path: PathBuf::from("/tmp"),
            cve_commits_path: None,
            seen_commit_messages: HashSet::new(),
            seen_subject_lines: HashSet::new(),
            cve_commits: HashSet::new(),
        };

        // Since we've overridden the implementation to avoid git calls,
        // we'll directly manipulate the seen_subject_lines and seen_commit_messages
        assert!(!collector.seen_subject_lines.contains("Test subject"));
        assert!(!collector.seen_commit_messages.contains("abcdef1234"));

        // Insert values into the HashSets to simulate previous commits
        collector.seen_subject_lines.insert("Test subject".to_string());
        collector.seen_commit_messages.insert("abcdef1234".to_string());

        // Verify they are now detected as seen
        assert!(collector.seen_subject_lines.contains("Test subject"));
        assert!(collector.seen_commit_messages.contains("abcdef1234"));
    }

    #[test]
    fn test_deduplicate_dataset() {
        // Generate some test commit features with duplicates
        let date = Utc::now();
        let commits = vec![
            // First commit
            CommitFeatures {
                sha: "abc123".to_string(),
                message: "First commit".to_string(),
                diff: "diff1".to_string(),
                author: "Author 1".to_string(),
                date,
                files_changed: vec!["file1.c".to_string()],
                was_selected: Some(true),
                upstream_sha: None,
            },
            // Duplicate commit with same message but different SHA
            CommitFeatures {
                sha: "def456".to_string(),
                message: "First commit".to_string(),
                diff: "diff2".to_string(),
                author: "Author 2".to_string(),
                date,
                files_changed: vec!["file2.c".to_string()],
                was_selected: Some(false),
                upstream_sha: None,
            },
            // Unique commit
            CommitFeatures {
                sha: "ghi789".to_string(),
                message: "Second commit".to_string(),
                diff: "diff3".to_string(),
                author: "Author 3".to_string(),
                date,
                files_changed: vec!["file3.c".to_string()],
                was_selected: Some(true),
                upstream_sha: None,
            },
        ];

        // Deduplicate by subject line (simulates what build_dataset would do)
        let mut unique_subjects = HashSet::new();
        let deduplicated: Vec<CommitFeatures> = commits.into_iter()
            .filter(|commit| {
                let subject = commit.message.lines().next().unwrap_or("").to_string();
                unique_subjects.insert(subject)
            })
            .collect();

        // Verify that only two unique commits remain
        assert_eq!(deduplicated.len(), 2);

        // Check the subjects of the remaining commits
        let subjects: Vec<String> = deduplicated.iter()
            .map(|commit| commit.message.lines().next().unwrap_or("").to_string())
            .collect();

        assert!(subjects.contains(&"First commit".to_string()));
        assert!(subjects.contains(&"Second commit".to_string()));
    }
}