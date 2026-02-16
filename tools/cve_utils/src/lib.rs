// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

pub mod dyad;
pub mod kernel;
pub mod verhaal;
pub mod version_utils;

use anyhow::{anyhow, Context, Result};
use git2::{Oid, Repository};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// Re-export specific functions from submodules for easier access
// Common utilities for finding and working with CVE data
pub use self::common::{
    find_cve_by_sha, find_sha_by_cve, find_vulns_dir, get_cve_root,
    get_kernel_tree, verify_commit,
};
// Git repository operations using the git2 library
pub use self::git_utils::{
    get_affected_files, get_commit_details, get_commit_message, get_commit_oneline,
    get_commit_year, get_full_sha, get_modified_files, get_object_full_sha, get_short_sha,
    git_sort_ids, match_pattern, print_git_error_details, resolve_reference,
};
// CVE file operations
pub use self::cve_utils::{extract_cve_id_from_path, find_next_free_cve_id};
// Git configuration utilities
pub use self::git_config::{get_git_config, set_git_config};
// CVE validation and processing
pub use self::cve_validation::{extract_year_from_cve, find_cve_id, is_valid_cve};
// Command execution utilities
pub use self::cmd_utils::run_command;
// Year-based utilities
pub use self::year_utils::{is_valid_year, is_year_dir_exists};
// Version utilities
pub use self::version_utils::{
    compare_kernel_versions, get_rc_number, kernel_version_major,
    version_is_mainline, version_is_queue, version_is_rc, version_major_match, KernelVersion,
};
// Kernel structures
pub use self::kernel::{Kernel, KernelPair};
// Verhaal structure
pub use self::verhaal::{FoundInResult, Verhaal};

/// Common functionality shared across all CVE utilities
pub mod common {
    use super::{anyhow, Context, Oid, Path, PathBuf, Repository, Result, WalkDir};
    use super::{env, fs};

    /// Gets the kernel tree path from the CVEKERNELTREE environment variable
    ///
    /// Returns the validated path to the kernel tree or an error if the
    /// environment variable is not set or points to an invalid directory.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The CVEKERNELTREE environment variable is not set
    /// - The directory specified by CVEKERNELTREE does not exist
    pub fn get_kernel_tree() -> Result<PathBuf> {
        let kernel_tree = env::var("CVEKERNELTREE")
            .map_err(|_| anyhow!("CVEKERNELTREE environment variable not set. It needs to be set to the stable repo directory"))?;

        let kernel_tree_path = PathBuf::from(&kernel_tree);
        if !kernel_tree_path.is_dir() {
            return Err(anyhow!(
                "CVEKERNELTREE directory does not exist: {}",
                kernel_tree
            ));
        }

        Ok(kernel_tree_path)
    }

    /// Finds the root directory of the vulns repository
    ///
    /// This function attempts to locate the vulns repository by traversing up from
    /// the current directory until it finds a directory named "vulns".
    /// Additional fallback methods implemented for robust directory discovery.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The current directory cannot be determined
    /// - The 'vulns' directory cannot be found in the directory tree
    pub fn find_vulns_dir() -> Result<PathBuf> {
        // First attempt: Check current directory and its parents
        let mut current_dir = env::current_dir().context("Failed to get current directory")?;

        // Check if we're already in the vulns repo
        if current_dir.file_name().is_some_and(|name| name == "vulns") {
            return Ok(current_dir);
        }

        // Traverse up the directory tree
        while current_dir.parent().is_some() {
            if current_dir.file_name().is_some_and(|name| name == "vulns") {
                return Ok(current_dir);
            }

            if !current_dir.pop() {
                break;
            }
        }

        // Second attempt: look from executable directory
        if let Ok(exec_path) = env::current_exe()
            && let Some(exec_dir) = exec_path.parent() {
                let mut current_dir = exec_dir.to_path_buf();

                // Check if we're already in the vulns repo
                if current_dir.file_name().is_some_and(|name| name == "vulns") {
                    return Ok(current_dir);
                }

                // Traverse up the directory tree
                while current_dir.parent().is_some() {
                    if current_dir.file_name().is_some_and(|name| name == "vulns") {
                        return Ok(current_dir);
                    }

                    if !current_dir.pop() {
                        break;
                    }
                }
            }

        Err(anyhow!(
            "Could not find vulns directory. Please run from within the vulns directory."
        ))
    }

    /// Gets the root CVE directory path
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The vulns directory cannot be found (propagates errors from `find_vulns_dir`)
    pub fn get_cve_root() -> Result<PathBuf> {
        let vulns_dir = find_vulns_dir()?;
        Ok(vulns_dir.join("cve"))
    }

    /// Verifies that a Git commit exists in the kernel tree
    ///
    /// Returns true if the commit exists, false otherwise
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The git repository cannot be opened at the specified path
    pub fn verify_commit(kernel_tree: &Path, sha: &str) -> Result<bool> {
        let repo = Repository::open(kernel_tree).context("Failed to open git repository")?;

        // Check if the commit hash is valid format
        let Ok(oid) = Oid::from_str(sha) else {
            return Ok(false);
        };

        // Check if the commit exists in the repository
        let exists = repo.find_commit(oid).is_ok();
        Ok(exists)
    }

    /// Finds a CVE ID by its associated git SHA
    ///
    /// Searches both published and rejected CVE directories for a match
    ///
    /// # Panics
    ///
    /// This function may panic if:
    /// - A file path doesn't have a valid file name (i.e., when `path.file_name()` returns None)
    #[must_use]
    pub fn find_cve_by_sha(cve_root: &Path, sha: &str) -> Option<String> {
        let published_dir = cve_root.join("published");
        let rejected_dir = cve_root.join("rejected");

        for dir in [published_dir, rejected_dir] {
            if !dir.exists() {
                continue;
            }

            for entry in WalkDir::new(dir).into_iter().filter_map(Result::ok) {
                let path = entry.path();

                // Only check .sha1 files
                if path.is_file()
                    && path
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .ends_with(".sha1")
                    && let Ok(content) = fs::read_to_string(path) {
                        // Match either exact SHA or if it starts with the provided partial SHA
                        if (content.trim() == sha || content.trim().starts_with(sha))
                            && let Some(filename) = path.file_name() {
                                let filename_str = filename.to_string_lossy();
                                if let Some(cve_id) = filename_str.strip_suffix(".sha1") {
                                    return Some(cve_id.to_string());
                                }
                            }
                    }
            }
        }

        None
    }

    /// Finds a git SHA by its associated CVE ID
    ///
    /// Searches the CVE directory structure for a matching CVE ID and returns its associated SHA
    #[must_use]
    pub fn find_sha_by_cve(cve_root: &Path, cve_id: &str) -> Option<String> {
        for entry in WalkDir::new(cve_root).into_iter().filter_map(Result::ok) {
            let path = entry.path();

            // Skip reserved and testing directories
            if path.to_string_lossy().contains("reserved")
                || path.to_string_lossy().contains("testing")
            {
                continue;
            }

            if let Some(filename) = path.file_name()
                && filename.to_string_lossy() == cve_id {
                    let sha_file = path.with_extension("sha1");
                    if sha_file.exists()
                        && let Ok(sha) = fs::read_to_string(sha_file) {
                            return Some(sha.trim().to_string());
                        }
                }
        }

        None
    }
}

/// Git repository operations commonly used across CVE tools
pub mod git_utils {
    use anyhow::{anyhow, Context, Result};
    use chrono::DateTime;
    use git2::{Object, ObjectType, Oid, Repository, Status, StatusOptions};
    use log::{debug, error};
    use std::path::{Path, PathBuf};

    /// Gets the full SHA from a partial SHA
    ///
    /// Uses git2 library to resolve a partial SHA to its full form.
    /// The function accepts a kernel tree path and a partial SHA, and returns
    /// the complete 40-character git commit hash if found.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The git repository cannot be opened at the specified path
    /// - The provided git SHA does not exist or cannot be resolved
    /// - The resolved object is not a commit
    pub fn get_full_sha(kernel_tree: &Path, git_sha: &str) -> Result<String> {
        let repo = Repository::open(kernel_tree).context("Failed to open git repository")?;

        // Use revparse_single directly without the ^{commit} suffix which will work for partial SHAs too
        let object = repo
            .revparse_single(git_sha)
            .context(format!("Git SHA '{git_sha}' not found in kernel tree"))?;

        let commit = repo
            .find_commit(object.id())
            .context("Found object is not a commit")?;

        Ok(commit.id().to_string())
    }

    /// Gets the full SHA from a git Object
    ///
    /// Simple utility to get the full SHA string from a git Object.
    /// Unlike `get_full_sha`, this doesn't require resolving a reference first.
    ///
    /// # Errors
    ///
    /// This function should never fail as it's simply converting an Object ID to a string,
    /// but it returns a Result for API consistency with other git functions.
    pub fn get_object_full_sha(_repo: &Repository, obj: &Object) -> Result<String> {
        Ok(obj.id().to_string())
    }

    /// Gets the short SHA (12 characters) from an Object
    ///
    /// Standardized implementation used by both dyad and bippy
    ///
    /// # Errors
    ///
    /// This function should never fail as it's simply extracting the first 12 characters
    /// of an Object ID string, but it returns a Result for API consistency with other git functions.
    pub fn get_short_sha(_repo: &Repository, obj: &Object) -> Result<String> {
        let id = obj.id().to_string();
        Ok(id[0..12].to_string())
    }

    /// Resolves a reference (SHA, branch, etc.) to a git Object
    ///
    /// Standardized implementation used across utilities
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The reference cannot be resolved in the repository
    /// - The resolved object is not a commit
    pub fn resolve_reference<'a>(repo: &'a Repository, reference: &str) -> Result<Object<'a>> {
        // Try to resolve as a direct reference first
        let object = match repo.revparse_single(reference) {
            Ok(obj) => obj,
            Err(e) => {
                return Err(anyhow!(
                    "Failed to resolve reference '{}': {}",
                    reference,
                    e
                ));
            }
        };

        // Ensure it's a commit object
        if object.kind() != Some(ObjectType::Commit) {
            return Err(anyhow!("Reference '{}' is not a commit", reference));
        }

        Ok(object)
    }

    /// Returns git ids in reverse sorted order in time (i.e. newest first)
    ///
    /// This function is used by the Kernel struct to sort git commit IDs by their
    /// chronological order in the repository.
    ///
    /// # Panics
    ///
    /// This function may panic if:
    /// - A git ID string in the `remaining_ids` vector cannot be parsed as a valid Git Oid
    #[must_use]
    pub fn git_sort_ids(kernel_tree: &Path, ids: &Vec<String>) -> Vec<String> {
        // For optimization: if we only have one ID, just return it
        if ids.len() <= 1 {
            return ids.clone();
        }

        debug!(
            "\t\tSorting git ids {ids:?} using repository {}",
            kernel_tree.display()
        );

        // Try to open the git repository
        let repo = match Repository::open(kernel_tree) {
            Ok(repo) => repo,
            Err(e) => {
                error!("Error opening repository: {e}");
                // Keep original order for consistency
                return ids.clone();
            }
        };

        // Convert string IDs to Oid objects for lookup
        let mut valid_ids = Vec::new();

        for id_str in ids {
            match Oid::from_str(id_str) {
                Ok(oid) => {
                    // Check if the object exists in the repository
                    if repo.find_commit(oid).is_ok() {
                        // Resolve the reference and get full SHA
                        match resolve_reference(&repo, id_str) {
                            Ok(obj) => {
                                if let Ok(full_sha) = get_object_full_sha(&repo, &obj) {
                                    valid_ids.push(full_sha);
                                }
                            }
                            Err(_) => {
                                debug!("Warning: git id {id_str} not found in repository");
                            }
                        }
                    } else {
                        debug!("Warning: git id {id_str} not found in repository");
                    }
                }
                Err(e) => {
                    debug!("Warning: invalid git id {id_str}: {e}");
                }
            }
        }

        // If no valid IDs were found, return original order
        if valid_ids.is_empty() {
            debug!("No valid git IDs found, returning original order");
            return ids.clone();
        }

        // Determine the relationship between commits directly rather than using revwalk
        // This creates a directed graph of "is ancestor of" relationships
        let mut result_order = Vec::new();
        let mut remaining_ids = valid_ids.clone();

        while !remaining_ids.is_empty() {
            // Find a commit that is not an ancestor of any other remaining commit
            // This will be the newest commit among the remaining ones
            let mut newest_idx = 0;

            'outer: for i in 0..remaining_ids.len() {
                let mut is_newest = true;
                for j in 0..remaining_ids.len() {
                    if i == j {
                        continue;
                    }

                    // Use the Oid objects for comparison
                    let oid_i = Oid::from_str(&remaining_ids[i]).unwrap();
                    let oid_j = Oid::from_str(&remaining_ids[j]).unwrap();

                    if repo.graph_descendant_of(oid_j, oid_i) == Ok(true) {
                        // Found a descendant, so this one isn't the newest
                        is_newest = false;
                        break;
                    }
                    // Not a descendant or error determining relationship
                    // Continue checking (in case of unrelated history lines)
                }

                if is_newest {
                    newest_idx = i;
                    break 'outer;
                }
            }

            // If no clear newest was found (possible with unrelated history),
            // just take the first one
            result_order.push(remaining_ids.remove(newest_idx));
        }

        // Add any missing IDs that we couldn't find in the repo
        for id in ids {
            if !result_order.contains(id) && !id.is_empty() {
                result_order.push(id.clone());
            }
        }

        debug!("git_sort_ids: sorted_ids = {result_order:?}");
        result_order
    }

    /// Gets a list of files changed in a commit
    ///
    /// Used by bippy and other tools to find affected files
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The commit cannot be found in the repository
    /// - The git show command fails to execute
    ///
    /// This implementation uses direct git commands rather than libgit2,
    /// which is significantly faster (at least 200ms improvement).
    pub fn get_affected_files<'a>(_repo: &'a Repository, obj: &Object<'a>) -> Result<Vec<String>> {
        let commit_id = obj.id().to_string();

        // Get the kernel tree path to run git commands in
        let kernel_tree = crate::common::get_kernel_tree()?;
        let kernel_tree_str = kernel_tree.to_string_lossy();

        // Run git show to get the list of affected files
        // We use --pretty=format: to suppress commit info and only get file names
        // --name-only gives us just the file names that were changed
        let output = crate::cmd_utils::run_command(
            "git",
            &[
                "show",
                "--pretty=format:",
                "--name-only",
                &commit_id,
            ],
            Some(&kernel_tree_str)
        ).context("Failed to run git show command")?;

        // Split the output into lines and filter out empty lines
        let affected_files: Vec<String> = output
            .lines()
            .filter(|line| !line.is_empty())
            .map(String::from)
            .collect();

        Ok(affected_files)
    }

    /// Gets commit details as a formatted string
    ///
    /// Uses git2 to retrieve commit information and format it.
    /// Returns a string containing the short SHA and commit subject/message.
    ///
    /// # Arguments
    /// * `kernel_tree` - Path to the git repository
    /// * `git_sha` - The SHA of the commit
    /// * `format_type` - Optional format type: "details" (default) or "oneline"
    ///
    /// # Returns
    /// A string with the commit details in the specified format
    ///
    /// Note, `format_type` is currently ignored, "details" is the output for now
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The git repository cannot be opened at the specified path
    /// - The provided git SHA is not a valid format
    /// - The commit cannot be found in the repository
    pub fn get_commit_details(kernel_tree: &Path, git_sha: &str, _format_type: Option<&str>) -> Result<String> {
        let repo = Repository::open(kernel_tree).context("Failed to open git repository")?;

        // Try to resolve the reference instead of direct Oid parsing
        let object = repo
            .revparse_single(git_sha)
            .context(format!("Git SHA '{git_sha}' not found in kernel tree"))?;

        let commit = repo
            .find_commit(object.id())
            .context(format!("Commit not found: {git_sha}"))?;

        // Get short SHA and message - use the original SHA prefix if it's already short
        let short_id = if git_sha.len() <= 12 {
            git_sha.to_string() // Use the original SHA if it's already short
        } else {
            commit.id().to_string()[0..12].to_string() // Otherwise use the first 12 chars
        };
        let message = commit.summary().unwrap_or("").to_string();

        // Format based on the common kernel commit output of:
        // git show -s --abbrev-commit --abbrev=12 --pretty=format:"%h (\"%s\")%n" "${GIT_SHA_FULL}")
        Ok(format!("{short_id} (\"{message}\")"))
    }

    /// Gets the commit year from a SHA
    ///
    /// Uses git2 to retrieve a commit's timestamp and extract the year.
    /// This is useful for organizing CVEs by the year of the commit they reference.
    ///
    /// # Arguments
    /// * `kernel_tree` - Path to the git repository
    /// * `git_sha` - The SHA of the commit
    ///
    /// # Returns
    /// The year of the commit as a string (e.g., "2023")
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The git repository cannot be opened at the specified path
    /// - The provided git SHA is not a valid format
    /// - The commit cannot be found in the repository
    /// - The commit timestamp cannot be converted to a `DateTime`
    pub fn get_commit_year(kernel_tree: &Path, git_sha: &str) -> Result<String> {
        let repo = Repository::open(kernel_tree).context("Failed to open git repository")?;

        // Try to resolve the reference instead of direct Oid parsing
        let object = repo
            .revparse_single(git_sha)
            .context(format!("Git SHA '{git_sha}' not found in kernel tree"))?;

        let commit = repo
            .find_commit(object.id())
            .context(format!("Commit not found: {git_sha}"))?;

        let time = commit.time();
        let dt = DateTime::from_timestamp(time.seconds(), 0)
            .context("Failed to convert git timestamp to DateTime")?;

        Ok(dt.format("%Y").to_string())
    }

    /// Prints detailed information about a `git2::Error`
    ///
    /// This utility function extracts and prints detailed information from a `git2::Error`
    /// object, including its error code, class, and message.
    ///
    /// # Arguments
    /// * `error` - The error object that might contain a `git2::Error`
    pub fn print_git_error_details(error: &anyhow::Error) {
        // Recursively check the chain of causes
        let mut current_err: Option<&dyn std::error::Error> = Some(error.root_cause());

        while let Some(err) = current_err {
            if let Some(git_err) = err.downcast_ref::<git2::Error>() {
                eprintln!("Git error details:");
                eprintln!("  Code: {:?}", git_err.code());
                eprintln!("  Class: {:?}", git_err.class());
                eprintln!("  Message: {}", git_err.message());
                break;
            }
            current_err = err.source();
        }
    }

    /// Gets a list of modified files matching the specified patterns
    ///
    /// Searches the current git repository for modified files that match any of the
    /// provided patterns.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The git repository cannot be opened in the current directory
    /// - The repository status cannot be retrieved
    pub fn get_modified_files(patterns: &[&str]) -> Result<Vec<PathBuf>> {
        let repo = Repository::open(".").context("Failed to open git repository")?;

        let mut options = StatusOptions::new();
        options.include_untracked(true);

        let statuses = repo
            .statuses(Some(&mut options))
            .context("Failed to get git status")?;

        let mut modified_files = Vec::new();

        for entry in statuses.iter() {
            // Skip deleted files
            if entry.status() == Status::WT_DELETED {
                continue;
            }

            if let Some(path) = entry.path()
                && patterns.iter().any(|pattern| match_pattern(path, pattern)) {
                    modified_files.push(PathBuf::from(path));
                }
        }

        Ok(modified_files)
    }

    /// Simple pattern matching for file paths
    ///
    /// Supports exact matches and *.ext patterns
    #[must_use]
    pub fn match_pattern(path: &str, pattern: &str) -> bool {
        pattern.strip_prefix("*").map_or_else(
            || path == pattern, // Exact match
            |suffix| path.ends_with(suffix) // Handle *.ext pattern
        )
    }

    /// Gets the full commit message for a git SHA
    ///
    /// Uses git2 to retrieve the complete commit message for a given SHA.
    /// This is equivalent to 'git show --no-patch --format=%B'.
    ///
    /// # Arguments
    /// * `sha` - The SHA of the commit to retrieve the message for
    ///
    /// # Returns
    /// The full commit message as a string
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The git repository cannot be opened in the current directory
    /// - The provided git SHA is not a valid format
    /// - The commit cannot be found in the repository
    pub fn get_commit_message(sha: &str) -> Result<String> {
        let repo = Repository::open(".").context("Failed to open git repository")?;

        let oid = git2::Oid::from_str(sha).context(format!("Invalid Git SHA format: {sha}"))?;

        let commit = repo
            .find_commit(oid)
            .context(format!("Commit not found: {sha}"))?;

        // Get the full commit message
        let message = commit.message().unwrap_or("").to_string();

        Ok(message)
    }

    /// Gets a one-line commit summary for a git SHA
    ///
    /// Uses git2 to retrieve a one-line summary of a commit, formatted in
    /// the style of 'git show --no-patch --oneline'.
    ///
    /// # Arguments
    /// * `sha` - The SHA of the commit to retrieve the summary for
    ///
    /// # Returns
    /// A one-line summary in the format "`short_sha` summary"
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The current directory cannot be determined
    /// - Any errors from `get_commit_details` are propagated:
    ///   - The git repository cannot be opened
    ///   - The provided git SHA is not a valid format
    ///   - The commit cannot be found in the repository
    pub fn get_commit_oneline(sha: &str) -> Result<String> {
        // Use current directory as the repository path
        let current_dir = std::env::current_dir().context("Failed to get current directory")?;
        get_commit_details(&current_dir, sha, Some("oneline"))
    }
}

/// CVE file operations commonly used across tools
pub mod cve_utils {
    use anyhow::{anyhow, Context, Result};
    use std::fs;
    use std::path::Path;

    /// Extracts a CVE ID from a file path
    ///
    /// This function attempts to extract a CVE ID from a file path by examining
    /// the file name and, if necessary, its parent directory.
    ///
    /// This is a generalized version that handles:
    /// - File paths with CVE ID as the filename (with or without extension)
    /// - Paths with CVE ID in the parent directory
    /// - Paths in various formats (absolute, relative, string slices)
    /// - Support for both Path and String/&str inputs via `AsRef<Path>`
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No valid CVE ID pattern can be found in the file path or its components
    pub fn extract_cve_id_from_path<P: AsRef<Path>>(file_path: P) -> Result<String> {
        let path = file_path.as_ref();

        // First try getting a CVE ID from the filename
        if let Some(file_name) = path.file_name() {
            let file_name_str = file_name.to_string_lossy();

            // Check if the filename itself is a CVE ID
            if file_name_str.starts_with("CVE-") {
                // Handle filenames with extensions (e.g., CVE-2023-12345.mbox)
                if file_name_str.contains('.') {
                    if let Some(name_part) = file_name_str.split('.').next()
                        && name_part.starts_with("CVE-") {
                            return Ok(name_part.to_string());
                        }
                } else {
                    return Ok(file_name_str.to_string());
                }
            }

            // If filename is file stem without the "CVE-" prefix, try the parent directory
            if let Some(parent) = path.parent()
                && let Some(parent_name) = parent.file_name() {
                    let parent_str = parent_name.to_string_lossy();
                    if parent_str.starts_with("CVE-") {
                        return Ok(parent_str.to_string());
                    }

                    // Try to find CVE pattern in path components
                    for component in path.components() {
                        let comp_str = component.as_os_str().to_string_lossy();
                        if comp_str.starts_with("CVE-") {
                            return Ok(comp_str.to_string());
                        }
                    }
                }
        }

        // If we got to this point, try to find CVE pattern in the entire path string
        let path_str = path.to_string_lossy();
        for part in path_str.split(std::path::MAIN_SEPARATOR) {
            if part.starts_with("CVE-") {
                return Ok(part.to_string());
            }
        }

        // Last resort: check if any part of the path contains "CVE-YYYY-NNNNN"
        let path_str = path.to_string_lossy();
        if let Some(start) = path_str.find("CVE-") {
            let cve_part = &path_str[start..];
            if let Some(end) = cve_part.find(|c: char| !c.is_ascii_alphanumeric() && c != '-') {
                let candidate = &cve_part[..end];
                if candidate.len() >= 13
                    && candidate.starts_with("CVE-")
                    && candidate[4..8].chars().all(|c| c.is_ascii_digit())
                    && candidate[8..9] == *"-"
                    && candidate[9..].chars().all(|c| c.is_ascii_digit())
                {
                    return Ok(candidate.to_string());
                }
            } else {
                return Ok(cve_part.to_string());
            }
        }

        Err(anyhow!(
            "Could not extract CVE ID from path: {}",
            path.display()
        ))
    }

    /// Finds the next free CVE ID in a reserved directory
    ///
    /// Searches for the first empty file in the reserved directory, which
    /// indicates an available CVE ID.
    ///
    /// # Panics
    ///
    /// This function may panic if:
    /// - Reading the directory entries fails but `unwrap()` is called on the result
    /// - Processing a directory entry fails but `unwrap()` is called on the result
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The reserved directory does not exist
    /// - A file path is invalid (missing file name)
    /// - Cannot get metadata for a file
    /// - No available (empty) CVE ID files are found
    pub fn find_next_free_cve_id(reserved_dir: &Path) -> Result<String> {
        if !reserved_dir.exists() {
            return Err(anyhow!(
                "Reserved directory does not exist: {}",
                reserved_dir.display()
            ));
        }

        // Get all reserved CVE IDs
        let mut entries: Vec<_> = fs::read_dir(reserved_dir).unwrap().map(|r| r.unwrap()).collect();
        // Sort them so that we always pick the lowest number first
        entries.sort_by_key(std::fs::DirEntry::path);

        // Find the first available CVE ID (empty file)
        for entry in entries {
            let path = entry.path();

            if path.is_file() {
                let file_name = path
                    .file_name()
                    .ok_or_else(|| anyhow!("Invalid file path: {}", path.display()))?
                    .to_string_lossy();

                // Skip non-CVE files
                if !file_name.starts_with("CVE-") {
                    continue;
                }

                // Empty file means it's available
                let metadata = fs::metadata(&path)
                    .context(format!("Failed to get metadata for {}", path.display()))?;

                if metadata.len() == 0 {
                    return Ok(file_name.to_string());
                }
            }
        }

        Err(anyhow!("No available CVE IDs found in {}", reserved_dir.display()))
    }
}

/// Git configuration utilities
pub mod git_config {
    use anyhow::{anyhow, Context, Result};
    use git2::Config;

    /// Gets a value from git configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The git configuration cannot be opened
    /// - The requested key does not exist in the configuration
    pub fn get_git_config(key: &str) -> Result<String> {
        let config = Config::open_default().context("Failed to open git config")?;
        let value = config
            .get_string(key)
            .map_err(|_| anyhow!("Git config value '{}' not found", key))?;
        Ok(value)
    }

    /// Sets a value in git configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The git configuration cannot be opened
    /// - Setting the value fails (e.g., insufficient permissions)
    pub fn set_git_config(key: &str, value: &str) -> Result<()> {
        let mut config = Config::open_default().context("Failed to open git config")?;
        config
            .set_str(key, value)
            .context("Failed to set git config value")?;
        Ok(())
    }
}

/// CVE ID validation and processing
pub mod cve_validation {
    use super::common;
    use anyhow::{anyhow, Context, Result};
    use regex::Regex;
    use std::path::{Path, PathBuf};
    use walkdir::WalkDir;

    /// Extracts the year from a CVE ID using regex
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The regex pattern fails to compile
    /// - The CVE ID does not match the expected format (CVE-YYYY-NNNNN)
    pub fn extract_year_from_cve(cve_id: &str) -> Result<String> {
        let re = Regex::new(r"(?i)CVE-(\d{4})-\d+")
            .context("Failed to compile CVE regex pattern")?;

        re.captures(cve_id)
            .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
            .ok_or_else(|| anyhow!("Invalid CVE format: {}", cve_id))
    }

    /// Checks if a CVE ID is valid and exists in the repository
    ///
    /// # Errors
    ///
    /// This function returns a Result<bool> but should never fail,
    /// as it only performs file existence checks. The Result type is
    /// used for consistency with other CVE validation functions.
    pub fn is_valid_cve(cve_root: &Path, cve_entry: &str) -> Result<bool> {
        // Check if it's a valid file path
        let cve_path = Path::new(cve_entry);
        if cve_path.exists() {
            return Ok(true);
        }

        // Search in the CVE directory structure
        for entry in WalkDir::new(cve_root).into_iter().filter_map(Result::ok) {
            if entry.file_name().to_string_lossy() == cve_entry {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Finds a CVE ID by name in the CVE directory structure
    ///
    /// Returns the path to the CVE file if found, or an error if not found
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The CVE root directory cannot be found
    /// - The specified CVE ID is not found in the repository
    pub fn find_cve_id(cve_id: &str) -> Result<Option<PathBuf>> {
        let cve_root = common::get_cve_root()?;

        // Check if this is a year directory
        if cve_id.len() == 4 && cve_id.chars().all(|c| c.is_ascii_digit()) {
            return Ok(None);
        }

        // Try building path based on CVE year
        if let Ok(year) = extract_year_from_cve(cve_id) {
            // First priority: Check published directory
            let published_path = cve_root
                .join("published")
                .join(&year)
                .join(format!("{cve_id}.sha1"));
            if published_path.exists() {
                return Ok(Some(published_path));
            }

            // Second priority: Check rejected directory
            let rejected_path = cve_root
                .join("rejected")
                .join(&year)
                .join(format!("{cve_id}.sha1"));
            if rejected_path.exists() {
                return Ok(Some(rejected_path));
            }
        }

        // Fallback: Search for the specific CVE ID in the entire cve directory
        for entry in WalkDir::new(&cve_root).into_iter().filter_map(Result::ok) {
            let path = entry.path();
            if path.is_file()
                && path
                    .file_stem()
                    .is_some_and(|s| s.to_string_lossy() == cve_id)
            {
                return Ok(Some(path.to_path_buf()));
            }
        }

        Err(anyhow!("CVE ID '{}' not found", cve_id))
    }
}

/// Command execution utilities
pub mod cmd_utils {
    use anyhow::{anyhow, Context, Result};
    use std::process::Command;

    /// Runs a command and returns its output as a string
    ///
    /// # Arguments
    /// * `cmd` - The command to run
    /// * `args` - Arguments to pass to the command
    /// * `work_dir` - Optional working directory
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The command fails to execute
    /// - The command exits with a non-zero status code
    /// - The command output cannot be converted to a UTF-8 string
    pub fn run_command(cmd: &str, args: &[&str], work_dir: Option<&str>) -> Result<String> {
        let mut command = Command::new(cmd);
        command.args(args);

        if let Some(dir) = work_dir {
            command.current_dir(dir);
        }

        let output = command
            .output()
            .context(format!("Failed to execute: {cmd} {args:?}"))?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!(
                "Command failed: {} {:?}\nError: {}",
                cmd,
                args,
                error
            ));
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
}

/// Year utilities for CVE management
pub mod year_utils {
    use anyhow::Result;
    use chrono::Datelike;
    use std::path::Path;

    /// Checks if a string is a valid year (4 digits, reasonable range)
    ///
    /// A year is considered valid if it's 4 digits and between 2000 and current year + 1
    #[must_use]
    pub fn is_valid_year(year: &str) -> bool {
        if year.len() != 4 || !year.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }

        let year_num = year.parse::<i32>().unwrap_or(0);
        let current_year = chrono::Utc::now().year();

        (2000..=current_year + 1).contains(&year_num)
    }

    /// Checks if a year directory exists in the CVE root
    ///
    /// # Errors
    ///
    /// This function returns a Result<bool> but should never fail,
    /// as it only performs file existence checks. The Result type is
    /// used for consistency with other CVE validation functions.
    pub fn is_year_dir_exists(cve_root: &Path, year: &str) -> Result<bool> {
        let published_year_dir = cve_root.join("published").join(year);
        let rejected_year_dir = cve_root.join("rejected").join(year);

        Ok(published_year_dir.exists() || rejected_year_dir.exists())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_vulns_dir() {
        // This test assumes it's running within the vulns project
        let result = common::find_vulns_dir();
        assert!(result.is_ok(), "Should find the vulns directory");

        let vulns_dir = result.unwrap();
        assert!(vulns_dir.ends_with("vulns"), "Path should end with 'vulns'");
        assert!(
            vulns_dir.join("cve").exists(),
            "cve directory should exist in vulns dir"
        );
    }

    #[test]
    fn test_get_cve_root() {
        let result = common::get_cve_root();
        assert!(result.is_ok(), "Should find the CVE root directory");

        let cve_root = result.unwrap();
        assert!(cve_root.ends_with("cve"), "Path should end with 'cve'");
        assert!(
            cve_root.join("published").exists(),
            "published directory should exist in CVE root"
        );
    }

    #[test]
    fn test_short_sha_handling() {
        // This test will only work when run in a git repository
        // It verifies that partial SHAs are handled correctly
        let current_dir = std::env::current_dir().unwrap();

        // Use a fake short SHA for testing - this should fail gracefully
        // but not with a padding error.
        let result = git_utils::get_commit_details(&current_dir, "b807b7c81a6d", None);

        // We expect an error, but it should NOT contain zero padding
        assert!(result.is_err(), "Result should be an error for invalid SHA");
        let err = result.unwrap_err().to_string();
        assert!(!err.contains("0000000000000000000000000000"),
                "Error shouldn't contain zero padding");
        // Don't assert on specific error message text as it may vary
    }

    // --- Tests for extract_cve_id_from_path ---

    #[test]
    fn test_extract_cve_id_from_filename_with_extension() {
        let result = cve_utils::extract_cve_id_from_path("published/2024/CVE-2024-12345.sha1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "CVE-2024-12345");
    }

    #[test]
    fn test_extract_cve_id_from_filename_mbox() {
        let result = cve_utils::extract_cve_id_from_path("published/2024/CVE-2024-12345.mbox");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "CVE-2024-12345");
    }

    #[test]
    fn test_extract_cve_id_from_filename_json() {
        let result = cve_utils::extract_cve_id_from_path("published/2024/CVE-2024-12345.json");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "CVE-2024-12345");
    }

    #[test]
    fn test_extract_cve_id_from_parent_dir() {
        let result = cve_utils::extract_cve_id_from_path("published/2024/CVE-2024-12345/file.json");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "CVE-2024-12345");
    }

    #[test]
    fn test_extract_cve_id_from_deeper_path_component() {
        let result = cve_utils::extract_cve_id_from_path("data/CVE-2023-99999/subdir/notes.txt");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "CVE-2023-99999");
    }

    #[test]
    fn test_extract_cve_id_from_bare_filename() {
        let result = cve_utils::extract_cve_id_from_path("CVE-2024-00001");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "CVE-2024-00001");
    }

    #[test]
    fn test_extract_cve_id_no_cve_in_path() {
        let result = cve_utils::extract_cve_id_from_path("published/2024/somefile.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_cve_id_from_filename_no_extension() {
        let result = cve_utils::extract_cve_id_from_path("published/2024/CVE-2024-12345");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "CVE-2024-12345");
    }

    // --- Tests for extract_year_from_cve ---

    #[test]
    fn test_extract_year_valid_cve() {
        let result = cve_validation::extract_year_from_cve("CVE-2024-12345");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "2024");
    }

    #[test]
    fn test_extract_year_old_cve() {
        let result = cve_validation::extract_year_from_cve("CVE-2000-0001");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "2000");
    }

    #[test]
    fn test_extract_year_not_a_cve() {
        let result = cve_validation::extract_year_from_cve("not-a-cve");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_year_invalid_year_letters() {
        let result = cve_validation::extract_year_from_cve("CVE-XXXX-12345");
        assert!(result.is_err());
    }

    // --- Tests for match_pattern ---

    #[test]
    fn test_match_pattern_exact() {
        assert!(git_utils::match_pattern("drivers/net/foo.c", "drivers/net/foo.c"));
    }

    #[test]
    fn test_match_pattern_glob_suffix_match() {
        assert!(git_utils::match_pattern("foo.c", "*.c"));
    }

    #[test]
    fn test_match_pattern_glob_suffix_no_match() {
        assert!(!git_utils::match_pattern("foo.c", "*.h"));
    }

    #[test]
    fn test_match_pattern_no_match() {
        assert!(!git_utils::match_pattern("other/file.c", "drivers/net/foo.c"));
    }

    #[test]
    fn test_match_pattern_glob_deep_path() {
        assert!(git_utils::match_pattern("drivers/net/ethernet/intel/e1000e/netdev.c", "*.c"));
    }

    // --- Tests for is_valid_year ---

    #[test]
    fn test_is_valid_year_current() {
        assert!(year_utils::is_valid_year("2024"));
    }

    #[test]
    fn test_is_valid_year_2000() {
        assert!(year_utils::is_valid_year("2000"));
    }

    #[test]
    fn test_is_valid_year_below_2000() {
        assert!(!year_utils::is_valid_year("1999"));
    }

    #[test]
    fn test_is_valid_year_not_digits() {
        assert!(!year_utils::is_valid_year("abcd"));
    }

    #[test]
    fn test_is_valid_year_too_short() {
        assert!(!year_utils::is_valid_year("202"));
    }

    #[test]
    fn test_is_valid_year_too_long() {
        assert!(!year_utils::is_valid_year("20245"));
    }

    #[test]
    fn test_is_valid_year_empty() {
        assert!(!year_utils::is_valid_year(""));
    }
}
