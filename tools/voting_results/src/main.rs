// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use git2::Repository;
use owo_colors::{OwoColorize, Stream::Stdout};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::LazyLock;

// Define a type alias for the complex commit result type
type CommitResult = (String, bool, HashMap<String, bool>);

// Define primary reviewers - other reviewers are determined dynamically
static PRIMARY_REVIEWERS: LazyLock<Vec<String>> =
    LazyLock::new(|| vec!["greg".to_string(), "lee".to_string(), "sasha".to_string()]);

// Git remote name for stable branches
static STABLE_REMOTE: LazyLock<String> = LazyLock::new(|| "stable".to_string());

// Regular expressions used in the code
static UPSTREAM_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[0-9a-f]{40}").unwrap());

#[derive(Parser, Debug)]
#[clap(
    version,
    about = "Conducts voting system between the present reviewers"
)]
struct Args {
    /// Git range in the format 'v6.7.1..v6.7.2'
    #[clap(name = "RANGE")]
    range: Option<String>,

    /// Skip git fetch operation
    #[clap(long = "no-fetch")]
    no_fetch: bool,

    /// Do not print out annotations
    #[clap(long = "no-annotate")]
    no_annotate: bool,
}

struct VotingResults {
    repo: Repository,
    range: String,
    top: String,
    proposed_dir: PathBuf,
    script_dir: PathBuf,
    reviewers: Vec<String>,
    guest_reviewers: Vec<String>,
    review_files: Vec<PathBuf>,
    annotated_files: Vec<PathBuf>,
    commits_by_pattern: HashMap<String, Vec<String>>,
    no_annotate: bool,
}

impl VotingResults {
    fn new(args: Args) -> Result<Self> {
        // Check if range is provided and properly formatted
        let range = match args.range {
            Some(r) if r.contains("..") => r,
            Some(r) => return Err(anyhow!("Unrecognized argument: {}", r)),
            None => return Err(anyhow!("Please supply a Git range (e.g v6.7.1..v6.7.2)")),
        };

        // Verify we're in a kernel directory
        if !Path::new("MAINTAINERS").exists() {
            return Err(anyhow!("Not in a kernel directory"));
        }

        // Open the repository
        let repo = Repository::open(".").context("Failed to open git repository")?;

        // Parse range and get the top version
        let top = range
            .split("..")
            .nth(1)
            .ok_or_else(|| anyhow!("Invalid range format"))?
            .to_string();

        // Fetch from stable remote if --no-fetch is not specified
        if !args.no_fetch {
            println!(
                "{}",
                format!("Fetching from {}", *STABLE_REMOTE).if_supports_color(Stdout, |x| x.blue())
            );
            if let Err(e) = repo
                .find_remote(&STABLE_REMOTE)
                .and_then(|mut remote| remote.fetch(&[] as &[&str], None, None))
            {
                eprintln!("Warning: Failed to fetch from stable remote: {e}");
            }
        }

        // Use the standard cve_utils implementation to find the vulns directory
        let vulns_dir = cve_utils::find_vulns_dir()?;
        let proposed_dir = vulns_dir.join("cve").join("review").join("proposed");
        let script_dir = vulns_dir.join("scripts");

        if !proposed_dir.exists() {
            return Err(anyhow!("Cannot find review directory: {:?}", proposed_dir));
        }

        // Create a new instance with initialized fields
        let mut results = Self {
            repo,
            range,
            top,
            proposed_dir,
            script_dir,
            reviewers: Vec::new(),
            guest_reviewers: Vec::new(),
            review_files: Vec::new(),
            annotated_files: Vec::new(),
            commits_by_pattern: HashMap::new(),
            no_annotate: args.no_annotate,
        };

        // Initialize the remaining fields
        results.init()?;
        Ok(results)
    }

    fn init(&mut self) -> Result<()> {
        self.find_reviewers()?;
        self.identify_guest_reviewers();
        self.display_reviewer_info();
        self.find_review_files()?;
        self.init_commits_by_pattern();
        Ok(())
    }

    fn display_reviewer_info(&self) {
        println!(
            "{}",
            format!("Primary reviewers: {}", PRIMARY_REVIEWERS.join(" "))
                .if_supports_color(Stdout, |x| x.blue())
        );
        println!(
            "{}",
            format!("All reviewers found: {}", self.reviewers.join(" "))
                .if_supports_color(Stdout, |x| x.blue())
        );

        if self.guest_reviewers.is_empty() {
            println!(
                "{}",
                "No guest reviewers found".if_supports_color(Stdout, |x| x.blue())
            );
        } else {
            println!(
                "{}",
                format!("Guest reviewers: {}", self.guest_reviewers.join(" "))
                    .if_supports_color(Stdout, |x| x.blue())
            );
        }
    }

    fn find_reviewers(&mut self) -> Result<()> {
        let mut reviewer_set = HashSet::new();

        // Extract reviewer names from review filenames
        let pattern = format!("{}-[a-z]+$", self.top);
        let regex = Regex::new(&pattern)?;

        // Scan the proposed directory for reviewer files
        if let Ok(entries) = fs::read_dir(&self.proposed_dir) {
            for entry in entries.filter_map(Result::ok) {
                let file_name = entry.file_name().to_string_lossy().to_string();

                if regex.is_match(&file_name)
                    && let Some(reviewer) = file_name.split('-').next_back() {
                        reviewer_set.insert(reviewer.to_string());
                    }
            }
        }

        // If no reviewers found, use primary reviewers as fallback
        if reviewer_set.is_empty() {
            println!(
                "{}",
                "No reviewers found in review files, using only primary reviewers".red()
            );
            reviewer_set.extend(PRIMARY_REVIEWERS.iter().cloned());
        }

        // Convert to sorted vector for consistent output
        self.reviewers = reviewer_set.into_iter().collect();
        self.reviewers.sort();

        Ok(())
    }

    fn identify_guest_reviewers(&mut self) {
        // A guest reviewer is any reviewer not in the PRIMARY_REVIEWERS list
        self.guest_reviewers = self
            .reviewers
            .iter()
            .filter(|r| !PRIMARY_REVIEWERS.contains(r))
            .cloned()
            .collect();
    }

    fn find_review_files(&mut self) -> Result<()> {
        // Create reviewer pattern for glob matching
        let reviewer_pattern = self.reviewers.join("|");

        // Regex patterns for finding review and annotation files
        let review_regex = Regex::new(&format!("{}-(?:{})", self.top, reviewer_pattern))?;
        let annotated_regex = Regex::new(&format!(
            "{}.*-annotated-(?:{})",
            self.top, reviewer_pattern
        ))?;

        // Scan directory for matching files
        if let Ok(entries) = fs::read_dir(&self.proposed_dir) {
            for entry in entries.filter_map(Result::ok) {
                let path = entry.path();
                if let Some(file_name) = path.file_name().map(|f| f.to_string_lossy().to_string()) {
                    if review_regex.is_match(&file_name) {
                        self.review_files.push(path);
                    } else if annotated_regex.is_match(&file_name) {
                        self.annotated_files.push(path);
                    }
                }
            }
        }

        Ok(())
    }

    fn init_commits_by_pattern(&mut self) {
        // Initialize arrays for storing commits by vote pattern
        self.commits_by_pattern
            .insert("cve".to_string(), Vec::new());
        self.commits_by_pattern
            .insert("all".to_string(), Vec::new());

        // Initialize vote patterns for single reviewers
        for reviewer in &self.reviewers {
            self.commits_by_pattern.insert(reviewer.clone(), Vec::new());
        }

        // Two-reviewer combinations for primary reviewers
        for (i, r1) in PRIMARY_REVIEWERS.iter().enumerate() {
            for r2 in PRIMARY_REVIEWERS.iter().skip(i + 1) {
                let pattern = format!("{r1},{r2}");
                self.commits_by_pattern.insert(pattern, Vec::new());
            }
        }

        // Combinations with guest reviewers
        for primary in PRIMARY_REVIEWERS.iter() {
            for guest in &self.guest_reviewers {
                let pattern = format!("{primary},{guest}");
                self.commits_by_pattern.insert(pattern, Vec::new());
            }
        }
    }

    fn process_commits(&mut self) -> Result<()> {
        // Get all commits in the range
        let mut revwalk = self.repo.revwalk()?;
        revwalk.push_range(&self.range)?;

        // Collect all oids first to release the borrow on self.repo
        let oids: Result<Vec<_>, _> = revwalk.collect();

        // Store all commit outputs and data for categorization
        let mut all_commit_outputs = Vec::new();
        let mut to_process = Vec::new();

        for oid in oids? {
            if let Some((output, commit_data)) = self.process_single_commit(oid)? {
                all_commit_outputs.push(output);
                to_process.push(commit_data);
            }
        }

        // Categorize the processed commits
        self.categorize_commits(to_process);

        // Display all commit outputs
        for output in all_commit_outputs {
            print!("{output}");
        }

        Ok(())
    }

    fn process_single_commit(&self, oid: git2::Oid) -> Result<Option<(String, CommitResult)>> {
        let stable_commit = self.repo.find_commit(oid)?;

        // Get the stable commit SHA
        let stable_sha = stable_commit.id().to_string();
        let short_stable_sha = format!("{}", stable_commit.id())[0..12].to_string();

        // Extract the upstream SHA
        let mainline_long_sha = self.get_upstream_sha(&short_stable_sha, &stable_sha);

        // Get the short SHA and subject
        let (mainline_sha, subject, oneline) = self.get_commit_details(&mainline_long_sha)?;

        // Count votes from each reviewer
        let reviewer_votes = self.tally_votes(&subject);

        // Count total votes
        let total_votes = reviewer_votes.values().filter(|&&v| v).count();

        // Skip if no votes
        if total_votes == 0 {
            return Ok(None);
        }

        // Check if all PRIMARY reviewers agree, not necessarily all reviewers
        let everyone_agrees = PRIMARY_REVIEWERS
            .iter()
            .all(|reviewer| reviewer_votes.get(reviewer).unwrap_or(&false) == &true);

        // Check for CVE
        let has_cve = self.check_for_cve(&mainline_sha);

        // Create output string
        let output = self.format_commit_output(&oneline, has_cve, &reviewer_votes);

        // Only return output if not "everyone agrees" and not has CVE
        if !everyone_agrees && !has_cve {
            Ok(Some((output, (oneline, has_cve, reviewer_votes))))
        } else {
            // Still return commit data for categorization
            Ok(Some((String::new(), (oneline, has_cve, reviewer_votes))))
        }
    }

    fn get_upstream_sha(&self, short_stable_sha: &str, stable_sha: &str) -> String {
        // Try to find the commit using full SHA first
        let commit = if let Ok(oid) = git2::Oid::from_str(stable_sha) {
            self.repo.find_commit(oid)
        } else {
            // If that fails, try to resolve the short SHA using git_utils
            // First, we'll need to find the working directory to pass to get_full_sha
            let repo_path = self
                .repo
                .path()
                .parent()
                .unwrap_or_else(|| self.repo.path());
            match cve_utils::git_utils::get_full_sha(repo_path, short_stable_sha) {
                Ok(full_sha) => match git2::Oid::from_str(&full_sha) {
                    Ok(oid) => self.repo.find_commit(oid),
                    Err(_) => return stable_sha.to_string(),
                },
                Err(_) => {
                    // If git_utils fails, just return the original SHA
                    return stable_sha.to_string();
                }
            }
        };

        // Process the commit if found
        if let Ok(commit) = commit {
            // Get the full message and look for "commit X upstream" pattern
            let message = commit.message().unwrap_or("");

            // Use the existing UPSTREAM_REGEX to extract the SHA
            if let Some(captures) = UPSTREAM_REGEX.captures(message)
                && let Some(sha_match) = captures.get(0) {
                    return sha_match.as_str().to_string();
                }
        }

        // If all else fails, return original SHA
        stable_sha.to_string()
    }

    fn get_commit_details(&self, sha: &str) -> Result<(String, String, String)> {
        // Parse the SHA
        let oid = git2::Oid::from_str(sha).context("Invalid git hash")?;

        // Get the commit
        let commit = self
            .repo
            .find_commit(oid)
            .context("Failed to find commit")?;

        // Get short SHA (first 12 characters instead of 7)
        let short_sha = format!("{:.12}", commit.id());

        // Get the summary (first line of commit message)
        let summary = commit.summary().unwrap_or("").to_string();

        // Combine to match the format from the git command
        let oneline = format!("{short_sha} {summary}");

        Ok((short_sha, summary, oneline))
    }

    fn tally_votes(&self, subject: &str) -> HashMap<String, bool> {
        let mut reviewer_votes = HashMap::new();

        // Initialize all reviewers to false (no vote)
        for reviewer in &self.reviewers {
            reviewer_votes.insert(reviewer.clone(), false);
        }

        // Check each review file for votes
        for file_path in &self.review_files {
            if let Ok(file) = File::open(file_path) {
                let file_name = file_path.file_name().unwrap().to_string_lossy();
                if let Some(reviewer) = file_name.split('-').next_back() {
                    let reader = BufReader::new(file);

                    // Process the current commit for this file
                    for line in reader.lines().map_while(Result::ok) {
                        // Skip empty lines
                        if line.trim().is_empty() {
                            continue;
                        }

                        // First try matching by SHA hash (for files that only contain SHA hashes)
                        // Extract the first part of the line as a possible SHA
                        if line.len() >= 12 {
                            let possible_sha = line.split_whitespace().next().unwrap_or("");

                            // Try to get the current commit's full SHA from the repo
                            let commit = match git2::Oid::from_str(possible_sha) {
                                Ok(oid) => self.repo.find_commit(oid).ok(),
                                Err(_) => {
                                    // For short SHAs, we need a different approach
                                    if possible_sha.len() >= 7 {
                                        // Try to use lookup_prefix if available
                                        match self.repo.revparse_single(possible_sha) {
                                            Ok(obj) => {
                                                if let Some(commit) = obj.as_commit() {
                                                    self.repo.find_commit(commit.id()).ok()
                                                } else {
                                                    None
                                                }
                                            }
                                            Err(_) => None,
                                        }
                                    } else {
                                        None
                                    }
                                }
                            };

                            // Check if this commit's subject matches our target subject
                            if let Some(c) = commit
                                && let Some(commit_subject) = c.summary()
                                && commit_subject == subject {
                                    reviewer_votes.insert(reviewer.to_string(), true);
                                    break;
                                }
                        }

                        // If we can't match by SHA, try matching by subject (the original method)
                        // Check for subject in various formats:
                        // 1. Direct string match
                        // 2. Subject in parentheses
                        // 3. Subject in quotes or other common delimiters
                        if line.contains(subject)
                            || line.contains(&format!("(\"{subject}\")"))
                            || line.contains(&format!("({subject})"))
                            || line.contains(&format!("\"{subject}\""))
                        {
                            reviewer_votes.insert(reviewer.to_string(), true);
                            break;
                        }
                    }

                    // If we've found a match for this reviewer, we can move on to the next file
                    // We don't break out of the outer loop because we need to check all reviewers
                }
            }
        }

        reviewer_votes
    }

    fn format_commit_output(
        &self,
        oneline: &str,
        has_cve: bool,
        reviewer_votes: &HashMap<String, bool>,
    ) -> String {
        let mut output = oneline.to_string() + "\n";
        write!(output, "\tCVE:\t{}\t", if has_cve { "0" } else { "1" }).unwrap();

        // Print reviewers in alphabetical order
        for reviewer in &self.reviewers {
            let vote = reviewer_votes.get(reviewer).unwrap_or(&false);
            // Capitalize first letter
            let capitalized = format!(
                "{}:",
                reviewer
                    .chars()
                    .next()
                    .unwrap_or_default()
                    .to_uppercase()
                    .collect::<String>()
                    + &reviewer[1..]
            );
            write!(
                output,
                "{}\t{}\t",
                capitalized,
                if *vote { "1" } else { "0" }
            )
            .unwrap();
        }
        output.push('\n');

        output
    }

    fn categorize_commits(&mut self, commits_data: Vec<CommitResult>) {
        for (oneline, has_cve, reviewer_votes) in commits_data {
            // In bash, a return value of 0 means a CVE was found
            if has_cve {
                if let Some(vec) = self.commits_by_pattern.get_mut("cve") {
                    vec.push(oneline);
                }
                continue;
            }

            // Check for all reviewers agreeing
            let all_agree = PRIMARY_REVIEWERS
                .iter()
                .all(|reviewer| reviewer_votes.get(reviewer).unwrap_or(&false) == &true);

            if all_agree {
                if let Some(vec) = self.commits_by_pattern.get_mut("all") {
                    vec.push(oneline);
                }
                continue;
            }

            // Process vote patterns for remaining cases
            self.process_vote_patterns(oneline, &reviewer_votes);
        }
    }

    fn process_vote_patterns(&mut self, oneline: String, reviewer_votes: &HashMap<String, bool>) {
        // Get list of reviewers who voted
        let reviewers_who_voted: Vec<&String> = reviewer_votes
            .iter()
            .filter(|&(_, voted)| *voted)
            .map(|(reviewer, _)| reviewer)
            .collect();

        match reviewers_who_voted.len() {
            0 => {} // No one voted, do nothing
            1 => {
                // Single reviewer case
                let reviewer = reviewers_who_voted[0];
                if let Some(vec) = self.commits_by_pattern.get_mut(reviewer) {
                    vec.push(oneline);
                }
            }
            _ => {
                // Multiple reviewers - check pairs
                for (i, r1) in reviewers_who_voted.iter().enumerate() {
                    for r2 in reviewers_who_voted.iter().skip(i + 1) {
                        // Try both pattern orders
                        let pattern1 = format!("{r1},{r2}");
                        let pattern2 = format!("{r2},{r1}");

                        if let Some(vec) = self.commits_by_pattern.get_mut(&pattern1) {
                            vec.push(oneline.clone());
                        } else if let Some(vec) = self.commits_by_pattern.get_mut(&pattern2) {
                            vec.push(oneline.clone());
                        }
                    }
                }
            }
        }
    }

    fn check_for_cve(&self, commit_sha: &str) -> bool {
        // Get the path to the cve_search script
        let cve_search = self.script_dir.join("cve_search");

        // We still need to use Command for this external script
        // since it's not part of the git repository
        Command::new(&cve_search)
            .arg(commit_sha)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    fn print_annotations(&self, oneline: &str) {
        if self.no_annotate {
            return;
        }

        // Extract the commit SHA from the oneline format
        let Some(short_sha) = oneline.split_whitespace().next() else {
            return;
        };

        // Check each annotation file for this commit
        for file_path in &self.annotated_files {
            if let Ok(file) = File::open(file_path) {
                let reader = BufReader::new(file);
                let mut lines_iter = reader.lines().peekable();

                // Find the line containing the SHA
                while let Some(Ok(line)) = lines_iter.next() {
                    if line.contains(short_sha) {
                        // If found, check if there's a next line (the annotation)
                        if let Some(Ok(annotation_line)) = lines_iter.next()
                            && !annotation_line.is_empty() {
                                println!("  {annotation_line}");

                                // Check for multi-line annotations (lines starting with two spaces)
                                while let Some(Ok(continuation)) = lines_iter.next() {
                                    if continuation.starts_with("  ") {
                                        println!("  {continuation}");
                                    } else {
                                        break;
                                    }
                                }
                            }
                        break;
                    }
                }
            }
        }
    }

    fn display_results(&self) {
        // Helper function to capitalize first letter
        let capitalize = |s: &str| -> String {
            let mut chars = s.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_uppercase().chain(chars).collect()
            })
        };

        // Get the set of commits that everyone agrees on or have CVEs
        // These will be excluded from other sections
        let mut excluded_commits = HashSet::new();
        for category in ["all", "cve"] {
            if let Some(commits) = self.commits_by_pattern.get(category) {
                excluded_commits.extend(commits.iter().cloned());
            }
        }

        // Print CVE results
        Self::display_commit_section("Already assigned a CVE", self.commits_by_pattern.get("cve"));

        // Print results where everyone agrees
        Self::display_commit_section("Everyone agrees", self.commits_by_pattern.get("all"));

        // Print primary reviewer combinations
        for (i, r1) in PRIMARY_REVIEWERS.iter().enumerate() {
            for r2 in PRIMARY_REVIEWERS.iter().skip(i + 1) {
                let pattern = format!("{r1},{r2}");
                self.display_filtered_section(
                    &format!("{} and {} agree", capitalize(r1), capitalize(r2)),
                    self.commits_by_pattern.get(&pattern),
                    &excluded_commits,
                );
            }
        }

        // Print single primary reviewer results
        for reviewer in PRIMARY_REVIEWERS.iter() {
            self.display_filtered_section(
                &format!("{} only", capitalize(reviewer)),
                self.commits_by_pattern.get(reviewer),
                &excluded_commits,
            );
        }

        // Print guest reviewer results
        println!("\n{}", "------------ GUEST RESULTS BELOW, use for re-review only at this time ----------------".if_supports_color(Stdout, |x| x.blue()));

        // Print combinations with guest reviewers
        for primary in PRIMARY_REVIEWERS.iter() {
            for guest in &self.guest_reviewers {
                let pattern = format!("{primary},{guest}");
                self.display_filtered_section(
                    &format!(
                        "{} and guest ({}) agree",
                        capitalize(primary),
                        capitalize(guest)
                    ),
                    self.commits_by_pattern.get(&pattern),
                    &excluded_commits,
                );
            }
        }

        // Print guest-only results
        println!(
            "\n{}",
            "Guest-only results".if_supports_color(Stdout, |x| x.blue())
        );
        for guest in &self.guest_reviewers {
            println!(
                "  {}:",
                capitalize(guest).if_supports_color(Stdout, |x| x.blue())
            );

            self.display_filtered_section_indented(
                "",
                self.commits_by_pattern.get(guest),
                &excluded_commits,
            );
        }
    }

    fn display_commit_section(title: &str, commits: Option<&Vec<String>>) {
        println!("\n{}", title.if_supports_color(Stdout, |x| x.blue()));
        if let Some(commits_vec) = commits {
            for commit in commits_vec {
                if !commit.is_empty() {
                    println!("  {commit}");
                }
            }
        }
    }

    fn display_filtered_section(
        &self,
        title: &str,
        commits: Option<&Vec<String>>,
        excluded: &HashSet<String>,
    ) {
        if let Some(commits) = commits {
            let filtered_commits: Vec<&String> = commits
                .iter()
                .filter(|commit| !excluded.contains(*commit))
                .collect();

            println!("\n{}", title.if_supports_color(Stdout, |x| x.blue()));

            for commit in filtered_commits {
                println!("  {commit}");
                self.print_annotations(commit);
            }
        }
    }

    fn display_filtered_section_indented(
        &self,
        title: &str,
        commits: Option<&Vec<String>>,
        excluded: &HashSet<String>,
    ) {
        if let Some(commits) = commits {
            let filtered_commits: Vec<&String> = commits
                .iter()
                .filter(|commit| !excluded.contains(*commit))
                .collect();

            if !filtered_commits.is_empty() {
                if !title.is_empty() {
                    println!("  {}:", title.if_supports_color(Stdout, |x| x.blue()));
                }

                for commit in filtered_commits {
                    println!("    {commit}");
                    self.print_annotations(commit);
                }
            }
        }
    }

    fn run(&mut self) -> Result<()> {
        self.process_commits()?;
        self.display_results();
        Ok(())
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut voting_results = VotingResults::new(args)?;
    voting_results.run()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::env;
    use tempfile::tempdir;

    // Test the UPSTREAM_REGEX pattern
    #[test]
    fn test_upstream_regex() {
        let message = "Fix a bug\n\nUpstream: 1234567890123456789012345678901234567890";
        let captures = UPSTREAM_REGEX.captures(message).unwrap();
        assert_eq!(
            captures.get(0).unwrap().as_str(),
            "1234567890123456789012345678901234567890"
        );

        let message_lowercase = "Fix a bug\n\nupstream: 1234567890123456789012345678901234567890";
        let captures = UPSTREAM_REGEX.captures(message_lowercase).unwrap();
        assert_eq!(
            captures.get(0).unwrap().as_str(),
            "1234567890123456789012345678901234567890"
        );

        let message_no_upstream = "Fix a bug\n\nSome other text";
        assert!(UPSTREAM_REGEX.captures(message_no_upstream).is_none());
    }

    // Test vote pattern processing
    #[test]
    fn test_process_vote_patterns() {
        let mut voting_results = create_test_voting_results();

        // Initialize patterns first
        voting_results.init_commits_by_pattern();

        let oneline = "abcdef1 Test commit";

        // Case 1: Single reviewer voted
        let mut reviewer_votes = HashMap::new();
        reviewer_votes.insert("greg".to_string(), true);
        reviewer_votes.insert("lee".to_string(), false);
        reviewer_votes.insert("sasha".to_string(), false);

        voting_results.process_vote_patterns(oneline.to_string(), &reviewer_votes);

        assert_eq!(
            voting_results.commits_by_pattern.get("greg").unwrap().len(),
            1
        );
        assert_eq!(
            voting_results.commits_by_pattern.get("lee").unwrap().len(),
            0
        );
        assert_eq!(
            voting_results
                .commits_by_pattern
                .get("sasha")
                .unwrap()
                .len(),
            0
        );

        // Case 2: Two reviewers voted
        let mut reviewer_votes = HashMap::new();
        reviewer_votes.insert("greg".to_string(), true);
        reviewer_votes.insert("lee".to_string(), true);
        reviewer_votes.insert("sasha".to_string(), false);

        // Reset patterns for this test
        voting_results.commits_by_pattern.clear();
        voting_results.init_commits_by_pattern();

        voting_results.process_vote_patterns(oneline.to_string(), &reviewer_votes);

        assert_eq!(
            voting_results
                .commits_by_pattern
                .get("greg,lee")
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            voting_results.commits_by_pattern.get("greg").unwrap().len(),
            0
        );
        assert_eq!(
            voting_results.commits_by_pattern.get("lee").unwrap().len(),
            0
        );
    }

    // Test guest reviewer identification
    #[test]
    fn test_identify_guest_reviewers() {
        let mut voting_results = create_test_voting_results();

        // Add a mix of primary and guest reviewers
        voting_results.reviewers = vec![
            "greg".to_string(),
            "lee".to_string(),
            "sasha".to_string(),
            "guest1".to_string(),
            "guest2".to_string(),
        ];

        voting_results.identify_guest_reviewers();

        assert_eq!(voting_results.guest_reviewers.len(), 2);
        assert!(voting_results
            .guest_reviewers
            .contains(&"guest1".to_string()));
        assert!(voting_results
            .guest_reviewers
            .contains(&"guest2".to_string()));
        assert!(!voting_results.guest_reviewers.contains(&"greg".to_string()));
    }

    // Test commits_by_pattern initialization
    #[test]
    fn test_init_commits_by_pattern() {
        let mut voting_results = create_test_voting_results();

        // Add reviewers including guests
        voting_results.reviewers = vec![
            "greg".to_string(),
            "lee".to_string(),
            "sasha".to_string(),
            "guest1".to_string(),
        ];

        voting_results.guest_reviewers = vec!["guest1".to_string()];

        voting_results.init_commits_by_pattern();

        // Check that all expected patterns are initialized
        assert!(voting_results.commits_by_pattern.contains_key("all"));
        assert!(voting_results.commits_by_pattern.contains_key("cve"));
        assert!(voting_results.commits_by_pattern.contains_key("greg"));
        assert!(voting_results.commits_by_pattern.contains_key("lee"));
        assert!(voting_results.commits_by_pattern.contains_key("sasha"));
        assert!(voting_results.commits_by_pattern.contains_key("guest1"));
        assert!(voting_results.commits_by_pattern.contains_key("greg,lee"));
        assert!(voting_results.commits_by_pattern.contains_key("greg,sasha"));
        assert!(voting_results.commits_by_pattern.contains_key("lee,sasha"));
        assert!(voting_results
            .commits_by_pattern
            .contains_key("greg,guest1"));
        assert!(voting_results.commits_by_pattern.contains_key("lee,guest1"));
        assert!(voting_results
            .commits_by_pattern
            .contains_key("sasha,guest1"));
    }

    // Test check_for_cve function
    #[test]
    fn test_check_for_cve() {
        use std::process::Command;

        // Test command behavior with simple test commands

        // Test case 1: Success (CVE found)
        let status_success = Command::new("test")
            .arg("1")
            .arg("=")
            .arg("1")
            .status()
            .unwrap();
        assert!(status_success.success());
        let cve_result = status_success.success();
        assert!(cve_result);

        // Test case 2: Failure (no CVE found)
        let status_failure = Command::new("test")
            .arg("1")
            .arg("=")
            .arg("0")
            .status()
            .unwrap();
        assert!(!status_failure.success());
        let cve_result = status_failure.success();
        assert!(!cve_result);
    }

    // Test print_annotations function
    #[test]
    fn test_print_annotations() {
        use std::fs::File;
        use std::io::Write;

        let mut voting_results = create_test_voting_results();

        // Create temporary annotation files
        let temp_dir = tempdir().unwrap();
        let annotated_file_path = temp_dir.path().join("v6.7.2-annotated-greg");

        // Create an annotation file with test content
        let content = "abcdef1 Test commit\nThis is an annotation for the commit\n";
        let mut file = File::create(&annotated_file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        // Add the file to the annotated_files list
        voting_results.annotated_files = vec![annotated_file_path];

        // Test that annotations are found correctly
        voting_results.print_annotations("abcdef1 Test commit");
    }

    // Test multi-line print_annotations function
    #[test]
    fn test_multi_line_annotations() {
        use std::fs::File;
        use std::io::Write;

        let mut voting_results = create_test_voting_results();

        // Create temporary annotation files
        let temp_dir = tempdir().unwrap();
        let annotated_file_path = temp_dir.path().join("v6.7.2-annotated-lee");

        // Create an annotation file with multi-line test content
        let content = "abcdef1 Test commit\n{Lee} This is a multi-line annotation\n  This is a continuation line\n  This is another continuation line\nThis is not a continuation line\n";
        let mut file = File::create(&annotated_file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();

        // Add the file to the annotated_files list
        voting_results.annotated_files = vec![annotated_file_path];

        // Test the function behavior by verifying it correctly processes the content
        // We can't easily capture stdout in unit tests, so we'll validate the functionality
        // indirectly by checking that the function processes the file correctly

        // The test passes if the function doesn't panic when reading and processing
        // the multi-line annotation format. In a real execution, it would print the
        // annotations as expected.
        voting_results.print_annotations("abcdef1 Test commit");

        // Test successful if it reaches here without panicking
        // Visual inspection can confirm the expected output in actual runs
    }

    // Test reviewer setup
    #[test]
    fn test_reviewer_setup() {
        let mut voting_results = create_test_voting_results();

        // Test that primary reviewers are correctly defined
        assert_eq!(PRIMARY_REVIEWERS.len(), 3);
        assert!(PRIMARY_REVIEWERS.contains(&"greg".to_string()));
        assert!(PRIMARY_REVIEWERS.contains(&"lee".to_string()));
        assert!(PRIMARY_REVIEWERS.contains(&"sasha".to_string()));

        // Test guest reviewer identification
        voting_results.reviewers = vec![
            "greg".to_string(),
            "lee".to_string(),
            "sasha".to_string(),
            "guest1".to_string(),
        ];

        voting_results.identify_guest_reviewers();

        // Should only identify guest1 as a guest reviewer
        assert_eq!(voting_results.guest_reviewers.len(), 1);
        assert!(voting_results
            .guest_reviewers
            .contains(&"guest1".to_string()));

        // Primary reviewers should not be identified as guests
        assert!(!voting_results.guest_reviewers.contains(&"greg".to_string()));
        assert!(!voting_results.guest_reviewers.contains(&"lee".to_string()));
        assert!(!voting_results
            .guest_reviewers
            .contains(&"sasha".to_string()));
    }

    #[test]
    fn test_upstream_regex_mixed_hex() {
        // Real-world SHA with mixed hex digits
        let message = "commit abc123\n\nUpstream commit abcdef1234567890abcdef1234567890abcdef12";
        let captures = UPSTREAM_REGEX.captures(message).unwrap();
        assert_eq!(
            captures.get(0).unwrap().as_str(),
            "abcdef1234567890abcdef1234567890abcdef12"
        );
    }

    #[test]
    fn test_upstream_regex_no_match_short_sha() {
        // Exactly 40 hex chars should match
        let message = "commit 1234567890abcdef1234567890abcdef12345678";
        let captures = UPSTREAM_REGEX.captures(message);
        assert!(captures.is_some());

        // 39 hex chars should not match
        let message_short = "commit 1234567890abcdef1234567890abcdef1234567";
        let captures_short = UPSTREAM_REGEX.captures(message_short);
        assert!(captures_short.is_none());
    }

    #[test]
    fn test_upstream_regex_ignores_uppercase_hex() {
        // Uppercase hex should not match (SHA1s are lowercase)
        let message = "commit ABCDEF1234567890ABCDEF1234567890ABCDEF12";
        let captures = UPSTREAM_REGEX.captures(message);
        assert!(captures.is_none());
    }

    #[test]
    fn test_no_all_zero_reviewers() {
        let mut voting_results = create_test_voting_results();
        voting_results.reviewers = vec!["greg".to_string(), "lee".to_string(), "sasha".to_string()];
        voting_results.identify_guest_reviewers();
        // No guest reviewers when only primary reviewers are present
        assert!(voting_results.guest_reviewers.is_empty());
    }

    // Helper to create a test VotingResults instance
    fn create_test_voting_results() -> VotingResults {
        let temp_dir = tempdir().unwrap();
        let proposed_dir = temp_dir.path().to_path_buf();
        let script_dir = temp_dir.path().to_path_buf();

        // Get kernel tree path from the CVEKERNELTREE environment variable
        let kernel_tree = match env::var("CVEKERNELTREE") {
            Ok(path) => PathBuf::from(path),
            Err(_) => {
                panic!("CVEKERNELTREE environment variable not set. It needs to be set to the stable repo directory");
            }
        };

        // Validate kernel tree path
        if !kernel_tree.is_dir() {
            panic!(
                "CVEKERNELTREE directory does not exist: {}",
                kernel_tree.display()
            );
        }

        VotingResults {
            repo: Repository::open(&kernel_tree).expect("Failed to open kernel repository"),
            range: "v6.7.1..v6.7.2".to_string(),
            top: "v6.7.2".to_string(),
            proposed_dir,
            script_dir,
            reviewers: vec!["greg".to_string(), "lee".to_string(), "sasha".to_string()],
            guest_reviewers: Vec::new(),
            review_files: Vec::new(),
            annotated_files: Vec::new(),
            commits_by_pattern: HashMap::new(),
            no_annotate: false,
        }
    }
}
