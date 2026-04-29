// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Greg Kroah-Hartman <gregkh@linuxfoundation.org>
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
//

use cve_utils::FoundInResult;
use cve_utils::Kernel;
use cve_utils::Verhaal;
use log::debug;
use std::collections::HashSet;
use std::fs;

/// State for dyad tool runtime
pub struct DyadState {
    pub kernel_tree: String,
    pub verhaal: Verhaal,
    pub vulnerable_sha: Vec<Kernel>,
    pub git_sha_full: Vec<Kernel>,
    pub fixed_set: Vec<Kernel>,
    pub vulnerable_set: Vec<Kernel>,
    /// Direct pairs of (vulnerable_backport, revert_commit) for revert-based fixes.
    /// These are pre-computed pairs that should be used directly without going through
    /// the general pairing logic, since we already know exactly which commit each revert fixes.
    pub revert_pairs: Vec<(Kernel, Kernel)>,
    /// SHAs from scripts/not_reverts: backports whose revert is non-functional
    /// (e.g. cosmetic compiler-warning fixup followed by an immediate re-apply).
    /// When a reverted backport's git id is in this set, dyad treats the original
    /// as still-active on its stable branch and suppresses the re-applied sibling.
    pub not_reverts: HashSet<String>,
    // HashSets for O(1) deduplication checks
    fixed_set_ids: HashSet<String>,
    vulnerable_set_ids: HashSet<String>,
    revert_pair_vuln_ids: HashSet<String>,
}

impl DyadState {
    pub fn new() -> Self {
        let verhaal = match Verhaal::new() {
            Ok(verhaal) => verhaal,
            Err(error) => panic!("Can not open the database file {error:?}"),
        };

        Self {
            // Init with some "blank" default, the command line and
            // environment variables will override them
            kernel_tree: String::new(),
            verhaal,
            vulnerable_sha: vec![],
            git_sha_full: vec![],
            fixed_set: vec![],
            vulnerable_set: vec![],
            revert_pairs: vec![],
            not_reverts: load_not_reverts(),
            fixed_set_ids: HashSet::new(),
            vulnerable_set_ids: HashSet::new(),
            revert_pair_vuln_ids: HashSet::new(),
        }
    }

    /// Add a kernel to fixed_set if not already present.
    /// Returns true if the kernel was added, false if it was already present.
    pub fn add_to_fixed_set(&mut self, kernel: Kernel) -> bool {
        let id = kernel.git_id();
        if self.fixed_set_ids.insert(id) {
            self.fixed_set.push(kernel);
            true
        } else {
            false
        }
    }

    /// Add a kernel to vulnerable_set if not already present.
    /// Returns true if the kernel was added, false if it was already present.
    pub fn add_to_vulnerable_set(&mut self, kernel: Kernel) -> bool {
        let id = kernel.git_id();
        if self.vulnerable_set_ids.insert(id) {
            self.vulnerable_set.push(kernel);
            true
        } else {
            false
        }
    }

    /// Add a revert pair if not already present (checked by vulnerable kernel's git_id).
    /// Returns true if the pair was added, false if it was already present.
    pub fn add_revert_pair(&mut self, vuln_kernel: Kernel, fix_kernel: Kernel) -> bool {
        let vuln_id = vuln_kernel.git_id();
        if self.revert_pair_vuln_ids.insert(vuln_id) {
            self.revert_pairs.push((vuln_kernel, fix_kernel));
            true
        } else {
            false
        }
    }
}

/// Validates and sets up environment variables for the `DyadState`
pub fn validate_env_vars(state: &mut DyadState) {
    // Use cve_utils to get kernel tree path
    match cve_utils::common::get_kernel_tree() {
        Ok(path) => state.kernel_tree = path.to_string_lossy().into_owned(),
        Err(e) => panic!("Failed to get kernel tree: {e}"),
    }
    debug!("kernel_tree = {}", state.kernel_tree);
}

/// Determines the list of kernels where a specific git sha has been backported to, both mainline
/// and stable kernel releases, if any.
///
/// Returns a `FoundInResult` containing:
/// - `kernels`: Non-reverted backports
/// - `reverted_pairs`: Pairs of (reverted_backport, revert_commit) where the backport was later reverted
pub fn found_in(state: &DyadState, git_sha: &str) -> FoundInResult {
    let result = state.verhaal.found_in(git_sha, &state.fixed_set);
    match result {
        Ok(r) => r,
        Err(e) => {
            debug!("{e:?}");
            FoundInResult::default()
        }
    }
}

/// Load the scripts/not_reverts whitelist of commit SHAs whose revert is known to be
/// non-functional. Comment lines (starting with '#') and blank lines are skipped.
/// SHAs are lowercased for case-insensitive matching.
///
/// Returns an empty set on any read error so dyad behaves as it did before this file existed.
fn load_not_reverts() -> HashSet<String> {
    let vulns_dir = match cve_utils::common::find_vulns_dir() {
        Ok(p) => p,
        Err(e) => {
            debug!("not_reverts: could not locate vulns dir: {e:?}");
            return HashSet::new();
        }
    };

    let path = vulns_dir.join("scripts").join("not_reverts");
    let contents = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            debug!("not_reverts: could not read {}: {e:?}", path.display());
            return HashSet::new();
        }
    };

    let set: HashSet<String> = contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_lowercase)
        .collect();

    debug!("not_reverts: loaded {} entries", set.len());
    set
}
