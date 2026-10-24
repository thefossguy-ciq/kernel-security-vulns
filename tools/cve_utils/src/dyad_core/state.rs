// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Greg Kroah-Hartman <gregkh@linuxfoundation.org>
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
//

use crate::FoundInResult;
use crate::Kernel;
use crate::Verhaal;
use anyhow::Result;
use log::debug;
use std::collections::HashSet;
use std::fs;
use std::sync::OnceLock;

// The scripts/not_reverts and scripts/not_fixes whitelists, loaded once per
// process and shared by every dyad run.  The files never change while a tool
// runs, so there is no point in re-reading them for every CVE processed.
static NOT_REVERTS: OnceLock<HashSet<String>> = OnceLock::new();
static NOT_FIXES: OnceLock<HashSet<String>> = OnceLock::new();

/// State for a dyad run
pub struct DyadState {
    pub kernel_tree: String,
    pub vulnerable_sha: Vec<Kernel>,
    pub git_sha_full: Vec<Kernel>,
    pub fixed_set: Vec<Kernel>,
    pub vulnerable_set: Vec<Kernel>,
    /// Direct pairs of (`vulnerable_backport`, `revert_commit`) for revert-based fixes.
    /// These are pre-computed pairs that should be used directly without going through
    /// the general pairing logic, since we already know exactly which commit each revert fixes.
    pub revert_pairs: Vec<(Kernel, Kernel)>,
    /// SHAs from `scripts/not_reverts`: backports whose revert is non-functional
    /// (e.g. cosmetic compiler-warning fixup followed by an immediate re-apply).
    /// When a reverted backport's git id is in this set, dyad treats the original
    /// as still-active on its stable branch and suppresses the re-applied sibling.
    pub not_reverts: &'static HashSet<String>,
    /// SHAs from `scripts/not_fixes`: stable backports that look like a fix for
    /// the CVE but did not actually fix the issue (typo, misplaced check,
    /// dropped hunk, etc.).  Kernels matching these SHAs are dropped from the
    /// fix set; the actual fix needs to be supplied separately (e.g. via an
    /// extra line in the CVE's .sha1 file).
    pub not_fixes: &'static HashSet<String>,
    // HashSets for O(1) deduplication checks
    fixed_set_ids: HashSet<String>,
    vulnerable_set_ids: HashSet<String>,
    revert_pair_vuln_ids: HashSet<String>,
}

impl DyadState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            // Init with some "blank" default, the command line and
            // environment variables will override them
            kernel_tree: String::new(),
            vulnerable_sha: vec![],
            git_sha_full: vec![],
            fixed_set: vec![],
            vulnerable_set: vec![],
            revert_pairs: vec![],
            not_reverts: NOT_REVERTS.get_or_init(|| load_sha_list("not_reverts")),
            not_fixes: NOT_FIXES.get_or_init(|| load_sha_list("not_fixes")),
            fixed_set_ids: HashSet::new(),
            vulnerable_set_ids: HashSet::new(),
            revert_pair_vuln_ids: HashSet::new(),
        }
    }

    /// Add a kernel to `fixed_set` if not already present.
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

    /// Add a kernel to `vulnerable_set` if not already present.
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

    /// Add a revert pair if not already present (checked by vulnerable kernel's `git_id`).
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

impl Default for DyadState {
    fn default() -> Self {
        Self::new()
    }
}

/// Validates and sets up environment variables for the `DyadState`
///
/// # Errors
///
/// Returns an error if the kernel tree cannot be determined (i.e. the
/// CVEKERNELTREE environment variable is not set or does not point at a
/// directory).
pub fn validate_env_vars(state: &mut DyadState) -> Result<()> {
    // Use cve_utils to get kernel tree path
    state.kernel_tree = crate::common::get_kernel_tree()?
        .to_string_lossy()
        .into_owned();
    debug!("kernel_tree = {}", state.kernel_tree);
    Ok(())
}

/// Determines the list of kernels where a specific git sha has been backported to, both mainline
/// and stable kernel releases, if any.
///
/// Returns a `FoundInResult` containing:
/// - `kernels`: Non-reverted backports
/// - `reverted_pairs`: Pairs of (`reverted_backport`, `revert_commit`) where the backport was later reverted
pub fn found_in(state: &DyadState, git_sha: &str) -> FoundInResult {
    let result = Verhaal::with(|verhaal| verhaal.found_in(git_sha, &state.fixed_set));
    match result.and_then(|r| r) {
        Ok(r) => r,
        Err(e) => {
            debug!("{e:?}");
            FoundInResult::default()
        }
    }
}

/// Load a `scripts/<name>` SHA whitelist (one SHA per line, '#' comments and
/// blanks ignored, lowercased for case-insensitive matching).  Used for
/// `not_reverts` and `not_fixes`; returns an empty set on any read error so
/// dyad behaves as it did before the file existed.
fn load_sha_list(name: &str) -> HashSet<String> {
    let vulns_dir = match crate::common::find_vulns_dir() {
        Ok(p) => p,
        Err(e) => {
            debug!("{name}: could not locate vulns dir: {e:?}");
            return HashSet::new();
        }
    };

    let path = vulns_dir.join("scripts").join(name);
    let contents = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            debug!("{name}: could not read {}: {e:?}", path.display());
            return HashSet::new();
        }
    };

    let set: HashSet<String> = contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_lowercase)
        .collect();

    debug!("{name}: loaded {} entries", set.len());
    set
}
