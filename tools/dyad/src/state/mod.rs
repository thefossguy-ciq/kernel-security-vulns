// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Greg Kroah-Hartman <gregkh@linuxfoundation.org>
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
//

use cve_utils::FoundInResult;
use cve_utils::Kernel;
use cve_utils::Verhaal;
use log::debug;

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
