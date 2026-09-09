// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Greg Kroah-Hartman <gregkh@linuxfoundation.org>
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
//

use crate::state::DyadState;
use cve_utils::Kernel;
use log::debug;

/// Adds a git SHA to the state's list of fixing kernels
pub fn process_fixing_sha(state: &mut DyadState, git_sha: &str) -> bool {
    if let Ok(kernel) = Kernel::from_id(git_sha) {
        state.git_sha_full.push(kernel);
        return true;
    }

    debug!("git sha {git_sha} could not be validated, attempting a second way...");
    // Sometimes the git id is in stable kernels but is NOT in a released Linus tree
    // just yet, so verhaal will not have the data. So let's check the git repo to see
    // if that's the case
    if let Ok(path) = cve_utils::common::get_kernel_tree()
        && let Ok(git_sha_full) = cve_utils::get_full_sha(&path, git_sha)
    {
        // It is valid, so let's make an "empty" kernel object and fill it in by hand
        // without a valid version number just yet.
        let kernel = Kernel::from_id_no_validate(&git_sha_full, "0");
        debug!("git sha {git_sha_full} was validated, but not in a Linus release yet, so moving forward with it.");
        state.git_sha_full.push(kernel);
        return true;
    }

    false
}

/// Process the vulnerable SHA1s provided on the command line
pub fn process_vulnerable_sha(state: &mut DyadState, vuln_id: &str) -> bool {
    if let Ok(kernel) = Kernel::from_id(vuln_id) {
        state.vulnerable_sha.push(kernel);
        true
    } else {
        false
    }
}
