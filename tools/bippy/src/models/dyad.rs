// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use crate::models::errors::BippyError;
use cve_utils::Kernel;

/// `DyadEntry` represents a kernel vulnerability range entry from the dyad script
#[derive(Debug, Clone)]
pub struct DyadEntry {
    pub vulnerable: Kernel,
    pub fixed: Kernel,
}

impl DyadEntry {
    /// Create a new `DyadEntry` from a colon-separated string
    pub fn from_str(s: &str) -> Result<Self, BippyError> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 4 {
            return Err(BippyError::InvalidDyadEntry(s.to_string()));
        }

        let vulnerable_version = parts[0].to_string();
        let vulnerable_git = parts[1].to_string();
        let fixed_version = parts[2].to_string();
        let fixed_git = parts[3].to_string();

        // Create the vulnerable and fixed kernels by the git id, verifying that this is a valid
        // git id AND that the version number is what dyad gave us so that we don't go off of crazy
        // information somehow.
        let vulnerable_kernel = match Kernel::from_id(&vulnerable_git) {
            Ok(v) => v,
            Err(_e) => return Err(BippyError::InvalidDyadGitId(vulnerable_git)),
        };
        if vulnerable_kernel.version() != vulnerable_version {
            return Err(BippyError::InvalidDyadVersion(vulnerable_version));
        }

        let fixed_kernel = match Kernel::from_id(&fixed_git) {
            Ok(v) => v,
            Err(_e) => return Err(BippyError::InvalidDyadGitId(fixed_git)),
        };
        if fixed_kernel.version() != fixed_version {
            return Err(BippyError::InvalidDyadVersion(fixed_version));
        }

        Ok(Self {
            vulnerable: vulnerable_kernel,
            fixed: fixed_kernel,
        })
    }

    /// Check if this vulnerability is found/fixed in the same kernel version
    pub fn is_same_version(&self) -> bool {
        self.vulnerable.version() == self.fixed.version()
    }

    /// Check if this vulnerability has been fixed
    #[cfg(test)]
    pub fn is_fixed(&self) -> bool {
        !self.fixed.is_empty()
    }

    /// Check if vulnerability spans across different kernel versions
    #[cfg(test)]
    pub fn is_cross_version(&self) -> bool {
        !self.vulnerable.is_empty()
            && !self.fixed.is_empty()
            && self.vulnerable.version() != self.fixed.version()
    }
}
