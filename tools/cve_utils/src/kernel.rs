// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Greg Kroah-Hartman <gregkh@linuxfoundation.org>
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
//
//
// kernel.rs - some common kernel version and pair handling structures and functions
//

//! Linux Kernel Git Commit handling library
//!
//! Semi-useful object to handle Linux kernel git commit ids, will help determine the version a git
//! id was released in, if it is in a -rc release, or if it is in a mainline or stable (i.e. not
//! mainline) release.
//!
//! Requires both a Linux kernel git tree to be on the system so it can look up git ids.  Location
//! of the git tree must be in the CVEKERNELTREE environment variable.
//!

use crate::common;
use crate::git_utils;
use crate::version_utils;
use crate::Verhaal;
use anyhow::Result;
use std::cmp::Ordering;
use std::path::Path;
use std::sync::OnceLock;

// Location of the kernel git tree we are working with.
// Defaults to using the CVEKERNELTREE environment variable
static GIT_DIR: OnceLock<String> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct Kernel {
    version: String,
    git_id: String,
}

impl Kernel {
    /// Create a new Kernel object
    /// `mainline` and `rc` attributes will be determined when created
    //#[deprecated(note = "Should use from_id() instead")]
    pub fn new(v: String, g: String) -> Result<Self> {
        Ok(Self {
            version: v,
            git_id: g,
        })
    }

    /// Creates an "empty" kernel object.
    ///
    /// Sometimes you don't know when a kernel release happened, so use this as an initial
    /// "placeholder" that you can pass around where needed (i.e. by the dyad tool).
    ///
    /// Note that the kernel object created here will return false for both `is_mainline()` and
    /// `is_rc()`.
    pub fn empty_kernel() -> Self {
        Self {
            version: "0".to_string(),
            git_id: "0".to_string(),
        }
    }

    /// Create a new Kernel object based on a git id
    /// Will verify, AND turn the id passed in into a "full" sha1 value, and properly populate the
    /// `mainline` and `rc` attributes as needed
    /// Should be always used, new() will be deprecated soon.
    pub fn from_id(id: String) -> Result<Self> {
        // Verify, AND turn the id given to us into a "full" sha1
        let kernel_tree = Self::git_dir();
        let repo_path = Path::new(&kernel_tree);
        let full_id = git_utils::get_full_sha(repo_path, &id)?;

        let verhaal = Verhaal::new()?;
        let version = verhaal.get_version(&full_id)?;
        Self::new(version, full_id)
    }

    pub fn git_id(&self) -> String {
        self.git_id.clone()
    }

    pub fn version(&self) -> String {
        self.version.clone()
    }

    pub fn is_empty(&self) -> bool {
        if self.version == "0" && self.git_id == "0" {
            return true;
        }
        false
    }

    /// Check if a kernel commit is in a mainline branch (i.e. Linus's), or in a stable branch
    pub fn is_mainline(&self) -> bool {
        // for a "NULL" kernel, we treat that as "not mainline"
        if self.git_id == "0" {
            return false;
        }

        version_utils::version_is_mainline(&self.version)
    }

    /// Check if a kernel commit is in a RC version
    pub fn is_rc_version(&self) -> bool {
        version_utils::version_is_rc(&self.version)
    }

    fn git_dir() -> &'static String {
        GIT_DIR.get_or_init(|| {
            // Use cve_utils to get and validate the kernel tree path
            match common::get_kernel_tree() {
                Ok(path) => path.to_string_lossy().into_owned(),
                Err(e) => panic!("Failed to get kernel tree: {}", e),
            }
        })
    }

    /// Return the "major" string portion of a kernel version string
    /// Used internally and also can be used externally as it might be useful for others.
    pub fn major(&self) -> String {
        version_utils::kernel_version_major(&self.version)
    }

    /// Return true if X.Y matches in a kernel version (i.e. the major is the same)
    pub fn version_major_match(&self, k: &Kernel) -> bool {
        version_utils::version_major_match(&self.version, &k.version)
    }

    /// Get the RC number if this is an RC version
    pub fn rc_number(&self) -> Option<u32> {
        version_utils::get_rc_number(&self.version)
    }

    /// Returns git ids in reverse sorted order in time (i.e. newest first)
    pub fn git_sort_ids(ids: &Vec<String>) -> Vec<String> {
        let kernel_tree = Self::git_dir();
        let repo_path = Path::new(&kernel_tree);
        git_utils::git_sort_ids(repo_path, ids)
    }

    /// Compare the version numbers of a kernel.
    /// Will look in git if the version string is the same
    pub fn compare(&self, k: &Kernel) -> Ordering {
        // Fast path: exact same version
        if self.version == k.version {
            // If versions match exactly, check git IDs
            if self.git_id == k.git_id {
                return Ordering::Equal;
            }

            // Version numbers match, so dig into git
            let v: Vec<String> = [self.git_id.clone(), k.git_id.clone()].to_vec();
            let sorted_ids = Self::git_sort_ids(&v);

            // In our version comparison, the newest commit is first in the list
            // The ordering is reversed because the newest commit is "greater than" the older one
            if sorted_ids[0] == self.git_id {
                return Ordering::Greater;
            }
            return Ordering::Less;
        }

        // For different versions, use the shared version comparison logic
        version_utils::compare_kernel_versions(&self.version, &k.version)
    }
}

impl Ord for Kernel {
    fn cmp(&self, other: &Self) -> Ordering {
        self.compare(other)
    }
}

impl PartialOrd for Kernel {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Kernel {
    fn eq(&self, other: &Self) -> bool {
        self.compare(other) == Ordering::Equal
    }
}

impl Eq for Kernel {}

#[derive(Debug, Clone)]
pub struct KernelPair {
    pub vulnerable: Kernel,
    pub fixed: Kernel,
}

#[cfg(test)]
mod tests {
    use crate::version_utils;
    use crate::Kernel;
    use std::cmp::Ordering;

    // Helper function to ALWAYS allocate a kernel object for testing.
    // Not generally a good idea to do (allocation can fail if you provide
    // an invalid git id, but good enough for testing, as we "know" what
    // we are doing here.  Hopefully...
    fn alloc_kernel(version: String, git_id: String) -> Kernel {
        if let Ok(k) = Kernel::new(version, git_id) {
            return k;
        } else {
            return Kernel::empty_kernel();
        }
    }

    fn alloc_kernel_id(git_id: String) -> Kernel {
        let k = match Kernel::from_id(git_id) {
            Ok(k) => k,
            Err(err) => panic!("{}", err),
        };
        k
    }

    #[test]
    fn empty_kernel_1() {
        let k: Kernel = Kernel::empty_kernel();
        assert_eq!(k.version, "0");
        assert_eq!(k.git_id, "0");
        assert_eq!(k.is_mainline(), false);
        assert_eq!(k.is_rc_version(), false);
    }

    #[test]
    fn empty_kernel_2() {
        let k: Kernel = Kernel::empty_kernel();
        assert!(k.is_empty());
    }

    #[test]
    fn empty_kernel_3() {
        let k: Kernel = alloc_kernel("5.10".to_string(), "1234".to_string());
        assert!(!k.is_empty());
    }

    #[test]
    fn constructor_logic() {
        let k1: Kernel = alloc_kernel("5.10".to_string(), "1234".to_string());
        assert_eq!(k1.is_mainline(), true);

        let k2: Kernel = alloc_kernel("5.10.1".to_string(), "1234".to_string());
        assert_eq!(k2.is_mainline(), false);
    }

    #[test]
    #[should_panic(expected = "Git SHA '111111' not found in kernel tree")]
    fn constructor_invalid_id() {
        let _k = match Kernel::from_id("111111".to_string()) {
            Ok(k) => k,
            Err(err) => panic!("{}", err),
        };
    }

    #[test]
    fn constructor_valid_id() {
        let k = match Kernel::from_id("2e13f88e01ae7e28a7e83".to_string()) {
            Ok(k) => k,
            Err(err) => panic!("{}", err),
        };
        assert_eq!(k.git_id(), "2e13f88e01ae7e28a7e831bf5c2409c4748e0a60");
        assert_eq!(k.version(), "6.1.132");
    }

    #[test]
    fn constructor_valid_id_2() {
        let mut k = alloc_kernel_id("e87e08c94c9541b4e18c4c13f2f605935f512605".to_string());
        assert_eq!(k.version(), "6.6.24");
        assert!(!k.is_mainline());

        k = alloc_kernel_id("af054a5fb24a144f99895afce9519d709891894c".to_string());
        assert_eq!(k.version(), "6.7.12");
        assert!(!k.is_mainline());

        k = alloc_kernel_id("22f665ecfd1225afa1309ace623157d12bb9bb0c".to_string());
        assert_eq!(k.version(), "6.8.3");
        assert!(!k.is_mainline());

        k = alloc_kernel_id("22207fd5c80177b860279653d017474b2812af5e".to_string());
        assert_eq!(k.version(), "6.9");
        assert!(k.is_mainline());
    }

    #[test]
    fn major() {
        let mut k: Kernel = Kernel::empty_kernel();

        k.version = "2.6.12.11".to_string();
        assert_eq!(k.major(), "2.6.12");

        k.version = "2.6.12".to_string();
        assert_eq!(k.major(), "2.6.12");

        k.version = "5.14".to_string();
        assert_eq!(k.major(), "5.14");

        k.version = "5.14.10".to_string();
        assert_eq!(k.major(), "5.14");

        // Test with RC versions
        k.version = "5.14-rc1".to_string();
        assert_eq!(k.major(), "5.14");

        k.version = "2.6.12-rc3".to_string();
        assert_eq!(k.major(), "2.6.12");
    }

    #[test]
    fn rc_version_handling() {
        let k: Kernel = alloc_kernel("5.14-rc1".to_string(), "1234".to_string());
        assert!(k.is_rc_version());
        assert_eq!(k.rc_number(), Some(1));

        let k: Kernel = alloc_kernel("5.14-rc10".to_string(), "1234".to_string());
        assert_eq!(k.rc_number(), Some(10));

        let k: Kernel = alloc_kernel("5.14".to_string(), "1234".to_string());
        assert!(!k.is_rc_version());
        assert_eq!(k.rc_number(), None);

        // Invalid RC format
        let k1: Kernel = alloc_kernel("5.14-rcx".to_string(), "1234".to_string());
        assert!(k1.is_rc_version());
        assert_eq!(k1.rc_number(), None);
    }

    #[test]
    fn version_is_mainline() {
        // Modern kernels
        assert!(version_utils::version_is_mainline("6.9"));
        assert!(!version_utils::version_is_mainline("6.9.1"));
        assert!(version_utils::version_is_mainline("6.16-rc1"));

        // 2.* kernels
        assert!(version_utils::version_is_mainline("2.6.14")); // 2.X.Y is mainline
        assert!(!version_utils::version_is_mainline("2.6.32.12")); // 2.X.Y.z is NOT mainline
        assert!(version_utils::version_is_mainline("2.4.20"));
        assert!(!version_utils::version_is_mainline("2.4.20.1"));
    }

    #[test]
    fn version_major_match() {
        let mut k1: Kernel = Kernel {
            version: "5.1.12".to_string(),
            git_id: "1234".to_string(),
        };
        let mut k2: Kernel = Kernel {
            version: "5.1.24".to_string(),
            git_id: "5678".to_string(),
        };

        assert!(k1.version_major_match(&k2));

        k1.version = "5.2.24".to_string();
        assert!(!k1.version_major_match(&k2));

        k1.version = "5.1".to_string();
        assert!(k1.version_major_match(&k2));

        k1.version = "2.6.31.1".to_string();
        k2.version = "2.6.31.4".to_string();
        assert!(k1.version_major_match(&k2));

        k2.version = "2.6.30.1".to_string();
        assert!(!k1.version_major_match(&k2));

        // Test with RC versions
        k1.version = "5.10-rc1".to_string();
        k2.version = "5.10.1".to_string();
        assert!(k1.version_major_match(&k2));

        k1.version = "5.10-rc1".to_string();
        k2.version = "5.10-rc2".to_string();
        assert!(k1.version_major_match(&k2));
    }

    #[test]
    fn version_compare() {
        let mut k1: Kernel = Kernel {
            version: "4.19".to_string(),
            git_id: "1234".to_string(),
        };
        let mut k2: Kernel = Kernel {
            version: "4.19.1".to_string(),
            git_id: "5678".to_string(),
        };

        assert_eq!(k1.compare(&k2), Ordering::Less);
        k1.version = "3.19.1".to_string();
        assert_eq!(k1.compare(&k2), Ordering::Less);

        k1.version = "5.19.1".to_string();
        assert_eq!(k1.compare(&k2), Ordering::Greater);

        k1.version = "4.2.201".to_string();
        assert_eq!(k1.compare(&k2), Ordering::Less);

        k1.version = "6.12".to_string();
        k2.version = "6.13-rc1".to_string();
        assert_eq!(k1.compare(&k2), Ordering::Less);

        k1.version = "6.13".to_string();
        k2.version = "6.13-rc1".to_string();
        assert_eq!(k1.compare(&k2), Ordering::Greater);

        k1.version = "6.14".to_string();
        k2.version = "6.13-rc1".to_string();
        assert_eq!(k1.compare(&k2), Ordering::Greater);

        // Additional RC version tests
        k1.version = "6.1-rc1".to_string();
        k2.version = "6.1-rc2".to_string();
        assert_eq!(k1.compare(&k2), Ordering::Less);

        k1.version = "6.1-rc5".to_string();
        k2.version = "6.1-rc2".to_string();
        assert_eq!(k1.compare(&k2), Ordering::Greater);

        k1.version = "6.1-rc1".to_string();
        k2.version = "6.0".to_string();
        assert_eq!(k1.compare(&k2), Ordering::Greater);

        // Test complex version numbers
        k1.version = "4.19.123".to_string();
        k2.version = "4.19.12".to_string();
        assert_eq!(k1.compare(&k2), Ordering::Greater);

        k1.version = "4.9.123".to_string();
        k2.version = "4.19.1".to_string();
        assert_eq!(k1.compare(&k2), Ordering::Less);

        k1.version = "6.9".to_string();
        k1.git_id = "ff956a3be95b45b2a823693a8c9db740939ca35e".to_string();
        k2.version = "6.9".to_string();
        k2.git_id = "0327ca9d53bfbb0918867313049bba7046900f73".to_string();
        assert_eq!(k1.compare(&k2), Ordering::Greater);

        k1.version = "6.9".to_string();
        k1.git_id = "ff956a3be95b45b2a823693a8c9db740939ca35e".to_string();
        k2.version = "6.9".to_string();
        k2.git_id = "ff956a3be95b45b2a823693a8c9db740939ca35e".to_string();
        assert_eq!(k1.compare(&k2), Ordering::Equal);
        assert!(k1 == k2);

        // Test sorting of lists of kernels, first the easy one with versions being the sort order
        let mut kernels: Vec<Kernel> = vec![];
        kernels.push(alloc_kernel(
            "6.1.132".to_string(),
            "2e13f88e01ae7e28a7e831bf5c2409c4748e0a60".to_string(),
        ));
        kernels.push(alloc_kernel(
            "6.6.24".to_string(),
            "e87e08c94c9541b4e18c4c13f2f605935f512605".to_string(),
        ));
        kernels.push(alloc_kernel(
            "6.7.12".to_string(),
            "af054a5fb24a144f99895afce9519d709891894c".to_string(),
        ));
        kernels.push(alloc_kernel(
            "6.8.3".to_string(),
            "22f665ecfd1225afa1309ace623157d12bb9bb0c".to_string(),
        ));
        kernels.push(alloc_kernel(
            "6.9".to_string(),
            "22207fd5c80177b860279653d017474b2812af5e".to_string(),
        ));
        kernels.sort_by(|a, b| a.cmp(b));

        assert_eq!(kernels[0].version, "6.1.132");
        assert_eq!(kernels[1].version, "6.6.24");
        assert_eq!(kernels[2].version, "6.7.12");
        assert_eq!(kernels[3].version, "6.8.3");
        assert_eq!(kernels[4].version, "6.9");

        kernels = Vec::new();
        kernels.push(alloc_kernel(
            "6.9".to_string(),
            "22207fd5c80177b860279653d017474b2812af5e".to_string(),
        ));
        kernels.push(alloc_kernel(
            "6.8.3".to_string(),
            "22f665ecfd1225afa1309ace623157d12bb9bb0c".to_string(),
        ));
        kernels.push(alloc_kernel(
            "6.7.12".to_string(),
            "af054a5fb24a144f99895afce9519d709891894c".to_string(),
        ));
        kernels.push(alloc_kernel(
            "6.1.132".to_string(),
            "2e13f88e01ae7e28a7e831bf5c2409c4748e0a60".to_string(),
        ));
        kernels.push(alloc_kernel(
            "6.6.24".to_string(),
            "e87e08c94c9541b4e18c4c13f2f605935f512605".to_string(),
        ));
        kernels.sort_by(|a, b| a.cmp(b));

        assert_eq!(kernels[0].version, "6.1.132");
        assert_eq!(kernels[1].version, "6.6.24");
        assert_eq!(kernels[2].version, "6.7.12");
        assert_eq!(kernels[3].version, "6.8.3");
        assert_eq!(kernels[4].version, "6.9");

        // Now a harder test, only look at git commit ids
        kernels = Vec::new();
        let v = "6.11".to_string();
        kernels.push(alloc_kernel(
            v.clone(),
            "538fd3921afac97158d4177139a0ad39f056dbb2".to_string(),
        ));
        kernels.push(alloc_kernel(
            v.clone(),
            "28cd47f75185c4818b0fb1b46f2f02faaba96376".to_string(),
        ));
        kernels.push(alloc_kernel(
            v.clone(),
            "bbf3c7ff9dfa45be51500d23a1276991a7cd8c6e".to_string(),
        ));
        kernels.push(alloc_kernel(
            v.clone(),
            "4e9903b0861c9df3464b82db4a7025863bac1897".to_string(),
        ));
        kernels.push(alloc_kernel(
            v.clone(),
            "4f336dc07eceb77d2164bc1121a5ae6003b19f55".to_string(),
        ));
        kernels.sort_by(|a, b| a.cmp(b));
        assert_eq!(
            kernels[0].git_id,
            "28cd47f75185c4818b0fb1b46f2f02faaba96376"
        );
        assert_eq!(
            kernels[1].git_id,
            "538fd3921afac97158d4177139a0ad39f056dbb2"
        );
        assert_eq!(
            kernels[2].git_id,
            "4e9903b0861c9df3464b82db4a7025863bac1897"
        );
        assert_eq!(
            kernels[3].git_id,
            "bbf3c7ff9dfa45be51500d23a1276991a7cd8c6e"
        );
        assert_eq!(
            kernels[4].git_id,
            "4f336dc07eceb77d2164bc1121a5ae6003b19f55"
        );
    }
}
