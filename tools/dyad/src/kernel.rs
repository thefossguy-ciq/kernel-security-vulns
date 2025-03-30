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

//use log::debug;
use git2::{Oid, Repository};
use log::{debug, error};
use std::cmp::Ordering;
use std::env;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

// Location of the kernel git tree we are working with.
// Defaults to using the CVEKERNELTREE environment variable
static GIT_DIR: OnceLock<String> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct Kernel {
    pub version: String,
    pub git_id: String,
    mainline: bool,
    rc: bool,
}

impl Kernel {
    /// Create a new Kernel object
    /// `mainline` and `rc` attributes will be determined when created
    pub fn new(v: String, g: String) -> Self {
        let mainline = Self::version_is_mainline(&v);
        let rc = Self::version_is_rc(&v);
        Self {
            version: v,
            git_id: g,
            mainline,
            rc,
        }
    }

    /// Creates an "empty" kernel object.
    ///
    /// Sometimes you don't know when a kernel release happened, so use this as an initial
    /// "placeholder" that you can pass around where needed (i.e. by the dyad tool).
    ///
    /// Note that the kernel object created here will return true for both `is_mainline()` and
    /// `is_rc()`.
    pub fn empty_kernel() -> Self {
        Self {
            version: "0".to_string(),
            git_id: "0".to_string(),
            mainline: false, // This MUST be false, we rely on it elsewhere...
            rc: false,
        }
    }

    /// Check if a kernel commit is in a mainline branch (i.e. Linus's), or in a stable branch
    pub fn is_mainline(&self) -> bool {
        self.mainline
    }

    /// Check if a kernel commit is in a RC version
    pub fn is_rc_version(&self) -> bool {
        self.rc
    }

    fn git_dir() -> &'static String {
        GIT_DIR.get_or_init(|| {
            let dir = match env::var("CVEKERNELTREE") {
                Ok(val) => val,
                Err(_error) => panic!("Environment variable CVEKERNELTREE not found, please set!"),
            };
            // Validate that this really is a git directory by looking for .git/
            let dot_git = dir.clone() + "/.git";
            match fs::exists(dot_git.clone()) {
                Ok(true) => debug!("\tgit_dir: {} path found", dot_git),
                Ok(false) => panic!(
                    "CVEKERNELTREE value of {} is not found, please set to valid git directory",
                    dot_git
                ),
                Err(e) => panic!(
                    "Error {e}: Something went wrong trying to lookup the path for '{}'",
                    dot_git
                ),
            }
            dir
        })
    }

    /// Return the "major" string portion of a kernel version string
    /// Used internally and also can be used externally as it might be useful for others.
    pub fn major(&self) -> String {
        // Handle RC versions by stripping the -rcX suffix if present
        let base_version = if let Some(pos) = self.version.find("-rc") {
            self.version[0..pos].to_string()
        } else {
            self.version.clone()
        };

        let v: Vec<&str> = base_version.split('.').collect();
        let len = v.len();
        debug!("major: v={:?} len={}", v, len);

        if len <= 1 {
            debug!("major: real short version, just bailing...");
            return "".to_string();
        }

        if v[0] == "2" {
            // Ugh, 2.6.x.y potentially, figure out if we have a .y
            // len must be 3 or 4 only
            if len == 3 || len == 4 {
                return [v[0], ".", v[1], ".", v[2]].concat();
            }
            debug!("major: 2.X?  Odd release...");
            return "".to_string();
        }
        // Not 2.6.x, so it's the normal "major.major.minor" structure
        [v[0], ".", v[1]].concat()
    }

    /// Return true if X.Y matches in a kernel version (i.e. the major is the same)
    pub fn version_major_match(&self, k: &Kernel) -> bool {
        let major1 = self.major();
        let major2 = k.major();

        // Handle case where either major is empty
        if major1.is_empty() || major2.is_empty() {
            debug!(
                "version_major_match: empty major version {:?} {:?}",
                self.version, k.version
            );
            return false;
        }

        let ret = major1 == major2;
        debug!(
            "version_major_match: {:?} ({}) {:?} ({}) = {}",
            self.version, major1, k.version, major2, ret
        );
        ret
    }

    /// Parse a version string into components for comparison
    fn parse_version(version: &str) -> (Vec<u32>, Option<u32>, bool) {
        // Handle RC versions
        let (version_base, is_rc) = if let Some(rc_idx) = version.find("-rc") {
            (&version[0..rc_idx], true)
        } else {
            (version, false)
        };

        // Parse the version numbers
        // First split by dot and ensure all parts are valid u32 values
        let ver_parts: Vec<u32> = version_base
            .split('.')
            .filter_map(|s| s.parse::<u32>().ok())
            .collect();

        // Get RC number if present
        let rc_num = if is_rc {
            if let Some(rc_idx) = version.find("-rc") {
                let rc_suffix = &version[rc_idx + 3..];
                rc_suffix.parse::<u32>().ok()
            } else {
                None
            }
        } else {
            None
        };

        (ver_parts, rc_num, is_rc)
    }

    /// Returns git ids in reverse sorted order in time (i.e. newest first)
    pub fn git_sort_ids(ids: &Vec<String>) -> Vec<String> {
        // For optimization: if we only have one ID, just return it
        if ids.len() <= 1 {
            return ids.clone();
        }

        let kernel_tree = Self::git_dir();
        let repo_path = Path::new(&kernel_tree);

        debug!(
            "\t\tSorting git ids {:?} using repository {}",
            ids,
            repo_path.display()
        );

        // Try to open the git repository
        let repo = match Repository::open(repo_path) {
            Ok(repo) => repo,
            Err(e) => {
                error!("Error opening repository: {}", e);
                // Keep original order for consistency
                return ids.clone();
            }
        };

        // Convert string IDs to Oid objects for lookup
        let mut oid_map = std::collections::HashMap::new();
        let mut valid_oids = Vec::new();

        for id_str in ids {
            match Oid::from_str(id_str) {
                Ok(oid) => {
                    // Check if the object exists in the repository
                    if repo.find_commit(oid).is_ok() {
                        oid_map.insert(oid, id_str);
                        valid_oids.push(oid);
                    } else {
                        debug!("Warning: git id {} not found in repository", id_str);
                    }
                }
                Err(e) => {
                    debug!("Warning: invalid git id {}: {}", id_str, e);
                }
            }
        }

        // If no valid IDs were found, return original order
        if valid_oids.is_empty() {
            debug!("No valid git IDs found, returning original order");
            return ids.clone();
        }

        // Determine the relationship between commits directly rather than using revwalk
        // This creates a directed graph of "is ancestor of" relationships
        let mut result_order = Vec::new();
        let mut remaining_oids = valid_oids.clone();

        while !remaining_oids.is_empty() {
            // Find a commit that is not an ancestor of any other remaining commit
            // This will be the newest commit among the remaining ones
            let mut newest_idx = 0;

            'outer: for i in 0..remaining_oids.len() {
                let mut is_newest = true;
                for j in 0..remaining_oids.len() {
                    if i == j {
                        continue;
                    }

                    match repo.graph_descendant_of(remaining_oids[j], remaining_oids[i]) {
                        Ok(true) => {
                            // Found a descendant, so this one isn't the newest
                            is_newest = false;
                            break;
                        }
                        Ok(false) => {
                            // Not a descendant, continue checking
                        }
                        Err(_) => {
                            // Error determining relationship, assume not related
                            // This can happen with unrelated history lines
                        }
                    }
                }

                if is_newest {
                    newest_idx = i;
                    break 'outer;
                }
            }

            // If no clear newest was found (possible with unrelated history),
            // just take the first one
            result_order.push(remaining_oids.remove(newest_idx));
        }

        // Convert back to original string IDs
        let mut sorted_ids: Vec<String> = result_order
            .iter()
            .filter_map(|oid| oid_map.get(oid).map(|&s| s.clone()))
            .collect();

        // Add any missing IDs that we couldn't find in the repo
        for id in ids {
            if !sorted_ids.contains(id) {
                sorted_ids.push(id.clone());
            }
        }

        debug!("git_sort_ids: sorted_ids = {:?}", sorted_ids);
        sorted_ids
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

        // Special case for sort_releases_properly test - bash's sort -V will consider
        // stable releases in numerical order first, then consider the number of components

        // Handle mainline vs stable differently - mainline is X.Y, stable is X.Y.Z
        let self_is_mainline = self.is_mainline();
        let k_is_mainline = k.is_mainline();

        // When comparing a mainline version against its stable counterpart,
        // the stable version is always greater (e.g., 6.1 vs 6.1.1)
        if self_is_mainline && !k_is_mainline && self.major() == k.major() {
            return Ordering::Less;
        }
        if !self_is_mainline && k_is_mainline && self.major() == k.major() {
            return Ordering::Greater;
        }

        // Use a more robust version comparison for Linux kernel versions
        let (ver1_parts, rc1_num, is_rc1) = Self::parse_version(&self.version);
        let (ver2_parts, rc2_num, is_rc2) = Self::parse_version(&k.version);

        // Compare version components (e.g., major.minor.patch)
        let max_len = std::cmp::max(ver1_parts.len(), ver2_parts.len());
        for i in 0..max_len {
            let v1 = if i < ver1_parts.len() {
                ver1_parts[i]
            } else {
                0
            };
            let v2 = if i < ver2_parts.len() {
                ver2_parts[i]
            } else {
                0
            };

            match v1.cmp(&v2) {
                Ordering::Equal => continue,
                other => return other,
            }
        }

        // If we get here, the version components are identical, check RC status
        match (is_rc1, is_rc2) {
            (true, false) => Ordering::Less,    // RC is less than final
            (false, true) => Ordering::Greater, // Final is greater than RC
            (true, true) => {
                // Both are RCs, compare RC numbers
                let rc1 = rc1_num.unwrap_or(0);
                let rc2 = rc2_num.unwrap_or(0);
                rc1.cmp(&rc2)
            }
            (false, false) => {
                // If we get here with non-RC versions, they should be equal,
                // but this was handled at the start of the function.
                // This is just a fallback.
                debug!("Warning: unexpected version comparison state reached");
                // Implementation of version comparison directly in Rust, no more vsort dependency

                // Compare based on number of components and mainline status
                match (self_is_mainline, k_is_mainline) {
                    (true, false) => Ordering::Less,    // Mainline is less than stable
                    (false, true) => Ordering::Greater, // Stable is greater than mainline
                    _ => {
                        // This is a fallback for when we have compared all numeric parts
                        // and they were equal, but we still need a consistent ordering
                        // Just compare the string representations lexicographically as a last resort
                        self.version.cmp(&k.version)
                    }
                }
            }
        }
    }

    /// Takes a kernel release version, in string form, and figures out if it is a "mainline"
    /// release or not, based on the kernel release numbering system.
    pub fn version_is_mainline(version: &String) -> bool {
        //println!("git_dir: {}", Self::git_dir());

        // Check for -rc version first
        if version.contains("-rc") {
            return true;
        }

        // Split the version number up into pieces
        let v: Vec<&str> = version.split('.').collect();
        if v.len() == 1 {
            debug!("Version split of {} did not work", version);
            return false;
        }

        // 2.6.X is just one more level "deep"
        if v[0] == "2" && v.len() == 3 {
            return true;
        }

        // If version only has X.Y format (no .Z), it's mainline
        if v.len() == 2 {
            return true;
        }

        // Otherwise this is a stable release
        false
    }

    /// Takes a kernel release version, in string form, and figures out if it is a "-rc" release or
    /// not, based on the kernel release numbering system.
    fn version_is_rc(version: &str) -> bool {
        version.contains("-rc")
    }

    /// Get the RC number if this is an RC version
    pub fn rc_number(&self) -> Option<u32> {
        if let Some(rc_index) = self.version.find("-rc") {
            let rc_part = &self.version[rc_index + 3..];
            rc_part.parse::<u32>().ok()
        } else {
            None
        }
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

#[derive(Debug)]
pub struct KernelPair {
    pub vulnerable: Kernel,
    pub fixed: Kernel,
}

#[cfg(test)]
mod tests {
    use crate::Kernel;
    use std::cmp::Ordering;

    #[test]
    fn empty_kernel() {
        let k: Kernel = Kernel::empty_kernel();
        assert_eq!(k.version, "0");
        assert_eq!(k.git_id, "0");
        assert_eq!(k.is_mainline(), false);
    }

    #[test]
    fn constructor_logic() {
        let k1: Kernel = Kernel::new("5.10".to_string(), "1234".to_string());
        assert_eq!(k1.is_mainline(), true);

        let k2: Kernel = Kernel::new("5.10.1".to_string(), "1234".to_string());
        assert_eq!(k2.is_mainline(), false);
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
    fn parse_version() {
        let (parts, rc_num, is_rc) = Kernel::parse_version("5.14.2");
        assert_eq!(parts, vec![5, 14, 2]);
        assert_eq!(rc_num, None);
        assert!(!is_rc);

        let (parts, rc_num, is_rc) = Kernel::parse_version("5.14-rc3");
        assert_eq!(parts, vec![5, 14]);
        assert_eq!(rc_num, Some(3));
        assert!(is_rc);

        let (parts, rc_num, is_rc) = Kernel::parse_version("2.6.32.12");
        assert_eq!(parts, vec![2, 6, 32, 12]);
        assert_eq!(rc_num, None);
        assert!(!is_rc);
    }

    #[test]
    fn rc_version_handling() {
        let k: Kernel = Kernel::new("5.14-rc1".to_string(), "1234".to_string());
        assert!(k.is_rc_version());
        assert_eq!(k.rc_number(), Some(1));

        let k: Kernel = Kernel::new("5.14-rc10".to_string(), "1234".to_string());
        assert_eq!(k.rc_number(), Some(10));

        let k: Kernel = Kernel::new("5.14".to_string(), "1234".to_string());
        assert!(!k.is_rc_version());
        assert_eq!(k.rc_number(), None);

        // Invalid RC format
        let k1: Kernel = Kernel::new("5.14-rcx".to_string(), "1234".to_string());
        assert!(k1.is_rc_version());
        assert_eq!(k1.rc_number(), None);
    }

    #[test]
    fn version_is_mainline() {
        assert!(Kernel::version_is_mainline(&"6.9".to_string()));
        assert!(!Kernel::version_is_mainline(&"6.9.1".to_string()));
        assert!(Kernel::version_is_mainline(&"2.6.14".to_string()));
        assert!(!Kernel::version_is_mainline(&"2.6.32.12".to_string()));
        assert!(Kernel::version_is_mainline(&"6.16-rc1".to_string()));
    }

    #[test]
    fn version_major_match() {
        let mut k1: Kernel = Kernel {
            version: "5.1.12".to_string(),
            git_id: "1234".to_string(),
            mainline: false,
            rc: false,
        };
        let mut k2: Kernel = Kernel {
            version: "5.1.24".to_string(),
            git_id: "5678".to_string(),
            mainline: false,
            rc: false,
        };

        assert!(k1.version_major_match(&k2));

        k1.version = "5.2.24".to_string();
        assert!(!k1.version_major_match(&k2));

        k1.version = "5.1".to_string();
        k1.mainline = true;
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
            mainline: false,
            rc: false,
        };
        let mut k2: Kernel = Kernel {
            version: "4.19.1".to_string(),
            git_id: "5678".to_string(),
            mainline: false,
            rc: false,
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

        // Test sorting of lists of kernels, first the easy one with versions being the sort order
        let mut kernels: Vec<Kernel> = vec![];
        kernels.push(Kernel::new("6.1.132".to_string(), "2e13f88e01ae7e28a7e831bf5c2409c4748e0a60".to_string()));
        kernels.push(Kernel::new("6.6.24".to_string(), "e87e08c94c9541b4e18c4c13f2f605935f512605".to_string()));
        kernels.push(Kernel::new("6.7.12".to_string(), "af054a5fb24a144f99895afce9519d709891894c".to_string()));
        kernels.push(Kernel::new("6.8.3".to_string(), "22f665ecfd1225afa1309ace623157d12bb9bb0c".to_string()));
        kernels.push(Kernel::new("6.9".to_string(), "22207fd5c80177b860279653d017474b2812af5e".to_string()));
        kernels.sort_by(|a, b| a.cmp(b));

        assert_eq!(kernels[0].version, "6.1.132");
        assert_eq!(kernels[1].version, "6.6.24");
        assert_eq!(kernels[2].version, "6.7.12");
        assert_eq!(kernels[3].version, "6.8.3");
        assert_eq!(kernels[4].version, "6.9");

        kernels = Vec::new();
        kernels.push(Kernel::new("6.9".to_string(), "22207fd5c80177b860279653d017474b2812af5e".to_string()));
        kernels.push(Kernel::new("6.8.3".to_string(), "22f665ecfd1225afa1309ace623157d12bb9bb0c".to_string()));
        kernels.push(Kernel::new("6.7.12".to_string(), "af054a5fb24a144f99895afce9519d709891894c".to_string()));
        kernels.push(Kernel::new("6.1.132".to_string(), "2e13f88e01ae7e28a7e831bf5c2409c4748e0a60".to_string()));
        kernels.push(Kernel::new("6.6.24".to_string(), "e87e08c94c9541b4e18c4c13f2f605935f512605".to_string()));
        kernels.sort_by(|a, b| a.cmp(b));

        assert_eq!(kernels[0].version, "6.1.132");
        assert_eq!(kernels[1].version, "6.6.24");
        assert_eq!(kernels[2].version, "6.7.12");
        assert_eq!(kernels[3].version, "6.8.3");
        assert_eq!(kernels[4].version, "6.9");

        // Now a harder test, only look at git commit ids
        kernels = Vec::new();
        let v = "6.11".to_string();
        kernels.push(Kernel::new(v.clone(), "538fd3921afac97158d4177139a0ad39f056dbb2".to_string()));
        kernels.push(Kernel::new(v.clone(), "28cd47f75185c4818b0fb1b46f2f02faaba96376".to_string()));
        kernels.push(Kernel::new(v.clone(), "bbf3c7ff9dfa45be51500d23a1276991a7cd8c6e".to_string()));
        kernels.push(Kernel::new(v.clone(), "4e9903b0861c9df3464b82db4a7025863bac1897".to_string()));
        kernels.push(Kernel::new(v.clone(), "4f336dc07eceb77d2164bc1121a5ae6003b19f55".to_string()));
        kernels.sort_by(|a, b| a.cmp(b));
        assert_eq!(kernels[0].git_id, "28cd47f75185c4818b0fb1b46f2f02faaba96376");
        assert_eq!(kernels[1].git_id, "538fd3921afac97158d4177139a0ad39f056dbb2");
        assert_eq!(kernels[2].git_id, "4e9903b0861c9df3464b82db4a7025863bac1897");
        assert_eq!(kernels[3].git_id, "bbf3c7ff9dfa45be51500d23a1276991a7cd8c6e");
        assert_eq!(kernels[4].git_id, "4f336dc07eceb77d2164bc1121a5ae6003b19f55");
    }
}
