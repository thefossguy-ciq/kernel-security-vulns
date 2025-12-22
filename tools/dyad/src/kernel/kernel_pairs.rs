// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Greg Kroah-Hartman <gregkh@linuxfoundation.org>
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
//

use crate::state::DyadState;
use cve_utils::{Kernel, KernelPair};
use log::debug;
use owo_colors::{OwoColorize, Stream::Stdout};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

/// Process pairs with exact version match (Priority 1)
fn find_exact_version_match(
    fixed_kernel: &Kernel,
    vulnerabilities: &[Kernel],
) -> Option<KernelPair> {
    for vuln in vulnerabilities {
        if fixed_kernel.version() == vuln.version() {
            debug!(
                "\t\t{} == {} save it",
                fixed_kernel.version(),
                vuln.version()
            );
            return Some(KernelPair {
                vulnerable: vuln.clone(),
                fixed: fixed_kernel.clone(),
            });
        }
    }
    None
}

/// Process mainline-to-mainline pairs (Priority 2)
fn find_mainline_to_mainline_matches(
    fixed_kernel: &Kernel,
    mainline_vulns: &[&Kernel],
) -> Vec<KernelPair> {
    let mut pairs = Vec::new();

    if fixed_kernel.is_mainline() && !mainline_vulns.is_empty() {
        // For mainline fixes, pair with all mainline vulnerabilities
        for vuln in mainline_vulns {
            // Only add pairs where fix version >= vulnerable version
            if fixed_kernel.compare(vuln) != std::cmp::Ordering::Less {
                debug!(
                    "\t\t{} and {} are both mainline, save it",
                    fixed_kernel.version(),
                    vuln.version()
                );
                pairs.push(KernelPair {
                    vulnerable: (*vuln).clone(),
                    fixed: fixed_kernel.clone(),
                });
            }
        }
    }

    pairs
}

/// Find matches based on same major version (Priority 3)
fn find_same_major_version_match(
    fixed_kernel: &Kernel,
    vulnerabilities: &[Kernel],
) -> Option<KernelPair> {
    for vuln in vulnerabilities {
        if vuln.version_major_match(fixed_kernel) {
            debug!(
                "\t\t{} and {} are same major release, save it",
                fixed_kernel.version(),
                vuln.version()
            );
            return Some(KernelPair {
                vulnerable: vuln.clone(),
                fixed: fixed_kernel.clone(),
            });
        }
    }
    None
}

/// Calculate version distance between kernel versions
fn calculate_version_distance(v: &Kernel, k: &Kernel) -> Option<i32> {
    let v_version_parts: Vec<i32> = v
        .version()
        .split('.')
        .filter_map(|s| s.parse::<i32>().ok())
        .collect();

    let k_version_parts: Vec<i32> = k
        .version()
        .split('.')
        .filter_map(|s| s.parse::<i32>().ok())
        .collect();

    if !v_version_parts.is_empty() && !k_version_parts.is_empty() {
        let v_major = v_version_parts[0];
        let k_major = k_version_parts[0];

        // Only consider vulnerabilities that come before the fix
        if v_major <= k_major {
            // Calculate version distance - prioritize closeness
            let mut distance = (k_major - v_major) * 100;

            // Add minor version component
            if v_version_parts.len() > 1 && k_version_parts.len() > 1 {
                let v_minor = v_version_parts[1];
                let k_minor = k_version_parts[1];
                distance += (k_minor - v_minor).abs();
            }

            return Some(distance);
        }
    }

    None
}

/// Find best mainline match based on version proximity (Priority 4)
fn find_best_mainline_match(
    fixed_kernel: &Kernel,
    mainline_vulns: &[&Kernel],
) -> Option<KernelPair> {
    if mainline_vulns.is_empty() {
        return None;
    }

    let mut best_match: Option<&Kernel> = None;
    let mut best_match_score = i32::MAX;

    for vuln in mainline_vulns {
        if let Some(distance) = calculate_version_distance(vuln, fixed_kernel)
            && distance < best_match_score {
                best_match_score = distance;
                best_match = Some(vuln);
                debug!(
                    "\t\t\tFound better mainline match: {} -> {} (score: {})",
                    vuln.version(),
                    fixed_kernel.version(),
                    distance
                );
            }
    }

    if let Some(best_vuln) = best_match {
        debug!(
            "\t\tUsing closest mainline vulnerability {} for fix {} (score: {})",
            best_vuln.version(),
            fixed_kernel.version(),
            best_match_score
        );

        return Some(KernelPair {
            vulnerable: best_vuln.clone(),
            fixed: fixed_kernel.clone(),
        });
    } else if !mainline_vulns.is_empty() {
        // Fall back to oldest mainline if we couldn't find a better match
        let closest_mainline = mainline_vulns[0];
        debug!(
            "\t\tFalling back to oldest mainline vulnerability {} for fix {}",
            closest_mainline.version(),
            fixed_kernel.version()
        );

        return Some(KernelPair {
            vulnerable: closest_mainline.clone(),
            fixed: fixed_kernel.clone(),
        });
    }

    None
}

/// Find best match based on version distance (Priority 5)
fn find_best_version_match(
    fixed_kernel: &Kernel,
    vulnerabilities: &[Kernel],
) -> Option<KernelPair> {
    let mut best_match: Option<&Kernel> = None;
    let mut best_match_score = i32::MAX;

    for vuln in vulnerabilities {
        if let Some(distance) = calculate_version_distance(vuln, fixed_kernel)
            && distance < best_match_score {
                best_match_score = distance;
                best_match = Some(vuln);
                debug!(
                    "\t\t\tFound better version match: {} -> {} (score: {})",
                    vuln.version(),
                    fixed_kernel.version(),
                    distance
                );
            }
    }

    if let Some(vuln) = best_match {
        debug!(
            "\t\tbest version match for {} is {}, score {}",
            fixed_kernel.version(),
            vuln.version(),
            best_match_score
        );

        return Some(KernelPair {
            vulnerable: vuln.clone(),
            fixed: fixed_kernel.clone(),
        });
    }

    None
}

/// Find default pairing if no other matches found
fn find_default_match(fixed_kernel: &Kernel, vulnerabilities: &[Kernel]) -> Option<KernelPair> {
    // Get the oldest mainline kernel from the vulnerable set
    let oldest_mainline_kernel = vulnerabilities
        .iter()
        .filter(|k| k.is_mainline())
        .min_by(|a, b| a.compare(b))
        .cloned();

    if let Some(kernel) = oldest_mainline_kernel {
        debug!(
            "\tnothing found for {}, using default of {:?}",
            fixed_kernel.version(),
            kernel
        );

        return Some(KernelPair {
            vulnerable: kernel,
            fixed: fixed_kernel.clone(),
        });
    }

    debug!(
        "\tno mainline pair vulnerable at this point in time (fix in the future?), so skipping {}",
        fixed_kernel.version()
    );

    None
}

/// Process unfixed vulnerabilities to find matching pairs
fn process_unfixed_vulnerabilities(
    vulnerable_kernel: &Kernel,
    fixed_pairs: &[KernelPair],
    fixed_set: &[Kernel],
) -> Option<KernelPair> {
    // Check if this vulnerability is already part of a pair
    for pair in fixed_pairs {
        if vulnerable_kernel.version() == pair.vulnerable.version()
            && vulnerable_kernel.git_id() == pair.vulnerable.git_id()
        {
            return None;
        }
        if vulnerable_kernel.version() == pair.fixed.version() {
            return None;
        }
    }

    debug!("not found {vulnerable_kernel:?}");

    // Attempt to find a matching fix for this vulnerable version
    let mut best_fix: Option<Kernel> = None;

    // Find a compatible kernel version in the fixed_set
    for fix in fixed_set {
        // Check if this is a mainline fix for a mainline vulnerability
        if vulnerable_kernel.is_mainline() && fix.is_mainline() {
            // For mainline vulnerable and fixed, pick the closest future release
            if fix.compare(vulnerable_kernel) == std::cmp::Ordering::Greater
                && (best_fix.is_none()
                    || fix.compare(best_fix.as_ref().unwrap()) == std::cmp::Ordering::Less)
            {
                best_fix = Some(fix.clone());
            }
        }
    }

    // If we found a fix, create a pair
    best_fix.map_or_else(
        || {
            // No fix found, mark as unfixed
            Some(KernelPair {
                vulnerable: vulnerable_kernel.clone(),
                fixed: Kernel::empty_kernel(),
            })
        },
        |fix| {
            debug!(
                "Found compatible fix for {} in {}",
                vulnerable_kernel.version(),
                fix.version()
            );

            Some(KernelPair {
                vulnerable: vulnerable_kernel.clone(),
                fixed: fix,
            })
        },
    )
}

pub fn generate_kernel_pairs(state: &DyadState) -> Vec<KernelPair> {
    // Our "pairs of vuln/fixed kernels
    let mut fixed_pairs: Vec<KernelPair> = vec![];

    // Track which fix commits have been used via revert_pairs so we skip them in the general logic
    let mut used_fix_ids: HashSet<String> = HashSet::new();
    // Track which vulnerable commits were already paired via revert - they shouldn't participate
    // in general pairing since the revert already fixed them
    let mut revert_fixed_vuln_ids: HashSet<String> = HashSet::new();

    // First, add the revert-based pairs directly. We already know exactly which vulnerable
    // commit each revert fixes, so we don't need to go through the general pairing logic.
    for (vuln_kernel, fix_kernel) in &state.revert_pairs {
        debug!(
            "Adding revert-based pair directly: {} ({}) -> {} ({})",
            vuln_kernel.version(), vuln_kernel.git_id(),
            fix_kernel.version(), fix_kernel.git_id()
        );
        fixed_pairs.push(KernelPair {
            vulnerable: vuln_kernel.clone(),
            fixed: fix_kernel.clone(),
        });
        used_fix_ids.insert(fix_kernel.git_id());
        revert_fixed_vuln_ids.insert(vuln_kernel.git_id());
    }

    // Now we have two lists, one where the kernel became vulnerable (could not be known, so we
    // assume 0), and where it was fixed (the id originally passed to us and where it has been
    // backported to.) Take those two lists and start matching them up based on kernel versions

    // Iterate over all of the "fixed" kernel versions/ids
    for fixed_kernel in &state.fixed_set {
        // Skip fixes that were already used in revert-based pairs
        if used_fix_ids.contains(&fixed_kernel.git_id()) {
            debug!("\t skipping {fixed_kernel:?} (already used in revert pair)");
            continue;
        }
        let mut create: bool = false;

        debug!("\t k={fixed_kernel:?}");

        // Case: No vulnerabilities specified
        if state.vulnerable_set.is_empty() {
            fixed_pairs.push(KernelPair {
                vulnerable: Kernel::empty_kernel(),
                fixed: fixed_kernel.clone(),
            });
            continue;
        }

        // Sort vulnerable kernels by version for more predictable pairing
        // Exclude vulnerabilities that were already fixed by a revert
        let mut sorted_vulnerabilities: Vec<Kernel> = state.vulnerable_set
            .iter()
            .filter(|k| !revert_fixed_vuln_ids.contains(&k.git_id()))
            .cloned()
            .collect();
        sorted_vulnerabilities.sort();

        // Get mainline vulnerabilities
        let mainline_vulns = sorted_vulnerabilities
            .iter()
            .filter(|k| k.is_mainline())
            .collect::<Vec<_>>();

        // Priority 1: Exact version match
        if let Some(pair) = find_exact_version_match(fixed_kernel, &sorted_vulnerabilities) {
            fixed_pairs.push(pair);
            create = true;
        }

        // If we haven't found a match yet, try other matching strategies
        if !create {
            // Priority 2: Mainline to mainline special case
            let mainline_pairs = find_mainline_to_mainline_matches(fixed_kernel, &mainline_vulns);
            if !mainline_pairs.is_empty() {
                fixed_pairs.extend(mainline_pairs);
                create = true;
            }
            // Priority 3: Same major version line
            else if let Some(pair) =
                find_same_major_version_match(fixed_kernel, &sorted_vulnerabilities)
            {
                fixed_pairs.push(pair);
                create = true;
            }
        }

        // Priority 4: Best mainline match based on version proximity
        if !create && !mainline_vulns.is_empty()
            && let Some(pair) = find_best_mainline_match(fixed_kernel, &mainline_vulns) {
                fixed_pairs.push(pair);
                create = true;
            }

        // Priority 5: Distance-based scoring for all vulnerabilities
        if !create
            && let Some(pair) = find_best_version_match(fixed_kernel, &sorted_vulnerabilities) {
                fixed_pairs.push(pair);
                create = true;
            }

        // Default: Use oldest mainline vulnerability as default
        if !create
            && let Some(pair) = find_default_match(fixed_kernel, &state.vulnerable_set) {
                fixed_pairs.push(pair);
            }
    }

    // Process unfixed vulnerabilities (skip those already fixed by revert)
    for vuln in &state.vulnerable_set {
        if revert_fixed_vuln_ids.contains(&vuln.git_id()) {
            continue;
        }
        if let Some(pair) = process_unfixed_vulnerabilities(vuln, &fixed_pairs, &state.fixed_set) {
            fixed_pairs.push(pair);
        }
    }

    fixed_pairs
}

/// Filter and sort kernel pairs to ensure consistency and accuracy
pub fn filter_and_sort_pairs(pairs: &[KernelPair]) -> Vec<KernelPair> {
    // We need to filter out invalid pairs
    // For example, if we have a vulnerability in 6.6 and fixes in 6.7 and 6.13,
    // we shouldn't create a pair 6.6:6.13 if the version was fixed in 6.7
    let mut filtered_pairs: Vec<KernelPair> = Vec::new();

    // First, separate the pairs by vulnerable git id
    let mut pairs_by_vuln_id: HashMap<String, Vec<KernelPair>> = HashMap::new();

    for pair in pairs {
        // Skip empty kernel pairs (unfixed)
        if pair.fixed.version() == "0" {
            filtered_pairs.push(pair.clone());
            continue;
        }

        let vuln_id = pair.vulnerable.git_id();
        pairs_by_vuln_id
            .entry(vuln_id)
            .or_default()
            .push(pair.clone());
    }

    // Process each set of pairs for a specific vulnerability
    for (vuln_id, mut vuln_pairs) in pairs_by_vuln_id {
        // Sort the pairs within each vulnerability group
        vuln_pairs.sort_by(|a, b| {
            // First group by fix type: stable vs mainline
            if a.fixed.is_mainline() != b.fixed.is_mainline() {
                // For different types, prefer mainline
                return if a.fixed.is_mainline() {
                    Ordering::Less
                } else {
                    Ordering::Greater
                };
            }

            // If both are mainline, sort by version (ascending - we want closest future version first)
            if a.fixed.is_mainline() {
                return a.fixed.compare(&b.fixed);
            }

            // For stable kernels, compare versions normally (ascending)
            a.fixed.compare(&b.fixed)
        });

        // Debugging output
        debug!("Processing vulnerability ID {vuln_id} pairs:");
        for pair in &vuln_pairs {
            debug!(
                "  {} -> {}",
                pair.vulnerable.version(),
                pair.fixed.version()
            );
        }

        // Find the best mainline fix for this vulnerability
        let mut mainline_fix = None;
        for pair in &vuln_pairs {
            if pair.fixed.is_mainline() {
                mainline_fix = Some(pair.clone());
                break;
            }
        }

        // Record and add the mainline fix pair if found
        if let Some(mainline_pair) = mainline_fix {
            debug!(
                "Selected mainline fix for {}:{} -> {}",
                mainline_pair.vulnerable.version(),
                vuln_id,
                mainline_pair.fixed.version()
            );
            filtered_pairs.push(mainline_pair);
        }

        // Add all stable fix pairs for this vulnerability
        for pair in &vuln_pairs {
            if !pair.fixed.is_mainline() {
                // Ensure that the mainline kernel isn't "newer" than the fixed kernel, this catches things
                // where a fix was backported to older kernels, but the vulnerable commit never was, so
                // there's no "vulnerable" range here.
                if pair.vulnerable > pair.fixed {
                    debug!("Skipping {}:{} as this range is backwards", pair.vulnerable.version(), pair.fixed.version());
                    continue;
                }

                debug!(
                    "Added stable fix for {}:{} -> {}",
                    pair.vulnerable.version(),
                    vuln_id,
                    pair.fixed.version()
                );
                filtered_pairs.push(pair.clone());
            }
        }
    }

    // Sort the filtered pairs by fixed kernel version to ensure consistent order
    filtered_pairs.sort_by(|a, b| {
        // If one is unfixed (version "0"), it goes last
        if a.fixed.version() == "0" {
            return Ordering::Greater;
        }
        if b.fixed.version() == "0" {
            return Ordering::Less;
        }

        // If fixed is not equal, compare them
        if a.fixed.version() != b.fixed.version() {
            return a.fixed.compare(&b.fixed);
        }

        // Otherwise, sort by vulnerable version
        a.vulnerable.compare(&b.vulnerable)
    });

    filtered_pairs
}

/// Print kernel pairs in the format required by bippy
pub fn print_kernel_pairs(pairs: &[KernelPair]) {
    for e in pairs {
        /* ***POLICY***
         * FIXME
         * Should we be testing for if we have a fix in an older kernel than was actually
         * vulnerable?  If so, uncomment this if {} out for it to print it in a comment only
         */
        /*
        if !e.fixed.is_empty() && (e.vulnerable > e.fixed) {
            print!("# fix before vulnerable ");
        }
        */
        println!(
            "{}:{}:{}:{}",
            e.vulnerable
                .version()
                .if_supports_color(Stdout, |x| x.green()),
            e.vulnerable
                .git_id()
                .if_supports_color(Stdout, |x| x.cyan()),
            e.fixed.version().if_supports_color(Stdout, |x| x.green()),
            e.fixed.git_id().if_supports_color(Stdout, |x| x.cyan())
        );
    }
}
