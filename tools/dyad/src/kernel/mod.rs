// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Greg Kroah-Hartman <gregkh@linuxfoundation.org>
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
//

// Internal modules
mod sha_processing;
mod vulnerability;
mod kernel_pairs;

// Re-export public functions
pub use sha_processing::{process_fixing_sha, process_vulnerable_sha};
pub use vulnerability::{
    find_fixed_kernels,
    add_provided_vulnerabilities,
    derive_vulnerabilities,
    process_vulnerable_kernels
};
pub use kernel_pairs::{generate_kernel_pairs, filter_and_sort_pairs, print_kernel_pairs};