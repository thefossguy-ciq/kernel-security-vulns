// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Greg Kroah-Hartman <gregkh@linuxfoundation.org>
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
//

// Internal modules
mod kernel_pairs;
mod sha_processing;
mod vulnerability;

// Re-export public functions
pub use kernel_pairs::{filter_and_sort_pairs, generate_kernel_pairs, print_kernel_pairs};
pub use sha_processing::{process_fixing_sha, process_vulnerable_sha};
pub use vulnerability::{
    add_provided_vulnerabilities, derive_vulnerabilities, find_fixed_kernels,
    process_vulnerable_kernels,
};
