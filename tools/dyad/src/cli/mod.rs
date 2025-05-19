// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Greg Kroah-Hartman <gregkh@linuxfoundation.org>
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>
//

use gumdrop::Options;

/// Command line arguments for the dyad tool
#[derive(Debug, Options)]
pub struct DyadArgs {
    #[options(help_flag, help = "Print this help message")]
    pub help: bool,

    #[options(short = "V", help = "Show version")]
    pub version: bool,

    #[options(no_short, help = "Show debugging information to stdout")]
    pub verbose: bool,

    #[options(
        short = "s",
        help = "The kernel git sha1 that fixes this issue",
        multi = "push"
    )]
    pub sha1: Vec<String>,

    #[options(
        short = "v",
        help = "The kernel git sha1 that this issue became vulnerable at",
        multi = "push"
    )]
    pub vulnerable: Vec<String>,
}

/// Parse command line arguments and return the result
pub fn parse_args() -> DyadArgs {
    DyadArgs::parse_args_default_or_exit()
}
