// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

pub mod json;
pub mod mbox;

pub use json::generate_json_record;
pub use mbox::generate_mbox;