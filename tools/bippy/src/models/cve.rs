// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct CveMetadata {
    #[serde(rename = "assignerOrgId")]
    pub assigner_org_id: String,
    #[serde(rename = "cveID")]
    pub cve_id: String,
    #[serde(rename = "requesterUserId")]
    pub requester_user_id: String,
    pub serial: String,
    pub state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Description {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProviderMetadata {
    #[serde(rename = "orgId")]
    pub org_id: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct VersionRange {
    // Version string, in a specific type, see versionType below for the valid types
    // 0 means "beginning of time"
    pub version: String,

    #[serde(rename = "lessThan", skip_serializing_if = "Option::is_none")]
    pub less_than: Option<String>,

    #[serde(rename = "lessThanOrEqual", skip_serializing_if = "Option::is_none")]
    pub less_than_or_equal: Option<String>,

    // valid values are "affected", "unaffected", or "unknown"
    pub status: String,

    // valid values are "custom", "git", "maven", "python", "rpm", or "semver"
    // We will just stick with "git" or "semver" as that's the most sane for us, even though
    // "semver" is NOT what Linux kernel release numbers represent at all.
    #[serde(rename = "versionType", skip_serializing_if = "Option::is_none")]
    pub version_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AffectedProduct {
    pub product: String,
    pub vendor: String,
    #[serde(rename = "defaultStatus")]
    pub default_status: String,
    pub repo: String,
    #[serde(rename = "programFiles")]
    pub program_files: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<VersionRange>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Reference {
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Generator {
    pub engine: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct CpeMatch {
    // boolean value, must be "true" or "false"
    pub vulnerable: bool,

    // critera for us is always going to be: "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"
    pub criteria: String,

    #[serde(rename = "versionStartIncluding")]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version_start_including: String,

    #[serde(rename = "versionEndExcluding")]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version_end_excluding: String,

    // Odds are we will not use the following fields, but they are here
    // just to round out the documentation of the schema
    #[serde(rename = "matchCriteriaId")]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub match_criteria_id: String,

    #[serde(rename = "versionStartExcluding")]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version_start_excluding: String,

    #[serde(rename = "versionEndIncluding")]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version_end_including: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CpeNodes {
    // must be "OR" or "AND"
    pub operator: String,
    // boolean value, must be "true" or "false"
    pub negate: bool,
    #[serde(rename = "cpeMatch")]
    pub cpe_match: Vec<CpeMatch>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CpeApplicability {
    pub nodes: Vec<CpeNodes>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CnaData {
    #[serde(rename = "providerMetadata")]
    pub provider_metadata: ProviderMetadata,
    pub descriptions: Vec<Description>,
    pub affected: Vec<AffectedProduct>,
    #[serde(rename = "cpeApplicability")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cpe_applicability: Vec<CpeApplicability>,
    pub references: Vec<Reference>,
    pub title: String,
    #[serde(rename = "x_generator")]
    pub x_generator: Generator,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Containers {
    pub cna: CnaData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CveRecord {
    pub containers: Containers,
    #[serde(rename = "cveMetadata")]
    pub cve_metadata: CveMetadata,
    #[serde(rename = "dataType")]
    pub data_type: String,
    #[serde(rename = "dataVersion")]
    pub data_version: String,
}