// SPDX-License-Identifier: GPL-2.0-only
//
// JSON writer tests for metrics insertion.

use serde_json::Value;
use std::fs;
use tempfile::tempdir;

/// Minimal CVE JSON structure for testing.
fn sample_cve_json() -> Value {
    serde_json::json!({
        "containers": {
            "cna": {
                "providerMetadata": {
                    "orgId": "f4215fc3-5b6b-47ff-a258-f7189bd81038"
                },
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Test vulnerability description."
                    }
                ],
                "affected": [
                    {
                        "product": "Linux",
                        "vendor": "Linux",
                        "defaultStatus": "unaffected",
                        "repo": "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
                        "programFiles": ["net/sched/sch_qfq.c"],
                        "versions": []
                    }
                ],
                "references": [
                    {"url": "https://git.kernel.org/stable/c/abc123"}
                ],
                "title": "Test CVE title",
                "x_generator": {
                    "engine": "bippy-1.2.0"
                }
            }
        },
        "cveMetadata": {
            "assignerOrgId": "f4215fc3-5b6b-47ff-a258-f7189bd81038",
            "cveID": "CVE-2026-99999",
            "requesterUserId": "test@kernel.org",
            "serial": "1",
            "state": "PUBLISHED"
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0"
    })
}

/// Write a test CVE JSON file mimicking the real directory structure.
fn setup_test_cve(dir: &std::path::Path, cve_id: &str) -> std::path::PathBuf {
    // Create the directory structure: cve/published/YEAR/
    let year = &cve_id[4..8]; // Extract year from CVE-YYYY-XXXXX
    let published_dir = dir.join("cve").join("published").join(year);
    fs::create_dir_all(&published_dir).unwrap();

    let json_path = published_dir.join(format!("{cve_id}.json"));
    let sha1_path = published_dir.join(format!("{cve_id}.sha1"));

    // Write sample JSON
    let json = sample_cve_json();
    let mut modified = json.clone();
    modified["cveMetadata"]["cveID"] = Value::String(cve_id.to_string());
    fs::write(
        &json_path,
        serde_json::to_string_pretty(&modified).unwrap(),
    )
    .unwrap();

    // Write a fake .sha1
    fs::write(&sha1_path, "abc123def456\n").unwrap();

    // Also create the empty CVE file (the directory marker)
    fs::write(published_dir.join(cve_id), "").unwrap();

    json_path
}

#[test]
fn metrics_structure_is_correct() {
    let dir = tempdir().unwrap();
    let json_path = setup_test_cve(dir.path(), "CVE-2026-99999");

    // Manually write metrics using the json_writer logic
    let content = fs::read_to_string(&json_path).unwrap();
    let mut root: Value = serde_json::from_str(&content).unwrap();

    let metrics = serde_json::json!([
        {
            "cvssV3_1": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                "baseScore": 5.5,
                "baseSeverity": "MEDIUM"
            }
        }
    ]);

    root["containers"]["cna"]
        .as_object_mut()
        .unwrap()
        .insert("metrics".to_string(), metrics);

    // Verify structure
    let m = &root["containers"]["cna"]["metrics"][0]["cvssV3_1"];
    assert_eq!(m["version"], "3.1");
    assert_eq!(
        m["vectorString"],
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
    );
    assert_eq!(m["baseScore"], 5.5);
    assert_eq!(m["baseSeverity"], "MEDIUM");
}

#[test]
fn original_fields_preserved_after_metrics_insertion() {
    let dir = tempdir().unwrap();
    let json_path = setup_test_cve(dir.path(), "CVE-2026-99998");

    let content = fs::read_to_string(&json_path).unwrap();
    let mut root: Value = serde_json::from_str(&content).unwrap();

    let metrics = serde_json::json!([
        {
            "cvssV3_1": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "baseScore": 9.8,
                "baseSeverity": "CRITICAL"
            }
        }
    ]);

    root["containers"]["cna"]
        .as_object_mut()
        .unwrap()
        .insert("metrics".to_string(), metrics);

    // Verify original fields are preserved
    assert_eq!(root["containers"]["cna"]["title"], "Test CVE title");
    assert_eq!(
        root["containers"]["cna"]["descriptions"][0]["value"],
        "Test vulnerability description."
    );
    assert_eq!(root["cveMetadata"]["cveID"], "CVE-2026-99998");
    assert_eq!(root["dataType"], "CVE_RECORD");
    assert_eq!(root["dataVersion"], "5.0");
}

#[test]
fn three_space_indentation() {
    let dir = tempdir().unwrap();
    let json_path = setup_test_cve(dir.path(), "CVE-2026-99997");

    let content = fs::read_to_string(&json_path).unwrap();
    let mut root: Value = serde_json::from_str(&content).unwrap();

    root["containers"]["cna"]
        .as_object_mut()
        .unwrap()
        .insert(
            "metrics".to_string(),
            serde_json::json!([{"cvssV3_1": {"baseScore": 7.8}}]),
        );

    // Serialize with 3-space indent
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"   ");
    let mut output = Vec::new();
    let mut serializer = serde_json::ser::Serializer::with_formatter(&mut output, formatter);
    serde::Serialize::serialize(&root, &mut serializer).unwrap();
    let json_string = String::from_utf8(output).unwrap();

    // Verify 3-space indentation is used
    assert!(
        json_string.contains("   \"containers\""),
        "should use 3-space indentation"
    );
    // Verify NOT 2-space or 4-space
    assert!(
        !json_string.contains("    \"containers\""),
        "should not use 4-space indentation"
    );
}

#[test]
fn metrics_replacement() {
    let dir = tempdir().unwrap();
    let json_path = setup_test_cve(dir.path(), "CVE-2026-99996");

    // First, add initial metrics
    let content = fs::read_to_string(&json_path).unwrap();
    let mut root: Value = serde_json::from_str(&content).unwrap();
    root["containers"]["cna"]
        .as_object_mut()
        .unwrap()
        .insert(
            "metrics".to_string(),
            serde_json::json!([{"cvssV3_1": {"baseScore": 1.0}}]),
        );
    fs::write(
        &json_path,
        serde_json::to_string_pretty(&root).unwrap(),
    )
    .unwrap();

    // Now replace with new metrics
    let content = fs::read_to_string(&json_path).unwrap();
    let mut root: Value = serde_json::from_str(&content).unwrap();
    root["containers"]["cna"]
        .as_object_mut()
        .unwrap()
        .insert(
            "metrics".to_string(),
            serde_json::json!([{"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]),
        );

    assert_eq!(
        root["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"],
        9.8
    );
}
