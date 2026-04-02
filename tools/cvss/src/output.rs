// SPDX-License-Identifier: GPL-2.0-only
//
// Output formatting for CVSS scoring results.
//
// Copyright (c) 2026 - Sasha Levin <sashal@kernel.org>

use crate::scoring::formula::ScoreResult;
use crate::scoring::metrics::CvssMetrics;

pub fn print_result(
    cve_id: Option<&str>,
    vector: &str,
    metrics: &CvssMetrics,
    result: &ScoreResult,
    verbose: bool,
    json_output: bool,
) {
    if json_output {
        print_json(cve_id, vector, result);
        return;
    }

    if let Some(id) = cve_id {
        println!("{}  {:.1}  {}  {}", id, result.score, result.severity, vector);
    } else {
        println!("{:.1}  {}  {}", result.score, result.severity, vector);
    }

    if verbose {
        print_verbose(metrics, result);
    }
}

fn print_verbose(metrics: &CvssMetrics, result: &ScoreResult) {
    println!(
        "  Attack Vector:       {} ({:.2})",
        metrics.av,
        metrics.av.weight()
    );
    println!(
        "  Attack Complexity:   {} ({:.2})",
        metrics.ac,
        metrics.ac.weight()
    );
    println!(
        "  Privileges Required: {} ({:.2})",
        metrics.pr,
        metrics.pr.weight(metrics.scope)
    );
    println!(
        "  User Interaction:    {} ({:.2})",
        metrics.ui,
        metrics.ui.weight()
    );
    println!("  Scope:               {}", metrics.scope);
    println!(
        "  Confidentiality:     {} ({:.2})",
        metrics.confidentiality,
        metrics.confidentiality.weight()
    );
    println!(
        "  Integrity:           {} ({:.2})",
        metrics.integrity,
        metrics.integrity.weight()
    );
    println!(
        "  Availability:        {} ({:.2})",
        metrics.availability,
        metrics.availability.weight()
    );
    println!("  ---");
    println!(
        "  ISS: {:.4}  Impact: {:.4}  Exploitability: {:.4}",
        result.iss, result.impact, result.exploitability
    );
}

fn print_json(cve_id: Option<&str>, vector: &str, result: &ScoreResult) {
    let json = if let Some(id) = cve_id {
        serde_json::json!({
            "cveId": id,
            "score": result.score,
            "severity": result.severity,
            "vectorString": vector
        })
    } else {
        serde_json::json!({
            "score": result.score,
            "severity": result.severity,
            "vectorString": vector
        })
    };

    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"   ");
    let mut buf = Vec::new();
    let mut ser = serde_json::ser::Serializer::with_formatter(&mut buf, formatter);
    serde::Serialize::serialize(&json, &mut ser).unwrap();
    println!("{}", String::from_utf8(buf).unwrap());
}
