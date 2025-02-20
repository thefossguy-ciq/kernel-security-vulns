#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2025 - Sasha Levin <sashal@kernel.org>

#set -x
# Directory paths
REVIEW_DIR="cve/review/done"
PUBLISHED_DIR="cve/published"

# Function to check if a commit has a CVE
check_commit_has_cve() {
    local commit="$1"
    # Extract just the SHA1 (first column) and search through published .sha1 files
    local sha1=$(echo "$commit" | cut -d' ' -f1)
    # Search through all year directories in published, only in .sha1 files
    for year_dir in "$PUBLISHED_DIR"/*/; do
        if grep -q "^$sha1" "$year_dir"/*.sha1 2>/dev/null; then
            return 0  # Found
        fi
    done
    return 1  # Not found
}

# Get unique reviewer names from all review files recursively
get_reviewers() {
    find "$REVIEW_DIR" -type f -name "v*-*" -not -path "*/gsd/*" -not -name "*annotated*" | 
    sed -n 's/.*v[0-9.]*-\([^/]*\)$/\1/p' | 
    sort -u
}

# Create a temporary directory for our data
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# First pass: collect all reviews
collect_reviews() {
    local reviewer="$1"

    # Find all review files for this reviewer recursively
    find "$REVIEW_DIR" -type f -name "v*-$reviewer" -not -path "*/gsd/*" -not -name "*annotated*" | while read -r file; do
        # Extract version from filename
        version=$(basename "$file" | sed -n 's/\(v[0-9.]*\).*/\1/p')
        while IFS= read -r commit || [ -n "$commit" ]; do
            [ -z "$commit" ] && continue
            sha1=$(echo "$commit" | cut -d' ' -f1)
            # Store with version info
            echo "$version $sha1" >> "$TEMP_DIR/all_reviews"
            echo "$sha1" >> "$TEMP_DIR/by_reviewer/$reviewer"
            echo "$version" >> "$TEMP_DIR/versions_by_reviewer/$reviewer"
        done < "$file"
    done
}

# Function to process a single reviewer
process_reviewer() {
    local reviewer="$1"
    local total_predictions=0
    local correct_predictions=0
    local missed_consensus=0
    local total_possible_consensus=0
    local files_processed=0

    # Count predictions and correct ones
    [ -f "$TEMP_DIR/by_reviewer/$reviewer" ] || return
    total_predictions=$(sort -u "$TEMP_DIR/by_reviewer/$reviewer" | wc -l)

    while read -r sha1; do
        if check_commit_has_cve "$sha1"; then
            ((correct_predictions++))
        fi
    done < <(sort -u "$TEMP_DIR/by_reviewer/$reviewer")

    # Get the versions this reviewer has reviewed
    [ -f "$TEMP_DIR/versions_by_reviewer/$reviewer" ] || return
    sort -u "$TEMP_DIR/versions_by_reviewer/$reviewer" > "$TEMP_DIR/reviewer_versions"

    # Get all commits from versions this reviewer has reviewed
    while read -r version sha1; do
        # Only check versions this reviewer has reviewed
        grep -qFx "$version" "$TEMP_DIR/reviewer_versions" || continue
        
        # If the commit has a CVE, count it towards total possible consensus
        if check_commit_has_cve "$sha1"; then
            ((total_possible_consensus++))
            # If this reviewer didn't mark it, it's a missed consensus
            if ! grep -qF "$sha1" "$TEMP_DIR/by_reviewer/$reviewer" 2>/dev/null; then
                ((missed_consensus++))
            fi
        fi
    done < <(cut -d' ' -f1,2 "$TEMP_DIR/all_reviews" | sort -u)

    # Output results if there were any predictions
    if [ "$total_predictions" -gt 0 ]; then
        local hit_percentage=$(awk "BEGIN {printf \"%.1f\", ($correct_predictions / $total_predictions) * 100}")
        local missed_percentage=0
        if [ "$total_possible_consensus" -gt 0 ]; then
            missed_percentage=$(awk "BEGIN {printf \"%.1f\", ($missed_consensus / $total_possible_consensus) * 100}")
        fi
        
        echo "  Done processing $reviewer: $correct_predictions/$total_predictions predictions correct" >&2
        echo "  Missed $missed_consensus/$total_possible_consensus possible consensus commits" >&2
        echo >&2
        printf "%-15s: Hit consensus: %5.1f%% (%d/%d) | Missed consensus: %5.1f%% (%d/%d)\n" \
            "$reviewer" "$hit_percentage" "$correct_predictions" "$total_predictions" \
            "$missed_percentage" "$missed_consensus" "$total_possible_consensus"
    fi
}

export -f process_reviewer check_commit_has_cve collect_reviews
export REVIEW_DIR PUBLISHED_DIR TEMP_DIR

# Main processing
echo "Reviewer Accuracy Report"
echo "======================="
echo

# Get reviewers
mapfile -t reviewers < <(get_reviewers)
total_reviewers=${#reviewers[@]}

echo "Found $total_reviewers reviewers to process"
echo

# Create directories for per-reviewer files
mkdir -p "$TEMP_DIR/by_reviewer"
mkdir -p "$TEMP_DIR/versions_by_reviewer"

# First collect all reviews
echo "Collecting all reviews..."
parallel --keep-order collect_reviews ::: "${reviewers[@]}"

# Then process each reviewer
echo "Processing reviewers..."
parallel --keep-order --line-buffer process_reviewer ::: "${reviewers[@]}" | sort -t':' -k3 -nr

echo
echo "Analysis complete!"
