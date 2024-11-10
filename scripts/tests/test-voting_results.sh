#!/bin/bash

# SPDX-License-Identifier: GPL-2.0

# Assumes this test lives in scripts/tests/ and voting_results is in scripts/

# Set up paths relative to test location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VOTING_SCRIPT="${SCRIPT_DIR}/voting_results"
TESTDIR=$(mktemp -d)
TEST_CVE_DIR="${TESTDIR}/cve"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test helper functions
setup_test_repo() {
    cd "${TESTDIR}"
    git init -q
    touch MAINTAINERS
    git add MAINTAINERS >/dev/null 2>&1
    git -c user.name="Test" -c user.email="test@example.com" commit -qm "Initial commit" >/dev/null 2>&1
    
    # Create mainline commit with a 40-character SHA
    echo "test file" > testfile
    git add testfile >/dev/null 2>&1
    MAINLINE_SHA=$(git -c user.name="Test" -c user.email="test@example.com" commit -q --no-gpg-sign -m "Test commit 5" --allow-empty | cut -d' ' -f1)
    
    # Create and switch to stable branch
    git checkout -b stable >/dev/null 2>&1
    
    # Tag v6.7.1 at first commit
    git tag -a v6.7.1 -m "v6.7.1" HEAD^ >/dev/null 2>&1
    
    # Create stable commit referencing mainline
    echo "stable fix" > stablefile
    git add stablefile >/dev/null 2>&1
    git -c user.name="Test" -c user.email="test@example.com" commit -q --no-gpg-sign -m "Test commit 5

Upstream: ${MAINLINE_SHA}" >/dev/null 2>&1
    
    git tag -a v6.7.2 -m "v6.7.2" HEAD >/dev/null 2>&1
    
    # Set up the remote to point to our local repo
    git remote add stable . >/dev/null 2>&1
    git fetch stable >/dev/null 2>&1
}

setup_review_files() {
    local version=$1
    # Create review directory in test directory
    mkdir -p "${TEST_CVE_DIR}/review/proposed"
}

debug_info() {
    echo "DEBUG INFO:"
    echo "Current directory: $(pwd)"
    echo "Current branch:"
    git branch
    echo "Git log with upstream info:"
    git log -n 2 --format="%h %s%n%b"
    echo "Git tags with commits:"
    git show-ref --tags
    echo "Review files content for v6.7.2-greg:"
    cat "${TEST_CVE_DIR}/review/proposed/v6.7.2-greg" || echo "File not found"
    echo "Git log between tags:"
    git log v6.7.1..v6.7.2 --format="%h %s"
    echo "Git remote and branches:"
    git remote -v
    git branch -a
    echo "Contents of review directory:"
    ls -la "${TEST_CVE_DIR}/review/proposed/"
}

cleanup() {
    # Remove test directory 
    rm -rf "${TESTDIR}"

    # Clean up any leftover test symlinks
    rm -f "${SCRIPT_DIR}/../cve.test."*

    # Clean up any leftover cve_search backup/test files
    rm -f "${SCRIPT_DIR}/cve_search.test"
    if [ -e "${SCRIPT_DIR}/cve_search.orig" ]; then
        mv "${SCRIPT_DIR}/cve_search.orig" "${SCRIPT_DIR}/cve_search"
    fi
}

assert_contains() {
    if echo "$2" | grep -q "$1"; then
        echo -e "${GREEN}✓ Output contains: $1${NC}"
    else
        echo -e "${RED}✗ Output missing: $1${NC}"
        echo "Actual output:"
        echo "$2"
        debug_info
        exit 1
    fi
}

run_script_with_debug() {
    # Store original script if it exists and create test version
    if [ -e "${SCRIPT_DIR}/cve_search" ]; then
        cp "${SCRIPT_DIR}/cve_search" "${SCRIPT_DIR}/cve_search.orig"
    fi
    echo '#!/bin/bash' > "${SCRIPT_DIR}/cve_search"
    echo 'exit 0' >> "${SCRIPT_DIR}/cve_search"
    chmod +x "${SCRIPT_DIR}/cve_search"

    # Save original cve directory if it exists
    if [ -e "${SCRIPT_DIR}/../cve" ]; then
        mv "${SCRIPT_DIR}/../cve" "${SCRIPT_DIR}/../cve.orig"
    fi

    # Create symlink to our test directory
    ln -sf "${TEST_CVE_DIR}" "${SCRIPT_DIR}/../cve"

    # Run the script
    (
        PS4='+ ${BASH_SOURCE}:${LINENO}: ${FUNCNAME[0]:+${FUNCNAME[0]}(): }'
        bash -x "${VOTING_SCRIPT}" "$@" 2>/tmp/debug.log
    )

    # Clean up test symlink and restore original
    rm -f "${SCRIPT_DIR}/../cve"
    if [ -e "${SCRIPT_DIR}/../cve.orig" ]; then
        mv "${SCRIPT_DIR}/../cve.orig" "${SCRIPT_DIR}/../cve"
    fi

    # Restore original cve_search if it existed
    if [ -e "${SCRIPT_DIR}/cve_search.orig" ]; then
        mv "${SCRIPT_DIR}/cve_search.orig" "${SCRIPT_DIR}/cve_search"
    else
        rm -f "${SCRIPT_DIR}/cve_search"
    fi

    echo "Script debug output:"
    cat /tmp/debug.log
}

# Test cases
test_invalid_directory() {
    echo -e "${BLUE}Testing invalid directory detection...${NC}"
    cd /tmp
    output=$(${VOTING_SCRIPT} v6.7.1..v6.7.2 2>&1)
    assert_contains "Not in a kernel directory" "${output}"
}

test_missing_range() {
    echo -e "${BLUE}Testing missing range parameter...${NC}"
    cd "${TESTDIR}"
    output=$(${VOTING_SCRIPT} 2>&1)
    assert_contains "Please supply a Git range" "${output}"
}

test_invalid_range() {
    echo -e "${BLUE}Testing invalid range format...${NC}"
    cd "${TESTDIR}"
    output=$(${VOTING_SCRIPT} "invalid-range" 2>&1)
    assert_contains "Unrecognised argument" "${output}"
}

test_unanimous_vote() {
    echo -e "${BLUE}Testing unanimous vote detection...${NC}"
    cd "${TESTDIR}"
    local version="v6.7.2"
    local commit_line=$(git log --format="%h %s" -n1 v6.7.2)
    echo "Using commit line: $commit_line"
    
    # Clear previous review files and add approval from all reviewers
    rm -f "${TEST_CVE_DIR}/review/proposed/${version}-*"
    for reviewer in greg lee sasha ruiqi; do
        echo "${commit_line}" > "${TEST_CVE_DIR}/review/proposed/${version}-${reviewer}"
    done
    
    output=$(run_script_with_debug v6.7.1..v6.7.2)
    assert_contains "Everyone agrees" "${output}"
    assert_contains "Test commit 5" "${output}"
}

test_partial_agreement() {
    echo -e "${BLUE}Testing partial agreement detection...${NC}"
    cd "${TESTDIR}"
    local version="v6.7.2"
    local commit_line=$(git log --format="%h %s" -n1 v6.7.2)
    
    # Clear previous review files
    rm -f "${TEST_CVE_DIR}/review/proposed/${version}-*"
    
    # Add approval from only Greg and Lee
    echo "${commit_line}" > "${TEST_CVE_DIR}/review/proposed/${version}-greg"
    echo "${commit_line}" > "${TEST_CVE_DIR}/review/proposed/${version}-lee"
    
    output=$(run_script_with_debug v6.7.1..v6.7.2)
    assert_contains "Greg and Lee agree" "${output}"
    assert_contains "Test commit 5" "${output}"
}

test_cve_detection() {
    echo -e "${BLUE}Testing CVE detection...${NC}"
    cd "${TESTDIR}"
    
    local version="v6.7.2"
    local commit_line=$(git log --format="%h %s" -n1 v6.7.2)
    
    # Clear previous review files
    rm -f "${TEST_CVE_DIR}/review/proposed/${version}-*"
    echo "${commit_line}" > "${TEST_CVE_DIR}/review/proposed/${version}-greg"
    
    output=$(run_script_with_debug v6.7.1..v6.7.2)
    assert_contains "Already assigned a CVE" "${output}"
    assert_contains "Test commit 5" "${output}"
}

test_reviewer_disagreement() {
    echo -e "${BLUE}Testing reviewer disagreement detection...${NC}"
    cd "${TESTDIR}"
    local version="v6.7.2"
    local commit_line=$(git log --format="%h %s" -n1 v6.7.2)
    
    # Clear previous review files
    rm -f "${TEST_CVE_DIR}/review/proposed/${version}-*"
    
    # Add different commit approvals for reviewers
    echo "${commit_line}" > "${TEST_CVE_DIR}/review/proposed/${version}-greg"
    echo "${commit_line}" > "${TEST_CVE_DIR}/review/proposed/${version}-lee"
    # Sasha and Ruiqi have different opinions, so they won't show in the same groups
    echo "different_sha Different commit" > "${TEST_CVE_DIR}/review/proposed/${version}-sasha"
    echo "another_sha Another commit" > "${TEST_CVE_DIR}/review/proposed/${version}-ruiqi"
    
    output=$(run_script_with_debug v6.7.1..v6.7.2)
    assert_contains "Greg and Lee agree" "${output}"
    assert_contains "Sasha only" "${output}"
    assert_contains "Test commit 5" "${output}"
}

test_annotated_reviews() {
    echo -e "${BLUE}Testing annotated review handling...${NC}"
    cd "${TESTDIR}"
    local version="v6.7.2"
    local commit_line=$(git log --format="%h %s" -n1 v6.7.2)
    local commit_sha=$(echo ${commit_line} | cut -d' ' -f1)
    
    # Clear previous review files
    rm -f "${TEST_CVE_DIR}/review/proposed/${version}-*"
    
    # Add approval and annotations from Greg and Lee
    echo "${commit_line}" > "${TEST_CVE_DIR}/review/proposed/${version}-greg"
    echo "${commit_line}" > "${TEST_CVE_DIR}/review/proposed/${version}-lee"
    
    # Add annotations with correct format
    cat > "${TEST_CVE_DIR}/review/proposed/${version}-annotated-greg" <<EOF
${commit_sha}
Potential performance impact on ARM platforms
EOF

    cat > "${TEST_CVE_DIR}/review/proposed/${version}-annotated-lee" <<EOF
${commit_sha}
Need to backport dependent commit first
EOF

    echo "TEST: Contents of review files before test:"
    echo "Greg's review file:"
    cat "${TEST_CVE_DIR}/review/proposed/${version}-greg"
    echo "Greg's annotation file:"
    cat "${TEST_CVE_DIR}/review/proposed/${version}-annotated-greg"
    echo "Lee's review file:"
    cat "${TEST_CVE_DIR}/review/proposed/${version}-lee"
    echo "Lee's annotation file:"
    cat "${TEST_CVE_DIR}/review/proposed/${version}-annotated-lee"
    
    output=$(run_script_with_debug v6.7.1..v6.7.2)
    assert_contains "Greg and Lee agree" "${output}"
    assert_contains "Potential performance impact" "${output}"
    assert_contains "Need to backport dependent commit" "${output}"
    
    echo "TEST: Review directory contents after test:"
    ls -la "${TEST_CVE_DIR}/review/proposed/"
}

# Main test runner
main() {
    trap cleanup EXIT
    
    echo -e "${BLUE}Setting up test environment...${NC}"
    setup_test_repo
    setup_review_files "v6.7.2"
    
    # Run all tests
    test_invalid_directory
    test_missing_range
    test_invalid_range
    test_unanimous_vote
    test_partial_agreement
    test_cve_detection
    test_reviewer_disagreement
    test_annotated_reviews
    
    echo -e "${GREEN}All tests completed successfully!${NC}"
}

main "$@"
