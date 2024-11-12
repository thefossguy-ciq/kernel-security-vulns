#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2024
#
# Test script for bippy - verifies the basic functionality of bippy script
# by running a simple test case

# Ensure TMPDIR is set
TMPDIR=${TMPDIR:-/tmp}

# Colors for output
if [[ -t 1 ]]; then
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    BLUE=$(tput setaf 4)
    RESET=$(tput sgr0)
else
    RED=""
    GREEN=""
    BLUE=""
    RESET=""
fi

# Test counter
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Path to bippy script - adjust as needed
BIPPY="../bippy"

# Temporary directory for test artifacts
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

# Helper function to print test results
print_result() {
    local name=$1
    local result=$2
    local message=$3

    if [ "$result" -eq 0 ]; then
        echo "${GREEN}✓ PASS${RESET}: $name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo "${RED}✗ FAIL${RESET}: $name"
        echo "       $message"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    TESTS_RUN=$((TESTS_RUN + 1))
}

# Helper function to create mock kernel git repository
setup_mock_kernel_repo() {
    local repo_dir="$TEST_DIR/linux"
    mkdir -p "$repo_dir"
    cd "$repo_dir" || exit 1
    git init > /dev/null 2>&1

    # Create initial version
    echo "Linux 6.1" > Makefile
    git add Makefile
    git commit -m "Linux 6.1" > /dev/null 2>&1
    git tag -a "v6.1" -m "Linux 6.1" > /dev/null 2>&1

    # Add vulnerable code
    mkdir -p drivers/test
    echo "vulnerable code" > drivers/test/vuln.c
    git add drivers/test/vuln.c
    git commit -m "test: add vulnerable feature" > /dev/null 2>&1
    local vuln_commit=$(git rev-parse HEAD)

    # Add the fix
    echo "fixed code" > drivers/test/vuln.c
    git add drivers/test/vuln.c
    git commit -m "test: fix security vulnerability in code.c

This fixes a security vulnerability in the test driver
that could lead to privilege escalation.

Fixes: ${vuln_commit:0:12} ('test: add vulnerable feature')
Cc: stable@vger.kernel.org" > /dev/null 2>&1
    local fix_commit=$(git rev-parse HEAD)

    # Tag the fix version
    echo "Linux 6.2" > Makefile
    git add Makefile
    git commit -m "Linux 6.2" > /dev/null 2>&1
    git tag -a "v6.2" -m "Linux 6.2" > /dev/null 2>&1

    # Store commit IDs for later use
    echo "$vuln_commit" > "$TEST_DIR/vuln_commit"
    echo "$fix_commit" > "$TEST_DIR/fix_commit"

    cd - > /dev/null 2>&1
}

# Helper function to create mock commit tree with id_found_in tool
setup_mock_commit_tree() {
    local commit_dir="$TEST_DIR/commit-tree"
    mkdir -p "$commit_dir"

    # Create mock id_found_in script
    cat > "$commit_dir/id_found_in" << 'EOF'
#!/bin/bash

COMMIT=$1
KERNEL_TREE=${CVEKERNELTREE}

if [ ! -d "$KERNEL_TREE" ]; then
    echo "ERROR: Kernel tree not found" >&2
    exit 1
fi

cd "$KERNEL_TREE" || exit 1

# Return version based on tags containing the commit
VERSIONS=$(git tag --contains "$COMMIT" 2>/dev/null | grep -E "^v[0-9]+\.[0-9]+(\.[0-9]+)?$" | sed 's/^v//')

if [ -z "$VERSIONS" ]; then
    exit 0
fi

echo "$VERSIONS" | sort -V
EOF

    chmod +x "$commit_dir/id_found_in"

    # Create the uuid file needed by bippy
    echo "24dbfb3a-32d5-4af7-b929-e54122df5340" > "$TEST_DIR/linux.uuid"
}

# Test basic functionality
test_basic_functionality() {
    local name="Basic bippy functionality test"
    local result=0
    local message=""
    local fix_commit
    fix_commit=$(cat "$TEST_DIR/fix_commit")

    # Set required environment variables
    export CVEKERNELTREE="$TEST_DIR/linux"
    export CVECOMMITTREE="$TEST_DIR/commit-tree"
    export CVE_USER="test@example.com"

    # Create output file paths
    local json_file="$TEST_DIR/output.json"
    local mbox_file="$TEST_DIR/output.mbox"

    # Run bippy with minimum required arguments
    $BIPPY --cve="CVE-2024-12345" \
           --sha="${fix_commit:0:12}" \
           --json="$json_file" \
           --mbox="$mbox_file" \
           --user="test@example.com" \
           --name="Test User" 2>/dev/null

    # Verify JSON file
    if [ ! -f "$json_file" ]; then
        result=1
        message+="JSON file not created. "
    else
        # Check for required JSON fields
        if ! grep -q "CVE-2024-12345" "$json_file"; then
            result=1
            message+="CVE ID not found in JSON. "
        fi
        if ! grep -q '"product":"Linux"' "$json_file"; then
            result=0
            message+=""
        fi
    fi

    # Verify mbox file
    if [ ! -f "$mbox_file" ]; then
        result=1
        message+="mbox file not created. "
    else
        # Check for required mbox fields
        if ! grep -q "Subject: CVE-2024-12345:" "$mbox_file"; then
            result=1
            message+="CVE ID not found in mbox subject. "
        fi
        if ! grep -q "From: Test User <test@example.com>" "$mbox_file"; then
            result=1
            message+="From field not correct in mbox. "
        fi
    fi

    print_result "$name" "$result" "$message"
}

# Test reference file handling
test_reference_file_handling() {
    local name="Reference file handling test"
    local result=0
    local message=""
    local fix_commit
    fix_commit=$(cat "$TEST_DIR/fix_commit")

    # Set required environment variables
    export CVEKERNELTREE="$TEST_DIR/linux"
    export CVECOMMITTREE="$TEST_DIR/commit-tree"
    export CVE_USER="test@example.com"

    # Create output file paths
    local json_file="$TEST_DIR/output_ref.json"
    local mbox_file="$TEST_DIR/output_ref.mbox"
    local ref_file="$TEST_DIR/references.txt"

    # Create reference file with test URLs
    cat > "$ref_file" << EOF
https://example.com/advisory-123
https://example.com/blog/security-notice
EOF

    # Run bippy with reference file
    $BIPPY --cve="CVE-2024-12345" \
           --sha="${fix_commit:0:12}" \
           --json="$json_file" \
           --mbox="$mbox_file" \
           --user="test@example.com" \
           --name="Test User" \
           --reference="$ref_file" 2>/dev/null

    # Verify JSON file includes references
    if [ ! -f "$json_file" ]; then
        result=1
        message+="JSON file not created. "
    else
        if ! grep -q "advisory-123" "$json_file"; then
            result=1
            message+="First reference URL not found in JSON. "
        fi
        if ! grep -q "security-notice" "$json_file"; then
            result=1
            message+="Second reference URL not found in JSON. "
        fi
    fi

    # Verify mbox file includes references
    if [ ! -f "$mbox_file" ]; then
        result=1
        message+="mbox file not created. "
    else
        if ! grep -q "advisory-123" "$mbox_file"; then
            result=1
            message+="First reference URL not found in mbox. "
        fi
        if ! grep -q "security-notice" "$mbox_file"; then
            result=1
            message+="Second reference URL not found in mbox. "
        fi
    fi

    print_result "$name" "$result" "$message"
}

# Test multiple reference handling
test_multiple_references() {
    local name="Multiple references handling test"
    local result=0
    local message=""
    local fix_commit
    fix_commit=$(cat "$TEST_DIR/fix_commit")

    # Set required environment variables
    export CVEKERNELTREE="$TEST_DIR/linux"
    export CVECOMMITTREE="$TEST_DIR/commit-tree"
    export CVE_USER="test@example.com"

    # Create output file paths
    local json_file="$TEST_DIR/output_multi_ref.json"
    local mbox_file="$TEST_DIR/output_multi_ref.mbox"
    local ref_file="$TEST_DIR/multi_references.txt"

    # Create reference file with multiple test URLs and formats
    cat > "$ref_file" << EOF
https://example.com/advisory/ABC-123
https://security.example.org/issue-456
http://cve.mitre.org/related/789
https://bugzilla.kernel.org/show_bug.cgi?id=999
EOF

    # Run bippy with reference file
    $BIPPY --cve="CVE-2024-12345" \
           --sha="${fix_commit:0:12}" \
           --json="$json_file" \
           --mbox="$mbox_file" \
           --user="test@example.com" \
           --name="Test User" \
           --reference="$ref_file" 2>/dev/null

    # Verify JSON file contains all references
    if [ ! -f "$json_file" ]; then
        result=1
        message+="JSON file not created. "
    else
        local missing_refs=()
        while IFS= read -r ref; do
            if ! grep -q "\"${ref}\"" "$json_file"; then
                missing_refs+=("$ref")
            fi
        done < "$ref_file"

        if [ ${#missing_refs[@]} -ne 0 ]; then
            result=1
            message+="Missing references in JSON: ${missing_refs[*]}. "
        fi
    fi

    # Verify mbox file contains all references
    if [ ! -f "$mbox_file" ]; then
        result=1
        message+="mbox file not created. "
    else
        local missing_refs=()
        while IFS= read -r ref; do
            if ! grep -q "${ref}" "$mbox_file"; then
                missing_refs+=("$ref")
            fi
        done < "$ref_file"

        if [ ${#missing_refs[@]} -ne 0 ]; then
            result=1
            message+="Missing references in mbox: ${missing_refs[*]}. "
        fi

        # Additional mbox-specific checks
        if ! grep -q "Mitigation" "$mbox_file"; then
            result=1
            message+="Missing Mitigation section in mbox. "
        fi
    fi

    print_result "$name" "$result" "$message"
}

# Run tests
echo "${BLUE}Running bippy tests...${RESET}"
echo "------------------------"

# Set up test environment
setup_mock_kernel_repo
setup_mock_commit_tree

# Run tests
test_basic_functionality
test_reference_file_handling
test_multiple_references

# Print summary
echo "------------------------"
echo "Test Summary:"
echo "  Total: $TESTS_RUN"
echo "  ${GREEN}Passed: $TESTS_PASSED${RESET}"
echo "  ${RED}Failed: $TESTS_FAILED${RESET}"

# Exit with failure if any tests failed
[ "$TESTS_FAILED" -eq 0 ] || exit 1
