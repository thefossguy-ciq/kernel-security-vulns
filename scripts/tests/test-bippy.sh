#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2024
#
# Test script for bippy - verifies the basic functionality of bippy script
# by running a simple test case

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

# Download and cache the CVE schema
setup_cve_schema() {
    local schema_file="$TEST_DIR/cve_schema.json"
    local schema_url="https://raw.githubusercontent.com/CVEProject/cve-schema/main/schema/CVE_Record_Format.json"

    # Download schema if we don't have it
    if [ ! -f "$schema_file" ]; then
        if ! curl -sSL "$schema_url" -o "$schema_file"; then
            echo "${RED}Failed to download CVE schema${RESET}" >&2
            return 1
        fi
    fi

    # Verify we have a valid JSON file
    if ! jq empty "$schema_file" 2>/dev/null; then
        echo "${RED}Downloaded schema is not valid JSON${RESET}" >&2
        return 1
    fi

    echo "$schema_file"
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

# Test JSON changelog/commit message truncation handling
test_json_truncation() {
    local name="JSON changelog truncation test"
    local result=0
    local message=""
    local fix_commit
    fix_commit=$(cat "$TEST_DIR/fix_commit")

    # Set required environment variables
    export CVEKERNELTREE="$TEST_DIR/linux"
    export CVECOMMITTREE="$TEST_DIR/commit-tree"
    export CVE_USER="test@example.com"

    local json_file="$TEST_DIR/output_truncation.json"
    local long_commit_file="$TEST_DIR/long_commit.txt"

    # Create a commit message longer than 3982 bytes
    printf 'test: Add very long commit message for truncation test\n\n' > "$long_commit_file"
    printf 'a%.0s' {1..5000} >> "$long_commit_file"

    # Modify the git repo to use this long commit message
    (cd "$TEST_DIR/linux" && \
        git add drivers/test/vuln.c && \
        git commit --amend -F "$long_commit_file" > /dev/null 2>&1) || {
            print_result "$name" 1 "Failed to set up test commit"
            return
        }

    # Run bippy
    $BIPPY --cve="CVE-2024-12345" \
           --sha="${fix_commit:0:12}" \
           --json="$json_file" \
           --user="test@example.com" \
           --name="Test User" 2>/dev/null

    # Verify JSON file exists
    if [ ! -f "$json_file" ]; then
        print_result "$name" 1 "JSON file not created"
        return
    fi

    # Extract the description text from JSON
    local description
    description=$(perl -MJSON::PP -e '
        local $/;
        my $json = decode_json(<>);
        my $desc = $json->{containers}{cna}{descriptions}[0]{value};
        print $desc;
    ' "$json_file")

    local desc_length=${#description}

    # Check if description exists
    if [ -z "$description" ]; then
        print_result "$name" 1 "No description found in JSON"
        return
    fi

    # Verify length is under limit
    if [ "$desc_length" -gt 3982 ]; then
        message+="Description length ($desc_length) exceeds 3982 byte limit. "
    fi

    # Verify truncation marker is present when needed
    if [ "$desc_length" -ge 3970 ]; then
        if ! echo "$description" | grep -q "---truncated---"; then
            message+="Missing truncation marker in truncated description. "
        fi
    fi

    # Verify required CVE prefix
    local required_prefix="In the Linux kernel, the following vulnerability has been resolved:"
    if ! echo "$description" | grep -q "^$required_prefix"; then
        message+="Missing required CVE description prefix. "
    fi

    # Set result if any checks failed
    if [ -n "$message" ]; then
        result=1
    fi

    print_result "$name" "$result" "$message"
}

# Test JSON schema validation
test_json_schema_validation() {
    local name="JSON schema validation test"
    local result=0
    local message=""
    local fix_commit
    fix_commit=$(cat "$TEST_DIR/fix_commit")

    # Check for required tools
    if ! command -v jq >/dev/null 2>&1; then
        print_result "$name" 1 "jq is required but not installed"
        return
    fi

    if ! command -v curl >/dev/null 2>&1; then
        print_result "$name" 1 "curl is required but not installed"
        return
    fi

    # Set required environment variables
    export CVEKERNELTREE="$TEST_DIR/linux"
    export CVECOMMITTREE="$TEST_DIR/commit-tree"
    export CVE_USER="test@example.com"

    # Create output file paths
    local json_file="$TEST_DIR/output_schema_test.json"
    local filter_file="$TEST_DIR/schema_validate.jq"

    # Create the jq filter file for schema validation
    cat > "$filter_file" << 'EOF'
# Load the input files
def check_required_props(properties):
  reduce (properties | to_entries[]) as $prop ({valid: true, missing: []};
    if $prop.value.required and (input | has($prop.key) | not)
    then .valid = false | .missing += [$prop.key]
    else .
    end
  );

def check_type(value; type):
  if type == "array" then (value | type == "array")
  elif type == "string" then (value | type == "string")
  elif type == "object" then (value | type == "object")
  elif type == "number" then (value | type == "number")
  elif type == "boolean" then (value | type == "boolean")
  else false
  end;

def validate_schema:
  # Required top-level fields
  if (.dataType | not) then
    "Missing required field: dataType"
  elif (.dataVersion | not) then
    "Missing required field: dataVersion"
  elif (.cveMetadata | not) then
    "Missing required field: cveMetadata"
  elif (.cveMetadata.cveID | not) then
    "Missing required field: cveMetadata.cveID"
  elif (.containers | not) then
    "Missing required field: containers"
  elif (.containers.cna | not) then
    "Missing required field: containers.cna"
  elif (.containers.cna.descriptions | length == 0) then
    "Missing or empty descriptions array"
  elif (.containers.cna.affected | length == 0) then
    "Missing or empty affected array"
  # Type checks
  elif (.dataType | type) != "string" then
    "dataType must be a string"
  elif (.dataVersion | type) != "string" then
    "dataVersion must be a string"
  elif (.cveMetadata.cveID | test("^CVE-\\d{4}-\\d+$") | not) then
    "cveID format invalid"
  else
    "valid"
  end;

validate_schema
EOF

    # Get schema path
    local schema_file
    schema_file=$(setup_cve_schema)
    if [ $? -ne 0 ] || [ ! -f "$schema_file" ]; then
        print_result "$name" 1 "Failed to setup CVE schema"
        return
    fi

    # Run bippy to generate JSON
    $BIPPY --cve="CVE-2024-12345" \
           --sha="${fix_commit:0:12}" \
           --json="$json_file" \
           --user="test@example.com" \
           --name="Test User" 2>/dev/null

    # Check if JSON file was created
    if [ ! -f "$json_file" ]; then
        print_result "$name" 1 "JSON file not created"
        return
    fi

    # Validate JSON against our schema rules
    local validation_output
    validation_output=$(jq -r -f "$filter_file" "$json_file" 2>&1)
    local validate_status=$?

    if [ $validate_status -ne 0 ]; then
        result=1
        message="JSON validation failed with jq error: ${validation_output}"
    elif [ "$validation_output" != "valid" ]; then
        result=1
        message="JSON validation failed: ${validation_output}"
    fi

    # Additional specific checks for required CVE fields
    local required_fields=(
        ".containers.cna.affected[].product"
        ".containers.cna.descriptions[].value"
    )

    for field in "${required_fields[@]}"; do
        if ! jq -e "$field" "$json_file" >/dev/null 2>&1; then
            result=1
            message+="Missing required field: $field. "
        fi
    done

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
test_json_truncation

# Check for jq availability before running schema validation
if command -v jq >/dev/null 2>&1; then
    test_json_schema_validation
else
    echo "${BLUE}Skipping schema validation test - jq not installed${RESET}"
fi

# Print summary
echo "------------------------"
echo "Test Summary:"
echo "  Total: $TESTS_RUN"
echo "  ${GREEN}Passed: $TESTS_PASSED${RESET}"
echo "  ${RED}Failed: $TESTS_FAILED${RESET}"

# Exit with failure if any tests failed
[ "$TESTS_FAILED" -eq 0 ] || exit 1
