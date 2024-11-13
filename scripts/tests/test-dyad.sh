#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2024
#
# Test script for dyad - verifies the functionality of dyad script
# by running multiple test cases with different scenarios

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

# Path to dyad script - adjust as needed
DYAD="../dyad"

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

# Helper function to create mock upstream kernel git repository
setup_mock_upstream_repo() {
    local repo_dir="$TEST_DIR/linux"
    mkdir -p "$repo_dir"
    cd "$repo_dir" || exit 1
    git init > /dev/null 2>&1

    # Create the initial version marker
    echo "Linux 6.1" > Makefile
    git add Makefile
    git commit -m "Linux 6.1" > /dev/null 2>&1
    git tag -a "v6.1" -m "Linux 6.1" > /dev/null 2>&1
    local v6_1_commit=$(git rev-parse HEAD)

    # Add a subsystem file with regular development
    mkdir -p drivers/subsystem
    echo "initial code" > drivers/subsystem/code.c
    git add drivers/subsystem/code.c
    git commit -m "subsystem: add initial implementation" > /dev/null 2>&1

    # Create a vulnerability
    echo "vulnerable code" >> drivers/subsystem/code.c
    git add drivers/subsystem/code.c
    git commit -m "subsystem: add new feature to code.c

This adds a new feature that will later be found to have security implications.
" > /dev/null 2>&1
    local vuln_commit=$(git rev-parse HEAD)

    # Some regular development commits
    mkdir -p drivers/other
    echo "unrelated change" > drivers/other/other.c
    git add drivers/other/other.c
    git commit -m "other: add new driver" > /dev/null 2>&1

    # Version 6.2-rc1
    echo "Linux 6.2-rc1" > Makefile
    git add Makefile
    git commit -m "Linux 6.2-rc1" > /dev/null 2>&1
    git tag -a "v6.2-rc1" -m "Linux 6.2-rc1" > /dev/null 2>&1

    # Version 6.2 release
    echo "Linux 6.2" > Makefile
    git add Makefile
    git commit -m "Linux 6.2" > /dev/null 2>&1
    git tag -a "v6.2" -m "Linux 6.2" > /dev/null 2>&1
    local v6_2_commit=$(git rev-parse HEAD)

    # More development
    mkdir -p drivers/feature
    echo "feature" > drivers/feature/new.c
    git add drivers/feature/new.c
    git commit -m "feature: add new capability" > /dev/null 2>&1

    # Fix for the vulnerability
    echo "fixed code" > drivers/subsystem/code.c
    git add drivers/subsystem/code.c
    git commit -m "subsystem: fix security vulnerability in code.c

A security issue was discovered in the feature added earlier.
This could lead to [description of the issue].

Fixes: ${vuln_commit:0:12} ('subsystem: add new feature to code.c')
Cc: stable@vger.kernel.org
" > /dev/null 2>&1
    local fix_commit=$(git rev-parse HEAD)

    # Version 6.3-rc1
    echo "Linux 6.3-rc1" > Makefile
    git add Makefile
    git commit -m "Linux 6.3-rc1" > /dev/null 2>&1
    git tag -a "v6.3-rc1" -m "Linux 6.3-rc1" > /dev/null 2>&1

    # Store commit IDs for later use
    echo "$v6_1_commit" > "$TEST_DIR/v6_1_commit"
    echo "$v6_2_commit" > "$TEST_DIR/v6_2_commit"
    echo "$vuln_commit" > "$TEST_DIR/vuln_commit"
    echo "$fix_commit" > "$TEST_DIR/fix_commit"

    cd - > /dev/null 2>&1
}

# Helper function to create mock stable kernel git repository
setup_mock_stable_repo() {
    local repo_dir="$TEST_DIR/stable-kernel"
    local fix_commit
    fix_commit=$(cat "$TEST_DIR/fix_commit")

    # Clone the upstream repo to create the stable repo
    git clone "$TEST_DIR/linux" "$repo_dir" > /dev/null 2>&1
    cd "$repo_dir" || exit 1

    # Create the 6.2.y branch at the 6.2 release point
    git checkout -b linux-6.2.y v6.2 > /dev/null 2>&1

    # Backport the fix commit
    # First, get the patch from upstream
    git format-patch -1 "$fix_commit" > /dev/null 2>&1

    # Create the backported fix with proper commit message
    echo "fixed code" > drivers/subsystem/code.c
    git add drivers/subsystem/code.c
    git commit -m "subsystem: fix security vulnerability in code.c

[Upstream commit ${fix_commit}]

A security issue was discovered in the feature added earlier.
This could lead to [description of the issue].

Fixes: ${vuln_commit:0:12} ('subsystem: add new feature to code.c')
Signed-off-by: Stable Developer <stable@example.com>
" > /dev/null 2>&1
    local stable_fix_commit=$(git rev-parse HEAD)

    # Create the stable release with the fix
    echo "Linux 6.2.1" > Makefile
    git add Makefile
    git commit -m "Linux 6.2.1" > /dev/null 2>&1
    git tag -a "v6.2.1" -m "Linux 6.2.1" > /dev/null 2>&1

    # Store the stable fix commit ID
    echo "$stable_fix_commit" > "$TEST_DIR/stable_fix_commit"

    cd - > /dev/null 2>&1
}

# Helper function to create mock kernel commits tree with id_found_in tool
setup_mock_commit_tree() {
    local commit_dir="$TEST_DIR/commit-tree"
    mkdir -p "$commit_dir"

    # Create mock id_found_in script that handles both upstream and stable trees
    cat > "$commit_dir/id_found_in" << 'EOF'
#!/bin/bash

# Mock id_found_in script that returns kernel versions for given commit IDs
# Handles both upstream and stable trees

COMMIT=$1
KERNEL_TREE=${CVEKERNELTREE}

if [ ! -d "$KERNEL_TREE" ]; then
    echo "ERROR: Kernel tree not found" >&2
    exit 1
fi

cd "$KERNEL_TREE" || exit 1

# Check if this is a stable tree commit first
if git show "$COMMIT" 2>/dev/null | grep -q "\[Upstream commit"; then
    # For stable commits, find the version in the stable tree
    VERSIONS=$(git tag --contains "$COMMIT" 2>/dev/null | grep -E "^v[0-9]+\.[0-9]+\.[0-9]+$" | sed 's/^v//')
else
    # For upstream commits, include all relevant versions
    VERSIONS=$(git tag --contains "$COMMIT" 2>/dev/null | grep -E "^v[0-9]+\.[0-9]+(\.[0-9]+)?(-rc[0-9]+)?$" | sed 's/^v//')
fi

if [ -z "$VERSIONS" ]; then
    exit 0
fi

# Sort versions and output
echo "$VERSIONS" | sort -V

EOF

    chmod +x "$commit_dir/id_found_in"

    # Create a mock git repo in the commit tree
    cd "$commit_dir" || exit 1
    git init > /dev/null 2>&1
    echo "Mock commit tree" > README
    git add README
    git commit -m "Initial commit" > /dev/null 2>&1
    cd - > /dev/null 2>&1
}

# Test Cases

test_basic_functionality() {
    local name="Basic functionality test"
    local result=0
    local output

    # Mock environment setup
    export CVEKERNELTREE="$TEST_DIR/stable-kernel"
    export CVECOMMITTREE="$TEST_DIR/commit-tree"

    setup_mock_upstream_repo
    setup_mock_stable_repo
    setup_mock_commit_tree

    output=$($DYAD --help 2>&1)
    if [[ ! "$output" =~ "Usage:" ]]; then
        print_result "$name" 1 "Help message not found in output"
        return
    fi

    print_result "$name" 0
}

test_fix_commit() {
    local name="Fix commit detection test"
    local stable_fix_commit
    stable_fix_commit=$(cat "$TEST_DIR/stable_fix_commit")
    local output

    output=$($DYAD "${stable_fix_commit:0:12}" 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process fix commit"
        return
    fi

    # Verify output contains expected version pairs
    if [[ ! "$output" =~ "6.2.1" ]]; then
        print_result "$name" 1 "Fix version not found in output"
        return
    fi

    print_result "$name" 0
}

test_vulnerable_commit() {
    local name="Vulnerable commit test"
    local vuln_commit
    local stable_fix_commit
    vuln_commit=$(cat "$TEST_DIR/vuln_commit")
    stable_fix_commit=$(cat "$TEST_DIR/stable_fix_commit")
    local output

    output=$($DYAD --vulnerable="${vuln_commit:0:12}" "${stable_fix_commit:0:12}" 2>&1)
    if [[ "$?" -ne 0 ]]; then
        print_result "$name" 1 "Failed to process vulnerable commit"
        return
    fi

    if [[ ! "$output" =~ "6.2" ]]; then
        print_result "$name" 1 "Vulnerable version not found in output"
        return
    fi

    print_result "$name" 0
}

test_invalid_git_sha() {
    local name="Invalid git SHA test"
    local result=0
    local output

    output=$($DYAD "invalid_sha" 2>&1)
    if [[ ! "$output" =~ "ERROR: git id" ]]; then
        print_result "$name" 1 "Expected error message for invalid git SHA not found"
        return
    fi

    print_result "$name" 0
}

test_version_parsing() {
    local name="Kernel version parsing test"
    local stable_fix_commit
    local vuln_commit
    stable_fix_commit=$(cat "$TEST_DIR/stable_fix_commit")
    vuln_commit=$(cat "$TEST_DIR/vuln_commit")
    local output
    local old_kernel_tree="$CVEKERNELTREE"

    # Test with stable commit
    output=$($DYAD --verbose "${stable_fix_commit:0:12}" 2>&1)
    if [[ ! "$output" =~ "6.2.1" ]]; then
        print_result "$name" 1 "Stable version not found in output"
        return
    fi

    # Test with upstream commit to verify rc handling
    export CVEKERNELTREE="$TEST_DIR/linux"
    output=$($DYAD --verbose "${vuln_commit:0:12}" 2>&1)
    if [[ ! "$output" =~ "6.2-rc1" ]]; then
        print_result "$name" 1 "RC version parsing failed"
        return
    fi

    export CVEKERNELTREE="$old_kernel_tree"
    print_result "$name" 0
}

test_debug_output() {
    local name="Debug output test"
    local stable_fix_commit
    stable_fix_commit=$(cat "$TEST_DIR/stable_fix_commit")
    local output

    output=$($DYAD --verbose "${stable_fix_commit:0:12}" 2>&1)
    if [[ ! "$output" =~ "#" ]]; then
        print_result "$name" 1 "Debug output not found with --verbose flag"
        return
    fi

    print_result "$name" 0
}

test_missing_environment() {
    local name="Missing environment variables test"
    local output

    # Temporarily unset required environment variables
    local old_kernel_tree="$CVEKERNELTREE"
    local old_commit_tree="$CVECOMMITTREE"
    unset CVEKERNELTREE
    unset CVECOMMITTREE

    output=$($DYAD "abcd1234" 2>&1)
    if [[ ! "$output" =~ "ERROR:" ]] || [[ ! "$output" =~ "needs setting" ]]; then
        print_result "$name" 1 "Expected error message for missing environment variables"
        export CVEKERNELTREE="$old_kernel_tree"
        export CVECOMMITTREE="$old_commit_tree"
        return
    fi

    export CVEKERNELTREE="$old_kernel_tree"
    export CVECOMMITTREE="$old_commit_tree"
    print_result "$name" 0
}

test_version_matching() {
    local name="Version matching test"
    local fix_commit
    local vuln_commit
    fix_commit=$(cat "$TEST_DIR/fix_commit")
    vuln_commit=$(cat "$TEST_DIR/vuln_commit")
    local output
    local result=0
    local message=""

    # Set required environment variables
    export CVEKERNELTREE="$TEST_DIR/linux"
    export CVECOMMITTREE="$TEST_DIR/commit-tree"

    # Test case 1: Basic version matching with fix commit only
    output=$($DYAD "${fix_commit:0:12}" 2>&1)
    if ! echo "$output" | grep -qE '[0-9]+\.[0-9]+[^:]*:[a-f0-9]+:[0-9]+\.[0-9]+[^:]*:[a-f0-9]+'; then
        result=1
        message+="No valid version:commit pairs found in fix commit output. "
    fi

    # Test case 2: Version matching with explicitly specified vulnerable commit
    output=$($DYAD --vulnerable="${vuln_commit:0:12}" "${fix_commit:0:12}" 2>&1)
    if ! echo "$output" | grep -qE '6\.2:[a-f0-9]+:6\.3-rc1:[a-f0-9]+'; then
        result=1
        message+="Expected mainline version pair not found. "
    fi

    # Test case 3: Check for all required versions in output
    output=$($DYAD "${fix_commit:0:12}" 2>&1)
    if ! echo "$output" | grep -q "6.2-rc1" && ! echo "$output" | grep -q "6.3-rc1"; then
        result=1
        message+="Expected mainline version numbers not found. "
    fi

    print_result "$name" "$result" "$message"
}

test_stable_branch_pairs() {
    local name="Stable branch commit pairs test"
    local result=0
    local message=""

    # Set up environment
    export CVEKERNELTREE="$TEST_DIR/stable-kernel"
    export CVECOMMITTREE="$TEST_DIR/commit-tree"

    # Create fresh stable tree
    rm -rf "$TEST_DIR/stable-kernel"
    mkdir -p "$TEST_DIR/stable-kernel"
    cd "$TEST_DIR/stable-kernel" || exit 1
    git init > /dev/null 2>&1

    # Create initial empty commit
    git commit --allow-empty -m "Initial commit" > /dev/null 2>&1

    # Create version 6.2
    echo "# version 6.2" > Makefile
    mkdir -p drivers/test
    echo "int test(void) { return 0; }" > drivers/test/test.c
    git add Makefile drivers/test/test.c
    git commit -m "Linux 6.2" > /dev/null 2>&1
    git tag -a v6.2 -m "Linux 6.2" > /dev/null 2>&1

    # Add vulnerable code
    cat > drivers/test/test.c << 'EOF'
int test(void) {
    /* BUG: No bounds checking */
    return -1;
}
EOF
    git add drivers/test/test.c
    git commit -m "test: add feature without bounds checking" > /dev/null 2>&1
    local vuln_commit=$(git rev-parse HEAD)

    # Add a fix
    cat > drivers/test/test.c << 'EOF'
int test(void) {
    /* Fixed: added bounds checking */
    return 0;
}
EOF
    git add drivers/test/test.c
    git commit -m "test: add missing bounds checking

Fixed security vulnerability in test function.

Fixes: ${vuln_commit:0:12} ('test: add feature without bounds checking')
Cc: stable@vger.kernel.org" > /dev/null 2>&1
    local fix_commit=$(git rev-parse HEAD)

    # Tag 6.3
    git tag -a v6.3 -m "Linux 6.3" > /dev/null 2>&1

    # Create id_found_in that deterministically maps commits to versions
    cat > "$TEST_DIR/commit-tree/id_found_in" << EOF
#!/bin/bash
COMMIT=\$1

case "\$COMMIT" in
    ${vuln_commit})
        echo "6.2"
        ;;
    ${fix_commit})
        echo "6.3"
        ;;
    *)
        exit 0
        ;;
esac
EOF
    chmod +x "$TEST_DIR/commit-tree/id_found_in"

    cd - > /dev/null 2>&1

    # Test case 1: Just the fix commit
    local output
    output=$($DYAD "${fix_commit:0:12}" 2>&1)

    local expected1="6.2:${vuln_commit}:6.3:${fix_commit}"
    if ! echo "$output" | grep -q "^${expected1}\$"; then
        result=1
        message+="Test 1: Expected output to match '${expected1}'. Got '${output}' instead. "
    fi

    # Test case 2: With explicit vulnerable commit
    output=$($DYAD --vulnerable="${vuln_commit:0:12}" "${fix_commit:0:12}" 2>&1)

    local expected2="6.3:${vuln_commit}:6.3:${fix_commit}"
    if ! echo "$output" | grep -q "^${expected2}\$"; then
        result=1
        message+="Test 2: Expected output to match '${expected2}'. Got '${output}' instead. "
    fi

    print_result "$name" "$result" "$message"
}

test_multiple_vulnerable_commits() {
    local name="Multiple vulnerable commits test"
    local result=0
    local message=""

    # Set up environment
    export CVEKERNELTREE="$TEST_DIR/linux"
    export CVECOMMITTREE="$TEST_DIR/commit-tree"

    # Create fresh repo
    rm -rf "$TEST_DIR/linux"
    mkdir -p "$TEST_DIR/linux"
    cd "$TEST_DIR/linux" || exit 1
    git init > /dev/null 2>&1

    # Create initial version
    echo "Linux 6.1" > Makefile
    git add Makefile
    git commit -m "Linux 6.1" > /dev/null 2>&1
    git tag -a v6.1 -m "Linux 6.1" > /dev/null 2>&1

    # Add first vulnerable commit
    mkdir -p drivers/test
    echo "vulnerable code 1" > drivers/test/vuln1.c
    git add drivers/test/vuln1.c
    git commit -m "test: add first vulnerable feature" > /dev/null 2>&1
    local vuln1_commit=$(git rev-parse HEAD)

    # Create branch for stable releases
    git checkout -b linux-6.1.y > /dev/null 2>&1

    # Add second vulnerable commit in 6.2
    git checkout master > /dev/null 2>&1
    echo "Linux 6.2" > Makefile
    echo "vulnerable code 2" > drivers/test/vuln2.c
    git add Makefile drivers/test/vuln2.c
    git commit -m "Linux 6.2 and second vulnerable feature" > /dev/null 2>&1
    git tag -a v6.2 -m "Linux 6.2" > /dev/null 2>&1
    local vuln2_commit=$(git rev-parse HEAD)

    # Add the fix
    echo "fixed code 1" > drivers/test/vuln1.c
    echo "fixed code 2" > drivers/test/vuln2.c
    git add drivers/test/vuln1.c drivers/test/vuln2.c
    git commit -m "test: fix multiple vulnerabilities

This fixes two separate vulnerabilities that were introduced earlier.

Fixes: ${vuln1_commit:0:12} ('test: add first vulnerable feature')
" > /dev/null 2>&1
    local fix_commit=$(git rev-parse HEAD)

    # Tag the fix version
    echo "Linux 6.3" > Makefile
    git add Makefile
    git commit -m "Linux 6.3" > /dev/null 2>&1
    git tag -a v6.3 -m "Linux 6.3" > /dev/null 2>&1

    # Create id_found_in that maps commits to versions
    cat > "$TEST_DIR/commit-tree/id_found_in" << EOF
#!/bin/bash
COMMIT=\$1

case "\$COMMIT" in
    ${vuln1_commit})
        echo "6.1"
        ;;
    ${fix_commit})
        echo "6.3"
        ;;
    *)
        exit 0
        ;;
esac
EOF
    chmod +x "$TEST_DIR/commit-tree/id_found_in"

    cd - > /dev/null 2>&1

    # Test case 1: Fix commit should identify the vulnerability from Fixes: line
    local output
    output=$($DYAD "${fix_commit:0:12}" 2>&1)

    # Should show vulnerable version being fixed
    if ! echo "$output" | grep -q "6.1.*:.*6.3"; then
        result=1
        message+="Vulnerable version pair not found in output. Output: $output "
    fi

    print_result "$name" "$result" "$message"
}

test_stable_backport_fix() {
    local name="Stable backport fix test"
    local result=0
    local message=""

    # Set up environment
    export CVEKERNELTREE="$TEST_DIR/linux"
    export CVECOMMITTREE="$TEST_DIR/commit-tree"

    # Create fresh repo
    rm -rf "$TEST_DIR/linux"
    mkdir -p "$TEST_DIR/linux"
    cd "$TEST_DIR/linux" || exit 1
    git init > /dev/null 2>&1

    # Create initial version
    echo "Linux 6.1" > Makefile
    git add Makefile
    git commit -m "Linux 6.1" > /dev/null 2>&1
    git tag -a v6.1 -m "Linux 6.1" > /dev/null 2>&1

    # Add vulnerable commit
    mkdir -p drivers/test
    echo "vulnerable code" > drivers/test/vuln.c
    git add drivers/test/vuln.c
    git commit -m "test: add vulnerable feature" > /dev/null 2>&1
    local vuln_commit=$(git rev-parse HEAD)

    # Create stable branch for 6.1.y
    git checkout -b linux-6.1.y > /dev/null 2>&1

    # Add the mainline fix first
    git checkout master > /dev/null 2>&1
    echo "Linux 6.2" > Makefile
    git add Makefile
    git commit -m "Linux 6.2" > /dev/null 2>&1
    git tag -a v6.2 -m "Linux 6.2" > /dev/null 2>&1

    echo "fixed code" > drivers/test/vuln.c
    git add drivers/test/vuln.c
    git commit -m "test: fix security vulnerability

Fix a security issue in the test driver.

Fixes: ${vuln_commit:0:12} ('test: add vulnerable feature')
Cc: stable@vger.kernel.org" > /dev/null 2>&1
    local mainline_fix=$(git rev-parse HEAD)

    # Tag the mainline fix version
    echo "Linux 6.3" > Makefile
    git add Makefile
    git commit -m "Linux 6.3" > /dev/null 2>&1
    git tag -a v6.3 -m "Linux 6.3" > /dev/null 2>&1

    # Create the stable backport
    git checkout linux-6.1.y > /dev/null 2>&1
    echo "fixed code" > drivers/test/vuln.c
    git add drivers/test/vuln.c
    git commit -m "test: fix security vulnerability

[Upstream commit ${mainline_fix:0:12}]

Fix a security issue in the test driver.

Fixes: ${vuln_commit:0:12} ('test: add vulnerable feature')" > /dev/null 2>&1
    local stable_fix=$(git rev-parse HEAD)

    # Tag the stable fix version
    echo "Linux 6.1.1" > Makefile
    git add Makefile
    git commit -m "Linux 6.1.1" > /dev/null 2>&1
    git tag -a v6.1.1 -m "Linux 6.1.1" > /dev/null 2>&1

    git checkout master > /dev/null 2>&1

    # Create id_found_in that maps commits to versions
    cat > "$TEST_DIR/commit-tree/id_found_in" << EOF
#!/bin/bash
COMMIT=\$1

case "\$COMMIT" in
    ${vuln_commit})
        echo "6.1"
        ;;
    ${mainline_fix})
        echo "6.3"
        ;;
    ${stable_fix})
        echo "6.1.1"
        ;;
    *)
        exit 0
        ;;
esac
EOF
    chmod +x "$TEST_DIR/commit-tree/id_found_in"

    cd - > /dev/null 2>&1

    # Test case 1: Mainline fix should identify full range
    local output
    output=$($DYAD "${mainline_fix:0:12}" 2>&1)

    # Should show vulnerable version being fixed in mainline
    if ! echo "$output" | grep -q "6.1.*:.*6.3"; then
        result=1
        message+="Mainline fix version pair not found in output. Output: $output "
    fi

    # Test case 2: Stable fix should identify stable range
    output=$($DYAD "${stable_fix:0:12}" 2>&1)

    # Should show vulnerable version being fixed in stable
    if ! echo "$output" | grep -q "6.1.*:.*6.1.1"; then
        result=1
        message+="Stable fix version pair not found in output. Output: $output "
    fi

    print_result "$name" "$result" "$message"
}

test_cherry_pick_no_fixes() {
    local name="Cherry-picked fix without Fixes tag test"
    local result=0
    local message=""

    # Set up environment
    export CVEKERNELTREE="$TEST_DIR/linux"
    export CVECOMMITTREE="$TEST_DIR/commit-tree"

    # Create fresh repo
    rm -rf "$TEST_DIR/linux"
    mkdir -p "$TEST_DIR/linux"
    cd "$TEST_DIR/linux" || exit 1
    git init > /dev/null 2>&1

    # Initial commit and tag for 6.1
    echo "Linux 6.1" > Makefile
    git add Makefile
    git commit -m "Linux 6.1" > /dev/null 2>&1
    git tag -a v6.1 -m "Linux 6.1" > /dev/null 2>&1

    # Add code with bug
    mkdir -p drivers/test
    echo "buggy code" > drivers/test/bug.c
    git add drivers/test/bug.c
    git commit -m "test: add new feature

This adds a new feature that will later be found to have issues." > /dev/null 2>&1
    local bug_commit=$(git rev-parse HEAD)
    git tag -a v6.1.1 -m "Linux 6.1.1" > /dev/null 2>&1

    # Add the fix much later
    echo "fixed code" > drivers/test/bug.c
    git add drivers/test/bug.c
    git commit -m "test: fix use-after-free in driver

The original implementation in commit ${bug_commit:0:12} failed to
properly handle resource cleanup, leading to a use-after-free condition.
This patch fixes the issue by ensuring proper cleanup order." > /dev/null 2>&1
    local fix_commit=$(git rev-parse HEAD)
    git tag -a v6.1.2 -m "Linux 6.1.2" > /dev/null 2>&1

    # Create id_found_in that only maps exact versions
    cat > "$TEST_DIR/commit-tree/id_found_in" << EOF
#!/bin/bash
COMMIT=\$1

case "\$COMMIT" in
    ${bug_commit})
        echo "6.1.1"
        ;;
    ${fix_commit})
        echo "6.1.2"
        ;;
    *)
        exit 0
        ;;
esac
EOF
    chmod +x "$TEST_DIR/commit-tree/id_found_in"

    cd - > /dev/null 2>&1

    # Test with explicit vulnerable commit
    local output
    output=$($DYAD --vulnerable="${bug_commit:0:12}" "${fix_commit:0:12}" 2>&1)

    # Should show version range from bug to fix, accommodate possible ^0 suffix
    if ! echo "$output" | grep -Eq "6\.1\.1(\^0)?:[a-f0-9]+:6\.1\.2:${fix_commit}"; then
        result=1
        message+="Fix with explicit vulnerable commit not found. Expected 6.1.1(^0)? to 6.1.2 range. Got: $output"
    fi

    print_result "$name" "$result" "$message"
}

test_missing_fixes() {
    local name="Missing fixes in version history test"
    local result=0
    local message=""

    # Set up environment
    export CVEKERNELTREE="$TEST_DIR/linux"
    export CVECOMMITTREE="$TEST_DIR/commit-tree"

    # Create fresh repo
    rm -rf "$TEST_DIR/linux"
    mkdir -p "$TEST_DIR/linux"
    cd "$TEST_DIR/linux" || exit 1
    git init > /dev/null 2>&1

    # Create initial version - 6.1
    echo "Linux 6.1" > Makefile
    git add Makefile
    git commit -m "Linux 6.1" > /dev/null 2>&1
    git tag -a v6.1 -m "Linux 6.1" > /dev/null 2>&1

    # Create branch for 6.1.y
    git checkout -b linux-6.1.y > /dev/null 2>&1

    # Back to master for 6.2
    git checkout master > /dev/null 2>&1
    echo "Linux 6.2" > Makefile
    git add Makefile
    git commit -m "Linux 6.2" > /dev/null 2>&1
    git tag -a v6.2 -m "Linux 6.2" > /dev/null 2>&1

    # Create branch for 6.2.y
    git checkout -b linux-6.2.y > /dev/null 2>&1

    # Back to master for vulnerable code
    git checkout master > /dev/null 2>&1

    # Add vulnerable code in 6.3
    mkdir -p drivers/test
    echo "vulnerable code" > drivers/test/vuln.c
    git add drivers/test/vuln.c
    git commit -m "test: add vulnerable feature" > /dev/null 2>&1
    local vuln_commit=$(git rev-parse HEAD)

    # Tag 6.3
    echo "Linux 6.3" > Makefile
    git add Makefile
    git commit -m "Linux 6.3" > /dev/null 2>&1
    git tag -a v6.3 -m "Linux 6.3" > /dev/null 2>&1

    # Create branch for 6.3.y
    git checkout -b linux-6.3.y > /dev/null 2>&1

    # Add fix only in 6.4
    git checkout master > /dev/null 2>&1
    echo "fixed code" > drivers/test/vuln.c
    git add drivers/test/vuln.c
    git commit -m "test: fix security vulnerability

This fixes a security issue introduced earlier.

Fixes: ${vuln_commit:0:12} ('test: add vulnerable feature')" > /dev/null 2>&1
    local fix_commit=$(git rev-parse HEAD)

    # Tag 6.4
    echo "Linux 6.4" > Makefile
    git add Makefile
    git commit -m "Linux 6.4" > /dev/null 2>&1
    git tag -a v6.4 -m "Linux 6.4" > /dev/null 2>&1

    # Create id_found_in that maps commits to versions
    cat > "$TEST_DIR/commit-tree/id_found_in" << EOF
#!/bin/bash
COMMIT=\$1

case "\$COMMIT" in
    ${vuln_commit})
        echo "6.3"
        ;;
    ${fix_commit})
        echo "6.4"
        ;;
    *)
        exit 0
        ;;
esac
EOF
    chmod +x "$TEST_DIR/commit-tree/id_found_in"

    cd - > /dev/null 2>&1

    # Test case 1: Fix commit should identify version range from vulnerable to fixed
    local output
    local output_no_debug
    output=$($DYAD "${fix_commit:0:12}" 2>&1)
    # Filter out debug lines (starting with #)
    output_no_debug=$(echo "$output" | grep -v "^#")

    # Should only show one line with the vulnerability range
    local expected_pattern="6\.3:${vuln_commit}:6\.4:${fix_commit}"
    if ! echo "$output_no_debug" | grep -q "${expected_pattern}"; then
        result=1
        message+="Expected version range pattern not found. Expected: ${expected_pattern}, Got: $output_no_debug "
    fi

    # Should not contain additional lines with unfixed versions
    local line_count
    line_count=$(echo "$output_no_debug" | wc -l)
    if [ "$line_count" -ne 1 ]; then
        result=1
        message+="Expected exactly one version range line, got ${line_count} lines. Output: $output_no_debug "
    fi

    # Test case 2: Earlier versions should not appear in the non-debug output
    if echo "$output_no_debug" | grep -q "6\.2"; then
        result=1
        message+="Found unexpected version 6.2 in output which should not be included. Output: $output_no_debug "
    fi

    print_result "$name" "$result" "$message"
}

test_multiple_branch_fixes() {
    local name="Multiple branch fix handling test"
    local result=0
    local message=""

    # Set up environment
    export CVEKERNELTREE="$TEST_DIR/linux"
    export CVECOMMITTREE="$TEST_DIR/commit-tree"

    # Create fresh repo
    rm -rf "$TEST_DIR/linux"
    mkdir -p "$TEST_DIR/linux"
    cd "$TEST_DIR/linux" || exit 1
    git init > /dev/null 2>&1

    # Create initial version - 5.15
    echo "Linux 5.15" > Makefile
    git add Makefile
    git commit -m "Linux 5.15" > /dev/null 2>&1
    git tag -a v5.15 -m "Linux 5.15" > /dev/null 2>&1

    # Create 5.15.y branch and add vulnerable code there
    git checkout -b linux-5.15.y > /dev/null 2>&1
    mkdir -p drivers/test
    echo "vulnerable code" > drivers/test/vuln.c
    git add drivers/test/vuln.c
    git commit -m "test: add feature to stable branch" > /dev/null 2>&1
    local stable_vuln_commit=$(git rev-parse HEAD)
    git tag -a v5.15.1 -m "Linux 5.15.1" > /dev/null 2>&1

    # Back to master for 6.0
    git checkout master > /dev/null 2>&1
    echo "Linux 6.0" > Makefile
    mkdir -p drivers/test
    echo "vulnerable code" > drivers/test/vuln.c
    git add Makefile drivers/test/vuln.c
    git commit -m "test: add feature to mainline

This adds a new feature that will later be found to have security implications." > /dev/null 2>&1
    local mainline_vuln_commit=$(git rev-parse HEAD)
    git tag -a v6.0 -m "Linux 6.0" > /dev/null 2>&1

    # Fix in mainline first - 6.1
    echo "fixed code" > drivers/test/vuln.c
    git add drivers/test/vuln.c
    git commit -m "test: fix security vulnerability in feature

A security issue was discovered in the feature added earlier.

Fixes: ${mainline_vuln_commit:0:12} ('test: add feature to mainline')" > /dev/null 2>&1
    local mainline_fix_commit=$(git rev-parse HEAD)

    echo "Linux 6.1" > Makefile
    git add Makefile
    git commit -m "Linux 6.1" > /dev/null 2>&1
    git tag -a v6.1 -m "Linux 6.1" > /dev/null 2>&1

    # Backport fix to 5.15.y
    git checkout linux-5.15.y > /dev/null 2>&1
    echo "fixed code" > drivers/test/vuln.c
    git add drivers/test/vuln.c
    git commit -m "test: fix security vulnerability in feature

[Upstream commit ${mainline_fix_commit:0:12}]

Backported from mainline to fix security issue discovered in earlier feature.

Fixes: ${stable_vuln_commit:0:12} ('test: add feature to stable branch')" > /dev/null 2>&1
    local stable_fix_commit=$(git rev-parse HEAD)

    echo "Linux 5.15.2" > Makefile
    git add Makefile
    git commit -m "Linux 5.15.2" > /dev/null 2>&1
    git tag -a v5.15.2 -m "Linux 5.15.2" > /dev/null 2>&1

    # Create id_found_in that maps commits to versions
    cat > "$TEST_DIR/commit-tree/id_found_in" << EOF
#!/bin/bash
COMMIT=\$1

case "\$COMMIT" in
    ${mainline_vuln_commit})
        echo "6.0"
        ;;
    ${mainline_fix_commit})
        echo "6.1"
        ;;
    ${stable_vuln_commit})
        echo "5.15.1"
        ;;
    ${stable_fix_commit})
        echo "5.15.2"
        ;;
    *)
        exit 0
        ;;
esac
EOF
    chmod +x "$TEST_DIR/commit-tree/id_found_in"

    cd - > /dev/null 2>&1

    # Test case 1: Mainline fix should show mainline version range
    local output
    local output_no_debug

    output=$($DYAD "${mainline_fix_commit:0:12}" 2>&1)
    output_no_debug=$(echo "$output" | grep -v "^#")

    local expected_mainline="6.0:${mainline_vuln_commit}:6.1:${mainline_fix_commit}"
    if ! echo "$output_no_debug" | grep -q "${expected_mainline}"; then
        result=1
        message+="Mainline version range not found. Expected: ${expected_mainline}, Got: $output_no_debug "
    fi

    # Test case 2: Stable fix should show stable version range
    output=$($DYAD "${stable_fix_commit:0:12}" 2>&1)
    output_no_debug=$(echo "$output" | grep -v "^#")

    local expected_stable="5.15.1:${stable_vuln_commit}:5.15.2:${stable_fix_commit}"
    if ! echo "$output_no_debug" | grep -q "${expected_stable}"; then
        result=1
        message+="Stable version range not found. Expected: ${expected_stable}, Got: $output_no_debug "
    fi

    # Test case 3: Each output should only show one version range
    if [ "$(echo "$output_no_debug" | wc -l)" -ne 1 ]; then
        result=1
        message+="Expected exactly one version range line for stable fix, got multiple lines. Output: $output_no_debug "
    fi

    print_result "$name" "$result" "$message"
}

test_rc_version_handling() {
    local name="RC version handling test"
    local result=0
    local message=""

    # Set up environment
    export CVEKERNELTREE="$TEST_DIR/linux"
    export CVECOMMITTREE="$TEST_DIR/commit-tree"

    # Create fresh repo
    rm -rf "$TEST_DIR/linux"
    mkdir -p "$TEST_DIR/linux"
    cd "$TEST_DIR/linux" || exit 1
    git init > /dev/null 2>&1

    # Create initial version - 6.4
    echo "Linux 6.4" > Makefile
    git add Makefile
    git commit -m "Linux 6.4" > /dev/null 2>&1
    git tag -a v6.4 -m "Linux 6.4" > /dev/null 2>&1

    # Add vulnerable code in first RC of 6.5
    echo "Linux 6.5-rc1" > Makefile
    mkdir -p drivers/test
    echo "vulnerable code" > drivers/test/vuln.c
    git add Makefile drivers/test/vuln.c
    git commit -m "test: add feature with vulnerability" > /dev/null 2>&1
    local vuln_commit=$(git rev-parse HEAD)
    git tag -a v6.5-rc1 -m "Linux 6.5-rc1" > /dev/null 2>&1

    # Some development between RC1 and RC2
    echo "more changes" >> drivers/test/vuln.c
    git add drivers/test/vuln.c
    git commit -m "test: add more features" > /dev/null 2>&1

    # Tag RC2
    echo "Linux 6.5-rc2" > Makefile
    git add Makefile
    git commit -m "Linux 6.5-rc2" > /dev/null 2>&1
    git tag -a v6.5-rc2 -m "Linux 6.5-rc2" > /dev/null 2>&1

    # Fix the vulnerability in RC3
    echo "fixed code" > drivers/test/vuln.c
    git add drivers/test/vuln.c
    git commit -m "test: fix security vulnerability

A security issue was discovered in the feature added in RC1.

Fixes: ${vuln_commit:0:12} ('test: add feature with vulnerability')" > /dev/null 2>&1
    local fix_commit=$(git rev-parse HEAD)

    # Tag RC3
    echo "Linux 6.5-rc3" > Makefile
    git add Makefile
    git commit -m "Linux 6.5-rc3" > /dev/null 2>&1
    git tag -a v6.5-rc3 -m "Linux 6.5-rc3" > /dev/null 2>&1

    # Final 6.5 release
    echo "Linux 6.5" > Makefile
    git add Makefile
    git commit -m "Linux 6.5" > /dev/null 2>&1
    git tag -a v6.5 -m "Linux 6.5" > /dev/null 2>&1

    # Create id_found_in that maps commits to versions
    cat > "$TEST_DIR/commit-tree/id_found_in" << EOF
#!/bin/bash
COMMIT=\$1

case "\$COMMIT" in
    ${vuln_commit})
        echo "6.5"
        echo "6.5-rc1"
        ;;
    ${fix_commit})
        echo "6.5"
        echo "6.5-rc3"
        ;;
    *)
        exit 0
        ;;
esac
EOF
    chmod +x "$TEST_DIR/commit-tree/id_found_in"

    cd - > /dev/null 2>&1

    # Test case 1: Basic version handling with explicit vulnerable commit
    local output
    local output_no_debug

    output=$($DYAD --vulnerable="${vuln_commit:0:12}" "${fix_commit:0:12}" 2>&1)
    output_no_debug=$(echo "$output" | grep -v "^#")

    # Should show two ranges: one for rc versions and one for final release
    local expected_rc="6.5:${vuln_commit}:6.5-rc3:${fix_commit}"
    local expected_final="6.5:${vuln_commit}:6.5:${fix_commit}"

    if ! echo "$output_no_debug" | grep -q "${expected_rc}"; then
        result=1
        message+="Expected RC version range not found. Expected to find: ${expected_rc}, Got: $output_no_debug "
    fi

    if ! echo "$output_no_debug" | grep -q "${expected_final}"; then
        result=1
        message+="Expected final version range not found. Expected to find: ${expected_final}, Got: $output_no_debug "
    fi

    # Test case 2: Should show exactly two lines (RC and final version ranges)
    local line_count
    line_count=$(echo "$output_no_debug" | wc -l)
    if [ "$line_count" -ne 2 ]; then
        result=1
        message+="Expected exactly two version range lines (RC and final), got ${line_count} lines. Output: $output_no_debug "
    fi

    # Test case 3: Previous version should not be marked as vulnerable
    if echo "$output_no_debug" | grep -q "6\.4"; then
        result=1
        message+="Found unexpected version 6.4 in output which should not be included. Output: $output_no_debug "
    fi

    print_result "$name" "$result" "$message"
}

test_multiple_fixes_tags() {
    local name="Multiple Fixes tags handling test"
    local result=0
    local message=""

    # Set up environment
    export CVEKERNELTREE="$TEST_DIR/linux"
    export CVECOMMITTREE="$TEST_DIR/commit-tree"

    # Create fresh repo
    rm -rf "$TEST_DIR/linux"
    mkdir -p "$TEST_DIR/linux"
    cd "$TEST_DIR/linux" || exit 1
    git init > /dev/null 2>&1

    # Create initial version - 5.15
    echo "Linux 5.15" > Makefile
    git add Makefile
    git commit -m "Linux 5.15" > /dev/null 2>&1
    git tag -a v5.15 -m "Linux 5.15" > /dev/null 2>&1

    # Add first vulnerable code
    mkdir -p drivers/test
    echo "vulnerable code 1" > drivers/test/vuln1.c
    git add drivers/test/vuln1.c
    git commit -m "test: add first vulnerable feature" > /dev/null 2>&1
    local vuln1_commit=$(git rev-parse HEAD)

    # Tag 5.16
    echo "Linux 5.16" > Makefile
    git add Makefile
    git commit -m "Linux 5.16" > /dev/null 2>&1
    git tag -a v5.16 -m "Linux 5.16" > /dev/null 2>&1

    # Add second vulnerable code
    echo "vulnerable code 2" > drivers/test/vuln2.c
    git add drivers/test/vuln2.c
    git commit -m "test: add second vulnerable feature" > /dev/null 2>&1
    local vuln2_commit=$(git rev-parse HEAD)

    # Tag 5.17
    echo "Linux 5.17" > Makefile
    git add Makefile
    git commit -m "Linux 5.17" > /dev/null 2>&1
    git tag -a v5.17 -m "Linux 5.17" > /dev/null 2>&1

    # Fix both vulnerabilities with one commit
    echo "fixed code 1" > drivers/test/vuln1.c
    echo "fixed code 2" > drivers/test/vuln2.c
    git add drivers/test/vuln1.c drivers/test/vuln2.c
    git commit -m "test: fix multiple security vulnerabilities

This fixes two separate security issues:
1. A vulnerability in the first feature
2. A vulnerability in the second feature

Fixes: ${vuln1_commit:0:12} ('test: add first vulnerable feature')
Fixes: ${vuln2_commit:0:12} ('test: add second vulnerable feature')" > /dev/null 2>&1
    local fix_commit=$(git rev-parse HEAD)

    # Tag 5.18
    echo "Linux 5.18" > Makefile
    git add Makefile
    git commit -m "Linux 5.18" > /dev/null 2>&1
    git tag -a v5.18 -m "Linux 5.18" > /dev/null 2>&1

    # Create id_found_in that maps commits to versions
    cat > "$TEST_DIR/commit-tree/id_found_in" << EOF
#!/bin/bash
COMMIT=\$1

case "\$COMMIT" in
    ${vuln1_commit})
        echo "5.16"
        ;;
    ${vuln2_commit})
        echo "5.17"
        ;;
    ${fix_commit})
        echo "5.18"
        ;;
    *)
        exit 0
        ;;
esac
EOF
    chmod +x "$TEST_DIR/commit-tree/id_found_in"

    cd - > /dev/null 2>&1

    # Test case 1: Fix commit should identify both vulnerabilities
    local output
    local output_no_debug
    
    output=$($DYAD "${fix_commit:0:12}" 2>&1)
    output_no_debug=$(echo "$output" | grep -v "^#")
    
    # Should show range from first vulnerability to fix
    local expected_first="5.16:${vuln1_commit}:5.18:${fix_commit}"
    if ! echo "$output_no_debug" | grep -q "${expected_first}"; then
        result=1
        message+="First vulnerability range not found. Expected: ${expected_first}, Got: $output_no_debug "
    fi

    # Test case 2: Using --vulnerable with first commit
    output=$($DYAD --vulnerable="${vuln1_commit:0:12}" "${fix_commit:0:12}" 2>&1)
    output_no_debug=$(echo "$output" | grep -v "^#")
    
    # Should show exactly the specified range
    if ! echo "$output_no_debug" | grep -q "^${expected_first}\$"; then
        result=1
        message+="Explicit first vulnerable commit range not found. Expected: ${expected_first}, Got: $output_no_debug "
    fi

    # Test case 3: Using --vulnerable with second commit
    output=$($DYAD --vulnerable="${vuln2_commit:0:12}" "${fix_commit:0:12}" 2>&1)
    output_no_debug=$(echo "$output" | grep -v "^#")
    
    # Should show range from second vulnerability to fix
    local expected_second="5.17:${vuln2_commit}:5.18:${fix_commit}"
    if ! echo "$output_no_debug" | grep -q "^${expected_second}\$"; then
        result=1
        message+="Explicit second vulnerable commit range not found. Expected: ${expected_second}, Got: $output_no_debug "
    fi

    print_result "$name" "$result" "$message"
}

test_legacy_kernel_handling() {
    local name="Legacy 2.6.x kernel handling test"
    local result=0
    local message=""

    # Set up environment
    export CVEKERNELTREE="$TEST_DIR/linux"
    export CVECOMMITTREE="$TEST_DIR/commit-tree"

    # Create fresh repo
    rm -rf "$TEST_DIR/linux"
    mkdir -p "$TEST_DIR/linux"
    cd "$TEST_DIR/linux" || exit 1
    git init > /dev/null 2>&1

    # Create initial 2.6.32 version
    echo "Linux 2.6.32" > Makefile
    mkdir -p drivers/test
    git add Makefile
    git commit -m "Linux 2.6.32" > /dev/null 2>&1
    git tag -a v2.6.32 -m "Linux 2.6.32" > /dev/null 2>&1

    # Add a base feature
    echo "base feature" > drivers/test/base.c
    git add drivers/test/base.c
    git commit -m "test: add base feature to 2.6.32" > /dev/null 2>&1
    local base_commit=$(git rev-parse HEAD)

    # Create 2.6.32.y branch
    git checkout -b linux-2.6.32.y > /dev/null 2>&1

    # Add vulnerable code in 2.6.32.1
    echo "vulnerable code" > drivers/test/vuln.c
    git add drivers/test/vuln.c
    git commit -m "test: add feature to 2.6.32.1" > /dev/null 2>&1
    local legacy_vuln_commit=$(git rev-parse HEAD)
    git tag -a v2.6.32.1 -m "Linux 2.6.32.1" > /dev/null 2>&1

    # Fix in 2.6.32.2
    echo "fixed code" > drivers/test/vuln.c
    git add drivers/test/vuln.c
    git commit -m "test: fix security vulnerability in 2.6.32.2

Found a security issue in earlier code.

Fixes: ${legacy_vuln_commit:0:12} ('test: add feature to 2.6.32.1')" > /dev/null 2>&1
    local legacy_fix_commit=$(git rev-parse HEAD)
    git tag -a v2.6.32.2 -m "Linux 2.6.32.2" > /dev/null 2>&1

    # Add another vulnerable feature
    echo "second vulnerable code" > drivers/test/vuln2.c
    git add drivers/test/vuln2.c
    git commit -m "test: add second feature to 2.6.32.2" > /dev/null 2>&1
    local legacy_vuln2_commit=$(git rev-parse HEAD)

    # Fix second vulnerability in 2.6.32.3
    echo "second fixed code" > drivers/test/vuln2.c
    git add drivers/test/vuln2.c
    git commit -m "test: fix second security vulnerability

Another security issue was found.

Fixes: ${legacy_vuln2_commit:0:12} ('test: add second feature to 2.6.32.2')" > /dev/null 2>&1
    local legacy_fix2_commit=$(git rev-parse HEAD)
    git tag -a v2.6.32.3 -m "Linux 2.6.32.3" > /dev/null 2>&1

    # Back to master for 2.6.33
    git checkout master > /dev/null 2>&1
    echo "Linux 2.6.33" > Makefile
    git add Makefile
    git commit -m "Linux 2.6.33" > /dev/null 2>&1
    git tag -a v2.6.33 -m "Linux 2.6.33" > /dev/null 2>&1

    # Add mainline vulnerability
    echo "mainline vulnerable code" > drivers/test/mainline_vuln.c
    git add drivers/test/mainline_vuln.c
    git commit -m "test: add vulnerable feature to mainline" > /dev/null 2>&1
    local mainline_vuln_commit=$(git rev-parse HEAD)

    # Fix mainline vulnerability in 2.6.34
    echo "mainline fixed code" > drivers/test/mainline_vuln.c
    git add drivers/test/mainline_vuln.c
    git commit -m "test: fix mainline security vulnerability

Fix security issue in mainline.

Fixes: ${mainline_vuln_commit:0:12} ('test: add vulnerable feature to mainline')" > /dev/null 2>&1
    local mainline_fix_commit=$(git rev-parse HEAD)
    git tag -a v2.6.34 -m "Linux 2.6.34" > /dev/null 2>&1

    # Add complex fix in stable branch
    git checkout linux-2.6.32.y > /dev/null 2>&1
    echo "complex fix" > drivers/test/complex.c
    git add drivers/test/complex.c
    git commit -m "test: fix spanning multiple versions

Fixes multiple issues:
Fixes: ${legacy_vuln_commit:0:12} ('test: add feature to 2.6.32.1')" > /dev/null 2>&1
    local complex_fix_commit=$(git rev-parse HEAD)
    git tag -a v2.6.32.4 -m "Linux 2.6.32.4" > /dev/null 2>&1

    # Create id_found_in that maps commits to versions
    cat > "$TEST_DIR/commit-tree/id_found_in" << EOF
#!/bin/bash
COMMIT=\$1

case "\$COMMIT" in
    ${base_commit})
        echo "2.6.32"
        ;;
    ${legacy_vuln_commit})
        echo "2.6.32.1"
        ;;
    ${legacy_fix_commit})
        echo "2.6.32.2"
        ;;
    ${legacy_vuln2_commit})
        echo "2.6.32.2"
        ;;
    ${legacy_fix2_commit})
        echo "2.6.32.3"
        ;;
    ${mainline_vuln_commit})
        echo "2.6.33"
        ;;
    ${mainline_fix_commit})
        echo "2.6.34"
        ;;
    ${complex_fix_commit})
        echo "2.6.32.4"
        ;;
    *)
        exit 0
        ;;
esac
EOF
    chmod +x "$TEST_DIR/commit-tree/id_found_in"

    cd - > /dev/null 2>&1

    # Test cases
    # Test case 1: Basic version handling with 2.6.x stable kernel
    local output
    local output_no_debug

    output=$($DYAD "${legacy_fix_commit:0:12}" 2>&1)
    output_no_debug=$(echo "$output" | grep -v "^#")

    # Should show the correct range for 2.6.x versions, accommodating ^0 suffix
    if ! echo "$output_no_debug" | grep -Eq "2\.6\.32\.1(\^0)?:${legacy_vuln_commit}:2\.6\.32\.2:${legacy_fix_commit}"; then
        result=1
        message+="Expected 2.6.x version range not found in output: $output_no_debug "
    fi

    # Test case 2: Multiple fixes in 2.6.x stable series
    output=$($DYAD "${legacy_fix2_commit:0:12}" 2>&1)
    output_no_debug=$(echo "$output" | grep -v "^#")

    if ! echo "$output_no_debug" | grep -Eq "2\.6\.32\.2(\^0)?:${legacy_vuln2_commit}:2\.6\.32\.3:${legacy_fix2_commit}"; then
        result=1
        message+="Second fix in 2.6.x stable series not handled correctly. Output: $output_no_debug "
    fi

    # Test case 3: Simple mainline 2.6.x handling
    output=$($DYAD "${mainline_fix_commit:0:12}" 2>&1)
    output_no_debug=$(echo "$output" | grep -v "^#")

    if ! echo "$output_no_debug" | grep -q "2.6.33:${mainline_vuln_commit}:2.6.34:${mainline_fix_commit}"; then
        result=1
        message+="Mainline 2.6.x version handling incorrect. Output: $output_no_debug "
    fi

    # Test case 4: Complex fix
    output=$($DYAD "${complex_fix_commit:0:12}" 2>&1)
    output_no_debug=$(echo "$output" | grep -v "^#")

    # Should match the single fix
    if ! echo "$output_no_debug" | grep -Eq "2\.6\.32\.1(\^0)?:${legacy_vuln_commit}:2\.6\.32\.4:${complex_fix_commit}"; then
        result=1
        message+="Complex fix handling incorrect. Expected fix from 2.6.32.1 to 2.6.32.4. Output: $output_no_debug "
    fi

    # Test case 5: Check explicit vulnerable commit handling
    output=$($DYAD --vulnerable="${legacy_vuln_commit:0:12}" "${complex_fix_commit:0:12}" 2>&1)
    output_no_debug=$(echo "$output" | grep -v "^#")

    if ! echo "$output_no_debug" | grep -Eq "2\.6\.32\.1(\^0)?:${legacy_vuln_commit}:2\.6\.32\.4:${complex_fix_commit}"; then
        result=1
        message+="Explicit vulnerable commit handling incorrect. Expected 2.6.32.1 to 2.6.32.4 range. Output: $output_no_debug "
    fi

    print_result "$name" "$result" "$message"
}

# Run all tests
echo "${BLUE}Running dyad tests...${RESET}"
echo "------------------------"

test_basic_functionality
test_fix_commit
test_vulnerable_commit
test_invalid_git_sha
test_version_parsing
test_debug_output
test_missing_environment
test_version_matching
test_stable_branch_pairs
test_multiple_vulnerable_commits
test_stable_backport_fix
test_cherry_pick_no_fixes
test_missing_fixes
test_multiple_branch_fixes
test_rc_version_handling
test_multiple_fixes_tags
test_legacy_kernel_handling

# Print summary
echo "------------------------"
echo "Test Summary:"
echo "  Total: $TESTS_RUN"
echo "  ${GREEN}Passed: $TESTS_PASSED${RESET}"
echo "  ${RED}Failed: $TESTS_FAILED${RESET}"

# Exit with failure if any tests failed
[ "$TESTS_FAILED" -eq 0 ] || exit 1
