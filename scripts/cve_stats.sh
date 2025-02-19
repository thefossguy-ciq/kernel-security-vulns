#!/bin/bash

# Function to count unique CVEs in a date range
count_cves_in_range() {
    local start_date="$1"
    local end_date="$2"
    
    # Get unique CVE IDs from filenames, ignoring extensions and duplicates
    git log --diff-filter=A --pretty=format: --name-only --after="$start_date" --before="$end_date" cve/published/ |
        grep -o 'CVE-[0-9]\{4\}-[0-9]\{4,\}' |
        sort -u |
        wc -l
}

# Function to get commit author from sha1 file
get_commit_author() {
    local sha1_file="$1"
    local sha1=$(cat "$sha1_file")
    if [ -n "$sha1" ]; then
        # Get author name from Linux repo
        cd ~/linux && git log -1 --format="%aN" "$sha1" 2>/dev/null || echo "unknown"
    fi
}
export -f get_commit_author

# Function to get subsystem from commit
get_commit_subsystem() {
    local sha1_file="$1"
    local sha1=$(cat "$sha1_file")
    if [ -n "$sha1" ]; then
        # Get the first changed file from the commit to determine subsystem and sub-subsystem
        local path=$(cd ~/linux && git show --pretty=format: --name-only "$sha1" 2>/dev/null | head -n1)
        if [ -n "$path" ]; then
            local main_subsystem=$(echo "$path" | cut -d'/' -f1)
            local sub_subsystem=$(echo "$path" | cut -d'/' -f1,2)
            echo "$main_subsystem|$sub_subsystem"
        fi
    fi
}
export -f get_commit_subsystem

# Function to process a single CVE for subsystem stats
process_cve_subsystem() {
    local sha1_file="$1"
    local tmp_dir="$2"
    local sub_tmp_dir="$3"
    
    local cve=$(basename "$sha1_file" .sha1)
    local subsystem_info=$(get_commit_subsystem "$sha1_file")
    if [ -n "$subsystem_info" ]; then
        local main_subsystem=$(echo "$subsystem_info" | cut -d'|' -f1)
        local sub_subsystem=$(echo "$subsystem_info" | cut -d'|' -f2)
        
        # Use underscore instead of slash for filenames
        local main_file="$tmp_dir/${main_subsystem}"
        local sub_file="$sub_tmp_dir/${sub_subsystem//\//_}"
        
        # Use flock to safely append to files from multiple processes
        (
            flock -x 200
            echo "$cve" >> "$main_file"
        ) 200>"$main_file.lock"
        
        if [ "$main_subsystem" != "$sub_subsystem" ]; then
            (
                flock -x 200
                echo "$cve" >> "$sub_file"
            ) 200>"$sub_file.lock"
        fi
    fi
}
export -f process_cve_subsystem

# Function to show subsystem statistics
show_subsystem_stats() {
    local num_subsystems="$1"
    local num_sub_subsystems="$2"
    local show_authors="$3"
    
    print_header "Top $num_subsystems Subsystems with CVEs (showing top $num_sub_subsystems sub-subsystems each)"

    # Create temporary directories for subsystem processing
    local tmp_dir=$(mktemp -d)
    local sub_tmp_dir=$(mktemp -d)
    mkdir -p "$tmp_dir/locks"
    mkdir -p "$sub_tmp_dir/locks"
    trap 'rm -rf "$tmp_dir" "$sub_tmp_dir"' EXIT

    # Process all sha1 files in parallel - now recursively searching through subdirectories
    find cve/published -type f -name "*.sha1" -exec readlink -f {} \; | \
        parallel -j$(nproc) process_cve_subsystem {} "$tmp_dir" "$sub_tmp_dir"

    # Clean up lock files
    rm -f "$tmp_dir"/*.lock "$sub_tmp_dir"/*.lock

    # Count and sort subsystems by CVE count
    for subsys in "$tmp_dir"/*; do
        if [ -f "$subsys" ]; then
            local name=$(basename "$subsys")
            local count=$(wc -l < "$subsys")
            echo "$count $name"
        fi
    done | sort -rn | head -n "$num_subsystems" | while read count subsystem; do
        echo "$subsystem: $count CVEs"
        
        # Find files that start with the subsystem name followed by underscore
        find "$sub_tmp_dir" -type f -name "${subsystem}_*" 2>/dev/null | while read sub_file; do
            local sub_name=$(basename "$sub_file" | tr '_' '/')
            local sub_count=$(wc -l < "$sub_file")
            echo "$sub_count $sub_name"
        done | sort -rn | head -n "$num_sub_subsystems" | while read sub_count sub_name; do
            echo "    $sub_name: $sub_count CVEs"
        done
        
        # If authors flag is set, show top authors for this subsystem
        if [ "$show_authors" = true ]; then
            echo "  Top authors for $subsystem:"
            # Create a temporary file to store CVE IDs for this subsystem
            local cve_list_file=$(mktemp)
            cat "$tmp_dir/$subsystem" > "$cve_list_file"
            
            # Process each CVE and get its author
            local authors_file=$(mktemp)
            while read cve; do
                # Find the .sha1 file for this CVE
                local sha1_file=$(find cve/published -type f -name "${cve}.sha1" 2>/dev/null)
                if [ -n "$sha1_file" ]; then
                    local author=$(get_commit_author "$sha1_file")
                    if [ -n "$author" ] && [ "$author" != "unknown" ]; then
                        echo "$author" >> "$authors_file"
                    fi
                fi
            done < "$cve_list_file"
            
            # Sort and count authors
            if [ -s "$authors_file" ]; then
                sort "$authors_file" | uniq -c | sort -rn | head -n 5 | \
                while read author_count author; do
                    echo "    $author: $author_count CVEs"
                done
            else
                echo "    No author information available"
            fi
            
            # Clean up temporary files
            rm -f "$cve_list_file" "$authors_file"
            echo ""
        fi
        echo ""
    done
}

# Function to print a section header
print_header() {
    echo -e "\n=== $1 ==="
}

# Parse command line arguments
show_authors=false
show_subsystems=false
num_authors=10
num_subsystems=10
num_sub_subsystems=3  # Default number of sub-subsystems to show
for arg in "$@"; do
    if [[ $arg =~ ^--authors(=([0-9]+))?$ ]]; then
        show_authors=true
        if [[ -n "${BASH_REMATCH[2]}" ]]; then
            num_authors="${BASH_REMATCH[2]}"
        fi
    elif [[ $arg =~ ^--subsystem(=([0-9]+)(,[0-9]+)?)?$ ]]; then
        show_subsystems=true
        if [[ -n "${BASH_REMATCH[2]}" ]]; then
            if [[ "${BASH_REMATCH[2]}" =~ ^([0-9]+),([0-9]+)$ ]]; then
                num_subsystems="${BASH_REMATCH[1]}"
                num_sub_subsystems="${BASH_REMATCH[2]}"
            else
                num_subsystems="${BASH_REMATCH[2]}"
            fi
        fi
    fi
done

# Get first CVE date for statistics
first_cve_date=$(git log --diff-filter=A --reverse --pretty=format:%ad --date=short cve/published/ | head -n 1)
if [ -z "$first_cve_date" ]; then
    first_cve_date="2019-01-01" # Fallback if no git history
fi

# Show summary statistics if --summary flag is provided
if [[ " $* " =~ " --summary " ]]; then
    # Get current date components
    current_year=$(date +%Y)
    current_month=$(date +%m)

    # Calculate statistics per year
    print_header "CVEs Published Per Year"
    end_year=$(date +%Y)
    for year in $(seq 2019 $end_year); do
        count=$(count_cves_in_range "$year-01-01" "$((year+1))-01-01")
        echo "$year: $count CVEs"
    done

    # Calculate statistics for last 6 months
    print_header "CVEs Published in Last 6 Months"
    for i in {5..0}; do
        # Calculate month and year
        month=$((current_month - i))
        year=$current_year
        if [ $month -le 0 ]; then
            month=$((month + 12))
            year=$((year - 1))
        fi
        
        # Format dates for consistent 2-digit months
        month_padded=$(printf "%02d" $month)
        next_month=$((month + 1))
        next_year=$year
        if [ $next_month -gt 12 ]; then
            next_month=1
            next_year=$((year + 1))
        fi
        next_month_padded=$(printf "%02d" $next_month)
        
        # Get count for this month
        start_date="$year-$month_padded-01"
        end_date="$next_year-$next_month_padded-01"
        count=$(count_cves_in_range "$start_date" "$end_date")
        echo "$(date -d "$start_date" +"%B %Y"): $count CVEs"
    done

    # Calculate overall averages
    print_header "Overall Averages"

    total_days=$(( ($(date +%s) - $(date -d "$first_cve_date" +%s)) / 86400 ))
    total_cves=$(count_cves_in_range "$first_cve_date" "$(date +%Y-%m-%d)")

    # Calculate averages
    avg_per_month=$(bc <<< "scale=2; $total_cves / ($total_days / 30.44)")
    avg_per_week=$(bc <<< "scale=2; $total_cves / ($total_days / 7)")
    avg_per_day=$(bc <<< "scale=2; $total_cves / $total_days")

    echo "Average CVEs per month: $avg_per_month"
    echo "Average CVEs per week: $avg_per_week"
    echo "Average CVEs per day: $avg_per_day"
fi

# Show author stats if --authors flag is provided
if [[ "$show_authors" = true ]]; then
    print_header "Top $num_authors CVE Commit Authors"
    echo "Processing commit authors (this may take a while)..."

    # Find all sha1 files and process them in parallel
    find cve/published -type f -name "*.sha1" | \
        parallel -j$(nproc) get_commit_author | \
        sort | \
        grep -v "^$" | \
        grep -v "unknown" | \
        uniq -c | \
        sort -rn | \
        head -n "$num_authors" | \
        while read count author; do
            echo "$author: $count CVEs"
        done
fi

# Show subsystem stats if --subsystem flag is provided
if [[ "$show_subsystems" = true ]]; then
    show_subsystem_stats "$num_subsystems" "$num_sub_subsystems" "$show_authors"
fi

# Update help message
if [[ ! " $* " =~ " --summary " ]] && [[ "$show_authors" = false ]] && [[ "$show_subsystems" = false ]]; then
    echo "Usage: $0 [--summary] [--authors[=N]] [--subsystem[=M[,S]]]"
    echo "  --summary              Show general CVE statistics"
    echo "  --authors[=N]          Show top N CVE commit authors (default: 10)"
    echo "  --subsystem[=M[,S]]    Show top M subsystems with S sub-subsystems each (default: M=10,S=3)"
fi

echo -e "\nStatistics calculated from $first_cve_date to $(date +%Y-%m-%d)" 