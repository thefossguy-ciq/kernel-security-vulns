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

# Function to print a section header
print_header() {
    echo -e "\n=== $1 ==="
}

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

# Get total CVEs and days since first CVE
first_cve_date=$(git log --diff-filter=A --reverse --pretty=format:%ad --date=short cve/published/ | head -n 1)
if [ -z "$first_cve_date" ]; then
    first_cve_date="2019-01-01" # Fallback if no git history
fi

total_days=$(( ($(date +%s) - $(date -d "$first_cve_date" +%s)) / 86400 ))
total_cves=$(count_cves_in_range "$first_cve_date" "$(date +%Y-%m-%d)")

# Calculate averages
avg_per_month=$(bc <<< "scale=2; $total_cves / ($total_days / 30.44)")
avg_per_week=$(bc <<< "scale=2; $total_cves / ($total_days / 7)")
avg_per_day=$(bc <<< "scale=2; $total_cves / $total_days")

echo "Average CVEs per month: $avg_per_month"
echo "Average CVEs per week: $avg_per_week"
echo "Average CVEs per day: $avg_per_day"
echo -e "\nStatistics calculated from $first_cve_date to $(date +%Y-%m-%d)" 