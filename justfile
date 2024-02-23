#!/usr/bin/env -S just --justfile

# show the list of options
_help:
	@just --list

# Search for a specific git id in the list of published CVE ids
@cve_search GIT_ID:
	-scripts/cve_search {{GIT_ID}}


# Create a CVE for a specific Linux kernel git commit id
@cve_create GIT_ID:
	-scripts/cve_create {{GIT_ID}}


# Update all allocated CVE entries with the latest version information
@cve_update:
	scripts/cve_update


# Publish all modified .json files with the CVE server
@cve_publish_json:
	scripts/cve_publish_json


# Publish all modified .mbox messages with git-send-email
@cve_publish_mbox:
	scripts/cve_publish_mbox

# Reject a published/reserved CVE
@cve_reject CVE_ID:
	scripts/cve_reject {{CVE_ID}}

# Query the CVE server for the list of all ids assigned to us
@list_ids:
	cve -u gregkh@kernel.org -o Linux list
	#cve -u gregkh@linuxfoundation.org -o Linux -e test list


# List a summary of the ids at this point in time
summary:
	#!/usr/bin/env bash
	cd cve/reserved
	echo "Number of allocated, but not assigned CVE ids, by year:"
	for dir in $(ls); do
		count=$(find ${dir}/ -type f | wc -l)
		echo "	${dir}:	${count}"
	done

	cd ../../cve/published
	echo "Number of assigned CVE ids, by year:"
	for dir in $(ls); do
		count=$(find ${dir}/ -type f | grep "sha1" | wc -l)
		echo "	${dir}:	${count}"
	done

	cd ../../cve/rejected
	echo "Number of rejected CVE ids, by year:"
	for dir in $(ls); do
		count=$(find ${dir}/ -type f | grep "sha1" | wc -l)
		echo "	${dir}:	${count}"
	done

