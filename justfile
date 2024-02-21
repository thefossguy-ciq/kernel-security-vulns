#!/usr/bin/env -S just --justfile

# show the list of options
_help:
	@just --list


# Create a CVE for a specific Linux kernel git commit id
@cve_create GIT_ID:
	cd {{invocation_directory()}}; scripts/cve_create {{GIT_ID}}


# Update all allocated CVE entries with the latest version information
@cve_update:
	cd {{invocation_directory()}}; scripts/cve_update


# Publish all modified .json files with the CVE server
@cve_publish_json:
	cd {{invocation_directory()}}; scripts/cve_publish_json


# Publish all modified .mbox messages with git-send-email
@cve_publish_mbox:
	cd {{invocation_directory()}}; scripts/cve_publish_mbox


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

