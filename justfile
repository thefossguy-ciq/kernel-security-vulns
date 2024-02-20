#!/usr/bin/env -S just --justfile

# show the list of options
_help:
	@just --list


# Create a CVE for a specific Linux kernel git commit id
cve_create GIT_ID:
	cd {{invocation_directory()}}; scripts/cve_create {{GIT_ID}}


# Update all allocated CVE entries with the latest version information
cve_update:
	cd {{invocation_directory()}}; scripts/cve_update


# Publish all current .json files with the CVE server
cve_publish_json:
	cd {{invocation_directory()}}; scripts/cve_publish_json

