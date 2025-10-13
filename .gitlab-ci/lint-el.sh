#!/usr/bin/env bash
set -xe
script_dir=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
project_dir=${script_dir}/../

# extract el release (e.g. el9)
# shellcheck disable=SC1091 # sourcing file from container
distcode="$( . /etc/os-release && echo "$PLATFORM_ID" | cut -d':' -f2 )"
export distcode

pushd "$project_dir"
    mkdir -v lint_report
    for rpm_pkg in "${distcode}"/*/*.rpm; do
        output_file=$(echo "$rpm_pkg" | sed -n "s/^.*\/\s*\(\S*\)-.*$/\1.log/p")
        set +e # rpmlint prints errors - this is known and skipped
        rpmlint "$rpm_pkg" | tee lint_report/"$output_file"
    done
popd