#!/usr/bin/env bash
set -xe
script_dir=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
project_dir=${script_dir}/../

usage() {
    echo "Usage: build-debian.sh"
    echo
    echo "Optional (CI) inputs via environment variables:"
    echo " - ARCH: amd64/arm64 - repo architecture used in the directory name"
    echo " - CROSS_ARM64: amd64/arm64 - enables cross-compiling variables"
    exit 1
}
[[ $1 == "-h" || $1 == "--help" ]] && usage >&2

# extract debian release codename (e.g. bookworm)
# shellcheck disable=SC1091 # sourcing file from container
distcode="$( . /etc/os-release && echo "$VERSION_CODENAME" )"
# Only used for the repo directory (based on dpkg's arch) - important for cross-compiling
arch=${ARCH:-$(dpkg --print-architecture)}

# Necessary variables for cross-compiling to arm64
if [[ "$CROSS_ARM64" == "true" ]]; then
    export CROSS_COMPILE=aarch64-linux-gnu-
    CROSS_ARGS=("-aarm64" "-Pcross,nocheck")
fi

pushd "$project_dir"
    # Create repo structure
    mkdir -pv "${distcode}/main/binary-${arch}"

    # Build debs
    dpkg-buildpackage -b "${CROSS_ARGS[@]}" -us -uc
    pushd .repo
        dpkg-buildpackage -b "${CROSS_ARGS[@]}" -us -uc
    popd

    mv -v {..,.}/ripe-atlas-*.deb "${distcode}/main/binary-${arch}/"

    # Copy VERSION files
    mv -v VERSION "${distcode}/VERSION"
    find "${distcode}/main/binary-${arch}/" -name "*repo*" | sed -E 's/.*repo_(.*)_.*\.deb/\1/' > "${distcode}/VERSION_REPO"
popd