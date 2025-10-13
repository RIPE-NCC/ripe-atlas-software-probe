#!/usr/bin/env bash
set -xe
script_dir=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
project_dir=${script_dir}/../

usage() {
    echo "Usage: build-el.sh"
    echo
    echo "Optional (CI) inputs via environment variables:"
    echo " - CI_COMMIT_TAG: GitLab CI input, specifies the tag the pipeline is ran for (if it is)"
    echo " - CI_COMMIT_BRANCH: GitLab CI input, specifies the branch the pipeline is ran for (if it is)"
    echo " - CI_REPOSITORY_URL: clone URL to the repository"
    echo
    echo "If those variables are missing, the script will default to:"
    echo " - the current tag, or (then) branch"
    echo " - the upstream repo, as defined in .spec files (github.com/RIPE-NCC/ripe-atlas-software-probe, via HTTP)"
    exit 1
}
[[ $1 == "-h" || $1 == "--help" ]] && usage >&2

# Extract el release (e.g. el9)
# shellcheck disable=SC1091 # sourcing file from container
distcode="$( . /etc/os-release && echo "$PLATFORM_ID" | cut -d':' -f2 )"

pushd "$project_dir"
    # -- Set rpmbuild variables / functions / etc.
    if [[ "$CI" == "true" ]]; then
        git_tag_value="${CI_COMMIT_TAG:-${CI_COMMIT_BRANCH}}" # Override default branch
        git_url=("--define" "git_source ${CI_REPOSITORY_URL%%/ripe-atlas-software-probe.git}") # Override default URL
    else
        if tag=$(git describe --tags --exact-match); then
            git_tag_value=$tag
        elif branch=$(git rev-parse --abbrev-ref HEAD); then
            git_tag_value=$branch
        else
            echo "Error: Could not get Git tag or branch." >&2
            exit 1
        fi
    fi

    git_tag=("--define" "git_tag ${git_tag_value}")

    build_pkg() {
        local specfile=$1
        export HOME="${project_dir}" # rpmbuild uses HOME for output data
        # Bash arrays used for optional parameters (if they do not exist, they expand to no argument)
        rpmbuild -bb "${git_tag[@]}" "${git_url[@]}" "${specfile}"
    }

    # -- Building of packages
    # Create repo structure
    mkdir -pv "${distcode}"

    # Build rpms
    pushd .repo
        build_pkg rhel/ripe-atlas-repo.spec
    popd
    build_pkg rhel/ripe-atlas-probe.spec
    build_pkg rhel/ripe-atlas-anchor.spec

    cp -av "rpmbuild/RPMS/"* "${distcode}"

    # Copy VERSION files
    cp VERSION "${distcode}/VERSION"
    find "${distcode}/" -name "*repo*" | sed -E "s/.*repo-(.*)\..*\..*\.rpm*/\1/" > "${distcode}"/VERSION_REPO
popd