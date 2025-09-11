#!/bin/sh
#
# gcc-version gcc-command
#
# Prints the gcc version of `gcc-command' in a canonical 4-digit form
# such as `0295' for gcc-2.95, `0303' for gcc-3.3, etc.
# Also works with clang by detecting __GNUC__ compatibility.
#

compiler="$*"

# Check if compiler is clang and handle accordingly
if $compiler --version 2>/dev/null | grep -q "clang"; then
    # For clang, try to get the gcc compatibility version
    # Clang defines __GNUC__ and __GNUC_MINOR__ for compatibility
    MAJ_MIN=$(echo __GNUC__ __GNUC_MINOR__ | $compiler -E -xc - | tail -n 1)
    if [ -n "$MAJ_MIN" ] && [ "$MAJ_MIN" != "__GNUC__ __GNUC_MINOR__" ]; then
        printf '%02d%02d\n' $MAJ_MIN
    else
        # Fallback: assume clang is compatible with gcc 4.0+
        printf '0400\n'
    fi
else
    # For gcc, use the original logic
    MAJ_MIN=$(echo __GNUC__ __GNUC_MINOR__ | $compiler -E -xc - | tail -n 1)
    printf '%02d%02d\n' $MAJ_MIN
fi
