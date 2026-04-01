#!/bin/bash
set -euo pipefail

test_example() {
    echo "Doing example test"
}

do_test() { # $1: name
    echo '=============================='
    echo "Test $1"
    echo '------------------------------'
    if "test_$1"; then
        echo "PASS $1"
    else
        echo "FAIL $1"
    fi
    echo '=============================='
}

DIR_WORK=$(mktemp -d "${TMPDIR:-/tmp}/adumpkTests.XXXXXXX")
trap "rm -rf ${DIR_WORK}" EXIT INT TERM KILL

if [[ "$#" -gt 0 ]]; then
    for TEST in "$@"; do
        do_test "${TEST}"
    done
else
    for TEST in $(declare -F | sed -n 's/^declare -f test_\([a-zA-Z0-9]\+\)$/\1/p'); do
        do_test "${TEST}"
    done
fi
