#!/bin/bash
set -euo pipefail

OPENWRT_MIRROR="${OPENWRT_MIRROR:-https://downloads.openwrt.org}"

DIR_WORK=$(mktemp -d "${TMPDIR:-/tmp}/adumpkTests.XXXXXXX")
trap "rm -rf ${DIR_WORK}" EXIT INT TERM KILL

if [[ -z "${OPENWRT_RELEASE:-}" ]]; then
    echo "Getting OpenWrt Latest Release from ${OPENWRT_MIRROR}..."
    OPENWRT_RELEASE=$(
        curl "${OPENWRT_MIRROR}/" |
        sed -n 's|^.\+a href="releases/\([0-9.]\+\)/targets.\+$|\1|p;T;q'
    )
    echo "Latest OpenWrt Release is ${OPENWRT_RELEASE}"
    
fi

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

if [[ "$#" -gt 0 ]]; then
    for TEST in "$@"; do
        do_test "${TEST}"
    done
else
    for TEST in $(declare -F | sed -n 's/^declare -f test_\([a-zA-Z0-9]\+\)$/\1/p'); do
        do_test "${TEST}"
    done
fi
