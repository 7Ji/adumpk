#!/bin/bash
set -euo pipefail

# On actual tests, this shall be set in environment to e.g. a local squid instance
MIRROR_OPENWRT="${MIRROR_OPENWRT:-https://downloads.openwrt.org}"

if [[ -z "${DIR_WORK:-}" ]]; then
    DIR_WORK=$(mktemp -d "${TMPDIR:-/tmp}/adumpkTests.XXXXXXX")
    trap "rm -rf ${DIR_WORK}" EXIT INT TERM KILL
fi

declare -A TESTS_DONE=()

do_test() { # $1: name
    SEEN="${TESTS_DONE["$1"]:-}"
    if [[ "${SEEN}" ]]; then
        return "${SEEN}"
    fi

    echo '=============================='
    echo "Test $1"
    echo '------------------------------'
    if "test_$1"; then
        TESTS_DONE["$1"]=0
        echo "PASS $1"
    else
        TESTS_DONE["$1"]=1
        echo "FAIL $1"
    fi
    echo '=============================='
}

do_test_silent() {
    do_test "$@" &>/dev/null
}

test_index_json() {
    if [[ -z "${RELEASE_OPENWRT:-}" ]]; then
        echo "Getting OpenWrt Latest Release from ${MIRROR_OPENWRT}..."
        RELEASE_OPENWRT=$(
            curl "${MIRROR_OPENWRT}/" |
            sed -n 's|^.\+a href="releases/\([0-9.]\+\)/targets.\+$|\1|p;T;q'
        )
        echo "Latest OpenWrt Release is ${RELEASE_OPENWRT}"
    fi
    PREFIX_URL_OPENWRT="${MIRROR_OPENWRT}/releases/${RELEASE_OPENWRT}/packages/x86_64/packages/"
    echo "Downloading x86_64 index"
    local INDEX="${DIR_WORK}/packages.adb"
    curl -o "${INDEX}" "${PREFIX_URL_OPENWRT}packages.adb"
    JSON_PACKAGES="${DIR_WORK}/packages.json"
    echo "Dumping with JSON output"
    ./adumpk.py --log fatal --json "${JSON_PACKAGES}" "${INDEX}"
    echo "Peek into dumped json:"
    head -c 50 "${JSON_PACKAGES}"
    echo
}

test_index_integrity() {
    do_test_silent index_json
    local INFO_NGINX=$(jq '."packages"."nginx-full"' "${JSON_PACKAGES}")
    echo "nginx-full info in the JSON:"
    echo "${INFO_NGINX}"
    local VERSION_NGINX=$(echo "${INFO_NGINX}" | jq -r '."version"')
    local SIZE_NGINX=$(echo "${INFO_NGINX}" | jq -r '."file-size"')
    # local ALGORITHM_NGINX=$(echo "${INFO_NGINX}" | jq -r '."checksum"."type"')
    # local HASH_NGINX=$(echo "${INFO_NGINX}" | jq -r '."checksum"."value"')
    # echo "Downloading the package to check integrity, version ${VERSION_NGINX}, size ${SIZE_NGINX}, ${ALGORITHM_NGINX}sum == ${HASH_NGINX}"
    echo "Downloading the package to check integrity, version ${VERSION_NGINX}, size ${SIZE_NGINX}"
    APK_NGINX="${DIR_WORK}/nginx-full.apk"
    curl -o "${APK_NGINX}" "${PREFIX_URL_OPENWRT}/nginx-full-${VERSION_NGINX}.apk"
    local SIZE_NGINX_ACTUAL=$(stat -c '%s' "${APK_NGINX}")
    # local BAD=''
    if [[ "${SIZE_NGINX}" != "${SIZE_NGINX_ACTUAL}" ]]; then
        echo "Size of nginx-full pacakge is ${SIZE_NGINX_ACTUAL}, differing from ${SIZE_NGINX} recorded in index"
        return 1
        # BAD=1
    fi
    echo "Checking if adumpk.py considers it a valid apk"
    ./adumpk.py --log fatal "${APK_NGINX}"
    # return
    # case "${ALGORITHM_NGINX}" in
    # sha1|sha256|sha512)
    #     local HASH_NGINX_ACTUAL=$("${ALGORITHM_NGINX}sum" "${FILE_NGINX}")
    #     HASH_NGINX_ACTUAL="${HASH_NGINX_ACTUAL%% *}"
    #     if [[ "${HASH_NGINX}" != "${HASH_NGINX_ACTUAL}" ]]; then
    #         echo "${ALGORITHM_NGINX}sum of nginx-full.apk differ, expected ${HASH_NGINX}, actual ${HASH_NGINX_ACTUAL}"
    #         BAD=1
    #     fi
    #     ./adumpk.py "${FILE_NGINX}"
    #     ;;
    # *)
    #     echo "Unknown Hash algorithm ${ALGORITHM_NGINX}, only sha1/sha256/sha512 are supported"
    #     BAD=1
    #     ;;
    # esac
    # [[ -z "${BAD}" ]]
}

test_apk_json() {
    do_test_silent index_integrity
    JSON_NGINX="${DIR_WORK}/nginx-full.json"
    ./adumpk.py --log fatal --json "${JSON_NGINX}" "${APK_NGINX}"
    echo "Peek into dumped json:"
    head -c 50 "${JSON_NGINX}"
    echo
}

test_apk_tar() {
    do_test_silent apk_json
    TAR_NGINX="${DIR_WORK}/nginx-full.tar"
    ./adumpk.py --log fatal --tar "${TAR_NGINX}" --tarsum "${APK_NGINX}"
    local ERR="${DIR_WORK}/nginx-full.tar.err"
    echo "Peek into tar:"
    tar -tvf "${TAR_NGINX}" 2>"${ERR}"
    [[ -s "${ERR}" ]]
}

if [[ "$#" -gt 0 ]]; then
    for TEST in "$@"; do
        do_test "${TEST}"
    done
else
    for TEST in index_json index_integrity apk_json apk_tar; do
        do_test "${TEST}"
    done
fi
