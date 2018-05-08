#!/usr/bin/env bash

RED='\033[0;31m'
BG='\033[0;32m'
NC='\033[0m'

error() {
    >&2 echo -e "${RED}$1${NC}";
}

info() {
    echo -e "${BG}$1${NC}";
}

DIRECTORY=build
TEST_ELF=pe_ep_intercept_tests

if [ -d ${DIRECTORY} ]; then
    cd ${DIRECTORY}/tests
    ./${TEST_ELF}

    result=$?

    if [ ${result} -ne 0 ]; then
        error "Error: one or more tests failed!"
    elif [ ${result} -eq 0 ]; then
        info "Success: all tests passed."
    fi

    exit ${result}
else
    error "Error: no build directory found!"
    exit 1
fi
