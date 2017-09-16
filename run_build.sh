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

mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j8 -Wall

if [ $? -ne 0 ]; then
    error "Error: failed to compile!"
    exit 1
fi
