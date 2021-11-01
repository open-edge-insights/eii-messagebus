#!/bin/bash

# Copyright (c) 2021 Intel Corporation.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM,OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

RED='\033[0;31m'
YELLOW="\033[1;33m"
GREEN="\033[0;32m"
NC='\033[0m' # No Color

function log_warn() {
    echo -e "${YELLOW}WARN: $1 ${NC}"
}

function log_info() {
    echo -e "${GREEN}INFO: $1 ${NC}"
}

function log_error() {
    echo -e "${RED}ERROR: $1 ${NC}"
}

function log_fatal() {
    echo -e "${RED}FATAL: $1 ${NC}"
    exit -1
}

function check_error() {
    if [ $? -ne 0 ] ; then
        if [ -f "rm /tmp/cmake-3.11.1-Linux-x86_64.sh" ] ; then
            rm /tmp/cmake-3.11.1-linux-x86_64.sh
        fi
        log_fatal "$1"
    fi
}

if [ -z $PACKAGE_NAME ] ; then
    log_fatal "Environmental variable 'PACKAGE_NAME' is not set"
fi

pkg_loc="/home/builder/packages/x86_64/$PACKAGE_NAME"

if [ -d "/apks/" ] ; then
    if [ -z $EXTERNAL_APKS ] ; then
        log_fatal "Environmental variable 'EXTERNAL_APKS' is not set"
    fi

    log_info "Installing required external APKs"
    for apk in ${EXTERNAL_APKS//,/ } ; do
        log_info "Installing $apk"
        sudo -E apk add --allow-untrusted /apks/${apk}*.apk
        check_error "Failed to install $apk"
    done
fi

log_info "Executing abuild checksum"
abuild checksum
check_error "abuild checksum failed"

log_info "Executing abuild -r"
abuild -r
check_error "abuild -r failed"

if [ ! -f $pkg_loc ] ; then
    log_fatal "APK file not generated where expected: $pkg_loc"
fi

log_info "Copying over finished APK file: $pkg_loc"
cp $pkg_loc /package/$PACKAGE_NAME
check_error "Failed to copy over APK file: $pkg_loc"
