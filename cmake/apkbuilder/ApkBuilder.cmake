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

## -- check_exists() --
## Helper function to verify that a variable is defined, and to set a default
## value based on whether or not it is required to be set.
## --
function(check_exists varname vardefault required)
    if(NOT DEFINED ${varname})
        if(NOT required)
            message(STATUS "${varname} is undefined, default: ${vardefault}")
        else()
            message(FATAL_ERROR "!! ${varname} must be set")
        endif()
        set(${varname} ${vardefault} PARENT_SCOPE)
    endif()
endfunction()

find_program(DOCKER "docker")
if(NOT DOCKER)
    message(FATAL_ERROR "!! Cannot find docker executable")
endif()
message(STATUS "Using docker binary: ${DOCKER}")

if(NOT DEFINED APKBUILD_ALPINE_VERSION)
    set(APKBUILD_ALPINE_VERSION "3.14")
endif()

# Verify optional and required variables
check_exists("CMAKE_BUILD_TYPE" "" TRUE)
check_exists("CMAKE_PROJECT_DESCRIPTION" "" TRUE)
check_exists("PROJECT_HOMEPAGE_URL" "" FALSE)
check_exists("PROJECT_LICENSE" "" TRUE)
check_exists("APKBUILD_ALPINE_VERSION" "3.14" FALSE)
check_exists("APKBUILD_DEPENDS" "" TRUE)
check_exists("APKBUILD_DEPENDS_DEV" "" TRUE)
check_exists("APKBUILD_DEPENDS_MAKE" "" TRUE)
check_exists("APKBUILD_PKGREL" "0" FALSE)
check_exists("APKBUILD_REQUIRE_EXTERNAL_APKS" FALSE FALSE)
check_exists("APKBUILD_CMAKE_FLAGS" "" FALSE)

if(${APKBUILD_REQUIRE_EXTERNAL_APKS} AND NOT EXISTS ${CMAKE_SOURCE_DIR}/apks/)
    message(FATAL_ERROR "APKBUILD requires external APKs to be installed and apks/ directory is missing")
endif()

set(APKBUILD_APK_FILENAME "${PROJECT_NAME}-${PROJECT_VERSION}-r${APKBUILD_PKGREL}.apk")

if("${APKBUILD_CMAKE_FLAGS}" STREQUAL "")
    set(APKBUILD_CMAKE_FLAGS_STR "")
else()
    list(JOIN APKBUILD_CMAKE_FLAGS " \\\n" APKBUILD_CMAKE_FLAGS_STR)
endif()

message(STATUS "Generating APKBUILD file")
set(APKBUILD_IN "${CMAKE_SOURCE_DIR}/cmake/apkbuilder/APKBUILD.in")
set(APKBUILD_OUT "${CMAKE_BINARY_DIR}/apkbuilder/APKBUILD")
configure_file(${APKBUILD_IN} ${APKBUILD_OUT})

set(APKBUILD_IMAGE "apkbuilder-${PROJECT_NAME}:${PROJECT_VERSION}")
execute_process(
    COMMAND ${DOCKER} images -q ${APKBUILD_IMAGE}
    OUTPUT_VARIABLE IMAGE_RESULT)
if("${IMAGE_RESULT}" STREQUAL "")
    # NOTE: --no-cache is used to build the container so that a new build key
    # is generated for each apkbuilder container on the system.
    execute_process(
        COMMAND ${DOCKER} build --no-cache --build-arg ALPINE_VERSION=${APKBUILD_ALPINE_VERSION} -t ${APKBUILD_IMAGE} .
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/cmake/apkbuilder/"
        RESULT_VARIABLE DOCKER_BUILD_RESULT)
    if(${DOCKER_BUILD_RESULT})
        message(FATAL_ERROR "Docker build for ${APKBUILD_IMAGE} failed")
    endif()
else()
    message(STATUS "${APKBUILD_IMAGE} docker image exists")
endif()

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/apkbuilder/src/build)

# NOTE: --no-cache is used to build the container so that a new build key is
# generated for each apkbuilder container on the system.
add_custom_target(apkbuilder
    COMMAND ${DOCKER} build --no-cache --build-arg ALPINE_VERSION=${APKBUILD_ALPINE_VERSION} -t ${APKBUILD_IMAGE} .
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/cmake/apkbuilder/"
    VERBATIM)

# Get the base build directory to exclude it from the tar file for APK building
find_program(BASENAME "basename")
if(NOT BASENAME)
    message(FATAL_ERROR "Unable to find 'basename' utility")
endif()
execute_process(
    COMMAND ${BASENAME} ${CMAKE_BINARY_DIR}
    OUTPUT_VARIABLE BASENAME_BINARY_DIR
    RESULT_VARIABLE BASENAME_RESULT)
if(${BASENAME_RESULT})
    message(FATAL_ERROR "'${BASENAME}' command failed: ${BASENAME_BINARY_DIR}")
endif()

string(REGEX REPLACE "\n$" "" BASENAME_BINARY_DIR "${BASENAME_BINARY_DIR}")
set(BASENAME_BINARY_DIR "${BASENAME_BINARY_DIR}/*")

if(${APKBUILD_REQUIRE_EXTERNAL_APKS})
    add_custom_target(package-apk
        COMMENT "Generating APK"
        COMMAND rm -rf ${CMAKE_BINARY_DIR}/apkbuilder/src/build/
        COMMAND tar -C ${CMAKE_SOURCE_DIR} -czf ${CMAKE_BINARY_DIR}/apkbuilder/apkbuild_source.tar.gz --exclude=${BASENAME_BINARY_DIR} --exclude=build/* ./
        COMMAND ${DOCKER} run --rm -it
            -e PACKAGE_NAME=${APKBUILD_APK_FILENAME}
            -e EXTERNAL_APKS=${APKBUILD_EXTERNAL_APKS}
            -v ${CMAKE_BINARY_DIR}/apkbuilder:/package
            -v ${CMAKE_SOURCE_DIR}/apks:/apks
            ${APKBUILD_IMAGE}
        COMMAND cp ${CMAKE_BINARY_DIR}/apkbuilder/${APKBUILD_APK_FILENAME} ${CMAKE_BINARY_DIR}/${APKBUILD_APK_FILENAME}
        VERBATIM)
else()
    add_custom_target(package-apk
        COMMENT "Generating APK"
        COMMAND rm -rf ${CMAKE_BINARY_DIR}/apkbuilder/src/build/
        COMMAND tar -C ${CMAKE_SOURCE_DIR} -czf ${CMAKE_BINARY_DIR}/apkbuilder/apkbuild_source.tar.gz --exclude=${BASENAME_BINARY_DIR} --exclude=build/* ./
        COMMAND ${DOCKER} run --rm -it
            -e PACKAGE_NAME=${APKBUILD_APK_FILENAME}
            -v ${CMAKE_BINARY_DIR}/apkbuilder:/package
            ${APKBUILD_IMAGE}
        COMMAND cp ${CMAKE_BINARY_DIR}/apkbuilder/${APKBUILD_APK_FILENAME} ${CMAKE_BINARY_DIR}/${APKBUILD_APK_FILENAME}
        VERBATIM)
endif()
