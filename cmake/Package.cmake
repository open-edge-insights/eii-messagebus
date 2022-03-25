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
option(PACKAGING "Enable packaging of the library" OFF)

set(CPACK_GENERATOR "")

# Check if dpkg-deb is installed, if it is not, set a different default value
# for the PACKAGE_DEB option
set(DPKG_DEB "dpkg-deb")
set(PACKAGE_DEB_DF ON)
find_program(DPKG_DEB_BIN "dpkg-deb")
if(NOT DPKG_DEB_BIN)
    set(PACKAGE_DEB_DF OFF)
endif()
option(PACKAGE_DEB "Enable packaging the library as a .deb" ${PACKAGE_DEB_DF})

if(PACKAGE_DEB AND NOT DPKG_DEB_BIN)
    message(FATAL_ERROR "Missing ${DPKG_DEB} tool to package DEB")
endif()

if(PACKAGE_DEB)
    list(APPEND CPACK_GENERATOR "DEB")
endif()

# Check if rpmbuild is installed, if it is not, set a different default value
# for the PACKAGE_RPM option
set(PACKAGE_RPM_DF ON)
set(RPMBUILD "rpmbuild")

find_program(RPMBUILD_BIN "${RPMBUILD}")
if(NOT RPMBUILD_BIN)
    set(PACKAGE_RPM_DF OFF)
endif()

option(PACKAGE_RPM "Enable packaging the library as a .rpm" ${PACKAGE_RPM_DF})

if(PACKAGE_RPM AND NOT RPMBUILD_BIN)
    message(FATAL_ERROR "Missing ${RPMBUILD} tools to package RPM")
endif()

if(PACKAGE_RPM)
    list(APPEND CPACK_GENERATOR "RPM")
endif()

# APK building details
set(PACKAGE_APK_DF ON)
set(DOCKER "docker")

find_program(DOCKER_BIN "${DOCKER}")
if(NOT DOCKER_BIN)
    set(PACKAGE_APK_DF OFF)
endif()

option(PACKAGE_APK "Enable packaging the library as an .apk" ${PACKAGE_APK_DF})
if(PACKAGE_APK AND NOT DOCKER_BIN)
    message(FATAL_ERROR "Missing ${DOCKER} for packaging APK")
endif()

# Check packaging
if(NOT PACKAGE_RPM AND NOT PACKAGE_DEB AND NOT PACKAGE_APK AND PACKAGING)
    message(FATAL_ERROR "Packaging enabled, but there is nothing to package")
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/LICENSE")
    set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/README.md")
    set(CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README.md")
endif()

set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")

set(CPACK_RPM_PACKAGE_AUTOPROV "1")

# List of additional paths to automatically exclude from the RPM
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "/usr/lib/cmake")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "/usr/lib/pkgconfig")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "/usr/lib/local")

if(PACKAGING)
    include(CPack)
    if(PACKAGE_APK)
        include(cmake/apkbuilder/ApkBuilder.cmake)
    endif()

    message("===== PACKAGING DETAILS =====")

    message("* PACKAGE NAME...............: ${CPACK_PACKAGE_NAME}")
    message("* PACKAGE BUILD TYPE.........: ${CMAKE_BUILD_TYPE}")
    message("* PACKAGE VENDOR.............: ${CPACK_PACKAGE_VENDOR}")
    message("* PROJECT VERSION............: ${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")
    message("* PACKAGE FILENAME...........: ${CPACK_PACKAGE_FILE_NAME}")
    message("* PACKAGE HOMEPAGE...........: ${PROJECT_HOMEPAGE_URL}")
    message("* PACKAGE LICENSE............: ${PROJECT_LICENSE}")

    message("*")
    message("* Debian Package:")
    if(PACKAGE_DEB)
        message("*  DEBIAN DEPENDENCIES.......: ${CPACK_DEBIAN_PACKAGE_DEPENDS}")
    else()
        message("*  No Debian Package")
    endif()

    message("*")
    message("* RPM Package:")
    if(PACKAGE_RPM)
        message("*  RPM DEPENDENCIES..........: ${CPACK_RPM_PACKAGE_REQUIRES}")
    else()
        message("*  No RPM Package")
    endif()

    message("*")
    message("* APK Package:")
    if(PACKAGE_APK)
        message("*  ALPINE VERSION............: ${APKBUILD_ALPINE_VERSION}")
        message("*  APK DEPENDENCEIS..........: ${APKBUILD_DEPENDS}")
        message("*  APK DEPENDENCEIS (dev)....: ${APKBUILD_DEPENDS_DEV}")
        message("*  APK MAKE DEPENDENCIES.....: ${APKBUILD_DEPENDS_MAKE}")
    else()
        message("*  No APK Package")
    endif()

    message("=============================")
else()
    message("-- Packaging disabled")
endif()
