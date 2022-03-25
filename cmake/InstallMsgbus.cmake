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

##
## Helper CMake script for setting up the EIIMsgEnv library to be installed
##

##
## Configure pkg-config file to be installed for the EII Message Bus
##
set(PKG_CONFIG_IN  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/libeiimsgbus.pc.in")
set(PKG_CONFIG_OUT "${CMAKE_CURRENT_BINARY_DIR}/libeiimsgbus.pc")
set(DEST_DIR       "${CMAKE_INSTALL_PREFIX}")
set(PRIVATE_LIBS   "-lzmq -lcjson")

configure_file(${PKG_CONFIG_IN} ${PKG_CONFIG_OUT} @ONLY)

##
## Add CMake configuration for installing the library including files for other
## projects finding the library using CMake
##

include(GNUInstallDirs)
set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/EIIMessageBus)

install(TARGETS eiimsgbus
    EXPORT eiimsgbus-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

set_target_properties(eiimsgbus PROPERTIES EXPORT_NAME EIIMessageBus)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Install pkg-config libeiimsgbus.pc file
install(
    FILES
        ${PKG_CONFIG_OUT}
    DESTINATION
        ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

# Export targets to a script
install(EXPORT eiimsgbus-targets
    FILE
        EIIMessageBusTargets.cmake
    DESTINATION
        ${INSTALL_CONFIGDIR}
)

# Create a ConfigVersion.cmake file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/EIIMessageBusConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
    ${CMAKE_CURRENT_LIST_DIR}/EIIMessageBusConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/EIIMessageBusConfig.cmake
    INSTALL_DESTINATION ${INSTALL_CONFIGDIR}
)

# Install the config, configversion and custom find modules
install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/EIIMessageBusConfigVersion.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/EIIMessageBusConfig.cmake
    DESTINATION
        ${INSTALL_CONFIGDIR}
)

# Install ZeroMQ so that other applications do not have to include it
install(
    FILES
        cmake/FindZMQ.cmake
    DESTINATION
        ${INSTALL_CONFIGDIR}/../
)

export(EXPORT eiimsgbus-targets
    FILE ${CMAKE_CURRENT_BINARY_DIR}/EIIMessageBusTargets.cmake)

# Register package in user's package registry
export(PACKAGE EIIMessageBus)
