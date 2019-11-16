# Copyright (c) 2019 Intel Corporation.
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

cmake_minimum_required(VERSION 3.11)
project(eis-messagebus VERSION 1.0.0 LANGUAGES C CXX)

# Define CMake options
option(WITH_EXAMPLES "Compile with examples" OFF)
option(WITH_TESTS    "Compile with unit tests" OFF)
option(WITH_PYTHON   "Compile with Python bindings" OFF)
option(WITH_GO       "Install Go bindings with the message bus installation" OFF)
option(WITH_DOCS     "Generate message bus documentation" OFF)

# Globals
set(EIS_COMMON_CMAKE "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake")

# Set C standard to C11
set(CMAKE_C_STANDARD 11)

# Set CFLAGS
set(CMAKE_C_FLAGS "-fPIE -fPIC -O2 -Wall -pedantic -fstack-protector-strong -D_FORTIFY_SOURCE=2")

# Set LDFLAGS
set(CMAKE_SHARED_LINKER_FLAGS "-z noexecstack -z relro -z now")

# Add cmake module path
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" "${EIS_COMMON_CMAKE}")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(EXISTS "${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json")
    EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json
        ${CMAKE_CURRENT_SOURCE_DIR}/compile_commands.json
    )
endif()

# Finding libraries
find_package(ZMQ REQUIRED)
find_package(Threads REQUIRED)
find_package(cJSON REQUIRED)
find_package(EISUtils REQUIRED)
find_package(EISMsgEnv REQUIRED)
find_package(IntelSafeString REQUIRED)

# Include header directories
include_directories(
    include/
    ${CMAKE_CURRENT_SOURCE_DIR}/../../util/cpuid/
    ${EISMsgEnv_INCLUDE}
    ${EISUtils_INCLUDE}
    ${ZMQ_INCLUDE_DIRS}
    ${CJSON_INCLUDE_DIRS}
    ${IntelSafeString_INCLUDE})

# Get all source files
file(GLOB SOURCES "src/*.c")
set_source_files_properties(${SOURCES} PROPERTIES LANGUAGE C)

add_library(eismsgbus SHARED
    ${SOURCES}
    "${CMAKE_CURRENT_SOURCE_DIR}/../../util/cpuid/cpuid-check.c")
target_link_libraries(eismsgbus
    PUBLIC
        pthread
        ${EISUtils_LIBRARIES}
        ${EISMsgEnv_LIBRARIES}
    PRIVATE
        ${ZMQ_LIBRARIES}
        ${CJSON_LIBRARIES}
        ${IntelSafeString_LIBRARIES})

# If compile in debug mode, set DEBUG flag for C code
if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    target_compile_definitions(eismsgbus PRIVATE DEBUG=1)
endif()

if(WITH_EXAMPLES)
    add_subdirectory(examples/)
endif()
if(WITH_PYTHON)
    add_subdirectory(python/)
endif()
if(WITH_TESTS)
    add_subdirectory(tests/)
endif()

##
## Configure pkg-config file to be installed for the EIS Message Bus
##
set(PKG_CONFIG_IN  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/libeismsgbus.pc.in")
set(PKG_CONFIG_OUT "${CMAKE_CURRENT_BINARY_DIR}/libeismsgbus.pc")
set(DEST_DIR       "${CMAKE_INSTALL_PREFIX}")
set(PRIVATE_LIBS   "-lzmq -lcjson")

configure_file(${PKG_CONFIG_IN} ${PKG_CONFIG_OUT} @ONLY)

##
## Add CMake configuration for installing the library including files for other
## projects finding the library using CMake
##

include(GNUInstallDirs)
set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/EISMessageBus)

install(TARGETS eismsgbus
    EXPORT eismsgbus-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

set_target_properties(eismsgbus PROPERTIES EXPORT_NAME EISMessageBus)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Install pkg-config libeismsgbus.pc file
install(
    FILES
        ${PKG_CONFIG_OUT}
    DESTINATION
        ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

# Install Go package if specified to
if(WITH_GO)
    message("-- Configuring Go package installation")

    # Verify the $GOPATH environmental variable exists
    if("$ENV{GOPATH}" STREQUAL "")
        message(FATAL_ERROR "-- $GOPATH envronmental variable is not set")
    endif()

    # Configure install command to copy the Go EIS Message Bus library to the
    # user's $GOPATH
    install(
        DIRECTORY
            ${CMAKE_CURRENT_SOURCE_DIR}/go/EISMessageBus
        DESTINATION
            $ENV{GOPATH}/src/
    )
endif()

# Export targets to a script
install(EXPORT eismsgbus-targets
    FILE
        EISMessageBusTargets.cmake
    DESTINATION
        ${INSTALL_CONFIGDIR}
)

# Create a ConfigVersion.cmake file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/EISMessageBusConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
    ${CMAKE_CURRENT_LIST_DIR}/cmake/EISMessageBusConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/EISMessageBusConfig.cmake
    INSTALL_DESTINATION ${INSTALL_CONFIGDIR}
)

# Install the config, configversion and custom find modules
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/EISMessageBusConfigVersion.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/EISMessageBusConfig.cmake
    DESTINATION ${INSTALL_CONFIGDIR}
)

export(EXPORT eismsgbus-targets
    FILE ${CMAKE_CURRENT_BINARY_DIR}/EISMessageBusTargets.cmake)

# Register package in user's package registry
export(PACKAGE EISMessageBus)

##
## Documentation generation
##
if(WITH_DOCS)
    message("-- Configuring documentation generation")

    set(DOCS_DIR "${CMAKE_CURRENT_BINARY_DIR}/docs")
    set(PDFS_DIR "${DOCS_DIR}/pdfs")

    # Create doxygen directory
    file(MAKE_DIRECTORY ${DOCS_DIR})
    file(MAKE_DIRECTORY ${PDFS_DIR})

    # Doxygen documentation generation
    message("       Configuring C API documentation")
    find_package(Doxygen REQUIRED)
    find_program(PDFLATEX NAMES pdflatex)

    # Make C documentation directory
    file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/docs/c")

    set(DOXYFILE_IN  "${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in")
    set(DOXYFILE_OUT "${CMAKE_CURRENT_BINARY_DIR}/Doxyfile")

    configure_file(${DOXYFILE_IN} ${DOXYFILE_OUT} @ONLY)

    # Add target for generating doxygen documentation
    add_custom_target(doxygen-docs
        COMMENT "Generating C API Doxygen documentation"
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYFILE_OUT}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        VERBATIM)

    # Add target for generating PDF of C doxygen documentation
    add_custom_target(doxygen-docs-pdf
        COMMENT "Generating C API PDF"
        DEPENDS doxygen-docs
        COMMAND ${CMAKE_COMMAND} -E remove "${PDFS_DIR}/EIS_MsgBus_C_Reference_${PROJECT_VERSION}.pdf"
        COMMAND ${PDFLATEX}
            -interaction=nonstopmode
            -output-directory ${PDFS_DIR}
            -jobname=EIS_MsgBus_C_Reference_${PROJECT_VERSION}
            refman.tex
        WORKING_DIRECTORY ${DOCS_DIR}/c/latex/
        VERBATIM)

    # List of docs dependency targets
    set(DOCS_TARGETS doxygen-docs doxygen-docs-pdf)

    if(WITH_PYTHON)
        message("       Configuring Python API documentation")

        # Find Sphinx commands
        find_package(Sphinx REQUIRED)

        set(PY_DOCS_DIR "${DOCS_DIR}/python")
        set(CONF_PY_IN "${CMAKE_CURRENT_SOURCE_DIR}/python/docs/conf.py.in")
        set(CONF_PY_OUT "${PY_DOCS_DIR}/conf.py")

        # Create documentation directories
        file(MAKE_DIRECTORY "${PY_DOCS_DIR}")
        file(MAKE_DIRECTORY "${PY_DOCS_DIR}/_cache")

        # Configure conf.py file
        configure_file(${CONF_PY_IN} ${CONF_PY_OUT} @ONLY)

        # Generate API documentation
        add_custom_target(python-gen-api-docs
            COMMENT "Generating Python API documentation"
            COMMAND ${SPHINX_APIDOC_BIN}
                -f -o ${CMAKE_CURRENT_SOURCE_DIR}/python/docs
                ${CMAKE_CURRENT_SOURCE_DIR}/python/eis/
            VERBATIM)

        # Generate API latex
        add_custom_target(python-gen-latex
            COMMENT "Generating Python API latex"
            DEPENDS py-eis-msgbus python-gen-api-docs
            COMMAND ${CMAKE_COMMAND}
                -E env PYTHONPATH=${CMAKE_CURRENT_BINARY_DIR}/python/build/lib.linux-x86_64-3.6
                ${SPHINX_BUILD_BIN}
                    -q -b latex
                    -c "${PY_DOCS_DIR}"
                    -d "${PY_DOCS_DIR}/_cache"
                    ${CMAKE_CURRENT_SOURCE_DIR}/python/docs/
                    ${PY_DOCS_DIR}/latex
            VERBATIM)

        # Generate PDF
        add_custom_target(python-docs-pdf
            COMMENT "Generating Python API PDF"
            DEPENDS doxygen-docs
            COMMAND ${CMAKE_COMMAND} -E remove "${PDFS_DIR}/EIS_MsgBus_Python_Reference_${PROJECT_VERSION}.pdf"
            COMMAND ${PDFLATEX}
                -interaction=nonstopmode
                -output-directory ${PDFS_DIR}
                EIS_MsgBus_Python_Reference_${PROJECT_VERSION}.tex
            WORKING_DIRECTORY ${DOCS_DIR}/python/latex/
            VERBATIM)

        # Append new target dependencies
        list(APPEND DOCS_TARGETS py-eis-msgbus python-gen-api-docs
                python-gen-latex python-docs-pdf)
    endif()

    # Final target for compiling all EIS Message Bus documentation with make docs
    add_custom_target(docs
        COMMENT "Generating EIS Message Bus documentation"
        DEPENDS ${DOCS_TARGETS}
        VERBATIM)
endif()
