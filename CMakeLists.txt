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
project(eii-messagebus VERSION 2.4.0 LANGUAGES C CXX)

# Define CMake options
option(WITH_TESTS    "Compile with unit tests" OFF)
option(WITH_DOCS     "Generate message bus documentation" OFF)
option(WITH_EXAMPLES "Compile with examples" OFF)

# Set C standard to C11
set(CMAKE_C_STANDARD 11)

# Set CFLAGS
set(CMAKE_C_FLAGS "-fPIE -fPIC -O2 -Wall -pedantic -fstack-protector-strong -D_FORTIFY_SOURCE=2")

# Set LDFLAGS
set(CMAKE_SHARED_LINKER_FLAGS "-z noexecstack -z relro -z now")

# Add cmake module path
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

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
find_package(EIIUtils REQUIRED)
find_package(IntelSafeString REQUIRED)
find_package(EIIDynLibLoad REQUIRED)

# Include header directories
include_directories(
    include/
    ${EIIUtils_INCLUDE}
    ${ZMQ_INCLUDE_DIRS}
    ${CJSON_INCLUDE_DIRS}
    ${EIIDYNLIBLOAD_INCLUDE}
    ${IntelSafeString_INCLUDE})

# List out all source files for the EIIMsgEnv library
set(MSGENV_SRC
    "src/msg_envelope.c"
    "src/hashmap.c"
    "src/linkedlist.c"
    "src/crc32.c"
    "src/profiling.cpp")
# set_source_files_properties(${MSGENV_SRC} PROPERTIES LANGUAGE C)

add_library(eiimsgenv SHARED ${MSGENV_SRC})
target_link_libraries(eiimsgenv
    PRIVATE
        ${EIIUtils_LIBRARIES}
        ${CJSON_LIBRARIES}
        ${IntelSafeString_LIBRARIES})

# Get all source files
file(GLOB ZMQ_SOURCE "src/proto_zmq/*.c")
set(MSGBUS_SRC "src/msgbus.c" "src/msgbus.c" ${ZMQ_SOURCE})
set_source_files_properties(${MSGBUS_SRC} PROPERTIES LANGUAGE C)

add_library(eiimsgbus SHARED ${MSGBUS_SRC})
target_link_libraries(eiimsgbus
    PUBLIC
        pthread
        eiimsgenv
        ${EIIUtils_LIBRARIES}
    PRIVATE
        ${EIIDYNLIBLOAD_LIBRARIES}
        ${ZMQ_LIBRARIES}
        ${CJSON_LIBRARIES}
        ${IntelSafeString_LIBRARIES})

# If compile in debug mode, set DEBUG flag for C code
if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    target_compile_definitions(eiimsgbus PRIVATE DEBUG=1)
endif()

if(WITH_TESTS)
    add_subdirectory(tests/)
endif()

if(WITH_EXAMPLES)
    add_subdirectory(examples/)
endif()

##
## Include CMake script for initializing all of the necessary pieces to install
## the EIIMsgEnv library
##
include("cmake/InstallMsgEnv.cmake")

##
## Include CMake script for initializing all of the necessary pieces to install
## the EIIMessageBus library
##
include("cmake/InstallMsgbus.cmake")


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
        COMMAND ${CMAKE_COMMAND} -E remove "${PDFS_DIR}/EII_MsgBus_C_Reference_${PROJECT_VERSION}.pdf"
        COMMAND ${PDFLATEX}
            -interaction=nonstopmode
            -output-directory ${PDFS_DIR}
            -jobname=EII_MsgBus_C_Reference_${PROJECT_VERSION}
            refman.tex
        WORKING_DIRECTORY ${DOCS_DIR}/c/latex/
        VERBATIM)

    # List of docs dependency targets
    set(DOCS_TARGETS doxygen-docs doxygen-docs-pdf)

    # Final target for compiling all EII Message Bus documentation with make docs
    add_custom_target(docs
        COMMENT "Generating EII Message Bus documentation"
        DEPENDS ${DOCS_TARGETS}
        VERBATIM)
endif()

# Generate DEB package for EIIMessageBus
set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "EII")
set(CPACK_PACKAGING_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")
include(CPack)
