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

message("-- Including Python bindings")

find_package(PythonInterp 3.6 REQUIRED)

# Needed variables for building
set(SETUP_PY_IN "${CMAKE_CURRENT_SOURCE_DIR}/setup.py.in")
set(SETUP_PY    "${CMAKE_CURRENT_BINARY_DIR}/setup.py")
set(DEPS        "${CMAKE_CURRENT_SOURCE_DIR}/eis/__init__.py")
set(OUTPUT      "${CMAKE_CURRENT_BINARY_DIR}/build/timestamp")

# Configure setup.py script
message("-- Configuring setup.py")
configure_file(${SETUP_PY_IN} ${SETUP_PY})

# Add custom build command
add_custom_command(
    DEPENDS eismsgbus
    OUTPUT ${OUTPUT}
    COMMAND ${PYTHON_EXECUTABLE} ${SETUP_PY} build
    COMMAND ${CMAKE_COMMAND} -E touch ${OUTPUT}
    DEPENDS ${DEPS})

# Add target for the Python library
add_custom_target(py-eis-msgbus ALL DEPENDS ${OUTPUT})

install(CODE "execute_process(COMMAND ${PYTHON_EXECUTABLE} ${SETUP_PY} install)")

if(WITH_EXAMPLES)
    set(EXAMPLE_SOURCE_IN "${CMAKE_CURRENT_SOURCE_DIR}/examples/source.sh.in")
    set(EXAMPLE_SOURCE    "${PROJECT_BINARY_DIR}/examples/source.sh")

    message("-- Copying over Python examples")
    file(GLOB PY_EXAMPLES "${CMAKE_CURRENT_SOURCE_DIR}/examples/*.py")
    file(COPY ${PY_EXAMPLES}
         DESTINATION "${PROJECT_BINARY_DIR}/examples")

    # Configure file for sourcing the PYTHONPATH to be able to use the Python
    # examples
    configure_file(${EXAMPLE_SOURCE_IN} ${EXAMPLE_SOURCE})
endif()

if(WITH_TESTS)
    set(TEST_SOURCE_IN "${CMAKE_CURRENT_SOURCE_DIR}/tests/source.sh.in")
    set(TEST_SOURCE    "${PROJECT_BINARY_DIR}/tests/source.sh")

    message("-- Copying over Python tests")
    file(GLOB PY_TESTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.py")
    file(COPY ${PY_TESTS}
         DESTINATION "${PROJECT_BINARY_DIR}/tests")

    # Configure file for sourcing the PYTHONPATH to be able to use the Python
    # tests
    configure_file(${TEST_SOURCE_IN} ${TEST_SOURCE})
endif()
