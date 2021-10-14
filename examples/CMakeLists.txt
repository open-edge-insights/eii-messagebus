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

# Copy over TCP configuration files
file(GLOB CONFIGS "configs/*.json")

foreach(CONFIG ${CONFIGS})
    file(COPY "${CONFIG}" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/configs")
endforeach()

# Copy over configuration tool
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/gen_tcp_sub_conf.py"
     DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")

# Add publisher example
add_executable(publisher "publisher.c")
target_link_libraries(publisher eiimsgbus
                                ${IntelSafeString_LIBRARIES}
                                eiiutils
                                eiimsgenv
                                pthread)

# Add subscriber example
add_executable(subscriber "subscriber.c")
target_link_libraries(subscriber eiimsgbus
                                 ${IntelSafeString_LIBRARIES}
                                 eiiutils
                                 eiimsgenv
                                 pthread)

# Add echo service example
add_executable(echo-service "echo_service.c")
target_link_libraries(echo-service eiimsgbus
                                   ${IntelSafeString_LIBRARIES}
                                   eiiutils
                                   eiimsgenv
                                   pthread)

# Add echo service client example
add_executable(echo-client "echo_client.c")
target_link_libraries(echo-client eiimsgbus
                                  ${IntelSafeString_LIBRARIES}
                                  eiiutils
                                  eiimsgenv
                                  pthread)

# Add publisher many example
add_executable(publisher-many "publisher_many.c")
target_link_libraries(publisher-many eiimsgbus
                                     ${IntelSafeString_LIBRARIES}
                                     eiiutils
                                     eiimsgenv
                                     pthread)

# Add publisher multi blob example
add_executable(publisher-multi-blob "publisher_multi_blob.c")
target_link_libraries(publisher-multi-blob eiimsgbus
                                     ${IntelSafeString_LIBRARIES}
                                     eiiutils
                                     eiimsgenv
                                     pthread)

# Add pubsub c++ example
add_executable(pubsub-threads "pubsub_threads.cpp")
target_link_libraries(pubsub-threads eiimsgbus
                                     ${IntelSafeString_LIBRARIES}
                                     eiiutils
                                     eiimsgenv
                                     pthread)

# Add subscriber thread C++ example
add_executable(thread-subscriber "subscriber_thread.cpp")
target_link_libraries(thread-subscriber eiimsgbus
                                        ${IntelSafeString_LIBRARIES}
                                        eiiutils
                                        eiimsgenv
                                        pthread)

# Add MsgEnvelope C++ example
add_executable(msg_envelope_example "msg_envelope_example.cpp")
target_link_libraries(msg_envelope_example eiimsgbus
                                           pthread
                                           ${IntelSafeString_LIBRARIES}
                                           eiiutils
                                           eiimsgenv)

# Add C++ publisher example
add_executable(cpp-publisher "publisher.cpp")
target_link_libraries(cpp-publisher eiimsgbus
                                   pthread
                                   ${IntelSafeString_LIBRARIES}
                                   eiiutils
                                   eiimsgenv)

# Add C++ subscriber example
add_executable(cpp-subscriber "subscriber.cpp")
target_link_libraries(cpp-subscriber eiimsgbus
                                   pthread
                                   ${IntelSafeString_LIBRARIES}
                                   eiiutils
                                   eiimsgenv)
