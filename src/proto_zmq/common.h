// Copyright (c) 2020 Intel Corporation.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM,OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

/**
 * @brief Common utility functions used in the EIS Message Bus ZMQ protocol
 * @author Kevin Midkiff <kevin.midkiff@intel.com>
 */

#ifndef _EIS_MESSAGE_BUS_ZMQ_COMMON_H
#define _EIS_MESSAGE_BUS_ZMQ_COMMON_H

#include <stdarg.h>
#include <stdbool.h>
// Include libzmq zmq.h header
#include <zmq.h>
#include <eis/utils/logger.h>

#define ZMQ_CFG_TCP_PUB             "zmq_tcp_publish"
#define ZMQ_CFG_TCP_ALLOWED_CLIENTS "allowed_clients"

// Expected configuration keys for server sockets (used for TCP communication)
#define ZMQ_CFG_SERVER_SECRET   "server_secret_key"

// Expected configuration keys for client sockets (used for TCP communication)
#define ZMQ_CFG_SERVER_PUBLIC_KEY "server_public_key"
#define ZMQ_CFG_CLIENT_PUBLIC_KEY "client_public_key"
#define ZMQ_CFG_CLIENT_SECRET_KEY "client_secret_key"

// Helper macro for logging errors in ZeroMQ
#define LOG_ZMQ_ERROR(msg) \
    LOG_ERROR(msg ": [%d] %s", zmq_errno(), zmq_strerror(zmq_errno()));

/**
 * Helper method to verify that the given ZeroMQ curve key is of length 40.
 *
 * @param key - Key to verify
 * @return true if key is valid, otherwise return false
 */
bool verify_key_len(const char* key);

/**
 * ZeroMQ helper function to close a socket with no linger for currently
 * sending messages.
 *
 * @param socket - ZeroMQ socket pointer
 */
void close_zero_linger(void* socket);

/**
 * Helper function to get a string for the name of a ZeroMQ event.
 *
 * @param event - ZeroMQ event ID
 */
const char* get_event_str(int event);

/**
 * Helper method to see if any events occured on a given socket.
 *
 * @param monitor - ZeroMQ monitor socket
 * @param block   - Flag for whether or not to block until an event occurs
 * @return ZeroMQ event ID
 */
int get_monitor_event(void* monitor, bool block);

#endif // _EIS_MESSAGE_BUS_ZMQ_COMMON_H
