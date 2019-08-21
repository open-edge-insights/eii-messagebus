// Copyright (c) 2019 Intel Corporation.
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
 * @file
 * @brief ZeroMQ protocol interface
 * @author Kevin Midkiff <kevin.midkiff@intel.com>
 */

#ifndef _EIS_MESSAGE_BUS_ZMQ_H
#define _EIS_MESSAGE_BUS_ZMQ_H

#ifdef __cplusplus
extern "C" {
#endif

#include "eis/msgbus/protocol.h"

// Protocol supported by the zeromq protocol implementation
#define ZMQ_IPC "zmq_ipc"
#define ZMQ_TCP "zmq_tcp"
#define ZMQ_CFG_TCP_PUB         "zmq_tcp_publish"
#define ZMQ_CFG_TCP_ALLOWED_CLIENTS "allowed_clients"

// Expected configuration keys for server sockets (used for TCP communication)
#define ZMQ_CFG_SERVER_SECRET   "server_secret_key"

// Expected configuration keys for client sockets (used for TCP communication)
#define ZMQ_CFG_SERVER_PUBLIC_KEY "server_public_key"
#define ZMQ_CFG_CLIENT_PUBLIC_KEY "client_public_key"
#define ZMQ_CFG_CLIENT_SECRET_KEY "client_secret_key"

/**
 * Initialize the ZeroMQ protocol for the EIS message bus.
 *
 * @param type   - Protocol type string
 * @param config - Configuration
 * @return ZeroMQ protocol context, or NULL
 */
protocol_t* proto_zmq_initialize(const char* type, config_t* config);

#ifdef __cplusplus
}
#endif

#endif // _EIS_MESSAGE_BUS_ZMQ_H
