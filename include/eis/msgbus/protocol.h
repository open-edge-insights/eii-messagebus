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
 * @brief Messaging protocol interface
 * @author Kevin Midkiff <kevin.midkiff@intel.com>
 */

#ifndef _EIS_MESSAGE_BUS_PROTOCOL_H
#define _EIS_MESSAGE_BUS_PROTOCOL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "eis/msgbus/msgbus.h"

/**
 * Underlying protocol interface for messaging through the message bus.
 */
typedef struct {
    void* proto_ctx;
    config_t* config;

    void (*destroy)(void* ctx);
    msgbus_ret_t (*publisher_new)(
            void* ctx, const char* topic, void** pub_ctx);
    msgbus_ret_t (*publisher_publish)(
            void* ctx, void* pub_ctx, msg_envelope_t* msg);
    void (*publisher_destroy)(void* ctx, void* pub_ctx);
    msgbus_ret_t (*subscriber_new)(
            void* ctx, const char* topic, void** subscriber);
    void (*recv_ctx_destroy)(void* ctx, void* recv_ctx);
    msgbus_ret_t (*request)(
            void* ctx, void* service_ctx, msg_envelope_t* message);
    msgbus_ret_t (*response)(
            void* ctx, void* service_ctx, msg_envelope_t* message);
    msgbus_ret_t (*service_get)(
            void* ctx, const char* service_name, void** service_ctx);
    msgbus_ret_t (*service_new)(
            void* ctx, const char* service_name, void** service_ctx);
    msgbus_ret_t (*recv_wait)(
            void* ctx, void* recv_ctx, msg_envelope_t** message);
    msgbus_ret_t (*recv_timedwait)(
            void* ctx, void* recv_ctx, int timeout, msg_envelope_t** message);
    msgbus_ret_t (*recv_nowait)(
            void* ctx, void* recv_ctx, msg_envelope_t** message);
} protocol_t;

#ifdef __cplusplus
}
#endif

#endif // _EIS_MESSAGE_BUS_PROTOCOL_H
