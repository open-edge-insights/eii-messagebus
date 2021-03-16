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

#ifndef _EII_MESSAGE_BUS_PROTOCOL_H
#define _EII_MESSAGE_BUS_PROTOCOL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "eii/msgbus/msgbus.h"

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

/**
 * Structure for shared object protocol exports.
 *
 * This structure must be filled out as a symbol in the shared library for a
 * protocol that is dynamically loaded by the message bus.
 *
 * The message bus will look for the symbol `PROTO_EXPORTS` which is a globally
 * defined instance of this structure. This will look like the following:
 *
 * ```c
 * protocol_exports_t PROTO_EXPORTS = { .initialize=proto_example_init }
 * ```
 *
 * Where the `proto_example_init()` function referenced above follows the
 * prototype of the `initialize()` function pointer in this structure.
 *
 * This structure ultimately allows the message bus to safely load the symbol
 * without worrying about various errors that can happen with directly loading
 * a function symbol and going agains the ISO C standards around this.
 */
typedef struct {
    protocol_t* (*initialize)(const char*, config_t*);
} protocol_exports_t;

/**
 * Helper macro for defining a new protocol.
 *
 * This macro defines the function prototypes for all of the functions needed
 * for an EII Message Bus protocol. Additionally, it defines the
 * `PROTO_EXPORTS` global which is required to dynamically load the protocol
 * into the EII Message Bus.
 */
#define EII_MSGBUS_PROTO(proto_name) \
    protocol_t* proto_##proto_name##_initialize(const char*, config_t*); \
    void proto_##proto_name##_destroy(void* ctx); \
    msgbus_ret_t proto_##proto_name##_publisher_new( \
            void* ctx, const char* topic, void** pub_ctx); \
    msgbus_ret_t proto_##proto_name##_publisher_publish( \
            void* ctx, void* pub_ctx, msg_envelope_t* msg); \
    void proto_##proto_name##_publisher_destroy(void* ctx, void* pub_ctx); \
    msgbus_ret_t proto_##proto_name##_subscriber_new( \
        void* ctx, const char* topic, void** subscriber); \
    void proto_##proto_name##_recv_ctx_destroy(void* ctx, void* recv_ctx); \
    msgbus_ret_t proto_##proto_name##_recv_wait( \
            void* ctx, void* recv_ctx, msg_envelope_t** message); \
    msgbus_ret_t proto_##proto_name##_recv_timedwait( \
            void* ctx, void* recv_ctx, int timeout, msg_envelope_t** message); \
    msgbus_ret_t proto_##proto_name##_recv_nowait( \
            void* ctx, void* recv_ctx, msg_envelope_t** message); \
    msgbus_ret_t proto_##proto_name##_service_get( \
            void* ctx, const char* service_name, void** service_ctx); \
    msgbus_ret_t proto_##proto_name##_service_new( \
            void* ctx, const char* service_name, void** service_ctx); \
    msgbus_ret_t proto_##proto_name##_request( \
            void* ctx, void* service_ctx, msg_envelope_t* msg); \
    msgbus_ret_t proto_##proto_name##_response( \
            void* ctx, void* service_ctx, msg_envelope_t* message); \
    protocol_exports_t PROTO_EXPORTS = {  \
        .initialize=proto_##proto_name##_initialize };

#ifdef __cplusplus
}
#endif

#endif // _EII_MESSAGE_BUS_PROTOCOL_H
