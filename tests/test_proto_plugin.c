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
 * @brief Test protocol plugin used for unit testing dynamically loading
 *  protocol libraries
 */

#include <eii/utils/logger.h>
#include "eii/msgbus/protocol.h"

// NOTE: This line would typically be done in a header file...

// Define "test" EII protocol plugin
EII_MSGBUS_PROTO(test)

// END NORMAL HEADER SECTION

protocol_t* proto_test_initialize(const char* type, config_t* config) {
    LOG_DEBUG_0("Initializing test protocol");

    // Initialize the protocol_t structure
    protocol_t* proto_ctx = (protocol_t*) malloc(sizeof(protocol_t));
    if (proto_ctx == NULL) {
        LOG_ERROR_0("Ran out of memory allocating the protocol_t struct");
        goto err;
    }

    proto_ctx->proto_ctx = NULL;
    proto_ctx->config = config;

    // Assign all of the function pointers

    proto_ctx->destroy = proto_test_destroy;
    proto_ctx->publisher_new = proto_test_publisher_new;
    proto_ctx->publisher_publish = proto_test_publisher_publish;
    proto_ctx->publisher_destroy = proto_test_publisher_destroy;
    proto_ctx->subscriber_new = proto_test_subscriber_new;
    proto_ctx->request = proto_test_request;
    proto_ctx->response = proto_test_response;
    proto_ctx->service_get = proto_test_service_get;
    proto_ctx->service_new = proto_test_service_new;
    proto_ctx->recv_ctx_destroy = proto_test_recv_ctx_destroy;
    proto_ctx->recv_wait = proto_test_recv_wait;
    proto_ctx->recv_timedwait = proto_test_recv_timedwait;
    proto_ctx->recv_nowait = proto_test_recv_nowait;

    return proto_ctx;

err:
    return NULL;
}

// proto_* function implementations

void proto_test_destroy(void* ctx) {
    LOG_DEBUG_0("Destroying test protocol context");
}

msgbus_ret_t proto_test_publisher_new(
        void* ctx, const char* topic, void** pub_ctx)
{
    LOG_DEBUG("Initializing publisher for topic '%s'", topic);
    return MSG_SUCCESS;
}

msgbus_ret_t proto_test_publisher_publish(
        void* ctx, void* pub_ctx, msg_envelope_t* msg)
{
    return MSG_SUCCESS;
}

void proto_test_publisher_destroy(void* ctx, void* pub_ctx) {
    LOG_DEBUG_0("Destroying publisher context");
}

msgbus_ret_t proto_test_subscriber_new(
    void* ctx, const char* topic, void** subscriber)
{
    LOG_DEBUG("Initializig subscriber to topic '%s'", topic);
    return MSG_SUCCESS;
}

void proto_test_recv_ctx_destroy(void* ctx, void* recv_ctx) {
    LOG_DEBUG_0("Destroying receive context");
}

msgbus_ret_t proto_test_recv_wait(
        void* ctx, void* recv_ctx, msg_envelope_t** message)
{
    return MSG_SUCCESS;
}

msgbus_ret_t proto_test_recv_timedwait(
        void* ctx, void* recv_ctx, int timeout, msg_envelope_t** message)
{
    return MSG_SUCCESS;
}

msgbus_ret_t proto_test_recv_nowait(
        void* ctx, void* recv_ctx, msg_envelope_t** message)
{
    return MSG_SUCCESS;
}

msgbus_ret_t proto_test_service_get(
        void* ctx, const char* service_name, void** service_ctx)
{
    LOG_DEBUG("Initializing service request for service '%s'", service_name);
    return MSG_SUCCESS;
}

msgbus_ret_t proto_test_service_new(
        void* ctx, const char* service_name, void** service_ctx)
{
    LOG_DEBUG("Initializing service '%s' context", service_name);
    return MSG_SUCCESS;
}

msgbus_ret_t proto_test_request(
        void* ctx, void* service_ctx, msg_envelope_t* msg)
{
    return MSG_SUCCESS;
}

msgbus_ret_t proto_test_response(
        void* ctx, void* service_ctx, msg_envelope_t* message)
{
    return MSG_SUCCESS;
}
