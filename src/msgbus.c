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
 * @brief Messaging abstraction implementation
 * @author Kevin Midkiff <kevin.midkiff@intel.com>
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <safe_lib.h>
#include <eii/utils/logger.h>
#include <eii/utils/dynlibload.h>
#include <eii/utils/string.h>

#include "eii/msgbus/msgbus.h"
#include "eii/msgbus/protocol.h"
#include "proto_zmq/zmq.h"

#define INTEL_VENDOR "GenuineIntel"
#define INTEL_VENDOR_LENGTH 12
#define PROTO_LIB_LIB "lib"
#define PROTO_LIB_SO  ".so"
#define PROTO_LIB_LEN 7
#define PROTO_SYM_NAME "PROTO_EXPORTS"

/**
 * Internal msgbus context structure
 */
typedef struct {
    protocol_t* proto;
    dynlib_ctx_t* proto_lib;
    config_t* config;
} msgbus_ctx_t;

void* msgbus_initialize(config_t* config) {
    LOG_DEBUG_0("Initilizing message bus");
    char* lib_name = NULL;
    protocol_t* proto = NULL;
    dynlib_ctx_t* proto_lib = NULL;
    config_value_t* value = config->get_config_value(config->cfg, "type");

    if (value == NULL) {
        LOG_ERROR_0("Config missing 'type' key");
        goto err;
    }

    if (value->type != CVT_STRING) {
        LOG_ERROR_0("Config 'type' value MUST be a string");
        goto err;
    }

    int ind_ipc;
    int ind_tcp;
    const char* proto_name = value->body.string;

    strcmp_s(proto_name, strlen(ZMQ_IPC), ZMQ_IPC, &ind_ipc);
    strcmp_s(proto_name, strlen(ZMQ_TCP), ZMQ_TCP, &ind_tcp);

    if (ind_ipc == 0 ||ind_tcp == 0) {
        proto = proto_zmq_initialize(value->body.string, config);
        if (proto == NULL)
            goto err;
    } else {
        // Creating library name string
        size_t proto_name_len = strlen(proto_name);
        size_t dest_len = proto_name_len + PROTO_LIB_LEN;
        lib_name = concat_s(
                dest_len, 3, PROTO_LIB_LIB, proto_name, PROTO_LIB_SO);
        if (lib_name == NULL) { goto err; }

        // Load the library
        LOG_DEBUG("Loading library: %s", lib_name);
        int rc = dynlib_new(lib_name, &proto_lib);
        if (rc != DYNLOAD_SUCCESS) {
            LOG_ERROR("(rc: %d) Failed to load protocol plugin %s",
                      rc, lib_name);
            goto err;
        }

        // Extract the necessary symbol
        LOG_DEBUG("Getting '%s()' symbol from %s library",
                  PROTO_SYM_NAME, lib_name);
        void* exports_sym =  dynlib_load_sym(proto_lib, PROTO_SYM_NAME);
        if (exports_sym == NULL) {
            LOG_ERROR("Failed to load symbol '%s' in %s library",
                      PROTO_SYM_NAME, lib_name);
            goto err;
        }

        // Free no longer needed string for the library name
        // and set it to NULL
        free(lib_name);
        lib_name = NULL;

        // Attempt to initlize the protocol

        // Cast symbol to exports structure
        protocol_exports_t* proto_exports = (protocol_exports_t*) exports_sym;

        // Casting symbol to expected function
        proto = proto_exports->initialize(proto_name, config);
        if (proto == NULL) {
            LOG_ERROR("Failed to initialize protocol '%s'", proto_name);
            goto err;
        }
    }

    proto->config = config;
    config_value_destroy(value);

    msgbus_ctx_t* msgbus_ctx = (msgbus_ctx_t*) malloc(sizeof(msgbus_ctx_t));
    if (msgbus_ctx == NULL) {
        LOG_ERROR_0("Failed to initialize msgbus context");
        goto err;
    }

    msgbus_ctx->proto = proto;
    msgbus_ctx->proto_lib = proto_lib;
    msgbus_ctx->config = config;

    return (void*) msgbus_ctx;
err:
    if (value != NULL)
        free(value);
    if (lib_name != NULL)
        free(lib_name);
    if (proto_lib != NULL)
        dynlib_destroy(proto_lib);
    return NULL;
}

void msgbus_destroy(void* ctx) {
    LOG_DEBUG_0("Destroying message bus");
    msgbus_ctx_t* msgbus_ctx = (msgbus_ctx_t*) ctx;

    // Destroy the protocol context
    protocol_t* proto = msgbus_ctx->proto;
    proto->destroy(proto->proto_ctx);
    free(proto);

    // Destroy the configuration
    config_destroy(msgbus_ctx->config);

    // Destroy the dynamically loaded library if it is initialized
    if (msgbus_ctx->proto_lib != NULL)
        dynlib_destroy(msgbus_ctx->proto_lib);

    // Destroy the message bus context
    free(msgbus_ctx);
}

msgbus_ret_t msgbus_publisher_new(
        void* ctx, const char* topic, publisher_ctx_t** pub_ctx)
{
    protocol_t* proto = ((msgbus_ctx_t*) ctx)->proto;
    return proto->publisher_new(proto->proto_ctx, topic, (void*) pub_ctx);
}

msgbus_ret_t msgbus_publisher_publish(
        void* ctx, publisher_ctx_t* pub_ctx, msg_envelope_t* message) {
    protocol_t* proto = ((msgbus_ctx_t*) ctx)->proto;
    return proto->publisher_publish(proto->proto_ctx, pub_ctx, message);
}

void msgbus_publisher_destroy(void* ctx, publisher_ctx_t* pub_ctx) {
    protocol_t* proto = ((msgbus_ctx_t*) ctx)->proto;
    proto->publisher_destroy(proto->proto_ctx, pub_ctx);
}

msgbus_ret_t msgbus_subscriber_new(
        void* ctx, const char* topic, user_data_t* user_data,
        recv_ctx_t** subscriber) {
    protocol_t* proto = ((msgbus_ctx_t*) ctx)->proto;

    void* proto_sub_ctx = NULL;
    msgbus_ret_t ret =  proto->subscriber_new(
            proto->proto_ctx, topic, &proto_sub_ctx);

    if (ret == MSG_SUCCESS) {
        recv_ctx_t* recv_ctx = (recv_ctx_t*) malloc(sizeof(recv_ctx_t));
        if (recv_ctx == NULL) {
            LOG_ERROR_0("Out of memory");
            proto->recv_ctx_destroy(proto->proto_ctx, proto_sub_ctx);
            return MSG_ERR_NO_MEMORY;
        }
        recv_ctx->ctx = proto_sub_ctx;
        recv_ctx->user_data = user_data;
        (*subscriber) = recv_ctx;
    }

    return ret;
}

msgbus_ret_t msgbus_service_get(
        void* ctx, const char* service_name, void* user_data,
        recv_ctx_t** service_ctx) {
    protocol_t* proto = ((msgbus_ctx_t*) ctx)->proto;
    void* proto_service_ctx = NULL;

    msgbus_ret_t ret = proto->service_get(
            proto->proto_ctx, service_name, &proto_service_ctx);

    if (ret == MSG_SUCCESS) {
        recv_ctx_t* recv_ctx = (recv_ctx_t*) malloc(sizeof(recv_ctx_t));
        if (recv_ctx == NULL) {
            LOG_ERROR_0("Out of memory");
            proto->recv_ctx_destroy(proto->proto_ctx, proto_service_ctx);
            return MSG_ERR_NO_MEMORY;
        }
        recv_ctx->ctx = proto_service_ctx;
        recv_ctx->user_data = user_data;
        (*service_ctx) = recv_ctx;
    }

    return ret;
}

msgbus_ret_t msgbus_service_new(
        void* ctx, const char* service_name, void* user_data,
        recv_ctx_t** service_ctx) {
    protocol_t* proto = ((msgbus_ctx_t*) ctx)->proto;
    void* proto_service_ctx = NULL;

    msgbus_ret_t ret = proto->service_new(
            proto->proto_ctx, service_name, &proto_service_ctx);

    if (ret == MSG_SUCCESS) {
        recv_ctx_t* recv_ctx = (recv_ctx_t*) malloc(sizeof(recv_ctx_t));
        if (recv_ctx == NULL) {
            LOG_ERROR_0("Out of memory");
            proto->recv_ctx_destroy(proto->proto_ctx, proto_service_ctx);
            return MSG_ERR_NO_MEMORY;
        }
        recv_ctx->ctx = proto_service_ctx;
        recv_ctx->user_data = user_data;
        (*service_ctx) = recv_ctx;
    }

    return ret;
}

void msgbus_recv_ctx_destroy(void* ctx, recv_ctx_t* recv_ctx) {
    protocol_t* proto = ((msgbus_ctx_t*) ctx)->proto;
    proto->recv_ctx_destroy(proto->proto_ctx, recv_ctx->ctx);
    if (recv_ctx->user_data)
        recv_ctx->user_data->free(recv_ctx->user_data->data);
    free(recv_ctx);
}

msgbus_ret_t msgbus_request(
        void* ctx, recv_ctx_t* service_ctx, msg_envelope_t* message) {
    protocol_t* proto = ((msgbus_ctx_t*) ctx)->proto;
    return proto->request(proto->proto_ctx, service_ctx->ctx, message);
}

msgbus_ret_t msgbus_response(
        void* ctx, recv_ctx_t* service_ctx, msg_envelope_t* message) {
    protocol_t* proto = ((msgbus_ctx_t*) ctx)->proto;
    return proto->response(proto->proto_ctx, service_ctx->ctx, message);
}

msgbus_ret_t msgbus_recv_wait(
        void* ctx, recv_ctx_t* recv_ctx, msg_envelope_t** message) {
    protocol_t* proto = ((msgbus_ctx_t*) ctx)->proto;
    return proto->recv_wait(proto->proto_ctx, recv_ctx->ctx, message);
}

msgbus_ret_t msgbus_recv_timedwait(
        void* ctx, recv_ctx_t* recv_ctx, int timeout, msg_envelope_t** message)
{
    protocol_t* proto = ((msgbus_ctx_t*) ctx)->proto;
    return proto->recv_timedwait(
            proto->proto_ctx, recv_ctx->ctx, timeout, message);
}

msgbus_ret_t msgbus_recv_nowait(
        void* ctx, recv_ctx_t* recv_ctx, msg_envelope_t** message) {
    protocol_t* proto = ((msgbus_ctx_t*) ctx)->proto;
    return proto->recv_nowait(proto->proto_ctx, recv_ctx->ctx, message);
}
