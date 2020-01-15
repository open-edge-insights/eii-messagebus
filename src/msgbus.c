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
#include <eis/utils/logger.h>

#include "eis/msgbus/msgbus.h"
#include "eis/msgbus/protocol.h"
#include "proto_zmq/zmq.h"
#include "cpuid-check.h"

#define INTEL_VENDOR "GenuineIntel"
#define INTEL_VENDOR_LENGTH 12

void* msgbus_initialize(config_t* config) {
    LOG_DEBUG_0("Checking if vendor is Intel");
    char* vendor = get_vendor();

    int ind_vendor;
    strcmp_s(vendor, INTEL_VENDOR_LENGTH, INTEL_VENDOR, &ind_vendor);
    if(ind_vendor != 0) {
        LOG_ERROR("EIS can only be used on Intel HW, you are running on %s",
        vendor);
        return NULL;
    }

    LOG_DEBUG("Running on %s", vendor);

    LOG_DEBUG_0("Initilizing message bus");
    protocol_t* proto = NULL;
    config_value_t* value = config->get_config_value(config->cfg, "type");

    if(value == NULL) {
        LOG_ERROR_0("Config missing 'type' key");
        goto err;
    }

    if(value->type != CVT_STRING) {
        LOG_ERROR_0("Config 'type' value MUST be a string");
        goto err;
    }

    int ind_ipc;
    int ind_tcp;

    strcmp_s(value->body.string, strlen(ZMQ_IPC), ZMQ_IPC, &ind_ipc);
    strcmp_s(value->body.string, strlen(ZMQ_TCP), ZMQ_TCP, &ind_tcp);

    if(ind_ipc == 0 ||ind_tcp == 0) {
        proto = proto_zmq_initialize(value->body.string, config);
        if(proto == NULL)
            goto err;
    } else {
        LOG_ERROR("Unknown protocol type: %s", value->body.string);
        goto err;
    }

    proto->config = config;
    config_value_destroy(value);

    return (void*) proto;
err:
    if(value != NULL)
        free(value);
    return NULL;
}

void msgbus_destroy(void* ctx) {
    LOG_DEBUG_0("Destroying message bus");
    protocol_t* proto = (protocol_t*) ctx;
    proto->destroy(proto->proto_ctx);
    config_destroy(proto->config);
    free(proto);
    return;
}

msgbus_ret_t msgbus_publisher_new(
        void* ctx, const char* topic, publisher_ctx_t** pub_ctx)
{
    protocol_t* proto = (protocol_t*) ctx;
    return proto->publisher_new(proto->proto_ctx, topic, (void*) pub_ctx);
}

msgbus_ret_t msgbus_publisher_publish(
        void* ctx, publisher_ctx_t* pub_ctx, msg_envelope_t* message) {
    protocol_t* proto = (protocol_t*) ctx;
    return proto->publisher_publish(proto->proto_ctx, pub_ctx, message);
}

void msgbus_publisher_destroy(void* ctx, publisher_ctx_t* pub_ctx) {
    protocol_t* proto = (protocol_t*) ctx;
    proto->publisher_destroy(proto->proto_ctx, pub_ctx);
}

msgbus_ret_t msgbus_subscriber_new(
        void* ctx, const char* topic, user_data_t* user_data,
        recv_ctx_t** subscriber) {
    protocol_t* proto = (protocol_t*) ctx;

    void* proto_sub_ctx = NULL;
    msgbus_ret_t ret =  proto->subscriber_new(
            proto->proto_ctx, topic, &proto_sub_ctx);

    if(ret == MSG_SUCCESS) {
        recv_ctx_t* recv_ctx = (recv_ctx_t*) malloc(sizeof(recv_ctx_t));
        if(recv_ctx == NULL) {
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
    protocol_t* proto = (protocol_t*) ctx;
    void* proto_service_ctx = NULL;

    msgbus_ret_t ret = proto->service_get(
            proto->proto_ctx, service_name, &proto_service_ctx);

    if(ret == MSG_SUCCESS) {
        recv_ctx_t* recv_ctx = (recv_ctx_t*) malloc(sizeof(recv_ctx_t));
        if(recv_ctx == NULL) {
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
    protocol_t* proto = (protocol_t*) ctx;
    void* proto_service_ctx = NULL;

    msgbus_ret_t ret = proto->service_new(
            proto->proto_ctx, service_name, &proto_service_ctx);

    if(ret == MSG_SUCCESS) {
        recv_ctx_t* recv_ctx = (recv_ctx_t*) malloc(sizeof(recv_ctx_t));
        if(recv_ctx == NULL) {
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
    protocol_t* proto = (protocol_t*) ctx;
    proto->recv_ctx_destroy(proto->proto_ctx, recv_ctx->ctx);
    if(recv_ctx->user_data)
        recv_ctx->user_data->free(recv_ctx->user_data->data);
    free(recv_ctx);
}

msgbus_ret_t msgbus_request(
        void* ctx, recv_ctx_t* service_ctx, msg_envelope_t* message) {
    protocol_t* proto = (protocol_t*) ctx;
    return proto->request(proto->proto_ctx, service_ctx->ctx, message);
}

msgbus_ret_t msgbus_response(
        void* ctx, recv_ctx_t* service_ctx, msg_envelope_t* message) {
    protocol_t* proto = (protocol_t*) ctx;
    return proto->response(proto->proto_ctx, service_ctx->ctx, message);
}

msgbus_ret_t msgbus_recv_wait(
        void* ctx, recv_ctx_t* recv_ctx, msg_envelope_t** message) {
    protocol_t* proto = (protocol_t*) ctx;
    return proto->recv_wait(proto->proto_ctx, recv_ctx->ctx, message);
}

msgbus_ret_t msgbus_recv_timedwait(
        void* ctx, recv_ctx_t* recv_ctx, int timeout, msg_envelope_t** message)
{
    protocol_t* proto = (protocol_t*) ctx;
    return proto->recv_timedwait(
            proto->proto_ctx, recv_ctx->ctx, timeout, message);
}

msgbus_ret_t msgbus_recv_nowait(
        void* ctx, recv_ctx_t* recv_ctx, msg_envelope_t** message) {
    protocol_t* proto = (protocol_t*) ctx;
    return proto->recv_nowait(proto->proto_ctx, recv_ctx->ctx, message);
}
