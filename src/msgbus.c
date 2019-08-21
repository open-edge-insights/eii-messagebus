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

#include "eis/msgbus/msgbus.h"
#include "eis/msgbus/protocol.h"
#include "eis/msgbus/logger.h"
#include "eis/msgbus/zmq.h"

config_t* msgbus_config_new(
        void* cfg, void (*free_fn)(void*),
        config_value_t* (*get_config_value)(const void*,const char*)) {
    if(cfg != NULL && free_fn == NULL) {
        LOG_ERROR_0("Free method not specified for cfg object");
        return NULL;
    } else if(cfg == NULL && free_fn != NULL) {
        LOG_ERROR_0("Free method specified for NULL cfg");
        return NULL;
    }

    config_t* config = (config_t*) malloc(sizeof(config_t));
    if(config == NULL) {
        LOG_ERROR_0("config malloc failed");
        return NULL;
    }

    config->cfg = cfg;
    config->free = free_fn;
    config->get_config_value = get_config_value;

    return config;
}

config_value_t* msgbus_config_value_new_integer(int64_t value) {
    config_value_t* cv = (config_value_t*) malloc(sizeof(config_value_t));
    if(cv == NULL) {
        LOG_ERROR_0("Out of memory creating config value");
        return NULL;
    }

    cv->type = CVT_INTEGER;
    cv->body.integer = value;
    return cv;
}

config_value_t* msgbus_config_value_new_floating(double value) {
    config_value_t* cv = (config_value_t*) malloc(sizeof(config_value_t));
    if(cv == NULL) {
        LOG_ERROR_0("Out of memory creating config value");
        return NULL;
    }

    cv->type = CVT_FLOATING;
    cv->body.floating = value;
    return cv;
}

config_value_t* msgbus_config_value_new_string(const char* value) {
    config_value_t* cv = (config_value_t*) malloc(sizeof(config_value_t));
    if(cv == NULL) {
        LOG_ERROR_0("Out of memory creating config value");
        return NULL;
    }

    size_t len = strlen(value);

    cv->type = CVT_STRING;
    cv->body.string = (char*) malloc(sizeof(char) * (len + 1));
    memcpy_s(cv->body.string, len, value, len);
    cv->body.string[len] = '\0';

    return cv;
}

config_value_t* msgbus_config_value_new_boolean(bool value) {
    config_value_t* cv = (config_value_t*) malloc(sizeof(config_value_t));
    if(cv == NULL) {
        LOG_ERROR_0("Out of memory creating config value");
        return NULL;
    }

    cv->type = CVT_BOOLEAN;
    cv->body.boolean = value;

    return cv;
}

config_value_t* msgbus_config_value_new_object(
        void* value, void (*free_fn)(void* object))
{
    config_value_t* cv = (config_value_t*) malloc(sizeof(config_value_t));
    if(cv == NULL) {
        LOG_ERROR_0("Out of memory creating config value");
        return NULL;
    }

    cv->type = CVT_OBJECT;
    cv->body.object = (config_value_object_t*) malloc(
            sizeof(config_value_object_t));
    if(cv->body.object == NULL) {
        LOG_ERROR_0("Out of memory creating config object wrapper");
        free(cv);
        return NULL;
    }

    cv->body.object->object = value;
    cv->body.object->free = free_fn;

    return cv;
}

config_value_t* msgbus_config_value_new_array(
        void* array, size_t length, config_value_t* (get)(void*,int),
        void (*free_fn)(void*))
{
    config_value_t* cv = (config_value_t*) malloc(sizeof(config_value_t));
    if(cv == NULL) {
        LOG_ERROR_0("Out of memory creating config value");
        return NULL;
    }

    cv->type = CVT_ARRAY;
    cv->body.array = (config_value_array_t*) malloc(
            sizeof(config_value_array_t));
    if(cv->body.array == NULL) {
        LOG_ERROR_0("Out of memory creating config array wrapper");
        free(cv);
        return NULL;
    }

    cv->body.array->array = array;
    cv->body.array->length = length;
    cv->body.array->get = get;
    cv->body.array->free = free_fn;

    return cv;
}

void msgbus_config_value_destroy(config_value_t* value) {
    if(value == NULL) return;

    if(value->type == CVT_OBJECT) {
        if(value->body.object->free != NULL)
            value->body.object->free(value->body.object->object);
        free(value->body.object);
    } else if(value->type == CVT_ARRAY) {
        if(value->body.array->free != NULL)
            value->body.array->free(value->body.array->array);
        free(value->body.array);
    } else if(value->type == CVT_STRING) {
        free(value->body.string);
    }

    free(value);
}

void msgbus_config_destroy(config_t* config) {
    if(config->cfg != NULL) {
        config->free(config->cfg);
    }
    free(config);
}

void* msgbus_initialize(config_t* config) {
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
    msgbus_config_value_destroy(value);

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
    msgbus_config_destroy(proto->config);
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

owned_blob_t* owned_blob_new(
        void* ptr, void (*free_fn)(void*), const char* data, size_t len)
{
    owned_blob_t* shared = (owned_blob_t*) malloc(sizeof(owned_blob_t));
    if(shared == NULL) {
        LOG_ERROR_0("Failed to malloc shared blob");
        return NULL;
    }

    shared->ptr = ptr;
    shared->free = free_fn;
    shared->owned = true;
    shared->len = len;
    shared->bytes = data;

    return shared;
}

owned_blob_t* owned_blob_copy(owned_blob_t* to_copy) {
    owned_blob_t* shared = (owned_blob_t*) malloc(sizeof(owned_blob_t));
    if(shared == NULL) {
        LOG_ERROR_0("Failed to malloc shared blob");
        return NULL;
    }

    shared->ptr = to_copy->ptr;
    shared->free = to_copy->free;
    shared->len = to_copy->len;
    shared->bytes = to_copy->bytes;
    shared->owned = false;  // This is important to note!

    return shared;
}

void owned_blob_destroy(owned_blob_t* shared) {
    if(shared->owned)
        shared->free(shared->ptr);
    free(shared);
}
