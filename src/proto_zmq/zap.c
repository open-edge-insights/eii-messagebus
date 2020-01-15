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
 * @brief ZeroMQ Authentication Protocol (ZAP) Implementation
 * @author Kevin Midkiff <kevin.midkiff@intel.com>
 */

// Include libzmq zmq.h
#include <string.h>
#include <zmq.h>
#include <safe_lib.h>

#include "zap.h"
#include "common.h"

// Defines
#define ZAP_URI       "inproc://zeromq.zap.01"
#define ZAP_CURVE     "CURVE"

// Macro to make receiving ZAP frames simpler
#define ZAP_RECV(dest) { \
    rc = zmq_recv(zap_ctx->socket, dest, 255, 0); \
    if(rc == -1) { \
        LOG_ZMQ_ERROR("Failed to receive ZAP frame"); \
        continue; \
    } \
}

// Macro to make sending ZAP responses simpler
#define ZAP_SEND(msg, send_more) { \
    rc = zmq_send(zap_ctx->socket, msg, strlen(msg), send_more); \
    if(rc == -1) { \
        LOG_ZMQ_ERROR("Failed sending ZAP response"); \
        continue; \
    } \
}

static void* zap_run(void* vargs) {
    zap_ctx_t* zap_ctx = (zap_ctx_t*) vargs;
    bool keep_running = true;
    bool accepted = false;
    int rc = 0;
    int ind = 0;
    size_t curve_len = strlen(ZAP_CURVE);
    zmq_pollitem_t poll_items[] = {{ zap_ctx->socket, 0, ZMQ_POLLIN, 0 }};

    // ZAP fields (All fields have a max size of 255, see ZAP spec)
    char version[255];
    char request_id[255];
    char domain[255];
    char address[255];
    char identity[255];
    char mechanism[255];
    uint8_t client_public_key[32];
    char encoded_key[41];

    LOG_DEBUG_0("ZeroMQ ZAP thread started");

    // Using while(true) here so inner code block can utilize continue and
    // still exit promptly when ZMQ protocol context is destroyed
    while(true) {
        // Check if the thread should stop
        if(pthread_mutex_lock(&zap_ctx->mtx_stop) != 0) {
            LOG_DEBUG_0("Unable to lock mutex...");
        }
        keep_running = !zap_ctx->stop;
        if(pthread_mutex_unlock(&zap_ctx->mtx_stop) != 0) {
            LOG_DEBUG_0("Unable to unlock mutex...");
        }

        if(!keep_running)
            break;

        // Poll for poll_items
        zmq_poll(poll_items, 1, 1000);

        if(!(poll_items[0].revents & ZMQ_POLLIN))
            continue;

        // Receive all ZAP request fields
        ZAP_RECV(version);
        ZAP_RECV(request_id);
        ZAP_RECV(domain);
        ZAP_RECV(address);
        ZAP_RECV(identity);
        ZAP_RECV(mechanism);

        LOG_DEBUG(
            "ZAP REQUEST:\n"
            "\tVERSION...: %s\n"
            "\tREQUEST ID: %s\n"
            "\tDOMAIN....: %s\n"
            "\tADDRESS...: %s\n"
            "\tIDENTITY..: %s\n"
            "\tMECHANISM.: %s\n",
            version, request_id, domain, address, identity, mechanism);

        // Verify that the mechanism is "CURVE" and not NULL nor PLAIN
        strcmp_s(mechanism, curve_len, ZAP_CURVE, &ind);
        if(ind != 0) {
            LOG_WARN("Received ZAP request with non CURVE mechanism: %s",
                       mechanism);
            continue;
        }

        // Receive the client's public key
        ZAP_RECV(client_public_key);
        zmq_z85_encode(encoded_key, client_public_key, 32);

        // TODO: This NEEDs to be optimized by using a hashmap rather than
        // traversing an array each time
        for(int i = 0; i < zap_ctx->num_allowed_clients; i++) {
            strcmp_s(encoded_key, strlen(encoded_key),
                    zap_ctx->allowed_clients[i], &ind);
            if(ind == 0) {
                accepted = true;
                break;
            }
        }

#ifdef DEBUG
        if(accepted) {
            LOG_DEBUG_0("Client authentication successful");
        } else {
            LOG_DEBUG_0("Client authentication denied");
        }
#endif

        // Send authentication response
        ZAP_SEND("1.0", ZMQ_SNDMORE);      // Version
        ZAP_SEND(request_id, ZMQ_SNDMORE); // Request ID
        ZAP_SEND(accepted ? "200" : "400", ZMQ_SNDMORE); // Accepted
        ZAP_SEND("", ZMQ_SNDMORE);         // Status text
        ZAP_SEND("", ZMQ_SNDMORE);         // User ID
        ZAP_SEND("", 0);                   // Meta data
    }

    return NULL;
}

void zap_destroy(zap_ctx_t* zap_ctx) {
    LOG_DEBUG_0("Destroying ZAP thread");

    // Set stop flag
    if(pthread_mutex_lock(&zap_ctx->mtx_stop) != 0) {
        LOG_DEBUG_0("Unable to lock mutex");
    }

    zap_ctx->stop = true;
    if(pthread_mutex_unlock(&zap_ctx->mtx_stop) != 0) {
        LOG_DEBUG_0("Unable to unlock mutex");
    }

    // Join with the ZAP thread
    LOG_DEBUG_0("Waiting for ZAP thread to join");
    pthread_join(zap_ctx->th, NULL);

    // Destroy mutex
    if(pthread_mutex_destroy(&zap_ctx->mtx_stop) != 0) {
        LOG_DEBUG_0("Unable to destroy mutex");
    }


    // Close ZeroMQ socket
    zmq_close(zap_ctx->socket);

    // Destroy config value
    for(int i = 0; i < zap_ctx->num_allowed_clients; i++) {
        free(zap_ctx->allowed_clients[i]);
    }
    free(zap_ctx->allowed_clients);

    // Final free
    free(zap_ctx);
}

int zap_initialize(void* zmq_ctx, config_t* config, zap_ctx_t** zap_ctx) {
    zap_ctx_t* ctx = NULL;
    void* socket = NULL;
    int rc = 0;

    // Get configuration value for the allowed clients
    config_value_t* obj = config->get_config_value(
            config->cfg, ZMQ_CFG_TCP_ALLOWED_CLIENTS);
    if(obj == NULL) {
        LOG_WARN_0("Running ZeroMQ TCP sockets without ZAP authentication");
        rc = -2;
        goto err;
    }

    if(obj->type != CVT_ARRAY) {
        LOG_ERROR("ZeroMQ config '%s' must be a list of strings",
                  ZMQ_CFG_TCP_ALLOWED_CLIENTS);
        goto err;
    }

    // Initialize ZeroMQ socket
    socket = zmq_socket(zmq_ctx, ZMQ_REP);
    if(socket == NULL) {
        LOG_ZMQ_ERROR("Error opening ZAP ZeroMQ socket");
        rc = -1;
        goto err;
    }

    // Binding socket
    rc = zmq_bind(socket, ZAP_URI);
    if(rc != 0) {
        LOG_ZMQ_ERROR("Failed to bind to ZAP URI");
        rc = -1;
        goto err;
    }

    ctx = (zap_ctx_t*) malloc(sizeof(zap_ctx_t));
    if(ctx == NULL) {
        LOG_ERROR_0("Out of memory initializing ZAP thread");
        rc = -1;
        goto err;
    }

    ctx->socket = socket;
    ctx->allowed_clients = NULL;
    ctx->stop = false;

    // Copy over the allowed cients
    config_value_array_t* arr = obj->body.array;
    size_t len = arr->length;
    ctx->allowed_clients = (char**) malloc(sizeof(char*) * len);
    if(ctx->allowed_clients == NULL) {
        LOG_ERROR_0("Out of memory initializing ZAP allowed clients");
        goto err;
    }
    ctx->num_allowed_clients= len;
    // Initialize all char's
    for(int i = 0; i < len; i++) {
        ctx->allowed_clients[i] = (char*) malloc(sizeof(char) * 41);
        if(ctx->allowed_clients[i] == NULL) {
            LOG_ERROR_0("Out of memory intiailizing ZAP allowed clients");
            goto err;
        }
    }

    // TODO: Make this a hashmap in the future for efficient key lookup
    for(int i = 0; i < len; i++) {
        config_value_t* cvt_key = arr->get(arr->array, i);
        if(cvt_key == NULL) {
            LOG_ERROR_0("Failed to get array element");
            goto err;
        } else if(cvt_key->type != CVT_STRING) {
            LOG_ERROR_0("All allowed keys must be strings");
            config_value_destroy(cvt_key);
            goto err;
        } else if(!verify_key_len(cvt_key->body.string)) {
            LOG_ERROR_0("Incorrect key length, must be 40 characters");
            config_value_destroy(cvt_key);
            goto err;
        }

        // Copy over the string
        memcpy_s(ctx->allowed_clients[i], 40, cvt_key->body.string, 40);
        ctx->allowed_clients[i][40] = '\0';
        config_value_destroy(cvt_key);
    }

    pthread_mutex_init(&ctx->mtx_stop, NULL);
    pthread_create(&ctx->th, NULL, zap_run, (void*) ctx);

    config_value_destroy(obj);

    *zap_ctx = ctx;

    return rc;
err:
    if(obj != NULL)
        config_value_destroy(obj);
    if(ctx != NULL) {
        if(ctx->allowed_clients != NULL) {
            for(int i = 0; i < ctx->num_allowed_clients; i++) {
                free(ctx->allowed_clients[i]);
            }
            free(ctx->allowed_clients);
        }
        free(ctx);
    }
    if(socket != NULL)
        zmq_close(socket);
    *zap_ctx = NULL;
    return rc;
}
