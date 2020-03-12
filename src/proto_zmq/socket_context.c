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
 * @brief Internal ZeroMQ socket context utility implementation
 * @author Kevin Midkiff <kevin.midkiff@intel.com>
 */

#include <stdlib.h>
#include <string.h>
#include <safe_lib.h>
#include <eis/utils/logger.h>
// Include libzmq zmq.h
#include <zmq.h>

#include "common.h"
#include "socket_context.h"

//
// Prototypes
//

/**
 * Helper method to generate a random string of the given size (only using
 * caps in this case).
 *
 * @param len - Length of the string to generate
 */
static char* generate_random_str(int len);

zmq_shared_sock_t* shared_sock_new(
        void* zmq_ctx, const char* uri, void* socket, int socket_type) {
    // Verify socket type
    if(socket_type != ZMQ_PUB && socket_type != ZMQ_SUB
            && socket_type != ZMQ_REQ && socket_type != ZMQ_REP) {
        LOG_ERROR_0("Unknown ZeroMQ socket type");
        return NULL;
    }

    char* monitor_uri = NULL;
    zmq_shared_sock_t* shared_sock = (zmq_shared_sock_t*) malloc(
            sizeof(zmq_shared_sock_t));
    if(shared_sock == NULL) {
        LOG_ERROR_0("Out of memory allocating shared socket");
        return NULL;
    }

    shared_sock->socket = socket;
    shared_sock->socket_type = socket_type;
    shared_sock->refcount = 1;
    shared_sock->retries = 0;
    shared_sock->monitor = NULL;
    shared_sock->uri = NULL;
    shared_sock->uri_len = strlen(uri);
    shared_sock->mtx = NULL;

    // Copy URI
    int pthread_init_failed = 0;
    shared_sock->uri = (char*) malloc(
            sizeof(char) * (shared_sock->uri_len + 1));
    if(shared_sock->uri == NULL) {
        LOG_ERROR_0("Out of memory copying URI");
        goto err;
    }
    memcpy_s(shared_sock->uri, shared_sock->uri_len, uri, shared_sock->uri_len);
    shared_sock->uri[shared_sock->uri_len] = '\0';

    // Initialize Mutex
    shared_sock->mtx = (pthread_mutex_t*) malloc(sizeof(pthread_mutex_t));
    if(shared_sock->mtx == NULL) {
        LOG_ERROR_0("Out of memory allocating mutex");
        goto err;
    }

    pthread_init_failed = pthread_mutex_init(shared_sock->mtx, NULL);
    if(pthread_init_failed != 0) {
        LOG_ERROR_0("Failed to initlaize mutex");
        goto err;
    }

    // Initialize monitor
    // Generating random part of string in case there are multiple services
    // or publishers with the same name. There can only be one monitor socket
    // per monitor URI
    char* rand_str = generate_random_str(5);
    if(rand_str == NULL) {
        LOG_ERROR_0("Failed to initialize random string");
        goto err;
    }

    size_t total_len = strlen(rand_str) + 10;
    monitor_uri = concat_s(total_len, 2, "inproc://", rand_str);
    free(rand_str);
    if(monitor_uri == NULL) {
        LOG_ERROR_0("Failed to initialize monotor URI for the new socket");
        goto err;
    }

    LOG_DEBUG("Creating socket monitor for %s", monitor_uri);
    int rc = zmq_socket_monitor(socket, monitor_uri, ZMQ_EVENT_ALL);
    if(rc == -1) {
        // Only an error if the socket has not been bound already, if it has
        // then it is okay
        if(zmq_errno() != EADDRINUSE) {
            LOG_ZMQ_ERROR("Failed creating socket monitor");
            goto err;
        }
    }

    // Create monitor socket
    shared_sock->monitor = zmq_socket(zmq_ctx, ZMQ_PAIR);
    if(shared_sock->monitor == NULL) {
        LOG_ZMQ_ERROR("Failed to create ZMQ_PAIR monitor socket");
        goto err;
    }

    // Connect monitor socket
    LOG_DEBUG_0("Connecting monitor ZMQ socket");
    rc = zmq_connect(shared_sock->monitor, monitor_uri);
    if(rc == -1) {
        LOG_ZMQ_ERROR("Failed to connect to monitor URI");
        goto err;
    }

    free(monitor_uri);

    return shared_sock;
err:
    if(monitor_uri != NULL)
        free(monitor_uri);
    if(shared_sock->uri != NULL)
        free(shared_sock->uri);
    if(shared_sock->mtx != NULL) {
        if(pthread_init_failed == 0) {
            if(pthread_mutex_destroy(shared_sock->mtx) != 0) {
                LOG_ERROR_0("Failed to destory shared socket mutex");
            }
        }
        free(shared_sock->mtx);
    }
    if(shared_sock != NULL)
        free(shared_sock);
    return NULL;
}

void shared_sock_incref(zmq_shared_sock_t* shared_sock) {
    if(shared_sock_lock(shared_sock) != 0) {
        LOG_ERROR_0("Failed to obtain mutex");
        return;
    }
    shared_sock->refcount++;
    if(shared_sock_unlock(shared_sock) != 0) {
        LOG_ERROR_0("Failed to unlock mutex");
        return;
    }
}

void shared_sock_decref(zmq_shared_sock_t* shared_sock) {
    if(shared_sock_lock(shared_sock) != 0) {
        LOG_ERROR_0("Failed to obtain mutex");
        return;
    }
    if(shared_sock->refcount > 0) {
        shared_sock->refcount--;
    } else {
        LOG_ERROR_0("shared_sock_decref() called with refcount == 0");
    }
    if(shared_sock_unlock(shared_sock) != 0) {
        LOG_ERROR_0("Failed to unlock mutex");
        return;
    }
}

int shared_sock_lock(zmq_shared_sock_t* shared_sock) {
    return pthread_mutex_lock(shared_sock->mtx);
}

int shared_sock_unlock(zmq_shared_sock_t* shared_sock) {
    return pthread_mutex_unlock(shared_sock->mtx);
}

void shared_sock_retries_incr(zmq_shared_sock_t* shared_sock) {
    if(shared_sock_lock(shared_sock) != 0) {
        LOG_ERROR_0("Failed to obtain mutex");
        return;
    }
    shared_sock->retries++;
    if(shared_sock_unlock(shared_sock) != 0) {
        LOG_ERROR_0("Failed to unlock mutex");
        return;
    }
}

void shared_sock_retries_reset(zmq_shared_sock_t* shared_sock) {
    if(shared_sock_lock(shared_sock) != 0) {
        LOG_ERROR_0("Failed to obtain mutex");
        return;
    }
    shared_sock->retries = 0;
    if(shared_sock_unlock(shared_sock) != 0) {
        LOG_ERROR_0("Failed to unlock mutex");
        return;
    }
}

void shared_sock_replace(
        zmq_shared_sock_t* shared_sock, void* zmq_ctx, void* socket) {
    // NOTE: This assumes that the lock is already held and that the prior
    // underlying socket has been closed. This is so that the caller can
    // re-bind to the same TCP port if needed.
    char* monitor_uri = NULL;
    shared_sock->socket = socket;

    // Closing old ZeroMQ monitor for the old socket
    close_zero_linger(shared_sock->monitor);

    // Initialize new socket monitor

    // Generating random part of string in case there are multiple services
    // or publishers with the same name. There can only be one monitor socket
    // per monitor URI
    char* rand_str = generate_random_str(5);
    if(rand_str == NULL) {
        LOG_ERROR_0("Failed to initialize random string");
        goto err;
    }

    size_t total_len = strlen(rand_str) + 10;
    monitor_uri = concat_s(total_len, 2, "inproc://", rand_str);
    free(rand_str);
    if(monitor_uri == NULL) {
        LOG_ERROR_0("Failed to initialize monotor URI for the new socket");
        goto err;
    }

    LOG_DEBUG("Creating socket monitor for %s", monitor_uri);
    int rc = zmq_socket_monitor(socket, monitor_uri, ZMQ_EVENT_ALL);
    if(rc == -1) {
        // Only an error if the socket has not been bound already, if it has
        // then it is okay
        if(zmq_errno() != EADDRINUSE) {
            LOG_ZMQ_ERROR("Failed creating socket monitor");
            goto err;
        }
    }

    // Create monitor socket
    shared_sock->monitor = zmq_socket(zmq_ctx, ZMQ_PAIR);
    if(shared_sock->monitor == NULL) {
        LOG_ZMQ_ERROR("Failed to create ZMQ_PAIR monitor socket");
        goto err;
    }

    // Connect monitor socket
    LOG_DEBUG_0("Connecting monitor ZMQ socket");
    rc = zmq_connect(shared_sock->monitor, monitor_uri);
    if(rc == -1) {
        LOG_ZMQ_ERROR("Failed to connect to monitor URI");
        goto err;
    }

    free(monitor_uri);
    return;
err:
    if(monitor_uri != NULL)
        free(monitor_uri);

    return;
}

void shared_sock_destroy(zmq_shared_sock_t* shared_sock) {
    shared_sock_decref(shared_sock);

    LOG_DEBUG("Remaining references: %d", shared_sock->refcount);

    // If the reference count is 0, then destroy the pointer, otherwise do
    // nothing because other references need this data to still exist
    if(shared_sock->refcount == 0) {
        LOG_DEBUG_0("Closing underlying ZMQ socket");

        // NOTE: This way of closing will allow for all pending messages to
        // send before closing the socket
        zmq_close(shared_sock->socket);

        // Destroy the pthread mutex
        if(pthread_mutex_destroy(shared_sock->mtx) != 0) {
            LOG_ERROR_0("Failed to destroy shared socket mutex");
        }
        free(shared_sock->mtx);

        // Free URI
        free(shared_sock->uri);

        // Close monitor socket
        if(shared_sock->monitor != NULL)
            close_zero_linger(shared_sock->monitor);

        // The final free
        free(shared_sock);
    }
}

msgbus_ret_t sock_ctx_new(
        void* zmq_ctx, const char* name, zmq_shared_sock_t* socket,
        zmq_sock_ctx_t** sock_ctx)
{
    LOG_DEBUG("Creating socket context for %s", name);

    zmq_sock_ctx_t* ctx = (zmq_sock_ctx_t*) malloc(sizeof(zmq_sock_ctx_t));
    if(ctx == NULL) { return MSG_ERR_NO_MEMORY; }

    ctx->shared_socket = socket;
    ctx->name_len = strlen(name) + 1;
    ctx->name = (char*) malloc(sizeof(char) * ctx->name_len);
    if(ctx->name == NULL) {
        free(ctx);
        return MSG_ERR_NO_MEMORY;
    }

    memcpy_s(ctx->name, ctx->name_len, name, ctx->name_len);
    ctx->name[ctx->name_len - 1] = '\0';

    *sock_ctx = ctx;

    // Increase the reference count to the underlying shared socket
    shared_sock_incref(socket);

    return MSG_SUCCESS;
}

int sock_ctx_lock(zmq_sock_ctx_t* ctx) {
    return shared_sock_lock(ctx->shared_socket);
}

int sock_ctx_unlock(zmq_sock_ctx_t* ctx) {
    return shared_sock_unlock(ctx->shared_socket);
}

void sock_ctx_retries_incr(zmq_sock_ctx_t* ctx) {
    shared_sock_retries_incr(ctx->shared_socket);
}

void sock_ctx_retries_reset(zmq_sock_ctx_t* ctx) {
    shared_sock_retries_reset(ctx->shared_socket);
}

void sock_ctx_replace(zmq_sock_ctx_t* ctx, void* zmq_ctx, void* socket) {
    shared_sock_replace(ctx->shared_socket, zmq_ctx, socket);
}

void sock_ctx_destroy(zmq_sock_ctx_t* ctx) {
    shared_sock_destroy(ctx->shared_socket);
    if(ctx->name != NULL) { free(ctx->name); }
    free(ctx);
}

static char* generate_random_str(int len) {
    static const char ucase[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    char* str = (char*) malloc(sizeof(char) * (len + 1));
    if(str == NULL) {
        LOG_ERROR_0("Out of memory generating random string");
        return NULL;
    }

    for(int i = 0; i < len; i++) {
        str[i] = ucase[rand() % 26];
    }

    str[len - 1] = '\0';

    return str;
}
