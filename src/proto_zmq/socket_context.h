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
 * @brief Internal ZeroMQ socket context utilities
 * @author Kevin Midkiff <kevin.midkiff@intel.com>
 */

#ifndef _EII_MESSAGE_BUS_ZMQ_SOCK_CTX_H
#define _EII_MESSAGE_BUS_ZMQ_SOCK_CTX_H

#include <stdbool.h>
#include <pthread.h>
#include <eii/msgbus/msgbusret.h>

/**
 * Internal shared socket structure.
 */
typedef struct {
    // Underlying ZeroMQ socket pointer
    void* socket;

    // ZeroMQ socket type (ZMQ_PUB, ZMQ_SUB, ZMQ_REQ, or ZMQ_REP)
    int socket_type;

    // Boolean flag for if the socket is brokered (only applies to ZMQ_PUB)
    bool brokered;

    // Number of references to the shared socket
    int refcount;

    // Number of times the given socket has tried to reconnect
    int retries;

    // inproc socket monitor for the ZeroMQ socket
    void* monitor;

    // URI for the socket
    char* uri;
    size_t uri_len;

    // Mutex for using the socket to provide thread-safety
    pthread_mutex_t* mtx;
} zmq_shared_sock_t;

/**
 * Internal ZeroMQ send context for publications and services.
 *
 * This structure includes primitives for providing thread-safety and shared
 * pointer methods.
 */
typedef struct {
    // Name of the socket context (i.e. topic, service name, etc.)
    char* name;
    size_t name_len;

    // Shared socket for the ZeroMQ socket context
    zmq_shared_sock_t* shared_socket;
} zmq_sock_ctx_t;

/**
 * Create a new shared socket wrapper for the given ZeroMQ socket pointer.
 *
 * \note There should only be one shared socket wrapper per socket.
 *
 * @param zmq_ctx     - ZeroMQ context
 * @param uri         - URI for the socket
 * @param socket      - ZeroMQ socket
 * @param socket_type - ZeroMQ socket type
 * @param brokered    - Whether the socket shall be brokered (only for ZMQ_PUB)
 * @return @c zmq_shared_sock_t, or NULL if an error occurs
 */
zmq_shared_sock_t* shared_sock_new(
        void* zmq_ctx, const char* uri, void* socket, int socket_type,
        bool brokered);

/**
 * Increase the number of references that exist for the given shared socket.
 *
 * @param shared_sock - ZeroMQ shared socket
 */
void shared_sock_incref(zmq_shared_sock_t* shared_sock);

/**
 * Decrease the number of references that exist for the given shared socket.
 *
 * @param shared_sock - ZeroMQ shared socket
 */
void shared_sock_decref(zmq_shared_sock_t* shared_sock);

/**
 * Lock the mutex for the shared socket.
 *
 * @param shared_sock - ZeroMQ shared socket
 */
int shared_sock_lock(zmq_shared_sock_t* shared_sock);

/**
 * Unlock the mutex for the shared socket.
 *
 * @param shared_sock - ZeroMQ shared socket
 */
int shared_sock_unlock(zmq_shared_sock_t* shared_sock);

/**
 * Increment the number of retries that have occured on the socket.
 *
 * @param shared_sock - ZeroMQ shared socket
 */
void shared_sock_retries_incr(zmq_shared_sock_t* shared_sock);

/**
 * Reset the number of retries to zero.
 *
 * @param shared_sock - ZeroMQ shared socket
 */
void shared_sock_retries_reset(zmq_shared_sock_t* shared_sock);

/**
 * Replace the shared socket's underlying ZeroMQ socket with the given socket.
 * It is the job of the caller to close the original socket. Additionally, the
 * lock should be held prior to calling this method, otherwise unknown behavior
 * may occur.
 *
 * @param shared_sock - ZeroMQ shared socket
 * @param zmq_ctx     - ZeroMQ context
 * @param socket      - ZeroMQ socket
 */
void shared_sock_replace(
        zmq_shared_sock_t* shared_sock, void* zmq_ctx, void* socket);

/**
 * Destroy the shared socket.
 *
 * If the reference count is not 0, then this will only decrease the
 * reference count. If the reference count is 0 (after this method
 * decreases the count), then the socket will be closed.
 *
 * @param shared_sock - ZeroMQ shared socket
 */
void shared_sock_destroy(zmq_shared_sock_t* shared_sock);

/**
 * Initialize a new ZMQ socket context structure.
 *
 * @param[in]  zmq_ctx         - ZeroMQ context pointer
 * @param[in]  name            - Service name or topic string
 * @param[in]  shared_socket   - ZeroMQ shared socket
 * @param[out] sock_ctx        - Resulting socket context structure
 * @return @c msgbus_ret_t
 */
msgbus_ret_t sock_ctx_new(
        void* zmq_ctx, const char* name, zmq_shared_sock_t* shared_socket,
        zmq_sock_ctx_t** sock_ctx);

/**
 * Lock socket mutex.
 *
 * @param ctx - ZeroMQ socket context
 */
int sock_ctx_lock(zmq_sock_ctx_t* ctx);

/**
 * Unlock socket mutex.
 *
 * @param ctx - ZeroMQ socket context
 */
int sock_ctx_unlock(zmq_sock_ctx_t* ctx);

/**
 * Increment the number of retries that have occured on the socket.
 *
 * @param ctx - ZeroMQ socket context
 */
void sock_ctx_retries_incr(zmq_sock_ctx_t* ctx);

/**
 * Reset the number of retries to zero.
 *
 * @param ctx - ZeroMQ socket context
 */
void sock_ctx_retries_reset(zmq_sock_ctx_t* ctx);

/**
 * Replace the shared socket's underlying ZeroMQ socket with the given socket.
 * It is the job of the caller to close the original socket. Additionally, the
 * lock should be held prior to calling this method, otherwise unknown behavior
 * may occur.
 *
 * @param ctx     - ZeroMQ socket context
 * @param zmq_ctx - ZeroMQ context
 * @param socket  - ZeroMQ socket
 */
void sock_ctx_replace(zmq_sock_ctx_t* ctx, void* zmq_ctx, void* socket);

/**
 * Destroy the given ZMQ socket context.
 *
 * \note This may result in the closing of the underlying shared socket, if
 *      there are no more references besides this context to the shared socket.
 *
 * @param ctx - ZeroMQ socket context
 */
void sock_ctx_destroy(zmq_sock_ctx_t* ctx);

#endif // _EII_MESSAGE_BUS_ZMQ_SOCK_CTX_H
