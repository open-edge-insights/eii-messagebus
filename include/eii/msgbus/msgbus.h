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
 * @brief Messaging abstraction interface
 * @author Kevin Midkiff <kevin.midkiff@intel.com>
 */

#ifndef _EII_MESSAGE_BUS_H
#define _EII_MESSAGE_BUS_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <eii/utils/config.h>
#include <eii/msgbus/msg_envelope.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Request user data type
 */
typedef struct {
    void* data;
    void (*free)(void* data);
} user_data_t;

/**
 * Receive context structure used for service, subscription, and request
 * contexts.
 */
typedef struct {
    void* ctx;
    user_data_t* user_data;
} recv_ctx_t;

/**
 * Set of receive context to be used with `msgbus_recv_ready_poll()` method.
 */
typedef struct {
    int size;
    int max_size;
    bool* tbl_ready;
    recv_ctx_t** tbl_ctxs;
} recv_ctx_set_t;

/**
 * Publisher context
 */
typedef void* publisher_ctx_t;

/**
 * Initialize the message bus.
 *
 * \note{The message bus context takes ownership of the config_t object at this
 * point and the caller does not have to free the config object.}
 *
 * @param config - Configuration object
 * @return Message bus context, or NULL
 */
void* msgbus_initialize(config_t* config);

/**
 * Delete and clean up the message bus.
 */
void msgbus_destroy(void* ctx);

/**
 * Create a new publisher context object.
 *
 * \note The `get_config_value()` method for the configuration will be called
 *  to retrieve values needed for the underlying protocol to initialize the
 *  context for publishing.
 *
 * \note This method is not necessarily thread-safe. Calls to this method
 *  should either all be done from the same thread or surrounded by a lock.
 *
 * @param[in]  ctx     - Message bus context
 * @param[out] pub_ctx - Publisher context
 * @return msgbus_ret_t
 */
msgbus_ret_t msgbus_publisher_new(
        void* ctx, const char* topic, publisher_ctx_t** pub_ctx);

/**
 * Publish a message on the message bus.
 *
 * @param ctx     - Message bus context
 * @param pub_ctx - Publisher context
 * @param message - Messsage object to publish
 * @return msgbus_ret_t
 */
msgbus_ret_t msgbus_publisher_publish(
        void* ctx, publisher_ctx_t* pub_ctx, msg_envelope_t* message);

/**
 * Destroy publisher
 *
 * @param ctx     - Message bus context
 * @param pub_ctx - Publisher context
 */
void msgbus_publisher_destroy(void* ctx, publisher_ctx_t* pub_ctx);

/**
 * Subscribe to the given topic.
 *
 * \note This method is not necessarily thread-safe. Calls to this method
 *  should either all be done from the same thread or surrounded by a lock.
 *
 * @param[in]  ctx        - Message bus context
 * @param[in]  topic      - Subscription topic string
 * @param[in]  user_data  - User data attached to the receive context
 * @param[out] subscriber - Resulting subscription context
 * @return msgbus_ret_t
 */
msgbus_ret_t msgbus_subscriber_new(
        void* ctx, const char* topic, user_data_t* user_data,
        recv_ctx_t** subscriber);

/**
 * Delete and clean up a service, request, or subscriber context.
 *
 * @param ctx        - Message bus context
 * @param recv_ctx   - Receive context
 */
void msgbus_recv_ctx_destroy(void* ctx, recv_ctx_t* recv_ctx);

/**
 * Issue a request over the message bus.
 *
 * @param ctx          Message bus context
 * @param service_ctx  Service context
 * @param message      Request
 * @return msgbus_ret_t
 */
msgbus_ret_t msgbus_request(
        void* ctx, recv_ctx_t* service_ctx, msg_envelope_t* message);

/**
 * Respond to the given request.
 *
 * @param ctx         - Message bus context
 * @param service_ctx - Service context
 * @param message     - Response message
 * @return msgbus_ret_t
 */
msgbus_ret_t msgbus_response(
        void* ctx, recv_ctx_t* service_ctx, msg_envelope_t* message);

/**
 * Create a context to send requests to a service.
 *
 * \note This method is not necessarily thread-safe. Calls to this method
 *  should either all be done from the same thread or surrounded by a lock.
 *
 * @param[in]  ctx          - Message bus context
 * @param[in]  service_name - Name of the service
 * @param[in]  user_data    - User data
 * @param[out] service_ctx  - Service context
 * @param msgbus_ret_t
 */
msgbus_ret_t msgbus_service_get(
        void* ctx, const char* service_name, void* user_data,
        recv_ctx_t** service_ctx);

/**
 * Create context to receive requests over the message bus.
 *
 * \note This method is not necessarily thread-safe. Calls to this method
 *  should either all be done from the same thread or surrounded by a lock.
 *
 * @param[in]  ctx          - Message bus context
 * @param[in]  service_name - Name of the service
 * @param[in]  user_data    - User data
 * @param[out] service_ctx  - Service context
 * @return msgbus_ret_t
 */
msgbus_ret_t msgbus_service_new(
        void* ctx, const char* service_name, void* user_data,
        recv_ctx_t** service_ctx);

/**
 * Receive a message over the message bus using the given receiving context.
 *
 * \note{If a response has already been received for a given request, then a
 *   MSG_ERR_ALREADY_RECEIVED will be returned.}
 *
 * @param[in]  ctx      - Message bus context
 * @param[in]  recv_ctx - Context to use when receiving a message
 * @param[out] message  - Message received (if one exists)
 * @return msgbus_ret_t
 */
msgbus_ret_t msgbus_recv_wait(
        void* ctx, recv_ctx_t* recv_ctx, msg_envelope_t** message);

/**
 * Receive a message over the message bus, if no message is available wait for
 * the given amount of time for a message to arrive.
 *
 * @param[in]  ctx      - Message bus context
 * @param[in]  recv_ctx - Receive context
 * @param[in]  timeout  - Timeout for waiting to receive a message in
 *                        milliseconds
 * @param[out] message  - Received message, NULL if timedout
 * @return msgbus_ret_t, MSG_RECV_NO_MESSAGE if no message received
 */
msgbus_ret_t msgbus_recv_timedwait(
        void* ctx, recv_ctx_t* recv_ctx, int timeout,
        msg_envelope_t** message);

/**
 * Receive a message if available, immediately return if there are no messages
 * available.
 *
 * @param[in]  ctx      - Message bus context
 * @param[in]  recv_ctx - Receive context
 * @param[out] message  - Received message, NULL if timedout
 * @return msgbus_ret_t, MSG_RECV_NO_MESSAGE if no message is available
 */
msgbus_ret_t msgbus_recv_nowait(
        void* ctx, recv_ctx_t* recv_ctx, msg_envelope_t** message);

#ifdef __cplusplus
} // extern "C"
#endif // __cpluspplus

#endif // _EII_MESSAGE_BUS_H
