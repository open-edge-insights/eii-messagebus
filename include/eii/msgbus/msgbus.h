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

#ifndef _EIS_MESSAGE_BUS_H
#define _EIS_MESSAGE_BUS_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Return type for messaging actions.
 */
typedef enum {
    MSG_SUCCESS = 0,
    MSG_ERR_PUB_FAILED = 1,
    MSG_ERR_SUB_FAILED = 2,
    MSG_ERR_RESP_FAILED = 3,
    MSG_ERR_RECV_FAILED = 4,
    MSG_ERR_RECV_EMPTY = 5,
    MSG_ERR_ALREADY_RECEIVED = 6,
    MSG_ERR_NO_SUCH_SERVICE = 7,
    MSG_ERR_SERVICE_ALREADY_EXIST = 8,
    MSG_ERR_BUS_CONTEXT_DESTROYED = 9,
    MSG_ERR_INIT_FAILED = 10,
    MSG_ERR_NO_MEMORY = 11,
    MSG_ERR_ELEM_NOT_EXIST = 12,
    MSG_ERR_ELEM_ALREADY_EXISTS = 13,
    MSG_ERR_ELEM_BLOB_ALREADY_SET = 14,
    MSG_ERR_ELEM_BLOB_MALFORMED = 15,
    MSG_RECV_NO_MESSAGE = 16,
    MSG_ERR_SERVICE_INIT_FAILED = 17,
    MSG_ERR_REQ_FAILED = 18,
    MSG_ERR_EINTR = 19,
    MSG_ERR_MSG_SEND_FAILED = 20,
    MSG_ERR_DISCONNECTED = 21,
    MSG_ERR_AUTH_FAILED = 22,
    MSG_ERR_UNKNOWN = 255,
} msgbus_ret_t;

/**
 * Valid configuration value types
 */
typedef enum {
    CVT_INTEGER  = 0,
    CVT_FLOATING = 1,
    CVT_STRING   = 2,
    CVT_BOOLEAN  = 3,
    CVT_OBJECT   = 4,
    CVT_ARRAY    = 5,
} config_value_type_t;

// Forward declaration of config_value_t struct
typedef struct _config_value config_value_t;

/**
 * Config value object representation. Includes method for freeing the object
 * when the caller that obtained the object is finished with it.
 */
typedef struct {
    void* object;
    void (*free)(void* object);
} config_value_object_t;

/**
 * Config value array representation. Includes methods for getting elements
 * at a given index and for freeing the array.
 */
typedef struct {
    void* array;
    size_t length;
    config_value_t* (*get)(void* array, int idx);
    void (*free)(void* array);
} config_value_array_t;

/**
 * Structure representing a configuration value.
 */
typedef struct _config_value {
    config_value_type_t type;

    union {
        int64_t      integer;
        double       floating;
        char*        string;
        bool         boolean;
        config_value_object_t* object;
        config_value_array_t*  array;
    } body;
} config_value_t;

/**
 * Content types
 */
typedef enum {
    CT_JSON = 0,

    // For custom serialized data by the user (assumed done by the caller of
    // the `msgbus_recv()` prior to calling the method)
    CT_BLOB = 1,

    // TODO: ADD support for CBOR
    // CT_CBOR = 2,
} content_type_t;

/**
 * Message envelope value data types.
 */
typedef enum {
    MSG_ENV_DT_INT      = 0,
    MSG_ENV_DT_FLOATING = 1,
    MSG_ENV_DT_STRING   = 2,
    MSG_ENV_DT_BOOLEAN  = 3,
    MSG_ENV_DT_BLOB     = 4,
} msg_envelope_data_type_t;

/**
 * Shared object structure for message bus data blobs.
 */
typedef struct {
    void* ptr;
    void (*free)(void*);
    bool owned;

    size_t len;
    const char* bytes;
} owned_blob_t;

/**
 * Message envelope blob data type.
 */
typedef struct {
    owned_blob_t* shared;

    uint64_t len;
    const char*    data;
} msg_envelope_blob_t;

/**
 * Message envelope element body type.
 */
typedef struct {
    msg_envelope_data_type_t type;

    union {
        int64_t              integer;
        double               floating;
        char*                string;
        bool                 boolean;
        msg_envelope_blob_t* blob;
    } body;
} msg_envelope_elem_body_t;

/**
 * Message envelope element type.
 */
typedef struct {
    char* key;
    size_t key_len;
    bool in_use;
    msg_envelope_elem_body_t* body;
} msg_envelope_elem_t;

/**
 * Message envelope around a given message that is to be sent or received over
 * the message bus.
 */
typedef struct {
    char* correlation_id;
    content_type_t content_type;
    int size;
    int max_size;

    // Internal tracking for (key, value) pairs
    msg_envelope_elem_t* elems;

    // Internal tracking for blob data
    msg_envelope_elem_body_t* blob;
} msg_envelope_t;

/**
 * Part of a serialized message envelope.
 */
typedef struct {
    owned_blob_t* shared;

    // Convenience values
    size_t len;
    const char* bytes;
} msg_envelope_serialized_part_t;

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
 * Configuration object
 */
typedef struct {
    void* cfg;
    void (*free)(void*);
    config_value_t* (*get_config_value)(const void*,const char*);
} config_t;

/**
 * Create a new configuration object.
 *
 * @param cfg              - Configuration context
 * @param free_fn          - Method to free the configuration context
 * @param get_config_value - Method to retrieve a key from the configuration
 * @return config_t, or NULL if an error occurs
 */
config_t* msgbus_config_new(
        void* cfg, void (*free_fn)(void*),
        config_value_t* (*get_config_value)(const void*,const char*));

/**
 * Destroy the configuration object.
 *
 * @param config - Configuration to destroy
 */
void msgbus_config_destroy(config_t* config);

/**
 * Helper function to create a new config_value_t pointer to the given integer
 * value.
 *
 * @param value - Integer value
 * @return config_value_t*
 */
config_value_t* msgbus_config_value_new_integer(int64_t value);

/**
 * Helper to create a new config_value_t pointer to the given double value.
 *
 * @param value - Floating point value
 * @return config_value_t*
 */
config_value_t* msgbus_config_value_new_floating(double value);

/**
 * Helper function to create a new config_value_t pointer to the given string
 * value.
 *
 * @param value - String value
 * @return config_value_t*
 */
config_value_t* msgbus_config_value_new_string(const char* value);

/**
 * Helper function to create a new config_value_t pointer to the given boolean
 * value.
 *
 * @param value - Boolean value
 * @return config_value_t*
 */
config_value_t* msgbus_config_value_new_boolean(bool value);

/**
 * Helper function to create a new config_value_t pointer to the given
 * configuration object value.
 *
 * @param value    - Object value
 * @param free_fn  - Free method for the object value
 * @return config_value_t*
 */
config_value_t* msgbus_config_value_new_object(
        void* value, void (*free_fn)(void* object));

/**
 * Helper function to create a new config_value_t pointer to the given array
 * value.
 *
 * @param array   - Pointer to array context
 * @param length  - Array length
 * @param get     - Get method for getting an element in the array
 * @param free_fn - Function to free the array object
 * @return config_value_t*
 */
config_value_t* msgbus_config_value_new_array(
        void* array, size_t length, config_value_t* (get)(void*,int),
        void (*free_fn)(void*));

/**
 * Destroy a configuration value.
 *
 * @param value - Configuration value to destroy
 */
void msgbus_config_value_destroy(config_value_t* value);

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
 * \note{The `get_config_value()` method for the configuration will be called
 *  to retrieve values needed for the underlying protocol to initialize the
 *  context for publishing.}
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
 *                        microseconds
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

/**
 * Create a new msg_envelope_t to be sent over the message bus.
 *
 * @param ct      - Content type
 * @return msg_envelope_t, or NULL if an error occurs
 */
msg_envelope_t* msgbus_msg_envelope_new(content_type_t ct);

/**
 * Helper function for creating a new message envelope element containing
 * a string value.
 *
 * @param string - String value to be placed in the envelope element
 * @return msg_envelope_body_t, or NULL if errors occur
 */
msg_envelope_elem_body_t* msgbus_msg_envelope_new_string(const char* string);

/**
 * Helper function for creating a new message envelope element containing
 * an integer value.
 *
 * @param integer - Integer value to be placed in the envelope element
 * @return msg_envelope_body_t, or NULL if errors occur
 */
msg_envelope_elem_body_t* msgbus_msg_envelope_new_integer(int64_t integer);

/**
 * Helper function for creating a new message envelope element containing
 * a floating point value.
 *
 * @param floating - Floating point value to be placed in the envelope element
 * @return msg_envelope_body_t, or NULL if errors occur
 */
msg_envelope_elem_body_t* msgbus_msg_envelope_new_floating(double floating);

/**
 * Helper function for creating a new message envelope element containing
 * a boolean value.
 *
 * @param boolean - Boolean value to be placed in the envelope element
 * @return msg_envelope_body_t, or NULL if errors occur
 */
msg_envelope_elem_body_t* msgbus_msg_envelope_new_bool(bool boolean);

/**
 * Helper function for creating a new message envelope element containing
 * a data blob.
 *
 * \note The enevelope element takes ownership of releasing the data.
 *
 * @param blob - Blob data to be placed in the envelope element
 * @param len  - Size of the data blob
 * @return msg_envelope_body_t, or NULL if errors occur
 */
msg_envelope_elem_body_t* msgbus_msg_envelope_new_blob(
        char* data, size_t len);

/**
 * Helper function to destroy a message envelope element.
 *
 * @param elem - Element to destroy
 */
void msgbus_msg_envelope_elem_destroy(msg_envelope_elem_body_t* elem);

/**
 * Add (key, value) pair to the message envelope.
 *
 * \note{If the message envelope is set to be a `CT_BLOB`, then it will act
 *  differently than a message set to a different content type. For a blob the
 *  data can only be set once for the message and the key value will be ignored
 *  and the key `BLOB` will be used. Additionally, the value body must be a
 *  blob as well.}
 *
 * @param env  - Message envelope
 * @param key  - Key for the value
 * @param data - Value to be added
 * @return msgbus_ret_t
 */
msgbus_ret_t msgbus_msg_envelope_put(
        msg_envelope_t* env, const char* key, msg_envelope_elem_body_t* data);

/**
 * Remove the (key, value) pair with the given key.
 *
 * @param env - Message envelope
 * @param key - Key to remove
 * @return msgbus_ret_t
 */
msgbus_ret_t msgbus_msg_envelope_remove(msg_envelope_t* env, const char* key);

/**
 * Get the value for the given key in the message bus.
 *
 * \note{If the content type is `CT_BLOB`, then use "BLOB" as the key to
 *  retrieve the blob data.}
 *
 * @param[in]  env  - Message envelope
 * @param[in]  key  - Key for the element to find
 * @param[out] data - Data for the key
 * @return msgbus_ret_t
 */
msgbus_ret_t msgbus_msg_envelope_get(
        msg_envelope_t* env, const char* key, msg_envelope_elem_body_t** data);

/**
 * Serialize the data in the envelope into the given message parts buffer based
 * on the content type given when msgbus_msg_envelope_new() was called.
 *
 * @param[in]  env   - Message envelope
 * @param[out] parts - Serialized parts
 * @return Number of serialized message parts
 */
int msgbus_msg_envelope_serialize(
        msg_envelope_t* env, msg_envelope_serialized_part_t** parts);

/**
 * Deserialize the given data into a msg_envelope_t.
 *
 * If the content type is set to CT_BLOB, then this method assumes that there
 * will only be one serialized message part.
 *
 * Additionally, if the content type is CT_JSON, then this method assumes that
 * there will be either one or two message parts. The first part MUST always
 * be a JSON string. If a second part is present it MUST be a binary blob of
 * data.
 *
 * @param[in]  ct        - Message content type
 * @param[in]  parts     - Serialized parts to deserailize
 * @param[in]  num_parts - Number of message parts
 * @param[out] env       - Output message envelope
 * @return msgbus_ret_t
 */
msgbus_ret_t msgbus_msg_envelope_deserialize(
        content_type_t ct, msg_envelope_serialized_part_t* parts,
        int num_parts, msg_envelope_t** env);

/**
 * Create a new list of serialized message parts.
 *
 * @param[in]  num_parts - Number of serialized message parts
 * @param[out] parts     - Serialzied parts
 * @return msgbus_ret_t
 */
msgbus_ret_t msgbus_msg_envelope_serialize_parts_new(
        int num_parts, msg_envelope_serialized_part_t** parts);

/**
 * Destroy the serialized parts of a message
 *
 * @param parts     - Serialized parts
 * @param num_parts - Number of serialized parts
 * @return msgbus_ret_t
 */
void msgbus_msg_envelope_serialize_destroy(
        msg_envelope_serialized_part_t* parts, int num_parts);

/**
 * Delete and clean up a message envelope structure.
 *
 * @param msg - Message envelope to delete
 */
void msgbus_msg_envelope_destroy(msg_envelope_t* msg);

/**
 * Helper for initializing owned blob pointer.
 *
 * \note Assumes data is owned
 */
owned_blob_t* owned_blob_new(
        void* ptr, void (*free_fn)(void*), const char* data, size_t len);

/**
 * Copy a shared blob, except assume the underlying data is NOT owned by the
 * copy of the blob.
 */
owned_blob_t* owned_blob_copy(owned_blob_t* to_copy);

/**
 * Helper for destroying owned blob pointer.
 */
void owned_blob_destroy(owned_blob_t* shared);

#ifdef __cplusplus
}
#endif

#endif // _EIS_MESSAGE_BUS_H
