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
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

/**
 * @brief Message bus GTests unit tests
 * @author Kevin Midkiff (kevin.midkiff@intel.com)
 */

// Enable use of timeit utility
#define WITH_TIMEIT

#include <gtest/gtest.h>
#include "eis/msgbus/msgbus.h"
#include "eis/msgbus/logger.h"
#include "eis/msgbus/timeit.h"
#include "eis/msgbus/zmq.h"
#include "eis/utils/json_config.h"

#define PUB_SUB_TOPIC "unittest-pubsub"
#define SERVICE_NAME  "unittest-service"

#define IPC_CONFIG "./ipc_unittest_config.json"
#define TCP_CONFIG "./tcp_unittest_config.json"

#define TEST_BLOB "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"

// Global flag for using TCP communication
bool g_use_tcp;

/**
 * Helper to create the config_t object.
 */
config_t* create_config() {
    if(g_use_tcp)
        return json_config_new(TCP_CONFIG);
    else
        return json_config_new(IPC_CONFIG);
}

/**
 * Simple initialization and destruction test
 */
TEST(msgbus_test, msgbus_init_test) {
    config_t* config = create_config();
    void* ctx = msgbus_initialize(config);
    if(ctx == NULL) {
        FAIL() << "Init failed";
    }
    msgbus_destroy(ctx);
}

/**
 * Test publishing a blob message
 */
TEST(msgbus_test, msgbus_publish_blob) {
    config_t* config = create_config();
    void* ctx = msgbus_initialize(config);
    if(ctx == NULL) {
        FAIL() << "Init failed";
    }

    // Initailizing message
    char* blob = (char*) malloc(sizeof(char) * 10);
    memcpy(blob, TEST_BLOB, 10);
    msg_envelope_elem_body_t* data = msgbus_msg_envelope_new_blob(blob, 10);

    msg_envelope_t* msg = msgbus_msg_envelope_new(CT_BLOB);

    msgbus_ret_t ret = msgbus_msg_envelope_put(msg, NULL, data);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to put element";

    // Creating publisher
    publisher_ctx_t* pub_ctx = NULL;
    ret = msgbus_publisher_new(ctx, PUB_SUB_TOPIC, &pub_ctx);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to create publisher";

    // Creating subscriber
    recv_ctx_t* sub_ctx = NULL;
    ret = msgbus_subscriber_new(ctx, PUB_SUB_TOPIC, NULL, &sub_ctx);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to create subscriber";

    // Allow subscriber time to initialize and connect
    sleep(1);

    ret = msgbus_publisher_publish(ctx, pub_ctx, msg);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to publish message";

    // Allow time for publication to be received
    msg_envelope_t* received = NULL;
    ret = msgbus_recv_wait(ctx, sub_ctx, &received);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to recv message";

    // Verify message
    ASSERT_EQ(received->content_type, msg->content_type);

    msg_envelope_elem_body_t* data_get = NULL;
    ret = msgbus_msg_envelope_get(received, NULL, &data_get);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to get data from msg envelope";
    ASSERT_EQ(data_get->type, MSG_ENV_DT_BLOB) << "Incorrect data type";
    ASSERT_EQ(data_get->body.blob->len, 10) << "Incorrect length";

    // Verify that each byte is correct
    for(int i = 0; i < 10; i++) {
        ASSERT_EQ(data_get->body.blob->data[i], TEST_BLOB[i]);
    }

    // Clean up
    msgbus_msg_envelope_destroy(received);
    msgbus_msg_envelope_destroy(msg);
    msgbus_publisher_destroy(ctx, pub_ctx);
    msgbus_recv_ctx_destroy(ctx, sub_ctx);
    msgbus_destroy(ctx);
}

/**
 * Test publishing JSON message
 */
TEST(msgbus_test, msgbus_publish_json) {
    config_t* config = create_config();
    void* ctx = msgbus_initialize(config);
    if(ctx == NULL) {
        FAIL() << "Init failed";
    }

    // Initailizing message
    char* data = (char*) malloc(sizeof(char) * 10);
    memcpy(data, TEST_BLOB, 10);
    msg_envelope_elem_body_t* blob = msgbus_msg_envelope_new_blob(data, 10);

    msg_envelope_elem_body_t* integer = (msg_envelope_elem_body_t*) malloc(
            sizeof(msg_envelope_elem_body_t));
    integer->type = MSG_ENV_DT_INT;
    integer->body.integer = 42;

    msg_envelope_elem_body_t* floating = (msg_envelope_elem_body_t*) malloc(
            sizeof(msg_envelope_elem_body_t));
    floating->type = MSG_ENV_DT_FLOATING;
    floating->body.floating = 55.5;

    msg_envelope_t* msg = msgbus_msg_envelope_new(CT_JSON);

    msgbus_ret_t ret = msgbus_msg_envelope_put(msg, "hello", integer);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to put element";

    ret = msgbus_msg_envelope_put(msg, "world", floating);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to put element";

    ret = msgbus_msg_envelope_put(msg, NULL, blob);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to put element";

    // Creating publisher
    publisher_ctx_t* pub_ctx = NULL;
    ret = msgbus_publisher_new(ctx, PUB_SUB_TOPIC, &pub_ctx);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to create publisher";

    // Creating subscriber
    recv_ctx_t* sub_ctx = NULL;
    ret = msgbus_subscriber_new(ctx, PUB_SUB_TOPIC, NULL, &sub_ctx);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to create subscriber";

    // Allow subscriber time to initialize and connect
    sleep(1);

    ret = msgbus_publisher_publish(ctx, pub_ctx, msg);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to publish message";

    // Allow time for publication to be received
    msg_envelope_t* received = NULL;
    ret = msgbus_recv_wait(ctx, sub_ctx, &received);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to recv message";

    // Verify message
    ASSERT_EQ(received->content_type, msg->content_type);

    msg_envelope_elem_body_t* data_get = NULL;
    ret = msgbus_msg_envelope_get(received, "hello", &data_get);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to get integer from msg envelope";
    ASSERT_EQ(data_get->type, MSG_ENV_DT_INT) << "Incorrect data type";
    ASSERT_EQ(data_get->body.integer, 42);

    data_get = NULL;
    ret = msgbus_msg_envelope_get(received, "world", &data_get);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to get floating from msg envelope";
    ASSERT_EQ(data_get->type, MSG_ENV_DT_FLOATING) << "Incorrect data type";
    ASSERT_EQ(data_get->body.floating, 55.5);

    data_get = NULL;
    ret = msgbus_msg_envelope_get(received, NULL, &data_get);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to get floating from msg envelope";
    ASSERT_EQ(data_get->type, MSG_ENV_DT_BLOB) << "Incorrect data type";
    ASSERT_EQ(data_get->body.blob->len, 10) << "Incorrect length";

    for(int i = 0; i < 10; i++) {
        ASSERT_EQ(data_get->body.blob->data[i], TEST_BLOB[i]);
    }

    // Clean up
    msgbus_msg_envelope_destroy(received);
    msgbus_msg_envelope_destroy(msg);
    msgbus_publisher_destroy(ctx, pub_ctx);
    msgbus_recv_ctx_destroy(ctx, sub_ctx);
    msgbus_destroy(ctx);
}

/**
 * Test publishing a blob message with a receive timeout
 */
TEST(msgbus_test, msgbus_publish_blob_timedwait) {
    config_t* config = create_config();
    void* ctx = msgbus_initialize(config);
    if(ctx == NULL) {
        FAIL() << "Init failed";
    }

    // Initailizing message
    char* data = (char*) malloc(sizeof(char) * 10);
    memcpy(data, TEST_BLOB, 10);
    msg_envelope_elem_body_t* blob = msgbus_msg_envelope_new_blob(data, 10);

    msg_envelope_t* msg = msgbus_msg_envelope_new(CT_BLOB);

    msgbus_ret_t ret = msgbus_msg_envelope_put(msg, NULL, blob);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to put element";

    // Creating publisher
    publisher_ctx_t* pub_ctx = NULL;
    ret = msgbus_publisher_new(ctx, PUB_SUB_TOPIC, &pub_ctx);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to create publisher";

    // Creating subscriber
    recv_ctx_t* sub_ctx = NULL;
    ret = msgbus_subscriber_new(ctx, PUB_SUB_TOPIC, NULL, &sub_ctx);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to create subscriber";

    // Allow subscriber time to initialize and connect
    sleep(1);

    ret = msgbus_publisher_publish(ctx, pub_ctx, msg);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to publish message";

    msg_envelope_t* received = NULL;
    ret = msgbus_recv_timedwait(ctx, sub_ctx, 10 * 1000, &received);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to recv message";

    // Verify message
    ASSERT_EQ(received->content_type, msg->content_type);

    msg_envelope_elem_body_t* data_get = NULL;
    ret = msgbus_msg_envelope_get(received, NULL, &data_get);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to get data from msg envelope";
    ASSERT_EQ(data_get->type, MSG_ENV_DT_BLOB);
    ASSERT_EQ(data_get->type, MSG_ENV_DT_BLOB) << "Incorrect data type";
    ASSERT_EQ(data_get->body.blob->len, 10) << "Incorrect length";

    // Verify that each byte is correct
    for(int i = 0; i < 10; i++) {
        ASSERT_EQ(data_get->body.blob->data[i], TEST_BLOB[i]);
    }

    // Clean up
    msgbus_msg_envelope_destroy(received);
    msgbus_msg_envelope_destroy(msg);
    msgbus_publisher_destroy(ctx, pub_ctx);
    msgbus_recv_ctx_destroy(ctx, sub_ctx);
    msgbus_destroy(ctx);
}

/**
 * Test publishing a blob message with a receive timeout, must trigger the
 * timeout
 */
TEST(msgbus_test, msgbus_publish_blob_timedwait_timeout) {
    config_t* config = create_config();
    void* ctx = msgbus_initialize(config);
    if(ctx == NULL) {
        FAIL() << "Init failed";
    }

    // Creating publisher (need something that binds)
    publisher_ctx_t* pub_ctx = NULL;
    msgbus_ret_t ret = msgbus_publisher_new(ctx, PUB_SUB_TOPIC, &pub_ctx);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to create publisher";

    // Creating subscriber
    recv_ctx_t* sub_ctx = NULL;
    ret = msgbus_subscriber_new(
            ctx, PUB_SUB_TOPIC, NULL, &sub_ctx);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to create subscriber";

    msg_envelope_t* received = NULL;
    ret = msgbus_recv_timedwait(ctx, sub_ctx, 100, &received);
    ASSERT_EQ(ret, MSG_RECV_NO_MESSAGE) << "Should not have received msg";

    // Clean up
    msgbus_publisher_destroy(ctx, pub_ctx);
    msgbus_recv_ctx_destroy(ctx, sub_ctx);
    msgbus_destroy(ctx);
}

/**
 * Test request/response
 */
TEST(msgbus_test, msgbus_request_response) {
    config_t* config = create_config();
    void* ctx = msgbus_initialize(config);
    if(ctx == NULL) {
        FAIL() << "Init failed";
    }

    // Initailizing message
    char* data = (char*) malloc(sizeof(char) * 10);
    memcpy(data, TEST_BLOB, 10);
    msg_envelope_elem_body_t* blob = msgbus_msg_envelope_new_blob(data, 10);

    msg_envelope_t* msg = msgbus_msg_envelope_new(CT_BLOB);

    msgbus_ret_t ret = msgbus_msg_envelope_put(msg, NULL, blob);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to put element";

    // Create service to receive requests
    LOG_INFO_0("Creating service context");
    recv_ctx_t* service_resp_ctx = NULL;
    ret = msgbus_service_new(ctx, SERVICE_NAME, NULL, &service_resp_ctx);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to initalize service";

    // Get service to issue request on
    LOG_INFO_0("Creating service request context");
    recv_ctx_t* service_req_ctx = NULL;
    ret = msgbus_service_get(ctx, SERVICE_NAME, NULL, &service_req_ctx);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to initalize service to issue req";

    // Issue request
    ret = msgbus_request(ctx, service_req_ctx, msg);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to issue request";

    // Receive request
    msg_envelope_t* received = NULL;
    ret = msgbus_recv_wait(ctx, service_resp_ctx, &received);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to recv request";

    // Verify message
    ASSERT_EQ(received->content_type, msg->content_type);

    msg_envelope_elem_body_t* data_get = NULL;
    ret = msgbus_msg_envelope_get(received, NULL, &data_get);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to get data from msg envelope";
    ASSERT_EQ(data_get->type, MSG_ENV_DT_BLOB) << "Incorrect data type";
    ASSERT_EQ(data_get->body.blob->len, 10) << "Incorrect length";

    // Verify that each byte is correct
    for(int i = 0; i < 10; i++) {
        ASSERT_EQ(data_get->body.blob->data[i], TEST_BLOB[i]);
    }

    // Issue response
    ret = msgbus_response(ctx, service_resp_ctx, received);

    // Receive request
    msg_envelope_t* response = NULL;
    ret = msgbus_recv_wait(ctx, service_req_ctx, &response);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to recv response";

    // Verify message
    ASSERT_EQ(response->content_type, msg->content_type);

    data_get = NULL;
    ret = msgbus_msg_envelope_get(response, NULL, &data_get);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to get data from msg envelope";
    ASSERT_EQ(data_get->type, MSG_ENV_DT_BLOB) << "Incorrect data type";
    ASSERT_EQ(data_get->body.blob->len, 10) << "Incorrect length";

    // Verify that each byte is correct
    for(int i = 0; i < 10; i++) {
        ASSERT_EQ(data_get->body.blob->data[i], TEST_BLOB[i]);
    }

    // Clean up
    msgbus_msg_envelope_destroy(msg);
    msgbus_msg_envelope_destroy(received);
    msgbus_msg_envelope_destroy(response);

    msgbus_recv_ctx_destroy(ctx, service_resp_ctx);
    msgbus_recv_ctx_destroy(ctx, service_req_ctx);

    msgbus_destroy(ctx);
}

/**
 * Overridden GTest main method
 */
GTEST_API_ int main(int argc, char** argv) {
    // Parse out gTest command line parameters
    ::testing::InitGoogleTest(&argc, argv);

    if(argc == 2) {
        if(strcmp(argv[1], "--tcp") == 0) {
            LOG_INFO_0("Running msgbus tests over TCP");
            g_use_tcp = true;
        } else {
            LOG_ERROR("Unknown parameter: %s", argv[1]);
            return -1;
        }
    } else {
        LOG_INFO_0("Running msgbus tests over IPC");
        g_use_tcp = false;
    }

    return RUN_ALL_TESTS();
}
