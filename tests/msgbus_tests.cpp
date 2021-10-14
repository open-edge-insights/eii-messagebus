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

#include <limits.h>
#include <gtest/gtest.h>
#include <chrono>
#include <thread>
#include <eii/utils/logger.h>
#include <eii/utils/string.h>
#include "eii/msgbus/msgbus.h"
#include "eii/msgbus/msgbus.hpp"
#include "eii/utils/timeit.h"
#include "eii/utils/logger.h"
#include "eii/utils/json_config.h"

#define PUB_SUB_TOPIC "unittest-pubsub"
#define SERVICE_NAME  "unittest-service"
#define LD_PATH_SET   "LD_LIBRARY_PATH="
#define LD_SEP        ":"

#define IPC_CONFIG \
"{" \
    "\"type\": \"zmq_ipc\"," \
    "\"socket_dir\": \"/tmp\"" \
"}"

#define TCP_CONFIG \
"{" \
    "\"type\": \"zmq_tcp\"," \
    "\"zmq_tcp_publish\": {" \
        "\"host\": \"127.0.0.1\"," \
        "\"port\": 5569" \
    "}," \
    "\"unittest-pubsub\": {" \
        "\"host\": \"127.0.0.1\"," \
        "\"port\": 5569" \
    "}," \
    "\"unittest-service\": {" \
        "\"host\": \"127.0.0.1\"," \
        "\"port\": 8675" \
    "}" \
"}"

#define DYN_CONFIG \
"{" \
    "\"type\": \"test-proto\"" \
"}"

#define TEST_BLOB "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"

// Global flag for using TCP communication
bool g_use_tcp;

// Prototypes
static char* update_ld_library_path();

/**
 * Helper to create the config_t object.
 */
static config_t* create_config() {
    if(g_use_tcp)
        return json_config_new_from_buffer(TCP_CONFIG);
    else
        return json_config_new_from_buffer(IPC_CONFIG);
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

TEST(msgbus_test, msgbus_load_proto) {
    // Update the LD_LIBRARY_PATH with the CWD to load the test proto plugin
    char* ld_lib_path = update_ld_library_path();

    // Load JSON configuration
    config_t* config = json_config_new_from_buffer(DYN_CONFIG);
    void* ctx = msgbus_initialize(config);
    if(ctx == NULL)
        FAIL() << "Failed to initlize msgbus";

    recv_ctx_t* recv_ctx;

    // Exercise all msgbus methods to make sure everything was loaded correctly
    msgbus_publisher_new(ctx, "TOPIC", NULL);
    msgbus_publisher_publish(ctx, NULL, NULL);
    msgbus_publisher_destroy(ctx, NULL);

    msgbus_subscriber_new(ctx, "TOPIC", NULL, &recv_ctx);
    msgbus_recv_ctx_destroy(ctx, recv_ctx);
    recv_ctx = NULL;

    msgbus_service_get(ctx, "NAME", NULL, &recv_ctx);
    msgbus_request(ctx, recv_ctx, NULL);
    msgbus_recv_ctx_destroy(ctx, recv_ctx);
    recv_ctx = NULL;

    msgbus_service_new(ctx, "NAME", NULL, &recv_ctx);
    msgbus_response(ctx, recv_ctx, NULL);
    msgbus_recv_wait(ctx, recv_ctx, NULL);
    msgbus_recv_timedwait(ctx, recv_ctx, 0, NULL);
    msgbus_recv_nowait(ctx, recv_ctx, NULL);
    msgbus_recv_ctx_destroy(ctx, recv_ctx);
    recv_ctx = NULL;

    msgbus_destroy(ctx);
    free(ld_lib_path);
}

TEST(msgbus_test, cpp_pubsub_recv) {
    config_t* config = create_config();
    eii::msgbus::MsgbusContext* ctx = new eii::msgbus::MsgbusContext(config);
    eii::msgbus::Publisher* pub = ctx->new_publisher(PUB_SUB_TOPIC);
    eii::msgbus::Subscriber* sub = ctx->new_subscriber(PUB_SUB_TOPIC);

    // Allow subscriber time to initialize and connect
    sleep(1);

    eii::msgbus::MsgEnvelope* msg = new eii::msgbus::MsgEnvelope(CT_JSON);
    msg->put_float("floating", 55.5);
    msg->put_integer("integer", 42);
    msg->put_string("string", "hello, world");

    pub->publish(msg);

    eii::msgbus::MsgEnvelope* recv = sub->recv_wait();

    // TODO(kmidkiff): Verify message envelope...

    delete msg;
    delete recv;
    delete sub;
    delete pub;
    delete ctx;
}

TEST(msgbus_test, cpp_pubsub_recv_nowait) {
    config_t* config = create_config();
    eii::msgbus::MsgbusContext* ctx = new eii::msgbus::MsgbusContext(config);
    eii::msgbus::Publisher* pub = ctx->new_publisher(PUB_SUB_TOPIC);
    eii::msgbus::Subscriber* sub = ctx->new_subscriber(PUB_SUB_TOPIC);

    // Allow subscriber time to initialize and connect
    sleep(1);

    eii::msgbus::MsgEnvelope* msg = new eii::msgbus::MsgEnvelope(CT_JSON);
    msg->put_float("floating", 55.5);
    msg->put_integer("integer", 42);
    msg->put_string("string", "hello, world");

    pub->publish(msg);

    // Give ample time for the message to arrrive
    sleep(1);

    eii::msgbus::MsgEnvelope* recv = sub->recv_nowait();
    if (recv == NULL) {
        FAIL() << "Received NULL message";
    }

    // TODO(kmidkiff): Verify message envelope...

    delete msg;
    delete recv;
    delete sub;
    delete pub;
    delete ctx;
}

TEST(msgbus_test, cpp_pubsub_recv_timedwait) {
    auto timeout = std::chrono::microseconds(500);
    config_t* config = create_config();
    eii::msgbus::MsgbusContext* ctx = new eii::msgbus::MsgbusContext(config);
    eii::msgbus::Publisher* pub = ctx->new_publisher(PUB_SUB_TOPIC);
    eii::msgbus::Subscriber* sub = ctx->new_subscriber(PUB_SUB_TOPIC);

    // Allow subscriber time to initialize and connect
    sleep(1);

    eii::msgbus::MsgEnvelope* msg = new eii::msgbus::MsgEnvelope(CT_JSON);
    msg->put_float("floating", 55.5);
    msg->put_integer("integer", 42);
    msg->put_string("string", "hello, world");

    pub->publish(msg);

    eii::msgbus::MsgEnvelope* recv = sub->recv_timedwait(timeout);
    if (recv == NULL) {
        FAIL() << "Received NULL message";
    }

    // TODO(kmidkiff): Verify message envelope...

    delete recv;

    // Verify that a timeout works correctly
    recv = sub->recv_timedwait(timeout);
    if (recv != NULL) {
        delete recv;
        FAIL() << "Timeout did not occur when it should have";
    }

    delete msg;
    delete sub;
    delete pub;
    delete ctx;
}

TEST(msgbus_test, cpp_reqresp) {
    auto timeout = std::chrono::microseconds(500);
    config_t* config = create_config();
    eii::msgbus::MsgbusContext* ctx = new eii::msgbus::MsgbusContext(config);
    eii::msgbus::Service* service = ctx->new_service(SERVICE_NAME);
    eii::msgbus::ServiceRequester* requester = ctx->get_service(SERVICE_NAME);

    // Allow time for the sockets to initialize (this is probably too long)
    sleep(1);

    eii::msgbus::MsgEnvelope* msg = new eii::msgbus::MsgEnvelope(CT_JSON);
    msg->put_float("floating", 55.5);
    msg->put_integer("integer", 42);
    msg->put_string("string", "hello, world");

    requester->request(msg);

    eii::msgbus::MsgEnvelope* request = service->recv_timedwait(timeout);
    if (request == NULL) {
        FAIL() << "Receive of request timed out";
    }

    // TODO(kmidkiff): Verify message envelope...

    service->response(request);

    eii::msgbus::MsgEnvelope* response = requester->recv_timedwait(timeout);
    if (response == NULL) {
        FAIL() << "Receive of response timed out";
    }

    // TODO(kmidkiff): Verify message envelope...

    delete msg;
    delete request;
    delete response;

    delete service;
    delete requester;
    delete ctx;
}


/**
 * Thread run method used in the msgbus_subscriber_first test.
 */
// void deplayed_publisher(
//         void* msgbus_ctx, const char* topic, int sec_sleep) {
//     LOG_INFO_0("Publsher thread started");
//
//     // Sleeping publisher thread
//     auto sleep_time  = std::chrono::seconds(sec_sleep);
//     std::this_thread::sleep_for(sleep_time);
//
//     // Initialize the publisher
//     publisher_ctx_t* pub_ctx = NULL;
//     msgbus_ret_t ret = msgbus_publisher_new(msgbus_ctx, topic, &pub_ctx);
//     if (ret != MSG_SUCCESS) {
//         LOG_ERROR("(rc: %d) Failed to initialize publisher", ret);
//         return;
//     }
//
//     // Give publisher time to initialize
//     sleep(1);
//
//     // Creating message to be published
//     // NOTE: Other tests check that the following is successful
//     msg_envelope_t* msg = NULL;
//     msg_envelope_elem_body_t* integer = msgbus_msg_envelope_new_integer(42);
//     msg_envelope_elem_body_t* fp = msgbus_msg_envelope_new_floating(55.5);
//     msg = msgbus_msg_envelope_new(CT_JSON);
//     msgbus_msg_envelope_put(msg, "hello", integer);
//     msgbus_msg_envelope_put(msg, "world", fp);
//
//     // Publish the message
//     LOG_INFO_0("Publishing message");
//     ret = msgbus_publisher_publish(msgbus_ctx, pub_ctx, msg);
//     if (ret != MSG_SUCCESS) {
//         LOG_ERROR("(rc: %d) Failed to publish message", ret);
//         // NOTE: Not returning so that the clean up below happens for the
//         // initialized memory in this thread.
//     }
//
//     // Clean up memory
//     msgbus_msg_envelope_destroy(msg);
//     msgbus_publisher_destroy(msgbus_ctx, pub_ctx);
// }
//
// /**
//  * A unittest which purposefully starts the subscriber first to make sure the
//  * underlying protocol does not error out if a given publisher does not exist
//  * on the network yet.
//  *
//  * \note This may only apply to ZeroMQ, further looking into whether this
//  *      applies to other protocols should be done.
//  */
// TEST(msgbus_test, msgbus_subscriber_first) {
//     // Initialize message bus context
//     msgbus_ret_t ret = MSG_SUCCESS;
//     msg_envelope_t* received = NULL;
//     config_t* config = create_config();
//     void* ctx = msgbus_initialize(config);
//     if(ctx == NULL) {
//         FAIL() << "Init failed";
//     }
//
//     // Initialize subscriber
//     recv_ctx_t* sub_ctx = NULL;
//     ret = msgbus_subscriber_new(ctx, PUB_SUB_TOPIC, NULL, &sub_ctx);
//     ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to create subscriber";
//     sleep(1);  // Allow time for subscriber to start
//
//     // Start publisher thread - delayed start for 1 second
//     std::thread pub_th(deplayed_publisher, ctx, PUB_SUB_TOPIC, 3);
//
//     // Wait for message
//     // ret = msgbus_recv_timedwait(ctx, sub_ctx, 10 * 1000, &received);
//     ret = msgbus_recv_wait(ctx, sub_ctx, &received);
//     ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to receive publication";
//
//     // Join with publisher thread
//     pub_th.join();
//
//     // Clean up memory
//     msgbus_msg_envelope_destroy(received);
//     msgbus_recv_ctx_destroy(ctx, sub_ctx);
//     msgbus_destroy(ctx);
// }

/**
 * Overridden GTest main method
 */
GTEST_API_ int main(int argc, char** argv) {
    // Parse out gTest command line parameters
    ::testing::InitGoogleTest(&argc, argv);

    log_lvl_t log_lvl = LOG_LVL_ERROR;

    if(argc > 1) {
        int idx = 1;

        while(argc != 1) {
            if(strcmp(argv[idx], "--tcp") == 0) {
                LOG_INFO_0("Running msgbus tests over TCP");
                g_use_tcp = true;
                idx++;
                argc--;
            } else if(strcmp(argv[idx], "--log-level") == 0) {
                if(argc < 3) {
                    LOG_ERROR_0("Too few arguments");
                    return -1;
                }

                char* log_level = argv[idx + 1];
                if (strcmp(log_level, "INFO") == 0) {
                    log_lvl = LOG_LVL_INFO;
                } else if (strcmp(log_level, "DEBUG") == 0) {
                    log_lvl = LOG_LVL_DEBUG;
                } else if (strcmp(log_level, "ERROR") == 0) {
                    log_lvl = LOG_LVL_ERROR;
                } else if (strcmp(log_level, "WARN") == 0) {
                    log_lvl = LOG_LVL_WARN;
                } else {
                    LOG_ERROR("Unknown log level: %s", log_level);
                    return -1;
                }

                idx += 2;
                argc -= 2;
            } else {
                LOG_ERROR("Unknown parameter: %s", argv[1]);
                return -1;
            }
        }
    } else {
        g_use_tcp = false;
    }

    set_log_level(log_lvl);

    if(g_use_tcp) {
        LOG_INFO_0("Running msgbus tests over TCP");
    } else {
        LOG_INFO_0("Running msgbus tests over IPC");
    }

    return RUN_ALL_TESTS();
}

/**
 * Helper method to add the current working directory to the LD_LIBRARY_PATH.
 *
 * Note that this function returns the string for the environmental variable is
 * returned. This memory needs to stay allocated until that variable is no
 * longer needed.
 *
 * @return char*
 */
static char* update_ld_library_path() {
    const char* ld_library_path = getenv("LD_LIBRARY_PATH");
    size_t len = (ld_library_path != NULL) ? strlen(ld_library_path) : 0;

    // Get current working directory
   char cwd[PATH_MAX];
   char* result = getcwd(cwd, PATH_MAX);
   assert(result != NULL);

   size_t dest_len = strlen(LD_PATH_SET) + strlen(cwd) + len + 2;
   char* env_str = NULL;

   if(ld_library_path == NULL) {
       // Setting the environmental variable from scratch
       env_str = concat_s(dest_len, 3, LD_PATH_SET, LD_SEP, cwd);
   } else {
       // Setting the environmental variable with existing path
       env_str = concat_s(
               dest_len, 4, LD_PATH_SET, ld_library_path, LD_SEP, cwd);
   }
   assert(env_str != NULL);

   // Put the new LD_LIBRARY_PATH into the environment
   putenv(env_str);

   return env_str;
}
