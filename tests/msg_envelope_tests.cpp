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
 * @brief Message envelope tests
 * @author Kevin Midkiff (kevin.midkiff@intel.com)
 */

// Enable use of timeit utility
#define WITH_TIMEIT

#include <stdio.h>
#include <stdlib.h>
#include <gtest/gtest.h>
#include "eis/msgbus/msg_envelope.h"

#define EXPECTED_JSON_LEN 60
#define EXPECTED_JSON "{"\
    "\"int\":42,"\
    "\"floating\":55.5,"\
    "\"bool\":true,"\
    "\"str\":\"Hello, World!\""\
    "}"

/**
 * Simple initialization and destroy case with no data.
 */
TEST(msg_envelope_tests, simple_init) {
    msg_envelope_t* msg = msgbus_msg_envelope_new(CT_JSON);
    msgbus_msg_envelope_destroy(msg);
}

/**
 * Test to verify flow of put, get, remove, and get
 */
TEST(msg_envelope_tests, simple_put_get_remove) {
    msg_envelope_t* msg = msgbus_msg_envelope_new(CT_JSON);
    msg_envelope_elem_body_t* data = msgbus_msg_envelope_new_integer(42);

    msgbus_msg_envelope_put(msg, "testing", data);

    msg_envelope_elem_body_t* data_get;
    msgbus_ret_t ret = msgbus_msg_envelope_get(msg, "testing", &data_get);

    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to retrieve 'testing' from body";
    ASSERT_EQ(data_get->type, MSG_ENV_DT_INT) << "Value of data type wrong";
    ASSERT_EQ(data_get->body.integer, 42) << "Value of retrieved data wrong";

    ret = msgbus_msg_envelope_remove(msg, "testing");
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to remove 'testing' from the body";

    ret = msgbus_msg_envelope_get(msg, "testing", &data_get);
    ASSERT_EQ(ret, MSG_ERR_ELEM_NOT_EXIST);

    msgbus_msg_envelope_destroy(msg);
}

/**
 * Test to verify that adding a value under the same key returns
 * MSG_ERR_ELEM_ALREADY_EXISTS.
 */
TEST(msg_envelope_tests, already_exists) {
    msg_envelope_t* msg = msgbus_msg_envelope_new(CT_JSON);

    msg_envelope_elem_body_t* data = (msg_envelope_elem_body_t*) malloc(
            sizeof(msg_envelope_elem_body_t));
    data->type = MSG_ENV_DT_INT;
    data->body.integer = 42;

    msgbus_ret_t ret = msgbus_msg_envelope_put(msg, "testing", data);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to put element";

    ret = msgbus_msg_envelope_put(msg, "testing", data);
    ASSERT_EQ(ret, MSG_ERR_ELEM_ALREADY_EXISTS) << "Allowed duplicates";

    msgbus_msg_envelope_destroy(msg);
}

/**
 * Test to validate correct rehashing behaivior
 */
TEST(msg_envelope_tests, rehash) {
    msg_envelope_t* msg = msgbus_msg_envelope_new(CT_JSON);

    char** keys = (char**) malloc(sizeof(char*) * 260);

    for(int i = 0; i < 260; i++) {
        char* key = (char*) malloc(sizeof(char) * 12);
        sprintf(key, "testing-%03d", i);
        keys[i] = key;
        msg_envelope_elem_body_t* data = (msg_envelope_elem_body_t*) malloc(
                sizeof(msg_envelope_elem_body_t));
        data->type = MSG_ENV_DT_INT;
        data->body.integer = 42;
        msgbus_ret_t ret = msgbus_msg_envelope_put(msg, key, data);
        ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to put element " << i;
    }

    msgbus_msg_envelope_destroy(msg);
    for(int i = 0; i < 260; i++)
        free(keys[i]);
    free(keys);
}

/**
 * Test blob basic path
 */
TEST(msg_envelope_tests, ct_blob_put) {
    msg_envelope_t* msg = msgbus_msg_envelope_new(CT_BLOB);

    char* data = (char*) malloc(sizeof(char) * 10);
    memcpy(data, "\x01\x01\x02\x03\x04\x05\x06\x07\x08\x09", 10);
    msg_envelope_elem_body_t* blob = msgbus_msg_envelope_new_blob(data, 10);

    msgbus_ret_t ret = msgbus_msg_envelope_put(msg, NULL, blob);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to put element";

    msg_envelope_elem_body_t* data_get;
    ret = msgbus_msg_envelope_get(msg, NULL, &data_get);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to get element";
    ASSERT_EQ(data_get->type, MSG_ENV_DT_BLOB) << "Incorrect data type";
    ASSERT_EQ(data_get->body.blob->len, 10) << "Incorrect length";

    // Verify that each byte is correct
    for(int i = 0; i < 10; i++) {
        ASSERT_EQ(data_get->body.blob->data[i], data[i]);
    }

    msgbus_msg_envelope_destroy(msg);
}

/**
 * Test to verify that the put method will only accept MSG_ENV_DT_BLOBs
 */
TEST(msg_envelope_tests, ct_blob_put_wrong_type) {
    msg_envelope_t* msg = msgbus_msg_envelope_new(CT_BLOB);

    msg_envelope_elem_body_t* data = (msg_envelope_elem_body_t*) malloc(
            sizeof(msg_envelope_elem_body_t));
    data->type = MSG_ENV_DT_INT;
    data->body.integer = 42;

    msgbus_ret_t ret = msgbus_msg_envelope_put(msg, NULL, data);
    ASSERT_EQ(ret, MSG_ERR_ELEM_BLOB_MALFORMED) << "Wrong return type";

    // Manual free because the element was rejected and so therefore the
    // memory ownership does not fall onto the message envelope
    free(data);

    msgbus_msg_envelope_destroy(msg);
}

/**
 * Test to verify that the put method will not allow a double put for a blob.
 */
TEST(msg_envelope_tests, ct_blob_double_put) {
    msg_envelope_t* msg = msgbus_msg_envelope_new(CT_BLOB);

    char* data = (char*) malloc(sizeof(char) * 10);
    memcpy(data, "\x01\x01\x02\x03\x04\x05\x06\x07\x08\x09", 10);
    msg_envelope_elem_body_t* blob = msgbus_msg_envelope_new_blob(data, 10);

    msgbus_ret_t ret = msgbus_msg_envelope_put(msg, NULL, blob);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to put element";

    ret = msgbus_msg_envelope_put(msg, NULL, blob);
    ASSERT_EQ(ret, MSG_ERR_ELEM_BLOB_ALREADY_SET) << "Allowed double blob put";

    msgbus_msg_envelope_destroy(msg);
}

/**
 * Test blob serialization
 */
TEST(msg_envelope_tests, ct_blob_serialize) {
    msg_envelope_t* msg = msgbus_msg_envelope_new(CT_BLOB);

    char* data = (char*) malloc(sizeof(char) * 10);
    memcpy(data, "\x01\x01\x02\x03\x04\x05\x06\x07\x08\x09", 10);
    msg_envelope_elem_body_t* blob = msgbus_msg_envelope_new_blob(data, 10);

    msgbus_ret_t ret = msgbus_msg_envelope_put(msg, NULL, blob);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to put element";

    msg_envelope_serialized_part_t* parts = NULL;
    int num_parts = msgbus_msg_envelope_serialize(msg, &parts);
    ASSERT_EQ(parts[0].len, 10) << "Incorrect serialized length";

    for(int i = 0; i < 10; i++) {
        ASSERT_EQ(parts[0].bytes[i], data[i]);
    }

    msg_envelope_t* env = NULL;
    ret = msgbus_msg_envelope_deserialize(CT_BLOB, parts, num_parts, &env);
    ASSERT_EQ(ret, MSG_SUCCESS);

    msgbus_msg_envelope_serialize_destroy(parts, num_parts);

    // Setting internal deserialized envelope memory to not owned, since it
    // is still technically owned by the other msgbus since not copies occur
    env->blob->body.blob->shared->owned = false;

    msg_envelope_elem_body_t* data_get;
    ret = msgbus_msg_envelope_get(env, NULL, &data_get);

    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to retrieve 'testing' from body";
    ASSERT_EQ(data_get->type, MSG_ENV_DT_BLOB) << "Value of data type wrong";

    for(int i = 0; i < 10; i++) {
        ASSERT_EQ(data_get->body.blob->data[i], data[i]);
    }

    msgbus_msg_envelope_destroy(msg);
    msgbus_msg_envelope_destroy(env);
}

/**
 * Test JSON serialization
 */
TEST(msg_envelope_tests, ct_json_serialize) {
    msg_envelope_t* msg = msgbus_msg_envelope_new(CT_JSON);

    char* data = (char*) malloc(sizeof(char) * 6);
    memcpy(data, "HELLO", 6);
    msg_envelope_elem_body_t* blob = msgbus_msg_envelope_new_blob(data, 6);

    msg_envelope_elem_body_t* int_data = (msg_envelope_elem_body_t*) malloc(
            sizeof(msg_envelope_elem_body_t));
    int_data->type = MSG_ENV_DT_INT;
    int_data->body.integer = 42;

    msg_envelope_elem_body_t* float_data = (msg_envelope_elem_body_t*) malloc(
            sizeof(msg_envelope_elem_body_t));
    float_data->type = MSG_ENV_DT_FLOATING;
    float_data->body.floating = 55.5;

    msg_envelope_elem_body_t* str_data = (msg_envelope_elem_body_t*) malloc(
            sizeof(msg_envelope_elem_body_t));
    str_data->type = MSG_ENV_DT_STRING;
    str_data->body.string = (char*) malloc(sizeof(char) * 14);
    memcpy(str_data->body.string, "Hello, World!", 14);

    msg_envelope_elem_body_t* bool_data = (msg_envelope_elem_body_t*) malloc(
            sizeof(msg_envelope_elem_body_t));
    bool_data->type = MSG_ENV_DT_BOOLEAN;
    bool_data->body.boolean = true;

    msgbus_ret_t ret = msgbus_msg_envelope_put(msg, NULL, blob);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to put blob";

    ret = msgbus_msg_envelope_put(msg, "int", int_data);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to put int";

    ret = msgbus_msg_envelope_put(msg, "floating", float_data);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to put float";

    ret = msgbus_msg_envelope_put(msg, "str", str_data);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to put str";

    ret = msgbus_msg_envelope_put(msg, "bool", bool_data);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to put bool";

    msg_envelope_serialized_part_t* parts = NULL;
    int num_parts = msgbus_msg_envelope_serialize(msg, &parts);

    ASSERT_EQ(num_parts, 2) << "Incorrect number of parts";
    ASSERT_EQ(parts[0].len, EXPECTED_JSON_LEN) << "Incorrect length";
    ASSERT_EQ(parts[1].len, blob->body.blob->len) << "Wrong blob len";

    for(int i = 0; i < EXPECTED_JSON_LEN; i++) {
        ASSERT_EQ(parts[0].bytes[i], EXPECTED_JSON[i]);
    }

    for(int i = 0; i < parts[1].len; i++) {
        ASSERT_EQ(parts[1].bytes[i], blob->body.blob->data[i]);
    }

    msg_envelope_t* deserialized = NULL;
    ret = msgbus_msg_envelope_deserialize(
            CT_JSON, parts, num_parts, &deserialized);
    ASSERT_EQ(ret, MSG_SUCCESS);

    // Setting internal deserialized envelope memory to not owned, since it
    // is still technically owned by the other msgbus since not copies occur
    deserialized->blob->body.blob->shared->owned = false;

    msgbus_msg_envelope_serialize_destroy(parts, num_parts);

    msgbus_msg_envelope_destroy(deserialized);
    msgbus_msg_envelope_destroy(msg);
}
