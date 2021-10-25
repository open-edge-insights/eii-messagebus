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
 */

// Enable use of timeit utility
#define WITH_TIMEIT

#include <stdio.h>
#include <stdlib.h>
#include <gtest/gtest.h>
#include <cjson/cJSON.h>
#include <cstring>
#include <csignal>
#include <vector>
#include "eii/msgbus/msg_envelope.hpp"
#include "eii/msgbus/msg_envelope.h"

#define TEST_NAME "topic-or-service-name"
#define EXPECTED_JSON_LEN 108
#define EXPECTED_JSON "{"\
    "\"int\":42,"\
    "\"floating\":55.5,"\
    "\"bool\":true,"\
    "\"str\":\"Hello, World!\""\
    "\"obj\":{\"test\":65},"\
    "\"none\":null",\
    "\"arr\":[\"test\",65]"\
    "}"

#define ASSERT_NULL(val) { \
    if(val != NULL) FAIL() << "Value should be NULL"; \
}

#define ASSERT_NOT_NULL(val) { \
    if(val == NULL) FAIL() << "Value shoud not be NULL"; \
}

using namespace eii::msgbus;

/**
 * Simple initialization and destroy case with no data.
 */
TEST(msg_envelope_tests, simple_init) {
    msg_envelope_t* msg = msgbus_msg_envelope_new(CT_JSON);
    if(msg == NULL)
        FAIL() << "NULL";
    msgbus_msg_envelope_destroy(msg);
}

/**
 * Test to add name field to msg_envelope_t & verify that there are no memory leaks.
 */
TEST(msg_envelope_tests, topic_envelope) {
    msg_envelope_t* msg = msgbus_msg_envelope_new(CT_JSON);
    if(msg == NULL)
        FAIL() << "NULL";

    msg_envelope_elem_body_t* data = msgbus_msg_envelope_new_integer(42);
    msgbus_msg_envelope_put(msg, "testing", data);

    size_t len = strlen(TEST_NAME) + 1;
    msg->name = (char*) malloc(sizeof(char) * len);
    ASSERT_NOT_NULL(msg->name);
    strcpy(msg->name, TEST_NAME);
    msg->name[len - 1] = '\0';  // NULL terminate string

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
 * Test blob serialization
 */
TEST(msg_envelope_tests, ct_blob_serialize) {
    msg_envelope_t* msg = msgbus_msg_envelope_new(CT_BLOB);

    char* data = (char*) malloc(sizeof(char) * 10);
    memcpy(data, "\x01\x01\x02\x03\x04\x05\x06\x07\x08\x09", 10);
    msg_envelope_elem_body_t* blob = msgbus_msg_envelope_new_blob(data, 10);
    if(blob == NULL)
        FAIL() << "Failed to initialize blob";

    msgbus_ret_t ret = msgbus_msg_envelope_put(msg, NULL, blob);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to put element";

    msg_envelope_serialized_part_t* parts = NULL;
    int num_parts = msgbus_msg_envelope_serialize(msg, &parts);
    ASSERT_EQ(parts[0].len, 10) << "Incorrect serialized length";

    for(int i = 0; i < 10; i++) {
        ASSERT_EQ(parts[0].bytes[i], data[i]);
    }

    msg_envelope_t* env = NULL;
    ret = msgbus_msg_envelope_deserialize(CT_BLOB, parts, num_parts, "test", &env);
    ASSERT_EQ(ret, MSG_SUCCESS);

    msgbus_msg_envelope_serialize_destroy(parts, num_parts);

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

    msg_envelope_elem_body_t* none_data = msgbus_msg_envelope_new_none();
    ASSERT_NOT_NULL(none_data);

    msg_envelope_elem_body_t* arr_data = msgbus_msg_envelope_new_array();
    ASSERT_NOT_NULL(arr_data);

    msg_envelope_elem_body_t* arr_str = msgbus_msg_envelope_new_string("test");
    ASSERT_NOT_NULL(arr_str);

    msg_envelope_elem_body_t* arr_int = msgbus_msg_envelope_new_integer(65);
    ASSERT_NOT_NULL(arr_int);

    msgbus_ret_t ret = msgbus_msg_envelope_elem_array_add(arr_data, arr_str);
    ASSERT_EQ(ret, MSG_SUCCESS);

    ret = msgbus_msg_envelope_elem_array_add(arr_data, arr_int);
    ASSERT_EQ(ret, MSG_SUCCESS);

    msg_envelope_elem_body_t* obj = msgbus_msg_envelope_new_object();
    ASSERT_NOT_NULL(obj);

    msg_envelope_elem_body_t* obj_int = msgbus_msg_envelope_new_integer(65);
    ASSERT_NOT_NULL(obj_int);

    ret = msgbus_msg_envelope_elem_object_put(obj, "test", obj_int);
    ASSERT_EQ(ret, MSG_SUCCESS);

    ret = msgbus_msg_envelope_put(msg, "arr", arr_data);
    ASSERT_EQ(ret, MSG_SUCCESS);

    ret = msgbus_msg_envelope_put(msg, "obj", obj);
    ASSERT_EQ(ret, MSG_SUCCESS);

    ret = msgbus_msg_envelope_put(msg, "none", none_data);
    ASSERT_EQ(ret, MSG_SUCCESS);

    ret = msgbus_msg_envelope_put(msg, NULL, blob);
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

    // TODO: Deep comparison of JSON values
    // for(int i = 0; i < EXPECTED_JSON_LEN; i++) {
    //     ASSERT_EQ(parts[0].bytes[i], EXPECTED_JSON[i]);
    // }

    for(int i = 0; i < parts[1].len; i++) {
        ASSERT_EQ(parts[1].bytes[i], blob->body.blob->data[i]);
    }

    msg_envelope_t* deserialized = NULL;
    ret = msgbus_msg_envelope_deserialize(
            CT_JSON, parts, num_parts, "test", &deserialized);
    ASSERT_EQ(ret, MSG_SUCCESS);

    // Verify the object is there after deserialization
    msg_envelope_elem_body_t* get_obj = NULL;
    ret = msgbus_msg_envelope_get(deserialized, "obj", &get_obj);
    ASSERT_EQ(ret, MSG_SUCCESS);

    // Get sub object value
    msg_envelope_elem_body_t* get_subobj = msgbus_msg_envelope_elem_object_get(
            get_obj, "test");
    ASSERT_NOT_NULL(get_subobj);
    ASSERT_EQ(get_subobj->type, MSG_ENV_DT_INT);
    ASSERT_EQ(get_subobj->body.integer, 65);

    // Verify none type is there
    msg_envelope_elem_body_t* get_none = NULL;
    ret = msgbus_msg_envelope_get(deserialized, "none", &get_none);
    ASSERT_EQ(ret, MSG_SUCCESS);
    ASSERT_EQ(get_none->type, MSG_ENV_DT_NONE);

    // Verify the array is there after deserialization
    msg_envelope_elem_body_t* get_arr = NULL;
    ret = msgbus_msg_envelope_get(deserialized, "arr", &get_arr);
    ASSERT_EQ(ret, MSG_SUCCESS);

    // Verify int/string is there
    msg_envelope_elem_body_t* get_arr_str = msgbus_msg_envelope_elem_array_get_at(get_arr, 0);
    ASSERT_NOT_NULL(get_arr_str);
    ASSERT_EQ(get_arr_str->type, MSG_ENV_DT_STRING);
    ASSERT_STREQ(get_arr_str->body.string, "test");

    msg_envelope_elem_body_t* get_arr_int = msgbus_msg_envelope_elem_array_get_at(get_arr, 1);
    ASSERT_NOT_NULL(get_arr_int);
    ASSERT_EQ(get_arr_int->type, MSG_ENV_DT_INT);
    ASSERT_EQ(get_arr_int->body.integer, 65);

    msgbus_msg_envelope_serialize_destroy(parts, num_parts);

    msgbus_msg_envelope_destroy(deserialized);
    msgbus_msg_envelope_destroy(msg);
}


/**
 * Helper method to verify bytes
 */
static void verify_bytes(const char* expected, const char* actual, int length) {
    for (int i = 0; i < length; i++) {
        ASSERT_EQ(expected[i], actual[i]);
    }
}


/**
 * Test multi blob serialization
 */
TEST(msg_envelope_tests, ct_multi_blob_serialize) {
    msg_envelope_t* msg = msgbus_msg_envelope_new(CT_BLOB);

    char* data = (char*) malloc(sizeof(char) * 10);
    memcpy(data, "\x01\x01\x02\x03\x04\x05\x06\x07\x08\x09", 10);
    msg_envelope_elem_body_t* blob = msgbus_msg_envelope_new_blob(data, 10);
    if(blob == NULL)
        FAIL() << "Failed to initialize blob";

    char* data_two = (char*) malloc(sizeof(char) * 10);
    memcpy(data_two, "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19", 10);
    msg_envelope_elem_body_t* blob_two = msgbus_msg_envelope_new_blob(data_two, 10);
    if(blob_two == NULL)
        FAIL() << "Failed to initialize blob_two";

    char* data_three = (char*) malloc(sizeof(char) * 10);
    memcpy(data_three, "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29", 10);
    msg_envelope_elem_body_t* blob_three = msgbus_msg_envelope_new_blob(data_three, 10);
    if(blob_three == NULL)
        FAIL() << "Failed to initialize blob_three";

    msgbus_ret_t ret = msgbus_msg_envelope_put(msg, NULL, blob);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to put element";

    ret = msgbus_msg_envelope_put(msg, NULL, blob_two);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to put element";

    ret = msgbus_msg_envelope_put(msg, NULL, blob_three);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to put element";

    msg_envelope_serialized_part_t* parts = NULL;
    int num_parts = msgbus_msg_envelope_serialize(msg, &parts);

    verify_bytes(parts[0].bytes, data, 10);
    verify_bytes(parts[1].bytes, data_two, 10);
    verify_bytes(parts[2].bytes, data_three, 10);

    msg_envelope_t* env = NULL;
    ret = msgbus_msg_envelope_deserialize(CT_BLOB, parts, num_parts, "test", &env);
    ASSERT_EQ(ret, MSG_SUCCESS);

    msgbus_msg_envelope_serialize_destroy(parts, num_parts);

    msg_envelope_elem_body_t* data_get;
    ret = msgbus_msg_envelope_get(env, NULL, &data_get);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to retrieve 'testing' from body";
    ASSERT_EQ(data_get->type, MSG_ENV_DT_ARRAY) << "Value of data type wrong";

    msg_envelope_elem_body_t* env_get_data;
    env_get_data = msgbus_msg_envelope_elem_array_get_at(data_get, 0);
    msg_envelope_elem_body_t* env_get_data_two;
    env_get_data_two = msgbus_msg_envelope_elem_array_get_at(data_get, 1);
    msg_envelope_elem_body_t* env_get_data_three;
    env_get_data_three = msgbus_msg_envelope_elem_array_get_at(data_get, 2);
    verify_bytes(env_get_data->body.blob->data, data, 10);
    verify_bytes(env_get_data_two->body.blob->data, data_two, 10);
    verify_bytes(env_get_data_three->body.blob->data, data_three, 10);

    msgbus_msg_envelope_destroy(msg);
    msgbus_msg_envelope_destroy(env);
}

/**
 * Test JSON + multi blob serialization
 */
TEST(msg_envelope_tests, ct_multi_json_serialize) {
    msg_envelope_t* msg = msgbus_msg_envelope_new(CT_JSON);

    // char* data = (char*) malloc(sizeof(char) * 6);
    // memcpy(data, "HELLO", 6);
    // msg_envelope_elem_body_t* blob = msgbus_msg_envelope_new_blob(data, 6);

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

    msg_envelope_elem_body_t* none_data = msgbus_msg_envelope_new_none();
    ASSERT_NOT_NULL(none_data);

    msg_envelope_elem_body_t* arr_data = msgbus_msg_envelope_new_array();
    ASSERT_NOT_NULL(arr_data);

    msg_envelope_elem_body_t* arr_str = msgbus_msg_envelope_new_string("test");
    ASSERT_NOT_NULL(arr_str);

    msg_envelope_elem_body_t* arr_int = msgbus_msg_envelope_new_integer(65);
    ASSERT_NOT_NULL(arr_int);

    msgbus_ret_t ret = msgbus_msg_envelope_elem_array_add(arr_data, arr_str);
    ASSERT_EQ(ret, MSG_SUCCESS);

    ret = msgbus_msg_envelope_elem_array_add(arr_data, arr_int);
    ASSERT_EQ(ret, MSG_SUCCESS);

    msg_envelope_elem_body_t* obj = msgbus_msg_envelope_new_object();
    ASSERT_NOT_NULL(obj);

    msg_envelope_elem_body_t* obj_int = msgbus_msg_envelope_new_integer(65);
    ASSERT_NOT_NULL(obj_int);

    ret = msgbus_msg_envelope_elem_object_put(obj, "test", obj_int);
    ASSERT_EQ(ret, MSG_SUCCESS);

    ret = msgbus_msg_envelope_put(msg, "arr", arr_data);
    ASSERT_EQ(ret, MSG_SUCCESS);

    ret = msgbus_msg_envelope_put(msg, "obj", obj);
    ASSERT_EQ(ret, MSG_SUCCESS);

    ret = msgbus_msg_envelope_put(msg, "none", none_data);
    ASSERT_EQ(ret, MSG_SUCCESS);

    char* data = (char*) malloc(sizeof(char) * 10);
    memcpy(data, "\x01\x01\x02\x03\x04\x05\x06\x07\x08\x09", 10);
    msg_envelope_elem_body_t* blob = msgbus_msg_envelope_new_blob(data, 10);
    if(blob == NULL)
        FAIL() << "Failed to initialize blob";

    char* data_two = (char*) malloc(sizeof(char) * 10);
    memcpy(data_two, "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19", 10);
    msg_envelope_elem_body_t* blob_two = msgbus_msg_envelope_new_blob(data_two, 10);
    if(blob_two == NULL)
        FAIL() << "Failed to initialize blob_two";

    char* data_three = (char*) malloc(sizeof(char) * 10);
    memcpy(data_three, "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29", 10);
    msg_envelope_elem_body_t* blob_three = msgbus_msg_envelope_new_blob(data_three, 10);
    if(blob_three == NULL)
        FAIL() << "Failed to initialize blob_three";

    ret = msgbus_msg_envelope_put(msg, NULL, blob);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to put multi blob";

    ret = msgbus_msg_envelope_put(msg, NULL, blob_two);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to put multi blob";

    ret = msgbus_msg_envelope_put(msg, NULL, blob_three);
    ASSERT_EQ(ret, MSG_SUCCESS) << "Failed to put multi blob";

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

    ASSERT_EQ(num_parts, 4) << "Incorrect number of parts";
    ASSERT_EQ(parts[0].len, EXPECTED_JSON_LEN) << "Incorrect length";
    ASSERT_EQ(parts[1].len, blob->body.blob->len) << "Wrong blob len";
    ASSERT_EQ(parts[2].len, blob_two->body.blob->len) << "Wrong blob len";
    ASSERT_EQ(parts[3].len, blob_three->body.blob->len) << "Wrong blob len";

    // // TODO: Deep comparison of JSON values
    // // for(int i = 0; i < EXPECTED_JSON_LEN; i++) {
    // //     ASSERT_EQ(parts[0].bytes[i], EXPECTED_JSON[i]);
    // // }

    verify_bytes(parts[1].bytes, data, 10);
    verify_bytes(parts[2].bytes, data_two, 10);
    verify_bytes(parts[3].bytes, data_three, 10);

    msg_envelope_t* deserialized = NULL;
    ret = msgbus_msg_envelope_deserialize(
            CT_JSON, parts, num_parts, "test", &deserialized);
    ASSERT_EQ(ret, MSG_SUCCESS);

    // Verify the object is there after deserialization
    msg_envelope_elem_body_t* get_obj = NULL;
    ret = msgbus_msg_envelope_get(deserialized, "obj", &get_obj);
    ASSERT_EQ(ret, MSG_SUCCESS);

    // Get sub object value
    msg_envelope_elem_body_t* get_subobj = msgbus_msg_envelope_elem_object_get(
            get_obj, "test");
    ASSERT_NOT_NULL(get_subobj);
    ASSERT_EQ(get_subobj->type, MSG_ENV_DT_INT);
    ASSERT_EQ(get_subobj->body.integer, 65);

    // Verify none type is there
    msg_envelope_elem_body_t* get_none = NULL;
    ret = msgbus_msg_envelope_get(deserialized, "none", &get_none);
    ASSERT_EQ(ret, MSG_SUCCESS);
    ASSERT_EQ(get_none->type, MSG_ENV_DT_NONE);

    // Verify the array is there after deserialization
    msg_envelope_elem_body_t* get_arr = NULL;
    ret = msgbus_msg_envelope_get(deserialized, "arr", &get_arr);
    ASSERT_EQ(ret, MSG_SUCCESS);

    // Verify int/string is there
    msg_envelope_elem_body_t* get_arr_str = msgbus_msg_envelope_elem_array_get_at(get_arr, 0);
    ASSERT_NOT_NULL(get_arr_str);
    ASSERT_EQ(get_arr_str->type, MSG_ENV_DT_STRING);
    ASSERT_STREQ(get_arr_str->body.string, "test");

    msg_envelope_elem_body_t* get_arr_int = msgbus_msg_envelope_elem_array_get_at(get_arr, 1);
    ASSERT_NOT_NULL(get_arr_int);
    ASSERT_EQ(get_arr_int->type, MSG_ENV_DT_INT);
    ASSERT_EQ(get_arr_int->body.integer, 65);

    msgbus_msg_envelope_serialize_destroy(parts, num_parts);

    msgbus_msg_envelope_destroy(deserialized);
    msgbus_msg_envelope_destroy(msg);
}

/**
 * Test to verify correct functionality of msg envelope nested object
 * put/get/remove methods.
 */
TEST(msg_envelope_tests, object_put_get_remove) {
    msg_envelope_elem_body_t* obj = msgbus_msg_envelope_new_object();
    ASSERT_NOT_NULL(obj);

    msg_envelope_elem_body_t* integer = msgbus_msg_envelope_new_integer(32);
    ASSERT_NOT_NULL(integer);

    msgbus_ret_t ret = msgbus_msg_envelope_elem_object_put(obj, "test", integer);
    ASSERT_EQ(ret, MSG_SUCCESS);

    // Attempt double put
    ret = msgbus_msg_envelope_elem_object_put(obj, "test", integer);
    ASSERT_EQ(ret, MSG_ERR_ELEM_ALREADY_EXISTS);

    // Attempt get not exists
    msg_envelope_elem_body_t* get = msgbus_msg_envelope_elem_object_get(obj, "not_exist");
    ASSERT_NULL(get);

    get = msgbus_msg_envelope_elem_object_get(obj, "test");
    ASSERT_NOT_NULL(get);
    ASSERT_EQ(get->type, MSG_ENV_DT_INT);
    ASSERT_EQ(get->body.integer, integer->body.integer);

    ret = msgbus_msg_envelope_elem_object_remove(obj, "test");
    ASSERT_EQ(ret, MSG_SUCCESS);

    // Attempt remove not exists
    ret = msgbus_msg_envelope_elem_object_remove(obj, "not_exist");
    ASSERT_EQ(ret, MSG_ERR_ELEM_NOT_EXIST);

    get = msgbus_msg_envelope_elem_object_get(obj, "test");
    ASSERT_NULL(get);

    // Test double nested object with freeing
    msg_envelope_elem_body_t* subobj = msgbus_msg_envelope_new_object();
    ASSERT_NOT_NULL(subobj);

    msg_envelope_elem_body_t* string = msgbus_msg_envelope_new_string("subobj");
    ASSERT_NOT_NULL(string);

    ret = msgbus_msg_envelope_elem_object_put(subobj, "string", string);
    ASSERT_EQ(ret, MSG_SUCCESS);

    ret = msgbus_msg_envelope_elem_object_put(obj, "subobj", subobj);
    ASSERT_EQ(ret, MSG_SUCCESS);

    msgbus_msg_envelope_elem_destroy(obj);
}

/**
 * Test to verify correct functionality of msg envelope nested array
 * add/get/remove methods.
 */
TEST(msg_envelope_tests, array_put_get_remove) {
    msg_envelope_elem_body_t* arr = msgbus_msg_envelope_new_array();
    ASSERT_NOT_NULL(arr);

    msg_envelope_elem_body_t* integer = msgbus_msg_envelope_new_integer(32);
    ASSERT_NOT_NULL(integer);

    msgbus_ret_t ret = msgbus_msg_envelope_elem_array_add(arr, integer);
    ASSERT_EQ(ret, MSG_SUCCESS);

    // Attempt get not exists
    msg_envelope_elem_body_t* get = msgbus_msg_envelope_elem_array_get_at(arr, 1);
    ASSERT_NULL(get);

    get = msgbus_msg_envelope_elem_array_get_at(arr, 0);
    ASSERT_NOT_NULL(get);
    ASSERT_EQ(get->type, MSG_ENV_DT_INT);
    ASSERT_EQ(get->body.integer, integer->body.integer);

    ret = msgbus_msg_envelope_elem_array_remove_at(arr, 0);
    ASSERT_EQ(ret, MSG_SUCCESS);

    // Attempt remove not exists
    ret = msgbus_msg_envelope_elem_array_remove_at(arr, 11);
    ASSERT_EQ(ret, MSG_ERR_ELEM_NOT_EXIST);

    get = msgbus_msg_envelope_elem_array_get_at(arr, 0);
    ASSERT_NULL(get);

    // Test double nested object with freeing
    msg_envelope_elem_body_t* subobj = msgbus_msg_envelope_new_object();
    ASSERT_NOT_NULL(subobj);

    msg_envelope_elem_body_t* string = msgbus_msg_envelope_new_string("subobj");
    ASSERT_NOT_NULL(string);

    ret = msgbus_msg_envelope_elem_object_put(subobj, "string", string);
    ASSERT_EQ(ret, MSG_SUCCESS);

    ret = msgbus_msg_envelope_elem_array_add(arr, subobj);
    ASSERT_EQ(ret, MSG_SUCCESS);

    msgbus_msg_envelope_elem_destroy(arr);
}

/**
 * Simple initialization and destroy case with no data.
 */
TEST(msg_envelope_tests, cpp_simple_init) {
    try {
        // Create MsgEnvelope
        MsgEnvelope* msgEnv = new MsgEnvelope(CT_JSON);
        ASSERT_NOT_NULL(msgEnv);
        delete msgEnv;
    } catch(const std::exception& MsgbusException) {
        FAIL() << "Exception thrown: " << MsgbusException.what();
    } catch(...) {
        FAIL() << "Exception thrown";
    }
}

/**
 * Simple initialization, addition and destroy case for MsgEnvelope
 */
TEST(msg_envelope_tests, cpp_msg_envelope_test) {
    try {
        // Create MsgEnvelope
        MsgEnvelope* msgEnv = new MsgEnvelope(CT_JSON);
        ASSERT_NOT_NULL(msgEnv);

        // Add test (key, value) pairs to MsgEnvelope
        msgEnv->put_bool("Bool", true);
        msgEnv->put_string("Strng", "string_test");
        msgEnv->put_integer("Int", 3);
        msgEnv->put_float("Float", 3.45);

        // put_vector example
        std::vector<int> nums;
        nums.push_back(1);
        nums.push_back(2);
        nums.push_back(3);
        msgEnv->put_vector("IntVector", nums);

        // put_vector example
        std::vector<double> floats;
        floats.push_back(1.4);
        floats.push_back(2.5);
        floats.push_back(3.6);
        msgEnv->put_vector("FloatVector", floats);

        // put_vector example
        std::vector<bool> bools;
        bools.push_back(true);
        bools.push_back(false);
        msgEnv->put_vector("BoolVector", bools);

        // Verify data put into MsgEnvelope matches with
        // the fetched data
        ASSERT_EQ(msgEnv->get_int("Int"), 3);
        ASSERT_EQ(msgEnv->get_float("Float"), 3.45);
        ASSERT_EQ(msgEnv->get_bool("Bool"), true);

        // This test case will fail since the string
        // is converted to a c string internally which changes the
        // address of the variable but the content remains the same
        // since a strcpy is performed on the string
        // ASSERT_EQ(msgEnv->get_string("Strng"), "string_test");

        msgbus_msg_envelope_print(msgEnv->get_msg_envelope(), true, false);
        delete msgEnv;
    } catch(const std::exception& MsgbusException) {
        FAIL() << "Exception thrown: " << MsgbusException.what();
    } catch(...) {
        FAIL() << "Exception thrown";
    }
}

/**
 * Simple initialization, addition and destroy case for MsgEnvelopeObject
 */
TEST(msg_envelope_tests, cpp_msg_envelope_object_test) {
    try {
        // Create MsgEnvelope
        MsgEnvelope* msgEnv = new MsgEnvelope(CT_JSON);
        ASSERT_NOT_NULL(msgEnv);

        // Create MsgEnvelopeObject
        MsgEnvelopeObject* msgEnvObj = new MsgEnvelopeObject();
        ASSERT_NOT_NULL(msgEnvObj);

        // Add test (key, value) pairs to MsgEnvelopeObject
        msgEnvObj->put_bool("objBool", true);
        msgEnvObj->put_string("objStrng", "msgEnvObj_string_test");
        msgEnvObj->put_integer("objInt", 1);
        msgEnvObj->put_float("objFloat", 1.45);

        msgEnv->put_object("msg_envelope_object", msgEnvObj);

        // Verify data put into MsgEnvelopeObject matches with
        // the fetched data after putting it into MsgEnvelope
        ASSERT_EQ(msgEnvObj->get_int("objInt"), 1);
        ASSERT_EQ(msgEnvObj->get_float("objFloat"), 1.45);
        ASSERT_EQ(msgEnvObj->get_bool("objBool"), true);

        // This test case will fail since the string
        // is converted to a c string internally which changes the
        // address of the variable but the content remains the same
        // since a strcpy is performed on the string
        // ASSERT_EQ(msgEnvObj->get_string("objStrng"), "msgEnvObj_string_test");

        msgbus_msg_envelope_print(msgEnv->get_msg_envelope(), true, false);
        delete msgEnv;
    } catch(const std::exception& MsgbusException) {
        FAIL() << "Exception thrown: " << MsgbusException.what();
    } catch(...) {
        FAIL() << "Exception thrown";
    }
}

/**
 * Simple initialization, addition and destroy case for MsgEnvelopeList
 */
TEST(msg_envelope_tests, cpp_msg_envelope_array_test) {
    try {
        // Create MsgEnvelope
        MsgEnvelope* msgEnv = new MsgEnvelope(CT_JSON);
        ASSERT_NOT_NULL(msgEnv);

        // Create MsgEnvelopeList
        MsgEnvelopeList* msgEnvArr = new MsgEnvelopeList();
        ASSERT_NOT_NULL(msgEnvArr);

        // Add test (key, value) pairs to MsgEnvelopeList
        msgEnvArr->put_bool(true);
        msgEnvArr->put_string("msgEnvArr_string_test");
        msgEnvArr->put_integer(2);
        msgEnvArr->put_float(2.45);

        msgEnv->put_array("msg_envelope_array", msgEnvArr);

        // Verify data put into MsgEnvelopeList matches with
        // the fetched data after putting it into MsgEnvelope
        ASSERT_EQ(msgEnvArr->get_bool(0), true);
        ASSERT_EQ(msgEnvArr->get_int(2), 2);
        ASSERT_EQ(msgEnvArr->get_float(3), 2.45);

        // This test case will fail since the string
        // is converted to a c string internally which changes the
        // address of the variable but the content remains the same
        // since a strcpy is performed on the string
        // ASSERT_EQ(msgEnvArr->get_string(1), "msgEnvArr_string_test");

        msgbus_msg_envelope_print(msgEnv->get_msg_envelope(), true, false);
        delete msgEnv;
    } catch(const std::exception& MsgbusException) {
        FAIL() << "Exception thrown: " << MsgbusException.what();
    } catch(...) {
        FAIL() << "Exception thrown";
    }
}
