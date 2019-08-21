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
 * @brief Message envelope implementation
 * @author Kevin Midkiff <kevin.midkiff@intel.com>
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <cjson/cJSON.h>
#include <safe_lib.h>

#include "eis/msgbus/msgbus.h"
#include "eis/msgbus/crc32.h"
#include "eis/msgbus/logger.h"

#define INITIAL_SIZE  256
#define MAX_CHAIN_LEN 8

// Return values used internally
#define MAP_SUCCESS      0
#define MAP_FULL        -1
#define MAP_OMEM        -2
#define MAP_KEY_EXISTS  -3
#define MAP_PUT_ERR     -4

// Function prototypes
msgbus_ret_t msg_envelope_put_helper(
        msg_envelope_t* env, char* key, msg_envelope_elem_body_t* data);

/**
 * Hash the given key to get the preferred index in the envelope
 *
 * @param env - Message envelope
 * @param key - Key to hash
 * @return index
 */
unsigned int hash_int(msg_envelope_t* env, const char* key) {
    uint32_t crc = msgbus_crc32(key, strlen(key));

	// Robert Jenkins' 32 bit Mix Function
	crc += (crc << 12);
	crc ^= (crc >> 22);
	crc += (crc << 4);
	crc ^= (crc >> 9);
	crc += (crc << 10);
	crc ^= (crc >> 2);
	crc += (crc << 7);
	crc ^= (crc >> 12);

	// Knuth's Multiplicative Method
	crc = (crc >> 3) * 2654435761;

	return crc % env->max_size;
}

/**
 * Hash the given key.
 *
 * @param[in]  env  - Message envelope
 * @param[in]  key  - Key to hash
 * @param[out] hash - Index to store the value at if found
 * @return MAP_SUCCESS if successful, otherwise a different MAP_* value
 */
int hash(msg_envelope_t* env, const char* key) {
    int curr;
    int i;

    // Check if map is full, if so return
    if(env->size >= (env->max_size / 2)) return MAP_FULL;

    // Get preferred has index for the key
    curr = hash_int(env, key);
    curr = hash_int(env, key);

    int ind = 0;

    // Linear probing
    for(i = 0; i < MAX_CHAIN_LEN; i++) {
        // We have a good index to use
        if(!env->elems[curr].in_use) return curr;

        strcmp_s(env->elems[curr].key, env->elems[curr].key_len, key, &ind);

        // For a message envelope only one value at a key can exist, there is
        // no updating currently supported, a new message envelope must be
        // created for each message
        if(env->elems[curr].in_use && ind == 0)
            return MAP_KEY_EXISTS;

        curr = (curr + 1) % env->max_size;
    }

    // Reached max chain size and therefore the map is full for those CRC
    // collisions
    return MAP_FULL;
}

/**
 * Rehash the message envelope to double its size.
 *
 * \note{Ideally, a message does not have more than INITIAL_SIZE keys in it.}
 *
 * @param env - Message envelope
 * @return MAP_SUCESS if successfull, otherwise a different MAP_* value
 */
int rehash(msg_envelope_t* env) {
    // Issuing warning since this is not ideal, and that is a massive message
    LOG_WARN("Rehashing message envelope (using more that %d keys)",
             env->max_size);

    int i;
    msgbus_ret_t status;
    int old_size;
    msg_envelope_elem_t* curr;

    // Initialize new message envelope elements buffer
    msg_envelope_elem_t* temp = (msg_envelope_elem_t*) calloc(
            2 * env->max_size, sizeof(msg_envelope_elem_t));
    if(!temp) return MAP_OMEM;

    // Update the array
    curr = env->elems;
    env->elems = temp;

    // Update the size values
    old_size = env->max_size;
    env->max_size = 2 * old_size;
    env->size = 0;

    // Rehash all of the elements
    for(i = 0; i < old_size; i++) {

        // If dealing with an empty slot, continue to the next one
        if(!curr[i].in_use) continue;

        // Put value into resized envelope
        status = msg_envelope_put_helper(env, curr[i].key, curr[i].body);
        if(status != MSG_SUCCESS) goto err;
    }

    free(curr);
    return MAP_SUCCESS;

err:
    free(curr);
    return MAP_PUT_ERR;
}

msg_envelope_t* msgbus_msg_envelope_new(content_type_t ct) {
    msg_envelope_t* env = (msg_envelope_t*) malloc(sizeof(msg_envelope_t));
    if(!env) goto err;

    env->correlation_id = NULL; // TODO: Need to assign this
    env->content_type = ct;
    env->size = 0;
    env->blob = NULL;

    if(ct == CT_BLOB) {
        env->max_size = 0;
        env->elems = NULL;
    } else {
        env->max_size = INITIAL_SIZE;
        env->elems = (msg_envelope_elem_t*) calloc(
                env->max_size, sizeof(msg_envelope_elem_t));
        if(!env->elems) goto err;
    }

    return env;

err:
    if(env)
        msgbus_msg_envelope_destroy(env);
    return NULL;
}

/**
 * Helper function for putting an element into the envelope. This method
 * exists so that the rehash function can operate without needing to copy
 * the key strings. It still allows for the msgbus_msg_envelope_put() API
 * to copy the key given by the user.
 */
msgbus_ret_t msg_envelope_put_helper(
        msg_envelope_t* env, char* key, msg_envelope_elem_body_t* data)
{
    // Blob has different behavior
    if(env->content_type == CT_BLOB) {
        if(data->type != MSG_ENV_DT_BLOB)
            // The body type must be a MSG_ENV_DT_BLOB
            return MSG_ERR_ELEM_BLOB_MALFORMED;

        if(env->blob != NULL)
            // The blob for the message can only be set once
            return MSG_ERR_ELEM_BLOB_ALREADY_SET;

        env->blob = data;
    } else {
        if(data->type == MSG_ENV_DT_BLOB) {
            if(env->blob != NULL)
                // The blob for a (key,value) message can only be set once
                return MSG_ERR_ELEM_BLOB_ALREADY_SET;

            env->blob = data;
        } else {
            // Get hash index
            int index = hash(env, key);

            // Keep on rehashing until we can do something
            while(index == MAP_FULL) {
                if(rehash(env) == MAP_OMEM)
                    return MSG_ERR_NO_MEMORY;
                index = hash(env, key);
            }

            if(index == MAP_KEY_EXISTS)
                return MSG_ERR_ELEM_ALREADY_EXISTS;

            // Set data in the envelope
            env->elems[index].key = key;
            env->elems[index].key_len = strlen(key);
            env->elems[index].in_use = true;
            env->elems[index].body = data;
        }
    }

    return MSG_SUCCESS;
}

msg_envelope_elem_body_t* msgbus_msg_envelope_new_string(const char* string) {
    msg_envelope_elem_body_t* elem = (msg_envelope_elem_body_t*) malloc(
            sizeof(msg_envelope_elem_body_t));
    if(elem == NULL) {
        LOG_ERROR_0("Out of memory allocating the msg element body");
        return NULL;
    }

    size_t len = strlen(string);

    elem->type = MSG_ENV_DT_STRING;
    elem->body.string = (char*) malloc(sizeof(char) * (len + 1));
    if(elem->body.string == NULL) {
        LOG_ERROR_0("Out of memory allocating string");
        free(elem);
        return NULL;
    }
    memcpy_s(elem->body.string, len, string, len);
    elem->body.string[len] = '\0';

    return elem;
}

msg_envelope_elem_body_t* msgbus_msg_envelope_new_integer(int64_t integer) {
    msg_envelope_elem_body_t* elem = (msg_envelope_elem_body_t*) malloc(
            sizeof(msg_envelope_elem_body_t));
    if(elem == NULL) {
        LOG_ERROR_0("Out of memory allocating the msg element body");
        return NULL;
    }

    elem->type = MSG_ENV_DT_INT;
    elem->body.integer = integer;

    return elem;
}

msg_envelope_elem_body_t* msgbus_msg_envelope_new_floating(double floating) {
    msg_envelope_elem_body_t* elem = (msg_envelope_elem_body_t*) malloc(
            sizeof(msg_envelope_elem_body_t));
    if(elem == NULL) {
        LOG_ERROR_0("Out of memory allocating the msg element body");
        return NULL;
    }

    elem->type = MSG_ENV_DT_FLOATING;
    elem->body.floating = floating;

    return elem;
}

msg_envelope_elem_body_t* msgbus_msg_envelope_new_bool(bool boolean) {
    msg_envelope_elem_body_t* elem = (msg_envelope_elem_body_t*) malloc(
            sizeof(msg_envelope_elem_body_t));
    if(elem == NULL) {
        LOG_ERROR_0("Out of memory allocating the msg element body");
        return NULL;
    }

    elem->type = MSG_ENV_DT_BOOLEAN;
    elem->body.boolean = boolean;

    return elem;
}

msg_envelope_elem_body_t* msgbus_msg_envelope_new_blob(char* data, size_t len)
{
    msg_envelope_elem_body_t* elem = NULL;
    msg_envelope_blob_t* blob = NULL;

    owned_blob_t* shared = owned_blob_new((void*) data, free, data, len);
    if(shared == NULL) {
        LOG_ERROR_0("Out of memory allocating shared element");
        goto err;
    }

    blob = (msg_envelope_blob_t*) malloc(sizeof(msg_envelope_blob_t));
    if(blob == NULL) {
        LOG_ERROR_0("Out of memory allocating blob element");
        goto err;
    }
    blob->shared = shared;
    blob->len = shared->len;
    blob->data = shared->bytes;

    elem = (msg_envelope_elem_body_t*) malloc(
            sizeof(msg_envelope_elem_body_t));
    if(elem == NULL) {
        LOG_ERROR_0("Out of memory allocating the msg element body");
        goto err;
    }

    elem->type = MSG_ENV_DT_BLOB;
    elem->body.blob = blob;

    return elem;

err:
    if(shared != NULL) {
        shared->free(shared->ptr);
        free(shared);
    }
    if(blob != NULL)
        free(blob);
    if(elem != NULL)
        free(elem);
    return NULL;
}

void msgbus_msg_envelope_elem_destroy(msg_envelope_elem_body_t* body) {
    if(body->type == MSG_ENV_DT_STRING) {
        free(body->body.string);
    } else if(body->type == MSG_ENV_DT_BLOB) {
        owned_blob_destroy(body->body.blob->shared);
        free(body->body.blob);
    }
    free(body);
}

msgbus_ret_t msgbus_msg_envelope_put(
        msg_envelope_t* env, const char* key, msg_envelope_elem_body_t* data)
{
    char* key_cpy = NULL;

    // If the element has a key, make a copy for the envelope to own
    if(key != NULL) {
        size_t len = strlen(key);
        // Copying the key value
        key_cpy = (char*) malloc(sizeof(char) * len + 1);
        memcpy_s(key_cpy, len, key, len);
        key_cpy[len] = '\0';
    }

    msgbus_ret_t ret = msg_envelope_put_helper(env, key_cpy, data);
    if(ret != MSG_SUCCESS)
        free(key_cpy);

    return ret;
}

msgbus_ret_t msgbus_msg_envelope_remove(msg_envelope_t* env, const char* key) {
    // Immediately return if the message is a blob
    if(env->content_type == CT_BLOB)
        return MSG_ERR_ELEM_NOT_EXIST;

    // Get intiial hash value
    uint32_t curr = hash_int(env, key);
    size_t key_len;
    int ind = 0;

    // Linear probing
    for(int i = 0; i < MAX_CHAIN_LEN; i++) {
        if(env->elems[curr].in_use) {
            key_len = env->elems[curr].key_len;
            strcmp_s(env->elems[curr].key, key_len, key, &ind);
            if(ind == 0) {
                // Found the correct body element
                free(env->elems[curr].body);
                free(env->elems[curr].key);

                env->elems[curr].in_use = false;
                env->elems[curr].key = NULL;
                env->elems[curr].body = NULL;

                return MSG_SUCCESS;
            }
        }

        curr = (curr + 1) % env->max_size;
    }

    return MSG_ERR_ELEM_NOT_EXIST;
}

msgbus_ret_t msgbus_msg_envelope_get(
        msg_envelope_t* env, const char* key, msg_envelope_elem_body_t** data)
{
    // If the key is NULL, then retrieve the blob, if one has been set
    if(key == NULL) {
        if(env->blob == NULL)
            return MSG_ERR_ELEM_NOT_EXIST;
        *data = env->blob;
        return MSG_SUCCESS;
    }

    if(env->content_type == CT_BLOB) {
        LOG_ERROR_0("Message envelope given key for blob retrieval");
        return MSG_ERR_ELEM_NOT_EXIST;
    }

    // Get intiial hash value
    uint32_t curr = hash_int(env, key);
    size_t key_len;
    int ind;

    // Linear probing
    for(int i = 0; i < MAX_CHAIN_LEN; i++) {
        if(env->elems[curr].in_use) {
            key_len = env->elems[curr].key_len;
            strcmp_s(env->elems[curr].key, key_len, key, &ind);
            if(ind == 0) {
                *data = env->elems[curr].body;
                return MSG_SUCCESS;
            }
        }

        curr = (curr + 1) % env->max_size;
    }

    // Make sure data is NULL
    data = NULL;

    return MSG_ERR_ELEM_NOT_EXIST;
}

int msgbus_msg_envelope_serialize(
        msg_envelope_t* env, msg_envelope_serialized_part_t** parts) {
    if(env->content_type == CT_BLOB) {
        msgbus_ret_t ret = msgbus_msg_envelope_serialize_parts_new(1, parts);
        if(ret != MSG_SUCCESS) {
            return ret;
        }

        (*parts)[0].shared = owned_blob_copy(env->blob->body.blob->shared);
        (*parts)[0].len  = (*parts)[0].shared->len;
        (*parts)[0].bytes  = (*parts)[0].shared->bytes;

        // Set part to own the data
        if(env->blob->body.blob->shared->owned) {
            (*parts)[0].shared->owned = true;
            env->blob->body.blob->shared->owned = false;
        }

        // Only a single part for CT_BLOBs
        return 1;
    } else if(env->content_type == CT_JSON) {
        // Initialize JSON object
        cJSON* obj = cJSON_CreateObject();

        for(int i = 0; i < env->max_size; i++) {
            msg_envelope_elem_t* elem = &env->elems[i];

            // Pass by elements that are not in use in the hashmap
            if(!elem->in_use)
                continue;

            cJSON* subobj = NULL;

            if(elem->body->type == MSG_ENV_DT_INT) {
                subobj = cJSON_CreateNumber(elem->body->body.integer);
            } else if(elem->body->type == MSG_ENV_DT_FLOATING) {
                subobj = cJSON_CreateNumber(elem->body->body.floating);
            } else if(elem->body->type == MSG_ENV_DT_STRING) {
                subobj = cJSON_CreateString(elem->body->body.string);
            } else if(elem->body->type == MSG_ENV_DT_BOOLEAN) {
                subobj = cJSON_CreateBool(elem->body->body.boolean);
            } else {
                // This should NEVER happen, type has to have been set
                LOG_ERROR_0("This should never have happened...");
            }

            // Add the item to the JSON

            cJSON_AddItemToObject(obj, elem->key, subobj);
        }

        // Calculate number of parts for the serialized message
        int num_parts = 1;
        if(env->blob != NULL)
            num_parts++;

        // Initialize parts
        msgbus_ret_t ret = msgbus_msg_envelope_serialize_parts_new(
                num_parts, parts);
        if(ret != MSG_SUCCESS) {
            cJSON_Delete(obj);
            return -1;
        }

        // Add JSON part
        char* json_bytes = cJSON_PrintUnformatted(obj);

        // TODO: Check if shared is NULL
        (*parts)[0].shared = owned_blob_new(
                (void*) json_bytes, free, json_bytes, strlen(json_bytes));
        (*parts)[0].len  = (*parts)[0].shared->len;
        (*parts)[0].bytes  = (*parts)[0].shared->bytes;

        // Add blob part if one exists
        if(env->blob != NULL) {
            (*parts)[1].shared = owned_blob_copy(env->blob->body.blob->shared);
            (*parts)[1].len  = (*parts)[1].shared->len;
            (*parts)[1].bytes  = (*parts)[1].shared->bytes;

            if(env->blob->body.blob->shared->owned) {
                (*parts)[1].shared->owned = true;
                env->blob->body.blob->shared->owned = false;
            }
        }

        // Destroy JSON object
        cJSON_Delete(obj);

        return num_parts;
    } else {
        // This should never be reached, since the content type has to have
        // been set to one of the values defined in the content_type_t enum
        LOG_ERROR_0("This should never have happened...");
        return -1;
    }
}

int parse_json_object(msg_envelope_t* env, const char* key, cJSON* obj) {
    msg_envelope_elem_body_t* data = NULL;

    if(cJSON_IsArray(obj)) {
        LOG_ERROR_0("Message envelope does not support JSON arrays");
        return -1;
    } else if(cJSON_IsObject(obj)) {
        int elems = cJSON_GetArraySize(obj);
        for(int i = 0; i < elems; i++) {
            cJSON* next = cJSON_GetArrayItem(obj, i);
            int rc = parse_json_object(env, next->string, next);
            if(rc != 0) {
                return -1;
            }
        }

        // Return early because all nested items have been added
        return 0;
    } else if(cJSON_IsBool(obj)) {
        data = (msg_envelope_elem_body_t*) malloc(
               sizeof(msg_envelope_elem_body_t));
        data->type = MSG_ENV_DT_BOOLEAN;
        if(cJSON_IsTrue(obj))
            data->body.boolean = true;
        else
            data->body.boolean = false;
    } else if(cJSON_IsNumber(obj)) {
        double value = obj->valuedouble;
        data = (msg_envelope_elem_body_t*) malloc(
               sizeof(msg_envelope_elem_body_t));
        if(value == (int64_t) value) {
            data->type = MSG_ENV_DT_INT;
            data->body.integer = (int64_t) value;
        } else {
            data->type = MSG_ENV_DT_FLOATING;
            data->body.floating = value;
        }
    } else if(cJSON_IsString(obj)) {
        size_t len = strlen(obj->valuestring) + 1;
        data = (msg_envelope_elem_body_t*) malloc(
               sizeof(msg_envelope_elem_body_t));
        data->type = MSG_ENV_DT_STRING;
        data->body.string = (char*) malloc(sizeof(char) * len);
        memcpy_s(data->body.string, len, obj->valuestring, len);
        data->body.string[len - 1] = '\0';
    }

    if(key == NULL)
        LOG_ERROR_0("Key should not be NULL");

    msgbus_ret_t ret = msgbus_msg_envelope_put(env, key, data);
    if(ret != MSG_SUCCESS) {
        LOG_ERROR("Failed to put deserialized JSON: %s (errno: %d)", key, ret);
        return -1;
    }

    return 0;
}

/**
 * Helper function to deserialize a blob and add it to the given message
 * envelope.
 */
msgbus_ret_t deserialize_blob(
        msg_envelope_t* msg, msg_envelope_serialized_part_t* part)
{
    LOG_DEBUG_0("Deserializing BLOB");

    // Intiailize blob element
    size_t len = part->len;
    msg_envelope_blob_t* blob = (msg_envelope_blob_t*) malloc(
            sizeof(msg_envelope_blob_t));
    if(blob == NULL) return MSG_ERR_NO_MEMORY;
    blob->len = len;
    blob->data = part->bytes;
    blob->shared = owned_blob_copy(part->shared);

    // Take ownership of the underlying shared pointer to the blob data from
    // the serialized part. This way the data will not be freed until the
    // message envelope is not longerr needed
    blob->shared->owned = true;
    part->shared->owned = false;

    // Initialize body element
    msg_envelope_elem_body_t* elem = (msg_envelope_elem_body_t*) malloc(
            sizeof(msg_envelope_elem_body_t));
    if(elem == NULL) {
        owned_blob_destroy(blob->shared);
        free(blob);
        return MSG_ERR_NO_MEMORY;
    }
    elem->type = MSG_ENV_DT_BLOB;
    elem->body.blob = blob;

    // Put value into msg envelope
    msgbus_ret_t ret = msgbus_msg_envelope_put(msg, NULL, elem);
    if(ret != MSG_SUCCESS) {
        msgbus_msg_envelope_elem_destroy(elem);
    }

    return ret;
}

msgbus_ret_t msgbus_msg_envelope_deserialize(
        content_type_t ct, msg_envelope_serialized_part_t* parts,
        int num_parts, msg_envelope_t** env)
{
    msgbus_ret_t ret = MSG_SUCCESS;
    msg_envelope_t* msg = msgbus_msg_envelope_new(ct);
    if(msg == NULL) return MSG_ERR_UNKNOWN;

    if(ct == CT_BLOB) {
        if(num_parts > 1) {
            LOG_ERROR_0("CT_BLOB should only have one serialized part");
            msgbus_msg_envelope_destroy(msg);
            return MSG_ERR_UNKNOWN;
        }

        ret = deserialize_blob(msg, &parts[0]);
        if(ret != MSG_SUCCESS) {
            msgbus_msg_envelope_destroy(msg);
        }
    } else if(ct == CT_JSON) {
        if(num_parts > 2) {
            LOG_ERROR_0("CT_JSON can only have up to 2 serialized parts");
            msgbus_msg_envelope_destroy(msg);
            return MSG_ERR_UNKNOWN;
        }

        LOG_DEBUG_0("Deserializing JSON");
        cJSON* json = cJSON_Parse(parts[0].bytes);
        if(json == NULL) {
            LOG_ERROR("Failed to parse JSON: %s", cJSON_GetErrorPtr());
            msgbus_msg_envelope_destroy(msg);
            return MSG_ERR_UNKNOWN;
        }

        int rc = parse_json_object(msg, NULL, json);
        if(rc != 0)
            ret = MSG_ERR_UNKNOWN;

        // Free JSON structure
        cJSON_Delete(json);

        if(num_parts == 2) {
            ret = deserialize_blob(msg, &parts[1]);
            if(ret != MSG_SUCCESS) {
                msgbus_msg_envelope_destroy(msg);
            }
        }
    } else {
        LOG_ERROR_0("This should never have happened...");
        return MSG_ERR_UNKNOWN;
    }

    if(ret == MSG_SUCCESS)
        *env = msg;
    else
        msgbus_msg_envelope_destroy(msg);
    return ret;
}

msgbus_ret_t msgbus_msg_envelope_serialize_parts_new(
        int num_parts, msg_envelope_serialized_part_t** parts)
{
    *parts = (msg_envelope_serialized_part_t*) malloc(
            sizeof(msg_envelope_serialized_part_t) * num_parts);
    if(parts == NULL) {
        LOG_ERROR_0("Failed to initialize serialized parts");
        return MSG_ERR_NO_MEMORY;
    }

    // Initialize initial values
    for(int i = 0; i < num_parts; i++) {
        (*parts)[i].shared = NULL;
        (*parts)[i].len = 0;
        (*parts)[i].bytes = NULL;
    }

    return MSG_SUCCESS;
}

void msgbus_msg_envelope_serialize_destroy(
        msg_envelope_serialized_part_t* parts, int num_parts) {
    for(int i = 0; i < num_parts; i++) {
        if(parts[i].shared != NULL)
            owned_blob_destroy(parts[i].shared);
    }
    free(parts);
}

void msgbus_msg_envelope_destroy(msg_envelope_t* env) {
    if(env->blob != NULL)
        msgbus_msg_envelope_elem_destroy(env->blob);

    for(int i = 0; i < env->max_size; i++) {
        if(env->elems[i].in_use) {
            msgbus_msg_envelope_elem_destroy(env->elems[i].body);
            free(env->elems[i].key);
        }
    }

    free(env->elems);
    free(env);
}
