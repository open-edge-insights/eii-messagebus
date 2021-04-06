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
 */

#include <stdlib.h>

#include <stdio.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <cjson/cJSON.h>
#include <safe_lib.h>

#include "eii/msgbus/msg_envelope.h"

#define INITIAL_SIZE 32

/**
 * Internal method for freeing a msg_envelope_body_t from a hashmap
 */
static void free_elem(void* vargs) {
    msgbus_msg_envelope_elem_destroy((msg_envelope_elem_body_t*) vargs);
}

msg_envelope_t* msgbus_msg_envelope_new(content_type_t ct) {
    msg_envelope_t* env = (msg_envelope_t*) malloc(sizeof(msg_envelope_t));
    if(!env) goto err;

    env->correlation_id = NULL; // TODO: Need to assign this
    env->content_type = ct;
    env->blob = NULL;
    env->name = NULL; // topic name/ service name
    env->multi_blob_flag = false;

    if(ct == CT_BLOB) {
        env->map = NULL;
    } else {
        env->map = hashmap_new(INITIAL_SIZE);
        if(env->map == NULL)
            goto err;
    }

    return env;

err:
    if(env)
        msgbus_msg_envelope_destroy(env);
    return NULL;
}

msg_envelope_elem_body_t* msgbus_msg_envelope_new_none() {
    msg_envelope_elem_body_t* elem = (msg_envelope_elem_body_t*) malloc(
            sizeof(msg_envelope_elem_body_t));
    if(elem == NULL) {
        return NULL;
    }

    // Initialize element values
    elem->type = MSG_ENV_DT_NONE;

    return elem;
}

msg_envelope_elem_body_t* msgbus_msg_envelope_new_array() {
    msg_envelope_elem_body_t* elem = (msg_envelope_elem_body_t*) malloc(
            sizeof(msg_envelope_elem_body_t));
    if(elem == NULL) {
        return NULL;
    }

    // Initialize element values
    elem->type = MSG_ENV_DT_ARRAY;
    elem->body.array = linkedlist_new();
    if(elem->body.array == NULL) {
        free(elem);
        return NULL;
    }

    return elem;
}

msg_envelope_elem_body_t* msgbus_msg_envelope_new_object() {
    msg_envelope_elem_body_t* elem = (msg_envelope_elem_body_t*) malloc(
            sizeof(msg_envelope_elem_body_t));
    if(elem == NULL) {
        return NULL;
    }

    // Initializing underlying hashmap structure for the object.
    hashmap_t* map = hashmap_new(INITIAL_SIZE);
    if(map == NULL) {
        free(elem);
        return NULL;
    }

    // Initialize element values
    elem->type = MSG_ENV_DT_OBJECT;
    elem->body.object = map;

    return elem;
}

msg_envelope_elem_body_t* msgbus_msg_envelope_new_string(const char* string) {
    msg_envelope_elem_body_t* elem = (msg_envelope_elem_body_t*) malloc(
            sizeof(msg_envelope_elem_body_t));
    if(elem == NULL) {
        return NULL;
    }

    size_t len = strlen(string);

    elem->type = MSG_ENV_DT_STRING;
    elem->body.string = (char*) malloc(sizeof(char) * (len + 1));
    if(elem->body.string == NULL) {
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
        goto err;
    }

    blob = (msg_envelope_blob_t*) malloc(sizeof(msg_envelope_blob_t));
    if(blob == NULL) {
        goto err;
    }
    blob->shared = shared;
    blob->len = shared->len;
    blob->data = shared->bytes;

    elem = (msg_envelope_elem_body_t*) malloc(
            sizeof(msg_envelope_elem_body_t));
    if(elem == NULL) {
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
    return NULL;
}

msgbus_ret_t msgbus_msg_envelope_elem_object_put(
        msg_envelope_elem_body_t* obj, const char* key,
        msg_envelope_elem_body_t* value)
{
    // Verify that the given msg envelope element is an object
    if(obj->type != MSG_ENV_DT_OBJECT)
        return MSG_ERR_ELEM_OBJ;

    // Attempt to put the element into the object hashmap
    hashmap_ret_t ret = hashmap_put(
            obj->body.object, key, (void*) value, free_elem);
    if(ret != MAP_SUCCESS) {
        if(ret == MAP_KEY_EXISTS)
            return MSG_ERR_ELEM_ALREADY_EXISTS;
        return MSG_ERR_ELEM_OBJ;
    }

    return MSG_SUCCESS;
}

msg_envelope_elem_body_t* msgbus_msg_envelope_elem_object_get(
        msg_envelope_elem_body_t* obj, const char* key)
{
    // Verify that the given msg envelope element is an object
    if(obj->type != MSG_ENV_DT_OBJECT)
        return NULL;

    // Retrieve the value (if it exists) from the hashmap of the object
    void* value = hashmap_get(obj->body.object, key);
    if(value == NULL)
        return NULL;

    return (msg_envelope_elem_body_t*) value;
}

msgbus_ret_t msgbus_msg_envelope_elem_object_remove(
        msg_envelope_elem_body_t* obj, const char* key)
{
    // Verify that the given msg envelope element is an object
    if(obj->type != MSG_ENV_DT_OBJECT)
        return MSG_ERR_ELEM_OBJ;

    // Attempt to remove the element from the underlying hashmap
    hashmap_ret_t ret = hashmap_remove(obj->body.object, key);
    if(ret != MAP_SUCCESS) {
        return MSG_ERR_ELEM_NOT_EXIST;
    }

    return MSG_SUCCESS;
}

msgbus_ret_t msgbus_msg_envelope_elem_array_add(
        msg_envelope_elem_body_t* arr,
        msg_envelope_elem_body_t* value)
{
    // Verify that the given msg envelope element is an array
    if(arr->type != MSG_ENV_DT_ARRAY)
        return MSG_ERR_ELEM_ARR;

    // Initialize the new node to add
    node_t* node = linkedlist_node_new(value, free_elem);
    if(node == NULL)
        return MSG_ERR_ELEM_ARR;

    // Attempt to add the element to the array's linked list
    linkedlist_ret_t ret = linkedlist_add(arr->body.array, node);
    if(ret != LL_SUCCESS)
        return MSG_ERR_ELEM_ARR;

    return MSG_SUCCESS;
}

msg_envelope_elem_body_t* msgbus_msg_envelope_elem_array_get_at(
        msg_envelope_elem_body_t* arr, int idx)
{
    // Verify that the given msg envelope element is an array
    if(arr->type != MSG_ENV_DT_ARRAY)
        return NULL;

    // Attempt to get the element to the array's linked list
    node_t* node = linkedlist_get_at(arr->body.array, idx);
    if(node == NULL)
        return NULL;
    else
        return (msg_envelope_elem_body_t*) node->value;
}

msgbus_ret_t msgbus_msg_envelope_elem_array_remove_at(
        msg_envelope_elem_body_t* arr, int idx)
{
    // Verify that the given msg envelope element is an array
    if(arr->type != MSG_ENV_DT_ARRAY)
        return MSG_ERR_ELEM_ARR;

    // Attempt to add the element to the array's linked list
    linkedlist_ret_t ret = linkedlist_remove_at(arr->body.array, idx);
    if(ret == LL_ERR_NOT_FOUND)
        return MSG_ERR_ELEM_NOT_EXIST;

    return MSG_SUCCESS;
}


void msgbus_msg_envelope_elem_destroy(msg_envelope_elem_body_t* body) {
    if(body->type == MSG_ENV_DT_STRING) {
        free(body->body.string);
    } else if(body->type == MSG_ENV_DT_BLOB) {
        owned_blob_destroy(body->body.blob->shared);
        free(body->body.blob);
    } else if(body->type == MSG_ENV_DT_OBJECT) {
        hashmap_destroy(body->body.object);
    } else if(body->type == MSG_ENV_DT_ARRAY) {
        linkedlist_destroy(body->body.array);
    }
    free(body);
}

msgbus_ret_t msgbus_msg_envelope_put(
        msg_envelope_t* env, const char* key, msg_envelope_elem_body_t* data)
{
    msgbus_ret_t ret = MSG_SUCCESS;
    if (key == NULL) {
        if (data->type != MSG_ENV_DT_BLOB) {
            // The body type must be a MSG_ENV_DT_BLOB
            return MSG_ERR_ELEM_BLOB_MALFORMED;
        }
        if (env->blob != NULL) {
            if (env->multi_blob_flag == false) {
                env->multi_blob_flag = true;
                // Create linked list array to store multi blobs
                // if first multi blob
                msg_envelope_elem_body_t* arr_data =\
                    msgbus_msg_envelope_new_array();
                if (arr_data == NULL) {
                    return MSG_ERR_NO_MEMORY;
                }
                // Fetch and add first single blob
                ret = msgbus_msg_envelope_elem_array_add(arr_data, env->blob);
                if (ret != MSG_SUCCESS) {
                    msgbus_msg_envelope_elem_destroy(arr_data);
                    return ret;
                }
                // Add current blob
                ret = msgbus_msg_envelope_elem_array_add(arr_data, data);
                if (ret != MSG_SUCCESS) {
                    msgbus_msg_envelope_elem_destroy(arr_data);
                    return ret;
                }
                // Set env->blob to array
                env->blob = arr_data;
            } else {
                ret = msgbus_msg_envelope_elem_array_add(env->blob, data);
                if (ret != MSG_SUCCESS) {
                    return ret;
                }
            }
        } else {
            // Add first single blob
            env->blob = data;
        }
    } else {
        hashmap_ret_t put_ret = hashmap_put(
                env->map, key, (void*) data, free_elem);
        if(put_ret != MAP_SUCCESS) {
            // The only possible errors returned from hashmap_put() are
            // MAP_OMEM and MAP_KEY_EXISTS
            if(put_ret == MAP_KEY_EXISTS) {
                return MSG_ERR_ELEM_ALREADY_EXISTS;
            } else {
                return MSG_ERR_NO_MEMORY;
            }
        }
    }

    return ret;
}

msgbus_ret_t msgbus_msg_envelope_remove(msg_envelope_t* env, const char* key) {
    // Immediately return if the message is a blob
    if(env->content_type == CT_BLOB)
        return MSG_ERR_ELEM_NOT_EXIST;

    hashmap_ret_t ret = hashmap_remove(env->map, key);
    if(ret != MAP_SUCCESS)
        return MSG_ERR_ELEM_ALREADY_EXISTS;
    else
        return MSG_SUCCESS;
}

msgbus_ret_t msgbus_msg_envelope_get(
        msg_envelope_t* env, const char* key, msg_envelope_elem_body_t** data)
{
    // If the key is NULL, then retrieve the blob, if one has been set
    if (key == NULL) {
        if (env->blob == NULL)
            return MSG_ERR_ELEM_NOT_EXIST;
        *data = env->blob;
        return MSG_SUCCESS;
    }

    if (env->content_type == CT_BLOB) {
        return MSG_ERR_ELEM_NOT_EXIST;
    }

    (*data) = (msg_envelope_elem_body_t*) hashmap_get(env->map, key);
    if((*data) == NULL) {
        return MSG_ERR_ELEM_NOT_EXIST;
    } else {
        return MSG_SUCCESS;
    }
}

/**
 * Recursive function to convert @c msg_envelope_elem_body elements into
 * @c cJSON object.
 */
static cJSON* elem_to_json(msg_envelope_elem_body_t* elem) {
    cJSON* obj = NULL;

    switch(elem->type) {
        case MSG_ENV_DT_INT:
            obj = cJSON_CreateNumber(elem->body.integer);
            break;
        case MSG_ENV_DT_FLOATING:
            obj = cJSON_CreateNumber(elem->body.floating);
            break;
        case MSG_ENV_DT_STRING:
            obj = cJSON_CreateString(elem->body.string);
            break;
        case MSG_ENV_DT_BOOLEAN:
            obj = cJSON_CreateBool(elem->body.boolean);
            break;
        case MSG_ENV_DT_OBJECT:
            obj = cJSON_CreateObject();
            if(obj == NULL) break;  // Failed to initialize JSON object...

            // Get pointer to the map to make code cleaner going forward
            hashmap_t* map = elem->body.object;

            // Loop over all hashmap items... This could probably be improved
            HASHMAP_LOOP(map, msg_envelope_elem_body_t, {
                cJSON* subobj = elem_to_json(value);
                if(subobj == NULL) {
                    // Failed to create a sub-JSON object
                    cJSON_Delete(obj);
                    obj = NULL;
                    break;
                }
                // Add the object to the JSON object
                cJSON_AddItemToObject(obj, key, subobj);
            });
            break;
        case MSG_ENV_DT_ARRAY:
            obj = cJSON_CreateArray();
            if(obj == NULL) break; // Failed to initialize JSON object...

            LINKEDLIST_FOREACH(elem->body.array, msg_envelope_elem_body_t, {
                cJSON* subobj = elem_to_json(value);
                if(subobj == NULL) {
                    // Failed to create a sub-JSON object
                    cJSON_Delete(obj);
                    obj = NULL;
                    break;
                }
                // Add the array item to the JSON array
                cJSON_AddItemToArray(obj, subobj);
            });
            break;
        case MSG_ENV_DT_NONE:
            obj = cJSON_CreateNull();
            break;
        // Blob should never happen...
        case MSG_ENV_DT_BLOB:
        default:
            break;
    }

    return obj;
}


/**
 * Helper function to serialize a blob into a given serialized part.
 * 
 * @param dest - Destination serialized part for the blob
 * @param blob - Blob to serialize
 */ 
static void serialize_blob(
        msg_envelope_serialized_part_t* dest, msg_envelope_elem_body_t* blob) {
    dest->shared = owned_blob_copy(blob->body.blob->shared);
    dest->len  = dest->shared->len;
    dest->bytes  = dest->shared->bytes;

    // Set part to own the data
    if(blob->body.blob->shared->owned) {
        dest->shared->owned = true;
        blob->body.blob->shared->owned = false;
    }
}


int msgbus_msg_envelope_serialize(
        msg_envelope_t* env, msg_envelope_serialized_part_t** parts) {
    if(env->content_type == CT_BLOB) {
        if (env->blob == NULL)
            return -1;
        // For single only blob scenario
        if (env->blob->type == MSG_ENV_DT_BLOB) {
            msgbus_ret_t ret = \
                msgbus_msg_envelope_serialize_parts_new(1, parts);
            if (ret != MSG_SUCCESS) {
                return ret;
            }

            // Serialize the blob into the given serialized part
            serialize_blob(&(*parts)[0], env->blob);

            // Only a single part for CT_BLOBs
            return 1;
        } else if (env->blob->type == MSG_ENV_DT_ARRAY) {
            // For only multi blob scenario
            int num_parts = env->blob->body.array->len;
            msgbus_ret_t ret = \
                msgbus_msg_envelope_serialize_parts_new(num_parts, parts);
            if (ret != MSG_SUCCESS) {
                return ret;
            }

            for (int i = 0; i < num_parts; i++) {
                msg_envelope_elem_body_t* arr_blob = \
                    msgbus_msg_envelope_elem_array_get_at(env->blob, i);
                serialize_blob(&(*parts)[i], arr_blob);
            }
            // Total number of parts
            return num_parts;
        }
    } else if (env->content_type == CT_JSON) {
        // For single blob + json scenario
        int num_parts = 1;
        // Initialize JSON object
        cJSON* obj = cJSON_CreateObject();
        HASHMAP_LOOP(env->map, msg_envelope_elem_body_t, {
            cJSON* subobj = elem_to_json(value);
            if (subobj == NULL) {
                cJSON_Delete(obj);
                break;
            }
            // Add the item to the root JSON object
            cJSON_AddItemToObject(obj, key, subobj);
        });

        // If the object is NULL at this point, then a JSON serialization error
        // occurred
        if (obj == NULL)
            return -1;

        if (env->blob != NULL) {
            if (env->blob->type == MSG_ENV_DT_BLOB) {
                // Calculate number of parts for the serialized message
                // Increment num_parts by 1 for one blob
                num_parts++;

                // Initialize parts
                msgbus_ret_t ret = msgbus_msg_envelope_serialize_parts_new(
                        num_parts, parts);
                if (ret != MSG_SUCCESS) {
                    cJSON_Delete(obj);
                    return -1;
                }

                // Serialize blob
                serialize_blob(&(*parts)[1], env->blob);
            } else if (env->blob->type == MSG_ENV_DT_ARRAY) {
                // For multi blob + json scenario
                // Calculate number of parts for the serialized message
                num_parts = env->blob->body.array->len + 1;

                // Initialize parts
                msgbus_ret_t ret = msgbus_msg_envelope_serialize_parts_new(
                        num_parts, parts);
                if (ret != MSG_SUCCESS) {
                    cJSON_Delete(obj);
                    return -1;
                }

                for (int i = 1; i < num_parts; i++) {
                    msg_envelope_elem_body_t* arr_blob = \
                        msgbus_msg_envelope_elem_array_get_at(env->blob, i-1);
                    // Serialize every blob in blob array
                    serialize_blob(&(*parts)[i], arr_blob);
                }
            }
        } else {
            // No blobs to add the the message, initialize a single part for
            // the JSON data
            msgbus_ret_t ret = msgbus_msg_envelope_serialize_parts_new(
                    num_parts, parts);
            if (ret != MSG_SUCCESS) {
                cJSON_Delete(obj);
                return -1;
            }
        }

        // Add JSON part
        char* json_bytes = cJSON_PrintUnformatted(obj);

        // TODO: Check if shared is NULL
        (*parts)[0].shared = owned_blob_new(
                (void*) json_bytes, free, json_bytes, strlen(json_bytes));
        (*parts)[0].len  = (*parts)[0].shared->len;
        (*parts)[0].bytes  = (*parts)[0].shared->bytes;

        // Destroy JSON object
        cJSON_Delete(obj);

        return num_parts;
    }

    // This is ultimately an error, and this should never be reached.
    // However, this must be here to avoid a compiler warning
    return -1;
}

/**
 * Helper function to recursivly deserialize JSON objects into
 * msg_envelope_elem_body_t structures.
 */
static msg_envelope_elem_body_t* deserialize_json(cJSON* obj) {
    msg_envelope_elem_body_t* elem = NULL;

    if(cJSON_IsArray(obj)) {
        elem = msgbus_msg_envelope_new_array();
        if(elem == NULL)
            return NULL;

        cJSON* subobj = NULL;
        msgbus_ret_t ret = MSG_SUCCESS;

        cJSON_ArrayForEach(subobj, obj) {
            msg_envelope_elem_body_t* subelem = deserialize_json(subobj);
            if(subelem == NULL) {
                msgbus_msg_envelope_elem_destroy(elem);
                elem = NULL;
                break;
            }

            ret = msgbus_msg_envelope_elem_array_add(elem, subelem);
            if(ret != MSG_SUCCESS) {
                msgbus_msg_envelope_elem_destroy(subelem);
                msgbus_msg_envelope_elem_destroy(elem);
                elem = NULL;
                break;
            }
        }
    } else if(cJSON_IsObject(obj)) {
        elem = msgbus_msg_envelope_new_object();
        if(elem == NULL)
            return NULL;

        cJSON* subobj = NULL;
        msgbus_ret_t ret = MSG_SUCCESS;

        cJSON_ArrayForEach(subobj, obj) {
            msg_envelope_elem_body_t* subelem = deserialize_json(subobj);
            if(subelem == NULL) {
                msgbus_msg_envelope_elem_destroy(elem);
                return NULL;
            }

            ret = msgbus_msg_envelope_elem_object_put(
                    elem, subobj->string, subelem);
            if(ret != MSG_SUCCESS) {
                msgbus_msg_envelope_elem_destroy(subelem);
                msgbus_msg_envelope_elem_destroy(elem);
                elem = NULL;
                break;
            }
        }
    } else if(cJSON_IsBool(obj)) {
        if(cJSON_IsTrue(obj))
            elem = msgbus_msg_envelope_new_bool(true);
        else
            elem = msgbus_msg_envelope_new_bool(false);
    } else if(cJSON_IsNumber(obj)) {
        double value = obj->valuedouble;
        if(value == (int64_t) value)
            elem = msgbus_msg_envelope_new_integer((int64_t) value);
        else
            elem = msgbus_msg_envelope_new_floating(value);
    } else if(cJSON_IsString(obj)) {
        elem = msgbus_msg_envelope_new_string(obj->valuestring);
    } else if(cJSON_IsNull(obj)) {
        elem = msgbus_msg_envelope_new_none();
    } else {
        return NULL;
    }

    return elem;
}

/**
 * Helper function to deserialize a blob and add it to the given message
 * envelope.
 */
static msgbus_ret_t deserialize_blob(
        msg_envelope_t* msg, msg_envelope_serialized_part_t* part,
        int num_parts, content_type_t ct)
{

    msgbus_ret_t ret = MSG_SUCCESS;
    int i = 0;
    if (ct == CT_JSON) {
        // If json enabled, json is first part
        // Hence, traverse from second part
        i = 1;
    }
    for (; i < num_parts; i++) {
        msg_envelope_serialized_part_t* current_part = &part[i];
        // Intiailize blob element
        size_t len = current_part->len;
        msg_envelope_blob_t* blob = (msg_envelope_blob_t*) malloc(
                sizeof(msg_envelope_blob_t));
        if(blob == NULL) return MSG_ERR_NO_MEMORY;
        blob->len = len;
        blob->data = current_part->bytes;
        blob->shared = NULL;
        blob->shared = owned_blob_copy(current_part->shared);
        if(blob->shared == NULL) {
            free(blob);
            return MSG_ERR_NO_MEMORY;
        }

        // Take ownership of the underlying shared pointer to the blob data from
        // the serialized part. This way the data will not be freed until the
        // message envelope is not longerr needed
        blob->shared->owned = true;
        current_part->shared->owned = false;

        // Initialize body element
        msg_envelope_elem_body_t* elem = (msg_envelope_elem_body_t*) malloc(
                sizeof(msg_envelope_elem_body_t));
        if(elem == NULL) {
            if(blob->shared)
                owned_blob_destroy(blob->shared);
            free(blob);
            return MSG_ERR_NO_MEMORY;
        }
        elem->type = MSG_ENV_DT_BLOB;
        elem->body.blob = blob;

        // Put value into msg envelope
        ret = msgbus_msg_envelope_put(msg, NULL, elem);
        if (ret != MSG_SUCCESS) {
            msgbus_msg_envelope_elem_destroy(elem);
            return ret;
        }
    }
    return ret;
}

msgbus_ret_t msgbus_msg_envelope_deserialize(
        content_type_t ct, msg_envelope_serialized_part_t* parts,
        int num_parts, const char* name, msg_envelope_t** env)
{
    msgbus_ret_t ret = MSG_SUCCESS;
    msg_envelope_t* msg = msgbus_msg_envelope_new(ct);
    if(msg == NULL) return MSG_ERR_NO_MEMORY;

    if (ct == CT_BLOB) {
        ret = deserialize_blob(msg, parts, num_parts, ct);
        if (ret != MSG_SUCCESS) {
            return MSG_ERR_DESERIALIZE_FAILED;
        }
    } else if (ct == CT_JSON) {
        // For json + single blob scenario
        cJSON* json = cJSON_Parse(parts[0].bytes);
        if (json == NULL) {
            msgbus_msg_envelope_destroy(msg);
            return MSG_ERR_DESERIALIZE_FAILED;
        }

        // Start parsing the root level of the JSON object
        cJSON* subobj = NULL;
        cJSON_ArrayForEach(subobj, json) {
            msg_envelope_elem_body_t* elem = deserialize_json(subobj);
            if (elem == NULL) {
                ret = MSG_ERR_DESERIALIZE_FAILED;
                break;
            }
            ret = msgbus_msg_envelope_put(msg, subobj->string, elem);
            if (ret != MSG_SUCCESS) {
                msgbus_msg_envelope_elem_destroy(elem);
                break;
            }
        }

        // Free JSON structure
        cJSON_Delete(json);

        // Only deserialize the blob if the JSON was successfully parsed
        if (ret == MSG_SUCCESS && num_parts > 1) {
            ret = deserialize_blob(msg, parts, num_parts, ct);
        }
    }

    size_t len = strlen(name) + 1;
    msg->name = (char*) malloc(len);
    if (msg->name == NULL) {
        msgbus_msg_envelope_destroy(msg);
        return MSG_ERR_NO_MEMORY;
    }
    memset(msg->name, '\0', len);
    strcpy_s(msg->name, len, name);
    if (ret == MSG_SUCCESS)
        *env = msg;
    else
        msgbus_msg_envelope_destroy(msg);
    return ret;
}

msgbus_ret_t msgbus_msg_envelope_serialize_parts_new(
        int num_parts, msg_envelope_serialized_part_t** parts)
{
    msg_envelope_serialized_part_t* tmp_parts =
        (msg_envelope_serialized_part_t*) malloc(
                sizeof(msg_envelope_serialized_part_t) * num_parts);
    if(tmp_parts == NULL) {
        return MSG_ERR_NO_MEMORY;
    }

    // Initialize initial values
    for(int i = 0; i < num_parts; i++) {
        tmp_parts[i].shared = NULL;
        tmp_parts[i].len = 0;
        tmp_parts[i].bytes = NULL;
    }

    // Assign user's variable
    *parts = tmp_parts;

    // Successfully initialized the serialized parts
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
    if(env->map != NULL)
        hashmap_destroy(env->map);
    if (env->name != NULL)
        free(env->name);
    free(env);
}

owned_blob_t* owned_blob_new(
        void* ptr, void (*free_fn)(void*), const char* data, size_t len)
{
    owned_blob_t* shared = (owned_blob_t*) malloc(sizeof(owned_blob_t));
    if(shared == NULL) {
        return NULL;
    }

    shared->ptr = ptr;
    shared->free = free_fn;
    shared->owned = true;
    shared->len = len;
    shared->bytes = data;

    return shared;
}

owned_blob_t* owned_blob_copy(owned_blob_t* to_copy) {
    owned_blob_t* shared = (owned_blob_t*) malloc(sizeof(owned_blob_t));
    if(shared == NULL) {
        return NULL;
    }

    shared->ptr = to_copy->ptr;
    shared->free = to_copy->free;
    shared->len = to_copy->len;
    shared->bytes = to_copy->bytes;
    shared->owned = false;  // This is important to note!

    return shared;
}

void owned_blob_destroy(owned_blob_t* shared) {
    if(shared->owned)
        shared->free(shared->ptr);
    free(shared);
}
