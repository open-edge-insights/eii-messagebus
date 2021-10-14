// Copyright (c) 2021 Intel Corporation.
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
 * @brief MsgEnvelope Implementation
 * Holds the implementaion of APIs supported by MsgEnvelope & MsgEnvelopeArray class
 */


#include <sstream>
#include "eii/msgbus/msg_envelope.hpp"

using namespace eii::msgbus;


#define MSG_ENV_DT_CASE(ret) \
    case ret: return #ret;

const char* msgbus_msg_envelope_elem_type_str(msg_envelope_data_type_t dt) {
    switch (dt) {
    MSG_ENV_DT_CASE(MSG_ENV_DT_INT)
    MSG_ENV_DT_CASE(MSG_ENV_DT_FLOATING)
    MSG_ENV_DT_CASE(MSG_ENV_DT_STRING)
    MSG_ENV_DT_CASE(MSG_ENV_DT_BOOLEAN)
    MSG_ENV_DT_CASE(MSG_ENV_DT_BLOB)
    MSG_ENV_DT_CASE(MSG_ENV_DT_OBJECT)
    MSG_ENV_DT_CASE(MSG_ENV_DT_ARRAY)
    MSG_ENV_DT_CASE(MSG_ENV_DT_NONE)
    default:
        return "";
    }
}

MsgbusException::MsgbusException(msgbus_ret_t ret, const char* msg) :
    m_ret(ret)
{
    const char* ret_str = msgbus_ret_str(ret);
    std::ostringstream os;
    os << "[" << ret_str << "(" << ret << ")] " << msg;
    m_msg = os.str();
}

msgbus_ret_t MsgbusException::get_msgbus_ret() {
    return m_ret;
}

MsgEnvelopeElement::~MsgEnvelopeElement() {
    if (m_elem != NULL) {
        msgbus_msg_envelope_elem_destroy(m_elem);
    }
}

MsgEnvelopeElement::MsgEnvelopeElement(msg_envelope_elem_body_t* elem) {
    if (elem == NULL) {
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Failed to create MsgEnvelopeElement");
    }
    m_elem = elem;
}

bool MsgEnvelopeElement::is_none() {
    if (m_elem->type == MSG_ENV_DT_NONE) {
        return true;
    }
    return false;
}

msg_envelope_data_type_t MsgEnvelopeElement::get_type() {
    return m_elem->type;
}

const char* MsgEnvelopeElement::get_type_str() {
    return msgbus_msg_envelope_elem_type_str(m_elem->type);
}

int64_t MsgEnvelopeElement::to_int() {
    if(m_elem->type != MSG_ENV_DT_INT) {
        msgbus_msg_envelope_elem_destroy(m_elem);
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Value type is not an integer");
    }
    return m_elem->body.integer;
}

const char* MsgEnvelopeElement::to_string() {
    if(m_elem->type != MSG_ENV_DT_STRING) {
        msgbus_msg_envelope_elem_destroy(m_elem);
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Value type is not a string");
    }
    return m_elem->body.string;
}

double MsgEnvelopeElement::to_float() {
    if(m_elem->type != MSG_ENV_DT_FLOATING) {
        msgbus_msg_envelope_elem_destroy(m_elem);
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Value type is not an integer");
    }
    return m_elem->body.floating;
}

bool MsgEnvelopeElement::to_bool() {
    if(m_elem->type != MSG_ENV_DT_BOOLEAN) {
        msgbus_msg_envelope_elem_destroy(m_elem);
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Value type is not an integer");
    }
    return m_elem->body.boolean;
}

MsgEnvelopeElement::MsgEnvelopeElement(const MsgEnvelopeElement& src) {
    throw "This object should not be copied";
}

MsgEnvelopeElement& MsgEnvelopeElement::operator=(const MsgEnvelopeElement& src) {
    return *this;
}

MsgEnvelope::MsgEnvelope(content_type_t ct) {
    msgbus_ret_t ret = MSG_SUCCESS;
    // Initializing C msg_envelope_elem_body_t object
    msg_envelope_t* msgenv = msgbus_msg_envelope_new(ct);
    if (msgenv == NULL) {
        msgbus_msg_envelope_destroy(msgenv);
        ret = MSG_ERR_NO_MEMORY;
        throw MsgbusException(ret, "Failed to create MsgEnvelope object");
    }
    m_msgenv = msgenv;
}

MsgEnvelope::MsgEnvelope(msg_envelope_t* msgenv) {
    msgbus_ret_t ret = MSG_SUCCESS;
    // Set m_msgenv to msgenv if user provides an
    // existing msg_envelope_t* object
    if (msgenv == NULL) {
        msgbus_msg_envelope_destroy(msgenv);
        ret = MSG_ERR_NO_MEMORY;
        throw MsgbusException(ret, "NULL msg_envelope_t is not allowed");
    }
    m_msgenv = msgenv;
}

MsgEnvelope::MsgEnvelope(const MsgEnvelope& src) {
    throw "This object should not be copied";
}

MsgEnvelope& MsgEnvelope::operator=(const MsgEnvelope& src) {
    return *this;
}

void MsgEnvelope::put_integer(std::string key, int64_t value) {
    if (m_msgenv == NULL) {
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Message Envelope already consumed, "
                              "unable to add to message envelope");
    }
    msgbus_ret_t ret = msgbus_msg_envelope_put_integer(m_msgenv, key.c_str(), value);
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to put elem into message envelope");
    }
}

void MsgEnvelope::put_string(std::string key, std::string value) {
    if (m_msgenv == NULL) {
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Message Envelope already consumed, "
                              "unable to add to message envelope");
    }
    msgbus_ret_t ret = msgbus_msg_envelope_put_string(m_msgenv, key.c_str(), value.c_str());
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to put elem into message envelope");
    }
}

void MsgEnvelope::put_float(std::string key, double value) {
    if (m_msgenv == NULL) {
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Message Envelope already consumed, "
                              "unable to add to message envelope");
    }
    msgbus_ret_t ret = msgbus_msg_envelope_put_float(m_msgenv, key.c_str(), value);
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to put elem into message envelope");
    }
}

void MsgEnvelope::put_bool(std::string key, bool value) {
    if (m_msgenv == NULL) {
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Message Envelope already consumed, "
                              "unable to add to message envelope");
    }
    msgbus_ret_t ret = msgbus_msg_envelope_put_bool(m_msgenv, key.c_str(), value);
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to put elem into message envelope");
    }
}

void MsgEnvelope::put_array(std::string key, MsgEnvelopeArray* value) {
    if (m_msgenv == NULL) {
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Message Envelope already consumed, "
                              "unable to add to message envelope");
    }
    msgbus_ret_t ret = msgbus_msg_envelope_put(m_msgenv,
                                               key.c_str(),
                                               value->get_msg_envelope_array());
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to add array into message envelope");
    }
}

void MsgEnvelope::put_object(std::string key, MsgEnvelopeObject* value) {
    if (m_msgenv == NULL) {
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Message Envelope already consumed, "
                              "unable to add to message envelope");
    }
    msgbus_ret_t ret = msgbus_msg_envelope_put(m_msgenv,
                                               key.c_str(),
                                               value->get_msg_envelope_object());
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to add object into message envelope");
    }
}

void MsgEnvelope::put_blob(char* value, size_t size) {
    if (m_msgenv == NULL) {
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Message Envelope already consumed, "
                              "unable to add to message envelope");
    }
    msgbus_ret_t ret = MSG_SUCCESS;
    msg_envelope_elem_body_t* blob = \
        msgbus_msg_envelope_new_blob(value, size);
    if (blob == NULL) {
        ret = MSG_ERR_NO_MEMORY;
        throw MsgbusException(ret, "Failed to create blob");
    }
    ret = msgbus_msg_envelope_put(m_msgenv, NULL, blob);
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to add blob into MsgEnvelope");
    }
}

void MsgEnvelope::remove(std::string key) {
    if (m_msgenv == NULL) {
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Message Envelope already consumed, "
                              "unable to remove from message envelope");
    }
    msgbus_ret_t ret = MSG_SUCCESS;
    ret = msgbus_msg_envelope_remove(m_msgenv, key.c_str());
    if (ret == MSG_ERR_ELEM_NOT_EXIST) {
        throw MsgbusException(ret, "Element at provided index not found");
    }
}

msg_envelope_t* MsgEnvelope::get_msg_envelope() {
    msg_envelope_t* msgenv = m_msgenv;
    // Consume the message envelope
    if (m_msgenv != NULL) {
        m_msgenv = NULL;
    }
    return msgenv;
}

int64_t MsgEnvelope::get_int(const std::string key) {
    msg_envelope_elem_body_t* body = NULL;
    msgbus_ret_t ret = msgbus_msg_envelope_get(m_msgenv, key.c_str(), &body);
    if(ret != MSG_SUCCESS) {
        if (ret == MSG_ERR_ELEM_NOT_EXIST) {
            throw MsgbusException(ret, "Value for key not found");
        }
    }
    if(body->type != MSG_ENV_DT_INT) {
        throw MsgbusException(ret, "Value type is not an integer");
    }
    return body->body.integer;
}

const char* MsgEnvelope::get_string(const std::string key) {
    msg_envelope_elem_body_t* body = NULL;
    msgbus_ret_t ret = msgbus_msg_envelope_get(m_msgenv, key.c_str(), &body);
    if(ret != MSG_SUCCESS) {
        if (ret == MSG_ERR_ELEM_NOT_EXIST) {
            throw MsgbusException(ret, "Value for key not found");
        }
    }
    if(body->type != MSG_ENV_DT_STRING) {
        throw MsgbusException(ret, "Value type is not a string");
    }
    return body->body.string;
}

double MsgEnvelope::get_float(const std::string key) {
    msg_envelope_elem_body_t* body = NULL;
    msgbus_ret_t ret = msgbus_msg_envelope_get(m_msgenv, key.c_str(), &body);
    if(ret != MSG_SUCCESS) {
        if (ret == MSG_ERR_ELEM_NOT_EXIST) {
            throw MsgbusException(ret, "Value for key not found");
        }
    }
    if(body->type != MSG_ENV_DT_FLOATING) {
        throw MsgbusException(ret, "Value type is not a float");
    }
    return body->body.floating;
}

bool MsgEnvelope::get_bool(const std::string key) {
    msg_envelope_elem_body_t* body = NULL;
    msgbus_ret_t ret = msgbus_msg_envelope_get(m_msgenv, key.c_str(), &body);
    if(ret != MSG_SUCCESS) {
        if (ret == MSG_ERR_ELEM_NOT_EXIST) {
            throw MsgbusException(ret, "Value for key not found");
        }
    }
    if(body->type != MSG_ENV_DT_BOOLEAN) {
        throw MsgbusException(ret, "Value type is not a boolean");
    }
    return body->body.boolean;
}

MsgEnvelopeElement* MsgEnvelope::get_msg_envelope_element(const std::string key) {
    msg_envelope_elem_body_t* body = NULL;
    msgbus_ret_t ret = msgbus_msg_envelope_get(m_msgenv, key.c_str(), &body);
    if(ret != MSG_SUCCESS) {
        if (ret == MSG_ERR_ELEM_NOT_EXIST) {
            throw MsgbusException(ret, "Value for key not found");
        }
    }
    MsgEnvelopeElement* msg_envelope_elemnt = new MsgEnvelopeElement(body);
    return msg_envelope_elemnt;
}

MsgEnvelope::~MsgEnvelope() {
    if (m_msgenv != NULL) {
        msgbus_msg_envelope_destroy(m_msgenv);
    }
}

MsgEnvelopeArray::MsgEnvelopeArray() {
    m_arr = msgbus_msg_envelope_new_array();
    if (m_arr == NULL) {
        throw MsgbusException(
            MSG_ERR_NO_MEMORY, "Failed to create underlying msg envelope array");
    }
    m_owns_array = true;
}

MsgEnvelopeArray::MsgEnvelopeArray(msg_envelope_elem_body_t* arr, bool owns_array) {
    if (arr == NULL) {
        throw MsgbusException(
            MSG_ERR_UNKNOWN, "Failed to create underlying msg envelope array");
    }
    m_arr = arr;
    m_owns_array = owns_array;
}

MsgEnvelopeArray::MsgEnvelopeArray(const MsgEnvelopeArray& src) {
    throw "This object should not be copied";
}

MsgEnvelopeArray& MsgEnvelopeArray::operator=(const MsgEnvelopeArray& src) {
    return *this;
}

void MsgEnvelopeArray::put_integer(int64_t value) {
    if (m_arr == NULL) {
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Message Envelope already consumed, "
                              "unable to add to message envelope array");
    }
    msgbus_ret_t ret = \
        msgbus_msg_envelope_elem_array_add_integer(m_arr, value);
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to add object "
                                    "into MsgEnvelopeArray");
    }
}

void MsgEnvelopeArray::put_string(std::string value) {
    if (m_arr == NULL) {
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Message Envelope already consumed, "
                              "unable to add to message envelope array");
    }
    msgbus_ret_t ret = \
        msgbus_msg_envelope_elem_array_add_string(m_arr, value.c_str());
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to add object "
                                    "into MsgEnvelopeArray");
    }
}

void MsgEnvelopeArray::put_float(double value) {
    if (m_arr == NULL) {
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Message Envelope already consumed, "
                              "unable to add to message envelope array");
    }
    msgbus_ret_t ret = \
        msgbus_msg_envelope_elem_array_add_float(m_arr, value);
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to add object "
                                    "into MsgEnvelopeArray");
    }
}

void MsgEnvelopeArray::put_bool(bool value) {
    if (m_arr == NULL) {
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Message Envelope already consumed, "
                              "unable to add to message envelope array");
    }
    msgbus_ret_t ret = \
        msgbus_msg_envelope_elem_array_add_bool(m_arr, value);
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to add object "
                                    "into MsgEnvelopeArray");
    }
}

void MsgEnvelopeArray::put_object(MsgEnvelopeObject* value) {
    if (m_arr == NULL) {
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Message Envelope already consumed, "
                              "unable to add to message envelope array");
    }
    msgbus_ret_t ret = \
        msgbus_msg_envelope_elem_array_add(m_arr,
                                           value->get_msg_envelope_object());
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to add object into "
                                    "MsgEnvelopeArray");
    }
}

void MsgEnvelopeArray::remove_at(int64_t index) {
    if (m_arr == NULL) {
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Message Envelope already consumed, "
                              "unable to remove from message envelope array");
    }
    msgbus_ret_t ret = MSG_SUCCESS;
    ret = msgbus_msg_envelope_elem_array_remove_at(m_arr, index);
    if (ret == MSG_ERR_ELEM_ARR) {
        throw MsgbusException(ret, "Provided element is not an array");
    } else if (ret == MSG_ERR_ELEM_NOT_EXIST) {
        throw MsgbusException(ret, "Element at provided index not found");
    }
}

int64_t MsgEnvelopeArray::get_int(int64_t index) {
    msg_envelope_elem_body_t* body = \
        msgbus_msg_envelope_elem_array_get_at(m_arr, index);
    if (body == NULL) {
        throw MsgbusException(MSG_ERR_ELEM_NOT_EXIST,
                              "Value for key not found");
    }
    if(body->type != MSG_ENV_DT_INT) {
        throw MsgbusException(MSG_ERR_ELEM_OBJ,
                              "Value type is not an integer");
    }
    return body->body.integer;
}

double MsgEnvelopeArray::get_float(int64_t index) {
    msg_envelope_elem_body_t* body = \
        msgbus_msg_envelope_elem_array_get_at(m_arr, index);
    if (body == NULL) {
        throw MsgbusException(MSG_ERR_ELEM_NOT_EXIST,
                              "Value for key not found");
    }
    if(body->type != MSG_ENV_DT_FLOATING) {
        throw MsgbusException(MSG_ERR_ELEM_OBJ,
                              "Value type is not a float");
    }
    return body->body.floating;
}

const char* MsgEnvelopeArray::get_string(int64_t index) {
    msg_envelope_elem_body_t* body = \
        msgbus_msg_envelope_elem_array_get_at(m_arr, index);
    if (body == NULL) {
        throw MsgbusException(MSG_ERR_ELEM_NOT_EXIST,
                              "Value for key not found");
    }
    if(body->type != MSG_ENV_DT_STRING) {
        throw MsgbusException(MSG_ERR_ELEM_OBJ,
                              "Value type is not a string");
    }
    return body->body.string;
}

bool MsgEnvelopeArray::get_bool(int64_t index) {
    msg_envelope_elem_body_t* body = \
        msgbus_msg_envelope_elem_array_get_at(m_arr, index);
    if (body == NULL) {
        throw MsgbusException(MSG_ERR_ELEM_NOT_EXIST,
                              "Value for key not found");
    }
    if(body->type != MSG_ENV_DT_BOOLEAN) {
        throw MsgbusException(MSG_ERR_ELEM_OBJ,
                              "Value type is not a boolean");
    }
    return body->body.boolean;
}

MsgEnvelopeElement* MsgEnvelopeArray::get_msg_envelope_element(int64_t index) {
    msg_envelope_elem_body_t* body = msgbus_msg_envelope_elem_array_get_at(m_arr, index);
    if(body == NULL) {
        throw MsgbusException(MSG_ERR_UNKNOWN, "Value for key not found");
    }
    MsgEnvelopeElement* msg_envelope_elemnt = new MsgEnvelopeElement(body);
    return msg_envelope_elemnt;
}

msg_envelope_elem_body_t* MsgEnvelopeArray::get_msg_envelope_array() {
    if (m_owns_array) return m_arr;
    return NULL;
}

MsgEnvelopeArray::~MsgEnvelopeArray() {
    if (m_arr != NULL && m_owns_array) {
        msgbus_msg_envelope_elem_destroy(m_arr);
    }
}

MsgEnvelopeObject::MsgEnvelopeObject() {
    m_msgenvobj = msgbus_msg_envelope_new_object();
    if (m_msgenvobj == NULL) {
        throw MsgbusException(
            MSG_ERR_NO_MEMORY, "Failed to create underlying msg envelope object");
    }
    m_owns_object = true;
}

MsgEnvelopeObject::MsgEnvelopeObject(msg_envelope_elem_body_t* obj, bool owns_object) {
    if (obj == NULL) {
        throw MsgbusException(
            MSG_ERR_UNKNOWN, "Failed to create underlying msg envelope object");
    }
    m_msgenvobj = obj;
    m_owns_object = owns_object;
}

MsgEnvelopeObject::MsgEnvelopeObject(const MsgEnvelopeObject& src) {
    throw "This object should not be copied";
}

MsgEnvelopeObject& MsgEnvelopeObject::operator=(const MsgEnvelopeObject& src) {
    return *this;
}

void MsgEnvelopeObject::put_integer(std::string key, int64_t value) {
    if (m_msgenvobj == NULL) {
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Message Envelope already consumed, "
                              "unable to add to message envelope object");
    }
    msgbus_ret_t ret = \
        msgbus_msg_envelope_elem_object_put_integer(m_msgenvobj,
                                                    key.c_str(),
                                                    value);
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to add object "
                                    "into MsgEnvelopeObject");
    }
}

void MsgEnvelopeObject::put_string(std::string key, std::string value) {
    if (m_msgenvobj == NULL) {
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Message Envelope already consumed, "
                              "unable to add to message envelope object");
    }
    msgbus_ret_t ret = \
        msgbus_msg_envelope_elem_object_put_string(m_msgenvobj,
                                                   key.c_str(),
                                                   value.c_str());
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to add object "
                                    "into MsgEnvelopeObject");
    }
}

void MsgEnvelopeObject::put_float(std::string key, double value) {
    if (m_msgenvobj == NULL) {
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Message Envelope already consumed, "
                              "unable to add to message envelope object");
    }
    msgbus_ret_t ret = \
        msgbus_msg_envelope_elem_object_put_float(m_msgenvobj,
                                                  key.c_str(),
                                                  value);
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to add object "
                                    "into MsgEnvelopeObject");
    }
}

void MsgEnvelopeObject::put_bool(std::string key, bool value) {
    if (m_msgenvobj == NULL) {
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Message Envelope already consumed, "
                              "unable to add to message envelope object");
    }
    msgbus_ret_t ret = \
        msgbus_msg_envelope_elem_object_put_bool(m_msgenvobj,
                                                 key.c_str(),
                                                 value);
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to add object "
                                    "into MsgEnvelopeObject");
    }
}

void MsgEnvelopeObject::remove(std::string key) {
    if (m_msgenvobj == NULL) {
        throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Message Envelope already consumed, "
                              "unable to remove from message envelope object");
    }
    msgbus_ret_t ret = MSG_SUCCESS;
    ret = msgbus_msg_envelope_elem_object_remove(m_msgenvobj, key.c_str());
    if (ret == MSG_ERR_ELEM_NOT_EXIST) {
        throw MsgbusException(ret, "Element at provided index not found");
    } else if (ret == MSG_ERR_ELEM_OBJ) {
        throw MsgbusException(ret, "Provided element is not a "
                                    "msg_envelope_elem object");
    }
}

int64_t MsgEnvelopeObject::get_int(const std::string key) {
    msg_envelope_elem_body_t* body = \
        msgbus_msg_envelope_elem_object_get(m_msgenvobj,
                                            key.c_str());
    if (body == NULL) {
        throw MsgbusException(MSG_ERR_ELEM_NOT_EXIST,
                              "Value for key not found");
    }
    if(body->type != MSG_ENV_DT_INT) {
        throw MsgbusException(MSG_ERR_ELEM_OBJ,
                              "Value type is not an integer");
    }
    return body->body.integer;
}

double MsgEnvelopeObject::get_float(const std::string key) {
    msg_envelope_elem_body_t* body = \
        msgbus_msg_envelope_elem_object_get(m_msgenvobj,
                                            key.c_str());
    if (body == NULL) {
        throw MsgbusException(MSG_ERR_ELEM_NOT_EXIST,
                              "Value for key not found");
    }
    if(body->type != MSG_ENV_DT_FLOATING) {
        throw MsgbusException(MSG_ERR_ELEM_OBJ,
                              "Value type is not a float");
    }
    return body->body.floating;
}

const char* MsgEnvelopeObject::get_string(const std::string key) {
    msg_envelope_elem_body_t* body = \
        msgbus_msg_envelope_elem_object_get(m_msgenvobj,
                                            key.c_str());
    if (body == NULL) {
        throw MsgbusException(MSG_ERR_ELEM_NOT_EXIST,
                              "Value for key not found");
    }
    if(body->type != MSG_ENV_DT_STRING) {
        throw MsgbusException(MSG_ERR_ELEM_OBJ,
                              "Value type is not a string");
    }
    return body->body.string;
}

bool MsgEnvelopeObject::get_bool(const std::string key) {
    msg_envelope_elem_body_t* body = \
        msgbus_msg_envelope_elem_object_get(m_msgenvobj,
                                            key.c_str());
    if (body == NULL) {
        throw MsgbusException(MSG_ERR_ELEM_NOT_EXIST,
                              "Value for key not found");
    }
    if(body->type != MSG_ENV_DT_BOOLEAN) {
        throw MsgbusException(MSG_ERR_ELEM_OBJ,
                              "Value type is not a boolean");
    }
    return body->body.boolean;
}

MsgEnvelopeElement* MsgEnvelopeObject::get_msg_envelope_element(const std::string key) {
    msg_envelope_elem_body_t* body = msgbus_msg_envelope_elem_object_get(m_msgenvobj,
                                                                         key.c_str());
    if(body == NULL) {
        throw MsgbusException(MSG_ERR_UNKNOWN, "Value for key not found");
    }
    MsgEnvelopeElement* msg_envelope_elemnt = new MsgEnvelopeElement(body);
    return msg_envelope_elemnt;
}

msg_envelope_elem_body_t* MsgEnvelopeObject::get_msg_envelope_object() {
    if (m_owns_object) return m_msgenvobj;
    return NULL;
}

MsgEnvelopeObject::~MsgEnvelopeObject() {
    if (m_msgenvobj != NULL && m_owns_object) {
        msgbus_msg_envelope_elem_destroy(m_msgenvobj);
    }
}

MsgEnvelopeArray* MsgEnvelope::get_array(std::string key) {
    msg_envelope_elem_body_t* body = NULL;
    msgbus_ret_t ret = msgbus_msg_envelope_get(m_msgenv, key.c_str(), &body);
    if(ret != MSG_SUCCESS) {
        if (ret == MSG_ERR_ELEM_NOT_EXIST) {
            throw MsgbusException(ret, "Value for key not found");
        }
    }
    return new MsgEnvelopeArray(body, false);
}

MsgEnvelopeObject* MsgEnvelope::get_object(std::string key) {
    msg_envelope_elem_body_t* body = NULL;
    msgbus_ret_t ret = msgbus_msg_envelope_get(m_msgenv, key.c_str(), &body);
    if(ret != MSG_SUCCESS) {
        if (ret == MSG_ERR_ELEM_NOT_EXIST) {
            throw MsgbusException(ret, "Value for key not found");
        }
    }
    return new MsgEnvelopeObject(body, false);
}
