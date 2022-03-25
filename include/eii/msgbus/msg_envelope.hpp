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
 * @file
 * @brief MsgEnvelope interface
 */

#ifndef _EII_MSGENVELOPE_HPP_
#define _EII_MSGENVELOPE_HPP_

#include <stdint.h>
#include <iostream>
#include <string>
#include <vector>
#include <typeinfo>
#include <exception>
#include "eii/msgbus/msg_envelope.h"


namespace eii {
namespace msgbus {

/**
 * Exception thrown by the EII Message envelope APIs indicating an error occurred
 * in the called method.
 */
class MsgbusException : public std::exception {
 private:
    // EII Message Bus C return value
    msgbus_ret_t m_ret;

    // Extra message with the exception providing additional context
    std::string m_msg;

 public:
    /**
     * Constructor
     *
     * @param ret - Message bus return code
     * @param msg - Extra message with the exception
     */
    MsgbusException(msgbus_ret_t ret, const char* msg);

    /**
     * Returns the explanatory string.
     *
     * @return Pointer to null-terminated explanation string
     */
    const char * what() const noexcept override {
        return m_msg.c_str();
    }

    /**
     * Returns the @c msgbus_ret_t indicating the error type.
     *
     * @return msgbus_ret_t
     */
    msgbus_ret_t get_msgbus_ret();
};

// Forward declarations
class MsgEnvelopeObject;
class MsgEnvelopeList;
class MsgEnvelope;

/**
 * MsgEnvelopeElement class
 */
class MsgEnvelopeElement {
 private:
    // msg_envelope_elem_body_t object
    msg_envelope_elem_body_t* m_elem;

    /**
     * Private @c MsgEnvelopeElement copy constructor.
     */
    MsgEnvelopeElement(const MsgEnvelopeElement& src);

    /**
     * Private @c MsgEnvelopeElement assignment operator.
     */
    MsgEnvelopeElement& operator=(const MsgEnvelopeElement& src);

    /**
     * Constructor
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param elem  - @c msg_envelope_elem_body_t MsgEnvelope Element body
     */
    MsgEnvelopeElement(msg_envelope_elem_body_t* elem);

 public:
    // Declaring MsgEnvelope as friend so that it can access
    // private constructors
    friend MsgEnvelope;
    friend MsgEnvelopeList;
    friend MsgEnvelopeObject;

    /**
     * Fetch integer value from @c MsgEnvelopeElement object.
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @return int64_t - returns the integer value
     */
    int64_t to_int();

    /**
     * Fetch float value from @c MsgEnvelopeElement object.
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @return double - returns the float value
     */
    double to_float();

    /**
     * Fetch string value from @c MsgEnvelopeElement object.
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @return const char* - returns the string value
     */
    const char* to_string();

    /**
     * Fetch boolean value from @c MsgEnvelopeElement object.
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @return bool - returns the boolean value
     */
    bool to_bool();

    /**
     * Fetch integer value from @c MsgEnvelopeElement object.
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @return @c MsgEnvelopeList - returns the @c MsgEnvelopeList value
     */
    MsgEnvelopeList* to_array();

    /**
     * Fetch integer value from @c MsgEnvelopeElement object.
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @return @c MsgEnvelopeObject - returns the @c MsgEnvelopeObject value
     */
    MsgEnvelopeObject* to_object();

    /**
     * Check whether or not the message envelope element type is none.
     *
     * @return true if the value is none, false otherwise
     */
    bool is_none();

    /**
     * Return the data type of the message envelope element.
     *
     * @return @c msg_envelope_data_type_t
     */
    msg_envelope_data_type_t get_type();

    /**
     * Get a string representation of the of the message envelope element type.
     *
     * @return const char*
     */
    const char* get_type_str();

    /**
     * Destructor
     */
    ~MsgEnvelopeElement();
};

/**
 * MsgEnvelope class
 */
class MsgEnvelope {
 private:
    // msg_envelope_t object
    msg_envelope_t* m_msgenv;

    /**
     * Private @c MsgEnvelope copy constructor.
     */
    MsgEnvelope(const MsgEnvelope& src);

    /**
     * Private @c MsgEnvelope assignment operator.
     */
    MsgEnvelope& operator=(const MsgEnvelope& src);

 public:
    /**
     * Constructor
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param ct  - @c content_type whether CT_JSON/CT_BLOB
     */
    MsgEnvelope(content_type_t ct);

    /**
     * Constructor
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param msgenv  - @c msg_envelope_t object
     */
    MsgEnvelope(msg_envelope_t* msgenv);

    /**
     * Add a new integer value to the @c MsgEnvelope object.
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key     -  key to be added into @c MsgEnvelope object
     * @param value   -  integer value to be added into @c MsgEnvelope object
     */
    void put_integer(const std::string key, int64_t value);

    /**
     * Add a new floating value to the @c MsgEnvelope object.
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key     -  key to be added into @c MsgEnvelope object
     * @param value   -  float value to be added into @c MsgEnvelope object
     */
    void put_float(const std::string key, double value);

    /**
     * Add a new string value to the @c MsgEnvelope object.
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key     -  key to be added into @c MsgEnvelope object
     * @param value   -  string value to be added into @c MsgEnvelope object
     */
    void put_string(const std::string key, const std::string value);

    /**
     * Add a new boolean value to the @c MsgEnvelope object.
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key     -  key to be added into @c MsgEnvelope object
     * @param value   -  boolean value to be added into @c MsgEnvelope object
     */
    void put_bool(const std::string key, bool value);

    /**
     * Add a @c MsgEnvelopeList to the @c MsgEnvelope object.
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key     -  key to be added into @c MsgEnvelope object
     * @param value   -  @c MsgEnvelopeList value to be added into @c MsgEnvelope object
     */
    void put_array(const std::string key, MsgEnvelopeList* value);

    /**
     * Add a vector as an array to the @c MsgEnvelope object.
     * Note: The supported types for the vector are integer, float & bool only.
     * Add a @c MsgEnvelopeList to the @c MsgEnvelope object.
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key     -  key to be added into @c MsgEnvelope object
     * @param value   -  std::vector<T> value to be added into @c MsgEnvelope object
     */
    template<typename T>
    void put_vector(const std::string key,
                    std::vector<T> const& value) {
      if (m_msgenv == NULL) {
         throw MsgbusException(MSG_ERR_UNKNOWN,
                               "Message Envelope already consumed, "
                               "unable to add to message envelope");
      }
      msg_envelope_elem_body_t* arr = msgbus_msg_envelope_new_array();
      if (arr == NULL) {
         throw MsgbusException(MSG_ERR_NO_MEMORY,
                               "Failed to create underlying msg envelope array");
      }
      msgbus_ret_t ret;
      for (int i = 0; i < value.size(); i++) {
         try {
            if (typeid(value).name() == typeid(std::vector<int>).name()) {
               ret = msgbus_msg_envelope_elem_array_add_integer(arr, value[i]);
               if (ret != MSG_SUCCESS) {
                  throw MsgbusException(ret, "Failed to add integer "
                                             "into msg envelope array");
               }
            } else if (typeid(value).name() == typeid(std::vector<double>).name()) {
               ret = msgbus_msg_envelope_elem_array_add_float(arr, value[i]);
               if (ret != MSG_SUCCESS) {
                  throw MsgbusException(ret, "Failed to add integer "
                                             "into msg envelope array");
               }
            } else if (typeid(value).name() == typeid(std::vector<bool>).name()) {
               ret = msgbus_msg_envelope_elem_array_add_bool(arr, value[i]);
               if (ret != MSG_SUCCESS) {
                  throw MsgbusException(ret, "Failed to add integer "
                                             "into msg envelope array");
               }
            } else {
               throw MsgbusException(MSG_ERR_UNKNOWN, "Vector type not supported");
            }
         } catch (const std::exception& e) {
            throw MsgbusException(MSG_ERR_UNKNOWN, e.what());
         }
      }

      if (m_msgenv == NULL) {
         throw MsgbusException(MSG_ERR_UNKNOWN,
                              "Message Envelope already consumed, "
                              "unable to add to message envelope");
      }
      ret = msgbus_msg_envelope_put(m_msgenv, key.c_str(), arr);
      if (ret != MSG_SUCCESS) {
         throw MsgbusException(ret, "Failed to add array into message envelope");
      }
    }

    /**
     * Add a new nested @c MsgEnvelopeObject to the @c MsgEnvelope object.
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key     -  key to be added into @c MsgEnvelope object
     * @param value   -  @c MsgEnvelopeObject value to be added into @c MsgEnvelope object
     */
    void put_object(const std::string key, MsgEnvelopeObject* value);

    /**
     * Add a new blob to the @c MsgEnvelope object.
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param value   -  blob value to be added into @c MsgEnvelope object
     * @param size    -  length of blob to be added into @c MsgEnvelope object
     */
    void put_blob(char* value, size_t size);

    /**
     * To remove value associated with the key provided
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key   -  key of value to be removed
     */
    void remove(const std::string key);

    /**
     * To fetch an integer value associated with the key provided
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key   -  key of value to be fetched
     *
     * @return int64_t - returns the integer value associated with the key
     */
    int64_t get_int(const std::string key);

    /**
     * To fetch a float value associated with the key provided
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key   -  key of value to be fetched
     *
     * @return double - returns the float value associated with the key
     */
    double get_float(const std::string key);

    /**
     * To fetch a string associated with the key provided
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key   -  key of value to be fetched
     *
     * @return const char* - returns the string value associated with the key
     */
    const char* get_string(const std::string key);

    /**
     * To fetch a boolean value associated with the key provided
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key   -  key of value to be fetched
     *
     * @return bool - returns the boolean value associated with the key
     */
    bool get_bool(const std::string key);

    /**
     * To fetch blob from @c MsgEnvelope
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @return @c char* - returns the blob from MsgEnvelope
     */
    char* get_blob(const std::string key);

    /**
     * To fetch a @c MsgEnvelopeObject value associated with the key provided
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key   -  key of value to be fetched
     *
     * @return @c MsgEnvelopeObject - returns the @c MsgEnvelopeObject  value
     *                                associated with the key
     */
    MsgEnvelopeObject* get_object(const std::string key);

    /**
     * To fetch a @c MsgEnvelopeList value associated with the key provided
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key   -  key of value to be fetched
     *
     * @return @c MsgEnvelopeList - returns the @c MsgEnvelopeList  value
     *                                associated with the key
     */
    MsgEnvelopeList* get_array(const std::string key);

    /**
     * To fetch a @c MsgEnvelopeElement value associated with the key provided
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key   -  key of value to be fetched
     *
     * @return @c MsgEnvelopeElement - returns the @c MsgEnvelopeElement  value
     *                                 associated with the key
     */
    MsgEnvelopeElement* get_msg_envelope_element(const std::string key);

    /**
     * Getter to retrieve the underlying @c msg_envelope_t structure
     *
     * @return @c msg_envelope_t - returns the @c msg_envelope_t struct
     */
    msg_envelope_t* get_msg_envelope();

    /**
     * Destructor
     */
    ~MsgEnvelope();
};

/**
 * MsgEnvelopeList class
 */
class MsgEnvelopeList {
 private:
    // msg_envelope_elem_body_t object
    msg_envelope_elem_body_t* m_arr;

    // bool whether the MsgEnvelopeList owns m_arr
    bool m_owns_array;

    /**
     * Private @c MsgEnvelopeList copy constructor.
     */
    MsgEnvelopeList(const MsgEnvelopeList& src);

    /**
     * Private @c MsgEnvelopeList assignment operator.
     */
    MsgEnvelopeList& operator=(const MsgEnvelopeList& src);

    /**
     * Private Constructor
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param obj           -  Underlying @c msg_envelope_elem_body_t object
     * @param owns_object   -  boolean whether @c MsgEnvelopeList owns m_arr
     *
     */
    MsgEnvelopeList(msg_envelope_elem_body_t* arr, bool owns_array);

 public:
    // Declaring MsgEnvelope as friend so that it can access
    // private constructors
    friend MsgEnvelope;

    /**
     * Constructor
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     */
    MsgEnvelopeList();

    /**
     * Add a new integer value to the MsgEnvelopeList object.
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param value   -  integer value to be added into @c MsgEnvelopeList object
     */
    void put_integer(int64_t value);

    /**
     * Add a new float value to the MsgEnvelopeList object.
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param value   -  float value to be added into @c MsgEnvelopeList object
     */
    void put_float(double value);

    /**
     * Add a new string value to the @c MsgEnvelopeList object.
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param value   -  string value to be added into @c MsgEnvelopeList object
     */
    void put_string(const std::string value);

    /**
     * Add a new boolean value to the @c MsgEnvelopeList object.
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param value   -  boolean value to be added into @c MsgEnvelopeList object
     */
    void put_bool(bool value);

    /**
     * Add a new nested @c MsgEnvelopeObject to the @c MsgEnvelope object.
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key     -  key to be added into @c MsgEnvelope object
     * @param value   -  @c MsgEnvelopeObject value to be added into @c MsgEnvelope object
     */
    void put_object(MsgEnvelopeObject* value);

    /**
     * To remove value associated with the key provided
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param index   -  index of value to be removed
     */
    void remove_at(int64_t index);

    /**
     * To fetch an integer value associated with the key provided
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param index   -  index of value to be fetched
     *
     * @return int64_t - returns the integer value associated with the key
     */
    int64_t get_int(int64_t index);

    /**
     * To fetch a float value associated with the key provided
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param index   -  index of value to be fetched
     *
     * @return double - returns the float value associated with the key
     */
    double get_float(int64_t index);

    /**
     * To fetch a string associated with the key provided
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param index   -  index of value to be fetched
     *
     * @return const char* - returns the string value associated with the key
     */
    const char* get_string(int64_t index);

    /**
     * To fetch a boolean value associated with the key provided
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param index   -  index of value to be fetched
     *
     * @return bool - returns the boolean value associated with the key
     */
    bool get_bool(int64_t index);

    /**
     * To fetch a @c MsgEnvelopeObject value associated with the key provided
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param index   -  index of value to be fetched
     *
     * @return @c MsgEnvelopeObject - returns the @c MsgEnvelopeObject value
     *                                associated with the key
     */
    MsgEnvelopeObject* get_msg_envelope_object(int64_t index);

    /**
     * To fetch a @c MsgEnvelopeElement value associated with the index provided
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param index   -  index of value to be fetched
     *
     * @return @c MsgEnvelopeElement - returns the @c MsgEnvelopeElement value
     *                                 associated with the key
     */
    MsgEnvelopeElement* get_msg_envelope_element(int64_t index);

    /**
     * Getter to retrieve the underlying @c msg_envelope_elem_body_t structure
     *
     * @return @c msg_envelope_elem_body_t - returns the @c msg_envelope_elem_body_t struct
     */
    msg_envelope_elem_body_t* get_msg_envelope_array();

    /**
     * Destructor
     */
    ~MsgEnvelopeList();
};

class MsgEnvelopeObject {
 private:
    // msg_envelope_elem_body_t object
    msg_envelope_elem_body_t* m_msgenvobj;

    // bool whether the MsgEnvelopeObject object owns m_msgenvobj
    bool m_owns_object;

    /**
     * Private @c MsgEnvelopeObject copy constructor.
     */
    MsgEnvelopeObject(const MsgEnvelopeObject& src);

    /**
     * Private @c MsgEnvelopeObject assignment operator.
     */
    MsgEnvelopeObject& operator=(const MsgEnvelopeObject& src);

    /**
     * Private Constructor
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param obj           -  Underlying @c msg_envelope_elem_body_t object
     * @param owns_object   -  boolean whether @c MsgEnvelopeObject owns m_msgenvobj
     *
     */
    MsgEnvelopeObject(msg_envelope_elem_body_t* obj, bool owns_object);

 public:
    // Declaring MsgEnvelope as friend so that it can access
    // private constructors
    friend MsgEnvelope;

    /**
     * Constructor
     */
    MsgEnvelopeObject();

    /**
     * Add a new integer value to the @c MsgEnvelopeObject.
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key     -  key to be added into @c MsgEnvelopeObject
     * @param value   -  integer value to be added into @c MsgEnvelopeObject
     */
    void put_integer(const std::string key, int64_t value);

    /**
     * Add a new integer value to the @c MsgEnvelopeObject.
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key     -  key to be added into @c MsgEnvelopeObject
     * @param value   -  integer value to be added into @c MsgEnvelopeObject
     */
    void put_float(const std::string key, double value);

    /**
     * Add a new string value to the @c MsgEnvelopeObject.
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key     -  key to be added into @c MsgEnvelopeObject
     * @param value   -  string value to be added into @c MsgEnvelopeObject
     */
    void put_string(const std::string key, const std::string value);

    /**
     * Add a new boolean value to the @c MsgEnvelopeObject.
     *
     *  \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key     -  key to be added into @c MsgEnvelopeObject
     * @param value   -  boolean value to be added into @c MsgEnvelopeObject
     */
    void put_bool(const std::string key, bool value);

    /**
     * To remove value associated with the key provided
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key   -  key associated with the value to be removed
     */
    void remove(const std::string key);

    /**
     * To fetch an integer value associated with the key provided
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key   -  key of value to be fetched
     *
     * @return int64_t - returns the integer value associated with the key
     */
    int64_t get_int(const std::string key);

    /**
     * To fetch a float value associated with the key provided
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key   -  key of value to be fetched
     *
     * @return double - returns the float value associated with the key
     */
    double get_float(const std::string key);

    /**
     * To fetch a string associated with the key provided
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key   -  key of value to be fetched
     *
     * @return const char* - returns the string value associated with the key
     */
    const char* get_string(const std::string key);

    /**
     * To fetch a boolean value associated with the key provided
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key   -  key of value to be fetched
     *
     * @return bool - returns the boolean value associated with the key
     */
    bool get_bool(const std::string key);

    /**
     * To fetch a @c MsgEnvelopeElement value associated with the key provided
     *
     * \exception @c MsgbusException thrown if an error occurs in the message bus.
     *
     * @param key   -  key of value to be fetched
     *
     * @return @c MsgEnvelopeElement - returns the @c MsgEnvelopeElement value
     *                                 associated with the key
     */
    MsgEnvelopeElement* get_msg_envelope_element(const std::string key);

    /**
     * Getter to retrieve the underlying @c msg_envelope_elem_body_t structure
     *
     * @return @c msg_envelope_elem_body_t - returns the @c msg_envelope_elem_body_t struct
     */
    msg_envelope_elem_body_t* get_msg_envelope_object();

    /**
     * Destructor
     */
    ~MsgEnvelopeObject();
};

}  // namespace msgbus
}  // namespace eii

/**
 * Helper method to get the string representation of a message envelope data
 * type.
 *
 * @param dt - @c msg_envelope_data_type_t value
 * @return const char* of the return value's name
 */
const char* msgbus_msg_envelope_elem_type_str(msg_envelope_data_type_t dt);

#endif  // _EII_MSGENVELOPE_HPP_
