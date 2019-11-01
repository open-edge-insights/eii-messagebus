# Copyright (c) 2019 Intel Corporation.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""EIS Message Envelope utility functions
"""

# Python imports
import json
import warnings
from .exc import MessageBusError

# Cython imports
from .libeismsgbus cimport *
from cpython cimport bool, Py_INCREF, Py_DECREF
from libc.stdint cimport int64_t


cdef void free_python_blob(void* vhint) nogil:
    """Method for freeing a Python blob by decreasing the number of references
    on it in the Python interpreter.

    This method is called once the message bus is done with the data.
    """
    # Explicitly acquiring the GIL here, must be done this way, otherwise
    # this method cannot be called from the underlying C library
    with gil:
        # Decrement the reference count and delete the Python object so it can
        # be freed by the Python garbage collector.
        obj = <object> vhint
        Py_DECREF(obj)
        del obj


cdef void put_bytes_helper(msg_envelope_t* env, data) except *:
    """Helper function to serialize a Python bytes object to a blob object.
    """
    cdef msgbus_ret_t ret
    cdef msg_envelope_elem_body_t* body

    body = msgbus_msg_envelope_new_blob(<char*> data, len(data))
    if body == NULL:
        raise MessageBusError('Failed to initialize new blob')

    # Put element into the message envelope
    ret = msgbus_msg_envelope_put(env, NULL, body)
    if ret != msgbus_ret_t.MSG_SUCCESS:
        msgbus_msg_envelope_elem_destroy(body)
        raise MessageBusError('Failed to put blob in message envelope')

    # Increment the reference count on the underlying Python object for the
    # blob data being published over the message bus. This will keep the data
    # from being garbage collected by the interpreter.
    Py_INCREF(data)
    env.blob.body.blob.shared.ptr = <void*> data
    env.blob.body.blob.shared.free = free_python_blob


cdef msg_envelope_elem_body_t* python_to_msg_env_elem_body(data):
    """Helper function to recursively convert a python object to
    msg_envelope_elem_body_t.
    """
    cdef msg_envelope_elem_body_t* elem = NULL
    cdef msg_envelope_elem_body_t* subelem = NULL
    cdef msgbus_ret_t ret = MSG_SUCCESS

    if isinstance(data, str):
        bv = bytes(data, 'utf-8')
        elem = msgbus_msg_envelope_new_string(bv)
    elif isinstance(data, int):
        elem = msgbus_msg_envelope_new_integer(<int64_t> data)
    elif isinstance(data, float):
        elem = msgbus_msg_envelope_new_floating(<double> data)
    elif isinstance(data, bool):
        elem = msgbus_msg_envelope_new_bool(<bint> data)
    elif isinstance(data, dict):
        elem = msgbus_msg_envelope_new_object()
        for k, v in data.items():
            # Convert the python element to a msg envelope element
            subelem = python_to_msg_env_elem_body(v)
            if subelem == NULL:
                msgbus_msg_envelope_elem_destroy(elem)
                return NULL

            # Add the element to the nested object
            k = bytes(k, 'utf-8')
            ret = msgbus_msg_envelope_elem_object_put(elem, <char*> k, subelem)
            if ret != MSG_SUCCESS:
                msgbus_msg_envelope_elem_destroy(subelem)
                msgbus_msg_envelope_elem_destroy(elem)
                return NULL
    elif isinstance(data, (list, tuple,)):
        elem = msgbus_msg_envelope_new_array()
        for v in data:
            # Convert the python element to a msg envelope element
            subelem = python_to_msg_env_elem_body(v)
            if subelem == NULL:
                msgbus_msg_envelope_elem_destroy(elem)
                return NULL

            # Add the element to the array
            ret = msgbus_msg_envelope_elem_array_add(elem, subelem)
            if ret != MSG_SUCCESS:
                msgbus_msg_envelope_elem_destroy(subelem)
                msgbus_msg_envelope_elem_destroy(elem)
                return NULL
    elif data is None:
        elem = msgbus_msg_envelope_new_none()

    return elem


cdef msg_envelope_t* python_to_msg_envelope(data) except *:
    """Helper function to create a msg_envelope_t from a Python bytes or
    dictionary object.

    :param data: Data for the message envelope
    :type: bytes or dict
    :return: Message envelope
    :rtype: msg_envelope_t
    """
    cdef msgbus_ret_t ret
    cdef msg_envelope_elem_body_t* body
    cdef msg_envelope_t* env
    cdef content_type_t ct
    cdef char* key = NULL

    binary = None
    kv_data = None

    if isinstance(data, bytes):
        ct = content_type_t.CT_BLOB
        binary = data
    elif isinstance(data, dict):
        ct = content_type_t.CT_JSON
        kv_data = data
    elif isinstance(data, (list, tuple,)):
        ct = content_type_t.CT_JSON
        if len(data) > 2:
            raise MessageBusError('List can only be 2 elements for a msg')

        if isinstance(data[0], bytes):
            if not isinstance(data[1], dict):
                raise MessageBusError('Second element must be dict')

            binary = data[0]
            kv_data = data[1]
        elif isinstance(data[0], dict):
            if not isinstance(data[1], bytes):
                raise MessageBusError('Second element must be bytes')

            binary = data[1]
            kv_data = data[0]
        else:
            raise MessageBusError(
                    f'Unknown data type: {type(data)}, must be bytes or dict')
    else:
        raise MessageBusError(
                'Unable to create msg envelope from type: {}'.format(
                    type(data)))

    # Initialize message envelope object
    env = msgbus_msg_envelope_new(ct)

    if env == NULL:
        raise MessageBusError('Failed to initialize message envelope')

    if ct == content_type_t.CT_BLOB:
        try:
            put_bytes_helper(env, data)
        except MessageBusError:
            msgbus_msg_envelope_destroy(env)
            raise  # Re-raise
    else:
        if binary is not None:
            try:
                put_bytes_helper(env, binary)
            except:
                msgbus_msg_envelope_destroy(env)
                raise  # Re-raise

        for k, v in kv_data.items():
            body = python_to_msg_env_elem_body(v)
            if body == NULL:
                raise MessageBusError(f'Failed to convert: {k} to envelope')

            k = bytes(k, 'utf-8')
            ret = msgbus_msg_envelope_put(env, <char*> k, body)
            if ret != msgbus_ret_t.MSG_SUCCESS:
                msgbus_msg_envelope_elem_destroy(body)
                msgbus_msg_envelope_destroy(env)
                raise MessageBusError(f'Failed to put element {k}')
            else:
                # The message envelope takes ownership of the memory allocated
                # for these elements. Setting to NULL to keep the state clean.
                body = NULL
                key = NULL

    return env


cdef object char_to_bytes(const char* data, int length):
    """Helper function to convert char* to byte array without stopping on a
    NULL termination.

    NOTE: This is workaround for Cython's built-in way of doing this which will
    automatically stop when it hits a NULL byte.
    """
    return <bytes> data[:length]


cdef object msg_envelope_to_python(msg_envelope_t* msg):
    """Convert msg_envelope_t to Python dictionary or bytes object.

    :param msg: Message envelope to convert
    :type: msg_envelope_t*
    """
    cdef msg_envelope_serialized_part_t* parts = NULL

    num_parts = msgbus_msg_envelope_serialize(msg, &parts)
    if num_parts <= 0:
        raise MessageBusError('Error serializing to Python representation')

    if num_parts > 2:
        warnings.warn('The Python library only supports 2 parts!')

    try:
        data = None

        if msg.content_type == content_type_t.CT_JSON:
            data = json.loads(char_to_bytes(parts[0].bytes, parts[0].len))
            if num_parts > 1:
                data = (data, char_to_bytes(parts[1].bytes, parts[1].len),)
        elif msg.content_type == content_type_t.CT_BLOB:
            data = char_to_bytes(parts[0].bytes, parts[0].len)
        else:
            raise MessageBusError('Unknown content type')

        return data
    finally:
        msgbus_msg_envelope_serialize_destroy(parts, num_parts)
