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
 * @brief Message bus return value utility implementations.
 */

#include "eii/msgbus/msgbusret.h"

#define MSGBUS_RET_STR_CASE(ret) \
    case ret: return #ret;

const char* msgbus_ret_str(msgbus_ret_t ret) {
    switch (ret) {
    MSGBUS_RET_STR_CASE(MSG_SUCCESS)
    MSGBUS_RET_STR_CASE(MSG_ERR_PUB_FAILED)
    MSGBUS_RET_STR_CASE(MSG_ERR_SUB_FAILED)
    MSGBUS_RET_STR_CASE(MSG_ERR_RESP_FAILED)
    MSGBUS_RET_STR_CASE(MSG_ERR_RECV_FAILED)
    MSGBUS_RET_STR_CASE(MSG_ERR_RECV_EMPTY)
    MSGBUS_RET_STR_CASE(MSG_ERR_ALREADY_RECEIVED)
    MSGBUS_RET_STR_CASE(MSG_ERR_NO_SUCH_SERVICE)
    MSGBUS_RET_STR_CASE(MSG_ERR_SERVICE_ALREADY_EXIST)
    MSGBUS_RET_STR_CASE(MSG_ERR_BUS_CONTEXT_DESTROYED)
    MSGBUS_RET_STR_CASE(MSG_ERR_NO_MEMORY)
    MSGBUS_RET_STR_CASE(MSG_ERR_ELEM_NOT_EXIST)
    MSGBUS_RET_STR_CASE(MSG_ERR_ELEM_ALREADY_EXISTS)
    MSGBUS_RET_STR_CASE(MSG_ERR_ELEM_BLOB_ALREADY_SET)
    MSGBUS_RET_STR_CASE(MSG_ERR_ELEM_BLOB_MALFORMED)
    MSGBUS_RET_STR_CASE(MSG_RECV_NO_MESSAGE)
    MSGBUS_RET_STR_CASE(MSG_ERR_SERVICE_INIT_FAILED)
    MSGBUS_RET_STR_CASE(MSG_ERR_REQ_FAILED)
    MSGBUS_RET_STR_CASE(MSG_ERR_EINTR)
    MSGBUS_RET_STR_CASE(MSG_ERR_MSG_SEND_FAILED)
    MSGBUS_RET_STR_CASE(MSG_ERR_DISCONNECTED)
    MSGBUS_RET_STR_CASE(MSG_ERR_AUTH_FAILED)
    MSGBUS_RET_STR_CASE(MSG_ERR_ELEM_OBJ)
    MSGBUS_RET_STR_CASE(MSG_ERR_ELEM_ARR)
    MSGBUS_RET_STR_CASE(MSG_ERR_DESERIALIZE_FAILED)
    MSGBUS_RET_STR_CASE(MSG_ERR_UNKNOWN)
    default:
        return "";
    }
}
