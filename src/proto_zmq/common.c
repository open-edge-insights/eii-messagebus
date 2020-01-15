// Copyright (c) 2020 Intel Corporation.
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
 * @brief Common utility function implementations
 * @author Kevin Midkiff <kevin.midkiff@intel.com>
 */

#include <stdlib.h>
#include <string.h>
#include <safe_lib.h>
#include "common.h"

bool verify_key_len(const char* key) {
    size_t key_len = strlen(key);
    if(key_len != 40) {
        LOG_ERROR("ZeroMQ curve key must be 40, not %d", (int) key_len);
        return false;
    }
    return true;
}

char* concat_s(size_t dst_len, int num_strs, ...) {
    char* dst = (char*) malloc(sizeof(char) * dst_len);
    if(dst == NULL) {
        LOG_ERROR_0("Failed to initialize dest for string concat");
        return NULL;
    }

    va_list ap;
    size_t curr_len = 0;
    int ret = 0;

    va_start(ap, num_strs);

    // First element must be copied into dest
    char* src = va_arg(ap, char*);
    size_t src_len = strlen(src);
    ret = strncpy_s(dst, dst_len, src, src_len);
    if(ret != 0) {
        LOG_ERROR("Concatincation failed (errno: %d)", ret);
        free(dst);
        va_end(ap);
        return NULL;
    }
    curr_len += src_len;

    for(int i = 1; i < num_strs; i++) {
        src = va_arg(ap, char*);
        src_len = strlen(src);
        LOG_DEBUG("%s", src);
        ret = strncat_s(dst + curr_len, dst_len, src, src_len);
        if(ret != 0) {
            LOG_ERROR("Concatincation failed (errno: %d)", ret);
            free(dst);
            dst = NULL;
            break;
        }
        curr_len += src_len;
        dst[curr_len] = '\0';
    }
    va_end(ap);

    if(dst == NULL)
        return NULL;
    else
        return dst;
}

void close_zero_linger(void* socket) {
    int linger = 0;
    zmq_setsockopt(socket, ZMQ_LINGER, &linger, sizeof(linger));
    zmq_close(socket);
}
