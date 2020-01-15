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
 * @brief ZeroMQ Authentication Protocol (ZAP)
 * @author Kevin Midkiff <kevin.midkiff@intel.com>
 */

#ifndef _EIS_MESSAGE_BUS_ZAP_H
#define _EIS_MESSAGE_BUS_ZAP_H

#include <pthread.h>
#include <stdbool.h>
#include <eis/utils/config.h>

/**
 * Internal context object for the ZAP authentication thread.
 */
typedef struct {
    void* socket;
    pthread_t th;
    pthread_mutex_t mtx_stop;
    size_t num_allowed_clients;
    char** allowed_clients;
    bool stop;
} zap_ctx_t;

/**
 * Initialize ZAP context.
 *
 * \note This starts the ZAP authentication thread.
 *
 * @param[in]  zmq_ctx - ZeroMQ context pointer
 * @param[in]  config  - ZeroMQ protocol configuration
 * @param[out] zap_ctx - Output ZAP context structure
 * @return 0 if successful, < 0 if an error occurred
 */
int zap_initialize(void* zmq_ctx, config_t* config, zap_ctx_t** zap_ctx);

/**
 * Destroy ZAP context.
 *
 * @param zap_ctx - ZAP context to destroy
 */
void zap_destroy(zap_ctx_t* zap_ctx);

#endif // _EIS_MESSAGE_BUS_ZAP_H
