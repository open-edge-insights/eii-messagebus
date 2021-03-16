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
 * @brief Message bus echo service example
 */

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <eii/msgbus/msgbus.h>
#include <eii/utils/logger.h>
#include <eii/utils/json_config.h>
#include "common.h"

#define SERVICE_NAME "echo_service"

// Globals for cleaning up nicely
bool g_stop = false;

/**
 * Function to print publisher usage
 */
void usage(const char* name) {
    fprintf(stderr, "usage: %s [-h|--help] [--log-level <log-level>] "
                    "<json-config>\n", name);
    fprintf(stderr, "\t-h|--help   - Show this help\n");
    fprintf(stderr, "\t--log-level - Log level, must be DEBUG, INFO, WARN, "
                    "or ERROR (df: INFO)\n");
    fprintf(stderr, "\tjson-config - Path to JSON configuration file\n");
}

/**
 * Signal handler
 */
void signal_handler(int signo) {
    LOG_INFO_0("Stopping service server");
    g_stop = true;
}

int main(int argc, char** argv) {
    void* msgbus_ctx = NULL;
    recv_ctx_t* service_ctx = NULL;
    msg_envelope_serialized_part_t* parts = NULL;
    msg_envelope_t* msg = NULL;
    int num_parts = 0;
    msgbus_ret_t ret = MSG_SUCCESS;
    log_lvl_t log_level = LOG_LVL_INFO;

    // Index of the JSON configuration CLI parameter (varies based on if the
    // log level is set via the command line).
    int config_idx = 1;

    if (argc == 1) {
        LOG_ERROR_0("Too few arguments");
        return -1;
    } else if (argc > 4) {
        LOG_ERROR_0("Too many arguments");
        return -1;
    }

    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        usage(argv[0]);
        return 0;
    } else if (strcmp(argv[1], "--log-level") == 0) {
        if (argc < 4) {
            LOG_ERROR_0("Too few arguments");
            return -1;
        }
        if (!parse_log_level(argv[2], &log_level)) {
            return -1;
        }
        config_idx = 3;
    }

    // Set log level
    set_log_level(log_level);

    // Setting up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    config_t* config = json_config_new(argv[config_idx]);
    if (config == NULL) {
        LOG_ERROR_0("Failed to load JSON configuration");
        goto err;
    }

    msgbus_ctx = msgbus_initialize(config);
    if (msgbus_ctx == NULL) {
        LOG_ERROR_0("Failed to initialize message bus");
        goto err;
    }

    ret = msgbus_service_new(msgbus_ctx, SERVICE_NAME, NULL, &service_ctx);
    if (ret != MSG_SUCCESS) {
        LOG_ERROR("Failed to initialize service (errno: %d)", ret);
        goto err;
    }

    LOG_INFO_0("Running...");

    while (!g_stop) {
        ret = msgbus_recv_wait(msgbus_ctx, service_ctx, &msg);
        if (ret != MSG_SUCCESS) {
            // Interrupt is an acceptable error
            if (ret == MSG_ERR_EINTR)
                break;
            LOG_ERROR("Failed to receive message (errno: %d)", ret);
            goto err;
        }

        num_parts = msgbus_msg_envelope_serialize(msg, &parts);
        if (num_parts <= 0) {
            LOG_ERROR_0("Failed to serialize message");
            goto err;
        }

        LOG_INFO("Received Request: %s", parts[0].bytes);

        // Responding
        ret = msgbus_response(msgbus_ctx, service_ctx, msg);
        if (ret != MSG_SUCCESS) {
            LOG_ERROR("Failed to send response (errno: %d)", ret);
            goto err;
        }

        msgbus_msg_envelope_serialize_destroy(parts, num_parts);
        msgbus_msg_envelope_destroy(msg);
        msg = NULL;
        parts = NULL;
    }

    if (msg != NULL)
        msgbus_msg_envelope_destroy(msg);
    if (parts != NULL)
        msgbus_msg_envelope_serialize_destroy(parts, num_parts);
    if (service_ctx != NULL)
        msgbus_recv_ctx_destroy(msgbus_ctx, service_ctx);
    if (msgbus_ctx != NULL)
        msgbus_destroy(msgbus_ctx);

    return 0;

err:
    if (msg != NULL)
        msgbus_msg_envelope_destroy(msg);
    if (parts != NULL)
        msgbus_msg_envelope_serialize_destroy(parts, num_parts);
    if (service_ctx != NULL)
        msgbus_recv_ctx_destroy(msgbus_ctx, service_ctx);
    if (msgbus_ctx != NULL)
        msgbus_destroy(msgbus_ctx);

    return -1;
}
