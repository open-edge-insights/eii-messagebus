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
 * @brief Message bus publisher example
 */

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <eis/msgbus/msgbus.h>
#include <eis/utils/logger.h>
#include <eis/utils/json_config.h>
#include "common.h"

#define TOPIC "publish_test"

// Globals for cleaning up nicely
bool g_stop = false;

/**
 * Helper to initailize the message to be published
 */
msg_envelope_t* initialize_message() {
    msg_envelope_t* msg = NULL;

    // Creating message to be published
    msg_envelope_elem_body_t* integer = msgbus_msg_envelope_new_integer(42);
    msg_envelope_elem_body_t* fp = msgbus_msg_envelope_new_floating(55.5);
    msg = msgbus_msg_envelope_new(CT_JSON);
    msgbus_msg_envelope_put(msg, "hello", integer);
    msgbus_msg_envelope_put(msg, "world", fp);

    return msg;
}

/**
 * Function to print publisher usage
 */
void usage(const char* name) {
    fprintf(stderr, "usage: %s [-h|--help] [--log-level <log-level>] "
                    "<json-config> [topic]\n", name);
    fprintf(stderr, "\t-h|--help   - Show this help\n");
    fprintf(stderr, "\t--log-level - Log level, must be DEBUG, INFO, WARN, "
                    "or ERROR (df: INFO)\n");
    fprintf(stderr, "\tjson-config - Path to JSON configuration file\n");
    fprintf(stderr, "\ttopic       - (Optional) Topic string "\
                    "(df: publish_test)\n");
}

/**
 * Signal handler
 */
void signal_handler(int signo) {
    LOG_INFO_0("Signaling publisher to quit...");
    g_stop = true;
}

int main(int argc, char** argv) {
    void* msgbus_ctx = NULL;
    publisher_ctx_t* pub_ctx = NULL;
    msg_envelope_t* msg = NULL;
    msgbus_ret_t ret = MSG_SUCCESS;
    log_lvl_t log_level = LOG_LVL_INFO;

    // Index of the JSON configuration CLI parameter (varies based on if the
    // log level is set via the command line).
    int config_idx = 1;
    int topic_idx = 2;
    int topic_argc = 3;

    if (argc == 1) {
        LOG_ERROR_0("Too few arguments");
        return -1;
    } else if (argc > 5) {
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
        topic_idx = config_idx + 1;
        topic_argc = 5;
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

    if (argc == topic_argc)
         ret = msgbus_publisher_new(msgbus_ctx, argv[topic_idx], &pub_ctx);
    else
         ret = msgbus_publisher_new(msgbus_ctx, TOPIC, &pub_ctx);

    if (ret != MSG_SUCCESS) {
        LOG_ERROR("Failed to initialize publisher (errno: %d)", ret);
        goto err;
    }

    // Initialize message to be published
    msg = initialize_message();
    if (msg == NULL) {
        LOG_ERROR_0("Failed to initialize message");
        goto err;
    }

    LOG_INFO_0("Running...");
    while (!g_stop) {
        LOG_INFO_0("Publishing message");
        ret = msgbus_publisher_publish(msgbus_ctx, pub_ctx, msg);
        if (ret != MSG_SUCCESS) {
            LOG_ERROR("Failed to publish message (errno: %d)", ret);
            goto err;
        }
        sleep(1);
    }

    if (msg != NULL)
        msgbus_msg_envelope_destroy(msg);
    if (pub_ctx != NULL)
        msgbus_publisher_destroy(msgbus_ctx, pub_ctx);
    if (msgbus_ctx != NULL)
        msgbus_destroy(msgbus_ctx);


    return 0;

err:
    if (msg != NULL)
        msgbus_msg_envelope_destroy(msg);
    if (pub_ctx != NULL)
        msgbus_publisher_destroy(msgbus_ctx, pub_ctx);
    if (msgbus_ctx != NULL)
        msgbus_destroy(msgbus_ctx);

    return -1;
}
