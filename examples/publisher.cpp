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
 * @brief Example EII message bus publisher using the C++ API wrappers.
 */

#include <eii/utils/json_config.h>
#include <signal.h>
#include <chrono>
#include <thread>
#include <cstring>
#include <string>
#include <atomic>
#include <eii/msgbus/msgbus.hpp>
#include "common.h"

#define TOPIC "publish_test"

// Globals for cleaning up nicely
std::atomic<bool> g_stop(false);

/**
 * Signal handler
 */
void signal_handler(int signo) {
    g_stop.store(true);
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

int main(int argc, char** argv) {
    std::string topic(TOPIC);
    log_lvl_t log_level = LOG_LVL_INFO;
    eii::msgbus::MsgbusContext* ctx = NULL;
    eii::msgbus::MsgEnvelope* msg = NULL;
    eii::msgbus::Publisher* publisher = NULL;

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

    if (argc == topic_argc) {
        topic = std::string(argv[topic_idx]);
    }

    LOG_INFO("Loading JSON configuration: %s", argv[config_idx]);
    config_t* config = json_config_new(argv[config_idx]);
    if (config == NULL) {
        LOG_ERROR_0("Failed to load JSON configuration");
        return -1;
    }

    try {
        LOG_INFO_0("Initializing message bus context");
        ctx = new eii::msgbus::MsgbusContext(config);

        LOG_INFO("Initializing publisher for topic: %s", topic.c_str());
        publisher = ctx->new_publisher(topic);

        while (!g_stop.load()) {
            // Initialize a new message envelope
            // IMPORTANT NOTE: Every published message MUST be created new
            // before publishing. NEVER re-use a given MsgEnvelope object.
            msg = new eii::msgbus::MsgEnvelope(CT_JSON);
            msg->put_integer("hello", 42);
            msg->put_float("world", 55.5);

            LOG_INFO_0("Publishing message");
            publisher->publish(msg);

            // Delete the message after publish
            delete msg;
            // Setting to NULL as to not re-use the message envelope object
            msg = NULL;

            // Sleep for 1 second
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    } catch (const eii::msgbus::MsgbusException& ex) {
        LOG_ERROR("Error in publisher: %s", ex.what());

        if (msg != NULL) { delete msg; }
        if (publisher != NULL) { delete publisher; }
        if (ctx != NULL) { delete ctx; }

        return -1;
    }

    LOG_INFO_0("Quitting...");
    delete publisher;
    delete ctx;
    if (msg != NULL) { delete msg; }

    return 0;
}
