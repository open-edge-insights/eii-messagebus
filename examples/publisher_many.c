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
 * @brief Message bus application example with many publishers
 * @author Kevin Midkiff (kevin.midkiff@intel.com)
 */

#include <signal.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "eis/msgbus/msgbus.h"
#include "eis/msgbus/logger.h"
#include "eis/msgbus/json_config.h"

// Globals
int g_num_publishers = 0;
pthread_mutex_t g_mutex;
pthread_cond_t g_cv;
pthread_t** g_pub_threads = NULL;
void* g_msgbus_ctx = NULL;
bool g_stop = false;

/**
 * Structure to contain state for a publisher thread
 */
typedef struct {
    msg_envelope_t* msg;
    publisher_ctx_t* pub_ctx;
} pub_thread_ctx_t;

/**
 * Helper to initailize the message to be published
 */
msg_envelope_t* initialize_message(const char* topic) {
    // Creating message to be published
    msg_envelope_elem_body_t* integer = msgbus_msg_envelope_new_integer(42);
    msg_envelope_elem_body_t* fp = msgbus_msg_envelope_new_floating(55.5);
    msg_envelope_elem_body_t* string = msgbus_msg_envelope_new_string(topic);

    msg_envelope_t* msg = msgbus_msg_envelope_new(CT_JSON);

    msgbus_msg_envelope_put(msg, "hello", integer);
    msgbus_msg_envelope_put(msg, "world", fp);
    msgbus_msg_envelope_put(msg, "topic", string);

    return msg;
}

/**
 * Publisher run method
 */
void* pub_run(void* vargs) {
    bool keep_running = true;
    pub_thread_ctx_t* ctx = (pub_thread_ctx_t*) vargs;

    while(keep_running) {
        msgbus_publisher_publish(g_msgbus_ctx, ctx->pub_ctx, ctx->msg);

        sleep(1);

        pthread_mutex_lock(&g_mutex);
        keep_running = !g_stop;
        pthread_mutex_unlock(&g_mutex);
    }

    pthread_mutex_lock(&g_mutex);
    msgbus_publisher_destroy(g_msgbus_ctx, ctx->pub_ctx);
    pthread_mutex_unlock(&g_mutex);

    msgbus_msg_envelope_destroy(ctx->msg);
    free(ctx);

    return NULL;
}

/**
 * Signal handler
 */
void signal_handler(int signo) {
    LOG_INFO_0("Cleaning up");

    // Set stop flag
    LOG_INFO_0("Setting stop flag");
    pthread_mutex_lock(&g_mutex);
    g_stop = true;
    pthread_mutex_unlock(&g_mutex);

    // Join with all publisher threads
    for(int i = 0; i < g_num_publishers; i++) {
        if(g_pub_threads[i] != NULL) {
            LOG_INFO("Waiting to join with publisher thread %d", i);
            pthread_join(*g_pub_threads[i], NULL);
            free(g_pub_threads[i]);
            g_pub_threads[i] = NULL;
            LOG_INFO("Publisher thread %d joined", i);
        }
    }

    // Clean up the rest
    LOG_INFO_0("Cleaning up the rest of the state");
    free(g_pub_threads);
    msgbus_destroy(g_msgbus_ctx);

    // Signal main to stop
    pthread_cond_signal(&g_cv);
}

/**
 * Function to print usage
 */
void usage(const char* name) {
    fprintf(stderr, "usage: %s [-h|--help] <json-config> <n-pubs>\n", name);
    fprintf(stderr, "\t-h|--help   - Show this help\n");
    fprintf(stderr, "\tjson-config - Path to JSON configuration file\n");
    fprintf(stderr, "\tn-pubs      - Number of publishers\n");
}

int main(int argc, char** argv) {
    if(argc < 3) {
        if(argc == 2) {
            if(strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
                usage(argv[0]);
                return 0;
            } else {
                LOG_ERROR_0("Too few arguments");
                return -1;
            }
        } else {
            LOG_ERROR_0("Too few arguments");
            return -1;
        }
    } else if(argc > 3) {
        LOG_ERROR_0("Too many arguments");
        return -1;
    }

    char* config_file = argv[1];
    g_num_publishers = atoi(argv[2]);

    LOG_INFO("Initializing msgbus context with config '%s'", config_file);
    config_t* config = msgbus_json_config_new(config_file);
    if(config == NULL) {
        LOG_ERROR_0("Failed to load configuration file");
        return -1;
    }

    g_msgbus_ctx = msgbus_initialize(config);
    if(g_msgbus_ctx == NULL) {
        LOG_ERROR_0("Failed to initialize the message bus context");
        msgbus_config_destroy(config);
        return -1;
    }

    LOG_INFO("Initializing %d publishsers", g_num_publishers);

    pthread_mutex_init(&g_mutex, NULL);
    pthread_cond_init(&g_cv, NULL);

    g_pub_threads = (pthread_t**) malloc(
            sizeof(pthread_t*) * g_num_publishers);

    // Assign all pthread contexts to NULL to keep clean up easy
    for(int i = 0; i < g_num_publishers; i++) {
        g_pub_threads[i] = NULL;
    }

    msgbus_ret_t ret;
    for(int i = 0; i < g_num_publishers; i++) {
        pub_thread_ctx_t* ctx = (pub_thread_ctx_t*) malloc(
                sizeof(pub_thread_ctx_t));
        char topic[64];

        // Create topic string
        sprintf(topic, "pub-%d", i);

        LOG_INFO("Initializing publisher for topic: %s", topic);

        // Create publisher
        ret = msgbus_publisher_new(g_msgbus_ctx, topic, &ctx->pub_ctx);
        if(ret != MSG_SUCCESS) {
            LOG_ERROR("Error creating publisher (errno: %d)", ret);
            goto err;
        }

        // Create the message for the publisher to send
        ctx->msg = initialize_message(topic);

        // Start publisher thread
        g_pub_threads[i] = (pthread_t*) malloc(sizeof(pthread_t));
        pthread_create(g_pub_threads[i], NULL, pub_run, (void*) ctx);
    }

    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Wait for signal to stop
    pthread_mutex_lock(&g_mutex);
    pthread_cond_wait(&g_cv, &g_mutex);
    pthread_mutex_unlock(&g_mutex);

    pthread_mutex_destroy(&g_mutex);
    pthread_cond_destroy(&g_cv);

    return 0;

err:
    // Run signal handler (it does all the clean up needed)
    signal_handler(0);

    pthread_mutex_destroy(&g_mutex);
    pthread_cond_destroy(&g_cv);

    return -1;
}
