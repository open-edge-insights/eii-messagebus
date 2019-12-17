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
// FROM,OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

/**
 * @brief ZeroMQ protocol implementation
 * @author Kevin Midkiff <kevin.midkiff@intel.com>
 */

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include <zmq.h>
#include <safe_lib.h>
#include <eis/utils/logger.h>

#include "eis/msgbus/zmq.h"

#define SOCKET_DIR    "socket_dir"
#define PORT          "port"
#define HOST          "host"
#define ZAP_URI       "inproc://zeromq.zap.01"
#define ZAP_CURVE     "CURVE"
#define IPC_PREFIX    "ipc://"
#define IPC_PREFIX_LEN 6
#define TCP_PREFIX     "tcp://"
#define TCP_PREFIX_LEN 6
#define ZEROMQ_HWM     "zmq_recv_hwm"

#define LOG_ZMQ_ERROR(msg) \
    LOG_ERROR(msg ": [%d] %s", zmq_errno(), zmq_strerror(zmq_errno()));

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
 * Internal ZeroMQ send context for publications and services.
 */
typedef struct {
    // Underlying ZeroMQ socket object
    void* socket;

    // inproc socket monitor ZeroMQ socket object
    void* monitor;

    // Name of the socket context (i.e. topic, service name, etc.)
    char* name;
    size_t name_len;

    // Disconnected
    bool disconnected;
} zmq_sock_ctx_t;

/**
 * Internal ZeroMQ protocol context
 */
typedef struct {
    void* zmq_context;
    bool is_ipc;
    config_t* config;
    int zmq_recv_hwm;

    // Known config values alread extracted from the configuration
    union {
        struct {
            config_value_t* socket_dir;
        } ipc;
        struct {
            config_value_t* pub_host;
            int64_t pub_port;
            void* pub_socket;
            pthread_mutex_t* pub_mutex;
            config_value_t* pub_config;
            zap_ctx_t* zap;
        } tcp;
    } cfg;
} zmq_proto_ctx_t;

/**
 * ZeroMQ receive context types
 */
typedef enum {
    RECV_SUBSCRIBER = 0,
    RECV_SERVICE = 1,
    RECV_SERVICE_REQ = 2,
} recv_type_t;

/**
 * Internal ZeroMQ receive context
 */
typedef struct {
    recv_type_t type;
    zmq_sock_ctx_t* sock_ctx;
} zmq_recv_ctx_t;

// Helper method to generate a random string of the given size (only using
// caps in this case).
char* generate_random_str(int len) {
    static const char ucase[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    char* str = (char*) malloc(sizeof(char) * (len + 1));
    if(str == NULL) {
        LOG_ERROR_0("Out of memory generating random string");
        return NULL;
    }

    for(int i = 0; i < len; i++) {
        str[i] = ucase[rand() % 26];
    }

    str[len - 1] = '\0';

    return str;
}

/**
 * Secure helper function for concatinating a list of c-strings.
 */
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

/**
 * Helper function for creating ZeroMQ URI for binding/connecting a given
 * socket.
 */
char* create_uri(zmq_proto_ctx_t* ctx, const char* name, bool is_publisher) {
    char* uri = NULL;
    config_value_t* host = NULL;

    if(ctx->is_ipc) {
        // Temp pointer to the socket directory
        char* sock_dir = ctx->cfg.ipc.socket_dir->body.string;
        // Get all string portion lengths
        size_t name_len = strlen(name);
        size_t socket_dir_len = strlen(sock_dir);
        size_t total_len = sizeof(char) * (socket_dir_len + name_len + 12);

        uri = concat_s(total_len, 4, IPC_PREFIX, sock_dir, "/", name);
        if(uri == NULL) {
            return NULL;
        }
    } else {
        const char* host_str = NULL;
        int64_t port_int = -1;

        if(is_publisher) {
            host_str = ctx->cfg.tcp.pub_host->body.string;
            port_int = ctx->cfg.tcp.pub_port;
        } else {
            config_value_t* conf = ctx->config->get_config_value(
                    ctx->config->cfg, name);
            if(conf == NULL) {
                LOG_DEBUG_0("ZeroMQ TCP not configured for publishing");
                return NULL;
            } else if(conf->type != CVT_OBJECT) {
                LOG_DEBUG("Configuration for '%s' must be an object", name);
                config_value_destroy(conf);
                return NULL;
            }

            config_value_t* port = ctx->config->get_config_value(
                    conf->body.object->object, PORT);
            if(port == NULL) {
                LOG_ERROR("Configuration for '%s' missing '%s'", name, PORT);
                config_value_destroy(conf);
                return NULL;
            } else if(port->type != CVT_INTEGER) {
                LOG_ERROR_0("Port must be an integer");
                config_value_destroy(port);
                config_value_destroy(conf);
                return NULL;
            }

            host = ctx->config->get_config_value(
                    conf->body.object->object, HOST);
            if(host == NULL) {
                LOG_ERROR("Configuration for '%s' missing '%s'", name, HOST);
                config_value_destroy(port);
                config_value_destroy(conf);
                return NULL;
            } else if(host->type != CVT_STRING) {
                LOG_ERROR_0("Host must be string");
                config_value_destroy(host);
                config_value_destroy(port);
                config_value_destroy(conf);
                return NULL;
            }

            host_str = host->body.string;
            port_int = port->body.integer;

            config_value_destroy(port);
            config_value_destroy(conf);
        }

        // Get length of string for the port
        // Adding 1 for null termintator
        int port_len = snprintf(NULL, 0, "%ld", port_int) + 1;
        char* const port_str = (char*) malloc(sizeof(char) * port_len);

        // This is the only required sprintf, it is the only portable way to
        // convert an integer to a string
        snprintf(port_str, port_len, "%ld", port_int);

        size_t host_len = strlen(host_str);
        size_t uri_len = sizeof(char) * (port_len + host_len + 11);
        uri = concat_s(uri_len, 4, TCP_PREFIX, host_str, ":", port_str);
        if(uri == NULL) {
            config_value_destroy(host);
            free(port_str);
            return NULL;
        }

        free(port_str);
        if(host != NULL)
            config_value_destroy(host);
    }

    return uri;
}

// ZeroMQ helper function to close a socket with no linger for currently
// sending messages
void close_zero_linger(void* socket) {
    int linger = 0;
    zmq_setsockopt(socket, ZMQ_LINGER, &linger, sizeof(linger));
    zmq_close(socket);
}

static const char* get_event_str(int event) {
    switch(event) {
        case ZMQ_EVENT_CONNECTED:       return "ZMQ_EVENT_CONNECTED";
        case ZMQ_EVENT_CONNECT_DELAYED: return "ZMQ_EVENT_CONNECT_DELAYED";
        case ZMQ_EVENT_CONNECT_RETRIED: return "ZMQ_EVENT_CONNECT_RETRIED";
        case ZMQ_EVENT_LISTENING:       return "ZMQ_EVENT_LISTENING";
        case ZMQ_EVENT_BIND_FAILED:     return "ZMQ_EVENT_BIND_FAILED";
        case ZMQ_EVENT_ACCEPTED:        return "ZMQ_EVENT_ACCEPTED";
        case ZMQ_EVENT_CLOSED:          return "ZMQ_EVENT_CLOSED";
        case ZMQ_EVENT_CLOSE_FAILED:    return "ZMQ_EVENT_CLOSE_FAILED";
        case ZMQ_EVENT_DISCONNECTED:    return "ZMQ_EVENT_DISCONNECTED";
        case ZMQ_EVENT_MONITOR_STOPPED: return "ZMQ_EVENT_MONITOR_STOPPED";
        case ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL:
            return "ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL";
        case ZMQ_EVENT_HANDSHAKE_SUCCEEDED:
            return "ZMQ_EVENT_HANDSHAKE_SUCCEEDED";
        case ZMQ_EVENT_HANDSHAKE_FAILED_PROTOCOL:
            return "ZMQ_EVENT_HANDSHAKE_FAILED_PROTOCOL";
        case ZMQ_EVENT_HANDSHAKE_FAILED_AUTH:
            return "ZMQ_EVENT_HANDSHAKE_FAILED_AUTH";
        default: return "";
    }
}

// Helper method to see if any events occured on a given socket
int get_monitor_event(void* monitor, bool block) {
    zmq_msg_t msg;
    zmq_msg_init(&msg);

    int flag = ZMQ_DONTWAIT;
    if(block)
        flag = 0;

    if(zmq_msg_recv(&msg, monitor, flag) == -1) {
        zmq_msg_close(&msg);
        if(zmq_errno() == EAGAIN && !block) {
            return 0;
        }
        return -1;
    }

    // Get the event which occurred
    uint16_t event = *(uint16_t*)((uint8_t*) zmq_msg_data(&msg));
    zmq_msg_close(&msg);

    LOG_DEBUG("ZeroMQ socket event: %s", get_event_str(event));

    // Retrieve second frame
    zmq_msg_init(&msg);
    // Ignore any errors since we do not care about the contents of the message
    zmq_msg_recv(&msg, monitor, 0);
    zmq_msg_close(&msg);

    return event;
}

// ----------
// NOTE: Commented out for now, this method may be required in the future,
// keeping it for now
//
// Helper function to wait until a socket is connected
// msgbus_ret_t wait_client_connected(void* monitor) {
//     LOG_DEBUG_0("Waiting for successful connection");
//     int event = get_monitor_event(monitor, true);
//
//     if(event == ZMQ_EVENT_CONNECT_DELAYED) {
//         LOG_DEBUG_0("Connection delayed.. Still waiting");
//         event = get_monitor_event(monitor, true);
//     }
//
//     if(event != ZMQ_EVENT_CONNECTED) {
//         LOG_ERROR_0("Socket failed to connect");
//         return MSG_ERR_UNKNOWN;
//     }
//
//     event = get_monitor_event(monitor, true);
//     if(event != ZMQ_EVENT_HANDSHAKE_SUCCEEDED) {
//         LOG_ERROR_0("ZeroMQ handshake failed");
//         return MSG_ERR_AUTH_FAILED;
//     }
//
//     return MSG_SUCCESS;
// }
// ----------

msgbus_ret_t sock_ctx_new(
        void* zmq_ctx, const char* name, void* socket,
        zmq_sock_ctx_t** sock_ctx)
{
    LOG_DEBUG("Creating socket context for %s", name);
    char* monitor_uri = NULL;
    zmq_sock_ctx_t* ctx = (zmq_sock_ctx_t*) malloc(sizeof(zmq_sock_ctx_t));
    if(ctx == NULL)
        return MSG_ERR_NO_MEMORY;

    // Assign the name of the socket context
    ctx->disconnected = false;
    ctx->name_len = strlen(name) + 1;
    ctx->name = (char*) malloc(sizeof(char) * ctx->name_len);
    ctx->monitor = NULL;
    if(ctx->name == NULL)
        goto err;
    memcpy_s(ctx->name, ctx->name_len, name, ctx->name_len);
    ctx->name[ctx->name_len - 1] = '\0';

    // Assign the socket
    ctx->socket = socket;

    // Create URI for socket monitor
    // Generating random part of string in case there are multiple services
    // or publishers with the same name. There can only be one monitor socket
    // per monitor URI
    const char* rand_str = generate_random_str(5);
    if(rand_str == NULL) {
        LOG_ERROR_0("Failed to initialize random string");
        goto err;
    }

    size_t total_len = strlen(rand_str) + strlen(name) + 14;
    monitor_uri = concat_s(total_len, 4, "inproc://", rand_str, "-", name);
    free((void*) rand_str);
    if(monitor_uri == NULL) {
        LOG_ERROR_0("Failed to initialize monotor URI for the new socket");
        goto err;
    }

    LOG_DEBUG("Creating socket monitor for %s", monitor_uri);
    int rc = zmq_socket_monitor(socket, monitor_uri, ZMQ_EVENT_ALL);
    if(rc == -1) {
        // Only an error if the socket has not been bound already, if it has
        // then it is okay
        if(zmq_errno() != EADDRINUSE) {
            LOG_ZMQ_ERROR("Failed creating socket monitor");
            goto err;
        }
    }

    // Create monitor socket
    ctx->monitor = zmq_socket(zmq_ctx, ZMQ_PAIR);
    if(ctx->monitor == NULL) {
        LOG_ZMQ_ERROR("Failed to create ZMQ_PAIR monitor socket");
        goto err;
    }

    // Connect monitor socket
    LOG_DEBUG_0("Connecting monitor ZMQ socket");
    rc = zmq_connect(ctx->monitor, monitor_uri);
    if(rc == -1) {
        LOG_ZMQ_ERROR("Failed to connect to monitor URI");
        goto err;
    }

    *sock_ctx = ctx;
    free(monitor_uri);

    LOG_DEBUG_0("Finished adding monitor for ZMQ socket");

    return MSG_SUCCESS;

err:
    sock_ctx = NULL;
    if(ctx != NULL) {
        if(ctx->name != NULL)
            free(ctx->name);
        if(ctx->monitor != NULL)
            close_zero_linger(ctx->monitor);
        free(ctx);
    }
    if(monitor_uri != NULL)
        free(monitor_uri);
    return MSG_ERR_UNKNOWN;
}

void sock_ctx_destroy(zmq_sock_ctx_t* ctx, bool close_socket) {
    if(ctx != NULL) {
        if(ctx->name != NULL)
            free(ctx->name);
        if(ctx->socket != NULL && close_socket)
            close_zero_linger(ctx->socket);
        if(ctx->monitor != NULL)
            close_zero_linger(ctx->monitor);
        free(ctx);
    }
}

/**
 * Helper function for setting the ZMQ_RCVHWM socket option on a ZMQ socket.
 *
 * \note Returns true immediately if zmq_rcvhwm < 0
 *
 * @param socket     - ZeroMQ socket
 * @param zmq_rcvhwm - ZeroMQ receive high watermark value
 * @return bool
 */
bool set_rcv_hwm(void* socket, int zmq_rcvhwm) {
    if(zmq_rcvhwm < 0) return true;

    int ret = zmq_setsockopt(socket, ZMQ_RCVHWM, &zmq_rcvhwm, sizeof(int));
    if(ret != 0) {
        LOG_ZMQ_ERROR("Failed setting ZMQ_RCVHWM");
        return false;
    }

    return true;
}

bool verify_key_len(const char* key);

// Macro to make receiving ZAP frames simpler
#define ZAP_RECV(dest) { \
    rc = zmq_recv(zap_ctx->socket, dest, 255, 0); \
    if(rc == -1) { \
        LOG_ZMQ_ERROR("Failed to receive ZAP frame"); \
        continue; \
    } \
}

// Macro to make sending ZAP responses simpler
#define ZAP_SEND(msg, send_more) { \
    rc = zmq_send(zap_ctx->socket, msg, strlen(msg), send_more); \
    if(rc == -1) { \
        LOG_ZMQ_ERROR("Failed sending ZAP response"); \
        continue; \
    } \
}

void* zap_run(void* vargs) {
    zap_ctx_t* zap_ctx = (zap_ctx_t*) vargs;
    bool keep_running = true;
    bool accepted = false;
    int rc = 0;
    int ind = 0;
    size_t curve_len = strlen(ZAP_CURVE);
    zmq_pollitem_t poll_items[] = {{ zap_ctx->socket, 0, ZMQ_POLLIN, 0 }};

    // ZAP fields (All fields have a max size of 255, see ZAP spec)
    char version[255];
    char request_id[255];
    char domain[255];
    char address[255];
    char identity[255];
    char mechanism[255];
    uint8_t client_public_key[32];
    char encoded_key[41];

    LOG_DEBUG_0("ZeroMQ ZAP thread started");

    // Using while(true) here so inner code block can utilize continue and
    // still exit promptly when ZMQ protocol context is destroyed
    while(true) {
        // Check if the thread should stop
        if(pthread_mutex_lock(&zap_ctx->mtx_stop) != 0) {
            LOG_DEBUG_0("Unable to lock mutex...");
        }
        keep_running = !zap_ctx->stop;
        if(pthread_mutex_unlock(&zap_ctx->mtx_stop) != 0) {
            LOG_DEBUG_0("Unable to unlock mutex...");
        }

        if(!keep_running)
            break;

        // Poll for poll_items
        zmq_poll(poll_items, 1, 1000);

        if(!(poll_items[0].revents & ZMQ_POLLIN))
            continue;

        // Receive all ZAP request fields
        ZAP_RECV(version);
        ZAP_RECV(request_id);
        ZAP_RECV(domain);
        ZAP_RECV(address);
        ZAP_RECV(identity);
        ZAP_RECV(mechanism);

        LOG_DEBUG(
            "ZAP REQUEST:\n"
            "\tVERSION...: %s\n"
            "\tREQUEST ID: %s\n"
            "\tDOMAIN....: %s\n"
            "\tADDRESS...: %s\n"
            "\tIDENTITY..: %s\n"
            "\tMECHANISM.: %s\n",
            version, request_id, domain, address, identity, mechanism);

        // Verify that the mechanism is "CURVE" and not NULL nor PLAIN
        strcmp_s(mechanism, curve_len, ZAP_CURVE, &ind);
        if(ind != 0) {
            LOG_WARN("Received ZAP request with non CURVE mechanism: %s",
                       mechanism);
            continue;
        }

        // Receive the client's public key
        ZAP_RECV(client_public_key);
        zmq_z85_encode(encoded_key, client_public_key, 32);

        // TODO: This NEEDs to be optimized by using a hashmap rather than
        // traversing an array each time
        for(int i = 0; i < zap_ctx->num_allowed_clients; i++) {
            strcmp_s(encoded_key, strlen(encoded_key),
                    zap_ctx->allowed_clients[i], &ind);
            if(ind == 0) {
                accepted = true;
                break;
            }
        }

#ifdef DEBUG
        if(accepted) {
            LOG_DEBUG_0("Client authentication successful");
        } else {
            LOG_DEBUG_0("Client authentication denied");
        }
#endif

        // Send authentication response
        ZAP_SEND("1.0", ZMQ_SNDMORE);      // Version
        ZAP_SEND(request_id, ZMQ_SNDMORE); // Request ID
        ZAP_SEND(accepted ? "200" : "400", ZMQ_SNDMORE); // Accepted
        ZAP_SEND("", ZMQ_SNDMORE);         // Status text
        ZAP_SEND("", ZMQ_SNDMORE);         // User ID
        ZAP_SEND("", 0);                   // Meta data
    }

    return NULL;
}

void zap_destroy(zap_ctx_t* zap_ctx) {
    LOG_DEBUG_0("Destroying ZAP thread");

    // Set stop flag
    if(pthread_mutex_lock(&zap_ctx->mtx_stop) != 0) {
        LOG_DEBUG_0("Unable to lock mutex");
    }

    zap_ctx->stop = true;
    if(pthread_mutex_unlock(&zap_ctx->mtx_stop) != 0) {
        LOG_DEBUG_0("Unable to unlock mutex");
    }

    // Join with the ZAP thread
    LOG_DEBUG_0("Waiting for ZAP thread to join");
    pthread_join(zap_ctx->th, NULL);

    // Destroy mutex
    if(pthread_mutex_destroy(&zap_ctx->mtx_stop) != 0) {
        LOG_DEBUG_0("Unable to destroy mutex");
    }


    // Close ZeroMQ socket
    zmq_close(zap_ctx->socket);

    // Destroy config value
    for(int i = 0; i < zap_ctx->num_allowed_clients; i++) {
        free(zap_ctx->allowed_clients[i]);
    }
    free(zap_ctx->allowed_clients);

    // Final free
    free(zap_ctx);
}

int zap_initialize(void* zmq_ctx, config_t* config, zap_ctx_t** zap_ctx) {
    zap_ctx_t* ctx = NULL;
    void* socket = NULL;
    int rc = 0;

    // Get configuration value for the allowed clients
    config_value_t* obj = config->get_config_value(
            config->cfg, ZMQ_CFG_TCP_ALLOWED_CLIENTS);
    if(obj == NULL) {
        LOG_WARN_0("Running ZeroMQ TCP sockets without ZAP authentication");
        rc = -2;
        goto err;
    }

    if(obj->type != CVT_ARRAY) {
        LOG_ERROR("ZeroMQ config '%s' must be a list of strings",
                  ZMQ_CFG_TCP_ALLOWED_CLIENTS);
        goto err;
    }

    // Initialize ZeroMQ socket
    socket = zmq_socket(zmq_ctx, ZMQ_REP);
    if(socket == NULL) {
        LOG_ZMQ_ERROR("Error opening ZAP ZeroMQ socket");
        rc = -1;
        goto err;
    }

    // Binding socket
    rc = zmq_bind(socket, ZAP_URI);
    if(rc != 0) {
        LOG_ZMQ_ERROR("Failed to bind to ZAP URI");
        rc = -1;
        goto err;
    }

    ctx = (zap_ctx_t*) malloc(sizeof(zap_ctx_t));
    if(ctx == NULL) {
        LOG_ERROR_0("Out of memory initializing ZAP thread");
        rc = -1;
        goto err;
    }

    ctx->socket = socket;
    ctx->allowed_clients = NULL;
    ctx->stop = false;

    // Copy over the allowed cients
    config_value_array_t* arr = obj->body.array;
    size_t len = arr->length;
    ctx->allowed_clients = (char**) malloc(sizeof(char*) * len);
    if(ctx->allowed_clients == NULL) {
        LOG_ERROR_0("Out of memory initializing ZAP allowed clients");
        goto err;
    }
    ctx->num_allowed_clients= len;
    // Initialize all char's
    for(int i = 0; i < len; i++) {
        ctx->allowed_clients[i] = (char*) malloc(sizeof(char) * 41);
        if(ctx->allowed_clients[i] == NULL) {
            LOG_ERROR_0("Out of memory intiailizing ZAP allowed clients");
            goto err;
        }
    }

    // TODO: Make this a hashmap in the future for efficient key lookup
    for(int i = 0; i < len; i++) {
        config_value_t* cvt_key = arr->get(arr->array, i);
        if(cvt_key == NULL) {
            LOG_ERROR_0("Failed to get array element");
            goto err;
        } else if(cvt_key->type != CVT_STRING) {
            LOG_ERROR_0("All allowed keys must be strings");
            config_value_destroy(cvt_key);
            goto err;
        } else if(!verify_key_len(cvt_key->body.string)) {
            LOG_ERROR_0("Incorrect key length, must be 40 characters");
            config_value_destroy(cvt_key);
            goto err;
        }

        // Copy over the string
        memcpy_s(ctx->allowed_clients[i], 40, cvt_key->body.string, 40);
        ctx->allowed_clients[i][40] = '\0';
        config_value_destroy(cvt_key);
    }

    pthread_mutex_init(&ctx->mtx_stop, NULL);
    pthread_create(&ctx->th, NULL, zap_run, (void*) ctx);

    config_value_destroy(obj);

    *zap_ctx = ctx;

    return rc;
err:
    if(obj != NULL)
        config_value_destroy(obj);
    if(ctx != NULL) {
        if(ctx->allowed_clients != NULL) {
            for(int i = 0; i < ctx->num_allowed_clients; i++) {
                free(ctx->allowed_clients[i]);
            }
            free(ctx->allowed_clients);
        }
        free(ctx);
    }
    if(socket != NULL)
        zmq_close(socket);
    *zap_ctx = NULL;
    return rc;
}

// Prototypes
void proto_zmq_destroy(void* ctx);

msgbus_ret_t send_message(zmq_sock_ctx_t* ctx, msg_envelope_t* msg);

msgbus_ret_t proto_zmq_publisher_new(
        void* ctx, const char* topic, void** pub_ctx);

msgbus_ret_t proto_zmq_publisher_publish(
        void* ctx, void* pub_ctx, msg_envelope_t* msg);

void proto_zmq_publisher_destroy(void* ctx, void* pub_ctx);

msgbus_ret_t proto_zmq_subscriber_new(
    void* ctx, const char* topic, void** subscriber);

void proto_zmq_recv_ctx_destroy(void* ctx, void* recv_ctx);

msgbus_ret_t proto_zmq_recv_wait(
        void* ctx, void* recv_ctx, msg_envelope_t** message);

msgbus_ret_t proto_zmq_recv_timedwait(
        void* ctx, void* recv_ctx, int timeout, msg_envelope_t** message);

msgbus_ret_t proto_zmq_recv_nowait(
        void* ctx, void* recv_ctx, msg_envelope_t** message);

msgbus_ret_t proto_zmq_service_get(
        void* ctx, const char* service_name, void** service_ctx);

msgbus_ret_t proto_zmq_service_new(
        void* ctx, const char* service_name, void** service_ctx);

msgbus_ret_t proto_zmq_request(
        void* ctx, void* service_ctx, msg_envelope_t* msg);

msgbus_ret_t proto_zmq_response(
        void* ctx, void* service_ctx, msg_envelope_t* message);

protocol_t* proto_zmq_initialize(const char* type, config_t* config) {
    // TODO: Clean up method to make sure all memeory is fully freed always
    LOG_DEBUG_0("Initilizing zeromq message bus");

    // Initialize protocol context structure
    zmq_proto_ctx_t* zmq_proto_ctx = (zmq_proto_ctx_t*) malloc(
            sizeof(zmq_proto_ctx_t));

    // Initialize all proto context values
    zmq_proto_ctx->zmq_context = zmq_ctx_new();
    zmq_proto_ctx->config = config;
    zmq_proto_ctx->zmq_recv_hwm = -1;
    zmq_proto_ctx->is_ipc = false;

    // Initialize IPC configuration values
    zmq_proto_ctx->cfg.ipc.socket_dir = NULL;

    // Initialize TCP configuration values
    zmq_proto_ctx->cfg.tcp.pub_host = NULL;
    zmq_proto_ctx->cfg.tcp.pub_port = 0;
    zmq_proto_ctx->cfg.tcp.pub_socket = NULL;
    zmq_proto_ctx->cfg.tcp.pub_config = NULL;
    zmq_proto_ctx->cfg.tcp.pub_mutex = NULL;

    // Getting ZeroMQ receive high wartermark
    config_value_t* recv_hwm = config_get(config, ZEROMQ_HWM);
    if(recv_hwm != NULL) {
        if(recv_hwm->type != CVT_INTEGER) {
            LOG_ERROR_0("ZeroMQ receive HWM must be an integer");
            config_value_destroy(recv_hwm);
            goto err;
        }

        if(recv_hwm->body.integer < 0) {
            LOG_ERROR_0("ZeroMQ receive HWM must be greater than 0");
            config_value_destroy(recv_hwm);
            goto err;
        }

        zmq_proto_ctx->zmq_recv_hwm = (int) recv_hwm->body.integer;
        LOG_DEBUG("ZeroMQ receive high watermark: %d",
                zmq_proto_ctx->zmq_recv_hwm);
        config_value_destroy(recv_hwm);
    }

    int ind_ipc;
    int ind_tcp;

    strcmp_s(type, strlen(ZMQ_IPC), ZMQ_IPC, &ind_ipc);
    strcmp_s(type, strlen(ZMQ_TCP), ZMQ_TCP, &ind_tcp);

    if(ind_ipc == 0) {
        LOG_DEBUG_0("Initializing ZeroMQ for IPC communication");

        // Set IPC flag
        zmq_proto_ctx->is_ipc = true;

        // Getting socket directory from the configuration
        config_value_t* value = config->get_config_value(
                config->cfg, SOCKET_DIR);

        if(value == NULL) {
            LOG_ERROR("Config missing key '%s'", SOCKET_DIR);
            goto err;
        }

        if(value->type != CVT_STRING) {
            LOG_ERROR("Config key '%s' value must be a string", SOCKET_DIR);
            config_value_destroy(value);
            goto err;
        }

        LOG_DEBUG("ZeroMQ IPC socket directory: %s", value->body.string);
        zmq_proto_ctx->cfg.ipc.socket_dir = value;
    } else if(ind_tcp == 0) {
        LOG_DEBUG_0("Initializing ZeroMQ for TCP communication");

        int rc = zap_initialize(zmq_proto_ctx->zmq_context, config,
                                &zmq_proto_ctx->cfg.tcp.zap);
        if(rc == -1) {
            goto err;
        }

        config_value_t* conf_obj = config->get_config_value(
                config->cfg, ZMQ_CFG_TCP_PUB);
        if(conf_obj == NULL) {
            LOG_DEBUG_0("ZeroMQ TCP not configured for publishing");
            zmq_proto_ctx->cfg.tcp.pub_host = NULL;
            zmq_proto_ctx->cfg.tcp.pub_port = -1;
            zmq_proto_ctx->cfg.tcp.pub_config = NULL;
        } else if(conf_obj->type != CVT_OBJECT) {
            LOG_ERROR("Configuration for '%s' must be an object",
                      ZMQ_CFG_TCP_PUB);
            config_value_destroy(conf_obj);
            goto err;
        } else {
            zmq_proto_ctx->cfg.tcp.pub_mutex = (pthread_mutex_t*) malloc(
                    sizeof(pthread_mutex_t));
            int rc = pthread_mutex_init(
                    zmq_proto_ctx->cfg.tcp.pub_mutex, NULL);
            if(rc != 0) {
                LOG_ERROR_0("Failed to initialize publish mutex");
                config_value_destroy(conf_obj);
                goto err;
            }

            config_value_t* port = config->get_config_value(
                    conf_obj->body.object->object, PORT);
            if(port == NULL) {
                LOG_ERROR("Configuration for '%s' missing '%s'",
                          ZMQ_CFG_TCP_PUB, PORT);
                config_value_destroy(conf_obj);
                goto err;
            } else if(port->type != CVT_INTEGER) {
                LOG_ERROR_0("Port must be an integer");
                config_value_destroy(port);
                config_value_destroy(conf_obj);
                goto err;
            }

            config_value_t* host = config->get_config_value(
                    conf_obj->body.object->object, HOST);
            if(host == NULL) {
                LOG_ERROR("Configuration for '%s' missing '%s'",
                          ZMQ_CFG_TCP_PUB, HOST);
                config_value_destroy(port);
                config_value_destroy(conf_obj);
                goto err;
            } else if(host->type != CVT_STRING) {
                LOG_ERROR_0("Host must be string");
                config_value_destroy(host);
                config_value_destroy(port);
                config_value_destroy(conf_obj);
                goto err;
            }

            zmq_proto_ctx->cfg.tcp.pub_host = host;
            zmq_proto_ctx->cfg.tcp.pub_port = port->body.integer;
            zmq_proto_ctx->cfg.tcp.pub_socket = NULL;
            zmq_proto_ctx->cfg.tcp.pub_config = conf_obj;

            config_value_destroy(port);
        }
    } else {
        LOG_ERROR("Unknown ZeroMQ type: %s, must be %s or %s",
               type, ZMQ_TCP, ZMQ_IPC);
        goto err;
    }

    protocol_t* proto_ctx = (protocol_t*) malloc(sizeof(protocol_t));
    proto_ctx->proto_ctx = (void*) zmq_proto_ctx;

    proto_ctx->destroy = proto_zmq_destroy;

    proto_ctx->publisher_new = proto_zmq_publisher_new;
    proto_ctx->publisher_publish = proto_zmq_publisher_publish;
    proto_ctx->publisher_destroy = proto_zmq_publisher_destroy;

    proto_ctx->subscriber_new = proto_zmq_subscriber_new;

    proto_ctx->request = proto_zmq_request;
    proto_ctx->response = proto_zmq_response;
    proto_ctx->service_get = proto_zmq_service_get;
    proto_ctx->service_new = proto_zmq_service_new;

    proto_ctx->recv_ctx_destroy = proto_zmq_recv_ctx_destroy;
    proto_ctx->recv_wait = proto_zmq_recv_wait;
    proto_ctx->recv_timedwait = proto_zmq_recv_timedwait;
    proto_ctx->recv_nowait = proto_zmq_recv_nowait;

    return proto_ctx;
err:
    proto_zmq_destroy((void*) zmq_proto_ctx);
    return NULL;
}

void proto_zmq_destroy(void* ctx) {
    LOG_DEBUG_0("Destroying zeromq message bus context");
    zmq_proto_ctx_t* zmq_ctx = (zmq_proto_ctx_t*) ctx;

    if(!zmq_ctx->is_ipc) {
        if(zmq_ctx->cfg.tcp.pub_host != NULL) {
            if(pthread_mutex_lock(zmq_ctx->cfg.tcp.pub_mutex) != 0) {
                LOG_DEBUG_0("Unable to lock mutex");
            }

            config_value_destroy(zmq_ctx->cfg.tcp.pub_config);

            // Clean up the socket context object
            zmq_close(zmq_ctx->cfg.tcp.pub_socket);
            zmq_ctx->cfg.tcp.pub_socket = NULL;

            if(pthread_mutex_unlock(zmq_ctx->cfg.tcp.pub_mutex) != 0) {
                LOG_DEBUG_0("Unable to unlock mutex");
            }
            if(pthread_mutex_destroy(zmq_ctx->cfg.tcp.pub_mutex) != 0) {
                LOG_DEBUG_0("Unable to destroy mutex");
            }

            free(zmq_ctx->cfg.tcp.pub_mutex);

            config_value_destroy(zmq_ctx->cfg.tcp.pub_host);
        }

        // Destroy the ZAP thread if it is running
        if(zmq_ctx->cfg.tcp.zap != NULL) {
            LOG_DEBUG_0("Stopping ZAP thread");
            zap_destroy(zmq_ctx->cfg.tcp.zap);
        }
    } else {
        config_value_destroy(zmq_ctx->cfg.ipc.socket_dir);
    }

    LOG_DEBUG_0("Destroying zeromq context");
    zmq_ctx_term(zmq_ctx->zmq_context);

    // Last free for the zmq protocol structure
    free(zmq_ctx);

    LOG_DEBUG_0("Zeromq message bus context destroyed");
}

/**
 * Helper method to verify that the given ZeroMQ curve key is of length 40.
 */
bool verify_key_len(const char* key) {
    size_t key_len = strlen(key);
    if(key_len != 40) {
        LOG_ERROR("ZeroMQ curve key must be 40, not %d", (int) key_len);
        return false;
    }
    return true;
}

/**
 * Helper function to configure the given ZeroMQ socket to act as a Curve
 * server.
 *
 * IMPORTANT NOTE: This method MUST be called prior to the zmq_bind() for the
 * socket.
 *
 * @param socket   - ZeroMQ socket
 * @param conf     - Configuration context
 * @param conf_obj - Configuration object for the TCP socket
 * @return msgbus_ret_t
 */
msgbus_ret_t init_curve_server_socket(
        void* socket, config_t* conf, config_value_t* conf_obj) {
    // Setup security on the socket if it is specified in the config
    config_value_t* secret_cv = conf->get_config_value(
            conf_obj->body.object->object, ZMQ_CFG_SERVER_SECRET);

    if(secret_cv != NULL) {
        LOG_DEBUG_0("Configuring ZeroMQ socket for server side auth");

        if(secret_cv->type != CVT_STRING) {
            LOG_ERROR("Config value for '%s' must be a string",
                      ZMQ_CFG_SERVER_SECRET);
            goto err;
        }

        // Verify key length
        if(!verify_key_len(secret_cv->body.string)) {
            goto err;
        }

        // Set socket as a curve server
        const int enable = 1;
        int ret = zmq_setsockopt(
                socket, ZMQ_CURVE_SERVER, &enable, sizeof(enable));
        if(ret != 0) {
            LOG_ZMQ_ERROR("Failed setting ZMQ_CURVE_SERVER");
            goto err;
        }

        // Set socket secret key
        ret = zmq_setsockopt(
                socket, ZMQ_CURVE_SECRETKEY, secret_cv->body.string, 40);
        if(ret != 0) {
            LOG_ZMQ_ERROR("Failed setting ZMQ_CURVE_SECRETKEY");
            goto err;
        }

        LOG_DEBUG_0("Finished configuring socket for server side auth");
    } else {
        // Returning early here so destroy calls are not executed
        LOG_WARN_0("ZeroMQ TCP socket running without encryption");
        return MSG_SUCCESS;
    }

    config_value_destroy(secret_cv);

    return MSG_SUCCESS;
err:
    if(secret_cv != NULL)
        config_value_destroy(secret_cv);
    return MSG_ERR_UNKNOWN;
}

/**
 * Helper function to configure the given ZeroMQ socket to be a client
 * participating in Curve encryption with the TCP socket it is connecting
 * to.
 *
 * IMPORTANT NOTE: This method MUST be called prior to the zmq_connect() for
 * the socket.
 *
 * @param sock_ctx - Internal socket context structure
 * @param conf     - Configuration context
 * @param conf_obj - Configuration object for the TCP socket
 * @return msgbus_ret_t
 */
msgbus_ret_t init_curve_client_socket(
        zmq_sock_ctx_t* sock_ctx, config_t* conf, config_value_t* conf_obj) {
    void* socket = sock_ctx->socket;

    // Get configuration values
    config_value_t* server_pub_cv = conf->get_config_value(
            conf_obj->body.object->object, ZMQ_CFG_SERVER_PUBLIC_KEY);
    config_value_t* client_pub_cv = conf->get_config_value(
            conf_obj->body.object->object, ZMQ_CFG_CLIENT_PUBLIC_KEY);
    config_value_t* client_secret_cv = conf->get_config_value(
            conf_obj->body.object->object, ZMQ_CFG_CLIENT_SECRET_KEY);

    if(server_pub_cv != NULL && client_pub_cv != NULL
            && client_secret_cv != NULL) {
        LOG_DEBUG_0("Configuring ZeroMQ socket for client side auth");

        // Verify config vlaue types
        if(server_pub_cv->type != CVT_STRING) {
            LOG_ERROR("Configuration value for key %s must be a string",
                      ZMQ_CFG_SERVER_PUBLIC_KEY);
            goto err;
        }
        if(client_pub_cv->type != CVT_STRING) {
            LOG_ERROR("Configuration value for key %s must be a string",
                      ZMQ_CFG_SERVER_PUBLIC_KEY);
            goto err;
        }
        if(client_secret_cv->type != CVT_STRING) {
            LOG_ERROR("Configuration value for key %s must be a string",
                      ZMQ_CFG_SERVER_PUBLIC_KEY);
            goto err;
        }

        // Verify key lengths
        if(!verify_key_len(server_pub_cv->body.string)
                || !verify_key_len(client_pub_cv->body.string)
                || !verify_key_len(client_secret_cv->body.string))
            goto err;

        // Set socket options for the keys
        int ret = zmq_setsockopt(
                socket, ZMQ_CURVE_SERVERKEY, server_pub_cv->body.string, 40);
        if(ret != 0) {
            LOG_ZMQ_ERROR("Failed setting ZMQ_CURVE_SERVERKEY");
            goto err;
        }

        ret = zmq_setsockopt(
                socket, ZMQ_CURVE_PUBLICKEY, client_pub_cv->body.string, 40);
        if(ret != 0) {
            LOG_ZMQ_ERROR("Failed setting ZMQ_CURVE_PUBLICKEY");
            goto err;
        }

        ret = zmq_setsockopt(socket, ZMQ_CURVE_SECRETKEY,
                             client_secret_cv->body.string, 40);
        if(ret != 0) {
            LOG_ZMQ_ERROR("Failed setting ZMQ_CURVE_SECRETKEY");
            goto err;
        }
    } else if(server_pub_cv != NULL || client_pub_cv != NULL
            || client_secret_cv != NULL) {
        LOG_ERROR("ZeroMQ TCP client socket config must have the '%s', '%s', "
                "and '%s' configuration keys specified to enable security",
                  ZMQ_CFG_SERVER_PUBLIC_KEY, ZMQ_CFG_CLIENT_PUBLIC_KEY,
                  ZMQ_CFG_CLIENT_SECRET_KEY);
        goto err;
    } else {
        // Returning early here so destroy calls are not executed
        LOG_WARN_0("ZeroMQ TCP client socket running in insecure mode");
        return MSG_SUCCESS;
    }

    // Destroy config values
    config_value_destroy(server_pub_cv);
    config_value_destroy(client_pub_cv);
    config_value_destroy(client_secret_cv);

    return MSG_SUCCESS;
err:
    if(server_pub_cv != NULL)
        config_value_destroy(server_pub_cv);
    if(client_pub_cv != NULL)
        config_value_destroy(client_pub_cv);
    if(client_secret_cv != NULL)
        config_value_destroy(client_secret_cv);

    return MSG_ERR_UNKNOWN;
}

msgbus_ret_t proto_zmq_publisher_new(
        void* ctx, const char* topic, void** pub_ctx)
{
    // Cast ptr to internal context type
    zmq_proto_ctx_t* zmq_ctx = (zmq_proto_ctx_t*) ctx;
    zmq_sock_ctx_t* sock_ctx = NULL;
    void* socket = NULL;

    LOG_DEBUG("Creating ZeroMQ publisher for topic '%s'", topic);

    // Create the full topic
    char* topic_uri = create_uri(zmq_ctx, topic, true);
    if(topic_uri == NULL) {
        LOG_ERROR("Failed to create URI for topic: %s", topic);
        return MSG_ERR_INIT_FAILED;
    }

    LOG_DEBUG("ZeroMQ publisher URI: %s", topic_uri);

    if(zmq_ctx->is_ipc || zmq_ctx->cfg.tcp.pub_socket == NULL) {
        socket = zmq_socket(zmq_ctx->zmq_context, ZMQ_PUB);
        if(socket == NULL) {
            LOG_ZMQ_ERROR("Failed to initialize ZeroMQ socket");
            goto err;
        }

        // Setting socket_options
        int val = 0;
        int ret = zmq_setsockopt(socket, ZMQ_LINGER, &val, sizeof(val));
        if(ret != 0) {
            LOG_ZMQ_ERROR("Failed setting ZMQ_LINGER");
            goto err;
        }

        // Set the receive high watermark (if it is set for the protocol)
        if(!set_rcv_hwm(socket, zmq_ctx->zmq_recv_hwm)) { goto err; }

        // Initialize socket with Curve authentication if the socket is a TCP
        // socket and the correct values are set in the configuration for the
        // socket
        if(!zmq_ctx->is_ipc) {
            msgbus_ret_t rc = init_curve_server_socket(
                    socket, zmq_ctx->config, zmq_ctx->cfg.tcp.pub_config);
            if(rc != MSG_SUCCESS) {
                goto err;
            }
        }

        // Binding socket
        ret = zmq_bind(socket, topic_uri);
        if(ret != 0) {
            LOG_ZMQ_ERROR("Failed to bind publisher socket");
            goto err;
        }

        LOG_DEBUG_0("ZeroMQ publisher created");

        // Necessary sleep for publisher to be initialized in ZeroMQ
        struct timespec sleep_time;
        sleep_time.tv_sec = 0;
        sleep_time.tv_nsec = 250000000L;
        nanosleep(&sleep_time, NULL);

        msgbus_ret_t rc = sock_ctx_new(
                zmq_ctx->zmq_context, topic, socket, &sock_ctx);
        if(rc != MSG_SUCCESS) {
            LOG_ERROR_0("Failed to initailize socket context");
            goto err;
        }

        if(!zmq_ctx->is_ipc) {
            zmq_ctx->cfg.tcp.pub_socket = sock_ctx->socket;
        }
    } else {
        msgbus_ret_t rc = sock_ctx_new(
                zmq_ctx->zmq_context, topic, zmq_ctx->cfg.tcp.pub_socket,
                &sock_ctx);
        if(rc != MSG_SUCCESS) {
            LOG_ERROR_0("Failed to initailize socket context");
            goto err;
        }
    }

    // Free URI for the topic
    free(topic_uri);

    // Assign publisher context
    *pub_ctx = sock_ctx;

    LOG_DEBUG_0("Publisher successfully initialized");

    return MSG_SUCCESS;
err:
    if(socket != NULL)
        zmq_close(socket);
    free(topic_uri);
    return MSG_ERR_INIT_FAILED;
}

msgbus_ret_t proto_zmq_publisher_publish(
        void* ctx, void* pub_ctx, msg_envelope_t* msg)
{
    zmq_proto_ctx_t* zmq_ctx = (zmq_proto_ctx_t*) ctx;

    if(!zmq_ctx->is_ipc) {
        if(pthread_mutex_lock(zmq_ctx->cfg.tcp.pub_mutex) != 0) {
            LOG_DEBUG_0("Unable to lock mutex");
        }
    }

    msgbus_ret_t ret = send_message((zmq_sock_ctx_t*) pub_ctx, msg);

    if(!zmq_ctx->is_ipc) {
        if(pthread_mutex_unlock(zmq_ctx->cfg.tcp.pub_mutex) != 0) {
            LOG_DEBUG_0("Unable to unlock mutex");
        }
    }
    return ret;
}

void proto_zmq_publisher_destroy(void* ctx, void* pub_ctx) {
    // Only close the publisher context if it is an IPC socket
    zmq_proto_ctx_t* zmq_ctx = (zmq_proto_ctx_t*) ctx;
    if(zmq_ctx->is_ipc) {
        sock_ctx_destroy((zmq_sock_ctx_t*) pub_ctx, true);
    } else {
        sock_ctx_destroy((zmq_sock_ctx_t*) pub_ctx, false);
    }
}

msgbus_ret_t proto_zmq_subscriber_new(
    void* ctx, const char* topic, void** subscriber)
{
    LOG_DEBUG("ZeroMQ subscribing to %s", topic);

    // Cast context to proper structure
    zmq_proto_ctx_t* zmq_ctx = (zmq_proto_ctx_t*) ctx;
    zmq_recv_ctx_t* zmq_recv_ctx = NULL;
    msgbus_ret_t rc = MSG_ERR_SUB_FAILED;

    char* topic_uri = create_uri(zmq_ctx, topic, false);
    if(topic_uri == NULL) {
        LOG_ERROR("Failed to create URI for topic: %s", topic);
        return MSG_ERR_UNKNOWN;
    }

    LOG_DEBUG("ZeroMQ creating socket for URI: %s", topic_uri);

    void* socket = zmq_socket(zmq_ctx->zmq_context, ZMQ_SUB);
    if(socket == NULL) {
        LOG_ZMQ_ERROR("Failed to initialize ZeroMQ socket");
        goto err;
    }

    // Setting socket_options
    int val = 0;
    int ret = zmq_setsockopt(socket, ZMQ_LINGER, &val, sizeof(val));
    if(ret != 0) {
        LOG_ZMQ_ERROR("Failed setting ZMQ_LINGER");
        goto err;
    }

    // Set the receive high watermark (if it is set for the protocol)
    if(!set_rcv_hwm(socket, zmq_ctx->zmq_recv_hwm)) { goto err; }

    // Set subscription filter
    size_t topic_len = strlen(topic);
    char* tmp = (char*) malloc(sizeof(char) * (topic_len + 1));
    memcpy_s(tmp, topic_len, topic, topic_len);
    tmp[strlen(topic)] = '\0';
    ret = zmq_setsockopt(socket, ZMQ_SUBSCRIBE, tmp, topic_len);
    free(tmp);
    if(ret != 0) {
        LOG_ZMQ_ERROR("Failed to set socket opts");
        goto err;
    }

    // Initialize subscriber receive context
    zmq_recv_ctx = (zmq_recv_ctx_t*) malloc(sizeof(zmq_recv_ctx_t));
    zmq_recv_ctx->type = RECV_SUBSCRIBER;
    zmq_recv_ctx->sock_ctx = NULL;

    // Create socket context
    rc = sock_ctx_new(
            zmq_ctx->zmq_context, topic, socket, &zmq_recv_ctx->sock_ctx);
    if(rc != MSG_SUCCESS) {
        LOG_ERROR_0("Failed to initialize socket context");
        goto err;
    }

    if(!zmq_ctx->is_ipc) {
        // Can assume that this object is correct, since it would already have
        // been retrieved in the create_uri() function call where the object
        // would already have been validated
        config_value_t* cv = zmq_ctx->config->get_config_value(
                zmq_ctx->config->cfg, topic);
        rc = init_curve_client_socket(
                zmq_recv_ctx->sock_ctx, zmq_ctx->config, cv);
        config_value_destroy(cv);
        if(rc != MSG_SUCCESS)
            goto err;
    }

    // Connecting socket
    ret = zmq_connect(socket, topic_uri);
    if(ret != 0) {
        LOG_ZMQ_ERROR("Failed to bind socket");
        rc = MSG_ERR_SUB_FAILED;
        goto err;
    }

    *subscriber = (void*) zmq_recv_ctx;

    LOG_DEBUG_0("ZeroMQ subscription finished");
    free(topic_uri);

    return MSG_SUCCESS;
err:
    if(socket)
        zmq_close(socket);
    if(zmq_recv_ctx) {
        if(zmq_recv_ctx->sock_ctx != NULL) {
            zmq_recv_ctx->sock_ctx->socket = NULL;
            sock_ctx_destroy(zmq_recv_ctx->sock_ctx, false);
        }
    }
    free(topic_uri);
    free(zmq_recv_ctx);
    return rc;
}

void msg_envelope_destroy_wrapper(void* data) {
    msg_envelope_t* env = (msg_envelope_t*) data;
    msgbus_msg_envelope_destroy(env);
}

void proto_zmq_recv_ctx_destroy(void* ctx, void* recv_ctx) {
    zmq_recv_ctx_t* zmq_recv_ctx = (zmq_recv_ctx_t*) recv_ctx;
    sock_ctx_destroy(zmq_recv_ctx->sock_ctx, true);
    free(zmq_recv_ctx);
}

void free_zmq_msg(void* ptr) {
    zmq_msg_t* msg = (zmq_msg_t*) ptr;
    zmq_msg_close(msg);
    free(msg);
}

/**
 * Helper function to check for events occuring for a given client socket
 * (i.e. a subscriber or service client).
 *
 * Returns MSG_SUCCESS if no event occurred or if events occured but are not
 * critical errors.
 *
 * @param monitor - ZeroMQ monitor socket
 * @return MSG_SUCCESS
 */
msgbus_ret_t check_client_events(void* monitor) {
    switch(get_monitor_event(monitor, false)) {
        case ZMQ_EVENT_HANDSHAKE_SUCCEEDED:
            LOG_DEBUG_0("Handshake for the socket succeeded");
            break;
        case ZMQ_EVENT_CONNECT_DELAYED:
            LOG_DEBUG_0("ZeroMQ connection delayed");
            break;
        case ZMQ_EVENT_CONNECTED:
            LOG_DEBUG_0("ZeroMQ socket connected");
            break;
        case ZMQ_EVENT_DISCONNECTED:
            LOG_WARN_0("ZeroMQ socket disconnected");
            break;
        // All possible handshake failure events
        case ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL:
        case ZMQ_EVENT_HANDSHAKE_FAILED_PROTOCOL:
        case ZMQ_EVENT_HANDSHAKE_FAILED_AUTH:
            LOG_ERROR_0("ZeroMQ handshake failed");
            return MSG_ERR_AUTH_FAILED;
        default:
            // No event received...
            break;
    }
    return MSG_SUCCESS;
}

msgbus_ret_t base_recv(
        recv_type_t type, zmq_sock_ctx_t* ctx, int timeout,
        msg_envelope_t** env)
{
    int rc = 0;
    void* socket = ctx->socket;
    zmq_pollitem_t poll_items[1];
    poll_items[0].socket = socket;
    poll_items[0].events = ZMQ_POLLIN;
    if(timeout < 0) {
        msgbus_ret_t event_ret;
        // Poll indefinitley
        while(true) {
            rc = zmq_poll(poll_items, 1, 1000);
            if(rc < 0) {
                if(zmq_errno() == EINTR) {
                    LOG_DEBUG_0("Receive interrupted");
                    return MSG_ERR_EINTR;
                }
                LOG_ZMQ_ERROR("Error while polling indefinitley");
                return MSG_ERR_RECV_FAILED;
            } else if(rc > 0) {
                // Got message!
                break;
            }

            event_ret = check_client_events(ctx->monitor);
            if(event_ret != MSG_SUCCESS)
                return event_ret;
        }
    } else {
        // Get microseconds for the timeout
        rc = zmq_poll(poll_items, 1, timeout);
        LOG_DEBUG("Done polling: %d", rc);
        if(rc == 0) {
            return MSG_RECV_NO_MESSAGE;
        } else if(rc < 0) {
            LOG_ZMQ_ERROR("recv failed");
            return MSG_ERR_RECV_FAILED;
        }

        msgbus_ret_t event_ret = check_client_events(ctx->monitor);
        if(event_ret != MSG_SUCCESS)
            return event_ret;
    }

    LOG_DEBUG_0("Receiving all of the message");

    // Receive message prefix (i.e. topic or service name)
    zmq_msg_t prefix;
    rc = zmq_msg_init(&prefix);
    rc = zmq_msg_recv(&prefix, socket, 0);
    if(rc == -1) {
        if(zmq_errno() == EAGAIN) {
            LOG_DEBUG_0("ZMQ received EAGAIN");
            return MSG_RECV_NO_MESSAGE;
        }
        if(zmq_errno() == EINTR) {
            LOG_DEBUG_0("Receive interrupted");
            return MSG_ERR_EINTR;
        }
        LOG_ZMQ_ERROR("recv failed");
        return MSG_ERR_RECV_FAILED;
    }

    char* name = NULL;
    name = (char*) zmq_msg_data(&prefix);
    LOG_DEBUG("Received message for '%s'", name);
    zmq_msg_close(&prefix);

    // Receive content type
    uint8_t buf[1];
    size_t buf_size = 1;
    rc = zmq_recv(socket, (void*) buf, buf_size, 0);
    if(rc == -1) {
        if(zmq_errno() == EAGAIN) {
            LOG_DEBUG_0("ZMQ received EAGAIN");
            return MSG_RECV_NO_MESSAGE;
        }
        if(zmq_errno() == EINTR) {
            LOG_DEBUG_0("Receive interrupted");
            return MSG_ERR_EINTR;
        }
        LOG_ZMQ_ERROR("recv failed");
        return MSG_ERR_RECV_FAILED;
    }

    // Receive expected number of parts
    uint8_t parts_buf[1];
    rc = zmq_recv(socket, (void*) parts_buf, buf_size, 0);
    if(rc == -1) {
        if(zmq_errno() == EAGAIN) {
            LOG_DEBUG_0("ZMQ received EAGAIN");
            return MSG_RECV_NO_MESSAGE;
        }
        if(zmq_errno() == EINTR) {
            LOG_DEBUG_0("Receive interrupted");
            return MSG_ERR_EINTR;
        }
        LOG_ZMQ_ERROR("recv failed");
        return MSG_ERR_RECV_FAILED;
    }

    int num_parts = (int) parts_buf[0];

    // Receive body of the message
    msg_envelope_serialized_part_t* parts = NULL;
    msgbus_ret_t ret = msgbus_msg_envelope_serialize_parts_new(
            num_parts, &parts);
    if(ret != MSG_SUCCESS) {
        LOG_ERROR_0("Error initializing serialized parts");
        if(parts)
            free(parts);
        return MSG_ERR_RECV_FAILED;
    }

    int part_idx = 0;
    int more;
    size_t more_size = sizeof(more);

    do {
        // TODO: Check part NULL
        zmq_msg_t* part = (zmq_msg_t*) malloc(sizeof(zmq_msg_t));
        rc = zmq_msg_init(part);
        if(rc != 0) {
            LOG_ZMQ_ERROR("Failed to initialize ZeroMQ message");
            msgbus_msg_envelope_serialize_destroy(parts, num_parts);
            return MSG_ERR_RECV_FAILED;
        }

        rc = zmq_msg_recv(part, socket, 0);
        if(rc == -1) {
            LOG_ZMQ_ERROR("Error receiving zmq message body");
            msgbus_msg_envelope_serialize_destroy(parts, num_parts);
            zmq_msg_close(part);
            free(part);
            return MSG_ERR_RECV_FAILED;
        }

        LOG_DEBUG("Received %d bytes", rc);
        parts[part_idx].shared = owned_blob_new(
                (void*) part, free_zmq_msg, (char*) zmq_msg_data(part), rc);
        parts[part_idx].len = rc;
        parts[part_idx].bytes = parts[part_idx].shared->bytes;

        /* Determine if more message parts are to follow */
        rc = zmq_getsockopt(socket, ZMQ_RCVMORE, &more, &more_size);
        if(rc != 0) {
            LOG_ZMQ_ERROR("Error getting ZMQ_RCVMORE sockopt");
            msgbus_msg_envelope_serialize_destroy(parts, num_parts);
            zmq_msg_close(part);
            free(part);
            return MSG_ERR_RECV_FAILED;
        }
        part_idx++;
    } while(more);

    ret = msgbus_msg_envelope_deserialize(
            (content_type_t) buf[0], parts, num_parts, name, env);
    if(ret != MSG_SUCCESS) {
        LOG_ERROR("Failed to deserialize message: %d", ret);
        msgbus_msg_envelope_serialize_destroy(parts, num_parts);
        return ret;
    }
    LOG_DEBUG("env->name = %s \n",(*env)->name);
    msgbus_msg_envelope_serialize_destroy(parts, num_parts);

    return MSG_SUCCESS;
}


msgbus_ret_t proto_zmq_recv_wait(
        void* ctx, void* recv_ctx, msg_envelope_t** message) {
    zmq_recv_ctx_t* zmq_recv_ctx = (zmq_recv_ctx_t*) recv_ctx;
    return base_recv(zmq_recv_ctx->type, zmq_recv_ctx->sock_ctx, -1, message);
}

msgbus_ret_t proto_zmq_recv_timedwait(
        void* ctx, void* recv_ctx, int timeout, msg_envelope_t** message) {
    zmq_recv_ctx_t* zmq_recv_ctx = (zmq_recv_ctx_t*) recv_ctx;
    return base_recv(
            zmq_recv_ctx->type, zmq_recv_ctx->sock_ctx, timeout, message);
}

msgbus_ret_t proto_zmq_recv_nowait(
        void* ctx, void* recv_ctx, msg_envelope_t** message) {
    zmq_recv_ctx_t* zmq_recv_ctx = (zmq_recv_ctx_t*) recv_ctx;
    return base_recv(zmq_recv_ctx->type, zmq_recv_ctx->sock_ctx, 0, message);
}

msgbus_ret_t proto_zmq_service_get(
        void* ctx, const char* service_name, void** service_ctx) {
    LOG_DEBUG("Getting service: %s", service_name);
    zmq_proto_ctx_t* zmq_ctx = (zmq_proto_ctx_t*) ctx;

    char* service_uri = create_uri(zmq_ctx, service_name, false);
    if(service_uri == NULL) {
        LOG_ERROR("Failed to create URI for service: %s", service_name);
        return MSG_ERR_SERVICE_INIT_FAILED;
    }

    msgbus_ret_t ret = MSG_SUCCESS;
    zmq_recv_ctx_t* zmq_recv_ctx = NULL;
    void* socket = NULL;

    // Create ZeroMQ socket
    LOG_DEBUG_0("Creating zeromq socket");
    socket = zmq_socket(zmq_ctx->zmq_context, ZMQ_REQ);
    if(socket == NULL) {
        ret = MSG_ERR_SERVICE_INIT_FAILED;
        LOG_ZMQ_ERROR("Failed to initialize ZeroMQ socket");
        goto err;
    }

    // Set the receive high watermark (if it is set for the protocol)
    if(!set_rcv_hwm(socket, zmq_ctx->zmq_recv_hwm)) { goto err; }

    // Initialize context object
    zmq_recv_ctx = (zmq_recv_ctx_t*) malloc(sizeof(zmq_recv_ctx_t));
    if(zmq_recv_ctx == NULL) {
        LOG_ERROR_0("Ran out of memory allocating ZMQ recv ctx");
        ret = MSG_ERR_NO_MEMORY;
        goto err;
    }

    zmq_recv_ctx->type = RECV_SERVICE_REQ;
    ret = sock_ctx_new(
            zmq_ctx->zmq_context, service_name, socket,
            &zmq_recv_ctx->sock_ctx);
    if(ret != MSG_SUCCESS) {
        LOG_ERROR_0("Failed to malloc socket context name");
        goto err;
    }

    // Initialize socket with Curve authentication if the socket is a TCP
    // socket and the correct values are set in the configuration for the
    // socket
    if(!zmq_ctx->is_ipc) {
        config_value_t* cv = zmq_ctx->config->get_config_value(
                zmq_ctx->config->cfg, service_name);
        msgbus_ret_t rc = init_curve_client_socket(
                zmq_recv_ctx->sock_ctx, zmq_ctx->config, cv);
        config_value_destroy(cv);
        if(rc != MSG_SUCCESS)
            goto err;
    }

    // Connecting socket
    LOG_DEBUG("Connecting socket to %s", service_uri);
    int rc = zmq_connect(socket, service_uri);
    if(rc != 0) {
        ret = MSG_ERR_SERVICE_INIT_FAILED;
        LOG_ZMQ_ERROR("Failed to connect socket");
        goto err;
    }

    (*service_ctx) = zmq_recv_ctx;

    free(service_uri);

    return ret;
err:
    if(zmq_recv_ctx != NULL)
        proto_zmq_recv_ctx_destroy(ctx, zmq_recv_ctx);
    if(socket != NULL)
        zmq_close(socket);
    free(service_uri);
    return ret;
}

msgbus_ret_t proto_zmq_service_new(
        void* ctx, const char* service_name, void** service_ctx) {
    LOG_DEBUG("Create new service: %s", service_name);
    zmq_proto_ctx_t* zmq_ctx = (zmq_proto_ctx_t*) ctx;

    char* service_uri = create_uri(zmq_ctx, service_name, false);
    if(service_uri == NULL) {
        LOG_ERROR("Failed to create URI for service: %s", service_name);
        return MSG_ERR_SERVICE_INIT_FAILED;
    }

    msgbus_ret_t ret = MSG_SUCCESS;
    zmq_recv_ctx_t* zmq_recv_ctx = NULL;
    void* socket = NULL;

    // Create ZeroMQ socket
    LOG_DEBUG_0("Creating zeromq socket");
    socket = zmq_socket(zmq_ctx->zmq_context, ZMQ_REP);
    if(socket == NULL) {
        ret = MSG_ERR_SERVICE_INIT_FAILED;
        LOG_ZMQ_ERROR("Failed to initialize ZeroMQ socket");
        goto err;
    }

    // Set the receive high watermark (if it is set for the protocol)
    if(!set_rcv_hwm(socket, zmq_ctx->zmq_recv_hwm)) { goto err; }

    // Initialize socket with Curve authentication if the socket is a TCP
    // socket and the correct values are set in the configuration for the
    // socket
    if(!zmq_ctx->is_ipc) {
        config_value_t* cv = zmq_ctx->config->get_config_value(
                zmq_ctx->config->cfg, service_name);
        msgbus_ret_t rc = init_curve_server_socket(socket, zmq_ctx->config, cv);
        config_value_destroy(cv);
        if(rc != MSG_SUCCESS)
            goto err;
    }

    // Binding socket
    LOG_DEBUG("Binding socket to %s", service_uri);
    int rc = zmq_bind(socket, service_uri);
    if(rc != 0) {
        LOG_ZMQ_ERROR("Failed to bind socket");
        ret = MSG_ERR_SERVICE_INIT_FAILED;
        goto err;
    }

    // Initialize context object
    zmq_recv_ctx = (zmq_recv_ctx_t*) malloc(sizeof(zmq_recv_ctx_t));
    if(zmq_recv_ctx == NULL) {
        LOG_ERROR_0("Ran out of memory allocating ZMQ recv ctx");
        ret = MSG_ERR_NO_MEMORY;
        goto err;
    }

    zmq_recv_ctx->sock_ctx = NULL;
    zmq_recv_ctx->type = RECV_SERVICE;
    ret = sock_ctx_new(
            zmq_ctx->zmq_context, service_name, socket,
            &zmq_recv_ctx->sock_ctx);
    if(ret != MSG_SUCCESS) {
        LOG_ERROR_0("Failed to malloc socket context name");
        goto err;
    }

    (*service_ctx) = zmq_recv_ctx;

    free(service_uri);

    return ret;
err:
    if(zmq_recv_ctx != NULL) {
        if(zmq_recv_ctx->sock_ctx != NULL) {
            if(zmq_recv_ctx->sock_ctx->name != NULL)
                free(zmq_recv_ctx->sock_ctx->name);
            free(zmq_recv_ctx->sock_ctx);
        }
        free(zmq_recv_ctx);
    }
    if(socket != NULL)
        zmq_close(socket);
    free(service_uri);
    return ret;
}

msgbus_ret_t proto_zmq_request(
        void* ctx, void* service_ctx, msg_envelope_t* msg) {
    zmq_recv_ctx_t* req_ctx = (zmq_recv_ctx_t*) service_ctx;
    if(req_ctx->type != RECV_SERVICE_REQ) {
        LOG_ERROR_0("Incorrect service context, must be for requests");
        return MSG_ERR_REQ_FAILED;
    }

    return send_message(req_ctx->sock_ctx, msg);
}

msgbus_ret_t proto_zmq_response(
        void* ctx, void* service_ctx, msg_envelope_t* msg) {
    zmq_recv_ctx_t* resp_ctx = (zmq_recv_ctx_t*) service_ctx;
    if(resp_ctx->type != RECV_SERVICE) {
        LOG_ERROR_0("Incorrect service context, must be for receiving reqs");
        return MSG_ERR_REQ_FAILED;
    }

    return send_message(resp_ctx->sock_ctx, msg);
}

typedef struct {
    int num_parts;
    msg_envelope_serialized_part_t* parts;
} serialized_part_wrapper_t;

void free_part(void* data, void* hint) {
    serialized_part_wrapper_t* wrap = (serialized_part_wrapper_t*) hint;
    msgbus_msg_envelope_serialize_destroy(wrap->parts, wrap->num_parts);
    free(wrap);
}

msgbus_ret_t send_message(zmq_sock_ctx_t* ctx, msg_envelope_t* msg) {
    msg_envelope_serialized_part_t* parts = NULL;
    zmq_msg_t* msgs = NULL;

    int num_parts = msgbus_msg_envelope_serialize(msg, &parts);
    if(num_parts < 0) {
        LOG_ERROR_0("Failed to serialize message envelope");
        return MSG_ERR_MSG_SEND_FAILED;
    }

    // Send message prefix, i.e. the topic or service name
    zmq_msg_t prefix_msg;
    int rc = zmq_msg_init_data(
            &prefix_msg, (void*) ctx->name, ctx->name_len, NULL, NULL);
    if(rc != 0) {
        LOG_ZMQ_ERROR("Failed to intialize prefix message part");
        goto err;
    }

    // Separating into two for loops to be able to correctly clean up the
    // memory if constructing a zmq_msg_t fails
    msgs = (zmq_msg_t*) malloc(sizeof(zmq_msg_t) * num_parts);

    // Initialize zeromq multi-part messages
    for(int i = 0; i < num_parts; i++) {
        if((i + 1) == num_parts) {
            serialized_part_wrapper_t* wrap = (serialized_part_wrapper_t*)
                malloc(sizeof(serialized_part_wrapper_t));
            wrap->num_parts = num_parts;
            wrap->parts = parts;

            // Setting last message to free the serialized message parts
            rc = zmq_msg_init_data(
                &msgs[i], (void*) parts[i].bytes, parts[i].len, free_part,
                (void*) wrap);
        } else {
            rc = zmq_msg_init_data(
                &msgs[i], (void*) parts[i].bytes, parts[i].len, NULL, NULL);
        }

        if(rc != 0) {
            LOG_ZMQ_ERROR(
                    "Failed to create ZeroMQ message for message envelope");
            msgbus_msg_envelope_serialize_destroy(parts, num_parts);
            free(msgs);
            return MSG_ERR_MSG_SEND_FAILED;
        }
    }

    // Send message prefix
    int nbytes = zmq_msg_send(&prefix_msg, ctx->socket, ZMQ_SNDMORE);
    zmq_msg_close(&prefix_msg);
    if(nbytes <= 0 && zmq_errno() != EAGAIN) {
        LOG_ZMQ_ERROR("Failed to send message envelope for part");
        goto err;
    }

    // Send message part for the content type of the message
    uint8_t val[1];
    val[0] = (uint8_t) msg->content_type;

    nbytes = zmq_send(ctx->socket, &val, sizeof(val), ZMQ_SNDMORE);
    if(nbytes <= 0 && zmq_errno() != EAGAIN) {
        LOG_ZMQ_ERROR("Failed to send message envelope for content type");
        goto err;
    }

    // Send expected number of parts
    val[0] = (uint8_t) num_parts;

    nbytes = zmq_send(ctx->socket, &val, sizeof(val), ZMQ_SNDMORE);
    if(nbytes <= 0 && zmq_errno() != EAGAIN) {
        LOG_ZMQ_ERROR("Failed to send message envelope for num parts");
        goto err;
    }

    // Send message parts
    int flags = ZMQ_SNDMORE;
    for(int i = 0; i < num_parts; i++) {
        // Check if last part
        if((i + 1) == num_parts)
            flags = 0;

        // Send main body of the message
        nbytes = zmq_msg_send(&msgs[i], ctx->socket, flags);
        if(nbytes <= 0 && zmq_errno() != EAGAIN) {
            LOG_ZMQ_ERROR("Failed to send message envelope for part");
            goto err;
        }
    }

    // Clean up messages
    for(int i = 0; i < num_parts; i++) {
        zmq_msg_close(&msgs[i]);
    }
    free(msgs);

    return MSG_SUCCESS;
err:
    // If the msgs variable has been initialized, then the serialized parts
    // will be freed by the zmq_msg_close() call, otherwise, the serialized
    // parts need to be free'ed manually
    if(msgs != NULL) {
        for(int i = 0; i < num_parts; i++) {
            zmq_msg_close(&msgs[i]);
        }
        free(msgs);
    } else if(parts != NULL) {
        msgbus_msg_envelope_serialize_destroy(parts, num_parts);
    }

    // Check if ZeroMQ received a system interrupt, if it did return the
    // correct response
    if(zmq_errno() == EINTR)
        return MSG_ERR_EINTR;
    else
        return MSG_ERR_MSG_SEND_FAILED;
}
