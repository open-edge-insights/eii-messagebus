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
#include <string.h>
#include <time.h>
#include <pthread.h>

#include <zmq.h>
#include <safe_lib.h>
#include <eis/msgbus/hashmap.h>

#include "zmq.h"
#include "zap.h"
#include "common.h"
#include "socket_context.h"

#define SOCKET_DIR     "socket_dir"
#define SOCKET_FILE    "socket_file"
#define PORT           "port"
#define HOST           "host"
#define IPC_PREFIX     "ipc://"
#define IPC_PREFIX_LEN 6
#define TCP_PREFIX     "tcp://"
#define TCP_PREFIX_LEN 6
#define ZEROMQ_HWM     "zmq_recv_hwm"
#define ZEROMQ_RECONNECT_RETRIES "zmq_connect_retries"
#define ZEROMQ_RECONNECT_RETRIES_DF 50

/**
 * Internal ZeroMQ protocol context
 */
typedef struct {
    void* zmq_context;
    bool is_ipc;
    config_t* config;
    int zmq_recv_hwm;
    int zmq_connect_retries;

    // Known config values alread extracted from the configuration
    union {
        struct {
            config_value_t* socket_dir;
            hashmap_t* pub_sockets;
        } ipc;
        struct {
            config_value_t* pub_host;
            int64_t pub_port;
            zmq_shared_sock_t* pub_socket;
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

// Prototypes
void proto_zmq_destroy(void* ctx);
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

// Helper function prototypes
static char* create_uri(
        zmq_proto_ctx_t* ctx, const char* name, bool is_publisher);
static bool set_rcv_hwm(void* socket, int zmq_rcvhwm);
static const char* get_event_str(int event);
static int get_monitor_event(void* monitor, bool block);
static msgbus_ret_t send_message(zmq_sock_ctx_t* ctx, msg_envelope_t* msg);
static int send_zmq_msg(void* socket, zmq_msg_t* msg, int flags);
static int send_zmq(void* socket, void* buf, size_t buf_size, int flags);
static int recv_zmq(void* socket, void* buf, size_t buf_size);
static int recv_zmq_msg(void* socket, zmq_msg_t* msg);
static msgbus_ret_t base_recv(
        recv_type_t type, zmq_proto_ctx_t* zmq_ctx, zmq_sock_ctx_t* ctx,
        int timeout, msg_envelope_t** env);
static msgbus_ret_t init_curve_server_socket(
        void* socket, config_t* conf, config_value_t* conf_obj);
static msgbus_ret_t init_curve_client_socket(
        void* socket, config_t* conf, config_value_t* conf_obj);
static void free_sock_ctx(void* vargs);
static void* new_socket(
        zmq_proto_ctx_t* zmq_ctx, const char* uri, const char* name,
        int socket_type);

protocol_t* proto_zmq_initialize(const char* type, config_t* config) {
    // TODO: Clean up method to make sure all memeory is fully freed always
    LOG_DEBUG_0("Initilizing zeromq message bus");

    // Initialize protocol context structure
    zmq_proto_ctx_t* zmq_proto_ctx = (zmq_proto_ctx_t*) malloc(
            sizeof(zmq_proto_ctx_t));
    if(zmq_proto_ctx == NULL) {
        LOG_ERROR_0("Out of memory initializing protocol");
        return NULL;
    }

    // Initialize all proto context values
    zmq_proto_ctx->zmq_context = zmq_ctx_new();
    zmq_proto_ctx->config = config;
    zmq_proto_ctx->zmq_recv_hwm = -1;
    zmq_proto_ctx->zmq_connect_retries = ZEROMQ_RECONNECT_RETRIES_DF;
    zmq_proto_ctx->is_ipc = false;

    // Initialize IPC configuration values
    zmq_proto_ctx->cfg.ipc.socket_dir = NULL;
    zmq_proto_ctx->cfg.ipc.pub_sockets = NULL;

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

    // Getting ZeroMQ socket retries before recreating the socket
    config_value_t* retries = config_get(config, ZEROMQ_RECONNECT_RETRIES);
    if(retries != NULL) {
        if(retries->type != CVT_INTEGER) {
            LOG_ERROR_0("ZeroMQ receive HWM must be an integer");
            config_value_destroy(retries);
            goto err;
        }

        if(retries->body.integer < 0) {
            LOG_ERROR_0("ZeroMQ receive HWM must be greater than 0");
            config_value_destroy(retries);
            goto err;
        }

        zmq_proto_ctx->zmq_connect_retries = (int) retries->body.integer;
        LOG_DEBUG("ZeroMQ socket connect retries: %d",
                zmq_proto_ctx->zmq_connect_retries);
        config_value_destroy(retries);
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

        // Initial number of unique publisher sockets is 16
        zmq_proto_ctx->cfg.ipc.pub_sockets = hashmap_new(16);
        if(zmq_proto_ctx->cfg.ipc.pub_sockets == NULL) {
            LOG_ERROR_0("Failed to initialize hashmap of publisher sockets");
            goto err;
        }
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
            if(zmq_proto_ctx->cfg.tcp.pub_mutex == NULL) {
                LOG_ERROR_0("Failed to malloc publish mutex");
                goto err;
            }

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
    if(proto_ctx == NULL) {
        LOG_ERROR_0("Out of memory initializing protocol_t");
        goto err;
    }
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
            LOG_DEBUG_0("Destroying publisher shared socket");
            if(zmq_ctx->cfg.tcp.pub_socket != NULL) {
                shared_sock_destroy(zmq_ctx->cfg.tcp.pub_socket);
                zmq_ctx->cfg.tcp.pub_socket = NULL;
            }

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
        hashmap_destroy(zmq_ctx->cfg.ipc.pub_sockets);
    }

    LOG_DEBUG_0("Destroying zeromq context");
    zmq_ctx_term(zmq_ctx->zmq_context);

    // Last free for the zmq protocol structure
    free(zmq_ctx);

    LOG_DEBUG_0("Zeromq message bus context destroyed");
}

msgbus_ret_t proto_zmq_publisher_new(
        void* ctx, const char* topic, void** pub_ctx)
{
    // Cast ptr to internal context type
    zmq_proto_ctx_t* zmq_ctx = (zmq_proto_ctx_t*) ctx;
    zmq_sock_ctx_t* sock_ctx = NULL;
    void* socket = NULL;
    zmq_shared_sock_t* shared_socket = NULL;

    LOG_DEBUG("Creating ZeroMQ publisher for topic '%s'", topic);

    // Create the full topic
    char* topic_uri = create_uri(zmq_ctx, topic, true);
    if(topic_uri == NULL) {
        LOG_ERROR("Failed to create URI for topic: %s", topic);
        return MSG_ERR_INIT_FAILED;
    }

    LOG_DEBUG("ZeroMQ publisher URI: %s", topic_uri);

    if(zmq_ctx->is_ipc || zmq_ctx->cfg.tcp.pub_socket == NULL) {
        // Check if the application has already bound an IPC for the given
        // publisher
        if(zmq_ctx->is_ipc) {
            shared_socket = (zmq_shared_sock_t*) hashmap_get(
                    zmq_ctx->cfg.ipc.pub_sockets, topic_uri);
            if(shared_socket != NULL) {
               msgbus_ret_t ret = sock_ctx_new(
                       zmq_ctx->zmq_context, topic, shared_socket, &sock_ctx);
               if(ret != MSG_SUCCESS) {
                   LOG_ERROR_0("Failed to create a new socket context");
                   return MSG_ERR_UNKNOWN;
               }

               *pub_ctx = sock_ctx;
               return MSG_SUCCESS;
            }
        }

        socket = new_socket(zmq_ctx, topic_uri, topic, ZMQ_PUB);
        if(socket == NULL) { goto err; }

        LOG_DEBUG_0("ZeroMQ publisher created");

        // Necessary sleep for publisher to be initialized in ZeroMQ
        struct timespec sleep_time;
        sleep_time.tv_sec = 0;
        sleep_time.tv_nsec = 250000000L;
        nanosleep(&sleep_time, NULL);

        // Create shared socket for the newly created ZeroMQ socket
        shared_socket = shared_sock_new(
                zmq_ctx->zmq_context, topic_uri, socket, ZMQ_PUB);
        if(shared_socket == NULL) {
            LOG_ERROR_0("Failed to create shared socket");
            goto err;
        }

        msgbus_ret_t rc = sock_ctx_new(
                zmq_ctx->zmq_context, topic, shared_socket, &sock_ctx);
        if(rc != MSG_SUCCESS) {
            LOG_ERROR_0("Failed to initailize socket context");
            goto err;
        }

        if(!zmq_ctx->is_ipc) {
            // Assign internal shared socket for the zmq msgbus context's
            // TCP publisher socket
            zmq_ctx->cfg.tcp.pub_socket = shared_socket;
        } else {
            // Add the newly bound socket to the hashmap of bound sockets
            hashmap_ret_t ret = hashmap_put(
                    zmq_ctx->cfg.ipc.pub_sockets, topic_uri,
                    shared_socket, free_sock_ctx);
            if(ret != MAP_SUCCESS) {
                LOG_ERROR("Failed to put IPC socket in hashmap: %d", ret);
                goto err;
            }
        }
    } else {
        // Create new socket context for the shared TCP publisher socket
        msgbus_ret_t ret = sock_ctx_new(
                zmq_ctx->zmq_context, topic, zmq_ctx->cfg.tcp.pub_socket,
                &sock_ctx);
        if(ret != MSG_SUCCESS) {
            LOG_ERROR_0("Failed to create new socket context for pub socket");
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
    if(sock_ctx != NULL) {
        sock_ctx_destroy(sock_ctx);
    } else if(shared_socket != NULL) {
        shared_sock_destroy(shared_socket);
    } else if(socket != NULL) {
        zmq_close(socket);
    }
    free(topic_uri);
    return MSG_ERR_INIT_FAILED;
}

msgbus_ret_t proto_zmq_publisher_publish(
        void* ctx, void* pub_ctx, msg_envelope_t* msg)
{
    zmq_sock_ctx_t* sock_ctx = (zmq_sock_ctx_t*) pub_ctx;
    if(sock_ctx_lock(sock_ctx) != 0) {
        LOG_ERROR_0("Failed to obtain socket context lock");
        return MSG_ERR_UNKNOWN;
    }

    msgbus_ret_t ret = send_message(sock_ctx, msg);

    if(sock_ctx_unlock(sock_ctx) != 0) {
        LOG_ERROR_0("Failed to unlock socket context lock");
        return MSG_ERR_UNKNOWN;
    }

    return ret;
}

void proto_zmq_publisher_destroy(void* ctx, void* pub_ctx) {
    zmq_proto_ctx_t* zmq_ctx = (zmq_proto_ctx_t*) ctx;
    zmq_sock_ctx_t* sock_ctx = (zmq_sock_ctx_t*) pub_ctx;
    zmq_shared_sock_t* shared_socket = sock_ctx->shared_socket;

    // Destroy the socket context (note: this may only decrease the refcount)
    sock_ctx_destroy(sock_ctx);

    // If this is an IPC socket, check if the number of references to the
    // socket is 1, because if it is one then the only existing reference is
    // in the hashmap of bound IPC sockets. In this case, the socket should
    // be fully closed since there are no other users of the socket
    if(zmq_ctx->is_ipc && shared_socket->refcount == 1) {
        hashmap_ret_t ret = hashmap_remove(
                zmq_ctx->cfg.ipc.pub_sockets, shared_socket->uri);
        if(ret != MAP_SUCCESS) {
            LOG_ERROR("Failed to remove IPC publisher socket from hashmap: %d",
                      ret);
        }
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
    zmq_shared_sock_t* shared_socket = NULL;

    char* topic_uri = create_uri(zmq_ctx, topic, false);
    if(topic_uri == NULL) {
        LOG_ERROR("Failed to create URI for topic: %s", topic);
        return MSG_ERR_UNKNOWN;
    }

    LOG_DEBUG("ZeroMQ creating socket for URI: %s", topic_uri);

    void* socket = new_socket(zmq_ctx, topic_uri, topic, ZMQ_SUB);
    if(socket == NULL) { goto err; }

    // Initialize shared socket
    shared_socket = shared_sock_new(
            zmq_ctx->zmq_context, topic_uri, socket, ZMQ_SUB);
    if(shared_socket == NULL) { goto err; }

    // Initialize subscriber receive context
    zmq_recv_ctx = (zmq_recv_ctx_t*) malloc(sizeof(zmq_recv_ctx_t));
    if(zmq_recv_ctx == NULL) {
        LOG_ERROR_0("Out of memory initializing receive context");
        rc = MSG_ERR_NO_MEMORY;
        goto err;
    }
    zmq_recv_ctx->type = RECV_SUBSCRIBER;
    zmq_recv_ctx->sock_ctx = NULL;

    // Create socket context
    rc = sock_ctx_new(
            zmq_ctx->zmq_context, topic, shared_socket,
            &zmq_recv_ctx->sock_ctx);
    if(rc != MSG_SUCCESS) {
        LOG_ERROR_0("Failed to initialize socket context");
        goto err;
    }

    // Decrease the number of references to the shared socket, since the
    // socket context that was just created should be the only reference
    // going forward for the socket (i.e. the reference for this function after
    // creating the shared socket is no longer needed)
    shared_sock_decref(shared_socket);

    *subscriber = (void*) zmq_recv_ctx;

    LOG_DEBUG_0("ZeroMQ subscription finished");
    free(topic_uri);

    return MSG_SUCCESS;
err:
    if(zmq_recv_ctx != NULL) {
        proto_zmq_recv_ctx_destroy(ctx, zmq_recv_ctx);
    } else if(shared_socket != NULL) {
        shared_sock_destroy(shared_socket);
    } else if(socket != NULL) {
        zmq_close(socket);
    }

    free(topic_uri);
    return rc;
}

void msg_envelope_destroy_wrapper(void* data) {
    msg_envelope_t* env = (msg_envelope_t*) data;
    msgbus_msg_envelope_destroy(env);
}

void proto_zmq_recv_ctx_destroy(void* ctx, void* recv_ctx) {
    zmq_recv_ctx_t* zmq_recv_ctx = (zmq_recv_ctx_t*) recv_ctx;
    if(zmq_recv_ctx->sock_ctx != NULL) {
        sock_ctx_destroy(zmq_recv_ctx->sock_ctx);
    }
    free(zmq_recv_ctx);
}

msgbus_ret_t proto_zmq_recv_wait(
        void* ctx, void* recv_ctx, msg_envelope_t** message) {
    zmq_proto_ctx_t* zmq_ctx = (zmq_proto_ctx_t*) ctx;
    zmq_recv_ctx_t* zmq_recv_ctx = (zmq_recv_ctx_t*) recv_ctx;
    return base_recv(
            zmq_recv_ctx->type, zmq_ctx, zmq_recv_ctx->sock_ctx, -1, message);
}

msgbus_ret_t proto_zmq_recv_timedwait(
        void* ctx, void* recv_ctx, int timeout, msg_envelope_t** message) {
    zmq_proto_ctx_t* zmq_ctx = (zmq_proto_ctx_t*) ctx;
    zmq_recv_ctx_t* zmq_recv_ctx = (zmq_recv_ctx_t*) recv_ctx;
    return base_recv(
            zmq_recv_ctx->type, zmq_ctx, zmq_recv_ctx->sock_ctx, timeout,
            message);
}

msgbus_ret_t proto_zmq_recv_nowait(
        void* ctx, void* recv_ctx, msg_envelope_t** message) {
    zmq_proto_ctx_t* zmq_ctx = (zmq_proto_ctx_t*) ctx;
    zmq_recv_ctx_t* zmq_recv_ctx = (zmq_recv_ctx_t*) recv_ctx;
    return base_recv(
            zmq_recv_ctx->type, zmq_ctx, zmq_recv_ctx->sock_ctx, 0, message);
}

msgbus_ret_t proto_zmq_service_get(
        void* ctx, const char* service_name, void** service_ctx) {
    LOG_DEBUG("Getting service: %s", service_name);
    zmq_proto_ctx_t* zmq_ctx = (zmq_proto_ctx_t*) ctx;
    zmq_shared_sock_t* shared_socket = NULL;

    char* service_uri = create_uri(zmq_ctx, service_name, false);
    if(service_uri == NULL) {
        LOG_ERROR("Failed to create URI for service: %s", service_name);
        return MSG_ERR_SERVICE_INIT_FAILED;
    }

    msgbus_ret_t ret = MSG_SUCCESS;
    zmq_recv_ctx_t* zmq_recv_ctx = NULL;

    // Create ZeroMQ socket
    void* socket = new_socket(zmq_ctx, service_uri, service_name, ZMQ_REQ);
    if(socket == NULL) { goto err; }

    // Create shared socket
    shared_socket = shared_sock_new(
            zmq_ctx->zmq_context, service_uri, socket, ZMQ_REQ);
    if(shared_socket == NULL) {
        LOG_ERROR_0("Failed to initialize new shared socket");
        goto err;
    }

    // Initialize context object
    zmq_recv_ctx = (zmq_recv_ctx_t*) malloc(sizeof(zmq_recv_ctx_t));
    if(zmq_recv_ctx == NULL) {
        LOG_ERROR_0("Ran out of memory allocating ZMQ recv ctx");
        ret = MSG_ERR_NO_MEMORY;
        goto err;
    }

    // Assign initial values
    zmq_recv_ctx->type = RECV_SERVICE_REQ;
    zmq_recv_ctx->sock_ctx = NULL;

    ret = sock_ctx_new(
            zmq_ctx->zmq_context, service_name, shared_socket,
            &zmq_recv_ctx->sock_ctx);
    if(ret != MSG_SUCCESS) {
        LOG_ERROR_0("Failed to malloc socket context name");
        goto err;
    }

    // Decrease the number of references to the shared socket, since the
    // socket context that was just created should be the only reference
    // going forward for the socket (i.e. the reference for this function after
    // creating the shared socket is no longer needed)
    shared_sock_decref(shared_socket);

    (*service_ctx) = zmq_recv_ctx;

    free(service_uri);

    return ret;
err:
    if(zmq_recv_ctx != NULL) {
        if(zmq_recv_ctx->sock_ctx == NULL) {
            shared_sock_destroy(shared_socket);
        }
        proto_zmq_recv_ctx_destroy(ctx, zmq_recv_ctx);
    } else if(shared_socket != NULL) {
        shared_sock_destroy(shared_socket);
    } else if(socket != NULL) {
        zmq_close(socket);
    }
    free(service_uri);
    return ret;
}

msgbus_ret_t proto_zmq_service_new(
        void* ctx, const char* service_name, void** service_ctx) {
    LOG_DEBUG("Create new service: %s", service_name);
    zmq_proto_ctx_t* zmq_ctx = (zmq_proto_ctx_t*) ctx;
    zmq_shared_sock_t* shared_socket = NULL;

    char* service_uri = create_uri(zmq_ctx, service_name, false);
    if(service_uri == NULL) {
        LOG_ERROR("Failed to create URI for service: %s", service_name);
        return MSG_ERR_SERVICE_INIT_FAILED;
    }

    msgbus_ret_t ret = MSG_SUCCESS;
    zmq_recv_ctx_t* zmq_recv_ctx = NULL;

    // Create ZeroMQ socket
    void* socket = new_socket(zmq_ctx, service_uri, service_name, ZMQ_REP);
    if(socket == NULL) { goto err; }

    // Create shared socket
    shared_socket = shared_sock_new(
            zmq_ctx->zmq_context, service_uri, socket, ZMQ_REP);
    if(shared_socket == NULL) {
        LOG_ERROR_0("Out of memory initializing shared socket");
        goto err;
    }

    // Initialize context object
    zmq_recv_ctx = (zmq_recv_ctx_t*) malloc(sizeof(zmq_recv_ctx_t));
    if(zmq_recv_ctx == NULL) {
        LOG_ERROR_0("Ran out of memory allocating ZMQ recv ctx");
        ret = MSG_ERR_NO_MEMORY;
        goto err;
    }

    // Assign initial values
    zmq_recv_ctx->sock_ctx = NULL;
    zmq_recv_ctx->type = RECV_SERVICE;

    ret = sock_ctx_new(
            zmq_ctx->zmq_context, service_name, shared_socket,
            &zmq_recv_ctx->sock_ctx);
    if(ret != MSG_SUCCESS) {
        LOG_ERROR_0("Failed to malloc socket context name");
        goto err;
    }

    // Decrease the number of references to the shared socket, since the
    // socket context that was just created should be the only reference
    // going forward for the socket (i.e. the reference for this function after
    // creating the shared socket is no longer needed)
    shared_sock_decref(shared_socket);

    (*service_ctx) = zmq_recv_ctx;

    free(service_uri);

    return ret;
err:
    if(zmq_recv_ctx != NULL) {
        if(zmq_recv_ctx->sock_ctx == NULL) {
            shared_sock_destroy(shared_socket);
        }
        proto_zmq_recv_ctx_destroy(zmq_ctx, zmq_recv_ctx);
    } else if(shared_socket != NULL) {
        shared_sock_destroy(shared_socket);
    } else if(socket != NULL) {
        zmq_close(socket);
    }
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

static void free_part(void* data, void* hint) {
    serialized_part_wrapper_t* wrap = (serialized_part_wrapper_t*) hint;
    msgbus_msg_envelope_serialize_destroy(wrap->parts, wrap->num_parts);
    free(wrap);
}

static void free_zmq_msg(void* ptr) {
    zmq_msg_t* msg = (zmq_msg_t*) ptr;
    zmq_msg_close(msg);
    free(msg);
}

/**
 * Helper method to send a message over ZeroMQ. This method will continue
 * attempting to send data if EINTR or EAGAIN occur.
 *
 * @param socket - ZeroMQ socket
 * @param msg    - ZeroMQ message to send
 * @param flags  - ZeroMQ send flags
 * @return @c zmq_msg_send() return value
 */
static int send_zmq_msg(void* socket, zmq_msg_t* msg, int flags) {
    int nbytes = 0;

    while(true) {
        nbytes = zmq_msg_send(msg, socket, flags);
        if(nbytes <= 0) {
            // Either an error or an interrupt occurred
            if(zmq_errno() == EAGAIN || zmq_errno() == EINTR) {
                LOG_DEBUG_0("ZeroMQ send interrupted");
                continue;
            }
            break;
        } else {
            // The bytes were sent correctly
            break;
        }
    }

    return nbytes;
}

/**
 * Helper method to send a message over ZeroMQ. This method will continue
 * attempting to send data if EINTR or EAGAIN occur.
 *
 * @param socket   - ZeroMQ socket
 * @param buf      - Buffer to send
 * @parma buf_size - Size of the buffer to send
 * @param flags    - ZeroMQ send flags
 * @return @c zmq_send() return value
 */
static int send_zmq(void* socket, void* buf, size_t buf_size, int flags) {
    int nbytes = 0;

    while(true) {
        nbytes = zmq_send(socket, buf, buf_size, flags);
        if(nbytes <= 0) {
            // Either an error or an interrupt occurred
            if(zmq_errno() == EAGAIN || zmq_errno() == EINTR) {
                LOG_DEBUG_0("ZeroMQ send interrupted");
                continue;
            }
            break;
        } else {
            // The bytes were sent correctly
            break;
        }
    }

    return nbytes;
}

/**
 * Method for sending the given message envelope over the provided ZeroMQ
 * socket context.
 *
 * \note @c zmq_sock_ctx_t is an internal structure and not in the libzmq lib
 *
 * @param ctx - ZeroMQ socket context
 * @param msg - Message envelope to transmit
 * @return @c msgbus_ret_t
 */
static msgbus_ret_t send_message(zmq_sock_ctx_t* ctx, msg_envelope_t* msg) {
    msg_envelope_serialized_part_t* parts = NULL;
    zmq_msg_t* msgs = NULL;
    void* socket = ctx->shared_socket->socket;

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
    if(msg == NULL) {
        LOG_ERROR_0("Out of memory");
        goto err;
    }

    // Initialize zeromq multi-part messages
    for(int i = 0; i < num_parts; i++) {
        if((i + 1) == num_parts) {
            serialized_part_wrapper_t* wrap = (serialized_part_wrapper_t*)
                malloc(sizeof(serialized_part_wrapper_t));
            if(wrap == NULL) {
                LOG_ERROR_0("Out of memory");
                goto err;
            }
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
    int nbytes = send_zmq_msg(socket, &prefix_msg, ZMQ_SNDMORE);
    if(nbytes <= 0) {
        LOG_ZMQ_ERROR("Failed to send message envelope for part");
        goto err;
    }

    // Send message part for the content type of the message
    uint8_t val[1];
    val[0] = (uint8_t) msg->content_type;

    nbytes = send_zmq(socket, &val, sizeof(val), ZMQ_SNDMORE);
    if(nbytes <= 0) {
        LOG_ZMQ_ERROR("Failed to send message envelope for content type");
        goto err;
    }

    // Send expected number of parts
    val[0] = (uint8_t) num_parts;

    nbytes = send_zmq(socket, &val, sizeof(val), ZMQ_SNDMORE);
    if(nbytes <= 0) {
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
        nbytes = send_zmq_msg(socket, &msgs[i], flags);
        if(nbytes <= 0) {
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

/**
 * Helper method for receiving a @c zmq_msg_t from ZeroMQ. This method will
 * keep attempting to receive a message if EINTR or EAGAIN occur.
 *
 * @param[in]  socket - ZeroMQ socket
 * @param[out] msg    - Received message
 * @return ZMQ receive value
 */
static int recv_zmq_msg(void* socket, zmq_msg_t* msg) {
    int rc = zmq_msg_init(msg);
    if(rc != 0) {
        LOG_ZMQ_ERROR("Failed to initialize message");
        return rc;
    }

    while(true) {
        rc = zmq_msg_recv(msg, socket, 0);
        if(rc == -1) {
            if(zmq_errno() == EAGAIN) {
                LOG_DEBUG_0("ZMQ received EAGAIN");
                continue;
            }
            if(zmq_errno() == EINTR) {
                LOG_DEBUG_0("Receive interrupted");
                continue;
            }

            LOG_ZMQ_ERROR("Failed to receive message");
            return rc;
        } else {
            break;
        }
    }

    return rc;
}

/**
 * Helper method for receiving a bytes from ZeroMQ. This method will
 * keep attempting to receive a message if EINTR or EAGAIN occur.
 *
 * @param[in]  socket   - ZeroMQ socket
 * @param[out] buf      - Output buffer
 * @param[in]  buf_size - Buffer size
 * @return ZMQ receive value
 */
static int recv_zmq(void* socket, void* buf, size_t buf_size) {
    int rc = 0;

    while(true) {
        rc = zmq_recv(socket, (void*) buf, buf_size, 0);
        if(rc == -1) {
            if(zmq_errno() == EAGAIN) {
                LOG_DEBUG_0("ZMQ received EAGAIN");
                continue;
            }
            if(zmq_errno() == EINTR) {
                LOG_DEBUG_0("Receive interrupted");
                continue;
            }

            LOG_ZMQ_ERROR("Failed to receive message");
            return rc;
        } else {
            break;
        }
    }

    return rc;
}

static msgbus_ret_t base_recv(
        recv_type_t type, zmq_proto_ctx_t* zmq_ctx, zmq_sock_ctx_t* ctx,
        int timeout, msg_envelope_t** env)
{
    int rc = 0;
    void* socket = ctx->shared_socket->socket;
    bool indef_poll = timeout < 0;
    timeout = (indef_poll) ? 1000 : timeout;

    zmq_pollitem_t poll_items[1];
    poll_items[0].socket = socket;
    poll_items[0].events = ZMQ_POLLIN;

    do {
        rc = zmq_poll(poll_items, 1, timeout);
        if(rc < 0) {
            if(zmq_errno() == EINTR) {
                LOG_DEBUG_0("Receive interrupted");
                return MSG_ERR_EINTR;
            }
            LOG_ZMQ_ERROR("Error while polling indefinitley");
            return MSG_ERR_RECV_FAILED;
        } else if(rc > 0) {
            // Got message!
            if(ctx->shared_socket->retries != 0) {
                // Reset the number of retries if there are any (the if
                // statement exists because locking a mutex in the function
                // call is expensive)
                sock_ctx_retries_reset(ctx);
            }
            break;
        }

        switch(get_monitor_event(ctx->shared_socket->monitor, false)) {
            // Events to increment retries count for recreating the socket
            case ZMQ_EVENT_DISCONNECTED:
            case ZMQ_EVENT_CONNECT_RETRIED:
            case ZMQ_EVENT_CONNECT_DELAYED:
                sock_ctx_retries_incr(ctx);
                break;

            // All possible handshake failure events
            case ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL:
            case ZMQ_EVENT_HANDSHAKE_FAILED_PROTOCOL:
            case ZMQ_EVENT_HANDSHAKE_FAILED_AUTH:
                LOG_ERROR_0("ZeroMQ handshake failed");
                return MSG_ERR_AUTH_FAILED;

            // Events to ignore (NOTE: the event type is already logged)
            case ZMQ_EVENT_HANDSHAKE_SUCCEEDED:
            case ZMQ_EVENT_CONNECTED:
            case ZMQ_EVENT_MONITOR_STOPPED:
            case ZMQ_EVENT_CLOSE_FAILED:
            case ZMQ_EVENT_ACCEPTED:
            case ZMQ_EVENT_BIND_FAILED:
            case ZMQ_EVENT_LISTENING:
            case ZMQ_EVENT_CLOSED:
            default:
                // No event received...
                break;
        }

        if(ctx->shared_socket->retries == zmq_ctx->zmq_connect_retries) {
            LOG_WARN_0("Reached max retries on the socket connect, "
                       "initializing new ZeroMQ socket");
            if(sock_ctx_lock(ctx) != 0)  {
                LOG_ERROR_0("Failed to obtain socket context lock");
                return MSG_ERR_UNKNOWN;
            }
            close_zero_linger(socket);

            // Give the socket time to fully close... If not enough time is
            // given the socket could fail during creation
            struct timespec sleep_time;
            sleep_time.tv_sec = 0;
            sleep_time.tv_nsec = 5000000L;
            nanosleep(&sleep_time, NULL);

            ctx->shared_socket->socket = NULL;
            socket = NULL;
            socket = new_socket(
                      zmq_ctx, ctx->shared_socket->uri, ctx->name,
                        ctx->shared_socket->socket_type);
            if(socket == NULL) {
                if(sock_ctx_unlock(ctx) != 0) {
                    LOG_ERROR_0("Failed to unlock socket contxt lock");
                }
                return MSG_ERR_UNKNOWN;
            }
            sock_ctx_replace(ctx, zmq_ctx->zmq_context, socket);
            poll_items[0].socket = socket;
            if(sock_ctx_unlock(ctx) != 0) {
                LOG_ERROR_0("Failed to unlock socket contxt lock");
                return MSG_ERR_UNKNOWN;
            }
            sock_ctx_retries_reset(ctx);
            LOG_DEBUG_0("Finished re-initializing ZMQ socket");
        }

        if(!indef_poll) {
            return MSG_RECV_NO_MESSAGE;
        }
    } while(indef_poll);

    LOG_DEBUG_0("Receiving all of the message");

    // Receive message prefix (i.e. topic or service name)
    zmq_msg_t prefix;
    rc = recv_zmq_msg(socket, &prefix);
    if(rc == -1) {
        LOG_ERROR_0("Failed to receive message prefix");
        return MSG_ERR_RECV_FAILED;
    }

    char* name = NULL;
    name = (char*) zmq_msg_data(&prefix);
    LOG_DEBUG("Received message for '%s'", name);
    zmq_msg_close(&prefix);

    // Receive content type
    uint8_t buf[1];
    size_t buf_size = 1;
    rc = recv_zmq(socket, (void*) buf, buf_size);
    if(rc == -1) {
        LOG_ERROR_0("Failed to receive message content type");
        return MSG_ERR_RECV_FAILED;
    }

    // Receive expected number of parts
    uint8_t parts_buf[1];
    rc = recv_zmq(socket, (void*) parts_buf, buf_size);
    if(rc == -1) {
        LOG_ERROR_0("Failed to receive message content type");
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
        zmq_msg_t* part = (zmq_msg_t*) malloc(sizeof(zmq_msg_t));
        if(part == NULL) {
            LOG_ERROR_0("Ran out of memory initializing message part");
            return MSG_ERR_RECV_FAILED;
        }

        rc = recv_zmq_msg(socket, part);
        if(rc == -1) {
            LOG_ERROR_0("Failed to receive message part");
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

    msgbus_msg_envelope_serialize_destroy(parts, num_parts);

    return MSG_SUCCESS;
}

/**
 * Helper function for creating ZeroMQ URI for binding/connecting a given
 * socket.
 */
static char* create_uri(
        zmq_proto_ctx_t* ctx, const char* name, bool is_publisher) {
    char* uri = NULL;
    config_value_t* host = NULL;

    if(ctx->is_ipc) {
        // Temp pointer to the socket directory
        char* sock_dir = ctx->cfg.ipc.socket_dir->body.string;

        // Create first part of the URI
        size_t init_len = strlen(sock_dir) + IPC_PREFIX_LEN + 2;
        char* init_uri = concat_s(init_len, 3, IPC_PREFIX, sock_dir, "/");
        if(init_uri == NULL) {
            // Failed to do the first concatination
            return NULL;
        }

        LOG_DEBUG("Initial IPC uri: %s", init_uri);

        // Check if a specific socket file has been given for the IPC socket
        config_value_t* ipc_cfg_obj = config_get(ctx->config, name);
        if(ipc_cfg_obj != NULL) {
            if(ipc_cfg_obj->type != CVT_OBJECT) {
                LOG_ERROR("Configuration for '%s' must be an object", name);
                config_value_destroy(ipc_cfg_obj);
                free(init_uri);
                return NULL;
            }

            // Check if the configuration has as a specified socket file
            config_value_t* cv_sock_file = config_value_object_get(
                    ipc_cfg_obj, SOCKET_FILE);
            if(cv_sock_file != NULL) {
                if(cv_sock_file->type != CVT_STRING) {
                    LOG_ERROR("Configuration value for '%s' must be a string",
                              SOCKET_FILE);
                    config_value_destroy(cv_sock_file);
                    config_value_destroy(ipc_cfg_obj);
                    free(init_uri);
                    return NULL;
                }

                LOG_DEBUG("Using socket file: %s", cv_sock_file->body.string);

                size_t len = init_len + strlen(cv_sock_file->body.string);
                uri = concat_s(len, 2, init_uri, cv_sock_file->body.string);
                // The initial uri is not needed after this
                free(init_uri);
                if(uri == NULL) {
                    LOG_ERROR_0("Failed to concat init uri and socket file");
                    config_value_destroy(cv_sock_file);
                    config_value_destroy(ipc_cfg_obj);
                    return NULL;
                }

                return uri;
            } else {
                // No socket file was given in the configuration
                config_value_destroy(ipc_cfg_obj);
            }
        }

        // Using the given name for the socket file
        size_t len = init_len + strlen(name);
        uri = concat_s(len, 2, init_uri, name);
        free(init_uri);
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
                LOG_ERROR_0("ZeroMQ TCP not configured for publishing");
                return NULL;
            } else if(conf->type != CVT_OBJECT) {
                LOG_ERROR("Configuration for '%s' must be an object", name);
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
        if(port_str == NULL) {
            config_value_destroy(host);
            return NULL;
        }

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

/**
 * Helper function for setting the ZMQ_RCVHWM socket option on a ZMQ socket.
 *
 * \note Returns true immediately if zmq_rcvhwm < 0
 *
 * @param socket     - ZeroMQ socket
 * @param zmq_rcvhwm - ZeroMQ receive high watermark value
 * @return bool
 */
static bool set_rcv_hwm(void* socket, int zmq_rcvhwm) {
    if(zmq_rcvhwm < 0) return true;

    int ret = zmq_setsockopt(socket, ZMQ_RCVHWM, &zmq_rcvhwm, sizeof(int));
    if(ret != 0) {
        LOG_ZMQ_ERROR("Failed setting ZMQ_RCVHWM");
        return false;
    }

    return true;
}

/**
 * Helper function to get a string for the name of a ZeroMQ event.
 *
 * @param event - ZeroMQ event ID
 */
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

/**
 * Helper method to see if any events occured on a given socket.
 *
 * @param monitor - ZeroMQ monitor socket
 * @param block   - Flag for whether or not to block until an event occurs
 * @return ZeroMQ event ID
 */
static int get_monitor_event(void* monitor, bool block) {
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
static msgbus_ret_t init_curve_server_socket(
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
 * Helper free method for freeing a socket ctx that is in the pub_sockets
 * hashmap.
 */
static void free_sock_ctx(void* vargs) {
    zmq_shared_sock_t* sock_ctx = (zmq_shared_sock_t*) vargs;
    shared_sock_destroy(sock_ctx);
}

/**
 * Helper function to configure the given ZeroMQ socket to be a client
 * participating in Curve encryption with the TCP socket it is connecting
 * to.
 *
 * IMPORTANT NOTE: This method MUST be called prior to the zmq_connect() for
 * the socket.
 *
 * @param socket   - ZeroMQ socket
 * @param conf     - Configuration context
 * @param conf_obj - Configuration object for the TCP socket
 * @return msgbus_ret_t
 */
static msgbus_ret_t init_curve_client_socket(
        void* socket, config_t* conf, config_value_t* conf_obj) {

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

/**
 * Helper function for creating a new ZeroMQ socket.
 *
 * @param zmq_ctx     - EIS Message Bus ZeroMQ protocol context
 * @param uri         - Socket URI
 * @param name        - Service name or topic string
 * @param socket_type - ZMQ_* constant for the type of socket
 * @return ZeroMQ socket, NULL if an error occurs
 */
static void* new_socket(
        zmq_proto_ctx_t* zmq_ctx, const char* uri, const char* name,
        int socket_type) {
    // Bind / connect method to use on the socket
    int (*connect_fn)(void*,const char*) = zmq_bind;
    int ret = 0;
    int val = 0;

    LOG_DEBUG("Creating new socket: %s", uri);

    // Initialize ZeroMQ socket
    void* socket = zmq_socket(zmq_ctx->zmq_context, socket_type);
    if(socket == NULL) {
        LOG_ZMQ_ERROR("Failed to initialize ZeroMQ socket");
        goto err;
    }

    // Setting socket_options
    ret = zmq_setsockopt(socket, ZMQ_LINGER, &val, sizeof(val));
    if(ret != 0) {
        LOG_ZMQ_ERROR("Failed setting ZMQ_LINGER");
        goto err;
    }
    // Set the receive high watermark (if it is set for the protocol)
    if(!set_rcv_hwm(socket, zmq_ctx->zmq_recv_hwm)) { goto err; }

    switch(socket_type) {
        // Binding socket types
        case ZMQ_PUB:
            if(!zmq_ctx->is_ipc) {
                msgbus_ret_t rc = init_curve_server_socket(
                        socket, zmq_ctx->config, zmq_ctx->cfg.tcp.pub_config);
                if(rc != MSG_SUCCESS) { goto err; }
            }
            break;
        case ZMQ_REP:
            // Initialize socket with Curve authentication if the socket is a
            // TCP socket and the correct values are set in the configuration
            // for the socket
            if(!zmq_ctx->is_ipc) {
                config_value_t* cv = zmq_ctx->config->get_config_value(
                        zmq_ctx->config->cfg, name);
                msgbus_ret_t rc = init_curve_server_socket(
                        socket, zmq_ctx->config, cv);
                config_value_destroy(cv);
                if(rc != MSG_SUCCESS)
                    goto err;
            }
            break;

        // Connecting socket types
        case ZMQ_SUB:
            // Set the connect function to zmq_connect()
            connect_fn = zmq_connect;

            // Set subscription filter
            size_t topic_len = strlen(name);
            char* tmp = (char*) malloc(sizeof(char) * (topic_len + 1));
            if(tmp == NULL) {
                LOG_ERROR_0("Out of memory while initializing temp string");
                goto err;
            }

            memcpy_s(tmp, topic_len, name, topic_len);
            tmp[topic_len] = '\0';

            ret = zmq_setsockopt(socket, ZMQ_SUBSCRIBE, tmp, topic_len);
            free(tmp);
            if(ret != 0) {
                LOG_ZMQ_ERROR("Failed to set socket opts");
                goto err;
            }

            // Initialize socket with Curve authentication if the socket is a
            // TCP socket and the correct values are set in the configuration
            // for the socket
            if(!zmq_ctx->is_ipc) {
                config_value_t* cv = zmq_ctx->config->get_config_value(
                        zmq_ctx->config->cfg, name);
                msgbus_ret_t rc = init_curve_client_socket(
                        socket, zmq_ctx->config, cv);
                config_value_destroy(cv);
                if(rc != MSG_SUCCESS)
                    goto err;
            }
            break;
        case ZMQ_REQ:
            // Set the connect function to zmq_connect()
            connect_fn = zmq_connect;

            // Initialize socket with Curve authentication if the socket is a
            // TCP socket and the correct values are set in the configuration
            // for the socket
            if(!zmq_ctx->is_ipc) {
                config_value_t* cv = zmq_ctx->config->get_config_value(
                        zmq_ctx->config->cfg, name);
                msgbus_ret_t rc = init_curve_client_socket(
                        socket, zmq_ctx->config, cv);
                config_value_destroy(cv);
                if(rc != MSG_SUCCESS)
                    goto err;
            }
            break;

        // Unknown socket type
        default:
            LOG_ERROR_0("Unknown type of socket to create");
            goto err;
    }

    ret = connect_fn(socket, uri);
    if(ret != 0) {
        LOG_ZMQ_ERROR("Socket bind/connect failed");
        goto err;
    }

    return socket;
err:
    if(socket != NULL) {
        zmq_close(socket);
    }
    return NULL;
}
