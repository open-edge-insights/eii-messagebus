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
 * @file
 * @brief Messaging abstraction interface
 * @author Kevin Midkiff <kevin.midkiff@intel.com>
 */

#ifndef _EIS_MESSAGE_BUS_H
#define _EIS_MESSAGE_BUS_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <eis/utils/config.h>
#include <eis/msgbus/msg_envelope.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Request user data type
 */
typedef struct {
    void* data;
    void (*free)(void* data);
} user_data_t;

/**
 * Receive context structure used for service, subscription, and request
 * contexts.
 */
typedef struct {
    void* ctx;
    user_data_t* user_data;
} recv_ctx_t;

/**
 * Set of receive context to be used with `msgbus_recv_ready_poll()` method.
 */
typedef struct {
    int size;
    int max_size;
    bool* tbl_ready;
    recv_ctx_t** tbl_ctxs;
} recv_ctx_set_t;

/**
 * Publisher context
 */
typedef void* publisher_ctx_t;

/**
 * Initialize the message bus.
 *
 * \note{The message bus context takes ownership of the config_t object at this
 * point and the caller does not have to free the config object.}
 *
 * @param config - Configuration object
 * @return Message bus context, or NULL
 */
void* msgbus_initialize(config_t* config);

/**
 * Delete and clean up the message bus.
 */
void msgbus_destroy(void* ctx);

/**
 * Create a new publisher context object.
 *
 * \note{The `get_config_value()` method for the configuration will be called
 *  to retrieve values needed for the underlying protocol to initialize the
 *  context for publishing.}
 *
 * @param[in]  ctx     - Message bus context
 * @param[out] pub_ctx - Publisher context
 * @return msgbus_ret_t
 */
msgbus_ret_t msgbus_publisher_new(
        void* ctx, const char* topic, publisher_ctx_t** pub_ctx);

/**
 * Publish a message on the message bus.
 *
 * @param ctx     - Message bus context
 * @param pub_ctx - Publisher context
 * @param message - Messsage object to publish
 * @return msgbus_ret_t
 */
msgbus_ret_t msgbus_publisher_publish(
        void* ctx, publisher_ctx_t* pub_ctx, msg_envelope_t* message);

/**
 * Destroy publisher
 *
 * @param ctx     - Message bus context
 * @param pub_ctx - Publisher context
 */
void msgbus_publisher_destroy(void* ctx, publisher_ctx_t* pub_ctx);

/**
 * Subscribe to the given topic.
 *
 * @param[in]  ctx        - Message bus context
 * @param[in]  topic      - Subscription topic string
 * @param[in]  user_data  - User data attached to the receive context
 * @param[out] subscriber - Resulting subscription context
 * @return msgbus_ret_t
 */
msgbus_ret_t msgbus_subscriber_new(
        void* ctx, const char* topic, user_data_t* user_data,
        recv_ctx_t** subscriber);

/**
 * Delete and clean up a service, request, or subscriber context.
 *
 * @param ctx        - Message bus context
 * @param recv_ctx   - Receive context
 */
void msgbus_recv_ctx_destroy(void* ctx, recv_ctx_t* recv_ctx);

/**
 * Issue a request over the message bus.
 *
 * @param ctx          Message bus context
 * @param service_ctx  Service context
 * @param message      Request
 * @return msgbus_ret_t
 */
msgbus_ret_t msgbus_request(
        void* ctx, recv_ctx_t* service_ctx, msg_envelope_t* message);

/**
 * Respond to the given request.
 *
 * @param ctx         - Message bus context
 * @param service_ctx - Service context
 * @param message     - Response message
 * @return msgbus_ret_t
 */
msgbus_ret_t msgbus_response(
        void* ctx, recv_ctx_t* service_ctx, msg_envelope_t* message);

/**
 * Create a context to send requests to a service.
 *
 * @param[in]  ctx          - Message bus context
 * @param[in]  service_name - Name of the service
 * @param[in]  user_data    - User data
 * @param[out] service_ctx  - Service context
 * @param msgbus_ret_t
 */
msgbus_ret_t msgbus_service_get(
        void* ctx, const char* service_name, void* user_data,
        recv_ctx_t** service_ctx);

/**
 * Create context to receive requests over the message bus.
 *
 * @param[in]  ctx          - Message bus context
 * @param[in]  service_name - Name of the service
 * @param[in]  user_data    - User data
 * @param[out] service_ctx  - Service context
 * @return msgbus_ret_t
 */
msgbus_ret_t msgbus_service_new(
        void* ctx, const char* service_name, void* user_data,
        recv_ctx_t** service_ctx);

/**
 * Receive a message over the message bus using the given receiving context.
 *
 * \note{If a response has already been received for a given request, then a
 *   MSG_ERR_ALREADY_RECEIVED will be returned.}
 *
 * @param[in]  ctx      - Message bus context
 * @param[in]  recv_ctx - Context to use when receiving a message
 * @param[out] message  - Message received (if one exists)
 * @return msgbus_ret_t
 */
msgbus_ret_t msgbus_recv_wait(
        void* ctx, recv_ctx_t* recv_ctx, msg_envelope_t** message);

/**
 * Receive a message over the message bus, if no message is available wait for
 * the given amount of time for a message to arrive.
 *
 * @param[in]  ctx      - Message bus context
 * @param[in]  recv_ctx - Receive context
 * @param[in]  timeout  - Timeout for waiting to receive a message in
 *                        microseconds
 * @param[out] message  - Received message, NULL if timedout
 * @return msgbus_ret_t, MSG_RECV_NO_MESSAGE if no message received
 */
msgbus_ret_t msgbus_recv_timedwait(
        void* ctx, recv_ctx_t* recv_ctx, int timeout,
        msg_envelope_t** message);

/**
 * Receive a message if available, immediately return if there are no messages
 * available.
 *
 * @param[in]  ctx      - Message bus context
 * @param[in]  recv_ctx - Receive context
 * @param[out] message  - Received message, NULL if timedout
 * @return msgbus_ret_t, MSG_RECV_NO_MESSAGE if no message is available
 */
msgbus_ret_t msgbus_recv_nowait(
        void* ctx, recv_ctx_t* recv_ctx, msg_envelope_t** message);

#ifdef __cplusplus
} // extern "C"

#include <atomic>
#include <thread>
#include <chrono>
#include <condition_variable>
#include <eis/utils/logger.h>
#include <eis/utils/profiling.h>
#include <eis/utils/thread_safe_queue.h>
#include <eis/msgbus/msg_envelope.h>

// If in C++, add Publisher and Subscriber helpers for threads to subscribe
// and publish
namespace eis {
namespace msgbus {

using namespace eis::utils;

/**
 * Thread safe queue for serializable objects.
 */
typedef ThreadSafeQueue<eis::msgbus::Serializable*> MessageQueue;

/**
 * Base object for running message bus operations in a thread.
 */
class BaseMsgbusThread {
private:
    // Publisher thread handler
    std::thread* m_th;

protected:
    // Message bus context
    void* m_ctx;

    // Stop flag
    std::atomic<bool> m_stop;

    // Error condition variable to notify users of an error
    std::condition_variable& m_err_cv;

    /**
     * Run method to be overriden by subclasses.
     */
    virtual void run() = 0;

public:
    /**
     * Constructor
     *
     * @param msgbus_config - Message bus configuration
     */
    BaseMsgbusThread(config_t* msgbus_config, std::condition_variable& err_cv) :
        m_th(NULL), m_stop(false), m_err_cv(err_cv)
    {
        m_ctx = msgbus_initialize(msgbus_config);
        if(m_ctx == NULL) {
            throw "Failed to initialize message bus context";
        }
    };

    /**
     * Destructor.
     *
     * \note Child classes must destroy the msgbus context.
     */
    virtual ~BaseMsgbusThread() {
        if(m_th != NULL) {
            if(!m_stop.load()) {
                // Stop the thread because it is still running...
                this->stop();
            }
        }
    };

    /**
     * Start the publisher thread.
     */
    void start() {
        if(m_th == NULL) {
            m_stop.store(false);
            m_th = new std::thread(&BaseMsgbusThread::run, this);
        }
    };

    /**
     * Join with the underlying publisher thread.
     *
     * \note This will return immediately if the publisher has already stopped
     *      or if it has not been started yet.
     */
    void join() {
        if(m_th != NULL && !m_stop.load()) {
            m_th->join();
        }
    };

    /**
     * Stop the publisher thread.
     */
    void stop() {
        if(m_th != NULL && !m_stop.load()) {
            m_stop.store(true);
            m_th->join();
            delete m_th;
            m_th = NULL;
        }
    };
};

/**
 * Helper object for publishing messages in a thread given over an input
 * queue.
 */
class Publisher : public BaseMsgbusThread {
private:
    // Publisher context
    publisher_ctx_t* m_pub_ctx;

    // Input message queue
    MessageQueue* m_input_queue;

    // AppName variable
    std::string m_service_name;

    // Profiling variable
    Profiling* m_profile;

protected:
    /**
     * Publisher thread run method.
     */
    void run() override {
        LOG_DEBUG_0("Publisher thread started");

        // Duration to wait in between checking if the publisher should stop
        auto duration = std::chrono::milliseconds(250);
        Serializable* msg = NULL;
        msg_envelope_t* env = NULL;
        msgbus_ret_t ret = MSG_SUCCESS;

        // Profiling related variables
        int64_t serilization_start= 0;
        std::string serialization_start_ts_str = m_service_name + "_serialization_entry";
        std::string serialization_end_ts_str = m_service_name + "_serialization_exit";
        std::string publisher_ts_str = m_service_name + "_publisher_ts";

        while(!m_stop.load()) {
            if(m_input_queue->wait_for(duration)) {
                // Pop the envelope off the top of the queue
                msg = m_input_queue->front();
                m_input_queue->pop();
                if(msg == NULL) {
                    LOG_WARN_0("Got NULL serializable message...");
                    continue;
                }

                try {
                    // Serialize message into a message envelope
                    if(this->m_profile->is_profiling_enabled()) {
                        // Getting the current timestamp since DO_PROFILNG can't be used
                        // with msg
                        serilization_start = this->m_profile->get_curr_time_as_int_epoch();
                        env = msg->serialize();
                        DO_PROFILING(this->m_profile, env, serialization_end_ts_str.c_str());
                    } else {
                        env = msg->serialize();
                    }
                    if(env == NULL) {
                        delete msg;
                        msg = NULL;
                        LOG_ERROR_0("Failed to serialize message to msg envelope");
                        msgbus_msg_envelope_destroy(env);
                        m_err_cv.notify_all();
                        break;
                    }

                    if(this->m_profile->is_profiling_enabled()) {
                        // Adding the obtained start serialization timestamp to meta-data
                        msg_envelope_elem_body_t* serialization_time_start = msgbus_msg_envelope_new_integer(serilization_start);
                        if (serialization_time_start == NULL) {
                            LOG_ERROR_0("Failed to create profiling timestamp element");
                            msgbus_msg_envelope_destroy(env);
                            m_err_cv.notify_all();
                            break;
                        }
                        ret = msgbus_msg_envelope_put(env, serialization_start_ts_str.c_str(), serialization_time_start);
                        if(ret != MSG_SUCCESS) {
                            LOG_ERROR_0("Failed to add profiling timestamp to message envelope...");
                            msgbus_msg_envelope_destroy(env);
                            m_err_cv.notify_all();
                            break;
                        }
                        DO_PROFILING(this->m_profile, env, publisher_ts_str.c_str());
                    }

                    // Publish message
                    ret = msgbus_publisher_publish(m_ctx, m_pub_ctx, env);
                    if(ret != MSG_SUCCESS) {
                        LOG_ERROR_0("Failed to publish message...");
                        msgbus_msg_envelope_destroy(env);
                        m_err_cv.notify_all();
                        break;
                    }

                    LOG_DEBUG("Message published successfully");

                    // Clean up after publication attempt...
                    msgbus_msg_envelope_destroy(env);
                } catch(const std::exception& e) {
                    LOG_ERROR("Failed to serialize message: %s", e.what());
                    delete msg;
                    msg = NULL;
                    m_err_cv.notify_all();
                    break;
                }
            }
        }

        LOG_DEBUG_0("Publisher thread stopped");
    };

public:
    /**
     * Constructor.
     *
     * \note This object is not responsible for freeing the MessageQueue, it
     *      will free the message bus configuration if no exception is thrown.
     *
     * @param msgbus_config - Message bus context configuration
     * @param input_queue   - Input queue of messages to publish
     */
    Publisher(config_t* msgbus_config, std::condition_variable& err_cv,
              std::string topic, MessageQueue* input_queue, std::string service_name) :
        BaseMsgbusThread(msgbus_config, err_cv)
    {
        m_input_queue = input_queue;
        msgbus_ret_t ret = msgbus_publisher_new(
                m_ctx, topic.c_str(), &m_pub_ctx);
        if(ret != MSG_SUCCESS) {
            throw "Failed to initialize publisher context";
        }
        m_service_name = service_name;
        this->m_profile = new Profiling();
    };

    /**
     * Destructor.
     */
    ~Publisher() {
        this->stop();
        msgbus_publisher_destroy(m_ctx, m_pub_ctx);
        msgbus_destroy(m_ctx);
        delete m_profile;
    };
};

/**
 * Helper object for subscribing in a thread to messages from the message
 * bus and placing them in a message queue.
 */
template<class T>
class Subscriber : public BaseMsgbusThread {
private:
    // Subscriber context
    recv_ctx_t* m_recv_ctx;

    // Output message queue
    MessageQueue* m_output_queue;

    // Timeout for time to wait between receiving and checking if the stop
    // signal has been sent
    int m_timeout;

    // AppName variable
    std::string m_service_name;

    // Profiling variable
    Profiling* m_profile;

protected:
    /**
     * Subscriber thread run method.
     */
    void run() override {
        LOG_DEBUG_0("Subscriber thread started");

        msg_envelope_t* msg = NULL;
        msgbus_ret_t ret = MSG_SUCCESS;

        // Profiling related variables
        std::string subscriber_ts = m_service_name + "_subscriber_ts";
        std::string subscriber_exit_ts = m_service_name + "_subscriber_exit_ts";
        std::string subscriber_blocked_ts = m_service_name + "_subscriber_blocked_ts";

        while(!m_stop.load()) {
            ret = msgbus_recv_timedwait(m_ctx, m_recv_ctx, m_timeout, &msg);
            if(ret == MSG_SUCCESS) {
                // Received message
                T* received = new T(msg);

                // Add timestamp after message is received
                // if profiling is enabled
                if(this->m_profile->is_profiling_enabled()) {
                    DO_PROFILING(this->m_profile, msg, subscriber_ts.c_str());
                }
                QueueRetCode ret_queue = m_output_queue->push(received);
                if(ret_queue == QueueRetCode::QUEUE_FULL) {
                    // Add timestamp which acts as a marker if queue if blocked
                    if(this->m_profile->is_profiling_enabled()) {
                        DO_PROFILING(this->m_profile, msg, subscriber_blocked_ts.c_str());
                    }
                    if(m_output_queue->push_wait(received) != QueueRetCode::SUCCESS) {
                        LOG_ERROR_0("Failed to enqueue received message, "
                                    "message dropped");
                        delete received;
                        msgbus_msg_envelope_destroy(msg);
                        m_err_cv.notify_all();
                        break;
                    } else {
                        // Dropping pointer to message here because the memory for
                        // the envelope is not owned by the received variable
                        msg = NULL;
                    }
                }
                // Add timestamp for subscriber exit
                if(this->m_profile->is_profiling_enabled()) {
                    DO_PROFILING(this->m_profile, msg, subscriber_exit_ts.c_str());
                }
            } else if(ret != MSG_RECV_NO_MESSAGE) {
                LOG_ERROR("Error receiving message: %d", ret);
                m_err_cv.notify_all();
                break;
            }
        }

        LOG_DEBUG_0("Subscriber thread stopped");
    };

public:
    /**
     * Constructor.
     *
     * \note This object is not responsible for freeing the MessageQueue, it
     *      will free the message bus configuration if no exception is thrown.
     *
     * @param msgbus_config - Message bus context configuration
     * @param topic         - Topic to subscribe on
     * @param output_queue  - Output queue for received messages
     * @param timeout       - (Optional) Timeout in microseconds for when to
     *                        check if the thread should stop running (df: 250)
     */
    Subscriber(config_t* msgbus_config, std::condition_variable& err_cv,
              std::string topic, MessageQueue* output_queue, std::string service_name,
              int timeout=250) :
        BaseMsgbusThread(msgbus_config, err_cv)
    {
        static_assert(std::is_base_of<Serializable, T>::value,
                      "Template must be subclass of Serializable");
        m_output_queue = output_queue;
        msgbus_ret_t ret = msgbus_subscriber_new(
                m_ctx, topic.c_str(), NULL, &m_recv_ctx);
        if(ret != MSG_SUCCESS) {
            throw "Failed to initialize subscriber context";
        }
        m_timeout = timeout;
        m_service_name = service_name;
        this->m_profile = new Profiling();
    };

    /**
     * Destructor.
     */
    ~Subscriber() {
        this->stop();
        msgbus_recv_ctx_destroy(m_ctx, m_recv_ctx);
        msgbus_destroy(m_ctx);
        delete m_profile;
    };
};
} // msgbus
} // eis

#endif // __cpluspplus

#endif // _EIS_MESSAGE_BUS_H
