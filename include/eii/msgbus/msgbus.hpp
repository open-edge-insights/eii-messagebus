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
 * @brief EII Message Bus C++ API.
 */

#ifndef _EII_MSGBUS_HPP
#define _EII_MSGBUS_HPP

#include <atomic>
#include <string>
#include <chrono>
#include <thread>
#include <condition_variable>
#include <eii/utils/profiling.h>
#include <eii/utils/thread_safe_queue.h>
#include "eii/msgbus/msgbus.h"
#include "eii/msgbus/msg_envelope.hpp"

namespace eii {
namespace msgbus {

// Forward declarations
class ReceiveContext;
class Publisher;
class Service;
class ServiceRequester;

/**
 * EII Message Bus Subscriber wrapper.
 *
 * \note This is just a typedef, because it has no differences with a @c
 *   ReceiveContext object.
 */
typedef ReceiveContext Subscriber;

/**
 * EII Message Bus context object.
 */
class MsgbusContext {
private:
    // Underlying message bus context
    void* m_msgbus_ctx;

    /**
     * Private @c MsgbusContext copy constructor.
     */
    MsgbusContext(const MsgbusContext& src);

    /**
     * Private @c MsgbusContext assignment operator.
     */
    MsgbusContext& operator=(const MsgbusContext& src);

public:
    /**
     * Constructor.
     *
     * \exception MsgbusException Thrown if an error occurs in the message bus.
     *
     * @param config - Messae bus configuration object
     */
    MsgbusContext(config_t* config);

    /**
     * Destructor.
     */
    ~MsgbusContext();

    /**
     * Create a new publisher with the specified topic.
     *
     * \note The topic string provided to this message must have a
     *   corresponding configuration in the @c config_t given to the
     *   @c MsgbusContext's constructor.
     *
     * \exception MsgbusException Thrown if an error occurs in the message bus.
     *
     * @param topic     - Topic string for the publisher
     * @return @c Publisher*
     */
    Publisher* new_publisher(const std::string topic);

    /**
     * Create a new subscriber on the specified topic.
     *
     * \note The topic string provided to this message must have a
     *   corresponding configuration in the @c config_t given to the
     *   @c MsgbusContext's constructor.
     *
     * \exception MsgbusException Thrown if an error occurs in the message bus.
     *
     * @param topic - Topic string for the subscriber
     * @param user_data - Optional user data to attach to the subscriber.
     * @return @c Subscriber*
     */
    Subscriber* new_subscriber(
            const std::string topic, user_data_t* user_data=NULL);

    /**
     * Create a new service context for issuing requests to a service.
     *
     * \note This method will expect to find the configuration attributes
     *   needed to communicate with the specified service in the configuration
     *   given to the constructor.
     *
     * \exception MsgbusException Thrown if an error occurs in the message bus.
     *
     * @param service_name - Name of the service
     * @param user_data    - Optional user data to attach to the service.
     * @return @c Service*
     */
    Service* new_service(std::string service_name, void* user_data=NULL);

    /**
     * Create a new service context for receiving requests.
     *
     * \note This method will expect to find the configuration attributes
     *   needed to communicate with the specified service in the configuration
     *   given to the constructor.
     *
     * \exception MsgbusException Thrown if an error occurs in the message bus.
     *
     * @param service_name - Name of the service
     * @param user_data    - Optional user data to attach to the service.
     * @return @c Service*
     */
    ServiceRequester* get_service(
            std::string service_name, void* user_data=NULL);
};

/**
 * Base receive object used by the @c Subscriber, @c Service, and
 * @c ServiceRequester.
 */
class ReceiveContext {
protected:
    // Message bus context which the receive context belongs to
    void* m_msgbus_ctx;

    // Internal EII Message Bus receive context
    recv_ctx_t* m_recv_ctx;

    /**
     * Constructor
     *
     * \note This should never be called directly except inside of the
     *   @c MsgbusContext object.
     */
    ReceiveContext(void* msgbus_ctx, recv_ctx_t* recv_ctx);

public:
    /**
     * Destructor
     */
    ~ReceiveContext();

    /**
     * Receive a message on the message bus for the given receive context.
     *
     * \note This function will block indefinitely until a message is received
     *   or an interrupt occurs.
     *
     * \exception MsgbusException Thrown if an error occurs in the message bus.
     *
     * @return @c MsgEnvelope*
     */
    MsgEnvelope* recv_wait();

    /**
     * Receive a message on the message bus for the given receive context.
     * This method will attempt receive for the given duration of time, if no
     * message is received then the method shall return NULL.
     *
     * \note The timeout value must be a minimum is one microsecond.
     *
     * \exception MsgbusException Thrown if an error occurs in the message bus.
     *
     * @param timeout - Duration to wait until timing out
     * @return @c MsgEnvelope*, NULL if no message was received
     */
    template<class Rep, class Period>
    MsgEnvelope* recv_timedwait(
            const std::chrono::duration<Rep, Period>& timeout) {
        int timeout_ms = std::chrono::microseconds(timeout).count();
        msg_envelope_t* msg = NULL;

        msgbus_ret_t ret = msgbus_recv_timedwait(
                m_msgbus_ctx, m_recv_ctx, timeout_ms, &msg);
        if (ret == MSG_RECV_NO_MESSAGE) {
            return NULL;
        } else if (ret != MSG_SUCCESS) {
            throw MsgbusException(ret, "Failed to receive message");
        }

        return new MsgEnvelope(msg);
    }

    /**
     * Receive a message on the message bus for the given receive context.
     * If no message is immediately available, then NULL shall be returned.
     *
     * \exception MsgbusException Thrown if an error occurs in the message bus.
     *
     * @return @c MsgEnvelope*, NULL if no message was received
     */
    MsgEnvelope* recv_nowait();

    /**
     * Get the user-data attached to the context at creation.
     *
     * \note "Creation" occurs when calling @c MsgbusContext::new_subscriber(),
     *   @c MsgbusContext::new_service(), or @c MsgbusContext::get_service().
     *
     * \exception MsgbusException Thrown if an error occurs in the message bus.
     *
     * @return void*, may be NULL depending on the user assigned value
     */
    user_data_t* get_user_data();


    // MsgbusContext class friend so it can call the private constructor
    friend class MsgbusContext;
};

/**
 * EII Message Bus service (i.e. server) wrapper.
 */
class Service : public ReceiveContext {
private:
    /**
     * Constructor
     *
     * \note This should never be called directly except inside of the
     *   @c MsgbusContext object.
     */
    Service(void* msgbus_Ctx, recv_ctx_t* recv_ctx);

public:
    /**
     * Destructor
     */
    ~Service();

    /**
     * Issue a response over the message bus.
     *
     * \note delete should be called on the @c MsgEnvelope by the calling
     *   application after this method is called.
     *
     * \exception MsgbusException Thrown if an error occurs in the message bus.
     *
     * @param response - @c MsgEnvelope* response
     */
    void response(MsgEnvelope* response);

    // MsgbusContext class friend so it can call the private constructor
    friend class MsgbusContext;
};

/**
 * EII Message Bus service requester (i.e. client) wrapper.
 */
class ServiceRequester : public ReceiveContext {
private:
    /**
     * Constructor
     *
     * \note This should never be called directly except inside of the
     *   @c MsgbusContext object.
     */
    ServiceRequester(void* msgbus_ctx, recv_ctx_t* recv_ctx);

public:
    /**
     * Destructor
     */
    ~ServiceRequester();

    /**
     * Issue a request over the message bus.
     *
     * \note delete should be called on the @c MsgEnvelope by the calling
     *   application after this method is called.
     *
     * \exception MsgbusException Thrown if an error occurs in the message bus.
     *
     * @param request - @c MsgEnvelope* request
     */
    void request(MsgEnvelope* request);

    // MsgbusContext class friend so it can call the private constructor
    friend class MsgbusContext;
};

/**
 * EII Message Bus publisher wrapper.
 */
class Publisher {
private:
    // Publisher's message bus context
    void* m_msgbus_ctx;

    // Internal publisher context
    publisher_ctx_t* m_pub_ctx;

protected:
    /**
     * Constructor
     *
     * \note This should never be called directly except inside of the
     *   @c MsgbusContext object.
     */
    Publisher(void* msgbus_ctx, publisher_ctx_t* pub_ctx);

public:
    /**
     * Destructor
     */
    ~Publisher();

    /**
     * Publish a message over the EII message bus.
     *
     * \note delete should be called on the @c MsgEnvelope by the calling
     *   application after this method is called.
     *
     * \exception MsgbusException Thrown if an error occurs in the message bus.
     *
     * @param msg - @c MsgEnvelope to publish
     */
    void publish(MsgEnvelope* msg);

    // MsgbusContext class friend so it can call the private constructor
    friend class MsgbusContext;
};

/**
 * Thread safe queue for serializable objects.
 */
typedef eii::utils::ThreadSafeQueue<eii::msgbus::Serializable*> MessageQueue;

/**
 * Base object for running message bus operations in a thread.
 */
class BaseMsgbusThread {
private:
    // Publisher thread handler
    std::thread* m_th;

protected:
    // Message bus context
    MsgbusContext* m_ctx;

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
     * \exception MsgbusException Thrown if an error occurs in the message bus.
     *
     * @param msgbus_config - Message bus configuration
     * @param err_cv        - Condition variable to indicate an error in
     *                        the thread
     */
    BaseMsgbusThread(config_t* msgbus_config, std::condition_variable& err_cv);

    /**
     * Destructor.
     *
     * \note Child classes must destroy the msgbus context.
     */
    virtual ~BaseMsgbusThread();

    /**
     * Start the message bus thread.
     */
    virtual void start();

    /**
     * Join with the underlying message bus thread.
     *
     * \note This will return immediately if the publisher has already stopped
     *      or if it has not been started yet.
     */
    virtual void join();

    /**
     * Stop the message bus thread.
     */
    virtual void stop();
};

/**
 * Helper object for publishing messages in a thread given over an input
 * queue.
 */
class PublisherThread : public BaseMsgbusThread {
private:
    // Publisher context
    Publisher* m_pub;

    // Input message queue
    MessageQueue* m_input_queue;

    // AppName variable
    std::string m_service_name;

    // Profiling variable
    eii::utils::Profiling* m_profile;

    PublisherThread& operator=(const PublisherThread& src);

protected:
    /**
     * Publisher thread run method.
     */
    void run() override;

public:
    /**
     * Constructor.
     *
     * \note This object is not responsible for freeing the MessageQueue, it
     *      will free the message bus configuration if no exception is thrown.
     *
     * \exception MsgbusException Thrown if an error occurs in the message bus.
     *
     * @param msgbus_config - Message bus context configuration
     * @param err_cv        - Condition variable to indicate an error in
     *                        the thread
     * @param topic         - Topic to publish on
     * @param input_queue   - Input queue of messages to publish
     * @param service_name  - Name of the service running the publisher thread
     */
    PublisherThread(
            config_t* msgbus_config, std::condition_variable& err_cv,
            std::string topic, MessageQueue* input_queue,
            std::string service_name);

    /**
     * Destructor
     */
    ~PublisherThread();
};

/**
 * Helper object for subscribing in a thread to messages from the message
 * bus and placing them in a message queue.
 */
template<class T>
class SubscriberThread : public BaseMsgbusThread {
private:
    // Subscriber context
    ReceiveContext* m_recv_ctx;

    // Output message queue
    MessageQueue* m_output_queue;

    // Timeout for time to wait between receiving and checking if the stop
    // signal has been sent
    std::chrono::microseconds m_timeout;

    // AppName variable
    std::string m_service_name;

    // Profiling variable
    eii::utils::Profiling* m_profile;

    SubscriberThread& operator=(const SubscriberThread& src) { return *this; };

protected:
    /**
     * Subscriber thread run method.
     */
    void run() override {
        LOG_DEBUG_0("Subscriber thread started");

        msg_envelope_t* msg = NULL;
        MsgEnvelope* env = NULL;
        T* received = NULL;
        utils::QueueRetCode ret_queue = utils::QueueRetCode::SUCCESS;

        // Profiling related variables
        std::string subscriber_ts = m_service_name + "_subscriber_ts";
        std::string subscriber_exit_ts =
            m_service_name + "_subscriber_exit_ts";
        std::string subscriber_blocked_ts =
            m_service_name + "_subscriber_blocked_ts";

        try {
            while (!m_stop.load()) {
                env = m_recv_ctx->recv_timedwait(m_timeout);
                if (env == NULL) {
                    // Timeout...
                    continue;
                }

                // Received message
                msg = env->get_msg_envelope();
                received = new T(msg);

                // env is no longer needed after this point, delete it
                delete env;
                env = NULL;

                // Add timestamp after message is received if profiling is
                // enabled
                DO_PROFILING(this->m_profile, msg, subscriber_ts.c_str());

                ret_queue = m_output_queue->push(received);
                if (ret_queue == utils::QueueRetCode::QUEUE_FULL) {
                    // Add timestamp which acts as a marker if queue is blocked
                    DO_PROFILING(
                        this->m_profile, msg, subscriber_blocked_ts.c_str());

                    ret_queue = m_output_queue->push_wait(received);
                    if(ret_queue != utils::QueueRetCode::SUCCESS) {
                        LOG_ERROR_0("Failed to enqueue received message, "
                                    "message dropped");
                        // THIS SHOULD BE DONE BY RECEIVED...
                        // msgbus_msg_envelope_destroy(msg);
                        m_err_cv.notify_all();
                        break;
                    } else {
                        // Dropping pointer to message here because the memory for
                        // the envelope is now owned by the received variable
                        msg = NULL;
                        received = NULL;
                    }
                } else {
                        msg = NULL;
                        received = NULL;
                }

                // Add timestamp for subscriber exit
                DO_PROFILING(this->m_profile, msg, subscriber_exit_ts.c_str());
            }
        } catch (const std::exception& ex) {
            LOG_ERROR("Error in subscriber thread: %s", ex.what());
        }

        // When the while loop exits, if received is not NULL then it has been
        // initialized with the underlying msg_envelope_t and now owns the
        // deletion of its memory. If msg is not NULL and received is NULL,
        // then this thread owns the msg_envelope_t* structure and must free
        // it.
        if (received != NULL) {
            delete received;
        } else if (msg != NULL) {
            msgbus_msg_envelope_destroy(msg);
        }

        // Even if the above are true, if the MsgEnvelope (env) is not NULL it
        // must be deleted. If received is NULL, msg is NULL, and env is not
        // NULL then it currently owns a msg_envelope_t and will approprietly
        // dispose of it.
        if (env != NULL) {
            delete env;
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
     * \exception MsgbusException Thrown if an error occurs in the message bus.
     *
     * @param msgbus_config - Message bus context configuration
     * @param err_cv        - Condition variable to use to notify the main
     *                        application if an error has occurred
     * @param topic         - Topic to subscribe on
     * @param output_queue  - Output queue for received messages
     * @param timeout       - Timeout in microseconds to use in between
     *                        checking if the thread should stop
     */
    SubscriberThread(config_t* msgbus_config, std::condition_variable& err_cv,
                     std::string topic, MessageQueue* output_queue,
                     std::string service_name,
                     std::chrono::microseconds timeout=
                         std::chrono::microseconds(250)) :
        BaseMsgbusThread(msgbus_config, err_cv) {

        static_assert(std::is_base_of<Serializable, T>::value,
                  "Template must be subclass of eii::msgbus::Serializable");

        m_recv_ctx = m_ctx->new_subscriber(topic);
        m_output_queue = output_queue;
        m_timeout = timeout;
        m_service_name = service_name;
        m_profile = new eii::utils::Profiling();
    };

    /**
     * Destructor.
     */
    ~SubscriberThread() {
        this->stop();
        delete m_recv_ctx;
        delete m_ctx;
        delete m_profile;
    };
};

}  // namespace msgbus
}  // namespace eii

#endif  // _EII_MSGBUS_HPP
