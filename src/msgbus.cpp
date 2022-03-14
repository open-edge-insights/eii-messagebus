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
 * @brief EII Message Bus C++ API.
 */

#include "eii/msgbus/msgbus.hpp"

using namespace eii::msgbus;

MsgbusContext::MsgbusContext(config_t* config) {
    m_msgbus_ctx = msgbus_initialize(config);
    if (m_msgbus_ctx == NULL) {
        throw MsgbusException(
                MSG_ERR_UNKNOWN, "Failed to initialize message bus context");
    }
}

MsgbusContext::~MsgbusContext() {
    msgbus_destroy(m_msgbus_ctx);
}

Publisher* MsgbusContext::new_publisher(const std::string topic) {
    publisher_ctx_t* pub_ctx = NULL;

    msgbus_ret_t ret = msgbus_publisher_new(
            m_msgbus_ctx, topic.c_str(), &pub_ctx);
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to initialize publisher");
    }

    return new Publisher(m_msgbus_ctx, pub_ctx);
}

Subscriber* MsgbusContext::new_subscriber(
        const std::string topic, user_data_t* user_data) {
    recv_ctx_t* recv_ctx = NULL;

    msgbus_ret_t ret = msgbus_subscriber_new(
           m_msgbus_ctx, topic.c_str(), user_data, &recv_ctx);
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to initialize subscriber");
    }

    return new ReceiveContext(m_msgbus_ctx, recv_ctx);
}

Service* MsgbusContext::new_service(
        std::string service_name, void* user_data) {
    recv_ctx_t* recv_ctx = NULL;

    msgbus_ret_t ret = msgbus_service_new(
            m_msgbus_ctx, service_name.c_str(), user_data, &recv_ctx);
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to initialize service");
    }

    return new Service(m_msgbus_ctx, recv_ctx);
}

ServiceRequester* MsgbusContext::get_service(
        std::string service_name, void* user_data) {
    recv_ctx_t* recv_ctx = NULL;

    msgbus_ret_t ret = msgbus_service_get(
            m_msgbus_ctx, service_name.c_str(), user_data, &recv_ctx);
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to initialize service requester");
    }

    return new ServiceRequester(m_msgbus_ctx, recv_ctx);
}

Service::Service(void* msgbus_ctx, recv_ctx_t* recv_ctx) :
    ReceiveContext(msgbus_ctx, recv_ctx)
{}

Service::~Service() {}

void Service::response(MsgEnvelope* response) {
    msg_envelope_t* msg = response->get_msg_envelope();
    msgbus_ret_t ret = msgbus_response(m_msgbus_ctx, m_recv_ctx, msg);
    msgbus_msg_envelope_destroy(msg);
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to respond to request");
    }
}

ServiceRequester::ServiceRequester(void* msgbus_ctx, recv_ctx_t* recv_ctx) :
    ReceiveContext(msgbus_ctx, recv_ctx)
{}

ServiceRequester::~ServiceRequester() {}

void ServiceRequester::request(MsgEnvelope* env) {
    msg_envelope_t* msg = env->get_msg_envelope();
    msgbus_ret_t ret = msgbus_request(m_msgbus_ctx, m_recv_ctx, msg);
    msgbus_msg_envelope_destroy(msg);
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to issue request");
    }
}

Publisher::Publisher(void* msgbus_ctx, publisher_ctx_t* pub_ctx) :
    m_msgbus_ctx(msgbus_ctx), m_pub_ctx(pub_ctx)
{}

Publisher::~Publisher() {
    msgbus_publisher_destroy(m_msgbus_ctx, m_pub_ctx);
}

void Publisher::publish(MsgEnvelope* msg) {
    msg_envelope_t* env = msg->get_msg_envelope();
    msgbus_ret_t ret = msgbus_publisher_publish(m_msgbus_ctx, m_pub_ctx, env);
    msgbus_msg_envelope_destroy(env);
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to publish message");
    }
}

ReceiveContext::ReceiveContext(void* msgbus_ctx, recv_ctx_t* recv_ctx) :
    m_msgbus_ctx(msgbus_ctx), m_recv_ctx(recv_ctx)
{}

ReceiveContext::~ReceiveContext() {
    msgbus_recv_ctx_destroy(m_msgbus_ctx, m_recv_ctx);
}

MsgEnvelope* ReceiveContext::recv_wait() {
    msg_envelope_t* msg = NULL;

    msgbus_ret_t ret = msgbus_recv_wait(m_msgbus_ctx, m_recv_ctx, &msg);
    if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to receive message");
    }

    return new MsgEnvelope(msg);
}

MsgEnvelope* ReceiveContext::recv_nowait() {
    msg_envelope_t* msg = NULL;

    msgbus_ret_t ret = msgbus_recv_nowait(m_msgbus_ctx, m_recv_ctx, &msg);
    if (ret == MSG_RECV_NO_MESSAGE) {
        return NULL;
    } else if (ret != MSG_SUCCESS) {
        throw MsgbusException(ret, "Failed to receive message");
    }

    return new MsgEnvelope(msg);
}

user_data_t* ReceiveContext::get_user_data() {
    return m_recv_ctx->user_data;
}

BaseMsgbusThread::BaseMsgbusThread(
        config_t* msgbus_config, std::condition_variable& err_cv) :
    m_th(NULL), m_stop(false), m_err_cv(err_cv) {
    m_ctx = new MsgbusContext(msgbus_config);
}

BaseMsgbusThread::~BaseMsgbusThread() {
    if (m_th != NULL) {
        if (!m_stop.load()) {
            // Stop the thread because it is still running...
            this->stop();
        }
        if (m_ctx) {
            delete m_ctx;
        }
    }
}

void BaseMsgbusThread::start() {
    if (m_th == NULL) {
        m_stop.store(false);
        m_th = new std::thread(&BaseMsgbusThread::run, this);
    }
}

void BaseMsgbusThread::join() {
    if (m_th != NULL && !m_stop.load()) {
        m_th->join();
    }
}

void BaseMsgbusThread::stop() {
    if (m_th != NULL && !m_stop.load()) {
        m_stop.store(true);
        m_th->join();
        delete m_th;
        m_th = NULL;
    }
}

void PublisherThread::run() {
    LOG_DEBUG_0("Publisher thread started");

    // Duration to wait in between checking if the publisher should stop
    auto duration = std::chrono::milliseconds(250);
    msgbus_ret_t ret = MSG_SUCCESS;

    Serializable* msg = NULL;
    msg_envelope_t* env = NULL;
    MsgEnvelope* msg_env = NULL;

    // Profiling related variables
    int64_t serilization_start = 0;
    std::string serialization_start_ts_str =
        m_service_name + "_serialization_entry";
    std::string serialization_end_ts_str =
        m_service_name + "_serialization_exit";
    std::string publisher_ts_str = m_service_name + "_publisher_ts";

    while (!m_stop.load()) {
        if (m_input_queue->wait_for(duration)) {
            // Pop the envelope off the top of the queue
            msg = m_input_queue->pop();
            if (msg == NULL) {
                LOG_WARN_0("Got NULL serializable message");
                continue;
            }

            try {
                // Serialize message into a message envelope
                if (this->m_profile->is_profiling_enabled()) {
                    // Getting the current timestamp since DO_PROFILNG can't be
                    // used with msg
                    serilization_start =
                        this->m_profile->get_curr_time_as_int_epoch();
                    env = msg->serialize();
                    DO_PROFILING(
                            this->m_profile, env,
                            serialization_end_ts_str.c_str());
                } else {
                    env = msg->serialize();
                }

                if (env == NULL) {
                    delete msg;
                    msg = NULL;
                    LOG_ERROR_0("Failed to serialize message to msg envelope");
                    msgbus_msg_envelope_destroy(env);
                    m_err_cv.notify_all();
                    break;
                }

                if (this->m_profile->is_profiling_enabled()) {
                    // Adding the obtained start serialization timestamp to
                    // meta-data
                    ret = msgbus_msg_envelope_put_integer(
                            env, serialization_start_ts_str.c_str(),
                            serilization_start);
                    if (ret != MSG_SUCCESS) {
                        LOG_ERROR_0(
                                "Failed adding profiling timestamp to "
                                "message envelope");
                        msgbus_msg_envelope_destroy(env);
                        m_err_cv.notify_all();
                        break;
                    }
                    DO_PROFILING(
                            this->m_profile, env, publisher_ts_str.c_str());
                }

                // Publish message
                msg_env = new MsgEnvelope(env);
                m_pub->publish(msg_env);
                delete msg_env;
                msg_env = NULL;
                delete msg;
                msg = NULL;
            } catch(const std::exception& e) {
                LOG_ERROR("Failed to publish message: %s", e.what());
                delete msg;
                msg = NULL;
                if (msg_env != NULL) {
                    delete msg_env;
                    msg_env = NULL;
                } else if (env != NULL) {
                    msgbus_msg_envelope_destroy(env);
                    env = NULL;
                }
                m_err_cv.notify_all();
                break;
            }
        }
    }

    LOG_DEBUG_0("Publisher thread stopped");
}

PublisherThread& PublisherThread::operator=(const PublisherThread& src) {
    return *this;
}

PublisherThread::PublisherThread(
        config_t* msgbus_config, std::condition_variable& err_cv,
        std::string topic, MessageQueue* input_queue,
        std::string service_name) :
    BaseMsgbusThread(msgbus_config, err_cv) {
    m_input_queue = input_queue;
    m_pub = m_ctx->new_publisher(topic);
    m_service_name = service_name;
    this->m_profile = new eii::utils::Profiling();
}

PublisherThread::~PublisherThread() {
    this->stop();
    delete m_pub;
    delete m_ctx;
    delete m_profile;
}
