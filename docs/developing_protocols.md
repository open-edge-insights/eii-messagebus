# Developing Protocols

## Overview

Protocols are at the bottom most layer of the EIS Message Bus stack. They
provide the implementation for the messaging primitives supported by the
EIS Message Bus. The main tasks expected of a protocol are as follows:

1. Initialize the state of the underlying message library (i.e. ZeroMQ, DDS, etc.)
2. Implement methods for initializing contexts for publishers, subscribers,
    services, and service requesters
3. Implement base methods for sending messages from publishers, services, and
    service requesters
4. Implement base methods for receiving messages as blocking, non-blocking, and
    time out base function calls
5. Provide the translation between the underlying messaging library's messsage
    structure to the EIS Message Bus's `msg_envelope_t` structure

All protocols must have a unique protocol name which the EIS Message Bus can
use to load the protocol based on the `type` configuration value it is provided.
For example, the ZeroMQ TCP protocol uses the identifier `zmq_tcp`. Using this
type name, the EIS Message Bus knows how to load the protocol in the
`msgbus_initialize()` method.

Currently, the addition and loading of new protocols must be added directly
to the source code for the EIS Message Bus. In the future, the message bus will
include a feature for dynamically loading protocol plugins. All protocols are
expected to have an initialize method which follows the prototype:
`protocol_t* proto_<type>_initialize(const char* type, config_t* config)`. This
method is expected to initialize the underlying messaging library using the
given `config` parameter and then return a pointer to a `protocol_t` structure
which has pointers for all of the various messaging functions. This method
must then be added manually to the `msgbus_initialize()` function in
`src/msgbus.c`.

The `protocol_t` structure is defined below.

```c
typedef struct {
    void* proto_ctx;
    config_t* config;

    void (*destroy)(void* ctx);
    msgbus_ret_t (*publisher_new)(
            void* ctx, const char* topic, void** pub_ctx);
    msgbus_ret_t (*publisher_publish)(
            void* ctx, void* pub_ctx, msg_envelope_t* msg);
    void (*publisher_destroy)(void* ctx, void* pub_ctx);
    msgbus_ret_t (*subscriber_new)(
            void* ctx, const char* topic, void** subscriber);
    void (*recv_ctx_destroy)(void* ctx, void* recv_ctx);
    msgbus_ret_t (*request)(
            void* ctx, void* service_ctx, msg_envelope_t* message);
    msgbus_ret_t (*response)(
            void* ctx, void* service_ctx, msg_envelope_t* message);
    msgbus_ret_t (*service_new)(
            void* ctx, const char* service_name, void** service_ctx);
    msgbus_ret_t (*service_get)(
            void* ctx, const char* service_name, void** service_ctx);
    msgbus_ret_t (*recv_wait)(
            void* ctx, void* recv_ctx, msg_envelope_t** message);
    msgbus_ret_t (*recv_timedwait)(
            void* ctx, void* recv_ctx, int timeout, msg_envelope_t** message);
    msgbus_ret_t (*recv_nowait)(
            void* ctx, void* recv_ctx, msg_envelope_t** message);
} protocol_t;
```

It is expected that this structure is fully populated by a protocol's
initialization method. The `proto_ctx` value should be a pointer to an internal
structure representing the state of the protocol which the various functions
can use to perform the required tasks. Additionally, the `config` value should
be set to the `config` variable passed to the initialization function. It is
important to note that the returned `protocol_t` structure is not responsible
for freeing the memory assiciated with the `config` variable. This is managed
by the message bus context object.

For each of the functions in the structure the first `ctx` parameter will
always be the value of the `proto_ctx` variable.

For more information on the purpose of each of the function pointers in the
`protocol_t` structure see the [`protocol_t` Function Definition](#protocol_t-function-definition).

The rest of this section will cover the initial setup of a project to add a new
protocol to the EIS Message Bus, including the ideal code structure for the C
source code file.

For the purposes of this tutorial, the name of the proctol to be added will be
named `example`. To start, create a new header file in the `include/eis/msgbus`
directory and a new C file in the `src` directory.

```sh
$ touch include/eis/msgbus/example.h
$ touch src/example.c
```
> **NOTE:** The names of the files above should be the name of your protocol.

Once these files are created, add the following to the `example.h` file.

```c
// C include guards to prevent multiple definition from files including the
// header
#ifndef _EIS_MESSAGE_BUS_EXAMPLE_H
#define _EIS_MESSAGE_BUS_EXAMPLE_H

// Add extern C declaration if the code is being included from C++ code
#ifdef __cplusplus
extern "C" {
#endif

// Include the protocol.h to get the protocol_t and config_t structure
// definitions
#include "eis/msgbus/protocol.h"

/**
 * Method to initialize the example protocol.
 */
protocol_t* proto_example_initialize(const char* type, config_t* config);

#ifdef __cplusplus
}
#endif

#endif // _EIS_MESSAGE_BUS_EXAMPLE_H
```

The code above defines the initialization method for initializing the `example`
protocol.

Next, modify the `src/msgbus.c` file to call the new `proto_example_intiialize()`
method if the type configuration parameter is set to `example`.

First, include the `example.h` header file on line 36 in the `src/msgbus.c`
file.

```c
#include "eis/msgbus/example.h"
```

Then, add the following code at after line 210.

```c
int ind_example;
strcmp_s(value->body.string, strlen("example"), "example", &ind_example);
```

Next, extend the `if...else...` block from lines 212 to 219 to add an `else if`
clause for if the the protocol type is `example`. The entire code block should
look as follows in the end.

```c
if(ind_ipc == 0 ||ind_tcp == 0) {

    proto = proto_zmq_initialize(value->body.string, config);
    if(proto == NULL)
        goto err;
} else if(ind_example ==0) {
    proto = proto_example_initialize(value->body.string, config);
    if(proto == NULL)
        goto err;
} else {
    LOG_ERROR("Unknown protocol type: %s", value->body.string);
    goto err;
}
```

Once these steps are completed, switch to the `src/example.c` file to add the
protocol implementation. The recommended structure of the code in this file
is shown below.

The code below first defines a set of common header file includes, including
the `example.h` header file. Following this are the function prototypes for
all of the needed function pointers in the `protocol_t` structure.

After these definitions lies the implementation for the `proto_example_initialize()`
function. The `TODO` comments represent areas where code must be added depending
on the protocol being added to the EIS Message Bus. The code then intializes
the `protocol_t` struct and assigns all of the proper pointers.

After the implementation for the `proto_example_initialize()` function are all
of the function imlementations for the prototypes defined at the top of the
file.

Once this file is saved as `src/example.c`, compile the EIS Message Bus. The
examples should all work, however, they should immediately return or potentially
raise an error, since this is an empty protocol implementation and none of the
return objects are being initialized.

```c
// Standard C includes
#include <stdlib.h>

// Include the example.h header file
#include "eis/msgbus/example.h"

// Include the logger.h for helper logging macros
#include "eis/msgbus/logger.h"

// Function prototypes
void proto_example_destroy(void* ctx);

msgbus_ret_t proto_example_publisher_new(
        void* ctx, const char* topic, void** pub_ctx);

msgbus_ret_t proto_example_publisher_publish(
        void* ctx, void* pub_ctx, msg_envelope_t* msg);

void proto_example_publisher_destroy(void* ctx, void* pub_ctx);

msgbus_ret_t proto_example_subscriber_new(
    void* ctx, const char* topic, void** subscriber);

void proto_example_recv_ctx_destroy(void* ctx, void* recv_ctx);

msgbus_ret_t proto_example_recv_wait(
        void* ctx, void* recv_ctx, msg_envelope_t** message);

msgbus_ret_t proto_example_recv_timedwait(
        void* ctx, void* recv_ctx, int timeout, msg_envelope_t** message);

msgbus_ret_t proto_example_recv_nowait(
        void* ctx, void* recv_ctx, msg_envelope_t** message);

msgbus_ret_t proto_example_service_get(
        void* ctx, const char* service_name, void** service_ctx);

msgbus_ret_t proto_example_service_new(
        void* ctx, const char* service_name, void** service_ctx);

msgbus_ret_t proto_example_request(
        void* ctx, void* service_ctx, msg_envelope_t* msg);

msgbus_ret_t proto_example_response(
        void* ctx, void* service_ctx, msg_envelope_t* message);


// proto_example_initialize() method implementation
protocol_t* proto_example_initialize(const char* type, config_t* config) {
    LOG_DEBUG_0("Initializing example protocol");

    // TODO: Retreive needed configuration values from config

    // TODO: Initialize all the internal state for the protocol here

    // Initialize the protocol_t structure
    protocol_t* proto_ctx = (protocol_t*) malloc(sizeof(protocol_t));
    if(proto_ctx == NULL) {
        LOG_ERROR_0("Ran out of memory allocating the protocol_t struct");
        goto err;
    }

    // TODO: Replace with setting with the internal context structure for the
    // protocol initailized prior to this

    proto_ctx->proto_ctx = NULL;
    proto_ctx->config = config;

    // Assign all of the function pointers

    proto_ctx->destroy = proto_example_destroy;
    proto_ctx->publisher_new = proto_example_publisher_new;
    proto_ctx->publisher_publish = proto_example_publisher_publish;
    proto_ctx->publisher_destroy = proto_example_publisher_destroy;
    proto_ctx->subscriber_new = proto_example_subscriber_new;
    proto_ctx->request = proto_example_request;
    proto_ctx->response = proto_example_response;
    proto_ctx->service_get = proto_example_service_get;
    proto_ctx->service_new = proto_example_service_new;
    proto_ctx->recv_ctx_destroy = proto_example_recv_ctx_destroy;
    proto_ctx->recv_wait = proto_example_recv_wait;
    proto_ctx->recv_timedwait = proto_example_recv_timedwait;
    proto_ctx->recv_nowait = proto_example_recv_nowait;

    return proto_ctx;

    // It is recommended to have a single error goto location that cleans up
    // all allocated memory if an error occurs.
err:
    return NULL;
}

// proto_* function implementations

void proto_example_destroy(void* ctx) {
    LOG_DEBUG_0("Destroying example protocol context");
}

msgbus_ret_t proto_example_publisher_new(
        void* ctx, const char* topic, void** pub_ctx)
{
    LOG_DEBUG("Initializing publisher for topic '%s'", topic);

    // TODO: Intialize publisher

    return MSG_SUCCESS;
}

msgbus_ret_t proto_example_publisher_publish(
        void* ctx, void* pub_ctx, msg_envelope_t* msg)
{
    // TODO: Implement publishing a message

    return MSG_SUCCESS;
}

void proto_example_publisher_destroy(void* ctx, void* pub_ctx) {
    LOG_DEBUG_0("Destroying publisher context");

    // TODO: Destroy a publisher's context
}

msgbus_ret_t proto_example_subscriber_new(
    void* ctx, const char* topic, void** subscriber)
{
    LOG_DEBUG("Initializig subscriber to topic '%s'", topic);

    // TODO: Implement subscriber initialization

    return MSG_SUCCESS;
}

void proto_example_recv_ctx_destroy(void* ctx, void* recv_ctx) {
    LOG_DEBUG_0("Destroying receive context");
    // TODO: Implement destroying a receive context
}

msgbus_ret_t proto_example_recv_wait(
        void* ctx, void* recv_ctx, msg_envelope_t** message)
{
    // TODO: Implement blocking receive method

    return MSG_SUCCESS;
}

msgbus_ret_t proto_example_recv_timedwait(
        void* ctx, void* recv_ctx, int timeout, msg_envelope_t** message)
{
    // TODO: Implement receive which can timoue

    return MSG_SUCCESS;
}

msgbus_ret_t proto_example_recv_nowait(
        void* ctx, void* recv_ctx, msg_envelope_t** message)
{
    // TODO: Imeplement non-blocking receive method

    return MSG_SUCCESS;
}

msgbus_ret_t proto_example_service_get(
        void* ctx, const char* service_name, void** service_ctx)
{
    LOG_DEBUG("Initializing service request for service '%s'", service_name);

    // TODO: Intiailize context for sending requests and receiving responses
    // for the given service

    return MSG_SUCCESS;
}

msgbus_ret_t proto_example_service_new(
        void* ctx, const char* service_name, void** service_ctx)
{
    LOG_DEBUG("Initializing service '%s' context", service_name);

    // TODO: Initailize a service context

    return MSG_SUCCESS;
}

msgbus_ret_t proto_example_request(
        void* ctx, void* service_ctx, msg_envelope_t* msg)
{
    // NOTE: Becareful here that the service context is the correct one and
    // is not for receiving responses

    // TODO: Implement issuing a request to the service with the given
    // service context

    return MSG_SUCCESS;
}

msgbus_ret_t proto_example_response(
        void* ctx, void* service_ctx, msg_envelope_t* message)
{
    // NOTE: Becareful here that the service context is the correct one and
    // is not for receiving responses

    // TODO: Implement sending a response to a request

    return MSG_SUCCESS;
}
```

## `protocol_t` Function Definition

The following describes the purpose of each of the function pointers above.

### `destroy()`

Responsible for destroying the `proto_ctx` variable and freeing any memory
used by the context.

### `publisher_new()`

Initializes a new publisher context for the given `topic`.

### `publisher_publish()`

Publishes the given message value using the publisher context.

### `publisher_destroy()`

Destroys a context for a publisher freeing any sockets, memory, etc. used by
the publisher.

### `subscriber_new()`

Subscribe to the given topic and output a `recv_ctx_t` to use with the `recv_*`
methods to receive the publications for the topic.

### `service_new()`

Create a new `recv_ctx_t` structure which can be used to received requests
from clients and send responses to received requests using the `response()`
method.

### `service_get()`

Create a new `recv_ctx_t` structure which can be used to issue requests to and
received responses from the specified service.

### `recv_ctx_destroy()`

Destroy a `recv_ctx_t` structure.

### `request()`

Issue a request to the service using the given `recv_ctx_t`.

### `response()`

Send a response to a requesting client using the given `recv_ctx_t` structure.

### `recv_wait()`

Blocking function for receiving a message from a `recv_ctx_t` context structure.

### `recv_timedwait()`

Function for receiving messages from a `recv_ctx_t` context structure which
times out after the given timeout. The timeout shall always be milliseconds.

### `recv_nowait()`

Receive a message from a `recv_ctx_t` context structure if a message is available,
otherwise return immediately.
