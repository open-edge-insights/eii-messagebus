# EII Message Bus User Guide

## Overview

- [EII Message Bus Architecture]()
- [EII Message Bus Usage]()
    - [Compilation & Installtion]()
    - [Python Tutorial]()
    - [Go Tutorial]()
    - [C Tutorial]()
- [EII Message Bus Development]()
    - [Developing Protocols]()

## EII Message Bus Architecture


## EII Message Bus Usage

### Compilation & Installation

The EII Message Bus utilizes the CMake build tools for compiling the `C` and
`Python` libraries. To compile the library execute the following commands:

```sh
$ mkdir build
$ cd build
$ cmake ..
$ make
```

The EII Message Bus adds the following flags to CMake for the build process
to enable and disable features in the message bus. The table below specifies
all of the additional flags which can be given to CMake while building the
message bus.

|      Flag       |                    Description                 |
| :-------------: | ---------------------------------------------- |
| `WITH_PYTHON`   | Compile the Python binding with the C library. |
| `WITH_GO`       | Install the GO binding with the C library.     |
| `WITH_EXAMPLES` | Compile the C examples.                        |
| `WITH_TESTS`    | Compile the C unit tests.                      |

> **NOTE:** All of the flags are passed to CMake using the following CLI
> format: `-D<FLAG>=[ON | OFF]`. For example, `cmake -DWITH_PYTHON=ON ..`.

To install the message bus, execute the following command:

```sh
$ sudo make install
```

If the `WITH_PYTHON` flag was given to CMake during the compilation step, then
the Python binding will also be installed into the `dist-packages` in your
environment.

### Configuration

The EII Message Bus is configured through a `key, value` pair interface. The
values can be objects, arrays, integers, floating point, boolean, or strings.
The keys that are required to be available in the configuration are largly
determined by the underlying protocol which the message bus will use. The
protocol is specified via the `type` key and currently must be one of the
following:

- `zmq_ipc` - ZeroMQ over IPC protocol
- `zmq_tcp` - ZeroMQ over TCP protocol

The following sections specify the configuration attributes expected for the
TCP and IPC ZeroMQ protocols.

#### ZeroMQ IPC Configuration

The ZeroMQ IPC protocol implementation only requires one configuration
attribute: `socket_dir`. The value of this attribute specifies the directory
where the message bus should create the Unix socket files to establish the IPC
based communication.

#### ZeroMQ TCP Configuration

The ZeroMQ TCP protocol has several configuration attributes which must be
specified based on the communication pattern the application is using and
based on the security the application wishes to enable for its communication.

##### Publishers

For an application which wishes to publish messages over specific topics, the
configuration must contain the key `zmq_tcp_publish`. This attribute must be
an object which has the following keys:

|          Key        |   Type   | Required |                         Description                      |
| :-----------------: | -------- | -------- | -------------------------------------------------------- |
| `host`              | `string` | Yes      | Specifies the host to publish as                         |
| `port`              | `int`    | Yes      | Specifies the port to publish messages on                |
| `server_secret_key` | `string` | No       | Specifies the secret key for the port for authentication |

The `server_secret_key` must be a Curve Z85 encoded string value that is
specified if the application wishes to use CurveZMQ authentication with to
secure incoming connections from subscribers.

##### Subscribers

To subscribe to messages coming from a publisher over TCP, the configuration
must contain a key for the topic you wish to subscribe to. For example, if
*Application 1* were publishing on topic `sensor-1`, then the subscribing
application *Application 2* would need to contain a configuration key `sensor-1`
which contains the keys required to configure the TCP connection to
*Application 1*.

The key that can be specified for a subscribers configuration are outline in the
table below.

|          Key        |   Type   | Required |                         Description                        |
| :-----------------: | -------- | -------- | ---------------------------------------------------------- |
| `host`              | `string` | Yes      | Specifies the host of the publisher                        |
| `port`              | `int`    | Yes      | Specifies the port of the publisher                        |
| `server_public_key` | `string` | No       | Specifies the publisher's public key for authentication    |
| `client_secret_key` | `string` | No       | Specifies the subscribers's secret key for authentication  |
| `client_public_key` | `string` | No       | Specifies the subcribers's public key for authentication   |

> **NOTE:** If one of the `*_key` values is specifed, then all of them must be
> specified.

##### Services

The configuration to host a service to receive and respond to requests is
similar to the configuration for doing publications on a message bus context.
The only difference, is the configuration for a service is placed under a key
which is the name of the service.

For example, if *Application 1* wishes to host a service named `example-service`,
then the configuration must contain an a key called `example-service`. The value
for that key must be an object containing the keys listed in the table of
the Publishers section.

##### Requesters

The configuration to issue requests to a service is the exact same as a
subscriber. In the case of a requester, instead of the configuration being
under the name of the topic, the configuration is placed under the name of
the service it wishes to connect to. For the details of the allowed values,
see the table in the Subscribers section above.

##### Using ZAP Authentication

For services and publishers additional security can be enabled for all incoming
connections (i.e. requesters and subscribers). This method utilizes the ZMQ
ZAP protocol to verify the incoming client public keys against a list of
whitelisted clients.

The list of allowed clients is given to the message bus via the `allowed_clients`
key. This key must be a list of Z85 encoded CurveZMQ keys.

### Python Tutorial

#### Publish/Subscribe

The following tutorial will cover how to do publish/subscribe messaging using
the EII Message Bus. The outcome of this tutorial will be two Python scripts,
one of which will publish messages and the other which will subscribe to
messages.

To start, we will create a script named, `publisher.py`. To start, we will
add a few necessary imports which will be utilized later in the tutorial.

```python
import os
import time
import json
import argparse
import eii.msgbus as mb
```

The last line of the imports above is where we import the EII Message Bus
Python binding, which for sake of clarity will be referenced as `mb` in all
of the code to follow.

Next, we will add some more boilerplate code for parsing command line
arguments.

```python
# Argument parsing
ap = argparse.ArgumentParser()
ap.add_argument('config', help='JSON configuration')
ap.add_argument('-t', '--topic', default='publish_test', help='Topic')
args = ap.parse_args()
```

The code above initializes an `argparse.ArgumentParser()` object to parse
the incoming command line arguments. The arguments for the publisher will be
one positional argument, `config`, which will be the pointer to a JSON
file configuration for the message bus, and one optional argument, `--topic`,
which will give us the topic string under which to publish messages.

It is important to note at this point that a JSON configuration is going to be
used for the publisher, however, this is not required of an application using
the Python binding. The EII Message Bus Python API requires that a Python
`dict` object be used to configure the bus. For ease of use, JSON has been
used in this example.

Next we will load our configuration Python dictionary from the given JSON file.

```python
with open(args.config, 'r') as f:
    config = json.load(f)
```

Next we will initialize our message bus context object.

```python
print('[INFO] Initializing message bus context')
msgbus = mb.MsgbusContext(config)
```

The message bus context object is the object that will be used for initializing
all of the publisher, subscribers, services, and service requesters in your
application. However, what you are able to initialize via the context is
dependent on the configuration used during initialization.

Now, lets initailize our publisher.

```python
print(f'[INFO] Initializing publisher for topic \'{args.topic}\'')
publisher = msgbus.new_publisher(args.topic)
```

The message bus context object contains a method called, `new_publisher()`.
This method creates a new publisher object for the topic it is given. Once
this publisher object is obtained, the application can start publishing
messages (as shown below).

```python
print('[INFO] Running...')
while True:
    publisher.publish(({'hello': 123}, b'HELLO',))
    time.sleep(1)
```

The `publisher.publish()` method called above publishes the given values on the
topic given during the `new_publisher()` call. The `publish()` method can be
called one of three ways:

1. `publisher.publish({'hello': 123'})` - Publishes a JSON blob for the dictionary
2. `publisher.publish(b'HELLO')` - Publishes the arbitrary binary blob it was given
3. `publisher.publish(({'hello': 123}, b'HELLO',))` - Publishes the dictionary and blob together

The publisher object has a `close()` method which MUST be called on it prior to
the exit of your application. If this method is not called, then you application
may hang indefinitley. In order to make sure this happens, we'll wrap all of the
code in a `try...finally...` block in Python. Note that this is just the solution
for this simple application. Other applications may need to get more creative
in making sure the `close()` method is called.

When its all put together, the code looks as follows:

```python
import time
import json
import argparse
import eii.msgbus as mb

# Argument parsing
ap = argparse.ArgumentParser()
ap.add_argument('config', help='JSON configuration')
ap.add_argument('-t', '--topic', default='publish_test', help='Topic')
args = ap.parse_args()

with open(args.config, 'r') as f:
    config = json.load(f)

msgbus = None
publisher = None

try:
    print('[INFO] Initializing message bus context')
    msgbus = mb.MsgbusContext(config)

    print(f'[INFO] Initializing publisher for topic \'{args.topic}\'')
    publisher = msgbus.new_publisher(args.topic)

    print('[INFO] Running...')
    while True:
        publisher.publish(({'hello': 123}, b'HELLO',))
        time.sleep(1)
except KeyboardInterrupt:
    print('[INFO] Quitting...')
finally:
    if publisher is not None:
        publisher.close()
```

> **NOTE:** This code is provided in `python/examples/publisher.py` in the EII
> Message Bus source code.

#### Request/Response

To start, we will create a script named, `publisher.py`. To start, we will
add a few necessary imports which will be utilized later in the tutorial.

```python
import os
import time
import json
import argparse
import eii.msgbus as mb
```

The last line of the imports above is where we import the EII Message Bus
Python binding, which for sake of clarity will be referenced as `mb` in all
of the code to follow.

Next, we will add some more boilerplate code for parsing command line
arguments.

```python
# Argument parsing
ap = argparse.ArgumentParser()
ap.add_argument('config', help='JSON configuration')
ap.add_argument('-t', '--topic', default='publish_test', help='Topic')
args = ap.parse_args()
```

The code above initializes an `argparse.ArgumentParser()` object to parse
the incoming command line arguments. The arguments for the publisher will be
one positional argument, `config`, which will be the pointer to a JSON
file configuration for the message bus, and one optional argument, `--topic`,
which will give us the topic string under which to publish messages.

It is important to note at this point that a JSON configuration is going to be
used for the publisher, however, this is not required of an application using
the Python binding. The EII Message Bus Python API requires that a Python
`dict` object be used to configure the bus. For ease of use, JSON has been
used in this example.

Next we will load our configuration Python dictionary from the given JSON file.

```python
with open(args.config, 'r') as f:
    config = json.load(f)
```

Next we will initialize our message bus context object.

```python
print('[INFO] Initializing message bus context')
msgbus = mb.MsgbusContext(config)
```

The message bus context object is the object that will be used for initializing
all of the publisher, subscribers, services, and service requesters in your
application. However, what you are able to initialize via the context is
dependent on the configuration used during initialization.

Now, lets initailize our publisher.

```python
print(f'[INFO] Initializing publisher for topic \'{args.topic}\'')
publisher = msgbus.new_publisher(args.topic)
```

The message bus context object contains a method called, `new_publisher()`.
This method creates a new publisher object for the topic it is given. Once
this publisher object is obtained, the application can start publishing
messages (as shown below).

```python
print('[INFO] Running...')
while True:
    publisher.publish(({'hello': 123}, b'HELLO',))
    time.sleep(1)
```

The `publisher.publish()` method called above publishes the given values on the
topic given during the `new_publisher()` call. The `publish()` method can be
called one of three ways:

1. `publisher.publish({'hello': 123'})` - Publishes a JSON blob for the dictionary
2. `publisher.publish(b'HELLO')` - Publishes the arbitrary binary blob it was given
3. `publisher.publish(({'hello': 123}, b'HELLO',))` - Publishes the dictionary and blob together

The publisher object has a `close()` method which MUST be called on it prior to
the exit of your application. If this method is not called, then you application
may hang indefinitley. In order to make sure this happens, we'll wrap all of the
code in a `try...finally...` block in Python. Note that this is just the solution
for this simple application. Other applications may need to get more creative
in making sure the `close()` method is called.

When its all put together, the code looks as follows:

```python
import time
import json
import argparse
import eii.msgbus as mb

# Argument parsing
ap = argparse.ArgumentParser()
ap.add_argument('config', help='JSON configuration')
ap.add_argument('-t', '--topic', default='publish_test', help='Topic')
args = ap.parse_args()

with open(args.config, 'r') as f:
    config = json.load(f)

msgbus = None
publisher = None

try:
    print('[INFO] Initializing message bus context')
    msgbus = mb.MsgbusContext(config)

    print(f'[INFO] Initializing publisher for topic \'{args.topic}\'')
    publisher = msgbus.new_publisher(args.topic)

    print('[INFO] Running...')
    while True:
        publisher.publish(({'hello': 123}, b'HELLO',))
        time.sleep(1)
except KeyboardInterrupt:
    print('[INFO] Quitting...')
finally:
    if publisher is not None:
        publisher.close()
```

> **NOTE:** This code is provided in `python/examples/publisher.py` in the EII
> Message Bus source code.

Now that the publisher script is finished, we will create the subscriber script
called `subscriber.py`. The script will essentially be the same as the publiser
script, except that instead of calling `new_publisher()` we will call
`new_subscriber()`.

```python
import time
import json
import argparse
import eii.msgbus as mb

# Argument parsing
ap = argparse.ArgumentParser()
ap.add_argument('config', help='JSON configuration')
ap.add_argument('-t', '--topic', default='publish_test', help='Topic')
args = ap.parse_args()

msgbus = None
subscriber = None

with open(args.config, 'r') as f:
    config = json.load(f)

try:
    print('[INFO] Initializing message bus context')
    msgbus = mb.MsgbusContext(config)

    print(f'[INFO] Initializing subscriber for topic \'{args.topic}\'')
    subscriber = msgbus.new_subscriber(args.topic)

    print('[INFO] Running...')
    while True:
        msg = subscriber.recv()
        if msg is not None:
            print(f'[INFO] RECEIVED: {msg}')
        else:
            print('[INFO] Receive interrupted')
except KeyboardInterrupt:
    print('[INFO] Quitting...')
finally:
    if subscriber is not None:
        subscriber.close()
```

> **NOTE:** This code is provided in `python/examples/subscriber.py` in the EII
> Message Bus source code.

As can be seen in the code above, the `msgbus.new_publisher()` call has now
been replace with: `msgbus.new_subscriber()`. This call connects to the given
topic to receive publications. Depending on the underlying protocol that the
message bus is configured to use different values will be retrieved from the
configuration to accomplish the creation of the subscriber.

For instance, if you are using the ZeroMQ TCP protocol, then it will be
required that the configuration contains a key for the topic given to the
`msgbus.new_subscriber()` function call. For the purposes of this tutorial,
if the topic is the default topic (`publish_test`), then the configuration
must contain a JSON object similar to the following:

```json
{
    "type": "zmq_tcp",
    "publish_test": {
        "host": "127.0.0.1",
        "port": 3000
        }
    }
}
```

The other major difference between the `publisher.py` and `subscriber.py`
scripts is in the while loop at the end. In the `subscriber.py` script you'll
see that there is a call to `subscriber.recv()`. This method waits to receive
an incoming publication on the subscriber's topic. The `recv()` method has
three ways of being called.

1. `recv()`/`recv(-1)` - Blocks indefinitley until a new message is received.
2. `recv(0)` - Returns immediates if not message has been received.
3. `recv(timeout)` - Waits for the specified timeout to receive a message. `timeout`
    is assumed to be an integer that represents the time to wait in milliseconds.

To put this all together we need to first define the configuration we are going
to load for the publisher and subscriber. We will use the configuration below
saved to the file `ipc_config.json`.

```json
{
    "type": "zmq_ipc",
    "socket_dir": "/tmp"
}
```

Using this configuration will configure the message bus to use the ZeroMQ IPC
protocol and to save the Unix socket files into the `/tmp` directory on your
system.

Once this configuration is saved to the file `ipc_config.json`, start the
publisher in one Terminal window with the following command:

```sh
$ python3 publisher.py ipc_config.json
```

Next, start the subscriber in a different Terminal window with the command
shown below.

```sh
$ python3 subscriber.py ipc_config.json
```

At this point you should see the messages being published by the publisher
being printed to the console by the subscriber.

#### Request/Response

### Go Tutorial

#### Publish/Subscribe

#### Request/Response

## EII Message Bus Development

This section covers various instructions and tutorials for developing new
features for the EII Message Bus library. It does not cover how to use the
message bus or its APIs, that is covered in previous sections.

### Developing Protocols

#### Overview

Protocols are at the bottom most layer of the EII Message Bus stack. They
provide the implementation for the messaging primitives supported by the
EII Message Bus. The main tasks expected of a protocol are as follows:

1. Initialize the state of the underlying message library (i.e. ZeroMQ, DDS, etc.)
2. Implement methods for initializing contexts for publishers, subscribers,
    services, and service requesters
3. Implement base methods for sending messages from publishers, services, and
    service requesters
4. Implement base methods for receiving messages as blocking, non-blocking, and
    time out base function calls
5. Provide the translation between the underlying messaging library's messsage
    structure to the EII Message Bus's `msg_envelope_t` structure

All protocols must have a unique protocol name which the EII Message Bus can
use to load the protocol based on the `type` configuration value it is provided.
For example, the ZeroMQ TCP protocol uses the identifier `zmq_tcp`. Using this
type name, the EII Message Bus knows how to load the protocol in the
`msgbus_initialize()` method.

The EII Message Bus has the ability to dynamically load protocol plugins. It
does this by searching the system's `LD_LIBRARY_PATH` environmental variable
for a library following the naming scheme, "lib{TYPE}.so", where, "{TYPE}", is
the value retrieved from the `type` configuration key.

Once it has found the library, it calls `dlopen()` on the shared object and
extracts the `PROTO_EXPORTS` symbol from the binary. The `PROTO_EXPORTS` symbol
must be a global of the `protocol_exports_t` structure. This structure contains
a single function pointer `initialize()` which points to the initialization
function of the protocol plugin. The initialization function is responsible for
creating and populating the `protocol_t` structure.

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
protocol to the EII Message Bus, including the ideal code structure for the C
source code file.

The code will be split into a single header and C source file, `example.h` and
`example.c` respectively.

The header file is shown below. The `protocol.h` header file in the EII Message
Bus includes a helpful macro for generating all of the function prototypes
needed for a protocol. The usage of this is shown in the code below.

```c
// C include guards to prevent multiple definition from files including the
// header
#ifndef _EII_MESSAGE_BUS_EXAMPLE_H
#define _EII_MESSAGE_BUS_EXAMPLE_H

// Add extern C declaration if the code is being included from C++ code
#ifdef __cplusplus
extern "C" {
#endif

// Include the protocol.h to get the protocol_t and config_t structure
// definitions
#include <eii/msgbus/protocol.h>

/**
 * The following macro generates all of the necessary function prototypes for
 * initialization and all of the messaging primitives. In addition, it adds the
 * `PROTO_EXPORTS` symbol as well.
 */
EII_MSGBUS_PROTO(example)

#ifdef __cplusplus
}
#endif

#endif // _EII_MESSAGE_BUS_EXAMPLE_H
```

The `EII_MSGBUS_PROTO()` macro in the code above creates function prototypes of
the structure:

```
proto_<NAME>_<METHOD>()
```

Where `<NAME>` is the string given to the macro and `<METHOD>` is the protocol
function which must be implemented using the desired networking library.

The macro also creates a function called `proto_<NAME>_initialize()`, which
is used to create the context for a given protocol plugin.

In addition to this, it adds the `PROTO_EXPORTS` symbol mentioned before
and points the initialization function to the correct value in the structure.
This means, that the macro will generate a line of code that looks as
follows:

```c
protocol_exports_t PROTO_EXPORTS = { .initialize=proto_example_initialize };
```

Once you have your header defined, you must implement the corresponding C
code for the function prototypes generated by the macro.

The code below is an example of a stubbed out implementation of all of the
functions generated by the protocol macro.

```c
// Standard C includes
#include <stdlib.h>

// Include the logger.h for helper logging macros
#include <eii/utils/logger.h>

// Include the example.h header file
#include "eii/msgbus/example.h"

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

#### Adding a New Protocol

This section will cover how to add an example dummy protcol to the EII
Message Bus.

#### `protocol_t` Function Definition

The following describes the purpose of each of the function pointers above.

##### `destroy()`

Responsible for destroying the `proto_ctx` variable and freeing any memory
used by the context.

##### `publisher_new()`

Initializes a new publisher context for the given `topic`.

##### `publisher_publish()`

Publishes the given message value using the publisher context.

##### `publisher_destroy()`

Destroys a context for a publisher freeing any sockets, memory, etc. used by
the publisher.

##### `subscriber_new()`

Subscribe to the given topic and output a `recv_ctx_t` to use with the `recv_*`
methods to receive the publications for the topic.

##### `service_new()`

Create a new `recv_ctx_t` structure which can be used to received requests
from clients and send responses to received requests using the `response()`
method.

##### `service_get()`

Create a new `recv_ctx_t` structure which can be used to issue requests to and
received responses from the specified service.

##### `recv_ctx_destroy()`

Destroy a `recv_ctx_t` structure.

##### `request()`

Issue a request to the service using the given `recv_ctx_t`.

##### `response()`

Send a response to a requesting client using the given `recv_ctx_t` structure.

##### `recv_wait()`

Blocking function for receiving a message from a `recv_ctx_t` context structure.

##### `recv_timedwait()`

Function for receiving messages from a `recv_ctx_t` context structure which
times out after the given timeout. The timeout shall always be milliseconds.

##### `recv_nowait()`

Receive a message from a `recv_ctx_t` context structure if a message is available,
otherwise return immediately.
