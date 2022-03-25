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
 * @brief EII MessageEnvelope example using the C++ MessageEnvelope class.
 */

#include <chrono>
#include <cstring>
#include <csignal>
#include <vector>
#include "eii/msgbus/msg_envelope.hpp"

using namespace eii::msgbus;


int main(int argc, char** argv) {
    bool result = false;

    // Create MsgEnvelope
    MsgEnvelope* msgEnv = new MsgEnvelope(CT_JSON);

    // Create MsgEnvelopeObject & MsgEnvelopeList
    MsgEnvelopeObject* msgEnvObj = new MsgEnvelopeObject();
    MsgEnvelopeList* msgEnvArr = new MsgEnvelopeList();

    // Create MsgEnvelopeObject to add into MsgEnvelopeList
    MsgEnvelopeObject* msgEnvArrObj = new MsgEnvelopeObject();

    try {
        // Add test (key, value) pairs to MsgEnvelopeObject
        msgEnvObj->put_bool("objBool", true);
        msgEnvObj->put_string("objStrng", "msgEnvObj_string_test");
        msgEnvObj->put_integer("objInt", 1);
        msgEnvObj->put_float("objFloat", 1.45);

        int64_t int_value = msgEnvObj->get_int("objInt");
        std::cout << "MsgEnvelopeObject int value " << int_value << std::endl;

        double float_value = msgEnvObj->get_float("objFloat");
        std::cout << "MsgEnvelopeObject float value " << float_value << std::endl;

        std::string string_value = msgEnvObj->get_string("objStrng");
        std::cout << "MsgEnvelopeObject string value " << string_value << std::endl;

        bool bool_value = msgEnvObj->get_bool("objBool");
        std::cout << "MsgEnvelopeObject bool value " << bool_value << std::endl;

        MsgEnvelopeElement* msgEnvObjElement = msgEnvObj->get_msg_envelope_element("objFloat");
        msgEnvObjElement->get_type();

        float_value = msgEnvObjElement->to_float();
        std::cout << "MsgEnvelopeElement float value " << float_value << std::endl;

        // Add test (key, value) pairs to MsgEnvelopeList
        msgEnvArr->put_bool(true);
        msgEnvArr->put_string("msgEnvArr_string_test");
        msgEnvArr->put_integer(2);
        msgEnvArr->put_float(2.45);

        int_value = msgEnvArr->get_int(2);
        std::cout << "MsgEnvelopeList int value " << int_value << std::endl;

        float_value = msgEnvArr->get_float(3);
        std::cout << "MsgEnvelopeList float value " << float_value << std::endl;

        string_value = msgEnvArr->get_string(1);
        std::cout << "MsgEnvelopeList string value " << string_value << std::endl;

        bool_value = msgEnvArr->get_bool(0);
        std::cout << "MsgEnvelopeList bool value " << bool_value << std::endl;

        MsgEnvelopeElement* msgEnvArrElement = msgEnvArr->get_msg_envelope_element(0);
        msgEnvArrElement->get_type();

        bool_value = msgEnvArrElement->to_bool();
        std::cout << "MsgEnvelopeElement bool value " << bool_value << std::endl;

        // Add test (key, value) pairs to MsgEnvelope
        msgEnv->put_bool("Bool", true);
        msgEnv->put_string("Strng", "string_test");
        msgEnv->put_integer("Int", 3);
        msgEnv->put_float("Float", 3.45);

        // put_vector example
        std::vector<int> nums;
        nums.push_back(1);
        nums.push_back(2);
        nums.push_back(3);
        msgEnv->put_vector("IntVector", nums);

        // put_vector example
        std::vector<double> floats;
        floats.push_back(1.4);
        floats.push_back(2.5);
        floats.push_back(3.6);
        msgEnv->put_vector("FloatVector", floats);

        // put_vector example
        std::vector<bool> bools;
        bools.push_back(true);
        bools.push_back(false);
        msgEnv->put_vector("BoolVector", bools);

        int_value = msgEnv->get_int("Int");
        std::cout << "MsgEnvelope int value " << int_value << std::endl;

        float_value = msgEnv->get_float("Float");
        std::cout << "MsgEnvelope float value " << float_value << std::endl;

        string_value = msgEnv->get_string("Strng");
        std::cout << "MsgEnvelope string value " << string_value << std::endl;

        bool_value = msgEnv->get_bool("Bool");
        std::cout << "MsgEnvelope bool value " << bool_value << std::endl;

        MsgEnvelopeElement* msgEnvElement = msgEnv->get_msg_envelope_element("Int");
        msgEnvElement->get_type();

        int_value = msgEnvElement->to_int();
        std::cout << "MsgEnvelopeElement int value " << int_value << std::endl;

        // Add blob to MsgEnvelope
        char* data = (char*) malloc(sizeof(char) * 7);
        memcpy(data, "HELLO1", 7);
        msgEnv->put_blob(data, 7);

        // msgbus_msg_envelope_print(msgEnv->get_msg_envelope(), true, false);

        msgEnvObj->remove("objFloat");

        // msgbus_msg_envelope_print(msgEnv->get_msg_envelope(), true, false);

        // Add MsgEnvelopeObject to MsgEnvelope
        msgEnv->put_object("object_test", msgEnvObj);

        // msgbus_msg_envelope_print(msgEnv->get_msg_envelope(), true, true);

        // Add test (key, value) pairs to MsgEnvelopeObject
        msgEnvArrObj->put_bool("ArrObjBool", true);
        msgEnvArrObj->put_string("ArrObjStrng", "string_test");
        msgEnvArrObj->put_integer("ArrObjInt", 1);
        msgEnvArrObj->put_float("ArrObjFloat", 1.45);

        // Add MsgEnvelopeObject to MsgEnvelopeList
        msgEnvArr->put_object(msgEnvArrObj);

        // msgbus_msg_envelope_print(msgEnv->get_msg_envelope(), true, false);

        // msgEnvArr->remove_at(3);

        // msgbus_msg_envelope_print(msgEnv->get_msg_envelope(), true, false);

        // Add MsgEnvelopeList to MsgEnvelope
        msgEnv->put_array("array_test", msgEnvArr);

        // msgbus_msg_envelope_print(msgEnv->get_msg_envelope(), true, false);

        // msgEnv->remove("Float");

        msgbus_msg_envelope_print(msgEnv->get_msg_envelope(), true, false);
    } catch (const std::exception& MsgbusException) {
        std::cout << MsgbusException.what() << std::endl;
    }

    delete msgEnv;
    delete msgEnvObj;
    delete msgEnvArr;

    return 0;
}
