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
 * @file
 * @brief Utility function for using a JSON file as the mesage bus config
 * @author Kevin Midkiff (kevin.midkiff@intel.com)
 */

#ifndef _EIS_MESSAGE_BUS_JSON_CONFIG_H
#define _EIS_MESSAGE_BUS_JSON_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

#include "eis/msgbus/msgbus.h"

/**
 * Create a configuration object for the EIS message bus which pulls config
 * values from the given JSON file.
 *
 * \note Will return NULL if an error is encountered.
 *
 * @param config_file - Path to the JSON configuration file
 * @return config_t
 */
config_t* msgbus_json_config_new(const char* config_file);

#ifdef __cplusplus
}
#endif

#endif // _EIS_MESSAGE_BUS_JSON_CONFIG_H
