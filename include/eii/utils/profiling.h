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
 * @brief C++ Profiling Library
 */

#ifndef _EII_UTILS_PROFILING_H
#define _EII_UTILS_PROFILING_H

#include <chrono>
#include <string>
#include <eii/msgbus/msg_envelope.h>
#include <eii/utils/config.h>
#include <eii/utils/logger.h>

namespace eii {
namespace utils {

class Profiling {
private:
    // flag for if profiling enabled
    bool m_profiling_enabled;

public:
    /**
     * Constructor which reads the profiling mode value from env variable,
     * converts it to lower case & stores in member variable to be used
     * the clients who create Profiling objects.
     * */
    Profiling();

    /**
     * Check if profiling is enabled or not.
     *
     * @return bool
     */
    bool is_profiling_enabled();

    /**
     * Add a profiling timestamp to the given meta data message envelope.
     *
     * This method reads the current time as no. of miliseconds since epoch,
     * then * converts it to int64_t format and adds the value to the given
     * @c msg_envelope_t.
     *
     * @param meta - Message envelope to add the timestamp to
     * @param key - Key for the timestamp to be added
     */
    void add_profiling_ts(msg_envelope_t* meta_data, const char* key);

    /**
     * Utility function to be used to get the current time since epoch in
     * miliseconds as an int64_t.
     *
     * @return int64_t
     */
    int64_t get_curr_time_as_int_epoch();
};

//Macros for ease of use by calling modules
#define DO_PROFILING(profile, meta, ts_key) \
    if(profile->is_profiling_enabled()) { \
        profile->add_profiling_ts(meta, ts_key); \
    }

}  // namespace utils
}  // namespace eii

#endif
