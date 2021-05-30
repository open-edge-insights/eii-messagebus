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

#include "eii/utils/profiling.h"
#include <algorithm>

eii::utils::Profiling::Profiling() {
    char* prof_mode_str = getenv("PROFILING_MODE");
    if(prof_mode_str != NULL) {
        std::string prof_mode = std::string(prof_mode_str);
        std::transform(prof_mode.begin(), prof_mode.end(), prof_mode.begin(),
            [](unsigned char c){ return std::tolower(c); });

        if(prof_mode.compare(std::string("true")) == 0) {
            this->m_profiling_enabled = true;
        } else {
            this->m_profiling_enabled = false;
        }
    } else {
        // If the environmenatal variable Profiling mode is not found then
        // the default value is set to false
        this->m_profiling_enabled = false;
    }
}

bool eii::utils::Profiling::is_profiling_enabled() {
    return this->m_profiling_enabled;
}

void eii::utils::Profiling::add_profiling_ts(msg_envelope_t* meta, const char* key) {
    try {
        using namespace std::chrono;
        using time_stamp = std::chrono::time_point<std::chrono::system_clock,
                                           std::chrono::milliseconds>;
        time_stamp curr_time = std::chrono::time_point_cast<milliseconds>(system_clock::now());
        auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(curr_time);
        auto epoch = now_ms.time_since_epoch();
        auto value = std::chrono::duration_cast<std::chrono::milliseconds>(epoch);
        int64_t duration = value.count();
        msg_envelope_elem_body_t* curr_time_body = msgbus_msg_envelope_new_integer(duration);

        if (curr_time_body == NULL) {
            throw "Failed to create profiling timestamp element";
        }
        msgbus_ret_t ret = msgbus_msg_envelope_put(meta, key, curr_time_body);
        if(ret != MSG_SUCCESS) {
            throw "Failed to wrap msgBody into meta-data envelope";
        }
    } catch(const char *err) {
        LOG_ERROR("Exception: %s", err);
    } catch(std::exception& err) {
        LOG_ERROR("Exception: %s",err.what());
    } catch(...) {
        LOG_ERROR("Generic Exception Occured");
    }
}


int64_t eii::utils::Profiling::get_curr_time_as_int_epoch() {
    using namespace std::chrono;
     using time_stamp = std::chrono::time_point<std::chrono::system_clock,
                                           std::chrono::milliseconds>;
    time_stamp curr_time = std::chrono::time_point_cast<milliseconds>(system_clock::now());
    auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(curr_time);
    auto epoch = now_ms.time_since_epoch();
    auto value = std::chrono::duration_cast<std::chrono::milliseconds>(epoch);
    long duration = value.count();
    return duration;
}

