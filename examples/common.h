// Copyright (c) 2020 Intel Corporation.
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
 * @brief Message bus example common utilities
 */

#ifndef EIS_MESSAGE_BUS_EXAMPLES_COMMON_H
#define EIS_MESSAGE_BUS_EXAMPLES_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <eis/utils/logger.h>
#include <safe_lib.h>

// Helper macro for checking if a string is equal to the given target and then
// setting output equal to ret and returning true if it is. This is meant to be
// used with the following two common utility functions.
#define CHECK_STR_EQ(input, target, ret, output) { \
    strcmp_s(input, strlen(target), target, &ind); \
    if (ind == 0) { \
        *output = ret; \
        return true; \
    } \
}

/**
 * Parse the given log level string.
 *
 * \note The string must be one of the following: DEBUG, INFO, WARN, ERROR
 *
 * @param[in]  log_lvl_str - Log level string to parse
 * @param[out] log_lvl     - Output log level
 * @return True if successfully parse, False if not. Errors will be logged
 *  in the method accordingly.
 */
bool parse_log_level(const char* log_lvl_str, log_lvl_t* log_lvl) {
    int ind = 0;

    // Check against all log levels
    CHECK_STR_EQ(log_lvl_str, "DEBUG", LOG_LVL_DEBUG, log_lvl);
    CHECK_STR_EQ(log_lvl_str, "INFO", LOG_LVL_INFO, log_lvl);
    CHECK_STR_EQ(log_lvl_str, "WARN", LOG_LVL_WARN, log_lvl);
    CHECK_STR_EQ(log_lvl_str, "ERROR", LOG_LVL_ERROR, log_lvl);

    // If this is reached, it means none of the log levels returned, therefore
    // this is an error and an unknown log level string.
    LOG_ERROR("Unknown log level: %s", log_lvl_str);
    return false;
}

#ifdef __cplusplus
}  // __cpluspls
#endif

#endif // EIS_MESSAGE_BUS_EXAMPLES_COMMON_H
