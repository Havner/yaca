/*
 *  Copyright (c) 2016-2020 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Krzysztof Jackiewicz <k.jackiewicz@samsung.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */

/**
 * @file debug.h
 * @brief
 */

#ifndef YACA_DEBUG_H
#define YACA_DEBUG_H


#include <openssl/err.h>

#include <yaca_error.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef void (*yaca_error_cb)(const char*);
void yaca_debug_set_error_cb(yaca_error_cb cb);

const char *yaca_debug_translate_error(yaca_error_e err);

#define ERROR_CLEAR() ERR_clear_error()

void error_dump(const char *file, int line, const char *function, int code);
#define ERROR_DUMP(code) error_dump(__FILE__, __LINE__, __func__, (code))

/**
 * Function responsible for translating the openssl error to yaca error and
 * clearing/dumping the openssl error queue. Use only after openssl function
 * failure.
 *
 * The function checks only first error in the queue. If the function doesn't
 * find any error in openssl queue or is not able to translate it, it will
 * return YACA_ERROR_INTERNAL and dump openssl errors if any. If the
 * translation succeeds the function will clear the error queue and return the
 * result of translation.
 */
int error_handle(const char *file, int line, const char *function);
#define ERROR_HANDLE() error_handle(__FILE__, __LINE__, __func__)


#ifdef __cplusplus
} /* extern */
#endif


#endif /* YACA_DEBUG_H */
