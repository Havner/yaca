/*
 *  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file error.h
 * @brief
 */

#ifndef ERROR_H
#define ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup  Error  Yet another Crypto API - error enums and debug functions.
 *
 * @{
 */

/**
 *  @brief Error enums
 */
enum __yaca_error_code {
	YACA_ERROR_INVALID_ARGUMENT   = -1,
	YACA_ERROR_NOT_IMPLEMENTED    = -2,
	YACA_ERROR_OPENSSL_FAILURE    = -3,
	YACA_ERROR_NOT_SUPPORTED      = -4,
	YACA_ERROR_TOO_BIG_ARGUMENT   = -5,
	YACA_ERROR_OUT_OF_MEMORY      = -6,
	YACA_ERROR_SIGNATURE_INVALID  = -7
};

// TODO disable debug function in release?

/**
 * @brief Debug callback type.
 */
typedef void (*yaca_debug_func)(const char*);

/**
 * @brief yaca_error_set_debug_func  Sets a current thread debug callback that will be called each
 *                                   time an internal error occurs. A NULL terminated string with
 *                                   location and description of the error will be passed as an
 *                                   argument.
 *
 * @param[in] fn                     Function to set as internal error callback.
 */
void yaca_error_set_debug_func(yaca_debug_func fn);

/**@}*/

#ifdef __cplusplus
} /* extern */
#endif

#endif /* ERROR_H */
