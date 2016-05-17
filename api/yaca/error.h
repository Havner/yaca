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

#ifndef YACA_ERROR_H
#define YACA_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup  Error  Yet another Crypto API - error enums.
 *
 * @{
 */

/**
 *  @brief Error enums
 */
enum __yaca_error_code {
	YACA_ERROR_NONE               =  0,
	YACA_ERROR_INVALID_ARGUMENT   = -1,
	YACA_ERROR_NOT_IMPLEMENTED    = -2,
	YACA_ERROR_INTERNAL           = -3,
	YACA_ERROR_TOO_BIG_ARGUMENT   = -4,
	YACA_ERROR_OUT_OF_MEMORY      = -5,
	YACA_ERROR_DATA_MISMATCH      = -6,
	YACA_ERROR_PASSWORD_INVALID   = -7
};

/**@}*/

#ifdef __cplusplus
} /* extern */
#endif

#endif /* YACA_ERROR_H */
