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

#include <tizen.h>

#ifdef __cplusplus
extern "C" {
#endif


#define TIZEN_ERROR_YACA -0x01E30000

/**
 * @defgroup  Error  Yet another Crypto API - error enums.
 *
 * @{
 */

/**
 * @brief Error enums
 *
 * @since_tizen 3.0
 */
typedef enum {
	YACA_ERROR_NONE               = TIZEN_ERROR_NONE,
	YACA_ERROR_INVALID_ARGUMENT   = TIZEN_ERROR_INVALID_PARAMETER,
	YACA_ERROR_OUT_OF_MEMORY      = TIZEN_ERROR_OUT_OF_MEMORY,

	YACA_ERROR_INTERNAL           = TIZEN_ERROR_YACA | 0x01,
	YACA_ERROR_DATA_MISMATCH      = TIZEN_ERROR_YACA | 0x02,
	YACA_ERROR_PASSWORD_INVALID   = TIZEN_ERROR_YACA | 0x03
} yaca_error_e;

/**@}*/

#ifdef __cplusplus
} /* extern */
#endif

#endif /* YACA_ERROR_H */
