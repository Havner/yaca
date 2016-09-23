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
 * @file   yaca_error.h
 * @brief  Error enums and defines.
 */

#ifndef YACA_ERROR_H
#define YACA_ERROR_H

#include <tizen.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup CAPI_YACA_ENCRYPTION_MODULE
 * @{
 */

/* @cond  Define it temporarily until this code goes into capi-base-common package */
#ifndef TIZEN_ERROR_YACA
#define TIZEN_ERROR_YACA -0x01E30000
#endif
/* @endcond */

/**
 * @brief Enumeration of YACA error values.
 *
 * @since_tizen 3.0
 */
typedef enum {
	/** Successful */
	YACA_ERROR_NONE               = TIZEN_ERROR_NONE,
	/** Invalid function parameter */
	YACA_ERROR_INVALID_PARAMETER  = TIZEN_ERROR_INVALID_PARAMETER,
	/** Out of memory */
	YACA_ERROR_OUT_OF_MEMORY      = TIZEN_ERROR_OUT_OF_MEMORY,

	/** Internal error */
	YACA_ERROR_INTERNAL           = TIZEN_ERROR_YACA | 0x01,
	/** Data mismatch */
	YACA_ERROR_DATA_MISMATCH      = TIZEN_ERROR_YACA | 0x02,
	/** Invalid password */
	YACA_ERROR_INVALID_PASSWORD   = TIZEN_ERROR_YACA | 0x03
} yaca_error_e;

/**
 * @}
 */

#ifdef __cplusplus
} /* extern */
#endif

#endif /* YACA_ERROR_H */
