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

/*
  TODO: Error enums should be placed here
 */
#ifdef __cplusplus
extern "C" {
#endif

enum __owl_error_code {
	OWL_ERROR_INVALID_ARGUMENT = -1,
	OWL_ERROR_NOT_IMPLEMENTED= -2,
	OWL_ERROR_OPENSSL_FAILURE = -3,
	OWL_ERROR_NOT_SUPPORTED = -4,
	OWL_ERROR_TOO_BIG_ARGUMENT = -5,
	OWL_ERROR_OUT_OF_MEMORY = -6
};

#ifdef __cplusplus
} /* extern */
#endif

#endif /* ERROR_H */
