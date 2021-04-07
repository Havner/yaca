/*
 *  Copyright (c) 2021 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Lukasz Pawelczyk <l.pawelczyk@samsung.com>
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
 * @file
 * @brief
 */

#ifndef KEYMASTER_H
#define KEYMASTER_H

#include <stdint.h>
#include <keymaster_defs.h>


#ifdef __cplusplus
extern "C" {
#endif

/* All output data (without const) is allocated with yaca_alloc() and
 * memory ownership is transfered to the caller
 */
keymaster_error_t build_wrapped_key(const uint8_t *transit_key, const size_t transit_key_size,
                                    const uint8_t *iv, const size_t iv_size,
                                    const keymaster_key_format_t key_format,
                                    const uint8_t *secure_key, const size_t secure_key_size,
                                    const uint8_t *tag, const size_t tag_size,
                                    const keymaster_key_param_t *auth_data, const size_t auth_data_size,
                                    uint8_t **der, size_t *der_size);

/* All output data (without const) is allocated with yaca_alloc() and
 * memory ownership is transfered to the caller
 */
keymaster_error_t parse_wrapped_key(const uint8_t *der, const size_t der_size,
                                    uint8_t **iv, size_t *iv_size,
                                    uint8_t **transit_key, size_t *transit_key_size,
                                    uint8_t **secure_key, size_t *secure_key_size,
                                    uint8_t **tag, size_t *tag_size,
                                    keymaster_key_param_t **auth_data, size_t *auth_data_size,
                                    keymaster_key_format_t *key_format,
                                    uint8_t **der_desc, size_t *der_desc_size);

#ifdef __cplusplus
} /* extern */
#endif

#endif /* KEYMASTER_H */
