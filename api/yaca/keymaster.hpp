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

#pragma once

#include <vector>
#include <stdint.h>
#include <keymaster_defs.h>


using Data = std::vector<uint8_t>;
using AuthData = std::vector<keymaster_key_param_t>;

keymaster_error_t build_wrapped_key(const Data& transit_key, const Data& iv,
                                    const keymaster_key_format_t key_format,
                                    const Data& secure_key, const Data& tag,
                                    const AuthData& auth_data,
                                    Data* der_wrapped_key);

keymaster_error_t parse_wrapped_key(const Data& wrapped_key, Data* iv,
                                    Data* transit_key, Data* secure_key,
                                    Data* tag, AuthData* auth_data,
                                    keymaster_key_format_t* key_format,
                                    Data* wrapped_key_description);
