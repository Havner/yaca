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

#include <yaca/yaca_error.h>
#include <yaca/yaca_crypto.h>

#include "yaca_custom.hpp"


namespace keymaster {

keymaster_blob_t KeymasterBlob(const uint8_t *data, size_t length)
{
	int e;
	keymaster_blob_t ret = {nullptr, 0};
	e = yaca_malloc(length, (void**)&ret.data);
	if (e != YACA_ERROR_NONE)
		return ret;

	memcpy((void*)ret.data, data, length);
	ret.data_length = length;
	return ret;
}

keymaster_key_blob_t KeymasterKeyBlob(const uint8_t *data, size_t length)
{
	int e;
	keymaster_key_blob_t ret = {nullptr, 0};
	e = yaca_malloc(length, (void**)&ret.key_material);
	if (e != YACA_ERROR_NONE)
		return ret;

	memcpy((void*)ret.key_material, data, length);
	ret.key_material_size = length;
	return ret;
}

bool KeymasterKeyBlobPreAllocate(keymaster_key_blob_t *blob, size_t length)
{
	int e = yaca_malloc(length, (void**)&blob->key_material);
	if (e != YACA_ERROR_NONE)
		return false;

	blob->key_material_size = length;
	return true;
}

bool AuthSet::empty() const
{
	return data.empty();
}

bool AuthSet::push_back(keymaster_key_param_t elem)
{
	try {
		data.push_back(elem);
	} catch (std::exception) {
		return false;
	}

	return true;
}

}  // namespace keymaster
