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
#include <yaca_crypto.h>
#include <yaca_error.h>
#include <keymaster_defs.h>

#include "tags.hpp"


namespace keymaster {

inline keymaster_error_t TranslateLastOpenSslError()
{
	return KM_ERROR_UNKNOWN_ERROR;
}

keymaster_blob_t KeymasterBlob(const uint8_t *data, size_t length);
keymaster_key_blob_t KeymasterKeyBlob(const uint8_t *data, size_t length);

bool KeymasterKeyBlobPreAllocate(keymaster_key_blob_t *blob, size_t length);

struct AuthSet {
	AuthSet() {}
	AuthSet(const std::vector<keymaster_key_param_t> &d)
		: data(d) {}
	virtual ~AuthSet() {
		// for (auto elem: data) {
		// 	if (elem.tag & KM_BIGNUM || elem.tag & KM_BYTES)
		// 		yaca_free((void*)elem.blob.data);
		// }
	}

	bool empty() const;
	bool push_back(keymaster_key_param_t elem);

	template <keymaster_tag_t Tag, keymaster_tag_type_t Type, typename KeymasterEnum>
	bool push_back(TypedEnumTag<Type, Tag, KeymasterEnum> tag, KeymasterEnum val) {
		return push_back(Authorization(tag, val));
	}

	template <keymaster_tag_t Tag> bool push_back(TypedTag<KM_BOOL, Tag> tag) {
		return push_back(Authorization(tag));
	}

	template <keymaster_tag_t Tag>
	bool push_back(TypedTag<KM_BYTES, Tag> tag, const void* bytes, size_t bytes_len) {
		uint8_t *data;
		int ret = yaca_malloc(bytes_len, (void**)&data);
		if (ret != YACA_ERROR_NONE) return false;
		memcpy(data, bytes, bytes_len);
		return push_back(keymaster_param_blob(tag, static_cast<const uint8_t*>(data), bytes_len));
	}

	// template <keymaster_tag_t Tag>
	// bool push_back(TypedTag<KM_BYTES, Tag> tag, const keymaster_blob_t& blob) {
	// 	return push_back(tag, blob.data, blob.data_length);
	// }

	template <keymaster_tag_t Tag>
	bool push_back(TypedTag<KM_BIGNUM, Tag> tag, const void* bytes, size_t bytes_len) {
		return push_back(keymaster_param_blob(tag, static_cast<const uint8_t*>(bytes), bytes_len));
	}

	template <keymaster_tag_t Tag, keymaster_tag_type_t Type>
	bool push_back(TypedTag<Type, Tag> tag, typename TypedTag<Type, Tag>::value_type val) {
		return push_back(Authorization(tag, val));
	}

	template <keymaster_tag_t Tag, keymaster_tag_type_t Type>
	bool push_back(TypedTag<Type, Tag> tag, const void* bytes, size_t bytes_len) {
		return push_back(Authorization(tag, bytes, bytes_len));
	}

	std::vector<keymaster_key_param_t> data;
};

}  // namespace keymaster
