/*
 * Copyright 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <openssl/asn1t.h>
#include <memory>
#include <vector>
#include <keymaster.hpp>

#include "yaca_custom.hpp"
#include "wrapped_key.hpp"


namespace keymaster {

IMPLEMENT_ASN1_FUNCTIONS(KM_WRAPPED_KEY_DESCRIPTION)
IMPLEMENT_ASN1_FUNCTIONS(KM_WRAPPED_KEY)

struct KM_WRAPPED_KEY_Delete {
	void operator()(KM_WRAPPED_KEY* p) { KM_WRAPPED_KEY_free(p); }
};

struct KM_WRAPPED_KEY_DESCRIPTION_Delete {
	void operator()(KM_WRAPPED_KEY_DESCRIPTION* p) { KM_WRAPPED_KEY_DESCRIPTION_free(p); }
};

} // namespace keymaster


// CUSTOM PUBLIC:
#define API __attribute__ ((visibility("default")))

using namespace keymaster;

// DER encode a wrapped key for secure import
API keymaster_error_t build_wrapped_key(const Data& transit_key, const Data& iv,
                                        const keymaster_key_format_t key_format,
                                        const Data& secure_key, const Data& tag,
                                        const AuthData& auth_data,
                                        Data* der_wrapped_key)
{
	AuthSet auth_set(auth_data);

	std::unique_ptr<KM_WRAPPED_KEY, KM_WRAPPED_KEY_Delete> wrapped_key(KM_WRAPPED_KEY_new());
	if (!wrapped_key.get()) return KM_ERROR_MEMORY_ALLOCATION_FAILED;

	if (!ASN1_OCTET_STRING_set(wrapped_key->transit_key, transit_key.data(),
	                           transit_key.size()) ||
	    !ASN1_OCTET_STRING_set(wrapped_key->iv, iv.data(), iv.size()) ||
	    !ASN1_OCTET_STRING_set(wrapped_key->secure_key, secure_key.data(),
	                           secure_key.size()) ||
	    !ASN1_OCTET_STRING_set(wrapped_key->tag, tag.data(), tag.size()) ||
	    !ASN1_INTEGER_set(wrapped_key->wrapped_key_description->key_format, key_format)) {
		return TranslateLastOpenSslError();
	}

	auto err = build_auth_list(auth_set, wrapped_key->wrapped_key_description->auth_list);
	if (err != KM_ERROR_OK) {
		return err;
	}

	int len = i2d_KM_WRAPPED_KEY(wrapped_key.get(), nullptr);
	if (len < 0) {
		return TranslateLastOpenSslError();
	}
	try {
		der_wrapped_key->resize(len);
	} catch (std::exception) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	uint8_t* p = const_cast<uint8_t*>(der_wrapped_key->data());
	len = i2d_KM_WRAPPED_KEY(wrapped_key.get(), &p);
	if (len < 0) {
		return TranslateLastOpenSslError();
	}

	return KM_ERROR_OK;
}

// Parse the DER-encoded wrapped key format
API keymaster_error_t parse_wrapped_key(const Data& wrapped_key, Data* iv,
                                        Data* transit_key, Data* secure_key,
                                        Data* tag, AuthData* auth_data,
                                        keymaster_key_format_t* key_format,
                                        Data* wrapped_key_description)
{
	AuthSet auth_list;

	if (!iv || !transit_key || !secure_key || !tag || !auth_data || !key_format ||
	    !wrapped_key_description) {
		return KM_ERROR_UNEXPECTED_NULL_POINTER;
	}

	const uint8_t* tmp = wrapped_key.data();
	std::unique_ptr<KM_WRAPPED_KEY, KM_WRAPPED_KEY_Delete> record(
		d2i_KM_WRAPPED_KEY(nullptr, &tmp, wrapped_key.size()));
	if (!record.get()) return TranslateLastOpenSslError();

	try {
		iv->assign(record->iv->data,
		           record->iv->data + record->iv->length);

		transit_key->assign(record->transit_key->data,
		                    record->transit_key->data + record->transit_key->length);

		secure_key->assign(record->secure_key->data,
		                   record->secure_key->data + record->secure_key->length);

		tag->assign(record->tag->data,
		            record->tag->data + record->tag->length);

		// re-serialize the wrapped key description
		int len = i2d_KM_WRAPPED_KEY_DESCRIPTION(record->wrapped_key_description, nullptr);
		if (len < 0) {
			return TranslateLastOpenSslError();
		}
		wrapped_key_description->resize(len);
	} catch (std::exception) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	uint8_t* p = const_cast<uint8_t*>(wrapped_key_description->data());
	if (i2d_KM_WRAPPED_KEY_DESCRIPTION(record->wrapped_key_description, &p) < 0) {
		return TranslateLastOpenSslError();
	}

	*key_format = static_cast<keymaster_key_format_t>(
		ASN1_INTEGER_get(record->wrapped_key_description->key_format));
	keymaster_error_t err = extract_auth_list(record->wrapped_key_description->auth_list, &auth_list);
	if (err != KM_ERROR_OK)
		return err;

	*auth_data = auth_list.data;
	return KM_ERROR_OK;
}
