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
#include <keymaster.h>
#include <keymaster.hpp>
#include <yaca_crypto.h>

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

API keymaster_error_t build_wrapped_key(const uint8_t *transit_key, const size_t transit_key_size,
                                        const uint8_t *iv, const size_t iv_size,
                                        const keymaster_key_format_t key_format,
                                        const uint8_t *secure_key, const size_t secure_key_size,
                                        const uint8_t *tag, const size_t tag_size,
                                        const keymaster_key_param_t *auth_data, const size_t auth_data_size,
                                        uint8_t **der, size_t *der_size)
{
	if (transit_key == nullptr || transit_key_size == 0 || iv == nullptr || iv_size == 0 ||
	    secure_key == nullptr || secure_key_size == 0 || tag == nullptr || tag_size == 0 ||
	    auth_data == nullptr || auth_data == 0 || auth_data_size == 0 ||
	    der == nullptr || der_size == nullptr)
		return KM_ERROR_INVALID_ARGUMENT;

	keymaster_error_t km_ret;
	int ret;

	const Data v_transit_key(transit_key, transit_key + transit_key_size);
	const Data v_iv(iv, iv + iv_size);
	const Data v_secure_key(secure_key, secure_key + secure_key_size);
	const Data v_tag(tag, tag + tag_size);
	const AuthData v_auth_data(auth_data, auth_data + auth_data_size);
	Data v_der;

	km_ret = build_wrapped_key(v_transit_key, v_iv, key_format, v_secure_key,
	                           v_tag, v_auth_data, &v_der);
	if (km_ret != KM_ERROR_OK)
		return km_ret;

	ret = yaca_malloc(v_der.size(), (void**)der);
	if (ret != YACA_ERROR_NONE)
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	*der_size = v_der.size();
	memcpy(*der, v_der.data(), v_der.size());

	return KM_ERROR_OK;

}

API keymaster_error_t parse_wrapped_key(const uint8_t *der, const size_t der_size,
                                        uint8_t **iv, size_t *iv_size,
                                        uint8_t **transit_key, size_t *transit_key_size,
                                        uint8_t **secure_key, size_t *secure_key_size,
                                        uint8_t **tag, size_t *tag_size,
                                        keymaster_key_param_t **auth_data, size_t *auth_data_size,
                                        keymaster_key_format_t *key_format,
                                        uint8_t **der_desc, size_t *der_desc_size)
{
	if (der == nullptr || der_size == 0 || iv == nullptr || iv_size == nullptr ||
	    transit_key == nullptr || transit_key_size == nullptr ||
	    secure_key == nullptr || secure_key_size == nullptr ||
	    tag == nullptr || tag_size == nullptr || auth_data == nullptr || auth_data_size == nullptr ||
	    key_format == nullptr || der_desc == nullptr || der_desc_size == nullptr)
		return KM_ERROR_INVALID_ARGUMENT;

	keymaster_error_t km_ret;
	int ret;

	const Data v_der(der, der + der_size);
	Data v_iv, v_transit_key, v_secure_key, v_tag, v_der_desc;
	AuthData v_auth_data;

	km_ret = parse_wrapped_key(v_der, &v_iv, &v_transit_key, &v_secure_key, &v_tag,
	                           &v_auth_data, key_format, &v_der_desc);
	if (km_ret != KM_ERROR_OK)
		return km_ret;

	*iv = *transit_key = *secure_key = *tag = *der_desc = nullptr;
	*auth_data = nullptr;

	km_ret = KM_ERROR_MEMORY_ALLOCATION_FAILED;

	ret = yaca_malloc(v_iv.size(), (void**)iv);
	if (ret != YACA_ERROR_NONE) goto err;
	ret = yaca_malloc(v_transit_key.size(), (void**)transit_key);
	if (ret != YACA_ERROR_NONE) goto err;
	ret = yaca_malloc(v_secure_key.size(), (void**)secure_key);
	if (ret != YACA_ERROR_NONE) goto err;
	ret = yaca_malloc(v_tag.size(), (void**)tag);
	if (ret != YACA_ERROR_NONE) goto err;
	ret = yaca_malloc(v_der_desc.size(), (void**)der_desc);
	if (ret != YACA_ERROR_NONE) goto err;
	ret = yaca_malloc(v_auth_data.size() * sizeof(keymaster_key_param_t), (void**)auth_data);
	if (ret != YACA_ERROR_NONE) goto err;

	*iv_size = v_iv.size();
	*transit_key_size = v_transit_key.size();
	*secure_key_size = v_secure_key.size();
	*tag_size = v_tag.size();
	*der_desc_size = v_der_desc.size();
	*auth_data_size = v_auth_data.size();

	memcpy(*iv, v_iv.data(), v_iv.size());
	memcpy(*transit_key, v_transit_key.data(), v_transit_key.size());
	memcpy(*secure_key, v_secure_key.data(), v_secure_key.size());
	memcpy(*tag, v_tag.data(), v_tag.size());
	memcpy(*der_desc, v_der_desc.data(), v_der_desc.size());
	memcpy(*auth_data, v_auth_data.data(), v_auth_data.size() * sizeof(keymaster_key_param_t));

	return KM_ERROR_OK;

err:
	yaca_free(*iv);
	yaca_free(*transit_key);
	yaca_free(*secure_key);
	yaca_free(*tag);
	yaca_free(*auth_data);
	yaca_free(*der_desc);

	return km_ret;
}
