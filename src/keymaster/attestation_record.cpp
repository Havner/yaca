/*
 * Copyright 2016 The Android Open Source Project
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

#include <assert.h>
#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <memory>

#include "openssl_utils.hpp"
#include "attestation_record.hpp"


#define ASSERT_OR_RETURN_ERROR(stmt, error)	  \
	do { \
		assert(stmt); \
		if (!(stmt)) { \
			return error; \
		} \
	} while (0)

namespace keymaster {

constexpr size_t kMaximumAttestationChallengeLength = 128;

IMPLEMENT_ASN1_FUNCTIONS(KM_ROOT_OF_TRUST)
IMPLEMENT_ASN1_FUNCTIONS(KM_AUTH_LIST)
IMPLEMENT_ASN1_FUNCTIONS(KM_KEY_DESCRIPTION)

static const keymaster_tag_t kDeviceAttestationTags[] = {
	KM_TAG_ATTESTATION_ID_BRAND,        KM_TAG_ATTESTATION_ID_DEVICE, KM_TAG_ATTESTATION_ID_PRODUCT,
	KM_TAG_ATTESTATION_ID_SERIAL,       KM_TAG_ATTESTATION_ID_IMEI,   KM_TAG_ATTESTATION_ID_MEID,
	KM_TAG_ATTESTATION_ID_MANUFACTURER, KM_TAG_ATTESTATION_ID_MODEL,
};

struct KM_AUTH_LIST_Delete {
	void operator()(KM_AUTH_LIST* p) { KM_AUTH_LIST_free(p); }
};

struct KM_KEY_DESCRIPTION_Delete {
	void operator()(KM_KEY_DESCRIPTION* p) { KM_KEY_DESCRIPTION_free(p); }
};

struct KM_ROOT_OF_TRUST_Delete {
	void operator()(KM_ROOT_OF_TRUST* p) { KM_ROOT_OF_TRUST_free(p); }
};


// Insert value in either the dest_integer or the dest_integer_set, whichever is provided.
static keymaster_error_t insert_integer(ASN1_INTEGER* value, ASN1_INTEGER** dest_integer,
                                        ASN1_INTEGER_SET** dest_integer_set) {
	ASSERT_OR_RETURN_ERROR((dest_integer == nullptr) ^ (dest_integer_set == nullptr),
	                       KM_ERROR_UNEXPECTED_NULL_POINTER);
	ASSERT_OR_RETURN_ERROR(value, KM_ERROR_INVALID_ARGUMENT);

	if (dest_integer_set) {
		if (!*dest_integer_set) {
			*dest_integer_set = sk_ASN1_INTEGER_new_null();
		}
		if (!*dest_integer_set) {
			return KM_ERROR_MEMORY_ALLOCATION_FAILED;
		}
		if (!sk_ASN1_INTEGER_push(*dest_integer_set, value)) {
			return KM_ERROR_MEMORY_ALLOCATION_FAILED;
		}
		return KM_ERROR_OK;

	} else if (dest_integer) {
		if (*dest_integer) {
			ASN1_INTEGER_free(*dest_integer);
		}
		*dest_integer = value;
		return KM_ERROR_OK;
	}

	ASSERT_OR_RETURN_ERROR(false, KM_ERROR_UNKNOWN_ERROR);  // Should never get here.
}

static uint32_t get_uint32_value(const keymaster_key_param_t& param) {
	switch (keymaster_tag_get_type(param.tag)) {
	case KM_ENUM:
	case KM_ENUM_REP:
		return param.enumerated;
	case KM_UINT:
	case KM_UINT_REP:
		return param.integer;
	default:
		ASSERT_OR_RETURN_ERROR(false, 0xFFFFFFFF);
	}
}

// Put the contents of the keymaster AuthorizationSet auth_list into the ASN.1 record structure,
// record.
keymaster_error_t build_auth_list(const AuthSet& auth_list, KM_AUTH_LIST* record) {
	ASSERT_OR_RETURN_ERROR(record, KM_ERROR_UNEXPECTED_NULL_POINTER);

	if (auth_list.empty()) return KM_ERROR_OK;

	for (auto entry : auth_list.data) {

		ASN1_INTEGER_SET** integer_set = nullptr;
		ASN1_INTEGER** integer_ptr = nullptr;
		ASN1_OCTET_STRING** string_ptr = nullptr;
		ASN1_NULL** bool_ptr = nullptr;

		switch (entry.tag) {

			/* Tags ignored because they should never exist */
		case KM_TAG_INVALID:

			/* Tags ignored because they're not used. */
		case KM_TAG_ALL_USERS:
		case KM_TAG_EXPORTABLE:
		case KM_TAG_ECIES_SINGLE_HASH_MODE:

			/* Tags ignored because they're used only to provide information to operations */
		case KM_TAG_ASSOCIATED_DATA:
		case KM_TAG_NONCE:
		case KM_TAG_AUTH_TOKEN:
		case KM_TAG_MAC_LENGTH:
		case KM_TAG_ATTESTATION_CHALLENGE:
		case KM_TAG_RESET_SINCE_ID_ROTATION:
		case KM_TAG_KDF:

			/* Tags ignored because they're used only to provide for certificate generation */
		case KM_TAG_CERTIFICATE_SERIAL:
		case KM_TAG_CERTIFICATE_SUBJECT:
		case KM_TAG_CERTIFICATE_NOT_BEFORE:
		case KM_TAG_CERTIFICATE_NOT_AFTER:

			/* Tags ignored because they have no meaning off-device */
		case KM_TAG_USER_ID:
		case KM_TAG_USER_SECURE_ID:
		case KM_TAG_BLOB_USAGE_REQUIREMENTS:

			/* Tags ignored because they're not usable by app keys */
		case KM_TAG_BOOTLOADER_ONLY:
		case KM_TAG_INCLUDE_UNIQUE_ID:
		case KM_TAG_MAX_BOOT_LEVEL:
		case KM_TAG_MAX_USES_PER_BOOT:
		case KM_TAG_MIN_SECONDS_BETWEEN_OPS:
		case KM_TAG_UNIQUE_ID:

			/* Tags ignored because they contain data that should not be exported */
		case KM_TAG_APPLICATION_DATA:
		case KM_TAG_APPLICATION_ID:
		case KM_TAG_ROOT_OF_TRUST:
			continue;

			/* Non-repeating enumerations */
		case KM_TAG_ALGORITHM:
			integer_ptr = &record->algorithm;
			break;
		case KM_TAG_EC_CURVE:
			integer_ptr = &record->ec_curve;
			break;
		case KM_TAG_USER_AUTH_TYPE:
			integer_ptr = &record->user_auth_type;
			break;
		case KM_TAG_ORIGIN:
			integer_ptr = &record->origin;
			break;

			/* Repeating enumerations */
		case KM_TAG_PURPOSE:
			integer_set = &record->purpose;
			break;
		case KM_TAG_PADDING:
			integer_set = &record->padding;
			break;
		case KM_TAG_DIGEST:
			integer_set = &record->digest;
			break;
		case KM_TAG_BLOCK_MODE:
			integer_set = &record->block_mode;
			break;
		case KM_TAG_RSA_OAEP_MGF_DIGEST:
			integer_set = &record->mgf_digest;
			break;

			/* Non-repeating unsigned integers */
		case KM_TAG_KEY_SIZE:
			integer_ptr = &record->key_size;
			break;
		case KM_TAG_AUTH_TIMEOUT:
			integer_ptr = &record->auth_timeout;
			break;
		case KM_TAG_OS_VERSION:
			integer_ptr = &record->os_version;
			break;
		case KM_TAG_OS_PATCHLEVEL:
			integer_ptr = &record->os_patchlevel;
			break;
		case KM_TAG_MIN_MAC_LENGTH:
			integer_ptr = &record->min_mac_length;
			break;
		case KM_TAG_BOOT_PATCHLEVEL:
			integer_ptr = &record->boot_patch_level;
			break;
		case KM_TAG_VENDOR_PATCHLEVEL:
			integer_ptr = &record->vendor_patchlevel;
			break;
		case KM_TAG_USAGE_COUNT_LIMIT:
			integer_ptr = &record->usage_count_limit;
			break;

			/* Non-repeating long unsigned integers */
		case KM_TAG_RSA_PUBLIC_EXPONENT:
			integer_ptr = &record->rsa_public_exponent;
			break;

			/* Dates */
		case KM_TAG_ACTIVE_DATETIME:
			integer_ptr = &record->active_date_time;
			break;
		case KM_TAG_ORIGINATION_EXPIRE_DATETIME:
			integer_ptr = &record->origination_expire_date_time;
			break;
		case KM_TAG_USAGE_EXPIRE_DATETIME:
			integer_ptr = &record->usage_expire_date_time;
			break;
		case KM_TAG_CREATION_DATETIME:
			integer_ptr = &record->creation_date_time;
			break;

			/* Booleans */
		case KM_TAG_NO_AUTH_REQUIRED:
			bool_ptr = &record->no_auth_required;
			break;
		case KM_TAG_ALL_APPLICATIONS:
			bool_ptr = &record->all_applications;
			break;
		case KM_TAG_ROLLBACK_RESISTANT:
			bool_ptr = &record->rollback_resistant;
			break;
		case KM_TAG_ROLLBACK_RESISTANCE:
			bool_ptr = &record->rollback_resistance;
			break;
		case KM_TAG_ALLOW_WHILE_ON_BODY:
			bool_ptr = &record->allow_while_on_body;
			break;
		case KM_TAG_UNLOCKED_DEVICE_REQUIRED:
			bool_ptr = &record->unlocked_device_required;
			break;
		case KM_TAG_CALLER_NONCE:
			bool_ptr = &record->caller_nonce;
			break;
		case KM_TAG_TRUSTED_CONFIRMATION_REQUIRED:
			bool_ptr = &record->trusted_confirmation_required;
			break;
		case KM_TAG_EARLY_BOOT_ONLY:
			bool_ptr = &record->early_boot_only;
			break;
		case KM_TAG_DEVICE_UNIQUE_ATTESTATION:
			bool_ptr = &record->device_unique_attestation;
			break;
		case KM_TAG_IDENTITY_CREDENTIAL_KEY:
			bool_ptr = &record->identity_credential_key;
			break;
		case KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED:
			bool_ptr = &record->trusted_user_presence_required;
			break;
		case KM_TAG_STORAGE_KEY:
			bool_ptr = &record->storage_key;
			break;

			/* Byte arrays*/
		case KM_TAG_ATTESTATION_APPLICATION_ID:
			string_ptr = &record->attestation_application_id;
			break;
		case KM_TAG_ATTESTATION_ID_BRAND:
			string_ptr = &record->attestation_id_brand;
			break;
		case KM_TAG_ATTESTATION_ID_DEVICE:
			string_ptr = &record->attestation_id_device;
			break;
		case KM_TAG_ATTESTATION_ID_PRODUCT:
			string_ptr = &record->attestation_id_product;
			break;
		case KM_TAG_ATTESTATION_ID_SERIAL:
			string_ptr = &record->attestation_id_serial;
			break;
		case KM_TAG_ATTESTATION_ID_IMEI:
			string_ptr = &record->attestation_id_imei;
			break;
		case KM_TAG_ATTESTATION_ID_MEID:
			string_ptr = &record->attestation_id_meid;
			break;
		case KM_TAG_ATTESTATION_ID_MANUFACTURER:
			string_ptr = &record->attestation_id_manufacturer;
			break;
		case KM_TAG_ATTESTATION_ID_MODEL:
			string_ptr = &record->attestation_id_model;
			break;
		case KM_TAG_CONFIRMATION_TOKEN:
			string_ptr = &record->confirmation_token;
			break;
		}

		keymaster_tag_type_t type = keymaster_tag_get_type(entry.tag);
		switch (type) {
		case KM_ENUM:
		case KM_ENUM_REP:
		case KM_UINT:
		case KM_UINT_REP: {
			ASSERT_OR_RETURN_ERROR((keymaster_tag_repeatable(entry.tag) && integer_set) ||
			                       (!keymaster_tag_repeatable(entry.tag) && integer_ptr),
			                       KM_ERROR_INVALID_TAG);

			std::unique_ptr<ASN1_INTEGER, ASN1_INTEGER_Delete> value(ASN1_INTEGER_new());
			if (!value.get()) {
				return KM_ERROR_MEMORY_ALLOCATION_FAILED;
			}
			if (!ASN1_INTEGER_set(value.get(), get_uint32_value(entry))) {
				return TranslateLastOpenSslError();
			}

			insert_integer(value.release(), integer_ptr, integer_set);
			break;
		}

		case KM_ULONG:
		case KM_ULONG_REP:
		case KM_DATE: {
			ASSERT_OR_RETURN_ERROR((keymaster_tag_repeatable(entry.tag) && integer_set) ||
			                       (!keymaster_tag_repeatable(entry.tag) && integer_ptr),
			                       KM_ERROR_INVALID_TAG);

			std::unique_ptr<BIGNUM, BIGNUM_Delete> bn_value(BN_new());
			if (!bn_value.get()) {
				return KM_ERROR_MEMORY_ALLOCATION_FAILED;
			}

			if (type == KM_DATE) {
				if (!BN_set_word(bn_value.get(), entry.date_time)) {
					return TranslateLastOpenSslError();
				}
			} else {
				if (!BN_set_word(bn_value.get(), entry.long_integer)) {
					return TranslateLastOpenSslError();
				}
			}

			std::unique_ptr<ASN1_INTEGER, ASN1_INTEGER_Delete> value(
				BN_to_ASN1_INTEGER(bn_value.get(), nullptr));
			if (!value.get()) {
				return KM_ERROR_MEMORY_ALLOCATION_FAILED;
			}

			insert_integer(value.release(), integer_ptr, integer_set);
			break;
		}

		case KM_BOOL:
			ASSERT_OR_RETURN_ERROR(bool_ptr, KM_ERROR_INVALID_TAG);
			if (!*bool_ptr) *bool_ptr = ASN1_NULL_new();
			if (!*bool_ptr) return KM_ERROR_MEMORY_ALLOCATION_FAILED;
			break;

			/* Byte arrays*/
		case KM_BYTES:
			ASSERT_OR_RETURN_ERROR(string_ptr, KM_ERROR_INVALID_TAG);
			if (!*string_ptr) {
				*string_ptr = ASN1_OCTET_STRING_new();
			}
			if (!*string_ptr) {
				return KM_ERROR_MEMORY_ALLOCATION_FAILED;
			}
			if (!ASN1_OCTET_STRING_set(*string_ptr, entry.blob.data, entry.blob.data_length)) {
				return TranslateLastOpenSslError();
			}
			break;

		default:
			return KM_ERROR_UNIMPLEMENTED;
		}
	}

	// keymaster_ec_curve_t ec_curve;
	// uint32_t key_size;
	// if (auth_list.Contains(TAG_ALGORITHM, KM_ALGORITHM_EC) &&  //
	//     !auth_list.Contains(TAG_EC_CURVE) &&                   //
	//     auth_list.GetTagValue(TAG_KEY_SIZE, &key_size)) {
	//     // This must be a keymaster1 key. It's an EC key with no curve.  Insert the curve.

	//     keymaster_error_t error = EcKeySizeToCurve(key_size, &ec_curve);
	//     if (error != KM_ERROR_OK) return error;

	//     std::unique_ptr<ASN1_INTEGER, ASN1_INTEGER_Delete> value(ASN1_INTEGER_new());
	//     if (!value.get()) {
	//         return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	//     }

	//     if (!ASN1_INTEGER_set(value.get(), ec_curve)) {
	//         return TranslateLastOpenSslError();
	//     }

	//     insert_integer(value.release(), &record->ec_curve, nullptr);
	// }

	return KM_ERROR_OK;
}

// Copy all enumerated values with the specified tag from stack to auth_list.
static bool get_repeated_enums(const ASN1_INTEGER_SET* stack, keymaster_tag_t tag,
                               AuthSet* auth_list) {
	//ASSERT_OR_RETURN_ERROR(keymaster_tag_get_type(tag) == KM_ENUM_REP, KM_ERROR_INVALID_TAG);
	for (ssize_t i = 0; i < sk_ASN1_INTEGER_num(stack); ++i) {
		if (!auth_list->push_back(
			    keymaster_param_enum(tag, ASN1_INTEGER_get(sk_ASN1_INTEGER_value(stack, i)))))
			return false;
	}
	return true;
}

// Add the specified integer tag/value pair to auth_list.
template <keymaster_tag_type_t Type, keymaster_tag_t Tag, typename KeymasterEnum>
static bool get_enum(const ASN1_INTEGER* asn1_int, TypedEnumTag<Type, Tag, KeymasterEnum> tag,
                     AuthSet* auth_list) {
	if (!asn1_int) return true;
	return auth_list->push_back(tag, static_cast<KeymasterEnum>(ASN1_INTEGER_get(asn1_int)));
}

// Add the specified ulong tag/value pair to auth_list.
static bool get_ulong(const ASN1_INTEGER* asn1_int, keymaster_tag_t tag,
                      AuthSet* auth_list) {
	if (!asn1_int) return true;
	std::unique_ptr<BIGNUM, BIGNUM_Delete> bn(ASN1_INTEGER_to_BN(asn1_int, nullptr));
	if (!bn.get()) return false;
	uint64_t ulong = 0;
	ulong = BN_get_word(bn.get());
	return auth_list->push_back(keymaster_param_long(tag, ulong));
}

// Extract the values from the specified ASN.1 record and place them in auth_list.
keymaster_error_t extract_auth_list(const KM_AUTH_LIST* record, AuthSet* auth_list) {
	if (!record) return KM_ERROR_OK;

	// Purpose
	if (!get_repeated_enums(record->purpose, TAG_PURPOSE, auth_list)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Algorithm
	if (!get_enum(record->algorithm, TAG_ALGORITHM, auth_list)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Key size
	if (record->key_size &&
	    !auth_list->push_back(TAG_KEY_SIZE, ASN1_INTEGER_get(record->key_size))) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Block mode
	if (!get_repeated_enums(record->block_mode, TAG_BLOCK_MODE, auth_list)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Digest
	if (!get_repeated_enums(record->digest, TAG_DIGEST, auth_list)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Padding
	if (!get_repeated_enums(record->padding, TAG_PADDING, auth_list)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Rsa Oaep Mgf Digest
	if (!get_repeated_enums(record->mgf_digest, TAG_RSA_OAEP_MGF_DIGEST, auth_list)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Caller nonce
	if (record->caller_nonce && !auth_list->push_back(TAG_CALLER_NONCE)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Min mac length
	if (!get_ulong(record->min_mac_length, TAG_MIN_MAC_LENGTH, auth_list)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// EC curve
	if (!get_enum(record->ec_curve, TAG_EC_CURVE, auth_list)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// RSA public exponent
	if (!get_ulong(record->rsa_public_exponent, TAG_RSA_PUBLIC_EXPONENT, auth_list)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Active date time
	if (!get_ulong(record->active_date_time, TAG_ACTIVE_DATETIME, auth_list)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Origination expire date time
	if (!get_ulong(record->origination_expire_date_time, TAG_ORIGINATION_EXPIRE_DATETIME,
	               auth_list)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Usage Expire date time
	if (!get_ulong(record->usage_expire_date_time, TAG_USAGE_EXPIRE_DATETIME, auth_list)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// No auth required
	if (record->no_auth_required && !auth_list->push_back(TAG_NO_AUTH_REQUIRED)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// User auth type
	if (!get_enum(record->user_auth_type, TAG_USER_AUTH_TYPE, auth_list)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Auth timeout
	if (record->auth_timeout &&
	    !auth_list->push_back(TAG_AUTH_TIMEOUT, ASN1_INTEGER_get(record->auth_timeout))) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// All applications
	if (record->all_applications && !auth_list->push_back(TAG_ALL_APPLICATIONS)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Application ID
	if (record->application_id &&
	    !auth_list->push_back(TAG_APPLICATION_ID, record->application_id->data,
	                          record->application_id->length)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Attestation application ID
	if (record->attestation_application_id &&
	    !auth_list->push_back(TAG_ATTESTATION_APPLICATION_ID,
	                          record->attestation_application_id->data,
	                          record->attestation_application_id->length)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// identity credential key
	if (record->identity_credential_key && !auth_list->push_back(TAG_IDENTITY_CREDENTIAL_KEY)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// storage key
	if (record->storage_key && !auth_list->push_back(TAG_STORAGE_KEY)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// trusted user presence required
	if (record->trusted_user_presence_required &&
	    !auth_list->push_back(TAG_TRUSTED_USER_PRESENCE_REQUIRED)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// trusted confirmation required
	if (record->trusted_confirmation_required &&
	    !auth_list->push_back(TAG_TRUSTED_CONFIRMATION_REQUIRED)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// boot patch level
	if (record->boot_patch_level &&
	    !auth_list->push_back(TAG_BOOT_PATCHLEVEL, ASN1_INTEGER_get(record->boot_patch_level))) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// vendor patch level
	if (record->vendor_patchlevel &&
	    !auth_list->push_back(TAG_VENDOR_PATCHLEVEL, ASN1_INTEGER_get(record->vendor_patchlevel))) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// confirmation token
	if (record->confirmation_token &&
	    !auth_list->push_back(TAG_CONFIRMATION_TOKEN, record->confirmation_token->data,
	                          record->confirmation_token->length)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Creation date time
	if (!get_ulong(record->creation_date_time, TAG_CREATION_DATETIME, auth_list)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Origin
	if (!get_enum(record->origin, TAG_ORIGIN, auth_list)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Rollback resistant
	if (record->rollback_resistant && !auth_list->push_back(TAG_ROLLBACK_RESISTANT)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Root of trust
	if (record->root_of_trust) {
		KM_ROOT_OF_TRUST* rot = record->root_of_trust;
		if (!rot->verified_boot_key) return KM_ERROR_INVALID_KEY_BLOB;

		// Other root of trust fields are not mapped to auth set entries.
	}

	// OS Version
	if (record->os_version &&
	    !auth_list->push_back(TAG_OS_VERSION, ASN1_INTEGER_get(record->os_version))) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// OS Patch level
	if (record->os_patchlevel &&
	    !auth_list->push_back(TAG_OS_PATCHLEVEL, ASN1_INTEGER_get(record->os_patchlevel))) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Brand name
	if (record->attestation_id_brand &&
	    !auth_list->push_back(TAG_ATTESTATION_ID_BRAND, record->attestation_id_brand->data,
	                          record->attestation_id_brand->length)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Device name
	if (record->attestation_id_device &&
	    !auth_list->push_back(TAG_ATTESTATION_ID_DEVICE, record->attestation_id_device->data,
	                          record->attestation_id_device->length)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Product name
	if (record->attestation_id_product &&
	    !auth_list->push_back(TAG_ATTESTATION_ID_PRODUCT, record->attestation_id_product->data,
	                          record->attestation_id_product->length)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Serial number
	if (record->attestation_id_serial &&
	    !auth_list->push_back(TAG_ATTESTATION_ID_SERIAL, record->attestation_id_serial->data,
	                          record->attestation_id_serial->length)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// IMEI
	if (record->attestation_id_imei &&
	    !auth_list->push_back(TAG_ATTESTATION_ID_IMEI, record->attestation_id_imei->data,
	                          record->attestation_id_imei->length)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// MEID
	if (record->attestation_id_meid &&
	    !auth_list->push_back(TAG_ATTESTATION_ID_MEID, record->attestation_id_meid->data,
	                          record->attestation_id_meid->length)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Manufacturer name
	if (record->attestation_id_manufacturer &&
	    !auth_list->push_back(TAG_ATTESTATION_ID_MANUFACTURER,
	                          record->attestation_id_manufacturer->data,
	                          record->attestation_id_manufacturer->length)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Model name
	if (record->attestation_id_model &&
	    !auth_list->push_back(TAG_ATTESTATION_ID_MODEL, record->attestation_id_model->data,
	                          record->attestation_id_model->length)) {
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	// Trusted confirmation required
	if (record->trusted_confirmation_required) {
		if (!auth_list->push_back(TAG_NO_AUTH_REQUIRED)) {
			return KM_ERROR_MEMORY_ALLOCATION_FAILED;
		}
	}

	// Early boot only
	if (record->early_boot_only) {
		if (!auth_list->push_back(TAG_EARLY_BOOT_ONLY)) {
			return KM_ERROR_MEMORY_ALLOCATION_FAILED;
		}
	}

	return KM_ERROR_OK;
}

}  // namespace keymaster
