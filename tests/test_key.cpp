/*
 *  Copyright (c) 2020 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file    test_key.cpp
 * @author  Lukasz Pawelczyk <l.pawelczyk@samsung.com>
 * @brief   Key API unit tests.
 */

#include <boost/test/unit_test.hpp>
#include <vector>

#include <yaca_crypto.h>
#include <yaca_encrypt.h>
#include <yaca_key.h>
#include <yaca_simple.h>
#include <yaca_error.h>

#include "common.h"


namespace {

void import_export(yaca_key_h key, yaca_key_type_e expected_type,
				   yaca_key_bit_length_e expected_len, const char *password,
				   yaca_key_format_e format, yaca_key_file_format_e file_format)
{
	int ret;
	yaca_key_h imported = YACA_KEY_NULL;

	char *data1 = NULL, *data2 = NULL;
	size_t data1_len = 0, data2_len = 0;
	yaca_key_type_e key_type;
	size_t key_length;

	ret = yaca_key_export(key, format, file_format,
						  password, &data1, &data1_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	BOOST_REQUIRE(data1 != NULL);
	BOOST_REQUIRE(data1_len > 0);

	ret = yaca_key_import(expected_type, password, data1, data1_len, &imported);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_key_get_type(imported, &key_type);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_get_bit_length(imported, &key_length);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	BOOST_REQUIRE(key_type == expected_type);
	BOOST_REQUIRE(key_length == expected_len);

	ret = yaca_key_export(imported, format, file_format,
						  password, &data2, &data2_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	BOOST_REQUIRE(data2 != NULL);
	BOOST_REQUIRE(data2_len > 0);

	BOOST_REQUIRE(data1_len == data2_len);

	if (password == NULL || password[0] == '\0') {
		ret = yaca_memcmp(data1, data2, data1_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	}

	yaca_key_destroy(imported);
	yaca_free(data1);
	yaca_free(data2);
}

void assert_keys_identical(const yaca_key_h key1, const yaca_key_h key2)
{
	int ret;
	char *data1 = NULL, *data2 = NULL;
	size_t len1, len2, data1_len, data2_len;
	yaca_key_type_e type1, type2;
	yaca_key_file_format_e format;

	ret = yaca_key_get_bit_length(key1, &len1);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_get_bit_length(key2, &len2);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	BOOST_REQUIRE(len1 == len2);

	ret = yaca_key_get_type(key1, &type1);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_get_type(key2, &type2);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	BOOST_REQUIRE(type1 == type2);

	switch (type1) {
	case YACA_KEY_TYPE_SYMMETRIC:
	case YACA_KEY_TYPE_DES:
	case YACA_KEY_TYPE_IV:
		format = YACA_KEY_FILE_FORMAT_RAW;
		break;
	default:
		format = YACA_KEY_FILE_FORMAT_DER;
	}

	ret = yaca_key_export(key1, YACA_KEY_FORMAT_DEFAULT, format,
						  NULL, &data1, &data1_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_export(key2, YACA_KEY_FORMAT_DEFAULT, format,
						  NULL, &data2, &data2_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	BOOST_REQUIRE(data1_len == data2_len);

	ret = yaca_memcmp(data1, data2, data1_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	yaca_free(data1);
	yaca_free(data2);
}

} // namespace


BOOST_AUTO_TEST_SUITE(TESTS_KEY)

BOOST_FIXTURE_TEST_CASE(T201__positive__key_generate, InitDebugFixture)
{
	struct key_args {
		yaca_key_type_e type;
		size_t len;
		size_t expected;
	};

	const std::vector<struct key_args> kargs = {
		{YACA_KEY_TYPE_SYMMETRIC,
		 YACA_KEY_LENGTH_256BIT,
		 YACA_KEY_LENGTH_256BIT},
		{YACA_KEY_TYPE_SYMMETRIC,
		 200,
		 200},
		{YACA_KEY_TYPE_SYMMETRIC,
		 104,
		 104},
		{YACA_KEY_TYPE_DES,
		 YACA_KEY_LENGTH_192BIT,
		 YACA_KEY_LENGTH_192BIT},
		{YACA_KEY_TYPE_IV,
		 YACA_KEY_LENGTH_512BIT,
		 YACA_KEY_LENGTH_512BIT},
		{YACA_KEY_TYPE_RSA_PRIV,
		 YACA_KEY_LENGTH_2048BIT,
		 YACA_KEY_LENGTH_2048BIT},
		{YACA_KEY_TYPE_RSA_PRIV,
		 520,
		 520},
		{YACA_KEY_TYPE_RSA_PRIV,
		 1056,
		 1056},
		{YACA_KEY_TYPE_DSA_PRIV,
		 YACA_KEY_LENGTH_2048BIT,
		 YACA_KEY_LENGTH_2048BIT},
		{YACA_KEY_TYPE_DSA_PRIV,
		 576,
		 576},
		{YACA_KEY_TYPE_DSA_PRIV,
		 896,
		 896},
		{YACA_KEY_TYPE_DH_PRIV,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_DH_RFC_2048_224,
		 YACA_KEY_LENGTH_2048BIT},
		{YACA_KEY_TYPE_DH_PRIV,
		 (yaca_key_bit_length_e)(YACA_KEY_LENGTH_DH_GENERATOR_2 | 264),
		 264},
		{YACA_KEY_TYPE_DH_PRIV,
		 (yaca_key_bit_length_e)(YACA_KEY_LENGTH_DH_GENERATOR_5 | 376),
		 376},
		{YACA_KEY_TYPE_EC_PRIV,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_SECP384R1,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_SECP384R1}
	};

	for (const auto &ka: kargs) {
		int ret;
		yaca_key_h key = YACA_KEY_NULL;
		yaca_key_type_e key_type;
		size_t key_length;

		ret = yaca_key_generate(ka.type, ka.len, &key);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_key_get_type(key, &key_type);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		ret = yaca_key_get_bit_length(key, &key_length);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		BOOST_REQUIRE(key_type == ka.type);
		BOOST_REQUIRE(key_length == ka.expected);

		yaca_key_destroy(key);
	}
}

BOOST_FIXTURE_TEST_CASE(T202__negative__key_generate, InitDebugFixture)
{
	int ret;
	yaca_key_h key = YACA_KEY_NULL;

	ret = yaca_key_generate(YACA_INVALID_KEY_TYPE, YACA_KEY_LENGTH_256BIT, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_generate(YACA_KEY_TYPE_RSA_PUB, YACA_KEY_LENGTH_1024BIT, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_generate(YACA_KEY_TYPE_DSA_PARAMS, YACA_KEY_LENGTH_256BIT, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, 0, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, 255, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_generate(YACA_KEY_TYPE_DES, 127, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_generate(YACA_KEY_TYPE_RSA_PRIV, 2047, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_generate(YACA_KEY_TYPE_DH_PRIV,
							YACA_KEY_LENGTH_DH_GENERATOR_2 | 192U, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_generate(YACA_KEY_TYPE_DH_PRIV, YACA_KEYLEN_COMPONENT_TYPE_DH |
							YACA_KEYLEN_COMPONENT_DH_GEN_MASK | 1024U, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_generate(YACA_KEY_TYPE_DH_PRIV, YACA_KEYLEN_COMPONENT_TYPE_MASK |
							YACA_KEYLEN_COMPONENT_DH_GEN_2 | 1024U, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_generate(YACA_KEY_TYPE_DH_PRIV, YACA_KEYLEN_COMPONENT_TYPE_DH_RFC, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_generate(YACA_KEY_TYPE_EC_PARAMS, YACA_KEYLEN_COMPONENT_EC_SECT, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);
}

BOOST_FIXTURE_TEST_CASE(T203__positive__key_generate_from_parameters, InitDebugFixture)
{
	struct key_args {
		yaca_key_type_e type_params;
		yaca_key_type_e type_key;
		yaca_key_bit_length_e len;
		yaca_key_bit_length_e expected;
	};

	const std::vector<struct key_args> kargs = {
		{YACA_KEY_TYPE_DSA_PARAMS,
		 YACA_KEY_TYPE_DSA_PRIV,
		 YACA_KEY_LENGTH_1024BIT,
		 YACA_KEY_LENGTH_1024BIT},
		{YACA_KEY_TYPE_DH_PARAMS,
		 YACA_KEY_TYPE_DH_PRIV,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_DH_RFC_1024_160,
		 YACA_KEY_LENGTH_1024BIT},
		{YACA_KEY_TYPE_DH_PARAMS,
		 YACA_KEY_TYPE_DH_PRIV,
		 (yaca_key_bit_length_e)(YACA_KEY_LENGTH_DH_GENERATOR_2 | 1024U),
		 YACA_KEY_LENGTH_1024BIT},
		{YACA_KEY_TYPE_DH_PARAMS,
		 YACA_KEY_TYPE_DH_PRIV,
		 (yaca_key_bit_length_e)(YACA_KEY_LENGTH_DH_GENERATOR_5 | 512U),
		 YACA_KEY_LENGTH_512BIT},
		{YACA_KEY_TYPE_EC_PARAMS,
		 YACA_KEY_TYPE_EC_PRIV,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_PRIME256V1,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_PRIME256V1}
	};

	for (const auto &ka: kargs) {
		int ret;
		yaca_key_h params = YACA_KEY_NULL;
		yaca_key_h key = YACA_KEY_NULL;
		yaca_key_type_e key_type;
		size_t key_length;

		ret = yaca_key_generate(ka.type_params, ka.len, &params);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_key_get_type(params, &key_type);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		ret = yaca_key_get_bit_length(params, &key_length);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		BOOST_REQUIRE(key_type == ka.type_params);
		BOOST_REQUIRE(key_length == ka.expected);

		ret = yaca_key_generate_from_parameters(params, &key);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_key_get_type(key, &key_type);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		ret = yaca_key_get_bit_length(key, &key_length);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		BOOST_REQUIRE(key_type == ka.type_key);
		BOOST_REQUIRE(key_length == ka.expected);


		yaca_key_destroy(params);
		yaca_key_destroy(key);
	}
}

BOOST_FIXTURE_TEST_CASE(T204__negative__key_generate_from_parameters, InitDebugFixture)
{
	int ret;
	yaca_key_h key_prv = YACA_KEY_NULL, key_pub = YACA_KEY_NULL;
	yaca_key_h key_sym = YACA_KEY_NULL, key_params = YACA_KEY_NULL;
	yaca_key_h key = YACA_KEY_NULL;

	generate_asymmetric_keys(YACA_KEY_TYPE_DSA_PRIV, YACA_KEY_LENGTH_512BIT,
							  &key_prv, &key_pub, &key_params);

	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_UNSAFE_128BIT, &key_sym);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_key_generate_from_parameters(YACA_KEY_NULL, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_generate_from_parameters(key_prv, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_generate_from_parameters(key_pub, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_generate_from_parameters(key_sym, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_generate_from_parameters(key_params, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	yaca_key_destroy(key_prv);
	yaca_key_destroy(key_pub);
	yaca_key_destroy(key_params);
	yaca_key_destroy(key_sym);
}

BOOST_FIXTURE_TEST_CASE(T205__positive__key_extract_public_parameters, InitDebugFixture)
{
	struct key_args {
		yaca_key_type_e type_priv;
		yaca_key_type_e type_pub;
		yaca_key_type_e type_params;
		yaca_key_bit_length_e len;
		yaca_key_bit_length_e expected;
	};

	const std::vector<struct key_args> kargs = {
		{YACA_KEY_TYPE_RSA_PRIV,
		 YACA_KEY_TYPE_RSA_PUB,
		 YACA_INVALID_KEY_TYPE,
		 YACA_KEY_LENGTH_1024BIT,
		 YACA_KEY_LENGTH_1024BIT},
		{YACA_KEY_TYPE_DSA_PRIV,
		 YACA_KEY_TYPE_DSA_PUB,
		 YACA_KEY_TYPE_DSA_PARAMS,
		 YACA_KEY_LENGTH_1024BIT,
		 YACA_KEY_LENGTH_1024BIT},
		{YACA_KEY_TYPE_DH_PRIV,
		 YACA_KEY_TYPE_DH_PUB,
		 YACA_KEY_TYPE_DH_PARAMS,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_DH_RFC_2048_256,
		 YACA_KEY_LENGTH_2048BIT},
		{YACA_KEY_TYPE_EC_PRIV,
		 YACA_KEY_TYPE_EC_PUB,
		 YACA_KEY_TYPE_EC_PARAMS,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_PRIME256V1,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_PRIME256V1}
	};

	for (const auto &ka: kargs) {
		int ret;
		yaca_key_h priv = YACA_KEY_NULL;
		yaca_key_h pub = YACA_KEY_NULL;
		yaca_key_type_e key_type;
		size_t key_length;

		ret = yaca_key_generate(ka.type_priv, ka.len, &priv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_key_extract_public(priv, &pub);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_key_get_type(pub, &key_type);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		ret = yaca_key_get_bit_length(pub, &key_length);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		BOOST_REQUIRE(key_type == ka.type_pub);
		BOOST_REQUIRE(key_length == ka.expected);

		if (ka.type_params != YACA_INVALID_KEY_TYPE) {
			yaca_key_h params = YACA_KEY_NULL;
			yaca_key_h key = YACA_KEY_NULL;

			ret = yaca_key_extract_parameters(pub, &params);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			ret = yaca_key_get_type(params, &key_type);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			ret = yaca_key_get_bit_length(params, &key_length);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			BOOST_REQUIRE(key_type == ka.type_params);
			BOOST_REQUIRE(key_length == ka.expected);

			ret = yaca_key_generate_from_parameters(params, &key);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			ret = yaca_key_get_type(key, &key_type);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			ret = yaca_key_get_bit_length(key, &key_length);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			BOOST_REQUIRE(key_type == ka.type_priv);
			BOOST_REQUIRE(key_length == ka.expected);

			yaca_key_destroy(params);
			yaca_key_destroy(key);
		}

		yaca_key_destroy(priv);
		yaca_key_destroy(pub);
	}
}

BOOST_FIXTURE_TEST_CASE(T206__negative__key_extract_public_parameters, InitDebugFixture)
{
	int ret;
	yaca_key_h key_prv = YACA_KEY_NULL, key_pub = YACA_KEY_NULL;
	yaca_key_h key_sym = YACA_KEY_NULL, key_params = YACA_KEY_NULL;
	yaca_key_h key = YACA_KEY_NULL;

	generate_asymmetric_keys(YACA_KEY_TYPE_DSA_PRIV, YACA_KEY_LENGTH_512BIT, &key_prv, &key_pub, &key_params);

	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_UNSAFE_128BIT, &key_sym);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_key_extract_public(NULL, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_extract_public(key_pub, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_extract_public(key_params, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_extract_public(key_sym, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_extract_public(key_prv, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_extract_parameters(NULL, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_extract_parameters(key_params, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_extract_parameters(key_sym, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_extract_parameters(key_prv, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	yaca_key_destroy(key_prv);
	yaca_key_destroy(key_pub);
	yaca_key_destroy(key_params);
	yaca_key_destroy(key_sym);
}

BOOST_FIXTURE_TEST_CASE(T207__positive__key_import_export_symmetric, InitDebugFixture)
{
	struct key_args {
		yaca_key_type_e type;
		yaca_key_bit_length_e len;
	};

	struct format_args {
		yaca_key_format_e format;
		yaca_key_file_format_e file_format;
	};

	const std::vector<struct key_args> kargs = {
		{YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT},
		{YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_512BIT},
		{YACA_KEY_TYPE_IV, YACA_KEY_LENGTH_UNSAFE_128BIT},
		{YACA_KEY_TYPE_DES, YACA_KEY_LENGTH_UNSAFE_128BIT},
		{YACA_KEY_TYPE_DES, YACA_KEY_LENGTH_192BIT}
	};

	for (const auto &ka: kargs) {
		int ret;
		yaca_key_h key = YACA_KEY_NULL;

		ret = yaca_key_generate(ka.type, ka.len, &key);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		import_export(key, ka.type, ka.len, "",
					  YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_RAW);

		import_export(key, ka.type, ka.len, "",
					  YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_BASE64);

		yaca_key_destroy(key);
	}
}

BOOST_FIXTURE_TEST_CASE(T208__negative__key_import_export_symmetric, InitDebugFixture)
{
	int ret;
	yaca_key_h key = YACA_KEY_NULL, key_import = YACA_KEY_NULL;
	yaca_key_type_e type;
	size_t len;

	char *data = NULL;
	size_t data_len;

	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_key_export(YACA_KEY_NULL, YACA_KEY_FORMAT_DEFAULT,
						  YACA_KEY_FILE_FORMAT_BASE64, NULL, &data, &data_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_export(key, YACA_INVALID_KEY_FORMAT,
						  YACA_KEY_FILE_FORMAT_BASE64, NULL, &data, &data_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_export(key, YACA_KEY_FORMAT_PKCS8,
						  YACA_KEY_FILE_FORMAT_BASE64, NULL, &data, &data_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_export(key, YACA_KEY_FORMAT_DEFAULT,
						  YACA_INVALID_KEY_FILE_FORMAT, NULL, &data, &data_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_export(key, YACA_KEY_FORMAT_DEFAULT,
						  YACA_KEY_FILE_FORMAT_PEM, NULL, &data, &data_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_export(key, YACA_KEY_FORMAT_DEFAULT,
						  YACA_KEY_FILE_FORMAT_BASE64, "password", &data, &data_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_export(key, YACA_KEY_FORMAT_DEFAULT,
						  YACA_KEY_FILE_FORMAT_BASE64, NULL, NULL, &data_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_export(key, YACA_KEY_FORMAT_DEFAULT,
						  YACA_KEY_FILE_FORMAT_BASE64, NULL, &data, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_export(key, YACA_KEY_FORMAT_DEFAULT,
						  YACA_KEY_FILE_FORMAT_BASE64, NULL, &data, &data_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_key_import(YACA_INVALID_KEY_TYPE, "", data, data_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_DH_PRIV, "", data, data_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_DES, "", data, data_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_SYMMETRIC, "password", data, data_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_SYMMETRIC, "", NULL, data_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_SYMMETRIC, "", data, 0, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_SYMMETRIC, "", data, data_len, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	/* should still be correct */
	data[0] = (data[0] == 'A' ? 'Z' : 'A');
	ret = yaca_key_import(YACA_KEY_TYPE_SYMMETRIC, "", data, data_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_key_get_type(key_import, &type);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	BOOST_REQUIRE(type == YACA_KEY_TYPE_SYMMETRIC);
	ret = yaca_key_get_bit_length(key_import, &len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	BOOST_REQUIRE(len == YACA_KEY_LENGTH_256BIT);

	yaca_key_destroy(key_import);

	/* should be treated as raw */
	ret = yaca_key_import(YACA_KEY_TYPE_SYMMETRIC, "", data, data_len-1, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_key_get_type(key_import, &type);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	BOOST_REQUIRE(type == YACA_KEY_TYPE_SYMMETRIC);
	ret = yaca_key_get_bit_length(key_import, &len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	BOOST_REQUIRE(len == 344);

	yaca_key_destroy(key_import);

	/* should be treated as raw */
	data[0] = 10;
	ret = yaca_key_import(YACA_KEY_TYPE_SYMMETRIC, "", data, data_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_key_get_type(key_import, &type);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	BOOST_REQUIRE(type == YACA_KEY_TYPE_SYMMETRIC);
	ret = yaca_key_get_bit_length(key_import, &len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	BOOST_REQUIRE(len == 352);

	yaca_key_destroy(key_import);
	yaca_key_destroy(key);
	yaca_free(data);
}

BOOST_FIXTURE_TEST_CASE(T209__positive__key_import_export_asymmetric, InitDebugFixture)
{
	struct key_args {
		yaca_key_type_e type_priv;
		yaca_key_type_e type_pub;
		yaca_key_type_e type_params;
		yaca_key_bit_length_e len;
		yaca_key_bit_length_e expected;
	};

	struct format_args {
		yaca_key_format_e format;
		yaca_key_file_format_e file_format;
	};

	const std::vector<struct key_args> kargs = {
		{YACA_KEY_TYPE_RSA_PRIV,
		 YACA_KEY_TYPE_RSA_PUB,
		 YACA_INVALID_KEY_TYPE,
		 YACA_KEY_LENGTH_1024BIT,
		 YACA_KEY_LENGTH_1024BIT},
		{YACA_KEY_TYPE_DSA_PRIV,
		 YACA_KEY_TYPE_DSA_PUB,
		 YACA_KEY_TYPE_DSA_PARAMS,
		 YACA_KEY_LENGTH_1024BIT,
		 YACA_KEY_LENGTH_1024BIT},
		{YACA_KEY_TYPE_EC_PRIV,
		 YACA_KEY_TYPE_EC_PUB,
		 YACA_KEY_TYPE_EC_PARAMS,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_PRIME256V1,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_PRIME256V1},
		{YACA_KEY_TYPE_DH_PRIV,
		 YACA_KEY_TYPE_DH_PUB,
		 YACA_KEY_TYPE_DH_PARAMS,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_DH_RFC_1024_160,
		 YACA_KEY_LENGTH_1024BIT}
	};

	for (const auto &ka: kargs) {
		int ret;
		yaca_key_h key_priv = YACA_KEY_NULL;
		yaca_key_h key_pub = YACA_KEY_NULL;

		ret = yaca_key_generate(ka.type_priv, ka.len, &key_priv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		import_export(key_priv, ka.type_priv, ka.expected, NULL,
					  YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_DER);

		import_export(key_priv, ka.type_priv, ka.expected, NULL,
					  YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_PEM);

		ret = yaca_key_extract_public(key_priv, &key_pub);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		import_export(key_pub, ka.type_pub, ka.expected, "",
					  YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_DER);

		import_export(key_pub, ka.type_pub, ka.expected, "",
					  YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_PEM);

		if (ka.type_params != YACA_INVALID_KEY_TYPE) {
			yaca_key_h key_params = YACA_KEY_NULL;

			ret = yaca_key_extract_parameters(key_priv, &key_params);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			import_export(key_params, ka.type_params, ka.expected, NULL,
						  YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_DER);

			import_export(key_params, ka.type_params, ka.expected, NULL,
						  YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_PEM);

			yaca_key_destroy(key_params);
		}

		yaca_key_destroy(key_priv);
		yaca_key_destroy(key_pub);
	}
}

BOOST_FIXTURE_TEST_CASE(T210__negative__key_import_export_asymmetric, InitDebugFixture)
{
	int ret;
	yaca_key_h key_prv = YACA_KEY_NULL, key_pub;
	yaca_key_h key_params = YACA_KEY_NULL, key_import = YACA_KEY_NULL;
	char data_short[] = "abc";

	char *data_pem = NULL, *data_der = NULL;
	size_t data_pem_len, data_der_len;

	generate_asymmetric_keys(YACA_KEY_TYPE_DSA_PRIV, YACA_KEY_LENGTH_1024BIT, &key_prv, &key_pub, &key_params);

	ret = yaca_key_export(YACA_KEY_NULL, YACA_KEY_FORMAT_DEFAULT,
						  YACA_KEY_FILE_FORMAT_PEM, "", &data_pem, &data_pem_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_export(key_prv, YACA_INVALID_KEY_FORMAT,
						  YACA_KEY_FILE_FORMAT_PEM, "", &data_pem, &data_pem_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_export(key_prv, YACA_KEY_FORMAT_PKCS8,
						  YACA_KEY_FILE_FORMAT_PEM, "", &data_pem, &data_pem_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_export(key_prv, YACA_KEY_FORMAT_DEFAULT,
						  YACA_INVALID_KEY_FILE_FORMAT, "", &data_pem, &data_pem_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_export(key_prv, YACA_KEY_FORMAT_DEFAULT,
						  YACA_KEY_FILE_FORMAT_BASE64, "", &data_pem, &data_pem_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_export(key_prv, YACA_KEY_FORMAT_DEFAULT,
						  YACA_KEY_FILE_FORMAT_DER, "password", &data_der, &data_der_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_export(key_prv, YACA_KEY_FORMAT_DEFAULT,
						  YACA_KEY_FILE_FORMAT_PEM, "", NULL, &data_pem_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_export(key_prv, YACA_KEY_FORMAT_DEFAULT,
						  YACA_KEY_FILE_FORMAT_PEM, "", &data_pem, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_export(key_prv, YACA_KEY_FORMAT_DEFAULT,
						  YACA_KEY_FILE_FORMAT_PEM, "", &data_pem, &data_pem_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_export(key_prv, YACA_KEY_FORMAT_DEFAULT,
						  YACA_KEY_FILE_FORMAT_DER, "", &data_der, &data_der_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_key_import(YACA_INVALID_KEY_TYPE, "", data_pem, data_pem_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_RSA_PRIV, "", data_pem, data_pem_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PUB, "", data_pem, data_pem_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PARAMS, "", data_der, data_der_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, "password", data_pem, data_pem_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PASSWORD);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, "password", data_der, data_der_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, "", NULL, data_pem_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, "", data_pem, 0, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, "", data_pem, data_pem_len, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_RSA_PRIV, "", data_short, strlen(data_short), &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	/* two bytes have to be removed to get EINVAL, one is not enough, it's probably newline */
	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, "", data_pem, data_pem_len - 2, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, "", data_der, data_der_len - 1, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, "", data_pem + 1, data_pem_len - 1, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, "", data_der + 1, data_der_len - 1, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	data_pem[30] = (data_pem[30] == 'a' ? 'z' : 'a');
	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, "", data_pem, data_pem_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	data_der[0] = ~data_der[0];
	data_der[1] = ~data_der[1];
	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, "", data_der, data_der_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	yaca_key_destroy(key_prv);
	yaca_key_destroy(key_pub);
	yaca_key_destroy(key_params);
	yaca_free(data_der);
	yaca_free(data_pem);
}

BOOST_FIXTURE_TEST_CASE(T211__positive__key_import_export_encrypted, InitDebugFixture)
{
	static const char *PASSWORD = "ExamplE_PassworD";

	struct default_args {
		yaca_key_type_e type;
		yaca_key_bit_length_e len;
	};

	const std::vector<struct default_args> dargs = {
		{YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_1024BIT},
		{YACA_KEY_TYPE_DSA_PRIV, YACA_KEY_LENGTH_1024BIT}
	};

	for (const auto &da: dargs) {
		int ret;
		yaca_key_h key = YACA_KEY_NULL;

		ret = yaca_key_generate(da.type, da.len, &key);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		import_export(key, da.type, da.len, PASSWORD,
					  YACA_KEY_FORMAT_DEFAULT,
					  YACA_KEY_FILE_FORMAT_PEM);

		yaca_key_destroy(key);
	}

	struct pkcs8_args {
		yaca_key_type_e type;
		yaca_key_bit_length_e len;
		yaca_key_bit_length_e expected;
	};

	const std::vector<struct pkcs8_args> pargs {
		{YACA_KEY_TYPE_RSA_PRIV,
		 YACA_KEY_LENGTH_1024BIT,
		 YACA_KEY_LENGTH_1024BIT},
		{YACA_KEY_TYPE_DSA_PRIV,
		 YACA_KEY_LENGTH_1024BIT,
		 YACA_KEY_LENGTH_1024BIT},
		{YACA_KEY_TYPE_EC_PRIV,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_PRIME256V1,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_PRIME256V1},
		{YACA_KEY_TYPE_DH_PRIV,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_DH_RFC_1024_160,
		 YACA_KEY_LENGTH_1024BIT}
	};

	for (const auto &pa: pargs) {
		int ret;
		yaca_key_h key = YACA_KEY_NULL;

		ret = yaca_key_generate(pa.type, pa.len, &key);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		import_export(key, pa.type, pa.expected, PASSWORD,
					  YACA_KEY_FORMAT_PKCS8, YACA_KEY_FILE_FORMAT_DER);

		import_export(key, pa.type, pa.expected, PASSWORD,
					  YACA_KEY_FORMAT_PKCS8, YACA_KEY_FILE_FORMAT_PEM);

		yaca_key_destroy(key);
	}
}

BOOST_FIXTURE_TEST_CASE(T212__negative__key_import_export_encrypted, InitDebugFixture)
{
	static const char *PASSWORD = "ExamplE_PassworD";
	static const char *WRONG_PASSWORD = "wRONg_pASSWORd";

	int ret;
	yaca_key_h key_prv = YACA_KEY_NULL, key_pub;
	yaca_key_h key_params = YACA_KEY_NULL, key_import = YACA_KEY_NULL;

	char *data_pem = NULL, *data_pkcs8_pem = NULL, *data_pkcs8_der = NULL;
	size_t data_pem_len, data_pkcs8_pem_len, data_pkcs8_der_len;

	generate_asymmetric_keys(YACA_KEY_TYPE_DSA_PRIV, YACA_KEY_LENGTH_1024BIT, &key_prv, &key_pub, &key_params);

	ret = yaca_key_export(key_pub, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_PEM,
						  PASSWORD, &data_pem, &data_pem_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_export(key_params, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_PEM,
						  PASSWORD, &data_pem, &data_pem_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_export(key_pub, YACA_KEY_FORMAT_PKCS8, YACA_KEY_FILE_FORMAT_PEM,
						  PASSWORD, &data_pkcs8_pem, &data_pkcs8_pem_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_export(key_params, YACA_KEY_FORMAT_PKCS8, YACA_KEY_FILE_FORMAT_DER,
						  PASSWORD, &data_pkcs8_der, &data_pkcs8_der_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_export(key_prv, YACA_KEY_FORMAT_PKCS8, YACA_KEY_FILE_FORMAT_PEM,
						  NULL, &data_pkcs8_pem, &data_pkcs8_pem_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_export(key_prv, YACA_KEY_FORMAT_PKCS8, YACA_INVALID_KEY_FILE_FORMAT,
						  PASSWORD, &data_pkcs8_pem, &data_pkcs8_pem_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_export(key_prv, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_PEM,
						  PASSWORD, &data_pem, &data_pem_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_export(key_prv, YACA_KEY_FORMAT_PKCS8, YACA_KEY_FILE_FORMAT_PEM,
						  PASSWORD, &data_pkcs8_pem, &data_pkcs8_pem_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_export(key_prv, YACA_KEY_FORMAT_PKCS8, YACA_KEY_FILE_FORMAT_DER,
						  PASSWORD, &data_pkcs8_der, &data_pkcs8_der_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PUB, PASSWORD,
						  data_pem, data_pem_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, NULL,
						  data_pem, data_pem_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PASSWORD);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, WRONG_PASSWORD,
						  data_pem, data_pem_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PASSWORD);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, PASSWORD,
						  data_pem, data_pem_len - 2, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, PASSWORD,
						  data_pem + 1, data_pem_len - 1, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	data_pem[30] = (data_pem[30] == 'a' ? 'z' : 'a');
	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, PASSWORD,
						  data_pem, data_pem_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PUB, PASSWORD,
						  data_pkcs8_pem, data_pkcs8_pem_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, NULL,
						  data_pkcs8_pem, data_pkcs8_pem_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PASSWORD);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, WRONG_PASSWORD,
						  data_pkcs8_pem, data_pkcs8_pem_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PASSWORD);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, PASSWORD,
						  data_pkcs8_pem, data_pkcs8_pem_len - 2, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, PASSWORD,
						  data_pkcs8_pem + 1, data_pkcs8_pem_len - 1, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	data_pkcs8_pem[30] = (data_pkcs8_pem[30] == 'a' ? 'z' : 'a');
	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, PASSWORD,
						  data_pkcs8_pem, data_pkcs8_pem_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PARAMS, PASSWORD,
						  data_pkcs8_der, data_pkcs8_der_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, NULL,
						  data_pkcs8_der, data_pkcs8_der_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PASSWORD);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, WRONG_PASSWORD,
						  data_pkcs8_der, data_pkcs8_der_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PASSWORD);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, PASSWORD,
						  data_pkcs8_der, data_pkcs8_der_len - 1, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, PASSWORD,
						  data_pkcs8_der+ 1, data_pkcs8_der_len - 1, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	data_pkcs8_der[0] = ~data_pkcs8_der[0];
	data_pkcs8_der[1] = ~data_pkcs8_der[1];
	ret = yaca_key_import(YACA_KEY_TYPE_DSA_PRIV, PASSWORD,
						  data_pkcs8_der, data_pkcs8_der_len, &key_import);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	yaca_key_destroy(key_prv);
	yaca_key_destroy(key_pub);
	yaca_key_destroy(key_params);
	yaca_free(data_pem);
	yaca_free(data_pkcs8_pem);
	yaca_free(data_pkcs8_der);
}

BOOST_FIXTURE_TEST_CASE(T213__positive__key_derive_dh, InitDebugFixture)
{
	struct key_args {
		yaca_key_type_e type;
		yaca_key_bit_length_e len;
	};

	const std::vector<struct key_args> kargs = {
		{YACA_KEY_TYPE_DH_PRIV,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_DH_RFC_1024_160},
		{YACA_KEY_TYPE_EC_PRIV,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_SECP384R1}
	};

	for (const auto &ka: kargs) {
		int ret;
		yaca_key_h priv1 = YACA_KEY_NULL, pub1 = YACA_KEY_NULL;
		yaca_key_h priv2 = YACA_KEY_NULL, pub2 = YACA_KEY_NULL;
		char *secret1 = NULL, *secret2 = NULL;
		size_t secret1_len, secret2_len;

		generate_asymmetric_keys(ka.type, ka.len, &priv1, &pub1);
		generate_asymmetric_keys(ka.type, ka.len, &priv2, &pub2);

		ret = yaca_key_derive_dh(priv1, pub2, &secret1, &secret1_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		ret = yaca_key_derive_dh(priv2, pub1, &secret2, &secret2_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		BOOST_REQUIRE(secret1_len == secret2_len);
		ret = yaca_memcmp(secret1, secret2, secret1_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		yaca_key_destroy(priv1);
		yaca_key_destroy(priv2);
		yaca_key_destroy(pub1);
		yaca_key_destroy(pub2);
		yaca_free(secret1);
		yaca_free(secret2);
	}
}

BOOST_FIXTURE_TEST_CASE(T214__negative__key_derive_dh, InitDebugFixture)
{
	int ret;
	yaca_key_h priv1 = YACA_KEY_NULL, pub1 = YACA_KEY_NULL;
	yaca_key_h priv2 = YACA_KEY_NULL, pub2 = YACA_KEY_NULL;
	char *secret = NULL;
	size_t secret_len;

	generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_1024BIT, &priv1, &pub1);
	generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_1024BIT, &priv2, &pub2);

	ret = yaca_key_derive_dh(YACA_KEY_NULL, pub2, &secret, &secret_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_derive_dh(pub1, pub2, &secret, &secret_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_derive_dh(priv1, YACA_KEY_NULL, &secret, &secret_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_derive_dh(priv1, priv2, &secret, &secret_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_derive_dh(priv1, pub2, NULL, &secret_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_derive_dh(priv1, pub2, &secret, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	yaca_key_destroy(priv1);
	yaca_key_destroy(priv2);
	yaca_key_destroy(pub1);
	yaca_key_destroy(pub2);
}

BOOST_FIXTURE_TEST_CASE(T215__positive__key_derive_kdf, InitDebugFixture)
{
	static const size_t SECRET_LEN = 128;
	static const size_t MATERIAL_LEN = 256;

	struct kdf_args {
		yaca_kdf_e kdf;
		yaca_digest_algorithm_e digest;
	};

	const std::vector<struct kdf_args> kargs = {
		{YACA_KDF_X942, YACA_DIGEST_MD5},
		{YACA_KDF_X942, YACA_DIGEST_SHA1},
		{YACA_KDF_X942, YACA_DIGEST_SHA384},
		{YACA_KDF_X962, YACA_DIGEST_MD5},
		{YACA_KDF_X942, YACA_DIGEST_SHA1},
		{YACA_KDF_X942, YACA_DIGEST_SHA256}
	};

	int ret;
	char secret[SECRET_LEN];

	ret = yaca_randomize_bytes(secret, SECRET_LEN);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	for (const auto &ka: kargs) {
		char *key_material1 = NULL, *key_material2 = NULL;

		ret = yaca_key_derive_kdf(ka.kdf, ka.digest, secret, SECRET_LEN,
								  NULL, 0, MATERIAL_LEN, &key_material1);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		ret = yaca_key_derive_kdf(ka.kdf, ka.digest, secret, SECRET_LEN,
								  NULL, 0, MATERIAL_LEN, &key_material2);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_memcmp(key_material1, key_material2, MATERIAL_LEN);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		yaca_free(key_material1);
		yaca_free(key_material2);
	}
}

BOOST_FIXTURE_TEST_CASE(T216__negative__key_derive_kdf, InitDebugFixture)
{
	static const size_t SECRET_LEN = 128;
	static const size_t MATERIAL_LEN = 256;

	int ret;
	char secret[SECRET_LEN];
	char *key_material = NULL;

	ret = yaca_randomize_bytes(secret, SECRET_LEN);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_key_derive_kdf(YACA_INVALID_KDF, YACA_DIGEST_MD5, secret, SECRET_LEN,
							  NULL, 0, MATERIAL_LEN, &key_material);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_derive_kdf(YACA_KDF_X942, YACA_INVALID_DIGEST_ALGORITHM, secret, SECRET_LEN,
							  NULL, 0, MATERIAL_LEN, &key_material);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_derive_kdf(YACA_KDF_X942, YACA_DIGEST_MD5, NULL, SECRET_LEN,
							  NULL, 0, MATERIAL_LEN, &key_material);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_derive_kdf(YACA_KDF_X942, YACA_DIGEST_MD5, secret, 0,
							  NULL, 0, MATERIAL_LEN, &key_material);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_derive_kdf(YACA_KDF_X942, YACA_DIGEST_MD5, secret, SECRET_LEN,
							  "test", 0, MATERIAL_LEN, &key_material);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_derive_kdf(YACA_KDF_X942, YACA_DIGEST_MD5, secret, SECRET_LEN,
							  NULL, 10, MATERIAL_LEN, &key_material);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_derive_kdf(YACA_KDF_X942, YACA_DIGEST_MD5, secret, SECRET_LEN,
							  NULL, 0, 0, &key_material);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_derive_kdf(YACA_KDF_X942, YACA_DIGEST_MD5, secret, SECRET_LEN,
							  NULL, 0, MATERIAL_LEN, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);
}

BOOST_FIXTURE_TEST_CASE(T217__positive__key_derive_pbkdf2, InitDebugFixture)
{
	static const char *PASSWORD = "Password_ExamplE";
	static const size_t SALT_LEN = 64;

	struct pbkdf2_args {
		yaca_digest_algorithm_e digest;
		size_t iter;
		size_t bit_len;
	};

	const std::vector<struct pbkdf2_args> pargs = {
		{YACA_DIGEST_MD5, 1, 256},
		{YACA_DIGEST_SHA256, 10, 256},
		{YACA_DIGEST_SHA1, 15, 512},
		{YACA_DIGEST_SHA224, 33, 128},
		{YACA_DIGEST_SHA512, 50, 512}
	};

	int ret;
	char salt[SALT_LEN];

	ret = yaca_randomize_bytes(salt, SALT_LEN);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	for (const auto &pa: pargs) {
		yaca_key_h key1 = YACA_KEY_NULL, key2 = YACA_KEY_NULL;
		yaca_key_type_e type;
		size_t len;

		ret = yaca_key_derive_pbkdf2(PASSWORD, salt, SALT_LEN, pa.iter,
									 pa.digest, pa.bit_len, &key1);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		ret = yaca_key_derive_pbkdf2(PASSWORD, salt, SALT_LEN, pa.iter,
									 pa.digest, pa.bit_len, &key2);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_key_get_type(key1, &type);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		BOOST_REQUIRE(type == YACA_KEY_TYPE_SYMMETRIC);
		ret = yaca_key_get_bit_length(key1, &len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		BOOST_REQUIRE(len == pa.bit_len);

		ret = yaca_key_get_type(key2, &type);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		BOOST_REQUIRE(type == YACA_KEY_TYPE_SYMMETRIC);
		ret = yaca_key_get_bit_length(key2, &len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		BOOST_REQUIRE(len == pa.bit_len);

		assert_keys_identical(key1, key2);

		yaca_key_destroy(key1);
		yaca_key_destroy(key2);
	}
}

BOOST_FIXTURE_TEST_CASE(T218__negative__key_derive_pbkdf2, InitDebugFixture)
{
	static const char *PASSWORD = "Password_ExamplE";
	static const size_t SALT_LEN = 64;

	int ret;
	char salt[SALT_LEN];
	yaca_key_h key = YACA_KEY_NULL;

	ret = yaca_randomize_bytes(salt, SALT_LEN);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_key_derive_pbkdf2(NULL, salt, SALT_LEN, 10,
								 YACA_DIGEST_SHA1, YACA_KEY_LENGTH_256BIT, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_derive_pbkdf2(PASSWORD, NULL, SALT_LEN, 10,
								 YACA_DIGEST_SHA1, YACA_KEY_LENGTH_256BIT, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_derive_pbkdf2(PASSWORD, salt, 0, 10,
								 YACA_DIGEST_SHA1, YACA_KEY_LENGTH_256BIT, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_derive_pbkdf2(PASSWORD, salt, SALT_LEN, 0,
								 YACA_DIGEST_SHA1, YACA_KEY_LENGTH_256BIT, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_derive_pbkdf2(PASSWORD, salt, SALT_LEN, INT_MAX + 1UL,
								 YACA_DIGEST_SHA1, YACA_KEY_LENGTH_256BIT, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_derive_pbkdf2(PASSWORD, salt, SALT_LEN, 10,
								 YACA_INVALID_DIGEST_ALGORITHM, YACA_KEY_LENGTH_256BIT, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_derive_pbkdf2(PASSWORD, salt, SALT_LEN, 10,
								 YACA_DIGEST_SHA1, 0, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_derive_pbkdf2(PASSWORD, salt, SALT_LEN, 10,
								 YACA_DIGEST_SHA1, 1, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_derive_pbkdf2(PASSWORD, salt, SALT_LEN, 10,
								 YACA_DIGEST_SHA1, 127, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_derive_pbkdf2(PASSWORD, salt, SALT_LEN, 10,
								 YACA_DIGEST_SHA1, YACA_KEY_LENGTH_256BIT, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);
}

BOOST_FIXTURE_TEST_CASE(T219__positive__import_x509_cert, InitDebugFixture)
{
	static const char data_pem[] = "-----BEGIN CERTIFICATE-----\n\
MIIC9jCCAl+gAwIBAgIUaWM7DVy/evvsrKz8gkz3qWZKw7EwDQYJKoZIhvcNAQEL\n\
BQAwgYwxCzAJBgNVBAYTAlBMMRQwEgYDVQQIDAtNYXpvd2llY2tpZTERMA8GA1UE\n\
BwwIV2Fyc3phd2ExEDAOBgNVBAoMB1NhbXN1bmcxCzAJBgNVBAsMAklUMRQwEgYD\n\
VQQDDAtzYW1zdW5nLmNvbTEfMB0GCSqGSIb3DQEJARYQbm9uZUBzYW1zdW5nLmNv\n\
bTAeFw0yMDA0MDkxNzUzMDlaFw0yNTA0MDgxNzUzMDlaMIGMMQswCQYDVQQGEwJQ\n\
TDEUMBIGA1UECAwLTWF6b3dpZWNraWUxETAPBgNVBAcMCFdhcnN6YXdhMRAwDgYD\n\
VQQKDAdTYW1zdW5nMQswCQYDVQQLDAJJVDEUMBIGA1UEAwwLc2Ftc3VuZy5jb20x\n\
HzAdBgkqhkiG9w0BCQEWEG5vbmVAc2Ftc3VuZy5jb20wgZ8wDQYJKoZIhvcNAQEB\n\
BQADgY0AMIGJAoGBAMrx4VdcBEWSXdOa7nJr6Vh53TDfnqhgOGRUC8c+kGUu45Cp\n\
hcGU7q44zfqvEdgkVBK+Y6GBMrbB0TALo2zK4RVDIgTc8UskbiBjiP4cHB+Zl460\n\
kU/0vKZPWt7yWq9g87lppEr/f0RTGrKkkcVadCxmKILr4ZtS9563xXH+kKAlAgMB\n\
AAGjUzBRMB0GA1UdDgQWBBQBroKxSi+l6RqOD5jQGRYyoM0I1jAfBgNVHSMEGDAW\n\
gBQBroKxSi+l6RqOD5jQGRYyoM0I1jAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\n\
DQEBCwUAA4GBAC1f+n4ly876nTXMjdINH8qmxrHOH55vt7v1KYWqCVFSJbqtQMlT\n\
E9+bqRGN2LpzMBkDdNkGSrCesI1l/FUStjqdpBGMi1fqFDNDyBXkLJDH5HAMR3ei\n\
hajHIasdGWcAfj+Cyuk1KcTIEkBfdYR6a8C4g04Vbg6M0qEjFl5UTMwm\n\
-----END CERTIFICATE-----";

	/* THIS CHUNK OF BYTES IS AUTOMATICALLY GENERATED */
	static const unsigned char data_der[] = {
		0x30, 0x82, 0x02, 0xf6, 0x30, 0x82, 0x02, 0x5f, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x69,
		0x63, 0x3b, 0x0d, 0x5c, 0xbf, 0x7a, 0xfb, 0xec, 0xac, 0xac, 0xfc, 0x82, 0x4c, 0xf7, 0xa9, 0x66,
		0x4a, 0xc3, 0xb1, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
		0x05, 0x00, 0x30, 0x81, 0x8c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
		0x50, 0x4c, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0b, 0x4d, 0x61, 0x7a,
		0x6f, 0x77, 0x69, 0x65, 0x63, 0x6b, 0x69, 0x65, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04,
		0x07, 0x0c, 0x08, 0x57, 0x61, 0x72, 0x73, 0x7a, 0x61, 0x77, 0x61, 0x31, 0x10, 0x30, 0x0e, 0x06,
		0x03, 0x55, 0x04, 0x0a, 0x0c, 0x07, 0x53, 0x61, 0x6d, 0x73, 0x75, 0x6e, 0x67, 0x31, 0x0b, 0x30,
		0x09, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x02, 0x49, 0x54, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03,
		0x55, 0x04, 0x03, 0x0c, 0x0b, 0x73, 0x61, 0x6d, 0x73, 0x75, 0x6e, 0x67, 0x2e, 0x63, 0x6f, 0x6d,
		0x31, 0x1f, 0x30, 0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16,
		0x10, 0x6e, 0x6f, 0x6e, 0x65, 0x40, 0x73, 0x61, 0x6d, 0x73, 0x75, 0x6e, 0x67, 0x2e, 0x63, 0x6f,
		0x6d, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x30, 0x30, 0x34, 0x30, 0x39, 0x31, 0x37, 0x35, 0x33, 0x30,
		0x39, 0x5a, 0x17, 0x0d, 0x32, 0x35, 0x30, 0x34, 0x30, 0x38, 0x31, 0x37, 0x35, 0x33, 0x30, 0x39,
		0x5a, 0x30, 0x81, 0x8c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x50,
		0x4c, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0b, 0x4d, 0x61, 0x7a, 0x6f,
		0x77, 0x69, 0x65, 0x63, 0x6b, 0x69, 0x65, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x07,
		0x0c, 0x08, 0x57, 0x61, 0x72, 0x73, 0x7a, 0x61, 0x77, 0x61, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03,
		0x55, 0x04, 0x0a, 0x0c, 0x07, 0x53, 0x61, 0x6d, 0x73, 0x75, 0x6e, 0x67, 0x31, 0x0b, 0x30, 0x09,
		0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x02, 0x49, 0x54, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55,
		0x04, 0x03, 0x0c, 0x0b, 0x73, 0x61, 0x6d, 0x73, 0x75, 0x6e, 0x67, 0x2e, 0x63, 0x6f, 0x6d, 0x31,
		0x1f, 0x30, 0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x10,
		0x6e, 0x6f, 0x6e, 0x65, 0x40, 0x73, 0x61, 0x6d, 0x73, 0x75, 0x6e, 0x67, 0x2e, 0x63, 0x6f, 0x6d,
		0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
		0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xca, 0xf1, 0xe1,
		0x57, 0x5c, 0x04, 0x45, 0x92, 0x5d, 0xd3, 0x9a, 0xee, 0x72, 0x6b, 0xe9, 0x58, 0x79, 0xdd, 0x30,
		0xdf, 0x9e, 0xa8, 0x60, 0x38, 0x64, 0x54, 0x0b, 0xc7, 0x3e, 0x90, 0x65, 0x2e, 0xe3, 0x90, 0xa9,
		0x85, 0xc1, 0x94, 0xee, 0xae, 0x38, 0xcd, 0xfa, 0xaf, 0x11, 0xd8, 0x24, 0x54, 0x12, 0xbe, 0x63,
		0xa1, 0x81, 0x32, 0xb6, 0xc1, 0xd1, 0x30, 0x0b, 0xa3, 0x6c, 0xca, 0xe1, 0x15, 0x43, 0x22, 0x04,
		0xdc, 0xf1, 0x4b, 0x24, 0x6e, 0x20, 0x63, 0x88, 0xfe, 0x1c, 0x1c, 0x1f, 0x99, 0x97, 0x8e, 0xb4,
		0x91, 0x4f, 0xf4, 0xbc, 0xa6, 0x4f, 0x5a, 0xde, 0xf2, 0x5a, 0xaf, 0x60, 0xf3, 0xb9, 0x69, 0xa4,
		0x4a, 0xff, 0x7f, 0x44, 0x53, 0x1a, 0xb2, 0xa4, 0x91, 0xc5, 0x5a, 0x74, 0x2c, 0x66, 0x28, 0x82,
		0xeb, 0xe1, 0x9b, 0x52, 0xf7, 0x9e, 0xb7, 0xc5, 0x71, 0xfe, 0x90, 0xa0, 0x25, 0x02, 0x03, 0x01,
		0x00, 0x01, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04,
		0x14, 0x01, 0xae, 0x82, 0xb1, 0x4a, 0x2f, 0xa5, 0xe9, 0x1a, 0x8e, 0x0f, 0x98, 0xd0, 0x19, 0x16,
		0x32, 0xa0, 0xcd, 0x08, 0xd6, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16,
		0x80, 0x14, 0x01, 0xae, 0x82, 0xb1, 0x4a, 0x2f, 0xa5, 0xe9, 0x1a, 0x8e, 0x0f, 0x98, 0xd0, 0x19,
		0x16, 0x32, 0xa0, 0xcd, 0x08, 0xd6, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff,
		0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
		0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00, 0x2d, 0x5f, 0xfa, 0x7e, 0x25, 0xcb,
		0xce, 0xfa, 0x9d, 0x35, 0xcc, 0x8d, 0xd2, 0x0d, 0x1f, 0xca, 0xa6, 0xc6, 0xb1, 0xce, 0x1f, 0x9e,
		0x6f, 0xb7, 0xbb, 0xf5, 0x29, 0x85, 0xaa, 0x09, 0x51, 0x52, 0x25, 0xba, 0xad, 0x40, 0xc9, 0x53,
		0x13, 0xdf, 0x9b, 0xa9, 0x11, 0x8d, 0xd8, 0xba, 0x73, 0x30, 0x19, 0x03, 0x74, 0xd9, 0x06, 0x4a,
		0xb0, 0x9e, 0xb0, 0x8d, 0x65, 0xfc, 0x55, 0x12, 0xb6, 0x3a, 0x9d, 0xa4, 0x11, 0x8c, 0x8b, 0x57,
		0xea, 0x14, 0x33, 0x43, 0xc8, 0x15, 0xe4, 0x2c, 0x90, 0xc7, 0xe4, 0x70, 0x0c, 0x47, 0x77, 0xa2,
		0x85, 0xa8, 0xc7, 0x21, 0xab, 0x1d, 0x19, 0x67, 0x00, 0x7e, 0x3f, 0x82, 0xca, 0xe9, 0x35, 0x29,
		0xc4, 0xc8, 0x12, 0x40, 0x5f, 0x75, 0x84, 0x7a, 0x6b, 0xc0, 0xb8, 0x83, 0x4e, 0x15, 0x6e, 0x0e,
		0x8c, 0xd2, 0xa1, 0x23, 0x16, 0x5e, 0x54, 0x4c, 0xcc, 0x26
	};

	int ret;
	yaca_key_h key_pem = YACA_KEY_NULL, key_der = YACA_KEY_NULL;
	yaca_key_type_e type;
	size_t len;

	ret = yaca_key_import(YACA_KEY_TYPE_RSA_PUB, NULL, data_pem,
						  sizeof(data_pem), &key_pem);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_key_get_type(key_pem, &type);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	BOOST_REQUIRE(type == YACA_KEY_TYPE_RSA_PUB);

	ret = yaca_key_get_bit_length(key_pem, &len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	BOOST_REQUIRE(len == YACA_KEY_LENGTH_1024BIT);

	ret = yaca_key_import(YACA_KEY_TYPE_RSA_PUB, NULL, (char*)data_der,
						  sizeof(data_der), &key_der);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_key_get_type(key_der, &type);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	BOOST_REQUIRE(type == YACA_KEY_TYPE_RSA_PUB);

	ret = yaca_key_get_bit_length(key_der, &len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	BOOST_REQUIRE(len == YACA_KEY_LENGTH_1024BIT);

	assert_keys_identical(key_pem, key_der);

	yaca_key_destroy(key_pem);
	yaca_key_destroy(key_der);
}

BOOST_FIXTURE_TEST_CASE(T220__negative__key_get, InitDebugFixture)
{
	int ret;
	yaca_key_h key = YACA_KEY_NULL;
	yaca_key_type_e type;
	size_t len;

	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_key_get_type(YACA_KEY_NULL, &type);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_get_bit_length(YACA_KEY_NULL, &len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_get_type(key, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_key_get_bit_length(key, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	yaca_key_destroy(key);
}

BOOST_AUTO_TEST_SUITE_END()
