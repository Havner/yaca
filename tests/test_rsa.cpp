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
 * @file    test_rsa.c
 * @author  Lukasz Pawelczyk <l.pawelczyk@samsung.com>
 * @brief   RSA API unit tests.
 */

#include <boost/test/unit_test.hpp>
#include <vector>

#include <yaca_crypto.h>
#include <yaca_rsa.h>
#include <yaca_key.h>
#include <yaca_error.h>

#include "common.h"


BOOST_AUTO_TEST_SUITE(TESTS_RSA)

BOOST_FIXTURE_TEST_CASE(T401__positive__private_encrypt, InitDebugFixture)
{
	struct rsa_args {
		yaca_padding_e pad;
		yaca_key_bit_length_e bit_len;
		size_t shorter;
	};

	const std::vector<struct rsa_args> rargs = {
		{YACA_PADDING_NONE,         YACA_KEY_LENGTH_512BIT,   0},
		{YACA_PADDING_NONE,         YACA_KEY_LENGTH_2048BIT,  0},
		{YACA_PADDING_PKCS1,        YACA_KEY_LENGTH_512BIT,  11},
		{YACA_PADDING_PKCS1,        YACA_KEY_LENGTH_4096BIT, 11},
	};

	for (const auto &ra: rargs) {
		int ret;
		yaca_key_h rsa_prv = YACA_KEY_NULL, rsa_pub = YACA_KEY_NULL;
		size_t input_len = ra.bit_len / 8 - ra.shorter;
		char *encrypted = NULL, *decrypted = NULL;
		size_t encrypted_len, decrypted_len;

		generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, ra.bit_len, &rsa_prv, &rsa_pub);

		ret = yaca_rsa_private_encrypt(ra.pad, rsa_prv, INPUT_DATA, input_len,
									   &encrypted, &encrypted_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_rsa_public_decrypt(ra.pad, rsa_pub, encrypted, encrypted_len,
									  &decrypted, &decrypted_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		BOOST_REQUIRE(decrypted_len == input_len);
		ret = yaca_memcmp(decrypted, INPUT_DATA, input_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		yaca_key_destroy(rsa_prv);
		yaca_key_destroy(rsa_pub);
		yaca_free(encrypted);
		yaca_free(decrypted);
	}

	/* Empty input, must use padding */
	for (const auto &ra: rargs) {
		if (ra.pad == YACA_PADDING_NONE)
			continue;

		int ret;
		yaca_key_h rsa_prv = YACA_KEY_NULL, rsa_pub = YACA_KEY_NULL;
		char *encrypted = NULL, *decrypted = NULL;
		size_t encrypted_len, decrypted_len;

		generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, ra.bit_len, &rsa_prv, &rsa_pub);

		ret = yaca_rsa_private_encrypt(ra.pad, rsa_prv, NULL, 0,
									   &encrypted, &encrypted_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_rsa_public_decrypt(ra.pad, rsa_pub, encrypted, encrypted_len,
									  &decrypted, &decrypted_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		BOOST_REQUIRE(decrypted == NULL);
		BOOST_REQUIRE(decrypted_len == 0);

		yaca_key_destroy(rsa_prv);
		yaca_key_destroy(rsa_pub);
		yaca_free(encrypted);
		yaca_free(decrypted);
	}
}

BOOST_FIXTURE_TEST_CASE(T402__negative__private_encrypt, InitDebugFixture)
{
	int ret;
	size_t bit_len = YACA_KEY_LENGTH_1024BIT;
	yaca_key_h key_prv = YACA_KEY_NULL, key_pub = YACA_KEY_NULL;
	yaca_key_h key_prv2 = YACA_KEY_NULL, key_pub2 = YACA_KEY_NULL;
	yaca_key_h key_dsa = YACA_KEY_NULL, key_ec = YACA_KEY_NULL;
	size_t input_len = bit_len / 8;
	size_t input_len_pkcs1 = bit_len / 8 - 11;
	char *encrypted = NULL, *encrypted_pkcs1 = NULL, *decrypted = NULL;
	size_t encrypted_len, encrypted_pkcs1_len, decrypted_len;

	generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, bit_len, &key_prv, &key_pub);
	generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, bit_len, &key_prv2, &key_pub2);
	generate_asymmetric_keys(YACA_KEY_TYPE_DSA_PRIV, bit_len, &key_dsa);
	generate_asymmetric_keys(YACA_KEY_TYPE_EC_PRIV, YACA_KEY_LENGTH_EC_PRIME256V1, &key_ec);

	ret = yaca_rsa_private_encrypt(YACA_INVALID_PADDING, key_prv,
								   INPUT_DATA, input_len,
								   &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_encrypt(YACA_PADDING_X931, key_prv,
								   INPUT_DATA, input_len,
								   &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_encrypt(YACA_PADDING_PKCS1_OAEP, key_prv,
								   INPUT_DATA, input_len,
								   &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_encrypt(YACA_PADDING_NONE, YACA_KEY_NULL,
								   INPUT_DATA, input_len,
								   &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_encrypt(YACA_PADDING_NONE, key_pub,
								   INPUT_DATA, input_len,
								   &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_encrypt(YACA_PADDING_NONE, key_ec,
								   INPUT_DATA, input_len,
								   &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_encrypt(YACA_PADDING_NONE, key_dsa,
								   INPUT_DATA, input_len,
								   &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_encrypt(YACA_PADDING_NONE, key_prv,
								   NULL, input_len,
								   &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_encrypt(YACA_PADDING_NONE, key_prv,
								   INPUT_DATA, 0,
								   &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_encrypt(YACA_PADDING_NONE, key_prv,
								   INPUT_DATA, input_len + 1,
								   &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_encrypt(YACA_PADDING_NONE, key_prv,
								   INPUT_DATA, input_len - 1,
								   &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_encrypt(YACA_PADDING_NONE, key_prv,
								   INPUT_DATA, input_len - 8,
								   &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_encrypt(YACA_PADDING_NONE, key_prv,
								   INPUT_DATA, input_len,
								   NULL, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_encrypt(YACA_PADDING_NONE, key_prv,
								   INPUT_DATA, input_len,
								   &encrypted, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_encrypt(YACA_PADDING_PKCS1, key_prv,
								   INPUT_DATA, input_len_pkcs1 + 1,
								   &encrypted_pkcs1, &encrypted_pkcs1_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_encrypt(YACA_PADDING_NONE, key_prv,
								   INPUT_DATA, input_len,
								   &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_rsa_private_encrypt(YACA_PADDING_PKCS1, key_prv,
								   INPUT_DATA, input_len_pkcs1,
								   &encrypted_pkcs1, &encrypted_pkcs1_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_rsa_public_decrypt(YACA_INVALID_PADDING, key_pub,
								  encrypted, encrypted_len,
								  &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_decrypt(YACA_PADDING_PKCS1_SSLV23, key_pub,
								  encrypted, encrypted_len,
								  &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_decrypt(YACA_PADDING_PKCS1, key_pub,
								  encrypted, encrypted_len,
								  &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_decrypt(YACA_PADDING_NONE, YACA_KEY_NULL,
								  encrypted, encrypted_len,
								  &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_decrypt(YACA_PADDING_NONE, key_prv,
								  encrypted, encrypted_len,
								  &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_decrypt(YACA_PADDING_NONE, key_ec,
								  encrypted, encrypted_len,
								  &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_decrypt(YACA_PADDING_NONE, key_dsa,
								  encrypted, encrypted_len,
								  &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_decrypt(YACA_PADDING_NONE, key_pub,
								  NULL, encrypted_len,
								  &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_decrypt(YACA_PADDING_NONE, key_pub,
								  encrypted, 0,
								  &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_decrypt(YACA_PADDING_NONE, key_pub,
								  encrypted, encrypted_len,
								  NULL, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_decrypt(YACA_PADDING_NONE, key_pub,
								  encrypted, encrypted_len,
								  &decrypted, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_decrypt(YACA_PADDING_PKCS1_PSS, key_pub,
								  encrypted_pkcs1, encrypted_pkcs1_len,
								  &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_decrypt(YACA_PADDING_X931, key_pub,
								  encrypted_pkcs1, encrypted_pkcs1_len,
								  &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_decrypt(YACA_PADDING_PKCS1, key_pub2,
								  encrypted_pkcs1, encrypted_pkcs1_len,
								  &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_decrypt(YACA_PADDING_PKCS1, key_pub,
								  encrypted_pkcs1, encrypted_pkcs1_len - 1,
								  &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_decrypt(YACA_PADDING_PKCS1, key_pub,
								  encrypted_pkcs1 + 1, encrypted_pkcs1_len - 1,
								  &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	yaca_key_destroy(key_prv);
	yaca_key_destroy(key_pub);
	yaca_key_destroy(key_prv2);
	yaca_key_destroy(key_pub2);
	yaca_key_destroy(key_dsa);
	yaca_key_destroy(key_ec);
	yaca_free(encrypted);
	yaca_free(encrypted_pkcs1);
}

BOOST_FIXTURE_TEST_CASE(T403__positive__public_encrypt, InitDebugFixture)
{
	struct rsa_args {
		yaca_padding_e pad;
		yaca_key_bit_length_e bit_len;
		size_t shorter;
	};

	const std::vector<struct rsa_args> rargs = {
		{YACA_PADDING_NONE,         YACA_KEY_LENGTH_512BIT,   0},
		{YACA_PADDING_PKCS1,        YACA_KEY_LENGTH_1024BIT, 11},
		{YACA_PADDING_PKCS1_OAEP,   YACA_KEY_LENGTH_2048BIT, 42},
	};

	for (const auto &ra: rargs) {
		int ret;
		yaca_key_h rsa_prv = YACA_KEY_NULL, rsa_pub = YACA_KEY_NULL;
		size_t input_len = ra.bit_len / 8 - ra.shorter;
		char *encrypted = NULL, *decrypted = NULL;
		size_t encrypted_len, decrypted_len;

		generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, ra.bit_len, &rsa_prv, &rsa_pub);

		ret = yaca_rsa_public_encrypt(ra.pad, rsa_pub, INPUT_DATA, input_len,
									  &encrypted, &encrypted_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_rsa_private_decrypt(ra.pad, rsa_prv, encrypted, encrypted_len,
									   &decrypted, &decrypted_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		BOOST_REQUIRE(decrypted_len == input_len);
		ret = yaca_memcmp(decrypted, INPUT_DATA, input_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		yaca_key_destroy(rsa_prv);
		yaca_key_destroy(rsa_pub);
		yaca_free(encrypted);
		yaca_free(decrypted);
	}

	/* Empty input, must use padding */
	for (const auto &ra: rargs) {
		if (ra.pad == YACA_PADDING_NONE)
			continue;

		int ret;
		yaca_key_h rsa_prv = YACA_KEY_NULL, rsa_pub = YACA_KEY_NULL;
		char *encrypted = NULL, *decrypted = NULL;
		size_t encrypted_len, decrypted_len;

		generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, ra.bit_len, &rsa_prv, &rsa_pub);

		ret = yaca_rsa_public_encrypt(ra.pad, rsa_pub, NULL, 0,
									  &encrypted, &encrypted_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_rsa_private_decrypt(ra.pad, rsa_prv, encrypted, encrypted_len,
									   &decrypted, &decrypted_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		BOOST_REQUIRE(decrypted_len == 0);
		BOOST_REQUIRE(decrypted == NULL);

		yaca_key_destroy(rsa_prv);
		yaca_key_destroy(rsa_pub);
		yaca_free(encrypted);
		yaca_free(decrypted);
	}
}

BOOST_FIXTURE_TEST_CASE(T404__negative__public_encrypt, InitDebugFixture)
{
	int ret;
	size_t bit_len = YACA_KEY_LENGTH_1024BIT;
	yaca_key_h key_prv = YACA_KEY_NULL, key_pub = YACA_KEY_NULL;
	yaca_key_h key_prv2 = YACA_KEY_NULL, key_pub2 = YACA_KEY_NULL;
	yaca_key_h key_dsa = YACA_KEY_NULL, key_ec = YACA_KEY_NULL;
	size_t input_len = bit_len / 8;
	size_t input_len_pkcs1 = bit_len / 8 - 11;
	size_t input_len_pkcs1_oaep = bit_len / 8 - 42;
	size_t input_len_pkcs1_sslv23 = bit_len / 8 - 11;
	char *encrypted = NULL, *encrypted_pkcs1 = NULL;
	char *encrypted_pkcs1_oaep = NULL, *encrypted_pkcs1_sslv23 = NULL;
	char *decrypted = NULL;
	size_t encrypted_len, encrypted_pkcs1_len, encrypted_pkcs1_oaep_len;
	size_t encrypted_pkcs1_sslv23_len, decrypted_len;

	generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, bit_len, &key_prv, &key_pub);
	generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, bit_len, &key_prv2, &key_pub2);
	generate_asymmetric_keys(YACA_KEY_TYPE_DSA_PRIV, bit_len, &key_dsa);
	generate_asymmetric_keys(YACA_KEY_TYPE_EC_PRIV, YACA_KEY_LENGTH_EC_PRIME256V1, &key_ec);

	ret = yaca_rsa_public_encrypt(YACA_INVALID_PADDING, key_pub,
								  INPUT_DATA, input_len,
								  &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_encrypt(YACA_PADDING_X931, key_pub,
								  INPUT_DATA, input_len,
								  &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_encrypt(YACA_PADDING_PKCS1_PSS, key_pub,
								  INPUT_DATA, input_len,
								  &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_encrypt(YACA_PADDING_NONE, YACA_KEY_NULL,
								  INPUT_DATA, input_len,
								  &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_encrypt(YACA_PADDING_NONE, key_prv,
								  INPUT_DATA, input_len,
								  &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_encrypt(YACA_PADDING_NONE, key_ec,
								  INPUT_DATA, input_len,
								  &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_encrypt(YACA_PADDING_NONE, key_dsa,
								  INPUT_DATA, input_len,
								  &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_encrypt(YACA_PADDING_NONE, key_pub,
								  NULL, input_len,
								  &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_encrypt(YACA_PADDING_NONE, key_pub,
								  INPUT_DATA, 0,
								  &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_encrypt(YACA_PADDING_NONE, key_pub,
								  INPUT_DATA, input_len + 1,
								  &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_encrypt(YACA_PADDING_NONE, key_pub,
								  INPUT_DATA, input_len - 1,
								  &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_encrypt(YACA_PADDING_NONE, key_pub,
								  INPUT_DATA, input_len - 8,
								  &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_encrypt(YACA_PADDING_NONE, key_pub,
								  INPUT_DATA, input_len,
								  NULL, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_encrypt(YACA_PADDING_NONE, key_pub,
								  INPUT_DATA, input_len,
								  &encrypted, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_encrypt(YACA_PADDING_PKCS1, key_pub,
								  INPUT_DATA, input_len_pkcs1 + 1,
								  &encrypted_pkcs1, &encrypted_pkcs1_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_encrypt(YACA_PADDING_PKCS1_OAEP, key_pub,
								  INPUT_DATA, input_len_pkcs1_oaep + 1,
								  &encrypted_pkcs1_oaep, &encrypted_pkcs1_oaep_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_encrypt(YACA_PADDING_PKCS1_SSLV23, key_pub,
								  INPUT_DATA, input_len_pkcs1_sslv23 + 1,
								  &encrypted_pkcs1_sslv23, &encrypted_pkcs1_sslv23_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_public_encrypt(YACA_PADDING_NONE, key_pub,
								  INPUT_DATA, input_len,
								  &encrypted, &encrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_rsa_public_encrypt(YACA_PADDING_PKCS1, key_pub,
								  INPUT_DATA, input_len_pkcs1,
								  &encrypted_pkcs1, &encrypted_pkcs1_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_rsa_public_encrypt(YACA_PADDING_PKCS1_OAEP, key_pub,
								  INPUT_DATA, input_len_pkcs1_oaep,
								  &encrypted_pkcs1_oaep, &encrypted_pkcs1_oaep_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_rsa_public_encrypt(YACA_PADDING_PKCS1_SSLV23, key_pub,
								  INPUT_DATA, input_len_pkcs1_sslv23,
								  &encrypted_pkcs1_sslv23, &encrypted_pkcs1_sslv23_len);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	ret = yaca_rsa_private_decrypt(YACA_INVALID_PADDING, key_prv,
								   encrypted, encrypted_len,
								   &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_decrypt(YACA_PADDING_X931, key_prv,
								   encrypted, encrypted_len,
								   &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_decrypt(YACA_PADDING_PKCS1, key_prv,
								   encrypted, encrypted_len,
								   &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_decrypt(YACA_PADDING_NONE, YACA_KEY_NULL,
								   encrypted, encrypted_len,
								   &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_decrypt(YACA_PADDING_NONE, key_pub,
								   encrypted, encrypted_len,
								   &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_decrypt(YACA_PADDING_NONE, key_ec,
								   encrypted, encrypted_len,
								   &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_decrypt(YACA_PADDING_NONE, key_dsa,
								   encrypted, encrypted_len,
								   &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_decrypt(YACA_PADDING_NONE, key_prv,
								   NULL, encrypted_len,
								   &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_decrypt(YACA_PADDING_NONE, key_prv,
								   encrypted, 0,
								   &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_decrypt(YACA_PADDING_NONE, key_prv,
								   encrypted, encrypted_len,
								   NULL, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_decrypt(YACA_PADDING_NONE, key_prv,
								   encrypted, encrypted_len,
								   &decrypted, NULL);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_decrypt(YACA_PADDING_PKCS1_PSS, key_prv,
								   encrypted_pkcs1, encrypted_pkcs1_len,
								   &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_decrypt(YACA_PADDING_PKCS1, key_prv,
								   encrypted_pkcs1, encrypted_pkcs1_len - 1,
								   &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_decrypt(YACA_PADDING_PKCS1, key_prv,
								   encrypted_pkcs1_oaep, encrypted_pkcs1_oaep_len,
								   &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_decrypt(YACA_PADDING_PKCS1_SSLV23, key_prv,
								   encrypted_pkcs1_oaep, encrypted_pkcs1_oaep_len,
								   &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_decrypt(YACA_PADDING_PKCS1_OAEP, key_prv,
								   encrypted_pkcs1_oaep, encrypted_pkcs1_oaep_len - 1,
								   &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_decrypt(YACA_PADDING_PKCS1_OAEP, key_prv,
								   encrypted_pkcs1_sslv23, encrypted_pkcs1_sslv23_len,
								   &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	ret = yaca_rsa_private_decrypt(YACA_PADDING_PKCS1_SSLV23, key_prv,
								   encrypted_pkcs1_sslv23, encrypted_pkcs1_sslv23_len - 1,
								   &decrypted, &decrypted_len);
	BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

	yaca_key_destroy(key_prv);
	yaca_key_destroy(key_pub);
	yaca_key_destroy(key_prv2);
	yaca_key_destroy(key_pub2);
	yaca_key_destroy(key_dsa);
	yaca_key_destroy(key_ec);
	yaca_free(encrypted);
	yaca_free(encrypted_pkcs1);
	yaca_free(encrypted_pkcs1_oaep);
	yaca_free(encrypted_pkcs1_sslv23);
}

BOOST_AUTO_TEST_SUITE_END()
