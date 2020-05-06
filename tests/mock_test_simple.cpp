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
 * @file    test_simple.cpp
 * @author  Lukasz Pawelczyk <l.pawelczyk@samsung.com>
 * @brief   Simple API unit tests.
 */

#include <boost/test/unit_test.hpp>
#include <vector>

#include <yaca_crypto.h>
#include <yaca_encrypt.h>
#include <yaca_key.h>
#include <yaca_simple.h>
#include <yaca_error.h>

#include "common.h"


BOOST_AUTO_TEST_SUITE(MOCK_TESTS_SIMPLE)

BOOST_FIXTURE_TEST_CASE(T1301__mock__negative__positive__simple_encrypt_decrypt, InitFixture)
{
	struct encrypt_args {
		yaca_encrypt_algorithm_e algo;
		yaca_block_cipher_mode_e bcm;
		size_t key_bit_len;
	};

	const std::vector<struct encrypt_args> eargs = {
		{YACA_ENCRYPT_AES,        YACA_BCM_CBC, YACA_KEY_LENGTH_256BIT       },
		{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_ECB, YACA_KEY_LENGTH_192BIT       },
		{YACA_ENCRYPT_CAST5,      YACA_BCM_OFB, YACA_KEY_LENGTH_UNSAFE_128BIT}
	};

	for (const auto &ea: eargs) {
		auto test_case = [&ea]() -> int
			{
				int ret;
				yaca_key_h sym = YACA_KEY_NULL, iv = YACA_KEY_NULL;
				size_t iv_bit_len;
				char *encrypted = NULL, *decrypted = NULL;
				size_t encrypted_len, decrypted_len;

				ret = yaca_encrypt_get_iv_bit_length(ea.algo, ea.bcm, ea.key_bit_len, &iv_bit_len);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, ea.key_bit_len, &sym);
				if (ret != YACA_ERROR_NONE) goto exit;

				if (iv_bit_len > 0) {
					ret = yaca_key_generate(YACA_KEY_TYPE_IV, iv_bit_len, &iv);
					if (ret != YACA_ERROR_NONE) goto exit;
				}

				ret = yaca_simple_encrypt(ea.algo, ea.bcm, sym, iv, INPUT_DATA, INPUT_DATA_SIZE,
										  &encrypted, &encrypted_len);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_simple_decrypt(ea.algo, ea.bcm, sym, iv, encrypted, encrypted_len,
										  &decrypted, &decrypted_len);
				if (ret != YACA_ERROR_NONE) goto exit;

			exit:
				yaca_key_destroy(sym);
				yaca_key_destroy(iv);
				yaca_free(encrypted);
				yaca_free(decrypted);
				return ret;
			};

		call_mock_test(test_case);
	}
}

BOOST_FIXTURE_TEST_CASE(T1302__mock__negative__simple_calculate_digest, InitFixture)
{
	struct digest_args {
		yaca_digest_algorithm_e algo = YACA_DIGEST_SHA256;
	};

	const std::vector<struct digest_args> dargs = {
		{YACA_DIGEST_MD5},
		{YACA_DIGEST_SHA256}
	};

	for (const auto &da: dargs) {
		auto test_code = [&da]() -> int
			{
				int ret;
				char *digest = NULL;
				size_t digest_len;

				ret = yaca_simple_calculate_digest(da.algo, INPUT_DATA, INPUT_DATA_SIZE,
												   &digest, &digest_len);
				yaca_free(digest);
				return ret;
			};

		call_mock_test(test_code);
	}
}

BOOST_FIXTURE_TEST_CASE(T1303__mock__negative__simple_calculate_verify_signature, InitFixture)
{
	struct signature_args {
		yaca_key_type_e type;
		yaca_key_bit_length_e len;
		yaca_digest_algorithm_e algo;
	};

	const std::vector<struct signature_args> sargs = {
		{YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_512BIT, YACA_DIGEST_MD5},
		{YACA_KEY_TYPE_DSA_PRIV, YACA_KEY_LENGTH_512BIT, YACA_DIGEST_SHA256},
		{YACA_KEY_TYPE_EC_PRIV, (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_PRIME192V1,
		 YACA_DIGEST_SHA224}
	};

	for (const auto &sa: sargs) {
		auto test_code = [&sa]() -> int
			{
				int ret;
				yaca_key_h key_priv = YACA_KEY_NULL;
				yaca_key_h key_pub = YACA_KEY_NULL;

				char *signature = NULL;
				size_t signature_len;

				ret = yaca_key_generate(sa.type, sa.len, &key_priv);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_key_extract_public(key_priv, &key_pub);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_simple_calculate_signature(sa.algo, key_priv,
													  INPUT_DATA, INPUT_DATA_SIZE,
													  &signature, &signature_len);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_simple_verify_signature(sa.algo, key_pub,
												   INPUT_DATA, INPUT_DATA_SIZE,
												   signature, signature_len);
				if (ret != YACA_ERROR_NONE) goto exit;

			exit:
				yaca_key_destroy(key_priv);
				yaca_key_destroy(key_pub);
				yaca_free(signature);
				return ret;
			};

		call_mock_test(test_code);
	}
}

BOOST_FIXTURE_TEST_CASE(T1304__mock__negative__simple_calculate_hmac, InitFixture)
{
	struct hmac_args {
		yaca_key_type_e type;
		yaca_key_bit_length_e len;
		yaca_digest_algorithm_e algo;
	};

	const std::vector<struct hmac_args> hargs = {
		{YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_192BIT, YACA_DIGEST_MD5},
		{YACA_KEY_TYPE_DES, YACA_KEY_LENGTH_UNSAFE_128BIT, YACA_DIGEST_SHA1}
	};

	for (const auto &ha: hargs) {
		auto test_code = [&ha]() -> int
			{
				int ret;
				yaca_key_h key = YACA_KEY_NULL;
				char *mac = NULL;
				size_t mac_len;

				ret = yaca_key_generate(ha.type, ha.len, &key);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_simple_calculate_hmac(ha.algo, key,
												 INPUT_DATA, INPUT_DATA_SIZE,
												 &mac, &mac_len);
				if (ret != YACA_ERROR_NONE) goto exit;

			exit:
				yaca_key_destroy(key);
				yaca_free(mac);
				return ret;
			};

		call_mock_test(test_code);
	}
}

BOOST_FIXTURE_TEST_CASE(T1305__mock__negative__simple_calculate_cmac, InitFixture)
{
	struct cmac_args {
		yaca_key_type_e type;
		yaca_key_bit_length_e len;
		yaca_encrypt_algorithm_e algo;
	};

	const std::vector<struct cmac_args> cargs = {
		{YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_192BIT, YACA_ENCRYPT_AES},
		{YACA_KEY_TYPE_DES, YACA_KEY_LENGTH_UNSAFE_64BIT, YACA_ENCRYPT_UNSAFE_DES}
	};

	for (const auto &ca: cargs) {
		auto test_code = [&ca]() -> int
			{
				int ret;
				yaca_key_h key = YACA_KEY_NULL;
				char *mac = NULL;
				size_t mac_len;

				ret = yaca_key_generate(ca.type, ca.len, &key);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_simple_calculate_cmac(ca.algo, key,
												 INPUT_DATA, INPUT_DATA_SIZE,
												 &mac, &mac_len);
				if (ret != YACA_ERROR_NONE) goto exit;

			exit:
				yaca_key_destroy(key);
				yaca_free(mac);
				return ret;
			};

		call_mock_test(test_code);
	}
}

BOOST_AUTO_TEST_SUITE_END()
