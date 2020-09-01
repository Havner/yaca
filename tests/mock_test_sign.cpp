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
 * @file    test_sign.cpp
 * @author  Lukasz Pawelczyk <l.pawelczyk@samsung.com>
 * @brief   Signature API unit tests.
 */

#include <boost/test/unit_test.hpp>
#include <vector>

#include <yaca_crypto.h>
#include <yaca_sign.h>
#include <yaca_key.h>
#include <yaca_digest.h>
#include <yaca_error.h>

#include "common.h"


BOOST_AUTO_TEST_SUITE(MOCK_TESTS_SIGN)

BOOST_FIXTURE_TEST_CASE(T1801__mock__negative__sign_verify, InitFixture)
{
	struct sign_args {
		yaca_key_type_e type_prv;
		yaca_key_type_e type_pub;
		yaca_key_bit_length_e len;
		yaca_digest_algorithm_e digest;
		yaca_padding_e pad;
	};

	const std::vector<sign_args> sargs = {
		{YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_TYPE_RSA_PUB, YACA_KEY_LENGTH_512BIT,
		 YACA_DIGEST_SHA1, YACA_PADDING_X931},
		{YACA_KEY_TYPE_DSA_PRIV, YACA_KEY_TYPE_DSA_PUB, YACA_KEY_LENGTH_512BIT,
		 YACA_DIGEST_SHA224, YACA_INVALID_PADDING},
		{YACA_KEY_TYPE_EC_PRIV, YACA_KEY_TYPE_EC_PUB,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_PRIME192V1,
		 YACA_DIGEST_SHA384, YACA_INVALID_PADDING}
	};

	for (const auto &sa: sargs) {
		auto test_code = [&sa]() -> int
			{
				int ret;
				yaca_context_h ctx = YACA_CONTEXT_NULL;
				yaca_key_h key_prv = YACA_KEY_NULL, key_pub = YACA_KEY_NULL;

				char *signature = NULL;
				size_t signature_len;

				ret = yaca_key_generate(sa.type_prv, sa.len, &key_prv);
				if (ret != YACA_ERROR_NONE) goto exit;
				ret = yaca_key_extract_public(key_prv, &key_pub);
				if (ret != YACA_ERROR_NONE) goto exit;

				/* SIGN */
				{
					ret = yaca_sign_initialize(&ctx, sa.digest, key_prv);
					if (ret != YACA_ERROR_NONE) goto exit;

					if (sa.pad != YACA_INVALID_PADDING) {
						ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
						                                &sa.pad, sizeof(sa.pad));
						if (ret != YACA_ERROR_NONE) goto exit;
					}

					ret = yaca_sign_update(ctx, INPUT_DATA, INPUT_DATA_SIZE);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_get_output_length(ctx, 0, &signature_len);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_malloc(signature_len, (void **)&signature);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_sign_finalize(ctx, signature, &signature_len);
					if (ret != YACA_ERROR_NONE) goto exit;

					yaca_context_destroy(ctx);
					ctx = YACA_CONTEXT_NULL;
				}

				/* VERIFY */
				{
					ret = yaca_verify_initialize(&ctx, sa.digest, key_pub);
					if (ret != YACA_ERROR_NONE) goto exit;

					if (sa.pad != YACA_INVALID_PADDING) {
						ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
						                                &sa.pad, sizeof(sa.pad));
						if (ret != YACA_ERROR_NONE) goto exit;
					}

					ret = yaca_verify_update(ctx, INPUT_DATA, INPUT_DATA_SIZE);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_verify_finalize(ctx, signature, signature_len);
					if (ret != YACA_ERROR_NONE) goto exit;

					yaca_context_destroy(ctx);
					ctx = YACA_CONTEXT_NULL;
				}

			exit:
				yaca_context_destroy(ctx);
				yaca_key_destroy(key_prv);
				yaca_key_destroy(key_pub);
				yaca_free(signature);
				return ret;
			};

		call_mock_test(test_code);
	}
}

BOOST_FIXTURE_TEST_CASE(T1802__mock__negative__sign_cmac, InitFixture)
{
	struct cmac_args {
		yaca_key_type_e type;
		yaca_key_bit_length_e len;
		yaca_encrypt_algorithm_e algo;
	};

	const std::vector<cmac_args> cargs = {
		{YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_UNSAFE_64BIT,
		 YACA_ENCRYPT_UNSAFE_DES},
		{YACA_KEY_TYPE_DES, YACA_KEY_LENGTH_192BIT,
		 YACA_ENCRYPT_3DES_3TDEA}
	};

	for (const auto &ca: cargs) {
		auto test_code = [&ca]() -> int
			{
				int ret;
				yaca_context_h ctx = YACA_CONTEXT_NULL;
				yaca_key_h key = YACA_KEY_NULL;

				char *signature = NULL;
				size_t signature_len;

				ret = yaca_key_generate(ca.type, ca.len, &key);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_sign_initialize_cmac(&ctx, ca.algo, key);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_sign_update(ctx, INPUT_DATA, INPUT_DATA_SIZE);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_context_get_output_length(ctx, 0, &signature_len);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_malloc(signature_len, (void **)&signature);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_sign_finalize(ctx, signature, &signature_len);
				if (ret != YACA_ERROR_NONE) goto exit;

			exit:
				yaca_context_destroy(ctx);
				yaca_key_destroy(key);
				yaca_free(signature);
				return ret;
			};

		call_mock_test(test_code);
	}
}

BOOST_FIXTURE_TEST_CASE(T1803__mock__negative__sign_hmac, InitFixture)
{
	struct hmac_args {
		yaca_key_type_e type;
		yaca_key_bit_length_e len;
		yaca_digest_algorithm_e digest;
	};

	const std::vector<hmac_args> hargs = {
		{YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_UNSAFE_128BIT,
		 YACA_DIGEST_SHA1},
		{YACA_KEY_TYPE_DES, YACA_KEY_LENGTH_UNSAFE_128BIT,
		 YACA_DIGEST_SHA224}
	};

	for (const auto &ha: hargs) {
		auto test_code = [&ha]() -> int
			{
				int ret;
				yaca_context_h ctx = YACA_CONTEXT_NULL;
				yaca_key_h key = YACA_KEY_NULL;

				char *signature = NULL;
				size_t signature_len;

				ret = yaca_key_generate(ha.type, ha.len, &key);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_sign_initialize_hmac(&ctx, ha.digest, key);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_sign_update(ctx, INPUT_DATA, INPUT_DATA_SIZE);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_context_get_output_length(ctx, 0, &signature_len);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_malloc(signature_len, (void **)&signature);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_sign_finalize(ctx, signature, &signature_len);
				if (ret != YACA_ERROR_NONE) goto exit;

			exit:
				yaca_context_destroy(ctx);
				yaca_key_destroy(key);
				yaca_free(signature);
				return ret;
			};

		call_mock_test(test_code);
	}
}

BOOST_AUTO_TEST_SUITE_END()
