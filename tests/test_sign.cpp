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


namespace {

using update_fun_3_t = int(yaca_context_h ctx, const char *input, size_t input_len);

void call_update_loop(yaca_context_h &ctx, const char *input, size_t input_len,
                      size_t split, update_fun_3_t *fun)
{
	BOOST_REQUIRE_MESSAGE(split >= 1, "Fix your test");

	int ret;
	size_t left = input_len;
	size_t part = input_len / split;

	BOOST_REQUIRE_MESSAGE(part >= 1, "Fix your test");

	for (;;) {
		ret = fun(ctx, input, part);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		input += part;
		left -= part;

		if (left == 0)
			break;

		if (left < part)
			part = left;
	}
}

} //namespace


BOOST_AUTO_TEST_SUITE(TESTS_SIGN)

BOOST_FIXTURE_TEST_CASE(T801__positive__sign_verify, InitDebugFixture)
{
	struct sign_args {
		yaca_key_type_e type_prv;
		yaca_key_bit_length_e key_bit_len;
		yaca_digest_algorithm_e digest;
		yaca_padding_e pad;
		size_t split;
	};

	const std::vector<sign_args> sargs = {
		{YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_512BIT,
		 YACA_DIGEST_MD5, YACA_INVALID_PADDING, 27},
		{YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_1024BIT,
		 YACA_DIGEST_MD5, YACA_PADDING_PKCS1_PSS, 14},
		{YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_2048BIT,
		 YACA_DIGEST_SHA1, YACA_PADDING_X931, 34},
		{YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_1024BIT,
		 YACA_DIGEST_SHA384, YACA_PADDING_PKCS1, 9},
		{YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_2048BIT,
		 YACA_DIGEST_SHA512, YACA_PADDING_PKCS1_PSS, 12},

		{YACA_KEY_TYPE_DSA_PRIV, YACA_KEY_LENGTH_512BIT,
		 YACA_DIGEST_SHA256, YACA_INVALID_PADDING, 5},
		{YACA_KEY_TYPE_DSA_PRIV, YACA_KEY_LENGTH_1024BIT,
		 YACA_DIGEST_SHA224, YACA_INVALID_PADDING, 31},
		{YACA_KEY_TYPE_DSA_PRIV, YACA_KEY_LENGTH_2048BIT,
		 YACA_DIGEST_SHA1, YACA_INVALID_PADDING, 29},
		{YACA_KEY_TYPE_DSA_PRIV, YACA_KEY_LENGTH_1024BIT,
		 YACA_DIGEST_SHA384, YACA_INVALID_PADDING, 19},
		{YACA_KEY_TYPE_DSA_PRIV, YACA_KEY_LENGTH_2048BIT,
		 YACA_DIGEST_SHA512, YACA_INVALID_PADDING, 11},

		{YACA_KEY_TYPE_EC_PRIV,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_PRIME192V2,
		 YACA_DIGEST_SHA256, YACA_INVALID_PADDING, 13},
		{YACA_KEY_TYPE_EC_PRIV,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_PRIME256V1,
		 YACA_DIGEST_SHA256, YACA_INVALID_PADDING, 13},
		{YACA_KEY_TYPE_EC_PRIV,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_C2PNB272W1,
		 YACA_DIGEST_SHA256, YACA_INVALID_PADDING, 13},
		{YACA_KEY_TYPE_EC_PRIV,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_C2TNB191V3,
		 YACA_DIGEST_SHA256, YACA_INVALID_PADDING, 13},
		{YACA_KEY_TYPE_EC_PRIV,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_SECP160K1,
		 YACA_DIGEST_SHA224, YACA_INVALID_PADDING, 23},
		{YACA_KEY_TYPE_EC_PRIV,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_SECP384R1,
		 YACA_DIGEST_SHA224, YACA_INVALID_PADDING, 23},
		{YACA_KEY_TYPE_EC_PRIV,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_SECT239K1,
		 YACA_DIGEST_SHA1, YACA_INVALID_PADDING, 33},
		{YACA_KEY_TYPE_EC_PRIV,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_SECT409R1,
		 YACA_DIGEST_SHA1, YACA_INVALID_PADDING, 33},
		{YACA_KEY_TYPE_EC_PRIV,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_BRAINPOOLP192R1,
		 YACA_DIGEST_SHA384, YACA_INVALID_PADDING, 22},
		{YACA_KEY_TYPE_EC_PRIV,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_BRAINPOOLP320T1,
		 YACA_DIGEST_SHA384, YACA_INVALID_PADDING, 22}
	};

	for (const auto &sa: sargs) {
		int ret;
		yaca_context_h ctx = YACA_CONTEXT_NULL;
		yaca_key_h key_prv = YACA_KEY_NULL, key_pub = YACA_KEY_NULL;

		char *signature = NULL;
		size_t signature_len;

		generate_asymmetric_keys(sa.type_prv, sa.key_bit_len, &key_prv, &key_pub);

		/* SIGN */
		{
			ret = yaca_sign_initialize(&ctx, sa.digest, key_prv);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			if (sa.pad != YACA_INVALID_PADDING) {
				ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
				                                &sa.pad, sizeof(sa.pad));
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			}

			call_update_loop(ctx, INPUT_DATA, INPUT_DATA_SIZE,
			                 sa.split, &yaca_sign_update);

			ret = yaca_context_get_output_length(ctx, 0, &signature_len);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			ret = yaca_malloc(signature_len, (void **)&signature);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			ret = yaca_sign_finalize(ctx, signature, &signature_len);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			yaca_context_destroy(ctx);
			ctx = YACA_CONTEXT_NULL;
		}

		/* VERIFY */
		{
			ret = yaca_verify_initialize(&ctx, sa.digest, key_pub);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			if (sa.pad != YACA_INVALID_PADDING) {
				ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
				                                &sa.pad, sizeof(sa.pad));
				BOOST_REQUIRE(ret == YACA_ERROR_NONE);
			}

			call_update_loop(ctx, INPUT_DATA, INPUT_DATA_SIZE,
			                 sa.split + 3, &yaca_verify_update);

			ret = yaca_verify_finalize(ctx, signature, signature_len);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			yaca_context_destroy(ctx);
			ctx = YACA_CONTEXT_NULL;
		}

		yaca_key_destroy(key_prv);
		yaca_key_destroy(key_pub);
		yaca_free(signature);
	}
}

BOOST_FIXTURE_TEST_CASE(T802__negative__sign_verify, InitDebugFixture)
{
	int ret;
	yaca_context_h ctx = YACA_CONTEXT_NULL, ctx_digest = YACA_CONTEXT_NULL;
	yaca_key_h key_rsa_prv = YACA_KEY_NULL, key_rsa_pub = YACA_KEY_NULL;
	yaca_key_h key_rsa_prv2 = YACA_KEY_NULL, key_rsa_pub2 = YACA_KEY_NULL;
	yaca_key_h key_dsa_prv = YACA_KEY_NULL, key_dsa_pub = YACA_KEY_NULL;
	yaca_key_h key_sym = YACA_KEY_NULL, key_rsa_prv_short = YACA_KEY_NULL;
	yaca_padding_e pad_invalid = YACA_PADDING_X931, pad_none = YACA_PADDING_NONE;
	yaca_padding_e pad = YACA_PADDING_PKCS1, pad2 = YACA_PADDING_PKCS1_PSS;

	size_t len = 128;

	char *signature = NULL;
	size_t signature_len;

	ret = yaca_digest_initialize(&ctx_digest, YACA_DIGEST_MD5);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, &key_sym);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_512BIT, &key_rsa_prv_short);
	generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_1024BIT, &key_rsa_prv, &key_rsa_pub);
	generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_1024BIT, &key_rsa_prv2, &key_rsa_pub2);
	generate_asymmetric_keys(YACA_KEY_TYPE_DSA_PRIV, YACA_KEY_LENGTH_1024BIT, &key_dsa_prv, &key_dsa_pub);

	/* SIGN */
	{
		ret = yaca_sign_initialize(NULL, YACA_DIGEST_MD5, key_rsa_prv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_initialize(&ctx, YACA_INVALID_DIGEST_ALGORITHM, key_rsa_prv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_initialize(&ctx, YACA_DIGEST_MD5, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_initialize(&ctx, YACA_DIGEST_MD5, key_rsa_pub);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_initialize(&ctx, YACA_DIGEST_MD5, key_sym);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_initialize(&ctx, YACA_DIGEST_SHA384, key_rsa_prv_short);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_initialize(&ctx, YACA_DIGEST_MD5, key_rsa_prv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_INVALID_PROPERTY,
		                                &pad, sizeof(pad));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                NULL, sizeof(pad));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad, 1);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS,
		                                &len, sizeof(size_t));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad_none, sizeof(pad_none));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad_invalid, sizeof(pad_invalid));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad, sizeof(pad));
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_sign_update(YACA_CONTEXT_NULL, INPUT_DATA, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_update(ctx, NULL, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_update(ctx, INPUT_DATA, 0);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_update(ctx_digest, INPUT_DATA, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_update(ctx, INPUT_DATA, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_get_output_length(ctx, 0, NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_get_output_length(ctx, 1, &signature_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_get_output_length(ctx, 0, &signature_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_malloc(signature_len, (void **)&signature);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_sign_finalize(YACA_CONTEXT_NULL, signature, &signature_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_finalize(ctx, NULL, &signature_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_finalize(ctx, signature, NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_finalize(ctx, signature, &signature_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_sign_update(ctx, INPUT_DATA, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_finalize(ctx, signature, &signature_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* VERIFY */
	{
		ret = yaca_verify_initialize(NULL, YACA_DIGEST_MD5, key_rsa_pub);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_verify_initialize(&ctx, YACA_INVALID_DIGEST_ALGORITHM, key_rsa_pub);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_verify_initialize(&ctx, YACA_DIGEST_MD5, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_verify_initialize(&ctx, YACA_DIGEST_MD5, key_rsa_prv);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_verify_initialize(&ctx, YACA_DIGEST_MD5, key_sym);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_verify_initialize(&ctx, YACA_DIGEST_SHA384, key_rsa_prv_short);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_verify_initialize(&ctx, YACA_DIGEST_MD5, key_rsa_pub);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_INVALID_PROPERTY,
		                                &pad, sizeof(pad));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                NULL, sizeof(pad));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad, 1);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS,
		                                &len, sizeof(size_t));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad_none, sizeof(pad_none));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad_invalid, sizeof(pad_invalid));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad, sizeof(pad));
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_verify_update(YACA_CONTEXT_NULL, INPUT_DATA, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_verify_update(ctx, NULL, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_verify_update(ctx, INPUT_DATA, 0);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_verify_update(ctx_digest, INPUT_DATA, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_verify_update(ctx, INPUT_DATA, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_verify_finalize(YACA_CONTEXT_NULL, signature, signature_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_verify_finalize(ctx, NULL, signature_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_verify_finalize(ctx, signature, 0);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_verify_finalize(ctx_digest, signature, signature_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_verify_finalize(ctx, signature, signature_len - 1);
		BOOST_REQUIRE(ret == YACA_ERROR_DATA_MISMATCH);

		ret = yaca_verify_finalize(ctx, signature + 1, signature_len - 1);
		BOOST_REQUIRE(ret == YACA_ERROR_DATA_MISMATCH);

		ret = yaca_verify_finalize(ctx, signature, signature_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_verify_update(ctx, INPUT_DATA, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_verify_finalize(ctx, signature, signature_len);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* VERIFY, wrong algo */
	{
		ret = yaca_verify_initialize(&ctx, YACA_DIGEST_SHA1, key_rsa_pub);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad, sizeof(pad));
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_verify_update(ctx, INPUT_DATA, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_verify_finalize(ctx, signature, signature_len);
		BOOST_REQUIRE(ret == YACA_ERROR_DATA_MISMATCH);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* VERIFY, wrong key */
	{
		ret = yaca_verify_initialize(&ctx, YACA_DIGEST_MD5, key_rsa_pub2);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad, sizeof(pad));
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_verify_update(ctx, INPUT_DATA, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_verify_finalize(ctx, signature, signature_len);
		BOOST_REQUIRE(ret == YACA_ERROR_DATA_MISMATCH);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* VERIFY, wrong padding */
	{
		ret = yaca_verify_initialize(&ctx, YACA_DIGEST_MD5, key_rsa_pub);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad2, sizeof(pad2));
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_verify_update(ctx, INPUT_DATA, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_verify_finalize(ctx, signature, signature_len);
		BOOST_REQUIRE(ret == YACA_ERROR_DATA_MISMATCH);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* SIGN DSA */
	{
		ret = yaca_sign_initialize(&ctx, YACA_DIGEST_SHA1, key_dsa_prv);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad, sizeof(pad));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad2, sizeof(pad2));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad_invalid, sizeof(pad_invalid));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad_none, sizeof(pad_none));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* VERIFY DSA */
	{
		ret = yaca_verify_initialize(&ctx, YACA_DIGEST_SHA1, key_dsa_pub);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad, sizeof(pad));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad2, sizeof(pad2));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad_invalid, sizeof(pad_invalid));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
		                                &pad_none, sizeof(pad_none));
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	yaca_key_destroy(key_rsa_prv);
	yaca_key_destroy(key_rsa_pub);
	yaca_key_destroy(key_rsa_prv2);
	yaca_key_destroy(key_rsa_pub2);
	yaca_key_destroy(key_rsa_prv_short);
	yaca_key_destroy(key_dsa_prv);
	yaca_key_destroy(key_dsa_pub);
	yaca_key_destroy(key_sym);
	yaca_context_destroy(ctx_digest);
	yaca_free(signature);
}

BOOST_FIXTURE_TEST_CASE(T803__positive__sign_cmac, InitDebugFixture)
{
	struct cmac_args {
		yaca_key_type_e type;
		yaca_key_bit_length_e len;
		yaca_encrypt_algorithm_e algo;
		size_t split;
	};

	const std::vector<cmac_args> cargs = {
		{YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT,
		 YACA_ENCRYPT_AES, 11},
		{YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_UNSAFE_128BIT,
		 YACA_ENCRYPT_CAST5, 22},
		{YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_192BIT,
		 YACA_ENCRYPT_3DES_3TDEA, 33},
		{YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT,
		 YACA_ENCRYPT_UNSAFE_RC2, 44},
		{YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_UNSAFE_64BIT,
		 YACA_ENCRYPT_UNSAFE_DES, 13},

		{YACA_KEY_TYPE_DES, YACA_KEY_LENGTH_UNSAFE_128BIT,
		 YACA_ENCRYPT_AES, 15},
		{YACA_KEY_TYPE_DES, YACA_KEY_LENGTH_UNSAFE_128BIT,
		 YACA_ENCRYPT_CAST5, 41},
		{YACA_KEY_TYPE_DES, YACA_KEY_LENGTH_192BIT,
		 YACA_ENCRYPT_3DES_3TDEA, 17},
		{YACA_KEY_TYPE_DES, YACA_KEY_LENGTH_UNSAFE_128BIT,
		 YACA_ENCRYPT_UNSAFE_RC2, 9},
		{YACA_KEY_TYPE_DES, YACA_KEY_LENGTH_UNSAFE_64BIT,
		 YACA_ENCRYPT_UNSAFE_DES, 12},
	};

	for (const auto &ca: cargs) {
		int ret;
		yaca_context_h ctx = YACA_CONTEXT_NULL;
		yaca_key_h key = YACA_KEY_NULL;

		char *signature = NULL, *signature2 = NULL;
		size_t signature_len, signature2_len;

		ret = yaca_key_generate(ca.type, ca.len, &key);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		/* SIGN */
		{
			ret = yaca_sign_initialize_cmac(&ctx, ca.algo, key);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			call_update_loop(ctx, INPUT_DATA, INPUT_DATA_SIZE,
			                 ca.split, yaca_sign_update);

			ret = yaca_context_get_output_length(ctx, 0, &signature_len);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			ret = yaca_malloc(signature_len, (void **)&signature);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			ret = yaca_sign_finalize(ctx, signature, &signature_len);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			yaca_context_destroy(ctx);
			ctx = YACA_CONTEXT_NULL;
		}

		/* VERIFY */
		{
			ret = yaca_sign_initialize_cmac(&ctx, ca.algo, key);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			call_update_loop(ctx, INPUT_DATA, INPUT_DATA_SIZE,
			                 ca.split + 3, yaca_sign_update);

			ret = yaca_context_get_output_length(ctx, 0, &signature2_len);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			ret = yaca_malloc(signature2_len, (void **)&signature2);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			ret = yaca_sign_finalize(ctx, signature2, &signature2_len);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			yaca_context_destroy(ctx);
			ctx = YACA_CONTEXT_NULL;

			BOOST_REQUIRE(signature_len == signature2_len);
			ret = yaca_memcmp(signature, signature2, signature_len);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		}

		yaca_key_destroy(key);
		yaca_free(signature);
		yaca_free(signature2);
	}
}

BOOST_FIXTURE_TEST_CASE(T804__negative__sign_cmac, InitDebugFixture)
{
	int ret;
	yaca_context_h ctx = YACA_CONTEXT_NULL;
	yaca_key_h key = YACA_KEY_NULL, key2 = YACA_KEY_NULL;
	yaca_key_h key_rsa = YACA_KEY_NULL, key_dsa = YACA_KEY_NULL;

	char *signature = NULL, *signature2 = NULL;
	size_t signature_len, signature2_len;

	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_192BIT, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_192BIT, &key2);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_512BIT, &key_rsa);
	generate_asymmetric_keys(YACA_KEY_TYPE_DSA_PRIV, YACA_KEY_LENGTH_512BIT, &key_dsa);

	/* SIGN */
	{
		ret = yaca_sign_initialize_cmac(NULL, YACA_ENCRYPT_AES, key);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_initialize_cmac(&ctx, YACA_INVALID_ENCRYPT_ALGORITHM, key);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_initialize_cmac(&ctx, YACA_ENCRYPT_AES, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_initialize_cmac(&ctx, YACA_ENCRYPT_AES, key_rsa);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_initialize_cmac(&ctx, YACA_ENCRYPT_AES, key_dsa);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_initialize_cmac(&ctx, YACA_ENCRYPT_AES, key);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_sign_update(ctx, INPUT_DATA, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_get_output_length(ctx, 0, &signature_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_malloc(signature_len, (void **)&signature);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_sign_finalize(ctx, signature, &signature_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* VERIFY, wrong algo */
	{
		ret = yaca_sign_initialize_cmac(&ctx, YACA_ENCRYPT_3DES_3TDEA, key);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_sign_update(ctx, INPUT_DATA, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_get_output_length(ctx, 0, &signature2_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_malloc(signature2_len, (void **)&signature2);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_sign_finalize(ctx, signature2, &signature2_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		signature2_len = std::min(signature_len, signature2_len);
		ret = yaca_memcmp(signature, signature2, signature2_len);
		BOOST_REQUIRE(ret == YACA_ERROR_DATA_MISMATCH);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(signature2);
		signature2 = NULL;
	}

	/* VERIFY, wrong key */
	{
		ret = yaca_sign_initialize_cmac(&ctx, YACA_ENCRYPT_AES, key2);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_sign_update(ctx, INPUT_DATA, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_get_output_length(ctx, 0, &signature2_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_malloc(signature2_len, (void **)&signature2);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_sign_finalize(ctx, signature2, &signature2_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		BOOST_REQUIRE(signature_len == signature2_len);
		ret = yaca_memcmp(signature, signature2, signature_len);
		BOOST_REQUIRE(ret == YACA_ERROR_DATA_MISMATCH);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(signature2);
		signature2 = NULL;
	}

	yaca_key_destroy(key);
	yaca_key_destroy(key2);
	yaca_key_destroy(key_rsa);
	yaca_key_destroy(key_dsa);
	yaca_free(signature);
}

BOOST_FIXTURE_TEST_CASE(T805__positive__sign_hmac, InitDebugFixture)
{
	struct hmac_args {
		yaca_key_type_e type;
		yaca_key_bit_length_e len;
		yaca_digest_algorithm_e digest;
		size_t split;
	};

	const std::vector<hmac_args> hargs = {
		{YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT,
		 YACA_DIGEST_MD5, 13},
		{YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_UNSAFE_128BIT,
		 YACA_DIGEST_SHA1, 32},
		{YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_192BIT,
		 YACA_DIGEST_SHA224, 23},
		{YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT,
		 YACA_DIGEST_SHA256, 20},
		{YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_UNSAFE_64BIT,
		 YACA_DIGEST_SHA384, 13},

		{YACA_KEY_TYPE_DES, YACA_KEY_LENGTH_UNSAFE_128BIT,
		 YACA_DIGEST_MD5, 9},
		{YACA_KEY_TYPE_DES, YACA_KEY_LENGTH_UNSAFE_128BIT,
		 YACA_DIGEST_SHA1, 7},
		{YACA_KEY_TYPE_DES, YACA_KEY_LENGTH_192BIT,
		 YACA_DIGEST_SHA224, 14},
		{YACA_KEY_TYPE_DES, YACA_KEY_LENGTH_UNSAFE_128BIT,
		 YACA_DIGEST_SHA384, 20},
		{YACA_KEY_TYPE_DES, YACA_KEY_LENGTH_UNSAFE_64BIT,
		 YACA_DIGEST_SHA512, 10},
	};

	for (const auto &ha: hargs) {
		int ret;
		yaca_context_h ctx = YACA_CONTEXT_NULL;
		yaca_key_h key = YACA_KEY_NULL;

		char *signature = NULL, *signature2 = NULL;
		size_t signature_len, signature2_len;

		ret = yaca_key_generate(ha.type, ha.len, &key);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		/* SIGN */
		{
			ret = yaca_sign_initialize_hmac(&ctx, ha.digest, key);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			call_update_loop(ctx, INPUT_DATA, INPUT_DATA_SIZE,
			                 ha.split, yaca_sign_update);

			ret = yaca_context_get_output_length(ctx, 0, &signature_len);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			ret = yaca_malloc(signature_len, (void **)&signature);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			ret = yaca_sign_finalize(ctx, signature, &signature_len);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			yaca_context_destroy(ctx);
			ctx = YACA_CONTEXT_NULL;
		}

		/* VERIFY */
		{
			ret = yaca_sign_initialize_hmac(&ctx, ha.digest, key);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			call_update_loop(ctx, INPUT_DATA, INPUT_DATA_SIZE,
			                 ha.split + 3, yaca_sign_update);

			ret = yaca_context_get_output_length(ctx, 0, &signature2_len);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			ret = yaca_malloc(signature2_len, (void **)&signature2);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			ret = yaca_sign_finalize(ctx, signature2, &signature2_len);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);

			yaca_context_destroy(ctx);
			ctx = YACA_CONTEXT_NULL;

			BOOST_REQUIRE(signature_len == signature2_len);
			ret = yaca_memcmp(signature, signature2, signature_len);
			BOOST_REQUIRE(ret == YACA_ERROR_NONE);
		}

		yaca_key_destroy(key);
		yaca_free(signature);
		yaca_free(signature2);
	}
}

BOOST_FIXTURE_TEST_CASE(T806__negative__sign_hmac, InitDebugFixture)
{
	int ret;
	yaca_context_h ctx = YACA_CONTEXT_NULL;
	yaca_key_h key = YACA_KEY_NULL, key2 = YACA_KEY_NULL;
	yaca_key_h key_rsa = YACA_KEY_NULL, key_dsa = YACA_KEY_NULL;

	char *signature = NULL, *signature2 = NULL;
	size_t signature_len, signature2_len;

	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_192BIT, &key);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);
	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_192BIT, &key2);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	generate_asymmetric_keys(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_512BIT, &key_rsa);
	generate_asymmetric_keys(YACA_KEY_TYPE_DSA_PRIV, YACA_KEY_LENGTH_512BIT, &key_dsa);

	/* SIGN */
	{
		ret = yaca_sign_initialize_hmac(NULL, YACA_DIGEST_MD5, key);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_initialize_hmac(&ctx, YACA_INVALID_DIGEST_ALGORITHM, key);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_initialize_hmac(&ctx, YACA_DIGEST_MD5, YACA_KEY_NULL);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_initialize_hmac(&ctx, YACA_DIGEST_MD5, key_rsa);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_initialize_hmac(&ctx, YACA_DIGEST_MD5, key_dsa);
		BOOST_REQUIRE(ret == YACA_ERROR_INVALID_PARAMETER);

		ret = yaca_sign_initialize_hmac(&ctx, YACA_DIGEST_MD5, key);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_sign_update(ctx, INPUT_DATA, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_get_output_length(ctx, 0, &signature_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_malloc(signature_len, (void **)&signature);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_sign_finalize(ctx, signature, &signature_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
	}

	/* VERIFY, wrong algo */
	{
		ret = yaca_sign_initialize_hmac(&ctx, YACA_DIGEST_SHA1, key);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_sign_update(ctx, INPUT_DATA, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_get_output_length(ctx, 0, &signature2_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_malloc(signature2_len, (void **)&signature2);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_sign_finalize(ctx, signature2, &signature2_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		signature2_len = std::min(signature_len, signature2_len);
		ret = yaca_memcmp(signature, signature2, signature2_len);
		BOOST_REQUIRE(ret == YACA_ERROR_DATA_MISMATCH);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(signature2);
		signature2 = NULL;
	}

	/* VERIFY, wrong key */
	{
		ret = yaca_sign_initialize_hmac(&ctx, YACA_DIGEST_MD5, key2);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_sign_update(ctx, INPUT_DATA, INPUT_DATA_SIZE);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_context_get_output_length(ctx, 0, &signature2_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_malloc(signature2_len, (void **)&signature2);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		ret = yaca_sign_finalize(ctx, signature2, &signature2_len);
		BOOST_REQUIRE(ret == YACA_ERROR_NONE);

		BOOST_REQUIRE(signature_len == signature2_len);
		ret = yaca_memcmp(signature, signature2, signature_len);
		BOOST_REQUIRE(ret == YACA_ERROR_DATA_MISMATCH);

		yaca_context_destroy(ctx);
		ctx = YACA_CONTEXT_NULL;
		yaca_free(signature2);
		signature2 = NULL;
	}

	yaca_key_destroy(key);
	yaca_key_destroy(key2);
	yaca_key_destroy(key_rsa);
	yaca_key_destroy(key_dsa);
	yaca_free(signature);
}

BOOST_AUTO_TEST_SUITE_END()
