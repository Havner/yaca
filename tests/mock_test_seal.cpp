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
 * @file    test_seal.cpp
 * @author  Lukasz Pawelczyk <l.pawelczyk@samsung.com>
 * @brief   Seal API unit tests.
 */

#include <boost/test/unit_test.hpp>
#include <vector>

#include <yaca_crypto.h>
#include <yaca_seal.h>
#include <yaca_key.h>
#include <yaca_encrypt.h>
#include <yaca_error.h>

#include "common.h"


BOOST_AUTO_TEST_SUITE(MOCK_TESTS_SEAL)

BOOST_FIXTURE_TEST_CASE(T1701__mock__negative__seal_open, InitFixture)
{
	struct seal_args {
		yaca_encrypt_algorithm_e algo;
		yaca_block_cipher_mode_e bcm;
		size_t key_bit_len;
		yaca_padding_e padding;
	};

	const std::vector<seal_args> sargs = {
		{YACA_ENCRYPT_AES,               YACA_BCM_CBC,  128, YACA_PADDING_NONE   },
		{YACA_ENCRYPT_UNSAFE_DES,        YACA_BCM_ECB,   64, YACA_PADDING_PKCS7  },
		{YACA_ENCRYPT_UNSAFE_3DES_2TDEA, YACA_BCM_CFB,  128, YACA_INVALID_PADDING},
		{YACA_ENCRYPT_3DES_3TDEA,        YACA_BCM_CBC,  192, YACA_PADDING_PKCS7  },
		{YACA_ENCRYPT_UNSAFE_RC4,        YACA_BCM_NONE, 256, YACA_INVALID_PADDING},
		{YACA_ENCRYPT_CAST5,             YACA_BCM_CBC,  128, YACA_PADDING_NONE   },
	};

	for (const auto &sa: sargs) {
		auto test_code = [&sa]()
			{
				int ret;
				yaca_context_h ctx = YACA_CONTEXT_NULL;
				yaca_key_h key_prv = YACA_KEY_NULL, key_pub = YACA_KEY_NULL;
				yaca_key_h key_sym = YACA_KEY_NULL, iv = YACA_KEY_NULL;

				size_t len1 = 0, len2 = 0;

				char *encrypted = NULL, *decrypted = NULL;
				size_t encrypted_len = 0, decrypted_len = 0;

				ret = yaca_key_generate(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_512BIT, &key_prv);
				if (ret != YACA_ERROR_NONE) goto exit;
				ret = yaca_key_extract_public(key_prv, &key_pub);
				if (ret != YACA_ERROR_NONE) goto exit;

				/* SEAL */
				{
					ret = yaca_seal_initialize(&ctx, key_pub, sa.algo, sa.bcm,
					                           sa.key_bit_len, &key_sym, &iv);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_get_output_length(ctx, INPUT_DATA_SIZE, &len1);
					if (ret != YACA_ERROR_NONE) goto exit;
					ret = yaca_context_get_output_length(ctx, 0, &len2);
					if (ret != YACA_ERROR_NONE) goto exit;

					size_t total = len1 + len2;
					size_t written;

					ret = yaca_zalloc(total, (void**)&encrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_seal_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					encrypted_len = written;

					if (sa.padding != YACA_INVALID_PADDING) {
						ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING, &sa.padding,
						                                sizeof(yaca_padding_e));
						if (ret != YACA_ERROR_NONE) goto exit;
					}

					ret = yaca_seal_finalize(ctx, encrypted + encrypted_len, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					encrypted_len += written;

					ret = yaca_realloc(encrypted_len, (void **)&encrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					yaca_context_destroy(ctx);
					ctx = YACA_CONTEXT_NULL;
				}

				/* OPEN */
				{
					ret = yaca_open_initialize(&ctx, key_prv, sa.algo, sa.bcm,
					                           sa.key_bit_len, key_sym, iv);
					if (ret != YACA_ERROR_NONE) goto exit;

					if (sa.padding != YACA_INVALID_PADDING) {
						ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING, &sa.padding,
						                                sizeof(yaca_padding_e));
						if (ret != YACA_ERROR_NONE) goto exit;
					}

					ret = yaca_context_get_output_length(ctx, encrypted_len, &len1);
					if (ret != YACA_ERROR_NONE) goto exit;
					ret = yaca_context_get_output_length(ctx, 0, &len2);
					if (ret != YACA_ERROR_NONE) goto exit;

					size_t total = len1 + len2;
					size_t written;

					ret = yaca_zalloc(total, (void**)&decrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					decrypted_len = written;

					ret = yaca_open_finalize(ctx, decrypted + decrypted_len, &written);
					if (ret != YACA_ERROR_NONE) goto exit;

					yaca_context_destroy(ctx);
					ctx = YACA_CONTEXT_NULL;
				}

			exit:
				yaca_context_destroy(ctx);
				yaca_key_destroy(key_prv);
				yaca_key_destroy(key_pub);
				yaca_key_destroy(key_sym);
				yaca_key_destroy(iv);
				yaca_free(encrypted);
				yaca_free(decrypted);
				return ret;
			};

		call_mock_test(test_code);
	}
}

BOOST_FIXTURE_TEST_CASE(T1702__mock__negative__seal_open_rc2, InitFixture)
{
	struct seal_args {
		yaca_block_cipher_mode_e bcm;
		size_t key_bit_len;
		size_t effective_key_bits;
	};

	const std::vector<seal_args> sargs = {
		{YACA_BCM_CBC, 192,   1024},
		{YACA_BCM_CFB, 192,    333}
	};

	for (const auto &sa: sargs) {
		auto test_code = [&sa]()
			{
				int ret;
				yaca_context_h ctx = YACA_CONTEXT_NULL;
				yaca_key_h key_prv = YACA_KEY_NULL, key_pub = YACA_KEY_NULL;
				yaca_key_h key_sym = YACA_KEY_NULL, iv = YACA_KEY_NULL;

				size_t len1 = 0, len2 = 0;

				char *encrypted = NULL, *decrypted = NULL;
				size_t encrypted_len = 0, decrypted_len = 0;

				ret = yaca_key_generate(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_512BIT, &key_prv);
				if (ret != YACA_ERROR_NONE) goto exit;
				ret = yaca_key_extract_public(key_prv, &key_pub);
				if (ret != YACA_ERROR_NONE) goto exit;

				/* SEAL */
				{
					ret = yaca_seal_initialize(&ctx, key_pub, YACA_ENCRYPT_UNSAFE_RC2, sa.bcm,
					                           sa.key_bit_len, &key_sym, &iv);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_set_property(ctx, YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS,
					                                &sa.effective_key_bits, sizeof(size_t));
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_get_output_length(ctx, INPUT_DATA_SIZE, &len1);
					if (ret != YACA_ERROR_NONE) goto exit;
					ret = yaca_context_get_output_length(ctx, 0, &len2);
					if (ret != YACA_ERROR_NONE) goto exit;

					size_t total = len1 + len2;
					size_t written;

					ret = yaca_zalloc(total, (void**)&encrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_seal_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					encrypted_len = written;

					ret = yaca_seal_finalize(ctx, encrypted + encrypted_len, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					encrypted_len += written;

					ret = yaca_realloc(encrypted_len, (void **)&encrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					yaca_context_destroy(ctx);
					ctx = YACA_CONTEXT_NULL;
				}

				/* OPEN */
				{
					ret = yaca_open_initialize(&ctx, key_prv, YACA_ENCRYPT_UNSAFE_RC2, sa.bcm,
					                           sa.key_bit_len, key_sym, iv);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_set_property(ctx, YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS,
					                                &sa.effective_key_bits, sizeof(size_t));
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_get_output_length(ctx, encrypted_len, &len1);
					if (ret != YACA_ERROR_NONE) goto exit;
					ret = yaca_context_get_output_length(ctx, 0, &len2);
					if (ret != YACA_ERROR_NONE) goto exit;

					size_t total = len1 + len2;
					size_t written;

					ret = yaca_zalloc(total, (void**)&decrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					decrypted_len = written;

					ret = yaca_open_finalize(ctx, decrypted + decrypted_len, &written);
					if (ret != YACA_ERROR_NONE) goto exit;

					yaca_context_destroy(ctx);
					ctx = YACA_CONTEXT_NULL;
				}

			exit:
				yaca_context_destroy(ctx);
				yaca_key_destroy(key_prv);
				yaca_key_destroy(key_pub);
				yaca_key_destroy(key_sym);
				yaca_key_destroy(iv);
				yaca_free(encrypted);
				yaca_free(decrypted);
				return ret;
			};

		call_mock_test(test_code);
	}
}

BOOST_FIXTURE_TEST_CASE(T1703__mock__negative__open_seal_ccm, InitFixture)
{
	struct seal_args {
		size_t key_bit_len;
		size_t ccm_tag_len;
		size_t aad_len;
	};

	const std::vector<seal_args> sargs = {
		{128,  6, 23},
		{256, 12, 33}
	};

	for (const auto &sa: sargs) {
		auto test_code = [&sa]()
			{
				int ret;
				yaca_context_h ctx = YACA_CONTEXT_NULL;
				yaca_key_h key_prv = YACA_KEY_NULL, key_pub = YACA_KEY_NULL;
				yaca_key_h key_sym = YACA_KEY_NULL, iv = YACA_KEY_NULL;

				size_t len1, len2;

				char *tag = NULL, *aad = NULL;
				size_t tag_len;

				char *encrypted = NULL, *decrypted = NULL;
				size_t encrypted_len, decrypted_len;

				ret = yaca_key_generate(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_512BIT, &key_prv);
				if (ret != YACA_ERROR_NONE) goto exit;
				ret = yaca_key_extract_public(key_prv, &key_pub);
				if (ret != YACA_ERROR_NONE) goto exit;

				/* SEAL */
				{
					ret = yaca_seal_initialize(&ctx, key_pub, YACA_ENCRYPT_AES, YACA_BCM_CCM,
					                           sa.key_bit_len, &key_sym, &iv);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_get_output_length(ctx, INPUT_DATA_SIZE, &len1);
					if (ret != YACA_ERROR_NONE) goto exit;
					ret = yaca_context_get_output_length(ctx, 0, &len2);
					if (ret != YACA_ERROR_NONE) goto exit;

					size_t total = len1 + len2;
					size_t written;

					ret = yaca_zalloc(total, (void**)&encrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					tag_len = sa.ccm_tag_len;
					ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG_LEN,
					                                &tag_len, sizeof(tag_len));
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_malloc(sa.aad_len, (void**)&aad);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_randomize_bytes(aad, sa.aad_len);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_seal_update(ctx, NULL, INPUT_DATA_SIZE,
					                       NULL, &written);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD,
					                                aad, sa.aad_len);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_seal_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					encrypted_len = written;

					ret = yaca_seal_finalize(ctx, encrypted + encrypted_len, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					encrypted_len += written;

					ret = yaca_realloc(encrypted_len, (void **)&encrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_get_property(ctx, YACA_PROPERTY_CCM_TAG, (void**)&tag, &tag_len);
					if (ret != YACA_ERROR_NONE) goto exit;

					yaca_context_destroy(ctx);
					ctx = YACA_CONTEXT_NULL;
				}

				/* OPEN */
				{
					ret = yaca_open_initialize(&ctx, key_prv, YACA_ENCRYPT_AES, YACA_BCM_CCM,
					                           sa.key_bit_len, key_sym, iv);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_get_output_length(ctx, encrypted_len, &len1);
					if (ret != YACA_ERROR_NONE) goto exit;
					ret = yaca_context_get_output_length(ctx, 0, &len2);
					if (ret != YACA_ERROR_NONE) goto exit;

					size_t total = len1 + len2;
					size_t written;

					ret = yaca_zalloc(total, (void**)&decrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG, tag, tag_len);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_open_update(ctx, NULL, encrypted_len,
					                       NULL, &written);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD,
					                                aad, sa.aad_len);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					decrypted_len = written;

					ret = yaca_open_finalize(ctx, decrypted + decrypted_len, &written);
					if (ret != YACA_ERROR_NONE) goto exit;

					yaca_context_destroy(ctx);
					ctx = YACA_CONTEXT_NULL;
				}

			exit:
				yaca_context_destroy(ctx);
				yaca_key_destroy(key_prv);
				yaca_key_destroy(key_pub);
				yaca_key_destroy(key_sym);
				yaca_key_destroy(iv);
				yaca_free(encrypted);
				yaca_free(decrypted);
				yaca_free(tag);
				yaca_free(aad);
				return ret;
			};

		call_mock_test(test_code);
	}
}

BOOST_FIXTURE_TEST_CASE(T1704__mock__negative__seal_open_gcm, InitFixture)
{
	struct seal_args {
		size_t key_bit_len;
		size_t gcm_tag_len;
		size_t aad_len;
	};

	const std::vector<seal_args> sargs = {
		{128, 13, 22},
		{192, 15, 33}
	};

	for (const auto &sa: sargs) {
		auto test_code = [&sa]()
			{
				int ret;
				yaca_context_h ctx = YACA_CONTEXT_NULL;
				yaca_key_h key_prv = YACA_KEY_NULL, key_pub = YACA_KEY_NULL;
				yaca_key_h key_sym = YACA_KEY_NULL, iv = YACA_KEY_NULL;

				size_t len1 = 0, len2 = 0;

				char *encrypted = NULL, *decrypted = NULL;
				size_t encrypted_len = 0, decrypted_len = 0;

				char *tag = NULL, *aad = NULL;
				size_t tag_len;

				ret = yaca_key_generate(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_512BIT, &key_prv);
				if (ret != YACA_ERROR_NONE) goto exit;
				ret = yaca_key_extract_public(key_prv, &key_pub);
				if (ret != YACA_ERROR_NONE) goto exit;

				/* SEAL */
				{
					ret = yaca_seal_initialize(&ctx, key_pub, YACA_ENCRYPT_AES, YACA_BCM_GCM,
					                           sa.key_bit_len, &key_sym, &iv);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_get_output_length(ctx, INPUT_DATA_SIZE, &len1);
					if (ret != YACA_ERROR_NONE) goto exit;
					ret = yaca_context_get_output_length(ctx, 0, &len2);
					if (ret != YACA_ERROR_NONE) goto exit;

					size_t total = len1 + len2;
					size_t written;

					ret = yaca_zalloc(total, (void**)&encrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_malloc(sa.aad_len, (void**)&aad);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_randomize_bytes(aad, sa.aad_len);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD,
					                                aad, sa.aad_len);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_seal_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					encrypted_len = written;

					ret = yaca_seal_finalize(ctx, encrypted + encrypted_len, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					encrypted_len += written;

					ret = yaca_realloc(encrypted_len, (void **)&encrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					tag_len = sa.gcm_tag_len;
					ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG_LEN,
					                                &tag_len, sizeof(tag_len));
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_get_property(ctx, YACA_PROPERTY_GCM_TAG,
					                                (void**)&tag, &tag_len);
					if (ret != YACA_ERROR_NONE) goto exit;

					yaca_context_destroy(ctx);
					ctx = YACA_CONTEXT_NULL;
				}

				/* OPEN */
				{
					ret = yaca_open_initialize(&ctx, key_prv, YACA_ENCRYPT_AES, YACA_BCM_GCM,
					                           sa.key_bit_len, key_sym, iv);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_get_output_length(ctx, encrypted_len, &len1);
					if (ret != YACA_ERROR_NONE) goto exit;
					ret = yaca_context_get_output_length(ctx, 0, &len2);
					if (ret != YACA_ERROR_NONE) goto exit;

					size_t total = len1 + len2;
					size_t written;

					ret = yaca_zalloc(total, (void**)&decrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD,
					                                aad, sa.aad_len);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_open_update(ctx, encrypted, encrypted_len, decrypted, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					decrypted_len = written;

					ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG,
					                                tag, tag_len);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_open_finalize(ctx, decrypted + decrypted_len, &written);
					if (ret != YACA_ERROR_NONE) goto exit;

					yaca_context_destroy(ctx);
					ctx = YACA_CONTEXT_NULL;
				}

			exit:
				yaca_context_destroy(ctx);
				yaca_key_destroy(key_prv);
				yaca_key_destroy(key_pub);
				yaca_key_destroy(key_sym);
				yaca_key_destroy(iv);
				yaca_free(encrypted);
				yaca_free(decrypted);
				yaca_free(tag);
				yaca_free(aad);
				return ret;
			};

		call_mock_test(test_code);
	}
}

BOOST_AUTO_TEST_SUITE_END()
