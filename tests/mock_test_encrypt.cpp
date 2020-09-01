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
 * @file    test_encrypt.cpp
 * @author  Lukasz Pawelczyk <l.pawelczyk@samsung.com>
 * @brief   Encrypt API unit tests.
 */

#include <boost/test/unit_test.hpp>
#include <vector>
#include <cstring>

#include <yaca_crypto.h>
#include <yaca_encrypt.h>
#include <yaca_key.h>
#include <yaca_digest.h>
#include <yaca_error.h>

#include "common.h"


BOOST_AUTO_TEST_SUITE(MOCK_TESTS_ENCRYPT)

BOOST_FIXTURE_TEST_CASE(T1601__mock__negative__encrypt_decrypt, InitFixture)
{
	struct encrypt_args {
		yaca_encrypt_algorithm_e algo;
		yaca_block_cipher_mode_e bcm;
		size_t key_bit_len;
		yaca_padding_e padding;
	};

	const std::vector<encrypt_args> eargs = {
		{YACA_ENCRYPT_AES,               YACA_BCM_CBC,  128, YACA_PADDING_NONE   },
		{YACA_ENCRYPT_UNSAFE_DES,        YACA_BCM_OFB,   64, YACA_INVALID_PADDING},
		{YACA_ENCRYPT_UNSAFE_3DES_2TDEA, YACA_BCM_CBC,  128, YACA_PADDING_PKCS7  },
		{YACA_ENCRYPT_3DES_3TDEA,        YACA_BCM_CFB1, 192, YACA_INVALID_PADDING},
		{YACA_ENCRYPT_UNSAFE_RC4,        YACA_BCM_NONE, 256, YACA_INVALID_PADDING},
		{YACA_ENCRYPT_CAST5,             YACA_BCM_ECB,  128, YACA_PADDING_NONE   }
	};

	for (const auto &ea: eargs) {
		auto test_code = [&ea]()
			{
				int ret;
				yaca_context_h ctx = YACA_CONTEXT_NULL;
				yaca_key_h key = YACA_KEY_NULL, iv = YACA_KEY_NULL;

				size_t iv_bit_len, len1 = 0, len2 = 0;

				char *encrypted = NULL, *decrypted = NULL;
				size_t encrypted_len = 0, decrypted_len = 0;

				ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, ea.key_bit_len, &key);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_encrypt_get_iv_bit_length(ea.algo, ea.bcm, ea.key_bit_len, &iv_bit_len);
				if (ret != YACA_ERROR_NONE) goto exit;

				if (iv_bit_len > 0) {
					ret = yaca_key_generate(YACA_KEY_TYPE_IV, iv_bit_len, &iv);
					if (ret != YACA_ERROR_NONE) goto exit;
				}

				/* ENCRYPT */
				{
					ret = yaca_encrypt_initialize(&ctx, ea.algo, ea.bcm, key, iv);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_get_output_length(ctx, INPUT_DATA_SIZE, &len1);
					if (ret != YACA_ERROR_NONE) goto exit;
					ret = yaca_context_get_output_length(ctx, 0, &len2);
					if (ret != YACA_ERROR_NONE) goto exit;

					size_t total = len1 + len2;
					size_t written;

					ret = yaca_zalloc(total, (void**)&encrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_encrypt_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					encrypted_len = written;

					if (ea.padding != YACA_INVALID_PADDING) {
						ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING, &ea.padding,
						                                sizeof(yaca_padding_e));
						if (ret != YACA_ERROR_NONE) goto exit;
					}

					ret = yaca_encrypt_finalize(ctx, encrypted + encrypted_len, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					encrypted_len += written;

					ret = yaca_realloc(encrypted_len, (void **)&encrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					yaca_context_destroy(ctx);
					ctx = YACA_CONTEXT_NULL;
				}

				/* DECRYPT */
				{
					ret = yaca_decrypt_initialize(&ctx, ea.algo, ea.bcm, key, iv);
					if (ret != YACA_ERROR_NONE) goto exit;

					if (ea.padding != YACA_INVALID_PADDING) {
						ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING, &ea.padding,
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

					ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					decrypted_len = written;

					ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
					if (ret != YACA_ERROR_NONE) goto exit;

					yaca_context_destroy(ctx);
					ctx = YACA_CONTEXT_NULL;
				}

			exit:
				yaca_context_destroy(ctx);
				yaca_key_destroy(key);
				yaca_key_destroy(iv);
				yaca_free(encrypted);
				yaca_free(decrypted);
				return ret;
			};

		call_mock_test(test_code);
	}
}

BOOST_FIXTURE_TEST_CASE(T1602__mock__negative__encrypt_decrypt_wrap, InitFixture)
{
	struct encrypt_args {
		yaca_encrypt_algorithm_e algo;
		size_t key_bit_len;
		size_t key_material_len;
	};

	const std::vector<encrypt_args> eargs = {
		{YACA_ENCRYPT_AES,        128, 192 / 8},
		{YACA_ENCRYPT_3DES_3TDEA, 192, 128 / 8},
	};

	for (const auto &ea: eargs) {
		auto test_code = [&ea]()
			{
				int ret;
				yaca_context_h ctx = YACA_CONTEXT_NULL;
				yaca_key_h key = YACA_KEY_NULL, iv = YACA_KEY_NULL;
				char *key_material = NULL;

				size_t iv_bit_len, len1, len2;

				char *encrypted = NULL, *decrypted = NULL;
				size_t encrypted_len, decrypted_len;

				ret = yaca_zalloc(ea.key_material_len, (void**)&key_material);
				if (ret != YACA_ERROR_NONE) goto exit;
				ret = yaca_randomize_bytes(key_material, ea.key_material_len);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, ea.key_bit_len, &key);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_encrypt_get_iv_bit_length(ea.algo, YACA_BCM_WRAP, ea.key_bit_len, &iv_bit_len);
				if (ret != YACA_ERROR_NONE) goto exit;

				if (iv_bit_len > 0) {
					ret = yaca_key_generate(YACA_KEY_TYPE_IV, iv_bit_len, &iv);
					if (ret != YACA_ERROR_NONE) goto exit;
				}

				/* ENCRYPT */
				{
					ret = yaca_encrypt_initialize(&ctx, ea.algo, YACA_BCM_WRAP, key, iv);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_get_output_length(ctx, ea.key_material_len, &len1);
					if (ret != YACA_ERROR_NONE) goto exit;
					ret = yaca_context_get_output_length(ctx, 0, &len2);
					if (ret != YACA_ERROR_NONE) goto exit;

					size_t total = len1 + len2;
					size_t written;

					ret = yaca_zalloc(total, (void**)&encrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_encrypt_update(ctx, key_material, ea.key_material_len,
					                          encrypted, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					encrypted_len = written;

					ret = yaca_encrypt_finalize(ctx, encrypted + encrypted_len, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					encrypted_len += written;

					ret = yaca_realloc(encrypted_len, (void **)&encrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					yaca_context_destroy(ctx);
					ctx = YACA_CONTEXT_NULL;
				}

				/* DECRYPT */
				{
					ret = yaca_decrypt_initialize(&ctx, ea.algo, YACA_BCM_WRAP, key, iv);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_get_output_length(ctx, encrypted_len, &len1);
					if (ret != YACA_ERROR_NONE) goto exit;
					ret = yaca_context_get_output_length(ctx, 0, &len2);
					if (ret != YACA_ERROR_NONE) goto exit;

					size_t total = len1 + len2;
					size_t written;

					ret = yaca_zalloc(total, (void**)&decrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					decrypted_len = written;

					ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
					if (ret != YACA_ERROR_NONE) goto exit;

					yaca_context_destroy(ctx);
					ctx = YACA_CONTEXT_NULL;
				}

			exit:
				yaca_context_destroy(ctx);
				yaca_key_destroy(key);
				yaca_key_destroy(iv);
				yaca_free(key_material);
				yaca_free(encrypted);
				yaca_free(decrypted);
				return ret;
			};

		call_mock_test(test_code);
	}
}

BOOST_FIXTURE_TEST_CASE(T1603__mock__negative__encrypt_decrypt_rc2, InitFixture)
{
	struct encrypt_args {
		yaca_block_cipher_mode_e bcm;
		size_t key_bit_len;
		yaca_padding_e padding;
		size_t effective_key_bits;
	};

	const std::vector<encrypt_args> eargs = {
		{YACA_BCM_CBC, 224, YACA_INVALID_PADDING, 1},
		{YACA_BCM_CBC, 192, YACA_PADDING_NONE,   64},
		{YACA_BCM_CBC, 272, YACA_PADDING_PKCS7,   8},
	};

	for (const auto &ea: eargs) {
		auto test_code = [&ea]()
			{
				int ret;
				yaca_context_h ctx = YACA_CONTEXT_NULL;
				yaca_key_h key = YACA_KEY_NULL, iv = YACA_KEY_NULL;

				size_t iv_bit_len, len1 = 0, len2 = 0;

				char *encrypted = NULL, *decrypted = NULL;
				size_t encrypted_len = 0, decrypted_len = 0;

				ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, ea.key_bit_len, &key);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_encrypt_get_iv_bit_length(YACA_ENCRYPT_UNSAFE_RC2, ea.bcm, ea.key_bit_len, &iv_bit_len);
				if (ret != YACA_ERROR_NONE) goto exit;

				if (iv_bit_len > 0) {
					ret = yaca_key_generate(YACA_KEY_TYPE_IV, iv_bit_len, &iv);
					if (ret != YACA_ERROR_NONE) goto exit;
				}

				/* ENCRYPT */
				{
					ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_UNSAFE_RC2, ea.bcm, key, iv);
					if (ret != YACA_ERROR_NONE) goto exit;

					if (ea.padding != YACA_INVALID_PADDING) {
						ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
						                                &ea.padding, sizeof(yaca_padding_e));
						if (ret != YACA_ERROR_NONE) goto exit;
					}

					ret = yaca_context_set_property(ctx, YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS,
					                                &ea.effective_key_bits, sizeof(size_t));
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_get_output_length(ctx, INPUT_DATA_SIZE, &len1);
					if (ret != YACA_ERROR_NONE) goto exit;
					ret = yaca_context_get_output_length(ctx, 0, &len2);
					if (ret != YACA_ERROR_NONE) goto exit;

					size_t total = len1 + len2;
					size_t written;

					ret = yaca_zalloc(total, (void**)&encrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_encrypt_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					encrypted_len = written;

					ret = yaca_encrypt_finalize(ctx, encrypted + encrypted_len, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					encrypted_len += written;

					ret = yaca_realloc(encrypted_len, (void **)&encrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					yaca_context_destroy(ctx);
					ctx = YACA_CONTEXT_NULL;
				}

				/* DECRYPT */
				{
					ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_UNSAFE_RC2, ea.bcm, key, iv);
					if (ret != YACA_ERROR_NONE) goto exit;

					if (ea.padding != YACA_INVALID_PADDING) {
						ret = yaca_context_set_property(ctx, YACA_PROPERTY_PADDING,
						                                &ea.padding, sizeof(yaca_padding_e));
						if (ret != YACA_ERROR_NONE) goto exit;
					}

					ret = yaca_context_set_property(ctx, YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS,
					                                &ea.effective_key_bits, sizeof(size_t));
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_get_output_length(ctx, encrypted_len, &len1);
					if (ret != YACA_ERROR_NONE) goto exit;
					ret = yaca_context_get_output_length(ctx, 0, &len2);
					if (ret != YACA_ERROR_NONE) goto exit;

					size_t total = len1 + len2;
					size_t written;

					ret = yaca_zalloc(total, (void**)&decrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					decrypted_len = written;

					ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
					if (ret != YACA_ERROR_NONE) goto exit;

					yaca_context_destroy(ctx);
					ctx = YACA_CONTEXT_NULL;
				}

			exit:
				yaca_context_destroy(ctx);
				yaca_key_destroy(key);
				yaca_key_destroy(iv);
				yaca_free(encrypted);
				yaca_free(decrypted);
				return ret;
			};

		call_mock_test(test_code);
	}
}

BOOST_FIXTURE_TEST_CASE(T1604__mock__negative__encrypt_decrypt_ccm, InitFixture)
{
	struct encrypt_args {
		size_t key_bit_len;
		size_t ccm_tag_len;
		size_t aad_len;
		size_t iv_bit_len;
	};

	const std::vector<encrypt_args> eargs = {
		{128, 12, 19, 64},
		{192, 10, 34, 96}
	};

	for (const auto &ea: eargs) {
		auto test_code = [&ea]()
			{
				int ret;
				yaca_context_h ctx = YACA_CONTEXT_NULL;
				yaca_key_h key = YACA_KEY_NULL, iv = YACA_KEY_NULL;

				size_t len1, len2;

				char *tag = NULL, *aad = NULL;
				size_t tag_len;

				char *encrypted = NULL, *decrypted = NULL;
				size_t encrypted_len, decrypted_len;

				ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, ea.key_bit_len, &key);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_key_generate(YACA_KEY_TYPE_IV, ea.iv_bit_len, &iv);
				if (ret != YACA_ERROR_NONE) goto exit;

				/* ENCRYPT */
				{
					ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CCM, key, iv);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_get_output_length(ctx, INPUT_DATA_SIZE, &len1);
					if (ret != YACA_ERROR_NONE) goto exit;
					ret = yaca_context_get_output_length(ctx, 0, &len2);
					if (ret != YACA_ERROR_NONE) goto exit;

					size_t total = len1 + len2;
					size_t written;

					ret = yaca_zalloc(total, (void**)&encrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					tag_len = ea.ccm_tag_len;
					ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_TAG_LEN,
					                                &tag_len, sizeof(tag_len));
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_malloc(ea.aad_len, (void**)&aad);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_randomize_bytes(aad, ea.aad_len);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_encrypt_update(ctx, NULL, INPUT_DATA_SIZE,
					                          NULL, &written);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD,
					                                aad, ea.aad_len);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_encrypt_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					encrypted_len = written;

					ret = yaca_encrypt_finalize(ctx, encrypted + encrypted_len, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					encrypted_len += written;

					ret = yaca_realloc(encrypted_len, (void **)&encrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_get_property(ctx, YACA_PROPERTY_CCM_TAG, (void**)&tag, &tag_len);
					if (ret != YACA_ERROR_NONE) goto exit;

					yaca_context_destroy(ctx);
					ctx = YACA_CONTEXT_NULL;
				}

				/* DECRYPT */
				{
					ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_CCM, key, iv);
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

					ret = yaca_decrypt_update(ctx, NULL, encrypted_len,
					                          NULL, &written);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_set_property(ctx, YACA_PROPERTY_CCM_AAD,
					                                aad, ea.aad_len);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					decrypted_len = written;

					ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
					if (ret != YACA_ERROR_NONE) goto exit;

					yaca_context_destroy(ctx);
					ctx = YACA_CONTEXT_NULL;
				}

			exit:
				yaca_context_destroy(ctx);
				yaca_key_destroy(key);
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

BOOST_FIXTURE_TEST_CASE(T1605__mock__negative__encrypt_decrypt_gcm, InitFixture)
{
	struct encrypt_args {
		size_t key_bit_len;
		size_t gcm_tag_len;
		size_t aad_len;
		size_t iv_bit_len;
	};

	const std::vector<encrypt_args> eargs = {
		{128, 13, 22,  64},
		{256, 14, 12, 128}
	};

	for (const auto &ea: eargs) {
		auto test_code = [&ea]()
			{
				int ret;
				yaca_context_h ctx = YACA_CONTEXT_NULL;
				yaca_key_h key = YACA_KEY_NULL, iv = YACA_KEY_NULL;

				size_t len1 = 0, len2 = 0;

				char *encrypted = NULL, *decrypted = NULL;
				size_t encrypted_len = 0, decrypted_len = 0;

				char *tag = NULL, *aad = NULL;
				size_t tag_len;

				ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, ea.key_bit_len, &key);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_key_generate(YACA_KEY_TYPE_IV, ea.iv_bit_len, &iv);
				if (ret != YACA_ERROR_NONE) goto exit;

				/* ENCRYPT */
				{
					ret = yaca_encrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_GCM, key, iv);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_get_output_length(ctx, INPUT_DATA_SIZE, &len1);
					if (ret != YACA_ERROR_NONE) goto exit;
					ret = yaca_context_get_output_length(ctx, 0, &len2);
					if (ret != YACA_ERROR_NONE) goto exit;

					size_t total = len1 + len2;
					size_t written;

					ret = yaca_zalloc(total, (void**)&encrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_malloc(ea.aad_len, (void**)&aad);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_randomize_bytes(aad, ea.aad_len);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_AAD,
					                                aad, ea.aad_len);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_encrypt_update(ctx, INPUT_DATA, INPUT_DATA_SIZE, encrypted, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					encrypted_len = written;

					ret = yaca_encrypt_finalize(ctx, encrypted + encrypted_len, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					encrypted_len += written;

					ret = yaca_realloc(encrypted_len, (void **)&encrypted);
					if (ret != YACA_ERROR_NONE) goto exit;

					tag_len = ea.gcm_tag_len;
					ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG_LEN,
					                                &tag_len, sizeof(tag_len));
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_context_get_property(ctx, YACA_PROPERTY_GCM_TAG,
					                                (void**)&tag, &tag_len);
					if (ret != YACA_ERROR_NONE) goto exit;

					yaca_context_destroy(ctx);
					ctx = YACA_CONTEXT_NULL;
				}

				/* DECRYPT */
				{
					ret = yaca_decrypt_initialize(&ctx, YACA_ENCRYPT_AES, YACA_BCM_GCM, key, iv);
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
					                                aad, ea.aad_len);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_decrypt_update(ctx, encrypted, encrypted_len, decrypted, &written);
					if (ret != YACA_ERROR_NONE) goto exit;
					decrypted_len = written;

					ret = yaca_context_set_property(ctx, YACA_PROPERTY_GCM_TAG,
					                                tag, tag_len);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_decrypt_finalize(ctx, decrypted + decrypted_len, &written);
					if (ret != YACA_ERROR_NONE) goto exit;

					yaca_context_destroy(ctx);
					ctx = YACA_CONTEXT_NULL;
				}

			exit:
				yaca_context_destroy(ctx);
				yaca_key_destroy(key);
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
