/*
 *  Copyright (c) 2016-2020 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Krzysztof Jackiewicz <k.jackiewicz@samsung.com>
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
 * @file seal.c
 * @brief
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>

#include <yaca_crypto.h>
#include <yaca_seal.h>
#include <yaca_error.h>
#include <yaca_key.h>

#include "internal.h"

#ifdef OPENSSL_MOCKUP_TESTS
#include "../tests/openssl_mock_redefine.h"
#endif


static int seal_generate_sym_key(yaca_encrypt_algorithm_e algo,
                                 size_t sym_key_bit_len,
                                 yaca_key_h *sym_key)
{
	assert(sym_key != NULL);

	if (algo == YACA_ENCRYPT_3DES_3TDEA ||
	    algo == YACA_ENCRYPT_UNSAFE_3DES_2TDEA ||
	    algo == YACA_ENCRYPT_UNSAFE_DES)
		return yaca_key_generate(YACA_KEY_TYPE_DES, sym_key_bit_len, sym_key);
	else
		return yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, sym_key_bit_len, sym_key);
}

static int seal_generate_iv(const EVP_CIPHER *cipher, yaca_key_h *iv)
{
	int ret;
	int iv_len;

	assert(iv != NULL);
	assert(cipher != NULL);

	ret = EVP_CIPHER_iv_length(cipher);
	if (ret < 0) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	iv_len = ret;
	if (iv_len == 0) {
		*iv = YACA_KEY_NULL;
		return YACA_ERROR_NONE;
	}

	return yaca_key_generate(YACA_KEY_TYPE_IV, iv_len * 8, iv);
}

/* used for asymmetric encryption and decryption */
static int seal_encrypt_decrypt_key(const yaca_key_h asym_key,
                                    const yaca_key_h in_key,
                                    yaca_key_h *out_key)
{
	int ret;
	const struct yaca_key_evp_s *lasym_key;
	const struct yaca_key_simple_s *lin_key;
	struct yaca_key_simple_s *lout_key;
	size_t output_len;

	lin_key = key_get_simple(in_key);
	assert(lin_key != NULL);
	assert(lin_key->key.type == YACA_KEY_TYPE_SYMMETRIC ||
		   lin_key->key.type == YACA_KEY_TYPE_DES);

	lasym_key = key_get_evp(asym_key);
	assert(lasym_key != NULL);
	assert(lasym_key->key.type == YACA_KEY_TYPE_RSA_PRIV ||
		   lasym_key->key.type == YACA_KEY_TYPE_RSA_PUB);

	ret = EVP_PKEY_size(lasym_key->evp);
	if (ret <= 0) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	output_len = ret;

	ret = yaca_zalloc(sizeof(struct yaca_key_simple_s) + output_len, (void**)&lout_key);
	if (ret != YACA_ERROR_NONE)
		return ret;

	lout_key->key.type = YACA_KEY_TYPE_SYMMETRIC;
	lout_key->bit_len = output_len * 8;

	if (lasym_key->key.type == YACA_KEY_TYPE_RSA_PRIV)
		ret = EVP_PKEY_decrypt_old((unsigned char*)lout_key->d,
		                           (unsigned char*)lin_key->d,
		                           lin_key->bit_len / 8,
		                           lasym_key->evp);
	else
		ret = EVP_PKEY_encrypt_old((unsigned char*)lout_key->d,
		                           (unsigned char*)lin_key->d,
		                           lin_key->bit_len / 8,
		                           lasym_key->evp);

	if (ret <= 0) {
		ret = ERROR_HANDLE();
		goto exit;
	}

	output_len = ret;

	/* Update the key length just in case */
	lout_key->bit_len = output_len * 8;

	*out_key = (yaca_key_h)lout_key;
	lout_key = NULL;

	ret = YACA_ERROR_NONE;

exit:
	yaca_key_destroy((yaca_key_h)lout_key);

	return ret;
}

API int yaca_seal_initialize(yaca_context_h *ctx,
                             const yaca_key_h pub_key,
                             yaca_encrypt_algorithm_e algo,
                             yaca_block_cipher_mode_e bcm,
                             size_t sym_key_bit_len,
                             yaca_key_h *sym_key,
                             yaca_key_h *iv)
{
	int ret;
	const EVP_CIPHER *cipher;
	yaca_key_h lsym_key = YACA_KEY_NULL;
	yaca_key_h liv = YACA_KEY_NULL;
	yaca_key_h lenc_sym_key = YACA_KEY_NULL;

	if (pub_key == YACA_KEY_NULL || pub_key->type != YACA_KEY_TYPE_RSA_PUB ||
	    sym_key == NULL || bcm == YACA_BCM_WRAP || sym_key_bit_len % 8 != 0)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = encrypt_get_algorithm(algo, bcm, sym_key_bit_len, &cipher);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = seal_generate_sym_key(algo, sym_key_bit_len, &lsym_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = seal_generate_iv(cipher, &liv);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	if (liv != YACA_KEY_NULL && iv == NULL) {
		ret = YACA_ERROR_INVALID_PARAMETER;
		goto exit;
	}

	/* using public key will make it encrypt the symmetric key */
	ret = seal_encrypt_decrypt_key(pub_key, lsym_key, &lenc_sym_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = encrypt_initialize(ctx, cipher, lsym_key, liv, OP_SEAL);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	*sym_key = lenc_sym_key;
	lenc_sym_key = YACA_KEY_NULL;
	if (iv != NULL) {
		*iv = liv;
		liv = YACA_KEY_NULL;
	}

	ret = YACA_ERROR_NONE;

exit:
	yaca_key_destroy(liv);
	yaca_key_destroy(lsym_key);
	yaca_key_destroy(lenc_sym_key);

	return ret;
}

API int yaca_seal_update(yaca_context_h ctx,
                         const char *plaintext,
                         size_t plaintext_len,
                         char *ciphertext,
                         size_t *ciphertext_len)
{
	return encrypt_update(ctx, (const unsigned char*)plaintext,  plaintext_len,
	                      (unsigned char*)ciphertext, ciphertext_len, OP_SEAL);
}

API int yaca_seal_finalize(yaca_context_h ctx,
                           char *ciphertext,
                           size_t *ciphertext_len)
{
	return encrypt_finalize(ctx, (unsigned char*)ciphertext, ciphertext_len, OP_SEAL);
}

API int yaca_open_initialize(yaca_context_h *ctx,
                             const yaca_key_h prv_key,
                             yaca_encrypt_algorithm_e algo,
                             yaca_block_cipher_mode_e bcm,
                             size_t sym_key_bit_len,
                             const yaca_key_h sym_key,
                             const yaca_key_h iv)
{
	int ret;
	const EVP_CIPHER *cipher;
	yaca_key_h lsym_key = YACA_KEY_NULL;

	if (prv_key == YACA_KEY_NULL || prv_key->type != YACA_KEY_TYPE_RSA_PRIV ||
	    sym_key == YACA_KEY_NULL || bcm == YACA_BCM_WRAP || sym_key_bit_len % 8 != 0 ||
	    (sym_key->type != YACA_KEY_TYPE_SYMMETRIC && sym_key->type != YACA_KEY_TYPE_DES))
		return YACA_ERROR_INVALID_PARAMETER;

	ret = encrypt_get_algorithm(algo, bcm, sym_key_bit_len, &cipher);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* using private key will make it decrypt the symmetric key */
	ret = seal_encrypt_decrypt_key(prv_key, sym_key, &lsym_key);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = encrypt_initialize(ctx, cipher, lsym_key, iv, OP_OPEN);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = YACA_ERROR_NONE;

exit:
	yaca_key_destroy(lsym_key);
	return ret;
}

API int yaca_open_update(yaca_context_h ctx,
                         const char *ciphertext,
                         size_t ciphertext_len,
                         char *plaintext,
                         size_t *plaintext_len)
{
	return encrypt_update(ctx, (const unsigned char*)ciphertext, ciphertext_len,
	                      (unsigned char*)plaintext, plaintext_len, OP_OPEN);
}

API int yaca_open_finalize(yaca_context_h ctx,
                           char *plaintext,
                           size_t *plaintext_len)
{
	return encrypt_finalize(ctx, (unsigned char*)plaintext, plaintext_len, OP_OPEN);
}
