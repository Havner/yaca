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
 * @file encrypt.c
 * @brief
 */

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <string.h>

#include <openssl/evp.h>

#include <yaca_crypto.h>
#include <yaca_encrypt.h>
#include <yaca_error.h>
#include <yaca_key.h>

#include "internal.h"

#ifdef OPENSSL_MOCKUP_TESTS
#include "../tests/openssl_mock_redefine.h"
#endif


static int set_encrypt_property(yaca_context_h ctx, yaca_property_e property,
                                const void *value, size_t value_len);

static int get_encrypt_property(const yaca_context_h ctx, yaca_property_e property,
                                void **value, size_t *value_len);

static const size_t DEFAULT_GCM_TAG_LEN = 16;
static const size_t DEFAULT_CCM_TAG_LEN = 12;

enum encrypt_context_state_e {
	ENC_CTX_INITIALIZED = 0,
	ENC_CTX_MSG_LENGTH_UPDATED,
	ENC_CTX_AAD_UPDATED,
	ENC_CTX_MSG_UPDATED,
	ENC_CTX_TAG_SET,
	ENC_CTX_TAG_LENGTH_SET,
	ENC_CTX_FINALIZED,

	ENC_CTX_COUNT,
};

struct yaca_encrypt_context_s {
	struct yaca_context_s ctx;
	struct yaca_backup_context_s *backup_ctx;

	EVP_CIPHER_CTX *cipher_ctx;
	enum encrypt_op_type_e op_type; /* Operation context was created for */
	size_t tag_len;
	enum encrypt_context_state_e state;
};

struct yaca_backup_context_s {
	const EVP_CIPHER *cipher;
	yaca_key_h sym_key;
	yaca_key_h iv;
	yaca_padding_e padding;
};

static const struct {
	yaca_encrypt_algorithm_e algo;
	yaca_block_cipher_mode_e bcm;
	size_t key_bit_len;
	const EVP_CIPHER *(*cipher)(void);
} ENCRYPTION_CIPHERS[] = {
	{YACA_ENCRYPT_AES, YACA_BCM_CBC,  128, EVP_aes_128_cbc},
	{YACA_ENCRYPT_AES, YACA_BCM_CCM,  128, EVP_aes_128_ccm},
	{YACA_ENCRYPT_AES, YACA_BCM_CFB,  128, EVP_aes_128_cfb},
	{YACA_ENCRYPT_AES, YACA_BCM_CFB1, 128, EVP_aes_128_cfb1},
	{YACA_ENCRYPT_AES, YACA_BCM_CFB8, 128, EVP_aes_128_cfb8},
	{YACA_ENCRYPT_AES, YACA_BCM_CTR,  128, EVP_aes_128_ctr},
	{YACA_ENCRYPT_AES, YACA_BCM_ECB,  128, EVP_aes_128_ecb},
	{YACA_ENCRYPT_AES, YACA_BCM_GCM,  128, EVP_aes_128_gcm},
	{YACA_ENCRYPT_AES, YACA_BCM_OFB,  128, EVP_aes_128_ofb},
	{YACA_ENCRYPT_AES, YACA_BCM_WRAP, 128, EVP_aes_128_wrap},

	{YACA_ENCRYPT_AES, YACA_BCM_CBC,  192, EVP_aes_192_cbc},
	{YACA_ENCRYPT_AES, YACA_BCM_CCM,  192, EVP_aes_192_ccm},
	{YACA_ENCRYPT_AES, YACA_BCM_CFB,  192, EVP_aes_192_cfb},
	{YACA_ENCRYPT_AES, YACA_BCM_CFB1, 192, EVP_aes_192_cfb1},
	{YACA_ENCRYPT_AES, YACA_BCM_CFB8, 192, EVP_aes_192_cfb8},
	{YACA_ENCRYPT_AES, YACA_BCM_CTR,  192, EVP_aes_192_ctr},
	{YACA_ENCRYPT_AES, YACA_BCM_ECB,  192, EVP_aes_192_ecb},
	{YACA_ENCRYPT_AES, YACA_BCM_GCM,  192, EVP_aes_192_gcm},
	{YACA_ENCRYPT_AES, YACA_BCM_OFB,  192, EVP_aes_192_ofb},
	{YACA_ENCRYPT_AES, YACA_BCM_WRAP, 192, EVP_aes_192_wrap},

	{YACA_ENCRYPT_AES, YACA_BCM_CBC,  256, EVP_aes_256_cbc},
	{YACA_ENCRYPT_AES, YACA_BCM_CCM,  256, EVP_aes_256_ccm},
	{YACA_ENCRYPT_AES, YACA_BCM_CFB,  256, EVP_aes_256_cfb},
	{YACA_ENCRYPT_AES, YACA_BCM_CFB1, 256, EVP_aes_256_cfb1},
	{YACA_ENCRYPT_AES, YACA_BCM_CFB8, 256, EVP_aes_256_cfb8},
	{YACA_ENCRYPT_AES, YACA_BCM_CTR,  256, EVP_aes_256_ctr},
	{YACA_ENCRYPT_AES, YACA_BCM_ECB,  256, EVP_aes_256_ecb},
	{YACA_ENCRYPT_AES, YACA_BCM_GCM,  256, EVP_aes_256_gcm},
	{YACA_ENCRYPT_AES, YACA_BCM_OFB,  256, EVP_aes_256_ofb},
	{YACA_ENCRYPT_AES, YACA_BCM_WRAP, 256, EVP_aes_256_wrap},

	{YACA_ENCRYPT_UNSAFE_DES, YACA_BCM_CBC,  -1, EVP_des_cbc},
	{YACA_ENCRYPT_UNSAFE_DES, YACA_BCM_CFB,  -1, EVP_des_cfb},
	{YACA_ENCRYPT_UNSAFE_DES, YACA_BCM_CFB1, -1, EVP_des_cfb1},
	{YACA_ENCRYPT_UNSAFE_DES, YACA_BCM_CFB8, -1, EVP_des_cfb8},
	{YACA_ENCRYPT_UNSAFE_DES, YACA_BCM_ECB,  -1, EVP_des_ecb},
	{YACA_ENCRYPT_UNSAFE_DES, YACA_BCM_OFB,  -1, EVP_des_ofb},

	{YACA_ENCRYPT_UNSAFE_3DES_2TDEA, YACA_BCM_CBC, -1, EVP_des_ede_cbc},
	{YACA_ENCRYPT_UNSAFE_3DES_2TDEA, YACA_BCM_CFB, -1, EVP_des_ede_cfb},
	{YACA_ENCRYPT_UNSAFE_3DES_2TDEA, YACA_BCM_ECB, -1, EVP_des_ede_ecb},
	{YACA_ENCRYPT_UNSAFE_3DES_2TDEA, YACA_BCM_OFB, -1, EVP_des_ede_ofb},

	{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_CBC,  -1, EVP_des_ede3_cbc},
	{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_CFB,  -1, EVP_des_ede3_cfb},
	{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_CFB1, -1, EVP_des_ede3_cfb1},
	{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_CFB8, -1, EVP_des_ede3_cfb8},
	{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_ECB,  -1, EVP_des_ede3_ecb},
	{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_OFB,  -1, EVP_des_ede3_ofb},
	{YACA_ENCRYPT_3DES_3TDEA, YACA_BCM_WRAP, -1, EVP_des_ede3_wrap},

	{YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_CBC, -1, EVP_rc2_cbc},
	{YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_CFB, -1, EVP_rc2_cfb},
	{YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_ECB, -1, EVP_rc2_ecb},
	{YACA_ENCRYPT_UNSAFE_RC2, YACA_BCM_OFB, -1, EVP_rc2_ofb},

	{YACA_ENCRYPT_UNSAFE_RC4, YACA_BCM_NONE, -1, EVP_rc4},

	{YACA_ENCRYPT_CAST5, YACA_BCM_CBC, -1, EVP_cast5_cbc},
	{YACA_ENCRYPT_CAST5, YACA_BCM_CFB, -1, EVP_cast5_cfb},
	{YACA_ENCRYPT_CAST5, YACA_BCM_ECB, -1, EVP_cast5_ecb},
	{YACA_ENCRYPT_CAST5, YACA_BCM_OFB, -1, EVP_cast5_ofb},
};

static const size_t ENCRYPTION_CIPHERS_SIZE = sizeof(ENCRYPTION_CIPHERS) / sizeof(ENCRYPTION_CIPHERS[0]);

static bool is_encryption_op(enum encrypt_op_type_e op_type)
{
	return (op_type == OP_ENCRYPT || op_type == OP_SEAL);
}

static bool DEFAULT_STATES[ENC_CTX_COUNT][ENC_CTX_COUNT] = {
/* from \ to  INIT, MLEN, AAD,  MSG,  TAG,  TLEN, FIN */
/* INIT */  { 0,    0,    0,    1,    0,    0,    1 },
/* MLEN  */ { 0,    0,    0,    0,    0,    0,    0 },
/* AAD  */  { 0,    0,    0,    0,    0,    0,    0 },
/* MSG  */  { 0,    0,    0,    1,    0,    0,    1 },
/* TAG  */  { 0,    0,    0,    0,    0,    0,    0 },
/* TLEN */  { 0,    0,    0,    0,    0,    0,    0 },
/* FIN  */  { 0,    0,    0,    0,    0,    0,    0 },
};

static bool GCM_STATES[2][ENC_CTX_COUNT][ENC_CTX_COUNT] = { {
/* ENCRYPTION */
/* from \ to  INIT, MLEN, AAD,  MSG,  TAG,  TLEN, FIN */
/* INIT */  { 0,    0,    1,    1,    0,    0,    1 },
/* MLEN */  { 0,    0,    0,    0,    0,    0,    0 },
/* AAD  */  { 0,    0,    1,    1,    0,    0,    1 },
/* MSG  */  { 0,    0,    0,    1,    0,    0,    1 },
/* TAG  */  { 0,    0,    0,    0,    0,    0,    0 },
/* TLEN */  { 0,    0,    0,    0,    0,    0,    0 },
/* FIN  */  { 0,    0,    0,    0,    0,    1,    0 },
}, {
/* DECRYPTION */
/* from \ to  INIT, MLEN, AAD,  MSG,  TAG,  TLEN, FIN */
/* INIT */  { 0,    0,    1,    1,    1,    0,    0 },
/* MLEN */  { 0,    0,    0,    0,    0,    0,    0 },
/* AAD  */  { 0,    0,    1,    1,    1,    0,    0 },
/* MSG  */  { 0,    0,    0,    1,    1,    0,    0 },
/* TAG  */  { 0,    0,    0,    0,    0,    0,    1 },
/* TLEN */  { 0,    0,    0,    0,    0,    0,    0 },
/* FIN  */  { 0,    0,    0,    0,    0,    0,    0 },
} };

static bool CCM_STATES[2][ENC_CTX_COUNT][ENC_CTX_COUNT] = { {
/* ENCRYPTION */
/* from \ to  INIT, MLEN, AAD,  MSG,  TAG,  TLEN, FIN */
/* INIT */  { 0,    1,    0,    1,    0,    1,    0 },
/* MLEN */  { 0,    0,    1,    0,    0,    0,    0 },
/* AAD  */  { 0,    0,    0,    1,    0,    0,    0 },
/* MSG  */  { 0,    0,    0,    0,    0,    0,    1 },
/* TAG  */  { 0,    0,    0,    0,    0,    0,    0 },
/* TLEN */  { 0,    1,    0,    1,    0,    0,    0 },
/* FIN  */  { 0,    0,    0,    0,    0,    0,    0 },
}, {
/* DECRYPTION */
/* from \ to  INIT, MLEN, AAD,  MSG,  TAG,  TLEN, FIN */
/* INIT */  { 0,    0,    0,    0,    1,    0,    0 },
/* MLEN */  { 0,    0,    1,    0,    0,    0,    0 },
/* AAD  */  { 0,    0,    0,    1,    0,    0,    0 },
/* MSG  */  { 0,    0,    0,    0,    0,    0,    1 },
/* TAG  */  { 0,    1,    0,    1,    0,    0,    0 },
/* TLEN */  { 0,    0,    0,    0,    0,    0,    0 },
/* FIN  */  { 0,    0,    0,    0,    0,    0,    0 },
} };

static bool WRAP_STATES[ENC_CTX_COUNT][ENC_CTX_COUNT] = {
/* from \ to  INIT, MLEN, AAD,  MSG,  TAG,  TLEN, FIN */
/* INIT */  { 0,    0,    0,    1,    0,    0,    0 },
/* MLEN */  { 0,    0,    0,    0,    0,    0,    0 },
/* AAD  */  { 0,    0,    0,    0,    0,    0,    0 },
/* MSG  */  { 0,    0,    0,    0,    0,    0,    1 },
/* TAG  */  { 0,    0,    0,    0,    0,    0,    0 },
/* TLEN */  { 0,    0,    0,    0,    0,    0,    0 },
/* FIN  */  { 0,    0,    0,    0,    0,    0,    0 },
};

static bool verify_state_change(struct yaca_encrypt_context_s *c, enum encrypt_context_state_e to)
{
	int mode = EVP_CIPHER_CTX_mode(c->cipher_ctx);
	bool encryption = is_encryption_op(c->op_type);
	int from = c->state;

	if (mode == EVP_CIPH_CCM_MODE)
		return CCM_STATES[encryption ? 0 : 1][from][to];
	else if (mode == EVP_CIPH_GCM_MODE)
		return GCM_STATES[encryption ? 0 : 1][from][to];
	else if (mode == EVP_CIPH_WRAP_MODE)
		return WRAP_STATES[from][to];
	else
		return DEFAULT_STATES[from][to];

	return false;
}

static const size_t VALID_GCM_TAG_LENGTHS[] = { 4, 8, 12, 13, 14, 15, 16 };
static const size_t VALID_GCM_TAG_LENGTHS_LENGTH =
		sizeof(VALID_GCM_TAG_LENGTHS) / sizeof(VALID_GCM_TAG_LENGTHS[0]);

static const size_t VALID_CCM_TAG_LENGTHS[] = { 4, 6, 8, 10, 12, 14, 16 };
static const size_t VALID_CCM_TAG_LENGTHS_LENGTH =
		sizeof(VALID_CCM_TAG_LENGTHS) / sizeof(VALID_CCM_TAG_LENGTHS[0]);

static bool is_valid_tag_len(int mode, size_t tag_len)
{
	switch (mode) {
	case EVP_CIPH_GCM_MODE:
		for (size_t i = 0; i < VALID_GCM_TAG_LENGTHS_LENGTH; i++) {
			if (tag_len == VALID_GCM_TAG_LENGTHS[i])
				return true;
		}
		return false;
	case EVP_CIPH_CCM_MODE:
		for (size_t i = 0; i < VALID_CCM_TAG_LENGTHS_LENGTH; i++) {
			if (tag_len == VALID_CCM_TAG_LENGTHS[i])
				return true;
		}
		return false;
	default:
		assert(false);
		return false;
	}
}

static struct yaca_encrypt_context_s *get_encrypt_context(const yaca_context_h ctx)
{
	if (ctx == YACA_CONTEXT_NULL)
		return NULL;

	switch (ctx->type) {
	case YACA_CONTEXT_ENCRYPT:
		return (struct yaca_encrypt_context_s *)ctx;
	default:
		return NULL;
	}
}

static void destroy_encrypt_context(const yaca_context_h ctx)
{
	struct yaca_encrypt_context_s *c = get_encrypt_context(ctx);
	assert(c != NULL);

	if (c->backup_ctx != NULL) {
		yaca_key_destroy(c->backup_ctx->iv);
		yaca_key_destroy(c->backup_ctx->sym_key);
		yaca_free(c->backup_ctx);
		c->backup_ctx = NULL;
	}

	EVP_CIPHER_CTX_free(c->cipher_ctx);
	c->cipher_ctx = NULL;
}

static int get_encrypt_output_length(const yaca_context_h ctx, size_t input_len, size_t *output_len)
{
	assert(output_len != NULL);

	int block_size;
	struct yaca_encrypt_context_s *c = get_encrypt_context(ctx);
	assert(c != NULL);
	assert(c->cipher_ctx != NULL);

	block_size = EVP_CIPHER_CTX_block_size(c->cipher_ctx);
	if (block_size <= 0) {
		const int ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	if (input_len > 0) {
		if ((size_t)block_size > SIZE_MAX - input_len + 1)
			return YACA_ERROR_INVALID_PARAMETER;

		*output_len = block_size + input_len - 1;
	} else {
		*output_len = block_size;
	}
	assert(*output_len != 0);

	return YACA_ERROR_NONE;
}

static int get_wrap_output_length(const yaca_context_h ctx, size_t input_len, size_t *output_len)
{
	assert(output_len != NULL);

	struct yaca_encrypt_context_s *c = get_encrypt_context(ctx);
	assert(c != NULL);
	assert(c->cipher_ctx != NULL);

	bool encryption = is_encryption_op(c->op_type);
	int nid = EVP_CIPHER_CTX_nid(c->cipher_ctx);

	if (input_len > 0) {
		if (nid == NID_id_aes128_wrap || nid == NID_id_aes192_wrap || nid == NID_id_aes256_wrap) {
			*output_len = encryption ? input_len + 8 : input_len - 8;
		} else if (nid == NID_id_smime_alg_CMS3DESwrap) {
			*output_len = encryption ? input_len + 16 : input_len - 16;
		} else {
			assert(false);
			return YACA_ERROR_INTERNAL;
		}
	} else {
		*output_len = 0;
	}

	return YACA_ERROR_NONE;
}

static int encrypt_ctx_create(struct yaca_encrypt_context_s **c,
                              enum encrypt_op_type_e op_type,
                              const EVP_CIPHER *cipher)
{
	int ret;
	int mode;
	struct yaca_encrypt_context_s *nc;

	assert(c != NULL);
	assert(cipher != NULL);

	ret = yaca_zalloc(sizeof(struct yaca_encrypt_context_s), (void**)&nc);
	if (ret != YACA_ERROR_NONE)
		return ret;

	mode = EVP_CIPHER_flags(cipher) & EVP_CIPH_MODE;

	nc->ctx.type = YACA_CONTEXT_ENCRYPT;
	nc->backup_ctx = NULL;
	nc->ctx.context_destroy = destroy_encrypt_context;
	nc->ctx.get_output_length = (mode == EVP_CIPH_WRAP_MODE) ?
	                            get_wrap_output_length :
	                            get_encrypt_output_length;
	nc->ctx.set_property = set_encrypt_property;
	nc->ctx.get_property = get_encrypt_property;
	nc->op_type = op_type;
	nc->tag_len = 0;

	/* set default tag length for GCM and CCM */
	if (mode == EVP_CIPH_GCM_MODE)
		nc->tag_len = DEFAULT_GCM_TAG_LEN;
	else if (mode == EVP_CIPH_CCM_MODE)
		nc->tag_len = DEFAULT_CCM_TAG_LEN;

	nc->cipher_ctx = EVP_CIPHER_CTX_new();
	if (nc->cipher_ctx == NULL) {
		ret =  YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	if (mode == EVP_CIPH_WRAP_MODE)
		EVP_CIPHER_CTX_set_flags(nc->cipher_ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

	*c = nc;
	nc = NULL;

	ret = YACA_ERROR_NONE;

exit:
	yaca_free(nc);
	return ret;
}

static int encrypt_ctx_init(struct yaca_encrypt_context_s *c,
                            const EVP_CIPHER *cipher,
                            size_t key_bit_len)
{
	int ret;

	assert(c != NULL);
	assert(cipher != NULL);

	if (key_bit_len / 8 > INT_MAX)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = EVP_CipherInit_ex(c->cipher_ctx,
	                        cipher,
	                        NULL,
	                        NULL,
	                        NULL,
	                        is_encryption_op(c->op_type) ? 1 : 0);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	/* Handling of algorithms with variable key length */
	ret = EVP_CIPHER_CTX_set_key_length(c->cipher_ctx, key_bit_len / 8);
	if (ret != 1)
		return ERROR_HANDLE();

	return YACA_ERROR_NONE;
}

static int encrypt_ctx_setup_iv(struct yaca_encrypt_context_s *c,
                                const EVP_CIPHER *cipher,
                                const struct yaca_key_simple_s *iv)
{
	int ret;
	size_t default_iv_bit_len;

	assert(c != NULL);
	assert(cipher != NULL);

	ret = EVP_CIPHER_iv_length(cipher);
	if (ret < 0) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	default_iv_bit_len = ret * 8;

	/* 0 -> cipher doesn't use iv, but it was provided */
	if (default_iv_bit_len == 0 && iv != NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	if (default_iv_bit_len != 0) { /* cipher requires iv */
		 /* iv was not provided */
		if (iv == NULL || iv->key.type != YACA_KEY_TYPE_IV)
			return YACA_ERROR_INVALID_PARAMETER;

		if (iv->bit_len / 8 > INT_MAX)
			return YACA_ERROR_INVALID_PARAMETER;

		/* IV length doesn't match cipher (GCM & CCM supports variable IV length) */
		if (default_iv_bit_len != iv->bit_len) {
			size_t iv_len = iv->bit_len / 8;
			int mode = EVP_CIPHER_CTX_mode(c->cipher_ctx);

			if (mode == EVP_CIPH_GCM_MODE) {
				ret = EVP_CIPHER_CTX_ctrl(c->cipher_ctx, EVP_CTRL_GCM_SET_IVLEN,
				                          iv_len, NULL);
			} else if (mode == EVP_CIPH_CCM_MODE) {
				/* OpenSSL does not return a specific error code when
				 * wrong IVLEN is passed. It just returns 0. So there
				 * is no way to distinguish this error from ENOMEM for
				 * example. Handle this in our code then.
				 */
				if (iv_len < 7 || iv_len > 13)
					return YACA_ERROR_INVALID_PARAMETER;
				ret = EVP_CIPHER_CTX_ctrl(c->cipher_ctx, EVP_CTRL_CCM_SET_IVLEN,
				                          iv_len, NULL);
			} else {
				return YACA_ERROR_INVALID_PARAMETER;
			}

			if (ret != 1)
				return ERROR_HANDLE();
		}
	}

	return YACA_ERROR_NONE;
}

static int encrypt_ctx_setup(struct yaca_encrypt_context_s *c,
                             const yaca_key_h key,
                             const yaca_key_h iv)
{
	int ret;
	unsigned char *iv_data = NULL;
	const struct yaca_key_simple_s *lkey;
	const struct yaca_key_simple_s *liv;

	assert(c != NULL);
	assert(key != YACA_KEY_NULL);

	const EVP_CIPHER *cipher = EVP_CIPHER_CTX_cipher(c->cipher_ctx);
	assert(cipher != NULL);

	lkey = key_get_simple(key);
	assert(lkey != NULL);

	liv = key_get_simple(iv);

	ret = encrypt_ctx_setup_iv(c, cipher, liv);
	if (ret != YACA_ERROR_NONE)
		return ret;

	if (liv != NULL)
		iv_data = (unsigned char*)liv->d;

	ret = EVP_CipherInit_ex(c->cipher_ctx,
	                        NULL,
	                        NULL,
	                        (unsigned char*)lkey->d,
	                        iv_data,
	                        is_encryption_op(c->op_type) ? 1 : 0);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	return YACA_ERROR_NONE;
}

static int key_copy_simple(const yaca_key_h key, yaca_key_h *out)
{
	assert(key != YACA_KEY_NULL);
	assert(out != NULL);

	int ret;
	struct yaca_key_simple_s *simple = key_get_simple(key);
	assert(simple != NULL);

	struct yaca_key_simple_s *copy;
	size_t size = sizeof(struct yaca_key_simple_s) + simple->bit_len / 8;

	ret = yaca_zalloc(size, (void**)&copy);
	if (ret != YACA_ERROR_NONE)
		return ret;

	memcpy(copy, key, size);
	*out = (yaca_key_h)copy;
	return YACA_ERROR_NONE;
}

static int encrypt_ctx_backup(struct yaca_encrypt_context_s *c,
                              const EVP_CIPHER *cipher,
                              const yaca_key_h sym_key,
                              const yaca_key_h iv)
{
	int ret;
	struct yaca_backup_context_s *bc;

	assert(c != NULL);
	assert(cipher != NULL);
	assert(sym_key != YACA_KEY_NULL);
	assert(c->backup_ctx == NULL);

	ret = yaca_zalloc(sizeof(struct yaca_backup_context_s), (void**)&bc);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = key_copy_simple(sym_key, &bc->sym_key);
	if (ret != YACA_ERROR_NONE)
		goto err;
	if (iv != YACA_KEY_NULL) {
		ret = key_copy_simple(iv, &bc->iv);
		if (ret != YACA_ERROR_NONE)
			goto err;
	}
	bc->cipher = cipher;
	bc->padding = YACA_PADDING_PKCS7;

	c->backup_ctx = bc;

	return YACA_ERROR_NONE;

err:
	yaca_key_destroy(bc->iv);
	yaca_key_destroy(bc->sym_key);
	yaca_free(bc);
	return ret;
}

static int encrypt_ctx_restore(struct yaca_encrypt_context_s *c)
{
	int ret;
	struct yaca_key_simple_s *key;

	assert(c != NULL);
	assert(c->backup_ctx != NULL);

	ret = EVP_CIPHER_CTX_cleanup(c->cipher_ctx);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	key = key_get_simple(c->backup_ctx->sym_key);
	assert(key != NULL);

	ret = encrypt_ctx_init(c, c->backup_ctx->cipher, key->bit_len);
	assert(ret != YACA_ERROR_INVALID_PARAMETER);
	if (ret != YACA_ERROR_NONE)
		return ret;

	if (c->backup_ctx->padding == YACA_PADDING_NONE &&
	    EVP_CIPHER_CTX_set_padding(c->cipher_ctx, 0) != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	return ret;
}

static int encrypt_ctx_set_ccm_tag_len(struct yaca_encrypt_context_s *c, size_t tag_len)
{
	int ret;

	assert(c != NULL);
	assert(c->backup_ctx != NULL);
	assert(is_encryption_op(c->op_type));

	ret = encrypt_ctx_restore(c);
	if (ret != YACA_ERROR_NONE)
		return ret;

	c->tag_len = tag_len;
	ret = EVP_CIPHER_CTX_ctrl(c->cipher_ctx, EVP_CTRL_CCM_SET_TAG, tag_len, NULL);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	ret = encrypt_ctx_setup(c, c->backup_ctx->sym_key, c->backup_ctx->iv);
	assert(ret != YACA_ERROR_INVALID_PARAMETER);
	return ret;
}

static int encrypt_ctx_set_ccm_tag(struct yaca_encrypt_context_s *c, char *tag, size_t tag_len)
{
	int ret;

	assert(c != NULL);
	assert(c->backup_ctx != NULL);
	assert(!is_encryption_op(c->op_type));
	assert(tag != NULL);

	ret = encrypt_ctx_restore(c);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = EVP_CIPHER_CTX_ctrl(c->cipher_ctx, EVP_CTRL_CCM_SET_TAG, tag_len, tag);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	ret = encrypt_ctx_setup(c, c->backup_ctx->sym_key, c->backup_ctx->iv);
	assert(ret != YACA_ERROR_INVALID_PARAMETER);
	return ret;
}

static int encrypt_ctx_set_rc2_effective_key_bits(struct yaca_encrypt_context_s *c, size_t key_bits)
{
	int ret;

	assert(c != NULL);
	assert(c->backup_ctx != NULL);

	if (key_bits == 0 || key_bits > 1024)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = encrypt_ctx_restore(c);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = EVP_CIPHER_CTX_ctrl(c->cipher_ctx, EVP_CTRL_SET_RC2_KEY_BITS, key_bits, NULL);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	ret = encrypt_ctx_setup(c, c->backup_ctx->sym_key, c->backup_ctx->iv);
	assert(ret != YACA_ERROR_INVALID_PARAMETER);
	return ret;
}

static int set_encrypt_property(yaca_context_h ctx,
                                yaca_property_e property,
                                const void *value,
                                size_t value_len)
{
	int len;
	int ret = YACA_ERROR_NONE;
	struct yaca_encrypt_context_s *c = get_encrypt_context(ctx);
	assert(c != NULL);
	assert(c->cipher_ctx != NULL);

	if (value == NULL || value_len == 0)
		return YACA_ERROR_INVALID_PARAMETER;

	int mode = EVP_CIPHER_CTX_mode(c->cipher_ctx);
	int nid = EVP_CIPHER_CTX_nid(c->cipher_ctx);

	switch (property) {
	case YACA_PROPERTY_GCM_AAD:
		if (mode != EVP_CIPH_GCM_MODE ||
		    !verify_state_change(c, ENC_CTX_AAD_UPDATED))
			return YACA_ERROR_INVALID_PARAMETER;

		if (EVP_CipherUpdate(c->cipher_ctx, NULL, &len, value, value_len) != 1) {
			ret = YACA_ERROR_INTERNAL;
			ERROR_DUMP(ret);
			return ret;
		}
		c->state = ENC_CTX_AAD_UPDATED;
		break;
	case YACA_PROPERTY_CCM_AAD:
		if (mode != EVP_CIPH_CCM_MODE ||
		    !verify_state_change(c, ENC_CTX_AAD_UPDATED))
			return YACA_ERROR_INVALID_PARAMETER;

		if (EVP_CipherUpdate(c->cipher_ctx, NULL, &len, value, value_len) != 1) {
			ret = YACA_ERROR_INTERNAL;
			ERROR_DUMP(ret);
			return ret;
		}
		c->state = ENC_CTX_AAD_UPDATED;
		break;
	case YACA_PROPERTY_GCM_TAG:
		if (mode != EVP_CIPH_GCM_MODE || is_encryption_op(c->op_type) ||
		    !is_valid_tag_len(mode, value_len) ||
		    !verify_state_change(c, ENC_CTX_TAG_SET))
			return YACA_ERROR_INVALID_PARAMETER;

		if (EVP_CIPHER_CTX_ctrl(c->cipher_ctx, EVP_CTRL_GCM_SET_TAG, value_len, (void*)value) != 1) {
			ret = YACA_ERROR_INTERNAL;
			ERROR_DUMP(ret);
			return ret;
		}
		c->state = ENC_CTX_TAG_SET;
		break;
	case YACA_PROPERTY_GCM_TAG_LEN:
		if (value_len != sizeof(size_t) || mode != EVP_CIPH_GCM_MODE ||
		    !is_encryption_op(c->op_type) ||
		    !is_valid_tag_len(mode, *(size_t*)value) ||
		    !verify_state_change(c, ENC_CTX_TAG_LENGTH_SET))
			return YACA_ERROR_INVALID_PARAMETER;

		c->tag_len = *(size_t*)value;
		c->state = ENC_CTX_TAG_LENGTH_SET;
		break;
	case YACA_PROPERTY_CCM_TAG:
		if (mode != EVP_CIPH_CCM_MODE || is_encryption_op(c->op_type) ||
		    !is_valid_tag_len(mode, value_len) ||
		    !verify_state_change(c, ENC_CTX_TAG_SET))
			return YACA_ERROR_INVALID_PARAMETER;

		ret = encrypt_ctx_set_ccm_tag(c, (char*)value, value_len);
		if (ret != YACA_ERROR_NONE)
			return ret;

		c->state = ENC_CTX_TAG_SET;
		break;
	case YACA_PROPERTY_CCM_TAG_LEN:
		if (value_len != sizeof(size_t) || mode != EVP_CIPH_CCM_MODE ||
		    !is_encryption_op(c->op_type) ||
		    !is_valid_tag_len(mode, *(size_t*)value) ||
		    !verify_state_change(c, ENC_CTX_TAG_LENGTH_SET))
			return YACA_ERROR_INVALID_PARAMETER;

		ret = encrypt_ctx_set_ccm_tag_len(c, *(size_t*)value);
		if (ret != YACA_ERROR_NONE)
			return ret;

		c->state = ENC_CTX_TAG_LENGTH_SET;
		break;
	case YACA_PROPERTY_PADDING:
		if ((mode != EVP_CIPH_ECB_MODE && mode != EVP_CIPH_CBC_MODE) ||
		    value_len != sizeof(yaca_padding_e) ||
		    (*(yaca_padding_e*)value != YACA_PADDING_NONE &&
		    *(yaca_padding_e*)value != YACA_PADDING_PKCS7) ||
		    ((is_encryption_op(c->op_type)) && c->state == ENC_CTX_FINALIZED) ||
		    (!(is_encryption_op(c->op_type)) && c->state != ENC_CTX_INITIALIZED))
			return YACA_ERROR_INVALID_PARAMETER;

		int padding = *(yaca_padding_e*)value == YACA_PADDING_NONE ? 0 : 1;
		if (EVP_CIPHER_CTX_set_padding(c->cipher_ctx, padding) != 1) {
			ret = YACA_ERROR_INTERNAL;
			ERROR_DUMP(ret);
			return ret;
		}
		if (c->backup_ctx != NULL)
			c->backup_ctx->padding = padding;
		break;
	case YACA_PROPERTY_RC2_EFFECTIVE_KEY_BITS:
		if (value_len != sizeof(size_t) ||
		    (nid != NID_rc2_cbc && nid != NID_rc2_ecb && nid != NID_rc2_cfb64 && nid != NID_rc2_ofb64) ||
		    c->state != ENC_CTX_INITIALIZED)
			return YACA_ERROR_INVALID_PARAMETER;

		ret = encrypt_ctx_set_rc2_effective_key_bits(c, *(size_t*)value);
		break;
	default:
		return YACA_ERROR_INVALID_PARAMETER;
	}

	return ret;
}

static int get_encrypt_property(const yaca_context_h ctx, yaca_property_e property,
                                void **value, size_t *value_len)
{
	int ret;
	void *tag = NULL;
	struct yaca_encrypt_context_s *c = get_encrypt_context(ctx);
	int mode;

	if (c == NULL || value == NULL)
		return YACA_ERROR_INVALID_PARAMETER;
	assert(c->cipher_ctx != NULL);

	mode = EVP_CIPHER_CTX_mode(c->cipher_ctx);

	switch (property) {
	case YACA_PROPERTY_GCM_TAG:
		if (value_len == NULL ||
		    !is_encryption_op(c->op_type) ||
		    mode != EVP_CIPH_GCM_MODE ||
		    (c->state != ENC_CTX_TAG_LENGTH_SET && c->state != ENC_CTX_FINALIZED))
			return YACA_ERROR_INVALID_PARAMETER;

		assert(c->tag_len <= INT_MAX);

		ret = yaca_malloc(c->tag_len, &tag);
		if (ret != YACA_ERROR_NONE)
			return ret;

		if (EVP_CIPHER_CTX_ctrl(c->cipher_ctx,
		                        EVP_CTRL_GCM_GET_TAG,
		                        c->tag_len,
		                        tag) != 1) {
			ret = YACA_ERROR_INTERNAL;
			ERROR_DUMP(ret);
			goto err;
		}
		*value = tag;
		*value_len = c->tag_len;
		break;
	case YACA_PROPERTY_CCM_TAG:
		if (value_len == NULL ||
		    !is_encryption_op(c->op_type) ||
		    mode != EVP_CIPH_CCM_MODE ||
		    c->state != ENC_CTX_FINALIZED)
			return YACA_ERROR_INVALID_PARAMETER;

		assert(c->tag_len <= INT_MAX);

		ret = yaca_malloc(c->tag_len, &tag);
		if (ret != YACA_ERROR_NONE)
			return ret;

		if (EVP_CIPHER_CTX_ctrl(c->cipher_ctx,
		                        EVP_CTRL_CCM_GET_TAG,
		                        c->tag_len,
		                        tag) != 1) {
			ret = YACA_ERROR_INTERNAL;
			ERROR_DUMP(ret);
			goto err;
		}
		*value = tag;
		*value_len = c->tag_len;
		break;
	default:
		return YACA_ERROR_INVALID_PARAMETER;
		break;
	}

	return YACA_ERROR_NONE;

err:
	yaca_free(tag);
	return ret;
}

static int check_key_bit_length_for_algo(yaca_encrypt_algorithm_e algo, size_t key_bit_len)
{
	assert(key_bit_len % 8 == 0);
	int ret = YACA_ERROR_NONE;

	switch (algo) {
	case YACA_ENCRYPT_AES:
		if (key_bit_len != YACA_KEY_LENGTH_UNSAFE_128BIT &&
		    key_bit_len != YACA_KEY_LENGTH_192BIT &&
		    key_bit_len != YACA_KEY_LENGTH_256BIT)
			ret = YACA_ERROR_INVALID_PARAMETER;
		break;
	case YACA_ENCRYPT_UNSAFE_DES:
		if (key_bit_len != YACA_KEY_LENGTH_UNSAFE_64BIT)
			ret = YACA_ERROR_INVALID_PARAMETER;
		break;
	case YACA_ENCRYPT_UNSAFE_3DES_2TDEA:
		if (key_bit_len != YACA_KEY_LENGTH_UNSAFE_128BIT)
			ret = YACA_ERROR_INVALID_PARAMETER;
		break;
	case YACA_ENCRYPT_3DES_3TDEA:
		if (key_bit_len != YACA_KEY_LENGTH_192BIT)
			ret = YACA_ERROR_INVALID_PARAMETER;
		break;
	case YACA_ENCRYPT_UNSAFE_RC2:
		if (key_bit_len < YACA_KEY_LENGTH_UNSAFE_8BIT || key_bit_len > YACA_KEY_LENGTH_1024BIT)
			ret = YACA_ERROR_INVALID_PARAMETER;
		break;
	case YACA_ENCRYPT_UNSAFE_RC4:
		if (key_bit_len < YACA_KEY_LENGTH_UNSAFE_40BIT || key_bit_len > YACA_KEY_LENGTH_2048BIT)
			ret = YACA_ERROR_INVALID_PARAMETER;
		break;
	case YACA_ENCRYPT_CAST5:
		if (key_bit_len < YACA_KEY_LENGTH_UNSAFE_40BIT || key_bit_len > YACA_KEY_LENGTH_UNSAFE_128BIT)
			ret = YACA_ERROR_INVALID_PARAMETER;
		break;
	default:
		ret = YACA_ERROR_INVALID_PARAMETER;
		break;
	}

	return ret;
}

int encrypt_get_algorithm(yaca_encrypt_algorithm_e algo,
                          yaca_block_cipher_mode_e bcm,
                          size_t key_bit_len,
                          const EVP_CIPHER **cipher)
{
	int ret;
	size_t i;

	assert(cipher != NULL);

	ret = check_key_bit_length_for_algo(algo, key_bit_len);
	if (ret != YACA_ERROR_NONE)
		return ret;

	*cipher = NULL;
	ret = YACA_ERROR_INVALID_PARAMETER;

	for (i = 0; i < ENCRYPTION_CIPHERS_SIZE; ++i)
		if (ENCRYPTION_CIPHERS[i].algo == algo &&
		    ENCRYPTION_CIPHERS[i].bcm == bcm &&
		    (ENCRYPTION_CIPHERS[i].key_bit_len == key_bit_len ||
		     ENCRYPTION_CIPHERS[i].key_bit_len == (size_t)-1)) {
			*cipher = ENCRYPTION_CIPHERS[i].cipher();
			ret = YACA_ERROR_NONE;
			break;
		}

	if (ret == YACA_ERROR_NONE && *cipher == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	return ret;
}

int encrypt_initialize(yaca_context_h *ctx,
                       const EVP_CIPHER *cipher,
                       const yaca_key_h sym_key,
                       const yaca_key_h iv,
                       enum encrypt_op_type_e op_type)
{
	struct yaca_encrypt_context_s *nc;
	struct yaca_key_simple_s *lsym_key;
	int ret;

	if (ctx == NULL || sym_key == YACA_KEY_NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	lsym_key = key_get_simple(sym_key);
	assert(lsym_key != NULL);

	if (lsym_key->key.type != YACA_KEY_TYPE_DES &&
	    lsym_key->key.type != YACA_KEY_TYPE_SYMMETRIC)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = encrypt_ctx_create(&nc, op_type, cipher);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = encrypt_ctx_init(nc, cipher, lsym_key->bit_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = encrypt_ctx_setup(nc, sym_key, iv);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	int mode = EVP_CIPHER_CTX_mode(nc->cipher_ctx);
	int nid = EVP_CIPHER_CTX_nid(nc->cipher_ctx);
	if (mode == EVP_CIPH_CCM_MODE ||
	    nid == NID_rc2_cbc || nid == NID_rc2_ecb || nid == NID_rc2_cfb64 || nid == NID_rc2_ofb64) {
		ret = encrypt_ctx_backup(nc, cipher, sym_key, iv);
		if (ret != YACA_ERROR_NONE)
			goto exit;
	}

	nc->state = ENC_CTX_INITIALIZED;

	*ctx = (yaca_context_h)nc;
	nc = NULL;
	ret = YACA_ERROR_NONE;

exit:
	yaca_context_destroy((yaca_context_h)nc);

	return ret;
}

int encrypt_update(yaca_context_h ctx,
                   const unsigned char *input, size_t input_len,
                   unsigned char *output, size_t *output_len,
                   enum encrypt_op_type_e op_type)
{
	struct yaca_encrypt_context_s *c = get_encrypt_context(ctx);
	int ret;
	int loutput_len;

	if (c == NULL || input_len == 0 || output_len == NULL || op_type != c->op_type)
		return YACA_ERROR_INVALID_PARAMETER;

	int mode = EVP_CIPHER_CTX_mode(c->cipher_ctx);
	int nid = EVP_CIPHER_CTX_nid(c->cipher_ctx);

	enum encrypt_context_state_e target_state;
	if (output == NULL && input == NULL)
		target_state = ENC_CTX_MSG_LENGTH_UPDATED;
	else if (output == NULL)
		target_state = ENC_CTX_AAD_UPDATED;
	else if (input == NULL)
		return YACA_ERROR_INVALID_PARAMETER;
	else
		target_state = ENC_CTX_MSG_UPDATED;

	if (!verify_state_change(c, target_state))
		return YACA_ERROR_INVALID_PARAMETER;

	if (mode == EVP_CIPH_WRAP_MODE) {
		if (op_type == OP_ENCRYPT) {
			if (nid == NID_id_aes128_wrap || nid == NID_id_aes192_wrap || nid == NID_id_aes256_wrap) {
				if (input_len % 8 != 0 || input_len < (YACA_KEY_LENGTH_UNSAFE_128BIT / 8))
					return YACA_ERROR_INVALID_PARAMETER;
			} else if (nid == NID_id_smime_alg_CMS3DESwrap) {
				if (input_len != (YACA_KEY_LENGTH_UNSAFE_128BIT / 8) &&
				    input_len != (YACA_KEY_LENGTH_192BIT / 8))
					return YACA_ERROR_INVALID_PARAMETER;
			} else {
				assert(false);
				return YACA_ERROR_INTERNAL;
			}
		} else if (op_type == OP_DECRYPT) {
			if (nid == NID_id_aes128_wrap || nid == NID_id_aes192_wrap || nid == NID_id_aes256_wrap) {
				if (input_len % 8 != 0 || input_len < (YACA_KEY_LENGTH_UNSAFE_128BIT / 8 + 8))
					return YACA_ERROR_INVALID_PARAMETER;
			} else if (nid == NID_id_smime_alg_CMS3DESwrap) {
				if (input_len != (YACA_KEY_LENGTH_UNSAFE_128BIT / 8 + 16) &&
				    input_len != (YACA_KEY_LENGTH_192BIT / 8 + 16))
					return YACA_ERROR_INVALID_PARAMETER;
			} else {
				assert(false);
				return YACA_ERROR_INTERNAL;
			}
		} else {
			assert(false);
			return YACA_ERROR_INTERNAL;
		}
	}

	ret = EVP_CipherUpdate(c->cipher_ctx, output, &loutput_len, input, input_len);
	if (ret != 1 || loutput_len < 0) {
		if (mode == EVP_CIPH_CCM_MODE && (op_type == OP_DECRYPT || op_type == OP_OPEN)) {
			/* A non positive return value from EVP_CipherUpdate should be considered as
			 * a failure to authenticate ciphertext and/or AAD.
			 * It does not necessarily indicate a more serious error.
			 * There is no call to EVP_CipherFinal.
			 */
			return YACA_ERROR_INVALID_PARAMETER;
		} else {
			ret = YACA_ERROR_INTERNAL;
			ERROR_DUMP(ret);
			return ret;
		}
	}

	*output_len = loutput_len;

	c->state = target_state;
	return YACA_ERROR_NONE;
}

int encrypt_finalize(yaca_context_h ctx,
                     unsigned char *output, size_t *output_len,
                     enum encrypt_op_type_e op_type)
{
	struct yaca_encrypt_context_s *c = get_encrypt_context(ctx);
	int ret;
	int mode;
	int loutput_len = 0;

	if (c == NULL || output == NULL || output_len == NULL || op_type != c->op_type)
		return YACA_ERROR_INVALID_PARAMETER;

	if (!verify_state_change(c, ENC_CTX_FINALIZED))
		return YACA_ERROR_INVALID_PARAMETER;

	mode = EVP_CIPHER_CTX_mode(c->cipher_ctx);
	if (mode != EVP_CIPH_WRAP_MODE && mode != EVP_CIPH_CCM_MODE) {
		ret = EVP_CipherFinal(c->cipher_ctx, output, &loutput_len);
		if (ret != 1 || loutput_len < 0) {
			if (mode == EVP_CIPH_GCM_MODE && (op_type == OP_DECRYPT || op_type == OP_OPEN)) {
				/* A non positive return value from EVP_CipherFinal should be
				 * considered as a failure to authenticate ciphertext and/or
				 * AAD. It does not necessarily indicate a more serious error.
				 */
				return YACA_ERROR_INVALID_PARAMETER;
			} else {
				/* The same error code is used if trying to import a key with a
				 * wrong password and in case of a decrypt error due to wrong
				 * BCM or a key. Finalize cannot return INVALID_PASS so handle
				 * this here.
				 */
				ret = ERROR_HANDLE();
				if (ret == YACA_ERROR_INVALID_PASSWORD)
					ret = YACA_ERROR_INVALID_PARAMETER;
				return ret;
			}
		}
	}

	*output_len = loutput_len;

	c->state = ENC_CTX_FINALIZED;
	return YACA_ERROR_NONE;
}

API int yaca_encrypt_get_iv_bit_length(yaca_encrypt_algorithm_e algo,
                                       yaca_block_cipher_mode_e bcm,
                                       size_t key_bit_len,
                                       size_t *iv_bit_len)
{
	int ret;
	const EVP_CIPHER *cipher;

	if (iv_bit_len == NULL || key_bit_len % 8 != 0)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = encrypt_get_algorithm(algo, bcm, key_bit_len, &cipher);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = EVP_CIPHER_iv_length(cipher);
	if (ret < 0) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	*iv_bit_len = ret * 8;
	return YACA_ERROR_NONE;
}

API int yaca_encrypt_initialize(yaca_context_h *ctx,
                                yaca_encrypt_algorithm_e algo,
                                yaca_block_cipher_mode_e bcm,
                                const yaca_key_h sym_key,
                                const yaca_key_h iv)
{
	int ret;
	const EVP_CIPHER *cipher;
	struct yaca_key_simple_s *key = key_get_simple(sym_key);

	if (key == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = encrypt_get_algorithm(algo, bcm, key->bit_len, &cipher);
	if (ret != YACA_ERROR_NONE)
		return ret;

	return encrypt_initialize(ctx, cipher, sym_key, iv, OP_ENCRYPT);
}

API int yaca_encrypt_update(yaca_context_h ctx,
                            const char *plaintext,
                            size_t plaintext_len,
                            char *ciphertext,
                            size_t *ciphertext_len)
{
	return encrypt_update(ctx, (const unsigned char*)plaintext, plaintext_len,
	                      (unsigned char*)ciphertext, ciphertext_len, OP_ENCRYPT);
}

API int yaca_encrypt_finalize(yaca_context_h ctx,
                              char *ciphertext,
                              size_t *ciphertext_len)
{
	return encrypt_finalize(ctx, (unsigned char*)ciphertext, ciphertext_len, OP_ENCRYPT);
}

API int yaca_decrypt_initialize(yaca_context_h *ctx,
                                yaca_encrypt_algorithm_e algo,
                                yaca_block_cipher_mode_e bcm,
                                const yaca_key_h sym_key,
                                const yaca_key_h iv)
{
	int ret;
	const EVP_CIPHER *cipher;
	struct yaca_key_simple_s *key = key_get_simple(sym_key);

	if (key == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = encrypt_get_algorithm(algo, bcm, key->bit_len, &cipher);
	if (ret != YACA_ERROR_NONE)
		return ret;

	return encrypt_initialize(ctx, cipher, sym_key, iv, OP_DECRYPT);
}

API int yaca_decrypt_update(yaca_context_h ctx,
                            const char *ciphertext,
                            size_t ciphertext_len,
                            char *plaintext,
                            size_t *plaintext_len)
{
	return encrypt_update(ctx, (const unsigned char*)ciphertext, ciphertext_len,
	                      (unsigned char*)plaintext, plaintext_len, OP_DECRYPT);
}

API int yaca_decrypt_finalize(yaca_context_h ctx,
                              char *plaintext,
                              size_t *plaintext_len)
{
	return encrypt_finalize(ctx, (unsigned char*)plaintext, plaintext_len, OP_DECRYPT);
}
