/*
 *  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file internal.h
 * @brief
 */

#ifndef YACA_INTERNAL_H
#define YACA_INTERNAL_H

#include <stddef.h>
#include <stdbool.h>

#include <openssl/ossl_typ.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>

#include <yaca_types.h>

#define API __attribute__ ((visibility("default")))
#define UNUSED __attribute__((unused))

/* Functions that handle the hidden nature of internal
 * OpenSSL structures that don't exist in OpenSSL < 1.1.0
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L

static inline EVP_PKEY_CTX *EVP_MD_CTX_pkey_ctx(const EVP_MD_CTX *ctx)
{
	return ctx->pctx;
}

static inline int EVP_PKEY_up_ref(EVP_PKEY *pkey)
{
	if (CRYPTO_add(&pkey->references, 1, CRYPTO_LOCK_EVP_PKEY) <= 0)
		return 0;
	return 1;
}

static inline RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey)
{
	if (pkey->type != EVP_PKEY_RSA)
		return NULL;
	return pkey->pkey.rsa;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

enum yaca_context_type_e {
	YACA_CONTEXT_INVALID = 0,
	YACA_CONTEXT_DIGEST,
	YACA_CONTEXT_SIGN,
	YACA_CONTEXT_ENCRYPT
};

enum encrypt_op_type_e {
	OP_ENCRYPT = 0,
	OP_DECRYPT = 1,
	OP_SEAL    = 2,
	OP_OPEN    = 3
};

/* Base structure for crypto contexts - to be inherited */
struct yaca_context_s {
	enum yaca_context_type_e type;

	void (*context_destroy)(const yaca_context_h ctx);
	int (*get_output_length)(const yaca_context_h ctx, size_t input_len, size_t *output_len);
	int (*set_property)(yaca_context_h ctx, yaca_property_e property,
	                    const void *value, size_t value_len);
	int (*get_property)(const yaca_context_h ctx, yaca_property_e property,
	                    void **value, size_t *value_len);
};

struct yaca_backup_context_s {
	const EVP_CIPHER *cipher;
	yaca_key_h sym_key;
	yaca_key_h iv;
	yaca_padding_e padding;
};

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

enum context_state_e {
	CTX_INITIALIZED = 0,
	CTX_MSG_UPDATED,
	CTX_FINALIZED,

	CTX_COUNT,
};

struct yaca_encrypt_context_s {
	struct yaca_context_s ctx;
	struct yaca_backup_context_s *backup_ctx;

	EVP_CIPHER_CTX *cipher_ctx;
	enum encrypt_op_type_e op_type; /* Operation context was created for */
	size_t tag_len;
	enum encrypt_context_state_e state;
};

/* Base structure for crypto keys - to be inherited */
struct yaca_key_s {
	yaca_key_type_e type;
};

/**
 * Internal type for:
 * - YACA_KEY_TYPE_SYMMETRIC
 * - YACA_KEY_TYPE_DES
 * - YACA_KEY_TYPE_IV
 */
struct yaca_key_simple_s {
	struct yaca_key_s key;

	size_t bit_len;
	char d[];
};

/**
 * Internal type for:
 * - YACA_KEY_TYPE_RSA_PUB
 * - YACA_KEY_TYPE_RSA_PRIV
 * - YACA_KEY_TYPE_DSA_PUB
 * - YACA_KEY_TYPE_DSA_PRIV
 * - YACA_KEY_TYPE_DH_PUB
 * - YACA_KEY_TYPE_DH_PRIV
 * - YACA_KEY_TYPE_EC_PUB
 * - YACA_KEY_TYPE_EC_PRIV
 *
 */
struct yaca_key_evp_s {
	struct yaca_key_s key;

	EVP_PKEY *evp;
};

int digest_get_algorithm(yaca_digest_algorithm_e algo, const EVP_MD **md);

struct yaca_encrypt_context_s *get_encrypt_context(const yaca_context_h ctx);

void destroy_encrypt_context(const yaca_context_h ctx);

int get_encrypt_output_length(const yaca_context_h ctx, size_t input_len, size_t *output_len);

int set_encrypt_property(yaca_context_h ctx, yaca_property_e property,
                         const void *value, size_t value_len);

int get_encrypt_property(const yaca_context_h ctx, yaca_property_e property,
                         void **value, size_t *value_len);

int encrypt_get_algorithm(yaca_encrypt_algorithm_e algo,
                          yaca_block_cipher_mode_e bcm,
                          size_t key_bit_len,
                          const EVP_CIPHER **cipher);

int encrypt_initialize(yaca_context_h *ctx,
                       const EVP_CIPHER *cipher,
                       const yaca_key_h sym_key,
                       const yaca_key_h iv,
                       enum encrypt_op_type_e op_type);

int encrypt_update(yaca_context_h ctx,
                   const unsigned char *input, size_t input_len,
                   unsigned char *output, size_t *output_len,
                   enum encrypt_op_type_e op_type);

int encrypt_finalize(yaca_context_h ctx,
                     unsigned char *output, size_t *output_len,
                     enum encrypt_op_type_e op_type);

struct yaca_key_simple_s *key_get_simple(const yaca_key_h key);
struct yaca_key_evp_s *key_get_evp(const yaca_key_h key);

yaca_key_h key_copy(const yaca_key_h key);

void error_dump(const char *file, int line, const char *function, int code);
#define ERROR_DUMP(code) error_dump(__FILE__, __LINE__, __func__, (code))
#define ERROR_CLEAR() ERR_clear_error()

/**
 * Function responsible for translating the openssl error to yaca error and
 * clearing/dumping the openssl error queue. Use only after openssl function
 * failure.
 *
 * The function checks only first error in the queue. If the function doesn't
 * find any error in openssl queue or is not able to translate it, it will
 * return YACA_ERROR_INTERNAL and dump openssl errors if any. If the
 * translation succeeds the function will clear the error queue and return the
 * result of translation.
 */
int error_handle(const char *file, int line, const char *function);
#define ERROR_HANDLE() error_handle(__FILE__, __LINE__, __func__)

int rsa_padding2openssl(yaca_padding_e padding);

#endif /* YACA_INTERNAL_H */
