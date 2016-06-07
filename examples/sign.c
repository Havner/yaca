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
 * @file sign.c
 * @brief
 */

#include <stdio.h>

#include <yaca_crypto.h>
#include <yaca_sign.h>
#include <yaca_key.h>
#include <yaca_error.h>
#include <yaca_simple.h>

#include "lorem.h"
#include "misc.h"
#include "../src/debug.h"

// Signature creation and verification using simple API
void simple_sign_verify_asym(yaca_key_type_e type, const char *algo)
{
	char *signature = NULL;
	size_t signature_len;

	yaca_key_h prv = YACA_KEY_NULL;
	yaca_key_h pub = YACA_KEY_NULL;

	// GENERATE
	if (yaca_key_generate(type, YACA_KEY_LENGTH_1024BIT, &prv) != YACA_ERROR_NONE)
		return;

	if (yaca_key_extract_public(prv, &pub) != YACA_ERROR_NONE)
		goto exit;

	// SIGN
	if (yaca_simple_calculate_signature(YACA_DIGEST_SHA512,
	              prv,
	              lorem4096,
	              LOREM4096_SIZE,
	              &signature,
	              &signature_len) != YACA_ERROR_NONE)
		goto exit;

	dump_hex(signature, signature_len, "[Simple API] %s Signature of lorem4096:", algo);

	// VERIFY
	if (yaca_simple_verify_signature(YACA_DIGEST_SHA512,
	                pub,
	                lorem4096,
	                LOREM4096_SIZE,
	                signature,
	                signature_len) != YACA_ERROR_NONE)
		printf("[Simple API] %s verification failed\n", algo);
	else
		printf("[Simple API] %s verification successful\n", algo);

exit:
	yaca_free(signature);
	yaca_key_destroy(prv);
	yaca_key_destroy(pub);
}

void simple_sign_verify_hmac(void)
{
	char *signature1 = NULL;
	char *signature2 = NULL;
	size_t signature_len;

	yaca_key_h key = YACA_KEY_NULL;

	// GENERATE
	if (yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, &key) != YACA_ERROR_NONE)
		return;

	// SIGN
	if (yaca_simple_calculate_hmac(YACA_DIGEST_SHA512,
	              key,
	              lorem4096,
	              LOREM4096_SIZE,
	              &signature1,
	              &signature_len) != YACA_ERROR_NONE)
		goto exit;

	dump_hex(signature1, signature_len, "[Simple API] HMAC Signature of lorem4096:");

	// VERIFY
	if (yaca_simple_calculate_hmac(YACA_DIGEST_SHA512,
	              key,
	              lorem4096,
	              LOREM4096_SIZE,
	              &signature2,
	              &signature_len) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_memcmp(signature1, signature2, signature_len) != YACA_ERROR_NONE)
		printf("[Simple API] HMAC verification failed\n");
	else
		printf("[Simple API] HMAC verification successful\n");

exit:
	yaca_free(signature1);
	yaca_free(signature2);
	yaca_key_destroy(key);
}

void simple_sign_verify_cmac(void)
{
	char *signature1 = NULL;
	char *signature2 = NULL;
	size_t signature_len;

	yaca_key_h key = YACA_KEY_NULL;

	// GENERATE
	if (yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, &key))
		return;

	// SIGN
	if (yaca_simple_calculate_cmac(YACA_ENCRYPT_AES,
	              key,
	              lorem4096,
	              LOREM4096_SIZE,
	              &signature1,
	              &signature_len) != YACA_ERROR_NONE)
		goto exit;

	dump_hex(signature1, signature_len, "[Simple API] CMAC Signature of lorem4096:");


	// VERIFY
	if (yaca_simple_calculate_cmac(YACA_ENCRYPT_AES,
	              key,
	              lorem4096,
	              LOREM4096_SIZE,
	              &signature2,
	              &signature_len) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_memcmp(signature1, signature2, signature_len) != YACA_ERROR_NONE)
		printf("[Simple API] CMAC verification failed\n");
	else
		printf("[Simple API] CMAC verification successful\n");

exit:
	yaca_free(signature1);
	yaca_free(signature2);
	yaca_key_destroy(key);
}

// Signature creation and verification using advanced API
void sign_verify_asym(yaca_key_type_e type, const char *algo)
{
	char *signature = NULL;
	size_t signature_len;

	yaca_context_h ctx = YACA_CONTEXT_NULL;
	yaca_key_h prv = YACA_KEY_NULL;
	yaca_key_h pub = YACA_KEY_NULL;
	yaca_padding_e padding = YACA_PADDING_PKCS1_PSS;

	// GENERATE
	if (yaca_key_generate(type, YACA_KEY_LENGTH_1024BIT, &prv) != YACA_ERROR_NONE)
		return;

	if (yaca_key_extract_public(prv, &pub) != YACA_ERROR_NONE)
		goto exit;

	// SIGN
	if (yaca_sign_initialize(&ctx, YACA_DIGEST_SHA512, prv) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_context_set_property(ctx, YACA_PROPERTY_PADDING, (char*)(&padding), sizeof(padding)) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_sign_update(ctx, lorem4096, LOREM4096_SIZE) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_context_get_output_length(ctx, 0, &signature_len) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_malloc(signature_len, (void**)&signature) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_sign_finalize(ctx, signature, &signature_len) != YACA_ERROR_NONE)
		goto exit;

	dump_hex(signature, signature_len, "[Advanced API] %s Signature of lorem4096:", algo);

	// CLEANUP
	yaca_context_destroy(ctx);
	ctx = YACA_CONTEXT_NULL;

	// VERIFY
	if (yaca_verify_initialize(&ctx, YACA_DIGEST_SHA512, pub) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_context_set_property(ctx, YACA_PROPERTY_PADDING, (char*)(&padding), sizeof(padding)) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_verify_update(ctx, lorem4096, LOREM4096_SIZE) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_verify_finalize(ctx, signature, signature_len) != YACA_ERROR_NONE)
		printf("[Advanced API] %s verification failed\n", algo);
	else
		printf("[Advanced API] %s verification successful\n", algo);

exit:
	yaca_free(signature);
	yaca_key_destroy(prv);
	yaca_key_destroy(pub);
	yaca_context_destroy(ctx);
}

void sign_verify_hmac(void)
{
	char *signature1 = NULL;
	char *signature2 = NULL;
	size_t signature_len;

	yaca_context_h ctx = YACA_CONTEXT_NULL;
	yaca_key_h key = YACA_KEY_NULL;

	// GENERATE
	if (yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, &key) != YACA_ERROR_NONE)
		return;

	// SIGN
	if (yaca_sign_initialize_hmac(&ctx, YACA_DIGEST_SHA512, key) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_sign_update(ctx, lorem4096, LOREM4096_SIZE) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_context_get_output_length(ctx, 0, &signature_len) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_malloc(signature_len, (void**)&signature1) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_sign_finalize(ctx, signature1, &signature_len) != YACA_ERROR_NONE)
		goto exit;

	dump_hex(signature1, signature_len, "[Advanced API] HMAC Signature of lorem4096:");

	// CLEANUP
	yaca_context_destroy(ctx);
	ctx = YACA_CONTEXT_NULL;

	// VERIFY
	if (yaca_sign_initialize_hmac(&ctx, YACA_DIGEST_SHA512, key) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_sign_update(ctx, lorem4096, LOREM4096_SIZE) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_context_get_output_length(ctx, 0, &signature_len) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_malloc(signature_len, (void**)&signature2) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_sign_finalize(ctx, signature2, &signature_len) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_memcmp(signature1, signature2, signature_len) != YACA_ERROR_NONE)
		printf("[Advanced API] HMAC verification failed\n");
	else
		printf("[Advanced API] HMAC verification successful\n");

exit:
	yaca_free(signature1);
	yaca_free(signature2);
	yaca_key_destroy(key);
	yaca_context_destroy(ctx);
}

void sign_verify_cmac(void)
{
	char *signature1 = NULL;
	char *signature2 = NULL;
	size_t signature_len;

	yaca_context_h ctx = YACA_CONTEXT_NULL;
	yaca_key_h key = YACA_KEY_NULL;

	// GENERATE
	if (yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, &key))
		return;

	// SIGN
	if (yaca_sign_initialize_cmac(&ctx, YACA_ENCRYPT_AES, key) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_sign_update(ctx, lorem4096, LOREM4096_SIZE))
		goto exit;

	if (yaca_context_get_output_length(ctx, 0, &signature_len) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_malloc(signature_len, (void**)&signature1) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_sign_finalize(ctx, signature1, &signature_len))
		goto exit;

	dump_hex(signature1, signature_len, "[Advanced API] CMAC Signature of lorem4096:");

	// CLEANUP
	yaca_context_destroy(ctx);
	ctx = YACA_CONTEXT_NULL;

	// VERIFY
	if (yaca_sign_initialize_cmac(&ctx, YACA_ENCRYPT_AES, key) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_sign_update(ctx, lorem4096, LOREM4096_SIZE))
		goto exit;

	if (yaca_context_get_output_length(ctx, 0, &signature_len) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_malloc(signature_len, (void**)&signature2) != YACA_ERROR_NONE)
		goto exit;

	if (yaca_sign_finalize(ctx, signature2, &signature_len))
		goto exit;

	if (yaca_memcmp(signature1, signature2, signature_len) != YACA_ERROR_NONE)
		printf("[Advanced API] CMAC verification failed\n");
	else
		printf("[Advanced API] CMAC verification successful\n");

exit:
	yaca_free(signature1);
	yaca_free(signature2);
	yaca_key_destroy(key);
	yaca_context_destroy(ctx);
}

int main()
{
	yaca_debug_set_error_cb(debug_func);

	int ret = yaca_initialize();
	if (ret != YACA_ERROR_NONE)
		return ret;

	simple_sign_verify_asym(YACA_KEY_TYPE_RSA_PRIV, "RSA");
	simple_sign_verify_asym(YACA_KEY_TYPE_DSA_PRIV, "DSA");
	simple_sign_verify_cmac();
	simple_sign_verify_hmac();

	sign_verify_asym(YACA_KEY_TYPE_RSA_PRIV, "RSA");
	sign_verify_asym(YACA_KEY_TYPE_DSA_PRIV, "DSA");
	sign_verify_hmac();
	sign_verify_cmac();

	yaca_cleanup();
	return ret;
}
