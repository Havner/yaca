/*
 *  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact:
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
#include <yaca/crypto.h>
#include <yaca/sign.h>
#include <yaca/key.h>
#include <yaca/error.h>

#include "lorem.h"
#include "misc.h"

// Signature creation and verification using advanced API
void sign_verify_asym(yaca_key_type_e type, const char *algo)
{
	char* signature = NULL;
	size_t signature_len;

	yaca_ctx_h ctx = YACA_CTX_NULL;
	yaca_key_h prv = YACA_KEY_NULL;
	yaca_key_h pub = YACA_KEY_NULL;
	yaca_padding_e padding = YACA_PADDING_PKCS1_PSS;

	// GENERATE
	if (yaca_key_gen(&prv, type, YACA_KEY_1024BIT) != 0)
		return;

	if (yaca_key_extract_public(prv, &pub) != 0)
		goto finish;

	// SIGN
	if (yaca_sign_init(&ctx, YACA_DIGEST_SHA512, prv) != 0)
		goto finish;

	if (yaca_ctx_set_param(ctx, YACA_PARAM_PADDING, (char*)(&padding), sizeof(padding)) != 0)
		goto finish;

	if (yaca_sign_update(ctx, lorem4096, LOREM4096_SIZE) != 0)
		goto finish;

	if (yaca_get_sign_length(ctx, &signature_len) != 0)
		goto finish;

	if ((signature = yaca_malloc(signature_len)) == NULL)
		goto finish;

	if (yaca_sign_final(ctx, signature, &signature_len) != 0)
		goto finish;

	dump_hex(signature, signature_len, "%s Signature of lorem4096:", algo);

	// CLEANUP
	yaca_ctx_free(ctx);
	ctx = YACA_CTX_NULL;

	// VERIFY
	if (yaca_verify_init(&ctx, YACA_DIGEST_SHA512, pub) != 0)
		goto finish;

	if (yaca_ctx_set_param(ctx, YACA_PARAM_PADDING, (char*)(&padding), sizeof(padding)) != 0)
		goto finish;

	if (yaca_verify_update(ctx, lorem4096, LOREM4096_SIZE) != 0)
		goto finish;

	if (yaca_verify_final(ctx, signature, signature_len) != 0)
		printf("%s verification failed\n", algo);
	else
		printf("%s verification succesful\n", algo);

finish:
	yaca_free(signature);
	yaca_key_free(prv);
	yaca_key_free(pub);
	yaca_ctx_free(ctx);
}

void sign_verify_hmac(void)
{
	char* signature = NULL;
	size_t signature_len;

	yaca_ctx_h ctx = YACA_CTX_NULL;
	yaca_key_h key = YACA_KEY_NULL;

	// GENERATE
	if (yaca_key_gen(&key, YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_256BIT) != 0)
		return;

	// SIGN
	if (yaca_sign_init(&ctx, YACA_DIGEST_SHA512, key) != 0)
		goto finish;

	if (yaca_sign_update(ctx, lorem4096, LOREM4096_SIZE) != 0)
		goto finish;

	if (yaca_get_sign_length(ctx, &signature_len) != 0)
		goto finish;

	if ((signature = yaca_malloc(signature_len)) == NULL)
		goto finish;

	if (yaca_sign_final(ctx, signature, &signature_len) != 0)
		goto finish;

	dump_hex(signature, signature_len, "HMAC Signature of lorem4096:");

	// CLEANUP
	yaca_ctx_free(ctx);
	ctx = YACA_CTX_NULL;

	// VERIFY
	if (yaca_verify_init(&ctx, YACA_DIGEST_SHA512, key) != 0)
		goto finish;

	if (yaca_verify_update(ctx, lorem4096, LOREM4096_SIZE) != 0)
		goto finish;

	if (yaca_verify_final(ctx, signature, signature_len) != 0)
		printf("HMAC verification failed\n");
	else
		printf("HMAC verification succesful\n");

finish:
	yaca_free(signature);
	yaca_key_free(key);
	yaca_ctx_free(ctx);
}

void sign_verify_cmac(void)
{
	char* signature = NULL;
	size_t signature_len;

	yaca_ctx_h ctx = YACA_CTX_NULL;
	yaca_key_h key = YACA_KEY_NULL;

	// GENERATE
	if (yaca_key_gen(&key, YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_256BIT))
		return;

	// SIGN
	// TODO: CMAC must extract the key length to select the proper evp (EVP_aes_XXX_cbc()) it should be documented
	if (yaca_sign_init(&ctx, YACA_DIGEST_CMAC, key) != 0)
		goto finish;

	if (yaca_sign_update(ctx, lorem4096, LOREM4096_SIZE))
		goto finish;

	if (yaca_get_sign_length(ctx, &signature_len) != 0)
		goto finish;

	if ((signature = yaca_malloc(signature_len)) == NULL)
		goto finish;

	if (yaca_sign_final(ctx, signature, &signature_len))
		goto finish;

	dump_hex(signature, signature_len, "CMAC Signature of lorem4096:");

	// CLEANUP
	yaca_ctx_free(ctx);
	ctx = YACA_CTX_NULL;

	// VERIFY
	if (yaca_verify_init(&ctx, YACA_DIGEST_CMAC, key) != 0)
		goto finish;

	if (yaca_verify_update(ctx, lorem4096, LOREM4096_SIZE) != 0)
		goto finish;

	if (yaca_verify_final(ctx, signature, signature_len) != 0)
		printf("CMAC verification failed\n");
	else
		printf("CMAC verification succesful\n");

finish:
	yaca_free(signature);
	yaca_key_free(key);
	yaca_ctx_free(ctx);
}

int main()
{
	yaca_error_set_debug_func(debug_func);

	int ret = yaca_init();
	if (ret < 0)
		return ret;

	// TODO simple?

	sign_verify_asym(YACA_KEY_TYPE_RSA_PRIV, "RSA");
	sign_verify_asym(YACA_KEY_TYPE_DSA_PRIV, "DSA");
	sign_verify_hmac();
	sign_verify_cmac();

	yaca_exit(); // TODO: what about handing of return value from exit??
	return ret;
}
