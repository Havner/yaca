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
#include "misc.h"

size_t IDX = 0;
size_t MAX_IDX = 2345;
const size_t SIZE = 666;

void reset()
{
	IDX = 0;
}

size_t read_data(char* buffer, size_t size)
{
	size_t i = 0;

	for(; i < size && IDX < MAX_IDX; i++, IDX++)
		buffer[i] = IDX%0xff;

	return i;
}

int sign(yaca_ctx_h ctx, char** signature, size_t* signature_len)
{
	char buffer[SIZE];

	reset();
	for (;;) {
		size_t read = read_data(buffer, SIZE);
		if (read == 0)
			break;

		if (yaca_sign_update(ctx, buffer, read))
			return -1;
	}

	// TODO: is it a size in bytes or length in characters?
	*signature_len = yaca_get_digest_length(ctx);
	*signature = (char*)yaca_malloc(*signature_len);

	// TODO: yaca_get_digest_length() returns int but yaca_sign_final accepts size_t. Use common type.
	if (yaca_sign_final(ctx, *signature, signature_len))
		return -1;

	dump_hex(*signature, *signature_len, "Message signature: ");

	return 0;
}

int verify(yaca_ctx_h ctx, const char* signature, size_t signature_len)
{
	char buffer[SIZE];

	reset();
	for (;;) {
		size_t read = read_data(buffer, SIZE);
		if (read == 0)
			break;

		if (yaca_verify_update(ctx, buffer, read))
			return -1;
	}

	// TODO: use int or size_t for output sizes
	if (yaca_verify_final(ctx, signature, (size_t)signature_len))
		return -1;

	printf("Verification succeeded\n");

	return 0;
}

// Signature creation and verification using advanced API
void sign_verify_rsa(void)
{
	char* signature = NULL;
	size_t signature_len;

	yaca_ctx_h ctx = YACA_CTX_NULL;
	yaca_key_h prv = YACA_KEY_NULL;
	yaca_key_h pub = YACA_KEY_NULL;
	yaca_padding_e padding = YACA_PADDING_PKCS1;


	// GENERATE

	if (yaca_key_gen_pair(&prv, &pub, YACA_KEY_4096BIT, YACA_KEY_TYPE_PAIR_RSA))
		return;


	// SIGN

	if (yaca_sign_init(&ctx, YACA_DIGEST_SHA512, prv))
		goto finish;

	// TODO: yaca_ctx_set_param should take void* not char*
	if (yaca_ctx_set_param(ctx, YACA_PARAM_PADDING, (char*)(&padding), sizeof(padding)))
		goto finish;

	if (sign(ctx, &signature, &signature_len))
		goto finish;

	// TODO: is this necessary or will next ctx init handle it?
	yaca_ctx_free(ctx);
	ctx = YACA_CTX_NULL;


	// VERIFY

	if (yaca_verify_init(&ctx, YACA_DIGEST_SHA512, pub))
		goto finish;

	if (yaca_ctx_set_param(ctx, YACA_PARAM_PADDING, (char*)(&padding), sizeof(padding)))
		goto finish;

	if (verify(ctx, signature, signature_len))
		goto finish;

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

	if (yaca_key_gen(&key, YACA_KEY_256BIT, YACA_KEY_TYPE_SYMMETRIC))
		return;

	// SIGN

	if (yaca_sign_init(&ctx, YACA_DIGEST_SHA512, key))
		goto finish;

	if (sign(ctx, &signature, &signature_len))
		goto finish;


	// VERIFY

	if (yaca_verify_init(&ctx, YACA_DIGEST_SHA512, key))
		goto finish;

	if (verify(ctx, signature, signature_len))
		goto finish;

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

	if( yaca_key_gen(&key, YACA_KEY_256BIT, YACA_KEY_TYPE_SYMMETRIC))
		return;

	// SIGN
	// TODO: CMAC must extract the key length to select the proper evp (EVP_aes_XXX_cbc()) it should be documented
	if( yaca_sign_init(&ctx, YACA_DIGEST_CMAC, key))
		goto finish;

	if( sign(ctx, &signature, &signature_len))
		goto finish;


	// VERIFY

	if( yaca_verify_init(&ctx, YACA_DIGEST_CMAC, key))
		goto finish;

	if( verify(ctx, signature, signature_len))
		goto finish;

finish:
	yaca_free(signature);
	yaca_key_free(key);
	yaca_ctx_free(ctx);
}


int main()
{
	int ret = yaca_init();
	if (ret < 0)
		return ret;

	// TODO simple?

	sign_verify_rsa();
	sign_verify_hmac();
	sign_verify_cmac();

	yaca_exit(); // TODO: what about handing of return value from exit??
	return ret;
}
