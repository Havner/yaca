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
#include <crypto/crypto.h>
#include <crypto/sign.h>
#include <crypto/key.h>
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

	for(; i<size && IDX < MAX_IDX; i++,IDX++)
		buffer[i] = IDX%0xff;

	return i;
}

int sign(crypto_ctx_h ctx, char** signature, size_t* signature_len)
{
	char buffer[SIZE];

	reset();
	for(;;) {
		size_t read = read_data(buffer, SIZE);
		if(read == 0)
			break;

		if(crypto_sign_update(ctx, buffer, read))
			return -1;
	}

	// TODO: is it a size in bytes or length in characters?
	*signature_len = crypto_get_digest_length(ctx);
	*signature = (char*)crypto_alloc(*signature_len);

	// TODO: crypto_get_digest_length() returns int but crypto_sign_final accepts size_t. Use common type.
	if(crypto_sign_final(ctx, *signature, signature_len))
		return -1;

	dump_hex(*signature, *signature_len, "Message signature: ");
	return 0;
}

int verify(crypto_ctx_h ctx, const char* signature, size_t signature_len)
{
	char buffer[SIZE];

	reset();
	for(;;) {
		size_t read = read_data(buffer, SIZE);
		if(read == 0)
			break;

		if(crypto_verify_update(ctx, buffer, read))
			return -1;
	}

	// TODO: use int or size_t for output sizes
	if(crypto_verify_final(ctx, signature, (size_t)signature_len))
		return -1;

	printf("Verification succeeded\n");
	return 0;
}

// Signature creation and verification using advanced API
void sign_verify_rsa(void)
{
	char* signature = NULL;
	size_t signature_len;

	crypto_ctx_h ctx = NULL;
	crypto_key_h prv = NULL, pub = NULL;
	crypto_padding_e padding = CRYPTO_PADDING_PKCS1;


	// GENERATE

	if(crypto_key_gen_pair(&prv, &pub, CRYPTO_KEY_4096BIT, CRYPTO_KEY_TYPE_PAIR_RSA))
		return;


	// SIGN

	if(crypto_sign_init(&ctx, CRYPTO_DIGEST_SHA512, prv))
		goto finish;

	// TODO: crypto_ctx_set_param should take void* not char*
	if(crypto_ctx_set_param(ctx, CRYPTO_PARAM_PADDING, (char*)(&padding), sizeof(padding)))
		goto finish;

	if(sign(ctx, &signature, &signature_len))
		goto finish;

	// TODO: is this necessary or will next ctx init handle it?
	crypto_ctx_free(ctx);
	ctx = NULL;


	// VERIFY

	if(crypto_verify_init(&ctx, CRYPTO_DIGEST_SHA512, pub))
		goto finish;

	if(crypto_ctx_set_param(ctx, CRYPTO_PARAM_PADDING, (char*)(&padding), sizeof(padding)))
		goto finish;

	if(verify(ctx, signature, signature_len))
		goto finish;

finish:
	crypto_free(signature);
	crypto_key_free(prv);
	crypto_key_free(pub);
	crypto_ctx_free(ctx);
}

void sign_verify_hmac(void)
{
	char* signature = NULL;
	size_t signature_len;

	crypto_ctx_h ctx = NULL;
	crypto_key_h key = NULL;


	// GENERATE

	if(crypto_key_gen(&key, CRYPTO_KEY_256BIT, CRYPTO_KEY_TYPE_SYMMETRIC))
		return;

	// SIGN

	if(crypto_sign_init(&ctx, CRYPTO_DIGEST_SHA512, key))
		goto finish;

	if(sign(ctx, &signature, &signature_len))
		goto finish;


	// VERIFY

	if(crypto_verify_init(&ctx, CRYPTO_DIGEST_SHA512, key))
		goto finish;

	if(verify(ctx, signature, signature_len))
		goto finish;

finish:
	crypto_free(signature);
	crypto_key_free(key);
	crypto_ctx_free(ctx);
}

void sign_verify_cmac(void)
{
	char* signature = NULL;
	size_t signature_len;

	crypto_ctx_h ctx = NULL;
	crypto_key_h key = NULL;


	// GENERATE

	if(crypto_key_gen(&key, CRYPTO_KEY_256BIT, CRYPTO_KEY_TYPE_SYMMETRIC))
		return;

	// SIGN
	// TODO: CMAC must extract the key length to select the proper evp (EVP_aes_XXX_cbc()) it should be documented
	if(crypto_sign_init(&ctx, CRYPTO_DIGEST_CMAC, key))
		goto finish;

	if(sign(ctx, &signature, &signature_len))
		goto finish;


	// VERIFY

	if(crypto_verify_init(&ctx, CRYPTO_DIGEST_CMAC, key))
		goto finish;

	if(verify(ctx, signature, signature_len))
		goto finish;

finish:
	crypto_free(signature);
	crypto_key_free(key);
	crypto_ctx_free(ctx);
}


int main()
{
	int ret = 0;
	if ((ret = crypto_init()))
		return ret;

	// TODO simple?

	sign_verify_rsa();
	sign_verify_hmac();
	sign_verify_cmac();

	crypto_exit(); // TODO: what about handing of return value from exit??
	return ret;
}
