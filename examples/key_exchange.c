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
 * @file key_exchange.c
 * @brief
 */

#include <stdio.h>
#include <crypto/crypto.h>
#include <crypto/encrypt.h>
#include <crypto/key.h>
#include <crypto/types.h>

void key_exchange_dh(void)
{
	int ret;

	crypto_key_h private_key = CRYPTO_KEY_NULL;
	crypto_key_h public_key = CRYPTO_KEY_NULL;
	crypto_key_h peer_key = CRYPTO_KEY_NULL;
	crypto_key_h secret = CRYPTO_KEY_NULL;

	// generate  private, public key
	// add KEY_TYPE_PAIR_DH or use KEY_TYPE_PAIR_ECC and proper len?
	// imo add KEY_TYPE_PAIR_DH
	ret = crypto_key_gen_pair(&private_key, &public_key, CRYPTO_KEY_2048BIT, CRYPTO_KEY_TYPE_PAIR_DH);
	if (ret) goto clean;

	// get peer public key from file
	// add helper to read key from file to buffer?
	FILE *fp;
	long size;
	char *buffer;

	fp = fopen("key.pub", "r");
	if(!fp) goto clean;

	fseek(fp ,0L ,SEEK_END);
	size = ftell(fp);
	rewind(fp);

	/* allocate memory for entire content */
	buffer = crypto_alloc(size+1);
	if(!buffer) goto clean;

	/* copy the file into the buffer */
	if(1!=fread(buffer, size, 1, fp)) goto clean;

	ret = crypto_key_import(&peer_key,
				CRYPTO_KEY_FORMAT_RAW, CRYPTO_KEY_TYPE_DH_PUB,
				buffer, size);
	if (ret) goto clean;

	// derive secret
	ret = crypto_key_derive_dh(private_key, peer_key, &secret);
	if (ret) goto clean;

clean:
	crypto_key_free(private_key);
	crypto_key_free(public_key);
	crypto_key_free(peer_key);
	crypto_key_free(secret);
	fclose(fp);
	crypto_free(buffer);
}

void key_exchange_ecdh(void)
{

	int ret;

	crypto_key_h private_key = CRYPTO_KEY_NULL;
	crypto_key_h public_key = CRYPTO_KEY_NULL;
	crypto_key_h peer_key = CRYPTO_KEY_NULL;
	crypto_key_h secret = CRYPTO_KEY_NULL;

	// generate  private, public key
	ret = crypto_key_gen_pair(&private_key, &public_key, CRYPTO_KEY_CURVE_P256, CRYPTO_KEY_TYPE_PAIR_ECC);
	if (ret) goto clean;

	// get peer public key from file
	FILE *fp;
	long size;
	char *buffer;

	fp = fopen("key.pub", "r");
	if(!fp) goto clean;

	fseek(fp ,0L ,SEEK_END);
	size = ftell(fp);
	rewind(fp);

	/* allocate memory for entire content */
	buffer = crypto_alloc(size+1);
	if(!buffer) goto clean;

	/* copy the file into the buffer */
	if(1!=fread(buffer, size, 1, fp)) goto clean;

	ret = crypto_key_import(&peer_key, CRYPTO_KEY_FORMAT_RAW, CRYPTO_KEY_TYPE_ECC_PUB, buffer, size);
	if (ret) goto clean;

	// derive secret
	ret = crypto_key_derive_dh(private_key, peer_key, &secret);
	if (ret) goto clean;

clean:
	crypto_key_free(private_key);
	crypto_key_free(public_key);
	crypto_key_free(peer_key);
	crypto_key_free(secret);
	fclose(fp);
	crypto_free(buffer);
}

int main()
{
	int ret = 0;
	if ((ret = crypto_init()))
		return ret;

	key_exchange_dh();
	key_exchange_ecdh();

	crypto_exit();
	return ret;
}
