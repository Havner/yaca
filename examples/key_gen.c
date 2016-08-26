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

#include <stdio.h>

#include <yaca_crypto.h>
#include <yaca_key.h>
#include <yaca_types.h>
#include <yaca_error.h>

#include "misc.h"

int main()
{
	int ret;
	yaca_key_h key = YACA_KEY_NULL;
	yaca_key_h key_params = YACA_KEY_NULL;

	ret = yaca_initialize();
	if (ret != YACA_ERROR_NONE)
		goto error;

	printf("This example doesn't print anything useful unless an error occured.\n"
	       "It is intended to be looked at only as a code example.\n"
	       "It might take a long time to execute though due to several keys being generated.\n");

	/* Regular generation */

	ret = yaca_key_generate(YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT, &key);
	if (ret != YACA_ERROR_NONE)
		goto error;
	yaca_key_destroy(key);

	ret = yaca_key_generate(YACA_KEY_TYPE_DES, YACA_KEY_LENGTH_192BIT, &key);
	if (ret != YACA_ERROR_NONE)
		goto error;
	yaca_key_destroy(key);

	ret = yaca_key_generate(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_1024BIT, &key);
	if (ret != YACA_ERROR_NONE)
		goto error;
	yaca_key_destroy(key);

	ret = yaca_key_generate(YACA_KEY_TYPE_DSA_PRIV, YACA_KEY_LENGTH_512BIT, &key);
	if (ret != YACA_ERROR_NONE)
		goto error;
	yaca_key_destroy(key);

	ret = yaca_key_generate(YACA_KEY_TYPE_DH_PRIV, YACA_KEY_LENGTH_DH_GENERATOR_2 | 333, &key);
	if (ret != YACA_ERROR_NONE)
		goto error;
	yaca_key_destroy(key);

	ret = yaca_key_generate(YACA_KEY_TYPE_DH_PRIV, YACA_KEY_LENGTH_DH_RFC_2048_224, &key);
	if (ret != YACA_ERROR_NONE)
		goto error;
	yaca_key_destroy(key);

	ret = yaca_key_generate(YACA_KEY_TYPE_EC_PRIV, YACA_KEY_LENGTH_EC_SECP384R1, &key);
	if (ret != YACA_ERROR_NONE)
		goto error;
	yaca_key_destroy(key);

	/* Params + key generation */

	ret = yaca_key_generate(YACA_KEY_TYPE_DSA_PARAMS, YACA_KEY_LENGTH_512BIT, &key_params);
	if (ret != YACA_ERROR_NONE)
		goto error;
	ret = yaca_key_generate_from_parameters(key_params, &key);
	if (ret != YACA_ERROR_NONE)
		goto error;
	yaca_key_destroy(key);
	yaca_key_destroy(key_params);

	ret = yaca_key_generate(YACA_KEY_TYPE_DH_PARAMS,
	                        YACA_KEY_LENGTH_DH_GENERATOR_5 | YACA_KEY_LENGTH_2048BIT, &key_params);
	if (ret != YACA_ERROR_NONE)
		goto error;
	ret = yaca_key_generate_from_parameters(key_params, &key);
	if (ret != YACA_ERROR_NONE)
		goto error;
	yaca_key_destroy(key);
	yaca_key_destroy(key_params);

	ret = yaca_key_generate(YACA_KEY_TYPE_DH_PARAMS, YACA_KEY_LENGTH_DH_RFC_2048_256, &key_params);
	if (ret != YACA_ERROR_NONE)
		goto error;
	ret = yaca_key_generate_from_parameters(key_params, &key);
	if (ret != YACA_ERROR_NONE)
		goto error;
	yaca_key_destroy(key);
	yaca_key_destroy(key_params);

	ret = yaca_key_generate(YACA_KEY_TYPE_EC_PARAMS, YACA_KEY_LENGTH_EC_PRIME256V1, &key_params);
	if (ret != YACA_ERROR_NONE)
		goto error;
	ret = yaca_key_generate_from_parameters(key_params, &key);
	if (ret != YACA_ERROR_NONE)
		goto error;
	yaca_key_destroy(key);
	yaca_key_destroy(key_params);

	yaca_cleanup();
	return 0;

error:
	printf("Error occured.\n");
	yaca_cleanup();

	return 1;
}
