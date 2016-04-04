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

#include <stdio.h>
#include <owl/crypto.h>
#include <owl/key.h>
#include <owl/types.h>
#include "misc.h"

/** Simple test for development of library (before API is ready) */

int main(int argc, char* argv[])
{
	owl_key_h key;
	char *k;
	size_t kl;
	int ret;

	ret = owl_init();
	if (ret < 0)
		return ret;

	printf("Generating key using CryptoAPI.. ");
	ret = owl_key_gen(&key, OWL_KEY_TYPE_SYMMETRIC, OWL_KEY_UNSAFE_128BIT);
	if (ret < 0)
		return ret;
	printf("done (%d)\n", ret);

	printf("Exporting key using CryptoAPI.. ");
	ret = owl_key_export(key, OWL_KEY_FORMAT_RAW, &k, &kl);
	if (ret < 0)
		return ret;
	printf("done (%d)\n", ret);

	dump_hex(k, kl, "%zu-bit key: \n", kl);

	owl_exit();

	return 0;
}
