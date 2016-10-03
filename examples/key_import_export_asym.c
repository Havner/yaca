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
 * @file key_import_export_asym.c
 * @brief Asymmetric key import/export API example.
 */

//! [Asymmetric key import/export API example]
#include <stdio.h>

#include <yaca_crypto.h>
#include <yaca_key.h>
#include <yaca_error.h>

/* include helpers functions and definitions */
#include "misc.h"

int main()
{
	int ret;
	yaca_key_h rsa_priv = YACA_KEY_NULL;
	yaca_key_h rsa_pub = YACA_KEY_NULL;
	yaca_key_h pem_priv_imported = YACA_KEY_NULL;
	yaca_key_h der_pub_imported = YACA_KEY_NULL;

	char *pem_priv = NULL;
	size_t pem_priv_len;
	char *der_pub = NULL;
	size_t der_pub_len;

	ret = yaca_initialize();
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_generate(YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_2048BIT, &rsa_priv);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_extract_public(rsa_priv, &rsa_pub);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* PEM private */
	ret = yaca_key_export(rsa_priv, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_PEM, NULL,
	                      &pem_priv, &pem_priv_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_import(YACA_KEY_TYPE_RSA_PRIV, NULL, pem_priv, pem_priv_len, &pem_priv_imported);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	printf("\t***** PEM exported private key: *****\n%.*s", (int)pem_priv_len, pem_priv);
	yaca_free(pem_priv);
	pem_priv = NULL;

	ret = yaca_key_export(pem_priv_imported, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_PEM,
	                      NULL, &pem_priv, &pem_priv_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	printf("\t***** PEM imported private key: *****\n%.*s", (int)pem_priv_len, pem_priv);

	/* DER public */
	ret = yaca_key_export(rsa_pub, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_DER, NULL,
	                      &der_pub, &der_pub_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = yaca_key_import(YACA_KEY_TYPE_RSA_PUB, NULL, der_pub, der_pub_len, &der_pub_imported);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* display key in hexadecimal format */
	dump_hex(der_pub, der_pub_len, "\n\t***** DER exported public key: *****");
	yaca_free(der_pub);
	der_pub = NULL;

	ret = yaca_key_export(der_pub_imported, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_DER,
	                      NULL, &der_pub, &der_pub_len);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	/* display key in hexadecimal format */
	dump_hex(der_pub, der_pub_len, "\t***** DER imported public key: *****");

exit:
	yaca_key_destroy(rsa_pub);
	yaca_key_destroy(rsa_priv);
	yaca_key_destroy(pem_priv_imported);
	yaca_key_destroy(der_pub_imported);
	yaca_free(pem_priv);
	yaca_free(der_pub);

	yaca_cleanup();
	return ret;
}
//! [Asymmetric key import/export API example]
