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
 * @file key_import_export.c
 * @brief
 */

#include <stdio.h>

#include "misc.h"

#include <yaca/crypto.h>
#include <yaca/encrypt.h>
#include <yaca/key.h>
#include <yaca/types.h>
#include <yaca/error.h>

int key_import_export_sym(yaca_key_h sym)
{
	int ret;

	char *raw = NULL;
	size_t raw_len;
	char *b64= NULL;
	size_t b64_len;

	yaca_key_h raw_imported = YACA_KEY_NULL;
	yaca_key_h b64_imported = YACA_KEY_NULL;


	/* BASE64 */

	ret = yaca_key_export(sym, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_BASE64, &b64, &b64_len);
	if (ret != 0)
		return ret;
	ret = yaca_key_import(&b64_imported, YACA_KEY_TYPE_SYMMETRIC, b64, b64_len);
	if (ret != 0)
		goto free;

	printf("\n\t***** BASE64 exported key: *****\n%.*s\n", (int)b64_len, b64);
	yaca_free(b64);
	b64 = NULL;

	ret = yaca_key_export(b64_imported, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_BASE64, &b64, &b64_len);
	if (ret != 0)
		goto free;

	printf("\t***** BASE64 imported key: *****\n%.*s\n", (int)b64_len, b64);


	/* RAW */

	ret = yaca_key_export(sym, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_RAW, &raw, &raw_len);
	if (ret != 0)
		goto free;
	ret = yaca_key_import(&raw_imported, YACA_KEY_TYPE_SYMMETRIC, raw, raw_len);
	if (ret != 0)
		goto free;

	dump_hex(raw, raw_len, "\n\t***** RAW exported key: *****");
	yaca_free(raw);
	raw = NULL;

	ret = yaca_key_export(raw_imported, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_RAW, &raw, &raw_len);
	if (ret != 0)
		goto free;

	dump_hex(raw, raw_len, "\t***** RAW imported key: *****");

	ret = 0;

free:
	yaca_key_free(raw_imported);
	yaca_key_free(b64_imported);
	yaca_free(raw);
	yaca_free(b64);

	return ret;
}

int key_import_export_asym(yaca_key_h priv, yaca_key_h pub,
                           yaca_key_type_e priv_type, yaca_key_type_e pub_type,
                           const char *algo)
{
	int ret;

	char *pem_prv = NULL;
	size_t pem_prv_len;
	char *der_prv = NULL;
	size_t der_prv_len;

	char *pem_pub = NULL;
	size_t pem_pub_len;
	char *der_pub = NULL;
	size_t der_pub_len;

	yaca_key_h pem_prv_imported = YACA_KEY_NULL;
	yaca_key_h der_prv_imported = YACA_KEY_NULL;
	yaca_key_h pem_pub_imported = YACA_KEY_NULL;
	yaca_key_h der_pub_imported = YACA_KEY_NULL;


	/* PEM private */

	ret = yaca_key_export(priv, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_PEM, &pem_prv, &pem_prv_len);
	if (ret != 0)
		return ret;
	ret = yaca_key_import(&pem_prv_imported, priv_type, pem_prv, pem_prv_len);
	if (ret != 0)
		goto free;

	printf("\n\t***** %s PEM exported private key: *****\n%.*s", algo, (int)pem_prv_len, pem_prv);
	yaca_free(pem_prv);
	pem_prv = NULL;

	ret = yaca_key_export(pem_prv_imported, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_PEM, &pem_prv, &pem_prv_len);
	if (ret != 0)
		goto free;

	printf("\t***** %s PEM imported private key: *****\n%.*s", algo, (int)pem_prv_len, pem_prv);


	/* DER private */

	ret = yaca_key_export(priv, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_DER, &der_prv, &der_prv_len);
	if (ret != 0)
		goto free;
	ret = yaca_key_import(&der_prv_imported, priv_type, der_prv, der_prv_len);
	if (ret != 0)
		goto free;

	dump_hex(der_prv, der_prv_len, "\n\t***** %s DER exported private key: *****", algo);
	yaca_free(der_prv);
	der_prv = NULL;

	ret = yaca_key_export(der_prv_imported, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_DER, &der_prv, &der_prv_len);
	if (ret != 0)
		goto free;

	dump_hex(der_prv, der_prv_len, "\t***** %s DER imported private key: *****", algo);


	/* PEM public */

	ret = yaca_key_export(pub, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_PEM, &pem_pub, &pem_pub_len);
	if (ret != 0)
		goto free;
	ret = yaca_key_import(&pem_pub_imported, pub_type, pem_pub, pem_pub_len);
	if (ret != 0)
		goto free;

	printf("\n\t***** %s PEM exported public key: *****\n%.*s", algo, (int)pem_pub_len, pem_pub);
	yaca_free(pem_pub);
	pem_pub = NULL;

	ret = yaca_key_export(pem_pub_imported, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_PEM, &pem_pub, &pem_pub_len);
	if (ret != 0)
		goto free;

	printf("\t***** %s PEM imported public key: *****\n%.*s", algo, (int)pem_pub_len, pem_pub);


	/* DER public */

	ret = yaca_key_export(pub, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_DER, &der_pub, &der_pub_len);
	if (ret != 0)
		goto free;
	ret = yaca_key_import(&der_pub_imported, pub_type, der_pub, der_pub_len);
	if (ret != 0)
		goto free;

	dump_hex(der_pub, der_pub_len, "\n\t***** %s DER exported public key: *****", algo);
	yaca_free(der_pub);
	der_pub = NULL;

	ret = yaca_key_export(der_pub_imported, YACA_KEY_FORMAT_DEFAULT, YACA_KEY_FILE_FORMAT_DER, &der_pub, &der_pub_len);
	if (ret != 0)
		goto free;

	dump_hex(der_pub, der_pub_len, "\t***** %s DER imported public key: *****", algo);

	ret = 0;

free:
	yaca_key_free(der_pub_imported);
	yaca_key_free(pem_pub_imported);
	yaca_key_free(der_prv_imported);
	yaca_key_free(pem_prv_imported);
	yaca_free(der_pub);
	yaca_free(pem_pub);
	yaca_free(der_prv);
	yaca_free(pem_prv);

	return ret;
}

int main()
{
	yaca_key_h sym = YACA_KEY_NULL;
	yaca_key_h rsa_priv = YACA_KEY_NULL;
	yaca_key_h rsa_pub = YACA_KEY_NULL;
	yaca_key_h dsa_priv = YACA_KEY_NULL;
	yaca_key_h dsa_pub = YACA_KEY_NULL;
	int ret;

	ret = yaca_init();
	if (ret != 0)
		return ret;

	yaca_error_set_debug_func(debug_func);

	ret = yaca_key_gen(&sym, YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_1024BIT);
	if (ret != 0)
		goto exit;

	ret = yaca_key_gen(&rsa_priv, YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_1024BIT);
	if (ret != 0)
		goto free;

	ret = yaca_key_extract_public(rsa_priv, &rsa_pub);
	if (ret != 0)
		goto free;

	ret = yaca_key_gen(&dsa_priv, YACA_KEY_TYPE_DSA_PRIV, YACA_KEY_1024BIT);
	if (ret != 0)
		goto free;

	ret = yaca_key_extract_public(dsa_priv, &dsa_pub);
	if (ret != 0)
		goto free;

	printf("\t***************************************\n");
	printf("\t************** SYMMETRIC **************\n");
	printf("\t***************************************\n");
	ret = key_import_export_sym(sym);
	if (ret == 0)
		printf("\n\t********* SYMMETRIC - success *********\n\n");
	else
		printf("\n\t********* SYMMETRIC - failure *********\n\n");

	printf("\t***************************************\n");
	printf("\t***************** RSA *****************\n");
	printf("\t***************************************\n");
	ret = key_import_export_asym(rsa_priv, rsa_pub, YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_TYPE_RSA_PUB, "RSA");
	if (ret == 0)
		printf("\n\t************ RSA - success ************\n\n");
	else
		printf("\n\t************ RSA - failure ************\n\n");

	printf("\t***************************************\n");
	printf("\t***************** DSA *****************\n");
	printf("\t***************************************\n");
	ret = key_import_export_asym(dsa_priv, dsa_pub, YACA_KEY_TYPE_DSA_PRIV, YACA_KEY_TYPE_DSA_PUB, "DSA");
	if (ret == 0)
		printf("\n\t************ DSA - success ************\n\n");
	else
		printf("\n\t************ DSA - failure ************\n\n");

free:
	yaca_key_free(dsa_pub);
	yaca_key_free(dsa_priv);
	yaca_key_free(rsa_pub);
	yaca_key_free(rsa_priv);
	yaca_key_free(sym);
exit:
	yaca_exit();

	return ret;
}
