/*
 *  Copyright (c) 2020 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Lukasz Pawelczyk <l.pawelczyk@samsung.com>
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
 * @file    test_key.cpp
 * @author  Lukasz Pawelczyk <l.pawelczyk@samsung.com>
 * @brief   Key API unit tests.
 */

#include <boost/test/unit_test.hpp>
#include <vector>

#include <yaca_crypto.h>
#include <yaca_encrypt.h>
#include <yaca_key.h>
#include <yaca_simple.h>
#include <yaca_error.h>

#include "common.h"


namespace {

int import_export(yaca_key_h key, yaca_key_type_e type, const char *password,
				  yaca_key_format_e format, yaca_key_file_format_e file_format)
{
	int ret;
	yaca_key_h imported = YACA_KEY_NULL;

	char *data = NULL;
	size_t data_len = 0;
	yaca_key_type_e key_type;
	size_t key_length;

	ret = yaca_key_export(key, format, file_format,
						  password, &data, &data_len);
	if (ret != YACA_ERROR_NONE) goto exit;

	ret = yaca_key_import(type, password, data, data_len, &imported);
	if (ret != YACA_ERROR_NONE) goto exit;

	ret = yaca_key_get_type(imported, &key_type);
	if (ret != YACA_ERROR_NONE) goto exit;
	ret = yaca_key_get_bit_length(imported, &key_length);
	if (ret != YACA_ERROR_NONE) goto exit;

exit:
	yaca_key_destroy(imported);
	yaca_free(data);
	return ret;
}

} // namespace


BOOST_AUTO_TEST_SUITE(MOCK_TESTS_KEY)

BOOST_FIXTURE_TEST_CASE(T1201__mock__negative__key_symmetric_all, InitFixture)
{
	struct key_args {
		yaca_key_type_e type;
		yaca_key_bit_length_e len;
	};

	const std::vector<struct key_args> kargs = {
		{YACA_KEY_TYPE_SYMMETRIC, YACA_KEY_LENGTH_256BIT},
		{YACA_KEY_TYPE_DES,       YACA_KEY_LENGTH_192BIT},
		{YACA_KEY_TYPE_IV,        YACA_KEY_LENGTH_IV_64BIT}
	};

	for (const auto &ka: kargs) {
		auto test_code = [&ka]()
			{
				int ret;
				yaca_key_h key = YACA_KEY_NULL;

				ret = yaca_key_generate(ka.type, ka.len, &key);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = import_export(key, ka.type, "",
									YACA_KEY_FORMAT_DEFAULT,
									YACA_KEY_FILE_FORMAT_RAW);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = import_export(key, ka.type, "",
									YACA_KEY_FORMAT_DEFAULT,
									YACA_KEY_FILE_FORMAT_BASE64);
				if (ret != YACA_ERROR_NONE) goto exit;

			exit:
				yaca_key_destroy(key);
				return ret;
			};

		call_mock_test(test_code);
	}
}

BOOST_FIXTURE_TEST_CASE(T1202__mock__negative__key_asymmetric_generate_all, InitFixture)
{
	struct key_args {
		yaca_key_type_e type_priv;
		yaca_key_type_e type_pub;
		yaca_key_type_e type_params;
		yaca_key_bit_length_e len;
	};

	const std::vector<struct key_args> kargs = {
		{YACA_KEY_TYPE_RSA_PRIV,
		 YACA_KEY_TYPE_RSA_PUB,
		 YACA_INVALID_KEY_TYPE,
		 YACA_KEY_LENGTH_512BIT},
		{YACA_KEY_TYPE_DSA_PRIV,
		 YACA_KEY_TYPE_DSA_PUB,
		 YACA_KEY_TYPE_DSA_PARAMS,
		 YACA_KEY_LENGTH_512BIT},
		{YACA_KEY_TYPE_DH_PRIV,
		 YACA_KEY_TYPE_DH_PUB,
		 YACA_KEY_TYPE_DH_PARAMS,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_DH_RFC_1024_160},
		{YACA_KEY_TYPE_EC_PRIV,
		 YACA_KEY_TYPE_EC_PUB,
		 YACA_KEY_TYPE_EC_PARAMS,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_PRIME192V1}
	};

	for (const auto &ka: kargs) {
		auto test_code = [&ka]()
			{
				int ret;
				yaca_key_h priv = YACA_KEY_NULL;
				yaca_key_h priv2 = YACA_KEY_NULL;
				yaca_key_h pub = YACA_KEY_NULL;
				yaca_key_h params = YACA_KEY_NULL;
				yaca_key_h params2 = YACA_KEY_NULL;

				ret = yaca_key_generate(ka.type_priv, ka.len, &priv);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_key_extract_public(priv, &pub);
				if (ret != YACA_ERROR_NONE) goto exit;

				if (ka.type_params != YACA_INVALID_KEY_TYPE) {
					ret = yaca_key_generate(ka.type_params, ka.len, &params);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_key_generate_from_parameters(params, &priv2);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = yaca_key_extract_parameters(pub, &params2);
					if (ret != YACA_ERROR_NONE) goto exit;
				}

			exit:
				yaca_key_destroy(params);
				yaca_key_destroy(params2);
				yaca_key_destroy(priv);
				yaca_key_destroy(priv2);
				yaca_key_destroy(pub);
				return ret;
			};

		call_mock_test(test_code);
	}
}

BOOST_FIXTURE_TEST_CASE(T1204__mock__negative__key_asymmetric_import_export, InitFixture)
{
	struct key_args {
		yaca_key_type_e type_priv;
		yaca_key_type_e type_pub;
		yaca_key_type_e type_params;
		yaca_key_bit_length_e len;
	};

	const std::vector<struct key_args> kargs = {
		{YACA_KEY_TYPE_RSA_PRIV,
		 YACA_KEY_TYPE_RSA_PUB,
		 YACA_INVALID_KEY_TYPE,
		 YACA_KEY_LENGTH_512BIT},
		{YACA_KEY_TYPE_DSA_PRIV,
		 YACA_KEY_TYPE_DSA_PUB,
		 YACA_KEY_TYPE_DSA_PARAMS,
		 YACA_KEY_LENGTH_512BIT},
		{YACA_KEY_TYPE_EC_PRIV,
		 YACA_KEY_TYPE_EC_PUB,
		 YACA_KEY_TYPE_EC_PARAMS,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_PRIME192V1},
		{YACA_KEY_TYPE_DH_PRIV,
		 YACA_KEY_TYPE_DH_PUB,
		 YACA_KEY_TYPE_DH_PARAMS,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_DH_RFC_1024_160},
	};

	for (const auto &ka: kargs) {
		auto test_code = [&ka]()
			{
				int ret;
				yaca_key_h key_priv = YACA_KEY_NULL;
				yaca_key_h key_pub = YACA_KEY_NULL;
				yaca_key_h key_params = YACA_KEY_NULL;

				ret = yaca_key_generate(ka.type_priv, ka.len, &key_priv);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = import_export(key_priv, ka.type_priv, NULL,
									YACA_KEY_FORMAT_DEFAULT,
									YACA_KEY_FILE_FORMAT_DER);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = import_export(key_priv, ka.type_priv, NULL,
									YACA_KEY_FORMAT_DEFAULT,
									YACA_KEY_FILE_FORMAT_PEM);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_key_extract_public(key_priv, &key_pub);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = import_export(key_pub, ka.type_pub, "",
									YACA_KEY_FORMAT_DEFAULT,
									YACA_KEY_FILE_FORMAT_DER);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = import_export(key_pub, ka.type_pub, "",
									YACA_KEY_FORMAT_DEFAULT,
									YACA_KEY_FILE_FORMAT_PEM);
				if (ret != YACA_ERROR_NONE) goto exit;

				if (ka.type_params != YACA_INVALID_KEY_TYPE) {
					ret = yaca_key_extract_parameters(key_priv, &key_params);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = import_export(key_params, ka.type_params, NULL,
										YACA_KEY_FORMAT_DEFAULT,
										YACA_KEY_FILE_FORMAT_DER);
					if (ret != YACA_ERROR_NONE) goto exit;

					ret = import_export(key_params, ka.type_params, NULL,
										YACA_KEY_FORMAT_DEFAULT,
										YACA_KEY_FILE_FORMAT_PEM);
					if (ret != YACA_ERROR_NONE) goto exit;
				}

			exit:
				yaca_key_destroy(key_params);
				yaca_key_destroy(key_priv);
				yaca_key_destroy(key_pub);
				return ret;
			};

		call_mock_test(test_code);
	}
}

BOOST_FIXTURE_TEST_CASE(T1205__mock__negative__key_encrypted_import_export, InitFixture)
{
	static const char *PASSWORD = "ExamplE_PassworD";

	struct default_args {
		yaca_key_type_e type;
		yaca_key_bit_length_e len;
	};

	const std::vector<struct default_args> dargs = {
		{YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_LENGTH_512BIT},
		{YACA_KEY_TYPE_DSA_PRIV, YACA_KEY_LENGTH_512BIT}
	};

	for (const auto &da: dargs) {
		auto test_code = [&da]()
			{
				int ret;
				yaca_key_h key = YACA_KEY_NULL;

				ret = yaca_key_generate(da.type, da.len, &key);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = import_export(key, da.type, PASSWORD,
									YACA_KEY_FORMAT_DEFAULT,
									YACA_KEY_FILE_FORMAT_PEM);
				if (ret != YACA_ERROR_NONE) goto exit;

			exit:
				yaca_key_destroy(key);
				return ret;
			};

		call_mock_test(test_code);
	}

	struct pkcs8_args {
		yaca_key_type_e type;
		yaca_key_bit_length_e len;
	};

	const std::vector<struct pkcs8_args> pargs {
		{YACA_KEY_TYPE_RSA_PRIV,
		 YACA_KEY_LENGTH_512BIT},
		{YACA_KEY_TYPE_DSA_PRIV,
		 YACA_KEY_LENGTH_512BIT},
		{YACA_KEY_TYPE_EC_PRIV,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_PRIME256V1},
		{YACA_KEY_TYPE_DH_PRIV,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_DH_RFC_1024_160},
	};

	for (const auto &pa: pargs) {
		auto test_code2 = [&pa]()
			{
				int ret;
				yaca_key_h key = YACA_KEY_NULL;

				ret = yaca_key_generate(pa.type, pa.len, &key);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = import_export(key, pa.type, PASSWORD,
									YACA_KEY_FORMAT_PKCS8,
									YACA_KEY_FILE_FORMAT_DER);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = import_export(key, pa.type, PASSWORD,
									YACA_KEY_FORMAT_PKCS8,
									YACA_KEY_FILE_FORMAT_PEM);
				if (ret != YACA_ERROR_NONE) goto exit;

			exit:
				yaca_key_destroy(key);
				return ret;
			};

		call_mock_test(test_code2);
	}
}

BOOST_FIXTURE_TEST_CASE(T1206__mock__negative__key_derive_dh, InitFixture)
{
	struct key_args {
		yaca_key_type_e type;
		yaca_key_bit_length_e len;
	};

	const std::vector<struct key_args> kargs = {
		{YACA_KEY_TYPE_DH_PRIV,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_DH_RFC_1024_160},
		{YACA_KEY_TYPE_EC_PRIV,
		 (yaca_key_bit_length_e)YACA_KEY_LENGTH_EC_SECP256K1}
	};

	for (const auto &ka: kargs) {
		auto test_code = [&ka]()
			{
				int ret;
				yaca_key_h priv1 = YACA_KEY_NULL, pub1 = YACA_KEY_NULL;
				yaca_key_h priv2 = YACA_KEY_NULL, pub2 = YACA_KEY_NULL;
				char *secret1 = NULL, *secret2 = NULL;
				size_t secret1_len, secret2_len;

				ret = yaca_key_generate(ka.type, ka.len, &priv1);
				if (ret != YACA_ERROR_NONE) goto exit;
				ret = yaca_key_generate(ka.type, ka.len, &priv2);
				if (ret != YACA_ERROR_NONE) goto exit;
				ret = yaca_key_extract_public(priv1, &pub1);
				if (ret != YACA_ERROR_NONE) goto exit;
				ret = yaca_key_extract_public(priv2, &pub2);
				if (ret != YACA_ERROR_NONE) goto exit;

				ret = yaca_key_derive_dh(priv1, pub2, &secret1, &secret1_len);
				if (ret != YACA_ERROR_NONE) goto exit;
				ret = yaca_key_derive_dh(priv2, pub1, &secret2, &secret2_len);
				if (ret != YACA_ERROR_NONE) goto exit;

			exit:
				yaca_key_destroy(priv1);
				yaca_key_destroy(priv2);
				yaca_key_destroy(pub1);
				yaca_key_destroy(pub2);
				yaca_free(secret1);
				yaca_free(secret2);
				return ret;
			};

		call_mock_test(test_code);
	}
}

BOOST_FIXTURE_TEST_CASE(T1207__mock__negative__key_derive_kdf, InitFixture)
{
	static const size_t SECRET_LEN = 128;
	static const size_t MATERIAL_LEN = 256;

	struct kdf_args {
		yaca_kdf_e kdf;
		yaca_digest_algorithm_e digest;
	};

	const std::vector<struct kdf_args> kargs = {
		{YACA_KDF_X942, YACA_DIGEST_SHA1},
		{YACA_KDF_X962, YACA_DIGEST_MD5}
	};

	int ret;
	char secret[SECRET_LEN];

	ret = yaca_randomize_bytes(secret, SECRET_LEN);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	for (const auto &ka: kargs) {
		auto test_code = [&ka, &secret]()
			{
				int ret;
				char *key_material = NULL;;

				ret = yaca_key_derive_kdf(ka.kdf, ka.digest, secret, SECRET_LEN,
										  NULL, 0, MATERIAL_LEN, &key_material);

				yaca_free(key_material);
				return ret;
			};

		call_mock_test(test_code);
	}
}

BOOST_FIXTURE_TEST_CASE(T1208__mock__negative__key_derive_pbkdf2, InitFixture)
{
	static const char *PASSWORD = "Password_ExamplE";
	static const size_t SALT_LEN = 64;

	struct pbkdf2_args {
		yaca_digest_algorithm_e digest;
		size_t iter;
		size_t bit_len;
	};

	const std::vector<struct pbkdf2_args> pargs = {
		{YACA_DIGEST_MD5,     1, 256},
		{YACA_DIGEST_SHA512, 50, 512}
	};

	int ret;
	char salt[SALT_LEN];

	ret = yaca_randomize_bytes(salt, SALT_LEN);
	BOOST_REQUIRE(ret == YACA_ERROR_NONE);

	for (const auto &pa: pargs) {
		auto test_code = [&pa, &salt]()
			{
				int ret;
				yaca_key_h key = YACA_KEY_NULL;

				ret = yaca_key_derive_pbkdf2(PASSWORD, salt, SALT_LEN, pa.iter,
											 pa.digest, pa.bit_len, &key);

				yaca_key_destroy(key);
				return ret;
			};

		call_mock_test(test_code);
	}
}

BOOST_FIXTURE_TEST_CASE(T1209__mock__negative__import_x509_cert, InitFixture)
{
	static const char data_pem[] = "-----BEGIN CERTIFICATE-----\n\
MIIC9jCCAl+gAwIBAgIUaWM7DVy/evvsrKz8gkz3qWZKw7EwDQYJKoZIhvcNAQEL\n\
BQAwgYwxCzAJBgNVBAYTAlBMMRQwEgYDVQQIDAtNYXpvd2llY2tpZTERMA8GA1UE\n\
BwwIV2Fyc3phd2ExEDAOBgNVBAoMB1NhbXN1bmcxCzAJBgNVBAsMAklUMRQwEgYD\n\
VQQDDAtzYW1zdW5nLmNvbTEfMB0GCSqGSIb3DQEJARYQbm9uZUBzYW1zdW5nLmNv\n\
bTAeFw0yMDA0MDkxNzUzMDlaFw0yNTA0MDgxNzUzMDlaMIGMMQswCQYDVQQGEwJQ\n\
TDEUMBIGA1UECAwLTWF6b3dpZWNraWUxETAPBgNVBAcMCFdhcnN6YXdhMRAwDgYD\n\
VQQKDAdTYW1zdW5nMQswCQYDVQQLDAJJVDEUMBIGA1UEAwwLc2Ftc3VuZy5jb20x\n\
HzAdBgkqhkiG9w0BCQEWEG5vbmVAc2Ftc3VuZy5jb20wgZ8wDQYJKoZIhvcNAQEB\n\
BQADgY0AMIGJAoGBAMrx4VdcBEWSXdOa7nJr6Vh53TDfnqhgOGRUC8c+kGUu45Cp\n\
hcGU7q44zfqvEdgkVBK+Y6GBMrbB0TALo2zK4RVDIgTc8UskbiBjiP4cHB+Zl460\n\
kU/0vKZPWt7yWq9g87lppEr/f0RTGrKkkcVadCxmKILr4ZtS9563xXH+kKAlAgMB\n\
AAGjUzBRMB0GA1UdDgQWBBQBroKxSi+l6RqOD5jQGRYyoM0I1jAfBgNVHSMEGDAW\n\
gBQBroKxSi+l6RqOD5jQGRYyoM0I1jAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\n\
DQEBCwUAA4GBAC1f+n4ly876nTXMjdINH8qmxrHOH55vt7v1KYWqCVFSJbqtQMlT\n\
E9+bqRGN2LpzMBkDdNkGSrCesI1l/FUStjqdpBGMi1fqFDNDyBXkLJDH5HAMR3ei\n\
hajHIasdGWcAfj+Cyuk1KcTIEkBfdYR6a8C4g04Vbg6M0qEjFl5UTMwm\n\
-----END CERTIFICATE-----";

	/* THIS CHUNK OF BYTES IS AUTOMATICALLY GENERATED */
	static const unsigned char data_der[] = {
		0x30, 0x82, 0x02, 0xf2, 0x30, 0x82, 0x02, 0x5b, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x3e,
		0x03, 0xd9, 0x79, 0x86, 0xae, 0xa4, 0x85, 0x59, 0xd6, 0x2b, 0x53, 0x29, 0xee, 0xfd, 0x2c, 0x26,
		0xe8, 0x72, 0x57, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
		0x05, 0x00, 0x30, 0x81, 0x8a, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
		0x50, 0x4c, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0b, 0x4d, 0x61, 0x7a,
		0x6f, 0x77, 0x69, 0x65, 0x63, 0x6b, 0x69, 0x65, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04,
		0x07, 0x0c, 0x06, 0x57, 0x61, 0x72, 0x73, 0x61, 0x77, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55,
		0x04, 0x0a, 0x0c, 0x07, 0x53, 0x61, 0x6d, 0x73, 0x75, 0x6e, 0x67, 0x31, 0x0b, 0x30, 0x09, 0x06,
		0x03, 0x55, 0x04, 0x0b, 0x0c, 0x02, 0x49, 0x54, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04,
		0x03, 0x0c, 0x0b, 0x73, 0x61, 0x6d, 0x73, 0x75, 0x6e, 0x67, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x1f,
		0x30, 0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x10, 0x6e,
		0x6f, 0x6e, 0x65, 0x40, 0x73, 0x61, 0x6d, 0x73, 0x75, 0x6e, 0x67, 0x2e, 0x63, 0x6f, 0x6d, 0x30,
		0x1e, 0x17, 0x0d, 0x32, 0x30, 0x30, 0x34, 0x31, 0x34, 0x31, 0x35, 0x32, 0x33, 0x30, 0x37, 0x5a,
		0x17, 0x0d, 0x32, 0x31, 0x30, 0x34, 0x31, 0x34, 0x31, 0x35, 0x32, 0x33, 0x30, 0x37, 0x5a, 0x30,
		0x81, 0x8a, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x50, 0x4c, 0x31,
		0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0b, 0x4d, 0x61, 0x7a, 0x6f, 0x77, 0x69,
		0x65, 0x63, 0x6b, 0x69, 0x65, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x06,
		0x57, 0x61, 0x72, 0x73, 0x61, 0x77, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
		0x07, 0x53, 0x61, 0x6d, 0x73, 0x75, 0x6e, 0x67, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
		0x0b, 0x0c, 0x02, 0x49, 0x54, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0b,
		0x73, 0x61, 0x6d, 0x73, 0x75, 0x6e, 0x67, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x1f, 0x30, 0x1d, 0x06,
		0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x10, 0x6e, 0x6f, 0x6e, 0x65,
		0x40, 0x73, 0x61, 0x6d, 0x73, 0x75, 0x6e, 0x67, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x81, 0x9f, 0x30,
		0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81,
		0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xc9, 0x73, 0x11, 0x8f, 0x63, 0x4d, 0xaa,
		0x8e, 0xc5, 0xb5, 0x6d, 0x9c, 0xea, 0x30, 0x43, 0xb5, 0x5d, 0xd3, 0xb2, 0x9c, 0x59, 0x23, 0xdf,
		0xa8, 0x69, 0xe6, 0x0d, 0xfe, 0x0a, 0xdb, 0xce, 0x22, 0x64, 0x15, 0x02, 0xf6, 0xa4, 0xe9, 0x22,
		0x04, 0xce, 0x73, 0x9e, 0x89, 0x1e, 0x87, 0x93, 0x31, 0x07, 0x91, 0x0e, 0xbd, 0x98, 0x45, 0x3d,
		0x66, 0xe9, 0x59, 0x02, 0xfc, 0x2f, 0xd9, 0x11, 0x71, 0xc4, 0x11, 0x3f, 0x20, 0xf3, 0x49, 0xb6,
		0x59, 0x26, 0xb2, 0x8c, 0x9f, 0x74, 0xe0, 0x09, 0x3b, 0x4f, 0xdd, 0xf4, 0x13, 0x8b, 0x91, 0x48,
		0x1e, 0x1b, 0xf5, 0x86, 0xca, 0xe6, 0xd6, 0x1d, 0x29, 0x74, 0x1d, 0xb6, 0x84, 0x0b, 0x48, 0xe7,
		0x40, 0x14, 0x60, 0x65, 0xb2, 0x35, 0xf0, 0x48, 0xe9, 0x93, 0xea, 0x77, 0x63, 0x77, 0x53, 0x77,
		0xaf, 0xbb, 0xac, 0xc2, 0x86, 0x40, 0xc7, 0xb0, 0x0b, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x53,
		0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xd0, 0xb1, 0x78,
		0xed, 0xee, 0xb4, 0x57, 0x7b, 0x4f, 0xed, 0x45, 0xba, 0x0b, 0x5a, 0x32, 0xe5, 0xe1, 0x32, 0xee,
		0x83, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xd0, 0xb1,
		0x78, 0xed, 0xee, 0xb4, 0x57, 0x7b, 0x4f, 0xed, 0x45, 0xba, 0x0b, 0x5a, 0x32, 0xe5, 0xe1, 0x32,
		0xee, 0x83, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03,
		0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
		0x05, 0x00, 0x03, 0x81, 0x81, 0x00, 0x2e, 0xf4, 0x42, 0x8b, 0xde, 0xfe, 0x36, 0x79, 0x6d, 0xaa,
		0x51, 0x85, 0x65, 0xe3, 0x0f, 0x89, 0x1f, 0x84, 0xce, 0x5c, 0x34, 0x03, 0x0d, 0x59, 0x2a, 0xad,
		0xfb, 0x09, 0xd2, 0xcd, 0xbc, 0xac, 0x51, 0x4a, 0xe3, 0xcb, 0x9e, 0xe5, 0x75, 0x26, 0x36, 0x5e,
		0xe7, 0xc6, 0x86, 0x6b, 0xf8, 0xc4, 0x96, 0x99, 0x43, 0xb6, 0x53, 0xcc, 0x6a, 0x14, 0x57, 0xcd,
		0x08, 0xad, 0x53, 0x11, 0x5f, 0x17, 0x97, 0xb3, 0x2f, 0x36, 0xbe, 0xd6, 0x5c, 0x03, 0x32, 0xe3,
		0x2a, 0x4f, 0x69, 0x85, 0xf6, 0xf0, 0x14, 0x13, 0x2b, 0xfc, 0xa6, 0x64, 0x67, 0x4d, 0x7b, 0xab,
		0xb9, 0xd0, 0x06, 0x00, 0xce, 0xc6, 0x85, 0x08, 0x45, 0xfb, 0xca, 0x70, 0x1b, 0xb4, 0x8f, 0x4e,
		0x49, 0x2e, 0xfe, 0x94, 0xd7, 0x7b, 0xf1, 0xc6, 0x60, 0x24, 0xa6, 0x79, 0x5a, 0xeb, 0x92, 0xed,
		0xd7, 0x07, 0x42, 0x65, 0xd3, 0x31
	};

	auto test_code = []()
		{
			int ret;
			yaca_key_h key_pem = YACA_KEY_NULL, key_der = YACA_KEY_NULL;

			ret = yaca_key_import(YACA_KEY_TYPE_RSA_PUB, NULL, data_pem,
								  sizeof(data_pem), &key_pem);
			if (ret != YACA_ERROR_NONE) goto exit;

			ret = yaca_key_import(YACA_KEY_TYPE_RSA_PUB, NULL, (char*)data_der,
								  sizeof(data_der), &key_der);
			if (ret != YACA_ERROR_NONE) goto exit;

		exit:
			yaca_key_destroy(key_pem);
			yaca_key_destroy(key_der);
			return ret;
		};

	call_mock_test(test_code);
}

BOOST_AUTO_TEST_SUITE_END()
