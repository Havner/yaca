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
 * @file debug.c
 * @brief
 */

#include <stdbool.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/dsa.h>

#include <yaca_error.h>

#include "internal.h"
#include "debug.h"

// TODO any better idea than to use __thread?
static __thread yaca_error_cb error_cb = NULL;
static bool error_strings_loaded = false;
static const int GENERIC_REASON_MAX = 99;

API void yaca_debug_set_error_cb(yaca_error_cb fn)
{
	error_cb = fn;
}

#define ERRORDESCRIBE(name) case name: return #name
API const char *yaca_debug_translate_error(yaca_error_e err)
{
	switch (err) {
	ERRORDESCRIBE(YACA_ERROR_NONE);
	ERRORDESCRIBE(YACA_ERROR_INVALID_PARAMETER);
	ERRORDESCRIBE(YACA_ERROR_OUT_OF_MEMORY);
	ERRORDESCRIBE(YACA_ERROR_INTERNAL);
	ERRORDESCRIBE(YACA_ERROR_DATA_MISMATCH);
	ERRORDESCRIBE(YACA_ERROR_INVALID_PASSWORD);
	default: return "Error not defined";
	}
}
#undef ERRORDESCRIBE

void error_dump(const char *file, int line, const char *function, int code)
{
	if (error_cb == NULL) {
		ERR_clear_error();
		return;
	}

	static const size_t BUF_SIZE = 512;
	static const char ELLIPSIS[] = "...\n";
	static const size_t ELLIPSIS_SIZE = sizeof(ELLIPSIS) / sizeof(ELLIPSIS[0]);
	char buf[BUF_SIZE];
	unsigned long err;
	size_t written;
	const char *err_str = yaca_debug_translate_error(code);
	const char *sign = "";

	if (code < 0) {
		code *= -1;
		sign = "-";
	}

	written = snprintf(buf, BUF_SIZE, "%s:%d %s() API error: %s0x%02X (%s)\n", file,
	                   line, function, sign, code, err_str);

	while ((err = ERR_get_error()) != 0 && written < BUF_SIZE - 1) {
		if (!error_strings_loaded) {
			/*
			 * This function is thread-safe as long as static locks are
			 * installed according to doc so calling it twice won't break
			 * anything and I don't want to use synchronization mechanisms
			 * here.
			 */
			ERR_load_crypto_strings();
			error_strings_loaded = true;
		}

		ERR_error_string_n(err, buf + written, BUF_SIZE - written);
		written = strlen(buf); /* I trust you, openssl */
		if (written < BUF_SIZE - 1) {
			buf[written] = '\n';
			written++;
		}
	}

	if (written >= BUF_SIZE - 1) {
		strncpy(buf + BUF_SIZE - ELLIPSIS_SIZE, ELLIPSIS, ELLIPSIS_SIZE);
		written = BUF_SIZE - 1;
		ERR_clear_error();
	}
	buf[written] = '\0';

	(*error_cb)(buf);
}

int error_handle(const char *file, int line, const char *function)
{
	int ret = YACA_ERROR_NONE;
	unsigned long err = ERR_peek_error();

	if (err == 0)
		return YACA_ERROR_INTERNAL;

	/* known errors */
	switch (err) {
#if OPENSSL_VERSION_NUMBER > 0x10100000L
	case ERR_PACK(ERR_LIB_RSA, RSA_F_RSA_OSSL_PRIVATE_DECRYPT, RSA_R_DATA_GREATER_THAN_MOD_LEN):
	case ERR_PACK(ERR_LIB_RSA, RSA_F_RSA_OSSL_PUBLIC_DECRYPT, RSA_R_DATA_GREATER_THAN_MOD_LEN):
	case ERR_PACK(ERR_LIB_PEM, PEM_F_GET_NAME, PEM_R_NO_START_LINE):
#else /* OPENSSL_VERSION_NUMBER > 0x10100000L */
	case ERR_PACK(ERR_LIB_RSA, RSA_F_PKEY_RSA_CTRL, RSA_R_INVALID_KEYBITS):
	case ERR_PACK(ERR_LIB_RSA, RSA_F_RSA_EAY_PRIVATE_DECRYPT, RSA_R_DATA_GREATER_THAN_MOD_LEN):
	case ERR_PACK(ERR_LIB_RSA, RSA_F_RSA_EAY_PUBLIC_DECRYPT, RSA_R_DATA_GREATER_THAN_MOD_LEN):
#endif /* OPENSSL_VERSION_NUMBER > 0x10100000L */
	case ERR_PACK(ERR_LIB_RSA, RSA_F_PKEY_RSA_CTRL, RSA_R_KEY_SIZE_TOO_SMALL):
	case ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_CTX_CTRL, EVP_R_COMMAND_NOT_SUPPORTED):
	case ERR_PACK(ERR_LIB_PEM, PEM_F_PEM_READ_BIO, PEM_R_NO_START_LINE):
	case ERR_PACK(ERR_LIB_ASN1, ASN1_F_ASN1_D2I_READ_BIO, ASN1_R_NOT_ENOUGH_DATA):
	case ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_ENCRYPTFINAL_EX, EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH):
	case ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_DECRYPTFINAL_EX, EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH):
	case ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_DECRYPTFINAL_EX, EVP_R_WRONG_FINAL_BLOCK_LENGTH):
	case ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_PKEY_DERIVE_SET_PEER, EVP_R_DIFFERENT_PARAMETERS):
	case ERR_PACK(ERR_LIB_EC, EC_F_PKEY_EC_CTRL, EC_R_INVALID_DIGEST_TYPE):
	case ERR_PACK(ERR_LIB_DSA, DSA_F_PKEY_DSA_CTRL, DSA_R_INVALID_DIGEST_TYPE):
		ret = YACA_ERROR_INVALID_PARAMETER;
		break;
	case ERR_PACK(ERR_LIB_ASN1, ASN1_F_ASN1_GET_OBJECT, ASN1_R_TOO_LONG):
	case ERR_PACK(ERR_LIB_ASN1, ASN1_F_ASN1_GET_OBJECT, ASN1_R_HEADER_TOO_LONG):
	case ERR_PACK(ERR_LIB_ASN1, ASN1_F_ASN1_CHECK_TLEN, ASN1_R_WRONG_TAG):
	{
		bool found_crypto_error = false;

		while ((err = ERR_get_error()) != 0)
			if (err == ERR_PACK(ERR_LIB_PKCS12, PKCS12_F_PKCS12_ITEM_DECRYPT_D2I, PKCS12_R_DECODE_ERROR) ||
			    err == ERR_PACK(ERR_LIB_PKCS12, PKCS12_F_PKCS12_PBE_CRYPT, PKCS12_R_PKCS12_CIPHERFINAL_ERROR) ||
			    err == ERR_PACK(ERR_LIB_DSA, DSA_F_OLD_DSA_PRIV_DECODE, ERR_R_DSA_LIB) ||
			    err == ERR_PACK(ERR_LIB_RSA, RSA_F_OLD_RSA_PRIV_DECODE, ERR_R_RSA_LIB)) {
				found_crypto_error = true;
				break;
			}

		if (found_crypto_error)
			ret = YACA_ERROR_INVALID_PASSWORD;
		else
			ret = YACA_ERROR_INVALID_PARAMETER;

		break;
	}
	case ERR_PACK(ERR_LIB_EVP, EVP_F_EVP_DECRYPTFINAL_EX, EVP_R_BAD_DECRYPT):
	case ERR_PACK(ERR_LIB_PEM, PEM_F_PEM_DO_HEADER, PEM_R_BAD_DECRYPT):
	case ERR_PACK(ERR_LIB_PEM, PEM_F_PEM_DO_HEADER, PEM_R_BAD_PASSWORD_READ):
	case ERR_PACK(ERR_LIB_PEM, PEM_F_PEM_READ_BIO_PRIVATEKEY, PEM_R_BAD_PASSWORD_READ):
	case ERR_PACK(ERR_LIB_PEM, PEM_F_D2I_PKCS8PRIVATEKEY_BIO, PEM_R_BAD_PASSWORD_READ):
		ret = YACA_ERROR_INVALID_PASSWORD;
		break;
	}

	/* known rsa padding errors */
	if (ret == YACA_ERROR_NONE && ERR_GET_LIB(err) == ERR_LIB_RSA) {
		switch (ERR_GET_FUNC(err)) {
		case RSA_F_CHECK_PADDING_MD:
		case RSA_F_RSA_PADDING_CHECK_NONE:
		case RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP:
		case RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP_MGF1:
		case RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1:
		case RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2:
		case RSA_F_RSA_PADDING_CHECK_SSLV23:
		case RSA_F_RSA_PADDING_CHECK_X931:
		case RSA_F_RSA_PADDING_ADD_NONE:
		case RSA_F_RSA_PADDING_ADD_PKCS1_OAEP:
		case RSA_F_RSA_PADDING_ADD_PKCS1_OAEP_MGF1:
		case RSA_F_RSA_PADDING_ADD_PKCS1_PSS:
		case RSA_F_RSA_PADDING_ADD_PKCS1_PSS_MGF1:
		case RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1:
		case RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_2:
		case RSA_F_RSA_PADDING_ADD_SSLV23:
		case RSA_F_RSA_PADDING_ADD_X931:
			ret = YACA_ERROR_INVALID_PARAMETER;
			break;
		}
	}

	/* fatal errors */
	int reason = ERR_GET_REASON(err);
	if (ret == YACA_ERROR_NONE && reason <= GENERIC_REASON_MAX && (err & ERR_R_FATAL) > 0) {
		switch (reason) {
		case ERR_R_MALLOC_FAILURE:
			ret = YACA_ERROR_OUT_OF_MEMORY;
			break;
		case ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED:
		case ERR_R_PASSED_NULL_PARAMETER:
			ret = YACA_ERROR_INVALID_PARAMETER;
			break;
		case ERR_R_INTERNAL_ERROR:
		case ERR_R_DISABLED:
			ret = YACA_ERROR_INTERNAL;
			break;
		}
	}

	/* neither known nor fatal, unknown */
	if (ret == YACA_ERROR_NONE) {
		error_dump(file, line, function, YACA_ERROR_INTERNAL);
		ret = YACA_ERROR_INTERNAL;
	}

	/* remove all errors from queue */
	ERR_clear_error();
	return ret;
}
