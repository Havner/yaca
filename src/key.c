/*
 *  Copyright (c) 2016-2020 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file key.c
 * @brief
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/des.h>
#include <openssl/dh.h>

#include <yaca_crypto.h>
#include <yaca_error.h>
#include <yaca_key.h>
#include <yaca_types.h>

#include "internal.h"

struct openssl_password_data {
	bool password_requested;
	const char *password;
};

static int openssl_password_cb(char *buf, int size, UNUSED int rwflag, void *u)
{
	struct openssl_password_data *cb_data = u;

	if (cb_data == NULL)
		return 0;
	if (cb_data->password == NULL)
		return 0;

	size_t pass_len = strlen(cb_data->password);

	if (pass_len > INT_MAX || (int)pass_len > size)
		return 0;

	memcpy(buf, cb_data->password, pass_len);
	cb_data->password_requested = true;

	return pass_len;
}

static const struct {
	size_t ec;
	int nid;
} EC_NID_PAIRS[] = {
	{YACA_KEY_LENGTH_EC_PRIME192V1, NID_X9_62_prime192v1},
	{YACA_KEY_LENGTH_EC_PRIME256V1, NID_X9_62_prime256v1},
	{YACA_KEY_LENGTH_EC_SECP256K1,  NID_secp256k1},
	{YACA_KEY_LENGTH_EC_SECP384R1,  NID_secp384r1},
	{YACA_KEY_LENGTH_EC_SECP521R1,  NID_secp521r1}
};

static const size_t EC_NID_PAIRS_SIZE = sizeof(EC_NID_PAIRS) / sizeof(EC_NID_PAIRS[0]);

static const struct {
	int evp_id;
	yaca_key_type_e priv;
	yaca_key_type_e pub;
	yaca_key_type_e params;
} KEY_TYPES_PARAMS[] = {
	{EVP_PKEY_RSA, YACA_KEY_TYPE_RSA_PRIV, YACA_KEY_TYPE_RSA_PUB, -1},
	{EVP_PKEY_DSA, YACA_KEY_TYPE_DSA_PRIV, YACA_KEY_TYPE_DSA_PUB, YACA_KEY_TYPE_DSA_PARAMS},
	{EVP_PKEY_DH,  YACA_KEY_TYPE_DH_PRIV,  YACA_KEY_TYPE_DH_PUB,  YACA_KEY_TYPE_DH_PARAMS},
	{EVP_PKEY_EC,  YACA_KEY_TYPE_EC_PRIV,  YACA_KEY_TYPE_EC_PUB,  YACA_KEY_TYPE_EC_PARAMS},
	/* The following line is only used to import DHX (RFC5114) keys/params.
	 * In all other cases DH is used. It has to be below the DH one so conversions from YACA
	 * internal types are prioritized to EVP_PKEY_DH which is what we want. */
	{EVP_PKEY_DHX, YACA_KEY_TYPE_DH_PRIV,  YACA_KEY_TYPE_DH_PUB,  YACA_KEY_TYPE_DH_PARAMS}
};

static const size_t KEY_TYPES_PARAMS_SIZE = sizeof(KEY_TYPES_PARAMS) / sizeof(KEY_TYPES_PARAMS[0]);

#define CONVERT_TYPES_TEMPLATE(data, src_type, src, dst_type, dst) \
	static int convert_##src##_to_##dst(src_type src, dst_type *dst) \
	{ \
		assert(dst != NULL); \
		size_t i; \
		for (i = 0; i < data##_SIZE; ++i) \
			if (data[i].src == src) { \
				if (data[i].dst != (dst_type)-1) { \
					*dst = data[i].dst; \
					return YACA_ERROR_NONE; \
				} \
			} \
		return YACA_ERROR_INVALID_PARAMETER; \
	}

CONVERT_TYPES_TEMPLATE(EC_NID_PAIRS, int, nid, size_t, ec)
CONVERT_TYPES_TEMPLATE(EC_NID_PAIRS, size_t, ec, int, nid)

CONVERT_TYPES_TEMPLATE(KEY_TYPES_PARAMS, yaca_key_type_e, params, int, evp_id)
CONVERT_TYPES_TEMPLATE(KEY_TYPES_PARAMS, yaca_key_type_e, priv,   int, evp_id)
CONVERT_TYPES_TEMPLATE(KEY_TYPES_PARAMS, yaca_key_type_e, params, yaca_key_type_e, priv)
CONVERT_TYPES_TEMPLATE(KEY_TYPES_PARAMS, yaca_key_type_e, priv,   yaca_key_type_e, pub)
CONVERT_TYPES_TEMPLATE(KEY_TYPES_PARAMS, yaca_key_type_e, priv,   yaca_key_type_e, params)
CONVERT_TYPES_TEMPLATE(KEY_TYPES_PARAMS, yaca_key_type_e, pub,    yaca_key_type_e, params)
CONVERT_TYPES_TEMPLATE(KEY_TYPES_PARAMS, int, evp_id,             yaca_key_type_e, priv)
CONVERT_TYPES_TEMPLATE(KEY_TYPES_PARAMS, int, evp_id,             yaca_key_type_e, pub)
CONVERT_TYPES_TEMPLATE(KEY_TYPES_PARAMS, int, evp_id,             yaca_key_type_e, params)

static int base64_decode_length(const char *data, size_t data_len, size_t *len)
{
	assert(data != NULL);
	assert(data_len != 0);
	assert(len != NULL);

	size_t padded = 0;
	size_t tmp_len = data_len;

	if (data_len % 4 != 0)
		return YACA_ERROR_INVALID_PARAMETER;

	if (data[tmp_len - 1] == '=') {
		padded = 1;
		if (data[tmp_len - 2] == '=')
			padded = 2;
	}

	*len = data_len / 4 * 3 - padded;
	return YACA_ERROR_NONE;
}

#define TMP_BUF_LEN 512

static int base64_decode(const char *data, size_t data_len, BIO **output)
{
	assert(data != NULL);
	assert(data_len != 0);
	assert(output != NULL);

	int ret;
	BIO *b64 = NULL;
	BIO *src = NULL;
	BIO *dst = NULL;
	char tmpbuf[TMP_BUF_LEN];
	size_t b64_len;
	char *out;
	long out_len;

	/* This is because of BIO_new_mem_buf() having its length param typed int */
	if (data_len > INT_MAX)
		return YACA_ERROR_INVALID_PARAMETER;

	/* First phase of correctness checking, calculate expected output length */
	ret = base64_decode_length(data, data_len, &b64_len);
	if (ret != YACA_ERROR_NONE)
		return ret;

	b64 = BIO_new(BIO_f_base64());
	if (b64 == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	src = BIO_new_mem_buf(data, data_len);
	if (src == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	BIO_push(b64, src);

	dst = BIO_new(BIO_s_mem());
	if (dst == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	/* Try to decode */
	for (;;) {
		ret = BIO_read(b64, tmpbuf, TMP_BUF_LEN);
		if (ret < 0) {
			ret = YACA_ERROR_INTERNAL;
			ERROR_DUMP(ret);
			goto exit;
		}

		if (ret == YACA_ERROR_NONE)
			break;

		if (BIO_write(dst, tmpbuf, ret) != ret) {
			ret = YACA_ERROR_INTERNAL;
			ERROR_DUMP(ret);
			goto exit;
		}
	}

	BIO_flush(dst);

	/* Check wether the length of the decoded data is what we expected */
	out_len = BIO_get_mem_data(dst, &out);
	if (out_len < 0) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}
	if ((size_t)out_len != b64_len) {
		ret = YACA_ERROR_INVALID_PARAMETER;
		goto exit;
	}

	*output = dst;
	dst = NULL;
	ret = YACA_ERROR_NONE;

exit:
	BIO_free_all(b64);
	BIO_free_all(dst);

	return ret;
}

static int import_simple(yaca_key_h *key,
                         yaca_key_type_e key_type,
                         const char *data,
                         size_t data_len)
{
	assert(key != NULL);
	assert(data != NULL);
	assert(data_len != 0);

	int ret;
	BIO *decoded = NULL;
	const char *key_data;
	size_t key_data_len;
	struct yaca_key_simple_s *nk = NULL;

	ret = base64_decode(data, data_len, &decoded);
	if (ret == YACA_ERROR_NONE) {
		/* Conversion successfull, get the BASE64 */
		long len = BIO_get_mem_data(decoded, &key_data);
		if (len <= 0 || key_data == NULL) {
			ret = YACA_ERROR_INTERNAL;
			ERROR_DUMP(ret);
			return ret;
		}
		key_data_len = len;
	} else if (ret == YACA_ERROR_INVALID_PARAMETER) {
		/* This was not BASE64 or it was corrupted, treat as RAW */
		key_data_len = data_len;
		key_data = data;
	} else {
		/* Some other, possibly unrecoverable error, give up */
		return ret;
	}

	/* key_bit_len has to fit in size_t */
	if (key_data_len > SIZE_MAX / 8) {
		ret = YACA_ERROR_INVALID_PARAMETER;
		goto exit;
	}

	/* DES key length verification */
	if (key_type == YACA_KEY_TYPE_DES) {
		size_t key_bit_len = key_data_len * 8;
		if (key_bit_len != YACA_KEY_LENGTH_UNSAFE_64BIT &&
		    key_bit_len != YACA_KEY_LENGTH_UNSAFE_128BIT &&
		    key_bit_len != YACA_KEY_LENGTH_192BIT) {
			ret = YACA_ERROR_INVALID_PARAMETER;
			goto exit;
		}
	}

	ret = yaca_zalloc(sizeof(struct yaca_key_simple_s) + key_data_len, (void**)&nk);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	memcpy(nk->d, key_data, key_data_len);
	nk->bit_len = key_data_len * 8;
	nk->key.type = key_type;

	*key = (yaca_key_h)nk;
	nk = NULL;
	ret = YACA_ERROR_NONE;

exit:
	BIO_free_all(decoded);

	return ret;
}

static EVP_PKEY *d2i_DSAparams_bio_helper(BIO *src)
{
	assert(src != NULL);

	DSA *dsa = NULL;
	EVP_PKEY *pkey = NULL;

	dsa = d2i_DSAparams_bio(src, NULL);
	if (dsa == NULL)
		return NULL;

	pkey = EVP_PKEY_new();
	if (pkey == NULL)
		goto exit;

	if (EVP_PKEY_assign_DSA(pkey, dsa) != 1)
		goto exit;

	return pkey;

exit:
	EVP_PKEY_free(pkey);
	DSA_free(dsa);
	return NULL;
}

static EVP_PKEY *d2i_DHparams_bio_helper(BIO *src)
{
	assert(src != NULL);

	DH *dh = NULL;
	EVP_PKEY *pkey = NULL;

	dh = d2i_DHparams_bio(src, NULL);
	if (dh == NULL)
		return NULL;

	pkey = EVP_PKEY_new();
	if (pkey == NULL)
		goto exit;

	if (EVP_PKEY_assign_DH(pkey, dh) != 1)
		goto exit;

	return pkey;

exit:
	EVP_PKEY_free(pkey);
	DH_free(dh);
	return NULL;
}

static EVP_PKEY *d2i_ECPKParameters_bio_helper(BIO *src)
{
	assert(src != NULL);

	EC_GROUP *ecg = NULL;
	EC_KEY *eck = NULL;
	EVP_PKEY *pkey = NULL;

	ecg = d2i_ECPKParameters_bio(src, NULL);
	if (ecg == NULL)
		return NULL;

	eck = EC_KEY_new();
	if (eck == NULL)
		goto exit;

	if (EC_KEY_set_group(eck, ecg) != 1)
		goto exit;

	EC_GROUP_free(ecg);
	ecg = NULL;

	pkey = EVP_PKEY_new();
	if (pkey == NULL)
		goto exit;

	if (EVP_PKEY_assign_EC_KEY(pkey, eck) != 1)
		goto exit;

	return pkey;

exit:
	EVP_PKEY_free(pkey);
	EC_KEY_free(eck);
	EC_GROUP_free(ecg);
	return NULL;
}

static int import_evp(yaca_key_h *key,
                      yaca_key_type_e key_type,
                      const char *password,
                      const char *data,
                      size_t data_len)
{
	assert(key != NULL);
	assert(password == NULL || password[0] != '\0');
	assert(data != NULL);
	assert(data_len != 0);

	int ret;
	BIO *src = NULL;
	EVP_PKEY *pkey = NULL;
	pem_password_cb *cb = openssl_password_cb;
	struct openssl_password_data cb_data = {false, password};
	int imported_evp_id;
	enum {
		IMPORTED_KEY_CATEGORY_PRIVATE,
		IMPORTED_KEY_CATEGORY_PUBLIC,
		IMPORTED_KEY_CATEGORY_PARAMETERS
	} imported_key_category;
	yaca_key_type_e imported_key_type;
	bool password_supported;
	struct yaca_key_evp_s *nk = NULL;

	/* Neither PEM nor DER will ever be shorter then 4 bytes (12 seems
	 * to be minimum for DER, much more for PEM). This is just to make
	 * sure we have at least 4 bytes for strncmp() below.
	 */
	if (data_len < 4)
		return YACA_ERROR_INVALID_PARAMETER;

	/* This is because of BIO_new_mem_buf() having its length param typed int */
	if (data_len > INT_MAX)
		return YACA_ERROR_INVALID_PARAMETER;

	src = BIO_new_mem_buf(data, data_len);
	if (src == NULL) {
		ERROR_DUMP(YACA_ERROR_INTERNAL);
		return YACA_ERROR_INTERNAL;
	}

	/* Possible PEM */
	if (strncmp("----", data, 4) == 0) {
		if (pkey == NULL) {
			BIO_reset(src);
			pkey = PEM_read_bio_PrivateKey(src, NULL, cb, (void*)&cb_data);
			if (ERROR_HANDLE() == YACA_ERROR_INVALID_PASSWORD) {
				ret = YACA_ERROR_INVALID_PASSWORD;
				goto exit;
			}
			imported_key_category = IMPORTED_KEY_CATEGORY_PRIVATE;
			password_supported = true;
		}

		if (pkey == NULL) {
			BIO_reset(src);
			pkey = PEM_read_bio_PUBKEY(src, NULL, cb, NULL);
			ERROR_CLEAR();
			imported_key_category = IMPORTED_KEY_CATEGORY_PUBLIC;
			password_supported = false;
		}

		if (pkey == NULL) {
			BIO_reset(src);
			pkey = PEM_read_bio_Parameters(src, NULL);
			ERROR_CLEAR();
			imported_key_category = IMPORTED_KEY_CATEGORY_PARAMETERS;
			password_supported = false;
		}

		if (pkey == NULL) {
			BIO_reset(src);
			X509 *x509 = PEM_read_bio_X509(src, NULL, cb, NULL);
			if (x509 != NULL) {
				pkey = X509_get_pubkey(x509);
				X509_free(x509);
			}
			ERROR_CLEAR();
			imported_key_category = IMPORTED_KEY_CATEGORY_PUBLIC;
			password_supported = false;
		}
	}
	/* Possible DER */
	else {
		if (pkey == NULL) {
			BIO_reset(src);
			pkey = d2i_PKCS8PrivateKey_bio(src, NULL, cb, (void*)&cb_data);
			if (ERROR_HANDLE() == YACA_ERROR_INVALID_PASSWORD) {
				ret = YACA_ERROR_INVALID_PASSWORD;
				goto exit;
			}
			imported_key_category = IMPORTED_KEY_CATEGORY_PRIVATE;
			password_supported = true;
		}

		if (pkey == NULL) {
			BIO_reset(src);
			pkey = d2i_PrivateKey_bio(src, NULL);
			ERROR_CLEAR();
			imported_key_category = IMPORTED_KEY_CATEGORY_PRIVATE;
			password_supported = false;
		}

		if (pkey == NULL) {
			BIO_reset(src);
			pkey = d2i_PUBKEY_bio(src, NULL);
			ERROR_CLEAR();
			imported_key_category = IMPORTED_KEY_CATEGORY_PUBLIC;
			password_supported = false;
		}

		if (pkey == NULL) {
			BIO_reset(src);
			pkey = d2i_DSAparams_bio_helper(src);
			ERROR_CLEAR();
			imported_key_category = IMPORTED_KEY_CATEGORY_PARAMETERS;
			password_supported = false;
		}

		if (pkey == NULL) {
			BIO_reset(src);
			pkey = d2i_DHparams_bio_helper(src);
			ERROR_CLEAR();
			imported_key_category = IMPORTED_KEY_CATEGORY_PARAMETERS;
			password_supported = false;
		}

		if (pkey == NULL) {
			BIO_reset(src);
			pkey = d2i_ECPKParameters_bio_helper(src);
			ERROR_CLEAR();
			imported_key_category = IMPORTED_KEY_CATEGORY_PARAMETERS;
			password_supported = false;
		}

		if (pkey == NULL) {
			BIO_reset(src);
			X509 *x509 = d2i_X509_bio(src, NULL);
			if (x509 != NULL) {
				pkey = X509_get_pubkey(x509);
				X509_free(x509);
			}
			ERROR_CLEAR();
			imported_key_category = IMPORTED_KEY_CATEGORY_PUBLIC;
			password_supported = false;
		}
	}

	if (pkey == NULL) {
		ret = YACA_ERROR_INVALID_PARAMETER;
		goto exit;
	}

	/* password was given, but it was not required to perform import */
	if (password != NULL && !cb_data.password_requested) {
		if (password_supported)
			ret = YACA_ERROR_INVALID_PASSWORD;
		else
			ret = YACA_ERROR_INVALID_PARAMETER;
		goto exit;
	}

	imported_evp_id = EVP_PKEY_type(EVP_PKEY_id(pkey));

	switch (imported_key_category) {
	case IMPORTED_KEY_CATEGORY_PRIVATE:
		ret = convert_evp_id_to_priv(imported_evp_id, &imported_key_type);
		break;
	case IMPORTED_KEY_CATEGORY_PUBLIC:
		ret = convert_evp_id_to_pub(imported_evp_id, &imported_key_type);
		break;
	case IMPORTED_KEY_CATEGORY_PARAMETERS:
		ret = convert_evp_id_to_params(imported_evp_id, &imported_key_type);
		break;
	default:
		assert(false);
		ret = YACA_ERROR_INTERNAL;
		goto exit;
	}
	/* The imported key ID is of an YACA unsupported type */
	if (ret != YACA_ERROR_NONE)
		goto exit;

	if (imported_key_type != key_type) {
		ret = YACA_ERROR_INVALID_PARAMETER;
		goto exit;
	}

	if ((key_type == YACA_KEY_TYPE_RSA_PRIV || key_type == YACA_KEY_TYPE_RSA_PUB) &&
	    (EVP_PKEY_size(pkey) < YACA_KEY_LENGTH_512BIT / 8)) {
		ret = YACA_ERROR_INVALID_PARAMETER;
		goto exit;
	}

	ret = yaca_zalloc(sizeof(struct yaca_key_evp_s), (void**)&nk);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	nk->evp = pkey;
	*key = (yaca_key_h)nk;
	(*key)->type = key_type;

	pkey = NULL;
	ret = YACA_ERROR_NONE;

exit:
	EVP_PKEY_free(pkey);
	BIO_free_all(src);
	return ret;
}

static int export_simple_raw(struct yaca_key_simple_s *simple_key,
                             char **data,
                             size_t *data_len)
{
	int ret;
	assert(simple_key != NULL);
	assert(data != NULL);
	assert(data_len != NULL);

	size_t key_len = simple_key->bit_len / 8;

	assert(key_len > 0);

	ret = yaca_malloc(key_len, (void**)data);
	if (ret != YACA_ERROR_NONE)
		return ret;

	memcpy(*data, simple_key->d, key_len);
	*data_len = key_len;

	return YACA_ERROR_NONE;
}

static int export_simple_base64(struct yaca_key_simple_s *simple_key,
                                char **data,
                                size_t *data_len)
{
	assert(simple_key != NULL);
	assert(data != NULL);
	assert(data_len != NULL);

	int ret;
	size_t key_len = simple_key->bit_len / 8;
	BIO *b64;
	BIO *mem;
	char *bio_data;
	long bio_data_len;

	b64 = BIO_new(BIO_f_base64());
	if (b64 == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	mem = BIO_new(BIO_s_mem());
	if (mem == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	BIO_push(b64, mem);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	ret = BIO_write(b64, simple_key->d, key_len);
	if (ret <= 0 || (unsigned)ret != key_len) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	ret = BIO_flush(b64);
	if (ret <= 0) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	bio_data_len = BIO_get_mem_data(mem, &bio_data);
	if (bio_data_len <= 0) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	ret = yaca_malloc(bio_data_len, (void**)data);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	memcpy(*data, bio_data, bio_data_len);
	*data_len = bio_data_len;
	ret = YACA_ERROR_NONE;

exit:
	BIO_free_all(b64);

	return ret;
}

static int export_evp_default_bio(struct yaca_key_evp_s *evp_key,
                                  yaca_key_file_format_e key_file_fmt,
                                  const char *password,
                                  BIO *mem)
{
	assert(evp_key != NULL);
	assert(password == NULL || password[0] != '\0');
	assert(mem != NULL);

	int ret;
	const EVP_CIPHER *enc = NULL;

	if (password != NULL)
		enc = EVP_aes_256_cbc();

	switch (key_file_fmt) {

	case YACA_KEY_FILE_FORMAT_PEM:
		switch (evp_key->key.type) {

		case YACA_KEY_TYPE_RSA_PRIV:
		case YACA_KEY_TYPE_DSA_PRIV:
		case YACA_KEY_TYPE_DH_PRIV:
		case YACA_KEY_TYPE_EC_PRIV:
			ret = PEM_write_bio_PrivateKey(mem, evp_key->evp, enc,
			                               NULL, 0, NULL, (void*)password);
			break;

		case YACA_KEY_TYPE_RSA_PUB:
		case YACA_KEY_TYPE_DSA_PUB:
		case YACA_KEY_TYPE_DH_PUB:
		case YACA_KEY_TYPE_EC_PUB:
			if (password != NULL)
				return YACA_ERROR_INVALID_PARAMETER;
			ret = PEM_write_bio_PUBKEY(mem, evp_key->evp);
			break;

		case YACA_KEY_TYPE_DSA_PARAMS:
		case YACA_KEY_TYPE_DH_PARAMS:
		case YACA_KEY_TYPE_EC_PARAMS:
			if (password != NULL)
				return YACA_ERROR_INVALID_PARAMETER;
			ret = PEM_write_bio_Parameters(mem, evp_key->evp);
			break;

		default:
			return YACA_ERROR_INVALID_PARAMETER;
		}

		break;

	case YACA_KEY_FILE_FORMAT_DER:
		/* None of the formats in DEFAULT DER support a password */
		if (password != NULL)
			return YACA_ERROR_INVALID_PARAMETER;

		switch (evp_key->key.type) {

		case YACA_KEY_TYPE_RSA_PRIV:
		case YACA_KEY_TYPE_DSA_PRIV:
		case YACA_KEY_TYPE_DH_PRIV:
		case YACA_KEY_TYPE_EC_PRIV:
			ret = i2d_PrivateKey_bio(mem, evp_key->evp);
			break;

		case YACA_KEY_TYPE_RSA_PUB:
		case YACA_KEY_TYPE_DSA_PUB:
		case YACA_KEY_TYPE_DH_PUB:
		case YACA_KEY_TYPE_EC_PUB:
			ret = i2d_PUBKEY_bio(mem, evp_key->evp);
			break;

		case YACA_KEY_TYPE_DSA_PARAMS:
			ret = i2d_DSAparams_bio(mem, EVP_PKEY_get0(evp_key->evp));
			break;
		case YACA_KEY_TYPE_DH_PARAMS:
			ret = i2d_DHparams_bio(mem, EVP_PKEY_get0(evp_key->evp));
			break;
		case YACA_KEY_TYPE_EC_PARAMS: {
			const EC_KEY *eck = EVP_PKEY_get0(evp_key->evp);
			const EC_GROUP *ecg = EC_KEY_get0_group(eck);
			ret = i2d_ECPKParameters_bio(mem, ecg);
			break;
		}

		default:
			return YACA_ERROR_INVALID_PARAMETER;
		}

		break;

	default:
		return YACA_ERROR_INVALID_PARAMETER;
	}

	if (ret <= 0) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	return YACA_ERROR_NONE;
}

static int export_evp_pkcs8_bio(struct yaca_key_evp_s *evp_key,
                                yaca_key_file_format_e key_file_fmt,
                                const char *password,
                                BIO *mem)
{
	assert(evp_key != NULL);
	assert(password == NULL || password[0] != '\0');
	assert(mem != NULL);

	int ret;
	const EVP_CIPHER *enc = EVP_aes_256_cbc();;

	/* PKCS8 export requires a password */
	if (password == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	switch (key_file_fmt) {

	case YACA_KEY_FILE_FORMAT_PEM:
		switch (evp_key->key.type) {

		case YACA_KEY_TYPE_RSA_PRIV:
		case YACA_KEY_TYPE_DSA_PRIV:
		case YACA_KEY_TYPE_DH_PRIV:
		case YACA_KEY_TYPE_EC_PRIV:
			ret = PEM_write_bio_PKCS8PrivateKey(mem, evp_key->evp, enc,
			                                    NULL, 0, NULL, (void*)password);
			break;

		default:
			return YACA_ERROR_INVALID_PARAMETER;
		}

		break;

	case YACA_KEY_FILE_FORMAT_DER:
		switch (evp_key->key.type) {

		case YACA_KEY_TYPE_RSA_PRIV:
		case YACA_KEY_TYPE_DSA_PRIV:
		case YACA_KEY_TYPE_DH_PRIV:
		case YACA_KEY_TYPE_EC_PRIV:
			ret = i2d_PKCS8PrivateKey_bio(mem, evp_key->evp, enc,
			                              NULL, 0, NULL, (void*)password);
			break;

		default:
			return YACA_ERROR_INVALID_PARAMETER;
		}

		break;

	default:
		return YACA_ERROR_INVALID_PARAMETER;
	}

	if (ret <= 0) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	return YACA_ERROR_NONE;
}

static int export_evp(struct yaca_key_evp_s *evp_key,
                      yaca_key_format_e key_fmt,
                      yaca_key_file_format_e key_file_fmt,
                      const char *password,
                      char **data,
                      size_t *data_len)
{
	assert(evp_key != NULL);
	assert(password == NULL || password[0] != '\0');
	assert(data != NULL);
	assert(data_len != NULL);

	int ret = YACA_ERROR_NONE;
	BIO *mem;
	char *bio_data;
	long bio_data_len;

	mem = BIO_new(BIO_s_mem());
	if (mem == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		return ret;
	}

	switch (key_fmt) {
	case YACA_KEY_FORMAT_DEFAULT:
		ret = export_evp_default_bio(evp_key, key_file_fmt, password, mem);
		break;
	case YACA_KEY_FORMAT_PKCS8:
		ret = export_evp_pkcs8_bio(evp_key, key_file_fmt, password, mem);
		break;
	default:
		ret = YACA_ERROR_INVALID_PARAMETER;
		break;
	}

	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = BIO_flush(mem);
	if (ret <= 0) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	bio_data_len = BIO_get_mem_data(mem, &bio_data);
	if (bio_data_len <= 0) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	ret = yaca_malloc(bio_data_len, (void**)data);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	memcpy(*data, bio_data, bio_data_len);
	*data_len = bio_data_len;
	ret = YACA_ERROR_NONE;

exit:
	BIO_free_all(mem);

	return ret;
}

static int generate_simple(struct yaca_key_simple_s **out, size_t key_bit_len)
{
	assert(out != NULL);

	if (key_bit_len % 8 != 0)
		return YACA_ERROR_INVALID_PARAMETER;

	int ret;
	struct yaca_key_simple_s *nk;
	size_t key_byte_len = key_bit_len / 8;

	ret = yaca_zalloc(sizeof(struct yaca_key_simple_s) + key_byte_len, (void**)&nk);
	if (ret != YACA_ERROR_NONE)
		return ret;

	nk->bit_len = key_bit_len;

	ret = yaca_randomize_bytes(nk->d, key_byte_len);
	if (ret != YACA_ERROR_NONE) {
		yaca_free(nk);
		return ret;
	}

	*out = nk;
	return YACA_ERROR_NONE;
}

static int generate_simple_des(struct yaca_key_simple_s **out, size_t key_bit_len)
{
	assert(out != NULL);

	if (key_bit_len != YACA_KEY_LENGTH_UNSAFE_64BIT &&
	    key_bit_len != YACA_KEY_LENGTH_UNSAFE_128BIT &&
	    key_bit_len != YACA_KEY_LENGTH_192BIT)
		return YACA_ERROR_INVALID_PARAMETER;

	int ret;
	struct yaca_key_simple_s *nk;
	size_t key_byte_len = key_bit_len / 8;

	ret = yaca_zalloc(sizeof(struct yaca_key_simple_s) + key_byte_len, (void**)&nk);
	if (ret != YACA_ERROR_NONE)
		return ret;

	DES_cblock *des_key = (DES_cblock*)nk->d;
	if (key_byte_len >= 8) {
		ret = DES_random_key(des_key);
		if (ret != 1) {
			ret = YACA_ERROR_INTERNAL;
			ERROR_DUMP(ret);
			goto exit;
		}
	}
	if (key_byte_len >= 16) {
		ret = DES_random_key(des_key + 1);
		if (ret != 1) {
			ret = YACA_ERROR_INTERNAL;
			ERROR_DUMP(ret);
			goto exit;
		}
	}
	if (key_byte_len >= 24) {
		ret = DES_random_key(des_key + 2);
		if (ret != 1) {
			ret = YACA_ERROR_INTERNAL;
			ERROR_DUMP(ret);
			goto exit;
		}
	}

	nk->bit_len = key_bit_len;
	*out = nk;
	nk = NULL;
	ret = YACA_ERROR_NONE;

exit:
	yaca_free(nk);

	return ret;
}

static int generate_evp_pkey_params(int evp_id, size_t key_bit_len, EVP_PKEY **params)
{
	assert(key_bit_len > 0);
	assert(params != NULL);

	int ret;
	EVP_PKEY_CTX *pctx = NULL;
	int bit_len = 0;
	int dh_prime_len = 0;
	int dh_generator = 0;
	int dh_rfc5114 = 0;
	int ec_nid = 0;

	switch (evp_id) {
	case EVP_PKEY_DSA:
		if ((key_bit_len & YACA_KEYLEN_COMPONENT_TYPE_MASK) != YACA_KEYLEN_COMPONENT_TYPE_BITS ||
		    key_bit_len > INT_MAX || key_bit_len < 512 || key_bit_len % 64 != 0)
			return YACA_ERROR_INVALID_PARAMETER;

		bit_len = key_bit_len;

		break;
	case EVP_PKEY_DH:
		if ((key_bit_len & YACA_KEYLEN_COMPONENT_TYPE_MASK) == YACA_KEYLEN_COMPONENT_TYPE_DH) {
			size_t gen_block = key_bit_len & YACA_KEYLEN_COMPONENT_DH_GEN_MASK;
			size_t prime_len_block = key_bit_len & YACA_KEYLEN_COMPONENT_DH_PRIME_MASK;

			/* This is impossible now as we take only 16 bits,
			 * but for the sake of type safety */
			if (prime_len_block > INT_MAX)
				return YACA_ERROR_INVALID_PARAMETER;
			dh_prime_len = prime_len_block;

			if (gen_block == YACA_KEYLEN_COMPONENT_DH_GEN_2)
				dh_generator = 2;
			else if (gen_block == YACA_KEYLEN_COMPONENT_DH_GEN_5)
				dh_generator = 5;
			else
				return YACA_ERROR_INVALID_PARAMETER;

		} else if ((key_bit_len & YACA_KEYLEN_COMPONENT_TYPE_MASK) == YACA_KEYLEN_COMPONENT_TYPE_DH_RFC) {
			if (key_bit_len == YACA_KEY_LENGTH_DH_RFC_1024_160)
				dh_rfc5114 = 1; /* OpenSSL magic numbers */
			else if (key_bit_len == YACA_KEY_LENGTH_DH_RFC_2048_224)
				dh_rfc5114 = 2;
			else if (key_bit_len == YACA_KEY_LENGTH_DH_RFC_2048_256)
				dh_rfc5114 = 3;
			else
				return YACA_ERROR_INVALID_PARAMETER;

		} else {
			return YACA_ERROR_INVALID_PARAMETER;
		}

		break;
	case EVP_PKEY_EC:
		ret = convert_ec_to_nid(key_bit_len, &ec_nid);
		if (ret != YACA_ERROR_NONE)
			return ret;

		break;
	default:
		/* We shouldn't be here */
		assert(false);
		return YACA_ERROR_INTERNAL;
	}

	pctx = EVP_PKEY_CTX_new_id(evp_id, NULL);
	if (pctx == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	ret = EVP_PKEY_paramgen_init(pctx);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	switch (evp_id) {
	case EVP_PKEY_DSA:
		ret = EVP_PKEY_CTX_set_dsa_paramgen_bits(pctx, bit_len);
		break;
	case EVP_PKEY_DH:
		if (dh_rfc5114 > 0) {
			/* The following code is based on the macro call below.
			 * Unfortunately it doesn't work and the suspected reason is the
			 * fact that the _set_dh_ variant actually passes EVP_PKEY_DHX:
			 * ret = EVP_PKEY_CTX_set_dh_rfc5114(pctx, dh_rfc5114); */
			ret = EVP_PKEY_CTX_ctrl(pctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN,
			                        EVP_PKEY_CTRL_DH_RFC5114, dh_rfc5114, NULL);
		} else {
			ret = EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, dh_prime_len);
			if (ret == 1)
				ret = EVP_PKEY_CTX_set_dh_paramgen_generator(pctx, dh_generator);
		}
		break;
	case EVP_PKEY_EC:
		ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, ec_nid);
		if (ret == 1)
			ret = EVP_PKEY_CTX_set_ec_param_enc(pctx, OPENSSL_EC_NAMED_CURVE);
		break;
	}
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	ret = EVP_PKEY_paramgen(pctx, params);
	if (ret != 1 || params == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	ret = YACA_ERROR_NONE;

exit:
	EVP_PKEY_CTX_free(pctx);
	return ret;
}

static int generate_evp_pkey_key(int evp_id, size_t key_bit_len, EVP_PKEY *params, EVP_PKEY **key)
{
	assert(key != NULL);
	assert(key_bit_len > 0 || params != NULL);

	int ret;
	EVP_PKEY_CTX *kctx = NULL;

	switch (evp_id) {
	case EVP_PKEY_RSA:
		assert(params == NULL);
		kctx = EVP_PKEY_CTX_new_id(evp_id, NULL);
		break;
	case EVP_PKEY_DSA:
	case EVP_PKEY_DH:
	case EVP_PKEY_EC:
		if (params == NULL) {
			ret = generate_evp_pkey_params(evp_id, key_bit_len, &params);
			if (ret != YACA_ERROR_NONE)
				return ret;
		} else {
			EVP_PKEY_up_ref(params);
		}

		kctx = EVP_PKEY_CTX_new(params, NULL);
		break;
	default:
		assert(false);
		return YACA_ERROR_INTERNAL;
	}
	if (kctx == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	ret = EVP_PKEY_keygen_init(kctx);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	if (evp_id == EVP_PKEY_RSA) {
		if ((key_bit_len & YACA_KEYLEN_COMPONENT_TYPE_MASK) != YACA_KEYLEN_COMPONENT_TYPE_BITS ||
		    key_bit_len > INT_MAX || key_bit_len < 512 || key_bit_len % 8 != 0) {
			ret = YACA_ERROR_INVALID_PARAMETER;
			goto exit;
		}

		ret = EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, (int)key_bit_len);
		if (ret != 1) {
			ret = ERROR_HANDLE();
			goto exit;
		}
	}

	ret = EVP_PKEY_keygen(kctx, key);
	if (ret != 1 || key == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	ret = YACA_ERROR_NONE;

exit:
	EVP_PKEY_CTX_free(kctx);
	EVP_PKEY_free(params);
	return ret;
}

static int generate_evp(yaca_key_type_e out_type, size_t key_bit_len,
                        struct yaca_key_evp_s *params, struct yaca_key_evp_s **out)
{
	assert(out != NULL);
	assert(key_bit_len > 0 || params != NULL);

	int ret;
	int evp_id;
	EVP_PKEY *pkey_out = NULL;
	EVP_PKEY *pkey_params = NULL;

	if (params != NULL) {
		yaca_key_type_e key_type;
		yaca_key_type_e params_type = params->key.type;

		ret = convert_params_to_priv(params_type, &key_type);
		if (ret != YACA_ERROR_NONE)
			return ret;

		if (out_type != key_type)
			return YACA_ERROR_INVALID_PARAMETER;

		pkey_params = params->evp;
	}

	switch (out_type) {
	case YACA_KEY_TYPE_DSA_PARAMS:
	case YACA_KEY_TYPE_DH_PARAMS:
	case YACA_KEY_TYPE_EC_PARAMS:
		assert(params == NULL);
		ret = convert_params_to_evp_id(out_type, &evp_id);
		if (ret != YACA_ERROR_NONE)
			return ret;

		ret = generate_evp_pkey_params(evp_id, key_bit_len, &pkey_out);
		break;
	case YACA_KEY_TYPE_RSA_PRIV:
	case YACA_KEY_TYPE_DSA_PRIV:
	case YACA_KEY_TYPE_DH_PRIV:
	case YACA_KEY_TYPE_EC_PRIV:
		ret = convert_priv_to_evp_id(out_type, &evp_id);
		if (ret != YACA_ERROR_NONE)
			return ret;

		ret = generate_evp_pkey_key(evp_id, key_bit_len, pkey_params, &pkey_out);
		break;
	default:
		return YACA_ERROR_INVALID_PARAMETER;
	}
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = yaca_zalloc(sizeof(struct yaca_key_evp_s), (void**)out);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	(*out)->evp = pkey_out;
	pkey_out = NULL;

	ret = YACA_ERROR_NONE;

exit:
	EVP_PKEY_free(pkey_out);
	return ret;
}

struct yaca_key_simple_s *key_get_simple(const yaca_key_h key)
{
	struct yaca_key_simple_s *k;

	if (key == YACA_KEY_NULL)
		return NULL;

	switch (key->type) {
	case YACA_KEY_TYPE_SYMMETRIC:
	case YACA_KEY_TYPE_DES:
	case YACA_KEY_TYPE_IV:
		k = (struct yaca_key_simple_s *)key;

		/* sanity check */
		assert(k->bit_len != 0);
		assert(k->bit_len % 8 == 0);
		assert(k->d != NULL);

		return k;
	default:
		return NULL;
	}
}

struct yaca_key_evp_s *key_get_evp(const yaca_key_h key)
{
	struct yaca_key_evp_s *k;

	if (key == YACA_KEY_NULL)
		return NULL;

	switch (key->type) {
	case YACA_KEY_TYPE_RSA_PUB:
	case YACA_KEY_TYPE_RSA_PRIV:
	case YACA_KEY_TYPE_DSA_PUB:
	case YACA_KEY_TYPE_DSA_PRIV:
	case YACA_KEY_TYPE_DSA_PARAMS:
	case YACA_KEY_TYPE_DH_PUB:
	case YACA_KEY_TYPE_DH_PRIV:
	case YACA_KEY_TYPE_DH_PARAMS:
	case YACA_KEY_TYPE_EC_PUB:
	case YACA_KEY_TYPE_EC_PRIV:
	case YACA_KEY_TYPE_EC_PARAMS:
		k = (struct yaca_key_evp_s *)key;

		/* sanity check */
		assert(k->evp != NULL);

		return k;
	default:
		return NULL;
	}
}

static yaca_key_h key_copy_simple(const struct yaca_key_simple_s *key)
{
	int ret;
	assert(key != NULL);

	struct yaca_key_simple_s *copy;
	size_t size = sizeof(struct yaca_key_simple_s) + key->bit_len / 8;

	ret = yaca_zalloc(size, (void**)&copy);
	if (ret != YACA_ERROR_NONE)
		return YACA_KEY_NULL;

	memcpy(copy, key, size);
	return (yaca_key_h)copy;
}

static yaca_key_h key_copy_evp(const struct yaca_key_evp_s *key)
{
	int ret;
	assert(key != NULL);

	struct yaca_key_evp_s *copy = NULL;
	ret = yaca_zalloc(sizeof(struct yaca_key_evp_s), (void**)&copy);
	if (ret != YACA_ERROR_NONE)
		return YACA_KEY_NULL;

	/* raise the refcount */
	EVP_PKEY_up_ref(key->evp);

	copy->key.type = key->key.type;
	copy->evp = key->evp;
	return (yaca_key_h)copy;
}

yaca_key_h key_copy(const yaca_key_h key)
{
	struct yaca_key_simple_s *simple = key_get_simple(key);
	struct yaca_key_evp_s *evp = key_get_evp(key);

	if (simple != NULL)
		return key_copy_simple(simple);
	else if (evp != NULL)
		return key_copy_evp(evp);

	return YACA_KEY_NULL;
}

API int yaca_key_get_type(const yaca_key_h key, yaca_key_type_e *key_type)
{
	const struct yaca_key_s *lkey = (const struct yaca_key_s *)key;

	if (lkey == NULL || key_type == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	*key_type = lkey->type;
	return YACA_ERROR_NONE;
}

API int yaca_key_get_bit_length(const yaca_key_h key, size_t *key_bit_len)
{
	const struct yaca_key_simple_s *simple_key = key_get_simple(key);
	const struct yaca_key_evp_s *evp_key = key_get_evp(key);

	if (key_bit_len == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	if (simple_key != NULL) {
		*key_bit_len = simple_key->bit_len;
		return YACA_ERROR_NONE;
	}

	if (evp_key != NULL) {
		int ret;

		switch (evp_key->key.type) {
		case YACA_KEY_TYPE_RSA_PRIV:
		case YACA_KEY_TYPE_RSA_PUB:
		case YACA_KEY_TYPE_DSA_PRIV:
		case YACA_KEY_TYPE_DSA_PUB:
		case YACA_KEY_TYPE_DSA_PARAMS:
		case YACA_KEY_TYPE_DH_PRIV:
		case YACA_KEY_TYPE_DH_PUB:
		case YACA_KEY_TYPE_DH_PARAMS:
			ret = EVP_PKEY_bits(evp_key->evp);
			if (ret <= 0) {
				ret = YACA_ERROR_INTERNAL;
				ERROR_DUMP(ret);
				return ret;
			}

			*key_bit_len = ret;
			return YACA_ERROR_NONE;
		case YACA_KEY_TYPE_EC_PRIV:
		case YACA_KEY_TYPE_EC_PUB:
		case YACA_KEY_TYPE_EC_PARAMS: {
			assert(EVP_PKEY_type(EVP_PKEY_id(evp_key->evp)) == EVP_PKEY_EC);

			const EC_KEY *eck = EVP_PKEY_get0(evp_key->evp);
			const EC_GROUP *ecg = EC_KEY_get0_group(eck);
			int flags = EC_GROUP_get_asn1_flag(ecg);
			int nid;

			if (!(flags & OPENSSL_EC_NAMED_CURVE))
				/* This is case of a custom (not named) curve, that can happen when someone
				   imports such a key into YACA. There is nothing that can be returned here */
				return YACA_ERROR_INVALID_PARAMETER;

			nid = EC_GROUP_get_curve_name(ecg);
			return convert_nid_to_ec(nid, key_bit_len);
		}
		default:
			/* We shouldn't be here */
			assert(false);
			return YACA_ERROR_INTERNAL;
		}
	}

	return YACA_ERROR_INVALID_PARAMETER;
}

API int yaca_key_import(yaca_key_type_e key_type,
                        const char *password,
                        const char *data,
                        size_t data_len,
                        yaca_key_h *key)
{
	if (key == NULL || data == NULL || data_len == 0)
		return YACA_ERROR_INVALID_PARAMETER;

	/* allow an empty password, OpenSSL returns an error with "" */
	if (password != NULL && password[0] == '\0')
		password = NULL;

	switch (key_type) {
	case YACA_KEY_TYPE_SYMMETRIC:
	case YACA_KEY_TYPE_DES:
	case YACA_KEY_TYPE_IV:
		if (password != NULL)
			return YACA_ERROR_INVALID_PARAMETER;
		return import_simple(key, key_type, data, data_len);
	case YACA_KEY_TYPE_RSA_PUB:
	case YACA_KEY_TYPE_RSA_PRIV:
	case YACA_KEY_TYPE_DSA_PUB:
	case YACA_KEY_TYPE_DSA_PRIV:
	case YACA_KEY_TYPE_DSA_PARAMS:
	case YACA_KEY_TYPE_DH_PUB:
	case YACA_KEY_TYPE_DH_PRIV:
	case YACA_KEY_TYPE_DH_PARAMS:
	case YACA_KEY_TYPE_EC_PUB:
	case YACA_KEY_TYPE_EC_PRIV:
	case YACA_KEY_TYPE_EC_PARAMS:
		return import_evp(key, key_type, password, data, data_len);
	default:
		return YACA_ERROR_INVALID_PARAMETER;
	}
}

API int yaca_key_export(const yaca_key_h key,
                        yaca_key_format_e key_fmt,
                        yaca_key_file_format_e key_file_fmt,
                        const char *password,
                        char **data,
                        size_t *data_len)
{
	struct yaca_key_simple_s *simple_key = key_get_simple(key);
	struct yaca_key_evp_s *evp_key = key_get_evp(key);

	if (data == NULL || data_len == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	/* allow an empty password, OpenSSL returns an error with "" */
	if (password != NULL && password[0] == '\0')
		password = NULL;

	if (password != NULL && simple_key != NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	if (key_fmt == YACA_KEY_FORMAT_DEFAULT &&
	    key_file_fmt == YACA_KEY_FILE_FORMAT_RAW &&
	    simple_key != NULL)
		return export_simple_raw(simple_key, data, data_len);

	if (key_fmt == YACA_KEY_FORMAT_DEFAULT &&
	    key_file_fmt == YACA_KEY_FILE_FORMAT_BASE64 &&
	    simple_key != NULL)
		return export_simple_base64(simple_key, data, data_len);

	if (evp_key != NULL)
		return export_evp(evp_key, key_fmt, key_file_fmt,
		                  password, data, data_len);

	return YACA_ERROR_INVALID_PARAMETER;
}

API int yaca_key_generate(yaca_key_type_e key_type,
                          size_t key_bit_len,
                          yaca_key_h *key)
{
	int ret;
	struct yaca_key_simple_s *nk_simple = NULL;
	struct yaca_key_evp_s *nk_evp = NULL;

	if (key == NULL || key_bit_len == 0)
		return YACA_ERROR_INVALID_PARAMETER;

	switch (key_type) {
	case YACA_KEY_TYPE_SYMMETRIC:
	case YACA_KEY_TYPE_IV:
		ret = generate_simple(&nk_simple, key_bit_len);
		break;
	case YACA_KEY_TYPE_DES:
		ret = generate_simple_des(&nk_simple, key_bit_len);
		break;
	case YACA_KEY_TYPE_RSA_PRIV:
	case YACA_KEY_TYPE_DSA_PRIV:
	case YACA_KEY_TYPE_DSA_PARAMS:
	case YACA_KEY_TYPE_DH_PRIV:
	case YACA_KEY_TYPE_DH_PARAMS:
	case YACA_KEY_TYPE_EC_PRIV:
	case YACA_KEY_TYPE_EC_PARAMS:
		ret = generate_evp(key_type, key_bit_len, NULL, &nk_evp);
		break;
	default:
		return YACA_ERROR_INVALID_PARAMETER;
	}

	if (ret != YACA_ERROR_NONE)
		return ret;

	if (nk_simple != NULL) {
		nk_simple->key.type = key_type;
		*key = (yaca_key_h)nk_simple;
	} else if (nk_evp != NULL) {
		nk_evp->key.type = key_type;
		*key = (yaca_key_h)nk_evp;
	} else {
		assert(false);
	}

	return YACA_ERROR_NONE;
}

API int yaca_key_generate_from_parameters(const yaca_key_h params, yaca_key_h *prv_key)
{
	int ret;
	struct yaca_key_evp_s *evp_params = key_get_evp(params);
	yaca_key_type_e params_type;
	yaca_key_type_e key_type;
	struct yaca_key_evp_s *nk_evp = NULL;

	if (evp_params == NULL || prv_key == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = yaca_key_get_type(params, &params_type);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = convert_params_to_priv(params_type, &key_type);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = generate_evp(key_type, 0, evp_params, &nk_evp);
	if (ret != YACA_ERROR_NONE)
		return ret;

	assert(nk_evp != NULL);

	nk_evp->key.type = key_type;
	*prv_key = (yaca_key_h)nk_evp;

	return YACA_ERROR_NONE;
}

API int yaca_key_extract_public(const yaca_key_h prv_key, yaca_key_h *pub_key)
{
	int ret;
	struct yaca_key_evp_s *evp_key = key_get_evp(prv_key);
	struct yaca_key_evp_s *nk = NULL;
	yaca_key_type_e prv_type;
	yaca_key_type_e pub_type;
	BIO *mem = NULL;
	EVP_PKEY *pkey = NULL;

	if (evp_key == NULL || pub_key == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = yaca_key_get_type(prv_key, &prv_type);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = convert_priv_to_pub(prv_type, &pub_type);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = yaca_zalloc(sizeof(struct yaca_key_evp_s), (void**)&nk);
	if (ret != YACA_ERROR_NONE)
		return ret;

	mem = BIO_new(BIO_s_mem());
	if (mem == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	ret = i2d_PUBKEY_bio(mem, evp_key->evp);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	pkey = d2i_PUBKEY_bio(mem, NULL);
	if (pkey == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	BIO_free(mem);
	mem = NULL;

	nk->key.type = pub_type;
	nk->evp = pkey;
	pkey = NULL;
	*pub_key = (yaca_key_h)nk;
	nk = NULL;
	ret = YACA_ERROR_NONE;

exit:
	EVP_PKEY_free(pkey);
	BIO_free(mem);
	yaca_free(nk);

	return ret;
}

API int yaca_key_extract_parameters(const yaca_key_h key, yaca_key_h *params)
{
	int ret;
	struct yaca_key_evp_s *evp_key = key_get_evp(key);
	struct yaca_key_evp_s *nk = NULL;
	yaca_key_type_e key_type;
	yaca_key_type_e params_type;
	BIO *mem = NULL;
	EVP_PKEY *pkey = NULL;

	if (evp_key == NULL || params == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = yaca_key_get_type(key, &key_type);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = convert_priv_to_params(key_type, &params_type);
	if (ret != YACA_ERROR_NONE)
		ret = convert_pub_to_params(key_type, &params_type);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = yaca_zalloc(sizeof(struct yaca_key_evp_s), (void**)&nk);
	if (ret != YACA_ERROR_NONE)
		return ret;

	mem = BIO_new(BIO_s_mem());
	if (mem == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	ret = PEM_write_bio_Parameters(mem, evp_key->evp);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	pkey = PEM_read_bio_Parameters(mem, NULL);
	if (pkey == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	BIO_free(mem);
	mem = NULL;

	nk->key.type = params_type;
	nk->evp = pkey;
	pkey = NULL;
	*params = (yaca_key_h)nk;
	nk = NULL;
	ret = YACA_ERROR_NONE;

exit:
	EVP_PKEY_free(pkey);
	BIO_free(mem);
	yaca_free(nk);

	return ret;
}

API void yaca_key_destroy(yaca_key_h key)
{
	struct yaca_key_simple_s *simple_key = key_get_simple(key);
	struct yaca_key_evp_s *evp_key = key_get_evp(key);

	if (simple_key != NULL) {
		OPENSSL_cleanse(simple_key->d, simple_key->bit_len / 8);
		yaca_free(simple_key);
	}

	if (evp_key != NULL) {
		EVP_PKEY_free(evp_key->evp);
		yaca_free(evp_key);
	}
}

API int yaca_key_derive_dh(const yaca_key_h prv_key,
                           const yaca_key_h pub_key,
                           char **secret,
                           size_t *secret_len)
{
	int ret;
	struct yaca_key_evp_s *lprv_key = key_get_evp(prv_key);
	struct yaca_key_evp_s *lpub_key = key_get_evp(pub_key);
	EVP_PKEY_CTX *ctx;
	char *data = NULL;
	size_t data_len;

	if (lprv_key == NULL || lpub_key == NULL || secret == NULL || secret_len == NULL ||
	    (!(lprv_key->key.type == YACA_KEY_TYPE_DH_PRIV &&
	       lpub_key->key.type == YACA_KEY_TYPE_DH_PUB)
	    &&
	     !(lprv_key->key.type == YACA_KEY_TYPE_EC_PRIV &&
	       lpub_key->key.type == YACA_KEY_TYPE_EC_PUB)))
		return YACA_ERROR_INVALID_PARAMETER;

	ctx = EVP_PKEY_CTX_new(lprv_key->evp, NULL);
	if (ctx == NULL) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	ret = EVP_PKEY_derive_init(ctx);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	ret = EVP_PKEY_derive_set_peer(ctx, lpub_key->evp);
	if (ret != 1) {
		ret = ERROR_HANDLE();
		goto exit;
	}

	ret = EVP_PKEY_derive(ctx, NULL, &data_len);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	if (data_len == 0 || data_len > SIZE_MAX / 8) {
		ret = YACA_ERROR_INVALID_PARAMETER;
		goto exit;
	}

	ret = yaca_zalloc(data_len, (void**)&data);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	ret = EVP_PKEY_derive(ctx, (unsigned char*)data, &data_len);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	*secret = data;
	data = NULL;
	*secret_len = data_len;

	ret = YACA_ERROR_NONE;

exit:
	EVP_PKEY_CTX_free(ctx);
	yaca_free(data);
	return ret;
}

API int yaca_key_derive_kdf(yaca_kdf_e kdf,
                            yaca_digest_algorithm_e algo,
                            const char *secret,
                            size_t secret_len,
                            const char *info,
                            size_t info_len,
                            size_t key_material_len,
                            char **key_material)
{
	int ret;
	char *out = NULL;
	const EVP_MD *md;

	if (secret == NULL || secret_len == 0 ||
	    (info == NULL && info_len > 0) || (info != NULL && info_len == 0) ||
	    key_material_len == 0 || key_material == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	ret = yaca_zalloc(key_material_len, (void**)&out);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = digest_get_algorithm(algo, &md);
	if (ret != YACA_ERROR_NONE)
		goto exit;

	switch (kdf) {
	case YACA_KDF_X942:
		ret = DH_KDF_X9_42((unsigned char*)out, key_material_len,
		                   (unsigned char*)secret, secret_len,
		                   OBJ_nid2obj(NID_id_smime_alg_ESDH), (unsigned char*)info, info_len, md);
		if (ret != 1 || out == NULL) {
			ret = YACA_ERROR_INTERNAL;
			ERROR_DUMP(ret);
			goto exit;
		}
		break;
	case YACA_KDF_X962:
		ret = ECDH_KDF_X9_62((unsigned char*)out, key_material_len,
		                     (unsigned char*)secret, secret_len,
		                     (unsigned char*)info, info_len, md);
		if (ret != 1 || out == NULL) {
			ret = YACA_ERROR_INTERNAL;
			ERROR_DUMP(ret);
			goto exit;
		}
		break;
	default:
		ret = YACA_ERROR_INVALID_PARAMETER;
		goto exit;
	}

	*key_material = out;
	out = NULL;
	ret = YACA_ERROR_NONE;

exit:
	yaca_free(out);
	return ret;
}

API int yaca_key_derive_pbkdf2(const char *password,
                               const char *salt,
                               size_t salt_len,
                               size_t iterations,
                               yaca_digest_algorithm_e algo,
                               size_t key_bit_len,
                               yaca_key_h *key)
{
	const EVP_MD *md;
	struct yaca_key_simple_s *nk;
	size_t key_byte_len = key_bit_len / 8;
	int ret;

	if (password == NULL ||
	    (salt == NULL && salt_len > 0) || (salt != NULL && salt_len == 0) ||
	    iterations == 0 || key_bit_len == 0 || key == NULL)
		return YACA_ERROR_INVALID_PARAMETER;

	if (key_bit_len % 8) /* Key length must be multiple of 8-bit_len */
		return YACA_ERROR_INVALID_PARAMETER;

	if (iterations > INT_MAX) /* OpenSSL limitation */
		return YACA_ERROR_INVALID_PARAMETER;

	ret = digest_get_algorithm(algo, &md);
	if (ret != YACA_ERROR_NONE)
		return ret;

	ret = yaca_zalloc(sizeof(struct yaca_key_simple_s) + key_byte_len, (void**)&nk);
	if (ret != YACA_ERROR_NONE)
		return ret;

	nk->bit_len = key_bit_len;
	nk->key.type = YACA_KEY_TYPE_SYMMETRIC;

	ret = PKCS5_PBKDF2_HMAC(password, -1, (const unsigned char*)salt,
	                        salt_len, iterations, md, key_byte_len,
	                        (unsigned char*)nk->d);
	if (ret != 1) {
		ret = YACA_ERROR_INTERNAL;
		ERROR_DUMP(ret);
		goto exit;
	}

	*key = (yaca_key_h)nk;
	nk = NULL;
	ret = YACA_ERROR_NONE;
exit:
	yaca_free(nk);

	return ret;
}
