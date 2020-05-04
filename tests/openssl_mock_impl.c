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
 * @file openssl_mock_impl.c
 * @brief
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/err.h>

#include "openssl_mock_impl.h"


unsigned MOCK_fail_nth = 0;

static int BIO_reset_just_called = 0;
static void reset_conditions()
{
	BIO_reset_just_called = 0;
}

#define HANDLE_FUNCTION(FNAME, VALUE, COND)				\
	do {												\
		if (GET_BOOL_NAME(FNAME)) {						\
			GET_BOOL_NAME(FNAME) = 0;					\
			return VALUE;								\
		}												\
		if (COND) {										\
			reset_conditions();							\
			break;										\
		}												\
		reset_conditions();								\
		if (MOCK_fail_nth == 0) {						\
			break;										\
		}												\
		--MOCK_fail_nth;								\
		if (MOCK_fail_nth == 0) {						\
			return VALUE;								\
		}												\
	} while(0)


int GET_BOOL_NAME(open) = 0;
int MOCK_open(const char *pathname, int flags)
{
	HANDLE_FUNCTION(open, -1, 1);
	return open(pathname, flags);
}

int GET_BOOL_NAME(read) = 0;
ssize_t MOCK_read(int fd, void *buf, size_t count)
{
	HANDLE_FUNCTION(read, -1, 1);
	return read(fd, buf, count);
}

int GET_BOOL_NAME(BIO_flush) = 0;
int MOCK_BIO_flush(BIO *b)
{
	HANDLE_FUNCTION(BIO_flush, 0, 0);
	return BIO_flush(b);
}

int GET_BOOL_NAME(BIO_get_mem_data) = 0;
long MOCK_BIO_get_mem_data(BIO *b, char **pp)
{
	HANDLE_FUNCTION(BIO_get_mem_data, -1, 0);
	return BIO_get_mem_data(b, pp);
}

int GET_BOOL_NAME(BIO_new) = 0;
BIO *MOCK_BIO_new(const BIO_METHOD *type)
{
	HANDLE_FUNCTION(BIO_new, NULL, 0);
	return BIO_new(type);
}

int GET_BOOL_NAME(BIO_new_mem_buf) = 0;
BIO *MOCK_BIO_new_mem_buf(const void *buf, int len)
{
	HANDLE_FUNCTION(BIO_new_mem_buf, NULL, 0);
	return BIO_new_mem_buf(buf, len);
}

int GET_BOOL_NAME(BIO_read) = 0;
int MOCK_BIO_read(BIO *b, void *data, int dlen)
{
	HANDLE_FUNCTION(BIO_read, -1, 0);
	return BIO_read(b, data, dlen);
}

int GET_BOOL_NAME(BIO_reset) = 0;
int MOCK_BIO_reset(BIO *b)
{
	HANDLE_FUNCTION(BIO_reset, 0, 0);
	BIO_reset_just_called = 1;
	return BIO_reset(b);
}

int GET_BOOL_NAME(BIO_write) = 0;
int MOCK_BIO_write(BIO *b, const void *data, int dlen)
{
	HANDLE_FUNCTION(BIO_write, -1, 0);
	return BIO_write(b, data, dlen);
}

int GET_BOOL_NAME(CMAC_CTX_new) = 0;
CMAC_CTX *MOCK_CMAC_CTX_new(void)
{
	HANDLE_FUNCTION(CMAC_CTX_new, NULL, 0);
	return CMAC_CTX_new();
}

int GET_BOOL_NAME(CMAC_Init) = 0;
int MOCK_CMAC_Init(CMAC_CTX *ctx, const void *key, size_t keylen, const EVP_CIPHER *cipher, ENGINE *impl)
{
	HANDLE_FUNCTION(CMAC_Init, 0, 0);
	return CMAC_Init(ctx, key, keylen, cipher, impl);
}

int GET_BOOL_NAME(DES_random_key) = 0;
int MOCK_DES_random_key(DES_cblock *ret)
{
	HANDLE_FUNCTION(DES_random_key, 0, 0);
	return DES_random_key(ret);
}

int GET_BOOL_NAME(DH_KDF_X9_42) = 0;
int MOCK_DH_KDF_X9_42(unsigned char *out, size_t outlen, const unsigned char *Z, size_t Zlen, ASN1_OBJECT *key_oid, const unsigned char *ukm, size_t ukmlen, const EVP_MD *md)
{
	HANDLE_FUNCTION(DH_KDF_X9_42, 0, 0);
	return DH_KDF_X9_42(out, outlen, Z, Zlen, key_oid, ukm, ukmlen, md);
}

int GET_BOOL_NAME(ECDH_KDF_X9_62) = 0;
int MOCK_ECDH_KDF_X9_62(unsigned char *out, size_t outlen, const unsigned char *Z, size_t Zlen, const unsigned char *sinfo, size_t sinfolen, const EVP_MD *md)
{
	HANDLE_FUNCTION(ECDH_KDF_X9_62, 0, 0);
	return ECDH_KDF_X9_62(out, outlen, Z, Zlen, sinfo, sinfolen, md);
}

int GET_BOOL_NAME(EC_GROUP_get_asn1_flag) = 0;
int MOCK_EC_GROUP_get_asn1_flag(const EC_GROUP *group)
{
	HANDLE_FUNCTION(EC_GROUP_get_asn1_flag, 0, 0);
	return EC_GROUP_get_asn1_flag(group);
}

int GET_BOOL_NAME(EC_GROUP_get_curve_name) = 0;
int MOCK_EC_GROUP_get_curve_name(const EC_GROUP *group)
{
	HANDLE_FUNCTION(EC_GROUP_get_curve_name, 0, 0);
	return EC_GROUP_get_curve_name(group);
}

int GET_BOOL_NAME(EC_KEY_new) = 0;
EC_KEY *MOCK_EC_KEY_new()
{
	HANDLE_FUNCTION(EC_KEY_new, NULL, 0);
	return EC_KEY_new();
}

int GET_BOOL_NAME(EC_KEY_set_group) = 0;
int MOCK_EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group)
{
	HANDLE_FUNCTION(EC_KEY_set_group, 0, 0);
	return EC_KEY_set_group(key, group);
}

int GET_BOOL_NAME(EVP_CIPHER_CTX_block_size) = 0;
int MOCK_EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *ctx)
{
	HANDLE_FUNCTION(EVP_CIPHER_CTX_block_size, 0, 0);
	return EVP_CIPHER_CTX_block_size(ctx);
}

int GET_BOOL_NAME(EVP_CIPHER_CTX_cleanup) = 0;
int MOCK_EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *c)
{
	HANDLE_FUNCTION(EVP_CIPHER_CTX_cleanup, 0, 0);
	return EVP_CIPHER_CTX_cleanup(c);
}

int GET_BOOL_NAME(EVP_CIPHER_CTX_ctrl) = 0;
int MOCK_EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
	HANDLE_FUNCTION(EVP_CIPHER_CTX_ctrl, 0, 0);
	return EVP_CIPHER_CTX_ctrl(ctx, type, arg, ptr);
}

int GET_BOOL_NAME(EVP_CIPHER_CTX_new) = 0;
EVP_CIPHER_CTX *MOCK_EVP_CIPHER_CTX_new(void)
{
	HANDLE_FUNCTION(EVP_CIPHER_CTX_new, NULL, 0);
	return EVP_CIPHER_CTX_new();
}

int GET_BOOL_NAME(EVP_CIPHER_CTX_set_key_length) = 0;
int MOCK_EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen)
{
	HANDLE_FUNCTION(EVP_CIPHER_CTX_set_key_length, 0, 0);
	return EVP_CIPHER_CTX_set_key_length(x, keylen);
}

int GET_BOOL_NAME(EVP_CIPHER_CTX_set_padding) = 0;
int MOCK_EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad)
{
	HANDLE_FUNCTION(EVP_CIPHER_CTX_set_padding, 0, 0);
	return EVP_CIPHER_CTX_set_padding(c, pad);
}

int GET_BOOL_NAME(EVP_CIPHER_iv_length) = 0;
int MOCK_EVP_CIPHER_iv_length(const EVP_CIPHER *cipher)
{
	HANDLE_FUNCTION(EVP_CIPHER_iv_length, -1, 0);
	return EVP_CIPHER_iv_length(cipher);
}

int GET_BOOL_NAME(EVP_CipherFinal) = 0;
int MOCK_EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl)
{
	HANDLE_FUNCTION(EVP_CipherFinal, 0, 0);
	return EVP_CipherFinal(ctx, outm, outl);
}

int GET_BOOL_NAME(EVP_CipherInit_ex) = 0;
int MOCK_EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc)
{
	HANDLE_FUNCTION(EVP_CipherInit_ex, 0, 0);
	return EVP_CipherInit_ex(ctx, type, impl, key, iv, enc);
}

int GET_BOOL_NAME(EVP_CipherUpdate) = 0;
int MOCK_EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)
{
	HANDLE_FUNCTION(EVP_CipherUpdate, 0, 0);
	return EVP_CipherUpdate(ctx, out, outl, in, inl);
}

int GET_BOOL_NAME(EVP_DigestFinal_ex) = 0;
int MOCK_EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s)
{
	HANDLE_FUNCTION(EVP_DigestFinal_ex, 0, 0);
	return EVP_DigestFinal_ex(ctx, md, s);
}

int GET_BOOL_NAME(EVP_DigestInit) = 0;
int MOCK_EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type)
{
	HANDLE_FUNCTION(EVP_DigestInit, 0, 0);
	return EVP_DigestInit(ctx, type);
}

int GET_BOOL_NAME(EVP_DigestSignFinal) = 0;
int MOCK_EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen)
{
	HANDLE_FUNCTION(EVP_DigestSignFinal, 0, 0);
	return EVP_DigestSignFinal(ctx, sigret, siglen);
}

int GET_BOOL_NAME(EVP_DigestSignInit) = 0;
int MOCK_EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey)
{
	HANDLE_FUNCTION(EVP_DigestSignInit, 0, 0);
	return EVP_DigestSignInit(ctx, pctx, type, e, pkey);
}

int GET_BOOL_NAME(EVP_DigestSignUpdate) = 0;
int MOCK_EVP_DigestSignUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
{
	HANDLE_FUNCTION(EVP_DigestSignUpdate, 0, 0);
	return EVP_DigestSignUpdate(ctx, d, cnt);
}

int GET_BOOL_NAME(EVP_DigestUpdate) = 0;
int MOCK_EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
{
	HANDLE_FUNCTION(EVP_DigestUpdate, 0, 0);
	return EVP_DigestUpdate(ctx, d, cnt);
}

int GET_BOOL_NAME(EVP_DigestVerifyFinal) = 0;
int MOCK_EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen)
{
	HANDLE_FUNCTION(EVP_DigestVerifyFinal, -1, 0);
	return EVP_DigestVerifyFinal(ctx, sig, siglen);
}

int GET_BOOL_NAME(EVP_DigestVerifyInit) = 0;
int MOCK_EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey)
{
	HANDLE_FUNCTION(EVP_DigestVerifyInit, 0, 0);
	return EVP_DigestVerifyInit(ctx, pctx, type, e, pkey);
}

int GET_BOOL_NAME(EVP_DigestVerifyUpdate) = 0;
int MOCK_EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
{
	HANDLE_FUNCTION(EVP_DigestVerifyUpdate, 0, 0);
	return EVP_DigestVerifyUpdate(ctx, d, cnt);
}

int GET_BOOL_NAME(EVP_MD_CTX_create) = 0;
EVP_MD_CTX *MOCK_EVP_MD_CTX_create()
{
	HANDLE_FUNCTION(EVP_MD_CTX_create, NULL, 0);
	return EVP_MD_CTX_create();
}

int GET_BOOL_NAME(EVP_MD_CTX_pkey_ctx) = 0;
EVP_PKEY_CTX *MOCK_EVP_MD_CTX_pkey_ctx(const EVP_MD_CTX *ctx)
{
	HANDLE_FUNCTION(EVP_MD_CTX_pkey_ctx, NULL, 0);
	return EVP_MD_CTX_pkey_ctx(ctx);
}

int GET_BOOL_NAME(EVP_MD_CTX_size) = 0;
int MOCK_EVP_MD_CTX_size(const EVP_MD_CTX *ctx)
{
	HANDLE_FUNCTION(EVP_MD_CTX_size, 0, 0);
	return EVP_MD_CTX_size(ctx);
}

int GET_BOOL_NAME(EVP_PKEY_CTX_ctrl) = 0;
int MOCK_EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype, int cmd, int p1, void *p2)
{
	HANDLE_FUNCTION(EVP_PKEY_CTX_ctrl, 0, 0);
	return EVP_PKEY_CTX_ctrl(ctx, keytype, optype, cmd, p1, p2);
}

int GET_BOOL_NAME(EVP_PKEY_CTX_get0_pkey) = 0;
EVP_PKEY *MOCK_EVP_PKEY_CTX_get0_pkey(EVP_PKEY_CTX *ctx)
{
	HANDLE_FUNCTION(EVP_PKEY_CTX_get0_pkey, NULL, 0);
	return EVP_PKEY_CTX_get0_pkey(ctx);
}

int GET_BOOL_NAME(EVP_PKEY_CTX_new) = 0;
EVP_PKEY_CTX *MOCK_EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e)
{
	HANDLE_FUNCTION(EVP_PKEY_CTX_new, NULL, 0);
	return EVP_PKEY_CTX_new(pkey, e);
}

int GET_BOOL_NAME(EVP_PKEY_CTX_new_id) = 0;
EVP_PKEY_CTX *MOCK_EVP_PKEY_CTX_new_id(int id, ENGINE *e)
{
	HANDLE_FUNCTION(EVP_PKEY_CTX_new_id, NULL, 0);
	return EVP_PKEY_CTX_new_id(id, e);
}

int GET_BOOL_NAME(EVP_PKEY_CTX_set_dh_paramgen_generator) = 0;
int MOCK_EVP_PKEY_CTX_set_dh_paramgen_generator(EVP_PKEY_CTX *ctx, int gen)
{
	HANDLE_FUNCTION(EVP_PKEY_CTX_set_dh_paramgen_generator, 0, 0);
	return EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, gen);
}

int GET_BOOL_NAME(EVP_PKEY_CTX_set_dh_paramgen_prime_len) = 0;
int MOCK_EVP_PKEY_CTX_set_dh_paramgen_prime_len(EVP_PKEY_CTX *ctx, int len)
{
	HANDLE_FUNCTION(EVP_PKEY_CTX_set_dh_paramgen_prime_len, 0, 0);
	return EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, len);
}

int GET_BOOL_NAME(EVP_PKEY_CTX_set_dsa_paramgen_bits) = 0;
int MOCK_EVP_PKEY_CTX_set_dsa_paramgen_bits(EVP_PKEY_CTX *ctx, int nbits)
{
	HANDLE_FUNCTION(EVP_PKEY_CTX_set_dsa_paramgen_bits, 0, 0);
	return EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, nbits);
}

int GET_BOOL_NAME(EVP_PKEY_CTX_set_ec_param_enc) = 0;
int MOCK_EVP_PKEY_CTX_set_ec_param_enc(EVP_PKEY_CTX *ctx, int param_enc)
{
	HANDLE_FUNCTION(EVP_PKEY_CTX_set_ec_param_enc, 0, 0);
	return EVP_PKEY_CTX_set_ec_param_enc(ctx, param_enc);
}

int GET_BOOL_NAME(EVP_PKEY_CTX_set_ec_paramgen_curve_nid) = 0;
int MOCK_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid)
{
	HANDLE_FUNCTION(EVP_PKEY_CTX_set_ec_paramgen_curve_nid, 0, 0);
	return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
}

int GET_BOOL_NAME(EVP_PKEY_CTX_set_rsa_keygen_bits) = 0;
int MOCK_EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX *ctx, int mbits)
{
	HANDLE_FUNCTION(EVP_PKEY_CTX_set_rsa_keygen_bits, 0, 0);
	return EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, mbits);
}

int GET_BOOL_NAME(EVP_PKEY_CTX_set_rsa_padding) = 0;
int MOCK_EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad)
{
	HANDLE_FUNCTION(EVP_PKEY_CTX_set_rsa_padding, 0, 0);
	return EVP_PKEY_CTX_set_rsa_padding(ctx, pad);
}

int GET_BOOL_NAME(EVP_PKEY_assign) = 0;
int MOCK_EVP_PKEY_assign(EVP_PKEY *pkey, int type, void *key)
{
	HANDLE_FUNCTION(EVP_PKEY_assign, 0, 0);
	return EVP_PKEY_assign(pkey, type, key);
}

int GET_BOOL_NAME(EVP_PKEY_assign_DH) = 0;
int MOCK_EVP_PKEY_assign_DH(EVP_PKEY *pkey, DH *key)
{
	HANDLE_FUNCTION(EVP_PKEY_assign_DH, 0, 0);
	return EVP_PKEY_assign_DH(pkey, key);
}

int GET_BOOL_NAME(EVP_PKEY_assign_DSA) = 0;
int MOCK_EVP_PKEY_assign_DSA(EVP_PKEY *pkey, DSA *key)
{
	HANDLE_FUNCTION(EVP_PKEY_assign_DSA, 0, 0);
	return EVP_PKEY_assign_DSA(pkey, key);
}

int GET_BOOL_NAME(EVP_PKEY_assign_EC_KEY) = 0;
int MOCK_EVP_PKEY_assign_EC_KEY(EVP_PKEY *pkey, EC_KEY *key)
{
	HANDLE_FUNCTION(EVP_PKEY_assign_EC_KEY, 0, 0);
	return EVP_PKEY_assign_EC_KEY(pkey, key);
}

int GET_BOOL_NAME(EVP_PKEY_bits) = 0;
int MOCK_EVP_PKEY_bits(const EVP_PKEY *pkey)
{
	HANDLE_FUNCTION(EVP_PKEY_bits, 0, 0);
	return EVP_PKEY_bits(pkey);
}

int GET_BOOL_NAME(EVP_PKEY_decrypt_old) = 0;
int MOCK_EVP_PKEY_decrypt_old(unsigned char *dec_key, const unsigned char *enc_key, int enc_key_len, EVP_PKEY *private_key)
{
	HANDLE_FUNCTION(EVP_PKEY_decrypt_old, 0, 0);
	return EVP_PKEY_decrypt_old(dec_key, enc_key, enc_key_len, private_key);
}

int GET_BOOL_NAME(EVP_PKEY_derive) = 0;
int MOCK_EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
{
	HANDLE_FUNCTION(EVP_PKEY_derive, 0, 0);
	return EVP_PKEY_derive(ctx, key, keylen);
}

int GET_BOOL_NAME(EVP_PKEY_derive_init) = 0;
int MOCK_EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx)
{
	HANDLE_FUNCTION(EVP_PKEY_derive_init, 0, 0);
	return EVP_PKEY_derive_init(ctx);
}

int GET_BOOL_NAME(EVP_PKEY_derive_set_peer) = 0;
int MOCK_EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer)
{
	HANDLE_FUNCTION(EVP_PKEY_derive_set_peer, 0, 0);
	return EVP_PKEY_derive_set_peer(ctx, peer);
}

int GET_BOOL_NAME(EVP_PKEY_encrypt_old) = 0;
int MOCK_EVP_PKEY_encrypt_old(unsigned char *enc_key, const unsigned char *key, int key_len, EVP_PKEY *pub_key)
{
	HANDLE_FUNCTION(EVP_PKEY_encrypt_old, 0, 0);
	return EVP_PKEY_encrypt_old(enc_key, key, key_len, pub_key);
}

int GET_BOOL_NAME(EVP_PKEY_keygen) = 0;
int MOCK_EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)
{
	HANDLE_FUNCTION(EVP_PKEY_keygen, 0, 0);
	return EVP_PKEY_keygen(ctx, ppkey);
}

int GET_BOOL_NAME(EVP_PKEY_keygen_init) = 0;
int MOCK_EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx)
{
	HANDLE_FUNCTION(EVP_PKEY_keygen_init, 0, 0);
	return EVP_PKEY_keygen_init(ctx);
}

int GET_BOOL_NAME(EVP_PKEY_new) = 0;
EVP_PKEY *MOCK_EVP_PKEY_new()
{
	HANDLE_FUNCTION(EVP_PKEY_new, NULL, 0);
	return EVP_PKEY_new();
}

int GET_BOOL_NAME(EVP_PKEY_new_mac_key) = 0;
EVP_PKEY *MOCK_EVP_PKEY_new_mac_key(int type, ENGINE *e, const unsigned char *key, int keylen)
{
	HANDLE_FUNCTION(EVP_PKEY_new_mac_key, NULL, 0);
	return EVP_PKEY_new_mac_key(type, e, key, keylen);
}

int GET_BOOL_NAME(EVP_PKEY_paramgen) = 0;
int MOCK_EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)
{
	HANDLE_FUNCTION(EVP_PKEY_paramgen, 0, 0);
	return EVP_PKEY_paramgen(ctx, ppkey);
}

int GET_BOOL_NAME(EVP_PKEY_paramgen_init) = 0;
int MOCK_EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx)
{
	HANDLE_FUNCTION(EVP_PKEY_paramgen_init, 0, 0);
	return EVP_PKEY_paramgen_init(ctx);
}

int GET_BOOL_NAME(EVP_PKEY_size) = 0;
int MOCK_EVP_PKEY_size(EVP_PKEY *pkey)
{
	/* Cannot fail? */
	HANDLE_FUNCTION(EVP_PKEY_size, 0, 0);
	return EVP_PKEY_size(pkey);
}

int GET_BOOL_NAME(EVP_PKEY_up_ref) = 0;
int MOCK_EVP_PKEY_up_ref(EVP_PKEY *pkey)
{
	HANDLE_FUNCTION(EVP_PKEY_up_ref, 0, 0);
	return EVP_PKEY_up_ref(pkey);
}

int GET_BOOL_NAME(EVP_aes_128_cbc) = 0;
const EVP_CIPHER *MOCK_EVP_aes_128_cbc(void)
{
	HANDLE_FUNCTION(EVP_aes_128_cbc, NULL, 0);
	return EVP_aes_128_cbc();
}

int GET_BOOL_NAME(EVP_aes_128_ccm) = 0;
const EVP_CIPHER *MOCK_EVP_aes_128_ccm(void)
{
	HANDLE_FUNCTION(EVP_aes_128_ccm, NULL, 0);
	return EVP_aes_128_ccm();
}

#undef EVP_aes_128_cfb
int GET_BOOL_NAME(EVP_aes_128_cfb) = 0;
const EVP_CIPHER *MOCK_EVP_aes_128_cfb(void)
{
	HANDLE_FUNCTION(EVP_aes_128_cfb, NULL, 0);
	return EVP_aes_128_cfb128();
}

int GET_BOOL_NAME(EVP_aes_128_cfb1) = 0;
const EVP_CIPHER *MOCK_EVP_aes_128_cfb1(void)
{
	HANDLE_FUNCTION(EVP_aes_128_cfb1, NULL, 0);
	return EVP_aes_128_cfb1();
}

int GET_BOOL_NAME(EVP_aes_128_cfb8) = 0;
const EVP_CIPHER *MOCK_EVP_aes_128_cfb8(void)
{
	HANDLE_FUNCTION(EVP_aes_128_cfb8, NULL, 0);
	return EVP_aes_128_cfb8();
}

int GET_BOOL_NAME(EVP_aes_128_ctr) = 0;
const EVP_CIPHER *MOCK_EVP_aes_128_ctr(void)
{
	HANDLE_FUNCTION(EVP_aes_128_ctr, NULL, 0);
	return EVP_aes_128_ctr();
}

int GET_BOOL_NAME(EVP_aes_128_ecb) = 0;
const EVP_CIPHER *MOCK_EVP_aes_128_ecb(void)
{
	HANDLE_FUNCTION(EVP_aes_128_ecb, NULL, 0);
	return EVP_aes_128_ecb();
}

int GET_BOOL_NAME(EVP_aes_128_gcm) = 0;
const EVP_CIPHER *MOCK_EVP_aes_128_gcm(void)
{
	HANDLE_FUNCTION(EVP_aes_128_gcm, NULL, 0);
	return EVP_aes_128_gcm();
}

int GET_BOOL_NAME(EVP_aes_128_ofb) = 0;
const EVP_CIPHER *MOCK_EVP_aes_128_ofb(void)
{
	HANDLE_FUNCTION(EVP_aes_128_ofb, NULL, 0);
	return EVP_aes_128_ofb();
}

int GET_BOOL_NAME(EVP_aes_128_wrap) = 0;
const EVP_CIPHER *MOCK_EVP_aes_128_wrap(void)
{
	HANDLE_FUNCTION(EVP_aes_128_wrap, NULL, 0);
	return EVP_aes_128_wrap();
}

int GET_BOOL_NAME(EVP_aes_192_cbc) = 0;
const EVP_CIPHER *MOCK_EVP_aes_192_cbc(void)
{
	HANDLE_FUNCTION(EVP_aes_192_cbc, NULL, 0);
	return EVP_aes_192_cbc();
}

int GET_BOOL_NAME(EVP_aes_192_ccm) = 0;
const EVP_CIPHER *MOCK_EVP_aes_192_ccm(void)
{
	HANDLE_FUNCTION(EVP_aes_192_ccm, NULL, 0);
	return EVP_aes_192_ccm();
}

#undef EVP_aes_192_cfb
int GET_BOOL_NAME(EVP_aes_192_cfb) = 0;
const EVP_CIPHER *MOCK_EVP_aes_192_cfb(void)
{
	HANDLE_FUNCTION(EVP_aes_192_cfb, NULL, 0);
	return EVP_aes_192_cfb128();
}

int GET_BOOL_NAME(EVP_aes_192_cfb1) = 0;
const EVP_CIPHER *MOCK_EVP_aes_192_cfb1(void)
{
	HANDLE_FUNCTION(EVP_aes_192_cfb1, NULL, 0);
	return EVP_aes_192_cfb1();
}

int GET_BOOL_NAME(EVP_aes_192_cfb8) = 0;
const EVP_CIPHER *MOCK_EVP_aes_192_cfb8(void)
{
	HANDLE_FUNCTION(EVP_aes_192_cfb8, NULL, 0);
	return EVP_aes_192_cfb8();
}

int GET_BOOL_NAME(EVP_aes_192_ctr) = 0;
const EVP_CIPHER *MOCK_EVP_aes_192_ctr(void)
{
	HANDLE_FUNCTION(EVP_aes_192_ctr, NULL, 0);
	return EVP_aes_192_ctr();
}

int GET_BOOL_NAME(EVP_aes_192_ecb) = 0;
const EVP_CIPHER *MOCK_EVP_aes_192_ecb(void)
{
	HANDLE_FUNCTION(EVP_aes_192_ecb, NULL, 0);
	return EVP_aes_192_ecb();
}

int GET_BOOL_NAME(EVP_aes_192_gcm) = 0;
const EVP_CIPHER *MOCK_EVP_aes_192_gcm(void)
{
	HANDLE_FUNCTION(EVP_aes_192_gcm, NULL, 0);
	return EVP_aes_192_gcm();
}

int GET_BOOL_NAME(EVP_aes_192_ofb) = 0;
const EVP_CIPHER *MOCK_EVP_aes_192_ofb(void)
{
	HANDLE_FUNCTION(EVP_aes_192_ofb, NULL, 0);
	return EVP_aes_192_ofb();
}

int GET_BOOL_NAME(EVP_aes_192_wrap) = 0;
const EVP_CIPHER *MOCK_EVP_aes_192_wrap(void)
{
	HANDLE_FUNCTION(EVP_aes_192_wrap, NULL, 0);
	return EVP_aes_192_wrap();
}

int GET_BOOL_NAME(EVP_aes_256_cbc) = 0;
const EVP_CIPHER *MOCK_EVP_aes_256_cbc()
{
	HANDLE_FUNCTION(EVP_aes_256_cbc, NULL, 0);
	return EVP_aes_256_cbc();
}

int GET_BOOL_NAME(EVP_aes_256_ccm) = 0;
const EVP_CIPHER *MOCK_EVP_aes_256_ccm(void)
{
	HANDLE_FUNCTION(EVP_aes_256_ccm, NULL, 0);
	return EVP_aes_256_ccm();
}

#undef EVP_aes_256_cfb
int GET_BOOL_NAME(EVP_aes_256_cfb) = 0;
const EVP_CIPHER *MOCK_EVP_aes_256_cfb(void)
{
	HANDLE_FUNCTION(EVP_aes_256_cfb, NULL, 0);
	return EVP_aes_256_cfb128();
}

int GET_BOOL_NAME(EVP_aes_256_cfb1) = 0;
const EVP_CIPHER *MOCK_EVP_aes_256_cfb1(void)
{
	HANDLE_FUNCTION(EVP_aes_256_cfb1, NULL, 0);
	return EVP_aes_256_cfb1();
}

int GET_BOOL_NAME(EVP_aes_256_cfb8) = 0;
const EVP_CIPHER *MOCK_EVP_aes_256_cfb8(void)
{
	HANDLE_FUNCTION(EVP_aes_256_cfb8, NULL, 0);
	return EVP_aes_256_cfb8();
}

int GET_BOOL_NAME(EVP_aes_256_ctr) = 0;
const EVP_CIPHER *MOCK_EVP_aes_256_ctr(void)
{
	HANDLE_FUNCTION(EVP_aes_256_ctr, NULL, 0);
	return EVP_aes_256_ctr();
}

int GET_BOOL_NAME(EVP_aes_256_ecb) = 0;
const EVP_CIPHER *MOCK_EVP_aes_256_ecb(void)
{
	HANDLE_FUNCTION(EVP_aes_256_ecb, NULL, 0);
	return EVP_aes_256_ecb();
}

int GET_BOOL_NAME(EVP_aes_256_gcm) = 0;
const EVP_CIPHER *MOCK_EVP_aes_256_gcm(void)
{
	HANDLE_FUNCTION(EVP_aes_256_gcm, NULL, 0);
	return EVP_aes_256_gcm();
}

int GET_BOOL_NAME(EVP_aes_256_ofb) = 0;
const EVP_CIPHER *MOCK_EVP_aes_256_ofb(void)
{
	HANDLE_FUNCTION(EVP_aes_256_ofb, NULL, 0);
	return EVP_aes_256_ofb();
}

int GET_BOOL_NAME(EVP_aes_256_wrap) = 0;
const EVP_CIPHER *MOCK_EVP_aes_256_wrap(void)
{
	HANDLE_FUNCTION(EVP_aes_256_wrap, NULL, 0);
	return EVP_aes_256_wrap();
}

int GET_BOOL_NAME(EVP_cast5_cbc) = 0;
const EVP_CIPHER *MOCK_EVP_cast5_cbc(void)
{
	HANDLE_FUNCTION(EVP_cast5_cbc, NULL, 0);
	return EVP_cast5_cbc();
}

#undef EVP_cast5_cfb
int GET_BOOL_NAME(EVP_cast5_cfb) = 0;
const EVP_CIPHER *MOCK_EVP_cast5_cfb(void)
{
	HANDLE_FUNCTION(EVP_cast5_cfb, NULL, 0);
	return EVP_cast5_cfb64();
}

int GET_BOOL_NAME(EVP_cast5_ecb) = 0;
const EVP_CIPHER *MOCK_EVP_cast5_ecb(void)
{
	HANDLE_FUNCTION(EVP_cast5_ecb, NULL, 0);
	return EVP_cast5_ecb();
}

int GET_BOOL_NAME(EVP_cast5_ofb) = 0;
const EVP_CIPHER *MOCK_EVP_cast5_ofb(void)
{
	HANDLE_FUNCTION(EVP_cast5_ofb, NULL, 0);
	return EVP_cast5_ofb();
}

int GET_BOOL_NAME(EVP_des_cbc) = 0;
const EVP_CIPHER *MOCK_EVP_des_cbc(void)
{
	HANDLE_FUNCTION(EVP_des_cbc, NULL, 0);
	return EVP_des_cbc();
}

#undef EVP_des_cfb
int GET_BOOL_NAME(EVP_des_cfb) = 0;
const EVP_CIPHER *MOCK_EVP_des_cfb(void)
{
	HANDLE_FUNCTION(EVP_des_cfb, NULL, 0);
	return EVP_des_cfb64();
}

int GET_BOOL_NAME(EVP_des_cfb1) = 0;
const EVP_CIPHER *MOCK_EVP_des_cfb1(void)
{
	HANDLE_FUNCTION(EVP_des_cfb1, NULL, 0);
	return EVP_des_cfb1();
}

int GET_BOOL_NAME(EVP_des_cfb8) = 0;
const EVP_CIPHER *MOCK_EVP_des_cfb8(void)
{
	HANDLE_FUNCTION(EVP_des_cfb8, NULL, 0);
	return EVP_des_cfb8();
}

int GET_BOOL_NAME(EVP_des_ecb) = 0;
const EVP_CIPHER *MOCK_EVP_des_ecb(void)
{
	HANDLE_FUNCTION(EVP_des_ecb, NULL, 0);
	return EVP_des_ecb();
}

int GET_BOOL_NAME(EVP_des_ede3_cbc) = 0;
const EVP_CIPHER *MOCK_EVP_des_ede3_cbc(void)
{
	HANDLE_FUNCTION(EVP_des_ede3_cbc, NULL, 0);
	return EVP_des_ede3_cbc();
}

#undef EVP_des_ede3_cfb
int GET_BOOL_NAME(EVP_des_ede3_cfb) = 0;
const EVP_CIPHER *MOCK_EVP_des_ede3_cfb(void)
{
	HANDLE_FUNCTION(EVP_des_ede3_cfb, NULL, 0);
	return EVP_des_ede3_cfb64();
}

int GET_BOOL_NAME(EVP_des_ede3_cfb1) = 0;
const EVP_CIPHER *MOCK_EVP_des_ede3_cfb1(void)
{
	HANDLE_FUNCTION(EVP_des_ede3_cfb1, NULL, 0);
	return EVP_des_ede3_cfb1();
}

int GET_BOOL_NAME(EVP_des_ede3_cfb8) = 0;
const EVP_CIPHER *MOCK_EVP_des_ede3_cfb8(void)
{
	HANDLE_FUNCTION(EVP_des_ede3_cfb8, NULL, 0);
	return EVP_des_ede3_cfb8();
}

int GET_BOOL_NAME(EVP_des_ede3_ecb) = 0;
const EVP_CIPHER *MOCK_EVP_des_ede3_ecb(void)
{
	HANDLE_FUNCTION(EVP_des_ede3_ecb, NULL, 0);
	return EVP_des_ede3_ecb();
}

int GET_BOOL_NAME(EVP_des_ede3_ofb) = 0;
const EVP_CIPHER *MOCK_EVP_des_ede3_ofb(void)
{
	HANDLE_FUNCTION(EVP_des_ede3_ofb, NULL, 0);
	return EVP_des_ede3_ofb();
}

int GET_BOOL_NAME(EVP_des_ede3_wrap) = 0;
const EVP_CIPHER *MOCK_EVP_des_ede3_wrap(void)
{
	HANDLE_FUNCTION(EVP_des_ede3_wrap, NULL, 0);
	return EVP_des_ede3_wrap();
}

int GET_BOOL_NAME(EVP_des_ede_cbc) = 0;
const EVP_CIPHER *MOCK_EVP_des_ede_cbc(void)
{
	HANDLE_FUNCTION(EVP_des_ede_cbc, NULL, 0);
	return EVP_des_ede_cbc();
}

#undef EVP_des_ede_cfb
int GET_BOOL_NAME(EVP_des_ede_cfb) = 0;
const EVP_CIPHER *MOCK_EVP_des_ede_cfb(void)
{
	HANDLE_FUNCTION(EVP_des_ede_cfb, NULL, 0);
	return EVP_des_ede_cfb64();
}

int GET_BOOL_NAME(EVP_des_ede_ecb) = 0;
const EVP_CIPHER *MOCK_EVP_des_ede_ecb(void)
{
	HANDLE_FUNCTION(EVP_des_ede_ecb, NULL, 0);
	return EVP_des_ede_ecb();
}

int GET_BOOL_NAME(EVP_des_ede_ofb) = 0;
const EVP_CIPHER *MOCK_EVP_des_ede_ofb(void)
{
	HANDLE_FUNCTION(EVP_des_ede_ofb, NULL, 0);
	return EVP_des_ede_ofb();
}

int GET_BOOL_NAME(EVP_des_ofb) = 0;
const EVP_CIPHER *MOCK_EVP_des_ofb(void)
{
	HANDLE_FUNCTION(EVP_des_ofb, NULL, 0);
	return EVP_des_ofb();
}

int GET_BOOL_NAME(EVP_md5) = 0;
const EVP_MD *MOCK_EVP_md5(void)
{
	HANDLE_FUNCTION(EVP_md5, NULL, 0);
	return EVP_md5();
}

int GET_BOOL_NAME(EVP_rc2_cbc) = 0;
const EVP_CIPHER *MOCK_EVP_rc2_cbc(void)
{
	HANDLE_FUNCTION(EVP_rc2_cbc, NULL, 0);
	return EVP_rc2_cbc();
}

#undef EVP_rc2_cfb
int GET_BOOL_NAME(EVP_rc2_cfb) = 0;
const EVP_CIPHER *MOCK_EVP_rc2_cfb(void)
{
	HANDLE_FUNCTION(EVP_rc2_cfb, NULL, 0);
	return EVP_rc2_cfb64();
}

int GET_BOOL_NAME(EVP_rc2_ecb) = 0;
const EVP_CIPHER *MOCK_EVP_rc2_ecb(void)
{
	HANDLE_FUNCTION(EVP_rc2_ecb, NULL, 0);
	return EVP_rc2_ecb();
}

int GET_BOOL_NAME(EVP_rc2_ofb) = 0;
const EVP_CIPHER *MOCK_EVP_rc2_ofb(void)
{
	HANDLE_FUNCTION(EVP_rc2_ofb, NULL, 0);
	return EVP_rc2_ofb();
}

int GET_BOOL_NAME(EVP_rc4) = 0;
const EVP_CIPHER *MOCK_EVP_rc4(void)
{
	HANDLE_FUNCTION(EVP_rc4, NULL, 0);
	return EVP_rc4();
}

int GET_BOOL_NAME(EVP_sha1) = 0;
const EVP_MD *MOCK_EVP_sha1(void)
{
	HANDLE_FUNCTION(EVP_sha1, NULL, 0);
	return EVP_sha1();
}

int GET_BOOL_NAME(EVP_sha224) = 0;
const EVP_MD *MOCK_EVP_sha224(void)
{
	HANDLE_FUNCTION(EVP_sha224, NULL, 0);
	return EVP_sha224();
}

int GET_BOOL_NAME(EVP_sha256) = 0;
const EVP_MD *MOCK_EVP_sha256(void)
{
	HANDLE_FUNCTION(EVP_sha256, NULL, 0);
	return EVP_sha256();
}

int GET_BOOL_NAME(EVP_sha384) = 0;
const EVP_MD *MOCK_EVP_sha384(void)
{
	HANDLE_FUNCTION(EVP_sha384, NULL, 0);
	return EVP_sha384();
}

int GET_BOOL_NAME(EVP_sha512) = 0;
const EVP_MD *MOCK_EVP_sha512(void)
{
	HANDLE_FUNCTION(EVP_sha512, NULL, 0);
	return EVP_sha512();
}

int GET_BOOL_NAME(OPENSSL_malloc) = 0;
void *MOCK_OPENSSL_malloc(size_t num)
{
	HANDLE_FUNCTION(OPENSSL_malloc, NULL, 0);
	return OPENSSL_malloc(num);
}

int GET_BOOL_NAME(OPENSSL_realloc) = 0;
void *MOCK_OPENSSL_realloc(void *addr, size_t num)
{
	HANDLE_FUNCTION(OPENSSL_realloc, NULL, 0);
	return OPENSSL_realloc(addr, num);
}

int GET_BOOL_NAME(PEM_read_bio_PUBKEY) = 0;
EVP_PKEY *MOCK_PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u)
{
	HANDLE_FUNCTION(PEM_read_bio_PUBKEY, NULL, BIO_reset_just_called);
	return PEM_read_bio_PUBKEY(bp, x, cb, u);
}

int GET_BOOL_NAME(PEM_read_bio_Parameters) = 0;
EVP_PKEY *MOCK_PEM_read_bio_Parameters(BIO *bp, EVP_PKEY **x)
{
	HANDLE_FUNCTION(PEM_read_bio_Parameters, NULL, BIO_reset_just_called);
	return PEM_read_bio_Parameters(bp, x);
}

int GET_BOOL_NAME(PEM_read_bio_PrivateKey) = 0;
EVP_PKEY *MOCK_PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u)
{
	HANDLE_FUNCTION(PEM_read_bio_PrivateKey, NULL, BIO_reset_just_called);
	return PEM_read_bio_PrivateKey(bp, x, cb, u);
}

int GET_BOOL_NAME(PEM_read_bio_X509) = 0;
X509 *MOCK_PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u)
{
	HANDLE_FUNCTION(PEM_read_bio_X509, NULL, BIO_reset_just_called);
	return PEM_read_bio_X509(bp, x, cb, u);
}

int GET_BOOL_NAME(PEM_write_bio_PKCS8PrivateKey) = 0;
int MOCK_PEM_write_bio_PKCS8PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc, char *kstr, int klen, pem_password_cb *cb, void *u)
{
	HANDLE_FUNCTION(PEM_write_bio_PKCS8PrivateKey, 0, 0);
	return PEM_write_bio_PKCS8PrivateKey(bp, x, enc, kstr, klen, cb, u);
}

int GET_BOOL_NAME(PEM_write_bio_PUBKEY) = 0;
int MOCK_PEM_write_bio_PUBKEY(BIO *bp, EVP_PKEY *x)
{
	HANDLE_FUNCTION(PEM_write_bio_PUBKEY, 0, 0);
	return PEM_write_bio_PUBKEY(bp, x);
}

int GET_BOOL_NAME(PEM_write_bio_Parameters) = 0;
int MOCK_PEM_write_bio_Parameters(BIO *bp, EVP_PKEY *x)
{
	HANDLE_FUNCTION(PEM_write_bio_Parameters, 0, 0);
	return PEM_write_bio_Parameters(bp, x);
}

int GET_BOOL_NAME(PEM_write_bio_PrivateKey) = 0;
int MOCK_PEM_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u)
{
	HANDLE_FUNCTION(PEM_write_bio_PrivateKey, 0, 0);
	return PEM_write_bio_PrivateKey(bp, x, enc, kstr, klen, cb, u);
}

int GET_BOOL_NAME(PKCS5_PBKDF2_HMAC);
int MOCK_PKCS5_PBKDF2_HMAC(const char *pass, int passlen, const unsigned char *salt, int saltlen, int iter, const EVP_MD *digest, int keylen, unsigned char *out)
{
	HANDLE_FUNCTION(PKCS5_PBKDF2_HMAC, 0, 0);
	return PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iter, digest, keylen, out);
}

int GET_BOOL_NAME(RAND_bytes) = 0;
int MOCK_RAND_bytes(unsigned char *buf, int num)
{
	HANDLE_FUNCTION(RAND_bytes, 0, 0);
	return RAND_bytes(buf, num);
}

int GET_BOOL_NAME(RSA_private_decrypt) = 0;
int MOCK_RSA_private_decrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
	HANDLE_FUNCTION(RSA_private_decrypt, -1, 0);
	return RSA_private_decrypt(flen, from, to, rsa, padding);
}

int GET_BOOL_NAME(RSA_private_encrypt) = 0;
int MOCK_RSA_private_encrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
	HANDLE_FUNCTION(RSA_private_encrypt, -1, 0);
	return RSA_private_encrypt(flen, from, to, rsa, padding);
}

int GET_BOOL_NAME(RSA_public_decrypt) = 0;
int MOCK_RSA_public_decrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
	HANDLE_FUNCTION(RSA_public_decrypt, -1, 0);
	return RSA_public_decrypt(flen, from, to, rsa, padding);
}

int GET_BOOL_NAME(RSA_public_encrypt) = 0;
int MOCK_RSA_public_encrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
	HANDLE_FUNCTION(RSA_public_encrypt, -1, 0);
	return RSA_public_encrypt(flen, from, to, rsa, padding);
}

int GET_BOOL_NAME(X509_get_pubkey) = 0;
EVP_PKEY *MOCK_X509_get_pubkey(X509 *x)
{
	HANDLE_FUNCTION(X509_get_pubkey, NULL, 0);
	return X509_get_pubkey(x);
}

int GET_BOOL_NAME(d2i_DHparams_bio) = 0;
DH *MOCK_d2i_DHparams_bio(BIO *bp, DH **x)
{
	HANDLE_FUNCTION(d2i_DHparams_bio, NULL, BIO_reset_just_called);
	return d2i_DHparams_bio(bp, x);
}

int GET_BOOL_NAME(d2i_DSAparams_bio) = 0;
DSA *MOCK_d2i_DSAparams_bio(BIO *bp, DSA **x)
{
	HANDLE_FUNCTION(d2i_DSAparams_bio, NULL, BIO_reset_just_called);
	return d2i_DSAparams_bio(bp, x);
}

int GET_BOOL_NAME(d2i_ECPKParameters_bio) = 0;
EC_GROUP *MOCK_d2i_ECPKParameters_bio(BIO *bp, EC_GROUP **x)
{
	HANDLE_FUNCTION(d2i_ECPKParameters_bio, NULL, BIO_reset_just_called);
	return d2i_ECPKParameters_bio(bp, x);
}

int GET_BOOL_NAME(d2i_PKCS8PrivateKey_bio) = 0;
EVP_PKEY *MOCK_d2i_PKCS8PrivateKey_bio(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u)
{
	HANDLE_FUNCTION(d2i_PKCS8PrivateKey_bio, NULL, BIO_reset_just_called);
	return d2i_PKCS8PrivateKey_bio(bp, x, cb, u);
}

int GET_BOOL_NAME(d2i_PUBKEY_bio) = 0;
EVP_PKEY *MOCK_d2i_PUBKEY_bio(BIO *bp, EVP_PKEY **a)
{
	HANDLE_FUNCTION(d2i_PUBKEY_bio, NULL, BIO_reset_just_called);
	return d2i_PUBKEY_bio(bp, a);
}

int GET_BOOL_NAME(d2i_PrivateKey_bio) = 0;
EVP_PKEY *MOCK_d2i_PrivateKey_bio(BIO *bp, EVP_PKEY **a)
{
	HANDLE_FUNCTION(d2i_PrivateKey_bio, NULL, BIO_reset_just_called);
	return d2i_PrivateKey_bio(bp, a);
}

int GET_BOOL_NAME(d2i_X509_bio) = 0;
X509 *MOCK_d2i_X509_bio(BIO *bp, X509 **x509)
{
	HANDLE_FUNCTION(d2i_X509_bio, NULL, BIO_reset_just_called);
	return d2i_X509_bio(bp, x509);
}

int GET_BOOL_NAME(i2d_DHparams_bio) = 0;
int MOCK_i2d_DHparams_bio(BIO *bp, const DH *x)
{
	HANDLE_FUNCTION(i2d_DHparams_bio, 0, 0);
	return i2d_DHparams_bio(bp, x);
}

int GET_BOOL_NAME(i2d_DSAparams_bio) = 0;
int MOCK_i2d_DSAparams_bio(BIO *bp, const DSA *x)
{
	HANDLE_FUNCTION(i2d_DSAparams_bio, 0, 0);
	return i2d_DSAparams_bio(bp, x);
}

int GET_BOOL_NAME(i2d_ECPKParameters_bio) = 0;
int MOCK_i2d_ECPKParameters_bio(BIO *bp, const EC_GROUP *x)
{
	HANDLE_FUNCTION(i2d_ECPKParameters_bio, 0, 0);
	return i2d_ECPKParameters_bio(bp, x);
}

int GET_BOOL_NAME(i2d_PKCS8PrivateKey_bio) = 0;
int MOCK_i2d_PKCS8PrivateKey_bio(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc, char *kstr, int klen, pem_password_cb *cb, void *u)
{
	HANDLE_FUNCTION(i2d_PKCS8PrivateKey_bio, 0, 0);
	return i2d_PKCS8PrivateKey_bio(bp, x, enc, kstr, klen, cb, u);
}

int GET_BOOL_NAME(i2d_PUBKEY_bio) = 0;
int MOCK_i2d_PUBKEY_bio(BIO *bp, EVP_PKEY *pkey)
{
	HANDLE_FUNCTION(i2d_PUBKEY_bio, 0, 0);
	return i2d_PUBKEY_bio(bp, pkey);
}

int GET_BOOL_NAME(i2d_PrivateKey_bio) = 0;
int MOCK_i2d_PrivateKey_bio(BIO *bp, EVP_PKEY *pkey)
{
	HANDLE_FUNCTION(i2d_PrivateKey_bio, 0, 0);
	return i2d_PrivateKey_bio(bp, pkey);
}
