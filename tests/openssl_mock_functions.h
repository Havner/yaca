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
 * @file openssl_mock_functions.h
 * @brief
 */

#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/cmac.h>
#include <openssl/crypto.h>
#include <openssl/des.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* Mockup declarations */
int MOCK_open(const char *pathname, int flags);
ssize_t MOCK_read(int fd, void *buf, size_t count);
int MOCK_BIO_flush(BIO *b);
long MOCK_BIO_get_mem_data(BIO *b, char **pp);
BIO *MOCK_BIO_new(const BIO_METHOD *type);
BIO *MOCK_BIO_new_mem_buf(const void *buf, int len);
int MOCK_BIO_read(BIO *b, void *data, int dlen);
int MOCK_BIO_reset(BIO *b);
int MOCK_BIO_write(BIO *b, const void *data, int dlen);
CMAC_CTX *MOCK_CMAC_CTX_new(void);
int MOCK_CMAC_Init(CMAC_CTX *ctx, const void *key, size_t keylen, const EVP_CIPHER *cipher, ENGINE *impl);
int MOCK_DES_random_key(DES_cblock *ret);
int MOCK_DH_KDF_X9_42(unsigned char *out, size_t outlen, const unsigned char *Z, size_t Zlen, ASN1_OBJECT *key_oid, const unsigned char *ukm, size_t ukmlen, const EVP_MD *md);
int MOCK_ECDH_KDF_X9_62(unsigned char *out, size_t outlen, const unsigned char *Z, size_t Zlen, const unsigned char *sinfo, size_t sinfolen, const EVP_MD *md);
int MOCK_EC_GROUP_get_asn1_flag(const EC_GROUP *group);
int MOCK_EC_GROUP_get_curve_name(const EC_GROUP *group);
EC_KEY *MOCK_EC_KEY_new(void);
int MOCK_EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group);
int MOCK_EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *ctx);
int MOCK_EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *c);
int MOCK_EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
EVP_CIPHER_CTX *MOCK_EVP_CIPHER_CTX_new(void);
int MOCK_EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
int MOCK_EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);
int MOCK_EVP_CIPHER_iv_length(const EVP_CIPHER *cipher);
int MOCK_EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
int MOCK_EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc);
int MOCK_EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
int MOCK_EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
int MOCK_EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
int MOCK_EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen);
int MOCK_EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int MOCK_EVP_DigestSignUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
int MOCK_EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
int MOCK_EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen);
int MOCK_EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int MOCK_EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
EVP_MD_CTX *MOCK_EVP_MD_CTX_create(void);
EVP_PKEY_CTX *MOCK_EVP_MD_CTX_pkey_ctx(const EVP_MD_CTX *ctx);
int MOCK_EVP_MD_CTX_size(const EVP_MD_CTX *ctx);
int MOCK_EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype, int cmd, int p1, void *p2);
EVP_PKEY *MOCK_EVP_PKEY_CTX_get0_pkey(EVP_PKEY_CTX *ctx);
EVP_PKEY_CTX *MOCK_EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);
EVP_PKEY_CTX *MOCK_EVP_PKEY_CTX_new_id(int id, ENGINE *e);
int MOCK_EVP_PKEY_CTX_set_dh_paramgen_generator(EVP_PKEY_CTX *ctx, int gen);
int MOCK_EVP_PKEY_CTX_set_dh_paramgen_prime_len(EVP_PKEY_CTX *ctx, int len);
int MOCK_EVP_PKEY_CTX_set_dsa_paramgen_bits(EVP_PKEY_CTX *ctx, int nbits);
int MOCK_EVP_PKEY_CTX_set_ec_param_enc(EVP_PKEY_CTX *ctx, int param_enc);
int MOCK_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid);
int MOCK_EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX *ctx, int mbits);
int MOCK_EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad);
int MOCK_EVP_PKEY_assign(EVP_PKEY *pkey, int type, void *key);
int MOCK_EVP_PKEY_assign_DH(EVP_PKEY *pkey, DH *key);
int MOCK_EVP_PKEY_assign_DSA(EVP_PKEY *pkey, DSA *key);
int MOCK_EVP_PKEY_assign_EC_KEY(EVP_PKEY *pkey, EC_KEY *key);
int MOCK_EVP_PKEY_bits(const EVP_PKEY *pkey);
int MOCK_EVP_PKEY_decrypt_old(unsigned char *dec_key, const unsigned char *enc_key, int enc_key_len, EVP_PKEY *private_key);
int MOCK_EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
int MOCK_EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx);
int MOCK_EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer);
int MOCK_EVP_PKEY_encrypt_old(unsigned char *enc_key, const unsigned char *key, int key_len, EVP_PKEY *pub_key);
int MOCK_EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
int MOCK_EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);
EVP_PKEY *MOCK_EVP_PKEY_new(void);
EVP_PKEY *MOCK_EVP_PKEY_new_mac_key(int type, ENGINE *e, const unsigned char *key, int keylen);
int MOCK_EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
int MOCK_EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx);
int MOCK_EVP_PKEY_size(EVP_PKEY *pkey);
int MOCK_EVP_PKEY_up_ref(EVP_PKEY *pkey);
const EVP_CIPHER *MOCK_EVP_aes_128_cbc(void);
const EVP_CIPHER *MOCK_EVP_aes_128_ccm(void);
const EVP_CIPHER *MOCK_EVP_aes_128_cfb(void);
const EVP_CIPHER *MOCK_EVP_aes_128_cfb1(void);
const EVP_CIPHER *MOCK_EVP_aes_128_cfb8(void);
const EVP_CIPHER *MOCK_EVP_aes_128_ctr(void);
const EVP_CIPHER *MOCK_EVP_aes_128_ecb(void);
const EVP_CIPHER *MOCK_EVP_aes_128_gcm(void);
const EVP_CIPHER *MOCK_EVP_aes_128_ofb(void);
const EVP_CIPHER *MOCK_EVP_aes_128_wrap(void);
const EVP_CIPHER *MOCK_EVP_aes_192_cbc(void);
const EVP_CIPHER *MOCK_EVP_aes_192_ccm(void);
const EVP_CIPHER *MOCK_EVP_aes_192_cfb(void);
const EVP_CIPHER *MOCK_EVP_aes_192_cfb1(void);
const EVP_CIPHER *MOCK_EVP_aes_192_cfb8(void);
const EVP_CIPHER *MOCK_EVP_aes_192_ctr(void);
const EVP_CIPHER *MOCK_EVP_aes_192_ecb(void);
const EVP_CIPHER *MOCK_EVP_aes_192_gcm(void);
const EVP_CIPHER *MOCK_EVP_aes_192_ofb(void);
const EVP_CIPHER *MOCK_EVP_aes_192_wrap(void);
const EVP_CIPHER *MOCK_EVP_aes_256_cbc(void);
const EVP_CIPHER *MOCK_EVP_aes_256_ccm(void);
const EVP_CIPHER *MOCK_EVP_aes_256_cfb(void);
const EVP_CIPHER *MOCK_EVP_aes_256_cfb1(void);
const EVP_CIPHER *MOCK_EVP_aes_256_cfb8(void);
const EVP_CIPHER *MOCK_EVP_aes_256_ctr(void);
const EVP_CIPHER *MOCK_EVP_aes_256_ecb(void);
const EVP_CIPHER *MOCK_EVP_aes_256_gcm(void);
const EVP_CIPHER *MOCK_EVP_aes_256_ofb(void);
const EVP_CIPHER *MOCK_EVP_aes_256_wrap(void);
const EVP_CIPHER *MOCK_EVP_cast5_cbc(void);
const EVP_CIPHER *MOCK_EVP_cast5_cfb(void);
const EVP_CIPHER *MOCK_EVP_cast5_ecb(void);
const EVP_CIPHER *MOCK_EVP_cast5_ofb(void);
const EVP_CIPHER *MOCK_EVP_des_cbc(void);
const EVP_CIPHER *MOCK_EVP_des_cfb(void);
const EVP_CIPHER *MOCK_EVP_des_cfb1(void);
const EVP_CIPHER *MOCK_EVP_des_cfb8(void);
const EVP_CIPHER *MOCK_EVP_des_ecb(void);
const EVP_CIPHER *MOCK_EVP_des_ede3_cbc(void);
const EVP_CIPHER *MOCK_EVP_des_ede3_cfb(void);
const EVP_CIPHER *MOCK_EVP_des_ede3_cfb1(void);
const EVP_CIPHER *MOCK_EVP_des_ede3_cfb8(void);
const EVP_CIPHER *MOCK_EVP_des_ede3_ecb(void);
const EVP_CIPHER *MOCK_EVP_des_ede3_ofb(void);
const EVP_CIPHER *MOCK_EVP_des_ede3_wrap(void);
const EVP_CIPHER *MOCK_EVP_des_ede_cbc(void);
const EVP_CIPHER *MOCK_EVP_des_ede_cfb(void);
const EVP_CIPHER *MOCK_EVP_des_ede_ecb(void);
const EVP_CIPHER *MOCK_EVP_des_ede_ofb(void);
const EVP_CIPHER *MOCK_EVP_des_ofb(void);
const EVP_MD *MOCK_EVP_md5(void);
const EVP_CIPHER *MOCK_EVP_rc2_cbc(void);
const EVP_CIPHER *MOCK_EVP_rc2_cfb(void);
const EVP_CIPHER *MOCK_EVP_rc2_ecb(void);
const EVP_CIPHER *MOCK_EVP_rc2_ofb(void);
const EVP_CIPHER *MOCK_EVP_rc4(void);
const EVP_MD *MOCK_EVP_sha1(void);
const EVP_MD *MOCK_EVP_sha224(void);
const EVP_MD *MOCK_EVP_sha256(void);
const EVP_MD *MOCK_EVP_sha384(void);
const EVP_MD *MOCK_EVP_sha512(void);
void *MOCK_OPENSSL_malloc(size_t num);
void *MOCK_OPENSSL_realloc(void *addr, size_t num);
EVP_PKEY *MOCK_PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);
EVP_PKEY *MOCK_PEM_read_bio_Parameters(BIO *bp, EVP_PKEY **x);
EVP_PKEY *MOCK_PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);
X509 *MOCK_PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u);
int MOCK_PEM_write_bio_PKCS8PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc, char *kstr, int klen, pem_password_cb *cb, void *u);
int MOCK_PEM_write_bio_PUBKEY(BIO *bp, EVP_PKEY *x);
int MOCK_PEM_write_bio_Parameters(BIO *bp, EVP_PKEY *x);
int MOCK_PEM_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u);
int MOCK_PKCS5_PBKDF2_HMAC(const char *pass, int passlen, const unsigned char *salt, int saltlen, int iter, const EVP_MD *digest, int keylen, unsigned char *out);
int MOCK_RAND_bytes(unsigned char *buf, int num);
int MOCK_RSA_private_decrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
int MOCK_RSA_private_encrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
int MOCK_RSA_public_decrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
int MOCK_RSA_public_encrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
EVP_PKEY *MOCK_X509_get_pubkey(X509 *x);
DH *MOCK_d2i_DHparams_bio(BIO *bp, DH **x);
DSA *MOCK_d2i_DSAparams_bio(BIO *bp, DSA **x);
EC_GROUP *MOCK_d2i_ECPKParameters_bio(BIO *bp, EC_GROUP **x);
EVP_PKEY *MOCK_d2i_PKCS8PrivateKey_bio(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);
EVP_PKEY *MOCK_d2i_PUBKEY_bio(BIO *bp, EVP_PKEY **a);
EVP_PKEY *MOCK_d2i_PrivateKey_bio(BIO *bp, EVP_PKEY **a);
X509 *MOCK_d2i_X509_bio(BIO *bp, X509 **x509);
int MOCK_i2d_DHparams_bio(BIO *bp, const DH *x);
int MOCK_i2d_DSAparams_bio(BIO *bp, const DSA *x);
int MOCK_i2d_ECPKParameters_bio(BIO *bp, const EC_GROUP *x);
int MOCK_i2d_PKCS8PrivateKey_bio(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc, char *kstr, int klen, pem_password_cb *cb, void *u);
int MOCK_i2d_PUBKEY_bio(BIO *bp, EVP_PKEY *pkey);
int MOCK_i2d_PrivateKey_bio(BIO *bp, EVP_PKEY *pkey);

#ifdef  __cplusplus
}
#endif
