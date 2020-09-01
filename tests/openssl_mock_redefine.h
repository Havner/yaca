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
 * @file openssl_mock_redefine.h
 * @brief
 */

/* This file is to be included in the source files that want to mockup
 * OpenSSL and libc. After OpenSSL and libc headers. E.g.

 #include <openssl/...>
 #include <unistd.h>

 #ifdef OPENSSL_MOCKUP
 #include "../tests/openssl_mock_redefine.h"
 #endif

*/

#include "openssl_mock_functions.h"

#define open(a, b) MOCK_open(a, b)
#define read(a, b, c) MOCK_read(a, b, c)
#undef BIO_flush
#define BIO_flush(a) MOCK_BIO_flush(a)
#undef BIO_get_mem_data
#define BIO_get_mem_data(a, b) MOCK_BIO_get_mem_data(a, (char **)b)
#define BIO_new(a) MOCK_BIO_new(a)
#define BIO_new_mem_buf(a, b) MOCK_BIO_new_mem_buf(a, b)
#define BIO_read(a, b, c) MOCK_BIO_read(a, b, c)
#undef BIO_reset
#define BIO_reset(a) MOCK_BIO_reset(a)
#define BIO_write(a, b, c) MOCK_BIO_write(a, b, c)
#define CMAC_CTX_new() MOCK_CMAC_CTX_new()
#define CMAC_Init(a, b, c, d, e) MOCK_CMAC_Init(a, b, c, d, e)
#define DES_random_key(a) MOCK_DES_random_key(a)
#define DH_KDF_X9_42(a, b, c, d, e, f, g, h) MOCK_DH_KDF_X9_42(a, b, c, d, e, f, g, h)
#define ECDH_KDF_X9_62(a, b, c, d, e, f, g) MOCK_ECDH_KDF_X9_62(a, b, c, d, e, f, g)
#define EC_GROUP_get_asn1_flag(a) MOCK_EC_GROUP_get_asn1_flag(a)
#define EC_GROUP_get_curve_name(a) MOCK_EC_GROUP_get_curve_name(a)
#define EC_KEY_new() MOCK_EC_KEY_new()
#define EC_KEY_set_group(a, b) MOCK_EC_KEY_set_group(a, b)
#define EVP_CIPHER_CTX_block_size(a) MOCK_EVP_CIPHER_CTX_block_size(a)
#undef EVP_CIPHER_CTX_cleanup
#define EVP_CIPHER_CTX_cleanup(a) MOCK_EVP_CIPHER_CTX_cleanup(a)
#define EVP_CIPHER_CTX_ctrl(a, b, c, d) MOCK_EVP_CIPHER_CTX_ctrl(a, b, c, d)
#define EVP_CIPHER_CTX_new() MOCK_EVP_CIPHER_CTX_new()
#define EVP_CIPHER_CTX_set_key_length(a, b) MOCK_EVP_CIPHER_CTX_set_key_length(a, b)
#define EVP_CIPHER_CTX_set_padding(a, b) MOCK_EVP_CIPHER_CTX_set_padding(a, b)
#define EVP_CIPHER_iv_length(a) MOCK_EVP_CIPHER_iv_length(a)
#define EVP_CipherFinal(a, b, c) MOCK_EVP_CipherFinal(a, b, c)
#define EVP_CipherInit_ex(a, b, c, d, e, f) MOCK_EVP_CipherInit_ex(a, b, c, d, e, f)
#define EVP_CipherUpdate(a, b, c, d, e) MOCK_EVP_CipherUpdate(a, b, c, d, e)
#define EVP_DigestFinal_ex(a, b, c) MOCK_EVP_DigestFinal_ex(a, b, c)
#define EVP_DigestInit(a, b) MOCK_EVP_DigestInit(a, b)
#define EVP_DigestSignFinal(a, b, c) MOCK_EVP_DigestSignFinal(a, b, c)
#define EVP_DigestSignInit(a, b, c, d, e) MOCK_EVP_DigestSignInit(a, b, c, d, e)
#undef EVP_DigestSignUpdate
#define EVP_DigestSignUpdate(a, b, c) MOCK_EVP_DigestSignUpdate(a, b, c)
#undef EVP_DigestUpdate
#define EVP_DigestUpdate(a, b, c) MOCK_EVP_DigestUpdate(a, b, c)
#define EVP_DigestVerifyFinal(a, b, c) MOCK_EVP_DigestVerifyFinal(a, b, c)
#define EVP_DigestVerifyInit(a, b, c, d, e) MOCK_EVP_DigestVerifyInit(a, b, c, d, e)
#undef EVP_DigestVerifyUpdate
#define EVP_DigestVerifyUpdate(a, b, c) MOCK_EVP_DigestVerifyUpdate(a, b, c)
#undef EVP_MD_CTX_create
#define EVP_MD_CTX_create() MOCK_EVP_MD_CTX_create()
#define EVP_MD_CTX_pkey_ctx(a) MOCK_EVP_MD_CTX_pkey_ctx(a)
#undef EVP_MD_CTX_size
#define EVP_MD_CTX_size(a) MOCK_EVP_MD_CTX_size(a)
#define EVP_PKEY_CTX_ctrl(a, b, c, d, e, f) MOCK_EVP_PKEY_CTX_ctrl(a, b, c, d, e, f)
#define EVP_PKEY_CTX_get0_pkey(a) MOCK_EVP_PKEY_CTX_get0_pkey(a)
#define EVP_PKEY_CTX_new(a, b) MOCK_EVP_PKEY_CTX_new(a, b)
#define EVP_PKEY_CTX_new_id(a, b) MOCK_EVP_PKEY_CTX_new_id(a, b)
#undef EVP_PKEY_CTX_set_dh_paramgen_generator
#define EVP_PKEY_CTX_set_dh_paramgen_generator(a, b) MOCK_EVP_PKEY_CTX_set_dh_paramgen_generator(a, b)
#undef EVP_PKEY_CTX_set_dh_paramgen_prime_len
#define EVP_PKEY_CTX_set_dh_paramgen_prime_len(a, b) MOCK_EVP_PKEY_CTX_set_dh_paramgen_prime_len(a, b)
#undef EVP_PKEY_CTX_set_dsa_paramgen_bits
#define EVP_PKEY_CTX_set_dsa_paramgen_bits(a, b) MOCK_EVP_PKEY_CTX_set_dsa_paramgen_bits(a, b)
#undef EVP_PKEY_CTX_set_ec_param_enc
#define EVP_PKEY_CTX_set_ec_param_enc(a, b) MOCK_EVP_PKEY_CTX_set_ec_param_enc(a, b)
#undef EVP_PKEY_CTX_set_ec_paramgen_curve_nid
#define EVP_PKEY_CTX_set_ec_paramgen_curve_nid(a, b) MOCK_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(a, b)
#undef EVP_PKEY_CTX_set_rsa_keygen_bits
#define EVP_PKEY_CTX_set_rsa_keygen_bits(a, b) MOCK_EVP_PKEY_CTX_set_rsa_keygen_bits(a, b)
#undef EVP_PKEY_CTX_set_rsa_padding
#define EVP_PKEY_CTX_set_rsa_padding(a, b) MOCK_EVP_PKEY_CTX_set_rsa_padding(a, b)
#define EVP_PKEY_assign(a, b, c) MOCK_EVP_PKEY_assign(a, b, c)
#undef EVP_PKEY_assign_DH
#define EVP_PKEY_assign_DH(a, b) MOCK_EVP_PKEY_assign_DH(a, b)
#undef EVP_PKEY_assign_DSA
#define EVP_PKEY_assign_DSA(a, b) MOCK_EVP_PKEY_assign_DSA(a, b)
#undef EVP_PKEY_assign_EC_KEY
#define EVP_PKEY_assign_EC_KEY(a, b) MOCK_EVP_PKEY_assign_EC_KEY(a, b)
#define EVP_PKEY_bits(a) MOCK_EVP_PKEY_bits(a)
#define EVP_PKEY_decrypt_old(a, b, c, d) MOCK_EVP_PKEY_decrypt_old(a, b, c, d)
#define EVP_PKEY_derive(a, b, c) MOCK_EVP_PKEY_derive(a, b, c)
#define EVP_PKEY_derive_init(a) MOCK_EVP_PKEY_derive_init(a)
#define EVP_PKEY_derive_set_peer(a, b) MOCK_EVP_PKEY_derive_set_peer(a, b)
#define EVP_PKEY_encrypt_old(a, b, c, d) MOCK_EVP_PKEY_encrypt_old(a, b, c, d)
#define EVP_PKEY_keygen(a, b) MOCK_EVP_PKEY_keygen(a, b)
#define EVP_PKEY_keygen_init(a) MOCK_EVP_PKEY_keygen_init(a)
#define EVP_PKEY_new() MOCK_EVP_PKEY_new()
#define EVP_PKEY_new_mac_key(a, b, c, d) MOCK_EVP_PKEY_new_mac_key(a, b, c, d)
#define EVP_PKEY_paramgen(a, b) MOCK_EVP_PKEY_paramgen(a, b)
#define EVP_PKEY_paramgen_init(a) MOCK_EVP_PKEY_paramgen_init(a)
#define EVP_PKEY_size(a) MOCK_EVP_PKEY_size(a)
#define EVP_PKEY_up_ref(a) MOCK_EVP_PKEY_up_ref(a)
/* Special cases for algorithms, used as function pointers in YACA */
#define EVP_aes_128_cbc MOCK_EVP_aes_128_cbc
#define EVP_aes_128_ccm MOCK_EVP_aes_128_ccm
#undef EVP_aes_128_cfb
#define EVP_aes_128_cfb MOCK_EVP_aes_128_cfb
#define EVP_aes_128_cfb1 MOCK_EVP_aes_128_cfb1
#define EVP_aes_128_cfb8 MOCK_EVP_aes_128_cfb8
#define EVP_aes_128_ctr MOCK_EVP_aes_128_ctr
#define EVP_aes_128_ecb MOCK_EVP_aes_128_ecb
#define EVP_aes_128_gcm MOCK_EVP_aes_128_gcm
#define EVP_aes_128_ofb MOCK_EVP_aes_128_ofb
#define EVP_aes_128_wrap MOCK_EVP_aes_128_wrap
#define EVP_aes_192_cbc MOCK_EVP_aes_192_cbc
#define EVP_aes_192_ccm MOCK_EVP_aes_192_ccm
#undef EVP_aes_192_cfb
#define EVP_aes_192_cfb MOCK_EVP_aes_192_cfb
#define EVP_aes_192_cfb1 MOCK_EVP_aes_192_cfb1
#define EVP_aes_192_cfb8 MOCK_EVP_aes_192_cfb8
#define EVP_aes_192_ctr MOCK_EVP_aes_192_ctr
#define EVP_aes_192_ecb MOCK_EVP_aes_192_ecb
#define EVP_aes_192_gcm MOCK_EVP_aes_192_gcm
#define EVP_aes_192_ofb MOCK_EVP_aes_192_ofb
#define EVP_aes_192_wrap MOCK_EVP_aes_192_wrap
#define EVP_aes_256_cbc MOCK_EVP_aes_256_cbc
#define EVP_aes_256_ccm MOCK_EVP_aes_256_ccm
#undef EVP_aes_256_cfb
#define EVP_aes_256_cfb MOCK_EVP_aes_256_cfb
#define EVP_aes_256_cfb1 MOCK_EVP_aes_256_cfb1
#define EVP_aes_256_cfb8 MOCK_EVP_aes_256_cfb8
#define EVP_aes_256_ctr MOCK_EVP_aes_256_ctr
#define EVP_aes_256_ecb MOCK_EVP_aes_256_ecb
#define EVP_aes_256_gcm MOCK_EVP_aes_256_gcm
#define EVP_aes_256_ofb MOCK_EVP_aes_256_ofb
#define EVP_aes_256_wrap MOCK_EVP_aes_256_wrap
#define EVP_cast5_cbc MOCK_EVP_cast5_cbc
#undef EVP_cast5_cfb
#define EVP_cast5_cfb MOCK_EVP_cast5_cfb
#define EVP_cast5_ecb MOCK_EVP_cast5_ecb
#define EVP_cast5_ofb MOCK_EVP_cast5_ofb
#define EVP_des_cbc MOCK_EVP_des_cbc
#undef EVP_des_cfb
#define EVP_des_cfb MOCK_EVP_des_cfb
#define EVP_des_cfb1 MOCK_EVP_des_cfb1
#define EVP_des_cfb8 MOCK_EVP_des_cfb8
#define EVP_des_ecb MOCK_EVP_des_ecb
#define EVP_des_ede3_cbc MOCK_EVP_des_ede3_cbc
#undef EVP_des_ede3_cfb
#define EVP_des_ede3_cfb MOCK_EVP_des_ede3_cfb
#define EVP_des_ede3_cfb1 MOCK_EVP_des_ede3_cfb1
#define EVP_des_ede3_cfb8 MOCK_EVP_des_ede3_cfb8
#define EVP_des_ede3_ecb MOCK_EVP_des_ede3_ecb
#define EVP_des_ede3_ofb MOCK_EVP_des_ede3_ofb
#define EVP_des_ede3_wrap MOCK_EVP_des_ede3_wrap
#define EVP_des_ede_cbc MOCK_EVP_des_ede_cbc
#undef EVP_des_ede_cfb
#define EVP_des_ede_cfb MOCK_EVP_des_ede_cfb
#define EVP_des_ede_ecb MOCK_EVP_des_ede_ecb
#define EVP_des_ede_ofb MOCK_EVP_des_ede_ofb
#define EVP_des_ofb MOCK_EVP_des_ofb
#define EVP_md5 MOCK_EVP_md5
#define EVP_rc2_cbc MOCK_EVP_rc2_cbc
#undef EVP_rc2_cfb
#define EVP_rc2_cfb MOCK_EVP_rc2_cfb
#define EVP_rc2_ecb MOCK_EVP_rc2_ecb
#define EVP_rc2_ofb MOCK_EVP_rc2_ofb
#define EVP_rc4 MOCK_EVP_rc4
#define EVP_sha1 MOCK_EVP_sha1
#define EVP_sha224 MOCK_EVP_sha224
#define EVP_sha256 MOCK_EVP_sha256
#define EVP_sha384 MOCK_EVP_sha384
#define EVP_sha512 MOCK_EVP_sha512
#undef OPENSSL_malloc
#define OPENSSL_malloc(a) MOCK_OPENSSL_malloc(a)
#undef OPENSSL_realloc
#define OPENSSL_realloc(a, b) MOCK_OPENSSL_realloc(a, b)
#define PEM_read_bio_PUBKEY(a, b, c, d) MOCK_PEM_read_bio_PUBKEY(a, b, c, d)
#define PEM_read_bio_Parameters(a, b) MOCK_PEM_read_bio_Parameters(a, b)
#define PEM_read_bio_PrivateKey(a, b, c, d) MOCK_PEM_read_bio_PrivateKey(a, b, c, d)
#define PEM_read_bio_X509(a, b, c, d) MOCK_PEM_read_bio_X509(a, b, c, d)
#define PEM_write_bio_PKCS8PrivateKey(a, b, c, d, e, f, g) MOCK_PEM_write_bio_PKCS8PrivateKey(a, b, c, d, e, f, g)
#define PEM_write_bio_PUBKEY(a, b) MOCK_PEM_write_bio_PUBKEY(a, b)
#define PEM_write_bio_Parameters(a, b) MOCK_PEM_write_bio_Parameters(a, b)
#define PEM_write_bio_PrivateKey(a, b, c, d, e, f, g) MOCK_PEM_write_bio_PrivateKey(a, b, c, d, e, f, g)
#define PKCS5_PBKDF2_HMAC(a, b, c, d, e, f, g, h) MOCK_PKCS5_PBKDF2_HMAC(a, b, c, d, e, f, g, h)
#define RAND_bytes(a, b) MOCK_RAND_bytes(a, b)
/* 4 Special cases, used as function pointers in YACA */
#define RSA_private_decrypt MOCK_RSA_private_decrypt
#define RSA_private_encrypt MOCK_RSA_private_encrypt
#define RSA_public_decrypt MOCK_RSA_public_decrypt
#define RSA_public_encrypt MOCK_RSA_public_encrypt
#define X509_get_pubkey(a) MOCK_X509_get_pubkey(a)
#undef d2i_DHparams_bio
#define d2i_DHparams_bio(a, b) MOCK_d2i_DHparams_bio(a, b)
#undef d2i_DSAparams_bio
#define d2i_DSAparams_bio(a, b) MOCK_d2i_DSAparams_bio(a, b)
#undef d2i_ECPKParameters_bio
#define d2i_ECPKParameters_bio(a, b) MOCK_d2i_ECPKParameters_bio(a, b)
#define d2i_PKCS8PrivateKey_bio(a, b, c, d) MOCK_d2i_PKCS8PrivateKey_bio(a, b, c, d)
#define d2i_PUBKEY_bio(a, b) MOCK_d2i_PUBKEY_bio(a, b)
#define d2i_PrivateKey_bio(a, b) MOCK_d2i_PrivateKey_bio(a, b)
#define d2i_X509_bio(a, b) MOCK_d2i_X509_bio(a, b)
#undef i2d_DHparams_bio
#define i2d_DHparams_bio(a, b) MOCK_i2d_DHparams_bio(a, b)
#undef i2d_DSAparams_bio
#define i2d_DSAparams_bio(a, b) MOCK_i2d_DSAparams_bio(a, b)
#undef i2d_ECPKParameters_bio
#define i2d_ECPKParameters_bio(a, b) MOCK_i2d_ECPKParameters_bio(a, b)
#define i2d_PKCS8PrivateKey_bio(a, b, c, d, e, f, g) MOCK_i2d_PKCS8PrivateKey_bio(a, b, c, d, e, f, g)
#define i2d_PUBKEY_bio(a, b) MOCK_i2d_PUBKEY_bio(a, b)
#define i2d_PrivateKey_bio(a, b) MOCK_i2d_PrivateKey_bio(a, b)
