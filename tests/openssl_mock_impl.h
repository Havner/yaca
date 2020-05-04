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
 * @file openssl_mock_impl.h
 * @brief
 */

#ifndef OPENSSL_MOCK_IMPL_H
#define OPENSSL_MOCK_IMPL_H

#include "openssl_mock_functions.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define GET_BOOL_NAME(FNAME) MOCK_fail_##FNAME

extern unsigned MOCK_fail_nth;

extern int GET_BOOL_NAME(open);
extern int GET_BOOL_NAME(read);
extern int GET_BOOL_NAME(BIO_flush);
extern int GET_BOOL_NAME(BIO_flush);
extern int GET_BOOL_NAME(BIO_get_mem_data);
extern int GET_BOOL_NAME(BIO_new);
extern int GET_BOOL_NAME(BIO_new_mem_buf);
extern int GET_BOOL_NAME(BIO_read);
extern int GET_BOOL_NAME(BIO_reset);
extern int GET_BOOL_NAME(BIO_write);
extern int GET_BOOL_NAME(CMAC_CTX_new);
extern int GET_BOOL_NAME(CMAC_Init);
extern int GET_BOOL_NAME(DES_random_key);
extern int GET_BOOL_NAME(DH_KDF_X9_42);
extern int GET_BOOL_NAME(ECDH_KDF_X9_62);
extern int GET_BOOL_NAME(EC_GROUP_get_asn1_flag);
extern int GET_BOOL_NAME(EC_GROUP_get_curve_name);
extern int GET_BOOL_NAME(EC_KEY_new);
extern int GET_BOOL_NAME(EC_KEY_set_group);
extern int GET_BOOL_NAME(EVP_CIPHER_CTX_block_size);
extern int GET_BOOL_NAME(EVP_CIPHER_CTX_cleanup);
extern int GET_BOOL_NAME(EVP_CIPHER_CTX_ctrl);
extern int GET_BOOL_NAME(EVP_CIPHER_CTX_new);
extern int GET_BOOL_NAME(EVP_CIPHER_CTX_set_key_length);
extern int GET_BOOL_NAME(EVP_CIPHER_CTX_set_padding);
extern int GET_BOOL_NAME(EVP_CIPHER_iv_length);
extern int GET_BOOL_NAME(EVP_CipherFinal);
extern int GET_BOOL_NAME(EVP_CipherUpdate);
extern int GET_BOOL_NAME(EVP_DigestFinal_ex);
extern int GET_BOOL_NAME(EVP_DigestInit);
extern int GET_BOOL_NAME(EVP_DigestSignFinal);
extern int GET_BOOL_NAME(EVP_DigestSignInit);
extern int GET_BOOL_NAME(EVP_DigestSignUpdate);
extern int GET_BOOL_NAME(EVP_DigestUpdate);
extern int GET_BOOL_NAME(EVP_DigestVerifyFinal);
extern int GET_BOOL_NAME(EVP_DigestVerifyInit);
extern int GET_BOOL_NAME(EVP_DigestVerifyUpdate);
extern int GET_BOOL_NAME(EVP_MD_CTX_create);
extern int GET_BOOL_NAME(EVP_MD_CTX_pkey_ctx);
extern int GET_BOOL_NAME(EVP_MD_CTX_size);
extern int GET_BOOL_NAME(EVP_PKEY_CTX_ctrl);
extern int GET_BOOL_NAME(EVP_PKEY_CTX_get0_pkey);
extern int GET_BOOL_NAME(EVP_PKEY_CTX_new);
extern int GET_BOOL_NAME(EVP_PKEY_CTX_new_id);
extern int GET_BOOL_NAME(EVP_PKEY_CTX_set_dh_paramgen_generator);
extern int GET_BOOL_NAME(EVP_PKEY_CTX_set_dh_paramgen_prime_len);
extern int GET_BOOL_NAME(EVP_PKEY_CTX_set_dsa_paramgen_bits);
extern int GET_BOOL_NAME(EVP_PKEY_CTX_set_ec_param_enc);
extern int GET_BOOL_NAME(EVP_PKEY_CTX_set_ec_paramgen_curve_nid);
extern int GET_BOOL_NAME(EVP_PKEY_CTX_set_rsa_keygen_bits);
extern int GET_BOOL_NAME(EVP_PKEY_CTX_set_rsa_padding);
extern int GET_BOOL_NAME(EVP_PKEY_assign);
extern int GET_BOOL_NAME(EVP_PKEY_assign_DH);
extern int GET_BOOL_NAME(EVP_PKEY_assign_DSA);
extern int GET_BOOL_NAME(EVP_PKEY_assign_EC_KEY);
extern int GET_BOOL_NAME(EVP_PKEY_bits);
extern int GET_BOOL_NAME(EVP_PKEY_decrypt_old);
extern int GET_BOOL_NAME(EVP_PKEY_derive);
extern int GET_BOOL_NAME(EVP_PKEY_derive_init);
extern int GET_BOOL_NAME(EVP_PKEY_derive_set_peer);
extern int GET_BOOL_NAME(EVP_PKEY_encrypt_old);
extern int GET_BOOL_NAME(EVP_PKEY_keygen);
extern int GET_BOOL_NAME(EVP_PKEY_keygen_init);
extern int GET_BOOL_NAME(EVP_PKEY_new);
extern int GET_BOOL_NAME(EVP_PKEY_new_mac_key);
extern int GET_BOOL_NAME(EVP_PKEY_paramgen);
extern int GET_BOOL_NAME(EVP_PKEY_paramgen_init);
extern int GET_BOOL_NAME(EVP_PKEY_size);
extern int GET_BOOL_NAME(EVP_PKEY_up_ref);
extern int GET_BOOL_NAME(EVP_aes_128_cbc);
extern int GET_BOOL_NAME(EVP_aes_128_ccm);
extern int GET_BOOL_NAME(EVP_aes_128_cfb);
extern int GET_BOOL_NAME(EVP_aes_128_cfb1);
extern int GET_BOOL_NAME(EVP_aes_128_cfb8);
extern int GET_BOOL_NAME(EVP_aes_128_ctr);
extern int GET_BOOL_NAME(EVP_aes_128_ecb);
extern int GET_BOOL_NAME(EVP_aes_128_gcm);
extern int GET_BOOL_NAME(EVP_aes_128_ofb);
extern int GET_BOOL_NAME(EVP_aes_128_wrap);
extern int GET_BOOL_NAME(EVP_aes_192_cbc);
extern int GET_BOOL_NAME(EVP_aes_192_ccm);
extern int GET_BOOL_NAME(EVP_aes_192_cfb);
extern int GET_BOOL_NAME(EVP_aes_192_cfb1);
extern int GET_BOOL_NAME(EVP_aes_192_cfb8);
extern int GET_BOOL_NAME(EVP_aes_192_ctr);
extern int GET_BOOL_NAME(EVP_aes_192_ecb);
extern int GET_BOOL_NAME(EVP_aes_192_gcm);
extern int GET_BOOL_NAME(EVP_aes_192_ofb);
extern int GET_BOOL_NAME(EVP_aes_192_wrap);
extern int GET_BOOL_NAME(EVP_aes_256_cbc);
extern int GET_BOOL_NAME(EVP_aes_256_ccm);
extern int GET_BOOL_NAME(EVP_aes_256_cfb);
extern int GET_BOOL_NAME(EVP_aes_256_cfb1);
extern int GET_BOOL_NAME(EVP_aes_256_cfb8);
extern int GET_BOOL_NAME(EVP_aes_256_ctr);
extern int GET_BOOL_NAME(EVP_aes_256_ecb);
extern int GET_BOOL_NAME(EVP_aes_256_gcm);
extern int GET_BOOL_NAME(EVP_aes_256_ofb);
extern int GET_BOOL_NAME(EVP_aes_256_wrap);
extern int GET_BOOL_NAME(EVP_cast5_cbc);
extern int GET_BOOL_NAME(EVP_cast5_cfb);
extern int GET_BOOL_NAME(EVP_cast5_ecb);
extern int GET_BOOL_NAME(EVP_cast5_ofb);
extern int GET_BOOL_NAME(EVP_des_cbc);
extern int GET_BOOL_NAME(EVP_des_cfb);
extern int GET_BOOL_NAME(EVP_des_cfb1);
extern int GET_BOOL_NAME(EVP_des_cfb8);
extern int GET_BOOL_NAME(EVP_des_ecb);
extern int GET_BOOL_NAME(EVP_des_ede3_cbc);
extern int GET_BOOL_NAME(EVP_des_ede3_cfb);
extern int GET_BOOL_NAME(EVP_des_ede3_cfb1);
extern int GET_BOOL_NAME(EVP_des_ede3_cfb8);
extern int GET_BOOL_NAME(EVP_des_ede3_ecb);
extern int GET_BOOL_NAME(EVP_des_ede3_ofb);
extern int GET_BOOL_NAME(EVP_des_ede3_wrap);
extern int GET_BOOL_NAME(EVP_des_ede_cbc);
extern int GET_BOOL_NAME(EVP_des_ede_cfb);
extern int GET_BOOL_NAME(EVP_des_ede_ecb);
extern int GET_BOOL_NAME(EVP_des_ede_ofb);
extern int GET_BOOL_NAME(EVP_des_ofb);
extern int GET_BOOL_NAME(EVP_md5);
extern int GET_BOOL_NAME(EVP_rc2_cbc);
extern int GET_BOOL_NAME(EVP_rc2_cfb);
extern int GET_BOOL_NAME(EVP_rc2_ecb);
extern int GET_BOOL_NAME(EVP_rc2_ofb);
extern int GET_BOOL_NAME(EVP_rc4);
extern int GET_BOOL_NAME(EVP_sha1);
extern int GET_BOOL_NAME(EVP_sha224);
extern int GET_BOOL_NAME(EVP_sha256);
extern int GET_BOOL_NAME(EVP_sha384);
extern int GET_BOOL_NAME(EVP_sha512);
extern int GET_BOOL_NAME(OPENSSL_malloc);
extern int GET_BOOL_NAME(OPENSSL_realloc);
extern int GET_BOOL_NAME(PEM_read_bio_PUBKEY);
extern int GET_BOOL_NAME(PEM_read_bio_Parameters);
extern int GET_BOOL_NAME(PEM_read_bio_PrivateKey);
extern int GET_BOOL_NAME(PEM_read_bio_X509);
extern int GET_BOOL_NAME(PEM_write_bio_PKCS8PrivateKey);
extern int GET_BOOL_NAME(PEM_write_bio_PUBKEY);
extern int GET_BOOL_NAME(PEM_write_bio_Parameters);
extern int GET_BOOL_NAME(PEM_write_bio_PrivateKey);
extern int GET_BOOL_NAME(PKCS5_PBKDF2_HMAC);
extern int GET_BOOL_NAME(RAND_bytes);
extern int GET_BOOL_NAME(RSA_private_decrypt);
extern int GET_BOOL_NAME(RSA_private_encrypt);
extern int GET_BOOL_NAME(RSA_public_decrypt);
extern int GET_BOOL_NAME(RSA_public_encrypt);
extern int GET_BOOL_NAME(X509_get_pubkey);
extern int GET_BOOL_NAME(d2i_DHparams_bio);
extern int GET_BOOL_NAME(d2i_DSAparams_bio);
extern int GET_BOOL_NAME(d2i_ECPKParameters_bio);
extern int GET_BOOL_NAME(d2i_PKCS8PrivateKey_bio);
extern int GET_BOOL_NAME(d2i_PUBKEY_bio);
extern int GET_BOOL_NAME(d2i_PrivateKey_bio);
extern int GET_BOOL_NAME(d2i_X509_bio);
extern int GET_BOOL_NAME(i2d_DHparams_bio);
extern int GET_BOOL_NAME(i2d_DSAparams_bio);
extern int GET_BOOL_NAME(i2d_ECPKParameters_bio);
extern int GET_BOOL_NAME(i2d_PKCS8PrivateKey_bio);
extern int GET_BOOL_NAME(i2d_PUBKEY_bio);
extern int GET_BOOL_NAME(i2d_PrivateKey_bio);

#ifdef  __cplusplus
}
#endif

#endif // OPENSSL_MOCK_IMPL_H
