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
 * @file key.h
 * @brief
 */

#ifndef KEY_H
#define KEY_H

#include <stddef.h>
#include <yaca/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup  Key  Advanced API for the key and IV handling.
 *
 * TODO: extended description and examples.
 *
 * @{
 */

#define YACA_KEY_NULL ((yaca_key_h) NULL)

// TODO: We need a way to import keys encrypted with hw (or other) keys. New function like yaca_key_load or sth??

/**
 * @brief yaca_key_get_bits  Get key's length (in bits).
 *
 * @param[in] key  Key which length we return.
 *
 * @return negative on error or key length (in bits).
 */
int yaca_key_get_bits(const yaca_key_h key);

/**
 * @brief yaca_key_import  Imports a key.
 *
 * This function imports a key trying to match it to the key_type specified.
 * It should autodetect both, key format and file format.
 *
 * For symmetric, IV and DES keys RAW binary format and BASE64 encoded
 * binary format are supported.
 * For asymmetric keys PEM and DER file formats are supported.
 *
 * Asymmetric keys can be in PKCS#1 or SSleay key formats (for RSA and
 * DSA respectively). Asymmetric private keys can also be in PKCS#8
 * format. Additionally it is possible to import public RSA key from
 * X509 certificate.
 *
 * @param[out] key       Returned key (must be freed with yaca_key_free()).
 * @param[in]  key_type  Type of the key.
 * @param[in]  data      Blob containing the key.
 * @param[in]  data_len  Size of the blob.
 *
 * @return 0 on success, negative on error.
 * @see #yaca_key_type_e, yaca_key_export(), yaca_key_free()
 */
int yaca_key_import(yaca_key_h *key,
                    yaca_key_type_e key_type,
                    const char *data,
                    size_t data_len);

/**
 * @brief yaca_key_export  Exports a key to arbitrary format. Export may fail if key is HW-based.
 *
 * This function exports the key to an arbitrary key format and key file format.
 *
 * For key formats two values are allowed:
 * - #YACA_KEY_FORMAT_DEFAULT: this is the only option possible in case of symmetric keys (or IV),
 *                            for asymmetric keys it will choose PKCS#1 for RSA and SSLeay for DSA.
 * - #YACA_KEY_FORMAT_PKCS8:   this will only work for private asymmetric keys.
 *
 * The following file formats are supported:
 * - #YACA_KEY_FILE_FORMAT_RAW:    used only for symmetric, raw binary format
 * - #YACA_KEY_FILE_FORMAT_BASE64: used only for symmetric, BASE64 encoded binary form
 * - #YACA_KEY_FILE_FORMAT_PEM:    used only for asymmetric, PEM file format
 * - #YACA_KEY_FILE_FORMAT_DER:    used only for asymmetric, DER file format
 *
 * @param[in]  key           Key to be exported.
 * @param[in]  key_fmt       Format of the key.
 * @param[in]  key_file_fmt  Format of the key file.
 * @param[out] data          Data, allocated by the library, containing exported key
 *                           (must be freed with yaca_free()).
 * @param[out] data_len      Size of the output data.
 *
 * @return 0 on success, negative on error.
 * @see #yaca_key_fmt_e, #yaca_key_file_fmt_e, yaca_key_import(), yaca_key_free()
 */
int yaca_key_export(const yaca_key_h key,
                    yaca_key_fmt_e key_fmt,
                    yaca_key_file_fmt_e key_file_fmt,
                    char **data,
                    size_t *data_len);

/**
 * @brief yaca_key_gen  Generates a secure symmetric key (or an initialization vector).
 *
 * @param[out] sym_key   Newly generated key (must be freed with yaca_key_free()).
 * @param[in]  key_type  Type of the key to be generated.
 * @param[in]  key_bits  Length of the key (in bits) to be generated.
 *
 * @return 0 on success, negative on error.
 * @see #yaca_key_type_e, #yaca_key_bits_e, yaca_key_gen_pair(), yaca_key_free()
 */
int yaca_key_gen(yaca_key_h *sym_key,
                 yaca_key_type_e key_type,
                 size_t key_bits);

/**
 * @brief yaca_key_extract_public  Extracts public key from a private one.
 *
 * @param[in]  prv_key   Private key to extract the public one from.
 * @param[out] pub_key   Extracted public key (must be freed with yaca_key_free()).
 *
 * @return 0 on success, negative on error.
 * @see yaca_key_gen(), yaca_key_import(), yaca_key_free()
 */
int yaca_key_extract_public(const yaca_key_h prv_key, yaca_key_h *pub_key);

/**
 * @brief yaca_key_gen_pair  Generates a new key pair.
 *
 * @param[out] prv_key   Newly generated private key (must be freed with yaca_key_free()).
 * @param[out] pub_key   Newly generated public key (must be freed with yaca_key_free()).
 * @param[in]  key_type  Type of the key to be generated (must be YACA_KEY_TYPE_PAIR*).
 * @param[in]  key_bits  Length of the key (in bits) to be generated.
 *
 * @return 0 on success, negative on error.
 * @see #yaca_key_type_e, #yaca_key_bits_e, yaca_key_gen(), yaca_key_free()
 */
int yaca_key_gen_pair(yaca_key_h *prv_key,
                      yaca_key_h *pub_key,
                      yaca_key_type_e key_type,
                      size_t key_bits);

/**
 * @brief yaca_key_free  Frees the key created by the library.
 *                       Passing YACA_KEY_NULL is allowed.
 *
 * @param key  Key to be freed.
 * @see yaca_key_import(), yaca_key_export(), yaca_key_gen(), yaca_key_gen_pair()
 *
 */
void yaca_key_free(yaca_key_h key);

/**@}*/

/**
 * @defgroup  Key-Derivation  Advanced API for the key derivation.
 *
 * TODO: rethink separate group.
 * TODO: extended description and examples.
 *
 * @{
 */

/**
 * @brief yaca_key_derive_dh  Derives a key using Diffie-Helmann or EC Diffie-Helmann key exchange protocol.
 *
 * @param[in]  prv_key  Our private key.
 * @param[in]  pub_key  Peer public key.
 * @param[out] sym_key  Shared secret, that can be used as a symmetric key
 *                      (must be freed with yaca_key_free()).
 *
 * @return 0 on success, negative on error.
 */
int yaca_key_derive_dh(const yaca_key_h prv_key,
                       const yaca_key_h pub_key,
                       yaca_key_h *sym_key);

/**
 * @brief yaca_key_derive_kea  Derives a key using KEA key exchange protocol.
 *
 * @param[in]  prv_key       Our DH private component.
 * @param[in]  pub_key       Peers' DH public component.
 * @param[in]  prv_key_auth  Our private key used to create signature on our
 *                           DH public component sent to peer to verify our identity.
 * @param[in]  pub_key_auth  Peers' public key used for signature verification
 *                           of pub_key from peer (peer authentication).
 * @param[out] sym_key       Shared secret, that can be used as a symmetric key
 *                           (must be freed with yaca_key_free()).
 *
 * @return 0 on success, negative on error.
 */
int yaca_key_derive_kea(const yaca_key_h prv_key,
                        const yaca_key_h pub_key,
                        const yaca_key_h prv_key_auth,
                        const yaca_key_h pub_key_auth,
                        yaca_key_h *sym_key);

/**
 * @brief yaca_key_derive_pbkdf2  Derives a key from user password (PKCS #5 a.k.a. pbkdf2 algorithm).
 *
 * @param[in]  password  User password as a NULL-terminated string.
 * @param[in]  salt      Salt, should be non-zero.
 * @param[in]  salt_len  Length of the salt.
 * @param[in]  iter      Number of iterations. (TODO: add enum to proposed number of iterations, pick sane defaults).
 * @param[in]  algo      Digest algorithm that should be used in key generation. (TODO: sane defaults).
 * @param[in]  key_bits  Length of a key (in bits) to be generated.
 * @param[out] key       Newly generated key (must be freed with yaca_key_free()).
 *
 * @return 0 on success, negative on error.
 */
int yaca_key_derive_pbkdf2(const char *password,
                           const char *salt,
                           size_t salt_len,
                           int iter,
                           yaca_digest_algo_e algo,
                           size_t key_bits,
                           yaca_key_h *key);

// TODO: specify
//int yaca_key_wrap(yaca_key_h key, ??);
//int yaca_key_unwrap(yaca_key_h key, ??);

/**@}*/

#ifdef __cplusplus
} /* extern */
#endif

#endif /* KEY_H */
