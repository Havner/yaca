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
 * @file types.h
 * @brief
 */

#ifndef TYPES_H
#define TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup Crypto-Types Yet Another Crypto API - types.
 *
 * TODO: extended description.
 *
 * @{
 */

/**
 * @brief Context
 */
typedef struct yaca_ctx_s *yaca_ctx_h;

/**
 * @brief Key
 */
typedef struct yaca_key_s *yaca_key_h;

/**
 * @brief Key formats
 */
typedef enum {
	YACA_KEY_FORMAT_DEFAULT,  /**< key is either PKCS#1 for RSA or SSLeay for DSA, also use this option for symmetric */
	YACA_KEY_FORMAT_PKCS8     /**< key is in PKCS#8, can only be used for asymmetric private keys */
} yaca_key_fmt_e;

/**
 * @brief Key file formats
 */
typedef enum {
	YACA_KEY_FILE_FORMAT_RAW,      /**< key file is in raw binary format, used for symmetric keys */
	YACA_KEY_FILE_FORMAT_BASE64,   /**< key file is encoded in ASCII-base64, used for symmetric keys */
	YACA_KEY_FILE_FORMAT_PEM,      /**< key file is in PEM file format, used for asymmetric keys */
	YACA_KEY_FILE_FORMAT_DER       /**< key file is in DER file format, used for asymmetric keys */
} yaca_key_file_fmt_e;

/**
 * @brief Key types, IV is considered as key
 */
typedef enum {
	YACA_KEY_TYPE_SYMMETRIC,   /**< Generic symmetric cipher KEY */
	YACA_KEY_TYPE_DES,         /**< DES* key - must be handled differently because of parity bits */
	YACA_KEY_TYPE_IV,          /**< Initialization Vector for symmetric algorithms */

	YACA_KEY_TYPE_RSA_PUB,     /**< RSA public key */
	YACA_KEY_TYPE_RSA_PRIV,    /**< RSA private key */

	YACA_KEY_TYPE_DSA_PUB,     /**< Digital Signature Algorithm public key */
	YACA_KEY_TYPE_DSA_PRIV,    /**< Digital Signature Algorithm private key */

	YACA_KEY_TYPE_DH_PUB,      /**< Diffie-Hellman public key */
	YACA_KEY_TYPE_DH_PRIV,     /**< Diffie-Hellman private key */

	YACA_KEY_TYPE_ECDSA_PUB,   /**< Elliptic Curve Digital Signature Algorithm public key */
	YACA_KEY_TYPE_ECDSA_PRIV,  /**< Elliptic Curve Digital Signature Algorithm private key */

	// TODO: ECDH might not exist as a separate key type, remove?
	YACA_KEY_TYPE_ECDH_PUB,    /**< Elliptic Curve Diffie-Hellman public key */
	YACA_KEY_TYPE_ECDH_PRIV,   /**< Elliptic Curve Diffie-Hellman private key */
} yaca_key_type_e;

/**
 * @brief Key length, It is possible to use arbitrary integer instead, this enums are placed here to avoid magic numbers.
 */
typedef enum {
	YACA_KEY_IV_UNSAFE_24BIT = 24,    /**< 24-bit IV */
	YACA_KEY_IV_64BIT = 64,           /**< 64-bit IV */
	YACA_KEY_IV_128BIT = 128,         /**< 128-bit IV */
	YACA_KEY_IV_256BIT = 256,         /**< 256-bit IV */
	YACA_KEY_CURVE_P192 = 192,        /**< ECC: P192 curve */
	YACA_KEY_CURVE_P256 = 256,        /**< ECC: P-256 curve */
	YACA_KEY_CURVE_P384 = 384,        /**< ECC: SECP-384 curve */
	YACA_KEY_UNSAFE_40BIT = 40,
	YACA_KEY_UNSAFE_56BIT = 56,
	YACA_KEY_UNSAFE_80BIT = 80,
	YACA_KEY_UNSAFE_112BIT = 112,
	YACA_KEY_UNSAFE_128BIT = 128,
	YACA_KEY_192BIT = 192,
	YACA_KEY_256BIT = 256,
	YACA_KEY_512BIT = 512,
	YACA_KEY_1024BIT = 1024,
	YACA_KEY_2048BIT = 2048,
	YACA_KEY_3072BIT = 3072,
	YACA_KEY_4096BIT = 4096
} yaca_key_bits_e;

/**
 * @brief Message digest algorithms. CMAC is included to simplify API
 */
typedef enum {
	YACA_DIGEST_MD5,      /**< Message digest algorithm MD5  */
	YACA_DIGEST_SHA1,     /**< Message digest algorithm SHA1  */
	YACA_DIGEST_SHA224,   /**< Message digest algorithm SHA2, 224bit  */
	YACA_DIGEST_SHA256,   /**< Message digest algorithm SHA2, 256bit  */
	YACA_DIGEST_SHA384,   /**< Message digest algorithm SHA2, 384bit  */
	YACA_DIGEST_SHA512,   /**< Message digest algorithm SHA2, 512bit  */
	YACA_DIGEST_CMAC      /**< TODO: perhaps CMAC should be handled differently */
} yaca_digest_algo_e;

/**
 * @brief Symmetric encryption algorithms
 */
typedef enum {
	/**
	 * AES encryption.
	 * - see #yaca_block_cipher_mode_e for details on additional parameters (mandatory).
	 * - Supported key lengths: @c 128, @c 192 and @c 256.
	 */
	YACA_ENC_AES = 0,

	/**
	 * DES encryption.
	 * - see #yaca_block_cipher_mode_e for details on additional parameters (mandatory).
	 * - Supported key lengths: @c 56.
	 */
	YACA_ENC_UNSAFE_DES,

	/**
	 * 3DES 2-key encryption.
	 * - see #yaca_block_cipher_mode_e for details on additional parameters (mandatory).
	 * - Use double DES keys to perform corresponding 2-key 3DES encryption.
	 * - Supported key lengths: @c 112.
	 */
	YACA_ENC_UNSAFE_3DES_2TDEA,

	/**
	 * 3DES 3-key encryption.
	 * - see #yaca_block_cipher_mode_e for details on additional parameters (mandatory).
	 * - Use triple DES keys to perform corresponding 3-key 3DES encryption.
	 * - Supported key lengths: @c 168.
	 */
	YACA_ENC_3DES_3TDEA,

	/**
	 * RC2 encryption.
	 * - The key length is extracted from the key buffer.
	 * - Supported key lengths: 8-1024 bits in steps of 8 bits.
	 */
	YACA_ENC_UNSAFE_RC2,

	/**
	 * RC4 encryption.
	 * - The key length is extracted from the key buffer.
	 * - Supported key lengths: 40–2048 bits in steps of 8 bits.
	 */
	YACA_ENC_UNSAFE_RC4,

	/**
	 * CAST5 encryption.
	 * - see #yaca_block_cipher_mode_e for details on additional parameters (mandatory).
	 * - The key length is extracted from the key buffer.
	 * - Supported key lengths: 40-128 bits in steps of 8 bits.
	 */
	YACA_ENC_CAST5,

	/**
	 * SKIPJACK algorithm.
	 * - Supported key length: 80 bits.
	 */
	YACA_ENC_UNSAFE_SKIPJACK
} yaca_enc_algo_e;

/**
 * @brief Chaining modes for block ciphers
 */
typedef enum {
	/**
	 * ECB block cipher mode.
	 * Encrypts 64 bit at a time. No IV is used.
	 */
	YACA_BCM_ECB,

	/**
	 * CTR block cipher mode.
	 * 16-byte initialization vector is mandatory.
	 * Supported parameters:
	 * - #YACA_PARAM_CTR_CNT = length of counter block in bits
	 * (optional, only 128b is supported at the moment)
	 */
	YACA_BCM_CTR,

	/**
	 * CBC block cipher mode.
	 * 16-byte initialization vector is mandatory.
	 */
	YACA_BCM_CBC,

	/**
	 * GCM block cipher mode, IV is needed.
	 * Supported parameters:
	 * - #YACA_PARAM_GCM_TAG = GCM tag
	 * - #YACA_PARAM_GCM_TAG_LEN = GCM tag length
	 * - #YACA_PARAM_GCM_AAD = additional authentication data(optional)
	 */
	YACA_BCM_GCM,

	/**
	 * CFB block cipher mode.
	 * 16-byte initialization vector is mandatory.
	 */
	YACA_BCM_CFB,

	/**
	 * OFB block cipher mode.
	 * 16-byte initialization vector is mandatory.
	 */
	YACA_BCM_OFB,

	/**
	 * Offest Codebook Mode (AES)
	 */
	YACA_BCM_OCB,

	/**
	 * CBC-MAC Mode (AES).
	 * Supported parameters:
	 * - #YACA_PARAM_CCM_TAG = CCM tag
	 * - #YACA_PARAM_CCM_TAG_LEN = CCM tag length
	 * - #YACA_PARAM_CCM_AAD = additional authentication data(optional)
	 */
	YACA_BCM_CCM

} yaca_block_cipher_mode_e;


/**
 * @brief Non-standard parameters for algorithms
 */
typedef enum {
	YACA_PARAM_PADDING,      /**< Padding */

	YACA_PARAM_CTR_CNT,      /**< CTR Counter bits */

	YACA_PARAM_GCM_AAD,      /**< GCM Additional Authentication Data */
	YACA_PARAM_GCM_TAG,      /**< GCM Tag bits */
	YACA_PARAM_GCM_TAG_LEN,  /**< GCM Tag length */

	YACA_PARAM_CCM_AAD,      /**< CCM Additional Authentication Data */
	YACA_PARAM_CCM_TAG,      /**< CCM Tag bits */
	YACA_PARAM_CCM_TAG_LEN,  /**< CCM Tag length */
} yaca_ex_param_e;

/**
 * @brief Paddings supported by Yet Another Crypto API
 */
typedef enum {
	YACA_PADDING_NONE = 0,   /**< total number of data MUST multiple of block size, Default */
	YACA_PADDING_ZEROS,      /**< pad with zeros */
	YACA_PADDING_ISO10126,   /**< ISO 10126 */
	YACA_PADDING_ANSIX923,   /**< ANSI X.923 padding*/
	YACA_PADDING_ANSIX931,   /**< ANSI X.931 padding*/
	YACA_PADDING_PKCS1,      /**< RSA signature creation */
	YACA_PADDING_PKCS7       /**< Byte padding for symetric algos (RFC 5652), (PKCS5 padding is the same) */
} yaca_padding_e;

/**@}*/

#ifdef __cplusplus
} /* extern */
#endif

#endif /* TYPES_H */
