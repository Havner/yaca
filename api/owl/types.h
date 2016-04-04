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
 * @defgroup Crypto-Types   Enumerations for CryptoAPI
 *
 * TODO: extended description.
 *
 * @{
 */

/**
 * @brief Context
 */
typedef struct owl_ctx_s *owl_ctx_h;

/**
 * @brief Key
 */
typedef struct owl_key_s *owl_key_h;

/**
 * @brief Key formats
 */
typedef enum {
	OWL_KEY_FORMAT_RAW,      /**< key is in clear format */
	OWL_KEY_FORMAT_BASE64,   /**< key is encoded in ASCII-base64 */
	OWL_KEY_FORMAT_PEM,      /**< key is in PEM file format */
	OWL_KEY_FORMAT_DER       /**< key is in DER file format */
} owl_key_fmt_e;

/**
 * @brief Key types, IV is considered as key
 */
typedef enum {
	OWL_KEY_TYPE_SYMMETRIC,  /**< Generic symmetric cipher KEY */
	OWL_KEY_TYPE_DES,        /**< DES* key - must be handled differently because of parity bits */
	OWL_KEY_TYPE_IV,         /**< IV for symmetric algorithms */

	OWL_KEY_TYPE_RSA_PUB,    /**< RSA public key */
	OWL_KEY_TYPE_RSA_PRIV,   /**< RSA private key */

	OWL_KEY_TYPE_DSA_PUB,    /**< DSA public key */
	OWL_KEY_TYPE_DSA_PRIV,   /**< DSA private key */

	OWL_KEY_TYPE_DH_PUB,     /**< Diffie-Hellman public key */
	OWL_KEY_TYPE_DH_PRIV,    /**< Diffie-Hellman private key */

	OWL_KEY_TYPE_ECC_PUB,    /**< ECC public key */
	OWL_KEY_TYPE_ECC_PRIV,   /**< ECC private key */

	OWL_KEY_TYPE_PAIR_RSA,   /**< Pair of RSA keys */
	OWL_KEY_TYPE_PAIR_DSA,   /**< Pair of DSA keys */
	OWL_KEY_TYPE_PAIR_DH,    /**< Pair of Diffie-Hellman keys */
	OWL_KEY_TYPE_PAIR_ECC    /**< Pair of ECC keys */
} owl_key_type_e;

/**
 * @brief Key length, It is possible to use arbitrary integer instead, this enums are placed here to avoid magic numbers.
 */
typedef enum {
	OWL_KEY_IV_UNSAFE_24BIT = 24,    /**< 24-bit IV */
	OWL_KEY_IV_64BIT = 64,           /**< 64-bit IV */
	OWL_KEY_IV_128BIT = 128,         /**< 128-bit IV */
	OWL_KEY_IV_256BIT = 256,         /**< 256-bit IV */
	OWL_KEY_CURVE_P192 = 192,        /**< ECC: P192 curve */
	OWL_KEY_CURVE_P256 = 256,        /**< ECC: P-256 curve */
	OWL_KEY_CURVE_P384 = 384,        /**< ECC: SECP-384 curve */
	OWL_KEY_UNSAFE_40BIT = 40,
	OWL_KEY_UNSAFE_56BIT = 56,
	OWL_KEY_UNSAFE_80BIT = 80,
	OWL_KEY_UNSAFE_112BIT = 112,
	OWL_KEY_UNSAFE_128BIT = 128,
	OWL_KEY_192BIT = 192,
	OWL_KEY_256BIT = 256,
	OWL_KEY_512BIT = 512,
	OWL_KEY_1024BIT = 1024,
	OWL_KEY_2048BIT = 2048,
	OWL_KEY_3072BIT = 3072,
	OWL_KEY_4096BIT = 4096
} owl_key_len_e;

/**
 * @brief Message digest algorithms. CMAC is included to simplify API
 */
typedef enum {
	OWL_DIGEST_MD5,      /**< Message digest algorithm MD5  */
	OWL_DIGEST_SHA1,     /**< Message digest algorithm SHA1  */
	OWL_DIGEST_SHA224,   /**< Message digest algorithm SHA2, 224bit  */
	OWL_DIGEST_SHA256,   /**< Message digest algorithm SHA2, 256bit  */
	OWL_DIGEST_SHA384,   /**< Message digest algorithm SHA2, 384bit  */
	OWL_DIGEST_SHA512,   /**< Message digest algorithm SHA2, 512bit  */
	OWL_DIGEST_CMAC      /**< TODO: perhaps CMAC should be handled differently */
} owl_digest_algo_e;

/**
 * @brief Symmetric encryption algorithms
 */
typedef enum {
	OWL_ENC_AES = 0,     /**< AES encryption.
			    - see #owl_block_cipher_mode_e for details on additional parameters (mandatory)
			    Supported key lengths: @c 128, @c 192 and @c 256 */

	OWL_ENC_UNSAFE_DES,  /**< DES encryption.
			    - see #owl_block_cipher_mode_e for details on additional parameters (mandatory)
			    Supported key lengths: @c 56 */

	OWL_ENC_UNSAFE_3DES_2TDEA,   /**< 3DES 2-key encryption.
			    - see #owl_block_cipher_mode_e for details on additional parameters (mandatory)
			    Use double DES keys to perform corresponding 2-key 3DES encryption. Supported key lengths: @c 112 */

	OWL_ENC_3DES_3TDEA,  /**< 3DES 3-key encryption.
			    - see #owl_block_cipher_mode_e for details on additional parameters (mandatory)
			    Use triple DES keys to perform corresponding 3-key 3DES encryption. Supported key lengths: @c 168 */

	OWL_ENC_UNSAFE_RC2,  /**< RC2 encryption.
			    - see #owl_block_cipher_mode_e for details on additional parameters (mandatory)
			    The key length is extracted from the key buffer. Supported key lengths: 8-1024 bits in steps of 8 bits. */

	OWL_ENC_UNSAFE_RC4,  /**< RC4 encryption.
			    The key length is extracted from the key buffer. Supported key lengths: 40–2048 bits in steps of 8 bits */

	OWL_ENC_CAST5,       /**< CAST5 encryption.
			    - see #owl_block_cipher_mode_e for details on additional parameters (mandatory)
			    The key length is extracted from the key buffer. Supported key lengths: 40-128 bits in steps of 8 bits */

	OWL_ENC_UNSAFE_SKIPJACK  /**< SKIPJACK algorithm
				- see #owl_block_cipher_mode_e for details on additional parameters (mandatory)
				Supported key length: 80 bits */
} owl_enc_algo_e;

/**
 * @brief Chaining modes for block ciphers
 */
typedef enum {
	OWL_BCM_ECB, /**< ECB block cipher mode. Encrypts 64 bit at a time. No IV is used. */

	OWL_BCM_CTR, /**< CTR block cipher mode. 16-byte initialization vector is mandatory.
		    Supported parameters:
		    - OWL_PARAM_CTR_CNT = length of counter block in bits
		    (optional, only 128b is supported at the moment) */

	OWL_BCM_CBC, /**< CBC block cipher mode. 16-byte initialization vector is mandatory. */

	OWL_BCM_GCM, /**< GCM block cipher mode. IV is needed.
		    Supported parameters:
		    - OWL_PARAM_TAG = GCM tag
		    - OWL_PARAM_AAD = additional authentication data(optional) */

	OWL_BCM_CFB, /**< CFB block cipher mode. 16-byte initialization vector is mandatory. */

	OWL_BCM_OFB, /**< OFB block cipher mode. 16-byte initialization vector is mandatory. */

	OWL_BCM_OCB, /**< Offest Codebook Mode (AES) */

	OWL_BCM_CCM  /**< CBC-MAC Mode (AES) */

} owl_block_cipher_mode_e;


/**
 * @brief Non-standard parameters for algorithms
 */
typedef enum {
	OWL_PARAM_PADDING,      /**< Padding */

	OWL_PARAM_CTR_CNT,      /**< CTR Counter bits */

	OWL_PARAM_GCM_AAD,      /**< GCM Additional Authentication Data */
	OWL_PARAM_GCM_TAG,      /**< GCM Tag bits */
	OWL_PARAM_GCM_TAG_LEN,  /**< GCM Tag length */

	OWL_PARAM_CCM_AAD,      /**< CCM Additional Authentication Data */
	OWL_PARAM_CCM_TAG,      /**< CCM Tag bits */
	OWL_PARAM_CCM_TAG_LEN,  /**< CCM Tag length */
} owl_ex_param_e;

/**
 * @brief Paddings supported by CryptoAPI
 */
typedef enum {
	OWL_PADDING_NONE = 0,   /**< total number of data MUST multiple of block size, Default */
	OWL_PADDING_ZEROS,      /**< pad with zeros */
	OWL_PADDING_ISO10126,   /**< ISO 10126 */
	OWL_PADDING_ANSIX923,   /**< ANSI X.923 padding*/
	OWL_PADDING_ANSIX931,   /**< ANSI X.931 padding*/
	OWL_PADDING_PKCS1,      /**< RSA signature creation */
	OWL_PADDING_PKCS7       /**< Byte padding for symetric algos (RFC 5652), (PKCS5 padding is the same) */
} owl_padding_e;

/**@}*/

#ifdef __cplusplus
} /* extern */
#endif

#endif /* TYPES_H */
