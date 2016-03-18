#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    //symetric
    CIPHER_NONE,    //e.g. no cipher based digests
    CIPHER_DES,     //unsafe
    CIPHER_DES3,
    CIPHER_DESX,    //only CBC blockmode
    CIPHER_AES,
    CIPHER_RC2,     //unsafe
    CIPHER_RC4,     //unsafe
    CIPHER_RC5,
    CIPHER_CAST5,
    CIPHER_SKIPJACK,//unsafe

    //aymetric
    CIPHER_RSA,     //RSA cert - md5+sha1 is signed
    CIPHER_DSA,     //DSA cert - sha1 is signed
    CIPHER_KEA,     //key pair generation, TEK derivation (Token Encryption Key)
    CIPHER_DH,      //key pair generation, TEK derivation
    CIPHER_EC,      //eliptic curve
    CIPHER_ECDH,    //eliptic curve
} cipher_t;

typedef enum {
    BLOCKMODE_NONE,
    BLOCKMODE_EBC,  // Electronic Codeblock, unsafe
    BLOCKMODE_CBC,  // Cipher Block Chaining
    BLOCKMODE_CFB,  // Cipher Feedback
    BLOCKMODE_OFB,  // Output Feedback
    BLOCKMODE_CTR,  // Counter (DES,AES) [RFC 3686]
    BLOCKMODE_GCM,  // Galois Counter Mode (AES)
    BLOCKMODE_OCB,  // Offest Codebook Mode (AES)
    BLOCKMODE_CCM,  // CBC-MAC Mode (AES)
} blockmode_t;

typedef enum {
    DIGEST_MD5,      /**< Message digest algorithm MD5  */
    DIGEST_SHA1,     /**< Message digest algorithm SHA1  */
    DIGEST_SHA224,   /**< Message digest algorithm SHA2, 224bit  */
    DIGEST_SHA256,   /**< Message digest algorithm SHA2, 256bit  */
    DIGEST_SHA384,   /**< Message digest algorithm SHA2, 384bit  */
    DIGEST_SHA512    /**< Message digest algorithm SHA2, 512bit  */
} digest_algo_t;

typedef enum {
    PADDING_NONE,       // total number of data MUST multiple of block size
    PADDING_ZEROS,      // pad with zores
    PADDING_ISO10126,
    PADDING_ANSIX923,
    PADDING_ANSIX931,   // same as zero padding ?
    PADDING_PKCS1,      // RSA signature creation
    PADDING_PKCS7,      // Byte padding for symetric algos (RFC 5652), (PKCS5 padding is the same)
} padding_t;

typedef enum {
    KEYFORMAT_RAW,      // key is clear from
    KEYFORMAT_BASE64,   // key is encoded in ASCII-base64
    KEYFORMAT_PEM,      // key is in PEM file format
    KEYFORMAT_DER,      // key is in DER file format
} keyformat_t;

typedef enum {
    //common params
    PARAM_DIGEST_ALGO,
    PARAM_KEY,
    PARAM_IV,       // Initial Vector
    PARAM_PADDING,
    PARAM_BLOCKMODE,
    //specific params
    PARAM_CTR_CNT,  // CTR Counter bits
    PARAM_GCM_TAG,  // GCM Tag bits
    PARAM_GCM_ADD,  // GCM Additional Authentication Data
    PARAM_CCM_NONCE,// Nonce
    PARAM_CCM_ADD,  // Additional Authentication Data
    PARAM_CCM_MAC,  // MAC length in bytes
} param_t;

typedef enum {
    SIGN_CALC,
    SIGN_VERIFY,
} sign_dir_t;

//internal key info struct
typedef struct __crypt_key_info crypt_key_h;

// cryptograohic module initialization (crypt_module_init must be first func)
int crypt_module_init();
int crypt_module_exit();

// context init/reset
int crypt_init(crypt_key_h**, cipher_t);
int crypt_destroy(crypt_key_h *);

//*******************************************
// various parameters, depends on used cipher
//*******************************************

// optional parameters (research needed for what we need)
// note: internally it is stored as list of tag,length,value (TLV)
int crypt_setparam(crypt_key_h *, param_t p, const void *v, size_t len);
int crypt_getparam(crypt_key_h *, param_t p, void *v, size_t len);
//param_t : key, iv, padding method, block mode ….

// set of functions for known parameters
int crypt_setparam_digest_algo(crypt_key_h *, const digest_algo_t algo);
int crypt_setparam_iv(crypt_key_h *, const void *iv, size_t len);
int crypt_setparam_padding(crypt_key_h *, padding_t v);
int crypt_setparam_blockmode(crypt_key_h *, blockmode_t v);
// Note: GCM concat message len, message, and ADD (3 update calls)
//      (https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption)
int crypt_setparam_gcm_tag(crypt_key_h *,  const void *tag, size_t len);
int crypt_setparam_gcm_aad(crypt_key_h *, const void *add, size_t len);

int crypt_getparam_iv(crypt_key_h *, void *iv, size_t *len);
int crypt_getparam_gcm_tag(crypt_key_h *, void *tag, size_t len);

//*******************************************
// top level (simple) interface
//*******************************************

int crypt_import_key(crypt_key_h *key, keyformat_t format, void *blob, size_t size);
int crypt_export_key(crypt_key_h *key, keyformat_t format, void *blob, size_t size);

// possible static predefined digests contexts like SHA1,SHA224,SHA256
// digests (no key, default iv=<zeros>)
int crypt_digest_calc(const digest_algo_t algo, const void *data, size_t len, void **digest, size_t *digest_len);

// encryptions (key is mandatory, default iv=<zeros>), symmetric or asymetric
int crypt_encrypt(crypt_key_h *key, const void *data, size_t len, void **enc_data, size_t * enc_len);
int crypt_decrypt(crypt_key_h *key, const void *enc_data, size_t enc_len, void **data, size_t * len);

// message authentication (key is mandatory, padding method, default iv=<zeros>)
// note: this is, in fact, the same as diggest with key set up
int crypt_sign_verify(crypt_key_h *key, const void *data, size_t len, const void *mac, size_t mac_len);
int crypt_sign_calc(crypt_key_h *key, const void *data, size_t len, void **mac, size_t mac_len);

// deallocete memory allocated by crypto library
int crypto_free(void *buf);

// seal creates symkey (with set param iv, ivlen)
int crypt_seal(crypt_key_h *pubkey, crypt_key_h *symkey, const void *data, size_t len, void **enc_data, size_t *enc_len);
// open uses symkey taken from seal
int crypt_open(crypt_key_h *prvkey, crypt_key_h *symkey, const void *enc_data, size_t enc_len, void **data, size_t *len);


//*******************************************
// low level (advanced) interface
//*******************************************

//key material generation (depends on context cipher)
//  key - store generated key bytes
//implememtation:
//  read byte sequence from /dev/urandom, until got not trivial key
int crypt_generate_key(crypt_key_h *key, size_t key_len);
// keypub = (n,e)   keyprv = (n,d)
// where n is modulus, e is public key exponents, d is private key exponent
int crypt_generate_pkey(crypt_key_h *pub, crypt_key_h *priv, size_t key_len);

int crypt_digest_update(crypt_key_h *dig, const void *data, size_t len);
int crypt_digest_final(crypt_key_h *dig, void **digest, size_t *digest_len);

int crypt_encrypt_update(crypt_key_h *key, const void *indata, size_t inlen, void **outdata, size_t *outlen);
int crypt_encrypt_final(crypt_key_h *key, void **outdata, size_t *outlen);

int crypt_decrypt_update(crypt_key_h *key, const void *indata, size_t inlen, void **outdata, size_t *outlen);
int crypt_decrypt_final(crypt_key_h *key, void **outdata, size_t *outlen);

int crypt_sign_init(crypt_key_h *key, sign_dir_t);
int crypt_sign_update(crypt_key_h *key, const void *data, size_t len);
int crypt_sign_final(crypt_key_h *key, void **mac, size_t *mac_len);

int crypt_derive_key(crypt_key_h *dk, crypt_key_h *key);

int crypt_derive_pkey(crypt_key_h *dk, crypt_key_h *key);

#ifdef __cplusplus
}
#endif

