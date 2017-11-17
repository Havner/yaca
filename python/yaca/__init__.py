#!/usr/bin/env python3

# Copyright (c) 2017-2018 Samsung Electronics Co., Ltd All Rights Reserved
#
# Contact: Lukasz Pawelczyk <l.pawelczyk@samsung.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License


"""
Python3 bindings for YACA.

Usage is almost the same as in the C API. All the functions that made
sense in Python were implemented. Memory allocations and functions for
getting length of the buffers were ommited as all those things are
handled automatically for both input and output.

All the parameters for strings/data expect python's bytes type. All
the parameters are named the same as in the C API and their meaning is
exactly the same.

The major exception being encrypt/decrypt update where second
parameter can have 2 meanings. This is only used for CCM_AAD. See
examples.

Some parameters now have default values for ease of use.

For details please refer to the C API doxygen documentation.

For examples see tests/examples in yaca.tests module.
"""

import enum as _enum
import ctypes as _ctypes
import yaca.library
from yaca.error import *
del yaca.error

# Initialization

_lib = yaca.library.get_yaca()
del yaca.library


# Helpers

def _get_char_param_nullify_if_zero(param):
    return None if len(param) == 0 else param


def _context_get_output_length(ctx, input_length):
    output_length = _ctypes.c_size_t()
    _lib.yaca_context_get_output_length(ctx,
                                        input_length,
                                        _ctypes.byref(output_length))
    return output_length.value


# Types

class Context():
    def __init__(self, ptr):
        if not isinstance(ptr, _ctypes.c_void_p):
            raise TypeError('Invalid type')
        self._as_parameter_ = ptr

    def __del__(self):
        _lib.yaca_context_destroy(self._as_parameter_)


class Key():
    def __init__(self, ptr):
        if not isinstance(ptr, _ctypes.c_void_p):
            raise TypeError('Invalid type')
        self._as_parameter_ = ptr

    def __del__(self):
        _lib.yaca_key_destroy(self._as_parameter_)

    def __repr__(self):
        if self._as_parameter_.value is None:
            return '<yaca.Key: KEY_NULL>'
        return '<yaca.Key: ' + str(self.get_type()) + ', ' + \
            str(self.get_bit_length()) + ' bits at ' + str(hex(id(self))) + '>'

    def get_type(self):
        return key_get_type(self)

    def get_bit_length(self):
        return key_get_bit_length(self)


KEY_NULL = Key(_ctypes.c_void_p())


# Enums

@_enum.unique
class KEY_FORMAT(_enum.Enum):
    DEFAULT = 0
    PKCS8 = 1


@_enum.unique
class KEY_FILE_FORMAT(_enum.Enum):
    RAW = 0
    BASE64 = 1
    PEM = 2
    DER = 3


@_enum.unique
class KEY_TYPE(_enum.Enum):
    SYMMETRIC = 0
    DES = 1
    IV = 2
    RSA_PUB = 3
    RSA_PRIV = 4
    DSA_PUB = 5
    DSA_PRIV = 6
    DH_PUB = 7
    DH_PRIV = 8
    EC_PUB = 9
    EC_PRIV = 10
    DSA_PARAMS = 11
    DH_PARAMS = 12
    EC_PARAMS = 13


class KEY_BIT_LENGTH(_enum.IntEnum):
    IV_64BIT = 64
    IV_128BIT = 128
    UNSAFE_8BIT = 8
    UNSAFE_40BIT = 40
    UNSAFE_64BIT = 64
    UNSAFE_80BIT = 80
    UNSAFE_128BIT = 128
    L192BIT = 192
    L256BIT = 256
    L512BIT = 512
    L1024BIT = 1024
    L2048BIT = 2048
    L3072BIT = 3072
    L4096BIT = 4096


@_enum.unique
class KEY_BIT_LENGTH_EC(_enum.IntEnum):
    PRIME192V1 = 0x300000C0
    PRIME256V1 = 0x30000100
    SECP256K1 = 0x31200100
    SECP384R1 = 0x31100180
    SECP521R1 = 0x31100209


KEY_LENGTH_DH_GENERATOR_2 = 0x10000000
KEY_LENGTH_DH_GENERATOR_5 = 0x11000000


@_enum.unique
class KEY_BIT_LENGTH_DH_RFC(_enum.IntEnum):
    L1024_160 = 0x20000400
    L2048_224 = 0x21000800
    L2048_256 = 0x22000800


@_enum.unique
class DIGEST_ALGORITHM(_enum.Enum):
    MD5 = 0
    SHA1 = 1
    SHA224 = 2
    SHA256 = 3
    SHA384 = 4
    SHA512 = 5


@_enum.unique
class ENCRYPT_ALGORITHM(_enum.Enum):
    AES = 0
    UNSAFE_DES = 1
    UNSAFE_TRIPPLE_DES_2TDEA = 2
    TRIPPLE_DES_3TDEA = 3
    UNSAFE_RC2 = 4
    UNSAFE_RC4 = 5
    CAST5 = 6


@_enum.unique
class BLOCK_CIPHER_MODE(_enum.Enum):
    NONE = 0
    ECB = 1
    CTR = 2
    CBC = 3
    GCM = 4
    CFB = 5
    CFB1 = 6
    CFB8 = 7
    OFB = 8
    CCM = 9
    WRAP = 10


@_enum.unique
class PROPERTY(_enum.Enum):
    PADDING = 0
    GCM_AAD = 1
    GCM_TAG = 2
    GCM_TAG_LEN = 3
    CCM_AAD = 4
    CCM_TAG = 5
    CCM_TAG_LEN = 6
    RC2_EFFECTIVE_KEY_BITS = 7


@_enum.unique
class PADDING(_enum.Enum):
    NONE = 0
    X931 = 1
    PKCS1 = 2
    PKCS1_PSS = 3
    PKCS1_OAEP = 4
    PKCS1_SSLV23 = 5
    PKCS7 = 6


@_enum.unique
class KDF(_enum.Enum):
    X942 = 0
    X962 = 1


# Implementation crypto

def initialize():
    """Initializes the library. Must be called before any other crypto
    function. Should be called once in each thread that uses yaca."""
    _lib.yaca_initialize()


def cleanup():
    """Cleans up the library.
    Must be called before exiting the thread that called yaca_initialize()."""
    _lib.yaca_cleanup()


def memcmp(first, second, length):
    """Safely compares first length bytes of two buffers."""
    l = _ctypes.c_size_t(length)
    return _lib.yaca_memcmp(first, second, l)


def random_bytes(length):
    """Generates random data."""
    data = _ctypes.create_string_buffer(length)
    _lib.yaca_randomize_bytes(data, length)
    return bytes(data)


def context_set_property(ctx, prop, prop_val):
    """Sets the non-standard context properties.
    Can only be called on an initialized context."""
    if prop == PROPERTY.PADDING:
        value = _ctypes.c_int(prop_val.value)
        value_length = _ctypes.sizeof(value)
        _lib.yaca_context_set_property(ctx,
                                       prop.value,
                                       _ctypes.byref(value),
                                       value_length)
    elif (prop == PROPERTY.GCM_AAD) or (prop == PROPERTY.CCM_AAD) or \
         (prop == PROPERTY.GCM_TAG) or (prop == PROPERTY.CCM_TAG):
        value = prop_val
        value_length = len(prop_val)
        _lib.yaca_context_set_property(ctx, prop.value,
                                       value, value_length)
    elif (prop == PROPERTY.GCM_TAG_LEN) or (prop == PROPERTY.CCM_TAG_LEN) or \
         (prop == PROPERTY.RC2_EFFECTIVE_KEY_BITS):
        value = _ctypes.c_size_t(prop_val)
        value_length = _ctypes.sizeof(value)
        _lib.yaca_context_set_property(
            ctx, prop.value, _ctypes.byref(value), value_length)
    else:
        raise InvalidParameterError('Wrong property passed')


def context_get_property(ctx, prop):
    """Returns the non-standard context properties.
    Can only be called on an initialized context."""
    value = _ctypes.c_void_p()
    value_length = _ctypes.c_size_t()
    _lib.yaca_context_get_property(ctx, prop.value, _ctypes.byref(value),
                                   _ctypes.byref(value_length))
    if prop == PROPERTY.PADDING:
        value_cast = _ctypes.cast(value, _ctypes.POINTER(_ctypes.c_int))
        value_proper = value_cast.contents.value
        assert value_length.value == _ctypes.sizeof(value_cast.contents)
    elif (prop == PROPERTY.GCM_AAD) or (prop == PROPERTY.CCM_AAD) or \
         (prop == PROPERTY.GCM_TAG) or (prop == PROPERTY.CCM_TAG):
        value_cast = _ctypes.cast(value, _ctypes.POINTER(_ctypes.c_char))
        value_proper = value_cast[:value_length.value]
        assert value_length.value == len(value_proper)
    elif (prop == PROPERTY.GCM_TAG_LEN) or \
         (prop == PROPERTY.CCM_TAG_LEN) or \
         (prop == PROPERTY.RC2_EFFECTIVE_KEY_BITS):
        value_cast = _ctypes.cast(value, _ctypes.POINTER(_ctypes.c_size_t))
        value_proper = value_cast.contents.value
        assert value_length.value == _ctypes.sizeof(value_cast.contents)
    else:
        raise InvalidParameterError('Wrong property passed')
    _lib.yaca_free(value)
    return value_proper


# Implementation key

def key_get_type(key):
    """Gets key's type"""
    key_type = _ctypes.c_int()
    _lib.yaca_key_get_type(key, _ctypes.byref(key_type))
    return KEY_TYPE(key_type.value)


def key_get_bit_length(key):
    """Gets key's length (in bits)."""
    key_bit_length = _ctypes.c_size_t()
    _lib.yaca_key_get_bit_length(key, _ctypes.byref(key_bit_length))
    return key_bit_length.value


def key_import(data, key_type=KEY_TYPE.SYMMETRIC, password=b''):
    """Imports a key or key generation parameters."""
    key = _ctypes.c_void_p()
    _lib.yaca_key_import(key_type.value, _ctypes.c_char_p(password),
                         data, len(data), _ctypes.byref(key))
    return Key(key)


def key_export(key, key_file_fmt=KEY_FILE_FORMAT.BASE64,
               key_fmt=KEY_FORMAT.DEFAULT, password=b''):
    """Exports a key or key generation parameters to arbitrary format."""
    data = _ctypes.POINTER(_ctypes.c_char)()
    data_length = _ctypes.c_size_t()
    _lib.yaca_key_export(key, key_fmt.value, key_file_fmt.value,
                         _ctypes.c_char_p(password), _ctypes.byref(data),
                         _ctypes.byref(data_length))
    data_bytes = data[:data_length.value]
    _lib.yaca_free(data)
    return data_bytes


def key_generate(key_type=KEY_TYPE.SYMMETRIC,
                 key_bit_length=KEY_BIT_LENGTH.L256BIT):
    """Generates a secure key or key generation parameters
    (or an Initialization Vector)."""
    key = _ctypes.c_void_p()
    _lib.yaca_key_generate(key_type.value, key_bit_length,
                           _ctypes.byref(key))
    return Key(key)


def key_generate_from_parameters(params):
    """Generates a secure private asymmetric key from parameters."""
    prv_key = _ctypes.c_void_p()
    _lib.yaca_key_generate_from_parameters(params,
                                           _ctypes.byref(prv_key))
    return Key(prv_key)


def key_extract_public(prv_key):
    """Extracts public key from a private one."""
    pub_key = _ctypes.c_void_p()
    _lib.yaca_key_extract_public(prv_key, _ctypes.byref(pub_key))
    return Key(pub_key)


def key_extract_parameters(key):
    """Extracts parameters from a private or a public key."""
    params = _ctypes.c_void_p()
    _lib.yaca_key_extract_parameters(key, _ctypes.byref(params))
    return Key(params)


def key_derive_dh(prv_key, pub_key):
    """Derives a shared secret using Diffie-Helmann or EC Diffie-Helmann
    key exchange protocol."""
    secret = _ctypes.POINTER(_ctypes.c_char)()
    secret_length = _ctypes.c_size_t()
    _lib.yaca_key_derive_dh(prv_key, pub_key, _ctypes.byref(secret),
                            _ctypes.byref(secret_length))
    secret_bytes = secret[:secret_length.value]
    _lib.yaca_free(secret)
    return secret_bytes


def key_derive_kdf(secret, key_material_length, info=b'',
                   kdf=KDF.X942, digest_algo=DIGEST_ALGORITHM.SHA256):
    """Derives a key material from shared secret."""
    info_param = _get_char_param_nullify_if_zero(info)
    key_material = _ctypes.POINTER(_ctypes.c_char)()
    _lib.yaca_key_derive_kdf(kdf.value, digest_algo.value,
                             secret, len(secret),
                             info_param, len(info), key_material_length,
                             _ctypes.byref(key_material))
    key_material_bytes = key_material[:key_material_length]
    _lib.yaca_free(key_material)
    return key_material_bytes


def key_derive_pbkdf2(password, key_bit_length=KEY_BIT_LENGTH.L256BIT,
                      salt=b'', digest_algo=DIGEST_ALGORITHM.SHA256,
                      iterations=50000):
    """Derives a key from user password (PKCS #5 a.k.a. pbkdf2 algorithm)."""
    salt_param = _get_char_param_nullify_if_zero(salt)
    key = _ctypes.c_void_p()
    _lib.yaca_key_derive_pbkdf2(_ctypes.c_char_p(password), salt_param,
                                len(salt), iterations, digest_algo.value,
                                key_bit_length, _ctypes.byref(key))
    return Key(key)


# Implementation simple

def simple_encrypt(sym_key, plaintext, encrypt_algo=ENCRYPT_ALGORITHM.AES,
                   bcm=BLOCK_CIPHER_MODE.ECB, iv=KEY_NULL):
    """Encrypts data using a symmetric cipher."""
    plaintext_param = _get_char_param_nullify_if_zero(plaintext)
    ciphertext = _ctypes.POINTER(_ctypes.c_char)()
    ciphertext_length = _ctypes.c_size_t()
    _lib.yaca_simple_encrypt(encrypt_algo.value, bcm.value, sym_key, iv,
                             plaintext_param, len(plaintext),
                             _ctypes.byref(ciphertext),
                             _ctypes.byref(ciphertext_length))
    ciphertext_bytes = ciphertext[:ciphertext_length.value]
    _lib.yaca_free(ciphertext)
    return ciphertext_bytes


def simple_decrypt(sym_key, ciphertext, encrypt_algo=ENCRYPT_ALGORITHM.AES,
                   bcm=BLOCK_CIPHER_MODE.ECB, iv=KEY_NULL):
    """Decrypts data using a symmetric cipher."""
    ciphertext_param = _get_char_param_nullify_if_zero(ciphertext)
    plaintext = _ctypes.POINTER(_ctypes.c_char)()
    plaintext_length = _ctypes.c_size_t()
    _lib.yaca_simple_decrypt(encrypt_algo.value, bcm.value, sym_key, iv,
                             ciphertext_param, len(ciphertext),
                             _ctypes.byref(plaintext),
                             _ctypes.byref(plaintext_length))
    plaintext_bytes = plaintext[:plaintext_length.value]
    _lib.yaca_free(plaintext)
    return plaintext_bytes


def simple_calculate_digest(message, digest_algo=DIGEST_ALGORITHM.SHA256):
    """Calculates a digest of a message."""
    message_param = _get_char_param_nullify_if_zero(message)
    digest = _ctypes.POINTER(_ctypes.c_char)()
    digest_length = _ctypes.c_size_t()
    _lib.yaca_simple_calculate_digest(digest_algo.value, message_param,
                                      len(message),
                                      _ctypes.byref(digest),
                                      _ctypes.byref(digest_length))
    digest_bytes = digest[:digest_length.value]
    _lib.yaca_free(digest)
    return digest_bytes


def simple_calculate_signature(prv_key, message,
                               digest_algo=DIGEST_ALGORITHM.SHA256):
    """Creates a signature using asymmetric private key."""
    message_param = _get_char_param_nullify_if_zero(message)
    signature = _ctypes.POINTER(_ctypes.c_char)()
    signature_length = _ctypes.c_size_t()
    _lib.yaca_simple_calculate_signature(digest_algo.value, prv_key,
                                         message_param, len(message),
                                         _ctypes.byref(signature),
                                         _ctypes.byref(signature_length))
    signature_bytes = signature[:signature_length.value]
    _lib.yaca_free(signature)
    return signature_bytes


def simple_verify_signature(pub_key, message, signature,
                            digest_algo=DIGEST_ALGORITHM.SHA256):
    """Verifies a signature using asymmetric public key."""
    return _lib.yaca_simple_verify_signature(digest_algo.value, pub_key,
                                             message, len(message),
                                             signature, len(signature))


def simple_calculate_hmac(sym_key, message,
                          digest_algo=DIGEST_ALGORITHM.SHA256):
    """Calculates a HMAC of given message using symmetric key."""
    message_param = _get_char_param_nullify_if_zero(message)
    mac = _ctypes.POINTER(_ctypes.c_char)()
    mac_length = _ctypes.c_size_t()
    _lib.yaca_simple_calculate_hmac(digest_algo.value, sym_key,
                                    message_param, len(message),
                                    _ctypes.byref(mac),
                                    _ctypes.byref(mac_length))
    mac_bytes = mac[:mac_length.value]
    _lib.yaca_free(mac)
    return mac_bytes


def simple_calculate_cmac(sym_key, message,
                          encrypt_algo=ENCRYPT_ALGORITHM.AES):
    """Calculates a CMAC of given message using symmetric key."""
    message_param = _get_char_param_nullify_if_zero(message)
    mac = _ctypes.POINTER(_ctypes.c_char)()
    mac_length = _ctypes.c_size_t()
    _lib.yaca_simple_calculate_cmac(encrypt_algo.value, sym_key,
                                    message_param, len(message),
                                    _ctypes.byref(mac),
                                    _ctypes.byref(mac_length))
    mac_bytes = mac[:mac_length.value]
    _lib.yaca_free(mac)
    return mac_bytes


# Implementation digest

def digest_initialize(digest_algo=DIGEST_ALGORITHM.SHA256):
    """Initializes a digest context."""
    ctx = _ctypes.c_void_p()
    _lib.yaca_digest_initialize(_ctypes.byref(ctx), digest_algo.value)
    return Context(ctx)


def digest_update(ctx, message):
    """Feeds the message into the message digest algorithm."""
    _lib.yaca_digest_update(ctx, message, len(message))


def digest_finalize(ctx):
    """Calculates the final digest."""
    output_length = _context_get_output_length(ctx, 0)
    digest = _ctypes.create_string_buffer(output_length)
    digest_length = _ctypes.c_size_t()
    _lib.yaca_digest_finalize(ctx, digest, _ctypes.byref(digest_length))
    return bytes(digest[:digest_length.value])


# Implementation encrypt

def encrypt_get_iv_bit_length(encrypt_algo, bcm, key_bin_length):
    """Returns the recommended/default length of the Initialization Vector
    for a given encryption configuration."""
    iv_bit_length = _ctypes.c_size_t()
    _lib.yaca_encrypt_get_iv_bit_length(encrypt_algo.value, bcm.value,
                                        key_bin_length,
                                        _ctypes.byref(iv_bit_length))
    return iv_bit_length.value


def encrypt_initialize(sym_key, encrypt_algo=ENCRYPT_ALGORITHM.AES,
                       bcm=BLOCK_CIPHER_MODE.ECB, iv=KEY_NULL):
    """Initializes an encryption context."""
    ctx = _ctypes.c_void_p()
    _lib.yaca_encrypt_initialize(_ctypes.byref(ctx), encrypt_algo.value,
                                 bcm.value, sym_key, iv)
    return Context(ctx)


def encrypt_update(ctx, plaintext):
    """Encrypts chunk of the data.
    Alternatively plaintext can be the total length of the input (int).
    This is used for CCM_AAD."""
    if isinstance(plaintext, int):  # the case of using AAD in CCM
        _lib.yaca_encrypt_update(ctx, None, plaintext, None,
                                 _ctypes.byref(_ctypes.c_size_t()))
        return

    output_length = _context_get_output_length(ctx, len(plaintext))
    ciphertext = _ctypes.create_string_buffer(output_length)
    ciphertext_length = _ctypes.c_size_t()
    _lib.yaca_encrypt_update(ctx, plaintext, len(plaintext),
                             ciphertext, _ctypes.byref(ciphertext_length))
    return bytes(ciphertext[:ciphertext_length.value])


def encrypt_finalize(ctx):
    """Encrypts the final chunk of the data."""
    output_length = _context_get_output_length(ctx, 0)
    ciphertext = _ctypes.create_string_buffer(output_length)
    ciphertext_length = _ctypes.c_size_t()
    _lib.yaca_encrypt_finalize(ctx, ciphertext,
                               _ctypes.byref(ciphertext_length))
    return bytes(ciphertext[:ciphertext_length.value])


def decrypt_initialize(sym_key, encrypt_algo=ENCRYPT_ALGORITHM.AES,
                       bcm=BLOCK_CIPHER_MODE.ECB, iv=KEY_NULL):
    """Initializes an decryption context."""
    ctx = _ctypes.c_void_p()
    _lib.yaca_decrypt_initialize(_ctypes.byref(ctx), encrypt_algo.value,
                                 bcm.value, sym_key, iv)
    return Context(ctx)


def decrypt_update(ctx, ciphertext):
    """Decrypts chunk of the data.
    Alternatively ciphertext can be the total length of the input (int).
    This is used for CCM_AAD."""
    if isinstance(ciphertext, int):  # the case of using AAD in CCM
        _lib.yaca_decrypt_update(ctx, None, ciphertext, None,
                                 _ctypes.byref(_ctypes.c_size_t()))
        return

    output_length = _context_get_output_length(ctx, len(ciphertext))
    plaintext = _ctypes.create_string_buffer(output_length)
    plaintext_length = _ctypes.c_size_t()
    _lib.yaca_decrypt_update(ctx, ciphertext, len(ciphertext),
                             plaintext, _ctypes.byref(plaintext_length))
    return bytes(plaintext[:plaintext_length.value])


def decrypt_finalize(ctx):
    """Encrypts the final chunk of the data."""
    output_length = _context_get_output_length(ctx, 0)
    plaintext = _ctypes.create_string_buffer(output_length)
    plaintext_length = _ctypes.c_size_t()
    _lib.yaca_decrypt_finalize(ctx, plaintext,
                               _ctypes.byref(plaintext_length))
    return bytes(plaintext[:plaintext_length.value])


# Implementation sign

def sign_initialize(prv_key, digest_algo=DIGEST_ALGORITHM.SHA256):
    """Initializes a signature context for asymmetric signatures."""
    ctx = _ctypes.c_void_p()
    _lib.yaca_sign_initialize(_ctypes.byref(ctx), digest_algo.value,
                              prv_key)
    return Context(ctx)


def sign_initialize_hmac(sym_key, digest_algo=DIGEST_ALGORITHM.SHA256):
    """Initializes a signature context for HMAC."""
    ctx = _ctypes.c_void_p()
    _lib.yaca_sign_initialize_hmac(_ctypes.byref(ctx),
                                   digest_algo.value, sym_key)
    return Context(ctx)


def sign_initialize_cmac(sym_key, encrypt_algo=ENCRYPT_ALGORITHM.AES):
    """Initializes a signature context for CMAC."""
    ctx = _ctypes.c_void_p()
    _lib.yaca_sign_initialize_cmac(_ctypes.byref(ctx),
                                   encrypt_algo.value, sym_key)
    return Context(ctx)


def sign_update(ctx, message):
    """Feeds the message into the digital signature or MAC algorithm."""
    _lib.yaca_sign_update(ctx, message, len(message))


def sign_finalize(ctx):
    """Calculates the final signature or MAC."""
    output_length = _context_get_output_length(ctx, 0)
    signature = _ctypes.create_string_buffer(output_length)
    signature_len = _ctypes.c_size_t()
    _lib.yaca_sign_finalize(ctx, signature, _ctypes.byref(signature_len))
    return bytes(signature[:signature_len.value])


def verify_initialize(pub_key, digest_algo=DIGEST_ALGORITHM.SHA256):
    """Initializes a signature verification context for asymmetric signatures.
    """
    ctx = _ctypes.c_void_p()
    _lib.yaca_verify_initialize(_ctypes.byref(ctx), digest_algo.value,
                                pub_key)
    return Context(ctx)


def verify_update(ctx, message):
    """Feeds the message into the digital signature verification algorithm."""
    _lib.yaca_verify_update(ctx, message, len(message))


def verify_finalize(ctx, signature):
    """Performs the verification."""
    return _lib.yaca_verify_finalize(ctx, signature, len(signature))


# Implementation seal

def seal_initialize(pub_key, sym_key_bit_length=KEY_BIT_LENGTH.L256BIT,
                    encrypt_algo=ENCRYPT_ALGORITHM.AES,
                    bcm=BLOCK_CIPHER_MODE.ECB):
    ctx = _ctypes.c_void_p()
    sym_key = _ctypes.c_void_p()
    iv = _ctypes.c_void_p()
    _lib.yaca_seal_initialize(_ctypes.byref(ctx), pub_key,
                              encrypt_algo.value, bcm.value,
                              sym_key_bit_length, _ctypes.byref(sym_key),
                              _ctypes.byref(iv))
    return Context(ctx), Key(sym_key), Key(iv)


def seal_update(ctx, plaintext):
    """Encrypts piece of the data."""
    output_length = _context_get_output_length(ctx, len(plaintext))
    ciphertext = _ctypes.create_string_buffer(output_length)
    ciphertext_length = _ctypes.c_size_t()
    _lib.yaca_seal_update(ctx, plaintext, len(plaintext),
                          ciphertext, _ctypes.byref(ciphertext_length))
    return bytes(ciphertext[:ciphertext_length.value])


def seal_finalize(ctx):
    """Encrypts the final piece of the data."""
    output_length = _context_get_output_length(ctx, 0)
    ciphertext = _ctypes.create_string_buffer(output_length)
    ciphertext_length = _ctypes.c_size_t()
    _lib.yaca_seal_finalize(ctx, ciphertext,
                            _ctypes.byref(ciphertext_length))
    return bytes(ciphertext[:ciphertext_length.value])


def open_initialize(prv_key, sym_key, iv=KEY_NULL,
                    sym_key_bit_length=KEY_BIT_LENGTH.L256BIT,
                    encrypt_algo=ENCRYPT_ALGORITHM.AES,
                    bcm=BLOCK_CIPHER_MODE.ECB):
    """Initializes an asymmetric decryption context."""
    ctx = _ctypes.c_void_p()
    _lib.yaca_open_initialize(_ctypes.byref(ctx), prv_key,
                              encrypt_algo.value, bcm.value,
                              sym_key_bit_length, sym_key, iv)
    return Context(ctx)


def open_update(ctx, ciphertext):
    """Decrypts piece of the data."""
    output_length = _context_get_output_length(ctx, len(ciphertext))
    plaintext = _ctypes.create_string_buffer(output_length)
    plaintext_length = _ctypes.c_size_t()
    _lib.yaca_open_update(ctx, ciphertext, len(ciphertext),
                          plaintext, _ctypes.byref(plaintext_length))
    return bytes(plaintext[:plaintext_length.value])


def open_finalize(ctx):
    """Decrypts last chunk of sealed message."""
    output_length = _context_get_output_length(ctx, 0)
    plaintext = _ctypes.create_string_buffer(output_length)
    plaintext_length = _ctypes.c_size_t()
    _lib.yaca_open_finalize(ctx, plaintext,
                            _ctypes.byref(plaintext_length))
    return bytes(plaintext[:plaintext_length.value])


# Implementation rsa

def rsa_public_encrypt(pub_key, plaintext, padding=PADDING.PKCS1):
    """Encrypts data using a RSA public key (low-level encrypt equivalent)."""
    ciphertext = _ctypes.POINTER(_ctypes.c_char)()
    ciphertext_length = _ctypes.c_size_t()
    plaintext_param = _get_char_param_nullify_if_zero(plaintext)
    _lib.yaca_rsa_public_encrypt(padding.value, pub_key, plaintext_param,
                                 len(plaintext),
                                 _ctypes.byref(ciphertext),
                                 _ctypes.byref(ciphertext_length))
    ciphertext_bytes = ciphertext[:ciphertext_length.value]
    _lib.yaca_free(ciphertext)
    return ciphertext_bytes


def rsa_private_decrypt(prv_key, ciphertext, padding=PADDING.PKCS1):
    """Decrypts data using a RSA private key (low-level decrypt equivalent)."""
    plaintext = _ctypes.POINTER(_ctypes.c_char)()
    plaintext_length = _ctypes.c_size_t()
    ciphertext_param = _get_char_param_nullify_if_zero(ciphertext)
    _lib.yaca_rsa_private_decrypt(padding.value, prv_key,
                                  ciphertext_param, len(ciphertext),
                                  _ctypes.byref(plaintext),
                                  _ctypes.byref(plaintext_length))
    plaintext_bytes = plaintext[:plaintext_length.value]
    _lib.yaca_free(plaintext)
    return plaintext_bytes


def rsa_private_encrypt(prv_key, plaintext, padding=PADDING.PKCS1):
    """Encrypts data using a RSA private key (low-level sign equivalent)."""
    ciphertext = _ctypes.POINTER(_ctypes.c_char)()
    ciphertext_length = _ctypes.c_size_t()
    plaintext_param = _get_char_param_nullify_if_zero(plaintext)
    _lib.yaca_rsa_private_encrypt(padding.value, prv_key,
                                  plaintext_param, len(plaintext),
                                  _ctypes.byref(ciphertext),
                                  _ctypes.byref(ciphertext_length))
    ciphertext_bytes = ciphertext[:ciphertext_length.value]
    _lib.yaca_free(ciphertext)
    return ciphertext_bytes


def rsa_public_decrypt(pub_key, ciphertext, padding=PADDING.PKCS1):
    """Decrypts data using a RSA public key (low-level verify equivalent)."""
    plaintext = _ctypes.POINTER(_ctypes.c_char)()
    plaintext_length = _ctypes.c_size_t()
    ciphertext_param = _get_char_param_nullify_if_zero(ciphertext)
    _lib.yaca_rsa_public_decrypt(padding.value, pub_key,
                                 ciphertext_param, len(ciphertext),
                                 _ctypes.byref(plaintext),
                                 _ctypes.byref(plaintext_length))
    plaintext_bytes = plaintext[:plaintext_length.value]
    _lib.yaca_free(plaintext)
    return plaintext_bytes
