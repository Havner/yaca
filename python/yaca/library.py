# Copyright (c) 2017-2018 Samsung Electronics Co., Ltd All Rights Reserved

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


import ctypes as _ctypes
import enum as _enum
import yaca.error as _err


@_enum.unique
class _Error(_enum.Enum):
    __TIZEN_YACA_BASE = -0x01E30000
    NONE = 0
    INVALID_PARAMETER = -22
    OUT_OF_MEMORY = -12
    INTERNAL = __TIZEN_YACA_BASE | 0x01
    DATA_MISMATCH = __TIZEN_YACA_BASE | 0x02
    INVALID_PASSWORD = __TIZEN_YACA_BASE | 0x03


def _errcheck(ret, func, arguments):
    if ret == _Error.NONE.value:
        return True
    elif ret == _Error.DATA_MISMATCH.value:
        return False
    elif ret == _Error.INVALID_PARAMETER.value:
        raise _err.InvalidParameterError(
            'Invalid Parameter error returned from YACA')
    elif ret == _Error.OUT_OF_MEMORY.value:
        raise _err.OutOfMemoryError('Out Of Memory error returned from YACA')
    elif ret == _Error.INTERNAL.value:
        raise _err.InternalError('Internal error returned from YACA')
    elif ret == _Error.INVALID_PASSWORD.value:
        raise _err.InvalidPasswordError(
            'Invalid Password error returned from YACA')
    else:
        raise RuntimeError('Unknown error returned from YACA')


def get_yaca():
    """Get C library and set argtypes"""

    lib = _ctypes.CDLL("libyaca.so.0")

    # crypto
    lib.yaca_initialize.argtypes = []
    lib.yaca_initialize.errcheck = _errcheck
    lib.yaca_cleanup.argtypes = []
    lib.yaca_cleanup.restype = None
    lib.yaca_malloc.argtypes = \
        [_ctypes.c_size_t, _ctypes.POINTER(_ctypes.c_void_p)]
    lib.yaca_malloc.errcheck = _errcheck
    lib.yaca_zalloc.argtypes = \
        [_ctypes.c_size_t, _ctypes.POINTER(_ctypes.c_void_p)]
    lib.yaca_zalloc.errcheck = _errcheck
    lib.yaca_realloc.argtypes = \
        [_ctypes.c_size_t, _ctypes.POINTER(_ctypes.c_void_p)]
    lib.yaca_realloc.errcheck = _errcheck
    lib.yaca_free.argtypes = [_ctypes.c_void_p]
    lib.yaca_free.restype = None
    lib.yaca_memcmp.argtypes = \
        [_ctypes.POINTER(_ctypes.c_char), _ctypes.POINTER(_ctypes.c_char),
         _ctypes.c_size_t]
    lib.yaca_memcmp.errcheck = _errcheck
    lib.yaca_randomize_bytes.argtypes = \
        [_ctypes.POINTER(_ctypes.c_char), _ctypes.c_size_t]
    lib.yaca_randomize_bytes.errcheck = _errcheck
    lib.yaca_context_set_property.argtypes = \
        [_ctypes.c_void_p, _ctypes.c_int, _ctypes.c_void_p, _ctypes.c_size_t]
    lib.yaca_context_set_property.errcheck = _errcheck
    lib.yaca_context_get_property.argtypes = \
        [_ctypes.c_void_p, _ctypes.c_int, _ctypes.POINTER(_ctypes.c_void_p),
         _ctypes.POINTER(_ctypes.c_size_t)]
    lib.yaca_context_get_property.errcheck = _errcheck
    lib.yaca_context_get_output_length.argtypes = \
        [_ctypes.c_void_p, _ctypes.c_size_t, _ctypes.POINTER(_ctypes.c_size_t)]
    lib.yaca_context_get_output_length.errcheck = _errcheck
    lib.yaca_context_destroy.argtypes = [_ctypes.c_void_p]
    lib.yaca_context_destroy.restype = None

    # simple
    lib.yaca_simple_encrypt.argtypes = \
        [_ctypes.c_int, _ctypes.c_int, _ctypes.c_void_p, _ctypes.c_void_p,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.c_size_t,
         _ctypes.POINTER(_ctypes.POINTER(_ctypes.c_char)),
         _ctypes.POINTER(_ctypes.c_size_t)]
    lib.yaca_simple_encrypt.errcheck = _errcheck
    lib.yaca_simple_decrypt.argtypes = \
        [_ctypes.c_int, _ctypes.c_int, _ctypes.c_void_p, _ctypes.c_void_p,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.c_size_t,
         _ctypes.POINTER(_ctypes.POINTER(_ctypes.c_char)),
         _ctypes.POINTER(_ctypes.c_size_t)]
    lib.yaca_simple_decrypt.errcheck = _errcheck
    lib.yaca_simple_calculate_digest.argtypes = \
        [_ctypes.c_int, _ctypes.POINTER(_ctypes.c_char), _ctypes.c_size_t,
         _ctypes.POINTER(_ctypes.POINTER(_ctypes.c_char)),
         _ctypes.POINTER(_ctypes.c_size_t)]
    lib.yaca_simple_calculate_digest.errcheck = _errcheck
    lib.yaca_simple_calculate_signature.argtypes = \
        [_ctypes.c_int, _ctypes.c_void_p,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.c_size_t,
         _ctypes.POINTER(_ctypes.POINTER(_ctypes.c_char)),
         _ctypes.POINTER(_ctypes.c_size_t)]
    lib.yaca_simple_calculate_signature.errcheck = _errcheck
    lib.yaca_simple_verify_signature.argtypes = \
        [_ctypes.c_int, _ctypes.c_void_p,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.c_size_t,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.c_size_t]
    lib.yaca_simple_verify_signature.errcheck = _errcheck
    lib.yaca_simple_calculate_hmac.argtypes = \
        [_ctypes.c_int, _ctypes.c_void_p,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.c_size_t,
         _ctypes.POINTER(_ctypes.POINTER(_ctypes.c_char)),
         _ctypes.POINTER(_ctypes.c_size_t)]
    lib.yaca_simple_calculate_hmac.errcheck = _errcheck
    lib.yaca_simple_calculate_cmac.argtypes = \
        [_ctypes.c_int, _ctypes.c_void_p,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.c_size_t,
         _ctypes.POINTER(_ctypes.POINTER(_ctypes.c_char)),
         _ctypes.POINTER(_ctypes.c_size_t)]
    lib.yaca_simple_calculate_cmac.errcheck = _errcheck

    # key
    lib.yaca_key_get_type.argtypes = \
        [_ctypes.c_void_p, _ctypes.POINTER(_ctypes.c_int)]
    lib.yaca_key_get_type.errcheck = _errcheck
    lib.yaca_key_get_bit_length.argtypes = \
        [_ctypes.c_void_p, _ctypes.POINTER(_ctypes.c_size_t)]
    lib.yaca_key_get_bit_length.errcheck = _errcheck
    lib.yaca_key_import.argtypes = \
        [_ctypes.c_int, _ctypes.c_char_p,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.c_size_t,
         _ctypes.POINTER(_ctypes.c_void_p)]
    lib.yaca_key_import.errcheck = _errcheck
    lib.yaca_key_export.argtypes = \
        [_ctypes.c_void_p, _ctypes.c_int, _ctypes.c_int, _ctypes.c_char_p,
         _ctypes.POINTER(_ctypes.POINTER(_ctypes.c_char)),
         _ctypes.POINTER(_ctypes.c_size_t)]
    lib.yaca_key_export.errcheck = _errcheck
    lib.yaca_key_generate.argtypes = \
        [_ctypes.c_void_p, _ctypes.c_size_t, _ctypes.POINTER(_ctypes.c_void_p)]
    lib.yaca_key_generate.errcheck = _errcheck
    lib.yaca_key_generate_from_parameters.argtypes = \
        [_ctypes.c_void_p, _ctypes.POINTER(_ctypes.c_void_p)]
    lib.yaca_key_generate_from_parameters.errcheck = _errcheck
    lib.yaca_key_extract_public.argtypes = \
        [_ctypes.c_void_p, _ctypes.POINTER(_ctypes.c_void_p)]
    lib.yaca_key_extract_public.errcheck = _errcheck
    lib.yaca_key_extract_parameters.argtypes = \
        [_ctypes.c_void_p, _ctypes.POINTER(_ctypes.c_void_p)]
    lib.yaca_key_extract_parameters.errcheck = _errcheck
    lib.yaca_key_derive_dh.argtypes = \
        [_ctypes.c_void_p, _ctypes.c_void_p,
         _ctypes.POINTER(_ctypes.POINTER(_ctypes.c_char)),
         _ctypes.POINTER(_ctypes.c_size_t)]
    lib.yaca_key_derive_dh.errcheck = _errcheck
    lib.yaca_key_derive_kdf.argtypes = \
        [_ctypes.c_int, _ctypes.c_int,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.c_size_t,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.c_size_t,
         _ctypes.c_size_t, _ctypes.POINTER(_ctypes.POINTER(_ctypes.c_char))]
    lib.yaca_key_derive_kdf.errcheck = _errcheck
    lib.yaca_key_derive_pbkdf2.argtypes = \
        [_ctypes.c_char_p, _ctypes.POINTER(_ctypes.c_char), _ctypes.c_size_t,
         _ctypes.c_size_t, _ctypes.c_int,
         _ctypes.c_size_t, _ctypes.POINTER(_ctypes.c_void_p)]
    lib.yaca_key_derive_pbkdf2.errcheck = _errcheck
    lib.yaca_key_destroy.argtypes = [_ctypes.c_void_p]
    lib.yaca_key_destroy.restype = None

    # digest
    lib.yaca_digest_initialize.argtypes = \
        [_ctypes.POINTER(_ctypes.c_void_p), _ctypes.c_int]
    lib.yaca_digest_initialize.errcheck = _errcheck
    lib.yaca_digest_update.argtypes = \
        [_ctypes.c_void_p, _ctypes.POINTER(_ctypes.c_char), _ctypes.c_size_t]
    lib.yaca_digest_update.errcheck = _errcheck
    lib.yaca_digest_finalize.argtypes = \
        [_ctypes.c_void_p,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.POINTER(_ctypes.c_size_t)]
    lib.yaca_digest_finalize.errcheck = _errcheck

    # encrypt
    lib.yaca_encrypt_get_iv_bit_length.argtypes = \
        [_ctypes.c_int, _ctypes.c_int, _ctypes.c_size_t,
         _ctypes.POINTER(_ctypes.c_size_t)]
    lib.yaca_encrypt_get_iv_bit_length.errcheck = _errcheck
    lib.yaca_encrypt_initialize.argtypes = \
        [_ctypes.POINTER(_ctypes.c_void_p), _ctypes.c_int, _ctypes.c_int,
         _ctypes.c_void_p, _ctypes.c_void_p]
    lib.yaca_encrypt_initialize.errcheck = _errcheck
    lib.yaca_encrypt_update.argtypes = \
        [_ctypes.c_void_p,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.c_size_t,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.POINTER(_ctypes.c_size_t)]
    lib.yaca_encrypt_update.errcheck = _errcheck
    lib.yaca_encrypt_finalize.argtypes = \
        [_ctypes.c_void_p,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.POINTER(_ctypes.c_size_t)]
    lib.yaca_encrypt_finalize.errcheck = _errcheck
    lib.yaca_decrypt_initialize.argtypes = \
        [_ctypes.POINTER(_ctypes.c_void_p), _ctypes.c_int, _ctypes.c_int,
         _ctypes.c_void_p, _ctypes.c_void_p]
    lib.yaca_decrypt_initialize.errcheck = _errcheck
    lib.yaca_decrypt_update.argtypes = \
        [_ctypes.c_void_p,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.c_size_t,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.POINTER(_ctypes.c_size_t)]
    lib.yaca_decrypt_update.errcheck = _errcheck
    lib.yaca_decrypt_finalize.argtypes = \
        [_ctypes.c_void_p,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.POINTER(_ctypes.c_size_t)]
    lib.yaca_decrypt_finalize.errcheck = _errcheck

    # sign
    lib.yaca_sign_initialize.argtypes = \
        [_ctypes.POINTER(_ctypes.c_void_p), _ctypes.c_int, _ctypes.c_void_p]
    lib.yaca_sign_initialize.errcheck = _errcheck
    lib.yaca_sign_initialize_hmac.argtypes = \
        [_ctypes.POINTER(_ctypes.c_void_p), _ctypes.c_int, _ctypes.c_void_p]
    lib.yaca_sign_initialize_hmac.errcheck = _errcheck
    lib.yaca_sign_initialize_cmac.argtypes = \
        [_ctypes.POINTER(_ctypes.c_void_p), _ctypes.c_int, _ctypes.c_void_p]
    lib.yaca_sign_initialize_cmac.errcheck = _errcheck
    lib.yaca_sign_update.argtypes = \
        [_ctypes.c_void_p, _ctypes.POINTER(_ctypes.c_char), _ctypes.c_size_t]
    lib.yaca_sign_update.errcheck = _errcheck
    lib.yaca_sign_finalize.argtypes = \
        [_ctypes.c_void_p,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.POINTER(_ctypes.c_size_t)]
    lib.yaca_sign_finalize.errcheck = _errcheck
    lib.yaca_verify_initialize.argtypes = \
        [_ctypes.POINTER(_ctypes.c_void_p), _ctypes.c_int, _ctypes.c_void_p]
    lib.yaca_verify_initialize.errcheck = _errcheck
    lib.yaca_verify_update.argtypes = \
        [_ctypes.c_void_p, _ctypes.POINTER(_ctypes.c_char), _ctypes.c_size_t]
    lib.yaca_verify_update.errcheck = _errcheck
    lib.yaca_verify_finalize.argtypes = \
        [_ctypes.c_void_p, _ctypes.POINTER(_ctypes.c_char), _ctypes.c_size_t]
    lib.yaca_verify_finalize.errcheck = _errcheck

    # seal
    lib.yaca_seal_initialize.argtypes = \
        [_ctypes.POINTER(_ctypes.c_void_p), _ctypes.c_void_p, _ctypes.c_int,
         _ctypes.c_int, _ctypes.c_size_t, _ctypes.POINTER(_ctypes.c_void_p),
         _ctypes.POINTER(_ctypes.c_void_p)]
    lib.yaca_seal_initialize.errcheck = _errcheck
    lib.yaca_seal_update.argtypes = \
        [_ctypes.c_void_p, _ctypes.POINTER(_ctypes.c_char), _ctypes.c_size_t,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.POINTER(_ctypes.c_size_t)]
    lib.yaca_seal_update.errcheck = _errcheck
    lib.yaca_seal_finalize.argtypes = \
        [_ctypes.c_void_p,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.POINTER(_ctypes.c_size_t)]
    lib.yaca_seal_finalize.errcheck = _errcheck
    lib.yaca_open_initialize.argtypes = \
        [_ctypes.POINTER(_ctypes.c_void_p), _ctypes.c_void_p, _ctypes.c_int,
         _ctypes.c_int, _ctypes.c_size_t, _ctypes.c_void_p, _ctypes.c_void_p]
    lib.yaca_open_initialize.errcheck = _errcheck
    lib.yaca_open_update.argtypes = \
        [_ctypes.c_void_p,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.c_size_t,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.POINTER(_ctypes.c_size_t)]
    lib.yaca_open_update.errcheck = _errcheck
    lib.yaca_open_finalize.argtypes = \
        [_ctypes.c_void_p,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.POINTER(_ctypes.c_size_t)]
    lib.yaca_open_finalize.errcheck = _errcheck

    # rsa
    rsa_argtypes = \
        [_ctypes.c_int, _ctypes.c_void_p,
         _ctypes.POINTER(_ctypes.c_char), _ctypes.c_size_t,
         _ctypes.POINTER(_ctypes.POINTER(_ctypes.c_char)),
         _ctypes.POINTER(_ctypes.c_size_t)]
    lib.yaca_rsa_public_encrypt.argtypes = rsa_argtypes
    lib.yaca_rsa_public_encrypt.errcheck = _errcheck
    lib.yaca_rsa_private_decrypt.argtypes = rsa_argtypes
    lib.yaca_rsa_private_decrypt.errcheck = _errcheck
    lib.yaca_rsa_private_encrypt.argtypes = rsa_argtypes
    lib.yaca_rsa_private_encrypt.errcheck = _errcheck
    lib.yaca_rsa_public_decrypt.argtypes = rsa_argtypes
    lib.yaca_rsa_public_decrypt.errcheck = _errcheck

    return lib
