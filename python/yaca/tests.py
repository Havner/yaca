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


"""
These tests are not to test yaca itself. They are more of a
syntax test to see that no stupid mistakes has been made in the
python binding. To check whether the code runs properly and
returns expected things.

They can also be used as examples.
"""

import yaca


def split_into_parts(data, l):
    return [data[i:i + l] for i in range(0, len(data), l)]


msg = b'Lorem ipsum dolor sit amet, consectetuer adipiscing elit. \
Donec hendrerit tempor tellus.  Donec pretium posuere tellus.  Proin \
quam nisl, tincidunt et, mattis eget, convallis nec, purus.  Cum \
sociis natoque penatibus et magnis dis parturient montes, nascetur \
ridiculus mus.  Nulla posuere.  Donec vitae dolor.  Nullam tristique \
diam non turpis.  Cras placerat accumsan nulla.  Nullam rutrum.  Nam \
vestibulum accumsan nisl.'

msg_parts = split_into_parts(msg, 5)


def run_all_tests():
    """Runs all YACA tests/examples. No exceptions means success."""

    yaca.initialize()

    crypto()
    key_gen()
    key_exp_imp()
    key_derive()
    simple()
    digest()
    encrypt_basic()
    encrypt_rc2_property()
    encrypt_gcm_property()
    encrypt_ccm_property()
    sign()
    seal()
    rsa()

    yaca.cleanup()


def crypto():

    msg_whole = b''
    for part in msg_parts:
        msg_whole += part

    assert yaca.memcmp(msg, msg_whole, len(msg))

    rand_bytes = yaca.random_bytes(50)
    assert len(rand_bytes) == 50


def key_gen():

    key_iv_64 = yaca.key_generate(yaca.KEY_TYPE.IV,
                                  yaca.KEY_BIT_LENGTH.IV_64BIT)
    assert key_iv_64.get_type() == yaca.KEY_TYPE.IV
    assert key_iv_64.get_bit_length() == yaca.KEY_BIT_LENGTH.IV_64BIT

    key_iv_128 = yaca.key_generate(yaca.KEY_TYPE.IV,
                                   yaca.KEY_BIT_LENGTH.IV_128BIT)
    assert key_iv_128.get_type() == yaca.KEY_TYPE.IV
    assert key_iv_128.get_bit_length() == yaca.KEY_BIT_LENGTH.IV_128BIT

    key_sym = yaca.key_generate()
    assert key_sym.get_type() == yaca.KEY_TYPE.SYMMETRIC
    assert key_sym.get_bit_length() == yaca.KEY_BIT_LENGTH.L256BIT

    key_rsa_prv = yaca.key_generate(yaca.KEY_TYPE.RSA_PRIV,
                                    yaca.KEY_BIT_LENGTH.L2048BIT)
    assert key_rsa_prv.get_type() == yaca.KEY_TYPE.RSA_PRIV
    assert key_rsa_prv.get_bit_length() == yaca.KEY_BIT_LENGTH.L2048BIT

    key_rsa_pub = yaca.key_extract_public(key_rsa_prv)
    assert key_rsa_pub.get_type() == yaca.KEY_TYPE.RSA_PUB
    assert key_rsa_pub.get_bit_length() == yaca.KEY_BIT_LENGTH.L2048BIT

    key_dsa_prv = yaca.key_generate(yaca.KEY_TYPE.DSA_PRIV,
                                    yaca.KEY_BIT_LENGTH.L2048BIT)
    assert key_dsa_prv.get_type() == yaca.KEY_TYPE.DSA_PRIV
    assert key_dsa_prv.get_bit_length() == yaca.KEY_BIT_LENGTH.L2048BIT

    key_dsa_pub = yaca.key_extract_public(key_dsa_prv)
    assert key_dsa_pub.get_type() == yaca.KEY_TYPE.DSA_PUB
    assert key_dsa_pub.get_bit_length() == yaca.KEY_BIT_LENGTH.L2048BIT

    key_dh_prv = yaca.key_generate(yaca.KEY_TYPE.DH_PRIV,
                                   yaca.KEY_BIT_LENGTH_DH_RFC.L2048_256)
    assert key_dh_prv.get_type() == yaca.KEY_TYPE.DH_PRIV
    assert key_dh_prv.get_bit_length() == 2048

    key_dh_pub = yaca.key_extract_public(key_dh_prv)
    assert key_dh_pub.get_type() == yaca.KEY_TYPE.DH_PUB
    assert key_dh_pub.get_bit_length() == 2048

    key_dh_params = yaca.key_extract_parameters(key_dh_prv)
    key_dh_prv_2 = yaca.key_generate_from_parameters(key_dh_params)
    assert key_dh_prv_2.get_type() == key_dh_prv.get_type()
    assert key_dh_prv_2.get_bit_length() == key_dh_prv.get_bit_length()

    key_dh_prv_3 = yaca.key_generate(yaca.KEY_TYPE.DH_PRIV,
                                     yaca.KEY_LENGTH_DH_GENERATOR_5 | 256)
    assert key_dh_prv_3.get_type() == yaca.KEY_TYPE.DH_PRIV
    assert key_dh_prv_3.get_bit_length() == 256

    key_ec_prv = yaca.key_generate(yaca.KEY_TYPE.EC_PRIV,
                                   yaca.KEY_BIT_LENGTH_EC.PRIME256V1)
    assert key_ec_prv.get_type() == yaca.KEY_TYPE.EC_PRIV
    assert key_ec_prv.get_bit_length() == yaca.KEY_BIT_LENGTH_EC.PRIME256V1

    key_ec_pub = yaca.key_extract_public(key_ec_prv)
    assert key_ec_pub.get_type() == yaca.KEY_TYPE.EC_PUB
    assert key_ec_pub.get_bit_length() == yaca.KEY_BIT_LENGTH_EC.PRIME256V1


def key_exp_imp():
    # prepare:
    key_sym = yaca.key_generate()
    key_rsa_prv = yaca.key_generate(yaca.KEY_TYPE.RSA_PRIV,
                                    yaca.KEY_BIT_LENGTH.L2048BIT)
    # end prepare

    key_sym_exp = yaca.key_export(key_sym)
    key_sym_imp = yaca.key_import(key_sym_exp)
    assert key_sym.get_type() == key_sym_imp.get_type()
    assert key_sym.get_bit_length() == key_sym_imp.get_bit_length()

    key_rsa_prv_exp = yaca.key_export(key_rsa_prv, yaca.KEY_FILE_FORMAT.PEM)
    key_rsa_prv_imp = yaca.key_import(key_rsa_prv_exp, yaca.KEY_TYPE.RSA_PRIV)
    assert key_rsa_prv.get_type() == key_rsa_prv_imp.get_type()
    assert key_rsa_prv.get_bit_length() == key_rsa_prv_imp.get_bit_length()

    key_rsa_prv_exp = yaca.key_export(key_rsa_prv, yaca.KEY_FILE_FORMAT.PEM,
                                      yaca.KEY_FORMAT.PKCS8, b"password")
    key_rsa_prv_imp = yaca.key_import(key_rsa_prv_exp, yaca.KEY_TYPE.RSA_PRIV,
                                      b"password")
    assert key_rsa_prv.get_type() == key_rsa_prv_imp.get_type()
    assert key_rsa_prv.get_bit_length() == key_rsa_prv_imp.get_bit_length()


def key_derive():
    # prepare:
    key_dh_prv = yaca.key_generate(yaca.KEY_TYPE.DH_PRIV,
                                   yaca.KEY_BIT_LENGTH_DH_RFC.L2048_256)
    key_dh_pub = yaca.key_extract_public(key_dh_prv)
    key_dh_params = yaca.key_extract_parameters(key_dh_prv)
    key_dh_prv_2 = yaca.key_generate_from_parameters(key_dh_params)
    key_dh_pub_2 = yaca.key_extract_public(key_dh_prv_2)
    # end prepare

    secret = yaca.key_derive_dh(key_dh_prv_2, key_dh_pub)
    assert len(secret) == 256

    secret_2 = yaca.key_derive_dh(key_dh_prv, key_dh_pub_2)
    assert secret == secret_2

    key_material = yaca.key_derive_kdf(secret, 128)
    assert len(key_material) == 128

    key_derived = yaca.key_derive_pbkdf2(b'password')
    assert key_derived.get_type() == yaca.KEY_TYPE.SYMMETRIC
    assert key_derived.get_bit_length() == yaca.KEY_BIT_LENGTH.L256BIT


def simple():
    # prepare:
    key_sym = yaca.key_generate()
    key_iv_128 = yaca.key_generate(yaca.KEY_TYPE.IV,
                                   yaca.KEY_BIT_LENGTH.IV_128BIT)
    key_rsa_prv = yaca.key_generate(yaca.KEY_TYPE.RSA_PRIV,
                                    yaca.KEY_BIT_LENGTH.L2048BIT)
    key_rsa_pub = yaca.key_extract_public(key_rsa_prv)
    # end prepare

    enc_simple = yaca.simple_encrypt(key_sym, msg,
                                     yaca.ENCRYPT_ALGORITHM.AES,
                                     yaca.BLOCK_CIPHER_MODE.CBC, key_iv_128)
    dec_simple = yaca.simple_decrypt(key_sym, enc_simple,
                                     yaca.ENCRYPT_ALGORITHM.AES,
                                     yaca.BLOCK_CIPHER_MODE.CBC, key_iv_128)
    assert msg == dec_simple

    dgst_simple = yaca.simple_calculate_digest(msg,
                                               yaca.DIGEST_ALGORITHM.SHA512)
    assert len(dgst_simple) == 64

    hmac_simple = yaca.simple_calculate_hmac(key_sym, msg,
                                             yaca.DIGEST_ALGORITHM.SHA512)
    assert len(hmac_simple) == 64

    cmac_simple = yaca.simple_calculate_cmac(key_sym, msg,
                                             yaca.ENCRYPT_ALGORITHM.AES)
    assert len(cmac_simple) == 16

    sig_simple = yaca.simple_calculate_signature(key_rsa_prv, msg,
                                                 yaca.DIGEST_ALGORITHM.SHA512)
    assert yaca.simple_verify_signature(key_rsa_pub, msg, sig_simple,
                                        yaca.DIGEST_ALGORITHM.SHA512)


def digest():
    # prepare:
    dgst_simple = yaca.simple_calculate_digest(msg,
                                               yaca.DIGEST_ALGORITHM.SHA512)
    # end prepare

    ctx = yaca.digest_initialize(yaca.DIGEST_ALGORITHM.SHA512)
    for part in msg_parts:
        yaca.digest_update(ctx, part)
    dgst = yaca.digest_finalize(ctx)

    assert dgst == dgst_simple


def encrypt_basic():
    # prepare:
    key_sym = yaca.key_generate()
    key_iv_128 = yaca.key_generate(yaca.KEY_TYPE.IV,
                                   yaca.KEY_BIT_LENGTH.IV_128BIT)
    enc_simple = yaca.simple_encrypt(key_sym, msg,
                                     yaca.ENCRYPT_ALGORITHM.AES,
                                     yaca.BLOCK_CIPHER_MODE.CBC, key_iv_128)
    # end prepare

    len_iv = yaca.encrypt_get_iv_bit_length(yaca.ENCRYPT_ALGORITHM.AES,
                                            yaca.BLOCK_CIPHER_MODE.CBC,
                                            yaca.KEY_BIT_LENGTH.L256BIT)
    assert len_iv == 128

    ctx = yaca.encrypt_initialize(key_sym, bcm=yaca.BLOCK_CIPHER_MODE.CBC,
                                  iv=key_iv_128)
    enc = b''
    for part in msg_parts:
        enc += yaca.encrypt_update(ctx, part)
    enc += yaca.encrypt_finalize(ctx)

    assert enc == enc_simple

    enc_parts = split_into_parts(enc, 5)

    ctx = yaca.decrypt_initialize(key_sym, bcm=yaca.BLOCK_CIPHER_MODE.CBC,
                                  iv=key_iv_128)
    dec = b''
    for part in enc_parts:
        dec += yaca.decrypt_update(ctx, part)
    dec += yaca.decrypt_finalize(ctx)

    assert msg == dec


def encrypt_rc2_property():
    # prepare:
    key_sym = yaca.key_generate()
    # end prepare

    len_iv = yaca.encrypt_get_iv_bit_length(yaca.ENCRYPT_ALGORITHM.UNSAFE_RC2,
                                            yaca.BLOCK_CIPHER_MODE.ECB,
                                            yaca.KEY_BIT_LENGTH.L256BIT)
    assert len_iv == 0

    ctx = yaca.encrypt_initialize(key_sym, yaca.ENCRYPT_ALGORITHM.UNSAFE_RC2,
                                  yaca.BLOCK_CIPHER_MODE.ECB)
    yaca.context_set_property(ctx, yaca.PROPERTY.RC2_EFFECTIVE_KEY_BITS, 192)
    enc = b''
    for part in msg_parts:
        enc += yaca.encrypt_update(ctx, part)
    enc += yaca.encrypt_finalize(ctx)

    enc_parts = split_into_parts(enc, 5)

    ctx = yaca.decrypt_initialize(key_sym, yaca.ENCRYPT_ALGORITHM.UNSAFE_RC2,
                                  yaca.BLOCK_CIPHER_MODE.ECB)
    yaca.context_set_property(ctx, yaca.PROPERTY.RC2_EFFECTIVE_KEY_BITS, 192)
    dec = b''
    for part in enc_parts:
        dec += yaca.decrypt_update(ctx, part)
    dec += yaca.decrypt_finalize(ctx)

    assert msg == dec


def encrypt_gcm_property():
    # prepare:
    key_sym = yaca.key_generate()
    key_iv_128 = yaca.key_generate(yaca.KEY_TYPE.IV,
                                   yaca.KEY_BIT_LENGTH.IV_128BIT)
    # end prepare

    tag_len = 16
    aad = yaca.random_bytes(16)
    ctx = yaca.encrypt_initialize(key_sym, bcm=yaca.BLOCK_CIPHER_MODE.GCM,
                                  iv=key_iv_128)
    yaca.context_set_property(ctx, yaca.PROPERTY.GCM_AAD, aad)
    enc = b''
    for part in msg_parts:
        enc += yaca.encrypt_update(ctx, part)
    enc += yaca.encrypt_finalize(ctx)
    yaca.context_set_property(ctx, yaca.PROPERTY.GCM_TAG_LEN, tag_len)
    tag = yaca.context_get_property(ctx, yaca.PROPERTY.GCM_TAG)
    assert len(tag) == tag_len

    enc_parts = split_into_parts(enc, 5)

    ctx = yaca.decrypt_initialize(key_sym, bcm=yaca.BLOCK_CIPHER_MODE.GCM,
                                  iv=key_iv_128)
    yaca.context_set_property(ctx, yaca.PROPERTY.GCM_AAD, aad)
    dec = b''
    for part in enc_parts:
        dec += yaca.decrypt_update(ctx, part)
    yaca.context_set_property(ctx, yaca.PROPERTY.GCM_TAG, tag)
    dec += yaca.decrypt_finalize(ctx)

    assert msg == dec


def encrypt_ccm_property():
    # prepare:
    key_sym = yaca.key_generate()
    key_iv_64 = yaca.key_generate(yaca.KEY_TYPE.IV,
                                  yaca.KEY_BIT_LENGTH.IV_64BIT)
    # end prepare

    tag_len = 12
    aad = yaca.random_bytes(16)
    ctx = yaca.encrypt_initialize(key_sym, bcm=yaca.BLOCK_CIPHER_MODE.CCM,
                                  iv=key_iv_64)
    yaca.context_set_property(ctx, yaca.PROPERTY.CCM_TAG_LEN, tag_len)
    yaca.encrypt_update(ctx, len(msg))  # encrypt_update second type of usage
    yaca.context_set_property(ctx, yaca.PROPERTY.CCM_AAD, aad)
    enc = yaca.encrypt_update(ctx, msg)
    enc += yaca.encrypt_finalize(ctx)
    tag = yaca.context_get_property(ctx, yaca.PROPERTY.CCM_TAG)
    assert len(tag) == tag_len

    ctx = yaca.decrypt_initialize(key_sym, bcm=yaca.BLOCK_CIPHER_MODE.CCM,
                                  iv=key_iv_64)
    yaca.context_set_property(ctx, yaca.PROPERTY.CCM_TAG, tag)
    yaca.decrypt_update(ctx, len(enc))  # decrypt_update second type of usage
    yaca.context_set_property(ctx, yaca.PROPERTY.CCM_AAD, aad)
    dec = yaca.decrypt_update(ctx, enc)
    dec += yaca.decrypt_finalize(ctx)

    assert msg == dec


def sign():
    # prepare:
    key_sym = yaca.key_generate()
    key_rsa_prv = yaca.key_generate(yaca.KEY_TYPE.RSA_PRIV,
                                    yaca.KEY_BIT_LENGTH.L2048BIT)
    key_rsa_pub = yaca.key_extract_public(key_rsa_prv)
    hmac_simple = yaca.simple_calculate_hmac(key_sym, msg,
                                             yaca.DIGEST_ALGORITHM.SHA512)
    cmac_simple = yaca.simple_calculate_cmac(key_sym, msg,
                                             yaca.ENCRYPT_ALGORITHM.AES)
    sign_simple = yaca.simple_calculate_signature(key_rsa_prv, msg,
                                                  yaca.DIGEST_ALGORITHM.SHA512)
    # end prepare

    ctx = yaca.sign_initialize_hmac(key_sym, yaca.DIGEST_ALGORITHM.SHA512)
    for part in msg_parts:
        yaca.sign_update(ctx, part)
    hmac = yaca.sign_finalize(ctx)

    assert hmac == hmac_simple

    ctx = yaca.sign_initialize_cmac(key_sym, yaca.ENCRYPT_ALGORITHM.AES)
    for part in msg_parts:
        yaca.sign_update(ctx, part)
    cmac = yaca.sign_finalize(ctx)

    assert cmac == cmac_simple

    ctx = yaca.sign_initialize(key_rsa_prv, yaca.DIGEST_ALGORITHM.SHA512)
    for part in msg_parts:
        yaca.sign_update(ctx, part)
    sig = yaca.sign_finalize(ctx)

    assert sig == sign_simple  # won't work for DSA

    ctx = yaca.verify_initialize(key_rsa_pub, yaca.DIGEST_ALGORITHM.SHA512)
    for part in msg_parts:
        yaca.verify_update(ctx, part)
    assert yaca.verify_finalize(ctx, sig)

    # SIGN + SET PADDING

    ctx = yaca.sign_initialize(key_rsa_prv)
    for part in msg_parts:
        yaca.sign_update(ctx, part)
    yaca.context_set_property(ctx, yaca.PROPERTY.PADDING,
                              yaca.PADDING.PKCS1_PSS)
    sig = yaca.sign_finalize(ctx)

    ctx = yaca.verify_initialize(key_rsa_pub)
    for part in msg_parts:
        yaca.verify_update(ctx, part)
    yaca.context_set_property(ctx, yaca.PROPERTY.PADDING,
                              yaca.PADDING.PKCS1_PSS)
    assert yaca.verify_finalize(ctx, sig)


def seal():
    # prepare:
    key_rsa_prv = yaca.key_generate(yaca.KEY_TYPE.RSA_PRIV,
                                    yaca.KEY_BIT_LENGTH.L2048BIT)
    key_rsa_pub = yaca.key_extract_public(key_rsa_prv)
    # end prepare

    ctx, key_seal, iv = yaca.seal_initialize(key_rsa_pub,
                                             bcm=yaca.BLOCK_CIPHER_MODE.CBC)
    sealed = b''
    for part in msg_parts:
        sealed += yaca.seal_update(ctx, part)
    sealed += yaca.seal_finalize(ctx)

    sealed_parts = split_into_parts(sealed, 5)

    ctx = yaca.open_initialize(key_rsa_prv, key_seal, iv,
                               bcm=yaca.BLOCK_CIPHER_MODE.CBC)
    opened = b''
    for part in sealed_parts:
        opened += yaca.open_update(ctx, part)
    opened += yaca.open_finalize(ctx)

    assert opened == msg


def rsa():
    # prepare:
    key_rsa_prv = yaca.key_generate(yaca.KEY_TYPE.RSA_PRIV,
                                    yaca.KEY_BIT_LENGTH.L2048BIT)
    key_rsa_pub = yaca.key_extract_public(key_rsa_prv)
    # end prepare

    msg_short_max = int(2048 / 8 - 11)
    msg_short = msg[:msg_short_max]

    enc_rsa = yaca.rsa_public_encrypt(key_rsa_pub, msg_short)
    dec_rsa = yaca.rsa_private_decrypt(key_rsa_prv, enc_rsa)

    assert dec_rsa == msg_short

    enc_rsa = yaca.rsa_private_encrypt(key_rsa_prv, msg_short)
    dec_rsa = yaca.rsa_public_decrypt(key_rsa_pub, enc_rsa)

    assert dec_rsa == msg_short
