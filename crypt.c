#include "crypt.h"
#include <string.h>
#include <stdio.h>

// Use case 1
// encypt buffer of bytes with defined buffers
void use_case_1() {
    char buf[200] = "The quick brown fox jumps over the lazy dog";
    char out[200];
    size_t len = strlen(buf);
    size_t outlen=sizeof(out);
    crypt_key_h *key = NULL;

    crypt_init(&key, CIPHER_DES);
    crypt_import_key(key, KEYFORMAT_RAW, "012345678", 8); // setup 64-bit key for DES operation

    // encrypt
    int r = crypt_encrypt(key, buf, len, (void**)(&out), &outlen);
    if (r < 0) { printf("context is incorect"); }
    if (r < len) { printf("Out but to short"); }

    // decrypt
    len = sizeof(buf);
    r = crypt_decrypt(key, out, outlen, (void**)(&buf), &len);

    crypt_destroy(key);
}
