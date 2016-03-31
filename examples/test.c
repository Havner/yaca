#include <stdio.h>
#include <crypto/key.h>
#include <crypto/types.h>

#include "misc.h"

/** Simple test for development of library (before API is ready) */

int main(int argc, char* argv[])
{
	crypto_key_h key;
	char *k;
	size_t kl;
	int ret;

	printf("Generating key using CryptoAPI.. ");
	ret = crypto_key_gen(&key, CRYPTO_KEY_TYPE_SYMMETRIC, CRYPTO_KEY_UNSAFE_128BIT);
	printf("done (%d)\n", ret);
	printf("Exporting key using CryptoAPI.. ");
	ret = crypto_key_export(key, CRYPTO_KEY_FORMAT_RAW, &k, &kl);
	printf("done (%d)\n", ret);
	dump_hex(k, kl, "%zu-bit key: \n", kl);
	return 0;
}
