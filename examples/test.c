#include <stdio.h>
#include <crypto/key.h>
#include <crypto/types.h>

#include "misc.h"

/** Simple test for development of library (before API is ready) */

int main(int argc, char* argv[])
{
	owl_key_h key;
	char *k;
	size_t kl;
	int ret;

	printf("Generating key using CryptoAPI.. ");
	ret = owl_key_gen(&key, OWL_KEY_TYPE_SYMMETRIC, OWL_KEY_UNSAFE_128BIT);
	if (ret < 0)
		return ret;
	printf("done (%d)\n", ret);

	printf("Exporting key using CryptoAPI.. ");
	ret = owl_key_export(key, OWL_KEY_FORMAT_RAW, &k, &kl);
	if (ret < 0)
		return ret;
	printf("done (%d)\n", ret);

	dump_hex(k, kl, "%zu-bit key: \n", kl);

	return 0;
}
