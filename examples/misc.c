#include <stdio.h>
#include <stdarg.h>

#include <openssl/bio.h>
#include "misc.h"

void dump_hex(const char *buf, size_t dump_size, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	BIO_dump_fp(stdout, buf, dump_size);
}
