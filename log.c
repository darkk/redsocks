/* $Id$ */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <event.h>
#include "log.h"

static const char *lowmem = "<Can't print error, not enough memory>";

void _log_write(const char *file, int line, const char *func, int do_errno, const char *fmt, ...)
{
	int saved_errno = errno;
	struct evbuffer *buff = evbuffer_new();
	va_list ap;
	const char *message;

	if (buff) {
		va_start(ap, fmt);
		evbuffer_add_vprintf(buff, fmt, ap);
		va_end(ap);
		message = buff->buffer;
	}
	else 
		message = lowmem;

	if (do_errno)
		fprintf(stderr, "%s:%u %s(...) %s: %s\n", file, line, func, message, strerror(saved_errno));
	else
		fprintf(stderr, "%s:%u %s(...) %s\n", file, line, func, message);

	if (buff)
		evbuffer_free(buff);
}

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
