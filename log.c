/* $Id$ */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <event.h>
#include "log.h"

static const char *lowmem = "<Can't print error, not enough memory>";

void _log_vwrite(const char *file, int line, const char *func, int do_errno, const char *fmt, va_list ap)
{
	int saved_errno = errno;
	struct evbuffer *buff = evbuffer_new();
	const char *message;

	if (buff) {
		evbuffer_add_vprintf(buff, fmt, ap);
		message = buff->buffer;
	}
	else 
		message = lowmem;

	struct timeval tv = { };
	gettimeofday(&tv, 0);

	if (do_errno)
		fprintf(stderr, "%lu.%6.6lu %s:%u %s(...) %s: %s\n", tv.tv_sec, tv.tv_usec, file, line, func, message, strerror(saved_errno));
	else
		fprintf(stderr, "%lu.%6.6lu %s:%u %s(...) %s\n", tv.tv_sec, tv.tv_usec, file, line, func, message);

	if (buff)
		evbuffer_free(buff);
}

void _log_write(const char *file, int line, const char *func, int do_errno, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	_log_vwrite(file, line, func, do_errno, fmt, ap);
	va_end(ap);
}

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
