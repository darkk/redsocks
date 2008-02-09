#ifndef LOG_H_WED_JAN_24_18_21_27_2007
#define LOG_H_WED_JAN_24_18_21_27_2007
/* $Id$ */
#include <stdarg.h>
#include <stdbool.h>
#include <syslog.h>

#define log_errno(msg...) _log_write(__FILE__, __LINE__, __func__, 1, ## msg)
#define log_error(msg...) _log_write(__FILE__, __LINE__, __func__, 0, ## msg)

int log_preopen(const char *dst);
void log_open();

void _log_vwrite(const char *file, int line, const char *func, int do_errno, const char *fmt, va_list ap);
void _log_write(const char *file, int line, const char *func, int do_errno, const char *fmt, ...);

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
#endif /* LOG_H_WED_JAN_24_18_21_27_2007 */

