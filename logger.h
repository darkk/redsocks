/*
 * Copyright (c) 2013, Dustin Lundquist <dustin@null-ptr.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef LOGGER_H
#define LOGGER_H

struct Logger;

#define LOG_EMERG   0
#define LOG_ALERT   1
#define LOG_CRIT    2
#define LOG_ERR     3
#define LOG_WARNING 4
#define LOG_NOTICE  5
#define LOG_INFO    6
#define LOG_DEBUG   7

struct Logger *new_syslog_logger(const char *facility);
struct Logger *new_file_logger(const char *filepath);
void set_default_logger(struct Logger *);
void set_logger_priority(struct Logger *, int);
struct Logger *logger_ref_get(struct Logger *);
void logger_ref_put(struct Logger *);
void reopen_loggers();

/* Shorthand to log to global error log */
void fatal(const char *, ...)
    __attribute__ ((format (printf, 1, 2)))
    __attribute__ ((noreturn));
void err(const char *, ...)
    __attribute__ ((format (printf, 1, 2)));
void warn(const char *, ...)
    __attribute__ ((format (printf, 1, 2)));
void notice(const char *, ...)
    __attribute__ ((format (printf, 1, 2)));
void info(const char *, ...)
    __attribute__ ((format (printf, 1, 2)));
void debug(const char *, ...)
    __attribute__ ((format (printf, 1, 2)));

void log_msg(struct Logger *, int, const char *, ...)
    __attribute__ ((format (printf, 3, 4)));

#endif
