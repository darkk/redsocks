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
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <assert.h>
#include <sys/queue.h>
#include "logger.h"

struct Logger {
    struct LogSink *sink;
    int priority;
    int facility;
    int reference_count;
};

struct LogSink {
    enum {
        LOG_SINK_SYSLOG,
        LOG_SINK_STDERR,
        LOG_SINK_FILE
    } type;
    const char *filepath;

    FILE *fd;
    int reference_count;
    SLIST_ENTRY(LogSink) entries;
};


static struct Logger *default_logger = NULL;
static SLIST_HEAD(LogSink_head, LogSink) sinks = SLIST_HEAD_INITIALIZER(sinks);


static void free_logger(struct Logger *);
static void init_default_logger();
static void vlog_msg(struct Logger *, int, const char *, va_list);
static void free_at_exit();
static int lookup_syslog_facility(const char *);
static const char *timestamp(char *, size_t);
static struct LogSink *obtain_stderr_sink();
static struct LogSink *obtain_syslog_sink();
static struct LogSink *obtain_file_sink(const char *);
static struct LogSink *log_sink_ref_get(struct LogSink *);
static void log_sink_ref_put(struct LogSink *);
static void free_sink(struct LogSink *);


struct Logger *
new_syslog_logger(const char *facility) {
    struct Logger *logger = malloc(sizeof(struct Logger));
    if (logger != NULL) {
        logger->sink = obtain_syslog_sink();
        if (logger->sink == NULL) {
            free(logger);
            return NULL;
        }
        logger->priority = LOG_DEBUG;
        logger->facility = lookup_syslog_facility(facility);
        logger->reference_count = 0;

        log_sink_ref_get(logger->sink);
    }

    return logger;
}

struct Logger *
new_file_logger(const char *filepath) {
    struct Logger *logger = malloc(sizeof(struct Logger));
    if (logger != NULL) {
        logger->sink = obtain_file_sink(filepath);
        if (logger->sink == NULL) {
            free(logger);
            return NULL;
        }
        logger->priority = LOG_DEBUG;
        logger->facility = 0;
        logger->reference_count = 0;

        log_sink_ref_get(logger->sink);
    }

    return logger;
}

void
reopen_loggers() {
    struct LogSink *sink;

    SLIST_FOREACH(sink, &sinks, entries) {
        if (sink->type == LOG_SINK_SYSLOG) {
            closelog();
            openlog("redsocks", LOG_PID, 0);
        } else if (sink->type == LOG_SINK_FILE) {
            sink->fd = freopen(sink->filepath, "a", sink->fd);
            if (sink->fd == NULL)
                err("failed to reopen log file %s: %s",
                        sink->filepath, strerror(errno));
            else
                setvbuf(sink->fd, NULL, _IOLBF, 0);
        }
    }
}

void
set_default_logger(struct Logger *new_logger) {
    struct Logger *old_default_logger = default_logger;

    assert(new_logger != NULL);
    default_logger = logger_ref_get(new_logger);
    logger_ref_put(old_default_logger);
}

void
set_logger_priority(struct Logger *logger, int priority) {
    assert(logger != NULL);
    assert(priority >= LOG_EMERG && priority <= LOG_DEBUG);
    logger->priority = priority;
}

void
logger_ref_put(struct Logger *logger) {
    if (logger == NULL)
        return;

    assert(logger->reference_count > 0);
    logger->reference_count--;
    if (logger->reference_count == 0)
        free_logger(logger);
}

struct Logger *
logger_ref_get(struct Logger *logger) {
    if (logger != NULL)
        logger->reference_count++;

    return logger;
}

static void
free_logger(struct Logger *logger) {
    if (logger == NULL)
        return;

    log_sink_ref_put(logger->sink);
    logger->sink = NULL;

    free(logger);
}

void
log_msg(struct Logger *logger, int priority, const char *format, ...) {
    va_list args;

    va_start(args, format);
    vlog_msg(logger, priority, format, args);
    va_end(args);
}

void
fatal(const char *format, ...) {
    va_list args;

    init_default_logger();

    va_start(args, format);
    vlog_msg(default_logger, LOG_CRIT, format, args);
    va_end(args);

    exit(EXIT_FAILURE);
}

void
err(const char *format, ...) {
    va_list args;

    init_default_logger();

    va_start(args, format);
    vlog_msg(default_logger, LOG_ERR, format, args);
    va_end(args);
}

void
warn(const char *format, ...) {
    va_list args;

    init_default_logger();

    va_start(args, format);
    vlog_msg(default_logger, LOG_WARNING, format, args);
    va_end(args);
}

void
notice(const char *format, ...) {
    va_list args;

    init_default_logger();

    va_start(args, format);
    vlog_msg(default_logger, LOG_NOTICE, format, args);
    va_end(args);
}

void
info(const char *format, ...) {
    va_list args;

    init_default_logger();

    va_start(args, format);
    vlog_msg(default_logger, LOG_INFO, format, args);
    va_end(args);
}

void
debug(const char *format, ...) {
    va_list args;

    init_default_logger();

    va_start(args, format);
    vlog_msg(default_logger, LOG_DEBUG, format, args);
    va_end(args);
}

static void
vlog_msg(struct Logger *logger, int priority, const char *format, va_list args) {
    assert(logger != NULL);

    if (priority > logger->priority)
        return;

    if (logger->sink->type == LOG_SINK_SYSLOG) {
        vsyslog(logger->facility|logger->priority, format, args);
    } else if (logger->sink->fd != NULL) {
        char buffer[1024];

        timestamp(buffer, sizeof(buffer));
        size_t len = strlen(buffer);

        vsnprintf(buffer + len, sizeof(buffer) - len, format, args);
        buffer[sizeof(buffer) - 1] = '\0'; /* ensure buffer null terminated */

        fprintf(logger->sink->fd, "%s\n", buffer);
    }
}

static void
init_default_logger() {
    struct Logger *logger = NULL;

    if (default_logger != NULL)
        return;

    logger = malloc(sizeof(struct Logger));
    if (logger != NULL) {
        logger->sink = obtain_stderr_sink();
        if (logger->sink == NULL) {
            free(logger);
            return;
        }
        logger->priority = LOG_DEBUG;
        logger->facility = 0;
        logger->reference_count = 0;

        log_sink_ref_get(logger->sink);
    }

    if (logger == NULL)
        return;

    atexit(free_at_exit);

    default_logger = logger_ref_get(logger);
}

static void
free_at_exit() {
    logger_ref_put(default_logger);
    default_logger = NULL;
}

static int
lookup_syslog_facility(const char *facility) {
    static const struct {
        const char *name;
        int number;
    } facilities[] = {
        { "auth",   LOG_AUTH },
        { "cron",   LOG_CRON },
        { "daemon", LOG_DAEMON },
        { "ftp",    LOG_FTP },
        { "local0", LOG_LOCAL0 },
        { "local1", LOG_LOCAL1 },
        { "local2", LOG_LOCAL2 },
        { "local3", LOG_LOCAL3 },
        { "local4", LOG_LOCAL4 },
        { "local5", LOG_LOCAL5 },
        { "local6", LOG_LOCAL6 },
        { "local7", LOG_LOCAL7 },
        { "mail",   LOG_MAIL },
        { "news",   LOG_NEWS },
        { "user",   LOG_USER },
        { "uucp",   LOG_UUCP },
    };

    for (size_t i = 0; i < sizeof(facilities) / sizeof(facilities[0]); i++)
        if (strncasecmp(facilities[i].name, facility, strlen(facility)) == 0)
            return facilities[i].number;

    /* fall back value */
    return LOG_USER;
}

static struct LogSink *
obtain_stderr_sink() {
    struct LogSink *sink;

    SLIST_FOREACH(sink, &sinks, entries) {
        if (sink->type == LOG_SINK_STDERR)
            return sink;
    }

    sink = malloc(sizeof(struct LogSink));
    if (sink != NULL) {
        sink->type = LOG_SINK_STDERR;
        sink->filepath = NULL;
        sink->fd = stderr;
        sink->reference_count = 0;

        SLIST_INSERT_HEAD(&sinks, sink, entries);
    }

    return sink;
}

static struct LogSink *
obtain_syslog_sink() {
    struct LogSink *sink;

    SLIST_FOREACH(sink, &sinks, entries) {
        if (sink->type == LOG_SINK_SYSLOG)
            return sink;
    }

    sink = malloc(sizeof(struct LogSink));
    if (sink != NULL) {
        sink->type = LOG_SINK_SYSLOG;
        sink->filepath = NULL;
        sink->fd = NULL;
        sink->reference_count = 0;

        openlog("redsocks", LOG_PID, 0);

        SLIST_INSERT_HEAD(&sinks, sink, entries);
    }

    return sink;
}

static struct LogSink *
obtain_file_sink(const char *filepath) {
    struct LogSink *sink;

    if (filepath == NULL)
        return NULL;

    SLIST_FOREACH(sink, &sinks, entries) {
        if (sink->type == LOG_SINK_FILE &&
                strcmp(sink->filepath, filepath) == 0)
            return sink;
    }

    sink = malloc(sizeof(struct LogSink));
    if (sink == NULL)
        return NULL;


    FILE *fd = fopen(filepath, "a");
    if (fd == NULL) {
        free(sink);
        err("Failed to open new log file: %s", filepath);
        return NULL;
    }
    setvbuf(fd, NULL, _IOLBF, 0);

    sink->type = LOG_SINK_FILE;
    sink->filepath = strdup(filepath);
    sink->fd = fd;
    sink->reference_count = 0;

    SLIST_INSERT_HEAD(&sinks, sink, entries);

    return sink;
}

static struct LogSink *
log_sink_ref_get(struct LogSink *sink) {
    if (sink != NULL)
        sink->reference_count++;

    return sink;
}

static void
log_sink_ref_put(struct LogSink *sink) {
    if (sink == NULL)
        return;

    assert(sink->reference_count > 0);
    sink->reference_count--;
    if (sink->reference_count == 0)
        free_sink(sink);
}

static void
free_sink(struct LogSink *sink) {
    if (sink == NULL)
        return;

    SLIST_REMOVE(&sinks, sink, LogSink, entries);

    switch(sink->type) {
        case LOG_SINK_SYSLOG:
            closelog();
            break;
        case LOG_SINK_STDERR:
            fflush(sink->fd);
            sink->fd = NULL;
            break;
        case LOG_SINK_FILE:
            fclose(sink->fd);
            sink->fd = NULL;
            free((char *)sink->filepath);
            sink->filepath = NULL;
            break;
        default:
            assert(0);
    }

    free(sink);
}

static const char *
timestamp(char *dst, size_t dst_len) {
    /* TODO change to ev_now() */
    time_t now = time(NULL);
    static struct {
        time_t when;
        char string[32];
    } timestamp_cache = { .when = 0, .string = {'\0'} };

    if (now != timestamp_cache.when) {
#ifdef RFC3339_TIMESTAMP
        struct tm *tmp = gmtime(&now);
        strftime(timestamp_cache.string, sizeof(timestamp_cache.string),
                "%FT%TZ ", tmp);
#else
        struct tm *tmp = localtime(&now);
        strftime(timestamp_cache.string, sizeof(timestamp_cache.string),
                "%F %T ", tmp);
#endif

        timestamp_cache.when = now;
    }

    if (dst != NULL)
        strncpy(dst, timestamp_cache.string, dst_len);

    return timestamp_cache.string;
}
