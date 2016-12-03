/* redsocks - transparent TCP-to-proxy redirector
 * Copyright (C) 2007-2011 Leonid Evdokimov <leon@darkk.net.ru>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <sys/time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <assert.h>
#include <event2/event.h>
#include "log.h"
#include "main.h"
#include "utils.h"
#include "version.h"

extern app_subsys redsocks_subsys;
extern app_subsys base_subsys;
extern app_subsys redudp_subsys;
extern app_subsys tcpdns_subsys;
extern app_subsys autoproxy_app_subsys;
extern app_subsys cache_app_subsys;

app_subsys *subsystems[] = {
    &base_subsys,
    &redsocks_subsys,
    &autoproxy_app_subsys,
    &cache_app_subsys,
    &redudp_subsys,
    &tcpdns_subsys,
};

static const char *confname = "redsocks.conf";
static const char *pidfile = NULL;
static struct event_base * g_event_base = NULL;

static void terminate(int sig, short what, void *_arg)
{
    if (g_event_base && event_base_loopbreak(g_event_base) != 0)
        log_error(LOG_WARNING, "event_loopbreak");
}

static void dump_handler(int sig, short what, void *_arg)
{
    app_subsys **ss;
    FOREACH(ss, subsystems) {
        if ((*ss)->dump) {
           (*ss)->dump();
        }
    }
}

/* Setup signals not to be handled with libevent */
static int setup_signals()
{
    struct sigaction sa/* , sa_old*/;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL)  == -1) {
        log_errno(LOG_ERR, "sigaction");
        return -1;
    }
    return 0;
}

struct event_base * get_event_base()
{
    return g_event_base;
}

static void wait_for_network()
{
    struct evutil_addrinfo hints;
    struct evutil_addrinfo *answer = NULL;
    int err;

    /* Build the hints to tell getaddrinfo how to act. */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; /* v4 or v6 is fine. */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP; /* We want a TCP socket */
    /* Only return addresses we can use. */
    hints.ai_flags = EVUTIL_AI_ADDRCONFIG;

    /* Look up the hostname. */
    do {
        err = evutil_getaddrinfo("www.google.com", NULL, &hints, &answer);
        if (err)
            sleep(2);
        /* If there was no error, we should have at least one answer. */
        if (answer) {
            evutil_freeaddrinfo(answer);
            answer = NULL;
        }
    } while (err != 0);
}

int main(int argc, char **argv)
{
    int error;
    app_subsys **ss;
    int exit_signals[2] = {SIGTERM, SIGINT};
    struct event * terminators[2];
    struct event * dumper = NULL;
    bool conftest = false;
    int opt;
    int i;
    bool wait = false;

    evutil_secure_rng_init();
    while ((opt = getopt(argc, argv, "h?wvtc:p:")) != -1) {
        switch (opt) {
        case 't':
            conftest = true;
            break;
        case 'w':
            wait = true;
            break;
        case 'c':
            confname = optarg;
            break;
        case 'p':
            pidfile = optarg;
            break;
        case 'v':
            puts(redsocks_version);
            return EXIT_SUCCESS;
        default:
            printf(
                "Usage: %s [-?hwvt] [-c config] [-p pidfile]\n"
                "  -h, -?       this message\n"
                "  -w           wait util network ready\n"
                "  -v           print version\n"
                "  -t           test config syntax\n"
                "  -p           write pid to pidfile\n",
                argv[0]);
            return (opt == '?' || opt == 'h') ? EXIT_SUCCESS : EXIT_FAILURE;
        }
    }

    // Wait for network ready before further initializations so that
    // parser can resolve domain names.
    if (wait)
        wait_for_network();

    FILE *f = fopen(confname, "r");
    if (!f) {
        perror("Unable to open config file");
        return EXIT_FAILURE;
    }

    parser_context* parser = parser_start(f);
    if (!parser) {
        perror("Not enough memory for parser");
        return EXIT_FAILURE;
    }

    FOREACH(ss, subsystems)
        if ((*ss)->conf_section)
            parser_add_section(parser, (*ss)->conf_section);
    error = parser_run(parser);
    parser_stop(parser);
    fclose(f);

    if (error)
        return EXIT_FAILURE;

    if (conftest)
        return EXIT_SUCCESS;

    if (setup_signals())
        return EXIT_FAILURE;

    // Initialize global event base
    g_event_base = event_base_new();
    if (!g_event_base)
        return EXIT_FAILURE;
        
    memset(terminators, 0, sizeof(terminators));

    FOREACH(ss, subsystems) {
        if ((*ss)->init) {
            error = (*ss)->init();
            if (error)
                goto shutdown;
        }
    }

    if (pidfile) {
        f = fopen(pidfile, "w");
        if (!f) {
            perror("Unable to open pidfile for write");
            return EXIT_FAILURE;
        }
        fprintf(f, "%d\n", getpid());
        fclose(f);
    }

    assert(SIZEOF_ARRAY(exit_signals) == SIZEOF_ARRAY(terminators));
    for (i = 0; i < SIZEOF_ARRAY(exit_signals); i++) {
        terminators[i] = evsignal_new(get_event_base(), exit_signals[i], terminate, NULL);
        if (!terminators[i]) {
            log_errno(LOG_ERR, "evsignal_new");
            goto shutdown;
        }
        if (evsignal_add(terminators[i], NULL) != 0) {
            log_errno(LOG_ERR, "evsignal_add");
            goto shutdown;
        }
    }

    dumper = evsignal_new(get_event_base(), SIGUSR1, dump_handler, NULL);
    if (!dumper) {
        log_errno(LOG_ERR, "evsignal_new");
        goto shutdown;
    }
    if (evsignal_add(dumper, NULL) != 0) {
        log_errno(LOG_ERR, "evsignal_add");
        goto shutdown;
    }

    log_error(LOG_NOTICE, "redsocks started with: %s", event_base_get_method(g_event_base));

    event_base_dispatch(g_event_base);

    log_error(LOG_NOTICE, "redsocks goes down");

shutdown:
    if (dumper) {
        if (evsignal_del(dumper) != 0)
            log_errno(LOG_WARNING, "evsignal_del");
        event_free(dumper);
    }

    for (i = 0; i < SIZEOF_ARRAY(exit_signals); i++) {
        if (terminators[i]) {
            if (evsignal_del(terminators[i]) != 0)
                log_errno(LOG_WARNING, "evsignal_del");
            event_free(terminators[i]);
        }
    }

    for (--ss; ss >= subsystems; ss--)
        if ((*ss)->fini)
            (*ss)->fini();

    if (g_event_base)
        event_base_free(g_event_base);
    
    return !error ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
