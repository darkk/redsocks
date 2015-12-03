LIBHTTP_VERSION := 2.6.0
LIBHTTP_NAME := http-parser-$(LIBHTTP_VERSION)
LIBHTTP_CFLAGS := -I./http-parser-$(LIBHTTP_VERSION) -L./http-parser-$(LIBHTTP_VERSION)

OBJS := tls.o parser.o main.o redsocks.o log.o http-connect.o socks4.o socks5.o http-relay.o base.o base64.o md5.o http-auth.o utils.o redudp.o dnstc.o gen/version.o
SRCS := $(OBJS:.o=.c)
CONF := config.h
DEPS := .depend
OUT := redsocks
VERSION := 0.4.1-adallom

LIBS := -levent -lhttp_parser
CFLAGS += $(LIBHTTP_CFLAGS)
CFLAGS += -g -O2
override CFLAGS += -std=c99 -D_XOPEN_SOURCE=600 -D_BSD_SOURCE -D_DEFAULT_SOURCE -Wall

all: $(OUT)

.PHONY: all clean distclean http-parser

tags: *.c *.h
	ctags -R

$(LIBHTTP_NAME):
	wget https://github.com/nodejs/http-parser/archive/v$(LIBHTTP_VERSION).tar.gz
	tar -zxf v$(LIBHTTP_VERSION).tar.gz
	rm -f v$(LIBHTTP_VERSION).tar.gz

$(LIBHTTP_NAME)/libhttp_parser.o:
	cd $(LIBHTTP_NAME) && make package

http-parser: $(LIBHTTP_NAME) $(LIBHTTP_NAME)/libhttp_parser.o

$(CONF):
	@case `uname` in \
	Linux*) \
		echo "#define USE_IPTABLES" >$(CONF) \
		;; \
	OpenBSD) \
		echo "#define USE_PF" >$(CONF) \
		;; \
	*) \
		echo "Unknown system, only generic firewall code is compiled" 1>&2; \
		echo "/* Unknown system, only generic firewall code is compiled */" >$(CONF) \
		;; \
	esac

# Dependency on .git is useful to rebuild `version.c' after commit, but it breaks non-git builds.
gen/version.c: *.c *.h gen/.build
	rm -f $@.tmp
	echo '/* this file is auto-generated during build */' > $@.tmp
	echo '#include "../version.h"' >> $@.tmp
	echo 'const char* redsocks_version = ' >> $@.tmp
	if [ -d .git ]; then \
		echo '"redsocks.git/'`git describe --tags`'"'; \
		if [ `git status --porcelain | grep -v -c '^??'` != 0 ]; then \
			echo '"-unclean"'; \
		fi \
	else \
		echo '"redsocks/$(VERSION)"'; \
	fi >> $@.tmp
	echo ';' >> $@.tmp
	mv -f $@.tmp $@

gen/.build:
	mkdir -p gen
	touch $@

base.c: $(CONF)

$(DEPS): $(SRCS)
	gcc -MM $(SRCS) 2>/dev/null >$(DEPS) || \
	( \
		for I in $(wildcard *.h); do \
			export $${I//[-.]/_}_DEPS="`sed '/^\#[ \t]*include \?"\(.*\)".*/!d;s//\1/' $$I`"; \
		done; \
		echo -n >$(DEPS); \
		for SRC in $(SRCS); do \
			echo -n "$${SRC%.c}.o: " >>$(DEPS); \
			export SRC_DEPS="`sed '/\#[ \t]*include \?"\(.*\)".*/!d;s//\1/' $$SRC | sort`"; \
			while true; do \
				export SRC_DEPS_OLD="$$SRC_DEPS"; \
				export SRC_DEEP_DEPS=""; \
				for HDR in $$SRC_DEPS; do \
					eval export SRC_DEEP_DEPS="\"$$SRC_DEEP_DEPS \$$$${HDR//[-.]/_}_DEPS\""; \
				done; \
				export SRC_DEPS="`echo $$SRC_DEPS $$SRC_DEEP_DEPS | sed 's/  */\n/g' | sort -u`"; \
				test "$$SRC_DEPS" = "$$SRC_DEPS_OLD" && break; \
			done; \
			echo $$SRC $$SRC_DEPS >>$(DEPS); \
		done; \
	)

-include $(DEPS)

$(OUT): http-parser $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)

clean:
	$(RM) $(OUT) $(CONF) $(OBJS)

distclean: clean
	$(RM) tags $(DEPS)
	$(RM) -r gen
	$(RM) -rf $(LIBHTTP_NAME)
