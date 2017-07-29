OBJS := parser.o main.o redsocks.o log.o direct.o ipcache.o autoproxy.o encrypt.o shadowsocks.o http-connect.o \
        socks4.o socks5.o http-relay.o base.o base64.o md5.o http-auth.o utils.o redudp.o socks5-udp.o shadowsocks-udp.o \
        tcpdns.o gen/version.o
SRCS := $(OBJS:.o=.c)
CONF := config.h
DEPS := .depend
OUT := redsocks2
VERSION := 0.66
OS := $(shell uname)

LIBS := -levent
CFLAGS +=-fPIC -O3
override CFLAGS += -D_BSD_SOURCE -D_DEFAULT_SOURCE -Wall
ifeq ($(OS), Linux)
override CFLAGS += -std=c99 -D_XOPEN_SOURCE=600
endif
ifeq ($(OS), Darwin)
override CFLAGS +=-I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib
override CFLAGS +=-Ixnu/10.12/
endif


#LDFLAGS += -fwhole-program
ifdef USE_CRYPTO_POLARSSL
override LIBS += -lpolarssl
override CFLAGS += -DUSE_CRYPTO_POLARSSL
$(info Compile with PolarSSL.)
CRYPTO := PolarSSL
else
$(info Compile with OpenSSL by default. To compile with PolarSSL, run 'make USE_CRYPTO_POLARSSL=true' instead.)
CRYPTO := OpenSSL
ifdef ENABLE_HTTPS_PROXY
override OBJS += https-connect.o
override LIBS += -levent_openssl
override CFLAGS += -DENABLE_HTTPS_PROXY
$(info Compile with HTTPS proxy enabled.)
endif
override LIBS += -lssl -lcrypto
override CFLAGS += -DUSE_CRYPTO_OPENSSL
endif
ifdef ENABLE_STATIC
override LIBS += -ldl -lz
override LDFLAGS += -Wl,-static -static -static-libgcc -s
endif

all: $(OUT)

.PHONY: all clean distclean

tags: *.c *.h
	ctags -R

$(CONF):
	@case $(OS) in \
	Linux*) \
		echo "#define USE_IPTABLES" >$(CONF) \
		;; \
	FreeBSD) \
		echo "#define USE_PF" >$(CONF) \
		;; \
	OpenBSD) \
		echo "#define USE_PF" >$(CONF) \
		;; \
	Darwin) \
		echo "#define USE_PF\n#define _APPLE_" >$(CONF) \
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
		echo '"redsocks.git/'`git describe --tags`' $(CRYPTO)"'; \
		if [ `git status --porcelain | grep -v -c '^??'` != 0 ]; then \
			echo '"-unclean"'; \
		fi \
	else \
		echo '"redsocks/$(VERSION) $(CRYPTO)"'; \
	fi >> $@.tmp
	echo ';' >> $@.tmp
	mv -f $@.tmp $@

gen/.build:
	mkdir -p gen
	touch $@

base.c: $(CONF)

$(DEPS): $(SRCS)
	$(CC) -MM $(CFLAGS) $(SRCS) 2>/dev/null >$(DEPS)

-include $(DEPS)

$(OUT): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

clean:
	$(RM) $(OUT) $(CONF) $(OBJS)

distclean: clean
	$(RM) tags $(DEPS)
	$(RM) -r gen
