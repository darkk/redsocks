CFLAGS=-std=gnu99 -Wall -g -O0

.PHONY: all
all: redsocks

obj = parser.o main.o redsocks.o log.o http-connect.o socks4.o socks5.o base.o
src = $(patsubst %.o,%.c,$(obj))

redsocks: $(obj)
	$(CC) $+ -levent -o $@

tags: *.c *.h
	ctags -R

.PHONY: clean distclean
clean:
	rm -f redsocks config.h $(obj)

distclean: clean
	rm -f tags .depend

base.c: config.h

config.h:
	case `uname` in \
		Linux*) \
		echo "#define USE_IPTABLES" > config.h \
		;; \
		*) \
		echo "Unknown system, only generic firewall code is compiled" 1>&2 \
		echo "/* Unknown system, only generic firewall code is compiled */" > config.h \
		;; \
	esac

%.o: %.c
	$(CC) $(CFLAGS) -c $*.c -o $*.o

.depend: $(src)
	gcc -MM -MP $(src) $(CFLAGS) > .depend

include .depend

