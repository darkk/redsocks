CFLAGS=-std=gnu99 -Wall -g

.PHONY: all
redsocks: parser.o main.o redsocks.o log.o http-connect.o socks4.o socks5.o base.o
	$(CC) $+ -levent -o $@

tags: *.c *.h
	ctags -R

.PHONY: clean distclean
clean:
	rm -f redsocks *.o

distclean: clean
	rm -f tags

%.o: %.c
	$(CC) $(CFLAGS) -c $*.c -o $*.o


