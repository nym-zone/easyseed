CFLAGS+=-O2 -std=c11

LDFLAGS+=-L.
LDADD=-lcrypto -lutf8proc

ifdef LBSD
LDADD+=-lbsd
endif

SEDRE=-r

all: easyseed

HASHPROG=sha256sum

include Makefile.inc

easyseed: wordlist.h $(OBJS) libutf8proc.a
	cc $(LDFLAGS) -o $@ $(OBJS) $(LDADD)

install:
	install $(PROG) /usr/local/bin
	install $(PROG).$(MANSEC) /usr/local/man/man1
