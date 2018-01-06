CSTD=c11
LDADD=-lmd -lutf8proc
LDFLAGS+=-L$(.OBJDIR)

SEDRE=-E

HASHPROG=sha256 -q

.include "Makefile.inc"

.include <bsd.prog.mk>
