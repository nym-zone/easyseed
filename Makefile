CSTD=c11
LDADD=-lmd

SEDRE=-E

HASHPROG=sha256 -q

.include "Makefile.inc"

.include <bsd.prog.mk>
