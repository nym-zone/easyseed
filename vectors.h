#ifndef _VECTORS_H_
#define _VECTORS_H_

#include <stddef.h>

struct testent {
	size_t bits;
	unsigned char entropy[32];
	const char *mnemonic;
	const char *passphrase;
	unsigned char seed[64];
	const unsigned char *bip32_xprv;
};

struct testentvec {
	unsigned ntests;
	const char *lang;
	const struct testent *v;
};

extern const struct testentvec testvec[];
extern const size_t ntestlangs;

#endif /* !_VECTORS_H_ */
