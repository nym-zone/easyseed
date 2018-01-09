/**
 * By nullius <nullius@nym.zone>
 * PGP: 0xC2E91CD74A4C57A105F6C21B5A00591B2F307E0C
 * Bitcoin: 3NULL3ZCUXr7RDLxXeLPDMZDZYxuaYkCnG
 *
 * Copyright (c) 2017-18.  All rights reserved.
 *
 * The Antiviral License (AVL) v0.0.1, with added Bitcoin Consensus Clause:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of the source code must retain the above copyright
 *    and credit notices, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    and credit notices, this list of conditions, and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 * 3. Derivative works hereof MUST NOT be redistributed under any license
 *    containing terms which require derivative works and/or usages to
 *    publish source code, viz. what is commonly known as a "copyleft"
 *    or "viral" license.
 * 4. Derivative works hereof which have any functionality related to
 *    digital money (so-called "cryptocurrency") MUST EITHER adhere to
 *    consensus rules fully compatible with Bitcoin Core, OR use a name
 *    which does not contain the word "Bitcoin".
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef __linux__
#define	_POSIX_C_SOURCE	200809L
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <fcntl.h>
#include <unistd.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <err.h>

#ifdef wishlist
#ifdef __FreeBSD
#include <sha256.h>
#else
#include <openssl/sha.h>
#endif
#endif /*wishlist: deprecate OpenSSL */

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#ifdef BSD
#include <readpassphrase.h>
#define DYNPASS
#elif defined(HAVE_LBSD)
#include <bsd/readpassphrase.h>
#define DYNPASS
#endif /* BSD */

#include "utf8proc/utf8proc.h"

/* Changing this will appropriately change the device used: */
#define	DEV_RANDOM	"/dev/urandom"

/*
 * This is number of Unicode characters, *not* bytes.  It will permit
 * a passphrase of more than 24 words in most any language.  Note, the
 * same limitation will apply to BIP 39 mnemonics entered for key generation.
 */
#define	PASSPHRASE_UNICHARS_MAX		256
/*
 * This is set to contain PASSPHRASE_UNICHARS_MAX+1 UTF-8 encoded characters,
 * plus a terminating '\0' or '\n'.  The reason for the extra character is that
 * readpassphrase(3) does not give a precise idea of length.  To know surely
 * that a user has entered too many characters, and not the exact maximum,
 * we must be able to detect one extra character.
 */
#define	PASSPHRASE_BUFSIZE		((PASSPHRASE_UNICHARS_MAX + 1) * 4 + 1)

struct wordlist {
	const char *name;
	const char *lname;
	const char *code2;
	const char *space;
	const char **wordlist;
	const char *hash; /* SHA-256 */
	int status;
};

static const char ascii_space[] = " ";

#include "wordlist.h"

#define	LANG(name, lname, code2, space, status)	\
	{ #name, lname, code2, space, name, name##_hash, status }

/*
 * XXX: BUG: zh-TW and zh-CN are inaccurate descriptors.  HK Chinese use
 * Traditional; overseas Chinese use both.  Suggestions from from actual
 * Chinese people are welcome.
 *
 * XXX: I monkeypasted the native-written language names from sources
 * such as Wikipedia.  Corrections are welcome.
 *
 * Languages are here listed in lexicographical order, according to the
 * wordlist name in ASCII, with sole exception of the default language.
 * The default language gets the [0] slot, for purely technical reasons.
 * Do not bug me about this, or I will pick sides.
 */
static const struct wordlist wordlists[] =
{
	LANG(english,			u8"English",	"en",	ascii_space, 1),
	LANG(chinese_simplified,	u8"汉语",	"zh-CN",ascii_space, 1),
	LANG(chinese_traditional,	u8"漢語",	"zh-TW",ascii_space, 1),
	LANG(czech,			u8"Čeština",	"cz",	ascii_space, 0),
	LANG(french,			u8"Français",	"fr",	ascii_space, 1),
	LANG(indonesian,	u8"Bahasa Indonesia",	"id",	ascii_space, 0),
	LANG(italian,			u8"Italiano",	"it",	ascii_space, 1),
	LANG(japanese,			u8"日本語",	"ja",	u8"\u3000",  1),
	LANG(korean,			u8"한국어",	"ko",	ascii_space, 1),
	LANG(russian,			u8"Русский",	"ru",	ascii_space, 0),
	LANG(spanish,			u8"Español",	"es",	ascii_space, 1),
	LANG(ukrainian,			u8"Українська",	"uk",	ascii_space, 0),
};

#undef LANG

static const struct wordlist *default_wordlist = &wordlists[0];

#include "vectors.h"

			/* BIP 32 standard: */
static const uint8_t	xprv_ver[4] = { 0x04, 0x88, 0xad, 0xe4 },
			xpub_ver[4] = { 0x04, 0x88, 0xb2, 0x1e },
			tprv_ver[4] = { 0x04, 0x35, 0x83, 0x94 },
			tpub_ver[4] = { 0x04, 0x35, 0x87, 0xcf },
			/* Electrum Extensions: */
			/* Segwit P2WPKH-nested-in-P2SH: */
			yprv_ver[4] = { 0x04, 0x9d, 0x78, 0x78 },
			ypub_ver[4] = { 0x04, 0x9d, 0x7c, 0xb2 },
			/* Segwit P2WPKH native: */
			zprv_ver[4] = { 0x04, 0xb2, 0x43, 0x0c },
			zpub_ver[4] = { 0x04, 0xb2, 0x47, 0x46 },
			/* Segwit P2WSH-nested-in-P2SH (unsupported): */
			Yprv_ver[4] = { 0x02, 0x95, 0xb0, 0x05 },
			Ypub_ver[4] = { 0x02, 0x95, 0xb4, 0x3f },
			/* Segwit P2WSH native (unsupported): */
			Zprv_ver[4] = { 0x02, 0xaa, 0x7a, 0x99 },
			Zpub_ver[4] = { 0x02, 0xaa, 0x7e, 0xd3 };

struct xprv_type {
	const char *prv_str;
	const uint8_t *prv_ver;
	const char *pub_str;
	const uint8_t *pub_ver;
};

struct xprv_type_selector {
	const char *key;
	const struct xprv_type *type;
};

static const struct xprv_type xprv_type[] = {
	{ "xprv", xprv_ver, "xpub", xpub_ver }, /*[0]*/
	{ "tprv", tprv_ver, "tpub", tpub_ver }, /*[1]*/
	{ "yprv", yprv_ver, "ypub", ypub_ver }, /*[2]*/
	{ "zprv", zprv_ver, "zpub", zpub_ver }, /*[3]*/
};

/* Keep these sorted by key! */
static const struct xprv_type_selector xprv_types[] = {
	{ "1addr",		&xprv_type[0] },
	{ "3addr",		&xprv_type[2] },
	{ "bech32",		&xprv_type[3] },
	{ "bravo charlie",	&xprv_type[3] },
	{ "p2pkh",		&xprv_type[0] },
	{ "p2wpkh",		&xprv_type[3] },
	{ "segwit",		&xprv_type[3] },
	{ "testnet",		&xprv_type[1] },
	{ "tprv",		&xprv_type[1] },
	{ "tpub",		&xprv_type[1] },
	{ "xprv",		&xprv_type[0] },
	{ "xpub",		&xprv_type[0] },
	{ "yprv",		&xprv_type[2] },
	{ "ypub",		&xprv_type[2] },
	{ "zprv",		&xprv_type[3] },
	{ "zpub",		&xprv_type[3] },
};

static const struct xprv_type *default_xprv = &xprv_type[0];

static int nullfd = -1;

static void usage(void);

/*
 * Whilst standards for reliable memory-clearing are not yet consistently
 * available across platforms, I here use a little hack which I have
 * deployed for many years:
 *
 * The compiler cannot remove a call to memset() if the memory is
 * subsequently *used*.  Thus after zeroizing, I write() to /dev/null.
 * It does not even matter if the system call fails; no error checking
 * is required; indeed, I could also write() to fd -1.  The important
 * part is that after memset(), the memory is "accessed" across a boundary
 * across which no compiler can claim to see.
 */
static void
zeroize(void *buf, size_t len)
{

	memset(buf, 0, len);
	write(nullfd, buf, len);
}

static void
sfree(void *buf, size_t len)
{

	zeroize(buf, len);
	free(buf);
}

static void
zfree(char *str)
{
	size_t len;

	len = strlen(str) + 1;
	sfree(str, len);
}
#define	ZFREE(str)	zfree((char *)str)

static void
addchk(unsigned char *buf, unsigned ent)
{
	size_t entbytes;
	unsigned char hash[32];
	SHA256_CTX ctx;

	entbytes = ent/8;

	assert(ent == 80 || (entbytes >= 16 && entbytes <= 32));
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, buf, entbytes);
	SHA256_Final(hash, &ctx);

	buf[entbytes] = *hash;

	zeroize(&ctx, sizeof(ctx));
	zeroize(hash, sizeof(hash));
}

/*
 * We are guaranteed to work with a multiple of 11 bits.
 * Therefore, do as such:
 *
 * 0[0:7], 1[0:2]
 * 1[3:7], 2[0:5]
 * 2[6:7], 3[0:7], 4[0]
 * 4[1:7], 5[0:3]
 * 5[4:7], 6[0:6]
 * 6[7], 7[0:7], 8[0:1]
 * 8[2:7], 9[0:4]
 * 9[5:7], a[0:7]
 *
 */
static void
calc_indices(unsigned *w, const unsigned char *p, unsigned ms)
{

	for (unsigned i = 0; i < ms; ++i) {
		switch (i%8) {
		case 0:
			*w = (p[0] << 3) | (p[1] >> 5);			break;
		case 1:
			*w= ((p[1] & 0x1f) << 6) | (p[2] >> 2);		break;
		case 2:
			*w= ((p[2] & 3) << 9) | (p[3] << 1) | (p[4] >> 7);break;
		case 3:
			*w = ((p[4] & 0x7f) << 4) | (p[5] >> 4);	break;
		case 4:
			*w = ((p[5] & 0xf) << 7) | (p[6] >> 1);		break;
		case 5:
			*w=((p[6] & 1) << 10) | (p[7] << 2) | (p[8] >> 6);break;
		case 6:
			*w = ((p[8] & 0x3f) << 5) | (p[9] >> 3);	break;
		case 7:
			*w = ((p[9] & 7) << 8) | p[10];
			p += 11;
			break;
		}
		++w;
	}
}

/*
 * DO NOT modify buffer sizes without understanding the following:
 *
 * At this time, the measures of maximum word length in *bytes*
 * (not Unicode characters!) are as follows:
 *
 *  3	chinese_simplified.txt
 *  3	chinese_traditional.txt
 *  8	english.txt
 * 12	french.txt
 *  9	italian.txt
 * 27	japanese.txt
 * 33	korean.txt
 * 10	spanish.txt
 *
 * Thus at this time, counting words plus interword separators plus a
 * terminating '\0', the longest possible *byte* length of a seed phrase
 * is Korean: 24*33 + 23 + 1 = 816.  The next possible candidate was
 * Japanese with U+3000 word separators: 24*27 + 23*3 + 1 = 718.
 */

static void
mkmnemonic(char *phrase, unsigned nbits, const unsigned char *seed,
	const char **wordlist, const char *spc)
{
	/*char phrase[816];*/
	unsigned char buf[33]; /* Caveat!  Needs extra space for checksum. */
	char *cur;
	unsigned idx[24], nwords;
	size_t seedlen;

	if (nbits == 80) /* Exclusively for .onion v2 address data */
		nwords = 8;
	else
		/* Equation straight from BIP 39: */
		nwords = (nbits + nbits/32) / 11;

	/*
	 * This copy is done for testing and maintenance reasons.
	 * I ordinarily minimize copying around of keymat; however,
	 * it is *very important* that tests MUST follow exactly
	 * the same codepath as actual usage.  Thus, this function
	 * must be reasonably self-contained (including addchk() call).
	 */
	seedlen = nbits/8;
	memcpy(buf, seed, seedlen);
	addchk(buf, nbits);

	calc_indices(idx, buf, nwords);

	cur = phrase;

	/*
	 * I want to use strlcat(), and do length checks.  However,
	 * that requires -lbsd as a dependency on Linux; and this is
	 * a closed system, where the maximum buffer use can be
	 * guaranteed by logic.
	 */
	for (unsigned i = 0; i < nwords; ++i) {
		cur = stpcpy(cur, wordlist[idx[i]]);
		if (i < nwords - 1)
			cur = stpcpy(cur, spc);
	}

	zeroize(buf, sizeof(buf));
	zeroize(idx, sizeof(idx));
}

static ssize_t
newmnemonic(unsigned char **e, char **mnemonic,
	unsigned nbits, const char *keymat, const struct wordlist *wl)
{
	unsigned char *entropy;
	char *phrase;
	int keyfd = -1, error = 0;
	size_t phsize, len, nbytes;
	ssize_t rbytes;

	nbytes = nbits/8;

	entropy = malloc(nbytes);
	if (entropy == NULL)
		return (-1);

	phsize = 816; /* XXX: magic number calculated from wordlists */
	phrase = malloc(phsize);
	if (phrase == NULL) {
		free(entropy);
		return (-1);
	}

	/*
	 * Don't potentially leak the length of the mnemonic by the potential
	 * presence of heap trash trailing after the part later zeroed by
	 * sfree(mnemonic, strlen(mnemonic)).
	 */
	memset(phrase, 0, phsize);

	/*
	 * XXX: I know the checks of read() lengths are technically wrong.
	 * However, if the descriptor cannot give 16-32 bytes at a time,
	 * something else is wrong.  This will need editing if anybody
	 * insists on using blocking /dev/random on Linux.
	 */
	if (keymat == NULL) {
		if ((keyfd = open(DEV_RANDOM, O_RDONLY)) < 0) {
			warn("open(\"" DEV_RANDOM "\")");
			goto bad;
		}
		rbytes = read(keyfd, entropy, nbytes);
		if (rbytes != nbytes) {
			warn("read() on random device");
			goto bad;
		}
	} else {
		unsigned char scratch;

		if (!strcmp(keymat, "-")) {
			if (isatty(0)) {
				warnx("Will not read entropy from terminal.");
				goto bad;
			}
			keyfd = 0;
		} else
			if ((keyfd = open(keymat, O_RDONLY)) < 0) {
				warn("open(\"%s\")", keymat);
				goto bad;
			}
		rbytes = read(keyfd, entropy, nbytes);
		if (rbytes != nbytes) {
			warn("read() of key material");
			goto bad;
		}

		/* Check for EOF: */
		rbytes = read(keyfd, &scratch, 1);
		if (rbytes != 0) {
			zeroize(&scratch, sizeof(scratch));
			if (rbytes > 0)
				warnx(
				"Provided -k input length mismatches -b bits.");
			else
				warn("read() on key file");
			goto bad;
		}

	}

	/* XXX: Check close(2) for errors, which is a problem in POSIX: */
	close(keyfd);
	keyfd = -1;

	mkmnemonic(phrase, nbits, entropy, wl->wordlist, wl->space);

	len = strlen(phrase);

	assert(len + 1 < phsize);

	*e = entropy;
	*mnemonic = phrase;
	return (len);

bad:
	sfree(entropy, nbytes);
	sfree(phrase, phsize);
	return (-1);
}

/*
 * Wrapper to help isolate OpenSSL API pain.
 */
static int
PBKDF2_HMAC_SHA512(unsigned char *k, size_t klen,
	const char *pass, const char *salt, unsigned i)
{
	int error;
	size_t saltlen;

	/*
	 * OpenSSL specifies an int to pass the size.
	 * This can never be a problem with the mnemonic phrase; but it
	 * could theoretically be a problem with the user-entered passphrase.
	 *
	 * This is used in the salt (prepended with "mnemonic").
	 */
	saltlen = strlen(salt);
	if (saltlen > INT_MAX)
		return (-1);

	assert(strlen(pass) <= INT_MAX);

	error = PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, saltlen, i,
		EVP_sha512(), klen, k);

	/* OpenSSL inverts proper error returns. */
	return (error == 1? 0 : -1);
}

/*
 * utf8proc_map() is used directly instead of the utf8proc_NFKD() convenience
 * wrapper, so that we can get an error code if something goes wrong.
 *
 * The returned pointer was obtained from malloc(), and must be free()ed.
 */
const char *
norm_nfkd(const char *str)
{
	ssize_t len;
	const char *normalized;

	/* XXX character sign; sorting out the utf8 char type is TODO */
	len = utf8proc_map((const utf8proc_uint8_t *)str, 0,
		(unsigned char **)&normalized,
		UTF8PROC_DECOMPOSE | UTF8PROC_COMPAT |
		UTF8PROC_STABLE | UTF8PROC_NULLTERM);

	if (len < 0) {
		fprintf(stderr, "easyseed: %s\n", utf8proc_errmsg(len));
		return (NULL);
	}

	return (normalized);
}

static int
mkseed(unsigned char *seed/*[64]*/,const char *mnemonic, const char *passphrase)
{
	int error;
	const char *m, saltpre[] = "mnemonic"; /* Per BIP 39. */
	char *s, *cur;
	size_t prelen;

	s = strdup(saltpre);
	if (s == NULL)
		return (-1);

	assert(mnemonic != NULL);

	if (passphrase != NULL) {
		size_t prelen, phraselen;;

		prelen = strlen(saltpre);
		phraselen = strlen(passphrase);

		cur = realloc(s, prelen + phraselen + 1);
		if (cur == NULL) {
			free(s);
			return (-1);
		} else
			s = cur, cur += prelen;

		memcpy(cur, passphrase, phraselen);
		cur[phraselen] = '\0';

		/*
		 * XXX: const correctness
		 * But the behaviour is correct.
		 */
		cur = (char*)norm_nfkd(s);
		ZFREE(s);

		if (cur == NULL)
			return (-1);
		else
			s = cur, cur = NULL;
	}

	m = norm_nfkd(mnemonic);
	if (m == NULL) {
		ZFREE(s);
		return (-1);
	}

	/* Per BIP 39 specification: */
	error = PBKDF2_HMAC_SHA512(seed, 64, m, s, 2048);

	ZFREE(s);
	ZFREE(m);

	return (error);
}

static void
hmac_sha512(void *h, const void *k, size_t klen, const void *d, size_t dlen)
{
	void *t;

	t = HMAC(EVP_sha512(), k, klen, d, dlen, h, NULL);

	if (t == NULL)
		abort();
}

static void
sha256dchk(void *chk /* chr[4] */, const void *data, size_t len)
{
	SHA256_CTX ctx;
	uint8_t hash[32];

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, data, len);
	SHA256_Final(hash, &ctx);

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, hash, sizeof(hash));
	SHA256_Final(hash, &ctx);

	memcpy(chk, hash, 4);

	zeroize(&ctx, sizeof(ctx));
	zeroize(hash, sizeof(hash));
}

/*
 * base58enc() is adapted from code bearing this notice:
 *
 * Copyright 2012-2014 Luke Dashjr
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the standard MIT license.  See COPYING for more details.
 */
static int
base58enc(char *b58, size_t *b58sz, const void *data, size_t binsz)
{
	const char b58digits_ordered[] =
		"123456789ABCDEFGHJKLMNPQRSTUVWXYZ"
		"abcdefghijkmnopqrstuvwxyz";
	const uint8_t *bin = data;
	int carry, error = 0;
	ssize_t i, j, high, zcount = 0;
	size_t size;

	while (zcount < binsz && !bin[zcount])
		++zcount;

	size = (binsz - zcount) * 138 / 100 + 1;
	uint8_t buf[size];
	memset(buf, 0, size);

	for (i = zcount, high = size - 1; i < binsz; ++i, high = j) {
		for (carry = bin[i], j = size - 1; (j > high) || carry; --j) {
			carry += 256 * buf[j];
			buf[j] = carry % 58;
			carry /= 58;
		}
	}

	for (j = 0; j < size && !buf[j]; ++j);

	if (*b58sz <= zcount + size - j) {
		*b58sz = zcount + size - j + 1;
		error = -1;
		goto done;
	}

	if (zcount)
		memset(b58, '1', zcount);
	for (i = zcount; j < size; ++i, ++j)
		b58[i] = b58digits_ordered[buf[j]];
	b58[i] = '\0';
	*b58sz = i + 1;

done:
	zeroize(buf, size);
	return (error);
}

/*
 * BIP 32:
 */
static ssize_t
mkxser(char *xprv /*[113]*/, size_t len, const struct xprv_type *t,
	const unsigned char *seed /*[64]*/)
{
	const char k[] = "Bitcoin seed";
	uint8_t raw[82],
		*version	= raw +  0, /*  [4] */
		*depth		= raw +  4, /*  [1] */
		*pfingerprint	= raw +  5, /*  [4] */
		*childnr	= raw +  9, /*  [4] */
		*chain_code	= raw + 13, /* [32] */
		*key		= raw + 45, /* [33] */
		*b58chksum	= raw + 78, /*  [4] */
		hseed[64];
	int error;

	hmac_sha512(hseed, k, strlen(k), seed, 64);

	memcpy(version, t->prv_ver, 4);
	*depth = 0x00; /* master key */
	memset(pfingerprint, 0, 4); /* master key */
	memset(childnr, 0, 4); /* master key */
	memcpy(chain_code, hseed+32, 32);
	*key = 0x00; /* private key */
	memcpy(key+1, hseed, 32);

	zeroize(hseed, 64);

	sha256dchk(b58chksum, raw, 78);

	error = base58enc(xprv, &len, raw, sizeof(raw));

	zeroize(raw, sizeof(raw));

	return (!error? len : error);
}

static void
selftest(int T_flag)
{
	int error = 0;
	char mnemonic[816];
	unsigned char seed[64];
	char xprv[113];
	ssize_t xbytes;
	const char *m[2];
	unsigned m_errors = 0, s_errors = 0, x_errors = 0, total_tests = 0;
	FILE *f;

	f = T_flag? stdout : stderr;

	for (size_t lang = 0; lang < ntestlangs; ++lang) {
		const char **wl = NULL;
		const char *spacechar = NULL;

		for (size_t i = 0; i < sizeof(wordlists)/sizeof(*wordlists);++i)
			if (strcmp(wordlists[i].name, testvec[lang].lang) == 0){
				wl = wordlists[i].wordlist;
				spacechar = wordlists[i].space;
				break;
			}

		assert(wl != NULL && spacechar != NULL);

		for (size_t i = 0; i < testvec[lang].ntests; ++i) {
			++total_tests;
			mkmnemonic(mnemonic, testvec[lang].v[i].bits,
				testvec[lang].v[i].entropy, wl, spacechar);
			m[0] = norm_nfkd(mnemonic);
			m[1] = norm_nfkd(testvec[lang].v[i].mnemonic);
			if (m[0] == NULL || m[1] == NULL)
				abort(); /* That's a bad test failure! */
			if (strcmp(m[0], m[1]) != 0) {
				++m_errors;
				/* XXX types */
				fprintf(f, "Failed %s mnemonic self-test %u.\n",
					testvec[lang].lang, (unsigned)i);
				fprintf(f, "%s\n%s\n%s\n%s\n", mnemonic, m[0],
					testvec[lang].v[i].mnemonic, m[1]);
			} else if (T_flag)
				fprintf(f, "Success %s[%u] mnemonic: \"%s\"\n",
					testvec[lang].lang,
					(unsigned)i, mnemonic);
			ZFREE(m[0]);
			ZFREE(m[1]);

			if (!T_flag)
				continue;

			error = mkseed(seed, mnemonic,
				testvec[lang].v[i].passphrase);

			if (error)
				abort();

			if (memcmp(seed, testvec[lang].v[i].seed, 64) != 0) {
				++s_errors;
				fprintf(f, "Failed %s seed self-test %u.\n",
					testvec[lang].lang, (unsigned)i);
			} else if (T_flag)
				fprintf(f, "Success %s[%u] seed.\n",
					testvec[lang].lang, (unsigned)i);

			xbytes = mkxser(xprv, sizeof(xprv), default_xprv, seed);
			if (xbytes <= 0)
				abort();

			if (strcmp(xprv, testvec[lang].v[i].bip32_xprv) != 0) {
				++x_errors;
				fprintf(f, "Failed %s xprv test %u:\n%s\n%s\n",
					testvec[lang].lang, (unsigned)i,
					xprv, testvec[lang].v[i].bip32_xprv);
			} else if (T_flag)
				fprintf(f, "Success %s[%u] xprv: %s\n",
					testvec[lang].lang, (unsigned)i, xprv);
		}
	}
	if (m_errors || s_errors || x_errors) {
		/* XXX TODO: xprv testing */
		fprintf(f, "Self-testing failed: %u total tests, "
				"%u failed mnemonics, %u failed seeds, "
				"%u failed xprvs\n",
			total_tests, m_errors, s_errors, x_errors);
		abort();
	}
	if (T_flag)
		fprintf(f, "%u/%u self-tests succeeded.\n",
			total_tests, total_tests);
}

/*
 * The following function is for the purpose of sanity-checking the
 * build system.  I fear that some platform's shell tools may mangle
 * UTF-8.  With this function, it can be exactly verified by hand that
 * the compiled-in wordlist is identical to the source wordlist.
 */
static void
reproduce_wordlist(const struct wordlist *wl)
{

	fprintf(stderr, "%s  %s.txt\n", wl->hash, wl->name);
	for (int i = 0; i < 2048; ++i)
		printf("%s\n", wl->wordlist[i]);
}

static void
selftest_wordlists(int T_flag)
{
	const char hex[16] = "0123456789abcdef";
	char txthash[65], *cur;
	unsigned char buf[32];
	SHA256_CTX ctx;
	unsigned errors = 0;
	FILE *f;

	f = T_flag? stdout : stderr;

	for (int i = 0; i < sizeof(wordlists)/sizeof(*wordlists); ++i) {
		SHA256_Init(&ctx);
		for (int j = 0; j < 2048; ++j) {
			const char *word = wordlists[i].wordlist[j];
			SHA256_Update(&ctx, word, strlen(word));
			/* XXX: Horrid inefficiency. */
			SHA256_Update(&ctx, "\n", 1);
		}
		SHA256_Final(buf, &ctx);

		cur = txthash;
		for (int i = 0; i < 32; ++i)
			*cur++ = hex[buf[i] >> 4], *cur++ = hex[buf[i] & 0xf];
		*cur = '\0';

		if (strncmp(wordlists[i].hash, txthash, 64) != 0) {
			fprintf(f, "Hash failure for wordlist \"%s.txt\".  "
				"Compile-time hash:\n%s\n"
				"Auto-checked hash:\n%s\n",
				wordlists[i].name, wordlists[i].hash, txthash);
			++errors;
		} else if (T_flag)
			printf("%s  %s.txt\n", txthash, wordlists[i].name);
	}

	if (errors)
		abort();
}

/*
 * Pass a buflen < 0 to indicate a NUL-terminated string.
 */
static int
validpass(const char *buf, ssize_t buflen)
{
	int error = 0;
	ssize_t len, charcnt, charlen;
	const utf8proc_uint8_t *cur;
	utf8proc_int32_t c;
	const utf8proc_property_t *p;

	len = buflen >= 0? buflen : strlen(buf);

	charcnt = 0;
	cur = (utf8proc_uint8_t*)buf;

	while (len > 0) {
		const char *errmsg = NULL;

		charlen = utf8proc_iterate(cur, len, &c);
		if (charlen < 0) {
			fprintf(stderr, "easyseed: %s\n", utf8proc_errmsg(len));
			error = -1;
			goto done;
		}

		p = utf8proc_get_property(c);

		switch (p->category) {
		case UTF8PROC_CATEGORY_CN: /* Unassigned or invalid. */
			errmsg = "Invalid character, or unassigned in Unicode 9.0";
			break;
		case UTF8PROC_CATEGORY_ZL: /* Line separator */
			errmsg = "Line separator character detected";
			break;
		case UTF8PROC_CATEGORY_ZP:
			errmsg = "Paragraph separator character detected";
			break;
		case UTF8PROC_CATEGORY_CC: /* Control character */
			errmsg = "Control character detected";
			break;
		case UTF8PROC_CATEGORY_CF: /* Format character */
			errmsg = "Format character detected";
			break;
		case UTF8PROC_CATEGORY_CS: /* Surrogate */
			errmsg = "Surrogate character detected";
			break;
		/* case UTF8PROC_CATEGORY_CO:  Private use */
			/* XXX: allow this? */
		default:
			;
		}

		if (errmsg != NULL) {
			fprintf(stderr, "easyseed: %s.\n", errmsg);
			error = -1;
			goto done;
		}

		assert(len >= charlen);

		++charcnt, cur += charlen, len -= charlen;
	}

	if (charcnt > PASSPHRASE_UNICHARS_MAX) {
		error = -1;
		warnx("The entered string is too long, >= %jd Unicode "
			"characters (%jd bytes).\nMax Unicode chars: %d",
			(intmax_t)charcnt, (intmax_t)((const char*)cur - buf),
			PASSPHRASE_UNICHARS_MAX);
	}

done:
	zeroize(&c, sizeof(c));
	return (error);
}

static int getpass(char *buf, size_t len);

static int
passfile(char *buf, size_t len, const char *pfile)
{
	int passfd, error;
	ssize_t rbytes, nbytes;
	size_t cut;
	char *cur;

	if (strcmp(pfile, "-") == 0) {
		if (isatty(0))
			return (getpass(buf, len));
		passfd = 0;
	} else {
		passfd = open(pfile, O_RDONLY);
		if (passfd < 0)
			return (-1);
	}

	nbytes = 0;
	cur = buf;

	do {
		rbytes = read(passfd, cur, len - nbytes);
		if (rbytes < 0) {
			if (errno == EINTR)
				continue;
			warn("read() on %s", pfile);
			zeroize(buf, len);
			close(passfd);
			return (-1);
		} else if (rbytes == 0)
			break;

		nbytes += rbytes, cur += rbytes;
	} while (nbytes < len);

	/* XXX check errors; problem in POSIX */
	close(passfd);

	if (nbytes == len) {
		warnx("passphrase too long (bytes)");
		zeroize(buf, len);
		return (-1);
	} else
		buf[nbytes] = '\0';

	cur = strchr(buf, '\n');
	if (cur != NULL) {
		cut = len - (cur - buf);
		nbytes -= cut;
	} else {
		cut = len - nbytes;
		cur = buf + nbytes;
	}
	/*
	 * This avoids potential leakage of the length of the passphrase via
	 * trailing garbage.
	 *
	 * It also will implicitly nul-terminate an '\n'-terminated string.
	 */
	zeroize(cur, cut);

	error = validpass(buf, -1);
	if (error) {
		warnx("Invalid passphrase.");
		zeroize(buf, len);
	}

	return (error);
}

static int
getpass(char *buf, size_t len)
{
#ifdef DYNPASS
	const char	prompt[] =   "Please enter your passphrase:",
			reprompt[] = "Please re-enter it to confirm:";
	char *doublecheck, *cur;
	size_t rbytes;
	const int flags = RPP_ECHO_OFF | RPP_REQUIRE_TTY;
	int error;

	doublecheck = malloc(len);
	if (doublecheck == NULL)
		return (-1);

	cur = readpassphrase(prompt, buf, len, flags);
	if (cur == NULL) {
		zeroize(buf, len);
		error = -1;
		goto done;
	}

	error = validpass(buf, -1);
	if (error) {
		warnx("Invalid passphrase.");
		zeroize(buf, len);
		goto done;
	}

	cur = readpassphrase(reprompt, doublecheck, len, flags);
	if (cur == NULL) {
		zeroize(buf, len);
		error = -1;
		goto done;
	}

	if (strncmp(buf, doublecheck, len - 1) != 0) {
		warnx("The entered passphrases do not match.");
		error = -1;
		zeroize(buf, len);
		goto done;
	}

done:
	ZFREE(doublecheck);
	return (error);
#else /* !DYNPASS */
	errx(127, "Support for reading the passphrase from terminal is "
		"not compiled in.");
#endif /* DYNPASS */
}

static void
hexenc(char *h, const unsigned char *bin, size_t len)
{
	const char hex[16] = "0123456789abcdef";

	while (len > 0) {
		*h++ = hex[*bin >> 4];
		*h++ = hex[*bin & 0xf];
		++bin, --len;
	}
	*h = '\0';
}

static int
make_all_clean(unsigned nbits, const struct wordlist *wl, const char *keymat,
	int p_flag, const char *pfile, int E_flag, int D_flag)
{
	void *buf;
	size_t buflen;
	unsigned char *entropy;
	char *mnemonic;
	ssize_t mlen;
	char passbuf[PASSPHRASE_BUFSIZE], *cur, *passphrase = NULL;
	unsigned char seed[64];
	char hexbuf[129];
	char xprv[113];
	ssize_t xbytes;
	size_t nbytes;
	int error = 0;

	if ((buf = malloc((buflen = 65536))) == NULL)
		return (-1);

	error = setvbuf(stdout, buf, _IOFBF, buflen);
	if (error) {
		free(buf);
		return (-1);
	}

	assert(!(p_flag && pfile != NULL));
	if (p_flag) {
		passphrase = passbuf;
		error = getpass(passphrase, PASSPHRASE_BUFSIZE);
	} else if (pfile != NULL) {
		passphrase = passbuf;
		error = passfile(passphrase, PASSPHRASE_BUFSIZE, pfile);
	}
	/* error can only be nonzero if one of these functions failed. */
	if (error) {
		free(buf);
		return (error);
	}

	nbytes = nbits/8;

	mlen = newmnemonic(&entropy, &mnemonic, nbits, keymat, wl);
	if (mlen < 0) {
		error = -1;
		goto done;
	}

	hexenc(hexbuf, entropy, nbytes);
	printf("Entropy:\n%s\n\n", hexbuf);

	error = mkseed(seed, mnemonic, passphrase);
	if (error)
		goto done2;

	hexenc(hexbuf, seed, sizeof(seed));

	xbytes = mkxser(xprv, sizeof(xprv), default_xprv, seed);
	if (xbytes < 0) {
		error = -1;
		goto done3;
	}

	printf("Mnemonic:\n%s\n\n", mnemonic);
	if (D_flag)
		printf("Passphrase:\n%s\n\n", passphrase);
	printf("Seed:\n%s\n\n", hexbuf);
	if (!E_flag)
		printf("Master Extended Private Key:\n%s\n", xprv);
	else {
		printf(	"### Multiple formats of extended private key "
			"for use with Electrum.\n");
		printf("### USE ONLY ONE OF THESE!\n\n");
		printf(u8"Old-style address (“1-Address”):\n%s\n\n", xprv);
		xbytes = mkxser(xprv, sizeof(xprv), &xprv_type[2], seed);
		if (xbytes < 0) {
			error = -1;
			goto done3;
		}
		printf(u8"Segwit backward-compatible "
			u8"P2WPKH-nested-in-P2SH (“3-Address”):\n%s\n\n", xprv);
		xbytes = mkxser(xprv, sizeof(xprv), &xprv_type[3], seed);
		if (xbytes < 0) {
			error = -1;
			goto done3;
		}
		printf(u8"Segwit Bech32 New/Future Format "
			u8"(“Bravo Charlie One”):\n%s\n", xprv);
	}

	error = fflush(stdout);
	if (error)
		warn("Unable to write to stdout");
	else
		error = fclose(stdout);

done3:
	zeroize(xprv, sizeof(xprv));
done2:
	zeroize(hexbuf, sizeof(hexbuf));
	zeroize(seed, sizeof(seed));
done1:
	sfree(mnemonic, mlen);
	sfree(entropy, nbytes);
done:
	zeroize(passbuf, sizeof(passbuf));
	sfree(buf, buflen);

	return (error);
}

static const struct wordlist *
selectlang(const char *userlang, int enable_all)
{
	size_t len, maxlen = 0;
	const struct wordlist *result = NULL;

	for (int i = 0; i < sizeof(wordlists)/sizeof(*wordlists); ++i) {
		len = strlen(wordlists[i].name);
		maxlen = len > maxlen? len : maxlen;
	}

	for (int i = 0; i < sizeof(wordlists)/sizeof(*wordlists); ++i)
		if (strncasecmp(userlang, wordlists[i].name, maxlen) == 0) {
			result = &wordlists[i];
			goto found;
		}

	for (int i = 0; i < sizeof(wordlists)/sizeof(*wordlists); ++i) {
		len = strlen(wordlists[i].lname);
		maxlen = len > maxlen? len : maxlen;
	}

	/* XXX: I do not trust strncasecmp() here.  Or setlocale() first? */
	for (int i = 0; i < sizeof(wordlists)/sizeof(*wordlists); ++i)
		if (strncmp(userlang, wordlists[i].lname, maxlen) == 0) {
			result = &wordlists[i];
			goto found;
		}

	for (int i = 0; i < sizeof(wordlists)/sizeof(*wordlists); ++i) {
		len = strlen(wordlists[i].code2);
		maxlen = len > maxlen? len : maxlen;
	}

	for (int i = 0; i < sizeof(wordlists)/sizeof(*wordlists); ++i)
		if (strncasecmp(userlang, wordlists[i].code2, maxlen) == 0) {
			result = &wordlists[i];
			goto found;
		}

	return (NULL); /* not found */
found:
	return ((enable_all || result->status)? result : NULL);
}

static void
printlang(FILE *f, int enable_all)
{

	fprintf(f, "# Available wordlists and selectors:\n");
	for (int i = 0; i < sizeof(wordlists)/sizeof(*wordlists); ++i)
		if (enable_all || wordlists[i].status)
			fprintf(f, "\t%s: \"%s\" (%s)\n", wordlists[i].name,
				wordlists[i].lname, wordlists[i].code2);
}

int
main(int argc, char *argv[])
{
	int ch, error = 0, mode_flag = '\0',
		D_flag = 0, E_flag = 0, O_flag = 0, W_flag = 0, p_flag = 0;
	size_t nbits = 0, nbytes;
	char *keymat = NULL, *lang = NULL, *pfile = NULL;
	ssize_t wbytes;
	const struct wordlist *wl = default_wordlist;

	unsigned char *entropy;
	char *mnemonic;
	ssize_t len;

	opterr = 0;
	while ((ch = getopt(argc, argv, ":ADLEOPTWb:j:k:l:p")) > -1) {
		switch (ch) {
		case 'A':
		case 'L':
		case 'P':
		case 'T':
			mode_flag = ch;
			break;
		case 'D':
			D_flag = 1;
			break;
		case 'E':
#ifdef ELECTRUM_TEST
			E_flag = 1;
#else
			errx(63, "Unimplemented -E");
#endif
			break;
		case 'O': /* undocumented; for .onion */
			O_flag = 1;
			break;
		/*
		 * -W: Enable all wordlists.
		 * Undocumented.  For purposes of testing proposed
		 * wordlists which may be changed or removed.
		 */
		case 'W':
			W_flag = 1;
			break;
		case 'b': /* bits */
			/* XXX: atoi(), hahah */
			nbits = atoi(optarg);
			break;
		case 'j':
			pfile = optarg;
			break;
		case 'k':
			keymat = optarg;
			break;
		case 'l':
			lang = optarg;
			break;
		case 'p':
			p_flag = 1;
			break;
		default:
			errx(1, "Unknown option: -%c", (char)ch);
		}
	}

	if (lang != NULL) {
		if ((wl = selectlang(lang, W_flag)) == NULL) {
			fprintf(stderr, "Unknown language: %s\n", lang);
			printlang(stderr, W_flag);
			return (1);
		}
	}

	if (mode_flag == 'A') {
		if (p_flag && pfile != NULL) {
			warnx(
	"Passphrase cannot be read from both file (-j) and terminal (-p)");
			usage();
		}
	} else if (p_flag || pfile != NULL) {
		warnx("No use for passphrase in this mode.");
		usage();
	}

	if ((p_flag || (pfile != NULL && strcmp(pfile, "-") == 0)) &&
		(keymat != NULL && strcmp(keymat, "-") == 0)) {
		errx(1, "Too many options trying to read from stdin");
	}

	if (mode_flag == 'L') {
		printlang(stdout, W_flag);
		return (0);
	} else if (mode_flag == 'P') {
		reproduce_wordlist(wl);
		return (0);
	}

	switch (nbits) {
	case 128: case 160: case 192: case 224: case 256:
		break;
	case 80:
		if (O_flag && mode_flag != 'A')
			break;
		/*FALLTHROUGH*/
	default:
		if (mode_flag != 'T')
			usage();
	}

	if ((nullfd = open("/dev/null", O_RDWR)) < 0)
		err(2, "open() on /dev/null");

	selftest(mode_flag == 'T');
	selftest_wordlists(mode_flag == 'T');
	if (mode_flag == 'T')
		return (0);

	if (mode_flag == 'A')
		error = make_all_clean(nbits, wl, keymat, p_flag, pfile,
			E_flag, D_flag);
	else {
		assert(mode_flag == '\0');

		nbytes = nbits/8;

		len = newmnemonic(&entropy, &mnemonic, nbits, keymat, wl);
		if (len < 0)
			errx(2, "easyseed: mnemonic generation failed.");

		mnemonic[len] = '\n';
		wbytes = write(1, mnemonic, len+1);
		if (wbytes != len+1) {
			error = 2;
			warn("Failed to write() mnemonic to stdout!");
		}
		close(1);

		sfree(mnemonic, len);
		sfree(entropy, nbytes);
	}

	return (error);
}

static void
usage(void)
{

	fprintf(stderr,
		"# General usage:\n"
		"easyseed -b bits [-k file] [-l lang] [-A [-j passfile | -p]]\n"
		"# Valid values for bits: { 128, 160, 192, 224, 256 }\n"
		"# If given, file length must match bits. \"-\" for stdin.\n"
		"# List languages:\n"
		"easyseed -L\n"
		"# Print wordlist:\n"
		"easyseed -P [-l lang]\n"
		"# Full, verbose self-tests:\n"
		"easyseed -T\n"
	);
	exit(1);
}
