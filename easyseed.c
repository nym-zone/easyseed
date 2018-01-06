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

#include <fcntl.h>
#include <unistd.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <err.h>

#ifdef __FreeBSD
#include <sha256.h>
#else
#include <openssl/sha.h>
#endif

/* Changing this will appropriately change the device used: */
#define	DEV_RANDOM	"/dev/urandom"

struct wordlist {
	const char *name;
	const char *lname;
	const char *code2;
	const char *space;
	const char **wordlist;
	const char *hash; /* SHA-256 */
};

static const char ascii_space[] = " ";

#include "wordlist.h"

#define	LANG(name, lname, code2, space)	\
	{ #name, lname, code2, space, name, name##_hash }

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
	LANG(english,			u8"English",	"en",	ascii_space ),
	LANG(chinese_simplified,	u8"汉语",	"zh-CN",ascii_space ),
	LANG(chinese_traditional,	u8"漢語",	"zh-TW",ascii_space ),
	LANG(french,			u8"Français",	"fr",	ascii_space ),
	LANG(indonesian,	u8"Bahasa Indonesia",	"id",	ascii_space ),
	LANG(italian,			u8"Italiano",	"it",	ascii_space ),
	LANG(japanese,			u8"日本語",	"ja",	u8"\u3000"  ),
	LANG(korean,			u8"한국어",	"ko",	ascii_space ),
	LANG(spanish,			u8"Español",	"es",	ascii_space )
};

#undef LANG

static const struct wordlist *default_wordlist = &wordlists[0];

#include "vectors.h"

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

static void
selftest(int T_flag)
{
	char mnemonic[816];
	unsigned errors = 0, total_tests = 0;
	FILE *f;

	f = T_flag? stdout : stderr;

	/*
	 * XXX: In the Japanese test vectors, the mnemonics are quite properly
	 * not normalized to Unicode NFKD.  Thus, string comparison will fail
	 * without normalization.  (Good job, Japanese test vector designer!)
	 * Currently, 22 of the Japanese tests fail:  Those with indices of
	 * 0-7, 9, 10, 12-23.  Japanese tests 8 and 11 succeed.
	 *
	 * This will be re-enabled when normalization is added.
	 */
#ifdef notyet
	for (size_t lang = 0; lang < ntestlangs; ++lang) {
#else
	for (size_t lang = 0; lang < 1; ++lang) {
#endif
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
			if (strcmp(mnemonic, testvec[lang].v[i].mnemonic) != 0){
				++errors;
				/* XXX types */
				fprintf(f, "Failed %s self-test %u.\n",
					testvec[lang].lang, (unsigned)i);
				fprintf(f, "%s\n%s\n", mnemonic,
					testvec[lang].v[i].mnemonic);
			} else if (T_flag)
				fprintf(f, "Success %s[%u]: \"%s\"\n",
					testvec[lang].lang,
					(unsigned)i, mnemonic);
		}
	}
	if (errors) {
		fprintf(f, "Self-testing failed: %u/%u tests failed\n",
			errors, total_tests);
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

static const struct wordlist *
selectlang(const char *userlang)
{
	size_t len, maxlen = 0;

	for (int i = 0; i < sizeof(wordlists)/sizeof(*wordlists); ++i) {
		len = strlen(wordlists[i].name);
		maxlen = len > maxlen? len : maxlen;
	}

	for (int i = 0; i < sizeof(wordlists)/sizeof(*wordlists); ++i)
		if (strncasecmp(userlang, wordlists[i].name, maxlen) == 0)
			return (&wordlists[i]);

	for (int i = 0; i < sizeof(wordlists)/sizeof(*wordlists); ++i) {
		len = strlen(wordlists[i].lname);
		maxlen = len > maxlen? len : maxlen;
	}

	/* XXX: I do not trust strncasecmp() here.  Or setlocale() first? */
	for (int i = 0; i < sizeof(wordlists)/sizeof(*wordlists); ++i)
		if (strncmp(userlang, wordlists[i].lname, maxlen) == 0)
			return (&wordlists[i]);

	for (int i = 0; i < sizeof(wordlists)/sizeof(*wordlists); ++i) {
		len = strlen(wordlists[i].code2);
		maxlen = len > maxlen? len : maxlen;
	}

	for (int i = 0; i < sizeof(wordlists)/sizeof(*wordlists); ++i)
		if (strncasecmp(userlang, wordlists[i].code2, maxlen) == 0)
			return (&wordlists[i]);

	return (NULL); /* not found */
}

static void
printlang(FILE *f)
{

	fprintf(f, "# Available wordlists and selectors:\n");
	for (int i = 0; i < sizeof(wordlists)/sizeof(*wordlists); ++i)
		/* XXX: Indonesian not yet supported/documented. */
		if (strncmp(wordlists[i].code2, "id", 2) != 0)
		fprintf(f, "\t%s: \"%s\" (%s)\n", wordlists[i].name,
			wordlists[i].lname, wordlists[i].code2);
}

int
main(int argc, char *argv[])
{
	int ch, keyfd = -1, error = 0, O_flag = 0, P_flag = 0, T_flag = 0;
	size_t nbits = 0, nbytes;
	char *keymat = NULL;
	ssize_t rbytes, wbytes;
	const struct wordlist *wl = default_wordlist;

	unsigned char seed[32];
	char mnemonic[816];
	size_t len;

	opterr = 0;
	while ((ch = getopt(argc, argv, ":LOPTb:k:l:")) > -1) {
		switch (ch) {
		case 'b': /* bits */
			/* XXX: atoi(), hahah */
			nbits = atoi(optarg);
			break;
		case 'k':
			keymat = optarg;
			break;
		case 'l':
			if ((wl = selectlang(optarg)) == NULL) {
				fprintf(stderr, "Unknown language: %s\n",
					optarg);
				printlang(stderr);
				return (1);
			}
			break;
		case 'L':
			printlang(stdout);
			return (0);
		case 'O':
			O_flag = 1;
			break;
		case 'T':
			T_flag = 1;
			break;
		default:
			errx(1, "Unknown option: -%c", (char)ch);
		}
	}

	if (P_flag) {
		reproduce_wordlist(wl);
		return (0);
	}

	switch (nbits) {
	case 128: case 160: case 192: case 224: case 256:
		break;
	case 80:
		if (O_flag)
			break;
		/*FALLTHROUGH*/
	default:
		if (!T_flag)
			usage();
	}

	if ((nullfd = open("/dev/null", O_RDWR)) < 0)
		err(2, "open() on /dev/null");

	selftest(T_flag);
	selftest_wordlists(T_flag);
	if (T_flag)
		return (0);

	nbytes = nbits/8;

	/*
	 * XXX: I know the checks of read() lengths are technically wrong.
	 * However, if the descriptor cannot give 16-32 bytes at a time,
	 * something else is wrong.  This will need editing if anybody
	 * insists on using blocking /dev/random on Linux.
	 */
	if (keymat == NULL) {
		if ((keyfd = open(DEV_RANDOM, O_RDONLY)) < 0)
			err(2, "open(\"" DEV_RANDOM "\")");
		rbytes = read(keyfd, seed, nbytes);
		if (rbytes != nbytes)
			err(2, "read() on random device");
	} else {
		unsigned char scratch;

		if (!strcmp(keymat, "-"))
			keyfd = 0;
		else
			if ((keyfd = open(keymat, O_RDONLY)) < 0)
				err(2, "open(\"%s\")", keymat);
		rbytes = read(keyfd, seed, nbytes);
		if (rbytes != nbytes) {
			error = errno;
			zeroize(seed, sizeof(seed));
			errno = error;
			err(2, "read() of key material");
		}

		/* Check for EOF: */
		rbytes = read(keyfd, &scratch, 1);
		if (rbytes != 0) {
			zeroize(seed, sizeof(seed));
			zeroize(&scratch, sizeof(scratch));
			if (rbytes > 0)
				errx(1,
				"Provided -k input length mismatches -b bits.");
			else
				err(2, "read() on key file");
		}

		close(keyfd);
		keyfd = -1;
	}

	mkmnemonic(mnemonic, nbits, seed, wl->wordlist, wl->space);

	len = strlen(mnemonic);
	mnemonic[len] = '\n';
	wbytes = write(1, mnemonic, len+1);
	if (wbytes != len+1) {
		error = 2;
		warn("Failed to write() mnemonic to stdout!");
	}
	close(1);

	zeroize(mnemonic, sizeof(mnemonic));
	zeroize(seed, sizeof(seed));

	return (error);
}

static void
usage(void)
{

	fprintf(stderr,
		"# General usage:\n"
		"easyseed -b bits [-k file] [-l lang]\n"
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
