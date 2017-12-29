# easyseed

## The easy mnemonic generator for Bitcoin [BIP 39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) seed phrases.

- By nullius <[nullius@nym.zone](mailto:nullius@nym.zone)>
- PGP: [0xC2E91CD74A4C57A105F6C21B5A00591B2F307E0C](https://sks-keyservers.net/pks/lookup?op=get&search=0xC2E91CD74A4C57A105F6C21B5A00591B2F307E0C)
- Bitcoin, tips welcome: [3NULL3ZCUXr7RDLxXeLPDMZDZYxuaYkCnG](bitcoin:3NULL3ZCUXr7RDLxXeLPDMZDZYxuaYkCnG)

I wrote this because I needed a lightweight, reliable BIP 39 seed phrase generator with easily auditable sources and minimal dependencies for use on a stripped-down airgap machine.

The source code is written in (mostly) strict KNF.  It’s easy to read, and lovingly commented.  Anybody with basic knowledge of the C programming language should be able to understand what it does at a glance.

It has been tested on FreeBSD, my main platform, and on Linux.  [Unfortunately, I may have slightly mussed the BSD building while preparing for publication; this should soon be fixed.  The build system generally is still wonky.  This is an early release, with most attention paid to the source code and manpage!]

For further details, [RTFM](https://raw.githubusercontent.com/nym-zone/easyseed/easyseed.1.txt).  Yes, it has a manpage.  Software is unworthy of release if it does not have a proper manpage.

License: AVL v0.0.1 with Bitcoin clause.  I would prefer to disclaim copyright, and and release things to the public domain (*the public domain is not a license, “CC0” people*).  However, this is not an ideal world.

## Installation

FreeBSD:

```
make && make check
```

...then, `make install` as root (via `sudo` or otherwise).  Other BSDs are probably similar.

Linux:

```
make -f Makefile.linux && \
	make -f Makefile.linux check && \
	sudo make -f Makefile.linux install
```