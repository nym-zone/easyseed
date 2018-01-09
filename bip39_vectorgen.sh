#!/bin/sh
#
# Test vector generator for BIP 39, using easyseed.
# Takes a language short code as a single argument, outputs to stdout.
#
# Requires uconv, and also jq to validate the output JSON.
# (jq use can be disabled by editing this file, without loss of
# functioning other than validation.)
#
##
# By nullius <nullius@nym.zone>
# PGP: 0xC2E91CD74A4C57A105F6C21B5A00591B2F307E0C
# Bitcoin: 3NULL3ZCUXr7RDLxXeLPDMZDZYxuaYkCnG
#
# Copyright (c) 2018.  All rights reserved.
#
# The Antiviral License (AVL) v0.0.1, with added Bitcoin Consensus Clause:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of the source code must retain the above copyright
#    and credit notices, this list of conditions, and the following
#    disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    and credit notices, this list of conditions, and the following
#    disclaimer in the documentation and/or other materials provided
#    with the distribution.
# 3. Derivative works hereof MUST NOT be redistributed under any license
#    containing terms which require derivative works and/or usages to
#    publish source code, viz. what is commonly known as a "copyleft"
#    or "viral" license.
# 4. Derivative works hereof which have any functionality related to
#    digital money (so-called "cryptocurrency") MUST EITHER adhere to
#    consensus rules fully compatible with Bitcoin Core, OR use a name
#    which does not contain the word "Bitcoin".
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

PASSFMT='nullius　à　nym.zone ¹teſts² %s'

set -o errexit

if [ "${TESTBUILD}" = 1 ] ; then
	# Using freshest version, from build directory:
	easyseed="./easyseed"
else
	easyseed=easyseed
fi

fifo=`mktemp -u /tmp/fifo.XXXXXXXXXX`
mkfifo -m0600 "${fifo}"
tmpjson=`mktemp /tmp/json.XXXXXXXXXX`

cleanup()
{

	rm "${fifo}" "${tmpjson}"
}

trap cleanup EXIT

fail()
{

	printf 'error: %s\n' "${1}" >&2
	exit 1
}

jsoncheck()
{

	if which jq >/dev/null 2>&1 ; then
		jq -e . >/dev/null
	else
		#cat >/dev/null
		echo "error" >&2
		exit 1
	fi
}

vector0()
{
	local lang
	local entropy

	lang="${1}"
	entropy="${2}"

	case "${lang}" in
	zh)
		# XXX: Unimplemented in easyseed:
		lang="中文"
		;;
	zh-CN)
		lang="汉语"
		;;
	zh-TW)
		lang="漢語"
		;;
	cz)
		lang="Čeština"
		;;
	en)
		lang="English"
		;;
	fr)
		lang="Français"
		;;
	id)
		lang="Bahasa Indonesia"
		;;
	it)
		lang="Italiano"
		;;
	ja)
		lang="日本語"
		;;
	ko)
		lang="한국어"
		;;
	ru)
		lang="Русский"
		;;
	es)
		lang="Español"
		;;
	uk)
		lang="Українська"
		;;
	*)
		fail "lang=\"$lang\""
		;;
	esac

	printf "${PASSFMT}" "${lang}" \
		> "${fifo}" &

	echo "${entropy}" | xxd -p -r | \
		"${easyseed}" -W -b $((${#entropy}/2 * 8)) -l "${lang}" -A -D \
			-k - -j "${fifo}"
}

txt2json()
{
	local n

	grep -v '^$' | {
		printf '\t{\n'
		read n
		if [ "$n" != "Entropy:" ] ; then
			fail "Entropy:" "$n"
		fi
		read n
		printf '\t\t"entropy": "%s",\n' "${n}"
		read n
		if [ "$n" != "Mnemonic:" ] ; then
			fail "Mnemonic:" "$n"
		fi
		read n
		printf '\t\t"mnemonic": "%s",\n' "${n}"
		read n
		if [ "$n" != "Passphrase:" ] ; then
			fail "Passphrase:" "$n"
		fi
		read n
		printf '\t\t"passphrase": "%s",\n' "${n}"
		read n
		if [ "$n" != "Seed:" ] ; then
			fail "Seed:" "$n"
		fi
		read n
		printf '\t\t"seed": "%s",\n' "${n}"
		read n
		if [ "$n" != "Master Extended Private Key:" ] ; then
			fail "Master Extended Private Key:" "$n"
		fi
		read n
		printf '\t\t"bip32_xprv": "%s"\n' "${n}"
		printf '\t}'
	}
}

testvector()
{
	local lang
	local entropy

	lang="${1}"
	entropy="${2}"

	vector0 "${lang}" "${entropy}" | \
		uconv -x '::nfc;' | \
		txt2json
}

vectorset()
{
	local lang="$1"
	local str
	local x

	printf '[\n'

	for octet in 00 01 7f 80 fe ff aa 55 ; do
		for bytelen in 16 20 24 28 32 ; do
			x="${bytelen}"
			str="${octet}"
			until [ $((x -= 1)) -eq 0 ] ; do
				str="${str}${octet}"
			done
			# assert():
			if [ "${#str}" -ne $((bytelen * 2)) ] ; then
				fail "wrong bytelen: ${#str} '${str}'"
			fi
			testvector "${lang}" "${str}"
			printf ',\n'
		done
	done

	{
cat << EOF
9e885d952ad362caeb4efe34a8e91bd2
6610b25967cdcca9d59875f5cb50b0ea75433311869e930b
68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c
b3ffe8f56d54805218090de337779328a3a2e758
EOF
	} | \
	while read str ; do
		testvector "${lang}" "${str}"
		printf ',\n'
	done
	testvector "${lang}" \
		437dd688276ceb711cda3a126eab879a188a30b097b769a931bea6fe
	printf '\n]\n'
}

vectorset "$1" | tee "${tmpjson}" | jsoncheck && cat "${tmpjson}"
