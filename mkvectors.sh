#!/bin/sh

#
# This is quite possibly the worst shell script I have ever written.
# I am sorry.  It gets the job done, for now.
#

tmpenglish=`mktemp /tmp/english.json.XXXXXXXXXX`

{
cat << EOF
#include "vectors.h"

/*
 * English test vectors
 *
 * Combined from:
 *
 * https://github.com/trezor/python-mnemonic/blob/b502451a33a440783926e04428115e0bed87d01f/vectors.json
 *
 * https://github.com/bip32JP/bip32JP.github.io/blob/57f451fc785387c72e5b0b8db0f6b7c2b064c362/test_EN_BIP39.json
 */

static const struct testent english_vectors[] = {
EOF
}

jq '[.english[]|{"entropy": .[0], "mnemonic": .[1], "passphrase": "TREZOR", "seed": .[2], "bip32_xprv": .[3]}]' < vectors.json | \
jq -s 'add|unique_by(.entropy)' -- - test_EN_BIP39.json  > "${tmpenglish}"

#[(.[])]|
mkvec()
{
jq '.[]|[.entropy, .mnemonic, .passphrase, .seed, .bip32_xprv]|@sh' < "$1" | tr -d '"' | xargs -n5 sh -c '{
cat << EOF
	{
		.bits = $((${#1}*8/2)),
		.entropy = { `echo "$1" | sed -r -e "s/[0-9a-f]{2}/0x&, /g"`},
		.mnemonic = u8"$2",
		.passphrase = u8"$3",
		.seed = { `echo "$4" | sed -r -e "s/[0-9a-f]{2}/0x&, /g"`},
		.bip32_xprv = "$5"
	},
EOF
}' NULL
}

mkvec "${tmpenglish}"

{
cat << EOF
};

/*
 * Japanese vectors, from:
 *
 * https://github.com/bip32JP/bip32JP.github.io/blob/360c05a6439e5c461bbe5e84c7567ec38eb4ac5f/test_JP_BIP39.json
 */

static const struct testent japanese_vectors[] = {
EOF
}

mkvec test_JP_BIP39.json

{
cat << EOF
};

const struct testentvec testvec[] = {
EOF
}

printf "\t{ .ntests = %d, .lang = \"english\", .v = english_vectors },\n" \
	`jq length < "${tmpenglish}"`

printf "\t{ .ntests = %d, .lang = \"japanese\", .v = japanese_vectors }\n" \
	`jq length < test_JP_BIP39.json`

{
cat << EOF
};

const size_t ntestlangs = 2;
EOF
}

rm "${tmpenglish}"
