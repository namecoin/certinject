#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob globstar

# wincrypt.h was downloaded from the following URL:
# https://raw.githubusercontent.com/reactos/reactos/8ae8083378546fc7d907e489aeebddbe3c8d9399/sdk/include/psdk/wincrypt.h
# Note that wincrypt.h only has property ID's from Windows XP.
# certenroll.h appears to have more (from Windows Vista) but it's not in ReactOS.

{
  printf 'package certblob\n\n'

  echo "const ("

  INITIALISM_SED_PROGRAM='s/(Ctl|Crl|Aia|Ca|Efs|Ie30|Md5|Ocsp|Sha1|Url)([^a-z]|$)/\U\1\2/g'
  grep -E $'^#define CERT_.*PROP_ID +[0-9A-Z_]+($|\r)' wincrypt.h | sed 's/#define /\t/' | sed 's/_PROP_ID /_PROP_ID = /' | sed -E 's/(\s+|_)([A-Z])([A-Z]+)/\1\2\L\3/g' | sed 's/_//g' | sed -E 's/PropId( =|$)/PropID\1/g' | sed -E "$INITIALISM_SED_PROGRAM" | sed -E "$INITIALISM_SED_PROGRAM"

  echo ")"
} > propids.go

gofmt -w propids.go
